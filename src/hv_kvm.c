#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

int kvm, vmfd;

int
vmm_create(void)
{
  int ret;

  if ((kvm = open("/dev/kvm", O_RDWR | OCLOEXEC)) < 0)
    return VMM_ERROR;

  /* check API version */
  if ((ret = ioctl(kvm, KVM_GET_API_VERSION, NULL)) < 0)
    return VMM_ERROR;
  if (ret != 12)
    return VMM_ENOTSUP;

  if ((vmfd = ioctl(kvm, KVM_CREATE_VM, 0UL)) < 0)
    return VMM_ERROR;

  return 0;
}

int
vmm_memory_map(vmm_uvaddr_t uva, vmm_gpaddr_t gpa, size_t size, vmm_memory_flags_t flags)
{
  struct kvm_userspace_memory_region region = {
    .slot = 0,
    .guest_phys_addr = gpa,
    .memory_size = size,
    .userspace_addr = (uint64_t)uva,
  };

  if ((ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region)) < 0)
    return VMM_ERROR;

  return 0;
}

int
vmm_cpu_create(vmm_cpuid_t *cpu)
{
  int cpufd;
  struct kvm_run *run;
  int mmap_size;

  if ((cpufd = ioctl(vmfd, KVM_CREATE_VCPU, 0UL)) < 0)
    return VMM_ERROR;

  cpu = (unsigned)cpufd;

  /* Map the shared kvm_run structure and following data. */
  if ((mmap_size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL)) < 0)
    return VMM_ERROR;
  assert(mmap_size < sizeof(*run))
  if ((run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0)) == 0)
    return VMM_ERROR;

  return 0;
}

int
vmm_cpu_run(vmm_cpuid_t cpu)
{
  if (ioctl(vcpufd, KVM_RUN, NULL) < 0)
    return VMM_ERROR;
  return 0;
}

int
vmm_cpu_write_register(vmm_cpuid_t cpu, vmm_x64_reg_t reg, uint64_t value)
{
  /* FIXME */

  /* Initialize CS to point at 0, via a read-modify-write of sregs. */
  ret = ioctl(vcpufd, KVM_GET_SREGS, &sregs);
  if (ret == -1)
    err(1, "KVM_GET_SREGS");
  sregs.cs.base = 0;
  sregs.cs.selector = 0;
  ret = ioctl(vcpufd, KVM_SET_SREGS, &sregs);
  if (ret == -1)
    err(1, "KVM_SET_SREGS");

  /* Initialize registers: instruction pointer for our code, addends, and
   * initial flags required by x86 architecture. */
  struct kvm_regs regs = {
    .rip = 0x1000,
    .rax = 2,
    .rbx = 2,
    .rflags = 0x2,
  };
  ret = ioctl(vcpufd, KVM_SET_REGS, &regs);
  if (ret == -1)
    err(1, "KVM_SET_REGS");

  return 0;
}
