#include <vmm.h>
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <Windows.h>
#include "list.h"
#include "haxm.h"

HANDLE hax_dev = INVALID_HANDLE_VALUE;

struct vmm_vm {
  HANDLE vmfd;
  int vmid;
  struct list_head cpus;
};

struct vmm_cpu {
  struct list_head head;
  HANDLE vcpufd;
  int vcpuid;
  struct hax_tunnel *hax_tunnel;
  unsigned char *iobuf;
};

static int
init_hax(void)
{
  hax_dev = CreateFile("\\\\.\\HAX", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hax_dev == INVALID_HANDLE_VALUE) {
    if (GetLastError() == ERROR_FILE_NOT_FOUND)
      return VMM_ENODEV;
    return VMM_ERROR;
  }
  return 0;
}

static int
hax_notify_qemu_version(vmm_vm_t vm)
{
  int ret_size;
  static const struct hax_qemu_version qemu_version = {0x2, 0x1};
  BOOL ret = DeviceIoControl(vm->vmfd,
    HAX_VM_IOCTL_NOTIFY_QEMU_VERSION,
    reinterpret_cast<LPVOID>(const_cast<struct hax_qemu_version *>(&qemu_version)), sizeof(struct hax_qemu_version),
    NULL, 0,
    reinterpret_cast<LPDWORD>( &ret_size),
    reinterpret_cast<LPOVERLAPPED>(NULL));
  if (!ret)
    return VMM_ERROR;
  return 0;
}

int
vmm_create(vmm_vm_t *ret)
{
  if (hax_dev == INVALID_HANDLE_VALUE) {
    int err = init_hax();
    if (err < 0)
      return err;
  }
  struct vmm_vm *vm = (struct vmm_vm *)malloc(sizeof(*vm));
  memset(vm, 0, sizeof(*vm));

  int ret_size;
  BOOL succ = DeviceIoControl(hax_dev, HAX_IOCTL_CREATE_VM, NULL, 0, &vm->vmid, sizeof(int), (LPDWORD)&ret_size, (LPOVERLAPPED)NULL);
  if (!succ)
    return VMM_ERROR; // We cannot convert it to more meaningful error due to lack of the document of HAXM

  char vm_dev_path[MAX_PATH];
  int str_size = snprintf(vm_dev_path, MAX_PATH, "\\\\.\\hax_vm%02d", vm->vmid);
  if (str_size > MAX_PATH)
    return VMM_ERROR;

  vm->vmfd = CreateFile(vm_dev_path,
    GENERIC_READ | GENERIC_WRITE,
    0,
    NULL,
    CREATE_ALWAYS,
    FILE_ATTRIBUTE_NORMAL,
    NULL);
  if (vm->vmfd == INVALID_HANDLE_VALUE)
    return VMM_ENORES;

  hax_notify_qemu_version(vm);
  INIT_LIST_HEAD(&vm->cpus);

  *ret = vm;
  return 0;
}

int
vmm_destroy(vmm_vm_t vm)
{
  struct list_head *p, *n;
  list_for_each_safe(p, n, &vm->cpus) {
    vmm_cpu_destroy(vm, list_entry(p, struct vmm_cpu, head));
  }
  CloseHandle(vm->vmfd);
  free(vm);

  return 0;
}

int
vmm_memory_map(vmm_vm_t vm, vmm_uvaddr_t uva, vmm_gpaddr_t gpa, size_t size, int prot)
{
  return -1;
}

int
vmm_memory_unmap(vmm_vm_t vm, vmm_gpaddr_t gpa, size_t size) 
{
  return -1;
}

int
vmm_memory_protect(vmm_vm_t vm, vmm_gpaddr_t gpa, size_t size, int prot)
{
  return -1;
}

int
vmm_memregion_set(vmm_vm_t vm, uint32_t reg_slot, vmm_uvaddr_t uva, vmm_gpaddr_t gpa, size_t size, int prot)
{
  return -1;
}

int
vmm_memregion_unset(vmm_vm_t vm, uint32_t reg_slot)
{
  return -1;
}

int
vmm_cpu_create(vmm_vm_t vm, vmm_cpu_t *cpu)
{
  return -1;
}

int
vmm_cpu_destroy(vmm_vm_t vm, vmm_cpu_t cpu)
{
  return -1;
}

int
vmm_cpu_run(vmm_vm_t vm, vmm_cpu_t cpu)
{
  return -1;
}

int
vmm_cpu_set_register(vmm_vm_t vm, vmm_cpu_t cpu, vmm_x64_reg_t reg, uint64_t value)
{
  return -1;
}

int
vmm_cpu_get_register(vmm_vm_t vm, vmm_cpu_t cpu, vmm_x64_reg_t reg, uint64_t *value)
{
  return -1;
}

int
vmm_cpu_get_msr(vmm_vm_t vm, vmm_cpu_t cpu, uint32_t msr, uint64_t *value)
{
  return -1;
}

int
vmm_cpu_set_msr(vmm_vm_t vm, vmm_cpu_t cpu, uint32_t msr, uint64_t value)
{
  return -1;
}

int
vmm_cpu_get_state(vmm_vm_t vm, vmm_cpu_t cpu, int id, uint64_t *value)
{
  return -1;
}

int
vmm_cpu_set_state(vmm_vm_t vm, vmm_cpu_t cpu, int id, uint64_t value)
{
  return -1;
}
