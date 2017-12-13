#include <Windows.h>
#include <fcntl.h>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>
#include <list>
#include <memory>

#include <vmm.h>
#include "list.h"
#include "haxm.h"

HANDLE hax_dev_fd = INVALID_HANDLE_VALUE;

struct vmm_vm {
  HANDLE vmfd;
  int vmid;
  std::list<struct vmm_cpu*> cpus;

  vmm_vm() : vmfd(INVALID_HANDLE_VALUE), vmid(0), cpus(std::list<struct vmm_cpu*>()) {};
};

struct vmm_cpu {
  HANDLE vcpufd;
  int vcpuid;
  struct hax_tunnel *tunnel;
  unsigned char *iobuf;

  vmm_cpu() : vcpufd(INVALID_HANDLE_VALUE), vcpuid(0), tunnel(NULL), iobuf(NULL) {};
};

static vmm_return_t
init_hax(void)
{
  hax_dev_fd = CreateFile("\\\\.\\HAX", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hax_dev_fd == INVALID_HANDLE_VALUE) {
    if (GetLastError() == ERROR_FILE_NOT_FOUND)
      return VMM_ENODEV;
    return VMM_ERROR;
  }
  return VMM_SUCCESS;
}

static vmm_return_t
hax_notify_qemu_version(HANDLE vmfd)
{
  int ret_size;
  static const struct hax_qemu_version qemu_version = {0x4, 0x4};
  BOOL succ = DeviceIoControl(vmfd,
    HAX_VM_IOCTL_NOTIFY_QEMU_VERSION,
    reinterpret_cast<LPVOID>(const_cast<struct hax_qemu_version *>(&qemu_version)), sizeof(struct hax_qemu_version),
    NULL, 0,
    reinterpret_cast<LPDWORD>(&ret_size),
    reinterpret_cast<LPOVERLAPPED>(NULL));
  if (!succ)
    return VMM_ERROR;
  return VMM_SUCCESS;
}

static vmm_return_t
hax_create_vm(int *vmid, HANDLE *vmfd)
{
  if (hax_dev_fd == INVALID_HANDLE_VALUE) {
    int err = init_hax();
    if (err < 0)
      return err;
  }

  int ret_size;
  BOOL succ = DeviceIoControl(hax_dev_fd, HAX_IOCTL_CREATE_VM, NULL, 0, vmid, sizeof(int), (LPDWORD)&ret_size, (LPOVERLAPPED)NULL);
  if (!succ)
    return VMM_ERROR; // We cannot convert it to more meaningful error due to lack of the document of HAXM

  char vm_dev_path[MAX_PATH];
  int str_size = snprintf(vm_dev_path, MAX_PATH, "\\\\.\\hax_vm%02d", *vmid);
  if (str_size > MAX_PATH)
    return VMM_ERROR;

  *vmfd = CreateFile(vm_dev_path,
    GENERIC_READ | GENERIC_WRITE,
    0,
    NULL,
    CREATE_ALWAYS,
    FILE_ATTRIBUTE_NORMAL,
    NULL);
  if (*vmfd == INVALID_HANDLE_VALUE)
    return VMM_ENORES;
  return VMM_SUCCESS;
}

static vmm_return_t
hax_close_vm(HANDLE vmfd)
{
  if (CloseHandle(vmfd))
    return VMM_SUCCESS;
  else
    return VMM_ERROR;
}

static vmm_return_t
hax_alloc_ram(HANDLE vmfd, uint64_t hva, uint32_t size)
{
  struct hax_alloc_ram_info ram_info = { size, 0, hva };
  DWORD dsize;
  BOOL succ = DeviceIoControl(vmfd,
    HAX_VM_IOCTL_ALLOC_RAM,
    &ram_info, sizeof(ram_info), NULL, 0, &dsize,
    (LPOVERLAPPED)NULL);
  if (!succ)
    return VMM_EGMEM_ALLOC_FAIL;
  return VMM_SUCCESS;
}

static vmm_return_t
hax_map_region(HANDLE vmfd, uint64_t uva, uint64_t gpa, uint32_t size, int flags)
{
  struct hax_set_ram_info ram_info = { gpa, size, flags, {0}, uva };
  DWORD dsize;
  BOOL succ = DeviceIoControl(vmfd,
    HAX_VM_IOCTL_SET_RAM,
    &ram_info,
    sizeof(ram_info),
    NULL, 0, &dsize,
    (LPOVERLAPPED)NULL);
  if (!succ)
    return VMM_ERROR;
  return VMM_SUCCESS;
}

static vmm_return_t
hax_setup_vcpu_tunnel(HANDLE vcpufd, struct hax_tunnel **tunnel, unsigned char **iobuf)
{
  DWORD dsize;
  struct hax_tunnel_info tunnel_info = {0};
  BOOL succ = DeviceIoControl(vcpufd,
    HAX_VCPU_IOCTL_SETUP_TUNNEL, NULL, 0,
    &tunnel_info, sizeof(tunnel_info), &dsize, (LPOVERLAPPED)NULL);
  if (!succ)
    return VMM_ERROR;
  if (dsize > sizeof(tunnel_info))
    return VMM_EUNKNOWN_VERSION;
  *tunnel = reinterpret_cast<struct hax_tunnel *>(tunnel_info.va);
  *iobuf = reinterpret_cast<unsigned char *>(tunnel_info.io_va);
  return VMM_SUCCESS;
}

static vmm_return_t
hax_create_vcpu(HANDLE vmfd, int vmid, HANDLE *vcpufd, int *vcpuid)
{
  DWORD dsize;
  BOOL succ = DeviceIoControl(vmfd,
    HAX_VM_IOCTL_VCPU_CREATE,
    vcpuid, sizeof(*vcpuid), NULL, 0,
    &dsize, (LPOVERLAPPED)NULL);
  if (!succ)
    return VMM_ERROR;
  *vcpuid = 0;

  char dev_path[MAX_PATH];
  int str_size = snprintf(dev_path, MAX_PATH, "\\\\.\\hax_vm%02d_vcpu%02d", vmid, *vcpuid);
  if (str_size > MAX_PATH)
    return VMM_ERROR;

  *vcpufd = CreateFile(dev_path,
    GENERIC_READ | GENERIC_WRITE,
    0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (*vcpufd == INVALID_HANDLE_VALUE)
    return VMM_ERROR;
  return VMM_SUCCESS;
}

static vmm_return_t
hax_set_vcpu_state(HANDLE vmfd, HANDLE vcpufd, struct vcpu_state_t *state)
{
  DWORD dsize;
  BOOL succ = DeviceIoControl(vcpufd,
    HAX_VCPU_IOCTL_SET_REGS,
    state, sizeof(*state),
    NULL, 0, &dsize, (LPOVERLAPPED)NULL);
  if (!succ)
    return VMM_ERROR;
  return VMM_SUCCESS;
}

static vmm_return_t
hax_get_vcpu_state(HANDLE vmfd, HANDLE vcpufd, struct vcpu_state_t *state)
{
  DWORD dsize;
  BOOL succ = DeviceIoControl(vcpufd,
    HAX_VCPU_IOCTL_GET_REGS,
    NULL, 0,
    state, sizeof(*state), &dsize, (LPOVERLAPPED)NULL);
  if (!succ)
    return VMM_ERROR;
  return VMM_SUCCESS;
}

static vmm_return_t
hax_run_vcpu(HANDLE vcpufd)
{
  DWORD dsize;
  BOOL succ = DeviceIoControl(vcpufd, HAX_VCPU_IOCTL_RUN, NULL, 0, NULL, 0, &dsize, (LPOVERLAPPED)NULL);
  if (!succ)
    return VMM_ERROR;
  return VMM_SUCCESS;
}

static vmm_return_t
hax_get_msrs(HANDLE vcpufd, struct hax_msr_data *msrs)
{
  DWORD dsize;
  BOOL succ = DeviceIoControl(vcpufd, HAX_VCPU_IOCTL_GET_MSRS, 
    msrs, sizeof(*msrs), msrs, sizeof(*msrs),
    &dsize, (LPOVERLAPPED)NULL);
  if (!succ)
    return VMM_ERROR;
  return VMM_SUCCESS;
}

static vmm_return_t
hax_set_msrs(HANDLE vcpufd, struct hax_msr_data *msrs)
{
  DWORD dsize;
  BOOL succ = DeviceIoControl(vcpufd, HAX_VCPU_IOCTL_SET_MSRS, 
    msrs, sizeof(*msrs), msrs, sizeof(*msrs),
    &dsize, (LPOVERLAPPED)NULL);
  if (!succ)
    return VMM_ERROR;
  return VMM_SUCCESS;
}

vmm_return_t
vmm_create(vmm_vm_t *ret)
{
  struct vmm_vm *vm = new struct vmm_vm;
  int err = hax_create_vm(&vm->vmid, &vm->vmfd);
  if (err < 0)
    return err;
  *ret = vm;
  err = hax_notify_qemu_version(vm->vmfd);
  if (err < 0)
    return err;
  return VMM_SUCCESS;
}

vmm_return_t
vmm_destroy(vmm_vm_t vm)
{
  int err = hax_close_vm(vm->vmfd);
  if (err < 0)
    return err;
  // TODO: delete vcpus
  delete vm;
  return VMM_SUCCESS;
}

vmm_return_t
vmm_memory_map(vmm_vm_t vm, vmm_uvaddr_t uva, vmm_gpaddr_t gpa, size_t size, int prot)
{
  vmm_return_t err;
  err = hax_alloc_ram(vm->vmfd, (uint64_t)uva, size);
  if (err < 0)
    return err;
  err = hax_map_region(vm->vmfd, (uint64_t)uva, gpa, size, 0);
  if (err < 0)
    return err;
  return VMM_SUCCESS;
}

vmm_return_t
vmm_memory_unmap(vmm_vm_t vm, vmm_gpaddr_t gpa, size_t size) 
{
  return VMM_ERROR;
}

vmm_return_t
vmm_memory_protect(vmm_vm_t vm, vmm_gpaddr_t gpa, size_t size, int prot)
{
  return VMM_ERROR;
}

vmm_return_t
vmm_cpu_create(vmm_vm_t vm, vmm_cpu_t *cpu)
{
  vmm_return_t ret;
  auto new_cpu = std::make_unique<struct vmm_cpu>();
  ret = hax_create_vcpu(vm->vmfd, vm->vmid, &new_cpu->vcpufd, &new_cpu->vcpuid);
  if (ret != VMM_SUCCESS)
    return ret;
  ret = hax_setup_vcpu_tunnel(new_cpu->vcpufd, &new_cpu->tunnel, &new_cpu->iobuf);
  if (ret != VMM_SUCCESS)
    return ret;
  *cpu = new_cpu.release();
  vm->cpus.push_back(*cpu);

  return VMM_SUCCESS;
}

vmm_return_t
vmm_cpu_destroy(vmm_vm_t vm, vmm_cpu_t cpu)
{
  return VMM_ERROR;
}

vmm_return_t
vmm_cpu_run(vmm_vm_t vm, vmm_cpu_t cpu)
{
  return hax_run_vcpu(cpu->vcpufd);
}

static inline uint64_t
gs_vcpu_state(int reg, struct vcpu_state_t *state, uint64_t value, bool sets)
{
#define SET_OR_GET(field) do {return sets ? ((field) = value) : (field);} while(0)
  switch (reg) {
  case VMM_X64_RIP:    SET_OR_GET(state->rip);
  case VMM_X64_RFLAGS: SET_OR_GET(state->rflags);
  case VMM_X64_RAX:    SET_OR_GET(state->rax);
  case VMM_X64_RBX:    SET_OR_GET(state->rbx);
  case VMM_X64_RCX:    SET_OR_GET(state->rcx);
  case VMM_X64_RDX:    SET_OR_GET(state->rdx);
  case VMM_X64_RSI:    SET_OR_GET(state->rsi);
  case VMM_X64_RDI:    SET_OR_GET(state->rdi);
  case VMM_X64_RSP:    SET_OR_GET(state->rsp);
  case VMM_X64_RBP:    SET_OR_GET(state->rbp);
  case VMM_X64_R8:     SET_OR_GET(state->r8);
  case VMM_X64_R9:     SET_OR_GET(state->r9);
  case VMM_X64_R10:    SET_OR_GET(state->r10);
  case VMM_X64_R11:    SET_OR_GET(state->r11);
  case VMM_X64_R12:    SET_OR_GET(state->r12);
  case VMM_X64_R13:    SET_OR_GET(state->r13);
  case VMM_X64_R14:    SET_OR_GET(state->r14);
  case VMM_X64_R15:    SET_OR_GET(state->r15);

  case VMM_X64_CS:        SET_OR_GET(state->cs.selector);
  case VMM_X64_CS_BASE:   SET_OR_GET(state->cs.base);
  case VMM_X64_CS_LIMIT:  SET_OR_GET(state->cs.limit);
  case VMM_X64_CS_AR:     SET_OR_GET(state->cs.ar);
  case VMM_X64_SS:        SET_OR_GET(state->ss.selector);
  case VMM_X64_SS_BASE:   SET_OR_GET(state->ss.base);
  case VMM_X64_SS_LIMIT:  SET_OR_GET(state->ss.limit);
  case VMM_X64_SS_AR:     SET_OR_GET(state->ss.ar);
  case VMM_X64_DS:        SET_OR_GET(state->ds.selector);
  case VMM_X64_DS_BASE:   SET_OR_GET(state->ds.base);
  case VMM_X64_DS_LIMIT:  SET_OR_GET(state->ds.limit);
  case VMM_X64_DS_AR:     SET_OR_GET(state->ds.ar);
  case VMM_X64_ES:        SET_OR_GET(state->es.selector);
  case VMM_X64_ES_BASE:   SET_OR_GET(state->es.base);
  case VMM_X64_ES_LIMIT:  SET_OR_GET(state->es.limit);
  case VMM_X64_ES_AR:     SET_OR_GET(state->es.ar);
  case VMM_X64_FS:        SET_OR_GET(state->fs.selector);
  case VMM_X64_FS_BASE:   SET_OR_GET(state->fs.base);
  case VMM_X64_FS_LIMIT:  SET_OR_GET(state->fs.limit);
  case VMM_X64_FS_AR:     SET_OR_GET(state->fs.ar);
  case VMM_X64_GS:        SET_OR_GET(state->gs.selector);
  case VMM_X64_GS_BASE:   SET_OR_GET(state->gs.base);
  case VMM_X64_GS_LIMIT:  SET_OR_GET(state->gs.limit);
  case VMM_X64_GS_AR:     SET_OR_GET(state->gs.ar);
  case VMM_X64_LDTR:      SET_OR_GET(state->ldt.selector);
  case VMM_X64_LDT_BASE:  SET_OR_GET(state->ldt.base);
  case VMM_X64_LDT_LIMIT: SET_OR_GET(state->ldt.limit);
  case VMM_X64_LDT_AR:    SET_OR_GET(state->ldt.ar);
  case VMM_X64_TR:        SET_OR_GET(state->tr.selector);
  case VMM_X64_TSS_BASE:  SET_OR_GET(state->tr.base);
  case VMM_X64_TSS_LIMIT: SET_OR_GET(state->tr.limit);
  case VMM_X64_TSS_AR:    SET_OR_GET(state->tr.ar);
  case VMM_X64_IDT_BASE:  SET_OR_GET(state->idt.base);
  case VMM_X64_IDT_LIMIT: SET_OR_GET(state->idt.limit);
  case VMM_X64_GDT_BASE:  SET_OR_GET(state->gdt.base);
  case VMM_X64_GDT_LIMIT: SET_OR_GET(state->gdt.limit);

  case VMM_X64_CR0:  SET_OR_GET(state->cr0);
  case VMM_X64_CR1:
    return VMM_EINVAL;
  case VMM_X64_CR2:  SET_OR_GET(state->cr2);
  case VMM_X64_CR3:  SET_OR_GET(state->cr3);
  case VMM_X64_CR4:  SET_OR_GET(state->cr4);
  case VMM_X64_CR8:
    return VMM_EINVAL;
  case VMM_X64_EFER: SET_OR_GET(state->efer);
  case VMM_X64_DR0:
  case VMM_X64_DR1:
  case VMM_X64_DR2:
  case VMM_X64_DR3:
  case VMM_X64_DR4:
  case VMM_X64_DR5:
  case VMM_X64_DR6:
  case VMM_X64_DR7:
  case VMM_X64_TPR:
  case VMM_X64_XCR0:
    assert(false); // TODO
  default:
    assert(false);
  }

  assert(false);
  return 0;
}

vmm_return_t
vmm_cpu_set_register(vmm_vm_t vm, vmm_cpu_t cpu, vmm_x64_reg_t reg, uint64_t value)
{
  struct vcpu_state_t state;
  vmm_return_t ret = hax_get_vcpu_state(vm->vmfd, cpu->vcpufd, &state);
  if (ret != VMM_SUCCESS)
    return ret;
  gs_vcpu_state(reg, &state, value, true);
  return hax_set_vcpu_state(vm->vmfd, cpu->vcpufd, &state);
}

vmm_return_t
vmm_cpu_get_register(vmm_vm_t vm, vmm_cpu_t cpu, vmm_x64_reg_t reg, uint64_t *value)
{
  struct vcpu_state_t state;
  vmm_return_t ret = hax_get_vcpu_state(vm->vmfd, cpu->vcpufd, &state);
  if (ret != VMM_SUCCESS)
    return ret;
  *value = gs_vcpu_state(reg, &state, 0, false);
  return VMM_SUCCESS;
}

vmm_return_t
vmm_cpu_get_msr(vmm_vm_t vm, vmm_cpu_t cpu, uint32_t msr, uint64_t *value)
{
  struct hax_msr_data msrs;
  msrs.done = 0;
  msrs.nr_msr = 1;
  msrs.entries[0].entry = msr;
  msrs.entries[0].value = 0;
  vmm_return_t ret = hax_get_msrs(cpu->vcpufd, &msrs);
  if (ret != VMM_SUCCESS)
    return ret;
  *value = msrs.entries[0].value;
  return VMM_SUCCESS;
}

vmm_return_t
vmm_cpu_set_msr(vmm_vm_t vm, vmm_cpu_t cpu, uint32_t msr, uint64_t value)
{
  struct hax_msr_data msrs;
  msrs.done = 0;
  msrs.nr_msr = 1;
  msrs.entries[0].entry = msr;
  msrs.entries[0].value = value;
  return hax_set_msrs(cpu->vcpufd, &msrs);
}

static inline int
to_vmm_exit_reason(uint32_t hax_exit_status)
{
  switch (hax_exit_status) {
  case HAX_EXIT_HLT: return VMM_EXIT_HLT;
  case HAX_EXIT_IO: return VMM_EXIT_IO;
  case HAX_EXIT_STATECHANGE: return VMM_EXIT_SHUTDOWN;
  default:
    fprintf(stderr, "Unexpected HAX's exit_status: %d\n", hax_exit_status);
    assert(false);
    return -1;
  }
}

vmm_return_t
vmm_cpu_get_state(vmm_vm_t vm, vmm_cpu_t cpu, int id, uint64_t *value)
{
  switch(id) {
  case VMM_CTRL_EXIT_REASON:
    *value = to_vmm_exit_reason(cpu->tunnel->exit_status);
    break;
  case VMM_CTRL_NATIVE_EXIT_REASON:
    *value = to_vmm_exit_reason(cpu->tunnel->exit_reason);
    break;
  default:
    fprintf(stderr, "Unsupported vcpu state id: %d\n", id);
    return VMM_ERROR;
  }
  return VMM_SUCCESS;
}

vmm_return_t
vmm_cpu_set_state(vmm_vm_t vm, vmm_cpu_t cpu, int id, uint64_t value)
{
  return VMM_ERROR;
}
