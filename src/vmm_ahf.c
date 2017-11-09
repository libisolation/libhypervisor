#include <vmm.h>
#include <Hypervisor/hv.h>
#include <sys/mman.h>

static int tr_ret(hv_return_t ret) {
  if (ret == HV_SUCCESS)      return 0;
  if (ret == HV_ERROR)        return VMM_ERROR;
  if (ret == HV_BUSY)         return VMM_EBUSY;
  if (ret == HV_BAD_ARGUMENT) return VMM_EINVAL;
  if (ret == HV_NO_RESOURCES) return VMM_ENORES;
  if (ret == HV_NO_DEVICE)    return VMM_ENODEV;
  if (ret == HV_UNSUPPORTED)  return VMM_ENOTSUP;
  return VMM_ERROR;
}

static hv_memory_flags_t tr_prot(int prot) {
  hv_memory_flags_t ret = 0;
  if (prot | PROT_READ) ret |= HV_MEMORY_READ;
  if (prot | PROT_WRITE) ret |= HV_MEMORY_WRITE;
  if (prot | PROT_EXEC) ret |= HV_MEMORY_EXEC;
  return ret;
}

int vmm_create(vmm_vm_t *vm) {
  return tr_ret(hv_vm_create(HV_VM_DEFAULT));
}

int vmm_destroy(vmm_vm_t vm) {
  return tr_ret(hv_vm_destroy());
}

int vmm_memory_map(vmm_vm_t vm, vmm_uvaddr_t uva, vmm_gpaddr_t gpa, size_t size, int prot) {
  return tr_ret(hv_vm_map(uva, gpa, size, tr_prot(prot)));
}

int vmm_memory_unmap(vmm_vm_t vm, vmm_gpaddr_t gpa, size_t size) {
  return tr_ret(hv_vm_unmap(gpa, size));
}

int vmm_memory_protect(vmm_vm_t vm, vmm_gpaddr_t gpa, size_t size, int prot) {
  return tr_ret(hv_vm_protect(gpa, size, tr_prot(prot)));
}

__thread unsigned vmm_vcpuid;

int vmm_cpu_create(vmm_vm_t vm, vmm_cpu_t *cpu) {
  return tr_ret(hv_vcpu_create(&vmm_vcpuid, HV_VCPU_DEFAULT));
}

int vmm_cpu_destroy(vmm_vm_t vm, vmm_cpu_t cpu) {
  return tr_ret(hv_vcpu_destroy(vmm_vcpuid));
}

int vmm_cpu_run(vmm_vm_t vm, vmm_cpu_t cpu) {
  return tr_ret(hv_vcpu_run(vmm_vcpuid));
}

static hv_x86_reg_t tr_reg(vmm_x64_reg_t reg) {
  switch (reg) {
#define CASE(NAME) case VMM_X64_##NAME: return HV_X86_##NAME;
   CASE(RIP)
   CASE(RFLAGS)
   CASE(RAX)
   CASE(RCX)
   CASE(RDX)
   CASE(RBX)
   CASE(RSI)
   CASE(RDI)
   CASE(RSP)
   CASE(RBP)
   CASE(R8)
   CASE(R9)
   CASE(R10)
   CASE(R11)
   CASE(R12)
   CASE(R13)
   CASE(R14)
   CASE(R15)
   CASE(CS)
   CASE(SS)
   CASE(DS)
   CASE(ES)
   CASE(FS)
   CASE(GS)
   CASE(IDT_BASE)
   CASE(IDT_LIMIT)
   CASE(GDT_BASE)
   CASE(GDT_LIMIT)
   CASE(LDTR)
   CASE(LDT_BASE)
   CASE(LDT_LIMIT)
   CASE(LDT_AR)
   CASE(TR)
   CASE(TSS_BASE)
   CASE(TSS_LIMIT)
   CASE(TSS_AR)
   CASE(CR0)
   CASE(CR1)
   CASE(CR2)
   CASE(CR3)
   CASE(CR4)
   CASE(DR0)
   CASE(DR1)
   CASE(DR2)
   CASE(DR3)
   CASE(DR4)
   CASE(DR5)
   CASE(DR6)
   CASE(DR7)
   CASE(TPR)
   CASE(XCR0)
   CASE(REGISTERS_MAX)
  }
}

int vmm_cpu_get_register(vmm_vm_t vm, vmm_cpu_t cpu, vmm_x64_reg_t reg, uint64_t *value) {
  return tr_ret(hv_vcpu_read_register(vmm_vcpuid, tr_reg(reg), value));
}

int vmm_cpu_set_register(vmm_vm_t vm, vmm_cpu_t cpu, vmm_x64_reg_t reg, uint64_t value) {
  return tr_ret(hv_vcpu_write_register(vmm_vcpuid, tr_reg(reg), value));
}

int vmm_cpu_get_msr(vmm_vm_t vm, vmm_cpu_t cpu, uint32_t msr, uint64_t *value) {
  return tr_ret(hv_vcpu_read_msr(vmm_vcpuid, msr, value));
}

int vmm_cpu_set_msr(vmm_vm_t vm, vmm_cpu_t cpu, uint32_t msr, uint64_t value) {
  return tr_ret(hv_vcpu_write_msr(vmm_vcpuid, msr, value));
}

int vmm_cpu_get_state(vmm_vm_t vm, vmm_cpu_t cpu, int id, uint64_t *value) {
  return -1;
}

int vmm_cpu_set_state(vmm_vm_t vm, vmm_cpu_t cpu, int id, uint64_t value) {
  return -1;
}
