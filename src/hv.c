#include "hv.h"
#include <Hypervisor/hv.h>

vmm_return_t vmm_create(void) {
  return hv_vm_create(HV_VM_DEFAULT);
}

vmm_return_t vmm_destroy(void) {
  return hv_vm_destroy();
}

vmm_return_t vmm_vmem_map(vmm_uvaddr_t uva, vmm_gpaddr_t gpa, size_t size, vmm_vmem_flags_t flags) {
  return hv_vm_map(uva, gpa, size, flags);
}

vmm_return_t vmm_vmem_unmap(vmm_gpaddr_t gpa, size_t size) {
  return hv_vm_unmap(gpa, size);
}

vmm_return_t vmm_vmem_protect(vmm_gpaddr_t gpa, size_t size, vmm_vmem_flags_t flags) {
  return hv_vm_protect(gpa, size, flags);
}

vmm_return_t vmm_vcpu_create(vmm_vcpuid_t *vcpu) {
  return hv_vcpu_create(vcpu, HV_VCPU_DEFAULT);
}

vmm_return_t vmm_vcpu_destroy(vmm_vcpuid_t vcpu) {
  return hv_vcpu_destroy(vcpu);
}

vmm_return_t vmm_vcpu_run(vmm_vcpuid_t vcpu) {
  return hv_vcpu_run(vcpu);
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

vmm_return_t vmm_vcpu_read_register(vmm_vcpuid_t vcpu, vmm_x64_reg_t reg, uint64_t *value) {
  return hv_vcpu_read_register(vcpu, tr_reg(reg), value);
}

vmm_return_t vmm_vcpu_write_register(vmm_vcpuid_t vcpu, vmm_x64_reg_t reg, uint64_t value) {
  return hv_vcpu_write_register(vcpu, tr_reg(reg), value);
}

vmm_return_t vmm_vcpu_read_msr(vmm_vcpuid_t vcpu, uint32_t msr, uint64_t *value) {
  return hv_vcpu_read_msr(vcpu, msr, value);
}

vmm_return_t vmm_vcpu_write_msr(vmm_vcpuid_t vcpu, uint32_t msr, uint64_t value) {
  return hv_vcpu_write_msr(vcpu, msr, value);
}

