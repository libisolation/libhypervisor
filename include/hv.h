#ifndef HV_H
#define HV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef unsigned vmm_return_t;
typedef unsigned vmm_vcpuid_t;
typedef uint64_t vmm_uvaddr_t, vmm_gpaddr_t;
typedef uint64_t vmm_vmem_flags_t, vmm_vcpu_flags_t;

typedef enum {
  VMM_X86_RIP,
  VMM_X86_RFLAGS,
  VMM_X86_RAX,
  VMM_X86_RCX,
  VMM_X86_RDX,
  VMM_X86_RBX,
  VMM_X86_RSI,
  VMM_X86_RDI,
  VMM_X86_RSP,
  VMM_X86_RBP,
  VMM_X86_R8,
  VMM_X86_R9,
  VMM_X86_R10,
  VMM_X86_R11,
  VMM_X86_R12,
  VMM_X86_R13,
  VMM_X86_R14,
  VMM_X86_R15,
  VMM_X86_CS,
  VMM_X86_SS,
  VMM_X86_DS,
  VMM_X86_ES,
  VMM_X86_FS,
  VMM_X86_GS,
  VMM_X86_IDT_BASE,
  VMM_X86_IDT_LIMIT,
  VMM_X86_GDT_BASE,
  VMM_X86_GDT_LIMIT,
  VMM_X86_LDTR,
  VMM_X86_LDT_BASE,
  VMM_X86_LDT_LIMIT,
  VMM_X86_LDT_AR,
  VMM_X86_TR,
  VMM_X86_TSS_BASE,
  VMM_X86_TSS_LIMIT,
  VMM_X86_TSS_AR,
  VMM_X86_CR0,
  VMM_X86_CR1,
  VMM_X86_CR2,
  VMM_X86_CR3,
  VMM_X86_CR4,
  VMM_X86_DR0,
  VMM_X86_DR1,
  VMM_X86_DR2,
  VMM_X86_DR3,
  VMM_X86_DR4,
  VMM_X86_DR5,
  VMM_X86_DR6,
  VMM_X86_DR7,
  VMM_X86_TPR,
  VMM_X86_XCR0,
  VMM_X86_REGISTERS_MAX,
} vmm_x86_reg_t;

vmm_return_t vmm_vm_create(void);
vmm_return_t vmm_vm_destroy(void);

vmm_return_t vmm_vmem_map(vmm_uvaddr_t uva, vmm_gpaddr_t gpa, size_t size, vmm_vmem_flags_t flags);
vmm_return_t vmm_vmem_unmap(vmm_gpaddr_t gpa, size_t size);
vmm_return_t vmm_vmem_protect(vmm_gpaddr_t gpa, size_t size, vmm_vmem_flags_t flags);

vmm_return_t vmm_vcpu_create(vmm_vcpuid_t *vcpu);
vmm_return_t vmm_vcpu_destroy(vmm_vcpuid_t vcpu);

vmm_return_t vmm_vcpu_read_register(vmm_vcpuid_t vcpu, vmm_x86_reg_t reg, uint64_t *value);
vmm_return_t vmm_vcpu_write_register(vmm_vcpuid_t vcpu, vmm_x86_reg_t reg, uint64_t value);

vmm_return_t vmm_vcpu_enable_native_msr(vmm_vcpuid_t vcpu, uint32_t msr, bool enable);
vmm_return_t vmm_vcpu_read_msr(vmm_vcpuid_t vcpu, uint32_t msr, uint64_t *value);
vmm_return_t vmm_vcpu_write_msr(vmm_vcpuid_t vcpu, uint32_t msr, uint64_t value);

vmm_return_t vmm_vcpu_invalidate_tlb(vmm_vcpuid_t vcpu);
vmm_return_t vmm_vcpu_run(vmm_vcpuid_t vcpu);
vmm_return_t vmm_vcpu_interrupt(vmm_vcpuid_t* vcpus, unsigned int vcpu_count);

#ifdef __cplusplus
}
#endif

#endif
