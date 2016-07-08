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
typedef const void *vmm_uvaddr_t;
typedef uint64_t vmm_gpaddr_t;
typedef uint64_t vmm_vmem_flags_t, vmm_vcpu_flags_t;

typedef enum {
  VMM_X64_RIP,
  VMM_X64_RFLAGS,
  VMM_X64_RAX,
  VMM_X64_RCX,
  VMM_X64_RDX,
  VMM_X64_RBX,
  VMM_X64_RSI,
  VMM_X64_RDI,
  VMM_X64_RSP,
  VMM_X64_RBP,
  VMM_X64_R8,
  VMM_X64_R9,
  VMM_X64_R10,
  VMM_X64_R11,
  VMM_X64_R12,
  VMM_X64_R13,
  VMM_X64_R14,
  VMM_X64_R15,
  VMM_X64_CS,
  VMM_X64_SS,
  VMM_X64_DS,
  VMM_X64_ES,
  VMM_X64_FS,
  VMM_X64_GS,
  VMM_X64_IDT_BASE,
  VMM_X64_IDT_LIMIT,
  VMM_X64_GDT_BASE,
  VMM_X64_GDT_LIMIT,
  VMM_X64_LDTR,
  VMM_X64_LDT_BASE,
  VMM_X64_LDT_LIMIT,
  VMM_X64_LDT_AR,
  VMM_X64_TR,
  VMM_X64_TSS_BASE,
  VMM_X64_TSS_LIMIT,
  VMM_X64_TSS_AR,
  VMM_X64_CR0,
  VMM_X64_CR1,
  VMM_X64_CR2,
  VMM_X64_CR3,
  VMM_X64_CR4,
  VMM_X64_DR0,
  VMM_X64_DR1,
  VMM_X64_DR2,
  VMM_X64_DR3,
  VMM_X64_DR4,
  VMM_X64_DR5,
  VMM_X64_DR6,
  VMM_X64_DR7,
  VMM_X64_TPR,
  VMM_X64_XCR0,
  VMM_X64_REGISTERS_MAX,
} vmm_x64_reg_t;

vmm_return_t vmm_create(void);
vmm_return_t vmm_destroy(void);

vmm_return_t vmm_vmem_map(vmm_uvaddr_t uva, vmm_gpaddr_t gpa, size_t size, vmm_vmem_flags_t flags);
vmm_return_t vmm_vmem_unmap(vmm_gpaddr_t gpa, size_t size);
vmm_return_t vmm_vmem_protect(vmm_gpaddr_t gpa, size_t size, vmm_vmem_flags_t flags);

vmm_return_t vmm_vcpu_create(vmm_vcpuid_t *vcpu);
vmm_return_t vmm_vcpu_destroy(vmm_vcpuid_t vcpu);
vmm_return_t vmm_vcpu_run(vmm_vcpuid_t vcpu);
vmm_return_t vmm_vcpu_interrupt(vmm_vcpuid_t* vcpus, unsigned int vcpu_count);
vmm_return_t vmm_vcpu_invalidate_tlb(vmm_vcpuid_t vcpu);
vmm_return_t vmm_vcpu_read_register(vmm_vcpuid_t vcpu, vmm_x64_reg_t reg, uint64_t *value);
vmm_return_t vmm_vcpu_write_register(vmm_vcpuid_t vcpu, vmm_x64_reg_t reg, uint64_t value);
vmm_return_t vmm_vcpu_read_msr(vmm_vcpuid_t vcpu, uint32_t msr, uint64_t *value);
vmm_return_t vmm_vcpu_write_msr(vmm_vcpuid_t vcpu, uint32_t msr, uint64_t value);

#ifdef __cplusplus
}
#endif

#endif
