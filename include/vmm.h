#ifndef VMM_H
#define VMM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <errno.h>
#include "libhv_exports.h"

typedef int vmm_return_t;

#define VMM_SUCCESS 0
#define VMM_EBUSY   (-EBUSY)
#define VMM_EINVAL  (-EINVAL)
#define VMM_ENOMEM  (-ENOMEM)
#define VMM_ENODEV  (-ENODEV)
#define VMM_ENOTSUP (-ENOTSUP)
#define VMM_ERROR             (-200)  // Other General Error
#define VMM_ENORES            (-201)  // Can occur on Darwin
#define VMM_EGMEM_ALLOC_FAIL  (-202)  // Can occur on Windows
#define VMM_EUNKNOWN_VERSION  (-203)  // Can occur on Windows
#define VMM_INTERNAL_ERROR    (-204)  // Bug of Libhypervisor

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
  VMM_X64_CS_BASE,
  VMM_X64_CS_LIMIT,
  VMM_X64_CS_AR,
  VMM_X64_SS,
  VMM_X64_SS_BASE,
  VMM_X64_SS_LIMIT,
  VMM_X64_SS_AR,
  VMM_X64_DS,
  VMM_X64_DS_BASE,
  VMM_X64_DS_LIMIT,
  VMM_X64_DS_AR,
  VMM_X64_ES,
  VMM_X64_ES_BASE,
  VMM_X64_ES_LIMIT,
  VMM_X64_ES_AR,
  VMM_X64_FS,
  VMM_X64_FS_BASE,
  VMM_X64_FS_LIMIT,
  VMM_X64_FS_AR,
  VMM_X64_GS,
  VMM_X64_GS_BASE,
  VMM_X64_GS_LIMIT,
  VMM_X64_GS_AR,
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
  VMM_X64_CR8,
  VMM_X64_EFER,
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

enum {
  VMM_CTRL_EXIT_REASON,
  VMM_CTRL_NATIVE_EXIT_REASON,
};

enum {
  VMM_EXIT_HLT,
  VMM_EXIT_IO,
  VMM_EXIT_FAIL_ENTRY,
  VMM_EXIT_SHUTDOWN,
  VMM_EXIT_REASONS_MAX,
};

typedef struct vmm_vm *vmm_vm_t;

int EXTERN vmm_create(vmm_vm_t *vm);
int EXTERN vmm_destroy(vmm_vm_t vm);

typedef struct vmm_cpu *vmm_cpu_t;

int EXTERN vmm_cpu_create(vmm_vm_t vm, vmm_cpu_t *cpu);
int EXTERN vmm_cpu_destroy(vmm_vm_t vm, vmm_cpu_t cpu);
int EXTERN vmm_cpu_run(vmm_vm_t vm, vmm_cpu_t cpu);
int EXTERN vmm_cpu_get_register(vmm_vm_t vm, vmm_cpu_t cpu, vmm_x64_reg_t reg, uint64_t *value);
int EXTERN vmm_cpu_set_register(vmm_vm_t vm, vmm_cpu_t cpu, vmm_x64_reg_t reg, uint64_t value);
int EXTERN vmm_cpu_get_msr(vmm_vm_t vm, vmm_cpu_t cpu, uint32_t msr, uint64_t *value);
int EXTERN vmm_cpu_set_msr(vmm_vm_t vm, vmm_cpu_t cpu, uint32_t msr, uint64_t value);
int EXTERN vmm_cpu_get_state(vmm_vm_t vm, vmm_cpu_t cpu, int id, uint64_t *value);
int EXTERN vmm_cpu_set_state(vmm_vm_t vm, vmm_cpu_t cpu, int id, uint64_t value);

typedef const void *vmm_uvaddr_t;
typedef uint64_t vmm_gpaddr_t;


/* TODO: Abstract memory map management in Linux KVM */
#ifdef __APPLE__

int EXTERN vmm_memory_map(vmm_vm_t vm, vmm_uvaddr_t uva, vmm_gpaddr_t gpa, size_t size, int prot);
int EXTERN vmm_memory_unmap(vmm_vm_t vm, vmm_gpaddr_t gpa, size_t size);
int EXTERN vmm_memory_protect(vmm_vm_t vm, vmm_gpaddr_t gpa, size_t size, int prot);

#elif __linux__

#include <linux/kvm.h>
typedef struct kvm_userspace_memory_region *vmm_memregion_t;

int EXTERN vmm_memregion_set(vmm_vm_t vm, uint32_t reg_slot, vmm_uvaddr_t uva, vmm_gpaddr_t gpa, size_t size, int prot);
int EXTERN vmm_memregion_unset(vmm_vm_t vm, uint32_t reg_slot);
    
int EXTERN vmm_memory_map(vmm_vm_t vm, vmm_uvaddr_t uva, vmm_gpaddr_t gpa, size_t size, int prot) __attribute__ ((warning ("vmm_memory_map is not fully supported for KVM")));
int EXTERN vmm_memory_unmap(vmm_vm_t vm, vmm_gpaddr_t gpa, size_t size) __attribute__ ((error ("vmm_memory_unmap is not supported for KVM")));
int EXTERN vmm_memory_protect(vmm_vm_t vm, vmm_gpaddr_t gpa, size_t size, int prot) __attribute__ ((error ("vmm_memory_protect is not supported for KVM")));

#elif _WIN32

#include <vmm_prot.h>

int EXTERN vmm_memory_map(vmm_vm_t vm, vmm_uvaddr_t uva, vmm_gpaddr_t gpa, size_t size, int prot);
int EXTERN vmm_memory_unmap(vmm_vm_t vm, vmm_gpaddr_t gpa, size_t size);
int EXTERN vmm_memory_protect(vmm_vm_t vm, vmm_gpaddr_t gpa, size_t size, int prot);

#endif


#ifdef __cplusplus
}
#endif

#endif
