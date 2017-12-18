#include <vmm.h>
#include <processor_flags.h>
#include <processor_msrs.h>

#include <Hypervisor/hv.h>
#include <Hypervisor/hv_vmx.h>
#include <Hypervisor/hv_arch_vmx.h>
#include <sys/mman.h>
#include <assert.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>


/*
 * Currently AHF does not support multiple VMs,
 * so ignoring arguments of vmm_vm_t type in all APIs
 */

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

static inline uint64_t
cap2ctrl(uint64_t cap, uint64_t ctrl)
{
  return (ctrl | (cap & 0xffffffff)) & (cap >> 32);
}

static int
init_vmcs()
{
  uint64_t vmx_cap_pinbased, vmx_cap_procbased, vmx_cap_procbased2, vmx_cap_entry;
  hv_return_t err = 0;

  err |= hv_vmx_read_capability(HV_VMX_CAP_PINBASED, &vmx_cap_pinbased);
  err |= hv_vmx_read_capability(HV_VMX_CAP_PROCBASED, &vmx_cap_procbased);
  err |= hv_vmx_read_capability(HV_VMX_CAP_PROCBASED2, &vmx_cap_procbased2);
  err |= hv_vmx_read_capability(HV_VMX_CAP_ENTRY, &vmx_cap_entry);

  /* set up vmcs */

#define VMCS_PRI_PROC_BASED_CTLS_HLT           (1 << 7)
#define VMCS_PRI_PROC_BASED_CTLS_CR8_LOAD      (1 << 19)
#define VMCS_PRI_PROC_BASED_CTLS_CR8_STORE     (1 << 20)

  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_CTRL_PIN_BASED, cap2ctrl(vmx_cap_pinbased, 0));
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_CTRL_CPU_BASED, cap2ctrl(vmx_cap_procbased,
                                                 VMCS_PRI_PROC_BASED_CTLS_HLT |
                                                 VMCS_PRI_PROC_BASED_CTLS_CR8_LOAD |
                                                 VMCS_PRI_PROC_BASED_CTLS_CR8_STORE));
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_CTRL_CPU_BASED2, cap2ctrl(vmx_cap_procbased2, 0));
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_CTRL_VMENTRY_CONTROLS, cap2ctrl(vmx_cap_entry, VMENTRY_LOAD_EFER));
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_CTRL_EXC_BITMAP, 0xffffffff);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_CTRL_CR0_MASK, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_CTRL_CR0_SHADOW, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_CTRL_CR4_MASK, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_CTRL_CR4_SHADOW, 0);

  /* set up cpu regs */

  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_CS, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_CS_BASE, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_CS_LIMIT, 0x10000);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_CS_AR, 0x9b);

  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_DS, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_DS_BASE, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_DS_LIMIT, 0xffff);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_DS_AR, 0x93);

  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_ES, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_ES_BASE, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_ES_LIMIT, 0xffff);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_ES_AR, 0x93);

  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_FS, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_FS_BASE, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_FS_LIMIT, 0xffff);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_FS_AR, 0x93);

  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_GS, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_GS_BASE, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_GS_LIMIT, 0xffff);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_GS_AR, 0x93);

  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_SS, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_SS_BASE, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_SS_LIMIT, 0xffff);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_SS_AR, 0x93);

  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_LDTR, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_LDTR_BASE, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_LDTR_LIMIT, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_LDTR_AR, 0x10000);

  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_TR, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_TR_BASE, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_TR_LIMIT, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_TR_AR, 0x83);

  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_GDTR_BASE, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_GDTR_LIMIT, 0);

  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_IDTR_BASE, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_IDTR_LIMIT, 0);

  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_CR0, X86_CR0_NE);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_CR3, 0);
  err |= hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_CR4, X86_CR4_VMXE);

/*
 * Workaround:
 * VM Entry fails in long mode for some reason 
 * unless you set these three MSRs to native values 
 * on Apple Hypervisor Framework.
 */

  err |= hv_vcpu_enable_native_msr(vmm_vcpuid, MSR_IA32_TIME_STAMP_COUNTER, 1);
  err |= hv_vcpu_enable_native_msr(vmm_vcpuid, MSR_IA32_KERNEL_GS_BASE, 1);
  err |= hv_vcpu_enable_native_msr(vmm_vcpuid, MSR_IA32_TSC_AUX, 1);


  if (err != HV_SUCCESS)
    err = HV_ERROR;
  return err;
}


int vmm_cpu_create(vmm_vm_t vm, vmm_cpu_t *cpu) {
  int err = tr_ret(hv_vcpu_create(&vmm_vcpuid, HV_VCPU_DEFAULT));
  if (err != 0)
    return err;
  return tr_ret(init_vmcs());
}

int vmm_cpu_destroy(vmm_vm_t vm, vmm_cpu_t cpu) {
  return tr_ret(hv_vcpu_destroy(vmm_vcpuid));
}

int vmm_cpu_run(vmm_vm_t vm, vmm_cpu_t cpu) {
  while (true) {
    hv_return_t err = hv_vcpu_run(vmm_vcpuid);
    if (err != HV_SUCCESS)
      return tr_ret(err);

    uint64_t exit_reason = 0;
    err = hv_vmx_vcpu_read_vmcs(vmm_vcpuid, VMCS_RO_EXIT_REASON, &exit_reason);
    if (err != HV_SUCCESS)
      return VMM_INTERNAL_ERROR;
    // TODO: Check if this memory region is mapped by a user
    if (exit_reason != VMX_REASON_EPT_VIOLATION)
      break;
  }
  return 0;
}

static inline hv_return_t
gs_vcpu_state(int reg, uint64_t *value, bool sets)
{
#define SET_OR_GET(field) do {return sets ? (hv_vmx_vcpu_write_vmcs(vmm_vcpuid, field, *value)) : hv_vmx_vcpu_read_vmcs(vmm_vcpuid, field, value);} while(0)
  switch (reg) {
  case VMM_X64_RIP:    SET_OR_GET(VMCS_GUEST_RIP);
  case VMM_X64_RSP:    SET_OR_GET(VMCS_GUEST_RSP);
  case VMM_X64_RFLAGS: SET_OR_GET(VMCS_GUEST_RFLAGS);

  case VMM_X64_CS:        SET_OR_GET(VMCS_GUEST_CS);
  case VMM_X64_CS_BASE:   SET_OR_GET(VMCS_GUEST_CS_BASE);
  case VMM_X64_CS_LIMIT:  SET_OR_GET(VMCS_GUEST_CS_LIMIT);
  case VMM_X64_CS_AR:     SET_OR_GET(VMCS_GUEST_CS_AR);
  case VMM_X64_SS:        SET_OR_GET(VMCS_GUEST_SS);
  case VMM_X64_SS_BASE:   SET_OR_GET(VMCS_GUEST_SS_BASE);
  case VMM_X64_SS_LIMIT:  SET_OR_GET(VMCS_GUEST_SS_LIMIT);
  case VMM_X64_SS_AR:     SET_OR_GET(VMCS_GUEST_SS_AR);
  case VMM_X64_DS:        SET_OR_GET(VMCS_GUEST_DS);
  case VMM_X64_DS_BASE:   SET_OR_GET(VMCS_GUEST_DS_BASE);
  case VMM_X64_DS_LIMIT:  SET_OR_GET(VMCS_GUEST_DS_LIMIT);
  case VMM_X64_DS_AR:     SET_OR_GET(VMCS_GUEST_DS_AR);
  case VMM_X64_ES:        SET_OR_GET(VMCS_GUEST_ES);
  case VMM_X64_ES_BASE:   SET_OR_GET(VMCS_GUEST_ES_BASE);
  case VMM_X64_ES_LIMIT:  SET_OR_GET(VMCS_GUEST_ES_LIMIT);
  case VMM_X64_ES_AR:     SET_OR_GET(VMCS_GUEST_ES_AR);
  case VMM_X64_FS:        SET_OR_GET(VMCS_GUEST_FS);
  case VMM_X64_FS_BASE:   SET_OR_GET(VMCS_GUEST_FS_BASE);
  case VMM_X64_FS_LIMIT:  SET_OR_GET(VMCS_GUEST_FS_LIMIT);
  case VMM_X64_FS_AR:     SET_OR_GET(VMCS_GUEST_FS_AR);
  case VMM_X64_GS:        SET_OR_GET(VMCS_GUEST_GS);
  case VMM_X64_GS_BASE:   SET_OR_GET(VMCS_GUEST_GS_BASE);
  case VMM_X64_GS_LIMIT:  SET_OR_GET(VMCS_GUEST_GS_LIMIT);
  case VMM_X64_GS_AR:     SET_OR_GET(VMCS_GUEST_GS_AR);
  case VMM_X64_LDTR:      SET_OR_GET(VMCS_GUEST_LDTR);
  case VMM_X64_LDT_BASE:  SET_OR_GET(VMCS_GUEST_LDTR_BASE);
  case VMM_X64_LDT_LIMIT: SET_OR_GET(VMCS_GUEST_LDTR_LIMIT);
  case VMM_X64_LDT_AR:    SET_OR_GET(VMCS_GUEST_LDTR_AR);
  case VMM_X64_TR:        SET_OR_GET(VMCS_GUEST_TR);
  case VMM_X64_TSS_BASE:  SET_OR_GET(VMCS_GUEST_TR_BASE);
  case VMM_X64_TSS_LIMIT: SET_OR_GET(VMCS_GUEST_TR_LIMIT);
  case VMM_X64_TSS_AR:    SET_OR_GET(VMCS_GUEST_TR_AR);
  case VMM_X64_IDT_BASE:  SET_OR_GET(VMCS_GUEST_IDTR_BASE);
  case VMM_X64_IDT_LIMIT: SET_OR_GET(VMCS_GUEST_IDTR_LIMIT);
  case VMM_X64_GDT_BASE:  SET_OR_GET(VMCS_GUEST_GDTR_BASE);
  case VMM_X64_GDT_LIMIT: SET_OR_GET(VMCS_GUEST_GDTR_LIMIT);

  // AHF (or VT-x) needs the guest's NE bit of CR0 and VMXE bit of CR4 set
  // to make VM entry succeed. So, set them by force
  case VMM_X64_CR0:
    if (sets) {
      *value |= X86_CR0_NE;
    }
    SET_OR_GET(VMCS_GUEST_CR0);
  case VMM_X64_CR1:  return VMM_EINVAL;
  case VMM_X64_CR3:  SET_OR_GET(VMCS_GUEST_CR3);
  case VMM_X64_CR4:
    if (sets) {
      *value |= X86_CR4_VMXE;
    }
    SET_OR_GET(VMCS_GUEST_CR4);
  case VMM_X64_CR8:  return VMM_EINVAL;

  // Change of EFER needs modification of the vmentry control
  case VMM_X64_EFER:
    if (sets) {
      uint64_t vmx_cap_entry, vmx_cap_exit;
      hv_return_t err;
      err = hv_vmx_read_capability(HV_VMX_CAP_ENTRY, &vmx_cap_entry);
      if (err != HV_SUCCESS)
        return err;
      err = hv_vmx_read_capability(HV_VMX_CAP_EXIT, &vmx_cap_exit);
      if (err != HV_SUCCESS)
        return err;
      if (*value & EFER_LME) {
        *value |= EFER_LME | EFER_LMA | EFER_NX;
        err = hv_vmx_vcpu_write_vmcs(
            vmm_vcpuid,
            VMCS_CTRL_VMENTRY_CONTROLS,
            cap2ctrl(vmx_cap_entry, VMENTRY_LOAD_EFER | VMENTRY_GUEST_IA32E)
        );
        if (err != HV_SUCCESS)
          return err;
        err = hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_CTRL_VMEXIT_CONTROLS, cap2ctrl(vmx_cap_exit, VMEXIT_LOAD_EFER));
      } else {
        *value &= ~(EFER_LME | EFER_LMA);
        err = hv_vmx_vcpu_write_vmcs(
            vmm_vcpuid,
            VMCS_CTRL_VMENTRY_CONTROLS,
            cap2ctrl(vmx_cap_entry, 0)
        );
        if (err != HV_SUCCESS)
          return err;
        err = hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_CTRL_VMEXIT_CONTROLS, cap2ctrl(vmx_cap_exit, 0));
      }
      if (err != HV_SUCCESS)
        return err;
    }
    SET_OR_GET(VMCS_GUEST_IA32_EFER);
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
  }
#undef SET_OR_GET
#define SET_OR_GET(field) do {return sets ? (hv_vcpu_write_register(vmm_vcpuid, field, *value)) : hv_vcpu_read_register(vmm_vcpuid, field, value);} while(0)
  switch (reg) {
  case VMM_X64_RAX:    SET_OR_GET(HV_X86_RAX);
  case VMM_X64_RBX:    SET_OR_GET(HV_X86_RBX);
  case VMM_X64_RCX:    SET_OR_GET(HV_X86_RCX);
  case VMM_X64_RDX:    SET_OR_GET(HV_X86_RDX);
  case VMM_X64_RSI:    SET_OR_GET(HV_X86_RSI);
  case VMM_X64_RDI:    SET_OR_GET(HV_X86_RDI);
  case VMM_X64_RBP:    SET_OR_GET(HV_X86_RBP);
  case VMM_X64_R8:     SET_OR_GET(HV_X86_R8);
  case VMM_X64_R9:     SET_OR_GET(HV_X86_R9);
  case VMM_X64_R10:    SET_OR_GET(HV_X86_R10);
  case VMM_X64_R11:    SET_OR_GET(HV_X86_R11);
  case VMM_X64_R12:    SET_OR_GET(HV_X86_R12);
  case VMM_X64_R13:    SET_OR_GET(HV_X86_R13);
  case VMM_X64_R14:    SET_OR_GET(HV_X86_R14);
  case VMM_X64_R15:    SET_OR_GET(HV_X86_R15);
  case VMM_X64_CR2:  SET_OR_GET(HV_X86_CR2);
  }

  assert(false);
  return 0;
}

int vmm_cpu_get_register(vmm_vm_t vm, vmm_cpu_t cpu, vmm_x64_reg_t reg, uint64_t *value) {
  return tr_ret(gs_vcpu_state(reg, value, false));
}

int vmm_cpu_set_register(vmm_vm_t vm, vmm_cpu_t cpu, vmm_x64_reg_t reg, uint64_t value) {
  return tr_ret(gs_vcpu_state(reg, &value, true));
}

int vmm_cpu_get_msr(vmm_vm_t vm, vmm_cpu_t cpu, uint32_t msr, uint64_t *value) {
  return tr_ret(hv_vcpu_read_msr(vmm_vcpuid, msr, value));
}

int vmm_cpu_set_msr(vmm_vm_t vm, vmm_cpu_t cpu, uint32_t msr, uint64_t value) {
  if (msr == MSR_IA32_TIME_STAMP_COUNTER ||
      msr == MSR_IA32_KERNEL_GS_BASE ||
      msr == MSR_IA32_TSC_AUX) {
    hv_return_t err = hv_vcpu_enable_native_msr(vmm_vcpuid, msr, 0);
    if (err != HV_SUCCESS) {
      return tr_ret(err);
    }
  }
  return tr_ret(hv_vcpu_write_msr(vmm_vcpuid, msr, value));
}

static hv_return_t inc_rip_to_next(void) {
  uint64_t rip, instlen;
  hv_return_t err = hv_vmx_vcpu_read_vmcs(vmm_vcpuid, VMCS_GUEST_RIP, &rip);
  if (err != HV_SUCCESS)
    return tr_ret(err);
  err = hv_vmx_vcpu_read_vmcs(vmm_vcpuid, VMCS_RO_VMEXIT_INSTR_LEN, &instlen);
  if (err != HV_SUCCESS)
    return tr_ret(err);
  err = hv_vmx_vcpu_write_vmcs(vmm_vcpuid, VMCS_GUEST_RIP, rip + instlen);
  if (err != HV_SUCCESS)
    return tr_ret(err);
  return HV_SUCCESS;
}

int vmm_cpu_get_state(vmm_vm_t vm, vmm_cpu_t cpu, int id, uint64_t *value) {
  switch (id) {
    case VMM_CTRL_EXIT_REASON: {
      uint64_t exit_reason = 0;
      hv_return_t err = hv_vmx_vcpu_read_vmcs(vmm_vcpuid, VMCS_RO_EXIT_REASON, &exit_reason);
      if (err != HV_SUCCESS)
        return tr_ret(err);

      if ((0x1ULL << 31) & exit_reason) {
        *value = VMM_EXIT_FAIL_ENTRY;
        break;
      }
      switch (exit_reason) {
        case VMX_REASON_HLT: 
          *value = VMM_EXIT_HLT; 
          break;
        case VMX_REASON_IO:
          inc_rip_to_next();
          *value = VMM_EXIT_IO; 
          break;
        default:
          *value = VMM_EXIT_REASONS_MAX;
          fprintf(stderr, "UNKOWN EXIT_REASON: 0x%llx\n", exit_reason);
          assert(false);
          return -1;
      }
      break;
    }
    default:
      return VMM_EINVAL;
  }
  return 0;
}
