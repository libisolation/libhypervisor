#include "hv.h"
#include <Hypervisor/hv.h>

vmm_return_t vmm_create(void) {
  return hv_vm_create(HV_VM_DEFAULT);
}
