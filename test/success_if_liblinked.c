#include <vmm.h>
#include <assert.h>

int main() {
  void *vmm_create_addr = vmm_create;
  assert((*(char *) vmm_create_addr) == (*(char *) vmm_create_addr));  // Ensure it can access the library
  return 0;
}
