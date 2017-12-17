/* Sample code for /dev/kvm API
 *
 * Copyright (c) 2016 Yuichi Nishiwaki, Takaya Saeki
 *
 * Copyright (c) 2015 Intel Corporation
 * Author: Josh Triplett <josh@joshtriplett.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <vmm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <inttypes.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#ifdef _WIN32
void *memalloc(size_t size)
{
  return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}
#else
void *memalloc(size_t size)
{
  return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
}
#endif

int main(void)
{
  // Add rax + rbx (they both are 2, so the answer is 4)
  // and out it as ascii by adding '0' to it
  const uint8_t code[] = {
    0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
    0x00, 0xd8,       /* add %bl, %al */
    0x04, '0',        /* add $'0', %al */
    0xee,             /* out %al, (%dx) */
    0xf4,             /* hlt */
  };
  uint8_t *mem;
  int ret;
  vmm_vm_t vm;
  ret = vmm_create(&vm);
  assert(ret == 0);

  /* Allocate one aligned page of guest memory to hold the code. */
  mem = memalloc(0x1000);
  if (!mem) {
    fprintf(stderr, "allocating guest memory");
    abort();
  }
  memcpy(mem, code, sizeof(code));

  /* Map it to the second page frame (to avoid the real-mode IDT at 0). */
  ret = vmm_memory_map(vm, mem, 0x1000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
  assert(ret == 0);

  vmm_cpu_t cpu;
  ret = vmm_cpu_create(vm, &cpu);
  assert(ret == 0);

  ret |= vmm_cpu_set_register(vm, cpu, VMM_X64_CS, 0);
  ret |= vmm_cpu_set_register(vm, cpu, VMM_X64_CS_BASE, 0);
  ret |= vmm_cpu_set_register(vm, cpu, VMM_X64_RIP, 0x1000);
  ret |= vmm_cpu_set_register(vm, cpu, VMM_X64_RAX, 2);
  ret |= vmm_cpu_set_register(vm, cpu, VMM_X64_RBX, 2);
  ret |= vmm_cpu_set_register(vm, cpu, VMM_X64_RFLAGS, 0x2);
  assert(ret == 0);

  /* Repeatedly run code and handle VM exits. */
  while (1) {
    uint64_t exit_reason, value;
    ret = vmm_cpu_run(vm, cpu);
    assert(ret == 0);
    ret = vmm_cpu_get_state(vm, cpu, VMM_CTRL_EXIT_REASON, &exit_reason);
    assert(ret == 0);
    switch (exit_reason) {
    case VMM_EXIT_HLT:
      puts("KVM_EXIT_HLT");
      return 0;
    case VMM_EXIT_IO:
      ret = vmm_cpu_get_register(vm, cpu, VMM_X64_RAX, &value);
      assert(ret == 0);
      assert((char) value == '4'); // 2 + 2 as a char
      putchar((char) value);
      break;
    case VMM_EXIT_FAIL_ENTRY:
      fprintf(stderr, "KVM_EXIT_FAIL_ENTRY\n");
      abort();
    default:
      ret = vmm_cpu_get_register(vm, cpu, VMM_X64_RIP, &value);
      assert(ret == 0);
      fprintf(stderr, "ip = 0x%" PRIu64 "\n", value);
      fprintf(stderr, "exit_reason = 0x%" PRIu64 "\n", exit_reason);
      abort();
    }
  }
}
