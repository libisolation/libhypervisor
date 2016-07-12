/* Sample code for /dev/kvm API
 *
 * Copyright (c) 2016 Yuichi Nishiwaki
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

#include <hv.h>

int main(void)
{
  int kvm, vmfd, ret;
  unsigned cpu;
  const uint8_t code[] = {
    0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
    0x00, 0xd8,       /* add %bl, %al */
    0x04, '0',        /* add $'0', %al */
    0xee,             /* out %al, (%dx) */
    0xb0, '\n',       /* mov $'\n', %al */
    0xee,             /* out %al, (%dx) */
    0xf4,             /* hlt */
  };
  uint8_t *mem;
  struct kvm_sregs sregs;
  size_t mmap_size;

  vmm_create();

  /* Allocate one aligned page of guest memory to hold the code. */
  mem = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (!mem)
    err(1, "allocating guest memory");
  memcpy(mem, code, sizeof(code));

  /* Map it to the second page frame (to avoid the real-mode IDT at 0). */
  vmm_memory_map(mem, 0x1000, 0x1000, 0);

  vmm_cpu_create(&cpu);

  /*
   * Initialize CS to point at 0, via a read-modify-write of sregs.
   * Initialize registers: instruction pointer for our code, addends, and
   * initial flags required by x86 architecture.
   */
  vmm_cpu_write_register(cpu, VMM_X64_CS, 0);
  vmm_cpu_write_register(cpu, VMM_X64_RIP, 0x1000);
  vmm_cpu_write_register(cpu, VMM_X64_RAX, 2);
  vmm_cpu_write_register(cpu, VMM_X64_RBX, 2);
  vmm_cpu_write_register(cpu, VMM_X64_RFLAGS, 0x2);

  /* Repeatedly run code and handle VM exits. */
  while (1) {
    vmm_cpu_run(cpu);
    switch (run->exit_reason) {
    case KVM_EXIT_HLT:
      puts("KVM_EXIT_HLT");
      return 0;
    case KVM_EXIT_IO:
      if (run->io.direction == KVM_EXIT_IO_OUT && run->io.size == 1 && run->io.port == 0x3f8 && run->io.count == 1)
        putchar(*(((char *)run) + run->io.data_offset));
      else
        errx(1, "unhandled KVM_EXIT_IO");
      break;
    case KVM_EXIT_FAIL_ENTRY:
      errx(1, "KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x%llx",
           (unsigned long long)run->fail_entry.hardware_entry_failure_reason);
    case KVM_EXIT_INTERNAL_ERROR:
      errx(1, "KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x", run->internal.suberror);
    default:
      errx(1, "exit_reason = 0x%x", run->exit_reason);
    }
  }
}
