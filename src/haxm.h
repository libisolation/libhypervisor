#ifndef LIBHV_HAXM_H
#define LIBHV_HAXM_H

#include <stdint.h>
#include <winioctl.h>

struct fx_layout {
  uint16_t fcw;
  uint16_t fsw;
  uint8_t ftw;
  uint8_t res1;
  uint16_t fop;
  union {
    struct {
      uint32_t fip;
      uint16_t fcs;
      uint16_t res2;
    };
    uint64_t fpu_ip;
  };
  union {
    struct {
      uint32_t fdp;
      uint16_t fds;
      uint16_t res3;
    };
    uint64_t fpu_dp;
  };
  uint32_t mxcsr;
  uint32_t mxcsr_mask;
  uint8_t st_mm[8][16];
  uint8_t mmx_1[8][16];
  uint8_t mmx_2[8][16];
  uint8_t pad[96];
};

struct vmx_msr {
  uint64_t entry;
  uint64_t value;
};

#define HAX_MAX_MSR_ARRAY 0x20
struct hax_msr_data
{
  uint16_t nr_msr;
  uint16_t done;
  uint16_t pad[2];
  struct vmx_msr entries[HAX_MAX_MSR_ARRAY];
};

union interruptibility_state_t {
  uint32_t raw;
  struct {
    uint32_t sti_blocking   : 1;
    uint32_t movss_blocking : 1;
    uint32_t smi_blocking   : 1;
    uint32_t nmi_blocking   : 1;
    uint32_t reserved       : 28;
  };
  uint64_t pad;
};

typedef union interruptibility_state_t interruptibility_state_t;

struct segment_desc_t {
  uint16_t selector;
  uint16_t unused;
  uint32_t limit;
  uint64_t base;
  union {
    struct {
      uint32_t type          : 4;
      uint32_t desc          : 1;
      uint32_t dpl           : 2;
      uint32_t present       : 1;
      uint32_t pad1          : 4;
      uint32_t available     : 1;
      uint32_t long_mode     : 1;
      uint32_t operand_size  : 1;
      uint32_t granularity   : 1;
      uint32_t null          : 1;
      uint32_t pad2          : 15;
    };
    uint32_t ar;
  };
  uint32_t ipad;
};

typedef struct segment_desc_t segment_desc_t;

struct vcpu_state_t
{
  union {
    uint64_t regs[16];
    struct {
      union {
        struct {
          uint8_t al;
          uint8_t ah;
        };
        uint16_t ax;
        uint32_t eax;
        uint64_t rax;
      };
      union {
        struct {
          uint8_t cl;
          uint8_t ch;
        };
        uint16_t cx;
        uint32_t ecx;
        uint64_t rcx;
      };
      union {
        struct {
          uint8_t dl;
          uint8_t dh;
        };
        uint16_t dx;
        uint32_t edx;
        uint64_t rdx;
      };
      union {
        struct {
          uint8_t bl;
          uint8_t bh;
        };
        uint16_t bx;
        uint32_t ebx;
        uint64_t rbx;
      };
      union {
        uint16_t sp;
        uint32_t esp;
        uint64_t rsp;
      };
      union {
        uint16_t bp;
        uint32_t ebp;
        uint64_t rbp;
      };
      union {
        uint16_t si;
        uint32_t esi;
        uint64_t rsi;
      };
      union {
        uint16_t di;
        uint32_t edi;
        uint64_t rdi;
      };

      uint64_t r8;
      uint64_t r9;
      uint64_t r10;
      uint64_t r11;
      uint64_t r12;
      uint64_t r13;
      uint64_t r14;
      uint64_t r15;
    };
  };

  union {
    uint32_t eip;
    uint64_t rip;
  };

  union {
    uint32_t eflags;
    uint64_t rflags;
  };

  segment_desc_t cs;
  segment_desc_t ss;
  segment_desc_t ds;
  segment_desc_t es;
  segment_desc_t fs;
  segment_desc_t gs;
  segment_desc_t ldt;
  segment_desc_t tr;

  segment_desc_t gdt;
  segment_desc_t idt;

  uint64_t cr0;
  uint64_t cr2;
  uint64_t cr3;
  uint64_t cr4;

  uint64_t dr0;
  uint64_t dr1;
  uint64_t dr2;
  uint64_t dr3;
  uint64_t dr6;
  uint64_t dr7;
  uint64_t pde;

  uint32_t efer;

  uint32_t sysenter_cs;
  uint64_t sysenter_eip;
  uint64_t sysenter_esp;

  uint32_t activity_state;
  uint32_t pad;
  interruptibility_state_t interruptibility_state;
};

struct hax_tunnel
{
  uint32_t exit_reason;
  uint32_t exit_flag;
  uint32_t exit_status;
  uint32_t user_event_pending;
  int ready_for_interrupt_injection;
  int request_interrupt_window;
  union {
    struct {
#define HAX_EXIT_IO_IN  1
#define HAX_EXIT_IO_OUT 0
      uint8_t direction;
      uint8_t df;
      uint16_t size;
      uint16_t port;
      uint16_t count;
      uint8_t flags;
      uint8_t pad0;
      uint16_t pad1;
      uint32_t pad2;
      uint64_t vaddr;
    } pio;
    struct {
      uint64_t gla;
    } mmio;
  };
};

struct hax_tunnel_info
{
  uint64_t va;
  uint64_t io_va;
  uint16_t size;
  uint16_t pad[3];
};

enum exit_status {
  HAX_EXIT_IO = 1,
  HAX_EXIT_MMIO,
  HAX_EXIT_REAL,
  HAX_EXIT_INTERRUPT,
  HAX_EXIT_UNKNOWN_VMEXIT,
  HAX_EXIT_HLT,
  HAX_EXIT_STATECHANGE,
  HAX_EXIT_PAUSED,
  HAX_EXIT_FAST_MMIO,
};

struct hax_module_version
{
  uint32_t compat_version;
  uint32_t cur_version;
};

struct hax_qemu_version
{
  uint32_t cur_version;
  uint32_t least_version;
};

struct hax_alloc_ram_info
{
  uint32_t size;
  uint32_t pad;
  uint64_t va;
};

#define HAX_RAM_INFO_ROM 0x1
struct hax_set_ram_info
{
  uint64_t pa_start;
  uint32_t size;
  uint8_t flags;
  uint8_t pad[3];
  uint64_t va;
};

struct hax_capabilityinfo
{
#define HAX_CAP_STATUS_WORKING  0x1
#define HAX_CAP_STATUS_NOTWORKING  0x0
#define HAX_CAP_WORKSTATUS_MASK 0x1
#define HAX_CAP_MEMQUOTA    0x2
  uint16_t wstatus;
#define HAX_CAP_FAILREASON_VT   0x1
#define HAX_CAP_FAILREASON_NX   0x2
  uint16_t winfo;
  uint32_t pad;
  uint64_t mem_quota;
};

struct hax_fastmmio
{
  uint64_t gpa;
  uint64_t value;
  uint8_t size;
  uint8_t direction;
  uint16_t reg_index;
  uint32_t pad0;
  uint64_t cr0;
  uint64_t cr2;
  uint64_t cr3;
  uint64_t cr4;
};

#define HAX_DEVICE_TYPE 0x4000

#define HAX_IOCTL_VERSION                 CTL_CODE(HAX_DEVICE_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define HAX_IOCTL_CREATE_VM               CTL_CODE(HAX_DEVICE_TYPE, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define HAX_IOCTL_CAPABILITY              CTL_CODE(HAX_DEVICE_TYPE, 0x910, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define HAX_VM_IOCTL_VCPU_CREATE          CTL_CODE(HAX_DEVICE_TYPE, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define HAX_VM_IOCTL_ALLOC_RAM            CTL_CODE(HAX_DEVICE_TYPE, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define HAX_VM_IOCTL_SET_RAM              CTL_CODE(HAX_DEVICE_TYPE, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define HAX_VCPU_IOCTL_RUN                CTL_CODE(HAX_DEVICE_TYPE, 0x906, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define HAX_VCPU_IOCTL_SET_MSRS           CTL_CODE(HAX_DEVICE_TYPE, 0x907, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define HAX_VCPU_IOCTL_GET_MSRS           CTL_CODE(HAX_DEVICE_TYPE, 0x908, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define HAX_VCPU_IOCTL_SET_FPU            CTL_CODE(HAX_DEVICE_TYPE, 0x909, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define HAX_VCPU_IOCTL_GET_FPU            CTL_CODE(HAX_DEVICE_TYPE, 0x90a, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define HAX_VCPU_IOCTL_SETUP_TUNNEL       CTL_CODE(HAX_DEVICE_TYPE, 0x90b, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define HAX_VCPU_IOCTL_INTERRUPT          CTL_CODE(HAX_DEVICE_TYPE, 0x90c, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define HAX_VCPU_IOCTL_SET_REGS           CTL_CODE(HAX_DEVICE_TYPE, 0x90d, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define HAX_VCPU_IOCTL_GET_REGS           CTL_CODE(HAX_DEVICE_TYPE, 0x90e, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define HAX_VM_IOCTL_NOTIFY_QEMU_VERSION  CTL_CODE(HAX_DEVICE_TYPE, 0x910, METHOD_BUFFERED, FILE_ANY_ACCESS)


#endif
