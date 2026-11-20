/* Single byte/descriptor ABI shared by FastDyn and its QEMU fork. */
#ifndef QEMU_FASTDYN_FRAGMENTS_H
#define QEMU_FASTDYN_FRAGMENTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FASTDYN_FRAGMENT_MAX_INSNS 128u
#define FASTDYN_FRAGMENT_MAX_BYTES 2048u

typedef enum FastDynGuestISA {
    FASTDYN_GUEST_ISA_INVALID = 0,
    FASTDYN_GUEST_ISA_ARM,
    FASTDYN_GUEST_ISA_AARCH64,
    FASTDYN_GUEST_ISA_X86,
    FASTDYN_GUEST_ISA_RISCV,
} FastDynGuestISA;

typedef enum FastDynCodeMode {
    FASTDYN_CODE_MODE_INVALID = 0,
    FASTDYN_CODE_MODE_A32,
    FASTDYN_CODE_MODE_THUMB,
    FASTDYN_CODE_MODE_A64,
    FASTDYN_CODE_MODE_X86_16,
    FASTDYN_CODE_MODE_X86_32,
    FASTDYN_CODE_MODE_X86_64,
    FASTDYN_CODE_MODE_RV32,
    FASTDYN_CODE_MODE_RV64,
} FastDynCodeMode;

typedef enum FastDynInstructionOrder {
    FASTDYN_INSN_ORDER_INVALID = 0,
    FASTDYN_INSN_ORDER_LITTLE_ENDIAN,
    FASTDYN_INSN_ORDER_BIG_ENDIAN,
} FastDynInstructionOrder;

typedef struct FastDynCodeSpec {
    FastDynGuestISA isa;
    FastDynCodeMode mode;
    FastDynInstructionOrder instruction_order;
} FastDynCodeSpec;

#endif
