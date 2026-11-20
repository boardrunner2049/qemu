/* Typed ABI for FastDyn's guarded Cortex-M MMIO read replacements. */
#ifndef QEMU_FASTDYN_MMIO_H
#define QEMU_FASTDYN_MMIO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qemu/fastdyn-fragments.h"

#define FASTDYN_MMIO_MAX_EXPR_INSNS 16u

typedef enum FastDynMmioExprOpcode {
    FASTDYN_MMIO_EXPR_INVALID = 0,
    FASTDYN_MMIO_EXPR_CONST,
    FASTDYN_MMIO_EXPR_LOAD_U8,
    FASTDYN_MMIO_EXPR_LOAD_U16,
    FASTDYN_MMIO_EXPR_LOAD_U32,
    FASTDYN_MMIO_EXPR_ADD,
    FASTDYN_MMIO_EXPR_SUB,
    FASTDYN_MMIO_EXPR_AND,
    FASTDYN_MMIO_EXPR_OR,
    FASTDYN_MMIO_EXPR_XOR,
    FASTDYN_MMIO_EXPR_SHL,
    FASTDYN_MMIO_EXPR_LSHR,
} FastDynMmioExprOpcode;

/* Postfix expression instruction. LOAD uses state_offset; CONST uses value. */
typedef struct FastDynMmioExprInsn {
    uint8_t opcode;
    uint8_t reserved[3];
    uint32_t state_offset;
    uint64_t value;
} FastDynMmioExprInsn;

typedef struct FastDynMmioReplacement {
    uint64_t guest_pc;
    uint64_t expected_address;
    FastDynCodeSpec spec;
    uint8_t transfer_size;
    uint8_t expr_count;
    uint16_t reserved;
    uint32_t state_size;
    const void *state;
    const FastDynMmioExprInsn *expr;
    uint64_t *fast_count;
    uint64_t *fallback_count;
    /* Live disable flag. Checked by generated code, including existing TBs. */
    const int *disabled;
} FastDynMmioReplacement;

#endif
