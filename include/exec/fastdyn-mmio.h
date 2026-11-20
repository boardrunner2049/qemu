#ifndef EXEC_FASTDYN_MMIO_H
#define EXEC_FASTDYN_MMIO_H

#include "qemu/fastdyn-mmio.h"

typedef struct FastDynMmioBoundReplacement {
    uint64_t id;
    FastDynMmioReplacement replacement;
    FastDynMmioExprInsn expr[FASTDYN_MMIO_MAX_EXPR_INSNS];
} FastDynMmioBoundReplacement;

const FastDynMmioBoundReplacement *fastdyn_mmio_find(
    uint64_t guest_pc, FastDynCodeMode mode, unsigned transfer_size,
    size_t *cursor);

#endif
