#ifndef EXEC_FASTDYN_FRAGMENTS_H
#define EXEC_FASTDYN_FRAGMENTS_H

#include "qemu/fastdyn-fragments.h"

typedef struct FastDynFragment {
    uint64_t id;
    uint64_t guest_pc;
    FastDynCodeSpec spec;
    size_t insn_count;
    size_t code_size;
    const uint8_t *code;
} FastDynFragment;

const FastDynFragment *fastdyn_fragment_find(
    uint64_t guest_pc, FastDynGuestISA isa, FastDynCodeMode mode,
    FastDynInstructionOrder order, size_t *cursor);
G_NORETURN void fastdyn_fragment_translation_error(
    const FastDynFragment *fragment, size_t offset, const char *reason);

#endif
