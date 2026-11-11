/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TCG_SUPERCACHE_H
#define TCG_SUPERCACHE_H

#include "exec/translation-block.h"
#include "accel/tcg/tb-cpu-state.h"

typedef struct TCGContext TCGContext;

#ifdef CONFIG_SOFTMMU
void tcg_supercache_configure(const char *path, bool flat, int splitwx,
                              unsigned max_threads);
bool tcg_supercache_enabled(void);
int tcg_supercache_alloc_code_buffer(size_t size, void **buffer,
                                     Error **errp);
void tcg_supercache_after_prologue(TCGContext *s);
void tcg_supercache_runtime_reset(void);
void tcg_supercache_record(TranslationBlock *tb, const void *end);
TranslationBlock *tcg_supercache_lookup(CPUState *cpu, TCGTBCPUState state,
                                        tb_page_addr_t phys_pc);
TranslationBlock *tcg_supercache_host_lookup(uintptr_t tc_ptr);
bool tcg_supercache_flat_invalidate(TranslationBlock *tb);
#else
static inline void tcg_supercache_configure(const char *path, bool flat,
                                            int splitwx,
                                            unsigned max_threads)
{
}

static inline bool tcg_supercache_enabled(void)
{
    return false;
}

static inline int tcg_supercache_alloc_code_buffer(size_t size, void **buffer,
                                                   Error **errp)
{
    return 0;
}

static inline void tcg_supercache_after_prologue(TCGContext *s)
{
}

static inline void tcg_supercache_runtime_reset(void)
{
}

static inline void tcg_supercache_record(TranslationBlock *tb,
                                         const void *end)
{
}

static inline TranslationBlock *
tcg_supercache_lookup(CPUState *cpu, TCGTBCPUState state,
                      tb_page_addr_t phys_pc)
{
    return NULL;
}

static inline TranslationBlock *
tcg_supercache_host_lookup(uintptr_t tc_ptr)
{
    return NULL;
}

static inline bool tcg_supercache_flat_invalidate(TranslationBlock *tb)
{
    return false;
}
#endif

#endif
