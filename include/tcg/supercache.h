/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TCG_SUPERCACHE_H
#define TCG_SUPERCACHE_H

#include "exec/translation-block.h"
#include "accel/tcg/tb-cpu-state.h"
#include "tcg/supercache-v6.h"

typedef struct TCGContext TCGContext;

#ifdef CONFIG_SOFTMMU
void tcg_supercache_configure(const char *path, bool flat, int splitwx,
                              unsigned max_threads);
bool tcg_supercache_enabled(void);
void *tcg_supercache_buffer(void);
uint64_t tcg_supercache_loaded_max_end(void);
int tcg_supercache_alloc_code_buffer(size_t size, void **buffer,
                                     Error **errp);
void tcg_supercache_after_prologue(TCGContext *s);
void tcg_supercache_restore_window(bool started);
void tcg_supercache_runtime_reset(void);
void tcg_supercache_record(TranslationBlock *tb, const void *end);
TranslationBlock *tcg_supercache_lookup(CPUState *cpu, TCGTBCPUState state,
                                        tb_page_addr_t phys_pc);
TranslationBlock *tcg_supercache_host_lookup(uintptr_t tc_ptr);
bool tcg_supercache_flat_invalidate(TranslationBlock *tb);
const uint8_t *tcg_supercache_search_data(const TranslationBlock *tb);
bool tcg_supercache_code_invalidated(tb_page_addr_t start,
                                     tb_page_addr_t last,
                                     TranslationBlock *current_tb);

/*
 * .sc v6 loader (WP22, design/B3-B4-design.md §5.5-5.8).
 * tcg_supercache_mapping_changed: end of each vCPU TLB-flush worker (Q7).
 * tcg_supercache_v6_one_insn_per_tb: one-insn-per-tb was set (Q9).
 * tcg_supercache_v6_note_exit/_restore: QEMU_SC_V6_STATS counters (Q10),
 * called only while tcg_sc6_stats_active.
 */
extern bool tcg_sc6_stats_active;
void tcg_supercache_mapping_changed(CPUState *cpu);
void tcg_supercache_v6_one_insn_per_tb(void);
void tcg_supercache_v6_note_exit(TranslationBlock *tb, int tb_exit);
void tcg_supercache_v6_note_restore(TranslationBlock *tb);
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

static inline void *tcg_supercache_buffer(void)
{
    return NULL;
}

static inline uint64_t tcg_supercache_loaded_max_end(void)
{
    return 0;
}

static inline int tcg_supercache_alloc_code_buffer(size_t size, void **buffer,
                                                   Error **errp)
{
    return 0;
}

static inline void tcg_supercache_restore_window(bool started)
{
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

static inline const uint8_t *
tcg_supercache_search_data(const TranslationBlock *tb)
{
    return NULL;
}

static inline bool
tcg_supercache_code_invalidated(tb_page_addr_t start,
                                tb_page_addr_t last,
                                TranslationBlock *current_tb)
{
    return false;
}

#define tcg_sc6_stats_active false
static inline void tcg_supercache_mapping_changed(CPUState *cpu)
{
}

static inline void tcg_supercache_v6_one_insn_per_tb(void)
{
}

static inline void tcg_supercache_v6_note_exit(TranslationBlock *tb,
                                               int tb_exit)
{
}

static inline void tcg_supercache_v6_note_restore(TranslationBlock *tb)
{
}
#endif

/* Return address of the TB epilogue (static tb_ret_addr), or NULL. */
const void *tcg_target_tb_ret_addr(void);

/*
 * Supercache state for the profile writer (scp, qemu-sc-profile.patch).
 * The loaded_* fields describe the header as it was read from disk on a
 * reused cache, and are all zero for a new cache.  Returns false (and
 * zeroes @info) when no supercache is configured.
 */
typedef struct TCGSupercacheInfo {
    bool configured;
    bool initialized;
    bool flat;
    bool reused;
    uint64_t code_address;
    uint64_t runtime_signature;
    uint64_t loaded_record_count;
    uint64_t loaded_header_checksum;
    uint64_t loaded_max_end;
} TCGSupercacheInfo;

bool tcg_supercache_get_info(TCGSupercacheInfo *info);

#endif
