/*
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 *
 * plugin-gen.h - TCG-dependent definitions for generating plugin code
 *
 * This header should be included only from plugin.c and C files that emit
 * TCG code.
 */
#ifndef QEMU_PLUGIN_GEN_H
#define QEMU_PLUGIN_GEN_H

#include "tcg/tcg.h"

struct DisasContextBase;

/* Common bits in the otherwise target-owned per-instruction state. */
#define FASTDYN_CONST_PC_SUPPORTED          (1ULL << 0)
#define FASTDYN_CONST_PC_NEEDS_PAGE_GUARD   (1ULL << 1)

uint64_t fastdyn_const_pc_insn_state(const struct DisasContextBase *db);
bool fastdyn_const_pc_target_is_pc_reg(uint64_t reg);
bool fastdyn_const_pc_target_eligible(uint64_t state, uint64_t source_pc,
                                     uint64_t destination);
void fastdyn_const_pc_target_emit(uint64_t state, uint64_t destination,
                                  uint64_t expected_page,
                                  TCGLabel *fallback);
void fastdyn_const_pc_target_emit_legacy(uint64_t destination,
                                         TCGLabel *fallback);

#ifdef CONFIG_PLUGIN

bool plugin_gen_tb_start(CPUState *cpu, const struct DisasContextBase *db);
void plugin_gen_tb_end(CPUState *cpu, size_t num_insns);
void plugin_gen_insn_start(CPUState *cpu, const struct DisasContextBase *db);
void plugin_gen_insn_end(void);

void plugin_gen_disable_mem_helpers(void);

#else /* !CONFIG_PLUGIN */

static inline
bool plugin_gen_tb_start(CPUState *cpu, const struct DisasContextBase *db)
{
    return false;
}

static inline
void plugin_gen_insn_start(CPUState *cpu, const struct DisasContextBase *db)
{ }

static inline void plugin_gen_insn_end(void)
{ }

static inline void plugin_gen_tb_end(CPUState *cpu, size_t num_insns)
{ }

static inline void plugin_gen_disable_mem_helpers(void)
{ }

#endif /* CONFIG_PLUGIN */

#endif /* QEMU_PLUGIN_GEN_H */

