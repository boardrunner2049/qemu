/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Supercache preparation capture (scc, Tier 0): records relocation metadata
 * for every committed supercache TB into a separate .scm file.
 *
 * Design: design/B1-design.md section 2 (hooks H1-H18, construction rules
 * R1-R6, file format .scm v1).  Enabled only by QEMU_SC_CAPTURE=/abs/path.
 *
 * Construction rules, enforced in sc-capture.c:
 *  R1 hooks only observe: they take const pointers and scalars captured after
 *     the emission decision and never touch code_ptr, labels, pools, ldst
 *     lists or control flow;
 *  R2 no allocation: static .bss staging, write(2) output, no stdio;
 *  R3 the static arrays exist in every run (identical layout on and off);
 *  R4 a full staging array sets TB.flags.capture_overflow, nothing else;
 *  R5 every per-TB hook is gated on scc_in_tb, every per-run hook on
 *     scc_active, at the call site;
 *  R6 the .sc file is never touched.
 */
#ifndef TCG_SC_CAPTURE_H
#define TCG_SC_CAPTURE_H

#ifdef CONFIG_USER_ONLY
/*
 * sc-capture.c is system-mode only (the supercache is).  The hooks in the
 * shared tcg.c and backend are then dead code that the compiler removes.
 */
#define scc_active false
#define scc_in_tb false
#else
/* True once QEMU_SC_CAPTURE was accepted (per-run hooks gate on this). */
extern bool scc_active;
/* True only between H3 (scc_tb_begin) and H15 (scc_tb_end). */
extern bool scc_in_tb;
#endif

typedef struct TCGContext TCGContext;
typedef struct TCGOp TCGOp;
typedef struct TCGLabel TCGLabel;
typedef struct TCGHelperInfo TCGHelperInfo;
typedef struct TranslationBlock TranslationBlock;

/* .scm v1 site kinds (design 2.4); numbering is part of the file format. */
enum {
    SCC_SITE_LABEL_JMP        = 0x01,
    SCC_SITE_LABEL_JCC        = 0x02,
    SCC_SITE_LDST_FAST_JCC    = 0x03,
    SCC_SITE_LDST_RET_JMP     = 0x04,
    SCC_SITE_LDST_HELPER_CALL = 0x05,
    SCC_SITE_HELPER_CALL      = 0x06,
    SCC_SITE_EXIT_TB_RET_JMP  = 0x07,
    SCC_SITE_EXIT_TB_EPI_JMP  = 0x08,
    SCC_SITE_MOVI_EXIT_TB_PTR = 0x09,
    SCC_SITE_MOVI_LDST_RA     = 0x0A,
    SCC_SITE_MOVI_CONST       = 0x0B,
    SCC_SITE_POOL_REF         = 0x0C,
    SCC_SITE_GOTO_TB          = 0x0D,
    SCC_SITE_GOTO_PTR         = 0x0E,
    SCC_SITE_OTHER_BRANCH     = 0x0F,
};

/* .scm v1 site encodings (design 2.4). */
enum {
    SCC_ENC_NONE          = 0,
    SCC_ENC_REL8          = 1,
    SCC_ENC_REL32         = 2,
    SCC_ENC_RIPREL32      = 3,
    SCC_ENC_IMM32_ZX      = 4,
    SCC_ENC_IMM32_SX      = 5,
    SCC_ENC_IMM64         = 6,
    SCC_ENC_XOR0          = 7,
    SCC_ENC_POOL_INDIRECT = 8,
    SCC_ENC_GOTO_TB_REL32 = 9,
};

/* Arguments of H2, read by supercache.c from its private header. */
typedef struct SccRunInfoArgs {
    const void *buffer;             /* code_address */
    uint64_t code_size;
    uint64_t prologue_end;
    uint64_t runtime_signature;
    uint64_t record_count_at_load;  /* header.record_count = first new slot */
    uint64_t loaded_max_end;
    uint32_t tb_size;
    uint32_t host_page_size;
    uint32_t target_page_bits;
} SccRunInfoArgs;

/* H1: called at the end of tcg_supercache_configure(). */
void scc_configure_from_env(void);
/* Defined in supercache.c: whether supercache-flat was requested (H1). */
bool tcg_supercache_flat_requested(void);

/* H2: end of tcg_supercache_after_prologue(); gate: scc_active. */
void scc_run_info(const TCGContext *s, const void *tb_ret_addr,
                  const SccRunInfoArgs *a);

/* H3: tcg_gen_code() after the code buffer reset; gate: scc_active. */
void scc_tb_begin(const TCGContext *s, const TranslationBlock *tb,
                  uint64_t pc_start);
/* H4: first statement of the tcg_gen_code() op loop; gate: scc_in_tb. */
void scc_op(const TCGContext *s, const TCGOp *op, int num_insns);
/* H5: tcg_reg_alloc_call() right before tcg_out_call(); gate: scc_in_tb. */
void scc_helper(const TCGHelperInfo *info, const void *func);

/* H6: tcg_out_jxx(), all four emit paths. opc == -1 is JMP. */
void scc_label_jump(const TCGContext *s, const void *insn_start,
                    const void *field, unsigned width, int opc,
                    const TCGLabel *l);
/* H7: tcg_out_branch(), both forms. */
void scc_branch(const TCGContext *s, const void *insn_start,
                const void *field, int call, unsigned enc, const void *dest);
/* H8: tcg_out_movi_int(), each of its five returns (field NULL for xor). */
void scc_movi(const TCGContext *s, const void *insn_start, const void *field,
              unsigned enc, uint64_t arg);
/* H9/H10: pending tags consumed by the next branch / movi emitter. */
void scc_tag_branch(unsigned kind, uint32_t aux);
void scc_tag_movi(unsigned kind, uint32_t aux);
/* H11: tcg_out_goto_tb() after the E9 byte. */
void scc_goto_tb(const TCGContext *s, int which, const void *pad_start,
                 const void *field);
/* H12: tcg_out_goto_ptr(). */
void scc_goto_ptr(const TCGContext *s, const void *insn_start, int reg);

/* H13: tcg_out_ldst_finalize() slow-path bracket. */
void scc_ldst_begin(const TCGContext *s, bool is_ld, uint32_t oi,
                    const void *label_ptr0, const void *label_ptr1,
                    const void *raddr);
void scc_ldst_end(const TCGContext *s);
void scc_ldst_done(const TCGContext *s);

/* H14: tcg_out_pool_finalize(). */
void scc_pool_start(const TCGContext *s, const void *a);
void scc_pool_entry(const TCGContext *s, const void *label, int rtype,
                    intptr_t addend, unsigned nlong, const void *data,
                    uintptr_t value);

/* H15: tcg_gen_code() after tcg_resolve_relocs() succeeded. */
void scc_tb_end(const TCGContext *s, const TranslationBlock *tb,
                size_t code_size);

/* H16a: tcg_func_start(); gate: scc_active. */
void scc_translate_begin(void);
/* H16: target/arm gen_goto_tb(); gate: scc_active. */
void scc_static_exit(unsigned slot, uint64_t dest_vaddr, bool direct,
                     int insn_idx);

/*
 * H17: tcg_supercache_record() after the record pwrite, before
 * record_count++; gate: scc_active.  @record is the 104-byte v5 record.
 */
void scc_tb_commit(const TranslationBlock *tb, uint64_t slot,
                   const void *record, size_t record_size,
                   const void *buffer);

#endif
