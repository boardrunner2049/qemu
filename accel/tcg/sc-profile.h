/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Supercache exact software profile (scp): counts TB dispatches and edges on
 * an unchained warm run into a .qprof file (design/B1-design.md section 3).
 *
 * Switches (read once from tcg_supercache_configure()):
 *   QEMU_SC_PROFILE=/abs/run.qprof
 *   QEMU_SC_PROFILE_PHASES=name@0xVADDR[,name@0xVADDR...]   (optional)
 *
 * With profiling active, chaining is disabled at run time only
 * (tb_add_jump is skipped); code bytes and cflags are unchanged, so every TB
 * entry is observed either by the main loop (P1) or by a
 * helper_lookup_tb_ptr hit (P3).  All state is static .bss; the hot hooks
 * never allocate.  Everything here is inert unless scp_active is true.
 *
 * Hook map (cpu-exec.c):
 *   P1 cpu_exec_loop        scp_dispatch()      main-loop TB entry
 *   P2 cpu_tb_exec          scp_return()        TB returned to the main loop
 *   P3 helper_lookup_tb_ptr scp_lookup_hit()/scp_lookup_miss()
 *   P4 cpu_handle_interrupt scp_note_irq()
 *   P5 cpu_handle_exception scp_note_exception()
 *   P6 cpu_exec_longjmp_cleanup scp_longjmp()
 *   P7 atexit               writes the .qprof
 */
#ifndef ACCEL_TCG_SC_PROFILE_H
#define ACCEL_TCG_SC_PROFILE_H

#include "exec/vaddr.h"

typedef struct CPUState CPUState;
typedef struct TranslationBlock TranslationBlock;

/* .qprof v1 edge kinds (u16) and flags (u16); scopt/formats/enums.py. */
enum {
    SCP_EDGE_CHAIN0 = 1,
    SCP_EDGE_CHAIN1 = 2,
    SCP_EDGE_LOOKUP_HIT = 3,
    SCP_EDGE_LOOKUP_MISS = 4,
    SCP_EDGE_EXIT_NULL = 5,
    SCP_EDGE_EXIT_REQUESTED = 6,
    SCP_EDGE_FIRST = 7,
};
enum {
    SCP_EDGE_F_IRQ = 1 << 0,
    SCP_EDGE_F_EXCEPTION = 1 << 1,
    SCP_EDGE_F_LONGJMP = 1 << 2,
};

#ifdef CONFIG_USER_ONLY

#define scp_active false
static inline void scp_dispatch(CPUState *cpu, TranslationBlock *tb,
                                vaddr pc) { }
static inline void scp_return(TranslationBlock *last_tb, int tb_exit,
                              uintptr_t ret) { }
static inline void scp_lookup_hit(CPUState *cpu, TranslationBlock *tb,
                                  vaddr pc, uintptr_t retaddr) { }
static inline void scp_lookup_miss(void) { }
static inline void scp_note_irq(void) { }
static inline void scp_note_exception(void) { }
static inline void scp_longjmp(void) { }

#else

/* True once QEMU_SC_PROFILE was accepted. */
extern bool scp_active;

/*
 * Called at the end of tcg_supercache_configure(), after
 * scc_configure_from_env().  Rejects the switch without a supercache, with
 * supercache-flat, or together with QEMU_SC_CAPTURE; opens the output fd
 * (moved to >= 1000), writes a provisional header and registers the P7
 * atexit writer.
 */
void scp_configure_from_env(void);

/* P1: main-loop entry of @tb (looked up or translated for guest @pc). */
void scp_dispatch(CPUState *cpu, TranslationBlock *tb, vaddr pc);
/* P2: cpu_tb_exec() returned @ret (@last_tb, @tb_exit already decoded). */
void scp_return(TranslationBlock *last_tb, int tb_exit, uintptr_t ret);
/*
 * P3 hit: the running TB transfers directly to @tb via lookup_tb_ptr.
 * @retaddr is GETPC() of the helper; a CONFIG_DEBUG_TCG build asserts
 * tcg_tb_lookup(retaddr) == the current TB.
 */
void scp_lookup_hit(CPUState *cpu, TranslationBlock *tb, vaddr pc,
                    uintptr_t retaddr);
/* P3 miss: lookup_tb_ptr returns the epilogue (the TB exits with 0). */
void scp_lookup_miss(void);
/* P4 / P5: an interrupt or exception was delivered before the next entry. */
void scp_note_irq(void);
void scp_note_exception(void);
/* P6: cpu_exec_longjmp_cleanup(). */
void scp_longjmp(void);

#endif /* CONFIG_USER_ONLY */

#endif
