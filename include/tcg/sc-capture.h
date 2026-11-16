/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Supercache preparation capture (scc, Tier 0): records relocation metadata
 * for every committed supercache TB into a separate .scm file.
 *
 * Base stub (qemu-sc-base.patch): capture is never active.  The capture
 * patch fills in the hooks; see design/B1-design.md section 2.
 */
#ifndef TCG_SC_CAPTURE_H
#define TCG_SC_CAPTURE_H

/* True once QEMU_SC_CAPTURE was accepted (per-run hooks gate on this). */
extern bool scc_active;
/* True only between H3 (scc_tb_begin) and H15 (scc_tb_end). */
extern bool scc_in_tb;

/* H1: called at the end of tcg_supercache_configure(). */
void scc_configure_from_env(void);

#endif
