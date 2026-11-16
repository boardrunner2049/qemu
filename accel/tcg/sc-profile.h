/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Supercache exact software profile (scp): counts TB dispatches and edges on
 * an unchained warm run into a .qprof file.
 *
 * Base stub (qemu-sc-base.patch): profiling is never active.  The profile
 * patch fills in the hooks; see design/B1-design.md section 3.
 */
#ifndef ACCEL_TCG_SC_PROFILE_H
#define ACCEL_TCG_SC_PROFILE_H

/* True once QEMU_SC_PROFILE was accepted. */
extern bool scp_active;

/*
 * Called at the end of tcg_supercache_configure(), after
 * scc_configure_from_env().  The capture/profile mutual-exclusion check
 * belongs here.
 */
void scp_configure_from_env(void);

#endif
