/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Target-independent part of the supercache .sc v6 loader interface
 * (WP22).  Usable from files that are built once for all targets, such as
 * plugins/loader.c, which cannot include tcg/supercache.h.
 */
#ifndef TCG_SUPERCACHE_V6_H
#define TCG_SUPERCACHE_V6_H

/*
 * Q11: forbid further v6 arming for the run and disarm what is armed
 * (plugin reset/uninstall, scoreboard growth; exclusive context).
 * Defined by the system-mode tcg/supercache.c; the supercache is
 * system-mode only.
 */
void tcg_supercache_v6_forbid(void);

#endif
