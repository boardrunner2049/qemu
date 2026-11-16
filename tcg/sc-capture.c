/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Supercache preparation capture (scc, Tier 0).
 *
 * Base stub (qemu-sc-base.patch): capture is never active and
 * scc_configure_from_env() is a no-op.  Everything here lives in .bss so the
 * memory layout is identical with capture on or off (design rule R3).
 */
#include "qemu/osdep.h"
#include "tcg/sc-capture.h"

bool scc_active;
bool scc_in_tb;

void scc_configure_from_env(void)
{
}
