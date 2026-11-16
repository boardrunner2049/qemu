/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Supercache exact software profile (scp).
 *
 * Base stub (qemu-sc-base.patch): profiling is never active and
 * scp_configure_from_env() is a no-op.
 */
#include "qemu/osdep.h"
#include "accel/tcg/sc-profile.h"

bool scp_active;

void scp_configure_from_env(void)
{
}
