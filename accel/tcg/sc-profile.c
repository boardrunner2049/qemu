/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Supercache exact software profile (scp), design/B1-design.md section 3.
 *
 * Counts every TB entry (per phase), the edge that led to it, aborted
 * entries (TB_EXIT_REQUESTED) and entries left by a longjmp, on a warm
 * unchained run, and writes them to a .qprof v1 file at exit.
 *
 * Construction:
 * - All tables are static .bss with fixed capacities; overflow sets a
 *   header flag and drops the observation, never allocates.
 * - The output fd is moved to >= 1000 so QEMU's own fd numbering is the
 *   same with profiling on or off.  The body is written with write(2) from
 *   a static buffer; the final header is pwrite(2)n last, so a crash while
 *   writing leaves the provisional header (clean_exit=0).
 * - Single vCPU only: dispatches from a second vCPU are not counted and
 *   the file is written without clean_exit.
 *
 * Counting rules (section 3.4):
 * - entries[t][p]: P1 main-loop entries plus P3 lookup hits (lookup_hits is
 *   the P3 subset).  executions = entries - aborted.
 * - Every counted entry adds exactly one in-edge, in the phase of that
 *   entry.  The first entry has src NONE and kind FIRST.  The edge kind is
 *   decided by how the previous TB left (P2/P3/P6) and the flags by what
 *   happened in between (P4 IRQ, P5 EXCEPTION, P6 LONGJMP).
 * - Phases: at every dispatch, the next pending marker m is tested with
 *   pc <= m < pc + tb->size; on a hit the phase advances before the entry
 *   is counted, so the dispatching TB counts in the new phase.  If one TB
 *   contains several pending markers, all of them advance on that dispatch.
 *   Phase row 'reached' is 0 (not reached), 1 (reached, exact_start:
 *   m == pc) or 2 (reached, contained).
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "hw/core/cpu.h"
#include "exec/translation-block.h"
#include "tcg/tcg.h"
#include "tcg/supercache.h"
#include "accel/tcg/sc-profile.h"

/* Capacities: scopt/formats/layouts.py QPROF_CAP_*. */
#define SCP_TB_CAP       65536
#define SCP_TB_HASH_BITS 17
#define SCP_EDGE_CAP     262144
#define SCP_EDGE_HASH_BITS 19
#define SCP_MAX_PHASES   8
#define SCP_NAME_LEN     16
#define SCP_NONE         UINT32_MAX

/* Same constants as SUPERCACHE_FNV_OFFSET/PRIME in tcg/supercache.c. */
#define SCP_FNV_OFFSET   UINT64_C(1469598103934665603)
#define SCP_FNV_PRIME    UINT64_C(1099511628211)

#define QPROF_MAGIC      "QSCPROF1"
#define QPROF_VERSION    1

/* .qprof v1 on-disk layout (little-endian host; x86-64 only). */
typedef struct QEMU_PACKED QprofHeader {
    char magic[8];
    uint32_t version;
    uint32_t header_size;
    uint64_t code_address;
    uint64_t runtime_signature;
    uint64_t loaded_record_count;
    uint64_t loaded_max_end;
    uint64_t loaded_header_checksum;
    uint32_t n_phases;
    uint32_t flags;
    uint64_t n_tb_rows;
    uint64_t n_edge_rows;
    uint64_t total_dispatches;
    uint64_t created_realtime_ns;
    uint64_t reserved[3];
    uint64_t checksum;
} QprofHeader;

typedef struct QEMU_PACKED QprofPhase {
    uint32_t id;
    uint32_t reached;
    uint64_t marker_vaddr;
    uint64_t first_dispatch_index;
    char name[SCP_NAME_LEN];
} QprofPhase;

typedef struct QEMU_PACKED QprofTbRow {
    uint64_t tb_offset;
    uint64_t first_vaddr;
    uint64_t page_addr0;
    uint64_t page_addr1;
    uint64_t cs_base;
    uint32_t flags;
    uint32_t cflags;
    uint16_t size;
    uint16_t icount;
    uint32_t pad;
    uint64_t reserved[2];
} QprofTbRow;

typedef struct QEMU_PACKED QprofTbPhase {
    uint64_t entries;
    uint64_t aborted;
    uint64_t longjmp;
    uint64_t lookup_hits;
} QprofTbPhase;

typedef struct QEMU_PACKED QprofEdge {
    uint64_t src_tb_offset;
    uint64_t dst_tb_offset;
    uint16_t kind;
    uint16_t flags;
    uint32_t phase;
    uint64_t count;
} QprofEdge;

QEMU_BUILD_BUG_ON(sizeof(QprofHeader) != 128);
QEMU_BUILD_BUG_ON(offsetof(QprofHeader, checksum) != 120);
QEMU_BUILD_BUG_ON(sizeof(QprofPhase) != 40);
QEMU_BUILD_BUG_ON(sizeof(QprofTbRow) != 72);
QEMU_BUILD_BUG_ON(sizeof(QprofTbPhase) != 32);
QEMU_BUILD_BUG_ON(sizeof(QprofEdge) != 32);

enum {
    QPROF_F_CLEAN_EXIT = 1 << 0,
    QPROF_F_TB_OVERFLOW = 1 << 1,
    QPROF_F_EDGE_OVERFLOW = 1 << 2,
};

typedef struct ScpTb {
    const TranslationBlock *tb;
    uint64_t first_vaddr;
    uint64_t page_addr0;
    uint64_t page_addr1;
    uint64_t cs_base;
    uint32_t flags;
    uint32_t cflags;
    uint16_t size;
    uint16_t icount;
} ScpTb;

typedef struct ScpEdge {
    uint32_t src;
    uint32_t dst;
    uint16_t kind;
    uint16_t flags;
    uint32_t phase;
    uint64_t count;
} ScpEdge;

typedef struct ScpPhase {
    char name[SCP_NAME_LEN];
    uint64_t marker;
    uint32_t reached;
    uint64_t first_dispatch_index;
} ScpPhase;

bool scp_active;

/* Tables (static .bss, identical layout with profiling on or off). */
static ScpTb scp_tbs[SCP_TB_CAP];
static QprofTbPhase scp_counts[SCP_TB_CAP][SCP_MAX_PHASES];
static uint32_t scp_tb_hash[1u << SCP_TB_HASH_BITS];       /* row + 1 */
static ScpEdge scp_edges[SCP_EDGE_CAP];
static uint32_t scp_edge_hash[1u << SCP_EDGE_HASH_BITS];   /* row + 1 */
static uint8_t scp_wbuf[64 * 1024];

static struct {
    int fd;
    const char *path;
    uint32_t n_phases;
    ScpPhase phases[SCP_MAX_PHASES];
    uint32_t phase;
    uint32_t n_tbs;
    uint32_t n_edges;
    uint32_t cur;
    bool in_tb;
    bool miss;
    bool tb_overflow;
    bool edge_overflow;
    bool multi_cpu;
    bool finished;
    uint16_t pending_kind;
    uint16_t pending_flags;
    const CPUState *cpu;
    uint64_t total_dispatches;
    uint64_t created_ns;
    /* body writer */
    size_t wlen;
    uint64_t wfnv;
    bool werror;
} scp = {
    .fd = -1,
    .cur = SCP_NONE,
};

/* ------------------------------------------------------------------ */
/* Tables                                                              */
/* ------------------------------------------------------------------ */

static inline uint32_t scp_hash64(uint64_t v, unsigned bits)
{
    v ^= v >> 29;
    v *= UINT64_C(0x9e3779b97f4a7c15);
    return (uint32_t)(v >> (64 - bits));
}

/* Row index of @tb, inserting it on first sight; SCP_NONE on overflow. */
static uint32_t scp_tb_row(const TranslationBlock *tb, vaddr pc)
{
    const uint32_t mask = (1u << SCP_TB_HASH_BITS) - 1;
    uint32_t h = scp_hash64((uintptr_t)tb >> 4, SCP_TB_HASH_BITS);

    for (;;) {
        uint32_t slot = scp_tb_hash[h];
        ScpTb *row;

        if (slot == 0) {
            if (scp.n_tbs >= SCP_TB_CAP) {
                scp.tb_overflow = true;
                return SCP_NONE;
            }
            row = &scp_tbs[scp.n_tbs];
            row->tb = tb;
            row->first_vaddr = pc;
            row->page_addr0 = (uint64_t)tb_page_addr0(tb);
            row->page_addr1 = (uint64_t)tb_page_addr1(tb);
            row->cs_base = tb->cs_base;
            row->flags = tb->flags;
            row->cflags = tb_cflags(tb);
            row->size = tb->size;
            row->icount = tb->icount;
            scp_tb_hash[h] = ++scp.n_tbs;
            return scp.n_tbs - 1;
        }
        if (scp_tbs[slot - 1].tb == tb) {
            return slot - 1;
        }
        h = (h + 1) & mask;
    }
}

static void scp_edge_add(uint32_t src, uint32_t dst, uint16_t kind,
                         uint16_t flags, uint32_t phase)
{
    const uint32_t mask = (1u << SCP_EDGE_HASH_BITS) - 1;
    uint64_t key = ((uint64_t)src << 32) ^ dst ^
                   ((uint64_t)kind << 48) ^ ((uint64_t)flags << 56) ^
                   ((uint64_t)phase << 20);
    uint32_t h = scp_hash64(key ^ (key >> 7), SCP_EDGE_HASH_BITS);

    for (;;) {
        uint32_t slot = scp_edge_hash[h];
        ScpEdge *e;

        if (slot == 0) {
            if (scp.n_edges >= SCP_EDGE_CAP) {
                scp.edge_overflow = true;
                return;
            }
            e = &scp_edges[scp.n_edges];
            e->src = src;
            e->dst = dst;
            e->kind = kind;
            e->flags = flags;
            e->phase = phase;
            e->count = 1;
            scp_edge_hash[h] = ++scp.n_edges;
            return;
        }
        e = &scp_edges[slot - 1];
        if (e->src == src && e->dst == dst && e->kind == kind &&
            e->flags == flags && e->phase == phase) {
            e->count++;
            return;
        }
        h = (h + 1) & mask;
    }
}

/* ------------------------------------------------------------------ */
/* Hooks                                                               */
/* ------------------------------------------------------------------ */

static void scp_enter(CPUState *cpu, TranslationBlock *tb, vaddr pc,
                      uint16_t kind, bool hit)
{
    uint64_t index;
    uint32_t row;

    if (unlikely(cpu != scp.cpu)) {
        if (scp.cpu) {
            scp.multi_cpu = true;
            return;
        }
        scp.cpu = cpu;
    }

    index = scp.total_dispatches++;
    if (index == 0) {
        scp.phases[0].reached = 1;
    }
    while (scp.phase + 1 < scp.n_phases) {
        ScpPhase *next = &scp.phases[scp.phase + 1];

        if (!(pc <= next->marker && next->marker < pc + tb->size)) {
            break;
        }
        scp.phase++;
        next->reached = next->marker == pc ? 1 : 2;
        next->first_dispatch_index = index;
    }

    row = scp_tb_row(tb, pc);
    if (likely(row != SCP_NONE)) {
        QprofTbPhase *c = &scp_counts[row][scp.phase];

        c->entries++;
        if (hit) {
            c->lookup_hits++;
        }
        if (index == 0) {
            scp_edge_add(SCP_NONE, row, SCP_EDGE_FIRST, 0, scp.phase);
        } else if (scp.cur != SCP_NONE) {
            scp_edge_add(scp.cur, row, kind, scp.pending_flags, scp.phase);
        }
        /* else: the source row was lost to tb_overflow (flagged) */
    }

    scp.cur = row;
    scp.in_tb = true;
    scp.miss = false;
    scp.pending_kind = 0;
    scp.pending_flags = 0;
}

void scp_dispatch(CPUState *cpu, TranslationBlock *tb, vaddr pc)
{
    /* No P2/P6 since the last entry cannot happen; treat as EXIT_NULL. */
    uint16_t kind = scp.pending_kind ? scp.pending_kind : SCP_EDGE_EXIT_NULL;

    scp_enter(cpu, tb, pc, kind, false);
}

void scp_lookup_hit(CPUState *cpu, TranslationBlock *tb, vaddr pc,
                    uintptr_t retaddr)
{
#ifdef CONFIG_DEBUG_TCG
    if (cpu == scp.cpu && scp.cur != SCP_NONE) {
        /* The TB calling lookup_tb_ptr must be the one we think runs. */
        assert(tcg_tb_lookup(retaddr) == scp_tbs[scp.cur].tb);
    }
#endif
    scp_enter(cpu, tb, pc, SCP_EDGE_LOOKUP_HIT, true);
}

void scp_lookup_miss(void)
{
    scp.miss = true;
}

void scp_return(TranslationBlock *last_tb, int tb_exit, uintptr_t ret)
{
    if (!scp.in_tb) {
        /* e.g. cpu_exec_step_atomic(): an entry P1 did not see. */
        return;
    }
    scp.in_tb = false;
    if (last_tb == NULL) {
        scp.pending_kind = scp.miss ? SCP_EDGE_LOOKUP_MISS
                                    : SCP_EDGE_EXIT_NULL;
    } else {
#ifdef CONFIG_DEBUG_TCG
        assert(scp.cur == SCP_NONE || scp_tbs[scp.cur].tb == last_tb);
#endif
        if (tb_exit == TB_EXIT_REQUESTED) {
            if (scp.cur != SCP_NONE) {
                scp_counts[scp.cur][scp.phase].aborted++;
            }
            scp.pending_kind = SCP_EDGE_EXIT_REQUESTED;
        } else {
            scp.pending_kind = tb_exit == TB_EXIT_IDX0 ? SCP_EDGE_CHAIN0
                                                       : SCP_EDGE_CHAIN1;
        }
    }
    scp.miss = false;
}

void scp_note_irq(void)
{
    scp.pending_flags |= SCP_EDGE_F_IRQ;
}

void scp_note_exception(void)
{
    scp.pending_flags |= SCP_EDGE_F_EXCEPTION;
}

void scp_longjmp(void)
{
    /*
     * Only a longjmp out of a running TB (fault, cpu_io_recompile,
     * cpu_loop_exit from a helper) leaves an entry mid-TB.  A longjmp out
     * of translation or interrupt delivery happens between entries and
     * changes nothing here.
     */
    if (!scp.in_tb) {
        return;
    }
    scp.in_tb = false;
    if (scp.cur != SCP_NONE) {
        scp_counts[scp.cur][scp.phase].longjmp++;
    }
    scp.pending_kind = SCP_EDGE_EXIT_NULL;
    scp.pending_flags |= SCP_EDGE_F_LONGJMP;
    scp.miss = false;
}

/* ------------------------------------------------------------------ */
/* Output                                                              */
/* ------------------------------------------------------------------ */

static uint64_t scp_fnv(uint64_t h, const void *data, size_t len)
{
    const uint8_t *p = data;

    while (len--) {
        h ^= *p++;
        h *= SCP_FNV_PRIME;
    }
    return h;
}

static bool scp_write_all(int fd, const void *data, size_t len)
{
    const uint8_t *p = data;

    while (len) {
        ssize_t n = write(fd, p, len);

        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return false;
        }
        p += n;
        len -= n;
    }
    return true;
}

static void scp_flush(void)
{
    if (scp.wlen && !scp_write_all(scp.fd, scp_wbuf, scp.wlen)) {
        scp.werror = true;
    }
    scp.wlen = 0;
}

static void scp_emit(const void *data, size_t len)
{
    scp.wfnv = scp_fnv(scp.wfnv, data, len);
    if (scp.wlen + len > sizeof(scp_wbuf)) {
        scp_flush();
    }
    memcpy(scp_wbuf + scp.wlen, data, len);
    scp.wlen += len;
}

static void scp_fill_header(QprofHeader *h, const TCGSupercacheInfo *info,
                            uint32_t flags, uint64_t n_tb, uint64_t n_edge)
{
    memset(h, 0, sizeof(*h));
    memcpy(h->magic, QPROF_MAGIC, 8);
    h->version = QPROF_VERSION;
    h->header_size = sizeof(*h);
    h->n_phases = scp.n_phases;
    h->created_realtime_ns = scp.created_ns;
    if (info) {
        h->code_address = info->code_address;
        h->runtime_signature = info->runtime_signature;
        h->loaded_record_count = info->loaded_record_count;
        h->loaded_max_end = info->loaded_max_end;
        h->loaded_header_checksum = info->loaded_header_checksum;
    }
    h->flags = flags;
    h->n_tb_rows = n_tb;
    h->n_edge_rows = n_edge;
    h->total_dispatches = scp.total_dispatches;
    h->checksum = scp_fnv(SCP_FNV_OFFSET, h, offsetof(QprofHeader, checksum));
}

static uint64_t scp_tb_offset(uint32_t row, uint64_t code_address)
{
    if (row == SCP_NONE) {
        return UINT64_MAX;
    }
    return (uint64_t)(uintptr_t)scp_tbs[row].tb - code_address;
}

static void scp_msg(const char *s)
{
    if (write(STDERR_FILENO, s, strlen(s)) < 0) {
        /* nothing more we can do at exit */
    }
}

/* P7: registered with atexit() in scp_configure_from_env(). */
static void scp_finish(void)
{
    TCGSupercacheInfo info;
    QprofHeader header;
    uint32_t flags = 0;
    uint64_t trailer;

    if (scp.finished || scp.fd < 0) {
        return;
    }
    scp.finished = true;
    scp_active = false;

    tcg_supercache_get_info(&info);

    if (lseek(scp.fd, sizeof(QprofHeader), SEEK_SET) < 0) {
        scp.werror = true;
    }
    scp.wlen = 0;
    scp.wfnv = SCP_FNV_OFFSET;

    for (uint32_t i = 0; i < scp.n_phases; i++) {
        QprofPhase p = {
            .id = i,
            .reached = scp.phases[i].reached,
            .marker_vaddr = scp.phases[i].marker,
            .first_dispatch_index = scp.phases[i].first_dispatch_index,
        };

        memcpy(p.name, scp.phases[i].name, SCP_NAME_LEN);
        scp_emit(&p, sizeof(p));
    }

    for (uint32_t i = 0; i < scp.n_tbs; i++) {
        const ScpTb *t = &scp_tbs[i];
        QprofTbRow r = {
            .tb_offset = scp_tb_offset(i, info.code_address),
            .first_vaddr = t->first_vaddr,
            .page_addr0 = t->page_addr0,
            .page_addr1 = t->page_addr1,
            .cs_base = t->cs_base,
            .flags = t->flags,
            .cflags = t->cflags,
            .size = t->size,
            .icount = t->icount,
        };

        scp_emit(&r, sizeof(r));
        scp_emit(scp_counts[i], scp.n_phases * sizeof(QprofTbPhase));
    }

    for (uint32_t i = 0; i < scp.n_edges; i++) {
        const ScpEdge *e = &scp_edges[i];
        QprofEdge r = {
            .src_tb_offset = scp_tb_offset(e->src, info.code_address),
            .dst_tb_offset = scp_tb_offset(e->dst, info.code_address),
            .kind = e->kind,
            .flags = e->flags,
            .phase = e->phase,
            .count = e->count,
        };

        scp_emit(&r, sizeof(r));
    }

    trailer = scp.wfnv;
    scp_flush();
    if (!scp_write_all(scp.fd, &trailer, sizeof(trailer))) {
        scp.werror = true;
    }

    if (!scp.multi_cpu && !scp.werror) {
        flags |= QPROF_F_CLEAN_EXIT;
    }
    if (scp.tb_overflow) {
        flags |= QPROF_F_TB_OVERFLOW;
    }
    if (scp.edge_overflow) {
        flags |= QPROF_F_EDGE_OVERFLOW;
    }
    scp_fill_header(&header, &info, flags, scp.n_tbs, scp.n_edges);
    if (scp.werror ||
        pwrite(scp.fd, &header, sizeof(header), 0) != sizeof(header)) {
        scp_msg("supercache-profile: error writing the .qprof file\n");
    }
    if (scp.multi_cpu) {
        scp_msg("supercache-profile: more than one vCPU dispatched; "
                "profile written without clean_exit\n");
    }
    close(scp.fd);
    scp.fd = -1;
}

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

static void G_NORETURN scp_fail(const char *msg, const char *detail)
{
    error_report("supercache-profile: %s%s%s", msg,
                 detail ? ": " : "", detail ? detail : "");
    exit(EXIT_FAILURE);
}

static bool scp_name_char(char c)
{
    return g_ascii_isalnum(c) || c == '_' || c == '-' || c == '.';
}

/* QEMU_SC_PROFILE_PHASES=name@0xVADDR[,name@0xVADDR...] */
static void scp_parse_phases(const char *spec)
{
    const char *p = spec;

    memset(scp.phases, 0, sizeof(scp.phases));
    memcpy(scp.phases[0].name, "boot", 5);
    scp.n_phases = 1;

    if (!spec) {
        return;
    }
    if (!*spec) {
        scp_fail("empty QEMU_SC_PROFILE_PHASES", NULL);
    }
    while (*p) {
        const char *at = strchr(p, '@');
        const char *end;
        ScpPhase *ph;
        size_t name_len;
        uint64_t marker = 0;
        int digits = 0;

        if (scp.n_phases >= SCP_MAX_PHASES) {
            scp_fail("too many phases in QEMU_SC_PROFILE_PHASES (max 7)",
                     spec);
        }
        if (!at) {
            scp_fail("phase without '@0xVADDR' in QEMU_SC_PROFILE_PHASES",
                     p);
        }
        name_len = at - p;
        if (name_len == 0 || name_len >= SCP_NAME_LEN) {
            scp_fail("phase name must be 1..15 bytes", p);
        }
        for (size_t i = 0; i < name_len; i++) {
            if (!scp_name_char(p[i])) {
                scp_fail("phase name may only use [A-Za-z0-9_.-]", p);
            }
        }
        ph = &scp.phases[scp.n_phases];
        memcpy(ph->name, p, name_len);
        for (uint32_t i = 0; i < scp.n_phases; i++) {
            if (!strcmp(scp.phases[i].name, ph->name)) {
                scp_fail("duplicate phase name", ph->name);
            }
        }
        end = at + 1;
        if (end[0] != '0' || (end[1] != 'x' && end[1] != 'X')) {
            scp_fail("phase marker must be 0x-prefixed hex", at + 1);
        }
        end += 2;
        while (g_ascii_isxdigit(*end)) {
            if (++digits > 16) {
                scp_fail("phase marker too long", at + 1);
            }
            marker = (marker << 4) | g_ascii_xdigit_value(*end);
            end++;
        }
        if (digits == 0 || (*end != ',' && *end != '\0')) {
            scp_fail("bad phase marker", at + 1);
        }
        ph->marker = marker;
        scp.n_phases++;
        p = *end == ',' ? end + 1 : end;
        if (*end == ',' && !*p) {
            scp_fail("trailing ',' in QEMU_SC_PROFILE_PHASES", spec);
        }
    }
}

void scp_configure_from_env(void)
{
    static bool configured;
    const char *path = getenv("QEMU_SC_PROFILE");
    const char *phases = getenv("QEMU_SC_PROFILE_PHASES");
    TCGSupercacheInfo info;
    QprofHeader header;
    struct timespec ts;
    int fd, fd2;

    if (configured) {
        return;
    }
    configured = true;

    if (!path) {
        if (phases) {
            scp_fail("QEMU_SC_PROFILE_PHASES is set without QEMU_SC_PROFILE",
                     NULL);
        }
        return;
    }
    if (getenv("QEMU_SC_CAPTURE")) {
        scp_fail("QEMU_SC_CAPTURE and QEMU_SC_PROFILE are mutually exclusive",
                 NULL);
    }
    if (!tcg_supercache_get_info(&info) || !tcg_supercache_enabled()) {
        scp_fail("QEMU_SC_PROFILE is set but no supercache is configured",
                 NULL);
    }
    if (info.flat) {
        scp_fail("QEMU_SC_PROFILE does not support supercache-flat", NULL);
    }
    if (path[0] != '/') {
        scp_fail("QEMU_SC_PROFILE must be an absolute path", path);
    }
    scp_parse_phases(phases);

    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0) {
        error_report("supercache-profile: cannot create '%s': %s", path,
                     strerror(errno));
        exit(EXIT_FAILURE);
    }
    fd2 = fcntl(fd, F_DUPFD_CLOEXEC, 1000);
    if (fd2 < 0) {
        error_report("supercache-profile: cannot move fd to >= 1000: %s",
                     strerror(errno));
        exit(EXIT_FAILURE);
    }
    close(fd);
    scp.fd = fd2;
    scp.path = path;

    clock_gettime(CLOCK_REALTIME, &ts);
    scp.created_ns = (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;

    /* Provisional header: no rows, no clean_exit until P7 rewrites it. */
    scp_fill_header(&header, NULL, 0, 0, 0);
    if (!scp_write_all(scp.fd, &header, sizeof(header))) {
        error_report("supercache-profile: cannot write '%s': %s", path,
                     strerror(errno));
        exit(EXIT_FAILURE);
    }

    atexit(scp_finish);
    scp_active = true;

    fprintf(stderr, "supercache-profile: path=%s phases=%u chaining=off\n",
            path, scp.n_phases);
}
