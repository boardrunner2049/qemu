/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Supercache preparation capture (scc, Tier 0).
 *
 * Records, for every TB that tcg_supercache_record() commits to the .sc,
 * the relocation metadata the offline optimizer needs: instruction
 * boundaries, every reference-bearing field the x86-64 backend emits, the
 * constant pool, the qemu_ld/st slow paths, op marks, static guest exits
 * and the guest bytes.  Output is the chunked binary .scm v1 file
 * (design/B1-design.md section 2.5).
 *
 * Construction rules (design 2.2), which this file must keep:
 *  - observe only: hooks never write TCG state and never change a decision;
 *  - no allocation: every buffer is a static array in .bss, output goes
 *    through write(2)/pread(2) only, no stdio, no glib, no tcg_malloc, no
 *    mmap.  `nm sc-capture.c.o` must show no malloc/g_malloc/fopen;
 *  - the static arrays exist in every run, so the memory layout is the same
 *    with capture on or off;
 *  - a full staging array only sets TB flag capture_overflow;
 *  - the .sc file is never touched.
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "tcg/sc-capture.h"

bool scc_active;
bool scc_in_tb;

#if defined(CONFIG_LINUX) && defined(HOST_X86_64)

#include "qemu/cacheflush.h"
#include "qemu/cacheinfo.h"
#include "tcg/supercache.h"
#include "host/cpuinfo.h"
#include "exec/cpu-common.h"
#include "exec/icount.h"
#include "system/memory.h"
#include "exec/translation-block.h"
#include "tcg/tcg.h"
#include "tcg/helper-info.h"
#include "tcg/insn-start-words.h"
#include "elf.h"

/* Must equal SUPERCACHE_FNV_OFFSET/PRIME in tcg/supercache.c (not FNV std). */
#define SCC_FNV_OFFSET  UINT64_C(1469598103934665603)
#define SCC_FNV_PRIME   UINT64_C(1099511628211)

#define SCC_MAGIC       "QSCMETA1"
#define SCC_VERSION     1
#define SCC_NONE32      UINT32_C(0xFFFFFFFF)
#define SCC_NONE16      UINT16_C(0xFFFF)
#define SCC_FD_MIN      1000

/* Static staging capacities (design 2.5.7). */
#define SCC_CAP_SITES        16384
#define SCC_CAP_INSNS        512
#define SCC_CAP_POOL         4096
#define SCC_CAP_LDST         4096
#define SCC_CAP_OPMARKS      8192
#define SCC_CAP_STATIC_EXITS 4
#define SCC_CAP_GUEST_BYTES  4096
#define SCC_CAP_CHUNK_BUF    (1 << 20)
#define SCC_CAP_MAPS_BUF     (256 << 10)
#define SCC_CAP_HELPERS      2048
#define SCC_HELPER_HASH      4096

QEMU_BUILD_BUG_ON(SCC_CAP_INSNS < TCG_MAX_INSNS);

/* Chunk types (design 2.5.2). */
enum {
    SCC_CHUNK_RUN_INFO  = 1,
    SCC_CHUNK_HELPER    = 3,
    SCC_CHUNK_TB        = 4,
    SCC_CHUNK_MAPS      = 7,
    SCC_CHUNK_RAMBLOCKS = 8,
    SCC_CHUNK_END       = 10,
};

/* Op mark kinds (design 2.4). */
enum {
    SCC_OPM_CALL = 1, SCC_OPM_QEMU_LD, SCC_OPM_QEMU_ST,
    SCC_OPM_EXIT_TB, SCC_OPM_GOTO_TB, SCC_OPM_GOTO_PTR,
};

/* TB flags (design 2.4). */
#define SCC_TBF_IRQ_CHECK         (1u << 0)
#define SCC_TBF_CAPTURE_OVERFLOW  (1u << 1)
#define SCC_TBF_CAPTURE_ERROR     (1u << 2)
#define SCC_TBF_GUEST_TRUNCATED   (1u << 5)

/*
 * ---- On-disk structures (little-endian; sizes frozen by scopt layouts.py)
 */
typedef struct ScmFileHeader {
    char magic[8];
    uint32_t version;
    uint32_t header_size;
    uint32_t capture_level;
    uint32_t pid;
    uint64_t created_realtime_ns;
    uint64_t reserved[3];
    uint64_t checksum;
} ScmFileHeader;
QEMU_BUILD_BUG_ON(sizeof(ScmFileHeader) != 64);

typedef struct ScmRunInfo {
    uint32_t info_version;
    uint32_t capture_level;
    uint64_t code_address;
    uint64_t code_size;
    uint64_t prologue_end;
    uint64_t tb_ret_off;
    uint64_t epilogue_off;
    uint64_t runtime_signature;
    uint64_t header_record_count_at_load;
    uint64_t loaded_max_end;
    uint64_t highwater_off;
    uint32_t icache_linesize;
    uint32_t tb_struct_size;
    uint32_t host_page_size;
    uint32_t target_page_bits;
    uint32_t insn_start_words;
    uint32_t cpuinfo;
    uint64_t exe_dev;
    uint64_t exe_ino;
    uint64_t exe_size;
    uint64_t exe_mtim_ns;
    uint32_t flags;
    uint32_t prologue_len;
} ScmRunInfo;
QEMU_BUILD_BUG_ON(sizeof(ScmRunInfo) != 144);

typedef struct ScmHelper {
    uint32_t helper_id;
    uint32_t tcg_flags;
    uint32_t typemask;
    uint32_t name_len;
    uint64_t func;
} ScmHelper;
QEMU_BUILD_BUG_ON(sizeof(ScmHelper) != 24);

typedef struct ScmTbHeader {
    uint32_t tb_chunk_version;
    uint32_t slot;
    uint64_t commit_seq;
    uint8_t record[104];
    uint64_t vaddr;
    uint64_t code_fnv64;
    uint32_t attempts;
    uint32_t flags;
    uint32_t insn0_start;
    uint32_t body_end;
    uint32_t ldst_end;
    uint32_t pool_start;
    uint32_t code_size;
    uint16_t icount;
    uint16_t insn_start_words;
    uint32_t n_sites;
    uint32_t n_pool;
    uint32_t n_ldst;
    uint32_t n_opmarks;
    uint32_t n_static_exits;
    uint32_t n_guest_bytes;
    uint64_t reserved;
} ScmTbHeader;
QEMU_BUILD_BUG_ON(sizeof(ScmTbHeader) != 200);
QEMU_BUILD_BUG_ON(offsetof(ScmTbHeader, vaddr) != 120);

typedef struct ScmInsn {
    uint64_t word[3];
    uint32_t host_start;
    uint32_t host_end;
} ScmInsn;
QEMU_BUILD_BUG_ON(sizeof(ScmInsn) != 32);

typedef struct ScmSite {
    uint32_t field_off;
    uint32_t insn_off;
    uint8_t width;
    uint8_t enc;
    uint16_t kind;
    uint32_t aux;
    uint64_t value;
    uint32_t insn_idx;
    uint32_t final_field;
} ScmSite;
QEMU_BUILD_BUG_ON(sizeof(ScmSite) != 32);

typedef struct ScmPool {
    uint32_t user_field_off;
    uint32_t slot_off;
    uint16_t rtype;
    uint16_t nlong;
    int32_t addend;
    uint64_t data0;
} ScmPool;
QEMU_BUILD_BUG_ON(sizeof(ScmPool) != 24);

typedef struct ScmLdst {
    uint32_t jcc_field[2];
    uint32_t slow_start;
    uint32_t slow_end;
    uint32_t raddr_off;
    uint32_t oi;
    uint32_t op_ordinal;
    uint8_t is_ld;
    uint8_t pad[3];
} ScmLdst;
QEMU_BUILD_BUG_ON(sizeof(ScmLdst) != 32);

typedef struct ScmOpMark {
    uint32_t host_off;
    uint16_t kind;
    uint16_t insn_idx;
    uint32_t helper_id;
    uint32_t reserved;
} ScmOpMark;
QEMU_BUILD_BUG_ON(sizeof(ScmOpMark) != 16);

typedef struct ScmStaticExit {
    uint8_t slot;
    uint8_t direct;
    uint16_t insn_idx;
    uint32_t reserved;
    uint64_t dest_vaddr;
} ScmStaticExit;
QEMU_BUILD_BUG_ON(sizeof(ScmStaticExit) != 16);

typedef struct ScmRamBlockRow {
    char idstr[64];
    uint64_t ram_offset;
    uint64_t used_length;
    uint64_t max_length;
    uint64_t host;
} ScmRamBlockRow;
QEMU_BUILD_BUG_ON(sizeof(ScmRamBlockRow) != 96);

/* The v5 .sc record, as tcg/supercache.c lays it out (104 bytes). */
typedef struct ScRecordView {
    uint64_t tb_offset;
    uint64_t end_offset;
    uint64_t tc_offset;
    uint64_t tc_size;
    uint64_t pc;
    uint64_t cs_base;
    uint64_t page_addr0;
    uint64_t page_addr1;
    uint64_t guest_hash;
    uint32_t flags;
    uint32_t cflags;
    uint16_t guest_size;
    uint16_t icount;
    uint16_t jmp_reset_offset[2];
    uint16_t jmp_insn_offset[2];
    uint32_t checksum;
    uint32_t committed;
} ScRecordView;
QEMU_BUILD_BUG_ON(sizeof(ScRecordView) != 104);

/*
 * ---- Static state.  Everything lives in .bss (rule R2/R3).
 */
enum { SCC_IDLE, SCC_STAGING, SCC_READY };

typedef struct SccTag {
    bool set;
    uint16_t kind;
    uint32_t aux;
} SccTag;

static struct {
    int fd;                 /* .scm, moved to >= 1000; valid iff scc_active */
    int maps_fd;            /* /proc/self/maps, moved to >= 1000 */
    uint32_t level;
    bool write_failed;
    uint64_t seq;

    /* RUN_INFO values needed later */
    uintptr_t code_address;
    uint64_t code_size;
    uint32_t target_page_size;
    bool have_run_info;

    /* END counters */
    uint64_t committed;
    uint64_t discarded;
    uint64_t overflow;
    uint64_t capture_error;
    uint64_t write_errors;
    uint32_t n_helpers;
} scc_run;

static struct {
    int state;
    const TranslationBlock *tb;
    const uint8_t *code_buf;
    uint64_t vaddr;
    uint32_t attempts;
    uint32_t flags;
    uint32_t insn0_start;
    uint32_t body_end;
    uint32_t ldst_end;
    uint32_t pool_start;
    uint32_t code_size;
    int cur_insn;
    uint32_t n_insns_seen;
    uint16_t icount;
    uint32_t n_sites, n_pool, n_ldst, n_opmarks, n_exits;
    int last_call_opmark;
    uint32_t n_ldst_ops;
    bool ldst_bracket;
    bool ldst_done;
    int ldst_cur;           /* index into ldst[] or -1 when not recorded */
    uint32_t ldst_cur_insn;
    SccTag branch_tag;
    SccTag movi_tag;
} st;

static ScmInsn st_insns[SCC_CAP_INSNS];
static ScmSite st_sites[SCC_CAP_SITES];
static const TCGLabel *st_site_label[SCC_CAP_SITES];
static ScmPool st_pool[SCC_CAP_POOL];
static ScmLdst st_ldst[SCC_CAP_LDST];
static ScmOpMark st_opmarks[SCC_CAP_OPMARKS];
static uint32_t st_ldst_op_mark[SCC_CAP_LDST];
static ScmStaticExit st_exits[SCC_CAP_STATIC_EXITS];
static uint8_t st_guest[SCC_CAP_GUEST_BYTES];

/* Pre-staging filled by H16 during translate_code, adopted by H3. */
static ScmStaticExit pre_exits[SCC_CAP_STATIC_EXITS];
static uint32_t pre_n_exits;
static bool pre_overflow;

/* Helper intern table: (info, func) -> dense helper_id. */
static struct {
    const TCGHelperInfo *info;
    const void *func;
} helpers[SCC_CAP_HELPERS];
static uint16_t helper_hash[SCC_HELPER_HASH];   /* 0 empty, else id + 1 */

static uint8_t out_buf[SCC_CAP_CHUNK_BUF];
static size_t out_len;
static bool out_overflow;
static char maps_buf[SCC_CAP_MAPS_BUF];

/*
 * ---- Output helpers
 */
static uint64_t scc_fnv(uint64_t h, const void *data, size_t len)
{
    const uint8_t *p = data;

    while (len--) {
        h ^= *p++;
        h *= SCC_FNV_PRIME;
    }
    return h;
}

static bool write_full(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;

    while (len) {
        ssize_t r = write(fd, p, len);

        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r <= 0) {
            return false;
        }
        p += r;
        len -= r;
    }
    return true;
}

static void out_put(const void *data, size_t len)
{
    /* Keep room for the padding and the trailer. */
    if (out_overflow || len > sizeof(out_buf) - 16 - out_len) {
        out_overflow = true;
        return;
    }
    memcpy(out_buf + out_len, data, len);
    out_len += len;
}

static void out_zero(size_t len)
{
    if (out_overflow || len > sizeof(out_buf) - 16 - out_len) {
        out_overflow = true;
        return;
    }
    memset(out_buf + out_len, 0, len);
    out_len += len;
}

static void out_pad8(void)
{
    out_zero(-out_len & 7);
}

static void chunk_begin(uint32_t type)
{
    uint32_t zero = 0;

    out_len = 0;
    out_overflow = false;
    out_put(&type, 4);
    out_put(&zero, 4);
    out_put(&scc_run.seq, 8);
}

/* Pad, add the trailer and write the chunk. */
static void chunk_end(void)
{
    uint32_t payload_len = out_len - 16;
    uint64_t trailer;

    out_pad8();
    if (out_overflow) {
        /* Cannot happen with the design capacities; never write a torn chunk */
        scc_run.write_errors++;
        return;
    }
    memcpy(out_buf + 4, &payload_len, 4);
    trailer = scc_fnv(SCC_FNV_OFFSET, out_buf, out_len);
    memcpy(out_buf + out_len, &trailer, 8);
    out_len += 8;
    if (scc_run.write_failed) {
        scc_run.write_errors++;
        return;
    }
    if (!write_full(scc_run.fd, out_buf, out_len)) {
        /* The file is torn from here on; readers keep the valid prefix. */
        scc_run.write_failed = true;
        scc_run.write_errors++;
        return;
    }
    scc_run.seq++;
}

static void scc_die(const char *msg, const char *arg)
{
    error_report("supercache-capture: %s%s%s", msg, arg ? ": " : "",
                 arg ? arg : "");
    exit(EXIT_FAILURE);
}

static void stderr_puts(const char *s)
{
    /* Best effort; stderr is informational. */
    if (write(STDERR_FILENO, s, strlen(s)) < 0) {
        return;
    }
}

/*
 * ---- MAPS, RAMBLOCKS, END
 */
static void write_maps(uint32_t tag)
{
    size_t len = 0;
    uint32_t truncated = 0, len32, pad = 0;

    while (len < sizeof(maps_buf)) {
        ssize_t r = pread(scc_run.maps_fd, maps_buf + len,
                          sizeof(maps_buf) - len, len);

        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r <= 0) {
            break;
        }
        len += r;
    }
    if (len == sizeof(maps_buf)) {
        char probe;

        truncated = pread(scc_run.maps_fd, &probe, 1, len) > 0;
    }
    len32 = len;
    chunk_begin(SCC_CHUNK_MAPS);
    out_put(&tag, 4);
    out_put(&truncated, 4);
    out_put(&len32, 4);
    out_put(&pad, 4);
    out_put(maps_buf, len);
    chunk_end();
}

static int ramblock_row(RAMBlock *rb, void *opaque)
{
    uint32_t *n = opaque;
    ScmRamBlockRow row;
    const char *id = qemu_ram_get_idstr(rb);

    memset(&row, 0, sizeof(row));
    if (id) {
        strncpy(row.idstr, id, sizeof(row.idstr) - 1);
    }
    row.ram_offset = qemu_ram_get_offset(rb);
    row.used_length = qemu_ram_get_used_length(rb);
    row.max_length = qemu_ram_get_max_length(rb);
    row.host = (uintptr_t)qemu_ram_get_host_addr(rb);
    out_put(&row, sizeof(row));
    (*n)++;
    return 0;
}

static void write_ramblocks(void)
{
    uint32_t n = 0, pad = 0;
    size_t n_pos;

    chunk_begin(SCC_CHUNK_RAMBLOCKS);
    n_pos = out_len;
    out_put(&n, 4);
    out_put(&pad, 4);
    qemu_ram_foreach_block(ramblock_row, &n);
    if (!out_overflow) {
        memcpy(out_buf + n_pos, &n, 4);
    }
    chunk_end();
}

static void scc_finish(void)
{
    uint64_t c[6];
    uint32_t clean = 1;

    if (!scc_active) {
        return;
    }
    scc_in_tb = false;
    if (st.state != SCC_IDLE) {
        scc_run.discarded++;
        st.state = SCC_IDLE;
    }
    write_maps(2);
    c[0] = scc_run.committed;
    c[1] = scc_run.discarded;
    c[2] = scc_run.overflow;
    c[3] = scc_run.capture_error;
    c[4] = scc_run.write_errors;
    c[5] = scc_run.n_helpers;
    chunk_begin(SCC_CHUNK_END);
    out_put(c, sizeof(c));
    out_put(&clean, 4);
    chunk_end();
    scc_active = false;
}

/*
 * ---- H1: configuration
 */
static int fd_high(int fd, const char *what)
{
    int hi = fcntl(fd, F_DUPFD_CLOEXEC, SCC_FD_MIN);

    if (hi < 0) {
        scc_die("cannot move fd to >= 1000", what);
    }
    close(fd);
    return hi;
}

void scc_configure_from_env(void)
{
    const char *path = getenv("QEMU_SC_CAPTURE");
    const char *level = getenv("QEMU_SC_CAPTURE_LEVEL");
    const char *prof = getenv("QEMU_SC_PROFILE");
    ScmFileHeader h;
    struct timespec ts;
    int fd;

    if (!path || !*path || scc_active) {
        return;
    }
    if (!level || !*level || strcmp(level, "reloc") == 0) {
        scc_run.level = 1;
    } else if (strcmp(level, "ops") == 0) {
        scc_die("QEMU_SC_CAPTURE_LEVEL=ops (Tier 1) is reserved and not "
                "implemented in this build", NULL);
    } else {
        scc_die("unknown QEMU_SC_CAPTURE_LEVEL", level);
    }
    if (!tcg_supercache_enabled()) {
        scc_die("QEMU_SC_CAPTURE is set but no supercache file is "
                "configured (-accel tcg,supercache=...)", NULL);
    }
    if (tcg_supercache_flat_requested()) {
        scc_die("QEMU_SC_CAPTURE cannot be used with supercache-flat=on",
                NULL);
    }
    if (prof && *prof) {
        scc_die("QEMU_SC_CAPTURE and QEMU_SC_PROFILE are mutually "
                "exclusive", NULL);
    }
    if (path[0] != '/') {
        scc_die("QEMU_SC_CAPTURE must be an absolute path", path);
    }

    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0) {
        scc_die(strerror(errno), path);
    }
    scc_run.fd = fd_high(fd, path);
    fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        scc_die("cannot open /proc/self/maps", strerror(errno));
    }
    scc_run.maps_fd = fd_high(fd, "/proc/self/maps");

    memset(&h, 0, sizeof(h));
    memcpy(h.magic, SCC_MAGIC, 8);
    h.version = SCC_VERSION;
    h.header_size = sizeof(h);
    h.capture_level = scc_run.level;
    h.pid = getpid();
    clock_gettime(CLOCK_REALTIME, &ts);
    h.created_realtime_ns = (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
    h.checksum = scc_fnv(SCC_FNV_OFFSET, &h, offsetof(ScmFileHeader, checksum));
    if (!write_full(scc_run.fd, &h, sizeof(h))) {
        scc_die("cannot write the .scm header", strerror(errno));
    }

    st.state = SCC_IDLE;
    st.ldst_cur = -1;
    st.last_call_opmark = -1;
    atexit(scc_finish);
    scc_active = true;

    stderr_puts("supercache-capture: level=reloc path=");
    stderr_puts(path);
    stderr_puts("\n");
}

/*
 * ---- H2: RUN_INFO
 */
void scc_run_info(const TCGContext *s, const void *tb_ret_addr,
                  const SccRunInfoArgs *a)
{
    ScmRunInfo ri;
    struct stat sb;
    const uint8_t *buf = a->buffer;

    memset(&ri, 0, sizeof(ri));
    ri.info_version = 1;
    ri.capture_level = scc_run.level;
    ri.code_address = (uintptr_t)buf;
    ri.code_size = a->code_size;
    ri.prologue_end = a->prologue_end;
    ri.tb_ret_off = tb_ret_addr ? (const uint8_t *)tb_ret_addr - buf : 0;
    ri.epilogue_off = tcg_code_gen_epilogue
                      ? (const uint8_t *)tcg_code_gen_epilogue - buf : 0;
    ri.runtime_signature = a->runtime_signature;
    ri.header_record_count_at_load = a->record_count_at_load;
    ri.loaded_max_end = a->loaded_max_end;
    ri.highwater_off = (const uint8_t *)s->code_gen_highwater - buf;
    ri.icache_linesize = qemu_icache_linesize;
    ri.tb_struct_size = a->tb_size;
    ri.host_page_size = a->host_page_size;
    ri.target_page_bits = a->target_page_bits;
    ri.insn_start_words = INSN_START_WORDS;
    ri.cpuinfo = cpuinfo;
    if (stat("/proc/self/exe", &sb) == 0) {
        ri.exe_dev = sb.st_dev;
        ri.exe_ino = sb.st_ino;
        ri.exe_size = sb.st_size;
        ri.exe_mtim_ns = (uint64_t)sb.st_mtim.tv_sec * 1000000000ull +
                         sb.st_mtim.tv_nsec;
    }
    ri.flags = icount_enabled() ? 1 : 0;   /* bit1 flat: always 0 */
    ri.prologue_len = a->prologue_end;

    scc_run.code_address = (uintptr_t)buf;
    scc_run.code_size = a->code_size;
    scc_run.target_page_size = 1u << a->target_page_bits;
    scc_run.have_run_info = true;

    chunk_begin(SCC_CHUNK_RUN_INFO);
    out_put(&ri, sizeof(ri));
    out_put(buf, a->prologue_end);
    chunk_end();
}

/*
 * ---- Staging helpers
 */
static inline uint32_t st_off(const void *p)
{
    return (uint32_t)((const uint8_t *)p - st.code_buf);
}

static inline uint32_t cur_off(const TCGContext *s)
{
    return st_off(s->code_ptr);
}

static inline uint32_t insn_idx32(int idx)
{
    return idx < 0 ? SCC_NONE32 : (uint32_t)idx;
}

static void st_error(void)
{
    st.flags |= SCC_TBF_CAPTURE_ERROR;
}

static int add_site(uint32_t field_off, uint32_t insn_off, unsigned width,
                    unsigned enc, unsigned kind, uint32_t aux, uint64_t value,
                    uint32_t insn_idx, const TCGLabel *l)
{
    ScmSite *p;

    if (st.n_sites >= SCC_CAP_SITES) {
        st.flags |= SCC_TBF_CAPTURE_OVERFLOW;
        return -1;
    }
    p = &st_sites[st.n_sites];
    p->field_off = field_off;
    p->insn_off = insn_off;
    p->width = width;
    p->enc = enc;
    p->kind = kind;
    p->aux = aux;
    p->value = value;
    p->insn_idx = insn_idx;
    p->final_field = 0;
    st_site_label[st.n_sites] = l;
    return st.n_sites++;
}

static int add_opmark(uint32_t host_off, unsigned kind, int insn_idx)
{
    ScmOpMark *m;

    if (st.n_opmarks >= SCC_CAP_OPMARKS) {
        st.flags |= SCC_TBF_CAPTURE_OVERFLOW;
        return -1;
    }
    m = &st_opmarks[st.n_opmarks];
    m->host_off = host_off;
    m->kind = kind;
    m->insn_idx = insn_idx < 0 ? SCC_NONE16 : insn_idx;
    m->helper_id = SCC_NONE32;
    m->reserved = 0;
    return st.n_opmarks++;
}

static void set_tag(SccTag *t, unsigned kind, uint32_t aux)
{
    if (t->set) {
        /* The previous tag was never consumed by its emitter. */
        st_error();
    }
    t->set = true;
    t->kind = kind;
    t->aux = aux;
}

/* Insn index a site belongs to: the issuing ld/st insn inside a slow path. */
static uint32_t site_insn_idx(void)
{
    return st.ldst_bracket ? st.ldst_cur_insn : insn_idx32(st.cur_insn);
}

static uint32_t intern_helper(const TCGHelperInfo *info, const void *func)
{
    uintptr_t k = (uintptr_t)info ^ ((uintptr_t)func >> 3);
    uint32_t h = (uint32_t)((k >> 4) ^ (k >> 17)) & (SCC_HELPER_HASH - 1);
    ScmHelper rec;
    const char *name;
    uint32_t id;

    for (;;) {
        uint16_t e = helper_hash[h];

        if (!e) {
            break;
        }
        if (helpers[e - 1].info == info && helpers[e - 1].func == func) {
            return e - 1;
        }
        h = (h + 1) & (SCC_HELPER_HASH - 1);
    }
    if (scc_run.n_helpers >= SCC_CAP_HELPERS) {
        st.flags |= SCC_TBF_CAPTURE_OVERFLOW;
        return SCC_NONE32;
    }
    id = scc_run.n_helpers++;
    helpers[id].info = info;
    helpers[id].func = func;
    helper_hash[h] = id + 1;

    name = info ? info->name : NULL;
    rec.helper_id = id;
    rec.tcg_flags = info ? info->flags : 0;
    rec.typemask = info ? info->typemask : 0;
    rec.name_len = name ? strlen(name) : 0;
    rec.func = (uintptr_t)func;
    chunk_begin(SCC_CHUNK_HELPER);
    out_put(&rec, sizeof(rec));
    out_put(name ? name : "", rec.name_len);
    chunk_end();
    return id;
}

/*
 * ---- H16a / H16: translation begin and static exits
 */
void scc_translate_begin(void)
{
    if (st.state != SCC_IDLE) {
        /*
         * Staged data that was never committed: a codegen retry (STAGING,
         * same tb, attempts continue) or a TB that tb_gen_code dropped after
         * codegen (READY: one-shot, existing_tb, encode_search overflow).
         */
        scc_run.discarded++;
        if (st.state == SCC_READY) {
            st.tb = NULL;
        }
        st.state = SCC_IDLE;
    }
    scc_in_tb = false;
    pre_n_exits = 0;
    pre_overflow = false;
}

void scc_static_exit(unsigned slot, uint64_t dest_vaddr, bool direct,
                     int insn_idx)
{
    ScmStaticExit *e;

    if (pre_n_exits >= SCC_CAP_STATIC_EXITS) {
        pre_overflow = true;
        return;
    }
    e = &pre_exits[pre_n_exits++];
    e->slot = direct ? slot : 0xFF;
    e->direct = direct;
    e->insn_idx = insn_idx < 0 ? SCC_NONE16 : insn_idx;
    e->reserved = 0;
    e->dest_vaddr = dest_vaddr;
}

/*
 * ---- H3 / H4 / H5
 */
void scc_tb_begin(const TCGContext *s, const TranslationBlock *tb,
                  uint64_t pc_start)
{
    if (st.state != SCC_IDLE) {
        scc_run.discarded++;
        if (st.state == SCC_READY) {
            st.tb = NULL;
        }
    }
    st.attempts = (tb == st.tb) ? st.attempts + 1 : 1;
    st.tb = tb;
    st.code_buf = (const uint8_t *)s->code_buf;
    st.vaddr = pc_start;
    st.flags = pre_overflow ? SCC_TBF_CAPTURE_OVERFLOW : 0;
    st.insn0_start = 0;
    st.body_end = 0;
    st.ldst_end = 0;
    st.pool_start = SCC_NONE32;
    st.code_size = 0;
    st.cur_insn = -1;
    st.n_insns_seen = 0;
    st.icount = 0;
    st.n_sites = st.n_pool = st.n_ldst = st.n_opmarks = 0;
    st.last_call_opmark = -1;
    st.n_ldst_ops = 0;
    st.ldst_bracket = false;
    st.ldst_done = false;
    st.ldst_cur = -1;
    st.ldst_cur_insn = SCC_NONE32;
    st.branch_tag.set = false;
    st.movi_tag.set = false;
    memcpy(st_exits, pre_exits, sizeof(pre_exits[0]) * pre_n_exits);
    st.n_exits = pre_n_exits;
    st.state = SCC_STAGING;
    scc_in_tb = true;
}

void scc_op(const TCGContext *s, const TCGOp *op, int num_insns)
{
    int m;

    switch (op->opc) {
    case INDEX_op_insn_start: {
        int idx = num_insns + 1;

        st.cur_insn = idx;
        st.n_insns_seen = idx + 1;
        if (idx >= SCC_CAP_INSNS) {
            st.flags |= SCC_TBF_CAPTURE_OVERFLOW;
            break;
        }
        for (int i = 0; i < INSN_START_WORDS; i++) {
            st_insns[idx].word[i] =
                tcg_get_insn_start_param((TCGOp *)op, i);
        }
        st_insns[idx].host_start = cur_off(s);
        st_insns[idx].host_end = 0;
        if (idx == 0) {
            st.insn0_start = cur_off(s);
        }
        break;
    }
    case INDEX_op_call:
        st.last_call_opmark = add_opmark(cur_off(s), SCC_OPM_CALL, num_insns);
        break;
    case INDEX_op_qemu_ld:
    case INDEX_op_qemu_ld2:
    case INDEX_op_qemu_st:
    case INDEX_op_qemu_st2:
        m = add_opmark(cur_off(s),
                       (op->opc == INDEX_op_qemu_ld ||
                        op->opc == INDEX_op_qemu_ld2)
                       ? SCC_OPM_QEMU_LD : SCC_OPM_QEMU_ST, num_insns);
        if (st.n_ldst_ops < SCC_CAP_LDST) {
            st_ldst_op_mark[st.n_ldst_ops] = m < 0 ? SCC_NONE32 : m;
        }
        st.n_ldst_ops++;
        break;
    case INDEX_op_exit_tb:
        add_opmark(cur_off(s), SCC_OPM_EXIT_TB, num_insns);
        break;
    case INDEX_op_goto_tb:
        add_opmark(cur_off(s), SCC_OPM_GOTO_TB, num_insns);
        break;
    case INDEX_op_goto_ptr:
        add_opmark(cur_off(s), SCC_OPM_GOTO_PTR, num_insns);
        break;
    default:
        break;
    }
}

void scc_helper(const TCGHelperInfo *info, const void *func)
{
    uint32_t id = intern_helper(info, func);

    set_tag(&st.branch_tag, SCC_SITE_HELPER_CALL, id);
    if (st.last_call_opmark >= 0 &&
        st_opmarks[st.last_call_opmark].helper_id == SCC_NONE32) {
        st_opmarks[st.last_call_opmark].helper_id = id;
    } else {
        /* A call op whose OpMark was not recorded or was already used. */
        st_error();
    }
}

/*
 * ---- H6-H12: backend emitters
 */
void scc_label_jump(const TCGContext *s, const void *insn_start,
                    const void *field, unsigned width, int opc,
                    const TCGLabel *l)
{
    add_site(st_off(field), st_off(insn_start), width,
             width == 1 ? SCC_ENC_REL8 : SCC_ENC_REL32,
             opc == -1 ? SCC_SITE_LABEL_JMP : SCC_SITE_LABEL_JCC,
             0, 0, site_insn_idx(), l);
}

void scc_branch(const TCGContext *s, const void *insn_start,
                const void *field, int call, unsigned enc, const void *dest)
{
    unsigned kind;
    uint32_t aux = 0;

    if (st.branch_tag.set) {
        kind = st.branch_tag.kind;
        aux = st.branch_tag.aux;
        st.branch_tag.set = false;
        if ((kind == SCC_SITE_HELPER_CALL) != !!call) {
            st_error();
        }
    } else if (st.ldst_bracket) {
        kind = call ? SCC_SITE_LDST_HELPER_CALL : SCC_SITE_LDST_RET_JMP;
        aux = st.ldst_cur < 0 ? SCC_NONE32 : (uint32_t)st.ldst_cur;
        if (!call && st.ldst_cur >= 0 &&
            st_off(dest) != st_ldst[st.ldst_cur].raddr_off) {
            st_error();
        }
    } else {
        kind = SCC_SITE_OTHER_BRANCH;
    }
    add_site(st_off(field), st_off(insn_start), 4, enc, kind, aux,
             (uintptr_t)dest, site_insn_idx(), NULL);
}

void scc_movi(const TCGContext *s, const void *insn_start, const void *field,
              unsigned enc, uint64_t arg)
{
    unsigned kind, width;
    uint32_t aux = 0;

    if (st.movi_tag.set) {
        kind = st.movi_tag.kind;
        aux = st.movi_tag.aux;
        st.movi_tag.set = false;
    } else if (enc == SCC_ENC_RIPREL32 || enc == SCC_ENC_IMM64 ||
               (arg >= scc_run.code_address &&
                arg - scc_run.code_address < scc_run.code_size)) {
        kind = SCC_SITE_MOVI_CONST;
    } else {
        return;
    }
    width = enc == SCC_ENC_XOR0 ? 0 : enc == SCC_ENC_IMM64 ? 8 : 4;
    add_site(st_off(field ? field : insn_start), st_off(insn_start), width,
             enc, kind, aux, arg, site_insn_idx(), NULL);
}

void scc_tag_branch(unsigned kind, uint32_t aux)
{
    set_tag(&st.branch_tag, kind, aux);
}

void scc_tag_movi(unsigned kind, uint32_t aux)
{
    if (kind == SCC_SITE_MOVI_LDST_RA) {
        aux = st.ldst_cur < 0 ? SCC_NONE32 : (uint32_t)st.ldst_cur;
    }
    set_tag(&st.movi_tag, kind, aux);
}

void scc_goto_tb(const TCGContext *s, int which, const void *pad_start,
                 const void *field)
{
    /* insn_off is the E9 byte; the nop pad [pad_start, insn_off) precedes. */
    add_site(st_off(field), st_off(field) - 1, 4, SCC_ENC_GOTO_TB_REL32,
             SCC_SITE_GOTO_TB, which, 0, site_insn_idx(), NULL);
}

void scc_goto_ptr(const TCGContext *s, const void *insn_start, int reg)
{
    add_site(st_off(insn_start), st_off(insn_start), 0, SCC_ENC_NONE,
             SCC_SITE_GOTO_PTR, reg, 0, site_insn_idx(), NULL);
}

/*
 * ---- H13: slow paths
 */
void scc_ldst_begin(const TCGContext *s, bool is_ld, uint32_t oi,
                    const void *label_ptr0, const void *label_ptr1,
                    const void *raddr)
{
    uint32_t k = st.n_ldst;
    uint32_t start = cur_off(s);
    uint32_t insn = SCC_NONE32;
    const void *lp[2] = { label_ptr0, label_ptr1 };

    if (st.ldst_bracket) {
        st_error();
    }
    st.ldst_bracket = true;
    /* ldst labels are created in op order: slow path k <-> k-th ld/st op */
    if (k < st.n_ldst_ops && k < SCC_CAP_LDST &&
        st_ldst_op_mark[k] != SCC_NONE32) {
        uint16_t i = st_opmarks[st_ldst_op_mark[k]].insn_idx;

        insn = i == SCC_NONE16 ? SCC_NONE32 : i;
    } else if (k >= st.n_ldst_ops) {
        st_error();
    }
    st.ldst_cur_insn = insn;
    if (k >= SCC_CAP_LDST) {
        st.flags |= SCC_TBF_CAPTURE_OVERFLOW;
        st.ldst_cur = -1;
        return;
    }
    st.ldst_cur = k;
    st.n_ldst++;
    st_ldst[k].jcc_field[0] = label_ptr0 ? st_off(label_ptr0) : SCC_NONE32;
    st_ldst[k].jcc_field[1] = label_ptr1 ? st_off(label_ptr1) : SCC_NONE32;
    st_ldst[k].slow_start = start;
    st_ldst[k].slow_end = 0;
    st_ldst[k].raddr_off = st_off(raddr);
    st_ldst[k].oi = oi;
    st_ldst[k].op_ordinal = k;
    st_ldst[k].is_ld = is_ld;
    memset(st_ldst[k].pad, 0, sizeof(st_ldst[k].pad));
    for (int i = 0; i < 2; i++) {
        if (lp[i]) {
            /* 0F 8x rel32: the opcode is the 2 bytes before the field */
            add_site(st_off(lp[i]), st_off(lp[i]) - 2, 4, SCC_ENC_REL32,
                     SCC_SITE_LDST_FAST_JCC, k,
                     (uintptr_t)(st.code_buf + start), insn, NULL);
        }
    }
}

void scc_ldst_end(const TCGContext *s)
{
    if (!st.ldst_bracket) {
        st_error();
    }
    if (st.ldst_cur >= 0) {
        st_ldst[st.ldst_cur].slow_end = cur_off(s);
    }
    st.ldst_bracket = false;
    st.ldst_cur = -1;
    st.ldst_cur_insn = SCC_NONE32;
}

void scc_ldst_done(const TCGContext *s)
{
    if (st.ldst_bracket || st.n_ldst_ops != st.n_ldst) {
        st_error();
    }
    st.ldst_end = cur_off(s);
    st.ldst_done = true;
}

/*
 * ---- H14: constant pool
 */
void scc_pool_start(const TCGContext *s, const void *a)
{
    st.pool_start = st_off(a);
}

void scc_pool_entry(const TCGContext *s, const void *label, int rtype,
                    intptr_t addend, unsigned nlong, const void *data,
                    uintptr_t value)
{
    uint32_t idx = st.n_pool;
    uint32_t field = st_off(label);
    uint64_t d0;
    bool found = false;

    memcpy(&d0, data, sizeof(d0));
    if (nlong != 1) {
        st_error();
    }
    if (idx >= SCC_CAP_POOL) {
        st.flags |= SCC_TBF_CAPTURE_OVERFLOW;
        return;
    }
    st_pool[idx].user_field_off = field;
    st_pool[idx].slot_off = (uint32_t)(value - (uintptr_t)st.code_buf);
    st_pool[idx].rtype = rtype;
    st_pool[idx].nlong = nlong;
    st_pool[idx].addend = addend;
    st_pool[idx].data0 = d0;
    st.n_pool++;

    /* A pool-indirect branch already has its site (H7); others get one. */
    for (uint32_t i = st.n_sites; i-- > 0;) {
        if (st_sites[i].field_off == field && st_sites[i].width) {
            found = true;
            break;
        }
    }
    if (!found) {
        add_site(field, SCC_NONE32, 4,
                 rtype == R_386_PC32 ? SCC_ENC_RIPREL32 : SCC_ENC_IMM32_ZX,
                 SCC_SITE_POOL_REF, idx, d0, SCC_NONE32, NULL);
    }
}

/*
 * ---- H15: end of code generation
 */
void scc_tb_end(const TCGContext *s, const TranslationBlock *tb,
                size_t code_size)
{
    uint32_t n;

    if (st.state != SCC_STAGING || st.tb != tb) {
        st_error();
    }
    st.icount = tb->icount;
    if (st.n_insns_seen != tb->icount) {
        st_error();
    }
    n = MIN(st.n_insns_seen, (uint32_t)SCC_CAP_INSNS);
    n = MIN(n, (uint32_t)tb->icount);
    for (uint32_t i = 0; i < n; i++) {
        st_insns[i].host_end = s->gen_insn_end_off[i];
    }
    st.body_end = tb->icount ? s->gen_insn_end_off[tb->icount - 1] : 0;
    st.pool_start = s->data_gen_ptr ? st_off(s->data_gen_ptr) : SCC_NONE32;
    st.code_size = code_size;
    if (!st.ldst_done) {
        st_error();
    }
    if (st.branch_tag.set || st.movi_tag.set || st.ldst_bracket) {
        /* A tag still pending at H15 (design 2.3 tag protocol). */
        st_error();
    }

    for (uint32_t i = 0; i < st.n_sites; i++) {
        ScmSite *p = &st_sites[i];
        const TCGLabel *l = st_site_label[i];
        unsigned w = MIN(p->width, 4u);

        if (l) {
            if (l->has_value) {
                p->value = (uintptr_t)l->u.value_ptr;
            } else {
                st_error();
            }
        }
        if (p->width) {
            if ((uint64_t)p->field_off + p->width > code_size) {
                st_error();
                continue;
            }
            p->final_field = 0;
            memcpy(&p->final_field, st.code_buf + p->field_off, w);
        }
        if (p->kind == SCC_SITE_GOTO_TB) {
            p->value = (uintptr_t)st.code_buf + p->field_off + 4 +
                       (int64_t)(int32_t)p->final_field;
            if (p->aux > 1 || tb->jmp_insn_offset[p->aux] != p->field_off) {
                st_error();
            }
        }
    }
    if (st.insn0_start > 0 && !(tb_cflags(tb) & CF_NOIRQ)) {
        st.flags |= SCC_TBF_IRQ_CHECK;
    }
    st.state = SCC_READY;
    scc_in_tb = false;
}

/*
 * ---- H17: commit
 */
void scc_tb_commit(const TranslationBlock *tb, uint64_t slot,
                   const void *record, size_t record_size,
                   const void *buffer)
{
    ScmTbHeader h;
    ScRecordView r;
    bool ok = st.state == SCC_READY && st.tb == tb;
    uint32_t flags = ok ? st.flags : SCC_TBF_CAPTURE_ERROR;
    uint32_t n_guest, first;
    const uint8_t *code = buffer;
    bool first_commit = scc_run.committed == 0;

    memset(&r, 0, sizeof(r));
    if (record_size == sizeof(r)) {
        memcpy(&r, record, sizeof(r));
    } else {
        flags |= SCC_TBF_CAPTURE_ERROR;
    }
    if (ok && st.code_size != r.tc_size) {
        flags |= SCC_TBF_CAPTURE_ERROR;
    }

    /* Guest bytes, read the way supercache.c guest_hash() reads them. */
    n_guest = r.guest_size;
    if (n_guest > SCC_CAP_GUEST_BYTES) {
        n_guest = SCC_CAP_GUEST_BYTES;
        flags |= SCC_TBF_GUEST_TRUNCATED;
    }
    first = MIN(n_guest, scc_run.target_page_size -
                (uint32_t)(r.page_addr0 & (scc_run.target_page_size - 1)));
    if (n_guest) {
        memcpy(st_guest, qemu_map_ram_ptr(NULL, r.page_addr0), first);
        if (first < n_guest) {
            if (r.page_addr1 == UINT64_MAX) {
                n_guest = first;
                flags |= SCC_TBF_GUEST_TRUNCATED;
            } else {
                memcpy(st_guest + first, qemu_map_ram_ptr(NULL, r.page_addr1),
                       n_guest - first);
            }
        }
    }

    memset(&h, 0, sizeof(h));
    h.tb_chunk_version = 1;
    h.slot = slot;
    h.commit_seq = scc_run.committed;
    memcpy(h.record, &r, sizeof(h.record));
    h.code_fnv64 = scc_fnv(SCC_FNV_OFFSET, code + r.tc_offset,
                           r.end_offset - r.tc_offset);
    h.flags = flags;
    h.insn_start_words = INSN_START_WORDS;
    h.n_guest_bytes = n_guest;
    if (ok) {
        h.vaddr = st.vaddr;
        h.attempts = st.attempts;
        h.insn0_start = st.insn0_start;
        h.body_end = st.body_end;
        h.ldst_end = st.ldst_end;
        h.pool_start = st.pool_start;
        h.code_size = st.code_size;
        h.icount = MIN((uint32_t)st.icount, (uint32_t)SCC_CAP_INSNS);
        h.n_sites = st.n_sites;
        h.n_pool = st.n_pool;
        h.n_ldst = st.n_ldst;
        h.n_opmarks = st.n_opmarks;
        h.n_static_exits = st.n_exits;
    } else {
        h.pool_start = SCC_NONE32;
        h.code_size = r.tc_size;
    }

    chunk_begin(SCC_CHUNK_TB);
    out_put(&h, sizeof(h));
    out_put(st_insns, sizeof(st_insns[0]) * h.icount);
    out_put(st_sites, sizeof(st_sites[0]) * h.n_sites);
    out_put(st_pool, sizeof(st_pool[0]) * h.n_pool);
    out_put(st_ldst, sizeof(st_ldst[0]) * h.n_ldst);
    out_put(st_opmarks, sizeof(st_opmarks[0]) * h.n_opmarks);
    out_put(st_exits, sizeof(st_exits[0]) * h.n_static_exits);
    out_put(st_guest, n_guest);
    chunk_end();

    if (flags & SCC_TBF_CAPTURE_OVERFLOW) {
        scc_run.overflow++;
    }
    if (flags & SCC_TBF_CAPTURE_ERROR) {
        scc_run.capture_error++;
    }
    scc_run.committed++;
    st.state = SCC_IDLE;
    st.tb = NULL;

    if (first_commit) {
        write_maps(1);
        write_ramblocks();
    }
}

#else /* !(CONFIG_LINUX && HOST_X86_64) */

void scc_configure_from_env(void)
{
    const char *path = getenv("QEMU_SC_CAPTURE");

    if (path && *path) {
        error_report("supercache-capture: needs a Linux x86-64 host");
        exit(EXIT_FAILURE);
    }
}

void scc_run_info(const TCGContext *s, const void *t, const SccRunInfoArgs *a)
{
}
void scc_tb_begin(const TCGContext *s, const TranslationBlock *tb,
                  uint64_t pc) { }
void scc_op(const TCGContext *s, const TCGOp *op, int n) { }
void scc_helper(const TCGHelperInfo *info, const void *func) { }
void scc_label_jump(const TCGContext *s, const void *i, const void *f,
                    unsigned w, int opc, const TCGLabel *l) { }
void scc_branch(const TCGContext *s, const void *i, const void *f, int c,
                unsigned e, const void *d) { }
void scc_movi(const TCGContext *s, const void *i, const void *f, unsigned e,
              uint64_t a) { }
void scc_tag_branch(unsigned k, uint32_t a) { }
void scc_tag_movi(unsigned k, uint32_t a) { }
void scc_goto_tb(const TCGContext *s, int w, const void *p, const void *f) { }
void scc_goto_ptr(const TCGContext *s, const void *i, int r) { }
void scc_ldst_begin(const TCGContext *s, bool l, uint32_t oi, const void *a,
                    const void *b, const void *r) { }
void scc_ldst_end(const TCGContext *s) { }
void scc_ldst_done(const TCGContext *s) { }
void scc_pool_start(const TCGContext *s, const void *a) { }
void scc_pool_entry(const TCGContext *s, const void *l, int r, intptr_t a,
                    unsigned n, const void *d, uintptr_t v) { }
void scc_tb_end(const TCGContext *s, const TranslationBlock *tb, size_t n) { }
void scc_translate_begin(void) { }
void scc_static_exit(unsigned s, uint64_t d, bool dir, int i) { }
void scc_tb_commit(const TranslationBlock *tb, uint64_t slot,
                   const void *r, size_t n, const void *b) { }

#endif
