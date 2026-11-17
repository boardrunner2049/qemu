/*
 * Persistent TCG translation cache for fuzzing.
 *
 * Generated host code contains process addresses, so the cache is mapped at
 * the same virtual address on every run.  The system-mode entry points below
 * also rebuild all process-local TB lookup and invalidation metadata.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "tcg/supercache.h"
#include "tcg/sc-capture.h"
#include "accel/tcg/sc-profile.h"

#if defined(CONFIG_LINUX) && defined(HOST_X86_64)

#include "qemu/cacheflush.h"
#include "qemu/mprotect.h"
#include "qemu/plugin.h"
#include "qemu/units.h"
#include "exec/cpu-common.h"
#include "exec/log.h"
#include "exec/target_page.h"
#include "qapi/error.h"
#include "system/memory.h"
#include "tcg/tcg.h"
#include "accel/tcg/internal-common.h"
#include "accel/tcg/probe.h"
#include "qemu/bitops.h"
#include "qemu/target-info.h"

#include <sys/file.h>

#define SUPERCACHE_MAGIC          "QSCACHE1"
#define SUPERCACHE_VERSION        5
#define SC6_VERSION               6       /* .sc v6 (WP22) */
#define SUPERCACHE_CODE_OFFSET    (64 * KiB)
#define SUPERCACHE_RECORD_COMMIT  0x53435231U
#define SUPERCACHE_FNV_OFFSET     UINT64_C(1469598103934665603)
#define SUPERCACHE_FNV_PRIME      UINT64_C(1099511628211)
#define SUPERCACHE_FLAT_DIRECT_SPAN (32 * MiB)
#define SUPERCACHE_FLAT_MAX_SPAN  (512 * MiB)

typedef struct SupercacheHeader {
    char magic[8];
    uint32_t version;
    uint32_t header_size;
    uint64_t code_size;
    uint64_t code_address;
    uint64_t prologue_end;
    uint64_t record_count;
    uint64_t runtime_signature;
    uint32_t host_page_size;
    uint32_t target_page_bits;
    uint32_t tb_size;
    uint32_t reserved;
    uint64_t checksum;
} SupercacheHeader;

typedef struct SupercacheRecord {
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
} SupercacheRecord;

typedef struct SupercacheKey {
    uint64_t pc;
    uint64_t cs_base;
    uint64_t page_addr0;
    uint32_t flags;
    uint32_t cflags;
} SupercacheKey;

typedef struct SupercacheEntry {
    SupercacheRecord record;
    uint32_t next;
    bool used;
    bool invalid;
} SupercacheEntry;

typedef struct SupercacheFlatPage {
    uint32_t first;
    uint32_t mask;
    uint32_t count;
} SupercacheFlatPage;

static struct {
    char *path;
    int fd;
    void *buffer;
    size_t size;
    SupercacheHeader header;
    SupercacheEntry *entries;
    uint32_t *buckets;
    uint32_t entry_count;
    uint32_t entry_capacity;
    uint32_t bucket_count;
    uint32_t *flat_direct;
    uint64_t flat_direct_size;
    SupercacheFlatPage *flat_pages;
    uint32_t *flat_slots;
    uint32_t flat_page_count;
    uint64_t flat_guest_base;
    uint64_t max_end;
    uint64_t loaded_max_end;
    SupercacheHeader loaded_header;
    bool configured;
    bool initialized;
    bool flat;
} supercache = {
    .fd = -1,
};

static uint64_t hash_bytes(uint64_t hash, const void *data, size_t len)
{
    const uint8_t *p = data;

    while (len--) {
        hash ^= *p++;
        hash *= SUPERCACHE_FNV_PRIME;
    }
    return hash;
}

static uint64_t header_checksum(const SupercacheHeader *header)
{
    return hash_bytes(SUPERCACHE_FNV_OFFSET, header,
                      offsetof(SupercacheHeader, checksum));
}

static uint32_t record_checksum(const SupercacheRecord *record)
{
    uint64_t h = hash_bytes(SUPERCACHE_FNV_OFFSET, record,
                            offsetof(SupercacheRecord, checksum));
    return h ^ (h >> 32);
}

/*
 * Include every executable mapping and its backing file timestamp.  This
 * covers QEMU, shared libraries, and loaded plugins, whose addresses may be
 * embedded directly in generated code.
 */
static uint64_t runtime_signature(void)
{
    g_autofree char *maps = NULL;
    gsize maps_len;
    struct stat st;
    uint64_t hash = SUPERCACHE_FNV_OFFSET;

    if (stat("/proc/self/exe", &st) == 0) {
        hash = hash_bytes(hash, &st.st_dev, sizeof(st.st_dev));
        hash = hash_bytes(hash, &st.st_ino, sizeof(st.st_ino));
        hash = hash_bytes(hash, &st.st_size, sizeof(st.st_size));
        hash = hash_bytes(hash, &st.st_mtim, sizeof(st.st_mtim));
    }
    if (g_file_get_contents("/proc/self/maps", &maps, &maps_len, NULL)) {
        g_auto(GStrv) lines = g_strsplit(maps, "\n", -1);

        for (char **line = lines; *line; line++) {
            char *path;

            if (!strstr(*line, " r-x")) {
                continue;
            }
            hash = hash_bytes(hash, *line, strlen(*line));
            path = strchr(*line, '/');
            if (path && stat(path, &st) == 0) {
                hash = hash_bytes(hash, &st.st_size, sizeof(st.st_size));
                hash = hash_bytes(hash, &st.st_mtim, sizeof(st.st_mtim));
            }
        }
    }
    return hash;
}

static uint32_t key_hash(const SupercacheKey *key)
{
    uint64_t h = key->pc ^ rol64(key->cs_base, 13) ^
                 rol64(key->page_addr0, 29) ^
                 ((uint64_t)key->flags << 32) ^ key->cflags;

    return h ^ (h >> 32);
}

static bool key_equal(const SupercacheKey *ka, const SupercacheKey *kb)
{
    return ka->pc == kb->pc && ka->cs_base == kb->cs_base &&
           ka->page_addr0 == kb->page_addr0 && ka->flags == kb->flags &&
           ka->cflags == kb->cflags;
}

static SupercacheKey record_key(const SupercacheRecord *record)
{
    return (SupercacheKey) {
        .pc = (record->cflags & CF_PCREL) ? 0 : record->pc,
        .cs_base = record->cs_base,
        .page_addr0 = record->page_addr0,
        .flags = record->flags,
        .cflags = record->cflags,
    };
}

static void *index_map(size_t bytes)
{
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    void *p;

#ifdef MAP_NORESERVE
    flags |= MAP_NORESERVE;
#endif
    p = mmap(NULL, bytes, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (p == MAP_FAILED) {
        error_report("supercache: cannot allocate translation index: %s",
                     strerror(errno));
        exit(EXIT_FAILURE);
    }
    return p;
}

static uint32_t next_power_of_two(uint64_t value)
{
    uint64_t result = 1;

    while (result < value) {
        result <<= 1;
    }
    if (result > UINT32_MAX) {
        error_report("supercache: translation index is too large");
        exit(EXIT_FAILURE);
    }
    return result;
}

static void index_resize(uint64_t wanted)
{
    uint32_t capacity = next_power_of_two(MAX(wanted, UINT64_C(65536)));
    uint32_t bucket_count = next_power_of_two((uint64_t)capacity * 2);
    size_t entries_size = (size_t)capacity * sizeof(*supercache.entries);
    size_t buckets_size = (size_t)bucket_count * sizeof(*supercache.buckets);
    SupercacheEntry *entries = index_map(entries_size);
    uint32_t *buckets = index_map(buckets_size);

    if (supercache.entries) {
        memcpy(entries, supercache.entries,
               (size_t)supercache.entry_count * sizeof(*entries));
        munmap(supercache.entries,
               (size_t)supercache.entry_capacity * sizeof(*entries));
        munmap(supercache.buckets,
               (size_t)supercache.bucket_count * sizeof(*buckets));
    }
    supercache.entries = entries;
    supercache.buckets = buckets;
    supercache.entry_capacity = capacity;
    supercache.bucket_count = bucket_count;

    for (uint32_t i = 0; i < supercache.entry_count; i++) {
        SupercacheKey key = record_key(&entries[i].record);
        uint32_t bucket = key_hash(&key) & (bucket_count - 1);

        entries[i].next = buckets[bucket];
        buckets[bucket] = i + 1;
    }
}

static void index_record(const SupercacheRecord *record, bool used)
{
    SupercacheEntry *entry;
    SupercacheKey key;
    uint32_t bucket;

    if (supercache.entry_count == supercache.entry_capacity) {
        index_resize((uint64_t)supercache.entry_capacity * 2);
    }
    entry = &supercache.entries[supercache.entry_count];
    entry->record = *record;
    entry->used = used;
    key = record_key(record);
    bucket = key_hash(&key) & (supercache.bucket_count - 1);
    entry->next = supercache.buckets[bucket];
    supercache.buckets[bucket] = ++supercache.entry_count;
}

static void write_header(void)
{
    ssize_t ret;

    supercache.header.checksum = header_checksum(&supercache.header);
    ret = pwrite(supercache.fd, &supercache.header,
                 sizeof(supercache.header), 0);
    if (ret != sizeof(supercache.header)) {
        error_report("supercache: cannot update '%s': %s", supercache.path,
                     ret < 0 ? strerror(errno) : "short write");
        exit(EXIT_FAILURE);
    }
}

static off_t record_offset(uint64_t index)
{
    return SUPERCACHE_CODE_OFFSET + supercache.size +
           index * sizeof(SupercacheRecord);
}

static void sync_cache(void)
{
    if (supercache.initialized) {
        fdatasync(supercache.fd);
    }
}

static void sc6_configure_from_env(void);

/* scc H1 needs to reject supercache-flat; see tcg/sc-capture.c. */
bool tcg_supercache_flat_requested(void)
{
    return supercache.configured && supercache.flat;
}

void tcg_supercache_configure(const char *path, bool flat, int splitwx,
                              unsigned max_threads)
{
    if (!path) {
        /* Let capture/profile reject their switch without a supercache. */
        scc_configure_from_env();
        scp_configure_from_env();
        return;
    }
    if (splitwx > 0) {
        error_report("supercache is incompatible with split-wx=on");
        exit(EXIT_FAILURE);
    }
    if (max_threads != 1) {
        error_report("supercache requires thread=single");
        exit(EXIT_FAILURE);
    }
    supercache.path = g_canonicalize_filename(path, NULL);
    supercache.configured = true;
    supercache.flat = flat;
    sc6_configure_from_env();
    scc_configure_from_env();
    scp_configure_from_env();
}

bool tcg_supercache_enabled(void)
{
    return supercache.configured;
}

void *tcg_supercache_buffer(void)
{
    return supercache.initialized ? supercache.buffer : NULL;
}

uint64_t tcg_supercache_loaded_max_end(void)
{
    return supercache.initialized ? supercache.loaded_max_end : 0;
}

static void *map_cache(size_t size, uintptr_t address, Error **errp)
{
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    void *buffer;

#ifdef MAP_FIXED_NOREPLACE
    if (address) {
        flags |= MAP_FIXED_NOREPLACE;
    }
#endif
    buffer = mmap((void *)address, size, PROT_NONE, flags, -1, 0);
    if (buffer == MAP_FAILED) {
        error_setg_errno(errp, errno, "allocate supercache code buffer");
        return NULL;
    }
    if (address && buffer != (void *)address) {
        munmap(buffer, size);
        error_setg(errp, "supercache address %p is unavailable",
                   (void *)address);
        return NULL;
    }
    return buffer;
}

static bool valid_header(const SupercacheHeader *header, size_t size,
                         uint64_t signature)
{
    return memcmp(header->magic, SUPERCACHE_MAGIC, 8) == 0 &&
           (header->version == SUPERCACHE_VERSION ||
            header->version == SC6_VERSION) &&
           header->header_size == sizeof(*header) &&
           header->checksum == header_checksum(header) &&
           header->code_size == size &&
           header->runtime_signature == signature &&
           header->host_page_size == qemu_real_host_page_size() &&
           header->target_page_bits == TARGET_PAGE_BITS &&
           header->tb_size == sizeof(TranslationBlock);
}

static void load_records(void)
{
    struct stat st;
    uint64_t count = supercache.header.record_count;
    SupercacheRecord *records;
    size_t records_size;

    if (fstat(supercache.fd, &st) < 0 ||
        st.st_size < record_offset(0)) {
        count = 0;
    } else {
        uint64_t available = (st.st_size - record_offset(0)) /
                             sizeof(SupercacheRecord);
        count = MIN(count, available);
    }

    if (!count) {
        return;
    }
    records_size = count * sizeof(*records);
    records = mmap(NULL, records_size, PROT_READ, MAP_PRIVATE, supercache.fd,
                   record_offset(0));
    if (records == MAP_FAILED) {
        error_report("supercache: cannot map translation records: %s",
                     strerror(errno));
        exit(EXIT_FAILURE);
    }

    for (uint64_t i = 0; i < count; i++) {
        const SupercacheRecord *record = &records[i];

        if (record->committed != SUPERCACHE_RECORD_COMMIT ||
            record->checksum != record_checksum(record) ||
            record->tb_offset > supercache.size - sizeof(TranslationBlock) ||
            record->tb_offset >= record->tc_offset ||
            record->tc_offset >= record->end_offset ||
            record->tc_size > record->end_offset - record->tc_offset ||
            record->end_offset > supercache.size) {
            warn_report("supercache: ignoring invalid record #%" PRIu64, i);
            continue;
        }
        index_record(record, false);
        supercache.max_end = MAX(supercache.max_end, record->end_offset);
    }
    munmap(records, records_size);
}

static uint32_t flat_pc_hash(uint64_t pc)
{
    pc ^= pc >> 32;
    return pc * UINT32_C(2654435761);
}

static void flat_index_init(void)
{
    uint64_t min_pc = UINT64_MAX;
    uint64_t max_pc = 0;
    uint64_t slot_count = 0;

    if (!supercache.flat || !supercache.entry_count) {
        return;
    }
    for (uint32_t i = 0; i < supercache.entry_count; i++) {
        const SupercacheRecord *record = &supercache.entries[i].record;

        if (record->cflags & CF_PCREL) {
            continue;
        }
        min_pc = MIN(min_pc, record->pc);
        max_pc = MAX(max_pc, record->pc + MAX(record->guest_size, 1));
    }
    if (min_pc == UINT64_MAX) {
        return;
    }
    if (max_pc - min_pc > SUPERCACHE_FLAT_MAX_SPAN) {
        error_report("supercache-flat guest PC span is larger than 512 MiB; "
                     "disable supercache-flat for this firmware");
        exit(EXIT_FAILURE);
    }
    if (max_pc - min_pc <= SUPERCACHE_FLAT_DIRECT_SPAN) {
        supercache.flat_guest_base = min_pc;
        supercache.flat_direct_size = max_pc - min_pc;
        supercache.flat_direct = index_map(
            (size_t)supercache.flat_direct_size *
            sizeof(*supercache.flat_direct));
        for (uint32_t i = 0; i < supercache.entry_count; i++) {
            const SupercacheRecord *record = &supercache.entries[i].record;

            if (!(record->cflags & CF_PCREL)) {
                supercache.flat_direct[record->pc - min_pc] = i + 1;
            }
        }
        return;
    }
    supercache.flat_guest_base = min_pc & TARGET_PAGE_MASK;
    supercache.flat_page_count =
        DIV_ROUND_UP(max_pc - supercache.flat_guest_base, TARGET_PAGE_SIZE);
    supercache.flat_pages = index_map((size_t)supercache.flat_page_count *
                                      sizeof(*supercache.flat_pages));

    for (uint32_t i = 0; i < supercache.entry_count; i++) {
        const SupercacheRecord *record = &supercache.entries[i].record;

        if (!(record->cflags & CF_PCREL)) {
            uint32_t page = (record->pc - supercache.flat_guest_base) >>
                            TARGET_PAGE_BITS;

            supercache.flat_pages[page].count++;
        }
    }
    for (uint32_t i = 0; i < supercache.flat_page_count; i++) {
        SupercacheFlatPage *page = &supercache.flat_pages[i];

        if (page->count) {
            uint32_t capacity = next_power_of_two((uint64_t)page->count * 2);

            if (slot_count > UINT32_MAX - capacity) {
                error_report("supercache-flat translation index is too large");
                exit(EXIT_FAILURE);
            }
            page->first = slot_count;
            page->mask = capacity - 1;
            slot_count += capacity;
        }
    }
    supercache.flat_slots = index_map((size_t)slot_count *
                                      sizeof(*supercache.flat_slots));

    for (uint32_t i = 0; i < supercache.entry_count; i++) {
        const SupercacheRecord *record = &supercache.entries[i].record;
        SupercacheFlatPage *page;
        uint32_t slot;

        if (record->cflags & CF_PCREL) {
            continue;
        }
        page = &supercache.flat_pages[
            (record->pc - supercache.flat_guest_base) >> TARGET_PAGE_BITS];
        slot = flat_pc_hash(record->pc) & page->mask;
        while (supercache.flat_slots[page->first + slot]) {
            slot = (slot + 1) & page->mask;
        }
        supercache.flat_slots[page->first + slot] = i + 1;
    }
}

static bool pread_full(int fd, void *buffer, size_t size, off_t offset)
{
    uint8_t *p = buffer;

    while (size) {
        ssize_t ret = pread(fd, p, size, offset);

        if (ret < 0 && errno == EINTR) {
            continue;
        }
        if (ret <= 0) {
            return false;
        }
        p += ret;
        size -= ret;
        offset += ret;
    }
    return true;
}

static bool pwrite_full(int fd, const void *buffer, size_t size, off_t offset)
{
    const uint8_t *p = buffer;

    while (size) {
        ssize_t ret = pwrite(fd, p, size, offset);

        if (ret < 0 && errno == EINTR) {
            continue;
        }
        if (ret <= 0) {
            return false;
        }
        p += ret;
        size -= ret;
        offset += ret;
    }
    return true;
}

/*
 * .sc v6 loader (design/B3-B4-design.md §5, WP22, Q1-Q11).
 *
 * A v6 file is a v5 file whose header has version 6 and whose `reserved`
 * word holds feature flags; the extension table lives at file offset 0x100,
 * inside the [80, 0x10000) gap that no v5 path reads or writes.  It names
 * variants (relocated clones C' of a general record C, never in the QHT),
 * guarded slots (registered goto_tb slots of a grown record R whose stub
 * S checks the whole lookup key) and links (SPEC slot -> variant).
 *
 * The loader validates the table (fail loud, before any guest instruction),
 * arms SPEC links when both members are activated in the same tb_flush
 * epoch, and unlinks every guarded slot and every built variant's slots on
 * every TLB flush.  Nothing here touches generated code paths of v5 files.
 */

#define SC6_EXT_OFFSET           0x100
#define SC6_ARRAYS_OFFSET        0x140
#define SC6_EXT_MAGIC            "QSCX6EXT"
#define SC6_FEAT_EXT_TABLE       (1u << 0)
#define SC6_FEAT_VARIANTS        (1u << 1)
#define SC6_FEAT_GUARDED_SLOTS   (1u << 2)
#define SC6_FEAT_REWRITTEN       (1u << 3)
#define SC6_KNOWN_FEATURES       0xfu
#define SC6_VARIANT_FACTS        (1u << 0)
#define SC6_SLOT_GENERAL         1
#define SC6_SLOT_SPEC            2
#define SC6_EXIT_RETURN          1
#define SC6_EXIT_STATIC          2
#define SC6_MAX_DISARMS          64
#define SC6_NONE                 UINT32_MAX

typedef struct Sc6ExtHeader {
    char magic[8];
    uint32_t ext_version;
    uint32_t ext_header_size;
    uint32_t n_variants;
    uint32_t n_slots;
    uint32_t n_links;
    uint16_t variant_entry_size;
    uint16_t slot_entry_size;
    uint16_t link_entry_size;
    uint16_t reserved0;
    uint32_t reserved1;
    uint64_t variants_max_end;
    uint8_t artifact_id8[8];
    uint64_t checksum;
} Sc6ExtHeader;

typedef struct Sc6VariantEntry {
    uint64_t general_tb_offset;
    uint64_t tb_offset;
    uint64_t tc_offset;
    uint64_t tc_size;
    uint64_t end_offset;
    uint64_t code_fnv64;
    uint32_t variant_id;
    uint32_t flags;
    uint64_t reserved;
} Sc6VariantEntry;

typedef struct Sc6SlotEntry {
    uint64_t src_tb_offset;
    uint8_t slot_n;
    uint8_t kind;
    uint8_t exit_class;
    uint8_t reserved;
    uint32_t target_vaddr;
    uint32_t guard_off;
    uint32_t guard_len;
    uint64_t guard_fnv64;
} Sc6SlotEntry;

typedef struct Sc6LinkEntry {
    uint32_t slot_index;
    uint32_t variant_index;
    uint64_t reserved;
} Sc6LinkEntry;

QEMU_BUILD_BUG_ON(sizeof(Sc6ExtHeader) != 64);
QEMU_BUILD_BUG_ON(offsetof(Sc6ExtHeader, checksum) != 56);
QEMU_BUILD_BUG_ON(sizeof(Sc6VariantEntry) != 64);
QEMU_BUILD_BUG_ON(sizeof(Sc6SlotEntry) != 32);
QEMU_BUILD_BUG_ON(offsetof(Sc6SlotEntry, guard_fnv64) != 24);
QEMU_BUILD_BUG_ON(sizeof(Sc6LinkEntry) != 16);
QEMU_BUILD_BUG_ON(offsetof(SupercacheHeader, reserved) != 68);

typedef struct Sc6Variant {
    Sc6VariantEntry e;
    uint32_t general;           /* loaded entry index of C */
    uint32_t link;              /* link index */
    TranslationBlock *built;    /* C' struct, built in this flush epoch */
} Sc6Variant;

typedef struct Sc6Slot {
    Sc6SlotEntry e;
    uint32_t src;               /* loaded entry index of R */
    uint32_t link;              /* link index (SPEC) or SC6_NONE */
} Sc6Slot;

typedef struct Sc6Link {
    uint32_t slot;
    uint32_t variant;
    bool armed;
    bool disarmed_epoch;
} Sc6Link;

enum {
    SC6_REFUSE_FORBIDDEN,
    SC6_REFUSE_PROFILE,
    SC6_REFUSE_ONE_INSN,
    SC6_REFUSE_NOCHAIN,
    SC6_REFUSE_SINGLESTEP,
    SC6_REFUSE_BREAKPOINTS,
    SC6_REFUSE_WATCHPOINTS,
    SC6_REFUSE_INVALID,
    SC6_REFUSE_TWO_PAGE,
    SC6_REFUSE_MMU_IDX,
    SC6_REFUSE_PROBE_NO_HOST,
    SC6_REFUSE_PROBE_PAGE_SIZE,
    SC6_REFUSE_PROBE_MISMATCH,
    SC6_REFUSE_BUSY,
    SC6_REFUSE__COUNT,
};

static const char *const sc6_refuse_names[SC6_REFUSE__COUNT] = {
    [SC6_REFUSE_FORBIDDEN] = "forbidden",
    [SC6_REFUSE_PROFILE] = "profile_mode",
    [SC6_REFUSE_ONE_INSN] = "one_insn_per_tb",
    [SC6_REFUSE_NOCHAIN] = "nochain",
    [SC6_REFUSE_SINGLESTEP] = "singlestep",
    [SC6_REFUSE_BREAKPOINTS] = "breakpoints",
    [SC6_REFUSE_WATCHPOINTS] = "watchpoints",
    [SC6_REFUSE_INVALID] = "member_invalid",
    [SC6_REFUSE_TWO_PAGE] = "two_page_target",
    [SC6_REFUSE_MMU_IDX] = "mmu_idx",
    [SC6_REFUSE_PROBE_NO_HOST] = "probe_no_host",
    [SC6_REFUSE_PROBE_PAGE_SIZE] = "probe_page_size",
    [SC6_REFUSE_PROBE_MISMATCH] = "probe_mismatch",
    [SC6_REFUSE_BUSY] = "slot_busy",
};

enum {
    SC6_FORBID_NONE,
    SC6_FORBID_ONE_INSN,
    SC6_FORBID_PLUGIN,
    SC6_FORBID_TLB_BUDGET,
};

static const char *const sc6_forbid_names[] = {
    [SC6_FORBID_NONE] = "none",
    [SC6_FORBID_ONE_INSN] = "one_insn_per_tb",
    [SC6_FORBID_PLUGIN] = "plugin_reset",
    [SC6_FORBID_TLB_BUDGET] = "tlb_disarm_budget",
};

/* Set once QEMU_SC_V6_STATS was accepted; read by cpu-exec/translate-all. */
bool tcg_sc6_stats_active;

static struct {
    bool loaded;
    bool forbidden;             /* qatomic: written by the monitor thread */
    int forbid_reason;          /* qatomic */
    uint32_t features;
    uint8_t artifact_id8[8];
    uint32_t n_variants, n_slots, n_links;
    Sc6Variant *variants;
    Sc6Slot *slots;
    Sc6Link *links;
    uint32_t n_entries;         /* records loaded from the file */
    TranslationBlock **live;    /* per loaded entry: activated TB, or NULL */
    uint8_t *role;              /* per loaded entry: SC6_ROLE_* */
    uint32_t disarms;
    char *stats_path;
    struct {
        int64_t ext_load_ns;
        uint64_t activations;
        uint64_t armed;
        uint64_t refused[SC6_REFUSE__COUNT];
        uint64_t variants_built;
        uint64_t disarm_tlb_events;
        uint64_t disarm_tlb_links;
        uint64_t tlb_hook_calls;
        uint64_t disarm_flush_links;
        uint64_t flush_resets;
        uint64_t disarm_forbid_events;
        uint64_t disarm_forbid_links;
        uint64_t forbid_requests;
        uint64_t slots_unlinked;
        uint64_t variant_slots_unlinked;
        uint64_t variant_entry_exits;
        uint64_t variant_exits;
        uint64_t variant_restores;
        uint64_t invariant_checks;
        uint64_t invariant_violations;
    } st;
} sc6;

#define SC6_ROLE_SRC      1     /* R of some guarded slot */
#define SC6_ROLE_GENERAL  2     /* C of some variant */

static G_NORETURN G_GNUC_PRINTF(1, 2) void sc6_die(const char *fmt, ...)
{
    va_list ap;
    g_autofree char *reason = NULL;

    va_start(ap, fmt);
    reason = g_strdup_vprintf(fmt, ap);
    va_end(ap);
    error_report("supercache: invalid v6 extension: %s", reason);
    exit(EXIT_FAILURE);
}

/* First failing check of valid_header(), for the "discarding" warning. */
static const char *header_problem(const SupercacheHeader *header, size_t size,
                                  uint64_t signature)
{
    if (header->header_size != sizeof(*header)) {
        return "header_size";
    }
    if (header->checksum != header_checksum(header)) {
        return "header checksum";
    }
    if (header->code_size != size) {
        return "code_size";
    }
    if (header->runtime_signature != signature) {
        return "runtime signature";
    }
    if (header->host_page_size != qemu_real_host_page_size()) {
        return "host page size";
    }
    if (header->target_page_bits != TARGET_PAGE_BITS) {
        return "target page bits";
    }
    if (header->tb_size != sizeof(TranslationBlock)) {
        return "tb_size";
    }
    return "unknown";
}

static int sc6_cmp_offset(const void *a, const void *b)
{
    const SupercacheEntry *e = supercache.entries;
    uint64_t x = e[*(const uint32_t *)a].record.tb_offset;
    uint64_t y = e[*(const uint32_t *)b].record.tb_offset;

    return x < y ? -1 : x > y;
}

/* Q3: loaded entry index whose record has @tb_offset, or SC6_NONE. */
static uint32_t sc6_find(const uint32_t *order, uint32_t n, uint64_t tb_offset)
{
    uint32_t lo = 0, hi = n;

    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        uint64_t v = supercache.entries[order[mid]].record.tb_offset;

        if (v == tb_offset) {
            return order[mid];
        }
        if (v < tb_offset) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return SC6_NONE;
}

static bool sc6_ranges_overlap(uint64_t a0, uint64_t a1,
                               uint64_t b0, uint64_t b1)
{
    return a0 < b1 && b0 < a1;
}

/*
 * Q2: parse and validate the extension table (design §5.3, §5.4).  Called
 * in the reuse branch of tcg_supercache_alloc_code_buffer() after
 * load_records() and before loaded_max_end is set.  Every failure exits.
 * The two code hashes are checked later, after the code pread (Q4).
 */
static void sc6_load_ext(void)
{
    const SupercacheHeader *h = &supercache.header;
    int64_t t0 = g_get_monotonic_time();
    Sc6ExtHeader x;
    g_autofree uint8_t *arrays = NULL;
    g_autofree uint32_t *order = NULL;
    uint64_t arrays_size, hash, max_end = 0;
    uint64_t floor, limit;
    uint32_t n = supercache.entry_count;
    const size_t tb_struct = ROUND_UP(sizeof(TranslationBlock), 64);

    if (h->reserved & ~SC6_KNOWN_FEATURES) {
        sc6_die("unknown feature bits 0x%" PRIx32,
                h->reserved & ~SC6_KNOWN_FEATURES);
    }
    if (!(h->reserved & SC6_FEAT_EXT_TABLE)) {
        sc6_die("feature EXT_TABLE clear");
    }
    if (supercache.flat) {
        sc6_die("v6 needs normal mode");
    }
    if (strcmp(target_name(), "arm") != 0) {
        sc6_die("v6 needs the arm target");
    }
    if (!pread_full(supercache.fd, &x, sizeof(x), SC6_EXT_OFFSET)) {
        sc6_die("cannot read the extension header");
    }
    if (memcmp(x.magic, SC6_EXT_MAGIC, 8) != 0) {
        sc6_die("bad ext magic");
    }
    if (x.ext_version != 1) {
        sc6_die("bad ext_version %" PRIu32, x.ext_version);
    }
    if (x.ext_header_size != sizeof(x)) {
        sc6_die("bad ext_header_size %" PRIu32, x.ext_header_size);
    }
    if (x.variant_entry_size != sizeof(Sc6VariantEntry) ||
        x.slot_entry_size != sizeof(Sc6SlotEntry) ||
        x.link_entry_size != sizeof(Sc6LinkEntry)) {
        sc6_die("bad entry sizes %u/%u/%u", x.variant_entry_size,
                x.slot_entry_size, x.link_entry_size);
    }
    if (x.reserved0 || x.reserved1) {
        sc6_die("reserved header fields not zero");
    }
    arrays_size = (uint64_t)x.n_variants * sizeof(Sc6VariantEntry) +
                  (uint64_t)x.n_slots * sizeof(Sc6SlotEntry) +
                  (uint64_t)x.n_links * sizeof(Sc6LinkEntry);
    if (SC6_ARRAYS_OFFSET + arrays_size > SUPERCACHE_CODE_OFFSET) {
        sc6_die("ext table too large");
    }
    arrays = g_malloc0(arrays_size + 1);
    if (arrays_size &&
        !pread_full(supercache.fd, arrays, arrays_size, SC6_ARRAYS_OFFSET)) {
        sc6_die("cannot read the extension arrays");
    }
    hash = hash_bytes(SUPERCACHE_FNV_OFFSET, &x,
                      offsetof(Sc6ExtHeader, checksum));
    hash = hash_bytes(hash, arrays, arrays_size);
    if (hash != x.checksum) {
        sc6_die("ext checksum mismatch");
    }
    if (!!(h->reserved & SC6_FEAT_VARIANTS) != !!x.n_variants) {
        sc6_die("feature VARIANTS disagrees with n_variants %" PRIu32,
                x.n_variants);
    }
    if (!!(h->reserved & SC6_FEAT_GUARDED_SLOTS) != !!x.n_slots) {
        sc6_die("feature GUARDED_SLOTS disagrees with n_slots %" PRIu32,
                x.n_slots);
    }
    memcpy(sc6.artifact_id8, x.artifact_id8, 8);
    if (!ldq_he_p(sc6.artifact_id8)) {
        sc6_die("artifact id is zero");
    }

    /* Q3: tb_offset -> loaded entry index (unique among valid records). */
    order = g_new(uint32_t, n + 1);
    for (uint32_t i = 0; i < n; i++) {
        order[i] = i;
    }
    qsort(order, n, sizeof(*order), sc6_cmp_offset);
    for (uint32_t i = 1; i < n; i++) {
        uint64_t a = supercache.entries[order[i - 1]].record.tb_offset;

        if (a == supercache.entries[order[i]].record.tb_offset) {
            sc6_die("duplicate record tb_offset 0x%" PRIx64, a);
        }
    }

    sc6.n_entries = n;
    sc6.n_variants = x.n_variants;
    sc6.n_slots = x.n_slots;
    sc6.n_links = x.n_links;
    sc6.variants = g_new0(Sc6Variant, x.n_variants + 1);
    sc6.slots = g_new0(Sc6Slot, x.n_slots + 1);
    sc6.links = g_new0(Sc6Link, x.n_links + 1);
    sc6.live = g_new0(TranslationBlock *, n + 1);
    sc6.role = g_new0(uint8_t, n + 1);
    sc6.features = h->reserved;

    floor = ROUND_UP(h->prologue_end, 64);
    limit = supercache.size - qemu_real_host_page_size() - 1024;

    for (uint32_t i = 0; i < x.n_variants; i++) {
        Sc6Variant *v = &sc6.variants[i];
        const SupercacheRecord *c;

        memcpy(&v->e, arrays + i * sizeof(Sc6VariantEntry), sizeof(v->e));
        v->link = SC6_NONE;
        v->general = sc6_find(order, n, v->e.general_tb_offset);
        if (v->general == SC6_NONE) {
            sc6_die("variant %u: general_tb_offset 0x%" PRIx64
                    " names no valid record", i, v->e.general_tb_offset);
        }
        c = &supercache.entries[v->general].record;
        if (v->e.variant_id != i) {
            sc6_die("variant %u: variant_id %" PRIu32 " is not dense",
                    i, v->e.variant_id);
        }
        if (v->e.flags & ~SC6_VARIANT_FACTS) {
            sc6_die("variant %u: unknown flags 0x%" PRIx32, i, v->e.flags);
        }
        if (v->e.reserved) {
            sc6_die("variant %u: reserved not zero", i);
        }
        if (v->e.tb_offset % 64) {
            sc6_die("variant %u: tb_offset 0x%" PRIx64 " not 64-aligned",
                    i, v->e.tb_offset);
        }
        if (v->e.tc_offset < v->e.tb_offset ||
            v->e.tc_offset - v->e.tb_offset != tb_struct) {
            sc6_die("variant %u: tc_offset - tb_offset != %zu", i, tb_struct);
        }
        if (v->e.tc_size != c->tc_size) {
            sc6_die("variant %u: tc_size 0x%" PRIx64 " != C tc_size 0x%"
                    PRIx64, i, v->e.tc_size, c->tc_size);
        }
        if (v->e.end_offset != v->e.tc_offset +
                               (c->end_offset - c->tc_offset)) {
            sc6_die("variant %u: end_offset does not match C's extent", i);
        }
        if (v->e.tb_offset < floor) {
            sc6_die("variant %u: below the prologue", i);
        }
        if (v->e.end_offset >= limit) {
            sc6_die("variant %u: end_offset 0x%" PRIx64 " out of range",
                    i, v->e.end_offset);
        }
        for (uint32_t k = 0; k < n; k++) {
            const SupercacheRecord *r = &supercache.entries[k].record;

            if (sc6_ranges_overlap(v->e.tb_offset, v->e.end_offset,
                                   r->tb_offset, r->end_offset)) {
                sc6_die("variant %u: overlaps record at tb_offset 0x%"
                        PRIx64, i, r->tb_offset);
            }
        }
        for (uint32_t k = 0; k < i; k++) {
            if (sc6_ranges_overlap(v->e.tb_offset, v->e.end_offset,
                                   sc6.variants[k].e.tb_offset,
                                   sc6.variants[k].e.end_offset)) {
                sc6_die("variant %u: overlaps variant %u", i, k);
            }
        }
        max_end = MAX(max_end, v->e.end_offset);
        sc6.role[v->general] |= SC6_ROLE_GENERAL;
    }
    if (x.variants_max_end != max_end) {
        sc6_die("variants_max_end 0x%" PRIx64 " != 0x%" PRIx64,
                x.variants_max_end, max_end);
    }

    for (uint32_t i = 0; i < x.n_slots; i++) {
        Sc6Slot *s = &sc6.slots[i];
        const SupercacheRecord *r;
        uint32_t n_slot, jmp, rst, g_end;

        memcpy(&s->e, arrays + x.n_variants * sizeof(Sc6VariantEntry) +
               i * sizeof(Sc6SlotEntry), sizeof(s->e));
        s->link = SC6_NONE;
        s->src = sc6_find(order, n, s->e.src_tb_offset);
        if (s->src == SC6_NONE) {
            sc6_die("slot %u: src_tb_offset 0x%" PRIx64
                    " names no valid record", i, s->e.src_tb_offset);
        }
        r = &supercache.entries[s->src].record;
        n_slot = s->e.slot_n;
        if (n_slot > 1) {
            sc6_die("slot %u: slot_n %u", i, n_slot);
        }
        if (s->e.kind != SC6_SLOT_GENERAL && s->e.kind != SC6_SLOT_SPEC) {
            sc6_die("slot %u: bad kind %u", i, s->e.kind);
        }
        if (s->e.exit_class != SC6_EXIT_RETURN &&
            s->e.exit_class != SC6_EXIT_STATIC) {
            sc6_die("slot %u: bad exit_class %u", i, s->e.exit_class);
        }
        if (s->e.reserved) {
            sc6_die("slot %u: reserved not zero", i);
        }
        jmp = r->jmp_insn_offset[n_slot];
        rst = r->jmp_reset_offset[n_slot];
        if (jmp == TB_JMP_OFFSET_INVALID || rst == TB_JMP_OFFSET_INVALID) {
            sc6_die("slot %u: R has no registered jump %u", i, n_slot);
        }
        if (s->e.guard_len == 0 || s->e.guard_off >= r->tc_size ||
            (uint64_t)s->e.guard_off + s->e.guard_len > r->tc_size) {
            sc6_die("slot %u: guard [0x%" PRIx32 ", +0x%" PRIx32
                    ") outside R's code", i, s->e.guard_off, s->e.guard_len);
        }
        g_end = s->e.guard_off + s->e.guard_len;
        if (jmp < s->e.guard_off || jmp + 4 > g_end ||
            rst < s->e.guard_off || rst >= g_end) {
            sc6_die("slot %u: jump %u (insn 0x%x, reset 0x%x) outside the "
                    "guard", i, n_slot, jmp, rst);
        }
        if ((r->tc_offset + jmp) % 4) {
            sc6_die("slot %u: jump field not 4-aligned", i);
        }
        for (uint32_t k = 0; k < i; k++) {
            if (sc6.slots[k].src == s->src &&
                sc6.slots[k].e.slot_n == n_slot) {
                sc6_die("slot %u: duplicates slot %u", i, k);
            }
        }
        sc6.role[s->src] |= SC6_ROLE_SRC;
    }

    for (uint32_t i = 0; i < x.n_links; i++) {
        Sc6Link *l = &sc6.links[i];
        Sc6LinkEntry le;
        const SupercacheRecord *c;

        memcpy(&le, arrays + x.n_variants * sizeof(Sc6VariantEntry) +
               x.n_slots * sizeof(Sc6SlotEntry) + i * sizeof(Sc6LinkEntry),
               sizeof(le));
        if (le.reserved) {
            sc6_die("link %u: reserved not zero", i);
        }
        if (le.slot_index >= x.n_slots) {
            sc6_die("link %u: slot_index %" PRIu32 " out of range",
                    i, le.slot_index);
        }
        if (le.variant_index >= x.n_variants) {
            sc6_die("link %u: variant_index %" PRIu32 " out of range",
                    i, le.variant_index);
        }
        if (sc6.slots[le.slot_index].e.kind != SC6_SLOT_SPEC) {
            sc6_die("link %u: slot %" PRIu32 " is not SPEC",
                    i, le.slot_index);
        }
        if (sc6.slots[le.slot_index].link != SC6_NONE) {
            sc6_die("slot %" PRIu32 ": more than one link", le.slot_index);
        }
        if (sc6.variants[le.variant_index].link != SC6_NONE) {
            sc6_die("variant %" PRIu32 ": more than one link",
                    le.variant_index);
        }
        c = &supercache.entries[sc6.variants[le.variant_index].general].record;
        if ((sc6.slots[le.slot_index].e.target_vaddr & ~TARGET_PAGE_MASK) !=
            (c->page_addr0 & ~TARGET_PAGE_MASK)) {
            sc6_die("link %u: target 0x%" PRIx32
                    " is not at C's page offset", i,
                    sc6.slots[le.slot_index].e.target_vaddr);
        }
        sc6.slots[le.slot_index].link = i;
        sc6.variants[le.variant_index].link = i;
        l->slot = le.slot_index;
        l->variant = le.variant_index;
    }
    for (uint32_t i = 0; i < x.n_slots; i++) {
        if (sc6.slots[i].e.kind == SC6_SLOT_SPEC &&
            sc6.slots[i].link == SC6_NONE) {
            sc6_die("slot %u: SPEC slot has no link", i);
        }
    }
    for (uint32_t i = 0; i < x.n_variants; i++) {
        if (sc6.variants[i].link == SC6_NONE) {
            sc6_die("variant %u: has no link", i);
        }
    }

    /* Q4: variant code is loaded and never overwritten by translations. */
    supercache.max_end = MAX(supercache.max_end, max_end);
    sc6.loaded = true;
    sc6.st.ext_load_ns = (g_get_monotonic_time() - t0) * 1000;
}

/* Q4: code and guard hashes, after the code pread in after_prologue. */
static void sc6_verify_hashes(void)
{
    const uint8_t *buf = supercache.buffer;

    for (uint32_t i = 0; i < sc6.n_variants; i++) {
        const Sc6VariantEntry *e = &sc6.variants[i].e;

        if (hash_bytes(SUPERCACHE_FNV_OFFSET, buf + e->tc_offset,
                       e->end_offset - e->tc_offset) != e->code_fnv64) {
            sc6_die("variant %u: code hash mismatch", i);
        }
    }
    for (uint32_t i = 0; i < sc6.n_slots; i++) {
        const Sc6Slot *s = &sc6.slots[i];
        const SupercacheRecord *r = &supercache.entries[s->src].record;

        if (hash_bytes(SUPERCACHE_FNV_OFFSET,
                       buf + r->tc_offset + s->e.guard_off,
                       s->e.guard_len) != s->e.guard_fnv64) {
            sc6_die("slot %u: guard hash mismatch", i);
        }
    }
}

static bool sc6_is_variant(const TranslationBlock *tb, uint32_t *index)
{
    uintptr_t off = (uintptr_t)tb - (uintptr_t)supercache.buffer;

    for (uint32_t i = 0; i < sc6.n_variants; i++) {
        if (sc6.variants[i].e.tb_offset == off) {
            if (index) {
                *index = i;
            }
            return true;
        }
    }
    return false;
}

/* §4.6 arm-time conditions; returns SC6_REFUSE__COUNT when all hold. */
static int sc6_arm_conditions(CPUState *cpu, TranslationBlock *R,
                              TranslationBlock *G, uint32_t vc)
{
    CPUTLBEntryFull *full = NULL;
    void *host = NULL;
    int mmu_idx;

    if (qatomic_read(&sc6.forbidden)) {
        return SC6_REFUSE_FORBIDDEN;
    }
    if (scp_active) {
        return SC6_REFUSE_PROFILE;
    }
    if (qatomic_read(&one_insn_per_tb)) {
        return SC6_REFUSE_ONE_INSN;
    }
    if (qemu_loglevel_mask(CPU_LOG_TB_NOCHAIN)) {
        return SC6_REFUSE_NOCHAIN;
    }
    if (cpu->singlestep_enabled) {
        return SC6_REFUSE_SINGLESTEP;
    }
    if (!QTAILQ_EMPTY(&cpu->breakpoints)) {
        return SC6_REFUSE_BREAKPOINTS;
    }
    if (!QTAILQ_EMPTY(&cpu->watchpoints)) {
        return SC6_REFUSE_WATCHPOINTS;
    }
    if ((tb_cflags(R) | tb_cflags(G)) & CF_INVALID) {
        return SC6_REFUSE_INVALID;
    }
    if (tb_page_addr1(G) != -1) {
        return SC6_REFUSE_TWO_PAGE;
    }
    /*
     * The lookup's fetch MMU index: FIELD_EX32(G->flags, TBFLAG_ANY,
     * MMUIDX) (target/arm/cpu.h, bits 4..7).  This file is compiled once
     * for all targets, so the field is extracted by position; the load
     * refuses any target other than arm.
     */
    mmu_idx = extract32(G->flags, 4, 4);
    if (mmu_idx >= NB_MMU_MODES) {
        return SC6_REFUSE_MMU_IDX;
    }
    probe_access_full_mmu(cpu_env(cpu), vc, 1, MMU_INST_FETCH, mmu_idx,
                          &host, &full);
    if (!host) {
        return SC6_REFUSE_PROBE_NO_HOST;
    }
    if (!full || full->lg_page_size < TARGET_PAGE_BITS) {
        return SC6_REFUSE_PROBE_PAGE_SIZE;
    }
    if (qemu_ram_addr_from_host(host) != tb_page_addr0(G)) {
        return SC6_REFUSE_PROBE_MISMATCH;
    }
    return SC6_REFUSE__COUNT;
}

/* Build C' from G (= the live general C), as lookup_entry builds C. */
static TranslationBlock *sc6_build_variant(CPUState *cpu, Sc6Variant *v,
                                           TranslationBlock *G)
{
    TranslationBlock *cp = (TranslationBlock *)
        ((uint8_t *)supercache.buffer + v->e.tb_offset);

    memset(cp, 0, sizeof(*cp));
    cp->pc = G->pc;
    cp->cs_base = G->cs_base;
    cp->flags = G->flags;
    cp->cflags = tb_cflags(G);
    cp->size = G->size;
    cp->icount = G->icount;
    cp->tc.ptr = (uint8_t *)supercache.buffer + v->e.tc_offset;
    cp->tc.size = v->e.tc_size;
    tb_set_page_addr0(cp, tb_page_addr0(G));
    tb_set_page_addr1(cp, tb_page_addr1(G));
    memcpy(cp->jmp_reset_offset, G->jmp_reset_offset,
           sizeof(cp->jmp_reset_offset));
    memcpy(cp->jmp_insn_offset, G->jmp_insn_offset,
           sizeof(cp->jmp_insn_offset));
    qemu_spin_init(&cp->jmp_lock);
    cp->jmp_list_head = 0;
    cp->jmp_list_next[0] = cp->jmp_list_next[1] = 0;
    cp->jmp_dest[0] = cp->jmp_dest[1] = 0;
    qemu_thread_jit_write();
    for (int k = 0; k < 2; k++) {
        if (cp->jmp_reset_offset[k] != TB_JMP_OFFSET_INVALID) {
            tb_reset_jump(cp, k);
        }
    }
    flush_idcache_range((uintptr_t)cp->tc.ptr, (uintptr_t)cp->tc.ptr,
                        cp->tc.size);
    tcg_tb_insert(cp);          /* region tree only: unwind finds C' */
    v->built = cp;
    sc6.st.variants_built++;
    return cp;
}

static void sc6_try_arm(CPUState *cpu, uint32_t li)
{
    Sc6Link *l = &sc6.links[li];
    Sc6Slot *s = &sc6.slots[l->slot];
    Sc6Variant *v = &sc6.variants[l->variant];
    TranslationBlock *R = sc6.live[s->src];
    TranslationBlock *G = sc6.live[v->general];
    TranslationBlock *cp;
    int n = s->e.slot_n;
    int why;

    if (l->armed || l->disarmed_epoch || !R || !G) {
        return;
    }
    why = sc6_arm_conditions(cpu, R, G, s->e.target_vaddr);
    if (why != SC6_REFUSE__COUNT) {
        sc6.st.refused[why]++;
        return;
    }
    cp = v->built ? v->built : sc6_build_variant(cpu, v, G);

    qemu_thread_jit_write();
    qemu_spin_lock(&G->jmp_lock);
    if (!(G->cflags & CF_INVALID) &&
        qatomic_cmpxchg(&R->jmp_dest[n], (uintptr_t)NULL,
                        (uintptr_t)G) == (uintptr_t)NULL) {
        tb_set_jmp_target(R, n, (uintptr_t)cp->tc.ptr);
        R->jmp_list_next[n] = G->jmp_list_head;
        G->jmp_list_head = (uintptr_t)R | n;
        l->armed = true;
        sc6.st.armed++;
    } else {
        sc6.st.refused[SC6_REFUSE_BUSY]++;
    }
    qemu_spin_unlock(&G->jmp_lock);
    qemu_thread_jit_execute();
}

/* Q5: called at the end of lookup_entry() when @tb was linked. */
static void sc6_on_activate(CPUState *cpu, uint32_t index,
                            TranslationBlock *tb)
{
    sc6.live[index] = tb;
    sc6.st.activations++;
    for (uint32_t i = 0; i < sc6.n_links; i++) {
        const Sc6Link *l = &sc6.links[i];

        if (sc6.slots[l->slot].src == index ||
            sc6.variants[l->variant].general == index) {
            sc6_try_arm(cpu, i);
        }
    }
}

/*
 * Debug invariant (design §5.6): after a disarm, no SPEC slot points at a
 * variant, no guarded slot and no variant slot is linked.
 */
static void sc6_check_disarmed(void)
{
    uint64_t bad = 0;

    sc6.st.invariant_checks++;
    for (uint32_t i = 0; i < sc6.n_slots; i++) {
        const Sc6Slot *s = &sc6.slots[i];
        TranslationBlock *R = sc6.live[s->src];
        int n = s->e.slot_n;

        if (!R || (tb_cflags(R) & CF_INVALID)) {
            continue;
        }
        if ((qatomic_read(&R->jmp_dest[n]) & ~(uintptr_t)1) ||
            R->jmp_target_addr[n] !=
            (uintptr_t)R->tc.ptr + R->jmp_reset_offset[n]) {
            bad++;
        }
    }
    for (uint32_t i = 0; i < sc6.n_variants; i++) {
        TranslationBlock *cp = sc6.variants[i].built;

        if (!cp || (tb_cflags(cp) & CF_INVALID)) {
            continue;
        }
        for (int n = 0; n < 2; n++) {
            if (cp->jmp_reset_offset[n] != TB_JMP_OFFSET_INVALID &&
                (qatomic_read(&cp->jmp_dest[n]) & ~(uintptr_t)1)) {
                bad++;
            }
        }
    }
    for (uint32_t i = 0; i < sc6.n_links; i++) {
        if (sc6.links[i].armed) {
            bad++;
        }
    }
    sc6.st.invariant_violations += bad;
#ifdef CONFIG_DEBUG_TCG
    g_assert(bad == 0);
#endif
}

/*
 * Unlink every guarded slot of a live, valid R and both registered slots of
 * every built variant; clear every armed link for the rest of the epoch.
 * Runs on the vCPU thread (TLB-flush workers) or in the exclusive context
 * (Q9/Q11 disarm).  Returns the number of armed links cleared.
 */
static uint32_t sc6_unlink_all(void)
{
    uint32_t cleared = 0;

    qemu_thread_jit_write();
    for (uint32_t i = 0; i < sc6.n_slots; i++) {
        TranslationBlock *R = sc6.live[sc6.slots[i].src];

        if (R && !(tb_cflags(R) & CF_INVALID)) {
            tb_unlink_jump(R, sc6.slots[i].e.slot_n);
            sc6.st.slots_unlinked++;
        }
    }
    for (uint32_t i = 0; i < sc6.n_variants; i++) {
        TranslationBlock *cp = sc6.variants[i].built;

        if (!cp || (tb_cflags(cp) & CF_INVALID)) {
            continue;
        }
        for (int n = 0; n < 2; n++) {
            if (cp->jmp_reset_offset[n] != TB_JMP_OFFSET_INVALID) {
                tb_unlink_jump(cp, n);
                sc6.st.variant_slots_unlinked++;
            }
        }
    }
    for (uint32_t i = 0; i < sc6.n_links; i++) {
        Sc6Link *l = &sc6.links[i];

        if (l->armed) {
            cleared++;
            l->armed = false;
            l->disarmed_epoch = true;
        }
    }
    qemu_thread_jit_execute();
    if (tcg_sc6_stats_active) {
        sc6_check_disarmed();
    }
    return cleared;
}

static bool sc6_any_live(void)
{
    for (uint32_t i = 0; i < sc6.n_slots; i++) {
        if (sc6.live[sc6.slots[i].src]) {
            return true;
        }
    }
    for (uint32_t i = 0; i < sc6.n_variants; i++) {
        if (sc6.variants[i].built) {
            return true;
        }
    }
    return false;
}

static void sc6_forbid(int reason)
{
    if (!qatomic_xchg(&sc6.forbidden, true)) {
        qatomic_set(&sc6.forbid_reason, reason);
    }
}

/* Q7: end of every vCPU TLB-flush worker (cputlb.c). */
void tcg_supercache_mapping_changed(CPUState *cpu)
{
    uint32_t cleared;

    if (likely(!sc6.loaded)) {
        return;
    }
    sc6.st.tlb_hook_calls++;
    if (!sc6_any_live()) {
        return;
    }
    cleared = sc6_unlink_all();
    sc6.st.disarm_tlb_events++;
    sc6.st.disarm_tlb_links += cleared;
    if (cleared && ++sc6.disarms >= SC6_MAX_DISARMS) {
        sc6_forbid(SC6_FORBID_TLB_BUDGET);
    }
}

static void sc6_disarm_all_work(CPUState *cpu, run_on_cpu_data data)
{
    g_assert(cpu_in_exclusive_context(cpu));
    if (sc6.loaded && sc6_any_live()) {
        sc6.st.disarm_forbid_events++;
        sc6.st.disarm_forbid_links += sc6_unlink_all();
    }
}

/*
 * Q9: tcg_set_one_insn_per_tb(true).  At run time this runs on the monitor
 * thread (HMP one-insn-per-tb), so it only sets the flag and queues the
 * disarm into the exclusive context, like tb_flush.
 */
void tcg_supercache_v6_one_insn_per_tb(void)
{
    sc6.st.forbid_requests++;
    sc6_forbid(SC6_FORBID_ONE_INSN);
    if (supercache.initialized && sc6.loaded && first_cpu) {
        async_safe_run_on_cpu(first_cpu, sc6_disarm_all_work,
                              RUN_ON_CPU_NULL);
    }
}

/* Q11: plugin reset/uninstall and scoreboard growth (exclusive context). */
void tcg_supercache_v6_forbid(void)
{
    sc6.st.forbid_requests++;
    sc6_forbid(SC6_FORBID_PLUGIN);
    if (sc6.loaded && sc6_any_live()) {
        sc6.st.disarm_forbid_events++;
        sc6.st.disarm_forbid_links += sc6_unlink_all();
    }
}

/* Q6: tcg_supercache_runtime_reset (tb_flush, exclusive context). */
static void sc6_runtime_reset(void)
{
    if (!sc6.loaded) {
        return;
    }
    sc6.st.flush_resets++;
    for (uint32_t i = 0; i < sc6.n_links; i++) {
        if (sc6.links[i].armed) {
            sc6.st.disarm_flush_links++;
        }
        sc6.links[i].armed = false;
        sc6.links[i].disarmed_epoch = false;
    }
    for (uint32_t i = 0; i < sc6.n_variants; i++) {
        sc6.variants[i].built = NULL;
    }
    memset(sc6.live, 0, sc6.n_entries * sizeof(*sc6.live));
}

/* Q10 (cpu_tb_exec), only while QEMU_SC_V6_STATS is set. */
void tcg_supercache_v6_note_exit(TranslationBlock *tb, int tb_exit)
{
    if (sc6.loaded && sc6_is_variant(tb, NULL)) {
        sc6.st.variant_exits++;
        if (tb_exit == TB_EXIT_REQUESTED) {
            sc6.st.variant_entry_exits++;
        }
    }
}

/* Q10 (cpu_restore_state_from_tb), only while QEMU_SC_V6_STATS is set. */
void tcg_supercache_v6_note_restore(TranslationBlock *tb)
{
    if (sc6.loaded && sc6_is_variant(tb, NULL)) {
        sc6.st.variant_restores++;
    }
}

static void sc6_write_stats(void)
{
    g_autoptr(GString) j = g_string_new("{\n");
    int reason = qatomic_read(&sc6.forbid_reason);

    g_string_append_printf(j, "  \"schema\": \"qemu-sc-v6-stats@1\",\n");
    g_string_append_printf(j, "  \"loaded\": %s,\n",
                           sc6.loaded ? "true" : "false");
    g_string_append_printf(j, "  \"file_version\": %" PRIu32 ",\n",
                           supercache.loaded_header.version);
    g_string_append_printf(j, "  \"feature_flags\": %" PRIu32 ",\n",
                           sc6.features);
    g_string_append(j, "  \"artifact_id8\": \"");
    for (int i = 0; i < 8; i++) {
        g_string_append_printf(j, "%02x", sc6.artifact_id8[i]);
    }
    g_string_append(j, "\",\n");
    g_string_append_printf(j, "  \"n_variants\": %" PRIu32 ",\n"
                           "  \"n_slots\": %" PRIu32 ",\n"
                           "  \"n_links\": %" PRIu32 ",\n",
                           sc6.n_variants, sc6.n_slots, sc6.n_links);
    g_string_append_printf(j, "  \"ext_load_ns\": %" PRId64 ",\n",
                           sc6.st.ext_load_ns);
    g_string_append_printf(j, "  \"activations\": %" PRIu64 ",\n",
                           sc6.st.activations);
    g_string_append_printf(j, "  \"links_armed\": %" PRIu64 ",\n",
                           sc6.st.armed);
    g_string_append(j, "  \"refused\": {");
    for (int i = 0; i < SC6_REFUSE__COUNT; i++) {
        g_string_append_printf(j, "%s\"%s\": %" PRIu64, i ? ", " : "",
                               sc6_refuse_names[i], sc6.st.refused[i]);
    }
    g_string_append(j, "},\n");
    g_string_append_printf(j,
        "  \"variants_built\": %" PRIu64 ",\n"
        "  \"tlb_hook_calls\": %" PRIu64 ",\n"
        "  \"disarm_tlb_events\": %" PRIu64 ",\n"
        "  \"disarm_tlb_links\": %" PRIu64 ",\n"
        "  \"flush_resets\": %" PRIu64 ",\n"
        "  \"disarm_flush_links\": %" PRIu64 ",\n"
        "  \"forbid_requests\": %" PRIu64 ",\n"
        "  \"disarm_forbid_events\": %" PRIu64 ",\n"
        "  \"disarm_forbid_links\": %" PRIu64 ",\n"
        "  \"slots_unlinked\": %" PRIu64 ",\n"
        "  \"variant_slots_unlinked\": %" PRIu64 ",\n"
        "  \"variant_exits\": %" PRIu64 ",\n"
        "  \"variant_entry_exits\": %" PRIu64 ",\n"
        "  \"variant_restores\": %" PRIu64 ",\n"
        "  \"invariant_checks\": %" PRIu64 ",\n"
        "  \"invariant_violations\": %" PRIu64 ",\n",
        sc6.st.variants_built, sc6.st.tlb_hook_calls,
        sc6.st.disarm_tlb_events, sc6.st.disarm_tlb_links,
        sc6.st.flush_resets, sc6.st.disarm_flush_links,
        sc6.st.forbid_requests, sc6.st.disarm_forbid_events,
        sc6.st.disarm_forbid_links, sc6.st.slots_unlinked,
        sc6.st.variant_slots_unlinked, sc6.st.variant_exits,
        sc6.st.variant_entry_exits, sc6.st.variant_restores,
        sc6.st.invariant_checks, sc6.st.invariant_violations);
    g_string_append(j, "  \"links\": [");
    for (uint32_t i = 0; i < sc6.n_links; i++) {
        g_string_append_printf(j, "%s{\"armed\": %s, \"disarmed_epoch\": %s}",
                               i ? ", " : "",
                               sc6.links[i].armed ? "true" : "false",
                               sc6.links[i].disarmed_epoch ? "true" : "false");
    }
    g_string_append(j, "],\n");
    g_string_append_printf(j, "  \"tlb_disarm_budget_used\": %" PRIu32 ",\n",
                           sc6.disarms);
    g_string_append_printf(j, "  \"forbidden\": %s,\n",
                           qatomic_read(&sc6.forbidden) ? "true" : "false");
    g_string_append_printf(j, "  \"forbid_reason\": \"%s\"\n}\n",
                           sc6_forbid_names[reason]);
    if (!g_file_set_contents(sc6.stats_path, j->str, j->len, NULL)) {
        warn_report("supercache: cannot write QEMU_SC_V6_STATS file '%s'",
                    sc6.stats_path);
    }
}

static void sc6_configure_from_env(void)
{
    const char *path = getenv("QEMU_SC_V6_STATS");

    if (!path || !*path) {
        return;
    }
    if (!g_path_is_absolute(path)) {
        error_report("supercache: QEMU_SC_V6_STATS must be an absolute path");
        exit(EXIT_FAILURE);
    }
    sc6.stats_path = g_strdup(path);
    tcg_sc6_stats_active = true;
    atexit(sc6_write_stats);
}

int tcg_supercache_alloc_code_buffer(size_t size, void **buffer,
                                     Error **errp)
{
    SupercacheHeader disk_header;
    uint64_t signature;
    bool reuse = false;
    off_t code_end = SUPERCACHE_CODE_OFFSET + size;

    if (!supercache.configured) {
        return 0;
    }

    supercache.fd = open(supercache.path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (supercache.fd < 0) {
        error_setg_errno(errp, errno, "open supercache '%s'", supercache.path);
        return -1;
    }
    if (flock(supercache.fd, LOCK_EX | LOCK_NB) < 0) {
        error_setg_errno(errp, errno, "lock supercache '%s'", supercache.path);
        return -1;
    }

    signature = runtime_signature();
    if (pread(supercache.fd, &disk_header, sizeof(disk_header), 0) ==
            sizeof(disk_header)) {
        if (valid_header(&disk_header, size, signature)) {
            reuse = true;
            supercache.header = disk_header;
        } else if (memcmp(disk_header.magic, SUPERCACHE_MAGIC, 8) == 0 &&
                   disk_header.version == SC6_VERSION) {
            /* Q1: the stock path below truncates; say so for v6 files. */
            warn_report("supercache: discarding v6 file: %s",
                        header_problem(&disk_header, size, signature));
        }
    }

    supercache.size = size;
    if (!reuse) {
        if (ftruncate(supercache.fd, code_end) < 0) {
            error_setg_errno(errp, errno, "resize supercache '%s'",
                             supercache.path);
            return -1;
        }
        memset(&supercache.header, 0, sizeof(supercache.header));
        memcpy(supercache.header.magic, SUPERCACHE_MAGIC, 8);
        supercache.header.version = SUPERCACHE_VERSION;
        supercache.header.header_size = sizeof(supercache.header);
        supercache.header.code_size = size;
        supercache.header.runtime_signature = signature;
        supercache.header.host_page_size = qemu_real_host_page_size();
        supercache.header.target_page_bits = TARGET_PAGE_BITS;
        supercache.header.tb_size = sizeof(TranslationBlock);
    }

    supercache.buffer = map_cache(size,
        reuse ? supercache.header.code_address : 0, errp);
    if (!supercache.buffer) {
        return -1;
    }

    supercache.header.code_address = (uintptr_t)supercache.buffer;
    index_resize(reuse ? supercache.header.record_count + 1 : 1);
    if (reuse) {
        load_records();
        flat_index_init();
        if (supercache.header.version == SC6_VERSION) {
            sc6_load_ext();                         /* Q2, Q3, Q4 */
        }
        supercache.loaded_max_end = supercache.max_end;
        supercache.loaded_header = disk_header;
    } else {
        write_header();
    }
    supercache.initialized = true;
    atexit(sync_cache);
    *buffer = supercache.buffer;
    return PROT_NONE;
}

void tcg_supercache_after_prologue(TCGContext *s)
{
    uint64_t prologue_end;
    bool header_changed;

    if (!supercache.initialized) {
        return;
    }
    prologue_end = (uint8_t *)s->code_ptr - (uint8_t *)supercache.buffer;
    if (supercache.header.prologue_end &&
        supercache.header.prologue_end != prologue_end) {
        error_report("supercache: TCG prologue layout changed");
        exit(EXIT_FAILURE);
    }
    header_changed = supercache.header.prologue_end != prologue_end;
    supercache.header.prologue_end = prologue_end;
    if (supercache.max_end) {
        uint64_t highwater = (uint8_t *)s->code_gen_highwater -
                             (uint8_t *)supercache.buffer;
        size_t cached_size = supercache.max_end - prologue_end;

        if (supercache.max_end >= highwater) {
            error_report("supercache: cached translations exceed the buffer");
            exit(EXIT_FAILURE);
        }
        if (!pread_full(supercache.fd,
                        (uint8_t *)supercache.buffer + prologue_end,
                        cached_size,
                        SUPERCACHE_CODE_OFFSET + prologue_end)) {
            error_report("supercache: cannot load cached host code: %s",
                         errno ? strerror(errno) : "short read");
            exit(EXIT_FAILURE);
        }
        if (sc6.loaded) {
            sc6_verify_hashes();                    /* Q4 */
        }
        qatomic_set(&s->code_gen_ptr,
                    (uint8_t *)supercache.buffer + supercache.max_end);
    }
    if (header_changed) {
        write_header();
    }
    if (unlikely(scc_active)) {
        /* scc H2: RUN_INFO (design 2.5.3) */
        SccRunInfoArgs a = {
            .buffer = supercache.buffer,
            .code_size = supercache.header.code_size,
            .prologue_end = supercache.header.prologue_end,
            .runtime_signature = supercache.header.runtime_signature,
            .record_count_at_load = supercache.header.record_count,
            .loaded_max_end = supercache.loaded_max_end,
            .tb_size = supercache.header.tb_size,
            .host_page_size = supercache.header.host_page_size,
            .target_page_bits = supercache.header.target_page_bits,
        };
        scc_run_info(s, tcg_target_tb_ret_addr(), &a);
    }
}

void tcg_supercache_runtime_reset(void)
{
    if (supercache.initialized) {
        for (uint32_t i = 0; i < supercache.entry_count; i++) {
            supercache.entries[i].used = false;
            supercache.entries[i].invalid = false;
        }
        sc6_runtime_reset();                        /* Q6 */
    }
}

static uint64_t guest_hash(tb_page_addr_t page0, tb_page_addr_t page1,
                           size_t size)
{
    size_t first = MIN(size,
                       TARGET_PAGE_SIZE - (page0 & ~TARGET_PAGE_MASK));
    uint64_t hash = SUPERCACHE_FNV_OFFSET;
    void *p = qemu_map_ram_ptr(NULL, page0);

    hash = hash_bytes(hash, p, first);
    if (first != size) {
        if (page1 == (tb_page_addr_t)-1) {
            return 0;
        }
        p = qemu_map_ram_ptr(NULL, page1);
        hash = hash_bytes(hash, p, size - first);
    }
    return hash;
}

void tcg_supercache_record(TranslationBlock *tb, const void *end)
{
    SupercacheRecord record = { 0 };
    ssize_t ret;

    if (!supercache.initialized ||
        tb_page_addr0(tb) == (tb_page_addr_t)-1) {
        return;
    }
    record.tb_offset = (const uint8_t *)tb -
                       (const uint8_t *)supercache.buffer;
    record.end_offset = (const uint8_t *)end -
                        (const uint8_t *)supercache.buffer;
    record.tc_offset = (const uint8_t *)tb->tc.ptr -
                       (const uint8_t *)supercache.buffer;
    record.tc_size = tb->tc.size;
    record.pc = tb->pc;
    record.cs_base = tb->cs_base;
    record.page_addr0 = tb_page_addr0(tb);
    record.page_addr1 = tb_page_addr1(tb);
    record.flags = tb->flags;
    record.cflags = tb_cflags(tb);
    record.guest_size = tb->size;
    record.icount = tb->icount;
    memcpy(record.jmp_reset_offset, tb->jmp_reset_offset,
           sizeof(record.jmp_reset_offset));
    memcpy(record.jmp_insn_offset, tb->jmp_insn_offset,
           sizeof(record.jmp_insn_offset));
    record.guest_hash = guest_hash(record.page_addr0, record.page_addr1,
                                   record.guest_size);
    record.checksum = record_checksum(&record);
    record.committed = SUPERCACHE_RECORD_COMMIT;

    if (!pwrite_full(supercache.fd,
                     (uint8_t *)supercache.buffer + record.tc_offset,
                     record.end_offset - record.tc_offset,
                     SUPERCACHE_CODE_OFFSET + record.tc_offset)) {
        error_report("supercache: cannot persist translated host code: %s",
                     errno ? strerror(errno) : "short write");
        exit(EXIT_FAILURE);
    }
    ret = pwrite(supercache.fd, &record, sizeof(record),
                 record_offset(supercache.header.record_count));
    if (ret != sizeof(record)) {
        error_report("supercache: cannot append translation: %s",
                     ret < 0 ? strerror(errno) : "short write");
        exit(EXIT_FAILURE);
    }
    if (unlikely(scc_active)) {
        /* scc H17: TB chunk joined to the slot just written */
        scc_tb_commit(tb, supercache.header.record_count, &record,
                      sizeof(record), supercache.buffer);
    }
    supercache.header.record_count++;
    supercache.max_end = MAX(supercache.max_end, record.end_offset);
    write_header();
    index_record(&record, true);
}

static bool second_page_matches(CPUState *cpu, TCGTBCPUState state,
                                const SupercacheRecord *record)
{
    tb_page_addr_t current;

    if (record->page_addr1 == UINT64_MAX) {
        return true;
    }
    current = get_page_addr_code(cpu_env(cpu), TARGET_PAGE_ALIGN(state.pc));
    return current == record->page_addr1;
}

static TranslationBlock *lookup_entry(CPUState *cpu, TCGTBCPUState state,
                                      const SupercacheKey *key,
                                      SupercacheEntry *entry)
{
    SupercacheRecord *r = &entry->record;
    SupercacheKey candidate_key = record_key(r);
    TranslationBlock *tb;
    TranslationBlock *linked;

    if (!key_equal(key, &candidate_key) || entry->invalid) {
        return NULL;
    }
    tb = (TranslationBlock *)((uint8_t *)supercache.buffer + r->tb_offset);
    if (entry->used) {
        return supercache.flat ? tb : NULL;
    }
    if (!second_page_matches(cpu, state, r) ||
        guest_hash(r->page_addr0, r->page_addr1,
                   r->guest_size) != r->guest_hash) {
        return NULL;
    }

    tb->pc = r->pc;
    tb->cs_base = r->cs_base;
    tb->flags = r->flags;
    tb->cflags = r->cflags;
    tb->size = r->guest_size;
    tb->icount = r->icount;
    tb->tc.ptr = (uint8_t *)supercache.buffer + r->tc_offset;
    tb->tc.size = r->tc_size;
    tb_set_page_addr0(tb, r->page_addr0);
    tb_set_page_addr1(tb, r->page_addr1);
    memcpy(tb->jmp_reset_offset, r->jmp_reset_offset,
           sizeof(tb->jmp_reset_offset));
    memcpy(tb->jmp_insn_offset, r->jmp_insn_offset,
           sizeof(tb->jmp_insn_offset));
    qemu_spin_init(&tb->jmp_lock);
    tb->jmp_list_head = 0;
    tb->jmp_list_next[0] = tb->jmp_list_next[1] = 0;
    tb->jmp_dest[0] = tb->jmp_dest[1] = 0;
    qemu_thread_jit_write();
    if (tb->jmp_reset_offset[0] != TB_JMP_OFFSET_INVALID) {
        tb_reset_jump(tb, 0);
    }
    if (tb->jmp_reset_offset[1] != TB_JMP_OFFSET_INVALID) {
        tb_reset_jump(tb, 1);
    }
    qemu_plugin_supercache_rehydrate(cpu, tb, state.pc);
    flush_idcache_range((uintptr_t)tb->tc.ptr,
                        (uintptr_t)tb->tc.ptr, tb->tc.size);
    entry->used = true;
    if (supercache.flat) {
        return tb;
    }

    tcg_tb_insert(tb);
    linked = tb_supercache_link(tb);
    if (linked != tb) {
        tcg_tb_remove(tb);
        return linked;
    }
    if (unlikely(sc6.loaded)) {
        uint32_t index = entry - supercache.entries;

        if (index < sc6.n_entries && sc6.role[index]) {
            sc6_on_activate(cpu, index, tb);        /* Q5 */
        }
    }
    return tb;
}

TranslationBlock *tcg_supercache_lookup(CPUState *cpu, TCGTBCPUState state,
                                        tb_page_addr_t phys_pc)
{
    SupercacheKey key = {
        .pc = (state.cflags & CF_PCREL) ? 0 : state.pc,
        .cs_base = state.cs_base,
        .page_addr0 = phys_pc,
        .flags = state.flags,
        .cflags = state.cflags,
    };
    TranslationBlock *tb;
    uint32_t flat_link = 0;
    uint32_t bucket;
    uint32_t link;

    if (!supercache.initialized) {
        return NULL;
    }
    if (supercache.flat_direct && !(state.cflags & CF_PCREL) &&
        state.pc >= supercache.flat_guest_base &&
        state.pc - supercache.flat_guest_base <
        supercache.flat_direct_size) {
        flat_link = supercache.flat_direct[
            state.pc - supercache.flat_guest_base];
    } else if (supercache.flat_pages && !(state.cflags & CF_PCREL) &&
        state.pc >= supercache.flat_guest_base) {
        uint64_t page_index = (state.pc - supercache.flat_guest_base) >>
                              TARGET_PAGE_BITS;

        if (page_index < supercache.flat_page_count) {
            const SupercacheFlatPage *page =
                &supercache.flat_pages[page_index];

            if (page->count) {
                uint32_t slot = flat_pc_hash(state.pc) & page->mask;

                while ((flat_link =
                        supercache.flat_slots[page->first + slot])) {
                    if (supercache.entries[flat_link - 1].record.pc ==
                        state.pc) {
                        break;
                    }
                    slot = (slot + 1) & page->mask;
                }
            }
        }
    }
    if (flat_link) {
        tb = lookup_entry(cpu, state, &key,
                          &supercache.entries[flat_link - 1]);
        if (tb) {
            return tb;
        }
    }

    bucket = key_hash(&key) & (supercache.bucket_count - 1);
    for (link = supercache.buckets[bucket]; link;
         link = supercache.entries[link - 1].next) {
        if (link == flat_link) {
            continue;
        }
        tb = lookup_entry(cpu, state, &key,
                          &supercache.entries[link - 1]);
        if (tb) {
            return tb;
        }
    }
    return NULL;
}

TranslationBlock *tcg_supercache_host_lookup(uintptr_t tc_ptr)
{
    uint64_t offset;
    uint32_t low = 0;
    uint32_t high = supercache.entry_count;
    SupercacheEntry *entry;
    SupercacheRecord *record;

    if (!supercache.initialized || !supercache.flat ||
        tc_ptr < (uintptr_t)supercache.buffer ||
        tc_ptr - (uintptr_t)supercache.buffer >= supercache.size) {
        return NULL;
    }
    offset = tc_ptr - (uintptr_t)supercache.buffer;
    while (low < high) {
        uint32_t mid = low + (high - low) / 2;

        if (supercache.entries[mid].record.tc_offset <= offset) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    if (!low) {
        return NULL;
    }
    entry = &supercache.entries[low - 1];
    record = &entry->record;
    if (!entry->used || entry->invalid ||
        offset >= record->tc_offset + record->tc_size) {
        return NULL;
    }
    return (TranslationBlock *)((uint8_t *)supercache.buffer +
                                record->tb_offset);
}

bool tcg_supercache_flat_invalidate(TranslationBlock *tb)
{
    uint64_t offset;
    uint32_t low = 0;
    uint32_t high = supercache.entry_count;

    if (!supercache.initialized || !supercache.flat ||
        (uint8_t *)tb < (uint8_t *)supercache.buffer ||
        (uint8_t *)tb - (uint8_t *)supercache.buffer >= supercache.size) {
        return false;
    }
    offset = (uint8_t *)tb - (uint8_t *)supercache.buffer;
    while (low < high) {
        uint32_t mid = low + (high - low) / 2;
        uint64_t candidate = supercache.entries[mid].record.tb_offset;

        if (candidate < offset) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    if (low == supercache.entry_count ||
        supercache.entries[low].record.tb_offset != offset ||
        !supercache.entries[low].used) {
        return false;
    }
    supercache.entries[low].used = false;
    supercache.entries[low].invalid = true;
    return true;
}

bool tcg_supercache_get_info(TCGSupercacheInfo *info)
{
    memset(info, 0, sizeof(*info));
    if (!supercache.configured) {
        return false;
    }
    info->configured = true;
    info->flat = supercache.flat;
    if (supercache.initialized) {
        info->initialized = true;
        info->code_address = (uintptr_t)supercache.buffer;
        info->runtime_signature = supercache.header.runtime_signature;
        if (supercache.loaded_header.version) {
            info->reused = true;
            info->loaded_record_count = supercache.loaded_header.record_count;
            info->loaded_header_checksum = supercache.loaded_header.checksum;
            info->loaded_max_end = supercache.loaded_max_end;
        }
    }
    return true;
}

#else /* CONFIG_LINUX && HOST_X86_64 */

void tcg_supercache_configure(const char *path, bool flat, int splitwx,
                              unsigned max_threads)
{
    if (path) {
        error_report("supercache is currently supported only by x86-64 "
                     "Linux system emulation");
        exit(EXIT_FAILURE);
    }
}

bool tcg_supercache_enabled(void)
{
    return false;
}

void *tcg_supercache_buffer(void)
{
    return NULL;
}

uint64_t tcg_supercache_loaded_max_end(void)
{
    return 0;
}

int tcg_supercache_alloc_code_buffer(size_t size, void **buffer,
                                     Error **errp)
{
    return 0;
}

void tcg_supercache_after_prologue(TCGContext *s)
{
}

void tcg_supercache_runtime_reset(void)
{
}

void tcg_supercache_record(TranslationBlock *tb, const void *end)
{
}

TranslationBlock *tcg_supercache_lookup(CPUState *cpu, TCGTBCPUState state,
                                        tb_page_addr_t phys_pc)
{
    return NULL;
}

TranslationBlock *tcg_supercache_host_lookup(uintptr_t tc_ptr)
{
    return NULL;
}

bool tcg_supercache_flat_invalidate(TranslationBlock *tb)
{
    return false;
}

bool tcg_supercache_get_info(TCGSupercacheInfo *info)
{
    memset(info, 0, sizeof(*info));
    return false;
}

bool tcg_sc6_stats_active;

void tcg_supercache_mapping_changed(CPUState *cpu)
{
}

void tcg_supercache_v6_one_insn_per_tb(void)
{
}

void tcg_supercache_v6_forbid(void)
{
}

void tcg_supercache_v6_note_exit(TranslationBlock *tb, int tb_exit)
{
}

void tcg_supercache_v6_note_restore(TranslationBlock *tb)
{
}

#endif /* CONFIG_LINUX && HOST_X86_64 */
