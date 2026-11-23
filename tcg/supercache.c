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
#define SC7_VERSION               7       /* firmware regions */
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
static void sc7_configure_from_env(void);

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
    sc7_configure_from_env();
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
            header->version == SC6_VERSION ||
            header->version == SC7_VERSION) &&
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

/* V7: call-site-specific private firmware regions.  The directory itself is
 * arena-resident so exhaustive mode does not inherit v6's 64 KiB array cap. */
#define SC7_DIR_OFFSET            0x100
#define SC7_DIR_MAGIC             "QSC7FWRG"
#define SC7_FEAT_FIRMWARE_REGIONS 1u
#define SC7_DIR_VERSION_COMPOSITE 2u
#define SC7_REGION_COMPOSITE      1u

typedef struct Sc7DirHeader {
    char magic[8];
    uint32_t ext_version;
    uint32_t header_size;
    uint32_t n_regions;
    uint32_t n_members;
    uint32_t n_edges;
    uint32_t region_entry_size;
    uint64_t table_offset;
    uint64_t table_size;
    uint64_t max_end;
    uint8_t artifact_id8[8];
    uint64_t checksum;
    uint8_t reserved[8];
} Sc7DirHeader;

typedef struct Sc7RegionEntry {
    uint8_t region_id8[8];
    uint8_t callsite_id8[8];
    uint32_t entry_member;
    uint32_t first_member;
    uint32_t n_members;
    uint32_t first_edge;
    uint64_t source_tb_offset;
    uint64_t start_offset;
    uint64_t end_offset;
    uint32_t n_edges;
    uint32_t flags;
} Sc7RegionEntry;

typedef struct Sc7MemberEntry {
    uint64_t source_tb_offset;
    uint64_t tb_offset;
    uint64_t tc_offset;
    uint64_t tc_size;
    uint64_t search_offset;
    uint64_t code_fnv64;
    uint64_t search_fnv64;
    uint64_t guest_vaddr;
    uint8_t context_id8[8];
    uint32_t region_index;
    uint32_t flags;
} Sc7MemberEntry;

typedef struct Sc7EdgeEntry {
    uint32_t region_index;
    uint32_t source_member;
    uint32_t target_member;
    uint32_t field_offset;
    uint8_t kind;
    uint8_t flags;
    uint16_t reserved;
    uint32_t guest_target;
    uint64_t exit_id_fnv64;
} Sc7EdgeEntry;

QEMU_BUILD_BUG_ON(sizeof(Sc7DirHeader) != 80);
QEMU_BUILD_BUG_ON(sizeof(Sc7RegionEntry) != 64);
QEMU_BUILD_BUG_ON(sizeof(Sc7MemberEntry) != 80);
QEMU_BUILD_BUG_ON(sizeof(Sc7EdgeEntry) != 32);

static struct {
    bool loaded;
    Sc7DirHeader header;
    Sc7RegionEntry *regions;
    Sc7MemberEntry *members;
    Sc7EdgeEntry *edges;
    bool *region_admitted;
    bool *member_prepared;
    TranslationBlock **private_tbs;
    uint32_t *source_index;
    uint64_t entries;
    uint64_t region_activations;
    uint64_t member_descriptors_instantiated;
    uint64_t members_activated;
    uint64_t dependency_refusals;
    uint64_t dependency_invalidations;
    uint64_t mapping_invalidations;
    uint64_t internal_edges;
    uint64_t search_hits;
    uint64_t member_callback_replays;
    uint64_t member_callback_omissions;
    uint64_t member_callbacks_executed;
    char *stats_path;
} sc7;

static void sc7_runtime_reset(void);
static void sc7_mapping_changed(CPUState *cpu);
static G_NORETURN G_GNUC_PRINTF(1, 2) void sc7_die(const char *fmt, ...);

typedef struct Sc7Span {
    uint64_t start;
    uint64_t end;
} Sc7Span;

static int sc7_cmp_span(const void *ap, const void *bp)
{
    const Sc7Span *a = ap;
    const Sc7Span *b = bp;

    return a->start < b->start ? -1 : a->start > b->start ? 1 :
           a->end < b->end ? -1 : a->end > b->end;
}

static bool sc7_range(uint64_t start, uint64_t size, uint64_t limit,
                      uint64_t *end)
{
    if (start > limit || size > limit - start) {
        return false;
    }
    *end = start + size;
    return true;
}

static void sc7_check_disjoint(Sc7Span *spans, uint64_t count,
                               const char *what)
{
    qsort(spans, count, sizeof(*spans), sc7_cmp_span);
    for (uint64_t i = 1; i < count; i++) {
        if (spans[i].start < spans[i - 1].end) {
            sc7_die("%s spans overlap at 0x%" PRIx64, what,
                    spans[i].start);
        }
    }
}

static uint32_t sc7_source_index(uint64_t tb_offset)
{
    for (uint32_t i = 0; i < supercache.entry_count; i++) {
        if (supercache.entries[i].record.tb_offset == tb_offset) {
            return i;
        }
    }
    return UINT32_MAX;
}

static G_NORETURN G_GNUC_PRINTF(1, 2) void sc7_die(const char *fmt, ...)
{
    va_list ap;
    g_autofree char *reason = NULL;

    va_start(ap, fmt);
    reason = g_strdup_vprintf(fmt, ap);
    va_end(ap);
    error_report("supercache: invalid v7 firmware regions: %s", reason);
    exit(EXIT_FAILURE);
}

static void sc7_load_ext(void)
{
    Sc7DirHeader h;
    g_autofree uint8_t *table = NULL;
    g_autofree Sc7Span *occupied = NULL;
    g_autofree Sc7Span *region_spans = NULL;
    uint64_t expected, hash;
    uint64_t table_end;
    uint64_t n_occupied, next_occupied = 0;
    uint32_t expected_member = 0, expected_edge = 0;
    uint8_t zero[8] = { 0 };

    if (supercache.header.reserved != SC7_FEAT_FIRMWARE_REGIONS) {
        sc7_die("unknown feature bits 0x%x", supercache.header.reserved);
    }
    if (supercache.flat) {
        sc7_die("firmware regions need normal mode");
    }
    if (pread(supercache.fd, &h, sizeof(h), SC7_DIR_OFFSET) != sizeof(h)) {
        sc7_die("cannot read directory header");
    }
    if (memcmp(h.magic, SC7_DIR_MAGIC, 8) ||
        h.ext_version != SC7_DIR_VERSION_COMPOSITE ||
        h.header_size != sizeof(h) || h.region_entry_size != sizeof(Sc7RegionEntry) ||
        memcmp(h.reserved, zero, sizeof(zero))) {
        sc7_die("bad directory header");
    }
    expected = (uint64_t)h.n_regions * sizeof(Sc7RegionEntry) +
               (uint64_t)h.n_members * sizeof(Sc7MemberEntry) +
               (uint64_t)h.n_edges * sizeof(Sc7EdgeEntry);
    if (h.table_offset % 8 || h.table_size != expected ||
        h.table_offset < supercache.header.prologue_end ||
        !sc7_range(h.table_offset, h.table_size, supercache.size,
                   &table_end) || h.max_end != table_end) {
        sc7_die("directory bounds/count mismatch");
    }
    table = g_malloc(h.table_size ? h.table_size : 1);
    if (h.table_size && pread(supercache.fd, table, h.table_size,
                              SUPERCACHE_CODE_OFFSET + h.table_offset) != h.table_size) {
        sc7_die("cannot read directory table");
    }
    hash = hash_bytes(SUPERCACHE_FNV_OFFSET, &h, offsetof(Sc7DirHeader, checksum));
    hash = hash_bytes(hash, table, h.table_size);
    if (hash != h.checksum) {
        sc7_die("directory checksum mismatch");
    }
    sc7.regions = g_memdup2(table, h.n_regions * sizeof(Sc7RegionEntry));
    sc7.members = g_memdup2(table + h.n_regions * sizeof(Sc7RegionEntry),
                            h.n_members * sizeof(Sc7MemberEntry));
    sc7.edges = g_memdup2(table + h.n_regions * sizeof(Sc7RegionEntry) +
                          h.n_members * sizeof(Sc7MemberEntry),
                          h.n_edges * sizeof(Sc7EdgeEntry));
    sc7.region_admitted = g_new0(bool, h.n_regions + 1);
    sc7.member_prepared = g_new0(bool, h.n_members + 1);
    sc7.private_tbs = g_new0(TranslationBlock *, h.n_members + 1);
    sc7.source_index = g_new(uint32_t, h.n_members + 1);
    region_spans = g_new(Sc7Span, (uint64_t)h.n_regions + 1);
    for (uint32_t i = 0; i < h.n_regions; i++) {
        Sc7RegionEntry *r = &sc7.regions[i];
        uint64_t member_end = (uint64_t)r->first_member + r->n_members;
        uint64_t edge_end = (uint64_t)r->first_edge + r->n_edges;

        if (r->flags != SC7_REGION_COMPOSITE || r->entry_member != 0 ||
            r->first_member != expected_member ||
            r->first_edge != expected_edge || !r->n_members ||
            member_end > h.n_members || edge_end > h.n_edges ||
            r->start_offset % 64 ||
            sc7_source_index(r->source_tb_offset) == UINT32_MAX ||
            r->end_offset > h.table_offset || r->start_offset >= r->end_offset) {
            sc7_die("region %u has invalid slices", i);
        }
        region_spans[i] = (Sc7Span) { r->start_offset, r->end_offset };
        expected_member = member_end;
        expected_edge = edge_end;
    }
    if (expected_member != h.n_members || expected_edge != h.n_edges) {
        sc7_die("directory arrays are not partitioned by regions");
    }
    sc7_check_disjoint(region_spans, h.n_regions, "region");

    n_occupied = (uint64_t)supercache.entry_count +
                 (uint64_t)h.n_members * 3 + 1;
    occupied = g_new(Sc7Span, n_occupied);
    for (uint32_t i = 0; i < supercache.entry_count; i++) {
        SupercacheRecord *r = &supercache.entries[i].record;

        occupied[next_occupied++] = (Sc7Span) { r->tb_offset, r->end_offset };
    }
    occupied[next_occupied++] = (Sc7Span) { h.table_offset, h.max_end };
    for (uint32_t i = 0; i < h.n_members; i++) {
        Sc7MemberEntry *m = &sc7.members[i];
        uint32_t src = sc7_source_index(m->source_tb_offset);
        Sc7RegionEntry *r;
        uint64_t descriptor_end, code_end, search_end, search_size;

        if (src == UINT32_MAX || m->region_index >= h.n_regions || m->flags) {
            sc7_die("member %u has invalid source, region, or flags", i);
        }
        r = &sc7.regions[m->region_index];
        if (i < r->first_member ||
            i >= (uint64_t)r->first_member + r->n_members) {
            sc7_die("member %u is outside its declared region", i);
        }
        search_size = supercache.entries[src].record.end_offset -
                      supercache.entries[src].record.tc_offset -
                      supercache.entries[src].record.tc_size;
        if (!m->tc_size ||
            !sc7_range(m->tb_offset, supercache.header.tb_size,
                       r->end_offset, &descriptor_end) ||
            !sc7_range(m->tc_offset, m->tc_size, r->end_offset, &code_end) ||
            !sc7_range(m->search_offset, search_size, r->end_offset,
                       &search_end) ||
            m->tb_offset < r->start_offset ||
            m->tc_offset < r->start_offset ||
            m->search_offset < r->start_offset) {
            sc7_die("member %u has invalid descriptor/code/search bounds", i);
        }
        sc7.source_index[i] = src;
        occupied[next_occupied++] =
            (Sc7Span) { m->tb_offset, descriptor_end };
        occupied[next_occupied++] =
            (Sc7Span) { m->tc_offset, code_end };
        occupied[next_occupied++] =
            (Sc7Span) { m->search_offset, search_end };
    }
    g_assert(next_occupied == n_occupied);
    sc7_check_disjoint(occupied, n_occupied, "arena");

    for (uint32_t i = 0; i < h.n_regions; i++) {
        Sc7RegionEntry *r = &sc7.regions[i];
        uint32_t entry = r->first_member + r->entry_member;
        uint64_t descriptor_next = r->start_offset;
        uint64_t code_next;
        uint64_t search_next;

        if (sc7.members[entry].source_tb_offset != r->source_tb_offset) {
            sc7_die("region %u entry source record mismatch", i);
        }
        for (uint32_t n = 0; n < r->n_members; n++) {
            Sc7MemberEntry *m = &sc7.members[r->first_member + n];

            if (m->tb_offset != descriptor_next) {
                sc7_die("region %u member descriptors are not contiguous", i);
            }
            descriptor_next += supercache.header.tb_size;
        }
        code_next = ROUND_UP(descriptor_next, 16);
        for (uint32_t n = 0; n < r->n_members; n++) {
            Sc7MemberEntry *m = &sc7.members[r->first_member + n];

            if (m->tc_offset != code_next) {
                sc7_die("region %u member code is not contiguous", i);
            }
            code_next += m->tc_size;
        }
        search_next = code_next;
        for (uint32_t n = 0; n < r->n_members; n++) {
            uint32_t mi = r->first_member + n;
            Sc7MemberEntry *m = &sc7.members[mi];
            SupercacheRecord *s =
                &supercache.entries[sc7.source_index[mi]].record;
            uint64_t search_size = s->end_offset - s->tc_offset - s->tc_size;

            if (m->search_offset != search_next) {
                sc7_die("region %u member search data is not contiguous", i);
            }
            search_next += search_size;
        }
        if (search_next != r->end_offset) {
            sc7_die("region %u end does not match composite payload", i);
        }
    }
    for (uint32_t i = 0; i < h.n_edges; i++) {
        Sc7EdgeEntry *e = &sc7.edges[i];
        Sc7RegionEntry *r;
        Sc7MemberEntry *source;
        uint64_t member_end;

        if (e->region_index >= h.n_regions || e->kind != 1 || e->flags ||
            e->reserved) {
            sc7_die("edge %u has invalid kind, flags, or region", i);
        }
        r = &sc7.regions[e->region_index];
        member_end = (uint64_t)r->first_member + r->n_members;
        if (i < r->first_edge || i >= (uint64_t)r->first_edge + r->n_edges ||
            e->source_member < r->first_member ||
            e->source_member >= member_end ||
            e->target_member < r->first_member ||
            e->target_member >= member_end) {
            sc7_die("edge %u is outside its declared region", i);
        }
        source = &sc7.members[e->source_member];
        if (source->tc_size < 4 || e->field_offset > source->tc_size - 4) {
            sc7_die("edge %u field is outside source code", i);
        }
    }
    sc7.header = h;
    sc7.loaded = true;
    supercache.max_end = MAX(supercache.max_end, h.max_end);
}

static void sc7_verify_hashes(void)
{
    uint8_t *buf = supercache.buffer;
    GChecksum *artifact = g_checksum_new(G_CHECKSUM_SHA256);
    static const uint8_t domain[] = "scopt.sc7/2";
    uint8_t artifact_digest[32];
    gsize artifact_len = sizeof(artifact_digest);
    uint8_t zero_id[8] = { 0 };

    g_checksum_update(artifact, domain, sizeof(domain) - 1);
    g_checksum_update(artifact, (const uint8_t *)sc7.regions,
                      (gsize)sc7.header.n_regions * sizeof(Sc7RegionEntry));
    g_checksum_update(artifact, (const uint8_t *)sc7.members,
                      (gsize)sc7.header.n_members * sizeof(Sc7MemberEntry));
    g_checksum_update(artifact, (const uint8_t *)sc7.edges,
                      (gsize)sc7.header.n_edges * sizeof(Sc7EdgeEntry));

    for (uint32_t i = 0; i < sc7.header.n_members; i++) {
        Sc7MemberEntry *m = &sc7.members[i];
        SupercacheRecord *s = &supercache.entries[sc7.source_index[i]].record;
        uint64_t search_size = s->end_offset - s->tc_offset - s->tc_size;
        GChecksum *member = g_checksum_new(G_CHECKSUM_SHA256);
        uint8_t member_digest[32];
        gsize member_len = sizeof(member_digest);
        bool descriptor_zero = true;

        for (uint32_t n = 0; n < supercache.header.tb_size; n++) {
            if (buf[m->tb_offset + n]) {
                descriptor_zero = false;
                break;
            }
        }

        if (!descriptor_zero ||
            hash_bytes(SUPERCACHE_FNV_OFFSET, buf + m->tc_offset, m->tc_size) !=
                m->code_fnv64 ||
            hash_bytes(SUPERCACHE_FNV_OFFSET, buf + m->search_offset, search_size) !=
                m->search_fnv64) {
            g_checksum_free(member);
            g_checksum_free(artifact);
            sc7_die("member %u descriptor/code/search mismatch", i);
        }
        g_checksum_update(member, buf + m->tb_offset,
                          supercache.header.tb_size);
        g_checksum_update(member, buf + m->tc_offset, m->tc_size);
        g_checksum_update(member, buf + m->search_offset, search_size);
        g_checksum_get_digest(member, member_digest, &member_len);
        g_assert(member_len == sizeof(member_digest));
        g_checksum_update(artifact, member_digest, sizeof(member_digest));
        g_checksum_free(member);
    }
    for (uint32_t i = 0; i < sc7.header.n_edges; i++) {
        Sc7EdgeEntry *e = &sc7.edges[i];
        Sc7MemberEntry *source = &sc7.members[e->source_member];
        Sc7MemberEntry *target = &sc7.members[e->target_member];
        int32_t displacement;
        int64_t next = source->tc_offset + e->field_offset + 4;

        memcpy(&displacement, buf + source->tc_offset + e->field_offset,
               sizeof(displacement));
        if (next + displacement < 0 ||
            (uint64_t)(next + displacement) != target->tc_offset) {
            g_checksum_free(artifact);
            sc7_die("edge %u rel32 target mismatch", i);
        }
    }
    g_checksum_get_digest(artifact, artifact_digest, &artifact_len);
    g_checksum_free(artifact);
    if (artifact_len != sizeof(artifact_digest) ||
        !memcmp(sc7.header.artifact_id8, zero_id, sizeof(zero_id)) ||
        memcmp(sc7.header.artifact_id8, artifact_digest,
               sizeof(sc7.header.artifact_id8))) {
        sc7_die("directory artifact identity mismatch");
    }
}

static void sc7_write_stats(void)
{
    g_autoptr(GString) j = g_string_new("{\n");

    g_string_append(j, "  \"schema\": \"qemu-sc-v7-stats@1\",\n");
    g_string_append_printf(j, "  \"loaded\": %s,\n",
                           sc7.loaded ? "true" : "false");
    g_string_append_printf(j, "  \"file_version\": %" PRIu32 ",\n",
                           supercache.loaded_header.version);
    g_string_append(j, "  \"artifact_id8\": \"");
    for (int i = 0; i < 8; i++) {
        g_string_append_printf(j, "%02x", sc7.header.artifact_id8[i]);
    }
    g_string_append(j, "\",\n");
    g_string_append_printf(j,
        "  \"regions_loaded\": %" PRIu32 ",\n"
        "  \"members_loaded\": %" PRIu32 ",\n"
        "  \"region_entries\": %" PRIu64 ",\n"
        "  \"region_activations\": %" PRIu64 ",\n"
        "  \"member_descriptors_instantiated\": %" PRIu64 ",\n"
        "  \"members_registered\": %" PRIu64 ",\n"
        "  \"members_activated\": %" PRIu64 ",\n"
        "  \"internal_edges_admitted\": %" PRIu64 ",\n"
        "  \"dependency_refusals\": %" PRIu64 ",\n"
        "  \"dependency_invalidations\": %" PRIu64 ",\n"
        "  \"mapping_invalidations\": %" PRIu64 ",\n"
        "  \"member_callback_replays\": %" PRIu64 ",\n"
        "  \"member_callback_omissions\": %" PRIu64 ",\n"
        "  \"member_callbacks_executed\": %" PRIu64 ",\n"
        "  \"search_data_hits\": %" PRIu64 "\n}\n",
        sc7.loaded ? sc7.header.n_regions : 0,
        sc7.loaded ? sc7.header.n_members : 0,
        sc7.entries, sc7.region_activations,
        sc7.member_descriptors_instantiated, sc7.members_activated,
        sc7.members_activated,
        sc7.internal_edges,
        sc7.dependency_refusals,
        sc7.dependency_invalidations, sc7.mapping_invalidations,
        sc7.member_callback_replays, sc7.member_callback_omissions,
        sc7.member_callbacks_executed,
        sc7.search_hits);
    if (!g_file_set_contents(sc7.stats_path, j->str, j->len, NULL)) {
        warn_report("supercache: cannot write QEMU_SC_V7_STATS file '%s'",
                    sc7.stats_path);
    }
}

static void sc7_configure_from_env(void)
{
    const char *path = getenv("QEMU_SC_V7_STATS");

    if (!path || !*path) {
        return;
    }
    if (!g_path_is_absolute(path)) {
        error_report("supercache: QEMU_SC_V7_STATS must be an absolute path");
        exit(EXIT_FAILURE);
    }
    sc7.stats_path = g_strdup(path);
    atexit(sc7_write_stats);
}

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

    if (unlikely(sc7.loaded)) {
        sc7_mapping_changed(cpu);
    }
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
                   (disk_header.version == SC6_VERSION ||
                    disk_header.version == SC7_VERSION)) {
            /* The stock path below truncates; say so for extension files. */
            warn_report("supercache: discarding v%u file: %s", disk_header.version,
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
        } else if (supercache.header.version == SC7_VERSION) {
            sc7_load_ext();
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
        if (sc7.loaded) {
            sc7_verify_hashes();
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
        sc7_runtime_reset();
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

static bool sc7_member_internal_slot(uint32_t member, uint16_t field)
{
    for (uint32_t i = 0; i < sc7.header.n_edges; i++) {
        if (sc7.edges[i].source_member == member &&
            sc7.edges[i].field_offset == field) {
            return true;
        }
    }
    return false;
}

static TranslationBlock *sc7_member_tb(uint32_t index)
{
    return (TranslationBlock *)((uint8_t *)supercache.buffer +
                                sc7.members[index].tb_offset);
}

/*
 * A composite region has one registered entry TB and one shadow descriptor
 * for each member.  Native exits embedded in copied member code still carry
 * that member's descriptor address, and unwind/icount/plugin recovery needs
 * its original metadata.  Consequently all descriptors must be initialized
 * before the entry can run, but only the entry is inserted in the host-PC
 * tree.  Host-PC recovery finds shadows directly by their member code range.
 */
static TranslationBlock *sc7_prepare_member(CPUState *cpu, uint32_t index)
{
    Sc7MemberEntry *m = &sc7.members[index];
    SupercacheRecord *r = &supercache.entries[sc7.source_index[index]].record;
    TranslationBlock *tb = sc7_member_tb(index);

    if (sc7.member_prepared[index]) {
        return tb;
    }

    memset(tb, 0, sizeof(*tb));
    tb->pc = r->pc;
    tb->cs_base = r->cs_base;
    tb->flags = r->flags;
    tb->cflags = r->cflags;
    tb->size = r->guest_size;
    tb->icount = r->icount;
    tb->tc.ptr = (uint8_t *)supercache.buffer + m->tc_offset;
    tb->tc.size = m->tc_size;
    tb_set_page_addr0(tb, r->page_addr0);
    tb_set_page_addr1(tb, r->page_addr1);
    tb_supercache_protect_code(r->page_addr0);
    if (r->page_addr1 != UINT64_MAX) {
        tb_supercache_protect_code(r->page_addr1);
    }
    memcpy(tb->jmp_reset_offset, r->jmp_reset_offset,
           sizeof(tb->jmp_reset_offset));
    memcpy(tb->jmp_insn_offset, r->jmp_insn_offset,
           sizeof(tb->jmp_insn_offset));
    qemu_spin_init(&tb->jmp_lock);
    qemu_thread_jit_write();
    for (int n = 0; n < 2; n++) {
        if (tb->jmp_reset_offset[n] != TB_JMP_OFFSET_INVALID &&
            !sc7_member_internal_slot(index, tb->jmp_insn_offset[n])) {
            tb_reset_jump(tb, n);
        }
    }
    qemu_thread_jit_execute();
    /* The plugin path obtains member-local search data through this flag. */
    sc7.member_prepared[index] = true;
    bool omit = !cpu->singlestep_enabled &&
                QTAILQ_EMPTY(&cpu->breakpoints) &&
                QTAILQ_EMPTY(&cpu->watchpoints) &&
                qemu_plugin_tb_restore_omittable(cpu, m->guest_vaddr,
                                                 r->guest_size);
    unsigned callbacks = qemu_plugin_supercache_rehydrate(
        cpu, tb, m->guest_vaddr, omit);

    sc7.member_callback_omissions += omit;
    sc7.member_callback_replays += !omit;
    sc7.member_callbacks_executed += callbacks;
    sc7.member_descriptors_instantiated++;
    return tb;
}

static TranslationBlock *sc7_register_entry(uint32_t index)
{
    TranslationBlock *tb = sc7_member_tb(index);

    g_assert(sc7.member_prepared[index]);
    if (!sc7.private_tbs[index]) {
        tcg_tb_insert(tb);
        sc7.private_tbs[index] = tb;
        sc7.members_activated++;
    }
    return tb;
}

static TranslationBlock *sc7_try_region(CPUState *cpu, uint32_t source)
{
    if (!sc7.loaded || scp_active || cpu->singlestep_enabled ||
        !QTAILQ_EMPTY(&cpu->breakpoints) || !QTAILQ_EMPTY(&cpu->watchpoints)) {
        return NULL;
    }
    for (uint32_t ri = 0; ri < sc7.header.n_regions; ri++) {
        Sc7RegionEntry *region = &sc7.regions[ri];

        if (sc7_source_index(region->source_tb_offset) != source) {
            continue;
        }
        if (!sc7.region_admitted[ri]) {
            for (uint32_t n = 0; n < region->n_members; n++) {
                uint32_t mi = region->first_member + n;
                SupercacheEntry *dep =
                    &supercache.entries[sc7.source_index[mi]];
                SupercacheRecord *r = &dep->record;

                if (dep->invalid || guest_hash(r->page_addr0, r->page_addr1,
                                               r->guest_size) != r->guest_hash) {
                    sc7.dependency_refusals++;
                    return NULL;
                }
            }
            sc7.region_admitted[ri] = true;
        }
        for (uint32_t n = 0; n < region->n_members; n++) {
            uint32_t mi = region->first_member + n;

            sc7_prepare_member(cpu, mi);
        }
        uint32_t entry = region->first_member + region->entry_member;

        if (!sc7.private_tbs[entry]) {
            Sc7MemberEntry *first = &sc7.members[region->first_member];
            Sc7MemberEntry *last =
                &sc7.members[region->first_member + region->n_members - 1];
            TranslationBlock *entry_tb = sc7_member_tb(entry);
            uint64_t code_end = last->tc_offset + last->tc_size;

            entry_tb->tc.ptr = (uint8_t *)supercache.buffer + first->tc_offset;
            entry_tb->tc.size = code_end - first->tc_offset;
            flush_idcache_range((uintptr_t)entry_tb->tc.ptr,
                                (uintptr_t)entry_tb->tc.ptr,
                                entry_tb->tc.size);
            sc7_register_entry(entry);
            sc7.region_activations++;
        }
        sc7.entries++;
        sc7.internal_edges += region->n_edges;
        return sc7.private_tbs[entry];
    }
    return NULL;
}

static bool sc7_any_live(void)
{
    for (uint32_t i = 0; i < sc7.header.n_members; i++) {
        if (sc7.member_prepared[i]) {
            return true;
        }
    }
    return false;
}

static void sc7_retire_all(void)
{
    qemu_thread_jit_write();
    for (uint32_t i = 0; i < sc7.header.n_members; i++) {
        TranslationBlock *tb;
        bool registered;

        if (!sc7.member_prepared[i]) {
            continue;
        }
        tb = sc7_member_tb(i);
        registered = sc7.private_tbs[i] != NULL;
        for (int slot = 0; slot < 2; slot++) {
            if (tb->jmp_reset_offset[slot] != TB_JMP_OFFSET_INVALID &&
                !sc7_member_internal_slot(i, tb->jmp_insn_offset[slot])) {
                tb_unlink_jump(tb, slot);
            }
        }
        tb_supercache_invalidate_private(tb, registered);
        sc7.private_tbs[i] = NULL;
        sc7.member_prepared[i] = false;
    }
    qemu_thread_jit_execute();
}

static void sc7_disarm_mapping_work(CPUState *cpu, run_on_cpu_data data)
{
    g_assert(cpu_in_exclusive_context(cpu));
    if (sc7.loaded && sc7_any_live()) {
        sc7_retire_all();
        sc7.mapping_invalidations++;
    }
}

static void sc7_mapping_changed(CPUState *cpu)
{
    memset(sc7.region_admitted, 0,
           sizeof(*sc7.region_admitted) * (sc7.header.n_regions + 1));
    if (sc7_any_live()) {
        /*
         * Every member retains its ordinary exit-request check.  Requesting
         * an exit prevents a changed mapping from crossing the next direct
         * internal edge; exclusive work retires all descriptors before the
         * CPU resumes ordinary dispatch.
         */
        cpu_exit(cpu);
        async_safe_run_on_cpu(cpu, sc7_disarm_mapping_work,
                              RUN_ON_CPU_NULL);
    }
}

static void sc7_runtime_reset(void)
{
    if (sc7.loaded) {
        if (sc7_any_live()) {
            sc7_retire_all();
        }
        memset(sc7.region_admitted, 0,
               sizeof(*sc7.region_admitted) * (sc7.header.n_regions + 1));
    }
}

const uint8_t *tcg_supercache_search_data(const TranslationBlock *tb)
{
    if (!sc7.loaded) {
        return NULL;
    }
    for (uint32_t i = 0; i < sc7.header.n_members; i++) {
        /*
         * Precise SMC recovery retires a region before unwinding the store
         * that invalidated it.  Descriptor identity and immutable search
         * bytes remain valid after member_prepared is cleared.
         */
        if (sc7_member_tb(i) == tb) {
            sc7.search_hits++;
            return (const uint8_t *)supercache.buffer +
                   sc7.members[i].search_offset;
        }
    }
    return NULL;
}

static bool sc7_record_overlaps(const SupercacheRecord *r,
                                tb_page_addr_t start,
                                tb_page_addr_t last)
{
    uint64_t first = MIN((uint64_t)r->guest_size,
                         (uint64_t)TARGET_PAGE_SIZE -
                         (r->page_addr0 & ~TARGET_PAGE_MASK));
    uint64_t p0_last = r->page_addr0 + first - 1;

    if (r->page_addr0 <= last && p0_last >= start) {
        return true;
    }
    if (first < r->guest_size && r->page_addr1 != UINT64_MAX) {
        uint64_t p1_last = r->page_addr1 + (r->guest_size - first) - 1;

        return r->page_addr1 <= last && p1_last >= start;
    }
    return false;
}

bool tcg_supercache_code_invalidated(tb_page_addr_t start,
                                     tb_page_addr_t last,
                                     TranslationBlock *current_tb)
{
    bool current_affected = false;

    if (!sc7.loaded) {
        return false;
    }
    qemu_thread_jit_write();
    for (uint32_t ri = 0; ri < sc7.header.n_regions; ri++) {
        Sc7RegionEntry *region = &sc7.regions[ri];
        bool affected = false;

        for (uint32_t n = 0; n < region->n_members && !affected; n++) {
            uint32_t mi = region->first_member + n;
            SupercacheRecord *r =
                &supercache.entries[sc7.source_index[mi]].record;

            affected = sc7_record_overlaps(r, start, last);
        }
        if (!affected) {
            continue;
        }
        sc7.region_admitted[ri] = false;
        for (uint32_t n = 0; n < region->n_members; n++) {
            uint32_t mi = region->first_member + n;
            TranslationBlock *tb;
            bool registered;

            if (!sc7.member_prepared[mi]) {
                continue;
            }
            tb = sc7_member_tb(mi);
            registered = sc7.private_tbs[mi] != NULL;
            current_affected |= tb == current_tb;
            for (int slot = 0; slot < 2; slot++) {
                if (tb->jmp_reset_offset[slot] != TB_JMP_OFFSET_INVALID &&
                    !sc7_member_internal_slot(mi,
                                              tb->jmp_insn_offset[slot])) {
                    tb_unlink_jump(tb, slot);
                }
            }
            tb_supercache_invalidate_private(tb, registered);
            sc7.private_tbs[mi] = NULL;
            sc7.member_prepared[mi] = false;
        }
        sc7.dependency_invalidations++;
    }
    qemu_thread_jit_execute();
    return current_affected;
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

typedef struct RestoreHint {
    uint64_t offset;
    uint32_t checksum;
} RestoreHint;

typedef struct RestoreCounts {
    uint64_t attempted;
    uint64_t nominated;
    uint64_t skipped;
    uint64_t vetoed;
    uint64_t callbacks_executed;
} RestoreCounts;

static GArray *restore_hints;
static bool restore_initialized;
static bool restore_stats_window;
static const char *restore_stats_path;
static RestoreCounts restore_all, restore_benchmark;

static void write_restore_counts(FILE *f, const RestoreCounts *c)
{
    fprintf(f, "{\"attempted\":%" PRIu64 ",\"nominated\":%" PRIu64
            ",\"skipped\":%" PRIu64 ",\"vetoed\":%" PRIu64
            ",\"callbacks_executed\":%" PRIu64 "}",
            c->attempted, c->nominated, c->skipped, c->vetoed,
            c->callbacks_executed);
}

static void write_restore_stats(void)
{
    FILE *f = fopen(restore_stats_path, "w");

    if (!f) {
        return;
    }
    fprintf(f, "{\"schema\":\"fastdyn.supercache_restore_stats/1\","
            "\"records_validated\":%u,\"hint_records\":%u,"
            "\"hint_file_valid\":%s,\"all\":",
            supercache.entry_count, restore_hints ? restore_hints->len : 0,
            restore_hints ? "true" : "false");
    write_restore_counts(f, &restore_all);
    fputs(",\"benchmark\":", f);
    write_restore_counts(f, &restore_benchmark);
    fputs("}\n", f);
    fclose(f);
}

void tcg_supercache_restore_window(bool started)
{
    restore_stats_window = started;
}

static bool restore_uint(const char *token, int base, uint64_t *value)
{
    char *end;
    const char *digits = token;

    if (base == 16 && g_str_has_prefix(digits, "0x")) {
        digits += 2;
    }
    if (!*digits) {
        return false;
    }
    for (const char *p = digits; *p; p++) {
        if (!(base == 16 ? g_ascii_isxdigit(*p) : g_ascii_isdigit(*p))) {
            return false;
        }
    }
    errno = 0;
    *value = g_ascii_strtoull(digits, &end, base);
    return !errno && !*end;
}

static bool restore_header_matches(char *line, const SupercacheHeader *h)
{
    g_auto(GStrv) parts = g_strsplit(g_strchomp(line), " ", -1);
    uint64_t signature, header_sum, records;

    return g_strv_length(parts) == 5 &&
           !strcmp(parts[0], "FD_SC_RESTORE_HINTS") && !strcmp(parts[1], "1") &&
           restore_uint(parts[2], 16, &signature) &&
           restore_uint(parts[3], 16, &header_sum) &&
           restore_uint(parts[4], 10, &records) &&
           signature == h->runtime_signature && header_sum == h->checksum &&
           records == h->record_count;
}

static bool restore_hint_parse(char *line, RestoreHint *row)
{
    g_auto(GStrv) parts = g_strsplit(g_strchomp(line), " ", -1);
    uint64_t checksum;

    if (g_strv_length(parts) != 2 ||
        !restore_uint(parts[0], 16, &row->offset) ||
        !restore_uint(parts[1], 16, &checksum) || checksum > UINT32_MAX) {
        return false;
    }
    row->checksum = checksum;
    return true;
}

static void init_restore_hints(void)
{
    const char *mode = getenv("QEMU_SC_RESTORE_REPLAY");
    const char *explicit = getenv("QEMU_SC_RESTORE_HINTS");
    g_autofree char *sibling = NULL;
    const SupercacheHeader *h = &supercache.loaded_header;
    char line[160];
    struct stat st;
    FILE *f;
    int fd;
    GArray *rows;

    restore_initialized = true;
    restore_stats_path = getenv("QEMU_SC_RESTORE_STATS");
    if (restore_stats_path && *restore_stats_path) {
        atexit(write_restore_stats);
    } else {
        restore_stats_path = NULL;
    }
    if ((mode && strcmp(mode, "verified")) || supercache.flat ||
        h->version != SUPERCACHE_VERSION || h->record_count > UINT32_MAX ||
        !h->record_count) {
        return;
    }

    if (!explicit) {
        sibling = g_strconcat(supercache.path, ".restore-hints", NULL);
    }
    fd = open(explicit ?: sibling, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        return;
    }
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (uint64_t)st.st_size > sizeof(line) * (h->record_count + 1)) {
        close(fd);
        return;
    }
    f = fdopen(fd, "r");
    if (!f) {
        close(fd);
        return;
    }
    if (!fgets(line, sizeof(line), f) || !strchr(line, '\n') ||
        !restore_header_matches(line, h)) {
        fclose(f);
        return;
    }

    rows = g_array_new(false, false, sizeof(RestoreHint));
    while (fgets(line, sizeof(line), f)) {
        RestoreHint row;
        if (!strchr(line, '\n') || rows->len >= h->record_count ||
            !restore_hint_parse(line, &row) ||
            (rows->len &&
             row.offset <= g_array_index(rows, RestoreHint, rows->len - 1).offset)) {
            goto refuse;
        }
        g_array_append_val(rows, row);
    }
    if (ferror(f) || !rows->len) {
        goto refuse;
    }
    fclose(f);
    restore_hints = rows;
    return;

refuse:
    fclose(f);
    g_array_unref(rows);
}

static bool restore_hint_matches(const SupercacheRecord *r)
{
    if (unlikely(!restore_initialized)) {
        init_restore_hints();
    }
    if (!restore_hints || scc_active || scp_active) {
        return false;
    }
    unsigned low = 0, high = restore_hints->len;

    while (low < high) {
        unsigned mid = low + (high - low) / 2;
        const RestoreHint *hint = &g_array_index(restore_hints, RestoreHint, mid);

        if (hint->offset == r->tb_offset) {
            return hint->checksum == r->checksum;
        }
        if (hint->offset > r->tb_offset) {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    return false;
}

static void note_restore(RestoreCounts *c, bool nominated, bool skip,
                         unsigned callbacks)
{
    c->attempted++;
    c->nominated += nominated;
    c->skipped += skip;
    c->vetoed += nominated && !skip;
    c->callbacks_executed += callbacks;
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
    if (unlikely(sc7.loaded)) {
        TranslationBlock *private_entry = sc7_try_region(cpu,
            entry - supercache.entries);

        if (private_entry) {
            return private_entry;
        }
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
    bool nominated = restore_hint_matches(r);
    bool skip = nominated && !cpu->singlestep_enabled &&
                QTAILQ_EMPTY(&cpu->breakpoints) && QTAILQ_EMPTY(&cpu->watchpoints) &&
                qemu_plugin_tb_restore_omittable(cpu, state.pc, r->guest_size);
    unsigned callbacks = qemu_plugin_supercache_rehydrate(cpu, tb, state.pc,
                                                           skip);

    if (unlikely(restore_stats_path)) {
        note_restore(&restore_all, nominated, skip, callbacks);
        if (restore_stats_window) {
            note_restore(&restore_benchmark, nominated, skip, callbacks);
        }
    }
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

    if (!supercache.initialized ||
        tc_ptr < (uintptr_t)supercache.buffer ||
        tc_ptr - (uintptr_t)supercache.buffer >= supercache.size) {
        return NULL;
    }
    offset = tc_ptr - (uintptr_t)supercache.buffer;
    if (sc7.loaded) {
        for (uint32_t i = 0; i < sc7.header.n_members; i++) {
            Sc7MemberEntry *m = &sc7.members[i];

            if (sc7.member_prepared[i] && offset >= m->tc_offset &&
                offset < m->tc_offset + m->tc_size) {
                return sc7_member_tb(i);
            }
        }
    }
    if (!supercache.flat) {
        return NULL;
    }
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

void tcg_supercache_restore_window(bool started)
{
}

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

const uint8_t *tcg_supercache_search_data(const TranslationBlock *tb)
{
    return NULL;
}

bool tcg_supercache_code_invalidated(tb_page_addr_t start,
                                     tb_page_addr_t last,
                                     TranslationBlock *current_tb)
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
