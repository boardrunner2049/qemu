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

#include <sys/file.h>

#define SUPERCACHE_MAGIC          "QSCACHE1"
#define SUPERCACHE_VERSION        5
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

void tcg_supercache_configure(const char *path, bool flat, int splitwx,
                              unsigned max_threads)
{
    if (!path) {
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
}

bool tcg_supercache_enabled(void)
{
    return supercache.configured;
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
           header->version == SUPERCACHE_VERSION &&
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
            sizeof(disk_header) &&
        valid_header(&disk_header, size, signature)) {
        reuse = true;
        supercache.header = disk_header;
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
        qatomic_set(&s->code_gen_ptr,
                    (uint8_t *)supercache.buffer + supercache.max_end);
    }
    if (header_changed) {
        write_header();
    }
}

void tcg_supercache_runtime_reset(void)
{
    if (supercache.initialized) {
        for (uint32_t i = 0; i < supercache.entry_count; i++) {
            supercache.entries[i].used = false;
            supercache.entries[i].invalid = false;
        }
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

#endif /* CONFIG_LINUX && HOST_X86_64 */
