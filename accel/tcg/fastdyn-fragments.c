#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/error-report.h"
#include "qemu/bswap.h"
#include "qemu/thread.h"
#include "qemu/qemu-plugin.h"
#include "exec/fastdyn-fragments.h"

#define FASTDYN_MAX_FRAGMENTS 1024u

static FastDynFragment fragments[FASTDYN_MAX_FRAGMENTS];
static const FastDynFragment *fragments_by_pc[FASTDYN_MAX_FRAGMENTS];
static size_t fragment_count;
static uint64_t next_fragment_id = 1;
static bool registry_sealed;
static QemuMutex registry_lock;
static gsize registry_once;

static void registry_init(void)
{
    qemu_mutex_init(&registry_lock);
}

static bool valid_spec(const FastDynCodeSpec *spec)
{
    if (!spec || (spec->instruction_order != FASTDYN_INSN_ORDER_LITTLE_ENDIAN &&
                  spec->instruction_order != FASTDYN_INSN_ORDER_BIG_ENDIAN)) {
        return false;
    }
    switch (spec->isa) {
    case FASTDYN_GUEST_ISA_ARM:
        return spec->mode == FASTDYN_CODE_MODE_A32 ||
               spec->mode == FASTDYN_CODE_MODE_THUMB;
    case FASTDYN_GUEST_ISA_AARCH64:
        return spec->mode == FASTDYN_CODE_MODE_A64 &&
               spec->instruction_order == FASTDYN_INSN_ORDER_LITTLE_ENDIAN;
    case FASTDYN_GUEST_ISA_X86:
        return spec->mode >= FASTDYN_CODE_MODE_X86_16 &&
               spec->mode <= FASTDYN_CODE_MODE_X86_64 &&
               spec->instruction_order == FASTDYN_INSN_ORDER_LITTLE_ENDIAN;
    case FASTDYN_GUEST_ISA_RISCV:
        return (spec->mode == FASTDYN_CODE_MODE_RV32 ||
                spec->mode == FASTDYN_CODE_MODE_RV64) &&
               spec->instruction_order == FASTDYN_INSN_ORDER_LITTLE_ENDIAN;
    default:
        return false;
    }
}

static bool aligned_pc(uint64_t pc, const FastDynCodeSpec *spec)
{
    switch (spec->mode) {
    case FASTDYN_CODE_MODE_A32:
    case FASTDYN_CODE_MODE_A64:
        return !(pc & 3);
    case FASTDYN_CODE_MODE_THUMB:
    case FASTDYN_CODE_MODE_RV32:
    case FASTDYN_CODE_MODE_RV64:
        return !(pc & 1);
    default:
        return true;
    }
}

static bool representable_pc(uint64_t pc, const FastDynCodeSpec *spec)
{
    switch (spec->mode) {
    case FASTDYN_CODE_MODE_A32:
    case FASTDYN_CODE_MODE_THUMB:
    case FASTDYN_CODE_MODE_X86_16:
    case FASTDYN_CODE_MODE_X86_32:
    case FASTDYN_CODE_MODE_RV32:
        return pc <= UINT32_MAX;
    default:
        /* Canonicality and implemented VA width are live CPU properties. */
        return true;
    }
}

static uint16_t fragment_u16(const uint8_t *p, bool big)
{
    return big ? lduw_be_p(p) : lduw_le_p(p);
}

static bool count_x86(const uint8_t *code, size_t size, FastDynCodeMode mode,
                      size_t *count)
{
    size_t p = 0;
    *count = 0;
    while (p < size) {
        size_t start = p, imm = 0;
        unsigned op, modrm = 0, ext = 0;
        bool p66 = false, rexw = false, need_modrm = false;
        int opsize;

#define REG_BYTE() ((p < size) ? code[p++] : 0x100)
        do {
            op = REG_BYTE();
            if (op == 0x66) {
                p66 = true;
                rexw = false;
            } else if (mode == FASTDYN_CODE_MODE_X86_64 &&
                       op >= 0x40 && op <= 0x4f) {
                rexw = op & 8;
            } else {
                break;
            }
        } while (p - start <= 15);
        if (op > 0xff) {
            return false;
        }
        opsize = mode == FASTDYN_CODE_MODE_X86_16 ? (p66 ? 4 : 2) :
                 mode == FASTDYN_CODE_MODE_X86_32 ? (p66 ? 2 : 4) :
                 rexw ? 8 : p66 ? 2 : 4;
        if ((op & 0xf8) == 0xb0) {
            imm = 1;
        } else if ((op & 0xf8) == 0xb8) {
            imm = opsize;
        } else if (op == 0x88 || op == 0x89 || op == 0x8a || op == 0x8b ||
                   op == 0x84 || op == 0x85) {
            need_modrm = true;
        } else if (((op & 0xf8) == 0x00 || (op & 0xf8) == 0x08 ||
                    (op & 0xf8) == 0x20 || (op & 0xf8) == 0x28 ||
                    (op & 0xf8) == 0x30 || (op & 0xf8) == 0x38) &&
                   (op & 7) <= 3) {
            need_modrm = true;
        } else if (op == 0x04 || op == 0x0c || op == 0x24 || op == 0x2c ||
                   op == 0x34 || op == 0x3c) {
            imm = 1;
        } else if (op == 0x05 || op == 0x0d || op == 0x25 || op == 0x2d ||
                   op == 0x35 || op == 0x3d) {
            imm = rexw ? 4 : opsize;
        } else if (op == 0x80 || op == 0x81 || op == 0x83 ||
                   op == 0xc6 || op == 0xc7 || op == 0xf6 || op == 0xf7 ||
                   op == 0xc0 || op == 0xc1 || op == 0xd0 || op == 0xd1) {
            modrm = REG_BYTE();
            if (modrm > 0xff || (modrm >> 6) != 3) {
                return false;
            }
            ext = (modrm >> 3) & 7;
            if (op == 0x80 || op == 0x81 || op == 0x83) {
                if (!(ext == 0 || ext == 1 || ext >= 4)) {
                    return false;
                }
                imm = op == 0x81 ? (rexw ? 4 : opsize) : 1;
            } else if (op == 0xc6 || op == 0xc7) {
                if (ext) return false;
                imm = op == 0xc6 ? 1 : rexw ? 4 : opsize;
            } else if (op == 0xf6 || op == 0xf7) {
                if (ext) return false;
                imm = op == 0xf6 ? 1 : rexw ? 4 : opsize;
            } else {
                if (!(ext == 4 || ext == 5 || ext == 7)) return false;
                imm = (op == 0xc0 || op == 0xc1) ? 1 : 0;
            }
        } else if (op == 0x0f) {
            op = REG_BYTE();
            if (!(op == 0xb6 || op == 0xb7 || op == 0xbe || op == 0xbf)) {
                return false;
            }
            need_modrm = true;
        } else if (op == 0x63 && mode == FASTDYN_CODE_MODE_X86_64) {
            need_modrm = true;
        } else {
            return false;
        }
        if (need_modrm) {
            modrm = REG_BYTE();
            if (modrm > 0xff || (modrm >> 6) != 3) return false;
        }
        if (size - p < imm || p + imm - start > 15) return false;
        p += imm;
        if (++*count > FASTDYN_FRAGMENT_MAX_INSNS) return false;
#undef REG_BYTE
    }
    return true;
}

static bool count_instructions(const uint8_t *code, size_t size,
                               const FastDynCodeSpec *spec, size_t *count)
{
    size_t p = 0;
    bool big = spec->instruction_order == FASTDYN_INSN_ORDER_BIG_ENDIAN;

    if (spec->mode == FASTDYN_CODE_MODE_A32 ||
        spec->mode == FASTDYN_CODE_MODE_A64) {
        if (size & 3) return false;
        *count = size / 4;
        return *count <= FASTDYN_FRAGMENT_MAX_INSNS;
    }
    if (spec->mode == FASTDYN_CODE_MODE_X86_16 ||
        spec->mode == FASTDYN_CODE_MODE_X86_32 ||
        spec->mode == FASTDYN_CODE_MODE_X86_64) {
        return count_x86(code, size, spec->mode, count);
    }
    *count = 0;
    while (p < size) {
        uint16_t first;
        size_t len;
        if (size - p < 2) return false;
        first = fragment_u16(code + p, big);
        if (spec->mode == FASTDYN_CODE_MODE_THUMB) {
            unsigned top = first >> 11;
            len = (top == 0x1d || top == 0x1e || top == 0x1f) ? 4 : 2;
        } else {
            len = (first & 3) == 3 ? 4 : 2;
        }
        if (size - p < len || ++*count > FASTDYN_FRAGMENT_MAX_INSNS) {
            return false;
        }
        p += len;
    }
    return true;
}

bool qemu_plugin_register_fastdyn_fragment(
    uint64_t guest_pc, const uint8_t *code, size_t code_size,
    const FastDynCodeSpec *spec, uint64_t *out_hook_id)
{
    uint8_t *copy = NULL;
    size_t combined = 0;
    size_t combined_insns = 0, insn_count = 0;
    size_t i;
    bool ok = false;

    if (out_hook_id) {
        *out_hook_id = 0;
    }
    if (g_once_init_enter(&registry_once)) {
        registry_init();
        g_once_init_leave(&registry_once, 1);
    }
    if (!code || code_size == 0 || code_size > FASTDYN_FRAGMENT_MAX_BYTES ||
        !valid_spec(spec) || !representable_pc(guest_pc, spec) ||
        !aligned_pc(guest_pc, spec) ||
        !count_instructions(code, code_size, spec, &insn_count)) {
        error_report("FastDyn fragment registration rejected: invalid bytes, descriptor, limit, or address at 0x%" PRIx64,
                     guest_pc);
        return false;
    }
    copy = g_try_malloc(code_size);
    if (!copy) {
        error_report("FastDyn fragment registration rejected: allocation failed");
        return false;
    }
    memcpy(copy, code, code_size);

    qemu_mutex_lock(&registry_lock);
    if (registry_sealed) {
        error_report("FastDyn fragment registration rejected: translation has started");
        goto out;
    }
    if (fragment_count == FASTDYN_MAX_FRAGMENTS) {
        error_report("FastDyn fragment registration rejected: registry is full");
        goto out;
    }
    for (i = 0; i < fragment_count; i++) {
        FastDynFragment *f = &fragments[i];
        if (f->guest_pc == guest_pc &&
            !memcmp(&f->spec, spec, sizeof(*spec))) {
            combined += f->code_size;
            combined_insns += f->insn_count;
        }
    }
    if (combined + code_size > FASTDYN_FRAGMENT_MAX_BYTES ||
        combined_insns + insn_count > FASTDYN_FRAGMENT_MAX_INSNS) {
        error_report("FastDyn fragment registration rejected: combined site limits exceeded at 0x%" PRIx64,
                     guest_pc);
        goto out;
    }
    fragments[fragment_count] = (FastDynFragment) {
        .id = next_fragment_id++, .guest_pc = guest_pc, .spec = *spec,
        .insn_count = insn_count,
        .code_size = code_size, .code = copy,
    };
    if (out_hook_id) {
        *out_hook_id = fragments[fragment_count].id;
    }
    fragment_count++;
    copy = NULL;
    ok = true;
out:
    qemu_mutex_unlock(&registry_lock);
    g_free(copy);
    return ok;
}

static int compare_fragments(const void *a, const void *b)
{
    const FastDynFragment *left = *(const FastDynFragment *const *)a;
    const FastDynFragment *right = *(const FastDynFragment *const *)b;

    if (left->guest_pc != right->guest_pc) {
        return left->guest_pc < right->guest_pc ? -1 : 1;
    }
    return (left->id > right->id) - (left->id < right->id);
}

static void seal_registry(void)
{
    if (g_once_init_enter(&registry_once)) {
        registry_init();
        g_once_init_leave(&registry_once, 1);
    }
    qemu_mutex_lock(&registry_lock);
    if (!registry_sealed) {
        for (size_t i = 0; i < fragment_count; i++) {
            fragments_by_pc[i] = &fragments[i];
        }
        qsort(fragments_by_pc, fragment_count, sizeof(fragments_by_pc[0]),
              compare_fragments);
        /* Publish the index and entries once. Registration stops at the
         * first lookup, including when the registry is empty. */
        qatomic_store_release(&registry_sealed, true);
    }
    qemu_mutex_unlock(&registry_lock);
}

const FastDynFragment *fastdyn_fragment_find(
    uint64_t guest_pc, FastDynGuestISA isa, FastDynCodeMode mode,
    FastDynInstructionOrder order, size_t *cursor)
{
    size_t i = *cursor;

    if (unlikely(!qatomic_load_acquire(&registry_sealed))) {
        seal_registry();
    }
    if (i == 0) {
        size_t end = fragment_count;

        /* Start at the lowest PC match and visit ties in registration order. */
        while (i < end) {
            size_t mid = i + (end - i) / 2;

            if (fragments_by_pc[mid]->guest_pc < guest_pc) {
                i = mid + 1;
            } else {
                end = mid;
            }
        }
    }
    for (; i < fragment_count && fragments_by_pc[i]->guest_pc == guest_pc;
         i++) {
        const FastDynFragment *f = fragments_by_pc[i];

        if (f->spec.isa == isa && f->spec.mode == mode &&
            f->spec.instruction_order == order) {
            *cursor = i + 1;
            return f;
        }
    }
    return NULL;
}

void fastdyn_fragment_translation_error(const FastDynFragment *fragment,
                                        size_t offset, const char *reason)
{
    error_report("FastDyn fragment hook=%" PRIu64 " pc=0x%" PRIx64
                 " offset=%zu encoding=%d/%d rejected: %s",
                 fragment->id, fragment->guest_pc, offset,
                 fragment->spec.isa, fragment->spec.mode, reason);
    abort();
}
