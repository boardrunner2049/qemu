#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/error-report.h"
#include "qemu/thread.h"
#include "qemu/qemu-plugin.h"
#include "exec/fastdyn-mmio.h"

#define FASTDYN_MAX_MMIO_REPLACEMENTS 4096u

static FastDynMmioBoundReplacement replacements[FASTDYN_MAX_MMIO_REPLACEMENTS];
static const FastDynMmioBoundReplacement *replacements_by_pc[FASTDYN_MAX_MMIO_REPLACEMENTS];
static size_t replacement_count;
static uint64_t next_replacement_id = 1;
static bool registry_sealed;
static QemuMutex registry_lock;
static gsize registry_once;

static void registry_init(void)
{
    qemu_mutex_init(&registry_lock);
}

static bool valid_expr(const FastDynMmioReplacement *r)
{
    unsigned depth = 0;
    size_t i;

    if (!r->state || !r->expr || !r->expr_count ||
        r->expr_count > FASTDYN_MMIO_MAX_EXPR_INSNS || !r->state_size) {
        return false;
    }
    for (i = 0; i < r->expr_count; i++) {
        const FastDynMmioExprInsn *op = &r->expr[i];
        unsigned width = 0;

        switch (op->opcode) {
        case FASTDYN_MMIO_EXPR_CONST:
            depth++;
            break;
        case FASTDYN_MMIO_EXPR_LOAD_U8:
            width = 1;
            goto check_load;
        case FASTDYN_MMIO_EXPR_LOAD_U16:
            width = 2;
            goto check_load;
        case FASTDYN_MMIO_EXPR_LOAD_U32:
            width = 4;
check_load:
            if (op->state_offset > r->state_size ||
                width > r->state_size - op->state_offset) {
                return false;
            }
            depth++;
            break;
        case FASTDYN_MMIO_EXPR_ADD:
        case FASTDYN_MMIO_EXPR_SUB:
        case FASTDYN_MMIO_EXPR_AND:
        case FASTDYN_MMIO_EXPR_OR:
        case FASTDYN_MMIO_EXPR_XOR:
        case FASTDYN_MMIO_EXPR_SHL:
        case FASTDYN_MMIO_EXPR_LSHR:
            if (depth < 2) {
                return false;
            }
            depth--;
            break;
        default:
            return false;
        }
        if (depth > FASTDYN_MMIO_MAX_EXPR_INSNS) {
            return false;
        }
    }
    return depth == 1;
}

bool qemu_plugin_register_fastdyn_mmio_replacement(
    const FastDynMmioReplacement *replacement, uint64_t *out_hook_id)
{
    FastDynMmioBoundReplacement *dst;
    bool ok = false;

    if (out_hook_id) {
        *out_hook_id = 0;
    }
    if (!replacement || replacement->spec.isa != FASTDYN_GUEST_ISA_ARM ||
        replacement->spec.mode != FASTDYN_CODE_MODE_THUMB ||
        replacement->spec.instruction_order != FASTDYN_INSN_ORDER_LITTLE_ENDIAN ||
        (replacement->guest_pc & 1) || replacement->guest_pc > UINT32_MAX ||
        replacement->expected_address > UINT32_MAX ||
        (replacement->transfer_size != 1 && replacement->transfer_size != 2 &&
         replacement->transfer_size != 4) || !valid_expr(replacement)) {
        error_report("FastDyn MMIO replacement registration rejected");
        return false;
    }

    if (g_once_init_enter(&registry_once)) {
        registry_init();
        g_once_init_leave(&registry_once, 1);
    }
    qemu_mutex_lock(&registry_lock);
    if (registry_sealed || replacement_count == FASTDYN_MAX_MMIO_REPLACEMENTS) {
        goto out;
    }
    dst = &replacements[replacement_count++];
    dst->id = next_replacement_id++;
    dst->replacement = *replacement;
    memcpy(dst->expr, replacement->expr,
           replacement->expr_count * sizeof(replacement->expr[0]));
    dst->replacement.expr = dst->expr;
    if (out_hook_id) {
        *out_hook_id = dst->id;
    }
    ok = true;
out:
    qemu_mutex_unlock(&registry_lock);
    return ok;
}

static int compare_replacements(const void *a, const void *b)
{
    const FastDynMmioBoundReplacement *left = *(const FastDynMmioBoundReplacement *const *)a;
    const FastDynMmioBoundReplacement *right = *(const FastDynMmioBoundReplacement *const *)b;

    if (left->replacement.guest_pc != right->replacement.guest_pc) {
        return left->replacement.guest_pc < right->replacement.guest_pc ? -1 : 1;
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
        for (size_t i = 0; i < replacement_count; i++) {
            replacements_by_pc[i] = &replacements[i];
        }
        qsort(replacements_by_pc, replacement_count, sizeof(replacements_by_pc[0]),
              compare_replacements);
        /* Publish the index and entries once. Registration stops at the
         * first lookup, including when the registry is empty. */
        qatomic_store_release(&registry_sealed, true);
    }
    qemu_mutex_unlock(&registry_lock);
}

const FastDynMmioBoundReplacement *fastdyn_mmio_find(
    uint64_t guest_pc, FastDynCodeMode mode, unsigned transfer_size,
    size_t *cursor)
{
    size_t i = *cursor;

    if (unlikely(!qatomic_load_acquire(&registry_sealed))) {
        seal_registry();
    }
    if (i == 0) {
        size_t end = replacement_count;

        /* Start at the lowest PC match and visit ties in registration order. */
        while (i < end) {
            size_t mid = i + (end - i) / 2;

            if (replacements_by_pc[mid]->replacement.guest_pc < guest_pc) {
                i = mid + 1;
            } else {
                end = mid;
            }
        }
    }
    for (; i < replacement_count && replacements_by_pc[i]->replacement.guest_pc == guest_pc;
         i++) {
        const FastDynMmioBoundReplacement *f = replacements_by_pc[i];

        if (f->replacement.spec.mode == mode &&
            f->replacement.transfer_size == transfer_size) {
            *cursor = i + 1;
            return f;
        }
    }
    return NULL;
}
