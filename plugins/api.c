/*
 * QEMU Plugin API
 *
 * This provides the API that is available to the plugins to interact
 * with QEMU. We have to be careful not to expose internal details of
 * how QEMU works so we abstract out things like translation and
 * instructions to anonymous data types:
 *
 *  qemu_plugin_tb
 *  qemu_plugin_insn
 *  qemu_plugin_register
 *
 * Which can then be passed back into the API to do additional things.
 * As such all the public functions in here are exported in
 * qemu-plugin.h.
 *
 * The general life-cycle of a plugin is:
 *
 *  - plugin is loaded, public qemu_plugin_install called
 *    - the install func registers callbacks for events
 *    - usually an atexit_cb is registered to dump info at the end
 *  - when a registered event occurs the plugin is called
 *     - some events pass additional info
 *     - during translation the plugin can decide to instrument any
 *       instruction
 *  - when QEMU exits all the registered atexit callbacks are called
 *
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 * Copyright (C) 2019, Linaro
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qemu/plugin.h"
#include "qemu/log.h"
#include "tcg/tcg.h"
#include "exec/gdbstub.h"
#include "exec/target_page.h"
#include "exec/translation-block.h"
#include "exec/translator.h"
#include "system/runstate.h"
#include "disas/disas.h"
#include "plugin.h"
#include "elf.h"
#include "hw/core/cpu.h"
#include "exec/icount.h"
#include "system/cpu-timers-internal.h"

/* Uninstall and Reset handlers */

void qemu_plugin_uninstall(qemu_plugin_id_t id, qemu_plugin_simple_cb_t cb)
{
    plugin_reset_uninstall(id, cb, false);
}

void qemu_plugin_reset(qemu_plugin_id_t id, qemu_plugin_simple_cb_t cb)
{
    plugin_reset_uninstall(id, cb, true);
}

/*
 * Plugin Register Functions
 *
 * This allows the plugin to register callbacks for various events
 * during the translation.
 */

void qemu_plugin_register_vcpu_init_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_INIT, cb);
}

void qemu_plugin_register_vcpu_exit_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_EXIT, cb);
}

static bool tb_is_mem_only(void)
{
    return tb_cflags(tcg_ctx->gen_tb) & CF_MEMI_ONLY;
}

extern int64_t qemu_start_time(void);
int64_t qemu_plugin_host_start_ns(void) {
	return qemu_clock_get_ns(QEMU_CLOCK_START);
}

static int64_t qemu_plugin_get_virtual_time_ns(void)
{
    int64_t icount;
    CPUState *cpu;

    if (!icount_enabled()) {
        return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    }

    /*
     * Plugin callbacks can run from translated code while can_do_io is false.
     * qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) would try to commit the current
     * CPU's partial icount there, which QEMU rejects.  For plugins, return a
     * read-only view: committed global icount plus this CPU's in-flight budget
     * consumption.
     */
    icount = qatomic_read_i64(&timers_state.qemu_icount);
    cpu = current_cpu;
    if (cpu && cpu->running) {
        icount += cpu->icount_budget -
            (cpu->neg.icount_decr.u16.low + cpu->icount_extra);
    }

    return qatomic_read_i64(&timers_state.qemu_icount_bias) +
        icount_to_ns(icount);
}


void qemu_plugin_pause_vm(void) {
	qemu_system_vmstop_request(RUN_STATE_PAUSED);
}

typedef struct BudgetControl {
    QemuCond cond;
    QemuMutex lock;
    uint64_t total_budget;
    int budget_init;
    QEMUTimer budget_timer;
	QEMUTimerCB * cb;
	RunState vm_old_state;
} BudgetControl;

extern BudgetControl bc_tcb;

void budget_exhausted(void * arg);
void budget_exhausted(void * arg) {
	BudgetControl * bc = (BudgetControl *) arg;
	printf("Budgeting time!!\n");

	qemu_mutex_lock(&bc->lock);
	uint64_t ts = qemu_plugin_get_virtual_time_ns();
	if (ts >= bc->total_budget) {
		if (runstate_get() != RUN_STATE_PAUSED) {
			bc->vm_old_state = runstate_get();
    	    qemu_system_vmstop_request(RUN_STATE_PAUSED);
			printf("Stopping vm at %ld \n", ts);
		}
		//Try to account for drift
		bc->total_budget = qemu_plugin_get_virtual_time_ns();
    }
    else {
		vm_resume(bc->vm_old_state);
		printf("See you in %ld\n", bc->total_budget);
        timer_mod_ns(&bc->budget_timer, bc->total_budget); 
    }

	qemu_mutex_unlock(&bc->lock);
}

extern void init_budget_system(void);
uint64_t qemu_plugin_wait_for_budget(void) {
	if (!bc_tcb.budget_init) {
		init_budget_system();
	}
	budget_exhausted(&bc_tcb);
	return 0;
}
//Hook to register loader functions.
extern void plugin_vmstate_budget(void);
void qemu_plugin_vmstate(void) {
		plugin_vmstate_budget();
}


static void (*irq_cb)(int);
static void (*irq_finish_cb)(int);
void qemu_plugin_irq_hook(int number);
void qemu_plugin_irq_hook(int number) {
		if (irq_cb) {
				irq_cb(number);
		}
}

void qemu_plugin_register_irq_hook(void (*notify_cb)(int), void (*finish_cb)(int)) {
		irq_cb = notify_cb;
		irq_finish_cb = finish_cb;
}
uint64_t qemu_plugin_timer_new_ns(void (*cb)(void *), void *data) {
	return (uint64_t ) timer_new_ns(QEMU_CLOCK_VIRTUAL, cb, data);
}

void qemu_plugin_timer_alarm(uint64_t timer_fd, uint64_t delay_ns) {
	timer_mod_ns((QEMUTimer *)(uintptr_t) timer_fd, delay_ns);
}

#define MAX_TIMERS 10
typedef struct {
    QEMUTimer * timer;
    uint64_t period_ns;
    int64_t next_fire_ns;
	int used;
	void (*cb)(void *);
	void *data;
} PTimerCtx;

PTimerCtx ptimers[MAX_TIMERS];

static PTimerCtx * _timer_allocate(void) {
    for (int i = 0; i < MAX_TIMERS; i++) {
        if (!ptimers[i].used) {
            ptimers[i].used = true;
            return &ptimers[i];
        }
    }
    return NULL;  // No free slot available
}


#include <inttypes.h>
static void ptimer_callback(void *opaque) {
    PTimerCtx *ctx = (PTimerCtx *)opaque;

    if (!ctx->used) {
        return;  // Timer was freed
    }

    // Fire user callback
    if (ctx->cb) {
        ctx->cb(ctx->data);
    }

    // Reschedule for next aligned period
    int64_t now = qemu_plugin_get_virtual_time_ns();

    // If we're behind, skip missed intervals to stay aligned
	int missed =-1;
    while (ctx->next_fire_ns <= now) {
        ctx->next_fire_ns += ctx->period_ns;
		missed++;
    }

	if (missed) {
			printf("⚠️  Missed %d alarm(s)! Now: %" PRId64 ", Next: %" PRId64 "\n",
               missed , now, ctx->next_fire_ns);
	}
    timer_mod_ns(ctx->timer, ctx->next_fire_ns);
}

uint64_t qemu_plugin_timer_new_period_ns(void (*cb)(void *), void *data, uint64_t period) {
	PTimerCtx * ctx = _timer_allocate();
	if (ctx) {
	    ctx->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, ptimer_callback, ctx);
		ctx->data = data;
		ctx->cb =cb;
		ctx->period_ns = period;
		ctx->next_fire_ns = qemu_plugin_get_virtual_time_ns() + ctx->period_ns;
		timer_mod_ns(ctx->timer, ctx->next_fire_ns);
	} else {
		printf("Too many timers requested, i will die now");
		exit(1);
	}

	return (uint64_t) (ctx->timer);
}

void qemu_plugin_register_vcpu_tb_exec_cb(struct qemu_plugin_tb *tb,
                                          qemu_plugin_vcpu_udata_cb_t cb,
                                          enum qemu_plugin_cb_flags flags,
                                          void *udata)
{
    if (!tb_is_mem_only()) {
        plugin_register_dyn_cb__udata(&tb->cbs, cb, flags, udata);
    }
}

void qemu_plugin_register_vcpu_tb_exec_cond_cb(struct qemu_plugin_tb *tb,
                                               qemu_plugin_vcpu_udata_cb_t cb,
                                               enum qemu_plugin_cb_flags flags,
                                               enum qemu_plugin_cond cond,
                                               qemu_plugin_u64 entry,
                                               uint64_t imm,
                                               void *udata)
{
    if (cond == QEMU_PLUGIN_COND_NEVER || tb_is_mem_only()) {
        return;
    }
    if (cond == QEMU_PLUGIN_COND_ALWAYS) {
        qemu_plugin_register_vcpu_tb_exec_cb(tb, cb, flags, udata);
        return;
    }
    plugin_register_dyn_cond_cb__udata(&tb->cbs, cb, flags,
                                       cond, entry, imm, udata);
}

void qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
    struct qemu_plugin_tb *tb,
    enum qemu_plugin_op op,
    qemu_plugin_u64 entry,
    uint64_t imm)
{
    if (!tb_is_mem_only()) {
        plugin_register_inline_op_on_entry(&tb->cbs, 0, op, entry, imm);
    }
}

void qemu_plugin_register_vcpu_insn_exec_cb(struct qemu_plugin_insn *insn,
                                            qemu_plugin_vcpu_udata_cb_t cb,
                                            enum qemu_plugin_cb_flags flags,
                                            void *udata)
{
    if (!tb_is_mem_only()) {
        plugin_register_dyn_cb__udata(&insn->insn_cbs, cb, flags, udata);
    }
}

void qemu_plugin_register_vcpu_insn_exec_cond_cb(
    struct qemu_plugin_insn *insn,
    qemu_plugin_vcpu_udata_cb_t cb,
    enum qemu_plugin_cb_flags flags,
    enum qemu_plugin_cond cond,
    qemu_plugin_u64 entry,
    uint64_t imm,
    void *udata)
{
    if (cond == QEMU_PLUGIN_COND_NEVER || tb_is_mem_only()) {
        return;
    }
    if (cond == QEMU_PLUGIN_COND_ALWAYS) {
        qemu_plugin_register_vcpu_insn_exec_cb(insn, cb, flags, udata);
        return;
    }
    plugin_register_dyn_cond_cb__udata(&insn->insn_cbs, cb, flags,
                                       cond, entry, imm, udata);
}

void qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
    struct qemu_plugin_insn *insn,
    enum qemu_plugin_op op,
    qemu_plugin_u64 entry,
    uint64_t imm)
{
    if (!tb_is_mem_only()) {
        plugin_register_inline_op_on_entry(&insn->insn_cbs, 0, op, entry, imm);
    }
}


/*
 * We always plant memory instrumentation because they don't finalise until
 * after the operation has complete.
 */
void qemu_plugin_register_vcpu_mem_cb(struct qemu_plugin_insn *insn,
                                      qemu_plugin_vcpu_mem_cb_t cb,
                                      enum qemu_plugin_cb_flags flags,
                                      enum qemu_plugin_mem_rw rw,
                                      void *udata)
{
    plugin_register_vcpu_mem_cb(&insn->mem_cbs, cb, flags, rw, udata);
}

void qemu_plugin_register_vcpu_mem_inline_per_vcpu(
    struct qemu_plugin_insn *insn,
    enum qemu_plugin_mem_rw rw,
    enum qemu_plugin_op op,
    qemu_plugin_u64 entry,
    uint64_t imm)
{
    plugin_register_inline_op_on_entry(&insn->mem_cbs, rw, op, entry, imm);
}

#include "hw/loader.h"

void armv7m_load_elf(CPUState *cs, const char *kernel_filename);
__attribute__((weak)) void armv7m_load_elf(CPUState *cs, const char *kernel_filename) {
    uint64_t entry;
    AddressSpace *as = cs ? cpu_get_address_space(cs, 0) : NULL;
    if (kernel_filename && as) {
        load_elf_ram_sym(kernel_filename, NULL, NULL, NULL,
                         &entry, NULL, NULL,
                         NULL, ELFDATA2LSB, EM_NONE, 1, 0, as, false, NULL);
    }
}

void qemu_plugin_load_elf(char * elf) {
	g_assert(current_cpu);
	armv7m_load_elf(current_cpu, elf);
}

void qemu_plugin_register_vcpu_tb_trans_cb(qemu_plugin_id_t id,
                                           qemu_plugin_vcpu_tb_trans_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_TB_TRANS, cb);
}

void qemu_plugin_register_vcpu_syscall_cb(qemu_plugin_id_t id,
                                          qemu_plugin_vcpu_syscall_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_SYSCALL, cb);
}

void
qemu_plugin_register_vcpu_syscall_ret_cb(qemu_plugin_id_t id,
                                         qemu_plugin_vcpu_syscall_ret_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_SYSCALL_RET, cb);
}

/*
 * Plugin Queries
 *
 * These are queries that the plugin can make to gauge information
 * from our opaque data types. We do not want to leak internal details
 * here just information useful to the plugin.
 */

/*
 * Translation block information:
 *
 * A plugin can query the virtual address of the start of the block
 * and the number of instructions in it. It can also get access to
 * each translated instruction.
 */

size_t qemu_plugin_tb_n_insns(const struct qemu_plugin_tb *tb)
{
    return tb->n;
}

uint64_t qemu_plugin_tb_vaddr(const struct qemu_plugin_tb *tb)
{
    const DisasContextBase *db = tcg_ctx->plugin_db;
    return db->pc_first;
}

struct qemu_plugin_insn *
qemu_plugin_tb_get_insn(const struct qemu_plugin_tb *tb, size_t idx)
{
    if (unlikely(idx >= tb->n)) {
        return NULL;
    }
    return g_ptr_array_index(tb->insns, idx);
}

extern void *gpa2hva(MemoryRegion **p_mr, hwaddr addr, uint64_t size, Error **errp);
unsigned long long  qemu_plugin_gpa2hva(unsigned long long  addr){
	Error *local_err = NULL;
    MemoryRegion *mr = NULL;
    void *ptr;

    ptr = gpa2hva(&mr, addr, 1, &local_err);
    return (unsigned long long) ptr;
}

/*
 * Instruction information
 *
 * These queries allow the plugin to retrieve information about each
 * instruction being translated.
 */

size_t qemu_plugin_insn_data(const struct qemu_plugin_insn *insn,
                             void *dest, size_t len)
{
    const DisasContextBase *db = tcg_ctx->plugin_db;

    len = MIN(len, insn->len);
    return translator_st(db, dest, insn->vaddr, len) ? len : 0;
}

size_t qemu_plugin_insn_size(const struct qemu_plugin_insn *insn)
{
    return insn->len;
}

uint64_t qemu_plugin_insn_vaddr(const struct qemu_plugin_insn *insn)
{
    return insn->vaddr;
}

void *qemu_plugin_insn_haddr(const struct qemu_plugin_insn *insn)
{
    const DisasContextBase *db = tcg_ctx->plugin_db;
    vaddr page0_last = db->pc_first | ~qemu_target_page_mask();

    if (db->fake_insn) {
        return NULL;
    }

    /*
     * ??? The return value is not intended for use of host memory,
     * but as a proxy for address space and physical address.
     * Thus we are only interested in the first byte and do not
     * care about spanning pages.
     */
    if (insn->vaddr <= page0_last) {
        if (db->host_addr[0] == NULL) {
            return NULL;
        }
        return db->host_addr[0] + insn->vaddr - db->pc_first;
    } else {
        if (db->host_addr[1] == NULL) {
            return NULL;
        }
        return db->host_addr[1] + insn->vaddr - (page0_last + 1);
    }
}

char *qemu_plugin_insn_disas(const struct qemu_plugin_insn *insn)
{
    return plugin_disas(tcg_ctx->cpu, tcg_ctx->plugin_db,
                        insn->vaddr, insn->len);
}

const char *qemu_plugin_insn_symbol(const struct qemu_plugin_insn *insn)
{
    const char *sym = lookup_symbol(insn->vaddr);
    return sym[0] != 0 ? sym : NULL;
}

/*
 * The memory queries allow the plugin to query information about a
 * memory access.
 */

unsigned qemu_plugin_mem_size_shift(qemu_plugin_meminfo_t info)
{
    MemOp op = get_memop(info);
    return op & MO_SIZE;
}

bool qemu_plugin_mem_is_sign_extended(qemu_plugin_meminfo_t info)
{
    MemOp op = get_memop(info);
    return op & MO_SIGN;
}

bool qemu_plugin_mem_is_big_endian(qemu_plugin_meminfo_t info)
{
    MemOp op = get_memop(info);
    return (op & MO_BSWAP) == MO_BE;
}

bool qemu_plugin_mem_is_store(qemu_plugin_meminfo_t info)
{
    return get_plugin_meminfo_rw(info) & QEMU_PLUGIN_MEM_W;
}

qemu_plugin_mem_value qemu_plugin_mem_get_value(qemu_plugin_meminfo_t info)
{
    uint64_t low = current_cpu->neg.plugin_mem_value_low;
    qemu_plugin_mem_value value;

    switch (qemu_plugin_mem_size_shift(info)) {
    case 0:
        value.type = QEMU_PLUGIN_MEM_VALUE_U8;
        value.data.u8 = (uint8_t)low;
        break;
    case 1:
        value.type = QEMU_PLUGIN_MEM_VALUE_U16;
        value.data.u16 = (uint16_t)low;
        break;
    case 2:
        value.type = QEMU_PLUGIN_MEM_VALUE_U32;
        value.data.u32 = (uint32_t)low;
        break;
    case 3:
        value.type = QEMU_PLUGIN_MEM_VALUE_U64;
        value.data.u64 = low;
        break;
    case 4:
        value.type = QEMU_PLUGIN_MEM_VALUE_U128;
        value.data.u128.low = low;
        value.data.u128.high = current_cpu->neg.plugin_mem_value_high;
        break;
    default:
        g_assert_not_reached();
    }
    return value;
}

int qemu_plugin_num_vcpus(void)
{
    return plugin_num_vcpus();
}

/*
 * Plugin output
 */
void qemu_plugin_outs(const char *string)
{
    qemu_log_mask(CPU_LOG_PLUGIN, "%s", string);
}

bool qemu_plugin_bool_parse(const char *name, const char *value, bool *ret)
{
    return name && value && qapi_bool_parse(name, value, ret, NULL);
}

/*
 * Create register handles.
 *
 * We need to create a handle for each register so the plugin
 * infrastructure can call gdbstub to read a register. They are
 * currently just a pointer encapsulation of the gdb_reg but in
 * future may hold internal plugin state so its important plugin
 * authors are not tempted to treat them as numbers.
 *
 * We also construct a result array with those handles and some
 * ancillary data the plugin might find useful.
 */

static GArray *create_register_handles(GArray *gdbstub_regs)
{
    GArray *find_data = g_array_new(true, true,
                                    sizeof(qemu_plugin_reg_descriptor));

    for (int i = 0; i < gdbstub_regs->len; i++) {
        GDBRegDesc *grd = &g_array_index(gdbstub_regs, GDBRegDesc, i);
        qemu_plugin_reg_descriptor desc;

        /* skip "un-named" regs */
        if (!grd->name) {
            continue;
        }

        /* Create a record for the plugin */
        desc.handle = GINT_TO_POINTER(grd->gdb_reg + 1);
        desc.name = g_intern_string(grd->name);
        desc.feature = g_intern_string(grd->feature_name);
        g_array_append_val(find_data, desc);
    }

    return find_data;
}

GArray *qemu_plugin_get_registers(void)
{
    g_autoptr(GArray) regs = gdb_get_register_list(first_cpu);
    return create_register_handles(regs);
}


int64_t qemu_plugin_get_virtual_timer(void) {
	return qemu_plugin_get_virtual_time_ns();
}

void raise_irq(CPUState *cs, int irq_num, int secure);
void __attribute__((weak)) raise_irq(CPUState *cs, int irq_num, int secure) {}
void qemu_plugin_raise_irq(int irq, int secure) {
	raise_irq(first_cpu, irq, secure); 
}

void pulse_irq(CPUState *cs, int irq_num);
void __attribute__((weak)) pulse_irq(CPUState *cs, int irq_num) {}
void qemu_plugin_pulse_irq(int irq) {
    pulse_irq(first_cpu, irq);  
}

void qemu_plugin_set_register(uint8_t *mem_buf, int reg)
{
    gdb_write_register(first_cpu, mem_buf, reg);
}

int qemu_plugin_write_memory(unsigned long long addr, uint8_t *mem_buf, int len)
{
	return gdb_target_memory_rw_debug(first_cpu, addr, mem_buf, len, true);
}

int qemu_plugin_read_memory(unsigned long long addr, uint8_t *mem_buf, int len)
{

    return gdb_target_memory_rw_debug(first_cpu, addr, mem_buf, len, false);
}


bool qemu_plugin_read_memory_vaddr(uint64_t addr, GByteArray *data, size_t len)
{

    if (len == 0) {
        return false;
    }

    g_byte_array_set_size(data, len);

    int result = cpu_memory_rw_debug(first_cpu, addr, data->data,
                                     data->len, false);

    if (result < 0) {
        return false;
    }

    return true;
}

int qemu_plugin_read_register(struct qemu_plugin_register *reg, GByteArray *buf)
{
    return gdb_read_register(first_cpu, buf, GPOINTER_TO_INT(reg) - 1);
}

struct qemu_plugin_scoreboard *qemu_plugin_scoreboard_new(size_t element_size)
{
    return plugin_scoreboard_new(element_size);
}

void qemu_plugin_scoreboard_free(struct qemu_plugin_scoreboard *score)
{
    plugin_scoreboard_free(score);
}

void *qemu_plugin_scoreboard_find(struct qemu_plugin_scoreboard *score,
                                  unsigned int vcpu_index)
{
    g_assert(vcpu_index < qemu_plugin_num_vcpus());
    /* we can't use g_array_index since entry size is not statically known */
    char *base_ptr = score->data->data;
    return base_ptr + vcpu_index * g_array_get_element_size(score->data);
}

static uint64_t *plugin_u64_address(qemu_plugin_u64 entry,
                                    unsigned int vcpu_index)
{
    char *ptr = qemu_plugin_scoreboard_find(entry.score, vcpu_index);
    return (uint64_t *)(ptr + entry.offset);
}

void qemu_plugin_u64_add(qemu_plugin_u64 entry, unsigned int vcpu_index,
                         uint64_t added)
{
    *plugin_u64_address(entry, vcpu_index) += added;
}

uint64_t qemu_plugin_u64_get(qemu_plugin_u64 entry,
                             unsigned int vcpu_index)
{
    return *plugin_u64_address(entry, vcpu_index);
}

void qemu_plugin_u64_set(qemu_plugin_u64 entry, unsigned int vcpu_index,
                         uint64_t val)
{
    *plugin_u64_address(entry, vcpu_index) = val;
}

uint64_t qemu_plugin_u64_sum(qemu_plugin_u64 entry)
{
    uint64_t total = 0;
    for (int i = 0, n = qemu_plugin_num_vcpus(); i < n; ++i) {
        total += qemu_plugin_u64_get(entry, i);
    }
    return total;
}
void qemu_plugin_irqret_hook(int irq_num);
void qemu_plugin_irqret_hook(int irq_num) {
	if (irq_finish_cb) {
			irq_finish_cb(irq_num);
	}
}
