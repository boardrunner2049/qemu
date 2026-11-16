/*
 * QMP commands related to QOM
 *
 * Copyright IBM, Corp. 2011
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "block/qdict.h"
#include "hw/qdev-core.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-qdev.h"
#include "qapi/qapi-commands-qom.h"
#include "qapi/qapi-visit-qom.h"
#include "qobject/qdict.h"
#include "qapi/qmp/qerror.h"
#include "qapi/qobject-input-visitor.h"
#include "qapi/qobject-output-visitor.h"
#include "qemu/cutils.h"
#include "qemu/timer.h"
#include "qom/object_interfaces.h"
#include "qom/qom-qobject.h"
#include "system/runstate.h"
#include "migration/vmstate.h"

static Object *qom_resolve_path(const char *path, Error **errp)
{
    bool ambiguous = false;
    Object *obj = object_resolve_path(path, &ambiguous);

    if (obj == NULL) {
        if (ambiguous) {
            error_setg(errp, "Path '%s' is ambiguous", path);
        } else {
            error_set(errp, ERROR_CLASS_DEVICE_NOT_FOUND,
                      "Device '%s' not found", path);
        }
    }
    return obj;
}

typedef struct BudgetControl {
    QemuCond cond;
    QemuMutex lock;
    uint64_t total_budget;
    int budget_init;
    QEMUTimer budget_timer;
    QEMUTimerCB * cb;
	RunState vm_old_state;
	bool exact_stop;
} BudgetControl;

extern void budget_exhausted(void *);
extern uint64_t budget_current_time_ns(void);
extern void budget_set_exact_stop(bool exact);
extern bool budget_get_exact_stop(void);
BudgetControl bc_tcb;
static int bc_tcb_post_load(void *opaque, int version_id)
{
    BudgetControl *ctrl = opaque;

    qemu_cond_init(&ctrl->cond);
    qemu_mutex_init(&ctrl->lock);

   	ctrl->cb = budget_exhausted;

    return 0;
}

static int bc_tcb_pre_load(void *opaque)
{
	timer_init_ns(&bc_tcb.budget_timer, QEMU_CLOCK_VIRTUAL, budget_exhausted, &bc_tcb);

    return 0;
}

static const VMStateDescription vmstate_budget_control = {
    .name = "budget_control",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_load = bc_tcb_pre_load,
    .post_load = bc_tcb_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_UINT64(total_budget, BudgetControl),
        VMSTATE_INT32(budget_init, BudgetControl),
        VMSTATE_U32(vm_old_state, BudgetControl),
		VMSTATE_TIMER(budget_timer, BudgetControl),
        VMSTATE_END_OF_LIST()
    }
};


void plugin_vmstate_budget(void);
void plugin_vmstate_budget(void) {
	vmstate_register(NULL, 0, &vmstate_budget_control, &bc_tcb);
}
void init_budget_system(void);
void init_budget_system(void) {
		qemu_mutex_init(&bc_tcb.lock);
        qemu_cond_init(&bc_tcb.cond);
        bc_tcb.cb = budget_exhausted;
        timer_init_ns(&bc_tcb.budget_timer, QEMU_CLOCK_VIRTUAL, budget_exhausted, &bc_tcb);
        bc_tcb.budget_init = 1;
        //TODO: Hack read from snaphot maybe.
        bc_tcb.vm_old_state = RUN_STATE_RUNNING;

}

/*
 * run-for arrives on the main loop thread while qemu_plugin_wait_for_budget()
 * runs on a vCPU thread, so a plain `if (!budget_init) init()` could run the
 * initializer twice and leave two threads with different mutexes.  g_once
 * makes first use safe from either side.
 */
void budget_system_ensure_init(void);
void budget_system_ensure_init(void) {
	static gsize initialized;

	if (g_once_init_enter(&initialized)) {
		init_budget_system();
		g_once_init_leave(&initialized, 1);
	}
}

Budget *qmp_run_for(uint64_t budget, Error **errp) {
	Budget * total;

	budget_system_ensure_init();

	total = g_new0(Budget, 1);
	qemu_mutex_lock(&bc_tcb.lock);
	bc_tcb.total_budget += budget;
	qemu_mutex_unlock(&bc_tcb.lock);

	/*
	 * bc_tcb.cb() takes the same lock, so it must be called unlocked. Re-take
	 * the lock afterwards: the callback may have snapped total_budget forward
	 * to absorb guest overshoot, and an unlocked read could tear or observe a
	 * stale value.
	 */
	bc_tcb.cb(&bc_tcb);

	qemu_mutex_lock(&bc_tcb.lock);
	total->totalbudget = bc_tcb.total_budget;
	total->currenttime = budget_current_time_ns();
	total->exact = bc_tcb.exact_stop;
	qemu_mutex_unlock(&bc_tcb.lock);

	return total;
}

Budget *qmp_query_budget(Error **errp) {
	Budget * state;

	budget_system_ensure_init();

	state = g_new0(Budget, 1);
	qemu_mutex_lock(&bc_tcb.lock);
	state->totalbudget = bc_tcb.total_budget;
	state->currenttime = budget_current_time_ns();
	state->exact = bc_tcb.exact_stop;
	qemu_mutex_unlock(&bc_tcb.lock);

	return state;
}

Budget *qmp_set_budget_mode(bool exact, Error **errp) {
	budget_system_ensure_init();
	budget_set_exact_stop(exact);
	return qmp_query_budget(errp);
}

ObjectPropertyInfoList *qmp_qom_list(const char *path, Error **errp)
{
    Object *obj;
    ObjectPropertyInfoList *props = NULL;
    ObjectProperty *prop;
    ObjectPropertyIterator iter;

    obj = qom_resolve_path(path, errp);
    if (obj == NULL) {
        return NULL;
    }

    object_property_iter_init(&iter, obj);
    while ((prop = object_property_iter_next(&iter))) {
        ObjectPropertyInfo *value = g_new0(ObjectPropertyInfo, 1);

        QAPI_LIST_PREPEND(props, value);

        value->name = g_strdup(prop->name);
        value->type = g_strdup(prop->type);
    }

    return props;
}

void qmp_qom_set(const char *path, const char *property, QObject *value,
                 Error **errp)
{
    Object *obj;

    obj = object_resolve_path(path, NULL);
    if (!obj) {
        error_set(errp, ERROR_CLASS_DEVICE_NOT_FOUND,
                  "Device '%s' not found", path);
        return;
    }

    object_property_set_qobject(obj, property, value, errp);
}

QObject *qmp_qom_get(const char *path, const char *property, Error **errp)
{
    Object *obj;

    obj = object_resolve_path(path, NULL);
    if (!obj) {
        error_set(errp, ERROR_CLASS_DEVICE_NOT_FOUND,
                  "Device '%s' not found", path);
        return NULL;
    }

    return object_property_get_qobject(obj, property, errp);
}

static void qom_list_types_tramp(ObjectClass *klass, void *data)
{
    ObjectTypeInfoList **pret = data;
    ObjectTypeInfo *info;
    ObjectClass *parent = object_class_get_parent(klass);

    info = g_malloc0(sizeof(*info));
    info->name = g_strdup(object_class_get_name(klass));
    info->has_abstract = info->abstract = object_class_is_abstract(klass);
    if (parent) {
        info->parent = g_strdup(object_class_get_name(parent));
    }

    QAPI_LIST_PREPEND(*pret, info);
}

ObjectTypeInfoList *qmp_qom_list_types(const char *implements,
                                       bool has_abstract,
                                       bool abstract,
                                       Error **errp)
{
    ObjectTypeInfoList *ret = NULL;

    module_load_qom_all();
    object_class_foreach(qom_list_types_tramp, implements, abstract, &ret);

    return ret;
}

ObjectPropertyInfoList *qmp_device_list_properties(const char *typename,
                                                Error **errp)
{
    ObjectClass *klass;
    Object *obj;
    ObjectProperty *prop;
    ObjectPropertyIterator iter;
    ObjectPropertyInfoList *prop_list = NULL;

    klass = module_object_class_by_name(typename);
    if (klass == NULL) {
        error_set(errp, ERROR_CLASS_DEVICE_NOT_FOUND,
                  "Device '%s' not found", typename);
        return NULL;
    }

    if (!object_class_dynamic_cast(klass, TYPE_DEVICE)
        || object_class_is_abstract(klass)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "typename",
                   "a non-abstract device type");
        return NULL;
    }

    obj = object_new_with_class(klass);

    object_property_iter_init(&iter, obj);
    while ((prop = object_property_iter_next(&iter))) {
        ObjectPropertyInfo *info;

        /* Skip Object and DeviceState properties */
        if (strcmp(prop->name, "type") == 0 ||
            strcmp(prop->name, "realized") == 0 ||
            strcmp(prop->name, "hotpluggable") == 0 ||
            strcmp(prop->name, "hotplugged") == 0 ||
            strcmp(prop->name, "parent_bus") == 0) {
            continue;
        }

        /* Skip legacy properties since they are just string versions of
         * properties that we already list.
         */
        if (strstart(prop->name, "legacy-", NULL)) {
            continue;
        }

        info = g_new0(ObjectPropertyInfo, 1);
        info->name = g_strdup(prop->name);
        info->type = g_strdup(prop->type);
        info->description = g_strdup(prop->description);
        info->default_value = qobject_ref(prop->defval);

        QAPI_LIST_PREPEND(prop_list, info);
    }

    object_unref(obj);

    return prop_list;
}

ObjectPropertyInfoList *qmp_qom_list_properties(const char *typename,
                                             Error **errp)
{
    ObjectClass *klass;
    Object *obj = NULL;
    ObjectProperty *prop;
    ObjectPropertyIterator iter;
    ObjectPropertyInfoList *prop_list = NULL;

    klass = module_object_class_by_name(typename);
    if (klass == NULL) {
        error_set(errp, ERROR_CLASS_DEVICE_NOT_FOUND,
                  "Class '%s' not found", typename);
        return NULL;
    }

    if (!object_class_dynamic_cast(klass, TYPE_OBJECT)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "typename",
                   "a QOM type");
        return NULL;
    }

    if (object_class_is_abstract(klass)) {
        object_class_property_iter_init(&iter, klass);
    } else {
        obj = object_new(typename);
        object_property_iter_init(&iter, obj);
    }
    while ((prop = object_property_iter_next(&iter))) {
        ObjectPropertyInfo *info;

        info = g_malloc0(sizeof(*info));
        info->name = g_strdup(prop->name);
        info->type = g_strdup(prop->type);
        info->description = g_strdup(prop->description);
        info->default_value = qobject_ref(prop->defval);

        QAPI_LIST_PREPEND(prop_list, info);
    }

    object_unref(obj);

    return prop_list;
}

void qmp_object_add(ObjectOptions *options, Error **errp)
{
    user_creatable_add_qapi(options, errp);
}

void qmp_object_del(const char *id, Error **errp)
{
    user_creatable_del(id, errp);
}
