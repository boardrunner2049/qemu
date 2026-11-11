/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2020 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu-main.h"
#include "qemu/main-loop.h"
#include "system/replay.h"
#include "system/system.h"

#ifdef CONFIG_LINUX
#include <sys/personality.h>
#endif

#ifdef CONFIG_SDL
/*
 * SDL insists on wrapping the main() function with its own implementation on
 * some platforms; it does so via a macro that renames our main function, so
 * <SDL.h> must be #included here even with no SDL code called from this file.
 */
#include <SDL.h>
#endif

#ifdef CONFIG_DARWIN
#include <CoreFoundation/CoreFoundation.h>
#endif

static void *qemu_default_main(void *opaque)
{
    int status;

    replay_mutex_lock();
    bql_lock();
    status = qemu_main_loop();
    qemu_cleanup(status);
    bql_unlock();
    replay_mutex_unlock();

    exit(status);
}

int (*qemu_main)(void);

static bool qemu_accel_has_supercache(const char *arg)
{
    const char *option = arg;

    while ((option = strstr(option, "supercache="))) {
        if (option == arg || option[-1] == ',') {
            return true;
        }
        option++;
    }
    return false;
}

/*
 * Native TCG code contains absolute addresses into QEMU and its plugins.
 * Supercache deliberately does not change the process personality or re-exec:
 * callers must opt in to stable addresses before starting QEMU.
 */
static void qemu_supercache_check_aslr(int argc, char **argv)
{
#ifdef CONFIG_LINUX
    bool requested = false;
    int persona;

    for (int i = 1; i < argc; i++) {
        const char *accel = NULL;

        if (!strcmp(argv[i], "-accel") && i + 1 < argc) {
            accel = argv[++i];
        } else if (g_str_has_prefix(argv[i], "-accel=")) {
            accel = argv[i] + strlen("-accel=");
        }
        if (accel && qemu_accel_has_supercache(accel)) {
            requested = true;
            break;
        }
    }
    if (!requested) {
        return;
    }

    persona = personality(0xffffffffUL);
    if (persona < 0) {
        perror("supercache: personality");
        exit(EXIT_FAILURE);
    }
    if (persona & ADDR_NO_RANDOMIZE) {
        return;
    }
    fprintf(stderr,
            "supercache requires QEMU to be started with ASLR disabled; "
            "run it as:\n  setarch $(uname -m) -R %s ...\n",
            argv[0]);
    exit(EXIT_FAILURE);
#else
    for (int i = 1; i < argc; i++) {
        const char *accel = NULL;

        if (!strcmp(argv[i], "-accel") && i + 1 < argc) {
            accel = argv[++i];
        } else if (g_str_has_prefix(argv[i], "-accel=")) {
            accel = argv[i] + strlen("-accel=");
        }
        if (accel && qemu_accel_has_supercache(accel)) {
            fprintf(stderr, "supercache is supported only on Linux\n");
            exit(EXIT_FAILURE);
        }
    }
#endif
}

#ifdef CONFIG_DARWIN
static int os_darwin_cfrunloop_main(void)
{
    CFRunLoopRun();
    g_assert_not_reached();
}
int (*qemu_main)(void) = os_darwin_cfrunloop_main;
#endif
int main(int argc, char **argv)
{
    qemu_supercache_check_aslr(argc, argv);
    qemu_host_clock_start();
    qemu_init(argc, argv);

    /*
     * qemu_init acquires the BQL and replay mutex lock. BQL is acquired when
     * initializing cpus, to block associated threads until initialization is
     * complete. Replay_mutex lock is acquired on initialization, because it
     * must be held when configuring icount_mode.
     *
     * On MacOS, qemu main event loop runs in a background thread, as main
     * thread must be reserved for UI. Thus, we need to transfer lock ownership,
     * and the simplest way to do that is to release them, and reacquire them
     * from qemu_default_main.
     */
    bql_unlock();
    replay_mutex_unlock();

    if (qemu_main) {
        QemuThread main_loop_thread;
        qemu_thread_create(&main_loop_thread, "qemu_main",
                           qemu_default_main, NULL, QEMU_THREAD_DETACHED);
        return qemu_main();
    } else {
        qemu_default_main(NULL);
        g_assert_not_reached();
    }
}
