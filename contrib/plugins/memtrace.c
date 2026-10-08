/*
 * Successful data-memory accesses as CSV, for user and system TCG.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * No TLB simulation, fault detection, address-space tracking, binary
 * output or timing model. PA need not identify a unique address space.
 * Sequence numbers describe cross-vCPU callback serialization, not
 * simulated hardware timing. Output requires QEMU's -d plugin (and -D).
 */
#include <glib.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static GMutex trace_lock;
static uint64_t limit = 1000;
static uint64_t sequence;
static GHashTable *pcs;
static bool marker_mode;
static FILE *events_file;
static const char *events_path;
static bool events_failed;
static uint64_t event_id;
static uint64_t interval_id;
static FILE *walks_file;
static const char *walks_path;
static bool walks_failed;
static char *walks_buffer;
/* Access these flags only through GLib atomics, including under the lock. */
static gint recording;
static gint exhausted;
static const unsigned char begin_marker[8] = {
    0x0f, 0x1f, 0x84, 0x00, 0x56, 0x57, 0x42, 0x47
};
static const unsigned char end_marker[8] = {
    0x0f, 0x1f, 0x84, 0x00, 0x56, 0x57, 0x45, 0x4e
};

static void events_error(const char *operation)
{
    fprintf(stderr, "memtrace: events %s failed for '%s': %s\n",
            operation, events_path, strerror(errno ? errno : EIO));
}

/* Caller holds trace_lock. A failed sink is diagnosed once and disabled;
 * guest execution and memory recording continue, but events are incomplete.
 */
static void emit_event(const char *event, unsigned int cpu, bool has_cpu)
{
    char cpu_field[16] = "NA";

    if (!events_file || events_failed) {
        return;
    }
    if (has_cpu) {
        snprintf(cpu_field, sizeof(cpu_field), "%u", cpu);
    }
    errno = 0;
    if (fprintf(events_file, "%" PRIu64 ",%" PRIu64 ",%s,%s,%" PRIu64 "\n",
                ++event_id, interval_id, event, cpu_field, sequence) < 0 ||
        fflush(events_file) != 0) {
        events_error("write/flush");
        events_failed = true;
    }
}

static void walks_error(const char *operation)
{
    fprintf(stderr, "memtrace: walks %s failed for '%s': %s\n",
            operation, walks_path, strerror(errno ? errno : EIO));
    walks_failed = true;
}

/* Caller holds trace_lock. Never retry a diagnosed stream failure. */
static void flush_walks(void)
{
    if (walks_file && !walks_failed) {
        errno = 0;
        if (fflush(walks_file) != 0) {
            walks_error("flush");
        }
    }
}

static const char *walk_status(enum qemu_plugin_x86_walk_status status)
{
    static const char *const names[] = {
        "OK", "UNAVAILABLE", "UNSUPPORTED_MODE", "UNSUPPORTED_LA57",
        "UNSUPPORTED_NESTED", "UNSUPPORTED_A20", "UNSUPPORTED_PHYS_BITS",
        "NONCANONICAL", "NONPRESENT", "RESERVED_CR3", "RESERVED_ENTRY",
        "NOT_RAM", "READ_FAILED",
    };
    return (unsigned int)status < G_N_ELEMENTS(names) ? names[status] : "UNKNOWN";
}

/* Called only for an emitted access, under trace_lock. The copied snapshot
 * observes current tables after success, not the original faulting attempt.
 * A fresh walk may differ from a stale TLB or concurrently edited tables;
 * retain the mismatch, never replace callback PA with reconstructed PA.
 */
static void emit_walk(unsigned int cpu, uint64_t va, bool has_pa, uint64_t pa)
{
    struct qemu_plugin_x86_walk walk = {
        .status = QEMU_PLUGIN_X86_WALK_UNAVAILABLE,
    };
    bool captured = qemu_plugin_x86_paging_walk(cpu, va, &walk);
    bool ok = captured && walk.status == QEMU_PLUGIN_X86_WALK_OK;
    GString *row = g_string_new(NULL);

    if (!captured) {
        walk.status = QEMU_PLUGIN_X86_WALK_UNAVAILABLE;
        walk.n_entries = 0;
    }

    g_string_append_printf(row, "%" PRIu64 ",%u,0x%" PRIx64 ",",
                           sequence, cpu, va);
    if (captured) {
        struct qemu_plugin_x86_paging *s = &walk.paging;
        g_string_append_printf(row,
            "0x%" PRIx64 ",0x%" PRIx64 ",0x%" PRIx64
            ",0x%" PRIx64 ",0x%" PRIx64 ",%u,",
            s->cr3, s->root_pa, s->cr0, s->cr4, s->efer, s->phys_bits);
    } else {
        g_string_append(row, "NA,NA,NA,NA,NA,NA,");
    }
    g_string_append_printf(row, "%s,", walk_status(walk.status));
    if (ok) {
        g_string_append_printf(row, "%" PRIu64 ",0x%" PRIx64 ",",
                               walk.leaf_size, walk.pa);
    } else {
        g_string_append(row, "NA,NA,");
    }
    if (has_pa) {
        g_string_append_printf(row, "0x%" PRIx64 ",", pa);
    } else {
        g_string_append(row, "NA,");
    }
    g_string_append_printf(row, "%s,\"",
        !ok || !has_pa ? "not-comparable" : walk.pa == pa ? "match" : "mismatch");
    /* CSV quoted field; grammar contains only numeric hex tokens and ':'/';',
     * so embedded quotes/newlines cannot occur. Entry order is architectural.
     */
    for (unsigned int i = 0; i < walk.n_entries; i++) {
        const struct qemu_plugin_x86_pte *pte = &walk.entries[i];
        g_string_append_printf(row, "%s%u:0x%" PRIx64 ":0x%" PRIx64,
                               i ? ";" : "", pte->level,
                               pte->entry_pa, pte->value);
    }
    g_string_append(row, "\"\n");
    errno = 0;
    if (fputs(row->str, walks_file) == EOF) {
        walks_error("write");
    }
    g_string_free(row, true);
}

static void marker_begin(unsigned int cpu, void *userdata)
{
    /* Any guest executing the bytes can toggle this global interval,
     * including kernel and other processes. Ordering is lock serialization.
     */
    g_mutex_lock(&trace_lock);
    if (!g_atomic_int_get(&recording) &&
        !g_atomic_int_get(&exhausted)) {
        interval_id++;
        g_atomic_int_set(&recording, true);
        emit_event("BEGIN", cpu, true);
    }
    g_mutex_unlock(&trace_lock);
}

static void marker_end(unsigned int cpu, void *userdata)
{
    g_mutex_lock(&trace_lock);
    if (g_atomic_int_get(&recording)) {
        g_atomic_int_set(&recording, false);
        flush_walks();
        emit_event("END", cpu, true);
    }
    g_mutex_unlock(&trace_lock);
}

static void vcpu_mem(unsigned int cpu, qemu_plugin_meminfo_t info,
                     uint64_t vaddr, void *userdata)
{
    const uint64_t *pc = userdata;
    struct qemu_plugin_hwaddr *hwaddr;
    const char *memory_type = "UNKNOWN";
    char pa[32] = "NA";
    char record[256];
    uint64_t callback_pa = 0;

    /* QEMU invokes memory callbacks after successful loads/stores only. */
    if (!g_atomic_int_get(&recording)) {
        return;
    }
    g_mutex_lock(&trace_lock);
    if (!g_atomic_int_get(&recording) || sequence == limit) {
        g_mutex_unlock(&trace_lock);
        return;
    }

    /* This temporary handle must be queried here, never retained. */
    hwaddr = qemu_plugin_get_hwaddr(info, vaddr);
    if (hwaddr) {
        callback_pa = qemu_plugin_hwaddr_phys_addr(hwaddr);
        snprintf(pa, sizeof(pa), "0x%" PRIx64,
                 callback_pa);
        memory_type = qemu_plugin_hwaddr_is_io(hwaddr) ? "MMIO" : "RAM";
    }
    snprintf(record, sizeof(record),
             "%" PRIu64 ",%u,0x%" PRIx64 ",0x%" PRIx64
             ",%s,%" PRIu64 ",%c,%s\n",
             ++sequence, cpu, *pc, vaddr, pa,
             UINT64_C(1) << qemu_plugin_mem_size_shift(info),
             qemu_plugin_mem_is_store(info) ? 'W' : 'R', memory_type);
    /* Keep allocation of numbers and whole-record output in one lock. */
    qemu_plugin_outs(record);
    if (walks_file && !walks_failed) {
        emit_walk(cpu, vaddr, hwaddr != NULL, callback_pa);
    }
    if (sequence == limit) {
        g_atomic_int_set(&recording, false);
        g_atomic_int_set(&exhausted, true);
        flush_walks();
        if (marker_mode) {
            /* The final access callback supplies the applicable vCPU ID. */
            emit_event("LIMIT", cpu, true);
        }
    }
    g_mutex_unlock(&trace_lock);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);

    if (g_atomic_int_get(&exhausted)) {
        return;
    }
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t addr;
        uint64_t *pc;

        if (marker_mode && qemu_plugin_insn_size(insn) == 8) {
            const void *bytes = qemu_plugin_insn_data(insn);
            qemu_plugin_vcpu_udata_cb_t cb = NULL;

            if (memcmp(bytes, begin_marker, sizeof(begin_marker)) == 0) {
                cb = marker_begin;
            } else if (memcmp(bytes, end_marker, sizeof(end_marker)) == 0) {
                cb = marker_end;
            }
            if (cb) {
                qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, cb, QEMU_PLUGIN_CB_NO_REGS, NULL);
                continue;
            }
        }
        addr = qemu_plugin_insn_vaddr(insn);
        g_mutex_lock(&trace_lock);
        pc = g_hash_table_lookup(pcs, &addr);

        /*
         * Instruction handles expire after translation. Copy just the VA
         * into stable heap storage, shared by translations of the same PC.
         * QEMU 8.2 has no per-insn userdata destructor: retain these immutable
         * values across TB invalidation/flush until atexit, when execution
         * callbacks have finished. Never free metadata upon reaching limit:
         * already translated code can still invoke callbacks with it.
         */
        if (!pc) {
            pc = g_new(uint64_t, 1);
            *pc = addr;
            g_hash_table_insert(pcs, pc, pc);
        }
        g_mutex_unlock(&trace_lock);
        /* Never hold our output lock while registering QEMU callbacks. */
        qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_RW, pc);
    }
}

static void plugin_exit(qemu_plugin_id_t id, void *userdata)
{
    g_mutex_lock(&trace_lock);
    /* Also flush immediate mode and intervals already closed by END/LIMIT. */
    flush_walks();
    if (marker_mode && g_atomic_int_get(&recording)) {
        g_atomic_int_set(&recording, false);
        emit_event("EXIT", 0, false);
    }
    if (events_file) {
        errno = 0;
        if (fclose(events_file) != 0) {
            events_error("close");
        }
        events_file = NULL;
    }
    if (walks_file) {
        errno = 0;
        if (fclose(walks_file) != 0) {
            walks_error("close");
        }
        walks_file = NULL;
    }
    g_clear_pointer(&walks_buffer, g_free);
    g_mutex_unlock(&trace_lock);
    /* The table owns keys; values alias keys and must not be freed twice. */
    g_hash_table_destroy(pcs);
    g_mutex_clear(&trace_lock);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                         const qemu_info_t *info,
                                         int argc, char **argv)
{
    bool seen_limit = false;
    bool seen_roi = false;

    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i];
        uint64_t value = 0;

        if (g_str_has_prefix(arg, "walks=")) {
            if (walks_path || arg[6] != '/') {
                goto invalid;
            }
            walks_path = arg + 6;
            continue;
        }
        if (g_str_has_prefix(arg, "events=")) {
            if (events_path || !arg[7]) {
                goto invalid;
            }
            events_path = arg + 7;
            continue;
        }
        if (g_str_has_prefix(arg, "roi=")) {
            if (seen_roi) {
                goto invalid;
            }
            if (strcmp(arg + 4, "markers") == 0) {
                marker_mode = true;
            } else if (strcmp(arg + 4, "immediate") != 0) {
                goto invalid;
            }
            seen_roi = true;
            continue;
        }
        if (seen_limit || !g_str_has_prefix(arg, "limit=") || !arg[6]) {
            goto invalid;
        }
        for (const char *p = arg + 6; *p; p++) {
            if (*p < '0' || *p > '9' ||
                value > (UINT64_MAX - (*p - '0')) / 10) {
                goto invalid;
            }
            value = value * 10 + (*p - '0');
        }
        limit = value;
        seen_limit = true;
        continue;

invalid:
        fprintf(stderr, "memtrace: invalid argument '%s'; expected "
                "limit=N (unsigned decimal 0..%" PRIu64 ") or "
                "roi=immediate|markers, events=PATH or walks=/ABSOLUTE/PATH; "
                "each option at most once\n",
                arg, UINT64_MAX);
        return -1;
    }

    if (marker_mode && strcmp(info->target_name, "x86_64") != 0) {
        fprintf(stderr, "memtrace: roi=markers requires an x86_64 guest "
                "(got %s)\n", info->target_name);
        return -1;
    }
    if (walks_path && (!info->system_emulation ||
                       strcmp(info->target_name, "x86_64") != 0)) {
        fprintf(stderr, "memtrace: walks requires full-system x86_64 TCG\n");
        return -1;
    }
    if (walks_path && events_path && strcmp(walks_path, events_path) == 0) {
        fprintf(stderr, "memtrace: walks and events must use separate files\n");
        return -1;
    }

    /* Parse and validate everything before opening a file or registering
     * callbacks. argv strings remain valid for the plugin lifetime in 8.2.
     */
    if (events_path) {
        events_file = fopen(events_path, "w");
        if (!events_file) {
            events_error("open");
            return -1;
        }
        errno = 0;
        if (fputs("event_id,interval_id,event,cpu,access_sequence\n",
                  events_file) == EOF || fflush(events_file) != 0) {
            events_error("header write/flush");
            if (fclose(events_file) != 0) {
                events_error("close");
            }
            events_file = NULL;
            return -1;
        }
    }
    if (walks_path) {
        walks_file = fopen(walks_path, "w");
        if (!walks_file) {
            walks_error("open");
            goto install_failed;
        }
        /* Supply storage explicitly: setvbuf(NULL, ...) need not allocate
         * the requested size on every libc. Keep it live through fclose.
         */
        walks_buffer = g_malloc(1024 * 1024);
        errno = 0;
        if (setvbuf(walks_file, walks_buffer, _IOFBF, 1024 * 1024) != 0) {
            walks_error("buffer configuration");
            goto install_failed;
        }
        errno = 0;
        if (fputs("sequence,cpu,data_va,cr3,root_pa,cr0,cr4,efer,phys_bits,"
                  "status,leaf_size,reconstructed_pa,callback_pa,comparison,"
                  "pte_path\n", walks_file) == EOF || fflush(walks_file) != 0) {
            walks_error("header write/flush");
            goto install_failed;
        }
    }

    g_mutex_init(&trace_lock);
    pcs = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);
    g_atomic_int_set(&recording, !marker_mode && limit != 0);
    g_atomic_int_set(&exhausted, limit == 0);
    qemu_plugin_outs("sequence,cpu,pc_va,data_va,data_pa,size_bytes,"
                     "operation,memory_type\n");
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;

install_failed:
    if (walks_file) {
        if (fclose(walks_file) != 0) {
            walks_error("close");
        }
        walks_file = NULL;
    }
    g_clear_pointer(&walks_buffer, g_free);
    if (events_file) {
        if (fclose(events_file) != 0) {
            events_error("close");
        }
        events_file = NULL;
    }
    return -1;
}
