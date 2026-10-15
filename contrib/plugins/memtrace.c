/*
 * Successful data-memory accesses as CSV, for user and system TCG.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * No TLB simulation, fault detection, address-space tracking, binary
 * output or timing model. PA need not identify a unique address space.
 * Sequence numbers describe cross-vCPU callback serialization, not
 * simulated hardware timing. Default memory output requires -d plugin/-D;
 * optional dedicated writers provide checked raw or lossless streaming XZ.
 */
#include <glib.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <qemu-plugin.h>
#include "memtrace-writer.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static GMutex trace_lock;
static uint64_t limit = 1000;
/* Immutable after installation; zero remains a numeric cap, not a sentinel. */
static bool unlimited;
static uint64_t sequence;
static GHashTable *pcs;
static bool marker_mode;
static FILE *events_file;
static const char *events_path;
static bool events_failed;
static uint64_t event_id;
static uint64_t interval_id;
static TraceWriter memory_writer, walks_writer;
static const char *memory_path;
static bool compression_xz;
static unsigned int compression_level = 3;
static bool output_failed;
static const char *walks_path;

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
    fprintf(stderr, "memtrace: events %s failed for '%s': %s; capture incomplete\n",
            operation, events_path, strerror(errno ? errno : EIO));
}

/* Caller holds trace_lock. A failed sink is diagnosed once and disabled;
 * callers permanently disable recording on failure; events are incomplete.
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

/* Caller holds trace_lock. Never advertise a successful boundary after failure.
 * ERROR is a terminal event with unchanged CSV columns. If events itself has
 * failed, stderr is the only reliable failure channel. Guest execution continues.
 */
static void output_error(unsigned int cpu, bool has_cpu)
{
    if (output_failed) {
        return;
    }
    output_failed = true;
    g_atomic_int_set(&recording, false);
    g_atomic_int_set(&exhausted, true);
    emit_event("ERROR", cpu, has_cpu);
}

static bool flush_outputs(unsigned int cpu, bool has_cpu)
{
    bool memory_ok = writer_boundary(&memory_writer);
    bool walks_ok = writer_boundary(&walks_writer);
    if (!memory_ok || !walks_ok || events_failed) {
        output_error(cpu, has_cpu);
        return false;
    }
    return true;
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
    if (!writer_write(&walks_writer, row->str, row->len)) {
        output_error(cpu, true);
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
        if (events_failed) {
            output_error(cpu, true);
        }
    }
    g_mutex_unlock(&trace_lock);
}

static void marker_end(unsigned int cpu, void *userdata)
{
    g_mutex_lock(&trace_lock);
    if (g_atomic_int_get(&recording)) {
        g_atomic_int_set(&recording, false);
        if (flush_outputs(cpu, true)) {
            emit_event("END", cpu, true);
            if (events_failed) {
                output_error(cpu, true);
            }
        }
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
    if (!g_atomic_int_get(&recording) || g_atomic_int_get(&exhausted)) {
        return;
    }
    g_mutex_lock(&trace_lock);
    if (!g_atomic_int_get(&recording) || g_atomic_int_get(&exhausted) ||
        (!unlimited && sequence == limit)) {
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
    if (memory_writer.file) {
        if (!writer_write(&memory_writer, record, strlen(record))) {
            output_error(cpu, true);
        }
    } else {
        qemu_plugin_outs(record);
    }
    if (walks_writer.file && !output_failed) {
        emit_walk(cpu, vaddr, hwaddr != NULL, callback_pa);
    }
    if (output_failed) {
        g_mutex_unlock(&trace_lock);
        return;
    }
    if (!unlimited && sequence == limit) {
        g_atomic_int_set(&recording, false);
        g_atomic_int_set(&exhausted, true);
        if (flush_outputs(cpu, true) && marker_mode) {
            /* The final access callback supplies the applicable vCPU ID. */
            emit_event("LIMIT", cpu, true);
            if (events_failed) {
                output_error(cpu, true);
            }
        }
    } else if (sequence == UINT64_MAX) {
        /* Never wrap the next sequence to zero. This representational failure
         * is not a configured LIMIT. Leave the interval active so its actual
         * END (or plugin EXIT) can close it, but permanently suppress accesses
         * and later BEGINs. The stderr diagnostic marks the capture incomplete.
         */
        g_atomic_int_set(&exhausted, true);
        flush_outputs(cpu, true);
        fprintf(stderr, "memtrace: access sequence counter exhausted at "
                "UINT64_MAX; further recording disabled; capture incomplete\n");
    }
    g_mutex_unlock(&trace_lock);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);

    if (g_atomic_int_get(&exhausted) && !marker_mode) {
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
        /* Even after counter exhaustion, instrument END so it can close an
         * unlimited interval. Numeric exhaustion already closed with LIMIT.
         */
        if (g_atomic_int_get(&exhausted)) {
            continue;
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
    bool was_active = g_atomic_int_get(&recording);
    flush_outputs(0, false);
    bool memory_ok = writer_close(&memory_writer);
    bool walks_ok = writer_close(&walks_writer);
    if (!memory_ok || !walks_ok) {
        output_error(0, false);
    }
    if (marker_mode && was_active && !output_failed) {
        g_atomic_int_set(&recording, false);
        emit_event("EXIT", 0, false);
    }
    if (events_file) {
        errno = 0;
        if (fclose(events_file) != 0) {
            events_error("close");
            events_failed = true;
        }
        events_file = NULL;
    }
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
    bool seen_compression = false;
    bool seen_level = false;

    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i];
        uint64_t value = 0;

        if (g_str_has_prefix(arg, "memory=")) {
            if (memory_path || arg[7] != '/') {
                goto invalid;
            }
            memory_path = arg + 7;
            continue;
        }
        if (g_str_has_prefix(arg, "compression=")) {
            if (seen_compression) {
                goto invalid;
            }
            if (!strcmp(arg + 12, "xz")) {
                compression_xz = true;
            } else if (strcmp(arg + 12, "none")) {
                goto invalid;
            }
            seen_compression = true;
            continue;
        }
        if (g_str_has_prefix(arg, "compression-level=")) {
            if (seen_level || strlen(arg + 18) != 1 ||
                arg[18] < '0' || arg[18] > '9') {
                goto invalid;
            }
            compression_level = arg[18] - '0';
            seen_level = true;
            continue;
        }
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
        if (strcmp(arg + 6, "unlimited") == 0) {
            unlimited = true;
            seen_limit = true;
            continue;
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
                "limit=unlimited or limit=N (unsigned decimal 0..%" PRIu64 ") or "
                "roi=immediate|markers, events=PATH, memory=/ABSOLUTE/PATH, "
                "walks=/ABSOLUTE/PATH, compression=none|xz, compression-level=0..9; "
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

    if ((compression_xz && !memory_path) || (seen_level && !compression_xz)) {
        fprintf(stderr, "memtrace: xz requires memory=/ABSOLUTE/PATH; "
                "compression-level requires compression=xz\n");
        return -1;
    }
    /* Validate all options before exclusively creating new files. O_EXCL
     * rejects aliases/hardlinks to any existing output, input or QEMU log.
     * If two new output names alias, the second creation fails, without
     * truncating the first. Failed installation leaves identifiable partials.
     */
    if (events_path) {
        events_file = trace_create(events_path);
        if (!events_file) {
            events_error("open");
            return -1;
        }
        errno = 0;
        if (fputs("event_id,interval_id,event,cpu,access_sequence\n",
                  events_file) == EOF || fflush(events_file) != 0) {
            events_error("header write/flush");
            goto install_failed;
        }
    }
    if (memory_path) {
        if (!writer_open(&memory_writer, "memory", memory_path,
                         compression_xz, compression_level)) {
            goto install_failed;
        }
    }
    if (walks_path) {
        if (!writer_open(&walks_writer, "walks", walks_path,
                         compression_xz, compression_level) ||
            !writer_write(&walks_writer,
                "sequence,cpu,data_va,cr3,root_pa,cr0,cr4,efer,phys_bits,"
                "status,leaf_size,reconstructed_pa,callback_pa,comparison,pte_path\n",
                strlen("sequence,cpu,data_va,cr3,root_pa,cr0,cr4,efer,phys_bits,"
                "status,leaf_size,reconstructed_pa,callback_pa,comparison,pte_path\n")) ||
            !writer_boundary(&walks_writer)) {
            goto install_failed;
        }
    }
    const char *header = "sequence,cpu,pc_va,data_va,data_pa,size_bytes,"
                         "operation,memory_type\n";
    if (memory_path) {
        if (!writer_write(&memory_writer, header, strlen(header)) ||
            !writer_boundary(&memory_writer)) {
            goto install_failed;
        }
    } else {
        qemu_plugin_outs(header);
    }

    g_mutex_init(&trace_lock);
    pcs = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);
    g_atomic_int_set(&recording, !marker_mode && (unlimited || limit != 0));
    g_atomic_int_set(&exhausted, !unlimited && limit == 0);

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;

install_failed:
    writer_close(&walks_writer);
    writer_close(&memory_writer);
    if (events_file) {
        if (fclose(events_file) != 0) {
            events_error("close");
        }
        events_file = NULL;
    }
    return -1;
}
