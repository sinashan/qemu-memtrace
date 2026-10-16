/*
 * Successful data-memory accesses as CSV, for user and system TCG.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * CSV and experimental inline binary capture. No TLB simulation, fault
 * detection, address-space tracking or timing model. PA need not identify a unique address space.
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
#include "memtrace-binary.h"

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
static bool binary_mode, test_dual;
static const char *binary_path;
static size_t binary_chunk = 4 * 1024 * 1024;
static TraceBinary binary_sink;
static unsigned binary_status = 5; /* EMPTY; footer written only at plugin exit. */

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
    unsigned kind = !strcmp(event,"BEGIN") ? 0 : !strcmp(event,"END") ? 1 :
                    !strcmp(event,"LIMIT") ? 2 : !strcmp(event,"EXIT") ? 3 : 4;
    if (event_id == UINT64_MAX || (binary_mode && has_cpu && cpu != 0)) {
        fprintf(stderr,"memtrace: event counter/CPU invalid; capture incomplete\n");
        output_failed = true;
        binary_sink.failed = true;
        g_atomic_int_set(&recording, false);
        g_atomic_int_set(&exhausted, true);
        return;
    }
    ++event_id;
    if (binary_mode) {
        binary_status = kind == 0 ? 4 : kind == 1 ? 0 : kind == 2 ? 1 : kind == 3 ? 2 : 3;
        if (!binary_sink.failed && !binary_sink.writer.failed &&
            (!binary_event(&binary_sink,event_id,interval_id,kind,has_cpu,sequence) ||
             !binary_boundary(&binary_sink))) {
            fprintf(stderr,"memtrace: binary event/flush failed; capture incomplete\n");
            binary_sink.failed = true;
            output_failed = true;
            g_atomic_int_set(&recording, false);
            g_atomic_int_set(&exhausted, true);
            event = "ERROR";
            binary_status = 3;
        }
    }
    /* Binary boundary is flushed before its progress sidecar is visible. */
    if (!events_file || events_failed) {
        return;
    }
    if (has_cpu) {
        snprintf(cpu_field, sizeof(cpu_field), "%u", cpu);
    }
    errno = 0;
    if (fprintf(events_file, "%" PRIu64 ",%" PRIu64 ",%s,%s,%" PRIu64 "\n",
                event_id, interval_id, event, cpu_field, sequence) < 0 ||
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
    fprintf(stderr,"memtrace: recording permanently disabled; capture incomplete\n");
    g_atomic_int_set(&recording, false);
    g_atomic_int_set(&exhausted, true);
    emit_event("ERROR", cpu, has_cpu);
}

static bool flush_outputs(unsigned int cpu, bool has_cpu)
{
    bool binary_ok = !binary_mode || binary_boundary(&binary_sink);
    bool memory_ok = writer_boundary(&memory_writer);
    bool walks_ok = writer_boundary(&walks_writer);
    if (!binary_ok || !memory_ok || !walks_ok || events_failed) {
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
static void emit_walk(unsigned int cpu, uint64_t va, bool has_pa, uint64_t pa,
                      const struct qemu_plugin_x86_walk *snapshot, bool captured)
{
    struct qemu_plugin_x86_walk walk = *snapshot;
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

/* No CSV construction or per-access allocation in the production binary path. */
static bool emit_binary_access(uint64_t pc, uint64_t va, bool has_pa, uint64_t pa,
                               uint64_t size, bool store, bool io,
                               const struct qemu_plugin_x86_walk *w, bool captured)
{
    TcAccess a = {0};
    bool ok = captured && w->status == QEMU_PLUGIN_X86_WALK_OK;
    a.memory.mask = has_pa ? 7 : 3;
    a.memory.value[0]=pc; a.memory.value[1]=va; a.memory.value[2]=pa;
    if(captured) {
        a.context.mask=63;
        a.context.value[0]=w->paging.cr3; a.context.value[1]=w->paging.root_pa;
        a.context.value[2]=w->paging.cr0; a.context.value[3]=w->paging.cr4;
        a.context.value[4]=w->paging.efer; a.context.value[5]=w->paging.phys_bits;
    }
    a.result.mask=(ok?3:0)|(has_pa?4:0);
    a.result.value[0]=w->leaf_size; a.result.value[1]=w->pa; a.result.value[2]=pa;
    a.size=size; a.operation=store; a.memory_type=!has_pa?2:io?1:0;
    a.status=walk_status(w->status);
    a.comparison=!ok||!has_pa?"not-comparable":w->pa==pa?"match":"mismatch";
    a.status_size=strlen(a.status); a.comparison_size=strlen(a.comparison);
    a.path_tag=w->n_entries?2:0; a.n_entries=w->n_entries;
    if(w->n_entries>G_N_ELEMENTS(w->entries))return false;
    for(unsigned i=0;i<w->n_entries;i++){
        if(w->entries[i].level<1 || w->entries[i].level>5)return false;
        a.entries[i].level=w->entries[i].level;
        a.entries[i].address=w->entries[i].entry_pa; a.entries[i].value=w->entries[i].value;
    }
    return binary_access(&binary_sink,&a);
}

static void marker_begin(unsigned int cpu, void *userdata)
{
    /* Any guest executing the bytes can toggle this global interval,
     * including kernel and other processes. Ordering is lock serialization.
     */
    g_mutex_lock(&trace_lock);
    if (!g_atomic_int_get(&recording) &&
        !g_atomic_int_get(&exhausted)) {
        if (interval_id == UINT64_MAX || (binary_mode && cpu != 0)) {
            output_error(cpu, true);
            g_mutex_unlock(&trace_lock);
            return;
        }
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

    if (binary_mode && cpu != 0) {
        output_error(cpu, true);
        g_mutex_unlock(&trace_lock);
        return;
    }
    unsigned shift = qemu_plugin_mem_size_shift(info);
    if (shift > 20 || sequence == UINT64_MAX) {
        output_error(cpu, true);
        g_mutex_unlock(&trace_lock);
        return;
    }
    uint64_t size = UINT64_C(1) << shift;
    bool store = qemu_plugin_mem_is_store(info);
    bool io = false;
    struct qemu_plugin_x86_walk walk = { .status = QEMU_PLUGIN_X86_WALK_UNAVAILABLE };
    bool captured = false;
    hwaddr = qemu_plugin_get_hwaddr(info, vaddr);
    if (hwaddr) {
        callback_pa = qemu_plugin_hwaddr_phys_addr(hwaddr);
        io = qemu_plugin_hwaddr_is_io(hwaddr);
        memory_type = io ? "MMIO" : "RAM";
    }
    if (binary_mode || walks_writer.file) {
        captured = qemu_plugin_x86_paging_walk(cpu, vaddr, &walk);
        if (!captured) { walk.status = QEMU_PLUGIN_X86_WALK_UNAVAILABLE; walk.n_entries = 0; }
    }
    ++sequence;
    if (binary_mode && !emit_binary_access(*pc,vaddr,hwaddr!=NULL,callback_pa,size,store,io,&walk,captured)) {
        fprintf(stderr,"memtrace: binary access serialization/write failed; capture incomplete\n");
        output_error(cpu, true);
    }
    if ((!binary_mode || test_dual) && !output_failed) {
        if (hwaddr)snprintf(pa,sizeof(pa),"0x%" PRIx64,callback_pa);
        snprintf(record,sizeof(record),"%" PRIu64 ",%u,0x%" PRIx64 ",0x%" PRIx64
                 ",%s,%" PRIu64 ",%c,%s\n", sequence,cpu,*pc,vaddr,pa,size,store?'W':'R',memory_type);
        if (memory_writer.file) {
            if (!writer_write(&memory_writer,record,strlen(record)))output_error(cpu,true);
        } else { qemu_plugin_outs(record); }
        if (walks_writer.file && !output_failed)emit_walk(cpu,vaddr,hwaddr!=NULL,callback_pa,&walk,captured);
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
        if (binary_mode) { output_error(cpu, true); } else { flush_outputs(cpu, true); }
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
    if (binary_mode) {
        if (g_atomic_int_get(&recording) && !output_failed) {
            g_atomic_int_set(&recording,false);
            if(flush_outputs(0,false))emit_event("EXIT",0,false);
        }
        bool m_ok=writer_close(&memory_writer), w_ok=writer_close(&walks_writer);
        if(!m_ok || !w_ok || events_failed)output_error(0,false);
        /* Keep a descriptor to our exclusively-created inode until close has
         * succeeded. If finalization/close fails, remove the footer segment so
         * a later reader cannot mistake this session for finalized. */
        int guard=-1;
        off_t checkpoint=-1;
        bool finished=false;
        if(!binary_sink.failed && !binary_sink.writer.failed && binary_boundary(&binary_sink)) {
            guard=fcntl(fileno(binary_sink.writer.file),F_DUPFD_CLOEXEC,0);
            if(guard>=0)checkpoint=lseek(guard,0,SEEK_END);
            if(guard>=0 && checkpoint>=0)finished=binary_finish(&binary_sink,output_failed?3:binary_status);
        }
        bool closed=binary_close(&binary_sink);
        if(!finished || !closed) {
            if(guard>=0 && checkpoint>=0 && ftruncate(guard,checkpoint)) {
                fprintf(stderr,"memtrace: binary footer rollback failed; capture incomplete\n");
            }
            fprintf(stderr,"memtrace: binary finalization/close failed; capture incomplete\n");
            binary_sink.failed=true;
            output_error(0,false);
        }
        binary_sink.failed=true; /* Session closed: no further embedded writes. */
        if(events_file) {
            FILE *f=events_file;events_file=NULL;
            if(fclose(f)) {
                events_error("close");events_failed=true;
                if(guard>=0 && checkpoint>=0 && ftruncate(guard,checkpoint))
                    fprintf(stderr,"memtrace: binary footer rollback failed; capture incomplete\n");
                output_error(0,false);
            }
        }
        if(guard>=0 && close(guard)) {
            fprintf(stderr,"memtrace: binary guard close failed; capture incomplete\n");
            binary_sink.failed=true;
            output_error(0,false);
        }
        g_mutex_unlock(&trace_lock);
        g_hash_table_destroy(pcs);g_mutex_clear(&trace_lock);return;
    }
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
    bool seen_level = false, seen_format = false, seen_chunk = false, seen_dual = false;

    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i];
        uint64_t value = 0;

        if (g_str_has_prefix(arg,"format=")) {
            if(seen_format || (strcmp(arg+7,"csv") && strcmp(arg+7,"inline-binary")))goto invalid;
            seen_format=true;binary_mode=!strcmp(arg+7,"inline-binary");continue;
        }
        if (g_str_has_prefix(arg,"binary=")) {
            if(binary_path || arg[7]!='/')goto invalid;
            binary_path=arg+7;continue;
        }
        if (g_str_has_prefix(arg,"chunk-mib=")) {
            const char *v=arg+10;
            if(seen_chunk || !*v)goto invalid;
            unsigned n=0;for(;*v;v++){if(*v<'0'||*v>'9'||n>16)goto invalid;n=n*10+*v-'0';}
            if(n<1||n>16)goto invalid;
            binary_chunk=n*1024*1024;seen_chunk=true;continue;
        }
        if (!strcmp(arg,"test-dual=on")) {
            if(seen_dual)goto invalid;
            test_dual=true;seen_dual=true;continue;
        }
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
                "format=csv|inline-binary, binary=/ABSOLUTE/PATH, chunk-mib=1..16, test-dual=on; each option at most once\n",
                arg, UINT64_MAX);
        return -1;
    }

    if (binary_mode) {
        if (!info->system_emulation || strcmp(info->target_name,"x86_64") ||
            info->system.smp_vcpus!=1 || info->system.max_vcpus!=1 ||
            !marker_mode || !binary_path || !events_path ||
            (seen_compression && !compression_xz) ||
            (!test_dual && (memory_path || walks_path)) ||
            (test_dual && (!memory_path || !walks_path))) {
            fprintf(stderr,"memtrace: inline-binary requires full-system x86_64 TCG, CPU0 only (-smp 1,maxcpus=1), roi=markers, binary=/ABSOLUTE/PATH, events=PATH, compression=xz; CSV paths only with test-dual=on\n");
            return -1;
        }
        compression_xz=true;
    } else if(binary_path || seen_chunk || test_dual) {
        fprintf(stderr,"memtrace: binary/chunk/test-dual options require format=inline-binary\n");return -1;
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

    if ((!binary_mode && compression_xz && !memory_path) || (seen_level && !compression_xz)) {
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
    if (binary_mode && !binary_open(&binary_sink,binary_path,binary_chunk,compression_level)) {
        goto install_failed;
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
    } else if (!binary_mode) {
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
    if(binary_mode)binary_close(&binary_sink);
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
