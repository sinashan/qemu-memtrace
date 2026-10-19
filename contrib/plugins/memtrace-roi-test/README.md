# memtrace guest markers

`roi=immediate` (default) records from the start as before. `roi=markers`
starts disabled and requires an x86-64 guest. `limit=N` defaults to 1000;
`limit=0` records zero accesses. Explicit `limit=unlimited` removes the numeric
cap; it is stored separately from the numeric value, not encoded as zero.
options may appear in any order, once each. Optional `events=PATH` writes a
separate host-side event CSV, exclusively creating a new file during installation.
An empty path, duplicate option, open failure, or header write failure rejects
installation. Without this option, behavior is unchanged.

Markers are eight-byte NOPs identified by instruction length and raw bytes:

- BEGIN: `0f 1f 84 00 56 57 42 47`
- END: `0f 1f 84 00 56 57 45 4e`

Recording changes when these instructions execute. BEGIN enables a global
interval; END disables it. Repeating either marker is harmless. Record numbers
and numeric limits are cumulative across intervals. Once a numeric limit is reached,
BEGIN cannot resume recording. No marker messages or summaries enter the CSV.
In unlimited mode, END closes the current interval at its current sequence;
later BEGIN can start another interval, with cumulative numbering and no LIMIT
event. If the access counter reaches UINT64_MAX, recording is permanently
suppressed before it can wrap, walks are flushed, and stderr explicitly reports
an incomplete capture. This is not a configured LIMIT; the active interval is
still closed by its actual END or plugin EXIT. Numeric UINT64_MAX remains an
ordinary numeric cap with its usual LIMIT behavior.

The optional event CSV has columns
`event_id,interval_id,event,cpu,access_sequence`. Event IDs start at 1;
interval IDs start at 1 and advance on accepted BEGIN. BEGIN and END report
only real state transitions, so repeated markers emit nothing. `access_sequence`
is the number of memory records already emitted at the boundary. LIMIT closes
an active interval after its final memory record and reports that callback's
vCPU. Later BEGIN cannot reopen an exhausted interval. EXIT closes an interval
still active at QEMU exit and uses `NA` for CPU. Immediate mode and no-marker
execution produce only the event header.

For BEGIN and its matching END, LIMIT, or EXIT, the interval's memory records
satisfy `begin.access_sequence < sequence <= close.access_sequence`.
Marker transitions, event emission, and memory numbering serialize under the
same mutex. Events flush at each boundary; the file closes at plugin exit.
Runtime write/flush failures are diagnosed on stderr and permanently stop
recording while the guest continues; that capture is incomplete. A writable
event sink receives terminal ERROR; an event-sink failure may only be visible
on stderr. ERROR must not be treated as a normal interval closure. Close errors also go to stderr. Use separate paths for the event
file and QEMU's `-D` memory log. No events or diagnostics enter the memory CSV.
This plugin counts records submitted to `qemu_plugin_outs()`; use `-d plugin`
to ensure the corresponding memory log is enabled.

Startup/boot and accesses before BEGIN or after END are excluded. All successful
data accesses during the interval are eligible, including compiler-generated
stack accesses, kernel accesses, and other-process accesses in system mode.
This is not process filtering. Any guest code executing these bytes can toggle
recording. Cross-vCPU ordering reflects callback serialization, not simulated
hardware timing; inactive callbacks can return via an atomic check, while
record emission and marker changes serialize under the output mutex.

For whole-command captures, [roi-run.c](roi-run.c) emits BEGIN, forks/execs the
command, waits for it, and emits END. Child startup, loading, teardown and
concurrent kernel/other-process activity are included until END. If the wrapper
is killed before END, the interval may remain active until plugin/QEMU exit;
unlimited mode does not fix that. No PID polling or process detection is used.
Unlimited recording neither compresses output nor bounds disk usage. Preserve
existing captures, choose fresh output paths (existing sidecars are refused),
and monitor free space, for example `df -h /path/to/capture-directory`.
Diagnosed sidecar write failures still report errors on stderr and mark the
sidecar incomplete; do not accept such captures as complete or ignore errors.
The QEMU-managed memory log retains its existing error handling.

New plugin argument (replace placeholders with fresh host-side absolute paths):
`roi=markers,limit=unlimited,events=...,walks=...`.
For GAP BFS, `-g 12` generates 4096 vertices, `-n 1` requests one BFS trial,
and `-n 4096` requests 4096 trials, not 4096 vertices. Confirm the installed
guest's help as described in [gap-bfs.md](gap-bfs.md).

Instruction PCs are copied into stable heap storage shared by translations of
the same PC, retained across TB flushes, and freed at plugin exit. No temporary
instruction or hardware-address handles are retained. Metadata can grow with
unique translated PCs while waiting for markers. There is no TLB simulation,
fault detection, address-space tracking, binary output, or timing model.

Optional experimental `walks=/absolute/path.csv` adds full-system x86-64 TCG
paging capture without changing the memory/event CSVs. See [paging-walks.md](paging-walks.md)
for API details, sidecar encoding, limitations, and one-vCPU first-touch
validation commands. With walks disabled, no state capture or table reads occur.

## Local build and verification

From the QEMU source root:

```sh
make -C build/contrib/plugins libmemtrace.so
cc -O2 -Wall -Wextra -static -o build/contrib/plugins/memtrace-roi-test \
  contrib/plugins/memtrace-roi-test/roi-test.c
cc -O2 -Wall -Wextra -static -o build/contrib/plugins/memtrace-exit-active \
  contrib/plugins/memtrace-roi-test/exit-active.c
python3 contrib/plugins/memtrace-roi-test/verify.py

build/qemu-x86_64 \
  -plugin build/contrib/plugins/libmemtrace.so,roi=markers,limit=10000,events=/tmp/memtrace-roi-events.csv \
  -d plugin -D /tmp/memtrace-roi.csv \
  build/contrib/plugins/memtrace-roi-test > /tmp/memtrace-roi-regions.txt

build/qemu-x86_64 \
  -plugin build/contrib/plugins/libmemtrace.so,roi=markers \
  -d plugin -D /tmp/memtrace-true.csv /bin/true
```

The test reports three distinct array regions on stdout, separate from CSV.
The verifier checks that active-region reads and writes occur and pre/post
regions have no overlapping accesses. An immediate-mode control confirms
that those regions really are touched. Two intervals exercise repeated
markers and cumulative numbering; a limit of five also tests that the later
BEGIN cannot restart recording. Total access counts are not assumed.
The verifier also checks boundary event order and interval partitions,
unlimited multi-interval numbering and pre/post exclusion, no unlimited LIMIT,
immediate unlimited recording, unlimited EXIT, numeric zero and duplicate or
malformed unlimited options,
counter overflow using a temporary test-only plugin initialized near UINT64_MAX,
and numeric UINT64_MAX retaining its ordinary LIMIT transition,
LIMIT without reopening, EXIT with an active interval, header-only event
files, malformed arguments, invalid paths, header-write failure, runtime
boundary-write failure with guest continuation, and that a
parse error does not truncate an existing event file. The tiny `exit-active.c`
test executes BEGIN and exits without END.

The installed toolchain builds this test statically: no guest dynamic loader
or shared C library is needed. The executable requires x86-64 Linux.

## Existing guest transfer

These commands copy and run the test; they do not install the host plugin
inside the guest. Run them only when desired:

```sh
scp -P 2222 -i ~/qemu-work/guest/guest_key \
  ~/qemu-work/qemu-8.2.10/build/contrib/plugins/memtrace-roi-test \
  ubuntu@localhost:~/memtrace-roi-test
ssh -p 2222 -i ~/qemu-work/guest/guest_key \
  ubuntu@localhost './memtrace-roi-test'
```

## Full-system example

For a future launch when the existing VM is stopped and its disk and port 2222
are available. This command has not been run:

```sh
cd ~/qemu-work/qemu-8.2.10
build/qemu-system-x86_64 \
  -accel tcg -m 2G -smp 2 -nographic \
  -drive file=../guest/jammy-server-cloudimg-amd64.img,format=qcow2,if=virtio \
  -drive file=../guest/seed.iso,format=raw,media=cdrom,readonly=on \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22 \
  -device virtio-net-pci,netdev=net0 \
  -plugin build/contrib/plugins/libmemtrace.so,roi=markers,limit=1000000,events=/tmp/memtrace-system-events.csv \
  -d plugin -D /tmp/memtrace-system-roi.csv
```

The CSV is written on the host. Running a guest test under a VM that was
launched without this plugin will not produce a trace.

## Streaming compression

See [compression.md](compression.md) for `compression=xz,compression-level=3,`
`memory=/absolute/path/memory.csv.xz,walks=/absolute/path/walks.csv.xz`,
concatenated-stream boundary framing, bounded buffers, terminal ERROR semantics,
fresh-file protection, launch/runner options and local compression checks.
Without `memory=`, raw memory output remains through QEMU logging.

`execution/` contains a small **diskless full-system** multiboot regression for
the opt-in `format=execution-binary` extension: observed cross-page segments and
committed architectural context events. See
[execution/README.md](execution/README.md) before running it. Existing Linux ROI,
first-touch and footprint workloads are unchanged.

`linux-v3/` adds a static Linux cross-page SSE and shared-memfd remapping
workload, a bounded shared-decoder verifier, and user-run v3 capture commands.
See [linux-v3/README.md](linux-v3/README.md); its local tests do not launch a VM.
