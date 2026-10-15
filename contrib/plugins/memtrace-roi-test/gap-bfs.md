# Whole-command GAP BFS capture

`roi-run.c` is a Linux x86-64 wrapper: `memtrace-roi-run -- COMMAND ARG...`.
It emits the existing BEGIN bytes before `fork`, calls `execvp` with arguments
unchanged, waits (retrying EINTR), and emits END in the parent. Both markers use
volatile inline assembly with a compiler `memory` clobber. No shell is inserted.
Do not wrap a command that emits its own markers, or run other marked workloads
concurrently: the plugin has global, non-nesting intervals.

This is **whole-command capture, not BFS-kernel-only capture**. Child process
launch, dynamic loading, graph generation, BFS, printing, teardown, parent
fork/wait activity, kernel accesses, and other guest activity while active are
eligible. Wrapper argument validation and ordinary wrapper messages occur
outside the interval. Exceptional child exec errors can print inside it.

Normal child exit status is propagated. Signal termination returns 128 plus
the signal (SIGTERM gives 143). Usage errors return 2; wrapper/fork/wait errors
125; exec failures 126, or 127 for a missing command/path component. Fork and
wait failures attempt END; a wait failure leaves the child outcome unknown and
is not a successful workload capture. END is not guaranteed if the wrapper is
killed, SSH disconnects, or the guest/QEMU fails. Require both successful child
completion and a matching END event.

## Build and local checks

```sh
cd /home/ubuntu/qemu-work/qemu-memtrace
cc -O2 -Wall -Wextra -Werror -static \
  -o build/contrib/plugins/memtrace-roi-run \
  contrib/plugins/memtrace-roi-test/roi-run.c
python3 contrib/plugins/memtrace-roi-test/verify-roi-run.py \
  --binary build/contrib/plugins/memtrace-roi-run \
  --qemu build/qemu-x86_64 \
  --plugin build/contrib/plugins/libmemtrace.so
```

The static binary needs no guest shared libraries. Local checks cover true,
false, missing executable, SIGTERM, argument handling, injected fork/wait
errors, EINTR retry, marker bytes, and a user-mode QEMU BEGIN/END. User-mode
testing does not validate guest-kernel tracing. No guest benchmark was run.

## Check GAP options and transfer (user-run commands)

The host script `/home/ubuntu/scripts/gap.sh` invokes BFS with `-n 5` and
`-f GRAPH`; it is a separate PIN workflow and should not be run for this capture.
The guest checkout was not available locally. Upstream GAP's
[argument parser](https://github.com/sbeamer/gapbs/blob/master/src/command_line.h)
defines `-g SCALE` as a generated graph with 2^SCALE vertices, `-n TRIALS`,
and opt-in `-v` verification, `-a` analysis, and `-l` performance logging.
Its [BFS main](https://github.com/sbeamer/gapbs/blob/master/src/bfs.cc) constructs
the graph before invoking the benchmark, all within the child process.
These upstream options must be confirmed against the installed guest version.
Do not invent a disable-verification flag: omit optional flags after checking.

Create a unique host artifact directory and save the actual help output:

```sh
mkdir -p /home/ubuntu/qemu-work/gap-bfs-captures
run_dir=$(mktemp -d /home/ubuntu/qemu-work/gap-bfs-captures/bfs-s12-XXXXXX)
ssh -p 2222 -i /home/ubuntu/qemu-work/guest/guest_key ubuntu@localhost \
  'cd /home/ubuntu/benchmarks/gapbs && ./bfs -h' \
  > "$run_dir/bfs-help.txt" 2>&1
cat "$run_dir/bfs-help.txt"
scp -P 2222 -i /home/ubuntu/qemu-work/guest/guest_key \
  /home/ubuntu/qemu-work/qemu-memtrace/build/contrib/plugins/memtrace-roi-run \
  ubuntu@localhost:/home/ubuntu/memtrace-roi-run
```

Check `-g`, `-n`, and defaults before proceeding. The intended command is
`./bfs -g 12 -n 1` with `OMP_NUM_THREADS=1`; scale 12 gives 4096 vertices,
and `-n 1` means one BFS trial. `-n 4096` means 4096 trials, not vertices.
not a bound on total captured accesses. Generation and kernel work can be
substantial even with a small graph. These instructions assume that transfer
destination is available for this wrapper; choose a fresh guest filename if
it already contains something you need to preserve.

## Find the existing capture and check its budget

The plugin must already have been loaded when QEMU started with `roi=markers`,
`events=...`, `walks=...`, and logging `-d plugin -D ...`. The wrapper cannot
load/reconfigure the plugin or reset its cumulative limit. Do not restart or
stop the VM for these instructions.

For a separately planned capture session, the plugin now accepts
`roi=markers,limit=unlimited,events=...,walks=...` (use fresh absolute sidecar
paths). Unlimited has no configured LIMIT and still relies on wrapper END;
killing the wrapper can leave recording active until QEMU/plugin exit. It
does not compress output or limit disk usage. Preserve existing captures and
monitor `df -h` on the capture filesystem. Do not use an incomplete sidecar
after a diagnosed write failure. The budget check below accepts the literal
`unlimited` and still requires an inactive interval before starting.

No running capture command or actual output paths were visible in the local
environment during preparation. Discover them from your actual session:

```sh
ps -eo pid,args | rg '[q]emu-system'
# Set this to the PID of YOUR VM, then inspect untruncated arguments and cwd:
qemu_pid=YOUR_VM_PID
python3 - "$qemu_pid" <<'PY'
import os, sys
p = '/proc/' + sys.argv[1]
print('cwd:', os.readlink(p + '/cwd'))
for arg in open(p + '/cmdline', 'rb').read().split(b'\0'):
    if arg:
        print(os.fsdecode(arg))
PY
```

In the same host shell, set `trace_memory` to the actual `-D` path,
`trace_walks` and `trace_events` to this plugin's actual `walks=` and `events=`
paths, and `trace_limit` to its actual `limit=` value (`unlimited` when configured;
default 1000 if absent).
Resolve relative paths against the QEMU process cwd. Do not use assumed `/tmp`
names. Check this is the intended VM and memtrace instance, not another logger.
If required capture options are absent, this session cannot provide the
requested three-file capture; do not proceed with assumed files.

```sh
# Assign the four variables above using your inspected session, then:
printf 'memory=%s\nwalks=%s\nevents=%s\nlimit=%s\n' \
  "$trace_memory" "$trace_walks" "$trace_events" "$trace_limit" \
  > "$run_dir/session.txt"
cp -n -- "$trace_events" "$run_dir/events-before.csv"
cat "$run_dir/events-before.csv"
python3 - "$run_dir/events-before.csv" "$trace_limit" <<'PY'
import csv, sys
active = False
last = 0
with open(sys.argv[1], newline='') as f:
    for row in csv.DictReader(f):
        last = int(row['access_sequence'])
        active = row['event'] == 'BEGIN'
        if row['event'] == 'LIMIT':
            raise SystemExit('Permanent cumulative limit already exhausted')
if active:
    raise SystemExit('An interval is already active: do not nest markers')
if sys.argv[2] == 'unlimited':
    print('Unlimited recording: require END and monitor free disk space')
    raise SystemExit(0)
remaining = int(sys.argv[2]) - last
if remaining <= 0:
    raise SystemExit('No remaining record budget')
print('Remaining cumulative record budget:', remaining)
PY
```

Use a sufficiently high existing budget; no reliable bound is assumed here.
Ultimately a matching END, not an estimated budget, establishes completion.
If the limit was reached during an earlier workload, later BEGINs are ignored.

## Run one small single-threaded case

After confirming the actual help and capture setup, run this yourself:

```sh
ssh -p 2222 -i /home/ubuntu/qemu-work/guest/guest_key ubuntu@localhost \
  'cd /home/ubuntu/benchmarks/gapbs && export OMP_NUM_THREADS=1 && exec /home/ubuntu/memtrace-roi-run -- ./bfs -g 12 -n 1' \
  > "$run_dir/guest-stdout.txt" 2> "$run_dir/guest-stderr.txt"
guest_status=$?
printf '%s\n' "$guest_status" > "$run_dir/guest-status.txt"
cat "$run_dir/guest-stdout.txt" "$run_dir/guest-stderr.txt"
```

Environment setup and directory selection precede the wrapper. One OpenMP
thread does not restrict all global trace records to one process or vCPU.
Host SSH redirection keeps workload output separate from the plugin CSVs;
the child's guest-side printing/syscalls still occur inside the interval.
Require status 0 and the wrapper's successful child outcome. An SSH error or
unknown child outcome is a failed experiment, even if some records exist.

## Identify END, flush completion, and preserve the matching files

Keep all other marked workloads idle until the snapshot is complete:

```sh
cp -n -- "$trace_events" "$run_dir/events-after.csv"
interval_id=$(python3 - "$run_dir/events-before.csv" "$run_dir/events-after.csv" <<'PY'
import csv, sys
def load(path):
    with open(path, newline='') as f:
        return list(csv.DictReader(f))
before, after = map(load, sys.argv[1:])
if after[:len(before)] != before:
    raise SystemExit('Events changed/replaced: not a matching capture')
new = after[len(before):]
if len(new) != 2 or [r['event'] for r in new] != ['BEGIN', 'END']:
    raise SystemExit('Require exactly one new BEGIN/END; LIMIT, EXIT, missing or concurrent intervals fail')
if new[0]['interval_id'] != new[1]['interval_id']:
    raise SystemExit('Interval IDs do not match')
print(new[0]['interval_id'])
PY
) || exit 1
printf '%s\n' "$interval_id" > "$run_dir/interval.txt"
stat -c '%n: %s bytes' -- "$trace_memory" "$trace_walks" "$trace_events"
cp -n -- "$trace_memory" "$run_dir/memory.csv"
cp -n -- "$trace_walks" "$run_dir/walks.csv"
cp -n -- "$trace_events" "$run_dir/events.csv"
cmp -- "$run_dir/events-after.csv" "$run_dir/events.csv" || exit 1
python3 - "$run_dir" <<'PY'
import csv, pathlib, sys
p = pathlib.Path(sys.argv[1])
with (p / 'events.csv').open(newline='') as f:
    events = list(csv.DictReader(f))
end = events[-1]
if end['event'] != 'END':
    raise SystemExit('Capture did not finish with END')
expected = int(end['access_sequence'])
for name in ('memory.csv', 'walks.csv'):
    count = 0
    with (p / name).open(newline='') as f:
        for row in csv.DictReader(f):
            count += 1
            if int(row['sequence']) != count:
                raise SystemExit(name + ': noncontiguous sequence')
    print(name, 'bytes=', (p / name).stat().st_size, 'records=', count)
    if count != expected:
        raise SystemExit(name + ': incomplete/unflushed or mismatched capture')
print('Selected interval:', (p / 'interval.txt').read_text().strip())
print('Cumulative recorded accesses:', expected)
PY
sha256sum "$run_dir/memory.csv" "$run_dir/walks.csv" "$run_dir/events.csv" \
  > "$run_dir/capture-sha256.txt"
```

Accepted END flushes the walk sidecar and events. In this checkout,
`qemu_plugin_outs()` uses QEMU logging, whose unlock flushes the memory log.
Only inspect/copy after END, with no new marked activity. Compare cumulative
row counts to END's `access_sequence`, and check QEMU stderr for sidecar write
errors: an END does not repair a failed file. Buffered walks may be lost on
crash/interruption. Preserve all matching files, session metadata, help,
workload output, and status; do not filter away kernel/MMIO records or delete
original captures. Row counts above describe the entire cumulative capture,
not just this interval. Its records satisfy BEGIN.sequence < sequence <=
END.sequence (using the events' `access_sequence` fields).

A LIMIT event closes a truncated interval permanently; EXIT closes an active
interval on QEMU exit and is not the requested END. Neither is acceptable for
this experiment. A missing BEGIN can mean the cumulative limit was previously
exhausted. Do not raise/reset a limit by editing CSVs or repeatedly invoking
the wrapper. Check the actual plugin limit and events together.

## Optional baseline replay

Use the saved files and newly identified interval, initially with no warmup:

```sh
/home/ubuntu/qemu-work/qemu-replay/build/qemu-replay --model baseline \
  --memory "$run_dir/memory.csv" --walks "$run_dir/walks.csv" \
  --events "$run_dir/events.csv" --interval "$interval_id" --warmup 0 \
  --config /home/ubuntu/qemu-work/qemu-replay/1d_modern_intel.cfg \
  --results "$run_dir/baseline-results.csv"
```

This may expose preliminary-model limits: changed mappings under unchanged
roots, stale translations/current-walk mismatches, accesses crossing 4-KiB
boundaries, or multiple vCPUs. Keep explicit rejections rather than skipping
records. Do not attempt full Virt-Walker replay yet: it only supports 4-KiB
leaves, while global kernel activity can include large-page mappings.
Replay is functional TLB/cache modeling, not execution timing or IPC.

For direct lossless XZ capture and updated ERROR completion semantics, see
[compression.md](compression.md). Use its streaming integrity checks rather
than reading `.xz` files as plain CSV. The discovery/count commands above are
for raw captures; preserve originals and all matching event/workload files.
