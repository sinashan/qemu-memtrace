# Targeted Linux guest validation for execution-binary v3

This small **single-threaded Linux x86-64** workload has two self-contained
BEGIN/END intervals. It uses exactly the existing eight-byte markers and
volatile assembly with compiler `memory` clobbers. Do **not** put `roi-run`
around it: use `--markers-in-benchmark` with the experiment runner.

## What runs inside each interval

1. **Cross-page:** anonymous adjacent 4-KiB virtual pages are populated outside
   recording, with checked `MADV_NOHUGEPAGE`. An explicit `movdqu` reads 16 bytes
   at `base+4088`, then another explicit `movdqu` writes 16 different bytes at
   the same VA. Both operations must remain whole 16-byte SSE instructions.
   Loaded and stored values are verified after END. Function-call, stack and
   buffer-copy accesses are incidental trace traffic, not excluded from replay.
2. **Mapping change:** a two-page `memfd` and its shared preparation alias are
   populated outside recording. A reserved one-page VA is mapped shared to
   backing page A, without touching that alias before BEGIN. The first marked
   byte load establishes translation state. `mmap(MAP_SHARED|MAP_FIXED)` replaces
   **exactly that still-owned reserved page** with backing page B, inside ROI;
   the second marked byte load reads the same VA. `madvise` is checked again for
   the replacement VMA. After END, both loaded values and all backing bytes are
   checked. An additional outside-ROI write confirms shared aliasing to B while
   A stays unchanged. Cleanup `munmap`/`close` errors are checked.

All preparation/output and normal validation/cleanup are outside ROI. A
recoverable syscall failure closes an active ROI before reporting failure.
Killing the process can prevent END. The interval remains **global**, including
kernel execution, interrupts and concurrent guest activity; it is not a process
filter or benchmark-kernel-only trace.

The workload prints the mapping base, exact target VAs, and **actual instruction
label addresses** before the first BEGIN, then success/value checks after END.
The verifier uses those reported PCs, not assumed instruction address stability,
source line numbers, or disassembly text. Static non-PIE builds make inspection
easy, but rebuilding can change PCs; always keep the matching workload output.
Physical placement is never assumed from `mmap` or memfd allocation.

## Build and local checks — no VM

```sh
cd /home/ubuntu/qemu-work
make -C qemu-replay
make -C qemu-memtrace/contrib/plugins/memtrace-roi-test/linux-v3 test
```

This warning/error-enabled build creates:

- `qemu-memtrace/build/contrib/plugins/memtrace-linux-v3`: **static** guest executable.
- `qemu-memtrace/build/contrib/plugins/verify-linux-v3`: host streaming inspector,
  linked with existing liblzma; it uses the shared typed binary decoder and pure
  x86 PTE decoder. It does not introduce another wire parser.
- `linux-v3-fixture`: small synthetic test producer using the shared serializer.

The test target runs the workload natively and, when available, with
`build/qemu-x86_64` **without a tracing plugin**. It tests byte contents and
syscall handling, not guest-kernel invalidation capture. It also inspects actual
machine instructions and runs synthetic positive/negative capture validation
and strict baseline replay. No VM, SSH, SCP, or real benchmark is run. The only
runner invocation is `--dry-run`.

For manual instruction inspection:

```sh
objdump -d --disassemble=wide_load \
  qemu-memtrace/build/contrib/plugins/memtrace-linux-v3
objdump -d --disassemble=wide_store \
  qemu-memtrace/build/contrib/plugins/memtrace-linux-v3
nm -n qemu-memtrace/build/contrib/plugins/memtrace-linux-v3 | \
  rg 'linux_v3_(wide_load|wide_store|old|new)_pc'
```

The locally inspected wide instructions were `f3 0f 6f 07` (`movdqu (%rdi),%xmm0`)
and `f3 0f 7f 0f` (`movdqu %xmm1,(%rdi)`), each one 16-byte operation. Their
reported PCs in this build are `0x402430` and `0x402444`; these are **examples,
not verifier constants**. SSE2 is part of the x86-64 baseline. The static binary
requires a Linux kernel supporting memfd and MADV_NOHUGEPAGE, and 4096-byte pages;
no guest shared libraries or extra packages are required.

## User-run transfer and capture commands — NOT executed here

Stage the binary into your guest when appropriate:

```sh
scp -P 2222 -i /home/ubuntu/qemu-work/guest/guest_key \
  /home/ubuntu/qemu-work/qemu-memtrace/build/contrib/plugins/memtrace-linux-v3 \
  ubuntu@127.0.0.1:/home/ubuntu/memtrace-linux-v3
```

The existing runner **starts and owns a VM**; it does not attach to an existing
VM. Run the following only in a planned capture session when port 2222 and the
runner's guest image are exclusively available. Do not run it while your
existing VM is using that image. This task does not ask you to stop that VM.
The runner currently uses `guest/jammy-server-cloudimg-amd64.img` and
`guest/seed.iso`; staging must have been persisted in the image used for this
session. Prefer a separately managed, offline-prepared test image/workspace if
keeping the existing VM active. Do not copy a writable live disk as a substitute
for an offline-consistent image.

```sh
cd /home/ubuntu/qemu-work
set -o pipefail
run_log=$(mktemp /home/ubuntu/qemu-work/traces/linux-v3-run-XXXXXX.log)
python3 -u traces/run_experiment.py \
  --workspace /home/ubuntu/qemu-work \
  --profiles /home/ubuntu/qemu-work/qemu-memtrace/contrib/plugins/memtrace-roi-test/linux-v3/runner-profile.json \
  --profile linux-v3 --name linux-v3-small \
  --trace-format execution-binary --markers-in-benchmark \
  --limit 2000000 --cpus 1 --compression xz --compression-level 3 \
  --port 2222 --ssh-user ubuntu \
  --key /home/ubuntu/qemu-work/guest/guest_key \
  --benchmark-timeout 300 | tee "$run_log"
```

The profile executes `/home/ubuntu/memtrace-linux-v3` directly, without an outer
wrapper. The runner selects `max,la57=off,pcid=off,invpcid=off`, TCG single-thread,
its existing QEMU virtual clock settings, and a fresh timestamped capture
folder. The two intervals should be 1=cross-page and 2=remapping. Do not invoke
the workload a second time in the same capture without selecting the new IDs.

The numeric limit is a safety cap, not a desired record count. Require both ENDs.
If LIMIT or timeout occurs, retain that failed capture and use a **new** capture
with an explicitly reconsidered cap/timeout; never accept a prefix as success.
Do not use `--keep-vm` for this validation: a finalized binary footer and XZ EOF
are required. Normal runner completion closes its own capture process. A live
END-visible stream alone is not a finalized artifact.

Get the **actual session path** from the saved runner log, without guessing a
`/tmp` path or choosing an ambiguous 'latest' capture:

```sh
capture_dir=$(python3 - "$run_log" <<'PY'
from pathlib import Path
import sys
paths=[line[len('Capture: '):] for line in Path(sys.argv[1]).read_text().splitlines()
       if line.startswith('Capture: ')]
if len(paths)!=1:
    raise SystemExit('Expected exactly one Capture: path in the successful runner log')
print(paths[0])
PY
)
printf 'Capture: %s\n' "$capture_dir"
```

Keep `trace.bin.xz`, `events.csv`, `logs/guest-stdout.txt`,
`logs/guest-stderr.txt`, and `logs/run.json` together. Program output and QEMU
logging remain separate from the binary trace.

## Verification and strict replay

Only run this after a normally finalized capture. The wrapper requires a **new**
results directory; it never overwrites the capture or previous results:

```sh
python3 /home/ubuntu/qemu-work/qemu-memtrace/contrib/plugins/memtrace-roi-test/linux-v3/verify-linux-v3.py \
  --trace "$capture_dir/trace.bin.xz" \
  --events "$capture_dir/events.csv" \
  --workload-output "$capture_dir/logs/guest-stdout.txt" \
  --cross-interval 1 --remap-interval 2 \
  --max-records 10000000 --timeout 300 \
  --config /home/ubuntu/qemu-work/qemu-replay/1d_modern_intel.cfg \
  --results-dir "$capture_dir/linux-v3-verification"
```

This reads typed records in one bounded streaming inspection, then performs two
**full strict baseline replays**, retaining matching embedded/sidecar events and
all incidental accesses. It writes capture analysis, exact subprocess commands,
stdout/stderr, separate summary CSVs, and finally `verification.json` only after
both replays and counter checks succeed. It uses no per-access audit or CSV
export and no `infer-remap` or prefix cutoff. Inputs are identity-checked before
and after each stage. A rejected replay is reported with its exact existing
reason; model behavior is not changed to pass the workload.

The inspector retains only four target groups, two interval summaries, and at
most eight explanatory context records. Decoder chunk/XZ memory is bounded by
the shared implementation (128-MiB decoder cap). Workload output is limited to
64 KiB. `--max-records` bounds **all binary packets**, including contexts/events;
exceeding it is failure, never a successful prefix. A timeout also fails. A
complete finalized capture must fit the chosen bound to pass.

Required evidence:

- Full framing/checksums/footer/XZ EOF and complete END for both selected ROIs;
  successful guest output, no source prefix or failed/truncated source.
- Exactly one targeted load and store in the cross interval. Each original has
  size 16 and two 8-byte segments at offsets 0 and 8, covering both pages once.
  Segment RAM PAs and callback PAs must match complete, correctly indexed,
  independently decoded 4-KiB PTE paths. Load/store mappings must agree.
- Old/new target byte loads use the same VA and application root but different
  **observed** physical frames. The verifier reports both frames and paths.
- Between those two target groups, a matching-page/root INVLPG or a PCIDE-off
  CR3 write/reload for the nonglobal old mapping must be recorded. An unrelated
  INVLPG does **not** qualify merely because v3's model conservatively flushes
  everything. CR0/CR4/EFER updates are counted, but alone are not accepted as
  evidence of the Linux test's targeted invalidation. This is deliberately
  stronger than assuming that any conservative model flush proves the remap.
- Strict baseline succeeds for all selected accesses; originals, segments/TLB
  lookups, hits/misses, walk depths, PTE cache outcomes, actual RAM cache-line
  traffic, RAM/MMIO counts and architectural event counts reconcile.

Targeted records are reported separately from incidental kernel-PC **heuristic**
accesses and other accesses. The heuristic is not a verified privilege label.
Incidental records are **never filtered from replay**. No fixed total access or
walk count is asserted for real Linux execution.

Cross-page physical noncontiguity is reported as `observed` or
`absent (captured frames are contiguous)`. A contiguous result still tests
cross-page segmentation, but **does not establish noncontiguous-frame coverage**.
No physical placement claim is made from local native/user-mode runs or from
synthetic fixtures.

For manual strict replay to additional **fresh** summary paths:

```sh
/home/ubuntu/qemu-work/qemu-replay/build/qemu-replay \
  --model baseline --mapping-policy strict \
  --trace "$capture_dir/trace.bin.xz" --events "$capture_dir/events.csv" \
  --interval 1 --warmup 0 \
  --config /home/ubuntu/qemu-work/qemu-replay/1d_modern_intel.cfg \
  --results "$capture_dir/linux-v3-cross-manual-new.csv"
/home/ubuntu/qemu-work/qemu-replay/build/qemu-replay \
  --model baseline --mapping-policy strict \
  --trace "$capture_dir/trace.bin.xz" --events "$capture_dir/events.csv" \
  --interval 2 --warmup 0 \
  --config /home/ubuntu/qemu-work/qemu-replay/1d_modern_intel.cfg \
  --results "$capture_dir/linux-v3-remap-manual-new.csv"
```

Results append sequentially if the same compatible results file is reused, so
choose unused names for an independent verification. Old incompatible headers
remain rejected.

## Local validation and limits

Static compilation, native and QEMU-user execution, disassembly checks, and
15 local tests passed. Synthetic tests include full strict replay and rejection
of missing/unrelated invalidations, unchanged frames, invalid PTE paths/PA
reconstructions, duplicates, LIMIT, record bounds, corrupt/truncated artifacts
and existing output paths. The runner profile was checked with `--dry-run` only.
**No VM was launched/contacted, no files transferred, and no actual Linux v3
capture was collected for this task.** Physical placement, captured Linux kernel
invalidation hooks and full strict replay of that real capture remain untested
until the user runs the commands above.

The production v3 policy remains explicitly conservative-all, including globals;
this test does not add exact PCID/INVPCID semantics or hardware fidelity. PTE
snapshots are fresh post-success observations and may disagree with stale cached
translations or concurrently modified tables. Ordinary callbacks omit faulting
attempts. Such failures stay failures; this workload/verifier does not synthesize
missing translations, events or records and does not modify tracing/replay code.
