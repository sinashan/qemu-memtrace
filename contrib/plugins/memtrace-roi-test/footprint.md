# Controlled resident-footprint experiment

`footprint-test.c` is a standalone x86-64 Linux workload. Defaults are 32 pages,
four passes, sequential order. `--pages` must be a power of two in 1..65536;
`--passes` must be in 1..1000000. Values are checked decimal integers, with
allocation/read-count/checksum arithmetic checked for overflow. The experiment
requires the actual OS page size to be 4096. Mapping is anonymous/private,
`MADV_NOHUGEPAGE` is checked, and every page start is written before BEGIN.
The static binary needs no guest dynamic loader or shared libraries.

The single marked interval reads one volatile byte at each page start per
pass. The order is repeated every pass. Permuted order is
`(i * stride) & (pages - 1)`, with stride `pages/2 + 1` for pages >= 4 and
stride 1 otherwise. Thus the requested strides are 17, 257 and 2049: jumps
across approximately half the footprint. An odd multiplier is coprime to a
power of two and visits every index exactly once. There is no permutation
array, RNG, allocation, printing or explicit syscall inside the interval.
The checksum is reported after END. BEGIN/END bytes and volatile-asm memory
clobbers are identical to `first-touch.c` and `roi-test.c`.

The global ROI can still include incidental compiler/stack accesses,
interrupts, kernel work, MMIO and unrelated activity. Prepopulation removes
intentional first-touch faults from the marked loop; it does not guarantee
that the guest kernel never accesses or changes mappings during recording.
Do not infer an aggregate miss count solely from the application page count.

## Local build and checks

These commands operate locally and do not contact the VM:

```sh
cd /home/ubuntu/qemu-work/qemu-memtrace
cc -O2 -Wall -Wextra -Werror -static \
  -o build/contrib/plugins/memtrace-footprint-test \
  contrib/plugins/memtrace-roi-test/footprint-test.c
file build/contrib/plugins/memtrace-footprint-test
python3 contrib/plugins/memtrace-roi-test/verify-footprint.py \
  --binary build/contrib/plugins/memtrace-footprint-test \
  --qemu build/qemu-x86_64 \
  --plugin build/contrib/plugins/libmemtrace.so
```

Verification runs all six requested cases natively and through user-mode QEMU,
checks their checksums, marker intervals, page-start read counts and order,
checks malformed arguments, and tests the analyzer with extras, other
intervals, LIMIT/EXIT, incomplete events, missing records and duplicate reads.
It independently verifies the arithmetic permutation for every allowed power
of two. User-mode validation checks the workload and marker recognition only;
it cannot validate guest-kernel tracing or full-system paging-walk capture.

## First run: 32 pages, sequential, four passes

First check whether your **already running** VM was started with memtrace,
`roi=markers`, boundary events and paging walks enabled. A guest program emits
markers only; it cannot install the plugin, enable host tracing, change the
host output paths, or reset the cumulative limit. If the existing VM has those
options, use its existing host CSV paths and identify the new interval as
explained below. No restart is necessary to run a workload on such a VM.

For a separate future capture that you manage yourself, the following is a
launch template, **not a command to run alongside the current VM**. Use it
only when its disk and port are available. Use one guest CPU for the replay.
Use a fresh case_id for every capture; QEMU/plugin capture files are opened
for writing, so reusing a name would replace the capture. This template uses
new paths rather than the previous memtrace-system capture:

```sh
cd /home/ubuntu/qemu-work/qemu-memtrace
case_id=footprint-p32-sequential-run01
build/qemu-system-x86_64 \
  -accel tcg -cpu max,la57=off -m 2G -smp 1 -nographic \
  -drive file=/home/ubuntu/qemu-work/guest/jammy-server-cloudimg-amd64.img,format=qcow2,if=virtio \
  -drive file=/home/ubuntu/qemu-work/guest/seed.iso,format=raw,media=cdrom,readonly=on \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22 \
  -device virtio-net-pci,netdev=net0 \
  -plugin "build/contrib/plugins/libmemtrace.so,roi=markers,limit=100000000,events=/tmp/${case_id}-events.csv,walks=/tmp/${case_id}-walks.csv" \
  -d plugin -D "/tmp/${case_id}-memory.csv"
```

LA57 is disabled so the guest uses the replay's supported four-level mode.
The limit is deliberately high and global/cumulative. Always confirm END;
do not assume that the requested limit is sufficient. Use the following
transfer and invocation commands yourself, in a separate host terminal:

```sh
scp -P 2222 -i /home/ubuntu/qemu-work/guest/guest_key \
  /home/ubuntu/qemu-work/qemu-memtrace/build/contrib/plugins/memtrace-footprint-test \
  ubuntu@localhost:~/memtrace-footprint-test

ssh -p 2222 -i /home/ubuntu/qemu-work/guest/guest_key \
  ubuntu@localhost './memtrace-footprint-test --pages 32 --passes 4 --pattern sequential' \
  > /tmp/footprint-p32-sequential-run01-guest-output.txt
```

The guest output must show page_count=32, footprint_bytes=131072,
expected_page_start_reads=128 and equal checksum/expected_checksum. Keep this
stdout separate from the host memory/events/walk CSVs. Each successful guest
invocation emits exactly one BEGIN and one END.

For the dedicated capture above, run no other marker workload and select
interval 1. Analyze the **unmodified host memory CSV** after the accepted END:

```sh
python3 /home/ubuntu/qemu-work/qemu-memtrace/contrib/plugins/memtrace-roi-test/analyze-footprint.py \
  --memory /tmp/footprint-p32-sequential-run01-memory.csv \
  --events /tmp/footprint-p32-sequential-run01-events.csv \
  --output /tmp/footprint-p32-sequential-run01-guest-output.txt \
  --interval 1 \
  > /tmp/footprint-p32-sequential-run01-analysis.txt
cat /tmp/footprint-p32-sequential-run01-analysis.txt
```

Require closure=END, application_page_start_reads=128 and per_page_reads=4.
The analyzer streams memory/events and keeps only O(page_count) read counters.
It matches exact reported VAs, checks the expected order separately in each
pass, and reports all extra selected records by memory type and operation.
LIMIT, EXIT, missing END, incomplete memory and wrong counts/order fail with
nonzero exit. VA matching is not verified process or privilege attribution;
other code accessing the same VAs can cause extra candidates and a failure.
No filtered trace is produced.

Replay the complete capture with zero warmup, retaining kernel and MMIO rows:

```sh
cd /home/ubuntu/qemu-work/qemu-replay
make
./build/qemu-replay \
  --memory /tmp/footprint-p32-sequential-run01-memory.csv \
  --walks /tmp/footprint-p32-sequential-run01-walks.csv \
  --events /tmp/footprint-p32-sequential-run01-events.csv \
  --interval 1 --warmup 0 \
  --config /home/ubuntu/qemu-work/qemu-replay/1d_modern_intel.cfg \
  --audit /tmp/footprint-p32-sequential-run01-audit.csv \
  --results /tmp/footprint-p32-sequential-run01-results.csv
```

`1d_modern_intel.cfg` is present. With no CLI overrides its effective baseline
configuration is:

| Level | Sets | Ways | Entries/capacity |
|---|---:|---:|---:|
| TLB L1 | 1 | 64 | 64 entries |
| TLB L2 | 128 | 12 | 1536 entries |
| Memory L2 | 1024 | 16 | 1,048,576 bytes (1 MiB) |
| Memory L3 | 32768 | 11 | 23,068,672 bytes (22 MiB) |

Cache lines are 64 bytes; supported translation sizes are 4 KiB, 2 MiB and
1 GiB. Walker-specific fields in that config do not enable other replay
models. The summary CSV reports the effective values. Start with --warmup 0:
--warmup counts **all captured accesses**, so --warmup equal to page_count
is not necessarily exactly one application pass.

## Larger cases and interval identity

After the 32-page sequential analyzer and replay succeed, use these cases:

| case_id prefix | Pages | Footprint | Passes | Expected page-start reads |
|---|---:|---:|---:|---:|
| footprint-p32-sequential | 32 | 128 KiB | 4 | 128 |
| footprint-p32-permuted | 32 | 128 KiB | 4 | 128 |
| footprint-p512-sequential | 512 | 2 MiB | 4 | 2048 |
| footprint-p512-permuted | 512 | 2 MiB | 4 | 2048 |
| footprint-p4096-sequential | 4096 | 16 MiB | 4 | 16384 |
| footprint-p4096-permuted | 4096 | 16 MiB | 4 | 16384 |

Separate user-managed captures use the launch template with each case_id
(e.g. footprint-p512-permuted-run01), then the matching guest command below.
Use its own memory, walks, events, guest-output, analysis, audit and results
filenames; select interval 1 when it is the only marked workload in that
capture. Do not automate VM lifecycle or operate a second VM on the same disk.

```sh
ssh -p 2222 -i /home/ubuntu/qemu-work/guest/guest_key ubuntu@localhost \
  './memtrace-footprint-test --pages 32 --passes 4 --pattern permuted' \
  > /tmp/footprint-p32-permuted-run01-guest-output.txt
ssh -p 2222 -i /home/ubuntu/qemu-work/guest/guest_key ubuntu@localhost \
  './memtrace-footprint-test --pages 512 --passes 4 --pattern sequential' \
  > /tmp/footprint-p512-sequential-run01-guest-output.txt
ssh -p 2222 -i /home/ubuntu/qemu-work/guest/guest_key ubuntu@localhost \
  './memtrace-footprint-test --pages 512 --passes 4 --pattern permuted' \
  > /tmp/footprint-p512-permuted-run01-guest-output.txt
ssh -p 2222 -i /home/ubuntu/qemu-work/guest/guest_key ubuntu@localhost \
  './memtrace-footprint-test --pages 4096 --passes 4 --pattern sequential' \
  > /tmp/footprint-p4096-sequential-run01-guest-output.txt
ssh -p 2222 -i /home/ubuntu/qemu-work/guest/guest_key ubuntu@localhost \
  './memtrace-footprint-test --pages 4096 --passes 4 --pattern permuted' \
  > /tmp/footprint-p4096-permuted-run01-guest-output.txt
```

Alternatively, the already tracing VM can capture the six invocations
serially in one host session. Before and after **each** invocation inspect
its host events CSV (for example `cat /tmp/memtrace-system-events.csv` if that
is its configured path). Note the last closed interval_id before starting;
the invocation's newly added BEGIN/END pair identifies its interval. Do not
run other marker programs concurrently. Store each invocation's stdout
separately, and use that pair's actual interval_id in both analyzer and replay.
There is no workload name or process ID in the event schema; do not infer
identity from an instruction PC or assume that interval 1 is yours. If there
are unexpected intervening markers, repeat with an unambiguous capture.

For a shared capture, point analyzer/replay at the same complete session CSVs
and use unique case-specific output/audit/results files. For separate captures,
substitute each case_id throughout the first-case commands. The cumulative
limit spans all invocations; if LIMIT or EXIT closes the selected interval,
analysis/replay fail. A later guest invocation cannot reset an exhausted limit.
Use complete sidecars and require END before accepting any result. No kernel
or MMIO records should be removed to manufacture application-only miss counts.

## Validation performed locally

The static build passed -Wall -Wextra -Werror. All six cases completed natively
with correct checksums and through user-mode QEMU with exact read counts and
per-pass order. All 32 local workload/analyzer checks passed; permutation
bijections were checked for page counts 1,2,...,65536 (powers of two).
No files were transferred, guest commands run, or VM lifecycle actions taken.
Full-system capture/replay of this new workload has not been performed.
