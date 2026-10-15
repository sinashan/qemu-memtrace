# Direct streaming CSV compression

The example plugin now requires liblzma development headers/library (found
locally: 5.2.4). No dependencies are installed automatically. Other example
plugins do not gain liblzma linkage. Build incrementally:

```sh
cd /home/ubuntu/qemu-work/qemu-memtrace
pkg-config --modversion liblzma
make -C build/contrib/plugins libmemtrace.so
python3 contrib/plugins/memtrace-roi-test/verify.py
python3 contrib/plugins/memtrace-roi-test/verify-compression.py
build/tests/unit/test-x86-plugin-paging
```

## Options and preservation

- `compression=none|xz`, default `none`, applies to both dedicated memory and
  walk outputs. Events always remain plain text.
- `memory=/absolute/path`: dedicated memory CSV, raw or XZ. When absent, the
  original `qemu_plugin_outs()` / `-d plugin -D FILE` memory output remains.
- `walks=/absolute/path`: the existing full-system x86-64 paging capture.
- `compression-level=0..9`: XZ preset, default 3; rejected without `compression=xz`.
- `compression=xz` requires `memory=`. Compressed bytes never enter QEMU's log.
- Existing `roi=immediate|markers`, default numeric limit 1000, numeric zero,
  and `limit=unlimited` retain their capture semantics.

No encodings, addresses, raw PTE values, NA/status fields, sequence numbers or
CSV columns change. No binary format or deduplication is introduced. Dedicated
memory/walk/event files are exclusively created with mode 0600: existing files,
symlinks, devices, hard links to existing inputs/outputs, and aliasing new
output names are rejected rather than truncated. A failed installation may
leave new partial files; preserve them and choose fresh names for another run.
This intentionally changes the former sidecar truncation behavior. The default
QEMU-managed `-D` log still has QEMU's own creation/error behavior: select a
fresh log path yourself. The void `qemu_plugin_outs()` API cannot report its
write errors back to this plugin; use dedicated `memory=` for checked memory
output. Never point diagnostics at a dedicated capture file.

## Framing, synchronization and memory

Compression is synchronous under the existing trace mutex, with one encoder
per dedicated output; it does not implement four compression threads or a
worker queue. Each writer has 64 KiB input, 64 KiB codec-output and 64 KiB
stdio buffers (192 KiB), independent of trace length. On this liblzma,
`lzma_easy_encoder_memusage(3)` reports 32,608,783 bytes, about 31.1 MiB per
active encoder; two active outputs use about 62.2 MiB plus fixed buffers.
Higher presets may use substantially more memory. This bounds output buffering
even with unlimited recording. Existing immutable instruction-PC metadata still
grows with distinct instrumented PCs, not with output record count.

XZ uses CRC64 and liblzma's preset 3, like single-threaded `xz -3`. Installation
writes exactly one CSV header, immediately finalizes its own XZ stream, and
flushes stdio. Subsequent data uses independently finalized concatenated streams:
one for each nonempty ROI. Streams are started lazily; an empty interval emits
its BEGIN/END events but adds no data stream or second header. END finalizes
both encoders and flushes both files before emitting/flushing the plain END
event. A later BEGIN can produce another stream without resetting sequence
numbers. LIMIT finalizes after the final capped record; an active EXIT or normal
immediate-mode exit finalizes remaining data. Immediate mode uses a header
stream and one data stream ending at LIMIT or exit. Numeric zero/no-marker
execution leaves a valid header-only stream. Ordinary raw mode uses the same
writer's checked writes and boundary flushes.

`xz -dc` and Python `lzma.open()` decode concatenated streams to one ordinary
single-header CSV. Files are fully readable at a successful boundary even while
QEMU continues running, provided no later marked interval is active. Completion
means codec/stdio availability, **not fsync durability**. Do not run integrity
checks on a currently active stream and mistake its unfinished footer for an
I/O failure.

## Failure and completion checks

Every writer write, encoder initialization/code operation, boundary flush and
close is checked. A diagnosed failure permanently stops recording, blocks
later BEGINs, reports `capture incomplete` on stderr, and attempts a terminal
`ERROR` event using the unchanged event CSV columns. ERROR's access sequence is
the last allocated record number; buffered/failed records need not be present
in both files. No END, LIMIT or EXIT is subsequently advertised as successful.
If the events sink itself fails, an ERROR event cannot be relied upon: stderr
is mandatory evidence. Failed writers get no further writes/explicit flushes;
`fclose` still performs necessary cleanup. The guest continues executing.
If a close failure is discovered after an earlier END, ERROR/stderr overrides
that earlier apparent completion. Event close failures are diagnosed on stderr.
Readers must reject ERROR rather than interpreting it as a normal closure.

An abnormal termination can leave a truncated stream or stale END from an
earlier interval. **END alone is insufficient**: require no ERROR/write/close
diagnostics, matching memory/walk sequences, and successful integrity checks
on the complete capture. After capture completes, without modifying originals:

```sh
xz -t /fresh/capture/memory.csv.xz /fresh/capture/walks.csv.xz
xz -dc /fresh/capture/memory.csv.xz | head -n 5
df -h /fresh/capture
```

Compression is lossless but gives no disk-usage cap. Preserve existing captures
and monitor free space. Unlimited recording still relies on wrapper END;
startup/loading/teardown and concurrent kernel/other-process activity remain
inside the global interval. Killing the wrapper does not guarantee END.

## Launch arguments (instructions only)

Use a new host directory and append these options to your established VM launch
only when launching is independently intended. Do not start a second VM on the
existing disk or port. This change was tested without launching a system VM.

```sh
capture_dir=$(mktemp -d /home/ubuntu/qemu-work/traces/xz-capture-XXXXXX)
# QEMU arguments, in addition to the existing disk/network/CPU configuration:
# -accel tcg -smp 1
# -plugin /home/ubuntu/qemu-work/qemu-memtrace/build/contrib/plugins/libmemtrace.so,roi=markers,limit=unlimited,compression=xz,compression-level=3,memory=$capture_dir/memory.csv.xz,walks=$capture_dir/walks.csv.xz,events=$capture_dir/events.csv
# -d plugin -D $capture_dir/qemu-diagnostics.log
```

The experiment runner now accepts the following **future user-run** command:

```sh
cd /home/ubuntu/qemu-work
python3 traces/run_experiment.py --profile gap-bfs-small \
  --compression xz --compression-level 3 --limit unlimited \
  --key /home/ubuntu/qemu-work/guest/guest_key --port 2222 \
  -- ./bfs -g 12 -n 1
```

The runner manages its own VM lifecycle; it must not be run against the current
VM's occupied disk/port. It was NOT executed during this change. It creates a
fresh directory, names memory/walk files `.csv.xz`, keeps diagnostics in
`logs/qemu-diagnostics.log`, and records compression/preset/thread count and
actual `-icount shift=0,align=off,sleep=on`, `-rtc clock=vm` settings in run
metadata. Its read-only completion checks detect ERROR, memtrace stderr errors,
missing outputs and truncated/corrupt XZ using bounded streaming decompression.
These checks do not substitute for replay's memory/walk join validation. A
numeric LIMIT still identifies truncation, not a completed workload interval.
Baseline/replay tools currently consume CSV paths; compression does not change
those readers. Decompress saved captures separately when needed, retaining the
matching event file and originals.

## Validation scope

Local tests compare raw/XZ bytes for controlled user-mode captures, limits,
multiple and empty ROIs, LIMIT, EXIT, and contiguous sequences; they inspect
decoded files at END before process exit. Direct writer fixtures exercise walk
CSV fields, multi-buffer streams, concatenation, codec initialization failure,
disk-full write/flush errors, close failure and truncated-XZ detection. Tests
also cover exclusive creation, aliases/hardlinks, QEMU-log collision, and
terminal ERROR with no later reopening. Existing ROI/overflow tests and the
eight paging decoder tests are retained. Runner tests mock all VM/network
operations. These tests do **not** validate full-system guest PA capture,
measure compression throughput, or prove fsync durability.
