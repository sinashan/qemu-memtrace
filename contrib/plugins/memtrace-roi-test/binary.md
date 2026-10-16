# Direct inline binary+XZ capture

This is a runtime producer for the offline trace-codec's inline packet schema.
There are **no runtime dictionaries or architectural elisions**. The same
C-compatible serializer in `traces/trace-codec/wire.h` writes runtime and offline
packets, chunk headers/checksums, and file headers/footers. The runtime sink is
`memtrace-binary.h`; compression continues to use `memtrace-writer.h`.

The workspace must contain both `qemu-memtrace/` and `traces/trace-codec/` for the
shared-header build. Dependencies are the existing compiler/GLib and liblzma.
No QEMU core, paging API, replay simulator or statistical analyzer change is
needed. The existing full-system QEMU must export the x86 paging-walk API used
by CSV walks already. The serializer uses explicit byte order, not C structs.

## Options and artifacts

Plugin defaults remain legacy CSV for existing manual commands. Explicitly use:

```
format=inline-binary,binary=/NEW/ABSOLUTE/trace.bin.xz,events=/NEW/events.csv,roi=markers,compression=xz,compression-level=3,chunk-mib=4
```

* `format=csv|inline-binary`: explicitly select output format; plugin default CSV.
* `binary=/ABSOLUTE/PATH`: dedicated combined binary path, required in binary mode.
* `events=PATH`: required small plain progress sidecar in binary mode.
* `compression=xz`: required in binary mode; implied if omitted there. Preset
  `compression-level=0..9`, default 3. Single-threaded CRC64 XZ, as before.
* `chunk-mib=1..16`: binary uncompressed payload capacity, default 4 MiB.
* `roi=markers`: required for binary. Immediate mode has no ROI event contract
  and is rejected for binary rather than inventing synthetic intervals.
* `limit=N|unlimited`: unchanged cumulative callback cap; plugin default 1000.
  Numeric zero disables recording and emits an empty finalized session, with
  no invented LIMIT. Unlimited is distinct from numeric UINT64_MAX.
* `test-dual=on`: **test only**, disabled by default. Requires binary mode plus
  dedicated `memory=/NEW/ABSOLUTE/memory.csv.xz` and
  `walks=/NEW/ABSOLUTE/walks.csv.xz`. Both CSV and binary serialize the **same
  callback fields and single captured paging snapshot**. CSV writers use the
  same compression setting. No second walk or second VM execution is involved.

Binary requires full-system x86_64 TCG with initial **and maximum** vCPUs equal
to one (`-smp 1,maxcpus=1`); CPU IDs other than zero are rejected defensively in
callbacks. Unsupported paging modes remain literal diagnostic walk records,
not an installation error. User-mode, non-x86_64, multiple/hotpluggable CPUs,
CSV paths without test-dual, binary options in CSV mode, duplicate options,
invalid limits/levels/chunk sizes and nonabsolute binary paths are refused.

All dedicated outputs use exclusive O_EXCL/O_NOFOLLOW creation. Existing files,
hard links, symlinks, devices, aliases to QEMU's log and aliases between outputs
are refused without truncation. Failed installation can leave identifiable new
partials; it never overwrites an existing capture. Keep QEMU `-D` diagnostics
separate from the binary path. Do not analyze an actively recorded capture.

Runtime memory is one fixed-capacity chunk, bounded stack packets and existing
64 KiB byte/stdio buffers, plus liblzma's preset-dependent encoder allocation
(about 32 MiB at preset 3). Production binary avoids GString/CSV formatting per
access. The plugin's existing translated-PC userdata interning is unchanged;
it is instrumentation metadata, not a new trace-length dictionary. Test dual
mode additionally pays for both CSV writers and formatting.

## Provenance and compatibility

Runtime files use **version 2**, LIVE flag bit 3, with otherwise identical inline
packets, little-endian fields, numeric missing masks, chunk layout and CRCs.
Version-1 offline CSV artifacts and offline dictionary mode remain supported.
Version-1 meanings are unchanged. See
[wire format](../../../../traces/trace-codec/FORMAT.md).

Live provenance has no source CSVs. In version 2 the footer's two former CSV byte
slots are reserved zero and must be zero; inspection exposes them as **null /
unavailable**, not invented zero-byte CSV inputs. Producer (`runtime` versus
`offline-csv`), artifact finalization and benchmark/ROI completeness are separate
properties. A finalized LIMIT/EXIT/ERROR file remains incomplete/failed; FULL
means a finalized session, not that the benchmark reached END. No runtime PREFIX
or runtime dictionary feature is defined.

## Ordering, boundaries and failures

The existing trace lock serializes callback records, numbering and markers.
Paging is captured once for each emitted access. Every field the CSV path emits
is retained: all original registers including CR3 flags, observed and
reconstructed PAs, leaf size, status/comparison, and complete ordered raw PTE
values/entry addresses/levels. Unsupported/unavailable/partial/mismatch records
remain literal, with the same NA and comparison semantics as CSV.

Events follow all accesses through their access_sequence, before the next
access. Equal-boundary END/BEGIN events retain callback order. BEGIN/END can
repeat, including empty intervals. END closes an ROI, **not** the plugin session.
Numeric LIMIT is terminal; active plugin exit emits EXIT with NA CPU. Later
BEGIN cannot resume LIMIT/error/exhausted recording. Counters never wrap.

At END/LIMIT/EXIT, pending access chunks are flushed, the embedded event is
written and its chunk/XZ segment finalized, and only then is the matching plain
sidecar boundary written/flushed. BEGIN is also flushed before sidecar visibility.
There is one logical file header, multiple independently checksummed chunks and
possibly concatenated XZ segments, and **one completion footer only at clean
plugin exit**. No fsync or power-loss durability is promised.

Consequently, sidecar END and fully readable XZ boundary segments can exist
while a live plugin has **no final binary footer**. The decoder deliberately
rejects this as an unfinished session. A killed QEMU, absent footer, damaged
chunk, truncated XZ stream or trailing junk never passes full validation.

Write/compression/flush/close/serialization failure permanently suppresses
recording and later BEGINs, diagnoses incomplete capture, and emits ERROR where
possible. A healthy binary sink can finalize an explicit ERROR capture; a failed
binary sink cannot produce a trusted footer. A duplicate descriptor of the
exclusively created inode is kept across finalization/close; on failure the
footer segment is rolled back to its preceding flushed offset, where possible,
so it cannot masquerade as finalized. Sidecar close failure also invalidates
that footer. Any rollback/descriptor error is diagnosed as incomplete; runner
checks diagnostics as well as binary structure and sidecar equality. This is
process-level failure handling, not crash durability or a transactional filesystem.

## Incremental builds and small local tests

From `/home/ubuntu/qemu-work`:

```bash
make -C qemu-memtrace/build/contrib/plugins libmemtrace.so
make -C traces trace-codec/trace-codec
make -C traces test-codec
PYTHONDONTWRITEBYTECODE=1 python3 traces/tool-tests/test_run_experiment.py
# Existing small legacy user-mode tests, not a full-system VM:
(cd qemu-memtrace && python3 contrib/plugins/memtrace-roi-test/verify-compression.py)
```

`test_runtime.py` compiles the actual plugin into a deterministic callback harness
with stubbed QEMU APIs. It compares test-dual records with `trace-codec verify`
and checks byte-identical flattened inline packets against offline v1 inline
serialization. It covers 4 KiB/2 MiB/1 GiB paths, high/low PCs, RAM/MMIO/UNKNOWN,
missing/partial/unsupported/mismatching walks, A/D changes, chunk rollover,
zero/default/numeric/unlimited limits, empty/multiple intervals and later BEGIN,
active EXIT, finalized ERROR, injected post-END disk-full/codec/close/sidecar-close
failures, counter overflow, incompatible configuration and exclusive creation.
It checks that visible END is not a final footer, reconciles sidecars and rejects
corruption/truncation/junk. These are synthetic callback tests, **not proof of
full-system paging correctness**. Existing offline tests cover v1 dictionary and
inline compatibility, memory caps and malformed framing.

## Small full-system first-touch validation (future user-run commands)

No full-system VM or benchmark was started during this implementation. The
runner refuses an occupied port/disk and never adopts or stops an existing VM.
Install the static test in your guest using your normal provisioning procedure:

```bash
cd /home/ubuntu/qemu-work
cc -O2 -Wall -Wextra -static \
  qemu-memtrace/contrib/plugins/memtrace-roi-test/first-touch.c \
  -o qemu-memtrace/build/contrib/plugins/memtrace-first-touch
# Only when your intended provisioning guest is reachable:
scp -P 2222 -i guest/guest_key \
  qemu-memtrace/build/contrib/plugins/memtrace-first-touch \
  ubuntu@127.0.0.1:/home/ubuntu/memtrace-first-touch
```

After that guest has been shut down by you and the image is available for a new
owned runner VM, execute the small self-marked 16-page/two-pass test:

```bash
python3 traces/run_experiment.py \
  --name first-touch-inline-validation --limit unlimited \
  --trace-format inline-binary --test-dual-output --markers-in-benchmark \
  --guest-dir /home/ubuntu -- /home/ubuntu/memtrace-first-touch
```

`--markers-in-benchmark` prevents nested outer ROI markers. The runner validates
through binary EOF and matches events.csv, then performs logical record-by-record
verification against the simultaneously captured CSV+XZ streams. Successful
`logs/run.json` includes `binary_validation.test_dual_verified=true`. Run only on
a guest/image you intend the runner to own; no existing VM is automatically stopped.

For manual repetition after shutdown, set CAPTURE to the new directory:

```bash
traces/trace-codec/trace-codec verify --input "$CAPTURE/trace.bin.xz" \
  --capture "$CAPTURE" --memory-input memory.csv.xz --walks-input walks.csv.xz
```

## Normal DaCapo capture (future user-run command)

The built-in profile uses the existing absolute JAR path, and a unique UUID-suffixed
working directory under `/home/ubuntu/benchmarks/.memtrace-runs/` to isolate scratch
files. Override the profile/JAR if your guest installation differs.

```bash
python3 traces/run_experiment.py --profile dacapo-avrora-small \
  --name dacapo-avrora-small-inline --limit unlimited --copy-roi-run
```

Default artifacts: `trace.bin.xz`, plain `events.csv`, guest/VM diagnostics and
manifest under `logs/`. No CSV memory/walk streams are produced unless explicitly
selecting legacy mode or test-dual. The runner's default cap remains 1,000,000,000
when `--limit` is omitted. Add `--symbols` if desired. Normal capture uses the
outer ROI runner. All existing GAP/argument override/SSH/provenance/VM protections
remain; `--keep-vm` explicitly leaves finalization and validation pending.

Explicit legacy CSV+XZ:

```bash
python3 traces/run_experiment.py --trace-format csv --compression xz \
  --profile dacapo-avrora-small --limit unlimited
```

Raw legacy CSV additionally uses `--compression none`. Binary rejects that option.

The statistical analyzer and replay simulator do **not** directly consume binary.
A compatibility export streams directly to compressed CSV, with no large raw
intermediate, into a fresh directory:

```bash
traces/trace-codec/trace-codec decode --input "$CAPTURE/trace.bin.xz" \
  --output-dir "$CAPTURE/compat-csv" --csv-xz
```

This produces memory.csv.xz, walks.csv.xz, plain events.csv and a metadata sidecar.
Export is explicit, never automatic; downstream replay's CSV/XZ capabilities
remain its existing ones. No replay code was modified.
