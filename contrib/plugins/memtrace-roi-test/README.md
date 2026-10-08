# memtrace guest markers

`roi=immediate` (default) records from the start as before. `roi=markers`
starts disabled and requires an x86-64 guest. `limit=N` defaults to 1000;
options may appear in any order, once each. Optional `events=PATH` writes a
separate host-side event CSV, opening/truncating the file during installation.
An empty path, duplicate option, open failure, or header write failure rejects
installation. Without this option, behavior is unchanged.

Markers are eight-byte NOPs identified by instruction length and raw bytes:

- BEGIN: `0f 1f 84 00 56 57 42 47`
- END: `0f 1f 84 00 56 57 45 4e`

Recording changes when these instructions execute. BEGIN enables a global
interval; END disables it. Repeating either marker is harmless. Record numbers
and the limit are cumulative across intervals. Once the limit is reached,
BEGIN cannot resume recording. No marker messages or summaries enter the CSV.

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
Runtime write/flush failures are diagnosed on stderr and disable further event
writes while the guest and memory recording continue; that event file is
incomplete. Close errors also go to stderr. Use separate paths for the event
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
