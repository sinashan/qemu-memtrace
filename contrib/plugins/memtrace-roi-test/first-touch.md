# First-touch experiment

`first-touch.c` maps 16 anonymous writable pages without population, applies
`MADV_NOHUGEPAGE`, and reports the base and page size without touching the
mapping. A marked first pass writes one volatile byte at each page start;
a separately marked resident pass repeats those writes. Reports, flushing,
and unmapping occur outside the markers. There are no fault-counter
measurements or fixed fault-count assumptions in this version.

## Build and local run

From the QEMU source root, using the existing plugin:

```sh
cc -O2 -Wall -Wextra -static \
  -o build/contrib/plugins/memtrace-first-touch \
  contrib/plugins/memtrace-roi-test/first-touch.c
build/contrib/plugins/memtrace-first-touch
build/qemu-x86_64 \
  -plugin build/contrib/plugins/libmemtrace.so,roi=markers,limit=10000 \
  -d plugin -D /tmp/memtrace-first-touch.csv \
  build/contrib/plugins/memtrace-first-touch \
  > /tmp/memtrace-first-touch-output.txt
```

The executable is static and needs no guest dynamic loader or shared libc.
User-mode QEMU checks marker recognition and successful application writes;
it does not trace the guest Linux kernel. Native execution is also only a
basic execution check, not full-system tracing validation.

## Transfer and guest execution

```sh
scp -P 2222 -i ~/qemu-work/guest/guest_key \
  ~/qemu-work/qemu-8.2.10/build/contrib/plugins/memtrace-first-touch \
  ubuntu@localhost:~/memtrace-first-touch
ssh -p 2222 -i ~/qemu-work/guest/guest_key \
  ubuntu@localhost './memtrace-first-touch' \
  > /tmp/memtrace-first-touch-guest-output.txt
```

These are commands for the user to run; no VM lifecycle changes are needed.
The VM must already have been launched with memtrace in `roi=markers` mode
to produce a host CSV. The limit is cumulative across all earlier intervals;
if it is exhausted, this program cannot restart recording. Kernel activity
can consume substantially more records than the 32 application writes.

## Inspect the full-system host CSV

Use the base and page size from **that guest execution**, not a local run.
The 16 application page-start VAs are `base + i * page_size`, for `i=0..15`.
Filter `operation=W`, `size_bytes=1`, and `data_va` equal to one of these
addresses. Expect the application write pattern to visit all 16 addresses
in order in each pass, if the trace limit did not truncate recording.
The CSV records successful writes; the initial faulting attempts themselves
are absent from ordinary memory callbacks.

For these application rows, compare both `data_va` and `data_pa`. In system
mode RAM rows provide physical addresses; check the observed association of
each VA with its PA in each pass and the distinct physical page numbers
(`data_pa // page_size`). Do not assume physical pages are contiguous or
that VA/PA associations cannot change. User-mode records have `NA` for PA
and cannot perform this check.

Identify additional rows whose `pc_va` falls in the guest's kernel address
ranges. High-half PCs are a useful heuristic on typical x86-64 Linux setups,
but this is not a verified privilege-mode label. Guest kernel symbols or
known kernel ranges can improve the classification. High-half **data** VAs
alone do not identify which instruction performed the access.

The first group of 16 application writes identifies the first-touch pass;
the second group identifies the resident pass. Look for kernel-PC rows
before and among the first group, then compare with rows among the second
group. The current CSV has no marker rows or interval IDs, so it cannot
precisely assign every intervening kernel row to a pass. Recording is global:
other-vCPU and unrelated process activity may appear during either interval.
Kernel-looking accesses are evidence to inspect, not exact page-fault labels
or a way to count faults. Full-system behavior has not been validated locally.
