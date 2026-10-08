# Experimental x86 paging capture

This local extension requires rebuilding this QEMU checkout and the plugin;
it is not an API from QEMU master or stock QEMU 8.2.10. Existing plugins and
the memory/event CSV formats are preserved. The optional argument
`walks=/absolute/path/to/walks.csv` opens a separate host file during plugin
installation. Empty/relative paths, duplicates, user-mode/non-x86-64 targets,
and open/header errors are rejected. Use distinct memory, event, and walk files.
Runtime write/flush errors diagnose an incomplete sidecar on stderr and disable
further sidecar output while guest execution and memory recording continue.
The walk file uses a 1 MiB fully buffered stream. Each record write is checked;
the header flushes during installation and records flush at accepted END,
LIMIT, and shutdown/EXIT boundaries, including immediate-mode limit exhaustion
and shutdown. Flush and close failures mark the sidecar incomplete. After a
diagnosed failure there are no further writes or explicit flush attempts;
the stream is still closed and its buffer freed. An interrupted or crashed
run can lose buffered walk records; normal boundaries and shutdown flush them.

## Public API and internal hook

`qemu_plugin_x86_paging_walk(vcpu_index, data_va, &result)` is exported through
`include/qemu/qemu-plugin.h` and `plugins/qemu-plugins.symbols`. Call it only
inside a data-memory callback with that callback's vCPU index. `plugins/api.c`
checks `current_cpu` against the index and dispatches through the optional
`SysemuCPUOps.plugin_x86_paging_walk` target hook. Other targets and user mode
return UNAVAILABLE. The hook is installed only for x86-64 with TCG and plugins.
There are no internal CPU headers in the standalone plugin.

The x86 implementation in `target/i386/tcg/sysemu/plugin-paging.c` copies the
current guest CPU's CR3, CR0, CR4, EFER and configured `X86CPU.phys_bits`.
Root PA excludes the low 12 CR3 bits (PCID with PCIDE enabled, cache/control
bits otherwise) and uses the configured guest physical-width mask. No host
CR3 or host physical-width inference is involved. The guest's 1-GiB-page
capability is also passed to the decoder.

Entry reads use the current CPU's physical address space selected through
`cpu_get_mem_attrs()` and `cpu_addressspace()` (including the SMM address-space
selection). `memory_region_find()` resolves the flattened mapping without
invoking device or IOMMU translation operations. Only an entire eight-byte
entry in ordinary writable RAM is accepted. RCU and a region reference protect
the direct little-endian read. ROM, device RAM, MMIO, IOMMU regions, and
discard-managed RAM are rejected. No generic physical load/debug walk is
called: no MMIO reads, A/D writes, guest faults, TLB fills, or recursive plugin
memory callbacks are generated.

`target/i386/plugin-paging.h` contains the pure decoder shared with unit tests.
Production reads actual guest RAM; only tests supply synthetic table contents.
Supported mode is CR0.PG + CR4.PAE + EFER.LMA, with LA57 clear, ordinary A20
behavior and no nested paging. Architectural levels are 4=PML4, 3=PDPT, 2=PD,
1=PT. Supported leaves are 4096, 2097152 and 1073741824 bytes. The decoder checks
48-bit canonical addresses, present bits, physical-address reserved bits,
NX when NXE is disabled, PML4 PS, 1-GiB capability, and large-leaf alignment
while allowing PAT bit 12. It does not validate all access permissions.

Status/reason values are OK, UNAVAILABLE, UNSUPPORTED_MODE, UNSUPPORTED_LA57,
UNSUPPORTED_NESTED, UNSUPPORTED_A20, UNSUPPORTED_PHYS_BITS, NONCANONICAL,
NONPRESENT, RESERVED_CR3, RESERVED_ENTRY, NOT_RAM, and READ_FAILED.
Nonpresent and reserved entries are retained in the path. A failed read stops
before adding an entry whose raw value could not be recovered.

## Walk CSV

```text
sequence,cpu,data_va,cr3,root_pa,cr0,cr4,efer,phys_bits,status,leaf_size,reconstructed_pa,callback_pa,comparison,pte_path
```

There is one row for each memory record emitted within the ROI/limit, keyed
by the exact same sequence number, assuming successful sidecar I/O. Capture
and output occur under the existing trace mutex. No snapshot or walk occurs
when `walks` is absent or recording is disabled. Addresses/registers are hex;
physical width and leaf byte size are decimal. Failed walks use `NA` for leaf
size and reconstructed PA; unavailable snapshots use `NA` for paging fields.
Comparison is `match`, `mismatch`, or `not-comparable`. Mismatches remain
explicit; neither physical-address column is corrected to the other.

The final field is always CSV-quoted and contains ordered
`level:entry_pa:raw_value` tokens separated by semicolons, for example:

```text
"4:0x1010:0x2027;3:0x2000:0x3027;2:0x3000:0x4027;1:0x4008:0x12345067"
```

An empty path is `""`. Tokens contain only decimal levels, hexadecimal
numbers, colons and semicolons, so embedded quotes/newlines cannot arise.
Standard CSV readers recover the field; split it on `;`, then `:`.

## Build and local checks

```sh
cd ~/qemu-work/qemu-8.2.10
ninja -C build -j 4 qemu-system-x86_64 qemu-x86_64 tests/unit/test-x86-plugin-paging
make -C build/contrib/plugins libmemtrace.so
build/tests/unit/test-x86-plugin-paging
python3 contrib/plugins/memtrace-roi-test/verify.py
```

The eight decoder tests cover 4-KiB paths, both large leaves, CR3 PCID/control
masking, nonpresent entries at each level, unsupported modes/LA57, noncanonical
addresses, reserved bits, and read failures. The existing ROI/events suite
also checks malformed walks arguments and rejects walks in user mode before
creating a file. Only the configured x86-64 user/system builds were compiled;
other-target portability is structurally supported, not build-tested here.

## Full-system first-touch validation (commands only)

No VM was launched, stopped, or modified for these checks. The following is
for a future launch after the existing VM's disk and SSH port are available.
Start with one CPU and a fresh event/walk log. A larger limit leaves room for
kernel fault-handling accesses; LIMIT still makes truncation visible.

```sh
cd ~/qemu-work/qemu-8.2.10
cc -O2 -Wall -Wextra -static -o build/contrib/plugins/memtrace-first-touch \
  contrib/plugins/memtrace-roi-test/first-touch.c
build/qemu-system-x86_64 \
  -accel tcg -cpu max,la57=off -m 2G -smp 1 -nographic \
  -drive file=../guest/jammy-server-cloudimg-amd64.img,format=qcow2,if=virtio \
  -drive file=../guest/seed.iso,format=raw,media=cdrom,readonly=on \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22 \
  -device virtio-net-pci,netdev=net0 \
  -plugin build/contrib/plugins/libmemtrace.so,roi=markers,limit=1000000,events=/tmp/memtrace-system-events.csv,walks=/tmp/memtrace-system-walks.csv \
  -d plugin -D /tmp/memtrace-system.csv
```

In a separate host terminal, after guest SSH is ready:

```sh
scp -P 2222 -i ~/qemu-work/guest/guest_key \
  ~/qemu-work/qemu-8.2.10/build/contrib/plugins/memtrace-first-touch \
  ubuntu@localhost:~/memtrace-first-touch
ssh -p 2222 -i ~/qemu-work/guest/guest_key \
  ubuntu@localhost './memtrace-first-touch' \
  > /tmp/memtrace-first-touch-guest-output.txt
cd ~/qemu-work/qemu-8.2.10
python3 contrib/plugins/memtrace-roi-test/analyze-walks.py \
  --memory /tmp/memtrace-system.csv \
  --events /tmp/memtrace-system-events.csv \
  --walks /tmp/memtrace-system-walks.csv \
  --guest-output /tmp/memtrace-first-touch-guest-output.txt
```

The analyzer checks one-to-one sequence/CPU/VA/callback-PA joins and complete
event coverage, groups all walk statuses/comparisons by interval, and validates
all 16 one-byte application page-start writes in each pass against callback PA.
It reports CR3/root and distinct physical-page counts. If earlier workloads
created intervals, select the two first-touch IDs with `--intervals A B`.
Kernel-looking PC counts use a typical Linux high-half-address heuristic,
not a verified privilege-mode label. No full-system result is claimed here.

## Correctness limits

Memory callbacks occur after successful accesses. This walk observes current
page-table contents, not the original faulting attempt. It does not recover
the PTEs used for an existing cached translation. Stale cached translations,
concurrent vCPU/DMA table edits, or mapping changes can cause mismatches or
inconsistent paths. The multi-entry walk is not an atomic snapshot, and a raw
entry read is not a guarantee against concurrent tearing on every host.

No complete x86 permission/fault validation is performed (RW/US, NX access
intent, WP, SMEP/SMAP, protection keys, etc.). Raw entries retain permission
and A/D bits for later analysis. LA57, non-long paging/disabled paging, nested
paging, disabled A20, unusual physical widths and nonordinary table backing
are explicit unsupported/failure results. Encrypted/other special memory
configurations are outside the intended diagnostic scope.

These observational reads are not guest memory records or simulated walk
costs. A future simulator must generate and charge its own walk accesses.
CR3 capture alone does not model invalidations, PCID lifetimes, or mapping
history. The first-touch workload and Linux kernel are unchanged.
