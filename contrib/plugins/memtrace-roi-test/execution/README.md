# Isolated execution-translation checks

`guest.S`/`guest.ld` build a tiny multiboot x86 guest with controlled actual
page tables. This is not a Linux workload. `verify.py` runs only fresh diskless,
networkless, time-bounded TCG instances; it does not contact an existing VM or
open a guest disk. Captures/exports/results are retained in a fresh directory
under `build/contrib/plugins/execution-*`.

From `/home/ubuntu/qemu-work`, build and run:

```sh
make -C qemu-memtrace/build -j4 qemu-system-x86_64 qemu-x86_64
make -C qemu-memtrace/build/contrib/plugins libmemtrace.so
make -C traces trace-codec/trace-codec
make -C qemu-replay
python3 qemu-memtrace/contrib/plugins/memtrace-roi-test/execution/verify.py
```

The script saves exact QEMU arguments in each `command.json`. It verifies actual
captured physical frames; it does not infer noncontiguity from Linux allocation.
The first 16-byte access at VA `0x400ff8` reaches PA `0x300ff8` then `0x500000`.
After modifying the real leaf and executing INVLPG it reaches `0x700ff8` then
`0x500000`. Additional cases cover contiguous frames, large-page subdivisions,
2/4/8-byte crossings, aligned/noncrossing controls, MMIO bypass, same-PA NX
changes, same-value CR3, CR0/CR4/EFER updates and an outside-ROI root change.
A page-two fault produces no successful memory group. Three normal intervals
include an empty interval and fresh initial snapshots.

This opt-in plugin format requires one full-system x86-64 TCG CPU and marker
mode. It records after-state context updates and applies an **explicitly
conservative all-entry/all-global invalidation policy** in replay. PCIDE/exact
PCID retention, INVPCID CPU implementation, nested paging and Virt-Walker
invalidation are unsupported. Existing CSV and v2 modes keep their previous
semantics. Extended export is JSONL; legacy CSV export is refused for v3.

Detailed API, hook sites, counter definitions, format and replay commands:
[/home/ubuntu/qemu-work/qemu-replay/EXECUTION_TRACES.md](/home/ubuntu/qemu-work/qemu-replay/EXECUTION_TRACES.md),
and `traces/trace-codec/FORMAT.md` in the workspace.
