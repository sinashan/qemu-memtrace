#!/usr/bin/env python3
"""Run from the QEMU source root after building the plugin and guest test."""
import csv
from pathlib import Path
import re
import resource
import shlex
import signal
import subprocess
import tempfile

QEMU = "build/qemu-x86_64"
PLUGIN = "build/contrib/plugins/libmemtrace.so"
GUEST = "build/contrib/plugins/memtrace-roi-test"
HEADER = "sequence,cpu,pc_va,data_va,data_pa,size_bytes,operation,memory_type"
EVENT_HEADER = "event_id,interval_id,event,cpu,access_sequence"


def run(directory, name, options, guest):
    path = directory / (name + ".csv")
    result = subprocess.run(
        [QEMU, "-plugin", PLUGIN + options, "-d", "plugin", "-D",
         str(path), guest], capture_output=True, text=True, check=True)
    assert not result.stderr, result.stderr
    with path.open() as stream:
        rows = list(csv.reader(stream))
    assert rows.pop(0) == HEADER.split(",")
    for number, row in enumerate(rows, 1):
        assert len(row) == 8 and int(row[0]) == number
        assert int(row[1]) >= 0
        assert all(v.startswith("0x") and int(v, 16) >= 0 for v in row[2:4])
        assert row[4] == "NA" and row[7] == "UNKNOWN"
        assert int(row[5]) in (1, 2, 4, 8, 16, 32, 64)
        assert row[6] in ("R", "W")
    print(f"{name}: {len(rows)} valid records")
    return rows, result.stdout


def region_accesses(rows, start, size):
    # Check overlap, including an access starting before the region.
    return [r for r in rows if int(r[3], 16) < start + size
            and int(r[3], 16) + int(r[5]) > start]


def run_events(directory, name, options, guest, expected):
    path = directory / (name + "-events.csv")
    rows, output = run(directory, name, options + ",events=" + str(path), guest)
    with path.open() as stream:
        events = list(csv.reader(stream))
    assert events.pop(0) == EVENT_HEADER.split(",")
    assert [e[2] for e in events] == expected
    active = None
    interval = 0
    partition = []
    for number, event in enumerate(events, 1):
        assert len(event) == 5 and int(event[0]) == number
        position = int(event[4])
        assert 0 <= position <= len(rows)
        if event[2] == "BEGIN":
            assert active is None
            interval += 1
            active = position
        else:
            assert active is not None and position >= active
            partition.extend(range(active + 1, position + 1))
            active = None
        assert int(event[1]) == interval
        if event[2] == "EXIT":
            assert event[3] == "NA"
        else:
            assert event[3] != "NA" and int(event[3]) >= 0
    assert active is None
    if expected:
        assert partition == [int(r[0]) for r in rows]
    print(f"{name}: events {expected}, interval ranges verified")
    return rows, events


with tempfile.TemporaryDirectory(prefix="memtrace-roi-") as temp:
    directory = Path(temp)
    for name, options, expected in [
        ("default", "", 1000), ("default-10", ",limit=10", 10),
        ("immediate-10", ",roi=immediate,limit=10", 10),
        ("immediate-zero", ",limit=0,roi=immediate", 0),
        ("markers-true", ",roi=markers", 0),
        ("markers-zero", ",roi=markers,limit=0", 0),
    ]:
        rows, _ = run(directory, name, options, "/bin/true")
        assert len(rows) == expected

    for name, options, marked in [
        ("marked-loop", ",roi=markers,limit=10000", True),
        ("unlimited-loop", ",limit=unlimited,roi=markers", True),
        ("immediate-loop", ",limit=100000,roi=immediate", False),
    ]:
        rows, output = run(directory, name, options, GUEST)
        match = re.fullmatch(
            r"pre=(0x[0-9a-f]+) active=(0x[0-9a-f]+) "
            r"post=(0x[0-9a-f]+) bytes=(\d+)\n", output)
        assert match, output
        pre, active, post = (int(v, 16) for v in match.groups()[:3])
        size = int(match[4])
        assert {r[6] for r in region_accesses(rows, active, size)} == {"R", "W"}
        for address in (pre, post):
            accesses = region_accesses(rows, address, size)
            assert not accesses if marked else bool(accesses)
        print(f"{name}: pre/post exclusion and active reads/writes verified")

    for options in (",roi=markers,limit=5", ",limit=5,roi=markers"):
        rows, _ = run(directory, "marked-limit-5", options, GUEST)
        assert len(rows) == 5

    run_events(directory, "events-two-intervals", ",roi=markers,limit=10000",
               GUEST, ["BEGIN", "END", "BEGIN", "END"])
    unlimited_rows, _ = run_events(
        directory, "events-unlimited", ",roi=markers,limit=unlimited",
        GUEST, ["BEGIN", "END", "BEGIN", "END"])
    numeric_rows, _ = run_events(
        directory, "events-numeric-control", ",limit=10000,roi=markers",
        GUEST, ["BEGIN", "END", "BEGIN", "END"])
    assert len(unlimited_rows) == len(numeric_rows)
    run_events(directory, "events-unlimited-no-markers",
               ",roi=markers,limit=unlimited", "/bin/true", [])
    immediate_unlimited, _ = run_events(
        directory, "events-unlimited-immediate", ",limit=unlimited",
        "/bin/true", [])
    assert len(immediate_unlimited) > 1000
    run_events(directory, "events-unlimited-exit",
               ",roi=markers,limit=unlimited",
               "build/contrib/plugins/memtrace-exit-active", ["BEGIN", "EXIT"])
    rows, events = run_events(directory, "events-limit", ",roi=markers,limit=5",
                              GUEST, ["BEGIN", "LIMIT"])
    assert len(rows) == 5 and events[-1][4] == "5"
    run_events(directory, "events-no-markers", ",roi=markers", "/bin/true", [])
    run_events(directory, "events-zero", ",roi=markers,limit=0", GUEST, [])
    rows, _ = run_events(directory, "events-immediate", ",roi=immediate,limit=10",
                         GUEST, [])
    assert len(rows) == 10
    run_events(directory, "events-exit", ",roi=markers,limit=10000",
               "build/contrib/plugins/memtrace-exit-active", ["BEGIN", "EXIT"])

    invalid = ["limit=", "limit=-1", "limit=+1", "limit=abc", "limit=1x",
               "limit= 1", "limit=18446744073709551616", "foo=1", "limit",
               "limit=1,limit=2", "roi=", "roi=unknown", "roi",
               "roi=markers,roi=markers", "roi=immediate,roi=markers",
               "events=", "events=a,events=b", "walks=", "walks=relative.csv",
               "walks=/tmp/a.csv,walks=/tmp/b.csv", "limit=Unlimited",
               "limit=unlimitedx", "limit= unlimited", "limit=unlimited ",
               "limit=unlimited,limit=1", "limit=0,limit=unlimited",
               "limit=unlimited,limit=unlimited"]
    for options in invalid:
        result = subprocess.run(
            [QEMU, "-plugin", PLUGIN + "," + options, "/bin/true"],
            capture_output=True, text=True)
        assert result.returncode != 0
        assert "memtrace: invalid argument" in result.stderr
    print(f"{len(invalid)} invalid argument cases rejected clearly")

    # Test-only counter injection in a temporary plugin: exercising uint64
    # exhaustion must not require emitting 2**64 records or a production knob.
    source = Path("contrib/plugins/memtrace.c").read_text()
    assert source.count("static uint64_t sequence;") == 1
    overflow_source = directory / "overflow.c"
    overflow_source.write_text(source.replace(
        "static uint64_t sequence;",
        "static uint64_t sequence = UINT64_MAX - 1;"))
    overflow_plugin = directory / "overflow.so"
    cflags = shlex.split(subprocess.check_output(
        ["pkg-config", "--cflags", "glib-2.0"], text=True))
    subprocess.run(["cc", "-shared", "-fPIC", "-Wall", "-Wextra",
                    "-Wno-unused-parameter", "-Werror", "-Iinclude/qemu",
                    "-Icontrib/plugins",
                    *cflags, str(overflow_source), "-llzma", "-o", str(overflow_plugin)],
                   check=True)
    for cap, closing in [("unlimited", "END"),
                         ("18446744073709551615", "LIMIT")]:
        memory = directory / ("overflow-" + cap + ".csv")
        events = directory / ("overflow-" + cap + "-events.csv")
        result = subprocess.run(
            [QEMU, "-plugin", str(overflow_plugin) +
             ",roi=markers,limit=" + cap + ",events=" + str(events),
             "-d", "plugin", "-D", str(memory), GUEST],
            capture_output=True, text=True, check=True)
        with memory.open() as f:
            records = list(csv.DictReader(f))
        assert [int(r["sequence"]) for r in records] == [2**64 - 1]
        with events.open() as f:
            boundaries = list(csv.DictReader(f))
        assert [r["event"] for r in boundaries] == ["BEGIN", closing]
        assert int(boundaries[-1]["access_sequence"]) == 2**64 - 1
        if cap == "unlimited":
            assert result.stderr.count("access sequence counter exhausted") == 1
            assert "capture incomplete" in result.stderr
        else:
            assert not result.stderr, result.stderr
    print("sequence overflow guarded; numeric UINT64_MAX retains LIMIT")

    walk_path = directory / "user-walks.csv"
    result = subprocess.run(
        [QEMU, "-plugin", PLUGIN + ",walks=" + str(walk_path), "/bin/true"],
        capture_output=True, text=True)
    assert result.returncode != 0
    assert "walks requires full-system x86_64 TCG" in result.stderr
    assert not walk_path.exists()
    print("walks rejected in user mode before file creation")

    # Validate before opening: a later bad option must not truncate a file.
    sentinel = directory / "sentinel.csv"
    sentinel.write_text("preserve me\n")
    result = subprocess.run(
        [QEMU, "-plugin", PLUGIN + ",events=" + str(sentinel) + ",roi=bad",
         "/bin/true"], capture_output=True, text=True)
    assert result.returncode != 0 and sentinel.read_text() == "preserve me\n"

    for path, error in [(directory / "missing" / "events.csv", "open failed"),
                        (directory, "open failed"),
                        (Path("/dev/full"), "open failed")]:
        result = subprocess.run(
            [QEMU, "-plugin", PLUGIN + ",events=" + str(path), "/bin/true"],
            capture_output=True, text=True)
        assert result.returncode != 0 and error in result.stderr, result.stderr
    print("invalid paths, header write failure, and parse-error cleanup verified")

    def restrict_event_file():
        # Header fits; the first boundary flush exceeds the limit. Ignore
        # SIGXFSZ so stdio returns an error for the plugin to handle.
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        resource.setrlimit(resource.RLIMIT_FSIZE, (64, 64))

    result = subprocess.run(
        [QEMU, "-plugin", PLUGIN + ",events=" + str(directory / "write-error.csv")
         + ",roi=markers,limit=10000", GUEST], capture_output=True, text=True,
        preexec_fn=restrict_event_file)
    assert result.returncode == 0, result.stderr
    assert result.stderr.count("events write/flush failed") == 1, result.stderr
    assert "pre=" in result.stdout
    print("runtime boundary write failure diagnosed once; recording stopped; guest completed")

    # Some checkouts also build i386 user emulation; installation must reject
    # its architecture before attempting to load the x86-64 guest executable.
    other = Path("build/qemu-i386")
    if other.exists():
        result = subprocess.run(
            [str(other), "-plugin", PLUGIN + ",roi=markers", "/bin/true"],
            capture_output=True, text=True)
        assert result.returncode != 0
        assert "roi=markers requires an x86_64 guest" in result.stderr
        print("unsupported i386 architecture rejected clearly")

print("PASS")
