#!/usr/bin/env python3
"""Validate a one-vCPU first-touch system trace; no guest execution here."""
import argparse
from collections import Counter
import csv
from itertools import zip_longest
from pathlib import Path
import re


def analyze(args):
    report = Path(args.guest_output).read_text()
    mapping = re.search(r"base=(0x[0-9a-f]+) page_size=(\d+) page_count=(\d+)",
                        report)
    assert mapping, "missing mapping report from this guest execution"
    base, size, count = int(mapping[1], 16), int(mapping[2]), int(mapping[3])
    assert count == 16
    assert "completed first-touch pass" in report and "completed resident pass" in report
    intervals = []
    active = None
    previous_close = 0
    with open(args.events) as stream:
        for number, event in enumerate(csv.DictReader(stream), 1):
            assert int(event["event_id"]) == number
            interval = int(event["interval_id"])
            position = int(event["access_sequence"])
            if event["event"] == "BEGIN":
                assert active is None and interval == len(intervals) + 1
                assert position == previous_close
                active = (interval, position)
            else:
                assert event["event"] in ("END", "LIMIT", "EXIT")
                assert active and active[0] == interval and position >= active[1]
                intervals.append((*active, position, event["event"]))
                previous_close = position
                active = None
    assert active is None, "event file contains an unclosed interval"
    summaries = {i: Counter() for i, *_ in intervals}
    writes = {i: [] for i, *_ in intervals}
    cpus = set()
    cursor = 0
    total = 0
    with open(args.memory) as memory, open(args.walks) as walks:
        for number, (access, walk) in enumerate(zip_longest(
                csv.DictReader(memory), csv.DictReader(walks)), 1):
            assert access is not None and walk is not None, "sidecar row count differs"
            total = number
            assert int(access["sequence"]) == int(walk["sequence"]) == number
            assert access["cpu"] == walk["cpu"]
            cpus.add(access["cpu"])
            assert len(cpus) == 1, "start validation with one guest CPU"
            assert int(access["data_va"], 16) == int(walk["data_va"], 16)
            assert access["data_pa"] == walk["callback_pa"]
            while cursor < len(intervals) and number > intervals[cursor][2]:
                cursor += 1
            assert cursor < len(intervals), "access outside a closed interval"
            interval, begin, end, closing = intervals[cursor]
            assert begin < number <= end
            path = walk["pte_path"]
            if path:
                assert re.fullmatch(r"[1-4]:0x[0-9a-f]+:0x[0-9a-f]+"
                                    r"(;[1-4]:0x[0-9a-f]+:0x[0-9a-f]+)*", path)
                levels = [int(token.split(":")[0]) for token in path.split(";")]
                assert levels == list(range(4, 4 - len(levels), -1))
            comparison = walk["comparison"]
            if walk["status"] == "OK" and walk["callback_pa"] != "NA":
                equal = int(walk["reconstructed_pa"], 16) == int(walk["callback_pa"], 16)
                assert comparison == ("match" if equal else "mismatch")
            else:
                assert comparison == "not-comparable"
            summaries[interval][comparison] += 1
            summaries[interval]["status:" + walk["status"]] += 1
            # Typical Linux high-half PC heuristic; not a privilege label.
            if int(access["pc_va"], 16) >= 0xffff800000000000:
                summaries[interval]["kernel_pc_heuristic"] += 1
            va = int(access["data_va"], 16)
            if (access["operation"] == "W" and access["size_bytes"] == "1"
                    and va in range(base, base + count * size, size)):
                writes[interval].append(walk)
    assert total == previous_close, "memory log ends before the final event boundary"
    assert args.intervals[0] != args.intervals[1], "select two distinct intervals"
    for interval, begin, end, closing in intervals:
        print(f"interval {interval}: sequences ({begin}, {end}], close={closing}, "
              f"{dict(summaries[interval])}")
    expected = [base + i * size for i in range(count)]
    for interval, name in zip(args.intervals, ("first-touch", "resident")):
        assert interval in writes, f"missing {name} interval {interval}"
        application = writes[interval]
        assert [int(w["data_va"], 16) for w in application] == expected, (
            f"{name}: expected all 16 page-start writes; check limit/interval selection")
        for walk in application:
            assert walk["status"] == "OK" and walk["comparison"] == "match", walk
            assert int(walk["leaf_size"]) == size, walk
            print(f"{name}: seq={walk['sequence']} va={walk['data_va']} "
                  f"pa={walk['callback_pa']} cr3={walk['cr3']} root={walk['root_pa']}")
        pages = {int(w["callback_pa"], 16) // size for w in application}
        print(f"{name}: 16 matching writes, {len(pages)} distinct physical pages")
    print("PASS: application page-start translations match callback PA")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--memory", required=True)
    parser.add_argument("--events", required=True)
    parser.add_argument("--walks", required=True)
    parser.add_argument("--guest-output", required=True)
    parser.add_argument("--intervals", nargs=2, type=int, default=[1, 2],
                        help="first-touch and resident interval IDs (default: 1 2)")
    try:
        analyze(parser.parse_args())
    except (AssertionError, KeyError, ValueError) as error:
        parser.exit(1, f"validation failed: {error}\n")
