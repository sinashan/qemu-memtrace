#!/usr/bin/env python3
"""Stream a complete memory CSV; validate one reported workload/ROI, not a filtered replay."""
import argparse
import collections
import csv
import sys

MH = 'sequence,cpu,pc_va,data_va,data_pa,size_bytes,operation,memory_type'.split(',')
EH = 'event_id,interval_id,event,cpu,access_sequence'.split(',')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def report(path):
    found = []
    with open(path) as stream:
        for line in stream:
            if line.startswith('base='):
                fields = dict(token.split('=', 1) for token in line.split())
                found.append(fields)
    require(len(found) == 1, 'workload output must contain exactly one mapping report')
    r = found[0]
    for key in ['base', 'page_size', 'page_count', 'footprint_bytes', 'passes', 'pattern',
                'stride', 'expected_page_start_reads']:
        require(key in r, 'missing workload field: ' + key)
    for key in r:
        if key != 'pattern':
            r[key] = int(r[key], 16 if key == 'base' else 10)
    pages = r['page_count']
    require(r['page_size'] == 4096 and 1 <= pages <= 65536 and not pages & (pages-1),
            'invalid workload page size/count')
    require(1 <= r['passes'] <= 1000000, 'invalid workload passes')
    require(r['base'] >= 0 and r['base'] % 4096 == 0 and
            r['base'] + r['footprint_bytes'] <= 1 << 64, 'invalid workload mapping range')
    require(r['footprint_bytes'] == pages * 4096 and
            r['expected_page_start_reads'] == pages * r['passes'], 'inconsistent workload counts')
    require(r['pattern'] in ['sequential', 'permuted'], 'invalid workload pattern')
    stride = pages // 2 + 1 if r['pattern'] == 'permuted' and pages >= 4 else 1
    require(r['stride'] == stride, 'unexpected permutation stride')
    return r


def records(path, header):
    with open(path, newline='') as stream:
        reader = csv.DictReader(stream)
        require(reader.fieldnames == header, 'incorrect header in ' + str(path))
        for row in reader:
            require(None not in row and all(value is not None for value in row.values()),
                    'wrong CSV column count in ' + str(path))
            yield row


def interval(path, wanted):
    active = None
    chosen = None
    last = eid = iid = 0
    for r in records(path, EH):
        require(int(r['event_id']) == eid + 1, 'invalid event_id order')
        eid += 1
        seq, ident = int(r['access_sequence']), int(r['interval_id'])
        require(seq >= last, 'decreasing event access_sequence')
        if r['event'] == 'BEGIN':
            require(active is None and ident == iid + 1 and seq == last, 'invalid BEGIN transition')
            iid = ident
            active = (ident, seq)
        else:
            require(active is not None and active[0] == ident and r['event'] in ['END', 'LIMIT', 'EXIT'],
                    'invalid closing event')
            if ident == wanted:
                require(r['event'] == 'END', 'selected interval is LIMIT-truncated/incomplete: ' + r['event'])
                chosen = (active[1], seq)
            active = None
        last = seq
    require(chosen is not None, 'selected interval missing/incomplete (requires BEGIN and END)')
    return chosen


def analyze(memory, events, output, selected):
    r = report(output)
    begin, end = interval(events, selected)
    counts = [0] * r['page_count']
    matched = inside = sequence = 0
    extras = collections.Counter()
    for row in records(memory, MH):
        current = int(row['sequence'])
        require(current == sequence + 1, 'missing/duplicate/out-of-order memory sequence')
        sequence = current
        if not begin < current <= end:
            continue
        inside += 1
        va = int(row['data_va'], 0)
        offset = va - r['base']
        at_start = 0 <= offset < r['footprint_bytes'] and offset % 4096 == 0
        if at_start and row['operation'] == 'R':
            require(int(row['size_bytes']) == 1, 'page-start read has unexpected size at sequence ' + str(current))
            index = offset // 4096
            expected = ((matched % r['page_count']) * r['stride']) & (r['page_count'] - 1)
            require(index == expected, 'wrong application page order/duplicate at sequence ' + str(current))
            counts[index] += 1
            matched += 1
        else:
            extras[(row['memory_type'], row['operation'])] += 1
    require(sequence >= end and inside == end - begin, 'selected interval memory records missing')
    require(matched == r['expected_page_start_reads'] and all(n == r['passes'] for n in counts),
            f'page-start reads incomplete: got {matched}, expected {r["expected_page_start_reads"]}; '
            f'per-page range {min(counts)}..{max(counts)}, expected {r["passes"]}')
    print(f'interval={selected} begin_sequence={begin} end_sequence={end} closure=END')
    print(f'application_page_start_reads={matched} pages={len(counts)} passes={r["passes"]} '
          f'pattern={r["pattern"]} order=verified per_page_reads={r["passes"]}')
    print(f'interval_records={inside} extra_records={inside-matched}')
    for (kind, operation), count in sorted(extras.items()):
        print(f'extra memory_type={kind} operation={operation} records={count}')
    print('Extra records remain in the original CSV for replay; no filtered trace was created.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--memory', required=True)
    parser.add_argument('--events', required=True)
    parser.add_argument('--output', required=True, help='stdout from exactly one guest invocation')
    parser.add_argument('--interval', type=int, default=1)
    args = parser.parse_args()
    try:
        require(args.interval > 0, 'interval must be positive')
        analyze(args.memory, args.events, args.output, args.interval)
    except (ValueError, OSError, KeyError, csv.Error) as error:
        print('analyze-footprint: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
