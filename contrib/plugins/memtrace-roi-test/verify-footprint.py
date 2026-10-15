#!/usr/bin/env python3
"""Local standalone footprint checks; never connect to a guest or manage a VM."""
import argparse
import csv
import importlib.util
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('footprint_analysis', ROOT/'analyze-footprint.py')
analysis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analysis)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', required=True)
parser.add_argument('--qemu')
parser.add_argument('--plugin')
args = parser.parse_args()
assert bool(args.qemu) == bool(args.plugin), '--qemu and --plugin must be supplied together'
binary = str(Path(args.binary).resolve())

# Validate exact markers/compiler barriers against the preserved workload.
for name in ['BEGIN', 'END']:
    pattern = rf'#define {name}\(\).*?" ::: "memory"\)'
    original = re.search(pattern, (ROOT/'first-touch.c').read_text(), re.S).group()
    assert re.search(pattern, (ROOT/'footprint-test.c').read_text(), re.S).group() == original
for exponent in range(17):
    pages = 1 << exponent
    stride = pages // 2 + 1 if pages >= 4 else 1
    order = [(i * stride) & (pages-1) for i in range(pages)]
    assert len(set(order)) == pages and sorted(order) == list(range(pages))

cases = 0
with tempfile.TemporaryDirectory(prefix='footprint-checks-') as directory:
    directory = Path(directory)
    for pages in [32,512,4096]:
        for pattern in ['sequential','permuted']:
            name = f'p{pages}-{pattern}'
            flags = ['--pages',str(pages),'--passes','4','--pattern',pattern]
            native = subprocess.run([binary,*flags],capture_output=True,text=True,check=True)
            checksum = re.search(r'checksum=(\d+) expected_checksum=(\d+)',native.stdout)
            assert checksum and checksum[1] == checksum[2]
            assert int(checksum[1]) == 4*sum(i % 251 + 1 for i in range(pages))
            output = directory/(name+'.out'); output.write_text(native.stdout)
            r = analysis.report(output)
            assert r['expected_page_start_reads'] == 4*pages and r['footprint_bytes'] == 4096*pages
            cases += 1
            if args.qemu:
                memory=directory/(name+'.csv'); events=directory/(name+'-events.csv')
                with output.open('w') as stream:
                    result=subprocess.run([str(Path(args.qemu).resolve()),'-plugin',
                        f'{Path(args.plugin).resolve()},roi=markers,limit=1000000,events={events}',
                        '-d','plugin','-D',str(memory),binary,*flags],stdout=stream,stderr=subprocess.PIPE,text=True)
                assert result.returncode == 0, result.stderr
                result=subprocess.run([sys.executable,str(ROOT/'analyze-footprint.py'),
                    '--memory',str(memory),'--events',str(events),'--output',str(output)],
                    capture_output=True,text=True)
                assert result.returncode == 0, result.stderr
                assert f'application_page_start_reads={4*pages}' in result.stdout
                mapping=analysis.report(output)
                for row in analysis.records(memory,analysis.MH):
                    va=int(row['data_va'],0)
                    if mapping['base'] <= va < mapping['base']+mapping['footprint_bytes']:
                        assert row['operation']=='R', 'prepopulation write leaked into ROI'
                print(name+': '+result.stdout.splitlines()[1])
                cases += 1
    for flags,error in [(['--pages','3'],'power of two'),(['--pages','0'],'positive decimal'),
                        (['--pages','65537'],'power of two'),(['--pages','-1'],'positive decimal'),
                        (['--pages','18446744073709551616'],'positive decimal'),
                        (['--passes','1000001'],'passes in'),(['--passes','0'],'positive decimal'),
                        (['--passes','2x'],'positive decimal'),(['--pattern','random'],'pattern must'),
                        (['--pages','32','--pages','32'],'duplicate'),(['--pages'],'missing value'),
                        (['--unknown','1'],'unknown option')]:
        result=subprocess.run([binary,*flags],capture_output=True,text=True)
        assert result.returncode != 0 and error in result.stderr, (flags,result)
        assert not result.stdout
        cases += 1

    # Separate intervals and extra records must not be confused with application
    # reads or stripped out. Corruptions must fail rather than silently skip.
    output=directory/'synthetic.out'
    output.write_text('base=0x100000 page_size=4096 page_count=32 footprint_bytes=131072 '
                      'passes=4 pattern=permuted stride=17 expected_page_start_reads=128\n')
    rows=[]
    def add(va,operation='R',kind='RAM'):
        rows.append([len(rows)+1,0,'0x401000',hex(va),'NA',1,operation,kind])
    add(0x100000); add(0x100000)
    for _ in range(4):
        for i in range(32): add(0x100000+((i*17)&31)*4096)
        add(0x800000,'W','MMIO')
    end=len(rows)
    add(0x100000); add(0x100000); add(0x100000)
    events=[[1,1,'BEGIN',0,0],[2,1,'END',0,2],[3,2,'BEGIN',0,2],
            [4,2,'END',0,end],[5,3,'BEGIN',0,end],[6,3,'END',0,len(rows)]]
    memory=directory/'synthetic.csv'; boundaries=directory/'synthetic-events.csv'
    def test(data,ev,error=None):
        global cases
        for path,header,records in [(memory,analysis.MH,data),(boundaries,analysis.EH,ev)]:
            with path.open('w',newline='') as stream:
                writer=csv.writer(stream); writer.writerow(header); writer.writerows(records)
        result=subprocess.run([sys.executable,str(ROOT/'analyze-footprint.py'),'--memory',str(memory),
            '--events',str(boundaries),'--output',str(output),'--interval','2'],capture_output=True,text=True)
        if error:
            assert result.returncode != 0 and error in result.stderr, result
        else:
            assert result.returncode == 0 and 'extra_records=4' in result.stdout, result
        cases += 1
    test(rows,events)
    for reason in ['LIMIT','EXIT']:
        ev=[row[:] for row in events]; ev[3][2]=reason; test(rows,ev,'truncated/incomplete')
    test(rows,events[:3],'missing/incomplete')
    data=[row[:] for row in rows]; data[3][3]=data[2][3]; test(data,events,'wrong application page order')
    data=[row[:] for row in rows]; data[2][5]=2; test(data,events,'unexpected size')
    test(rows[:-4],events,'records missing')
    test(rows[:10]+rows[11:],events,'memory sequence')
print(f'PASS: {cases} local footprint/analyzer cases; permutation verified for powers of two 1..65536')
