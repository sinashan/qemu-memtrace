#!/usr/bin/env python3
"""Small isolated full-system TCG checks. No disk, network, or existing VM use."""
import csv
import json
import resource
import signal
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[4]
WORK=ROOT.parent
HERE=Path(__file__).resolve().parent
BUILD=ROOT/'build'
CODEC=WORK/'traces/trace-codec/trace-codec'
REPLAY=WORK/'qemu-replay/build/qemu-replay'
def command(a,**kwargs):
    p=subprocess.run([str(x) for x in a],capture_output=True,text=True,timeout=30,**kwargs)
    assert p.returncode==0,(a,p.returncode,p.stderr)
    return p
out=Path(tempfile.mkdtemp(prefix='execution-',dir=BUILD/'contrib/plugins'))
print('Fresh validation outputs:',out,flush=True)
for mode in ('normal','default-limit','numeric-limit','zero-limit','fault-second','output-failure'):
    d=out/mode;d.mkdir()
    command(['as','--32',*(['--defsym','FAULT_SECOND=1'] if mode=='fault-second' else []),HERE/'guest.S','-o',d/'guest.o'])
    command(['ld','-m','elf_i386','-T',HERE/'guest.ld',d/'guest.o','-o',d/'guest.elf'])
    limit={'default-limit':'','numeric-limit':',limit=5','zero-limit':',limit=0'}.get(mode,',limit=unlimited')
    args=[BUILD/'qemu-system-x86_64','-accel','tcg,thread=single','-cpu','max,la57=off','-smp','1','-m','64M',
          '-display','none','-serial','none','-monitor','none','-nic','none','-no-reboot',
          '-kernel',d/'guest.elf','-device','isa-debug-exit,iobase=0xf4,iosize=4','-plugin',
          f'{BUILD}/contrib/plugins/libmemtrace.so,format=execution-binary,binary={d}/trace.bin.xz,events={d}/events.csv,roi=markers{limit}']
    (d/'command.json').write_text(json.dumps([str(x) for x in args],indent=2))
    def file_limit():
        signal.signal(signal.SIGXFSZ,signal.SIG_IGN)
        resource.setrlimit(resource.RLIMIT_FSIZE,(512,512))
    p=subprocess.run([str(x) for x in args],capture_output=True,text=True,timeout=20,
                     preexec_fn=file_limit if mode=='output-failure' else None)
    (d/'stderr.txt').write_text(p.stderr)
    assert p.returncode==(0 if mode=='fault-second' else 33),(p.returncode,p.stderr)
    if mode=='output-failure':
        assert 'incomplete' in p.stderr,p.stderr
        with (d/'events.csv').open() as stream:events=list(csv.DictReader(stream))
        assert 'ERROR' in [e['event'] for e in events] and not any(e['event']=='END' for e in events)
        check=subprocess.run([str(CODEC),'inspect','--input',str(d/'trace.bin.xz')],capture_output=True,text=True)
        assert check.returncode,check.stdout
        print('PASS: injected EFBIG disables recording, emits ERROR, prevents END and rejects incomplete artifact',flush=True)
        continue
    assert not p.stderr,p.stderr
    info=json.loads(command([CODEC,'inspect','--input',d/'trace.bin.xz','--events-input',d/'events.csv']).stdout)
    command([CODEC,'export-extended','--input',d/'trace.bin.xz','--output',d/'extended.jsonl'])
    rows=[json.loads(line) for line in (d/'extended.jsonl').read_text().splitlines()]
    assert [int(r['order']) for r in rows]==list(range(1,len(rows)+1))
    groups=[r for r in rows if r['type']=='access_group']
    if mode in ('numeric-limit','zero-limit'):
        assert len(groups)==(5 if mode=='numeric-limit' else 0)
        assert info['capture_status']==('LIMIT' if mode=='numeric-limit' else 'EMPTY')
        events=[r['event'] for r in rows if r['type']=='roi']
        assert events==(['BEGIN','LIMIT'] if mode=='numeric-limit' else [])
        print('PASS:',mode,'counts original callbacks without reopening',flush=True)
        continue
    if mode=='fault-second':
        assert not groups,groups
        assert info['capture_status']=='EXIT'
        p=subprocess.run([str(REPLAY),'--trace',str(d/'trace.bin.xz'),'--interval','1'],capture_output=True,text=True)
        assert p.returncode and 'incomplete' in p.stderr,p.stderr
        print('PASS: second-page fault creates no successful access group',flush=True)
        continue
    assert info['capture_status']=='END' and info['format_version']==3
    assert len(groups)==19  # literal callback operations in this diskless assembly test
    assert [int(g['sequence']) for g in groups]==list(range(1,len(groups)+1))
    def at(va):return [g for g in groups if int(g['segments'][0]['data_va'],16)==va]
    def physical(g):return [int(s['observed_pa'],16) for s in g['segments']]
    assert physical(at(0x400ff8)[0])==[0x300ff8,0x500000]
    assert physical(at(0x403ff8)[0])==[0x800ff8,0x801000]
    assert physical(at(0x200ff8)[0])==[0x200ff8,0x201000]
    assert physical(at(0x400ff8)[2])==[0x700ff8,0x500000]
    assert physical(at(0x400ff8)[3])==[0x700ff8,0x500000]
    assert all(s['fresh_walk']['leaf_size']==2097152 for s in at(0x200ff8)[0]['segments'])
    for va,lens in [(0x400fff,[1,1]),(0x400ffd,[3,1]),(0x400ff9,[7,1]),(0x404000,[16]),(0x403fe0,[16])]:
        assert [s['size_bytes'] for s in at(va)[0]['segments']]==lens
    mmio=at(0x4020b0)[0]['segments'][0]
    assert mmio['memory_type']=='MMIO' and int(mmio['observed_pa'],16)==0xfee000b0
    for group in groups:
        offset=0;va=int(group['segments'][0]['data_va'],16)
        for seg in group['segments']:
            assert seg['offset']==offset and int(seg['data_va'],16)==va+offset
            offset+=seg['size_bytes'];w=seg['fresh_walk']
            assert w['status']=='OK' and w['comparison']=='match'
            assert int(w['reconstructed_pa'],16)==int(w['observed_pa'],16)==int(seg['observed_pa'],16)
        assert offset==group['size_bytes']
    ctx=[r for r in rows if r['type']=='context']
    assert [r['kind'] for r in ctx]==[0,1,1,3,2,4,5,0,0]
    roots=[r['after']['root_pa'] for r in ctx if r['kind']==0]
    assert roots[0]!=roots[1] and roots[1]==roots[2]
    cr3=next(r for r in ctx if r['kind']==3)
    assert cr3['operand']==cr3['after']['cr3']
    assert [r['event'] for r in rows if r['type']=='roi']==['BEGIN','END']*3
    stats=[]
    for interval in (1,2,3):
        a=[REPLAY,'--trace',d/'trace.bin.xz','--events',d/'events.csv','--interval',str(interval),'--results',d/f'interval-{interval}.csv','--audit',d/f'interval-{interval}-audit.csv']
        p=command(a);(d/f'interval-{interval}.txt').write_text(p.stdout)
        s=dict(line.split('=',1) for line in p.stdout.splitlines());stats.append(s)
        assert s['counter_invariants']=='PASS' and s['full_input_validated']=='true'
    with (d/'interval-1-audit.csv').open() as stream:audit=list(csv.DictReader(stream))
    large=at(0x200ff8)
    assert sum(r['traffic']=='PTE' and r['sequence']==large[0]['sequence'] for r in audit)==3
    assert not any(r['traffic']=='PTE' and r['sequence']==large[1]['sequence'] for r in audit)
    assert stats[0]['replayed_data_accesses']=='18' and stats[0]['replayed_segments']=='29'
    assert stats[0]['architectural_invalidation_flushes']=='6' and stats[0]['inferred_remap_events']=='0'
    assert stats[1]['replayed_data_accesses']=='0'
    assert stats[2]['replayed_data_accesses']=='1' and stats[2]['replayed_segments']=='2'
    print('PASS: observed noncontiguous/contiguous segments, large leaf, sizes 2/4/8/16, MMIO, committed hooks, same-value CR3, permission change, three ROIs',flush=True)
print('PASS: isolated full-system checks complete; no Linux/DaCapo fidelity claim')
