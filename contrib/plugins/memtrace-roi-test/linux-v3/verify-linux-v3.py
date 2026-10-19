#!/usr/bin/env python3
"""Read-only bounded capture inspection, then TWO full strict baseline replays.
No VM, SSH, SCP, benchmark, or per-access audit is executed by this verifier.
"""
import argparse
import json
import math
from pathlib import Path
import subprocess
import sys
WORK=Path(__file__).resolve().parents[5]

def identity(p):
    s=p.stat()
    return s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--trace',type=Path,required=True)
    ap.add_argument('--workload-output',type=Path,required=True)
    ap.add_argument('--events',type=Path)
    ap.add_argument('--cross-interval',type=int,default=1)
    ap.add_argument('--remap-interval',type=int,default=2)
    ap.add_argument('--max-records',type=int,default=10000000,
                    help='Maximum all-category binary packets; exceeding it FAILS, never accepts a prefix')
    ap.add_argument('--timeout',type=float,default=300,help='Seconds per inspection/replay process')
    ap.add_argument('--results-dir',type=Path,required=True,help='New directory only; existing paths refused')
    ap.add_argument('--verifier',type=Path,default=WORK/'qemu-memtrace/build/contrib/plugins/verify-linux-v3')
    ap.add_argument('--replay',type=Path,default=WORK/'qemu-replay/build/qemu-replay')
    ap.add_argument('--config',type=Path,default=WORK/'qemu-replay/1d_modern_intel.cfg')
    a=ap.parse_args()
    if not 0<a.max_records<=1000000000 or not math.isfinite(a.timeout) or a.timeout<=0 or a.cross_interval<=0 or a.remap_interval<=0 or a.cross_interval==a.remap_interval:
        ap.error('positive distinct intervals, positive timeout and max-records in [1,1000000000] required')
    inputs=[a.trace,a.workload_output,a.config]+([a.events] if a.events else [])
    ids={p.resolve():identity(p) for p in inputs}
    def unchanged():
        if any(identity(p)!=v for p,v in ids.items()):raise RuntimeError('input changed during validation')
    # Exclusive directory creation prevents overwriting inputs, existing captures,
    # symlinks and previous results. All output names below are internal constants.
    a.results_dir.mkdir()
    def execute(name,args):
        unchanged()
        (a.results_dir/(name+'-command.json')).write_text(json.dumps([str(x) for x in args],indent=2)+'\n')
        p=subprocess.run([str(x) for x in args],capture_output=True,text=True,timeout=a.timeout)
        (a.results_dir/(name+'-stdout.txt')).write_text(p.stdout)
        (a.results_dir/(name+'-stderr.txt')).write_text(p.stderr)
        unchanged()
        if p.returncode:raise RuntimeError(f'{name} failed ({p.returncode}): {p.stderr.strip()}')
        return p.stdout
    analysis=json.loads(execute('inspect',[a.verifier,a.trace,a.workload_output,a.cross_interval,a.remap_interval,a.max_records]))
    if not analysis.get('full_input_validated') or not analysis.get('capture_verified'):
        raise RuntimeError('inspection did not fully validate the capture')
    (a.results_dir/'capture-analysis.json').write_text(json.dumps(analysis,indent=2)+'\n')
    results=[]
    for name,expected in zip(('cross','remap'),analysis['intervals']):
        args=[a.replay,'--model','baseline','--mapping-policy','strict','--trace',a.trace,
              '--interval',expected['interval'],'--warmup','0','--config',a.config,
              '--results',a.results_dir/(name+'-summary.csv')]
        if a.events:args+=['--events',a.events]
        text=execute(name,args)
        stats=dict(line.split('=',1) for line in text.splitlines())
        def n(k):return int(stats[k])
        def check(ok,reason):
            if not ok:raise RuntimeError(name+': '+reason)
        check(stats['validation_scope']=='FULL' and stats['full_input_validated']=='true' and
              stats['counter_invariants']=='PASS' and stats['mapping_policy']=='strict' and
              n('inferred_remap_events_including_warmup')==0 and n('binary_version')==3,
              'requires full strict v3 replay with no inferred remaps')
        check(n('warmup_accesses')==0 and n('warmup_segments')==0,'warmup must be zero')
        check(n('measured_data_accesses')==n('replayed_data_accesses')==expected['original_accesses'],
              'original access count differs from inspected interval')
        check(n('measured_segments')==n('replayed_segments')==n('translation_lookups')==expected['segments'],
              'segment/lookup count mismatch')
        check(n('translation_lookups')==n('tlb_hits')+n('tlb_misses') and n('tlb_hits')==n('tlb_l1_hits')+n('tlb_l2_hits'),
              'TLB counters do not reconcile')
        check(n('modeled_page_walks')==n('tlb_misses')==sum(n('page_walks_'+s) for s in ('4k','2m','1g')),
              'walk counts do not reconcile')
        check(n('pte_reads')==4*n('page_walks_4k')+3*n('page_walks_2m')+2*n('page_walks_1g')==
              sum(n('pte_'+s) for s in ('l2_hits','l3_hits','dram')),'PTE traffic does not reconcile')
        check(n('data_cache_line_accesses')==expected['ram_cache_line_transactions']==
              sum(n('data_'+s) for s in ('l2_hits','l3_hits','dram')),'RAM cache-line traffic mismatch')
        check(n('ram_data_accesses')+n('mmio_data_accesses')-n('mixed_ram_mmio_data_accesses')==expected['original_accesses'] and
              n('ram_translation_lookups')+n('mmio_translation_lookups')==expected['segments'], 'RAM/MMIO counts mismatch')
        check(n('architectural_invalidation_flushes')==expected['context_events'], 'context event counts mismatch')
        results.append({'interval':expected['interval'],'counters':stats})
    unchanged()
    report={'status':'PASS','full_input_validated':True,'strict_baseline_replay':True,
            'capture':analysis,'replays':results,
            'limitations':'Conservative v3 invalidation scope, fresh PTE snapshots; PC classification is a heuristic, not measured privilege.'}
    (a.results_dir/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: finalized v3 capture and both full strict baseline replays')
    print('Cross-page noncontiguity:',analysis['cross_noncontiguous_coverage'])
    print('Observed remap:',analysis['old_frame'],'->',analysis['new_frame'])
    print('Applicable recorded invalidations:',analysis['applicable_invalidation_records'],
          'first:',analysis['first_applicable_event'])
    for c in analysis['intervals']:
        print(f"interval {c['interval']}: targets={c['targeted_accesses']} originals={c['original_accesses']} segments={c['segments']} "
              f"incidental kernel-PC heuristic={c['incidental_kernel_pc_accesses_heuristic']} other={c['incidental_other_accesses']}")
    print('Results:',a.results_dir)
if __name__=='__main__':
    try:main()
    except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired,KeyError) as e:
        print('verify-linux-v3: FAILED:',e,file=sys.stderr);sys.exit(1)
