#!/usr/bin/env python3
"""Native/user-mode workload and synthetic verifier checks. Never starts a VM."""
import json
import lzma
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
HERE=Path(__file__).resolve().parent
WORK=HERE.parents[4]
OUT=WORK/'qemu-memtrace/build/contrib/plugins'
WRAPPER=HERE/'verify-linux-v3.py'
class Tests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.d=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def fixture(self,mode='noncontiguous'):
        trace=self.d/(mode+'.bin');manifest=self.d/(mode+'.txt')
        subprocess.run([str(OUT/'linux-v3-fixture'),mode,str(trace),str(manifest)],check=True)
        return trace,manifest
    def verify(self,trace,manifest,flags=(),error=None):
        a=subprocess.run([sys.executable,str(WRAPPER),'--trace',str(trace),'--workload-output',str(manifest),
                          '--results-dir',str(self.d/'verified'),*flags],capture_output=True,text=True,timeout=30)
        if error:
            self.assertNotEqual(a.returncode,0);self.assertIn(error,a.stderr)
            self.assertFalse((self.d/'verified/verification.json').exists());return
        self.assertEqual(a.returncode,0,a.stderr)
        return json.loads((self.d/'verified/verification.json').read_text())
    def test_runner_dry_run_only(self):
        p=subprocess.run([sys.executable,str(WORK/'traces/run_experiment.py'),'--dry-run',
            '--profiles',str(HERE/'runner-profile.json'),'--profile','linux-v3',
            '--trace-format','execution-binary','--markers-in-benchmark','--limit','2000000'],capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr);self.assertIn('format=execution-binary',p.stdout)
        self.assertIn('exec env /home/ubuntu/memtrace-linux-v3',p.stdout);self.assertNotIn('memtrace-roi-run',p.stdout)
    def test_native_and_user_mode(self):
        for args in [[OUT/'memtrace-linux-v3'],[WORK/'qemu-memtrace/build/qemu-x86_64',OUT/'memtrace-linux-v3']]:
            if not args[0].exists():continue
            p=subprocess.run([str(x) for x in args],capture_output=True,text=True,timeout=15)
            self.assertEqual(p.returncode,0,p.stderr);self.assertFalse(p.stderr)
            self.assertIn('linux_v3_success=1',p.stdout)
        p=subprocess.run([str(OUT/'memtrace-linux-v3'),'unexpected'],capture_output=True,text=True)
        self.assertNotEqual(p.returncode,0);self.assertFalse(p.stdout)
    def test_disassembly(self):
        p=subprocess.run(['nm','-n',str(OUT/'memtrace-linux-v3')],capture_output=True,text=True,check=True)
        symbols={line.split()[2]:int(line.split()[0],16) for line in p.stdout.splitlines() if len(line.split())==3}
        for name,opcode,operand in [('linux_v3_wide_load_pc','f3 0f 6f',r'movdqu\s+\([^)]*\),%xmm0'),
                                    ('linux_v3_wide_store_pc','f3 0f 7f',r'movdqu\s+%xmm1,\(')]:
            pc=symbols[name];text=subprocess.check_output(['objdump','-d',f'--start-address={pc}',f'--stop-address={pc+4}',str(OUT/'memtrace-linux-v3')],text=True)
            self.assertIn(opcode,text);self.assertRegex(text,operand)
            print(text.strip())
    def test_noncontiguous_strict_replay(self):
        r=self.verify(*self.fixture());self.assertEqual(r['status'],'PASS');self.assertEqual(r['capture']['cross_noncontiguous_coverage'],'observed')
        self.assertEqual(r['capture']['intervals'][0]['incidental_kernel_pc_accesses_heuristic'],1)
        self.assertEqual(r['replays'][0]['counters']['translation_lookups'],'5')
    def test_contiguous_coverage_reported_absent(self):
        r=self.verify(*self.fixture('contiguous'));self.assertIn('absent',r['capture']['cross_noncontiguous_coverage'])
    def test_same_value_cr3_qualifies(self):self.verify(*self.fixture('cr3'))
    def test_missing_event_rejected(self):self.verify(*self.fixture('missing-event'),error='missing applicable recorded invalidation')
    def test_unrelated_invlpg_rejected(self):self.verify(*self.fixture('unrelated-event'),error='missing applicable recorded invalidation')
    def test_frame_must_change(self):self.verify(*self.fixture('same-frame'),error='did not change the observed physical frame')
    def test_path_and_reconstruction_errors(self):
        for mode,message in [('mismatch','PA mismatch'),('bad-path','PTE path')]:
            trace,manifest=self.fixture(mode)
            p=subprocess.run([str(OUT/'verify-linux-v3'),str(trace),str(manifest),'1','2','1000'],capture_output=True,text=True)
            self.assertNotEqual(p.returncode,0);self.assertIn(message,p.stderr)
    def test_duplicate_rejected(self):self.verify(*self.fixture('duplicate'),error='duplicate targeted PC')
    def test_limit_rejected(self):self.verify(*self.fixture('limit'),error='complete END')
    def test_bound_is_failure_not_prefix(self):self.verify(*self.fixture(),flags=['--max-records','3'],error='footer/EOF NOT validated')
    def test_corruption_and_truncation(self):
        trace,manifest=self.fixture();raw=trace.read_bytes();xz=self.d/'bad.bin.xz'
        for data in [lzma.compress(raw[:-4]),lzma.compress(raw)[:-8]]:
            xz.write_bytes(data)
            p=subprocess.run([str(OUT/'verify-linux-v3'),str(xz),str(manifest),'1','2','1000'],capture_output=True,text=True)
            self.assertNotEqual(p.returncode,0)
        b=bytearray(raw);b[90]^=1;trace.write_bytes(b)
        self.verify(trace,manifest,error='checksum')
    def test_existing_results_protected(self):
        trace,manifest=self.fixture();d=self.d/'verified';d.mkdir();(d/'keep').write_text('keep')
        self.verify(trace,manifest,error='File exists');self.assertEqual((d/'keep').read_text(),'keep')
if __name__=='__main__':unittest.main()
