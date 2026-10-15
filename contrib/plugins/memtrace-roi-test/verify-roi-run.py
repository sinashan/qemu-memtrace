#!/usr/bin/env python3
"""Local wrapper tests only. Does not transfer files or contact/manage a VM."""
import argparse
import csv
from pathlib import Path
import re
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parent
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary',required=True)
parser.add_argument('--qemu')
parser.add_argument('--plugin')
args=parser.parse_args()
assert bool(args.qemu)==bool(args.plugin), '--qemu and --plugin must be supplied together'
binary=str(Path(args.binary).resolve())
passed=0

def check(command,status,diagnostic):
    global passed
    result=subprocess.run(command,capture_output=True,text=True,timeout=30)
    assert result.returncode==status,(command,result)
    assert diagnostic in result.stdout+result.stderr,(command,result)
    passed+=1
    return result

for marker in ['BEGIN','END']:
    pattern=rf'#define {marker}\(\).*?" ::: "memory"\)'
    assert re.search(pattern,(ROOT/'roi-run.c').read_text(),re.S).group()==re.search(
        pattern,(ROOT/'roi-test.c').read_text(),re.S).group()
check([binary,'--','/bin/true'],0,'status=0')
check([binary,'--','/bin/false'],1,'status=1')
check([binary,'--','/definitely/missing/roi-run-command'],127,'execvp(')
check([binary,'--','/bin/sh','-c','kill -TERM $$'],143,'signal=15')
for flags in [[],['--'],['/bin/true'],['--','']]: check([binary,*flags],2,'usage:')
# Metacharacters/whitespace remain literal argv. Only an explicitly supplied
# shell (the signal test above) interprets a shell program.
check([binary,'--','/usr/bin/python3','-c',
       'import sys; assert sys.argv[1:]==["a b", ";echo NOT_A_SHELL", "$(echo literal)"]',
       'a b',';echo NOT_A_SHELL','$(echo literal)'],0,'status=0')

with tempfile.TemporaryDirectory(prefix='roi-run-checks-') as directory:
    directory=Path(directory)
    source=directory/'faults.c'
    source.write_text('''#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
pid_t __real_fork(void);
pid_t __real_waitpid(pid_t,int *,int);
pid_t __wrap_fork(void) {
#ifdef FORK_FAIL
    errno=EAGAIN; return -1;
#else
    return __real_fork();
#endif
}
pid_t __wrap_waitpid(pid_t child,int *status,int flags) {
#ifdef WAIT_FAIL
    errno=EIO; return -1;
#else
#ifdef EINTR_ONCE
    static int first=1;
    if(first) { first=0; errno=EINTR; return -1; }
#endif
    return __real_waitpid(child,status,flags);
#endif
}
''')
    for define,status,diagnostic in [('FORK_FAIL',125,'fork failed'),
                                    ('WAIT_FAIL',125,'waitpid failed'),
                                    ('EINTR_ONCE',0,'status=0')]:
        test_binary=directory/define
        subprocess.run(['cc','-O2','-Wall','-Wextra','-Wno-unused-parameter','-static',
            '-D'+define,str(ROOT/'roi-run.c'),str(source),'-Wl,--wrap=fork','-Wl,--wrap=waitpid',
            '-o',str(test_binary)],check=True)
        check([str(test_binary),'--','/bin/true'],status,diagnostic)
    if args.qemu:
        memory=directory/'normal-memory.csv'; events=directory/'normal-events.csv'
        command=[str(Path(args.qemu).resolve()),'-plugin',
            f'{Path(args.plugin).resolve()},roi=markers,limit=1000000,events={events}',
            '-d','plugin','-D',str(memory),binary,'--','/bin/true']
        check(command,0,'status=0')
        with events.open(newline='') as stream: rows=list(csv.DictReader(stream))
        assert [row['event'] for row in rows]==['BEGIN','END'], rows
        assert [row['interval_id'] for row in rows]==['1','1'],rows
        assert int(rows[1]['access_sequence'])>int(rows[0]['access_sequence'])
        with memory.open(newline='') as stream: records=sum(1 for _ in csv.DictReader(stream))
        assert records>0
        print(f'User-mode normal child: BEGIN/END interval, {records} memory rows '
              '(fork/exec user-mode logs are not full-system validation).')
print(f'PASS: {passed} local ROI-wrapper checks, including injected fork/wait errors and EINTR retry')
