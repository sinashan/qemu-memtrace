#!/usr/bin/env python3
"""Local small captures and direct writer fixtures; never manage a VM."""
import csv
import io
import lzma
import os
from pathlib import Path
import resource
import shlex
import signal
import subprocess
import tempfile

QEMU = 'build/qemu-x86_64'
PLUGIN = str(Path('build/contrib/plugins/libmemtrace.so').resolve())
GUEST = 'build/contrib/plugins/memtrace-roi-test'


def read(path, xz):
    return lzma.decompress(path.read_bytes()) if xz else path.read_bytes()


def run(root, name, xz, options, guest=GUEST, preexec=None):
    memory = root / (name + ('.csv.xz' if xz else '.csv'))
    events = root / (name + '-events.csv')
    args = (f'{PLUGIN},memory={memory},events={events}' + (',' + options if options else '') +
            (',compression=xz,compression-level=3' if xz else ',compression=none'))
    result = subprocess.run([QEMU, '-plugin', args, guest],
                            capture_output=True, text=True, preexec_fn=preexec)
    return result, memory, events


with tempfile.TemporaryDirectory(prefix='memtrace-xz-') as d:
    root = Path(d)
    live_source = root / 'live.c'
    live_source.write_text(r'''
#include <stdio.h>
#include <unistd.h>
#define BEGIN() __asm__ volatile(".byte 0x0f,0x1f,0x84,0x00,0x56,0x57,0x42,0x47" ::: "memory")
#define END() __asm__ volatile(".byte 0x0f,0x1f,0x84,0x00,0x56,0x57,0x45,0x4e" ::: "memory")
int main(int argc, char **argv) {
    (void)argv;
    if (argc == 1) { BEGIN(); END(); BEGIN(); END(); return 0; }
    volatile unsigned char value = 0;
    for (int n=0; n<2; n++) {
        BEGIN(); value++; END();
        puts("ready"); fflush(stdout);
        char c; if (read(0, &c, 1) != 1) return 1;
    }
    return 0;
}
''')
    live = root / 'live'
    subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror', '-static',
                    str(live_source), '-o', str(live)], check=True)
    cases = [('', '/bin/true', 1000), ('limit=0', '/bin/true', 0),
             ('roi=markers,limit=0', GUEST, 0),
             ('roi=markers,limit=5', GUEST, 5),
             ('roi=markers,limit=unlimited', GUEST, None),
             ('roi=immediate,limit=unlimited', '/bin/true', None),
             ('roi=markers,limit=unlimited', '/bin/true', 0),
             ('roi=markers,limit=unlimited', str(live), 0),
             ('roi=markers,limit=unlimited',
              'build/contrib/plugins/memtrace-exit-active', None)]
    for i, (options, guest, count) in enumerate(cases):
        captures = []
        for xz in (False, True):
            result, memory, events = run(root, f'case-{i}-{xz}', xz, options, guest)
            assert result.returncode == 0 and not result.stderr, result.stderr
            decoded = read(memory, xz)
            rows = list(csv.DictReader(io.StringIO(decoded.decode())))
            assert [int(r['sequence']) for r in rows] == list(range(1, len(rows)+1))
            if count is not None:
                assert len(rows) == count
            captures.append((decoded, events.read_bytes()))
        assert captures[0] == captures[1], f'raw/XZ mismatch in {options}'
    print('PASS: 9 raw/XZ identical memory/event cases, limits, multiple/empty ROIs, EXIT')

    memory, events = root/'live.csv.xz', root/'live-events.csv'
    command = [QEMU, '-plugin', f'{PLUGIN},memory={memory},events={events},'
               'roi=markers,limit=unlimited,compression=xz', str(live), 'pause']
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    try:
        for interval in (1, 2):
            assert process.stdout.readline() == 'ready\n'
            rows = list(csv.DictReader(io.StringIO(lzma.decompress(memory.read_bytes()).decode())))
            with events.open() as f:
                boundaries = list(csv.DictReader(f))
            assert boundaries[-1]['event'] == 'END'
            assert int(boundaries[-1]['interval_id']) == interval
            assert int(boundaries[-1]['access_sequence']) == len(rows)
            process.stdin.write('x'); process.stdin.flush()
        assert process.wait(timeout=30) == 0
        assert not process.stderr.read()
    finally:
        if process.poll() is None:
            process.kill(); process.wait()
    print('PASS: complete concatenated XZ readable at END while guest process still running')

    # Direct writer fixtures also test arbitrary walk fields, buffer rollover,
    # empty boundaries, CRC integrity, and codec/stdio errors independently of
    # the full-system-only paging API. These are NOT actual guest PA captures.
    source = root / 'writer-test.c'
    source.write_text(r'''
#include "memtrace-writer.h"
#include <assert.h>
#include <inttypes.h>
static bool fail_close;
int __real_fclose(FILE *);
int __wrap_fclose(FILE *f) {
    int result = __real_fclose(f);
    if (fail_close) { errno = EIO; return EOF; }
    return result;
}
int main(int argc, char **argv) {
    (void)argc;
    static TraceWriter w;
    bool xz = argv[2][0] == '1';
    assert(writer_open(&w, "fixture", argv[1], xz, 3));
    if (argv[3][0] == 'c') {
        assert(writer_write(&w, "header\n", 7));
        fail_close = true;
        assert(!writer_close(&w));
        return 0;
    }
    if (argv[3][0] == 'f') {
        assert(!fclose(w.file));
        w.file = fopen("/dev/full", "wb");
        assert(w.file);
        assert(!setvbuf(w.file, w.stdio_buffer, _IOFBF, sizeof(w.stdio_buffer)));
        assert(writer_write(&w, "header\n", 7));
        assert(!writer_boundary(&w));
        assert(w.failed);
        assert(!writer_write(&w, "no retry", 8));
        assert(!writer_boundary(&w));
        assert(!writer_close(&w));
        return 0;
    }
    if (argv[3][0] == 'i') {
        w.level = UINT32_MAX;
        assert(writer_write(&w, "header\n", 7));
        assert(!writer_boundary(&w));
        assert(!writer_close(&w));
        return 0;
    }
    const char *header = "sequence,cpu,data_va,cr3,root_pa,cr0,cr4,efer,phys_bits,status,leaf_size,reconstructed_pa,callback_pa,comparison,pte_path\n";
    const char *row = "1,0,0xffff800000001000,0x123045,0x123000,0x80000001,0x20,0xd00,48,OK,4096,0xabc000,0xabc000,match,\"4:0x123800:0x200027;3:0x200000:0x300027;2:0x300000:0x400027;1:0x400008:0xabc067\"\n";
    assert(writer_write(&w, header, strlen(header)));
    assert(writer_boundary(&w));
    assert(writer_boundary(&w)); /* Empty ROI: no extra stream/header. */
    for (int interval=0; interval<2; interval++) {
        for (int n=0; n<2000; n++)
            assert(writer_write(&w, row, strlen(row)));
        const char *unavailable = "2,0,0x1,NA,NA,NA,NA,NA,NA,UNAVAILABLE,NA,NA,NA,not-comparable,\"\"\n";
        assert(writer_write(&w, unavailable, strlen(unavailable)));
        assert(writer_boundary(&w));
    }
    assert(writer_close(&w));
    printf("preset3 encoder bytes=%" PRIu64 " writer bytes=%zu\n",
           lzma_easy_encoder_memusage(3), sizeof(w));
    return 0;
}
''')
    flags = shlex.split(subprocess.check_output(
        ['pkg-config', '--cflags', '--libs', 'liblzma'], text=True))
    executable = root / 'writer-test'
    subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-Icontrib/plugins',
                    str(source), '-Wl,--wrap=fclose', '-o', str(executable), *flags], check=True)
    fixture = []
    for xz in (False, True):
        path = root / ('fixture-' + str(xz))
        result = subprocess.run([str(executable), str(path), str(int(xz)), 'ok'],
                                capture_output=True, text=True, check=True)
        print(result.stdout.strip())
        fixture.append(read(path, xz))
        for mode in ('full', 'init', 'close') if xz else ('full', 'close'):
            result = subprocess.run([str(executable), str(root / f'{xz}-{mode}'),
                                     str(int(xz)), mode], capture_output=True,
                                    text=True, check=True)
            assert 'failed' in result.stderr and 'incomplete' in result.stderr
    assert fixture[0] == fixture[1]
    encoded = (root / 'fixture-True').read_bytes()
    streams, remaining = 0, encoded
    while remaining:
        decoder = lzma.LZMADecompressor()
        decoder.decompress(remaining)
        assert decoder.eof
        remaining = decoder.unused_data
        streams += 1
    assert streams == 3  # Header plus two nonempty intervals.
    try:
        lzma.decompress(encoded[:-8])
        raise AssertionError('truncation accepted')
    except lzma.LZMAError:
        pass
    print('PASS: walk fixture equality, 3 concatenated streams, empty boundaries, truncation, disk-full, close and codec initialization failures')

    # At plugin boundary failure, ERROR replaces END and later BEGIN is blocked.
    for xz in (False, True):
        def header_failure():
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (64, 64))
        result, _, _ = run(root, 'header-failure-' + str(xz), xz,
                            'roi=markers', preexec=header_failure)
        assert result.returncode and 'failed' in result.stderr
        def restrict():
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (200, 200))
        result, memory, events = run(root, 'full-' + str(xz), xz,
                                     'roi=markers,limit=unlimited', preexec=restrict)
        assert result.returncode == 0, result.stderr
        assert 'memtrace: memory' in result.stderr and 'failed' in result.stderr
        with events.open() as f:
            assert [r['event'] for r in csv.DictReader(f)] == ['BEGIN', 'ERROR']
        if xz:
            try:
                lzma.decompress(memory.read_bytes())
                raise AssertionError('disk-full truncated XZ accepted')
            except lzma.LZMAError:
                pass

    sentinel = root / 'existing'
    sentinel.write_text('preserve')
    hardlink = root / 'hardlink'
    os.link(sentinel, hardlink)
    symlink = root / 'symlink'
    symlink.symlink_to(sentinel)
    for path in (sentinel, hardlink, symlink):
        result = subprocess.run([QEMU, '-plugin', PLUGIN + ',memory=' + str(path),
                                 '/bin/true'], capture_output=True, text=True)
        assert result.returncode and 'open failed' in result.stderr
        assert sentinel.read_text() == 'preserve'
    alias = root / 'alias.csv'
    result = subprocess.run([QEMU, '-plugin',
                             f'{PLUGIN},memory={alias},events={alias}', '/bin/true'],
                            capture_output=True, text=True)
    assert result.returncode and 'open failed' in result.stderr
    log = root / 'qemu-log.csv'
    result = subprocess.run([QEMU, '-d', 'plugin', '-D', str(log), '-plugin',
                             f'{PLUGIN},memory={log}', '/bin/true'],
                            capture_output=True, text=True)
    assert result.returncode and 'open failed' in result.stderr
    for option in ('compression=gzip', 'compression=xz', 'compression-level=3',
                   'memory=relative', 'memory=', 'compression=xz,compression=none',
                   f'memory={root}/unused,memory={root}/unused-2',
                   'compression=xz,compression-level=10',
                   'compression=xz,compression-level=',
                   'compression=xz,compression-level=3,compression-level=3'):
        result = subprocess.run([QEMU, '-plugin', PLUGIN + ',' + option,
                                 '/bin/true'], capture_output=True, text=True)
        assert result.returncode and 'memtrace:' in result.stderr
    print('PASS: terminal ERROR, no later END/reopening, existing/alias/hardlink/log protection, malformed options')
