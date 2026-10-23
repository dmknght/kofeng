"""Builds the synthetic inputs the TUI tests need (deterministic, read-only).
Everything goes under SCRATCH/vt/fixtures; nothing outside it is touched."""
import os, io, zipfile, tarfile, gzip, random, stat
from tui import VT

FX = os.path.join(VT, 'fixtures')


def _w(name, data, mode=0o444):
    os.makedirs(FX, exist_ok=True)
    p = os.path.join(FX, name)
    if os.path.exists(p):
        os.chmod(p, 0o644)
    with open(p, 'wb') as f:
        f.write(data)
    os.chmod(p, mode)
    return p


def build():
    rng = random.Random(7)
    out = {}
    out['empty'] = _w('empty.bin', b'')
    out['one'] = _w('one.bin', b'A')
    out['tiny'] = _w('tiny.bin', bytes(range(16)))
    out['text'] = _w('plain.txt', b'hello world\nsecond line\n' * 40)
    long_line = ('x' * 5000 + ' END\n').encode()
    out['longline'] = _w('longline.txt', long_line)
    out['php'] = _w('shell.php', b'<?php\n@eval($_POST["c"]);\nsystem($_GET["x"]);\n?>\n' * 3)
    # a zip with many entries (long tree), nested names
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, 'w', zipfile.ZIP_DEFLATED) as z:
        for i in range(80):
            z.writestr('dir%d/file_%03d.txt' % (i % 5, i), (b'entry %d ' % i) * (20 + i))
        z.writestr('payload.exe', b'MZ' + bytes(rng.randrange(256) for _ in range(300)))
    out['zip'] = _w('many.zip', bio.getvalue())
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode='w:gz') as t:
        for i in range(30):
            data = (b'tar member %d\n' % i) * 50
            ti = tarfile.TarInfo('t/%02d.txt' % i)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    out['targz'] = _w('many.tar.gz', bio.getvalue())
    out['gz'] = _w('one.txt.gz', gzip.compress(b'gzip payload\n' * 100))
    # random data (high entropy), 256 KiB
    out['random'] = _w('random.bin', bytes(rng.randrange(256) for _ in range(256 * 1024)))
    # a large sparse-ish file (64 MiB of a repeating pattern) for scroll extremes
    big = (bytes(range(256)) * 4096)  # 1 MiB
    out['big'] = _w('big64.bin', big * 64)
    # member names that try to inject terminal escapes / non-ASCII / very long
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, 'w') as z:
        z.writestr('plain.txt', b'plain')
        z.writestr('evil\x1b[31mRED\x1b]0;PWNED-TITLE\x07name.txt', b'x')
        z.writestr('\u65e5\u672c\u8a9e.txt', b'jp')
        z.writestr('tab\there.txt', b'x')
        z.writestr('a' * 300 + '.txt', b'long')
    out['evil_zip'] = _w('evil_names.zip', bio.getvalue())
    # event logs: compiled on demand from evtgen.c, written by the repo's own
    # kofevtlog writer (so the records are what the real collectors emit)
    import subprocess
    from tui import REPO
    here = os.path.dirname(os.path.abspath(__file__))
    gen = os.path.join(FX, 'evtgen')
    if not os.path.exists(gen):
        ev = os.path.join(REPO, 'libkoforbit', 'evt')
        subprocess.run(['cc', '-std=gnu11', '-I' + ev, os.path.join(here, 'evtgen.c'),
                        os.path.join(ev, 'kofevt.c'), os.path.join(ev, 'kofevtlog.c'),
                        os.path.join(ev, 'kofevtfmt.c'), '-o', gen], check=True)
    # a relocatable kernel module a test diagnose (tests/sigs/diagnoses/kmod_give_root.c)
    # matches: built from the unit tests' own image builder
    kgen = os.path.join(FX, 'kmodgen')
    if not os.path.exists(kgen):
        subprocess.run(['cc', '-std=gnu11', '-I' + os.path.join(REPO, 'libkofeng', 'kofcore'),
                        '-I' + os.path.join(REPO, 'libgenome'), '-I' + os.path.join(REPO, 'libuncoat'),
                        '-I' + REPO, os.path.join(here, 'kmodgen.c'), '-o', kgen], check=True)
    p = os.path.join(FX, 'giveroot.ko')
    if os.path.exists(p):
        os.chmod(p, 0o644)
    subprocess.run([kgen, p], check=True)
    os.chmod(p, 0o444)
    out['giveroot_ko'] = p
    # a raw 32-bit stager-shaped blob (no header, no symbols): a counted loop, `call $+5; pop`, an int 0x80 execve.
    # The same bytes as tests/unit/code_notes.c.
    out['stager32'] = _w('stager32.bin', bytes([
        0x31, 0xc9, 0xb9, 0x03, 0, 0, 0, 0x90, 0x49, 0x75, 0xfc, 0xe8, 0, 0, 0, 0, 0x5e,
        0x31, 0xc0, 0xb8, 0x0b, 0, 0, 0, 0xcd, 0x80, 0xc3]))
    # `cmp eax, ebx`, sixty nops, `jz $+2`, `nop` (the blob ends in an instruction that leaves the flags alone, so the walk that ends it does not clear them): the jump is far from its comparison, so a window that shows the jump but not the comparison
    # must not borrow the comparison of the window before it.
    out['condgap'] = _w('condgap.bin', bytes([0x39, 0xd8]) + bytes([0x90] * 60) + bytes([0x74, 0x00, 0x90]))
    # a static freestanding x86-64 ELF for the disassembly annotations: a loop, a
    # named callee, and raw write(1) / exit(60) syscalls
    p = os.path.join(FX, 'disfix.elf')
    if os.path.exists(p):
        os.chmod(p, 0o644)
    subprocess.run(['cc', '-O1', '-static', '-nostdlib', '-fno-pic', '-no-pie',
                    '-fcf-protection=none', '-o', p, os.path.join(here, 'disfix.c')], check=True)
    os.chmod(p, 0o444)
    out['disfix_elf'] = p
    # the same program linked stripped: no symbol names anything
    p = os.path.join(FX, 'disfix_stripped.elf')
    if os.path.exists(p):
        os.chmod(p, 0o644)
    subprocess.run(['cc', '-O1', '-static', '-nostdlib', '-fno-pic', '-no-pie', '-s',
                    '-fcf-protection=none', '-o', p, os.path.join(here, 'disfix.c')], check=True)
    os.chmod(p, 0o444)
    out['disfix_stripped_elf'] = p
    for nm, cnt in (('events.ktr', 40), ('events_many.ktr', 600), ('events_one.ktr', 1)):
        p = os.path.join(FX, nm)
        if os.path.exists(p):
            os.chmod(p, 0o644)
        subprocess.run([gen, p, str(cnt)], check=True)
        os.chmod(p, 0o444)
        out[nm] = p
    return out


if __name__ == '__main__':
    for k, v in build().items():
        print(k, v, os.path.getsize(v))
