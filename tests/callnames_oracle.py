#!/usr/bin/env python3
"""callnames_oracle.py - compare the engine's call-name table with objdump.

  python3 -B tests/callnames_oracle.py <unit_callnames binary> <dir-or-file>... [--list N]

For every x86 / x86-64 ELF found under the arguments it runs `unit_callnames <file>` (the dump mode of tests/unit/callnames.c: one line
`<address> <name>@plt` per STUB entry) and compares it with the synthetic labels `<name@plt>` objdump prints for .plt, .plt.sec and
.plt.got. objdump is the oracle and is not used by the engine. An entry the engine lists at an endbr64 + 4 (the stub's own jmp, which objdump
labels at the endbr64) is folded into the one at the endbr64. Prints the counts and every mismatch; exit 0 always (it is a measurement).
Files are only read.
"""
import os, re, struct, subprocess, sys

LABEL = re.compile(r'^([0-9a-f]+) <([^>]+@plt)>:')


def is_x86_elf(path):
    try:
        with open(path, 'rb') as f:
            h = f.read(20)
    except OSError:
        return False
    return len(h) == 20 and h[:4] == b'\x7fELF' and h[5] == 1 and struct.unpack('<H', h[18:20])[0] in (3, 62)


def walk(args):
    for a in args:
        if os.path.isfile(a):
            yield a
        for d, _, fs in os.walk(a):
            for n in fs:
                p = os.path.join(d, n)
                if os.path.isfile(p) and not os.path.islink(p) and os.path.getsize(p) <= 64 << 20:
                    yield p


def objdump_labels(path):
    out = subprocess.run(['objdump', '-d', '-j', '.plt', '-j', '.plt.sec', '-j', '.plt.got', path],
                         capture_output=True, text=True, timeout=120).stdout
    r = {}
    for ln in out.splitlines():
        m = LABEL.match(ln)
        if m:
            r[int(m.group(1), 16)] = re.sub(r'@plt$', '', m.group(2)).split('@')[0] + '@plt'
    return r


def engine(binary, path):
    out = subprocess.run([binary, path], capture_output=True, text=True, timeout=120).stdout.splitlines()
    ours, status = {}, ''
    for ln in out:
        if ln.startswith('STATUS'):
            status = ln
        elif ln in ('NOTELF',) or ln.startswith('NA '):
            return None, ln
        else:
            a, n = ln.split(' ', 1)
            ours[int(a, 16)] = n
    # the jmp of an IBT stub sits 4 after the endbr64 objdump labels: fold it
    for a in sorted(ours):
        if a - 4 in ours and ours[a - 4] == ours[a]:
            del ours[a]
    return ours, status


def main():
    argv = sys.argv[1:]
    lim = None
    if '--list' in argv:
        i = argv.index('--list')
        lim = int(argv[i + 1])
        del argv[i:i + 2]
    binary, paths = argv[0], argv[1:]
    files = skipped = tot_o = tot_e = miss = extra = badname = 0
    mism = []
    t_ms = t_bytes = t_insns = t_size = 0
    max_ms = max_bytes = 0
    seen = set()
    for p in walk(paths):
        rp = os.path.realpath(p)
        if rp in seen or not is_x86_elf(p):
            continue
        seen.add(rp)
        try:
            lab = objdump_labels(p)
            ours, st = engine(binary, p)
        except subprocess.TimeoutExpired:
            mism.append((p, 'TIMEOUT'))
            continue
        if ours is None:
            skipped += 1
            continue
        files += 1
        m = re.search(r'bytes=(\d+) insns=(\d+) size=(\d+) ms=([\d.]+)', st or '')
        if m:
            t_bytes += int(m.group(1)); t_insns += int(m.group(2)); t_size += int(m.group(3)); t_ms += float(m.group(4))
            max_ms = max(max_ms, float(m.group(4))); max_bytes = max(max_bytes, int(m.group(1)))
        tot_o += len(lab)
        tot_e += len(ours)
        for a, n in lab.items():
            if a not in ours:
                miss += 1
                mism.append((p, 'missing %x %s' % (a, n)))
            elif ours[a] != n:
                badname += 1
                mism.append((p, 'name %x objdump=%s engine=%s' % (a, n, ours[a])))
        for a, n in ours.items():
            if a not in lab:
                extra += 1
                mism.append((p, 'extra %x %s' % (a, n)))
    print('files=%d skipped=%d objdump_labels=%d engine_stubs=%d missing=%d extra=%d wrong_name=%d' %
          (files, skipped, tot_o, tot_e, miss, extra, badname))
    if files:
        print('work: total %.1f ms over %d objects (%.3f ms/object, max %.3f ms), %.1f MB of file (%.1f MB/s), %d insns decoded, table bytes: total %d, max %d' %
              (t_ms, files, t_ms / files, max_ms, t_size / 1e6, t_size / 1e6 / (t_ms / 1e3) if t_ms else 0, t_insns, t_bytes, max_bytes))
    for p, m in mism[:lim if lim is not None else len(mism)]:
        print('  %s: %s' % (p, m))


main()
