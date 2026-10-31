#!/usr/bin/env python3
"""cfg_vs_rizin.py - an INDEPENDENT oracle for the engine's control-flow graph: for every function of an ELF that its symbol table names, the number of blocks and edges the engine
reports (the unit test binary build/test/unit_cfg_view_scene prints the facts text of a function: `CFG  reachable=N  edges=M`) against what rizin's own analysis says
(`afbj`: a block per entry, an edge per `jump` and per `fail`). A developer's tool, not part of a build: it needs rizin (`RIZIN`, default `rizin` on PATH; on a host behind a
sandbox pass `--rizin "flatpak-spawn --host rizin"`) and runs nothing from the tree but the test binary. No data from rizin is kept or shipped.

Usage: tools/cfg_vs_rizin.py [--rizin CMD] [--base 0x8048000] ELF [name ...]       (no names: every FUNC symbol that has a size)
The file offset of a function is its address less `--base` for a static executable that maps its first byte at `--base`.

Prints one line per function (engine blocks/edges, rizin blocks/edges, `same` or `DIFFER`) and `N of M functions agree`. A function whose graph differs is not a defect by itself: rizin
follows jump tables and merges a call that never returns; the engine's rules are the table in cfg_isa.c. The line says which of the two has more.
"""
import json
import re
import subprocess
import sys


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=600, **kw)


def main(argv):
    rizin, base, args = 'rizin', 0, []
    it = iter(argv[1:])
    for a in it:
        if a == '--rizin':
            rizin = next(it)
        elif a == '--base':
            base = int(next(it), 0)
        else:
            args.append(a)
    if not args:
        print(__doc__)
        return 2
    elf, names = args[0], args[1:]
    syms = {}
    for l in sh(['readelf', '-sW', elf]).stdout.split('\n'):
        p = l.split()
        if len(p) >= 8 and p[3] == 'FUNC' and int(p[2]) > 0 and p[1] != '0' * len(p[1]):
            syms.setdefault(p[7], int(p[1], 16))
    names = names or sorted(syms)
    cmds = '; '.join('afbj @ sym.%s' % n for n in names)
    out = sh(rizin.split() + ['-q', '-e', 'scr.color=0', '-c', 'aa; ' + cmds, elf]).stdout
    blocks = []
    for l in out.split('\n'):
        l = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', l).strip()
        if l.startswith('['):
            try:
                blocks.append(json.loads(l))
            except ValueError:
                blocks.append(None)
    same = total = 0
    for n, b in zip(names, blocks):
        if n not in syms or b is None:
            continue
        r = sh(['build/test/unit_cfg_view_scene', elf, '%x' % (syms[n] - base)])
        m = re.search(r'reachable=(\d+)\s+edges=(\d+)', r.stdout)
        if not m:
            continue
        eb, ee = int(m.group(1)), int(m.group(2))
        rb = len(b)
        re_ = sum((blk.get('jump', -1) not in (-1, 0xffffffffffffffff)) + (blk.get('fail', -1) not in (-1, 0xffffffffffffffff)) for blk in b)
        total += 1
        ok = (eb, ee) == (rb, re_)
        same += ok
        print('%-32s engine %3d blocks %3d edges   rizin %3d blocks %3d edges   %s' % (n, eb, ee, rb, re_, 'same' if ok else 'DIFFER (engine has %s)' % ('more' if eb + ee > rb + re_ else 'fewer')))
    print('%d of %d functions agree' % (same, total))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
