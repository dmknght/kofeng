#!/usr/bin/env python3
"""
check_layers.py - the include direction between the parts of the engine.

CLAUDE.md section 12: libkofeng (the engine) -> kuncoat -> kgenome -> core. A part
may include itself and what is below it; an include that points up is a defect.

The parts are named by where their code is GOING, not only where it is: the
analysis directories that still have to move into kgenome would be listed in
GENOME_DIRS (none are left: lineages moved to libgenome/phenotype). libgenome/ is
`genome` and libuncoat/ is `uncoat` - both are real directories now. So today's violations
are exactly the list of edges the move has to cut.

THE RATCHET. tools/layers.baseline lists the violations that exist today, one per
line. A violation not in it fails the check; one in it that is gone is reported
so the line can be deleted. The file only ever shrinks.

Two more checks live below the part check (the sections ENGINE ORDER and THE
TRANSITIVE CHECK), each with its own baseline file.

`abi` (libkofeng/kofcore/kofmod) is the engine's module ABI. The libs define the
types of what they analyse and the ABI headers RE-EXPORT them (kofmod/cell.h
includes <celllysis/cell.h>), so abi -> genome and abi -> uncoat are the allowed
direction. The reverse - genome or uncoat including <kofmod/...> - is a
violation, except for the exact headers in TRANSITIONAL_ABI below, which are the
cuts the migration still owes.

THE PREFIX PASS (--prefix, and part of the default run). Every public name a lib header declares
carries the lib's prefix - kgenome_ / KGENOME_ in libgenome/, kuncoat_ / KUNCOAT_ in libuncoat/
(CLAUDE.md section 12). Public is what a header declares: macros (include guards too), struct /
union / enum tags, enumerators, typedefs, functions, variables. A macro the same header #undefs is a
local helper. tools/prefix.baseline lists the names that still lack the prefix, one `path: name`
per line; like the layer baseline it only shrinks (--write-prefix-baseline rewrites it).
"""
import os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
ROOTS = ['libkofeng/kofcore', 'libgenome', 'libuncoat', 'libkofeng']
GENOME_DIRS = ()
UNCOAT_DIRS = ('libuncoat/',)

def part(p):
    if p.startswith('libgenome/'):
        return 'genome'
    if p.startswith('libkofeng/kofcore/kofmod/'):
        return 'abi'
    if p.startswith('libkofeng/kofcore/'):
        return 'core'
    if p.startswith(GENOME_DIRS):
        return 'genome'
    if p.startswith(UNCOAT_DIRS):
        return 'uncoat'
    if p.startswith('libkofeng/'):
        return 'engine'
    return None

# genome/uncoat -> abi: NONE. The lib defines the object it analyses (struct
# kgenome_obj, libgenome/genotype/image/obj.h) and the engine's head functions
# fill it through kof_genome_obj (libkofeng/analyzers/genome_obj.h); every type
# the ABI re-exports from a lib is defined in the lib. Any <kofmod/...> include
# from a lib fails the check. The set stays so a cut that cannot be made yet can
# be listed here with the reason; never add to it.
TRANSITIONAL_ABI = set()
ALLOW = {
    'core':   {'core', 'abi'},      # kofmod lives inside kofcore: same directory, same foundation
    'abi':    {'abi', 'core', 'genome', 'uncoat'},   # the ABI re-exports the libs' types
    'genome': {'genome', 'core'},
    'uncoat': {'uncoat', 'genome', 'core'},
    'engine': {'engine', 'uncoat', 'genome', 'core', 'abi'},
}
# ---- ENGINE ORDER (CLAUDE.md 12, "the engine") ---------------------------------
#
# Inside libkofeng, bottom to top. A file may include its own class and every
# class below it; an include that points up is a defect, recorded in
# tools/layers_engine.baseline until it is cut.
#
#   core       libkofeng/kofcore/**         buffers, hash, rangelist, the module ABI
#   analyzers  analyzers/**, extractors/**  what is READ out of one object
#   pack       databases/pack/**            the LAYOUT of a loaded pack and its
#                                           accessors: data, no matchers
#   detectors  detectors/**                 pattern, mutations, linkage, heur
#   databases  databases/**                 the loader and packer, which BUILD
#                                           matchers and so stand above them
#   verdictor  verdictor/**                 syndromes, verdicts
#   scanners   scanners/**                  the pipeline that drives all of it
#   api        libkofeng/kofeng.{c,h}       the public API
#
# A lower class that includes the public API header is a violation like any
# other: kofeng.h defines the result types the whole engine fills, so those
# entries are the work of moving the types down into core.
ENGINE_ORDER = ['core', 'analyzers', 'pack', 'detectors', 'databases',
                'verdictor', 'scanners', 'api']

def eclass(p):
    if p.startswith('libkofeng/kofcore/'):
        return 'core'
    if p.startswith(('libkofeng/analyzers/', 'libkofeng/extractors/')):
        return 'analyzers'
    if p.startswith('libkofeng/databases/pack/'):
        return 'pack'
    if p.startswith('libkofeng/detectors/'):
        return 'detectors'
    if p.startswith('libkofeng/databases/'):
        return 'databases'
    if p.startswith('libkofeng/verdictor/'):
        return 'verdictor'
    if p.startswith('libkofeng/scanners/'):
        return 'scanners'
    if p in ('libkofeng/kofeng.c', 'libkofeng/kofeng.h'):
        return 'api'
    return None

def engine_violations():
    out = {}
    rank = {c: i for i, c in enumerate(ENGINE_ORDER)}
    for src in sorted(sources('libkofeng')):
        a = eclass(src)
        if a is None:
            continue
        for t in includes_of(src):
            b = eclass(t)
            if b and rank[b] > rank[a]:
                out[f'{src} -> {t}  [{a} -> {b}]'] = ''
    return out

# ---- THE TRANSITIVE CHECK -------------------------------------------------------
#
# A direct include is the visible edge. core must not reach a lib through a
# chain either: rangelist.h included kofsig.h only for `struct kof_range`, and
# kofsig.h includes libgenome headers, so core depended on genome through the
# ABI header without one line saying so.
#
# Sources are the files of core PROPER (libkofeng/kofcore/ outside kofmod/).
# kofmod/ is the module ABI and re-exports the libs' types by design (see the
# part check above), so its own headers reach genome and uncoat on purpose; they
# are the intermediate nodes a core file must not walk through, not sources.
def closure_hit(src):
    seen = {src: None}
    queue = [src]
    while queue:
        f = queue.pop(0)
        for t in includes_of(f):
            if t in seen:
                continue
            seen[t] = f
            if t.startswith(('libgenome/', 'libuncoat/')):
                chain = [t]
                while seen[chain[-1]] is not None:
                    chain.append(seen[chain[-1]])
                return t, list(reversed(chain))
            queue.append(t)
    return None

def transitive_violations():
    out = {}
    for src in sorted(sources('libkofeng/kofcore')):
        if src.startswith('libkofeng/kofcore/kofmod/'):
            continue
        hit = closure_hit(src)
        if hit:
            lib = 'genome' if hit[0].startswith('libgenome/') else 'uncoat'
            out[f'{src} ~> {lib}'] = ' -> '.join(hit[1])
    return out

INC = re.compile(r'^\s*#\s*include\s+([<"])([^>"]+)[>"]', re.M)

def resolve(src, kind, name):
    cands = []
    if kind == '"':
        cands.append(os.path.normpath(os.path.join(os.path.dirname(src), name)))
    for r in ROOTS:
        cands.append(os.path.normpath(os.path.join(r, name)))
    for c in cands:
        if os.path.isfile(c):
            return c
    return None

def sources(base):
    for d, ds, fs in os.walk(base):
        for f in sorted(fs):
            if f.endswith(('.c', '.h')):
                yield os.path.join(d, f)

_inc_cache = {}
def includes_of(src):
    if src not in _inc_cache:
        try:
            text = open(src, encoding='utf-8', errors='replace').read()
        except OSError:
            text = ''
        r = []
        for m in INC.finditer(text):
            t = resolve(src, m.group(1), m.group(2))
            if t:
                r.append(t)
        _inc_cache[src] = r
    return _inc_cache[src]

def violations(transitional=None):
    out = []
    for base in ('libkofeng', 'libgenome', 'libuncoat'):
        for d, ds, fs in os.walk(base):
            for f in fs:
                if not f.endswith(('.c', '.h')):
                    continue
                src = os.path.join(d, f)
                a = part(src)
                if a is None:
                    continue
                try:
                    text = open(src, encoding='utf-8', errors='replace').read()
                except OSError:
                    continue
                for m in INC.finditer(text):
                    t = resolve(src, m.group(1), m.group(2))
                    if not t:
                        continue
                    b = part(t)
                    if b == 'abi' and a in ('genome', 'uncoat') and t in TRANSITIONAL_ABI:
                        if transitional is not None:
                            transitional.append(f'{src} -> {t}')
                        continue
                    if b and b not in ALLOW[a]:
                        out.append(f'{src} -> {t}  [{a} -> {b}]')
    return sorted(set(out))

# ---- the prefix pass --------------------------------------------------------------
PREFIX = {'libgenome/': ('kgenome_', 'KGENOME_'), 'libuncoat/': ('kuncoat_', 'KUNCOAT_')}
C_WORDS = {'enum', 'struct', 'union', 'typedef', 'static', 'extern', 'const', 'inline', 'void', 'int',
           '_Static_assert', '_Alignas', 'sizeof'}

def _blank(src):
    out = []; i = 0; n = len(src)
    while i < n:
        if src.startswith('/*', i):
            j = src.find('*/', i + 2); j = n if j < 0 else j + 2
            out.append(re.sub(r'[^\n]', ' ', src[i:j])); i = j
        elif src.startswith('//', i):
            j = src.find('\n', i); j = n if j < 0 else j
            out.append(' ' * (j - i)); i = j
        elif src[i] in '"\'':
            c = src[i]; j = i + 1
            while j < n and src[j] != c and src[j] != '\n':
                j += 2 if src[j] == '\\' else 1
            j += 1
            out.append(c + re.sub(r'[^\n]', ' ', src[i + 1:j - 1]) + c); i = j
        else:
            out.append(src[i]); i += 1
    return ''.join(out)

def header_names(path):
    """The public names a header declares (see the docstring)."""
    raw = open(path, encoding='utf-8', errors='replace').read()
    text = _blank(raw)
    names = set(); undef = set(re.findall(r'^\s*#\s*undef\s+(\w+)', text, re.M))
    lines = text.split('\n'); body = []; i = 0
    while i < len(lines):
        l = lines[i]
        if re.match(r'\s*#', l):
            full = l
            while full.rstrip().endswith('\\') and i + 1 < len(lines):
                i += 1; full += '\n' + lines[i]
            m = re.match(r'\s*#\s*define\s+(\w+)', full)
            if m and m.group(1) not in undef:
                names.add(m.group(1))
            body.append('')
            body.extend([''] * full.count('\n'))
        else:
            body.append(l)
        i += 1
    text = '\n'.join(body)
    depth = 0; cur = ''; i = 0; n = len(text)
    ident = re.compile(r'[A-Za-z_]\w*')

    def skip_braces(j):
        d = 1; j += 1
        while j < n and d:
            d += (text[j] == '{') - (text[j] == '}'); j += 1
        return j

    def decl(s):
        s = ' '.join(s.split())
        if not s:
            return
        if s.startswith('typedef'):
            m = re.search(r'\(\s*\*\s*(\w+)\s*\)', s)
            names.update([m.group(1)] if m else ident.findall(s)[-1:])
            return
        if re.match(r'(struct|union|enum)\s+\w+$', s):
            names.add(s.split()[1]); return
        head = s.split('(')[0] if '(' in s else s.split('=')[0]
        head = re.sub(r'\[[^\]]*\]', '', head.split('=')[0])
        w = ident.findall(head)
        if w:
            names.add(w[-1])
    while i < n:
        c = text[i]
        if c == ';':
            decl(cur); cur = ''
        elif c == '{':
            s = ' '.join(cur.split())
            m = re.search(r'\b(struct|union|enum)\s+(\w+)\s*$', s)
            j = skip_braces(i)
            if m:
                names.add(m.group(2))
            if re.search(r'\benum\b\s*\w*\s*$', s):
                for part in text[i + 1:j - 1].split(','):
                    mm = re.match(r'\s*(\w+)', part)
                    if mm: names.add(mm.group(1))
            if '(' in s and not re.search(r'\b(struct|union|enum)\b[^()]*$', s) and not s.startswith('typedef'):
                decl(s); cur = ''; i = j; continue
            k = text.find(';', j); k = n - 1 if k < 0 else k
            tail = text[j:k]
            if s.startswith('typedef'):
                names.update(ident.findall(tail))
            elif m is None and '=' in s:
                w = ident.findall(re.sub(r'\[[^\]]*\]', '', s.split('=')[0]))
                if w: names.add(w[-1])
            elif tail.strip():
                names.update(ident.findall(re.sub(r'\[[^\]]*\]', '', tail)))
            cur = ''; i = k + 1; continue
        else:
            cur += c
        i += 1
    return {x for x in names if x not in C_WORDS and not x[0].isdigit()}

def prefix_violations():
    out = []
    for lib, pre in PREFIX.items():
        for d, ds, fs in os.walk(lib.rstrip('/')):
            for f in sorted(fs):
                if not f.endswith('.h'):
                    continue
                p = os.path.join(d, f)
                for nm in sorted(header_names(p)):
                    if not nm.startswith(pre):
                        out.append(f'{p}: {nm}')
    return sorted(set(out))

def prefix_main(write=False):
    now = prefix_violations()
    bp = os.path.join(ROOT, 'tools', 'prefix.baseline')
    if write:
        open(bp, 'w').write('\n'.join(now) + ('\n' if now else ''))
        print('check-prefix: baseline written,', len(now), 'names')
        return 0
    base = set()
    if os.path.exists(bp):
        base = set(l.rstrip('\n') for l in open(bp) if l.strip())
    new = [v for v in now if v not in base]
    gone = [v for v in sorted(base) if v not in set(now)]
    if new:
        print('check-prefix: a lib header declares a public name without the lib prefix (CLAUDE.md 12: kgenome_/KGENOME_, kuncoat_/KUNCOAT_):')
        for v in new:
            print('  ' + v)
        return 1
    print(f'check-prefix: every public name in libgenome/ and libuncoat/ headers has the lib prefix ({len(now)} known, tools/prefix.baseline)')
    for v in gone:
        print('  fixed, delete from the baseline: ' + v)
    return 0

def ratchet(name, now, bp, write, what):
    """One baseline file. A key not in it fails; a key in it that is gone is
    reported so the line can be deleted. `now` maps key -> detail."""
    if write:
        open(bp, 'w').write(''.join(k + '\n' for k in sorted(now)))
        print(f'check-layers: {name} baseline written,', len(now), 'entries')
        return 0
    base = set()
    if os.path.exists(bp):
        base = set(l.rstrip('\n') for l in open(bp) if l.strip())
    new = [k for k in sorted(now) if k not in base]
    gone = [k for k in sorted(base) if k not in now]
    rel = os.path.relpath(bp, ROOT)
    if new:
        print(f'check-layers: {what}')
        for k in new:
            print('  ' + k + (f'   ({now[k]})' if now[k] else ''))
        return 1
    print(f'check-layers: {name}: no new violation ({len(now)} known, {rel})')
    for k in gone:
        print('  fixed, delete from the baseline: ' + k)
    return 0

def main():
    if '--prefix' in sys.argv:
        return prefix_main()
    if '--write-prefix-baseline' in sys.argv:
        return prefix_main(write=True)
    rc = layers_main()
    rc2 = prefix_main()
    return rc or rc2

def layers_main():
    if '--transitional' in sys.argv:
        tr = []
        violations(tr)
        for v in sorted(set(tr)):
            print(v)
        print(len(set(tr)), 'lib -> abi edges still allowed')
        return 0
    w = '--write-baseline' in sys.argv
    tools = os.path.join(ROOT, 'tools')
    rc = ratchet('parts', {v: '' for v in violations()},
                 os.path.join(tools, 'layers.baseline'), w,
                 'an include points up the order libkofeng -> kuncoat -> kgenome -> core (CLAUDE.md 12):')
    rc |= ratchet('engine order', engine_violations(),
                  os.path.join(tools, 'layers_engine.baseline'), w,
                  'an include points up the engine order ' + ' < '.join(ENGINE_ORDER) + ':')
    rc |= ratchet('core closure', transitive_violations(),
                  os.path.join(tools, 'layers_closure.baseline'), w,
                  'a core file reaches libgenome/libuncoat through its includes:')
    return rc

if __name__ == '__main__':
    sys.exit(main())
