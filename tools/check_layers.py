#!/usr/bin/env python3
"""
check_layers.py - the include direction between the parts of the engine.

CLAUDE.md section 12: libkofeng (the engine) -> kuncoat -> kgenome -> core. A part
may include itself and what is below it; an include that points up is a defect.

The parts are libkofeng/kofcore (`core`; its kofmod/ is `abi`), libgenome/
(`genome`), libuncoat/ (`uncoat`) and the rest of libkofeng/ (`engine`). Every rule
passes with no violation; there are no baseline files. What cannot be cut today is in
the EXEMPT table below, each entry with its reason, and an entry whose violation is
gone is reported so the line can be deleted.

Two more checks live below the part check (the sections ENGINE ORDER and THE
TRANSITIVE CHECK).

Two more passes keep the tree's own spelling rules:
TOOL INCLUDES - a program under kofscanner/, ksigbuilder/, kofwatcher/ or tools/
names the engine by an include root (<kofeng.h>, <databases/dbpacker.h>), never by
a relative path out of its own directory ("../libkofeng/..."), so the SDK headers
and the tree's inner directories stay distinguishable - and INCLUDE GUARDS - a
header's guard macro contains its file's name, so a guard cannot be copied from
another file unchanged (the two headers then silently exclude each other).

Three more passes keep what CLAUDE.md states and a grep did not see (MODULE INCLUDES - a module under bases/ is a freestanding blob and
reaches the engine and the libs only through the module ABI, so every #include in bases/
is <kofmod/...> or <kofshared/...> (and so none names another module's file: bases/ carries
no shared code); ORBIT - libkoforbit is the collectors, above the engine, so no engine or lib
file includes it; HEADERS COMPILE ALONE - every header of libkofeng/, libgenome/ and
libuncoat/ compiles by itself (gcc -std=c11 -fsyntax-only, a header of the module ABI after
<kofmod/kofsig.h>, which is how a module meets it); and TESTS DO NOT USE /tmp - no test
creates a file there (a path under /tmp in a record's text is data, not a file).

PARAMETER COUNT (no function with more than 8 parameters) is the sixth of them. Five more passes keep what CLAUDE.md states about size and naming:
ORBIT HEADERS COMPILE ALONE (the 18 non-Windows headers of libkoforbit), FUNCTION LENGTH (400
lines; EXEMPT names the interpreter loop and the unpackers of bases/, which cannot move),
FILE SIZE (a .c over 1500 lines, a header over 1000: a recorded reason, not an order to split), NO kof NAME IN libgenome (a lib defines
kgenome_ / KGENOME_ names only) and GETENV IN TESTS. A pass that is not in the default run
does not exist: all of them run with `make check-rules`, and each was shown to fail on a
deliberate violation when it was added.

`abi` (libkofeng/kofcore/kofmod) is the engine's module ABI. The libs define the
types of what they analyse and the ABI headers RE-EXPORT them (kofmod/cell.h
includes <celllysis/cell.h>), so abi -> genome and abi -> uncoat are the allowed
direction. The reverse - genome or uncoat including <kofmod/...> - is a
violation, with no exceptions.

THE PREFIX PASS (--prefix, and part of the default run). Every public name a lib header declares
carries the lib's prefix - kgenome_ / KGENOME_ in libgenome/, kuncoat_ / KUNCOAT_ in libuncoat/
(CLAUDE.md section 12). Public is what a header declares: macros (include guards too), struct /
union / enum tags, enumerators, typedefs, functions, variables. A macro the same header #undefs is a
local helper. No name is exempt.
"""
import concurrent.futures, glob, os, re, shutil, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
ROOTS = ['libkofeng/kofcore', 'libgenome', 'libuncoat', 'libkofeng', 'libkoforbit']
def part(p):
    if p.startswith('libgenome/'):
        return 'genome'
    if p.startswith('libkofeng/kofcore/kofmod/'):
        return 'abi'
    if p.startswith('libkofeng/kofcore/'):
        return 'core'
    if p.startswith('libuncoat/'):
        return 'uncoat'
    if p.startswith('libkofeng/'):
        return 'engine'
    if p.startswith('libkoforbit/'):
        return 'orbit'
    if p.startswith('bases/'):
        return 'module'
    return None

# genome/uncoat -> abi: NONE. The lib defines the object it analyses (struct
# kgenome_obj, libgenome/genotype/image/obj.h) and the engine's head functions
# fill it through kof_genome_obj (libkofeng/analyzers/genome_obj.h); every type
# the ABI re-exports from a lib is defined in the lib. Any <kofmod/...> include
# from a lib fails the check.
ALLOW = {
    'core':   {'core', 'abi'},      # kofmod lives inside kofcore: same directory, same foundation
    'abi':    {'abi', 'core', 'genome', 'uncoat'},   # the ABI re-exports the libs' types
    'genome': {'genome', 'core'},
    'uncoat': {'uncoat', 'genome', 'core'},
    'engine': {'engine', 'uncoat', 'genome', 'core', 'abi'},
    # The collectors sit above the engine (CLAUDE.md 12, "Where the rest of the tree
    # lives"; the verdict cache is "orbit, not the engine"): nothing below includes
    # them, and the standard says nothing about what they may include, so they may
    # include anything.
    'orbit':  {'orbit', 'engine', 'uncoat', 'genome', 'core', 'abi'},
    # A module is a freestanding blob: it reaches a lib only through a slot of the
    # module ABI, and a module's file is included by no other module (bases/ carries no
    # shared code). The text of the includes themselves is MODULE INCLUDES below.
    'module': {'abi'},
}
# ---- ENGINE ORDER (CLAUDE.md 12, "the engine") ---------------------------------
#
# Inside libkofeng, bottom to top. A file may include its own class and every
# class below it; an include that points up is a defect, recorded in
# EXEMPT until it is cut.
#
#   core       libkofeng/kofcore/**         buffers, hash, rangelist, the module ABI
#   analyzers  analyzers/**                 what is READ out of one object
#   pack       databases/pack/**            the LAYOUT of a loaded pack and its
#                                           accessors: data, no matchers
#   detectors  detectors/**                 pattern, mutations, linkage, heur
#   databases  databases/**                 the loader and packer, which BUILD
#                                           matchers and so stand above them
#   verdictor  verdictor/**                 verdicts
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
    if p.startswith('libkofeng/analyzers/'):
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

def violations():
    out = []
    for base in ('libkofeng', 'libgenome', 'libuncoat', 'libkoforbit', 'bases'):
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

def prefix_main():
    now = prefix_violations()
    if now:
        print('check-prefix: a lib header declares a public name without the lib prefix (CLAUDE.md 12: kgenome_/KGENOME_, kuncoat_/KUNCOAT_):')
        for v in now:
            print('  ' + v)
        return 1
    print('check-prefix: every public name in libgenome/ and libuncoat/ headers has the lib prefix')
    return 0

def ratchet(name, now, what, exempt=None):
    """One structural rule. `now` maps key -> detail. A key not in `exempt` fails.
    `exempt` maps key -> the reason it cannot be cut today (see EXEMPT); an entry
    whose key is gone is reported so the line can be deleted."""
    exempt = exempt or {}
    new = [k for k in sorted(now) if k not in exempt]
    gone = [k for k in sorted(exempt) if k not in now]
    if new:
        print(f'check-layers: {what}')
        for k in new:
            print('  ' + k + (f'   ({now[k]})' if now[k] else ''))
        return 1
    print(f'check-layers: {name}: no violation' + (f' ({len(exempt)} exempt)' if exempt else ''))
    for k in gone:
        print('  fixed, delete from EXEMPT: ' + k)
    return 0

# What cannot be cut today, with the reason. Everything else must pass with none.
EXEMPT = {
    'function length': {
        'bases/unp/mpress_pe.c: kof_unpack': 'a module: pack bytes depend on the line numbers of bases/ (CLAUDE.md 12)',
        'bases/unp/upx_elf_00.c: kof_unpack': 'a module: pack bytes depend on the line numbers of bases/ (CLAUDE.md 12)',
        'libgenome/phenotype/emu_interp.c: kgenome_emu_run': 'the interpreter loop: one switch, kept whole so the compiler inlines the hot path',
    },
    'file size': {
        'libkoforbit/grille/wevt_decode.c': 'Windows-only, cannot be compiled or checked on this host',
        'libkoforbit/grille/wproc.c': 'Windows-only, cannot be compiled or checked on this host',
        'libgenome/celllysis/decode_arm64.c': 'cohesive: the AArch64 decoder, one handler per encoding group; no function is long, nothing in it is read apart from the rest',
        'libgenome/phenotype/emu_interp.c': 'cohesive: the interpreter loop and the inlined step helpers it is kept whole with (the register, flag and operand accessors are emu_state.c)',
        'libgenome/phenotype/emu_private.h': 'cohesive: the interpreter family\'s ONE private header (the machine, its state, and what each part of the interpreter offers another: the vector, x87, integer and syscall parts all read it); a header per part would be several private headers for one family',
        'libuncoat/decompressors/ppmd.c': 'cohesive: one PPMd variant H decoder (model, range coder, symbol decode share one state)',
        'tools/genotype/x86_gen.c': 'needs the external reference decoder to build or verify a split',
    },
    'parameter count': {
        'libgenome/genotype/image/elf_rebuild.h: kgenome_elf_write_hdr': 'the old form kofexamine calls; moves to the struct form in its upgrade',
    },
    'getenv in tests': {
        'tests/unit/budget.c: getenv(KOF_BUDGET_TRACE)': 'a trace switch of the test itself',
        'tests/unit/db_scale.c: getenv(KOF_SCALE_MODS)': 'the size of the scale run, chosen by the caller',
    },
}

# ---- TOOL INCLUDES --------------------------------------------------------------
#
# The programs are built against the engine's include roots (CFLAGS carries
# -Ilibkofeng/kofcore; ksigbuilder adds -Ilibkofeng), so a tool that writes
# "../libkofeng/databases/x.h" is reaching around the root by a path that only
# works from where it sits. kofscanner is the one that says it is written against
# the SDK headers alone (Makefile, "the scanner"): a reach by path was how it
# came to include three core headers the SDK did not ship.
TOOL_DIRS = ('kofscanner', 'ksigbuilder', 'kofwatcher', 'tools')
ENGINE_TREES = ('libkofeng', 'libgenome', 'libuncoat', 'libkoforbit')
REL_INC = re.compile(r'^\s*#\s*include\s+"((?:\.\./)+)([^"]+)"', re.M)

def tool_include_violations():
    out = {}
    for base in TOOL_DIRS:
        for src in sorted(sources(base)):
            try:
                text = open(src, encoding='utf-8', errors='replace').read()
            except OSError:
                continue
            for m in REL_INC.finditer(text):
                target = os.path.normpath(os.path.join(os.path.dirname(src), m.group(1) + m.group(2)))
                if target.split(os.sep)[0] in ENGINE_TREES:
                    out[f'{src} -> {target}'] = ''
    return out

# ---- INCLUDE GUARDS -------------------------------------------------------------
#
# The guard is the file's own name, upper-cased, with every non-word character an
# underscore: pe_unmap.h -> a macro containing PE_UNMAP, ending _H. A guard that
# does not carry the name is one that was copied from another header and not
# renamed - two files with one guard include each other away, and nothing says so.
# libgenome/ and libuncoat/ headers are covered by the prefix pass (a guard is a
# public macro there, and must carry the lib's prefix as well).
GUARD = re.compile(r'^\s*#\s*ifndef\s+(\w+)\s*\n\s*#\s*define\s+\1\b', re.M)

def guard_violations():
    out = {}
    for d, ds, fs in os.walk('.'):
        ds[:] = [x for x in ds if not x.startswith('.') and x != 'build']
        rel = os.path.normpath(d)
        if rel.startswith(('libgenome', 'libuncoat')):
            continue
        for f in sorted(fs):
            if not f.endswith('.h'):
                continue
            p = os.path.normpath(os.path.join(d, f))
            try:
                text = open(p, encoding='utf-8', errors='replace').read()
            except OSError:
                continue
            m = GUARD.search(text)
            stem = re.sub(r'\W', '_', f[:-2]).upper()
            if not m:
                out[f'{p}: no include guard'] = ''
            elif stem not in m.group(1) or not m.group(1).endswith('_H'):
                out[f'{p}: guard {m.group(1)}'] = f'expected a guard containing {stem} and ending _H'
    return out

# ---- MODULE INCLUDES ------------------------------------------------------------
#
# bases/ is case routines built into freestanding blobs: "they reach a lib only
# through a slot of the module ABI" and "bases/ does not carry shared code"
# (CLAUDE.md 12). In include terms that is one rule - everything a module names is
# <kofmod/...> (the ABI and its module-side helpers) or <kofshared/...> (the disease
# units the SDK ships, msf_*.h) - and it covers the system headers too: a blob has no
# libc to include.
MODULE_OK = ('kofmod/', 'kofshared/')

def module_include_violations():
    out = {}
    for src in sorted(sources('bases')):
        try:
            text = open(src, encoding='utf-8', errors='replace').read()
        except OSError:
            continue
        for m in INC.finditer(text):
            name = m.group(2)
            if m.group(1) == '<' and name.startswith(MODULE_OK):
                continue
            out[f'{src}: #include {m.group(1)}{name}{">" if m.group(1) == "<" else chr(34)}'] = ''
    return out

# ---- LIB PUBLIC HEADERS ---------------------------------------------------------
#
# "One public header per lib" (CLAUDE.md 12): the surface of kgenome is <kgenome.h> and
# the part headers it lists, the surface of kuncoat is <uncoat.h> and the headers it
# lists. Everything else - every `_private.h`, anything the umbrella does not name - is
# the lib's own. A file outside the lib (the engine, the orbit, the programs under
# kofscanner/, ksigbuilder/, kofwatcher/, tools/, kofexamine/) that includes one of those
# is reaching into the lib. libkofeng/kofcore/kofmod/ is not checked: it is the module
# ABI and re-exports the libs' own types by design (an intermediate node, see the core
# closure). tests/ is not checked either: a white-box test of a lib includes its
# private header (and belongs in tests/lib/<lib>/ when it links the lib alone).
LIB_UMBRELLAS = ('libgenome/kgenome.h', 'libuncoat/uncoat.h')
LIB_PUBLIC_FROM = ('libkofeng', 'libkoforbit', 'kofscanner', 'ksigbuilder', 'kofwatcher',
                   'tools', 'kofexamine')
ABI_DIR = 'libkofeng/kofcore/kofmod/'

def lib_public_violations():
    pub = set(LIB_UMBRELLAS)
    for u in LIB_UMBRELLAS:
        for t in includes_of(u):
            pub.add(t)
    out = {}
    for base in LIB_PUBLIC_FROM:
        for src in sorted(sources(base)):
            if src.startswith(ABI_DIR):
                continue
            for t in includes_of(src):
                if t.startswith(('libgenome/', 'libuncoat/')) and t not in pub:
                    out[f'{src} -> {t}'] = ('private header' if t.endswith('_private.h')
                                            else 'not named by ' + ' or '.join(LIB_UMBRELLAS))
    return out

# ---- HEADERS COMPILE ALONE ------------------------------------------------------
#
# A header that needs something included before it is a header whose first includer
# works by accident. Every header of the three libs is compiled by itself with
# -fsyntax-only. Three things are said here and not hidden:
#   - _GNU_SOURCE is defined, because a feature test macro belongs to the translation
#     unit and not to a header (kofplatform.h says so where it calls memmem);
#   - a header of the module ABI is compiled after <kofmod/kofsig.h>, which is how a
#     module meets it ("a module includes after <kofmod/kofsig.h>", CLAUDE.md 12);
#   - analyzers/diseases/msf_*.h are skipped: they include <kofshared/...>, a path that
#     exists only in the staged SDK, and compile there.
# Cheap: about 220 headers in well under a second on 16 threads.
HEADER_TREES = ('libkofeng', 'libgenome', 'libuncoat')
HEADER_SKIP = re.compile(r'^libkofeng/analyzers/diseases/msf_[^/]*\.h$')

def _header_compile(cc, h):
    args = [cc, '-std=c11', '-fsyntax-only', '-D_GNU_SOURCE', '-x', 'c',
            '-Ilibkofeng/kofcore', '-Ilibgenome', '-Ilibuncoat']
    if h.startswith('libkofeng/kofcore/kofmod/'):
        # after the umbrella, as a module meets it
        src = '#include <kofmod/kofsig.h>\n#include "%s"\n' % os.path.abspath(h)
        r = subprocess.run(args + ['-'], input=src, capture_output=True, text=True)
    else:
        r = subprocess.run(args + [h], capture_output=True, text=True)
    if r.returncode == 0:
        return None
    first = [l for l in r.stderr.split('\n') if 'error' in l]
    return (first[0] if first else r.stderr.split('\n')[0])[:160]

def header_violations():
    cc = os.environ.get('CC') or shutil.which('cc') or shutil.which('gcc') or shutil.which('clang')
    out = {}
    if not cc:
        print('check-layers: headers compile alone: skipped, no C compiler found')
        return out
    hs = [h for base in HEADER_TREES for h in sorted(sources(base))
          if h.endswith('.h') and not HEADER_SKIP.match(h)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as ex:
        for h, err in zip(hs, ex.map(lambda x: _header_compile(cc, x), hs)):
            if err:
                out[f'{h}: does not compile alone'] = err
    return out

# ---- TESTS DO NOT USE /tmp ------------------------------------------------------
#
# "Scratch files go in /mnt/games/, never /tmp" (CLAUDE.md, Working in this tree):
# the tmpfs there is 3.2 GB and filling it broke the build twice. A test creates its
# files under the build tree. What is checked is a CREATING call, because a path that
# starts with /tmp is also ordinary text in a record under test ("/tmp/x" as the
# image of a process): a "/tmp" string in a statement that opens, creates, renames or
# removes, or in a statement that builds a path a later such call takes, and the
# names that choose /tmp for you (tmpfile, tmpnam, tempnam, P_tmpdir, kof_tmpdir).
# Honouring TMPDIR is fine - that is the caller choosing; defaulting to /tmp is not.
TMP_TEST_TREES = ('tests',)
FS_CALL = (r'(?:fopen|freopen|open|openat|creat|mkdir|mkdirat|mkstemp|mkdtemp|rename|'
           r'renameat|unlink|remove|rmdir|symlink|link|truncate|kof_fopen\w*|kof_mkdir\w*|'
           r'kof_truncate_file|kof_rename\w*|kof_remove\w*|kofevt_log_open\w*)')
TMP_LITERAL = re.compile(r'"[^"\n]*(?<![\w.-])/tmp\b[^"\n]*"')
TMP_NAMES = re.compile(r'\b(?:tmpfile|tmpnam|tempnam|kof_tmpdir)\s*\(|\bP_tmpdir\b')

def _strip_comments(src):
    """Comments blanked, string literals kept (a string may contain /* or //)."""
    return re.sub(r'/\*.*?\*/|//[^\n]*|("(?:\\.|[^"\\\n])*")',
                  lambda m: m.group(1) if m.group(1) else re.sub(r'[^\n]', ' ', m.group(0)),
                  src, flags=re.S)

def tests_tmp_violations():
    out = {}
    for base in TMP_TEST_TREES:
        for src in sorted(sources(base)):
            try:
                text = _strip_comments(open(src, encoding='utf-8', errors='replace').read())
            except OSError:
                continue
            for m in TMP_NAMES.finditer(text):
                out[f'{src}:{text.count(chr(10), 0, m.start()) + 1}: {m.group(0).strip("(").strip()}'] = ''
            for m in TMP_LITERAL.finditer(text):
                lo = max(text.rfind(c, 0, m.start()) for c in ';{}') + 1
                hi = text.find(';', m.end())
                hi = len(text) if hi < 0 else hi
                stmt = text[lo:hi]
                line = text.count('\n', 0, m.start()) + 1
                hit = re.search(FS_CALL + r'\s*\(', stmt)
                if hit:
                    out[f'{src}:{line}: "/tmp" given to {hit.group(0).rstrip("( ")}'] = ''
                    continue
                # a path built here and taken by a creating call further down
                var = (re.match(r'\s*(?:snprintf|sprintf|strcpy|strcat|strncpy|kof_\w*cpy)\s*\(\s*(\w+)', stmt)
                       or re.match(r'[\w\s\*]*?\b(\w+)\s*(?:\[[^\]]*\])?\s*=\s*$', stmt[:m.start() - lo]))
                if var:
                    later = re.search(FS_CALL + r'\s*\([^;]*\b' + re.escape(var.group(1)) + r'\b', text[hi:])
                    if later:
                        out[f'{src}:{line}: "/tmp" path {var.group(1)} reaches a creating call'] = ''
    return out

# ---- ORBIT HEADERS COMPILE ALONE -------------------------------------------------
#
# The headers of libkoforbit (the collectors and the event, cache and report
# libraries) are included by tools and tests that each build their own list of
# sources, so a header that needs something included before it fails only in
# whichever tool happens to include it first. Same test as HEADERS COMPILE ALONE,
# with the orbit include roots added. The Windows half (grille/, chan_win.c) needs
# windows.h and is skipped, as it cannot be compiled on a POSIX host: its headers are
# not tested by this pass.
ORBIT_SKIP = re.compile(r'^libkoforbit/(grille/|chan/chan_win)')

def _orbit_header_compile(cc, h):
    args = [cc, '-std=c11', '-fsyntax-only', '-D_GNU_SOURCE', '-x', 'c',
            '-Ilibkofeng', '-Ilibkofeng/kofcore', '-Ilibgenome', '-Ilibuncoat']
    for d in sorted(os.listdir('libkoforbit')):
        if os.path.isdir(os.path.join('libkoforbit', d)) and d != 'grille':
            args.append('-Ilibkoforbit/' + d)
    r = subprocess.run(args + [h], capture_output=True, text=True)
    if r.returncode == 0:
        return None
    first = [l for l in r.stderr.split('\n') if 'error' in l]
    return (first[0] if first else r.stderr.split('\n')[0])[:160]

def orbit_header_violations():
    cc = os.environ.get('CC') or shutil.which('cc') or shutil.which('gcc') or shutil.which('clang')
    out = {}
    if not cc:
        print('check-layers: orbit headers compile alone: skipped, no C compiler found')
        return out
    hs = [h for h in sorted(sources('libkoforbit')) if h.endswith('.h') and not ORBIT_SKIP.match(h)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as ex:
        for h, err in zip(hs, ex.map(lambda x: _orbit_header_compile(cc, x), hs)):
            if err:
                out[f'{h}: does not compile alone'] = err
    return out

# ---- FUNCTION LENGTH --------------------------------------------------------------
#
# CLAUDE.md 12: "A function longer than about 400 lines is a sequence of named static
# steps". The ceiling is 400 lines, counted from the line of the signature's closing
# parenthesis to the closing brace at column 0, comments and blank lines included. What
# is in EXEMPT cannot move today: kgenome_emu_run (the interpreter loop,
# one switch whose cases share the register state in locals - a split would put that
# state behind a struct on the hot path) and the unpackers under bases/ (a module's
# object bytes depend on the order and the source lines of its functions, so splitting
# one changes the pack with no change of behaviour - CLAUDE.md 12, "bases/").
FN_CEILING = 400
# kofexamine/ (the examiner and the viewer) is outside the scope of this pass and of FILE SIZE:
# it is a separate tool tree with its own long units, not yet split.
FN_TREES = ('libkofeng', 'libgenome', 'libuncoat', 'libkoforbit', 'kofscanner',
            'kofwatcher', 'ksigbuilder', 'tools', 'bases')
FN_HEAD = re.compile(r'^((?:static\s+|inline\s+|const\s+)*[A-Za-z_][\w\s\*]*?\b([A-Za-z_]\w*)\s*\([^;{}]*\))\s*\{', re.M)
FN_NOT = ('if', 'for', 'while', 'switch', 'sizeof')

def function_length_violations():
    out = {}
    for base in FN_TREES:
        for src in sorted(sources(base)):
            try:
                text = _blank(open(src, encoding='utf-8', errors='replace').read())
            except OSError:
                continue
            for m in FN_HEAD.finditer(text):
                if m.group(2) in FN_NOT:
                    continue
                e = re.compile(r'^\}', re.M).search(text, m.end())
                end = e.end() if e else len(text)
                n = text.count('\n', m.start(), end) + 1
                if n > FN_CEILING:
                    out[f'{src}: {m.group(2)}'] = f'{n} lines, ceiling {FN_CEILING}'
    return out

# ---- PARAMETER COUNT --------------------------------------------------------------
#
# CLAUDE.md 12, "One request, one result": a function with more than 8 parameters is a
# stage whose input is several things that are really one (a window, a sink, options, a
# budget). Each stage takes ONE request struct and fills ONE result struct; the budget,
# the ledger and the status come from the caller as members. Counted over every function
# DEFINITION in the .c and .h of the engine, the libs and the programs (libkoforbit and its
# Windows collectors, kofexamine/ and bases/ are outside the scope: the first is built for
# another platform, the second is a separate tool tree, the third is a module ABI whose
# signatures are fixed). What is in EXEMPT cannot move today:
# kgenome_elf_write_hdr is the positional form kept for kofexamine, which moves to the
# struct form (kgenome_elf_hdr_write) in its own upgrade.
PARAM_MAX = 8
PARAM_TREES = ('libkofeng', 'libgenome', 'libuncoat', 'ksigbuilder', 'kofscanner', 'kofwatcher')

def _param_count(params):
    params = params.strip()
    if not params or params == 'void':
        return 0
    depth = 0; n = 1
    for c in params:
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        elif c == ',' and depth == 0:
            n += 1
    return n

def param_count_violations():
    out = {}
    for base in PARAM_TREES:
        for src in sorted(sources(base)):
            try:
                text = _blank(open(src, encoding='utf-8', errors='replace').read())
            except OSError:
                continue
            for m in FN_HEAD.finditer(text):
                name = m.group(2)
                if name in FN_NOT:
                    continue
                head = m.group(1)
                o = re.search(r'\b' + re.escape(name) + r'\s*\(', head)
                if not o:
                    continue
                n = _param_count(head[o.end():head.rindex(')')])
                if n > PARAM_MAX:
                    out[f'{src}: {name}'] = f'{n} parameters, limit {PARAM_MAX}'
    return out

# ---- FILE SIZE --------------------------------------------------------------------
#
# A hand-written .c over 1500 lines or a header over 1000 lines is a prompt to LOOK, not an
# order to split (CLAUDE.md 12, "Where code lives"). Size is not the fault; a file that
# mixes jobs a reader would look for separately is, and a file that is one job (one
# decoder, one interpreter loop, one generated table) is not made better by cutting it.
# So a file over the ceiling needs a recorded reason, and there are two: split it by
# purpose (one private header per family), or put it in EXEMPT['file size'] with a
# one-line reason of the form 'cohesive: <what it is>'. Generated files are exempt by
# name, and so is the one module-ABI struct header, kofmod/kofcontent.h, which is one
# struct (the vtable) whose member order is the ABI. libgenome/ is in the pass; the
# Windows-only orbit files (grille/wproc.c, grille/wevt_decode.c) are listed because
# they cannot be compiled or checked on this host. What is in EXEMPT is over the
# ceiling today; a file that drops under it is reported so its line goes.
SIZE_C, SIZE_H = 1500, 1000
SIZE_TREES = ('libkofeng', 'libgenome', 'libkoforbit', 'libuncoat', 'kofscanner', 'kofwatcher',
              'ksigbuilder', 'tools')
SIZE_EXEMPT = re.compile(r'(^|/)(x86_tab\.c|x86_ids\.h|kofcontent\.h)$')

def size_violations():
    out = {}
    for base in SIZE_TREES:
        for src in sorted(sources(base)):
            if SIZE_EXEMPT.search(src):
                continue
            cap = SIZE_C if src.endswith('.c') else SIZE_H
            try:
                n = sum(1 for _ in open(src, encoding='utf-8', errors='replace'))
            except OSError:
                continue
            if n > cap:
                out[src] = f'{n} lines, ceiling {cap}'
    return out

# ---- NO kof NAME DEFINED INSIDE libgenome ------------------------------------------
#
# CLAUDE.md 12: "No kof in a name inside libgenome" - what the lib defines carries
# kgenome_ / KGENOME_ (the prefix pass checks the headers; this one covers the .c files
# too, where a static helper or a local macro is just as much a name). A lib may USE a
# core name (kof_buf, kof_ld_le32); what it may not do is define one. Looked for: a
# #define, a typedef / struct / union / enum tag, or a function definition or
# declaration at column 0 whose name begins kof_ / KOF_.
KOF_DEF = re.compile(
    r'^\s*#\s*define\s+((?:kof|KOF)_\w+)'
    r'|^\s*(?:typedef\s+)?(?:struct|union|enum)\s+(kof_\w+)\s*(?:\{|$)'
    r'|^\s*typedef\b[^;(]*\b(kof_\w+)\s*;'
    r'|^[A-Za-z_][\w \t\*]*?\b(kof_\w+)\s*\([^;]*$'
    r'|^[A-Za-z_][\w \t\*]*?\b(kof_\w+)\s*\([^;]*\)\s*;', re.M)

def genome_kof_violations():
    out = {}
    for src in sorted(sources('libgenome')):
        try:
            text = _blank(open(src, encoding='utf-8', errors='replace').read())
        except OSError:
            continue
        for m in KOF_DEF.finditer(text):
            name = next(g for g in m.groups() if g)
            out[f'{src}: {name}'] = ''
    return out

# ---- BYTE CLASSES IN THE TEXT ROUTE AND THE LEXERS -------------------------------------
#
# "Use the API. Do not write the logic a second time" (kofeng/CLAUDE.md 2): core's kofcore.h
# answers "is this byte a letter" (kof_is_alpha), "a letter or a digit or _" (kof_is_word_byte), "a
# hex digit" (kof_hex_val) and "this byte, lower case" (kof_lower_byte), and every one of them is
# the same on every locale. The TEXT route (libgenome/phenotype/diag_text*) and the lexers
# (libgenome/textual/) had four open-coded `(c | 0x20) - 'a'` letter tests of their own, and
# three of the route's files included <ctype.h> for nothing: a ctype call reads the locale, so in a
# locale that is not "C" a byte above 0x7f may be a letter and the route reads a script
# differently from one host to the next. Looked for, in comments-stripped text: the open-coded
# fold, an include of <ctype.h>, and a call of a ctype function.
TEXT_FAMILY = re.compile(r'^libgenome/(phenotype/diag_text[^/]*\.[ch]|textual/.*\.[ch])$')
FOLD_OPEN = re.compile(r"\|\s*0x20u?\s*\)\s*-\s*'a'")
CTYPE_INC = re.compile(r'^\s*#\s*include\s*<ctype\.h>', re.M)
CTYPE_CALL = re.compile(r'\b(?:isalpha|isdigit|isalnum|isspace|isupper|islower|isxdigit|ispunct|isprint|isgraph|iscntrl|tolower|toupper)\s*\(')

def text_class_violations():
    out = {}
    for src in sorted(sources('libgenome')):
        if not TEXT_FAMILY.match(src):
            continue
        try:
            text = _strip_comments(open(src, encoding='utf-8', errors='replace').read())
        except OSError:
            continue
        for m in FOLD_OPEN.finditer(text):
            out[f'{src}:{text.count(chr(10), 0, m.start()) + 1}: open-coded letter test'] = 'kof_is_alpha / kof_is_word_byte / kof_hex_val'
        if CTYPE_INC.search(text):
            out[f'{src}: includes <ctype.h>'] = 'the route reads no locale'
        for m in CTYPE_CALL.finditer(text):
            out[f'{src}:{text.count(chr(10), 0, m.start()) + 1}: ctype call'] = 'locale dependent'
    return out

# ---- getenv IN THE TESTS ----------------------------------------------------------
#
# The getenv rule is the Makefile's check-rules (the engine, the libs and the tools).
# A test may read an environment variable to size a run or find a scratch directory -
# the caller choosing - but a test that reads one to change WHAT it checks passes or
# fails by the shell it ran in. TMPDIR, TMP and TEMP are the caller choosing scratch space and are
# allowed. The sites that exist today are in EXEMPT,
# one per file and variable; a new one fails the check.
GETENV = re.compile(r'\bgetenv\s*\(\s*"(\w+)"\s*\)')

def tests_getenv_violations():
    out = {}
    for src in sorted(sources('tests')):
        try:
            text = _strip_comments(open(src, encoding='utf-8', errors='replace').read())
        except OSError:
            continue
        for m in GETENV.finditer(text):
            if m.group(1) in ('TMPDIR', 'TMP', 'TEMP'):
                continue    # the caller choosing where scratch files go
            out[f'{src}: getenv({m.group(1)})'] = ''
    return out


# ---- FUZZ COVERAGE ----------------------------------------------------------------
#
# Every public function of the lib surfaces - the umbrellas <kgenome.h> and <uncoat.h> with the part headers they
# name, and the core helpers they expose - needs a row in a fuzz adapter (tests/fuzz/<stage>/*.c: `.covers = "fn ..."`
# on an FZ_ADAPTER row, and the function is CALLED in that file) or an entry of the EXEMPT tables
# (tests/fuzz/exempt/*.txt, `function<TAB>reason`). A new public function with neither FAILS here, which is how "every new
# function is covered" is enforced. permanent.txt holds what bytes cannot drive (a wall clock, a path); wp<N>.txt hold the
# functions that are only waiting for work package N - the package deletes its lines as it adds its rows, and a function that
# is both covered and exempt fails too, so the tables cannot go stale. The surface is read from the headers by the same
# rule as the plan's api.tsv (465 functions when this pass was added): static functions without a body are skipped,
# static inline ones count.
FUZZ_TOPS = ('libgenome/kgenome.h', 'libuncoat/uncoat.h')
FUZZ_CORE = {'kofcore.h', 'range.h', 'rangelist.h', 'heapsort.h', 'kofcmp.h', 'kofbytes.h', 'kofstrlist.h', 'kofentropy.h',
             'kofhash.h', 'tabgrow.h', 'runlist.h', 'kofbudget.h'}
# The examiner's terminal-free API (phase B of the examiner suite): the three headers whose functions a person's typing or a corrupt object
# reaches (goto_parse.h is a header-only static function that this reader does not list; its adapter row has no .covers). The viewer's own units (kv_*.c) and the examiner command (kofexaminer*.c) are not here: they are driven by tests/tui.
FUZZ_TOOL_HEADERS = ('kofexamine/kofinspect.h', 'kofexamine/codec_ui.h', 'kofexamine/kofscfind.h')
FUZZ_NOT_FN = {'if', 'while', 'for', 'sizeof', 'defined', 'switch', 'return', '__attribute__'}
FUZZ_COVERS = re.compile(r'\.covers\s*=\s*((?:"[^"\n]*"\s*)+)')

def fuzz_headers():
    seen, stack, out = set(), [t for t in FUZZ_TOPS if os.path.exists(t)], []
    while stack:
        f = stack.pop()
        if f in seen:
            continue
        seen.add(f)
        stack.extend(includes_of(f))
        base = os.path.basename(f)
        if f.endswith('_private.h') or (f.startswith('libkofeng') and base not in FUZZ_CORE):
            continue
        out.append(f)
    for c in sorted(FUZZ_CORE):
        f = 'libkofeng/kofcore/' + c
        if f not in out and os.path.exists(f):
            out.append(f)
    for f in FUZZ_TOOL_HEADERS:
        if os.path.exists(f):
            out.append(f)
    # libkoforbit (system-resource handling, orbit): every header that is not private to its directory (`*_int.h`).
    for d, ds, fs in os.walk('libkoforbit'):
        for f in sorted(fs):
            if f.endswith('.h') and not f.endswith(('_int.h', '_private.h')):
                out.append(os.path.join(d, f))
    return sorted(set(out))

def _fuzz_statements(s):
    res, depth, cur, kind = [], 0, [], None
    for c in s:
        if c == '{':
            if depth == 0:
                head = ''.join(cur).strip()
                kind = 'fn' if re.search(r'\)\s*(?:__attribute__\s*\(\(.*?\)\)\s*)?$', head) else 'agg'
            depth += 1
            if depth > 1 or kind == 'agg':
                cur.append(c)
            continue
        if c == '}':
            depth -= 1
            if depth == 0 and kind == 'fn':
                res.append((''.join(cur).strip(), True))
                cur, kind = [], None
            else:
                cur.append(c)
            continue
        if depth > 0 and kind == 'fn':
            continue
        if c == ';' and depth == 0:
            res.append((''.join(cur).strip(), False))
            cur = []
            continue
        cur.append(c)
    return res

def fuzz_functions(path):
    text = _strip_comments(open(path, encoding='utf-8', errors='replace').read())
    text = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', text).replace('\\\n', ' ')
    text = '\n'.join('' if re.match(r'\s*#', ln) else ln for ln in text.split('\n'))
    names = []
    for st, has_body in _fuzz_statements(text):
        st = ' '.join(st.split())
        if not st or st.startswith('typedef') or re.match(r'(struct|enum|union)\s+\w+\s*(\{|$)', st) or '(' not in st:
            continue
        m = re.match(r'(.*?)\b([A-Za-z_]\w*)\s*\((.*)\)\s*(?:__attribute__.*)?$', st)
        if not m or not m.group(1).strip() or m.group(2) in FUZZ_NOT_FN:
            continue
        if 'static' in m.group(1).split() and not has_body:
            continue
        names.append(m.group(2))
    return names

# The container parsers of the engine (libkofeng/analyzers/parsers/containers/*_parse.h) are the byte-drivable entry points of the
# container stage, and are in the surface too: sniff, parse, and the view's mem / row / release. They are driven by tests/fuzz/container.
FUZZ_CONTAINER_FN = re.compile(r'kof_\w+_(?:parse|sniff|release|row|mem)$')

def fuzz_surface():
    out = {}
    for h in fuzz_headers():
        for n in fuzz_functions(h):
            out.setdefault(n, h)
    for h in sorted(glob.glob('libkofeng/analyzers/parsers/containers/*_parse.h')):
        for n in fuzz_functions(h):
            if FUZZ_CONTAINER_FN.match(n):
                out.setdefault(n, h)
    return out

def fuzz_rows():
    """(function -> files that cover it), and the covers entries that are wrong."""
    cov, bad = {}, {}
    surface = fuzz_surface() if os.path.isdir('tests/fuzz') else {}
    for src in sorted(sources('tests/fuzz')):
        if not src.endswith('.c'):
            continue
        raw = open(src, encoding='utf-8', errors='replace').read()
        code = _strip_comments(raw)
        for m in FUZZ_COVERS.finditer(raw):
            for fn in ''.join(re.findall(r'"([^"\n]*)"', m.group(1))).split():
                cov.setdefault(fn, []).append(src)
                if fn not in surface:
                    bad[f'{src}: .covers names {fn}'] = 'not a public function of the lib surface (renamed, removed or misspelt)'
                elif not re.search(r'\b' + re.escape(fn) + r'\s*\(', re.sub(r'"[^"\n]*"', '""', code)):
                    bad[f'{src}: .covers names {fn}'] = 'the adapter file never calls it'
    return cov, bad

def fuzz_exempt():
    out = {}
    for src in sorted(glob.glob('tests/fuzz/exempt/*.txt')):
        for ln in open(src, encoding='utf-8'):
            ln = ln.rstrip('\n')
            if ln.strip() and not ln.startswith('#'):
                fn, _, why = ln.partition('\t')
                if not why.strip():
                    out[f'{src}: {fn}'] = 'an EXEMPT entry needs a reason after a tab'
                out.setdefault(fn.strip(), os.path.basename(src))
    return out

def fuzz_cover_violations():
    if not os.path.isdir('tests/fuzz'):
        return {}
    surface = fuzz_surface()
    cov, out = fuzz_rows()
    ex = fuzz_exempt()
    for k, v in list(ex.items()):
        if ' ' in k:
            out[k] = v
    for fn, h in sorted(surface.items()):
        if fn not in cov and fn not in ex:
            out[f'{h}: {fn}'] = 'no adapter row (.covers) and no EXEMPT entry'
        elif fn in cov and fn in ex:
            out[f'{h}: {fn}'] = f'covered by {cov[fn][0]} and still in tests/fuzz/exempt/{ex[fn]}: delete the entry'
    for fn, f in sorted(ex.items()):
        if ' ' not in fn and fn not in surface:
            out[f'tests/fuzz/exempt/{f}: {fn}'] = 'not a public function any more: delete the entry'
    return out

def main():
    if '--prefix' in sys.argv:
        return prefix_main()
    rc = layers_main()
    rc2 = prefix_main()
    return rc or rc2

def layers_main():
    rc = ratchet('parts', {v: '' for v in violations()},
                 'an include points up the order libkofeng -> kuncoat -> kgenome -> core (CLAUDE.md 12):')
    rc |= ratchet('engine order', engine_violations(),
                 'an include points up the engine order ' + ' < '.join(ENGINE_ORDER) + ':')
    rc |= ratchet('core closure', transitive_violations(),
                 'a core file reaches libgenome/libuncoat through its includes:')
    rc |= ratchet('tool includes', tool_include_violations(),
                 'a program names the engine by a relative path (use an include root, <kofeng.h> or <databases/x.h>):')
    rc |= ratchet('include guards', guard_violations(),
                 'a header guard does not carry the header\'s name:')
    rc |= ratchet('module includes', module_include_violations(),
                 'a module (bases/) names something other than <kofmod/...> or <kofshared/...>:')
    rc |= ratchet('lib public headers', lib_public_violations(),
                 'a file outside a lib includes a header the lib\'s umbrella (kgenome.h, uncoat.h) does not name:')
    rc |= ratchet('headers compile alone', header_violations(),
                 'a header of libkofeng/, libgenome/ or libuncoat/ needs something included before it:')
    rc |= ratchet('tests and /tmp', tests_tmp_violations(),
                 'a test creates a file under /tmp (use the build tree; /tmp is a 3.2 GB tmpfs):')
    rc |= ratchet('orbit headers compile alone', orbit_header_violations(),
                 'a header of libkoforbit/ needs something included before it:')
    rc |= ratchet('function length', function_length_violations(),
                 f'a function is longer than {FN_CEILING} lines (a sequence of named static steps, CLAUDE.md 12):', EXEMPT['function length'])
    rc |= ratchet('parameter count', param_count_violations(),
                 f'a function takes more than {PARAM_MAX} parameters (one request struct and one result struct, CLAUDE.md 12):', EXEMPT['parameter count'])
    rc |= ratchet('file size', size_violations(),
                 f'a .c file is over {SIZE_C} lines or a header over {SIZE_H} (split it by purpose, or record why it is one job in EXEMPT, CLAUDE.md 12):', EXEMPT['file size'])
    rc |= ratchet('no kof name in libgenome', genome_kof_violations(),
                 'libgenome defines a kof_ / KOF_ name (the lib is kgenome_ / KGENOME_, CLAUDE.md 12):')
    rc |= ratchet('text route byte classes', text_class_violations(),
                 'the TEXT route or a lexer spells a byte class itself or reads the locale (use kofcore.h: kof_is_alpha, kof_is_word_byte, kof_hex_val, kof_lower_byte):')
    rc |= ratchet('getenv in tests', tests_getenv_violations(),
                 'a test reads the environment (see the note at tests_getenv_violations):', EXEMPT['getenv in tests'])
    rc |= ratchet('fuzz coverage', fuzz_cover_violations(),
                 'a public function has no fuzz adapter row and no EXEMPT entry, or a table is stale (tests/fuzz/README.txt):')
    rc |= known_defect_main()
    return rc

def known_defect_main():
    """KNOWN DEFECT comments (tools/known_defects.py): count is informational, a malformed one fails."""
    sys.path.insert(0, os.path.join(ROOT, 'tools'))
    import known_defects
    recs, errs = known_defects.scan(ROOT)
    n = len([r for r in recs if not r['ref']])
    sv = {k: len([r for r in recs if not r['ref'] and r.get('sev') == k]) for k in 'HML'}
    print(f'check-layers: KNOWN DEFECT comments: {n} recorded (high {sv["H"]}, medium {sv["M"]}, low {sv["L"]}), {len([r for r in recs if r["ref"]])} test rows pin one (informational)')
    if errs:
        print('check-layers: a KNOWN DEFECT comment is malformed, orphaned, duplicated, under bases/, or a test row names an id with no comment (tools/known_defects.py):')
        for e in errs:
            print('  ' + e)
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
