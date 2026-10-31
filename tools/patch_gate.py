#!/usr/bin/env python3
"""patch_gate.py - what a change ADDS or REMOVES, found mechanically, checked against what was asked for.

    patch_gate.py BASE TREE MANIFEST [--all] [--patch PATCHFILE]

BASE and TREE are two source trees (build output, .git and caches are skipped). The script compares the two and
lists, per construct, what the tree has that the base has not (and the reverse):

    function     a function definition (name), in the engine, the libs, the tools, tools/*.py
    api          an exported function, a declaration / macro / typedef in a header under libkofeng, libgenome or
                 libuncoat (kofeng.h and the kofmod headers included)
    api-member   a member of a struct or union in those headers
    api-enum     an enumerator in those headers
    include      a new #include (counted only); `include-internal` when a tool includes an engine-internal header
    ui-section   a title passed to sec_bar / decl_table_head / block_begin
    ui-text      a string the viewer draws (out_str, out_fmt, span, row_new ...)
    ui-menu      a label in a menu table
    ui-button    a [ button ] label
    ui-hit       a hit zone (hit_add ...) and the handler it runs
    key          a key binding (case K_x:, k == K_x ...) in the viewer
    out-text     a string a command-line tool prints
    trace        a KOF_TRACE line
    derive       a tool-side function that loops over engine results to work out a value (DERIVE_RULES below)
    file         a new file; `golden` a new or changed screen snapshot under tests/tui/golden
    removed-test a test case or test file that went away (always listed, and checked)

The manifest is a text file the author of the patch writes from the TASK, in the owner's words. One line each:

    allow function dash_matcher_text     (a glob is allowed: dash_*)
    allow api kdet_foo
    allow ui "Diagnoses"                 (a substring of the string)
    allow hit hit_diag_goto
    allow key K_F5
    allow trace [diag]
    allow derive some_function
    allow file tests/unit/foo.c
    allow golden dashboard_overview
    allow remove-test the_old_case
    allow remove-file path
    allow remove-api name
    allow touch kofexamine/kv_view.c     (a file the patch may change; see THE FILE LIST)
    # comment

Every ADDED item that no line covers is printed `UNREQUESTED: <kind> <name> <file>` and the exit status is 1.
Removed tests, test files, files and api names that no `allow remove-*` line covers fail the same way. Removed UI
and keys are listed (a retired path is reported) but do not fail. A manifest line that covered nothing is printed
as UNUSED (an allowance wider than the patch). A line that allows only `*` is refused.

A function defined only in a new file that a `allow file` line covers is covered by that line (the file is what was asked
for; its api, ui, key and derive items are still checked).

THE FILE LIST. A manifest that has at least one `allow touch <glob>` line turns the file list on (tools/merge_gate.sh refuses a
manifest without one): every file of the tree that is CHANGED, ADDED or REMOVED against the base must match a `touch`, an
`allow file`, an `allow remove-file` / `remove-test` or (a golden screen) an `allow golden` line, else
`UNREQUESTED: touched-file <path>`; and an `allow touch` glob that matches no touched file is `FILELIST: manifest names ...`, which fails
too: the manifest and the patch name the same files, in both directions (incident D23: a patch cut against the wrong base touched
files nobody listed). `--patch FILE` also reads the file list of a `diff -ru` patch and fails with `PATCHLIST` when it is not
exactly the set of files that differ between BASE and TREE (a stale or hand-edited patch).

Moved code is not an addition: items are counted by (kind, name) over every touched file, so a function that went
from one file to another changes nothing, and a second copy of a name is an addition.
"""
import collections, fnmatch, os, re, sys

SKIP_DIRS = {'build', 'build_det', '.git', '__pycache__'}
SKIP_SUFFIX = ('.pyc', '.o', '.a', '.d', '.orig', '.rej', '.bak')
LIBS = ('libkofeng/', 'libgenome/', 'libuncoat/')
TOOLS = ('kofexamine/', 'kofscanner/', 'kofwatcher/', 'ksigbuilder/')
VIEWER = 'kofexamine/'
ENGINE_INTERNAL = re.compile(r'(^|/)(scanners|analyzers|databases|detectors|verdictor)/|_int\.h$|_private\.h$|scan_state|objctx')
SDK_OK = re.compile(r'(^|/)(kofeng\.h|kofmod/[^/]+|kofcore/[^/]+|uncoat\.h|kgenome\.h)$')

UI_SECTION = {'sec_bar', 'decl_table_head', 'block_begin'}
UI_TEXT = {'out_str', 'out_fmt', 'span', 'row_new', 'out_puts', 'prow_text'}
OUT_TEXT = {'printf', 'fprintf', 'puts', 'fputs', 'perror'}
KEY_RE = re.compile(r"\bcase\s+(K_\w+|'(?:\\.|[^'])')\s*:|\b(?:k|key|ch|c)\s*==\s*(K_\w+|'(?:\\.|[^'])')")
BUTTON_RE = re.compile(r'\[\s*[+\-]?\s*[A-Za-z][^\]"]*\]')

# ---- the tool-side "derives a value from engine results" heuristic ------------------------------------------------
# (name, reason, test over (loop header, loop body)). A hit is a REVIEW item: the engine may already answer it.
DRAW = re.compile(r'\b(out_str|out_fmt|row_new|span|row_start|hit_add|printf|fprintf|snprintf)\s*\(')
DERIVE_RULES = [
    ('verdict-from-objects',
     'loops over the object list and reads a verdict field: the engine already answers which object carries the verdict (kverdict_filemap, kdet_info)',
     lambda h, b: re.search(r'n_obj|->obj\[|\bobj\[', h + b) and re.search(r'has_verdict|\.verdict|->verdict|\.heur\.', b)),
    ('selects-or-counts-engine-rows',
     'loops over engine result rows (diag, matches, findings) and counts or selects without drawing: a derived value, ask the engine for it',
     lambda h, b: re.search(r'n_diag|n_match|n_find|->diag\b|n_hit|->match\[', h) and re.search(r'\+\+|\+=|\bbreak\b|\breturn\b', b) and not DRAW.search(b)),
    ('compares-verdict-names',
     'compares or searches verdict / finding names as strings: filtering engine results by logic of the tool',
     lambda h, b: re.search(r'\b(strcmp|strncmp|strstr|strcasecmp)\s*\(', b) and re.search(r'verdict|finding', h + b)),
]
VERDICT_COMPOSE = re.compile(r'(Infected#|Diagnose#|#ELF|#PE-|Heur:)')


# ---- C lexer ------------------------------------------------------------------------------------------------------
def lex(src):
    """-> (code, strings): code is src with comments blanked and every string/char literal body replaced by '_'
    (same length, same newlines); strings is [(pos, text)] of the string literals (not chars)."""
    out = list(src)
    strs = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == '/' and i + 1 < n and src[i + 1] == '*':
            j = src.find('*/', i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != '\n':
                    out[k] = ' '
            i = j
        elif c == '/' and i + 1 < n and src[i + 1] == '/':
            j = src.find('\n', i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = ' '
            i = j
        elif c == '"' or c == "'":
            j = i + 1
            while j < n and src[j] != c:
                if src[j] == '\\':
                    j += 1
                if j < n and src[j] == '\n':
                    break
                j += 1
            if c == '"':
                strs.append((i, src[i + 1:j]))
            for k in range(i + 1, min(j, n)):
                out[k] = '_'
            i = j + 1
        else:
            i += 1
    return ''.join(out), strs


def directives(src, code):
    """-> (directive texts, code with the preprocessor lines blanked)."""
    lines = code.split('\n')
    raw = src.split('\n')
    res = []
    i = 0
    while i < len(lines):
        if lines[i].lstrip().startswith('#'):
            j = i
            text = raw[i]
            while raw[j].rstrip().endswith('\\') and j + 1 < len(raw):
                j += 1
                text += ' ' + raw[j]
            res.append(text.strip())
            for k in range(i, j + 1):
                lines[k] = ' ' * len(lines[k])
            i = j + 1
        else:
            i += 1
    return res, '\n'.join(lines)


def match_brace(code, i):
    d = 0
    n = len(code)
    while i < n:
        c = code[i]
        if c == '{':
            d += 1
        elif c == '}':
            d -= 1
            if d == 0:
                return i
        i += 1
    return n - 1


def split_top(text, sep):
    parts, d, cur = [], 0, []
    for c in text:
        if c in '({[':
            d += 1
        elif c in ')}]':
            d -= 1
        if c == sep and d == 0:
            parts.append(''.join(cur))
            cur = []
        else:
            cur.append(c)
    if ''.join(cur).strip():
        parts.append(''.join(cur))
    return parts


def member_names(chunk):
    """Names declared by one `type a, *b[3], (*fn)(int), c : 3` chunk."""
    names = []
    for part in split_top(chunk, ','):
        m = re.search(r'\(\s*\*\s*(\w+)', part)
        if m:
            names.append(m.group(1))
            continue
        p = re.sub(r'\[[^\]]*\]', '', part)
        p = re.sub(r':\s*\w+\s*$', '', p).strip()
        m = re.search(r'(\w+)\s*$', p)
        if m:
            names.append(m.group(1))
    return names


def aggregate(tag, body, is_enum, out):
    """Members of a struct/union body (recursively) or enumerators of an enum body, appended to out."""
    if is_enum:
        for ch in split_top(body, ','):
            m = re.match(r'\s*(\w+)', ch)
            if m:
                out.append(('enumerator', m.group(1), tag))
        return
    pos, n = 0, len(body)
    while pos < n:
        j = pos
        d = 0
        while j < n and not (body[j] == ';' and d == 0):
            if body[j] in '{(':
                d += 1
            elif body[j] in '})':
                d -= 1
            j += 1
        chunk = body[pos:j]
        pos = j + 1
        if '{' in chunk:
            a = chunk.index('{')
            b = match_brace(chunk, a)
            head = chunk[:a]
            sub = chunk[a + 1:b]
            tail = chunk[b + 1:]
            names = member_names(tail) if tail.strip() else []
            is_en = bool(re.search(r'\benum\b', head))
            for x in names:
                out.append(('member', '%s.%s' % (tag, x), tag))
            aggregate('%s.%s' % (tag, names[0]) if names and not is_en else tag, sub, is_en, out)
        elif chunk.strip():
            for x in member_names(chunk):
                out.append(('member', '%s.%s' % (tag, x), tag))


def parse_c(text):
    """-> dict: funcs [(name, static, start, end)], decls [name], members, enumerators, macros, includes,
    strings [(pos, text)], tables [(name, start, end)], code."""
    code0, strs = lex(text)
    dirs, code = directives(text, code0)
    r = dict(funcs=[], decls=[], members=[], enumerators=[], macros=[], includes=[], strings=strs, code=code, tables=[], tags=[], typedefs=[])
    for d in dirs:
        m = re.match(r'#\s*include\s*([<"])([^>"]+)[>"]', d)
        if m:
            r['includes'].append(m.group(2))
        m = re.match(r'#\s*define\s+(\w+)', d)
        if m and not m.group(1).endswith('_H'):
            r['macros'].append(m.group(1))
    n = len(code)
    pos = 0
    stop = re.compile(r'[{;]')
    while pos < n:
        m = stop.search(code, pos)
        if not m:
            break
        j = m.start()
        head = code[pos:j].strip()
        head = re.sub(r'__attribute__\s*\(\(.*?\)\)', '', head, flags=re.S)
        if code[j] == ';':
            pos = j + 1
            if not head:
                continue
            if head.startswith('typedef'):
                m2 = re.search(r'\(\s*\*\s*(\w+)\s*\)', head) or re.search(r'(\w+)\s*(\[[^\]]*\])*\s*$', head)
                if m2:
                    r['decls'].append(m2.group(1))
                    r['typedefs'].append(m2.group(1))
                continue
            if '(' not in head or ('=' in head and head.index('=') < head.index('(')):
                continue
            m2 = re.match(r'[^()]*\(\s*\*\s*(\w+)', head)
            if m2:
                r['decls'].append(m2.group(1))
            else:
                m2 = re.search(r'(\w+)\s*\(', head)
                if m2 and m2.group(1) not in ('sizeof', 'defined'):
                    r['decls'].append(m2.group(1))
            continue
        k = match_brace(code, j)
        agg = re.match(r'(?:typedef\s+)?(struct|union|enum)\s*(\w*)\s*$', head)
        if agg:
            e = code.find(';', k)
            e = n - 1 if e < 0 else e
            tail = code[k + 1:e]
            names = member_names(tail) if tail.strip() else []
            tag = agg.group(2) or (names[0] if names else '')
            if not tag:
                m3 = re.match(r'\s*(\w+)', code[j + 1:k])
                tag = 'anon:%s' % (m3.group(1) if m3 else '?')
            if names and head.startswith('typedef'):
                r['decls'].append(names[0])
                r['typedefs'].append(names[0])
            tmp = []
            aggregate(tag, code[j + 1:k], agg.group(1) == 'enum', tmp)
            r['tags'].append(tag)
            for kind, nm, tg in tmp:
                (r['members'] if kind == 'member' else r['enumerators']).append((nm, tg))
            pos = e + 1
        elif '=' in head and not re.search(r'\)\s*$', head):
            e = code.find(';', k)
            e = n - 1 if e < 0 else e
            nm = re.search(r'(\w+)\s*(\[[^\]]*\])*\s*$', head.split('=')[0].strip())
            r['tables'].append((nm.group(1) if nm else '?', j, k))
            pos = e + 1
        elif re.search(r'\)\s*$', head) and '(' in head:
            m2 = re.search(r'(\w+)\s*\(', head)
            if m2 and m2.group(1) not in ('if', 'for', 'while', 'switch'):
                r['funcs'].append((m2.group(1), bool(re.search(r'\bstatic\b', head)), j, k))
            pos = k + 1
        else:
            pos = k + 1
    return r


def callee_at(code, p):
    """Name of the call whose argument list holds position p, or None."""
    d = 0
    i = p - 1
    while i >= 0:
        c = code[i]
        if c == ')':
            d += 1
        elif c == '(':
            if d == 0:
                m = re.search(r'(\w+)\s*$', code[:i])
                return m.group(1) if m else None
            d -= 1
        elif c in ';{}' and d == 0:
            return None
        i -= 1
    return None


def call_args(code, text, start):
    """Raw argument strings of the call whose '(' is at `start`."""
    d = 0
    i = start
    args, cur = [], start + 1
    while i < len(code):
        c = code[i]
        if c in '([{':
            d += 1
        elif c in ')]}':
            d -= 1
            if d == 0:
                args.append(text[cur:i].strip())
                break
        elif c == ',' and d == 1:
            args.append(text[cur:i].strip())
            cur = i + 1
        i += 1
    return args


# ---- items --------------------------------------------------------------------------------------------------------
class Item(object):
    __slots__ = ('kind', 'name', 'file', 'grp')

    def __init__(self, kind, name, file, grp=None):
        self.kind, self.name, self.file, self.grp = kind, name, file, grp


def file_class(rel):
    if rel.startswith(LIBS):
        return 'lib'
    if rel.startswith(TOOLS):
        return 'tool'
    if rel.startswith('libkoforbit/'):
        return 'orbit'
    if rel.startswith('tests/'):
        return 'test'
    return 'other'


def loops_of(code):
    """[(header, body)] of every for/while statement of a function body (code is blanked)."""
    res = []
    for m in re.finditer(r'\b(for|while)\s*\(', code):
        i = m.end() - 1
        d = 0
        j = i
        while j < len(code):
            if code[j] == '(':
                d += 1
            elif code[j] == ')':
                d -= 1
                if d == 0:
                    break
            j += 1
        hdr = code[i:j + 1]
        k = j + 1
        while k < len(code) and code[k] in ' \t\n':
            k += 1
        if k < len(code) and code[k] == '{':
            body = code[k:match_brace(code, k) + 1]
        else:
            e = code.find(';', k)
            body = code[k:(e if e >= 0 else len(code)) + 1]
        res.append((hdr, body))
    return res


def items_of_c(rel, text):
    cls = file_class(rel)
    P = parse_c(text)
    code = P['code']
    out = []
    is_h = rel.endswith('.h')
    pub = cls == 'lib' and is_h
    for name, static, a, b in P['funcs']:
        if cls == 'lib':
            out.append(Item('function' if (static and not is_h) else 'api', name, rel))
        elif cls in ('tool', 'orbit'):
            out.append(Item('function', name, rel))
        if cls == 'tool':
            body = code[a:b + 1]
            seen = set()
            for h, bd in loops_of(body):
                for rname, why, test in DERIVE_RULES:
                    if test(h, bd) and rname not in seen:
                        seen.add(rname)
                        out.append(Item('derive', '%s [%s]' % (name, rname), rel))
            for p, s in P['strings']:
                if a <= p <= b and VERDICT_COMPOSE.search(s):
                    out.append(Item('derive', '%s [composes-verdict-text]' % name, rel))
                    break
    if pub:
        for nm in P['decls'] + P['macros']:
            out.append(Item('api', nm, rel))
        for tg in P['tags']:
            out.append(Item('api-type', tg, rel))
        for nm, tg in P['members']:
            out.append(Item('api-member', nm, rel, tg.split('.')[0]))
        for nm, tg in P['enumerators']:
            out.append(Item('api-enum', nm, rel, tg))
    for inc in P['includes']:
        if cls == 'tool' and ENGINE_INTERNAL.search(inc) and not SDK_OK.search(inc):
            out.append(Item('include-internal', inc, rel))
        else:
            out.append(Item('include', inc, rel))
    if cls == 'tool':
        tbl = {}
        for nm, a, b in P['tables']:
            for p, s in P['strings']:
                if a <= p <= b:
                    tbl[p] = nm
        for p, s in P['strings']:
            if not re.search(r'[A-Za-z]{3}', s):
                continue
            ce = callee_at(code, p)
            kind = None
            if rel.startswith(VIEWER):
                if ce in UI_SECTION:
                    kind = 'ui-section'
                elif BUTTON_RE.search(s):
                    kind = 'ui-button'
                elif p in tbl and rel.endswith(('kv_bar.c', 'kv_menu.c')) and re.search(r'menu|item', tbl[p], re.I):
                    kind = 'ui-menu'
                elif ce in UI_TEXT:
                    kind = 'ui-text'
                elif ce in OUT_TEXT:
                    kind = 'out-text'
            elif ce in OUT_TEXT or ce in UI_TEXT:
                kind = 'out-text'
            if kind:
                out.append(Item(kind, s, rel))
        if rel.startswith(VIEWER):
            for m in re.finditer(r'\bhit_add\s*\(', code):
                args = call_args(code, text, m.end() - 1)
                h = [a for a in args if re.match(r'^&?hit_\w+$', a)]
                nm = (h[0] if h else (args[4] if len(args) > 4 else ' '.join(args))).lstrip('&')
                out.append(Item('ui-hit', nm, rel))
    return out


def line_items(rel, text):
    """Items found per line: key bindings in the viewer, KOF_TRACE lines."""
    out = []
    cls = file_class(rel)
    if not rel.endswith(('.c', '.h')) or cls == 'test':
        return out
    for ln in text.split('\n'):
        s = ln.strip()
        if s.startswith(('*', '/')):
            continue
        if rel.startswith(VIEWER):
            for m in KEY_RE.finditer(s):
                out.append(Item('key', m.group(1) or m.group(2), rel))
        if 'KOF_TRACE(' in s and cls in ('lib', 'tool', 'orbit') and not s.startswith('#'):
            m = re.search(r'"\s*(\[[\w\-]+\])', s)
            out.append(Item('trace', m.group(1) if m else s[:40], rel))
    return out


PY_DEF = re.compile(r'^\s*def\s+(\w+)', re.M)
PY_CASE = re.compile(r'^@case\([^\n]*\)\s*\n(?:@[^\n]*\n)*def\s+(\w+)', re.M)


def items_of(rel, data):
    text = data.decode('utf-8', 'replace')
    out = []
    if rel.endswith(('.c', '.h')):
        out += items_of_c(rel, text)
        out += line_items(rel, text)
    elif rel.endswith('.py') and not rel.startswith('tests/'):
        for m in PY_DEF.finditer(text):
            out.append(Item('function', m.group(1), rel))
    return out


def test_names(rel, data):
    """Names of the test cases a test file holds (Python cases; a C test is a file)."""
    if not rel.startswith('tests/') or not rel.endswith('.py'):
        return []
    text = data.decode('utf-8', 'replace')
    return PY_CASE.findall(text) + re.findall(r'^def\s+(test_\w+)', text, re.M)


ASSERT_RE = re.compile(r'\b(OKF|CHECK|ASSERT|EXPECT\w*|assert|check|eq)\s*\(')


def assertion_count(rel, data):
    if not rel.startswith('tests/') or not rel.endswith(('.c', '.py', '.h')):
        return 0
    return len(ASSERT_RE.findall(data.decode('utf-8', 'replace')))


# ---- trees --------------------------------------------------------------------------------------------------------
def walk(root):
    res = {}
    for d, ds, fs in os.walk(root):
        ds[:] = [x for x in ds if x not in SKIP_DIRS and not x.startswith('kof_fuzz_orbit')]
        for f in fs:
            if f.endswith(SKIP_SUFFIX):
                continue
            p = os.path.join(d, f)
            if os.path.islink(p):
                continue
            res[os.path.relpath(p, root)] = p
    return res


def read(p):
    with open(p, 'rb') as f:
        return f.read()


def count_items(files_map, rels):
    c = collections.Counter()
    where = {}
    grp = {}
    for rel in rels:
        for it in items_of(rel, read(files_map[rel])):
            c[(it.kind, it.name)] += 1
            where.setdefault((it.kind, it.name), []).append(rel)
            if it.grp:
                grp[(it.kind, it.name)] = it.grp
    return c, where, grp


def collect(base, tree):
    b, t = walk(base), walk(tree)
    added = sorted(set(t) - set(b))
    removed = sorted(set(b) - set(t))
    changed = sorted(x for x in set(b) & set(t) if read(b[x]) != read(t[x]))
    touched = sorted(set(added) | set(changed) | set(removed))
    bc, bw, bg = count_items(b, [x for x in touched if x in b])
    tc, tw, tg = count_items(t, [x for x in touched if x in t])
    add, rem = {}, {}
    for k in set(tc) | set(bc):
        d = tc[k] - bc[k]
        if d > 0:
            add[k] = (d, sorted(set(tw[k])))
        elif d < 0:
            rem[k] = (-d, sorted(set(bw[k])))
    # a member or enumerator of a type that is itself new is part of that one addition
    new_types = set(n for (k, n) in add if k == 'api-type')
    members_of = collections.Counter()
    for (k, n) in list(add):
        if k in ('api-member', 'api-enum') and tg.get((k, n)) in new_types:
            members_of[tg[(k, n)]] += add[(k, n)][0]
            del add[(k, n)]
    R = dict(type_members=members_of, added_files=added, removed_files=removed, changed_files=changed, add=add, rem=rem)
    bt, tt = collections.Counter(), collections.Counter()
    for x in touched:
        if x in b:
            bt.update(test_names(x, read(b[x])))
        if x in t:
            tt.update(test_names(x, read(t[x])))
    R['removed_tests'] = sorted(n for n in bt if tt[n] < bt[n])
    R['added_tests'] = sorted(n for n in tt if tt[n] > bt[n])
    R['assert_base'] = sum(assertion_count(x, read(b[x])) for x in touched if x in b)
    R['assert_tree'] = sum(assertion_count(x, read(t[x])) for x in touched if x in t)
    G = 'tests/tui/golden/'
    R['golden_new'] = [x for x in added if x.startswith(G)]
    R['golden_changed'] = [x for x in changed if x.startswith(G)]
    R['golden_removed'] = [x for x in removed if x.startswith(G)]
    return R


# ---- manifest -----------------------------------------------------------------------------------------------------
DIRECTIVES = {'touch', 'function', 'api', 'ui', 'hit', 'key', 'include', 'trace', 'derive', 'file', 'golden', 'remove-test',
              'remove-file', 'remove-api'}


def load_manifest(path):
    rules = []
    with open(path) as f:
        for n, ln in enumerate(f, 1):
            ln = ln.strip()
            if not ln or ln.startswith('#'):
                continue
            m = re.match(r'allow\s+(\S+)\s+(.*)$', ln)
            if not m or m.group(1) not in DIRECTIVES:
                sys.exit('%s:%d: bad manifest line: %s' % (path, n, ln))
            arg = m.group(2).strip()
            if len(arg) >= 2 and arg[0] == '"' and arg[-1] == '"':
                arg = arg[1:-1]
            if arg.strip('*') == '':
                sys.exit('%s:%d: an allowance of everything is no allowance: %s' % (path, n, ln))
            rules.append([m.group(1), arg, 0, ln])
    return rules


KIND_DIRECTIVE = {'function': 'function', 'api': 'api', 'api-type': 'api', 'api-member': 'api', 'api-enum': 'api', 'include': 'include',
                  'include-internal': 'include', 'ui-section': 'ui', 'ui-text': 'ui', 'ui-menu': 'ui', 'ui-button': 'ui',
                  'out-text': 'ui', 'ui-hit': 'hit', 'key': 'key', 'trace': 'trace', 'derive': 'derive'}
ORDER = ['api', 'api-type', 'api-member', 'api-enum', 'function', 'derive', 'include-internal', 'include', 'ui-section', 'ui-menu',
         'ui-button', 'ui-hit', 'ui-text', 'key', 'out-text', 'trace']


def covered(rules, directive, name):
    ok = False
    for r in rules:
        if r[0] != directive:
            continue
        if directive == 'derive':
            hit = fnmatch.fnmatchcase(name.split(' [')[0], r[1]) or fnmatch.fnmatchcase(name, r[1])
        elif directive == 'ui':
            hit = r[1] in name
        elif directive == 'trace':
            hit = r[1] in name
        else:
            hit = fnmatch.fnmatchcase(name, r[1])
        if hit:
            r[2] += 1
            ok = True
    return ok


def short(fs):
    return fs[0] + ('+%d' % (len(fs) - 1) if len(fs) > 1 else '')


def patch_files(path):
    """The set of files a `diff -ru[N] base tree` patch names (the part after the first path component of the `diff` line's
    second path, so `tree/x/y` -> `x/y`), without golden-independent filtering: every file counts."""
    res = set()
    with open(path, errors='replace') as f:
        for ln in f:
            if ln.startswith('diff '):
                parts = ln.split()
                if len(parts) >= 3:
                    res.add(parts[-1].split('/', 1)[1] if '/' in parts[-1] else parts[-1])
    return res


def run(base, tree, manifest, show_all=False, out=sys.stdout, patch_file=None):
    rules = load_manifest(manifest)
    R = collect(base, tree)
    fails = []
    P_ = []
    P = P_.append
    P('patch_gate  base=%s  tree=%s' % (base, tree))
    P('files: +%d new  ~%d changed  -%d removed' % (len(R['added_files']), len(R['changed_files']), len(R['removed_files'])))
    by_kind, rem_kind = collections.defaultdict(list), collections.defaultdict(list)
    for (k, n), (c, fs) in R['add'].items():
        by_kind[k].append((n, c, fs))
    for (k, n), (c, fs) in R['rem'].items():
        rem_kind[k].append((n, c, fs))

    def tally(d):
        return '  '.join('%s %d' % (k, sum(c for _, c, _ in d[k])) for k in ORDER if d.get(k)) or '(nothing)'
    P('ADDED   ' + tally(by_kind))
    P('REMOVED ' + tally(rem_kind))
    P('tests: %d case(s) added, %d removed; assertions in touched test files %d -> %d' % (
        len(R['added_tests']), len(R['removed_tests']), R['assert_base'], R['assert_tree']))

    ok_names = collections.defaultdict(list)
    new_ok = set(f for f in R['added_files'] if any(r[0] == 'file' and fnmatch.fnmatchcase(f, r[1]) for r in rules))
    for k in ORDER:
        if k == 'include':
            continue                    # counted on the page; only the internal ones are enforced
        for n, c, fs in sorted(by_kind.get(k, [])):
            if k == 'function' and set(fs) <= new_ok:
                ok_names['function (in an allowed new file)'].append(n)
                continue
            if covered(rules, KIND_DIRECTIVE.get(k, 'api'), n):
                ok_names[k].append(n)
                continue
            extra = ''
            if k == 'api-type' and R['type_members'].get(n):
                extra = ' (%d members, all new)' % R['type_members'][n]
            fails.append('UNREQUESTED: %s %s%s %s' % (k, n if len(n) < 110 else n[:107] + '...', extra, short(fs)))
    for f in R['added_files']:
        if f.startswith('tests/tui/golden/'):
            continue
        if covered(rules, 'file', f):
            ok_names['file'].append(f)
        else:
            fails.append('UNREQUESTED: file %s' % f)
    for what, fl in (('new', R['golden_new']), ('changed', R['golden_changed']), ('removed', R['golden_removed'])):
        for f in fl:
            nm = os.path.splitext(os.path.basename(f))[0]
            if covered(rules, 'golden', nm):
                ok_names['golden %s' % what].append(nm)
            else:
                fails.append('UNREQUESTED: golden %s %s' % (nm, what))
    for n in R['removed_tests']:
        if covered(rules, 'remove-test', n):
            ok_names['removed-test'].append(n)
        else:
            fails.append('UNREQUESTED: removed-test %s' % n)
    for f in R['removed_files']:
        if f.startswith('tests/tui/golden/'):
            continue
        if f.startswith('tests/') and f.endswith(('.c', '.py')):
            if covered(rules, 'remove-test', f) or covered(rules, 'remove-file', f):
                ok_names['removed-file'].append(f)
            else:
                fails.append('UNREQUESTED: removed-test-file %s' % f)
        elif covered(rules, 'remove-file', f):
            ok_names['removed-file'].append(f)
        else:
            fails.append('UNREQUESTED: removed-file %s' % f)
    for k in ('api', 'api-type', 'api-member', 'api-enum'):
        for n, c, fs in rem_kind.get(k, []):
            if covered(rules, 'remove-api', n):
                ok_names['removed-' + k].append(n)
            else:
                fails.append('UNREQUESTED: removed-%s %s %s' % (k, n, short(fs)))

    touch_rules = [r for r in rules if r[0] == 'touch']
    if touch_rules:
        for f in sorted(set(R['changed_files']) | set(R['added_files']) | set(R['removed_files'])):
            if f.startswith('tests/tui/golden/'):
                continue                # a golden screen is named by `allow golden`, checked above
            if any(fnmatch.fnmatchcase(f, r[1]) for r in rules if r[0] in ('touch', 'file', 'remove-file', 'remove-test')):
                for r in rules:
                    if r[0] == 'touch' and fnmatch.fnmatchcase(f, r[1]):
                        r[2] += 1
            else:
                fails.append('UNREQUESTED: touched-file %s' % f)
        for r in touch_rules:
            if r[2] == 0:
                fails.append('FILELIST: manifest names %s, the patch does not touch it' % r[1])
    if patch_file:
        want = set(R['changed_files']) | set(R['added_files']) | set(R['removed_files'])
        have = patch_files(patch_file)
        for f in sorted(want - have):
            fails.append('PATCHLIST: %s differs between base and tree but is not in the patch' % f)
        for f in sorted(have - want):
            fails.append('PATCHLIST: %s is in the patch but base and tree do not differ there' % f)
    P('')
    for k, v in ok_names.items():
        P('allowed %-12s %d: %s' % (k, len(v), ', '.join(v[:6]) + (', ...' if len(v) > 6 else '')))
    if show_all:
        for n, c, fs in sorted(by_kind.get('include', [])):
            P('  + include          %s  (%s)' % (n, short(fs)))
    gone = []
    for k in ORDER:
        if k in ('function', 'include', 'trace'):
            continue
        for n, c, fs in sorted(rem_kind.get(k, [])):
            gone.append('  - %-16s %s  (%s)' % (k, n if len(n) < 80 else n[:77] + '...', short(fs)))
    if gone:
        P('removed, reported (not a failure):')
        for ln in gone[:30]:
            P(ln)
        if len(gone) > 30:
            P('  ... %d more' % (len(gone) - 30))
    for r in rules:
        if r[2] == 0:
            P('UNUSED: %s' % r[3])
    P('')
    for f in fails:
        P(f)
    P('RESULT: %s' % ('FAIL (%d unrequested)' % len(fails) if fails else 'PASS'))
    out.write('\n'.join(P_) + '\n')
    return 1 if fails else 0


def main(argv):
    patch = None
    argv = list(argv)
    if '--patch' in argv:
        i = argv.index('--patch')
        if i + 1 >= len(argv):
            sys.stderr.write(__doc__)
            return 2
        patch = argv[i + 1]
        del argv[i:i + 2]
    args = [a for a in argv if not a.startswith('--')]
    if len(args) != 3:
        sys.stderr.write(__doc__)
        return 2
    return run(args[0], args[1], args[2], show_all='--all' in argv, patch_file=patch)


if __name__ == '__main__':
    sys.dont_write_bytecode = True
    sys.exit(main(sys.argv[1:]))
