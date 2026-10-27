#!/usr/bin/env python3
"""
known_defects.py - the list of KNOWN DEFECT comments, and the checks that keep it honest.

Owner rule (2026-10-24): a bug that is not fixed is written down where it is made, as a
block comment directly above the SINK (the statement or function that produces the wrong
behaviour), in this shape (at most 6 lines):

    /* KNOWN DEFECT <id> (<date>, <M|R|Inference>) [sev H|M|L]: <what is wrong; name the sink symbol>.
     * Trigger: <input/state>. Effect: <what the program does wrong>.
     * Reproducer: <path or test>. Fix: <the cheapest correct fix, or the open question>. */

Severity (owner 2026-10-25): H = memory corruption / UB reachable from hostile input;
M = silent evidence loss, wrong result or link, resource-cap bypass, hang, uninitialised read;
L = hygiene, duplicate logic, locale, test hygiene, cosmetic.

The id is the id of the report (N*, L*, G*, W*, X*, WP12-*, WP2-D*, D*), so
`grep -rn 'KNOWN DEFECT' .` finds it. The sink is named by SYMBOL, never by file:line (a
line number goes stale; the comment moves with its code). The index is this program's
output, not a file somebody keeps: `tools/known_defects.py` prints id, file, current
line, enclosing function and status for every comment; `--check` is what `make
check-rules` runs.

Check (both ways):
  * every comment has a well formed id, a date, a status and a `Fix:` part, at most 6 lines;
  * it sits DIRECTLY above a statement or a function: the next line exists, is not blank,
    not another comment and not a lone closing brace;
  * ids are unique;
  * nothing under bases/ carries one (a module's pack bytes follow its source lines);
  * a comment under tests/ WITHOUT a `Fix:` part is a reference ("this row pins defect
    <id>"): its id must exist as a comment in the sources, and a source comment that says
    `green until fixed` in its Reproducer names a row that must exist.
Only .c and .h files are read.

Usage: known_defects.py [--check] [--tsv] [root]
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {'build', 'build_det', '.git', 'LICENSES'}
HEAD = re.compile(r'KNOWN DEFECT\b')
WELL = re.compile(r'KNOWN DEFECT ([A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*) '
                  r'\((\d{4}-\d{2}-\d{2}), (M|R|Inference)\)(?: \[sev (H|M|L)\])?: (.*)')
FUNC = re.compile(r'^[A-Za-z_][^;{}]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')


def files(root):
    for d, ds, fs in os.walk(root):
        ds[:] = [x for x in ds if x not in SKIP_DIRS]
        for f in fs:
            if f.endswith(('.c', '.h')):
                yield os.path.join(d, f)


def comments(text):
    """(start_line_index, end_line_index) of every /* ... */ block that says KNOWN DEFECT."""
    lines = text.split('\n')
    out = []
    i = 0
    while i < len(lines):
        s = lines[i]
        p = s.find('/*')
        if p >= 0 and '*/' not in s[p + 2:]:
            j = i
            while j < len(lines) and '*/' not in lines[j]:
                j += 1
            if any(HEAD.search(l) for l in lines[i:j + 1]):
                out.append((i, min(j, len(lines) - 1)))
            i = j + 1
            continue
        if p >= 0 and HEAD.search(s):
            out.append((i, i))
        i += 1
    return lines, out


def enclosing(lines, at):
    """Name of the function that holds line `at` (or starts at it); '-' if none is found."""
    for k in range(at, -1, -1):
        l = lines[k]
        if (l[:1].isalpha() or l[:1] == '_') and not l.startswith(('typedef', 'struct ', 'enum ', 'union ', 'extern ')):
            m = FUNC.match(l)
            if m:
                return m.group(1)
    return '-'


def scan(root=ROOT):
    recs, errs = [], []
    for path in sorted(files(root)):
        rel = os.path.relpath(path, root)
        try:
            text = open(path, encoding='utf-8', errors='replace').read()
        except OSError:
            continue
        if 'KNOWN DEFECT' not in text:
            continue
        lines, cs = comments(text)
        for a, b in cs:
            block = '\n'.join(lines[a:b + 1])
            m = WELL.search(re.sub(r'\n\s*\*?[ \t]*', ' ', block))
            where = f'{rel}:{a + 1}'
            r = dict(file=rel, line=a + 1, end=b + 1, id=None, status=None, text=block,
                     func='-', ref=False)
            if not m:
                errs.append(f'{where}: KNOWN DEFECT comment without "<id> (<date>, <M|R|Inference>): <statement>"')
                continue
            r['id'], r['status'], r['sev'] = m.group(1), m.group(3), m.group(4)
            r['stmt'] = m.group(5).split('. ')[0].strip()
            r['ref'] = rel.startswith('tests/') and 'Fix:' not in block
            if rel.startswith('bases/'):
                errs.append(f'{where}: {r["id"]}: a comment under bases/ moves the pack bytes (CLAUDE.md 12); list it as a module sink instead')
            if not r['ref']:
                if not r['sev']:
                    errs.append(f'{where}: {r["id"]}: no severity: header must read "(<date>, <M|R|Inference>) [sev H|M|L]:"')
                if 'Fix:' not in block:
                    errs.append(f'{where}: {r["id"]}: no "Fix:" part')
                if 'Trigger:' not in block:
                    errs.append(f'{where}: {r["id"]}: no "Trigger:" part')
                if b - a + 1 > 6:
                    errs.append(f'{where}: {r["id"]}: {b - a + 1} lines (at most 6)')
            nxt = lines[b + 1] if b + 1 < len(lines) else None
            if nxt is None or not nxt.strip() or nxt.lstrip().startswith(('/*', '//', '*')) \
               or nxt.strip() in ('}', '};', '#endif'):
                errs.append(f'{where}: {r["id"]}: orphaned: the line after the comment is not a statement or a function')
            else:
                r['func'] = enclosing(lines, b + 1)
            recs.append(r)
    seen = {}
    for r in recs:
        if r['ref']:
            continue
        if r['id'] in seen:
            errs.append(f'{r["file"]}:{r["line"]}: {r["id"]}: duplicate id (first at {seen[r["id"]]})')
        else:
            seen[r['id']] = f'{r["file"]}:{r["line"]}'
    for r in recs:
        if r['ref'] and r['id'] not in seen:
            errs.append(f'{r["file"]}:{r["line"]}: {r["id"]}: a test row names a defect that has no KNOWN DEFECT comment in the sources')
    refd = {r['id'] for r in recs if r['ref']}
    for r in recs:
        if not r['ref'] and re.search(r'green until fixed', r['text'], re.I) and r['id'] not in refd:
            errs.append(f'{r["file"]}:{r["line"]}: {r["id"]}: says "green until fixed" but no test row carries "KNOWN DEFECT {r["id"]}"')
    return recs, errs


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    root = args[0] if args else ROOT
    recs, errs = scan(root)
    defs = [r for r in recs if not r['ref']]
    if '--check' in sys.argv:
        sv = {k: len([r for r in defs if r.get('sev') == k]) for k in 'HML'}
        print(f'check-rules: KNOWN DEFECT comments: {len(defs)} recorded (high {sv["H"]}, medium {sv["M"]}, low {sv["L"]}), '
              f'{len([r for r in recs if r["ref"]])} test rows pin one (informational)')
        for e in errs:
            print('  ' + e)
        return 1 if errs else 0
    for r in sorted(defs, key=lambda r: (r['id'])):
        if '--tsv' in sys.argv:
            print('\t'.join([r['id'], r['file'], str(r['line']), r['func'], r['status'], r['sev'] or '-', r['stmt']]))
        else:
            print(f'{r["id"]:10} {r["file"]}:{r["line"]} [{r["func"]}] {r["status"]} sev {r["sev"] or "-"} {r["stmt"]}')
    for r in sorted((r for r in recs if r['ref']), key=lambda r: r['id']):
        print(f'{r["id"]:10} {r["file"]}:{r["line"]} (test row)')
    for e in errs:
        print('ERROR ' + e, file=sys.stderr)
    return 1 if errs else 0


if __name__ == '__main__':
    sys.exit(main())
