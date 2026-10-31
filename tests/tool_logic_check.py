#!/usr/bin/env python3
"""tool_logic_check.py - a tool shows what the engine answers; it does not answer for itself (kofeng/CLAUDE.md rules 2, 3 and 11).

Static half of the owner's test (2026-10-29: tests that detect a tool re-implementing logic the engine already answers). The dynamic half is
tests/unit/tool_agree.c (kofscanner, kofexaminer) and tests/tui/t_agree.py (kofviewer): they compare what a tool prints with the engine's pull API. This one reads
the tool SOURCES for the shapes the two real defects had, in the style of tools/check_layers.py (a rule, an EXEMPT table with a reason for every entry, an entry
whose violation is gone is reported so the line can be deleted, and a self test that shows each rule fails on a deliberate violation):

  INCLUDE   a tool names the engine's INNER headers (../libkofeng/..., <verdictor/...>, <scanners/...>, <detectors/...>, <databases/...>). kofscanner may include
            none (it is written against the SDK: <kofeng.h> and the core headers). kofexamine/ is an analysis tool and includes parsers on purpose: its inner
            includes are a ratchet (INNER_OK: a pattern and why), so a NEW kind of inner include is a review, and a verdict-making one is never in the table.
  LOOP      a loop in a tool whose body reads a result's verdict (has_verdict, verdict.name, verdict.n_diag, verdict.diag, cat.level) walks objects to derive
            something the engine has an answer for (kverdict_filemap_*: the file's verdict and the object that carries it). The viewer's
            dash_detected_children was this and showed "no verdict X in child".
  SPELL     a format string that spells a detection name: "%s#%s", "%s!%s", "Infected#", "!Diagnose", or "%s-%s" within two lines of a word that names a detection
            (verdict, family, variant, tag, diagnos, disease). The engine owns the separators (kof_verdict_name); a tool quotes kof_result.verdict.
  COUNT     a tool counts matched diagnoses itself (== KOF_DIAG_ST_MATCH in a loop or a sum): kdet_info.n_diag / kdet_run_* answer it.

usage: tool_logic_check.py [<tree root>]       exits 1 on a violation, a stale EXEMPT entry or a rule that does not fail its self test
       tool_logic_check.py --selftest <scratch dir>   only the self test (writes under the scratch dir, never /tmp)
"""
import os, re, sys

TOOL_DIRS = ['kofexamine', 'kofscanner', 'ksigbuilder', 'kofwatcher']
INNER = re.compile(r'#\s*include\s*["<](?:\.\./libkofeng/|(?:verdictor|scanners|detectors|databases|analyzers)/)')
# a result's own fields (heur. is the viewer's copy of kof_result): the fields of a kverdict_file (e->has_verdict) are the ENGINE's roll-up and are the answer
VERDICT_READ = re.compile(r'(?:heur\.|\bres->|\bres\.|\bresult\.|\br->)(?:has_verdict|verdict\.name|verdict\.n_diag|verdict\.diag|cat\.level)')
LOOP_HEAD = re.compile(r'^\s*(for|while)\s*\(')
SPELL = [
    (re.compile(r'"[^"]*%s#%s[^"]*"'), 'a verdict spelled with "#"'),
    (re.compile(r'"[^"]*%s![A-Za-z%][^"]*"'), 'a verdict spelled with "!"'),
    (re.compile(r'"[^"]*Infected#[^"]*"'), 'the literal verdict word'),
    (re.compile(r'"[^"]*!Diagnose[^"]*"'), 'the literal engine word'),
]
DASH = re.compile(r'"[^"]*%s-%s[^"]*"')
DETECT_WORD = re.compile(r'verdict|family|variant|\btag\b|diagnos|disease', re.I)
MATCH_COUNT = re.compile(r'(?:\+=|\+\+)[^;]*KOF_DIAG_ST_MATCH|KOF_DIAG_ST_MATCH[^;]*\+\+')
NO_VERDICT = re.compile(r'no verdict.*%s')

# kofscanner takes none; ksigbuilder and kofwatcher are outside this rule (ksigbuilder is the one program that reads inner headers, with -Ilibkofeng: CLAUDE.md).
INNER_STRICT = ['kofscanner']
INNER_RATCHET = ['kofexamine']
# The inner headers kofexamine includes today, by kind, each with why. Not reviewed one by one: BASELINE of 2026-10-29. A header outside these patterns fails.
INNER_OK = [
    (r'analyzers/', 'the examiner reads the structure of the object itself (parsers, symbols, code notes): analysis, not a verdict'),
    (r'kofcore/', 'core types and helpers'),
    (r'(?:^|/)kofeng\.h$', 'the public API, reached by a relative path (check_layers "tool includes" asks for <kofeng.h>)'),
    (r'databases/(?:dbloader|diagsrc|pack/)', 'the editor reads and writes diagnose SOURCES and the pack layout (draft, Generate)'),
    (r'detectors/(?:pattern|linkage|mutations|heur)/', 'the draft panel evaluates markers, lineage and mutation blocks for the researcher [Inference: baseline, to review]'),
    (r'scanners/(?:scan|objsrc)\.h', 'the examiner scans the object it opens itself, read only [Inference: baseline, to review]'),
    (r'verdictor/(?:famcat|tagcat|catstore)', 'the catalog EDITOR (Manage > Pathogens / Syndromes) owns those files: a model of data it writes, not a verdict'),
]
# (file, rule, function) -> why it stays. The function is the one enclosing the line, found by the last column-0 definition above it.
EXEMPT = {
    ('kofexamine/kofexaminer_unpack.c', 'LOOP', 'print_why'):
        'the examiner explains only the objects that have a verdict: it reads kdet_object.res.has_verdict to skip the others. A tool filtering the engine\'s results by a flag of '
        'its own (CLAUDE.md 11); proposal: kdet_run_find / a kdet_run walk that lists the objects with a verdict. Reported 2026-10-29.',
    ('kofexamine/kv_decl.c', 'COUNT', 'diag_shown_n'):
        'the draft panel counts the report rows of the diagnoses that matched (kdet_run_* gives the rows, no count): proposal kdet_run_matched(run, obj)',
}


def strip_comments(text):
    out = []
    in_block = False
    for line in text.split('\n'):
        res, i = '', 0
        while i < len(line):
            if in_block:
                j = line.find('*/', i)
                if j < 0:
                    i = len(line)
                else:
                    in_block = False
                    i = j + 2
                continue
            if line.startswith('/*', i):
                in_block = True
                i += 2
                continue
            if line.startswith('//', i):
                break
            res += line[i]
            i += 1
        out.append(res)
    return out


FUNC = re.compile(r'^(?:static\s+|inline\s+)*[A-Za-z_][\w\s\*]*?\b([A-Za-z_]\w*)\s*\([^;]*$')


def enclosing(lines, n):
    for i in range(n, -1, -1):
        m = FUNC.match(lines[i])
        if m and not lines[i].startswith(('\t', ' ', '#', '}')) and not re.match(r'^(if|for|while|switch|return|else)\b', lines[i]):
            return m.group(1)
    return '?'


def scan_file(rel, text):
    """The violations of one tool source: (rule, line number, function, message)."""
    lines = strip_comments(text)
    out = []
    top = rel.split('/')[0]
    for n, l in enumerate(lines):
        if INNER.search(l):
            if top in INNER_STRICT:
                out.append(('INCLUDE', n + 1, '-', 'kofscanner includes an inner header of the engine: %s' % l.strip()))
            elif top in INNER_RATCHET:
                m = re.search(r'["<]([^">]+)[">]', l)
                hdr = m.group(1) if m else l
                if not any(re.search(p, hdr) for p, _ in INNER_OK):
                    out.append(('INCLUDE', n + 1, '-', 'an inner header no INNER_OK pattern names: %s' % hdr))
        if top in ('kofexamine', 'kofscanner', 'kofwatcher'):
            if VERDICT_READ.search(l):
                for b in range(max(0, n - 12), n):
                    if LOOP_HEAD.match(lines[b]):
                        # the loop must still be open at line n: count braces between
                        depth = 0
                        opened = False
                        for k in range(b, n + 1):
                            depth += lines[k].count('{') - lines[k].count('}')
                            opened = opened or '{' in lines[k]
                        if depth > 0 or (not opened and n - b <= 2):
                            out.append(('LOOP', n + 1, enclosing(lines, n), 'a loop (line %d) reads a result\'s verdict: %s' % (b + 1, l.strip())))
                            break
        for rx, why in SPELL:
            if rx.search(l):
                out.append(('SPELL', n + 1, enclosing(lines, n), why + ': ' + l.strip()))
        if DASH.search(l) and any(DETECT_WORD.search(lines[k]) for k in range(max(0, n - 2), min(len(lines), n + 3))):
            out.append(('SPELL', n + 1, enclosing(lines, n), 'a name joined with "-" beside a detection word: ' + l.strip()))
        if NO_VERDICT.search(l) and 'verdict.name' in ' '.join(lines[n:n + 2]):
            out.append(('SPELL', n + 1, enclosing(lines, n), 'composes "no verdict <child\'s verdict> in <child>" itself: ' + l.strip()))
        if MATCH_COUNT.search(l):
            out.append(('COUNT', n + 1, enclosing(lines, n), 'counts matched diagnoses itself: ' + l.strip()))
    return out


def scan_tree(root):
    res = []
    for d in TOOL_DIRS:
        base = os.path.join(root, d)
        if not os.path.isdir(base):
            continue
        for fn in sorted(os.listdir(base)):
            if fn.endswith(('.c', '.h')):
                rel = d + '/' + fn
                with open(os.path.join(base, fn), errors='replace') as f:
                    for v in scan_file(rel, f.read()):
                        res.append((rel,) + v)
    return res


def selftest(scratch):
    """Each rule fails on a deliberate violation, and the clean shapes do not. Written under `scratch`."""
    os.makedirs(scratch, exist_ok=True)
    cases = [
        ('kofscanner/x.c', '#include "../libkofeng/verdictor/verdict.h"\n', 'INCLUDE'),
        ('kofexamine/x.c', '#include "../libkofeng/verdictor/vmatch.h"\n', 'INCLUDE'),
        ('kofexamine/x.c', 'void f(struct view *v)\n{\n\tfor (k = 0; k < v->n_obj; k++)\n\t\tif (v->obj[k].heur.has_verdict)\n\t\t\tn++;\n}\n', 'LOOP'),
        ('kofscanner/x.c', 'void g(void)\n{\n\tsnprintf(b, n, "%s#%s", a, c);\n}\n', 'SPELL'),
        ('kofexamine/x.c', 'void h(void)\n{\n\tsnprintf(verdict, n, "%s-%s", fam, var);\n}\n', 'SPELL'),
        ('kofexamine/x.c', 'void k(void)\n{\n\tout_fmt(o, "no verdict  %s", kid->heur.verdict.name);\n}\n', 'SPELL'),
        ('kofexamine/x.c', 'void j(void)\n{\n\tn += ob->diag[i].state == KOF_DIAG_ST_MATCH;\n}\n', 'COUNT'),
    ]
    clean = [
        ('kofscanner/y.c', '#include <kofeng.h>\n'),
        ('kofexamine/y.c', '#include "../libkofeng/analyzers/parsers/kofformat.h"\n'),
        ('kofexamine/y.c', 'void f(void)\n{\n\t/* has_verdict in a comment: for (;;) verdict.name */\n\tout = kdet_info_name(r);\n\tif (r->has_verdict)\n\t\tshow(r->verdict.name);\n}\n'),
        ('kofexamine/y.c', 'void g(void)\n{\n\tsnprintf(b, n, "%s-%s", a, c);\n}\n'),
    ]
    bad = 0
    for rel, text, rule in cases:
        got = [v[0] for v in scan_file(rel, text)]
        if rule not in got:
            print('  SELFTEST FAIL: rule %s did not fire on %s:\n%s' % (rule, rel, text))
            bad += 1
        p = os.path.join(scratch, 'case_%s.c' % rule)
        with open(p, 'w') as f:
            f.write(text)
    for rel, text in clean:
        got = scan_file(rel, text)
        if got:
            print('  SELFTEST FAIL: a clean shape fired %s' % (got,))
            bad += 1
    print('  self test: %d rules shown to fail on a deliberate violation, %d clean shapes pass%s' % (len(cases), len(clean), '' if not bad else ', %d WRONG' % bad))
    return bad


def main(argv):
    if len(argv) >= 3 and argv[1] == '--selftest':
        return 1 if selftest(argv[2]) else 0
    root = argv[1] if len(argv) > 1 else '.'
    scratch = os.path.join(root, 'build', 'tool_logic_selftest')
    bad = selftest(scratch)
    used = set()
    found = scan_tree(root)
    for rel, rule, ln, fn, msg in found:
        key = (rel, rule, fn)
        if key in EXEMPT:
            used.add(key)
            continue
        print('%s:%d: [%s] %s (in %s)' % (rel, ln, rule, msg, fn))
        bad += 1
    for key, why in sorted(EXEMPT.items()):
        if key not in used:
            print('  fixed, delete from EXEMPT: %s %s %s' % key)
            bad += 1
    print('tool_logic_check: %d exempt, %d violation(s)' % (len(used), bad))
    return 1 if bad else 0


sys.exit(main(sys.argv))
