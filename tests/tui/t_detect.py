"""What the viewer shows of the engine's detection (kdet_*): the verdict, the catalog family / variant / tag it was decided from,
the basis, each matched diagnose and why it matched (a matcher's similarity percentage against what was demanded).

The viewer shows what the engine answered and computes nothing: the sample is the Mirai build the release database's diagnoses
(bases/diagnoses) detect, and the verdict lives on its normalised view (`//0:norm`), the object the similarity stage scores."""
import subprocess
from tui import *
from dl import click_in_panel, status

A = 'detect'
RUN1 = os.environ.get('KOF_RUN1', '/mnt/games/normtest/scan_run1/run1')


def dash_text(v):
    check(v.menu_item('Analysis', 'Dashboard'), 'no Dashboard item')
    v.pump_quiet()
    p = v.find('Overview', rows=(1, 4))
    check(p, 'no Overview tab')
    v.click(*p)
    v.pump_quiet()
    return '\n'.join(v.lines)


def select(v, name):
    y = v.find(name)
    check(y, 'no row %s' % name)
    v.click(y[0], y[1])
    v.pump_quiet()


@case(A)
def view_row_dashboard_shows_the_verdict_family_variant_tag_and_basis():
    if not os.path.exists(RUN1):
        raise Skip('no sample at %s' % RUN1)
    with Viewer(RUN1) as v:
        select(v, '//0:norm')
        t = dash_text(v)
        check('Detection' in t, 'no Detection block:\n' + t)
        check('Infected#ELF-x64/Botnet:Mirai.A' in t, 'verdict missing')
        check(re.search(r'family\s+Mirai\b', t), 'family row missing')
        check(re.search(r'variant\s+Mirai\.A', t), 'variant row missing')
        # Function units carry no similarity signature (prototype 2026-10-30): the six flood diagnoses (blocks cut from functions) no longer
        # match; the lead is the data-block diagnose Mirai-Ops-Str, over the two that still do. The diagnoses holding CODE blocks are moved to docs/disabled/diagnoses, so the variant's set is the four
        # that are loaded and the two matched cover all of what matched (the engine's numbers: cover 1000, jaccard 1000; 666/800 while the six were loaded and scored 0).
        check(re.search(r'tag\s+Mirai-Ops-Str', t), 'tag row missing')
        check(re.search(r'basis\s+variant\s+cover 1000\s+jaccard 1000\s+groups 1\s+matched 2', t), 'basis row missing')


@case(A)
def each_matched_diagnose_is_listed_with_its_catalog_facts_and_why_it_matched():
    if not os.path.exists(RUN1):
        raise Skip('no sample at %s' % RUN1)
    with Viewer(RUN1) as v:
        select(v, '//0:norm')
        t = dash_text(v)
        # The diagnoses of data blocks match; the six whose blocks are cut from functions are not scored (no function signature yet).
        for name in ('botnet_mirai_mirai-ops-str_01', 'botnet_mirai_mirai-wordlist_01'):
            check(name in t, 'diagnose %s not listed' % name)
        for i in range(1, 7):
            check('botnet_mirai_mirai-flood_0%d' % i not in t, 'diagnose flood %d is listed though its block is a function' % i)
        check('Botnet' in t, 'the diagnose type is missing')
        check(re.search(r'family Mirai\s+variant Mirai\.A\s+tag Mirai-Ops-Str', t), 'a diagnose line has no family/variant/tag')
        check(re.search(r'matcher 0 similarity \d+% of the 1 block\(s\), 70% demanded', t), 'no matcher row (why it matched):\n' + t)


@case(A)
def the_file_itself_shows_the_verdict_the_engine_made_for_the_file():
    """The verdict is made on the normalised child; the object that is the file shows the engine's per-file roll-up (kverdict_filemap),
    on the status bar and in the Detection block."""
    if not os.path.exists(RUN1):
        raise Skip('no sample at %s' % RUN1)
    with Viewer(RUN1) as v:
        check(re.search(r'ELF\s+\|\s+Infected#ELF-x64/Botnet:Mirai\.A', '\n'.join(v.lines)), 'no verdict on the status bar of the file')
        t = dash_text(v)
        check(re.search(r'verdict\s+Infected#ELF-x64/Botnet:Mirai\.A', t), 'no verdict in the Detection block of the file:\n' + t)


@case(A)
def a_clean_object_has_no_detection_block():
    with Viewer(os.path.realpath('/bin/ls')) as v:        # a system binary the database has nothing to say about
        t = dash_text(v)
        check('Detection' not in t, 'a Detection block for an object with no verdict')


def panel_text(v):
    """The working panel below the rule: everything under the line of '=' signs."""
    rows = v.lines
    top = max(i for i, l in enumerate(rows) if l.startswith('-') and '=' in l)
    return '\n'.join(l.rstrip() for l in rows[top + 1:])


def open_graphs_tab(v):
    p = v.find('Graphs')
    check(p, 'no Graphs tab in the working panel')
    v.click(*p)
    v.pump_quiet()


@case(A)
def the_graphs_tab_does_not_list_the_diagnoses_of_the_object():
    """The Graphs tab is for the lineage design; the matched diagnoses are shown on the Dashboard and, as ticked blocks, on the Blocks tab."""
    if not os.path.exists(RUN1):
        raise Skip('no sample at %s' % RUN1)
    with Viewer(RUN1) as v:
        select(v, '//0:norm')
        open_graphs_tab(v)
        t = panel_text(v)
        check('botnet_mirai_mirai-flood' not in t and 'Diagnoses' not in t, 'the Graphs tab lists diagnoses:\n' + t)


EXAMINER = os.environ.get('KOFEXAMINER', REPO + '/build/release/bin/kofexaminer')
PART = re.compile(r'block ([0-9a-f]{8}) yes: holds (\d+) of (\d+) hashes \((\d+)%\), cut from (\w+); place 0x([0-9a-f]+) \+(\d+) in (\w+)(?:, (\w+))? holds (\d+)')


@case(A)
def each_block_that_decided_a_form_is_listed_with_its_place_and_function():
    """The Dashboard's Detection block lists, under a form's row, the blocks it compared: id, share held, region, the place in the object and
    the function. The oracle is another tool of the engine: kofexaminer --blocks lists the units with the same offsets, lengths, ids and functions."""
    if not os.path.exists(RUN1):
        raise Skip('no sample at %s' % RUN1)
    with Viewer(RUN1, rows=70) as v:
        select(v, '//0:norm')
        t = dash_text(v)
        seen = {}
        for m in PART.finditer(t):
            seen[m.group(1)] = m.groups()
        # The 12 diagnoses with window hashes of functions stay disabled (docs/disabled), so only the blocks cut from DATA decide a form (two: ops-str,
        # wordlist) and none of them is a function; kofexaminer --blocks lists the function units with their CFG signature or the reason they have none.
        check(len(seen) >= 2, 'the two data blocks are not all listed: %r\n%s' % (sorted(seen), t))
        units = {}
        out = subprocess.run([EXAMINER, '--no-color', '--blocks', '--db', REPO + '/build/release/databases', RUN1], capture_output=True,
                             text=True, timeout=300).stdout
        # CFG step 2c: a function unit is signed by the shape of its function (cfg_blocks=N block_id=...) or says why it is not (function unit: not signed: ...)
        check('function unit: not signed' in out or 'cfg_blocks=' in out, 'kofexaminer --blocks does not list the function units with their CFG signature or the reason')
        for l in out.splitlines():
            m = re.match(r'\s+unit\s+region=(\S+)\s+off=0x([0-9a-f]+)\s+len=(\d+)\s+side=\S+(?:\s+func=(\S+))?\s+windows=\d+\s+block_id=([0-9a-f]{8})', l)
            if m:
                units[(m.group(2), m.group(3))] = (m.group(4), m.group(5))
        for bid, g in seen.items():
            off, ln, fn = g[5], g[6], g[8]
            check(fn is None, 'block %s is placed in a function (%s): function units are not scored' % (bid, fn))
            check(g[1] == g[2] and g[3] == '100', 'block %s does not hold all of its hashes: %r' % (bid, g))
            check((off, ln) in units, 'block %s: place 0x%s +%s is not a unit of kofexaminer --blocks' % (bid, off, ln))
            check(units[(off, ln)][1] == bid, 'block %s: the unit there has block_id %s' % (bid, units[(off, ln)][1]))


def blocks_rows(v, sel):
    if sel:
        select(v, sel)
    p = v.find('Blocks')
    check(p, 'no Blocks tab')
    v.click(*p)
    v.pump_quiet()
    top = max(i for i, l in enumerate(v.lines) if l.startswith('-') and '=' in l)
    got, text = {}, ''
    head = v.lines[top + 1]
    for _ in range(60):
        pt = panel_text(v)
        text += '\n' + pt
        for l in pt.splitlines():
            m = re.search(r'\[(.)\]\s+0x([0-9a-f]{8})\s+([0-9a-f]{8})\s+(?:(\S+)\s+)?\d+\s+(?:CODE|DATA)\s+(\d+)%', l)
            if m:
                got[m.group(3)] = (m.group(1), m.group(4) or '', m.group(5))
        v.wheel(60, top + 4, n=1)
        v.pump(0.1)
    return got, text, head


@case(A)
def the_blocks_tab_ticks_the_blocks_that_decided_and_parses_the_diagnose_into_the_head():
    """A block a matched form decided is ticked (so it is a matcher), with the engine's share in the one percentage column, on the file and on its
    normalised view alike (the block id is the same, the offset is not). The head takes the diagnose's family, variant and the variant's comment;
    each matcher takes the diagnose's tag and the threshold it demands (70, not the editor's default)."""
    if not os.path.exists(RUN1):
        raise Skip('no sample at %s' % RUN1)
    with Viewer(RUN1, rows=70) as v:
        for sel in (None, '//0:norm'):
            got, text, head = blocks_rows(v, sel)
            # Prototype 2026-10-30: a function unit has no signature, so the six function blocks (botnetTScan, SendHTTP, SendHTTPHex, sendUDP,
            # sendTCP, sendSTD) no longer decide a form and are not ticked; the two DATA blocks (no function name) still are.
            ids = {'541cd7e6': '', 'fd523fd5': ''}
            for bid, name in ids.items():
                check(got.get(bid) == ('x', name, '100'), '%s: block %s %s is not ticked with 100%%: %r' % (sel, bid, name, got.get(bid)))
            check(len([1 for x in got.values() if x[0] == 'x']) == 2, 'not exactly the two data blocks are ticked: %r' % got)
            check('Family [ Mirai ]  Variant [ A ]  [Well known IOT botnet]' in head, 'the head is not parsed from the diagnose: %r' % head)
            check(len(re.findall(r'\d\.\s+(?:\S+: )?[0-9a-f]{8}\s+Threshold: >= \[ 70\]%[^\n]*\n\s+Type: Botnet\s+Tag: Mirai-(?:Ops-Str|wordlist)', text)) >= 2,
                  'the matchers do not carry threshold 70 and the tag:\n' + text[-1500:])
            check(re.search(r'^\s+\d+\.\s+[0-9a-f]{8}\s+Threshold', text, re.M) and 'find_sim' not in text, 'a data block prints the bare hash and no find_sim word:\n' + text[-1500:])
            check('Scan region' not in text, 'the Scan region row is on the Blocks tab')


def tick_rows(v):
    """The ticked rows of the Blocks table now on the screen: block id -> the screen position of its [x]."""
    got = {}
    for y in range(1, v.rows):
        m = re.search(r'\[x\]\s+0x[0-9a-f]{8}\s+([0-9a-f]{8})\s', v.row(y))
        if m:
            got[m.group(1)] = (v.row(y).index('[x]') + 2, y)
    return got


def find_tick(v):
    """Scroll the block table (wheel, down and then up) until a ticked row is on the screen; its position, or None."""
    top = max(i for i, l in enumerate(v.lines) if l.startswith('-') and '=' in l)
    for step in (1, -1):
        for _ in range(40):
            t = tick_rows(v)
            if t:
                return sorted(t.items())[0]
            v.wheel(60, top + 4, n=3 * step)
            v.pump(0.04)
    return None


def diag_files(dd):
    out = {}
    for f in sorted(os.listdir(dd)):
        with open(os.path.join(dd, f), 'rb') as fh:
            out[f] = fh.read()
    return out


@case(A)
def save_writes_what_was_added_and_deletes_the_diagnose_of_a_block_that_was_unticked():
    """The Blocks tab ticks the six blocks that decided the matched Mirai diagnoses, each matcher linked to the diagnose it came from.
    Generate with nothing changed writes and deletes nothing; unticking a block deletes that diagnose's file and only that one (the status
    line names it), and unticking the rest deletes the rest."""
    if not os.path.exists(RUN1):
        raise Skip('no sample at %s' % RUN1)
    import shutil
    with Viewer(RUN1, rows=90) as d:          # the engine's own list of what matched: the Overview of the view lists each matched diagnose (tall enough for all)
        select(d, '//0:norm')
        t = dash_text(d)
        matched = set(re.findall(r'botnet_mirai_mirai-[a-z0-9-]+_\d+', t))
        eq(len(matched), int(re.search(r'basis .*?matched (\d+)', t).group(1)), 'the Overview lists every matched diagnose')
    check(matched, 'the engine lists no matched diagnose')
    with Viewer(RUN1, rows=70, cols=200) as v:
        dd = os.path.join(BASES_COPY, 'diagnoses')
        os.makedirs(dd, exist_ok=True)
        try:
            save_cases(v, dd, matched)
        finally:
            for f in os.listdir(dd):          # the private bases copy holds no diagnose for the other cases
                os.unlink(os.path.join(dd, f))


def save_cases(v, dd, matched):
    import shutil
    for f in sorted(os.listdir(os.path.join(REPO, 'bases', 'diagnoses'))):
        if f.startswith('botnet_mirai_mirai-'):
            shutil.copy(os.path.join(REPO, 'bases', 'diagnoses', f), dd)
    if True:
        select(v, '//0:norm')
        p = v.find('Blocks')
        check(p, 'no Blocks tab')
        v.click(*p)
        v.pump_quiet()
        start = diag_files(dd)
        # How many diagnoses the owner's bases/ holds is not this test's business: what is ticked is what the engine matched, and only that is
        # deleted when unticked; a diagnose that did not match has no ticked block and stays.
        mine = {f for f in start if f[:-2] in matched}
        check(mine and any(('ops-str' in f or 'wordlist' in f) for f in mine), 'the matched diagnoses are in the bases copy: %r / %r' % (sorted(matched), sorted(start)))
        click_in_panel(v, '[ Save ]')
        check('Nothing new to write' in status(v), 'Generate with nothing changed: %r' % status(v)[-200:])
        eq(diag_files(dd), start, 'Generate with nothing changed touched the directory')
        t = find_tick(v)
        check(t, 'no ticked block in the table')
        v.click(*t[1])
        v.pump_quiet()
        click_in_panel(v, '[ Save ]')
        now = diag_files(dd)
        gone = sorted(set(start) - set(now))
        check(len(gone) == 1 and gone[0] in mine, 'exactly one matched diagnose is deleted: %r' % gone)
        eq({f: now[f] for f in now}, {f: start[f] for f in now}, 'a file that stayed was changed')
        check('Deleted 1 file' in status(v) and gone[0][:-2] in status(v), 'the status does not name what was deleted: %r' % status(v)[-200:])
        click_in_panel(v, '[ Save ]')
        check('Nothing new to write' in status(v) or 'Nothing to write' in status(v), 'a second Generate: %r' % status(v)[-200:])
        eq(sorted(diag_files(dd)), sorted(now), 'a second Generate changed the directory')
        for _ in range(len(start) + 8):      # one untick per matcher at most: more than the files the copy holds
            t = find_tick(v)
            if not t:
                break
            v.click(*t[1])
            v.pump_quiet()
        click_in_panel(v, '[ Save ]')
        rest = diag_files(dd)
        eq(sorted(rest), sorted(set(start) - mine), 'every ticked block was unticked: every matched diagnose of the copy is deleted, the others stay')
        eq({f: rest[f] for f in rest}, {f: start[f] for f in rest}, 'a file that stayed was changed')
        check('Deleted %d file%s' % (len(mine) - 1, '' if len(mine) == 2 else 's') in status(v), 'status (%d matched, one went before): %r' % (len(mine), status(v)[-200:]))


if __name__ == '__main__':
    main(A)
