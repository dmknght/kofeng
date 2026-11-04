"""What the viewer shows of the engine's detection (kdet_*): the verdict on the status bar, the Blocks tab's ticked blocks and the save of them.

The viewer shows what the engine answered and computes nothing: the sample is the Mirai build the release database's diagnoses
(bases/diagnoses) detect, and the verdict lives on its normalised view (`//0:norm`), the object the similarity stage scores."""
import subprocess
from tui import *
from dl import click_in_panel, status

A = 'detect'
RUN1 = os.environ.get('KOF_RUN1', '/mnt/games/normtest/scan_run1/run1')
EXAMINER = os.environ.get('KOFEXAMINER', REPO + '/build/release/bin/kofexaminer')


def select(v, name):
    y = v.find(name)
    check(y, 'no row %s' % name)
    v.click(y[0], y[1])
    v.pump_quiet()


@case(A)
def the_file_itself_shows_the_verdict_the_engine_made_for_the_file():
    """The verdict is made on the normalised child; the object that is the file shows the engine's per-file roll-up (kverdict_filemap),
    on the status bar."""
    if not os.path.exists(RUN1):
        raise Skip('no sample at %s' % RUN1)
    with Viewer(RUN1) as v:
        check(re.search(r'ELF\s+\|\s+Infected#ELF-x64/Botnet:Mirai\.A', '\n'.join(v.lines)), 'no verdict on the status bar of the file')


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
    # the engine's own list of what matched, from another tool of the engine (kofexaminer prints each matched diagnose of a verdict)
    out = subprocess.run([EXAMINER, '--no-color', '--db', REPO + '/build/release/databases', RUN1], capture_output=True, text=True, timeout=300).stdout
    matched = set(re.findall(r'^\s+(botnet_mirai_mirai-[a-z0-9-]+_\d+)\s+(?:form|graph)\s*$', out, re.M))
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
