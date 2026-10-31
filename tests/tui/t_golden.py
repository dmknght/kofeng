"""Golden screens: text dumps of the real viewer on four fixed samples, compared to tests/tui/golden/<name>.txt.

A case fails on ANY difference (one cell of text) and prints the diff. The golden file changes only in a patch whose manifest
says `allow golden <name>` (tools/patch_gate.py lists a changed or new file under tests/tui/golden as UNREQUESTED otherwise): a
screen changes because somebody asked for that change, not because a function was added beside the one that was asked for.

States, all reached by the mouse and the menus (no key route is used or added):
  per sample (run1 = a Mirai build the release database detects, clean = an ELF the engine finds nothing in, pe = a small PE,
  zip = an archive with children): the tree and status bar as opened, and the dashboard's five tabs;
  run1 only: the verdict-carrying view row (//0:norm) with its dashboard Detection block, the diagnose panel's Patterns / Blocks / Graphs
  tabs for the file and for that view; the five menus open; the dialogs of Edit and Help and Analysis > Decode string; the
  disassembly panel; the context menu of the hex pane.

Samples are read-only copies in $KOF_GOLDEN_SAMPLES (default /mnt/games/normtest/golden_samples), checked by sha256 against
tests/tui/golden/SAMPLES.txt: a changed sample is a FAIL of its own, not a pile of screen diffs.

  python3 run_all.py golden                       run them
  KOF_GOLDEN_WRITE=1 python3 run_all.py golden    rewrite the golden files (then name each in the manifest)
"""
import difflib, hashlib, os, resource
# The screens are of THIS tree: its viewer (KOFVIEWER) and its bases/ (KOF_REPO), whichever directory make was started in; and every
# process the case starts, the viewer included, is under ulimit -v 4194304 (CLAUDE.md, Resources).
os.environ.setdefault('KOF_REPO', os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
try:
    resource.setrlimit(resource.RLIMIT_AS, (4194304 * 1024, 4194304 * 1024))
except (ValueError, OSError):
    pass
from tui import *
from dl import enlarge

A = 'golden'
HERE = os.path.dirname(os.path.abspath(__file__))
GOLD = os.path.join(HERE, 'golden')
SDIR = os.environ.get('KOF_GOLDEN_SAMPLES', '/mnt/games/normtest/golden_samples')
WRITE = os.environ.get('KOF_GOLDEN_WRITE') == '1'
FILES = {'run1': 'run1', 'clean': 'clean_elf', 'pe': 'pe_small.exe', 'zip': 'many.zip'}
ROWS, COLS = 50, 170
TABS5 = ('Overview', 'Segments', 'Sections', 'Imports', 'Exports')


def sample(key):
    """The sample's read-only copy under a FIXED directory (prep_sample's directory carries the process id, whose digits change the
    width of the dashboard's folder row), after its sha256 is checked."""
    p = os.path.join(SDIR, FILES[key])
    if not os.path.exists(p):
        raise Fail('golden sample %s is missing (%s); see tests/tui/golden/SAMPLES.txt' % (key, p))
    want = None
    with open(os.path.join(GOLD, 'SAMPLES.txt')) as f:
        for ln in f:
            if ln.split() and ln.split()[0] == FILES[key]:
                want = ln.split()[1]
    got = hashlib.sha256(open(p, 'rb').read()).hexdigest()
    if got != want:
        raise Fail('golden sample %s changed: sha256 %s, SAMPLES.txt says %s' % (key, got, want))
    d = os.path.join(VT, 'work', 'golden')
    os.makedirs(d, exist_ok=True)
    dst = os.path.join(d, FILES[key])
    if os.path.exists(dst):
        os.chmod(dst, 0o644)
    shutil.copyfile(p, dst)
    os.chmod(dst, 0o444)
    return dst


def screen(v, title):
    """The screen as text, with what differs between two runs (scratch paths, process ids) replaced."""
    rows = []
    for i, l in enumerate(v.screen.display):
        l = l.rstrip()
        l = re.sub(r'bases_copy_p\d+', 'bases_copy', l)
        l = re.sub(r'((?:Engine|Database)\s+\S+\s+build )\d{10}', r'\1<stamp>', l)   # the database's build stamp moves with every build (2026102907 vs ...04), the engine's as well
        rows.append('%2d|%s' % (i + 1, l))
    return '# golden %s: %dx%d\n%s\n' % (title, v.cols, v.rows, '\n'.join(rows))


def compare(name, text):
    path = os.path.join(GOLD, name + '.txt')
    if WRITE:
        os.makedirs(GOLD, exist_ok=True)
        with open(path, 'w') as f:
            f.write(text)
        return
    if not os.path.exists(path):
        raise Fail('no golden file for %s (%s): KOF_GOLDEN_WRITE=1 writes it, the manifest must say `allow golden %s`' % (name, path, name))
    with open(path) as f:
        want = f.read()
    if want != text:
        d = list(difflib.unified_diff(want.split('\n'), text.split('\n'), 'golden/%s.txt' % name, 'screen now', lineterm='', n=1))
        n = sum(1 for x in d if x[:1] in '+-' and x[:3] not in ('+++', '---'))
        # the diff goes to the output whole (run_all cuts a case's message at 200 characters)
        print('--- DIFF %s (%d changed lines)\n%s\n--- END DIFF' % (name, n, '\n'.join(x[:200] for x in d[:80])), flush=True)
        raise Fail('screen %s differs from its golden file (%d changed lines)' % (name, n))


def select(v, name):
    p = v.find(name)
    check(p, 'no row %s' % name)
    v.click(*p)
    v.pump_quiet()


def dash_tab(v, tab):
    d = v.dialog()
    if not (d and 'Overview' in d[4]):
        check(v.menu_item('Analysis', 'Dashboard'), 'no Dashboard item')
        v.pump_quiet()
    p = v.find(tab, rows=(1, 4))
    check(p, 'no %s tab' % tab)
    v.click(*p)
    v.pump_quiet()


def panel_tab(v, tab):
    enlarge(v, 12)
    v.pump_quiet()
    p = v.find(' %s ' % tab, rows=(2, v.rows - 1))
    check(p, 'no %s tab in the panel' % tab)
    v.click(p[0] + 1, p[1])
    v.pump_quiet()


def reg(name, fn, key='run1', rows=ROWS, cols=COLS):
    def run():
        p = sample(key)
        with Viewer(p, rows=rows, cols=cols, copy=False) as v:
            fn(v)
            compare(name, screen(v, name))
    run.__name__ = 'golden_' + name
    case(A)(run)


# ---- per sample: the tree as opened, the dashboard's tabs ----------------------------------------------------------------
for _k in FILES:
    reg('%s_tree' % _k, lambda v: None, _k)
    for _t in TABS5:
        reg('%s_dash_%s' % (_k, _t.lower()), (lambda t: lambda v: dash_tab(v, t))(_t), _k)

# ---- run1: the view row that carries the verdict --------------------------------------------------------------------------
reg('run1_norm_tree', lambda v: select(v, '//0:norm'))
for _t in ('Overview', 'Sections'):
    reg('run1_norm_dash_%s' % _t.lower(), (lambda t: lambda v: (select(v, '//0:norm'), dash_tab(v, t)))(_t))
for _t in ('Patterns', 'Blocks', 'Graphs'):
    reg('run1_panel_%s' % _t.lower(), (lambda t: lambda v: panel_tab(v, t))(_t), rows=60)
    reg('run1_norm_panel_%s' % _t.lower(), (lambda t: lambda v: (select(v, '//0:norm'), panel_tab(v, t)))(_t), rows=60)
reg('zip_panel_graphs', lambda v: panel_tab(v, 'Graphs'), 'zip', rows=60)

# ---- menus and dialogs -----------------------------------------------------------------------------------------------------
for _m in ('File', 'Edit', 'Analysis', 'Manage', 'Help'):
    reg('menu_%s' % _m.lower(), (lambda m: lambda v: (v.menu_open(m), v.pump_quiet()))(_m))
for _name, _m, _it in (('dlg_find', 'Edit', 'Find...'), ('dlg_goto', 'Edit', 'Go to...'), ('dlg_decode', 'Analysis', 'Decode string'),
                       ('dlg_help_keyboard', 'Help', 'Keyboard'), ('dlg_help_about', 'Help', 'About'),
                       ('page_disasm', 'Analysis', 'Show disassembly'), ('page_pathogens', 'Manage', 'Pathogens'),
                       ('page_syndromes', 'Manage', 'Syndromes')):
    reg(_name, (lambda m, it: lambda v: (check(v.menu_item(m, it), 'no %s item' % it), v.pump_quiet()))(_m, _it))
reg('hex_context_menu', lambda v: (v.rclick(60, 8), v.pump_quiet()))


# What a regenerated golden MUST still show. KOF_GOLDEN_WRITE=1 records whatever the viewer draws, so a broken screen could be
# recorded as the new truth; these rows are the part of each screen that the viewer's features stand on, and a golden file that
# lacks one fails here whatever the manifest says. A row is added here when the owner names a part of a screen as required.
REQUIRED = {
    # the object that is the file shows the engine's file verdict (kverdict_filemap): in the status bar and as the one `verdict` row
    'run1_tree': ['ELF  |  Infected#ELF-x64/Botnet:Mirai.A!Diagnose'],
    'run1_dash_overview': ['Detection', 'verdict     Infected#ELF-x64/Botnet:Mirai.A!Diagnose'],
    'clean_tree': ['ELF  |  no verdict'],
    'run1_norm_tree': ['Norm  |  Infected#ELF-x64/Botnet:Mirai.A!Diagnose'],
    'run1_norm_dash_overview': ['Detection', 'verdict     Infected#ELF-x64/Botnet:Mirai.A!Diagnose', 'family      Mirai', 'variant     Mirai.A',
                                'diagnose    botnet_mirai_mirai-ops-str_01'],
    # the head parses the matched diagnose: family, variant, and the variant's comment; the Blocks tab ticks the blocks that decided it
    # and shows the engine's one percentage in the score column, on the file and on its normalised view.
    # A function row shows the unit id of its CFG signature in the hash column (CFG step 2c), or a dash when it has fewer than 12 reachable blocks;
    # the blocks that decide a matched diagnose are the DATA ones (the 12 diagnoses with window hashes of functions stay disabled). The rows the owner
    # named before, which only those diagnoses can make true, are in SUSPENDED_REQUIRED below.
    'run1_norm_panel_blocks': ['Family [ Mirai ]  Variant [ A ]  [Well known IOT botnet]', 'Mutation blocks', 'region  score',
                               '[x]  0x0000a259  fd523fd5', 'DATA    100%', '[ ]  0x000020ab  -         rand_cmwc'],
    'run1_panel_blocks': ['Family [ Mirai ]  Variant [ A ]  [Well known IOT botnet]', 'Mutation blocks', 'region  score', '[x]  0x0000',
                          '[ ]  0x00003be9  308e6e3d  print', '[ ]  0x00003fed  -         szprintf'],
    'run1_panel_patterns': ['Patterns', 'Matchers', '[+ Matcher]', 'Conditions', '[+ Condition]'],
    'run1_norm_panel_patterns': ['Patterns', 'Matchers', '[+ Matcher]', 'Conditions', '[+ Condition]'],
}
# What must NOT be on a screen: a column or row the owner rejected, or a second spelling of a fact the screen already shows.
FORBIDDEN = {
    'run1_norm_panel_blocks': ['match   family', 'variant  ', 'Mirai.A  ', '\u2713', 'Scan region'],
    'run1_panel_blocks': ['match   family', '\u2713', 'Scan region'],
    # the Graphs tab is for the lineage design: it does not list the diagnoses of the object (the old design did)
    'run1_norm_panel_graphs': ['Diagnoses', 'botnet_mirai_mirai-flood'],
    'run1_panel_graphs': ['Diagnoses'],
    'run1_dash_overview': ['family      ', 'variant     ', 'basis       '],
}

# SUSPENDED (owner 2026-10-30, still true after CFG step 2c): the 12 diagnoses whose blocks are WINDOW hashes of functions stay disabled
# (docs/disabled/diagnoses), so the rows only they can make true cannot exist. Turn them back on (move them into REQUIRED) in the change that
# restores those diagnoses or replaces them with CFG ones.
SUSPENDED_REQUIRED = {
    'run1_norm_dash_overview': ['diagnose    botnet_mirai_mirai-flood_01'],
    'run1_norm_panel_blocks': ['[x]  0x00006c7a  846060fe  SendHTTP', 'CODE    100%'],
    'run1_panel_blocks': ['[x]  0x00008064  846060fe  SendHTTP'],
}


@case(A)
def golden_required_rows_are_present():
    """The Dashboard Detection block, the Blocks tab's ticked matched blocks with the parsed head, and the Patterns tab's Matchers / Conditions
    rows are in the golden files (and so in the viewer)."""
    miss = []
    for name, rows in REQUIRED.items():
        path = os.path.join(GOLD, name + '.txt')
        text = open(path, encoding='utf-8').read() if os.path.exists(path) else ''
        miss += ['%s: %r' % (name, r) for r in rows if r not in text]
    check(not miss, 'golden screens lack required rows: %s' % '; '.join(miss))
    extra = []
    for name, rows in FORBIDDEN.items():
        text = open(os.path.join(GOLD, name + '.txt'), encoding='utf-8').read()
        extra += ['%s: %r' % (name, r) for r in rows if r in text]
    check(not extra, 'golden screens hold rows that must not be there: %s' % '; '.join(extra))


@case(A)
def golden_inventory_files_and_cases_agree():
    """A golden file nobody checks is a screen that can change unnoticed; a case with no file cannot fail."""
    names = set(r[1][len('golden_'):] for r in REGISTRY if r[0] == A and r[1].startswith('golden_') and r[1] not in ('golden_inventory_files_and_cases_agree', 'golden_required_rows_are_present'))
    have = set(f[:-4] for f in os.listdir(GOLD) if f.endswith('.txt') and f != 'SAMPLES.txt')
    if WRITE:
        return
    check(names == have, 'golden files without a case: %s; cases without a file: %s' % (sorted(have - names), sorted(names - have)))


if __name__ == '__main__':
    main(A)
