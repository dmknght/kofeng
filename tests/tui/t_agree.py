"""What the VIEWER shows of an object is what the ENGINE answers for it (owner 2026-10-29: tests that catch a tool computing for itself what the engine answers).

The old viewer cases (t_detect.py) grep the screen for a string they were handed ("Infected#ELF-x64/Botnet:Mirai.A"), which a hard-coded copy of that string
would print too, and which stays right until the engine changes. Here the expected text is not written in the test: `build/test/unit_tool_agree --truth <db>
<bases> <path>` asks the engine through its pull API (kscan_path, kdet_info, kdet_diag, kverdict_filemap_*) and the screen must say exactly that - the verdict,
family, variant, tag, type, each matched diagnose, the basis numbers, the file's verdict and the child it lives in (the status bar and the file row) - for

  * the samples run1 (the Mirai build the product's diagnoses detect), a tar that holds it (the verdict is in a child), a clean system binary and a PE,
  * four databases: the product's, and three built from tests/agree (other family, variant letter, tag and type; six diagnoses, three, and none that match).

A viewer that composes the file's verdict itself, spells a name with its own separator or keeps a name from another database fails on the data whose answer differs.
Only unit_tool_agree's own prints are the oracle; it is built by `make unit` (tests/unit/tool_agree.c), which also compares kofscanner and kofexaminer.

Run: KOF_REPO=<tree> KOFVIEWER=<tree>/build/release/bin/kofviewer python3 t_agree.py
"""
from tui import *
import subprocess

A = 'agree'
RUN1 = os.environ.get('KOF_RUN1', '/mnt/games/normtest/scan_run1/run1')
TRUTH = os.path.join(REPO, 'build/test/unit_tool_agree')
AGREE = os.path.join(VT, 'agree_p%d' % os.getpid())
os.makedirs(AGREE, exist_ok=True)
UNP = ['unpack-archive.ksig', 'unpack-doc.ksig', 'unpack-elf.ksig', 'unpack-pe.ksig', 'unpack-raw.ksig', 'unpack-raw-x7.ksig']

_dbs = {}


def database(tag):
    """(db dir, bases dir, expected family or None) of one of the four databases: the product's and tests/agree's three."""
    if tag in _dbs:
        return _dbs[tag]
    if tag == 'release':
        _dbs[tag] = (os.path.join(REPO, 'build/release/databases'), BASES_COPY if os.path.isdir(BASES_COPY) else fresh_bases())
        return _dbs[tag]
    alt = {'alt_a': 'alt_a', 'alt_b': 'alt_b', 'alt_none': 'alt_none'}[tag]
    db = os.path.join(AGREE, 'db_' + tag)
    os.makedirs(db, exist_ok=True)
    for f in UNP:
        shutil.copyfile(os.path.join(REPO, 'build/release/databases', f), os.path.join(db, f))
    src = os.path.join(REPO, 'build/test/databases-' + alt)
    for f in ('diag-trojan.kdig', 'names.kdig'):
        shutil.copyfile(os.path.join(src, f), os.path.join(db, f))
    bases = os.path.join(AGREE, 'bases_' + tag)       # the viewer writes into --bases: a private copy
    if os.path.isdir(bases):
        shutil.rmtree(bases)
    shutil.copytree(os.path.join(REPO, 'tests/agree', alt), bases)
    _dbs[tag] = (db, bases)
    return _dbs[tag]


def truth(db, bases, path):
    """The engine's answer as a dict: file-level keys and a list of objects, each with its verdict and diagnoses."""
    if not os.path.exists(TRUTH):
        raise Skip('%s is not built (make unit)' % TRUTH)
    out = subprocess.run([TRUTH, '--truth', db, bases, path], cwd=REPO, capture_output=True, text=True, timeout=120).stdout
    t = {'objects': [], 'file_verdict': None, 'file_object': None}
    cur = None
    for line in out.splitlines():
        k, _, rest = line.partition(' ')
        if k == 'file_verdict':
            t['file_verdict'] = rest
        elif k == 'file_object':
            t['file_object'] = rest
        elif k == 'object':
            cur = {'name': rest, 'verdict': None, 'diag': [], 'basis': None}
            t['objects'].append(cur)
        elif k == 'verdict' and cur is not None:
            cur['verdict'] = rest
        elif k == 'basis' and cur is not None:
            cur['basis'] = dict(p.split('=') for p in rest.split())
        elif k == 'diag' and cur is not None:
            m = re.match(r'(\S+) family=(.*?) variant=(.*?) tag=(.*?) type=(\S+)$', rest)
            cur['diag'].append(m.groups())
    return t


def leaf(name):
    """The last component of an object name as the tree labels it: 'x.tar//0:run1.elf//0:norm' -> '0:norm'."""
    return name.rsplit('//', 1)[-1] if '//' in name else None


def select_row(v, label):
    y = v.find('//' + label)
    check(y, 'no tree row //%s:\n%s' % (label, '\n'.join(v.lines[:30])))
    v.click(y[0], y[1])
    v.pump_quiet()


def overview(v):
    check(v.menu_item('Analysis', 'Dashboard'), 'no Dashboard item')
    v.pump_quiet()
    p = v.find('Overview', rows=(1, 4))
    check(p, 'no Overview tab')
    v.click(*p)
    v.pump_quiet()
    return '\n'.join(v.lines)


def detection_block(text):
    """What the dashboard says between its Detection heading and the next heading."""
    if 'Detection' not in text:
        return ''
    rest = text[text.index('Detection'):]
    m = re.search(r'\n[ │]*(Regions|Anomalies|Object|Imports|Exports)\b', rest)
    return rest[:m.start()] if m else rest


def compare(db_tag, sample_name, src, expect_old=None):
    if not os.path.exists(src):
        raise Skip('no sample at %s' % src)
    db, bases = database(db_tag)
    path = prep_sample(src, sample_name)
    t = truth(db, bases, path)
    first = t['file_object']
    with Viewer(path, rows=100, db=db, bases=bases) as v:     # tall enough that the Detection block (six diagnoses of three lines each) is not cut by the dialog
        bar = v.lines[-1]
        txt = overview(v)
        v.esc()
        v.pump_quiet()
        # The viewer shows what the engine answered for the OBJECT in hand and, when it also names the file's verdict (the old "inside <verdict> in <child>" row), that is
        # kverdict_filemap's answer and no search of its own. Whatever form it takes, a verdict word on the root's screen must be one the engine produced: a viewer that
        # respells a name, keeps one from another database or composes "which child" itself shows a string the engine never made.
        engine_names = set(o['verdict'] for o in t['objects'] if o['verdict'])
        if t['file_verdict']:
            engine_names.add(t['file_verdict'])
        for shown in set(re.findall(r'\b[A-Za-z]+#[A-Za-z0-9/:.!?+_-]+', txt + '\n' + bar)):
            check(shown in engine_names, 'the root\'s screen shows %r, which the engine did not make (engine: %s)\n%s\n%s' % (shown, sorted(engine_names), bar.rstrip(), txt))
        if 'inside' in txt:
            check(t['file_verdict'], 'the file row names a child with a verdict where the engine made none:\n' + txt)
            m = re.search(r'inside\s+(\S+)\s+in\s+(\S+)', txt)
            check(m, 'no "inside <verdict> in <child>" line:\n' + txt)
            eq(m.group(1), t['file_verdict'], 'the verdict the file row shows is not the engine\'s file verdict')
            eq(m.group(2), leaf(first), 'the child the file row names is not the one the engine made the verdict in')
        root = t['objects'][0] if t['objects'] else None
        if root and not root['verdict'] and t['file_verdict']:
            # The object that IS the file shows the engine's per-file verdict (kverdict_filemap): on the status bar and as the Detection block's one row.
            check(t['file_verdict'] in bar, 'the status bar of the file does not carry the engine\'s file verdict %r: %r' % (t['file_verdict'], bar.rstrip()))
            check(re.search(r'verdict\s+' + re.escape(t['file_verdict']), txt), 'the Detection block of the file does not carry the engine\'s file verdict:\n' + txt)
        elif root and not root['verdict']:
            check('Detection' not in txt, 'a Detection block on a root the engine gave no verdict:\n' + txt)
            check('no verdict' in bar, 'the status bar of an object with no verdict does not say so: %r' % bar.rstrip())
        elif root and root['verdict']:
            check(root['verdict'] in bar, 'the status bar of the root does not carry the engine\'s verdict %r: %r' % (root['verdict'], bar.rstrip()))
        # each object the engine gave a verdict: its own row says exactly what kdet_info / kdet_diag say
        for o in t['objects']:
            if not o['verdict']:
                continue
            lf = leaf(o['name'])
            check(lf, 'a verdict on the root object itself is not exercised by these samples: %s' % o['name'])
            select_row(v, lf)
            full = overview(v)
            v.esc()
            v.pump_quiet()
            d = detection_block(full)
            check(d, 'no Detection block for %s (the engine: %s)' % (lf, o['verdict']))
            check(o['verdict'] in d, 'the verdict shown is not the engine\'s\n  engine: %s\n  screen:\n%s' % (o['verdict'], d))
            fam, var, tag, typ = o['diag'][0][1], o['diag'][0][2], o['diag'][0][3], o['diag'][0][4]
            check(re.search(r'family\s+%s\b' % re.escape(fam), d), 'family %r not shown:\n%s' % (fam, d))
            check(re.search(r'variant\s+%s\b' % re.escape(var), d), 'variant %r not shown:\n%s' % (var, d))
            check(re.search(r'tag\s+%s\b' % re.escape(tag), d), 'tag %r not shown:\n%s' % (tag, d))
            check(typ in d, 'type %r not shown:\n%s' % (typ, d))
            b = o['basis']
            check(re.search(r'basis\s+(variant|tag)\s+cover %s\s+jaccard %s\s+groups %s\s+matched %s' % (b['cover'], b['jaccard'], b['groups'], b['matched']), d),
                  'the basis numbers are not the engine\'s (%s):\n%s' % (b, d))
            for dg in o['diag']:
                check(dg[0] in d, 'diagnose %s (engine) is not listed:\n%s' % (dg[0], d))
            # nothing the engine did not list: every "<family>_<n>"-shaped diagnose name on the screen is one of the engine's
            names = set(x[0] for x in o['diag'])
            for shown in set(re.findall(r'\b(?:botnet|trojan)_[a-z0-9]+_[a-z0-9-]+_\d+\b', d)):
                check(shown in names, 'the screen lists diagnose %s that the engine did not match' % shown)
            if expect_old:
                check(expect_old not in d, 'the old name %r is still shown for data that does not carry it:\n%s' % (expect_old, d))


def sample(name):
    return {'run1': RUN1, 'tar': None, 'ls': os.path.realpath('/bin/ls'),
            'pe': os.path.join(REPO, 'build/test/fixtures/synth-pe64.exe')}[name]


def tar_with_run1():
    if not os.path.exists(RUN1):
        raise Skip('no sample at %s' % RUN1)
    d = os.path.join(AGREE, 'tar')
    os.makedirs(d, exist_ok=True)
    shutil.copyfile(RUN1, os.path.join(d, 'run1.elf'))
    out = os.path.join(d, 'holds_run1.tar')
    subprocess.run(['tar', '-C', d, '-cf', out, 'run1.elf'], check=True)
    return out


def make(db_tag, what):
    old = {'release': None, 'alt_a': 'Mirai', 'alt_b': 'Mirai', 'alt_none': 'Mirai'}[db_tag]

    def body():
        src = tar_with_run1() if what == 'tar' else sample(what)
        compare(db_tag, 'holds_run1.tar' if what == 'tar' else None, src, old)
    body.__name__ = 'viewer_shows_what_the_engine_answers_%s_on_%s' % (db_tag, what)
    return body


for _db in ('release', 'alt_a', 'alt_b', 'alt_none'):
    for _s in ('run1', 'tar', 'ls', 'pe'):
        case(A)(make(_db, _s))

if __name__ == '__main__':
    try:
        main(A)
    finally:
        shutil.rmtree(AGREE, ignore_errors=True)
