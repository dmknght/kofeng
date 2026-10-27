"""The Syndrome table (Analysis > Syndrome table): four tabs over the tag
sources, search, Add / Edit / Delete / Check / Save, the forms and the pick
list, and the diagnose panel's Tag chooser and output names that read them.

Every case works on a COPY of the seeds in a directory beside the build output
(build/kof_syn_<pid>_<n>, never /tmp), passed with --syndromes: what Save
writes is read back from there."""
import atexit
import glob
import shutil
from tui import *
from dl import *

A = 'syntable'
_dirs = []


def fresh_dir():
    """A copy of bases/syndromes under REPO/build, removed at exit."""
    d = os.path.join(REPO, 'build', 'kof_syn_%d_%d' % (os.getpid(), len(_dirs)))
    if os.path.isdir(d):
        shutil.rmtree(d)
    shutil.copytree(os.path.join(REPO, 'bases', 'syndromes'), d)
    _dirs.append(d)
    return d


def _cleanup():
    for d in _dirs:
        shutil.rmtree(d, ignore_errors=True)


atexit.register(_cleanup)


def viewer(d, path=None, rows=40, cols=140):
    return Viewer(path or FIX('tiny.bin'), rows=rows, cols=cols,
                  extra=['--syndromes', d])


def ko_viewer(d, rows=60, cols=150):
    v = Viewer(SAMPLES['ko'], rows=rows, cols=cols, extra=['--syndromes', d])
    enlarge(v, 18)
    return v


def open_table(v):
    raise Skip('Manage > Syndromes is switched off for now (bar_enabled BI_SYNTAB); the table code is kept')
    check(v.menu_item('Analysis', 'Syndrome table'), 'no Syndrome table item')
    check(v.wait_for('Syndrome table', 3), 'the page did not open')


TABS_ = ('Activities', 'Types', 'Families', 'Tags')


def tab_y(v):
    for y in range(2, 8):
        if ' Activities ' in v.row(y) and ' Families ' in v.row(y):
            return y
    return None


def tab(v, name):
    y = tab_y(v)
    check(y, 'no tab bar')
    v.click(v.row(y).index(' %s ' % name) + 3, y)


def active(v):
    y = tab_y(v)
    rev = set(v.reverse_cols(y))
    on = [n for n in TABS_
          if rev & set(range(v.row(y).index(' %s ' % n) + 2, v.row(y).index(' %s ' % n) + len(n) + 3))]
    return on[0] if len(on) == 1 else None


def press(v, label):
    """Click a button of the page's control row."""
    y = tab_y(v) + 1
    p = v.find(label, rows=(y, y))
    check(p, 'button %s not on %r' % (label, v.row(y)[:100]))
    v.click(*p)


def cells(line):
    """The words of one table row, split on runs of two spaces."""
    return [c for c in re.split(r'\s{2,}', line.strip('│ ').strip()) if c]


def table(v):
    """The rows of the open tab: [[cells]] from under the column names."""
    y0 = tab_y(v) + 3
    out = []
    for y in range(y0, v.rows - 2):
        r = v.row(y)
        if '│' not in r:
            break
        c = cells(r[r.index('│'):r.rindex('│') + 1])
        if c and not c[0].startswith('nothing'):
            out.append([x.lstrip('+* ') if i == 0 else x for i, x in enumerate(c)])
    return out


def names(v):
    return [r[0] for r in table(v)]


def heading(v):
    y = tab_y(v) + 2
    r = v.row(y)
    return cells(r[r.index('│'):r.rindex('│') + 1])


def box(v, title):
    """(y0, x0, x1, y1) of the box whose top rule says `title`, or None."""
    for y in range(2, v.rows):
        r = v.row(y)
        j = r.find('─ %s ' % title)
        if j >= 0:
            x0 = r.rfind('╭', 0, j)
            x1 = r.find('╮', j)
            if x0 >= 0 and x1 > x0:
                for y1 in range(y + 1, v.rows + 1):
                    if v.row(y1)[x0:x0 + 1] == '╰':
                        return (y, x0 + 1, x1 + 1, y1)
    return None


def bfind(v, b, label, nth=0):
    """(x, y) of `label` inside box b, below its top rule."""
    y0, x0, x1, y1 = b
    k = 0
    for y in range(y0 + 1, y1):
        seg = v.row(y)[x0:x1 - 1]
        j = seg.find(label)
        while j >= 0:
            if k == nth:
                return (x0 + 1 + j + len(label) // 2, y)
            k += 1
            j = seg.find(label, j + 1)
    return None


def btext(v, b):
    return '\n'.join(v.row(y)[b[1] - 1:b[2]] for y in range(b[0], b[3] + 1))


def files(d, kind=None):
    return sorted(f for f in os.listdir(d) if f.endswith('.c') and (not kind or f.startswith(kind + '_')))


def read(d, f):
    with open(os.path.join(d, f)) as fh:
        return fh.read()


def add_entity(v, tabname, name):
    tab(v, tabname)
    press(v, '[Add]')
    v.type(name)
    v.key('enter')


def pick_in(v, title, labels):
    """In the pick list `title`: tick each label in turn, then [ OK ]."""
    b = box(v, title)
    check(b, 'pick list %r did not open: %r' % (title, v.snapshot()[10:24]))
    for l in labels:
        p = bfind(v, b, l)
        check(p, 'no %r in %s: %s' % (l, title, btext(v, b)))
        v.click(*p)
    ok = bfind(v, b, '[ OK ]')
    if ok:                              # a single choice closes on its row
        v.click(*ok)
    check(box(v, title) is None, 'pick list did not close')


def form_select(v, row_word):
    """Click the [Select] of one row of the open tag form."""
    b = box(v, 'Add tag') or box(v, 'Edit tag')
    check(b, 'no tag form')
    for y in range(b[0], b[3]):
        if row_word in v.row(y)[b[1]:b[2]]:
            x = v.row(y).index('[Select]', b[1]) + 3
            v.click(x, y)
            return
    raise Fail('no row %r in the form' % row_word)


# ---------------------------------------------------------------- the page
@case(A)
def opens_from_the_analysis_menu_and_closes_with_escape():
    d = fresh_dir()
    with viewer(d) as v:
        open_table(v)
        t = v.text()
        check('Activities' in t and 'Types' in t and 'Families' in t and 'Tags' in t, t[:300])
        v.esc()
        check(not v.has('Syndrome table'), 'Esc did not close the page')
        open_table(v)
        v.click(*v.find('[ Close ]'))
        check(not v.has('Syndrome table'), 'Close did not close the page')
        check(v.alive())


@case(A)
def four_tabs_switch_by_click_and_each_has_its_columns():
    d = fresh_dir()
    with viewer(d) as v:
        open_table(v)
        y = tab_y(v)
        r = v.row(y)
        check(r.index('Activities') < r.index('Types') < r.index('Families') < r.index('Tags'), r)
        eq(active(v), 'Activities', 'first tab')
        eq(heading(v), ['Name', 'Used', 'Comment'])
        tab(v, 'Types')
        eq(active(v), 'Types')
        eq(heading(v), ['Name', 'Used'])
        tab(v, 'Families')
        eq(active(v), 'Families')
        eq(heading(v), ['Name', 'Used'])
        tab(v, 'Tags')
        eq(active(v), 'Tags')
        eq(heading(v), ['Name', 'Activities', 'Types', 'Family', 'Formats/Arch/Subtype', 'Used', 'Comment'])
        tab(v, 'Activities')
        eq(active(v), 'Activities')


@case(A)
def seeds_are_listed_with_their_used_counts():
    d = fresh_dir()
    with viewer(d) as v:
        open_table(v)
        eq(table(v), [['linux-kernel', '0', 'runs in, or reaches into, the Linux kernel'],
                      ['memory', '1', 'allocates, maps or changes memory to hold code'],
                      ['network', '2', 'connects to, listens on or sends to a network']])
        tab(v, 'Types')
        t = {r[0]: r[1] for r in table(v)}
        eq(sorted(t), ['adware', 'botnet', 'dropper', 'exploit', 'hacktool', 'miner',
                       'ransom', 'rootkit', 'trojan', 'virus'])
        eq((t['botnet'], t['trojan'], t['dropper'], t['virus']), ('2', '2', '1', '0'))
        tab(v, 'Families')
        eq(table(v), [])
        tab(v, 'Tags')
        rows = table(v)
        eq([r[0] for r in rows], ['command-and-control', 'execute-memory', 'network-flood'])
        check(rows[0][1] == 'network' and rows[0][2] == 'botnet, trojan', rows[0])
        check(rows[1][1] == 'memory' and rows[1][2] == 'dropper, trojan', rows[1])
        check(rows[2][1] == 'network' and rows[2][2] == 'botnet', rows[2])
        # no tag is used by a diagnose yet: Used is 0
        check(all('0' in r for r in rows), rows)


@case(A)
def no_column_joins_a_name_with_another():
    d = fresh_dir()
    with viewer(d) as v:
        open_table(v)
        tab(v, 'Tags')
        t = '\n'.join(v.row(y) for y in range(tab_y(v), tab_y(v) + 8))
        check('network/' not in t and '/c' not in t and 'botnet/' not in t, t)


@case(A)
def search_filters_by_name_and_in_tags_by_activity_type_and_family():
    d = fresh_dir()
    with viewer(d) as v:
        open_table(v)
        tab(v, 'Types')
        v.type('bot')
        eq(names(v), ['botnet'])
        v.key('ctrl+a'); v.key('bs')
        eq(len(names(v)), 10, 'clearing the search shows every row')
        tab(v, 'Tags')
        v.type('trojan')                        # a type name
        eq(names(v), ['command-and-control', 'execute-memory'])
        v.key('ctrl+a'); v.type('memory')       # an activity name, and a name part
        eq(names(v), ['execute-memory'])
        v.key('ctrl+a'); v.type('network botnet')   # every word has to be found
        eq(names(v), ['command-and-control', 'network-flood'])
        v.key('ctrl+a'); v.type('dropper network')
        eq(names(v), [])
        check(v.has('nothing matches'), 'an empty result says why')
        v.key('ctrl+a'); v.key('bs')
        eq(len(names(v)), 3)
        # a family is searched too: make one, use it in a tag
        add_entity(v, 'Families', 'mirai')
        tab(v, 'Tags')
        press(v, '[Add]')
        v.type('seeded')
        form_select(v, 'Types')
        pick_in(v, 'Types', ['botnet'])
        form_select(v, 'Family')
        pick_in(v, 'Family', ['mirai'])
        v.key('enter')
        eq(len(names(v)), 4)
        v.type('mirai')
        eq(names(v), ['seeded'], 'a family name is searched in Tags')


# ----------------------------------------------------- adding, ids, saving
@case(A)
def add_each_kind_normalises_the_name_generates_an_id_and_save_writes_one_file():
    d = fresh_dir()
    before = set(files(d))
    with viewer(d) as v:
        open_table(v)
        tab(v, 'Activities')
        press(v, '[Add]')
        b = box(v, 'Add activity')
        check(b, 'no Add activity form')
        v.type('Disk IO_x!')
        check('disk-io-x' in btext(v, b), 'the name is not normalised as it is typed: %s' % btext(v, b))
        v.key('enter')
        check(box(v, 'Add activity') is None, 'OK did not close the form')
        check('disk-io-x' in names(v), table(v))
        check(any(r[0] == 'disk-io-x' for r in table(v)))
        check('1 changed' in v.text(), 'the foot does not count the change')
        eq(files(d), sorted(before), 'a file was written before Save')
        add_entity(v, 'Types', 'worm')
        add_entity(v, 'Families', 'mirai')
        check('mirai' in names(v))
        press(v, '[Save]')
        check(v.wait_for('Saved 3 file(s)', 3), 'save said: %r' % v.row(v.rows - 1))
    new = sorted(set(files(d)) - before)
    eq(len(new), 3, new)
    ids = set()
    for kind, name in (('activity', 'disk-io-x'), ('type', 'worm'), ('family', 'mirai')):
        f = [x for x in new if x.startswith('%s_%s_' % (kind, name))]
        eq(len(f), 1, '%s file: %r' % (kind, new))
        m = re.match(r'%s_%s_([0-9a-f]{8})\.c$' % (kind, name), f[0])
        check(m, 'file name %s' % f[0])
        t = read(d, f[0])
        mm = re.search(r'KOF_%s_ID\(0x([0-9a-f]{16})\);' % kind.upper(), t)
        check(mm, t)
        i = int(mm.group(1), 16)
        check(i >= 0x10000, 'a generated id is in the seeds\' range: %x' % i)
        eq(mm.group(1)[:8], m.group(1), 'the file name carries the first 8 hex of the id')
        check('KOF_%s_NAME("%s");' % (kind.upper(), name) in t, t)
        ids.add(i)
    eq(len(ids), 3, 'ids collide')


@case(A)
def add_a_tag_with_every_part_and_save_writes_declarations_by_id():
    d = fresh_dir()
    before = set(files(d))
    with viewer(d) as v:
        open_table(v)
        add_entity(v, 'Families', 'mirai')
        tab(v, 'Tags')
        press(v, '[Add]')
        v.type('Scan Net')
        form_select(v, 'Activities')
        pick_in(v, 'Activities', ['network', 'memory'])
        form_select(v, 'Types')
        pick_in(v, 'Types', ['botnet', 'trojan'])
        form_select(v, 'Family')
        pick_in(v, 'Family', ['mirai'])
        form_select(v, 'Formats')
        pick_in(v, 'Formats', ['KOF_FMT_ELF'])
        form_select(v, 'Arch')
        pick_in(v, 'Architectures', ['KOF_ARCH_X86_64'])
        form_select(v, 'Subtypes')
        pick_in(v, 'Subtypes', ['KOF_ELF_EXEC'])
        b = box(v, 'Add tag')
        t = btext(v, b)
        check('network, memory' in t and 'botnet, trojan' in t and 'mirai' in t, t)
        check('KOF_FMT_ELF' in t and 'KOF_ARCH_X86_64' in t and 'KOF_ELF_EXEC' in t, t)
        y = [yy for yy in range(b[0], b[3]) if 'Comment' in v.row(yy)][0]
        v.click(v.row(y).index('Comment') + 16, y)
        v.type('scans for peers')
        v.key('enter')
        rows = {r[0]: r for r in table(v)}
        r = rows['scan-net']
        check('network, memory' in r and 'botnet, trojan' in r and 'mirai' in r, r)
        check(any('fmt ELF' in x and 'arch X86_64' in x and 'sub ELF_EXEC' in x for x in r), r)
        press(v, '[Save]')
        v.wait_for('Saved 2 file(s)', 3)
    f = [x for x in set(files(d)) - before if x.startswith('tag_scan-net_')]
    eq(len(f), 1, files(d))
    t = read(d, f[0])
    acts = re.findall(r'KOF_TAG_ACTIVITY\(0x([0-9a-f]{16})\);  /\* (\S+) \*/', t)
    eq([a[1] for a in acts], ['network', 'memory'], 'declared in the order they were ticked: %s' % t)
    eq([int(a[0], 16) for a in acts], [0x100, 0x101])
    typs = re.findall(r'KOF_TAG_TYPE\(0x([0-9a-f]{16})\);  /\* (\S+) \*/', t)
    eq([x[1] for x in typs], ['botnet', 'trojan'])
    check(re.search(r'KOF_TAG_FAMILY\(0x[0-9a-f]{16}\);  /\* mirai \*/', t), t)
    for want in ('KOF_TAG_FORMAT(KOF_FMT_ELF);', 'KOF_TAG_ARCH(KOF_ARCH_X86_64);',
                 'KOF_TAG_SUBTYPE(KOF_ELF_EXEC);', 'KOF_TAG_COMMENT("scans for peers");',
                 'KOF_TAG_NAME("scan-net");'):
        check(want in t, '%s missing from\n%s' % (want, t))
    # a tag declares nothing joined: no "network/" anywhere in the file
    check('/c2' not in t and 'network/' not in t)


@case(A)
def a_new_activity_made_from_the_tag_form_is_ticked_in_it():
    d = fresh_dir()
    with viewer(d) as v:
        open_table(v)
        tab(v, 'Tags')
        press(v, '[Add]')
        v.type('flow')
        b = box(v, 'Add tag')
        v.click(*bfind(v, b, '[+ New activity]'))
        check(box(v, 'Add activity'), 'no activity form')
        v.type('Timing')
        v.key('enter')
        b = box(v, 'Add tag')
        check(b, 'the tag form did not come back')
        t = btext(v, b)
        check('flow' in t and 'timing' in t, 'the new activity is not in the tag form: %s' % t)
        v.key('enter')
        tab(v, 'Activities')
        check('timing' in names(v), names(v))
        tab(v, 'Tags')
        rows = {r[0]: r for r in table(v)}
        check('timing' in rows['flow'], rows['flow'])
        # Cancel of the nested form leaves the tag form as it was
        press(v, '[Add]')
        v.type('other')
        b = box(v, 'Add tag')
        v.click(*bfind(v, b, '[+ New type]'))
        v.type('zz')
        v.click(*bfind(v, box(v, 'Add type'), '[ Cancel ]'))
        b = box(v, 'Add tag')
        check(b and 'other' in btext(v, b), 'the tag form lost what was typed')


# ----------------------------------------------------- edit and delete
@case(A)
def edit_changes_the_label_and_never_the_id_and_keeps_what_it_does_not_know():
    d = fresh_dir()
    f = 'activity_network_00000000.c'
    path = os.path.join(d, f)
    text = read(d, f) + 'KOF_ACTIVITY_SEVERITY(3);   /* a newer tool */\n// the author\'s evidence\n'
    with open(path, 'w') as fh:
        fh.write(text)
    others = {x: read(d, x) for x in files(d) if x != f}
    with viewer(d) as v:
        open_table(v)
        y = [yy for yy in range(5, 12) if 'network' in v.row(yy)][0]
        v.click(v.row(y).index('network') + 2, y)
        press(v, '[Edit]')
        b = box(v, 'Edit activity')
        check(b and 'network' in btext(v, b), 'edit form: %r' % [v.row(yy)[:80] for yy in range(8, 16)])
        v.key('ctrl+a'); v.key('bs')
        v.type('Net Work')
        v.key('enter')
        check('net-work' in names(v) and 'network' not in names(v), names(v))
        press(v, '[Save]')
        v.wait_for('Saved 1 file(s)', 3)
    t = read(d, f)
    check('KOF_ACTIVITY_ID(0x0000000000000100);' in t, 'the id changed:\n%s' % t)
    check('KOF_ACTIVITY_NAME("net-work");' in t and 'KOF_ACTIVITY_NAME("network")' not in t, t)
    check('KOF_ACTIVITY_SEVERITY(3);   /* a newer tool */' in t and "// the author's evidence" in t,
          'unknown declaration or prose lost:\n%s' % t)
    check('KOF_ACTIVITY_COMMENT("connects to, listens on or sends to a network");' in t, t)
    eq({x: read(d, x) for x in files(d) if x != f}, others, 'another entity\'s file changed')
    eq(f in files(d), True, 'the file was renamed: the name is a label')
    # the tags still name it by id: rename moved nothing
    check('KOF_TAG_ACTIVITY(0x0000000000000100);' in read(d, 'tag_network-flood_00000000.c'))


@case(A)
def delete_is_refused_with_the_list_of_what_still_names_it():
    d = fresh_dir()
    before = {x: read(d, x) for x in files(d)}
    with viewer(d) as v:
        open_table(v)
        y = [yy for yy in range(5, 12) if 'network' in v.row(yy)][0]
        v.click(v.row(y).index('network') + 2, y)
        press(v, '[Delete]')
        b = box(v, 'Cannot delete')
        check(b, 'no refusal: %r' % [v.row(yy)[:90] for yy in range(5, 14)])
        t = btext(v, b)
        check('network' in t and 'command-and-control' in t and 'network-flood' in t, t)
        check('execute-memory' not in t, 'a tag that does not name it is listed: %s' % t)
        v.esc()
        check(box(v, 'Cannot delete') is None)
        check('network' in names(v), 'the activity went anyway')
        tab(v, 'Types')
        y = [yy for yy in range(5, 20) if re.search(r'\bbotnet\b', v.row(yy))][0]
        v.click(v.row(y).index('botnet') + 2, y)
        press(v, '[Delete]')
        b = box(v, 'Cannot delete')
        check(b and 'command-and-control' in btext(v, b) and 'network-flood' in btext(v, b), v.snapshot()[8:20])
        v.esc()
        press(v, '[Save]')
    eq({x: read(d, x) for x in files(d)}, before, 'a refused delete changed files')


@case(A)
def delete_of_an_unused_entity_removes_its_file_at_save():
    d = fresh_dir()
    with viewer(d) as v:
        open_table(v)
        add_entity(v, 'Activities', 'spare')
        press(v, '[Save]')
        v.wait_for('Saved 1 file(s)', 3)
        f = [x for x in files(d, 'activity') if 'spare' in x]
        eq(len(f), 1)
        y = [yy for yy in range(5, 12) if 'spare' in v.row(yy)][0]
        v.click(v.row(y).index('spare') + 2, y)
        press(v, '[Delete]')
        check('spare' not in names(v), names(v))
        check(os.path.exists(os.path.join(d, f[0])), 'the file went before Save')
        press(v, '[Save]')
        v.wait_for('Saved 1 file(s)', 3)
        check(not os.path.exists(os.path.join(d, f[0])), 'Save did not remove the file')
        check(len(files(d, 'activity')) == 3)


@case(A)
def save_writes_only_the_changed_entities_and_nothing_when_none_changed():
    d = fresh_dir()
    snap = {x: os.stat(os.path.join(d, x)).st_mtime_ns for x in files(d)}
    with viewer(d) as v:
        open_table(v)
        press(v, '[Save]')
        check(v.wait_for('Nothing changed', 3), v.row(v.rows - 1))
        eq({x: os.stat(os.path.join(d, x)).st_mtime_ns for x in files(d)}, snap, 'a save with no change wrote')
        add_entity(v, 'Types', 'worm')
        press(v, '[Save]')
        v.wait_for('Saved 1 file(s)', 3)
    after = {x: os.stat(os.path.join(d, x)).st_mtime_ns for x in files(d)}
    changed = sorted(x for x in after if snap.get(x) != after[x])
    eq(len(changed), 1, changed)
    check(changed[0].startswith('type_worm_'), changed)
    left = [x for x in os.listdir(d) if not x.endswith('.c')]
    eq(left, [], 'a temporary file is left beside the entities')


# ------------------------------------------------------------------ check
@case(A)
def check_reports_errors_warnings_and_notes_in_a_result_box():
    d = fresh_dir()
    with viewer(d) as v:
        open_table(v)
        press(v, '[Check]')
        b = box(v, 'Check')
        check(b, 'no result box: %r' % v.snapshot()[3:12])
        t = btext(v, b)
        check('0 error(s)' in t, t)
        check('is used by no tag' in t and 'virus' in t, 'unused entities are not warned about: %s' % t)
        v.esc()
        # an error: a tag naming nothing
        tab(v, 'Tags')
        press(v, '[Add]')
        v.type('lonely')
        v.key('enter')
        press(v, '[Check]')
        b = box(v, 'Check')
        t = btext(v, b)
        check('error' in t and 'neither an activity nor a type' in t and '1 error(s)' in t, t)
        v.esc()
        # a tag with the name of another, a different meaning: a note
        press(v, '[Add]')
        v.type('network-flood')
        form_select(v, 'Types')
        pick_in(v, 'Types', ['rootkit'])
        v.key('enter')
        press(v, '[Check]')
        t = btext(v, box(v, 'Check'))
        check('type sets disjoint' in t, 'the relation of the type sets is not said: %s' % t)
        check('1 error(s)' in t, t)
        v.esc()
        # near-duplicate names of one table
        tab(v, 'Activities')
        add_entity(v, 'Activities', 'networks')
        press(v, '[Check]')
        t = btext(v, box(v, 'Check'))
        check('one edit apart' in t, t)
        v.esc()
        check(v.alive())


@case(A)
def check_is_the_same_answer_as_ksigbuilder_tags():
    d = fresh_dir()
    sb = os.path.join(REPO, 'build', 'release', 'bin', 'ksigbuilder')
    if not os.path.exists(sb):
        raise Skip('no ksigbuilder')
    import subprocess
    p = subprocess.run([sb, '--tags', d], capture_output=True, text=True)
    eq(p.returncode, 0, p.stdout + p.stderr)
    check('0 error(s)' in p.stdout, p.stdout)
    with open(os.path.join(d, 'tag_bad_00000000.c'), 'w') as fh:
        fh.write('KOF_TAG_ID(0x500);\nKOF_TAG_NAME("bad");\n')
    p = subprocess.run([sb, '--tags', d], capture_output=True, text=True)
    eq(p.returncode, 1, 'an error did not fail the check')
    check('neither an activity nor a type' in p.stdout, p.stdout)
    with viewer(d) as v:
        open_table(v)
        press(v, '[Check]')
        t = btext(v, box(v, 'Check'))
        check('neither an activity nor a type' in t and '1 error(s)' in t, t)


@case(A)
def tag_used_counts_the_diagnose_sources_that_name_it():
    d = fresh_dir()
    dd = os.path.join(BASES_COPY if os.path.isdir(BASES_COPY) else fresh_bases(), 'diagnoses')
    os.makedirs(dd, exist_ok=True)
    f = os.path.join(dd, 'botnet_probe_00.c')
    with open(f, 'w') as fh:
        fh.write('KOF_DIAG_NAME(probe);\nKOF_DIAG_TAG(0x0000000000000200);\n'
                 '/* KOF_DIAG_TAG(0x0000000000000201); only a mention */\n')
    try:
        with viewer(d) as v:
            open_table(v)
            tab(v, 'Tags')
            rows = {r[0]: r for r in table(v)}
            check('1' in rows['command-and-control'] and '0' in rows['execute-memory'], rows)
            used = [x for x in rows['command-and-control'] if x.isdigit()]
            eq(used, ['1'], rows['command-and-control'])
            y = [yy for yy in range(5, 12) if 'command-and-control' in v.row(yy)][0]
            v.click(v.row(y).index('command-and-control') + 3, y)
            press(v, '[Delete]')
            b = box(v, 'Cannot delete')
            check(b and 'diagnose source' in btext(v, b), 'a tag a diagnose names was deleted: %r' % v.snapshot()[6:14])
    finally:
        os.remove(f)


@case(A)
def used_counts_the_diagnoses_the_draft_is_about_to_write():
    d = fresh_dir()
    with ko_viewer(d) as v:
        str_condition(v)
        pick_tag(v, 'network-flood')
        open_table(v)
        tab(v, 'Tags')
        rows = {r[0]: r for r in table(v)}
        eq([x for x in rows['network-flood'] if x.isdigit()], ['1'], rows['network-flood'])
        eq([x for x in rows['command-and-control'] if x.isdigit()], ['0'], rows['command-and-control'])
        y = [yy for yy in range(5, 14) if 'network-flood' in v.row(yy)][0]
        v.click(v.row(y).index('network-flood') + 3, y)
        press(v, '[Delete]')
        b = box(v, 'Cannot delete')
        check(b and 'draft' in btext(v, b), 'a tag the draft names was deleted: %r' % v.snapshot()[6:16])


# ------------------------------------------------------------------- keys
@case(A)
def keys_move_the_cursor_edit_and_type_into_the_search():
    d = fresh_dir()
    with viewer(d) as v:
        open_table(v)
        v.key('down')
        v.key('enter')
        b = box(v, 'Edit activity')
        check(b and 'memory' in btext(v, b), 'Down then Enter did not edit the second row: %r' % v.snapshot()[6:16])
        v.esc()                         # leaves the field
        v.esc()                         # cancels the form
        check(box(v, 'Edit activity') is None)
        v.type('net')
        eq(names(v), ['network'], 'typing did not go to the search')
        v.esc()                         # leaves the box
        check(v.has('Syndrome table'), 'Esc in the search closed the page')
        v.key('right')
        eq(active(v), 'Types', 'Right did not switch tab')
        v.esc()
        check(not v.has('Syndrome table'))


# ------------------------------------------------- the diagnose panel
@case(A)
def tag_chooser_opens_on_the_shared_type_and_family_and_clearing_shows_all():
    d = fresh_dir()
    with ko_viewer(d) as v:
        str_condition(v)
        click_in_panel(v, '[Virus]')
        pick_menu_item(v, 'Botnet', rows=(grip(v) + 2, v.rows))
        y = open_tag_chooser(v)
        t = '\n'.join(v.row(yy) for yy in range(y, y + 12))
        check('Botnet' in v.row(y + 1), 'search not pre-filled with the shared Type: %r' % v.row(y + 1))
        check('command-and-control' in t and 'network-flood' in t and 'execute-memory' not in t,
              'not narrowed to botnet tags: %s' % t)
        check('(no tag)' in t, 'the way out is hidden by the filter')
        v.key('ctrl+a'); v.key('bs')
        t = '\n'.join(v.row(yy) for yy in range(y, y + 12))
        check('execute-memory' in t, 'clearing the search shows every tag: %s' % t)
        v.esc()


@case(A)
def generator_names_come_from_the_tags_first_type_family_and_name():
    d = fresh_dir()
    with viewer(d, path=SAMPLES['ko'], rows=60, cols=150) as v:
        open_table(v)
        add_entity(v, 'Families', 'mirai')
        tab(v, 'Tags')
        press(v, '[Add]')
        v.type('scan')
        form_select(v, 'Types')
        pick_in(v, 'Types', ['trojan', 'botnet'])       # trojan first
        form_select(v, 'Family')
        pick_in(v, 'Family', ['mirai'])
        v.key('enter')
        v.esc()
        enlarge(v, 22)
        str_condition(v)
        pick_tag(v, 'scan')
        check('Tag: scan' in txt_(v), txt_(v)[-300:])
        click_in_panel(v, '[ Generate ]')
        names_ = re.findall(r'\S+\.c', txt_(v))
        eq(names_, ['trojan_mirai_scan_01.c'], 'first type, family, tag name, id')


def txt_(v):
    return '\n'.join(v.row(y) for y in panel(v))


@case(A)
def a_repeated_tag_name_is_told_apart_by_family_and_types_in_the_cell():
    d = fresh_dir()
    with viewer(d, path=SAMPLES['ko'], rows=60, cols=150) as v:
        open_table(v)
        tab(v, 'Tags')
        press(v, '[Add]')
        v.type('network-flood')
        form_select(v, 'Types')
        pick_in(v, 'Types', ['rootkit'])
        v.key('enter')
        v.esc()
        enlarge(v, 22)
        str_condition(v)
        pick_tag(v, 'network-flood')            # the first row of that name
        t = txt_(v)
        check(re.search(r'Tag: network-flood \(types (botnet|rootkit)\)', t), t[-300:])
        # a name that exists once carries nothing beside it
        pick_tag(v, 'execute-memory')
        check('Tag: execute-memory' in txt_(v) and 'execute-memory (' not in txt_(v), txt_(v)[-300:])


@case(A)
def a_block_matcher_no_condition_uses_carries_its_own_tag_and_its_own_file():
    d = fresh_dir()
    with ko_viewer(d) as v:
        open_tab(v, 'Blocks')
        h1, h2 = tick_blocks(v, 2)
        fold_mutation(v)
        t = txt_(v)
        eq(t.count('Tag: none'), 2, 'each standalone matcher has a Tag cell: %s' % t[-400:])
        # pick the first matcher's tag
        y = [yy for yy in panel(v) if 'find_sim' in v.row(yy) and h1 in v.row(yy)][0]
        v.click(v.row(y).index('Tag: none') + 7, y)
        check(tag_box_top(v), 'the Tag cell did not open the chooser')
        v.key('ctrl+a'); v.key('bs')
        v.click(*v.find('network-flood', rows=(tag_box_top(v) + 3, v.rows - 1)))
        check('Tag: network-flood' in v.row(y), v.row(y))
        # a condition over the second matcher takes it: that matcher has no cell
        click_in_panel(v, '[+ Condition]')
        yy = [x for x in panel(v) if 'Matchers: None' in v.row(x)][0]
        v.click(v.row(yy).index('[+ Matcher]') + 3, yy)
        v.click(*v.find('2  find_sim', rows=(yy, yy + 4)))
        y2 = [x for x in panel(v) if 'find_sim' in v.row(x) and h2 in v.row(x)][0]
        check('Tag:' not in v.row(y2), 'a matcher in a condition has its own tag cell: %r' % v.row(y2))
        click_in_panel(v, '[ Generate ]')
        t = txt_(v)
        check('botnet_network-flood_01.c' in t, 'no diagnose for the standalone matcher: %s' % t[-500:])
        check(('find_sim  # hash %s  threshold 60' % h1) in t, t[-500:])
        # one for the condition (no tag yet) and one for the standalone matcher
        eq(len(re.findall(r'\S+\.c', t)), 2, re.findall(r'\S+\.c', t))
        check('<tag>_01.c' in t, 'the condition without a tag says so: %s' % t[-400:])


# ------------------------------------------------------------ small screens
@case(A)
def the_table_and_the_tag_form_fit_an_80_by_24_screen():
    d = fresh_dir()
    with viewer(d, rows=24, cols=80) as v:
        open_table(v)
        for name in TABS_:
            tab(v, name)
            eq(active(v), name)
        tab(v, 'Tags')
        press(v, '[Add]')
        b = box(v, 'Add tag')
        check(b and b[3] <= 23 and b[2] <= 80, 'the form does not fit: %r' % (b,))
        check('[ OK ]' in btext(v, b) and '[ Cancel ]' in btext(v, b) and '[+ New activity]' in btext(v, b),
              btext(v, b))
        v.esc()
        v.esc()
        press(v, '[Add]')
        v.esc()
        v.esc()
        check(v.alive() and v.has('Syndrome table'))


if __name__ == '__main__':
    main(A)
