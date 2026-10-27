"""Manage > Pathogens: a list of families with the variants of each under it (indented), no heading row, an [ Add variant ]
line per family, and a bottom row: [ Add family ] at the left, [ Save ] and [ Discard ] at the right (greyed while the catalog equals what was loaded or last saved).
A variant is its type set, lettered by the library (<family>_A, _B, ...), never typed. Add family = a name field, the first variant's name, a Comment field and the tick grid of
malware types; Add variant = a read-only line with the new variant's name, a Comment field and the same grid. A third column holds the
variant's comment; a click on its text (or on the first 12 columns of an empty one) turns that cell into a text field in place (Enter
commits, Esc cancels, a press outside commits); a click right of the text opens nothing. All small dialogs and
the main one are dragged by the top border. OK, Cancel and a [x] in the frame, one common width. The types of a variant are ticked in a menu opened from its types cell. The catalog is the engine's
(verdictor/famcat); Save writes one lower-case file per family into the pathogens directory (--pathogens, else <bases>/pathogens), the dialog loads
that directory when it first opens, Discard goes back to what was loaded or last saved. Every case here gets a directory of its own."""
from tui import *

A = 'families'
TYPES = ('Virus', 'Trojan', 'Rootkit', 'Botnet', 'Ransom', 'Miner', 'Adware', 'Exploit', 'Dropper', 'Hacktool')


_PD = [0]


def fresh_pdir():
    """A pathogens directory of this case's own, not created yet (Save creates it); removed with the process's work directory."""
    _PD[0] += 1
    d = os.path.join(VT, 'work', 'p%d' % os.getpid(), 'pathogens_%d' % _PD[0])
    os.makedirs(os.path.dirname(d), exist_ok=True)
    return d


def pfiles(pd):
    return sorted(os.listdir(pd)) if os.path.isdir(pd) else []


def pread(pd, name):
    with open(os.path.join(pd, name)) as f:
        return f.read()


def pwrite(pd, name, text):
    os.makedirs(pd, exist_ok=True)
    with open(os.path.join(pd, name), 'w') as f:
        f.write(text)


def opened(rows=40, cols=120, pdir=None, bases=True):
    """The dialog open. pdir: a path (--pathogens), None = a fresh directory of this case, 'default' = no --pathogens (<bases>/pathogens)."""
    if pdir is None:
        pdir = fresh_pdir()
    v = Viewer(SAMPLES['ko'], rows=rows, cols=cols, bases=bases,
               extra=() if pdir in ('default', 'none') else ('--pathogens', pdir))
    v.pdir = pdir
    check(v.menu_item('Manage', 'Pathogens'), 'no Pathogens item')
    v.pump_quiet()
    check(v.has('[ Add family ]'), 'the dialog did not open: %r' % v.row(3))
    return v


def press(v, text, nth=0, dx=0):
    p = v.find(text, nth=nth)
    check(p, 'no %r on screen' % text)
    v.click(p[0] + dx, p[1])
    v.pump_quiet()


def tick(v, name):
    """Press the tick-grid cell of a type, ticked or not (a type word may also be in the table behind the dialog)."""
    p = v.find('[ ] ' + name) or v.find('[x] ' + name)
    check(p, 'no tick cell for %s' % name)
    v.click(p[0] + 1, p[1])
    v.pump_quiet()


def add_family(v, name, *ticks):
    press(v, '[ Add family ]', dx=2)
    check(v.has('[ OK ]') and v.has('Name'), 'the Add family dialog did not open')
    v.type(name)
    for t in ticks:
        tick(v, t)
    press(v, '[ OK ]')


def body(v):
    """The dialog's body rows between its walls, blanks dropped. The box is as big as its content, so it is located, not assumed."""
    d = v.dialog()
    check(d, 'no dialog on screen')
    x0, y0, x1, y1, _ = d
    out = []
    for y in range(y0 + 1, y1):
        t = v.row(y)[x0:x1 - 1].rstrip()
        if t.strip():
            out.append(t)
    return out


def click_field(v, label):
    """Press inside the text field of the small dialog's row `label` (the bracket is drawn after the 8-column label)."""
    y = next((y for y in range(1, v.rows + 1) if label + ' ' in v.row(y) and '[' in v.row(y)), None)
    check(y, 'no %s field row' % label)
    r = v.row(y)
    v.click(r.index(label) + 1 + 8 + 3, y)
    v.pump_quiet()


def norm(rows):
    return [' '.join(r.split()) for r in rows]


def frame_width(v, title):
    """Columns of the small dialog's frame: from the corner before its title to the closing corner on that row."""
    for y in range(1, v.rows + 1):
        r = v.row(y)
        i = r.find('╭─ ' + title)
        if i >= 0:
            return r.index('╮', i) - i + 1
    raise Fail('no %r frame' % title)


@case(A)
def opens_empty_with_no_heading_row_and_the_three_buttons_on_one_row():
    with opened() as v:
        eq(norm(body(v)), ['[ Add family ] [ Save ] [ Discard ]'], 'an empty catalog shows only the buttons: %r' % body(v))
        a, s, d = (v.find(t) for t in ('[ Add family ]', '[ Save ]', '[ Discard ]'))
        check(a[1] == s[1] == d[1] and a[0] < s[0] < d[0], 'Add family left, Save and Discard right, one row: %r' % ((a, s, d),))
        check(v.has('0 families'), 'no count')
        add_family(v, 'Mirai', 'Botnet')
        b = body(v)
        check(b[0].strip() == 'Mirai', 'the first body row is not the family (a heading?): %r' % b)
        for w in ('Name', 'Variant', 'Types', 'Family'):
            check(w not in ' '.join(b), 'heading word %r in the table: %r' % (w, b))


def greyed(v, t):
    x, y = v.find(t)
    c = v.cell(x + 2, y)
    return (c.fg, c.bg) == ('brightblack', 'white')


def bottom_rule(v):
    """The dialog's bottom rule: where a refusal or the count is said."""
    x0, y0, x1, y1, _ = v.dialog()
    return v.row(y1)[x0 - 1:x1]


@case(A)
def save_and_discard_are_greyed_while_clean_and_enabled_while_the_catalog_differs():
    with opened() as v:
        check(greyed(v, '[ Save ]') and greyed(v, '[ Discard ]'), 'a clean catalog must show Save and Discard greyed')
        x, y = v.find('[ Add family ]')
        check(v.cell(x + 2, y).bg != 'white', 'Add family is drawn greyed')
        before = v.fingerprint()
        for t in ('[ Save ]', '[ Discard ]'):
            press(v, t, dx=2)
            check(v.fingerprint() == before, '%s changed the screen while greyed' % t)
        check(pfiles(v.pdir) == [], 'a greyed Save wrote something')
        add_family(v, 'Mirai', 'Botnet')
        check(not greyed(v, '[ Save ]') and not greyed(v, '[ Discard ]'), 'a changed catalog must enable Save and Discard')
        press(v, '[ Discard ]', dx=2)
        eq(norm(body(v)), ['[ Add family ] [ Save ] [ Discard ]'], 'Discard did not restore the empty catalog: %r' % body(v))
        check(v.has('0 families') and greyed(v, '[ Save ]') and greyed(v, '[ Discard ]'), 'after Discard the buttons are not greyed again')
        check(pfiles(v.pdir) == [], 'Discard touched the directory')


@case(A)
def save_writes_one_lower_case_file_per_family_and_a_new_viewer_loads_it():
    pd = fresh_pdir()
    head = '// Generated by Manage > Pathogens; edit by hand with care.\n'
    with opened(pdir=pd) as v:
        press(v, '[ Add family ]', dx=2)
        v.type('Mirai')
        click_field(v, 'Comment')
        v.type('first seen 2016')
        tick(v, 'Rootkit')
        tick(v, 'Botnet')
        press(v, '[ OK ]')
        press(v, '[ Add variant ]')
        tick(v, 'Ransom')
        press(v, '[ OK ]')
        add_family(v, 'Gafgyt', 'Trojan')
        press(v, '[ Save ]', dx=2)
        check(greyed(v, '[ Save ]') and greyed(v, '[ Discard ]'), 'after Save the catalog is the snapshot: Save and Discard grey')
        eq(pfiles(pd), ['gafgyt.c', 'mirai.c'], 'one lower-case file per family')
        eq(pread(pd, 'mirai.c'), head + 'KOF_MALWARE_FAMILY_NAME("Mirai");\nKOF_MALWARE_NEXT_VARIANT("C");\n// first seen 2016\n'
           'KOF_MALWARE_VARIANT("A", KOF_MALTYPE_ROOTKIT, KOF_MALTYPE_BOTNET);\nKOF_MALWARE_VARIANT("B", KOF_MALTYPE_RANSOM);\n')
        eq(pread(pd, 'gafgyt.c'), head + 'KOF_MALWARE_FAMILY_NAME("Gafgyt");\nKOF_MALWARE_NEXT_VARIANT("B");\nKOF_MALWARE_VARIANT("A", KOF_MALTYPE_TROJAN);\n')
        # delete the last variant of Mirai: the counter stays at C, the line is gone; delete a family: its file goes at the next Save
        press(v, 'Mirai_B')
        press(v, '[ Delete ]')
        press(v, 'Gafgyt')
        press(v, '[ Delete ]')
        check(not greyed(v, '[ Save ]'), 'deleting must enable Save')
        press(v, '[ Save ]', dx=2)
        eq(pfiles(pd), ['mirai.c'], 'the deleted family kept its file')
        eq(pread(pd, 'mirai.c'), head + 'KOF_MALWARE_FAMILY_NAME("Mirai");\nKOF_MALWARE_NEXT_VARIANT("C");\n// first seen 2016\n'
           'KOF_MALWARE_VARIANT("A", KOF_MALTYPE_ROOTKIT, KOF_MALTYPE_BOTNET);\n')
    with opened(pdir=pd) as v:                       # a new viewer on the same directory
        eq(norm(body(v))[:3], ['Mirai', 'Mirai_A Rootkit, Botnet first seen 2016', '[ Add variant ]'], 'the saved state was not loaded: %r' % body(v))
        check(v.has('1 family') and greyed(v, '[ Save ]') and greyed(v, '[ Discard ]'), 'a loaded catalog is clean')
        press(v, '[ Add variant ]')
        check(v.has('Mirai_C'), 'the counter did not survive the deleted last variant: %r' % v.snapshot()[8:22])
        press(v, '[ Cancel ]')
        add_family(v, 'Zed', 'Virus')
        press(v, '[ Discard ]', dx=2)
        check(not v.has('Zed') and v.has('1 family') and greyed(v, '[ Save ]'), 'Discard did not go back to the loaded state')
        eq(pfiles(pd), ['mirai.c'], 'Discard touched the directory')


@case(A)
def a_file_that_does_not_load_is_named_in_one_line_and_save_never_touches_it():
    pd = fresh_pdir()
    pwrite(pd, 'broken.c', 'this is not a pathogen file\nKOF_MALWARE_VARIANT("A", KOF_MALTYPE_BOTNET);\n')
    pwrite(pd, 'okfam.c', 'KOF_MALWARE_FAMILY_NAME("Okfam");\nKOF_MALWARE_VARIANT("A", KOF_MALTYPE_TROJAN);\nsomething odd\n')
    with opened(pdir=pd) as v:
        check('Okfam_A Trojan' in norm(body(v)), 'the good file was not loaded: %r' % body(v))
        rule = bottom_rule(v)
        check('not loaded: broken.c' in rule and '1 line ignored' in rule, 'the bad file and the ignored line are not on one line: %r' % rule)
        check(greyed(v, '[ Save ]'), 'a load is clean')
        press(v, '[ Add variant ]')
        tick(v, 'Ransom')
        press(v, '[ OK ]')
        press(v, '[ Save ]', dx=2)
        eq(pfiles(pd), ['broken.c', 'okfam.c'])
        check('this is not a pathogen file' in pread(pd, 'broken.c'), 'Save rewrote a file that did not load')
        check('KOF_MALTYPE_RANSOM' in pread(pd, 'okfam.c'), 'Save did not write the new variant')
        # a family that would take the name of the file that did not load is refused, nothing is touched
        add_family(v, 'Broken', 'Virus')
        press(v, '[ Save ]', dx=2)
        rule = bottom_rule(v)
        check('not loaded' in rule and 'broken.c' in rule, 'the collision is not said: %r' % rule)
        check(not greyed(v, '[ Save ]'), 'a refused Save must leave the catalog dirty')
        check('this is not a pathogen file' in pread(pd, 'broken.c') and pfiles(pd) == ['broken.c', 'okfam.c'], 'a refused Save changed the directory')


@case(A)
def save_without_a_directory_says_so_and_keeps_the_catalog_dirty():
    with opened(pdir='none', bases=False) as v:
        add_family(v, 'Mirai', 'Botnet')
        press(v, '[ Save ]', dx=2)
        check('no pathogens directory' in bottom_rule(v), 'no refusal line: %r' % bottom_rule(v))
        check(not greyed(v, '[ Save ]') and not greyed(v, '[ Discard ]'), 'a refused Save must leave Save and Discard enabled')
        eq(norm(body(v))[:2], ['Mirai', 'Mirai_A Botnet'], 'a refused Save changed the catalog')


@case(A)
def the_default_directory_is_pathogens_under_bases():
    # the bases copy is made from the real bases/, which may already hold the owner's own saved pathogens: start from none
    pd = bases_dir() + '/pathogens'
    shutil.rmtree(pd, ignore_errors=True)
    with opened(pdir='default') as v:
        add_family(v, 'Mirai', 'Botnet')
        press(v, '[ Save ]', dx=2)
        check(greyed(v, '[ Save ]'), 'Save refused: %r' % bottom_rule(v))
        eq(pfiles(pd), ['mirai.c'], 'the file is not under <bases>/pathogens')
        shutil.rmtree(pd, ignore_errors=True)


@case(A)
def add_family_ticks_types_and_creates_the_lettered_first_variant():
    with opened() as v:
        press(v, '[ Add family ]', dx=2)
        for t in TYPES:
            check(v.has('[ ] ' + t), 'no tick for %s' % t)
        check(not v.has('Packer') and not v.has('cnc'), 'Packer or a tag is offered as a type')
        check(v.has('Variant -'), 'no placeholder for the first variant while the name is empty')
        v.type('Mirai')
        check(v.has('Variant Mirai_A'), 'the first variant\'s name does not follow the typing')
        rows = [y for y in range(3, v.rows) if 'Name    [' in v.row(y)]
        check(rows and 'Variant' in v.row(rows[0] + 1) and 'Virus' not in v.row(rows[0] + 1), 'line 2 is not the variant name line')
        press(v, '[ OK ]')
        check(v.has('[ OK ]') and v.has('Select at least one Malware type'), 'no type ticked must be refused, dialog open')
        tick(v, 'Trojan')
        tick(v, 'Botnet')
        check(v.has('[x] Trojan') and v.has('[x] Botnet'), 'the ticks did not show')
        tick(v, 'Trojan')
        check(v.has('[ ] Trojan'), 'a second press did not untick')
        tick(v, 'Trojan')
        press(v, '[ OK ]')
        check(not v.has('[ OK ]'), 'the dialog stayed open after OK')
        b = norm(body(v))
        eq(b[:3], ['Mirai', 'Mirai_A Trojan, Botnet', '[ Add variant ]'], 'rows: %r' % b)
        ind = lambda r: len(r) - len(r.lstrip())
        rb = body(v)
        check(ind(rb[1]) > ind(rb[0]) and ind(rb[2]) == ind(rb[1]), 'variants are not indented under the family: %r' % rb)
        check('Trojan' not in rb[0] and 'Botnet' not in rb[0], 'the family row carries a type list')
        add_family(v, 'Gafgyt', 'Virus')
        eq([r for r in norm(body(v)) if not r.startswith('[ Add')][:4], ['Mirai', 'Mirai_A Trojan, Botnet', 'Gafgyt', 'Gafgyt_A Virus'])
        check(v.has('2 families'), 'count after two families')


@case(A)
def add_variant_shows_the_new_name_read_only_and_the_same_grid():
    with opened() as v:
        add_family(v, 'Mirai', 'Botnet')
        press(v, '[ Add variant ]')
        check(v.has('Variant') and v.has('Mirai_B') and v.has('[ OK ]'), 'the Add variant dialog did not open')
        r = [x for x in v.lines if 'Variant' in x and 'Mirai_B' in x]
        check(r and '[' not in r[0].split('Variant', 1)[1].split('│')[0], 'the name is drawn as an input field: %r' % r)
        v.type('zzz')
        check(not any('Variant' in r and 'zzz' in r for r in v.lines), 'typing changed a read-only line')
        check(any('Comment [' in r and 'zzz' in r for r in v.lines), 'typing did not go to the Comment field')
        for t in TYPES:
            check(v.has('[ ] ' + t), 'no tick for %s' % t)
        check(not v.has('Packer'), 'Packer is offered as a type')
        press(v, '[ OK ]')
        check(v.has('Select at least one Malware type') and v.has('Mirai_B'), 'no type: refused, dialog open')
        tick(v, 'Botnet')
        press(v, '[ OK ]')
        check(v.has('same types as another variant'), 'the same set as Mirai_A must be refused: %r' % v.snapshot()[8:22])
        tick(v, 'Botnet')
        tick(v, 'Ransom')
        press(v, '[ OK ]')
        check(not v.has('[ OK ]'), 'the dialog stayed open after OK')
        b = norm(body(v))
        eq(b[:4], ['Mirai', 'Mirai_A Botnet', 'Mirai_B Ransom zzz', '[ Add variant ]'], 'rows: %r' % b)
        press(v, '[ Add variant ]')
        check(v.has('Mirai_C'), 'the next name is not Mirai_C')


@case(A)
def both_small_dialogs_have_one_size_that_fits_any_screen():
    ws = {}
    for rows, cols in ((40, 120), (24, 80)):
        with opened(rows, cols) as v:
            press(v, '[ Add family ]', dx=2)
            ws['f', cols] = frame_width(v, 'Add family')
            press(v, '[ Cancel ]')
            add_family(v, 'Mirai', 'Botnet')
            press(v, '[ Add variant ]')
            ws['v', cols] = frame_width(v, 'Add variant')
            check(v.has('[ OK ]') and v.has('[ Cancel ]') and v.has('Hacktool'), 'the dialog is cut at %dx%d' % (cols, rows))
            press(v, '[ Cancel ]')
    eq(ws['f', 120], ws['v', 120], 'the two dialogs differ in width: %r' % ws)
    check(52 <= ws['f', 120] <= 56, 'the dialog is not about 54 columns wide (the comment field): %r' % ws)
    eq(ws['f', 80], ws['f', 120], 'the size changed with the screen')


@case(A)
def types_cell_of_a_variant_opens_a_tick_menu_that_keeps_one_type():
    with opened() as v:
        add_family(v, 'Mirai', 'Botnet')
        press(v, 'Botnet')
        for t in ('Virus', 'Trojan', 'Hacktool'):
            check(v.has('[ ] ' + t), 'the menu has no %s' % t)
        check(v.has('[x] Botnet') and not v.has('[ ] Packer'), 'the menu does not show the variant\'s type / has Packer')
        press(v, '[ ] Virus')
        check(v.has('[x] Virus'), 'the tick did not show in the menu (it stays open)')
        press(v, '[x] Botnet')
        check(v.has('[ ] Botnet'), 'untick Botnet')
        press(v, '[x] Virus')
        # the refusal sits on the bottom rule, and the open menu covers the right of it: its first words are what shows
        check(v.has('[x] Virus') and v.has('Select at least one'), 'the last type was unticked, or the refusal is not said')
        v.esc()
        check(not v.has('[ ] Trojan'), 'Esc did not put the menu away')
        check('Mirai_A Virus' in norm(body(v)), 'the row does not show the ticked type: %r' % body(v))
        press(v, 'Mirai', dx=30)
        check(not v.has('[ ] Trojan'), 'a family row opened a type menu')


@case(A)
def cancel_close_box_and_esc_discard():
    with opened() as v:
        press(v, '[ Add family ]', dx=2)
        v.type('Zed')
        tick(v, 'Botnet')
        press(v, '[ Cancel ]')
        check(not v.has('[ OK ]') and v.has('[ Add family ]'), 'Cancel did not close only the small dialog')
        check(not v.has('Zed'), 'Cancel kept the family')
        press(v, '[ Add family ]', dx=2)
        check(v.has('[ ] Botnet'), 'the ticks survived a Cancel')
        v.type('Zed')
        p = v.find('[x]')
        check(p, 'no [x] in the dialog frame')
        v.click(p[0] + 1, p[1])
        v.pump_quiet()
        check(not v.has('[ OK ]') and not v.has('Zed'), 'the [x] did not discard')
        press(v, '[ Add family ]', dx=2)
        v.type('Zed')
        v.esc()
        check(not v.has('[ OK ]') and not v.has('Zed') and v.has('[ Add family ]'), 'Esc did not cancel')
        add_family(v, 'Mirai', 'Botnet')
        press(v, '[ Add variant ]')
        tick(v, 'Miner')
        press(v, '[ Cancel ]')
        eq(len(body(v)), 4, 'a cancelled variant left a row: %r' % body(v))
        v.esc()
        check(not v.has('Pathogens'), 'Esc did not close the main dialog')


@case(A)
def duplicate_family_and_bad_names_show_one_error_line_and_keep_the_dialog():
    with opened() as v:
        add_family(v, 'Mirai', 'Botnet')
        press(v, '[ Add family ]', dx=2)
        v.type('Mirai')
        tick(v, 'Botnet')
        press(v, '[ OK ]')
        check(v.has('[ OK ]') and v.has('a family of that name exists'), 'duplicate family: %r' % v.snapshot()[8:20])
        v.esc()
        press(v, '[ Add family ]', dx=2)
        tick(v, 'Botnet')
        press(v, '[ OK ]')
        check(v.has('the name is empty'), 'empty name')
        v.type('a b')
        check(not v.has('a b'), 'a space was typed into a name')
        v.type('.*/')
        fld = [r for r in v.lines if 'Name    [' in r][0].split('Name    [', 1)[1].split(']')[0]
        check(not any(ch in fld for ch in './*'), 'a character outside the engine\'s name rule was typed: %r' % fld)
        v.type('x' * 70)
        press(v, '[ OK ]')
        check(v.has('name is over 63'), 'a long name: %r' % v.snapshot()[8:20])
        v.esc()
        press(v, '[ Add family ]', dx=2)
        v.type('y' * 61)
        tick(v, 'Botnet')
        press(v, '[ OK ]')
        check(v.has('[ OK ]') and v.has('family name too long') or v.has('family name over 60'), 'a 61-character family must be refused: %r' % v.snapshot()[8:20])


def drag_title(v, dx, dy, grab=6):
    """Drag the dialog by its top border `grab` columns after its left corner; returns its new (x0, y0)."""
    d = v.dialog()
    check(d, 'no dialog to drag')
    v.drag(d[0] + grab, d[1], d[0] + grab + dx, d[1] + dy)
    n = v.dialog()
    check(n, 'the dialog vanished after the drag')
    return d, n


@case(A)
def comment_field_sits_under_the_variant_row_and_above_the_types_title():
    with opened() as v:
        press(v, '[ Add family ]', dx=2)
        ys = {k: next((y for y in range(1, v.rows + 1) if k in v.row(y)), None) for k in ('Name    [', 'Variant', 'Comment [', 'Malware types')}
        check(all(ys.values()), 'a row is missing: %r' % ys)
        eq((ys['Variant'], ys['Comment ['], ys['Malware types']), (ys['Name    [' ] + 1, ys['Name    ['] + 2, ys['Name    ['] + 3), 'row order: %r' % ys)
        v.type('Mirai')
        click_field(v, 'Comment')
        v.type('first seen 2016')
        check(v.has('first seen 2016'), 'the comment was not typed')
        v.type('a*b/c')
        fld = [r for r in v.lines if 'Comment [' in r][0].split('Comment [', 1)[1].split(']')[0]
        check('*' not in fld and '/' not in fld and 'abc' in fld, 'the engine comment rule is not the typing filter: %r' % fld)
        tick(v, 'Botnet')
        press(v, '[ OK ]')
        b = norm(body(v))
        eq(b[0], 'Mirai', 'a family row has no comment: %r' % b)
        eq(b[1], 'Mirai_A Botnet first seen 2016abc', 'the comment of Add family is the first variant\'s: %r' % b)
        press(v, '[ Add variant ]')
        v.type('second')
        tick(v, 'Ransom')
        press(v, '[ OK ]')
        check(norm(body(v))[2] == 'Mirai_B Ransom second', 'the variant row has not its own comment: %r' % body(v))
        check(norm(body(v))[1] == 'Mirai_A Botnet first seen 2016abc', 'the first variant lost its comment: %r' % body(v))


@case(A)
def comment_longer_than_120_is_refused_and_the_dialog_stays():
    with opened() as v:
        press(v, '[ Add family ]', dx=2)
        v.type('Mirai')
        click_field(v, 'Comment')
        v.type('c' * 121)
        tick(v, 'Botnet')
        press(v, '[ OK ]')
        check(v.has('[ OK ]') and v.has('comment is over 120'), 'a 121-character comment must be refused: %r' % v.snapshot()[8:22])


@case(A)
def comment_column_is_dim_third_and_scrolls_sideways():
    with opened(rows=40, cols=60) as v:
        press(v, '[ Add family ]', dx=2)
        v.type('Mirai')
        click_field(v, 'Comment')
        v.type('abcdefghij' * 8)
        tick(v, 'Botnet')
        press(v, '[ OK ]')
        x, y = v.find('Mirai_A')
        check(v.has('abcdef'), 'the comment is not in the third column')
        cx = v.row(y).find('abcdef') + 1
        before = v.row(y)
        v.hwheel(cx, y, n=3)
        check(v.row(y) != before, 'the shifted wheel did not scroll the table sideways')


def col_of(v, y, word):
    """Screen column (1-based) of the first character of `word` on row y."""
    i = v.row(y).find(word)
    check(i >= 0, 'no %r on row %d: %r' % (word, y, v.row(y)))
    return i + 1


def comment_x(v, y, types):
    """First column of the comment column on row y: after the types text (every types text here is 6 characters, the widest), the 4 gap columns and the column gap."""
    return col_of(v, y, types) + 6 + 4 + 1


def two_variants(v):
    add_family(v, 'Mirai', 'Botnet')
    press(v, '[ Add variant ]')
    tick(v, 'Ransom')
    press(v, '[ OK ]')
    ya, yb, yf = v.find('Mirai_A')[1], v.find('Mirai_B')[1], v.find('Mirai')[1]
    return ya, yb, yf, comment_x(v, ya, 'Botnet'), comment_x(v, yb, 'Ransom')


def no_dialog(v):
    return not v.has('Edit variant') and not v.has('Edit family') and not v.has('[ OK ]')


@case(A)
def comment_cell_becomes_a_text_field_in_place_enter_commits_esc_cancels():
    with opened() as v:
        ya, yb, yf, cxa, cxb = two_variants(v)
        v.click(cxa + 3, ya)                         # an empty comment cell is hit over its first 12 columns
        v.pump_quiet()
        check(no_dialog(v), 'the comment cell opened a dialog: %r' % v.snapshot()[8:24])
        v.type('hello')
        eq(norm(body(v))[1], 'Mirai_A Botnet hello', 'the field is not in the cell: %r' % body(v))
        check(v.cell(cxa, ya).reverse, 'the cell is not drawn as a field (the dialogs\' field style)')
        v.key('enter')
        v.pump_quiet()
        check(no_dialog(v) and not v.cell(cxa, ya).reverse, 'Enter did not close the field')
        eq(norm(body(v))[1], 'Mirai_A Botnet hello', 'Enter did not commit: %r' % body(v))
        # the field starts from the current comment (caret at its end) and Esc puts it back as it was
        v.click(cxa + 1, ya)
        v.pump_quiet()
        v.type(' more')
        eq(norm(body(v))[1], 'Mirai_A Botnet hello more', 'the field did not start from the comment: %r' % body(v))
        v.esc()
        eq(norm(body(v))[1], 'Mirai_A Botnet hello', 'Esc did not cancel: %r' % body(v))
        check(v.has('Pathogens'), 'Esc with a field open closed the dialog')
        # a character the engine refuses is not typed
        v.click(cxb + 1, yb)
        v.pump_quiet()
        v.type('a*b/c')
        eq(norm(body(v))[2], 'Mirai_B Ransom abc', 'the engine comment rule is not the typing filter: %r' % body(v))
        # a press outside commits, and what it hit is then handled as usual (here: nothing, the margin of the dialog)
        d = v.dialog()
        v.click(d[0] + 1, ya)
        v.pump_quiet()
        eq(norm(body(v))[2], 'Mirai_B Ransom abc', 'a press outside did not commit: %r' % body(v))
        check(not v.cell(cxb, yb).reverse, 'the field stayed open after a press outside')
        # only one edit at a time: pressing another comment cell commits the first and opens the second
        v.click(cxa + 1, ya)
        v.pump_quiet()
        v.type('!')
        v.click(cxb + 1, yb)
        v.pump_quiet()
        v.type('?')
        eq(norm(body(v))[1:3], ['Mirai_A Botnet hello!', 'Mirai_B Ransom abc?'], 'two fields open or the first was lost: %r' % body(v))
        check(v.cell(cxb, yb).reverse and not v.cell(cxa, ya).reverse, 'more than one field is open')
        v.esc()
        # a click in the open field is a caret, not a press outside: typing goes in at the caret
        v.click(cxb + 1, yb)
        v.pump_quiet()
        v.click(cxb + 1, yb)
        v.pump_quiet()
        v.type('X')
        check(v.cell(cxb, yb).reverse and 'Mirai_B Ransom aXbc' in norm(body(v))[2], 'a click inside the field did not place the caret: %r' % body(v))
        v.key('enter')
        v.pump_quiet()
        eq(norm(body(v))[1:3], ['Mirai_A Botnet hello!', 'Mirai_B Ransom aXbc'], 'Enter: %r' % body(v))
        check(not greyed(v, '[ Save ]'), 'a committed comment did not make the catalog dirty')


@case(A)
def comment_cell_refused_comment_is_one_line_on_the_bottom_rule_and_the_field_stays_open():
    with opened() as v:
        ya, yb, yf, cxa, cxb = two_variants(v)
        v.click(cxa + 1, ya)
        v.pump_quiet()
        v.type('c' * 130)
        v.key('enter')
        v.pump_quiet()
        check('comment is over 120' in bottom_rule(v), 'the error is not on the bottom rule: %r' % bottom_rule(v))
        check(v.cell(cxa, ya).reverse and no_dialog(v), 'the field did not stay open')
        # a press outside is refused the same way and keeps the field
        d = v.dialog()
        v.click(d[0] + 1, yb)
        v.pump_quiet()
        check(v.cell(cxa, ya).reverse and 'comment is over 120' in bottom_rule(v), 'a refused press outside closed the field')
        v.key('bs', n=20)
        v.key('enter')
        v.pump_quiet()
        check(not v.cell(cxa, ya).reverse and 'comment is over' not in bottom_rule(v), 'the corrected comment was not committed: %r' % bottom_rule(v))
        check('Mirai_A Botnet ' + 'c' * 5 in norm(body(v))[1], 'the cell does not show the committed comment: %r' % body(v))
        # Esc drops the refused text (the box grew with the long comment: its columns are found again)
        ya, yb = v.find('Mirai_A')[1], v.find('Mirai_B')[1]
        cxb = comment_x(v, yb, 'Ransom')
        v.click(cxb + 1, yb)
        v.pump_quiet()
        v.type('c' * 130)
        v.key('enter')
        v.pump_quiet()
        v.esc()
        eq(norm(body(v))[2], 'Mirai_B Ransom', 'a refused comment changed the catalog: %r' % body(v))


@case(A)
def a_click_opens_a_cell_only_over_the_extent_of_its_text():
    with opened() as v:
        ya, yb, yf, cxa, cxb = two_variants(v)
        v.click(cxa + 1, ya)
        v.pump_quiet()
        v.type('abc')
        v.key('enter')
        v.pump_quiet()
        tx, nx = col_of(v, ya, 'Botnet'), col_of(v, ya, 'Mirai_A')
        quiet = v.fingerprint()

        def nothing(x, y, what):
            v.click(x, y)
            v.pump_quiet()
            check(v.fingerprint() == quiet, '%s opened something' % what)

        nothing(cxa + 3 + 4, ya, 'a press right of the short comment text')
        nothing(v.dialog()[2] - 3, ya, 'a press at the right end of the comment column')
        nothing(cxa - 1, ya, 'the gap before the comment')
        nothing(tx + 6, ya, 'the padding after the types text')
        nothing(nx - 1, ya, 'the indent before a variant name')
        nothing(nx + 7, ya, 'the gap after a variant name')
        nothing(v.find('Mirai')[0] + 20, yf, 'a family row right of its name')
        nothing(cxa + 10, yf, 'a family row\'s comment area')
        # the last character of the text and the first one hit
        v.click(cxa + 2, ya)
        v.pump_quiet()
        v.type('Z')
        eq(norm(body(v))[1], 'Mirai_A Botnet abcZ', 'the last character of the comment text did not hit: %r' % body(v))
        v.esc()
        # an empty comment cell hits over 12 columns and no further
        nothing(cxb + 12, yb, 'the 13th column of an empty comment cell')
        v.click(cxb + 11, yb)
        v.pump_quiet()
        v.type('q')
        eq(norm(body(v))[2], 'Mirai_B Ransom q', 'the 12th column of an empty comment cell did not hit: %r' % body(v))
        v.esc()
        # the name cells and the types cell still answer over their text
        v.click(nx + 6, ya)
        v.pump_quiet()
        check(v.has('Edit variant'), 'the last character of the variant name did not open Edit variant')
        press(v, '[ Cancel ]')
        v.click(tx + 5, ya)
        v.pump_quiet()
        check(v.has('[ ] Virus'), 'the last character of the types text did not open the tick menu')
        v.esc()
        v.click(v.find('Mirai')[0] - 2, yf)
        v.pump_quiet()
        check(v.has('Edit family'), 'the first character of the family name did not open Edit family')
        press(v, '[ Cancel ]')
        # scrolled sideways, the visible part of a long comment hits
    with opened(rows=40, cols=60) as v:
        ya, yb, yf, cxa, cxb = two_variants(v)
        v.click(cxa + 1, ya)
        v.pump_quiet()
        v.type('abcdefghij' * 8)
        v.key('enter')
        v.pump_quiet()
        v.hwheel(cxa + 1, ya, n=2)
        i = v.row(ya).find('abcdef')
        check(i >= 0, 'the comment is not visible after the pan: %r' % v.row(ya))
        v.click(i + 3, ya)
        v.pump_quiet()
        v.type('Z')
        check(no_dialog(v) and v.has('Z'), 'a press on the visible part of a panned comment did not open the field: %r' % v.row(ya))


def under_box_is_pane(v, pane, box, what):
    """Every cell outside `box` (x0, y0, x1, y1) and between the bar and the status row shows what the panes showed before any dialog."""
    x0, y0, x1, y1 = box
    bad = []
    for y in range(2, v.rows):
        r, p = v.row(y), pane[y - 1]
        for x in range(1, v.cols + 1):
            if x0 <= x <= x1 and y0 <= y <= y1:
                continue
            if r[x - 1:x] != p[x - 1:x]:
                bad.append((x, y, r[x - 1:x], p[x - 1:x]))
    check(not bad, '%s: %d cells under the old box are not the panes\' (first: %r)' % (what, len(bad), bad[:3]))


@case(A)
def no_ghost_of_the_dialog_when_it_grows_shrinks_moves_or_a_small_dialog_closes():
    with opened(rows=40, cols=120) as v:
        v.esc()                                      # the panes alone, to compare against
        pane = list(v.lines)
        check(v.menu_item('Manage', 'Pathogens'), 'reopen')
        v.pump_quiet()
        box = lambda: v.dialog()[:4]
        under_box_is_pane(v, pane, box(), 'the first frame')
        for n in range(6):                           # the box grows with every family
            add_family(v, 'Fam%d' % n, 'Botnet')
            under_box_is_pane(v, pane, box(), 'after adding family %d' % n)
        # a small dialog taller than the box under it, opened and closed
        press(v, '[ Add family ]', dx=2)
        press(v, '[ Cancel ]')
        under_box_is_pane(v, pane, box(), 'after a small dialog closed')
        press(v, 'Fam5_A')
        press(v, '[ Cancel ]')
        under_box_is_pane(v, pane, box(), 'after Edit variant closed')
        press(v, 'Botnet')                           # the tick menu over the table, then away
        v.esc()
        under_box_is_pane(v, pane, box(), 'after the tick menu closed')
        # drag: what the box leaves is the panes again
        d0 = box()
        v.drag(d0[0] + 6, d0[1], d0[0] + 6 + 25, d0[1] + 5)
        under_box_is_pane(v, pane, box(), 'after a drag')
        v.drag(box()[0] + 6, box()[1], 3, 3)
        under_box_is_pane(v, pane, box(), 'after a drag to the corner')
        # the box shrinks: delete every family
        for n in range(6):
            p = v.find('Fam%d' % n)
            check(p, 'no Fam%d row' % n)
            v.click(p[0], p[1])
            v.pump_quiet()
            press(v, '[ Delete ]')
            under_box_is_pane(v, pane, box(), 'after deleting family %d' % n)


@case(A)
def edit_variant_changes_types_and_comment_together_and_a_refusal_changes_nothing():
    with opened() as v:
        add_family(v, 'Mirai', 'Botnet')
        press(v, '[ Add variant ]')
        tick(v, 'Ransom')
        press(v, '[ OK ]')
        press(v, 'Mirai_B')                          # the name cell
        check(v.has('Edit variant') and v.has('[x] Ransom'), 'a variant name cell did not open Edit variant')
        tick(v, 'Botnet')                            # now the same set as Mirai_A
        tick(v, 'Ransom')
        v.type('x')
        press(v, '[ OK ]')
        check(v.has('Edit variant') and v.has('same types as another variant'), 'the same set must be refused: %r' % v.snapshot()[8:24])
        v.esc()
        eq(norm(body(v))[2], 'Mirai_B Ransom', 'a refused edit changed the variant')
        press(v, 'Mirai_B')
        tick(v, 'Ransom')
        tick(v, 'Virus')
        v.type('note')
        press(v, '[ OK ]')
        eq(norm(body(v))[2], 'Mirai_B Virus note', 'types and comment were not both stored: %r' % body(v))


@case(A)
def edit_family_has_only_the_name_row_renames_and_its_variants_follow():
    with opened() as v:
        add_family(v, 'Mirai', 'Botnet')
        add_family(v, 'Gafgyt', 'Virus')
        y = v.find('Mirai')[1]
        v.click(v.find('Mirai')[0], y)
        v.pump_quiet()
        check(v.has('Edit family') and v.has('Name    [Mirai') and v.has('[ Delete ]') and v.has('[ OK ]') and v.has('[ Cancel ]'), 'no Edit family: %r' % v.snapshot()[8:24])
        check(not v.has('Comment [') and not v.has('Malware types') and not any('Variant' in r and 'Mirai_A' in r for r in v.lines), 'Edit family has more than the name row')
        v.key('bs', n=5)
        v.type('Zed')
        press(v, '[ Cancel ]')
        eq(norm(body(v))[:2], ['Mirai', 'Mirai_A Botnet'], 'Cancel changed the name')
        v.click(v.find('Mirai')[0], v.find('Mirai')[1])
        v.pump_quiet()
        v.key('bs', n=5)
        v.type('Zed')
        press(v, '[ OK ]')
        eq(norm(body(v))[:2], ['Zed', 'Zed_A Botnet'], 'the variants did not follow the rename: %r' % body(v))
        # a case-only duplicate of another family is refused, in the dialog
        v.click(v.find('Gafgyt')[0], v.find('Gafgyt')[1])
        v.pump_quiet()
        v.key('bs', n=6)
        v.type('zED')
        press(v, '[ OK ]')
        check(v.has('Edit family') and v.has('a family of that name exists'), 'a case-only duplicate must be refused: %r' % v.snapshot()[8:24])
        v.esc()
        check('Gafgyt_A Virus' in norm(body(v)), 'a refused rename changed the family')
        # the same family renamed to another letter case is its own name, fine
        v.click(v.find('Zed')[0], v.find('Zed')[1])
        v.pump_quiet()
        v.key('bs', n=3)
        v.type('ZED')
        press(v, '[ OK ]')
        check('ZED_A Botnet' in norm(body(v)), 'a case change of the own name was refused: %r' % body(v))


@case(A)
def delete_removes_a_variant_or_a_family_at_once_and_a_family_may_stay_empty():
    with opened() as v:
        add_family(v, 'Mirai', 'Botnet')
        press(v, '[ Add variant ]')
        tick(v, 'Ransom')
        press(v, '[ OK ]')
        add_family(v, 'Gafgyt', 'Virus')
        press(v, 'Mirai_B')
        press(v, '[ Delete ]')
        check(not v.has('Mirai_B') and not v.has('Edit variant'), 'Delete did not remove the variant at once')
        eq([r for r in norm(body(v)) if not r.startswith('[ Add family')][:5], ['Mirai', 'Mirai_A Botnet', '[ Add variant ]', 'Gafgyt', 'Gafgyt_A Virus'])
        press(v, 'Mirai_A')
        press(v, '[ Delete ]')
        check(norm(body(v))[:2] == ['Mirai', '[ Add variant ]'], 'a family with no variant must stay with its Add variant row: %r' % body(v))
        v.click(v.find('Mirai')[0], v.find('Mirai')[1])
        v.pump_quiet()
        press(v, '[ Delete ]')
        check(not v.has('Mirai') and 'Gafgyt_A Virus' in norm(body(v)) and v.has('1 family'), 'Delete did not remove the family: %r' % body(v))


@case(A)
def a_deleted_variant_name_is_not_reused_unless_the_tick_asks_for_it():
    with opened() as v:
        add_family(v, 'Mirai', 'Botnet')
        for t in ('Ransom', 'Miner'):
            press(v, '[ Add variant ]')
            tick(v, t)
            press(v, '[ OK ]')
        # no deleted name yet: the reuse tick is drawn greyed and does nothing
        press(v, '[ Add variant ]')
        check(v.has('Variant Mirai_D') and v.has('[ ] Reuse a deleted name'), 'no reuse tick in Add variant: %r' % v.snapshot()[8:26])
        x, y = v.find('Reuse a deleted name')
        c = v.cell(x, y)
        eq((c.fg, c.bg), ('brightblack', 'white'), 'the reuse tick is not greyed with no free letter: %r' % ((c.fg, c.bg),))
        v.click(x, y)
        v.pump_quiet()
        check(v.has('[ ] Reuse a deleted name') and v.has('Variant Mirai_D'), 'a greyed tick changed something')
        press(v, '[ Cancel ]')
        # delete Mirai_B: the default name goes on with D, the tick takes B
        press(v, 'Mirai_B')
        press(v, '[ Delete ]')
        press(v, '[ Add variant ]')
        check(v.has('Variant Mirai_D'), 'the default reused a deleted name: %r' % v.snapshot()[8:26])
        x, y = v.find('Reuse a deleted name')
        c = v.cell(x, y)
        check((c.fg, c.bg) != ('brightblack', 'white'), 'the reuse tick is greyed although a name is free')
        v.click(x, y)
        v.pump_quiet()
        check(v.has('[x] Reuse a deleted name') and v.has('Variant Mirai_B'), 'the name line does not follow the tick: %r' % v.snapshot()[8:26])
        tick(v, 'Virus')
        press(v, '[ OK ]')
        check('Mirai_B Virus' in norm(body(v)), 'the variant did not take the deleted name: %r' % body(v))
        # deleting the LAST letter does not lower the counter
        press(v, 'Mirai_C')
        press(v, '[ Delete ]')
        press(v, '[ Add variant ]')
        check(v.has('Variant Mirai_D'), 'the counter went down after deleting the last variant: %r' % v.snapshot()[8:26])
        press(v, '[ Cancel ]')
        # Add family and the edit modes have no such tick
        press(v, '[ Add family ]', dx=2)
        check(not v.has('Reuse a deleted name'), 'Add family has the reuse tick')
        press(v, '[ Cancel ]')
        press(v, 'Mirai_A')
        check(not v.has('Reuse a deleted name'), 'Edit variant has the reuse tick')


@case(A)
def add_family_and_add_variant_draw_the_same_rows_except_the_first():
    with opened() as v:
        press(v, '[ Add family ]', dx=2)
        fam = [r.rstrip() for r in body(v)]
        press(v, '[ Cancel ]')
        add_family(v, 'Mirai', 'Botnet')
        press(v, '[ Add variant ]')
        var = [r.rstrip() for r in body(v)]
        var = [r for r in var if 'Reuse a deleted name' not in r]     # Add variant's one extra tick row (under the Variant row)
        i = next(k for k, r in enumerate(fam) if 'Comment' in r)
        j = next(k for k, r in enumerate(var) if 'Comment' in r)
        eq(fam[i:], var[j:], 'the rows from the Comment row down differ')
        check('Name' in fam[0] and 'Variant' in var[0] and '[' not in var[0].split('Variant', 1)[1], 'the first rows are not Name field / read-only variant line')


@case(A)
def main_dialog_is_dragged_by_the_top_border_and_stays_on_screen():
    with opened() as v:
        add_family(v, 'Mirai', 'Botnet')
        d0, d1 = drag_title(v, -12, 6, grab=6)
        eq((d1[0], d1[1]), (d0[0] - 12, d0[1] + 6), 'the box did not follow the pointer: %r -> %r' % (d0[:2], d1[:2]))
        # what is inside follows: a button at the new place works
        press(v, '[ Add family ]', dx=2)
        check(v.has('[ OK ]'), 'the button at the dragged place did not work')
        press(v, '[ Cancel ]')


@case(A)
def main_dialog_drag_is_clamped_to_the_screen_and_resets_on_open():
    with opened() as v:
        d0 = v.dialog()
        v.drag(d0[0] + 6, d0[1], v.cols, v.rows)
        d = v.dialog()
        check(d and d[2] <= v.cols and d[3] <= v.rows and d[1] >= 2, 'the box left the screen: %r' % (d,))
        check(d[0] > d0[0] and d[1] > d0[1], 'the box did not move: %r -> %r' % (d0[:2], d[:2]))
        v.drag(d[0] + 6, d[1], 1, 1)
        d = v.dialog()
        check(d and d[0] >= 1 and d[1] >= 2, 'clamped at the top left: %r' % (d,))
        v.esc()
        check(v.menu_item('Manage', 'Pathogens'), 'reopen')
        v.pump_quiet()
        eq(v.dialog()[:2], d0[:2], 'the dialog did not reopen centred')


@case(A)
def small_dialog_is_dragged_by_its_title_row_with_the_same_grab_as_find():
    with opened() as v:
        press(v, '[ Add family ]', dx=2)
        d0, d1 = drag_title(v, 10, 3, grab=4)
        eq((d1[0], d1[1]), (d0[0] + 10, d0[1] + 3), 'the small dialog did not follow the pointer')
        v.type('Zed')
        check(v.has('Zed'), 'the field does not work at the new place')
        tick(v, 'Botnet')
        press(v, '[ OK ]')
        check('Zed' in v.text() and not v.has('[ OK ]'), 'OK at the new place did not add')
        # [x] on the title row is a button, not a handle
        press(v, '[ Add variant ]')
        p = v.find('[x]')
        d = v.dialog()
        v.drag(p[0], p[1], p[0] - 5, p[1] + 2)
        check(not v.has('[ OK ]') or v.dialog()[:2] == d[:2], 'the [x] was dragged')


if __name__ == '__main__':
    main(A)
