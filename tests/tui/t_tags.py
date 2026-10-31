"""Manage > Syndromes: a list of syndromes (tags), one row each, no heading row: name | activities | objects (the engine's words,
comma-joined), and a bottom row [ Add Syndrome ] at the left, [ Save ] and [ Discard ] at the right (greyed while the catalog equals what was loaded
or last saved). Save writes one file per distinct pair of sets, `<objects>_<activities>.c`, into the syndromes directory (--syndromes, else
<bases>/syndromes; every case here gets a directory of its own), each tag with a random id the engine made once; the dialog loads that directory
when it first opens and Discard goes back to what was loaded or last saved. A tag is
a NAME, a SET of Activities (at least one) and a SET of Objects (may be empty). Add and Edit are ONE small form: Name field, the title
`Activities` and the tick grid of the 9 activities (2 columns), the title `Objects` and the tick grid of the 8 objects; OK and Cancel at the
left, a red Delete alone at the right in Edit, a [x] in the frame. A click on the name opens Edit; a click on the activities or objects
text (or the first 12 columns of an empty objects cell) opens the 2-column tick menu of that list. A name is letters of either case, digits and '-' (a duplicate is refused, letter case ignored); a Comment row sits under the Name row and a Comment column ends the table (a `// ` line above the tag in its file). The dialog uses the shared dialog code of Manage > Pathogens, so its frame, drag and keys are the same (no hotkeys)."""
from tui import *
from t_families import press, tick, norm, body, no_dialog, drag_title, greyed, bottom_rule, pfiles, pread, pwrite

A = 'tags'
# The words as the dialog SHOWS them (an independent oracle: the engine stores them lower case and shows the first letter capitalised, C2 whole).
ACTS = ('Scan', 'Steal', 'Execution', 'Persistence', 'Escalation', 'Evasion', 'Hidden', 'C2', 'Destruction')
OBJS = ('Network', 'File', 'Memory', 'Process', 'Registry', 'Kernel', 'System', 'Input')
SHOW = {w.lower(): w for w in ACTS + OBJS}


_SD = [0]


def fresh_sdir():
    """A syndromes directory of this case's own, not created yet (Save creates it); removed with the process's work directory."""
    _SD[0] += 1
    d = os.path.join(VT, 'work', 'p%d' % os.getpid(), 'syndromes_%d' % _SD[0])
    os.makedirs(os.path.dirname(d), exist_ok=True)
    return d


def opened(rows=40, cols=120, sdir=None):
    if sdir is None:
        sdir = fresh_sdir()
    v = Viewer(SAMPLES['ko'], rows=rows, cols=cols, bases=True, extra=('--syndromes', sdir))
    v.sdir = sdir
    check(v.menu_item('Manage', 'Syndromes'), 'no Syndromes item')
    v.pump_quiet()
    check(v.has('[ Add Syndrome ]'), 'the dialog did not open: %r' % v.row(3))
    return v


def add_tag(v, name, acts=(), objs=()):
    press(v, '[ Add Syndrome ]', dx=2)
    check(v.has('[ OK ]') and v.has('Activities'), 'the Add form did not open')
    v.type(name)
    for t in acts + objs:
        tick(v, SHOW[t])
    press(v, '[ OK ]')


def cell_x(v, y, word):
    """Screen column of `word` on row y INSIDE the dialog (the panes behind it have text of their own)."""
    return v.row(y).index(word, v.dialog()[0]) + 1       # 1-based, as v.find and v.click count


def three(v):
    """Rows of the table: (y, name column, activities column, objects column) is not needed; the normalised body rows."""
    return norm(body(v))


@case(A)
def opens_empty_with_the_three_buttons_on_one_row_and_save_discard_greyed():
    with opened() as v:
        eq(three(v), ['[ Add Syndrome ] [ Save ] [ Discard ]'], 'an empty catalog shows only the buttons: %r' % body(v))
        a, s, d = (v.find(t) for t in ('[ Add Syndrome ]', '[ Save ]', '[ Discard ]'))
        check(a[1] == s[1] == d[1] and a[0] < s[0] < d[0], 'Add left, Save and Discard right, one row')
        check(v.has('Syndromes: 0'), 'no count or title')
        check(greyed(v, '[ Save ]') and greyed(v, '[ Discard ]'), 'Save and Discard must be greyed')
        check(not greyed(v, '[ Add Syndrome ]'), 'Add must be live')
        add_tag(v, 'recon', ('scan',))
        check(not greyed(v, '[ Save ]') and not greyed(v, '[ Discard ]'), 'a changed catalog must enable Save and Discard')
        press(v, '[ Discard ]', dx=2)
        eq(three(v), ['[ Add Syndrome ] [ Save ] [ Discard ]'], 'Discard did not restore the empty catalog: %r' % body(v))
        check(v.has('Syndromes: 0') and greyed(v, '[ Save ]') and greyed(v, '[ Discard ]'), 'after Discard the buttons are not greyed again')
        check(pfiles(v.sdir) == [], 'a Discard or a greyed Save wrote something')
        before = v.fingerprint()
        press(v, '[ Save ]', dx=2)
        check(v.fingerprint() == before and pfiles(v.sdir) == [], 'a greyed Save did something')


@case(A)
def save_writes_one_file_per_pair_of_sets_without_ids_and_a_new_dialog_loads_them():
    with opened() as v:
        add_tag(v, 'recon', ('scan',), ('network',))
        add_tag(v, 'probe', ('scan',), ('network',))
        add_tag(v, 'hide', ('hidden',))
        press(v, '[ Save ]', dx=2)
        check(greyed(v, '[ Save ]') and greyed(v, '[ Discard ]'), 'after Save the catalog is the snapshot: Save and Discard grey')
        sd = v.sdir
        eq(pfiles(sd), ['network_scan.c', 'none_hidden.c'], 'one file per pair of sets')
        a = pread(sd, 'network_scan.c')
        check(a.startswith('// Generated by Manage > Syndromes;'), 'header: %r' % a[:60])
        check('KOF_TAG_NAME("recon");' in a and 'KOF_TAG_NAME("probe");' in a and 'KOF_TAG_HIDE' not in a, 'both tags in one file: %r' % a)
        check('KOF_TAG_ID' not in a and 'KOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);' in a and 'KOF_TAG_OBJS(KOF_DISEASE_OBJ_NETWORK);' in a,
              'no id line, and the sets: %r' % a)
        check('KOF_TAG_OBJS();' in pread(sd, 'none_hidden.c'), 'an empty object set is written as an empty call')
        rows = three(v)
    with opened(sdir=sd) as v:
        eq(three(v), rows, 'a new dialog on the saved directory shows other rows')
        check(greyed(v, '[ Save ]'), 'a loaded catalog is clean')
        eq(pread(sd, 'network_scan.c'), a, 'loading changed a file')


@case(A)
def an_edit_moves_a_tag_to_the_file_of_its_new_sets_and_a_delete_removes_an_emptied_file_and_discard_keeps_the_directory():
    with opened() as v:
        add_tag(v, 'recon', ('scan',), ('network',))
        add_tag(v, 'probe', ('scan',), ('network',))
        press(v, '[ Save ]', dx=2)
        sd = v.sdir
        check('KOF_TAG_ID' not in pread(sd, 'network_scan.c'), 'a saved file holds an id line')
        # change the activities of probe: it moves to network_steal.c with the same id, recon stays
        press(v, 'probe', dx=1)
        tick(v, 'Scan')
        tick(v, 'Steal')
        press(v, '[ OK ]')
        press(v, '[ Save ]', dx=2)
        eq(pfiles(sd), ['network_scan.c', 'network_steal.c'], 'the tag did not move to its pair file')
        check('"probe"' not in pread(sd, 'network_scan.c') and '"probe"' in pread(sd, 'network_steal.c'), 'probe is in the wrong file')
        check(all('KOF_TAG_ID' not in pread(sd, f) for f in pfiles(sd)), 'an edit wrote an id line')
        # a rename (a new name is a new id, made when needed: nothing is written)
        press(v, 'recon', dx=1)
        v.key('bs', n=5)
        v.type('recon2')
        press(v, '[ OK ]')
        press(v, '[ Save ]', dx=2)
        check(all('KOF_TAG_ID' not in pread(sd, f) for f in pfiles(sd)) and '"recon2"' in pread(sd, 'network_scan.c'), 'a rename wrote an id line or lost the tag')
        # delete one: its file goes at the next Save; Discard before Save brings it back and the directory is untouched
        press(v, 'probe', dx=1)
        press(v, '[ Delete ]')
        check(not v.has('probe') and not greyed(v, '[ Save ]'), 'delete did not enable Save')
        press(v, '[ Discard ]', dx=2)
        check(v.has('probe') and greyed(v, '[ Save ]') and 'network_steal.c' in pfiles(sd), 'Discard did not undo the delete')
        press(v, 'probe', dx=1)
        press(v, '[ Delete ]')
        press(v, '[ Save ]', dx=2)
        eq(pfiles(sd), ['network_scan.c'], 'the emptied pair kept its file')


@case(A)
def a_file_with_old_id_lines_loads_clean_and_the_next_save_writes_it_without_them():
    sd = fresh_sdir()
    pwrite(sd, 'old.c', 'KOF_TAG_NAME("flood");\nKOF_TAG_ID(0x7b5c9a6b3eff2038);\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\nKOF_TAG_OBJS(KOF_DISEASE_OBJ_NETWORK);\nUNKNOWN_LINE(1);\n')
    with opened(sdir=sd) as v:
        check(v.has('flood') and greyed(v, '[ Save ]'), 'the old file did not load clean: %r' % body(v))
        check('2 lines ignored' in bottom_rule(v), 'the ignored lines (the old id and the unknown one) are not said: %r' % bottom_rule(v))
        eq(pfiles(sd), ['old.c'], 'a load wrote a file')
        add_tag(v, 'other', ('steal',))
        press(v, '[ Save ]', dx=2)
        eq(pfiles(sd), ['network_scan.c', 'none_steal.c'], 'save did not rewrite the old file under its pair name')
        check('KOF_TAG_ID' not in pread(sd, 'network_scan.c') and 'KOF_TAG_NAME("flood");' in pread(sd, 'network_scan.c') and
              'KOF_TAG_ID' not in pread(sd, 'none_steal.c'), 'the old id line was written back, or the tag was lost')


@case(A)
def a_file_that_breaks_a_rule_is_named_and_left_alone_and_a_save_refuses_to_replace_it():
    sd = fresh_sdir()
    pwrite(sd, 'bad.c', 'KOF_TAG_NAME("Up_per");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n')
    pwrite(sd, 'network_scan.c', 'this is not a tag file\n')
    with opened(sdir=sd) as v:
        check('bad.c' in bottom_rule(v) and 'network_scan.c' in bottom_rule(v), 'the files not loaded are not named: %r' % bottom_rule(v))
        add_tag(v, 'recon', ('scan',), ('network',))
        press(v, '[ Save ]', dx=2)
        check('in the way' in bottom_rule(v) and not greyed(v, '[ Save ]'), 'a refused Save must say why and stay dirty: %r' % bottom_rule(v))
        eq(pread(sd, 'network_scan.c'), 'this is not a tag file\n', 'Save overwrote a file it did not load')


@case(A)
def add_form_has_plural_titles_and_two_tick_grids_in_two_columns():
    with opened() as v:
        press(v, '[ Add Syndrome ]', dx=2)
        check(v.has('Add Syndrome') and v.has('Name') and v.has('Activities') and v.has('Objects'), 'form rows missing')
        check(not v.has('Activity') or v.has('Activities'), 'the title must be plural')
        for a in ACTS:
            check(v.find('[ ] ' + a), 'no tick for activity %s' % a)
        for o in OBJS:
            check(v.find('[ ] ' + o), 'no tick for object %s' % o)
        ya = [v.find('[ ] ' + a)[1] for a in ACTS]
        eq(len(set(ya)), 5, 'nine activities must fill 5 rows of 2 columns: %r' % ya)
        yo = [v.find('[ ] ' + o)[1] for o in OBJS]
        eq(len(set(yo)), 4, 'eight objects must fill 4 rows of 2 columns: %r' % yo)
        check(max(ya) < v.find('Objects')[1] <= min(yo) - 1 and v.find('Activities')[1] < min(ya), 'titles are not above their grids')
        check(v.has('[ OK ]') and v.has('[ Cancel ]') and not v.has('[ Delete ]'), 'Add has OK and Cancel only')
        ok, cn = v.find('[ OK ]'), v.find('[ Cancel ]')
        check(ok[1] == cn[1] and ok[0] < cn[0], 'OK before Cancel on one row')
        press(v, '[ Cancel ]')


@case(A)
def add_creates_a_row_with_activities_and_objects_in_the_engines_order():
    with opened() as v:
        add_tag(v, 'recon', ('steal', 'scan'), ('file', 'network'))
        eq(three(v)[0], 'recon Scan, Steal Network, File', 'row: %r' % body(v))
        check(v.has('Syndromes: 1'), 'count: %r' % bottom_rule(v))
        add_tag(v, 'c2-x', ('c2',))
        eq(three(v), ['recon Scan, Steal Network, File', 'c2-x C2', '[ Add Syndrome ] [ Save ] [ Discard ]'], 'rows in creation order')
        check(v.has('Syndromes: 2'), 'count')
        for w in ('Name', 'Activities', 'Objects'):
            check(w not in ' '.join(body(v)), 'heading word %r in the table' % w)


@case(A)
def no_activity_is_refused_with_one_line_and_objects_are_optional():
    with opened() as v:
        press(v, '[ Add Syndrome ]', dx=2)
        v.type('t')
        tick(v, 'File')
        press(v, '[ OK ]')
        check(v.has('Select at least one Activity') and v.has('[ OK ]'), 'no activity must be refused, dialog kept')
        tick(v, 'Steal')
        press(v, '[ OK ]')
        check(not v.has('[ OK ]'), 'the form did not close with an activity')
        add_tag(v, 'u', ('scan',))
        eq(three(v)[1], 'u Scan', 'objects are optional: %r' % body(v))


@case(A)
def empty_long_and_duplicate_names_show_one_error_line():
    with opened() as v:
        add_tag(v, 'recon', ('scan',))
        for name, want in (('', 'name is empty'), ('x' * 64, 'over 63'), ('recon', 'already used')):
            press(v, '[ Add Syndrome ]', dx=2)
            if name:
                v.type(name)
            tick(v, 'Scan')
            press(v, '[ OK ]')
            check(v.has(want) and v.has('[ OK ]'), '%r: %r not said, or the dialog closed' % (name, want))
            press(v, '[ Cancel ]')
        eq(three(v)[0], 'recon Scan', 'a refusal changed the catalog: %r' % body(v))
        # characters outside the tag rule (letters of either case, digits, '-') are not typed at all: space, '_', '.', '*', '/'
        press(v, '[ Add Syndrome ]', dx=2)
        v.type('aB c_D.*/E-9')
        eq(field_text(v, 'Name'), 'aBcDE-9', 'a character outside the name rule was typed, or a letter was not')
        press(v, '[ Cancel ]')
        # 63 characters are fine
        add_tag(v, 'n' * 63, ('scan',))
        check(v.has('Syndromes: 2'), '63 characters must be accepted')


@case(A)
def name_click_opens_edit_filled_with_ticks_and_a_delete_alone_at_the_right():
    with opened() as v:
        add_tag(v, 'recon', ('scan', 'steal'), ('network',))
        p = v.find('recon')
        v.click(p[0] + 2, p[1])
        v.pump_quiet()
        check(v.has('Edit Syndrome') and v.has('[ OK ]') and v.has('[ Cancel ]') and v.has('[ Delete ]'), 'Edit form missing')
        check(v.has('[x] Scan') and v.has('[x] Steal') and v.has('[ ] C2') and v.has('[x] Network') and v.has('[ ] File'), 'ticks not filled')
        ok, cn, dl = v.find('[ OK ]'), v.find('[ Cancel ]'), v.find('[ Delete ]')
        check(ok[1] == dl[1] and ok[0] < cn[0] < dl[0] and dl[0] - cn[0] > 10, 'Delete must be alone at the far right: %r' % ((ok, cn, dl),))
        press(v, '[ Cancel ]')
        check(not v.has('[ OK ]'), 'Cancel')


@case(A)
def edit_renames_and_changes_both_sets_and_a_refusal_changes_nothing():
    with opened() as v:
        add_tag(v, 'recon', ('scan',), ('network',))
        add_tag(v, 'other', ('steal',))
        p = v.find('recon')
        v.click(p[0] + 1, p[1])
        v.pump_quiet()
        for _ in range(5):
            v.key('bs')
        v.type('other')
        press(v, '[ OK ]')
        check(v.has('already used') and v.has('Edit Syndrome'), 'rename onto another name must be refused')
        for _ in range(5):
            v.key('bs')
        v.type('probe')
        tick(v, 'Scan')
        press(v, '[ OK ]')
        check(v.has('Select at least one Activity'), 'unticking the last activity must be refused')
        tick(v, 'Destruction')
        tick(v, 'Network')
        tick(v, 'Kernel')
        press(v, '[ OK ]')
        check(not v.has('[ OK ]'), 'the edit did not close')
        eq(three(v)[:2], ['probe Destruction Kernel', 'other Steal'], 'edited row: %r' % body(v))


@case(A)
def delete_removes_at_once_without_confirmation():
    with opened() as v:
        add_tag(v, 'alpha', ('scan',))
        add_tag(v, 'beta', ('steal',))
        p = v.find('alpha')
        v.click(p[0], p[1])
        v.pump_quiet()
        check(v.has('Edit Syndrome'), 'edit did not open')
        press(v, '[ Delete ]')
        check(not v.has('[ OK ]') and not v.has('Delete'), 'no confirmation: the form closes')
        eq(three(v), ['beta Steal', '[ Add Syndrome ] [ Save ] [ Discard ]'], 'rows after delete: %r' % body(v))
        check(v.has('Syndromes: 1'), 'count')


@case(A)
def activities_cell_opens_a_two_column_tick_menu_that_keeps_one_activity():
    with opened() as v:
        add_tag(v, 'recon', ('scan',), ('network',))
        y = v.find('recon')[1]
        x = cell_x(v, y, 'Scan')
        v.click(x + 1, y)
        v.pump_quiet()
        check(v.has('[x] Scan') and v.has('[ ] Destruction') and not v.has('[ ] Network'), 'the activities menu is not up')
        ya = {a: (v.find('[x] ' + a) or v.find('[ ] ' + a))[1] for a in ACTS}
        eq(len(set(ya.values())), 5, 'the menu is not 2 columns: %r' % ya)
        press(v, '[ ] Steal')
        check(v.has('[x] Steal') and v.has('[x] Scan'), 'the tick did not show (the menu stays open)')
        press(v, '[x] Scan')
        press(v, '[x] Steal')
        check(v.has('[x] Steal') and v.has('Select at least one Activity'), 'the last activity was removed, or the refusal is not said')
        v.click(1, v.rows)
        v.pump_quiet()
        check(not v.has('[ ] Destruction'), 'a press outside did not put the menu away')
        eq(three(v)[0], 'recon Steal Network', 'row after the menu: %r' % body(v))
        # the objects cell: ticks, and all of them may be cleared
        y = v.find('recon')[1]
        x = cell_x(v, y, 'Network')
        v.click(x + 1, y)
        v.pump_quiet()
        check(v.has('[x] Network') and v.has('[ ] Input'), 'the objects menu is not up')
        press(v, '[x] Network')
        press(v, '[ ] File')
        v.esc()
        check(not v.has('[ ] Input') and v.has('Syndromes'), 'Esc must close the menu only')
        eq(three(v)[0], 'recon Steal File', 'row: %r' % body(v))


@case(A)
def an_empty_objects_cell_is_clickable_over_twelve_columns_and_no_further():
    with opened() as v:
        add_tag(v, 'alpha', ('scan',))
        y = v.find('alpha')[1]
        x = cell_x(v, y, 'Scan') + len('scan') + 3      # the objects column: the activities text, the table's gap and this dialog's two blanks
        v.click(x + 14, y)
        v.pump_quiet()
        quiet = v.fingerprint()
        v.click(x + 12, y)
        v.pump_quiet()
        check(v.fingerprint() == quiet, 'the 13th column of an empty objects cell opened something')
        v.click(x + 11, y)
        v.pump_quiet()
        check(v.has('[ ] Network'), 'the 12th column of an empty objects cell did not open the menu')
        press(v, '[ ] Network')
        v.esc()
        eq(three(v)[0], 'alpha Scan Network', 'row: %r' % body(v))


@case(A)
def a_press_opens_a_cell_only_over_the_extent_of_its_text():
    with opened() as v:
        add_tag(v, 'recon', ('scan',), ('network',))
        y = v.find('recon')[1]
        nx, ax = cell_x(v, y, 'recon'), cell_x(v, y, 'Scan')
        v.click(nx + 6, y)
        v.pump_quiet()
        quiet = v.fingerprint()
        for x, what in ((nx + 5, 'the gap after the name'), (ax + 4, 'the gap after the activities'), (v.dialog()[2] - 3, 'the right end')):
            v.click(x, y)
            v.pump_quiet()
            check(v.fingerprint() == quiet, '%s opened something' % what)
        v.click(nx + 4, y)
        v.pump_quiet()
        check(v.has('Edit Syndrome'), 'the last character of the name did not hit')
        press(v, '[ Cancel ]')
        v.click(ax + 3, y)
        v.pump_quiet()
        check(v.has('[ ] Destruction'), 'the last character of the activities text did not hit')
        v.esc()


@case(A)
def cancel_close_box_and_esc_discard():
    with opened() as v:
        press(v, '[ Add Syndrome ]', dx=2)
        v.type('zed')
        tick(v, 'Scan')
        press(v, '[ Cancel ]')
        check(not v.has('[ OK ]') and v.has('[ Add Syndrome ]') and not v.has('zed'), 'Cancel did not close only the form')
        press(v, '[ Add Syndrome ]', dx=2)
        check(v.has('[ ] Scan'), 'the ticks survived a Cancel')
        v.type('zed')
        p = v.find('[x]')
        check(p, 'no [x] in the form frame')
        v.click(p[0] + 1, p[1])
        v.pump_quiet()
        check(not v.has('[ OK ]') and not v.has('zed'), 'the [x] did not discard')
        press(v, '[ Add Syndrome ]', dx=2)
        v.type('zed')
        v.esc()
        check(not v.has('[ OK ]') and not v.has('zed') and v.has('[ Add Syndrome ]'), 'Esc did not cancel')
        v.esc()
        check(not v.has('Syndromes'), 'Esc did not close the main dialog')
        check(v.menu_item('Manage', 'Syndromes'), 'reopen')
        v.pump_quiet()
        check(v.has('[ Add Syndrome ]'), 'reopen did not show the dialog')


@case(A)
def the_catalog_survives_closing_the_dialog_and_both_dialogs_are_independent():
    with opened() as v:
        add_tag(v, 'recon', ('scan',))
        v.esc()
        check(v.menu_item('Manage', 'Syndromes'), 'reopen')
        v.pump_quiet()
        check(v.has('recon'), 'the catalog was lost by closing')
        v.esc()
        check(v.menu_item('Manage', 'Pathogens'), 'Pathogens')
        v.pump_quiet()
        check(v.has('[ Add family ]') and not v.has('recon'), 'Pathogens shows the other catalog')
        v.esc()


@case(A)
def main_dialog_and_form_are_dragged_like_pathogens_and_stay_on_screen():
    with opened() as v:
        add_tag(v, 'recon', ('scan',))
        d0 = v.dialog()
        v.drag(d0[0] + 6, d0[1], d0[0] - 6, d0[1] + 5)
        d1 = v.dialog()
        eq((d1[0], d1[1]), (d0[0] - 12, d0[1] + 5), 'the box did not follow the pointer')
        press(v, '[ Add Syndrome ]', dx=2)
        check(v.has('[ OK ]'), 'the button at the dragged place did not work')
        f0, f1 = drag_title(v, 10, 3, grab=4)
        eq((f1[0], f1[1]), (f0[0] + 10, f0[1] + 3), 'the form did not follow the pointer')
        v.type('zed')
        tick(v, 'Scan')
        press(v, '[ OK ]')
        check('zed' in v.text() and not v.has('[ OK ]'), 'OK at the new place did not add')
        d = v.dialog()
        v.drag(d[0] + 6, d[1], v.cols, v.rows)
        d = v.dialog()
        check(d and d[2] <= v.cols and d[3] <= v.rows and d[1] >= 2, 'the box left the screen: %r' % (d,))


@case(A)
def small_screens_keep_the_form_whole_and_the_dialog_content_sized():
    with opened(rows=24, cols=80) as v:
        add_tag(v, 'recon', ('scan',))
        d = v.dialog()
        check(d and d[2] - d[0] + 1 <= 80 and d[3] - d[1] + 1 <= 24, 'main dialog does not fit 80x24')
        press(v, '[ Add Syndrome ]', dx=2)
        d = v.dialog()
        check(d and d[2] <= 80 and d[3] <= 24 and v.has('[ OK ]') and v.has('[ ] Input'), 'the form does not fit 80x24: %r' % (d,))
        press(v, '[ Cancel ]')



def field_text(v, label):
    """What a labelled field of the open form holds (the text between its brackets)."""
    row = [r for r in v.lines if label + ' ' in r and '[' in r.split(label, 1)[1]][0]
    return row.split(label, 1)[1].split('[', 1)[1].rsplit(']', 1)[0].strip()


@case(A)
def typing_upper_case_is_taken_and_a_bad_character_is_not_and_every_word_is_shown_capitalised():
    with opened() as v:
        press(v, '[ Add Syndrome ]', dx=2)
        v.type('RECON')
        eq(field_text(v, 'Name'), 'RECON', 'upper-case letters were not typed')
        v.type('Re_c.o n')
        eq(field_text(v, 'Name'), 'RECONRecon', 'letters of either case are typed, "_", "." and " " are not')
        for w in ACTS + OBJS:
            check(v.find('[ ] ' + w), 'no capitalised tick %s' % w)
        for w in ('scan', 'network', 'c2', 'escalation'):
            check(not v.find('[ ] ' + w), 'a lower-case word %s is shown' % w)
        check(v.has('[ ] C2') and v.has('[ ] Escalation'), 'c2 is upper-cased whole, escalation capitalised')
        press(v, '[ Cancel ]')


@case(A)
def an_upper_case_name_is_kept_as_typed_a_duplicate_by_case_is_refused_and_the_file_name_is_lower_case():
    with opened() as v:
        add_tag(v, 'C2-Beacon', ('c2',))
        check(v.has('C2-Beacon'), 'the name lost its capitals: %r' % body(v))
        press(v, '[ Add Syndrome ]', dx=2)
        v.type('c2-beacon')
        tick(v, 'Scan')
        press(v, '[ OK ]')
        check('already used' in bottom_rule(v) or v.has('that name is already used'), 'a duplicate by letter case was not refused')
        press(v, '[ Cancel ]')
        press(v, '[ Save ]', dx=2)
        eq(pfiles(v.sdir), ['none_c2.c'], 'the file name is made lower case')
        check('KOF_TAG_NAME("C2-Beacon");' in pread(v.sdir, 'none_c2.c'), 'the name is written as typed')
        sd = v.sdir
    with opened(sdir=sd) as v:
        check(v.has('C2-Beacon') and greyed(v, '[ Save ]'), 'the saved name did not load as typed')


@case(A)
def the_form_has_a_comment_row_under_the_name_and_the_table_a_comment_column_that_never_widens_the_dialog():
    with opened() as v:
        press(v, '[ Add Syndrome ]', dx=2)
        ny, cy = v.find('Name')[1], v.find('Comment')[1]
        eq(cy, ny + 1, 'the Comment row is not directly under the Name row')
        v.type('recon')
        p = v.find('Comment')
        v.click(p[0] + 12, p[1])
        v.pump_quiet()
        v.type('a*b/c and more')
        eq(field_text(v, 'Comment'), 'abc and more', '"*" and "/" must not be typed')
        eq(field_text(v, 'Name'), 'recon', 'the text went to the wrong field')
        tick(v, 'Scan')
        press(v, '[ OK ]')
        check(v.has('recon') and v.has('abc and more'), 'the comment column is missing: %r' % body(v))
        w0 = v.dialog()
        # a 120-character comment: edit, type, OK; the dialog keeps its size (the table scrolls sideways)
        press(v, 'recon', dx=1)
        eq(field_text(v, 'Comment'), 'abc and more', 'Edit does not start from the comment')
        p = v.find('Comment')
        v.click(p[0] + 12, p[1])
        v.pump_quiet()
        v.key('bs', n=20)
        v.type('x' * 120 + 'y')
        check(v.has('xxxxxxxx'), 'the comment field holds nothing')
        press(v, '[ OK ]')
        check(v.has('[ OK ]') and v.has('comment is over 120 characters'), 'a 121-character comment was not refused: %r' % bottom_rule(v))
        v.key('bs')
        press(v, '[ OK ]')
        check(not v.has('[ OK ]'), 'a 120-character comment was refused: %r' % bottom_rule(v))
        d = v.dialog()
        check(d[2] - d[0] <= 100 + 2 and d[3] - d[1] <= 32 + 2, 'a long comment widened or heightened the dialog: %r -> %r' % (w0, d))
        press(v, '[ Save ]', dx=2)
        t = pread(v.sdir, 'none_scan.c')
        check(('// ' + 'x' * 120 + '\nKOF_TAG_NAME("recon");') in t, 'the comment is not a // line above the tag: %r' % t)
        sd = v.sdir
    with opened(sdir=sd) as v:
        check(v.has('recon') and v.has('xxxxxxxx') and greyed(v, '[ Save ]'), 'the comment did not load: %r' % body(v))
        before = pread(sd, 'none_scan.c')
        add_tag(v, 'other', ('scan',))
        press(v, '[ Save ]', dx=2)
        after = pread(sd, 'none_scan.c')
        check(before.split('\n', 1)[1] in after, 'a save after a load changed the existing block (save-load-save is not byte-identical)')


@case(A)
def save_with_no_syndromes_option_writes_into_the_bases_syndromes_directory():
    """The owner's path: --bases only (no --syndromes), Add, Save. Passes on the old code too (the reported 'Save does not work' was not
    reproduced here); it pins the default directory so a later change cannot break it unseen."""
    bd = bases_dir()
    sd = os.path.join(bd, 'syndromes')
    os.makedirs(sd, exist_ok=True)
    for f in pfiles(sd):
        os.remove(os.path.join(sd, f))
    v = Viewer(SAMPLES['ko'], rows=40, cols=120, bases=True)
    try:
        check(v.menu_item('Manage', 'Syndromes'), 'no Syndromes item')
        v.pump_quiet()
        add_tag(v, 'recon', ('scan',))
        check(not greyed(v, '[ Save ]'), 'Save is greyed after an Add')
        press(v, '[ Save ]', dx=2)
        check(greyed(v, '[ Save ]'), 'Save did not take: %r' % bottom_rule(v))
        eq(pfiles(sd), ['none_scan.c'], 'nothing was written under <bases>/syndromes')
    finally:
        v.close()
        for f in pfiles(sd):
            os.remove(os.path.join(sd, f))


@case(A)
def every_row_of_the_form_ends_with_the_wall_at_any_screen_size():
    for rows, cols in ((40, 120), (30, 100), (24, 80), (50, 200)):
        with opened(rows=rows, cols=cols) as v:
            add_tag(v, 'recon', ('scan',))
            for edit in (False, True):
                if edit:
                    p = v.find('recon')
                    v.click(p[0] + 1, p[1])
                    v.pump_quiet()
                else:
                    press(v, '[ Add Syndrome ]', dx=2)
                x0, y0, x1, y1, _ = v.dialog()
                for y in range(y0 + 1, y1):
                    r = v.row(y)
                    check(r[x0 - 1] == '\u2502' and r[x1 - 1] == '\u2502', 'a form row has no wall at %dx%d (row %d): %r' % (cols, rows, y, r[x0 - 1:x1 + 4]))
                check(v.has('[ ] Escalation') and v.has('[ ] Destruction'), 'the grid was cut at %dx%d' % (cols, rows))
                press(v, '[ Cancel ]')


if __name__ == "__main__":
    main(A)
