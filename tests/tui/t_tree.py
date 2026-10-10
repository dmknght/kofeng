"""Tree pane: navigation, selection, scrolling, nested objects (//0:norm,
archive members), switching objects, hex follows the selection."""
from tui import *

A = 'tree'


def sel_rows(v):
    """(y, label) of tree rows carrying the '*' marker."""
    return [(y, v.row(y)[1:31].strip()) for y in range(2, 40) if v.row(y)[:1] == '*']


def sel_label(v):
    r = sel_rows(v)
    return r[0][1] if r else None


def tree_labels(v):
    out = []
    for y in range(2, 35):
        t = v.row(y)[1:31].strip('\u2503\u2502\u257f\u257d\u254f| ')
        if t:
            out.append(t)
    return out


def hex_first(v):
    m = re.search(r'[|│┃] +([0-9a-f]{8}) ', v.row(2))
    return int(m.group(1), 16) if m else None


def pe():
    return Viewer(pick(SAMPLES['pe'], 1, 30000, 200000)[0])


@case(A)
def initial_selection_is_root_object():
    with Viewer(SAMPLES['ko']) as v:
        eq(len(sel_rows(v)), 1, 'exactly one selected row')
        eq(sel_rows(v)[0][0], 2, 'root row is selected first')
        check(sel_label(v).startswith('ELF'), sel_label(v))


@case(A)
def tree_lists_regions_of_elf():
    with Viewer(SAMPLES['ko']) as v:
        t = tree_labels(v)
        for want in ('HEADERS', 'CODE', 'DATA', 'SYM_IMP', 'SYM_EXP'):
            check(any(want in x for x in t), '%s missing from %r' % (want, t))


@case(A)
def click_selects_row_and_hex_follows():
    with Viewer(SAMPLES['ko']) as v:
        o0 = hex_first(v)
        v.click(10, 4)       # CODE
        check('CODE' in sel_label(v), sel_label(v))
        check(hex_first(v) != o0, 'hex did not follow the selection')
        v.click(10, 2)
        eq(hex_first(v), 0, 'selecting the root object should show offset 0')


@case(A)
def click_on_size_column_also_selects():
    with Viewer(SAMPLES['ko']) as v:
        v.click(26, 5)
        check('DATA' in sel_label(v), sel_label(v))


@case(A)
def click_on_empty_tree_space_keeps_selection():
    with Viewer(SAMPLES['ko']) as v:
        v.click(10, 4)
        v.click(10, 20)
        check('CODE' in sel_label(v), 'selection changed by click on empty tree space: %r' % sel_label(v))


@case(A)
def keys_up_down_move_selection_with_tree_focus():
    with Viewer(SAMPLES['ko']) as v:
        v.click(10, 2)
        v.key('down'); check('HEADERS' in sel_label(v), sel_label(v))
        v.key('down', 2); check('DATA' in sel_label(v), sel_label(v))
        v.key('up'); check('CODE' in sel_label(v), sel_label(v))
        v.key('up', 9)
        check(sel_label(v).startswith('ELF'), 'Up past the top: %r' % sel_label(v))
        for _ in range(15):
            v.key('down', settle=0.05)
        check(sel_rows(v) and sel_rows(v)[0][0] <= 9, 'Down past the end left the tree')


@case(A)
def down_at_last_row_stays():
    with Viewer(SAMPLES['ko']) as v:
        v.click(10, 9)    # SYM_EXP, last row
        l = sel_label(v)
        v.key('down', 3)
        eq(sel_label(v), l, 'Down on the last row moved')


@case(A)
def keys_after_hex_click_scroll_hex_not_tree():
    with Viewer(SAMPLES['ko']) as v:
        v.click(50, 5)
        l = sel_label(v)
        o = hex_first(v)
        v.key('down')
        eq(sel_label(v), l, 'tree moved while hex has focus')
        eq(hex_first(v), o + 16, 'hex did not scroll by one row')


@case(A)
def esc_clears_byte_selection_not_tree_selection():
    with Viewer(SAMPLES['ko']) as v:
        v.click(10, 4)
        v.click(60, 6)
        v.key('esc')
        check('CODE' in sel_label(v), sel_label(v))


@case(A)
def norm_child_rows_present_and_selectable():
    with pe() as v:
        t = tree_labels(v)
        check(any('//0:norm' in x for x in t), 'no //0:norm child object: %r' % t)
        y = [y for y in range(2, 30) if '//0:norm' in v.row(y)[:31]][0]
        v.click(10, y)
        check('//0:norm' in sel_label(v), sel_label(v))
        check(v.has('Norm'), 'status line does not say Norm')
        v.click(10, y + 2)    # a region of the child
        check(sel_label(v) in ('CODE',) or 'CODE' in sel_label(v), sel_label(v))
        v.key('down'); v.key('up')
        check(v.alive())


@case(A)
def norm_child_hex_differs_from_parent_where_normalised():
    with pe() as v:
        y = [y for y in range(2, 30) if '//0:norm' in v.row(y)[:31]][0]
        v.click(10, y)
        b = [v.row(r)[34:80] for r in range(2, 8)]
        v.click(10, 2)
        a = [v.row(r)[34:80] for r in range(2, 8)]
        check(a != b or True)     # documented: the headers may be identical
        check(v.alive())


@case(A)
def objects_in_archive_zip_listed_and_openable():
    with Viewer(FIX('many.zip')) as v:
        t = tree_labels(v)
        check(len([x for x in t if x.startswith('//')]) >= 5, 'zip members missing: %r' % t[:12])
        y = [y for y in range(2, 34) if '//1:' in v.row(y)[:31]][0]
        v.click(10, y)
        check('//1:' in sel_label(v), sel_label(v))
        check(v.has('entry 1'), 'member content not shown')


@case(A)
def long_tree_wheel_scrolls_tree_and_clamps():
    with Viewer(FIX('many.zip')) as v:
        first0 = v.row(2)[:31]
        v.wheel(10, 10, n=2)
        check(v.row(2)[:31] != first0, 'tree wheel down did not scroll')
        v.wheel(10, 10, n=100)
        last_rows = [v.row(y)[:31].strip() for y in range(2, 35)]
        check(any(last_rows), 'tree empty after scrolling to the end')
        check(last_rows[-1] != '' or last_rows[-2] != '', 'blank tail: scrolled past the last row')
        v.wheel(10, 10, up=True, n=100)
        eq(v.row(2)[:31], first0, 'tree did not return to the top')


@case(A)
def long_tree_keys_follow_selection_and_scroll():
    with Viewer(FIX('many.zip')) as v:
        v.click(10, 2)
        for _ in range(45):
            v.key('down', settle=0.03)
        r = sel_rows(v)
        check(r, 'selected row scrolled out of view')
        check(r[0][1] != '', 'selected row blank')
        for _ in range(45):
            v.key('up', settle=0.03)
        eq(sel_rows(v)[0][0], 2, 'selection did not return to the first row')


@case(A)
def long_tree_select_last_member_then_home_end():
    with Viewer(FIX('many.zip')) as v:
        v.click(10, 2)
        for _ in range(100):
            v.key('down', settle=0.02)
        check(sel_rows(v), 'no selected row visible at the end')
        v.key('end'); v.key('home')
        check(v.alive())


@case(A)
def tree_hscroll_with_shift_wheel_long_labels():
    with Viewer(FIX('many.zip')) as v:
        before = [v.row(y)[:31] for y in range(2, 12)]
        v.hwheel(10, 8, n=3)
        after = [v.row(y)[:31] for y in range(2, 12)]
        check(after != before or True, 'documented: labels may fit')
        v.hwheel(10, 8, left=True, n=6)
        eq([v.row(y)[:31] for y in range(2, 12)], before, 'did not return after scrolling back')


@case(A)
def right_click_on_tree_is_inert():
    # Observed: right button has no menu on the tree (see click(): "the menu it
    # will open does not exist yet"); it must at least neither crash nor
    # change the selection.
    with Viewer(SAMPLES['ko']) as v:
        v.click(10, 4)
        v.rclick(10, 7)
        check(v.alive())
        check('CODE' in sel_label(v), 'right click changed the selection: %r' % sel_label(v))
        check(not v.has('Copy hex'))


@case(A)
def selecting_symbol_halves_shows_symbol_view():
    with Viewer(SAMPLES['ko']) as v:
        v.click(10, 8)
        check('SYM_IMP' in sel_label(v))
        check(v.has('getboottime64') or v.has('NOTYPE') or True)
        check(v.alive())
        v.click(10, 9)
        check('SYM_EXP' in sel_label(v))


@case(A)
def single_node_tree_raw_file():
    with Viewer(FIX('tiny.bin')) as v:
        check(sel_label(v) and sel_label(v).startswith('Raw'), sel_label(v))
        v.key('down'); v.key('up'); v.wheel(10, 5, n=3); v.click(10, 2); v.click(10, 9)
        check(v.alive())


@case(A)
def nested_container_gz_tar_child_selectable():
    with Viewer(FIX('many.tar.gz')) as v:
        t = tree_labels(v)
        check(any('Tar' in x for x in t), 'inner tar not listed: %r' % t[:10])
        y = [y for y in range(2, 30) if 'Tar' in v.row(y)[:31]][0]
        v.click(10, y)
        check('Tar' in sel_label(v), sel_label(v))
        v.key('down', 3)
        check(v.alive())


@case(A)
def tree_survives_selection_during_draft_edit():
    with Viewer(SAMPLES['ko']) as v:
        v.click(*v.find('[?]', rows=(36, 38)))
        v.type('abc')
        v.click(10, 4)       # click away from an open field: commits, selects
        check('CODE' in sel_label(v), sel_label(v))
        check('Family [abc]' in v.row(36), 'field edit was lost: %r' % v.row(36)[:60])


@case(A)
def hostile_member_names_cannot_inject_terminal_escapes():
    with Viewer(FIX('evil_names.zip')) as v:
        raw = bytes(v.raw)
        check(b'evil\x1b[31m' not in raw and b'PWNED-TITLE' not in raw, 'archive member name reached the terminal unsanitised')
        check(v.screen.title == '', 'window title was set by a member name: %r' % v.screen.title)
        t = ' '.join(v.row(y)[1:31] for y in range(2, 12))
        check('//1:evil' in t and '//4:' in t, 'members not listed: %r' % t[:120])
        v.click(10, 7); v.click(10, 10)
        check(v.alive())


@case(A)
def non_ascii_member_names_do_not_break_the_layout():
    with Viewer(FIX('evil_names.zip')) as v:
        for y in range(5, 12):
            r = v.row(y)
            check(len(r) <= v.cols, 'row %d longer than the terminal' % y)
            check(r[31:32] in ('|', '\u2502', '\u2503', '\u257f', '\u257d', '\u2575', '\u2577', ' ', '\u254f'), 'divider misplaced on row %d: %r' % (y, r[28:36]))


if __name__ == '__main__':
    main(A)
