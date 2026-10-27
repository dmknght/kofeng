"""The symbol tables: the Imports and Exports tabs of the dashboard (Analysis > Dashboard, a click on the tab).
They were the Symbols dialog; the dialog and its menu item are gone, every feature it had is here."""
from tui import *

A = 'symbols'
ROWRX = r'│\s*(\d+)\s+(SECTION|NOTYPE|FUNC|OBJECT|FILE|TLS|COMMON|\S+)\s+(LOCAL|GLOBAL|WEAK)'


def first_rec(v):
    r = v.find_re(ROWRX)
    return int(r[2].group(1)) if r else None


def rows_text(v):
    """Symbol rows currently drawn in the page."""
    d = v.dialog()
    out = []
    if not d:
        return out
    for y in range(d[1] + 1, d[3]):
        l = v.row(y)
        if re.search(ROWRX, l):
            out.append(l)
    return out


def frow(v):
    """The row of the filter line (the one with the two ticks)."""
    p = v.find('icase')
    check(p, 'no filter line')
    return p[1]


def filter_box(v):
    """(x, y) of a cell inside the filter box (the word 'filter' is only a placeholder: it is gone once the box has
    text)."""
    p = v.find('icase')
    return (p[0] - 20, p[1])


def opened(tab='Exports'):
    """The dashboard on the Exports tab (what the dialog opened on), reached by the mouse."""
    v = Viewer(SAMPLES['ko'])
    open_dash_tab(v, tab)
    check(v.dialog() and 'Overview' in v.dialog()[4], 'dashboard did not open')
    check(v.has('filter') and v.has('icase'), 'the %s tab has no filter line' % tab)
    return v


@case(A)
def open_shows_both_tabs_with_counts():
    with opened() as v:
        check(v.has('Imports') and v.has('Exports'), 'tab labels missing')
        check(not v.has('Imports 49', rows=(2, 2)), 'the strip still carries a count')
        check(first_rec(v) == 0, 'first rec != 0: %r' % first_rec(v))


@case(A)
def wheel_scrolls_and_repaints():
    with opened() as v:
        r0 = first_rec(v)
        v.wheel(60, 25, n=3)
        eq(first_rec(v), r0 + 9, 'wheel x3 (3 rows each)')
        v.wheel(60, 25, up=True, n=3)
        eq(first_rec(v), r0, 'wheel back')


@case(A)
def wheel_over_tree_area_still_scrolls_dialog_not_tree():
    with opened() as v:
        tree_before = [v.row(y)[:2] for y in range(2, 10)]
        v.wheel(10, 5, n=2)       # pointer over the tree, outside the box
        check(first_rec(v) == 6, 'dialog did not scroll: %r' % first_rec(v))
        eq([v.row(y)[:2] for y in range(2, 10)], tree_before, 'tree moved')


@case(A)
def keys_down_up_pgdn_pgup_home_end():
    with opened() as v:
        v.key('down', 3, settle=0.1);  eq(first_rec(v), 3, 'down x3')
        v.key('up', 1, settle=0.1);    eq(first_rec(v), 2, 'up')
        v.key('pgdn');                 pg = first_rec(v) - 2
        check(pg >= 10, 'PgDn step too small: %d' % pg)
        v.key('pgup');                 eq(first_rec(v), 2, 'PgUp')
        v.key('end')
        last = first_rec(v)
        check(last > 4000, 'End did not reach the tail: %r' % last)
        v.key('down', 5, settle=0.05); eq(first_rec(v), last, 'Down past the end must clamp')
        v.key('home');                 eq(first_rec(v), 0, 'Home')
        v.key('up', 3, settle=0.05);   eq(first_rec(v), 0, 'Up at top must clamp')


@case(A)
def end_shows_last_record_fully():
    with opened() as v:
        v.key('end')
        rows = rows_text(v)
        d = v.dialog()
        check(len(rows) >= 20, 'last page not full: %d rows' % len(rows))
        m = re.search(ROWRX, rows[-1])
        eq(int(m.group(1)), 4046, 'last record id')


@case(A)
def tab_click_switches_halves():
    with opened() as v:
        exp = rows_text(v)[1]
        v.click(*v.find('Imports', rows=(1, 4)))
        imp = rows_text(v)
        check(imp and imp[0] != rows_text(v)[1] if len(imp) > 1 else True)
        check('UND' in imp[0] or '.U' in imp[0], 'IMP rows should be undefined symbols: %r' % imp[0])
        v.click(*v.find('Exports', rows=(1, 4)))
        eq(rows_text(v)[1], exp, 'EXP tab did not restore')


@case(A)
def no_key_switches_tabs():
    """Owner decision: the strip is switched by a click and by nothing else. Tab, Shift+Tab and the digits do nothing
    here (the dialog's Tab, which swapped its two halves, went with the dialog)."""
    with opened() as v:
        a = rows_text(v)[0]
        for k in ('tab', 'backtab'):
            v.key(k)
            eq(rows_text(v)[0], a, '%s switched the page' % k)
        v.type('1234')
        eq(rows_text(v)[0], a, 'a digit switched the page')
        check(v.has('icase'), 'the Exports tab is no longer showing')


@case(A)
def tab_switch_resets_scroll():
    with opened() as v:
        v.key('pgdn', 2)
        check(first_rec(v) > 0)
        v.click(*v.find('Imports', rows=(1, 4)))
        eq(first_rec(v), 0, 'scroll should reset to 0 on tab change')


@case(A)
def filter_substring_and_clear():
    with opened() as v:
        v.click(*filter_box(v))
        v.type('rpc_create')
        rows = rows_text(v)
        check(rows, 'no rows for rpc_create')
        for r in rows:
            check('rpc_create' in r, 'row does not match filter: %r' % r[:80])
        for _ in range(10):
            v.key('bs', settle=0.05)
        check(len(rows_text(v)) > len(rows), 'clearing the filter did not restore rows')


@case(A)
def filter_case_sensitivity_toggle():
    with opened() as v:
        v.click(*filter_box(v))
        v.type('RPC_CREATE')
        n_cs = len(rows_text(v))
        v.click(*v.find('icase'))
        n_ic = len(rows_text(v))
        check(n_cs == 0, 'case sensitive match found upper-case rows: %d' % n_cs)
        check(n_ic > 0, 'icase found nothing')


@case(A)
def filter_regex_toggle_and_bad_regex():
    # NOTE: the regex dialect is the matcher's (kof_hex_walk): no ^ / $ anchors.
    with opened() as v:
        v.click(*filter_box(v))
        v.type('ksymtab_rpc_cr.ate')
        check(not rows_text(v), 'literal filter with a regex dot matched')
        v.click(*v.find('regex'))
        rows = rows_text(v)
        check(len(rows) == 1 and '__ksymtab_rpc_create' in rows[0], 'regex rows: %r' % rows)
        v.type('(')
        check(v.alive(), 'viewer died on invalid regex')
        check(not rows_text(v), 'invalid regex should show no rows')
        check(v.has('regex'))


@case(A)
def regex_anchors_unsupported_is_documented_behaviour():
    # ^ and $ are literal in this dialect: documents what a user will hit.
    with opened() as v:
        v.click(*v.find('regex'))
        v.click(*filter_box(v))
        v.type('^__ksymtab_rpc_create')
        eq(len(rows_text(v)), 0, 'anchored regex unexpectedly matched (dialect changed?)')


@case(A)
def filter_no_match_message():
    with opened() as v:
        v.click(*filter_box(v))
        v.type('zzzz_no_such_symbol')
        check(v.has('no symbol matches the filter'), 'empty-result message missing')


@case(A)
def typing_without_focus_does_not_edit_filter():
    with opened() as v:
        v.type('rpc')
        eq(first_rec(v), 0)
        check(len(rows_text(v)) > 0)
        check('rpc' not in v.row(frow(v))[10:90], 'typing leaked into the filter without focus')


@case(A)
def esc_leaves_filter_then_closes():
    with opened() as v:
        v.click(*filter_box(v))
        v.type('abc')
        v.key('esc')
        check(v.dialog(), 'first Esc closed the dialog instead of leaving the field')
        v.key('esc')
        check(not v.dialog(), 'second Esc did not close')


@case(A)
def esc_closes_and_restores_panes():
    with Viewer(SAMPLES['ko']) as v:
        before = v.snapshot()
        open_dash_tab(v, 'Exports')
        v.key('pgdn', 2)
        v.key('esc')
        check(not v.dialog(), 'dialog still drawn')
        eq(v.snapshot(), before, 'screen differs after open/scroll/close')


@case(A)
def close_button_closes():
    with opened() as v:
        d = v.dialog()
        p = v.find('[ Close ]', rows=(1, 4))
        check(p, 'no [ Close ] button')
        v.click(*p)
        check(not v.dialog(), 'close button did not close')
        check(v.alive())


@case(A)
def click_inside_rows_is_swallowed():
    with opened() as v:
        r0 = first_rec(v)
        v.click(70, 20)
        check(v.dialog(), 'row click closed the dialog')
        v.click(10, 4)    # outside the box: swallowed too (modal)
        check(v.dialog(), 'click outside should not close or act through the modal')
        eq(first_rec(v), r0)


@case(A)
def hscroll_with_shift_wheel_and_right_key():
    with opened() as v:
        v.resize(30, 100)       # at 170 columns the table fits: nothing to scroll
        y = [yy for yy in range(3, v.rows) if re.search(ROWRX, v.row(yy))][0]
        l0 = v.row(y)
        v.key('right', 3, settle=0.05)
        l1 = v.row(y)
        check(l0 != l1, 'Right did not scroll horizontally')
        v.key('left', 3, settle=0.05)
        eq(v.row(y), l0, 'Left did not restore')
        v.hwheel(40, 20, n=2)
        check(v.row(y) != l0, 'shift+wheel did not scroll sideways')


@case(A)
def drag_select_and_ctrl_c_copies_row_text():
    # was BUG-3 of the dialog (it never recorded its rows); the page records every row it draws
    with opened() as v:
        y = [yy for yy in range(3, v.rows) if re.search(ROWRX, v.row(yy))][3]
        v.drag(6, y, 60, y)
        n0 = len(v.osc52())
        v.key('ctrl+c')
        got = v.osc52()
        check(len(got) > n0, 'Ctrl+C sent no clipboard data')
        check(b'NOTYPE' in got[-1] or b'SECTION' in got[-1], 'copied text unexpected: %r' % got[-1][:60])


@case(A)
def resize_while_open_keeps_dialog_inside_screen():
    with opened() as v:
        for rows, cols in ((30, 100), (50, 170), (70, 240)):
            v.resize(rows, cols)
            check(v.alive(), 'died at %dx%d' % (rows, cols))
            d = v.dialog()
            check(d, 'dialog vanished at %dx%d' % (rows, cols))
            check(d[2] <= cols and d[3] <= rows, 'box %r outside %dx%d' % (d, rows, cols))
        v.key('end')
        check(v.alive())


@case(A, known_bug='BUG-1 kof_winch is a static in kofplat.h (2 copies): resize wipe never runs; ghost frames under a modal')
def resize_while_open_leaves_no_ghost_frame():
    with opened() as v:
        for rows, cols in ((30, 100), (62, 200), (40, 120), (50, 170)):
            v.resize(rows, cols)
            corners = v.text().count('\u256d\u2500 Overview')
            check(corners == 1, '%d dialog boxes on screen after resize to %dx%d' % (corners, rows, cols))
            n = sum(1 for l in v.snapshot() if 'no verdict' in l)
            check(n <= 1, 'stale status line left behind at %dx%d' % (rows, cols))


@case(A)
def tiny_terminal_while_open():
    with opened() as v:
        v.resize(6, 30)
        check(v.alive(), 'died at 6x30')
        v.key('pgdn'); v.key('end'); v.key('tab')
        check(v.alive(), 'died on keys at 6x30')
        v.resize(50, 170)
        check(v.dialog(), 'dialog not restored after growing back')


@case(A)
def not_offered_without_symbols():
    p = pick(SCRATCH + '/snapcorp/ws_webshells', 1, 2000, 20000)[0]
    with Viewer(p) as v:
        v.menu_open('Analysis')
        check(not v.popup_item('Symbols'), 'the retired Symbols item is offered for a script')
        v.esc()
        open_dash_tab(v, 'Imports')
        check(v.has('this kind of object has no symbol table'), 'the Imports tab does not say why it is empty')


@case(A)
def pe_imports_tab_opens():
    p = pick(SAMPLES['pe'], 1, 30000, 200000)[0]
    with Viewer(p) as v:
        open_dash_tab(v, 'Imports')
        check(v.dialog(), 'no dialog')
        v.key('pgdn'); v.key('tab'); v.key('end')
        check(v.alive())


if __name__ == '__main__':
    main(A)
