"""Terminal resize (TIOCSWINSZ + SIGWINCH): small, large, repeated, with panels
and dialogs open.  Note: the viewer clamps its layout to >= 12 rows x 60 cols."""
from tui import *
from dl import *

A = 'resize'
SIZES = [(24, 80), (30, 100), (40, 120), (50, 170), (62, 200), (70, 240), (100, 300)]


def ko(**kw):
    return Viewer(SAMPLES['ko'], **kw)


def sane(v, r, c):
    """Every drawn row fits the terminal and the chrome is where it belongs."""
    check(v.alive(), 'died at %dx%d' % (r, c))
    check('File' in v.row(1), 'menu bar missing at %dx%d: %r' % (r, c, v.row(1)[:40]))
    last = v.row(r).strip()
    check(last and ('no marker' in last or 'Matched' in last or '|' in last),
          'status line missing on the last row at %dx%d: %r' % (r, c, last[:60]))


@case(A)
def resize_sweep_plain():
    with ko() as v:
        for r, c in SIZES:
            v.resize(r, c)
            sane(v, r, c)
            check('=======' in '\n'.join(v.snapshot()), 'panel grip missing at %dx%d' % (r, c))


@case(A)
def resize_sweep_back_and_forth_leaves_exactly_one_status_line():
    with ko() as v:
        for r, c in SIZES + SIZES[::-1]:
            v.resize(r, c)
        n = sum(1 for l in v.snapshot() if 'no marker selected' in l)
        eq(n, 1, 'stale status lines after many resizes: %d' % n)


@case(A)
def resize_below_minimum_is_clamped_not_fatal():
    with ko() as v:
        for r, c in ((8, 40), (4, 20), (12, 60), (2, 10), (1, 1)):
            v.resize(r, c)
            check(v.alive(), 'died at %dx%d' % (r, c))
        v.resize(50, 170)
        sane(v, 50, 170)


@case(A)
def resize_keeps_tree_selection_and_hex_offset():
    with ko() as v:
        v.click(10, 4)
        v.wheel(80, 10, n=3)
        o = hex_off(v)
        for r, c in ((30, 100), (60, 200), (50, 170)):
            v.resize(r, c)
        eq(v.row(4)[0], '*', 'tree selection lost')
        check(hex_off(v) == o, 'hex offset changed across resize: %r -> %r' % (o, hex_off(v)))


@case(A)
def resize_with_selection_and_context_menu_open():
    with ko() as v:
        v.rclick(60, 6)
        v.resize(30, 100)
        check(v.alive())
        v.esc(); v.resize(50, 170)
        sane(v, 50, 170)


@case(A)
def resize_with_open_menu():
    with ko() as v:
        v.menu_open('Analysis')
        v.resize(30, 100)
        check(v.alive())
        v.esc(); sane(v, 30, 100)


@case(A)
def resize_with_field_edit_active():
    with ko() as v:
        click_in_panel(v, '[?]')
        v.type('abc')
        v.resize(30, 100)
        v.type('d'); v.key('enter')
        check('Family [abcd]' in v.row(grip(v) + 1), v.row(grip(v) + 1)[:60])


@case(A)
def resize_with_disasm_and_event_panels():
    with ko() as v:
        v.click(10, 4); v.menu_item('Analysis', 'Show disassembly')
        for r, c in ((30, 100), (24, 80), (50, 170)):
            v.resize(r, c)
            check(v.alive())
    with Viewer(FIX('events.ktr')) as v:
        v.click(10, 3)
        for r, c in ((30, 100), (24, 80), (50, 170)):
            v.resize(r, c)
            check(v.alive())


@case(A)
def resize_every_dialog_open():
    for name, opener in (('symbols', lambda v: v.menu_item('Analysis', 'Symbols')),
                         ('props', lambda v: v.menu_item('Analysis', 'Dashboard')),
                         ('keys', lambda v: v.menu_item('Help', 'Keyboard')),
                         ('about', lambda v: v.menu_item('Help', 'About')),
                         ('find', lambda v: v.menu_item('Edit', 'Find...')),
                         ('goto', lambda v: v.menu_item('Edit', 'Go to...')),
                         ('enc', lambda v: v.menu_item('Analysis', 'Decode string'))):
        with ko() as v:
            opener(v)
            for r, c in ((30, 100), (24, 80), (70, 240), (50, 170)):
                v.resize(r, c)
                check(v.alive(), '%s: died at %dx%d' % (name, r, c))
            v.esc(2)
            check(v.alive())


@case(A, known_bug='BUG-1 kof_winch is a static in kofplat.h (2 copies) so the resize wipe (ESC[2J + full repaint under a modal) never runs')
def resize_under_modal_repaints_the_panes():
    with ko() as v:
        v.menu_item('Analysis', 'Dashboard')
        v.resize(62, 200)
        # the status line must have moved to the new last row
        check('no marker selected' in v.row(62) or 'Matched' in v.row(62),
              'status line not on the new last row: %r' % v.row(62)[:50])
        check(sum(1 for l in v.snapshot() if 'no marker selected' in l) <= 1, 'stale status line left behind')


@case(A)
def resize_burst_of_32_sizes():
    with ko() as v:
        import random
        rng = random.Random(3)
        for _ in range(32):
            v.rows, v.cols = rng.choice([24, 30, 50, 70]), rng.choice([80, 120, 170, 240])
            v.screen.resize(v.rows, v.cols)
            v._setsize(v.rows, v.cols)
        v.pump_quiet(0.8, maxt=6)
        check(v.alive(), 'died after a burst of resizes')
        sane(v, v.rows, v.cols)


@case(A)
def resize_hex_row_width_tracks_columns():
    with Viewer(FIX('big64.bin')) as v:
        widths = {}
        for r, c in ((50, 100), (50, 170), (50, 240)):
            v.resize(r, c)
            a, b = hex_off(v, 2), hex_off(v, 3)
            widths[c] = b - a
        check(widths[100] <= widths[170] <= widths[240], 'row width not monotonic with columns: %r' % widths)


@case(A, known_bug='BUG-11 draw_tree follows the selection only when it changes (g_tree_followed): a shrink leaves the selected row below the visible window until the next key')
def resize_tree_follows_selection_when_height_shrinks():
    with Viewer(FIX('many.zip')) as v:
        v.click(10, 2)
        for _ in range(30):
            v.key('down', settle=0.03)
        v.resize(20, 100)
        check(any(v.row(y)[:1] == '*' for y in range(2, 20)), 'selected tree row not visible after shrinking')


@case(A)
def resize_events_table_with_filter_menu_open():
    with Viewer(FIX('events.ktr')) as v:
        v.click(10, 3)
        v.menu_open('Analysis')
        v.resize(30, 100)
        v.esc()
        check(v.alive())


@case(A, known_bug='BUG-20 term_size() clamps the layout to >= 12 rows x 60 columns whatever the terminal really is: on a 40-column terminal the viewer addresses column 60 and every line wraps into the next (it should say the terminal is too small)')
def terminal_narrower_than_the_layout_is_not_written_beyond_its_edge():
    import re
    with ko() as v:
        v.resize(20, 40)
        n = len(v.raw)
        v.key('down')
        post = bytes(v.raw[n:])
        cols = [int(m.group(1)) for m in re.finditer(rb'\x1b\[\d+;(\d+)H', post)]
        rows = [int(m.group(1)) for m in re.finditer(rb'\x1b\[(\d+);\d+H', post)]
        check(not cols or max(cols) <= 40, 'viewer addressed column %d on a 40-column terminal' % max(cols or [0]))
        check(not rows or max(rows) <= 20, 'viewer addressed row %d on a 20-row terminal' % max(rows or [0]))
        check(v.has('too small'), 'no "terminal too small" message: %r' % v.row(1)[:50])


if __name__ == '__main__':
    main(A)
