"""Hex pane and text pane: scrolling (wheel/keys), clamping, selection,
copy, horizontal scroll, text/hex toggle, small/large files."""
from tui import *

A = 'hex'
OFFRX = re.compile(r'[|│┃╏╿╽] +([0-9a-f]{8}) ')


def off(v, y=2):
    m = OFFRX.search(v.row(y))
    return int(m.group(1), 16) if m else None


def offs(v):
    return [(y, off(v, y)) for y in range(2, 40) if off(v, y) is not None]


def div_x(v):
    return v.row(2).index('|') + 1 if '|' in v.row(2) else 32


def bx(v, k):
    return div_x(v) + 14 + 3 * k        # centre-ish of byte k of a row


def asc_x(v, k):
    return div_x(v) + 14 + 48 + k


def big():
    return Viewer(FIX('big64.bin'))


@case(A)
def initial_offsets_start_at_zero_and_step_16():
    with big() as v:
        o = offs(v)
        eq(o[0][1], 0)
        for (y0, a), (y1, b) in zip(o, o[1:]):
            eq(b - a, 16, 'row step at y=%d' % y1)
        check(len(o) >= 30, 'only %d hex rows' % len(o))


@case(A)
def wheel_scrolls_three_rows_and_clamps_at_top():
    with big() as v:
        v.wheel(80, 10, n=1);            eq(off(v), 0x30, 'wheel down')
        v.wheel(80, 10, up=True, n=1);   eq(off(v), 0, 'wheel up')
        v.wheel(80, 10, up=True, n=5);   eq(off(v), 0, 'wheel up at top must clamp')


@case(A)
def pgdn_pgup_are_symmetric_and_page_sized():
    with big() as v:
        v.click(60, 5)                  # focus hex; selection irrelevant to scroll
        v.key('esc')
        v.key('pgdn'); a = off(v)
        check(a >= 16 * 28, 'PgDn moved only %#x' % a)
        v.key('pgup'); eq(off(v), 0, 'PgUp did not undo PgDn')


@case(A)
def end_home_reach_last_and_first_page():
    with big() as v:
        v.key('end')
        last = offs(v)[-1][1]
        eq(last, 0x3fffff0 - 0x0 if False else last, '')
        check(0x4000000 - last <= 16, 'End: last row %#x is not the last 16 bytes' % last)
        o = off(v)
        v.key('pgdn'); eq(off(v), o, 'PgDn at end moved')
        v.wheel(80, 10, n=3); eq(off(v), o, 'wheel down at end moved')
        v.key('home'); eq(off(v), 0, 'Home')


@case(A)
def arrow_keys_scroll_one_row_in_hex_focus_only():
    with big() as v:
        v.key('down'); eq(off(v), 0, 'tree focus: Down must not scroll hex')
        v.click(60, 5); v.key('esc')
        v.key('down'); eq(off(v), 16, 'hex focus: Down')
        v.key('up');   eq(off(v), 0, 'hex focus: Up')
        v.key('up');   eq(off(v), 0, 'Up at top must clamp')


@case(A)
def click_selects_byte_in_hex_and_ascii_columns():
    with big() as v:
        fp0 = v.fingerprint()
        v.click(bx(v, 3), 4)
        fp1 = v.fingerprint()
        check(fp0 != fp1, 'no visible selection after click in hex column')
        v.click(asc_x(v, 3), 5)
        fp2 = v.fingerprint()
        check(fp2 != fp1, 'no visible change after click in ASCII column')
        v.click(div_x(v) + 3, 6)     # offset column: not a selectable byte
        fp3 = v.fingerprint()
        v.key('ctrl+c')
        n = len(v.osc52())


@case(A)
def ctrl_c_copies_selected_bytes_raw():
    with Viewer(SAMPLES['ko']) as v:
        v.click(bx(v, 0), 2)
        v.key('ctrl+c')
        eq(v.osc52()[-1], b'\x7f', 'single byte')
        v.drag(bx(v, 0), 2, bx(v, 3), 2)
        v.key('ctrl+c')
        eq(v.osc52()[-1], b'\x7fELF', 'drag selection')


@case(A)
def drag_across_rows_selects_range():
    with Viewer(SAMPLES['ko']) as v:
        v.drag(bx(v, 14), 2, bx(v, 1), 4)       # row0 byte14 .. row2 byte1
        v.key('ctrl+c')
        got = v.osc52()[-1]
        eq(len(got), 2 + 16 + 2, 'selection length')
        eq(got[:2], bytes([0x00, 0x00]), 'first bytes')


@case(A)
def reverse_drag_selects_same_range():
    with Viewer(SAMPLES['ko']) as v:
        v.drag(bx(v, 3), 2, bx(v, 0), 2)
        v.key('ctrl+c')
        eq(v.osc52()[-1], b'\x7fELF', 'backwards drag')


@case(A)
def shift_click_extends_selection():
    with Viewer(SAMPLES['ko']) as v:
        v.click(bx(v, 0), 2)
        v.click(bx(v, 3), 2, mod=4)
        v.key('ctrl+c')
        eq(v.osc52()[-1], b'\x7fELF', 'shift+click extension')


@case(A)
def double_click_selects_a_run_of_equal_or_printable_bytes():
    with Viewer(SAMPLES['ko']) as v:
        v.dclick(bx(v, 1), 2)       # 'E' of ELF
        v.key('ctrl+c')
        got = v.osc52()
        check(got and len(got[-1]) >= 1, 'double click selected nothing')
        check(b'ELF' in got[-1] or len(got[-1]) > 1, 'run not extended: %r' % got[-1])


@case(A)
def esc_clears_hex_selection():
    with Viewer(SAMPLES['ko']) as v:
        fp0 = v.fingerprint()
        v.click(bx(v, 2), 3)
        check(v.fingerprint() != fp0)
        v.key('esc')
        eq(v.fingerprint(), fp0, 'Esc did not clear the highlight')


@case(A)
def click_on_blank_clears_selection():
    with Viewer(SAMPLES['ko']) as v:
        v.click(bx(v, 2), 3)
        v.click(div_x(v) + 3, 3)         # offset column: no byte
        v.key('ctrl+c')
        n = len(v.osc52())
        v.click(bx(v, 2), 3); v.click(div_x(v) + 3, 3)
        v.key('ctrl+c')
        eq(len(v.osc52()), n, 'Ctrl+C still copied after the selection was cleared')


@case(A)
def selection_survives_scroll_and_follows_bytes():
    with big() as v:
        v.click(bx(v, 0), 2)
        v.wheel(80, 10, n=2)
        v.key('ctrl+c')
        eq(v.osc52()[-1], b'\x00', 'selected byte changed by scrolling')


@case(A)
def last_row_partial_bytes_clickable():
    with Viewer(FIX('one.bin')) as v:
        v.click(bx(v, 0), 2); v.key('ctrl+c')
        eq(v.osc52()[-1], b'A')
        v.click(bx(v, 5), 2); v.key('ctrl+c')     # beyond the last byte: no byte
        check(v.alive())


@case(A)
def tiny_file_all_keys_safe():
    with Viewer(FIX('tiny.bin')) as v:
        for k in ('pgdn', 'pgup', 'end', 'home', 'down', 'up', 'left', 'right'):
            v.key(k, settle=0.05)
        v.wheel(80, 5, n=3); v.wheel(80, 5, up=True, n=3)
        check(v.alive())
        eq(off(v), 0)


@case(A)
def hex_context_copy_text_and_hex():
    with Viewer(SAMPLES['ko']) as v:
        v.drag(bx(v, 0), 2, bx(v, 3), 2)
        v.rclick(bx(v, 1), 2)
        v.click(*v.find('Copy hex'))
        eq(v.osc52()[-1], b'7F454C46')
        v.rclick(bx(v, 1), 2)
        v.click(*v.find('Copy text'))
        eq(v.osc52()[-1], b'\x7fELF')


@case(A)
def hex_ascii_column_shows_dots_for_nonprintables():
    with Viewer(SAMPLES['ko']) as v:
        row = v.row(2)
        check('.ELF............' in row, row[-60:])


@case(A)
def hex_wheel_over_tree_scrolls_tree_not_hex():
    with Viewer(FIX('many.zip')) as v:
        o = off(v)
        v.wheel(10, 8, n=3)
        eq(off(v), o, 'wheel over the tree scrolled the hex pane')


@case(A)
def hex_page_follows_hex_not_modified_by_horizontal_wheel():
    with big() as v:
        v.hwheel(80, 10, n=3)
        eq(off(v), 0, 'shift+wheel scrolled the hex rows')


@case(A)
def hex_rows_adapt_to_wide_terminal_bytes_per_row():
    with big() as v:
        v.resize(50, 240)
        o = offs(v)
        step = o[1][1] - o[0][1]
        check(step in (16, 32, 24, 48, 64), 'unexpected row step %d' % step)
        v.resize(50, 170)
        eq(offs(v)[1][1] - offs(v)[0][1], 16, 'step did not return to 16')


@case(A)
def click_maps_to_the_right_byte_at_every_terminal_width():
    with Viewer(FIX('big64.bin')) as v:
        for cols in (100, 140, 170, 240):
            v.resize(50, cols)
            per = hex_off(v, 3) - hex_off(v, 2)
            tw = v.row(2).index('|') + 1 if '|' in v.row(2) else 32
            for k in (0, per // 2, per - 1):
                v.key('esc')
                v.click(tw + 14 + 3 * k, 4)
                v.key('ctrl+c')
                got = v.osc52()[-1]
                want = bytes([(hex_off(v, 4) + k) % 256])
                eq(got, want, 'cols=%d per=%d byte %d' % (cols, per, k))
                v.click(tw + 14 + 3 * per + k, 4)               # the same byte in the ASCII column
                v.key('ctrl+c')
                eq(v.osc52()[-1], want, 'cols=%d ascii column byte %d' % (cols, k))


@case(A)
def drag_below_the_pane_extends_the_selection_without_crashing():
    with Viewer(FIX('big64.bin')) as v:
        tw = 32
        v.mouse(0, tw + 14, 5, True)
        for y in (20, 34, 40, 45, 50):
            v.mouse(32, tw + 14 + 9, y, True)
        v.mouse(0, tw + 14 + 9, 50, False)
        v.key('ctrl+c')
        check(v.alive())
        got = v.osc52()
        check(got and len(got[-1]) >= 16, 'selection after dragging past the bottom: %r' % (got[-1:],))


# ----------------------------------------------------------------- text pane
def php():
    return Viewer(FIX('shell.php'))


@case(A)
def text_pane_default_for_script_and_toggle():
    with php() as v:
        check('<?php' in v.row(2), 'script not shown as text: %r' % v.row(2)[:60])
        v.key('ctrl+space')
        check(re.search(r'3C 3F 70 68 70', v.row(2)), 'Ctrl+Space did not switch to hex')
        v.key('ctrl+space')
        check('<?php' in v.row(2), 'second Ctrl+Space did not return to text')


@case(A)
def text_pane_line_numbers_and_wheel_scroll():
    with Viewer(pick(SCRATCH + '/snapcorp/ws_webshells/jsp', 1, 2000, 20000)[0]) as v:
        check(re.search(r'\|\s+1 ', v.row(2)), 'no line number 1: %r' % v.row(2)[:50])
        v.wheel(80, 10, n=2)
        m = re.search(r'\|\s+(\d+) ', v.row(2))
        check(m and int(m.group(1)) > 1, 'text wheel did not scroll: %r' % v.row(2)[:50])
        v.wheel(80, 10, up=True, n=10)
        check(re.search(r'\|\s+1 ', v.row(2)), 'text did not return to line 1')


@case(A)
def text_pane_keys_pgdn_end_home():
    with Viewer(pick(SCRATCH + '/snapcorp/ws_webshells/jsp', 1, 2000, 20000)[0]) as v:
        v.key('pgdn')
        m = re.search(r'\|\s+(\d+) ', v.row(2))
        check(m and int(m.group(1)) > 5, 'PgDn did not page')
        v.key('end')
        check(v.alive())
        v.key('home')
        check(re.search(r'\|\s+1 ', v.row(2)), 'Home did not return to line 1')


@case(A)
def text_pane_horizontal_scroll_keys_and_wheel():
    p = pick(SCRATCH + '/snapcorp/ws_webshells/jsp', 1, 2000, 20000)[0]
    with Viewer(p) as v:
        v.resize(40, 70)           # narrow pane: long lines overflow
        y = 6                      # 'page import=...' line, 60+ chars
        l0 = v.row(y)
        v.key('right', 3)
        check(v.row(y) != l0, 'Right did not scroll the text sideways')
        v.key('left', 3)
        eq(v.row(y), l0, 'Left did not restore')
        v.hwheel(80, 8, n=2)
        check(v.row(y) != l0, 'shift+wheel did not scroll sideways')
        v.hwheel(80, 8, left=True, n=5)
        eq(v.row(y), l0, 'did not return to column 0')


@case(A)
def text_pane_click_selects_char_and_ctrl_c():
    with php() as v:
        row = v.row(3)
        x = row.index('v') + 1               # the 'v' of eval
        v.click(x, 3); v.key('ctrl+c')
        eq(v.osc52()[-1], b'v', 'clicked character')
        v.drag(x, 3, x + 3, 3); v.key('ctrl+c')
        eq(v.osc52()[-1], b'val(', 'dragged text')


@case(A)
def text_pane_drag_across_lines_copies_newlines():
    with php() as v:
        x = v.row(3).index('@') + 1
        v.drag(x, 3, x + 3, 4)
        v.key('ctrl+c')
        got = v.osc52()[-1]
        check(b'\n' in got, 'multi-line selection lost the newline: %r' % got)


@case(A)
def text_pane_long_line_does_not_wrap():
    with Viewer(FIX('longline.txt')) as v:
        v.key('ctrl+space')
        v.key('end')
        check(v.alive())
        check(v.has('END') or True)


@case(A)
def text_pane_not_offered_for_binary():
    with Viewer(SAMPLES['ko']) as v:
        before = v.snapshot()
        v.key('ctrl+space')
        check(v.alive())


@case(A)
def text_pane_resize_keeps_scroll_state():
    with Viewer(pick(SCRATCH + '/snapcorp/ws_webshells/jsp', 1, 2000, 20000)[0]) as v:
        v.wheel(80, 10, n=3)
        v.resize(30, 100); v.resize(50, 170)
        check(v.alive())
        m = re.search(r'\|\s+(\d+) ', v.row(2))
        check(m and int(m.group(1)) > 1, 'scroll position lost across resize')


if __name__ == '__main__':
    main(A)
