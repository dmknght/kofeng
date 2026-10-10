"""Disassembler panel (Analysis > Show/Hide disassembly)."""
from tui import *

A = 'disasm'
LINE = re.compile(r'([0-9a-f]{8})  ((?:[0-9a-f]{2} ?)+)\s+([A-Z][A-Z0-9]*)')


def dis_head(v):
    for y in range(2, v.rows):
        if '-- Disassembly' in v.row(y):
            return y
    return None


def dis_rows(v):
    y = dis_head(v)
    out = []
    if y is None:
        return out
    for r in range(y + 1, v.rows):
        m = LINE.search(v.row(r))
        if not m:
            break
        out.append((r, int(m.group(1), 16), m.group(3)))
    return out


def code_viewer():
    v = Viewer(SAMPLES['ko'])
    v.click(10, 4)                                  # CODE region
    check(v.menu_item('Analysis', 'Show disassembly'), 'no Show disassembly item')
    check(dis_head(v), 'panel did not open')
    return v


@case(A)
def open_close_via_menu_and_label_toggles():
    with code_viewer() as v:
        v.menu_open('Analysis')
        check(v.popup_item('Hide disassembly'), 'label did not become Hide')
        v.click(*(lambda p: (p[1] + 2, p[0]))(v.popup_item('Hide disassembly')))
        check(dis_head(v) is None, 'panel still shown after Hide')
        v.menu_open('Analysis')
        check(v.popup_item('Show disassembly'), 'label did not return to Show')
        v.esc()


@case(A)
def heading_names_architecture():
    with code_viewer() as v:
        check('[x64]' in v.row(dis_head(v)), v.row(dis_head(v))[:80])
    p = pick(SAMPLES['pe'], 1, 30000, 200000)[0]
    with Viewer(p) as v:
        v.click(10, 4)
        v.menu_item('Analysis', 'Show disassembly')
        check(dis_head(v) and '[x86]' in v.row(dis_head(v)), 'PE-x86 heading: %r' % v.row(dis_head(v) or 2)[:80])


@case(A)
def rows_are_address_bytes_mnemonic():
    with code_viewer() as v:
        v.click(60, 6)
        r = dis_rows(v)
        check(len(r) >= 12, 'only %d decoded rows' % len(r))
        for (y0, a, m), (y1, b, m1) in zip(r, r[1:]):
            check(b > a, 'addresses not increasing at row %d' % y1)
        mnems = {m for _, _, m in r}
        check(mnems & {'MOV', 'JMP', 'NOP', 'PUSH', 'CALL', 'LEA', 'RET', 'SUB', 'ADD'}, mnems)


@case(A)
def panel_follows_hex_scroll():
    with code_viewer() as v:
        a0 = dis_rows(v)[0][1]
        v.wheel(80, 10, n=2)                 # over the hex pane
        a1 = dis_rows(v)[0][1]
        check(a1 > a0, 'panel did not follow the hex wheel: %#x -> %#x' % (a0, a1))
        v.key('pgdn')
        a2 = dis_rows(v)[0][1]
        check(a2 > a1, 'panel did not follow PgDn')


@case(A)
def wheel_over_panel_moves_panel_only():
    with code_viewer() as v:
        hex0 = v.row(2)[32:46]
        a0 = dis_rows(v)[0][1]
        y = dis_head(v) + 3
        v.wheel(70, y, n=2)
        a1 = dis_rows(v)[0][1]
        check(a1 != a0, 'panel did not move')
        eq(v.row(2)[32:46], hex0, 'hex pane scrolled by a wheel over the panel')
        v.wheel(70, y, up=True, n=5)
        eq(dis_rows(v)[0][1], a0, 'panel did not return to the hex position')


@case(A)
def click_hex_byte_brings_instruction_into_panel_and_highlights():
    with code_viewer() as v:
        v.click(60, 14)
        want = int(re.search(r'([0-9a-f]{8}) ', v.row(14)[32:]).group(1), 16)
        rows = dis_rows(v)
        check(any(a <= want + 4 and a + 16 > want - 4 for _, a, _ in rows), 'clicked offset %#x not in panel %r' % (want, rows[:3]))


@case(A)
def click_panel_line_selects_and_ctrl_c_copies_text():
    with code_viewer() as v:
        v.click(60, 6)
        y = dis_rows(v)[2][0]
        fp = v.fingerprint()
        v.click(45, y)
        check(v.fingerprint() != fp, 'no highlight after clicking a disassembly line')
        v.drag(36, y, 70, y + 1)
        n0 = len(v.osc52())
        v.key('ctrl+c')
        got = v.osc52()
        check(len(got) > n0, 'Ctrl+C copied nothing')
        check(re.search(rb'[0-9a-f]{8}  ', got[-1]), 'copied text is not disassembly: %r' % got[-1][:60])


@case(A)
def panel_context_menu_items_and_copy_hex():
    with code_viewer() as v:
        v.click(60, 6)
        y = dis_rows(v)[1][0]
        v.drag(36, y, 60, y)
        v.rclick(45, y)
        for it in ('Copy', 'Copy hex', 'Declare as hex', 'Decode string', 'Find string', 'Find hex'):
            check(v.has(it), 'panel menu missing %r' % it)
        v.click(*v.find('Copy hex'))
        got = v.osc52()[-1]
        check(re.fullmatch(rb'[0-9A-F]+', got), 'Copy hex gave %r' % got)


@case(A, known_bug='BUG-6 click_hex never clears dis_have: a stale disassembly-text selection beats a newer hex selection on Ctrl+C')
def stale_disasm_selection_does_not_beat_new_hex_selection():
    with code_viewer() as v:
        y0 = dis_rows(v)[0][0]
        v.drag(36, y0, 60, y0 + 1)                 # select two panel lines
        v.key('ctrl+c')
        old = v.osc52()[-1]
        tw = 32
        v.drag(tw + 14, 12, tw + 14 + 9, 12)       # now select 4 bytes in the hex pane, row 12
        v.key('ctrl+c')
        new = v.osc52()[-1]
        check(new != old, 'Ctrl+C returned the stale panel selection: %r' % new[:50])


@case(A)
def ctrl_c_with_panel_open_copies_disassembly_of_hex_selection():
    # Observed design: with the panel open Ctrl+C on a hex selection copies the
    # instructions, not the raw bytes (raw bytes only when the panel is closed).
    with code_viewer() as v:
        tw = 32
        v.drag(tw + 14, 12, tw + 14 + 9, 12)
        v.key('ctrl+c')
        got = v.osc52()[-1]
        check(re.search(rb'[0-9a-f]{8}  ', got), 'unexpected: %r' % got[:40])


@case(A)
def panel_absent_for_symbol_view_and_back():
    with code_viewer() as v:
        v.click(10, 8)               # SYM_IMP
        check(dis_head(v) is None, 'panel shown over the symbol view')
        v.click(10, 4)
        check(dis_head(v), 'panel did not come back for a code region')


@case(A)
def panel_height_adapts_to_terminal():
    with code_viewer() as v:
        n50 = len(dis_rows(v))
        v.resize(30, 120)
        n30 = len(dis_rows(v))
        check(0 < n30 < n50, 'rows %d -> %d' % (n50, n30))
        v.resize(70, 200)
        check(len(dis_rows(v)) > n50, 'panel did not grow with the terminal')


@case(A, known_bug='BUG-8 redraw(): dis_open is cleared when the terminal is too short ("nowhere to put it") and never restored')
def panel_survives_a_temporary_shrink():
    with code_viewer() as v:
        v.resize(14, 70)
        v.resize(50, 170)
        check(dis_head(v), 'disassembly panel did not come back after shrinking to 14 rows and growing again')


@case(A)
def not_offered_for_arm_and_script():
    with Viewer(SAMPLES['gafgyt']) as v:
        v.menu_open('Analysis')
        check(not v.popup_item('disassembly'), 'disassembly offered for ARM: %r' % [t for _, _, t, _ in v.popup()])
    with Viewer(FIX('shell.php')) as v:
        v.menu_open('Analysis')
        check(not v.popup_item('disassembly'), 'disassembly offered for a script')


@case(A)
def offered_for_raw_bytes_with_mode_choice():
    with Viewer(FIX('tiny.bin')) as v:
        v.menu_open('Analysis')
        it = v.popup_item('disassembly')
        if not it:
            raise Skip('not offered for Raw in this build')
        v.click(it[1] + 2, it[0])
        check(v.alive())


@case(A)
def panel_disables_when_no_bytes_to_show():
    with Viewer(SAMPLES['ko']) as v:
        v.click(10, 2)
        v.menu_item('Analysis', 'Show disassembly')
        check(v.alive())
        v.click(10, 7)               # UNCLAIMED
        check(v.alive())


@case(A)
def panel_close_other_way_menu_twice():
    with code_viewer() as v:
        for _ in range(3):
            v.menu_item('Analysis', 'Hide disassembly')
            check(dis_head(v) is None)
            v.menu_item('Analysis', 'Show disassembly')
            check(dis_head(v))


if __name__ == '__main__':
    main(A)
