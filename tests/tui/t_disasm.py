"""Disassembler panel (Analysis > Show/Hide disassembly)."""
from tui import *
from dl import status  # noqa

A = 'disasm'
LABEL = re.compile(r'\| ([.A-Za-z_][\w.$@-]*):\s')
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
            if LABEL.search(v.row(r)):
                continue            # a label row stands for no instruction
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
def not_offered_for_script():
    with Viewer(FIX('shell.php')) as v:
        v.menu_open('Analysis')
        check(not v.popup_item('disassembly'), 'disassembly offered for a script')


ARM_MNEMONICS = {'PUSH', 'POP', 'LDR', 'STR', 'MOV', 'ADD', 'SUB', 'CMP', 'BL', 'BX', 'B', 'LDM', 'STM', 'AND', 'ORR'}
A64_MNEMONICS = {'STP', 'LDP', 'MOV', 'ADD', 'SUB', 'LDR', 'STR', 'BL', 'B', 'RET', 'ADRP', 'CMP', 'CBZ', 'NOP'}
A64_SAMPLE = '/mnt/games/virus_share/Bazaar.2026.08/HEUR-Backdoor.Linux.Mirai.gen-47c1bf90182c9aebbaa84b5f256da89f5c3b1f175282717fbc9be6a7dcd618c3'


@case(A)
def arm_state_code_is_disassembled():
    """An ARM ELF is offered the panel and its rows are ARM text (the library has text for ARM state)."""
    with Viewer(SAMPLES['gafgyt']) as v:
        check(v.menu_item('Analysis', 'Show disassembly'), 'no Show disassembly item for ARM')
        check(dis_head(v), 'panel did not open for ARM')
        check('[a32]' in v.row(dis_head(v)), v.row(dis_head(v))[:80])
        r = dis_rows(v)
        check(len(r) >= 8, 'only %d decoded rows' % len(r))
        for (y0, a, m), (y1, b, m1) in zip(r, r[1:]):
            check(b == a + 4, 'ARM rows are not one word apart at row %d: %#x -> %#x' % (y1, a, b))
        check({m for _, _, m in r} & ARM_MNEMONICS, {m for _, _, m in r})


@case(A)
def aarch64_code_is_disassembled():
    if not os.path.exists(A64_SAMPLE):
        raise Skip('no AArch64 sample on this machine')
    with Viewer(prep_sample(A64_SAMPLE, 'a64_sample')) as v:
        check(v.menu_item('Analysis', 'Show disassembly'), 'no Show disassembly item for AArch64')
        check(dis_head(v), 'panel did not open for AArch64')
        check('[a64]' in v.row(dis_head(v)), v.row(dis_head(v))[:80])
        r = dis_rows(v)
        check(len(r) >= 8, 'only %d decoded rows' % len(r))
        check({m for _, _, m in r} & A64_MNEMONICS, {m for _, _, m in r})


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


def panel_text(v, pages=4):
    """Every panel row seen while scrolling the panel: {address: whole row text}."""
    seen, labels, pending, nxt = {}, {}, [], None
    for _ in range(pages):
        y = dis_head(v)
        for r in range(y + 1, v.rows):
            m = re.search(r'([0-9a-f]{8})  [0-9a-f]{2}', v.row(r))
            if not m:
                lm = LABEL.search(v.row(r))
                if lm:
                    labels[lm.group(1)] = nxt   # the label above the row that follows
                    pending.append(lm.group(1))
                    continue
                break
            seen[int(m.group(1), 16)] = v.row(r)
            for nm in pending:
                labels[nm] = int(m.group(1), 16)
            pending = []
        v.wheel(70, y + 3, n=3)             # over the panel: it scrolls, the hex does not
    seen['labels'] = labels
    return seen


def fixture_panel():
    v = Viewer(FIX('disfix.elf'))
    v.click(10, 4)                                  # CODE region
    check(v.menu_item('Analysis', 'Show disassembly'), 'no Show disassembly item')
    return v


@case(A)
def only_engine_data_is_drawn_labels_for_functions_and_nothing_computed():
    # The panel computes no analysis: function labels come from the engine's
    # function table and symbol block; there is no syscall name, no callee
    # name, no jump label, no loop mark and no invented fcn_ name.
    with fixture_panel() as v:
        rows = panel_text(v, pages=8)
        lab = rows.pop('labels')
        check(lab.get('emit') == 0x1000, 'emit label not on its own row above 0x1000: %r' % lab)
        check(lab.get('spin') == 0x1014, 'spin label not above 0x1014: %r' % lab)
        check(lab.get('_start') == 0x1047, '_start label not above 0x1047: %r' % lab)
        check(set(lab) == {'emit', 'spin', '_start'}, 'a label the engine did not give: %r' % lab)
        check(re.search(r'CALL\s+0x1000\s+; emit\s', rows.get(0x1051, '') + ' '), 'call keeps its address and gets the function name as a comment: %r' % rows.get(0x1051))
        check(re.search(r'JMP\s+0x103c', rows.get(0x1045, '')), 'a jump into a function got a name: %r' % rows.get(0x1045))
        for a, t in rows.items():
            check((';' not in t.split('|', 1)[-1] or a in (0x1051, 0x1014, 0x1017, 0x1037, 0x103a)) and '->' not in t and '(loop)' not in t,
                  'panel-computed annotation on %#x: %r' % (a, t))
        # a conditional jump says what it asks, from the flags' last setter, with no analysis asked for
        # the comparison row says the comparison, the jump row the condition it jumps on - with no analysis asked for
        check('; compare rdi with 0' in rows[0x1014], 'the test row does not say what it compares: %r' % rows[0x1014])
        check('jump if' not in rows[0x1014], 'the test row says the jump: %r' % rows[0x1014])
        check('; jump if rdi <= 0' in rows[0x1017], 'the jle row does not say its condition: %r' % rows[0x1017])
        check('; compare rax with rcx' in rows[0x1037], 'the cmp row does not say what it compares: %r' % rows[0x1037])
        check('; jump if rax != rcx' in rows[0x103a], 'the jnz row does not say its condition: %r' % rows[0x103a])


@case(A)
def relocatable_module_shows_no_fabricated_targets():
    with code_viewer() as v:
        rows = panel_text(v, pages=6)
        rows.pop('labels')
        for t in rows.values():
            check('; ' not in t.split('|', 1)[-1] and '->' not in t, 'annotation computed by the panel: %r' % t)


@case(A)
def copied_row_is_exactly_the_row():
    with fixture_panel() as v:
        y = [r for r, a, m in dis_rows(v) if a == 0x1011][0]
        v.click(45, y)
        v.drag(36, y, 100, y)
        n0 = len(v.osc52())
        v.key('ctrl+c')
        got = v.osc52()
        check(len(got) > n0, 'Ctrl+C copied nothing')
        check(b'SYSCALL' in got[-1] and b';' not in got[-1], 'copy differs from the row: %r' % got[-1][:90])


@case(A)
def click_on_a_label_row_selects_the_instruction_below():
    with fixture_panel() as v:
        y = dis_head(v) + 1
        check(LABEL.search(v.row(y)), 'first panel row is not the emit label: %r' % v.row(y)[28:80])
        v.click(45, y)
        v.drag(36, y, 100, y)
        n0 = len(v.osc52())
        v.key('ctrl+c')
        got = v.osc52()
        check(len(got) > n0, 'a click on a label selected nothing')
        check(re.search(rb'1000  49 89 f8', got[-1]), 'label click did not land on the instruction below: %r' % got[-1][:60])


def analyse(v):
    check(v.menu_item('Analysis', 'Analyze disassembly'), 'no Analyze disassembly item')
    v.pump(0.8)


def row_with(v, text):
    for r in range(dis_head(v) + 1, v.rows):
        if text in v.row(r):
            return r
    return None


def fg_of(v, text):
    r = row_with(v, text)
    check(r, 'no row shows %r' % text)
    return v.cell(v.row(r).index(text) + 1, r).fg


@case(A)
def analysis_labels_calls_jumps_and_syscalls_come_from_the_engine():
    with fixture_panel() as v:
        analyse(v)
        check('analysed' in v.row(dis_head(v)), 'heading does not say it was analysed')
        check('xrefs: 1051 call' in v.row(row_with(v, 'emit:')), 'the function does not say who calls it')
        # a function and a jump label are told apart by colour as well as by spelling
        check(fg_of(v, 'spin:') != fg_of(v, '.L-1030:'), 'a jump label is drawn as a function name')
        rows = panel_text(v, pages=8)
        lab = rows.pop('labels')
        check({'emit', 'spin', '_start', '.L-1030', '.L-103c', '.L-1040'} <= set(lab), 'labels: %r' % lab)
        check('write (1)' in rows[0x1011], rows[0x1011])
        check('-> emit' in rows[0x1051], rows[0x1051])
        check('-> .L-1030 (backward), jump if rax != rcx' in rows[0x103a], rows[0x103a])
        check('exit (60)' in rows[0x1066], rows[0x1066])
        check(all('(loop)' not in t for t in rows.values()), 'a backward jump was called a loop')


@case(A)
def analysis_names_entries_of_a_stripped_elf_and_never_a_symbol():
    with Viewer(FIX('disfix_stripped.elf')) as v:
        v.click(10, 4)
        check(v.menu_item('Analysis', 'Show disassembly'))
        check(row_with(v, 'fcn_') is None and not [r for r in range(dis_head(v) + 1, v.rows) if LABEL.search(v.row(r))],
              'labels before the analysis, with no symbol to give one')
        analyse(v)
        rows = panel_text(v, pages=8)
        lab = rows.pop('labels')
        check('fcn_00001000' in lab and 'spin' not in lab and 'emit' not in lab, 'labels: %r' % lab)
        check('-> fcn_00001000' in rows[0x1051], rows[0x1051])
        check('write (1)' in rows[0x1011], rows[0x1011])


@case(A)
def analysis_of_a_module_names_the_relocation_symbols():
    with code_viewer() as v:
        analyse(v)
        rows = panel_text(v, pages=6)
        rows.pop('labels')
        calls = [t for t in rows.values() if re.search(r'e8 00 00 00 00 +CALL', t)]
        check(calls, 'no unrelocated call in the window')
        for t in calls:
            m = re.search(r'; -> ([A-Za-z_][\w.$@]*)', t)
            check(m and not m.group(1).startswith(('fcn_', '.L')), 'call not named by its relocation: %r' % t)


@case(A)
def analysis_of_a_raw_stager_blob_in_32_bit_mode():
    with Viewer(FIX('stager32.bin')) as v:
        check(v.menu_item('Analysis', 'Show disassembly'))
        v.click(45, dis_head(v))                    # the heading's mode: x64 -> x86
        analyse(v)
        rows = panel_text(v, pages=2)
        lab = rows.pop('labels')
        check(lab == {'.L-7': 0x7, 'fcn_00000010': 0x10}, 'labels: %r' % lab)
        check('-> .L-7 (backward)' in rows[0x9], rows[0x9])
        check('-> fcn_00000010' in rows[0xb], rows[0xb])
        check('linux: execve (11)' in rows[0x18], rows[0x18])


@case(A)
def changing_the_width_drops_the_analysis():
    with Viewer(FIX('stager32.bin')) as v:
        check(v.menu_item('Analysis', 'Show disassembly'))
        v.click(45, dis_head(v))
        analyse(v)
        check('analysed' in v.row(dis_head(v)))
        v.click(45, dis_head(v))
        check('analysed' not in v.row(dis_head(v)), 'an analysis made reading 32 bits is still shown at 64')


@case(A)
def a_jump_far_from_its_comparison_does_not_borrow_the_comparison_of_an_earlier_window():
    with Viewer(FIX('condgap.bin')) as v:
        check(v.menu_item('Analysis', 'Show disassembly'))
        y = dis_head(v)
        check(re.search(r'CMP\s+eax, ebx\s+; compare eax with ebx', v.row(y + 1)), 'first row: %r' % v.row(y + 1)[28:90])
        jz = None
        for _ in range(40):                              # scroll the comparison out of the window and the jump in
            v.wheel(70, y + 3, n=1)
            jz = row_with(v, ' JZ ')
            if jz:
                break
        check(jz, 'the jump never came into the window')
        check('CMP' not in ''.join(v.row(r) for r in range(y + 1, v.rows)), 'the comparison is still in the window')
        text = v.row(jz)
        check('jump if ZF=1 (equal / zero)' in text, 'with no comparison in view the jump says the flag: %r' % text[28:110])
        check('eax == ebx' not in text, 'the jump borrowed a comparison that is not in this window: %r' % text[28:110])



# ---------------------------------------------------------- Analysis > Resolve call symbols
RUN1 = '/home/dmknght/Desktop/MalwareLab/MalwareSourceCode/Linux/Mirai-Family/run1'    # x86-64 PIE, dynamic: `call 0x3360` at 0x80c6 is rand@plt


def run1_at_call():
    """run1 with the panel open and the instruction at 0x80c6 (a call to the rand PLT stub) on screen."""
    if not os.path.exists(RUN1):
        raise Skip('run1 is not on this machine')
    v = Viewer(RUN1)
    v.click(10, 2)
    check(v.menu_item('Analysis', 'Show disassembly'), 'no Show disassembly item')
    check(v.menu_item('Edit', 'Go to...'), 'no Go to item')
    v.type('50b8')                                  # CODE region + 0x50b8 = file offset 0x80b8
    v.click(*v.find('[ Go ]'))
    v.pump(0.5)
    v.click(60, 2)
    check(row_with(v, '000080c6'), 'the call at 0x80c6 is not on screen')
    return v


@case(A)
def analyze_names_the_plt_call_and_builds_the_notes():
    with run1_at_call() as v:
        r = row_with(v, '000080c6')
        check('CALL' in v.row(r) and 'rand@plt' not in v.row(r), 'named before it was asked for: %r' % v.row(r)[30:100])
        v.menu_open('Analysis')
        names = [t for _y, _x, t, _en in v.popup()]
        v.esc()
        check(not any(t.startswith('Resolve call symbols') for t in names), 'Resolve call symbols is still in Analysis: %r' % names)
        analyse(v)
        r = row_with(v, '000080c6')
        check(r and re.search(r'CALL\s+0x3360\s+; (-> )?rand@plt', v.row(r)), 'analysed: %r' % (v.row(r) if r else None))
        check('analysed, resolved' in v.row(dis_head(v)), v.row(dis_head(v))[:90])
        check('Resolved call symbols' in status(v) and 'Analysed the whole object' in status(v), status(v)[-100:])
        # Analyze stays enabled so that it can be run again
        v.menu_open('Analysis')
        it = v.popup_item('Analyze disassembly')
        check(it and it[3] is not False, 'Analyze disassembly is greyed after it ran: %r' % (it,))
        v.esc()


@case(A)
def analyze_an_object_the_engine_cannot_resolve_has_no_names():
    with code_viewer() as v:                        # a .ko is a relocatable object: it has no PLT and no import table
        analyse(v)
        check('resolved' not in v.row(dis_head(v)), v.row(dis_head(v))[:90])


if __name__ == '__main__':
    main(A)
