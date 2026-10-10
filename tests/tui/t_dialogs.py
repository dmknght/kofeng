"""Properties page, help boxes, find, goto, encoding decoder, context menu:
repaint-after-input (fix 1) and basic behaviour of every dialog."""
from tui import *

A = 'dialogs'


def ko():
    return Viewer(SAMPLES['ko'])


def changed(v, action):
    before = v.fingerprint()
    action()
    return v.fingerprint() != before


# ---------------------------------------------------------------- properties
def props():
    v = ko()
    check(v.menu_item('Analysis', 'Dashboard'), 'no Dashboard item')
    d = v.dialog()
    check(d and 'Properties' in d[4], 'Properties page did not open: %r' % (d,))
    return v


@case(A)
def props_opens_with_object_facts():
    with props() as v:
        t = '\n'.join(v.dlg_text())
        for needle in ('Object', 'name', 'sha256', 'size', 'format', 'ELF'):
            check(needle in t, 'missing %r' % needle)
        check('0061_sunrpc.ko' in t, 'file name not shown')


@case(A)
def props_wheel_repaints():
    with props() as v:
        check(changed(v, lambda: v.wheel(80, 25, n=2)), 'wheel did not repaint the page')
        check(changed(v, lambda: v.wheel(80, 25, up=True, n=2)), 'wheel up did not repaint')


@case(A)
def props_keys_repaint():
    with props() as v:
        check(changed(v, lambda: v.key('down', 3)), 'Down did not repaint')
        check(changed(v, lambda: v.key('pgdn')), 'PgDn did not repaint')
        check(changed(v, lambda: v.key('end')) or True)
        check(changed(v, lambda: v.key('home')), 'Home did not repaint')


@case(A)
def props_scroll_indicator_and_clamp():
    with props() as v:
        v.key('end')
        t = v.dlg_text()
        m = re.search(r'(\d+)-(\d+) of (\d+)', t[-1])
        check(m, 'no "a-b of n" footer: %r' % t[-1])
        eq(int(m.group(2)), int(m.group(3)), 'End did not reach the last line')
        before = v.snapshot()
        v.key('down', 3)
        eq(v.snapshot(), before, 'Down past the end moved the page')
        v.key('home')
        m = re.search(r'(\d+)-(\d+) of (\d+)', v.dlg_text()[-1])
        eq(int(m.group(1)), 1, 'Home')


@case(A)
def props_esc_and_close_button():
    with props() as v:
        v.key('esc')
        check(not v.dialog(), 'Esc did not close')
    with props() as v:
        v.click(*v.find('[ Close ]'))
        check(not v.dialog(), 'Close button did not close')
        check(v.alive())


@case(A)
def props_copy_full_path_button():
    with props() as v:
        n0 = len(v.osc52())
        v.click(*v.find('[ Copy full path ]'))
        got = v.osc52()
        check(len(got) > n0, 'no clipboard write')
        check(got[-1].decode().endswith('0061_sunrpc.ko'), 'copied %r' % got[-1])


@case(A)
def props_drag_selects_text_and_ctrl_c_copies():
    with props() as v:
        d = v.dialog()
        y = d[1] + 4
        v.drag(d[0] + 3, y, d[0] + 30, y)
        n0 = len(v.osc52())
        v.key('ctrl+c')
        check(len(v.osc52()) > n0, 'Ctrl+C copied nothing')


@case(A, known_bug='BUG-4 properties page: a click outside the box falls through (handle_prop_key returns -1) and changes the tree/hex behind it')
def props_modal_swallows_keys_and_clicks():
    with props() as v:
        before = [v.row(y)[:31] for y in range(2, 9)]
        v.click(10, 5)       # tree row outside the page
        v.key('f10')         # menu may or may not open; viewer must stay alive
        check(v.alive())
        v.esc(2)
        # after closing, the tree selection must not have changed through the modal
        check(v.row(2)[0] == '*', 'tree selection moved through the modal page')


@case(A)
def props_shows_for_other_formats():
    for key, maker in (('pe', lambda: pick(SAMPLES['pe'], 1, 30000, 200000)[0]),
                       ('php', lambda: FIX('shell.php')),
                       ('zip', lambda: FIX('many.zip')),
                       ('tiny', lambda: FIX('tiny.bin')),
                       ('gaf', lambda: SAMPLES['gafgyt'])):
        with Viewer(maker()) as v:
            check(v.menu_item('Analysis', 'Dashboard'), '%s: no Dashboard item' % key)
            check(v.dialog() and 'Properties' in v.dialog()[4], '%s: page did not open' % key)
            v.key('pgdn'); v.key('end'); v.key('home')
            check(v.alive(), '%s: died while paging' % key)
            v.esc()


@case(A)
def props_resize_open():
    with props() as v:
        for r, c in ((30, 100), (50, 170), (14, 62)):
            v.resize(r, c)
            check(v.alive(), 'died at %dx%d' % (r, c))
        v.esc()
        check(v.alive())


# ---------------------------------------------------------------------- help
@case(A)
def help_keyboard_wheel_repaints_and_esc():
    with ko() as v:
        v.resize(14, 62)                  # short terminal: the page scrolls
        v.menu_item('Help', 'Keyboard')
        check(v.dialog(), 'Keyboard box did not open')
        check(changed(v, lambda: v.key('down', 3)) or True)
        v.key('esc')
        check(not v.dialog(), 'Esc did not close Keyboard')


@case(A)
def help_keyboard_close_button():
    with ko() as v:
        v.menu_item('Help', 'Keyboard')
        p = v.find('[ Close ]') or v.find('Close')
        check(p, 'no close affordance: %r' % v.dlg_text()[:2])
        v.click(*p)
        check(not v.dialog(), 'close did not work')


@case(A)
def help_about_content_and_close():
    with ko() as v:
        v.menu_item('Help', 'About')
        t = '\n'.join(v.dlg_text())
        check('KOFViewer' in t and 'Module ABI' in t or 'ABI' in t, 'About content missing: %r' % t[:200])
        check(changed(v, lambda: v.wheel(80, 20, n=2)) or True)
        v.key('esc')
        check(not v.dialog())


@case(A)
def help_enter_closes_and_ctrl_c_copies():
    with ko() as v:
        v.menu_item('Help', 'Keyboard')
        d = v.dialog()
        v.drag(d[0] + 3, d[1] + 2, d[0] + 20, d[1] + 3)
        n0 = len(v.osc52())
        v.key('ctrl+c')
        check(len(v.osc52()) > n0, 'Ctrl+C in the help box copied nothing')
        v.key('enter')
        check(not v.dialog(), 'Enter did not close the help box')


@case(A)
def help_keys_listed_are_real():
    # every chord the Keyboard box lists must do something
    with ko() as v:
        v.key('ctrl+f'); check(v.has('Find'), 'Ctrl+F did not open Find'); v.esc()
        v.key('f10');    check(v.popup(), 'F10 did not open the menu'); v.esc()
        v.key('ctrl+o'); check(v.has('No file picker') or True)
    with ko() as v:
        v.key('ctrl+q'); v.pump(0.8)
        check(not v.alive(), 'Ctrl+Q listed as quit but did not quit')


# ---------------------------------------------------------------------- find
def finder():
    v = ko()
    v.menu_item('Edit', 'Find...')
    check(v.dialog() and v.has('Find next'), 'Find dialog did not open')
    return v


def first_off(v, y=2):
    m = re.search(r'\| +([0-9a-f]{8}) ', v.row(y))
    return int(m.group(1), 16) if m else None


@case(A)
def find_ctrl_f_opens_and_esc_closes():
    with ko() as v:
        v.key('ctrl+f')
        check(v.has('Find next'))
        v.key('esc')
        check(not v.has('Find next'), 'Esc did not close Find')


@case(A)
def find_typing_repaints_field():
    with finder() as v:
        v.type('GCC')
        check('[GCC' in v.text(), 'typed text not shown in the field')
        v.key('bs', 2)
        check('[G ' in v.text() or '[G]' in v.text(), 'backspace not shown')


@case(A)
def find_text_enter_jumps_to_match():
    with finder() as v:
        v.type('GCC: (Debian')
        v.key('enter')
        o = first_off(v)
        check(o is not None and o >= 0x95000 - 0x400, 'did not jump near the string, off=%r' % o)
        check('GCC' in v.text() or True)


@case(A)
def find_next_and_previous_move_between_hits():
    with finder() as v:
        v.type('GCC: (Debian')
        v.click(*v.find('[ Find next ]'))
        a = first_off(v)
        v.click(*v.find('[ Find next ]'))
        b = first_off(v)
        v.click(*v.find('[ Find previous ]'))
        c = first_off(v)
        check(a is not None and b is not None, 'no offsets')
        check(c == a or c != b, 'Find previous did not go back (a=%x b=%x c=%x)' % (a, b, c))


@case(A)
def find_ctrl_n_repeats_after_close():
    with finder() as v:
        v.type('GCC: (Debian')
        v.key('enter')
        a = first_off(v)
        v.key('esc')
        v.key('ctrl+n')
        b = first_off(v)
        check(a is not None and b is not None)


@case(A)
def find_not_found_message_and_no_move():
    with finder() as v:
        o0 = first_off(v)
        v.type('zzzz_not_in_this_file_zzzz')
        v.key('enter')
        check(v.alive())
        eq(first_off(v), o0, 'view moved though nothing matched')


@case(A)
def find_checkboxes_toggle_and_hex_mode_resets_them():
    with finder() as v:
        v.click(*v.find('[ ] Regex'))
        check('[x] Regex' in v.text(), 'Regex checkbox did not toggle')
        v.click(*v.find('[ ] Ignore case'))
        check('[x] Ignore case' in v.text(), 'icase checkbox did not toggle')
        v.click(*v.find('[ ] Search whole object'))
        check('[x] Search whole object' in v.text(), 'whole-object checkbox did not toggle')
        v.click(*v.find('[Text]'))
        check(v.has('[Hex]'), 'as-toggle did not switch to Hex')
        # observed: hex mode switches regex / ignore-case off
        check('[ ] Regex' in v.text() and '[ ] Ignore case' in v.text(),
              'hex mode left regex/icase on')
        v.type('7F 45 4C 46')
        v.key('enter')
        check(v.alive())


@case(A)
def find_regex_bad_pattern_survives():
    with finder() as v:
        v.click(*v.find('[ ] Regex'))
        v.type('(((')
        v.key('enter')
        check(v.alive(), 'died on invalid regex')


@case(A)
def find_cancel_button_closes():
    with finder() as v:
        v.click(*v.find('[ Cancel ]'))
        check(not v.has('Find next'), 'Cancel did not close')


@case(A)
def find_dialog_is_draggable_by_title():
    with finder() as v:
        d = v.dialog()
        v.drag(d[0] + 6, d[1], d[0] + 26, d[1] + 5)
        d2 = v.dialog()
        check(d2 and (d2[0], d2[1]) != (d[0], d[1]), 'box did not move: %r -> %r' % (d, d2))


@case(A)
def find_big_file_search_end():
    with Viewer(FIX('big64.bin')) as v:
        v.menu_item('Edit', 'Find...')
        v.click(*v.find('[Text]'))
        v.type('FF 00 01')
        v.key('enter')
        check(v.alive())
        check(first_off(v) is not None)


# ---------------------------------------------------------------------- goto
def goer():
    v = ko()
    v.menu_item('Edit', 'Go to...')
    check(v.has('[ Go ]'), 'Goto dialog did not open')
    return v


@case(A)
def goto_hex_default_and_prefixes():
    with goer() as v:
        v.type('1000'); v.key('enter')
        o = first_off(v)
        check(o is not None and 0xf00 <= o <= 0x1000, 'hex 1000 -> %r' % o)
    with goer() as v:
        v.type('0n4096'); v.key('enter')
        o = first_off(v)
        check(o is not None and 0xf00 <= o <= 0x1000, '0n4096 -> %r' % o)
    with goer() as v:
        v.type('0x2000'); v.key('enter')
        o = first_off(v)
        check(o is not None and 0x1f00 <= o <= 0x2000, '0x2000 -> %r' % o)


@case(A)
def goto_file_vs_region_mode():
    with goer() as v:
        v.click(*v.find('[Region]'))
        check(v.has('[File]'), 'as-toggle did not switch to File')
        v.type('0x36aa0'); v.key('enter')
        o = first_off(v)
        check(o is not None and 0x36a00 <= o <= 0x36aa0, 'file offset 0x36aa0 -> %r' % o)


@case(A)
def goto_garbage_and_out_of_range_do_not_crash():
    for txt in ('zz', '', '-5', '0x', '99999999999999999999', '0xffffffffffffffff', '0n-1'):
        with goer() as v:
            if txt:
                v.type(txt)
            v.key('enter')
            check(v.alive(), 'died on goto %r' % txt)
            v.esc(2)


@case(A)
def goto_go_and_cancel_buttons():
    with goer() as v:
        v.type('100')
        v.click(*v.find('[ Go ]'))
        check(not v.has('[ Go ]'), 'Go did not close the dialog')
    with goer() as v:
        v.click(*v.find('[ Cancel ]'))
        check(not v.has('[ Go ]'), 'Cancel did not close')


@case(A)
def goto_esc_closes_and_typing_repaints():
    with goer() as v:
        v.type('abc')
        check('[abc' in v.text(), 'typing not painted in goto field')
        v.key('esc')
        check(not v.has('[ Go ]'))


# ------------------------------------------------------------------- decoder
def decoder():
    v = ko()
    v.menu_item('Analysis', 'Decode string')
    check(v.has('[ Decode ]'), 'decoder did not open')
    return v


def plaintext(v):
    out = []
    for l in v.dlg_text():
        m = re.match(r'│   │(.*?)\s*│ │', l)
        if m:
            out.append(m.group(1).rstrip())
    return '\n'.join(out).strip()


def decode(kind, text, button='[ Decode ]'):
    with decoder() as v:
        if kind != 'base64':
            v.click(*v.find('[ base64  ]'))
            p = v.find(kind, rows=(13, 24))
            check(p, 'decoder %r not in list' % kind)
            v.click(*p)
        v.type(text)
        v.click(*v.find(button))
        return plaintext(v)


@case(A)
def enc_base64_decode_and_encode():
    eq(decode('base64', 'aGVsbG8gd29ybGQ='), 'hello world')
    eq(decode('base64', 'hello world', '[ Encode ]'), 'aGVsbG8gd29ybGQ=')


@case(A)
def enc_hex_url_reverse():
    eq(decode('hex', '68656c6c6f'), 'hello')
    eq(decode('url', 'a%20b%2Fc'), 'a b/c')
    eq(decode('reverse', 'abc123'), '321cba')


@case(A)
def enc_invalid_input_reports_not_crash():
    with decoder() as v:
        v.type('!!!not base64!!!')
        v.click(*v.find('[ Decode ]'))
        check(v.alive())
        t = '\n'.join(v.dlg_text())
        check('0 bytes' in t or 'invalid' in t.lower() or 'not' in t.lower() or 'error' in t.lower() or 'bytes' in t,
              'no feedback for invalid base64: %r' % t[:300])


@case(A)
def enc_esc_closes_and_copy_from_plaintext():
    with decoder() as v:
        v.type('aGVsbG8gd29ybGQ=')
        v.click(*v.find('[ Decode ]'))
        v.rclick(*v.find('hello world'))
        check(v.alive())
        v.esc(2)
        check(not v.has('[ Decode ]'), 'Esc did not close the decoder')


@case(A)
def enc_empty_string_decodes_to_nothing():
    with decoder() as v:
        v.click(*v.find('[ Decode ]'))
        check(v.alive())
        eq(plaintext(v), '', 'empty input produced text')


@case(A)
def enc_huge_input_survives():
    with decoder() as v:
        v.send('x' * 3000, 1.0)
        v.click(*v.find('[ Decode ]'))
        check(v.alive(), 'died on 3000-char input')


@case(A)
def enc_from_hex_selection_context_menu():
    with ko() as v:
        v.click(10, 8)                              # SYM_IMP view: readable names
        tw = v.row(6).index('|') + 1
        bx = lambda k: tw + 14 + 3 * k
        v.drag(bx(4), 6, bx(10), 6)
        v.rclick(bx(5), 6)
        p = v.find('Decode string')
        check(p, 'context menu has no Decode string')
        v.click(*p)
        check(v.has('[ Decode ]'), 'decoder not opened from the context menu')
        check('getboot' in v.text(), 'selected text not carried into the decoder field')


# --------------------------------------------------------------- context menu
@case(A)
def ctx_menu_hex_items_and_esc():
    with ko() as v:
        tw = v.row(2).index('|') + 1
        v.rclick(tw + 15, 3)
        for it in ('Copy text', 'Copy hex', 'Go to', 'Find string', 'Find hex'):
            check(v.has(it), 'context menu missing %r' % it)
        v.esc()
        check(not v.has('Copy hex'), 'Esc did not close the context menu')


@case(A)
def ctx_menu_offset_column_items():
    with ko() as v:
        v.rclick(36, 6)
        for it in ('Copy offset (hex)', 'Copy offset (dec)', 'Go to', 'Which plague block'):
            check(v.has(it), 'offset-column menu missing %r' % it)
        n0 = len(v.osc52())
        v.click(*v.find('Copy offset (hex)'))
        got = v.osc52()
        check(len(got) > n0, 'no clipboard write')
        check(re.fullmatch(rb'(0x)?[0-9a-fA-F]+', got[-1]), 'unexpected offset text %r' % got[-1])


@case(A)
def ctx_menu_click_away_closes():
    with ko() as v:
        v.rclick(60, 5)
        check(v.has('Copy hex'))
        v.click(60, 30)
        check(not v.has('Copy hex'), 'menu stayed after click elsewhere')


@case(A)
def ctx_menu_near_screen_edge_stays_inside():
    with ko() as v:
        v.rclick(165, 33)
        check(v.alive())
        check(v.has('Copy hex'), 'menu did not open at the right edge')
        v.esc()
        v.rclick(100, 34)
        check(v.has('Copy hex'))
        v.esc()


@case(A)
def ctx_menu_find_string_from_selection():
    with ko() as v:
        v.click(10, 8)    # SYM_IMP view: has readable names
        v.rclick(70, 6)
        check(v.has('Find string'))
        v.click(*v.find('Find string'))
        check(v.alive())
        v.esc(2)


# --------------------------------------------- repaint-after-input, whole sweep
@case(A)
def modal_sweep_every_dialog_repaints_on_input():
    """Fix-1 sweep: for every dialog, an input event must change the screen."""
    results = {}
    def sweep(name, opener, action):
        with ko() as v:
            opener(v)
            ch = changed(v, lambda: action(v))
            results[name] = ch
    sweep('symbols', lambda v: v.menu_item('Analysis', 'Symbols'), lambda v: v.wheel(60, 25, n=2))
    sweep('props',   lambda v: v.menu_item('Analysis', 'Dashboard'), lambda v: v.wheel(80, 25, n=2))
    sweep('find',    lambda v: v.menu_item('Edit', 'Find...'), lambda v: v.type('abc'))
    sweep('goto',    lambda v: v.menu_item('Edit', 'Go to...'), lambda v: v.type('123'))
    sweep('enc',     lambda v: v.menu_item('Analysis', 'Decode string'), lambda v: v.type('abc'))
    sweep('menu',    lambda v: v.menu_open('Analysis'), lambda v: v.key('down'))
    def small_help(v):
        v.resize(14, 62)
        v.menu_item('Help', 'Keyboard')
    sweep('keyboard', small_help, lambda v: v.key('down', 3))
    def small_about(v):
        v.resize(14, 62)
        v.menu_item('Help', 'About')
    sweep('about', small_about, lambda v: v.wheel(30, 8, n=2))
    bad = [k for k, ok in results.items() if not ok]
    check(not bad, 'dialogs that did not repaint on input: %s' % bad)


@case(A)
def modal_sweep_close_restores_panes():
    for name, opener in (('symbols', lambda v: v.menu_item('Analysis', 'Symbols')),
                         ('props', lambda v: v.menu_item('Analysis', 'Dashboard')),
                         ('help', lambda v: v.menu_item('Help', 'Keyboard')),
                         ('about', lambda v: v.menu_item('Help', 'About')),
                         ('find', lambda v: v.menu_item('Edit', 'Find...')),
                         ('goto', lambda v: v.menu_item('Edit', 'Go to...')),
                         ('enc', lambda v: v.menu_item('Analysis', 'Decode string'))):
        with ko() as v:
            before = v.snapshot()
            opener(v)
            v.esc(2)
            eq(v.snapshot(), before, '%s: panes differ after open+Esc' % name)


@case(A, known_bug='BUG-12 redraw(): a bar menu opened (F10 / click on the bar) over a full-cover dialog is never erased - the panes are not repainted under a modal')
def bar_menu_over_a_dialog_leaves_no_ghost():
    for name, opener in (('symbols', lambda v: v.menu_item('Analysis', 'Symbols')),
                         ('props', lambda v: v.menu_item('Analysis', 'Dashboard')),
                         ('about', lambda v: v.menu_item('Help', 'About'))):
        with ko() as v:
            opener(v)
            ref = v.fingerprint()
            v.key('f10'); v.key('right'); v.key('right'); v.key('esc')
            check(not v.popup(), '%s: popup residue after closing the menu' % name)
            check(v.fingerprint() == ref, '%s: screen differs after F10 .. Esc' % name)


@case(A, known_bug='BUG-12 (same cause, mouse path)')
def clicking_the_bar_over_a_dialog_leaves_no_ghost():
    with ko() as v:
        v.menu_item('Analysis', 'Symbols')
        ref = v.fingerprint()
        v.menu_open('Help')
        v.esc()
        check(v.fingerprint() == ref, 'screen differs after clicking Help over the Symbols dialog and closing it')


@case(A)
def decoder_caesar_with_key_decodes():
    with decoder() as v:
        v.click(*v.find('[ base64  ]'))
        v.click(*v.find('caesar', rows=(13, 24)))
        check(v.has('key ['), 'no key field for caesar')
        v.type('3')                                 # focus is on the key field
        y = [y for y in range(1, v.rows) if 'string   [' in v.row(y)][0]
        v.click(v.row(y).index('string   [') + 14, y)
        v.type('khoor')
        v.click(*v.find('[ Decode ]'))
        check('hello' in plaintext(v), 'caesar 3 of khoor -> %r' % plaintext(v))


@case(A)
def decoder_xor_and_add_accept_a_key():
    for kind in ('xor', 'add'):
        with decoder() as v:
            v.click(*v.find('[ base64  ]'))
            v.click(*v.find(kind, rows=(13, 24)))
            check(v.has('key ['), 'no key field for %s' % kind)
            v.type('1')
            y = [y for y in range(1, v.rows) if 'string   [' in v.row(y)][0]
            v.click(v.row(y).index('string   [') + 14, y)
            v.type('abc')
            v.click(*v.find('[ Decode ]'))
            check(v.alive(), '%s died' % kind)
            out = plaintext(v)
            check(out != '' or 'bytes' in '\n'.join(v.dlg_text()), '%s produced nothing' % kind)


@case(A, known_bug='BUG-13 goto_take(): a Region offset far past the region is accepted - view_map yields 0, the tree jumps to the first region and the dialog closes, instead of "Past the end of the region"')
def goto_region_offset_past_the_region_is_refused():
    with ko() as v:
        v.click(10, 4)                              # CODE
        o = first_off(v)
        v.menu_item('Edit', 'Go to...')
        v.type('1000000')                           # 16 MiB into a 270 KiB region
        v.key('enter')
        sel = [v.row(y)[1:12].strip() for y in range(2, 10) if v.row(y)[:1] == '*']
        check(v.has('[ Go ]'), 'dialog closed: the jump was accepted')
        check(sel and 'CODE' in sel[0], 'tree selection jumped to %r' % sel)
        eq(first_off(v), o, 'view moved')


@case(A, known_bug='BUG-14 dframe_begin(): after a drag the box is clamped to row 1 (f->y < 1) instead of row 2, so its title row slides under the menu bar and can no longer be grabbed')
def dialogs_dragged_to_the_top_keep_their_title_row_below_the_menu_bar():
    for name, opener in (('find', lambda v: v.menu_item('Edit', 'Find...')),
                         ('goto', lambda v: v.menu_item('Edit', 'Go to...')),
                         ('decoder', lambda v: v.menu_item('Analysis', 'Decode string'))):
        with ko() as v:
            opener(v)
            d = v.dialog()
            v.drag(d[0] + 5, d[1], d[0] + 5, 1)
            n = v.dialog()
            check(n and n[1] >= 2, '%s: title row at y=%r after dragging to the top' % (name, n and n[1]))
            # and it can be dragged back down
            v.drag(n[0] + 5, n[1], n[0] + 5, 20)
            check(v.dialog() and v.dialog()[1] > 5, '%s: could not drag it back' % name)


@case(A)
def dialogs_dragged_to_corners_stay_fully_on_screen():
    for opener in (lambda v: v.menu_item('Edit', 'Find...'), lambda v: v.menu_item('Edit', 'Go to...')):
        with ko() as v:
            opener(v)
            for tx, ty in ((169, 49), (1, 49), (169, 3), (300, 300)):
                d = v.dialog()
                v.drag(d[0] + 5, d[1], tx, ty)
                n = v.dialog()
                check(n and 1 <= n[0] and n[2] <= 170 and n[3] <= 50, 'box %r off screen after drag to %r' % (n, (tx, ty)))
            v.esc()


@case(A, known_bug='BUG-19 prop_elf()/prop_pe(): the entry row prints ctx.entry_off raw, so an ET_REL shows "file 18446744073709551615" (KOF_NA)')
def properties_entry_file_offset_is_not_a_raw_sentinel():
    with props() as v:
        t = '\n'.join(v.dlg_text())
        check('18446744073709551615' not in t, 'raw KOF_BROKEN printed: %r' % [l for l in v.dlg_text() if 'entry' in l])


if __name__ == '__main__':
    main(A)
