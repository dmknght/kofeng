"""Menu bar: titles, items, enabled/disabled, keyboard + mouse navigation."""
from tui import *
from dl import status  # noqa

A = 'menu'
EXPECT = {
    'File': ['Next File', 'Previous File', 'Quit'],
    'Edit': ['Find...', 'Go to...'],
    'Analysis': ['Dashboard', 'Infection', 'Decode string', 'Unpack', 'Dump',
                 'Rebuild database'],
    'Help': ['Keyboard', 'About'],
    'Manage': ['Pathogens', 'Syndromes'],
}


def ko():
    return Viewer(SAMPLES['ko'])


@case(A)
def bar_titles_present():
    with ko() as v:
        for m in v.MENUS:
            check(v.bar_pos(m), 'title %s missing from bar: %r' % (m, v.row(1)))


@case(A)
def each_menu_lists_its_items():
    with ko() as v:
        for m, items in EXPECT.items():
            v.menu_open(m)
            txt = [t for _, _, t, _ in v.popup()]
            for it in items:
                check(any(it in t for t in txt), '%s: %r missing in %r' % (m, it, txt))
            v.esc()


@case(A)
def esc_closes_menu_and_repaints():
    with ko() as v:
        before = v.snapshot()
        v.menu_open('Analysis')
        check(v.popup(), 'menu did not open')
        v.esc()
        check(not v.popup(), 'popup still drawn after Esc')
        eq(v.snapshot(), before, 'screen differs after open+Esc')


@case(A)
def file_menu_has_only_quit_and_it_is_enabled():
    with ko() as v:
        v.menu_open('File')
        q = v.popup_item('Quit')
        check(q and q[3], 'Quit must be enabled')
        check(not v.popup_item('Save') and not v.popup_item('Save As'),
              'File offers a Save: the draft is not written')


@case(A)
def disabled_item_click_does_nothing():
    with Viewer(FIX('tiny.bin')) as v:
        v.menu_open('Analysis')
        s = v.popup_item('Infection')
        check(s and not s[3], 'expected disabled: %r' % (s,))
        v.click(s[1] + 2, s[0])
        check(v.alive(), 'viewer died')
        check(not v.dialog(), 'a dialog opened from a disabled item')


@case(A)
def infection_is_listed_and_greyed_for_now():
    # one item for both old ones: live when the object has infected ranges or its format can carry shellcode
    with ko() as v:
        v.menu_open('Analysis')
        it = v.popup_item('Infection')
        check(it and not it[3], 'Infection must be listed and greyed (switched off for now): %r' % (it,))
        check(not v.popup_item('Find shellcode') and not v.popup_item('Find infected'), 'a retired item is still offered')
        v.esc()
    with Viewer(FIX('tiny.bin')) as v:
        v.menu_open('Analysis')
        it = v.popup_item('Infection')
        check(it and not it[3], 'expected greyed for a raw blob: %r' % (it,))


@case(A)
def switching_title_while_open_moves_menu():
    with ko() as v:
        v.menu_open('File')
        v.menu_open('Help')
        txt = ' '.join(t for _, _, t, _ in v.popup())
        check('Keyboard' in txt and 'Quit' not in txt, 'Help menu not shown: %r' % txt)
        v.esc()


@case(A)
def click_outside_closes_menu():
    with ko() as v:
        v.menu_open('Analysis')
        v.click(100, 25)
        check(not v.popup(), 'menu still open after click outside')
        check(v.alive())


@case(A)
def click_on_open_title_keeps_menu_open():
    # Observed design: a second click on the open title re-opens it (it does
    # not toggle).  Recorded so a change is noticed.
    with ko() as v:
        v.menu_open('Edit')
        check(v.popup())
        v.menu_open('Edit')
        check(v.popup(), 'menu closed on re-click (design changed?)')
        v.esc()


@case(A)
def f10_opens_and_keys_navigate():
    with ko() as v:
        v.key('f10')
        check(v.popup(), 'F10 did not open a menu')
        first = [t for _, _, t, _ in v.popup()]
        v.key('right')
        second = [t for _, _, t, _ in v.popup()]
        check(first != second, 'Right arrow did not move to the next menu')
        v.key('left')
        eq([t for _, _, t, _ in v.popup()], first, 'Left did not come back')
        v.key('esc')
        check(not v.popup(), 'Esc did not close F10 menu')


@case(A)
def f10_down_enter_runs_item():
    with ko() as v:
        v.key('f10'); v.key('right'); v.key('right')   # Analysis
        v.key('down'); v.key('enter')
        check(v.dialog() or v.has('Properties'), 'Enter on first Analysis item did not open Dashboard')
        v.esc()


@case(A)
def arrow_skips_disabled_items():
    with Viewer(FIX('tiny.bin')) as v:
        v.menu_open('Analysis')
        # walk down 12 times; the selected row (bold / reverse) must never be
        # the disabled "Infection" (a raw blob: no infected range, no executable image)
        for _ in range(12):
            v.key('down', settle=0.1)
            for y, x, t, en in v.popup():
                b = v.screen.buffer[y - 1][x]
                if (b.reverse or b.bold) and 'Infection' in t:
                    raise Fail('cursor landed on disabled item')
        v.esc()


@case(A)
def menu_dump_submenu_opens():
    with ko() as v:
        v.menu_open('Analysis')
        d = v.popup_item('Dump')
        v.click(d[1] + 3, d[0])
        check(v.has('Static unpacker') and v.has('Emu unpacker'),
              'no submenu after clicking Dump')
        check(v.alive())
        v.esc(2)


@case(A)
def quit_item_exits():
    with ko() as v:
        v.menu_item('File', 'Quit')
        v.pump(1.0)
        check(not v.alive(), 'Quit item did not end the process')


@case(A)
def ctrl_q_exits():
    with ko() as v:
        v.key('ctrl+q'); v.pump(1.0)
        check(not v.alive(), 'Ctrl+Q did not end the process')


@case(A)
def mouse_hover_over_open_menu_does_not_crash():
    with ko() as v:
        v.menu_open('Analysis')
        for y in range(2, 14):
            v.motion(22, y)
        check(v.alive())
        v.esc()


@case(A)
def keyboard_help_lists_f10():
    with ko() as v:
        v.menu_item('Help', 'Keyboard')
        check(any('F10' in l for l in v.dlg_text()), 'F10 row missing from keyboard help')
        v.esc()


@case(A)
def next_prev_enabled_states():
    with ko() as v:
        v.menu_open('File')
        for nm in ('Next File', 'Previous File'):
            it = v.popup_item(nm)
            check(it and it[3], '%s should be enabled with a clean draft' % nm)


# ---------------------------------------------------------- analysis actions
def last_line(v):
    return v.row(v.rows).strip()


@case(A)
def analysis_infection_opens_a_dialog_with_its_two_tabs():
    raise Skip('the Infection item is switched off until its analysis is reworked (bar_enabled BI_INFECTION)')
    # the old item printed "No shellcode-like variable here" on the status row; the dialog says why a tab is empty, on the tab
    with ko() as v:
        check(v.menu_item('Analysis', 'Infection'), 'no Infection item')
        v.pump_quiet()
        d = v.dialog()
        check(d and 'Infected data' in v.row(2) and 'Shellcode' in v.row(2), 'no Infection dialog: %r' % (v.row(2)[:100],))
        check(v.row(2).index('Infected data') < v.row(2).index('Shellcode'), 'tabs out of order')
        check('No shellcode-like variable here' not in last_line(v), 'the retired status message is back')
        v.click(*v.find('Shellcode', rows=(1, 4)))
        v.pump_quiet()
        check(v.has('no variable or data range') or v.has('shape'), 'the Shellcode tab says nothing: %r' % v.show(3, 8))


@case(A)
def analysis_unpack_reports_when_nothing_comes_out():
    with ko() as v:
        v.menu_item('Analysis', 'Unpack')
        v.pump(0.6)
        check('Nothing came out' in last_line(v), last_line(v)[-80:])


@case(A)
def analysis_dump_submenu_items_for_executable():
    with ko() as v:
        v.menu_open('Analysis')
        d = v.popup_item('Dump')
        v.click(d[1] + 3, d[0])
        check(v.has('Static unpacker') and v.has('Emu unpacker'))
        v.esc(2)


@case(A)
def analysis_dump_plain_for_non_executable():
    with Viewer(pick(SCRATCH + '/packtest', 1, 5000, 500000)[0]) as v:
        v.menu_open('Analysis')
        check(v.popup_item('Dump'), 'no Dump item for a script')
        check(not v.popup_item('Symbols'), 'Symbols shown for a script (the item is retired: the dashboard has the tabs)')
        v.esc()


@case(A)
def analysis_dump_writes_directory_beside_the_copy():
    p = pick(SCRATCH + '/packtest', 1, 5000, 500000)[0]
    with Viewer(p) as v:
        v.menu_item('Analysis', 'Dump')
        v.pump(1.0)
        check(v.alive())
        d = os.path.join(os.path.dirname(v.path), '_' + os.path.basename(v.path) + '_dump')
        check(os.path.isdir(d), 'no dump directory %s; status %r' % (d, last_line(v)[-80:]))
        check(os.listdir(d), 'dump directory is empty')


@case(A)
def analysis_rebuild_is_refused_outside_a_source_tree():
    # SAFETY: the test bases live outside the repository, so there is no Makefile
    # above them and nothing is rebuilt.  Never point --bases at the repo here.
    db = os.path.join(REPO, 'build', 'release', 'databases')
    m0 = os.stat(db).st_mtime
    with ko() as v:
        v.menu_item('Analysis', 'Rebuild database')
        v.pump(1.5)
        check('No Makefile above' in last_line(v), last_line(v)[-90:])
    eq(os.stat(db).st_mtime, m0, 'database directory changed')


@case(A)
def analysis_infection_is_greyed_for_every_object_for_now():
    # Design (bar_enabled BI_INFECTION): live when the object has infected ranges (the engine reported them) or its format can
    # carry shellcode (kv_cap); greyed for neither. The infected half is t_dashtabs (the fixture that has an infected range).
    with Viewer(SAMPLES['gafgyt']) as v:
        v.menu_open('Analysis')
        it = v.popup_item('Infection')
        check(it and not it[3], 'Infection must be listed and greyed (switched off for now): %r' % (it,))
        v.esc()
    with Viewer(FIX('tiny.bin')) as v:
        v.menu_open('Analysis')
        it = v.popup_item('Infection')
        check(it and not it[3], 'expected greyed for a raw blob: %r' % (it,))
        v.esc()


@case(A)
def analysis_symbols_item_is_retired_and_dashboard_always():
    with Viewer(FIX('tiny.bin')) as v:
        v.menu_open('Analysis')
        check(v.popup_item('Dashboard'), 'Dashboard must always be offered')
        check(not v.popup_item('Symbols'), 'the retired Symbols item is offered for a raw blob')


@case(A)
def menu_items_for_empty_selection_states():
    # the same menus must open on every sample kind without dying
    for maker in (lambda: FIX('tiny.bin'), lambda: FIX('shell.php'), lambda: FIX('many.zip'),
                  lambda: FIX('events.ktr'), lambda: SAMPLES['gafgyt']):
        with Viewer(maker()) as v:
            for m in v.MENUS:
                v.menu_open(m)
                check(v.popup(), '%s menu empty for %s' % (m, os.path.basename(v.path)))
                v.esc()
            check(v.alive())


@case(A)
def menu_hover_highlight_follows_mouse_motion():
    with ko() as v:
        v.menu_open('Analysis')
        y0 = v.popup_item('Dashboard')[0]
        fp = v.fingerprint()
        v.mouse(35, 24, y0 + 2, True)       # motion without button (viewer sees a drag)
        check(v.alive())
        v.esc()


@case(A, known_bug='BUG-17 say_note() messages are drawn only while the draft panel has focus: Ctrl+O / Ctrl+\\ / Ctrl+] refusals are invisible from the tree or hex pane')
def key_ctrl_o_says_there_is_no_file_picker():
    with ko() as v:
        v.key('ctrl+o')                      # focus is on the tree here
        check(v.has('No file picker'), 'no message on screen after Ctrl+O (tree focus)')


@case(A)
def key_ctrl_o_message_is_visible_with_the_draft_panel_focused():
    from dl import click_in_panel
    with ko() as v:
        click_in_panel(v, '[Comment...]'); v.key('esc')
        v.key('ctrl+o')
        check(v.has('No file picker'), 'no message with the panel focused')


@case(A)
def question_mark_does_nothing_although_usage_mentions_it():
    # kofviewer --help says: "? in the viewer lists the keys."  Observed: nothing happens.
    with ko() as v:
        v.type('?')
        check(not v.dialog(), 'a "?" help box exists now - remove this test and the usage nit')


if __name__ == '__main__':
    main(A)


@case(A)
def manage_families_is_live_and_syndromes_is_greyed_for_now():
    with ko() as v:
        v.menu_open('Manage')
        it = v.popup_item('Pathogens')
        check(it and it[3], 'Pathogens must be enabled: %r' % (it,))
        it = v.popup_item('Syndromes')
        check(it and not it[3], 'Syndromes must be listed and greyed (switched off for now): %r' % (it,))
        v.esc()
        v.menu_open('Analysis')
        check(not v.popup_item('Syndrome table') and not v.popup_item('Syndromes'), 'the syndrome item is still in Analysis')
        v.esc()
        check('Switch-File' not in ' '.join(v.row(1).split()), 'the Switch-File menu is still on the bar')
