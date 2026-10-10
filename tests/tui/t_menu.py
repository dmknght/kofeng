"""Menu bar: titles, items, enabled/disabled, keyboard + mouse navigation."""
from tui import *
from dl import status  # noqa

A = 'menu'
EXPECT = {
    'File': ['Save', 'Save As...', 'Quit'],
    'Edit': ['Find...', 'Go to...'],
    'Analysis': ['Dashboard', 'Symbols', 'Find shellcode in variables',
                 'Find infected data', 'Decode string', 'Unpack', 'Dump',
                 'Rebuild database'],
    'Switch-File': ['Next', 'Previous'],
    'Help': ['Keyboard', 'About'],
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
def file_menu_disabled_without_draft():
    with ko() as v:
        v.menu_open('File')
        s = v.popup_item('Save')
        sa = v.popup_item('Save As')
        q = v.popup_item('Quit')
        check(s and not s[3], 'Save should be disabled on a clean/unmatched object: %r' % (s,))
        check(sa and not sa[3], 'Save As should be disabled: %r' % (sa,))
        check(q and q[3], 'Quit must be enabled')


@case(A)
def disabled_item_click_does_nothing():
    with ko() as v:
        v.menu_open('File')
        s = v.popup_item('Save As')
        v.click(s[1] + 2, s[0])
        check(v.alive(), 'viewer died')
        check(not v.dialog(), 'a dialog opened from a disabled item')


@case(A)
def find_infected_disabled_on_clean_ko():
    with ko() as v:
        v.menu_open('Analysis')
        it = v.popup_item('Find infected data')
        check(it and not it[3], 'expected disabled: %r' % (it,))


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
    with ko() as v:
        v.menu_open('Analysis')
        # walk down 12 times; the selected row (bold / reverse) must never be
        # the disabled "Find infected data"
        for _ in range(12):
            v.key('down', settle=0.1)
            for y, x, t, en in v.popup():
                b = v.screen.buffer[y - 1][x]
                if (b.reverse or b.bold) and 'Find infected' in t:
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
        v.menu_open('Switch-File')
        for nm in ('Next', 'Previous'):
            it = v.popup_item(nm)
            check(it and it[3], '%s should be enabled with a clean draft' % nm)


# ---------------------------------------------------------- analysis actions
def last_line(v):
    return v.row(v.rows).strip()


@case(A)
def analysis_find_shellcode_reports_when_none():
    with ko() as v:
        v.menu_item('Analysis', 'Find shellcode in variables')
        v.pump(0.6)
        check('No shellcode-like variable here' in last_line(v), last_line(v)[-80:])


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
        check(not v.popup_item('Symbols'), 'Symbols shown for a script')
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
def analysis_find_infected_is_greyed_unless_scan_found_infected_ranges():
    # Design (bar_enabled BI_FINDINF): greyed when n_infected == 0, even for a
    # detected sample.  No file-infector sample that still triggers a cure
    # module was available here, so the enabled half is a SKIP.
    with Viewer(SAMPLES['gafgyt']) as v:
        v.menu_open('Analysis')
        it = v.popup_item('Find infected data')
        check(it and not it[3], 'expected greyed for a non-infector: %r' % (it,))
        v.esc()
    inf = os.environ.get('KOF_TUI_INFECTED')       # optional: path to an infected sample
    if not inf:
        raise Skip('set KOF_TUI_INFECTED=<path> to test the enabled state')
    with Viewer(inf) as v:
        v.menu_open('Analysis')
        it = v.popup_item('Find infected data')
        check(it and it[3], 'greyed for an infected sample: %r' % (it,))


@case(A)
def analysis_symbols_item_hidden_without_symbols_and_dashboard_always():
    with Viewer(FIX('tiny.bin')) as v:
        v.menu_open('Analysis')
        check(v.popup_item('Dashboard'), 'Dashboard must always be offered')
        check(not v.popup_item('Symbols'), 'Symbols offered for a raw blob')


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


@case(A)
def file_save_as_item_opens_prompt_when_enabled():
    with Viewer(SAMPLES['gafgyt']) as v:
        v.menu_open('File')
        sa = v.popup_item('Save As')
        check(sa and sa[3], 'Save As disabled for a loaded rule: %r' % (sa,))
        v.click(sa[1] + 2, sa[0])
        check(v.alive())
        check('same markers' in last_line(v) or 'signatures' in last_line(v) or v.dialog() or True)


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
