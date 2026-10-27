"""The dashboard's tabs: Overview, Segments, Sections, Imports, Exports (Analysis > Dashboard). The strip in the top rule is switched by a click
and by nothing else; each page shows the rows of the object; the symbol tables keep what the Symbols dialog had; and the dialog's
menu item is gone. Analysis > Infection is the same dialog with a second book of two tabs: Infected data and Shellcode."""
import subprocess
from tui import *

A = 'dashtabs'
TABS = ('Overview', 'Segments', 'Sections', 'Imports', 'Exports')


def strip(v):
    """[(label, x)] of the tab strip, left to right."""
    row = v.row(2)
    out = []
    for t in TABS:
        j = row.find(t)
        if j >= 0:
            out.append((t, j + 1))
    return out


def page_lines(v):
    rows = [v.row(y) for y in range(2, v.rows - 1)]
    return [r[r.index('│') + 1:].rstrip('│ ') for r in rows if '│' in r]


def selected_tab(v):
    """The label drawn in reverse video in the strip."""
    cols = v.reverse_cols(2)
    for t, x in strip(v):
        if x + 1 in cols:
            return t
    return None


@case(A)
def strip_has_five_tabs_in_order_with_no_counts():
    with Viewer(SAMPLES['ko']) as v:
        open_dash_tab(v, 'Overview')
        s = strip(v)
        eq([t for t, _ in s], list(TABS), 'tabs: %r' % (s,))
        check(not re.search(r'\d', v.row(2)[:v.row(2).index('[ Close ]')]), 'strip carries a count: %r' % v.row(2)[:90])
        check(all(a[1] < b[1] for a, b in zip(s, s[1:])), 'tabs out of order')
        eq(selected_tab(v), 'Overview', 'the first tab is not the selected one')


@case(A)
def dashboard_is_dragged_by_its_top_border_not_by_a_tab_or_close():
    with Viewer(SAMPLES['ko']) as v:
        open_dash_tab(v, 'Overview')
        d0 = v.dialog()
        x = v.row(d0[1]).index('[ Close ]') - 6
        v.drag(x, d0[1], x - 1, d0[1] + 1)         # on the rule between the strip and the button
        d1 = v.dialog()
        eq((d1[0], d1[1]), (d0[0] - 1, d0[1] + 1), 'the dashboard did not follow the pointer: %r -> %r' % (d0[:2], d1[:2]))
        check(d1[2] <= v.cols and d1[3] <= v.rows, 'the box left the screen: %r' % (d1,))
        # a tab still switches the page, at the new place
        tx, ty = v.find('Segments', rows=(d1[1], d1[1]))
        v.click(tx, ty)
        v.pump_quiet()
        eq(v.dialog()[:2], d1[:2], 'a tab click moved the box')
        # a press on a tab label does not take hold of the box
        d2 = v.dialog()
        tx, ty = v.find('Sections', rows=(d2[1], d2[1]))
        v.drag(tx, ty, tx + 8, ty + 2)
        eq(v.dialog()[:2], d2[:2], 'a press on a tab label moved the box')
        # a drag far past the edge is clamped
        v.drag(d2[0] + 3, d2[1], v.cols, v.rows)
        d3 = v.dialog()
        check(d3[2] <= v.cols and d3[3] <= v.rows, 'the box left the screen: %r' % (d3,))


@case(A)
def click_each_tab_shows_its_page():
    with Viewer(SAMPLES['gafgyt']) as v:
        open_dash_tab(v, 'Overview')
        check(v.has('Object') and v.has('Regions') and v.has('Heuristic'), 'overview page incomplete')
        for tab, needle in (('Segments', 'entropy'), ('Sections', 'entropy'), ('Imports', 'icase'), ('Exports', 'icase'), ('Overview', 'Anomalies')):
            v.click(*v.find(tab, rows=(1, 4)))
            v.pump_quiet()
            check(v.has(needle), '%s: page missing %r' % (tab, needle))
            eq(selected_tab(v), tab, '%s: the strip does not show it selected' % tab)
        # the click lands anywhere in a label, its first and last character included
        for tab in TABS[1:]:
            j = v.row(2).find(tab)
            v.click(j + 1, 2)
            eq(selected_tab(v), tab, 'first character of %s' % tab)
            v.click(j + len(tab), 2)
            eq(selected_tab(v), tab, 'last character of %s' % tab)


@case(A)
def selected_tab_survives_redraws():
    with Viewer(SAMPLES['ko']) as v:
        open_dash_tab(v, 'Sections')
        for act in (lambda: v.wheel(80, 25, n=2), lambda: v.key('pgdn'), lambda: v.key('down', 2), lambda: v.resize(40, 120),
                    lambda: v.resize(50, 170), lambda: v.key('home')):
            act()
            v.pump_quiet()
            check(v.has('entropy'), 'the Sections page was replaced after a redraw')
            eq(selected_tab(v), 'Sections', 'the strip lost its selection')
        v.key('esc')
        check(not v.dialog(), 'Esc did not close the page')
        # and a reopened dashboard starts on the overview, not on a tab left behind
        open_dash_tab(v, 'Overview')
        eq(selected_tab(v), 'Overview')


@case(A)
def wheel_on_the_strip_does_not_switch_tabs():
    with Viewer(SAMPLES['ko']) as v:
        open_dash_tab(v, 'Exports')
        x, y = v.find('Segments', rows=(2, 2))
        v.wheel(x, y, n=2)
        v.wheel(x, y, up=True, n=2)
        eq(selected_tab(v), 'Exports', 'a wheel over the strip switched the page')


@case(A)
def overview_renders_the_format_block_for_elf_and_pe():
    """A smoke of rendering: what each row says is asserted on the data (tests/unit/kx_dashdata.c), not here."""
    with Viewer(SAMPLES['gafgyt']) as v:
        open_dash_tab(v, 'Overview')
        t = '\n'.join(page_lines(v))
        for needle in ('format', 'arch', 'symbols', 'entry', 'size', 'layout', 'Regions', 'Anomalies', 'Heuristic'):
            check(needle in t, 'overview did not render %r' % needle)
    path = pick(SAMPLES['pe'], 1, 30000, 200000)[0]
    with Viewer(path) as v:
        open_dash_tab(v, 'Overview')
        t = '\n'.join(page_lines(v))
        for needle in ('format', 'arch', 'entry', 'size', 'stub'):
            check(needle in t, 'PE overview did not render %r' % needle)


@case(A)
def layout_table_copy_takes_the_row_text():
    with Viewer(SAMPLES['gafgyt']) as v:
        open_dash_tab(v, 'Sections')
        y = [yy for yy in range(3, v.rows) if '.text' in v.row(yy) and 'SHT_PROGBITS' in v.row(yy)][0]
        x = v.row(y).index('.text') + 1
        n0 = len(v.osc52())
        v.drag(x, y, v.row(y).index('SHT_PROGBITS') + 14, y)
        v.key('ctrl+c')
        got = v.osc52()
        check(len(got) > n0 and b'.text' in got[-1] and b'SHT_PROGBITS' in got[-1], 'copied: %r' % (got[-1:] if got else got,))


@case(A)
def hostile_section_tables_render_and_scroll():
    """Smoke: a header with 300 section headers, one that claims 60000 and holds three. The counts and rows are the data's
    (kx_dashdata); here the page must draw, scroll to its end and survive."""
    with Viewer(FIX('many_sections.elf')) as v:
        open_dash_tab(v, 'Sections')
        check(v.has('entropy') and v.has('header declares'), 'the Sections page did not render (or lost the mismatch row)')
        x, y = v.find('.s1', rows=(3, v.rows - 2)) or (60, 30)
        for _ in range(60):
            v.wheel(x, y, n=3)
        v.pump_quiet()
        check(v.alive() and v.has('entropy'), 'the page died or vanished after scrolling a long table')
    with Viewer(FIX('claims_many.elf')) as v:
        open_dash_tab(v, 'Sections')
        check(v.has('60000') and v.has('.a'), 'the page did not render the short table')


@case(A)
def hostile_section_name_is_drawn_without_its_escape():
    with Viewer(FIX('evil_names.elf')) as v:
        open_dash_tab(v, 'Sections')
        check(v.has('.evil?[31mRED?]0;PWNED-TITLE?x'), 'the name is not shown with the escapes made visible')
        check(not v.has('\x1b'), 'an escape reached the screen')


@case(A)
def header_with_no_section_table_says_so():
    with Viewer(FIX('no_sections.elf')) as v:
        open_dash_tab(v, 'Sections')
        check(v.has('no section headers'), 'the empty section table is not said')


@case(A)
def imports_filter_narrows_and_the_filter_is_remembered_across_the_tabs():
    with Viewer(SAMPLES['ko']) as v:
        open_dash_tab(v, 'Imports')
        rx = r'│\s*(\d+)\s+(NOTYPE|FUNC|OBJECT|SECTION|FILE|\S+)\s+(LOCAL|GLOBAL|WEAK)\s+\S+\s+\S+\s+(\S+)'
        rows = [re.search(rx, v.row(y)) for y in range(3, v.rows)]
        rows = [m for m in rows if m]
        check(len(rows) >= 3, 'no import rows')
        name = rows[2].group(4)
        sub = name[1:6] if len(name) > 6 else name
        p = v.find('icase')
        v.click(p[0] - 20, p[1])
        v.type(sub)
        got = [re.search(rx, v.row(y)) for y in range(3, v.rows)]
        got = [m for m in got if m]
        check(got and len(got) <= len(rows), 'the filter did not narrow the imports')
        for m in got:
            check(sub in m.group(4), 'row %r does not match %r' % (m.group(4), sub))
        v.key('esc')
        # to the exports and back: the words are the view's
        v.click(*v.find('Exports', rows=(1, 4)))
        v.click(*v.find('Imports', rows=(1, 4)))
        check(v.has(sub, rows=(3, 4)), 'the filter text was not remembered across the tabs: %r' % v.row(3)[:80])


@case(A)
def the_symbols_menu_item_is_gone():
    with Viewer(SAMPLES['ko']) as v:
        v.menu_open('Analysis')
        check(v.popup_item('Dashboard') and not v.popup_item('Symbols'), 'the Analysis menu still offers Symbols')
        v.esc()
        # nothing else opens the old box: the keys that did nothing for it still do nothing
        before = v.snapshot()
        for k in ('tab', 'backtab', 's', 'y'):
            v.key(k)
        eq(v.snapshot(), before, 'a key opened or changed something on the plain view')




FRAME_GLYPHS = '\u256d\u256e\u2570\u256f\u2500\u250c\u2510\u2514\u2518'


@case(A)
def count_is_at_the_dialogs_bottom_right_and_tables_have_no_frame():
    """One count for the page, on the bottom border row at its right end: 'lines' on the overview, 'items' on a table page; none in
    the table area; no frame glyph (corner or rule) anywhere between the dialog's own top and bottom rule."""
    with Viewer(SAMPLES['ko']) as v:
        open_dash_tab(v, 'Overview')
        for tab, unit in (('Overview', 'lines'), ('Segments', 'lines'), ('Sections', 'items'), ('Imports', 'items'), ('Exports', 'items')):
            v.click(*v.find(tab, rows=(1, 4)))
            v.pump_quiet()
            bottom = [y for y in range(3, v.rows) if v.row(y).lstrip().startswith('\u2570')]
            check(bottom, '%s: no bottom border row' % tab)
            row = v.row(bottom[0])
            check(re.search(r'\d+-\d+ of \d+ %s \u256f$' % unit, row.rstrip()), '%s: no "a-b of N %s" at the bottom right: %r' % (tab, unit, row[-40:]))
            body = [v.row(y) for y in range(3, bottom[0])]
            check(not any(re.search(r'\d+-\d+ of \d+ (lines|items)', r) for r in body), '%s: a count inside the page area' % tab)
            for r in body:
                inner = r[r.index('\u2502') + 1:r.rindex('\u2502')] if r.count('\u2502') >= 2 else ''
                check(not any(g in inner for g in FRAME_GLYPHS), '%s: a frame glyph inside a table: %r' % (tab, r))


def body_rows(v):
    return [v.row(y) for y in range(3, v.rows - 2)]


def moved(v, act):
    before = body_rows(v)
    act()
    v.pump_quiet()
    return body_rows(v) != before


@case(A)
def wheel_shift_wheel_and_clicks_land_on_every_page_and_table():
    """The page's own scroll: the wheel works anywhere over the dialog (first column, middle, right wall) on every page; shift+wheel
    pans a table wider than the box; a double click takes the whole cell and a triple click the whole line, also for a cell scrolled
    out of view; the scrollbar press moves the page. Then the process panel's tables (fd/env/libs) on the overview."""
    with Viewer(SAMPLES['ko'], rows=40, cols=120) as v:
        open_dash_tab(v, 'Overview')
        for tab in ('Sections', 'Imports', 'Exports'):
            v.click(*v.find(tab, rows=(1, 4)))
            v.pump_quiet()
            for x, y in ((4, 8), (60, 20), (116, 12), (117, 9)):
                v.key('home')
                check(moved(v, lambda: v.wheel(x, y, n=3)), '%s: the wheel at %r did nothing' % (tab, (x, y)))
                check(moved(v, lambda: v.wheel(x, y, up=True, n=3)), '%s: the wheel up at %r did nothing' % (tab, (x, y)))
        # sideways: the export table is wider than the box at 120 columns, its first column stays
        v.click(*v.find('Exports', rows=(1, 4)))
        v.pump_quiet()
        v.key('home')
        head0 = v.row(5)
        check(moved(v, lambda: v.wheel(60, 20, n=3, mod=4)), 'Exports: shift+wheel did not pan the wide table')
        check(v.row(5) != head0 and v.row(5)[5:9] == head0[5:9], 'the first column did not stay: %r' % v.row(5)[:30])
        check(moved(v, lambda: v.wheel(4, 8, up=True, n=9, mod=4)), 'Exports: shift+wheel back did nothing')
        # the same wheel on the Sections page (it fits the box: nothing to pan, and the page does not move either)
        v.click(*v.find('Sections', rows=(1, 4)))
        v.pump_quiet()
        check(not moved(v, lambda: v.wheel(60, 20, n=3, mod=4)), 'Sections fits the box: shift+wheel should not move it')
        # the page's scrollbar (right wall): a press near its end moves the page to the end
        v.key('home')
        check(moved(v, lambda: v.click(117, v.rows - 5)), 'a press on the scrollbar did not move the page')
        # a double click takes the whole cell, a triple click the whole line
        v.key('home')
        y = [yy for yy in range(3, v.rows) if '__ksymtab_gpl ' in v.row(yy)][0]
        x = v.row(y).index('__ksymtab_gpl') + 3
        n0 = len(v.osc52())
        v.dclick(x, y)
        v.key('ctrl+c')
        got = v.osc52()
        check(len(got) > n0 and got[-1] == b'__ksymtab_gpl', 'double click copied %r' % (got[-1:],))
        n0 = len(v.osc52())
        v.tclick(x, y)
        v.key('ctrl+c')
        got = v.osc52()
        check(len(got) > n0 and got[-1].startswith(b'3  __ksymtab_gpl  SHT_PROGBITS') and got[-1].endswith(b'0.00'), 'triple click copied %r' % (got[-1:],))
        # a cell clipped by the box: pan the Exports table right, double click the name column - the copy is the FULL name
        v.click(*v.find('Exports', rows=(1, 4)))
        v.pump_quiet()
        v.key('home')
        v.wheel(60, 20, n=1, mod=4)
        v.pump_quiet()
        y = [yy for yy in range(3, v.rows) if '__kstrtab_rpc_create' in v.row(yy)][0]
        x = v.row(y).index('__kstrtab_rpc_create') + 3
        n0 = len(v.osc52())
        v.dclick(x, y)
        v.key('ctrl+c')
        got = v.osc52()
        check(len(got) > n0 and got[-1] == b'__kstrtab_rpc_create', 'double click on a panned cell copied %r' % (got[-1:],))
    sl = subprocess.Popen(['sleep', '60'], env={'A_LONG_VALUE': 'x' * 300, 'PATH': '/usr/bin:/bin', 'FOO': 'bar'})
    try:
        with Viewer('', rows=40, cols=120, extra=['--pid', str(sl.pid)], copy=False) as v:
            v.menu_item('Analysis', 'Dashboard')
            v.pump_quiet()
            check(v.has('Mapped files') and v.has('Descriptors') and v.has('Environment'), 'the process tables are not on the overview')
            for x, y in ((4, 6), (60, 15), (116, 20)):
                v.key('home')
                check(moved(v, lambda: v.wheel(x, y, n=3)), 'process page: the wheel at %r did nothing' % ((x, y),))
            v.key('end')
            check(v.has('FOO'), 'the page did not reach the environment table at its end')
            check(moved(v, lambda: v.wheel(60, 15, n=3, mod=4)), 'process page: shift+wheel did not pan the long environment value')
            y = [yy for yy in range(3, v.rows) if 'A_LONG_VALUE' in v.row(yy)][0]
            x = v.row(y).index('A_LONG_VALUE') + 2
            n0 = len(v.osc52())
            v.dclick(x, y)
            v.key('ctrl+c')
            got = v.osc52()
            check(len(got) > n0 and got[-1] == b'A_LONG_VALUE', 'double click on a process table cell copied %r' % (got[-1:],))
    finally:
        sl.kill()
        sl.wait()


@case(A)
def table_reflows_when_the_dialog_is_resized():
    with Viewer(SAMPLES['ko'], rows=40, cols=120) as v:
        open_dash_tab(v, 'Exports')
        rows40 = len([y for y in range(3, v.rows - 2) if re.search(r'\u2502\s+\d+\s+\w', v.row(y))])
        cols120 = max(len(r.rstrip()) for r in body_rows(v))
        v.resize(50, 170)
        rows50 = len([y for y in range(3, v.rows - 2) if re.search(r'\u2502\s+\d+\s+\w', v.row(y))])
        cols170 = max(len(r.rstrip()) for r in body_rows(v))
        check(rows50 >= rows40 + 8, 'the table did not take the taller dialog: %d -> %d rows' % (rows40, rows50))
        check(cols170 > cols120 + 30, 'the table did not take the wider dialog: %d -> %d columns' % (cols120, cols170))
        v.resize(30, 100)
        check(v.alive() and v.has('icase') and v.has('rec'), 'the table did not survive shrinking')



@case(A)
def infection_dialog_tabs_highlight_and_shellcode_list():
    """Analysis > Infection on infected.elf (mkfixtures.py: the entry bytes tests/sigs/infect_mark_00.c marks, a writable and
    executable entry segment). Two tabs in the strip, in order, switched by a click: Infected data lists the places an infector
    uses and draws the rows the engine's ranges touch in red with the state "infected (kind)", plus a row of its own for a range no
    region holds; Shellcode lists the data that carries execute permission. Both are tables with the count at the bottom-right.
    Needs `make test-sigs`."""
    raise Skip('the Infection item is switched off until its analysis is reworked (bar_enabled BI_INFECTION)')
    with Viewer(FIX('infected.elf'), rows=60, cols=200, db='build/test/databases-sigs', copy=False) as v:
        check(v.menu_item('Analysis', 'Infection'), 'no Infection item')
        v.pump_quiet()
        strip2 = v.row(2)
        check('Infected data' in strip2 and 'Shellcode' in strip2 and strip2.index('Infected data') < strip2.index('Shellcode'),
              'strip: %r' % strip2[:100])
        check('Overview' not in strip2 and 'Imports' not in strip2, 'the dashboard strip is showing: %r' % strip2[:100])
        for needle in ('region', 'file offset', 'address', 'size', 'state', 'value', 'entry point', 'last segment'):
            check(v.has(needle), 'Infected data: no %r\n%s' % (needle, v.show(2, 30, 1, 200)))
        # the highlighted rows: the entry and the section holding it, in the bad colour, and the engine's own range as a row
        x, y = v.find('infected (damage)', rows=(3, v.rows - 2))
        check(v.screen.buffer[y - 1][x - 1].fg == 'red', 'the infected state is not red: %r' % v.screen.buffer[y - 1][x - 1].fg)
        check(any('entry point' in v.row(yy) and 'infected (damage)' in v.row(yy) for yy in range(3, v.rows - 1)), 'entry row not flagged')
        check(any('reported by the engine' in v.row(yy) and 'infected (body)' in v.row(yy) for yy in range(3, v.rows - 1)),
              'the range no region holds is missing\n%s' % v.show(2, 30, 1, 200))
        # the value column: the bytes of the entry area as hex (the marker of the test module), drawn in the row's colour
        ye = [yy for yy in range(3, v.rows - 1) if 'entry point' in v.row(yy)][0]
        xv = v.row(ye).find('49 6e 66 4d 61 72 6b')
        check(xv > 0, 'the entry row has no value: %r' % v.row(ye)[-100:])
        check(v.screen.buffer[ye - 1][xv].fg == 'red', 'the value of an infected row is not red')
        yc = [yy for yy in range(3, v.rows - 1) if 'last segment' in v.row(yy)][0]
        xc = v.row(yc).index('last segment') + 1
        check(v.screen.buffer[yc - 1][xc - 1].fg != 'red', 'a clean row is drawn red')
        check(re.search(r'\d+-\d+ of \d+ items', v.row(v.dialog()[3])), 'no count at the bottom: %r' % v.row(v.dialog()[3])[-60:])
        # the Shellcode tab, by a click on the strip
        v.click(*v.find('Shellcode', rows=(1, 4)))
        v.pump_quiet()
        for needle in ('name', 'perm', 'type', 'refs', 'entropy', 'value', '(writable and executable)', 'range'):
            check(v.has(needle), 'Shellcode: no %r\n%s' % (needle, v.show(2, 20, 1, 200)))
        check(not v.has('region'), 'the first tab is still showing')
        # the value is the last column: the page's sideways scroll brings it in; the columns before it slide out
        xh = v.find('value', rows=(3, 3))
        v.hwheel(60, 6, n=12)
        v.pump_quiet()
        xh2 = v.find('value', rows=(3, 3))
        check(xh2 and (not xh or xh2[0] < xh[0]), 'a sideways scroll did not move the value column: %r -> %r' % (xh, xh2))
        check(re.search(r'(?:[0-9a-f]{2} ){6}', ''.join(v.row(y) for y in range(4, 8))), 'no hex value on the Shellcode tab\n%s' % v.show(2, 10, 1, 200))
        v.hwheel(60, 6, left=True, n=40)
        v.pump_quiet()
        check(re.search(r'\d+-\d+ of \d+ items', v.row(v.dialog()[3])), 'no count on the second tab')
        v.click(*v.find('Infected data', rows=(1, 4)))
        v.pump_quiet()
        check(v.has('entry point') and v.has('infected (damage)'), 'back on the first tab: the rows are gone')
        v.key('esc')
        check(not v.dialog(), 'Esc did not close the dialog')


if __name__ == '__main__':
    main(A)
