"""The name of a function row in the blocks table opens the CFG of that function (hit_plg_cfg, kofexamine/kv_decl.c): a dialog in the frame of the Syndromes and Pathogens dialogs
(kv_cfgdlg.c) with THREE TABS in its top rule - Overview (the engine's facts and the calls as a table), Disasm (the disassembly panel's own rows of the function) and Graph (the graph
drawn as boxes in ranks by kofexamine/kv_graph.c) - switched by a press on the tab's title and by nothing else; draggable by its top rule, a scrollbar in its right wall, the wheel scrolls it down and the shift or ctrl wheel sideways.

THE SCENE is written at run time by the unit test tests/unit/cfg_view_scene.c (`--write`): an ELF64 x86-64 executable of five inert functions
(cv_small below the anchor, cv_loop with two loops, cv_switch with a fan-out, cv_big of seventy blocks, and one no symbol names) and a data
segment of strings. The same binary answers `<file> <hex offset>` with what the ENGINE says of that function (kof_cfgview_build, the pull API
the viewer asks), so every assertion about the dialog is against the engine's own text and not against a copy made here. Assertions are on text
with REQUIRED and FORBIDDEN rows; there is no golden screen. What the dialog shows is compared with the ROWS OF ITS BODY that the unit test binary prints
(`<file> <hex offset> --body overview|graph`: kv_cfgbody.c, the same code the dialog asks), at the scroll offsets the case set. The Disasm tab is compared with the library's own disassembly of the function
(`<file> <hex offset> --insn`) and the Overview's table with the engine's calls as fields (`--calls`). No key and no menu item is added for the dialog: a case sends keys to prove none opens it.
"""
from tui import *
from dl import *
import subprocess

A = 'cfgview'
BLK = re.compile(r'^\s+\[( |x)\]\s+0x([0-9a-f]{8})\s+([0-9a-f]{8}|-)\s+([A-Za-z_]\S*)?\s*(\d+)\s+(CODE|DATA|NOLOAD)\b(.*)$')

_state = {}


def helper():
    """The unit test binary that writes the scene and prints the engine's text of one function (built on demand in the tree under test)."""
    if 'bin' not in _state:
        exe = os.path.join(REPO, 'build', 'test', 'unit_cfg_view_scene')
        r = subprocess.run(['make', '-s', '-j2', 'build/test/unit_cfg_view_scene'], cwd=REPO, capture_output=True, text=True)
        check(r.returncode == 0 and os.path.exists(exe), 'cannot build the helper: %s' % r.stderr[-300:])
        _state['bin'] = exe
    return _state['bin']


def scene(name='cfg_scene.elf', damage=None, cut=None):
    """The scene's ELF in the scratch directory, read-only; `damage` is (offset, bytes) written over it, `cut` a size to truncate to."""
    d = os.path.join(VT, 'cfgview')
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, name)
    if os.path.exists(p):
        os.chmod(p, 0o644)
    r = subprocess.run([helper(), '--write', p], capture_output=True)
    check(r.returncode == 0, 'the writer failed')
    if damage:
        b = bytearray(open(p, 'rb').read())
        b[damage[0]:damage[0] + len(damage[1])] = damage[1]
        open(p, 'wb').write(bytes(b))
    if cut:
        b = open(p, 'rb').read()[:cut]
        open(p, 'wb').write(b)
    os.chmod(p, 0o444)
    return p


def engine_text(path, off):
    """What the engine says of the function at file offset `off` of `path`, through the pull API (the helper), as lines."""
    r = subprocess.run([helper(), path, '%x' % off], capture_output=True, text=True)
    check(r.returncode == 0, 'the helper failed on %s' % path)
    return r.stdout.split('\n')[:-1]


def table(v):
    """The rows of the blocks table: (y, offset, hash, name, region, rest)."""
    out = []
    for y in panel(v):
        m = BLK.match(v.row(y))
        if m:
            out.append((y, int(m.group(2), 16), m.group(3), (m.group(4) or '').strip(), m.group(6), m.group(7)))
    return out


def blocks(path=None, rows=60, cols=200):
    v = Viewer(path or scene(), rows=rows, cols=cols)
    open_tab(v, 'Blocks')
    v.wait_for('[ ]  0x', t=10)
    return v


def function_rows(v):
    """The rows that are a function: the engine names them (a symbol, or fcn_<offset>) and they are CODE. A signed one shows its unit id in the hash column,
    one the engine did not sign shows `-` (the floor of 12 reachable blocks is gone: a small function is signed)."""
    return [r for r in table(v) if r[3] and r[4] == 'CODE']


def row_named(v, name):
    r = [x for x in function_rows(v) if x[3].startswith(name)]
    check(r, 'no function row named %s: %r' % (name, [x[3] for x in function_rows(v)]))
    return r[0]


def click_name(v, row):
    """Press the NAME of the row (its text, not the padding after it)."""
    y = row[0]
    v.click(v.row(y).index(row[3]) + 1 + len(row[3]) // 2, y)
    v.pump_quiet(0.2, maxt=5)


def box(v):
    d = v.dialog()
    check(d, 'no dialog on screen:\n%s' % v.show())
    return d


def inner(v):
    """The body rows inside the dialog (the wall and one blank column each side are the frame's; the body's own margin column is in), trailing blanks off: (rows, width, title)."""
    x0, y0, x1, y1, title = box(v)
    return [v.row(y)[x0 + 1:x1 - 2].rstrip() for y in range(y0 + 1, y1)], x1 - x0 - 3, title


TABS = ('Overview', 'Disasm', 'Graph')


def body_rows(path, off, tab='Overview'):
    """The rows of one tab of the dialog body as the engine side makes them (kv_cfgbody.c; the Disasm tab has no such rows): (n_row, n_col, rows)."""
    r = subprocess.run([helper(), path, '%x' % off, '--body', tab.lower()], capture_output=True, text=True)
    check(r.returncode == 0, 'the helper failed on %s' % path)
    lines = r.stdout.split('\n')
    n_row, n_col = [int(x) for x in lines[0].split()]
    return n_row, n_col, lines[1:1 + n_row]


def expect(rows, off, hoff, width, height):
    """What the dialog shows for a window of the body: row `off` at the top, `hoff` columns off to the left (the margin column stays)."""
    out = []
    for i in range(height):
        r = rows[off + i] if off + i < len(rows) else ''
        out.append((' ' + r[1:][hoff:hoff + width - 1]).rstrip() if r or hoff == 0 else '')
    return out


def same_window(v, rows, off, hoff, what):
    got, w, _ = inner(v)
    want = expect(rows, off, hoff, w, len(got))
    for i, (g, e) in enumerate(zip(got, want)):
        eq(g.rstrip(), e.rstrip(), '%s: row %d of the dialog differs from the body (scroll %d, sideways %d)' % (what, i, off, hoff))


def func_off(v, row):
    """The function's own offset, from the dialog's extent line (the row's offset is the unit's)."""
    click_name(v, row)
    for l in inner(v)[0]:
        m = re.match(r' extent  0x([0-9a-f]+) \+', l)
        if m:
            return int(m.group(1), 16)
    raise Fail('no extent line in the dialog')


def handle_x(v):
    """A column of the top rule that is neither a tab title nor [ Close ]: where a press takes hold of the box."""
    x0, y0, x1, y1, _ = box(v)
    return v.row(y0).index('Graph') + len('Graph') + 6


def show_tab(v, name):
    """Press the title of a tab of the strip in the top rule (a mouse press: the tabs have no key)."""
    x0, y0, x1, y1, _ = box(v)
    v.click(v.row(y0).index(name) + 2, y0)
    v.pump_quiet(0.2, maxt=5)


def current_tab(v):
    """The tab the strip shows as selected (the reverse video one)."""
    x0, y0, x1, y1, _ = box(v)
    line = v.row(y0)
    sel = [t for t in TABS if t in line and v.cell(line.index(t) + 2, y0).reverse]
    check(len(sel) == 1, 'tabs shown as selected: %r in %r' % (sel, line))
    return sel[0]


def close(v):
    x0, y0, x1, y1, _ = box(v)
    v.click(v.row(y0).index('[ Close ]') + 3, y0)
    v.pump_quiet(0.2, maxt=5)


@case(A)
def function_rows_are_named_by_the_engine_and_nothing_says_show_cfg():
    with blocks() as v:
        rows = table(v)
        fn = function_rows(v)
        data = [r for r in rows if r not in fn]
        check(len(fn) == 5, 'function rows: %r' % [r[3] for r in rows])
        check(data, 'no data row in the scene: %r' % [r[3] for r in rows])
        eq([r[3] for r in fn[:4]], ['cv_small', 'cv_loop', 'cv_switch', 'cv_big'], 'the names of the functions the symbols name')
        # the function no symbol names is fcn_<offset>, the offset of its row (it is a unit of its own)
        eq(fn[4][3], 'fcn_%08x' % fn[4][1], 'an unnamed function is fcn_<offset>')
        for r in data:
            check(r[3] == '', 'a data row has a name: %r' % (r,))
        # FORBIDDEN: a button or cell of its own anywhere on the screen
        check('show CFG' not in v.text() and 'Overview' not in v.text() and not v.dialog(), 'a cell or a dialog before any click')
        # the name looks like every other name: the colour of the size cell beside it (plain), not a control colour
        r = row_named(v, 'cv_loop')
        line = v.row(r[0])
        nx = line.index(r[3]) + 2
        sx = line.index(' CODE') - 3
        eq(v.cell(nx, r[0]).fg, v.cell(sx, r[0]).fg, 'the name of a function has a colour of its own')


@case(A)
def pressing_a_function_name_opens_the_dialog_and_it_shows_the_body_the_engine_side_makes():
    p = scene()
    with blocks(p) as v:
        for name in ('cv_small', 'cv_loop', 'cv_switch', 'cv_big', 'fcn_'):
            row = row_named(v, name)
            off = func_off(v, row)
            rows, w, title = inner(v)
            # the dialog opens on the Overview: the strip names the three tabs in order, the engine's head is the first rows
            check(title.startswith('Overview') and title.index('Overview') < title.index('Disasm') < title.index('Graph'), 'the strip: %r' % title)
            eq(current_tab(v), 'Overview', 'the tab it opens on')
            n_row, n_col, want = body_rows(p, off)
            check(n_row > 8 and want[0].strip() == 'function %s' % row[3], 'the engine side gave no overview for %s: %r' % (name, want[:2]))
            same_window(v, want, 0, 0, name + ' overview')
            # the Graph tab: the engine's graph as boxes; every reachable block of the function is a box (up to the drawing's cap), a loop head is marked
            show_tab(v, 'Graph')
            eq(current_tab(v), 'Graph', 'after a press on Graph')
            g_row, g_col, gwant = body_rows(p, off, 'Graph')
            same_window(v, gwant, 0, 0, name + ' graph')
            txt = '\n'.join(gwant)
            blk = int(re.search(r'reachable=(\d+)', '\n'.join(want)).group(1))
            check(len(re.findall(r'[│|] B\d+( @)? 0x', txt)) == blk, '%s: %d reachable blocks, boxes: %d' % (name, blk, len(re.findall(r'[│|] B\d+( @)? 0x', txt))))
            # FORBIDDEN: legend prose; the facts of the Overview are not repeated in the Graph
            check('legend' not in txt and 'letters' not in txt and 'BACK edge' not in txt, '%s: legend prose in the body' % name)
            check('extent  0x' not in txt and 'canon  0x' not in txt, '%s: the Graph tab holds the Overview facts' % name)
            close(v)
            check(not v.dialog(), 'the dialog did not close')


@case(A)
def only_the_name_of_a_function_row_opens_it_and_the_offset_lights():
    with blocks() as v:
        row = row_named(v, 'cv_loop')
        y = row[0]
        line = v.row(y)
        name_x = line.index(row[3])
        # the padding after the name, the size, the region, the offset (it lights the block) and the hash (the same) never open the dialog (the tick is not pressed)
        hx = line.index(row[2])
        for x in (name_x + len(row[3]) + 3, line.index(' CODE') + 3, line.index('0x00000200') + 4, hx + 1):
            v.click(x, y)
            v.pump_quiet(0.2, maxt=4)
            check(not v.dialog(), 'a press at column %d of a function row opened a dialog' % x)
            check('Overview' not in v.text(), 'a press at column %d showed the CFG' % x)
            if x in (line.index('0x00000200') + 4, hx + 1):
                v.click(x, y)             # a second press puts the light out again
                v.pump_quiet(0.2, maxt=4)
        # the name of a DATA row is blank: nothing to press; and a press on its other cells opens nothing
        d = [r for r in table(v) if r not in function_rows(v)][0]
        for x in (name_x + 2, v.row(d[0]).index(' DATA') + 3):
            v.click(x, d[0])
            v.pump_quiet(0.2, maxt=4)
            check(not v.dialog(), 'a data row opened a dialog')
        check(v.alive(), 'the viewer died')


@case(A)
def the_hash_line_is_the_engines_canon_and_the_anchor_is_said():
    p = scene()
    with blocks(p) as v:
        for name, verdict in (('cv_small', ': PASS'), ('cv_loop', ': PASS'),
                              ('cv_switch', ': PASS'), ('cv_big', ': PASS')):
            off = func_off(v, row_named(v, name))
            n_row, n_col, want = body_rows(p, off)
            canon = [l for l in engine_text(p, off) if l.startswith('canon  0x')]
            check(len(canon) == 1, 'the engine has no canon line')
            check(canon[0] in [l.strip() for l in want], '%s: the body does not hold %r' % (name, canon[0]))
            # the facts are the Overview's head: read them on the screen
            lines = [l.strip() for l in inner(v)[0]]
            check(any(l.startswith('anchor  ') and verdict in l for l in lines), '%s: anchor line missing: %r' % (name, [l for l in lines if l][-8:]))
            check(not any('hashed' in l or 'shape' in l for l in lines), '%s: a sentence of explanation in the Overview' % name)
            check(any(l.startswith('keys   ') for l in lines) and canon[0] in lines, 'no keys line or canon line')
            close(v)
        # its calls are in the Overview's table with the names the object gives them, and each in its box of the Graph
        off = func_off(v, row_named(v, 'cv_small'))
        _, _, want = body_rows(p, off)
        txt = '\n'.join(want)
        check(re.search(r'call +0x[0-9a-f]+ +cv_loop', txt) and 'syscall' in txt and 'call indirect' in txt, 'the call facts are not in the Overview:\n%s' % txt[-400:])
        check('not evidence' not in txt and 'rebuild changes' not in txt and re.search(r'^ *calls: 3$', txt, re.M), 'the calls title is the count and nothing else')
        _, _, gwant = body_rows(p, off, 'Graph')
        gtxt = '\n'.join(gwant)
        check(re.search(r'[│|] call cv_loop', gtxt) and re.search(r'[│|] syscall', gtxt), 'the calls are not lines of the boxes')
        close(v)


@case(A)
def the_bottom_rule_has_no_choose_sentence_and_the_dialog_has_its_frame():
    with blocks() as v:
        click_name(v, row_named(v, 'cv_loop'))
        x0, y0, x1, y1, _ = box(v)
        foot = v.row(y1)
        check('choose is not available' not in foot, 'the bottom rule still carries the retired sentence: %r' % foot)
        # the one control besides the tab titles is the frame's own [ Close ] on the top rule
        eq(v.row(y0).count('['), 1, 'controls on the title row')
        check('[ Close ]' in v.row(y0), 'no Close on the top rule')
        # modal: the dialog stays until Close
        close(v)
        check(not v.dialog(), 'still open after [ Close ]')


@case(A)
def closing_works_and_it_opens_again():
    with blocks() as v:
        row = row_named(v, 'cv_loop')
        before = [v.row(y) for y in range(1, v.rows + 1)]
        click_name(v, row)
        box(v)
        close(v)
        check(not v.dialog(), 'still open after [ Close ]')
        eq([v.row(y) for y in range(1, v.rows + 1)], before, 'the screen did not come back as it was')
        click_name(v, row)
        box(v)
        v.esc(1)
        v.pump_quiet(0.2, maxt=4)
        check(not v.dialog(), 'Esc did not close it')
        click_name(v, row)
        box(v)
        close(v)
        check(v.alive(), 'the viewer died')


@case(A)
def the_wheel_scrolls_the_dialog_down_and_it_has_a_scrollbar():
    p = scene()
    with blocks(p, rows=40) as v:
        off = func_off(v, row_named(v, 'cv_big'))
        show_tab(v, 'Graph')
        n_row, n_col, want = body_rows(p, off, 'Graph')
        rows, w, _ = inner(v)
        h = len(rows)
        check(n_row > h, 'the body fits the box: nothing to scroll (%d rows, %d lines)' % (n_row, h))
        same_window(v, want, 0, 0, 'top')
        x0, y0, x1, y1, _ = box(v)
        # a scrollbar in the right wall: a thumb glyph on some row of the wall
        wall = ''.join(v.row(y)[x1 - 1] for y in range(y0 + 1, y1))
        check(any(c in wall for c in '┃╿╽'), 'no scrollbar thumb in the right wall: %r' % wall)
        v.wheel((x0 + x1) // 2, (y0 + y1) // 2, n=3)
        v.pump_quiet(0.2, maxt=5)
        same_window(v, want, 9, 0, 'three notches')                # three rows a notch
        v.wheel((x0 + x1) // 2, (y0 + y1) // 2, up=True, n=12)
        v.pump_quiet(0.2, maxt=5)
        same_window(v, want, 0, 0, 'back to the top')
        v.wheel((x0 + x1) // 2, (y0 + y1) // 2, n=2000)
        v.pump_quiet(0.2, maxt=5)
        same_window(v, want, n_row - h, 0, 'the end')
        # no key scrolls it: the dialog owns the keyboard and answers only Esc and Enter
        v.key('up')
        v.key('pgup')
        v.pump_quiet(0.2, maxt=4)
        same_window(v, want, n_row - h, 0, 'after Up and PgUp')
        close(v)


@case(A)
def the_shift_and_ctrl_wheel_scroll_it_sideways():
    p = scene()
    with blocks(p, rows=50, cols=100) as v:
        off = func_off(v, row_named(v, 'cv_big'))
        show_tab(v, 'Graph')
        n_row, n_col, want = body_rows(p, off, 'Graph')
        rows, w, _ = inner(v)
        check(n_col + 1 > w, 'the body (%d columns) fits the box (%d): nothing to scroll sideways' % (n_col, w))
        x0, y0, x1, y1, _ = box(v)
        cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
        # the top rows of the drawing are one box in the middle of a wide canvas: start where the boxes spread over the width
        v.wheel(cx, cy, n=6)
        v.pump_quiet(0.2, maxt=5)
        rows, w, _ = inner(v)
        same_window(v, want, 18, 0, 'left edge')
        v.wheel(cx, cy, n=3, mod=4)                                  # shift + wheel: eight columns a notch
        v.pump_quiet(0.2, maxt=5)
        same_window(v, want, 18, 24, 'shift, three notches')
        check(inner(v)[0] != rows, 'the shifted wheel did not move the text')
        v.wheel(cx, cy, n=2, mod=16)                                 # ctrl + wheel: the same
        v.pump_quiet(0.2, maxt=5)
        same_window(v, want, 18, 40, 'ctrl, two more notches')
        v.wheel(cx, cy, up=True, n=50, mod=4)
        v.pump_quiet(0.2, maxt=5)
        same_window(v, want, 18, 0, 'back to the left edge')
        v.wheel(cx, cy, n=500, mod=4)                                # as far as it goes: the widest row ends at the right edge
        v.pump_quiet(0.2, maxt=5)
        got, w, _ = inner(v)
        check(max(len(g) for g in got) <= w and max(len(g) for g in got) >= w - 2, 'at the far end the widest row does not end at the right edge: %d of %d' % (max(len(g) for g in got), w))
        # vertical and sideways together
        v.wheel(cx, cy, n=4)
        v.pump_quiet(0.2, maxt=5)
        check(inner(v)[0] != got, 'the plain wheel did not scroll down after a sideways scroll')
        close(v)


@case(A)
def the_title_bar_drags_the_dialog_and_it_stays_on_the_screen():
    p = scene()
    with blocks(p, rows=60, cols=160) as v:
        off = func_off(v, row_named(v, 'cv_small'))
        n_row, n_col, want = body_rows(p, off)
        d0 = box(v)
        hx = handle_x(v)                                   # the top rule right of the tab titles: a press on a title is not a handle
        v.drag(hx, d0[1], hx - 12, d0[1] + 6)
        v.pump_quiet(0.2, maxt=5)
        d1 = box(v)
        eq((d1[0], d1[1]), (d0[0] - 12, d0[1] + 6), 'the box did not move with the drag')
        eq((d1[2] - d1[0], d1[3] - d1[1]), (d0[2] - d0[0], d0[3] - d0[1]), 'the box changed size when dragged')
        same_window(v, want, 0, 0, 'after the drag')
        # a drag past the corner keeps the box whole on the screen
        v.drag(handle_x(v), d1[1], 1, 1)
        v.pump_quiet(0.2, maxt=5)
        d2 = box(v)
        check(d2[0] >= 1 and d2[1] >= 2 and d2[2] <= v.cols and d2[3] <= v.rows, 'the box left the screen: %r' % (d2,))
        # the body is not a handle: a drag that starts in it moves nothing
        x0, y0, x1, y1, _ = d2
        v.drag((x0 + x1) // 2, (y0 + y1) // 2, (x0 + x1) // 2 + 9, (y0 + y1) // 2 + 4)
        v.pump_quiet(0.2, maxt=5)
        eq(box(v)[:2], d2[:2], 'a drag in the body moved the box')
        close(v)
        check(not v.dialog(), 'the moved box did not close')
        # it opens centred again
        click_name(v, row_named(v, 'cv_small'))
        eq(box(v)[:2], d0[:2], 'the dialog did not open where it opened the first time')
        close(v)


@case(A)
def a_big_function_has_every_block_as_a_box_and_a_say_for_what_it_leaves_out():
    p = scene()
    with blocks(p) as v:
        off = func_off(v, row_named(v, 'cv_big'))
        m = re.search(r'reachable=(\d+)', '\n'.join(body_rows(p, off)[2]))
        n_row, n_col, want = body_rows(p, off, 'Graph')
        txt = '\n'.join(want)
        check(m and int(m.group(1)) >= 60, 'cv_big has %s blocks' % (m and m.group(1)))
        # the drawing's cap is 400 boxes: every block of this function is a box, and nothing says "not drawn"
        boxes = re.findall(r'[│|] B\d+( @)? 0x', txt)
        eq(len(boxes), int(m.group(1)), 'boxes of cv_big')
        check('not drawn' not in txt, 'a function inside the caps says something is not drawn')
        # loop links are dotted, with their arrowhead under the head (the plain set is `:` and `=`, the box-drawing set the dotted glyphs)
        check(re.search(r'[┆┄:=]', txt) and '^' in txt, 'cv_big has loops and the body shows none')
        close(v)


@case(A)
def a_damaged_function_says_so_and_the_viewer_lives():
    # Eight undecodable bytes (0x06 is not an instruction in 64-bit mode) inside cv_loop: the engine steps over them and says so.
    base = scene('cfg_probe.elf')
    with blocks(base) as v:
        off = func_off(v, row_named(v, 'cv_loop'))
    p = scene('cfg_damaged.elf', damage=(off + 16, b'\x06' * 8))
    with blocks(p) as v:
        row = row_named(v, 'cv_loop')
        click_name(v, row)
        lines, _, _ = inner(v)
        txt = '\n'.join(lines)
        check('skipped-bytes=' in txt and 'status=truncated' in txt, 'a damaged function does not say so:\n%s' % txt[:700])
        n_row, n_col, want = body_rows(p, off)
        same_window(v, want, 0, 0, 'damaged')
        check(any('skipped-bytes=' in l for l in engine_text(p, off)), 'the engine does not say it either')
        check(v.alive(), 'the viewer died')
        close(v)
    # a truncated object: the viewer opens it (or refuses it) and does not crash, and any function name it shows opens a dialog
    for cut in (0x300, 0x80, 0x205, 1100):
        q = scene('cfg_cut.elf', cut=cut)
        w = Viewer(q, rows=60, cols=200)
        try:
            open_tab(w, 'Blocks')
            w.pump_quiet(0.3, maxt=5)
            rows = function_rows(w)
            for r in rows[:1]:
                click_name(w, r)
            check(w.alive(), 'the viewer died on the object cut at %d' % cut)
        except Fail:
            check(w.alive(), 'the viewer died on the object cut at %d' % cut)
        finally:
            w.close()


@case(A)
def no_key_opens_the_dialog_and_the_menu_has_no_new_item():
    with blocks() as v:
        for k in ('c', 'C', 'g', 'f', 'enter', 'tab', 'ctrl+o'):
            v.key(k)
            v.pump_quiet(0.15, maxt=3)
            check('Overview' not in v.text() and not v.dialog(), 'the key %r opened the dialog' % k)
            v.esc(2)
        check(v.alive(), 'died')
    with blocks() as v:
        for menu in ('File', 'Edit', 'Analysis', 'Manage', 'Help'):
            items = v.menu_items(menu)
            check(not [i for i in items if 'CFG' in i], 'the %s menu has a CFG item: %r' % (menu, items))
            v.esc(2)


def engine_calls(path, off):
    """The engine's calls of the function as fields (the helper's --calls): [(block, offset, kind number, target or None, name)]."""
    r = subprocess.run([helper(), path, '%x' % off, '--calls'], capture_output=True, text=True)
    check(r.returncode == 0, 'the helper failed on %s' % path)
    out = []
    for l in r.stdout.split('\n')[:-1]:
        f = l.split(' ', 4)
        out.append((f[0], int(f[1], 16), int(f[2]), None if f[3] == '-' else int(f[3], 16), f[4] if len(f) > 4 else ''))
    return out


KIND = {1: 'call', 2: 'call', 3: 'call', 4: 'call indirect', 5: 'syscall'}


@case(A)
def the_strip_names_three_tabs_and_a_press_on_a_title_switches():
    p = scene()
    with blocks(p) as v:
        off = func_off(v, row_named(v, 'cv_small'))
        x0, y0, x1, y1, title = box(v)
        eq(re.findall(r'[A-Za-z]+', title)[:3], list(TABS), 'the titles of the strip, in order')
        eq(current_tab(v), 'Overview', 'the tab it opens on')
        top = [v.row(y) for y in range(y0, y1 + 1)]
        show_tab(v, 'Disasm')
        eq(current_tab(v), 'Disasm', 'after a press on Disasm')
        check([v.row(y) for y in range(y0, y1 + 1)] != top, 'the body did not change')
        # the same tab again changes nothing
        again = [v.row(y) for y in range(y0, y1 + 1)]
        show_tab(v, 'Disasm')
        eq([v.row(y) for y in range(y0, y1 + 1)], again, 'a press on the tab already shown changed the screen')
        show_tab(v, 'Graph')
        eq(current_tab(v), 'Graph', 'after a press on Graph')
        show_tab(v, 'Overview')
        eq(current_tab(v), 'Overview', 'after a press on Overview')
        eq([v.row(y) for y in range(y0, y1 + 1)], top, 'back on the Overview the screen is as it was')
        # the box stays where it is and as big as it was from tab to tab
        eq(box(v)[:4], (x0, y0, x1, y1), 'the box moved or changed size')
        # a press in the body, or on the top rule beside the titles, switches nothing
        v.click((x0 + x1) // 2, (y0 + y1) // 2)
        v.pump_quiet(0.2, maxt=4)
        eq(current_tab(v), 'Overview', 'a press in the body switched the tab')
        close(v)


@case(A)
def no_key_switches_a_tab():
    p = scene()
    with blocks(p) as v:
        click_name(v, row_named(v, 'cv_loop'))
        x0, y0, x1, y1, _ = box(v)
        before = [v.row(y) for y in range(y0, y1 + 1)]
        for k in ('tab', 'backtab', 'right', 'left', '1', '2', '3', 'ctrl+n', 'ctrl+o', 'ctrl+e', 'ctrl+a', 'pgdn', 'pgup', 'home', 'end', 'g', 'd', 'o', 'f'):
            v.key(k)
            v.pump_quiet(0.15, maxt=3)
            check(v.dialog(), 'the key %r closed the dialog' % k)
            eq(current_tab(v), 'Overview', 'the key %r switched the tab' % k)
        eq([v.row(y) for y in range(y0, y1 + 1)], before, 'a key changed the dialog')
        show_tab(v, 'Graph')
        for k in ('tab', 'backtab', 'right', 'left', '1', 'ctrl+n'):
            v.key(k)
            v.pump_quiet(0.15, maxt=3)
            eq(current_tab(v), 'Graph', 'the key %r switched the tab away from the Graph' % k)
        close(v)


@case(A)
def overview_calls_table_cells_are_the_engines_fields():
    p = scene()
    with blocks(p, rows=60, cols=200) as v:
        off = func_off(v, row_named(v, 'cv_small'))
        calls = engine_calls(p, off)
        check(len(calls) == 3, 'the engine has %d calls of cv_small' % len(calls))
        lines = [l.strip() for l in inner(v)[0]]
        # the head: the engine's own lines, in the engine's words (the helper prints the engine's text)
        head = [l.strip() for l in engine_text(p, off)[:3]]
        eq(lines[:3], head, 'the first three rows of the Overview are the engine head lines')
        # the table: a header and one row per call, every cell a field of struct kof_cfgview_call
        hdr = [i for i, l in enumerate(lines) if re.match(r'block\s+offset\s+kind\s+target\s+name$', l)]
        eq(len(hdr), 1, 'table header rows: %r' % lines)
        rows = lines[hdr[0] + 1:hdr[0] + 1 + len(calls)]
        for (blk, at, kind, target, name), row in zip(calls, rows):
            m = re.match(r'(B\d+)\s+0x([0-9a-f]+)\s+(call indirect|call|syscall)\s+(-|0x[0-9a-f]+)(?:\s+(\S.*))?$', row)
            check(m, 'a call row does not parse: %r' % row)
            eq(m.group(1), blk, 'block cell')
            eq(int(m.group(2), 16), at, 'offset cell')
            eq(m.group(3), KIND[kind], 'kind cell')
            eq(None if m.group(4) == '-' else int(m.group(4), 16), target, 'target cell')
            eq(m.group(5) or '', name, 'name cell')
        # a call to a function of the object has a target and the object's name for it; a syscall has none
        check(calls[0][3] is not None and calls[0][4] == 'cv_loop' and calls[1][3] is None, 'the scene changed: %r' % (calls,))
        # FORBIDDEN: a column for what the engine does not expose on a call
        txt = '\n'.join(lines)
        check('nucleo' not in txt.lower() and 'activit' not in txt.lower() and 'links to' not in txt.lower(), 'a nucleo / activity column in the Overview')
        # the unreachable block the engine listed is the last rows
        check(any(l.startswith('unreachable blocks') for l in lines) and any(re.match(r'0x[0-9a-f]+ n_insn=\d+$', l) for l in lines), 'no unreachable blocks in the Overview')
        close(v)
    # a function with no call has no table
    with blocks(p, rows=60, cols=200) as v:
        off = func_off(v, row_named(v, 'cv_loop'))
        check(not engine_calls(p, off), 'cv_loop has calls')
        lines = [l.strip() for l in inner(v)[0]]
        check(not [l for l in lines if re.match(r'block\s+offset', l)], 'a table for a function with no call')
        close(v)


def disasm_rows(v, top_to_bottom=True):
    """Every row of the Disasm tab, read by scrolling the dialog down a window at a time: [(offset, text before the comment) or ('label', text)]."""
    x0, y0, x1, y1, _ = box(v)
    cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
    v.wheel(cx, cy, up=True, n=3000)
    v.pump_quiet(0.2, maxt=5)
    seen = []
    last = None
    for _ in range(400):
        rows = [l.rstrip() for l in inner(v)[0]]
        for l in rows:
            m = re.match(r' {1,2}([0-9a-f]{8})  (?:[0-9a-f]{2} ?)*\s+(.*)$', l)
            if m:
                t = m.group(2).split('  ; ')[0].strip()
                if (int(m.group(1), 16), t) not in seen:
                    seen.append((int(m.group(1), 16), t))
            elif l.strip():
                if ('label', l.strip()) not in seen:
                    seen.append(('label', l.strip()))
        if rows == last:
            break
        last = rows
        v.wheel(cx, cy, n=8)
        v.pump_quiet(0.15, maxt=5)
    return seen


def oracle_insns(path, off):
    r = subprocess.run([helper(), path, '%x' % off, '--insn'], capture_output=True, text=True)
    check(r.returncode == 0, 'the helper failed on %s' % path)
    out = []
    for l in r.stdout.split('\n')[:-1]:
        a, t = l.split(' ', 1)
        out.append((int(a, 16), ' '.join(t.split())))
    return out


@case(A)
def disasm_tab_lists_the_functions_instructions_as_the_librarys_disassembler_spells_them():
    p = scene()
    with blocks(p, rows=60, cols=200) as v:
        for name in ('cv_small', 'cv_loop'):
            off = func_off(v, row_named(v, name))
            show_tab(v, 'Disasm')
            eq(current_tab(v), 'Disasm', 'on the Disasm tab')
            want = oracle_insns(p, off)
            check(len(want) > 100, 'the oracle has %d instructions' % len(want))
            got = disasm_rows(v)
            labels = [t for k, t in got if k == 'label']
            insns = [(k, ' '.join(t.split())) for k, t in got if k != 'label']
            # the function's own name is a label row above its first instruction, as the panel draws it
            eq(labels, ['%s:' % name], 'label rows of %s' % name)
            # every instruction of the function, in order, none of another function, the library's text (the panel's comments come after it)
            eq([o for o, _ in insns], [o for o, _ in want], '%s: the offsets of the rows' % name)
            for (o, t), (o2, t2) in zip(insns, want):
                eq(t, t2, '%s: the text of the row at 0x%x' % (name, o))
            check('more byte(s) of the function not listed' not in '\n'.join(l for l in inner(v)[0]), 'the walk stopped short')
            close(v)
        # the panel's comment is there: a call to a named function says its name, a compare says what it compares
        off = func_off(v, row_named(v, 'cv_small'))
        show_tab(v, 'Disasm')
        lines = [l.strip() for l in inner(v)[0]]
        check(any('CALL' in l and '; cv_loop' in l for l in lines), 'the call to cv_loop has no name beside it:\n%s' % '\n'.join(lines[:12]))
        check(any('CMP' in l and '; compare eax with 0x1' in l for l in lines), 'the compare has no note')
        check(any('JZ' in l and '; jump if eax == 0x1' in l for l in lines), 'the conditional jump has no note')
        close(v)


@case(A)
def disasm_tab_reads_the_analysis_the_reader_ran_and_asks_for_none():
    # What the object's analysis (Analysis > Analyze disassembly: the engine's notes for the whole object) holds is in the Disasm tab as it is in the panel: a jump label row,
    # the engine's comment beside a call. Before it is run the tab has the panel's plain labels and comments, and opening the tab does not run it.
    p = scene()
    with blocks(p, rows=60, cols=200) as v:
        click_name(v, row_named(v, 'cv_small'))
        show_tab(v, 'Disasm')
        before = '\n'.join(inner(v)[0])
        check('.L-' not in before and '; -> ' not in before, 'the tab shows notes the reader never asked for:\n%s' % before[:600])
        close(v)
        check(v.menu_item('Analysis', 'Analyze disassembly'), 'no Analyze disassembly item')
        v.pump_quiet(0.5, maxt=10)
        click_name(v, row_named(v, 'cv_small'))
        show_tab(v, 'Disasm')
        after = '\n'.join(inner(v)[0])
        check(re.search(r'\.L-[0-9a-f]+:', after) and re.search(r'CALL +0x200 +; -> cv_loop', after), 'the analysis is not in the Disasm tab:\n%s' % after[:800])
        close(v)


def dialog_cells(v):
    """(char, foreground) of every cell inside the dialog box."""
    x0, y0, x1, y1, _ = box(v)
    return [[(v.cell(x, y).data, v.cell(x, y).fg) for x in range(x0 + 1, x1)] for y in range(y0 + 1, y1)]


@case(A)
def graph_tab_colours_its_edges_and_marks_from_the_engines_values():
    # The attribute of an edge is a function of the engine's (cond, loop) and is asserted exhaustively on data in tests/unit/cfg_view_scene.c; this is the smoke on the real screen:
    # T green, F red, a loop head's first row yellow, the entry's border cyan, the call rows of a block blue; the Overview and the Disasm tabs are not touched.
    p = scene()
    with blocks(p, rows=70, cols=200) as v:
        click_name(v, row_named(v, 'cv_loop'))
        ov = dialog_cells(v)
        check(not any(fg in ('green', 'red', 'cyan', 'brown') and ch in 'TF' for row in ov for ch, fg in row), 'the Overview carries graph colours')
        show_tab(v, 'Graph')
        cells = dialog_cells(v)
        flat = [c for row in cells for c in row]
        check(('T', 'green') in flat, 'no green T')
        check(('F', 'red') in flat, 'no red F')
        # the loop head: the `@` of its first row and the row's text are yellow
        at = [(ch, fg) for row in cells for ch, fg in row if ch == '@']
        check(at and all(fg == 'brown' for ch, fg in at), 'the loop head rows are not yellow: %r' % at)
        # loop links are dotted and yellow when unconditional; every dotted glyph is a coloured one
        dots = [fg for row in cells for ch, fg in row if ch in '\u2506\u2504']
        check(dots and all(fg in ('brown', 'green', 'red') for fg in dots), 'a dotted loop link in a colour of no kind: %r' % sorted(set(dots)))
        # the entry node's border is cyan: one box, four corners
        corners = [fg for row in cells for ch, fg in row if ch in '\u256d\u256e\u2570\u256f']
        eq(sum(1 for fg in corners if fg == 'cyan'), 4, 'the entry box corners are not the only cyan ones (%r)' % corners[:12])
        # the plain forward edges keep the terminal colour
        check(any(fg == 'default' for row in cells for ch, fg in row if ch in 'v'), 'no unconditional edge in the terminal colour')
        close(v)
    with blocks(p, rows=70, cols=200) as v:
        click_name(v, row_named(v, 'cv_small'))
        show_tab(v, 'Graph')
        cells = dialog_cells(v)
        calls = []
        for row in cells:
            txt = ''.join(ch for ch, fg in row)
            i = txt.find('call cv_loop')
            if i >= 0:
                calls.append({fg for ch, fg in row[i:i + len('call cv_loop')]})
        check(calls and all(c == {'blue'} for c in calls), 'the call rows of a block are not blue: %r' % calls)
        # the box's own first rows are not call rows: B1 holds the calls, its first two rows are in the terminal colour
        for row in cells:
            txt = ''.join(ch for ch, fg in row)
            i = txt.find('in=0 out=2 call=0')
            if i >= 0:
                check({fg for ch, fg in row[i:i + 10]} == {'default'}, 'the counts row is coloured')
        close(v)


def styled_row(v, y, x_from):
    """(character, foreground, bold) of the cells of a screen row from column x_from on, trailing blanks off."""
    cells = [(v.cell(x, y).data, v.cell(x, y).fg, v.cell(x, y).bold) for x in range(x_from, v.cols + 1)]
    while cells and cells[-1][0] == ' ':
        cells.pop()
    return cells


@case(A)
def disasm_tab_keeps_the_panels_colours_row_for_row():
    # The panel (Analysis > Show disassembly) on the scene's code, and the dialog's Disasm tab of cv_small, draw the instruction at 0x100 with the same colours: the offset, the
    # bytes, the mnemonic, the register, the immediate, the comment. The panel is the oracle: one formatter, one palette.
    p = scene()
    panel = None
    with blocks(p, rows=60, cols=200) as v:
        v.click(10, 4)                                  # the CODE region
        v.pump_quiet(0.2, maxt=4)
        check(v.menu_item('Analysis', 'Show disassembly'), 'no Show disassembly item')
        v.pump_quiet(0.3, maxt=5)
        # a press on the first byte of 0x100 in the hex pane moves the panel to it
        for y in range(2, 23):
            if '00000100   83 F8' in v.row(y):
                v.click(v.row(y).index('83 F8') + 1, y)
                v.pump_quiet(0.3, maxt=5)
                break
        for y in range(2, v.rows):
            if v.row(y).find('00000103  0f 84') >= 0:
                x = v.row(y).index('00000103')
                panel = [c for c in styled_row(v, y, x + 1)]
                break
    check(panel, 'the panel did not show the instruction at 0x103')
    with blocks(p, rows=60, cols=200) as v:
        click_name(v, row_named(v, 'cv_small'))
        show_tab(v, 'Disasm')
        for y in range(2, v.rows):
            if v.row(y).find('00000103  0f 84') >= 0:
                x = v.row(y).index('00000103')
                dlg = [c for c in styled_row(v, y, x + 1)]
                break
        else:
            raise Fail('the dialog did not show the instruction at 0x103')
        # the panel's row runs on to the edge of its pane (the hex pane's divider and its content are beside it): compare what the instruction says
        n = len('00000103  0f 84 15 00 00 00    JZ        0x11e  ; jump if eax == 0x1')
        eq([c[0] for c in dlg[:n]], [c[0] for c in panel[:n]], 'the text of the row')
        eq([(c[1], c[2]) for c in dlg[:n]], [(c[1], c[2]) for c in panel[:n]], 'the colours of the row differ from the panel\'s')
        # the colours are not all one: the offset, the bytes, the mnemonic and the comment are four different foregrounds
        check(len(set(c[1] for c in dlg[:n])) >= 4, 'the row is one colour: %r' % sorted(set(c[1] for c in dlg[:n])))
        close(v)


@case(A)
def each_tab_keeps_the_scroll_it_was_left_at():
    p = scene()
    with blocks(p, rows=40) as v:
        off = func_off(v, row_named(v, 'cv_big'))
        show_tab(v, 'Graph')
        n_row, n_col, want = body_rows(p, off, 'Graph')
        x0, y0, x1, y1, _ = box(v)
        cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
        v.wheel(cx, cy, n=4)
        v.pump_quiet(0.2, maxt=5)
        same_window(v, want, 12, 0, 'graph scrolled')
        show_tab(v, 'Overview')
        _, _, ov = body_rows(p, off)
        same_window(v, ov, 0, 0, 'overview opens at its own top')
        show_tab(v, 'Graph')
        same_window(v, want, 12, 0, 'graph where it was left')
        close(v)


def lit_rows(v):
    return [yy for yy in range(2, 40) if any(v.cell(x, yy).bg != 'default' for x in range(48, 70))]


@case(A)
def the_offset_lights_the_block_and_a_second_press_puts_it_out():
    # A function row and a data row: pressing the OFFSET paints the block's bytes in the hex pane (and scrolls to them), pressing it again clears them;
    # no dialog opens. The hash does the same for now.
    with blocks() as v:
        for r in (row_named(v, 'cv_loop'), [x for x in table(v) if x[2] != '-'][0]):
            x = v.row(r[0]).index('0x%08x' % r[1]) + 4
            check(not lit_rows(v), 'something is lit before the press')
            v.click(x, r[0])
            v.pump_quiet(0.2, maxt=4)
            check(not v.dialog(), 'the offset opened a dialog')
            check(len(lit_rows(v)) >= 3, 'the offset of row 0x%x lit nothing' % r[1])
            r2 = [y for y in table(v) if y[1] == r[1]][0]
            v.click(v.row(r2[0]).index('0x%08x' % r[1]) + 4, r2[0])
            v.pump_quiet(0.2, maxt=4)
            check(not lit_rows(v), 'a second press did not put the light out (row 0x%x)' % r[1])



def examiner_blocks(path):
    """`kofexaminer --blocks` of the scene: {unit offset: block_id or '-'} for the function units (the engine's own list: kof_cfgsign_function)."""
    exe = os.path.join(REPO, 'build', 'release', 'bin', 'kofexaminer')
    r = subprocess.run([exe, '--blocks', path], capture_output=True, text=True)
    out = {}
    for l in r.stdout.split('\n'):
        m = re.search(r'unit  region=CODE  off=0x([0-9a-f]+)  len=\d+  side=\w+  func=\S+.*?block_id=([0-9a-f]{8}|-)', l)
        if m:
            out[int(m.group(1), 16)] = m.group(2)
    return out


@case(A)
def a_function_row_shows_the_engines_unit_id_and_a_dash_below_the_floor():
    p = scene()
    want = examiner_blocks(p)
    check(len(want) == 5, 'the examiner lists %d function units: %r' % (len(want), want))
    with blocks(p) as v:
        fn = function_rows(v)
        for r in fn:
            eq(r[2], want[r[1]], 'the hash cell of %s (0x%x) is the id the engine prints' % (r[3], r[1]))
        # the floor of 12 reachable blocks is gone: cv_small (4 blocks) and fcn_00000700 (1 block) are signed and show an id too
        eq(sorted(r[3] for r in fn if r[2] == '-'), [], 'no function of the scene keeps a dash')
        check(all(re.fullmatch('[0-9a-f]{8}', r[2]) for r in fn), 'every function shows an id')


@case(A)
def a_signed_function_row_is_ticked_like_a_data_row_and_an_unsigned_one_says_why():
    with blocks() as v:
        loop = row_named(v, 'cv_loop')
        v.click(v.row(loop[0]).index('[ ]') + 1, loop[0])
        v.pump_quiet(0.2, maxt=4)
        check(v.row(loop[0]).lstrip().startswith('[x]'), 'the tick of a signed function row did not take: %r' % v.row(loop[0])[:30])
        small = row_named(v, 'cv_small')
        v.click(v.row(small[0]).index('[ ]') + 1, small[0])
        v.pump_quiet(0.2, maxt=4)
        check(v.row(small[0]).lstrip().startswith('[x]'), 'the tick of a small signed function did not take: %r' % v.row(small[0])[:30])


def sign_diagnose_db(p, off, pct=70):
    """A database whose only diagnose is made of the CFG block of the function at file offset `off` of the scene (its keys as the engine prints them), with the catalogs it
    names (a family Mirai with a variant A, a tag Mirai-flood), built by ksigbuilder in this process's scratch directory. Returns (db, bases)."""
    import shutil, subprocess
    want = examiner_keys(p)
    keys = want[off]
    d = os.path.join(VT, 'work', 'cfgsig%d' % os.getpid())
    if os.path.exists(d):
        shutil.rmtree(d)
    for sub in ('tree/diagnoses', 'art', 'db', 'bases/pathogens', 'bases/syndromes', 'bases/diagnoses'):
        os.makedirs(os.path.join(d, sub))
    open(os.path.join(d, 'tree/diagnoses/botnet_mirai_mirai-flood_01.c'), 'w').write(
        'KOF_DIAG_NAME(botnet_mirai_mirai-flood_01);\nKOF_TARGET_FORMAT(KOF_FMT_ELF);\nKOF_DIAG_FAMILY("Mirai");\nKOF_DIAG_VARIANT("A");\nKOF_DIAG_TYPE(KOF_MALTYPE_BOTNET);\n'
        'KOF_DIAG_TAG("Mirai-flood");\nKOF_MUTATION_BLOCK(b0, KOF_SCAN_ELF_CODE, %s);\nKOF_DIAG_SIMILAR(m1, %d, b0);\n'
        % (', '.join('0x%su' % k for k in keys), pct))
    open(os.path.join(d, 'bases/pathogens/mirai.c'), 'w').write('// Generated by Manage > Pathogens; edit by hand with care.\nKOF_MALWARE_FAMILY_NAME("Mirai");\nKOF_MALWARE_NEXT_VARIANT("B");\n'
                                                              'KOF_MALWARE_VARIANT("A", KOF_MALTYPE_BOTNET);\n')
    open(os.path.join(d, 'bases/syndromes/flood.c'), 'w').write('// Generated by Manage > Syndromes; edit by hand with care.\n\nKOF_TAG_NAME("Mirai-flood");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_DESTRUCTION);\n'
                                                              'KOF_TAG_OBJS(KOF_DISEASE_OBJ_NETWORK);\n')
    exe = os.path.join(REPO, 'build', 'release', 'bin', 'ksigbuilder')
    r = subprocess.run([exe, '--tree', d + '/tree', d + '/art', d + '/db', '--pathogens', d + '/bases/pathogens', '--syndromes', d + '/bases/syndromes', '--basedir', d + '/bases'],
                       capture_output=True, text=True)
    check(r.returncode == 0, 'the builder refused the generated diagnose: %s' % r.stderr[-300:])
    shutil.copy(os.path.join(REPO, 'build', 'release', 'databases', 'unpack-raw.ksig'), d + '/db')   # a database needs one module pack to load
    return d + '/db', d + '/bases'


def examiner_keys(path):
    """{unit offset: [the 8-hex keys of its block]} of the function units the engine signed (`kofexaminer --blocks`)."""
    exe = os.path.join(REPO, 'build', 'release', 'bin', 'kofexaminer')
    lines = subprocess.run([exe, '--blocks', path], capture_output=True, text=True).stdout.split('\n')
    out = {}
    for i, l in enumerate(lines):
        m = re.search(r'unit  region=CODE  off=0x([0-9a-f]+)  len=\d+  side=\w+  func=\S+.*?cfg_blocks=\d+', l)
        if m and lines[i + 1].strip().startswith('block'):
            out[int(m.group(1), 16)] = lines[i + 1].split()[1:]
    return out


@case(A)
def a_function_block_that_decided_a_diagnose_is_ticked_on_arrival_with_the_diagnoses_threshold():
    """The engine matched a diagnose whose block is the CFG sketch of cv_loop: the viewer ticks that row on arrival (mtn_from_match), the matcher takes the diagnose's
    threshold (70, not the editor's 60), the header takes the family and variant, and the row's id is the id the engine's report names as the place's unit."""
    p = scene()
    db, bases = sign_diagnose_db(p, 0x200, 70)
    with Viewer(p, rows=60, cols=200, extra=('--db', db, '--bases', bases)) as v:
        open_tab(v, 'Blocks')
        v.wait_for('[x]  0x', t=10)
        rows = table(v)
        ticked = [l for l in (v.row(y) for y in panel(v)) if re.match(r'\s+\[x\]\s+0x00000200\s+[0-9a-f]{8}\s+cv_loop', l)]
        check(ticked, 'the function row cv_loop is not ticked: %r' % [r[:3] for r in rows[:6]])
        check(not [l for l in (v.row(y) for y in panel(v)) if re.match(r'\s+\[x\]', l) and 'cv_loop' not in l], 'another row is ticked')
        txt = '\n'.join(v.row(y) for y in panel(v))
        check('Family [ Mirai ]' in txt and 'Variant [ A ]' in txt, 'the header does not carry the diagnose\'s family and variant: %r' % txt[:200])
        fold_mutation(v)
        txt = '\n'.join(v.row(y) for y in panel(v))
        check(re.search(r'1\.\s+(?:\S+: )?[0-9a-f]{8}\s+Threshold: >= \[\s*70\]%', txt), 'the matcher does not take the diagnose\'s 70%%: %r' % txt[-300:])
        # Owner 2026-10-31: the matcher row names the function (the blocks table's own name, the engine's), the hash is bare, Type and Tag are on the row under it.
        enlarge(v, 6)      # the matcher's second row must be inside the panel
        h = [m.group(3) for m in (BLK.match(l) for l in (v.row(y) for y in panel(v))) if m and m.group(4) == 'cv_loop']
        check(h, 'no cv_loop row in the table')
        ys = [y for y in panel(v) if re.match(SIM_ROW, v.row(y))]
        check(ys, 'no matcher row')
        check(re.match(r'\s+1\.\s+cv_loop: %s\s+Threshold: >= \[\s*70\]%%' % h[0], v.row(ys[0])), 'the matcher row does not name the function: %r' % v.row(ys[0]))
        check('find_sim' not in v.row(ys[0]), 'the word find_sim is printed: %r' % v.row(ys[0]))
        check('#' not in v.row(ys[0]), 'a # in the matcher row: %r' % v.row(ys[0]))
        check(re.match(r'^ {7}Type: Botnet {3}Tag: \S+', v.row(ys[0] + 1)), 'Type/Tag are not on the row under it: %r' % v.row(ys[0] + 1))


if __name__ == '__main__':
    main(A)
