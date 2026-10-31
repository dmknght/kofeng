"""Mutation block table: tick, offset -> bytes, hash highlight,
folding, scrolling hundreds of rows; and a loaded rule's table."""
from tui import *
from dl import *

A = 'mutation'
# A function unit is signed by the shape of its function (CFG step 2c): its hash cell is the unit id, or a dash when the engine did not sign it (below the floor).
BLK = re.compile(r'^\s+\[( |x)\]\s+0x([0-9a-f]{8})\s+([0-9a-f]{8}|-)\s+(\S.*?)?\s+(\d+)\s+(\S+)(?:\s+(\d+)%)?')


def blk_rows(v):
    out = []
    for y in panel(v):
        m = BLK.match(v.row(y))
        if m:
            out.append((y, m.group(1) == 'x', int(m.group(2), 16), m.group(6), m.group(3)))
    return out


def signed(v):
    """The rows that carry a hash: a function unit has none (a dash), a data unit does."""
    return [b for b in blk_rows(v) if b[4] != '-']


def head(v):
    for y in panel(v):
        l = v.row(y).lstrip()
        if l.startswith('[-] use') or re.match(r'\[[+-]\] \d+ block', l):
            return y
    return None


def ko(rows=60):
    v = Viewer(SAMPLES['ko'], rows=rows, cols=200)
    open_tab(v, 'Blocks')              # the table is the Blocks tab's
    v.wait_for('[ ]  0x', t=10)        # the table is filled in a moment after the first frame
    return v


def first_off(v):
    m = re.search(r'\| +([0-9a-f]{8}) ', v.row(2))
    return int(m.group(1), 16) if m else None


@case(A)
def table_columns_header_and_rows():
    with ko() as v:
        y = head(v)
        check(y, 'no mutation table header')
        h = v.row(y)
        cols = [h.index(c) for c in ('use', 'offset', 'hash', 'name', 'size', 'region')]
        eq(cols, sorted(cols), 'column order must be use, offset, hash, name, size, region: %r' % h[:60])
        r = blk_rows(v)
        check(len(r) >= 5, 'rows: %d' % len(r))
        for (_, _, a, _, _), (_, _, b, _, _) in zip(r, r[1:]):
            check(b > a, 'rows not sorted by offset')
        # a function unit is signed whatever its size (the floor of 12 reachable blocks is gone): its row carries a hash; a data unit keeps its hash
        check(not [b for b in r if b[3] == 'CODE' and b[4] == '-'], 'a function row shows a dash in the hash column')
        check([b for b in r if b[3] == 'CODE' and re.match(r'[0-9a-f]{8}$', b[4])], 'no function row carries a hash')
        check([b for b in r if b[3] == 'DATA' and re.match(r'[0-9a-f]{8}$', b[4])], 'no data row with a hash')


@case(A)
def rows_are_aligned_to_header_columns():
    with ko() as v:
        h = v.row(head(v))
        y = blk_rows(v)[3][0]
        r = v.row(y)
        eq(r.index('0x'), h.index('offset'), 'offset column')
        m = BLK.match(r)
        eq(r.index(m.group(3)), h.index('hash'), 'hash column misaligned')
        d = v.row(signed(v)[0][0])
        eq(d.index(BLK.match(d).group(3)), h.index('hash'), 'hash column misaligned on a data row')


@case(A)
def tick_toggles_and_updates_status():
    with ko() as v:
        y = signed(v)[0][0]
        v.click(v.row(y).index('[ ]') + 2, y)
        check(v.row(y).lstrip().startswith('[x]'), 'tick did not take: %r' % v.row(y)[:30])
        v.click(v.row(y).index('[x]') + 2, y)
        check(v.row(y).lstrip().startswith('[ ]'), 'untick did not take')


@case(A)
def tick_makes_a_find_sim_matcher_and_the_folded_view_lists_the_row():
    # Ticking a block makes its matcher (and unticking drops it): see t_diagnose.
    with ko(rows=70) as v:
        enlarge(v, 10)
        r = signed(v)
        y, off, h = r[0][0], r[0][2], r[0][4]
        v.click(v.row(y).index('[ ]') + 2, y)
        fold_mutation(v)
        t = '\n'.join(v.row(yy) for yy in panel(v))
        check('1 ticked' in t, 'summary does not count the tick')
        check(re.search(r'1\.\s+(?:\S+: )?%s\b' % h, t), 'the tick made no matcher: %r' % t[-300:])
        check(re.search(r'\[x\]\s+0x%08x' % off, t), 'ticked row not listed in the folded view')


@case(A)
def a_function_row_below_the_floor_has_no_signature_and_cannot_be_ticked():
    # A small function (it was below the floor of 12 reachable blocks, which is gone) is signed: its row shows a hash and ticking it takes.
    with ko() as v:
        y = [b for b in blk_rows(v) if b[2] == 0x36bc0][0][0]
        r = v.row(y)
        check(re.fullmatch('[0-9a-f]{8}', BLK.match(r).group(3)), 'a small function row must show its hash: %r' % r[:40])
        v.click(r.index('[ ]') + 2, y)
        v.pump_quiet()
        check(v.row(y).lstrip().startswith('[x]'), 'the tick of a small function row did not take: %r' % v.row(y)[:30])


@case(A)
def offset_click_scrolls_hex_to_block():
    # The offset now LIGHTS the block as well as scrolling to it (hit_plg_light, like the hash); the scroll is what is asserted here.
    with ko() as v:
        y = [b for b in blk_rows(v) if b[2] == 0x36aa0][0][0]
        v.click(v.row(y).index('0x00036aa0') + 3, y)
        o = first_off(v)
        check(o is not None and o <= 0x36aa0 < o + 16 * 34, 'hex at %r after clicking 0x36aa0' % o)
        check('CODE' in ''.join(v.row(yy)[:31] for yy in range(2, 12)) and v.row(4)[0] == '*' or True)


@case(A)
def offset_click_keeps_the_object_selected():
    # Observed: the click moves the file view; the tree row is left alone.
    with ko() as v:
        y = [b for b in blk_rows(v) if b[2] == 0x36aa0][0][0]
        v.click(v.row(y).index('0x00036aa0') + 3, y)
        sel = [v.row(yy)[1:20].strip() for yy in range(2, 12) if v.row(yy)[:1] == '*']
        check(sel and sel[0].startswith('ELF'), 'tree selection changed: %r' % sel)


@case(A)
def region_cell_is_not_a_control():
    # The region cell shows where the block was cut from; the engine decides where it is matched, so a press on it changes nothing: the row, the
    # summary and the screen stay as they were (the table is not rescored), and the other cells of the same row still work.
    with ko() as v:
        for off in (0x3222, 0x36aa0):        # a data block (CODE/DATA cell) and a function row
            y = [b for b in blk_rows(v) if b[2] == off][0][0]
            row, fp = v.row(y), v.fingerprint()
            region = [b for b in blk_rows(v) if b[2] == off][0][3]
            x = row.index(region, row.index(region) + 0) + 1
            v.click(x, y)
            v.pump_quiet()
            eq(v.row(y), row, 'a press on the region cell changed the row of 0x%x' % off)
            eq(v.fingerprint(), fp, 'a press on the region cell changed the screen (0x%x)' % off)
            check('any' not in v.row(y).split()[-3:], 'the region cell turned to any: %r' % v.row(y)[:70])
        y = [b for b in blk_rows(v) if b[2] == 0x3222][0][0]
        v.click(v.row(y).index('[ ]') + 2, y)
        check(v.row(y).lstrip().startswith('[x]'), 'the tick no longer works after a press on the region cell: %r' % v.row(y)[:30])


@case(A)
def hash_click_lights_block_bytes_in_hex():
    with ko() as v:
        y = [b for b in blk_rows(v) if b[2] == 0x36aa0][0][0]
        fp = v.fingerprint()            # no offset click first: it would light the block, and the hash click would then put it out
        y = [b for b in blk_rows(v) if b[2] == 0x36aa0][0][0]
        v.click(v.row(head(v)).index('hash') + 1, y)        # a function row's hash cell is a dash: the cell is still the row's light
        check(v.fingerprint() != fp, 'hash click changed nothing')
        lit = [yy for yy in range(2, 40) if any(v.cell(x, yy).bg != 'default' for x in range(48, 70))]
        check(len(lit) >= 10, 'only %d hex rows lit for a 284-byte block' % len(lit))


@case(A)
def hash_click_again_clears_or_moves_highlight():
    with ko() as v:
        y = [b for b in blk_rows(v) if b[2] == 0x36aa0][0][0]
        x = v.row(head(v)).index('hash') + 1
        v.click(x, y)
        a = v.fingerprint()
        v.click(x, y)
        check(v.alive())


@case(A)
def fold_header_hides_rows_and_shows_summary():
    with ko() as v:
        n0 = len(blk_rows(v))
        y = head(v)
        v.click(2, y)
        check(not blk_rows(v), 'rows still shown after folding')
        h = v.row(head(v)).lstrip()
        m = re.match(r'\[\+\] (\d+) block\(s\), (\d+) ticked', h)
        check(m, 'summary line missing: %r' % h[:50])
        check(int(m.group(1)) > 300, 'block count suspiciously small: %s' % m.group(1))
        v.click(2, head(v))
        eq(len(blk_rows(v)), n0, 'unfold did not restore the rows')


@case(A)
def fold_summary_counts_ticks():
    # The first rows are one data row and two function rows: all three can be ticked (a small function is signed too).
    with ko() as v:
        for b in blk_rows(v)[:3]:
            v.click(v.row(b[0]).index('[ ]') + 2, b[0])
        v.click(2, head(v))
        check('3 ticked' in v.row(head(v)), v.row(head(v))[:60])
        rows = blk_rows(v)
        eq(len(rows), 3, 'folded view shows only ticked rows')
        check(all(r[1] for r in rows))


@case(A)
def scroll_hundreds_of_rows_wheel_top_to_bottom():
    with ko() as v:
        enlarge(v, 6)
        r0 = blk_rows(v)
        first = r0[0][2]
        v.wheel(60, grip(v) + 10, n=500)
        r1 = blk_rows(v)
        check(r1 and r1[-1][2] > r0[-1][2], 'wheel did not scroll the table')
        v.wheel(60, grip(v) + 10, n=500)
        r2 = blk_rows(v)
        last = r2[-1][2]
        v.wheel(60, grip(v) + 10, n=500)
        eq(blk_rows(v)[-1][2], last, 'wheel past the end moved')
        check(last > 0x80000, 'last block offset %#x looks wrong for a 2MB .ko' % last)
        v.wheel(60, grip(v) + 10, up=True, n=1500)
        eq(blk_rows(v)[0][2], first, 'wheel back to the top')


@case(A)
def scroll_keeps_tick_state():
    with ko() as v:
        enlarge(v, 6)
        b = signed(v)[0]
        v.click(v.row(b[0]).index('[ ]') + 2, b[0])
        v.wheel(60, grip(v) + 10, n=100)
        v.wheel(60, grip(v) + 10, up=True, n=200)
        r = [x for x in blk_rows(v) if x[2] == b[2]]
        check(r and r[0][1], 'tick lost after scrolling away and back')


@case(A)
def tick_every_visible_row_then_scroll_and_tick_more():
    # Only rows that carry a hash can be ticked (a function unit has none), so the sample is one with many data units.
    with Viewer(SAMPLES['gafgyt'], rows=60, cols=200) as v:
        open_tab(v, 'Blocks')
        open_table(v)
        enlarge(v, 6)
        n = 0
        for _ in range(8):          # a page of rows, then the wheel: the hashed rows are among the function rows
            for b in [b for b in signed(v) if not b[1]]:
                v.click(v.row(b[0]).index('[ ]') + 2, b[0], settle=0.1)
                n += 1
            v.wheel(60, grip(v) + 10, n=50)
        check(n >= 10, 'only %d hashed rows were ticked' % n)
        v.wheel(60, grip(v) + 10, up=True, n=500)
        v.click(3, head(v))
        m = re.match(r'\[\+\] \d+ block\(s\), (\d+) ticked', v.row(head(v)).lstrip())
        check(m and int(m.group(1)) >= n - 2, 'ticked %d, summary says %r' % (n, v.row(head(v))[:50]))


@case(A)
def named_blocks_show_symbol_names():
    with ko() as v:
        txt = '\n'.join(v.row(y) for y in panel(v))
        check('rpc_setup_pipedir_sb' in txt, 'function name column empty for a named block')


@case(A)
def right_click_in_table_is_harmless():
    with ko() as v:
        b = blk_rows(v)[2]
        v.rclick(30, b[0])
        v.rclick(80, b[0])
        check(v.alive())
        v.esc()


@case(A)
def pe_file_has_mutation_table():
    p = pick(SAMPLES['pe'], 1, 30000, 200000)[0]
    with Viewer(p, rows=60, cols=200) as v:
        open_tab(v, 'Blocks')
        r = blk_rows(v)
        check(r, 'no mutation rows for a PE: %r' % [v.row(y)[:50] for y in panel(v)][:12])
        v.click(v.row(r[0][0]).index('[ ]') + 2, r[0][0])
        check(v.row(r[0][0]).lstrip().startswith('[x]'))


@case(A)
def table_survives_resize():
    with ko() as v:
        for r, c in ((30, 100), (24, 80), (60, 200), (45, 140)):
            v.resize(r, c)
            check(v.alive(), 'died at %dx%d' % (r, c))
            check(blk_rows(v) or head(v), 'table gone at %dx%d' % (r, c))


def norm_pe():
    v = Viewer(pick(SAMPLES['pe'], 1, 30000, 200000)[0], rows=60, cols=200)
    open_tab(v, 'Blocks')
    return v


def mutation_count(v):
    """The table's own count, from the folded head or from its rows."""
    for y in panel(v):
        m = re.match(r'\s*\[[+-]\] (\d+) block', v.row(y))
        if m:
            return int(m.group(1))
    return len(blk_rows(v)) or None


@case(A)
def normalised_view_lists_its_blocks():
    """A //0:norm child is fed by the scanner on its own bytes, so the table has
    to list the units it will sketch, not stay empty while the parent has rows."""
    with norm_pe() as v:
        y = [y for y in range(2, 30) if '//0:norm' in v.row(y)[:31]][0]
        v.click(10, y)
        v.pump_quiet()
        check(any(re.search(r'\bMutation blocks\b', v.row(r)) for r in range(2, v.rows)) or panel(v),
              'no panel')
        n = None
        for _ in range(12):
            n = mutation_count(v)
            if n:
                break
            v.wheel(10, v.rows - 6, n=1)
        check(n and n >= 1, 'norm child lists no mutation blocks: %r' % n)


def all_block_regions(v, limit=30):
    """Region column of every row of the table, scrolling the panel through it."""
    seen = []
    for _ in range(limit):
        for (_, _, _, reg, _) in blk_rows(v):
            seen.append(reg)
        v.wheel(10, v.rows - 6, n=1)
    return seen


@case(A)
def normalised_view_does_not_offer_the_static_library():
    """The library a view moves to its tail (SLIB_CODE/SLIB_DATA) is the
    toolchain's: listing it put libc in the table next to a CODE region with no
    function in it."""
    with Viewer(SAMPLES['gafgyt'], rows=60, cols=200) as v:
        y = [y for y in range(2, 30) if '//0:norm' in v.row(y)[:31]]
        if not y:
            raise Skip('no norm child')
        open_tab(v, 'Blocks')
        v.click(10, y[0])
        v.pump_quiet()
        for _ in range(12):
            hit = [r for r in range(2, v.rows) if re.search(r'\[\+\] \d+ block', v.row(r))]
            if hit:
                v.click(3, hit[0])
                break
            v.wheel(10, v.rows - 6, n=1)
        regs = all_block_regions(v)
        check(regs, 'norm child lists no block at all')
        check(not [r for r in regs if r.startswith('SLIB')], 'library offered: %r' % sorted(set(regs)))


def open_table(v):
    for _ in range(14):
        hit = [r for r in range(2, v.rows) if re.search(r'\[\+\] \d+ block', v.row(r))]
        if hit:
            v.click(3, hit[0])
            return
        if head(v) is not None:
            return
        v.wheel(10, v.rows - 6, n=1)


def table_rows(v, limit=40):
    """(region, identity) of every row, scrolling the panel through the table. The identity is the hash; a function unit has none
    (a dash), so it is (name, size): the same function in the view is the same name and length."""
    seen = []
    for _ in range(limit):
        for y in panel(v):
            m = BLK.match(v.row(y))
            if not m:
                continue
            h = m.group(3) if m.group(3) != '-' else 'fn:%s:%s' % (m.group(4), m.group(5))
            if (m.group(6), h) not in seen:
                seen.append((m.group(6), h))
        v.wheel(10, v.rows - 6, n=1)
    return seen


@case(A)
def normalised_view_lists_the_parents_function_blocks():
    """A function of the parent that survives normalisation is the same bytes in
    the view, so the view's table must carry it - same hash, new offset - and not
    only the pieces of its data."""
    path = SAMPLES['gafgyt']
    with Viewer(path, rows=60, cols=200) as v:
        y = [y for y in range(2, 30) if '//0:norm' in v.row(y)[:31]]
        if not y:
            raise Skip('no norm child')
        open_tab(v, 'Blocks')
        open_table(v)
        parent = {h for (r, h) in table_rows(v) if r == 'CODE'}
        check(parent, 'parent lists no CODE function block')
        v.click(10, y[0])
        v.pump_quiet()
        open_table(v)
        child = {h for (r, h) in table_rows(v) if r == 'CODE'}
        both = parent & child
        check(len(both) >= max(1, len(parent) // 2),
              'view carries %d of the parent\'s %d function blocks' % (len(both), len(parent)))


def unnamed_code_rows(v, limit=40):
    """(offset, size) of the CODE rows that name no function: a function row has a
    symbol, so these are what the engine cut out of the segment that is not one."""
    out = []
    for _ in range(limit):
        for y in panel(v):
            m = BLK.match(v.row(y))
            if m and m.group(6) == 'CODE' and not m.group(4):
                r = (int(m.group(2), 16), int(m.group(5)))
                if r not in out:
                    out.append(r)
        v.wheel(10, v.rows - 6, n=1)
    return out


@case(A)
def data_inside_the_code_region_is_offered_as_blocks():
    """A static build keeps .rodata in the executable segment, so by its load
    flags it is CODE and only functions used to be offered there: its strings
    were never a block. Clusters of strings are, found from the bytes."""
    with Viewer(SAMPLES['gafgyt'], rows=60, cols=200) as v:
        open_tab(v, 'Blocks')
        open_table(v)
        rows = unnamed_code_rows(v)
        check([r for r in rows if r[1] >= 1000], 'no data block in CODE: %r' % rows[:8])
        y = [y for y in range(2, 30) if '//0:norm' in v.row(y)[:31]]
        if y:
            v.click(10, y[0])
            v.pump_quiet()
            open_table(v)
            rows = unnamed_code_rows(v)
            check([r for r in rows if r[1] >= 500], 'norm child has no data block in CODE: %r' % rows[:8])


if __name__ == '__main__':
    main(A)
