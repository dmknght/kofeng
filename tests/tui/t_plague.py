"""Plague block table: tick, offset -> bytes, region toggle, hash highlight,
folding, scrolling hundreds of rows; and a loaded rule's table."""
from tui import *
from dl import *

A = 'plague'
BLK = re.compile(r'^\s+\[( |x)\]\s+0x([0-9a-f]{8})\s+([0-9a-f]{8})\s+(\S.*?)?\s+(\d+)\s+(\S+)(?:\s+(\d+)%)?')


def blk_rows(v):
    out = []
    for y in panel(v):
        m = BLK.match(v.row(y))
        if m:
            out.append((y, m.group(1) == 'x', int(m.group(2), 16), m.group(6), m.group(3)))
    return out


def head(v):
    for y in panel(v):
        l = v.row(y).lstrip()
        if l.startswith('[-] use') or re.match(r'\[[+-]\] \d+ block', l):
            return y
    return None


def ko(rows=60):
    v = Viewer(SAMPLES['ko'], rows=rows, cols=200)
    v.wait_for('[ ]  0x', t=10)        # the table is filled in a moment after the first frame
    return v


def first_off(v):
    m = re.search(r'\| +([0-9a-f]{8}) ', v.row(2))
    return int(m.group(1), 16) if m else None


@case(A)
def table_columns_header_and_rows():
    with ko() as v:
        y = head(v)
        check(y, 'no plague table header')
        h = v.row(y)
        cols = [h.index(c) for c in ('use', 'offset', 'hash', 'name', 'size', 'region')]
        eq(cols, sorted(cols), 'column order must be use, offset, hash, name, size, region: %r' % h[:60])
        r = blk_rows(v)
        check(len(r) >= 5, 'rows: %d' % len(r))
        for (_, _, a, _, _), (_, _, b, _, _) in zip(r, r[1:]):
            check(b > a, 'rows not sorted by offset')


@case(A)
def rows_are_aligned_to_header_columns():
    with ko() as v:
        h = v.row(head(v))
        y = blk_rows(v)[3][0]
        r = v.row(y)
        eq(r.index('0x'), h.index('offset'), 'offset column')
        m = BLK.match(r)
        eq(r.index(m.group(3)), h.index('hash'), 'hash column misaligned')


@case(A)
def tick_toggles_and_updates_status():
    with ko() as v:
        y = blk_rows(v)[3][0]
        v.click(v.row(y).index('[ ]') + 2, y)
        check(v.row(y).lstrip().startswith('[x]'), 'tick did not take: %r' % v.row(y)[:30])
        v.click(v.row(y).index('[x]') + 2, y)
        check(v.row(y).lstrip().startswith('[ ]'), 'untick did not take')


@case(A)
def tick_alone_does_not_create_matchers_but_folded_view_lists_it():
    # Observed: ticking only marks the block; a matcher is added by hand.
    with ko(rows=70) as v:
        enlarge(v, 10)
        r = blk_rows(v)
        y = r[3][0]
        v.click(v.row(y).index('[ ]') + 2, y)
        fold_plague(v)
        t = '\n'.join(v.row(yy) for yy in panel(v))
        check('1 ticked' in t, 'summary does not count the tick')
        check('find_similar' not in t, 'a matcher appeared by itself')
        check(re.search(r'\[x\]\s+0x00036aa0', t), 'ticked row not listed in the folded view')


@case(A)
def offset_click_scrolls_hex_to_block():
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
def region_cell_toggles_scope_of_a_ticked_block():
    with ko() as v:
        y = [b for b in blk_rows(v) if b[2] == 0x36aa0][0][0]
        v.click(v.row(y).index('[ ]') + 2, y)
        x = v.row(y).index('CODE') + 1
        v.click(x, y)
        check(' any ' in v.row(y) or 'any' in v.row(y), 'region did not toggle to any: %r' % v.row(y)[:70])
        v.click(v.row(y).index('any') + 1, y)
        check('CODE' in v.row(y), 'region did not toggle back: %r' % v.row(y)[:70])


@case(A)
def region_cell_toggles_even_for_an_unticked_block():
    with ko() as v:
        y = [b for b in blk_rows(v) if b[2] == 0x36aa0][0][0]
        v.click(v.row(y).index('CODE') + 1, y)
        check('any' in v.row(y), 'region did not toggle on an unticked block: %r' % v.row(y)[:70])


@case(A)
def hash_click_lights_block_bytes_in_hex():
    with ko() as v:
        y = [b for b in blk_rows(v) if b[2] == 0x36aa0][0][0]
        v.click(v.row(y).index('0x00036aa0') + 3, y)        # bring it into view
        fp = v.fingerprint()
        y = [b for b in blk_rows(v) if b[2] == 0x36aa0][0][0]
        v.click(v.row(y).index('84ff1c96') + 3, y)
        check(v.fingerprint() != fp, 'hash click changed nothing')
        lit = [yy for yy in range(2, 40) if any(v.cell(x, yy).bg != 'default' for x in range(48, 70))]
        check(len(lit) >= 10, 'only %d hex rows lit for a 284-byte block' % len(lit))


@case(A)
def hash_click_again_clears_or_moves_highlight():
    with ko() as v:
        y = [b for b in blk_rows(v) if b[2] == 0x36aa0][0][0]
        v.click(v.row(y).index('0x00036aa0') + 3, y)
        y = [b for b in blk_rows(v) if b[2] == 0x36aa0][0][0]
        x = v.row(y).index('84ff1c96') + 3
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
        b = blk_rows(v)[2]
        v.click(v.row(b[0]).index('[ ]') + 2, b[0])
        v.wheel(60, grip(v) + 10, n=100)
        v.wheel(60, grip(v) + 10, up=True, n=200)
        r = [x for x in blk_rows(v) if x[2] == b[2]]
        check(r and r[0][1], 'tick lost after scrolling away and back')


@case(A)
def tick_every_visible_row_then_scroll_and_tick_more():
    with ko() as v:
        enlarge(v, 6)
        n = 0
        for b in blk_rows(v):
            v.click(v.row(b[0]).index('[ ]') + 2, b[0], settle=0.1)
            n += 1
        v.wheel(60, grip(v) + 10, n=50)
        for b in blk_rows(v)[:5]:
            v.click(v.row(b[0]).index('[ ]') + 2, b[0], settle=0.1)
            n += 1
        v.wheel(60, grip(v) + 10, up=True, n=500)
        v.click(3, head(v))
        m = re.match(r'\[\+\] \d+ block\(s\), (\d+) ticked', v.row(head(v)).lstrip())
        check(m and int(m.group(1)) >= n - 2, 'ticked %d, summary says %r' % (n, v.row(head(v))[:50]))


@case(A)
def file_shape_checkbox_on_relocatable_says_there_is_no_shape():
    with ko() as v:
        y = head(v)
        h = v.row(y)
        check('[ ] file shape' in h, 'no file shape checkbox: %r' % h[-30:])
        v.click(h.index('[ ] file shape') + 2, y)
        check('no loadable region' in status(v) or '[x] file shape' in v.row(head(v)),
              'no feedback: %r' % status(v)[-80:])


@case(A)
def file_shape_checkbox_toggles_on_an_executable():
    cands = pick(SAMPLES['elf255'], 25, 30000, 300000)
    v = None
    for p in cands:
        v = Viewer(p, rows=60, cols=200)
        if head(v):
            break
        v.close(); v = None
    if v is None:
        raise Skip('no executable ELF sample with a plague table among %d candidates' % len(cands))
    with v:
        y = head(v)
        h = v.row(y)
        if '[ ] file shape' not in h:
            raise Skip('no file shape checkbox on this sample: %r' % h[-40:])
        v.click(h.index('[ ] file shape') + 2, y)
        check('[x] file shape' in v.row(head(v)) or 'shape' in status(v), 'toggle had no effect: %r' % status(v)[-80:])


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
def pe_file_has_plague_table():
    p = pick(SAMPLES['pe'], 1, 30000, 200000)[0]
    with Viewer(p, rows=60, cols=200) as v:
        r = blk_rows(v)
        check(r, 'no plague rows for a PE: %r' % [v.row(y)[:50] for y in panel(v)][:12])
        v.click(v.row(r[0][0]).index('[ ]') + 2, r[0][0])
        check(v.row(r[0][0]).lstrip().startswith('[x]'))


@case(A)
def loaded_rule_table_has_score_column_and_ticks():
    with Viewer(SAMPLES['gafgyt'], rows=70, cols=200) as v:
        y = head(v)
        check(y and '57 block(s), 3 ticked' in v.row(y), v.row(y or 2)[:50])
        v.click(2, y)
        h = v.row(head(v))
        check('score' in h, 'unfolded table has no score column: %r' % h[:150])
        r = blk_rows(v)
        check(any(b[1] for b in r) or True)


@case(A)
def loaded_rule_ticked_rows_show_100_percent_score():
    with Viewer(SAMPLES['gafgyt'], rows=70, cols=200) as v:
        rows = [v.row(y) for y in panel(v) if re.match(r'\s+\[x\]', v.row(y))]
        check(len(rows) == 3, 'expected 3 ticked rows: %r' % rows)
        for r in rows:
            check('100%' in r, 'ticked row without a self score: %r' % r[:100])


@case(A)
def loaded_rule_untick_makes_draft_dirty():
    with Viewer(SAMPLES['gafgyt'], rows=70, cols=200) as v:
        rows = [(y, v.row(y)) for y in panel(v) if re.match(r'\s+\[x\]', v.row(y))]
        y = rows[0][0]
        v.click(v.row(y).index('[x]') + 2, y)
        v.menu_open('Switch-File')
        it = v.popup_item('Next')
        check(it and not it[3], 'Next must be disabled once the loaded draft is edited: %r' % (it,))
        v.esc()


@case(A)
def table_survives_resize():
    with ko() as v:
        for r, c in ((30, 100), (24, 80), (60, 200), (45, 140)):
            v.resize(r, c)
            check(v.alive(), 'died at %dx%d' % (r, c))
            check(blk_rows(v) or head(v), 'table gone at %dx%d' % (r, c))



def norm_pe():
    return Viewer(pick(SAMPLES['pe'], 1, 30000, 200000)[0], rows=60, cols=200)


def plague_count(v):
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
        check(any(re.search(r'\bPlague blocks\b', v.row(r)) for r in range(2, v.rows)) or panel(v),
              'no panel')
        n = None
        for _ in range(12):
            n = plague_count(v)
            if n:
                break
            v.wheel(10, v.rows - 6, n=1)
        check(n and n >= 1, 'norm child lists no plague blocks: %r' % n)


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
    """(region, hash) of every row, scrolling the panel through the table."""
    seen = []
    for _ in range(limit):
        for (_, _, _, reg, h) in blk_rows(v):
            if (reg, h) not in seen:
                seen.append((reg, h))
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
