"""dl.py - helpers for driving the draft panel (shared by the draft tests)."""
from tui import *


def grip(v):
    """Row of the draft panel's top rule ('=======' resize grip)."""
    for y in range(2, v.rows):
        if '=======' in v.row(y):
            return y
    return None


def panel(v):
    g = grip(v)
    return range(g + 1, v.rows)


def prow(v, text, nth=0):
    """(x, y) of text inside the panel, or None."""
    g = grip(v)
    return v.find(text, rows=(g + 1, v.rows - 1), nth=nth) if g else None


def prow_scroll(v, text, nth=0):
    """prow, scrolling the panel down until the text is in view."""
    g = grip(v)
    p = prow(v, text, nth)
    for _ in range(12):
        if p:
            break
        v.wheel(60, g + 4, n=2)
        p = prow(v, text, nth)
    check(p, 'panel text %r not found after scrolling' % text)
    return p


def click_in_panel(v, text, nth=0, dx=0):
    """Click panel text, scrolling the panel down to it when it is below the window."""
    p = prow_scroll(v, text, nth)
    v.click(p[0] + dx, p[1])
    return p


def enlarge(v, to=8):
    g = grip(v)
    x = v.row(g).index('=======') + 3
    v.drag(x, g, x, to)


def fold_mutation(v):
    """Collapse the mutation block table (it is hundreds of rows on a .ko)."""
    g = grip(v)
    for y in range(g + 1, v.rows):
        if v.row(y).lstrip().startswith('[-] use'):
            v.click(3, y)
            return True
    return False


def pick_menu_item(v, label, rows=None):
    """Click a drop-down item drawn on screen (panel pop-ups have no frame)."""
    p = v.find(label, rows=rows)
    check(p, 'menu item %r not on screen' % label)
    v.click(*p)


def add_string(v, text, kind='String'):
    """[+ String] -> kind -> type text -> Enter.  The menu opens downward, or
    upward when the button is near the bottom of the screen; 'Hex' is its middle
    entry, so the other two are found relative to it."""
    g = grip(v)
    p = v.find('[+ String]', rows=(g + 1, v.rows - 1))
    for _ in range(12):
        if p:
            break
        v.wheel(60, g + 4, n=2)             # the panel scrolls; bring the button into view
        p = v.find('[+ String]', rows=(g + 1, v.rows - 1))
    check(p, '[+ String] not found')
    v.click(*p)
    h = v.find('Hex', rows=(max(g + 1, p[1] - 5), min(v.rows - 1, p[1] + 5)))
    check(h, 'add-string menu not shown')
    dy = {'String': -1, 'Hex': 0, 'Regex': 1}[kind]
    v.click(h[0], h[1] + dy)
    v.type(text)
    v.key('enter')


def str_rows(v):
    return [y for y in panel(v) if re.match(r'\s+\d+\. (str|hex|rx)\b', v.row(y))]


def add_matcher(v, kind='find_str'):
    p = prow(v, '[+ Matcher]')
    check(p, '[+ Matcher] not found')
    v.click(p[0], p[1])
    q = v.find(kind, rows=(p[1] + 1, v.rows - 1))
    check(q, 'matcher kind %r not offered' % kind)
    v.click(*q)


def tall(path, rows=70, cols=200, **kw):
    return Viewer(path, rows=rows, cols=cols, **kw)


def status(v):
    return v.row(v.rows).rstrip()


def head_row(v):
    g = grip(v)
    return g + 1 if g else None


TABS = ('Patterns', 'Blocks', 'Graphs')


def tab_row(v):
    """Screen row of the diagnose panel's title bar, or None."""
    p = prow(v, ' Patterns ')
    return p[1] if p else None


def tab_cols(v, name):
    """(x0, x1) of one cell of the title bar, spaces included."""
    y = tab_row(v)
    check(y, 'title bar not visible: %r' % [v.row(yy)[:60] for yy in panel(v)][:8])
    i = v.row(y).index(' %s ' % name)
    return (i + 1, i + len(name) + 2)


def open_tab(v, name):
    """Click a cell of the title bar."""
    x0, x1 = tab_cols(v, name)
    v.click(x0 + 1, tab_row(v))


def active_tab(v):
    """The one cell of the title bar that is drawn reversed, or None."""
    y = tab_row(v)
    if not y:
        return None
    rev = set(v.reverse_cols(y))
    on = [n for n in TABS if rev & set(range(tab_cols(v, n)[0] + 1, tab_cols(v, n)[1]))]
    return on[0] if len(on) == 1 else None


def tick_blocks(v, n=1):
    """Tick the first n unticked rows of the block table; returns their hashes."""
    got = []
    for y in panel(v):
        m = re.match(r'\s+\[ \]\s+0x[0-9a-f]{8}\s+([0-9a-f]{8})', v.row(y))
        if m and len(got) < n:
            v.click(v.row(y).index('[ ]') + 2, y)
            got.append(m.group(1))
    return got


def sim_rows(v):
    """The block matchers listed on the panel: [(number, hash, threshold)]."""
    out = []
    for y in panel(v):
        m = re.match(r'\s+(\d+)\.\s+find_sim\s+# hash ([0-9a-f]{8}).*Threshold: >= \[\s*(\d+)\]%', v.row(y))
        if m:
            out.append((int(m.group(1)), m.group(2), int(m.group(3))))
    return out


def tag_box_top(v):
    """Screen row of the top rule of the Tag chooser's box, or None."""
    for y in range(2, v.rows):
        if '\u2500 Tag \u2500' in v.row(y):
            return y
    return None


def open_tag_chooser(v, nth=0):
    """Click the nth Tag cell of the draft panel; returns the box's top row."""
    p = prow_scroll(v, 'Tag:', nth)
    v.click(p[0] + 5, p[1])
    y = tag_box_top(v)
    check(y, 'the Tag chooser did not open: %r' % [v.row(yy)[:60] for yy in range(p[1], p[1] + 6)])
    return y


def pick_tag(v, label, nth=0):
    """Open the nth Tag cell's chooser, clear the search it starts from (the
    draft's shared Type and Family) and take the row named `label`."""
    y = open_tag_chooser(v, nth)
    v.key('ctrl+a')
    v.key('bs')
    p = v.find(label, rows=(y + 3, v.rows - 1))
    check(p, 'tag %r not in the chooser: %r' % (label, [v.row(yy)[:90] for yy in range(y, y + 9)]))
    v.click(*p)


def str_condition(v):
    """One string, one find_str over it, one condition naming it."""
    add_string(v, 'GCC: (Debian')
    add_matcher(v, 'find_str')
    y = [y for y in panel(v) if 'Markers: none yet' in v.row(y)][0]
    v.click(v.row(y).index('[+ String]') + 3, y)
    x, yy = v.find('  1  str')
    v.click(x + 4, yy)
    click_in_panel(v, '[+ Condition]')
    y = [y for y in panel(v) if 'Matchers: None' in v.row(y)][0]
    v.click(v.row(y).index('[+ Matcher]') + 3, y)
    p = v.find('find_str', rows=(y, y + 5))
    check(p, 'matcher not offered in the condition')
    v.click(*p)
