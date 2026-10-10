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


def click_in_panel(v, text, nth=0, dx=0):
    p = prow(v, text, nth)
    check(p, 'panel text %r not found; panel: %r' % (text, [v.row(y)[:70].rstrip() for y in range((grip(v) or 1) + 1, v.rows)][:14]))
    v.click(p[0] + dx, p[1])
    return p


def enlarge(v, to=8):
    g = grip(v)
    x = v.row(g).index('=======') + 3
    v.drag(x, g, x, to)


def fold_plague(v):
    """Collapse the plague block table (it is hundreds of rows on a .ko)."""
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
