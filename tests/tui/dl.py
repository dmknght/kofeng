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
    """Tick the first n unticked rows of the block table that carry a hash (a function unit has none: prototype 2026-10-30, it cannot be
    ticked), scrolling the table when the page holds fewer; returns their hashes."""
    got = []
    scrolled = 0
    top = max(i for i, l in enumerate(v.lines) if l.startswith('-') and '=' in l)
    for _ in range(60):
        for y in panel(v):
            m = re.match(r'\s+\[ \]\s+0x[0-9a-f]{8}\s+([0-9a-f]{8})', v.row(y))
            if m and len(got) < n:
                v.click(v.row(y).index('[ ]') + 2, y)
                got.append(m.group(1))
        if len(got) >= n:
            break
        v.wheel(60, top + 4, n=1)
        v.pump(0.1)
        scrolled += 1
    if scrolled:                   # back to the top: the callers read the matchers, which are listed above the table
        v.wheel(60, top + 4, up=True, n=scrolled + 5)
        v.pump(0.1)
    return got


# The first row of a Blocks-tab matcher: `  1.  cv_loop: a8beb9fc  Threshold: ...`; a data block has no name and no `: `.
SIM_ROW = r'\s+\d+\.\s+(?:\S+: )?[0-9a-f]{8}\s+(?:\+\d+\s+)?Threshold'


def sim_rows(v):
    """The block matchers listed on the panel: [(number, hash, threshold)]."""
    out = []
    for y in panel(v):
        m = re.match(r'\s+(\d+)\.\s+(?:\S+: )?([0-9a-f]{8})\b.*Threshold: >= \[\s*(\d+)\]%', v.row(y))
        if m:
            out.append((int(m.group(1)), m.group(2), int(m.group(3))))
    return out


def open_tag_chooser(v, nth=0):
    """Click the nth Tag cell of the draft panel; returns the screen row of the cell (the list opens under it)."""
    return open_unit_cell(v, 'Tag:', nth)


def pick_tag(v, label, nth=0):
    """Open the nth Tag cell's list (the Syndromes catalog's tags) and take the row named `label`."""
    pick_unit_cell(v, 'Tag:', label, nth)


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


# ------------------------------------------------------- header: the Pathogens catalog, units: the tag catalog
_PD = [None]

CATALOG = {
    'mirai.c': 'KOF_MALWARE_FAMILY_NAME("Mirai");\nKOF_MALWARE_NEXT_VARIANT("C");\n'
               'KOF_MALWARE_VARIANT("A", KOF_MALTYPE_BOTNET);\n'
               'KOF_MALWARE_VARIANT("B", KOF_MALTYPE_BOTNET, KOF_MALTYPE_ROOTKIT);\n',
    'gafgyt.c': 'KOF_MALWARE_FAMILY_NAME("Gafgyt");\nKOF_MALWARE_NEXT_VARIANT("B");\n'
                'KOF_MALWARE_VARIANT("A", KOF_MALTYPE_BOTNET, KOF_MALTYPE_EXPLOIT);\n',
    'zeus.c': 'KOF_MALWARE_FAMILY_NAME("Zeus");\nKOF_MALWARE_NEXT_VARIANT("B");\n'
              'KOF_MALWARE_VARIANT("A", KOF_MALTYPE_TROJAN);\n',
}


def pathogens_dir():
    """A pathogens directory of this process's own: Mirai (A Botnet, B Botnet+Rootkit), Gafgyt (A Botnet+Exploit), Zeus (A Trojan)."""
    if _PD[0] is None:
        d = os.path.join(VT, 'work', 'p%d' % os.getpid(), 'pathogens_draft')
        os.makedirs(d, exist_ok=True)
        for name, text in CATALOG.items():
            with open(os.path.join(d, name), 'w') as f:
                f.write(text)
        _PD[0] = d
    return _PD[0]


_SD = [0]


def syndromes_dir_empty():
    """An EMPTY syndromes directory of this process's own. Without --syndromes the viewer reads <bases>/syndromes, and the copy of bases/
    holds the owner's own saved tags (Mirai-flood): the catalog was then not empty, the 'no syndromes' note never came and the Tag list
    offered a name no case put there."""
    _SD[0] += 1
    d = os.path.join(VT, 'work', 'p%d' % os.getpid(), 'syndromes_draft_%d' % _SD[0])
    os.makedirs(d, exist_ok=True)
    return d


def ko_cat(rows=60, cols=130, grow=None, **kw):
    """The kernel-module sample with the Pathogens catalog above (--pathogens) and an empty Syndromes catalog (--syndromes)."""
    v = Viewer(SAMPLES['ko'], rows=rows, cols=cols, extra=('--pathogens', pathogens_dir(), '--syndromes', syndromes_dir_empty()), **kw)
    if grow:
        enlarge(v, grow)
    return v


def data_cat(rows=60, cols=130, grow=None, **kw):
    """ko_cat on a sample with several data units. The kernel module has ONE unit that carries a hash; the rest are function units, which have
    no similarity signature (prototype 2026-10-30) and cannot be ticked, so a case that ticks two blocks needs this one."""
    v = Viewer(SAMPLES['gafgyt'], rows=rows, cols=cols, extra=('--pathogens', pathogens_dir(), '--syndromes', syndromes_dir_empty()), **kw)
    if grow:
        enlarge(v, grow)
    return v


def head(v):
    return v.row(head_row(v))


def pick_head(v, cell, item):
    """Click a header cell (`Family [`... text) and take `item` of the list that opens under it."""
    click_in_panel(v, cell)
    pick_menu_item(v, item, rows=(grip(v) + 2, v.rows))


def set_family(v, name):
    click_in_panel(v, '[ ? ]' if 'Family [ ? ]' in head(v) else '[ %s ]' % re.search(r'Family \[ (\S+) \]', head(v)).group(1))
    pick_menu_item(v, name, rows=(grip(v) + 2, v.rows))


def set_variant(v, name_in_list):
    m = re.search(r'Variant \[ (\S+) \]', head(v))
    click_in_panel(v, 'Variant [ %s ]' % m.group(1))
    pick_menu_item(v, name_in_list, rows=(grip(v) + 2, v.rows))


def add_syndromes(v, *names):
    """Add tags to the session's Syndromes catalog through its dialog (no storage: it lives in the viewer), then close it."""
    from t_families import press, tick
    for name in names:
        check(v.menu_item('Manage', 'Syndromes'), 'no Syndromes item')
        v.pump_quiet()
        press(v, '[ Add Syndrome ]', dx=2)
        v.type(name)
        tick(v, 'Scan')
        press(v, '[ OK ]')
        v.esc()
        v.pump_quiet()


def open_unit_cell(v, label, nth=0):
    """Click the VALUE of the nth `Type:` / `Tag:` cell of the panel (v.find answers the centre of the label) and return the screen row."""
    p = prow_scroll(v, label, nth)
    v.click(p[0] + len(label) // 2 + 2, p[1])
    return p[1]


def find_near(v, y, item, span=12):
    """(x, y) of `item` in the list that opened from screen row y: a list opens under its cell, or above it when the
    screen has no room below, so the rows on both sides are searched (the cell's own row is not)."""
    for rows in ((y + 1, min(y + span, v.rows - 1)), (max(y - span, 2), y - 1)):
        p = v.find(item, rows=rows)
        if p:
            return p
    return None


def pick_near(v, y, item):
    p = find_near(v, y, item)
    check(p, '%r not in the list near row %d: %r' % (item, y, [v.row(yy)[:60] for yy in range(max(y - 6, 2), y + 6)]))
    v.click(*p)


def pick_unit_cell(v, label, item, nth=0):
    pick_near(v, open_unit_cell(v, label, nth), item)


def unit_list(v, y):
    """The text rows of the list that opened from screen row y, both sides of the cell."""
    return [v.row(yy).strip() for yy in list(range(max(y - 8, 2), y)) + list(range(y + 1, min(y + 8, v.rows)))]
