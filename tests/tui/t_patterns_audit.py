"""The Patterns tab attacked from the screen: the cap of the matcher table, row counts after removals, a marker removed
while matchers and conditions name it, and what a row says against what Generate writes.

Each case that carries known_bug= is RED on this tree: it names the defect (the sink holds the KNOWN DEFECT comment;
tools/known_defects.py lists it) and turns into FIXED? when the sink is fixed - delete the marker then.
Run: KOFVIEWER=<tree>/build/release/bin/kofviewer KOF_REPO=<tree> python3 t_patterns_audit.py"""
from tui import *
from dl import *

A = 'patterns_audit'


def ko(rows=130, cols=200):
    fresh_bases()
    v = ko_cat(rows=rows, cols=cols, grow=6)
    fold_mutation(v)
    return v


def txt(v):
    return '\n'.join(v.row(y) for y in panel(v))


def matchers(v):
    """[(number, kind)] of the matcher rows drawn."""
    out = []
    for y in panel(v):
        m = re.match(r'\s+(\d+)\.\s+(find_\w+)', v.row(y))
        if m:
            out.append((int(m.group(1)), m.group(2)))
    return out


def add_matcher_scrolled(v, kind):
    """[+ Matcher], scrolled into view, then the kind (the list opens beside the button)."""
    p = click_in_panel(v, '[+ Matcher]')
    q = None
    for nth in range(12):
        c = v.find(kind, rows=(max(1, p[1] - 8), min(v.rows - 1, p[1] + 8)), nth=nth)
        if not c:
            break
        if not re.match(r'\s+\d+\.\s+find_', v.row(c[1])):     # a matcher row of the table is not a menu entry
            q = c
            break
    check(q, 'matcher kind %r not offered' % kind)
    v.click(*q)


def no_miscount(v):
    t = txt(v) + status(v)
    check('miscounted' not in t, 'the row model and the drawing disagree: %r' % t[-200:])


@case(A)
def eight_matchers_fit_and_no_row_is_miscounted():
    with ko() as v:
        add_string(v, 'GCC: (Debian')
        for k in range(8):
            add_matcher_scrolled(v, 'find_str')
            no_miscount(v)
        eq([k for _, k in matchers(v)], ['find_str'] * 8, 'matchers drawn')


@case(A)
def a_ninth_matcher_leaves_the_eighth_alone():
    with ko() as v:
        add_string(v, 'GCC: (Debian')
        for k in range(8):
            add_matcher_scrolled(v, 'find_str')
        add_matcher_scrolled(v, 'find_at (offset)')
        got = [k for _, k in matchers(v)]
        eq(got, ['find_str'] * 8, 'a refused ninth matcher changed another one')
        no_miscount(v)


@case(A)
def removing_the_first_matcher_renumbers_the_rest_and_keeps_every_row_counted():
    with ko() as v:
        add_string(v, 'GCC: (Debian')
        for k in range(3):
            add_matcher_scrolled(v, 'find_str')
        add_matcher_scrolled(v, 'find_at (offset)')
        eq([n for n, _ in matchers(v)], [1, 2, 3, 4])
        y = [y for y in panel(v) if re.match(r'\s+1\.\s+find_str', v.row(y))][0]
        v.click(v.row(y).rindex('[x]') + 1, y)
        eq(matchers(v), [(1, 'find_str'), (2, 'find_str'), (3, 'find_at')], 'after removing matcher 1')
        no_miscount(v)


@case(A)
def removing_a_string_used_by_a_matcher_leaves_the_matcher_empty_and_says_so():
    with ko() as v:
        add_string(v, 'GCC: (Debian')
        add_matcher_scrolled(v, 'find_str')
        y = [y for y in panel(v) if 'Markers: none yet' in v.row(y)][0]
        v.click(v.row(y).index('[+ String]') + 3, y)
        x, yy = v.find('  1  str')
        v.click(x + 4, yy)
        check('Markers: 1' in txt(v), txt(v)[-300:])
        rows = str_rows(v)
        check(rows, 'no string row')
        y = rows[0]
        v.click(v.row(y).rindex('[x]') + 1, y)
        check('Markers: none yet' in txt(v), 'the matcher still names a marker that is gone: %r' % txt(v)[-300:])
        no_miscount(v)
        check(v.alive())


@case(A)
def an_empty_condition_is_listed_and_generate_refuses_it_with_a_reason():
    with ko() as v:
        add_string(v, 'GCC: (Debian')
        add_matcher_scrolled(v, 'find_str')
        click_in_panel(v, '[+ Condition]')
        click_in_panel(v, '[ Save ]')
        s = status(v)
        check('Not written' in s or 'Nothing' in s or 'no ' in s, 'Generate on an unfinished draft said nothing useful: %r' % s)
        eq(os.listdir(os.path.join(BASES_COPY, 'diagnoses')), [], 'a refused draft wrote a file')


@case(A)
def clearing_the_box_and_pressing_enter_keeps_the_marker():
    with ko() as v:
        add_string(v, 'GCC')
        y = str_rows(v)[0]
        check('474343' in v.row(y), 'the marker row does not show its bytes: %r' % v.row(y)[:60])
        v.click(v.row(y).index('[e]') + 2, y)
        v.key('bs', 3)
        v.key('enter')
        check('474343' in v.row(str_rows(v)[0]), 'the status says unchanged (%r) and the marker is gone: %r' % (status(v)[-50:], v.row(str_rows(v)[0])[:70]))


@case(A)
def a_new_string_left_empty_is_not_kept_as_a_marker():
    with ko() as v:
        p = click_in_panel(v, '[+ String]')
        h = v.find('Hex', rows=(max(1, p[1] - 5), min(v.rows - 1, p[1] + 5)))
        check(h, 'add-string menu not shown')
        v.click(h[0], h[1] - 1)
        v.key('enter')
        check(v.alive())
        eq(len(str_rows(v)), 0, 'an empty marker is listed: %r' % [v.row(y)[:50] for y in str_rows(v)])


@case(A)
def the_region_row_belongs_to_the_patterns_tab_only():
    with ko(rows=70) as v:
        check(prow(v, '[+ Scan region]'), 'no Region row on the Patterns tab')
        for name in ('Blocks', 'Graphs'):
            open_tab(v, name)
            check(not prow(v, '[+ Scan region]'), 'the Region row is drawn on the %s tab' % name)
            check('Region ' not in '\n'.join(v.row(y)[:12] for y in panel(v)), 'a Region heading on %s' % name)
        open_tab(v, 'Patterns')
        check(prow(v, '[+ Scan region]'), 'the Region row did not come back')
        add_string(v, 'GCC: (Debian')
        add_matcher_scrolled(v, 'find_str')
        y = [y for y in panel(v) if 'Markers: none yet' in v.row(y)][0]
        v.click(v.row(y).index('[+ String]') + 3, y)
        x, yy = v.find('  1  str')
        v.click(x + 4, yy)
        check('WHOLE-FILE' in '\n'.join(v.row(y) for y in panel(v)) or 'CODE' in '\n'.join(v.row(y) for y in panel(v)), 'the matcher has no region')


if __name__ == "__main__":
    main(A)
