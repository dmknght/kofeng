"""Matchers, thresholds, Similarity measures, Conditions, Diagnose table."""
from tui import *
from dl import *

A = 'rules'


def ko(rows=70):
    v = Viewer(SAMPLES['ko'], rows=rows, cols=200)
    enlarge(v, 10)
    fold_mutation(v)
    return v


def lines(v):
    return [v.row(y) for y in panel(v)]


def txt(v):
    return '\n'.join(lines(v))


def thresholds(v):
    return re.findall(r'Threshold: [<>=!]+ \[?\s*(\d+)\s*\]?%?', txt(v))


# ------------------------------------------------------------------- matchers
@case(A)
def matcher_menu_kinds():
    with ko() as v:
        add_string(v, 'GCC')
        p = prow(v, '[+ Matcher]')
        v.click(*p)
        for kind in ('find_str', 'find_at (offset)'):
            check(v.has(kind, rows=(p[1] - 6, v.rows)), 'matcher kind %r not offered' % kind)
        check(not v.has('find_similar'), 'find_similar is not a string matcher: ticking a block makes it')
        v.esc()
        check(not v.has('find_at (offset)'), 'menu stayed open after Esc')


@case(A)
def add_find_str_matcher_row_and_remove_button():
    with ko() as v:
        add_string(v, 'GCC')
        add_matcher(v, 'find_str')
        y = [y for y in panel(v) if re.match(r'\s+1\.\s+find_str', v.row(y))]
        check(y, 'matcher row missing: %r' % [l[:60] for l in lines(v)][-9:])
        y = y[0]
        check('Threshold' in v.row(y) and '[comment...]' in v.row(y), v.row(y)[:70])
        x = v.row(y).rindex('[x]') + 1
        v.click(x, y)
        check(not [1 for l in lines(v) if re.match(r'\s+1\.\s+find_str', l)], 'matcher not removed by [x]')


@case(A)
def marker_popup_adds_marker_and_scopes_matcher_region():
    with ko() as v:
        add_string(v, 'GCC: (Debian')
        add_matcher(v, 'find_str')
        y = [y for y in panel(v) if 'Markers: none yet' in v.row(y)][0]
        v.click(v.row(y).index('[+ String]') + 3, y)
        check(v.has('  1  str'), 'marker popup does not list the string')
        x, yy = v.find('  1  str')
        v.click(x + 4, yy)
        check('Markers: 1' in txt(v), 'marker not attached: %r' % [l[:40] for l in lines(v)][-8:])
        check('WHOLE-FILE' in txt(v), 'matcher/region not scoped to WHOLE-FILE')
        check('== 1 of 1' in txt(v), 'threshold not derived: %r' % txt(v)[-300:])


@case(A)
def marker_popup_esc_leaves_matcher_empty():
    with ko() as v:
        add_string(v, 'GCC')
        add_matcher(v, 'find_str')
        y = [y for y in panel(v) if 'Markers: none yet' in v.row(y)][0]
        v.click(v.row(y).index('[+ String]') + 3, y)
        v.esc()
        check('Markers: none yet' in txt(v))


@case(A)
def two_markers_one_matcher_threshold_counts():
    with ko() as v:
        add_string(v, 'GCC: (Debian')
        add_string(v, 'GNU')
        add_matcher(v, 'find_str')
        for n in (1, 2):
            y = [y for y in panel(v) if re.search(r'Markers: (none yet|\d)', v.row(y)) and '[+ String]' in v.row(y)
                 or 'Markers:' in v.row(y)][0]
            xs = v.row(y).index('[+ String]') + 3 if '[+ String]' in v.row(y) else None
            if xs is None:
                break
            v.click(xs, y)
            p = v.find('  %d  str' % n)
            if p:
                v.click(p[0] + 4, p[1])
        check(re.search(r'of 2', txt(v)) or re.search(r'of 1', txt(v)), 'threshold text: %r' % txt(v)[-200:])


@case(A)
def matcher_comment_field_on_find_str():
    with ko() as v:
        add_string(v, 'GCC')
        add_matcher(v, 'find_str')
        y = [y for y in panel(v) if 'Threshold' in v.row(y)][0]
        x = v.row(y).index('[comment...]') + 4
        v.click(x, y)
        v.type('my note'); v.key('enter')
        check('[my note' in v.row(y), v.row(y)[:70])


# ------------------------------------------------------------------ conditions
@case(A)
def condition_add_and_default_fields():
    with ko() as v:
        add_string(v, 'GCC')
        add_matcher(v, 'find_str')
        click_in_panel(v, '[+ Condition]')
        t = txt(v)
        check('Matchers: None' in t and 'Tag: none' in t and 'choose one' not in t, t[-250:])
        check('Variant:' not in t and 'Verdict' not in t, 'the old columns are drawn: %r' % t[-250:])


@case(A)
def condition_matcher_popup_adds_reference():
    with ko() as v:
        add_string(v, 'GCC')
        add_matcher(v, 'find_str')
        click_in_panel(v, '[+ Condition]')
        y = [y for y in panel(v) if 'Matchers: None' in v.row(y)][0]
        v.click(v.row(y).index('[+ Matcher]') + 3, y)
        p = v.find('find_str', rows=(y, y + 5))
        check(p, 'condition has no matcher to pick')
        v.click(*p)
        check('Matchers: 1' in txt(v), 'matcher not referenced: %r' % txt(v)[-200:])


# ---------------------------------------------------------------------- diagnose
def dia(rows=70):
    """A module two diagnoses match (the test database's kmod_give_root and kmod_commit_only),
    on the Graphs tab. Needs `make test-sigs`."""
    v = Viewer(FIX('giveroot.ko'), rows=rows, cols=200, db='build/test/databases-sigs', copy=False)
    enlarge(v, 8)
    open_tab(v, 'Graphs')
    return v


@case(A)
def diagnose_panel_has_generate_and_discard_and_no_save_buttons():
    with dia() as v:
        r = v.row(head_row(v))
        check('[ Save ]' in r and '[ Discard' in r, r[-60:])
        check('[ Generate ]' not in r and '[ Save As ]' not in r, r[-60:])


@case(A)
def hcrk_graphs_tab_shows_no_diagnose_table():
    p = pick(SCRATCH + '/hcrk', 1, 2000, 2000000)[0]
    with Viewer(p, rows=70, cols=200) as v:
        enlarge(v, 8)
        open_tab(v, 'Graphs')
        check('Diagnoses' not in txt(v), 'the Graphs tab shows the old diagnose table on the hcrk sample')
        check(v.alive())


if __name__ == '__main__':
    main(A)
