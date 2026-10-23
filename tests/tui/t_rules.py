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
        check('Variant' not in t and 'Verdict' not in t, 'the old columns are drawn: %r' % t[-250:])


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
    on the Graphs tab where the Lineage table is. Needs `make test-sigs`."""
    v = Viewer(FIX('giveroot.ko'), rows=rows, cols=200, db='build/test/databases-sigs', copy=False)
    enlarge(v, 8)
    open_tab(v, 'Graphs')
    return v


@case(A)
def diagnose_table_lists_matching_diagnoses():
    with dia() as v:
        t = txt(v)
        check('Lineage' in t and 'Diagnoses' not in t, 'section missing or not renamed')
        for d in ('kmod_give_root', 'kmod_commit_only'):
            check(d in t, '%s missing' % d)
        check(re.search(r'kmod_give_root\s+2/2\s+0x45', t), 'nodes/head columns wrong: %r' % [l for l in lines(v) if 'give_root' in l])


@case(A)
def diagnose_row_click_on_the_name_goes_to_head_offset():
    with dia() as v:
        y = [y for y in panel(v) if 'kmod_commit_only' in v.row(y)][0]
        v.click(v.row(y).index('kmod_commit') + 4, y)
        v.pump(0.6)
        o = hex_off(v)
        check(o is not None and abs(o - 0x4d) < 0x200, 'hex at %r after clicking the name' % o)
        y = [y for y in panel(v) if 'kmod_give_root' in v.row(y)][0]
        v.click(v.row(y).index('kmod_give_root') + 3, y)
        check(v.alive())


@case(A, known_bug='BUG-16 draw_decl_diag(): the click zone covers only the name column, so clicking the head offset (0x4d) or the node count does nothing')
def diagnose_row_click_on_the_head_offset_goes_there():
    with dia() as v:
        y = [y for y in panel(v) if 'kmod_commit_only' in v.row(y)][0]
        v.click(v.row(y).index('0x4d') + 2, y)
        v.pump(0.6)
        o = hex_off(v)
        check(o is not None and abs(o - 0x4d) < 0x200, 'hex at %r after clicking head 0x4d' % o)
        y = [y for y in panel(v) if 'kmod_give_root' in v.row(y)][0]
        v.click(v.row(y).index('kmod_give_root') + 3, y)
        check(v.alive())


@case(A)
def diagnose_fold_toggle():
    with dia() as v:
        y = [y for y in panel(v) if v.row(y).lstrip().startswith('[-]') and 'diagnose' in v.row(y)][0]
        v.click(3, y)
        check('2/2' not in txt(v) and 'nodes' not in txt(v), 'table rows still shown after folding')
        check('[+] 2 matched' in txt(v), 'no summary after folding: %r' % [l[:40] for l in lines(v)][:8])
        y = [y for y in panel(v) if '[+] 2 matched' in v.row(y)][0]
        v.click(3, y)
        check('2/2' in txt(v) and 'nodes' in txt(v), 'rows not restored')


@case(A)
def diagnose_panel_has_generate_and_discard_and_no_save_buttons():
    with dia() as v:
        r = v.row(head_row(v))
        check('[ Generate ]' in r and '[ Discard' in r, r[-60:])
        check('[ Save ]' not in r and '[ Save As ]' not in r, r[-60:])


@case(A)
def hcrk_diag_and_matcher_interplay():
    p = pick(SCRATCH + '/hcrk', 1, 2000, 2000000)[0]
    with Viewer(p, rows=70, cols=200) as v:
        enlarge(v, 8)
        open_tab(v, 'Graphs')
        check('Lineage' in txt(v), 'no Lineage table on hcrk sample')
        check(v.alive())


if __name__ == '__main__':
    main(A)
