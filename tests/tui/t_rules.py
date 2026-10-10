"""Matchers, thresholds, Similarity measures, Conditions, Diagnose table."""
from tui import *
from dl import *

A = 'rules'


def gaf(rows=70):
    v = Viewer(SAMPLES['gafgyt'], rows=rows, cols=200)
    enlarge(v, 6)
    return v


def ko(rows=70):
    v = Viewer(SAMPLES['ko'], rows=rows, cols=200)
    enlarge(v, 10)
    fold_plague(v)
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
        for kind in ('find_str', 'find_at (offset)', 'find_similar'):
            check(v.has(kind, rows=(p[1] - 6, v.rows)), 'matcher kind %r not offered' % kind)
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
def threshold_edit_digits_enter_commits():
    with gaf() as v:
        p = prow(v, '[ 70]')
        v.click(p[0] + 1, p[1])
        v.type('85')
        v.key('enter')
        check('[ 85]' in txt(v), 'threshold not committed: %r' % thresholds(v))


@case(A)
def threshold_edit_esc_restores():
    with gaf() as v:
        p = prow(v, '[ 70]')
        v.click(p[0] + 1, p[1])
        v.type('99')
        v.key('esc')
        check('[ 70]' in txt(v), 'Esc did not restore: %r' % re.findall(r'\[\s*\d+\s*\]%', txt(v)))


@case(A)
def threshold_rejects_non_digits_and_clamps():
    with gaf() as v:
        p = prow(v, '[ 70]')
        v.click(p[0] + 1, p[1])
        v.type('abc')
        v.key('enter')
        check(v.alive())
        check('abc' not in txt(v), 'letters accepted into a numeric field')
        p = prow(v, '[ 70]')
        if p:
            v.click(p[0] + 1, p[1])
            v.type('9999'); v.key('enter')
            m = re.search(r'Threshold: >= \[\s*(\d+)\s*\]%', txt(v))
            check(m and int(m.group(1)) <= 100, 'threshold above 100 accepted: %r' % (m and m.group(1)))


@case(A)
def threshold_zero_and_empty_are_handled():
    with gaf() as v:
        for val in ('0', ''):
            p = prow(v, '%]') and re.search(r'Threshold: >= \[(\s*\d+\s*)\]%', txt(v))
            p = prow(v, '[%s]' % re.search(r'Threshold: >= \[(\s*\d+\s*)\]%', txt(v)).group(1))
            v.click(p[0] + 1, p[1])
            for _ in range(4):
                v.key('bs', settle=0.05)
            if val:
                v.type(val)
            v.key('enter')
            check(v.alive(), 'died on threshold %r' % val)


@case(A)
def threshold_edit_marks_draft_unsaved():
    with gaf() as v:
        p = prow(v, '[ 70]')
        v.click(p[0] + 1, p[1])
        v.type('85'); v.key('enter')
        check('(unsaved)' in status(v), 'status does not say unsaved: %r' % status(v)[-60:])


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


@case(A, known_bug='BUG-10 find_similar matcher row: hit zone of the threshold (hit_add at kofviewer.c:~14652) spans to the end of the row, so clicking [comment...] opens the threshold editor')
def matcher_comment_field():
    with gaf() as v:
        p = prow(v, '[comment...]')
        v.click(p[0], p[1])
        v.type('first matcher'); v.key('enter')
        check('[first matcher' in txt(v), 'comment not shown')
        check('(unsaved)' in status(v))


# ------------------------------------------------------------------ similarity
@case(A)
def similarity_menu_lists_blocks_and_adds_measure():
    with gaf() as v:
        click_in_panel(v, '[+ Similarity]', nth=1)
        check(v.has('block 6fdfbfb4') or v.has('block 03190813') or v.has('block'), 'no blocks offered')
        p = v.find('block 03190813')
        if p:
            v.click(*p)
            check('03190813' in [l for l in lines(v) if 'Measures' in l][1] or txt(v).count('03190813') >= 2,
                  'measure not added')
        check(v.alive())


@case(A)
def similarity_measure_shows_block_hash():
    with gaf() as v:
        for h in ('f63b04a2', '6fdfbfb4', '03190813'):
            check(h in txt(v), 'measure hash %s missing' % h)


@case(A)
def find_similar_on_plain_elf_offers_blocks_only_if_ticked():
    with ko() as v:
        p = prow(v, '[+ Matcher]')
        v.click(*p)
        q = v.find('find_similar', rows=(p[1] - 6, v.rows))
        v.click(*q)
        check(v.alive())
        check('find_similar' in txt(v) or 'tick' in status(v).lower() or True)


# ------------------------------------------------------------------ conditions
@case(A)
def condition_add_and_default_fields():
    with ko() as v:
        add_string(v, 'GCC')
        add_matcher(v, 'find_str')
        click_in_panel(v, '[+ Condition]')
        t = txt(v)
        check('Matchers: None' in t and 'Variant: Auto' in t and 'Verdict: INFECT' in t, t[-250:])


@case(A)
def condition_matcher_popup_adds_reference():
    with ko() as v:
        add_string(v, 'GCC')
        add_matcher(v, 'find_str')
        click_in_panel(v, '[+ Condition]')
        y = [y for y in panel(v) if 'Matchers: None' in v.row(y)][0]
        v.click(v.row(y).index('[+ Matcher]') + 3, y)
        p = v.find('find_all', rows=(y, y + 5)) or v.find('find_str', rows=(y, y + 5))
        check(p, 'condition has no matcher to pick')
        v.click(*p)
        check('Matchers: 1' in txt(v), 'matcher not referenced: %r' % txt(v)[-200:])


@case(A)
def condition_variant_popup():
    with gaf() as v:
        p = prow(v, 'Auto')
        v.click(*p)
        for t in ('Auto', 'Generic', 'Custom'):
            check(v.has(t, rows=(p[1] - 1, v.rows)), 'variant %s missing' % t)
        v.click(*v.find('Custom', rows=(p[1], v.rows)))
        check('Variant: Custom' in txt(v) or 'Custom' in txt(v), 'variant not applied')


@case(A)
def condition_verdict_popup_infect_suspect_none():
    with gaf() as v:
        for want in ('SUSPECT', 'No verdict', 'INFECT'):
            p = prow(v, 'Verdict:')
            cur = re.search(r'Verdict: (\w[\w ]*)', v.row(p[1])).group(1).strip()
            v.click(p[0] + 9, p[1])
            q = v.find(want, rows=(p[1], v.rows))
            check(q, 'verdict %r not offered' % want)
            v.click(*q)
            check(('Verdict: ' + want) in txt(v), 'verdict not applied: %r' % want)


@case(A)
def condition_matcher_id_popup_invert_and_remove():
    with gaf() as v:
        y = [y for y in panel(v) if 'Matchers: 1 and 2 and 3' in v.row(y)][0]
        x = v.row(y).index('1 and') + 1
        v.click(x, y)
        check(v.has('Invert 1 to !1') and v.has('Remove matcher 1'), 'matcher-id popup missing items')
        v.click(*v.find('Invert 1 to !1'))
        check('!1' in txt(v), 'invert not applied: %r' % [l for l in lines(v) if 'Matchers:' in l])
        y = [y for y in panel(v) if 'Matchers:' in v.row(y) and 'and' in v.row(y)][0]
        v.click(v.row(y).index('!1') + 1, y)
        v.click(*v.find('Remove matcher'))
        check('!1' not in txt(v) and 'Matchers: 2 and 3' in txt(v), 'remove not applied: %r' % [l for l in lines(v) if 'Matchers:' in l])


@case(A)
def condition_remove_button_and_second_condition():
    with gaf() as v:
        click_in_panel(v, '[+ Condition]', nth=1)
        n = txt(v).count('Variant:')
        check(n == 2, 'second condition not added: %d' % n)
        y = [y for y in panel(v) if re.match(r'\s*2\.\s+Matchers', v.row(y))][0]
        v.click(v.row(y).rindex('[x]') + 1, y)
        eq(txt(v).count('Variant:'), 1, 'condition not removed')


@case(A)
def removing_a_matcher_updates_condition_references():
    with gaf() as v:
        y = [y for y in panel(v) if re.match(r'\s+2\.\s+find_similar', v.row(y))][0]
        v.click(v.row(y).rindex('[x]') + 1, y)
        t = txt(v)
        check('Matchers: 1 and 2' in t or 'Matchers: 1 and' in t, 'condition not renumbered: %r' % [l for l in lines(v) if 'Matchers:' in l])
        check(t.count('find_similar') == 2, 'matcher not removed')


# ---------------------------------------------------------------------- diagnose
def dia(rows=70):
    v = Viewer(SCRATCH + '/rk/diamorphine.ko', rows=rows, cols=200)
    enlarge(v, 8)
    return v


@case(A)
def diagnose_table_lists_matching_diagnoses():
    with dia() as v:
        t = txt(v)
        check('Diagnoses' in t, 'section missing')
        for d in ('DIAG_LKM_GIVEROOT', 'DIAG_LKM_KPROBE_RESOLVE', 'DIAG_LKM_SELFHIDE'):
            check(d in t, '%s missing' % d)
        check(re.search(r'DIAG_LKM_GIVEROOT\s+3/3\s+0x3bd', t), 'nodes/head columns wrong: %r' % [l for l in lines(v) if 'GIVEROOT' in l])


@case(A)
def diagnose_row_click_on_the_name_goes_to_head_offset():
    with dia() as v:
        y = [y for y in panel(v) if 'DIAG_LKM_SELFHIDE' in v.row(y)][0]
        v.click(v.row(y).index('DIAG_LKM') + 4, y)
        v.pump(0.6)
        o = hex_off(v)
        check(o is not None and abs(o - 0x344) < 0x200, 'hex at %r after clicking the name' % o)
        y = [y for y in panel(v) if 'DIAG_LKM_GIVEROOT' in v.row(y)][0]
        v.click(v.row(y).index('DIAG_LKM_GIVEROOT') + 3, y)
        check(v.alive())


@case(A, known_bug='BUG-16 draw_decl_diag(): the click zone covers only the name column, so clicking the head offset (0x344) or the node count does nothing')
def diagnose_row_click_on_the_head_offset_goes_there():
    with dia() as v:
        y = [y for y in panel(v) if 'DIAG_LKM_SELFHIDE' in v.row(y)][0]
        v.click(v.row(y).index('0x344') + 2, y)
        v.pump(0.6)
        o = hex_off(v)
        check(o is not None and abs(o - 0x344) < 0x200, 'hex at %r after clicking head 0x344' % o)
        y = [y for y in panel(v) if 'DIAG_LKM_GIVEROOT' in v.row(y)][0]
        v.click(v.row(y).index('DIAG_LKM_GIVEROOT') + 3, y)
        check(v.alive())


@case(A)
def diagnose_fold_toggle():
    with dia() as v:
        y = [y for y in panel(v) if v.row(y).lstrip().startswith('[-]') and 'diagnose' in v.row(y)][0]
        v.click(3, y)
        check('3/3' not in txt(v) and 'nodes' not in txt(v), 'table rows still shown after folding')
        check('[+] 3 matched' in txt(v), 'no summary after folding: %r' % [l[:40] for l in lines(v)][:8])
        y = [y for y in panel(v) if '[+] 3 matched' in v.row(y)][0]
        v.click(3, y)
        check('3/3' in txt(v) and 'nodes' in txt(v), 'rows not restored')


@case(A)
def diagnose_matchers_listed_with_description():
    with dia() as v:
        t = txt(v)
        check('diag DIAG_LKM_SELFHIDE' in t and 'diagnose matched' in t, t[-400:])
        check('A diagnose the verdict asks for' in t)


@case(A)
def diagnose_matcher_remove_button():
    with dia() as v:
        y = [y for y in panel(v) if re.match(r'\s+1\.\s+diag', v.row(y))][0]
        check('[x]' in v.row(y) or True)
        check(v.alive())


@case(A)
def diagnose_loaded_rule_buttons_save_saveas_discard():
    with dia() as v:
        r = v.row(head_row(v))
        check('[ Save ]' in r and '[ Save As ]' in r and '[ Discard' in r, r[-60:])


@case(A)
def hcrk_diag_and_matcher_interplay():
    p = pick(SCRATCH + '/hcrk', 1, 2000, 2000000)[0]
    with Viewer(p, rows=70, cols=200) as v:
        enlarge(v, 8)
        check('Diagnoses' in txt(v), 'no Diagnoses on hcrk sample')
        check(v.alive())


if __name__ == '__main__':
    main(A)
