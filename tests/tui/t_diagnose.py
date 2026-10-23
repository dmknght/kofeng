"""The diagnose panel: the shared declaration, the Patterns | Blocks | Graphs
title bar and each tab's own tables, the Tag cell (a chooser over the tags of
bases/syndromes), and the output preview.

Nothing here writes a file: Generate only LISTS the output, and one case checks
that (no signature appears, nothing is left in /tmp)."""
import glob
from tui import *
from dl import *

A = 'diagnose'


def ko(rows=60, cols=130, grow=14):
    v = Viewer(SAMPLES['ko'], rows=rows, cols=cols)
    enlarge(v, grow)
    return v


def txt(v):
    return '\n'.join(v.row(y) for y in panel(v))


# ------------------------------------------------------------------ title bar
@case(A)
def title_bar_has_three_cells_and_patterns_is_open():
    with ko() as v:
        y = tab_row(v)
        check(y, 'no title bar')
        r = v.row(y)
        check(r.index('Patterns') < r.index('Blocks') < r.index('Graphs'), r[:60])
        eq(active_tab(v), 'Patterns', 'open tab')


@case(A)
def clicking_a_cell_switches_tab_and_highlights_it():
    with ko() as v:
        open_tab(v, 'Blocks')
        eq(active_tab(v), 'Blocks')
        open_tab(v, 'Graphs')
        eq(active_tab(v), 'Graphs')
        open_tab(v, 'Patterns')
        eq(active_tab(v), 'Patterns')
        check(v.alive())


@case(A)
def shared_header_is_the_same_on_every_tab():
    with ko() as v:
        click_in_panel(v, '[?]')
        v.type('mirai'); v.key('enter')
        for name in TABS:
            open_tab(v, name)
            r = v.row(head_row(v))
            check('Family [mirai]' in r and 'Type [Virus]' in r, '%s: %r' % (name, r[:60]))
            t = txt(v)
            check('Format' in t and 'Region' in t and 'Option' in t and '[+ Options]' in t,
                  'shared rows missing on %s' % name)
            # and they are above the bar, which is where "shared" is drawn
            check(prow(v, '[+ Options]')[1] < tab_row(v), 'options are not above the title bar on %s' % name)


@case(A)
def option_row_is_the_shared_options_control():
    with ko() as v:
        click_in_panel(v, '[+ Options]')
        check(v.has('Architecture') or v.has('arch') or v.has('Subtype') or v.has('Size'),
              'options menu not shown: %r' % [v.row(y)[:50] for y in panel(v)][:8])
        v.esc()


# ----------------------------------------------------------------- the tables
@case(A)
def patterns_tab_has_intron_matchers_and_conditions():
    with ko() as v:
        t = txt(v)
        check('Intron' in t, 'Intron table missing')
        check('Strings' not in t, 'the old Strings title is still there')
        check(' Matchers' in t and ' Conditions' in t)
        check('Mutation blocks' not in t and 'Lineage' not in t, 'another tab leaked into Patterns')


@case(A)
def blocks_tab_has_mutation_blocks_matchers_and_conditions():
    with ko() as v:
        open_tab(v, 'Blocks')
        fold_mutation(v)            # the table is hundreds of rows; the rest is below it
        t = txt(v)
        check('Mutation blocks' in t and ' Matchers' in t and ' Conditions' in t, t[:300])
        check('Intron' not in t and 'Lineage' not in t, 'another tab leaked into Blocks')
        check('[+ Matcher]' not in t, 'a block matcher is made by ticking, not by a button')
        check('[+ String]' not in t)


@case(A)
def graphs_tab_is_on_hold_and_draws_its_tables_empty():
    with ko() as v:
        open_tab(v, 'Graphs')
        t = txt(v)
        check('Lineage' in t and 'on hold' in t, t[:300])
        check(' Conditions (on hold)' in t, 'Conditions heading not marked on hold')
        check('[+ Condition]' not in t and '[+ Matcher]' not in t and 'Intron' not in t and
              'Mutation blocks' not in t, 'graphs tab offers something to build: %r' % t[:300])
        check(v.alive())


@case(A)
def lineage_table_lists_matching_diagnoses_on_the_graphs_tab():
    with Viewer(FIX('giveroot.ko'), rows=70, cols=200, db='build/test/databases-sigs', copy=False) as v:
        enlarge(v, 12)
        check('Lineage' not in txt(v) and 'Diagnoses' not in txt(v), 'diagnoses shown outside the Graphs tab')
        open_tab(v, 'Graphs')
        t = txt(v)
        check('Lineage' in t and 'Diagnoses' not in t, 'table not renamed')
        for d in ('kmod_give_root', 'kmod_commit_only'):
            check(d in t, '%s missing' % d)


# ---------------------------------------------------------- string matcher kinds
@case(A)
def string_matcher_menu_offers_only_find_str_and_find_at():
    with ko() as v:
        add_string(v, 'GCC')
        p = prow(v, '[+ Matcher]')
        v.click(*p)
        check(v.has('find_str', rows=(p[1], v.rows)) and v.has('find_at (offset)', rows=(p[1], v.rows)))
        check(not v.has('find_similar') and not v.has('find_sim') and not v.has('find_all') and
              not v.has('find_any') and not v.has('find_multi'), 'another kind is offered')
        v.esc()


@case(A)
def condition_matcher_menu_uses_the_same_two_words():
    with ko() as v:
        add_string(v, 'GCC')
        add_matcher(v, 'find_str')
        add_matcher(v, 'find_at (offset)')
        click_in_panel(v, '[+ Condition]')
        y = [y for y in panel(v) if 'Matchers: None' in v.row(y)][0]
        v.click(v.row(y).index('[+ Matcher]') + 3, y)
        check(v.has('1  find_str', rows=(y, y + 6)) and v.has('2  find_at', rows=(y, y + 6)),
              [v.row(yy)[:60] for yy in range(y, y + 6)])
        check(not v.has('find_all') and not v.has('find_multi'))
        v.esc()


# ----------------------------------------------------- block matchers by the tick
@case(A)
def ticking_a_block_adds_a_find_sim_matcher_and_unticking_drops_it():
    with ko(grow=16) as v:
        open_tab(v, 'Blocks')
        h1, h2 = tick_blocks(v, 2)
        fold_mutation(v)
        rows = sim_rows(v)
        eq([r[1] for r in rows], [h1, h2], 'matchers by hash after two ticks')
        eq([r[2] for r in rows], [60, 60], 'default thresholds')
        # untick the first one, by its row in the (folded) table
        y = [y for y in panel(v) if re.match(r'\s+\[x\]\s+0x[0-9a-f]{8}\s+%s' % h1, v.row(y))][0]
        v.click(v.row(y).index('[x]') + 2, y)
        rows = sim_rows(v)
        eq([(r[0], r[1]) for r in rows], [(1, h2)], 'the first matcher is dropped and the next one renumbered')
        y = [y for y in panel(v) if re.match(r'\s+\[x\]\s+0x[0-9a-f]{8}\s+%s' % h2, v.row(y))][0]
        v.click(v.row(y).index('[x]') + 2, y)
        eq(sim_rows(v), [], 'no matcher left after the last block is unticked')


@case(A)
def block_matcher_is_one_row_with_hash_threshold_and_no_kind_to_choose():
    with ko(grow=16) as v:
        open_tab(v, 'Blocks')
        h = tick_blocks(v, 1)[0]
        fold_mutation(v)
        y = [y for y in panel(v) if 'find_sim' in v.row(y)][0]
        r = v.row(y)
        check(re.search(r'1\.\s+find_sim\s+# hash %s\s+Threshold: >= \[\s*60\]%%' % h, r), r[:90])
        check('[comment...]' in r and '[x]' not in r, 'row: %r' % r)
        x = r.index('find_sim') + 2
        v.click(x, y)
        check(not v.has('find_all') and not v.has('find_str') and not v.has('find_similar'),
              'clicking the word offered a kind')
        check(v.has('find_sim', rows=(y, y)), 'the matcher went away')


@case(A)
def block_matcher_threshold_is_editable():
    with ko(grow=16) as v:
        open_tab(v, 'Blocks')
        tick_blocks(v, 1)
        fold_mutation(v)
        p = prow(v, '[ 60]')
        v.click(p[0] + 1, p[1])
        v.type('75'); v.key('enter')
        eq([r[2] for r in sim_rows(v)], [75], 'threshold after typing')


@case(A)
def block_matcher_is_not_listed_on_the_patterns_tab():
    with ko(grow=16) as v:
        open_tab(v, 'Blocks')
        tick_blocks(v, 1)
        open_tab(v, 'Patterns')
        check('find_sim' not in txt(v), 'a block matcher on the Patterns tab')
        open_tab(v, 'Blocks')
        check('find_sim' in txt(v) or fold_mutation(v) or 'find_sim' in txt(v))


# ----------------------------------------------------------------- conditions
@case(A)
def conditions_have_a_tag_and_neither_variant_nor_verdict():
    with ko() as v:
        str_condition(v)
        t = txt(v)
        check('Tag: none' in t and 'choose one' not in t, t[-300:])
        check('Variant' not in t and 'Verdict' not in t, 'old columns still drawn: %r' % t[-300:])
        check('Matchers: 1' in t)


@case(A)
def tag_is_chosen_from_the_tags_table_and_never_typed():
    with ko(grow=18) as v:
        str_condition(v)
        y = open_tag_chooser(v)
        box = [v.row(yy) for yy in range(y, y + 12)]
        t = '\n'.join(box)
        for col in ('Name', 'Activities', 'Types', 'Family'):
            check(col in t, 'column %s missing: %r' % (col, t))
        for tag in ('command-and-control', 'execute-memory', 'network-flood'):
            check(tag in t, '%s is not offered' % tag)
        check('(no tag)' in t, 'no way to say "no tag"')
        check('network' in t and 'botnet, trojan' in t, 'activities and types not listed: %r' % t)
        check('network/' not in t and ':' not in ''.join(r[30:] for r in box[3:9]), 'a joined name is listed')
        # typing goes to the search box: it narrows the list and makes no tag
        v.type('zzz')
        t = '\n'.join(v.row(yy) for yy in range(y, y + 12))
        check('command-and-control' not in t and 'nothing matches' in t, 'search did not narrow: %r' % t)
        v.key('enter')                      # nothing to pick: not "(no tag)" by accident
        check(tag_box_top(v) is not None, 'Enter with no match closed the chooser')
        v.esc()
        check(tag_box_top(v) is None, 'Esc did not close the chooser')
        check('Tag: none' in txt(v), 'a tag appeared from nothing')
        pick_tag(v, 'network-flood')
        check('Tag: network-flood' in txt(v), txt(v)[-200:])
        pick_tag(v, 'execute-memory')
        check('Tag: execute-memory' in txt(v), txt(v)[-200:])
        # (no tag) takes the tag away again
        pick_tag(v, '(no tag)')
        check('Tag: none' in txt(v), txt(v)[-200:])


@case(A)
def blocks_condition_is_made_of_block_matchers_only():
    with ko(grow=18) as v:
        str_condition(v)                       # a Patterns condition over a find_str
        open_tab(v, 'Blocks')
        tick_blocks(v, 1)
        fold_mutation(v)
        check('Matchers: 1' not in txt(v), 'the Patterns condition is drawn on the Blocks tab')
        click_in_panel(v, '[+ Condition]')
        y = [y for y in panel(v) if 'Matchers: None' in v.row(y)][0]
        v.click(v.row(y).index('[+ Matcher]') + 3, y)
        check(v.has('find_sim', rows=(y, y + 4)) and not v.has('find_str', rows=(y, y + 4)),
              'condition menu: %r' % [v.row(yy)[:60] for yy in range(y, y + 4)])
        v.esc()


# ------------------------------------------------------------------- the output
def two_conditions(v, tag2='network-flood'):
    """Family mirai, two string conditions: the first tagged Botnet, the second
    with `tag2`."""
    click_in_panel(v, '[?]')
    v.type('Mirai'); v.key('enter')
    str_condition(v)
    click_in_panel(v, '[+ Condition]')
    y = [y for y in panel(v) if 'Matchers: None' in v.row(y)][0]
    v.click(v.row(y).index('[+ Matcher]') + 3, y)
    p = v.find('find_str', rows=(y, y + 5))
    v.click(*p)
    pick_tag(v, 'network-flood', 0)
    pick_tag(v, tag2, 1)


@case(A)
def generate_lists_one_entry_per_condition_with_its_file_name():
    with ko(grow=22) as v:
        two_conditions(v)
        check('PREVIEW' not in txt(v), 'the output is drawn before Generate')
        click_in_panel(v, '[ Generate ]')
        t = txt(v)
        check('Output - PREVIEW, nothing is written' in t, t[-400:])
        check('type Virus  family Mirai' in t and 'format ELF' in t, 'shared header: %r' % t[-300:])
        check('virus_' not in t, 'the file prefix is the tag\'s own type, not the shared Type')
        check('botnet_network-flood_01.c' in t and 'botnet_network-flood_02.c' in t,
              'two files, ids running per prefix: %r' % re.findall(r'\S+\.c', t))
        check(t.count('tag network-flood') == 2, 'tags not listed')
        check('1  find_str >= ' in t and 'markers 1' in t, 'matchers not listed: %r' % t[-300:])
        # and it is a toggle
        click_in_panel(v, '[ Generate ]')
        check('PREVIEW' not in txt(v), 'second press did not take the output away')


@case(A)
def output_names_follow_the_tag_and_say_what_is_missing():
    with ko(grow=22) as v:
        str_condition(v)
        click_in_panel(v, '[ Generate ]')
        check('<tag>_01.c' in txt(v), 'gap not in the name: %r' % re.findall(r'\S+\.c', txt(v)))
        click_in_panel(v, '[ Generate ]')
        click_in_panel(v, '[Virus]')
        pick_menu_item(v, 'Botnet', rows=(grip(v) + 2, v.rows))
        click_in_panel(v, '[?]'); v.type('Mirai X!'); v.key('enter')
        pick_tag(v, 'execute-memory')
        click_in_panel(v, '[ Generate ]')
        # the name is the tag's: its first type (dropper, declared before
        # trojan) and its name - the shared Type and Family are filters only
        check('dropper_execute-memory_01.c' in txt(v), re.findall(r'\S+\.c', txt(v)))


@case(A)
def output_lists_block_matchers_with_hash_and_threshold():
    with ko(grow=22) as v:
        click_in_panel(v, '[?]'); v.type('F'); v.key('enter')
        open_tab(v, 'Blocks')
        h = tick_blocks(v, 1)[0]
        fold_mutation(v)
        click_in_panel(v, '[+ Condition]')
        y = [y for y in panel(v) if 'Matchers: None' in v.row(y)][0]
        v.click(v.row(y).index('[+ Matcher]') + 3, y)
        v.click(*v.find('find_sim  ', rows=(y, y + 4)))
        pick_tag(v, 'execute-memory')
        click_in_panel(v, '[ Generate ]')
        t = txt(v)
        check(('1  find_sim  # hash %s  threshold 60' % h) in t, t[-300:])
        check('dropper_execute-memory_01.c' in t, re.findall(r'\S+\.c', t))


@case(A)
def each_condition_has_its_own_tag_and_its_own_file_name():
    with ko(grow=22) as v:
        two_conditions(v, 'command-and-control')
        t = txt(v)
        check('Tag: network-flood' in t and 'Tag: command-and-control' in t,
              'the two tags are not both on screen: %r' % t[-300:])
        click_in_panel(v, '[ Generate ]')
        t = txt(v)
        eq(re.findall(r'\S+\.c', t), ['botnet_network-flood_01.c', 'botnet_command-and-control_01.c'],
           'one file per condition, each from its own tag')
        check('tag network-flood' in t and 'tag command-and-control' in t, t[-300:])


@case(A)
def tag_and_file_names_stay_when_the_shared_type_changes():
    with ko(grow=22) as v:
        two_conditions(v, 'command-and-control')
        click_in_panel(v, '[Virus]')
        pick_menu_item(v, 'Dropper', rows=(grip(v) + 2, v.rows))
        check('Type [Dropper]' in v.row(head_row(v)), v.row(head_row(v))[:50])
        t = txt(v)
        check('Tag: network-flood' in t and 'Tag: command-and-control' in t,
              'a tag changed with the shared Type: %r' % t[-300:])
        click_in_panel(v, '[ Generate ]')
        eq(re.findall(r'\S+\.c', txt(v)),
           ['botnet_network-flood_01.c', 'botnet_command-and-control_01.c'],
           'the shared Type is not part of a name')


@case(A)
def an_empty_family_leaves_no_doubled_underscore_in_the_name():
    with ko(grow=22) as v:
        str_condition(v)
        pick_tag(v, 'execute-memory')
        click_in_panel(v, '[ Generate ]')
        names = re.findall(r'\S+\.c', txt(v))
        eq(names, ['dropper_execute-memory_01.c'], 'family-less name')
        check('__' not in names[0])


@case(A)
def matchers_are_numbered_per_tab_and_a_tab_switch_renumbers_nothing():
    with ko(grow=18) as v:
        add_string(v, 'GCC')
        add_matcher(v, 'find_str')
        add_matcher(v, 'find_str')
        open_tab(v, 'Blocks')
        h1, h2 = tick_blocks(v, 2)
        fold_mutation(v)
        eq([(r[0], r[1]) for r in sim_rows(v)], [(1, h1), (2, h2)],
           'the Blocks tab does not start at 1')
        open_tab(v, 'Patterns')
        nums = [int(m.group(1)) for y in panel(v)
                for m in [re.match(r'\s+(\d+)\.\s+find_str', v.row(y))] if m]
        eq(nums, [1, 2], 'Patterns numbering')
        open_tab(v, 'Blocks')
        eq([r[0] for r in sim_rows(v)], [1, 2], 'a tab switch renumbered the Blocks matchers')


@case(A)
def a_condition_can_name_only_its_own_tabs_matchers():
    with ko(grow=18) as v:
        str_condition(v)                       # Patterns: matcher 1 in condition 1
        open_tab(v, 'Blocks')
        tick_blocks(v, 1)
        fold_mutation(v)
        click_in_panel(v, '[+ Condition]')
        y = [y for y in panel(v) if 'Matchers: None' in v.row(y)][0]
        v.click(v.row(y).index('[+ Matcher]') + 3, y)
        check(v.has('1  find_sim', rows=(y, y + 4)), 'the Blocks matcher is not offered as 1')
        check(not v.has('find_str', rows=(y, y + 4)), 'a Patterns matcher is offered on Blocks')
        v.click(*v.find('1  find_sim', rows=(y, y + 4)))
        check('Matchers: 1 ' in txt(v) or 'Matchers: 1' in txt(v), txt(v)[-300:])
        open_tab(v, 'Patterns')
        t = txt(v)
        check(len(re.findall(r'Matchers: 1\b', t)) == 1, 'the Patterns condition changed: %r' % t[-300:])


@case(A)
def conditions_are_independent_blocks_with_no_nesting_and_no_join_row():
    with ko(grow=22) as v:
        two_conditions(v)
        t = txt(v)
        check('logic' not in t and '[and]' not in t and '[or]' not in t, 'a join row is drawn: %r' % t[-400:])
        eq(t.count('[+ Condition]'), 1, 'one button adds a condition; there is no nested one')
        check(len(re.findall(r'^\s+\d+\.\s+Matchers:', t, re.M)) == 2, 'two independent blocks: %r' % t[-400:])
        check(len(re.findall(r'^\s+\d+\.\s+Matchers:', t, re.M)) == len(re.findall(r'Tag:', t)))
        check(not re.search(r'\d+\.\d+\.', t), 'a nested label is drawn')


@case(A)
def generate_without_a_condition_says_so_and_draws_nothing():
    with ko() as v:
        click_in_panel(v, '[ Generate ]')
        check('PREVIEW' not in txt(v))
        check('condition' in status(v).lower(), 'status: %r' % status(v)[-70:])


@case(A)
def generate_writes_no_file_anywhere():
    fresh_bases()
    tmp0 = set(glob.glob('/tmp/kof_draft_src_*'))
    before = set(glob.glob(os.path.join(BASES_COPY, '**', '*.c'), recursive=True))
    with ko(grow=22) as v:
        two_conditions(v)
        click_in_panel(v, '[ Generate ]')
        check('PREVIEW' in txt(v))
        v.pump(0.5)
    after = set(glob.glob(os.path.join(BASES_COPY, '**', '*.c'), recursive=True))
    eq(sorted(after - before), [], 'files written by Generate')
    eq(sorted(set(glob.glob('/tmp/kof_draft_src_*')) - tmp0), [], 'scratch source left in /tmp')


def model_ok(v, where):
    """draw_decl writes "panel rows N, model M - a section is miscounted" into the
    status line when the row model and the drawing disagree, which is every click
    landing a row off: none of the states below may say it."""
    check('miscounted' not in status(v), '%s: %r' % (where, status(v)[-90:]))


@case(A)
def row_model_agrees_with_the_drawing_in_every_state():
    with ko(grow=22) as v:
        model_ok(v, 'Patterns, empty')
        str_condition(v)
        model_ok(v, 'Patterns, a condition')
        open_tab(v, 'Blocks')
        model_ok(v, 'Blocks, table open')
        tick_blocks(v, 2)
        fold_mutation(v)
        model_ok(v, 'Blocks, two matchers')
        click_in_panel(v, '[+ Condition]')
        model_ok(v, 'Blocks, a condition')
        open_tab(v, 'Graphs')
        model_ok(v, 'Graphs')
        open_tab(v, 'Patterns')
        click_in_panel(v, '[ Generate ]')
        model_ok(v, 'output on')
        open_tab(v, 'Blocks')
        model_ok(v, 'output on, Blocks')
    with Viewer(FIX('tiny.bin'), rows=40, cols=120) as v:
        enlarge(v, 12)
        open_tab(v, 'Blocks')
        check('none - this object has no executable code' in txt(v), 'no explanation for an object without blocks')
        model_ok(v, 'Blocks on an object with no code')
        open_tab(v, 'Graphs')
        model_ok(v, 'Graphs on a small object')
    with Viewer(SCRATCH + '/rk/diamorphine.ko', rows=60, cols=200) as v:
        enlarge(v, 12)
        for name in TABS:
            open_tab(v, name)
            model_ok(v, 'diamorphine, ' + name)


@case(A)
def discard_takes_the_output_away():
    with ko(grow=22) as v:
        two_conditions(v)
        click_in_panel(v, '[ Generate ]')
        click_in_panel(v, '[ Discard ]')
        check('PREVIEW' not in txt(v))


if __name__ == '__main__':
    main(A)
