"""The diagnose panel: the shared declaration, the Patterns | Blocks | Graphs
title bar and each tab's own tables, the Type and Tag cells of a unit (Type: the
types of the header's variant; Tag: a list over the Syndromes catalog), and the
output Generate lists.

THE UNIT RULE: a Patterns CONDITION is a unit and a Blocks MATCHER is a unit; nothing else is. Each has its own Type
and Tag cells (once per unit); the Blocks tab has no conditions.

Generate writes one diagnose source per unit into <bases>/diagnoses (a condition: its string matchers; a block matcher: its mutation
block and a similarity test) and refuses the whole draft, writing nothing, when a unit has no type or the text it would write does not read
back. The writer's own mechanics are pinned by tests/unit/diag_write.c and diag_form_generate.c."""
import glob, hashlib, os, re
from tui import *
from dl import *

A = 'diagnose'


def ko(rows=60, cols=130, grow=14):
    fresh_bases()                  # Generate writes into <bases>/diagnoses: every case starts from an empty one
    return ko_cat(rows=rows, cols=cols, grow=grow)


def two(rows=60, cols=130, grow=14):
    """ko() on a sample with at least two blocks that carry a hash (the kernel module has one: see dl.data_cat)."""
    fresh_bases()
    return data_cat(rows=rows, cols=cols, grow=grow)


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
        set_family(v, 'Mirai')
        for name in TABS:
            open_tab(v, name)
            r = v.row(head_row(v))
            check('Family [ Mirai ]' in r and 'Variant [ ? ]' in r and 'Type [' not in r, '%s: %r' % (name, r[:60]))
            t = txt(v)
            check('Format' in t and 'Option' in t and '[+ Options]' in t,
                  'shared rows missing on %s' % name)
            # the region list is no header row: it sits under the table of the Patterns and Blocks tabs
            if name != 'Blocks':          # (on Blocks it is below the block table, off the screen)
                check(('Region' in t) == (name == 'Patterns'), 'region row on %s' % name)
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
        check('Mutation blocks' not in t and 'Diagnoses' not in t, 'another tab leaked into Patterns')


@case(A)
def blocks_tab_has_mutation_blocks_and_matchers_and_no_conditions():
    with ko() as v:
        open_tab(v, 'Blocks')
        fold_mutation(v)            # the table is hundreds of rows; the rest is below it
        t = txt(v)
        check('Mutation blocks' in t and ' Matchers' in t, t[:300])
        check(' Conditions' not in t and '[+ Condition]' not in t and 'Matchers:' not in t, 'the Blocks tab has conditions: %r' % t[-300:])
        check('Intron' not in t and 'Diagnoses' not in t, 'another tab leaked into Blocks')
        check('[+ Matcher]' not in t, 'a block matcher is made by ticking, not by a button')
        check('[+ String]' not in t)


@case(A)
def graphs_tab_draws_nothing_to_build_and_no_diagnose_table():
    with ko() as v:
        open_tab(v, 'Graphs')
        t = txt(v)
        check('Diagnoses' not in t and 'Lineage' not in t, 'the Graphs tab shows the old diagnose table: ' + t[:300])
        check('Conditions' not in t, 'the Graphs tab has a Conditions heading')
        check('[+ Condition]' not in t and '[+ Matcher]' not in t and 'Intron' not in t and
              'Mutation blocks' not in t, 'graphs tab offers something to build: %r' % t[:300])
        check(v.alive())


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
    with two(grow=16) as v:
        open_tab(v, 'Blocks')
        h1, h2 = tick_blocks(v, 2)
        fold_mutation(v)
        rows = sim_rows(v)
        eq([r[1] for r in rows], [h1, h2], 'matchers by hash after two ticks')
        eq([r[2] for r in rows], [70, 70], 'default thresholds')
        # untick the first one, by its row in the (folded) table
        y = [y for y in panel(v) if re.match(r'\s+\[x\]\s+0x[0-9a-f]{8}\s+%s' % h1, v.row(y))][0]
        v.click(v.row(y).index('[x]') + 2, y)
        rows = sim_rows(v)
        eq([(r[0], r[1]) for r in rows], [(1, h2)], 'the first matcher is dropped and the next one renumbered')
        y = [y for y in panel(v) if re.match(r'\s+\[x\]\s+0x[0-9a-f]{8}\s+%s' % h2, v.row(y))][0]
        v.click(v.row(y).index('[x]') + 2, y)
        eq(sim_rows(v), [], 'no matcher left after the last block is unticked')


@case(A)
def block_matcher_is_two_rows_hash_threshold_and_unit_cells_and_no_kind_to_choose():
    with ko(grow=16) as v:
        open_tab(v, 'Blocks')
        h = tick_blocks(v, 1)[0]
        fold_mutation(v)
        y = [y for y in panel(v) if re.match(SIM_ROW, v.row(y))][0]
        r = v.row(y)
        check(re.search(r'1\.\s+(?:\S+: )?%s\s+Threshold: >= \[\s*70\]%%' % h, r), r[:90])
        check('find_sim' not in r, 'the word find_sim is printed: %r' % r)
        check('[comment...]' in r and '[x]' not in r, 'row: %r' % r)
        x = r.index(h) + 2
        v.click(x, y)
        check(not v.has('find_all') and not v.has('find_str') and not v.has('find_similar'),
              'clicking the word offered a kind')
        check(re.match(SIM_ROW, v.row(y)), 'the matcher went away')


@case(A)
def block_matcher_threshold_is_editable():
    with ko(grow=16) as v:
        open_tab(v, 'Blocks')
        tick_blocks(v, 1)
        fold_mutation(v)
        p = prow(v, '[ 70]')
        v.click(p[0] + 1, p[1])
        v.type('75'); v.key('enter')
        eq([r[2] for r in sim_rows(v)], [75], 'threshold after typing')


@case(A)
def block_matcher_is_not_listed_on_the_patterns_tab():
    with ko(grow=16) as v:
        open_tab(v, 'Blocks')
        tick_blocks(v, 1)
        open_tab(v, 'Patterns')
        check('find_sim' not in txt(v) and not re.search(SIM_ROW, txt(v), re.M), 'a block matcher on the Patterns tab')
        open_tab(v, 'Blocks')
        check(re.search(SIM_ROW, txt(v), re.M) or fold_mutation(v) or re.search(SIM_ROW, txt(v), re.M))


# ----------------------------------------------------------------- conditions
@case(A)
def conditions_have_a_tag_and_neither_variant_nor_verdict():
    with ko() as v:
        str_condition(v)
        t = txt(v)
        check('Tag: none' in t and 'choose one' not in t, t[-300:])
        check('Type: ?' in t, 'no Type cell beside the Tag cell: %r' % t[-300:])
        check('Verdict' not in t, 'old columns still drawn: %r' % t[-300:])
        check('Matchers: 1' in t)


@case(A)
def tag_is_chosen_from_the_syndromes_catalog_and_never_typed():
    with ko(grow=18) as v:
        str_condition(v)
        y = open_tag_chooser(v)
        check(v.has('no syndromes: add one in Manage > Syndromes'), 'an empty catalog is not said: %r' % unit_list(v, y))
        add_syndromes(v, 'command-and-control', 'execute-memory', 'network-flood')
        y = open_tag_chooser(v)
        rows = unit_list(v, y)
        t = '\n'.join(rows)
        for tag in ('command-and-control', 'execute-memory', 'network-flood'):
            check(tag in t, '%s is not offered: %r' % (tag, rows))
        check('(none)' in t, 'no way to say "no tag"')
        check('Mirai-flood' not in t, 'the owner\'s saved tag leaked into the harness catalog: %r' % rows)
        for tag in ('command-and-control', 'execute-memory', 'network-flood'):
            check(any(re.search(r'%s\s*(\[x\])?$' % tag, r) for r in rows), 'the tag list shows more than the name %s: %r' % (tag, rows))
        v.type('zzz')                         # typing makes no tag
        v.esc()
        check('Tag: none' in txt(v), 'a tag appeared from nothing')
        pick_tag(v, 'network-flood')
        check('Tag: network-flood' in txt(v), txt(v)[-200:])
        pick_tag(v, 'execute-memory')
        check('Tag: execute-memory' in txt(v), txt(v)[-200:])
        pick_tag(v, '(none)')
        check('Tag: none' in txt(v), txt(v)[-200:])


@case(A)
def a_condition_names_only_string_matchers_and_the_blocks_tab_has_none():
    with ko(grow=18) as v:
        str_condition(v)                       # a Patterns condition over a find_str
        open_tab(v, 'Blocks')
        tick_blocks(v, 1)
        fold_mutation(v)
        t = txt(v)
        check('Matchers: 1' not in t and '[+ Condition]' not in t and ' Conditions' not in t,
              'the Blocks tab draws a condition: %r' % t[-300:])
        open_tab(v, 'Patterns')
        t = txt(v)
        check(len(re.findall(r'Matchers: 1\b', t)) == 1 and t.count('[+ Condition]') == 1, t[-300:])
        y = [y for y in panel(v) if 'Matchers: 1' in v.row(y)][0]
        click_in_panel(v, '[+ Condition]')
        y = [y for y in panel(v) if 'Matchers: None' in v.row(y)][0]
        v.click(v.row(y).index('[+ Matcher]') + 3, y)
        check(v.has('find_str', rows=(y, y + 4)) and not v.has('find_sim', rows=(y, y + 4)),
              'condition menu: %r' % [v.row(yy)[:60] for yy in range(y, y + 4)])
        v.esc()


# ------------------------------------------------------------------- the output
def two_conditions(v, tag2='network-flood'):
    """Family mirai, two string conditions: the first tagged Botnet, the second
    with `tag2`."""
    add_syndromes(v, 'command-and-control', 'execute-memory', 'network-flood')
    set_family(v, 'Mirai')
    set_variant(v, 'Mirai_A')                  # one type, Botnet: every unit takes it
    str_condition(v)
    click_in_panel(v, '[+ Condition]')
    y = [y for y in panel(v) if 'Matchers: None' in v.row(y)][0]
    v.click(v.row(y).index('[+ Matcher]') + 3, y)
    p = v.find('find_str', rows=(y, y + 5))
    v.click(*p)
    pick_tag(v, 'network-flood', 0)
    pick_tag(v, tag2, 1)


# The source a string-matcher condition over "GCC: (Debian" writes, spelled out here as the oracle (the unit tests pin the writer; this pins what
# the panel hands it): the catalog lines, the range and the string, the matcher and the expression.
GEN_COND = (
    'KOF_DIAG_NAME(%s);\n'
    'KOF_TARGET_FORMAT(KOF_FMT_ELF);\n'
    'KOF_DIAG_FAMILY("Mirai");\n'
    'KOF_DIAG_VARIANT("A");\n'
    'KOF_DIAG_TYPE(KOF_MALTYPE_BOTNET);\n'
    'KOF_DIAG_TAG("network-flood");\n'
    'KOF_TARGET_RANGE(r0, KOF_SCAN_ALL);\n'
    'KOF_DEFINE_STR(s0, "GCC: (Debian", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n'
    'KOF_DIAG_FIND(m1, KOF_FIND_ALL, r0, s0);\n'
    'KOF_DIAG_EXPR(m1);\n')


@case(A)
def generate_writes_one_source_per_condition_with_its_matchers_and_lists_them():
    """MERGED 53: a diagnose now holds the string matcher (KDIG_SEC_FORM), so Generate writes the units instead of refusing them."""
    with ko(grow=22) as v:
        two_conditions(v)
        click_in_panel(v, '[ Save ]')
        t = txt(v)
        dd = os.path.join(BASES_COPY, 'diagnoses')
        check('Output -' not in t, 'the owner never asked for an output pane: %r' % t[-400:])
        check(('Wrote 2 files to %s' % dd) in status(v), 'status: %r' % status(v)[-160:])
        eq(sorted(os.listdir(dd)), ['botnet_mirai_network-flood_01.c', 'botnet_mirai_network-flood_02.c'], 'the files Generate wrote')
        for f in sorted(os.listdir(dd)):
            with open(os.path.join(dd, f)) as fh:
                src = fh.read()          # the header comment is pinned by the block-matcher case below
                eq(src[src.index('KOF_DIAG_NAME'):], GEN_COND % f[:-2], 'the text of %s' % f)
        # never written twice: the same draft again finds both diagnoses in the tree and writes nothing more
        click_in_panel(v, '[ Save ]')
        check('Nothing new to write' in status(v), 'a second Generate: %r' % status(v)[-160:])
        eq(len(os.listdir(dd)), 2, 'a second Generate wrote files')
        # saved is saved: the draft holds nothing to lose, so Rebuild and the file steps are not
        # refused with "Finish or undo the draft first" (it said so after "Wrote 6 files")
        v.menu_item('Manage', 'Rebuild database')
        check('Finish or undo' not in status(v), 'Rebuild after Generate: %r' % status(v)[-100:])


def save_cell(v):
    """The colour of the [ Save ] cell of the draft head, as (fg, bg)."""
    x, y = v.find('[ Save ]')
    c = v.cell(x + 2, y)
    return (c.fg, c.bg)


@case(A)
def save_is_not_gated_on_a_unit_and_draft_generate_alone_answers():
    """Owner 2026-10-31: Save was disabled with no block/pattern chosen - the old design. No gate on the button or in the click:
    draft_generate decides, and with no unit it says so itself ("Nothing to write"). Old tests missed it: (c) the empty-draft
    case only checked that SOME text came back, never whose text or the button's state."""
    with ko() as v:
        for step in ('empty draft', 'family and variant, no unit'):
            if step != 'empty draft':
                set_family(v, 'Mirai')
                set_variant(v, 'Mirai_A')
            check(save_cell(v) == ('black', 'green'), '%s: Save must wear the colour of an enabled button: %r' % (step, save_cell(v)))
            click_in_panel(v, '[ Save ]')
            s = status(v)
            check('Nothing to write' in s, '%s: the refusal must be draft_generate\'s own: %r' % (step, s[-160:]))
            check('Add a condition' not in s,
                  '%s: the viewer\'s own gate answered: %r' % (step, s[-160:]))
            eq(os.listdir(os.path.join(BASES_COPY, 'diagnoses')), [], '%s: a refused Save wrote a file' % step)


@case(A)
def output_names_follow_the_tag_and_say_what_is_missing():
    with ko(grow=22) as v:
        str_condition(v)
        click_in_panel(v, '[ Save ]')
        click_in_panel(v, '[ Save ]')
        add_syndromes(v, 'execute-memory')
        set_family(v, 'Gafgyt')                  # Gafgyt_A is its only variant: selected, two types
        pick_tag(v, 'execute-memory')
        click_in_panel(v, '[ Save ]')
        check('no type' in status(v), 'a unit without a type is refused: %r' % status(v)[-80:])
        eq(os.listdir(os.path.join(BASES_COPY, 'diagnoses')), [], 'a refused draft wrote a file')
        click_in_panel(v, '[ Save ]')
        pick_unit_cell(v, 'Type:', 'Exploit')
        click_in_panel(v, '[ Save ]')
        # the name is the unit's own type, the header's family and the unit's tag
        eq(os.listdir(os.path.join(BASES_COPY, 'diagnoses')), ['exploit_gafgyt_execute-memory_01.c'], 'the file the second Save wrote')


@case(A)
def output_lists_each_block_matcher_as_its_own_unit_with_hash_and_threshold():
    with ko(grow=22) as v:
        add_syndromes(v, 'execute-memory')
        set_family(v, 'Zeus')
        open_tab(v, 'Blocks')
        h = tick_blocks(v, 1)[0]
        fold_mutation(v)
        pick_tag(v, 'execute-memory')          # the matcher's own Tag cell: no condition is needed
        click_in_panel(v, '[ Save ]')
        t = txt(v)
        dd = os.path.join(BASES_COPY, 'diagnoses')
        check(('Wrote 1 file to %s' % dd) in status(v), 'status: %r' % status(v)[-160:])
        eq(os.listdir(dd), ['trojan_zeus_execute-memory_01.c'], 'the file Generate wrote')
        with open(os.path.join(dd, 'trojan_zeus_execute-memory_01.c')) as fh:
            src = fh.read()
        # the header comment: the sample's file name and its sha256 (an independent hash of the file), the engine's numbers, no researcher
        sample = SAMPLES['ko']
        with open(sample, 'rb') as sf:
            digest = hashlib.sha256(sf.read()).hexdigest()
        check(src.startswith('/*\n * Generated by KOFViewer.\n *\n * Test sample: %s  sha256:%s\n * Created ' % (os.path.basename(sample), digest)), src[:300])
        check(re.search(r' \* Created (\d{4}-\d\d-\d\d), updated \1\n \* Engine:      db format \d+\.\d+, module ABI \d+\n \*/\n\nKOF_DIAG_NAME', src) and 'Researcher' not in src, src[:400])
        src = src[src.index('KOF_DIAG_NAME'):]
        check(src.startswith('KOF_DIAG_NAME(trojan_zeus_execute-memory_01);\nKOF_TARGET_FORMAT(KOF_FMT_ELF);\n'
                             'KOF_DIAG_FAMILY("Zeus");\nKOF_DIAG_VARIANT("A");\nKOF_DIAG_TYPE(KOF_MALTYPE_TROJAN);\n'
                             'KOF_DIAG_TAG("execute-memory");\nKOF_MUTATION_BLOCK(b0, KOF_SCAN_ELF_DATA, '), src[:400])
        check(src.endswith(');\nKOF_DIAG_SIMILAR(m1, 70, b0);\n'), src[-120:])


@case(A)
def each_condition_has_its_own_tag_and_its_own_file_name():
    with ko(grow=22) as v:
        two_conditions(v, 'command-and-control')
        t = txt(v)
        check('Tag: network-flood' in t and 'Tag: command-and-control' in t,
              'the two tags are not both on screen: %r' % t[-300:])
        click_in_panel(v, '[ Save ]')
        eq(sorted(os.listdir(os.path.join(BASES_COPY, 'diagnoses'))), ['botnet_mirai_command-and-control_01.c', 'botnet_mirai_network-flood_01.c'],
           'one file per condition, each from its own tag')


@case(A)
def a_unit_whose_type_the_new_variant_lacks_goes_back_to_a_question_mark():
    with ko(grow=22) as v:
        two_conditions(v, 'command-and-control')
        t = txt(v)
        check(t.count('Type: Botnet') == 2, 'one-type variant did not fill every unit: %r' % t[-300:])
        set_family(v, 'Mirai')                   # the same family: the variant stays
        check(txt(v).count('Type: Botnet') == 2, 'choosing the same family changed the units')
        set_family(v, 'Zeus')                    # another family: the variant goes, its only variant is taken (Trojan)
        t = txt(v)
        check('Variant [ A ]' in head(v) and t.count('Type: Trojan') == 2, 'Zeus_A: %r %r' % (head(v), t[-300:]))
        check('Tag: network-flood' in t and 'Tag: command-and-control' in t, 'a tag changed with the header: %r' % t[-300:])
        set_family(v, 'Mirai')                   # another family clears the variant; two variants: none is taken
        check('Variant [ ? ]' in head(v) and txt(v).count('Type: ?') == 2, '%r %r' % (head(v), txt(v)[-300:]))
        click_in_panel(v, '[ Save ]')
        eq(os.listdir(os.path.join(BASES_COPY, 'diagnoses')), [], 'units with no type: a refused draft wrote a file')


@case(A)
def a_variant_deleted_in_the_pathogens_dialog_keeps_the_units_types_and_shows_its_name_red():
    """GEN-2: the draft keeps the variant's NAME; when the catalog loses it (Manage > Pathogens > Delete) the
    units' types are not reset to '?' and the header still names it (in red)."""
    with ko(grow=22) as v:
        two_conditions(v)
        set_family(v, 'Gafgyt')                  # Gafgyt_A: Botnet and Exploit
        pick_unit_cell(v, 'Type:', 'Exploit', 0)
        check('Type: Exploit' in txt(v), 'the unit did not take Exploit')
        check(v.menu_item('Manage', 'Pathogens'), 'no Pathogens item')
        v.pump_quiet()
        x, y = v.find('Gafgyt_A')
        v.click(x, y)
        v.pump_quiet()
        x, y = v.find('[ Delete ]')
        v.click(x, y)
        v.pump_quiet()
        check(not v.has('Botnet, Exploit'), 'the variant was not deleted')
        v.esc()
        v.pump_quiet()
        check('Type: Exploit' in txt(v), 'the unit lost its type when the variant was deleted: %r' % txt(v)[-300:])
        check('Variant [ Gafgyt_A ]' in head(v), 'the header lost the variant name: %r' % head(v)[:70])


@case(A)
def a_variant_with_two_types_offers_exactly_those_two_per_unit():
    with ko(grow=22) as v:
        two_conditions(v)
        set_family(v, 'Gafgyt')                  # Gafgyt_A: Botnet and Exploit
        check(txt(v).count('Type: Botnet') == 2, 'Botnet is a type of Gafgyt_A too, so the units keep it: %r' % txt(v)[-300:])
        y = open_unit_cell(v, 'Type:', 0)
        t = ' '.join(unit_list(v, y))
        check('Botnet' in t and 'Exploit' in t and not any(w in t for w in ('Trojan', 'Rootkit', 'Dropper', 'Virus', 'Miner')),
              'the list is not exactly the variant\'s two types: %r' % t)
        v.esc()
        pick_unit_cell(v, 'Type:', 'Exploit', 0)
        pick_unit_cell(v, 'Type:', 'Botnet', 1)
        t = txt(v)
        check('Type: Exploit' in t and 'Type: Botnet' in t, t[-300:])
        click_in_panel(v, '[ Save ]')
        eq(sorted(os.listdir(os.path.join(BASES_COPY, 'diagnoses'))), ['botnet_gafgyt_network-flood_01.c', 'exploit_gafgyt_network-flood_01.c'],
           'each unit names itself from its own type')


@case(A)
def variant_is_greyed_until_a_family_is_chosen_and_lists_only_its_variants():
    with ko() as v:
        r = head(v)
        check('Family [ ? ]' in r and 'Variant [ ? ]' in r, r[:70])
        p = prow(v, 'Variant [')
        v.click(p[0], p[1])
        check(not v.has('Mirai_A') and not v.has('Zeus_A'), 'a greyed Variant opened a list')
        set_family(v, 'Mirai')
        click_in_panel(v, 'Variant [')
        check(v.has('Mirai_A') and v.has('Mirai_B') and not v.has('Botnet'), 'the variant list shows the names only')
        check(not v.has('Zeus_A') and not v.has('Gafgyt_A'), 'another family\'s variants are listed')
        pick_menu_item(v, 'Mirai_B', rows=(grip(v) + 2, v.rows))
        check('Variant [ B ]' in head(v), head(v)[:70])


@case(A)
def type_is_greyed_with_no_variant_and_does_not_open():
    with ko(grow=22) as v:
        str_condition(v)
        p = prow_scroll(v, 'Type: ?')
        v.click(p[0] + 3, p[1])
        check(not v.has('Botnet', rows=(p[1] + 1, v.rows)) and not v.has('Trojan', rows=(p[1] + 1, v.rows)),
              'a greyed Type cell opened a list')


@case(A)
def an_empty_family_leaves_no_doubled_underscore_in_the_name():
    with ko(grow=22) as v:
        str_condition(v)
        add_syndromes(v, 'execute-memory')
        pick_tag(v, 'execute-memory')
        click_in_panel(v, '[ Save ]')
        eq(os.listdir(os.path.join(BASES_COPY, 'diagnoses')), [], 'a unit with no type and no family: a refused draft wrote a file')


@case(A)
def matchers_are_numbered_per_tab_and_a_tab_switch_renumbers_nothing():
    with two(grow=18) as v:
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
        click_in_panel(v, '[ Save ]')
        check('Output -' not in txt(v))
        check('condition' in status(v).lower() and 'block matcher' in status(v).lower(), 'status: %r' % status(v)[-70:])


@case(A)
def generate_writes_only_inside_the_diagnoses_directory_and_nothing_when_refused():
    fresh_bases()
    tmp0 = set(glob.glob('/tmp/kof_draft_src_*'))
    before = set(glob.glob(os.path.join(BASES_COPY, '**', '*.c'), recursive=True))
    with ko(grow=22) as v:
        str_condition(v)                 # no family, no type, no tag: a gap, and the whole draft is refused
        click_in_panel(v, '[ Save ]')
        check('Not written: condition 1 the header has no family' in status(v), 'a draft with a gap was not refused: %r' % status(v)[-120:])
        v.pump(0.5)
    after = set(glob.glob(os.path.join(BASES_COPY, '**', '*.c'), recursive=True))
    eq(sorted(after - before), [], 'files written by a refused Generate')
    with ko(grow=22) as v:
        two_conditions(v)
        click_in_panel(v, '[ Save ]')
        check('Wrote 2 files' in status(v), status(v)[-160:])
        v.pump(0.5)
    after = set(glob.glob(os.path.join(BASES_COPY, '**', '*.c'), recursive=True))
    dd = os.path.join(BASES_COPY, 'diagnoses')
    eq(sorted(after - before), [os.path.join(dd, 'botnet_mirai_network-flood_01.c'), os.path.join(dd, 'botnet_mirai_network-flood_02.c')],
       'Generate wrote outside <bases>/diagnoses or not exactly the two units')
    eq(sorted(set(glob.glob('/tmp/kof_draft_src_*')) - tmp0), [], 'scratch source left in /tmp')


@case(A)
def generate_refuses_a_draft_with_no_type_or_tag_and_writes_nothing():
    with ko(grow=22) as v:
        add_syndromes(v, 'network-flood')
        set_family(v, 'Mirai')
        set_variant(v, 'Mirai_A')
        str_condition(v)
        click_in_panel(v, '[ Save ]')
        check('no tag' in status(v) or 'no type' in status(v), 'status: %r' % status(v)[-80:])
        eq(os.listdir(os.path.join(BASES_COPY, 'diagnoses')), [], 'a refused draft wrote a file')


@case(A)
def discard_takes_the_output_away():
    with ko(grow=22) as v:
        two_conditions(v)
        click_in_panel(v, '[ Save ]')
        click_in_panel(v, '[ Discard ]')
        check('Output -' not in txt(v))


# ------------------------------------------------------------------- the units: Type and Tag once each
def unit_rows(v):
    """(matcher rows, condition rows) of the open tab as screen text: a matcher is its Blocks matcher row and the row under it (Type, Tag), the
    condition rows the ones with a Type: cell and no matcher row."""
    m = [v.row(y) + '\n' + v.row(y + 1) for y in panel(v) if re.match(SIM_ROW, v.row(y))]
    c = [v.row(y) for y in panel(v) if re.match(r'\s+Type:', v.row(y))]
    return m, c


@case(A)
def blocks_matcher_is_a_unit_with_its_own_type_and_tag_and_there_is_no_condition():
    with two(grow=22) as v:
        add_syndromes(v, 'command-and-control', 'execute-memory', 'network-flood')
        set_family(v, 'Mirai')
        set_variant(v, 'Mirai_A')
        open_tab(v, 'Blocks')
        tick_blocks(v, 2)
        fold_mutation(v)
        m, c = unit_rows(v)
        check(len(m) == 2 and all('Type: Botnet' in r and 'Tag: none' in r for r in m), 'matchers: %r' % m)
        eq(c, [], 'a Type/Tag row of a condition on the Blocks tab')
        eq(txt(v).count('Tag:'), 2, 'Type/Tag cells once per unit')
        check('[+ Condition]' not in txt(v) and ' Conditions' not in txt(v), 'a Conditions area on the Blocks tab')
        pick_tag(v, 'network-flood', 0)
        pick_tag(v, 'execute-memory', 1)
        m, c = unit_rows(v)
        check('Tag: network-flood' in m[0] and 'Tag: execute-memory' in m[1], 'each matcher has its own tag: %r' % m)
        # removing the first matcher (unticking its block) keeps the other one's own tag and type
        y = [y for y in panel(v) if re.match(r'\s+\[x\]\s+0x', v.row(y))][0]
        v.click(v.row(y).index('[x]') + 2, y)
        m, c = unit_rows(v)
        check(len(m) == 1 and 'Tag: execute-memory' in m[0] and 'Type: Botnet' in m[0], 'the survivor lost its pair: %r' % m)
        # Graphs: no unit cells there
        open_tab(v, 'Graphs')
        check(not any('find_' in v.row(y) and ('Type:' in v.row(y) or 'Tag:' in v.row(y)) for y in panel(v)), 'Graphs')


def sim_pairs(v):
    """[(screen row y, the matcher row, the row under it)] of the `find_sim` matchers on the screen."""
    return [(y, v.row(y), v.row(y + 1)) for y in panel(v) if re.match(SIM_ROW, v.row(y))]


@case(A)
def block_matcher_hash_is_bare_and_type_and_tag_are_on_an_indented_row_under_it():
    """Owner 2026-10-31: no `#` before the hash; Type and Tag on their own indented line. REQUIRED: the hash right after the word, the
    threshold and the comment on the first row, `Type:` and `Tag:` on the next row, indented, with the same indent as a condition's. FORBIDDEN:
    `# hash`, `Type:` or `Tag:` on the first row. A Patterns condition keeps its own Type/Tag row (the same cells, one drawing function)."""
    with two(grow=22) as v:
        add_syndromes(v, 'network-flood')
        set_family(v, 'Mirai')
        set_variant(v, 'Mirai_A')
        open_tab(v, 'Blocks')
        h1, h2 = tick_blocks(v, 2)
        fold_mutation(v)
        pairs = sim_pairs(v)
        check(len(pairs) >= 2, 'two matchers')
        for h in (h1, h2):
            y, a, b = [pr for pr in pairs if re.match(r'\s+\d+\.\s+(?:\S+: )?%s\s' % h, pr[1])][0]
            check(re.match(r'\s+\d+\.\s+(?:\S+: )?%s\s' % h, a), 'the hash is not right after the name: %r' % a)
            check('find_sim' not in a, 'the word find_sim is printed: %r' % a)
            check('#' not in a and 'hash' not in a, 'the first row still labels the hash: %r' % a)
            check('Threshold: >= [ 70]%' in a and '[comment...]' in a, a)
            check('Type:' not in a and 'Tag:' not in a, 'Type/Tag on the first row: %r' % a)
            check(re.match(r'^ {7}Type: Botnet {3}Tag: none\s*$', b), 'the second row is not the indented Type/Tag row: %r' % b)
        # the rows are consecutive: matcher 2 starts right under matcher 1's Type/Tag row
        eq([pairs[i + 1][0] - pairs[i][0] for i in range(len(pairs) - 1)], [2] * (len(pairs) - 1), 'a matcher takes two rows')
        eq(txt(v).count('Tag:'), len(pairs), 'one Tag cell per unit')


@case(A)
def clicks_on_type_and_tag_work_on_the_new_row_and_the_first_row_has_no_unit_zone():
    with two(grow=22) as v:
        add_syndromes(v, 'network-flood', 'execute-memory')
        set_family(v, 'Mirai')
        set_variant(v, 'Mirai_A')
        open_tab(v, 'Blocks')
        tick_blocks(v, 2)
        fold_mutation(v)
        pairs = sim_pairs(v)
        y2 = pairs[1][0] + 1
        # Type of the second matcher: its list opens from the second matcher's second row
        yc = open_unit_cell(v, 'Type:', 1)
        eq(yc, y2, 'the cell the click found is on the second matcher\'s own second row')
        check(find_near(v, yc, 'Botnet'), 'the Type list did not open: %r' % unit_list(v, yc))
        v.key('escape')
        # Tag of the first matcher
        pick_tag(v, 'network-flood', 0)
        pick_tag(v, 'execute-memory', 1)
        pairs = sim_pairs(v)
        check('Tag: network-flood' in pairs[0][2] and 'Tag: execute-memory' in pairs[1][2], 'tags landed on the wrong matcher: %r' % pairs)
        # a press on the blank part of the Type/Tag row (left of the cells) opens nothing and changes nothing
        v.click(3, pairs[0][0] + 1)
        eq([p[2] for p in sim_pairs(v)], [p[2] for p in pairs], 'a press on the indent changed the row')


@case(A)
def patterns_condition_is_a_unit_with_one_type_and_tag_cell_and_its_matchers_have_none():
    with ko(grow=22) as v:
        two_conditions(v)
        t = txt(v)
        eq(t.count('Tag:'), 2, 'Type/Tag cells once per condition')
        eq(t.count('Type:'), 2)
        check(not any(re.match(r'\s+\d+\.\s+find_str', v.row(y)) and ('Type:' in v.row(y) or 'Tag:' in v.row(y))
                      for y in panel(v)), 'a string matcher carries a cell')
        check(t.count('[+ Condition]') == 1)


@case(A)
def a_block_matcher_carries_its_own_tag_and_its_own_file():
    """Two standalone block matchers: each has its own Tag cell and its own file name; one without a tag is listed with `<tag>` in its
    name and refuses the whole draft (nothing is written). The tags come from the Syndromes catalog (Manage > Syndromes), as the unit's Tag
    list does since MERGED 40."""
    fresh_bases()                                   # Generate writes into <bases>/diagnoses: start from an empty one
    with data_cat(rows=60, cols=150, grow=22) as v:
        add_syndromes(v, 'network-flood')
        set_family(v, 'Zeus')                       # Zeus_A: one type, Trojan, which both units take
        open_tab(v, 'Blocks')
        h1, h2 = tick_blocks(v, 2)
        fold_mutation(v)
        t = txt(v)
        eq(t.count('Tag: none'), 2, 'each standalone matcher has a Tag cell: %s' % t[-400:])
        # pick the first matcher's tag
        y = [yy for yy in panel(v) if re.match(SIM_ROW, v.row(yy)) and h1 in v.row(yy)][0]
        pick_tag(v, 'network-flood', 0)
        check('Tag: network-flood' in v.row(y + 1), v.row(y + 1))
        # the second matcher is a unit too, with its own cells; there is no condition on this tab
        check('[+ Condition]' not in txt(v), 'a condition button on the Blocks tab')
        click_in_panel(v, '[ Save ]')
        t = txt(v)
        check('Not written: block matcher 2 it has no tag' in status(v), 'status: %r' % status(v)[-120:])
        eq(os.listdir(os.path.join(BASES_COPY, 'diagnoses')), [], 'a refused draft wrote a file')
        # tagging the second matcher lets the draft through: two files, each from its own tag
        pick_tag(v, 'network-flood', 1)
        click_in_panel(v, '[ Save ]')
        eq(sorted(os.listdir(os.path.join(BASES_COPY, 'diagnoses'))),
           ['trojan_zeus_network-flood_01.c', 'trojan_zeus_network-flood_02.c'], 'one file per matcher')


if __name__ == '__main__':
    main(A)
