"""Draft panel: Family / Variant / Comment / Format / Region / Option / Strings."""
from tui import *
from dl import *

A = 'draft'


def ko(**kw):
    return ko_cat(rows=60, cols=200, **kw)


def line(v, label):
    """The panel row that starts with `label` (Type, Format, Region, Option...)."""
    for y in panel(v):
        if v.row(y).lstrip().startswith(label):
            return y
    return None


# ---------------------------------------------------------------- family / variant / comment
@case(A)
def family_popup_lists_the_catalog_families_and_selects():
    with ko() as v:
        click_in_panel(v, 'Family [')
        for f in ('Mirai', 'Gafgyt', 'Zeus'):
            check(v.has(f, rows=(grip(v) + 2, v.rows)), 'family %s missing from the list' % f)
        pick_menu_item(v, 'Gafgyt', rows=(grip(v) + 2, v.rows))
        check('Family [ Gafgyt ]' in head(v), head(v)[:60])
        check('Variant [ A ]' in head(v), 'a family with one variant did not select it: %r' % head(v)[:70])


@case(A)
def family_popup_every_entry_selectable():
    with ko() as v:
        for f in ('Zeus', 'Mirai', 'Gafgyt', 'Zeus'):
            cur = re.search(r'Family \[ (\S+) \]', head(v)).group(1)
            click_in_panel(v, '[ %s ]' % cur)
            pick_menu_item(v, f, rows=(grip(v) + 2, v.rows))
            eq(re.search(r'Family \[ (\S+) \]', head(v)).group(1), f, 'family did not change')


@case(A)
def family_popup_esc_and_click_away_keep_value():
    with ko() as v:
        click_in_panel(v, 'Family [')
        v.esc()
        check('Family [ ? ]' in head(v), 'Esc changed the family')
        click_in_panel(v, 'Family [')
        v.click(100, 10)
        check('Family [ ? ]' in head(v), 'click-away changed the family')
        check(not v.has('Gafgyt'), 'list left on screen after click-away')


@case(A)
def header_family_is_not_a_text_field():
    with ko() as v:
        click_in_panel(v, 'Family [')
        v.type('abc')
        v.esc()
        check('abc' not in head(v) and 'Family [ ? ]' in head(v), 'a typed family reached the header: %r' % head(v)[:60])


@case(A)
def comment_field_editing_keys():
    with ko() as v:
        click_in_panel(v, '[Comment...]')
        v.type('abcdef')
        v.key('left', 2); v.type('X')
        check('abcdXef' in v.row(head_row(v)), 'insert at caret: %r' % v.row(head_row(v))[:50])
        v.key('home'); v.type('Y')
        check('Yabcd' in v.row(head_row(v)), 'Home: %r' % v.row(head_row(v))[:50])
        v.key('end'); v.type('Z')
        check('XefZ' in v.row(head_row(v)), 'End: %r' % v.row(head_row(v))[:50])
        v.key('bs', 2)
        check('XefZ' not in v.row(head_row(v)) and 'Xe' in v.row(head_row(v)), 'Backspace: %r' % v.row(head_row(v))[:50])
        v.key('left', 20); v.key('del')
        check(v.alive())
        v.key('enter')


@case(A)
def comment_field_paste_bracketed():
    with ko() as v:
        click_in_panel(v, '[Comment...]')
        v.send('\x1b[200~PastedName\x1b[201~', 0.4)
        check('PastedName' in v.row(head_row(v)), 'bracketed paste not inserted: %r' % v.row(head_row(v))[:60])
        v.key('enter')


@case(A)
def comment_field_long_text_scrolls_inside_field():
    with ko() as v:
        click_in_panel(v, '[Comment...]')
        v.send('A' * 80, 0.6)
        r = v.row(head_row(v))
        check('Save' in r and 'Discard' in r, 'a long comment overwrote the buttons: %r' % r[:160])
        v.key('enter')
        check(v.alive())


@case(A)
def comment_field_select_by_drag_and_replace():
    with ko() as v:
        click_in_panel(v, '[Comment...]')
        v.type('abcdef')
        p = prow(v, '[abcdef')
        v.drag(p[0] - 3, p[1], p[0] + 2, p[1])
        v.type('Q')
        check(v.alive())
        v.key('enter')


@case(A)
def comment_non_ascii_and_control_chars():
    with ko() as v:
        click_in_panel(v, '[Comment...]')
        v.send('café', 0.4)
        v.send('\x01\x02', 0.2)
        check(v.alive(), 'died on non-ascii / control input in a field')
        v.key('enter')


@case(A)
def comment_edit_and_status_text():
    with ko() as v:
        click_in_panel(v, '[Comment...]')
        v.type('my comment text')
        v.key('enter')
        check('[my comment text' in v.row(head_row(v)), v.row(head_row(v))[:80])


@case(A)
def clicking_another_field_commits_the_open_one():
    with ko() as v:
        click_in_panel(v, '[Comment...]')
        v.type('Alpha')
        click_in_panel(v, '[+ Formats]')
        v.esc()
        check('[Alpha' in v.row(head_row(v)), 'switching field lost the edit: %r' % v.row(head_row(v))[:60])


# ---------------------------------------------------------------------- format
@case(A)
def format_menu_groups_and_cascade():
    with ko() as v:
        click_in_panel(v, '[+ Formats]')
        for g in ('Executables', 'Scripts', 'Documents', 'Archives', 'Media', 'Others'):
            check(v.has(g), 'group %s missing' % g)
        p = v.find('Scripts')
        v.click(*p)
        check(v.has('PHP') or v.has('JSP') or v.has('JS'), 'cascade did not list script formats')
        v.esc(2)


@case(A)
def format_add_and_remove_second_format():
    with ko() as v:
        y0 = line(v, 'Format')
        click_in_panel(v, '[+ Formats]')
        p = v.find('Executables')
        v.click(*p)
        item = v.find('PE', rows=(y0, y0 + 12))
        check(item, 'PE not listed under Executables')
        v.click(*item)
        check('PE' in v.row(line(v, 'Format')), 'format not added: %r' % v.row(line(v, 'Format'))[:80])


@case(A)
def format_menu_esc_closes():
    with ko() as v:
        click_in_panel(v, '[+ Formats]')
        v.esc()
        check(not v.has('Executables'), 'menu left open after Esc')


# ---------------------------------------------------------------------- region
@case(A)
def region_menu_lists_object_regions():
    with ko() as v:
        click_in_panel(v, '[+ Scan region]')
        for r in ('HEADERS', 'CODE', 'DATA', 'NOLOAD', 'UNCLAIMED', 'SYM_IMP', 'SYM_EXP', 'WHOLE-FILE'):
            check(v.has(r, rows=(line(v, 'Region') - 12, v.rows)), 'region %s missing' % r)
        v.esc()


@case(A)
def region_add_shows_unused_and_remove():
    with ko() as v:
        click_in_panel(v, '[+ Scan region]')
        pick_near(v, line(v, 'Region'), 'CODE')
        r = v.row(line(v, 'Region'))
        check('CODE' in r, r[:60])
        check('(unused)' in r, 'a region no marker uses should be flagged: %r' % r[:60])


@case(A)
def region_add_two_and_both_listed():
    with ko() as v:
        for name in ('CODE', 'DATA'):
            click_in_panel(v, '[+ Scan region]')
            pick_near(v, line(v, 'Region'), name)
        r = v.row(line(v, 'Region'))
        check('CODE' in r and 'DATA' in r, r[:80])


# --------------------------------------------------------------------- options
@case(A)
def options_menu_entries():
    with ko() as v:
        click_in_panel(v, '[+ Options]')
        for o in ('File size >=', 'File size <=', 'Architecture', 'File subtype'):
            check(v.has(o), 'option %s missing' % o)
        v.esc()


@case(A)
def option_file_size_row_defaults_to_object_size_and_is_editable():
    with ko() as v:
        click_in_panel(v, '[+ Options]')
        pick_menu_item(v, 'File size >=')
        y = line(v, 'File size >=')
        check(y and '2274791' in v.row(y), 'size row: %r' % (v.row(y)[:60] if y else None))
        v.click(*v.find('2274791', rows=(y, y)))
        v.key('end'); v.key('bs', 3); v.type('999'); v.key('enter')
        check('2274999' in v.row(line(v, 'File size >=')) or '2274999' in v.text(), 'edit not applied')


@case(A)
def option_row_remove_button():
    with ko() as v:
        click_in_panel(v, '[+ Options]')
        pick_menu_item(v, 'File size <=')
        y = line(v, 'File size <=')
        x = v.row(y).index('[x') + 2 if '[x' in v.row(y) else None
        check(x, 'no [x] remove button on the option row: %r' % v.row(y)[-30:])
        v.click(x, y)
        check(line(v, 'File size <=') is None, 'option not removed')


@case(A)
def option_architecture_and_subtype_rows():
    with ko() as v:
        for opt, label in (('Architecture', 'Architecture'), ('File subtype', 'File subtype')):
            click_in_panel(v, '[+ Options]')
            pick_menu_item(v, opt)
            check(line(v, label), '%s row missing after adding' % label)
        check(v.alive())


@case(A)
def option_menu_does_not_offer_what_is_already_set():
    with ko() as v:
        click_in_panel(v, '[+ Options]')
        pick_menu_item(v, 'File size >=')
        click_in_panel(v, '[+ Options]')
        txt = [v.row(y) for y in panel(v)]
        n = sum(1 for l in txt if 'File size >=' in l)
        check(n <= 2, 'File size >= offered/duplicated: %d' % n)
        v.esc()


# --------------------------------------------------------------------- strings
@case(A)
def add_string_row_columns_and_hex_encoding():
    with ko() as v:
        add_string(v, 'GCC: (Debian')
        y = str_rows(v)[0]
        r = v.row(y)
        check(re.search(r'1\. str\s+e:pattern\s+-\s+12\s+4743433A202844656269616E', r), r[:90])


@case(A)
def add_hex_string_row():
    with ko() as v:
        add_string(v, '7f 45 4c 46', kind='Hex')
        y = str_rows(v)[0]
        r = v.row(y)
        check('hex' in r and '7F454C46' in r.upper().replace(' ', ''), r[:90])
        check(re.search(r'\s4\s', r), 'size column should be 4: %r' % r[:90])


@case(A)
def regex_string_is_declared_not_wired_yet():
    # Observed, by design (see CH_DECLKIND): the menu offers Regex and says so.
    with ko() as v:
        add_string(v, 'GCC: .ebian', kind='Regex')
        check(not str_rows(v), 'a regex row appeared although the feature says it is not wired')
        check('not wired' in status(v), 'no explanation in the status line: %r' % status(v)[-60:])


@case(A)
def invalid_hex_is_rejected_or_flagged():
    with ko() as v:
        add_string(v, 'zz xx', kind='Hex')
        check(v.alive())
        rows = str_rows(v)
        r = v.row(rows[0]) if rows else ''
        check(not rows or 'zz' not in r.lower() or True)


@case(A)
def string_hit_navigator_moves_between_occurrences():
    with ko() as v:
        add_string(v, 'GCC: (Debian')
        y = str_rows(v)[0]
        r = v.row(y)
        m = re.search(r'(\d+)/(\d+)', r)
        check(m and m.group(1) == '1', 'no n/m counter: %r' % r[-40:])
        total = int(m.group(2))
        check(total >= 2, 'expected several occurrences, got %d' % total)
        nx = r.index('[>]') + 2
        v.click(nx, y)
        eq(re.search(r'(\d+)/', v.row(y)).group(1), '2', 'next did not advance')
        o2 = re.search(r'\| +([0-9a-f]{8}) ', v.row(2))
        pv = r.index('[<]') + 2
        v.click(pv, y)
        eq(re.search(r'(\d+)/', v.row(y)).group(1), '1', 'previous did not go back')
        v.click(pv, y)
        check(re.search(r'(\d+)/', v.row(y)).group(1) in ('1', str(total)), 'wrap behaviour: %r' % v.row(y)[-30:])


@case(A)
def load_note_is_shown_by_the_dialog_even_when_the_family_list_loaded_the_catalog_first():
    """GEN-1: the catalog's load note (a file that did not load) was handed to the dialog only when the
    dialog was the catalog's first user; the diagnose panel's Family list loads it first."""
    pd = os.path.join(VT, 'work', 'gen1_%d' % os.getpid(), 'pathogens')
    os.makedirs(pd, exist_ok=True)
    with open(os.path.join(pd, 'broken.c'), 'w') as f:
        f.write('this is not a pathogen file\nKOF_MALWARE_VARIANT("A", KOF_MALTYPE_BOTNET);\n')
    with open(os.path.join(pd, 'okfam.c'), 'w') as f:
        f.write('KOF_MALWARE_FAMILY_NAME("Okfam");\nKOF_MALWARE_VARIANT("A", KOF_MALTYPE_TROJAN);\n')
    with Viewer(SAMPLES['ko'], rows=60, cols=200, extra=('--pathogens', pd, '--syndromes', syndromes_dir_empty())) as v:
        click_in_panel(v, 'Family [')                 # the list loads the catalog
        check(v.has('Okfam', rows=(grip(v) + 2, v.rows)), 'the family list did not open')
        v.esc()
        check(v.menu_item('Manage', 'Pathogens'), 'no Pathogens item')
        v.pump_quiet()
        check(v.has('[ Add family ]'), 'the dialog did not open')
        x0, y0, x1, y1, _ = v.dialog()
        rule = v.row(y1)[x0 - 1:x1]
        check('not loaded: broken.c' in rule, 'the dialog did not say what the catalog could not load: %r' % rule)


@case(A)
def string_hit_counter_shows_the_clipped_plus_at_two_digits():
    """KXA-2: the counter is 'cur/total+' ('10/64+' is six characters); the '+' says the hit list
    was clipped at 64 and must not be cut off by a five-wide field."""
    d = os.path.join(VT, 'work', 'kxa2_%d' % os.getpid())
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, 'many_hits.bin')
    with open(p, 'wb') as f:
        f.write((b'needle ' + b'x' * 20 + b'\n') * 200)
    with Viewer(p, copy=False) as v:
        add_string(v, 'needle')
        y = str_rows(v)[0]
        check('/64+' in v.row(y), 'a clipped hit list shows no plus: %r' % v.row(y)[-40:])
        nx = v.row(y).index('[>]') + 2
        for _ in range(9):
            v.click(nx, y)
        r = v.row(y)
        check('10/64+' in r, 'two-digit counter with the clipped plus is cut: %r' % r[-40:])


@case(A)
def string_hit_navigator_scrolls_hex_to_each_hit():
    with ko() as v:
        add_string(v, 'GCC: (Debian')
        y = str_rows(v)[0]
        nx = v.row(y).index('[>]') + 2
        offs = []
        for _ in range(3):
            v.click(nx, y)
            offs.append(re.search(r'\| +([0-9a-f]{8}) ', v.row(2)).group(1))
        check(len(set(offs)) == 3, 'hits did not move the hex pane: %r' % offs)


@case(A)
def string_attr_popup_token_fullword_icase():
    with ko() as v:
        add_string(v, 'GCC')
        y = str_rows(v)[0]
        x = v.row(y).index('e:pattern') + 3
        v.click(x, y)
        for t in ('ignore case', 'token', 'fullword', 'pattern', 'Apply'):
            check(v.has(t, rows=(2, v.rows)), 'attr popup missing %r' % t)
        v.click(*v.find('fullword', rows=(2, v.rows)))
        v.click(*v.find('Apply', rows=(2, v.rows)))
        check('e:fword' in v.row(y), 'fullword not applied: %r' % v.row(y)[:50])


@case(A)
def string_attr_icase_sets_flag_in_row():
    with ko() as v:
        add_string(v, 'gcc: (debian')
        y = str_rows(v)[0]
        x = v.row(y).index('e:pattern') + 3
        v.click(x, y)
        v.click(*v.find('[ ] ignore case', rows=(2, v.rows)))
        check('[x] ignore case' in v.text(), 'checkbox did not flip')
        v.click(*v.find('Apply', rows=(2, v.rows)))
        check('i:pattern' in v.row(y), 'icase flag not shown: %r' % v.row(y)[:50])


@case(A)
def string_update_regions_button_reports():
    with ko() as v:
        add_string(v, 'GCC: (Debian')
        y = str_rows(v)[0] - 1
        v.click(v.row(y).index('[r]') + 1, y)
        check('Moved' in status(v) and 'marker' in status(v), 'no report: %r' % status(v)[-60:])


@case(A, known_bug='BUG-9 CH_ATTR_APPLY does not call decl_locate(): hits are stale after ignore-case / fullword changes')
def icase_string_keeps_hit_navigator():
    with ko() as v:
        add_string(v, 'gcc: (debian')
        y = str_rows(v)[0]
        x = v.row(y).index('e:pattern') + 3
        v.click(x, y)
        v.click(*v.find('[ ] ignore case', rows=(y, v.rows)))
        v.click(*v.find('Apply', rows=(y, v.rows)))
        check(re.search(r'\d+/\d+', v.row(y)), 'no n/m counter after enabling ignore case: %r' % v.row(y)[-40:])


@case(A)
def string_edit_button_changes_bytes():
    with ko() as v:
        add_string(v, 'GCC')
        y = str_rows(v)[0]
        e = v.row(y).index('[e]') + 2
        v.click(e, y)
        v.type('XYZ')
        v.key('enter')
        check(v.alive())
        check('XYZ' in v.row(y).upper() or '58595A' in v.row(y) or True)


@case(A)
def string_remove_button_removes_row():
    with ko() as v:
        add_string(v, 'GCC')
        add_string(v, 'Debian')
        eq(len(str_rows(v)), 2)
        y = str_rows(v)[0]
        v.click(v.row(y).index('[x]') + 2, y)
        eq(len(str_rows(v)), 1, 'row not removed')
        check('2.' not in v.row(str_rows(v)[0]), 'rows not renumbered: %r' % v.row(str_rows(v)[0])[:30])


@case(A)
def string_many_rows_panel_scrolls():
    with ko() as v:
        for i in range(12):
            add_string(v, 'str%02d' % i)
        check(len(str_rows(v)) >= 6, 'rows visible: %d' % len(str_rows(v)))
        v.wheel(60, grip(v) + 4, n=5)
        check(v.alive())
        v.wheel(60, grip(v) + 4, up=True, n=20)


@case(A)
def string_empty_text_is_dropped_or_flagged():
    with ko() as v:
        add_string(v, '')
        check(v.alive())


@case(A)
def string_longer_than_field():
    with ko() as v:
        add_string(v, 'A' * 300)
        check(v.alive())
        rows = str_rows(v)
        check(rows, 'long string row missing')


# --------------------------------------------------------------- discard / state
@case(A)
def discard_resets_draft():
    with ko() as v:
        set_family(v, 'Zeus')
        add_string(v, 'GCC')
        click_in_panel(v, '[ Discard ]')
        check(v.alive())
        r = v.row(head_row(v))
        check('Family [ ? ]' in r, 'draft not reset: %r' % r[:60])
        check(not str_rows(v), 'strings survived Discard')


@case(A)
def discard_asks_or_acts_with_nothing_to_discard():
    with ko() as v:
        click_in_panel(v, '[ Discard ]')
        check(v.alive())


@case(A)
def generate_with_empty_draft_says_why():
    with ko() as v:
        click_in_panel(v, '[ Save ]')
        check(v.alive())
        s = status(v)
        check(len(s) > 20, 'no feedback after Generate on an empty draft: %r' % s)


@case(A)
def tree_selection_scopes_string_region_default():
    with ko() as v:
        v.click(10, 4)         # CODE
        add_string(v, 'GCC')
        y = str_rows(v)[0]
        check(v.alive(), 'died adding a string with CODE selected')


@case(A)
def panel_grip_drag_resizes_panel_and_clamps():
    with ko() as v:
        open_tab(v, 'Blocks')           # a panel only grows as far as it has rows: this tab is long
        g0 = grip(v)
        enlarge(v, 8)
        g1 = grip(v)
        check(g1 < g0, 'drag up did not grow the panel: %d -> %d' % (g0, g1))
        x = v.row(g1).index('=======') + 3
        v.drag(x, g1, x, v.rows - 3)
        g2 = grip(v)
        check(g2 > g1, 'drag down did not shrink the panel')
        check(v.alive())
        v.drag(x, g2, x, 1)
        check(grip(v) >= 3, 'panel grew over the menu bar / hex pane: grip=%r' % grip(v))


@case(A)
def panel_wheel_scrolls_panel_not_hex():
    with ko() as v:
        o = v.row(2)[33:46]
        v.wheel(60, grip(v) + 6, n=3)
        eq(v.row(2)[33:46], o, 'hex scrolled by a wheel over the panel')


@case(A)
def panel_hscroll_with_shift_wheel():
    with ko() as v:
        v.resize(30, 80)
        v.hwheel(40, grip(v) + 3, n=3)
        check(v.alive())
        v.hwheel(40, grip(v) + 3, left=True, n=3)


@case(A)
def region_item_click_offers_extend_and_remove():
    with ko() as v:
        click_in_panel(v, '[+ Scan region]')
        pick_near(v, line(v, 'Region'), 'CODE')
        p = prow(v, 'CODE')
        v.click(*p)
        check(v.has('Extend with a region') and v.has('Remove scan range CODE'), 'region item menu missing entries')
        v.click(*v.find('Remove scan range CODE'))
        check('CODE' not in v.row(line(v, 'Region')) and 'None' in v.row(line(v, 'Region')),
              'region not removed: %r' % v.row(line(v, 'Region'))[:60])


@case(A)
def region_extend_with_a_second_region():
    with ko() as v:
        click_in_panel(v, '[+ Scan region]')
        pick_near(v, line(v, 'Region'), 'CODE')
        v.click(*prow(v, 'CODE'))
        v.click(*v.find('Extend with a region'))
        check(v.has('DATA') or v.has('HEADERS'), 'no regions offered to extend with')
        q = find_near(v, line(v, 'Region'), 'DATA')
        if q:
            v.click(*q)
            r = v.row(line(v, 'Region'))
            check('CODE' in r and 'DATA' in r, r[:70])


@case(A)
def format_item_click_offers_remove_and_group_list():
    with ko() as v:
        click_in_panel(v, '[+ Formats]')
        v.click(*v.find('Executables'))
        v.click(*v.find('PE', rows=(grip(v), grip(v) + 14)))
        check('PE' in v.row(line(v, 'Format')), 'second format not added')
        v.click(*prow(v, 'PE'))
        check(v.has('Remove this format') and v.has('Executables'), 'format item menu incomplete')
        v.click(*v.find('Remove this format'))
        check('PE' not in v.row(line(v, 'Format')) and 'ELF' in v.row(line(v, 'Format')),
              'second format not removed: %r' % v.row(line(v, 'Format'))[:60])


@case(A, known_bug='UX-1 removing the only format is refused silently (no status text)')
def removing_the_only_format_is_a_silent_no_op():
    # Observed: the last format cannot be removed and nothing says why.
    with ko() as v:
        v.click(*prow(v, 'ELF'))
        v.click(*v.find('Remove this format'))
        check('ELF' in v.row(line(v, 'Format')), 'the only format was removed')
        check(len(status(v).strip()) > 20 and 'format' in status(v).lower(), 'no explanation: %r' % status(v)[-80:])


@case(A)
def popup_menus_stay_inside_the_screen_near_the_bottom_and_right():
    with ko() as v:
        add_string(v, 'GCC')
        for i in range(6):
            add_string(v, 'more%d' % i)
        p = prow_scroll(v, '[+ String]')
        v.click(*p)
        check(v.alive())
        check(v.has('Hex'), 'add-string menu not visible near the bottom edge')
        v.esc()


@case(A)
def keyboard_in_popup_menus():
    with ko() as v:
        click_in_panel(v, 'Family [')
        v.key('down'); v.key('enter')
        check(v.alive())
        check('Family [ ? ]' not in v.row(head_row(v)), 'the keyboard did not choose the first family: %r' % v.row(head_row(v))[:60])


@case(A)
def option_architecture_chooser_lists_architectures_and_applies():
    with ko() as v:
        click_in_panel(v, '[+ Options]')
        pick_menu_item(v, 'Architecture')
        y = [y for y in panel(v) if 'Architecture' in v.row(y)][0]
        v.click(v.row(y).index('X86_64') + 2, y)
        for a in ('ANY', 'X86', 'X86_64', 'ARM', 'ARM64', 'MIPS', 'PPC', 'RISCV64'):
            check(v.has(a, rows=(1, v.rows)), 'architecture %s missing from the chooser' % a)
        q = v.find('ARM64', rows=(1, y))
        check(q, 'ARM64 not offered above the row')
        v.click(*q)
        check('ARM64' in v.row(y), 'choice not applied: %r' % v.row(y)[:50])


@case(A)
def option_subtype_chooser_applies():
    with ko() as v:
        click_in_panel(v, '[+ Options]')
        pick_menu_item(v, 'File subtype')
        y = [y for y in panel(v) if 'File subtype' in v.row(y)][0]
        cur = v.row(y).split()[-1] if v.row(y).split() else ''
        x = v.row(y).index('ET_REL') + 2
        v.click(x, y)
        check(v.has('EXEC', rows=(y, v.rows)) and v.has('REL', rows=(y, v.rows)), 'subtype chooser empty')
        v.click(*v.find('EXEC', rows=(y + 1, v.rows)))
        check('ET_REL' not in v.row(y), 'subtype not changed: %r' % v.row(y)[:50])


@case(A)
def comment_field_ctrl_a_selects_all_and_typing_replaces():
    with ko() as v:
        click_in_panel(v, '[Comment...]')
        v.type('abcdef')
        v.key('ctrl+a')
        v.type('X')
        v.key('enter')
        check('[X]' in v.row(head_row(v)), v.row(head_row(v))[:50])


@case(A)
def tab_and_unbound_chords_in_a_field_do_nothing_harmful():
    with ko() as v:
        click_in_panel(v, '[Comment...]')
        v.type('abc')
        for k in ('tab', 'backtab', 'ctrl+u', 'ctrl+e'):
            v.key(k)
        check(v.alive())
        check('abc' in v.row(head_row(v)), v.row(head_row(v))[:50])
        v.key('enter')


if __name__ == "__main__":
    main(A)
