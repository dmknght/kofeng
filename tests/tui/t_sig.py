"""File > Next File / Previous File with and without a draft, and quitting with one.
Nothing here presses Generate: the draft is only written by that button, which
writes diagnose sources into <bases>/diagnoses (t_diagnose.py)."""
import glob
import subprocess, shutil
from tui import *
from dl import *

A = 'sig'


def ko(**kw):
    return Viewer(SAMPLES['ko'], rows=70, cols=220, **kw)


# ------------------------------------------------------------ switching with a draft
@case(A)
def navigation_blocked_with_unsaved_new_draft():
    fresh_bases()
    fs = prep_dir('sig_dirty', [(FIX('tiny.bin'), 'a_x'), (FIX('plain.txt'), 'b_x')])
    with Viewer(fs[0], rows=70, cols=200, copy=False) as v:
        click_in_panel(v, '[Comment...]'); v.type('abc'); v.key('enter')
        v.menu_open('File')
        n = v.popup_item('Next File')
        check(n and not n[3], 'Next enabled with an edited blank draft: %r' % (n,))
        v.esc()
        v.key('ctrl+\\')
        check('Finish or undo the draft first' in status(v), 'no explanation: %r' % status(v)[-80:])


@case(A, known_bug='BUG-17 (same cause) Ctrl+\\ / Ctrl+] with a dirty draft say nothing unless the draft panel has focus')
def navigation_chord_refusal_is_visible_from_the_tree():
    fresh_bases()
    fs = prep_dir('sig_dirty2', [(FIX('tiny.bin'), 'a_x'), (FIX('plain.txt'), 'b_x')])
    with Viewer(fs[0], rows=70, cols=200, copy=False) as v:
        click_in_panel(v, '[Comment...]'); v.type('abc'); v.key('enter')
        v.click(10, 2)                                  # focus the tree
        v.key('ctrl+\\')
        check('Finish or undo the draft first' in v.text(), 'silent refusal: %r' % v.row(v.rows)[-70:])


@case(A)
def navigation_resets_draft_for_new_file():
    fresh_bases()
    others = pick(SAMPLES['elf255'], 2, 5000, 80000)
    fs = prep_dir('sig_reset', [(others[0], 'a_x'), (others[1], 'b_x')])
    with Viewer(fs[0], rows=70, cols=200, copy=False) as v:
        v.menu_item('File', 'Next File')
        r = v.row(head_row(v))
        check('Family [' in r and 'Variant [' in r, r[:60])
        check(v.alive())


@case(A)
def quit_with_unsaved_draft_exits_without_confirmation():
    # Observed: no "discard changes?" - recorded so a change is noticed.
    fresh_bases()
    with ko() as v:
        click_in_panel(v, '[Comment...]'); v.type('abc'); v.key('enter')
        v.key('ctrl+q'); v.pump(0.8)
        check(not v.alive(), 'viewer asked something instead of quitting (design changed?)')


# ------------------------------------------------ the engine's offer is not the reader's edit (DR-2)
# On ARRIVAL at an object the viewer seeds the header (Family, Variant) and ticks the blocks that decided a matched
# diagnose, with their tag and threshold. That is what the ENGINE offers; the reader has done nothing, so no guard that
# asks "is there a draft to finish or undo" may refuse. Old tests missed it: (a) no case opened a sample that matches a
# diagnose and then asked for Next File / Unpack / Dump / Rebuild; the matched-sample cases in t_detect only read the screen.
RUN1 = os.environ.get('KOF_RUN1', '/mnt/games/normtest/scan_run1/run1')
UNDO = 'Finish or undo the draft first'


def arrived(v, norm=True):
    """The Blocks tab of the normalised view, where the matched diagnoses tick their blocks (the panel is enlarged so the matchers show)."""
    if norm:
        from t_detect import select
        select(v, '//0:norm')
    open_tab(v, 'Blocks')
    enlarge(v, 16)
    fold_mutation(v)


def file_guards(v):
    """Enabled flag of Next File, Previous File (File menu), Unpack (Analysis menu) and Rebuild database (Manage menu)."""
    out = {}
    for menu, names in (('File', ('Next File', 'Previous File')), ('Analysis', ('Unpack',)), ('Manage', ('Rebuild database',))):
        v.menu_open(menu)
        for y, x, t, en in v.popup():
            for n in names:
                if t.startswith(n):
                    out[n] = en
        v.esc(2)
    return out


def dump_refusal(v):
    """What the two Dump items answer when clicked (Analysis > Dump > Static unpacker / Emu unpacker): (label, status line after the click).
    The emulator one has to rebuild the tree, so it is the one an edited draft refuses; the dump lands beside the scratch copy."""
    out = []
    for label in ('Static unpacker', 'Emu unpacker'):
        v.menu_open('Analysis')
        for y, x, t, en in v.popup():
            if t.startswith('Dump'):
                v.click(x + 2, y)
                v.pump(0.2)
        p = v.find(label)
        check(p, 'no %s item in the Dump sub-menu' % label)
        v.click(*p)
        v.pump_quiet(0.5, maxt=60)
        out.append((label, status(v)))
        v.esc(2)
    return out


def check_not_refused(v, what, dump=True):
    g = file_guards(v)
    for n in ('Next File', 'Previous File', 'Rebuild database'):
        check(g.get(n), '%s: %s is refused with nothing done: %r (%r)' % (what, n, g, status(v)[-80:]))
    if not g.get('Unpack'):                    # Unpack may be unavailable for the object itself; it must not be the draft that says so
        v.menu_open('Analysis')
        for y, x, t, en in v.popup():
            if t.startswith('Unpack'):
                v.click(x + 2, y)
        check(UNDO not in status(v), '%s: Unpack answers %r with nothing done' % (what, status(v)[-80:]))
        v.esc(2)
    for t, st in (dump_refusal(v) if dump else ()):
        check(UNDO not in st, '%s: Dump item %r answers %r with nothing done' % (what, t, st[-80:]))


def two_matched():
    if not os.path.exists(RUN1):
        raise Skip('no sample at %s' % RUN1)
    d = os.path.join(VT, 'dirs', 'sig_arrival')
    if os.path.isdir(d):                            # an earlier Dump left directories beside the copies that the next rmtree cannot enter
        subprocess.run(['chmod', '-R', 'u+rwx', d], check=False)   # (prep_dir chmods a directory 0644)
        shutil.rmtree(d, ignore_errors=True)
    return prep_dir('sig_arrival', [(RUN1, 'a_run1'), (RUN1, 'b_run1')])


@case(A)
def arriving_at_a_matched_object_is_not_an_edit():
    """Open an object a diagnose matches and do nothing: the header took Mirai / A from the engine, and every guard stays open - on the file
    and, after arriving at the normalised view (blocks ticked, tag and threshold set by the engine), there too."""
    fs = two_matched()
    with Viewer(fs[0], rows=70, cols=200, copy=False) as v:
        check('Family [ Mirai ]' in head(v), 'the header was not seeded: %r' % head(v)[:60])
        check_not_refused(v, 'file')
        arrived(v)
        check(sim_rows(v), 'the engine ticked no block on the view')
        check_not_refused(v, 'view')
        v.key('ctrl+\\')
        check(UNDO not in status(v), 'Ctrl+\\ refused: %r' % status(v)[-80:])


@case(A)
def stepping_to_a_second_matched_object_is_not_an_edit():
    """Arriving at the second object runs the seeding again; stepping on from there, and back, is not refused either."""
    fs = two_matched()
    with Viewer(fs[0], rows=70, cols=200, copy=False) as v:
        v.menu_item('File', 'Next File')
        v.pump_quiet()
        check('Family [ Mirai ]' in head(v), 'the second object was not seeded: %r' % head(v)[:60])
        check_not_refused(v, 'second file')
        arrived(v)
        check_not_refused(v, 'second view')
        v.key('ctrl+]')
        check(UNDO not in status(v), 'Ctrl+] refused: %r' % status(v)[-80:])
        v.menu_item('File', 'Next File')
        v.pump_quiet()
        check_not_refused(v, 'back at the second file')


def refused_after(v, what):
    g = file_guards(v)
    check(not g.get('Next File') and not g.get('Previous File') and not g.get('Rebuild database') and not g.get('Unpack'),
          '%s: a guard stayed open over a real edit: %r' % (what, g))
    v.key('ctrl+\\')
    check(UNDO in status(v), '%s: Ctrl+\\ not refused: %r' % (what, status(v)[-80:]))


def mirai_with_variant_b():
    d = os.path.join(VT, 'work', 'p%d' % os.getpid(), 'pathogens_mirai_b')
    os.makedirs(d, exist_ok=True)
    s = open(os.path.join(REPO, 'bases', 'pathogens', 'mirai.c')).read()
    s += 'KOF_MALWARE_VARIANT("B", KOF_MALTYPE_BOTNET);\n'
    with open(os.path.join(d, 'mirai.c'), 'w') as f:
        f.write(s)
    return d


def reader_edit(what):
    """One viewer, one reader edit of a seeded draft. Each is its own case, so one edit cannot hide behind another and a mutant of the hash is
    caught by the edit that reaches it."""
    fs = two_matched()
    extra = ('--pathogens', mirai_with_variant_b()) if what == 'variant' else ()
    with Viewer(fs[0], rows=70, cols=200, copy=False, extra=extra) as v:
        arrived(v)
        check_not_refused(v, what + ' (before the edit)', dump=False)
        if what == 'family':
            set_family(v, 'Diamorphine')
        elif what == 'variant':
            eq(re.search(r'Variant \[ (\S+) \]', head(v)).group(1), 'A', 'seeded variant')
            set_variant(v, 'Mirai_B')
        elif what == 'tick':
            for y in panel(v):                  # arrived() folded the block table: open it again
                if v.row(y).lstrip().startswith('[+]'):
                    v.click(3, y)
            check(tick_blocks(v, 1), 'no unticked block with a hash')
        elif what == 'untick':
            from t_detect import find_tick
            fold_mutation(v)
            t = find_tick(v)
            check(t, 'no seeded tick')
            v.click(*t[1])
        elif what == 'threshold':
            p = prow(v, '[ 70]')
            check(p, 'no threshold cell')
            v.click(p[0] + 1, p[1])
            v.type('75'); v.key('enter')
        elif what == 'tag':
            pick_unit_cell(v, 'Tag:', 'Mirai-Ops-Func', 1)   # a name no matcher row carries
        elif what == 'comment':
            click_in_panel(v, '[Well known'); v.type('abc'); v.key('enter')
        v.pump_quiet()
        refused_after(v, what)


def _reader_case(what):
    @case(A, name='a_reader_edit_of_the_%s_after_the_seeding_still_refuses' % what)
    def _run():
        """Family, Variant, a block ticked, a seeded block unticked, a threshold, a tag and the comment are each an edit of a seeded draft."""
        reader_edit(what)


for _what in ('family', 'variant', 'tick', 'untick', 'threshold', 'tag', 'comment'):
    _reader_case(_what)


@case(A)
def an_edit_made_before_arriving_is_not_forgiven_by_the_seeding():
    """A comment typed on the file, then arrival at the view (blocks ticked, tags and thresholds set): the draft was edited before the seeding and
    stays edited after it."""
    fs = two_matched()
    with Viewer(fs[0], rows=70, cols=200, copy=False) as v:
        click_in_panel(v, '[Well known'); v.type('abc'); v.key('enter')
        arrived(v)
        check(sim_rows(v), 'the engine ticked no block on the view')
        refused_after(v, 'edit before arrival')


if __name__ == '__main__':
    main(A)
