"""File > Next File / Previous File with and without a draft, and quitting with one.
The draft is never written: the panel's Generate only lists the output
(t_diagnose.py)."""
import glob
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
        click_in_panel(v, '[?]'); v.type('abc'); v.key('enter')
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
        click_in_panel(v, '[?]'); v.type('abc'); v.key('enter')
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
        check('Type [' in r, r[:60])
        check(v.alive())


@case(A)
def quit_with_unsaved_draft_exits_without_confirmation():
    # Observed: no "discard changes?" - recorded so a change is noticed.
    fresh_bases()
    with ko() as v:
        click_in_panel(v, '[?]'); v.type('abc'); v.key('enter')
        v.key('ctrl+q'); v.pump(0.8)
        check(not v.alive(), 'viewer asked something instead of quitting (design changed?)')


if __name__ == '__main__':
    main(A)
