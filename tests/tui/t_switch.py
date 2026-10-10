"""Switch-File: Next / Previous stepping through a folder (menu and Ctrl+\\ / Ctrl+])."""
import shutil
from tui import *

A = 'switch'


def make_dir(name='nav_edge'):
    d = os.path.join(VT, 'dirs', name)
    if os.path.isdir(d):
        for f in os.listdir(d):
            p = os.path.join(d, f)
            if not os.path.islink(p) and os.path.isfile(p):
                os.chmod(p, 0o644)
        shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)

    def mk(n, data):
        p = os.path.join(d, n)
        with open(p, 'wb') as f:
            f.write(data)
        os.chmod(p, 0o444)
    mk('.hidden', b'hidden data')
    mk('a_empty', b'')
    mk('b_real', bytes(range(64)))
    os.makedirs(os.path.join(d, 'c_dir'))
    os.symlink(os.path.join(d, 'b_real'), os.path.join(d, 'd_link'))
    mk('e_real', b'MZ' + bytes(100))
    mk('g_last', b'last file data')
    return d


def msg(v):
    return v.row(v.rows)[40:].strip()


def step(v, which):
    v.menu_item('Switch-File', which)
    return msg(v)


@case(A)
def next_walks_files_skipping_directories():
    d = make_dir()
    with Viewer(os.path.join(d, 'b_real'), copy=False) as v:
        eq(step(v, 'Next'), 'Opened d_link', 'directory c_dir should be skipped')
        eq(step(v, 'Next'), 'Opened e_real')
        eq(step(v, 'Next'), 'Opened g_last')


@case(A)
def next_at_the_end_says_so_and_stays():
    d = make_dir()
    with Viewer(os.path.join(d, 'g_last'), copy=False) as v:
        for _ in range(3):
            eq(step(v, 'Next'), 'No next file in this folder')
        check(v.row(2).startswith('*Raw') and ' 14 ' in v.row(2), 'view changed: %r' % v.row(2)[:40])


@case(A)
def previous_skips_empty_files_and_stops_at_the_start():
    d = make_dir()
    with Viewer(os.path.join(d, 'b_real'), copy=False) as v:
        eq(step(v, 'Previous'), 'Opened .hidden', 'empty a_empty cannot be opened and is skipped')
        eq(step(v, 'Previous'), 'No previous file in this folder')


@case(A)
def keys_ctrl_backslash_and_ctrl_bracket():
    d = make_dir()
    with Viewer(os.path.join(d, 'b_real'), copy=False) as v:
        v.key('ctrl+\\')
        eq(msg(v), 'Opened d_link')
        v.key('ctrl+]')
        eq(msg(v), 'Opened b_real')


@case(A)
def single_file_folder_has_no_neighbours():
    d = os.path.join(VT, 'dirs', 'solo')
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    p = os.path.join(d, 'only')
    open(p, 'wb').write(b'abc')
    os.chmod(p, 0o444)
    with Viewer(p, copy=False) as v:
        eq(step(v, 'Next'), 'No next file in this folder')
        eq(step(v, 'Previous'), 'No previous file in this folder')


@case(A)
def navigation_resets_scroll_selection_and_panels():
    d = make_dir()
    with Viewer(os.path.join(d, 'b_real'), copy=False) as v:
        v.wheel(80, 10, n=3)
        v.click(60, 5)
        step(v, 'Next')
        check(hex_off(v) == 0, 'hex offset kept across files: %r' % hex_off(v))
        check(v.row(2)[0] == '*', 'tree selection not reset')


@case(A)
def navigation_with_open_dialog_does_not_crash():
    d = make_dir()
    with Viewer(os.path.join(d, 'b_real'), copy=False) as v:
        v.menu_item('Edit', 'Find...')
        v.key('ctrl+\\')
        check(v.alive())
        v.esc(2)


@case(A)
def file_deleted_while_open_then_next():
    d = make_dir('nav_del')
    with Viewer(os.path.join(d, 'b_real'), copy=False) as v:
        os.chmod(os.path.join(d, 'd_link'), 0o644) if not os.path.islink(os.path.join(d, 'd_link')) else None
        os.unlink(os.path.join(d, 'd_link'))
        step(v, 'Next')
        check(v.alive(), 'died after a neighbour disappeared')
        check(msg(v) in ('Opened e_real', 'Opened g_last'), msg(v))


@case(A)
def large_folder_stepping_is_fast():
    d = os.path.join(VT, 'dirs', 'nav_many')
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    for i in range(400):
        with open(os.path.join(d, 'f%04d' % i), 'wb') as f:
            f.write(b'x' * (i + 1))
    with Viewer(os.path.join(d, 'f0000'), copy=False) as v:
        import time
        t = time.time()
        for _ in range(10):
            v.key('ctrl+\\', settle=0.1)
        check(time.time() - t < 8, 'stepping through a 400-file folder is slow')
        check('f0010' in msg(v), msg(v))


if __name__ == '__main__':
    main(A)
