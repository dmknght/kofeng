"""Command line: usage, bad arguments, --db/--bases/--heur/--pid, files that
cannot be opened, non-tty."""
import subprocess
from tui import *

A = 'cli'


def run(args, **kw):
    r = subprocess.run([BIN] + list(args), capture_output=True, timeout=20,
                       stdin=subprocess.DEVNULL, text=True, **kw)
    return r.returncode, r.stdout, r.stderr


@case(A)
def no_arguments_prints_usage_and_exits_2():
    rc, out, err = run([])
    eq(rc, 2); check('kofviewer [--db' in err, err[:80])


@case(A)
def help_flags_print_usage_and_exit_0():
    for f in ('--help', '-h'):
        rc, out, err = run([f])
        eq(rc, 0, f); check('--heur' in err and '--pid' in err, err[:80])


@case(A)
def unknown_option_is_rejected_with_usage():
    rc, out, err = run(['--bogus', 'x'])
    eq(rc, 2); check('kofviewer' in err)


@case(A)
def option_missing_its_value_is_rejected():
    for opt in ('--db', '--bases', '--heur', '--pid'):
        rc, out, err = run([opt])
        check(rc != 0, '%s without value exited 0' % opt)


@case(A)
def heur_value_is_validated():
    rc, out, err = run(['--heur', '7', FIX('tiny.bin')])
    eq(rc, 2); check("--heur takes 0, 1 or 2" in err, err)
    rc, out, err = run(['--heur', 'x', FIX('tiny.bin')])
    check(rc != 0, 'non numeric --heur accepted')


@case(A)
def non_tty_stdin_is_refused_cleanly():
    rc, out, err = run([FIX('tiny.bin')])
    check(rc != 0 and 'needs a terminal' in err, '%r %r' % (rc, err))


@case(A)
def missing_empty_and_non_regular_files_are_refused():
    for p, what in (('/nonexistent/file', 'missing'), (FIX('empty.bin'), 'empty')):
        with Viewer(p, copy=False) as v:
            v.pump(0.5)
            check(not v.alive(), '%s file: viewer stayed up' % what)
            check(b'is empty or not a regular file' in bytes(v.raw), 'no message for a %s file: %r' % (what, bytes(v.raw)[-100:]))
            eq(v.exit_desc(), 'exit 1', what)


@case(A)
def error_message_names_the_file_it_means():
    # Observed nit: the message shows the base name only ("file", not the path).
    with Viewer('/nonexistent/dir/some_file.bin', copy=False) as v:
        v.pump(0.5)
        check(b'some_file.bin' in bytes(v.raw), bytes(v.raw)[-100:])


@case(A)
def directory_argument_opens_a_file_from_it():
    d = os.path.join(VT, 'fixtures')
    with Viewer(d, copy=False) as v:
        check(v.alive(), 'directory argument rejected although usage says <file|folder>')
        check(v.row(2)[:1] == '*', v.row(2)[:30])


@case(A)
def no_db_says_so_and_still_shows_bytes():
    with Viewer(SAMPLES['ko'], db=False) as v:
        check(v.alive())
        check('No database' in v.text() or 'pass --db' in v.text(), 'no hint about the missing database: %r' % v.row(50)[-80:])
        check(hex_off(v) is not None, 'bytes not shown without a database')
        v.menu_open('Analysis'); check(v.popup()); v.esc()


@case(A)
def bad_db_directory_is_reported_not_fatal():
    with Viewer(SAMPLES['ko'], extra=['--db', '/nonexistent/db'], db=False) as v:
        v.pump(0.5)
        check(v.alive() or b'database' in bytes(v.raw), 'neither a message nor a running viewer')


@case(A)
def bases_directory_missing_is_survivable():
    with Viewer(SAMPLES['ko'], bases='/nonexistent/bases') as v:
        check(v.alive(), 'died with a missing --bases directory')
        v.menu_open('File'); v.esc()


@case(A)
def heur_levels_change_what_is_separated():
    p = pick(SAMPLES['pe'], 1, 30000, 200000)[0]
    counts = {}
    for h in ('0', '1', '2'):
        with Viewer(p, extra=['--heur', h]) as v:
            counts[h] = sum(1 for y in range(2, 40) if v.row(y)[1:31].strip())
            check(v.alive(), '--heur %s died' % h)
    check(counts['0'] <= counts['2'], 'rows by level: %r' % counts)


@case(A)
def pid_mode_opens_a_process_snapshot():
    sl = subprocess.Popen(['sleep', '60'])
    try:
        with Viewer('', extra=['--pid', str(sl.pid)], copy=False) as v:
            check(v.alive(), 'viewer did not open a live process')
            check('NIX_PROC' in v.row(2) and 'CMDLINE' in v.text(), v.row(2)[:50])
            v.click(10, 4)
            v.key('down', 3)
            v.menu_item('Analysis', 'Dashboard')
            check(v.dialog() and 'Properties' in v.dialog()[4], 'no properties for a process')
            v.esc()
    finally:
        sl.kill()


@case(A)
def pid_mode_rejects_bad_pid():
    with Viewer('', extra=['--pid', '999999'], copy=False) as v:
        v.pump(0.5)
        check(not v.alive() and b'cannot be opened' in bytes(v.raw), bytes(v.raw)[-80:])
    with Viewer('', extra=['--pid', 'abc'], copy=False) as v:
        v.pump(0.5)
        check(not v.alive(), '--pid abc accepted')


@case(A)
def symlink_and_relative_paths():
    link = os.path.join(VT, 'fixtures', 'link_to_tiny')
    if os.path.lexists(link):
        os.unlink(link)
    os.symlink(FIX('tiny.bin'), link)
    try:
        with Viewer(link, copy=False) as v:
            check(v.alive(), 'symlink argument rejected')
    finally:
        os.unlink(link)


@case(A)
def unreadable_file_is_reported():
    p = os.path.join(VT, 'fixtures', 'noperm.bin')
    if os.path.exists(p):
        os.chmod(p, 0o644)
    open(p, 'wb').write(b'secret')
    os.chmod(p, 0o000)
    try:
        if os.access(p, os.R_OK):
            raise Skip('running as root')
        with Viewer(p, copy=False) as v:
            v.pump(0.5)
            check(not v.alive(), 'opened an unreadable file')
            check(b'kofviewer:' in bytes(v.raw), bytes(v.raw)[-80:])
    finally:
        os.chmod(p, 0o644)
        os.unlink(p)


if __name__ == '__main__':
    main(A)
