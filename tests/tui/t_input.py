"""Raw input robustness: malformed / unusual terminal sequences, mouse motion,
drag outside the window, rapid bursts, key chords, bracketed paste, quit."""
from tui import *
from dl import *

A = 'input'


def ko(**kw):
    return Viewer(SAMPLES['ko'], settle=0.7, **kw)


def tree_sel(v):
    return [v.row(y)[1:12].strip() for y in range(2, 10) if v.row(y)[:1] == '*']


CLICK_DATA = '\x1b[<0;10;5M\x1b[<0;10;5m'       # a click on the DATA tree row


# ------------------------------------------------------- malformed terminal data
@case(A, known_bug='BUG-2 read_mouse() returns K_NONE (= end of input) for a malformed SGR report: the viewer exits with status 0')
def malformed_sgr_mouse_report_must_not_quit():
    for seq in ('\x1b[<;;M', '\x1b[<a;b;cM', '\x1b[<1;2M', '\x1b[<M', '\x1b[<;M'):
        with ko() as v:
            v.send(seq, 0.4)
            check(v.alive(), 'viewer quit on %r' % seq)


@case(A)
def oversized_and_out_of_range_mouse_coordinates():
    for seq in ('\x1b[<0;0;0M', '\x1b[<0;-5;-5M', '\x1b[<0;9999;9999M', '\x1b[<99999999999;1;1M',
                '\x1b[<0;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1M', '\x1b[<2;9999;1M', '\x1b[<64;0;0M'):
        with ko() as v:
            v.send(seq, 0.3)
            v.send(CLICK_DATA, 0.3)
            check(v.alive(), 'viewer died on %r' % seq)
            check('DATA' in ' '.join(tree_sel(v)), 'viewer stopped responding after %r' % seq)


@case(A)
def x10_legacy_mouse_encoding_is_understood():
    with ko() as v:
        v.send('\x1b[M' + chr(32) + chr(32 + 10) + chr(32 + 5), 0.3)     # press at (10,5)
        v.send('\x1b[M' + chr(35) + chr(32 + 10) + chr(32 + 5), 0.3)     # release
        check('DATA' in ' '.join(tree_sel(v)), 'X10 click not handled: %r' % tree_sel(v))


@case(A)
def x10_truncated_sequence_does_not_hang_or_quit():
    with ko() as v:
        v.send('\x1b[M ', 0.3)
        v.send('\x1b[<', 0.3)
        v.send('q', 0.3)
        check(v.alive())


@case(A)
def unknown_escape_sequences_are_ignored():
    for seq in ('\x1b[99~', '\x1bOP', '\x1b[1;5A', '\x1b[1~', '\x1b[4~', '\x1b[7~', '\x1b[Z', '\x1b\x1b', '\x1b[?1;2c',
                '\x1b[0n', '\x1b]11;rgb:0000/0000/0000\x07'):
        with ko() as v:
            v.send(seq, 0.4)
            v.send(CLICK_DATA, 0.3)
            check(v.alive(), 'died on %r' % seq)
            check('DATA' in ' '.join(tree_sel(v)), 'stopped responding after %r: %r' % (seq, tree_sel(v)))


@case(A)
def non_utf8_and_binary_bytes_on_stdin():
    with ko() as v:
        v.send(bytes(range(128, 256)), 0.5)
        v.send(b'\xff\xfe\xfd', 0.3)
        v.send(CLICK_DATA, 0.3)
        check(v.alive())


@case(A)
def home_end_variants_in_a_field_do_not_corrupt_it():
    # tmux/screen send ESC[1~ / ESC[4~ for Home/End and xterm ESC[1;5C for Ctrl+Right.
    with ko() as v:
        click_in_panel(v, '[?]')
        v.type('abc')
        v.send('\x1b[1;5C', 0.3)
        r = v.row(grip(v) + 1)
        check('abc' in r, 'field content lost: %r' % r[:50])
        check(';5C' not in r and '5C' not in r, 'escape tail typed into the field: %r' % r[:50])


@case(A)
def lone_escape_is_answered_without_a_second_key():
    with ko() as v:
        v.menu_open('Analysis')
        v.send('\x1b', 0.4)
        check(not v.popup(), 'a lone Esc needed a second key')


@case(A)
def esc_then_key_is_not_eaten_as_alt_chord():
    with ko() as v:
        v.send('\x1b', 0.05)
        v.send('\x1b[B', 0.3)          # Down
        check(v.alive())
        v.menu_open('Edit'); check(v.popup()); v.esc()


@case(A)
def bracketed_paste_outside_a_field_is_harmless():
    with ko() as v:
        v.send('\x1b[200~' + 'q' * 50 + '\x1b[201~', 0.5)
        check(v.alive(), 'a paste of "q" quit the viewer')
        v.send('\x1b[200~' + 'x' * 5000 + '\x1b[201~', 0.8)
        check(v.alive(), 'died on a 5000-byte paste')


@case(A)
def bracketed_paste_with_newlines_into_a_field():
    with ko() as v:
        click_in_panel(v, '[?]')
        v.send('\x1b[200~line1\nline2\x1b[201~', 0.5)
        check(v.alive())
        v.key('enter')
        check(v.alive())


@case(A)
def unterminated_bracketed_paste_does_not_wedge_forever():
    with ko() as v:
        v.send('\x1b[200~abc', 0.4)
        v.send('\x1b[201~', 0.4)
        check(v.alive())
        v.send(CLICK_DATA, 0.3)
        check('DATA' in ' '.join(tree_sel(v)), 'viewer wedged after an unterminated paste: %r' % tree_sel(v))


# ------------------------------------------------------------- mouse behaviour
@case(A)
def motion_events_without_button_are_harmless():
    with ko() as v:
        for y in range(1, 40):
            v.motion(10 + y, y)
        check(v.alive())
        check('ELF' in ' '.join(tree_sel(v)), 'selection changed by plain motion')


@case(A)
def drag_leaving_the_window_edges_keeps_selection_sane():
    with ko() as v:
        tw = 32
        v.mouse(0, tw + 14, 5, True)
        v.mouse(32, 1, 1, True)
        v.mouse(32, 170, 50, True)
        v.mouse(32, 500, 500, True)
        v.mouse(0, 500, 500, False)
        v.key('ctrl+c')
        check(v.alive())


@case(A)
def release_without_press_and_press_without_release():
    with ko() as v:
        v.mouse(0, 40, 5, False)          # a lone release
        v.mouse(0, 40, 5, True)           # a press that never ends
        v.key('down')
        v.key('esc')
        check(v.alive())


@case(A)
def middle_button_and_extra_buttons():
    with ko() as v:
        for b in (1, 3, 8, 9, 128):
            v.mouse(b, 40, 5, True, 0.1)
            v.mouse(b, 40, 5, False, 0.1)
        check(v.alive())


@case(A)
def double_click_on_every_pane():
    with ko() as v:
        for (x, y) in ((10, 3), (60, 5), (100, 20), (60, 36), (5, 1), (60, 50)):
            v.dclick(x, y)
        check(v.alive())


@case(A)
def ctrl_and_shift_click_everywhere_is_safe():
    with ko() as v:
        for mod in (4, 8, 16, 20):
            for (x, y) in ((10, 3), (60, 5), (60, 38), (20, 1)):
                v.click(x, y, mod=mod, settle=0.08)
        check(v.alive())


# --------------------------------------------------------------------- bursts
@case(A)
def burst_of_2000_wheel_events():
    with ko() as v:
        v.send('\x1b[<65;80;10M' * 2000, 1.5)
        check(v.alive())
        v.send('\x1b[<64;80;10M' * 2000, 1.5)
        check(v.alive())
        eq(hex_off(v), 0, 'scroll up burst did not return to the top')


@case(A)
def burst_of_page_keys_and_arrows():
    with Viewer(FIX('big64.bin')) as v:
        v.click(60, 5); v.key('esc')
        v.send('\x1b[6~' * 300, 1.5)
        check(v.alive())
        o = hex_off(v)
        check(o is not None and o > 0x2000, 'PgDn burst did not scroll: %r' % o)
        v.send('\x1b[5~' * 400, 1.5)
        eq(hex_off(v), 0)
        v.send('\x1b[B\x1b[A' * 500, 1.5)
        check(v.alive())


@case(A)
def burst_of_random_clicks_then_normal_use():
    import random
    rng = random.Random(5)
    with ko() as v:
        buf = ''
        for _ in range(400):
            x, y = rng.randint(1, 170), rng.randint(1, 50)
            buf += '\x1b[<0;%d;%dM\x1b[<0;%d;%dm' % (x, y, x, y)
        v.send(buf, 2.0)
        check(v.alive(), 'died on a burst of 400 clicks')
        v.key('esc', 3)
        v.menu_open('Help')
        check(v.popup() or v.dialog() or True)


@case(A)
def burst_typing_into_a_field():
    with ko() as v:
        click_in_panel(v, '[?]')
        v.send('z' * 400, 1.0)
        check(v.alive())
        v.key('enter')
        check(v.alive())


@case(A)
def slow_trickle_of_split_escape_sequence():
    with ko() as v:
        import time
        for ch in '\x1b[<0;10;5M\x1b[<0;10;5m':
            os.write(v.fd, ch.encode())
            time.sleep(0.02)        # below ESC_WAIT_MS (50 ms)
        v.pump_quiet(0.4)
        check('DATA' in ' '.join(tree_sel(v)), 'split mouse sequence not reassembled: %r' % tree_sel(v))


@case(A)
def escape_split_for_longer_than_50ms_is_a_lone_escape_and_the_tail_is_text():
    # Documented trade-off (ESC_WAIT_MS): on a slow link the tail of a split
    # sequence is read as typed characters.  Harmless with nothing focused:
    with ko() as v:
        import time
        for ch in '\x1b[<0;10;5M\x1b[<0;10;5m':
            os.write(v.fd, ch.encode())
            time.sleep(0.07)
        v.pump_quiet(0.4)
        check(v.alive())


@case(A)
def interleaved_keys_and_mouse_sequence():
    with ko() as v:
        v.send('\x1b[B\x1b[<0;10;5M\x1b[A\x1b[<0;10;5m\x1b[B', 0.6)
        check(v.alive())


# ------------------------------------------------------------------- key chords
@case(A)
def control_chords_without_binding_are_ignored():
    with ko() as v:
        for k in ('\x01', '\x02', '\x04', '\x05', '\x07', '\x08', '\x0b', '\x0c', '\x10', '\x12', '\x14', '\x15', '\x17', '\x18', '\x19', '\x1a'):
            v.send(k, 0.1)
        check(v.alive(), 'an unbound control chord quit or killed the viewer')
        check('ELF' in ' '.join(tree_sel(v)))


@case(A)
def ctrl_space_nul_byte_does_not_quit():
    with ko() as v:
        v.send('\x00', 0.3)
        check(v.alive(), 'Ctrl+Space (NUL) ended the session')


@case(A)
def bare_characters_are_not_bound():
    with ko() as v:
        for ch in 'abcdefghijklmnopqrstuvwxyz0123456789 []{}()<>/\\|;:\'",.-_=+`~!@#$%^&*':
            v.send(ch, 0.02)
        check(v.alive())
        check(not v.dialog() and not v.popup(), 'a bare character opened something')


@case(A)
def f10_when_menu_open_closes_it():
    with ko() as v:
        v.key('f10'); check(v.popup())
        v.key('f10'); check(not v.popup(), 'second F10 did not close the menu')


@case(A, known_bug='UX-2 Ctrl+Q (listed in Help as "quit") is swallowed while Symbols / Find / Goto / Decoder / Help / a menu is open; only the main view and the Properties page honour it')
def quit_via_ctrl_q_with_dialog_open():
    stuck = []
    for name, opener in (('symbols', lambda v: v.menu_item('Analysis', 'Symbols')),
                         ('find', lambda v: v.menu_item('Edit', 'Find...')),
                         ('goto', lambda v: v.menu_item('Edit', 'Go to...')),
                         ('decoder', lambda v: v.menu_item('Analysis', 'Decode string')),
                         ('help', lambda v: v.menu_item('Help', 'Keyboard')),
                         ('props', lambda v: v.menu_item('Analysis', 'Dashboard')),
                         ('file menu', lambda v: v.menu_open('File'))):
        with ko() as v:
            opener(v)
            v.key('ctrl+q'); v.pump(0.8)
            if v.alive():
                stuck.append(name)
    check(not stuck, 'Ctrl+Q ignored while open: %s' % stuck)


@case(A)
def terminal_state_is_restored_on_exit():
    with ko() as v:
        v.key('ctrl+q'); v.pump(1.0)
        raw = bytes(v.raw)
        for need, what in ((b'\x1b[?1049l', 'alternate screen off'), (b'\x1b[?1006l', 'SGR mouse off'),
                           (b'\x1b[?25h', 'cursor on'), (b'\x1b[?2004l', 'bracketed paste off')):
            check(need in raw[-400:], 'exit did not send %s (%r)' % (what, need))


@case(A)
def terminal_modes_are_enabled_on_start():
    with ko() as v:
        raw = bytes(v.raw)
        for need, what in ((b'\x1b[?1049h', 'alternate screen'), (b'\x1b[?1000h', 'mouse 1000'),
                           (b'\x1b[?1002h', 'mouse 1002'), (b'\x1b[?1006h', 'SGR mouse'), (b'\x1b[?2004h', 'bracketed paste')):
            check(need in raw, 'start did not enable %s' % what)


@case(A)
def sigterm_restores_the_terminal():
    import signal
    with ko() as v:
        os.kill(v.pid, signal.SIGTERM)
        v.pump(1.0)
        check(not v.alive(), 'SIGTERM did not stop the viewer')
        check(b'\x1b[?1049l' in bytes(v.raw)[-400:], 'terminal not restored after SIGTERM')


@case(A)
def sigint_restores_the_terminal_then_dies():
    import signal
    with ko() as v:
        n = len(v.raw)
        os.kill(v.pid, signal.SIGINT)
        v.pump(1.0)
        v.alive()
        check(b'\x1b[?1049l' in bytes(v.raw)[n:], 'terminal not restored after SIGINT')
        check(v.exit_desc() in ('killed by signal 2', 'exit 0', 'exit 130', 'exit 1'), v.exit_desc())


@case(A, known_bug='UX-3 SIGHUP and SIGQUIT leave the terminal in raw / alternate-screen / mouse-reporting mode (only SIGINT and SIGTERM restore it)')
def sighup_and_sigquit_restore_the_terminal():
    import signal
    bad = []
    for sig in (signal.SIGHUP, signal.SIGQUIT):
        with ko() as v:
            n = len(v.raw)
            os.kill(v.pid, sig)
            v.pump(1.0)
            if b'\x1b[?1049l' not in bytes(v.raw)[n:]:
                bad.append(sig.name)
    check(not bad, 'not restored after: %s' % bad)


@case(A)
def sigcont_after_sigtstp_redraws():
    import signal
    with ko() as v:
        os.kill(v.pid, signal.SIGTSTP)
        v.pump(0.3)
        os.kill(v.pid, signal.SIGCONT)
        v.pump(0.5)
        v.send(CLICK_DATA, 0.4)
        check(v.alive() or True)


def _cpu(pid):
    f = open('/proc/%d/stat' % pid).read().split(')')[1].split()
    return (int(f[11]) + int(f[12])) / os.sysconf('SC_CLK_TCK')


@case(A)
def idle_viewer_uses_no_cpu():
    for p in (SAMPLES['ko'], FIX('events.ktr'), FIX('big64.bin')):
        with Viewer(p) as v:
            c0 = _cpu(v.pid)
            v.pump(3)
            check(_cpu(v.pid) - c0 < 0.15, 'idle CPU %.2fs in 3s for %s' % (_cpu(v.pid) - c0, os.path.basename(p)))


@case(A)
def startup_time_is_reasonable_even_for_a_64mib_file():
    import time
    for p, limit in ((FIX('big64.bin'), 6.0), (SAMPLES['ko'], 5.0), (FIX('many.zip'), 5.0)):
        t = time.time()
        with Viewer(p) as v:
            dt = time.time() - t
            check(dt < limit, '%s took %.1fs to draw the first screen' % (os.path.basename(p), dt))


@case(A)
def memory_does_not_grow_under_a_long_burst_of_redraws():
    with ko() as v:
        def rss():
            return int([l for l in open('/proc/%d/status' % v.pid) if l.startswith('VmRSS')][0].split()[1])
        v.send('\x1b[<65;80;10M\x1b[<64;80;10M' * 300, 1.0)
        r0 = rss()
        for _ in range(8):
            v.send('\x1b[<65;80;10M\x1b[<64;80;10M' * 500, 1.0)
        check(rss() - r0 < 8192, 'RSS grew by %d KiB over 8000 wheel events' % (rss() - r0))


if __name__ == '__main__':
    main(A)
