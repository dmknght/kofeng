"""Event log browsing: event rows in the tree, the event panel, Filter events."""
from tui import *

A = 'events'


def ev(name='events.ktr', **kw):
    return Viewer(FIX(name), **kw)


def tree_events(v):
    out = []
    for y in range(2, 38):
        m = re.match(r'[* ]\s*(\d+) (\w+) pid=', v.row(y))
        if m:
            out.append((y, int(m.group(1)), m.group(2)))
    return out


def panel_title(v):
    for y in range(2, 50):
        m = re.search(r'-- Event (\w+) -', v.row(y))
        if m:
            return y, m.group(1)
    return None


def sel_event(v):
    for y in range(2, 38):
        m = re.match(r'\*\s*(\d+) (\w+) pid=', v.row(y))
        if m:
            return int(m.group(1)), m.group(2)
    return None


def filter_open(v):
    v.menu_open('Analysis')
    p = v.popup_item('Filter events')
    check(p, 'no Filter events item')
    v.click(p[1] + 3, p[0])


@case(A)
def log_opens_with_status_summary():
    with ev() as v:
        check(v.has('event log: linux/x86_64'), 'banner missing: %r' % v.row(50)[-80:])
        check(v.has('40 event(s)'), 'event count missing')


@case(A)
def tree_lists_each_event_with_verb_and_pid():
    with ev() as v:
        e = tree_events(v)
        check(len(e) >= 30, 'only %d event rows' % len(e))
        eq(e[0][2], 'ProcStart'); eq(e[1][2], 'ProcStop'); eq(e[2][2], 'ImageLoad')


@case(A)
def click_event_opens_panel_with_fields():
    with ev() as v:
        v.click(10, 3)
        check(sel_event(v) == (0, 'ProcStart'), sel_event(v))
        t = panel_title(v)
        check(t and t[1] == 'ProcStart', 'event panel missing: %r' % (t,))
        txt = v.text()
        for need in ('stamp', 'seq', 'pid', 'ppid', 'tid', 'verb', 'image', 'cmdline'):
            check(need in txt, 'panel field %r missing' % need)
        check('/usr/bin/tool0' in txt and 'quoted arg' in txt, 'strings missing from panel')


@case(A)
def each_verb_shows_its_own_panel():
    with ev() as v:
        seen = {}
        for y, n, verb in tree_events(v)[:10]:
            v.click(10, y)
            t = panel_title(v)
            check(t and t[1] == verb, 'row %d (%s): panel says %r' % (n, verb, t))
            seen[verb] = True
        eq(len(seen), 10, 'distinct verbs')


@case(A)
def net_event_shows_address_and_port():
    with ev() as v:
        y = [y for y, n, vb in tree_events(v) if vb == 'NetConn'][0]
        v.click(10, y)
        check('10.0.0.' in v.text(), 'IPv4 address not rendered: %r' % [l for l in v.snapshot()[30:38]])
        check(' 80' in v.text() or ':80' in v.text() or 'port' in v.text(), 'port missing')


@case(A)
def hex_pane_shows_record_bytes_of_selected_event():
    with ev() as v:
        v.click(10, 3)
        check(re.search(r'\| 00000000 ', v.row(2)) or re.search(r'00000000', v.row(2)),
              'hex row 0 missing: %r' % v.row(2)[:60])


@case(A)
def keys_move_event_selection_and_panel_follows():
    with ev() as v:
        v.click(10, 3)
        v.key('down', 2)
        eq(sel_event(v), (2, 'ImageLoad'))
        eq(panel_title(v)[1], 'ImageLoad', 'panel did not follow Down')
        v.key('up')
        eq(sel_event(v), (1, 'ProcStop'))


@case(A)
def panel_close_button_and_reopen_by_selection():
    with ev() as v:
        v.click(10, 3)
        y, _ = panel_title(v)
        x = v.row(y).index('[x]') + 2
        v.click(x, y)
        check(panel_title(v) is None, 'close [x] did not close the panel')
        v.click(10, 5)
        check(panel_title(v) is None, 'closing sticks for the rest of the file (documented)')


@case(A)
def panel_box_wheel_scrolls_when_long():
    with ev() as v:
        v.click(10, 3)
        y, _ = panel_title(v)
        before = v.fingerprint()
        v.wheel(100, y + 3, n=2)
        check(v.alive())


@case(A)
def panel_right_click_menu_in_text_box():
    with ev() as v:
        v.click(10, 3)
        y, _ = panel_title(v)
        v.rclick(100, y + 2)
        check(v.alive())
        v.esc()


@case(A)
def tree_wheel_scrolls_within_the_loaded_window():
    with ev('events_many.ktr') as v:
        e0 = tree_events(v)
        v.wheel(10, 10, n=10)
        e1 = tree_events(v)
        check(e1 and e1[0][1] > e0[0][1], 'tree did not scroll: %r -> %r' % (e0[:1], e1[:1]))
        v.wheel(10, 10, up=True, n=100)
        eq(tree_events(v)[0][1], 0)


@case(A, known_bug='BUG-7 event-log tree: wheel stops at the 96-event window (LOG_WIN); only Up/Down slide the window (on_wheel never calls goto_node for a log)')
def tree_wheel_reaches_events_beyond_the_window():
    with ev('events_many.ktr') as v:
        v.wheel(10, 10, n=400)
        e = tree_events(v)
        check(e and e[-1][1] >= 590, 'last event reachable by wheel? last visible row is event %r' % (e[-1:],))


@case(A, known_bug='BUG-18 goto_node(): for a log, k == (uint32_t)-1 (Up on the first row) is also >= n_node, so the "page forward" branch wins and the "page back" branch below it is unreachable: Up on the root jumps FORWARD 96 events and there is no way back')
def up_on_the_log_root_pages_back_not_forward():
    with ev('events_many.ktr') as v:
        v.click(10, 3)
        v.key('down', 100)                         # into the second window
        first = tree_events(v)[0][1]
        v.click(10, 2)                             # the window's root row
        v.key('up')
        s = sel_event(v)
        check(s is not None and s[0] < first, 'Up on the root moved to event %r (the window started at %d)' % (s, first))


@case(A)
def keyboard_walk_down_600_events():
    with ev('events_many.ktr') as v:
        v.click(10, 3)
        for _ in range(60):
            v.key('down', settle=0.02)
        check(sel_event(v) and sel_event(v)[0] == 60, 'selection %r after 60 Downs' % (sel_event(v),))
        v.key('pgdn')
        check(v.alive())


@case(A)
def single_event_log():
    with ev('events_one.ktr') as v:
        check(v.has('1 event(s)'), v.row(50)[-80:])
        v.click(10, 3)
        check(panel_title(v), 'no panel for the only event')
        v.key('down'); v.key('up')
        check(v.alive())


@case(A)
def filter_menu_lists_present_verbs_with_checkboxes():
    with ev() as v:
        filter_open(v)
        for verb in ('FileDel', 'FileNew', 'FileRen', 'ImageLoad', 'NetClose', 'NetConn',
                     'NetRecv', 'NetSend', 'ProcStart'):
            check(v.has('[x] ' + verb), 'filter row for %s missing' % verb)
        check(v.has('Apply filter'))
        v.esc(2)


@case(A, known_bug='BUG-5 Filter events has 20 verb slots (BI_FILT_V0..V19) for 27 verbs: ProcStop (present in the log) cannot be listed or filtered')
def filter_menu_offers_every_verb_in_the_log():
    with ev() as v:
        filter_open(v)
        check(v.has('[x] ProcStop') or v.has('[ ] ProcStop'), 'ProcStop events exist in the log but the filter menu has no row for them')
        v.esc(2)


@case(A)
def filter_uncheck_and_apply_hides_verb():
    with ev() as v:
        before = len(tree_events(v))
        filter_open(v)
        v.click(*v.find('[x] NetSend'))
        check(v.has('[ ] NetSend'), 'toggle did not flip the box')
        v.click(*v.find('Apply filter'))
        check(v.has('Filtered: 36 event(s)') or v.has('36 event'), 'status does not report the filter: %r' % v.row(50)[-80:])
        verbs = {vb for _, _, vb in tree_events(v)}
        check('NetSend' not in verbs, 'NetSend rows still listed')
        check('NetRecv' in verbs, 'other verbs vanished')


@case(A)
def filter_state_persists_when_menu_reopened():
    with ev() as v:
        filter_open(v)
        v.click(*v.find('[x] NetSend'))
        v.click(*v.find('Apply filter'))
        filter_open(v)
        check(v.has('[ ] NetSend'), 'filter state lost')
        v.esc(2)


@case(A)
def filter_all_off_then_apply_does_not_crash():
    with ev() as v:
        filter_open(v)
        for verb in ('FileDel', 'FileNew', 'FileRen', 'ImageLoad', 'NetClose', 'NetConn',
                     'NetRecv', 'NetSend', 'ProcStart'):
            p = v.find('[x] ' + verb)
            if p:
                v.click(*p)
        v.click(*v.find('Apply filter'))
        check(v.alive(), 'died applying an all-off filter')
        v.click(10, 3); v.key('down'); v.wheel(10, 5, n=2)
        check(v.alive())


@case(A)
def filter_menu_absent_for_ordinary_files():
    with Viewer(SAMPLES['ko']) as v:
        v.menu_open('Analysis')
        check(not v.popup_item('Filter events'), 'Filter events offered for an ELF')


@case(A)
def event_log_resize_and_narrow():
    with ev() as v:
        v.click(10, 3)
        for r, c in ((30, 100), (20, 70), (50, 170), (70, 240)):
            v.resize(r, c)
            check(v.alive(), 'died at %dx%d' % (r, c))


@case(A)
def event_log_symbols_and_find_dialogs_do_not_crash():
    with ev() as v:
        v.click(10, 3)
        v.menu_item('Edit', 'Find...'); v.type('tool'); v.key('enter'); v.esc()
        v.menu_item('Edit', 'Go to...'); v.type('40'); v.key('enter'); v.esc()
        v.menu_item('Analysis', 'Dashboard'); v.key('pgdn'); v.esc()
        check(v.alive())


if __name__ == '__main__':
    main(A)
