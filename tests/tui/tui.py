"""tui.py - pty + pyte harness for kofviewer.

Spawns the viewer on a COPY of a sample, feeds it keys / SGR mouse events,
and exposes the emulated screen.  Coordinates are 1-based (x=column, y=row),
the same as the SGR mouse protocol; screen helpers use the same convention.

Nothing here edits a source file; samples are copied under SCRATCH/vt and
made read-only before the viewer sees them (the viewer / scanner can patch
files in place).
"""
import os, pty, sys, time, select, struct, fcntl, termios, signal, shutil
import re, traceback
import pyte

REPO = os.environ.get('KOF_REPO', '/home/dmknght/Desktop/AV/Kaspersky/kofeng')
SCRATCH = os.environ.get('KOF_SCRATCH', '/mnt/games/kofscratch')
VT = os.path.join(SCRATCH, 'vt')
BIN = os.environ.get('KOFVIEWER', os.path.join(VT, 'kofviewer'))

# --- sample catalogue (paths are the ones named in the task) -----------------
SAMPLES = {
    'ko':      SCRATCH + '/ko100c/0061_sunrpc.ko',
    'gafgyt':  SCRATCH + '/vt/gafgyt_src',
    'elf255':  SCRATCH + '/elf255',
    'pe':      SCRATCH + '/snapcorp/pe300',
}

# keys
KEYS = {
    'up': '\x1b[A', 'down': '\x1b[B', 'right': '\x1b[C', 'left': '\x1b[D',
    'home': '\x1b[H', 'end': '\x1b[F', 'pgup': '\x1b[5~', 'pgdn': '\x1b[6~',
    'del': '\x1b[3~', 'f10': '\x1b[21~', 'esc': '\x1b', 'enter': '\r',
    'tab': '\t', 'backtab': '\x1b[Z', 'bs': '\x7f',
    'ctrl+c': '\x03', 'ctrl+f': '\x06', 'ctrl+n': '\x0e', 'ctrl+o': '\x0f',
    'ctrl+q': '\x11', 'ctrl+v': '\x16', 'ctrl+]': '\x1d', 'ctrl+\\': '\x1c',
    'ctrl+space': '\x00', 'ctrl+a': '\x01', 'ctrl+e': '\x05', 'ctrl+u': '\x15',
}


class Fail(AssertionError):
    pass


class Skip(Exception):
    pass


def prep_sample(src, name=None):
    """Copy `src` into SCRATCH/vt/work/ read-only and return the copy."""
    d = os.path.join(VT, 'work', 'p%d' % os.getpid())
    os.makedirs(d, exist_ok=True)
    dst = os.path.join(d, name or os.path.basename(src))
    if os.path.exists(dst):
        os.chmod(dst, 0o644)
    shutil.copyfile(src, dst)
    os.chmod(dst, 0o444)
    return dst


def prep_dir(name, srcs):
    """A fresh directory of read-only copies (for Next/Previous tests)."""
    d = os.path.join(VT, 'dirs', name)
    if os.path.isdir(d):
        for f in os.listdir(d):
            os.chmod(os.path.join(d, f), 0o644)
        shutil.rmtree(d)
    os.makedirs(d)
    out = []
    for s in srcs:
        nm = None
        if isinstance(s, tuple):
            s, nm = s
        t = os.path.join(d, nm or os.path.basename(s))
        shutil.copyfile(s, t)
        os.chmod(t, 0o444)
        out.append(t)
    return out


def pick(dirpath, n=1, minsize=1, maxsize=1 << 20, ext=None):
    """First n regular files (recursive, sorted) with size in range."""
    out = []
    for root, ds, fs in os.walk(dirpath):
        ds.sort()
        for f in sorted(fs):
            p = os.path.join(root, f)
            try:
                sz = os.path.getsize(p)
            except OSError:
                continue
            if not os.path.isfile(p) or not (minsize <= sz <= maxsize):
                continue
            if ext and not p.endswith(ext):
                continue
            out.append(p)
            if len(out) >= n:
                return out
    return out


BASES_COPY = os.path.join(VT, 'bases_copy_p%d' % os.getpid())   # per process: modules run in parallel


def fresh_bases():
    """A pristine scratch copy of REPO/bases.  Draft saves go here, never into
    the repository (the viewer writes signatures into the --bases tree)."""
    if os.path.isdir(BASES_COPY):
        shutil.rmtree(BASES_COPY)
    shutil.copytree(os.path.join(REPO, 'bases'), BASES_COPY)
    return BASES_COPY


import atexit


def _cleanup():
    for d in (BASES_COPY, os.path.join(VT, 'work', 'p%d' % os.getpid())):
        try:
            if os.path.isdir(d):
                for root, ds, fs in os.walk(d):
                    for f in fs:
                        try:
                            os.chmod(os.path.join(root, f), 0o644)
                        except OSError:
                            pass
                shutil.rmtree(d, ignore_errors=True)
        except Exception:
            pass


atexit.register(_cleanup)


def bases_dir():
    return BASES_COPY if os.path.isdir(BASES_COPY) else fresh_bases()


class Viewer:
    def __init__(self, path, rows=50, cols=170, extra=(), db=True, bases=True,
                 settle=0.7, copy=True, cwd=None):
        self.rows, self.cols = rows, cols
        if copy and not path.startswith(VT):
            path = prep_sample(path)
        self.path = path
        self.log = []
        argv = ['kofviewer']
        if db:
            argv += ['--db', (REPO + '/build/release/databases') if cwd else 'build/release/databases']
        if bases:
            argv += ['--bases', bases if isinstance(bases, str) else bases_dir()]
        argv += list(extra) + [path]
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.chdir(cwd or REPO)
            os.environ['TERM'] = 'xterm-256color'
            os.execv(BIN, argv)
        self._setsize(rows, cols)
        self.screen = pyte.Screen(cols, rows)
        self.stream = pyte.ByteStream(self.screen)
        self.dead = False
        self.status = None
        self.nbytes = 0
        self.raw = bytearray()
        self.wait_ready(settle)

    # -- low level ------------------------------------------------------------
    def wait_ready(self, quiet=0.6, maxt=40.0):
        """Wait for the first frame, then until the menu bar AND the status line
        are both drawn (a loaded machine can leave a gap mid-startup), then for
        `quiet` seconds of silence."""
        end = time.time() + maxt
        while self.nbytes == 0 and time.time() < end and not self.dead:
            self.pump(0.1)
        self.pump_quiet(min(quiet, 1.0), maxt=10)
        while time.time() < end and not self.dead:
            if 'File' in self.screen.display[0] and self.screen.display[self.rows - 1].strip():
                break
            self.pump(0.2)
        self.pump_quiet(0.3, maxt=5)

    def _setsize(self, rows, cols):
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ,
                    struct.pack('HHHH', rows, cols, 0, 0))

    def _feed(self, d):
        self.raw += d
        if len(self.raw) > 400000:
            del self.raw[:200000]
        self.stream.feed(d)

    def osc52(self):
        """Decoded payloads of every OSC 52 (clipboard) sequence seen so far."""
        import base64
        out = []
        for m in re.finditer(rb'\x1b\]52;[a-z]*;([A-Za-z0-9+/=]*)(?:\x07|\x1b\\)', bytes(self.raw)):
            try:
                out.append(base64.b64decode(m.group(1)))
            except Exception:
                pass
        return out

    def pump(self, t=0.25):
        end = time.time() + t
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if r:
                try:
                    d = os.read(self.fd, 65536)
                except OSError:
                    self.dead = True
                    return
                if not d:
                    self.dead = True
                    return
                self.nbytes += len(d)
                self._feed(d)

    def pump_quiet(self, quiet=0.25, maxt=5.0):
        """Pump until `quiet` seconds pass without output (or maxt)."""
        start = last = time.time()
        while time.time() - start < maxt:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if r:
                try:
                    d = os.read(self.fd, 65536)
                except OSError:
                    self.dead = True
                    return
                if not d:
                    self.dead = True
                    return
                self.nbytes += len(d)
                self._feed(d)
                last = time.time()
            elif time.time() - last >= quiet:
                return

    def alive(self):
        if self.dead and getattr(self, 'status', None) is not None:
            return False
        try:
            p, st = os.waitpid(self.pid, os.WNOHANG)
            if p:
                self.dead = True
                self.status = st
                return False
        except ChildProcessError:
            self.dead = True
            return False
        return True

    def send(self, s, settle=0.15):
        """Write to the viewer.  Large payloads are written in pieces with the
        output drained in between (otherwise the pty's two buffers fill and
        both sides block)."""
        if isinstance(s, str):
            s = s.encode()
        if self.dead:
            return
        view = memoryview(s)
        pos = 0
        deadline = time.time() + 60
        while pos < len(view) and time.time() < deadline:
            try:
                r, w, _ = select.select([self.fd], [self.fd], [], 0.2)
            except (OSError, ValueError):
                self.dead = True
                return
            if r:
                try:
                    d = os.read(self.fd, 65536)
                except OSError:
                    self.dead = True
                    return
                if not d:
                    self.dead = True
                    return
                self.nbytes += len(d)
                self._feed(d)
            if w:
                try:
                    pos += os.write(self.fd, view[pos:pos + 1024])
                except OSError:
                    self.dead = True
                    return
        self.pump_quiet(settle, maxt=6.0)

    def crashed(self):
        """True when the child died from a signal (SEGV, ABRT, ...)."""
        self.alive()
        if self.status is None:
            for _ in range(10):
                time.sleep(0.05)
                self.alive()
                if self.status is not None:
                    break
        return self.status is not None and os.WIFSIGNALED(self.status)

    def exit_desc(self):
        if self.status is None:
            return 'running'
        if os.WIFSIGNALED(self.status):
            return 'killed by signal %d' % os.WTERMSIG(self.status)
        return 'exit %d' % os.WEXITSTATUS(self.status)

    def close(self):
        try:
            os.kill(self.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except OSError:
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    # -- input ----------------------------------------------------------------
    def key(self, name, n=1, settle=0.15):
        """n presses.  Presses are written one at a time (settle each) so the
        viewer paints between them, unless n > 12, which is sent as a burst."""
        seq = KEYS.get(name, name)
        if n > 12:
            self.send(seq * n, max(settle, 0.4))
            return
        for _ in range(n):
            self.send(seq, settle)

    def type(self, text, settle=0.2):
        for ch in text:
            self.send(ch, 0.05)
        self.pump_quiet(settle)

    def mouse(self, b, x, y, press=True, settle=0.15):
        self.send('\x1b[<%d;%d;%d%s' % (b, x, y, 'M' if press else 'm'), settle)

    def click(self, x, y, right=False, mod=0, settle=0.15):
        b = (2 if right else 0) | mod
        self.mouse(b, x, y, True, 0.06)
        self.mouse(b, x, y, False, settle)

    def dclick(self, x, y):
        self.mouse(0, x, y, True, 0.02); self.mouse(0, x, y, False, 0.02)
        self.mouse(0, x, y, True, 0.02); self.mouse(0, x, y, False, 0.25)

    def rclick(self, x, y):
        self.click(x, y, right=True)

    def wheel(self, x, y, up=False, n=1, mod=0, settle=0.2):
        """n wheel notches, written as ONE burst (also a rapid-input test)."""
        b = (64 if up else 65) | mod
        self.send('\x1b[<%d;%d;%dM' % (b, x, y) * n, settle if n == 1 else max(settle, 0.3))

    def hwheel(self, x, y, left=False, n=1):
        # shift+wheel = +4 in the SGR button code
        self.wheel(x, y, up=left, n=n, mod=4)

    def drag(self, x0, y0, x1, y1, steps=4):
        self.mouse(0, x0, y0, True, 0.1)
        for i in range(1, steps + 1):
            xx = x0 + (x1 - x0) * i // steps
            yy = y0 + (y1 - y0) * i // steps
            self.mouse(32, xx, yy, True, 0.05)     # motion with button 1
        self.mouse(0, x1, y1, False, 0.25)

    def motion(self, x, y):
        self.mouse(35, x, y, True, 0.05)   # motion, no button

    def resize(self, rows, cols, settle=0.6):
        self.rows, self.cols = rows, cols
        # emulator first, so nothing the viewer writes for the new size can be
        # fed to a screen that still has the old one (harness race)
        self.screen.resize(rows, cols)
        self._setsize(rows, cols)          # the kernel raises SIGWINCH
        self.pump_quiet(settle, maxt=4.0)

    # -- screen ---------------------------------------------------------------
    @property
    def lines(self):
        return self.screen.display

    def row(self, y):
        if y < 1 or y > self.rows:
            return ''
        return self.screen.display[y - 1]

    def text(self):
        return '\n'.join(self.screen.display)

    def has(self, s, rows=None):
        for i, l in enumerate(self.screen.display):
            if rows and not (rows[0] <= i + 1 <= rows[1]):
                continue
            if s in l:
                return True
        return False

    def find(self, s, rows=None, nth=0):
        """(x, y) of the CENTRE of the first occurrence of s (1-based)."""
        k = 0
        for i, l in enumerate(self.screen.display):
            if rows and not (rows[0] <= i + 1 <= rows[1]):
                continue
            j = l.find(s)
            while j >= 0:
                if k == nth:
                    return (j + 1 + len(s) // 2, i + 1)
                k += 1
                j = l.find(s, j + 1)
        return None

    def find_re(self, rx, rows=None):
        for i, l in enumerate(self.screen.display):
            if rows and not (rows[0] <= i + 1 <= rows[1]):
                continue
            m = re.search(rx, l)
            if m:
                return (m.start() + 1, i + 1, m)
        return None

    def cell(self, x, y):
        return self.screen.buffer[y - 1][x - 1]

    def reverse_cols(self, y):
        b = self.screen.buffer[y - 1]
        return [x + 1 for x in range(self.cols) if b[x].reverse]

    def bg_of(self, x, y):
        return self.cell(x, y).bg

    def snapshot(self):
        return [l.rstrip() for l in self.screen.display]

    def fingerprint(self):
        """Text AND attributes of every cell (selection/highlight changes
        are attribute-only, so snapshot() cannot see them)."""
        out = []
        for y in range(self.rows):
            b = self.screen.buffer[y]
            out.append(tuple((b[x].data, b[x].fg, b[x].bg, b[x].bold, b[x].reverse)
                             for x in range(self.cols)))
        return tuple(out)

    def dump(self, path=None, title=''):
        s = '\n'.join('%2d|%s' % (i + 1, l.rstrip())
                      for i, l in enumerate(self.screen.display))
        if path:
            with open(path, 'w') as f:
                f.write(s)
        return '== %s ==\n%s' % (title, s)

    def wait_for(self, s, t=5.0):
        end = time.time() + t
        while time.time() < end:
            if self.has(s):
                return True
            self.pump(0.2)
        return self.has(s)

    def wait_gone(self, s, t=5.0):
        end = time.time() + t
        while time.time() < end:
            if not self.has(s):
                return True
            self.pump(0.2)
        return not self.has(s)


    # -- dialog helpers ---------------------------------------------------------
    def dialog(self):
        """Locate the top-most rounded box: returns (x0,y0,x1,y1,title) 1-based
        or None.  Looks for a '╭' whose row continues with '─' and has a '╮'
        and a matching '╰' below."""
        L = self.screen.display
        best = None
        for i, l in enumerate(L):
            j = l.find('\u256d')
            while j >= 0:
                k = l.find('\u256e', j)
                if k > j:
                    for i2 in range(i + 1, len(L)):
                        if len(L[i2]) > j and L[i2][j] == '\u2570':
                            best = (j + 1, i + 1, k + 1, i2 + 1,
                                    l[j + 1:k].strip('\u2500 '))
                            break
                j = l.find('\u256d', j + 1)
            if best:
                break
        return best

    def dlg_text(self):
        d = self.dialog()
        if not d:
            return []
        x0, y0, x1, y1, _ = d
        return [self.screen.display[y - 1][x0 - 1:x1] for y in range(y0, y1 + 1)]

    def show(self, y0=1, y1=None, x0=1, x1=None):
        y1 = min(y1 or self.rows, self.rows)
        x1 = x1 or self.cols
        return '\n'.join('%2d|%s' % (y, self.row(y)[x0 - 1:x1].rstrip())
                         for y in range(y0, y1 + 1))

    # -- menu helpers ----------------------------------------------------------
    MENUS = ('File', 'Edit', 'Analysis', 'Switch-File', 'Help')

    def bar_pos(self, name):
        for nm in (name, name.replace('-', ' ')):
            p = self.find(nm, rows=(1, 1))
            if p:
                return p
        return None

    def menu_open(self, name):
        p = self.bar_pos(name)
        if not p:
            raise Fail('menu %r not on bar: %r' % (name, self.row(1).rstrip()))
        self.click(p[0], 1)
        return p


    def popup(self):
        """Cells of an open drop-down (and its sub-menu), as
        [(y, x0, text, enabled)] - one entry per contiguous brightblack run.
        Only rows directly below the bar are considered (the draft panel's
        table headers also use that background)."""
        out = []
        started = False
        for y in range(2, self.rows):
            b = self.screen.buffer[y - 1]
            runs, cur = [], []
            for x in range(self.cols):
                if b[x].bg == 'brightblack':
                    cur.append(x)
                elif cur:
                    runs.append(cur); cur = []
            if cur:
                runs.append(cur)
            if not runs:
                if started:
                    break
                if y > 3:
                    break
                continue
            started = True
            for run in runs:
                txt = ''.join(b[x].data for x in run).strip()
                first = next((x for x in run if b[x].data.strip()), None)
                en = first is not None and b[first].fg != 'white'
                out.append((y, run[0] + 1, txt, en))
        return out

    def popup_item(self, text):
        for y, x, t, en in self.popup():
            if text in t:
                return (y, x, t, en)
        return None

    def menu_item(self, menu, item):
        """Open `menu` and click `item`; returns False if item is absent."""
        self.menu_open(menu)
        p = self.find(item, rows=(2, 30))
        if not p:
            return False
        self.click(p[0], p[1])
        return True

    def menu_items(self, menu):
        """Visible text rows of an open menu (after clicking its title)."""
        self.menu_open(menu)
        return [l for l in self.snapshot()[1:30]]

    def esc(self, n=1):
        for _ in range(n):
            self.send('\x1b', 0.25)


# --- tiny test framework ------------------------------------------------------
REGISTRY = []   # (module, name, fn, flags)


def case(area, name=None, known_bug=None):
    """Register a test case.  known_bug='text' marks an EXPECTED failure that
    documents a bug (reported as XFAIL; it turns into FAIL-FIXED when it
    starts to pass, so the marker gets removed)."""
    def deco(fn):
        REGISTRY.append((area, name or fn.__name__, fn, known_bug))
        return fn
    return deco


def check(cond, msg='check failed'):
    if not cond:
        raise Fail(msg)


def eq(a, b, msg=''):
    if a != b:
        raise Fail('%s: %r != %r' % (msg, a, b))


def run_cases(only=None, area=None, verbose=True, timeout=120):
    res = []
    for (ar, nm, fn, kb) in REGISTRY:
        if area and ar != area:
            continue
        if only and only not in nm:
            continue
        t0 = time.time()
        signal.signal(signal.SIGALRM, lambda *a: (_ for _ in ()).throw(Fail('timeout')))
        signal.alarm(timeout)
        try:
            fn()
            st, info = 'PASS', ''
            if kb:
                st, info = 'FIXED?', 'marked known bug but passed: ' + kb
        except Skip as e:
            st, info = 'SKIP', str(e)
        except Fail as e:
            st, info = ('XFAIL' if kb else 'FAIL'), str(e)
        except Exception as e:
            st = 'XFAIL' if kb else 'ERROR'
            info = ''.join(traceback.format_exception_only(type(e), e)).strip()
            if st == 'ERROR':
                info += ' | ' + traceback.format_exc().splitlines()[-3].strip()
        finally:
            signal.alarm(0)
        res.append((ar, nm, st, info, time.time() - t0))
        if verbose:
            print('%-6s %-10s %-44s %5.1fs %s' % (st, ar, nm, time.time() - t0,
                  info[:200]), flush=True)
    return res


HEXOFF = re.compile(r'[|\u2502\u2503\u254f\u257f\u257d\u2575\u2577] +([0-9a-f]{8}) ')


def hex_off(v, y=2):
    """File offset shown at the start of hex row y (None when not a hex row)."""
    m = HEXOFF.search(v.row(y))
    return int(m.group(1), 16) if m else None


def FIX(name):
    """Path of a synthetic fixture (see mkfixtures.py); built on demand."""
    p = os.path.join(VT, 'fixtures', name)
    if not os.path.exists(p):
        import mkfixtures
        mkfixtures.build()
    return p


def main(area):
    """Entry point shared by the t_*.py modules: [-k substring]."""
    only = None
    if '-k' in sys.argv:
        only = sys.argv[sys.argv.index('-k') + 1]
    r = run_cases(area=area, only=only)
    sys.exit(1 if any(x[2] in ('FAIL', 'ERROR') for x in r) else 0)
