"""fuzz.py - seeded random input against kofviewer; looks for crashes/hangs.

usage: python3 fuzz.py [sample-key|path] [seed] [events]
A crash is a child killed by a signal.  The event list is printed so the run
can be replayed (same seed => same events; timing is not deterministic).
"""
import random, sys, time
from tui import *

KEYSET = ['up', 'down', 'left', 'right', 'pgup', 'pgdn', 'home', 'end', 'enter',
          'esc', 'tab', 'backtab', 'bs', 'del', 'f10', 'ctrl+f', 'ctrl+n',
          'ctrl+c', 'ctrl+v', 'ctrl+o', 'ctrl+space', 'ctrl+a', 'ctrl+e',
          'ctrl+u', 'ctrl+]', 'ctrl+\\']
TEXT = list('abcxyz019 *?[]()\\^$|+.-_%/') + ['0x10', 'é', 'GCC']


BIAS = False


def gen(rng, rows, cols):
    r = rng.random()
    x, y = rng.randint(1, cols), rng.randint(1, rows)
    if BIAS:
        # concentrate on the menu bar and the draft panel, where state lives
        q = rng.random()
        if q < 0.12:
            y = rng.randint(1, 3)
        elif q < 0.70:
            y = rng.randint(max(1, rows - 15), rows)
        if rng.random() < 0.5:
            x = rng.randint(1, min(cols, 70))
    if r < 0.30:
        return ('click', x, y)
    if r < 0.38:
        return ('rclick', x, y)
    if r < 0.50:
        return ('wheel', x, y, rng.random() < .5, rng.choice([1, 1, 3, 10]))
    if r < 0.55:
        return ('hwheel', x, y, rng.random() < .5)
    if r < 0.62:
        return ('drag', x, y, rng.randint(1, cols), rng.randint(1, rows))
    if r < 0.67:
        return ('motion', x, y)
    if r < 0.72:
        return ('dclick', x, y)
    if r < 0.77:
        return ('shiftclick', x, y)
    if r < 0.87:
        return ('key', rng.choice(KEYSET))
    if r < 0.96:
        return ('type', rng.choice(TEXT))
    return ('resize', rng.choice([24, 30, 40, 50, 70]), rng.choice([80, 100, 140, 170, 220]))


def apply(v, ev):
    k = ev[0]
    if k == 'click': v.click(ev[1], ev[2], settle=0.08)
    elif k == 'rclick': v.click(ev[1], ev[2], right=True, settle=0.08)
    elif k == 'dclick': v.dclick(ev[1], ev[2])
    elif k == 'shiftclick': v.click(ev[1], ev[2], mod=4, settle=0.08)
    elif k == 'wheel': v.wheel(ev[1], ev[2], up=ev[3], n=ev[4], settle=0.03)
    elif k == 'hwheel': v.hwheel(ev[1], ev[2], left=ev[3])
    elif k == 'drag': v.drag(ev[1], ev[2], ev[3], ev[4], steps=3)
    elif k == 'motion': v.motion(ev[1], ev[2])
    elif k == 'key': v.key(ev[1], settle=0.08)
    elif k == 'type': v.type(ev[1], settle=0.05)
    elif k == 'resize': v.resize(ev[1], ev[2], settle=0.2)


def run(path, seed, n=300, rows=50, cols=170, cwd=None, verbose=False):
    rng = random.Random(seed)
    v = Viewer(path, rows=rows, cols=cols, cwd=cwd or os.path.join(VT, 'cwd'))
    evs = []
    try:
        for i in range(n):
            ev = gen(rng, v.rows, v.cols)
            # never fuzz the quit chord/menu item: a clean exit is not a crash
            evs.append(ev)
            apply(v, ev)
            if not v.alive():
                if v.crashed():
                    return ('CRASH', v.exit_desc(), evs)
                return ('EXIT', v.exit_desc(), evs)
        return ('OK', '', evs)
    finally:
        v.close()


if __name__ == '__main__':
    os.makedirs(os.path.join(VT, 'cwd'), exist_ok=True)
    key = sys.argv[1] if len(sys.argv) > 1 else 'ko'
    path = SAMPLES.get(key, key)
    if os.path.isdir(path):
        path = pick(path, 1, 5000, 300000)[0]
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    BIAS = len(sys.argv) > 4 and sys.argv[4] == 'bias'
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 300
    st, info, evs = run(path, seed, n)
    print(st, info, 'after', len(evs), 'events')
    if st != 'OK':
        for e in evs[-15:]:
            print('  ', e)
