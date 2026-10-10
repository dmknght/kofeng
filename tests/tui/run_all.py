#!/usr/bin/env python3
"""run_all.py - run every t_*.py in parallel, print pass/fail per case + summary.

  python3 run_all.py            all modules, 4 at a time
  python3 run_all.py -j 8       more parallelism
  python3 run_all.py menu tree  only modules whose name contains one of these
  python3 run_all.py -k find    only cases whose name contains 'find'
  python3 run_all.py --viewer /path/to/kofviewer   test another binary

Statuses: PASS, FAIL, ERROR (harness exception), SKIP, XFAIL (a documented
known bug still failing), FIXED? (a known-bug case that now passes: remove its
known_bug marker).  Exit status is 1 when anything is FAIL or ERROR.
Scratch files live under /mnt/games/kofscratch (never /tmp); samples are
copied read-only before the viewer sees them.
"""
import glob, os, subprocess, sys, time, concurrent.futures as cf

HERE = os.path.dirname(os.path.abspath(__file__))


def cleanup_stale():
    """Remove per-process scratch dirs left by killed test processes."""
    import shutil, re
    vt = os.path.join(os.environ.get('KOF_SCRATCH', '/mnt/games/kofscratch'), 'vt')
    cands = [os.path.join(vt, 'work', d) for d in os.listdir(os.path.join(vt, 'work'))] if os.path.isdir(os.path.join(vt, 'work')) else []
    cands += [os.path.join(vt, d) for d in os.listdir(vt) if d.startswith('bases_copy_p')] if os.path.isdir(vt) else []
    for d in cands:
        m = re.search(r'p(\d+)$', d)
        if not m or not os.path.isdir(d):
            continue
        try:
            os.kill(int(m.group(1)), 0)
            continue                      # that process is still alive
        except OSError:
            pass
        for root, ds, fs in os.walk(d):
            for f in fs:
                try:
                    os.chmod(os.path.join(root, f), 0o644)
                except OSError:
                    pass
        shutil.rmtree(d, ignore_errors=True)


def main(argv):
    jobs, pats, kfilter, viewer = 4, [], None, None
    it = iter(argv)
    for a in it:
        if a == '-j':
            jobs = int(next(it))
        elif a == '-k':
            kfilter = next(it)
        elif a == '--viewer':
            viewer = next(it)
        else:
            pats.append(a)
    mods = sorted(glob.glob(os.path.join(HERE, 't_*.py')))
    if pats:
        mods = [m for m in mods if any(p in os.path.basename(m) for p in pats)]
    env = dict(os.environ)
    if viewer:
        env['KOFVIEWER'] = viewer
    sys.path.insert(0, HERE)
    import mkfixtures
    mkfixtures.build()          # once, before the workers start

    def run(m):
        cmd = [sys.executable, m] + (['-k', kfilter] if kfilter else [])
        t0 = time.time()
        p = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=HERE)
        return m, p.stdout, p.stderr, time.time() - t0

    rows = []
    t0 = time.time()
    with cf.ThreadPoolExecutor(jobs) as ex:
        for m, out, err, dt in ex.map(run, mods):
            name = os.path.basename(m)
            print('=== %s (%.0fs)' % (name, dt), flush=True)
            for line in out.splitlines():
                print(line)
                parts = line.split(None, 2)
                if parts and parts[0] in ('PASS', 'FAIL', 'ERROR', 'SKIP', 'XFAIL', 'FIXED?'):
                    rows.append((parts[0], name, parts[2] if len(parts) > 2 else ''))
            if err.strip():
                print('  [stderr] ' + err.strip().splitlines()[-1][:200])
                rows.append(('ERROR', name, 'module stderr: ' + err.strip().splitlines()[-1][:120]))
    try:
        import json
        with open(os.path.join(os.environ.get('KOF_SCRATCH', '/mnt/games/kofscratch'), 'vt', 'last_run.json'), 'w') as f:
            json.dump(rows, f, indent=0)
    except OSError:
        pass
    cleanup_stale()
    cnt = {}
    for st, _, _ in rows:
        cnt[st] = cnt.get(st, 0) + 1
    print('\n==== SUMMARY (%.0fs): %s' % (time.time() - t0,
          '  '.join('%s=%d' % (k, cnt[k]) for k in sorted(cnt))))
    bad = [r for r in rows if r[0] in ('FAIL', 'ERROR')]
    for st, mod, rest in bad:
        print('  %-6s %s %s' % (st, mod, rest[:150]))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
