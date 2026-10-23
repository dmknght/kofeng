#!/usr/bin/env python3
"""fuzz_expect.py - run a command and succeed only when it FAILS (--fail) or succeeds (--ok).

make fuzz-mutants uses it: the kit is built with a harness path broken on purpose, and its self-test is then expected to
report a planted defect as MISSED (exit status 1). A mutant whose self-test passes means the self-test does not
depend on that path."""
import subprocess, sys

def main(argv):
    want_fail = True
    if argv and argv[0] in ('--fail', '--ok'):
        want_fail = argv[0] == '--fail'
        argv = argv[1:]
    if argv and argv[0] == '--':
        argv = argv[1:]
    if not argv:
        print('usage: fuzz_expect.py [--fail|--ok] -- command...', file=sys.stderr)
        return 2
    r = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors='replace')
    failed = r.returncode != 0
    if failed != want_fail:
        sys.stdout.write(r.stdout[-4000:])
        print('fuzz_expect: %s was expected to %s and %s (rc %d)' % (argv[0], 'fail' if want_fail else 'pass', 'passed' if want_fail else 'failed', r.returncode))
        return 1
    print('fuzz_expect: %s %s as expected' % (argv[0].split('/')[-1], 'failed' if want_fail else 'passed'))
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
