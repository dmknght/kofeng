"""Seeded random input (fuzz.py) as test cases: the viewer must not crash,
exit, or hang.  Replay a failure with:  python3 fuzz.py <sample> <seed> <events> [bias]"""
from tui import *
import fuzz

A = 'fuzz'


def go(key_or_path, seed, n=140, bias=False):
    path = SAMPLES.get(key_or_path, key_or_path)
    if os.path.isdir(path):
        path = pick(path, 1, 5000, 300000)[0]
    fuzz.BIAS = bias
    os.makedirs(os.path.join(VT, 'cwd'), exist_ok=True)
    st, info, evs = fuzz.run(path, seed, n)
    check(st == 'OK', '%s after %d events (%s): replay with `python3 fuzz.py %s %d %d%s`; last: %r' % (
        st, len(evs), info, key_or_path, seed, n, ' bias' if bias else '', evs[-4:]))


@case(A)
def fuzz_ko_plain():
    go('ko', 101)


@case(A)
def fuzz_ko_panel_biased():
    go('ko', 102, bias=True)


@case(A)
def fuzz_gafgyt_loaded_draft_biased():
    go('gafgyt', 103, bias=True)


@case(A)
def fuzz_pe_biased():
    go('pe', 104, bias=True)


@case(A)
def fuzz_static_elf_biased():
    go('elf255', 105, bias=True)


@case(A)
def fuzz_archive_biased():
    go(FIX('many.zip'), 106, bias=True)


@case(A)
def fuzz_event_log_biased():
    go(FIX('events.ktr'), 107, bias=True)


@case(A)
def fuzz_script_biased():
    go(FIX('shell.php'), 108, bias=True)


@case(A)
def fuzz_raw_tiny():
    go(FIX('tiny.bin'), 109, bias=True)


@case(A)
def fuzz_diagnose_sample_biased():
    go(SCRATCH + '/rk/diamorphine.ko', 110, bias=True)


if __name__ == '__main__':
    main(A)
