"""kofexaminer --blocks / --hashes: the units the matcher reads, with every hash.

The listing is the engine's own cut printed, so what is pinned is its shape and
its arithmetic: each unit's pool is the strictly ascending set of its distinct
window hashes, `windows=` says how many, the block is the K smallest of the pool,
and with a database the normalised view is listed on its own."""
import re
import subprocess
from tui import *

A = 'examiner'
EXAMINER = os.environ.get('KOFEXAMINER', REPO + '/build/release/bin/kofexaminer')
UNIT = re.compile(r'^\s+unit\s+region=(\S+)\s+off=(0x[0-9a-f]+)\s+len=(\d+)\s+side=(\S+)'
                  r'(?:\s+func=(\S+))?\s+windows=(\d+|-)\s+(?:cfg_blocks=(\d+)\s+)?block_id=(\S+)')


def run(*args):
    p = subprocess.run([EXAMINER, '--no-color'] + list(args), capture_output=True,
                       text=True, timeout=300)
    return p.stdout.splitlines()


def units(lines, hashes=False):
    out = []
    for i, l in enumerate(lines):
        m = UNIT.match(l)
        if not m:
            continue
        blk = lines[i + 1].split()[1:] if lines[i + 1].strip().startswith('block') else []
        pool = lines[i + 2].split()[1:] if hashes and lines[i + 2].strip().startswith('pool') else None
        out.append(dict(region=m.group(1), off=int(m.group(2), 16), len=int(m.group(3)),
                        side=m.group(4), func=m.group(5), windows=None if m.group(6) == '-' else int(m.group(6)),
                        cfg=None if m.group(7) is None else int(m.group(7)), id=m.group(8), block=[int(x, 16) for x in blk],
                        pool=None if pool is None else [int(x, 16) for x in pool]))
    return out


@case(A)
def no_flag_no_listing():
    check(not [l for l in run(SAMPLES['gafgyt']) if 'unit ' in l or l.strip().startswith('blocks')],
          'the listing appeared without being asked for')


@case(A)
def blocks_lists_units_with_functions_and_a_block_each():
    u = units(run('--blocks', SAMPLES['gafgyt']))
    check(len(u) >= 20, 'too few units: %d' % len(u))
    check([x for x in u if x['func']], 'no function unit')
    # CFG step 2c: a function unit has no windows; it is signed by the shape of its function (cfg_blocks=N, an id, 12..32 keys) when N reaches the floor
    # (12 reachable blocks), and says it is not (block_id=-, no block line) when it does not. A data unit has windows and a block.
    check(all(x['windows'] is None for x in u if x['func']), 'a function unit carries windows')
    signed = [x for x in u if x['func'] and x['cfg'] is not None]
    check(signed, 'no function unit is signed by its CFG')
    check(all(x['cfg'] >= 12 and re.fullmatch(r'[0-9a-f]{8}', x['id']) and 12 <= len(x['block']) <= min(32, x['cfg']) for x in signed), 'a signed function unit: blocks below the floor, no id or keys outside 12..32')
    check(all(x['id'] == '-' and not x['block'] for x in u if x['func'] and x['cfg'] is None), 'an unsigned function unit carries an id or a block')
    check([x for x in u if not x['func'] and x['windows'] and x['block']], 'no data unit with a block')
    for x in u:
        check(len(x['block']) <= 32, 'a block has more than K values')
        check(x['block'] == sorted(set(x['block'])), 'block not ascending and distinct')
        check(x['id'] == '-' or re.fullmatch(r'[0-9a-f]{8}', x['id']), 'bad block id %r' % x['id'])
        check(x['side'] in ('USER', 'LIB'), x['side'])


@case(A)
def hashes_pool_is_the_ascending_set_and_the_block_is_its_smallest():
    u = units(run('--hashes', SAMPLES['gafgyt']), hashes=True)
    check(len(u) >= 20, 'too few units')
    check([x for x in u if x['func']] and all(x['pool'] is None for x in u if x['func']), 'a function unit prints a pool (no function signature yet)')
    for x in [x for x in u if not x['func']]:
        check(x['pool'] is not None, 'no pool printed')
        eq(len(x['pool']), x['windows'], 'windows= says %d, the pool has %d' % (x['windows'], len(x['pool'])))
        check(x['pool'] == sorted(set(x['pool'])), 'pool not strictly ascending')
        eq(x['block'], x['pool'][:32], 'the block is not the smallest 32 of the pool')


@case(A)
def a_units_blocks_are_what_the_engine_hashes():
    """The id is the fold of the block, as a rule's verdict spells it: two runs agree."""
    a = units(run('--blocks', SAMPLES['gafgyt']))
    b = units(run('--blocks', SAMPLES['gafgyt']))
    check(a, 'no units listed')
    eq([(x['off'], x['id']) for x in a], [(x['off'], x['id']) for x in b], 'listing is not deterministic')


@case(A)
def the_normalised_view_is_listed_on_its_own_with_a_database():
    lines = run('--blocks', '--db', REPO + '/build/release/databases', SAMPLES['gafgyt'])
    heads = [l for l in lines if l.strip().startswith('blocks')]
    check(len(heads) >= 2, 'no second listing for the view: %r' % heads)
    check(any('normalised view' in h for h in heads), 'the view is not labelled')
    view = units(lines[[i for i, l in enumerate(lines) if 'normalised view' in l][0]:])
    check(view, 'the view has no units')
    check(not [x for x in view if x['side'] == 'LIB'], 'the view still offers library units')



RUN1 = os.environ.get('KOF_RUN1', '/mnt/games/normtest/scan_run1/run1')


@case(A)
def verdict_is_explained_with_the_matchers_from_the_pull_api():
    """kofexaminer prints WHY each matched diagnose matched, from kscan_explain / kdet_matcher_text - the words the viewer shows."""
    if not os.path.exists(RUN1):
        raise Skip('no sample at %s' % RUN1)
    out = run('--db', REPO + '/build/release/databases', '--bases', REPO + '/bases', RUN1)
    t = '\n'.join(out)
    check('verdict   Infected#ELF-x64/Botnet:Mirai.A' in t, 'no verdict:\n' + t)
    check(re.search(r'why\s+\S+//0:norm', t), 'no why block for the object with the verdict:\n' + t)
    # Prototype 2026-10-30: the six flood diagnoses (function blocks) are not scored; the two data-block diagnoses are explained.
    check(t.count('matcher 0  similarity 100% of the 1 block(s), 70% demanded')   >= 2, 'the two similarity matchers are not all explained:\n' + t)
    check('form' in t[t.index('why'):], 'the kind is missing')
    check(len(re.findall(r'part 0  block [0-9a-f]{8} yes: holds 32 of 32 hashes \(100%\), cut from DATA; place 0x[0-9a-f]+ \+\d+ in DATA holds 32', t)) >= 2,
          'the two blocks with their places are not all printed:\n' + t)
    check('cut from CODE' not in t, 'a block cut from a function is explained though function units are not scored:\n' + t)


@case(A)
def a_clean_file_is_not_explained():
    out = run('--db', REPO + '/build/release/databases', '--bases', REPO + '/bases', os.path.realpath('/bin/ls'))
    check(not [l for l in out if l.startswith('  why')], 'a file with no verdict was explained')

if __name__ == '__main__':
    main(A)
