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
                  r'(?:\s+func=(\S+))?\s+windows=(\d+)\s+block_id=(\S+)')


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
                        side=m.group(4), func=m.group(5), windows=int(m.group(6)),
                        id=m.group(7), block=[int(x, 16) for x in blk],
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
    for x in u:
        check(len(x['block']) <= 32, 'a block has more than K values')
        check(x['block'] == sorted(set(x['block'])), 'block not ascending and distinct')
        check(x['id'] == '-' or re.fullmatch(r'[0-9a-f]{8}', x['id']), 'bad block id %r' % x['id'])
        check(x['side'] in ('USER', 'LIB'), x['side'])


@case(A)
def hashes_pool_is_the_ascending_set_and_the_block_is_its_smallest():
    u = units(run('--hashes', SAMPLES['gafgyt']), hashes=True)
    check(len(u) >= 20, 'too few units')
    for x in u:
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


if __name__ == '__main__':
    main(A)
