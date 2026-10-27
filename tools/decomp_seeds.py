#!/usr/bin/env python3
"""decomp_seeds.py - seed streams and a verdict for the decompress fuzz adapters, from Python's own zlib, bz2 and lzma modules.

  decomp_seeds.py seeds DIR      write valid streams (no blobs are stored in the tree) that the fuzz binary takes with --corpus DIR:
                                   deflate_*.bin  raw DEFLATE (zlib, levels 1/6/9, strategies, a stored block)
                                   bz2_*.bin      bzip2 streams (block sizes 1 and 9, a run, noise, two streams in a row)
                                   lzma1_*.bin    [properties byte][raw LZMA1 stream], the layout of the kuncoat/lzma adapter
                                   lzma2_*.bin    raw LZMA2 (several chunks)
                                 The deterministic generator is fixed: the same files every run.
  decomp_seeds.py verdict CODEC FILE
                                 what the reference decoder says about a file the fuzz binary saved (build/fuzz/found/*.bin):
                                 `ok <bytes> <sha1>` or `error <why>`. CODEC: deflate, bz2, lzma1 (first byte = lc/lp/pb), lzma2.
                                 A disagreement with kuncoat is a finding to CLASSIFY (lenient: ours OK, the reference refuses; strict:
                                 the reverse; the adapters hold the strict direction), not necessarily a defect.
The same oracles are linked into the adapters themselves (libz, libbz2, liblzma); this script is for looking at one saved input.
"""
import bz2, hashlib, lzma, os, random, sys, zlib


def plain_texts():
    r = random.Random(20261024)
    text = (b'pack my box with five dozen liquor jugs. the quick brown fox jumps over the lazy dog. ' * 400)[:30000]
    run = b'A' * 50000
    noise = bytes(r.getrandbits(8) for _ in range(6000))
    periodic = bytes(((i % 7) * 31 + i // 1000) & 255 for i in range(20000))
    return {'text': text, 'run': run, 'noise': noise, 'periodic': periodic, 'short': text[:7], 'empty': b''}


def write(d, name, data):
    with open(os.path.join(d, name), 'wb') as f:
        f.write(data)


def raw_deflate(data, level, strategy=zlib.Z_DEFAULT_STRATEGY):
    c = zlib.compressobj(level, zlib.DEFLATED, -15, 8, strategy)
    return c.compress(data) + c.flush()


def seeds(d):
    os.makedirs(d, exist_ok=True)
    t = plain_texts()
    for name, data in t.items():
        for lvl in (1, 6, 9):
            write(d, 'deflate_%s_%d.bin' % (name, lvl), raw_deflate(data, lvl))
    write(d, 'deflate_text_fixed.bin', raw_deflate(t['text'][:200], 6, zlib.Z_FIXED))
    write(d, 'deflate_text_huffman_only.bin', raw_deflate(t['text'], 6, zlib.Z_HUFFMAN_ONLY))
    write(d, 'deflate_stored.bin', bytes([1, 64, 0, 0xbf, 0xff]) + t['text'][:64])
    for name, data in t.items():
        for lvl in (1, 9):
            write(d, 'bz2_%s_%d.bin' % (name, lvl), bz2.compress(data, lvl))
    write(d, 'bz2_two_streams.bin', bz2.compress(t['text'][:700], 3) + bz2.compress(t['periodic'][:900], 3))
    for lc, lp, pb in ((3, 0, 2), (0, 2, 0), (4, 0, 4), (1, 3, 1)):
        props = (pb * 5 + lp) * 9 + lc
        flt = [{'id': lzma.FILTER_LZMA1, 'dict_size': 1 << 20, 'lc': lc, 'lp': lp, 'pb': pb}]
        for name in ('text', 'periodic', 'noise', 'short'):
            write(d, 'lzma1_%s_%d%d%d.bin' % (name, lc, lp, pb), bytes([props]) + lzma.compress(t[name], format=lzma.FORMAT_RAW, filters=flt))
    for name, data in t.items():
        flt = [{'id': lzma.FILTER_LZMA2, 'dict_size': 1 << 20}]
        write(d, 'lzma2_%s.bin' % name, lzma.compress(data, format=lzma.FORMAT_RAW, filters=flt))
    write(d, 'lzma2_noise_70k.bin', lzma.compress(bytes(random.Random(7).getrandbits(8) for _ in range(70000)), format=lzma.FORMAT_RAW,
                                                  filters=[{'id': lzma.FILTER_LZMA2, 'dict_size': 1 << 20}]))
    return 0


def verdict(codec, path):
    data = open(path, 'rb').read()
    try:
        if codec == 'deflate':
            d = zlib.decompressobj(-15)
            out = d.decompress(data)
            if not d.eof:
                raise ValueError('stream not complete')
        elif codec == 'bz2':
            out = b''
            rest = data
            while rest:
                d = bz2.BZ2Decompressor()
                out += d.decompress(rest)
                if not d.eof:
                    raise ValueError('stream not complete')
                rest = d.unused_data
                if not rest.startswith(b'BZh'):
                    break
        elif codec == 'lzma1':
            p = data[0]
            lc, p = p % 9, p // 9
            lp, pb = p % 5, p // 5
            out = lzma.decompress(data[1:], format=lzma.FORMAT_RAW,
                                  filters=[{'id': lzma.FILTER_LZMA1, 'dict_size': 1 << 20, 'lc': lc, 'lp': lp, 'pb': pb}])
        elif codec == 'lzma2':
            out = lzma.decompress(data, format=lzma.FORMAT_RAW, filters=[{'id': lzma.FILTER_LZMA2, 'dict_size': 1 << 20}])
        else:
            print('unknown codec', codec, file=sys.stderr)
            return 2
    except Exception as e:  # the reference refusing is an answer, not a failure of this script
        print('error', type(e).__name__, e)
        return 0
    print('ok', len(out), hashlib.sha1(out).hexdigest())
    return 0


def main(argv):
    if len(argv) == 2 and argv[0] == 'seeds':
        return seeds(argv[1])
    if len(argv) == 3 and argv[0] == 'verdict':
        return verdict(argv[1], argv[2])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
