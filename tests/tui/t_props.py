"""Dashboard (Analysis > Dashboard): the ELF/PE rows say offsets in hex, indent
their segment and section rows the same, and carry the numbers the file holds."""
import struct
from dl import *
from tui import *

A = 'props'


def elf_tables(path):
    """{section name: (file_off, file_size)} and [(p_type, off, filesz)] read
    straight out of the file, so the dashboard is compared with the bytes and not
    with another reader of them."""
    d = open(path, 'rb').read()
    is64 = d[4] == 2
    en = '<' if d[5] == 1 else '>'
    if is64:
        (_, _, _, _, ph_off, sh_off, _, _, ph_sz, ph_n, sh_sz, sh_n, sh_str) = \
            struct.unpack(en + 'HHIQQQIHHHHHH', d[16:64])
    else:
        (_, _, _, _, ph_off, sh_off, _, _, ph_sz, ph_n, sh_sz, sh_n, sh_str) = \
            struct.unpack(en + 'HHIIIIIHHHHHH', d[16:52])

    def sh(i):
        o = sh_off + i * sh_sz
        if is64:
            nm, ty, fl, ad, off, sz = struct.unpack(en + 'IIQQQQ', d[o:o + 40])
        else:
            nm, ty, fl, ad, off, sz = struct.unpack(en + 'IIIIII', d[o:o + 24])
        return nm, ty, off, sz

    stro = sh(sh_str)[2]
    secs = {}
    for i in range(sh_n):
        nm, ty, off, sz = sh(i)
        e = d.index(b'\0', stro + nm)
        secs[d[stro + nm:e].decode('latin1')] = (off, sz)
    segs = []
    for i in range(ph_n):
        o = ph_off + i * ph_sz
        if is64:
            ty, fl, off, va, pa, fsz, msz, al = struct.unpack(en + 'IIQQQQQQ', d[o:o + 56])
        else:
            ty, off, va, pa, fsz, msz, fl, al = struct.unpack(en + 'IIIIIIII', d[o:o + 32])
        segs.append((ty, off, fsz))
    return secs, segs


def dashboard(v):
    check(v.menu_item('Analysis', 'Dashboard'), 'no Dashboard item')
    v.pump_quiet()
    rows = [v.row(y) for y in range(2, v.rows - 1)]
    return [r[r.index('│') + 1:].rstrip('│ ') for r in rows if '│' in r]


def section_rows(lines):
    out = []
    for l in lines:
        m = re.match(r'( +)(\S*) +off=(\S+) +size=(\d+)\s', l + ' ')
        if m and len(m.group(1)) < 12:
            out.append((len(m.group(1)), m.group(2), m.group(3), int(m.group(4))))
    return out


@case(A)
def elf_dashboard_offsets_are_hex():
    with Viewer(SAMPLES['gafgyt']) as v:
        lines = dashboard(v)
        offs = [l for l in lines if ' off=' in l]
        check(len(offs) >= 6, 'no segment/section rows: %r' % lines[:12])
        for l in offs:
            check(re.search(r' off=0x[0-9a-f]+\b', l), 'offset not hex: %r' % l)
        ent = [l for l in lines if re.match(r' +entry ', l)]
        check(ent and re.search(r'file 0x[0-9a-f]+', ent[0]), 'entry file offset not hex: %r' % ent)


@case(A)
def elf_dashboard_rows_carry_the_files_numbers():
    with Viewer(SAMPLES['gafgyt']) as v:
        rows = section_rows(dashboard(v))
        secs, segs = elf_tables(SAMPLES['gafgyt'])
        seen = 0
        for _, name, off, size in rows:
            if name in secs:
                eq((int(off, 16), size), secs[name], 'section %s' % name)
                seen += 1
        check(seen >= 5, 'only %d named sections compared' % seen)
        got = sorted((int(o, 16), s) for _, n, o, s in rows if n.startswith('PT_'))
        want = sorted((o, s) for t, o, s in segs if t in (1, 6, 7, 0x6474e551))
        check(got and all(g in [(o, s) for _, o, s in segs] for g in got),
              'segment rows %r not in the file\'s %r' % (got, segs))


@case(A)
def unnamed_segment_type_is_hex_not_a_decimal_wall():
    """PT_ARM_EXIDX has no name here; it used to print as 1879048193."""
    with Viewer(SAMPLES['gafgyt']) as v:
        for l in dashboard(v):
            check(not re.match(r' +\d{6,} +off=', l), 'type printed in decimal: %r' % l)


@case(A)
def dashboard_segment_and_section_rows_share_one_indent():
    with Viewer(SAMPLES['gafgyt']) as v:
        ind = {r[0] for r in section_rows(dashboard(v))}
        eq(len(ind), 1, 'rows indent differently: %r' % ind)
        check(max(ind) <= 5, 'rows pushed in too far: %r' % ind)


@case(A)
def pe_dashboard_offsets_are_hex():
    path = pick(SAMPLES['pe'], 1, 30000, 200000)[0]
    with Viewer(path) as v:
        lines = dashboard(v)
        offs = [l for l in lines if ' off=' in l]
        check(offs, 'no PE section rows: %r' % lines[:10])
        for l in offs:
            check(re.search(r' off=0x[0-9a-f]+\b', l), 'offset not hex: %r' % l)
        for l in lines:
            m = re.search(r'lfanew=(\S+)', l)
            if m:
                check(m.group(1).startswith('0x'), 'lfanew not hex: %r' % l)


if __name__ == '__main__':
    main(A)
