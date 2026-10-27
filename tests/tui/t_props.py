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


def dashboard(v, tab='Overview'):
    """The lines of the dashboard's page `tab`, without the box."""
    open_dash_tab(v, tab)
    rows = [v.row(y) for y in range(2, v.rows - 1)]
    return [r[r.index('│') + 1:].rstrip('│ ') for r in rows if '│' in r]


def layout_lines(v):
    """The lines of the Segments page and then those of the Sections page."""
    return dashboard(v, 'Segments') + dashboard(v, 'Sections')


def table_rows(lines, first_col='#'):
    """Cells of every row of the layout tables: [(cells...)] split on blanks, after the wall of a framed table."""
    out = []
    for l in lines:
        l = l.replace('│', ' ').strip()
        c = l.split()
        if c and c[0].isdigit() and len(c) >= 5:
            out.append(c)
    return out


def section_rows(lines):
    """(name, offset, size) of each section row of the Sections tab: # name type flags addr offset size ..."""
    out = []
    for c in table_rows(lines):
        if len(c) >= 10 and c[2].startswith(('SHT_', '0x')) and re.match(r'0x[0-9a-f]+$', c[5]):
            out.append((c[1], c[5], int(c[6])))
    return out


def segment_rows(lines):
    """(type, flags, offset, filesz) of each segment row: # type flags offset vaddr filesz memsz align entropy."""
    out = []
    for c in table_rows(lines):
        if len(c) == 9 and re.match(r'[R-][W-][X-]$', c[2]) and re.match(r'0x[0-9a-f]+$', c[3]):
            out.append((c[1], c[2], c[3], int(c[5])))
    return out


@case(A)
def elf_dashboard_offsets_are_hex():
    with Viewer(SAMPLES['gafgyt']) as v:
        lines = layout_lines(v)
        segs, secs = segment_rows(lines), section_rows(lines)
        check(len(segs) >= 3 and len(secs) >= 6, 'no segment/section rows: %r' % lines[:12])
        for s in segs:
            check(re.match(r'0x[0-9a-f]+$', s[2]), 'offset not hex: %r' % (s,))
        for s in secs:
            check(re.match(r'0x[0-9a-f]+$', s[1]), 'offset not hex: %r' % (s,))
        off = [l for l in dashboard(v) if re.search(r'file offset +0x[0-9a-f]+', l)]
        check(off, 'entry file offset row missing or not hex')


@case(A)
def elf_dashboard_rows_carry_the_files_numbers():
    """A smoke of the whole path on a real file: the Segments and Sections tabs draw as many segment and section rows as the file has. What
    each cell says is asserted on the data against the bytes (tests/unit/kx_dashdata.c)."""
    with Viewer(SAMPLES['gafgyt']) as v:
        lines = layout_lines(v)
        secs, segs = elf_tables(SAMPLES['gafgyt'])
        eq(len(section_rows(lines)), len([k for k in secs if k]), 'section rows drawn (the null section has no name to match on)')
        eq(len(segment_rows(lines)), len(segs), 'segment rows drawn')


@case(A)
def unnamed_segment_type_is_hex_not_a_decimal_wall():
    """PT_ARM_EXIDX has no name here; it used to print as 1879048193."""
    with Viewer(SAMPLES['gafgyt']) as v:
        types = [t for t, f, o, s in segment_rows(layout_lines(v))]
        check(types, 'no segment rows')
        for t in types:
            check(not re.match(r'\d{6,}$', t), 'type printed in decimal: %r' % t)
        check(any(t.startswith('0x') for t in types), 'the unnamed type is not hex: %r' % types)


@case(A)
def dashboard_segment_and_section_tables_share_one_left_edge():
    with Viewer(SAMPLES['gafgyt']) as v:
        xs = set()
        for tab in ('Segments', 'Sections'):
            lines = dashboard(v, tab)
            xs |= {l.replace('\u2502', ' ').index('#') for l in lines if l.replace('\u2502', ' ').strip().startswith('#')}
        eq(len(xs), 1, 'the two tables do not start in one column: %r' % xs)
        check(max(xs) <= 20, 'tables pushed in too far: %r' % xs)


@case(A)
def layout_tabs_have_no_declared_rows_when_the_counts_agree():
    with Viewer(SAMPLES['gafgyt']) as v:
        for tab in ('Segments', 'Sections'):
            lines = dashboard(v, tab)
            t = '\n'.join(lines)
            check('declared' not in t, 'a declared-count row is back: %r' % lines[:6])
            check('entropy' in t and '#' in t, '%s: the table (with its entropy column) is missing: %r' % (tab, lines[:6]))


@case(A)
def pe_dashboard_offsets_are_hex():
    path = pick(SAMPLES['pe'], 1, 30000, 200000)[0]
    with Viewer(path) as v:
        lines = dashboard(v)
        for l in lines:
            m = re.search(r'file offset +(\S+)', l)
            if m:
                check(m.group(1).startswith('0x'), 'file offset not hex: %r' % l)
        lay = layout_lines(v)
        rows = [c for c in table_rows(lay) if len(c) >= 8 and re.match(r'0x[0-9a-f]+$', c[4])]
        check(rows, 'no PE section rows: %r' % lay[:10])
        check(any('mapped by its sections' in l for l in lay), 'the PE layout does not say it has no segments')


if __name__ == '__main__':
    main(A)
