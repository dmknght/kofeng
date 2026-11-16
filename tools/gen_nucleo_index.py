#!/usr/bin/env python3
"""
gen_nucleo_index.py - writes libgenome/celllysis/nucleo_index.c: for every table of names (nucleo_names_<target>.c) a CONST open-addressing index
of its rows, so that a name is found by its hash and not by reading the rows in turn. Nothing is built at run time and nothing writable is shared.

    gen_nucleo_index.py <out.c> <celllysis dir>

The tables are read from the sources: the order of the targets is that of `tables[]` in nucleo.c (an id is a position over the tables laid end to
end), the names are the `.name = "..."` of each row in order, and `.fold` is the table's own. The hash is FNV-1a (32 bit) over the bytes of the name
up to its NUL, folded to ASCII lower case for a `fold` table - the function nucleo.c computes for the name it is asked about (nidx_hash there). Slots
hold the row's position + 1, 0 is empty, linear probing, the capacity the power of two at or over twice the rows (at least 4); equal names are placed in
row order so the first row is found first, as in the scan.

THE SHAPES (nucleo_private.h, KGENOME_SHAPE): each row's spec is read from its initializer, a row without one takes its capability's
(nucleo_capshape.c), and the distinct shapes are written once (kgenome_nucleo_shapes, index 0 the empty shape) with one index per row
over the tables laid end to end (kgenome_nucleo_row_shape) and one per capability of nucleo_capshape.c (kgenome_nucleo_capshape_shape).
The role words are the enumerators of enum kgenome_diag_role (libgenome/phenotype/diag_vocab.h), read from there so a number is never
written twice. A spec the grammar does not allow, a role twice in one shape, an index past 7, or a word after `unverified` stops it.

A table the index cannot hold stops the generator: an empty name, a name holding "@" (a lookup ends at "@", so that name would be unreachable by hash)
or 65535 rows or more. Regenerate when a nucleo_names_*.c changes; tests/lib/genome/nucleo_index.c asks every row of every table against the scan, so a
stale file fails it. No make target regenerates it (REV-D16); the emitted file carries no comment saying so (this sentence said it did until
2026-11-15, and the generator never wrote one).
"""
import re
import sys

TOKEN = re.compile(r'"(?:[^"\\\n]|\\.)*"|/\*.*?\*/|//[^\n]*', re.S)


def strip(src):
    """The source with its comments blanked and its strings kept."""
    return TOKEN.sub(lambda m: m.group(0) if m.group(0)[0] == '"' else " ", src)


def unescape(lit):
    return bytes(lit[1:-1], "utf-8").decode("unicode_escape").encode("latin-1")


def order(nucleo_c):
    body = re.search(r"tables\[\]\s*=\s*\{(.*?)\};", strip(open(nucleo_c).read()), re.S).group(1)
    return re.findall(r"&kgenome_nucleo_names_(\w+)", body)


def macros(nucleo_h):
    """The string macros of nucleo.h (a row may spell its name by one: "(dynamic)", "(load)")."""
    return {m.group(1): m.group(2) for m in re.finditer(r'#define\s+(\w+)\s+("(?:[^"\\\n]|\\.)*")\s*$', strip(open(nucleo_h).read()), re.M)}


ROW = re.compile(r'\{\s*\.name\s*=\s*("(?:[^"\\\n]|\\.)*"|\w+)\s*,\s*\.cap\s*=\s*(\w+)([^{}]*)\}')
SPEC = re.compile(r'KGENOME_SHAPE\(\s*("(?:[^"\\\n]|\\.)*")\s*\)')


def table(path, mac):
    """The rows of one table: (name bytes, cap symbol, spec or None), in order, and the table's fold."""
    src = strip(open(path).read())
    rows = []
    for m in ROW.finditer(src):
        nm = m.group(1)
        if nm[0] != '"' and nm not in mac:
            sys.exit("%s: a row names itself by %s, which is not a string macro of nucleo.h" % (path, nm))
        sp = SPEC.search(m.group(3))
        rows.append((unescape(nm if nm[0] == '"' else mac[nm]), m.group(2), sp.group(1)[1:-1] if sp else None))
    # every `.name =` must have been a row the pattern read: a row written another way would lose its shape silently
    if len(rows) != len(re.findall(r'\.name\s*=', src)):
        sys.exit("%s: %d rows read, %d `.name =` in the file - a row is not of the form { .name = .., .cap = .., ... }" %
                 (path, len(rows), len(re.findall(r'\.name\s*=', src))))
    fold = int(re.search(r"\.fold\s*=\s*(\d+)", src).group(1))
    return rows, fold


def capshapes(path):
    """nucleo_capshape.c: (cap symbol, spec) in order."""
    src = strip(open(path).read())
    body = re.search(r"kgenome_nucleo_capshape_cap\[\]\s*=\s*\{(.*?)\};", src, re.S).group(1)
    out = re.findall(r'(KGENOME_NUCLEO_\w+)\s*,\s*KGENOME_SHAPE\(\s*"([^"]*)"\s*\)', body)
    if len(out) != len(re.findall(r'KGENOME_NUCLEO_\w+', body)):
        sys.exit("%s: every capability must be followed by its KGENOME_SHAPE" % path)
    caps = [c for c, _ in out]
    if len(set(caps)) != len(caps):
        sys.exit("%s: a capability listed twice" % path)
    return out


def roles(vocab_h):
    """enum kgenome_diag_role's enumerators -> their values."""
    body = re.search(r"enum\s+kgenome_diag_role\s*\{(.*?)\};", strip(open(vocab_h).read()), re.S).group(1)
    names = [n.strip().split("=")[0].strip() for n in body.split(",") if n.strip()]
    if names[0] != "KGENOME_DIAG_ROLE_NONE":
        sys.exit("diag_vocab.h: enum kgenome_diag_role does not start at NONE")
    return {n: i for i, n in enumerate(names)}


RES = ["status", "status0", "value", "handle", "pointer", "codeptr", "void", "noret"]
WORD = {"fd": "FD", "buf": "BUFFER", "src": "SOURCE", "path": "PATH", "val": "VALUE", "tgt": "TARGET"}
HOW = {"direct": 1, "field": 2, "remote": 3}
NONE = 0xff


def shape(spec, rv, label):
    """A spec -> a tuple in the C struct's member order."""
    role = [0] * 8
    field = 0
    res = 0
    out = []
    entry, how, rel, name, nkind = NONE, 0, NONE, NONE, 0
    for w in spec.split():
        m = re.fullmatch(r"(fd|buf|src|path|val|tgt|field|out|entry|rel|name|nameobj)([0-9]+)", w)
        if m:
            k = int(m.group(2))
            if k > 7 and m.group(1) not in ("out",):
                sys.exit("%s: %r - an argument index past 7" % (label, w))
            if k > 15:
                sys.exit("%s: %r - an out index past 15" % (label, w))
            kind = m.group(1)
            if kind in WORD:
                r = rv["KGENOME_DIAG_ROLE_" + WORD[kind]]
                if r in role:
                    sys.exit("%s: role %s twice in one shape" % (label, kind))
                if role[k]:
                    sys.exit("%s: argument %d given two roles" % (label, k))
                role[k] = r
            elif kind == "field":
                field |= 1 << k
            elif kind == "out":
                if len(out) == 2:
                    sys.exit("%s: more than two out arguments" % label)
                out.append(k)
            elif kind == "entry":
                entry, how = k, (how or 1)
            elif kind == "rel":
                rel = k
            else:
                name, nkind = k, (1 if kind == "name" else 2)
            continue
        m = re.fullmatch(r"res=(\w+)", w)
        if m and m.group(1) in RES:
            res = RES.index(m.group(1))
            continue
        m = re.fullmatch(r"entry=(\w+)", w)
        if m and m.group(1) in HOW:
            how = HOW[m.group(1)]
            continue
        sys.exit("%s: %r is not a word of the shape grammar (nucleo_private.h, KGENOME_SHAPE)" % (label, w))
    for k in range(8):
        if field >> k & 1 and not role[k] and entry != k and name != k:
            sys.exit("%s: field%d on an argument with no role, entry or name" % (label, k))
    if how and entry == NONE:
        sys.exit("%s: entry= without entry<k>" % label)
    if entry != NONE and role[entry] != rv["KGENOME_DIAG_ROLE_TARGET"]:
        sys.exit("%s: entry%d on an argument that is not tgt%d (an entry is where execution goes)" % (label, entry, entry))
    out += [NONE] * (2 - len(out))
    return tuple(role) + (field, res, out[0], out[1], entry, how, rel, name, nkind)


def fnv(name, fold):
    h = 2166136261
    for c in name:
        if fold and 65 <= c <= 90:
            c += 32
        h = ((h ^ c) * 16777619) & 0xffffffff
    return h


def slots(rows, fold, label):
    names = [r[0] for r in rows]
    if len(names) >= 0xffff:
        sys.exit("%s: %d rows do not fit a 16-bit slot" % (label, len(names)))
    cap = 4
    while cap < 2 * len(names):
        cap *= 2
    t = [0] * cap
    for i, nm in enumerate(names):
        if not nm or b"@" in nm:
            sys.exit("%s: row %d (%r) is a name the index cannot hold" % (label, i, nm))
        j = fnv(nm, fold) & (cap - 1)
        while t[j]:
            j = (j + 1) & (cap - 1)
        t[j] = i + 1
    return t


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    out, d = sys.argv[1], sys.argv[2].rstrip("/")
    targets = order(d + "/nucleo.c")
    mac = macros(d + "/nucleo.h")
    rv = roles(d + "/../phenotype/diag_vocab.h")
    text = ['/* GENERATED by tools/gen_nucleo_index.py from nucleo_names_*.c and nucleo_capshape.c - do not edit; see that file. */', '',
            '#include "nucleo_private.h"', '']
    shapes = [shape("", rv, "empty")]
    def intern(t):
        if t not in shapes:
            shapes.append(t)
        return shapes.index(t)
    capdef = {}
    capidx = []
    for c, sp in capshapes(d + "/nucleo_capshape.c"):
        i = intern(shape(sp, rv, c))
        capdef[c] = i
        capidx.append(i)
    rowidx = []
    shape_t = []
    for t in targets:
        rows, fold = table("%s/nucleo_names_%s.c" % (d, t), mac)
        for nm, cap, sp in rows:
            rowidx.append(intern(shape(sp, rv, "%s:%s" % (t, nm.decode("latin-1")))) if sp is not None else capdef.get(cap, 0))
        s = slots(rows, fold, t)
        shape_t.append((t, len(s), len(rows)))
        text.append("static const uint16_t idx_%s[%d] = {" % (t, len(s)))
        for k in range(0, len(s), 16):
            text.append("\t" + ", ".join(str(v) for v in s[k:k + 16]) + ",")
        text.append("};")
        text.append("")
    text.append("const struct kgenome_nucleo_index kgenome_nucleo_index[] = {")
    for t, cap, n in shape_t:
        text.append("\t{ %d, %d, idx_%s }," % (cap, n, t))
    text.append("};")
    text.append("")
    text.append("/* role[8], field, res, out[2], entry, entry_how, release, name, name_kind - struct kgenome_nucleo_shape */")
    text.append("const struct kgenome_nucleo_shape kgenome_nucleo_shapes[%d] = {" % len(shapes))
    for x in shapes:
        text.append("\t{ { %s }, %d, %d, { %d, %d }, %d, %d, %d, %d, %d }," % ((", ".join(str(v) for v in x[:8]),) + x[8:]))
    text.append("};")
    text.append("")
    text.append("const uint32_t kgenome_nucleo_rows_n = %d;" % len(rowidx))
    text.append("const uint16_t kgenome_nucleo_row_shape[%d] = {" % len(rowidx))
    for k in range(0, len(rowidx), 16):
        text.append("\t" + ", ".join(str(v) for v in rowidx[k:k + 16]) + ",")
    text.append("};")
    text.append("")
    text.append("const uint16_t kgenome_nucleo_capshape_shape[%d] = {" % len(capidx))
    text.append("\t" + ", ".join(str(v) for v in capidx) + ",")
    text.append("};")
    open(out, "w").write("\n".join(text) + "\n")


main()
