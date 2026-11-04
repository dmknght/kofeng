#!/usr/bin/env python3
"""ppc_vectors_gen.py - writes tests/lib/genome/ppc_asm_vectors.inc: PowerPC instruction words assembled by an
INDEPENDENT assembler, each with the identity and the fields its source line says.

NEEDS (outside this tree, so this is not built by make): clang with the PowerPC targets (`clang -print-targets`
lists ppc32 / ppc64), reached through CLANG (default `clang`; a flatpak host: CLANG="flatpak-spawn --host clang").
Usage: ppc_vectors_gen.py > tests/lib/genome/ppc_asm_vectors.inc

WHY: the decode table and the hand-written words in the tests are written by the same person from the same
manual; an assembler is not. A vector is "this assembly line, these operands, assembled by the LLVM assembler":
the test decodes the word and requires the identity and every operand the line named. A field read from the
wrong bits, or an extended opcode transcribed wrongly, fails here. Words the LLVM assembler does not know
(601 segment registers, tlbia, mftb's own encoding, lswx, stswx, eciwx, ecowx, a negative absolute branch) are not here; the tests carry those by hand.
"""
import os, struct, subprocess, sys, tempfile

CLANG = os.environ.get("CLANG", "clang").split()
SCRATCH = os.environ.get("PPC_VEC_TMP", ".")

# field names in the order of the C struct
F = ["rt", "ra", "rb", "simm", "bo", "bi", "lk", "aa", "rc", "oe", "sh", "mb", "me", "spr", "off"]

V = []   # (target, cpu, asm, ID, {field: value})


def add(asm, id_, fields=None, tgt="powerpc-linux-gnu", cpu="ppc"):
    V.append((tgt, cpu, asm, id_, fields or {}))


# ---- D-form arithmetic and compare: rt, ra, simm (the `ra` of addi is a register number here, 0 included)
for m, i in [("addi", "ADDI"), ("addis", "ADDIS"), ("addic", "ADDIC"), ("addic.", "ADDIC_"), ("mulli", "MULLI"),
             ("subfic", "SUBFIC")]:
    for rt, ra, imm in [(3, 4, -8), (31, 1, 32767), (1, 31, -32768), (0, 2, 0)]:
        add("%s %d, %d, %d" % (m, rt, ra, imm), i, dict(rt=rt, ra=ra, simm=imm))
# logical immediates: dest ra (bits 16..20), source rs (bits 6..10)
for m, i in [("ori", "ORI"), ("oris", "ORIS"), ("xori", "XORI"), ("xoris", "XORIS"), ("andi.", "ANDI_"),
             ("andis.", "ANDIS_")]:
    for ra, rs, u in [(3, 4, 0xffff), (31, 0, 1), (0, 31, 0x8000)]:
        add("%s %d, %d, %d" % (m, ra, rs, u), i, dict(ra=ra, rt=rs, simm=u if u < 0x8000 else u - 0x10000))
for m, i in [("cmpwi", "CMPI"), ("cmplwi", "CMPLI")]:
    for cr, ra, imm in [(0, 3, 5), (7, 31, 100)]:
        add("%s %d, %d, %d" % (m, cr, ra, imm), i, dict(ra=ra, simm=imm))
# loads and stores, D-form: rt, simm(ra)
for m, i in [("lwz", "LWZ"), ("lwzu", "LWZU"), ("lbz", "LBZ"), ("lbzu", "LBZU"), ("lhz", "LHZ"), ("lhzu", "LHZU"),
             ("lha", "LHA"), ("lhau", "LHAU"), ("stw", "STW"), ("stwu", "STWU"), ("stb", "STB"), ("stbu", "STBU"),
             ("sth", "STH"), ("sthu", "STHU"), ("lmw", "LMW"), ("stmw", "STMW"),
             ("lfs", "LFS"), ("lfsu", "LFSU"), ("lfd", "LFD"), ("lfdu", "LFDU"),
             ("stfs", "STFS"), ("stfsu", "STFSU"), ("stfd", "STFD"), ("stfdu", "STFDU")]:
    for rt, imm, ra in [(3, 8, 4), (31, -8, 1), (0, 32764, 30), (1, -32768, 2)]:
        add("%s %d, %d(%d)" % (m, rt, imm, ra), i, dict(rt=rt, ra=ra, simm=imm))
# X-form indexed loads and stores: rt, ra, rb
for m, i in [("lwzx", "LWZX"), ("lwzux", "LWZUX"), ("lbzx", "LBZX"), ("lbzux", "LBZUX"), ("lhzx", "LHZX"),
             ("lhzux", "LHZUX"), ("lhax", "LHAX"), ("lhaux", "LHAUX"), ("lhbrx", "LHBRX"), ("lwbrx", "LWBRX"),
             ("stwx", "STWX"), ("stwux", "STWUX"), ("stbx", "STBX"), ("stbux", "STBUX"), ("sthx", "STHX"),
             ("sthux", "STHUX"), ("sthbrx", "STHBRX"), ("stwbrx", "STWBRX"), ("lwarx", "LWARX"),
             ("lfsx", "LFSX"), ("lfsux", "LFSUX"), ("lfdx", "LFDX"), ("lfdux", "LFDUX"),
             ("stfsx", "STFSX"), ("stfsux", "STFSUX"), ("stfdx", "STFDX"), ("stfdux", "STFDUX"),
             ("stfiwx", "STFIWX")]:
    for rt, ra, rb in [(3, 4, 5), (31, 1, 0), (0, 30, 31)]:
        add("%s %d, %d, %d" % (m, rt, ra, rb), i, dict(rt=rt, ra=ra, rb=rb))
add("stwcx. 3, 4, 5", "STWCX_", dict(rt=3, ra=4, rb=5, rc=1))
add("lswi 5, 4, 7", "LSWI", dict(rt=5, ra=4, rb=7))
add("stswi 5, 4, 7", "STSWI", dict(rt=5, ra=4, rb=7))
# XO-form arithmetic: rt, ra, rb, with and without Rc and OE
for m, i in [("add", "ADD"), ("addc", "ADDC"), ("adde", "ADDE"), ("divw", "DIVW"), ("divwu", "DIVWU"),
             ("mullw", "MULLW"), ("subf", "SUBF"), ("subfc", "SUBFC"), ("subfe", "SUBFE")]:
    for suffix, rc, oe in [("", 0, 0), (".", 1, 0), ("o", 0, 1), ("o.", 1, 1)]:
        add("%s%s 3, 4, 5" % (m, suffix), i, dict(rt=3, ra=4, rb=5, rc=rc, oe=oe))
    add("%s 31, 0, 30" % m, i, dict(rt=31, ra=0, rb=30, rc=0, oe=0))
for m, i in [("mulhw", "MULHW"), ("mulhwu", "MULHWU")]:
    add("%s 3, 4, 5" % m, i, dict(rt=3, ra=4, rb=5, rc=0))
    add("%s. 3, 4, 5" % m, i, dict(rt=3, ra=4, rb=5, rc=1))
for m, i in [("neg", "NEG"), ("addme", "ADDME"), ("addze", "ADDZE"), ("subfme", "SUBFME"), ("subfze", "SUBFZE")]:
    for suffix, rc, oe in [("", 0, 0), (".", 1, 0), ("o", 0, 1), ("o.", 1, 1)]:
        add("%s%s 3, 4" % (m, suffix), i, dict(rt=3, ra=4, rc=rc, oe=oe))
# X-form logic and shifts: dest ra, source rs (field rt), rb
for m, i in [("and", "AND"), ("or", "OR"), ("xor", "XOR"), ("nand", "NAND"), ("nor", "NOR"), ("andc", "ANDC"),
             ("orc", "ORC"), ("eqv", "EQV"), ("slw", "SLW"), ("srw", "SRW"), ("sraw", "SRAW")]:
    add("%s 3, 4, 5" % m, i, dict(ra=3, rt=4, rb=5, rc=0))
    add("%s. 31, 0, 30" % m, i, dict(ra=31, rt=0, rb=30, rc=1))
for m, i in [("extsb", "EXTSB"), ("extsh", "EXTSH"), ("cntlzw", "CNTLZW")]:
    add("%s 3, 4" % m, i, dict(ra=3, rt=4, rc=0))
    add("%s. 3, 4" % m, i, dict(ra=3, rt=4, rc=1))
add("srawi 3, 4, 31", "SRAWI", dict(ra=3, rt=4, sh=31, rc=0))
add("srawi. 3, 4, 1", "SRAWI", dict(ra=3, rt=4, sh=1, rc=1))
# compare registers
for m, i in [("cmpw", "CMP"), ("cmplw", "CMPL")]:
    add("%s 1, 3, 4" % m, i, dict(ra=3, rb=4))
# rotates: ra, rs, sh, mb, me
for m, i in [("rlwinm", "RLWINM"), ("rlwimi", "RLWIMI")]:
    for ra, rs, sh, mb, me in [(3, 4, 5, 6, 7), (31, 0, 31, 31, 0), (0, 31, 0, 0, 31)]:
        add("%s %d, %d, %d, %d, %d" % (m, ra, rs, sh, mb, me), i, dict(ra=ra, rt=rs, sh=sh, mb=mb, me=me, rc=0))
        add("%s. %d, %d, %d, %d, %d" % (m, ra, rs, sh, mb, me), i, dict(ra=ra, rt=rs, sh=sh, mb=mb, me=me, rc=1))
add("rlwnm 3, 4, 5, 6, 7", "RLWNM", dict(ra=3, rt=4, rb=5, mb=6, me=7, rc=0))
# branches: offsets are bytes from the instruction
for off in (0x100, -0x100, 0x1fffffc, -0x2000000, 4):
    add("b .%+d" % off, "B", dict(off=off, lk=0, aa=0))
    add("bl .%+d" % off, "B", dict(off=off, lk=1, aa=0))
add("ba 0x100", "B", dict(off=0x100, lk=0, aa=1))
add("bla 0x100", "B", dict(off=0x100, lk=1, aa=1))
for off in (16, -8, 0x7ffc, -0x8000):
    add("bc 12, 2, .%+d" % off, "BC", dict(off=off, bo=12, bi=2, lk=0, aa=0))
    add("bc 4, 30, .%+d" % off, "BC", dict(off=off, bo=4, bi=30, lk=0, aa=0))
    add("bdnz .%+d" % off, "BC", dict(off=off, bo=16, bi=0, lk=0, aa=0))
    add("bcl 20, 31, .%+d" % off, "BC", dict(off=off, bo=20, bi=31, lk=1, aa=0))
add("bca 12, 2, 0x100", "BC", dict(off=0x100, bo=12, bi=2, lk=0, aa=1))
add("bcla 12, 2, 0x100", "BC", dict(off=0x100, bo=12, bi=2, lk=1, aa=1))
add("blr", "BCLR", dict(bo=20, bi=0, lk=0))
add("blrl", "BCLR", dict(bo=20, bi=0, lk=1))
add("beqlr", "BCLR", dict(bo=12, bi=2, lk=0))
add("bdnzlr", "BCLR", dict(bo=16, bi=0, lk=0))
add("bclr 4, 30, 0", "BCLR", dict(bo=4, bi=30, lk=0))
add("bctr", "BCCTR", dict(bo=20, bi=0, lk=0))
add("bctrl", "BCCTR", dict(bo=20, bi=0, lk=1))
add("bcctr 12, 2, 0", "BCCTR", dict(bo=12, bi=2, lk=0))
add("sc", "SC")
add("trap", "TW", dict(rt=31, ra=0, rb=0))
add("tweq 3, 4", "TW", dict(rt=4, ra=3, rb=4))
add("twi 31, 3, 5", "TWI", dict(rt=31, ra=3, simm=5))
add("twlti 3, -1", "TWI", dict(rt=16, ra=3, simm=-1))
# condition register
for m, i in [("crand", "CRAND"), ("crandc", "CRANDC"), ("creqv", "CREQV"), ("crnand", "CRNAND"), ("crnor", "CRNOR"),
             ("cror", "CROR"), ("crorc", "CRORC"), ("crxor", "CRXOR")]:
    add("%s 1, 2, 3" % m, i, dict(rt=1, ra=2, rb=3))
add("mcrf 1, 2", "MCRF")
add("isync", "ISYNC")
# special registers and system
add("mflr 0", "MFSPR", dict(rt=0, spr=8))
add("mflr 31", "MFSPR", dict(rt=31, spr=8))
add("mfctr 3", "MFSPR", dict(rt=3, spr=9))
add("mfxer 3", "MFSPR", dict(rt=3, spr=1))
add("mfspr 3, 1023", "MFSPR", dict(rt=3, spr=1023))
add("mfspr 3, 272", "MFSPR", dict(rt=3, spr=272))
add("mtlr 0", "MTSPR", dict(rt=0, spr=8))
add("mtctr 9", "MTSPR", dict(rt=9, spr=9))
add("mtxer 3", "MTSPR", dict(rt=3, spr=1))
add("mtspr 1023, 4", "MTSPR", dict(rt=4, spr=1023))
add("mtspr 272, 4", "MTSPR", dict(rt=4, spr=272))
add("mfcr 3", "MFCR", dict(rt=3))
add("mtcrf 255, 3", "MTCRF", dict(rt=3))
add("mfmsr 3", "MFMSR", dict(rt=3))
add("mtmsr 3", "MTMSR", dict(rt=3))
add("rfi", "RFI")
add("tlbie 3", "TLBIE", dict(rb=3))
add("tlbsync", "TLBSYNC")
add("sync", "SYNC")
add("lwsync", "SYNC")
add("eieio", "EIEIO")
add("dcbz 3, 4", "DCBZ", dict(ra=3, rb=4))
add("dcbf 3, 4", "DCBF", dict(ra=3, rb=4))
add("dcbst 3, 4", "DCBST", dict(ra=3, rb=4))
add("dcbt 3, 4", "DCBT", dict(ra=3, rb=4))
add("dcbtst 3, 4", "DCBTST", dict(ra=3, rb=4))
add("icbi 3, 4", "ICBI", dict(ra=3, rb=4))
# floating point: A-form and X-form, with the record bit
for m, i in [("fadds", "FADDS"), ("fsubs", "FSUBS"), ("fdivs", "FDIVS"), ("fadd", "FADD"), ("fsub", "FSUB"),
             ("fdiv", "FDIV")]:
    add("%s 1, 2, 3" % m, i, dict(rt=1, ra=2, rb=3, rc=0))
    add("%s. 1, 2, 3" % m, i, dict(rt=1, ra=2, rb=3, rc=1))
for m, i in [("fmuls", "FMULS"), ("fmul", "FMUL")]:
    add("%s 1, 2, 3" % m, i, dict(rt=1, ra=2, rc=0))
for m, i in [("fmadds", "FMADDS"), ("fmsubs", "FMSUBS"), ("fnmadds", "FNMADDS"), ("fnmsubs", "FNMSUBS"),
             ("fmadd", "FMADD"), ("fmsub", "FMSUB"), ("fnmadd", "FNMADD"), ("fnmsub", "FNMSUB"),
             ("fsel", "FSEL")]:
    add("%s 1, 2, 3, 4" % m, i, dict(rt=1, ra=2, rb=4, rc=0))
for m, i in [("fres", "FRES"), ("fsqrts", "FSQRTS"), ("fsqrt", "FSQRT"), ("frsp", "FRSP"), ("fctiw", "FCTIW"),
             ("fctiwz", "FCTIWZ"), ("fneg", "FNEG"), ("fmr", "FMR"), ("fnabs", "FNABS"), ("fabs", "FABS")]:
    add("%s 1, 2" % m, i, dict(rt=1, rb=2, rc=0))
add("fcmpu 1, 2, 3", "FCMPU", dict(ra=2, rb=3))
add("fcmpo 1, 2, 3", "FCMPO", dict(ra=2, rb=3))
add("mffs 5", "MFFS", dict(rt=5))
add("mtfsf 255, 5", "MTFSF", dict(rb=5))
add("mtfsb0 5", "MTFSB0", dict(rt=5))
add("mtfsb1 5", "MTFSB1", dict(rt=5))
# PowerPC 64 and the instructions only a newer CPU names
P = dict(tgt="powerpc64-linux-gnu", cpu="pwr7")
for m, i in [("ld", "LD"), ("ldu", "LDU"), ("lwa", "LWA"), ("std", "STD"), ("stdu", "STDU")]:
    for rt, imm, ra in [(3, 8, 4), (31, -8, 1), (0, 32764, 30)]:
        add("%s %d, %d(%d)" % (m, rt, imm, ra), i, dict(rt=rt, ra=ra, simm=imm), **P)
for m, i in [("ldx", "LDX"), ("ldux", "LDUX"), ("stdx", "STDX"), ("stdux", "STDUX"), ("lwax", "LWAX"),
             ("lwaux", "LWAUX"), ("ldarx", "LDARX")]:
    add("%s 3, 4, 5" % m, i, dict(rt=3, ra=4, rb=5), **P)
add("stdcx. 3, 4, 5", "STDCX_", dict(rt=3, ra=4, rb=5, rc=1), **P)
for m, i in [("divd", "DIVD"), ("divdu", "DIVDU"), ("mulld", "MULLD")]:
    for suffix, rc, oe in [("", 0, 0), ("o.", 1, 1)]:
        add("%s%s 3, 4, 5" % (m, suffix), i, dict(rt=3, ra=4, rb=5, rc=rc, oe=oe), **P)
for m, i in [("mulhd", "MULHD"), ("mulhdu", "MULHDU")]:
    add("%s 3, 4, 5" % m, i, dict(rt=3, ra=4, rb=5, rc=0), **P)
for m, i in [("sld", "SLD"), ("srd", "SRD"), ("srad", "SRAD")]:
    add("%s 3, 4, 5" % m, i, dict(ra=3, rt=4, rb=5, rc=0), **P)
add("sradi 3, 4, 63", "SRADI", dict(ra=3, rt=4, rc=0), **P)
add("cntlzd 3, 4", "CNTLZD", dict(ra=3, rt=4, rc=0), **P)
add("extsw 3, 4", "EXTSW", dict(ra=3, rt=4, rc=0), **P)
add("rldicl 3, 4, 5, 6", "RLDICL", dict(ra=3, rt=4), **P)
add("rldicr 3, 4, 5, 6", "RLDICR", dict(ra=3, rt=4), **P)
add("rldic 3, 4, 5, 6", "RLDIC", dict(ra=3, rt=4), **P)
add("rldimi 3, 4, 5, 6", "RLDIMI", dict(ra=3, rt=4), **P)
add("rldcl 3, 4, 5, 6", "RLDCL", dict(ra=3, rt=4, rb=5), **P)
add("rldcr 3, 4, 5, 6", "RLDCR", dict(ra=3, rt=4, rb=5), **P)
add("tdi 31, 3, 5", "TDI", dict(rt=31, ra=3, simm=5), **P)
add("td 31, 3, 4", "TD", dict(rt=31, ra=3, rb=4), **P)
add("fctid 1, 2", "FCTID", dict(rt=1, rb=2), **P)
add("fctidz 1, 2", "FCTIDZ", dict(rt=1, rb=2), **P)
add("fcfid 1, 2", "FCFID", dict(rt=1, rb=2), **P)
add("isel 3, 4, 5, 2", "ISEL", dict(rt=3, ra=4, rb=5), **P)
add("isel 31, 0, 30, 31", "ISEL", dict(rt=31, ra=0, rb=30), **P)
add("frsqrte 1, 2", "FRSQRTE", dict(rt=1, rb=2), **P)
add("frsqrtes 1, 2", "FRSQRTES", dict(rt=1, rb=2), **P)
# known but not spelled (UNSUPPORTED): AltiVec, VSX
add("vaddubm 1, 2, 3", "UNSUPPORTED", {}, tgt="powerpc-linux-gnu", cpu="g4")
add("lvx 1, 2, 3", "UNSUPPORTED", {}, tgt="powerpc-linux-gnu", cpu="g4")
add("stvx 1, 2, 3", "UNSUPPORTED", {}, tgt="powerpc-linux-gnu", cpu="g4")
add("lxvd2x 1, 2, 3", "UNSUPPORTED", {}, **P)
add("stxvd2x 1, 2, 3", "UNSUPPORTED", {}, **P)
add("xsadddp 1, 2, 3", "UNSUPPORTED", {}, **P)


def assemble(group):
    (tgt, cpu), items = group
    src = os.path.join(SCRATCH, "ppc_vec_%s_%s.s" % (tgt.split("-")[0], cpu))
    obj = src[:-2] + ".o"
    with open(src, "w") as f:
        f.write("\t.text\n")
        for (_t, _c, asm, _i, _f) in items:
            f.write("\t%s\n" % asm)
    cmd = CLANG + ["--target=" + tgt, "-mcpu=" + cpu, "-c", "-x", "assembler", src, "-o", obj]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        sys.stderr.write(r.stderr)
        sys.exit("assembler failed for %s %s" % (tgt, cpu))
    d = open(obj, "rb").read()
    e = ">" if d[5] == 2 else "<"
    is64 = d[4] == 2
    if is64:
        shoff = struct.unpack(e + "Q", d[40:48])[0]
        shentsize, shnum = struct.unpack(e + "HH", d[58:62])
    else:
        shoff = struct.unpack(e + "I", d[32:36])[0]
        shentsize, shnum = struct.unpack(e + "HH", d[46:50])
    words = None
    for i in range(shnum):
        o = shoff + i * shentsize
        if is64:
            nm, ty, fl, ad, off, sz = struct.unpack(e + "IIQQQQ", d[o:o + 40])
        else:
            nm, ty, fl, ad, off, sz = struct.unpack(e + "IIIIII", d[o:o + 24])
        if ty == 1 and fl & 4:
            words = struct.unpack(e + "%dI" % (sz // 4), d[off:off + sz])
            break
    if words is None or len(words) != len(items):
        sys.exit("expected %d words, got %s" % (len(items), None if words is None else len(words)))
    return words


def main():
    groups = {}
    for v in V:
        groups.setdefault((v[0], v[1]), []).append(v)
    print("/* ppc_asm_vectors.inc - GENERATED by tools/genotype/ppc_vectors_gen.py from the LLVM assembler; do not edit. */")
    print("/* word, identity, bit mask of the fields given, then the fields: " + ", ".join(F) + " */")
    n = 0
    for key in sorted(groups):
        words = assemble((key, groups[key]))
        for w, (tgt, cpu, asm, i, fields) in zip(words, groups[key]):
            mask = 0
            vals = []
            for k, name in enumerate(F):
                if name in fields:
                    mask |= 1 << k
                    vals.append(str(fields[name]))
                else:
                    vals.append("0")
            print("\t{ 0x%08xu, KGENOME_PPC_I_%s, 0x%04x, { %s }, \"%s\", %d }," %
                  (w, i, mask, ", ".join(vals), asm.replace('"', ''), 1 if "64" in tgt else 0))
            n += 1
    sys.stderr.write("%d vectors\n" % n)


main()
