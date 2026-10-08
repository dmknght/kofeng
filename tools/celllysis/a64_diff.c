/*
 * a64_diff - the AArch64 decoder against a reference decoder.
 *
 * A DEV TOOL, NOT A TEST: it needs Capstone's header and library, which are not
 * in this tree. Build by hand, e.g.
 *
 *   make celllysis-a64-diff CS_INC=<capstone include dir> CS_LIB=<libcapstone.a>
 *
 * WHAT IT CAN AND CANNOT SAY. Capstone is an ORACLE: where this decoder and it
 * disagree one of them is wrong, and which is decided from the architecture
 * reference, not by the oracle. A disagreement that is a decision (this decoder
 * leaves vector words undecided, reports an immediate-less `add` as a move) is
 * recorded in a64.c and counted here under its own heading so it cannot hide a
 * real one. Agreement proves nothing about a bug both share, which is why
 * tests/unit/decode_a64.c holds encodings written from the manual.
 *
 * WHAT IS COMPARED, per word: validity; the class (Capstone's mnemonic is
 * mapped to the set of classes this decoder may legitimately give it); the
 * branch target; the general registers written (Capstone's write list through
 * cs_regs_access, zero registers dropped); the value of movz/movn and of the
 * `mov` alias; the address adr/adrp resolve to.
 *
 * INPUTS, all deterministic (a fixed seed, so a disagreement is the same one
 * tomorrow):
 *   -r N      N random 32-bit words per thread (16 threads)
 *   -s N      N random fills for each of the 256 x 64 values of bits 31..24 and
 *             bits 15..10
 *   -e FILE   every four-byte word of every executable section of the AArch64
 *             ELF files named (one path per line) in FILE
 *   -d HEX    dump one word (both decoders)
 *   -t        speed: ns per instruction of the decoder alone
 *   -v        print every Capstone-valid / ours-invalid etc. category, not
 *             only the first 40 buckets
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <elf.h>

#include <capstone/capstone.h>

#include "kofmod/kofsig.h"
#include "celllysis/decode.h"

#define NTHR 16

/* ---- buckets: a category, its count and three examples ---------------------- */

#define NSLOT 8192
struct ex {
	uint32_t w;
	uint64_t va;
	char text[200];
};

struct bucket {
	char key[96];
	uint64_t n;
	struct ex ex[3];
};

struct stats {
	uint64_t words, cap_valid, our_valid;
	uint64_t both_valid, cap_only, our_only;
	uint64_t cmp_class, cmp_target, cmp_wmask, cmp_imm, cmp_adr;
	uint64_t degrade[CELL_OP_COUNT];        /* our class when Capstone's primary is a real class */
	struct bucket b[NSLOT];
	uint64_t full;
};

static uint64_t hash(const char *s)
{
	uint64_t h = 1469598103934665603ull;

	while (*s)
		h = (h ^ (uint8_t)*s++) * 1099511628211ull;
	return h;
}

static void note(struct stats *st, const char *key, uint32_t w, uint64_t va,
		 const char *text)
{
	uint64_t i = hash(key) & (NSLOT - 1);
	unsigned probes = 0;
	struct bucket *b;

	while (st->b[i].n && strcmp(st->b[i].key, key)) {
		i = (i + 1) & (NSLOT - 1);
		if (++probes > NSLOT) {
			st->full++;
			return;
		}
	}
	b = &st->b[i];
	if (!b->n)
		snprintf(b->key, sizeof b->key, "%s", key);
	if (b->n < 3) {
		b->ex[b->n].w = w;
		b->ex[b->n].va = va;
		snprintf(b->ex[b->n].text, sizeof b->ex[b->n].text, "%s", text);
	}
	b->n++;
}

static void merge(struct stats *d, const struct stats *s)
{
	size_t i;
	unsigned k;

	d->words += s->words; d->cap_valid += s->cap_valid;
	d->our_valid += s->our_valid; d->both_valid += s->both_valid;
	d->cap_only += s->cap_only; d->our_only += s->our_only;
	d->cmp_class += s->cmp_class; d->cmp_target += s->cmp_target;
	d->cmp_wmask += s->cmp_wmask; d->cmp_imm += s->cmp_imm;
	d->cmp_adr += s->cmp_adr;
	for (k = 0; k < CELL_OP_COUNT; k++)
		d->degrade[k] += s->degrade[k];
	for (i = 0; i < NSLOT; i++) {
		const struct bucket *b = &s->b[i];
		uint64_t j;
		unsigned e;
		struct bucket *t;

		if (!b->n)
			continue;
		j = hash(b->key) & (NSLOT - 1);
		while (d->b[j].n && strcmp(d->b[j].key, b->key))
			j = (j + 1) & (NSLOT - 1);
		t = &d->b[j];
		if (!t->n)
			snprintf(t->key, sizeof t->key, "%s", b->key);
		for (e = 0; e < 3 && e < b->n; e++)
			if (t->n + e < 3)
				t->ex[t->n + e] = b->ex[e];
		t->n += b->n;
	}
}

/* ---- Capstone side --------------------------------------------------------- */

static const char *const KN[CELL_OP_COUNT] = {
	"OTHER", "NOP", "MOV", "MOVZX", "MOVSX", "LEA", "XCHG", "PUSH", "POP",
	"ADD", "SUB", "ADC", "SBB", "AND", "OR", "XOR", "NOT", "NEG", "INC", "DEC",
	"CMP", "TEST", "SHL", "SHR", "SAR", "ROL", "ROR", "RCL", "RCR",
	"MUL", "IMUL", "DIV", "IDIV", "CALL", "JMP", "JCC", "LOOP", "RET", "INT",
	"CMOV", "SETCC", "FPU", "STRING", "PRIV", "SYSCALL", "WIDEN", "MOV_SPECIAL",
	"IRET", "UD"
};

/* A general-purpose register: its number, 0..30, 31 for sp, 32 for zr, -1 not. */
static int gpr(unsigned r)
{
	if (r >= ARM64_REG_W0 && r <= ARM64_REG_W30)
		return (int)(r - ARM64_REG_W0);
	if (r >= ARM64_REG_X0 && r <= ARM64_REG_X28)
		return (int)(r - ARM64_REG_X0);
	if (r == ARM64_REG_FP)
		return 29;
	if (r == ARM64_REG_LR)
		return 30;
	if (r == ARM64_REG_SP || r == ARM64_REG_WSP)
		return 31;
	if (r == ARM64_REG_XZR || r == ARM64_REG_WZR)
		return 32;
	return -1;
}

static uint64_t cs_wmask(csh h, const cs_insn *in)
{
	cs_regs rr, rw;
	uint8_t nr, nw, i;
	uint64_t m = 0;

	if (cs_regs_access(h, in, rr, &nr, rw, &nw) != CS_ERR_OK)
		return 0;
	for (i = 0; i < nw; i++) {
		int g = gpr(rw[i]);

		if (g >= 0 && g < 32)
			m |= 1ull << g;
	}
	return m;
}

#define B(c) (1ull << (c))
static const uint64_t ANY = ~0ull;

/*
 * What this decoder may call an instruction Capstone calls `mn`. A class is
 * listed only when the instruction can legitimately be that class; the
 * degradations (shifted operand, zero register, no class for it) are added by
 * the operand checks in want(), not here.
 */
struct kn { const char *mn; uint64_t cls; };

static int starts(const char *s, const char *p)
{
	return !strncmp(s, p, strlen(p));
}

static int is_vecreg(unsigned r)
{
	return gpr(r) < 0 && r != ARM64_REG_NZCV;
}

/*
 * The set of classes acceptable for `in`, from its mnemonic and operands. 0
 * means "I have no opinion" (counted separately), so a mnemonic missing from
 * this map is visible rather than silently accepted.
 */

static uint64_t want_inner(const cs_insn *in, uint32_t w)
{
	const char *m = in->mnemonic;
	const cs_arm64 *a = &in->detail->arm64;
	const cs_arm64_op *o = a->operands;
	int n = a->op_count;
	int shifted = 0, ext = 0, i, d0 = -1, hasz = 0;
	uint64_t s;

	(void)w;
	for (i = 0; i < n; i++) {
		if (o[i].type == ARM64_OP_REG && gpr(o[i].reg) == 32)
			hasz = 1;
		if (o[i].shift.type != 0 && o[i].shift.value)
			shifted = 1;
		if (o[i].ext)
			ext = 1;
	}
	if (n > 0 && o[0].type == ARM64_OP_REG)
		d0 = gpr(o[0].reg);
	/* a vector or predicate destination is a vector instruction that
	 * shares a mnemonic with a scalar one (add, mul, orr, adr, mov ...) */
	if (d0 < 0 && n > 0 && o[0].type == ARM64_OP_REG &&
	    !starts(in->mnemonic, "st") && !starts(in->mnemonic, "ld"))
		return B(CELL_OTHER);

#define IS(x) (!strcmp(m, x))
	/* the two-operand ALU family: the class, or OTHER when the operands do
	 * not fit it, or a move/NOP when a zero register collapses it */
	if (IS("add") || IS("adds") || IS("sub") || IS("subs") || IS("adc") ||
	    IS("adcs") || IS("sbc") || IS("sbcs") || IS("and") || IS("ands") ||
	    IS("orr") || IS("eor") || IS("lsl") || IS("lsr") || IS("asr") ||
	    IS("ror") || IS("mul") || IS("udiv") || IS("sdiv") || IS("smull") ||
	    IS("umull") || IS("smulh") || IS("umulh") || IS("neg") ||
	    IS("negs") || IS("ngc") || IS("ngcs") || IS("mvn")) {
		uint64_t p;

		if (IS("add") || IS("adds")) p = B(CELL_ADD);
		else if (IS("sub") || IS("subs")) p = B(CELL_SUB);
		else if (IS("adc") || IS("adcs")) p = B(CELL_ADC);
		else if (IS("sbc") || IS("sbcs") || IS("ngc") || IS("ngcs")) p = B(CELL_SBB);
		else if (IS("and") || IS("ands")) p = B(CELL_AND);
		else if (IS("orr")) p = B(CELL_OR);
		else if (IS("eor")) p = B(CELL_XOR);
		else if (IS("lsl")) p = B(CELL_SHL);
		else if (IS("lsr")) p = B(CELL_SHR);
		else if (IS("asr")) p = B(CELL_SAR);
		else if (IS("ror")) p = B(CELL_ROR);
		else if (IS("mul") || IS("umull") || IS("umulh")) p = B(CELL_MUL);
		else if (IS("smull") || IS("smulh")) p = B(CELL_IMUL);
		else if (IS("udiv")) p = B(CELL_DIV);
		else if (IS("sdiv")) p = B(CELL_IDIV);
		else if (IS("neg") || IS("negs") || IS("ngc") || IS("ngcs")) p = B(CELL_NEG) | B(CELL_SBB);
		else p = B(CELL_NOT) | B(CELL_MOV);     /* mvn */
		s = p;
		if (shifted || ext)
			s |= B(CELL_OTHER);
		if (hasz || d0 == 32) {
			s |= B(CELL_MOV) | B(CELL_NOP) | B(CELL_OTHER);
			if (IS("neg") || IS("negs") || IS("mvn") || IS("ngc") ||
			    IS("ngcs"))
				s |= B(CELL_NOT) | B(CELL_NEG);
		}
		/* `add xd,xn,#0` is a move */
		if (IS("add") && n == 3 && o[2].type == ARM64_OP_IMM && o[2].imm == 0)
			s |= B(CELL_MOV);
		if (IS("ngc") || IS("ngcs") || IS("negs") || IS("neg") || IS("mvn"))
			s |= B(CELL_OTHER);
		/* a shift whose source is the zero register is the constant 0 */
		return s;
	}
	if (IS("cmp") || IS("tst")) {
		s = IS("cmp") ? B(CELL_CMP) : B(CELL_TEST);
		if (shifted || ext || (IS("tst") && hasz))
			s |= B(CELL_OTHER);
		return s;
	}
	if (IS("cmn") || IS("ccmp") || IS("ccmn") || IS("bic") || IS("bics") ||
	    IS("orn") || IS("eon"))
		return B(CELL_OTHER) | B(CELL_NOP);
	if (IS("mov")) {
		/* movz, movn, orr-immediate, add sp, orr-register all spell mov */
		if (n >= 1 && o[0].type == ARM64_OP_REG && is_vecreg(o[0].reg))
			return B(CELL_OTHER);
		return B(CELL_MOV) | B(CELL_NOP) | B(CELL_OTHER);
	}
	if (IS("movz") || IS("movn"))
		return B(CELL_MOV) | B(CELL_NOP);
	if (IS("movk"))
		return B(CELL_OTHER);
	if (IS("uxtb") || IS("uxth"))
		return B(CELL_MOVZX) | B(CELL_OTHER);
	if (IS("sxtb") || IS("sxth") || IS("sxtw"))
		return B(CELL_MOVSX) | B(CELL_OTHER);
	if (IS("lslv")) return B(CELL_SHL);
	if (IS("lsrv")) return B(CELL_SHR);
	if (IS("asrv")) return B(CELL_SAR);
	if (IS("rorv")) return B(CELL_ROR);
	if (IS("b"))
		return a->cc != ARM64_CC_INVALID && a->cc != ARM64_CC_AL ?
		       B(CELL_JCC) : B(CELL_JMP);
	if (starts(m, "b.") || starts(m, "bc.") || IS("cbz") || IS("cbnz") ||
	    IS("tbz") || IS("tbnz"))
		return B(CELL_JCC);
	if (IS("bl") || IS("blr") || IS("blraa") || IS("blraaz") ||
	    IS("blrab") || IS("blrabz"))
		return B(CELL_CALL);
	if (IS("br") || IS("braa") || IS("braaz") || IS("brab") || IS("brabz"))
		return B(CELL_JMP);
	if (IS("ret") || IS("retaa") || IS("retab"))
		return B(CELL_RET);
	if (IS("eret") || IS("eretaa") || IS("eretab"))
		return B(CELL_IRET);
	if (IS("drps") || IS("hvc") || IS("smc") || starts(m, "dcps"))
		return B(CELL_PRIV);
	if (IS("svc"))
		return B(CELL_SYSCALL);
	if (IS("brk") || IS("hlt"))
		return B(CELL_INT);
	if (IS("udf"))
		return B(CELL_UD);
	if (IS("mrs") || IS("msr") || IS("smstart") || IS("smstop") ||
	    IS("cfinv") || IS("xaflag") || IS("axflag"))
		return B(CELL_PRIV);
	if (IS("tcommit") || IS("tstart") || IS("ttest"))
		return B(CELL_OTHER);
	if (IS("nop") || IS("yield") || IS("wfe") || IS("wfi") || IS("sev") ||
	    IS("sevl") || IS("csdb") || IS("esb") || IS("psb") || IS("tsb") ||
	    IS("bti") || IS("dgh") || IS("hint") || IS("wfet") || IS("wfit"))
		return B(CELL_NOP);
	if (IS("paciasp") || IS("pacibsp") || IS("autiasp") || IS("autibsp") ||
	    IS("paciaz") || IS("pacibz") || IS("autiaz") || IS("autibz") ||
	    IS("pacia1716") || IS("pacib1716") || IS("autia1716") ||
	    IS("autib1716") || IS("xpaclri"))
		return B(CELL_OTHER) | B(CELL_NOP);
	if (IS("adr") || IS("adrp"))
		return B(CELL_LEA) | B(CELL_NOP);
	/* the single-register loads and stores */
	if (starts(m, "ldr") || starts(m, "ldur") || starts(m, "ldtr") ||
	    starts(m, "ldar") || starts(m, "ldlar") || starts(m, "ldaxr") ||
	    starts(m, "ldxr") || starts(m, "ldapr") || starts(m, "ldapur")) {
		if (starts(m, "ldxp") || starts(m, "ldaxp"))
			return B(CELL_OTHER);
		if (n > 0 && o[0].type == ARM64_OP_REG && gpr(o[0].reg) >= 0 &&
		    gpr(o[0].reg) != 32)
			return B(CELL_MOV);
		return B(CELL_OTHER);
	}
	if (starts(m, "str") || starts(m, "stur") || starts(m, "sttr") ||
	    starts(m, "stlr") || starts(m, "stllr") || starts(m, "stlur")) {
		if (n > 0 && o[0].type == ARM64_OP_REG && gpr(o[0].reg) >= 0)
			return B(CELL_MOV);
		return B(CELL_OTHER);
	}
	(void)ext;
	return B(CELL_OTHER);
}

/*
 * A write to the zero register is nothing, whatever wrote it: this decoder
 * calls it a CELL_NOP (or leaves it OTHER where it has no class for the
 * instruction), and Capstone's operand 0 is xzr/wzr. Compares, branches and
 * stores name the zero register as a SOURCE, so they are excluded.
 */
static uint64_t want(const cs_insn *in, uint32_t w)
{
	const char *m = in->mnemonic;
	const cs_arm64 *a = &in->detail->arm64;
	uint64_t s = want_inner(in, w);

	if (a->op_count > 0 && a->operands[0].type == ARM64_OP_REG &&
	    gpr(a->operands[0].reg) == 32 && strcmp(m, "cmp") && strcmp(m, "cmn") &&
	    strcmp(m, "tst") && strcmp(m, "ccmp") && strcmp(m, "ccmn") &&
	    !starts(m, "cb") && !starts(m, "tb") && !starts(m, "st") &&
	    strcmp(m, "msr") && strcmp(m, "prfm"))
		s |= B(CELL_NOP) | B(CELL_OTHER);
	/* mrs/msr whose first field is below 2 are not system-register moves in
	 * the architecture (L=1 op0=01 is sysl, op0=00 is unallocated; L=0 op0=00
	 * is hints, barriers and pstate); Capstone names every one of them a
	 * generic mrs/msr, this decoder says what the encoding is */
	if ((!strcmp(m, "mrs") || !strcmp(m, "msr")) &&
	    (strstr(in->op_str, " s0_") || strstr(in->op_str, "s0_") ||
	     strstr(in->op_str, "s1_")))
		s |= B(CELL_OTHER) | B(CELL_NOP);
	return s;
}

/*
 * WHERE CAPSTONE'S OWN WRITE LIST IS WRONG, decided from the architecture
 * reference and checked to be exactly the register the encoding names - so a
 * genuine disagreement in the same mnemonic is still reported:
 *   omits the destination: adds, addg, subg, ldg, gmi, irg, subp, subps, ldraa,
 *     ldrab, the ld<op> atomics and swp (Rt receives the old value), cas (Rs),
 *     casp (Rs, Rs+1), fcvtzs/fcvtzu, and the FEAT_MOPS cpy/set families, which
 *     rewrite the pointer and count registers they print with a `!`;
 *   lists a register that is only read: cmp, cmn, tst (the source), st1..st4
 *     with a register post-index (Rm), and svc (it names x30 as written; the
 *     exception does not touch it).
 */
static const char *cs_wrong(const char *m, uint32_t w, uint64_t extra, uint64_t miss)
{
	uint64_t rd = 1ull << (w & 31u), rn = 1ull << ((w >> 5) & 31u);
	uint64_t rs = 1ull << ((w >> 16) & 31u);
	static const char *const atom[] = { "ldadd", "ldclr", "ldeor", "ldset",
		"ldsmax", "ldsmin", "ldumax", "ldumin", "swp" };
	unsigned i;

	if (!miss && !strcmp(m, "hint"))
		return !(extra & ~(1ull << 16)) ? "capstone-omits-chkfeat-x16" : NULL;
	if (!extra && (starts(m, "pac") || starts(m, "aut")) && strstr(m, "1716"))
		return miss == 1ull << 16 ? "capstone-lists-x16" : NULL;
	if (!miss) {
		if (!strcmp(m, "tstart") || !strcmp(m, "ttest") || !strcmp(m, "umov") || !strcmp(m, "smov") || !strcmp(m, "fmov") ||
		    starts(m, "fcvt") || !strcmp(m, "fjcvtzs") || starts(m, "ldlar") ||
		    !strcmp(m, "ldgm") || !strcmp(m, "adds") || !strcmp(m, "addg") || !strcmp(m, "subg") ||
		    !strcmp(m, "ldg") || !strcmp(m, "gmi") || !strcmp(m, "irg") ||
		    !strcmp(m, "subp") || !strcmp(m, "subps") ||
		    !strcmp(m, "ldraa") || !strcmp(m, "ldrab") ||
		    !strcmp(m, "fcvtzs") || !strcmp(m, "fcvtzu"))
			return !(extra & ~rd) ? "capstone-omits-Rd" : NULL;
		for (i = 0; i < sizeof atom / sizeof *atom; i++)
			if (starts(m, atom[i]))
				return !(extra & ~rd) ? "capstone-omits-Rt" : NULL;
		if (!strcmp(m, "st64bv") || !strcmp(m, "st64bv0"))
			return !(extra & ~rs) ? "capstone-omits-Rs" : NULL;
		if (!strcmp(m, "ld64b"))
			return !(extra & ~(0xffull << (w & 31u))) ? "capstone-omits-Rt..Rt+7" : NULL;
		if (starts(m, "casp"))
			return !(extra & ~(rs | rs << 1)) ? "capstone-omits-Rs" : NULL;
		if (starts(m, "cas"))
			return !(extra & ~rs) ? "capstone-omits-Rs" : NULL;
		if (starts(m, "cpy") || starts(m, "set"))
			return !(extra & ~(rd | rn | rs)) ? "capstone-omits-mops" : NULL;
	}
	if (!extra) {
		if (!strcmp(m, "cmp") || !strcmp(m, "cmn") || !strcmp(m, "tst"))
			return !(miss & ~rn) ? "capstone-lists-source" : NULL;
		if (starts(m, "st1") || starts(m, "st2") || starts(m, "st3") ||
		    starts(m, "st4") || starts(m, "ld1") || starts(m, "ld2") ||
		    starts(m, "ld3") || starts(m, "ld4"))
			return !(miss & ~rs) ? "capstone-lists-Rm" : NULL;
		if (!strcmp(m, "svc"))
			return miss == 1ull << 30 ? "capstone-lists-x30" : NULL;
	}
	return NULL;
}

/*
 * A word Capstone refuses and this decoder accepts is sometimes CONSTRAINED
 * UNPREDICTABLE in the architecture (a writeback base that is also the loaded
 * register, ldp x1,x1, a store-exclusive status register that is also the
 * data register ...): the reference refuses on a register equality, this
 * decoder reads the instruction. Detect it without a table: change one
 * register field at a time to every other value, and if the reference then
 * accepts, the refusal was about which registers were named, not about the
 * encoding. The pair (Rs, Rt2) is tried together for the SBO-field forms.
 */
static unsigned probe_every = 1;        /* probe 1 in N of the unexplained words */

static int cs_ok(csh h, cs_insn *in, uint32_t w, uint64_t va)
{
	uint8_t b[4] = { (uint8_t)w, (uint8_t)(w >> 8), (uint8_t)(w >> 16),
			 (uint8_t)(w >> 24) };
	const uint8_t *p = b;
	size_t sz = 4;
	uint64_t ad = va;

	return cs_disasm_iter(h, &p, &sz, &ad, in) != 0;
}

/* Features the reference does not have; this decoder decodes them from the
 * architecture reference. */
static const char *cap_lacks(uint32_t w)
{
	if ((w & 0xfc400000u) == 0x68000000u && ((w >> 23) & 3u))
		return "capstone-lacks-STGP(MTE)";
	if ((w & 0x1fc00000u) == 0x11c00000u)
		return "capstone-lacks-SMAX/UMAX/SMIN/UMIN-imm(CSSC)";
	return NULL;
}

static const char *regalias(csh h, cs_insn *in, uint32_t w, uint64_t va)
{
	static const struct { unsigned lo; const char *name; } f[] = {
		{ 0, "Rt" }, { 10, "Rt2" }, { 16, "Rs/Rm" }, { 5, "Rn" },
	};
	unsigned i, v;

	for (i = 0; i < 4; i++)
		for (v = 0; v < 32; v++) {
			uint32_t x = (w & ~(31u << f[i].lo)) | (v << f[i].lo);

			if (x != w && cs_ok(h, in, x, va))
				return f[i].name;
		}
	{
		uint32_t x = w | (31u << 16) | (31u << 10);

		if (cs_ok(h, in, x, va))
			return "SBO(Rs,Rt2)";
	}
	/* two constraints at once (ldp x1,x1,[x1]!): change two fields */
	{
		unsigned j, u, q;

		for (i = 0; i < 4; i++)
			for (j = i + 1; j < 4; j++)
				for (u = 0; u < 32; u++)
					for (q = 0; q < 32; q++) {
						uint32_t x = (w & ~(31u << f[i].lo) &
							      ~(31u << f[j].lo)) |
							     (u << f[i].lo) | (q << f[j].lo);

						if (cs_ok(h, in, x, va))
							return "two register fields";
					}
	}
	return NULL;
}

/* ---- one word, both decoders ------------------------------------------------ */

struct tctx {
	csh h;
	cs_insn *in;
	struct stats *st;
};

static void describe(const cs_insn *in, char *buf, size_t n)
{
	snprintf(buf, n, "%s %s", in->mnemonic, in->op_str);
}

static const char *kname(unsigned k)
{
	return k < CELL_OP_COUNT ? KN[k] : "?";
}

static void check(struct tctx *c, uint32_t w, uint64_t va)
{
	struct stats *st = c->st;
	uint8_t bytes[4] = { (uint8_t)w, (uint8_t)(w >> 8), (uint8_t)(w >> 16),
			     (uint8_t)(w >> 24) };
	const uint8_t *p = bytes;
	size_t sz = 4;
	uint64_t addr = va;
	struct cell_insn k;
	int cv, ov;
	char key[96], text[200], cs_text[120];
	const cs_insn *in = c->in;

	st->words++;
	cv = cs_disasm_iter(c->h, &p, &sz, &addr, c->in);
	if (cell_decode_a64(bytes, 4, va, &k) != 4) {
		fprintf(stderr, "a64_diff: decoder returned a length other than 4\n");
		exit(2);
	}
	/* `udf` is defined and faults; Capstone calls it valid, we call it UD. */
	ov = k.op != CELL_UD || (w >> 16) == 0;
	if (cv)
		st->cap_valid++;
	if (ov)
		st->our_valid++;
	if (!cv && !ov)
		return;
	if (cv)
		describe(in, cs_text, sizeof cs_text);
	else
		snprintf(cs_text, sizeof cs_text, "(invalid)");
	if (cv != ov) {
		if (cv) {
			st->cap_only++;
			if ((!strcmp(in->mnemonic, "mrs") || !strcmp(in->mnemonic, "msr")) &&
			    ((w >> 19) & 3u) < 2u)
				snprintf(key, sizeof key,
					 "valid: cap-valid ours-UD: capstone-generic-sysreg(op0<2) %s",
					 in->mnemonic);
			else
				snprintf(key, sizeof key, "valid: cap-valid ours-UD: %s",
					 in->mnemonic);
		} else {
			unsigned g = (w >> 25) & 15u;
			const char *al;

			st->our_only++;
			if (g == 0 || g == 2 || g == 7 || g == 15)
				snprintf(key, sizeof key,
					 "valid: cap-invalid ours-valid: UNDECIDED-SPACE grp%02x",
					 g);
			else if ((al = cap_lacks(w)))
				snprintf(key, sizeof key,
					 "valid: cap-invalid ours-valid: %s", al);
			else if (probe_every > 1 && ((w * 2654435761u) >> 20) % probe_every)
				snprintf(key, sizeof key,
					 "valid: cap-invalid ours-valid: not probed (constrained-unpredictable or other): grp%02x",
					 g);
			else if ((al = regalias(c->h, c->in, w, va)))
				snprintf(key, sizeof key,
					 "valid: cap-invalid ours-valid: constrained-unpredictable (%s): grp%02x",
					 al, g);
			else
				snprintf(key, sizeof key,
					 "valid: cap-invalid ours-valid: grp%02x %s top=%02x",
					 g, kname(k.op), w >> 24);
		}
		snprintf(text, sizeof text, "%s | ours %s wmask=%llx", cs_text,
			 kname(k.op), (unsigned long long)k.wmask);
		note(st, key, w, va, text);
		return;
	}
	st->both_valid++;

	/* class */
	{
		uint64_t ok = want(in, w);

		if (!(ok & B(k.op))) {
			char ws[200];

			st->cmp_class++;
			snprintf(key, sizeof key, "class: %s -> %s", in->mnemonic,
				 kname(k.op));
			snprintf(ws, sizeof ws, "%s | ours %s n_op=%u", cs_text,
				 kname(k.op), k.n_op);
			note(st, key, w, va, ws);
		}
	}

	/* branch target */
	{
		const char *m = in->mnemonic;
		const cs_arm64 *a = &in->detail->arm64;

		if (!strcmp(m, "b") || !strcmp(m, "bl") || starts(m, "b.") ||
		    starts(m, "bc.") || !strcmp(m, "cbz") || !strcmp(m, "cbnz") ||
		    !strcmp(m, "tbz") || !strcmp(m, "tbnz")) {
			uint64_t t = 0;
			int i;

			for (i = 0; i < a->op_count; i++)
				if (a->operands[i].type == ARM64_OP_IMM)
					t = (uint64_t)a->operands[i].imm;
			st->cmp_target++;
			if (t != k.target_va || k.o[0].kind != CELL_O_REL) {
				snprintf(key, sizeof key, "target: %s", m);
				snprintf(text, sizeof text, "%s | cap %llx ours %llx",
					 cs_text, (unsigned long long)t,
					 (unsigned long long)k.target_va);
				note(st, key, w, va, text);
			}
		} else if (k.op == CELL_JMP || k.op == CELL_CALL ||
			   k.op == CELL_JCC) {
			if (!(k.flags & CELL_F_INDIRECT) && k.target_va == KOF_BROKEN) {
				snprintf(key, sizeof key, "target: direct branch with no target %s", m);
				note(st, key, w, va, cs_text);
			}
		}
		if ((k.flags & CELL_F_INDIRECT) && k.target_va != KOF_BROKEN) {
			snprintf(key, sizeof key, "target: indirect with target %s", m);
			note(st, key, w, va, cs_text);
		}
	}

	/* written registers */
	{
		uint64_t cm = cs_wmask(c->h, in), om = k.wmask;

		/*
		 * Capstone reports no write access at all for the SVE
		 * instructions that write a general register (cntb x0 has an
		 * empty write list and access 0 on its operand), so in that
		 * space the oracle is the architecture's own syntax: a first
		 * operand that is a general register is the destination, bar
		 * ctermeq/ctermne which only read it.
		 */
		if (((w >> 25) & 15u) == 2u) {
			const cs_arm64 *a = &in->detail->arm64;
			int g;

			cm = 0;
			if (a->op_count > 0 && a->operands[0].type == ARM64_OP_REG &&
			    strncmp(in->mnemonic, "cterm", 5) &&
			    (g = gpr(a->operands[0].reg)) >= 0 && g < 32)
				cm = 1ull << g;
		}

		st->cmp_wmask++;
		if (cm != om) {
			uint64_t extra = om & ~cm, miss = cm & ~om;

			const char *why = cs_wrong(in->mnemonic, w, extra, miss);

			if (why)
				snprintf(key, sizeof key, "wmask(%s): %s", why, in->mnemonic);
			else
				snprintf(key, sizeof key, "wmask: %s: %s%s", in->mnemonic,
					 miss ? "ours-missing " : "",
					 extra ? "ours-extra" : "");
			snprintf(text, sizeof text, "%s | cap=%llx ours=%llx",
				 cs_text, (unsigned long long)cm,
				 (unsigned long long)om);
			note(st, key, w, va, text);
		}
	}

	/* mov immediates and adr */
	{
		const char *m = in->mnemonic;
		const cs_arm64 *a = &in->detail->arm64;

		if ((!strcmp(m, "mov") || !strcmp(m, "movz") || !strcmp(m, "movn")) &&
		    a->op_count >= 2 && a->operands[1].type == ARM64_OP_IMM &&
		    gpr(a->operands[0].reg) >= 0 && gpr(a->operands[0].reg) != 32 &&
		    k.op == CELL_MOV) {
			uint64_t v = (uint64_t)a->operands[1].imm;
			uint64_t sh = a->operands[1].shift.value;
			unsigned sf = (unsigned)(w >> 31);

			if (!strcmp(m, "movz") || !strcmp(m, "movn")) {
				v <<= sh;
				if (!strcmp(m, "movn"))
					v = ~v;
			}
			if (!sf)
				v &= 0xffffffffull;
			st->cmp_imm++;
			if (k.n_op < 2 || k.o[1].kind != CELL_O_IMM ||
			    k.o[1].imm != v) {
				if (!strcmp(m, "mov") && k.o[1].kind == CELL_O_REG)
					goto adr;       /* the register form */
				snprintf(key, sizeof key, "imm: %s", m);
				snprintf(text, sizeof text, "%s | cap %llx ours %llx",
					 cs_text, (unsigned long long)v,
					 (unsigned long long)k.o[1].imm);
				note(st, key, w, va, text);
			}
		}
adr:
		if ((!strcmp(m, "adr") || !strcmp(m, "adrp")) &&
		    a->op_count >= 2 && a->operands[1].type == ARM64_OP_IMM &&
		    k.op == CELL_LEA) {
			st->cmp_adr++;
			if (k.n_op < 2 ||
			    k.o[1].imm != (uint64_t)a->operands[1].imm) {
				snprintf(key, sizeof key, "adr: %s", m);
				snprintf(text, sizeof text, "%s | cap %llx ours %llx",
					 cs_text, (unsigned long long)a->operands[1].imm,
					 (unsigned long long)k.o[1].imm);
				note(st, key, w, va, text);
			}
		}
	}
}

/* ---- drivers ----------------------------------------------------------------- */

static uint64_t splitmix(uint64_t *s)
{
	uint64_t z = (*s += 0x9e3779b97f4a7c15ull);

	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
	return z ^ (z >> 31);
}

static void tctx_open(struct tctx *c)
{
	cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &c->h);
	cs_option(c->h, CS_OPT_DETAIL, CS_OPT_ON);
	c->in = cs_malloc(c->h);
	c->st = calloc(1, sizeof *c->st);
}

struct job {
	int id;
	int mode;                       /* 0 random, 1 systematic, 2 elf */
	uint64_t n;
	const char **files;
	int nfiles;
	struct tctx c;
};

static void do_elf(struct tctx *c, const char *path)
{
	FILE *f = fopen(path, "rb");
	uint8_t *buf;
	long len;
	const Elf64_Ehdr *eh;
	int i;

	if (!f)
		return;
	fseek(f, 0, SEEK_END);
	len = ftell(f);
	fseek(f, 0, SEEK_SET);
	buf = malloc((size_t)len);
	if (!buf || fread(buf, 1, (size_t)len, f) != (size_t)len) {
		fclose(f);
		free(buf);
		return;
	}
	fclose(f);
	eh = (const Elf64_Ehdr *)buf;
	if ((size_t)len < sizeof *eh || memcmp(buf, ELFMAG, 4) || eh->e_machine != 183 ||
	    buf[EI_CLASS] != ELFCLASS64)
		goto out;
	if (eh->e_shoff && eh->e_shoff + (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr) <= (uint64_t)len) {
		const Elf64_Shdr *sh = (const Elf64_Shdr *)(buf + eh->e_shoff);

		for (i = 0; i < eh->e_shnum; i++) {
			uint64_t off, o;

			if (!(sh[i].sh_flags & SHF_EXECINSTR) || sh[i].sh_type != SHT_PROGBITS ||
			    sh[i].sh_offset + sh[i].sh_size > (uint64_t)len)
				continue;
			off = sh[i].sh_offset;
			for (o = 0; o + 4 <= sh[i].sh_size; o += 4) {
				uint32_t w;

				memcpy(&w, buf + off + o, 4);
				check(c, w, sh[i].sh_addr + o);
			}
		}
	}
out:
	free(buf);
}

static void *worker(void *arg)
{
	struct job *j = arg;
	uint64_t s = 0x4b4f464e47ull + (uint64_t)j->id * 0x100000001b3ull, i;

	tctx_open(&j->c);
	if (j->mode == 0) {
		for (i = 0; i < j->n; i++) {
			uint64_t r = splitmix(&s);

			check(&j->c, (uint32_t)r, 0x400000ull + ((r >> 32) & 0xffffc));
		}
	} else if (j->mode == 1) {
		/* combos of bits 31..24 and 15..10 are divided among the threads */
		unsigned combo;

		for (combo = (unsigned)j->id; combo < 256u * 64u; combo += NTHR) {
			uint32_t hi = (combo >> 6) & 255u, mid = combo & 63u;

			for (i = 0; i < j->n; i++) {
				uint64_t r = splitmix(&s);
				uint32_t w = ((uint32_t)r & 0x00ff03ffu) |
					     (hi << 24) | (mid << 10);

				check(&j->c, w, 0x400000ull + ((r >> 40) & 0xffffc));
			}
		}
	} else if (j->mode == 3) {
		uint64_t q;

		for (q = (uint64_t)j->id; q < (1ull << 28); q += NTHR) {
			uint32_t w = (uint32_t)(((q >> 25) & 7u) << 29) |
				     (uint32_t)(j->n << 25) | (uint32_t)(q & 0x1ffffffu);

			check(&j->c, w, 0x400000ull + ((w >> 3) & 0xffffc));
		}
	} else {
		int f;

		for (f = j->id; f < j->nfiles; f += NTHR)
			do_elf(&j->c, j->files[f]);
	}
	return NULL;
}

static int cmpb(const void *a, const void *b)
{
	const struct bucket *x = a, *y = b;

	return x->n < y->n ? 1 : x->n > y->n ? -1 : strcmp(x->key, y->key);
}

static void report(const char *name, struct stats *st, int verbose)
{
	size_t i, nb = 0;
	struct bucket *list = malloc(NSLOT * sizeof *list);
	unsigned k;

	for (i = 0; i < NSLOT; i++)
		if (st->b[i].n)
			list[nb++] = st->b[i];
	qsort(list, nb, sizeof *list, cmpb);
	printf("== %s: words %llu  cap-valid %llu  ours-valid %llu  both %llu"
	       "  cap-only %llu  ours-only %llu\n", name,
	       (unsigned long long)st->words, (unsigned long long)st->cap_valid,
	       (unsigned long long)st->our_valid, (unsigned long long)st->both_valid,
	       (unsigned long long)st->cap_only, (unsigned long long)st->our_only);
	printf("   compared on the %llu words both call valid: class, wmask; target %llu; imm %llu; adr %llu\n",
	       (unsigned long long)st->both_valid, (unsigned long long)st->cmp_target,
	       (unsigned long long)st->cmp_imm, (unsigned long long)st->cmp_adr);
	(void)k;
	for (i = 0; i < nb && (verbose || i < 400); i++) {
		unsigned e;

		printf("  %-62s %10llu\n", list[i].key, (unsigned long long)list[i].n);
		for (e = 0; e < 3 && e < list[i].n; e++)
			printf("      %08x @%llx  %s\n", list[i].ex[e].w,
			       (unsigned long long)list[i].ex[e].va, list[i].ex[e].text);
	}
	if (st->full)
		printf("  (bucket table full: %llu notes dropped)\n",
		       (unsigned long long)st->full);
	free(list);
}

/* sums for the headline table */
static void headline(const char *name, const struct stats *st)
{
	size_t i;
	uint64_t cls = 0, tgt = 0, wm = 0, wx = 0, imm = 0, adr = 0, cv = 0;
	uint64_t ov = 0, und = 0, cu = 0, lack = 0;

	for (i = 0; i < NSLOT; i++) {
		const struct bucket *b = &st->b[i];

		if (!b->n)
			continue;
		if (starts(b->key, "class:")) cls += b->n;
		else if (starts(b->key, "target:")) tgt += b->n;
		else if (starts(b->key, "wmask(")) wx += b->n;
		else if (starts(b->key, "wmask:")) wm += b->n;
		else if (starts(b->key, "imm:")) imm += b->n;
		else if (starts(b->key, "adr:")) adr += b->n;
		else if (starts(b->key, "valid: cap-valid")) cv += b->n;
		else if (strstr(b->key, "UNDECIDED")) und += b->n;
		else if (strstr(b->key, "constrained")) cu += b->n;
		else if (strstr(b->key, "capstone-lacks")) lack += b->n;
		else if (starts(b->key, "valid: cap-invalid")) ov += b->n;
	}
	printf("HEADLINE %-10s words %llu | cap-valid&ours-UD %llu | cap-invalid&ours-valid: "
	       "undecided-space %llu, constrained-unpredictable/SBO(+unprobed) %llu, capstone-lacks-feature %llu, other %llu\n"
	       "           both-valid %llu: class-diff %llu, target-diff %llu/%llu, wmask-diff %llu"
	       " (+%llu explained Capstone omissions)/%llu, imm-diff %llu/%llu, adr-diff %llu/%llu\n",
	       name, (unsigned long long)st->words, (unsigned long long)cv,
	       (unsigned long long)und, (unsigned long long)cu, (unsigned long long)lack,
	       (unsigned long long)ov,
	       (unsigned long long)st->both_valid, (unsigned long long)cls,
	       (unsigned long long)tgt, (unsigned long long)st->cmp_target,
	       (unsigned long long)wm, (unsigned long long)wx,
	       (unsigned long long)st->cmp_wmask, (unsigned long long)imm,
	       (unsigned long long)st->cmp_imm, (unsigned long long)adr,
	       (unsigned long long)st->cmp_adr);
}

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

static void speed(const char *elf_list)
{
	enum { N = 1 << 20 };
	uint32_t *w = malloc(N * sizeof *w);
	uint8_t *buf = malloc((size_t)N * 4);
	uint64_t s = 99;
	size_t n = 0, i;
	int rep;
	double t0, t1;
	volatile uint64_t sink = 0;
	struct cell_insn k;

	while (n < N) {
		uint32_t x = (uint32_t)splitmix(&s);

		if (cell_decode_a64((const uint8_t *)&x, 4, 0, &k) == 4 && k.op != CELL_UD)
			w[n++] = x;
	}
	memcpy(buf, w, (size_t)N * 4);
	t0 = now();
	for (rep = 0; rep < 20; rep++)
		for (i = 0; i < N; i++) {
			cell_decode_a64(buf + i * 4, 4, 0x400000 + i * 4, &k);
			sink += k.wmask + k.op;
		}
	t1 = now();
	printf("SPEED random valid words: %.1f ns/insn (%d insns)\n",
	       (t1 - t0) * 1e9 / (20.0 * N), 20 * N);
	/* all random words, valid or not */
	for (i = 0; i < N; i++) {
		uint32_t x = (uint32_t)splitmix(&s);

		memcpy(buf + i * 4, &x, 4);
	}
	t0 = now();
	for (rep = 0; rep < 20; rep++)
		for (i = 0; i < N; i++) {
			cell_decode_a64(buf + i * 4, 4, 0x400000 + i * 4, &k);
			sink += k.wmask + k.op;
		}
	t1 = now();
	printf("SPEED random words (incl. unallocated): %.1f ns/insn\n",
	       (t1 - t0) * 1e9 / (20.0 * N));
	if (elf_list) {
		FILE *f = fopen(elf_list, "r");
		char line[1024];
		uint8_t *code = malloc(256u << 20);
		size_t cn = 0;

		while (f && fgets(line, sizeof line, f)) {
			FILE *g;
			long len;
			uint8_t *b;
			const Elf64_Ehdr *eh;
			int q;

			line[strcspn(line, "\n")] = 0;
			g = fopen(line, "rb");
			if (!g)
				continue;
			fseek(g, 0, SEEK_END);
			len = ftell(g);
			fseek(g, 0, SEEK_SET);
			b = malloc((size_t)len);
			if (fread(b, 1, (size_t)len, g) != (size_t)len) {
				fclose(g);
				free(b);
				continue;
			}
			fclose(g);
			eh = (const Elf64_Ehdr *)b;
			if (memcmp(b, ELFMAG, 4) || eh->e_machine != 183 || !eh->e_shoff ||
			    eh->e_shoff + (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr) > (uint64_t)len) {
				free(b);
				continue;
			}
			for (q = 0; q < eh->e_shnum; q++) {
				const Elf64_Shdr *sh = (const Elf64_Shdr *)(b + eh->e_shoff) + q;

				if ((sh->sh_flags & SHF_EXECINSTR) && sh->sh_type == SHT_PROGBITS &&
				    sh->sh_offset + sh->sh_size <= (uint64_t)len &&
				    cn + sh->sh_size < (256u << 20)) {
					memcpy(code + cn, b + sh->sh_offset, sh->sh_size & ~3ull);
					cn += sh->sh_size & ~3ull;
				}
			}
			free(b);
		}
		if (cn) {
			size_t cnt = cn / 4;
			int reps = (int)(200000000ull / cnt) + 1;

			t0 = now();
			for (rep = 0; rep < reps; rep++)
				for (i = 0; i < cnt; i++) {
					cell_decode_a64(code + i * 4, 4, 0x400000 + i * 4, &k);
					sink += k.wmask + k.op;
				}
			t1 = now();
			printf("SPEED real code: %.1f ns/insn (%zu distinct words, %d passes)\n",
			       (t1 - t0) * 1e9 / ((double)reps * (double)cnt), cnt, reps);
		} else {
			printf("SPEED real code: none found\n");
		}
	}
	(void)sink;
}

int main(int argc, char **argv)
{
	uint64_t nrand = 0, nsys = 0;
	const char *elf = NULL, *dump = NULL;
	int verbose = 0, dospeed = 0, a, exh = -1;

	for (a = 1; a < argc; a++) {
		if (!strcmp(argv[a], "-r") && a + 1 < argc) nrand = strtoull(argv[++a], 0, 0);
		else if (!strcmp(argv[a], "-s") && a + 1 < argc) nsys = strtoull(argv[++a], 0, 0);
		else if (!strcmp(argv[a], "-e") && a + 1 < argc) elf = argv[++a];
		else if (!strcmp(argv[a], "-d") && a + 1 < argc) dump = argv[++a];
		else if (!strcmp(argv[a], "-t")) dospeed = 1;
		else if (!strcmp(argv[a], "-x") && a + 1 < argc) { exh = (int)strtol(argv[++a], 0, 0); }
		else if (!strcmp(argv[a], "-p") && a + 1 < argc) probe_every = (unsigned)strtoul(argv[++a], 0, 0);
		else if (!strcmp(argv[a], "-v")) verbose = 1;
	}
	if (dump) {
		struct tctx c;
		uint32_t w = (uint32_t)strtoul(dump, 0, 16);
		uint8_t b[4] = { (uint8_t)w, (uint8_t)(w >> 8), (uint8_t)(w >> 16), (uint8_t)(w >> 24) };
		const uint8_t *p = b;
		size_t sz = 4;
		uint64_t ad = 0x400000;
		struct cell_insn k;
		int cv, i;

		tctx_open(&c);
		cv = cs_disasm_iter(c.h, &p, &sz, &ad, c.in);
		printf("cap: %s", cv ? "" : "(invalid)");
		if (cv) {
			const cs_arm64 *x = &c.in->detail->arm64;

			printf("%s %s  id=%u cc=%d wb=%d n=%d\n", c.in->mnemonic, c.in->op_str,
			       c.in->id, x->cc, x->writeback, x->op_count);
			for (i = 0; i < x->op_count; i++)
				printf("   op%d type=%d reg=%d imm=%lld sft=%d/%u ext=%d acc=%d\n", i,
				       x->operands[i].type, x->operands[i].type == ARM64_OP_REG ? (int)x->operands[i].reg : 0,
				       x->operands[i].type == ARM64_OP_IMM ? (long long)x->operands[i].imm : 0,
				       x->operands[i].shift.type, x->operands[i].shift.value,
				       x->operands[i].ext, x->operands[i].access);
			printf("   cs_wmask=%llx\n", (unsigned long long)cs_wmask(c.h, c.in));
		} else {
			printf("\n");
		}
		cell_decode_a64(b, 4, 0x400000, &k);
		printf("ours: op=%s n_op=%u cond=%u flags=%x wmask=%llx target=%llx\n", kname(k.op),
		       k.n_op, k.cond, k.flags, (unsigned long long)k.wmask,
		       (unsigned long long)k.target_va);
		for (i = 0; i < k.n_op; i++)
			printf("   o%d kind=%u reg=%u idx=%u scale=%u size=%u fl=%x disp=%lld imm=%llx\n", i,
			       k.o[i].kind, k.o[i].reg, k.o[i].index, k.o[i].scale, k.o[i].size,
			       k.o[i].flags, (long long)k.o[i].disp, (unsigned long long)k.o[i].imm);
		return 0;
	}
	if (dospeed) {
		speed(elf);
		return 0;
	}
	{
		int mode;
		const char *names[4] = { "random", "systematic", "elf", "" };
		char **files = NULL;
		int nfiles = 0;

		if (elf) {
			FILE *f = fopen(elf, "r");
			char line[1024];

			while (f && fgets(line, sizeof line, f)) {
				line[strcspn(line, "\n")] = 0;
				if (line[0]) {
					files = realloc(files, (size_t)(nfiles + 1) * sizeof *files);
					files[nfiles++] = strdup(line);
				}
			}
		}
		for (mode = 0; mode < 4; mode++) {
			uint64_t n = mode == 0 ? nrand : mode == 1 ? nsys :
				     mode == 2 ? 1 : (uint64_t)exh;
			char exname[32];

			if (mode == 3) {
				if (exh < 0)
					continue;
				snprintf(exname, sizeof exname, "exhaustive-grp%02x", exh);
				names[3] = exname;
			}
			struct job *jobs;
			pthread_t th[NTHR];
			struct stats *tot;
			int t;
			double t0 = now();

			if ((!n && mode != 3) || (mode == 2 && !nfiles))
				continue;
			jobs = calloc(NTHR, sizeof *jobs);
			tot = calloc(1, sizeof *tot);
			for (t = 0; t < NTHR; t++) {
				jobs[t].id = t;
				jobs[t].mode = mode;
				jobs[t].n = n;
				jobs[t].files = (const char **)files;
				jobs[t].nfiles = nfiles;
				pthread_create(&th[t], NULL, worker, &jobs[t]);
			}
			for (t = 0; t < NTHR; t++) {
				pthread_join(th[t], NULL);
				merge(tot, jobs[t].c.st);
			}
			report(names[mode], tot, verbose);
			headline(names[mode], tot);
			printf("   (%.1f s)\n", now() - t0);
		}
	}
	return 0;
}
