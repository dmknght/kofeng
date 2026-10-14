/*
 * diff_decode_cover - every instruction the decoder knows is either carried by the interpreter, or its decode is checked
 * against an independent reader and the reason it is not carried is written down. Nothing is left to be found out when a
 * packer stub stops on it.
 *
 * The decoder's table names 1748 instructions; the interpreter carries about five hundred of them. The gap is deliberate (an
 * unpacker needs the integer set, string moves, SSE and x87, not AVX-512 or the system instructions: CPUID and XGETBV tell a
 * guest it has x87 and SSE2 and nothing newer), and a gap that is not written down is
 * how a new decoder row ends up with no emulation and nobody notices: the run stops on it as UNSUPPORTED, a packer stub that
 * uses it is never unpacked, and nothing says why. The same gap is where a decoder LENGTH error hides: an instruction nobody
 * runs is an instruction nobody has compared, and one wrong length desynchronises every walk after it.
 *
 * THE SWEEP. Every encoding the decoder can be made to accept is generated - the one byte opcodes and the 0F, 0F38 and 0F3A
 * maps behind none, 66, F2, F3, 67, REX.W and 66+REX.W with EVERY ModRM byte; VEX (C5 and C4, the three maps, pp, L, W, a
 * vvvv in use and not), XOP, and EVEX (the maps 1-3 and the FP16 maps 5-6, pp, W, L'L, b, a mask and zeroing) with the ModRM
 * forms that decide a length and a register kind - in 64 and 32 bit mode, about forty-four million encodings (a second), and decoded. For
 * each instruction the decoder names (its id) up to eight encodings of different shape (mode, length, size prefix, address
 * size, SIB, displacement) are kept. The count of ids reached is printed; one that is not reached has to be in UNREACHED
 * with the reason (no decoder can be made to produce it).
 *
 * THE RULES, each a FAIL:
 *   1. emulated or listed: up to six encodings of the id are placed in the interpreter and run, with operands that make every
 *      carried instruction succeed. EMULATED when any runs; otherwise the interpreter stops with
 *      KGENOME_EMU_STOP_UNSUPPORTED and the id has to match one row of ROWS - a mnemonic, or a family by prefix or suffix, with
 *      the reason it is not carried. A row that matches nothing unsupported is a FAIL too (delete it), so ROWS is the list of
 *      what is NOT carried and nothing else.
 *   2. length verified: every kept encoding of an id, and one encoding of every leaf of the decoder's table in each size and
 *      address variant the sweep meets, goes to GNU objdump (a reader written by other people), which says how long it is. The
 *      decoder must agree on every one it decodes (one class is not an error: length_exception()); an instruction for which
 *      objdump agrees on none and which is not in UNVERIFIED (with the reason objdump cannot tell: it lacks the instruction,
 *      or reads the bytes as another) is a FAIL. Skipped, and said, when objdump is not installed.
 *   3. named as objdump names it: the mnemonic of each of those encodings, after the spellings the two readers differ on by
 *      design (names_agree, objdump_kit.h), is the same, or the id is in NAME_DIFFERS with the reason. This is what finds a
 *      decoder row that is the right length and the wrong instruction (0F 12 with a memory operand named MOVHLPS; the XOP
 *      VPSHLW named VPSHLB): both were in the table before this test could see them.
 *   4. reached: an id the sweep does not reach is in UNREACHED (APX, 3DNow!) with the reason, or the sweep is widened until
 *      it does; an id that is reached and listed is a FAIL (delete the row).
 * The operand SHAPE of each kept encoding (how many operands, each a register, memory or immediate) is compared with objdump's
 * and listed with -v: it differs for the implicit operands one reader writes and the other does not (the x87 stack top, the
 * string registers, XMM0 of BLENDV), which is not a finding, so it is a report and not a rule.
 * It prints how many instructions fall in each reason. With -v it lists the names; with -l what is missing from the tables.
 *
 * The sweep decodes bytes only; nothing here reads a file or the environment, and objdump reads an anonymous memory file.
 * Nothing in it is a rule about what an unpacker needs: a row says what is not carried and why, and is deleted the day it is.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include <phenotype/emu.h>
#include <kgenome.h>
#include <genotype/x86/x86.h>
#include <genotype/x86/x86_ids.h>

#include "objdump_kit.h"

static int fails;

#define CK(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		fails++; \
	} \
} while (0)

#define NID KGENOME_X86_I__COUNT
#define SAMPLES 8u          /* encodings of one id kept: of different shape */
#define TRIES 6u            /* of them placed in the interpreter */

struct seen {
	uint8_t  n[SAMPLES];
	uint8_t  b[SAMPLES][16];
	uint8_t  mode[SAMPLES];
	uint64_t key[SAMPLES];
	unsigned count;                 /* samples kept */
	char     name[24];
	int      emulated;
	unsigned len_ok, len_bad, len_silent, len_waived;
	unsigned shape_ok, shape_bad;
	char     shape_theirs[12], shape_ours[12];
	uint8_t  shape_b[16];
	uint8_t  shape_n, shape_mode;
	unsigned name_ok, name_bad;
	char     name_theirs[24], name_ours[24];
	uint8_t  name_b[16];
	uint8_t  name_n, name_mode;
	uint8_t  bad_b[16];             /* the first encoding objdump disagreed on, and what it said */
	uint8_t  bad_n, bad_mode;
	unsigned bad_theirs;
	char     bad_text[80];
};

static struct seen tab[NID];
static unsigned long encodings;

/*
 * ONE ENCODING OF EVERY LEAF OF THE DECODER'S TABLE, in every size and address variant the sweep meets: what is checked
 * against objdump is not only the encodings kept per id (those are what the interpreter is run on) but one for each distinct
 * (leaf, operand size, address size, prefix) - the opcodes an id is spelled with, which a per-id sample of the first shapes
 * met would leave out. Found by a sample this size: the XOP VPSHLW and VPSHLD with W = 1 named VPSHLB (the reference decoder's
 * own mistake, corrected where the table is made: tools/genotype/oracle_fix.h).
 */
struct item {
	unsigned id;
	uint8_t  mode, n;
	uint8_t  b[16];
};

#define MAX_ITEMS 80000u
static struct item items[MAX_ITEMS];
static unsigned n_items;
static uint8_t leaf_seen[(1u << 22) / 8u];

/* the reason an instruction is not carried: a row matches the mnemonic exactly, by prefix when it ends in '*', by suffix when it begins with one */
struct row {
	const char *pat;
	const char *why;
};

#define R_AVX     "VEX, EVEX and XOP vector encodings (AVX, AVX2, AVX-512, FMA, the BMI VEX forms not carried): XCR0 and CPUID say x87 and SSE only, so a guest does not choose them, and the interpreter keeps 128 bit xmm registers - no 256 or 512 bit state to run them on"
#define R_SYS     "system, privileged, virtualisation and enclave instructions: no ring 0, segments, descriptor tables, control registers, model-specific registers, port I/O, SEV/TDX/SGX or shadow stack is modelled; a run that reaches one has left the program"
#define R_SSEFP   "SSE floating point with no single right answer or no use outside AMD: RCPPS/RSQRTPS/RCPSS/RSQRTSS give an approximation whose last bits differ between cores, EXTRQ/INSERTQ are SSE4a (AMD only); DPPS and DPPD with a NaN in a lane that takes part stop too, but they are not listed here: the id is carried"
#define R_CRYPTO  "SHA extensions, GF2P8, the Key Locker AES forms and the random number instructions: nothing that unpacks a payload needs them, CPUID reports none, and RDRAND/RDSEED have no deterministic answer to give"
#define R_X87     "undocumented 80287 opcodes (FSTDW, FSTSG, FRINEAR, FSTPNCE, FNDISI/FNENI): not an instruction of any CPU since the 80387"
#define R_STATE   "extended-state save and restore (XSAVE, XRSTOR and their variants): CPUID leaf 0xD reports nothing, so a runtime saves with FXSAVE, which is carried"
#define R_RARE    "rarely used integer, string and flag instructions not met in any sample (BOUND, the CMPccXADD and atomic bit ops of the newest cores, MOVDIRI/MOVDIR64B)"
#define R_TBM     "AMD TBM (BLCFILL ... TZMSK, Piledriver and Steamroller only) and LWP (LLWPCB, LWPINS, LWPVAL, SLWPCB, Bulldozer family only): withdrawn from every later core, none in the corpora"
#define R_AMX     "AMX tile instructions: 1 KiB tile registers and a tile configuration the interpreter does not keep; Sapphire Rapids and later, none in the corpora"
#define R_KNC     "Xeon Phi only (Knights Corner and Landing: CLEVICT0/1, DELAY, SPFLT): no other core runs them"
#define R_TSX     "TSX and protection keys (XBEGIN, XEND, XABORT, XTEST, XSUSLDTRK, RDPKRU, WRPKRU): CPUID reports neither RTM nor PKU, so a guest that asks does not use them, and there is no transaction to run"
#define R_APX     "APX (REX2 and the APX forms of EVEX): 64-bit mode, Intel cores after 2026; the decoder reports them as not an instruction (x86.h) and no corpus encodes them"
#define R_3DNOW   "3DNow! (0F 0F, the opcode in a suffix byte after the operands): AMD K6-2 to K10, withdrawn in 2010; the decoder reports it as not an instruction and no corpus encodes it"
#define R_KNC_OD  "Xeon Phi (Knights Corner) only: objdump has no such instruction; the decode is the reference decoder's, measured by tools/genotype/x86_diff.c"
#define R_X87_OD  "undocumented 80287 opcode: objdump lists the bytes as (bad); the decode is the reference decoder's, measured by tools/genotype/x86_diff.c"

/* Filled in from the sweep's own findings (see main); every name here was observed UNSUPPORTED. */
extern const struct row ROWS[];
extern const unsigned NROWS;

static int match(const struct row *r, const char *name)
{
	size_t n = strlen(r->pat);

	if (n && r->pat[n - 1u] == '*')
		return !strncmp(name, r->pat, n - 1u);
	if (n && r->pat[0] == '*') {                    /* a family by suffix: "*BF16" */
		const size_t l = strlen(name);

		return l >= n - 1u && !strcmp(name + l - (n - 1u), r->pat + 1);
	}
	return !strcmp(name, r->pat);
}

/* ---- the sweep --------------------------------------------------------------------------- */

/* the shape of a decoded encoding, as one number: what makes two encodings of an id worth keeping both */
static uint64_t shape_key(const struct kgenome_x86_insn *in, unsigned mode)
{
	return (uint64_t)mode | ((uint64_t)in->len << 8) | ((uint64_t)in->dsz << 16) | ((uint64_t)in->sp << 20) |
	       ((uint64_t)in->osz << 24) | ((uint64_t)in->asz << 32) |
	       ((uint64_t)(in->flags & (KGENOME_GF_X86_66 | KGENOME_GF_X86_67 | KGENOME_GF_X86_REX | KGENOME_GF_X86_SIB |
					KGENOME_GF_X86_F2 | KGENOME_GF_X86_F3 | KGENOME_GF_X86_MODRM | KGENOME_GF_X86_RIPREL)) << 40);
}

static void record(const uint8_t *b, unsigned mode)
{
	struct kgenome_x86_insn in;
	struct seen *s;
	uint64_t key;
	unsigned i;

	encodings++;
	if (kgenome_x86_decode(&in, b, 15, (int)mode) != KGENOME_OK || in.id >= NID || in.len == 0 || in.len > 15)
		return;
	s = &tab[in.id];
	if (!s->name[0]) {
		char t[KGENOME_X86_TEXT];
		const char *p;

		kgenome_x86_format(&in, 0x1000, t, sizeof t);
		/* the mnemonic: after any prefix words the formatter writes in front of it */
		p = t;
		for (;;) {
			if (!strncmp(p, "REP ", 4) || !strncmp(p, "REPZ ", 5) || !strncmp(p, "REPNZ ", 6) || !strncmp(p, "LOCK ", 5) ||
			    !strncmp(p, "BND ", 4) || !strncmp(p, "XACQUIRE ", 9) || !strncmp(p, "XRELEASE ", 9) || !strncmp(p, "NOTRACK ", 8) ||
			    !strncmp(p, "REPE ", 5) || !strncmp(p, "REPNE ", 6)) {
				p = strchr(p, ' ') + 1;
				while (*p == ' ')
					p++;
				continue;
			}
			break;
		}
		for (i = 0; i + 1u < sizeof s->name && p[i] && p[i] != ' '; i++)
			s->name[i] = p[i];
		s->name[i] = 0;
		if (!s->name[0])
			snprintf(s->name, sizeof s->name, "id%u", (unsigned)in.id);
	}
	{
		const unsigned lk = ((unsigned)in.leaf << 6) | ((in.osz & 7u) << 3) | (mode == 64 ? 4u : 0u) |
				    ((in.flags & KGENOME_GF_X86_67) ? 2u : 0u) | ((in.flags & KGENOME_GF_X86_66) ? 1u : 0u);

		if (!(leaf_seen[lk >> 3] & (1u << (lk & 7u))) && n_items < MAX_ITEMS) {
			leaf_seen[lk >> 3] |= (uint8_t)(1u << (lk & 7u));
			items[n_items].id = in.id;
			items[n_items].mode = (uint8_t)mode;
			items[n_items].n = in.len;
			memcpy(items[n_items++].b, b, in.len);
		}
	}
	if (s->count >= SAMPLES)
		return;
	key = shape_key(&in, mode);
	for (i = 0; i < s->count; i++)
		if (s->key[i] == key)
			return;
	s->n[s->count] = in.len;
	memcpy(s->b[s->count], b, in.len);
	s->mode[s->count] = (uint8_t)mode;
	s->key[s->count++] = key;
}

static void legacy(unsigned mode)
{
	static const uint8_t pfx[7][2] = { { 0, 0 }, { 0x66, 0 }, { 0xf2, 0 }, { 0xf3, 0 }, { 0x48, 0 }, { 0x66, 0x48 }, { 0x67, 0 } };
	unsigned p, map, op, m, k;

	for (p = 0; p < 7; p++) {
		if (mode == 32 && (pfx[p][0] == 0x48 || pfx[p][1] == 0x48))
			continue;
		for (map = 0; map < 4; map++)
			for (op = 0; op < 256; op++) {
				/* the escape bytes and the prefixes are not opcodes of their own */
				if ((map == 0 && (op == 0x0f || op == 0x26 || op == 0x2e || op == 0x36 || op == 0x3e || op == 0x64 || op == 0x65 ||
						  op == 0x66 || op == 0x67 || op == 0xf0 || op == 0xf2 || op == 0xf3 ||
						  (mode == 64 && op >= 0x40 && op <= 0x4f))) ||
				    (map == 1 && (op == 0x38 || op == 0x3a || op == 0x0f)))
					continue;
				for (m = 0; m < 256; m++) {
					uint8_t b[16];
					unsigned n = 0;

					memset(b, 0x90, sizeof b);
					for (k = 0; k < 2; k++)
						if (pfx[p][k])
							b[n++] = pfx[p][k];
					if (map >= 1)
						b[n++] = 0x0f;
					if (map == 2)
						b[n++] = 0x38;
					if (map == 3)
						b[n++] = 0x3a;
					b[n++] = (uint8_t)op;
					b[n++] = (uint8_t)m;
					record(b, mode);
				}
			}
	}
}

/* ModRM bytes that decide a length and a register kind: every reg field with a register r/m, no base (RIP), a SIB, disp8, disp32 */
static unsigned modrms(uint8_t *out)
{
	static const unsigned rm_mem[3] = { 0, 4, 5 };
	unsigned md, r, j, n = 0;

	for (md = 0; md < 4; md++)
		for (r = 0; r < 8; r++) {
			if (md == 3) {
				out[n++] = (uint8_t)(0xc0u | (r << 3));
				out[n++] = (uint8_t)(0xc0u | (r << 3) | 1u);
				out[n++] = (uint8_t)(0xc0u | (r << 3) | 7u);
			} else {
				for (j = 0; j < 3; j++)
					out[n++] = (uint8_t)((md << 6) | (r << 3) | rm_mem[j]);
			}
		}
	return n;
}

static void vector(unsigned mode)
{
	static const unsigned emap[5] = { 1, 2, 3, 5, 6 };
	uint8_t mr[160];
	const unsigned nm = modrms(mr);
	unsigned map, pp, l, w, v, op, j, bb, aa, me;

	/* VEX: C5 for map 1 without W, C4 for the three maps; vvvv in use or 1111b */
	for (map = 1; map <= 3; map++)
		for (pp = 0; pp < 4; pp++)
			for (l = 0; l < 2; l++)
				for (w = 0; w < 2; w++)
					for (v = 0; v < 2; v++)
						for (op = 0; op < 256; op++)
							for (j = 0; j < nm; j++) {
								uint8_t b[16];
								unsigned n = 0;
								const unsigned vv = v ? 0xeu : 0xfu;

								memset(b, 0x90, sizeof b);
								if (map == 1 && !w) {
									b[n++] = 0xc5;
									b[n++] = (uint8_t)(0x80u | (vv << 3) | (l << 2) | pp);
								} else {
									b[n++] = 0xc4;
									b[n++] = (uint8_t)(0xe0u | map);
									b[n++] = (uint8_t)((w << 7) | (vv << 3) | (l << 2) | pp);
								}
								b[n++] = (uint8_t)op;
								b[n++] = mr[j];
								record(b, mode);
							}
	/* VEX map 5, the AMX FP8 forms */
	for (pp = 0; pp < 4; pp++)
		for (op = 0; op < 256; op++)
			for (j = 0; j < nm; j++) {
				uint8_t b[16];
				unsigned n = 0;

				memset(b, 0x90, sizeof b);
				b[n++] = 0xc4;
				b[n++] = 0xe5;
				b[n++] = (uint8_t)(0x78u | pp);
				b[n++] = (uint8_t)op;
				b[n++] = mr[j];
				record(b, mode);
			}
	/* XOP, maps 8-10 */
	for (map = 8; map <= 10; map++)
		for (l = 0; l < 2; l++)
			for (w = 0; w < 2; w++)
				for (op = 0; op < 256; op++)
					for (j = 0; j < nm; j++) {
						uint8_t b[16];
						unsigned n = 0;

						memset(b, 0x90, sizeof b);
						b[n++] = 0x8f;
						b[n++] = (uint8_t)(0xe0u | map);
						b[n++] = (uint8_t)((w << 7) | (0xfu << 3) | (l << 2));
						b[n++] = (uint8_t)op;
						b[n++] = mr[j];
						record(b, mode);
					}
	/* EVEX: maps 1-3 and the FP16 maps 5-6; W, pp, L'L (three), broadcast, and the mask: none, a mask register, a mask register
	 * with zeroing (a scatter has no zeroing form, so the two are separate states). */
	for (me = 0; me < 5; me++)
		for (pp = 0; pp < 4; pp++)
			for (w = 0; w < 2; w++)
				for (l = 0; l < 3; l++)
					for (bb = 0; bb < 2; bb++)
						for (aa = 0; aa < 3; aa++)
							for (op = 0; op < 256; op++)
								for (j = 0; j < nm; j++) {
									uint8_t b[16];
									unsigned n = 0;

									memset(b, 0x90, sizeof b);
									b[n++] = 0x62;
									b[n++] = (uint8_t)(0xf0u | emap[me]);
									b[n++] = (uint8_t)((w << 7) | (0xfu << 3) | 4u | pp);
									b[n++] = (uint8_t)(((aa == 2 ? 1u : 0u) << 7) | (l << 5) | (bb << 4) | 8u | (aa ? 1u : 0u));
									b[n++] = (uint8_t)op;
									b[n++] = mr[j];
									record(b, mode);
								}
}

static void sweep(unsigned mode)
{
	legacy(mode);
	vector(mode);
}

/* ---- running one encoding ------------------------------------------------------------------ */

#define CODE  0x400000ull
#define DATA  0x600000ull
#define STACK 0x7ff00000ull

static struct kgenome_emu *mkmachine(unsigned bits)
{
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *e;
	static uint8_t pat[0x2000];

	memset(&cfg, 0, sizeof cfg);
	cfg.bits = bits;
	cfg.max_insn = 1000000;
	e = kgenome_emu_new(&cfg);
	if (!e)
		return NULL;
	memset(pat, 0x03, sizeof pat);
	kgenome_emu_map(e, CODE, NULL, 0, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W | KGENOME_EMU_X);
	kgenome_emu_map(e, DATA, pat, sizeof pat, 0x2000, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_map(e, STACK, NULL, 0, 0x10000, KGENOME_EMU_R | KGENOME_EMU_W);
	return e;
}

/* 1 when the interpreter carries the encoding (it ran, or stopped for any reason but "unsupported") */
static int carried(struct kgenome_emu **ep, unsigned bits, const uint8_t *b, unsigned n)
{
	uint8_t code[32];
	unsigned k;
	enum kgenome_emu_stop s;
	struct kgenome_emu *e = *ep;

	if (!e)
		return -1;
	memset(code, 0xf4, sizeof code);
	memcpy(code, b, n);
	kgenome_emu_write(e, CODE, code, sizeof code);
	kgenome_emu_write(e, DATA, "\x03\x03\x03\x03\x03\x03\x03\x03", 8);
	for (k = 0; k < KGENOME_EMU_NGPR; k++)
		kgenome_emu_set_reg(e, k, 0);
	kgenome_emu_set_reg(e, KGENOME_EMU_RAX, 100);
	kgenome_emu_set_reg(e, KGENOME_EMU_RCX, 3);
	kgenome_emu_set_reg(e, KGENOME_EMU_RBX, 5);
	kgenome_emu_set_reg(e, KGENOME_EMU_RSI, DATA + 0x10);
	kgenome_emu_set_reg(e, KGENOME_EMU_RDI, DATA + 0x800);
	kgenome_emu_set_reg(e, KGENOME_EMU_RSP, STACK + 0x8000);
	kgenome_emu_set_rip(e, CODE);
	kgenome_emu_set_max_insn(e, kgenome_emu_insn_count(e) + 8u);
	s = kgenome_emu_run(e);
	(void)bits;
	/* the HLT after the instruction is itself reported as a stop: reaching it means the instruction ran */
	if (s == KGENOME_EMU_STOP_UNSUPPORTED && kgenome_emu_get_rip(e) != CODE + n)
		return 0;
	if (s != KGENOME_EMU_STOP_BUDGET && s != KGENOME_EMU_STOP_QUIET && s != KGENOME_EMU_STOP_FAULT &&
	    s != KGENOME_EMU_STOP_UNSUPPORTED) {
		/* a run that ended its machine (exit, hand-off): the next encoding gets a new one */
		kgenome_emu_free(e);
		*ep = mkmachine(bits);
	}
	return 1;
}

/* ---- the length, from a reader that is not ours -------------------------------------------- */

static int have_objdump(void)
{
	return access("/usr/bin/objdump", X_OK) == 0;
}

/* the leading prefix bytes of an encoding include a 66 (operand size) */
static int has_66(const uint8_t *b, unsigned n)
{
	unsigned i;

	for (i = 0; i < n; i++) {
		if (b[i] == 0x66)
			return 1;
		if (!(b[i] == 0x67 || b[i] == 0xf2 || b[i] == 0xf3 || b[i] == 0xf0 || b[i] == 0x2e || b[i] == 0x36 || b[i] == 0x3e ||
		      b[i] == 0x26 || b[i] == 0x64 || b[i] == 0x65 || (b[i] >= 0x40 && b[i] <= 0x4f)))
			return 0;
	}
	return 0;
}

/*
 * THE ONE DISAGREEMENT THAT IS NOT AN ERROR. A 66 prefix on a near relative branch (CALL E8, JMP E9, Jcc 0F 8x) in 64-bit
 * mode: Intel processors ignore it (the displacement stays 32 bits), AMD's honour it (16 bits), and objdump reads the AMD way
 * while the decoder - and the table it is generated from - follows Intel, whose cores run this code on nearly every machine
 * that matters. The lengths differ by two and both are right for the CPU each describes. Another waiver: objdump treats FWAIT
 * (9B) as a prefix of the x87 instruction after it (fstcw, fstenv, ...) and lists it with them as one line, and lists the prefixes
 * in front of a lone FWAIT as a line of their own, so the lengths of those are not comparable.
 */
static int length_exception(unsigned id, unsigned mode, const uint8_t *b, unsigned n)
{
	unsigned i;

	if (mode == 64 && has_66(b, n) && (id == KGENOME_X86_I_CALLNR || id == KGENOME_X86_I_JMPNR || id == KGENOME_X86_I_Jcc))
		return 1;
	if (id == KGENOME_X86_I_WAIT && n > 1)
		return 1;                       /* prefixes before an FWAIT: objdump lists them as a line of their own */
	for (i = 0; i + 1 < n && i < 4; i++)
		if (b[i] == 0x9b && b[i + 1] >= 0xd8 && b[i + 1] <= 0xdf)
			return 1;
	return 0;
}

/* the mnemonic objdump gives the same bytes, against the decoder's: rule 3 */
static void name_check(struct seen *s, const uint8_t *bytes, unsigned n, unsigned mode, const char *theirs_text)
{
	struct kgenome_x86_insn in;
	char t[KGENOME_X86_TEXT + 8], a[24], b[24];

	if (kgenome_x86_decode(&in, bytes, n, (int)mode) != KGENOME_OK || !kgenome_x86_format(&in, 0x1000, t, sizeof t))
		return;
	{
		char sa[12], sb[12];

		shape_of(t, sa, sizeof sa);
		shape_of(theirs_text, sb, sizeof sb);
		if (!strcmp(sa, sb)) {
			s->shape_ok++;
		} else if (!s->shape_bad++) {
			snprintf(s->shape_ours, sizeof s->shape_ours, "%s", sa);
			snprintf(s->shape_theirs, sizeof s->shape_theirs, "%s", sb);
			memcpy(s->shape_b, bytes, n);
			s->shape_n = (uint8_t)n;
			s->shape_mode = (uint8_t)mode;
		}
	}
	first_word(t, a, sizeof a);
	first_word(theirs_text, b, sizeof b);
	if (names_agree(b, a)) {
		s->name_ok++;
		return;
	}
	if (!s->name_bad++) {
		snprintf(s->name_theirs, sizeof s->name_theirs, "%s", b);
		snprintf(s->name_ours, sizeof s->name_ours, "%s", a);
		memcpy(s->name_b, bytes, n);
		s->name_n = (uint8_t)n;
		s->name_mode = (uint8_t)mode;
	}
}

#define SLOT 32u

/* The kept encodings of every id and the leaf samples, one mode at a time, one per 32 byte slot (padded with NOPs so that a
 * decode never runs into the next slot). */
static void verify(unsigned mode)
{
	static struct item list[NID * SAMPLES + MAX_ITEMS];
	static uint8_t buf[(NID * SAMPLES + MAX_ITEMS) * SLOT];
	unsigned id, k, n = 0;
	int fd;
	char cmd[200], ln[512];
	FILE *f;
	size_t off = 0;

	for (id = 0; id < NID; id++)
		for (k = 0; k < tab[id].count; k++)
			if (tab[id].mode[k] == mode) {
				list[n].id = id;
				list[n].mode = (uint8_t)mode;
				list[n].n = tab[id].n[k];
				memcpy(list[n++].b, tab[id].b[k], tab[id].n[k]);
			}
	for (k = 0; k < n_items; k++)
		if (items[k].mode == mode)
			list[n++] = items[k];
	if (!n)
		return;
	for (k = 0; k < n; k++) {
		memset(buf + (size_t)k * SLOT, 0x90, SLOT);
		memcpy(buf + (size_t)k * SLOT, list[k].b, list[k].n);
	}
	fd = memfd_create("kofeng-forms", 0);
	if (fd < 0)
		return;
	while (off < (size_t)n * SLOT) {
		const ssize_t w = write(fd, buf + off, (size_t)n * SLOT - off);

		if (w <= 0) {
			close(fd);
			return;
		}
		off += (size_t)w;
	}
	snprintf(cmd, sizeof cmd, "/usr/bin/objdump -D -w -b binary -m %s -M intel /proc/%d/fd/%d 2>/dev/null",
		 mode == 64 ? "i386:x86-64" : "i386", (int)getpid(), fd);
	f = popen(cmd, "r");
	if (!f) {
		close(fd);
		return;
	}
	while (fgets(ln, sizeof ln, f)) {
		struct ins o;
		struct seen *s;
		const struct item *r;
		unsigned slot;

		if (!parse(ln, &o) || o.addr % SLOT || o.addr / SLOT >= n)
			continue;
		slot = (unsigned)(o.addr / SLOT);
		r = &list[slot];
		s = &tab[r->id];
		if (!strncmp(o.text, "(bad)", 5) || !strncmp(o.text, ".byte", 5) || strstr(o.text, "(bad)") ||
		    (o.n == 1 && !strncmp(o.text, "rex", 3) && !strchr(o.text, ' '))) {
			s->len_silent++;
		} else if (o.n == r->n) {
			s->len_ok++;
			name_check(s, r->b, r->n, mode, o.text);
		} else if (length_exception(r->id, mode, r->b, r->n)) {
			s->len_waived++;
		} else {
			if (!s->len_bad++) {
				memcpy(s->bad_b, r->b, r->n);
				s->bad_n = r->n;
				s->bad_mode = (uint8_t)mode;
				s->bad_theirs = o.n;
				snprintf(s->bad_text, sizeof s->bad_text, "%s", o.text);
			}
		}
	}
	pclose(f);
	close(fd);
}

/* ---- the table of what is not carried ------------------------------------------------------ */

const struct row ROWS[] = {
	{ "K*", R_AVX },
	{ "V*", R_AVX },
	{ "ARPL", R_SYS },
	{ "BNDCL", R_SYS },
	{ "BNDCN", R_SYS },
	{ "BNDCU", R_SYS },
	{ "BNDLDX", R_SYS },
	{ "BNDMK", R_SYS },
	{ "BNDMOV", R_SYS },
	{ "BNDSTX", R_SYS },
	{ "CALLF", R_SYS },
	{ "CLAC", R_SYS },
	{ "CLGI", R_SYS },
	{ "CLI", R_SYS },
	{ "CLRSSBSY", R_SYS },
	{ "CLTS", R_SYS },
	{ "CLUI", R_SYS },
	{ "CLZERO", R_SYS },
	{ "ENCLS", R_SYS },
	{ "ENCLU", R_SYS },
	{ "ENCLV", R_SYS },
	{ "ENCODEKEY128", R_SYS },
	{ "ENCODEKEY256", R_SYS },
	{ "ENQCMD", R_SYS },
	{ "ENQCMDS", R_SYS },
	{ "ERETS", R_SYS },
	{ "ERETU", R_SYS },
	{ "GETSEC", R_SYS },
	{ "HLT", R_SYS },
	{ "HRESET", R_SYS },
	{ "IN", R_SYS },
	{ "INCSSPD", R_SYS },
	{ "INSB", R_SYS },
	{ "INT", R_SYS },
	{ "INT1", R_SYS },
	{ "INT3", R_SYS },
	{ "INTO", R_SYS },
	{ "INVD", R_SYS },
	{ "INVEPT", R_SYS },
	{ "INVLPG", R_SYS },
	{ "INVLPGA", R_SYS },
	{ "INVLPGB", R_SYS },
	{ "INVPCID", R_SYS },
	{ "INVVPID", R_SYS },
	{ "IRETD", R_SYS },
	{ "JMPF", R_SYS },
	{ "LAR", R_SYS },
	{ "LDS", R_SYS },
	{ "LDTILECFG", R_SYS },
	{ "LES", R_SYS },
	{ "LFS", R_SYS },
	{ "LGDT", R_SYS },
	{ "LGS", R_SYS },
	{ "LIDT", R_SYS },
	{ "LKGS", R_SYS },
	{ "LLDT", R_SYS },
	{ "LMSW", R_SYS },
	{ "LOADIWKEY", R_SYS },
	{ "LSL", R_SYS },
	{ "LSS", R_SYS },
	{ "LTR", R_SYS },
	{ "MCOMMIT", R_SYS },
	{ "MONITOR", R_SYS },
	{ "MONITORX", R_SYS },
	{ "MOV", R_SYS },
	{ "MOVRS", R_SYS },
	{ "MWAIT", R_SYS },
	{ "MWAITX", R_SYS },
	{ "OUT", R_SYS },
	{ "OUTSB", R_SYS },
	{ "PBNDKB", R_SYS },
	{ "PCONFIG", R_SYS },
	{ "PREFETCHRST2", R_SYS },
	{ "PSMASH", R_SYS },
	{ "PTWRITE", R_SYS },
	{ "PVALIDATE", R_SYS },
	{ "RDFSBASE", R_SYS },
	{ "RDGSBASE", R_SYS },
	{ "RDMSR", R_SYS },
	{ "RDMSRLIST", R_SYS },
	{ "RDPID", R_SYS },
	{ "RDPMC", R_SYS },
	{ "RDPRU", R_SYS },
	{ "RDSSPD", R_SYS },
	{ "RETF", R_SYS },
	{ "RMPADJUST", R_SYS },
	{ "RMPQUERY", R_SYS },
	{ "RMPREAD", R_SYS },
	{ "RMPUPDATE", R_SYS },
	{ "RSM", R_SYS },
	{ "RSTORSSP", R_SYS },
	{ "SAVEPREVSSP", R_SYS },
	{ "SEAMCALL", R_SYS },
	{ "SEAMOPS", R_SYS },
	{ "SEAMRET", R_SYS },
	{ "SENDUIPI", R_SYS },
	{ "SETSSBSY", R_SYS },
	{ "SGDT", R_SYS },
	{ "SIDT", R_SYS },
	{ "SKINIT", R_SYS },
	{ "SLDT", R_SYS },
	{ "SMSW", R_SYS },
	{ "STAC", R_SYS },
	{ "STGI", R_SYS },
	{ "STI", R_SYS },
	{ "STR", R_SYS },
	{ "STTILECFG", R_SYS },
	{ "STUI", R_SYS },
	{ "SWAPGS", R_SYS },
	{ "SYSENTER", R_SYS },
	{ "SYSEXIT", R_SYS },
	{ "SYSRET", R_SYS },
	{ "TCONJTFP16", R_SYS },
	{ "TCVTROWPS2PHH", R_SYS },
	{ "TDCALL", R_SYS },
	{ "TESTUI", R_SYS },
	{ "TLBSYNC", R_SYS },
	{ "TPAUSE", R_SYS },
	{ "TTRANSPOSED", R_SYS },
	{ "UD0", R_SYS },
	{ "UD1", R_SYS },
	{ "UD2", R_SYS },
	{ "UIRET", R_SYS },
	{ "UMONITOR", R_SYS },
	{ "UMWAIT", R_SYS },
	{ "URDMSR", R_SYS },
	{ "UWRMSR", R_SYS },
	{ "WBINVD", R_SYS },
	{ "WBNOINVD", R_SYS },
	{ "WRFSBASE", R_SYS },
	{ "WRGSBASE", R_SYS },
	{ "WRMSR", R_SYS },
	{ "WRMSRLIST", R_SYS },
	{ "WRMSRNS", R_SYS },
	{ "WRSSD", R_SYS },
	{ "WRUSSD", R_SYS },
	{ "XRESLDTRK", R_SYS },
	{ "XSETBV", R_SYS },
	{ "EXTRQ", R_SSEFP },
	{ "INSERTQ", R_SSEFP },
	{ "RCPPS", R_SSEFP },
	{ "RCPSS", R_SSEFP },
	{ "RSQRTPS", R_SSEFP },
	{ "RSQRTSS", R_SSEFP },
	{ "AESDEC128KL", R_CRYPTO },
	{ "AESDEC256KL", R_CRYPTO },
	{ "AESDECWIDE128KL", R_CRYPTO },
	{ "AESDECWIDE256KL", R_CRYPTO },
	{ "AESENC128KL", R_CRYPTO },
	{ "AESENC256KL", R_CRYPTO },
	{ "AESENCWIDE128KL", R_CRYPTO },
	{ "AESENCWIDE256KL", R_CRYPTO },
	{ "GF2P8AFFINEINVQB", R_CRYPTO },
	{ "GF2P8AFFINEQB", R_CRYPTO },
	{ "GF2P8MULB", R_CRYPTO },
	{ "RDRAND", R_CRYPTO },
	{ "RDSEED", R_CRYPTO },
	{ "SHA1MSG1", R_CRYPTO },
	{ "SHA1MSG2", R_CRYPTO },
	{ "SHA1NEXTE", R_CRYPTO },
	{ "SHA1RNDS4", R_CRYPTO },
	{ "SHA256MSG1", R_CRYPTO },
	{ "SHA256MSG2", R_CRYPTO },
	{ "SHA256RNDS2", R_CRYPTO },
	{ "FNDISI", R_X87 },
	{ "FRINEAR", R_X87 },
	{ "FSTDW", R_X87 },
	{ "FSTPNCE", R_X87 },
	{ "FSTSG", R_X87 },
	{ "XRSTOR", R_STATE },
	{ "XRSTORS", R_STATE },
	{ "XSAVE", R_STATE },
	{ "XSAVEC", R_STATE },
	{ "XSAVEOPT", R_STATE },
	{ "XSAVES", R_STATE },
	{ "AADD", R_RARE },
	{ "AAND", R_RARE },
	{ "AOR", R_RARE },
	{ "AXOR", R_RARE },
	{ "BOUND", R_RARE },
	{ "CMPBEXADD", R_RARE },
	{ "CMPCXADD", R_RARE },
	{ "CMPLEXADD", R_RARE },
	{ "CMPLXADD", R_RARE },
	{ "CMPNBEXADD", R_RARE },
	{ "CMPNCXADD", R_RARE },
	{ "CMPNLEXADD", R_RARE },
	{ "CMPNLXADD", R_RARE },
	{ "CMPNOXADD", R_RARE },
	{ "CMPNPXADD", R_RARE },
	{ "CMPNSXADD", R_RARE },
	{ "CMPNZXADD", R_RARE },
	{ "CMPOXADD", R_RARE },
	{ "CMPPXADD", R_RARE },
	{ "CMPSXADD", R_RARE },
	{ "CMPZXADD", R_RARE },
	{ "MOVDIR64B", R_RARE },
	{ "MOVDIRI", R_RARE },
	{ "BLCFILL", R_TBM },
	{ "BLCI", R_TBM },
	{ "BLCIC", R_TBM },
	{ "BLCMSK", R_TBM },
	{ "BLCS", R_TBM },
	{ "BLSFILL", R_TBM },
	{ "BLSIC", R_TBM },
	{ "LLWPCB", R_TBM },
	{ "LWPINS", R_TBM },
	{ "LWPVAL", R_TBM },
	{ "SLWPCB", R_TBM },
	{ "T1MSKC", R_TBM },
	{ "TZMSK", R_TBM },
	{ "T2RPNTLVWZ0", R_AMX },
	{ "T2RPNTLVWZ0RS", R_AMX },
	{ "T2RPNTLVWZ0RST1", R_AMX },
	{ "T2RPNTLVWZ0T1", R_AMX },
	{ "T2RPNTLVWZ1", R_AMX },
	{ "T2RPNTLVWZ1RS", R_AMX },
	{ "T2RPNTLVWZ1RST1", R_AMX },
	{ "T2RPNTLVWZ1T1", R_AMX },
	{ "TCMMIMFP16PS", R_AMX },
	{ "TCMMRLFP16PS", R_AMX },
	{ "TCONJTCMMIMFP16PS", R_AMX },
	{ "TCVTROWD2PS", R_AMX },
	{ "TCVTROWPS2BF16H", R_AMX },
	{ "TCVTROWPS2BF16L", R_AMX },
	{ "TCVTROWPS2PHL", R_AMX },
	{ "TDPBF16PS", R_AMX },
	{ "TDPBF8PS", R_AMX },
	{ "TDPBHF8PS", R_AMX },
	{ "TDPBSSD", R_AMX },
	{ "TDPBSUD", R_AMX },
	{ "TDPBUSD", R_AMX },
	{ "TDPBUUD", R_AMX },
	{ "TDPFP16PS", R_AMX },
	{ "TDPHBF8PS", R_AMX },
	{ "TDPHF8PS", R_AMX },
	{ "TILELOADD", R_AMX },
	{ "TILELOADDRS", R_AMX },
	{ "TILELOADDRST1", R_AMX },
	{ "TILELOADDT1", R_AMX },
	{ "TILEMOVROW", R_AMX },
	{ "TILERELEASE", R_AMX },
	{ "TILESTORED", R_AMX },
	{ "TILEZERO", R_AMX },
	{ "TMMULTF32PS", R_AMX },
	{ "TTCMMIMFP16PS", R_AMX },
	{ "TTCMMRLFP16PS", R_AMX },
	{ "TTDPBF16PS", R_AMX },
	{ "TTDPFP16PS", R_AMX },
	{ "TTMMULTF32PS", R_AMX },
	{ "CLEVICT0", R_KNC },
	{ "CLEVICT1", R_KNC },
	{ "DELAY", R_KNC },
	{ "SPFLT", R_KNC },
	{ "RDPKRU", R_TSX },
	{ "WRPKRU", R_TSX },
	{ "XABORT", R_TSX },
	{ "XBEGIN", R_TSX },
	{ "XEND", R_TSX },
	{ "XSUSLDTRK", R_TSX },
	{ "XTEST", R_TSX },
};
const unsigned NROWS = sizeof ROWS / sizeof ROWS[0];

/* ---- the tables --------------------------------------------------------------------------- */

/*
 * ids that no input produces: the decoder's table has the row (it is generated from the reference's identities) and no
 * encoding reaches it. A name here is an id that is deliberately not decoded, or one only a prefix this decoder refuses
 * can name; an id that is reached and listed is a FAIL (delete the row).
 */
struct idrow {
	unsigned id;
	const char *why;
};

static const struct idrow UNREACHED[] = {
	/* APX (REX2 and the APX forms of EVEX): 64-bit mode, Intel Nova Lake and later; no corpus encodes them (x86.h) */
	{ KGENOME_X86_I_CCMP, R_APX }, { KGENOME_X86_I_CFCMOV, R_APX }, { KGENOME_X86_I_CTEST, R_APX }, { KGENOME_X86_I_IBHF, R_APX },
	{ KGENOME_X86_I_JMPABS, R_APX }, { KGENOME_X86_I_POP2, R_APX }, { KGENOME_X86_I_POP2P, R_APX }, { KGENOME_X86_I_POPP, R_APX },
	{ KGENOME_X86_I_PUSH2, R_APX }, { KGENOME_X86_I_PUSH2P, R_APX }, { KGENOME_X86_I_PUSHP, R_APX },
	/* 3DNow! (0F 0F with the opcode in a suffix byte after the operands): AMD K6-2 to K10, withdrawn in 2010; the decoder reports it as not an instruction */
	{ KGENOME_X86_I_PAVGUSB, R_3DNOW }, { KGENOME_X86_I_PF2ID, R_3DNOW }, { KGENOME_X86_I_PF2IW, R_3DNOW }, { KGENOME_X86_I_PFACC, R_3DNOW },
	{ KGENOME_X86_I_PFADD, R_3DNOW }, { KGENOME_X86_I_PFCMPEQ, R_3DNOW }, { KGENOME_X86_I_PFCMPGE, R_3DNOW }, { KGENOME_X86_I_PFCMPGT, R_3DNOW },
	{ KGENOME_X86_I_PFMAX, R_3DNOW }, { KGENOME_X86_I_PFMIN, R_3DNOW }, { KGENOME_X86_I_PFMUL, R_3DNOW }, { KGENOME_X86_I_PFNACC, R_3DNOW },
	{ KGENOME_X86_I_PFPNACC, R_3DNOW }, { KGENOME_X86_I_PFRCP, R_3DNOW }, { KGENOME_X86_I_PFRCPIT1, R_3DNOW }, { KGENOME_X86_I_PFRCPIT2, R_3DNOW },
	{ KGENOME_X86_I_PFRCPV, R_3DNOW }, { KGENOME_X86_I_PFRSQIT1, R_3DNOW }, { KGENOME_X86_I_PFRSQRT, R_3DNOW }, { KGENOME_X86_I_PFRSQRTV, R_3DNOW },
	{ KGENOME_X86_I_PFSUB, R_3DNOW }, { KGENOME_X86_I_PFSUBR, R_3DNOW }, { KGENOME_X86_I_PI2FD, R_3DNOW }, { KGENOME_X86_I_PI2FW, R_3DNOW },
	{ KGENOME_X86_I_PMULHRW, R_3DNOW }, { KGENOME_X86_I_PSWAPD, R_3DNOW },

};
#define NUNREACHED (sizeof UNREACHED / sizeof UNREACHED[0])

/*
 * ids whose length objdump never confirms (every kept encoding came back "(bad)" or as no instruction): objdump reads
 * what it knows, and a few of the decoder's rows are instructions it does not have (or reads as another). The decode is
 * the reference decoder's, measured (tools/genotype/x86_diff.c), so it is checked there, and the reason is written here.
 */
static const struct row UNVERIFIED[] = {
	{ "CLEVICT0", R_KNC_OD }, { "CLEVICT1", R_KNC_OD }, { "DELAY", R_KNC_OD }, { "SPFLT", R_KNC_OD }, { "KMERGE2L1H", R_KNC_OD },
	{ "KMERGE2L1L", R_KNC_OD },
	{ "FRINEAR", R_X87_OD }, { "FSTDW", R_X87_OD }, { "FSTPNCE", R_X87_OD }, { "FSTSG", R_X87_OD },

};
#define NUNVERIFIED (sizeof UNVERIFIED / sizeof UNVERIFIED[0])

/*
 * ids whose mnemonic objdump spells another way for a reason that is not an error: the same instruction, a different word. The
 * rules of names_agree (objdump_kit.h) take the size letters, the string forms, SHL/SAL; what is left is here.
 */
static const struct row NAME_DIFFERS[] = {
	{ "FNOP", "DB E0 (FENI) and DB E4 (FSETPM) are 8087 and 80287 only; every later FPU executes them as a NOP, which is how the table names them, while objdump keeps the old names (fneni, fnsetpm)" },
	{ "KMOVW", "KMOVB, KMOVW, KMOVD and KMOVQ are one id; with VEX.W = 1 in 32-bit mode the reference decoder this table is measured from says KMOVQ and objdump (which ignores W there) says KMOVD; the instruction does not exist on a CPU in that mode" },
	{ "FNDISI", "objdump writes the 8087's FNDISI as \"fndisi(8087 only)\"" },
	{ "SALC", "D6 is the undocumented SETALC; objdump has no such instruction and lists the byte as UDB (the length is the same)" },
	{ "*BF16", "AVX10.2 renamed the BF16 forms (VADDNEPBF16 -> VADDBF16, VCOMSBF16 -> VCOMISBF16, VMAXPBF16 -> VMAXBF16 ...); the reference decoder this table is measured from has the draft names" },
	{ "VCVTNE*", "AVX10.2 renamed the FP8/BF16 conversions (VCVTNEPH2BF8 -> VCVTPH2BF8, VCVTNE2PH2HF8 -> VCVT2PH2HF8, VCVTNEBF162IBS -> VCVTBF162IBS ...); the reference decoder has the draft names" },
	{ "VCVTTNE*", "AVX10.2 renamed the truncating BF16 conversions (VCVTTNEBF162IBS -> VCVTTBF162IBS ...); the reference decoder has the draft names" },
};
#define NNAME_DIFFERS (sizeof NAME_DIFFERS / sizeof NAME_DIFFERS[0])

/* The row of `t` that names `name`, or -1. */
static int find_row(const struct row *t, unsigned n, const char *name)
{
	unsigned j;

	for (j = 0; j < n; j++)
		if (match(&t[j], name))
			return (int)j;
	return -1;
}

static void print_bytes(const uint8_t *b, unsigned n)
{
	unsigned j;

	for (j = 0; j < n; j++)
		printf(" %02x", b[j]);
}

int main(int argc, char **argv)
{
	int verbose = argc > 1 && !strcmp(argv[1], "-v");
	int listing = argc > 1 && !strcmp(argv[1], "-l");
	unsigned i, j, decoded = 0, emulated = 0, unsupported = 0, unlisted = 0, unreached = 0, unreached_listed = 0;
	unsigned verified = 0, unverified_listed = 0, len_waived = 0, name_listed = 0;
	struct kgenome_emu *m64, *m32;
	static unsigned rowhits[4096], urhits[256], unhits[256], nhits[256];
	const int od = have_objdump();

	sweep(64);
	sweep(32);
	m64 = mkmachine(64);
	m32 = mkmachine(32);
	CK(m64 && m32, "the interpreters were made");
	if (!m64 || !m32)
		return 1;
	if (od) {
		verify(64);
		verify(32);
	}
	for (i = 0; i < NID; i++) {
		struct seen *s = &tab[i];
		unsigned lim = s->count < TRIES ? s->count : TRIES;

		if (!s->count) {
			/* an id with no encoding: not reached. KGENOME_X86_I_INVALID is not an instruction. */
			if (i == KGENOME_X86_I_INVALID)
				continue;
			for (j = 0; j < NUNREACHED && UNREACHED[j].id != i; j++)
				;
			if (j < NUNREACHED) {
				urhits[j]++;
				unreached_listed++;
			} else {
				printf("  FAIL id %u is in the decoder's table and no encoding of the sweep reaches it (add it to UNREACHED with "
				       "the reason, or find the encoding)\n", i);
				if (listing)
					printf("  unreached: id %u\n", i);
				fails++;
			}
			unreached++;
			continue;
		}
		decoded++;
		for (j = 0; j < lim && !s->emulated; j++) {
			struct kgenome_emu **ep = s->mode[j] == 32 ? &m32 : &m64;

			if (carried(ep, s->mode[j], s->b[j], s->n[j]) == 1)
				s->emulated = 1;
		}
		/* rule 2: the length against objdump */
		len_waived += s->len_waived;
		if (s->len_bad) {
			printf("  FAIL %s (id %u): objdump reads %u bytes where the decoder reads %u (%s mode:", s->name, i, s->bad_theirs,
			       s->bad_n, s->bad_mode == 64 ? "64 bit" : "32 bit");
			print_bytes(s->bad_b, s->bad_n);
			printf(" = %s)\n", s->bad_text);
			fails++;
		}
		if (od) {
			if (s->len_ok) {
				verified++;
			} else if (s->len_waived) {
				verified++;                     /* every encoding fell under the documented waiver */
			} else {
				const int r = find_row(UNVERIFIED, NUNVERIFIED, s->name);

				if (r < 0) {
					if (listing)
						printf("  unverified: %s\n", s->name);
					printf("  FAIL %s (id %u): objdump confirms the length of none of its %u encoding(s) and the id is not in UNVERIFIED"
					       " (bytes", s->name, i, s->count);
					print_bytes(s->b[0], s->n[0]);
					printf(")\n");
					fails++;
				} else {
					unhits[r]++;
					unverified_listed++;
				}
			}
		}
		/* rule 3: the name against objdump's */
		if (s->name_bad) {
			const int r = find_row(NAME_DIFFERS, NNAME_DIFFERS, s->name);

			if (r < 0) {
				if (listing)
					printf("  namediff: %s\n", s->name);
				printf("  FAIL %s (id %u): objdump names it %s (%s mode:", s->name, i, s->name_theirs, s->name_mode == 64 ? "64 bit" : "32 bit");
				print_bytes(s->name_b, s->name_n);
				printf(") and it is not in NAME_DIFFERS\n");
				fails++;
			} else {
				nhits[r]++;
				name_listed++;
			}
		}
		/* rule 1: emulated, or listed with its reason */
		if (s->emulated) {
			emulated++;
			continue;
		}
		unsupported++;
		j = (unsigned)find_row(ROWS, NROWS, s->name);
		if ((int)j < 0) {
			unlisted++;
			if (listing)
				printf("  unlisted: %s\n", s->name);
			printf("  FAIL decoded but neither emulated nor listed as unsupported: %s (id %u, bytes", s->name, i);
			print_bytes(s->b[0], s->n[0]);
			printf(")\n");
			fails++;
		} else {
			rowhits[j]++;
		}
	}
	if (od)
		for (j = 0; j < NNAME_DIFFERS; j++)
			if (!nhits[j]) {
				printf("  FAIL NAME_DIFFERS row \"%s\" matches no instruction whose name objdump spells differently: delete it\n",
				       NAME_DIFFERS[j].pat);
				fails++;
			}
	for (j = 0; j < NUNREACHED; j++)
		if (!urhits[j]) {
			printf("  FAIL UNREACHED row for id %u: the sweep reaches it now: delete the row\n", UNREACHED[j].id);
			fails++;
		}
	printf("diff_decode_cover: %lu encodings swept, %u of the decoder's %u instructions reached (%u listed as not reachable, %u "
	       "unreached and unlisted), %u emulated, %u listed as not carried, %u unlisted\n", encodings, decoded, (unsigned)NID - 1u,
	       unreached_listed, unreached - unreached_listed, emulated, unsupported, unlisted);
	if (od)
		printf("diff_decode_cover: length: %u instruction(s) confirmed by objdump, %u listed as unverifiable, %u encodings under the "
		       "documented waivers; name: %u instruction(s) spelled differently by design\n", verified, unverified_listed, len_waived,
		       name_listed);
	else
		printf("diff_decode_cover: length verification SKIPPED (/usr/bin/objdump is not installed)\n");
	for (j = 0; j < NROWS; j++)
		if (!rowhits[j]) {
			printf("  FAIL row \"%s\" matches no unsupported instruction (carried now, or no longer decoded): delete it\n", ROWS[j].pat);
			fails++;
		}
	if (od)
		for (j = 0; j < NUNVERIFIED; j++)
			if (!unhits[j]) {
				printf("  FAIL UNVERIFIED row \"%s\" matches no instruction objdump fails to confirm: delete it\n", UNVERIFIED[j].pat);
				fails++;
			}
	{
		unsigned sh = 0;

		for (i = 0; i < NID; i++)
			sh += tab[i].shape_bad != 0;
		if (od)
			printf("diff_decode_cover: operand shape: %u instruction(s) differ from objdump's by an implicit operand (-v lists them)\n", sh);
	}
	if (verbose || listing) {
		for (i = 0; i < NID; i++)
			if (tab[i].shape_bad) {
				printf("    shape: %s (id %u) ours %s, objdump %s (%s mode:", tab[i].name, i, tab[i].shape_ours, tab[i].shape_theirs,
				       tab[i].shape_mode == 64 ? "64 bit" : "32 bit");
				print_bytes(tab[i].shape_b, tab[i].shape_n);
				printf(")\n");
			}
	}
	if (verbose) {
		for (j = 0; j < NROWS; j++)
			if (rowhits[j])
				printf("  %5u  %-14s %s\n", rowhits[j], ROWS[j].pat, ROWS[j].why);
		for (i = 0; i < NID; i++)
			if (tab[i].count && !tab[i].emulated)
				printf("    unsupported: %s id=%u\n", tab[i].name, i);
	}
	CK(decoded > 1700u, "the sweep reached the decoder's table (%u of %u)", decoded, (unsigned)NID);
	CK(emulated > 400u, "the interpreter carries several hundred instructions (%u)", emulated);
	kgenome_emu_free(m64);
	kgenome_emu_free(m32);
	if (fails) {
		printf("diff_decode_cover: FAILED (%d)\n", fails);
		return 1;
	}
	printf("diff_decode_cover: ok\n");
	return 0;
}
