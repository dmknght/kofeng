/*
 * endian_plan - a big-endian ELF made equal to its little-endian twin.
 *
 * THE ORACLE IS THE TWIN. endian_kit.h writes one logical program in both byte
 * orders, field by field from the ELF specification, so the claim "the plan puts
 * the big-endian object in the canonical form" is checked as: apply the plan to the
 * big-endian bytes and compare with the little-endian object, byte for byte, over
 * the ELF header, the program and section header tables, the code, and every table
 * the plan names. The bytes that must NOT match are the ones it must not touch.
 *
 *   1  twin equality   every architecture with a twin, ELF32 and ELF64: the whole file
 *                      equal outside the data the plan leaves alone
 *   2  untouched       the 32-bit integer in .data, ASCII, the contents of notes
 *   3  no twin         SPARC, SPARCv9, PPC32, m68k, s390x, OpenRISC: an empty plan
 *   4  little-endian   an empty plan for every architecture, bytes unchanged
 *   5  involution      apply twice is the identity; a canonical object has an empty plan
 *   6  range           kgenome_endian_range equals the same range of the applied object
 *                      at every offset and length that matters
 *   7  mapping symbols ARM big-endian code cut into ARM, Thumb and data runs
 *   8  overlap         a hostile object whose tables overlap code: reported, not hidden
 *   9  the order       code is claimed before headers, headers before tables
 */

#include <kgenome.h>

#include "endian_kit.h"

struct parsed {
	struct kgenome_elf_info info;
	struct kgenome_obj g;
};

static int parse(const uint8_t *b, uint32_t n, struct parsed *p)
{
	memset(p, 0, sizeof *p);
	if (!kgenome_elf_image_parse(kof_buf_make(b, n), &p->info, &p->g))
		return 0;
	p->g.file_header = &p->info;
	return 1;
}

static enum kgenome_status plan_of(const uint8_t *b, uint32_t n, struct kgenome_endian_plan *pl)
{
	struct parsed p;

	if (!parse(b, n, &p)) {
		memset(pl, 0, sizeof *pl);
		return KGENOME_BAD_INPUT;
	}
	return kgenome_endian_plan_build(kof_buf_make(b, n), &p.g, pl);
}

/* The bytes of the object that the plan leaves alone and the twin does not share: the
 * integer and the wide string. Everything else is compared. */
static int differs_outside(const struct ek_obj *a, const struct ek_obj *b, const char *tag)
{
	uint32_t i, bad = 0;

	for (i = 0; i < a->n; i++) {
		int skip = (i >= a->int_at && i < a->int_at + 4u) ||
			   (i >= a->wide_at && i < a->wide_at + 2u * a->wide_chars);

		if (!skip && a->b[i] != b->b[i]) {
			if (bad++ < 4)
				printf("  %s: byte %u is %02x, the twin has %02x\n", tag, i, a->b[i], b->b[i]);
		}
	}
	return (int)bad;
}

static void twin_equal(void)
{
	unsigned k;

	for (k = 0; k < EK_NARCH; k++) {
		const struct ek_arch *a = &ek_archs[k];
		struct ek_obj be, le, orig;
		struct kgenome_endian_plan pl;
		struct parsed p;
		enum kgenome_status st;
		unsigned i;

		ek_build(&be, a, 1, a->unit != 0);
		ek_build(&le, a, 0, 1);
		memcpy(&orig, &be, sizeof be);
		CK(parse(be.b, be.n, &p));
		CK(kgenome_obj_big_endian(&p.g));
		CK(kgenome_endian_wanted(&p.g));
		st = kgenome_endian_plan_build(kof_buf_make(be.b, be.n), &p.g, &pl);
		CK(st == KGENOME_OK);
		CK(pl.n > 0);
		CK(pl.ident == 1);
		CK(pl.code_unit == (a->thumb_entry ? 4u : a->unit));
		/* the spans are sorted, disjoint and inside the object */
		for (i = 0; i < pl.n; i++) {
			CK(pl.v[i].off + pl.v[i].len <= be.n);
			CK(pl.v[i].len > 0);
			if (i)
				CK(pl.v[i - 1u].off + pl.v[i - 1u].len <= pl.v[i].off);
		}
		CK(kgenome_endian_apply(be.b, be.n, &pl) > 0);
		if (differs_outside(&be, &le, a->name))
			printf("  FAIL twin %s\n", a->name), hk_fails++;
		CK(be.b[5] == 1);
		/* the integer is untouched: its width is not in the file */
		CK(memcmp(be.b + be.int_at, orig.b + orig.int_at, 4) == 0);
		/* ASCII is untouched */
		CK(memcmp(be.b + be.str_at, "Permission denied", 18) == 0);
		/* the notes' contents are untouched */
		CK(memcmp(be.b + be.sec_off[EK_NOTE] + 16, orig.b + orig.sec_off[EK_NOTE] + 16, 16) == 0);
		CK(memcmp(be.b + be.sec_off[EK_NOTE] + 52, orig.b + orig.sec_off[EK_NOTE] + 52, 8) == 0);
		/* the involution: the same plan again is the original */
		CK(kgenome_endian_apply(be.b, be.n, &pl) > 0);
		CK(memcmp(be.b, orig.b, be.n) == 0);
		kgenome_endian_plan_free(&pl);
	}
}

static void untouched_data(void)
{
	/* A big-endian object whose .data is all that differs from nothing: the plan names no
	 * span inside it, so no byte of it may move. */
	struct ek_obj be;
	struct kgenome_endian_plan pl;
	unsigned i;

	ek_build(&be, &ek_archs[0], 1, 1);
	CK(plan_of(be.b, be.n, &pl) == KGENOME_OK);
	for (i = 0; i < pl.n; i++) {
		uint64_t s = pl.v[i].off, e = pl.v[i].off + pl.v[i].len;

		CK(e <= be.data || s >= be.data + be.sec_len[EK_DATA]);
	}
	kgenome_endian_plan_free(&pl);
}

static void no_twin(void)
{
	unsigned k;

	for (k = 0; k < EK_NNOTWIN; k++) {
		struct ek_obj be, copy;
		struct kgenome_endian_plan pl;
		struct parsed p;

		ek_build(&be, &ek_notwin[k], 1, 1);
		memcpy(&copy, &be, sizeof be);
		CK(parse(be.b, be.n, &p));
		CK(kgenome_obj_big_endian(&p.g));
		CK(!kgenome_endian_wanted(&p.g));
		CK(kgenome_endian_plan_build(kof_buf_make(be.b, be.n), &p.g, &pl) == KGENOME_OK);
		CK(pl.n == 0 && pl.ident == 0 && pl.code_unit == 0);
		CK(kgenome_endian_apply(be.b, be.n, &pl) == 0);
		CK(memcmp(be.b, copy.b, be.n) == 0);
		kgenome_endian_plan_free(&pl);
	}
}

static void little_endian(void)
{
	unsigned k;

	for (k = 0; k < EK_NARCH; k++) {
		struct ek_obj le, copy;
		struct kgenome_endian_plan pl;
		struct parsed p;

		ek_build(&le, &ek_archs[k], 0, 1);
		memcpy(&copy, &le, sizeof le);
		CK(parse(le.b, le.n, &p));
		CK(!kgenome_obj_big_endian(&p.g));
		CK(!kgenome_endian_wanted(&p.g));
		CK(kgenome_endian_plan_build(kof_buf_make(le.b, le.n), &p.g, &pl) == KGENOME_OK);
		CK(pl.n == 0 && pl.ident == 0);
		CK(kgenome_endian_apply(le.b, le.n, &pl) == 0);
		CK(memcmp(le.b, copy.b, le.n) == 0);
		kgenome_endian_plan_free(&pl);
	}
}

static void idempotent(void)
{
	unsigned k;

	for (k = 0; k < EK_NARCH; k++) {
		struct ek_obj be;
		struct kgenome_endian_plan pl, again;

		ek_build(&be, &ek_archs[k], 1, ek_archs[k].unit != 0);
		CK(plan_of(be.b, be.n, &pl) == KGENOME_OK);
		(void)kgenome_endian_apply(be.b, be.n, &pl);
		/* the canonical object's own plan is empty: normalising twice does nothing */
		CK(plan_of(be.b, be.n, &again) == KGENOME_OK);
		CK(again.n == 0 && again.ident == 0);
		kgenome_endian_plan_free(&pl);
		kgenome_endian_plan_free(&again);
	}
}

static void range_equals_applied(void)
{
	static const unsigned lens[] = { 1, 2, 3, 4, 5, 7, 8, 13, 16, 31, 64 };
	unsigned arch_ix[] = { 0, 3, 8, 9 };
	unsigned a, l;

	for (a = 0; a < sizeof arch_ix / sizeof arch_ix[0]; a++) {
		struct ek_obj be, done;
		struct kgenome_endian_plan pl;
		uint8_t out[128];
		uint32_t off;

		ek_build(&be, &ek_archs[arch_ix[a]], 1, 1);
		memcpy(&done, &be, sizeof be);
		CK(plan_of(be.b, be.n, &pl) == KGENOME_OK);
		(void)kgenome_endian_apply(done.b, done.n, &pl);
		for (off = 0; off < be.n; off++)
			for (l = 0; l < sizeof lens / sizeof lens[0]; l++) {
				uint64_t len = lens[l];

				if (off + len > be.n)
					len = be.n - off;
				memset(out, 0xaa, sizeof out);
				kgenome_endian_range(out, be.b, be.n, off, len, &pl);
				if (memcmp(out, done.b + off, (size_t)len)) {
					printf("  FAIL range %s off %u len %llu\n", ek_archs[arch_ix[a]].name, off,
					       (unsigned long long)len);
					hk_fails++;
					off = be.n;
					break;
				}
				CK(out[len] == 0xaa);   /* and nothing past it */
			}
		kgenome_endian_plan_free(&pl);
	}
}

/*
 * ARM big-endian code with its mapping symbols. $a at the start, $t after 64 bytes,
 * $d after 96: ARM words, Thumb halfwords, and a literal pool the plan leaves alone.
 */
static void arm_mark(struct ek_obj *e, const struct ek_arch *a, int be, unsigned i,
		     const char *name_at, uint32_t nameoff, uint32_t value_off)
{
	uint8_t *s = e->b + e->sec_off[EK_SYMTAB] + i * 16u;

	(void)a; (void)name_at;
	ek_put(s, nameoff, 4, be);
	ek_put(s + 4, 0x400000u + e->text + value_off, 4, be);
	ek_put(s + 8, 0, 4, be);
	s[12] = 0;                      /* STB_LOCAL, STT_NOTYPE */
	s[13] = 0;
	ek_put(s + 14, 1, 2, be);       /* the .text section */
}

static void arm_marks_build(struct ek_obj *e, const struct ek_arch *a, int be)
{
	uint32_t shent = 40, k;
	uint8_t *sh = e->b + e->sh;

	/* names in the string section (it is also ".strtab": the symbols are paired with
	 * their strings by that name) */
	memcpy(e->b + e->sec_off[EK_SHSTR] + EK_MARKS, "$a\0$t\0$d\0", 9);
	(void)sh; (void)shent;
	arm_mark(e, a, be, 1, "$a", EK_MARKS, 0);
	arm_mark(e, a, be, 2, "$t", EK_MARKS + 3u, 64);
	arm_mark(e, a, be, 3, "$d", EK_MARKS + 6u, 96);
	for (k = 0; k < 16; k++)                /* ARM: 16 words, in this order */
		ek_put(e->b + e->text + 4u * k, 0xe1a00000u ^ (k * 0x00010103u), 4, be);
	for (k = 0; k < 16; k++)                /* Thumb: 16 halfwords */
		ek_put(e->b + e->text + 64u + 2u * k, 0x4600u ^ (k * 0x0113u), 2, be);
	for (k = 0; k < 32; k++)                /* the pool: raw bytes, in both objects */
		e->b[e->text + 96u + k] = (uint8_t)(0x30 + k);
}

static void mapping_symbols(void)
{
	struct ek_arch a = ek_archs[4];         /* arm-be32 */
	struct ek_obj be, le, orig;
	struct kgenome_endian_plan pl;
	unsigned i, nspan = 0;

	a.thumb_entry = 0;
	ek_build(&be, &a, 1, 1);
	ek_build(&le, &a, 0, 1);
	arm_marks_build(&be, &a, 1);
	arm_marks_build(&le, &a, 0);
	memcpy(&orig, &be, sizeof be);
	CK(plan_of(be.b, be.n, &pl) == KGENOME_OK);
	for (i = 0; i < pl.n; i++)
		if (pl.v[i].off >= be.text && pl.v[i].off < be.text + 128u) {
			nspan++;
			CK(pl.v[i].off + pl.v[i].len <= be.text + 96u);   /* never into the pool */
		}
	CK(nspan == 2);                         /* one ARM run and one Thumb run */
	(void)kgenome_endian_apply(be.b, be.n, &pl);
	CK(differs_outside(&be, &le, "arm-marks") == 0);
	CK(memcmp(be.b + be.text + 96, orig.b + orig.text + 96, 32) == 0);
	kgenome_endian_plan_free(&pl);
}

/*
 * A hostile object: the symbol table's file offset set to the middle of .text.
 * Code is claimed first, so the symbol table is the span dropped, and the plan
 * counts it instead of leaving two spans on one byte.
 */
static void overlap_is_reported(void)
{
	struct ek_obj be, orig;
	struct kgenome_endian_plan pl;
	uint32_t shent = 40, i;
	uint8_t *h;

	ek_build(&be, &ek_archs[0], 1, 1);
	h = be.b + be.sh + 3u * shent;          /* the .symtab section header */
	ek_put(h + 16, be.text + 8u, 4, 1);
	memcpy(&orig, &be, sizeof be);
	CK(plan_of(be.b, be.n, &pl) == KGENOME_OK);
	CK(pl.dropped > 0);                     /* and the plan says so */
	for (i = 1; i < pl.n; i++)
		CK(pl.v[i - 1u].off + pl.v[i - 1u].len <= pl.v[i].off);
	(void)kgenome_endian_apply(be.b, be.n, &pl);
	(void)kgenome_endian_apply(be.b, be.n, &pl);
	CK(memcmp(be.b, orig.b, be.n) == 0);
	kgenome_endian_plan_free(&pl);
}

/*
 * A stripped object: no section table, one executable segment that starts at the ELF
 * header. The header is not code and the string literals in the segment are not words:
 * both keep their meaning, the instructions around them are swapped.
 */
static void sectionless(void)
{
	struct ek_obj be, orig;
	struct kgenome_endian_plan pl;
	uint32_t i;
	uint64_t text_swapped = 0;

	ek_build(&be, &ek_archs[0], 1, 1);
	ek_put(be.b + 32, 0, 4, 1);             /* e_shoff */
	ek_put(be.b + 48, 0, 2, 1);             /* e_shnum */
	ek_put(be.b + 50, 0, 2, 1);             /* e_shstrndx */
	memcpy(&orig, &be, sizeof be);
	CK(plan_of(be.b, be.n, &pl) == KGENOME_OK);
	CK(pl.ident == 1 && pl.dropped == 0);
	/* the first span is the ELF header, and no code span starts inside it */
	CK(pl.n > 1 && pl.v[0].off == 0 && pl.v[0].len == 52);
	for (i = 1; i < pl.n; i++)
		CK(pl.v[i].off >= 52);
	(void)kgenome_endian_apply(be.b, be.n, &pl);
	CK(be.b[5] == 1);
	/* the instructions are swapped ... */
	for (i = 0; i < be.text_len; i += 4)
		text_swapped += be.b[be.text + i] == orig.b[be.text + i + 3] &&
				be.b[be.text + i + 1] == orig.b[be.text + i + 2] &&
				be.b[be.text + i + 2] == orig.b[be.text + i + 1] &&
				be.b[be.text + i + 3] == orig.b[be.text + i];
	/* (the last word ends in a printable byte that touches the string behind it, and a unit
	 * a run touches is left whole) */
	CK(text_swapped >= be.text_len / 4u - 1u);
	/* ... and the string in .data is not. (The integer next to it is swapped: a segment
	 * cannot say where its integers are, and only text is protected.) */
	CK(memcmp(be.b + be.str_at, orig.b + be.str_at, 17) == 0);
	(void)kgenome_endian_apply(be.b, be.n, &pl);
	CK(memcmp(be.b, orig.b, be.n) == 0);
	kgenome_endian_plan_free(&pl);
}

/* The order in endian.h: the code keeps its bytes when a header table is aimed at it. */
static void code_wins(void)
{
	struct ek_obj be;
	struct kgenome_endian_plan pl;
	uint32_t i;
	int code_span = 0;

	ek_build(&be, &ek_archs[0], 1, 1);
	/* the program header table moved into .text, its one entry intact */
	memmove(be.b + be.text + 4u, be.b + be.ph, 32);
	ek_put(be.b + 28, be.text + 4u, 4, 1);
	CK(plan_of(be.b, be.n, &pl) == KGENOME_OK);
	CK(pl.dropped > 0);
	for (i = 0; i < pl.n; i++)
		if (pl.v[i].off == be.text && pl.v[i].len == be.text_len)
			code_span = 1;
	CK(code_span);
	kgenome_endian_plan_free(&pl);
}

/*
 * The plan is bounded, and says so. A note section of 70000 records is 70000 spans, past
 * KGENOME_ENDIAN_MAX_SPANS: the plan keeps what it can hold and its status is TRUNCATED, which
 * the scanner reports as a limit - an object half in each order must not read as converted.
 */
static void span_bound(void)
{
	enum { RECS = 70000 };
	static uint8_t big[EK_MAX + 12u * RECS];
	struct ek_obj be;
	struct kgenome_endian_plan pl;
	uint32_t n, sh;
	uint32_t i;

	ek_build(&be, &ek_archs[0], 1, 1);
	memcpy(big, be.b, be.n);
	n = be.n + 12u * RECS;                  /* the appended records are zeros: valid, empty notes */
	sh = be.sh + (EK_NOTE + 2u) * 40u;
	ek_put(big + sh + 16, be.n, 4, 1);              /* sh_offset */
	ek_put(big + sh + 20, 12u * RECS, 4, 1);        /* sh_size */
	CK(plan_of(big, n, &pl) == KGENOME_TRUNCATED);
	CK(pl.n <= KGENOME_ENDIAN_MAX_SPANS && pl.n > KGENOME_ENDIAN_MAX_SPANS / 2u);
	for (i = 1; i < pl.n; i++)
		CK(pl.v[i - 1u].off + pl.v[i - 1u].len <= pl.v[i].off);
	{
		static uint8_t copy[EK_MAX + 12u * RECS];

		memcpy(copy, big, n);
		(void)kgenome_endian_apply(big, n, &pl);
		(void)kgenome_endian_apply(big, n, &pl);
		CK(memcmp(copy, big, n) == 0);
	}
	kgenome_endian_plan_free(&pl);
}

/* A big-endian ELF whose header is cut: nothing is known, nothing is swapped. */
static void cut_header(void)
{
	struct ek_obj be;
	struct kgenome_endian_plan pl;
	uint8_t copy[64];
	struct parsed p;

	ek_build(&be, &ek_archs[0], 1, 1);
	memcpy(copy, be.b, 40);
	CK(parse(be.b, 40, &p));
	CK(kgenome_endian_plan_build(kof_buf_make(be.b, 40), &p.g, &pl) == KGENOME_BAD_INPUT);
	CK(pl.n == 0 && pl.ident == 0);
	CK(kgenome_endian_apply(be.b, 40, &pl) == 0);
	CK(memcmp(copy, be.b, 40) == 0);
	kgenome_endian_plan_free(&pl);
}

/* A note whose name size would run past the end, a GNU hash whose bloom size is huge. */
static void hostile_tables(void)
{
	struct ek_obj be;
	struct kgenome_endian_plan pl;
	unsigned k;

	ek_build(&be, &ek_archs[0], 1, 1);
	ek_put(be.b + be.sec_off[EK_NOTE], 0xffffffffu, 4, 1);          /* namesz */
	ek_put(be.b + be.sec_off[EK_GNUHASH] + 8, 0xffffffffu, 4, 1);   /* bloom_size */
	CK(plan_of(be.b, be.n, &pl) == KGENOME_OK);
	for (k = 0; k < pl.n; k++)
		CK(pl.v[k].off + pl.v[k].len <= be.n);
	kgenome_endian_plan_free(&pl);
}

int main(void)
{
	twin_equal();
	untouched_data();
	no_twin();
	little_endian();
	idempotent();
	range_equals_applied();
	mapping_symbols();
	overlap_is_reported();
	code_wins();
	sectionless();
	cut_header();
	hostile_tables();
	span_bound();
	if (hk_fails) {
		printf("endian_plan: %d failure(s)\n", hk_fails);
		return 1;
	}
	printf("endian_plan: ok\n");
	return 0;
}
