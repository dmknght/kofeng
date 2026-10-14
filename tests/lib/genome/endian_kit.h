/*
 * endian_kit.h - the objects the endian tests are made of, built in memory.
 *
 * ONE LOGICAL OBJECT, TWO BYTE ORDERS. ek_build() writes the same program as an
 * ELF of either order: the header, one PT_LOAD, .text (instruction words of the
 * unit the architecture has), .data (an ASCII string, a UTF-16 string, a 32-bit
 * integer and raw bytes), and one section of every kind the plan swaps - symbols,
 * RELA, REL, dynamic, SysV hash, GNU hash, versions, init array, notes, a word
 * table. The big-endian object differs from its little-endian twin only in the
 * order its fields and words are written in, so "the plan makes the big-endian
 * object equal to its twin" is a test with an oracle that is not the plan: the twin
 * is written by the field-by-field code below, from the ELF specification.
 *
 * What the twin does NOT share, on purpose: the integer in .data and the UTF-16
 * string are written in each object's own order, as a compiler would, and the
 * plan is expected to leave the integer alone (its width is not in the file) and
 * the wide-string pass to fix the string.
 */
#ifndef KGENOME_TESTS_ENDIAN_KIT_H
#define KGENOME_TESTS_ENDIAN_KIT_H

#include "hk.h"

#ifndef EK_MAX
#define EK_MAX 8192u
#endif
#define EK_SHSTR_LEN 160u
#define EK_MARKS 128u   /* where a test writes mapping-symbol names in the string table */

struct ek_arch {
	const char *name;
	int      machine, is64;
	uint32_t flags;
	unsigned unit;          /* the unit the code is swapped in; 0: code untouched */
	int      thumb_entry;   /* odd entry point */
};

/* Section kinds, in file order after .text. */
enum { EK_DATA, EK_SYMTAB, EK_RELA, EK_REL, EK_DYNAMIC, EK_HASH, EK_GNUHASH, EK_VERSYM,
       EK_INITARR, EK_NOTE, EK_WORDS, EK_SHSTR, EK_COUNT };

struct ek_obj {
	uint8_t  b[EK_MAX];
	uint32_t n;
	uint32_t text, text_len, data, sh, ph;
	uint32_t sec_off[EK_COUNT], sec_len[EK_COUNT];
	uint32_t wide_at, wide_chars, int_at, str_at;
};

static const struct ek_arch ek_archs[] = {
	{ "mips32",       8,   0, 0x00001007u, 4, 0 },
	{ "mips-micro",   8,   0, 0x02001007u, 2, 0 },
	{ "mips16",       8,   0, 0x04001007u, 2, 0 },
	{ "mips64",       8,   1, 0x60000007u, 4, 0 },
	{ "arm-be32",     40,  0, 0x05000000u, 4, 0 },
	{ "arm-be32-thm", 40,  0, 0x05000000u, 2, 1 },
	{ "arm-be8",      40,  0, 0x05800000u, 0, 0 },
	{ "aarch64-be",   183, 1, 0x00000000u, 0, 0 },
	{ "ppc64",        21,  1, 0x00000001u, 4, 0 },
	{ "sh",           42,  0, 0x00000009u, 2, 0 },
	{ "microblaze",   189, 0, 0x00000000u, 4, 0 },
};
#define EK_NARCH ((unsigned)(sizeof ek_archs / sizeof ek_archs[0]))

/* Architectures with no little-endian twin: nothing is swapped. */
static const struct ek_arch ek_notwin[] = {
	{ "sparc",   2,   0, 0, 0, 0 },
	{ "sparcv9", 43,  1, 0, 0, 0 },
	{ "ppc32",   20,  0, 0, 0, 0 },
	{ "m68k",    4,   0, 0, 0, 0 },
	{ "s390x",   22,  1, 0, 0, 0 },
	{ "or1k",    92,  0, 0, 0, 0 },
};
#define EK_NNOTWIN ((unsigned)(sizeof ek_notwin / sizeof ek_notwin[0]))

static void ek_put(uint8_t *p, uint64_t v, unsigned n, int be) HK_UNUSED;
static void ek_put(uint8_t *p, uint64_t v, unsigned n, int be)
{
	hk_w(p, v, n, be);
}

/* The logical value of field k of entry i: distinct in every byte, so a swap that
 * is wrong anywhere changes it. */
static uint64_t ek_val(unsigned i, unsigned k, unsigned width) HK_UNUSED;
static uint64_t ek_val(unsigned i, unsigned k, unsigned width)
{
	uint64_t v = 0x0102030405060708ull + (uint64_t)(i + 1u) * 0x1110111011101110ull +
		     (uint64_t)k * 0x0001000100010001ull;

	return width >= 8u ? v : v & ((1ull << (8u * width)) - 1u);
}

/* One section's content; returns its length. `o` is where it goes. */
static uint32_t ek_fill(uint8_t *o, unsigned kind, int be, const struct ek_arch *a) HK_UNUSED;
static uint32_t ek_fill(uint8_t *o, unsigned kind, int be, const struct ek_arch *a)
{
	uint32_t i, at = 0;
	int is64 = a->is64;
	int mips64 = is64 && a->machine == 8;

	switch (kind) {
	case EK_SYMTAB:
		for (i = 0; i < 5; i++) {
			uint8_t *s = o + at;

			if (is64) {
				ek_put(s, ek_val(i, 0, 4), 4, be);
				s[4] = (uint8_t)(0x10 + i);
				s[5] = (uint8_t)i;
				ek_put(s + 6, ek_val(i, 1, 2), 2, be);
				ek_put(s + 8, ek_val(i, 2, 8), 8, be);
				ek_put(s + 16, ek_val(i, 3, 8), 8, be);
				at += 24;
			} else {
				ek_put(s, ek_val(i, 0, 4), 4, be);
				ek_put(s + 4, ek_val(i, 2, 4), 4, be);
				ek_put(s + 8, ek_val(i, 3, 4), 4, be);
				s[12] = (uint8_t)(0x10 + i);
				s[13] = (uint8_t)i;
				ek_put(s + 14, ek_val(i, 1, 2), 2, be);
				at += 16;
			}
		}
		return at;
	case EK_RELA:
	case EK_REL:
		for (i = 0; i < 3; i++) {
			uint8_t *r = o + at;
			int rela = kind == EK_RELA;

			if (is64) {
				ek_put(r, 0x24u * (i + 1u), 8, be);     /* a site inside .text */
				if (mips64) {
					ek_put(r + 8, ek_val(i, 1, 4), 4, be);
					r[12] = 0x11; r[13] = 0x22; r[14] = 0x33; r[15] = (uint8_t)(0x40 + i);
				} else {
					ek_put(r + 8, ek_val(i, 1, 8), 8, be);
				}
				if (rela)
					ek_put(r + 16, ek_val(i, 2, 8), 8, be);
				at += rela ? 24u : 16u;
			} else {
				ek_put(r, 0x24u * (i + 1u), 4, be);
				ek_put(r + 4, ek_val(i, 1, 4), 4, be);
				if (rela)
					ek_put(r + 8, ek_val(i, 2, 4), 4, be);
				at += rela ? 12u : 8u;
			}
		}
		return at;
	case EK_DYNAMIC:
		for (i = 0; i < 4; i++) {
			ek_put(o + at, ek_val(i, 0, is64 ? 8 : 4), is64 ? 8 : 4, be);
			ek_put(o + at + (is64 ? 8 : 4), ek_val(i, 1, is64 ? 8 : 4), is64 ? 8 : 4, be);
			at += is64 ? 16u : 8u;
		}
		return at;
	case EK_HASH:           /* nbucket 3, nchain 5, then the words */
		ek_put(o, 3, 4, be);
		ek_put(o + 4, 5, 4, be);
		for (i = 0; i < 8; i++)
			ek_put(o + 8 + 4 * i, ek_val(i, 5, 4), 4, be);
		return 8 + 32;
	case EK_GNUHASH: {      /* nbuckets 3, symoffset 1, bloom_size 2, shift 6 */
		unsigned cw = is64 ? 8u : 4u;

		ek_put(o, 3, 4, be);
		ek_put(o + 4, 1, 4, be);
		ek_put(o + 8, 2, 4, be);
		ek_put(o + 12, 6, 4, be);
		for (i = 0; i < 2; i++)
			ek_put(o + 16 + cw * i, ek_val(i, 6, cw), cw, be);
		at = 16 + 2u * cw;
		for (i = 0; i < 8; i++)
			ek_put(o + at + 4 * i, ek_val(i, 7, 4), 4, be);
		return at + 32;
	}
	case EK_VERSYM:
		for (i = 0; i < 6; i++)
			ek_put(o + 2 * i, ek_val(i, 8, 2), 2, be);
		return 12;
	case EK_INITARR:
		for (i = 0; i < 3; i++)
			ek_put(o + (is64 ? 8u : 4u) * i, ek_val(i, 9, is64 ? 8 : 4), is64 ? 8 : 4, be);
		return 3u * (is64 ? 8u : 4u);
	case EK_NOTE:           /* "GNU", 16 desc bytes; "stapsdt", 8 desc bytes: the desc is raw */
		ek_put(o, 4, 4, be); ek_put(o + 4, 16, 4, be); ek_put(o + 8, 3, 4, be);
		memcpy(o + 12, "GNU\0", 4);
		for (i = 0; i < 16; i++)
			o[16 + i] = (uint8_t)(0xa0 + i);
		ek_put(o + 32, 8, 4, be); ek_put(o + 36, 8, 4, be); ek_put(o + 40, 3, 4, be);
		memcpy(o + 44, "stapsdt\0", 8);
		for (i = 0; i < 8; i++)
			o[52 + i] = (uint8_t)(0xc0 + i);
		return 60;
	case EK_WORDS:
		for (i = 0; i < 6; i++)
			ek_put(o + 4 * i, ek_val(i, 10, 4), 4, be);
		return 24;
	case EK_SHSTR:          /* the section names, and room for mapping-symbol names at EK_MARKS */
		memset(o, 0, EK_SHSTR_LEN);
		{
			static const char nm[] = "\0.text\0.data\0.symtab\0.rela.text\0.rel.text\0.dynamic\0.hash\0"
						 ".gnu.hash\0.versym\0.init_array\0.note\0.words\0.strtab";
			memcpy(o, nm, sizeof nm);
		}
		return EK_SHSTR_LEN;
	default:
		return 0;
	}
}

static uint32_t ek_sh_type(unsigned kind, const struct ek_arch *a) HK_UNUSED;
static uint32_t ek_sh_type(unsigned kind, const struct ek_arch *a)
{
	switch (kind) {
	case EK_DATA:    return 1;
	case EK_SYMTAB:  return 2;
	case EK_RELA:    return 4;
	case EK_REL:     return 9;
	case EK_DYNAMIC: return 6;
	case EK_HASH:    return 5;
	case EK_GNUHASH: return 0x6ffffff6u;
	case EK_VERSYM:  return 0x6fffffffu;
	case EK_INITARR: return 14;
	case EK_NOTE:    return 7;
	case EK_WORDS:   return a->machine == 40 ? 0x70000001u : 0x70000006u;
	default:         return 3;
	}
}

/*
 * The code: `ek_words` instruction units, each a different value, written in the
 * object's order when the architecture is swapped (`unit`), and little-endian in
 * both objects otherwise.
 */
#ifndef EK_CODE_UNITS
#define EK_CODE_UNITS 32u
#endif

static uint32_t ek_code_unit_val(unsigned k, unsigned unit) HK_UNUSED;
static uint32_t ek_code_unit_val(unsigned k, unsigned unit)
{
	uint32_t v = 0x27bdffe8u ^ (k * 0x01000193u);

	return unit == 2u ? (v & 0xffffu) | 0x0100u : v;
}

/* Build the object in `be` order. `code_be` says whether its code is written big-endian
 * (the plan swaps it) or little-endian (nothing to swap). */
static void ek_build(struct ek_obj *e, const struct ek_arch *a, int be, int code_be) HK_UNUSED;
static void ek_build(struct ek_obj *e, const struct ek_arch *a, int be, int code_be)
{
	uint8_t *b = e->b;
	unsigned is64 = (unsigned)a->is64, k, nsec = EK_COUNT + 2u;
	uint32_t at, eh = is64 ? 64u : 52u, ph = is64 ? 56u : 32u, shent = is64 ? 64u : 40u;
	unsigned unit = a->unit ? a->unit : 4u;
	uint32_t sh_off[EK_COUNT], sh_len[EK_COUNT];

	memset(e, 0, sizeof *e);
	e->ph = eh;
	e->text = (eh + ph + 15u) & ~15u;
	e->text_len = EK_CODE_UNITS * unit;
	for (k = 0; k < EK_CODE_UNITS; k++) {
		uint32_t v = ek_code_unit_val(k, unit);

		ek_put(b + e->text + k * unit, v, unit, code_be ? be : 0);
	}
	at = e->text + e->text_len;
	/* .data: a string at an even offset, a UTF-16 string, an integer, raw bytes */
	at = (at + 7u) & ~7u;
	e->data = at;
	e->str_at = at;
	memcpy(b + at, "Permission denied\0", 18);
	at += 18;
	e->int_at = at;
	ek_put(b + at, 0xdeadbeefu, 4, be);
	at += 4;
	at = (at + 1u) & ~1u;
	e->wide_at = at;
	{
		const char *w = "cmd.exe /c wget";
		unsigned i;

		for (i = 0; w[i]; i++) {
			b[at + 2u * i + (be ? 1u : 0u)] = (uint8_t)w[i];
			b[at + 2u * i + (be ? 0u : 1u)] = 0;
		}
		e->wide_chars = i;
		at += 2u * i + 2u;
	}
	for (k = 0; k < 7; k++)
		b[at++] = (uint8_t)(0xf0 + k);
	sh_off[EK_DATA] = e->data;
	sh_len[EK_DATA] = at - e->data;
	for (k = EK_SYMTAB; k < EK_COUNT; k++) {
		at = (at + 7u) & ~7u;
		sh_off[k] = at;
		sh_len[k] = ek_fill(b + at, k, be, a);
		at += sh_len[k];
	}
	at = (at + 7u) & ~7u;
	e->sh = at;
	e->n = at + nsec * shent;
	for (k = 0; k < EK_COUNT; k++) {
		e->sec_off[k] = sh_off[k];
		e->sec_len[k] = sh_len[k];
	}
	/* ELF header */
	b[0] = 0x7f; b[1] = 'E'; b[2] = 'L'; b[3] = 'F';
	b[4] = (uint8_t)(is64 ? 2 : 1); b[5] = (uint8_t)(be ? 2 : 1); b[6] = 1;
	ek_put(b + 16, 2, 2, be);
	ek_put(b + 18, (uint64_t)a->machine, 2, be);
	ek_put(b + 20, 1, 4, be);
	if (is64) {
		ek_put(b + 24, 0x400000u + e->text + (a->thumb_entry ? 1u : 0u), 8, be);
		ek_put(b + 32, eh, 8, be);
		ek_put(b + 40, e->sh, 8, be);
		ek_put(b + 48, a->flags, 4, be);
		ek_put(b + 52, 64, 2, be);
		ek_put(b + 54, 56, 2, be);
		ek_put(b + 56, 1, 2, be);
		ek_put(b + 58, 64, 2, be);
		ek_put(b + 60, nsec, 2, be);
		ek_put(b + 62, nsec - 1u, 2, be);
	} else {
		ek_put(b + 24, 0x400000u + e->text + (a->thumb_entry ? 1u : 0u), 4, be);
		ek_put(b + 28, eh, 4, be);
		ek_put(b + 32, e->sh, 4, be);
		ek_put(b + 36, a->flags, 4, be);
		ek_put(b + 40, 52, 2, be);
		ek_put(b + 42, 32, 2, be);
		ek_put(b + 44, 1, 2, be);
		ek_put(b + 46, 40, 2, be);
		ek_put(b + 48, nsec, 2, be);
		ek_put(b + 50, nsec - 1u, 2, be);
	}
	/* one PT_LOAD over the whole file, R+X */
	{
		uint8_t *p = b + eh;

		ek_put(p, 1, 4, be);
		if (is64) {
			ek_put(p + 4, 5, 4, be);
			ek_put(p + 8, 0, 8, be);
			ek_put(p + 16, 0x400000, 8, be);
			ek_put(p + 24, 0x400000, 8, be);
			ek_put(p + 32, e->n, 8, be);
			ek_put(p + 40, e->n, 8, be);
			ek_put(p + 48, 0x1000, 8, be);
		} else {
			ek_put(p + 4, 0, 4, be);
			ek_put(p + 8, 0x400000, 4, be);
			ek_put(p + 12, 0x400000, 4, be);
			ek_put(p + 16, e->n, 4, be);
			ek_put(p + 20, e->n, 4, be);
			ek_put(p + 24, 5, 4, be);
			ek_put(p + 28, 0x1000, 4, be);
		}
	}
	/* section headers: null, .text, then the kinds in order, .shstrtab last (index EK_COUNT) */
	for (k = 0; k < nsec; k++) {
		uint8_t *h = b + e->sh + k * shent;
		uint32_t type, off, size, link, info;
		uint64_t flags;

		if (!k)
			continue;                       /* the null section */
		if (k == 1u) {                          /* .text */
			type = 1; off = e->text; size = e->text_len; flags = 6;
		} else {
			unsigned kind = k - 2u;

			type = ek_sh_type(kind, a); off = sh_off[kind]; size = sh_len[kind];
			flags = kind == EK_SHSTR ? 0u : 2u;
		}
		{
			static const uint8_t nm[EK_COUNT + 2] = { 0, 1, 7, 13, 21, 32, 42, 51, 57, 67, 75, 87, 93, 100 };

			ek_put(h, nm[k], 4, be);
		}
		ek_put(h + 4, type, 4, be);
		/* sh_link and sh_info say what the format says they do (the reader no longer pairs by
		 * the section's NAME): a symbol table's strings are the last section (also called
		 * ".strtab" here), a relocation section applies to .text (index 1). Every other section
		 * keeps the old filler values. */
		link = 1u;
		info = 2u;
		if (k >= 2u && k - 2u == EK_SYMTAB)
			link = EK_SHSTR + 2u;                    /* the string section */
		if (k >= 2u && (k - 2u == EK_RELA || k - 2u == EK_REL))
			info = 1u;
		if (is64) {
			ek_put(h + 8, flags, 8, be);
			ek_put(h + 16, 0x400000u + off, 8, be);
			ek_put(h + 24, off, 8, be);
			ek_put(h + 32, size, 8, be);
			ek_put(h + 40, link, 4, be);
			ek_put(h + 44, info, 4, be);
			ek_put(h + 48, 8, 8, be);
			ek_put(h + 56, 24, 8, be);
		} else {
			ek_put(h + 8, flags, 4, be);
			ek_put(h + 12, 0x400000u + off, 4, be);
			ek_put(h + 16, off, 4, be);
			ek_put(h + 20, size, 4, be);
			ek_put(h + 24, link, 4, be);
			ek_put(h + 28, info, 4, be);
			ek_put(h + 32, 4, 4, be);
			ek_put(h + 36, 16, 4, be);
		}
	}
}

#endif /* KGENOME_TESTS_ENDIAN_KIT_H */
