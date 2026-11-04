/*
 * embed_var - the objects an ELF holds in its VARIABLES are children of it (objtree_embed.c).
 *
 * The owner's rule (2026-11-03): when a variable's data starts with a format header at its offset 0, the sniff chain succeeds on
 * it, so the engine's walk opens it - no carve module, no second recogniser. The candidates are the target of each pointer word
 * stored in the host's data and the start of each sized OBJECT symbol; each is offered to the chain with the format's second check.
 *
 *   found        an ELF, a zip, a gzip, a PE and a shebang script in a data array reached by a pointer; the same ELF reached only
 *                by a sized OBJECT symbol; 40 pointers to ELFs of 14 machines in both classes and byte orders
 *   not found    the same ELF with NO pointer and NO symbol (the stated limit); a libc-style four-byte magic with an invalid
 *                header; a zip member header with no end record; a shebang naming nothing; a tar header, a PDF and a script
 *                tag (formats the measurement does not offer in data); a pointer outside the image and an unaligned one
 *   overlap      an ELF whose extent holds another ELF's header: only the outer is a child of the host
 *   limits       a child quota smaller than the pointers: the host says LIMIT; a table of 1M pointers; 64 MB of data
 *   mutants      each acceptance rule and the overlap rule is switched off in turn by the build flag EMBED_MUTANT (see the
 *                list under MUTANTS) and the test that pins it must fail
 *
 * WHY THE EXISTING TESTS MISSED IT: (a) the line never existed - the walk had no stage that looked in data at all, and the
 * only test that scans an ELF carrying a file (appended-carve tests) puts it past the last segment, in the unclaimed tail.
 *
 * Run by hand:  cc ... tests/unit/embed_var.c libkofeng.a  and  embed_var <database dir>
 */

#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../libkofeng/kofeng.h"
#include "../lib/genome/hk.h"

#define BASE 0x400000u
#define DATA_OFF 0x800u

static kof_engine  *eng;
static kof_scanner *sc;

struct obj {
	uint64_t len;
	uint8_t  head[8];
	unsigned broken;
};

struct seen {
	struct obj *o;
	unsigned    n, cap;
	unsigned    top_broken;
	uint64_t    limit_hits;
};

static int on_object(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct seen *s = user;

	(void)name;
	if (!s->n)
		s->top_broken = res->broken;
	if (s->n < s->cap) {
		struct obj *o = &s->o[s->n];

		o->len = len;
		memset(o->head, 0, sizeof o->head);
		memcpy(o->head, bytes, len < sizeof o->head ? (size_t)len : sizeof o->head);
		o->broken = res->broken;
	}
	s->n++;
	return 0;
}

static struct seen scan(const uint8_t *b, uint64_t n, uint32_t max_children)
{
	static struct obj store[8192];
	struct seen s;
	struct kof_scan_option opt;

	memset(&s, 0, sizeof s);
	s.o = store;
	s.cap = sizeof store / sizeof store[0];
	memset(&opt, 0, sizeof opt);
	opt.max_produced_bytes = 256u << 20;
	opt.max_resident_bytes = 512u << 20;
	opt.max_object_bytes = 64u << 20;
	opt.max_children = max_children;
	(void)kscan_bytes(sc, b, n, "host", &opt, on_object, &s);
	return s;
}

/* objects of the tree (not the top one) that start with `magic` (len bytes) and, when `len` is not 0, are exactly that long */
static unsigned count_kids(const struct seen *s, const void *magic, size_t mn, uint64_t len)
{
	unsigned i, k = 0;

	for (i = 1; i < s->n && i < s->cap; i++)
		if (!memcmp(s->o[i].head, magic, mn) && (!len || s->o[i].len == len))
			k++;
	return k;
}

/* ---- the host: ELF with a code segment and a data segment, optionally with symbols --------------------------------------- */

struct host {
	uint8_t *b;
	uint64_t n;       /* bytes used */
	uint64_t cap;
	int      is64, be;
	uint64_t data_at; /* file offset where the next thing in data goes */
	uint32_t machine;
};

static void wr(uint8_t *p, uint64_t v, unsigned size, int be)
{
	unsigned i;

	for (i = 0; i < size; i++)
		p[be ? size - 1u - i : i] = (uint8_t)(v >> (8u * i));
}

static void host_begin(struct host *h, uint64_t cap, int is64, int be, uint32_t machine)
{
	memset(h, 0, sizeof *h);
	h->b = calloc(1, (size_t)cap);
	h->cap = cap;
	h->is64 = is64;
	h->be = be;
	h->machine = machine;
	h->data_at = DATA_OFF;
	memset(h->b, 0x90, DATA_OFF);          /* the code segment's filler: not zero, not a header */
}

/* A pointer-sized word at the next place in data. */
static uint64_t host_word(struct host *h, uint64_t v)
{
	uint64_t at = h->data_at;
	unsigned w = h->is64 ? 8u : 4u;

	wr(h->b + at, v, w, h->be);
	h->data_at += w;
	return at;
}

static void host_align(struct host *h, unsigned a)
{
	while (h->data_at % a)
		h->b[h->data_at++] = 0;      /* alignment padding is zero */
}

/* Bytes into data (aligned to 16 first); the offset they landed at. */
static uint64_t host_put(struct host *h, const void *p, uint64_t n)
{
	uint64_t at;

	host_align(h, 16);
	at = h->data_at;
	memcpy(h->b + at, p, (size_t)n);
	h->data_at += n;
	return at;
}

static uint64_t va(uint64_t off) { return BASE + off; }

/*
 * The file: ELF header, two PT_LOAD (R-X over [0, DATA_OFF), RW over the data), and - when `syms` is given - a section table with
 * .text, .data, .symtab, .strtab and .shstrtab whose symbol table holds one sized OBJECT per entry (offset, size).
 */
static uint64_t host_finish(struct host *h, const uint64_t (*syms)[2], unsigned nsyms)
{
	uint8_t *b = h->b;
	int is64 = h->is64, be = h->be;
	unsigned eh = is64 ? 64u : 52u, ph = is64 ? 56u : 32u, sh = is64 ? 64u : 40u, sym = is64 ? 24u : 16u;
	uint64_t dend = h->data_at, end = dend, shoff = 0, symoff = 0, stroff = 0, shstroff = 0, i;
	static const char shn[] = "\0.text\0.data\0.symtab\0.strtab\0.shstrtab";

	memset(b, 0, 0); /* the header is written below; the filler already sits in [eh + 2 * ph, DATA_OFF) */
	memset(b, 0, eh + 2u * ph);
	b[0] = 0x7f; b[1] = 'E'; b[2] = 'L'; b[3] = 'F';
	b[4] = is64 ? 2 : 1; b[5] = be ? 2 : 1; b[6] = 1;
	wr(b + 16, 2, 2, be);
	wr(b + 18, h->machine, 2, be);
	wr(b + 20, 1, 4, be);
	if (syms) {
		symoff = (end + 7u) & ~7ull;
		stroff = symoff + (uint64_t)(nsyms + 1u) * sym;
		shstroff = stroff + 1u + (uint64_t)nsyms * 3u;
		shoff = (shstroff + sizeof shn + 7u) & ~7ull;
		end = shoff + 6u * sh;
		for (i = 0; i < nsyms; i++) {
			uint8_t *s = b + symoff + (i + 1u) * sym;

			if (is64) {
				wr(s, 1, 4, be);
				s[4] = 0x11;                       /* GLOBAL OBJECT */
				wr(s + 6, 2, 2, be);               /* .data */
				wr(s + 8, va(syms[i][0]), 8, be);
				wr(s + 16, syms[i][1], 8, be);
			} else {
				wr(s, 1, 4, be);
				wr(s + 4, va(syms[i][0]), 4, be);
				wr(s + 8, syms[i][1], 4, be);
				s[12] = 0x11;
				wr(s + 14, 2, 2, be);
			}
		}
		b[stroff] = 0;
		for (i = 0; i < nsyms; i++) {
			b[stroff + 1u + i * 3u] = 'v';
			b[stroff + 2u + i * 3u] = (uint8_t)('a' + i % 26u);
			b[stroff + 3u + i * 3u] = 0;
		}
		memcpy(b + shstroff, shn, sizeof shn);
	}
	if (is64) {
		wr(b + 24, va(0), 8, be);
		wr(b + 32, eh, 8, be);
		wr(b + 40, shoff, 8, be);
		wr(b + 52, eh, 2, be);
		wr(b + 54, ph, 2, be);
		wr(b + 56, 2, 2, be);
		wr(b + 58, shoff ? sh : 0u, 2, be);
		wr(b + 60, shoff ? 6u : 0u, 2, be);
		wr(b + 62, shoff ? 5u : 0u, 2, be);
	} else {
		wr(b + 24, va(0), 4, be);
		wr(b + 28, eh, 4, be);
		wr(b + 32, shoff, 4, be);
		wr(b + 40, eh, 2, be);
		wr(b + 42, ph, 2, be);
		wr(b + 44, 2, 2, be);
		wr(b + 46, shoff ? sh : 0u, 2, be);
		wr(b + 48, shoff ? 6u : 0u, 2, be);
		wr(b + 50, shoff ? 5u : 0u, 2, be);
	}
	for (i = 0; i < 2; i++) {
		uint8_t *p = b + eh + i * ph;
		uint64_t off = i ? DATA_OFF : 0, len = i ? dend - DATA_OFF : DATA_OFF;

		wr(p, 1, 4, be);
		if (is64) {
			wr(p + 4, i ? 6u : 5u, 4, be);
			wr(p + 8, off, 8, be);
			wr(p + 16, va(off), 8, be);
			wr(p + 24, va(off), 8, be);
			wr(p + 32, len, 8, be);
			wr(p + 40, len, 8, be);
			wr(p + 48, 0x10, 8, be);
		} else {
			wr(p + 4, off, 4, be);
			wr(p + 8, va(off), 4, be);
			wr(p + 12, va(off), 4, be);
			wr(p + 16, len, 4, be);
			wr(p + 20, len, 4, be);
			wr(p + 24, i ? 6u : 5u, 4, be);
			wr(p + 28, 0x10, 4, be);
		}
	}
	if (syms) {
		struct { uint32_t name, type, link; uint64_t flags, addr, off, size, ent; } sec[6] = {
			{ 0, 0, 0, 0, 0, 0, 0, 0 },
			{ 1, 1, 0, 6, va(0), 0, DATA_OFF, 0 },
			{ 7, 1, 0, 3, va(DATA_OFF), DATA_OFF, dend - DATA_OFF, 0 },
			{ 13, 2, 4, 0, 0, symoff, (uint64_t)(nsyms + 1u) * sym, sym },
			{ 21, 3, 0, 0, 0, stroff, 1u + (uint64_t)nsyms * 3u, 0 },
			{ 29, 3, 0, 0, 0, shstroff, sizeof shn, 0 }
		};

		for (i = 0; i < 6; i++) {
			uint8_t *s = b + shoff + i * sh;

			wr(s, sec[i].name, 4, be);
			wr(s + 4, sec[i].type, 4, be);
			if (is64) {
				wr(s + 8, sec[i].flags, 8, be);
				wr(s + 16, sec[i].addr, 8, be);
				wr(s + 24, sec[i].off, 8, be);
				wr(s + 32, sec[i].size, 8, be);
				wr(s + 40, sec[i].link, 4, be);
				wr(s + 56, sec[i].ent, 8, be);
			} else {
				wr(s + 8, sec[i].flags, 4, be);
				wr(s + 12, sec[i].addr, 4, be);
				wr(s + 16, sec[i].off, 4, be);
				wr(s + 20, sec[i].size, 4, be);
				wr(s + 24, sec[i].link, 4, be);
				wr(s + 36, sec[i].ent, 4, be);
			}
		}
		if (i == 6 && sec[3].type == 2)
			b[shoff + 3u * sh + (is64 ? 44u : 28u)] = (uint8_t)(1 + 0); /* sh_info: first non-local symbol */
	}
	h->n = end;
	return end;
}

static void host_free(struct host *h) { free(h->b); h->b = NULL; }

/* ---- payloads ------------------------------------------------------------------------------------------------------------ */

static uint32_t crc32_of(const uint8_t *p, size_t n)
{
	uint32_t c = 0xffffffffu, i, k;

	for (i = 0; i < n; i++) {
		c ^= p[i];
		for (k = 0; k < 8; k++)
			c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1u)));
	}
	return ~c;
}

static size_t make_elf(uint8_t *out, int is64, int be, uint32_t machine)
{
	struct hk_elf e;

	hk_elf(&e, is64, be, 0);
	memcpy(out, e.b, e.n);
	wr(out + 18, machine, 2, be);
	return e.n;
}

static size_t make_zip(uint8_t *o, const char *name, const char *data)
{
	size_t nl = strlen(name), dl = strlen(data), at = 0, cd, i;

	memset(o, 0, 30 + nl + dl + 46 + nl + 22);
	memcpy(o, "PK\3\4", 4); wr(o + 4, 20, 2, 0); wr(o + 6, 0, 2, 0); wr(o + 8, 0, 2, 0);
	wr(o + 14, crc32_of((const uint8_t *)data, dl), 4, 0); wr(o + 18, dl, 4, 0); wr(o + 22, dl, 4, 0);
	wr(o + 26, nl, 2, 0); wr(o + 28, 0, 2, 0);
	memcpy(o + 30, name, nl); memcpy(o + 30 + nl, data, dl);
	at = 30 + nl + dl;
	cd = at;
	memcpy(o + at, "PK\1\2", 4); wr(o + at + 4, 20, 2, 0); wr(o + at + 6, 20, 2, 0);
	wr(o + at + 16, crc32_of((const uint8_t *)data, dl), 4, 0); wr(o + at + 20, dl, 4, 0); wr(o + at + 24, dl, 4, 0);
	wr(o + at + 28, nl, 2, 0);
	memcpy(o + at + 46, name, nl);
	at += 46 + nl;
	memcpy(o + at, "PK\5\6", 4);
	wr(o + at + 8, 1, 2, 0); wr(o + at + 10, 1, 2, 0); wr(o + at + 12, at - cd, 4, 0); wr(o + at + 16, cd, 4, 0);
	(void)i;
	return at + 22;
}

static size_t make_gzip(uint8_t *o, const char *data)
{
	size_t dl = strlen(data);

	o[0] = 0x1f; o[1] = 0x8b; o[2] = 8; memset(o + 3, 0, 7);
	o[10] = 1;                                  /* final stored block */
	wr(o + 11, dl, 2, 0); wr(o + 13, ~dl & 0xffffu, 2, 0);
	memcpy(o + 15, data, dl);
	wr(o + 15 + dl, crc32_of((const uint8_t *)data, dl), 4, 0);
	wr(o + 19 + dl, dl, 4, 0);
	return 23 + dl;
}

static size_t make_pe(uint8_t *o)
{
	struct hk_pe p;

	hk_pe(&p, 0);
	memcpy(o, p.b, p.n);
	return p.n;
}

static unsigned fails;
#define CK2(cond) do { if (!(cond)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

/* One payload in data, reached by a pointer (or by nothing, or by a symbol). */
enum reach { BY_POINTER, BY_SYMBOL, BY_NOTHING };

static struct seen run_one(const uint8_t *pay, size_t pn, enum reach r, int is64, int be, uint32_t max_children)
{
	struct host h;
	struct seen s;
	uint64_t at, sym[1][2];

	host_begin(&h, 1u << 17, is64, be, is64 ? 62u : 3u);
	if (r == BY_POINTER) {
		uint64_t slot = host_word(&h, 0);

		host_align(&h, 16);
		at = host_put(&h, pay, pn);
		wr(h.b + slot, va(at), is64 ? 8u : 4u, be);
	} else {
		host_word(&h, 0x1234);
		at = host_put(&h, pay, pn);
	}
	sym[0][0] = at;
	sym[0][1] = pn;
	host_finish(&h, r == BY_SYMBOL ? (const uint64_t (*)[2])sym : NULL, r == BY_SYMBOL ? 1u : 0u);
	s = scan(h.b, h.n, max_children);
	host_free(&h);
	return s;
}

static void case_found(void)
{
	uint8_t pay[8192];
	size_t n;
	struct seen s;
	int cls;

	for (cls = 0; cls < 4; cls++) {
		int is64 = cls & 1, be = cls >> 1;

		n = make_elf(pay, 1, 0, 183);
		s = run_one(pay, n, BY_POINTER, is64, be, 0);
		printf("  elf by pointer (host %s %s): %u objects\n", is64 ? "elf64" : "elf32", be ? "be" : "le", s.n);
		CK2(count_kids(&s, "\x7f""ELF", 4, n) == 1u);
	}
	n = make_elf(pay, 0, 1, 8);                       /* a MIPS big-endian ELF held in an ELF64 little-endian host */
	s = run_one(pay, n, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "\x7f""ELF", 4, n) == 1u);

	n = make_zip(pay, "inner.txt", "a payload held in a variable");
	s = run_one(pay, n, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "PK\3\4", 4, n) == 1u);

	n = make_gzip(pay, "a payload held in a variable, gzip");
	s = run_one(pay, n, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "\x1f\x8b", 2, n) == 1u);

	n = make_pe(pay);
	s = run_one(pay, n, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "MZ", 2, 0) == 1u);

	{
		static const char sh[] = "#!/bin/sh\necho a script held in a variable\n";

		memcpy(pay, sh, sizeof sh);                  /* with its NUL: a C string */
		s = run_one(pay, sizeof sh, BY_POINTER, 1, 0, 0);
		CK2(count_kids(&s, "#!/bin/", 7, sizeof sh - 1u) == 1u);
	}
}

static void case_symbol(void)
{
	uint8_t pay[8192];
	size_t n = make_elf(pay, 1, 0, 62);
	struct seen s = run_one(pay, n, BY_SYMBOL, 1, 0, 0);

	printf("  elf by a sized OBJECT symbol, no pointer: %u objects\n", s.n);
	CK2(count_kids(&s, "\x7f""ELF", 4, n) == 1u);
	s = run_one(pay, n, BY_SYMBOL, 0, 1, 0);          /* ELF32 big-endian host */
	CK2(count_kids(&s, "\x7f""ELF", 4, n) == 1u);
}

/* THE STATED LIMIT: nothing points at it and no symbol names it. */
static void case_no_pointer(void)
{
	uint8_t pay[8192];
	size_t n = make_elf(pay, 1, 0, 62);
	struct seen s = run_one(pay, n, BY_NOTHING, 1, 0, 0);

	printf("  elf with no pointer and no symbol: %u objects (the limit)\n", s.n);
	CK2(count_kids(&s, "\x7f""ELF", 4, n) == 0u);
}

static void case_refused(void)
{
	uint8_t pay[8192];
	struct seen s;
	size_t n;

	/* libc-style: the four magic bytes and a constant, not a header */
	memset(pay, 0x20, sizeof pay);
	memcpy(pay, "\x7f""ELF", 4);
	s = run_one(pay, 200, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "\x7f""ELF", 4, 0) == 0u);
	/* a real header with a machine nobody knows */
	n = make_elf(pay, 1, 0, 0x7777);
	s = run_one(pay, n, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "\x7f""ELF", 4, 0) == 0u);
	/* a header cut short of its own size, the last thing in the file (a fuzz finding: 46 bytes of an ELF32 header) */
	n = make_elf(pay, 0, 0, 3);
	s = run_one(pay, 46, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "\x7f""ELF", 4, 0) == 0u);
	/* a real header with e_type RELOC */
	n = make_elf(pay, 1, 0, 62);
	wr(pay + 16, 1, 2, 0);
	s = run_one(pay, n, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "\x7f""ELF", 4, 0) == 0u);
	/* a zip member header and nothing else: no end record */
	memset(pay, 0x20, sizeof pay);
	memcpy(pay, "PK\3\4", 4);
	s = run_one(pay, 300, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "PK\3\4", 4, 0) == 0u);
	/* a zip whose end record names a directory that is not where it ends */
	n = make_zip(pay, "inner.txt", "payload");
	wr(pay + n - 6, 3, 4, 0);                           /* cd_off */
	s = run_one(pay, n, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "PK\3\4", 4, 0) == 0u);
	/* a gzip with a reserved flag */
	n = make_gzip(pay, "reserved flags");
	pay[3] = 0x20;
	s = run_one(pay, n, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "\x1f\x8b", 2, 0) == 0u);
	/* a gzip whose first block does not inflate */
	n = make_gzip(pay, "not a stream");
	pay[10] = 0x07;                                     /* BTYPE 3: reserved */
	s = run_one(pay, n, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "\x1f\x8b", 2, 0) == 0u);
	/* xz: the magic followed by something that is not the CRC of the flags (a pattern of a magic database), and one that is */
	memset(pay, 0x20, 64);
	memcpy(pay, "\xfd""7zXZ\0", 6);
	s = run_one(pay, 64, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "\xfd""7zXZ", 6, 0) == 0u);
	wr(pay + 8, crc32_of(pay + 6, 2), 4, 0);
	s = run_one(pay, 64, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "\xfd""7zXZ", 6, 0) == 1u);
	/* rar: the marker followed by a table's mask or a number (a recogniser's patterns), and RAR3 and RAR5 followed by a main header */
	memset(pay, 0x20, 64);
	memcpy(pay, "Rar!\x1a\x07\x00\xff\x01\x03\x07\x0f\x1f\x3f\x7f", 15);
	s = run_one(pay, 64, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "Rar!", 4, 0) == 0u);
	memcpy(pay, "Rar!\x1a\x07\x01\x00\x00\xca\x9a\x3b\x00\x00\x00\x00", 12);
	s = run_one(pay, 64, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "Rar!", 4, 0) == 0u);
	memset(pay, 0x20, 64);
	memcpy(pay, "Rar!\x1a\x07\x00\x00\x00\x73\x00\x00\x0d\x00\x00\x00\x00", 13);
	s = run_one(pay, 64, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "Rar!", 4, 0) == 1u);
	memset(pay, 0x20, 64);
	memcpy(pay, "Rar!\x1a\x07\x01\x00\x11\x22\x33\x44\x05\x01\x00\x00", 16);
	s = run_one(pay, 64, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "Rar!", 4, 0) == 1u);
	/* a shebang that names nothing */
	memset(pay, 0x01, 64);
	memcpy(pay, "#!\x01\x02\x03", 5);
	s = run_one(pay, 64, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "#!", 2, 0) == 0u);
	/* a PDF, a tar header and a script tag: not offered in data */
	memset(pay, 0, sizeof pay);
	memcpy(pay, "%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n", 44);
	s = run_one(pay, 44, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "%PDF", 4, 0) == 0u);
	memset(pay, 0, 512);
	memcpy(pay, "file.txt", 8);
	memcpy(pay + 100, "0000644", 7);
	memcpy(pay + 124, "00000000000", 11);
	memcpy(pay + 257, "ustar\0""00", 8);
	memcpy(pay + 148, "       ", 7);
	s = run_one(pay, 1024, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "file.txt", 8, 0) == 0u);
	memset(pay, 0x20, 64);
	memcpy(pay, "<?php echo 1; ?>", 16);
	pay[40] = 0;
	s = run_one(pay, 41, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "<?php", 5, 0) == 0u);
}

/* A pointer outside the image, an unaligned one, a pointer into the code segment: nothing is offered. */
static void case_outside(void)
{
	uint8_t pay[8192];
	size_t n = make_elf(pay, 1, 0, 62);
	struct host h;
	struct seen s;
	uint64_t at;

	host_begin(&h, 1u << 17, 1, 0, 62);
	host_word(&h, 0x10000000);                         /* past the image */
	host_word(&h, BASE + 0x40);                        /* into the code segment */
	host_word(&h, 0xffffffffffffffffull);
	host_align(&h, 16);
	at = host_put(&h, pay, n);
	h.b[h.data_at++] = 0;
	{
		/* an unaligned pointer word: the bytes of a pointer at an odd file offset are not read as one */
		uint64_t odd = h.data_at | 1u;

		if (odd == h.data_at)
			odd += 2u;
		wr(h.b + odd, va(at), 8, 0);
		h.data_at = odd + 8u;
	}
	host_finish(&h, NULL, 0);
	s = scan(h.b, h.n, 0);
	printf("  pointers outside the image / into code / unaligned: %u objects\n", s.n);
	CK2(count_kids(&s, "\x7f""ELF", 4, n) == 0u);
	host_free(&h);
}

static void case_forty(void)
{
	static const uint32_t m[14] = { 3, 62, 40, 183, 8, 20, 21, 243, 43, 2, 4, 42, 94, 189 };
	struct host h;
	struct seen s;
	uint8_t pay[8192];
	uint64_t slot[40], at;
	unsigned i, found = 0;
	size_t n;

	host_begin(&h, 1u << 18, 1, 0, 62);
	for (i = 0; i < 40; i++)
		slot[i] = host_word(&h, 0);
	for (i = 0; i < 40; i++) {
		int is64 = (m[i % 14] == 62 || m[i % 14] == 183 || m[i % 14] == 21 || m[i % 14] == 43) ? 1 : (int)(i & 1u);
		int be = (int)((i >> 1) & 1u);

		n = make_elf(pay, is64, be, m[i % 14]);
		pay[8 + (i % 7)] = (uint8_t)i;               /* distinct bytes in padding of e_ident: 40 different contents */
		at = host_put(&h, pay, n);
		wr(h.b + slot[i], va(at), 8, 0);
	}
	host_finish(&h, NULL, 0);
	s = scan(h.b, h.n, 0);
	for (i = 1; i < s.n && i < s.cap; i++)
		found += !memcmp(s.o[i].head, "\x7f""ELF", 4);
	printf("  40 pointers to ELFs of 14 machines: %u ELF children\n", found);
	CK2(found >= 40u);
	host_free(&h);
}

/* Overlap: the inner ELF's header sits inside the outer's extent; only the outer is a child of the host. */
static void case_overlap(void)
{
	uint8_t outer[8192], inner[8192];
	size_t ni = make_elf(inner, 1, 0, 183), no;
	struct host h;
	struct seen s;
	uint64_t s0, s1, at, in_at;
	struct hk_elf e;

	hk_elf(&e, 1, 0, 0);
	memcpy(outer, e.b, e.n);
	no = e.n + 64;
	memset(outer + e.n, 0x33, 64);
	memcpy(outer + e.n + 8, inner, ni < 48 ? ni : 48);   /* not a header: keeps the outer's own bytes plain */
	/* the outer ELF's PT_LOAD covers its whole file, so its extent is `no` and holds the inner header below */
	wr(outer + 64 + 32, no, 8, 0);
	wr(outer + 64 + 40, no + 0x100u, 8, 0);
	memcpy(outer + e.n, inner, ni < 64 ? ni : 64);
	host_begin(&h, 1u << 17, 1, 0, 62);
	s0 = host_word(&h, 0);
	s1 = host_word(&h, 0);
	at = host_put(&h, outer, no);
	in_at = at + e.n;
	wr(h.b + s0, va(at), 8, 0);
	wr(h.b + s1, va(in_at), 8, 0);
	host_finish(&h, NULL, 0);
	s = scan(h.b, h.n, 0);
	printf("  overlap: outer %zu bytes with an ELF header inside: %u objects\n", no, s.n);
	CK2(count_kids(&s, "\x7f""ELF", 4, no) == 1u);
	CK2(count_kids(&s, "\x7f""ELF", 4, 0) == 1u);        /* the inner header, inside the outer's extent, is not a child of the host */
	host_free(&h);
}

/* A quota smaller than the pointers: the host says LIMIT (reported, not dropped). */
static void case_quota(void)
{
	struct host h;
	struct seen s;
	uint8_t pay[8192];
	uint64_t slot[12], at;
	unsigned i;
	size_t n = make_elf(pay, 1, 0, 62);

	host_begin(&h, 1u << 17, 1, 0, 62);
	for (i = 0; i < 12; i++)
		slot[i] = host_word(&h, 0);
	for (i = 0; i < 12; i++) {
		pay[9] = (uint8_t)i;
		at = host_put(&h, pay, n);
		wr(h.b + slot[i], va(at), 8, 0);
	}
	host_finish(&h, NULL, 0);
	s = scan(h.b, h.n, 12);
	CK2(count_kids(&s, "\x7f""ELF", 4, n) == 12u);
	s = scan(h.b, h.n, 5);
	printf("  quota 5 of 12: %u ELF children, top broken=%u\n", count_kids(&s, "\x7f""ELF", 4, n), s.top_broken);
	CK2(count_kids(&s, "\x7f""ELF", 4, n) == 5u);
	CK2(s.top_broken == KOF_BROKEN_LIMIT);
	host_free(&h);
}


/* ---- encoded values: the gate names the decoder, the same second check follows ---------------------------------------- */

static size_t enc_esc(uint8_t *o, const uint8_t *p, size_t n, char sep)
{
	size_t i;

	for (i = 0; i < n; i++) {
		static const char hx[] = "0123456789abcdef";

		o[4 * i] = (uint8_t)sep; o[4 * i + 1] = 'x'; o[4 * i + 2] = (uint8_t)hx[p[i] >> 4]; o[4 * i + 3] = (uint8_t)hx[p[i] & 15];
	}
	return 4 * n;
}

static size_t enc_hex(uint8_t *o, const uint8_t *p, size_t n, int upper)
{
	size_t i;
	const char *hx = upper ? "0123456789ABCDEF" : "0123456789abcdef";

	for (i = 0; i < n; i++) {
		o[2 * i] = (uint8_t)hx[p[i] >> 4]; o[2 * i + 1] = (uint8_t)hx[p[i] & 15];
	}
	return 2 * n;
}

static size_t enc_b64(uint8_t *o, const uint8_t *p, size_t n)
{
	static const char a[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t i, k = 0;

	for (i = 0; i < n; i += 3) {
		uint32_t v = (uint32_t)p[i] << 16 | (i + 1 < n ? (uint32_t)p[i + 1] << 8 : 0) | (i + 2 < n ? p[i + 2] : 0u);

		o[k++] = (uint8_t)a[v >> 18 & 63]; o[k++] = (uint8_t)a[v >> 12 & 63];
		o[k++] = i + 1 < n ? (uint8_t)a[v >> 6 & 63] : '=';
		o[k++] = i + 2 < n ? (uint8_t)a[v & 63] : '=';
	}
	return k;
}

static void case_encoded(void)
{
	uint8_t pay[8192], enc[16384];
	size_t n = make_elf(pay, 1, 0, 62), m;
	struct seen s;

	m = enc_esc(enc, pay, n, '\\');
	s = run_one(enc, m, BY_POINTER, 1, 0, 0);
	printf("  ELF as \\xNN text: %u objects\n", s.n);
	CK2(count_kids(&s, "\x7f""ELF", 4, n) == 1u);
	m = enc_esc(enc, pay, n, '/');
	s = run_one(enc, m, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "\x7f""ELF", 4, n) == 1u);
	m = enc_hex(enc, pay, n, 0);
	s = run_one(enc, m, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "\x7f""ELF", 4, n) == 1u);
	m = enc_hex(enc, pay, n, 1);
	s = run_one(enc, m, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "\x7f""ELF", 4, n) == 1u);
	m = enc_b64(enc, pay, n);
	s = run_one(enc, m, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "\x7f""ELF", 4, n) == 1u);
	/* a gzip, as base64: the extent is the trailer's */
	n = make_gzip(pay, "a gzip payload carried as base64 text in a variable");
	m = enc_b64(enc, pay, n);
	s = run_one(enc, m, BY_POINTER, 1, 0, 0);
	CK2(count_kids(&s, "\x1f\x8b", 2, n) == 1u);

	/* a pointer into the middle of the same text: not where a variable starts (the one at its start is the child) */
	n = make_elf(pay, 1, 0, 62);
	m = enc_b64(enc, pay, n);
	{
		struct host h;
		uint64_t slot0, slot1, at;

		host_begin(&h, 1u << 17, 1, 0, 62);
		slot0 = host_word(&h, 0);
		slot1 = host_word(&h, 0);
		at = host_put(&h, enc, m);
		wr(h.b + slot0, va(at + 8), 8, 0);               /* into the middle: not offered */
		host_finish(&h, NULL, 0);
		s = scan(h.b, h.n, 0);
		CK2(count_kids(&s, "\x7f""ELF", 4, n) == 0u);
		wr(h.b + slot1, va(at), 8, 0);                   /* and at its start: found */
		s = scan(h.b, h.n, 0);
		CK2(count_kids(&s, "\x7f""ELF", 4, n) == 1u);
		host_free(&h);
	}

	/* text that decodes to nothing the chain accepts: a hash in hex, a table of 'A', a sentence */
	memset(pay, 0x37, 200);
	m = enc_hex(enc, pay, 64, 0);
	s = run_one(enc, m, BY_POINTER, 1, 0, 0);
	CK2(s.n == 1u);
	memset(enc, 'A', 400);
	s = run_one(enc, 400, BY_POINTER, 1, 0, 0);
	CK2(s.n == 1u);
	{
		static const char txt[] = "\x7f""ELF not a header at all, only four magic bytes and text";

		m = enc_hex(enc, (const uint8_t *)txt, sizeof txt - 1u, 0);
	}
	s = run_one(enc, m, BY_POINTER, 1, 0, 0);
	CK2(s.n == 1u);
}

/* A header written under a key the first bytes give: one byte, and four repeating. */
static void case_xor(void)
{
	uint8_t pay[8192], enc[8192];
	static const uint8_t keys[][4] = { { 0x5a, 0x5a, 0x5a, 0x5a }, { 0x01, 0x01, 0x01, 0x01 }, { 0xff, 0xff, 0xff, 0xff },
					   { 0x13, 0x37, 0xc0, 0xde }, { 0xde, 0xad, 0xbe, 0xef } };
	size_t n = make_elf(pay, 1, 0, 62), i;
	unsigned k;
	struct seen s;

	for (k = 0; k < sizeof keys / sizeof keys[0]; k++) {
		for (i = 0; i < n; i++)
			enc[i] = pay[i] ^ keys[k][i % 4];
		s = run_one(enc, n, BY_POINTER, 1, 0, 0);
		printf("  ELF under key %02x%02x%02x%02x: %u objects\n", keys[k][0], keys[k][1], keys[k][2], keys[k][3], s.n);
		CK2(count_kids(&s, "\x7f""ELF", 4, n) == 1u);
	}
	/* the four magic bytes under a key and a header that is not one: refused by the second check */
	memset(pay, 0x20, 200);
	memcpy(pay, "\x7f""ELF", 4);
	for (i = 0; i < 200; i++)
		enc[i] = pay[i] ^ keys[3][i % 4];
	s = run_one(enc, 200, BY_POINTER, 1, 0, 0);
	CK2(s.n == 1u);
	/* a key that is not the repeating form: the header is not found (the stated limit) */
	n = make_elf(pay, 1, 0, 62);
	for (i = 0; i < n; i++)
		enc[i] = pay[i] ^ (uint8_t)(0x40 + i);
	s = run_one(enc, n, BY_POINTER, 1, 0, 0);
	CK2(s.n == 1u);
}

/* An ELF in the host's CODE, pointed at from data. With a section table that names the code it is not a variable and is not
 * offered; a host with no section table cannot tell code from data (the Mozi arrays are .rodata in an R-X segment that nothing
 * names), so there all its loaded bytes are candidates. */
static void case_in_code(void)
{
	uint8_t pay[8192];
	size_t n = make_elf(pay, 1, 0, 62);
	struct host h;
	struct seen s;
	uint64_t dummy[1][2] = { { DATA_OFF, 8 } };

	host_begin(&h, 1u << 17, 1, 0, 62);
	memcpy(h.b + 0x200, pay, n);                      /* inside the code segment: [0, DATA_OFF) */
	host_word(&h, va(0x200));
	host_finish(&h, (const uint64_t (*)[2])dummy, 1);
	s = scan(h.b, h.n, 0);
	printf("  an ELF in code, host with a section table: %u objects\n", s.n);
	CK2(count_kids(&s, "\x7f""ELF", 4, n) == 0u);
	host_free(&h);

	host_begin(&h, 1u << 17, 1, 0, 62);
	memcpy(h.b + 0x200, pay, n);
	host_word(&h, va(0x200));
	host_finish(&h, NULL, 0);
	s = scan(h.b, h.n, 0);
	printf("  an ELF in code, host with NO section table: %u objects\n", s.n);
	CK2(count_kids(&s, "\x7f""ELF", 4, n) == 1u);
	host_free(&h);

	/* the same, named by a sized OBJECT symbol (which the envelope of the data does not filter) */
	{
		uint64_t sym[1][2] = { { 0x200, 0 } };

		sym[0][1] = n;
		host_begin(&h, 1u << 17, 1, 0, 62);
		memcpy(h.b + 0x200, pay, n);
		host_word(&h, 0x1234);
		host_finish(&h, (const uint64_t (*)[2])sym, 1);
		s = scan(h.b, h.n, 0);
		CK2(count_kids(&s, "\x7f""ELF", 4, n) == 0u);
		host_free(&h);
	}
}

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/* Hostile: 1M pointers to distinct places in plain data; and 64 MB of data with a sparse table. */
static void case_hostile(void)
{
	struct host h;
	struct seen s;
	uint64_t i, k, dataend;
	double t0;

	host_begin(&h, 20u << 20, 1, 0, 62);
	for (i = 0; i < (1u << 20); i++)
		host_word(&h, 0);
	host_align(&h, 16);
	dataend = h.data_at;
	memset(h.b + dataend, 0x41, 4u << 20);
	h.data_at = dataend + (4u << 20);
	for (i = 0; i < (1u << 20); i++)
		wr(h.b + DATA_OFF + i * 8u, va(dataend + (i * 4u) % (4u << 20)), 8, 0);
	host_finish(&h, NULL, 0);
	t0 = now();
	s = scan(h.b, h.n, 0);
	printf("  1M pointers, %u objects, %.2f s\n", s.n, now() - t0);
	CK2(count_kids(&s, "\x7f""ELF", 4, 0) == 0u);
	CK2(now() - t0 < 60.0);
	host_free(&h);

	host_begin(&h, 64u << 20, 1, 0, 62);
	for (k = 0; k < 4096; k++)
		host_word(&h, 0);
	h.data_at = (62u << 20);
	memset(h.b + DATA_OFF + 4096u * 8u, 0x41, h.data_at - DATA_OFF - 4096u * 8u);
	for (k = 0; k < 4096; k++)
		wr(h.b + DATA_OFF + k * 8u, va(DATA_OFF + 40000u + k * 13u), 8, 0);
	host_finish(&h, NULL, 0);
	t0 = now();
	s = scan(h.b, h.n, 0);
	printf("  64 MB of data: %u objects, %.2f s\n", s.n, now() - t0);
	CK2(count_kids(&s, "\x7f""ELF", 4, 0) == 0u);
	host_free(&h);
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/release/databases";

	eng = keng_open(db);
	if (!eng) {
		printf("embed_var: no database at %s - nothing tested\n", db);
		return 0;
	}
	sc = kscan_new(eng);
	if (!sc)
		return 1;
	case_found();
	case_symbol();
	case_no_pointer();
	case_refused();
	case_outside();
	case_forty();
	case_overlap();
	case_quota();
	case_encoded();
	case_xor();
	case_in_code();
	case_hostile();
	kscan_free(sc);
	keng_close(eng);
	printf("embed_var: %s (%u failures)\n", fails ? "FAILED" : "ok", fails);
	return fails != 0 || hk_fails != 0;
}
