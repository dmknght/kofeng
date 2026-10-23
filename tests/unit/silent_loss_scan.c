/*
 * silent_loss_scan - a container with more members than the engine will open must
 * SAY so. The invariant, per container, is "every member became an object, OR the
 * scan raised a signal" - kof_result.broken on some object, or a finding. A
 * caller that gets fewer objects and no signal cannot tell an archive with N
 * members from an archive it stopped reading at N.
 *
 * Fixtures are built in memory from bytes (stored members, distinct content, so
 * nothing is a duplicate and nothing needs a decoder). They are scanned through
 * the whole pipeline (kscan_bytes) against the product database, because the
 * parse is not where the member is lost or kept: the unpacker module decides
 * what to do with the parse's "entries full" anomaly.
 *
 * A case that holds is a CK; a case that loses evidence is a KM_CHECK whose cap
 * string names the limit, so the day it is fixed this goes red until the marker
 * is turned into a CK. Written against the expectation, never against the bug.
 */

#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofmod/zip.h"
#include "../../libkofeng/kofcore/kofmod/rtf.h"
#include "../../libkofeng/kofcore/kofmod/pdf.h"
#include "../../libkofeng/kofcore/kofmod/sevenzip.h"
#include "../../libkofeng/kofcore/kofmod/tar.h"
#include "../../libkofeng/kofcore/kofmod/arj.h"
#include "../../libkofeng/kofcore/kofmod/lha.h"
#include "../../libkofeng/kofcore/kofmod/cab.h"
#include "../../libkofeng/kofcore/kofmod/chm.h"
#include "../../libkofeng/scanners/scan.h"
#include "known_miss.h"
#include "notes.h"
#include "asking_db.h"
#include "chmgen.h"

static int fails;

#define MARKER "KOFMARK!"

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

static kof_engine  *eng;
static kof_scanner *sc;

/* ---- what a scan reported --------------------------------------------------- */

struct seen {
	unsigned objs;       /* every object the callback saw, the top one too   */
	unsigned broken;     /* objects with a non-zero kof_result.broken        */
	unsigned first_why;  /* the first reason                                 */
	unsigned finds;      /* notes the test modules made on any object        */
	unsigned marker;     /* children whose bytes are the marker              */
	unsigned anom;       /* objects carrying a format anomaly word           */
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct seen *s = user;
	struct note_list got;

	(void)name;
	notes_here(&got);
	s->objs++;
	if (bytes && len == 8u && memcmp(bytes, MARKER, 8) == 0)
		s->marker++;
	if (res->broken) {
		if (!s->broken)
			s->first_why = res->broken;
		s->broken++;
	}
	s->finds += got.n;
	if (res->heur_anomalies)
		s->anom++;
	return 0;
}

static void scan(const uint8_t *b, uint64_t n, const char *name, struct seen *s)
{
	struct kof_scan_option opt;

	memset(s, 0, sizeof *s);
	memset(&opt, 0, sizeof opt);
	opt.max_produced_bytes = 256u << 20;
	opt.max_resident_bytes = 512u << 20;
	opt.max_object_bytes = 64u << 20;
	(void)kscan_bytes(sc, b, n, name, &opt, on_object, s);
}

/* The invariant: the marker member was opened, OR the scan raised a signal. */
static int held(const struct seen *s)
{
	return s->marker || s->broken || s->finds || s->anom;
}

static void le16(uint8_t *p, unsigned v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* The eight bytes of member i of n: distinct, and the last one is the marker a
 * scan has to find. */
static void body8(uint8_t *b, unsigned i, unsigned n)
{
	char t[16];

	if (i + 1u == n) {
		memcpy(b, MARKER, 8);
		return;
	}
	snprintf(t, sizeof t, "KOF%04u", i % 10000u);
	memcpy(b, t, 8);
}

/* ---- zip: N stored members -------------------------------------------------- */

static uint8_t *zip_of(unsigned n, size_t *len, int sparse)
{
	size_t cap = (size_t)n * 160u + 64u, at = 0, cd, i;
	uint8_t *f = calloc(1, cap);
	char name[16];

	if (!f)
		return NULL;
	for (i = 0; i < n; i++) {
		unsigned nl = (unsigned)snprintf(name, sizeof name, "e%05u", (unsigned)i);

		unsigned dl = (!sparse || i + 1u == n) ? 8u : 0u;

		le32(f + at, 0x04034b50u);
		le16(f + at + 4, 10);
		le32(f + at + 18, dl);         /* csize */
		le32(f + at + 22, dl);         /* usize */
		le16(f + at + 26, nl);
		memcpy(f + at + 30, name, nl);
		if (dl)
			body8(f + at + 30 + nl, (unsigned)i, n);
		at += 30u + nl + dl;
	}
	cd = at;
	{
		size_t lo = 0;

		for (i = 0; i < n; i++) {
			unsigned nl = (unsigned)snprintf(name, sizeof name, "e%05u", (unsigned)i);

			le32(f + at, 0x02014b50u);
			le16(f + at + 4, 20);
			le16(f + at + 6, 10);
			unsigned dl = (!sparse || i + 1u == n) ? 8u : 0u;

			le32(f + at + 20, dl);
			le32(f + at + 24, dl);
			le16(f + at + 28, nl);
			le32(f + at + 42, (uint32_t)lo);
			memcpy(f + at + 46, name, nl);
			at += 46u + nl;
			lo += 30u + nl + dl;
		}
	}
	le32(f + at, 0x06054b50u);
	le16(f + at + 8, n > 0xffffu ? 0xffffu : n);
	le16(f + at + 10, n > 0xffffu ? 0xffffu : n);
	le32(f + at + 12, (uint32_t)(at - cd));
	le32(f + at + 16, (uint32_t)cd);
	at += 22u;
	*len = at;
	return f;
}

static uint8_t *build_zip(unsigned n, size_t *len) { return zip_of(n, len, 0); }

/* ---- tar: N stored members -------------------------------------------------- */

static uint8_t *build_tar(unsigned n, size_t *len)
{
	size_t at = 0, i, k;
	uint8_t *f = calloc((size_t)n + 2u, 1024u);

	if (!f)
		return NULL;
	for (i = 0; i < n; i++) {
		uint8_t *h = f + at;
		unsigned sum = 0;

		snprintf((char *)h, 100, "t%05u", (unsigned)i);
		memcpy(h + 100, "0000644", 8);
		memcpy(h + 108, "0000000", 8);
		memcpy(h + 116, "0000000", 8);
		memcpy(h + 124, "00000000010", 12);       /* 8 bytes */
		memcpy(h + 136, "00000000000", 12);
		memset(h + 148, ' ', 8);
		h[156] = '0';
		memcpy(h + 257, "ustar", 6);
		memcpy(h + 263, "00", 2);
		for (k = 0; k < 512; k++)
			sum += h[k];
		snprintf((char *)h + 148, 8, "%06o", sum);
		h[155] = ' ';
		body8(f + at + 512, (unsigned)i, n);
		at += 1024u;
	}
	at += 1024u;                                      /* the two zero blocks */
	*len = at;
	return f;
}

/* ---- arj / lha: N stored members -------------------------------------------- */

static uint32_t arj_hdr(uint8_t *p, uint8_t ftype, const char *name,
			const uint8_t *body, uint32_t blen)
{
	uint32_t nl = (uint32_t)strlen(name) + 1u, basic = 30u + nl + 1u, at;

	p[0] = 0x60u; p[1] = 0xeau;
	le16(p + 2, basic);
	p[4] = 30; p[5] = 11; p[6] = 1; p[7] = 2;
	p[8] = 0; p[9] = 0; p[10] = ftype;
	le32(p + 16, blen);
	le32(p + 20, blen);
	memcpy(p + 4 + 30, name, nl);
	at = 4u + basic;
	at += 4u;
	le16(p + at, 0);
	at += 2u;
	if (blen) {
		memcpy(p + at, body, blen);
		at += blen;
	}
	return at;
}

static uint8_t *build_arj(unsigned n, size_t *len)
{
	uint8_t *f = calloc((size_t)n + 4u, 96u);
	size_t at;
	unsigned i;

	if (!f)
		return NULL;
	at = arj_hdr(f, 2, "a.arj", NULL, 0);
	for (i = 0; i < n; i++) {
		char name[16];
		uint8_t body[8];

		snprintf(name, sizeof name, "a%05u", i);
		body8(body, i, n);
		at += arj_hdr(f + at, 0, name, body, 8);
	}
	f[at] = 0x60u; f[at + 1u] = 0xeau;
	at += 4u;
	*len = at;
	return f;
}

static uint32_t lha_hdr(uint8_t *p, const char *name, const uint8_t *body, uint32_t blen)
{
	uint32_t nl = (uint32_t)strlen(name), hsize = 20u + nl + 2u, sum = 0, i;

	p[0] = (uint8_t)hsize;
	memcpy(p + 2, "-lh0-", 5);
	le32(p + 7, blen);
	le32(p + 11, blen);
	p[19] = 0x20u;
	p[21] = (uint8_t)nl;
	memcpy(p + 22, name, nl);
	for (i = 0; i < hsize; i++)
		sum += p[2 + i];
	p[1] = (uint8_t)sum;
	memcpy(p + 2 + hsize, body, blen);
	return 2u + hsize + blen;
}

static uint8_t *build_lha(unsigned n, size_t *len)
{
	uint8_t *f = calloc((size_t)n + 4u, 64u);
	size_t at = 0;
	unsigned i;

	if (!f)
		return NULL;
	for (i = 0; i < n; i++) {
		char name[16];
		uint8_t body[8];

		snprintf(name, sizeof name, "l%05u", i);
		body8(body, i, n);
		at += lha_hdr(f + at, name, body, 8);
	}
	f[at++] = 0;
	*len = at;
	return f;
}

/* ---- cab: N files in one stored folder -------------------------------------- */

static uint8_t *build_cab(unsigned n, size_t *len)
{
	uint8_t *f = calloc((size_t)n + 4u, 64u);
	size_t at, i, data;

	if (!f)
		return NULL;
	memcpy(f, "MSCF", 4);
	le16(f + 24, 0x0301u);
	le16(f + 26, 1);
	le16(f + 28, n);
	at = 36u + 8u;
	le32(f + 16, 36u + 8u);
	for (i = 0; i < n; i++) {
		char name[16];
		size_t nl = (size_t)snprintf(name, sizeof name, "c%05u", (unsigned)i) + 1u;

		le32(f + at, 8);
		le32(f + at + 4, (uint32_t)(i * 8u));
		le16(f + at + 8, 0);
		le16(f + at + 14, 0x20u);
		memcpy(f + at + 16, name, nl);
		at += 16u + nl;
	}
	data = at;
	le32(f + 36, (uint32_t)data);
	le16(f + 36 + 4, 1);
	le16(f + 36 + 6, KOF_CAB_C_NONE);
	le16(f + at + 4, (uint16_t)(n * 8u));
	le16(f + at + 6, (uint16_t)(n * 8u));
	at += 8u;
	for (i = 0; i < n; i++) {
		body8(f + at, (unsigned)i, n);
		at += 8u;
	}
	le32(f + 8, (uint32_t)at);
	*len = at;
	return f;
}

/* ---- chm: N entries over as many directory chunks as it takes ---------------- */

#define CHM_CHUNK 4096u

static uint8_t *build_chm(unsigned n, size_t *len)
{
	const uint32_t itsf = 0x60u, itsp = 0x54u;
	size_t dir_at = itsf + itsp, nchunk = 1, cap = (size_t)n * 24u + 65536u;
	uint8_t *f = calloc(1, cap + (size_t)n * 8u), *dir, *at;
	size_t content_at, i;

	if (!f)
		return NULL;
	dir = f + dir_at;
	memcpy(dir, "PMGL", 4);
	at = dir + 0x14u;
	for (i = 0; i < n; i++) {
		uint8_t tmp[64];
		char name[16];
		uint32_t en;

		snprintf(name, sizeof name, "/p%05u", (unsigned)i);
		en = put_entry(tmp, name, 0, i * 8u, 8u);
		if ((size_t)(at - dir) + en > CHM_CHUNK) {
			le32(dir + 4, (uint32_t)(CHM_CHUNK - (size_t)(at - dir)));
			dir += CHM_CHUNK;
			nchunk++;
			memcpy(dir, "PMGL", 4);
			at = dir + 0x14u;
		}
		memcpy(at, tmp, en);
		at += en;
	}
	le32(dir + 4, (uint32_t)(CHM_CHUNK - (size_t)(at - dir)));
	content_at = dir_at + nchunk * CHM_CHUNK;

	memcpy(f, "ITSF", 4);
	le32(f + 4, 3);
	le32(f + 8, itsf);
	le32(f + 20, 0x409u);
	le32(f + 56, itsf);
	le32(f + 64, 0x18u);
	le32(f + 72, itsf);
	le32(f + 80, itsp);
	le32(f + 88, (uint32_t)content_at);
	memcpy(f + itsf, "ITSP", 4);
	le32(f + itsf + 4, 1);
	le32(f + itsf + 8, itsp);
	le32(f + itsf + 16, CHM_CHUNK);
	le32(f + itsf + 44, (uint32_t)nchunk);
	for (i = 0; i < n; i++) {
		body8(f + content_at + i * 8u, (unsigned)i, n);
	}
	*len = content_at + (size_t)n * 8u;
	return f;
}


/* ---- 7z: N folders, each one LZMA2 stream holding one uncompressed chunk ------ */

static uint8_t *build_7z(unsigned n, size_t *len)
{
	uint8_t *f = calloc(1, 64u + (size_t)n * 40u);
	size_t at = 32, hdr, i;

	if (!f || n > 120u) {
		free(f);
		return NULL;
	}
	memcpy(f, "7z\xbc\xaf\x27\x1c", 6);
	f[7] = 4;
	for (i = 0; i < n; i++) {                          /* the packed streams */
		f[at++] = 0x01; f[at++] = 0x00; f[at++] = 0x07;
		body8(f + at, (unsigned)i, n);
		at += 8;
		f[at++] = 0x00;
	}
	hdr = at;
	f[at++] = 0x01;                                    /* Header */
	f[at++] = 0x04;                                    /* MainStreamsInfo */
	f[at++] = 0x06; f[at++] = 0x00; f[at++] = (uint8_t)n;   /* PackInfo */
	f[at++] = 0x09;
	for (i = 0; i < n; i++)
		f[at++] = 12;
	f[at++] = 0x00;
	f[at++] = 0x07; f[at++] = 0x0b; f[at++] = (uint8_t)n; f[at++] = 0x00;
	for (i = 0; i < n; i++) {                          /* one LZMA2 coder each */
		f[at++] = 0x01; f[at++] = 0x21; f[at++] = 0x21;
		f[at++] = 0x01; f[at++] = 0x18;
	}
	f[at++] = 0x0c;
	for (i = 0; i < n; i++)
		f[at++] = 8;
	f[at++] = 0x00;
	f[at++] = 0x00;                                    /* end of streams */
	f[at++] = 0x00;                                    /* end of header */
	le32(f + 12, (uint32_t)(hdr - 32u));
	f[19] = 0;
	le32(f + 20, (uint32_t)(at - hdr));
	*len = at;
	return f;
}


/* ---- pdf: N objects, each a stream of eight bytes ---------------------------- */

static uint8_t *build_pdf(unsigned n, size_t *len)
{
	uint8_t *f = calloc((size_t)n + 4u, 96u);
	size_t at = 0;
	unsigned i;

	if (!f)
		return NULL;
	at += (size_t)sprintf((char *)f, "%%PDF-1.4\n");
	for (i = 1; i <= n; i++) {
		at += (size_t)sprintf((char *)f + at,
				      "%u 0 obj\n<< /Length 8 >>\nstream\n", i);
		body8(f + at, i - 1u, n);
		at += 8;
		at += (size_t)sprintf((char *)f + at, "\nendstream\nendobj\n");
	}
	at += (size_t)sprintf((char *)f + at,
			      "trailer\n<< /Size %u /Root 1 0 R >>\nstartxref\n0\n%%%%EOF\n", n + 1u);
	*len = at;
	return f;
}


/* ---- the interpreter's ceiling: KOF_SCAN_EMU_MAX ----------------------------- */

static const uint8_t stager[] = {
	0x31,0xff,0x6a,0x09,0x58,0x99,0xb6,0x10,0x48,0x89,0xd6,0x4d,0x31,0xc9,
	0x6a,0x22,0x41,0x5a,0x6a,0x07,0x5a,0x0f,0x05,0x48,0x85,0xc0,0x78,0x51,
	0x6a,0x0a,0x41,0x59,0x50,0x6a,0x29,0x58,0x99,0x6a,0x02,0x5f,0x6a,0x01,
	0x5e,0x0f,0x05,0x48,0x85,0xc0,0x78,0x3b,0x48,0x97,0x48,0xb9,0x02,0x00
};

/* One RWX PT_LOAD ELF64 over `stager`: the shape a rule asks the interpreter for. */
static uint64_t shell_elf(uint8_t *f)
{
	const uint64_t base = 0x400000, off = 0x78, len = off + sizeof stager;
	unsigned i;

	memset(f, 0, 512);
	memcpy(f, "\177ELF\2\1\1", 7);
	f[0x10] = 2; f[0x12] = 0x3e; f[0x14] = 1;
	for (i = 0; i < 8; i++)
		f[0x18 + i] = (uint8_t)((base + off) >> (i * 8));
	f[0x20] = 64; f[0x34] = 64; f[0x36] = 56; f[0x38] = 1; f[0x3a] = 64;
	f[64] = 1; f[68] = 7;
	for (i = 0; i < 8; i++) {
		f[64 + 0x10 + i] = (uint8_t)(base >> (i * 8));
		f[64 + 0x18 + i] = (uint8_t)(base >> (i * 8));
		f[64 + 0x20 + i] = (uint8_t)(len >> (i * 8));
		f[64 + 0x28 + i] = (uint8_t)(len >> (i * 8));
	}
	f[64 + 0x30] = 0x10;
	memcpy(f + off, stager, sizeof stager);
	return len;
}


/* The instruction budget: a stub that never finishes. */
static void case_emu_budget(void)
{
	static uint8_t f[512];
	static const uint8_t spin[] = { 0x48, 0xff, 0xc0, 0xeb, 0xfb };   /* inc rax; jmp -5 */
	uint64_t len = shell_elf(f);
	const struct kof_stats *st;
	uint64_t before;
	struct seen s;

	memcpy(f + 0x78, spin, sizeof spin);
	st = kscan_stats(sc);
	before = st->heur_emu;
	scan(f, len, "spin.elf", &s);
	st = kscan_stats(sc);
	printf("  emu budget: ran=%llu objs=%u broken=%u finds=%u\n",
	       (unsigned long long)(st->heur_emu - before), s.objs, s.broken, s.finds);
	/* The stub ran (the fixture is sound) and was cut by the budget: said. */
	CK(st->heur_emu - before == 1u);
	CK(held(&s));
}

static void case_emu_ceiling(void)
{
	static uint8_t f[512];
	uint64_t len = shell_elf(f), asked_at_first = 0, last = 0, stuck_from = 0;
	unsigned i, sig_after = 0;
	struct seen s;

	for (i = 0; i < KOF_SCAN_EMU_MAX + 40u; i++) {
		const struct kof_stats *st;
		uint64_t before;

		st = kscan_stats(sc);
		before = st->heur_emu;
		scan(f, len, "shell.elf", &s);
		st = kscan_stats(sc);
		if (i == 0)
			asked_at_first = st->heur_emu - before;
		last = st->heur_emu;
		if (!stuck_from && i && st->heur_emu == before)
			stuck_from = i;
		if (stuck_from && (s.broken || s.finds))
			sig_after++;
	}
	printf("  emu ceiling: first scan asked=%llu, heur_emu=%llu after %u scans, "
	       "stopped advancing at scan %llu, signal after that=%u\n",
	       (unsigned long long)asked_at_first, (unsigned long long)last,
	       KOF_SCAN_EMU_MAX + 40u, (unsigned long long)stuck_from, sig_after);
	CK(asked_at_first == 1u);
	/* The ceiling is per TREE, not per scanner lifetime: the same object scanned
	 * 552 times is 552 trees, and every one of them still asks. */
	CK(stuck_from == 0);
	CK(last >= KOF_SCAN_EMU_MAX + 40u);
}

/* A tree of more members than it may interpret: the ones past the allowance are
 * refused AND SAID - broken=LIMIT on them, and the scanner's counter moves. */
static void case_emu_tree(void)
{
	enum { N = KOF_SCAN_EMU_MAX + 88 };
	static uint8_t elf[512];
	size_t at = 0, len;
	unsigned i, k;
	uint8_t *f = calloc((size_t)N + 2u, 1024u);
	const struct kof_stats *st;
	uint64_t emu0, lim0;
	struct seen s;

	CK(f != NULL);
	if (!f)
		return;
	(void)shell_elf(elf);
	for (i = 0; i < N; i++) {
		uint8_t *h = f + at;
		unsigned sum = 0;

		snprintf((char *)h, 100, "e%05u", i);
		memcpy(h + 100, "0000644", 8);
		memcpy(h + 108, "0000000", 8);
		memcpy(h + 116, "0000000", 8);
		memcpy(h + 124, "00000000262", 12);      /* 178 bytes */
		memcpy(h + 136, "00000000000", 12);
		memset(h + 148, ' ', 8);
		h[156] = '0';
		memcpy(h + 257, "ustar", 6);
		memcpy(h + 263, "00", 2);
		for (k = 0; k < 512; k++)
			sum += h[k];
		snprintf((char *)h + 148, 8, "%06o", sum);
		h[155] = ' ';
		/* distinct members: the ident padding differs, nothing else does */
		elf[9] = (uint8_t)i;
		elf[10] = (uint8_t)(i >> 8);
		memcpy(f + at + 512, elf, 512);
		at += 1024u;
	}
	len = at + 1024u;
	st = kscan_stats(sc);
	emu0 = st->heur_emu;
	lim0 = st->limit_hits;
	scan(f, len, "many.tar", &s);
	st = kscan_stats(sc);
	printf("  emu tree: %u members, interpreted=%llu, limit_hits=%llu, broken=%u (why %u)\n",
	       (unsigned)N, (unsigned long long)(st->heur_emu - emu0),
	       (unsigned long long)(st->limit_hits - lim0), s.broken, s.first_why);
	/* the tree's allowance is spent exactly, and the refusals are counted and seen */
	CK(st->heur_emu - emu0 == KOF_SCAN_EMU_MAX);
	CK(st->limit_hits > lim0);
	CK(s.broken >= 1u);
	free(f);
}


/* ---- cab: F folders of one file each ------------------------------------------ */

static uint8_t *build_cab_folders(unsigned n, size_t *len)
{
	uint8_t *f = calloc((size_t)n + 4u, 64u);
	size_t at, i;

	if (!f)
		return NULL;
	memcpy(f, "MSCF", 4);
	le16(f + 24, 0x0301u);
	le16(f + 26, n);
	le16(f + 28, n);
	at = 36u + (size_t)n * 8u;
	le32(f + 16, (uint32_t)at);
	for (i = 0; i < n; i++) {
		char name[16];
		size_t nl = (size_t)snprintf(name, sizeof name, "c%05u", (unsigned)i) + 1u;

		le32(f + at, 8);
		le32(f + at + 4, 0);
		le16(f + at + 8, (uint16_t)i);
		le16(f + at + 14, 0x20u);
		memcpy(f + at + 16, name, nl);
		at += 16u + nl;
	}
	for (i = 0; i < n; i++) {                       /* one stored block per folder */
		le32(f + 36 + i * 8u, (uint32_t)at);
		le16(f + 36 + i * 8u + 4u, 1);
		le16(f + 36 + i * 8u + 6u, KOF_CAB_C_NONE);
		le16(f + at + 4, 8);
		le16(f + at + 6, 8);
		body8(f + at + 8, (unsigned)i, n);
		at += 16u;
	}
	le32(f + 8, (uint32_t)at);
	*len = at;
	return f;
}

/* ---- cab: N files in one folder cut into 12 byte blocks ------------------------ */

static uint8_t *build_cab_runs(unsigned n, size_t *len)
{
	size_t total, nb, at, i;
	uint8_t *f, *d;

	n += (2u + 3u - n % 3u) % 3u;   /* the last file starts at 8 mod 12: it crosses */
	total = (size_t)n * 8u;
	nb = (total + 11u) / 12u;
	f = calloc((size_t)n + nb + 8u, 64u);
	d = calloc(1, total + 16u);

	if (!f || !d) {
		free(f);
		free(d);
		return NULL;
	}
	for (i = 0; i < n; i++)
		body8(d + i * 8u, (unsigned)i, n);
	memcpy(f, "MSCF", 4);
	le16(f + 24, 0x0301u);
	le16(f + 26, 1);
	le16(f + 28, n);
	at = 44u;
	le32(f + 16, 44u);
	for (i = 0; i < n; i++) {
		char name[16];
		size_t nl = (size_t)snprintf(name, sizeof name, "c%05u", (unsigned)i) + 1u;

		le32(f + at, 8);
		le32(f + at + 4, (uint32_t)(i * 8u));
		le16(f + at + 14, 0x20u);
		memcpy(f + at + 16, name, nl);
		at += 16u + nl;
	}
	le32(f + 36, (uint32_t)at);
	le16(f + 40, (uint16_t)nb);
	le16(f + 42, KOF_CAB_C_NONE);
	for (i = 0; i < nb; i++) {
		size_t take = total - i * 12u < 12u ? total - i * 12u : 12u;

		le16(f + at + 4, (uint16_t)take);
		le16(f + at + 6, (uint16_t)take);
		memcpy(f + at + 8, d + i * 12u, take);
		at += 8u + take;
	}
	le32(f + 8, (uint32_t)at);
	free(d);
	*len = at;
	return f;
}

/* ---- chm: a name longer than KOF_CHM_MAX_NAME ahead of the marker --------------- */

static uint8_t *build_chm_longname(unsigned n, size_t *len)
{
	const uint32_t itsf = 0x60u, itsp = 0x54u;
	size_t dir_at = itsf + itsp, content_at = dir_at + CHM_CHUNK, i;
	uint8_t *f = calloc(1, content_at + 64u + (size_t)n * 8u), *dir, *at;
	char longname[1200];

	if (!f)
		return NULL;
	memset(longname, 'n', sizeof longname - 1u);
	longname[0] = '/';
	longname[sizeof longname - 1u] = 0;
	dir = f + dir_at;
	memcpy(dir, "PMGL", 4);
	at = dir + 0x14u;
	for (i = 0; i < 3; i++) {                       /* ok, too long, marker */
		char name[16];

		snprintf(name, sizeof name, "/p%05u", (unsigned)i);
		at += put_entry(at, i == 1 ? longname : name, 0, i * 8u, 8u);
	}
	le32(dir + 4, (uint32_t)(CHM_CHUNK - (size_t)(at - dir)));
	memcpy(f, "ITSF", 4);
	le32(f + 4, 3); le32(f + 8, itsf); le32(f + 20, 0x409u);
	le32(f + 56, itsf); le32(f + 64, 0x18u);
	le32(f + 72, itsf); le32(f + 80, itsp);
	le32(f + 88, (uint32_t)content_at);
	memcpy(f + itsf, "ITSP", 4);
	le32(f + itsf + 4, 1); le32(f + itsf + 8, itsp);
	le32(f + itsf + 16, CHM_CHUNK); le32(f + itsf + 44, 1);
	for (i = 0; i < 3; i++)
		body8(f + content_at + i * 8u, (unsigned)i, 3);
	(void)n;
	*len = content_at + 24u;
	return f;
}


/* ---- rtf: N embedded objects ------------------------------------------------- */

static uint8_t *build_rtf(unsigned n, size_t *len)
{
	uint8_t *f = calloc((size_t)n + 4u, 96u);
	size_t at;
	unsigned i, k;

	if (!f)
		return NULL;
	at = (size_t)sprintf((char *)f, "{\\rtf1\\ansi\n");
	for (i = 0; i < n; i++) {
		uint8_t b[8];

		body8(b, i, n);
		at += (size_t)sprintf((char *)f + at, "{\\object\\objemb{\\*\\objdata ");
		for (k = 0; k < 8; k++)
			at += (size_t)sprintf((char *)f + at, "%02x", (unsigned)b[k]);
		at += (size_t)sprintf((char *)f + at, "}}\n");
	}
	f[at++] = '}';
	*len = at;
	return f;
}

struct cont {
	const char *name;
	uint8_t *(*build)(unsigned n, size_t *len);
	unsigned cap;
};

/*
 * One container, N = cap + `over` members, the marker in the last one.
 * `lost` is 1 while the engine loses the marker silently, 0 when something says so,
 * and 2 when that is also counted in kof_stats.limit_hits.
 */
static void over_cap(const struct cont *c, unsigned over, int lost, const char *cap)
{
	size_t len;
	uint8_t *f = c->build(c->cap + over, &len);
	struct seen s;
	char what[160];
	uint64_t hits0 = kscan_stats(sc)->limit_hits;

	CK(f != NULL);
	if (!f)
		return;
	scan(f, len, c->name, &s);
	if (lost == 2)          /* said through the scanner's own counter as well */
		CK(kscan_stats(sc)->limit_hits > hits0);
	printf("  %s: n=%u objs=%u marker=%u broken=%u(why %u) finds=%u anom=%u\n", c->name,
	       c->cap + over, s.objs, s.marker, s.broken, s.first_why, s.finds, s.anom);
	snprintf(what, sizeof what, "%s: the marker member past the cap is neither opened nor flagged", c->name);
	if (lost == 1)
		KM_CHECK(held(&s), what, cap);
	else
		CK(held(&s));
	free(f);
}

/* Under the cap, the marker is found: the fixture itself is sound. */
static void under_cap(const struct cont *c, unsigned n)
{
	size_t len;
	uint8_t *f = c->build(n, &len);
	struct seen s;

	CK(f != NULL);
	if (!f)
		return;
	scan(f, len, c->name, &s);
	if (!s.marker)
		printf("  %s: n=%u marker not found, objs=%u\n", c->name, n, s.objs);
	CK(s.marker == 1u);
	free(f);
}

/* kof_scan_option.max_children: the caller's own bound has to say it bound. */
static void case_max_children(void)
{
	size_t len;
	uint8_t *f = build_tar(300, &len);
	struct kof_scan_option opt;
	struct seen s;

	CK(f != NULL);
	if (!f)
		return;
	memset(&s, 0, sizeof s);
	memset(&opt, 0, sizeof opt);
	opt.max_children = 100;
	opt.max_produced_bytes = 64u << 20;
	opt.max_resident_bytes = 256u << 20;
	opt.max_object_bytes = 64u << 20;
	(void)kscan_bytes(sc, f, len, "kids.tar", &opt, on_object, &s);
	printf("  max_children=100: objs=%u marker=%u broken=%u\n", s.objs, s.marker, s.broken);
	CK(s.objs <= 101u);
	CK(held(&s));
	free(f);
}

static void case_containers(void)
{
	/* zip and pdf had fixed tables (4096 entries; 4096 objects and 1024 streams): past
	 * those sizes they are now OPENED WHOLE, which is what under_cap asserts below. */
	static const struct cont zip  = { "zip", build_zip, 4096u };
	static const struct cont tar  = { "tar", build_tar, 2048u };
	static const struct cont arj  = { "arj", build_arj, 1024u };
	static const struct cont lha  = { "lha", build_lha, 1024u };
	static const struct cont cab  = { "cab", build_cab, 2048u };
	static const struct cont chm  = { "chm", build_chm, 2048u };
	static const struct cont sz   = { "7z", build_7z, 64u };
	static const struct cont pdf  = { "pdf", build_pdf, 4096u };
	static const struct cont pdfs = { "pdf-streams", build_pdf, 1024u };
	static const struct cont cabf = { "cab-folders", build_cab_folders, 256u };
	static const struct cont cabr = { "cab-runs", build_cab_runs, 1800u };
	static const struct cont rtf  = { "rtf", build_rtf, KOF_RTF_MAX_OBJECTS };
	static const struct cont chmn = { "chm-name", build_chm_longname, 0u };

	/* the fixtures are sound below their caps */
	under_cap(&zip, 1000);
	under_cap(&tar, 1000);
	under_cap(&arj, 500);
	under_cap(&lha, 500);
	under_cap(&cab, 1000);
	under_cap(&chm, 1000);
	under_cap(&sz, 32);
	under_cap(&pdf, 1000);
	under_cap(&zip, 4096u + 40u);     /* the old caps, and past them: the marker member is opened */
	under_cap(&pdf, 4096u + 40u);
	under_cap(&pdfs, 1024u + 40u);
	under_cap(&cabf, 100);
	under_cap(&cabr, 600);
	under_cap(&rtf, 100);

	/*
	 * THE OLD CAPS OF THE OTHER EIGHT FORMATS, AND PAST THEM: tar, arj, lha, cab (files, folders
	 * and the piece pool), chm (entries and a name past 1024 bytes) and 7z (folders) had tables of
	 * a size chosen in advance, and the member past each was reported. They are tables the size of
	 * the file now, so the marker member past the old cap is OPENED - what under_cap asserts. (What
	 * is still bound, by the ledger and the file's own length, reports with the format's full bit;
	 * tests/unit/view_tables_arch.c drives that.)
	 */
	under_cap(&tar, 2048u + 40u);
	under_cap(&arj, 1024u + 40u);
	under_cap(&lha, 1024u + 40u);
	under_cap(&cab, 2048u + 40u);
	under_cap(&chm, 2048u + 40u);
	under_cap(&sz, 64u + 40u);
	under_cap(&cabf, 256u + 40u);
	under_cap(&cabr, 1800u + 40u);
	under_cap(&chmn, 0u);
	over_cap(&rtf, 40, 0, "");     /* rtf.c: OBJECTS_FULL -> KOF_UNP_LIMIT            */
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : ad_db_asking();

	eng = keng_open(db);
	if (!eng) {
		printf("silent_loss_scan: no database at %s - nothing tested\n", db);
		return 0;
	}
	sc = notes_scanner(eng);
	if (!sc)
		return 1;
	case_containers();
	case_max_children();
	case_emu_budget();
	case_emu_ceiling();
	case_emu_tree();
	kscan_free(sc);
	keng_close(eng);
	return fails != 0 || km_failed();
}
