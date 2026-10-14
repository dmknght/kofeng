/*
 * arch_fixtures.h - archives of tar, lha, arj, cab, chm, docole, rar and 7z with N members of eight
 * bytes, the last holding the marker, and hostile variants of each, for the tests of the views of
 * those formats (view_tables_arch.c, view_oldpack.c). Built by hand from the formats' own layouts,
 * so no external tool decides whether a test passes. Static functions: include it, do not link it.
 */
#ifndef KOFENG_TESTS_ARCH_FIXTURES_H
#define KOFENG_TESTS_ARCH_FIXTURES_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <kofmod/cab.h>

#define MARKER "KOFMARK!"

static __attribute__((unused)) void le16(uint8_t *p, unsigned v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static __attribute__((unused)) void le32(uint8_t *p, uint32_t v) { le16(p, v & 0xffffu); le16(p + 2, v >> 16); }
static __attribute__((unused)) void le64(uint8_t *p, uint64_t v) { le32(p, (uint32_t)v); le32(p + 4, (uint32_t)(v >> 32)); }

/* eight bytes that are the member's content: the marker in the last one */
static __attribute__((unused)) void body8(uint8_t *b, unsigned i, unsigned n)
{
	char t[16];

	if (i + 1u == n) {
		memcpy(b, MARKER, 8);
		return;
	}
	snprintf(t, sizeof t, "KOF%04u", i % 10000u);
	memcpy(b, t, 8);
}

/* ---- the fixtures -------------------------------------------------------------------------------
 *
 * Each builder makes `n` members of eight bytes, the last holding the marker. `kind` 0 is the clean
 * archive; the others are hostile and are the same for every format only where it says (1: the clean
 * archive cut at three sevenths); `rows` is what a clean parse must list. */

enum { K_CLEAN = 0, K_CUT = 1, K_CLAIM = 2, K_SHARED = 3, K_LOOP = 4 };

struct made {
	uint8_t *p;
	size_t len;
	unsigned rows;     /* rows a clean parse lists */
	unsigned kids;     /* children the engine opens of a clean archive */
};

/* ---- tar ---------------------------------------------------------------------------------------- */

static struct made b_tar(unsigned n, int kind)
{
	struct made m = { calloc((size_t)n + 2u, 1024u), 0, n, n };
	size_t at = 0, k;
	unsigned i;

	if (!m.p)
		return m;
	for (i = 0; i < n; i++) {
		uint8_t *h = m.p + at;
		unsigned sum = 0;

		snprintf((char *)h, 100, "t%05u", i);
		memcpy(h + 100, "0000644", 8);
		memcpy(h + 108, "0000000", 8);
		memcpy(h + 116, "0000000", 8);
		/* K_CLAIM: every member says it is 2^35 bytes long: the content is past the object and
		 * the walk has to advance and end all the same */
		memcpy(h + 124, kind == K_CLAIM ? "00400000000" : "00000000010", 12);
		memcpy(h + 136, "00000000000", 12);
		memset(h + 148, ' ', 8);
		h[156] = '0';
		memcpy(h + 257, "ustar", 6);
		memcpy(h + 263, "00", 2);
		for (k = 0; k < 512; k++)
			sum += h[k];
		snprintf((char *)h + 148, 8, "%06o", sum);
		h[155] = ' ';
		body8(m.p + at + 512, i, n);
		at += 1024u;
	}
	m.len = at + 1024u;
	if (kind == K_CUT)
		m.len = m.len * 3u / 7u;
	if (kind == K_CLAIM)
		m.rows = n;
	return m;
}

/* ---- lha ---------------------------------------------------------------------------------------- */

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

static struct made b_lha(unsigned n, int kind)
{
	struct made m = { calloc((size_t)n + 4u, 64u), 0, n, n };
	size_t at = 0;
	unsigned i;

	if (!m.p)
		return m;
	for (i = 0; i < n; i++) {
		char name[16];
		uint8_t body[8];

		snprintf(name, sizeof name, "l%05u", i);
		body8(body, i, n);
		{
			size_t hs = at;

			at += lha_hdr(m.p + at, name, body, 8);
			if (kind == K_CLAIM)       /* the body says it is 4 GB long: the chain ends there */
				le32(m.p + hs + 7, 0xfffffff0u);
		}
	}
	m.p[at++] = 0;
	m.len = kind == K_CUT ? at * 3u / 7u : at;
	if (kind == K_CLAIM)
		m.rows = 0;                /* nothing is checked of the rows: the claim stops the walk at the first */
	return m;
}

/* ---- arj ---------------------------------------------------------------------------------------- */

static uint32_t arj_hdr(uint8_t *p, uint8_t ftype, const char *name, const uint8_t *body, uint32_t blen,
			uint32_t claim)
{
	uint32_t nl = (uint32_t)strlen(name) + 1u, basic = 30u + nl + 1u, at;

	p[0] = 0x60u; p[1] = 0xeau;
	le16(p + 2, basic);
	p[4] = 30; p[5] = 11; p[6] = 1; p[7] = 2;
	p[8] = 0; p[9] = 0; p[10] = ftype;
	le32(p + 16, claim ? claim : blen);
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

static struct made b_arj(unsigned n, int kind)
{
	struct made m = { calloc((size_t)n + 4u, 96u), 0, n, n };
	size_t at;
	unsigned i;

	if (!m.p)
		return m;
	at = arj_hdr(m.p, 2, "a.arj", NULL, 0, 0);
	for (i = 0; i < n; i++) {
		char name[16];
		uint8_t body[8];

		snprintf(name, sizeof name, "a%05u", i);
		body8(body, i, n);
		at += arj_hdr(m.p + at, 0, name, body, 8, kind == K_CLAIM ? 0xfffffff0u : 0);
	}
	m.p[at] = 0x60u; m.p[at + 1u] = 0xeau;
	at += 4u;
	m.len = kind == K_CUT ? at * 3u / 7u : at;
	if (kind == K_CLAIM)
		m.rows = 0;
	return m;
}

/* ---- cab: n files in a stored folder of 8192 byte blocks ---------------------------------------- */

#define CAB_BLK 8192u

static struct made b_cab(unsigned n, int kind)
{
	size_t blocks = ((size_t)n * 8u + CAB_BLK - 1u) / CAB_BLK;
	/* K_SHARED: as many folders as files, every one naming the first block chain */
	unsigned nfold = kind == K_SHARED ? (n > 65535u ? 65535u : n) : 1u;
	struct made m = { calloc(1, (size_t)n * 40u + blocks * 16u + (size_t)nfold * 8u + (size_t)n * 8u + 4096u), 0, n, n };
	size_t at, i, data_at, fold_at = 36u;
	uint8_t *f = m.p;

	if (!f)
		return m;
	memcpy(f, "MSCF", 4);
	le16(f + 24, 0x0301u);
	le16(f + 26, kind == K_CLAIM ? 0xffffu : nfold);
	le16(f + 28, kind == K_CLAIM ? 0xffffu : n > 65535u ? 65535u : n);
	at = fold_at + (size_t)nfold * 8u;
	le32(f + 16, (uint32_t)at);
	for (i = 0; i < (n > 65535u ? 65535u : n); i++) {
		char name[16];
		size_t nl = (size_t)snprintf(name, sizeof name, "c%05u", (unsigned)i) + 1u;

		le32(f + at, 8);
		le32(f + at + 4, (uint32_t)(i * 8u));
		le16(f + at + 8, kind == K_SHARED ? (unsigned)i : 0u);
		le16(f + at + 14, 0x20u);
		memcpy(f + at + 16, name, nl);
		at += 16u + nl;
	}
	data_at = at;
	for (i = 0; i < nfold; i++) {
		le32(f + fold_at + i * 8u, (uint32_t)data_at);
		le16(f + fold_at + i * 8u + 4u, (unsigned)blocks > 65535u ? 65535u : (unsigned)blocks);
		le16(f + fold_at + i * 8u + 6u, KOF_CAB_C_NONE);
	}
	for (i = 0; i < blocks; i++) {
		size_t take = (size_t)n * 8u - i * CAB_BLK;

		if (take > CAB_BLK)
			take = CAB_BLK;
		le16(f + at + 4, (unsigned)take);
		le16(f + at + 6, (unsigned)take);
		at += 8u;
		{
			size_t k;

			for (k = 0; k < take / 8u; k++)
				body8(f + at + k * 8u, (unsigned)(i * (CAB_BLK / 8u) + k), n);
		}
		at += take;
	}
	le32(f + 8, (uint32_t)at);
	m.len = kind == K_CUT ? at * 3u / 7u : at;
	if (n > 65535u) {
		m.rows = 65535u;               /* a cabinet counts its files in sixteen bits */
		m.kids = 65535u;
	}
	if (kind == K_CLAIM)
		m.rows = 0;
	return m;
}

/* ---- chm: n entries over as many directory chunks as it takes ----------------------------------- */

#define CHM_CHUNK 4096u

static uint32_t chm_entry(uint8_t *p, const char *name, uint32_t sect, uint32_t off, uint32_t len)
{
	uint32_t nl = (uint32_t)strlen(name), at = 0;

	p[at++] = (uint8_t)nl;                  /* every number below 128: one byte */
	memcpy(p + at, name, nl);
	at += nl;
	p[at++] = (uint8_t)sect;
	/* offsets run past 127: encode seven bits a byte, high group first */
	if (off >= 1u << 14) { p[at++] = (uint8_t)(0x80u | (off >> 14)); p[at++] = (uint8_t)(0x80u | ((off >> 7) & 0x7fu)); p[at++] = (uint8_t)(off & 0x7fu); }
	else if (off >= 128u) { p[at++] = (uint8_t)(0x80u | (off >> 7)); p[at++] = (uint8_t)(off & 0x7fu); }
	else p[at++] = (uint8_t)off;
	p[at++] = (uint8_t)len;
	return at;
}

static struct made b_chm(unsigned n, int kind)
{
	const uint32_t itsf = 0x60u, itsp = 0x54u;
	size_t dir_at = itsf + itsp, nchunk = 1, cap = (size_t)n * 24u + 65536u;
	struct made m = { calloc(1, cap + (size_t)n * 8u), 0, n, n };
	uint8_t *f = m.p, *dir, *at;
	size_t content_at, i;

	if (!f)
		return m;
	dir = f + dir_at;
	memcpy(dir, "PMGL", 4);
	at = dir + 0x14u;
	for (i = 0; i < n; i++) {
		uint8_t tmp[64];
		char name[16];
		uint32_t en;

		snprintf(name, sizeof name, "/p%05u", (unsigned)i);
		en = chm_entry(tmp, name, 0, (uint32_t)(i * 8u), 8u);
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
	/* K_CLAIM: four billion chunks, from a header that holds a handful */
	le32(f + itsf + 44, kind == K_CLAIM ? 0xffffffffu : (uint32_t)nchunk);
	for (i = 0; i < n; i++)
		body8(f + content_at + i * 8u, (unsigned)i, n);
	m.len = content_at + (size_t)n * 8u;
	if (kind == K_CUT)
		m.len = m.len * 3u / 7u;
	return m;
}

/* ---- 7z: n folders, each one LZMA2 stream holding one uncompressed chunk -------------------------- */

static size_t sz_num(uint8_t *p, uint64_t v)
{
	size_t k = 0;
	unsigned i;

	if (v < 0x80u) {
		p[0] = (uint8_t)v;
		return 1;
	}
	/* the first byte's leading ones say how many bytes follow; eight bytes cover any 64 bit value */
	for (i = 1; i < 8u; i++)
		if (v < (1ull << (7u * (i + 1u)))) {
			p[0] = (uint8_t)(0xffu << (8u - i));
			p[0] = (uint8_t)(p[0] | (uint8_t)(v >> (8u * i)));
			for (k = 0; k < i; k++)
				p[1 + k] = (uint8_t)(v >> (8u * k));
			return 1 + i;
		}
	p[0] = 0xff;
	for (k = 0; k < 8; k++)
		p[1 + k] = (uint8_t)(v >> (8u * k));
	return 9;
}

static struct made b_7z(unsigned n, int kind)
{
	struct made m = { calloc(1, 4096u + (size_t)n * 40u), 0, n, n };
	uint8_t *f = m.p;
	size_t at = 32, hdr, i;
	uint64_t claim = kind == K_CLAIM ? (1ull << 40) : (uint64_t)n;

	if (!f)
		return m;
	memcpy(f, "7z\xbc\xaf\x27\x1c", 6);
	f[7] = 4;
	for (i = 0; i < n; i++) {                          /* the packed streams: one stored LZMA2 chunk each */
		f[at++] = 0x01; f[at++] = 0x00; f[at++] = 0x07;
		body8(f + at, (unsigned)i, n);
		at += 8;
		f[at++] = 0x00;
	}
	hdr = at;
	f[at++] = 0x01;                                    /* Header */
	f[at++] = 0x04;                                    /* MainStreamsInfo */
	f[at++] = 0x06; f[at++] = 0x00;                    /* PackInfo: packPos 0 */
	at += sz_num(f + at, claim);
	f[at++] = 0x09;
	for (i = 0; i < n; i++)
		f[at++] = 12;
	f[at++] = 0x00;
	f[at++] = 0x07; f[at++] = 0x0b;
	at += sz_num(f + at, claim);
	f[at++] = 0x00;
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
	m.len = kind == K_CUT ? at * 3u / 7u : at;
	if (kind == K_CLAIM)
		m.rows = 0;
	if (kind == K_CUT)
		m.rows = 0;
	return m;
}

/* ---- rar (3): a marker block, a main block, n stored files and an end block --------------------- */

static struct made b_rar(unsigned n, int kind)
{
	struct made m = { calloc((size_t)n + 4u, 64u), 0, n, n };
	uint8_t *f = m.p;
	size_t at = 0;
	unsigned i;

	if (!f)
		return m;
	memcpy(f, "Rar!\x1a\x07\x00", 7);
	at = 7;
	f[at + 2] = 0x73;                                  /* main block, 13 bytes */
	le16(f + at + 5, 13);
	at += 13;
	for (i = 0; i < n; i++) {
		char name[16];
		unsigned nl = (unsigned)snprintf(name, sizeof name, "r%05u", i);
		uint8_t *h = f + at;

		h[2] = 0x74;
		le16(h + 3, 0x8000u);
		le16(h + 5, 32u + nl);
		le32(h + 7, kind == K_CLAIM ? 0xfffffff0u : 8u);   /* PACK_SIZE */
		le32(h + 11, 8u);                                   /* UNP_SIZE */
		h[25] = 0x30;                                       /* stored */
		le16(h + 26, nl);
		memcpy(h + 32, name, nl);
		body8(h + 32u + nl, i, n);
		at += 32u + nl + 8u;
	}
	f[at + 2] = 0x7b;
	le16(f + at + 5, 7);
	at += 7;
	m.len = kind == K_CUT ? at * 3u / 7u : at;
	if (kind == K_CLAIM)
		m.rows = 0;
	return m;
}

/* ---- docole: a root, a storage "Macros" and n streams of eight bytes in the mini stream ---------- */

static void ole_name(uint8_t *e, const char *s)
{
	unsigned i, l = (unsigned)strlen(s);

	for (i = 0; i < l; i++)
		le16(e + 2u * i, (uint8_t)s[i]);
	le16(e + 0x40, 2u * l + 2u);
}

static struct made b_ole(unsigned n, int kind)
{
	unsigned ents = n + 2u, dsec = (ents + 3u) / 4u, msec = (n + 7u) / 8u, fm = (n + 127u) / 128u;
	unsigned fat = 1, total, i, s;
	struct made m = { NULL, 0, n, n };
	uint8_t *f;
	uint32_t *fatt;
	size_t cap;

	for (;;) {
		total = fat + fm + dsec + msec;
		if ((total + 127u) / 128u <= fat)
			break;
		fat++;
	}
	if (fat > 109u)
		return m;                       /* beyond what the header's own DIFAT holds */
	cap = ((size_t)total + 1u) * 512u;
	f = calloc(1, cap);
	if (!f)
		return m;
	m.p = f;
	m.len = cap;
	/* header */
	memcpy(f, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 8);
	le16(f + 0x18, 0x3e); le16(f + 0x1a, 3); le16(f + 0x1c, 0xfffeu);
	le16(f + 0x1e, 9); le16(f + 0x20, 6);
	le32(f + 0x2c, fat);
	le32(f + 0x30, fat + fm);                           /* directory start */
	le32(f + 0x38, 4096u);
	le32(f + 0x3c, fat);                                /* MiniFAT start */
	le32(f + 0x40, fm);
	le32(f + 0x44, 0xfffffffeu);
	for (i = 0; i < 109u; i++)
		le32(f + 0x4c + 4u * i, i < fat ? i : 0xffffffffu);
	/* the FAT */
	fatt = (uint32_t *)calloc((size_t)fat * 128u, 4u);
	if (!fatt) {
		free(f);
		m.p = NULL;
		return m;
	}
	for (i = 0; i < fat * 128u; i++)
		fatt[i] = 0xffffffffu;
	for (i = 0; i < fat; i++)
		fatt[i] = 0xfffffffdu;
	for (i = 0; i < fm; i++)
		fatt[fat + i] = i + 1u == fm ? 0xfffffffeu : fat + i + 1u;
	for (i = 0; i < dsec; i++) {
		unsigned sec = fat + fm + i;

		fatt[sec] = i + 1u == dsec ? 0xfffffffeu : sec + 1u;
		if (kind == K_LOOP && i + 1u == dsec)
			fatt[sec] = fat + fm;                /* the directory chain loops back to its start */
	}
	for (i = 0; i < msec; i++) {
		unsigned sec = fat + fm + dsec + i;

		fatt[sec] = i + 1u == msec ? 0xfffffffeu : sec + 1u;
	}
	for (s = 0; s < fat; s++)
		for (i = 0; i < 128u; i++)
			le32(f + ((size_t)s + 1u) * 512u + 4u * i, fatt[s * 128u + i]);
	free(fatt);
	/* the MiniFAT: one sector per stream */
	for (i = 0; i < n; i++)
		le32(f + ((size_t)fat + (i / 128u) + 1u) * 512u + 4u * (i % 128u), 0xfffffffeu);
	/* the directory */
	for (i = 0; i < ents; i++) {
		uint8_t *e = f + ((size_t)fat + fm + (i / 4u) + 1u) * 512u + 128u * (i % 4u);

		le32(e + 0x44, 0xffffffffu);
		le32(e + 0x48, 0xffffffffu);
		le32(e + 0x4c, 0xffffffffu);
		if (i == 0) {
			ole_name(e, "Root Entry");
			e[0x42] = 5;
			le32(e + 0x4c, 1);
			le32(e + 0x74, fat + fm + dsec);
			le64(e + 0x78, (uint64_t)n * 64u);
		} else if (i == 1) {
			ole_name(e, "Macros");
			e[0x42] = 1;
			le32(e + 0x4c, 2);
		} else {
			char name[16];

			snprintf(name, sizeof name, "s%05u", i - 2u);
			ole_name(e, name);
			e[0x42] = 2;
			le32(e + 0x48, i + 1u < ents ? i + 1u : (kind == K_LOOP ? 2u : 0xffffffffu));
			le32(e + 0x74, i - 2u);
			le64(e + 0x78, 8);
		}
	}
	/* the mini stream */
	for (i = 0; i < n; i++)
		body8(f + ((size_t)fat + fm + dsec + 1u) * 512u + (size_t)i * 64u, i, n);
	if (kind == K_CUT)
		m.len = cap * 3u / 7u;
	if (kind == K_CUT || kind == K_LOOP)
		m.rows = 0;
	return m;
}


#endif /* KOFENG_TESTS_ARCH_FIXTURES_H */
