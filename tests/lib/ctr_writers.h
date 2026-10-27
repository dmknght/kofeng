/*
 * ctr_writers.h - deterministic WRITERS of container files, valid and lying, for the container stage (WP2).
 *
 * One call shape for every format:  cw_<fmt>(&w, ents, n, &lies, &map)
 *
 *   ents   n members. Each says what it is stored as (name, bytes) and, separately, what the HEADERS say about it
 *          (claim_packed / claim_unpacked, set with .claimed), so a member can be written truthfully or lie about its size.
 *          .kind gives a file, a directory, a symlink (.target) or a hardlink (.target); .share (1-based) makes a member
 *          point at ANOTHER member's data (overlap); .name_len overrides strlen (NUL in a name, a 5000 byte name).
 *   lies   structure-level lies, a mask of CW_L_*: the declared COUNT of members, a declared OFFSET, a CYCLE in the
 *          directory / chain / xref structure, a missing terminator. NULL: none.
 *   map    where the writer put each LEN / COUNT / OFFSET field, so a mutator can aim at them (struct cw_map). NULL: not wanted.
 *
 * What each lie means per format is written at its writer. A lie a format has no field for is ignored there, and the
 * writer says so; cw_supports() answers for the table-driven tests.
 *
 * Header only and static, like the other tests/lib kits; needs <stdint.h>, <stdlib.h>, <string.h>, <stdio.h>. Nothing is
 * read from a file or the environment: the same arguments give the same bytes.
 */
#ifndef KOF_TESTS_CTR_WRITERS_H
#define KOF_TESTS_CTR_WRITERS_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CW_UNUSED __attribute__((unused))

/* ---- the output buffer ----------------------------------------------------------------------------------- */

struct cw {
	uint8_t *p;
	size_t   n, cap;
	int      oom;
};

enum cw_fkind { CW_F_LEN = 0, CW_F_COUNT, CW_F_OFFSET };          /* the same numbers as enum fz_fkind */

#define CW_MAXF 256u
struct cw_map {
	struct { uint32_t off; uint8_t size, kind; } f[CW_MAXF];
	unsigned n;
};

static CW_UNUSED void cw_put(struct cw *w, const void *s, size_t n)
{
	if (w->oom)
		return;
	if (w->n + n > w->cap) {
		size_t nc = w->cap ? w->cap : 512u;
		uint8_t *q;

		while (nc < w->n + n)
			nc *= 2u;
		q = (uint8_t *)realloc(w->p, nc);
		if (!q) {
			w->oom = 1;
			return;
		}
		w->p = q;
		w->cap = nc;
	}
	if (n)
		memcpy(w->p + w->n, s, n);
	w->n += n;
}

static CW_UNUSED void cw_u8(struct cw *w, uint32_t v)  { uint8_t b = (uint8_t)v; cw_put(w, &b, 1); }
static CW_UNUSED void cw_u16(struct cw *w, uint32_t v) { cw_u8(w, v); cw_u8(w, v >> 8); }
static CW_UNUSED void cw_u32(struct cw *w, uint32_t v) { cw_u16(w, v); cw_u16(w, v >> 16); }
static CW_UNUSED void cw_u64(struct cw *w, uint64_t v) { cw_u32(w, (uint32_t)v); cw_u32(w, (uint32_t)(v >> 32)); }
static CW_UNUSED void cw_zero(struct cw *w, size_t n)  { while (n--) cw_u8(w, 0); }
static CW_UNUSED void cw_str(struct cw *w, const char *s) { cw_put(w, s, strlen(s)); }
static CW_UNUSED void cw_free(struct cw *w)            { free(w->p); memset(w, 0, sizeof *w); }

/* Overwrite bytes already written (a size known only afterwards). */
static CW_UNUSED void cw_at16(struct cw *w, size_t at, uint32_t v) { if (at + 2u <= w->n) { w->p[at] = (uint8_t)v; w->p[at + 1] = (uint8_t)(v >> 8); } }
static CW_UNUSED void cw_at32(struct cw *w, size_t at, uint32_t v) { cw_at16(w, at, v); cw_at16(w, at + 2u, v >> 16); }
static CW_UNUSED void cw_at64(struct cw *w, size_t at, uint64_t v) { cw_at32(w, at, (uint32_t)v); cw_at32(w, at + 4u, (uint32_t)(v >> 32)); }

/* The fields a writer publishes (offset, width, what it means). */
static CW_UNUSED void cw_field(struct cw_map *m, uint32_t off, unsigned size, enum cw_fkind k)
{
	if (m && m->n < CW_MAXF) {
		m->f[m->n].off = off;
		m->f[m->n].size = (uint8_t)size;
		m->f[m->n].kind = (uint8_t)k;
		m->n++;
	}
}

static CW_UNUSED uint32_t cw_crc32(const void *p, uint64_t n)
{
	uint32_t c = 0xffffffffu;
	const uint8_t *b = (const uint8_t *)p;
	uint64_t i;
	unsigned k;

	for (i = 0; i < n; i++) {
		c ^= b[i];
		for (k = 0; k < 8; k++)
			c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1u)));
	}
	return ~c;
}

/* ---- members and lies ------------------------------------------------------------------------------------ */

enum cw_kind { CW_FILE = 0, CW_DIR, CW_SYMLINK, CW_HARDLINK };

struct cw_ent {
	const char *name;
	uint32_t    name_len;          /* 0: strlen(name) */
	const void *data;              /* the bytes stored */
	uint64_t    len;
	int         kind;              /* enum cw_kind */
	const char *target;            /* symlink / hardlink target */
	int         claimed;           /* the headers carry claim_packed / claim_unpacked instead of len */
	uint64_t    claim_packed, claim_unpacked;
	int         share;             /* 1-based: this member's header points at that member's data */
	unsigned    method;            /* zip: 0 stored, 8 deflate (the data is then a raw deflate stream: cw_deflate_stored); rar: the method byte, 0 = 0x30 stored; lha: the digit of -lh<d>-, 0 = -lh0-; arj: the method byte */
};

/* A raw deflate stream of `n` bytes as stored blocks (the decoder's cheapest path, and no compressor needed). */
static CW_UNUSED void cw_deflate_stored(struct cw *w, const void *d, uint64_t n)
{
	uint64_t pos = 0, left;

	do {
		left = n - pos > 65535u ? 65535u : n - pos;
		cw_u8(w, pos + left >= n ? 1 : 0);
		cw_u16(w, (uint32_t)left);
		cw_u16(w, (uint32_t)~left);
		cw_put(w, (const uint8_t *)d + pos, (size_t)left);
		pos += left;
	} while (pos < n);
}

enum {
	CW_L_COUNT  = 1,               /* the declared number of members is count_claim */
	CW_L_OFFSET = 2,               /* a declared offset of the directory / next header / first block is off_claim */
	CW_L_CYCLE  = 4,               /* the directory / chain / xref structure points back at itself */
	CW_L_NOEND  = 8,               /* the terminator / end block / trailer is left out */
	CW_L_EXTRA  = 16,              /* rar5: every file carries a time, a CRC and an extra area holding an encryption record (so it is a file marked encrypted) */
	CW_L_CRYPT  = 32               /* rar5: an encryption header block stands before the last member (the walk of the headers ends there) */
};

struct cw_lies {
	unsigned mask;
	uint64_t count_claim;
	uint64_t off_claim;
};

static CW_UNUSED uint32_t cw_nlen(const struct cw_ent *e)
{
	return e->name_len ? e->name_len : (uint32_t)strlen(e->name);
}

static CW_UNUSED uint64_t cw_cp(const struct cw_ent *e) { return e->claimed ? e->claim_packed : e->len; }
static CW_UNUSED uint64_t cw_cu(const struct cw_ent *e) { return e->claimed ? e->claim_unpacked : e->len; }
static CW_UNUSED unsigned cw_lie(const struct cw_lies *l, unsigned bit) { return l && (l->mask & bit); }

/* ---- zip ---------------------------------------------------------------------------------------------------
 * Stored members. claim -> csize/usize of BOTH headers; share -> the central entry's local offset is the other member's
 * (no local header of its own); COUNT -> the EOCD entry counts; OFFSET -> the EOCD directory offset; CYCLE -> every
 * central entry's local offset is the central directory itself; NOEND -> no EOCD; EXTRA -> UTF-8 names, an unknown extra field, a file
 * and an archive comment, the second member behind a data descriptor, and zip64 end records (the classic ones say 0xffff / 0xffffffff);
 * CRYPT -> every member carries the encryption flag. Symlink: Unix attributes S_IFLNK and
 * the target as the data; a directory: a name ending in '/'. A hardlink has no zip form: written as a file.
 */
static CW_UNUSED void cw_zip(struct cw *w, const struct cw_ent *e, unsigned n, const struct cw_lies *l, struct cw_map *m)
{
	uint32_t *lho = (uint32_t *)calloc(n ? n : 1u, sizeof *lho);
	uint32_t cd_off, i, cd_n, nl;
	uint64_t cnt = cw_lie(l, CW_L_COUNT) ? l->count_claim : n;
	int extra = (int)cw_lie(l, CW_L_EXTRA), crypt = (int)cw_lie(l, CW_L_CRYPT);

	if (!lho) {
		w->oom = 1;
		return;
	}
	for (i = 0; i < n; i++) {
		const void *d = e[i].kind == CW_SYMLINK ? (const void *)e[i].target : e[i].data;
		uint64_t dl = e[i].kind == CW_SYMLINK ? (uint64_t)strlen(e[i].target) : e[i].len;
		uint32_t fl = (extra ? 0x800u : 0u) | (crypt ? 1u : 0u) | (extra && i == 1u ? 8u : 0u);   /* utf-8 names, encrypted, data descriptor */
		int desc = (fl & 8u) != 0;

		if (e[i].share) {
			lho[i] = lho[e[i].share - 1];
			continue;
		}
		nl = cw_nlen(&e[i]);
		lho[i] = (uint32_t)w->n;
		cw_u32(w, 0x04034b50u);
		cw_u16(w, 20); cw_u16(w, fl); cw_u16(w, e[i].method); cw_u16(w, 0); cw_u16(w, 0x21); cw_u32(w, 0);
		cw_field(m, (uint32_t)w->n, 4, CW_F_LEN);
		cw_u32(w, desc ? 0u : (uint32_t)(e[i].claimed ? e[i].claim_packed : dl));
		cw_field(m, (uint32_t)w->n, 4, CW_F_LEN);
		cw_u32(w, desc ? 0u : (uint32_t)(e[i].claimed ? e[i].claim_unpacked : dl));
		cw_field(m, (uint32_t)w->n, 2, CW_F_LEN);
		cw_u16(w, nl);
		cw_u16(w, extra ? 4u : 0u);
		cw_put(w, e[i].name, nl);
		if (extra) {                                   /* an extra field: unknown id 0xcafe, no data */
			cw_u16(w, 0xcafe);
			cw_u16(w, 0);
		}
		cw_put(w, d, (size_t)dl);
		if (desc) {                                    /* the data descriptor: signature, crc, sizes */
			cw_u32(w, 0x08074b50u);
			cw_u32(w, cw_crc32(d, dl));
			cw_u32(w, (uint32_t)(e[i].claimed ? e[i].claim_packed : dl));
			cw_u32(w, (uint32_t)(e[i].claimed ? e[i].claim_unpacked : dl));
		}
	}
	cd_off = (uint32_t)w->n;
	for (i = 0; i < n; i++) {
		uint64_t dl = e[i].kind == CW_SYMLINK ? (uint64_t)strlen(e[i].target) : e[i].len;
		uint32_t attr = e[i].kind == CW_SYMLINK ? (0120777u << 16) : (e[i].kind == CW_DIR ? (040755u << 16) : (0100644u << 16));
		uint32_t fl = (extra ? 0x800u : 0u) | (crypt ? 1u : 0u) | (extra && i == 1u ? 8u : 0u);

		nl = cw_nlen(&e[i]);
		cw_u32(w, 0x02014b50u);
		cw_u16(w, 0x031e); cw_u16(w, 20); cw_u16(w, fl); cw_u16(w, e[i].method); cw_u16(w, 0); cw_u16(w, 0x21); cw_u32(w, 0);
		cw_field(m, (uint32_t)w->n, 4, CW_F_LEN);
		cw_u32(w, (uint32_t)(e[i].claimed ? e[i].claim_packed : dl));
		cw_field(m, (uint32_t)w->n, 4, CW_F_LEN);
		cw_u32(w, (uint32_t)(e[i].claimed ? e[i].claim_unpacked : dl));
		cw_field(m, (uint32_t)w->n, 2, CW_F_LEN);
		cw_u16(w, nl);
		cw_u16(w, extra ? 4u : 0u); cw_u16(w, extra ? 3u : 0u); cw_u16(w, 0); cw_u16(w, 0);
		cw_u32(w, attr);
		cw_field(m, (uint32_t)w->n, 4, CW_F_OFFSET);
		cw_u32(w, cw_lie(l, CW_L_CYCLE) ? cd_off : lho[i]);
		cw_put(w, e[i].name, nl);
		if (extra) {
			cw_u16(w, 0xcafe);
			cw_u16(w, 0);
			cw_put(w, "abc", 3);                   /* the file comment */
		}
	}
	cd_n = (uint32_t)w->n - cd_off;
	if (extra) {                                           /* zip64: the end record, its locator, and the classic record saying "look there" */
		uint64_t e64 = w->n;

		cw_u32(w, 0x06064b50u);
		cw_u64(w, 44);
		cw_u16(w, 45); cw_u16(w, 45);
		cw_u32(w, 0); cw_u32(w, 0);
		cw_u64(w, cnt); cw_u64(w, cnt);
		cw_u64(w, cd_n);
		cw_u64(w, cd_off);
		cw_u32(w, 0x07064b50u);
		cw_u32(w, 0);
		cw_u64(w, e64);
		cw_u32(w, 1);
	}
	if (!cw_lie(l, CW_L_NOEND)) {
		cw_u32(w, 0x06054b50u);
		cw_u16(w, 0); cw_u16(w, 0);
		cw_field(m, (uint32_t)w->n, 2, CW_F_COUNT);
		cw_u16(w, extra ? 0xffffu : (uint32_t)cnt);
		cw_field(m, (uint32_t)w->n, 2, CW_F_COUNT);
		cw_u16(w, extra ? 0xffffu : (uint32_t)cnt);
		cw_field(m, (uint32_t)w->n, 4, CW_F_LEN);
		cw_u32(w, extra ? 0xffffffffu : cd_n);
		cw_field(m, (uint32_t)w->n, 4, CW_F_OFFSET);
		cw_u32(w, extra ? 0xffffffffu : (cw_lie(l, CW_L_OFFSET) ? (uint32_t)l->off_claim : cd_off));
		cw_u16(w, extra ? 5u : 0u);
		if (extra)
			cw_put(w, "ctr-z", 5);                 /* the archive comment */
	}
	free(lho);
}

/* ---- tar ---------------------------------------------------------------------------------------------------
 * ustar 512 byte headers. File '0', directory '5', symlink '2', hardlink '1' (linkname = target). A name over 100 bytes is
 * written as a GNU 'L' long-name record before the member. claim -> the octal size field (the data written is e.len);
 * CYCLE -> every hardlink / symlink target is the NEXT member's name, and the last one's the first's (a loop); NOEND ->
 * no two zero blocks; EXTRA -> a pax global header before the first member, a pax header ('x': path, size, mtime) before the second,
 * a GNU long link name ('K') for a link target over 100 bytes, and the third member in the old format (no magic: its checksum then
 * no longer matches, which is the format's own anomaly). COUNT and OFFSET: a tar has no field for them, ignored.
 */
static CW_UNUSED void cw_tar_hdr(struct cw *w, struct cw_map *m, const char *name, uint32_t nl, char type, uint64_t size, const char *link)
{
	uint8_t h[512];
	uint32_t i, sum = 0;
	char t[16];
	size_t base = w->n;

	memset(h, 0, sizeof h);
	memcpy(h, name, nl > 100u ? 100u : nl);
	memcpy(h + 100, "0000644", 7);
	memcpy(h + 108, "0000000", 7);
	memcpy(h + 116, "0000000", 7);
	snprintf(t, sizeof t, "%011llo", (unsigned long long)(size & 0x1ffffffffull));
	memcpy(h + 124, t, 11);
	memcpy(h + 136, "00000000000", 11);
	memset(h + 148, ' ', 8);
	h[156] = (uint8_t)type;
	if (link)
		memcpy(h + 157, link, strlen(link) > 100u ? 100u : strlen(link));
	memcpy(h + 257, "ustar", 5);
	memcpy(h + 263, "00", 2);
	for (i = 0; i < 512u; i++)
		sum += h[i];
	snprintf(t, sizeof t, "%06o", sum);
	memcpy(h + 148, t, 7);
	h[155] = ' ';
	cw_field(m, (uint32_t)base + 124u, 8, CW_F_LEN);
	cw_put(w, h, 512);
}

/* One pax record "<len> key=value\n", len counting its own digits. */
static CW_UNUSED void cw_pax_rec(struct cw *w, const char *kv)
{
	size_t base = strlen(kv) + 2u, len = base + 1u;
	char d[16];

	for (;;) {
		int k = snprintf(d, sizeof d, "%zu", len);

		if ((size_t)k + base == len)
			break;
		len = base + (size_t)k;
	}
	cw_str(w, d);
	cw_u8(w, ' ');
	cw_str(w, kv);
	cw_u8(w, '\n');
}

static CW_UNUSED void cw_tar(struct cw *w, const struct cw_ent *e, unsigned n, const struct cw_lies *l, struct cw_map *m)
{
	unsigned i;
	int extra = (int)cw_lie(l, CW_L_EXTRA);

	for (i = 0; i < n; i++) {
		uint32_t nl = cw_nlen(&e[i]);
		char type = e[i].kind == CW_DIR ? '5' : e[i].kind == CW_SYMLINK ? '2' : e[i].kind == CW_HARDLINK ? '1' : '0';
		const char *link = e[i].kind == CW_SYMLINK || e[i].kind == CW_HARDLINK ? e[i].target : NULL;
		uint64_t size = (type == '0') ? cw_cu(&e[i]) : 0u;
		size_t pad;

		if (cw_lie(l, CW_L_CYCLE) && link && n > 1)
			link = e[(i + 1u) % n].name;
		if (extra && i == 0) {                         /* a pax GLOBAL header ('g') before the first member */
			struct cw rec = { 0 };

			cw_pax_rec(&rec, "comment=ctr-writers");
			cw_tar_hdr(w, m, "pax_global_header", 17, 'g', rec.n, NULL);
			cw_put(w, rec.p, rec.n);
			cw_zero(w, (512u - (rec.n & 511u)) & 511u);
			cw_free(&rec);
		}
		if (extra && i == 1) {                         /* a pax header ('x') for the second member: its path, and its size restated */
			struct cw rec = { 0 };
			char kv[600];

			snprintf(kv, sizeof kv, "path=%.*s", (int)(nl > 500u ? 500u : nl), e[i].name);
			cw_pax_rec(&rec, kv);
			snprintf(kv, sizeof kv, "size=%llu", (unsigned long long)size);
			cw_pax_rec(&rec, kv);
			cw_pax_rec(&rec, "mtime=1700000000.5");
			cw_tar_hdr(w, m, "./PaxHeaders/x", 14, 'x', rec.n, NULL);
			cw_put(w, rec.p, rec.n);
			cw_zero(w, (512u - (rec.n & 511u)) & 511u);
			cw_free(&rec);
		}
		if (extra && link && strlen(link) > 100u) {   /* a GNU long LINK name ('K') */
			cw_tar_hdr(w, m, "././@LongLink", 13, 'K', strlen(link) + 1u, NULL);
			cw_put(w, link, strlen(link));
			cw_u8(w, 0);
			cw_zero(w, (512u - ((strlen(link) + 1u) & 511u)) & 511u);
		}
		if (nl > 100u) {
			cw_tar_hdr(w, m, "././@LongLink", 13, 'L', nl + 1u, NULL);
			cw_put(w, e[i].name, nl);
			cw_u8(w, 0);
			pad = (512u - ((nl + 1u) & 511u)) & 511u;
			cw_zero(w, pad);
		}
		cw_tar_hdr(w, m, e[i].name, nl, type, size, link);
		if (extra && i == 2 && w->n >= 512u)           /* the third member in the OLD format: no magic, no version (a v7 header) */
			memset(w->p + w->n - 512u + 257u, 0, 8);
		if (type == '0') {
			cw_put(w, e[i].data, (size_t)e[i].len);
			pad = (512u - (e[i].len & 511u)) & 511u;
			cw_zero(w, pad);
		}
	}
	if (!cw_lie(l, CW_L_NOEND))
		cw_zero(w, 1024);
}

/* ---- rar (version 3 blocks) --------------------------------------------------------------------------------
 * marker, main block, a file block per member (stored, method 0x30), end block. claim -> PACK_SIZE / UNP_SIZE; share and
 * COUNT / OFFSET / CYCLE have no field in the format and are ignored; NOEND -> no end block. A directory sets the
 * directory bit in the file flags. Symlink and hardlink are written as files.
 */
static CW_UNUSED void cw_rar(struct cw *w, const struct cw_ent *e, unsigned n, const struct cw_lies *l, struct cw_map *m)
{
	unsigned i;

	cw_put(w, "Rar!\x1a\x07\x00", 7);
	cw_u16(w, 0); cw_u8(w, 0x73); cw_u16(w, 0); cw_u16(w, 13); cw_zero(w, 6);
	for (i = 0; i < n; i++) {
		uint32_t nl = cw_nlen(&e[i]);
		uint32_t flags = 0x8000u | (e[i].kind == CW_DIR ? 0xe0u : 0u);

		cw_u16(w, 0); cw_u8(w, 0x74); cw_u16(w, flags); cw_u16(w, 32u + nl);
		cw_field(m, (uint32_t)w->n, 4, CW_F_LEN);
		cw_u32(w, (uint32_t)cw_cp(&e[i]));
		cw_field(m, (uint32_t)w->n, 4, CW_F_LEN);
		cw_u32(w, (uint32_t)cw_cu(&e[i]));
		cw_u8(w, 0); cw_u32(w, 0); cw_u32(w, 0); cw_u8(w, 29); cw_u8(w, e[i].method ? e[i].method : 0x30u);
		cw_field(m, (uint32_t)w->n, 2, CW_F_LEN);
		cw_u16(w, nl);
		cw_u32(w, 0);
		cw_put(w, e[i].name, nl);
		cw_put(w, e[i].data, (size_t)e[i].len);
	}
	if (!cw_lie(l, CW_L_NOEND)) {
		cw_u16(w, 0); cw_u8(w, 0x7b); cw_u16(w, 0); cw_u16(w, 7);
	}
}

/* ---- rar (version 5 blocks) ------------------------------------------------------------------------------
 * signature "Rar!\x1a\x07\x01\x00", a main block, a file block per member (stored, with variable length integers), an end block.
 * claim -> the block's data size and the unpacked size; a directory sets the directory file flag; NOEND -> no end block;
 * EXTRA -> a time and a CRC32 in every file header and an extra area with an encryption record; CRYPT -> an encryption header
 * block before the last member. COUNT / OFFSET / CYCLE have no field in the format and are ignored.
 */
static CW_UNUSED size_t cw_vint(uint8_t *p, uint64_t v)
{
	size_t k = 0;

	do {
		p[k] = (uint8_t)(v & 0x7fu);
		v >>= 7;
		if (v)
			p[k] |= 0x80u;
		k++;
	} while (v);
	return k;
}

static CW_UNUSED void cw_rar5(struct cw *w, const struct cw_ent *e, unsigned n, const struct cw_lies *l, struct cw_map *m)
{
	unsigned i;
	uint8_t h[1024];

	cw_put(w, "Rar!\x1a\x07\x01\x00", 8);
	{ static const uint8_t mainb[] = { 3, 1, 0, 0 };           /* the main block: size 3, type 1, flags 0, archive flags 0, behind its CRC32 */
	  cw_u32(w, cw_crc32(mainb, sizeof mainb)); cw_put(w, mainb, sizeof mainb); }
	for (i = 0; i < n; i++) {
		size_t k = 0;
		uint32_t nl = cw_nlen(&e[i]) > 600u ? 600u : cw_nlen(&e[i]);
		uint64_t fflags = (e[i].kind == CW_DIR ? 1u : 0u) | (cw_lie(l, CW_L_EXTRA) ? 6u : 0u);
		size_t hdr_len_at, extra_len = 0;
		uint8_t extra[8];

		if (cw_lie(l, CW_L_CRYPT) && n > 1 && i + 1u == n) {
			static const uint8_t cr[] = { 2, 4, 0 };                              /* an encryption header: size 2, type 4, flags 0 */

			cw_u32(w, cw_crc32(cr, sizeof cr));
			cw_put(w, cr, sizeof cr);
		}
		if (cw_lie(l, CW_L_EXTRA)) {
			extra[0] = 2;                                                          /* the record's size, from the next byte */
			extra[1] = 1;                                                          /* its type: file encryption */
			extra[2] = 0;
			extra_len = 3;
		}
		k += cw_vint(h + k, 2u);                                                   /* type: file */
		k += cw_vint(h + k, 2u | (extra_len ? 1u : 0u));                           /* flags: data present (+ extra) */
		if (extra_len)
			k += cw_vint(h + k, extra_len);
		cw_field(m, (uint32_t)(w->n + 4u + 1u + k), 1, CW_F_LEN);
		k += cw_vint(h + k, cw_cp(&e[i]));                                         /* data size */
		k += cw_vint(h + k, fflags);
		k += cw_vint(h + k, cw_cu(&e[i]));                                         /* unpacked size */
		k += cw_vint(h + k, 0);                                                    /* attributes */
		if (fflags & 2u) { memset(h + k, 0, 4); k += 4; }                          /* mtime */
		if (fflags & 4u) { memset(h + k, 0, 4); k += 4; }                          /* crc32 */
		k += cw_vint(h + k, 0);                                                    /* compression info: stored */
		k += cw_vint(h + k, 0);                                                    /* host os */
		k += cw_vint(h + k, nl);
		memcpy(h + k, e[i].name, nl);
		k += nl;
		if (extra_len) {
			memcpy(h + k, extra, extra_len);
			k += extra_len;
		}
		hdr_len_at = w->n;
		{
			uint8_t sz[10], both[1100];
			size_t sn = cw_vint(sz, k);

			memcpy(both, sz, sn);
			memcpy(both + sn, h, k);
			cw_u32(w, cw_crc32(both, sn + k));                                     /* the CRC32 covers the size and the header */
			cw_put(w, sz, sn);
		}
		(void)hdr_len_at;
		cw_put(w, h, k);
		cw_put(w, e[i].data, (size_t)e[i].len);
	}
	if (!cw_lie(l, CW_L_NOEND)) {
		static const uint8_t endb[] = { 3, 5, 0, 0 };         /* size 3: type 5, flags 0, end-of-archive flags 0 */

		cw_u32(w, cw_crc32(endb, sizeof endb));
		cw_put(w, endb, sizeof endb);
	}
}

/* ---- lha (level 0 headers) ---------------------------------------------------------------------------------
 * claim -> packed / original size; a directory is method "-lhd-"; NOEND -> no zero terminator byte; EXTRA -> the members cycle through
 * header level 0 with method -lh6-, level 1 and level 2 (the header sizes and fields move with the level). The rest has no field.
 */
static CW_UNUSED void cw_lha(struct cw *w, const struct cw_ent *e, unsigned n, const struct cw_lies *l, struct cw_map *m)
{
	unsigned i;
	int extra = (int)cw_lie(l, CW_L_EXTRA);

	for (i = 0; i < n; i++) {
		uint32_t nl = cw_nlen(&e[i]) > 200u ? 200u : cw_nlen(&e[i]);      /* the name length is one byte */
		unsigned level = extra ? i % 3u == 1u ? 1u : i % 3u == 2u ? 2u : 0u : 0u;
		uint32_t hsize = level == 1u ? 20u + nl + 2u + 1u + 2u : level == 2u ? 24u : 20u + nl + 2u, sum = 0, k;
		uint8_t h[300];

		memset(h, 0, sizeof h);
		if (level == 2u) {
			h[0] = 26; h[1] = 0;                                       /* the whole header, 16 bits, name in an extension that is not written */
		} else {
			h[0] = (uint8_t)hsize;
		}
		memcpy(h + 2, e[i].kind == CW_DIR ? "-lhd-" : (e[i].method ? "-lh0-" : (extra && i % 3u == 0u ? "-lh6-" : "-lh0-")), 5);
		if (e[i].method && e[i].kind != CW_DIR)
			h[5] = (uint8_t)('0' + e[i].method % 10u);                 /* -lh<d>-: the method digit */
		h[7] = (uint8_t)cw_cp(&e[i]); h[8] = (uint8_t)(cw_cp(&e[i]) >> 8); h[9] = (uint8_t)(cw_cp(&e[i]) >> 16); h[10] = (uint8_t)(cw_cp(&e[i]) >> 24);
		h[11] = (uint8_t)cw_cu(&e[i]); h[12] = (uint8_t)(cw_cu(&e[i]) >> 8); h[13] = (uint8_t)(cw_cu(&e[i]) >> 16); h[14] = (uint8_t)(cw_cu(&e[i]) >> 24);
		h[19] = 0x20;
		h[20] = (uint8_t)level;
		if (level == 2u) {
			h[23] = 'U';                                               /* crc16 at 21..22, the OS id, the (empty) next extension size at 24..25 */
			cw_field(m, (uint32_t)w->n + 7u, 4, CW_F_LEN);
			cw_field(m, (uint32_t)w->n + 11u, 4, CW_F_LEN);
			cw_put(w, h, 26);
		} else {
			h[21] = (uint8_t)nl;
			memcpy(h + 22, e[i].name, nl);
			if (level == 1u)
				h[22 + nl + 2u] = 'U';                             /* the OS id after the crc16 */
			for (k = 0; k < hsize; k++)
				sum += h[2 + k];
			h[1] = (uint8_t)sum;
			cw_field(m, (uint32_t)w->n + 7u, 4, CW_F_LEN);
			cw_field(m, (uint32_t)w->n + 11u, 4, CW_F_LEN);
			cw_put(w, h, 2u + hsize);                                  /* (level 1: the last two bytes are the next extension header's size, none) */
		}
		cw_put(w, e[i].data, (size_t)e[i].len);
	}
	if (!cw_lie(l, CW_L_NOEND))
		cw_u8(w, 0);
}

/* ---- arj ---------------------------------------------------------------------------------------------------
 * main header (a file header of type 2), a stored member each, the zero-size end header. claim -> compressed / original
 * size; a directory is file type 3; NOEND -> no end header.
 */
static CW_UNUSED void cw_arj(struct cw *w, const struct cw_ent *e, unsigned n, const struct cw_lies *l, struct cw_map *m)
{
	unsigned i;
	static const char main_name[] = "a.arj";

	for (i = 0; i <= n; i++) {
		int mainhdr = i == 0;
		const struct cw_ent *x = mainhdr ? NULL : &e[i - 1u];
		const char *name = mainhdr ? main_name : x->name;
		uint32_t nlen = mainhdr ? (uint32_t)sizeof main_name - 1u : cw_nlen(x);
		uint32_t nl = nlen + 1u, basic = 30u + nl + 1u;
		uint64_t cp = mainhdr ? 0u : cw_cp(x), cu = mainhdr ? 0u : cw_cu(x);

		if (basic > 2600u) {                    /* the basic header is bounded at 2600 bytes; cut the name */
			nlen = 2400u;
			nl = nlen + 1u;
			basic = 30u + nl + 1u;
		}
		cw_u8(w, 0x60); cw_u8(w, 0xea);
		cw_u16(w, basic);
		cw_u8(w, 30); cw_u8(w, 11); cw_u8(w, 1); cw_u8(w, 2); cw_u8(w, 0);
		cw_u8(w, mainhdr ? 0u : x->method);       /* method: 0 stored, 1..4 coded (the ARJ method byte) */
		cw_u8(w, mainhdr ? 2 : (x->kind == CW_DIR ? 3 : 0));
		cw_zero(w, 5);
		cw_field(m, (uint32_t)w->n, 4, CW_F_LEN);
		cw_u32(w, (uint32_t)cp);
		cw_field(m, (uint32_t)w->n, 4, CW_F_LEN);
		cw_u32(w, (uint32_t)cu);
		cw_zero(w, 10);
		cw_put(w, name, nlen);
		cw_u8(w, 0);
		cw_u8(w, 0);
		cw_u32(w, 0);
		cw_u16(w, 0);
		if (!mainhdr)
			cw_put(w, x->data, (size_t)x->len);
	}
	if (!cw_lie(l, CW_L_NOEND)) {
		cw_u8(w, 0x60); cw_u8(w, 0xea); cw_u16(w, 0);
	}
}

/* ---- cab ---------------------------------------------------------------------------------------------------
 * one stored folder whose data is every member's bytes end to end in blocks of at most 8192 (the members' offsets are
 * their position in it); claim -> the file's cbFile; COUNT -> cFiles; OFFSET -> coffFiles; CYCLE -> as many folders as
 * members, every one naming the first block chain (a shared chain walked N times); NOEND: none (a cabinet has no trailer); EXTRA -> the folders MSZIP coded ("CK" and one
 * stored deflate block per block of at most 32768 bytes); CRYPT -> a reserve area in the header, the folders and the blocks, and a next
 * cabinet's name (the "spanned" flag).
 */
static CW_UNUSED void cw_cab(struct cw *w, const struct cw_ent *e, unsigned n, const struct cw_lies *l, struct cw_map *m)
{
	uint64_t total = 0, off;
	int extra = (int)cw_lie(l, CW_L_EXTRA), resv = (int)cw_lie(l, CW_L_CRYPT);
	uint32_t i, nfold = cw_lie(l, CW_L_CYCLE) && n ? n : 1u, nblk, files_len = 0, coff, data_at, hdr_len = 36, fold_len = 8, blk_hdr = 8, at, k;
	size_t base = w->n;
	uint8_t *all;
	uint64_t pos, left;
	struct cw data = { 0 };

	for (i = 0; i < n; i++) {
		files_len += 16u + cw_nlen(&e[i]) + 1u;
		total += e[i].len;
	}
	if (resv) {                                      /* a reserve area (6 + 2 per folder + 2 per block) and the next cabinet's name */
		hdr_len += 4u + 6u + (uint32_t)strlen("next.cab") + 1u + (uint32_t)strlen("disk2") + 1u;
		fold_len += 2u;
		blk_hdr += 2u;
	}
	/* (EXTRA alone: MSZIP blocks; CRYPT alone: the reserve area, stored blocks) */
	all = (uint8_t *)malloc(total ? (size_t)total : 1u);
	if (!all) {
		w->oom = 1;
		return;
	}
	for (pos = 0, i = 0; i < n; i++) {
		if (e[i].len)
			memcpy(all + pos, e[i].data, (size_t)e[i].len);
		pos += e[i].len;
	}
	/* the blocks: stored, or (EXTRA) MSZIP - "CK" and a deflate stream of one stored block - of at most 32768 bytes of output each */
	nblk = 0;
	for (pos = 0; pos < total; pos += left) {
		left = total - pos > (extra ? 32768u : 8192u) ? (extra ? 32768u : 8192u) : total - pos;
		nblk++;
		for (k = 0; k < blk_hdr; k++)
			cw_u8(&data, 0);                 /* room for the block header, filled below */
		if (extra) {
			cw_u8(&data, 'C'); cw_u8(&data, 'K');
			cw_u8(&data, 1);                 /* final stored block */
			cw_u16(&data, (uint32_t)left);
			cw_u16(&data, (uint32_t)~left);
		}
		cw_put(&data, all + pos, (size_t)left);
		{
			size_t hdr_at = data.n - (size_t)left - (extra ? 7u : 0u) - blk_hdr;
			uint32_t cb = (uint32_t)left + (extra ? 7u : 0u);

			cw_at32(&data, hdr_at, 0);
			cw_at16(&data, hdr_at + 4u, cb);
			cw_at16(&data, hdr_at + 6u, (uint32_t)left);
		}
	}
	coff = hdr_len + fold_len * nfold;
	data_at = coff + files_len;
	cw_str(w, "MSCF");
	cw_u32(w, 0);
	cw_field(m, (uint32_t)(w->n - base), 4, CW_F_LEN);
	cw_u32(w, data_at + (uint32_t)data.n);
	cw_u32(w, 0);
	cw_field(m, (uint32_t)(w->n - base), 4, CW_F_OFFSET);
	cw_u32(w, cw_lie(l, CW_L_OFFSET) ? (uint32_t)l->off_claim : coff);
	cw_u32(w, 0);
	cw_u16(w, 0x0301);
	cw_field(m, (uint32_t)(w->n - base), 2, CW_F_COUNT);
	cw_u16(w, nfold);
	cw_field(m, (uint32_t)(w->n - base), 2, CW_F_COUNT);
	cw_u16(w, cw_lie(l, CW_L_COUNT) ? (uint32_t)l->count_claim : n);
	cw_u16(w, resv ? 0x0006u : 0u);                  /* flags: reserve present, a next cabinet */
	cw_u16(w, 0); cw_u16(w, 0);
	if (resv) {
		cw_u16(w, 6); cw_u8(w, 2); cw_u8(w, 2);  /* cbCFHeader, cbCFFolder, cbCFData */
		cw_zero(w, 6);
		cw_str(w, "next.cab"); cw_u8(w, 0);
		cw_str(w, "disk2"); cw_u8(w, 0);
	}
	for (i = 0; i < nfold; i++) {
		cw_u32(w, data_at);
		cw_u16(w, nblk);
		cw_u16(w, extra ? 1u : 0u);              /* typeCompress: MSZIP, or none */
		if (resv)
			cw_u16(w, 0);
	}
	off = 0;
	for (i = 0; i < n; i++) {
		cw_field(m, (uint32_t)(w->n - base), 4, CW_F_LEN);
		cw_u32(w, (uint32_t)cw_cu(&e[i]));
		cw_field(m, (uint32_t)(w->n - base), 4, CW_F_OFFSET);
		cw_u32(w, (uint32_t)off);
		cw_u16(w, cw_lie(l, CW_L_CYCLE) ? i : 0u);
		cw_u16(w, 0); cw_u16(w, 0);
		cw_u16(w, e[i].kind == CW_DIR ? 0x10u : 0x20u);
		cw_put(w, e[i].name, cw_nlen(&e[i]));
		cw_u8(w, 0);
		off += e[i].len;
	}
	at = (uint32_t)(w->n - base);
	(void)at;
	cw_put(w, data.p, data.n);
	cw_free(&data);
	free(all);
}

/* ---- chm ---------------------------------------------------------------------------------------------------
 * ITSF + ITSP + PMGL directory chunks of 4096 + the uncompressed content (section 0). A member is "/" + its name's
 * entry: section 0, offset = the end of the members before it, length = claim or len (all as encoded integers). COUNT ->
 * the ITSP chunk count; OFFSET -> the content offset in the ITSF header; CYCLE -> every PMGL chunk names itself as its
 * own next chunk. NOEND ignored.
 */
static CW_UNUSED size_t cw_chm_enc(uint8_t *p, uint64_t v)
{
	uint8_t t[10];
	size_t k = 0, i;

	do {
		t[k++] = (uint8_t)(v & 0x7fu);
		v >>= 7;
	} while (v);
	for (i = 0; i < k; i++)
		p[i] = (uint8_t)(t[k - 1u - i] | (i + 1u < k ? 0x80u : 0u));
	return k;
}

static CW_UNUSED void cw_chm(struct cw *w, const struct cw_ent *e, unsigned n, const struct cw_lies *l, struct cw_map *m)
{
	enum { CHUNK = 4096, ITSF = 0x60, ITSP = 0x54 };
	size_t cap = (size_t)n * 600u + 8192u, nchunk = 1, i, content_at, base = w->n;
	uint8_t *dir = (uint8_t *)calloc(1, cap), *at, *cur;
	uint64_t off = 0;

	if (!dir) {
		w->oom = 1;
		return;
	}
	cur = dir;
	memcpy(cur, "PMGL", 4);
	at = cur + 0x14;
	for (i = 0; i < n; i++) {
		uint8_t tmp[640];
		uint32_t nl = cw_nlen(&e[i]) > 500u ? 500u : cw_nlen(&e[i]);
		size_t k = 0, en;

		k += cw_chm_enc(tmp, nl + 1u);
		tmp[k++] = '/';
		memcpy(tmp + k, e[i].name, nl);
		k += nl;
		tmp[k++] = 0;
		k += cw_chm_enc(tmp + k, off);
		k += cw_chm_enc(tmp + k, cw_cu(&e[i]));
		en = k;
		if ((size_t)(at - cur) + en > CHUNK) {
			cur[4] = (uint8_t)((CHUNK - (size_t)(at - cur)));
			cur[5] = (uint8_t)((CHUNK - (size_t)(at - cur)) >> 8);
			cur += CHUNK;
			nchunk++;
			memcpy(cur, "PMGL", 4);
			at = cur + 0x14;
		}
		memcpy(at, tmp, en);
		at += en;
		off += e[i].len;
	}
	cur[4] = (uint8_t)((CHUNK - (size_t)(at - cur)));
	cur[5] = (uint8_t)((CHUNK - (size_t)(at - cur)) >> 8);
	if (cw_lie(l, CW_L_CYCLE))
		for (i = 0; i < nchunk; i++) {
			dir[i * CHUNK + 12] = (uint8_t)i;           /* the next chunk is itself */
		}
	content_at = ITSF + ITSP + nchunk * CHUNK;
	cw_put(w, "ITSF", 4);
	cw_u32(w, 3);
	cw_u32(w, ITSF);
	cw_zero(w, 8);
	cw_u32(w, 0x409);
	cw_zero(w, 32);
	cw_u64(w, ITSF);
	cw_u64(w, 0x18);
	cw_u64(w, ITSF);
	cw_u64(w, ITSP);
	cw_field(m, (uint32_t)(w->n - base), 8, CW_F_OFFSET);
	cw_u64(w, cw_lie(l, CW_L_OFFSET) ? l->off_claim : (uint64_t)content_at);
	cw_put(w, "ITSP", 4);
	cw_u32(w, 1);
	cw_u32(w, ITSP);
	cw_zero(w, 4);
	cw_u32(w, CHUNK);
	cw_zero(w, 24);
	cw_field(m, (uint32_t)(w->n - base), 4, CW_F_COUNT);
	cw_u32(w, cw_lie(l, CW_L_COUNT) ? (uint32_t)l->count_claim : (uint32_t)nchunk);
	cw_zero(w, ITSP - 48u);
	cw_put(w, dir, nchunk * CHUNK);
	for (i = 0; i < n; i++)
		cw_put(w, e[i].data, (size_t)e[i].len);
	free(dir);
}

/* ---- 7z ----------------------------------------------------------------------------------------------------
 * signature header (with its CRCs), each member as one packed stream of LZMA2 uncompressed chunks (the coder the shipped
 * unpacker decodes: a COPY, deflate or LZMA folder is named UNSUPPORTED, not opened), a plain header: one folder per
 * member with one LZMA2 coder, and the file names (UTF-16, the low byte of each name byte). claim -> the pack size and the
 * unpack size of that member's folder; COUNT -> the number of pack streams / folders; OFFSET -> the next header
 * offset in the start header; NOEND -> the header's closing kEnd bytes left out; CYCLE ignored; EXTRA -> stream digests, times,
 * attributes and padding, and the header itself CODED with the COPY coder (kEncodedHeader: this build opens a coded header only when it is LZMA, so the archive is
 * reported UNSUPPORTED); CRYPT -> the coded header under the AES coder (reported ENCRYPTED).
 */
static CW_UNUSED size_t cw_7z_num(uint8_t *p, uint64_t v)
{
	unsigned i;
	size_t k;

	if (v < 0x80u) {
		p[0] = (uint8_t)v;
		return 1;
	}
	for (i = 1; i < 8u; i++)
		if (v < (1ull << (7u * (i + 1u)))) {
			p[0] = (uint8_t)((0xffu << (8u - i)) | (uint8_t)(v >> (8u * i)));
			for (k = 0; k < i; k++)
				p[1 + k] = (uint8_t)(v >> (8u * k));
			return 1u + i;
		}
	p[0] = 0xff;
	for (k = 0; k < 8; k++)
		p[1 + k] = (uint8_t)(v >> (8u * k));
	return 9;
}

static CW_UNUSED int cw_7z_empty(const struct cw_ent *e) { return e->len == 0 && !e->claimed; }

static CW_UNUSED void cw_7z(struct cw *w, const struct cw_ent *e, unsigned n, const struct cw_lies *l, struct cw_map *m)
{
	struct cw h = { 0 }, pk = { 0 };
	uint8_t t[10];
	uint64_t *psz = (uint64_t *)calloc(n ? n : 1u, sizeof *psz), nxt_off, cnt;
	unsigned i, nf = 0, n_empty = 0;
	uint32_t hcrc, scrc;
	uint8_t sh[20];

	if (!psz) {
		w->oom = 1;
		return;
	}
	for (i = 0; i < n; i++) {                /* each member: LZMA2 uncompressed chunks (the one coder the shipped unpacker decodes) */
		uint64_t pos = 0, left;
		size_t st = pk.n;

		if (cw_7z_empty(&e[i])) {        /* an empty file or a directory: no folder, the EmptyStream property says so */
			n_empty++;
			continue;
		}
		nf++;
		while (pos < e[i].len) {
			left = e[i].len - pos > 65536u ? 65536u : e[i].len - pos;
			cw_u8(&pk, pos ? 2 : 1);
			cw_u8(&pk, (uint32_t)((left - 1u) >> 8));
			cw_u8(&pk, (uint32_t)((left - 1u) & 0xffu));
			cw_put(&pk, (const uint8_t *)e[i].data + pos, (size_t)left);
			pos += left;
		}
		cw_u8(&pk, 0);
		psz[i] = pk.n - st;
	}
	cnt = cw_lie(l, CW_L_COUNT) ? l->count_claim : nf;
	cw_u8(&h, 0x01);                       /* kHeader */
	if (nf) {
		cw_u8(&h, 0x04);               /* kMainStreamsInfo */
		cw_u8(&h, 0x06);               /* kPackInfo */
		cw_u8(&h, 0);                  /* packPos 0 */
		cw_put(&h, t, cw_7z_num(t, cnt));
		cw_u8(&h, 0x09);               /* kSize */
		for (i = 0; i < n; i++)
			if (!cw_7z_empty(&e[i]))
				cw_put(&h, t, cw_7z_num(t, e[i].claimed ? e[i].claim_packed : psz[i]));
		cw_u8(&h, 0x00);
		cw_u8(&h, 0x07);               /* kUnPackInfo */
		cw_u8(&h, 0x0b);               /* kFolder */
		cw_put(&h, t, cw_7z_num(t, cnt));
		cw_u8(&h, 0);                  /* not external */
		for (i = 0; i < nf; i++) {
			cw_u8(&h, 1);          /* one coder */
			cw_u8(&h, 0x21);       /* id size 1, has properties */
			cw_u8(&h, 0x21);       /* LZMA2 */
			cw_u8(&h, 1);          /* one property byte */
			cw_u8(&h, 0x18);       /* dictionary 1 MiB */
		}
		cw_u8(&h, 0x0c);               /* kCodersUnPackSize */
		for (i = 0; i < n; i++)
			if (!cw_7z_empty(&e[i]))
				cw_put(&h, t, cw_7z_num(t, cw_cu(&e[i])));
		cw_u8(&h, 0x00);               /* end of unpack info */
		cw_u8(&h, 0x08);               /* kSubStreamsInfo: one stream per folder */
		cw_u8(&h, 0x0d);
		for (i = 0; i < nf; i++)
			cw_u8(&h, 1);
		if (cw_lie(l, CW_L_EXTRA)) {
			cw_u8(&h, 0x0a);       /* kCRC: every stream's digest, defined */
			cw_u8(&h, 1);
			for (i = 0; i < n; i++)
				if (!cw_7z_empty(&e[i]))
					cw_u32(&h, cw_crc32(e[i].data, (size_t)e[i].len));
		}
		cw_u8(&h, 0x00);
		cw_u8(&h, 0x00);               /* end of streams info */
	}
	cw_u8(&h, 0x05);                       /* kFilesInfo */
	cw_put(&h, t, cw_7z_num(t, n));
	if (n_empty) {
		uint8_t bits[8192], ef[8192];
		unsigned eb = (n_empty + 7u) / 8u, nb = (n + 7u) / 8u, e_i = 0, any_ef = 0;

		memset(bits, 0, sizeof bits);
		memset(ef, 0, sizeof ef);
		if (nb <= sizeof bits) {
			for (i = 0; i < n; i++)
				if (cw_7z_empty(&e[i])) {
					bits[i / 8u] = (uint8_t)(bits[i / 8u] | (0x80u >> (i % 8u)));
					if (e[i].kind != CW_DIR) {
						ef[e_i / 8u] = (uint8_t)(ef[e_i / 8u] | (0x80u >> (e_i % 8u)));
						any_ef = 1;
					}
					e_i++;
				}
			cw_u8(&h, 0x0e);       /* kEmptyStream */
			cw_put(&h, t, cw_7z_num(t, nb));
			cw_put(&h, bits, nb);
			if (any_ef) {
				cw_u8(&h, 0x0f);   /* kEmptyFile */
				cw_put(&h, t, cw_7z_num(t, eb));
				cw_put(&h, ef, eb);
			}
		}
	}
	{
		uint64_t nb = 1;
		uint8_t sz[10];

		for (i = 0; i < n; i++)
			nb += 2ull * (cw_nlen(&e[i]) + 1u);
		cw_u8(&h, 0x11);               /* kNames */
		cw_put(&h, sz, cw_7z_num(sz, nb));
		cw_u8(&h, 0);
		for (i = 0; i < n; i++) {
			uint32_t k, nl = cw_nlen(&e[i]);

			for (k = 0; k < nl; k++) {
				cw_u8(&h, ((const uint8_t *)e[i].name)[k]);
				cw_u8(&h, 0);
			}
			cw_u16(&h, 0);
		}
	}
	if (cw_lie(l, CW_L_EXTRA)) {
		uint8_t sz[10];

		cw_u8(&h, 0x14);               /* kMTime: defined for all, not external */
		cw_put(&h, sz, cw_7z_num(sz, 2ull + 8ull * n));
		cw_u8(&h, 1); cw_u8(&h, 0);
		for (i = 0; i < n; i++)
			cw_u64(&h, 0x01d0000000000000ull + i);
		cw_u8(&h, 0x15);               /* kWinAttributes */
		cw_put(&h, sz, cw_7z_num(sz, 2ull + 4ull * n));
		cw_u8(&h, 1); cw_u8(&h, 0);
		for (i = 0; i < n; i++)
			cw_u32(&h, e[i].kind == CW_DIR ? 0x10u : 0x20u);
		cw_u8(&h, 0x19);               /* kDummy: padding */
		cw_u8(&h, 3); cw_u8(&h, 0); cw_u8(&h, 0); cw_u8(&h, 0);
	}
	cw_u8(&h, 0x00);
	if (!cw_lie(l, CW_L_NOEND))
		cw_u8(&h, 0x00);
	if (cw_lie(l, CW_L_EXTRA) || cw_lie(l, CW_L_CRYPT)) {
		/* the header itself CODED (kEncodedHeader): its bytes are a packed stream after the members', described by a streams info.
		 * EXTRA codes it with the COPY coder; CRYPT with the AES coder (ciphertext). */
		struct cw hh = { 0 };
		size_t packpos = pk.n, at = pk.n;
		uint8_t num[10];

		cw_put(&pk, h.p, h.n);                                   /* COPY: the bytes as they are; AES: they stand for ciphertext */
		at = pk.n - at;
		cw_u8(&hh, 0x17);
		cw_u8(&hh, 0x06);
		cw_put(&hh, num, cw_7z_num(num, packpos));
		cw_u8(&hh, 1);
		cw_u8(&hh, 0x09);
		cw_put(&hh, num, cw_7z_num(num, at));
		cw_u8(&hh, 0x00);
		cw_u8(&hh, 0x07);
		cw_u8(&hh, 0x0b);
		cw_u8(&hh, 1);
		cw_u8(&hh, 0);
		cw_u8(&hh, 1);
		if (cw_lie(l, CW_L_CRYPT)) {
			cw_u8(&hh, 0x24); cw_u8(&hh, 0x06); cw_u8(&hh, 0xf1); cw_u8(&hh, 0x07); cw_u8(&hh, 0x01);   /* id size 4 + properties; the AES id */
			cw_u8(&hh, 1); cw_u8(&hh, 0);
		} else {
			cw_u8(&hh, 0x01); cw_u8(&hh, 0x00);                  /* the COPY coder: the coded header is the header's own bytes */
		}
		cw_u8(&hh, 0x0c);
		cw_put(&hh, num, cw_7z_num(num, h.n));
		cw_u8(&hh, 0x00);
		cw_u8(&hh, 0x00);
		cw_free(&h);
		h = hh;
	}
	nxt_off = pk.n;
	hcrc = cw_crc32(h.p, h.n);
	memset(sh, 0, sizeof sh);
	{
		uint64_t no = cw_lie(l, CW_L_OFFSET) ? l->off_claim : nxt_off, ns = h.n;
		unsigned k;

		for (k = 0; k < 8; k++) {
			sh[k] = (uint8_t)(no >> (8u * k));
			sh[8 + k] = (uint8_t)(ns >> (8u * k));
		}
		sh[16] = (uint8_t)hcrc; sh[17] = (uint8_t)(hcrc >> 8); sh[18] = (uint8_t)(hcrc >> 16); sh[19] = (uint8_t)(hcrc >> 24);
	}
	scrc = cw_crc32(sh, 20);
	cw_put(w, "7z\xbc\xaf\x27\x1c", 6);
	cw_u8(w, 0); cw_u8(w, 4);
	cw_u32(w, scrc);
	cw_field(m, (uint32_t)w->n, 8, CW_F_OFFSET);
	cw_field(m, (uint32_t)w->n + 8u, 8, CW_F_LEN);
	cw_put(w, sh, 20);
	cw_put(w, pk.p, pk.n);
	cw_put(w, h.p, h.n);
	cw_free(&h);
	cw_free(&pk);
	free(psz);
}

/* ---- OLE compound file -------------------------------------------------------------------------------------
 * sector 512, mini sector 64, cutoff 4096, one directory (Root Entry + a stream per member, a sibling chain through the
 * right-sibling field), small streams in the mini stream, large in sectors. claim -> the directory entry's size field
 * (only the size the directory says; the sectors written are e.len); COUNT -> the number of MiniFAT sectors the header
 * says; OFFSET -> every stream's start sector (a sector past the end of the file); CYCLE -> the directory chain loops back
 * to its first sector and the last sibling points at the first stream; NOEND ignored. At most 109 FAT sectors.
 */
static CW_UNUSED void cw_ole(struct cw *w, const struct cw_ent *e, unsigned n, const struct cw_lies *l, struct cw_map *m)
{
	unsigned ents = n + 1u, dsec = (ents + 3u) / 4u, i, k, fat = 1, nmini = 0, mfat, nbig = 0, msec, total;
	uint32_t *fatt, *mini_next, *start = (uint32_t *)calloc(n ? n : 1u, 4u);
	uint8_t *f;
	size_t cap, mini_bytes = 0;
	uint32_t *mstart = (uint32_t *)calloc(n ? n : 1u, 4u);

	if (!start || !mstart) {
		free(start);
		free(mstart);
		w->oom = 1;
		return;
	}
	for (i = 0; i < n; i++) {
		if (e[i].len == 0)
			continue;
		if (e[i].len < 4096u) {
			mstart[i] = nmini;
			nmini += (uint32_t)((e[i].len + 63u) / 64u);
			mini_bytes += (size_t)((e[i].len + 63u) / 64u) * 64u;
		} else {
			nbig += (unsigned)((e[i].len + 511u) / 512u);
		}
	}
	mfat = (nmini + 127u) / 128u;
	msec = (unsigned)((mini_bytes + 511u) / 512u);
	for (;;) {
		total = fat + mfat + dsec + msec + nbig;
		if ((total + 127u) / 128u <= fat)
			break;
		fat++;
	}
	if (fat > 109u) {
		free(start);
		free(mstart);
		w->oom = 1;
		return;
	}
	cap = ((size_t)total + 1u) * 512u;
	f = (uint8_t *)calloc(1, cap);
	fatt = (uint32_t *)calloc((size_t)fat * 128u, 4u);
	mini_next = (uint32_t *)calloc(nmini ? nmini : 1u, 4u);
	if (!f || !fatt || !mini_next) {
		free(f); free(fatt); free(mini_next); free(start); free(mstart);
		w->oom = 1;
		return;
	}
	{
		unsigned sec_mfat = fat, sec_dir = fat + mfat, sec_mini = sec_dir + dsec, sec_big = sec_mini + msec;
		uint32_t big_at = sec_big;
		size_t base = w->n;

		memcpy(f, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 8);
		f[0x18] = 0x3e; f[0x1a] = 3; f[0x1c] = 0xfe; f[0x1d] = 0xff; f[0x1e] = 9; f[0x20] = 6;
		#define S32(o, v) do { uint32_t v_ = (v); f[(o)] = (uint8_t)v_; f[(o) + 1] = (uint8_t)(v_ >> 8); f[(o) + 2] = (uint8_t)(v_ >> 16); f[(o) + 3] = (uint8_t)(v_ >> 24); } while (0)
		S32(0x2c, fat);
		S32(0x30, sec_dir);
		S32(0x38, 4096u);
		S32(0x3c, mfat ? sec_mfat : 0xfffffffeu);
		cw_field(m, (uint32_t)base + 0x40u, 4, CW_F_COUNT);
		S32(0x40, cw_lie(l, CW_L_COUNT) ? (uint32_t)l->count_claim : mfat);
		S32(0x44, 0xfffffffeu);
		for (i = 0; i < 109u; i++)
			S32(0x4c + 4u * i, i < fat ? i : 0xffffffffu);
		for (i = 0; i < fat * 128u; i++)
			fatt[i] = 0xffffffffu;
		for (i = 0; i < fat; i++)
			fatt[i] = 0xfffffffdu;
		for (i = 0; i < mfat; i++)
			fatt[sec_mfat + i] = i + 1u == mfat ? 0xfffffffeu : sec_mfat + i + 1u;
		for (i = 0; i < dsec; i++)
			fatt[sec_dir + i] = i + 1u == dsec ? (cw_lie(l, CW_L_CYCLE) ? sec_dir : 0xfffffffeu) : sec_dir + i + 1u;
		for (i = 0; i < msec; i++)
			fatt[sec_mini + i] = i + 1u == msec ? 0xfffffffeu : sec_mini + i + 1u;
		for (i = 0; i < n; i++) {
			if (e[i].len >= 4096u) {
				unsigned sc = (unsigned)((e[i].len + 511u) / 512u);

				start[i] = big_at;
				for (k = 0; k < sc; k++)
					fatt[big_at + k] = k + 1u == sc ? 0xfffffffeu : big_at + k + 1u;
				memcpy(f + ((size_t)big_at + 1u) * 512u, e[i].data, (size_t)e[i].len);
				big_at += sc;
			} else if (e[i].len) {
				unsigned sc = (unsigned)((e[i].len + 63u) / 64u);

				start[i] = mstart[i];
				for (k = 0; k < sc; k++)
					mini_next[mstart[i] + k] = k + 1u == sc ? 0xfffffffeu : mstart[i] + k + 1u;
				memcpy(f + ((size_t)sec_mini + 1u) * 512u + (size_t)mstart[i] * 64u, e[i].data, (size_t)e[i].len);
			} else {
				start[i] = 0xfffffffeu;
			}
		}
		for (i = 0; i < fat * 128u; i++)
			S32(512u + 4u * i, fatt[i]);
		for (i = 0; i < nmini; i++)
			S32((size_t)(sec_mfat + 1u) * 512u + 4u * i, mini_next[i]);
		for (i = 0; i < ents; i++) {
			uint8_t *d = f + ((size_t)sec_dir + 1u + i / 4u) * 512u + 128u * (i % 4u);
			uint32_t nl = i ? cw_nlen(&e[i - 1u]) : 10u;
			const char *nm = i ? e[i - 1u].name : "Root Entry";
			uint32_t kk;

			if (nl > 31u)
				nl = 31u;
			for (kk = 0; kk < nl; kk++)
				d[2u * kk] = (uint8_t)nm[kk];
			d[0x40] = (uint8_t)(2u * nl + 2u); d[0x41] = 0;
			d[0x42] = i == 0 ? 5 : (e[i - 1u].kind == CW_DIR ? 1 : 2);
			memset(d + 0x44, 0xff, 12);
			if (i == 0) {
				S32((size_t)((d - f) + 0x4c), ents > 1 ? 1u : 0xffffffffu);
				S32((size_t)((d - f) + 0x74), nmini ? sec_mini : 0xfffffffeu);
					{ uint64_t sz = (uint64_t)nmini * 64u; unsigned b; for (b = 0; b < 8; b++) d[0x78 + b] = (uint8_t)(sz >> (8u * b)); }
			} else {
				uint32_t st = cw_lie(l, CW_L_OFFSET) ? total + 40u : start[i - 1u];
				uint64_t sz = cw_cu(&e[i - 1u]);
				unsigned b;

				S32((size_t)((d - f) + 0x48), i + 1u < ents ? i + 1u : (cw_lie(l, CW_L_CYCLE) ? 1u : 0xffffffffu));
				S32((size_t)((d - f) + 0x74), st);
				for (b = 0; b < 8; b++)
					d[0x78 + b] = (uint8_t)(sz >> (8u * b));
				cw_field(m, (uint32_t)base + (uint32_t)(d - f) + 0x74u, 4, CW_F_OFFSET);
				cw_field(m, (uint32_t)base + (uint32_t)(d - f) + 0x78u, 4, CW_F_LEN);
			}
		}
		#undef S32
		cw_put(w, f, cap);
	}
	free(f); free(fatt); free(mini_next); free(start); free(mstart);
}

/* ---- pdf ---------------------------------------------------------------------------------------------------
 * "%PDF-1.7", one stream object per member (/Length = claim or len), an xref, a trailer and startxref. The engine finds
 * objects by scanning, so the lies that matter are in the objects: claim -> /Length; share -> the member reuses the
 * object NUMBER of that one (a number defined twice); COUNT -> the xref section's count and /Size; OFFSET -> startxref;
 * CYCLE -> a second xref section whose /Prev names the first and the first's /Prev names the second (a loop), and an
 * object that names itself; NOEND -> no xref / trailer / %%EOF; EXTRA -> the catalog, file specification, document information,
 * metadata, object stream and xref stream a real document has; CRYPT -> an /Encrypt entry in the trailer. Names are written as /Name (bytes).
 */
static CW_UNUSED void cw_pdf(struct cw *w, const struct cw_ent *e, unsigned n, const struct cw_lies *l, struct cw_map *m)
{
	unsigned i;
	size_t xref_at, base = w->n;
	char t[640];

	cw_str(w, "%PDF-1.7\n");
	for (i = 0; i < n; i++) {
		unsigned num = e[i].share ? (unsigned)e[i].share : i + 1u;
		int k;

		k = snprintf(t, sizeof t, "%u 0 obj\n<< /Type /EmbeddedFile /Length ", num);
		cw_put(w, t, (size_t)k);
		cw_field(m, (uint32_t)(w->n - base), 8, CW_F_LEN);
		k = snprintf(t, sizeof t, "%08llu", (unsigned long long)cw_cu(&e[i]) % 100000000ull);
		cw_put(w, t, (size_t)k);
		cw_str(w, " /Name (");
		cw_put(w, e[i].name, cw_nlen(&e[i]));
		cw_str(w, ")");
		if (cw_lie(l, CW_L_CYCLE)) {
			k = snprintf(t, sizeof t, " /Parent %u 0 R", num);
			cw_put(w, t, (size_t)k);
		}
		cw_str(w, " >>\nstream\n");
		cw_put(w, e[i].data, (size_t)e[i].len);
		cw_str(w, "\nendstream\nendobj\n");
	}
	if (cw_lie(l, CW_L_EXTRA)) {
		/* the objects a real document carries besides its streams: a catalog with an OpenAction that runs script and a names tree,
		 * a file specification pointing at the first member (/EF), the document information, a metadata stream, an object stream
		 * and a cross reference stream. Each is what one branch of pdf_dict.c / pdf_docinfo.c / pdf_entries.c reads. */
		unsigned b = n + 1u;
		int k;

		k = snprintf(t, sizeof t, "%u 0 obj\n<< /Type /Catalog /Pages 99 0 R /OpenAction << /S /JavaScript /JS %u 0 R >> "
			     "/Names << /EmbeddedFiles << /Names [(a.txt) %u 0 R] >> >> /AA << /O << /S /JavaScript /JS (app.alert\\(2\\)) >> >> >>\nendobj\n", b, b + 6u, b + 1u);
		cw_put(w, t, (size_t)k);
		k = snprintf(t, sizeof t, "%u 0 obj\n<< /Type /Filespec /F (a.txt) /UF (a.txt) /EF << /F 1 0 R /UF 1 0 R >> >>\nendobj\n", b + 1u);
		cw_put(w, t, (size_t)k);
		k = snprintf(t, sizeof t, "%u 0 obj\n<< /Title (Doc \\(title\\)) /Author <4b6f6665> /Producer (P#41) /Creator (Kof) /Subject [1 2] "
			     "/Keywords << /A (x) >> /CreationDate (D:20260101000000Z) >>\nendobj\n", b + 2u);
		cw_put(w, t, (size_t)k);
		k = snprintf(t, sizeof t, "%u 0 obj\n<< /Type /Metadata /Subtype /XML /Length 21 >>\nstream\n<x:xmpmeta></x:xmpmeta>\nendstream\nendobj\n", b + 3u);
		cw_put(w, t, (size_t)k);
		k = snprintf(t, sizeof t, "%u 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Length 18 >>\nstream\n99 0 << /A 1 >>  \nendstream\nendobj\n", b + 4u);
		cw_put(w, t, (size_t)k);
		k = snprintf(t, sizeof t, "%u 0 obj\n<< /Length 13 >>\nstream\napp.alert(1);\nendstream\nendobj\n", b + 6u);       /* the script the OpenAction runs */
		cw_put(w, t, (size_t)k);
		k = snprintf(t, sizeof t, "%u 0 obj\n<< /Type /FontDescriptor /FontName /BCDEEE+Calibri /FontFile2 %u 0 R >>\nendobj\n", b + 7u, b + 8u);
		cw_put(w, t, (size_t)k);
		k = snprintf(t, sizeof t, "%u 0 obj\n<< /Length 4 >>\nstream\nWOFF\nendstream\nendobj\n", b + 8u);                    /* the font file */
		cw_put(w, t, (size_t)k);
		k = snprintf(t, sizeof t, "%u 0 obj\n<< /Type /XRef /Size %u /W [1 2 1] /Root %u 0 R /Info %u 0 R /Length 4 >>\nstream\n", b + 5u, b + 9u, b, b + 2u);
		cw_put(w, t, (size_t)k);
		cw_u32(w, 1);                                  /* one row of the stream: type 1, offset 0, generation 0 */
		cw_str(w, "\nendstream\nendobj\n");
	}
	if (cw_lie(l, CW_L_NOEND))
		return;
	xref_at = w->n;
	{
		uint64_t cnt = cw_lie(l, CW_L_COUNT) ? l->count_claim : n + 1u;
		int k = snprintf(t, sizeof t, "xref\n0 %llu\ntrailer\n<< /Size %llu /Root %u 0 R", (unsigned long long)cnt, (unsigned long long)cnt,
				 cw_lie(l, CW_L_EXTRA) ? n + 1u : 1u);

		cw_put(w, t, (size_t)k);
		if (cw_lie(l, CW_L_EXTRA)) {
			k = snprintf(t, sizeof t, " /Info %u 0 R", n + 3u);
			cw_put(w, t, (size_t)k);
		}
		if (cw_lie(l, CW_L_CRYPT)) {
			k = snprintf(t, sizeof t, " /Encrypt << /Filter /Standard /V 1 /R 2 >>");
			cw_put(w, t, (size_t)k);
		}
		if (cw_lie(l, CW_L_CYCLE)) {
			k = snprintf(t, sizeof t, " /Prev %zu", xref_at);
			cw_put(w, t, (size_t)k);
		}
		cw_str(w, " >>\n");
	}
	if (cw_lie(l, CW_L_CYCLE)) {
		size_t second = w->n;
		int k = snprintf(t, sizeof t, "xref\n0 1\ntrailer\n<< /Size 1 /Prev %zu >>\n", xref_at);

		cw_put(w, t, (size_t)k);
		xref_at = second;
	}
	cw_str(w, "startxref\n");
	cw_field(m, (uint32_t)(w->n - base), 8, CW_F_OFFSET);
	{
		int k = snprintf(t, sizeof t, "%08llu", cw_lie(l, CW_L_OFFSET) ? (unsigned long long)l->off_claim % 100000000ull : (unsigned long long)xref_at);

		cw_put(w, t, (size_t)k);
	}
	cw_str(w, "\n%%EOF\n");
}

/* ---- gzip --------------------------------------------------------------------------------------------------
 * one member holding the FIRST entry as stored deflate blocks (65535 at most each), FNAME = its name. claim -> the
 * trailer's ISIZE; NOEND -> no trailer. One member only, by the format.
 */
static CW_UNUSED void cw_gzip(struct cw *w, const struct cw_ent *e, unsigned n, const struct cw_lies *l, struct cw_map *m)
{
	uint64_t pos = 0, len = n ? e[0].len : 0, left;
	uint32_t nl = n ? cw_nlen(&e[0]) : 0;

	cw_u8(w, 0x1f); cw_u8(w, 0x8b); cw_u8(w, 8); cw_u8(w, 0x08); cw_u32(w, 0); cw_u8(w, 0); cw_u8(w, 3);
	if (n) {
		cw_put(w, e[0].name, nl);
		cw_u8(w, 0);
	}
	do {
		left = len - pos > 65535u ? 65535u : len - pos;
		cw_u8(w, pos + left >= len ? 1 : 0);
		cw_u16(w, (uint32_t)left);
		cw_u16(w, (uint32_t)~left);
		if (n)
			cw_put(w, (const uint8_t *)e[0].data + pos, (size_t)left);
		pos += left;
	} while (pos < len);
	if (!cw_lie(l, CW_L_NOEND)) {
		cw_u32(w, n ? cw_crc32(e[0].data, e[0].len) : 0u);
		cw_field(m, (uint32_t)w->n, 4, CW_F_LEN);
		cw_u32(w, (uint32_t)(n ? cw_cu(&e[0]) : 0u));
	}
}

/* ---- the table the tests walk ---------------------------------------------------------------------------- */

typedef void (*cw_fn)(struct cw *, const struct cw_ent *, unsigned, const struct cw_lies *, struct cw_map *);

struct cw_format {
	const char *name;
	cw_fn       write;
	unsigned    lead;               /* children the engine opens BEFORE the members (7z: the file list) */
	int         gathered;           /* the members come out as ONE child, their bytes end to end (the OLE document body) */
	unsigned    lies;               /* the CW_L_* this format has a field for */
	unsigned    max_members;        /* the most members one archive can hold (counts are 16 bit in cab and zip) */
};

static const struct cw_format cw_formats[] = {
	{ "zip",  cw_zip,  0, 0, CW_L_COUNT | CW_L_OFFSET | CW_L_CYCLE | CW_L_NOEND | CW_L_EXTRA | CW_L_CRYPT, 65535u },
	{ "tar",  cw_tar,  0, 0, CW_L_CYCLE | CW_L_NOEND | CW_L_EXTRA,             1u << 20 },
	{ "rar",  cw_rar,  0, 0, CW_L_NOEND,                                       1u << 20 },
	{ "lha",  cw_lha,  0, 0, CW_L_NOEND | CW_L_EXTRA,                          1u << 20 },
	{ "arj",  cw_arj,  0, 0, CW_L_NOEND,                                       1u << 20 },
	{ "cab",  cw_cab,  0, 0, CW_L_COUNT | CW_L_OFFSET | CW_L_CYCLE | CW_L_EXTRA | CW_L_CRYPT, 65535u },
	{ "chm",  cw_chm,  0, 0, CW_L_COUNT | CW_L_OFFSET | CW_L_CYCLE,            1u << 16 },
	{ "7z",   cw_7z,   1, 0, CW_L_COUNT | CW_L_OFFSET | CW_L_NOEND | CW_L_EXTRA | CW_L_CRYPT, 1u << 16 },
	{ "ole",  cw_ole,  0, 1, CW_L_COUNT | CW_L_OFFSET | CW_L_CYCLE,            4096u },
	{ "pdf",  cw_pdf,  0, 0, CW_L_COUNT | CW_L_OFFSET | CW_L_CYCLE | CW_L_NOEND | CW_L_EXTRA | CW_L_CRYPT, 1u << 16 },
	{ "gzip", cw_gzip, 0, 0, CW_L_NOEND,                                       1u },
	{ "rar5", cw_rar5, 0, 0, CW_L_NOEND | CW_L_EXTRA | CW_L_CRYPT,             1u << 20 }
};
#define CW_NFORMATS (sizeof cw_formats / sizeof cw_formats[0])

/* The index of a format by name, or CW_NFORMATS. */
static CW_UNUSED unsigned cw_find(const char *name)
{
	unsigned i;

	for (i = 0; i < CW_NFORMATS; i++)
		if (!strcmp(cw_formats[i].name, name))
			return i;
	return (unsigned)CW_NFORMATS;
}

/* `inner` as the one member (called "inner.bin") of an archive of format f: the link of a nesting chain. */
static CW_UNUSED struct cw cw_wrap(unsigned f, const struct cw *inner)
{
	struct cw w = { 0 };
	struct cw_ent e;

	memset(&e, 0, sizeof e);
	e.name = "inner.bin";
	e.data = inner->p;
	e.len = inner->n;
	cw_formats[f].write(&w, &e, 1, NULL, NULL);
	return w;
}

#endif /* KOF_TESTS_CTR_WRITERS_H */
