/*
 * engine3_containers - container defects fixed in fix_engine3 that the ctr_* matrices do not reach.
 *
 *   BE-9     a zip with bytes in front of it (an SFX stub, a junk prefix) is opened: the members are children. A file with
 *            "PK\5\6" bytes at its end and no directory where they point is NOT a zip (the probe is not a four byte test).
 *   BE-2     a deflate zip entry whose output ends exactly at the declared-ratio clamp (KOF_EXPAND_FLOOR, 1 MiB) is whole and
 *            reports nothing; one byte more is cut and says so.
 *   WP2-D1c  a V7 tar (no "ustar" magic, a right checksum) is opened member by member; a tar whose walk meets bytes that are
 *            neither zero blocks nor a header is DAMAGED, not clean.
 *
 * Why the old tests missed them: (a) kof_zip_sniff and the tar walk's magic test were executed only with a signature at offset
 * 0 / a ustar header (no boundary input: prefix, no magic); the matrix writers write ustar only.
 */
#define _GNU_SOURCE
#include "hostile_engine.h"
#include "../lib/ctr_writers.h"
#include "../lib/ctr_scan.h"

static uint8_t d0[100], d1[200], d2[300];

static void ents(struct cw_ent *e)
{
	memset(e, 0, 3 * sizeof *e);
	e[0].name = "a.txt"; e[0].data = d0; e[0].len = sizeof d0;
	e[1].name = "b.txt"; e[1].data = d1; e[1].len = sizeof d1;
	e[2].name = "c.txt"; e[2].data = d2; e[2].len = sizeof d2;
}

static unsigned members_found(const struct cs_run *r)
{
	unsigned k = 0;

	k += cs_find(r, ":a.txt") != NULL && cs_find(r, ":a.txt")->hash == cs_fnv(d0, sizeof d0);
	k += cs_find(r, ":b.txt") != NULL && cs_find(r, ":b.txt")->hash == cs_fnv(d1, sizeof d1);
	k += cs_find(r, ":c.txt") != NULL && cs_find(r, ":c.txt")->hash == cs_fnv(d2, sizeof d2);
	return k;
}

/* ---- BE-9 ---------------------------------------------------------------------------------------------- */

static int zip_prefix(void *unused)
{
	static const size_t pre[] = { 1, 3, 4, 100, 4096, 70000 };
	struct cw_ent e[3];
	struct cw w = { 0 };
	struct kof_scan_option o = cs_opt();
	unsigned i;

	(void)unused;
	cs_fill(d0, sizeof d0, 0);
	cs_fill(d1, sizeof d1, 1);
	cs_fill(d2, sizeof d2, 2);
	ents(e);
	cw_zip(&w, e, 3, NULL, NULL);
	for (i = 0; i < sizeof pre / sizeof pre[0]; i++) {
		struct cw x = { 0 };
		struct cs_run r;
		uint8_t *junk = (uint8_t *)malloc(pre[i]);
		size_t k;

		if (!junk)
			return 9;
		for (k = 0; k < pre[i]; k++)
			junk[k] = (uint8_t)(0x80u | (k * 131u + 7u));   /* never 'P': no signature by accident */
		cw_put(&x, junk, pre[i]);
		cw_put(&x, w.p, w.n);
		free(junk);
		if (cs_scan(x.p, x.n, "x.bin", &o, &r))
			return 9;
		CK(members_found(&r) == 3, "zip behind %zu junk bytes: %u of 3 members opened whole (BE-9), %u objects", pre[i], members_found(&r), r.n);
		cs_free(&r);
		cw_free(&x);
	}
	/* The control: the same bytes with no prefix. */
	{
		struct cs_run r;

		if (cs_scan(w.p, w.n, "x.zip", &o, &r))
			return 9;
		CK(members_found(&r) == 3, "zip control: %u of 3", members_found(&r));
		cs_free(&r);
	}
	cw_free(&w);
	return he_fails != 0 ? 1 : 0;
}

/* A file that merely ENDS like a zip is not one: the end record alone, then the end record with a directory offset that points at
 * nothing, then a real directory signature that is not where the record says. Each opens as nothing and nothing is a child. */
static int zip_probe_strict(void *unused)
{
	struct kof_scan_option o = cs_opt();
	uint8_t buf[600];
	unsigned variant;

	(void)unused;
	for (variant = 0; variant < 3; variant++) {
		struct cs_run r;
		size_t n;

		memset(buf, 0xa5, sizeof buf);
		n = 0;
		/* a lone end record at the very end: 22 bytes, comment length 0 */
		memset(buf + sizeof buf - 22, 0, 22);
		buf[sizeof buf - 22] = 'P'; buf[sizeof buf - 21] = 'K'; buf[sizeof buf - 20] = 5; buf[sizeof buf - 19] = 6;
		if (variant == 1) {          /* its directory size and offset name bytes that are not a central header */
			buf[sizeof buf - 22 + 12] = 40;       /* cd size */
			buf[sizeof buf - 22 + 16] = 100;      /* cd offset */
		}
		if (variant == 2) {          /* a central header signature elsewhere, not where the record points */
			buf[300] = 'P'; buf[301] = 'K'; buf[302] = 1; buf[303] = 2;
			buf[sizeof buf - 22 + 12] = 40;
			buf[sizeof buf - 22 + 16] = 120;
		}
		n = sizeof buf;
		if (cs_scan(buf, n, "x.bin", &o, &r))
			return 9;
		CK(r.n == 1, "an end record with no directory behind it (variant %u) opens children: %u objects", variant, r.n);
		cs_free(&r);
	}
	return he_fails != 0 ? 1 : 0;
}

/* ---- BE-2 ---------------------------------------------------------------------------------------------- */

struct bits { struct cw *w; uint32_t acc; unsigned n; };

static void b_put(struct bits *b, uint32_t v, unsigned n)          /* LSB first (header and extra bits) */
{
	unsigned i;

	for (i = 0; i < n; i++) {
		b->acc |= ((v >> i) & 1u) << b->n;
		if (++b->n == 8) { cw_u8(b->w, b->acc); b->acc = 0; b->n = 0; }
	}
}

static void b_code(struct bits *b, uint32_t code, unsigned n)      /* a Huffman code, MSB first */
{
	unsigned i;

	for (i = n; i-- > 0; )
		b_put(b, (code >> i) & 1u, 1);
}

static void b_lit(struct bits *b, unsigned c)                     /* fixed table, literal or length symbol */
{
	if (c < 144)       b_code(b, 0x30u + c, 8);
	else if (c < 256)  b_code(b, 0x190u + (c - 144), 9);
	else if (c < 280)  b_code(b, c - 256, 7);
	else               b_code(b, 0xc0u + (c - 280), 8);
}

static void b_match(struct bits *b, unsigned len)                  /* a match of `len` (3..258) at distance 1 */
{
	static const unsigned base[28] = { 3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227 };
	static const unsigned xb[28] = { 0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5 };
	unsigned k;

	if (len == 258) {
		b_lit(b, 285);
	} else {
		for (k = 27; base[k] > len; k--)
			;
		b_lit(b, 257 + k);
		b_put(b, len - base[k], xb[k]);
	}
	b_code(b, 0, 5);                                                /* distance code 0: 1 */
}

/* A raw deflate stream (one fixed block) of n zero bytes: a literal, then matches of 258. n >= 4. */
static void deflate_zeros(struct cw *w, uint64_t n)
{
	struct bits b = { w, 0, 0 };
	uint64_t left = n - 1u;

	b_put(&b, 1, 1); b_put(&b, 1, 2);                               /* final, fixed */
	b_lit(&b, 0);
	while (left >= 258u) { b_match(&b, 258); left -= 258u; }
	if (left >= 3u) { b_match(&b, (unsigned)left); left = 0; }
	while (left) { b_lit(&b, 0); left--; }
	b_lit(&b, 256);
	if (b.n)
		cw_u8(w, b.acc);
}

static int zip_clamp_edge(void *unused)
{
	static const uint64_t sizes[] = { 1048575u, 1048576u, 1048577u, 1048576u + 258u };
	struct kof_scan_option o = cs_opt();
	unsigned i;

	(void)unused;
	for (i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
		struct cw z = { 0 }, a = { 0 };
		struct cw_ent e;
		struct cs_run r;
		const struct cs_obj *m;
		uint64_t n = sizes[i];
		int whole = n <= 1048576u;

		deflate_zeros(&z, n);
		memset(&e, 0, sizeof e);
		e.name = "m.bin"; e.data = z.p; e.len = z.n; e.method = 8;
		e.claimed = 1; e.claim_packed = z.n; e.claim_unpacked = n;
		cw_zip(&a, &e, 1, NULL, NULL);
		if (cs_scan(a.p, a.n, "x.zip", &o, &r))
			return 9;
		m = cs_find(&r, ":m.bin");
		CK(m != NULL, "clamp edge %llu: the member is a child", (unsigned long long)n);
		if (m && whole) {
			CK(m->len == n, "clamp edge %llu: the member is whole (%llu bytes)", (unsigned long long)n, (unsigned long long)m->len);
			CK(m->broken == 0 && r.o[0].broken == 0, "clamp edge %llu: nothing is reported (member %u, root %u) (BE-2)", (unsigned long long)n, m->broken, r.o[0].broken);
			CK(r.limit_hits == 0, "clamp edge %llu: limit_hits %llu (BE-2)", (unsigned long long)n, (unsigned long long)r.limit_hits);
		}
		if (m && !whole) {
			CK(m->len == 1048576u, "clamp edge %llu: the member is cut at the floor (%llu)", (unsigned long long)n, (unsigned long long)m->len);
			CK(m->broken == KOF_BROKEN_LIMIT && r.limit_hits >= 1, "clamp edge %llu: the cut is said (member %u, limit_hits %llu)", (unsigned long long)n, m->broken, (unsigned long long)r.limit_hits);
		}
		cs_free(&r);
		cw_free(&z);
		cw_free(&a);
	}
	return he_fails != 0 ? 1 : 0;
}

/* ---- WP2-D1c ------------------------------------------------------------------------------------------- */

static void v7_header(struct cw *w, const char *name, size_t size, int bad_sum)
{
	uint8_t h[512];
	unsigned sum = 0, i;
	char f[16];

	memset(h, 0, sizeof h);
	memcpy(h, name, strlen(name));
	snprintf(f, sizeof f, "%07o", 0644u);        memcpy(h + 100, f, 8);
	snprintf(f, sizeof f, "%07o", 0u);           memcpy(h + 108, f, 8);
	snprintf(f, sizeof f, "%07o", 0u);           memcpy(h + 116, f, 8);
	snprintf(f, sizeof f, "%011o", (unsigned)size); memcpy(h + 124, f, 12);
	snprintf(f, sizeof f, "%011o", 0u);          memcpy(h + 136, f, 12);
	h[156] = '0';                                /* a regular file; no "ustar" anywhere: the V7 shape */
	memset(h + 148, ' ', 8);
	for (i = 0; i < 512; i++)
		sum += h[i];
	if (bad_sum)
		sum += 1u;
	snprintf(f, sizeof f, "%06o", sum);
	memcpy(h + 148, f, 6);
	h[154] = 0; h[155] = ' ';
	cw_put(w, h, sizeof h);
}

static void v7_body(struct cw *w, const uint8_t *d, size_t n)
{
	static const uint8_t z[512];

	cw_put(w, d, n);
	if (n % 512u)
		cw_put(w, z, 512u - n % 512u);
}

static int tar_v7(void *unused)
{
	struct kof_scan_option o = cs_opt();
	struct cw w = { 0 };
	struct cs_run r;
	static const uint8_t zero[1024];
	static const uint8_t junk[512] = { 'J', 'U', 'N', 'K' };

	(void)unused;
	cs_fill(d0, sizeof d0, 0);
	cs_fill(d1, sizeof d1, 1);
	cs_fill(d2, sizeof d2, 2);
	v7_header(&w, "a.txt", sizeof d0, 0); v7_body(&w, d0, sizeof d0);
	v7_header(&w, "b.txt", sizeof d1, 0); v7_body(&w, d1, sizeof d1);
	v7_header(&w, "c.txt", sizeof d2, 0); v7_body(&w, d2, sizeof d2);
	cw_put(&w, zero, sizeof zero);
	if (cs_scan(w.p, w.n, "x.tar", &o, &r))
		return 9;
	CK(members_found(&r) == 3, "V7 tar: %u of 3 members opened whole (WP2-D1c), %u objects", members_found(&r), r.n);
	CK(r.o[0].broken == 0, "V7 tar: a sound archive is not reported (%u)", r.o[0].broken);
	cs_free(&r);
	cw_free(&w);

	/* a V7 archive with a good member, then a block of junk (neither zero nor a header), then no end: the walk ends there and SAYS so */
	memset(&w, 0, sizeof w);
	v7_header(&w, "a.txt", sizeof d0, 0); v7_body(&w, d0, sizeof d0);
	cw_put(&w, junk, sizeof junk);
	if (cs_scan(w.p, w.n, "x.tar", &o, &r))
		return 9;
	CK(cs_find(&r, ":a.txt") != NULL, "V7 tar then junk: the first member is opened");
	CK(r.o[0].broken == KOF_BROKEN_DAMAGED, "V7 tar then junk: the root says DAMAGED (%u)", r.o[0].broken);
	cs_free(&r);
	cw_free(&w);

	/* a block that is not a tar at all (right size, no magic, a wrong checksum): not a tar, no child, no report of one */
	memset(&w, 0, sizeof w);
	v7_header(&w, "a.txt", sizeof d0, 1);
	v7_body(&w, d0, sizeof d0);
	if (cs_scan(w.p, w.n, "x.bin", &o, &r))
		return 9;
	CK(r.n == 1, "a header with a wrong checksum and no magic is not a tar: %u objects", r.n);
	cs_free(&r);
	cw_free(&w);
	return he_fails != 0 ? 1 : 0;
}

int main(void)
{
	static const struct { int (*fn)(void *); const char *what; } jobs[] = {
		{ zip_prefix, "BE-9 zip behind a prefix" }, { zip_probe_strict, "BE-9 an end record is not a zip" }, { zip_clamp_edge, "BE-2 ratio clamp edge" }, { tar_v7, "WP2-D1c V7 tar" }
	};
	unsigned i, bad = 0;

	cs_eng = keng_open(HE_DB);
	for (i = 0; i < sizeof jobs / sizeof jobs[0]; i++) {
		struct he_status st = he_child(jobs[i].fn, NULL, 120);

		printf("engine3_containers %-34s %s\n", jobs[i].what, he_how(st));
		bad |= !he_ok(st);
	}
	printf("engine3_containers: %s\n", bad ? "FAIL" : "ok");
	return bad ? 1 : 0;
}
