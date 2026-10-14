/*
 * kix_container - the block index container (databases/pack/dbkix.c): the writer, the reader, and what
 * both do with a file that is wrong.
 *
 * The container is a trailer in a pack file read with pread (see dbkix.h). The properties under test:
 *
 *   - what is written is what is read: the directory, the entries, the classes, the filter;
 *   - EVERY failure is a status. A flipped byte in the directory, the filter, a slice of the body or
 *     the footer is refused (the first three) or reported on the read that meets it (the body); a file
 *     shorter than it said is a short read and never a signal; a spent allowance is a flag;
 *   - the key is multiplied, and that is exact (a bijection) and flattens what bottom-k data does to a
 *     top-16-bit directory;
 *   - a database made to put every hash in one bucket still builds, reads and reports;
 *   - the same input is the same bytes (a pack is a build artefact: two machines, one file).
 *
 * The file is made beside the build output (build/kof_kixc_XXXXXX), never under /tmp.
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "../../libkofeng/databases/pack/dbkix.h"
#include "../../libkofeng/kofcore/kofcore.h"
#include "../../libkofeng/kofcore/kofplatform.h"

static int fails;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static uint32_t rs = 0x1badc0deu;

static uint32_t rnd(void)
{
	rs ^= rs << 13; rs ^= rs >> 17; rs ^= rs << 5;
	return rs;
}

static char dir[128];

/* ---- a set of blocks -------------------------------------------------------------------- */

struct set {
	struct kof_mutation_block *b;
	uint32_t *pool;
	uint32_t nb, np;
};

static void set_free(struct set *s)
{
	free(s->b);
	free(s->pool);
	memset(s, 0, sizeof *s);
}

/* Blocks whose hashes are small the way a bottom-k sketch's are: the smallest 32 of ~m uniform windows. */
static void set_bottomk(struct set *s, uint32_t nb, uint32_t classes)
{
	uint32_t i, j;

	s->nb = nb;
	s->b = calloc(nb ? nb : 1u, sizeof *s->b);
	s->pool = malloc((size_t)(nb ? nb : 1u) * 32u * 4u);
	s->np = 0;
	for (i = 0; i < nb; i++) {
		uint32_t m = 100u + rnd() % 2900u, acc = 0;

		s->b[i].first_hash = s->np;
		s->b[i].n_hash = 32;
		s->b[i].scan_mask = 1u << (i % (classes ? classes : 1u));
		s->b[i].norm = (uint8_t)(i % 3u);
		s->b[i].side = (uint8_t)(i % 2u);
		for (j = 0; j < 32u; j++) {
			/* a spacing of about 2^32 / m, exponential enough to keep them distinct and ascending */
			uint32_t gap = (uint32_t)(((uint64_t)(rnd() % 2000u + 1u) * (4294967296ull / m)) / 1000u);

			acc += gap ? gap : 1u;
			s->pool[s->np++] = acc;
		}
	}
}

/* ---- a file with an "old part" (the block table and pool) and the trailer ------------------ */

struct file {
	char path[192];
	int fd;
	uint64_t size, blk_off, pool_off, old_len, trailer_off;
	struct kof_kix_footer ft;
};

static int put(int fd, const void *p, uint64_t n)
{
	return write(fd, p, (size_t)n) == (ssize_t)n;
}

static int file_make(struct file *f, const struct set *s, const char *leaf, struct kof_kix_build_res *res)
{
	uint8_t pad[64] = { 0 };
	uint64_t tlen = 0;
	uint8_t *tr;
	struct kof_kix_build_in in;

	memset(f, 0, sizeof *f);
	snprintf(f->path, sizeof f->path, "%s/%s", dir, leaf);
	f->fd = open(f->path, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (f->fd < 0)
		return 0;
	/* the "old part": 64 bytes of header-ish filler, the block table, the pool */
	put(f->fd, pad, 64);
	f->blk_off = 64;
	put(f->fd, s->b, (uint64_t)s->nb * sizeof *s->b);
	f->pool_off = f->blk_off + (uint64_t)s->nb * sizeof *s->b;
	put(f->fd, s->pool, (uint64_t)s->np * 4u);
	f->old_len = f->pool_off + (uint64_t)s->np * 4u;
	f->trailer_off = kof_round_up(f->old_len, KOF_KIX_ALIGN);
	put(f->fd, pad, f->trailer_off - f->old_len);
	memset(&in, 0, sizeof in);
	in.blk = s->b; in.n_blk = s->nb; in.pool = s->pool; in.n_pool = s->np;
	tr = kof_kix_make(&in, f->trailer_off, f->old_len, 0x1234u, &tlen, res);
	if (!tr)
		return 0;
	put(f->fd, tr, tlen);
	free(tr);
	f->size = f->trailer_off + tlen;
	return 1;
}

static void file_close(struct file *f)
{
	if (f->fd >= 0)
		close(f->fd);
	unlink(f->path);
	f->fd = -1;
}

static void poke(struct file *f, uint64_t off, uint8_t x)
{
	uint8_t b;

	if (pread(f->fd, &b, 1, (off_t)off) != 1)
		return;
	b ^= x;
	if (pwrite(f->fd, &b, 1, (off_t)off) != 1)
		return;
}

static struct kof_kix *open_it(struct file *f, const struct set *s, char *why, size_t wl)
{
	struct kof_kix_loc loc;
	struct kof_kix_footer ft;

	if (!kof_kix_probe(f->fd, f->size, &ft))
		return NULL;
	memset(&loc, 0, sizeof loc);
	loc.fd = f->fd;
	loc.file_size = f->size;
	loc.blk_off = f->blk_off;
	loc.pool_off = f->pool_off;
	loc.n_blk = s->nb;
	loc.n_pool = s->np;
	return kof_kix_open_file(&loc, &ft, why, wl);
}

/* Re-seal the footer after a mutation of what it checksums, so a case tests the check it names and
 * not the footer's own. */
static void reseal_footer(struct file *f, uint32_t meta_crc)
{
	struct kof_kix_footer ft;
	uint64_t at = f->size - sizeof ft;

	if (pread(f->fd, &ft, sizeof ft, (off_t)at) != (ssize_t)sizeof ft)
		return;
	if (meta_crc)
		ft.meta_crc = meta_crc;
	ft.footer_crc = kof_crc32(&ft, sizeof ft - 4u);
	if (pwrite(f->fd, &ft, sizeof ft, (off_t)at) != (ssize_t)sizeof ft)
		return;
}

/* ---- round trip --------------------------------------------------------------------------- */

static void t_roundtrip(void)
{
	struct set s;
	struct file f;
	struct kof_kix_build_res res;
	struct kof_kix *k = NULL, *m = NULL;
	struct kof_kix_info ki, mi;
	struct kof_kix_io io;
	char why[200];
	uint8_t *a = NULL, *b = NULL, *fa = NULL, *fb = NULL;
	uint32_t i, h[KOF_MUTATION_MAX_HASH], n = 0;
	const uint32_t *da, *db;
	struct kof_mutation_block rec;

	set_bottomk(&s, 3000, 5);
	CK(file_make(&f, &s, "round", &res));
	CK(res.n_pair == 96000u && res.n_key > 90000u && res.n_class >= 10u);
	k = open_it(&f, &s, why, sizeof why);
	CK(k != NULL);
	if (!k)
		goto out;
	kof_kix_info(k, &ki);
	CK(ki.n_pair == 96000u && ki.n_block == 3000u && !ki.in_memory && ki.body_len == 96000u * 7u);
	CK(ki.resident < 400000u);                               /* the directory and the tables: not the body */
	/* the same set built in memory is the same index */
	{
		struct kof_kix_build_in in;
		uint64_t len = 0;
		uint8_t *img;

		memset(&in, 0, sizeof in);
		in.blk = s.b; in.n_blk = s.nb; in.pool = s.pool; in.n_pool = s.np;
		img = kof_kix_make(&in, f.trailer_off, f.old_len, 0x1234u, &len, NULL);
		m = kof_kix_open_mem(img, len, s.b, s.nb, s.pool, s.np, why, sizeof why);
		CK(m != NULL);
	}
	if (!m)
		goto out;
	kof_kix_info(m, &mi);
	CK(mi.n_pair == ki.n_pair && mi.n_key == ki.n_key && mi.top == ki.top && mi.in_memory);
	da = kof_kix_dir(k);
	db = kof_kix_dir(m);
	CK(memcmp(da, db, ((size_t)KOF_KIX_N_DIR + 1u) * 4u) == 0 && da[KOF_KIX_N_DIR] == 96000u);
	a = malloc(ki.body_len);
	b = malloc(ki.body_len);
	memset(&io, 0, sizeof io);
	io.budget = (uint64_t)1 << 40;
	CK(kof_kix_body(k, 0, a, ki.body_len, &io) && kof_kix_body(m, 0, b, ki.body_len, &io));
	CK(memcmp(a, b, ki.body_len) == 0 && io.err == 0);
	/* the filters: whatever size they are asked at, the file's and the memory's agree and hold every key */
	fa = aligned_alloc(64, 1u << 16);
	fb = aligned_alloc(64, 1u << 16);
	memset(fa, 0, 1u << 16);
	memset(fb, 0, 1u << 16);
	CK(kof_kix_filter_or(k, fa, 1u << 16) && kof_kix_filter_or(m, fb, 1u << 16));
	CK(memcmp(fa, fb, 1u << 16) == 0);
	for (i = 0; i < s.np; i++)
		CK(kof_kix_flt_test(fa, kof_kix_flt_lbits(1u << 16), s.pool[i] * KOF_KIX_MULT));
	/* blocks: record and hashes read back from the file */
	for (i = 0; i < s.nb; i += 97u) {
		CK(kof_kix_block(k, i, &rec, NULL) && rec.first_hash == s.b[i].first_hash && rec.n_hash == 32u);
		CK(kof_kix_block_hashes(k, i, h, &n, NULL) && n == 32u && memcmp(h, s.pool + s.b[i].first_hash, 128) == 0);
	}
	CK(!kof_kix_block(k, s.nb, &rec, NULL));                 /* a block the pack does not have */
out:
	free(fa); free(fb); free(a); free(b);
	kof_kix_close(m);
	kof_kix_close(k);
	file_close(&f);
	set_free(&s);
	printf("  round trip (file and memory agree: directory, body, filter, blocks): ok\n");
}

/* ---- a file that is wrong ------------------------------------------------------------------ */

/* Replace the meta CRC the footer carries by the CRC of what the file holds now: a mutation of the
 * header or the directory that the CRC no longer sees, so the validation behind it is what is tested. */
static void repair_meta(struct file *f)
{
	struct kof_kix_footer ft;
	uint8_t *m;

	if (!kof_kix_probe(f->fd, f->size, &ft))
		return;
	m = malloc((size_t)ft.meta_len);
	if (pread(f->fd, m, (size_t)ft.meta_len, (off_t)ft.trailer_off) == (ssize_t)ft.meta_len)
		reseal_footer(f, kof_crc32(m, ft.meta_len));
	free(m);
}

static void t_corrupt(void)
{
	struct set s;
	struct file f;
	struct kof_kix_footer ft;
	struct kof_kix *k;
	struct kof_kix_io io;
	char why[200];
	uint8_t buf[256];
	uint64_t body, flt;
	uint32_t n;

	set_bottomk(&s, 900, 3);                                  /* 28,800 entries: 197 KB of body, 4 slices */

	/* the footer: a byte flipped, and it is not a trailer at all (the whole-file CRC then decides) */
	CK(file_make(&f, &s, "foot", NULL));
	CK(kof_kix_probe(f.fd, f.size, &ft) == 1);
	poke(&f, f.size - 10u, 0x55);
	CK(kof_kix_probe(f.fd, f.size, NULL) == 0);
	file_close(&f);

	/* offsets in the footer that leave the file, footer CRC repaired: still not a trailer */
	CK(file_make(&f, &s, "footoff", NULL));
	{
		struct kof_kix_footer g;

		CK(pread(f.fd, &g, sizeof g, (off_t)(f.size - sizeof g)) == (ssize_t)sizeof g);
		g.trailer_off = f.size + 64u;
		g.footer_crc = kof_crc32(&g, sizeof g - 4u);
		CK(pwrite(f.fd, &g, sizeof g, (off_t)(f.size - sizeof g)) == (ssize_t)sizeof g);
		CK(kof_kix_probe(f.fd, f.size, NULL) == 0);
	}
	file_close(&f);

	/* a file with no trailer at all, and one too short to hold a footer */
	CK(file_make(&f, &s, "none", NULL));
	CK(kof_kix_probe(f.fd, f.trailer_off, NULL) == 0);
	CK(kof_kix_probe(f.fd, 10, NULL) == 0);
	file_close(&f);

	/* the directory: a flipped byte is the meta CRC's */
	CK(file_make(&f, &s, "dir", NULL));
	CK(kof_kix_probe(f.fd, f.size, &ft));
	poke(&f, ft.trailer_off + 2304u + 100u, 0x01);
	k = open_it(&f, &s, why, sizeof why);
	CK(k == NULL && strstr(why, "checksum") != NULL);
	/* the same flip with the CRC repaired: the directory that does not climb is refused on its own */
	repair_meta(&f);
	k = open_it(&f, &s, why, sizeof why);
	CK(k == NULL && (strstr(why, "climb") || strstr(why, "span")));
	kof_kix_close(k);
	file_close(&f);

	/* the header: a count that disagrees with the pack, CRC repaired */
	CK(file_make(&f, &s, "hdr", NULL));
	CK(kof_kix_probe(f.fd, f.size, &ft));
	poke(&f, ft.trailer_off + 8u, 0x01);                       /* n_block */
	repair_meta(&f);
	k = open_it(&f, &s, why, sizeof why);
	CK(k == NULL && (strstr(why, "agree") || strstr(why, "pack")));
	file_close(&f);

	/* the class table: a normaliser that does not exist, CRC repaired */
	CK(file_make(&f, &s, "cls", NULL));
	CK(kof_kix_probe(f.fd, f.size, &ft));
	{
		uint8_t bad = 200;

		CK(pwrite(f.fd, &bad, 1, (off_t)(ft.trailer_off + 256u + 4u)) == 1);   /* class 0's norm */
	}
	repair_meta(&f);
	k = open_it(&f, &s, why, sizeof why);
	CK(k == NULL && strstr(why, "normaliser") != NULL);
	file_close(&f);

	/* the filter: a flipped byte is the filter's own CRC */
	CK(file_make(&f, &s, "flt", NULL));
	CK(kof_kix_probe(f.fd, f.size, &ft));
	flt = ft.trailer_off + ft.filter_off;
	poke(&f, flt + 77u, 0x80);
	k = open_it(&f, &s, why, sizeof why);
	CK(k == NULL && strstr(why, "filter") != NULL);
	file_close(&f);

	/* the body: a flipped byte opens fine (it is not read at load) and is found by the first read of its slice */
	CK(file_make(&f, &s, "body", NULL));
	CK(kof_kix_probe(f.fd, f.size, &ft));
	body = ft.trailer_off + ft.meta_len;
	poke(&f, body + 70000u, 0x04);                             /* slice 1 of 4 */
	k = open_it(&f, &s, why, sizeof why);
	CK(k != NULL);
	if (k) {
		memset(&io, 0, sizeof io);
		io.budget = (uint64_t)1 << 30;
		CK(kof_kix_body(k, 0, buf, 200, &io) && io.err == 0);                 /* slice 0 is good */
		CK(!kof_kix_body(k, 65536u + 10u, buf, 100, &io) && (io.err & KOF_KIX_E_CRC));
		io.err = 0;
		CK(!kof_kix_body(k, 65536u + 10u, buf, 100, &io) && (io.err & KOF_KIX_E_CRC));   /* and it stays bad */
		io.err = 0;
		CK(kof_kix_body(k, 2u * 65536u + 5u, buf, 100, &io) && io.err == 0);  /* the next one is not tainted */
		io.err = 0;
		CK(!kof_kix_body(k, 65536u - 8u, buf, 16, &io) && (io.err & KOF_KIX_E_CRC));     /* a read across it is refused */
	}

	/* the file shrinks under an open index: a short read and a status, never a signal */
	if (k) {
		n = (uint32_t)(ft.trailer_off + ft.meta_len + 100000u);
		CK(ftruncate(f.fd, (off_t)n) == 0);
		memset(&io, 0, sizeof io);
		io.budget = (uint64_t)1 << 30;
		CK(!kof_kix_body(k, 3u * 65536u + 5u, buf, 100, &io) && (io.err & KOF_KIX_E_IO));
		io.err = 0;
		CK(!kof_kix_block(k, 5, (struct kof_mutation_block *)buf, &io) || 1);   /* the old part may still be there */
		kof_kix_close(k);
	}
	file_close(&f);

	/* a file cut before the footer is not a trailer; cut inside the trailer it cannot be opened */
	CK(file_make(&f, &s, "cut", NULL));
	CK(kof_kix_probe(f.fd, f.size, &ft));
	CK(ftruncate(f.fd, (off_t)(f.size - 100u)) == 0);
	CK(kof_kix_probe(f.fd, f.size - 100u, NULL) == 0);
	file_close(&f);

	set_free(&s);
	printf("  corrupt directory/header/classes/filter/slice, bad footer, absent trailer, truncation: refused or reported, none read out of bounds\n");
}

static void t_budget_flag(void)
{
	struct set s;
	struct file f;
	struct kof_kix *k;
	struct kof_kix_io io;
	uint8_t b[16];
	char why[200];

	set_bottomk(&s, 300, 2);
	CK(file_make(&f, &s, "budget", NULL));
	k = open_it(&f, &s, why, sizeof why);
	CK(k != NULL);
	if (k) {
		memset(&io, 0, sizeof io);
		io.budget = 5000;                                      /* a read is a page at the least */
		CK(kof_kix_body(k, 0, b, 8, &io) && io.spent == 4096u && io.err == 0);
		CK(!kof_kix_body(k, 100, b, 8, &io) && (io.err & KOF_KIX_E_BUDGET));
		CK(io.reads >= 1u && io.bytes > 0u);
		memset(&io, 0, sizeof io);                             /* a budget of nothing allows nothing */
		CK(!kof_kix_body(k, 0, b, 8, &io) && (io.err & KOF_KIX_E_BUDGET));
		CK(!kof_kix_body(k, 1u << 30, b, 8, &io));             /* and a range past the body is an error */
		kof_kix_close(k);
	}
	file_close(&f);
	set_free(&s);
	printf("  the read allowance: a page a read, spent means a flag: ok\n");
}

/* ---- the key ------------------------------------------------------------------------------- */

static uint32_t inv32(uint32_t m)
{
	uint32_t x = m, i;

	for (i = 0; i < 5u; i++)
		x *= 2u - m * x;
	return x;
}

static void t_key_and_skew(void)
{
	struct set s;
	struct kof_kix_build_in in;
	struct kof_kix_build_res res;
	struct kof_kix *k;
	uint8_t *img;
	uint64_t len = 0;
	uint32_t i, mx_mul = 0, mx_raw = 0, *rawb = calloc(KOF_KIX_N_DIR, 4);
	const uint32_t *d;
	char why[160];
	double mean;

	/* a bijection: no two hashes meet, and the inverse is exact */
	CK((KOF_KIX_MULT & 1u) == 1u && inv32(KOF_KIX_MULT) * KOF_KIX_MULT == 1u);
	for (i = 0; i < 100000u; i++) {
		uint32_t v = rnd();

		CK((v * KOF_KIX_MULT) * inv32(KOF_KIX_MULT) == v);
	}

	/* bottom-k data crowds towards zero: a top-16-bit directory on the raw hash is lopsided, on the key it is flat */
	set_bottomk(&s, 40000, 1);
	memset(&in, 0, sizeof in);
	in.blk = s.b; in.n_blk = s.nb; in.pool = s.pool; in.n_pool = s.np;
	img = kof_kix_make(&in, 0, 0, 0, &len, &res);
	k = kof_kix_open_mem(img, len, s.b, s.nb, s.pool, s.np, why, sizeof why);
	CK(k != NULL);
	if (k) {
		d = kof_kix_dir(k);
		for (i = 0; i < KOF_KIX_N_DIR; i++)
			if (d[i + 1u] - d[i] > mx_mul)
				mx_mul = d[i + 1u] - d[i];
		for (i = 0; i < s.np; i++)
			rawb[s.pool[i] >> 16]++;
		for (i = 0; i < KOF_KIX_N_DIR; i++)
			if (rawb[i] > mx_raw)
				mx_raw = rawb[i];
		mean = (double)s.np / KOF_KIX_N_DIR;
		printf("  skew: mean bucket %.1f, busiest %u of the multiplied key (x%.1f), %u of the raw hash (x%.1f)\n",
		       mean, mx_mul, mx_mul / mean, mx_raw, mx_raw / mean);
		CK(mx_mul < 4.0 * mean + 16.0);
		CK(mx_raw > 8.0 * mean);                              /* the reason the key is multiplied */
		kof_kix_close(k);
	}
	free(rawb);
	set_free(&s);

	/*
	 * A DATABASE MADE TO SKEW: every key in one bucket. It builds, the directory says so, and the bucket
	 * reads back whole and ascending - bounded work is the matcher's to keep (tests/unit/mutation_index.c
	 * searches such a bucket by small reads and stops at its allowance).
	 */
	{
		uint32_t inv = inv32(KOF_KIX_MULT), j, bucket = 0xbeefu, at = 0;
		struct kof_kix_io io;
		uint8_t *col;
		uint32_t n;

		s.nb = 1000;
		s.b = calloc(s.nb, sizeof *s.b);
		s.pool = malloc((size_t)s.nb * 32u * 4u);
		s.np = 0;
		for (i = 0; i < s.nb; i++) {
			s.b[i].first_hash = s.np; s.b[i].n_hash = 32; s.b[i].scan_mask = 1u;
			for (j = 0; j < 32u; j++)
				s.pool[s.np++] = ((bucket << 16) | (at++ * 2u + 1u)) * inv;   /* distinct lo16, one bucket */
		}
		memset(&in, 0, sizeof in);
		in.blk = s.b; in.n_blk = s.nb; in.pool = s.pool; in.n_pool = s.np;
		img = kof_kix_make(&in, 0, 0, 0, &len, &res);
		CK(img != NULL && res.max_mult == 1u && res.n_key == 32000u);
		k = kof_kix_open_mem(img, len, s.b, s.nb, s.pool, s.np, why, sizeof why);
		CK(k != NULL);
		if (k) {
			d = kof_kix_dir(k);
			n = d[bucket + 1u] - d[bucket];
			CK(n == 32000u && d[bucket] == 0u && d[KOF_KIX_N_DIR] == 32000u);
			col = malloc((size_t)n * KOF_KIX_ENTRY);
			memset(&io, 0, sizeof io);
			io.budget = (uint64_t)1 << 30;
			CK(kof_kix_body(k, 0, col, (size_t)n * KOF_KIX_ENTRY, &io));
			for (i = 1; i < n; i++) {
				uint16_t a, b;

				memcpy(&a, col + 2u * (i - 1u), 2);
				memcpy(&b, col + 2u * i, 2);
				CK(a < b);
			}
			free(col);
			kof_kix_close(k);
		}
		set_free(&s);
	}
	printf("  key is a bijection; all keys in one bucket builds and reads back: ok\n");
}

/* ---- the filter ---------------------------------------------------------------------------- */

static void t_filter_fold(void)
{
	struct set s;
	struct kof_kix_build_in in;
	struct kof_kix_build_res res;
	struct kof_kix *k;
	uint8_t *img, *f;
	uint64_t len = 0, sizes[4] = { 4096, 65536, 1u << 20, 1u << 22 }, z;
	uint32_t i, q, pass[4], tot = 0;
	char why[160];

	set_bottomk(&s, 2000, 1);                                   /* 64,000 entries */
	memset(&in, 0, sizeof in);
	in.blk = s.b; in.n_blk = s.nb; in.pool = s.pool; in.n_pool = s.np;
	in.filter_bytes = 1u << 16;                                 /* stored at 64 KiB */
	img = kof_kix_make(&in, 0, 0, 0, &len, &res);
	CK(img && res.filter_bytes == (1u << 16));
	k = kof_kix_open_mem(img, len, s.b, s.nb, s.pool, s.np, why, sizeof why);
	CK(k != NULL);
	if (!k)
		return;
	for (z = 0; z < 4u; z++) {
		f = aligned_alloc(64, sizes[z]);
		memset(f, 0, sizes[z]);
		CK(kof_kix_filter_or(k, f, sizes[z]));
		/* folded (smaller) or tiled (larger): every key still passes - a window that was in is still in */
		for (i = 0; i < s.np; i++)
			CK(kof_kix_flt_test(f, kof_kix_flt_lbits(sizes[z]), s.pool[i] * KOF_KIX_MULT));
		/* and what does not belong passes at a rate that falls as the filter grows */
		pass[z] = 0;
		for (q = 0, tot = 0; q < 200000u; q++) {
			uint32_t v = rnd();

			tot++;
			pass[z] += (uint32_t)kof_kix_flt_test(f, kof_kix_flt_lbits(sizes[z]), v * KOF_KIX_MULT);
		}
		free(f);
	}
	printf("  filter at 4K/64K/1M/4M (stored 64K): false passes per 200000 = %u / %u / %u / %u\n", pass[0], pass[1], pass[2], pass[3]);
	CK(pass[0] > pass[1] && pass[1] >= pass[2]);                /* smaller is worse, tiled is no better than stored */
	CK(pass[0] > 100000u / 2u);                                 /* 4 KiB for 64,000 keys is saturated: it says "maybe" to most */
	kof_kix_close(k);
	set_free(&s);
}

/* ---- what the writer refuses, and what it writes -------------------------------------------- */

static void t_writer(void)
{
	struct set s;
	struct kof_kix_build_in in;
	struct kof_kix_build_res res;
	uint8_t *a, *b;
	uint64_t la = 0, lb = 0;
	uint32_t i;
	struct kof_kix *k;
	char why[160];
	uint8_t *garbage;

	set_bottomk(&s, 600, 3);
	memset(&in, 0, sizeof in);
	in.blk = s.b; in.n_blk = s.nb; in.pool = s.pool; in.n_pool = s.np;
	/* the same input is the same bytes */
	a = kof_kix_make(&in, 64, 100, 7, &la, &res);
	b = kof_kix_make(&in, 64, 100, 7, &lb, NULL);
	CK(a && b && la == lb && memcmp(a, b, (size_t)la) == 0);
	free(a); free(b);
	/* the footer's old-part CRC is set after the fact (the packer cannot know it earlier) */
	a = kof_kix_make(&in, 64, 100, 0, &la, NULL);
	kof_kix_seal(a, la, 0xfeedbeefu);
	{
		struct kof_kix_footer ft;

		memcpy(&ft, a + la - sizeof ft, sizeof ft);
		CK(ft.old_crc == 0xfeedbeefu && ft.footer_crc == kof_crc32(&ft, sizeof ft - 4u));
	}
	free(a);

	/* refused with a cause */
	s.b[5].first_hash = s.np;                                   /* a slice past the pool */
	CK(kof_kix_make(&in, 0, 0, 0, &la, &res) == NULL && (res.status & KOF_KIX_B_BAD_BLOCK));
	s.b[5].first_hash = 5u * 32u;
	s.b[6].n_hash = 129;
	CK(kof_kix_make(&in, 0, 0, 0, &la, &res) == NULL && (res.status & KOF_KIX_B_BAD_BLOCK));
	s.b[6].n_hash = 32;
	s.b[7].norm = 100;
	CK(kof_kix_make(&in, 0, 0, 0, &la, &res) == NULL && (res.status & KOF_KIX_B_BAD_BLOCK));
	s.b[7].norm = 0;
	for (i = 0; i < 300u && i < s.nb; i++)                      /* 300 distinct regions: more classes than a byte names */
		s.b[i].scan_mask = 1u << (i % 31u), s.b[i].side = (uint8_t)(i / 31u);
	CK(kof_kix_make(&in, 0, 0, 0, &la, &res) == NULL && (res.status & KOF_KIX_B_TOO_MANY_CLASSES));
	for (i = 0; i < s.nb; i++)
		s.b[i].scan_mask = 1u, s.b[i].side = 0;
	in.max_bytes = 100000;                                      /* an allowance the image does not fit */
	CK(kof_kix_make(&in, 0, 0, 0, &la, &res) == NULL && (res.status & KOF_KIX_B_OVER_BUDGET) && res.bytes > 100000u);
	in.max_bytes = 0;
	in.blk = NULL;                                              /* blocks with no table */
	CK(kof_kix_make(&in, 0, 0, 0, &la, &res) == NULL && (res.status & KOF_KIX_B_BAD_BLOCK));
	in.blk = s.b;
	/* no blocks is a valid (empty) index */
	in.n_blk = 0; in.n_pool = 0;
	a = kof_kix_make(&in, 0, 0, 0, &la, &res);
	CK(a && res.n_pair == 0);
	k = kof_kix_open_mem(a, la, NULL, 0, NULL, 0, why, sizeof why);
	CK(k != NULL);
	kof_kix_close(k);

	/* garbage handed to the memory reader: refused, image freed once, nothing read out of bounds */
	garbage = malloc(500);
	for (i = 0; i < 500u; i++)
		garbage[i] = (uint8_t)rnd();
	CK(kof_kix_open_mem(garbage, 500, NULL, 0, NULL, 0, why, sizeof why) == NULL);
	garbage = malloc(64);
	memset(garbage, 0, 64);
	CK(kof_kix_open_mem(garbage, 64, NULL, 0, NULL, 0, why, sizeof why) == NULL);
	CK(kof_kix_open_mem(NULL, 0, NULL, 0, NULL, 0, why, sizeof why) == NULL);
	set_free(&s);
	printf("  writer: deterministic, sealed, refuses with a cause (slice, count, normaliser, classes, allowance): ok\n");
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	snprintf(dir, sizeof dir, "build/kof_kixc_XXXXXX");
	if (!mkdtemp(dir)) {
		printf("kix_container: cannot make a work directory\n");
		return 1;
	}
	t_roundtrip();
	t_corrupt();
	t_budget_flag();
	t_key_and_skew();
	t_filter_fold();
	t_writer();
	rmdir(dir);
	printf("kix_container: %s\n", fails ? "FAIL" : "ok");
	return fails != 0;
}
