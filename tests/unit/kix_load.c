/*
 * kix_load - the loader and the matcher over packs that carry the block index trailer, packs that do not, and
 * packs that are wrong.
 *
 * WHAT IS UNDER TEST is the whole path: the packer appends the trailer (databases/dbpacker.c), the loader
 * maps only what is before it, checks that part against the footer and opens the index (dbloader_packs.c), the
 * matcher takes it over (dbindex.c, kofmutation.c), and the engine's ledger decides how big its filter is.
 *
 *   - an OLD ENGINE's rules still hold: the pack with a trailer passes kof_db_pack_valid, the whole-file check
 *     a loader that never heard of the trailer makes; the format minor is unchanged; every record before the
 *     trailer is the same bytes as without it.
 *   - the trailer's counts equal the in-memory matcher's, entry for entry, on random objects.
 *   - a pack WITHOUT the trailer (stripped here the way an old build would have made it) loads, builds the same
 *     index in memory under the ledger, says so (KOF_MTN_B_IN_RAM), and gives the same counts; when the ledger
 *     cannot hold it the index is REFUSED with KOF_MTN_B_OVER_BUDGET and the engine loads without similarity -
 *     where the same data WITH the trailer loads under the same ledger. That is the memory claim, as a test.
 *   - the filter's size follows the ledger, tier by tier, each step reported.
 *   - a pack that is wrong is refused on its own (bad footer, bad directory, truncated), and one that is
 *     damaged or shortened AFTER load is a status on the object, not a signal.
 *   - several packs with blocks are one index with global block numbers.
 *
 * Files are made beside the build output, never under /tmp.
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>

#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/databases/dbloader.h"
#include "../../libkofeng/databases/pack/dbcore.h"
#include "../../libkofeng/databases/dbpacker.h"
#include "../../libkofeng/detectors/mutations/kofmutation.h"
#include "../../libkofeng/kofeng.h"

static int fails;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static char root[128];
static uint32_t rs = 0xfeed1234u;

static uint32_t rnd(void)
{
	rs ^= rs << 13; rs ^= rs >> 17; rs ^= rs << 5;
	return rs;
}

/* ---- material ------------------------------------------------------------------------- */

struct mat {
	struct kof_mutation_block *b;
	uint32_t *pool;
	uint32_t nb, np;
	uint8_t *obj;
	uint64_t n;
};

static void mat_free(struct mat *m)
{
	free(m->b); free(m->pool); free(m->obj);
	memset(m, 0, sizeof *m);
}

static uint32_t values(const uint8_t *p, uint64_t n, uint32_t *out, uint32_t max)
{
	struct kgenome_mtn_win w;
	uint32_t k = 0;

	if (!kgenome_mtn_win_begin(&w, p, n, 0))
		return 0;
	do {
		if (k < max && !kgenome_mtn_win_flat(&w))
			out[k++] = kgenome_mtn_win_value(&w);
	} while (kgenome_mtn_win_next(&w));
	return k;
}

/* `nb` blocks of 32 hashes, a third of them cut from the windows of a random object (so that the object
 * credits them), the rest random; region 1 or 2, two sides, two normalizers. */
static void mat_make(struct mat *m, uint32_t nb, uint64_t n)
{
	uint32_t *src = malloc((size_t)n * 4u), ns, i, j;

	m->n = n;
	m->obj = malloc((size_t)n);
	for (i = 0; i < n; i++)
		m->obj[i] = (uint8_t)rnd();
	ns = values(m->obj, n, src, (uint32_t)n);
	m->nb = nb;
	m->b = calloc(nb ? nb : 1u, sizeof *m->b);
	m->pool = malloc((size_t)(nb ? nb : 1u) * 32u * 4u);
	m->np = 0;
	for (i = 0; i < nb; i++) {
		m->b[i].first_hash = m->np;
		m->b[i].n_hash = 32;
		m->b[i].scan_mask = 1u << (i % 2u);
		m->b[i].norm = 0;
		m->b[i].side = (uint8_t)((i / 2u) % 2u);
		for (j = 0; j < 32u; j++)
			m->pool[m->np++] = i % 3u == 0 ? src[rnd() % ns] : rnd();
	}
	free(src);
}

/* ---- packs --------------------------------------------------------------------------------- */

/* One module that declares the blocks, and a second with none (a pack with blocks is rarely only blocks). */
static uint8_t *build_pack(const struct mat *m, uint32_t first, uint32_t count, size_t *len)
{
	static const uint8_t code[] = { 0xc3 };
	struct kof_pw_mod mod[2];
	struct kof_mutation_block *b = calloc(count ? count : 1u, sizeof *b);
	uint32_t i, p0 = m->b[first].first_hash, np = 0;
	uint8_t *img;

	for (i = 0; i < count; i++) {
		b[i] = m->b[first + i];
		b[i].first_hash -= p0;          /* a module's block records index its own pool from zero */
		np += b[i].n_hash;
	}
	memset(mod, 0, sizeof mod);
	mod[0].code = code; mod[0].code_len = 1; mod[0].n_target = 1; mod[0].target[0] = KOF_FMT_UNKNOWN;
	mod[0].scan_mask = 1u;
	mod[0].blk = b; mod[0].n_blk = count; mod[0].pool = m->pool + p0; mod[0].n_pool = np;
	mod[1].code = code; mod[1].code_len = 1; mod[1].n_target = 1; mod[1].target[0] = KOF_FMT_UNKNOWN;
	mod[1].scan_mask = 1u;
	img = kof_pack_build(KOF_PACK_DETECT, mod, 2, len);
	free(b);
	return img;
}

static int write_file(const char *path, const uint8_t *p, size_t n)
{
	FILE *f = fopen(path, "wb");

	if (!f)
		return 0;
	if (fwrite(p, 1, n, f) != n) {
		fclose(f);
		return 0;
	}
	return fclose(f) == 0;
}

static void reseal(uint8_t *img, size_t len)
{
	struct kof_pack_hdr *h = (struct kof_pack_hdr *)img;

	h->crc32 = kof_crc32(img + KOF_PACK_CRC_FROM, (uint64_t)len - KOF_PACK_CRC_FROM);
}

/* What an engine from before the trailer wrote: the same pack cut at the end of its last section. */
static size_t strip_trailer(uint8_t *img, size_t len)
{
	struct kof_pack_hdr *h = (struct kof_pack_hdr *)img;
	struct kof_kix_footer ft;
	size_t old;

	memcpy(&ft, img + len - sizeof ft, sizeof ft);
	old = (size_t)ft.old_len;
	h->file_len = old;
	reseal(img, old);
	return old;
}

static char *case_dir(const char *tag)
{
	static char d[256];

	snprintf(d, sizeof d, "%s/%s", root, tag);
	mkdir(d, 0700);
	return d;
}

static void rm_case(const char *tag, int n)
{
	char p[300];
	int i;

	for (i = 0; i < n; i++) {
		snprintf(p, sizeof p, "%s/%s/p%d.ksig", root, tag, i);
		unlink(p);
	}
	snprintf(p, sizeof p, "%s/%s", root, tag);
	rmdir(p);
}

static void put_pack(const char *tag, int i, const uint8_t *img, size_t len)
{
	char p[300];

	snprintf(p, sizeof p, "%s/%s/p%d.ksig", root, tag, i);
	CK(write_file(p, img, len));
}

/* The counts of every block after an object, by the engine's set, as an array. */
static uint32_t *counts_of(const struct kof_mutation_set *set, uint32_t nb, const uint8_t *obj, uint64_t n,
			   struct kof_mutation_stat *st, uint32_t chunk)
{
	struct kof_mutation_ctx c;
	uint32_t *out = calloc(nb ? nb : 1u, 4), b;
	uint64_t off;

	CK(kof_mutation_ctx_init(&c, set));
	c.chunk_max = chunk;
	kof_mutation_begin(&c);
	for (off = 0; off < n; off += 8192u) {
		kof_mutation_unit(&c, 1u, 0, 0, obj + off, n - off < 8192u + 8u ? n - off : 8192u + 8u);
		kof_mutation_unit(&c, 2u, 0, 1, obj + off, n - off < 8192u + 8u ? n - off : 8192u + 8u);
	}
	for (b = 0; b < nb; b++)
		out[b] = kof_mutation_matched(&c, b);
	if (st)
		kof_mutation_stat(&c, st);
	kof_mutation_ctx_done(&c);
	return out;
}

/* ---- the format, as an old engine sees it ----------------------------------------------------- */

static void t_old_engine_view(const struct mat *m)
{
	size_t len = 0, len2;
	uint8_t *img = build_pack(m, 0, m->nb, &len), *old;
	const struct kof_pack_hdr *h;
	struct kof_kix_footer ft;
	struct kof_pack_hdr h2;

	CK(img != NULL);
	if (!img)
		return;
	h = (const struct kof_pack_hdr *)img;
	/* the whole-file check a loader that does not know the trailer makes */
	CK(kof_crc32(img + KOF_PACK_CRC_FROM, len - KOF_PACK_CRC_FROM) == h->crc32 && h->file_len == len);
	CK(h->minor == KOF_PACK_MINOR && h->major == KOF_PACK_MAJOR);
	memcpy(&ft, img + len - sizeof ft, sizeof ft);
	CK(ft.magic == KOF_KIX_MAGIC_FOOT && ft.old_len < len && ft.trailer_off >= ft.old_len);
	/* ... and the part the new loader checks is the old part as it is in this file */
	CK(kof_crc32(img + KOF_PACK_CRC_FROM, ft.old_len - KOF_PACK_CRC_FROM) == ft.old_crc);
	/* every record before the trailer is what it was: the same pack, stripped, differs only in two header fields */
	old = malloc(len);
	memcpy(old, img, len);
	len2 = strip_trailer(old, len);
	CK(len2 == ft.old_len);
	memcpy(&h2, old, sizeof h2);
	CK(h2.n_blk == h->n_blk && h2.n_pool == h->n_pool && h2.n_mods == h->n_mods &&
	   memcmp(old + 64, img + 64, len2 - 64) == 0);
	free(old);
	free(img);
	printf("  an engine that does not know the trailer: whole-file CRC holds, minor unchanged, records identical\n");
}

/* ---- trailer, in-memory, and the same counts --------------------------------------------------- */

static void t_same_counts(const struct mat *m)
{
	size_t len = 0, olen;
	uint8_t *img = build_pack(m, 0, m->nb, &len), *old = NULL;
	struct kof_engine *e1, *e2;
	struct kof_mutation_set *mem;
	struct kof_mutation_build_res r1, r2;
	struct kof_mutation_stat st;
	uint32_t *a, *b, *c, i, bad = 0, nz = 0, nm;
	const char *d;
	struct kof_db_load_opt opt;
	uint64_t bytes;
	uint32_t keys, status;

	CK(img != NULL);
	if (!img)
		return;
	d = case_dir("same");
	put_pack("same", 0, img, len);
	memset(&opt, 0, sizeof opt);
	e1 = kof_db_load_opt(d, &opt);
	CK(e1 && e1->mutation);
	if (!e1 || !e1->mutation) {
		free(img);
		return;
	}
	kof_mutation_set_info(e1->mutation, &r1);
	CK(r1.n_part == 1u && r1.n_part_mem == 0u && !(r1.status & KOF_MTN_B_IN_RAM));
	CK(e1->packs[0].has_kix && e1->packs[0].fd >= 0 && e1->packs[0].len < len);   /* only the old part is mapped */
	CK(e1->n_blk == m->nb && e1->blk_tab == (const void *)((const uint8_t *)e1->packs[0].map +
	   ((const struct kof_pack_hdr *)e1->packs[0].map)->sec[KOF_SEC_MUTATION_BLK].off));   /* borrowed, not copied */
	/* resident: the directory and a filter, not the body (7 bytes an entry) */
	CK(r1.bytes < 400000u + 4u * (uint64_t)m->np && r1.bytes < 7u * (uint64_t)m->np / 4u + 600000u);
	status = kdb_mutation_status(e1, &bytes, &keys);
	CK(status == r1.status && bytes == r1.bytes);

	/* the same blocks, the arrays, in memory */
	mem = kof_mutation_build(m->b, m->nb, m->pool, m->np);
	CK(mem != NULL);
	kof_mutation_set_info(mem, &r2);
	CK(r2.n_part_mem == 1u && (r2.status & KOF_MTN_B_IN_RAM));
	a = counts_of(e1->mutation, m->nb, m->obj, m->n, &st, 0);
	CK(st.status == 0);
	b = counts_of(mem, m->nb, m->obj, m->n, NULL, 0);
	c = counts_of(e1->mutation, m->nb, m->obj, m->n, NULL, 4096);
	for (i = 0; i < m->nb; i++) {
		bad += a[i] != b[i] || a[i] != c[i];
		nz += a[i] != 0;
	}
	CK(bad == 0 && nz > m->nb / 10u);
	printf("  trailer = memory: %u blocks, %u credited, 0 differences (and in batches of 4096)\n", m->nb, nz);
	free(a); free(b); free(c);

	/* the same pack as an older build wrote it: no trailer; built in memory, the same counts, and it says so */
	old = malloc(len);
	memcpy(old, img, len);
	olen = strip_trailer(old, len);
	put_pack("same", 0, old, olen);
	kof_db_free(e1);
	e2 = kof_db_load_opt(d, &opt);
	CK(e2 && e2->mutation);
	if (e2 && e2->mutation) {
		kof_mutation_set_info(e2->mutation, &r2);
		CK(r2.n_part == 1u && r2.n_part_mem == 1u && (r2.status & KOF_MTN_B_IN_RAM));
		CK(!e2->packs[0].has_kix && e2->packs[0].fd < 0);
		a = counts_of(e2->mutation, m->nb, m->obj, m->n, NULL, 0);
		b = counts_of(mem, m->nb, m->obj, m->n, NULL, 0);
		bad = 0;
		for (nm = 0; nm < m->nb; nm++)
			bad += a[nm] != b[nm];
		CK(bad == 0);
		free(a); free(b);
		CK(r2.bytes > 7u * (uint64_t)m->np);                  /* the body is in memory: the cost that grows */
		kof_db_free(e2);
	}
	kof_mutation_set_free(mem);
	free(old); free(img);
	rm_case("same", 1);
	printf("  a pack with no trailer: indexed in memory, said so, same counts\n");
}

/* ---- the ledger ----------------------------------------------------------------------------- */

static void t_ledger(void)
{
	struct mat m;
	size_t len = 0, olen;
	uint8_t *img, *old;
	struct kof_budget b;
	struct kof_db_load_opt opt;
	struct kof_engine *e;
	struct kof_mutation_build_res r;
	uint64_t prev_bits = 0, caps[6] = { 64u << 20, 12u << 20, 6u << 20, 3u << 20, 1u << 20, 500u << 10 };
	uint32_t i;
	const char *d;

	/* 62,500 blocks, 2,000,000 hashes: the default filter is 4 MiB and the body is 14 MB */
	mat_make(&m, 62500, 100000);
	img = build_pack(&m, 0, m.nb, &len);
	CK(img != NULL);
	if (!img) {
		mat_free(&m);
		return;
	}
	d = case_dir("ledger");
	put_pack("ledger", 0, img, len);
	printf("  ledger tiers (2,000,000 hashes; the pack has the trailer; cap = what the engine may hold, the index takes at most half of what is left):\n");
	memset(&opt, 0, sizeof opt);
	for (i = 0; i < 6u; i++) {
		kof_budget_init(&b, caps[i]);
		opt.budget = &b;
		e = kof_db_load_opt(d, &opt);
		CK(e != NULL);
		if (!e)
			continue;
		if (e->mutation) {
			kof_mutation_set_info(e->mutation, &r);
			printf("    cap %6llu KiB: filter %7llu KiB (%.1f bits a key) resident %7llu KiB status 0x%x\n",
			       (unsigned long long)(caps[i] >> 10), (unsigned long long)(r.bloom_bits / 8192u),
			       (double)r.bloom_bits / (double)r.n_key, (unsigned long long)(r.bytes >> 10), r.status);
			CK(r.bytes <= kof_budget_room(&b) || r.bytes <= caps[i] / 2u + 1u);
			CK(i == 0 || r.bloom_bits <= prev_bits);               /* the filter never grows as the ledger shrinks */
			/* degraded: a bloom filter under 12 bits a key; a pre-built one under 8 bits an entry or with partitions left out */
			CK(!!(r.status & KOF_MTN_B_FILTER_DEGRADED) ==
			   ((r.flt_kind & KOF_MTN_FLT_FUSE) ? (r.flt_w < KOF_MFLT_W_FLOOR || r.flt_res < r.flt_parts)
			    : (r.bloom_bits < (uint64_t)KOF_KIX_FILTER_FLOOR_BPK * r.n_key)));
			prev_bits = r.bloom_bits;
		} else {
			uint64_t by;
			uint32_t keys, st = kdb_mutation_status(e, &by, &keys);

			printf("    cap %6llu KiB: refused, status 0x%x (the engine loads, similarity rules do not score)\n",
			       (unsigned long long)(caps[i] >> 10), st);
			CK(st & KOF_MTN_B_OVER_BUDGET);
			CK(i >= 4u);
		}
		kof_db_free(e);
	}
	/* the SAME data in a pack WITHOUT the trailer needs the body in memory: refused under a ledger the trailer fits in */
	old = malloc(len);
	memcpy(old, img, len);
	olen = strip_trailer(old, len);
	put_pack("ledger", 0, old, olen);
	kof_budget_init(&b, 12u << 20);
	opt.budget = &b;
	e = kof_db_load_opt(d, &opt);
	CK(e != NULL && e->mutation == NULL);
	if (e) {
		uint64_t by;
		uint32_t keys, st = kdb_mutation_status(e, &by, &keys);

		CK(st & KOF_MTN_B_OVER_BUDGET);
		printf("    no trailer, cap 12288 KiB: OVER_BUDGET (status 0x%x), reported; the trailer fit in %u KiB\n", st, 12u << 10);
		kof_db_free(e);
	}
	/* and the allowance given by the caller still lowers it */
	put_pack("ledger", 0, img, len);
	kof_budget_init(&b, 512u << 20);
	opt.budget = &b;
	opt.max_index_bytes = 100000;
	e = kof_db_load_opt(d, &opt);
	CK(e != NULL && e->mutation == NULL);
	kof_db_free(e);
	free(old); free(img);
	rm_case("ledger", 1);
	mat_free(&m);
}

/* ---- a pack that is wrong --------------------------------------------------------------------- */

static void t_wrong(const struct mat *m)
{
	size_t len = 0;
	uint8_t *img = build_pack(m, 0, m->nb, &len), *bad;
	struct kof_kix_footer ft;
	struct kof_db_load_opt opt;
	struct kof_engine *e;
	const char *d;
	uint8_t *good2;
	size_t len2 = 0;

	CK(img != NULL);
	if (!img)
		return;
	memcpy(&ft, img + len - sizeof ft, sizeof ft);
	memset(&opt, 0, sizeof opt);
	d = case_dir("wrong");

	/* a footer byte flipped: it is not a trailer, the whole-file CRC does not hold either, refused */
	bad = malloc(len);
	memcpy(bad, img, len);
	bad[len - 9] ^= 0x10;
	put_pack("wrong", 0, bad, len);
	e = kof_db_load_opt(d, &opt);
	CK(e == NULL);
	kof_db_free(e);

	/* a flipped byte in the directory (not in the old part): the pack is refused on its own */
	memcpy(bad, img, len);
	bad[ft.trailer_off + 2304u + 50u] ^= 0x01;
	put_pack("wrong", 0, bad, len);
	e = kof_db_load_opt(d, &opt);
	CK(e == NULL);
	kof_db_free(e);

	/* cut in the middle of the body: the footer is gone and the pack is shorter than it says */
	put_pack("wrong", 0, img, ft.trailer_off + ft.meta_len + 1000u);
	e = kof_db_load_opt(d, &opt);
	CK(e == NULL);
	kof_db_free(e);

	/* cut inside the old part */
	put_pack("wrong", 0, img, 1000);
	e = kof_db_load_opt(d, &opt);
	CK(e == NULL);
	kof_db_free(e);

	/* the old part damaged: the footer's CRC of it does not hold */
	memcpy(bad, img, len);
	bad[ft.old_len - 20u] ^= 0x01;
	put_pack("wrong", 0, bad, len);
	e = kof_db_load_opt(d, &opt);
	CK(e == NULL);
	kof_db_free(e);

	/* one good pack and one with a bad directory in one directory: the good one loads */
	good2 = build_pack(m, 0, m->nb / 2u, &len2);
	memcpy(bad, img, len);
	bad[ft.trailer_off + 2304u + 50u] ^= 0x01;
	put_pack("wrong", 0, good2, len2);
	put_pack("wrong", 1, bad, len);
	e = kof_db_load_opt(d, &opt);
	CK(e != NULL && e->n_packs == 1u && e->mutation != NULL && e->n_blk == m->nb / 2u);
	kof_db_free(e);

	free(good2); free(bad); free(img);
	rm_case("wrong", 2);
	printf("  bad footer, bad directory, cut body, cut old part, damaged old part: the pack is refused; a good neighbour loads\n");
}

/* ---- damaged or shortened after load: a status, not a signal ---------------------------------- */

static void t_after_load(const struct mat *m)
{
	size_t len = 0;
	uint8_t *img = build_pack(m, 0, m->nb, &len);
	struct kof_kix_footer ft;
	struct kof_db_load_opt opt;
	struct kof_engine *e;
	struct kof_mutation_set *mem;
	struct kof_mutation_stat st;
	uint32_t *base, *a, b, lower = 0, nz = 0, pass;
	char path[300];
	int fd;
	uint8_t x;
	uint64_t body, nslice, s;

	CK(img != NULL);
	if (!img)
		return;
	memcpy(&ft, img + len - sizeof ft, sizeof ft);
	case_dir("after");
	snprintf(path, sizeof path, "%s/after/p0.ksig", root);
	memset(&opt, 0, sizeof opt);
	mem = kof_mutation_build(m->b, m->nb, m->pool, m->np);
	base = counts_of(mem, m->nb, m->obj, m->n, NULL, 0);
	body = ft.trailer_off + ft.meta_len;
	nslice = (7u * (uint64_t)m->np + 65535u) / 65536u;

	/*
	 * A BYTE OF EVERY SLICE DAMAGED ON DISK AFTER THE LOAD, before anything read it. The first read of a
	 * slice checks it (once, for everybody); each is reported as a status on the object that met it, and
	 * every later read of it says so again. Counts fall, never rise.
	 */
	for (pass = 0; pass < 2u; pass++) {
		put_pack("after", 0, img, len);
		e = kof_db_load_opt(path, &opt);
		CK(e && e->mutation);
		if (!e || !e->mutation)
			break;
		fd = open(path, O_RDWR);
		CK(fd >= 0);
		if (fd < 0)
			break;
		if (pass == 0) {
			for (s = 0; s < nslice; s++) {
				uint64_t at = body + s * 65536u + 13u;

				CK(pread(fd, &x, 1, (off_t)at) == 1);
				x ^= 0x40;
				CK(pwrite(fd, &x, 1, (off_t)at) == 1);
			}
		} else {
			/* the file shortened under the engine: a read that is not there is a short read, and a status */
			CK(ftruncate(fd, (off_t)(body + 7u * (uint64_t)m->np / 3u)) == 0);
		}
		a = counts_of(e->mutation, m->nb, m->obj, m->n, &st, 0);
		CK(st.status & (pass == 0 ? KOF_MTN_S_SLICE_CRC : KOF_MTN_S_IO_ERROR));
		for (b = 0; b < m->nb; b++) {
			CK(a[b] <= base[b]);                               /* a lower bound, never a higher count */
			lower += a[b] < base[b];
			nz += base[b] != 0;
		}
		CK(lower > 0u && nz > 0u);
		free(a);
		a = counts_of(e->mutation, m->nb, m->obj, m->n, &st, 0);
		CK(st.status & (pass == 0 ? KOF_MTN_S_SLICE_CRC : KOF_MTN_S_IO_ERROR));   /* and it is said again */
		free(a);
		close(fd);
		kof_db_free(e);
	}
	free(base);
	kof_mutation_set_free(mem);
	free(img);
	rm_case("after", 1);
	printf("  a slice damaged and a file shortened after load: SLICE_CRC / IO_ERROR on the object, counts only fall, no signal\n");
}

/* ---- several packs, one index ------------------------------------------------------------------ */

static void t_multi(const struct mat *m)
{
	size_t l0 = 0, l1 = 0, o2;
	uint32_t half = m->nb / 2u;
	uint8_t *p0 = build_pack(m, 0, half, &l0), *p1 = build_pack(m, half, m->nb - half, &l1), *p2;
	struct kof_db_load_opt opt;
	struct kof_engine *e;
	struct kof_mutation_set *mem;
	struct kof_mutation_build_res r;
	uint32_t *a, *b, i, bad = 0;
	const char *d;

	CK(p0 && p1);
	if (!p0 || !p1)
		return;
	memset(&opt, 0, sizeof opt);
	d = case_dir("multi");
	mem = kof_mutation_build(m->b, m->nb, m->pool, m->np);
	b = counts_of(mem, m->nb, m->obj, m->n, NULL, 0);

	/* two packs with the trailer: two parts, one set, the blocks numbered pack after pack */
	put_pack("multi", 0, p0, l0);
	put_pack("multi", 1, p1, l1);
	e = kof_db_load_opt(d, &opt);
	CK(e && e->mutation);
	if (e && e->mutation) {
		kof_mutation_set_info(e->mutation, &r);
		CK(r.n_part == 2u && r.n_part_mem == 0u && e->n_blk == m->nb);
		CK(e->blk_owned);                                           /* the table is copied only when several packs carry blocks */
		a = counts_of(e->mutation, m->nb, m->obj, m->n, NULL, 0);
		for (i = 0; i < m->nb; i++)
			bad += a[i] != b[i];
		CK(bad == 0);
		free(a);
		for (i = 0; i < m->nb; i += 211u) {                         /* names are the fold of the hashes, from either pack */
			uint32_t h[KOF_MUTATION_MAX_HASH], n = 0;

			CK(kof_mutation_block_copy(e->mutation, i, h, &n) && n == 32u && memcmp(h, m->pool + m->b[i].first_hash, 128) == 0);
			CK(kof_mutation_block_id(e->mutation, i) == kof_mutation_block_id(mem, i));
		}
		kof_db_free(e);
	}

	/* one with, one without: a part in the pack and a part in memory, still one index */
	p2 = malloc(l1);
	memcpy(p2, p1, l1);
	o2 = strip_trailer(p2, l1);
	put_pack("multi", 1, p2, o2);
	e = kof_db_load_opt(d, &opt);
	CK(e && e->mutation);
	if (e && e->mutation) {
		kof_mutation_set_info(e->mutation, &r);
		CK(r.n_part == 2u && r.n_part_mem == 1u && (r.status & KOF_MTN_B_IN_RAM));
		a = counts_of(e->mutation, m->nb, m->obj, m->n, NULL, 0);
		bad = 0;
		for (i = 0; i < m->nb; i++)
			bad += a[i] != b[i];
		CK(bad == 0);
		free(a);
		kof_db_free(e);
	}
	free(p2); free(b); free(p0); free(p1);
	kof_mutation_set_free(mem);
	rm_case("multi", 2);
	printf("  two packs with blocks (trailer + trailer, trailer + none): one index, global block numbers, same counts and names\n");
}

/* ---- scanners on one index file, at once ------------------------------------------------------- */

struct thr {
	const struct kof_mutation_set *set;
	const struct mat *m;
	uint32_t chunk, *out;
};

static void *thr_run(void *a)
{
	struct thr *t = a;
	uint32_t i;

	for (i = 0; i < 3u; i++) {
		free(t->out);
		t->out = counts_of(t->set, t->m->nb, t->m->obj, t->m->n, NULL, t->chunk);
	}
	return NULL;
}

/* One pack file, one descriptor, four scanners reading slices of it and checking each slice the first time any of
 * them needs it: the same counts as one scanner alone. */
static void t_threads_on_file(const struct mat *m)
{
	enum { T = 4 };
	size_t len = 0;
	uint8_t *img = build_pack(m, 0, m->nb, &len);
	struct kof_db_load_opt opt;
	struct kof_engine *e;
	struct thr th[T];
	pthread_t id[T];
	uint32_t *want, i, b, bad = 0;
	const char *d;

	CK(img != NULL);
	if (!img)
		return;
	d = case_dir("thr");
	put_pack("thr", 0, img, len);
	memset(&opt, 0, sizeof opt);
	e = kof_db_load_opt(d, &opt);
	CK(e && e->mutation);
	if (!e || !e->mutation) {
		free(img);
		return;
	}
	want = counts_of(e->mutation, m->nb, m->obj, m->n, NULL, 0);
	/* a fresh engine, so that the slices are unchecked when the four start */
	kof_db_free(e);
	e = kof_db_load_opt(d, &opt);
	CK(e && e->mutation);
	if (e && e->mutation) {
		memset(th, 0, sizeof th);
		for (i = 0; i < T; i++) {
			th[i].set = e->mutation; th[i].m = m; th[i].chunk = i & 1u ? 4096u : 0u;
			pthread_create(&id[i], NULL, thr_run, &th[i]);
		}
		for (i = 0; i < T; i++)
			pthread_join(id[i], NULL);
		for (i = 0; i < T; i++) {
			for (b = 0; b < m->nb; b++)
				bad += th[i].out[b] != want[b];
			free(th[i].out);
		}
		CK(bad == 0);
		kof_db_free(e);
	}
	free(want); free(img);
	rm_case("thr", 1);
	printf("  four scanners on one pack file, slices checked once for all: same counts\n");
}

int main(void)
{
	struct mat m;

	setvbuf(stdout, NULL, _IONBF, 0);
	snprintf(root, sizeof root, "build/kof_kixl_XXXXXX");
	if (!mkdtemp(root)) {
		printf("kix_load: cannot make a work directory\n");
		return 1;
	}
	mat_make(&m, 1200, 300000);
	t_old_engine_view(&m);
	/* the refusals are noisy by design: the loader names the file and what is wrong with it */
	if (!freopen("/dev/null", "w", stderr))
		printf("  (could not silence the loader's diagnostics)\n");
	t_same_counts(&m);
	t_ledger();
	t_wrong(&m);
	t_after_load(&m);
	t_multi(&m);
	t_threads_on_file(&m);
	mat_free(&m);
	rmdir(root);
	printf("kix_load: %s\n", fails ? "FAIL" : "ok");
	return fails != 0;
}
