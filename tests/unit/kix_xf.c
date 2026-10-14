/*
 * kix_xf - the pre-built filter stored in the block index trailer (dbkix.h version 2, detectors/mutations/kofmutflt.h):
 * the packer writes it, the loader hands it to the matcher without reading it, the matcher keeps it at the width the
 * ledger grants and checks its checksum as it reads it.
 *
 *   - the packer's default pack carries it: footer and header say version 2, the region is there, and the
 *     whole-file CRC and the old part's CRC hold (a loader that does not know the trailer still loads the old pack).
 *   - the engine's counts through it equal the in-memory matcher's (the bloom filter built under the ledger), entry
 *     for entry, at every width the ledger can leave it at.
 *   - a byte flipped in the region AFTER the pack was written is caught when the matcher reads it (the load is
 *     refused, as a bloom filter that fails its CRC always refused it): never a wrong count.
 *   - a header that claims a bloom filter AND a region, a region that is not where the header says, a footer
 *     of an unknown version: the pack is refused on its own or loads without a trailer, never misread.
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


/* the footer and header of a pack, read from the file image */
static int xf_view(const uint8_t *img, size_t len, struct kof_kix_footer *ft, struct kof_kix_hdr *h)
{
	memcpy(ft, img + len - sizeof *ft, sizeof *ft);
	if (ft->magic != KOF_KIX_MAGIC_FOOT || ft->trailer_off + sizeof *h > len)
		return 0;
	memcpy(h, img + ft->trailer_off, sizeof *h);
	return 1;
}

static void t_stored(const struct mat *m)
{
	size_t len = 0;
	uint8_t *img = build_pack(m, 0, m->nb, &len);
	struct kof_kix_footer ft;
	struct kof_kix_hdr h;
	const struct kof_pack_hdr *ph;

	CK(img != NULL);
	if (!img)
		return;
	ph = (const struct kof_pack_hdr *)img;
	CK(xf_view(img, len, &ft, &h));
	CK(ft.version == KOF_KIX_VERSION_XF && h.version == KOF_KIX_VERSION_XF);
	CK(h.xf_kind == KOF_KIX_XF_FUSE && h.xf_bytes > 0 && h.filter_bytes == 0 && h.off_xf == h.off_filter);
	CK(h.xf_crc == kof_crc32(img + ft.trailer_off + h.off_xf, h.xf_bytes));
	CK(kof_crc32(img + KOF_PACK_CRC_FROM, len - KOF_PACK_CRC_FROM) == ph->crc32 && ph->file_len == len);
	CK(kof_crc32(img + KOF_PACK_CRC_FROM, ft.old_len - KOF_PACK_CRC_FROM) == ft.old_crc);
	CK(ph->minor == KOF_PACK_MINOR && ph->major == KOF_PACK_MAJOR);
	free(img);
	printf("  the packer's pack: trailer version 2, a pre-built filter of %u bytes in place of the bloom filter, CRCs hold, format minor unchanged\n",
	       (unsigned)h.xf_bytes);
}

static void t_counts(const struct mat *m)
{
	size_t len = 0, olen;
	uint8_t *img = build_pack(m, 0, m->nb, &len), *old;
	struct kof_engine *e;
	struct kof_mutation_build_res r;
	uint32_t *cx, *cb, b, bad = 0;
	uint64_t credits = 0;
	struct kof_budget bud;
	struct kof_db_load_opt opt;
	const char *d;

	CK(img != NULL);
	if (!img)
		return;
	d = case_dir("xf1");
	put_pack("xf1", 0, img, len);
	memset(&opt, 0, sizeof opt);
	e = kof_db_load_opt(d, &opt);
	CK(e && e->mutation);
	if (!e || !e->mutation)
		return;
	kof_mutation_set_info(e->mutation, &r);
	CK((r.flt_kind & KOF_MTN_FLT_FUSE) && !(r.flt_kind & KOF_MTN_FLT_BLOOM) && r.flt_w == 8u && !(r.status & KOF_MTN_B_FILTER_DEGRADED));
	cx = counts_of(e->mutation, m->nb, m->obj, m->n, NULL, 0);
	/* the same data with no trailer: the matcher builds a bloom filter in memory */
	old = malloc(len);
	memcpy(old, img, len);
	olen = strip_trailer(old, len);
	put_pack("xf1", 0, old, olen);
	{
		struct kof_engine *e2 = kof_db_load_opt(d, &opt);

		CK(e2 && e2->mutation);
		cb = e2 && e2->mutation ? counts_of(e2->mutation, m->nb, m->obj, m->n, NULL, 0) : calloc(m->nb, 4);
		if (e2)
			kof_db_free(e2);
	}
	for (b = 0; b < m->nb; b++) {
		credits += cx[b];
		bad += cx[b] != cb[b];
	}
	CK(bad == 0 && credits > 100u);
	free(cx); free(cb); free(old);
	kof_db_free(e);
	/* and under every ledger tier: the width falls, the counts do not */
	put_pack("xf1", 0, img, len);
	{
		static const uint64_t caps[] = { 64u << 20, 12u << 20, 6u << 20, 3u << 20, 1u << 20 };
		uint32_t i;
		uint32_t *want = NULL;

		for (i = 0; i < 5u; i++) {
			struct kof_engine *et;

			kof_budget_init(&bud, caps[i]);
			opt.budget = &bud;
			et = kof_db_load_opt(d, &opt);
			CK(et != NULL);
			if (!et || !et->mutation) {
				if (et)
					kof_db_free(et);
				continue;
			}
			kof_mutation_set_info(et->mutation, &r);
			cx = counts_of(et->mutation, m->nb, m->obj, m->n, NULL, 0);
			if (!want) {
				want = cx;
			} else {
				CK(memcmp(want, cx, (size_t)m->nb * 4u) == 0);
				free(cx);
			}
			kof_db_free(et);
		}
		free(want);
	}
	free(img);
	rm_case("xf1", 1);
	printf("  counts through the stored filter equal the in-memory bloom filter's (%llu credits), at every ledger tier\n",
	       (unsigned long long)credits);
}

static void t_damage(const struct mat *m)
{
	size_t len = 0;
	uint8_t *img = build_pack(m, 0, m->nb, &len), *bad;
	struct kof_kix_footer ft;
	struct kof_kix_hdr h;
	struct kof_engine *e;
	struct kof_db_load_opt opt;
	const char *d;
	uint64_t by;
	uint32_t keys, st;

	CK(img != NULL);
	if (!img)
		return;
	CK(xf_view(img, len, &ft, &h));
	d = case_dir("xf2");
	memset(&opt, 0, sizeof opt);
	/* a byte flipped inside the region: the old part, the footer and the header still check, the matcher's read does not */
	bad = malloc(len);
	memcpy(bad, img, len);
	bad[ft.trailer_off + h.off_xf + h.xf_bytes / 2u] ^= 0x40u;
	put_pack("xf2", 0, bad, len);
	e = kof_db_load_opt(d, &opt);
	CK(e == NULL);               /* the pack is refused at load, as one whose bloom filter fails its CRC always was */
	if (e)
		kof_db_free(e);
	/* a header that claims both a bloom filter and a region (version 2 has no bloom filter): refused */
	memcpy(bad, img, len);
	{
		struct kof_kix_hdr hh = h;
		struct kof_kix_footer f2 = ft;

		hh.filter_bytes = 4096u;
		memcpy(bad + ft.trailer_off, &hh, sizeof hh);
		f2.meta_crc = kof_crc32(bad + ft.trailer_off, ft.meta_len);
		f2.footer_crc = kof_crc32(&f2, sizeof f2 - 4u);
		memcpy(bad + len - sizeof f2, &f2, sizeof f2);
	}
	put_pack("xf2", 0, bad, len);
	e = kof_db_load_opt(d, &opt);
	CK(e == NULL || e->mutation == NULL);
	if (e)
		kof_db_free(e);
	/* a footer of a version nobody knows: the pack is read as one without a trailer (its whole-file CRC holds), and loads */
	memcpy(bad, img, len);
	{
		struct kof_kix_footer f3 = ft;

		f3.version = 7u;
		f3.footer_crc = kof_crc32(&f3, sizeof f3 - 4u);
		memcpy(bad + len - sizeof f3, &f3, sizeof f3);
		((struct kof_pack_hdr *)bad)->crc32 = kof_crc32(bad + KOF_PACK_CRC_FROM, len - KOF_PACK_CRC_FROM);
	}
	put_pack("xf2", 0, bad, len);
	e = kof_db_load_opt(d, &opt);
	CK(e != NULL);
	if (e) {
		st = kdb_mutation_status(e, &by, &keys);
		CK(e->mutation != NULL && (st & KOF_MTN_B_IN_RAM));     /* what an older engine does with a version it does not know */
		kof_db_free(e);
	}
	free(bad);
	free(img);
	rm_case("xf2", 1);
	printf("  a flipped byte in the region, a header with both filters, a footer of an unknown version: load refused, refused, loaded without the trailer\n");
}

int main(void)
{
	struct mat m;

	setvbuf(stdout, NULL, _IONBF, 0);
	snprintf(root, sizeof root, "build/kof_kixx_XXXXXX");
	if (!mkdtemp(root)) {
		printf("kix_xf: cannot make a work directory\n");
		return 1;
	}
	mat_make(&m, 3000, 400000);
	t_stored(&m);
	/* the refusals are noisy by design: the loader names the file and what is wrong with it */
	if (!freopen("/dev/null", "w", stderr))
		printf("  (could not silence the loader's diagnostics)\n");
	t_counts(&m);
	t_damage(&m);
	mat_free(&m);
	rmdir(root);
	if (fails) {
		printf("kix_xf: %d failure(s)\n", fails);
		return 1;
	}
	printf("kix_xf: ok\n");
	return 0;
}
