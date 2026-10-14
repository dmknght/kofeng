/*
 * pix_tail.c - the pattern table in a pack's tail, through the loader.
 *
 * pix_match.c proves the table finds what a marker-by-marker search finds. This proves the pack
 * around it: that a pack carries the table in a part of its tail (databases/pack/dbkix.h) next to the
 * block index, that the loader opens it where it lies, that a pack WITHOUT one - small, or from before the
 * part existed - gets the same table built in memory with the same answers, and that every way a file can
 * be wrong is a status and not a wrong answer or a signal.
 *
 * Every pack is made by the real packer (kof_pack_build_opt), written to a file and loaded by the real
 * loader; the answers are read from the engine's own set (e->pix_set) through a scanner's context.
 *
 *   1. both parts: a pack with markers and blocks carries two parts; both open; the sweep finds the
 *      planted markers and nothing else.
 *   2. no part: the same markers built without the part (the shape of a pack from before it existed)
 *      load with the table in memory, say so (KOF_PIX_B_IN_RAM), and answer the same.
 *   3. a small pack carries no part and says nothing about it: building it costs less than opening one.
 *   4. a byte of the slice table, of a record, or of the footer flipped: the first two are refused at
 *      load or reported by the sweep (never a wrong answer); the footer's is a pack that fails its checksum.
 *   5. a pack truncated after it was loaded: the sweep reports an I/O error. No signal.
 *   6. the ledger: a table that does not fit it is refused with a status, and the engine loads.
 *   7. the same pack, one module per marker versus 64 a module: the table does not depend on how the
 *      strings are grouped.
 *   8. a pack built by the previous packer (no part, no pattern code at all in the file) loads and
 *      answers as a current pack with the table in memory.
 *
 * Scratch files go under build/, never /tmp.
 */

#include "hostile_engine.h"

#include <stddef.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "../../libkofeng/databases/dbloader.h"
#include "../../libkofeng/databases/dbpacker.h"
#include "../../libkofeng/databases/pack/dbcore.h"
#include "../../libkofeng/databases/pack/dbkix.h"
#include "../../libkofeng/databases/pack/dbtables.h"
#include "../../libkofeng/databases/pack/hexprog.h"
#include "../../libkofeng/detectors/pattern/kofmatch.h"
#include "../../libkofeng/detectors/pattern/kofpix.h"
#include "../../libkofeng/detectors/mutations/kofmutation.h"
#include <kofmod/kofsig.h>

#define SCANBIT 2u
#define LEN 12u

static char tmp[300];

static void marker_text(uint32_t i, char *out)
{
	snprintf(out, LEN + 1u, "PXTL%08x", i);
}

/* A pack of `n` literals ("PXTL" and eight hex digits), a few hex programs, and optionally 64 blocks. */
struct made {
	uint8_t *img;
	size_t   len;
};

static struct made build(uint32_t n, uint32_t per, int blocks, uint64_t embed_min)
{
	static const uint8_t code[] = { 0x90, 0xc3 };
	static struct kof_pw_name names[1];
	static const uint32_t rng[1] = { 1u << SCANBIT };
	uint32_t nm = (n + per - 1u) / per;
	struct kof_pw_str *strs = malloc((size_t)n * sizeof *strs);
	char *txt = malloc((size_t)n * (LEN + 1u));
	struct kof_pw_mod *mods = calloc(nm + 1u, sizeof *mods);
	static uint8_t hex[4][KOF_HEX_MAX_PROG];
	uint32_t hex_len[4], i, nh = 0;
	struct kof_mutation_block *blk = NULL;
	uint32_t *pool = NULL;
	struct kof_pack_opt opt = { embed_min };
	struct made r = { NULL, 0 };

	if (!strs || !txt || !mods)
		goto out;
	for (i = 0; i < n; i++) {
		marker_text(i, txt + (size_t)i * (LEN + 1u));
		strs[i].bytes = (const uint8_t *)txt + (size_t)i * (LEN + 1u);
		strs[i].len = LEN;
		strs[i].kind = KOF_STR_LITERAL;
		strs[i].flags = 0;
	}
	/* four hex programs, replacing four literals' slots by being appended to the first module's run is not
	 * possible (a module's strings are contiguous), so they are a module of their own */
	for (i = 0; i < 4u; i++) {
		char t[80];
		struct kof_hex_stat st;

		snprintf(t, sizeof t, "50 58 54 4C 48 58 %02X 58 ?? %02X", 0x41u + i, 0x30u + i);
		memset(&st, 0, sizeof st);
		hex_len[i] = kof_hex_compile(t, hex[i], sizeof hex[i], &st);
		if (!hex_len[i])
			goto out;
	}
	names[0].id = 1;
	names[0].text = "Test.PixTail";
	for (i = 0; i < nm; i++) {
		struct kof_pw_mod *m = &mods[i];

		m->code = code;
		m->code_len = sizeof code;
		m->n_target = 1;
		m->target[0] = KOF_FMT_UNKNOWN;
		m->scan_mask = 1u << SCANBIT;
		m->size_min = 1;
		m->str = strs + (size_t)i * per;
		m->n_str = i + 1u == nm ? n - i * per : per;
		m->rng = rng;
		m->n_rng = 1;
		m->name = names;
		m->n_names = 1;
	}
	{
		static struct kof_pw_str hs[4];
		struct kof_pw_mod *m = &mods[nm];

		for (i = 0; i < 4u; i++) {
			hs[i].bytes = hex[i];
			hs[i].len = (uint16_t)hex_len[i];
			hs[i].kind = KOF_STR_HEX;
			hs[i].flags = 0;
		}
		m->code = code;
		m->code_len = sizeof code;
		m->n_target = 1;
		m->target[0] = KOF_FMT_UNKNOWN;
		m->scan_mask = 1u << SCANBIT;
		m->size_min = 1;
		m->str = hs;
		m->n_str = 4;
		m->rng = rng;
		m->n_rng = 1;
		m->name = names;
		m->n_names = 1;
		nh = 1;
		if (blocks) {
			blk = calloc(64, sizeof *blk);
			pool = malloc(64u * 32u * sizeof *pool);
			if (!blk || !pool)
				goto out;
			for (i = 0; i < 64u * 32u; i++)
				pool[i] = (uint32_t)he_below(0xfffffffeu) + 1u;
			for (i = 0; i < 64u; i++) {
				blk[i].first_hash = i * 32u;
				blk[i].n_hash = 32;
				blk[i].scan_mask = 1;
			}
			m->blk = blk;
			m->n_blk = 64;
			m->pool = pool;
			m->n_pool = 64u * 32u;
		}
	}
	r.img = kof_pack_build_opt(KOF_PACK_DETECT, mods, nm + nh, &opt, &r.len);
out:
	free(blk);
	free(pool);
	free(mods);
	free(strs);
	free(txt);
	return r;
}

static int put(const char *dir, const char *name, const uint8_t *img, size_t len)
{
	char path[500];
	FILE *f;

	mkdir(dir, 0700);
	snprintf(path, sizeof path, "%s/%s", dir, name);
	f = fopen(path, "wb");
	if (!f)
		return 0;
	if (fwrite(img, 1, len, f) != len) {
		fclose(f);
		return 0;
	}
	return fclose(f) == 0;
}

static struct kof_engine *load(const char *dir, const struct kof_db_load_opt *opt)
{
	return kof_db_load_opt(dir, opt);
}

/* A scanner's view of one object: the markers `ids` planted, then one sweep of the region. Returns the
 * number of markers found; *last is the sweep's status. found[i] says marker ids[i] was. */
static uint32_t sweep(const struct kof_engine *e, const uint32_t *ids, uint32_t n_ids, int everything, uint32_t *last,
		      uint32_t *found_ids_ok)
{
	struct kofpix_ctx ctx;
	struct kof_match_ctx m;
	struct kof_range ext;
	uint32_t i, hits = 0, ok = 0, n;
	uint8_t *buf;
	const struct kof_db_pack *pk = &e->packs[0];
	uint32_t uid_of_first = 0, k;

	*last = 0xffffffffu;
	if (!e->pix_set || !kofpix_ctx_init(&ctx, e->pix_set, 0))
		return 0;
	n = (everything ? pk->n_desc : n_ids) * (LEN + 4u) + 64u;
	buf = malloc(n);
	memset(buf, '.', n);
	for (i = 0; i < (everything ? pk->n_desc : n_ids); i++) {
		char t[LEN + 1u];

		if (everything) {
			if (pk->desc[i].kind != KOF_STR_LITERAL)
				continue;
			memcpy(buf + (size_t)i * (LEN + 4u), pk->pool + pk->desc[i].off, pk->desc[i].len);
		} else {
			marker_text(ids[i], t);
			memcpy(buf + (size_t)i * (LEN + 4u), t, LEN);
		}
	}
	(void)uid_of_first;
	memset(&m, 0, sizeof m);
	kof_match_begin(&m, kof_buf_make(buf, n));
	ext.off = 0;
	ext.len = n;
	kofpix_ctx_begin(&ctx);
	kofpix_ctx_limit(&ctx, 64u << 20);          /* what the scanner does for an object: the table may grow to the ledger's share */
	kofpix_sweep(e->pix_set, &ctx, SCANBIT, &m, &ext, 1);
	*last = ctx.last;
	for (k = 0; k < pk->n_desc; k++) {
		const struct kof_str_ent *d = &pk->desc[k];

		if (d->kind != KOF_STR_LITERAL)
			continue;
		if ((kofpix_found_get(&ctx, pk->uid_base + d->uid) >> SCANBIT) & 1u) {
			hits++;
			if (!everything) {
				char t[LEN + 1u];
				uint32_t j, planted = 0;

				memcpy(t, pk->pool + d->off, LEN);
				t[LEN] = 0;
				for (j = 0; j < n_ids; j++) {
					char q[LEN + 1u];

					marker_text(ids[j], q);
					planted |= !memcmp(q, t, LEN);
				}
				ok += planted;
			}
		}
	}
	if (found_ids_ok)
		*found_ids_ok = ok;
	kofpix_ctx_free(&ctx);
	free(buf);
	return hits;
}

static void t_both_parts(const char *dir)
{
	static const uint32_t ids[] = { 0u, 7777u, 19999u };
	struct made r = build(20000, 64, 1, 0);
	struct kof_engine *e;
	uint32_t last, ok, hits;
	uint64_t bytes = 0, markers = 0;

	CK(r.img != NULL, "the pack builds");
	if (!r.img)
		return;
	CK(put(dir, "p.ksig", r.img, r.len), "the pack is written");
	e = load(dir, NULL);
	free(r.img);
	CK(e != NULL, "the pack loads");
	if (!e)
		return;
	CK(e->packs[0].has_pix && e->packs[0].has_kix, "the pack carries both parts");
	CK(e->packs[0].pix != NULL && !e->packs[0].pix_in_ram && e->mutation != NULL, "and both open: the table in the pack, the block index");
	CK(kdb_pattern_status(e, &bytes, &markers) == 0, "clean status");
	CK(markers == 20000u + 4u && bytes > 0 && bytes < (8u << 20), "%llu markers keyed with %llu bytes resident", (unsigned long long)markers,
	   (unsigned long long)bytes);
	hits = sweep(e, ids, 3, 0, &last, &ok);
	CK(last == 0 && hits == 3 && ok == 3, "the planted markers and only they are found (%u found, %u planted among them)", hits, ok);
	hits = sweep(e, NULL, 0, 1, &last, &ok);
	CK(last == 0 && hits == 20000u, "an object holding every literal: all %u found (%u)", 20000u, hits);
	kof_db_free(e);
}

static void t_old_shape(const char *dir)
{
	static const uint32_t ids[] = { 0u, 7777u, 19999u };
	struct made r = build(20000, 64, 1, ~0ull);
	struct kof_engine *e;
	uint32_t last, ok, hits;

	CK(r.img != NULL, "the pack builds without the part (the shape of a pack from before it existed)");
	if (!r.img)
		return;
	CK(put(dir, "p.ksig", r.img, r.len), "written");
	e = load(dir, NULL);
	free(r.img);
	CK(e != NULL, "it loads");
	if (!e)
		return;
	CK(!e->packs[0].has_pix && e->packs[0].has_kix && e->packs[0].pix_in_ram, "no part: the table is built in memory (the block index is still read from the pack)");
	CK((e->pix_status & KOF_PIX_B_IN_RAM) != 0, "and the engine says so (KOF_PIX_B_IN_RAM)");
	hits = sweep(e, ids, 3, 0, &last, &ok);
	CK(last == 0 && hits == 3 && ok == 3, "the same three found");
	hits = sweep(e, NULL, 0, 1, &last, &ok);
	CK(last == 0 && hits == 20000u, "and all of them in the dense object (%u)", hits);
	kof_db_free(e);
}

static void t_small(const char *dir)
{
	static const uint32_t ids[] = { 3u, 150u };
	struct made r = build(200, 64, 0, 0);
	struct kof_engine *e;
	uint32_t last, ok, hits;

	CK(r.img != NULL, "a small pack builds");
	if (!r.img)
		return;
	CK(put(dir, "p.ksig", r.img, r.len), "written");
	e = load(dir, NULL);
	free(r.img);
	CK(e != NULL, "loads");
	if (!e)
		return;
	CK(!e->packs[0].has_pix && e->packs[0].pix_in_ram && e->pix_status == 0, "no part and no complaint: a table of 200 markers is built in less time than a part is opened");
	hits = sweep(e, ids, 2, 0, &last, &ok);
	CK(last == 0 && hits == 2 && ok == 2, "it answers (%u found)", hits);
	kof_db_free(e);
}

/* Flip one byte of the file, load, and say what happened. */
static void flip(const char *path, uint64_t at)
{
	int fd = open(path, O_RDWR);
	uint8_t b;

	if (fd < 0 || pread(fd, &b, 1, (off_t)at) != 1)
		return;
	b ^= 0x5a;
	if (pwrite(fd, &b, 1, (off_t)at) != 1)
		b = 0;
	close(fd);
}

static void t_corruption(const char *dir)
{
	struct made r = build(20000, 64, 0, 0);
	char path[500];
	struct kof_engine *e;
	struct kof_tail t;
	int fd;
	uint32_t last, hits;
	uint64_t size;

	CK(r.img != NULL, "the pack builds");
	if (!r.img)
		return;
	snprintf(path, sizeof path, "%s/p.ksig", dir);
	CK(put(dir, "p.ksig", r.img, r.len), "written");
	fd = open(path, O_RDONLY);
	CK(fd >= 0 && kof_tail_probe(fd, r.len, &t) && t.has_pix && !t.has_kix, "the part is the last thing in the file (a pack with markers and no blocks)");
	if (fd < 0 || !t.has_pix) {
		free(r.img);
		return;
	}
	close(fd);
	size = r.len;

	/* the slice checksum table: refused at load, because the part cannot be trusted at all */
	flip(path, t.pix.trailer_off + t.pix.filter_off + 1u);
	e = load(dir, NULL);
	CK(e == NULL, "a flipped byte in the slice table: the pack is refused, loudly");
	if (e)
		kof_db_free(e);
	put(dir, "p.ksig", r.img, r.len);

	/* the footer: the last byte of the file. No footer, so no part - and the header's checksum covers the
	 * whole file, so the pack fails it. */
	flip(path, size - 1u);
	e = load(dir, NULL);
	CK(e == NULL, "a flipped footer byte: the pack fails its checksum");
	if (e)
		kof_db_free(e);
	put(dir, "p.ksig", r.img, r.len);

	/* a record, deep in the table: opens (a record is not read at load), and the sweep that needs it
	 * reports a checksum failure and does not answer from it */
	flip(path, t.pix.trailer_off + t.pix.body_len - 40000u);
	e = load(dir, NULL);
	CK(e != NULL && e->packs[0].pix != NULL, "a flipped record byte: the pack loads (the slice is checked when it is read)");
	if (e) {
		uint32_t ok;

		hits = sweep(e, NULL, 0, 1, &last, &ok);
		CK((last & KOFPIX_S_CRC) != 0, "the sweep that reads it reports KOFPIX_S_CRC (0x%x) and the region is not swept", last);
		CK(hits < 20000u, "and the markers it could not look for are not reported found (%u of 20000)", hits);
		kof_db_free(e);
	}
	free(r.img);
}

static void t_truncated_after_load(const char *dir)
{
	struct made r = build(20000, 64, 0, 0);
	char path[500];
	struct kof_engine *e;
	uint32_t last, hits, ok;

	CK(r.img != NULL, "the pack builds");
	if (!r.img)
		return;
	snprintf(path, sizeof path, "%s/p.ksig", dir);
	CK(put(dir, "p.ksig", r.img, r.len), "written");
	e = load(dir, NULL);
	CK(e != NULL && e->packs[0].has_pix, "loads with its table in the pack");
	if (e) {
		/* the old part stays mapped and is not touched by the sweep; the table is cut in half */
		CK(truncate(path, (off_t)(e->packs[0].pix_foot.trailer_off + e->packs[0].pix_foot.body_len / 2u)) == 0, "the file is cut under the engine");
		hits = sweep(e, NULL, 0, 1, &last, &ok);
		CK((last & (KOFPIX_S_IO | KOFPIX_S_CRC)) != 0, "the sweep reports an error (0x%x): no signal, and no answer from a table it cannot read", last);
		CK(hits < 20000u, "markers it could not look for are not reported found (%u of 20000)", hits);
		kof_db_free(e);
	}
	free(r.img);
}

static void t_ledger(const char *dir)
{
	struct made r = build(60000, 64, 0, ~0ull);        /* no part: it would be built in memory, ~2.2 MB */
	struct kof_engine *e;
	struct kof_budget b;
	struct kof_db_load_opt opt;

	CK(r.img != NULL, "the pack builds");
	if (!r.img)
		return;
	CK(put(dir, "p.ksig", r.img, r.len), "written");
	free(r.img);
	/* a ledger with 3 MB left: half of it is 1.5 MB, which the table does not fit */
	kof_budget_init(&b, KOF_ENGINE_MEM_MIN);
	(void)kof_budget_charge(&b, KOF_ENGINE_MEM_MIN - (3u << 20));
	memset(&opt, 0, sizeof opt);
	opt.budget = &b;
	e = load(dir, &opt);
	CK(e != NULL, "the engine loads");
	if (e) {
		CK((e->pix_status & KOF_PIX_B_OVER_BUDGET) != 0 && e->packs[0].pix == NULL && e->pix_set == NULL,
		   "the table does not fit the ledger: refused with KOF_PIX_B_OVER_BUDGET, and the markers are searched one at a time");
		kof_db_free(e);
	}
	/* and with room, the same pack takes the table */
	kof_budget_init(&b, KOF_ENGINE_MEM_CAP);
	e = load(dir, &opt);
	CK(e != NULL && e->packs[0].pix != NULL && (e->pix_status & KOF_PIX_B_OVER_BUDGET) == 0, "with the default ledger the same pack takes it");
	if (e)
		kof_db_free(e);
}

static void t_grouping(const char *dir)
{
	/* 64 strings a module and 1 a module: the same markers, so the same table */
	uint64_t b1 = 0, b2 = 0, m1 = 0, m2 = 0;
	uint32_t i;

	for (i = 0; i < 2u; i++) {
		struct made r = build(8000, i ? 1u : 64u, 0, 1);       /* embed always */
		struct kof_engine *e;

		CK(r.img != NULL, "the pack builds");
		if (!r.img)
			return;
		CK(put(dir, "p.ksig", r.img, r.len), "written");
		free(r.img);
		e = load(dir, NULL);
		CK(e != NULL && e->packs[0].has_pix, "loads with the table in the pack");
		if (e) {
			(void)kdb_pattern_status(e, i ? &b2 : &b1, i ? &m2 : &m1);
			kof_db_free(e);
		}
	}
	CK(m1 == m2 && m1 == 8004u, "the same %llu markers either way (%llu)", (unsigned long long)m1, (unsigned long long)m2);
	(void)b1;
	(void)b2;
}

int main(void)
{
	char dir[400];

	snprintf(tmp, sizeof tmp, "build/kof_pix_tail_%d", (int)getpid());
	if (mkdir(tmp, 0700) != 0) {
		printf("pix_tail: no build directory - nothing tested\n");
		return 0;
	}
	he_seed(0x71e0a1ull);
	snprintf(dir, sizeof dir, "%s/a", tmp); t_both_parts(dir);
	snprintf(dir, sizeof dir, "%s/b", tmp); t_old_shape(dir);
	snprintf(dir, sizeof dir, "%s/c", tmp); t_small(dir);
	snprintf(dir, sizeof dir, "%s/d", tmp); t_corruption(dir);
	snprintf(dir, sizeof dir, "%s/e", tmp); t_truncated_after_load(dir);
	snprintf(dir, sizeof dir, "%s/f", tmp); t_ledger(dir);
	snprintf(dir, sizeof dir, "%s/g", tmp); t_grouping(dir);
	he_rmtree(tmp);
	printf("pix_tail: %u checks, %u failed\n", he_checks, he_fails);
	return he_fails != 0;
}
