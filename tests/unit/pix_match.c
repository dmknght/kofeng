/*
 * pix_match - the pattern table that stays in the pack must find exactly what a
 * marker-by-marker search finds, from memory and from a file, and must say so when it
 * cannot.
 *
 * kofpix.c replaced tables built in memory (five shapes, kofmultimatch.c) with a filter, an
 * exact key set and a directory that are resident and records that are read from the pack.
 * It may be cheaper and it may not be different: a marker it fails to find is a
 * detection lost for a reason that depends on how big the database is. So the oracle
 * here is the simplest thing that can be right - every marker, at every position its
 * first byte allows, through kof_multimatch_pat_at, the verification the table ends in
 * - and it knows nothing of keys, directories or filters.
 *
 * Cases:
 *   random bytes with planted markers (literal, case-folded, whole-word, hex), whole
 *     object and three extents that cut markers at their edges;
 *   many markers sharing one key (a bucket larger than the slice buffer's share is
 *     forced by shrinking the buffer is NOT done here - the equal-hash run is);
 *   the same table from memory and through pread of a file;
 *   a read bound that is too small: the sweep stops, REPORTS it, and what it found is
 *     true;
 *   a file truncated under an open table: an error status and no signal;
 *   a table truncated before it is opened: refused;
 *   two packs through one set and one scanner's context (their filters merged into one),
 *     with the same offsets holding different bytes: a marker read for one is never taken
 *     for the other's;
 *   a section with bytes flipped anywhere in it: refused or answered, never a read out of
 *     bounds (the sanitised twin of this test is what proves the second half);
 *   the memo, which is now a cache: two questions that share a cell must not answer
 *   for each other, and a question forgotten is asked again and answered the same.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include "../../libkofeng/detectors/pattern/kofmatch.h"
#include "../../libkofeng/detectors/pattern/kofpix.h"
#include "../../libkofeng/detectors/pattern/kofmultimatch.h"
#include "../../libkofeng/databases/pack/hexprog.h"
#include "../../libkofeng/databases/pack/dbcore.h"
#include "../../libkofeng/databases/pack/dbkix.h"

#define FILE_PATH "build/kof_pix_match.tmp"

static int failures;

static void fail(const char *what, const char *why)
{
	printf("  FAIL %s: %s\n", what, why);
	failures++;
}

static uint64_t rng = 0x9E3779B97F4A7C15ULL;

static uint32_t rnd(void)
{
	rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
	return (uint32_t)(rng >> 16);
}

/* An open table and the set it is swept through (a set of one). `sl` is the sliced reader of a table read
 * from a file. */
struct tbl {
	struct kofpix     *px;
	struct kofpix_set *set;
	struct kof_slices  sl;
	int                have_sl;
};

static int tbl_set(struct tbl *t)
{
	t->set = kofpix_set_make(&t->px, 1);
	return t->set != NULL;
}

static void tbl_close(struct tbl *t)
{
	kofpix_set_free(t->set);
	kofpix_close(t->px);
	if (t->have_sl)
		kof_slices_done(&t->sl);
	memset(t, 0, sizeof *t);
}

#define N_MK   3000u
#define HAY    (96u * 1024u)

struct set {
	struct kofpix_marker mk[N_MK];
	uint8_t              *pool;
	uint32_t              pool_len;
	uint8_t               win[N_MK][20];   /* the bytes a hex marker was compiled from */
};

static void make_set(struct set *S)
{
	static const char al[] = "abcdeAB_/.";   /* a small alphabet: keys and prefixes collide */
	uint32_t i, n = 0;

	S->pool = malloc((size_t)N_MK * 260u);
	for (i = 0; i < N_MK; i++) {
		struct kofpix_marker *m = &S->mk[i];

		memset(m, 0, sizeof *m);
		m->uid = i;
		m->off = n;
		m->regs = (rnd() & 1u) ? (1u << 1) : (rnd() & 1u) ? (1u << 2) : 6u;
		if (i % 5u == 4u) {
			char txt[100]; uint8_t out[KOF_HEX_MAX_PROG]; struct kof_hex_stat st; uint32_t j, k; int p = 0;

			for (j = 0; j < 20; j++)
				S->win[i][j] = (uint8_t)rnd();
			for (j = 0; j < 20; j++)
				p += (j == 10 || j == 11) ? sprintf(txt + p, "?? ") : sprintf(txt + p, "%02X ", S->win[i][j]);
			txt[p - 1] = 0;
			memset(&st, 0, sizeof st);
			k = kof_hex_compile(txt, out, sizeof out, &st);
			n = (n + 3u) & ~3u;
			m->off = n;
			memcpy(S->pool + n, out, k);
			m->len = (uint16_t)k; m->kind = KOF_STR_HEX;
			n += k;
		} else {
			uint32_t len = 4u + rnd() % 14u, j;

			for (j = 0; j < len; j++)
				S->pool[n + j] = (uint8_t)al[rnd() % (sizeof al - 1u)];
			m->len = (uint16_t)len; m->kind = KOF_STR_LITERAL;
			m->flags = (uint8_t)((rnd() % 10u == 0) ? KOF_STR_ICASE : (rnd() % 12u == 0) ? KOF_STR_FULLWORD : 0u);
			n += len;
		}
		m->bytes = S->pool + m->off;
	}
	S->pool_len = n;
}

/* the oracle: every marker at every position its first byte allows */
static uint32_t oracle(const struct set *S, const uint8_t *hay, uint64_t n, uint32_t bit,
		       const struct kof_range *ex, uint32_t ne, uint32_t *bitsout /* [N_MK] */)
{
	uint32_t i, e, found = 0;
	struct kof_match_ctx m;

	memset(&m, 0, sizeof m);
	m.data.p = hay; m.data.n = n;
	memset(bitsout, 0, N_MK * sizeof *bitsout);
	for (i = 0; i < N_MK; i++) {
		const struct kofpix_marker *k = &S->mk[i];
		struct kof_multimatch_pat p;
		uint32_t alen;

		if (!((k->regs >> bit) & 1u) || !kof_multimatch_keyable(k->kind, k->len, k->bytes))
			continue;
		memset(&p, 0, sizeof p);
		p.flags = k->flags;
		if (k->kind == KOF_STR_HEX) {
			const struct kof_hex_hdr *h = (const void *)k->bytes;

			p.b = kof_multimatch_hex_anchor(k->bytes, &alen);
			p.len = (uint16_t)alen; p.is_hex = 1; p.prog = k->bytes;
			p.before_min = h->anchor_before_min; p.before_max = h->anchor_before_max; p.min_span = h->min_span;
		} else {
			p.b = k->bytes; p.len = k->len;
		}
		for (e = 0; e < ne && !bitsout[i]; e++) {
			uint64_t base = ex[e].off, span = kof_clip_len(n, base, ex[e].len), at;

			for (at = base; at + p.len <= base + span; at++)
				if (kof_multimatch_pat_at(&m, &p, at, base, span)) { bitsout[i] = 1u << bit; break; }
		}
		found += bitsout[i] != 0;
	}
	return found;
}

static int run_case(const char *name, struct tbl *tb, const struct set *S, const uint8_t *hay, uint64_t n,
		    const struct kof_range *ex, uint32_t ne)
{
	struct kofpix_ctx c;
	struct kof_match_ctx m;
	uint32_t want[N_MK], bit, i, bad = 0, total = 0;

	if (!kofpix_ctx_init(&c, NULL, 1u << 22)) {
		fail(name, "no context");
		return 1;
	}
	memset(&m, 0, sizeof m);
	m.data.p = hay; m.data.n = n;
	c.io_floor = 1ull << 40;                 /* exact: no read bound here */
	for (bit = 0; bit < KOFPIX_MAX_REG; bit++) {
		if (!kofpix_region_n(tb->px, bit))
			continue;
		kofpix_ctx_begin(&c);
		c.io_floor = 1ull << 40;
		kofpix_sweep(tb->set, &c, bit, &m, ex, ne);
		if (c.status) {
			fail(name, "status set on an unbounded sweep");
			bad++;
		}
		total += oracle(S, hay, n, bit, ex, ne, want);
		for (i = 0; i < N_MK; i++)
			if ((kofpix_found_get(&c, i) & (1u << bit)) != want[i]) {
				if (bad++ < 4)
					printf("    %s: marker %u region %u oracle %x table %x (kind %u flags %u len %u)\n", name, i, bit,
					       want[i], kofpix_found_get(&c, i) & (1u << bit), S->mk[i].kind, S->mk[i].flags, S->mk[i].len);
			}
	}
	kofpix_ctx_free(&c);
	if (bad)
		fail(name, "the table and the oracle disagree");
	else
		printf("  ok   %s (%u markers present)\n", name, total);
	return bad != 0;
}

static void plant(const struct set *S, uint8_t *buf, uint32_t n_plant)
{
	uint32_t j;

	for (j = 0; j < n_plant; j++) {
		uint32_t i = rnd() % N_MK, at = j * 400u + 2u + rnd() % 80u;
		const struct kofpix_marker *k = &S->mk[i];

		if (at + 300u > HAY)
			break;
		if (k->kind == KOF_STR_LITERAL) {
			uint32_t t;

			memcpy(buf + at, k->bytes, k->len);
			if (k->flags & KOF_STR_ICASE)
				for (t = 0; t < k->len; t++)
					if ((rnd() & 1u) && buf[at + t] >= 'a' && buf[at + t] <= 'z')
						buf[at + t] = (uint8_t)(buf[at + t] - 32);
			buf[at - 1u] = ' '; buf[at + k->len] = ' ';
		} else {
			uint8_t w[20];

			memcpy(w, S->win[i], 20);
			w[10] = (uint8_t)rnd(); w[11] = (uint8_t)rnd();
			memcpy(buf + at, w, 20);
		}
	}
}


/* The memo is a direct-mapped cache of at most KOF_MEMO_CELLS_MAX cells. Slots that land in
 * one cell evict each other; an eviction may cost a search and may not change an answer. */
static void memo_cache(void)
{
	static const uint8_t hay[] = "xx hello world xx";
	struct kof_match_ctx m;
	struct kof_range ex = { 0, sizeof hay - 1u };
	const uint32_t cells = KOF_MEMO_CELLS_MAX, a = 5u, b = 5u + cells, big = 0x40000000u + 5u;
	uint64_t cost = kof_match_memo_bytes(0x40000000u);
	int bad = 0;
	struct kof_match_req ra = { .slot = a, .next = 1, .ext = &ex, .pat = { (const uint8_t *)"hello", 5, KOF_STR_LITERAL, 0 } };
	struct kof_match_req rb = { .slot = b, .next = 1, .ext = &ex, .pat = { (const uint8_t *)"xyzzy", 5, KOF_STR_LITERAL, 0 } };

	memset(&m, 0, sizeof m);
	if (!kof_match_state_init(&m, 2, 0x40000000u)) {
		fail("memo", "no state for a database of a billion slots");
		return;
	}
	if (cost != (uint64_t)KOF_MEMO_CELLS_MAX * sizeof(struct kof_memo_cell))
		bad++, fail("memo", "the cost of a memo grows with the database");
	kof_match_begin(&m, (kof_buf){ hay, sizeof hay - 1u });
	if (kof_match_lookup(&m, &ra) != 1 || kof_match_memo_get(&m, a) != 1)
		bad++, fail("memo", "first answer");
	if (kof_match_lookup(&m, &rb) != 0 || kof_match_memo_get(&m, b) != 0)
		bad++, fail("memo", "second answer");
	if (kof_match_memo_get(&m, a) != -1)
		bad++, fail("memo", "a slot another slot evicted still answered from the cell");
	if (kof_match_lookup(&m, &ra) != 1)
		bad++, fail("memo", "a forgotten question answered differently when asked again");
	ra.slot = big;
	if (kof_match_lookup(&m, &ra) != 1 || kof_match_memo_get(&m, big) != 1)
		bad++, fail("memo", "a slot past 2^30");
	ra.slot = KOF_MEMO_NONE;
	if (kof_match_lookup(&m, &ra) != 1 || kof_match_memo_get(&m, KOF_MEMO_NONE) != -1)
		bad++, fail("memo", "KOF_MEMO_NONE was cached");
	kof_match_begin(&m, (kof_buf){ hay, sizeof hay - 1u });
	if (kof_match_memo_get(&m, big) != -1)
		bad++, fail("memo", "an answer survived into the next object");
	kof_match_state_free(&m);
	if (!bad)
		printf("  ok   the memo is a cache: %llu bytes for any database, evictions change no answer\n", (unsigned long long)cost);
}

/* Open a table that is in memory. `budget` is what the ledger would have granted for the filters. */
static struct kofpix *open_mem(const uint8_t *sec, uint64_t len, const uint8_t *pool, uint32_t pool_len,
			       uint64_t budget, uint32_t uid_base, struct kofpix_open_res *res)
{
	struct kofpix_open_req rq;

	memset(&rq, 0, sizeof rq);
	rq.src.fd = -1;
	rq.src.sec_len = len;
	rq.src.mem = sec;
	rq.src.pool_mem = pool;
	rq.src.pool_len = pool_len;
	rq.filter_budget = budget;
	rq.filter_default = KOFPIX_FILTER_DEFAULT;
	rq.uid_base = uid_base;
	return kofpix_open(&rq, res);
}

/*
 * A table in a file the way a pack holds it: the pool first (the pack's old part), then the table with its
 * slice checksums and its footer (the pack's tail). Returns the descriptor, or -1. `*pool_len_out` is the
 * pool's padded length, which is where the part starts.
 */
static int write_pack_like(const char *path, const uint8_t *sec, uint64_t seclen, uint32_t n_item,
			   const uint8_t *pool, uint32_t pool_len, uint64_t *old_len, uint64_t *part_len)
{
	uint64_t at = ((uint64_t)pool_len + 63u) & ~63ULL, plen = 0;
	uint8_t *part = kof_pix_make(sec, seclen, n_item, at, at, 0, &plen), *pad = calloc(1, (size_t)at);
	int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);

	if (!part || !pad || fd < 0 || write(fd, pool, pool_len) != (ssize_t)pool_len ||
	    write(fd, pad + pool_len, (size_t)(at - pool_len)) != (ssize_t)(at - pool_len) ||
	    write(fd, part, (size_t)plen) != (ssize_t)plen) {
		free(part);
		free(pad);
		if (fd >= 0)
			close(fd);
		return -1;
	}
	free(part);
	free(pad);
	*old_len = at;
	*part_len = plen;
	return fd;
}

/* Open the table of a file made by write_pack_like through the container, as the loader does. 0 with a
 * reason on stderr-less failure (`why`). */
static int open_pack_like(int fd, uint64_t size, const struct set *S, uint64_t budget, uint32_t uid_base,
			  struct tbl *t, char *why, size_t why_len, enum kofpix_status *ks)
{
	struct kof_tail tail;
	struct kofpix_open_req rq;
	struct kofpix_open_res res;

	memset(t, 0, sizeof *t);
	if (!kof_tail_probe(fd, size, &tail) || !tail.has_pix) {
		snprintf(why, why_len, "no pattern part found at the end of the file");
		*ks = KOFPIX_E_FORMAT;
		return 0;
	}
	if (!kof_pix_open_file(fd, size, &tail.pix, &t->sl, why, why_len)) {
		*ks = KOFPIX_E_CRC;
		return 0;
	}
	t->have_sl = 1;
	memset(&rq, 0, sizeof rq);
	rq.src.sec = &t->sl;
	rq.src.sec_len = tail.pix.body_len;
	rq.src.fd = fd;
	rq.src.pool_off = 0;
	rq.src.pool_len = S->pool_len;
	rq.filter_budget = budget;
	rq.filter_default = KOFPIX_FILTER_DEFAULT;
	rq.uid_base = uid_base;
	t->px = kofpix_open(&rq, &res);
	*ks = res.status;
	if (!t->px) {
		snprintf(why, why_len, "the table does not open");
		kof_slices_done(&t->sl);
		t->have_sl = 0;
		return 0;
	}
	if (!tbl_set(t)) {
		tbl_close(t);
		return 0;
	}
	return 1;
}

/* Flip bytes of a copy of the section, open it, and sweep one object. What it may do is refuse
 * or answer; what it may not do is read outside what it was given. */
static void fuzz_section(const struct set *S, const uint8_t *sec, uint64_t seclen, const uint8_t *hay)
{
	uint8_t *copy = malloc(seclen);
	uint32_t round, opened = 0, refused = 0;

	for (round = 0; round < 600u; round++) {
		struct kofpix *px;
		struct kofpix_open_res res;
		uint32_t flips = 1u + rnd() % 6u, k;

		memcpy(copy, sec, seclen);
		for (k = 0; k < flips; k++) {
			/* half the flips land in the first 4 KB (header and region tables), the rest anywhere */
			uint64_t at = (rnd() & 1u) ? rnd() % 4096u : ((uint64_t)rnd() << 8 | (rnd() & 255u)) % seclen;

			copy[at % seclen] = (uint8_t)rnd();
		}
		px = open_mem(copy, seclen, S->pool, S->pool_len, 1u << 18, 0, &res);
		if (!px) {
			refused++;
			continue;
		}
		opened++;
		{
			struct kofpix_ctx c;
			struct kof_match_ctx m;
			struct kof_range ex = { 0, HAY };
			struct kofpix_set *set = kofpix_set_make(&px, 1);
			uint32_t bit;

			kofpix_ctx_init(&c, NULL, 1u << 20);
			memset(&m, 0, sizeof m);
			m.data.p = hay; m.data.n = HAY;
			kofpix_ctx_begin(&c);
			for (bit = 0; set && bit < KOFPIX_MAX_REG; bit++)
				if (kofpix_region_n(px, bit))
					kofpix_sweep(set, &c, bit, &m, &ex, 1);
			kofpix_ctx_free(&c);
			kofpix_set_free(set);
		}
		kofpix_close(px);
	}
	free(copy);
	printf("  ok   600 corrupted sections: %u refused, %u opened and swept without a fault\n", refused, opened);
}

/* The same, through the container: flip bytes of the part in a file (the table, its slice CRCs, its footer)
 * and open it as the loader does. Anything the checksums can see must be refused at open or answered as an
 * error by the sweep; nothing may be answered quietly wrong. */
static void fuzz_part(const struct set *S, const uint8_t *sec, uint64_t seclen, uint32_t n_item, const uint8_t *hay)
{
	const char *path = "build/kof_pix_match_part.tmp";
	uint64_t old_len, part_len;
	int fd = write_pack_like(path, sec, seclen, n_item, S->pool, S->pool_len, &old_len, &part_len);
	uint32_t round, ok = 0, refused = 0, wrong = 0, errored = 0;
	uint8_t *img;
	uint64_t size = old_len + part_len;

	if (fd < 0) {
		fail("fuzz part", "cannot write the scratch file");
		return;
	}
	img = malloc(size);
	if (pread(fd, img, size, 0) != (ssize_t)size) {
		fail("fuzz part", "cannot read the file back");
		free(img);
		close(fd);
		return;
	}
	for (round = 0; round < 200u; round++) {
		struct tbl t;
		char why[200];
		enum kofpix_status ks;
		uint64_t at = old_len + (((uint64_t)rnd() << 8 | (rnd() & 255u)) % part_len);
		uint8_t save = img[at];

		/* the flipped byte is written to the file; the descriptor is the loader's */
		img[at] = (uint8_t)(save ^ (1u + rnd() % 255u));
		if (pwrite(fd, img + at, 1, (off_t)at) != 1) {
			fail("fuzz part", "cannot write");
			break;
		}
		if (!open_pack_like(fd, size, S, 1u << 18, 0, &t, why, sizeof why, &ks)) {
			refused++;
		} else {
			struct kofpix_ctx c;
			struct kof_match_ctx m;
			struct kof_range ex = { 0, HAY };
			uint32_t bit, want[N_MK], i, bad = 0;

			ok++;
			kofpix_ctx_init(&c, NULL, 1u << 20);
			memset(&m, 0, sizeof m);
			m.data.p = hay; m.data.n = HAY;
			kofpix_ctx_begin(&c);
			c.io_floor = 1ull << 40;
			for (bit = 0; bit < KOFPIX_MAX_REG; bit++)
				if (kofpix_region_n(t.px, bit)) {
					kofpix_sweep(t.set, &c, bit, &m, &ex, 1);
					if (c.last) {
						errored++;       /* a checksum caught it during the sweep: the region is reported, not swept */
						continue;
					}
					oracle(S, hay, HAY, bit, &ex, 1, want);
					for (i = 0; i < N_MK; i++)
						if ((kofpix_found_get(&c, i) & (1u << bit)) != want[i])
							bad++;
				}
			wrong += bad != 0;
			kofpix_ctx_free(&c);
			tbl_close(&t);
		}
		img[at] = save;
		if (pwrite(fd, img + at, 1, (off_t)at) != 1)
			break;
	}
	free(img);
	close(fd);
	remove(path);
	if (wrong)
		fail("fuzz part", "a flipped byte changed an answer without being caught");
	else
		printf("  ok   200 flipped bytes in a part: %u refused at open, %u opened (%u regions reported by the sweep), none answered wrong\n",
		       refused, ok, errored);
}

/* Two tables, one set, one context, the same pool offsets holding different bytes (the second pool has every
 * literal reversed): the context caches marker bytes by offset, so it has to know whose they are. Their filters
 * are merged into one, which is the other thing this proves: a marker of either must pass it. */
static void two_packs(const struct set *S, const uint8_t *hay)
{
	static struct set S2;
	struct tbl tb[2];
	struct kofpix *px[2];
	struct kofpix_set *set;
	struct kofpix_ctx c;
	struct kof_match_ctx m;
	struct kof_range whole = { 0, HAY };
	uint8_t *sec[2], *pool2 = malloc(S->pool_len);
	uint64_t len[2];
	uint32_t i, bit, want1[N_MK], want2[N_MK], bad = 0;
	int fds[2], k;
	char path[2][64];

	memcpy(&S2, S, sizeof S2);
	memcpy(pool2, S->pool, S->pool_len);
	for (i = 0; i < N_MK; i++) {
		if (S->mk[i].kind == KOF_STR_LITERAL) {
			uint32_t a = 0, z = S->mk[i].len;

			while (a + 1u < z) {
				uint8_t t = pool2[S->mk[i].off + a];

				pool2[S->mk[i].off + a] = pool2[S->mk[i].off + z - 1u];
				pool2[S->mk[i].off + z - 1u] = t;
				a++; z--;
			}
		}
		S2.mk[i].bytes = pool2 + S->mk[i].off;
	}
	S2.pool = pool2;
	sec[0] = kofpix_build(S->mk, N_MK, &len[0], NULL, NULL);
	sec[1] = kofpix_build(S2.mk, N_MK, &len[1], NULL, NULL);
	for (k = 0; k < 2; k++) {
		char why[200];
		enum kofpix_status ks;
		uint64_t old_len, part_len;
		const uint8_t *pool = k ? pool2 : S->pool;

		snprintf(path[k], sizeof path[k], "build/kof_pix_match_%d.tmp", k);
		fds[k] = write_pack_like(path[k], sec[k], len[k], N_MK, pool, S->pool_len, &old_len, &part_len);
		if (fds[k] < 0 || !open_pack_like(fds[k], old_len + part_len, S, 1u << 16, k ? 100000u : 0u, &tb[k], why, sizeof why, &ks)) {
			fail("two packs", "open refused");
			return;
		}
		px[k] = tb[k].px;
		/* the set below takes both: this table's own set is given up, its table and its reader are kept */
		kofpix_set_free(tb[k].set);
		tb[k].set = NULL;
	}
	set = kofpix_set_make(px, 2);
	if (!set) {
		fail("two packs", "no set");
		return;
	}
	kofpix_ctx_init(&c, NULL, 1u << 22);
	memset(&m, 0, sizeof m);
	m.data.p = hay; m.data.n = HAY;
	kofpix_ctx_begin(&c);
	c.io_floor = 1ull << 40;
	for (bit = 0; bit < KOFPIX_MAX_REG; bit++)
		kofpix_sweep(set, &c, bit, &m, &whole, 1);
	for (bit = 1; bit <= 2u; bit++) {
		oracle(S, hay, HAY, bit, &whole, 1, want1);
		oracle(&S2, hay, HAY, bit, &whole, 1, want2);
		for (i = 0; i < N_MK; i++) {
			if ((kofpix_found_get(&c, i) & (1u << bit)) != want1[i]) bad++;
			if ((kofpix_found_get(&c, 100000u + i) & (1u << bit)) != want2[i]) bad++;
		}
	}
	if (bad)
		fail("two packs", "a marker of one pack was answered with the bytes of the other");
	else
		printf("  ok   two packs, one set, one context, the same offsets holding different bytes\n");
	kofpix_ctx_free(&c);
	kofpix_set_free(set);
	for (k = 0; k < 2; k++) {
		tbl_close(&tb[k]);
		close(fds[k]);
		remove(path[k]);
		free(sec[k]);
	}
	free(pool2);
}

/*
 * A BASE WHOSE MARKERS SHARE THEIR KEY, AND AN OBJECT FULL OF IT. 20000 hex programs on one eight-byte
 * anchor (they differ only in two bytes after a wildcard) put every one of them on the same key hash: a run
 * of 20000 equal keys. An object that is the anchor over and over makes every eighth position a survivor,
 * and each survivor would walk the whole run - a base size times an object size of work that no read bound
 * sees, because the records are in memory. The allowance of record visits stops it (KOFPIX_S_WORK), the
 * sweep says so, and what it found before it stopped is true.
 */
static void hostile_run(void)
{
	enum { N = 20000, HAYN = 256 * 1024 };
	static uint8_t progs[N][KOF_HEX_MAX_PROG];
	static uint32_t plen[N];
	struct kofpix_marker *mk = calloc(N, sizeof *mk);
	uint8_t *pool = malloc((size_t)N * 160u), *hay = malloc(HAYN), *sec;
	uint32_t i, n = 0, wrong = 0, got = 0;
	uint64_t seclen;
	struct kofpix *px;
	struct kofpix_set *set;
	struct kofpix_open_res res;
	struct kofpix_ctx c;
	struct kof_match_ctx m;
	struct kof_range whole = { 0, HAYN };
	struct kofpix_build_stat st;

	for (i = 0; i < N; i++) {
		char t[96];
		struct kof_hex_stat hs;

		snprintf(t, sizeof t, "50 58 54 4C 48 58 41 58 ?? %02X %02X", i & 255u, (i >> 8) & 255u);
		memset(&hs, 0, sizeof hs);
		plen[i] = kof_hex_compile(t, progs[i], sizeof progs[i], &hs);
		n = (n + 3u) & ~3u;
		memcpy(pool + n, progs[i], plen[i]);
		mk[i].bytes = pool + n; mk[i].off = n; mk[i].len = (uint16_t)plen[i]; mk[i].kind = KOF_STR_HEX;
		mk[i].uid = i; mk[i].regs = 1u << 1;
		n += plen[i];
	}
	for (i = 0; i < HAYN; i++)
		hay[i] = (uint8_t)"PXTLHXAX"[i & 7u];
	sec = kofpix_build(mk, N, &seclen, &st, NULL);
	px = sec ? open_mem(sec, seclen, pool, n, 1u << 20, 0, &res) : NULL;
	set = px ? kofpix_set_make(&px, 1) : NULL;
	if (!set || kofpix_ctx_init(&c, NULL, 1u << 22) == 0) {
		fail("hostile run", "setup failed");
		return;
	}
	memset(&m, 0, sizeof m);
	m.data.p = hay; m.data.n = HAYN;
	kofpix_ctx_begin(&c);
	{
		struct timespec t0, t1;
		double s;

		clock_gettime(CLOCK_MONOTONIC, &t0);
		kofpix_sweep(set, &c, 1, &m, &whole, 1);
		clock_gettime(CLOCK_MONOTONIC, &t1);
		s = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) * 1e-9;
		for (i = 0; i < N; i++) {
			uint32_t b = kofpix_found_get(&c, i) & 2u;

			wrong += b != 0;       /* no program can match: its tail bytes are never in the object */
			got += b != 0;
		}
		if (!(c.status & (KOFPIX_S_WORK | KOFPIX_S_BUDGET)) || !c.last)
			fail("hostile run", "a run of 20000 equal keys under an object full of the key did not stop or say so");
		else if (wrong)
			fail("hostile run", "a stopped sweep reported a program that cannot match");
		else if (s > 3.0)
			fail("hostile run", "the sweep took longer than the bound allows");
		else
			printf("  ok   a run of %llu equal keys under an object full of it: stopped (status 0x%x) in %.0f ms, none false\n",
			       (unsigned long long)st.max_run, c.status, s * 1e3);
	}
	kofpix_ctx_free(&c);
	kofpix_set_free(set);
	kofpix_close(px);
	free(sec); free(mk); free(pool); free(hay);
}

/*
 * A FILTER THE LEDGER GAVE LESS TO. The same 60000 markers opened with the default filter budget and with a
 * few kilobytes: the second is coarser (the result says how many regions are), and it finds exactly what the
 * first finds - a coarser filter only lets more positions reach the exact key set. Both are compared with
 * what was planted.
 */
static void degraded_filter(void)
{
	enum { N = 60000, HAYN = 200000 };
	struct kofpix_marker *mk = calloc(N, sizeof *mk);
	uint8_t *pool = malloc((size_t)N * 12u), *hay = malloc(HAYN), *sec;
	uint32_t i, n = 0, planted[40], np = 0, bad = 0, miss = 0;
	uint64_t seclen;
	struct kofpix *px[2];
	struct kofpix_set *set[2];
	struct kofpix_open_res res[2];
	struct kofpix_ctx c[2];
	struct kof_match_ctx m;
	struct kof_range whole = { 0, HAYN };
	uint32_t k;

	for (i = 0; i < N; i++) {
		uint32_t j;

		for (j = 0; j < 10; j++)
			pool[n + j] = (uint8_t)('a' + rnd() % 26u);
		mk[i].bytes = pool + n; mk[i].off = n; mk[i].len = 10; mk[i].kind = KOF_STR_LITERAL; mk[i].uid = i; mk[i].regs = 1u << 1;
		n += 10;
	}
	for (i = 0; i < HAYN; i++)
		hay[i] = (uint8_t)('a' + rnd() % 26u);
	for (k = 0; k < 40; k++) {
		planted[np] = rnd() % N;
		memcpy(hay + 1000u + k * 4000u, pool + mk[planted[np]].off, 10);
		np++;
	}
	sec = kofpix_build(mk, N, &seclen, NULL, NULL);
	for (k = 0; k < 2; k++) {
		px[k] = open_mem(sec, seclen, pool, n, k ? 1u << 12 : KOFPIX_FILTER_DEFAULT, 0, &res[k]);
		set[k] = px[k] ? kofpix_set_make(&px[k], 1) : NULL;
		if (!set[k] || !kofpix_ctx_init(&c[k], NULL, 1u << 22)) {
			fail("degraded filter", "setup failed");
			return;
		}
		memset(&m, 0, sizeof m);
		m.data.p = hay; m.data.n = HAYN;
		kofpix_ctx_begin(&c[k]);
		kofpix_sweep(set[k], &c[k], 1, &m, &whole, 1);
		if (c[k].last)
			bad++;
	}
	for (i = 0; i < N; i++)
		bad += (kofpix_found_get(&c[0], i) & 2u) != (kofpix_found_get(&c[1], i) & 2u);
	for (k = 0; k < np; k++)
		miss += !(kofpix_found_get(&c[1], planted[k]) & 2u);
	if (res[0].degraded != 0 || res[1].degraded == 0)
		fail("degraded filter", "the default budget was reported degraded, or the small one was not");
	else if (bad || miss)
		fail("degraded filter", "a coarser filter changed what was found, or lost a planted marker");
	else
		printf("  ok   a filter the ledger gave 4 KB: %u of its regions are reported degraded, the same %u markers found, none planted lost\n",
		       res[1].degraded, c[0].found.n);
	for (k = 0; k < 2; k++) {
		kofpix_ctx_free(&c[k]);
		kofpix_set_free(set[k]);
		kofpix_close(px[k]);
	}
	free(sec); free(mk); free(pool); free(hay);
}

int main(void)
{
	static struct set S;
	uint8_t *hay = malloc(HAY), *sec, *mem_copy;
	uint64_t seclen, i;
	struct kofpix_build_stat st;
	struct tbl t_mem, t_file;
	struct kofpix_open_res res;
	struct kof_range whole = { 0, HAY }, cut[3] = { { 1000, 30000 }, { 30003, 40000 }, { 70001, HAY } };
	uint64_t old_len, part_len, fsize;
	char why[200];
	enum kofpix_status ks;
	int fd;

	printf("pix_match\n");
	memo_cache();
	make_set(&S);
	for (i = 0; i < HAY; i++)
		hay[i] = (uint8_t)("abcdeAB_/. \n\t"[rnd() % 13u]);   /* the markers' own alphabet: many near misses */
	plant(&S, hay, 200);

	sec = kofpix_build(S.mk, N_MK, &seclen, &st, NULL);
	if (!sec) {
		fail("build", "no section");
		return 1;
	}
	printf("  section %llu bytes, %llu records in %u regions\n", (unsigned long long)seclen, (unsigned long long)st.n_rec, st.n_reg);

	/* from memory */
	memset(&t_mem, 0, sizeof t_mem);
	t_mem.px = open_mem(sec, seclen, S.pool, S.pool_len, 1u << 20, 0, &res);
	if (!t_mem.px || !tbl_set(&t_mem)) {
		fail("open memory", "refused");
		return 1;
	}
	run_case("memory, whole object", &t_mem, &S, hay, HAY, &whole, 1);
	run_case("memory, three extents", &t_mem, &S, hay, HAY, cut, 3);

	/* from a file, the way a pack holds it: the pool, then the part with its checksums and its footer */
	fd = write_pack_like(FILE_PATH, sec, seclen, N_MK, S.pool, S.pool_len, &old_len, &part_len);
	fsize = old_len + part_len;
	if (fd < 0 || !open_pack_like(fd, fsize, &S, 1u << 14, 0, &t_file, why, sizeof why, &ks)) {
		fail("open file", "refused");
		return 1;
	}
	run_case("file, whole object", &t_file, &S, hay, HAY, &whole, 1);
	run_case("file, three extents", &t_file, &S, hay, HAY, cut, 3);
	printf("  resident: file %llu bytes, memory %llu bytes (the section is %llu)\n", (unsigned long long)kofpix_resident(t_file.px),
	       (unsigned long long)kofpix_resident(t_mem.px), (unsigned long long)seclen);

	/* a bound that is too small: stop, say so, and what was found is true */
	{
		struct kofpix_ctx c;
		struct kof_match_ctx m;
		uint32_t want[N_MK], bit = 1, wrong = 0, got = 0;

		kofpix_ctx_init(&c, NULL, 1u << 22);
		memset(&m, 0, sizeof m);
		m.data.p = hay; m.data.n = HAY;
		kofpix_ctx_begin(&c);
		c.io_floor = 4; c.io_shift = 63;
		kofpix_sweep(t_file.set, &c, bit, &m, &whole, 1);
		oracle(&S, hay, HAY, bit, &whole, 1, want);
		for (i = 0; i < N_MK; i++) {
			uint32_t b = kofpix_found_get(&c, (uint32_t)i) & (1u << bit);

			if (b & ~want[i]) wrong++;
			got += b != 0;
		}
		if (!(c.status & KOFPIX_S_BUDGET) || !c.last)
			fail("bound", "a read bound of 4 did not stop the sweep, or did not say so");
		else if (wrong)
			fail("bound", "a stopped sweep reported a marker that is not there");
		else
			printf("  ok   a bound of 4 reads stops the sweep and reports it (%u found, none false)\n", got);
		kofpix_ctx_free(&c);
	}

	/* the file loses its tail under an open table: an error, never a signal */
	{
		struct kofpix_ctx c;
		struct kof_match_ctx m;

		if (ftruncate(fd, (off_t)(old_len + part_len / 2u)) != 0) {
			fail("truncate", "cannot truncate");
		} else {
			kofpix_ctx_init(&c, NULL, 1u << 22);
			memset(&m, 0, sizeof m);
			m.data.p = hay; m.data.n = HAY;
			kofpix_ctx_begin(&c);
			c.io_floor = 1ull << 40;
			kofpix_sweep(t_file.set, &c, 1, &m, &whole, 1);
			kofpix_sweep(t_file.set, &c, 2, &m, &whole, 1);
			if (!(c.status & KOFPIX_S_IO))
				fail("truncated under an open table", "no error status");
			else
				printf("  ok   a pack truncated under an open table reports an I/O error\n");
			kofpix_ctx_free(&c);
			/* and opened after the truncation: no footer at the end any more, so no part */
			tbl_close(&t_file);
			if (open_pack_like(fd, old_len + part_len / 2u, &S, 1u << 14, 0, &t_file, why, sizeof why, &ks))
				fail("truncated before open", "was accepted");
			else
				printf("  ok   a truncated part is refused at open (%s)\n", why);
		}
	}

	two_packs(&S, hay);
	hostile_run();
	degraded_filter();
	fuzz_section(&S, sec, seclen, hay);
	fuzz_part(&S, sec, seclen, N_MK, hay);

	/* a corrupt directory is refused */
	mem_copy = malloc(seclen);
	memcpy(mem_copy, sec, seclen);
	{
		uint8_t *p;

		/* the first region's record directory sits after the header; flip a word in it */
		p = mem_copy + 3000;                       /* inside a directory or key table */
		for (i = 0; i < 4096; i++)
			p[i] = 0xff;
		if (open_mem(mem_copy, seclen, S.pool, S.pool_len, 1u << 20, 0, &res))
			fail("corrupt directory", "was accepted");
		else
			printf("  ok   a corrupt directory is refused (status %d)\n", (int)res.status);
	}
	free(mem_copy);
	tbl_close(&t_mem);
	close(fd);
	remove(FILE_PATH);
	free(sec); free(hay); free(S.pool);
	printf(failures ? "FAILED (%d)\n" : "pix_match: all passed\n", failures);
	return failures != 0;
}
