/*
 * kofpix_build.c - the pattern table's builder: the packer's side of kofpix.h (kofpix_build), and
 * the collection of a pack's markers from its own sections (kofpix_build_pack), which the loader
 * also calls for a pack that has no table in its tail. The reader and the sweep are kofpix.c.
 */
#define _GNU_SOURCE
#include "kofpix_private.h"
#include "../../databases/pack/hexprog.h"
#include "../../databases/pack/dbcore.h"

#include <stdlib.h>
#include <string.h>


static uint32_t clog2(uint64_t v)
{
	uint32_t b = 0;

	while (((uint64_t)1 << b) < v)
		b++;
	return b;
}

static uint32_t ld4(const uint8_t *p, uint32_t fold)
{
	uint32_t v = kof_ld_le32(p);

	return fold ? kof_mm_swar_lower(v) : v;
}

/* The bytes after the key, nv of them, packed little-endian. */
static uint32_t after_key(const uint8_t *k, uint32_t klen, uint32_t koff, uint32_t fold,
			  uint32_t *nv)
{
	uint32_t n = klen > koff + 4u ? klen - koff - 4u : 0u, c = 0, j;

	if (n > 4u)
		n = 4u;
	for (j = 0; j < n; j++) {
		uint8_t b = k[koff + 4u + j];

		c |= (uint32_t)(fold ? kof_lower_byte(b) : b) << (8u * j);
	}
	*nv = n;
	return c;
}

/* The frequency table's size follows the number of grams it counts (2^10 .. 2^22 words): a table of
 * 16 MiB cleared for 226 markers would cost more than building the rest. A collision in it only
 * moves WHERE a marker is keyed. */
#define FREQ_BITS_MAX 22u
#define FREQ_BITS_MIN 10u

/*
 * Where to take a marker's key.
 *
 * The first rule is the one the in-memory table already uses: the four bytes that
 * the fewest other markers of the region contain, so one hash is shared by few
 * records. A wrong count costs a longer run of equal hashes, never an answer.
 *
 * The second is about the OBJECT and not the base. The key's hash is what the sweep
 * tests at every byte, so a key that is common in ordinary files lets that many
 * positions through the filter whatever the base holds - measured on a clean ELF
 * with a million markers, 36% of positions passed. `common` (kofpix_build_opt) says
 * which hashed grams ordinary files contain; a position of the marker that is not in
 * it is preferred over one that is. It is a choice of WHERE a marker is keyed and
 * moves no answer: every position of the marker is a valid key.
 *
 * Hex programs are keyed inside their concrete run the same way; `koff` then says
 * how far into the run the key sits, and the verify steps back by it.
 */
static void pick_koff(const struct kofpix_marker *mk, const uint32_t *idx, uint32_t n,
		      uint32_t fold, uint16_t *out, uint32_t *freq, uint32_t fbits,
		      const struct kofpix_build_opt *opt)
{
	uint32_t i, j;
	const uint16_t *common = opt ? opt->common : NULL;
	const uint32_t cbits = opt ? opt->common_bits : 0, cthr = opt ? opt->common_thr : 0;

	memset(freq, 0, ((size_t)1 << fbits) * sizeof *freq);
	for (i = 0; i < n; i++) {
		const struct kofpix_marker *q = &mk[idx[i]];
		const uint8_t *key = q->bytes;
		uint32_t klen = q->len;

		if (q->kind == KOF_STR_HEX)
			key = kof_multimatch_hex_anchor(q->bytes, &klen);
		for (j = 0; j + 4u <= klen; j++)
			freq[(ld4(key + j, fold) * KOF_MM_MUL) >> (32u - fbits)]++;
	}
	for (i = 0; i < n; i++) {
		const struct kofpix_marker *q = &mk[idx[i]];
		const uint8_t *key = q->bytes;
		uint32_t klen = q->len, best = 0, bs = 0xffffffffu;

		if (q->kind == KOF_STR_HEX)
			key = kof_multimatch_hex_anchor(q->bytes, &klen);
		for (j = 0; j + 4u <= klen; j++) {
			uint32_t g = ld4(key + j, fold) * KOF_MM_MUL;
			uint32_t f = freq[g >> (32u - fbits)], sc;
			uint32_t com = 0;

			if (common) {
				/* the document frequency of the lowercased gram, whatever the region folds */
				uint32_t gl = kof_mm_swar_lower(kof_ld_le32(key + j)) * KOF_MM_MUL;

				com = common[gl >> (32u - cbits)] >= cthr;
			}
			sc = (com ? 0x10000u : 0u) + (f < 0xffffu ? f : 0xffffu);
			if (sc < bs) { bs = sc; best = j; }
		}
		out[i] = (uint16_t)best;
	}
}

/* LSD radix on g, stable, 11+11+10 bits. */
static struct kofpix_rec *radix_g(struct kofpix_rec *a, struct kofpix_rec *b, size_t n)
{
	static const uint32_t sh[3] = { 0, 11, 22 }, bits[3] = { 11, 11, 10 };
	uint32_t pass;
	size_t i, *cnt = malloc(((size_t)1 << 11) * sizeof *cnt);

	if (!cnt)
		return NULL;
	for (pass = 0; pass < 3; pass++) {
		size_t k = (size_t)1 << bits[pass], pos = 0;
		struct kofpix_rec *t;

		memset(cnt, 0, k * sizeof *cnt);
		for (i = 0; i < n; i++)
			cnt[(a[i].g >> sh[pass]) & (uint32_t)(k - 1u)]++;
		for (i = 0; i < k; i++) { size_t c = cnt[i]; cnt[i] = pos; pos += c; }
		for (i = 0; i < n; i++)
			b[cnt[(a[i].g >> sh[pass]) & (uint32_t)(k - 1u)]++] = a[i];
		t = a; a = b; b = t;
	}
	free(cnt);
	return a;       /* three swaps: the sorted data is in what was `b` */
}

struct wbuf { uint8_t *p; uint64_t n, cap; };

static int wput(struct wbuf *w, const void *src, uint64_t n)
{
	if (w->n + n > w->cap) {
		uint64_t nc = w->cap ? w->cap : 1u << 12;
		uint8_t *np;

		while (nc < w->n + n)
			nc *= 2u;
		np = realloc(w->p, (size_t)nc);
		if (!np)
			return 0;
		w->p = np; w->cap = nc;
	}
	if (src)
		memcpy(w->p + w->n, src, (size_t)n);
	else
		memset(w->p + w->n, 0, (size_t)n);
	w->n += n;
	return 1;
}

static int walign(struct wbuf *w)
{
	uint64_t pad = (64u - (w->n & 63u)) & 63u;

	return pad ? wput(w, NULL, pad) : 1;
}

uint8_t *kofpix_build(const struct kofpix_marker *mk, uint32_t n, uint64_t *len,
		      struct kofpix_build_stat *st, const struct kofpix_build_opt *opt)
{
	struct kofpix_hdr *hdr = calloc(1, sizeof *hdr);
	struct wbuf w = { NULL, 0, 0 };
	uint32_t *idx = malloc((size_t)(n ? n : 1u) * sizeof *idx), *freq = NULL;
	uint16_t *koff = malloc((size_t)(n ? n : 1u) * sizeof *koff);
	uint32_t b, i, pool_end = 0, freq_bits = FREQ_BITS_MIN;
	struct kofpix_build_stat ls = { 0, 0, 0, 0 };

	if (!hdr || !idx || !koff)
		goto fail;
	{
		/* grams to count: the markers' bytes, an upper bound of what pick_koff will add */
		uint64_t grams = 0;

		for (i = 0; i < n; i++)
			grams += mk[i].len;
		freq_bits = FREQ_BITS_MIN;
		while (freq_bits < FREQ_BITS_MAX && ((uint64_t)1 << freq_bits) < grams * 2u)
			freq_bits++;
	}
	freq = malloc(((size_t)1 << freq_bits) * sizeof *freq);
	if (!freq)
		goto fail;
	hdr->magic = KOFPIX_MAGIC; hdr->version = 1; hdr->rec_size = KOFPIX_REC_SIZE;
	for (i = 0; i < n; i++)
		if ((uint64_t)mk[i].off + mk[i].len > pool_end)
			pool_end = mk[i].off + mk[i].len;
	hdr->pool_len = pool_end;
	for (i = 0; i < n; i++)
		if (mk[i].regs && !kof_multimatch_keyable(mk[i].kind, mk[i].len, mk[i].bytes))
			ls.n_skipped++;
	if (!wput(&w, NULL, sizeof *hdr) || !walign(&w))
		goto fail;

	for (b = 0; b < KOFPIX_MAX_REG; b++) {
		struct kofpix_regtab *rt = &hdr->reg[b];
		uint32_t m = 0, fold = 0, dbits, fb, lvl, j;
		struct kofpix_rec *a, *t, *sorted;
		uint32_t *dir;
		uint8_t *filt, *prev;
		uint64_t run = 1, rmax = 1;

		for (i = 0; i < n; i++)
			if ((mk[i].regs >> b) & 1u) {
				if (!kof_multimatch_keyable(mk[i].kind, mk[i].len, mk[i].bytes))
					continue;
				idx[m++] = i;
				if (mk[i].flags & KOF_STR_ICASE)
					fold = 1;
			}
		if (!m)
			continue;
		pick_koff(mk, idx, m, fold, koff, freq, freq_bits, opt);
		a = malloc((size_t)m * sizeof *a);
		t = malloc((size_t)m * sizeof *t);
		if (!a || !t) {
			free(a); free(t);
			goto fail;
		}
		for (j = 0; j < m; j++) {
			const struct kofpix_marker *q = &mk[idx[j]];
			struct kofpix_rec *r = &a[j];
			const uint8_t *key = q->bytes;
			uint32_t klen = q->len, nv, ko = koff[j];

			if (q->kind == KOF_STR_HEX)
				key = kof_multimatch_hex_anchor(q->bytes, &klen);
			memset(r, 0, sizeof *r);
			r->g = (ld4(key + ko, fold) * KOF_MM_MUL);
			r->c = after_key(key, klen, ko, fold, &nv);
			r->uid = q->uid; r->off = q->off; r->len = q->len;
			r->klen = (uint16_t)klen; r->koff = (uint16_t)ko; r->flags = q->flags;
			r->nvh = (uint8_t)(nv | (q->kind == KOF_STR_HEX ? KOFPIX_HEX : 0u));
		}
		sorted = radix_g(a, t, m);
		if (!sorted) {
			free(a); free(t);
			goto fail;
		}
		/* the radix leaves the data in `t` after three swaps */
		rt->bit = b; rt->fold = fold; rt->n_ent = m;
		dbits = clog2((uint64_t)m / 16u + 1u);
		if (dbits < 4u) dbits = 4u;
		if (dbits > KOFPIX_DIR_BITS_MAX) dbits = KOFPIX_DIR_BITS_MAX;
		rt->dbits = dbits;
		fb = clog2((uint64_t)m * 16u);
		if (fb < KOFPIX_FILTER_MIN_BITS) fb = KOFPIX_FILTER_MIN_BITS;
		if (fb > 28u) fb = 28u;
		rt->fb = fb;
		rt->n_lvl = fb - KOFPIX_FILTER_MIN_BITS + 1u;

		dir = calloc(((size_t)1 << dbits) + 1u, sizeof *dir);
		filt = calloc(1, (size_t)1 << (fb - 3u));
		if (!dir || !filt) {
			free(dir); free(filt); free(a); free(t);
			goto fail;
		}
		for (j = 0; j < m; j++) {
			dir[(sorted[j].g >> (32u - dbits)) + 1u]++;
			filt[(sorted[j].g >> (32u - fb)) >> 3] |= (uint8_t)(1u << ((sorted[j].g >> (32u - fb)) & 7u));
			if (j && sorted[j].g == sorted[j - 1].g) {
				++run;
				if (run > ls.max_run) ls.max_run = run;
				if (run > rmax) rmax = run;
			} else {
				run = 1;
			}
		}
		for (j = 0; j < ((uint32_t)1 << dbits); j++)
			dir[j + 1u] += dir[j];

		/* the exact key set: the distinct hashes in order. 2 bytes a key and no false
		 * positive: the hash is a bijection of the four bytes, so "this hash is here" is
		 * "some marker of the region is keyed on exactly these bytes". Over 8192 keys it
		 * is a directory over the top sixteen bits and the low sixteen of each; below
		 * that the directory alone would outweigh the keys (256 KB for 200 markers), so it
		 * is the sorted hashes themselves. */
		{
			uint32_t *kd = NULL;
			uint16_t *kl = NULL;
			uint32_t *kf = NULL;
			uint32_t nk = 0;

			for (j = 0; j < m; j++)
				nk += !j || sorted[j].g != sorted[j - 1].g;
			rt->n_keys = nk;
			if (nk > KOFPIX_KEYS_SMALL) {
				kd = calloc(((size_t)1 << 16) + 1u, sizeof *kd);
				kl = malloc((size_t)nk * sizeof *kl);
			} else {
				kf = malloc((size_t)nk * sizeof *kf);
			}
			if ((nk > KOFPIX_KEYS_SMALL && (!kd || !kl)) || (nk <= KOFPIX_KEYS_SMALL && !kf)) { free(kd); free(kl); free(kf); free(dir); free(filt); free(a); free(t); goto fail; }
			nk = 0;
			for (j = 0; j < m; j++)
				if (!j || sorted[j].g != sorted[j - 1].g) {
					if (kd) { kd[(sorted[j].g >> 16) + 1u]++; kl[nk] = (uint16_t)(sorted[j].g & 0xffffu); }
					else kf[nk] = sorted[j].g;
					nk++;
				}
			if (kd)
				for (j = 0; j < (1u << 16); j++)
					kd[j + 1u] += kd[j];
			if (!walign(&w) || (rt->kdir_off = kd ? w.n : 0, kd && !wput(&w, kd, (((uint64_t)1 << 16) + 1u) * 4u)) || !walign(&w) ||
			    (rt->klow_off = w.n, !(kd ? wput(&w, kl, (uint64_t)nk * 2u) : wput(&w, kf, (uint64_t)nk * 4u)))) { free(kd); free(kl); free(kf); free(dir); free(filt); free(a); free(t); goto fail; }
			free(kd); free(kl); free(kf);
		}
		if (!walign(&w)) { free(dir); free(filt); free(a); free(t); goto fail; }
		rt->dir_off = w.n;
		if (!wput(&w, dir, (((uint64_t)1 << dbits) + 1u) * 4u) || !walign(&w)) { free(dir); free(filt); free(a); free(t); goto fail; }
		rt->flt_off = w.n;
		/* the levels: fb bits, fb-1, ... each an OR of two bits of the one above, so the loader can take the
		 * largest that fits what it was given and a coarser level is still exact (a bit set for every key) */
		prev = filt;
		if (!wput(&w, filt, (uint64_t)1 << (fb - 3u))) { free(dir); free(filt); free(a); free(t); goto fail; }
		for (lvl = 1; lvl < rt->n_lvl; lvl++) {
			uint32_t bits = fb - lvl;
			uint64_t nb = (uint64_t)1 << (bits - 3u), q;
			uint8_t *cur = calloc(1, (size_t)nb);

			if (!cur) { free(dir); free(filt); free(a); free(t); goto fail; }
			for (q = 0; q < ((uint64_t)1 << bits); q++) {
				uint32_t k, any = 0;

				for (k = 0; k < 2u; k++) {
					uint64_t s = q * 2u + k;

					any |= ((uint32_t)prev[s >> 3] >> (s & 7u)) & 1u;
				}
				if (any)
					cur[q >> 3] |= (uint8_t)(1u << (q & 7u));
			}
			if (!wput(&w, cur, nb)) { free(cur); free(dir); free(filt); free(a); free(t); goto fail; }
			if (prev != filt)
				free(prev);
			prev = cur;
		}
		if (prev != filt)
			free(prev);
		if (!walign(&w)) { free(dir); free(filt); free(a); free(t); goto fail; }
		rt->rec_off = w.n;
		if (!wput(&w, sorted, (uint64_t)m * sizeof *sorted) || !walign(&w)) { free(dir); free(filt); free(a); free(t); goto fail; }
		rt->max_run = rmax > 0xffffffffu ? 0xffffffffu : (uint32_t)rmax;
		ls.n_rec += m; ls.n_reg++;
		free(dir); free(filt); free(a); free(t);
	}
	hdr->n_reg = ls.n_reg;
	hdr->sec_len = w.n;
	memcpy(w.p, hdr, sizeof *hdr);
	free(hdr); free(idx); free(koff); free(freq);
	{
		/* what the builder grew into is not what the table is: a table held in memory (a pack that has
		 * none in its tail) is exactly its own size, not the doubling's */
		uint8_t *fit = realloc(w.p, (size_t)w.n);

		if (fit)
			w.p = fit;
	}
	*len = w.n;
	if (st)
		*st = ls;
	return w.p;
fail:
	free(hdr); free(idx); free(koff); free(freq); free(w.p);
	return NULL;
}

uint8_t *kofpix_build_pack(const struct kofpix_pack_view *v, uint64_t *len,
			   struct kofpix_build_stat *st)
{
	struct kofpix_marker *mk = NULL;
	uint32_t *regs = NULL, *first = NULL;
	uint32_t n_uid = 0, i, k, n = 0;
	uint8_t *sec = NULL;
	const uint32_t bits = (1u << KOFPIX_MAX_REG) - 1u;

	*len = 0;
	/* A pattern id is dense, so it is below the number of strings. One that is not (a pack the loader
	 * would not refuse, built by something else) is not keyed - left to the per-marker path - and it
	 * does not size anything: n_uid is at most n_str, whatever a file says. */
	for (i = 0; i < v->n_str; i++)
		if (v->str[i].uid < v->n_str && v->str[i].uid + 1u > n_uid)
			n_uid = v->str[i].uid + 1u;
	regs = calloc(n_uid ? n_uid : 1u, sizeof *regs);
	first = calloc(n_uid ? n_uid : 1u, sizeof *first);       /* 1 + the first string with the uid */
	mk = calloc(n_uid ? n_uid : 1u, sizeof *mk);
	if (!regs || !first || !mk)
		goto nomem;
	for (i = 0; i < v->n_mod; i++) {
		const struct kof_pack_mod *m = &v->mod[i];
		uint32_t mbits = 0;

		/* The pack was checked when it was mapped; the slices are bounded again because this is
		 * also what the packer calls with arrays it has only just built. */
		if (m->rng_first > v->n_rng || m->n_rng > v->n_rng - m->rng_first ||
		    m->str_first > v->n_str || m->n_str > v->n_str - m->str_first)
			continue;
		for (k = 0; k < m->n_rng; k++)
			mbits |= v->rng[m->rng_first + k] & bits;
		for (k = 0; k < m->n_str; k++) {
			uint32_t si = m->str_first + k, uid = v->str[si].uid;

			if (uid >= n_uid)
				continue;
			regs[uid] |= mbits;
			if (!first[uid])
				first[uid] = si + 1u;
		}
	}
	for (i = 0; i < n_uid; i++) {
		const struct kof_pack_str *s;
		const uint8_t *bytes;

		if (!first[i] || !regs[i])
			continue;
		s = &v->str[first[i] - 1u];
		if (s->off > v->pool_len || s->len > v->pool_len - s->off)
			continue;
		bytes = v->pool + s->off;
		/* The key is read out of a program's header, so the program is checked first: a build
		 * from a pack the loader refuses must not walk what it cannot trust. */
		if (s->kind == KOF_STR_HEX &&
		    ((s->off % KOF_HEX_PROG_ALIGN) || !kof_hex_prog_valid(bytes, s->len)))
			continue;
		mk[n].bytes = bytes;
		mk[n].uid = i;
		mk[n].off = s->off;
		mk[n].regs = regs[i];
		mk[n].len = s->len;
		mk[n].kind = (uint8_t)s->kind;
		mk[n].flags = s->flags;
		n++;
	}
	if (n)
		sec = kofpix_build(mk, n, len, st, NULL);
	if (n && !sec)
		goto nomem;
	if (sec && st && !st->n_rec) {
		free(sec);
		sec = NULL;
		*len = 0;
	}
	free(mk); free(regs); free(first);
	return sec;
nomem:
	free(mk); free(regs); free(first);
	*len = ~(uint64_t)0;
	return NULL;
}

