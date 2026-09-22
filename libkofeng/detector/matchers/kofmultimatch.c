/*
 * kofmultimatch.c - one pass per region, every marker of it answered.
 *
 * See kofmultimatch.h for what this is for and which numbers the thresholds came
 * from. This file is the arithmetic.
 */

#include "kofmultimatch.h"
#include "hexprog.h"
#include "../../databases/dbloader.h"

#include <stdlib.h>
#include <string.h>

/* ---- keys ----------------------------------------------------------------- */

/*
 * Case folding, four bytes at a time and without a branch.
 *
 * Folding with a per-byte test in the sweep's inner loop measured three times
 * slower - 410 MB/s against 1.17 GB/s - on both text and binary, so the cost
 * was the branch and not the content. Per byte b, adding 0x7f-'A'+1 sets bit 7
 * when b >= 'A' and adding 0x7f-'Z' sets it when b > 'Z'; the difference is
 * exactly [A-Z], and 0x80 >> 2 is the 0x20 that lowercases it. Requiring the
 * original high bit clear leaves everything above ASCII alone.
 */
static uint32_t swar_lower(uint32_t v)
{
	uint32_t c  = v & 0x7f7f7f7fu;
	uint32_t ge = c + 0x3f3f3f3fu;
	uint32_t gt = c + 0x25252525u;

	return v | ((ge & ~gt & ~v & 0x80808080u) >> 2);
}

static uint32_t load32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/*
 * Read as bytes and shifted rather than memcpy'd into a word, because this has
 * to be right on a big-endian target and on one that faults an unaligned load.
 * The compiler folds it back to a single load wherever that is legal, which is
 * every target this actually ships on.
 */
static uint32_t key_gram(const uint8_t *p, uint32_t bits, int fold)
{
	uint32_t v = load32(p);

	if (fold)
		v = swar_lower(v);
	return (v * 2654435761u) >> (32 - bits);
}

static uint32_t key_block(const uint8_t *p, uint32_t bits, int fold)
{
	uint32_t v = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);

	if (fold)
		v = swar_lower(v) & 0x00ffffffu;
	return (v * 2654435761u) >> (32 - bits);
}

static uint8_t fold_byte(uint8_t c)
{
	return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c;
}

/* ---- verification --------------------------------------------------------- */

/*
 * The word rule as match_one applies it, and it has to be the same rule or the
 * two paths would disagree about one marker.
 *
 * The right boundary is the EXTENT's edge, then the object's: a match ending
 * where the region ends has no following byte, and neither has one ending at
 * the end of the object.
 */
static int pat_at(const struct kof_match_ctx *m, const struct kof_multimatch_pat *p,
		  uint64_t at, uint64_t base, uint64_t span)
{
	uint64_t end = at + p->len;
	uint16_t i;

	if (at < base || end > base + span || end > m->data.n)
		return 0;

	if (p->is_hex) {
		/*
		 * `at` is where the ANCHOR RUN sits, not where a match starts.
		 *
		 * The run has to be there first - the table only promised its
		 * first four bytes - and then the match may begin anywhere in
		 * the window ahead of it. This is hex_search's second and third
		 * steps unchanged, reached through the same walk so the two
		 * paths cannot come to different conclusions about a gap.
		 *
		 * `lim` ENDS AT THE EXTENT, not at the object: a hex match is
		 * not allowed to begin inside the region it was scoped to and
		 * run out the far side of it.
		 */
		kof_buf lim;
		uint64_t d;

		if (memcmp(m->data.p + at, p->b, p->len) != 0)
			return 0;
		lim.p = m->data.p;
		lim.n = base + span;
		if (lim.n > m->data.n)
			lim.n = m->data.n;
		for (d = p->before_min; d <= p->before_max; d++) {
			uint64_t start;

			if (at < d)
				break;
			start = at - d;
			if (start < base)
				break;
			/* Too little left for even the shortest match: the walk
			 * is not entered rather than entered and refused. */
			if (lim.n - start < p->min_span)
				continue;
			if (kof_hex_walk(lim, start, p->prog))
				return 1;
		}
		return 0;
	}

	if (p->flags & KOF_STR_ICASE) {
		for (i = 0; i < p->len; i++)
			if (fold_byte(m->data.p[at + i]) != fold_byte(p->b[i]))
				return 0;
	} else if (memcmp(m->data.p + at, p->b, p->len) != 0) {
		return 0;
	}
	if (!(p->flags & KOF_STR_BOUNDED))
		return 1;

	/*
	 * A WIDE MATCH IS BOUNDED BY CHARACTERS, NOT BY BYTES.
	 *
	 * The pattern is the marker with zero high halves interleaved and it
	 * ENDS with one, so the byte at `end` is the low half of the next
	 * character - the right byte to test, and the trailing side needs no
	 * change.
	 *
	 * The leading side does. The byte at `at - 1` is the zero high half of
	 * the character before, which is never a word byte, so that test passed
	 * on every match and the option meant nothing. The character before
	 * lives at [at - 2, at - 1]: it is a word character when its low half
	 * is a word byte AND its high half is zero. A non-zero high half means
	 * the bytes there are not UTF-16 text at all, so nothing is being
	 * abutted and the boundary holds.
	 */
	if (p->flags & KOF_STR_WIDE) {
		if (at >= base + 2u && m->data.p[at - 1] == 0 &&
		    kof_str_abuts(m->data.p[at - 2], p->flags))
			return 0;
	} else if (at > base && kof_str_abuts(m->data.p[at - 1], p->flags)) {
		return 0;
	}
	if (end < base + span && end < m->data.n &&
	    kof_str_abuts(m->data.p[end], p->flags)) {
		/* Wide: only when a whole character follows. A word byte with a
		 * non-zero byte above it is not a UTF-16 character. */
		if (!(p->flags & KOF_STR_WIDE) ||
		    (end + 1u < m->data.n && m->data.p[end + 1u] == 0))
			return 0;
	}
	return 1;
}

/* ---- building ------------------------------------------------------------- */

static uint32_t bits_for(uint32_t n, uint32_t per)
{
	uint32_t b = KOF_MULTIMATCH_BITS_MIN;

	while (b < KOF_MULTIMATCH_BITS_MAX && ((uint64_t)1u << b) < (uint64_t)n * per)
		b++;
	return b;
}

/*
 * The concrete run a hex program is keyed on, and how long it is.
 *
 * Read without re-validating, the same way hex_search and gram_admits read it:
 * hex_prog_valid checked every one of these offsets when the pack was loaded,
 * and checked the anchor LAST so it could not be believed before the tables it
 * indexes were known good. A second copy of that check here would be a second
 * thing to keep in step with the format.
 */
static const uint8_t *hex_anchor(const uint8_t *prog, uint32_t *len)
{
	const struct kof_hex_hdr *h = (const void *)prog;
	const struct kof_hex_step *steps = (const void *)(prog + h->steps_off);
	const struct kof_hex_alt *alts = (const void *)(prog + h->alts_off);
	const struct kof_hex_alt *aa = &alts[steps[h->anchor_step].alt_first];

	*len = h->anchor_len;
	return prog + aa->data_off + h->anchor_in_alt;
}

/*
 * Can this marker be keyed at all?
 *
 * A literal is keyed on its own first bytes; a hex program on its anchor run,
 * which is the only part of it that is concrete. Either way the key needs
 * KOF_MULTIMATCH_KEY bytes to exist, and a marker that cannot supply them is
 * left to the lazy path by simply not being in the table - which leaves its
 * memo cell unknown, which is what it is.
 */
static int keyable(const struct kof_str_ent *e, const uint8_t *bytes)
{
	if (e->kind == KOF_STR_HEX) {
		uint32_t alen;

		if (e->len < sizeof(struct kof_hex_hdr))
			return 0;
		(void)hex_anchor(bytes, &alen);
		/* Not KOF_MULTIMATCH_KEY: an anchor that long is a key with no
		 * verify behind it. See KOF_MULTIMATCH_HEX_MIN. */
		return alen >= KOF_MULTIMATCH_HEX_MIN;
	}
	return e->len >= KOF_MULTIMATCH_KEY;
}

/*
 * Every keyable marker in the database, once.
 *
 * Deduplicated by the id the build gave identical bytes, because a marker two
 * families both declare is one marker and has to have ONE slot in the caller's
 * per-object record - otherwise "found in CODE" and "found in DATA" would land
 * in different halves of an answer that is meant to be OR'd.
 */
static int collect_all(const struct kof_engine *e, uint8_t *seen,
		       size_t seen_bytes, struct kof_multimatch_set *set)
{
	const struct kof_module *arrays[3];
	uint32_t counts[3], a, i, s2, n = 0, pass;

	arrays[0] = e->mods; counts[0] = e->n_mods;
	arrays[1] = e->unp;  counts[1] = e->n_unp;
	arrays[2] = e->heur; counts[2] = e->n_heur;

	for (pass = 0; pass < 2; pass++) {
		memset(seen, 0, seen_bytes);
		n = 0;
		for (a = 0; a < 3; a++) {
			for (i = 0; i < counts[a]; i++) {
				const struct kof_module *m = &arrays[a][i];

				for (s2 = 0; s2 < m->n_str; s2++) {
					const uint8_t *bytes;
					const struct kof_str_ent *ent =
						kof_db_str(e, m, s2, &bytes);
					uint32_t uid;

					if (!ent || !bytes || !keyable(ent, bytes))
						continue;
					uid = e->packs[m->pack_id].uid_base + ent->uid;
					if (uid >= e->n_uid)
						continue;
					if (seen[uid >> 3] & (1u << (uid & 7)))
						continue;
					seen[uid >> 3] |= (uint8_t)(1u << (uid & 7));
					if (pass) {
						struct kof_multimatch_pat *q =
							&set->pat[n];

						q->uid = uid;
						if (ent->kind == KOF_STR_HEX) {
							const struct kof_hex_hdr *h =
								(const void *)bytes;
							uint32_t alen;

							q->b = hex_anchor(bytes, &alen);
							q->len = (uint16_t)alen;
							/* Case and word are a
							 * literal's options; a walk
							 * has no meaning for them,
							 * so they are cleared
							 * rather than carried. */
							q->flags = 0;
							q->is_hex = 1;
							q->prog = bytes;
							q->before_min = h->anchor_before_min;
							q->before_max = h->anchor_before_max;
							q->min_span = h->min_span;
						} else {
							q->b = bytes;
							q->len = ent->len;
							q->flags = ent->flags;
							q->is_hex = 0;
							q->prog = NULL;
						}
					}
					n++;
				}
			}
		}
		if (!pass) {
			if (!n)
				return 1;
			set->pat = calloc(n, sizeof *set->pat);
			if (!set->pat)
				return 0;
			set->bytes += (size_t)n * sizeof *set->pat;
		}
	}
	set->n_pat = n;
	return 1;
}

/*
 * Which markers can reach one REGION.
 *
 * Every marker of every module that names a mask carrying this region's bit.
 * The pairing of marker to range is decided by the module's code at run time -
 * kof_find_str takes both ids as arguments and ksigbuilder derives scan_mask
 * from the RANGE DECLARATIONS, not from the calls - so this is what the build
 * can know, and it is a SUPERSET.
 *
 * Every consequence of that is one-directional: n_pat too high only makes the
 * table larger and writes a cell nobody reads, and min_len too low only
 * shortens Wu-Manber's skip or picks the gram table instead. Both routines
 * answer the same question, so a superset costs speed and can never cost an
 * answer. Measured on the shipping base it changes no routine at all.
 */
static int collect_region(const struct kof_engine *e, uint32_t bit,
			  const uint32_t *uid_slot, struct kof_multimatch_set *set,
			  uint8_t *seen, size_t seen_bytes)
{
	struct kof_multimatch *t = &set->tab[bit];
	const struct kof_module *arrays[3];
	uint32_t counts[3], a, i, r, s2, n = 0, pass;
	uint32_t want = 1u << bit;

	arrays[0] = e->mods; counts[0] = e->n_mods;
	arrays[1] = e->unp;  counts[1] = e->n_unp;
	arrays[2] = e->heur; counts[2] = e->n_heur;
	t->mask = want;

	for (pass = 0; pass < 2; pass++) {
		memset(seen, 0, seen_bytes);
		n = 0;
		for (a = 0; a < 3; a++) {
			for (i = 0; i < counts[a]; i++) {
				const struct kof_module *m = &arrays[a][i];
				int names = 0;

				for (r = 0; r < m->n_rng; r++) {
					if (m->rng_base + r >= e->n_rng)
						break;
					if (e->rng_tab[m->rng_base + r] & want) {
						names = 1;
						break;
					}
				}
				if (!names)
					continue;
				for (s2 = 0; s2 < m->n_str; s2++) {
					const uint8_t *bytes;
					const struct kof_str_ent *ent =
						kof_db_str(e, m, s2, &bytes);
					uint32_t uid, slot;

					if (!ent || !bytes || !keyable(ent, bytes))
						continue;
					uid = e->packs[m->pack_id].uid_base + ent->uid;
					if (uid >= e->n_uid)
						continue;
					if (seen[uid >> 3] & (1u << (uid & 7)))
						continue;
					seen[uid >> 3] |= (uint8_t)(1u << (uid & 7));
					slot = uid_slot[uid];
					if (slot == 0xffffffffu)
						continue;
					if (pass && t->idx)
						t->idx[n] = slot;
					n++;
				}
			}
		}
		if (!pass) {
			if (!n)
				return 1;
			t->idx = calloc(n, sizeof *t->idx);
			if (!t->idx)
				return 0;
			t->bytes += (size_t)n * sizeof *t->idx;
		}
	}

	t->n_pat = n;
	t->min_len = 0xffffu;
	for (i = 0; i < n; i++) {
		const struct kof_multimatch_pat *q = &set->pat[t->idx[i]];

		if (q->len < t->min_len)
			t->min_len = q->len;
		if (q->flags & KOF_STR_ICASE)
			t->fold = 1;
	}
	if (t->min_len == 0xffffu)
		t->min_len = 0;
	return 1;
}


/* ---- BISECT: the same buckets, searched instead of walked ---------------- */

/*
 * qsort has no context argument, so the two things the comparison needs are
 * file scope. THE BUILD IS SINGLE THREADED - kof_multimatch_build runs once,
 * from kof_db_load, before any scanner exists - which is the only reason this
 * is allowed to be written this way. A second builder on another thread would
 * have to carry its own.
 */
static const struct kof_multimatch_pat *g_ord_pat;
static const struct kof_multimatch     *g_ord_tab;

/* Folded when any marker in the table folds, so the search can use the same
 * order. pat_at still applies each marker's own flags, so a case-exact marker
 * that this order puts beside a folded one is found and then refused. */
static int ord_cmp(const void *A, const void *B)
{
	uint32_t x = *(const uint32_t *)A, y = *(const uint32_t *)B;
	const struct kof_multimatch_pat *p = &g_ord_pat[g_ord_tab->idx[x]];
	const struct kof_multimatch_pat *q = &g_ord_pat[g_ord_tab->idx[y]];
	uint16_t n = p->len < q->len ? p->len : q->len, i;
	const int fold = g_ord_tab->fold;

	for (i = 0; i < n; i++) {
		uint8_t a = fold ? fold_byte(p->b[i]) : p->b[i];
		uint8_t b = fold ? fold_byte(q->b[i]) : q->b[i];

		if (a != b)
			return a < b ? -1 : 1;
	}
	return (int)p->len - (int)q->len;
}

/* Is `a` a proper prefix of `b`, in the same folded order as ord_cmp. */
static int is_prefix_of(const struct kof_multimatch_pat *a,
			const struct kof_multimatch_pat *b, int fold)
{
	uint16_t i;

	if (a->len >= b->len)
		return 0;
	for (i = 0; i < a->len; i++) {
		uint8_t x = fold ? fold_byte(a->b[i]) : a->b[i];
		uint8_t y = fold ? fold_byte(b->b[i]) : b->b[i];

		if (x != y)
			return 0;
	}
	return 1;
}

static int build_bisect(struct kof_multimatch *t,
			const struct kof_multimatch_pat *pat)
{
	uint32_t i, *fill = NULL, *stk = NULL;

	t->bits = bits_for(t->n_pat, 8);
	t->nb = 1u << t->bits;
	t->max_chain = 0;
	t->seen  = calloc(t->nb / 8u, 1);
	t->start = calloc((size_t)t->nb + 1u, sizeof *t->start);
	t->ord   = calloc(t->n_pat, sizeof *t->ord);
	t->pfx   = malloc((size_t)t->n_pat * sizeof *t->pfx);
	fill     = calloc(t->nb, sizeof *fill);
	stk      = malloc((size_t)t->n_pat * sizeof *stk);
	if (!t->seen || !t->start || !t->ord || !t->pfx || !fill || !stk)
		goto fail;
	t->bytes += t->nb / 8u + ((size_t)t->nb + 1u) * sizeof *t->start +
		    (size_t)t->n_pat * (sizeof *t->ord + sizeof *t->pfx);

	/* Counting sort into buckets: count, run the counts into offsets, place. */
	for (i = 0; i < t->n_pat; i++) {
		uint32_t b = key_gram(pat[t->idx[i]].b, t->bits, t->fold);

		t->start[b + 1u]++;
	}
	for (i = 0; i < t->nb; i++) {
		if (t->start[i + 1u] > t->max_chain)
			t->max_chain = t->start[i + 1u];
		t->start[i + 1u] += t->start[i];
	}
	for (i = 0; i < t->n_pat; i++) {
		uint32_t b = key_gram(pat[t->idx[i]].b, t->bits, t->fold);

		t->ord[t->start[b] + fill[b]++] = i;
		t->seen[b >> 3] |= (uint8_t)(1u << (b & 7));
	}
	free(fill);
	fill = NULL;

	for (i = 0; i < t->nb; i++) {
		uint32_t a = t->start[i], n = t->start[i + 1u] - a, j, sp = 0;

		if (n > 1u) {
			g_ord_pat = pat;
			g_ord_tab = t;
			qsort(t->ord + a, n, sizeof *t->ord, ord_cmp);
		}
		/*
		 * THE LONGEST PROPER PREFIX BELOW EACH ENTRY, by a stack over
		 * the sorted run.
		 *
		 * The adjacent entry is NOT the answer and taking it was wrong:
		 * sorted order puts "ab" "abb" "abc", so "ab" is a prefix of
		 * "abc" with a non-prefix between them. Measured against brute
		 * force it found 23 markers where 45 are present. Anything
		 * still on the stack is a prefix of what comes next, because
		 * sorted order visits a string's extensions right after it.
		 */
		for (j = 0; j < n; j++) {
			const struct kof_multimatch_pat *cur =
				&pat[t->idx[t->ord[a + j]]];

			while (sp && !is_prefix_of(&pat[t->idx[t->ord[a + stk[sp - 1u]]]],
						   cur, t->fold))
				sp--;
			t->pfx[a + j] = sp ? (int32_t)(a + stk[sp - 1u]) : -1;
			stk[sp++] = j;
		}
	}
	free(stk);
	return 1;
fail:
	free(fill);
	free(stk);
	return 0;
}

static void sweep_bisect(const struct kof_multimatch *t,
			 const struct kof_multimatch_pat *pat,
			 struct kof_match_ctx *m, uint64_t base, uint64_t span,
			 uint32_t bitmask, uint32_t *found)
{
	uint64_t i, end = base + span;
	const int fold = t->fold;

	if (span < KOF_MULTIMATCH_KEY)
		return;
	for (i = base; i + KOF_MULTIMATCH_KEY <= end; i++) {
		uint32_t b = key_gram(m->data.p + i, t->bits, fold);
		uint32_t a, n, lo, hi;
		int32_t j;

		if (!((t->seen[b >> 3] >> (b & 7)) & 1))
			continue;
		a = t->start[b];
		n = t->start[b + 1u] - a;

		/*
		 * The last entry that is not GREATER than the haystack here.
		 *
		 * A marker longer than what is left compares GREATER, which
		 * keeps the order the sort used total: running out of haystack
		 * is the haystack being the shorter string. Without that the
		 * search can land on the wrong side near the end of an extent
		 * and miss the marker below it.
		 */
		lo = 0; hi = n;
		while (lo < hi) {
			uint32_t mid = lo + (hi - lo) / 2u;
			const struct kof_multimatch_pat *p =
				&pat[t->idx[t->ord[a + mid]]];
			uint64_t avail = end - i;
			uint16_t k;
			int c = 0;

			for (k = 0; k < p->len; k++) {
				uint8_t x, y;

				if (k >= avail) { c = 1; break; }
				x = fold ? fold_byte(p->b[k]) : p->b[k];
				y = fold ? fold_byte(m->data.p[i + k])
					 : m->data.p[i + k];
				if (x != y) { c = x < y ? -1 : 1; break; }
			}
			if (c <= 0) lo = mid + 1u; else hi = mid;
		}
		if (!lo)
			continue;
		/* That entry, then every shorter marker that is a prefix of it -
		 * those are the other markers present at this position. */
		for (j = (int32_t)(a + lo - 1u); j >= 0; j = t->pfx[j]) {
			uint32_t slot = t->idx[t->ord[j]];

			if ((found[slot] & bitmask) == 0 &&
			    pat_at(m, &pat[slot], i, base, span))
				found[slot] |= bitmask;
		}
	}
}

/*
 * Where to take each marker's key: the four bytes that the fewest OTHER markers
 * in this table share.
 *
 * Two passes and a 64K counter table. The counts do not have to be exact - a
 * hash into 64K conflates some - because they are never read as a number, only
 * compared to pick the smaller. A slightly wrong choice costs a longer chain,
 * not a wrong answer.
 *
 * Hex markers are left at zero: their `b` is the anchor run the compiler
 * already chose, and pat_at reads `at` as the anchor's position.
 */
#define KOFF_FREQ_BITS 16u

static void pick_key_off(const struct kof_multimatch *t,
			 const struct kof_multimatch_pat *pat, uint16_t *out)
{
	uint32_t *freq = calloc(1u << KOFF_FREQ_BITS, sizeof *freq);
	uint32_t i, j;

	if (!freq)
		return;                 /* every offset stays 0 - the plain key */
	for (i = 0; i < t->n_pat; i++) {
		const struct kof_multimatch_pat *q = &pat[t->idx[i]];

		if (q->is_hex)
			continue;
		for (j = 0; j + KOF_MULTIMATCH_KEY <= q->len; j++)
			freq[key_gram(q->b + j, KOFF_FREQ_BITS, t->fold)]++;
	}
	for (i = 0; i < t->n_pat; i++) {
		const struct kof_multimatch_pat *q = &pat[t->idx[i]];
		uint32_t best = 0, bf = 0xffffffffu;

		if (q->is_hex)
			continue;
		for (j = 0; j + KOF_MULTIMATCH_KEY <= q->len; j++) {
			uint32_t f = freq[key_gram(q->b + j, KOFF_FREQ_BITS,
						   t->fold)];

			if (f < bf) { bf = f; best = j; }
		}
		out[i] = (uint16_t)best;
	}
	free(freq);
}

/*
 * Fill the bucket chains. mkoff NULL keys every marker on its first four bytes;
 * otherwise marker i is keyed mkoff[i] bytes in.
 */
static int fill_gram(struct kof_multimatch *t,
		     const struct kof_multimatch_pat *pat,
		     const uint16_t *mkoff)
{
	uint32_t i, chain = 1;

	t->bits = bits_for(t->n_pat, 8);
	t->nb = 1u << t->bits;
	t->max_chain = 0;
	t->seen = calloc(t->nb / 8u, 1);
	t->head = calloc(t->nb, sizeof *t->head);
	t->ids  = calloc((size_t)t->n_pat + 1, sizeof *t->ids);
	t->next = calloc((size_t)t->n_pat + 1, sizeof *t->next);
	t->tag  = calloc((size_t)t->n_pat + 1, sizeof *t->tag);
	if (mkoff) {
		t->koff = calloc((size_t)t->n_pat + 1, sizeof *t->koff);
		if (!t->koff)
			return 0;
		t->bytes += ((size_t)t->n_pat + 1) * sizeof *t->koff;
	}
	if (!t->seen || !t->head || !t->ids || !t->next || !t->tag)
		return 0;
	t->bytes += t->nb / 8u + (size_t)t->nb * sizeof *t->head +
		    ((size_t)t->n_pat + 1) * 2 * sizeof *t->ids +
		    ((size_t)t->n_pat + 1) * sizeof *t->tag;

	for (i = 0; i < t->n_pat; i++) {
		const struct kof_multimatch_pat *q = &pat[t->idx[i]];
		uint32_t o = mkoff ? mkoff[i] : 0u;
		uint32_t b = key_gram(q->b + o, t->bits, t->fold);
		uint32_t nx = o + KOF_MULTIMATCH_KEY;

		t->seen[b >> 3] |= (uint8_t)(1u << (b & 7));
		t->ids[chain] = i;
		t->next[chain] = t->head[b];
		/* The byte past the key, wherever the key now sits. */
		t->tag[chain] = q->len > nx
				? (t->fold ? fold_byte(q->b[nx]) : q->b[nx])
				: (uint16_t)KOF_MULTIMATCH_NOTAG;
		/* Chain-indexed, not marker-indexed: the walk has the chain
		 * index in hand and nothing else. */
		if (mkoff)
			t->koff[chain] = (uint16_t)o;
		t->head[b] = chain;
		chain++;
	}
	for (i = 0; i < t->nb; i++) {
		uint32_t c = 0, k;

		for (k = t->head[i]; k; k = t->next[k])
			c++;
		if (c > t->max_chain)
			t->max_chain = c;
	}
	return 1;
}

/*
 * Fill the plain table, and hand the region to BISECT when that came out
 * clustered.
 *
 * PREDICTING WHICH IS NEEDED IS THE POINT, and the prediction is made from the
 * table that was ACTUALLY BUILT rather than from a guess about the base: the
 * shape that decides it - the longest bucket - is not knowable from the marker
 * count or their lengths, only from hashing them. Building the cheap one first
 * costs milliseconds and tells the truth.
 */
/* Drop whatever the plain attempt allocated, so the next shape starts clean. */
static void gram_discard(struct kof_multimatch *t, size_t bytes_was)
{
	free(t->seen); free(t->head); free(t->ids);
	free(t->next); free(t->tag);  free(t->koff);
	t->seen = NULL; t->head = NULL; t->ids = NULL;
	t->next = NULL; t->tag = NULL; t->koff = NULL;
	t->bytes = bytes_was;
}

/*
 * Build the plain table, and move to a shape that survives when it clustered.
 *
 * THE PREDICTION IS MADE FROM THE TABLE THAT WAS ACTUALLY BUILT. The thing that
 * decides - the longest bucket - cannot be read off the marker count or their
 * lengths; only hashing them says. Building the cheap shape first costs
 * milliseconds and tells the truth, and it is also the shape that wins whenever
 * it is not clustered, so the common base pays nothing at all.
 *
 * Which replacement is chosen is the one measurement that IS a marker-count
 * question - see KOF_MULTIMATCH_REKEY_MIN_PAT.
 */
static int build_gram(struct kof_multimatch *t, const struct kof_multimatch_pat *pat)
{
	/* BEFORE the first attempt: what it allocates is about to be freed, so
	 * it is not part of what this table costs. Captured after, the stats
	 * reported a switched table at twice its size. */
	size_t bytes_was = t->bytes;

	if (!fill_gram(t, pat, NULL))
		return 0;
	if (t->max_chain <= KOF_MULTIMATCH_BISECT_CHAIN)
		return 1;                       /* the plain key was fine */

	if (t->n_pat >= KOF_MULTIMATCH_REKEY_MIN_PAT) {
		uint16_t *mkoff = calloc((size_t)t->n_pat + 1, sizeof *mkoff);
		uint32_t chain_was = t->max_chain;

		if (mkoff) {
			pick_key_off(t, pat, mkoff);
			gram_discard(t, bytes_was);
			if (!fill_gram(t, pat, mkoff)) {
				free(mkoff);
				return 0;
			}
			free(mkoff);
			/* A rekey that did not help is not worth its cost, and
			 * the sorted shape is the other answer. */
			if (t->max_chain < chain_was) {
				t->kind = KOF_MULTIMATCH_REKEY;
				return 1;
			}
		}
	}

	gram_discard(t, bytes_was);
	if (!build_bisect(t, pat))
		return 0;               /* the region falls back to per-marker */
	t->kind = KOF_MULTIMATCH_BISECT;
	return 1;
}

/*
 * Wu-Manber: for every block position inside the shortest marker, record how
 * far the next block may start. A block that ends some marker gets shift zero
 * and joins that marker's chain.
 *
 * Only the first min_len bytes of any marker are considered, because a shift
 * derived past that could step over a shorter marker's start.
 */
static int build_wm(struct kof_multimatch *t, const struct kof_multimatch_pat *pat)
{
	uint32_t i, chain = 1;
	uint16_t m = t->min_len, j;
	uint8_t  cap;

	if (m < KOF_MULTIMATCH_WM_BLOCK)
		return 0;
	t->bits = bits_for(t->n_pat, 16);
	t->nb = 1u << t->bits;
	t->shift = malloc(t->nb);
	t->head  = calloc(t->nb, sizeof *t->head);
	t->ids   = calloc((size_t)t->n_pat * m + 1u, sizeof *t->ids);
	t->next  = calloc((size_t)t->n_pat * m + 1u, sizeof *t->next);
	if (!t->shift || !t->head || !t->ids || !t->next)
		return 0;
	t->bytes += t->nb + (size_t)t->nb * sizeof *t->head +
		    ((size_t)t->n_pat * m + 1u) * 2 * sizeof *t->ids;

	cap = (uint8_t)((m - KOF_MULTIMATCH_WM_BLOCK + 1u) > 255u
			? 255u : (m - KOF_MULTIMATCH_WM_BLOCK + 1u));
	memset(t->shift, cap, t->nb);

	for (i = 0; i < t->n_pat; i++) {
		const struct kof_multimatch_pat *q = &pat[t->idx[i]];

		for (j = KOF_MULTIMATCH_WM_BLOCK - 1u; j < m; j++) {
			uint32_t b = key_block(q->b + j - (KOF_MULTIMATCH_WM_BLOCK - 1u),
					       t->bits, t->fold);
			uint32_t sh = (uint32_t)(m - 1u - j);

			if (sh < t->shift[b])
				t->shift[b] = (uint8_t)sh;
			if (sh == 0) {
				t->ids[chain] = i;
				t->next[chain] = t->head[b];
				t->head[b] = chain;
				chain++;
			}
		}
	}
	for (i = 0; i < t->nb; i++) {
		uint32_t c = 0, k;

		for (k = t->head[i]; k; k = t->next[k])
			c++;
		if (c > t->max_chain)
			t->max_chain = c;
	}
	return 1;
}

static void tab_free(struct kof_multimatch *t)
{
	uint32_t mask = t->mask;

	free(t->seen);
	free(t->head);
	free(t->ids);
	free(t->next);
	free(t->tag);
	free(t->koff);
	free(t->start);
	free(t->ord);
	free(t->pfx);
	free(t->shift);
	free(t->idx);
	memset(t, 0, sizeof *t);
	t->mask = mask;
}

/*
 * The static half of the decision: what the base says, before any object.
 *
 * K is not known here, so a region that would only be swept for a large K still
 * gets its table built. That is the right way round - the table is the
 * database's and is built once, while K changes per object and can only ever
 * turn a sweep OFF, never on for a region with no table.
 */
static enum kof_multimatch_kind kind_static(const struct kof_multimatch *t)
{
	if (!t->n_pat || t->min_len < KOF_MULTIMATCH_KEY)
		return KOF_MULTIMATCH_NONE;
	if (t->n_pat > KOF_MULTIMATCH_WM_MAX)
		return KOF_MULTIMATCH_HASH4;
	if (t->min_len >= KOF_MULTIMATCH_LONG_MIN)
		return KOF_MULTIMATCH_WUMANBER;
	return KOF_MULTIMATCH_HASH4;
}

struct kof_multimatch_set *kof_multimatch_build(const struct kof_engine *e)
{
	struct kof_multimatch_set *set;
	uint8_t *seen = NULL;
	uint32_t *uid_slot = NULL;
	size_t seen_bytes;
	uint32_t i, b;

	if (!e || !e->n_masks || !e->n_uid)
		return NULL;
	set = calloc(1, sizeof *set);
	if (!set)
		return NULL;
	seen_bytes = ((size_t)e->n_uid + 7u) / 8u;
	seen = malloc(seen_bytes);
	uid_slot = malloc((size_t)e->n_uid * sizeof *uid_slot);
	set->mask_bits = calloc(e->n_masks, sizeof *set->mask_bits);
	if (!seen || !uid_slot || !set->mask_bits)
		goto fail;
	set->n_masks = e->n_masks;
	set->bytes = sizeof *set + (size_t)e->n_masks * sizeof *set->mask_bits;

	if (!collect_all(e, seen, seen_bytes, set))
		goto fail;
	if (!set->n_pat) {
		free(seen);
		free(uid_slot);
		return set;          /* nothing keyable; every mask stays lazy */
	}

	/* uid -> slot in the shared array, so a region's list can be indices. */
	for (i = 0; i < e->n_uid; i++)
		uid_slot[i] = 0xffffffffu;
	for (i = 0; i < set->n_pat; i++)
		uid_slot[set->pat[i].uid] = i;

	/* The bits behind each dense mask id: rng_uid is parallel to rng_tab, so
	 * the first entry carrying an id is as good as any - they all carry the
	 * same bits, which is what made them one id. */
	for (i = 0; i < e->n_rng; i++)
		if (e->rng_uid[i] < set->n_masks)
			set->mask_bits[e->rng_uid[i]] = e->rng_tab[i];

	for (b = 0; b < KOF_MULTIMATCH_BITS; b++) {
		struct kof_multimatch *t = &set->tab[b];
		int ok;

		if (!collect_region(e, b, uid_slot, set, seen, seen_bytes)) {
			tab_free(t);
			continue;
		}
		t->kind = (uint8_t)kind_static(t);
		if (t->kind == KOF_MULTIMATCH_NONE) {
			set->bytes += t->bytes;
			continue;
		}
		ok = (t->kind == KOF_MULTIMATCH_WUMANBER)
		     ? build_wm(t, set->pat) : build_gram(t, set->pat);
		if (!ok && t->kind == KOF_MULTIMATCH_WUMANBER) {
			/* A shape Wu-Manber could not take is not a failure of
			 * the region, only of that routine. */
			free(t->shift); t->shift = NULL;
			free(t->head);  t->head  = NULL;
			free(t->ids);   t->ids   = NULL;
			free(t->next);  t->next  = NULL;
			t->nb = t->bits = t->max_chain = 0;
			t->kind = KOF_MULTIMATCH_HASH4;
			ok = build_gram(t, set->pat);
		}
		if (!ok) {
			uint32_t *keep = t->idx;
			uint32_t np = t->n_pat, mk = t->mask;

			t->idx = NULL;
			tab_free(t);
			t->idx = keep;
			t->n_pat = np;
			t->mask = mk;
			t->kind = KOF_MULTIMATCH_NONE;
			continue;
		}
		set->bytes += t->bytes;
	}
	free(seen);
	free(uid_slot);
	return set;
fail:
	free(seen);
	free(uid_slot);
	kof_multimatch_free(set);
	return NULL;
}

void kof_multimatch_free(struct kof_multimatch_set *set)
{
	uint32_t b;

	if (!set)
		return;
	for (b = 0; b < KOF_MULTIMATCH_BITS; b++)
		tab_free(&set->tab[b]);
	free(set->mask_bits);
	free(set->pat);
	free(set);
}

enum kof_multimatch_kind kof_multimatch_pick(const struct kof_multimatch *t,
					     uint32_t n_live)
{
	if (!t || t->kind == KOF_MULTIMATCH_NONE)
		return KOF_MULTIMATCH_NONE;
	/*
	 * Too few live markers to pay for a pass. This is the only place the
	 * object gets a say, and it can only say no: a region whose table was
	 * never built cannot be swept however many markers are live.
	 */
	if (n_live < KOF_MULTIMATCH_MIN_LIVE)
		return KOF_MULTIMATCH_NONE;
	return (enum kof_multimatch_kind)t->kind;
}

/* ---- sweeping ------------------------------------------------------------- */

static void sweep_gram(const struct kof_multimatch *t,
		       const struct kof_multimatch_pat *pat,
		       struct kof_match_ctx *m, uint64_t base, uint64_t span,
		       uint32_t bitmask, uint32_t *found)
{
	uint64_t i, end = base + span;
	const int fold = t->fold;
	uint16_t nb;

	if (span < KOF_MULTIMATCH_KEY)
		return;
	for (i = base; i + KOF_MULTIMATCH_KEY <= end; i++) {
		uint32_t b = key_gram(m->data.p + i, t->bits, fold);
		uint32_t k;

		if (!((t->seen[b >> 3] >> (b & 7)) & 1))
			continue;
		/* The byte past the key, once, for every entry on the chain.
		 * Only when it is inside the extent: at the very end there is
		 * no such byte and pat_at's bounds test is the right answer. */
		nb = (i + KOF_MULTIMATCH_KEY < end)
		     ? (fold ? fold_byte(m->data.p[i + KOF_MULTIMATCH_KEY])
			     : m->data.p[i + KOF_MULTIMATCH_KEY])
		     : (uint16_t)KOF_MULTIMATCH_NOTAG;
		for (k = t->head[b]; k; k = t->next[k]) {
			uint32_t slot = t->idx[t->ids[k]];

			if (t->tag[k] != KOF_MULTIMATCH_NOTAG &&
			    nb != KOF_MULTIMATCH_NOTAG && t->tag[k] != nb)
				continue;
			if ((found[slot] & bitmask) == 0 &&
			    pat_at(m, &pat[slot], i, base, span))
				found[slot] |= bitmask;
		}
	}
}

/*
 * The same walk as sweep_gram, for a table whose keys were moved.
 *
 * A COPY RATHER THAN A FLAG, because the difference is two instructions in the
 * innermost loop in the engine and a branch there is paid at every chain step
 * of every haystack position. The two must stay in step; what keeps them honest
 * is that both are checked against brute force in the harness.
 */
static void sweep_rekey(const struct kof_multimatch *t,
		       const struct kof_multimatch_pat *pat,
		       struct kof_match_ctx *m, uint64_t base, uint64_t span,
		       uint32_t bitmask, uint32_t *found)
{
	uint64_t i, end = base + span;
	const int fold = t->fold;
	uint16_t nb;

	if (span < KOF_MULTIMATCH_KEY)
		return;
	for (i = base; i + KOF_MULTIMATCH_KEY <= end; i++) {
		uint32_t b = key_gram(m->data.p + i, t->bits, fold);
		uint32_t k;

		if (!((t->seen[b >> 3] >> (b & 7)) & 1))
			continue;
		/* The byte past the key, once, for every entry on the chain.
		 * Only when it is inside the extent: at the very end there is
		 * no such byte and pat_at's bounds test is the right answer. */
		nb = (i + KOF_MULTIMATCH_KEY < end)
		     ? (fold ? fold_byte(m->data.p[i + KOF_MULTIMATCH_KEY])
			     : m->data.p[i + KOF_MULTIMATCH_KEY])
		     : (uint16_t)KOF_MULTIMATCH_NOTAG;
		for (k = t->head[b]; k; k = t->next[k]) {
			uint32_t slot = t->idx[t->ids[k]];

			if (t->tag[k] != KOF_MULTIMATCH_NOTAG &&
			    nb != KOF_MULTIMATCH_NOTAG && t->tag[k] != nb)
				continue;
			/* The hit is on the KEY; the marker begins koff bytes
			 * before it. */
			if (i < t->koff[k])
				continue;
			if ((found[slot] & bitmask) == 0 &&
			    pat_at(m, &pat[slot], i - t->koff[k], base, span))
				found[slot] |= bitmask;
		}
	}
}

static void sweep_wm(const struct kof_multimatch *t,
		     const struct kof_multimatch_pat *pat,
		     struct kof_match_ctx *m, uint64_t base, uint64_t span,
		     uint32_t bitmask, uint32_t *found)
{
	uint64_t end = base + span, i;
	const int fold = t->fold;
	uint16_t ml = t->min_len;

	if (span < ml)
		return;
	i = base + ml - 1u;
	while (i < end) {
		uint32_t b = key_block(m->data.p + i - (KOF_MULTIMATCH_WM_BLOCK - 1u),
				       t->bits, fold);
		uint8_t sh = t->shift[b];
		uint32_t k;

		if (sh) {
			i += sh;
			continue;
		}
		for (k = t->head[b]; k; k = t->next[k]) {
			uint32_t slot = t->idx[t->ids[k]];
			uint64_t at = i + 1u - ml;

			if ((found[slot] & bitmask) == 0 &&
			    pat_at(m, &pat[slot], at, base, span))
				found[slot] |= bitmask;
		}
		i++;
	}
}

uint64_t kof_multimatch_sweep(const struct kof_multimatch_set *set, uint32_t bit,
			      enum kof_multimatch_kind kind,
			      struct kof_match_ctx *m,
			      const struct kof_range *ext, uint32_t n_ext,
			      uint32_t *found)
{
	const struct kof_multimatch *t;
	uint64_t walked = 0;
	uint32_t i, bitmask;

	if (!set || bit >= KOF_MULTIMATCH_BITS || kind == KOF_MULTIMATCH_NONE)
		return 0;
	t = &set->tab[bit];
	if (!t->n_pat)
		return 0;
	bitmask = 1u << bit;

	for (i = 0; i < n_ext; i++) {
		uint64_t off = ext[i].off;
		uint64_t len = kof_clip_len(m->data.n, off, ext[i].len);

		if (!len)
			continue;
		walked += len;
		if (kind == KOF_MULTIMATCH_WUMANBER)
			sweep_wm(t, set->pat, m, off, len, bitmask, found);
		else if (kind == KOF_MULTIMATCH_BISECT)
			sweep_bisect(t, set->pat, m, off, len, bitmask, found);
		else if (kind == KOF_MULTIMATCH_REKEY)
			sweep_rekey(t, set->pat, m, off, len, bitmask, found);
		else
			sweep_gram(t, set->pat, m, off, len, bitmask, found);
	}
	return walked;
}

uint64_t kof_multimatch_fold(const struct kof_multimatch_set *set,
			     struct kof_match_ctx *m, uint32_t mask_uid,
			     uint32_t mask_bits, const uint32_t *found,
			     uint32_t n_masks)
{
	uint64_t cells = 0;
	uint32_t b;

	if (!set || !set->n_pat)
		return 0;
	/*
	 * Every marker that could reach any region this mask names, answered by
	 * ONE test on the word the sweeps filled.
	 *
	 * A marker reachable from two of the mask's regions is visited twice and
	 * written twice with the same value, which is why this does not need to
	 * deduplicate: the test is `found & mask_bits`, and that does not depend
	 * on which region's list led here.
	 *
	 * The ABSENT half is the whole point. A sweep that recorded only its
	 * hits would leave every miss to be searched one at a time, which is the
	 * cost this exists to remove; the caller has established that every
	 * region of this mask that the object HAS was swept, so a marker with no
	 * bit set is a marker that is not there.
	 */
	for (b = 0; b < KOF_MULTIMATCH_BITS; b++) {
		const struct kof_multimatch *t = &set->tab[b];
		uint32_t i;

		if (!(mask_bits & (1u << b)) || !t->n_pat || !t->idx)
			continue;
		for (i = 0; i < t->n_pat; i++) {
			uint32_t slot = t->idx[i];

			kof_match_memo_put(m,
					   set->pat[slot].uid * n_masks + mask_uid,
					   (found[slot] & mask_bits) != 0);
			cells++;
		}
	}
	return cells;
}
