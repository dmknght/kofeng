/*
 * kofmatch.c - literal search.
 *
 * It builds nothing: no automaton, no per-scan preparation. Building a shared
 * structure over every pattern in a database is what forces that structure to be
 * resident and to grow with the database, which is the cost this design avoids.
 * The same reasoning rules out a structure scoped to one module or one call, lazily
 * built and cached, too - not because it grows with the whole database at once, but
 * because a long, varied scan run eventually touches most modules that target a
 * common format anyway, and a cache that has been touched by "most of the database"
 * has paid the cost it was meant to avoid, just later. Every optimisation here
 * therefore has to hold within a single call: no state that outlives it, so nothing
 * it does can ever correlate with how large the database is.
 *
 * It trusts nothing in a compiled array either. Those arrive as bytes out of a
 * database, so every offset and length is bounds checked; a malformed set yields no
 * matches and never reads outside the array.
 */

/* Before any include, not after: memmem is a GNU/BSD extension and a feature test
 * macro placed after the first include has no effect at all - see kof_memmem in
 * kofplatform.h for what it is and why the Windows side of it does not need this. */
#define _GNU_SOURCE

#include "kofmatch.h"
#include "../kofdb/kofpack.h"   /* KOF_STR_* */
#include "../core/kofplatform.h"

#include <stdlib.h>
#include <string.h>

/* Defined with the presence set further down; declared here because starting on a new
 * object is the first thing in the file and restamping the table is part of it. */
/*
 * 24 bits of table, 16-bit generation stamps: 32MB, fixed whatever the database
 * holds. Measured on 400 binaries, 22 bits saturated on the files above 1MB and cost
 * 5x the wall time; 26 bits was slower again from TLB pressure.
 */
#define GRAM_BITS  24
#define GRAM_SLOTS (1u << GRAM_BITS)
#ifndef GRAM_MIN_PATTERNS
#define GRAM_MIN_PATTERNS 140
#endif

/*
 * The object size past which the presence table stops paying for itself.
 *
 * Occupancy after stamping an n byte object is about 1 - e^(-n/GRAM_SLOTS), so half
 * full is at GRAM_SLOTS * ln 2 - a shade under 11.7MB with a 24 bit table. Past that
 * the filter rejects less than it admits and still costs a pass over the object to
 * build, so it is skipped and every search runs.
 */
#define GRAM_MAX_BYTES ((uint64_t)GRAM_SLOTS * 693u / 1000u)

static struct kof_gram *gram_new(uint8_t bits);
static void             gram_free(struct kof_gram *);
static uint64_t         gram_build(struct kof_gram *, kof_buf);
static int              gram_may_contain(const struct kof_gram *, const uint8_t *,
					 uint16_t len, int icase);
static int              gram_ensure(struct kof_match_ctx *);

/*
 * Start on a new object.
 *
 * Keeps the state that is expensive to make and resets the state that is per object:
 * the presence table survives and is restamped, the memo is cleared, the counters go
 * back to zero.
 */
void kof_match_begin(struct kof_match_ctx *m, kof_buf data)
{
	struct kof_gram *gram = m->gram;
	uint16_t *memo = m->memo;
	uint32_t memo_len = m->memo_len;
	uint32_t patterns = m->gram_patterns;
	uint8_t  bits = m->gram_bits;
	uint32_t gmin = m->gram_min;
	uint16_t gen = m->memo_gen;

	memset(m, 0, sizeof *m);
	m->data = data;
	m->gram = gram;
	m->memo = memo;
	m->memo_len = memo_len;
	m->gram_patterns = patterns;
	m->gram_bits = bits;
	m->gram_min = gmin;

	/*
	 * A new generation instead of a new memo.
	 *
	 * The wrap is the only time anything is cleared, and after it every cell holds
	 * a generation that cannot recur, so the zeroing has to be real. Once every
	 * sixteen thousand objects.
	 */
	if (++gen > KOF_MEMO_GEN_MAX) {
		if (memo)
			memset(memo, 0, (size_t)memo_len * sizeof *memo);
		gen = 1;
	}
	m->memo_gen = gen;

	/*
	 * Is the presence table worth building for THIS object?
	 *
	 * It is stamped from the object's own bytes, so its occupancy is set by the
	 * object's size and not by the database's: an n byte object fills about
	 * 1 - e^(-n/SLOTS) of it. Past half full the filter admits more than it
	 * rejects while still costing a pass over every byte to build, which is the
	 * one shape where it is pure loss - so past that size it is not built and the
	 * searches run unfiltered.
	 *
	 * Conservative on real data: files repeat themselves, so the distinct grams in
	 * an object are fewer than its length and the true occupancy is below the
	 * estimate. The threshold errs towards keeping the filter.
	 */
	if (data.n <= (m->gram_bits
		       ? (uint64_t)(1u << m->gram_bits) * 693u / 1000u
		       : GRAM_MAX_BYTES) && gram_ensure(m))
		m->gram_use = m->gram;

	m->n_bytes_indexed = gram_build(m->gram_use, data);
}

static uint8_t fold(uint8_t c)
{
	return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c;
}

/*
 * Literal search over [hay, hay+hlen) for needle.
 *
 * The case sensitive path is kof_memmem: on POSIX the real memmem, vectorised in
 * any real libc and Two-Way internally on glibc, so it is both fast in the
 * ordinary case and immune to the failure mode a memchr-anchored scan has on a
 * haystack that repeats the needle's first byte - a run of one byte value turns
 * every position into a candidate, and a naive verify-per-candidate loop pays
 * O(hlen*nlen) for it. That case is not hypothetical for this engine: object
 * padding, zero-filled sections and repeated bytes in packed data are ordinary,
 * not adversarial, inputs. See kof_memmem in kofplatform.h for the Windows side,
 * which does not have memmem and gets the same worst-case bound from
 * Knuth-Morris-Pratt instead.
 */
static int find_lit(const uint8_t *hay, uint64_t hlen,
		    const uint8_t *needle, uint64_t nlen,
		    int nocase, uint64_t *found)
{
	if (nlen == 0 || nlen > hlen)
		return 0;

	if (!nocase) {
		const void *q = kof_memmem(hay, (size_t)hlen, needle, (size_t)nlen);
		if (!q)
			return 0;
		*found = (uint64_t)((const uint8_t *)q - hay);
		return 1;
	}

	/*
	 * Folded search, keeping the skip inside memchr too - folding every byte in
	 * scalar code measured 1.55 GB/s against 12.5 GB/s for this.
	 *
	 * Two ways to vectorise it, in order of preference: anchor on a byte that has
	 * no case, since a non-letter matches only itself and one memchr finds every
	 * candidate; otherwise memchr for both cases of the first byte and take
	 * whichever comes first.
	 *
	 * The inner compare folds on the fly. It only runs at candidate positions, so
	 * it is not where the time goes.
	 */
	{
		uint64_t last = hlen - nlen;   /* last possible start; nlen <= hlen */
		uint64_t anchor = 0, i, j;
		int has_anchor = 0;

		for (i = 0; i < nlen; i++) {
			uint8_t c = needle[i];
			if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))) {
				anchor = i;
				has_anchor = 1;
				break;
			}
		}

		if (has_anchor) {
			uint64_t at = anchor;      /* scanning anchor positions */
			uint64_t end = last + anchor;

			while (at <= end) {
				const uint8_t *q = memchr(hay + at, needle[anchor],
							  (size_t)(end - at + 1));
				uint64_t s;
				if (!q)
					return 0;
				s = (uint64_t)(q - hay) - anchor;
				for (j = 0; j < nlen; j++)
					if (fold(hay[s + j]) != fold(needle[j]))
						break;
				if (j == nlen) {
					*found = s;
					return 1;
				}
				at = (uint64_t)(q - hay) + 1;
			}
			return 0;
		}

		{
			uint8_t lo = fold(needle[0]);
			uint8_t up = (uint8_t)(lo - 32);   /* lo is a letter here */
			uint64_t s = 0;
			/*
			 * ONCE A CASE IS ABSENT FROM THE TAIL IT STAYS ABSENT.
			 *
			 * memchr returning NULL over [s, last] says the byte is
			 * in none of it, and `s` only ever grows - so every
			 * later call for that case would scan the same bytes to
			 * reach the same NULL. Without this the loop kept
			 * issuing it: with one case missing and the other
			 * frequent, the absent one rescanned the whole
			 * remaining span at every one of the ~n candidates, and
			 * the search went quadratic. Measured on a haystack of
			 * 0x41 with the needle "abc": 64 KB 0.014 s, 256 KB
			 * 0.251 s, 1 MB 5.9 s - an all-letter case-insensitive
			 * pattern over a few megabytes was minutes of one
			 * scan, reachable from the viewer's find box and from
			 * any object too large for the presence table.
			 */
			int lo_gone = 0, up_gone = 0;

			while (s <= last) {
				size_t span = (size_t)(last - s + 1);
				const uint8_t *q = NULL, *q2 = NULL;

				if (!lo_gone) {
					q = memchr(hay + s, lo, span);
					if (!q)
						lo_gone = 1;
				}
				if (!up_gone) {
					q2 = memchr(hay + s, up, span);
					if (!q2)
						up_gone = 1;
				}
				if (q2 && (!q || q2 < q))
					q = q2;
				if (!q)
					return 0;
				s = (uint64_t)(q - hay);
				for (j = 1; j < nlen; j++)
					if (fold(hay[s + j]) != fold(needle[j]))
						break;
				if (j == nlen) {
					*found = s;
					return 1;
				}
				s++;
			}
			return 0;
		}
	}
}

/*
 * Find a literal in [off, off+len), clamped to the object.
 *
 * Kept apart from match_ranges because the range walk and the single-range search
 * are different jobs, and because clamping in one place is what stops every caller
 * repeating it.
 *
 * A len of 0 means the range is not present in this object and there is nothing to
 * search - not "search everything", which would turn an absent region into a scan of
 * the whole file.
 */
static int find_range(struct kof_match_ctx *m, uint64_t off, uint64_t len,
		      const uint8_t *bytes, uint32_t nbytes, int nocase,
		      uint64_t *hit)
{
	uint64_t at = 0;

	m->n_calls++;
	len = kof_clip_len(m->data.n, off, len);
	if (len == 0 || nbytes == 0)
		return 0;

	m->n_bytes_scanned += len;
	if (!find_lit(m->data.p + off, len, bytes, nbytes, nocase, &at))
		return 0;
	if (hit)
		*hit = off + at;
	return 1;
}

/* ---- presence set --------------------------------------------------------- */


struct kof_gram {
	uint16_t *stamp;
	uint16_t  gen;
	uint32_t  slots;
	uint8_t   bits;
};

/* The threshold is gram_ensure's - its only caller tests it before calling, so
 * testing it again here was a second copy of one decision. */
static struct kof_gram *gram_new(uint8_t bits)
{
	struct kof_gram *g;

	g = calloc(1, sizeof *g);
	if (!g)
		return NULL;
	g->bits = bits;
	g->slots = 1u << bits;
	/* calloc is lazy, but build writes scattered stamps, so the pages get touched
	 * for real - which is why this is not allocated when it will not be used. */
	g->stamp = calloc(g->slots, sizeof *g->stamp);
	if (!g->stamp) {
		free(g);
		return NULL;
	}
	return g;
}

static void gram_free(struct kof_gram *g)
{
	if (!g)
		return;
	free(g->stamp);
	free(g);
}

static uint32_t gram_hash4(const struct kof_gram *g, const uint8_t *p)
{
	uint32_t v = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
		     ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
	/* Odd multiplier, high bits taken: mixes all four input bytes into the index,
	 * which matters because the low bytes of a gram in text or code are far from
	 * uniform. */
	return (v * 2654435761u) >> (32 - g->bits);
}

static uint64_t gram_build(struct kof_gram *g, kof_buf b)
{
	uint64_t i;

	if (!g)
		return 0;
	if (++g->gen == 0) {
		/* Wrapped: every slot still holds a stamp from 65535 objects ago,
		 * which would now read as current. */
		memset(g->stamp, 0, (size_t)g->slots * sizeof *g->stamp);
		g->gen = 1;
	}
	if (b.n < 4)
		return 0;
	for (i = 0; i + 4 <= b.n; i++)
		g->stamp[gram_hash4(g, b.p + i)] = g->gen;
	return b.n;
}

static int gram_may_contain(const struct kof_gram *g, const uint8_t *b,
			    uint16_t len, int icase)
{
	uint8_t letter[4], base[4];
	int nl = 0, i, comb;

	/* No table, or too short to key on: everything is a candidate. Checked here so
	 * no caller has to remember it. */
	if (!g || len < 4)
		return 1;
	if (!icase)
		return g->stamp[gram_hash4(g, b)] == g->gen;

	/* The table holds the object's bytes as they are, so a folded pattern has to be
	 * looked up as every case combination its letters allow. */
	for (i = 0; i < 4; i++) {
		uint8_t c = b[i];
		base[i] = c;
		letter[i] = 0;
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			letter[i] = 1;
			nl++;
			base[i] = (uint8_t)(c | 0x20);
		}
	}
	for (comb = 0; comb < (1 << nl); comb++) {
		uint8_t v[4];
		int bit = 0;
		for (i = 0; i < 4; i++) {
			v[i] = base[i];
			if (letter[i]) {
				if (comb & (1 << bit))
					v[i] = (uint8_t)(base[i] & ~0x20u);
				bit++;
			}
		}
		if (g->stamp[gram_hash4(g, v)] == g->gen)
			return 1;
	}
	return 0;
}

/* ---- hex patterns --------------------------------------------------------- */

/*
 * Does one alternative match at `at`?
 *
 * The unmasked path is a memcmp the compiler vectorises and is the common case by a
 * wide margin; the masked path only runs for a pattern that actually has wildcards.
 */
static int alt_at(kof_buf d, uint64_t at, const uint8_t *prog,
		  const struct kof_hex_alt *a)
{
	const uint8_t *b = prog + a->data_off;

	if (!kof_in_range(d, at, a->len))
		return 0;
	if (!(a->flags & KOF_HEX_ALT_MASKED))
		return memcmp(d.p + at, b, a->len) == 0;
	{
		const uint8_t *msk = b + a->len;
		uint16_t i;

		for (i = 0; i < a->len; i++)
			if (((d.p[at + i] ^ b[i]) & msk[i]) != 0)
				return 0;
		return 1;
	}
}

/*
 * Walk the steps forward from `start`, carrying the set of positions still in play.
 *
 * The set is what makes this bounded. Recursing per gap offset and per alternative
 * would multiply the branching factor at every step; carrying positions and
 * deduplicating them adds them instead, so the work is the sum over steps of
 * (positions x gap span x alternatives) rather than the product. Two paths that
 * arrive at the same offset become one, which is the whole trick.
 *
 * The set is kept sorted so the dedup is a comparison against the last write, and
 * so a caller could ask where the match ended.
 */
static int hex_walk(kof_buf d, uint64_t start, const uint8_t *prog)
{
	const struct kof_hex_hdr *h = (const void *)prog;
	const struct kof_hex_step *steps = (const void *)(prog + h->steps_off);
	const struct kof_hex_alt *alts = (const void *)(prog + h->alts_off);
	uint64_t cur[KOF_HEX_MAX_REACH], next[KOF_HEX_MAX_REACH];
	/*
	 * WHICH END OFFSETS THIS STEP HAS ALREADY RECORDED, exactly.
	 *
	 * The dedup used to be one comparison against the last write, on the
	 * claim that "positions are produced in non-decreasing order within a
	 * step". That is true only while there is ONE position to carry: with
	 * several, the writes run cur[0]+gap_min..cur[0]+gap_max, then restart
	 * at cur[1]+gap_min - BELOW the last write - so every overlap between
	 * one position's window and the next was written again. next[] filled
	 * with duplicates, reached KOF_HEX_MAX_REACH, and the `break` then
	 * discarded the whole high end of the genuinely reachable set: a
	 * pattern with two varying gaps of 23 bytes or more each stopped
	 * matching input it is present in. Measured: `[0-21] ?? [0-21]` found
	 * its target, `[0-22] ?? [0-22]` did not, the threshold being
	 * (gap+1)^2 > 512 - the count of DUPLICATES, not of answers.
	 *
	 * A bitmap makes it exact and O(1). Every end lies at or after `start`
	 * and no further than the longest a match can be, and the format bounds
	 * that: KOF_HEX_MAX_STEPS alternatives of at most KOF_HEX_MAX_ALT_LEN,
	 * plus KOF_HEX_MAX_GAP_TOTAL of summed gap variance. So the window is a
	 * compile-time size and the whole thing is 290 bytes of stack.
	 */
	uint8_t seen[(KOF_HEX_MAX_STEPS * KOF_HEX_MAX_ALT_LEN +
		      KOF_HEX_MAX_GAP_TOTAL) / 8u + 2u];
	uint32_t n_cur = 1, i;

	cur[0] = start;

	for (i = 0; i < h->n_steps; i++) {
		const struct kof_hex_step *st = &steps[i];
		uint32_t n_next = 0, k;

		memset(seen, 0, sizeof seen);
		for (k = 0; k < n_cur; k++) {
			uint32_t g;

			for (g = st->gap_min; g <= st->gap_max; g++) {
				uint64_t at = kof_sat_add(cur[k], g);
				uint32_t j;

				if (at >= d.n)
					break;
				for (j = 0; j < st->n_alts; j++) {
					const struct kof_hex_alt *a =
						&alts[st->alt_first + j];
					uint64_t end, rel;

					if (!alt_at(d, at, prog, a))
						continue;
					end = at + a->len;
					rel = end - start;
					if (rel < (uint64_t)sizeof seen * 8u) {
						if (seen[rel >> 3] &
						    (uint8_t)(1u << (rel & 7u)))
							continue;
						seen[rel >> 3] |=
						    (uint8_t)(1u << (rel & 7u));
					} else if (n_next &&
						   next[n_next - 1] == end) {
						/* Past the window the format
						 * allows: keep the old weaker
						 * test rather than record a
						 * duplicate. Unreachable for a
						 * program the loader accepted. */
						continue;
					}
					if (n_next >= KOF_HEX_MAX_REACH)
						goto reach_full;
					next[n_next++] = end;
				}
			}
		}
reach_full:
		if (n_next == 0)
			return 0;
		memcpy(cur, next, n_next * sizeof cur[0]);
		n_cur = n_next;
	}
	return 1;
}

/*
 * Find a hex pattern in [off, off+len).
 *
 * The anchor is what makes this a search rather than a walk from every position:
 * the compiler recorded the longest run of concrete bytes and how far into a match
 * it sits, so find_lit locates candidates at memchr speed and the walk only runs
 * where the run actually appeared.
 */
static int hex_search(struct kof_match_ctx *m, uint64_t off, uint64_t len,
		      const uint8_t *prog, uint64_t *hit)
{
	const struct kof_hex_hdr *h = (const void *)prog;
	const struct kof_hex_step *steps = (const void *)(prog + h->steps_off);
	const struct kof_hex_alt *alts = (const void *)(prog + h->alts_off);
	const struct kof_hex_alt *aa = &alts[steps[h->anchor_step].alt_first];
	const uint8_t *run = prog + aa->data_off + h->anchor_in_alt;
	uint64_t at = 0, base = off;
	/*
	 * THE RANGE'S END, and the walk is not allowed past it.
	 *
	 * hex_walk and alt_at bounded their reads against the OBJECT, so a hex
	 * match could begin inside the range and run out the other side of it -
	 * a pattern scoped to the PE headers could match with its tail in the
	 * first section, and it disagreed with the literal search, which
	 * respects the range exactly. Reading outside the range one was asked
	 * about is a bug however the bytes happen to be laid out.
	 *
	 * Fixed by handing the walk a view that ENDS where the range does
	 * rather than by threading a limit through every read: alt_at already
	 * bounds with kof_in_range against the buffer it is given, and
	 * hex_walk's own test is `at >= d.n`, so shrinking `n` bounds every
	 * read there is - present and future - and none can be forgotten. The
	 * base pointer is unchanged, so offsets stay absolute.
	 */
	kof_buf lim;

	m->n_calls++;
	len = kof_clip_len(m->data.n, off, len);
	if (len < h->min_span)
		return 0;
	m->n_bytes_scanned += len;
	lim.p = m->data.p;
	lim.n = off + len;

	for (;;) {
		uint64_t q, d;

		if (!find_lit(m->data.p + base, len, run, h->anchor_len, 0, &at))
			return 0;
		q = base + at;

		/*
		 * Where the match would have to begin for the run to land here.
		 * A window rather than a point, because a gap or an alternation of
		 * unequal lengths before the anchor makes the distance vary; it is
		 * one wide for a pattern whose concrete bytes come first.
		 */
		for (d = h->anchor_before_min; d <= h->anchor_before_max; d++) {
			uint64_t start;

			if (q < d)
				break;
			start = q - d;
			if (start < off)
				break;
			/*
			 * And the range's end is a cheap reject: a match needs
			 * min_span bytes and this candidate has only
			 * lim.n - start left, so the walk is not entered at all
			 * when the tail is too short for the shortest match.
			 */
			if (lim.n - start < h->min_span)
				continue;
			if (hex_walk(lim, start, prog)) {
				if (hit)
					*hit = start;
				return 1;
			}
		}

		if (at + 1 >= len)
			return 0;
		base += at + 1;
		len -= at + 1;
	}
}

/* ---- searching ranges ----------------------------------------------------- */

static int is_word_byte(uint8_t c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '_';
}

/*
 * Search one range for a pattern of either kind.
 *
 * One function rather than two because the kinds differ only in how a candidate is
 * found and verified; the walk over extents, the restart after a rejected hit and
 * the word-boundary rule around it are the same question either way.
 */
/*
 * `at` receives where the match began, and is the only reason this reports more
 * than yes or no.
 *
 * The search already knows: find_range and hex_search both compute the hit and it
 * was discarded at this line. An unpacker needs it - a UPX stub is located by its
 * magic and everything after is read relative to that - and a module that had to
 * find it itself would walk the object a byte at a time through the read vtable,
 * which is an indirect call per byte to repeat a search the host just did.
 */
static int match_one(struct kof_match_ctx *m, uint64_t base, uint64_t span,
		     const uint8_t *bytes, uint16_t len, uint8_t kind,
		     uint8_t flags, uint64_t *at)
{
	uint64_t from = 0, hit;

	while (span > from) {
		if (kind == KOF_STR_HEX) {
			if (!hex_search(m, base + from, span - from, bytes, &hit))
				return 0;
			if (at)
				*at = hit;
			return 1;      /* hex patterns carry no word option */
		}
		if (!find_range(m, base + from, span - from, bytes, len,
				(flags & KOF_STR_ICASE) != 0, &hit))
			return 0;
		if (!(flags & KOF_STR_FULLWORD)) {
			if (at)
				*at = hit;
			return 1;
		}
		{
			uint64_t end = hit + len;
			int lok = (hit == base) ||
				  !is_word_byte(m->data.p[hit - 1]);
			/*
			 * `end >= m->data.n` before the read, not only
			 * `end >= base + span`.
			 *
			 * span is the CALLER's, and match_ranges hands the
			 * region extents through unclipped - unlike
			 * kof_match_in and kof_match_where, which both clip
			 * first. An extent claiming more than the object holds
			 * therefore let a FULLWORD match at the very last byte
			 * read data.p[data.n]. It is also the right answer:
			 * a match that ends at the end of the object has no
			 * following byte, so there is nothing to break the
			 * word.
			 */
			int rok = (end >= base + span) || end >= m->data.n ||
				  !is_word_byte(m->data.p[end]);
			if (lok && rok) {
				if (at)
					*at = hit;
				return 1;
			}
		}
		from = (hit - base) + 1;
	}
	return 0;
}

static int match_ranges(struct kof_match_ctx *m, const struct kof_range *ext,
			uint32_t next, const uint8_t *bytes, uint16_t len,
			uint8_t kind, uint8_t flags)
{
	uint32_t i;

	for (i = 0; i < next; i++) {
		/* Clipped here as kof_match_in and kof_match_where do it: an
		 * extent is produced by a format collector and describes the
		 * object it was parsed from, so it should already fit - but the
		 * two ad-hoc entry points do not trust that either. */
		uint64_t l = kof_clip_len(m->data.n, ext[i].off, ext[i].len);

		if (l && match_one(m, ext[i].off, l, bytes, len, kind, flags, 0))
			return 1;
	}
	return 0;
}

/* ---- per-object search state ---------------------------------------------- */

/*
 * Make the presence table if this database wants one and it is not made yet.
 *
 * Deferred rather than made at init because it is 32MB of scattered writes: a
 * scanner that only ever sees objects too large for the filter, or that is created
 * and never used, should not pay for a table it does not touch. Returns whether one
 * is available.
 */
static int gram_ensure(struct kof_match_ctx *m)
{
	if (m->gram)
		return 1;
	if (m->gram_patterns < (m->gram_min ? m->gram_min : GRAM_MIN_PATTERNS))
		return 0;
	m->gram = gram_new(m->gram_bits ? m->gram_bits : GRAM_BITS);
	return m->gram != NULL;
}

int kof_match_state_init(struct kof_match_ctx *m, uint32_t n_patterns,
			 uint32_t memo_len)
{
	/* gram_bits and gram_min are the caller's, set before this and kept. */
	m->gram = NULL;                   /* built on first object that wants it */
	m->gram_use = NULL;
	m->gram_patterns = n_patterns;
	m->memo_len = memo_len;
	m->memo_gen = 0;
	m->memo = memo_len ? calloc(memo_len, sizeof *m->memo) : NULL;
	return !memo_len || m->memo != NULL;
}

void kof_match_state_free(struct kof_match_ctx *m)
{
	gram_free(m->gram);
	free(m->memo);
	m->gram = NULL;
	m->gram_use = NULL;
	m->memo = NULL;
	m->memo_len = 0;
}

/*
 * What the presence set should be asked about.
 *
 * A literal is keyed on its own first four bytes. A hex pattern is keyed on its
 * anchor run, which is the only part of it that is concrete - and only if that run
 * reaches four bytes, since the table holds four-byte windows. A shorter run means
 * the filter cannot speak for this pattern and it is searched.
 */
static int gram_admits(const struct kof_gram *g, const uint8_t *bytes, uint16_t len,
		       uint8_t kind, uint8_t flags)
{
	if (kind == KOF_STR_HEX) {
		const struct kof_hex_hdr *h = (const void *)bytes;
		const struct kof_hex_step *steps = (const void *)(bytes + h->steps_off);
		const struct kof_hex_alt *alts = (const void *)(bytes + h->alts_off);
		const struct kof_hex_alt *aa = &alts[steps[h->anchor_step].alt_first];

		if (h->anchor_len < 4)
			return 1;
		return gram_may_contain(g, bytes + aa->data_off + h->anchor_in_alt,
					(uint16_t)h->anchor_len, 0);
	}
	return gram_may_contain(g, bytes, len, (flags & KOF_STR_ICASE) != 0);
}

static uint16_t *memo_cell(const struct kof_match_ctx *m, uint32_t slot)
{
	return (m->memo && slot < m->memo_len) ? &m->memo[slot] : NULL;
}

int kof_match_memo_get(const struct kof_match_ctx *m, uint32_t slot)
{
	uint16_t *cell = memo_cell(m, slot);

	/* Written by an earlier object is the same as not written. */
	if (!cell || (*cell >> 2) != m->memo_gen)
		return -1;
	switch (*cell & 3u) {
	case KOF_MEMO_PRESENT: return 1;
	case KOF_MEMO_ABSENT:  return 0;
	default:               return -1;
	}
}

void kof_match_memo_put(struct kof_match_ctx *m, uint32_t slot, int found)
{
	uint16_t *cell = memo_cell(m, slot);

	if (cell)
		*cell = (uint16_t)((m->memo_gen << 2) |
				   (found ? KOF_MEMO_PRESENT : KOF_MEMO_ABSENT));
}

int kof_match_lookup(struct kof_match_ctx *m, uint32_t slot,
		     const struct kof_range *ext, uint32_t next,
		     const uint8_t *bytes, uint16_t len, uint8_t kind, uint8_t flags,
		     uint64_t *answered_without_scan)
{
	uint16_t *cell;
	int found;

	/*
	 * NO MEMO MEANS NO MEMOISING, NOT "ABSENT".
	 *
	 * This used to `return 0` when the memo was missing or too small - which
	 * reports the pattern as not present WITHOUT LOOKING, so a database that
	 * ended up with memo_size 0 (kofdb.c derives it from n_uid * n_masks)
	 * would load clean, scan every object and detect nothing at all. The
	 * memo is a cache; the honest degradation is to answer the question the
	 * slow way. kof_match_state_init already treats memo_len 0 as success,
	 * so the two now agree.
	 */
	cell = memo_cell(m, slot);
	{
		int known = kof_match_memo_get(m, slot);

		if (known >= 0)
			return known;
	}

	if (!gram_admits(m->gram_use, bytes, len, kind, flags)) {
		if (answered_without_scan)
			(*answered_without_scan)++;
		if (cell)
			*cell = (uint16_t)((m->memo_gen << 2) | KOF_MEMO_ABSENT);
		return 0;
	}
	found = match_ranges(m, ext, next, bytes, len, kind, flags);
	if (cell)
		*cell = (uint16_t)((m->memo_gen << 2) |
				   (found ? KOF_MEMO_PRESENT : KOF_MEMO_ABSENT));
	return found;
}

/*
 * Compare at exactly one offset.
 *
 * The bound is checked against the shortest a match can be, not the longest: a hex
 * pattern with a gap may match well inside its maximum span, and refusing on the
 * maximum would silently drop matches near the end of an object. Everything past
 * that point is bounds checked as it is read.
 *
 * No memo, no presence set. The offset is whatever the module computed, so there is
 * no constant to key a memo on, and the presence set answers "is it anywhere in the
 * object" - a question strictly weaker than the one being asked here, and no
 * cheaper than the comparison itself.
 */
int kof_match_at(struct kof_match_ctx *m, uint64_t off,
		 const uint8_t *bytes, uint16_t len, uint8_t kind, uint8_t flags)
{
	m->n_calls++;

	/*
	 * A pattern of no bytes matches nothing, which is what find_lit and
	 * find_range both already answer. This entry point did not: an empty
	 * needle passed the range test and then memcmp(.., 0) compared equal,
	 * so it reported a match at every offset in the object. The three
	 * entry points have to agree about what an empty pattern is, and a
	 * caller with a user-supplied length reaches this one - the viewer's
	 * find box does.
	 */
	if (!len && kind != KOF_STR_HEX)
		return 0;

	if (kind == KOF_STR_HEX) {
		const struct kof_hex_hdr *h = (const void *)bytes;

		if (!kof_in_range(m->data, off, h->min_span))
			return 0;
		m->n_bytes_scanned += h->min_span;
		return hex_walk(m->data, off, bytes);
	}

	if (!kof_in_range(m->data, off, len))
		return 0;
	m->n_bytes_scanned += len;
	/*
	 * THE WORD RULE APPLIES HERE TOO, AND USED NOT TO.
	 *
	 * The flag arrived, was carried through the descriptor, and was dropped:
	 * this compared bytes and nothing else. So one declaration meant two
	 * things depending on which door a module used - kof_find_str_any on a
	 * FULLWORD "sh" refuses to see it inside "bash", and kof_find_str_at on
	 * the same string agreed that it was there. A marker that means
	 * different things to different calls is worse than a marker that is
	 * wrong, because only one of the two readings is ever tested.
	 *
	 * The boundary is the OBJECT, which is the only one this call has: it is
	 * given an offset and no window. match_one, which is given a range,
	 * treats the range edge as a boundary instead - that is the region the
	 * module asked about, and its edge is where its text stops.
	 *
	 * Hex carries no word option; see the same note in match_one.
	 */
	if (flags & KOF_STR_FULLWORD) {
		if (off > 0 && is_word_byte(m->data.p[off - 1]))
			return 0;
		if (off + len < m->data.n && is_word_byte(m->data.p[off + len]))
			return 0;
	}
	if (flags & KOF_STR_ICASE) {
		uint16_t i;

		for (i = 0; i < len; i++)
			if (fold(m->data.p[off + i]) != fold(bytes[i]))
				return 0;
		return 1;
	}
	return memcmp(m->data.p + off, bytes, len) == 0;
}

int kof_match_in(struct kof_match_ctx *m, uint64_t off, uint64_t len,
		 const uint8_t *bytes, uint16_t plen, uint8_t kind, uint8_t flags)
{
	len = kof_clip_len(m->data.n, off, len);
	if (len == 0)
		return 0;
	return match_one(m, off, len, bytes, plen, kind, flags, 0);
}

/*
 * The same search, reporting where rather than whether.
 *
 * KOF_BROKEN for absent, which is the same "no answer" every other offset-valued
 * accessor in the module ABI uses, so a module tests it the way it already tests
 * kof_pe_rva_to_off.
 */
uint64_t kof_match_where(struct kof_match_ctx *m, uint64_t off, uint64_t len,
			 const uint8_t *bytes, uint16_t plen, uint8_t kind,
			 uint8_t flags)
{
	uint64_t at = 0;

	len = kof_clip_len(m->data.n, off, len);
	if (len == 0)
		return KOF_BROKEN;
	if (!match_one(m, off, len, bytes, plen, kind, flags, &at))
		return KOF_BROKEN;
	return at;
}
