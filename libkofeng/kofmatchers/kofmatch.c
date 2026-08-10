/*
 * kofmatch.c - literal search.
 *
 * It builds nothing: no automaton, no per-scan preparation. Building a shared
 * structure over every pattern in a database is what forces that structure to be
 * resident and to grow with the database, which is the cost this design avoids.
 *
 * It trusts nothing in a compiled array either. Those arrive as bytes out of a
 * database, so every offset and length is bounds checked; a malformed set yields no
 * matches and never reads outside the array.
 */

#include "../kofmatchers/kofmatch.h"

#include <stdlib.h>
#include <string.h>

/* Defined with the presence set further down; declared here because starting on a new
 * object is the first thing in the file and restamping the table is part of it. */
static struct kof_gram *gram_new(uint32_t n_patterns);
static void             gram_free(struct kof_gram *);
static uint64_t         gram_build(struct kof_gram *, kof_buf);
static int              gram_may_contain(const struct kof_gram *, const uint8_t *,
					 uint16_t len, int icase);

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
	uint8_t *memo = m->memo;
	uint32_t memo_len = m->memo_len;

	memset(m, 0, sizeof *m);
	m->data = data;
	m->gram = gram;
	m->memo = memo;
	m->memo_len = memo_len;

	if (memo)
		memset(memo, KOF_MEMO_UNKNOWN, memo_len);
	m->n_bytes_indexed = gram_build(gram, data);
}

static uint8_t fold(uint8_t c)
{
	return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c;
}

/*
 * Literal search over [hay, hay+hlen) for needle.
 *
 * The case sensitive path leaves the skip to memchr and the compare to memcmp, both
 * vectorised in any real libc: 18.8 GB/s against 1.55 GB/s for a byte at a time loop.
 */
static int find_lit(const uint8_t *hay, uint64_t hlen,
		    const uint8_t *needle, uint64_t nlen,
		    int nocase, uint64_t *found)
{
	if (nlen == 0 || nlen > hlen)
		return 0;

	if (!nocase) {
		const uint8_t *p = hay;
		uint64_t left = hlen;

		while (left >= nlen) {
			const uint8_t *q = memchr(p, needle[0], left - nlen + 1);
			if (!q)
				return 0;
			if (memcmp(q, needle, nlen) == 0) {
				*found = (uint64_t)(q - hay);
				return 1;
			}
			left -= (uint64_t)(q - p) + 1;
			p = q + 1;
		}
		return 0;
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

			while (s <= last) {
				size_t span = (size_t)(last - s + 1);
				const uint8_t *q = memchr(hay + s, lo, span);
				const uint8_t *q2 = memchr(hay + s, up, span);
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

/*
 * 24 bits of table, 16-bit generation stamps: 32MB, fixed whatever the database
 * holds. Measured on 400 binaries, 22 bits saturated on the files above 1MB and cost
 * 5x the wall time; 26 bits was slower again from TLB pressure.
 */
#define GRAM_BITS  24
#define GRAM_SLOTS (1u << GRAM_BITS)

/*
 * Below this many patterns the table is not built at all.
 *
 * It is an amortisation device: one pass over the object plus a scattered write per
 * byte, so that each of many queries is free. With two queries there is nothing to
 * amortise - measured on one module over one sample directory, building it
 * unconditionally cost 4.37s and 53MB against 2.74s and 5MB. The threshold is a guess
 * pending measurement of the crossover; that there *is* a crossover is not.
 */
#define GRAM_MIN_PATTERNS 32

struct kof_gram {
	uint16_t *stamp;
	uint16_t  gen;
};

static struct kof_gram *gram_new(uint32_t n_patterns)
{
	struct kof_gram *g;

	if (n_patterns < GRAM_MIN_PATTERNS)
		return NULL;
	g = calloc(1, sizeof *g);
	if (!g)
		return NULL;
	/* calloc is lazy, but build writes scattered stamps, so the pages get touched
	 * for real - which is why this is not allocated when it will not be used. */
	g->stamp = calloc(GRAM_SLOTS, sizeof *g->stamp);
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

static uint32_t gram_hash4(const uint8_t *p)
{
	uint32_t v = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
		     ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
	/* Odd multiplier, high bits taken: mixes all four input bytes into the index,
	 * which matters because the low bytes of a gram in text or code are far from
	 * uniform. */
	return (v * 2654435761u) >> (32 - GRAM_BITS);
}

static uint64_t gram_build(struct kof_gram *g, kof_buf b)
{
	uint64_t i;

	if (!g)
		return 0;
	if (++g->gen == 0) {
		/* Wrapped: every slot still holds a stamp from 65535 objects ago,
		 * which would now read as current. */
		memset(g->stamp, 0, (size_t)GRAM_SLOTS * sizeof *g->stamp);
		g->gen = 1;
	}
	if (b.n < 4)
		return 0;
	for (i = 0; i + 4 <= b.n; i++)
		g->stamp[gram_hash4(b.p + i)] = g->gen;
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
		return g->stamp[gram_hash4(b)] == g->gen;

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
		if (g->stamp[gram_hash4(v)] == g->gen)
			return 1;
	}
	return 0;
}

/* ---- searching ranges ----------------------------------------------------- */

static int is_word_byte(uint8_t c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '_';
}

static int match_ranges(struct kof_match_ctx *m, const struct kof_range *ext,
			uint32_t next, const uint8_t *bytes, uint16_t len,
			int icase, int fullword)
{
	uint32_t i;

	for (i = 0; i < next; i++) {
		uint64_t base = ext[i].off, span = ext[i].len, from = 0, hit;

		while (span > from &&
		       find_range(m, base + from, span - from, bytes, len,
				  icase, &hit)) {
			if (!fullword)
				return 1;
			{
				uint64_t end = hit + len;
				int lok = (hit == base) ||
					  !is_word_byte(m->data.p[hit - 1]);
				int rok = (end >= base + span) ||
					  !is_word_byte(m->data.p[end]);
				if (lok && rok)
					return 1;
			}
			from = (hit - base) + 1;
		}
	}
	return 0;
}

/* ---- per-object search state ---------------------------------------------- */

int kof_match_state_init(struct kof_match_ctx *m, uint32_t n_patterns,
			 uint32_t memo_len)
{
	m->gram = gram_new(n_patterns);   /* NULL is a normal answer */
	m->memo_len = memo_len;
	m->memo = memo_len ? calloc(memo_len, 1) : NULL;
	return !memo_len || m->memo != NULL;
}

void kof_match_state_free(struct kof_match_ctx *m)
{
	gram_free(m->gram);
	free(m->memo);
	m->gram = NULL;
	m->memo = NULL;
	m->memo_len = 0;
}

int kof_match_lookup(struct kof_match_ctx *m, uint32_t slot,
		     const struct kof_range *ext, uint32_t next,
		     const uint8_t *bytes, uint16_t len, int icase, int fullword,
		     uint64_t *answered_without_scan)
{
	uint8_t *cell;
	int found;

	if (!m->memo || slot >= m->memo_len)
		return 0;
	cell = &m->memo[slot];
	if (*cell != KOF_MEMO_UNKNOWN)
		return *cell == KOF_MEMO_PRESENT;

	if (!gram_may_contain(m->gram, bytes, len, icase)) {
		if (answered_without_scan)
			(*answered_without_scan)++;
		*cell = KOF_MEMO_ABSENT;
		return 0;
	}
	found = match_ranges(m, ext, next, bytes, len, icase, fullword);
	*cell = found ? KOF_MEMO_PRESENT : KOF_MEMO_ABSENT;
	return found;
}
