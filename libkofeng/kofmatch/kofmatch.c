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

#include "kofmatch.h"

#include <string.h>

void kof_match_begin(struct kof_match_ctx *m, kof_buf data)
{
	memset(m, 0, sizeof *m);
	m->data = data;
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

/* Bounds checked view of a record inside the compiled array. */
static const uint8_t *at(const uint8_t *p, uint32_t clen, uint32_t off,
			 uint32_t need)
{
	if (off > clen || need > clen - off)
		return 0;
	return p + off;
}

static uint16_t rd16le(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

uint64_t kof_match_find_set(struct kof_match_ctx *m,
			    uint64_t off, uint64_t len,
			    const uint8_t *compiled, uint32_t clen,
			    uint64_t *first_hit)
{
	const uint8_t *hdr, *descs;
	uint64_t hits = 0, earliest = UINT64_MAX;
	uint32_t npat, i;

	m->n_calls++;

	/*
	 * Clamp before anything else, so every path below works on a range known
	 * to be inside the object. A len of 0 means the region is not present in
	 * this object and there is nothing to search - not "search everything",
	 * which would turn an absent region into a scan of the whole file.
	 */
	if (len == 0 || off > m->data.n)
		return 0;
	if (len > m->data.n - off)
		len = m->data.n - off;

	if (m->memo_valid && m->memo_pat == compiled &&
	    m->memo_off == off && m->memo_len == len) {
		m->n_memo_hits++;
		if (first_hit)
			*first_hit = 0; /* not memoised; callers wanting the
					 * offset should not rely on the cache */
		return m->memo_hits;
	}

	hdr = at(compiled, clen, 0, (uint32_t)sizeof(struct kof_pat_hdr));
	if (!hdr)
		return 0;
	if (hdr[0] != KOF_PAT_FORMAT_VERSION)
		return 0;
	npat = hdr[1];
	if (npat == 0 || npat > KOF_PAT_MAX_IN_SET)
		return 0;
	if (rd16le(hdr + 2) != clen)
		return 0; /* self-check: the array was truncated or is not one */

	descs = at(compiled, clen, (uint32_t)sizeof(struct kof_pat_hdr),
		   npat * 4u);
	if (!descs)
		return 0;

	for (i = 0; i < npat; i++) {
		const uint8_t *d = descs + i * 4u;
		uint8_t  flags   = d[0];
		uint8_t  nfrag   = d[1];
		uint16_t frag_off = rd16le(d + 2);
		const uint8_t *f, *bytes;
		uint16_t dlen;
		uint64_t hit;

		/* Only single fragment patterns exist so far. Multi fragment
		 * sets are a generator change, not a format change, and are
		 * skipped rather than half matched until this side implements
		 * the gap walk. */
		if (nfrag != 1)
			continue;
		if (flags & (KOF_PATF_HAS_MASK | KOF_PATF_NEGATE))
			continue;

		f = at(compiled, clen, frag_off, 8);
		if (!f)
			continue;
		dlen = rd16le(f + 6);
		bytes = at(compiled, clen, rd16le(f + 4), dlen);
		if (!bytes || dlen == 0)
			continue;

		m->n_bytes_scanned += len;
		if (find_lit(m->data.p + off, len, bytes, dlen,
			     (flags & KOF_PATF_IGNORE_CASE) != 0, &hit)) {
			hits |= 1ull << i;
			if (off + hit < earliest)
				earliest = off + hit;
		}
	}

	m->memo_pat   = compiled;
	m->memo_off   = off;
	m->memo_len   = len;
	m->memo_hits  = hits;
	m->memo_valid = 1;

	if (first_hit && hits)
		*first_hit = earliest;
	return hits;
}

/*
 * Search a literal in a byte range of the object.
 *
 * The host side entry point, and now the one that matters: strings are declared and
 * the host owns the search, so there is no compiled array to walk. It clamps the
 * range and defers to find_lit, so every caller gets the same bounds handling rather
 * than repeating it.
 *
 * A len of 0 means the range is not present in this object and there is nothing to
 * search - not "search everything", which would turn an absent region into a scan of
 * the whole file.
 */
uint64_t kof_match_find(struct kof_match_ctx *m, uint64_t off, uint64_t len,
			const uint8_t *bytes, uint32_t nbytes, int nocase,
			uint64_t *hit)
{
	uint64_t at = 0;

	m->n_calls++;
	if (len == 0 || nbytes == 0 || off > m->data.n)
		return 0;
	if (len > m->data.n - off)
		len = m->data.n - off;

	m->n_bytes_scanned += len;
	if (!find_lit(m->data.p + off, len, bytes, nbytes, nocase, &at))
		return 0;
	if (hit)
		*hit = off + at;
	return 1;
}
