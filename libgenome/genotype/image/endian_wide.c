/*
 * endian_wide.c - UTF-16BE runs to UTF-16LE.
 *
 * The rule is in endian.h (kgenome_endian_wide); what is here is the walk. The
 * bytes the plan claims (the code, the tables) are stepped over a span at a time,
 * the bytes `keep` protects a map word at a time, and what is left is read an
 * aligned 2-byte unit at a time, losing interest in a unit the moment its first
 * byte is not zero - which is nearly every unit of compressed data.
 */

#define _GNU_SOURCE

#include <genotype/image/endian.h>

#include <string.h>

/* The printable ASCII range the narrowing in the normaliser uses: one unsigned compare. */
static int printable(uint8_t c)
{
	return (uint8_t)(c - 0x20u) < 0x5fu;
}

static int kept(const uint8_t *keep, uint64_t i)
{
	return keep && (keep[i >> 3] & (uint8_t)(1u << (i & 7u)));
}

/* Step over kept bytes a map word at a time: the bit test to a byte boundary, then 64
 * bytes, then 8. */
static uint64_t skip_kept(const uint8_t *keep, uint64_t i, uint64_t limit)
{
	while ((i & 7u) && i < limit && kept(keep, i))
		i++;
	while (i + 64u <= limit) {
		uint64_t w;

		memcpy(&w, keep + (i >> 3), sizeof w);
		if (w != ~(uint64_t)0)
			break;
		i += 64u;
	}
	while (i + 8u <= limit && keep[i >> 3] == 0xffu)
		i += 8u;
	return i;
}

/* Eight bytes none of which is zero: exact, and independent of the byte order. */
static int no_zero_byte(const uint8_t *p)
{
	uint64_t w;

	memcpy(&w, p, sizeof w);
	return !((w - 0x0101010101010101ull) & ~w & 0x8080808080808080ull);
}

/* The free stretch [i, limit): no plan span in it. Counts the runs it swaps. */
static void stretch(uint8_t *buf, uint64_t i, uint64_t limit, const uint8_t *keep,
		    uint32_t min_chars, uint32_t *runs)
{
	while (i + 1u < limit) {
		uint64_t k;

		if (buf[i] != 0u) {
			/* A unit that starts with a byte that is not zero is nothing to this
			 * pass, and so are eight bytes with no zero in them - nearly all of
			 * compressed data. */
			i += (i + 8u <= limit && no_zero_byte(buf + i)) ? 8u : 2u;
			continue;
		}
		if (!printable(buf[i + 1u])) {
			/* Padding is zero: a whole word of it is four units that start no run. */
			uint64_t w = 1;

			if (i + 8u <= limit)
				memcpy(&w, buf + i, sizeof w);
			i += w == 0u ? 8u : 2u;
			continue;
		}
		if (kept(keep, i) || kept(keep, i + 1u)) {
			uint64_t s = skip_kept(keep, i, limit);

			i = s > i ? (s + 1u) & ~(uint64_t)1u : i + 2u;  /* units are even-aligned */
			continue;
		}
		/* A run does not START on a unit whose zero follows a printable byte: that
		 * is the high byte of a little-endian character at the odd offset before
		 * it, and the two readings cannot be told apart by anything else. */
		if (i && printable(buf[i - 1u])) {
			i += 2u;
			continue;
		}
		/* The run: every unit (00, printable) up to a unit that is not, a kept
		 * byte, or the end of the stretch. */
		k = i;
		while (k + 1u < limit && buf[k] == 0u && printable(buf[k + 1u]) &&
		       !kept(keep, k) && !kept(keep, k + 1u))
			k += 2u;
		if ((k - i) / 2u >= min_chars) {
			uint64_t q;

			for (q = i; q < k; q += 2u) {
				uint8_t t = buf[q];

				buf[q] = buf[q + 1u];
				buf[q + 1u] = t;
			}
			(*runs)++;
		}
		i = k > i ? k : i + 2u;
	}
}

uint32_t kgenome_endian_wide(uint8_t *buf, uint64_t n, const uint8_t *keep,
			     const struct kgenome_endian_plan *plan, uint32_t min_chars)
{
	uint64_t i = 0;
	uint32_t runs = 0, j = 0, np = plan ? plan->n : 0;

	if (!buf || n < 2u || !min_chars)
		return 0;
	while (i + 1u < n) {
		uint64_t limit;

		/* Past the spans that end before here; inside one is not ours. */
		while (j < np && plan->v[j].off + plan->v[j].len <= i)
			j++;
		if (j < np && plan->v[j].off <= i) {
			i = (plan->v[j].off + plan->v[j].len + 1u) & ~(uint64_t)1u;
			continue;
		}
		limit = j < np ? plan->v[j].off : n;
		stretch(buf, i, limit, keep, min_chars, &runs);
		/* The unit that straddles the start of the next span is not whole inside
		 * the stretch; the next turn of this loop is inside the span. */
		i = (limit + 1u) & ~(uint64_t)1u;
	}
	return runs;
}
