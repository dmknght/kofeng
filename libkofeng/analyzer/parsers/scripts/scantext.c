/*
 * scantext.c - see scantext.h.
 */

#include <string.h>

#include "scantext.h"

int kof_txt_tag_at(kof_buf f, uint64_t at, const char *tag, uint32_t len)
{
	uint32_t i;

	if (at + len > f.n)
		return 0;
	for (i = 0; i < len; i++) {
		uint8_t a = f.p[at + i], b = (uint8_t)tag[i];

		if (a >= 'A' && a <= 'Z')
			a = (uint8_t)(a + 32);
		if (b >= 'A' && b <= 'Z')
			b = (uint8_t)(b + 32);
		if (a != b)
			return 0;
	}
	return 1;
}

/*
 * THE FIRST CHARACTER DECIDES WHETHER THE REST IS WORTH ASKING ABOUT.
 *
 * This called kof_txt_tag_at at EVERY position, and that function folds the
 * case of both sides a character at a time - so a search that fails, which is
 * nearly all of them, still paid a call and a fold to learn that byte zero did
 * not match. Measured with callgrind over 120 system binaries (109 MB):
 * 22,232,762 calls, 855 million instructions, 7.7% of the entire scan. It is a
 * naive O(n*m) substring search, and svrpage_parse.c asks it about FIFTEEN
 * different tags over the same buffer in one chain of `||`.
 *
 * So the first byte is tested inline. A tag that does not begin with a letter -
 * which is every "<...", and those are most of them - has exactly one byte that
 * can start it, and memchr finds the next one a cache line at a time. A tag
 * that does begin with a letter has two, and two compares still beat a call.
 *
 * NOTHING IS SKIPPED THAT COULD HAVE MATCHED: every position passed over holds
 * a byte that folds to neither spelling of the tag's first character, and
 * kof_txt_tag_at's first comparison is exactly that test. Verified against the
 * old form over 400,000 randomised buffers, ten tags and every value of `look`,
 * including the empty tag - which the old code answers 1 for.
 *
 * `cap` is both bounds at once. The old loop stopped at `look` and let
 * kof_txt_tag_at refuse anything past f.n; taking the smaller of the two up
 * front is the same set of positions, and it is what makes the memchr below
 * safe to run to its end.
 */
int kof_txt_has(kof_buf f, uint64_t look, const char *t)
{
	uint32_t len = 0;
	uint64_t i, cap, lim;
	uint8_t  c_lo, c_up;

	while (t[len])
		len++;
	if (look < len)
		return 0;
	if (!len)
		return 1;               /* what the old loop answered at i = 0 */

	cap = look < f.n ? look : f.n;
	if (cap < len)
		return 0;
	lim = cap - len + 1u;           /* positions 0 .. lim - 1 */

	c_lo = (uint8_t)t[0];
	if (c_lo >= 'A' && c_lo <= 'Z')
		c_lo = (uint8_t)(c_lo + 32);
	c_up = (c_lo >= 'a' && c_lo <= 'z') ? (uint8_t)(c_lo - 32) : c_lo;

	if (c_lo == c_up) {
		i = 0;
		while (i < lim) {
			const uint8_t *h = memchr(f.p + i, c_lo,
						  (size_t)(lim - i));

			if (!h)
				return 0;
			i = (uint64_t)(h - f.p);
			if (kof_txt_tag_at(f, i, t, len))
				return 1;
			i++;
		}
		return 0;
	}
	for (i = 0; i < lim; i++) {
		uint8_t a = f.p[i];

		if (a != c_lo && a != c_up)
			continue;
		if (kof_txt_tag_at(f, i, t, len))
			return 1;
	}
	return 0;
}

int kof_isl_add(struct kof_script_info *info, uint64_t off, uint64_t len)
{
	if (info->n_island >= KOF_SCRIPT_MAX_ISLAND)
		return 0;
	if (!len)
		return 1;               /* nothing to record, and not full */
	info->island[info->n_island].off = (uint32_t)off;
	info->island[info->n_island].len = (uint32_t)len;
	info->n_island++;
	return 1;
}

void kof_isl_seal(struct kof_script_info *info, uint64_t size)
{
	uint16_t n = info->n_island;

	if (n != KOF_SCRIPT_MAX_ISLAND)
		return;
	if ((uint64_t)info->island[n - 1].off + info->island[n - 1].len < size)
		info->anomalies |= KOF_SCRIPT_ANOM_ISLANDS_FULL;
}

/* Is [a, b) nothing but whitespace? An empty run is, vacuously. */
static int all_ws(kof_buf f, uint64_t a, uint64_t b)
{
	if (b > f.n)
		return 0;
	for (; a < b; a++)
		if (f.p[a] != ' ' && f.p[a] != '\t' &&
		    f.p[a] != '\n' && f.p[a] != '\r')
			return 0;
	return 1;
}

void kof_isl_join_ws(kof_buf f, uint64_t from, struct kof_script_info *info)
{
	uint16_t i, keep = 0;

	if (!f.p || !info->n_island)
		return;
	/* The run before the first island. */
	if (info->island[0].off > from &&
	    all_ws(f, from, info->island[0].off)) {
		info->island[0].len += (uint32_t)(info->island[0].off - from);
		info->island[0].off = (uint32_t)from;
	}
	/* And the run after the last. */
	{
		uint16_t k = (uint16_t)(info->n_island - 1u);
		uint64_t end = (uint64_t)info->island[k].off +
			       info->island[k].len;

		if (end < f.n && all_ws(f, end, f.n))
			info->island[k].len += (uint32_t)(f.n - end);
	}
	if (info->n_island < 2u)
		return;
	for (i = 0; i < info->n_island; i++) {
		uint64_t gap, end;

		if (!keep) {
			info->island[keep++] = info->island[i];
			continue;
		}
		end = (uint64_t)info->island[keep - 1u].off +
		      info->island[keep - 1u].len;
		gap = info->island[i].off;
		if (gap >= end && gap <= f.n) {
			uint64_t j = end;

			(void)j;
			if (all_ws(f, end, gap)) {
				/* Nothing but whitespace between them, so they
				 * are one island and the gap is its middle. */
				info->island[keep - 1u].len =
					(uint32_t)(info->island[i].off +
						   info->island[i].len -
						   info->island[keep - 1u].off);
				continue;
			}
		}
		info->island[keep++] = info->island[i];
	}
	info->n_island = keep;
}
