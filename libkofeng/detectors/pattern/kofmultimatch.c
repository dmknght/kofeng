/*
 * kofmultimatch.c - what a marker is to the region sweep. See kofmultimatch.h; the table that
 * finds candidates is kofpix.c.
 */

#include "kofmultimatch.h"
#include "../../databases/pack/hexprog.h"
#include "../../databases/pack/dbtables.h"

#include <string.h>

/* ---- verification --------------------------------------------------------- */

/*
 * The word rule as match_one applies it, and it has to be the same rule or the
 * two paths would disagree about one marker.
 *
 * The right boundary is the EXTENT's edge, then the object's: a match ending
 * where the region ends has no following byte, and neither has one ending at
 * the end of the object.
 */
int kof_multimatch_pat_at(const struct kof_match_ctx *m,
			  const struct kof_multimatch_pat *p,
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
			/*
			 * WITH THE PATTERN'S OPTIONS, because this answer is
			 * FINAL.
			 *
			 * What this function decides is written into the memo,
			 * and kof_match_lookup reads the memo before doing
			 * anything else - so a match reported here is never
			 * re-checked by the slower path. The literal branch
			 * below has always applied ICASE and the word rule;
			 * the hex branch called the bare walk and did not, so
			 * a hex pattern declared FULLWORD was answered "yes"
			 * here and "no" by every other door into the matcher.
			 */
			if (kof_hex_walk_flags(lim, start, p->prog, p->flags))
				return 1;
		}
		return 0;
	}

	if (p->flags & KOF_STR_ICASE) {
		for (i = 0; i < p->len; i++)
			if (kof_lower_byte(m->data.p[at + i]) != kof_lower_byte(p->b[i]))
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

/*
 * The concrete run a hex program is keyed on, and how long it is.
 *
 * Read without re-validating, the same way hex_search and gram_admits read it:
 * hex_prog_valid checked every one of these offsets when the pack was loaded,
 * and checked the anchor LAST so it could not be believed before the tables it
 * indexes were known good. A second copy of that check here would be a second
 * thing to keep in step with the format.
 */
const uint8_t *kof_multimatch_hex_anchor(const uint8_t *prog, uint32_t *len)
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
int kof_multimatch_keyable(uint8_t kind, uint32_t len, const uint8_t *bytes)
{
	if (kind == KOF_STR_HEX) {
		uint32_t alen;

		if (len < sizeof(struct kof_hex_hdr))
			return 0;
		(void)kof_multimatch_hex_anchor(bytes, &alen);
		/* Not KOF_MULTIMATCH_KEY: an anchor that long is a key with no
		 * verify behind it. See KOF_MULTIMATCH_HEX_MIN. */
		return alen >= KOF_MULTIMATCH_HEX_MIN;
	}
	return len >= KOF_MULTIMATCH_KEY;
}
