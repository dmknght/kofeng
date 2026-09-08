/* SPDX-License-Identifier: Apache-2.0 */
/* See amsi_parse.h for why this parser refuses to sniff. */

#include <string.h>

#include "amsi_parse.h"
#include "../../kofevt/kofevt.h"

/*
 * The target value and the verb are ONE NUMBER, and these are what keep them so.
 *
 * A mapping table would work and would be a second place to edit; equal values
 * make kof_evt_target_of a check rather than a translation. The asserts turn
 * "they happen to match" into "they cannot stop matching" - give a target a
 * number that is not its verb, or give one to a verb below the boundary, and
 * the build stops here instead of routing records to the wrong rules.
 */
_Static_assert((int)KOF_EVT_AMSI == (int)KOF_EVT_AMSI_SCAN,
	       "an event target's value must be its verb");
_Static_assert(KOF_EVT_AMSI >= KOF_TARGET_FIRST_EVENT &&
	       KOF_EVT_AMSI < KOF_TARGET_BITS,
	       "an event target must sit above the file formats and inside the "
	       "32-bit target mask");

uint8_t kof_evt_target_of(uint16_t verb)
{
	switch (verb) {
	case KOF_EVT_AMSI_SCAN:
		return KOF_EVT_AMSI;
	/*
	 * Everything else, INCLUDING the verbs whose rules are obviously worth
	 * writing one day. A network receive wants a rule that compares an
	 * address to a list, which is not a search through bytes and so is not
	 * this target's shape - it gets its own value and its own regions when
	 * it is built, not a borrowed one now.
	 */
	default:
		return KOF_FMT_UNKNOWN;
	}
}

const uint32_t kof_amsi_regions[2] = {
	KOF_SCAN_AMSI_META,
	KOF_SCAN_AMSI_OBJ
};

int kof_amsi_sniff(kof_buf b)
{
	/*
	 * Never. A record has no magic, so any test here would be a guess about
	 * whose bytes these are - see the header. Reached only through
	 * kof_parser_of(KOF_FMT_AMSI), by a caller that already knows.
	 */
	(void)b;
	return 0;
}

/*
 * The two regions, as ranges over the object.
 *
 * They PARTITION it, which is the contract kofsig.h asks a format to keep: OBJ
 * is the submitted content and META is everything else - the head in front of
 * it and whatever arena follows it. So naming both scans every byte once, and
 * naming either leaves nothing of the other reachable by accident.
 *
 * META is two ranges, not one. The content sits in the middle of the object,
 * so "everything else" is what is before it and what is after it, and merging
 * them into one bounding range would put the content back inside META - which
 * is exactly the distinction the two regions exist to make.
 */
static uint32_t amsi_resolve_scan(const struct kof_obj_ctx *ctx,
				  uint32_t scan_mask, struct kof_range *out,
				  uint32_t cap)
{
	const struct kof_amsi_view *v;
	uint32_t n = 0;

	if (!ctx || !out || !cap)
		return 0;
	v = ctx->file_header;
	if (!v)
		return 0;

	if (scan_mask & KOF_SCAN_AMSI_META) {
		if (v->obj_off && n < cap) {
			out[n].off = 0;
			out[n].len = v->obj_off;
			n++;
		}
		if (v->obj_off + v->obj_len < v->size && n < cap) {
			out[n].off = v->obj_off + v->obj_len;
			out[n].len = v->size - (v->obj_off + v->obj_len);
			n++;
		}
	}
	if ((scan_mask & KOF_SCAN_AMSI_OBJ) && v->obj_len && n < cap) {
		out[n].off = v->obj_off;
		out[n].len = v->obj_len;
		n++;
	}
	return n;
}

int kof_amsi_parse(kof_buf b, void *view, struct kof_obj_ctx *ctx)
{
	struct kof_amsi_view *v = view;
	struct kof_evt e;
	uint64_t start, len;

	if (!v || !ctx || !b.p || b.n < KOF_EVT_HEAD)
		return 0;

	/*
	 * Copied out rather than cast over.
	 *
	 * The buffer may be a mapping, and it may have been written by a build
	 * whose record was a different size; a bounded copy into this build's
	 * struct is the only read of it that is defined. It costs 512 bytes
	 * once per object.
	 */
	memset(&e, 0, sizeof e);
	memcpy(&e, b.p, b.n < sizeof e ? (size_t)b.n : sizeof e);

	/*
	 * BEING TOLD IS NOT BEING RIGHT. A caller declares the format; these
	 * checks are what stop a wrong declaration from resolving to ranges
	 * outside the object.
	 */
	if (e.verb != KOF_EVT_AMSI_SCAN)
		return 0;
	if (e.off_object == KOF_TEXT_NONE || e.off_object >= sizeof e.text)
		return 0;

	start = (uint64_t)KOF_EVT_HEAD + e.off_object;
	if (start >= b.n)
		return 0;

	/*
	 * HOW LONG THE CONTENT IS, and why the buffer has the last word.
	 *
	 * content_len is a uint16, so it cannot describe a submission past 64K
	 * - and a reassembled event routinely is one, because that is the whole
	 * point of the continuation records. When the caller has joined the
	 * chunks it presents head plus the WHOLE content and the content is
	 * everything to the end of the buffer, which is a length no field in
	 * the record can hold.
	 *
	 * So: the field when it fits inside the buffer, the rest of the buffer
	 * when it does not. Both readings agree for an unjoined record, and the
	 * disagreement for a joined one is resolved towards the bytes that are
	 * actually there rather than towards a number that cannot describe
	 * them.
	 */
	len = e.content_len;
	if (len == 0 || start + len > b.n)
		len = b.n - start;

	v->obj_off = start;
	v->obj_len = len;
	v->size    = b.n;

	ctx->format    = KOF_EVT_AMSI;
	ctx->obj_size  = b.n;
	ctx->file_header = v;
	ctx->resolve_scan = amsi_resolve_scan;
	return 1;
}

const char *kof_amsi_region_name(uint32_t bit)
{
	switch (bit) {
	case KOF_SCAN_AMSI_META: return "METADATA";
	case KOF_SCAN_AMSI_OBJ:  return "OBJDATA";
	default:                 return "?";
	}
}

const char *kof_amsi_anomaly_name(unsigned index)
{
	(void)index;
	return "?";
}

uint64_t kof_amsi_anomalies(const void *view)
{
	(void)view;
	return 0;
}
