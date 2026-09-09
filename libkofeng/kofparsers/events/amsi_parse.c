/* SPDX-License-Identifier: Apache-2.0 */
/* See amsi_parse.h for why this parser refuses to sniff. */

#include <string.h>

#include "amsi_parse.h"

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

	if (!v || !ctx || !b.p || !b.n)
		return 0;

	/*
	 * BEING TOLD IS NOT BEING RIGHT.
	 *
	 * The caller supplies the content's extent - see the header for why the
	 * engine does not read it out of the record itself - and these checks
	 * are what stop a wrong answer from resolving to ranges outside the
	 * object.
	 */
	if (v->obj_off >= b.n)
		return 0;
	if (!v->obj_len || v->obj_len > b.n - v->obj_off)
		v->obj_len = b.n - v->obj_off;

	v->size = b.n;

	ctx->format       = KOF_EVT_AMSI;
	ctx->obj_size     = b.n;
	ctx->file_header  = v;
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
