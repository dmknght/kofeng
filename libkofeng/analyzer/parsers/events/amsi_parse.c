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

/*
 * The entry table, which holds at most one row and usually none.
 *
 * Reached through ctx->entries, so the engine's declared-children walk opens it
 * the same way it opens a zip member or a PDF attachment - see objtree.h. There
 * is no AMSI-shaped path through the engine and there must not be one.
 */
static uint32_t amsi_entries(const struct kof_obj_ctx *ctx,
			     const struct kof_entry **out)
{
	const struct kof_amsi_view *v = ctx ? ctx->file_header : NULL;

	if (!v || !out)
		return 0;
	*out = v->ent;
	return v->n_ent;
}

/*
 * IS THE SUBMISSION AN EXECUTABLE.
 *
 * Three reads at fixed places and no search: the MZ, the offset it points at,
 * and the signature there. That is the same test the PE sniff makes, applied
 * once at the one offset where a submitted executable starts, rather than swept
 * across bytes that are a PowerShell script in twenty-eight cases out of thirty.
 *
 * The length declared is ALL THE REMAINING CONTENT and not a size computed from
 * the header. A submission is routinely shorter than the file it came from -
 * the provider hands over what it has - so a computed size would either reach
 * past the buffer or cut off an overlay that is present. What the submission
 * holds from the header on is exactly known, and it is the honest extent.
 */
static void declare_carried(struct kof_amsi_view *v, kof_buf b)
{
	uint16_t mz = 0;
	uint32_t lfanew = 0, sig = 0;

	v->n_ent = 0;
	if (v->obj_len < 0x40u)
		return;
	if (!kof_rd_u16(b, v->obj_off, 0, &mz) || mz != 0x5a4du)
		return;
	if (!kof_rd_u32(b, v->obj_off + 0x3cu, 0, &lfanew))
		return;
	if (lfanew < 0x40u || lfanew > v->obj_len - 4u)
		return;
	if (!kof_rd_u32(b, v->obj_off + lfanew, 0, &sig) || sig != 0x00004550u)
		return;   /* "PE\0\0" little endian */

	memset(&v->ent[0], 0, sizeof v->ent[0]);
	v->ent[0].off  = v->obj_off;
	v->ent[0].len  = v->obj_len;
	v->ent[0].kind = KOF_ENT_EMBEDDED;
	/*
	 * The format is DECLARED because it was checked, not guessed. The parse
	 * it names still runs and may still refuse - a truncated or hostile
	 * image comes back unidentified exactly as a failed sniff would - so
	 * saying so costs nothing and lets a host that has no PE module decline
	 * the child before it opens it.
	 */
	v->ent[0].format = KOF_FMT_PE;
	v->n_ent = 1;
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
	declare_carried(v, b);

	ctx->format       = KOF_EVT_AMSI;
	/*
	 * WHICH OF THE TWO THINGS THIS IS, so a module is not offered the other
	 * one. An image was proved by declare_carried; anything else with
	 * content is text a host was about to run, which is what a submission
	 * IS when it is not a file. See enum kof_amsi_kind.
	 */
	ctx->subtype      = v->n_ent ? (uint8_t)KOF_AMSI_IMAGE
				     : (uint8_t)(v->obj_len ? KOF_AMSI_COMMAND
							    : KOF_AMSI_UNKNOWN);
	ctx->obj_size     = b.n;
	ctx->file_header  = v;
	ctx->resolve_scan = amsi_resolve_scan;
	ctx->entries      = v->n_ent ? amsi_entries : NULL;
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
