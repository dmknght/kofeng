/*
 * rtf.c - turn an RTF's embedded objects back into objects.
 *
 * The whole of the work is undoing a hex encoding, and the whole of the value is
 * what is on the other side of it: an \objdata blob is usually a compound file, so
 * decoding it hands the document straight to the DOCOLE path - directory, streams,
 * and VBA macros included. Nothing downstream had to be written for this.
 *
 * One child per object rather than one for the document, because the objects are
 * separate things: two embedded files in one RTF are two files, and a finding
 * should be able to say which.
 */

#include <kofmod/kofsig.h>
#include <kofmod/rtf.h>

KOF_TARGET_FORMAT(KOF_FMT_RTF);

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_rtf_info *r = kof_rtf(ctx);
	uint32_t i, opened = 0;

	if (!r->valid)
		return;

	kof_debug("Rtf.objects", r->n_objects);
	kof_debug("Rtf.depth", r->max_depth);

	for (i = 0; i < r->n_objects; i++) {
		const struct kof_rtf_object *o = &r->obj[i];

		if (!o->data_len || !o->hex_bytes)
			continue;

		/* The object's class, when the document named one, so a finding
		 * reads as the thing rather than as an index. */
		if (o->class_len)
			kof_name_next(o->class_off, o->class_len);

		if (kof_unpack_at(KOF_UNP_HEXTEXT, o->data_off, o->data_len,
				  o->hex_bytes) == 0)
			continue;
		if (!kof_child())
			KOF_UNP_BROKEN(KOF_UNP_LIMIT);
		opened++;
	}

	kof_debug("Rtf.opened", opened);

	/*
	 * A document whose braces do not balance, or whose hex is not hex, has
	 * been read as far as it made sense and no further. Said rather than
	 * passed over: the recovery a word processor performs is the thing being
	 * exploited, so a document that needed recovering is worth flagging even
	 * when what came out looked fine.
	 */
	if (r->anomalies & (KOF_RTF_ANOM_UNBALANCED | KOF_RTF_ANOM_BAD_HEX |
			    KOF_RTF_ANOM_TRUNCATED))
		kof_unp_broken(KOF_UNP_DAMAGED);
	if (r->anomalies & (KOF_RTF_ANOM_OBJECTS_FULL | KOF_RTF_ANOM_EXTENTS_FULL |
			    KOF_RTF_ANOM_DEPTH))
		kof_unp_broken(KOF_UNP_LIMIT);
}
