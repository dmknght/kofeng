/*
 * rar.c - open what a RAR stores in the clear, and name what it does not.
 *
 * RAR is the largest container in this collection by bytes - 865 files and 18.7% of
 * everything - and until the parser existed every one of them was one opaque blob.
 * This module is the second half of closing that: the parse makes the archive
 * describable, this makes the readable part of it readable.
 *
 *
 * WHAT IS FREE, AND IT IS MORE THAN NOTHING
 *
 * A stored entry costs no budget at all - it is a WINDOW onto the parent's own
 * mapping, the same as a tar entry, because the bytes are already sitting there
 * uncompressed. Measured over this collection, 23% of RAR entries are stored, and
 * they are disproportionately the interesting ones: an author who adds a already
 * compressed payload to an archive gets a stored entry whether they meant to or not.
 *
 *
 * WHAT IS NOT, AND WHY IT IS SAID RATHER THAN GUESSED
 *
 * The other 77% is RAR's own compression, which this engine does not implement -
 * and unlike deflate or LZMA it is not shared with any other format here, so it is
 * a decoder written for exactly one container. That is a real piece of work and it
 * is not pretended away: an archive whose content could not be reached is reported
 * broken, with the reason that distinguishes a gap in this build from a gap no
 * build closes.
 *
 * The three reasons this can give are not interchangeable:
 *
 *   ENCRYPTED   - needs a key. No version of this engine will read it.
 *   UNSUPPORTED - RAR5, or RAR3 compression. A later build could.
 *   DAMAGED     - the archive does not contain what it says it does.
 */

#include <kofmod/kofsig.h>
#include <kofmod/rar.h>

KOF_TARGET_FORMAT(KOF_FMT_RAR);

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_rar_info *r = kof_rar(ctx);
	uint32_t i, opened = 0, packed = 0;

	if (!r->valid)
		return;

	kof_debug("Rar.version", r->rar_version);
	kof_debug("Rar.entries", r->n_entries);
	kof_debug("Rar.stored", r->n_stored);

	/*
	 * RAR5 first, because there is nothing to loop over: the parse recognised
	 * the format and did not walk it, so n_entries is zero and a silent return
	 * would report a 30MB archive as an object with nothing in it.
	 */
	if (r->anomalies & KOF_RAR_ANOM_UNSUPPORTED)
		KOF_UNP_BROKEN(KOF_UNP_UNSUPPORTED);

	for (i = 0; i < r->n_entries; i++) {
		const struct kof_rar_entry *e = &r->entry[i];

		if (!e->csize || !e->data_off)
			continue;                /* a directory, or an empty file */
		if (e->suspicious & KOF_RAR_ENT_PAST_EOF)
			continue;                /* content the object does not hold */
		/*
		 * An entry continued from another volume is half a file. Its bytes
		 * are here but its beginning or its end is in a file this engine was
		 * never given, so a decoder would fail on it and a window would hand
		 * over a fragment labelled as the whole.
		 */
		if (e->suspicious & KOF_RAR_ENT_SPLIT)
			continue;

		if (e->suspicious & KOF_RAR_ENT_ENCRYPTED) {
			packed++;
			continue;
		}

		/* What this entry is called, for the report. */
		kof_name_next(e->name_off, e->name_len);

		if (e->method == KOF_RAR_M_STORE) {
			/* Free: the child is a view of bytes that already exist. */
			if (!kof_child_window(e->data_off, e->csize))
				break;           /* a host limit bound: stop, do not spin */
			opened++;
			continue;
		}

		/*
		 * Compressed, and only RAR3 is decoded.
		 *
		 * RAR5 keeps a different LZ layout entirely and version 20 an older
		 * one; both are counted as out of reach rather than fed to a decoder
		 * that would produce something shaped like a file. The RAR3 decoder
		 * itself refuses a PPM block the same way, so an entry that starts LZ
		 * and switches mid-stream comes back short and says so.
		 *
		 * The declared size goes with the call so the host can see the ratio
		 * before spending on it; the decoder never reads it as a fact.
		 */
		if (r->rar_version != KOF_RAR_V3 || e->unp_ver != 29 || !e->usize) {
			packed++;
			continue;
		}
		if (kof_unpack_at(KOF_UNP_RAR3, e->data_off, e->csize,
				  e->usize) == 0) {
			packed++;
			continue;
		}
		if (!kof_child())
			break;
		opened++;
	}

	kof_debug("Rar.opened", opened);
	kof_debug("Rar.unreachable", packed);

	/*
	 * The order below is the order of severity, and only the first reason a
	 * caller sees is the one it acts on - so the answer that never changes with
	 * a better build comes first.
	 */
	if (r->anomalies & KOF_RAR_ANOM_ENCRYPTED)
		kof_unp_broken(KOF_UNP_ENCRYPTED);
	if (packed)
		kof_unp_broken(KOF_UNP_UNSUPPORTED);
	if (r->anomalies & (KOF_RAR_ANOM_TRUNCATED | KOF_RAR_ANOM_BAD_BLOCK))
		kof_unp_broken(KOF_UNP_DAMAGED);
	if (r->anomalies & (KOF_RAR_ANOM_ENTRIES_FULL | KOF_RAR_ANOM_EXTENTS_FULL))
		kof_unp_broken(KOF_UNP_LIMIT);
}
