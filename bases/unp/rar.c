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
 * they are disproportionately the interesting ones: an author who adds an already
 * compressed payload to an archive gets a stored entry whether they meant to or not.
 *
 * This holds for both versions, and for a while it did not: an early return for RAR5
 * threw its stored entries away unread, from when RAR5 was recognised and not walked.
 *
 *
 * WHAT IS DECODED, AND WHAT IS STILL A GAP
 *
 * The other 77% is RAR's own compression, and it is two unrelated schemes behind one
 * signature. Both have a decoder here: RAR3's LZ with its filter set, and RAR5's,
 * which shares nothing with it. Neither is shared with any other format in this
 * engine, so each is a decoder written for exactly one container.
 *
 * What is left is named rather than guessed at, because an archive read most of the
 * way is not an archive read:
 *
 *   RAR3 PPMd     - RAR3 chooses between LZ and PPMd per block. A stream that turns
 *                   to PPM comes back short and says so.
 *   RAR 2.0       - unpack version 20, an older and incompatible LZ layout.
 *   RAR 7         - compression version 1, a larger dictionary scheme.
 *   solid entries - continue the window of the entry before them, so they cannot be
 *                   decoded alone.
 *
 * The four reasons this can give are not interchangeable:
 *
 *   ENCRYPTED   - needs a key. No version of this engine will read it.
 *   UNSUPPORTED - one of the four above. A later build could.
 *   DAMAGED     - the archive does not contain what it says it does.
 *   LIMIT       - a budget stopped it; what came out is a prefix of the archive.
 */

#include <kofmod/kofsig.h>
#include <kofmod/rar.h>

KOF_TARGET_FORMAT(KOF_FMT_RAR);

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_rar_info *r = kof_rar(ctx);
	uint32_t i, opened = 0, packed = 0;
	/*
	 * WHY an entry was not opened, one counter per reason.
	 *
	 * `packed` alone said how many entries were out of reach and nothing
	 * about what would bring them in. The four reasons lead to completely
	 * different work - a decoder that gave up mid-stream is a bug or a
	 * missing coder, an entry that is solid needs the one before it, a
	 * version this build predates needs a different layout entirely - and
	 * telling them apart from outside meant guessing.
	 */
	uint32_t n_solid = 0, n_enc = 0, n_nosize = 0, n_ver = 0, n_dec = 0;

	if (!r->valid)
		return;

	kof_debug("Rar.version", r->rar_version);
	kof_debug("Rar.entries", r->n_entries);
	kof_debug("Rar.stored", r->n_stored);

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
		/*
		 * A solid entry continues the window of the one before it, so its
		 * first back reference points at bytes a decode starting here never
		 * produced. It is refused rather than decoded into something that is
		 * right at the front and quietly wrong after.
		 */
		if (e->suspicious & KOF_RAR_ENT_SOLID) {
			packed++;
			n_solid++;
			continue;
		}

		if (e->suspicious & KOF_RAR_ENT_ENCRYPTED) {
			packed++;
			n_enc++;
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
		 * Compressed, by whichever of the two the archive's version means.
		 *
		 * They are separate decoders because RAR5 shares nothing with RAR3
		 * below the signature. Unpack version 20 - RAR 2.0, an older and
		 * incompatible LZ layout - is counted as out of reach rather than
		 * fed to a decoder that would produce something shaped like a file,
		 * and so is a RAR3 stream that switches to PPM partway: the decoder
		 * comes back short and says so rather than returning a fragment.
		 *
		 * The declared size goes with the call so the host can see the ratio
		 * before spending on it; the decoder never reads it as a fact.
		 */
		if (!e->usize) {
			packed++;
			n_nosize++;
			continue;
		}
		if (r->rar_version == KOF_RAR_V5) {
			/* Algorithm version 0 is RAR 5.0; version 1 is the larger
			 * dictionary scheme RAR 7 added, which this decoder was
			 * not written for. */
			if (e->unp_ver != 0) {
				packed++;
				n_ver++;
				kof_debug("Rar.unp_ver", e->unp_ver);
				continue;
			}
			if (kof_unpack_at(KOF_UNP_RAR5, e->data_off, e->csize,
					  e->usize) == 0) {
				packed++;
				n_dec++;
				continue;
			}
		} else if (r->rar_version == KOF_RAR_V3 && e->unp_ver == 29) {
			if (kof_unpack_at(KOF_UNP_RAR3, e->data_off, e->csize,
					  e->usize) == 0) {
				packed++;
				n_dec++;
				continue;
			}
		} else {
			packed++;
			n_ver++;
			kof_debug("Rar.unp_ver", e->unp_ver);
			continue;
		}
		if (!kof_child())
			break;
		opened++;
	}

	/*
	 * What the PARSE could not offer, as opposed to what this loop refused.
	 *
	 * This used to be an early return at the top, from when RAR5 was recognised
	 * and not walked: n_entries was zero, so returning was the same as running
	 * the loop. It stopped being the same when the RAR5 walk landed, and the
	 * cost was two answers rather than one. A RAR5 holding stored entries had
	 * them thrown away unread - free bytes, no decoder involved - and an archive
	 * with encrypted headers was reported UNSUPPORTED, which says a later build
	 * could read it, instead of ENCRYPTED, which says none ever will.
	 */
	if (r->anomalies & KOF_RAR_ANOM_UNSUPPORTED)
		packed++;

	kof_debug("Rar.opened", opened);
	kof_debug("Rar.unreachable", packed);
	/* Only when there is something to say: a clean archive should not print
	 * five zeroes, and a reason at zero is not a fact worth a line. */
	if (n_solid)
		kof_debug("Rar.skip_solid", n_solid);
	if (n_enc)
		kof_debug("Rar.skip_encrypted", n_enc);
	if (n_nosize)
		kof_debug("Rar.skip_nosize", n_nosize);
	if (n_ver)
		kof_debug("Rar.skip_version", n_ver);
	if (n_dec)
		kof_debug("Rar.skip_decoder", n_dec);

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
