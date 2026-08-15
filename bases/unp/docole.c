/*
 * docole.c - join a document's streams back together.
 *
 * This is an unpacker that decompresses nothing. What it undoes is not compression
 * but SCATTERING: a compound file stores a stream as a chain of sectors in whatever
 * order the allocator left them, so the parse can say exactly which bytes belong to
 * the macros and still not be able to match a pattern lying across the join between
 * two of them. Putting the pieces next to each other is the whole job.
 *
 *
 * WHY THIS IS NOT DONE IN THE PARSE
 *
 * Because it costs memory and the parse must not. Naming the bytes is free - it is
 * arithmetic over the allocation table - and a scan that never asks for a document's
 * macros should never pay to have them assembled. So the parse names them, detectors
 * search them in place where a pattern fits inside one run, and this runs afterwards
 * only if the object got that far.
 *
 * That ordering is the host's and this module inherits it: unpackers run after
 * detectors, and not at all once something has already been found. A document
 * already named by a pattern in its directory does not get its streams joined.
 *
 *
 * WHAT IS GATHERED, AND WHAT IS NOT
 *
 * Macros and the document body, each into its own child, and nothing else.
 *
 *   - MACROS first and always when present, because it is small and it is where
 *     nearly everything malicious in a document lives. Measured over 64 documents
 *     carrying VBA the median is 14.1KB - joining that is not a cost worth
 *     reasoning about.
 *
 *   - CONTENT_DATA second, and capped, because it is the document body: measured at
 *     55.5% of the bytes of an OLE document with the largest single instance at
 *     6MB. Worth searching joined up, not worth an unbounded copy.
 *
 *   - RESOURCES is deliberately absent. It is 37.8% of the bytes and it is pictures
 *     and embedded object pools - payload the document carries rather than text it
 *     authored, and a pattern almost never wants it joined. It is still scanned in
 *     place as a region, so nothing is invisible; it is only not copied.
 *
 *   - METADATA is absent for the opposite reason: property streams are a few
 *     kilobytes and are almost never fragmented, so the in place region already
 *     answers everything a joined copy would.
 *
 * Both children are the CONTENT of a document with no structure around them, so
 * nothing will identify them as anything and no format module will run against
 * them. That is correct and is the point: what runs against them are the modules
 * that target text and scripts, which is what a VBA module and a document body are.
 */

#include <kofmod/kofsig.h>
#include <kofmod/docole.h>

KOF_TARGET_FORMAT(KOF_FMT_DOCOLE);

/*
 * What one gather may produce.
 *
 * The host's ceiling already bounds this and would be enough for safety. This is
 * the tighter, format-aware limit on top of it, and its job is different: it says
 * what an honest document costs, so that a file built to be expensive is cut at a
 * size that still leaves room for the next object rather than consuming the tree's
 * whole budget on one stream.
 *
 * 4MB against a measured worst case of 6MB for a body and 25.4KB for macros. The
 * body cap therefore binds on real files occasionally and the macro cap never does,
 * which is the right way round: a truncated body is a partial search of prose, a
 * truncated macro would be a partial search of code.
 */
#define GATHER_CAP (4u * 1024u * 1024u)

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_docole_info *o = kof_docole(ctx);
	uint64_t got, raw;
	uint32_t i, r, opened = 0;

	if (!o->valid)
		return;

	/*
	 * What the directory declared, before anything is joined.
	 *
	 * These are free - they come out of the parse - and they are the numbers
	 * that explain whatever happens next, so they are reported before the
	 * branches below can return.
	 */
	kof_debug("DocOLE.streams", o->stream_count);
	kof_debug("DocOLE.macro_bytes", o->macro_bytes);

	/*
	 * An encrypted document: nothing here can read it, and saying so is the
	 * whole value of noticing.
	 *
	 * Returns rather than carrying on, because every byte of the content is
	 * ciphertext - gathering it would spend budget to produce a child that no
	 * pattern can match and that identifies as nothing.
	 *
	 * ENCRYPTED and not DAMAGED, because the file is exactly what it claims to
	 * be; and not UNSUPPORTED, because what is missing is a key rather than a
	 * decoder this build could later grow.
	 */
	if (o->encrypted)
		KOF_UNP_BROKEN(KOF_UNP_ENCRYPTED);

	/*
	 * Structure that lost bytes, said BEFORE anything is gathered.
	 *
	 * These are the anomalies that mean a stream's bytes are not all there: a
	 * chain that ran off the end of the file, one that loops, a directory that
	 * points back at itself. Reported first because the first reason recorded is
	 * the one kept, and damage is what EXPLAINS a short gather - recording the
	 * shortfall first would name the symptom and hide the cause.
	 */
	if (o->anomalies & (KOF_DOCOLE_ANOM_TRUNCATED |
			    KOF_DOCOLE_ANOM_STREAM_PAST_EOF |
			    KOF_DOCOLE_ANOM_FAT_CYCLE |
			    KOF_DOCOLE_ANOM_DIR_CYCLE))
		kof_unp_broken(KOF_UNP_DAMAGED);

	/*
	 * Held against what the region COVERS, never against what the directory
	 * declared. A file whose streams claim more than they own would otherwise
	 * report a limit that was never reached - the bytes are missing from the
	 * file, not from the gather, and the anomalies above already said so.
	 */
	/*
	 * The macros, one stream at a time and decompressed.
	 *
	 * One child per stream rather than one for all of them, which is what this
	 * did before and what the other containers never did: a tar entry, a zip
	 * entry and a RAR entry each become their own object with their own name,
	 * and a VBA module is the same kind of thing. Gathering the region instead
	 * produced one object holding every module glued together, with no
	 * boundary between them and no name on any of it - so a finding could not
	 * say which module it was in, and the compressed containers could only be
	 * found by guessing where each began.
	 *
	 * What the decompression buys is narrower than it sounds and is worth
	 * stating where somebody will read it: measured over 50 documents,
	 * identifiers of 8 characters and up are ALREADY findable in the compressed
	 * bytes 88.7% of the time. What it adds is the 42% of 20-character tokens
	 * that are not, the ability to match a SEQUENCE rather than fragments - and
	 * mainly that the 88.7% is an accident of where a word falls in the
	 * compression window, so a signature relying on it works on one sample and
	 * silently misses its variant.
	 */
	for (i = 0; i < o->n_entries; i++) {
		const struct kof_docole_entry *e = &o->ent[i];

		if (e->cls != KOF_DOCOLE_CLS_MACROS || !e->n_runs)
			continue;

		if (e->flags & KOF_DOCOLE_ENT_OVBA) {
			kof_name_next(e->name_off, e->name_len);
			if (kof_unpack_entry(KOF_UNP_OVBA, i, 0)) {
				if (!kof_child())
					break;   /* the host will take no more */
				opened++;
				continue;
			}
		}

		/*
		 * Not a compressed container, or not one this could read.
		 *
		 * A VBA storage holds more than module source - the project
		 * record, the compiled p-code, the reference list - and those are
		 * not OVBA streams. They are still worth scanning as they lie, so
		 * they go out as a window rather than being dropped: it costs no
		 * budget and it is the only way anything sees them.
		 */
		raw = 0;
		for (r = 0; r < e->n_runs; r++)
			raw += o->ent_run[e->first_run + r].len;
		if (raw && e->n_runs == 1u) {
			kof_name_next(e->name_off, e->name_len);
			if (!kof_child_window(o->ent_run[e->first_run].off, raw))
				break;
			opened++;
		}
	}

	kof_debug("DocOLE.macro_children", opened);
	if (o->anomalies & KOF_DOCOLE_ANOM_ENTRIES_FULL)
		kof_unp_broken(KOF_UNP_LIMIT);

	if (o->region_bytes[KOF_DOCOLE_CLS_DATA]) {
		got = kof_gather_max(KOF_SCAN_DOCOLE_CONTENT_DATA, GATHER_CAP);
		if (got)
			kof_child();
		if (got < o->region_bytes[KOF_DOCOLE_CLS_DATA])
			kof_unp_broken(KOF_UNP_LIMIT);
	}
}
