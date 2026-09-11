/*
 * pdf.c - yield a PDF's streams as objects of their own.
 *
 * THE GAP THIS CLOSES. The parser has always described a PDF completely - the
 * objects, their filters, and a STREAM_PACKED region whose whole meaning is
 * "searching this raw finds nothing". Nothing made it findable. A dropper that
 * carries its payload in a FlateDecode stream - which is every PDF generator's
 * default and therefore what a builder produces without trying - was parsed,
 * partitioned, scanned, and reported clean, because the bytes a signature would
 * have matched were compressed and no module decompressed them.
 *
 * A CONTAINER, not a packer. A PDF carries parts that were separately authored:
 * fonts, images, embedded files, and the odd executable. It hid no program of
 * its own, so depth through it is a directory tree rather than a layer of
 * packing - see KOF_UNPACK_KIND in kofsig.h for why that distinction feeds a
 * score and must not be guessed.
 *
 *
 * WHY THE FILTER IS ATTEMPTED RATHER THAN DECIDED
 *
 * `filters` is a BITMASK of the whole chain, so the ORDER is not in it. A stream
 * declaring [/ASCII85Decode /FlateDecode] has the Flate bit set and its bytes on
 * disk are ASCII85, not DEFLATE. Reconstructing the order would mean re-reading
 * the dictionary this module was handed a summary of, and being wrong about it
 * quietly.
 *
 * So the chain is not reasoned about: where the Flate bit is set the stream is
 * handed to the DEFLATE decoder, and a stream that was not DEFLATE produces zero
 * bytes and is skipped. A wrong guess costs one failed decode that the host
 * already bounds - and the guess is right for the ordinary case, which is a
 * single /FlateDecode and nothing else.
 *
 * The reverse case needs no guess at all: [/FlateDecode /DCTDecode] decodes to
 * JPEG data, which is exactly what should be scanned, because whatever a
 * dropper hid behind a picture is in there and not in the compressed form.
 *
 * The framing is not this module's business either. /FlateDecode is zlib in
 * most documents and raw DEFLATE in a few, and KOF_UNP_ZLIB answers both -
 * checked in the host, where the two bytes belong, because nothing about RFC
 * 1950 is peculiar to PDF.
 *
 *
 * PLAIN STREAMS GET A CHILD TOO, AND IT COSTS NOTHING
 *
 * An unfiltered stream is already inside region STREAM_PLAIN, so a rule can
 * match its bytes without any of this. What a rule cannot do is IDENTIFY it: an
 * embedded EXE sitting unfiltered in a PDF is a PE, and only an object gets
 * parsed as one, given its own regions, and unpacked in turn.
 *
 * kof_child_window costs no copy and no byte budget - the child is the parent's
 * mapping seen at a different offset - so the only thing it spends is a child,
 * and the host bounds those. The same reasoning overlay.c gives for a PE's
 * overlay applies here to every stream that needs no decoding.
 *
 *
 * WHAT IS REPORTED WHEN A STREAM CANNOT BE OPENED
 *
 * Recorded and carried on, never returned on: one stream this build cannot
 * decode says nothing about the next, and a PDF's payload is rarely in the only
 * stream it has. That is what the lower-case kof_unp_broken is for.
 *
 * Encryption outranks an unsupported coding when both are true, for the reason
 * zip.c gives: a coding this build lacks is a gap a later build closes, and
 * encryption is not. It is also reported BEFORE the walk rather than after it,
 * because the host keeps the first reason recorded and a locked document's
 * failed decodes would otherwise get there first - see the note at the call.
 */
#include <kofmod/kofsig.h>
#include <kofmod/pdf.h>

KOF_TARGET_FORMAT(KOF_FMT_PDF);
KOF_UNPACK_KIND(KOF_UNP_CONTAINER);

#define PDF_F_UNDOABLE   (KOF_PDF_F_FLATE)

/*
 * A CODING THAT HIDES BYTES SOMEBODY MIGHT HAVE PUT THERE.
 *
 * These are the filters worth telling a reader about: the stream holds data
 * this build cannot read, and a payload could be in it. LZW is compression;
 * ASCIIHex, ASCII85 and RunLength are trivial encodings that nothing here
 * undoes yet; OTHER is a filter name the parser did not recognise, which is
 * the strongest case of all - an unknown coding is unknown content.
 *
 * CRYPT is deliberately absent: a stream behind /Crypt is encrypted content,
 * and encryption has its own reason that reads correctly whatever noticed it.
 */
#define PDF_F_HIDING     (KOF_PDF_F_LZW | KOF_PDF_F_ASCIIHEX |             \
			  KOF_PDF_F_ASCII85 | KOF_PDF_F_RUNLEN |           \
			  KOF_PDF_F_OTHER)

/*
 * IMAGE CODINGS, COUNTED AND NOT REPORTED.
 *
 * A build that grew a JPEG decoder would be decoding pictures rather than
 * finding malware, so these are not going to be supported and saying
 * "unsupported by this build" about them every time is not information.
 *
 * It is also actively wrong. `broken` means the engine could not finish and
 * what the object held was not examined - it is what turns a scan's exit
 * status to 2 - and a document containing a photograph has been examined as
 * fully as this engine ever intends to examine it.
 *
 * Measured before deciding: over 14147 files, adding this module reported five
 * PDFs as "Unsupported by this build", and the only opaque filter in any of
 * them was /DCTDecode - four of the five opened every other stream they had
 * (9 of 10, 107 of 109). Reporting those would have meant a broken count that
 * fires on ordinary documents, which is a broken count nobody reads.
 */
#define PDF_F_IMAGE      (KOF_PDF_F_DCT | KOF_PDF_F_CCITT |                \
			  KOF_PDF_F_JBIG2 | KOF_PDF_F_JPX)

KOF_DEFINE_UNPACK
{
	const struct kof_pdf_info *p = kof_pdf(ctx);
	uint32_t i, opened = 0, windowed = 0, unsupported = 0, failed = 0;
	uint32_t carried = 0, in_region = 0, images = 0, unwanted = 0;
	/* Where the entry walk got to - see the note beside kof_name_next. */
	uint32_t ent = 0;
	int encrypted;

	if (!p->valid || !p->n_objects)
		return;

	/* Read from the trailer, not from a stream, so it is known before the
	 * walk - which is what makes the ordering below possible. */
	encrypted = (p->anomalies & KOF_PDF_ANOM_ENCRYPTED) != 0;

	/*
	 * REPORTED BEFORE THE WALK, NOT AFTER IT, and that ordering is the whole
	 * point of these four lines.
	 *
	 * The host keeps the FIRST reason recorded. An encrypted document's
	 * streams do not decode - they are ciphertext - so every attempt below
	 * records a failure of its own, and by the time a report at the end of
	 * this function ran, the reason the reader sees would already have been
	 * set by the first stream that failed.
	 *
	 * Measured: info.pdf carries /Encrypt, 70 of its 85 streams fail to
	 * decode, and reporting at the end came back "Damaged object" - which
	 * says the file is malformed when the truth is that it is locked. Those
	 * are different answers to give somebody, and only one of them is right.
	 *
	 * The walk still runs afterwards. /Encrypt does not cover every stream in
	 * every document - the 15 that did decode here are real objects - and a
	 * stream that decodes is worth scanning whatever the trailer said.
	 */
	if (encrypted)
		kof_unp_broken(KOF_UNP_ENCRYPTED);

	kof_debug("Pdf.objects", p->n_objects);
	kof_debug("Pdf.streams", p->n_streams);
	kof_debug("Pdf.encrypted", (uint32_t)encrypted);

	for (i = 0; i < p->n_objects; i++) {
		const struct kof_pdf_object *o = &p->object[i];

		if (!(o->flags & KOF_PDF_OBJ_STREAM) || !o->stream_len)
			continue;

		/*
		 * AND NOTHING IS OPENED THAT NOTHING WOULD LOOK AT.
		 *
		 * THE DATABASE DECIDES THIS, NOT THIS MODULE. kof_fmt_wanted
		 * asks the host whether any loaded rule targets the format
		 * this child would be declared as - the same gate that decides
		 * who is offered the child once it exists, asked before the
		 * inflate rather than after it. A stream whose decoded form no
		 * rule can be offered is a stream this module would decompress
		 * in order to hand it to nobody.
		 *
		 * WHAT IT REPLACED, and this is the reason it is worth having:
		 * the test below used to be `o->cat == KOF_PDF_CAT_IMAGE`,
		 * written here, with the measurements that justified it in the
		 * comment. Two things were wrong with that. It could not be
		 * turned back on - a rule written about malicious image codecs
		 * would have had no way to reach the bytes, because the skip
		 * lived in a module nobody editing signatures would think to
		 * look at. And it could not be turned off for ONE document -
		 * the case that matters, where the object table has just
		 * matched /Launch and the pictures are suddenly worth opening.
		 * Both are answers the host has and a module does not.
		 *
		 * The category is still the parse's, from the object's own
		 * dictionary - see enum kof_pdf_cat - and the mapping from it
		 * to a format is shared with the parse rather than written
		 * twice; see kof_pdf_entry_format.
		 *
		 * KOF_FMT_UNKNOWN is always wanted, so every stream the
		 * dictionary said nothing about is still opened. This skips
		 * what a document DECLARED to be pixels or a typeface, and
		 * nothing else.
		 */
		if (!kof_fmt_wanted(kof_pdf_entry_format(o->cat))) {
			unwanted++;
			continue;
		}

		/*
		 * PIXELS ARE NOT OPENED, WHATEVER THEY ARE CODED WITH.
		 *
		 * This module already declined the image CODINGS - DCT, JPX,
		 * CCITT, JBIG2 - and the note above says why: a build that grew
		 * a JPEG decoder would be decoding pictures rather than finding
		 * malware. That was never a judgement though, it was a
		 * capability: those codings could not be undone here anyway.
		 *
		 * A Flate coded image could be, and was, and it is the same
		 * picture at the end of it. Measured on one 1.66MB document: 15
		 * of its 46 decodable streams were images, 950KB of the 1.26MB
		 * fed to the decoder, and most of the 23.7MB that came out - a
		 * fourteenfold expansion whose entire product is raw samples.
		 * Every one of them became an object nothing could identify, so
		 * a reader opening that file got fifteen rows of "Raw" between
		 * the rows that meant something, and a scan spent its budget
		 * decompressing them to search bytes that answer nothing.
		 *
		 * WHAT THIS GIVES UP, stated rather than glossed: a payload
		 * stored in a stream that declares /Subtype /Image and deflates
		 * is no longer decompressed, so a rule cannot match its decoded
		 * form. What remains is that the bytes are still in the file and
		 * still in a region - KOF_SCAN_PDF_RESOURCE_IMAGE names exactly
		 * them - so a rule that wants to look at compressed pixel data
		 * can, and the geometry a real image declares is in the view for
		 * a heuristic that wants to ask whether the size makes sense.
		 *
		 * THE TEST THIS PARAGRAPH DESCRIBED IS GONE, and the paragraph
		 * is kept because the measurements in it are why the answer
		 * above comes out the way it does on an ordinary document. A
		 * declared image now reaches kof_fmt_wanted as KOF_FMT_IMAGE,
		 * which no shipped rule targets, so it is skipped - by the
		 * database rather than by this line. What the codings below
		 * still decline is a capability and not a policy: DCT, JPX,
		 * CCITT and JBIG2 cannot be undone here at all.
		 */

		/*
		 * AN ATTACHMENT IS A FILE, NOT A STREAM THIS MODULE DECODES.
		 *
		 * The division this module lives on: a decompressor answers
		 * "what were these bytes before they were coded", and there is
		 * nothing to answer for an /EmbeddedFile stored with no filter -
		 * the bytes are already the file. Offering it anyway produced it
		 * TWICE, because the host opens declared carried files from the
		 * entry table as the last step of processing an object, and does
		 * it generically for every format rather than once per module.
		 * Measured on a document carrying one PE: two identical 729600
		 * byte children, each parsed and scanned in full.
		 *
		 * A COMPRESSED attachment is different and is NOT skipped here:
		 * undoing its filter is exactly this module's job, and what the
		 * host would window is the coded form. The category test is
		 * therefore paired with the filter test below rather than
		 * replacing it.
		 */
		if (o->cat == KOF_PDF_CAT_EMBEDDED && !o->filters) {
			carried++;
			continue;
		}

		/*
		 * A STORED METADATA STREAM IS ALREADY IN A REGION, BYTE FOR
		 * BYTE, SO A CHILD OF IT IS THE SAME SEARCH TWICE.
		 *
		 * Measured: the metadata region and the metadata child dumped
		 * to disk and compared - not one byte different. Unfiltered
		 * means the child is a WINDOW, so it is not a copy of those
		 * bytes, it IS those bytes seen through another offset. A rule
		 * scoped to the metadata region already reaches them; making a
		 * child adds an object, a parse, a full module pass and a row
		 * in every listing, and finds exactly what the region pass
		 * finds.
		 *
		 * ONLY WHEN STORED. A compressed metadata stream is a different
		 * case entirely - the region holds the CODED bytes, so nothing
		 * has seen the XMP at all until this module inflates it, and
		 * that child is the only way those bytes are ever searched.
		 */
		if (o->cat == KOF_PDF_CAT_METADATA && !o->filters) {
			in_region++;
			continue;
		}

		/*
		 * WHAT THIS CHILD IS, SAID BEFORE IT IS HANDED OVER.
		 *
		 * Every other container module in this tree names its children
		 * - zip from an entry name, tar from a header, docole from a
		 * directory entry - and this one did not, so a PDF's streams
		 * arrived at a reader as "//1", "//2", with nothing to say
		 * which of them was a page's drawing operators and which was
		 * the object stream holding the page tree. A category is the
		 * one thing a reader needs first and the only thing that was
		 * missing.
		 *
		 * The parse settled it and recorded WHERE the document says so
		 * - see kof_pdf_object.cat_off - so this is the range the file
		 * already contains and not a string invented here. A module has
		 * nothing to build a string in anyway.
		 *
		 * A stream that no dictionary described has no name in the file
		 * to give, and passes an empty range - the child is still
		 * produced, it just carries the index it always did.
		 *
		 * UNCONDITIONAL, AND THE GUARD THAT WAS HERE WAS THE BUG.
		 *
		 * kof_name_next names the NEXT child, and the host clears the
		 * pending name on every call before it looks at the range - so
		 * an empty one is how a caller says "no name". Written as
		 * `if (o->cat_len) kof_name_next(...)`, an object with no
		 * category never cleared, and the name left pending by an
		 * earlier object attached to ITS child instead. Two ways to
		 * arrive there and both happen in an ordinary document: an
		 * image coding this build does not undo is counted and emits
		 * nothing, and a decode that came back empty emits nothing
		 * either. Both had set a name.
		 *
		 * What that looked like: a page's content stream reported as
		 * "Image" because a JPEG two objects earlier had claimed the
		 * name and never spent it, and every row after it off by one.
		 * Measured on one document, 4 of 12 rows were wrong - and every
		 * one of them looked plausible, which is why the count of
		 * categories had to be compared against the names to see it.
		 */
		/*
		 * THE ENTRY'S NAME, NOT THE OBJECT'S /Type.
		 *
		 * cat_off is this object's own /Type or /Subtype, and for a
		 * stream that is usually nothing: a /FontFile carries no type
		 * of its own. The PARSE already worked out something better and
		 * put it on the entry - a font's typeface from the descriptor
		 * that references it, a script's trigger from the key that
		 * reached it - and reading it here is what puts that on the
		 * child rather than leaving it on a row.
		 *
		 * IT MATTERS BECAUSE THE ROW IT WAS ON IS GONE. A host that
		 * shows one row per stream drops the entry row when the
		 * content is present - two rows for one thing, and the first of
		 * them opening onto coded bytes - so a name that lives only on
		 * the entry is a name nobody sees. Measured: five font streams
		 * whose typefaces the parse had read came out labelled "FONT".
		 *
		 * A CURSOR AND NOT A SEARCH. The entry table is a projection of
		 * the object table and both are walked in the same order, so
		 * the row for object `i` is at or after where the last one was.
		 * Searching from the start for each object would be a thousand
		 * comparisons per stream on a document that has a thousand.
		 */
		while (ent < p->n_entries && p->entry[ent].index < i)
			ent++;
		if (ent < p->n_entries && p->entry[ent].index == i &&
		    p->entry[ent].name_len)
			kof_name_next(p->entry[ent].name_off,
				      p->entry[ent].name_len);
		else
			kof_name_next(o->cat_off, o->cat_len);
		/*
		 * AND WHAT IT IS, from the one mapping both this module and the
		 * parse read - see kof_pdf_entry_format in kofmod/pdf.h.
		 *
		 * Beside the name and for the same reason: a child that arrives
		 * unnamed is offered only to the modules that target unknown,
		 * and measured that was every rule refused at the target test
		 * and none run. A page content stream IS text and a /JS stream
		 * IS script; saying so is what makes producing them worth the
		 * inflation.
		 *
		 * Unconditional, like kof_name_next above and for the identical
		 * reason: the call CLEARS a previous claim, so skipping it on a
		 * category with nothing to say would leave the last one
		 * standing and the next child would wear it.
		 */
		kof_child_format(kof_pdf_entry_format(o->cat));
		/*
		 * And what it is for. This is what stops a column of identical
		 * unnamed rows: a page stream and a font program are not called
		 * anything in a PDF, so name_next above has nothing to point
		 * at, and 12 of 14 recovered objects arrived blank.
		 */
		kof_child_kind(kof_pdf_entry_kind(o->cat));
		/*
		 * And which entry this is the content of. The entry table is a
		 * projection of the object table, and kof_entry.index holds the
		 * OBJECT index - which is `i` here, so the two agree by
		 * construction rather than by a lookup.
		 */
		kof_child_entry(i);

		/*
		 * No filter at all: the bytes are already what they are, so the
		 * child is a window and the decoder is not involved.
		 */
		if (!o->filters) {
			if (!kof_child_window(o->stream_off, o->stream_len))
				break;
			windowed++;
			continue;
		}

		/*
		 * THE WHOLE CHAIN, IN ORDER, AND THE HOST RUNS IT.
		 *
		 * o->filters is a BITMASK - it cannot carry order - and that is
		 * the bug this replaces: handed the Flate bit for
		 * /Filter [/ASCII85Decode /FlateDecode], the decoder inflated
		 * ASCII85 text, failed, and a clean document was reported as
		 * one the engine could not finish. The entry table has the
		 * chain in the order the file wrote it, and kof_unpack_chain
		 * runs it - which this module could not do itself, because a
		 * chain needs a buffer between its steps and a module has no
		 * writable memory.
		 *
		 * Asked FIRST, so the single-filter case goes the same way as
		 * the chain: one path, exercised by every coded stream, rather
		 * than a common path and a rare one that only malformed input
		 * reaches. The index is the object's own, which is what
		 * kof_entry.index holds.
		 *
		 * A chain the host refuses reports through it - UNSUPPORTED for
		 * a coding this build lacks, DAMAGED for data that is not what
		 * it claims - so nothing here has to decide which.
		 */
		if (o->filters) {
			if (kof_unpack_chain(i)) {
				if (!kof_child())
					break;
				opened++;
				continue;
			}
			failed++;
			continue;
		}

		if (o->filters & PDF_F_UNDOABLE) {
			/*
			 * /FlateDecode is zlib in most documents and raw
			 * DEFLATE in a few, and this module does not have to
			 * know which: kof_unpack_zlib checks the RFC 1950
			 * header and decodes from the first byte when there is
			 * none. The framing lives in the host because it is
			 * standard and shared - see KOF_UNP_ZLIB in kofsig.h.
			 *
			 * No size hint. DEFLATE ends where the stream says it
			 * does and bounds a back reference at 32KB, so the
			 * decoder runs in fixed memory whatever comes out, and
			 * a PDF states no uncompressed length this module was
			 * given. The host's budget is what bounds it.
			 */
			if (kof_unpack_zlib(o->stream_off, o->stream_len)) {
				if (!kof_child())
					break;
				opened++;
				continue;
			}
			/*
			 * Nothing came out: a chain with another coding in
			 * front of the Flate, or a limit stopped the decode.
			 * Either way the next stream is unaffected.
			 */
			failed++;
			continue;
		}

		if (o->filters & PDF_F_HIDING)
			unsupported++;
		else if (o->filters & PDF_F_IMAGE)
			images++;
	}

	kof_debug("Pdf.opened", opened);
	kof_debug("Pdf.windowed", windowed);
	kof_debug("Pdf.failed", failed);
	kof_debug("Pdf.images", images);
	/* Streams whose decoded form no loaded rule could be offered - see the
	 * note on kof_fmt_wanted in the loop. Reported because "not opened"
	 * and "not there" must never look the same to a reader. */
	kof_debug("Pdf.unwanted", unwanted);
	/* Left to the host's declared-entry step rather than dropped, which is
	 * why it is counted here and not silently skipped. */
	kof_debug("Pdf.carried", carried);
	/* Left in their region rather than duplicated as children. Counted for
	 * the same reason carried is: skipped is not the same as absent. */
	kof_debug("Pdf.in_region", in_region);
	kof_debug("Pdf.unsupported", unsupported);

	/* Encryption is already reported above, before anything could overwrite
	 * it. This is the other reason, and only when there was no first one. */
	if (!encrypted && unsupported)
		kof_unp_broken(KOF_UNP_UNSUPPORTED);
}
