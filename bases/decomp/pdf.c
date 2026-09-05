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
	uint32_t images = 0;
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
		 * No filter at all: the bytes are already what they are, so the
		 * child is a window and the decoder is not involved.
		 */
		if (!o->filters) {
			if (!kof_child_window(o->stream_off, o->stream_len))
				break;
			windowed++;
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
	kof_debug("Pdf.unsupported", unsupported);

	/* Encryption is already reported above, before anything could overwrite
	 * it. This is the other reason, and only when there was no first one. */
	if (!encrypted && unsupported)
		kof_unp_broken(KOF_UNP_UNSUPPORTED);
}
