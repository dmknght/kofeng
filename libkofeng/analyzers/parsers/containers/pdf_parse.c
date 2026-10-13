/*
 * pdf_parse.c - walking a PDF for its objects.
 *
 * The walk is a scan for `N G obj`, and everything else follows from where those
 * land. That is a deliberate choice over reading the cross reference table, and
 * kofmod/pdf.h says why: the xref is a claim the file makes about itself, viewers
 * recover from it being wrong, and so malware is free to make it wrong.
 *
 * Every step is bounded by the object rather than by a terminator. A PDF that ends
 * mid-object, mid-stream or mid-dictionary is ordinary - documents are appended to,
 * truncated and stitched - so the parse has to produce a classification for what is
 * there instead of refusing the file.
 *
 * THIS FILE IS THE PARSE ITSELF: the header, the regions every stream is classed
 * into, the references resolved once the table is complete, and the entry point.
 * The rest is in the units next to it - see pdf_int.h.
 */

#include "pdf_int.h"

/* ---- the parse ---------------------------------------------------------------- */

int kof_pdf_sniff(kof_buf file)
{
	uint64_t to = file.n < KOF_PDF_HEADER_SEARCH ? file.n
						     : KOF_PDF_HEADER_SEARCH;

	return pdf_find_bytes(file, 0, to, "%PDF-", 5u) != KGENOME_BROKEN;
}

/* ---- regions ------------------------------------------------------------------ */

/*
 * ONE ENTRY PER CLASS, IN CLASS ORDER, AND EVERY ONE NON-ZERO - which is now
 * true by construction rather than by care: the array is KOF_PDF_CLASSES, the
 * same list the enum is generated from.
 *
 * kof_runs_resolve indexes this by run[].cls. When it was written out by hand a
 * class added to the enum and forgotten here read a zero, and a zero matches no
 * mask, so that class's bytes resolved into no region at all. Nothing noticed:
 * the partition still totalled the file. See KOF_PDF_CLASSES in kofmod/pdf.h.
 */
#define X_CLS_BIT(n, bit) (bit),
static const uint32_t pdf_cls_bit[] = { KOF_PDF_CLASSES(X_CLS_BIT) };
#undef X_CLS_BIT

/* The view sizes region_bytes to the run list's ceiling so that adding a class
 * moves no field after it - see the note on region_bytes in kofmod/pdf.h. This
 * is where the two are held to agree. */
_Static_assert(KOF_PDF_CLS_COUNT <= KOF_RUNS_MAX_CLS,
	       "more PDF classes than the run list will carry");
_Static_assert(sizeof ((struct kof_pdf_info *)0)->region_bytes /
	       sizeof ((struct kof_pdf_info *)0)->region_bytes[0] ==
	       KOF_RUNS_MAX_CLS,
	       "region_bytes is no longer sized to the run list's ceiling");

/*
 * WHICH REGION A STREAM'S BYTES BELONG TO.
 *
 * ONE QUESTION: what does this stream HOLD. Whether it is deflated does not
 * appear, which is the whole of the change - it used to decide the answer for
 * every stream no category had claimed, so "packed" was the name for a
 * compressed page's operators, a compressed object table and a compressed
 * cross reference alike. See the note on enum kof_scan_pdf.
 *
 * A SWITCH WITH NO DEFAULT, so a category added to enum kof_pdf_cat is a
 * compiler warning here. It used to be a chain of ifs ending in the coding,
 * which meant a new category silently became whatever that chain said last.
 */
static uint32_t stream_class(const struct kof_pdf_object *o)
{
	switch (o->cat) {
	/* A carried file before anything else this could say about it: it is
	 * not part of the document's presentation at all, it is a passenger. */
	case KOF_PDF_CAT_EMBEDDED:  return KOF_PDF_CLS_EMBEDDED;
	/* Structure, compressed. The same class its uncompressed equivalent
	 * gets - an ObjStm holds object definitions and an XRef stream holds a
	 * cross reference, whatever was done to the bytes afterwards. */
	case KOF_PDF_CAT_OBJSTM:    return KOF_PDF_CLS_OBJ_TABLE;
	case KOF_PDF_CAT_XREF:      return KOF_PDF_CLS_XREF;
	/* What the document draws with. */
	case KOF_PDF_CAT_IMAGE:     return KOF_PDF_CLS_RESOURCE_IMAGE;
	case KOF_PDF_CAT_FONT:      return KOF_PDF_CLS_RESOURCE_FONT;
	/* And what it is made of. */
	case KOF_PDF_CAT_SCRIPT:    return KOF_PDF_CLS_CONTENT_SCRIPT;
	case KOF_PDF_CAT_METADATA:  return KOF_PDF_CLS_CONTENT_METADATA;
	case KOF_PDF_CAT_UNKNOWN:
	case KOF_PDF_CAT_CONTENT:
	case KOF_PDF_CAT_COUNT:
		break;
	}
	/* A stream nothing described, which in practice is a page's drawing
	 * operators - and CAT_COUNT, which is not a category at all and is
	 * named above only so that the switch is exhaustive. */
	return KOF_PDF_CLS_CONTENT;
}

KOF_RUNS_RESOLVER(pdf, struct kof_pdf_info, pdf_cls_bit, KOF_SCAN_PDF_UNCLAIMED)

/* Everything of the view but its arrays - see the note inside. */
static void pdf_clear_view(struct kof_pdf_info *p)
{
/*
 * EVERYTHING BUT THE 800KB OF ARRAYS: 288 bytes instead of 819488.
 *
 * `memset(p, 0, sizeof *p)` cleared the whole view for every PDF
 * object scanned. Measured on this machine: 13.7us each, against a
 * head that is 168 bytes. The ZIP parser had the same line and the
 * same fix took a 300-file scan from 12ms to 7ms.
 *
 * THREE SPANS RATHER THAN ONE, because unlike ZIP the arrays here are
 * not at the tail - they are interleaved with the scalars:
 *
 *        0 .. 168      head
 *      168 .. 393384   run[]        393216 bytes, skipped
 *   393384 .. 753832   object[]     360448 bytes, skipped
 *   753832 .. 753840   n_entries and its padding
 *   753840 .. 819376   entry[]       65536 bytes, skipped
 *   819376 .. 819488   docinfo[] and the trailer scalars
 *
 * WHAT MAKES IT SAFE: nothing reads past a count. Every loop over
 * these arrays - here, in bases/decomp/pdf.c, in kofviewer - is bounded
 * by n_objects, n_entries or n_runs, and all three counts live in the
 * spans that ARE cleared. A parse that gives up early therefore leaves
 * the arrays dirty and the counts at zero, which reads as "nothing
 * found" and not as the previous file's objects. Each slot is cleared
 * as it is claimed - see the memsets beside `&p->object[p->n_objects]`
 * and `&p->entry[p->n_entries++]`.
 *
 * THE ASSERTS ARE THE GUARD. They pin every boundary above, so a field
 * added or moved breaks the build rather than quietly falling into a
 * gap nothing clears.
 */
	const size_t head_end = offsetof(struct kof_pdf_info, run);
	const size_t obj_end  = offsetof(struct kof_pdf_info, object) +
				sizeof p->object;
	const size_t ent_at   = offsetof(struct kof_pdf_info, entry);
	const size_t ent_end  = ent_at + sizeof p->entry;

	_Static_assert(offsetof(struct kof_pdf_info, object) ==
		       offsetof(struct kof_pdf_info, run) +
		       sizeof ((struct kof_pdf_info *)0)->run,
		       "a field appeared between run[] and object[] "
		       "and nothing clears it");
	_Static_assert(offsetof(struct kof_pdf_info, docinfo) >=
		       offsetof(struct kof_pdf_info, entry) +
		       sizeof ((struct kof_pdf_info *)0)->entry,
		       "entry[] and docinfo[] are out of order");

	memset(p, 0, head_end);
	memset((char *)p + obj_end, 0, ent_at - obj_end);
	memset((char *)p + ent_end, 0,
	       sizeof(struct kof_pdf_info) - ent_end);
}

/*
 * The header: where "%PDF-" is, and the version after it. Zero when there is
 * none.
 */
static int pdf_find_header(kof_buf file, struct kof_pdf_info *p,
			   uint64_t *hdr_out)
{
	uint64_t hdr, to;

	to = file.n < KOF_PDF_HEADER_SEARCH ? file.n : KOF_PDF_HEADER_SEARCH;
	hdr = pdf_find_bytes(file, 0, to, "%PDF-", 5u);
	if (hdr == KGENOME_BROKEN)
		return 0;
	p->valid = 1;
	p->header_off = hdr;
	if (hdr != 0)
		p->anomalies |= KOF_PDF_ANOM_HEADER_OFFSET;
	if (hdr + 8u <= file.n && kof_is_digit(file.p[hdr + 5u]) &&
	    kof_is_digit(file.p[hdr + 7u])) {
		p->ver_major = (uint8_t)(file.p[hdr + 5u] - '0');
		p->ver_minor = (uint8_t)(file.p[hdr + 7u] - '0');
	}
	*hdr_out = hdr;
	return 1;
}

/*
 * The version line, and the binary comment that may follow it, claimed as
 * header.
 */
static void pdf_claim_header(kof_buf file, struct kof_runs *runs, uint64_t hdr)
{
	/*
	 * THE VERSION LINE, AND NOT WHAT MAY SIT IN FRONT OF IT.
	 *
	 * A reader accepts junk before %PDF- and malware uses that, which is why
	 * the offset is searched for and recorded above. The bytes themselves are
	 * not the header though, and claiming them as one put up to a kilobyte of
	 * whatever a builder prepended into the region this format documents as
	 * "small, and the part that describes the rest" - a PE stub landed in
	 * HEADER and a rule asking which bytes no structure owns was told none.
	 *
	 * They belong to nothing, which is what UNCLAIMED means, and the
	 * complement puts them there by construction now that this claim starts
	 * at the magic rather than at zero.
	 */
	kof_runs_add(runs, file.n, hdr, hdr + 8u <= file.n ? 8u : file.n - hdr,
		     KOF_PDF_CLS_HEADERS);
	/*
	 * AND THE BINARY COMMENT UNDER IT.
	 *
	 * A writer that puts any binary in the document is told to follow the
	 * version line with a comment holding four bytes above 127, so that a
	 * transport which guesses at text sees at once that it must not. It is
	 * as much a part of the header as the version is - and it was landing
	 * in UNCLAIMED, nine bytes of it, on every file that has one.
	 *
	 * Recognised by the '%' and bounded by the line, because that is all it
	 * is: a comment. Nothing reads its contents.
	 */
	uint64_t c = hdr + 8u;

	while (c < file.n && (file.p[c] == '\r' || file.p[c] == '\n'))
		c++;
	if (c < file.n && file.p[c] == '%') {
		uint64_t e = c;

		while (e < file.n && file.p[e] != '\r' && file.p[e] != '\n')
			e++;
		while (e < file.n && (file.p[e] == '\r' || file.p[e] == '\n'))
			e++;
		kof_runs_add(runs, file.n, hdr + 8u, e - (hdr + 8u),
			     KOF_PDF_CLS_HEADERS);
	}
}

/* What the references said, resolved once the table is complete, and then
 * the streams' own runs. */
static void pdf_resolve_refs(kof_buf file, struct kof_pdf_info *p,
			     struct kof_runs *runs)
{
/*
 * WHAT THE REFERENCES SAID, resolved once the table is complete.
 *
 * After the walk, because the object a reference names is as likely to
 * come later in the file as earlier - a descriptor pointing forward at
 * its font program is the ordinary shape, and so is a catalog at the
 * front pointing at an action at the back.
 *
 * Quadratic in the worst case and that is measured rather than assumed:
 * the outer loop runs only for objects that carry one of these keys,
 * which on the documents to hand is six of a hundred and eighty. The
 * inner scan is paid that many times, not four thousand.
 *
 * SET ONLY WHERE THE TARGET DESCRIBED NOTHING BETTER. An object saying
 * /Type /EmbeddedFile that some dictionary also points at with /JS
 * keeps EMBEDDED: what a stream declares about itself outranks what
 * another dictionary says about it, and the two disagreeing is worth
 * leaving visible rather than resolving in favour of the second one.
 */
	uint32_t i, k;

	for (i = 0; i < p->n_objects; i++) {
		if (!p->object[i].ref_num)
			continue;
		for (k = 0; k < p->n_objects; k++) {
			if (p->object[k].num != p->object[i].ref_num ||
			    !p->object[k].stream_len)
				continue;
			if (p->object[k].cat == KOF_PDF_CAT_CONTENT ||
			    p->object[k].cat == KOF_PDF_CAT_UNKNOWN) {
				p->object[k].cat = p->object[i].ref_cat;
				if (p->object[i].ref_cat ==
				    KOF_PDF_CAT_SCRIPT)
					p->object[k].flags |=
					    KOF_PDF_OBJ_JS;
			}
			break;
		}
	}

	/*
	 * AND NOW THE STREAMS, with every category settled.
	 *
	 * One pass, in object order, so the runs of any one class still
	 * arrive ascending and kof_runs_add's coalescing hint works as
	 * it does everywhere else.
	 */
	for (i = 0; i < p->n_objects; i++) {
		const struct kof_pdf_object *o = &p->object[i];

		if (o->stream_len)
			kof_runs_add(runs, file.n, o->stream_off,
				     o->stream_len, stream_class(o));
	}
}

int kof_pdf_parse(kof_buf file, struct kof_pdf_info *p, struct kof_obj_ctx *ctx)
{
	struct kof_runs runs;
	uint64_t hdr;
	/* 8192 bits for the redefinition filter above. A kilobyte of frame, on
	 * a path whose caller already hands it a 650KB view. */
	uint8_t seen_num[1024];

	pdf_clear_view(p);
	memset(seen_num, 0, sizeof seen_num);
	p->version = KOF_PDF_INFO_VERSION;

	if (!pdf_find_header(file, p, &hdr))
		return 0;

	kof_runs_init(&runs, p->run, KOF_PDF_MAX_EXTENTS,
		      KOF_PDF_CLS_COUNT);

	pdf_claim_header(file, &runs, hdr);
	pdf_read_trailer(file, p, &runs);
	pdf_walk_objects(file, p, &runs, seen_num, hdr);
	pdf_claim_xref(file, p, &runs, hdr);
	pdf_resolve_refs(file, p, &runs);

	/* Both bits are read AFTER the settle, because the settle is what finds an
	 * overlap - it is the pass that sorts the runs and trims one against the
	 * next. Read before it, the bit was always clear and a PDF whose objects
	 * claimed each other's bytes was reported as an ordinary one. */
	kof_runs_settle(&runs, p->region_bytes);
	if (runs.full)
		p->anomalies |= KOF_PDF_ANOM_EXTENTS_FULL;
	if (runs.overlapped)
		p->anomalies |= KOF_PDF_ANOM_OVERLAP;
	p->n_runs = runs.n;

	pdf_build_entries(p, file);
	/* After the walk, because it looks an object up by number and the table
	 * has to be there to look in. */
	pdf_read_docinfo(p, file);

	ctx->obj_size = file.n;
	ctx->format = KOF_FMT_PDF;
	ctx->file_header = p;
	ctx->resolve_scan = pdf_resolve_scan;
	ctx->entries = pdf_entries;
	return 1;
}
