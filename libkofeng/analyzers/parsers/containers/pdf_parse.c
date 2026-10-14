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

/*
 * What a parse left in the view, given back: the three tables and the account of them.
 * The caller's room survives it - see kof_pdf_parse.
 */
void kof_pdf_release(struct kof_pdf_info *p)
{
	kof_tab_free((void **)&p->run);
	kof_tab_free((void **)&p->object);
	kof_tab_free((void **)&p->entry);
	p->n_runs = 0;
	p->n_objects = 0;
	p->n_entries = 0;
	p->mem.held = 0;
	p->mem.rows = 0;
}

/* The walk a module's kof_pdf_next reaches, and the account the host charges; see
 * zip_parse.h for what each is for. */
const void *kof_pdf_row(void *view, uint32_t *cursor)
{
	struct kof_pdf_info *p = (struct kof_pdf_info *)view;

	if (!p)
		return NULL;
	p->mem.walked++;
	if (!p->valid || !p->object || *cursor >= p->n_objects)
		return NULL;
	return &p->object[(*cursor)++];
}

struct kof_view_mem *kof_pdf_mem(void *view)
{
	return &((struct kof_pdf_info *)view)->mem;
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
 * THROUGH AN INDEX BY NUMBER, not a scan from the top for each reference. It was
 * quadratic and described as "measured rather than assumed" because the outer loop
 * ran only for objects carrying one of these keys - six in a hundred and eighty on the
 * documents to hand. A document built to carry one in every object, in a table as long
 * as the file, is the whole table squared. The first object with the number that
 * carries a stream is the first row of its key, which is what the scan returned.
 *
 * SET ONLY WHERE THE TARGET DESCRIBED NOTHING BETTER. An object saying
 * /Type /EmbeddedFile that some dictionary also points at with /JS
 * keeps EMBEDDED: what a stream declares about itself outranks what
 * another dictionary says about it, and the two disagreeing is worth
 * leaving visible rather than resolving in favour of the second one.
 */
	struct pdf_index by_num;
	uint32_t i;

	if (pdf_index_build(p, &by_num, PDF_IX_STREAM_NUM)) {
		for (i = 0; i < p->n_objects; i++) {
			const struct pdf_key *k;
			struct kof_pdf_object *t;

			if (!p->object[i].ref_num)
				continue;
			k = pdf_index_find(&by_num, p->object[i].ref_num);
			if (!k)
				continue;
			t = &p->object[k->idx];
			if (t->cat == KOF_PDF_CAT_CONTENT ||
			    t->cat == KOF_PDF_CAT_UNKNOWN) {
				t->cat = p->object[i].ref_cat;
				if (p->object[i].ref_cat == KOF_PDF_CAT_SCRIPT)
					t->flags |= KOF_PDF_OBJ_JS;
			}
		}
		pdf_index_free(p, &by_num);
	} else {
		/* No room for the index: the references are not followed and the categories
		 * stay what each dictionary said of itself - said, not hidden. */
		p->anomalies |= KOF_PDF_ANOM_OBJECTS_FULL;
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
	struct pdf_tabs tabs;
	uint64_t hdr, room, runs_limit;

	/* The whole view is cleared, because it is small now: the 800KB of arrays that made
	 * a three-span clear worth six asserts are tables the parse allocates. What an
	 * earlier parse left is let go first; the caller's room is read before the clear
	 * and put back after it. */
	room = p->mem.room;
	kof_pdf_release(p);
	memset(p, 0, sizeof *p);
	p->mem.room = room;
	p->version = KOF_PDF_INFO_VERSION;

	if (!pdf_find_header(file, p, &hdr))
		return 0;

	/*
	 * WHAT THE FILE CAN HOLD, which bounds every table whatever it says about itself: an
	 * object is KOF_PDF_OBJECT_MIN bytes at the least, so the rows cannot exceed the
	 * length over it; a run is made by an object (a dictionary, a stream, a tail), by a
	 * cross reference section or by one of the %%EOF and startxref lines the last 64 KiB
	 * can carry - the arithmetic is written out so the pool's bound is read, not trusted.
	 */
	memset(&tabs, 0, sizeof tabs);
	tabs.obj_limit = file.n / KOF_PDF_OBJECT_MIN + 1u;
	runs_limit = 3u * tabs.obj_limit + file.n / KOF_PDF_XREF_MIN + 1u +
		     2u * ((1u << 16) / KOF_PDF_XREF_MIN + 1u) + 16u;
	kof_runs_init_dyn(&runs, &p->mem, KOF_PDF_CLS_COUNT, runs_limit);

	pdf_claim_header(file, &runs, hdr);
	pdf_read_trailer(file, p, &runs);
	pdf_walk_objects(file, p, &tabs, &runs, hdr);
	pdf_mark_redefined(p);
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
	p->run = runs.v;
	p->n_runs = runs.n;

	pdf_build_entries(p, &tabs, file);
	/* After the walk, because it looks an object up by number and the table
	 * has to be there to look in. */
	pdf_read_docinfo(p, file);

	p->mem.rows = p->n_objects;
	ctx->obj_size = file.n;
	ctx->format = KOF_FMT_PDF;
	ctx->file_header = p;
	ctx->resolve_scan = pdf_resolve_scan;
	ctx->entries = pdf_entries;
	return 1;
}
