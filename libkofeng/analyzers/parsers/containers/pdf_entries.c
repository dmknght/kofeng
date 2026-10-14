/*
 * pdf_entries.c - what the host reads out of a parsed PDF: the entry table, and
 * for each stream the chain of codings it was written with.
 *
 * WHAT THIS SERVES: the module ABI's struct kof_entry for a document. The chain
 * is read again from the dictionary, where its order still exists, rather than
 * recorded during the scan - see read_chain.
 */

#include "pdf_int.h"

/*
 * The category this parse settled, as the kind every container speaks.
 *
 * A table and not a switch because the two enums are independent on purpose:
 * kof_pdf_cat says what a PDF dictionary declared, kof_entry_kind says what a
 * host has to decide about, and neither should acquire the other's values by
 * being written next to it.
 */
/*
 * The NAME value that follows `key` in this object's dictionary, as a range.
 *
 * A range and never a copy, for the reason kof_entry gives about names: the
 * text is already in the file and there is nowhere here to build another one.
 * Zero length when the key is absent or is followed by something that is not a
 * name - a reference, a number, a string - because this is used to LABEL and a
 * label that guessed would be worse than none.
 */
static void dict_name(kof_buf f, const struct kof_pdf_object *o,
		      const char *key, uint32_t klen,
		      uint64_t *val_off, uint32_t *val_len)
{
	uint64_t at = o->dict_off, end = o->dict_off + o->dict_len;

	*val_off = 0;
	*val_len = 0;
	if (!o->dict_len || end > f.n)
		return;
	while (at < end) {
		const uint8_t *sl = memchr(f.p + at, '/', (size_t)(end - at));
		uint8_t name[PDF_NAME_MAX];
		uint64_t pos, raw_end;
		uint32_t nm;
		int esc;

		if (!sl)
			return;
		pos = (uint64_t)(sl - f.p);
		nm = pdf_name_decode(f, pos, end, name, &esc, &raw_end);
		at = pos + 1u;
		if (nm != klen || memcmp(name, key, klen) != 0)
			continue;
		/* The value: the next '/' if one follows immediately, which is
		 * what makes it a NAME rather than anything else. */
		while (raw_end < end && pdf_is_ws(f.p[raw_end]))
			raw_end++;
		if (raw_end >= end || f.p[raw_end] != '/')
			return;
		{
			uint64_t vend;
			uint32_t vn = pdf_name_decode(f, raw_end, end, name, &esc,
						  &vend);

			if (vn < 2u)
				return;          /* "/" alone names nothing */
			/*
			 * PAST THE SLASH AND PAST A SUBSET PREFIX.
			 *
			 * A font a producer embedded is usually SUBSET, and the
			 * format marks that with six capitals and a '+' in
			 * front of the real name: /ABCDEF+Arial. The six are
			 * arbitrary - a different tag every time the file is
			 * written - so a label built from them is a label that
			 * changes for the same font. What a reader wants, and
			 * what is worth comparing between documents, is what
			 * follows the '+'.
			 */
			*val_off = raw_end + 1u;
			*val_len = vn - 1u;
			{
				const uint8_t *p = f.p + *val_off;
				uint32_t i;

				for (i = 0; i < *val_len; i++)
					if (p[i] == '+') {
						*val_off += i + 1u;
						*val_len -= i + 1u;
						break;
					}
			}
			return;
		}
	}
}

/*
 * Where a KEY itself sits in this object's dictionary, as a range.
 *
 * The key and not its value, which is unusual and is the point: a script
 * stream's useful label is WHEN IT RUNS, and that is the name of the key that
 * reached it - /OpenAction fires when the document is opened, /AA when
 * something happens to a page or a field. Neither has a value worth showing;
 * the key IS the fact.
 *
 * A range in the file like every other name here, so nothing is synthesised.
 * That is also the limit of it: a label this mechanism can show has to EXIST
 * in the file as text, so "page 3" is not expressible and /OpenAction is.
 */
static void dict_key(kof_buf f, const struct kof_pdf_object *o,
		     const char *key, uint32_t klen,
		     uint64_t *koff, uint32_t *klen_out)
{
	uint64_t at = o->dict_off, end = o->dict_off + o->dict_len;

	*koff = 0;
	*klen_out = 0;
	if (!o->dict_len || end > f.n)
		return;
	while (at < end) {
		const uint8_t *sl = memchr(f.p + at, '/', (size_t)(end - at));
		uint8_t name[PDF_NAME_MAX];
		uint64_t pos, raw_end;
		uint32_t nm;
		int esc;

		if (!sl)
			return;
		pos = (uint64_t)(sl - f.p);
		nm = pdf_name_decode(f, pos, end, name, &esc, &raw_end);
		at = pos + 1u;
		if (nm != klen || memcmp(name, key, klen) != 0)
			continue;
		/* Past the slash, so the label reads OpenAction rather than
		 * /OpenAction - the leading slash is syntax, not name. */
		*koff = pos + 1u;
		*klen_out = nm - 1u;
		return;
	}
}

/*
 * Which object POINTED AT this one, and therefore knows what it is for.
 *
 * The table records the reference on the REFERRER - object X says "object N is
 * a font" - because that is where the key was read. So the way back is a walk,
 * and it is a walk of a table already in memory with a bound the parse set.
 *
 * This is the only place a stream can be described from, and the reason is the
 * format: a /FontFile stream carries no /Type of its own, so the dictionary
 * that references it is the only thing that knows it is a font at all. The same
 * walk already assigned the CATEGORY; this reads the rest of what the referrer
 * has to say.
 */
static const struct kof_pdf_object *referrer_of(const struct kof_pdf_info *p,
						const struct pdf_index *by_ref,
						const struct kof_pdf_object *o)
{
	const struct pdf_key *k;

	if (!o->num)
		return NULL;
	/* The lowest-numbered object whose reference names this one: the first of its key
	 * in an index sorted by key and then by object, which is what the walk over the
	 * whole table this replaced returned. */
	k = pdf_index_find(by_ref, o->num);
	return k ? &p->object[k->idx] : NULL;
}

/* See kof_pdf_entry_kind in kofmod/pdf.h: one mapping, because the
 * decompressor names its children from the same categories. */

/* See kof_pdf_entry_format in kofmod/pdf.h: one mapping, because the
 * decompressor module declares the same thing about the same streams. */

/*
 * Project the object table into the entry table.
 *
 * One pass, after everything else has settled, because a category can still
 * change up to the reference resolution - a stream is not known to be a font
 * until the /FontFile pointing at it has been found.
 */
/*
 * IS THERE A PREDICTOR IN FRONT OF THE DECOMPRESSOR'S OUTPUT?
 *
 * /DecodeParms can put one there, and it is not a filter - it is a transform
 * applied to what the filter produced, so a chain of [FlateDecode] alone is
 * WRONG for a stream that has one: inflating gives predictor-encoded rows and
 * not the original bytes. This is the same lie as an inexpressible filter and
 * it wears a different hat, which is why it is easy to miss - the chain looks
 * complete and runnable.
 *
 * The whole dictionary is searched for /Predictor rather than the nesting
 * under /DecodeParms being walked, because /Predictor is only ever a
 * DecodeParms key: there is nowhere else in the format for it to appear, so
 * finding it anywhere in this dictionary is finding it in the right place.
 * Walking into the sub-dictionary buys nothing and costs a nesting parser
 * that hostile input would then be able to argue with.
 *
 * 1 is "no prediction" and is the format's default, so only above that
 * counts. Below or equal, and a missing value, are nothing to report - the
 * common case, which is why the test is for a number greater than one rather
 * than for the key.
 */
/*
 * A NAMED INTEGER IN THIS OBJECT'S DICTIONARY, or `absent` when it is not
 * there - and `absent` again when it is there as a reference this parse will
 * not follow.
 *
 * One function for the two DecodeParms keys that change what a decoder must
 * do, rather than two nearly identical scans. The whole dictionary is searched
 * rather than the nesting under /DecodeParms being walked, because neither key
 * has anywhere else in the format to appear - so finding one anywhere in this
 * dictionary is finding it in the right place, and walking the sub-dictionary
 * would buy nothing while costing a nesting parser that hostile input could
 * argue with.
 */
static int64_t dict_int(kof_buf f, const struct kof_pdf_object *o,
			const char *key, uint32_t klen, int64_t absent)
{
	uint64_t at = o->dict_off, end = o->dict_off + o->dict_len;

	if (!o->dict_len || end > f.n)
		return absent;
	while (at < end) {
		const uint8_t *sl = memchr(f.p + at, '/', (size_t)(end - at));
		uint8_t name[PDF_NAME_MAX];
		uint64_t pos, raw_end, v = 0;
		uint32_t nm;
		int esc, any = 0;

		if (!sl)
			return absent;
		pos = (uint64_t)(sl - f.p);
		nm = pdf_name_decode(f, pos, end, name, &esc, &raw_end);
		at = pos + 1u;
		if (nm != klen || memcmp(name, key, klen) != 0)
			continue;
		/*
		 * Read here rather than through pdf_read_length: that one records
		 * LENGTH_INDIR on a reference, which would be a /Length anomaly
		 * reported about a different key.
		 */
		while (raw_end < end && pdf_is_ws(f.p[raw_end]))
			raw_end++;
		while (raw_end < end && kof_is_digit(f.p[raw_end]) && v < 100000u) {
			v = v * 10u + (uint64_t)(f.p[raw_end] - '0');
			raw_end++;
			any = 1;
		}
		return any ? (int64_t)v : absent;
	}
	return absent;
}

static int has_predictor(kof_buf f, const struct kof_pdf_object *o)
{
	uint64_t at = o->dict_off, end = o->dict_off + o->dict_len;

	if (!o->dict_len || end > f.n)
		return 0;
	while (at < end) {
		const uint8_t *sl = memchr(f.p + at, '/', (size_t)(end - at));
		uint8_t name[PDF_NAME_MAX];
		uint64_t pos, raw_end, v;
		uint32_t nm;
		int esc, any = 0;

		if (!sl)
			return 0;
		pos = (uint64_t)(sl - f.p);
		nm = pdf_name_decode(f, pos, end, name, &esc, &raw_end);
		at = pos + 1u;
		if (nm != 10u || memcmp(name, "/Predictor", 10u) != 0)
			continue;
		/*
		 * Read the number here rather than through pdf_read_length: that
		 * one records LENGTH_INDIR on a reference, which would be a
		 * /Length anomaly reported about a /Predictor. An indirect
		 * predictor reads as no number, and no number is treated as a
		 * predictor being there - the conservative way round, since
		 * somebody wrote the key.
		 */
		v = 0;
		while (raw_end < end && pdf_is_ws(f.p[raw_end]))
			raw_end++;
		while (raw_end < end && kof_is_digit(f.p[raw_end]) && v < 1000u) {
			v = v * 10u + (uint64_t)(f.p[raw_end] - '0');
			raw_end++;
			any = 1;
		}
		return !any || v > 1u;
	}
	return 0;
}

/*
 * The filter chain, in the order the format wrote it.
 *
 * o->filters cannot answer this - it is a bitmask, so the order is not in it,
 * and that is the whole of the bug this was written for: a decompressor
 * handed the Flate bit for /Filter [/ASCII85Decode /FlateDecode] decoded raw
 * ASCII85 as DEFLATE, failed, and a clean document was reported as one the
 * engine could not finish.
 *
 * So the array is read again, here, where the order still exists. Re-read
 * rather than recorded during pdf_dict_scan because a chain is rare and four
 * bytes per object would be paid on every object that has none.
 *
 * Only what this build can undo is named. A member that IS a filter and is
 * not expressible stops the chain and says so through
 * KOF_ENT_F_CODED_UNKNOWN, because leaving the chain empty and silent would
 * be read as stored - see that flag for what a host then does with the bytes.
 */
static void read_chain(kof_buf f, const struct kof_pdf_object *o,
		       uint16_t out[4], uint32_t *flags)
{
	uint64_t at = o->dict_off, end = o->dict_off + o->dict_len;
	uint32_t n = 0;
	int in_filter = 0, f_i;

	if (!o->dict_len || end > f.n)
		return;
	/*
	 * Before the filters, because a predictor makes the chain incomplete
	 * whatever the filters turn out to be, and because the flag is what a
	 * host is told to read first.
	 */
	if (has_predictor(f, o))
		*flags |= KOF_ENT_F_CODED_UNKNOWN;
	/*
	 * /EarlyChange 0 MAKES THE LZW DECODER WRONG, so the chain is refused
	 * rather than run.
	 *
	 * The key decides whether the code width grows one code before the
	 * table needs it. The default is 1, which is what this build's decoder
	 * does - see libuncoat/decompressors/lzw.h - and a stream that says 0 decodes to
	 * PLAUSIBLE GARBAGE rather than to nothing: the first few hundred bytes
	 * are right and then it drifts. That is the worst possible failure, so
	 * it is reported as a coding this build cannot perform, which is what it
	 * is.
	 *
	 * Absent reads as 1 because the format says so. An indirect value reads
	 * as 0 - the conservative way round, since somebody wrote the key and
	 * this parse will not follow a reference to find out what they meant.
	 */
	if (dict_int(f, o, "/EarlyChange", 12u, 1) != 1)
		*flags |= KOF_ENT_F_CODED_UNKNOWN;
	/*
	 * `n < 4u` is NOT in this condition, and that is deliberate. It was,
	 * and it made the full-chain test below unreachable: the loop simply
	 * ended at four and the entry then claimed a complete chain for a
	 * stream with a fifth filter. The bound belongs where it can be
	 * REPORTED, not where it silently truncates.
	 */
	while (at < end) {
		const uint8_t *sl = memchr(f.p + at, '/', (size_t)(end - at));
		uint8_t name[PDF_NAME_MAX];
		uint64_t pos, raw_end;
		uint32_t nm;
		int esc;

		if (!sl)
			break;
		pos = (uint64_t)(sl - f.p);
		nm = pdf_name_decode(f, pos, end, name, &esc, &raw_end);
		at = pos + 1u;

		if (nm == 7u && memcmp(name, "/Filter", 7u) == 0) {
			in_filter = 1;
			continue;
		}
		if (!in_filter)
			continue;
		/*
		 * A CODING, OR THE NEXT KEY OF THE DICTIONARY - and the two are
		 * told apart by the format's own filter table rather than by the
		 * shape of the name.
		 *
		 * A single filter is written bare, so /Filter is followed by
		 * either a list or one name, and after that comes an ordinary
		 * key. Guessing from the name instead - anything ending in
		 * "Decode" - both misses /Crypt, which is a filter, and would
		 * accept a key someone named /XDecode. FILTERS is the list the
		 * format defines, and it is already here.
		 */
		f_i = pdf_find_filter(name, nm);
		if (f_i < 0)
			break;
		/*
		 * Room first. Four is chosen for real documents, so a chain
		 * longer than that is either malformed or built to be awkward;
		 * either way what cannot be written down cannot be claimed.
		 */
		if (n == 4u) {
			*flags |= KOF_ENT_F_CODED_UNKNOWN;
			break;
		}
		if (pdf_filter_bit(f_i) == KOF_PDF_F_FLATE) {
			/*
			 * ZLIB and not DEFLATE: PDF 32000-1 7.4.4 says the
			 * data is in zlib/deflate format, so the two byte
			 * header is there and a raw inflate would fail on it.
			 */
			out[n++] = KOF_UNP_ZLIB;
			continue;
		}
		/*
		 * THE ONE THAT PUT THIS FIELD HERE. /ASCII85Decode in front of
		 * a Flate is what a producer writes to get a stream through a
		 * text-only channel, and naming only the Flate half had the
		 * decoder inflate ASCII85 TEXT and fail - a clean document
		 * reported as one the engine could not finish, exit 2.
		 */
		if (pdf_filter_bit(f_i) == KOF_PDF_F_ASCII85) {
			out[n++] = KOF_UNP_ASCII85;
			continue;
		}
		/*
		 * The other two transport codings. Rare, and that is the reason
		 * to have them rather than not: reaching for an unusual filter
		 * is how a stream gets past a parser that implemented only the
		 * common one.
		 */
		if (pdf_filter_bit(f_i) == KOF_PDF_F_ASCIIHEX) {
			out[n++] = KOF_UNP_ASCIIHEX;
			continue;
		}
		if (pdf_filter_bit(f_i) == KOF_PDF_F_RUNLEN) {
			out[n++] = KOF_UNP_RUNLENGTH;
			continue;
		}
		if (pdf_filter_bit(f_i) == KOF_PDF_F_LZW) {
			out[n++] = KOF_UNP_LZW;
			continue;
		}
		/*
		 * The remaining five. DCT, JPX, JBIG2 and CCITT are image
		 * codings, which the image class exists to keep out of the scan
		 * entirely - decoding one yields pixels, which is not something
		 * a rule reads; /Crypt needs the document's encryption handled
		 * first. All of them are named by the file and none can be
		 * performed, which is exactly what the flag is for.
		 */
		*flags |= KOF_ENT_F_CODED_UNKNOWN;
		break;
	}
}

void pdf_build_entries(struct kof_pdf_info *p, struct pdf_tabs *t, kof_buf file)
{
	/* Built on the first stream that needs it - a script or a font - and not for a
	 * document whose streams are all pages and pictures. */
	struct pdf_index by_ref = { NULL, 0, 0 };
	int have_ref = 0, ref_refused = 0;
	uint32_t i;

	for (i = 0; i < p->n_objects; i++) {
		const struct kof_pdf_object *o = &p->object[i];
		struct kof_entry *e;

		if (!o->stream_len)
			continue;
		/*
		 * ONE ROW PER STREAM, and the table is as long as there are streams: a stream
		 * needs its own object, so the bound is the object table's and no number of
		 * its own. A row that cannot be had is the ledger refusing, and the entries
		 * from here on are not in the table - said, as every table that fills is.
		 */
		if (p->n_entries >= t->cap_ent) {
			void *tab = p->entry;

			if (!kof_tab_grow(&p->mem, &tab, &t->cap_ent, sizeof *p->entry,
					  (uint64_t)p->n_entries + 1u, p->n_objects)) {
				p->anomalies |= KOF_PDF_ANOM_EXTENTS_FULL;
				break;
			}
			p->entry = (struct kof_entry *)tab;
		}
		e = &p->entry[p->n_entries++];
		memset(e, 0, sizeof *e);
		e->off = o->stream_off;
		e->len = o->stream_len;
		e->name_off = o->cat_off;
		e->name_len = o->cat_len;
		/*
		 * A BETTER NAME WHEN THE REFERRER HAS ONE.
		 *
		 * cat_off above is the object's own /Type or /Subtype, and for
		 * most streams there is none: measured on one document, 12 of
		 * 14 arrived with nothing to be called. What a reader needs is
		 * on the dictionary that POINTED at the stream, because that is
		 * the thing that knows what the stream is for.
		 *
		 * Only where the format actually says something. A font's
		 * /BaseFont is the name of a typeface and is worth comparing
		 * between documents; a script's trigger says when it runs. A
		 * content stream's page is a third case and needs a reference
		 * this parse does not yet follow.
		 */
		/*
		 * WHEN A SCRIPT RUNS, when the file says it in one step.
		 *
		 * The trigger and the script are often the SAME dictionary -
		 * << /OpenAction << /S /JavaScript /JS (...) >> >> collapses to
		 * one object in the small malicious files that use it - and
		 * then the key is right there on the referrer. Where the
		 * trigger is a step further up, through a catalog or an
		 * annotation, this parse does not follow it and says nothing:
		 * the stream keeps the kind alone, which is the honest answer
		 * rather than a guess about what fires it.
		 *
		 * The document-level anomaly bits still record that an
		 * OpenAction exists at all - that is a different question from
		 * WHICH script it runs, and they are not conflated.
		 */
		if ((o->cat == KOF_PDF_CAT_SCRIPT || o->cat == KOF_PDF_CAT_FONT) &&
		    !have_ref && !ref_refused) {
			if (pdf_index_build(p, &by_ref, PDF_IX_REF))
				have_ref = 1;
			else
				ref_refused = 1;
		}
		if (o->cat == KOF_PDF_CAT_SCRIPT) {
			const struct kof_pdf_object *r =
				have_ref ? referrer_of(p, &by_ref, o) : NULL;
			uint64_t koff;
			uint32_t klen;

			if (r && (r->flags & KOF_PDF_OBJ_OPENACTION)) {
				dict_key(file, r, "/OpenAction", 11u, &koff,
					 &klen);
				if (!klen)
					dict_key(file, r, "/AA", 3u, &koff,
						 &klen);
				if (klen) {
					e->name_off = koff;
					e->name_len = klen;
				}
			}
		}
		if (o->cat == KOF_PDF_CAT_FONT) {
			const struct kof_pdf_object *r =
				have_ref ? referrer_of(p, &by_ref, o) : NULL;
			uint64_t noff;
			uint32_t nlen;

			/*
			 * /FontName FIRST, and that order is the format's.
			 *
			 * The chain is /Type /Font -> /FontDescriptor ->
			 * /FontFile2 -> the stream, so the dictionary that
			 * REFERENCES the stream is the DESCRIPTOR, and a
			 * descriptor's name key is /FontName. /BaseFont is on
			 * the Font dictionary one step further up, which this
			 * parse does not follow.
			 *
			 * Looking for /BaseFont alone found nothing: measured,
			 * five font streams stayed unnamed while the file said
			 * /FontName/BCDEEE+Calibri-Bold two bytes away.
			 * /BaseFont is still tried, because a descriptor is not
			 * required and a producer may put the stream on the
			 * Font dictionary itself.
			 */
			if (r) {
				dict_name(file, r, "/FontName", 9u, &noff,
					  &nlen);
				if (!nlen)
					dict_name(file, r, "/BaseFont", 9u,
						  &noff, &nlen);
				if (nlen) {
					e->name_off = noff;
					e->name_len = nlen;
				}
			}
		}
		/*
		 * The object's own index, not the row's. A PDF stream needs its
		 * own object, so this is the object table's index and it is what
		 * resolve_entry would be asked for. Rows are only the streams,
		 * so the two numbers differ from the first object without one.
		 */
		e->index = i;
		e->kind = kof_pdf_entry_kind(o->cat);
		e->format = kof_pdf_entry_format(o->cat);
		/* A PDF stream is one range: the walk found it between the
		 * keyword and endstream. Nothing here is ever scattered, so the
		 * flag stays clear and off/len are the answer. */
		read_chain(file, o, e->coding, &e->flags);
	}
	if (have_ref)
		pdf_index_free(p, &by_ref);
	/* A name that could not be looked up is a label that is missing, not a stream that
	 * is: the entry is still there, and the ledger saying no is still said. */
	if (ref_refused)
		p->anomalies |= KOF_PDF_ANOM_OBJECTS_FULL;
}

uint32_t pdf_entries(const struct kof_obj_ctx *ctx,
			    const struct kof_entry **out)
{
	const struct kof_pdf_info *p = (const struct kof_pdf_info *)ctx->file_header;

	if (!p || !p->valid || !out)
		return 0;
	*out = p->entry;
	return p->n_entries;
}
