/*
 * pdf_units - the PDF parser's private units (pdf_int.h, the `pdf_` family), one at a time.
 *
 * pdf_chain.c and api_engine_parsers.c drive the parser as a whole; every unit below is reached through it, and
 * a defect in one shows only as a wrong region or a wrong child several steps later. Here each is called on its own
 * and the whole is checked against the sum:
 *
 *   LEXER      pdf_is_ws / pdf_is_delim are exactly the sets the PDF syntax names; pdf_find_bytes returns the first
 *              occurrence inside [from, to), never reads past `to`, and answers KGENOME_BROKEN for every window it
 *              cannot search; pdf_name_decode undoes #xx once, leaves a malformed escape as bytes, stops at white
 *              space or a delimiter and at PDF_NAME_MAX
 *   NUMBERS    pdf_read_length and pdf_read_ref: `N G R` is a reference and not a length (and says so), digits stop
 *              growing at a bound instead of wrapping, no number is invented where there is none
 *   FILTERS    pdf_find_filter / pdf_filter_bit: every table row finds itself, near names find nothing
 *   WALK       the steps kof_pdf_parse runs - pdf_read_trailer, pdf_walk_objects, pdf_claim_xref, pdf_build_entries,
 *              pdf_read_docinfo, pdf_entries - run in that order by hand on a document of three objects and agree
 *              with kof_pdf_parse on every count; pdf_dict_scan reads one dictionary's filter and declared length
 */

#include "hostile_engine.h"

#include "../../libkofeng/analyzers/parsers/containers/pdf_int.h"

/* a document with a real cross reference table: the trailer dictionary is found through startxref */
static char DOC[1024];
static size_t DOC_N;

static void make_doc(void)
{
	size_t at = 0, o1, o2, o3, xr;
	unsigned i;
	size_t offs[4];

	at += (size_t)sprintf(DOC + at, "%%PDF-1.7\n");
	o1 = at;
	at += (size_t)sprintf(DOC + at, "1 0 obj\n<< /Type /Catalog >>\nendobj\n");
	o2 = at;
	at += (size_t)sprintf(DOC + at, "2 0 obj\n<< /Length 8 /Filter /FlateDecode >>\nstream\nABCDEFGH\nendstream\nendobj\n");
	o3 = at;
	at += (size_t)sprintf(DOC + at, "3 0 obj\n<< /Title (Hello) /Producer <4142> >>\nendobj\n");
	xr = at;
	offs[0] = 0; offs[1] = o1; offs[2] = o2; offs[3] = o3;
	at += (size_t)sprintf(DOC + at, "xref\n0 4\n");
	for (i = 0; i < 4u; i++)
		at += (size_t)sprintf(DOC + at, "%010zu %05u %c \n", offs[i], i ? 0u : 65535u, i ? 'n' : 'f');
	at += (size_t)sprintf(DOC + at, "trailer\n<< /Size 4 /Root 1 0 R /Info 3 0 R >>\nstartxref\n%zu\n%%%%EOF\n", xr);
	DOC_N = at;
}

static void lexer(void)
{
	static const char ws[] = " \t\r\n\f";
	static const char delim[] = "/[]<>(){}%";
	unsigned c;
	kof_buf f = kof_buf_make("abcabcabd", 9);

	for (c = 0; c < 256u; c++) {
		int is_ws = c == 0 || strchr(ws, (int)c) != NULL;
		int is_dl = c != 0 && strchr(delim, (int)c) != NULL;

		CK(pdf_is_ws((uint8_t)c) == is_ws, "pdf_is_ws(0x%02x)", c);
		CK(pdf_is_delim((uint8_t)c) == is_dl, "pdf_is_delim(0x%02x)", c);
	}
	CK(pdf_find_bytes(f, 0, 9, "abd", 3) == 6u, "find: the first occurrence is found where it is");
	CK(pdf_find_bytes(f, 0, 9, "abc", 3) == 0u && pdf_find_bytes(f, 1, 9, "abc", 3) == 3u, "and the search starts at `from`");
	CK(pdf_find_bytes(f, 0, 8, "abd", 3) == KGENOME_BROKEN, "an occurrence that crosses `to` is not one (the byte after `to` is not read)");
	CK(pdf_find_bytes(f, 0, 9, "d", 1) == 8u && pdf_find_bytes(f, 8, 9, "d", 1) == 8u, "a one byte pattern at the last byte");
	CK(pdf_find_bytes(f, 0, 9, "zz", 2) == KGENOME_BROKEN, "absent");
	CK(pdf_find_bytes(f, 0, 9, "a", 0) == KGENOME_BROKEN, "an empty pattern finds nothing");
	CK(pdf_find_bytes(f, 0, 10, "a", 1) == KGENOME_BROKEN && pdf_find_bytes(f, 5, 5, "a", 1) == KGENOME_BROKEN &&
	   pdf_find_bytes(f, 7, 3, "a", 1) == KGENOME_BROKEN && pdf_find_bytes(f, 0, 9, "abcabcabdx", 10) == KGENOME_BROKEN &&
	   pdf_find_bytes(kof_buf_make(NULL, 0), 0, 0, "a", 1) == KGENOME_BROKEN,
	   "a window past the object, an empty one, a reversed one, a pattern longer than it: all BROKEN");

	{
		uint8_t out[PDF_NAME_MAX + 8];
		int esc;
		uint64_t end;
		uint32_t n;
		const char *t1 = "/Na#6De rest", *t2 = "/A#4", *t3 = "/A#zzB/next", *t4 = "/Plain", *t5 = "/A(b";
		char big[200];

		n = pdf_name_decode(kof_buf_make(t1, strlen(t1)), 0, strlen(t1), out, &esc, &end);
		CK(n == 5u && !memcmp(out, "/Name", 5) && esc == 1 && end == 7u, "an escape is decoded once and reported (n %u, raw end %llu)", n, (unsigned long long)end);
		n = pdf_name_decode(kof_buf_make(t2, strlen(t2)), 0, strlen(t2), out, &esc, &end);
		CK(n == 4u && !memcmp(out, "/A#4", 4) && esc == 0 && end == 4u, "an escape cut by the end is kept as bytes");
		n = pdf_name_decode(kof_buf_make(t3, strlen(t3)), 0, strlen(t3), out, &esc, &end);
		CK(n == 6u && !memcmp(out, "/A#zzB", 6) && esc == 0 && end == 6u, "a malformed escape is bytes, and a `/` ends the name");
		n = pdf_name_decode(kof_buf_make(t4, strlen(t4)), 0, strlen(t4), out, &esc, &end);
		CK(n == 6u && esc == 0 && end == 6u, "a plain name runs to the end of the range");
		n = pdf_name_decode(kof_buf_make(t5, strlen(t5)), 0, strlen(t5), out, &esc, &end);
		CK(n == 2u && end == 2u, "a delimiter ends it");
		n = pdf_name_decode(kof_buf_make(t4, strlen(t4)), 0, 3, out, &esc, &end);
		CK(n == 3u && end == 3u, "and so does the end of the range given, not the end of the object");
		memset(big, 'x', sizeof big);
		big[0] = '/';
		n = pdf_name_decode(kof_buf_make(big, sizeof big), 0, sizeof big, out, &esc, &end);
		CK(n == PDF_NAME_MAX && end == PDF_NAME_MAX, "a name is cut at PDF_NAME_MAX and the raw end says how far it was read (%u, %llu)", n, (unsigned long long)end);
	}
}

static void numbers(void)
{
	struct kof_pdf_info *p = calloc(1, sizeof *p);
	const char *a = "  12 endstream", *b = "12 0 R", *c = "abc", *d = "99999999999999999999 x", *e = "12 7 x";

	CK(p != NULL, "an info");
	if (!p)
		return;
	CK(pdf_read_length(kof_buf_make(a, strlen(a)), 0, strlen(a), p) == 12u && p->anomalies == 0, "a length, after white space");
	CK(pdf_read_length(kof_buf_make(b, strlen(b)), 0, strlen(b), p) == 0u && (p->anomalies & KOF_PDF_ANOM_LENGTH_INDIR),
	   "`12 0 R` is an indirect length: 0 and the anomaly");
	p->anomalies = 0;
	CK(pdf_read_length(kof_buf_make(c, strlen(c)), 0, strlen(c), p) == 0u && p->anomalies == 0, "no digits: 0, no anomaly");
	CK(pdf_read_length(kof_buf_make(e, strlen(e)), 0, strlen(e), p) == 12u && p->anomalies == 0, "`12 7 x` is a length and a stray number");
	{
		uint64_t v = pdf_read_length(kof_buf_make(d, strlen(d)), 0, strlen(d), p);

		CK(v >= (1ull << 48) && v < (1ull << 63), "twenty digits stop growing at the bound and do not wrap (%llu)", (unsigned long long)v);
	}
	CK(pdf_read_length(kof_buf_make(a, strlen(a)), 5, 3, p) == 0u, "a window that ends before it starts");

	CK(pdf_read_ref(kof_buf_make(b, strlen(b)), 0, strlen(b)) == 12u, "`12 0 R` is object 12");
	CK(pdf_read_ref(kof_buf_make("  7 3 R", 8), 0, 8) == 7u, "after white space");
	CK(pdf_read_ref(kof_buf_make("0 0 R", 5), 0, 5) == 0u, "object 0 is no object");
	CK(pdf_read_ref(kof_buf_make("12 R", 4), 0, 4) == 0u && pdf_read_ref(kof_buf_make("12 0", 4), 0, 4) == 0u &&
	   pdf_read_ref(kof_buf_make("12 0 X", 6), 0, 6) == 0u && pdf_read_ref(kof_buf_make("x", 1), 0, 1) == 0u, "not a reference: 0");
	{
		uint32_t v = pdf_read_ref(kof_buf_make("99999999999999999999 0 R", 24), 0, 24);

		CK(v == 0u, "twenty digits are no reference: the number stops growing at the bound and what is left is not an `R` (%u)", v);
		CK(pdf_read_ref(kof_buf_make("268435455 0 R", 13), 0, 13) == 268435455u, "the largest number below the bound is read whole");
	}
	free(p);
}

static void filters(void)
{
	static const struct { const char *n; uint32_t bit; } t[] = {
		{ "/FlateDecode", KOF_PDF_F_FLATE }, { "/LZWDecode", KOF_PDF_F_LZW }, { "/ASCIIHexDecode", KOF_PDF_F_ASCIIHEX },
		{ "/ASCII85Decode", KOF_PDF_F_ASCII85 }, { "/RunLengthDecode", KOF_PDF_F_RUNLEN }, { "/DCTDecode", KOF_PDF_F_DCT },
		{ "/CCITTFaxDecode", KOF_PDF_F_CCITT }, { "/JBIG2Decode", KOF_PDF_F_JBIG2 }, { "/JPXDecode", KOF_PDF_F_JPX },
		{ "/Crypt", KOF_PDF_F_CRYPT }
	};
	unsigned i;
	uint32_t seen = 0;

	for (i = 0; i < sizeof t / sizeof t[0]; i++) {
		int k = pdf_find_filter((const uint8_t *)t[i].n, (uint32_t)strlen(t[i].n));

		CK(k >= 0 && pdf_filter_bit(k) == t[i].bit && t[i].bit && !(seen & t[i].bit), "%s finds itself, with its own bit", t[i].n);
		seen |= t[i].bit;
		CK(pdf_find_filter((const uint8_t *)t[i].n, (uint32_t)strlen(t[i].n) - 1u) == -1, "%s cut short is not a filter", t[i].n);
	}
	CK(pdf_find_filter((const uint8_t *)"/Flate", 6) == -1 && pdf_find_filter((const uint8_t *)"/flatedecode", 12) == -1 &&
	   pdf_find_filter((const uint8_t *)"", 0) == -1 && pdf_find_filter((const uint8_t *)"/FlateDecodeX", 13) == -1,
	   "a near name, another case, an empty one, a longer one: none");
}

/* the same steps kof_pdf_parse runs, by hand */
static void walk(void)
{
	struct kof_pdf_info *p = calloc(1, sizeof *p), *q = calloc(1, sizeof *q);
	struct kof_obj_ctx ctx, qctx;
	struct kof_runs runs;
	struct pdf_tabs tabs;
	kof_buf f = kof_buf_make(DOC, DOC_N);
	const struct kof_entry *ent = NULL;
	uint32_t ne, i;

	CK(p && q, "two views");
	if (!p || !q) {
		free(p);
		free(q);
		return;
	}
	memset(&tabs, 0, sizeof tabs);
	tabs.obj_limit = f.n / KOF_PDF_OBJECT_MIN + 1u;
	memset(&ctx, 0, sizeof ctx);
	memset(&qctx, 0, sizeof qctx);
	p->version = KOF_PDF_INFO_VERSION;
	kof_runs_init_dyn(&runs, &p->mem, KOF_PDF_CLS_COUNT, 3u * tabs.obj_limit + 4096u);

	pdf_read_trailer(f, p, &runs);
	CK(p->eof_off > 0 && p->startxref > 0 && p->startxref < p->eof_off && !memcmp(f.p + p->startxref, "xref", 4),
	   "read_trailer records %%%%EOF and where startxref points (%llu, %llu)", (unsigned long long)p->eof_off, (unsigned long long)p->startxref);
	pdf_walk_objects(f, p, &tabs, &runs, 0);
	pdf_mark_redefined(p);
	CK(p->n_objects == 3u && p->n_streams == 1u && p->declared_objects == 3u, "walk_objects: three objects, one stream (%u, %u)", p->n_objects, p->n_streams);
	CK(p->object[0].num == 1u && p->object[1].num == 2u && p->object[2].num == 3u && p->object[0].off < p->object[1].off && p->object[1].off < p->object[2].off,
	   "in file order, by number");
	CK(p->object[1].stream_len == 8u && !memcmp(f.p + p->object[1].stream_off, "ABCDEFGH", 8) && p->object[1].filters == KOF_PDF_F_FLATE,
	   "the stream's bytes and its filter");
	CK(p->object[0].stream_len == 0u && p->object[2].stream_len == 0u, "and the others have none");
	pdf_claim_xref(f, p, &runs, 0);
	CK(runs.n > 0u, "claim_xref and the walk have claimed bytes (%u runs)", runs.n);
	CK(p->trailer_len > 0 && p->trailer_off + p->trailer_len <= f.n && !memcmp(f.p + p->trailer_off, "<<", 2),
	   "claim_xref follows the table to the trailer and keeps its dictionary (%llu + %u)", (unsigned long long)p->trailer_off, p->trailer_len);
	kof_runs_settle(&runs, p->region_bytes);
	p->run = runs.v;
	p->n_runs = runs.n;
	pdf_build_entries(p, &tabs, f);
	CK(p->n_entries == 1u, "build_entries: one entry for one stream (%u)", p->n_entries);
	pdf_read_docinfo(p, f);
	CK(p->docinfo[KOF_PDF_DOCINFO_TITLE].len == 5u && !memcmp(f.p + p->docinfo[KOF_PDF_DOCINFO_TITLE].off, "Hello", 5) &&
	   p->docinfo[KOF_PDF_DOCINFO_TITLE].hex == 0, "docinfo: /Title is the range inside the parentheses");
	CK(p->docinfo[KOF_PDF_DOCINFO_PRODUCER].len == 4u && p->docinfo[KOF_PDF_DOCINFO_PRODUCER].hex == 1 &&
	   !memcmp(f.p + p->docinfo[KOF_PDF_DOCINFO_PRODUCER].off, "4142", 4), "docinfo: /Producer is hex, and says so");
	CK(p->docinfo[KOF_PDF_DOCINFO_AUTHOR].len == 0u, "a key the document lacks is empty");

	ctx.file_header = p;
	CK(pdf_entries(&ctx, &ent) == 0u, "pdf_entries answers nothing for a view the parse has not marked valid");
	p->valid = 1;
	ne = pdf_entries(&ctx, &ent);
	CK(ne == 1u && ent == p->entry && pdf_entries(&ctx, NULL) == 0u, "pdf_entries is the view's table, and needs somewhere to put it");
	ctx.file_header = NULL;
	CK(pdf_entries(&ctx, &ent) == 0u, "no view, no entries");

	/* and the whole parse says the same */
	CK(kof_pdf_parse(f, q, &qctx) == 1 && qctx.entries == pdf_entries, "kof_pdf_parse accepts it and installs pdf_entries");
	CK(q->startxref == p->startxref && q->eof_off == p->eof_off, "startxref and %%EOF agree");
	CK(q->n_objects == p->n_objects && q->n_streams == p->n_streams && q->n_entries == p->n_entries && q->trailer_off == p->trailer_off &&
	   q->trailer_len == p->trailer_len, "the whole parse and the steps by hand agree on every count");
	for (i = 0; i < KOF_PDF_DOCINFO_COUNT; i++)
		CK(q->docinfo[i].off == p->docinfo[i].off && q->docinfo[i].len == p->docinfo[i].len, "docinfo %u agrees", i);
	/* the partition is not compared: pdf_resolve_refs, which classifies the streams, is a static step of the parse */
	CK(p->mem.held > 0 && q->mem.held > 0 && q->mem.held >= p->mem.held - 64u,
	   "both views hold their tables, and the account says so (%llu, %llu)", (unsigned long long)p->mem.held,
	   (unsigned long long)q->mem.held);

	/* an object cut at the end of the file is clipped, not read past it */
	{
		struct kof_pdf_info *r = calloc(1, sizeof *r);
		struct kof_runs rr;
		struct pdf_tabs rt;
		kof_buf cut = kof_buf_make(DOC, 100);

		if (r) {
			memset(&rt, 0, sizeof rt);
			rt.obj_limit = cut.n / KOF_PDF_OBJECT_MIN + 1u;
			r->version = KOF_PDF_INFO_VERSION;
			kof_runs_init_dyn(&rr, &r->mem, KOF_PDF_CLS_COUNT, 4096u);
			pdf_read_trailer(cut, r, &rr);
			pdf_walk_objects(cut, r, &rt, &rr, 0);
			pdf_claim_xref(cut, r, &rr, 0);
			CK(r->n_objects <= 3u && (r->n_objects == 0u || r->object[r->n_objects - 1u].off + r->object[r->n_objects - 1u].len <= cut.n),
			   "a document cut at 100 bytes: no object reaches past the cut");
			free(rr.v);
			free(r->object);
			free(r);
		}
	}
	kof_pdf_release(p);
	kof_pdf_release(q);
	free(p);
	free(q);
}

static void dict(void)
{
	struct kof_pdf_info *p = calloc(1, sizeof *p);
	struct kof_pdf_object o;
	uint64_t declared = 99;
	const char *d1 = "<< /Length 8 /Filter /FlateDecode >>";
	const char *d2 = "<< /Length 12 0 R /Filter [/ASCII85Decode /LZWDecode] >>";
	const char *d3 = "<< /Type /Catalog >>";

	CK(p != NULL, "an info");
	if (!p)
		return;
	memset(&o, 0, sizeof o);
	pdf_dict_scan(kof_buf_make(d1, strlen(d1)), 0, strlen(d1), &o, p, &declared);
	CK(o.filters == KOF_PDF_F_FLATE && declared == 8u, "one filter and a declared length of 8 (filters 0x%x, length %llu)", o.filters, (unsigned long long)declared);
	memset(&o, 0, sizeof o);
	declared = 99;
	pdf_dict_scan(kof_buf_make(d2, strlen(d2)), 0, strlen(d2), &o, p, &declared);
	CK(o.filters == (KOF_PDF_F_ASCII85 | KOF_PDF_F_LZW), "an array of two filters gives both bits (0x%x)", o.filters);
	CK(declared == 0u && (p->anomalies & KOF_PDF_ANOM_LENGTH_INDIR), "an indirect /Length is not a length, and is recorded");
	memset(&o, 0, sizeof o);
	declared = 99;
	pdf_dict_scan(kof_buf_make(d3, strlen(d3)), 0, strlen(d3), &o, p, &declared);
	CK(o.filters == 0u, "a dictionary with no filter has none");
	free(p);
}

int main(void)
{
	make_doc();
	lexer();
	numbers();
	filters();
	walk();
	dict();
	printf("pdf_units: %u checks, %u failed\n", he_checks, he_fails);
	return he_fails != 0;
}
