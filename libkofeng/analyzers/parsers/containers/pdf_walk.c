/*
 * pdf_walk.c - the objects of a PDF: every "N G obj", where its stream ends and
 * what its bytes are claimed as.
 *
 * WHAT THIS SERVES: the scan the whole parse rests on. An object is an "obj"
 * confirmed by the two numbers in front of it, its dictionary is read by
 * pdf_dict_scan, its stream's extent is the declared length when the bytes bear
 * it out and the next "endstream" when they do not, and a number defined twice
 * is noted rather than trusted.
 */

#include "pdf_int.h"

/*
 * Read the `N G obj` that ends at `at`, where `at` is the 'o' of "obj".
 *
 * Walks BACKWARDS, because that is the direction the anchor gives: "obj" is what was
 * searched for, and the two numbers in front of it are what make it an object header
 * rather than the word appearing in a stream. Returns where the header starts, or
 * KGENOME_BROKEN when the bytes in front are not two numbers.
 */
static uint64_t obj_header_start(kof_buf f, uint64_t at, uint32_t *num,
				 uint32_t *gen)
{
	uint64_t i = at;
	uint64_t g_end, g_start, n_end, n_start;
	uint32_t v;

	if (i == 0)
		return KGENOME_BROKEN;
	/* whitespace, then the generation number */
	while (i > 0 && pdf_is_ws(f.p[i - 1u]))
		i--;
	if (i == at)
		return KGENOME_BROKEN;         /* "obj" must be preceded by space */
	g_end = i;
	while (i > 0 && kof_is_digit(f.p[i - 1u]))
		i--;
	g_start = i;
	if (g_start == g_end || g_end - g_start > 10u)
		return KGENOME_BROKEN;

	while (i > 0 && pdf_is_ws(f.p[i - 1u]))
		i--;
	if (i == g_start)
		return KGENOME_BROKEN;
	n_end = i;
	while (i > 0 && kof_is_digit(f.p[i - 1u]))
		i--;
	n_start = i;
	if (n_start == n_end || n_end - n_start > 10u)
		return KGENOME_BROKEN;

	v = 0;
	for (i = n_start; i < n_end; i++)
		v = v * 10u + (uint32_t)(f.p[i] - '0');
	*num = v;
	v = 0;
	for (i = g_start; i < g_end; i++)
		v = v * 10u + (uint32_t)(f.p[i] - '0');
	*gen = v;
	return n_start;
}

/*
 * Is the "stream" at `at` the KEYWORD, or the word inside something else?
 *
 * Two ways it is not the keyword, and both happen in ordinary documents.
 *
 * "endstream" contains it, which is the only one this used to test for - by
 * looking for a preceding "end".
 *
 * A NAME OR A STRING CAN CONTAIN IT, and that one was missed.
 * `/Subtype /octet-stream` is what almost every binary attachment a PDF
 * carries declares itself as, and matching inside that value cut the
 * dictionary short at it: /Length was never reached, so the stream fell back
 * to being measured by search, and THE REST OF THE DICTIONARY was filed as
 * stream data. Measured on a document carrying a 4.8MB executable - 4.4MB of
 * the payload landed in the OBJECTS region and the stream was reported 405KB
 * long. No anomaly fired, because nothing about it looked wrong from inside.
 *
 * So the keyword is recognised by what the format says surrounds it, rather
 * than by a list of things it might be part of. It follows the dictionary, so
 * whitespace or the '>' that closed it comes before; and an end of line
 * follows it. The format says CRLF or LF and never a lone CR, but accepting
 * one costs nothing and a writer that emitted it still wrote the keyword.
 */
static int stream_kw_at(kof_buf f, uint64_t at)
{
	uint8_t before, after;

	/* No room for the end of line means no room for data either, so this is
	 * not a stream whatever else it is. */
	if (at + 6u >= f.n)
		return 0;
	before = at ? f.p[at - 1u] : (uint8_t)'\n';
	if (!pdf_is_ws(before) && before != '>')
		return 0;
	after = f.p[at + 6u];
	return after == '\r' || after == '\n';
}

/*
 * Does an "endstream" stand at `at`, allowing what the format puts in front
 * of it?
 *
 * /Length counts the data bytes and a writer then puts an end of line before
 * the keyword, so a corroboration demanding the keyword exactly at the
 * declared end would fail on ordinary documents. Whitespace rather than CRLF
 * alone, because a writer padding to a boundary is still one whose /Length is
 * right - and bounded to a few bytes, so no field can make this walk.
 */
static int endstream_at(kof_buf f, uint64_t at)
{
	uint64_t i = at, lim = kof_sat_add(at, 8u);

	if (lim > f.n)
		lim = f.n;
	while (i < lim && pdf_is_ws(f.p[i]))
		i++;
	return i + 9u <= f.n && memcmp(f.p + i, "endstream", 9u) == 0;
}

/* The stream inside one object: where it ends, and what its length said about that.
 * Returns where the object ends, which the stream may have moved. */
static uint64_t pdf_stream_extent(kof_buf file, struct kof_pdf_info *p,
				  struct kof_pdf_object *o, uint64_t start,
				  uint64_t s_kw, uint64_t end,
				  uint64_t declared)
{
	uint64_t s_end;

	uint64_t d = s_kw + 6u;

	/* The data begins after the EOL that must follow the
	 * keyword; both CRLF and LF appear. */
	if (d < file.n && file.p[d] == '\r')
		d++;
	if (d < file.n && file.p[d] == '\n')
		d++;

	/*
	 * THE KEYWORD BELONGS TO THE OBJECT, NOT TO NOBODY.
	 *
	 * The dictionary run ended where "stream" begins and the
	 * data run starts after the end of line that follows it,
	 * so the eight bytes between them - the word and its EOL
	 * - were owned by nothing. Fifteen streams in one
	 * ordinary document, 120 of its 161 unclaimed bytes: the
	 * single largest thing left in a region whose whole
	 * value is being nearly empty on a file with nothing to
	 * hide.
	 *
	 * The dictionary grows to cover it rather than a run of
	 * its own being added, so the two coalesce and it costs
	 * no extent. What pdf_dict_scan already read is unchanged -
	 * it was given the range that ends at the keyword, and a
	 * keyword holds no names.
	 */
	if (d > start)
		o->dict_len = d - start;

	s_end = pdf_find_bytes(file, d, file.n, "endstream", 9u);

	/*
	 * /Length, CORROBORATED RATHER THAN TRUSTED.
	 *
	 * The format says /Length decides and "endstream" is
	 * how a reader recovers when it is wrong, so searching
	 * alone was reading the fallback and calling it the
	 * answer: a stream whose DATA carries the nine bytes
	 * "endstream" got cut off at them, and everything past
	 * the decoy left the stream, never reached the
	 * decompressor, and raised nothing at all.
	 *
	 * Corroborated, because a length is a number the file
	 * chooses too and a huge one would pull the rest of the
	 * document into one opaque region - the same trick from
	 * the other end. So it wins only where an "endstream"
	 * really stands where it points, and the two disagreeing
	 * is itself the thing recorded.
	 */
	if (declared) {
		uint64_t dend = kof_sat_add(d, declared);

		if (dend <= file.n && endstream_at(file, dend)) {
			if (s_end != KGENOME_BROKEN && s_end < dend) {
				p->anomalies |=
				    KOF_PDF_ANOM_STREAM_DECOY;
				o->flags |=
				    KOF_PDF_OBJ_STREAM_DECOY;
			}
			s_end = dend;
		} else {
			/* Pointing at no keyword at all: damage
			 * as often as intent, so its own bit. */
			p->anomalies |= KOF_PDF_ANOM_LENGTH_BAD;
		}
	}

	if (s_end == KGENOME_BROKEN) {
		p->anomalies |= KOF_PDF_ANOM_STREAM_UNTERM;
		s_end = end;
	} else if (s_end + 9u > end) {
		/*
		 * THE STREAM BOUNDS THE OBJECT, NOT THE FIRST
		 * "endobj" IN THE FILE.
		 *
		 * `end` was taken before the stream had been
		 * located, by a search with nothing but the file to
		 * bound it - and compressed bytes carry the string
		 * "endobj" as readily as any other six. Taken from
		 * inside the stream it made the walk rewind into the
		 * stream body and read opaque bytes as dictionaries:
		 * a phantom object whose /Launch or /JS raised an
		 * anomaly about a document that declared neither, a
		 * run colliding with the stream's own so the file was
		 * reported OVERLAP when nothing in it overlapped, and
		 * a slot spent out of the object table that a real
		 * stream-bearing object then could not have.
		 *
		 * Re-taken from past "endstream", which is the first
		 * offset the object's own structure resumes at.
		 */
		uint64_t e2 = pdf_find_bytes(file, s_end + 9u, file.n,
					 "endobj", 6u);

		if (e2 == KGENOME_BROKEN) {
			p->anomalies |= KOF_PDF_ANOM_TRUNCATED;
			end = file.n;
		} else {
			end = e2 + 6u;
		}
	}
	if (s_end > d) {
		o->stream_off = d;
		o->stream_len = s_end - d;
		o->flags |= KOF_PDF_OBJ_STREAM;
		p->n_streams++;
		o->len = end - start;
	}
	return end;
}

/* What an object claims: its dictionary and the whitespace after it, and the
 * tail of its stream. Returns where the next object may begin. */
static uint64_t pdf_claim_object(kof_buf file, struct kof_runs *runs,
				 struct kof_pdf_object *o, uint64_t start,
				 uint64_t end)
{
	uint64_t stop;

	/*
	 * WHERE THE NEXT OBJECT BEGINS, AND WHY THE GAP IS OURS.
	 *
	 * One or two bytes of end of line sit between "endobj" and the
	 * next "N G obj". Left to nobody they became a run in the
	 * complement, and that gap is exactly what stopped kof_runs_add
	 * from joining one object's tail to the next one's dictionary -
	 * so a document's runs went dict, stream, tail, GAP, dict, and
	 * every object cost three extents instead of the one its bytes
	 * describe. Measured on an ordinary 1.65MB document: 180 of its
	 * 240 UNCLAIMED extents were four bytes or fewer of this, and
	 * OBJECTS resolved to 238 extents where 58 say the same thing.
	 *
	 * Not a cosmetic count. Every extent is a range a search has to be
	 * given and a row of the run pool, and a benign PDF was reaching the
	 * cap that once bounded both. Whitespace between two structures is
	 * structure, so it goes to OBJECTS and consecutive objects coalesce
	 * into one run.
	 */
	stop = end;
	while (stop < file.n && pdf_is_ws(file.p[stop]))
		stop++;
	/* An object with no stream owns the gap as part of its own run;
	 * one with a stream has a tail below that reaches the same
	 * place. Only the RUN grows - the dictionary has already been
	 * read, and whitespace holds no names. */
	if (!o->stream_len && stop > start)
		o->dict_len = stop - start;

	kof_runs_add(runs, file.n, o->dict_off, o->dict_len,
		     KOF_PDF_CLS_OBJ_TABLE);
	/*
	 * THE STREAM'S OWN RUN IS NOT ADDED HERE.
	 *
	 * It cannot be. Which region it belongs in depends on the
	 * category, and the category of a script stream is not known
	 * until the /JS that points at it has been found - which may be
	 * in an object that comes LATER in the file. Added from here it
	 * was filed as CONTENT and the resolution below then changed a
	 * category that no longer decided anything: the region said
	 * CONTENT and the object table said SCRIPT, and the two
	 * disagreed with nothing to notice it.
	 *
	 * So the dictionary and the tail are claimed here, where they
	 * are known, and every stream run is added after the pass that
	 * settles categories. kof_runs_settle sorts, so nothing depends
	 * on the order the two are added in.
	 */
	/* The tail of the object - "endstream endobj" - is structure. */
	if (o->stream_len) {
		uint64_t tail = o->stream_off + o->stream_len;

		if (stop > tail)
			kof_runs_add(runs, file.n, tail, stop - tail,
				     KOF_PDF_CLS_OBJ_TABLE);
	}
	return stop;
}

/* The objects: every "obj" confirmed by the two numbers before it. */
void pdf_walk_objects(kof_buf file, struct kof_pdf_info *p, struct pdf_tabs *t,
		      struct kof_runs *runs, uint64_t hdr)
{
	uint64_t at;

/*
 * The objects.
 *
 * Anchored on "obj" and confirmed by the two numbers in front of it, which
 * is what keeps the word appearing inside a stream from starting a phantom
 * object. Each iteration advances past the anchor whether or not it was
 * real, so the walk ends on the object.
 */
	at = hdr;
	while (at < file.n) {
		uint64_t tok = pdf_find_bytes(file, at, file.n, "obj", 3u);
		uint64_t start, end, stop, dict_end, s_kw;
		uint64_t declared = 0;
		struct kof_pdf_object *o, spill;
		uint32_t num = 0, gen = 0;

		if (tok == KGENOME_BROKEN)
			break;
		at = tok + 3u;                  /* advance first, always */

		start = obj_header_start(file, tok, &num, &gen);
		if (start == KGENOME_BROKEN)
			continue;                /* "obj" inside something else */

		/* Where this object ends. A missing endobj is ordinary in a damaged
		 * file, so the next object's header bounds it instead. */
		end = pdf_find_bytes(file, tok + 3u, file.n, "endobj", 6u);
		if (end == KGENOME_BROKEN) {
			p->anomalies |= KOF_PDF_ANOM_TRUNCATED;
			end = file.n;
		} else {
			end += 6u;
		}

		/*
		 * A ROW THE TABLE CANNOT TAKE, and the walk CONTINUES.
		 *
		 * The table grows with the file (the bound is what the file can hold, see
		 * struct pdf_tabs), so this is the ledger refusing, or the allocator; it is not
		 * a number of objects. Breaking out was the obvious thing and it cost two: the
		 * rest of the document became one UNCLAIMED region, so a signature aimed at an
		 * object dictionary could not reach anything past the last stored object - and
		 * declared_objects, which this view promises is what the walk found whatever
		 * the tables took, could never differ from n_objects because the walk stopped
		 * at the same moment the count did. A row is written into `spill` and
		 * discarded, so the regions and the count are still right when the table is not.
		 */
		if (p->n_objects >= t->cap_obj) {
			void *tab = p->object;

			if (kof_tab_grow(&p->mem, &tab, &t->cap_obj, sizeof *p->object,
					 (uint64_t)p->n_objects + 1u, t->obj_limit))
				p->object = (struct kof_pdf_object *)tab;
		}
		if (p->n_objects >= t->cap_obj) {
			p->anomalies |= KOF_PDF_ANOM_OBJECTS_FULL;
			o = &spill;
		} else {
			o = &p->object[p->n_objects];
		}
		memset(o, 0, sizeof *o);
		o->off = start;
		o->len = end - start;
		o->num = num;
		o->gen = gen;

		/* A stream, if there is one inside this object. */
		s_kw = pdf_find_bytes(file, tok + 3u, end, "stream", 6u);
		/* Only the keyword begins the data - see stream_kw_at, which
		 * says what else the word turns up inside and what it cost. */
		while (s_kw != KGENOME_BROKEN && !stream_kw_at(file, s_kw))
			s_kw = pdf_find_bytes(file, s_kw + 6u, end, "stream", 6u);

		dict_end = (s_kw == KGENOME_BROKEN) ? end : s_kw;

		/*
		 * THE DICTIONARY IS READ BEFORE THE STREAM IS MEASURED.
		 *
		 * It has to be. /Length lives in the dictionary and is what the
		 * format says decides where the stream ends, so a parse that
		 * measured first and read the dictionary afterwards could only
		 * ever use the search - which is the recovery path and not the
		 * answer.
		 */
		o->dict_off = start;
		o->dict_len = dict_end > start ? dict_end - start : 0;
		pdf_dict_scan(file, o->dict_off, o->dict_len, o, p, &declared);

		if (s_kw != KGENOME_BROKEN)
			end = pdf_stream_extent(file, p, o, start, s_kw, end,
						declared);

		stop = pdf_claim_object(file, runs, o, start, end);

		if (o != &spill)
			p->n_objects++;
		p->declared_objects++;
		if (stop > at)
			at = stop;
	}
}
