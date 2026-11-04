#define _GNU_SOURCE

/*
 * kofeditor_decl.c - declarations of a draft: the pattern a declaration stands for, its hex text, where it is found, and the edit and removal of one.
 *
 * A part of the diagnose panel's draft model (see kofeditor.h for why it is apart from
 * the viewer); the types and what the parts share are in kofeditor_private.h.
 * Moved verbatim from kofeditor.c.
 */

#include "kofeditor_private.h"



/*
 * The pattern a declaration stands for, compiled the way the database will.
 *
 * Shared because two locators need it and a second reading of the same
 * declaration is a second thing to keep in step - which is how the panel came
 * to report "found" about markers the scan would miss in the first place.
 */
int decl_pattern(const struct decl *d, uint8_t *prog,
			const uint8_t **pat, uint32_t *plen,
			uint8_t *kind, uint8_t *flags)
{
	*flags = 0;
	if (d->hex && d->hexs[0]) {
		*plen = kof_hex_compile(d->hexs, prog, KOF_HEX_MAX_PROG, NULL);
		if (!*plen)
			return 0;       /* it will not compile; it cannot match */
		*pat = prog;
		*kind = KOF_STR_HEX;
	} else {
		*pat = d->bytes;
		*plen = d->nbytes;
		*kind = KOF_STR_LITERAL;
		if (!d->hex) {
			if (d->icase)
				*flags |= KOF_STR_ICASE;
			if (d->fullword == KOF_WORD_FULLWORD)
				*flags |= KOF_STR_FULLWORD;
			else if (d->fullword == KOF_WORD_TOKEN)
				*flags |= KOF_STR_TOKEN;
		}
	}
	return *pat && *plen && *plen <= 0xffffu;
}















/*
 * A hex pattern's concrete leading bytes, for locating it in the object.
 *
 * Whitespace is skipped, because the spelling in a file has it: bases/ writes
 * "2E 2E 5C" and reading that two characters at a time gives 2E 02 0E 5C - four
 * bytes, none of them the marker, so the row said "4" and reported the pattern
 * as absent from an object it is in.
 *
 * Stops at the first character that is not a hex digit, which is how a wildcard
 * or a gap ends the concrete part. Short is the honest answer there: there is no
 * byte a "??" is equal to, and inventing a 00 would be a marker the rule never
 * had. What the pattern IS remains in decl.hexs; this is only what can be
 * searched for.
 */
/*
 * A hex pattern, read by THE ENGINE'S COMPILER.
 *
 * What stood here read the text itself and kept only the concrete bytes,
 * stopping at the first character that was not a hex digit. That is right for
 * a pattern with no wildcard in it and quietly wrong for every pattern that
 * has one: "2E ?? 5C" came back as the single byte 2E, so the row said the
 * marker was one byte long and the search went looking for that one byte -
 * editing a working pattern to add a wildcard made it stop matching at the
 * wildcard.
 *
 * The repair is not a better parser here. kof_hex_compile is the parser, it
 * already knows "??" and "?4" and "[4-6]" and "( E8 | E9 )", it is what the
 * build runs over the same text, and a second reading of the same syntax in
 * this file would be a second thing to keep correct. So the panel compiles the
 * pattern exactly as the database will and asks the compiler how long a match
 * spans; the bytes array goes away, because a pattern with a wildcard has none.
 */
int decl_from_hexs(struct decl *d)
{
	uint8_t prog[KOF_HEX_MAX_PROG];
	struct kof_hex_stat st;

	free(d->bytes);
	d->bytes = NULL;
	d->nbytes = 0;
	if (!kof_hex_compile(d->hexs, prog, sizeof prog, &st)) {
		d->len = 0;
		d->span_max = 0;
		return 0;               /* kof_hex_error() says what is wrong */
	}
	d->len = st.min_span;
	d->span_max = st.max_span;
	return 1;
}



/*
 * Take the selection into the draft.
 *
 * The region comes from the tree row rather than from anything about the bytes,
 * because that is what the finished declaration will say: KOF_TARGET_RANGE names
 * where to look, and where somebody was looking when they found it is the
 * honest answer to that.
 */

/* ---- editing a declared string as text ------------------------------------ */

/*
 * Is this value one a person can type back?
 *
 * A literal is edited as the characters it is, so a byte that has no character
 * cannot survive the round trip: it would be shown as something, and whatever
 * that something was would be written back as itself. Refusing to open is the
 * only answer that does not quietly change the marker. Hex has no such problem
 * and is always editable - that is what hex is for.
 */
/*
 * THE SAME SET THE FILE ACCEPTS, which is printable ASCII and the three
 * whitespace bytes.
 *
 * This refused anything outside 0x20..0x7e, and that matched literal_safe until
 * literal_safe grew tab, newline and carriage return - a marker that crosses a
 * line is an ordinary thing to declare and is now written as "\t", "\n", "\r".
 * The two halves then disagreed: the panel would DECLARE such a marker and
 * then refuse to let it be edited, saying it was not text about something that
 * plainly is.
 *
 * The box shows them as escapes and decl_edit_commit reads them back - see
 * decl_edit_open - because a raw newline in a one-line field is not editable
 * whatever this answers.
 */
int decl_text_editable(const struct decl *d)
{
	uint32_t i;

	if (d->hex)
		return 1;
	for (i = 0; i < d->nbytes; i++) {
		uint8_t c = d->bytes[i];

		if (c == '\t' || c == '\n' || c == '\r')
			continue;
		if (c < 0x20 || c >= 0x7f)
			return 0;
	}
	return 1;
}



/* The vocabulary a family or variant name is allowed to be spelled in. Empty is
 * not this function's business - a name that has not been typed yet is a
 * different message from one typed wrongly. */





void decl_locate(struct kof_editor *e, struct decl *d)
{
	struct object *ob = &e->obj[d->obj < (*e->n_obj) ? d->obj : 0];
	struct kof_match_ctx m, msym;
	struct kof_region_map map;
	struct kof_locate lo;
	uint8_t prog[KOF_HEX_MAX_PROG];
	const uint8_t *pat;
	uint32_t plen, h;
	uint8_t kind, flags = 0;

	d->at = KGENOME_BROKEN;
	d->sym = 0;
	d->off_rgn = 0;
	d->at_rgn[0] = 0;
	d->at_mask = 0;
	d->n_hits = 0;
	d->hits_clipped = 0;
	if (!d->len || !e->scratch)
		return;
	if (!decl_pattern(d, prog, &pat, &plen, &kind, &flags))
		return;

	/*
	 * ONE CALL FOR WHERE A MARKER IS: the rule is kof_locate_str's and this
	 * only presents what it returns; see the note above it in kofinspect.h.
	 */
	memset(&m, 0, sizeof m);
	memset(&msym, 0, sizeof msym);
	if (!kof_match_state_init(&m, 0, 0))
		return;
	if (!kof_match_state_init(&msym, 0, 0)) {
		kof_match_state_free(&m);
		return;
	}
	kof_region_map_build(&map, &ob->ctx, ob->fmt);
	kof_locate_str(&m, &msym, &map, kof_buf_make(ob->buf.p, ob->buf.n),
		       ob->sym, ob->sym_n, d->mask, pat, (uint16_t)plen, kind,
		       flags, d->len, d->span_max, e->scratch,
		       KOF_SCAN_MAX_EXTENTS, &lo);
	kof_region_map_free(&map);
	kof_match_state_free(&msym);
	kof_match_state_free(&m);

	d->at = lo.at;
	d->at_mask = lo.at_mask;
	d->sym = lo.sym;
	d->off_rgn = lo.off_rgn;
	d->cur_hit = lo.cur_hit;
	d->hits_clipped = lo.clipped;
	d->n_hits = lo.n_hits < DECL_HITS_MAX ? lo.n_hits : DECL_HITS_MAX;
	for (h = 0; h < d->n_hits; h++) {
		d->hits[h] = lo.hits[h];
		d->hit_len[h] = lo.hit_len[h];
	}
	/* The label is presentation, so it is made here from the mask the
	 * locator returned rather than carried through it. */
	if (d->at_mask)
		rng_name_of(ob->fmt, d->at_mask, d->at_rgn, sizeof d->at_rgn);
}

/* How many markers are in this condition. */
/* Markers not yet in any condition. */
uint32_t decl_free(struct kof_editor *e)
{
	uint32_t i, n = 0;

	for (i = 0; i < e->dr.n_decl; i++)
		n += e->dr.decl[i].grp == 0;
	return n;
}

/*
 * Parse the scratch back into the declaration.
 *
 * A hex pattern keeps its spelling in `hexs` - that is what generation writes
 * and what a wildcard lives in - and the concrete prefix of it is decoded into
 * `bytes` so the row can still say how long it is and where it is. A literal is
 * its characters and nothing else.
 *
 * Either way the bytes have changed, so where they are is asked again rather
 * than carried over: the whole point of an edit is that it may no longer be the
 * same run, and a stale offset would light the wrong bytes in the pane.
 */
void decl_edit_commit(struct kof_editor *e, uint32_t i)
{
	struct decl *d;
	size_t n = strlen(e->dr.sedit);
	uint8_t *nb;

	if (i >= e->dr.n_decl)
		return;
	d = &e->dr.decl[i];
	/* Every refusal below comes BEFORE the marker is touched: "unchanged" is the status line's word and the marker's too. */
	if (!n) {
		/* A marker that never had text (a new one, left empty) is not kept: it would stay as a row of length 0. */
		if (!d->len) {
			decl_remove(e, i);
			say_note(e, "String %u had no text - not kept", i + 1u);
			return;
		}
		say_note(e, "String %u would be empty - unchanged", i + 1u);
		return;
	}
	if (d->hex) {
		/*
		 * Refused rather than truncated. A hex pattern cut off halfway
		 * is still a valid pattern - a shorter one, matching something
		 * else - so writing it would replace the marker with a marker
		 * nobody asked for, silently.
		 */
		if (n >= sizeof d->hexs) {
			say_note(e, "Hex pattern over %u characters - unchanged",
				 (unsigned)(sizeof d->hexs - 1u));
			return;
		}
		/*
		 * Refused by the same compiler the build uses, and in its own
		 * words. A pattern the panel accepted and the build then threw
		 * out is a rule that looked right in the viewer and does not
		 * exist in the database.
		 */
		{
			uint8_t prog[KOF_HEX_MAX_PROG];
			struct kof_hex_stat st;

			if (!kof_hex_compile(e->dr.sedit, prog, sizeof prog, &st)) {
				/*
				 * Capitalised here and not at the source: the
				 * same string is printed by ksigbuilder as
				 * "file:line: message", where lowercase is the
				 * convention every compiler follows. The status
				 * line is a sentence on its own and starts like
				 * one.
				 */
				char why[160];

				snprintf(why, sizeof why, "%s", kof_hex_error());
				if (why[0] >= 'a' && why[0] <= 'z')
					why[0] = (char)(why[0] - 32);
				say_note(e, "%s", why);
				return;
			}
			if (!st.min_span) {
				say_note(e, "String %u would be empty - unchanged", i + 1u);
				return;
			}
		}
		memcpy(d->hexs, e->dr.sedit, n + 1u);
		(void)decl_from_hexs(d);
	} else {
		size_t r, w = 0;

		nb = realloc(d->bytes, n + 1u);
		if (!nb)
			return;
		d->bytes = nb;
		/*
		 * The escapes the box shows, read back - see decl_edit_open.
		 * Only ever shortens, so the buffer sized for the text holds
		 * the bytes.
		 */
		for (r = 0; r < n; r++) {
			char c = e->dr.sedit[r];

			if (c == '\\' && r + 1u < n) {
				char nx = e->dr.sedit[r + 1u];

				if (nx == 't') { c = '\t'; r++; }
				else if (nx == 'n') { c = '\n'; r++; }
				else if (nx == 'r') { c = '\r'; r++; }
				else if (nx == '\\') { c = '\\'; r++; }
			}
			d->bytes[w++] = (uint8_t)c;
		}
		d->len = (uint32_t)w;
		d->nbytes = d->len;
	}
	decl_locate(e, d);
}

/*
 * ROOM FOR `want` DECLARED MARKERS. Same shape as blk_reserve: the table follows what the author declares, grows by doubling and, when memory
 * refuses, by exactly what was asked; a refusal keeps the rows held and the draft SAYS so. Answers 1 when `want` rows fit.
 */
int decl_reserve(struct kof_editor *e, uint32_t want)
{
	struct decl *p;
	size_t n;

	if (want <= e->dr.cap_decl)
		return 1;
	n = e->dr.cap_decl ? e->dr.cap_decl : 8u;
	while (n < want && n <= SIZE_MAX / 4u / sizeof *p)
		n *= 2u;
	p = n >= want ? realloc(e->dr.decl, n * sizeof *p) : NULL;
	if (!p) {
		n = want;
		p = n <= SIZE_MAX / sizeof *p ? realloc(e->dr.decl, n * sizeof *p) : NULL;
	}
	if (!p) {
		say_err(e, "out of memory: the strings table keeps its %u rows, the new marker is not declared", e->dr.n_decl);
		return 0;
	}
	e->dr.decl = p;
	e->dr.cap_decl = (uint32_t)n;
	return 1;
}

/* A new, zeroed row at the end of the table, counted; NULL (and said) when the table cannot grow. */
struct decl *decl_push(struct kof_editor *e)
{
	struct decl *d;

	if (!decl_reserve(e, e->dr.n_decl + 1u))
		return NULL;
	d = &e->dr.decl[e->dr.n_decl++];
	memset(d, 0, sizeof *d);
	return d;
}

void decl_remove(struct kof_editor *e, uint32_t i)
{
	/* A box open on a row that is about to move is a box on the wrong
	 * row - see kof_editor.edit. */
	if (e->edit)
		*e->edit = 0;
	if (i >= e->dr.n_decl)
		return;
	free(e->dr.decl[i].bytes);
	memmove(&e->dr.decl[i], &e->dr.decl[i + 1u],
		(e->dr.n_decl - i - 1u) * sizeof e->dr.decl[0]);
	e->dr.n_decl--;
	if (e->dr.sel_decl >= e->dr.n_decl && e->dr.n_decl)
		e->dr.sel_decl = e->dr.n_decl - 1u;
}
