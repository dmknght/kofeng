/*
 * ksb_read.c - Reading one declaration's arguments out of the source text:
 *    strings, enums, masks, names.
 */

#include "ksb.h"
#include <databases/diagsrc.h>

/*
 * THE REGION NAMES a range may be built from are the library's table now (kof_dsrc_region_at, databases/diagsrc.h): a
 * diagnose's KOF_TARGET_RANGE and a block's regions are read with the same words, so there is ONE table and not a copy
 * in the builder beside the reader's. The history of the table (a hand written copy that fell behind the headers, then
 * one generated from each format's own region list) is in databases/diagsrc_form.c, where it lives.
 */

/*
 * Find argument number `want` (1-based) of a macro invocation starting at p.
 *
 * Picking a literal by scanning for the first quote was wrong in the worst way: a
 * call like kof_find_str(rgn_sec_named(ctx, ".comment"), "GCC: (GNU)") compiled and
 * searched for ".comment". No error, just a signature looking for the wrong bytes.
 * That spelling is gone, but the hazard is not: any argument before the literal may
 * itself contain quotes.
 *
 * So the argument list is walked properly: balance parentheses from the opening one,
 * split on commas at depth 1. Strings are skipped while balancing, since a pattern is
 * free to contain a comma or a parenthesis.
 */
/*
 * HOW MANY ARGUMENTS THE MACRO WAS GIVEN, without complaining about it.
 *
 * nth_arg reports "too few arguments" when what was asked for is not there,
 * which is right when the argument is required and wrong when the point is to
 * find out whether it was written. KOF_DEFINE_HEXSTR takes two forms - with
 * and without its options - and telling them apart is a question, not a fault.
 *
 * The scan is nth_arg's, minus the reporting: string literals are skipped
 * whole so a comma inside one is not an argument separator.
 */
int ksb_arg_count(const char *p)
{
	const char *open = strchr(p, '(');
	int depth = 0, n = 0;

	if (!open)
		return 0;
	for (p = open; *p; p++) {
		if (*p == '"') {
			p++;
			while (*p && *p != '"') {
				if (*p == '\\' && p[1])
					p++;
				p++;
			}
			if (!*p)
				return n;
			continue;
		}
		if (*p == '(') {
			if (++depth == 1)
				n = 1;
			continue;
		}
		if (*p == ')') {
			if (--depth == 0)
				break;
			continue;
		}
		if (*p == ',' && depth == 1)
			n++;
	}
	return n;
}

static const char *nth_arg(struct ksb_ctx *ksb, const char *p, int want,
			   int line)
{
	const char *open = strchr(p, '(');
	const char *start = 0;
	int depth = 0, idx = 0;

	if (!open) {
		ksb_err(ksb, line, "pattern macro is not applied");
		return 0;
	}
	for (p = open; *p; p++) {
		if (*p == '"') {
			/* Skip the whole literal, including escaped quotes. */
			p++;
			while (*p && *p != '"') {
				if (*p == '\\' && p[1])
					p++;
				p++;
			}
			if (!*p) {
				ksb_err(ksb, line, "unterminated string literal");
				return 0;
			}
			continue;
		}
		if (*p == '(') {
			if (++depth == 1) {
				idx = 1;
				start = p + 1;
				if (idx == want)
					return start;
			}
			continue;
		}
		if (*p == ')') {
			if (--depth == 0)
				break;
			continue;
		}
		if (*p == ',' && depth == 1) {
			if (++idx == want)
				return p + 1;
		}
	}
	if (depth != 0) {
		ksb_err(ksb, line, "unbalanced parentheses in pattern macro");
		return 0;
	}
	ksb_err(ksb, line, "pattern macro has too few arguments");
	return 0;
}

/*
 * Read the pattern literal, which is argument 2 of
 * KOF_DEFINE_STR(name, "pat", casing, word).
 *
 * It must be a literal at that position and nowhere else - not "the first literal
 * found" - because a later argument may legitimately expand to something containing
 * quotes, and because being lenient here is what produced the silent wrong-pattern
 * bug above. Anything else is an error that stops the build.
 *
 * THREE ESCAPES, AND ONLY THREE.
 *
 * \\  \"  \?  - exactly the ones needed to write a printable ASCII byte into a C
 * string literal, and nothing else. \n, \x41, \0 stay rejected for the reason they
 * always were: this language has hex patterns, and deciding what a numeric escape
 * means in a pattern language that already spells bytes as bytes is a second way
 * to say one thing.
 *
 * They are here because without them three characters could not appear in a
 * marker at all. A quote and a backslash cannot be written raw - the reader ends
 * the literal on the first and C ends it on the second - and "?" cannot be
 * written in pairs, because signatures compile with -std=c11 and "??" followed by
 * one of nine characters is replaced by a trigraph in translation phase 1, before
 * the compiler ever sees a literal. \? breaks the pair without changing the byte.
 *
 * The cost of not having them was measured on real markers: a GPON exploit's
 * "POST /GponForm/diag_Form?images/ HTTP/1.1" and a Huawei one's
 * realm="HuaweiHomeGateway" could only be declared as hex - which compiles to a
 * matcher program rather than bytes, so the marker no longer reads as the string
 * it is anywhere the tools show it.
 */
int ksb_read_literal(struct ksb_ctx *ksb, const char *p, int line,
		     struct pat *out)
{
	const char *q;
	uint32_t n = 0;

	p = nth_arg(ksb, p, 2, line);
	if (!p)
		return 0;

	/* Only whitespace may precede the quote. Scanning ahead for one would accept
	 * a non-literal second argument and silently take a literal from further
	 * along the line. */
	while (*p == ' ' || *p == '\t')
		p++;
	if (*p != '"') {
		ksb_err(ksb, line, "second argument of KOF_DEFINE_STR must be a string literal");
		return 0;
	}
	/* The literal ends at its first quote that is not escaped; what is between is read by the library's one reader of the
	 * escapes (the same six, the same bound, the same words in the refusal) - see kof_dsrc_lit_unescape. */
	q = p + 1;
	while (*q && *q != '"') {
		if (*q == '\\' && q[1])
			q++;
		q++;
	}
	if (*q == '"') {
		const char *why = NULL;
		long got = kof_dsrc_lit_unescape(p + 1, (size_t)(q - (p + 1)), out->bytes, MAX_LITERAL, &why);

		if (got < 0) {
			ksb_err(ksb, line, why);
			return 0;
		}
		n = (uint32_t)got;
	}
	if (*q != '"') {
		ksb_err(ksb, line, "unterminated string literal");
		return 0;
	}
	if (n == 0) {
		ksb_err(ksb, line, "empty pattern");
		return 0;
	}
	out->len = n;
	return 1;
}

/*
 * Read the region mask, argument 2 of KOF_TARGET_RANGE, and OR it into the module
 * total as well.
 *
 * Only an OR of the names in rgn_names is accepted. Anything else - a variable, a
 * computed expression, an unknown name - is a hard error rather than being treated
 * as "no regions", and the direction of the risk is why.
 *
 * The host uses the module total to skip a module whose regions are all absent. If
 * an inferred total omitted a region the module really searches, then on an object
 * where only that region is present the module would be skipped and a detection
 * lost - a bug produced at build time, silent, and invisible in any single test.
 */
int ksb_read_mask(struct ksb_ctx *ksb, const char *p, int line,
		  struct rng *out)
{
	const char *a = nth_arg(ksb, p, 2, line);
	char tok[64];
	size_t n = 0;
	int i, done = 0;
	const char *nm;
	uint32_t bit = 0;

	if (!a)
		return 0;
	out->mask = 0;

	while (!done) {
		char c = *a;

		if (c == '|' || c == ',' || c == ')' || c == 0) {
			if (c == ',' || c == ')' || c == 0)
				done = 1;
			tok[n] = 0;
			if (n == 0) {
				ksb_err(ksb, line, "empty term in the region mask");
				return 0;
			}
			for (i = 0; (nm = kof_dsrc_region_at((size_t)i, &bit)) != NULL; i++)
				if (strcmp(tok, nm) == 0)
					break;
			if (!nm) {
				int k;
				/* The list below is the useful half; the
				 * sentence that used to be here explained why
				 * a range is an OR of names, which is not what
				 * a reader needs at the moment they mistyped
				 * one. */
				fprintf(stderr, "%s:%d: error: unknown region "
					"\"%s\". Known:\n",
					ksb->src_name, line, tok);
				for (k = 0; (nm = kof_dsrc_region_at((size_t)k, NULL)) != NULL; k++)
					fprintf(stderr, "    %s\n", nm);
				ksb->errors++;
				return 0;
			}
			out->mask |= bit;
			ksb->decl.scan_mask |= bit;
			n = 0;
			a++;
			continue;
		}
		if (c == ' ' || c == '\t' || c == '\\' || c == '\n' || c == '\r') {
			a++;
			continue;
		}
		if (n + 1 >= sizeof tok) {
			ksb_err(ksb, line, "region mask term too long");
			return 0;
		}
		tok[n++] = c;
		a++;
	}
	return 1;
}

/*
 * Read the hex text, argument 2 of KOF_DEFINE_HEXSTR.
 *
 * Located at that position and nowhere else, for the same reason a literal is: a
 * later argument may contain quotes, and scanning for the first one is how a
 * pattern silently becomes the wrong bytes.
 */
/*
 * THE REGEX TEXT, WHICH IS A C STRING LITERAL AND HAS TO BE READ AS ONE.
 *
 * A hex pattern has no backslash in it, so ksb_read_hex_text below takes the source
 * text between the quotes and hands it over as it stands. A regex does: "\." is
 * how it says "a dot, not any byte", and in a C file that is written "\\.".
 * Passed through raw, the compiler sees TWO characters - an escaped backslash
 * and then a dot meaning any byte - so the pattern silently becomes "a
 * backslash followed by anything", which matches nothing a reader expected.
 *
 * Only the two escapes that C forces are undone here - a backslash and a quote.
 * Every other sequence is left exactly as written, because it belongs to the
 * regex and not to C, and because a C source cannot contain any other backslash
 * sequence anyway: "\." is not a C escape and the compiler that builds the
 * module would refuse it first.
 */
int ksb_read_regex_text(struct ksb_ctx *ksb, const char *p, int line,
			char *out, size_t cap)
{
	const char *q = nth_arg(ksb, p, 2, line);
	size_t n = 0;

	if (!q)
		return 0;
	while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r')
		q++;
	if (*q != '"') {
		ksb_err(ksb, line, "the pattern must be a quoted string");
		return 0;
	}
	q++;
	while (*q && *q != '"') {
		char c = *q;

		if (c == '\\' && (q[1] == '\\' || q[1] == '"')) {
			c = q[1];
			q++;
		}
		if (n + 1u >= cap) {
			ksb_err(ksb, line, "the pattern is too long");
			return 0;
		}
		out[n++] = c;
		q++;
	}
	if (*q != '"') {
		ksb_err(ksb, line, "unterminated pattern");
		return 0;
	}
	out[n] = 0;
	if (!n) {
		ksb_err(ksb, line, "an empty pattern");
		return 0;
	}
	return 1;
}

int ksb_read_hex_text(struct ksb_ctx *ksb, const char *p, int line, char *out,
		      size_t cap)
{
	const char *q;
	size_t n = 0;

	q = nth_arg(ksb, p, 2, line);
	if (!q)
		return 0;
	while (*q == ' ' || *q == '\t')
		q++;
	if (*q != '"') {
		ksb_err(ksb, line, "second argument of KOF_DEFINE_HEXSTR must be a string "
				   "literal holding the hex pattern");
		return 0;
	}
	q++;
	while (*q && *q != '"') {
		if (n + 1 >= cap) {
			ksb_err(ksb, line, "hex pattern too long");
			return 0;
		}
		out[n++] = *q++;
	}
	if (*q != '"') {
		ksb_err(ksb, line, "unterminated hex pattern");
		return 0;
	}
	out[n] = 0;
	return 1;
}

/* Read a single enum name from argument `which`, matched against a table. */
/* n2 is optional - pass NULL for a two-valued option. The word option grew a
 * third value (KOF_WORD_TOKEN) and a second copy of this loop to read it would
 * be a second place for the spelling of an option to drift. */
int ksb_read_enum3(struct ksb_ctx *ksb, const char *p, int which, int line,
		   const char *what, const struct ksb_enum_names *names,
		   int *out)
{
	const char *n0 = names->n0, *n1 = names->n1, *n2 = names->n2;
	const char *a = nth_arg(ksb, p, which, line);
	char tok[64];
	size_t n = 0;

	if (!a)
		return 0;
	while (*a == ' ' || *a == '\t' || *a == '\n' || *a == '\r' || *a == '\\')
		a++;
	while (*a && *a != ',' && *a != ')' && *a != ' ' && *a != '\t' &&
	       *a != '\n' && *a != '\r') {
		if (n + 1 >= sizeof tok) {
			ksb_err(ksb, line, "option name too long");
			return 0;
		}
		tok[n++] = *a++;
	}
	tok[n] = 0;
	if (strcmp(tok, n0) == 0) { *out = 0; return 1; }
	if (strcmp(tok, n1) == 0) { *out = 1; return 1; }
	if (n2 && strcmp(tok, n2) == 0) { *out = 2; return 1; }
	if (n2)
		fprintf(stderr,
			"%s:%d: error: %s must be %s, %s or %s, not \"%s\"\n",
			ksb->src_name, line, what, n0, n1, n2, tok);
	else
		fprintf(stderr, "%s:%d: error: %s must be %s or %s, not \"%s\"\n",
			ksb->src_name, line, what, n0, n1, tok);
	ksb->errors++;
	return 0;
}

int ksb_read_enum(struct ksb_ctx *ksb, const char *p, int which, int line,
		  const char *what, const char *n0, const char *n1, int *out)
{
	const struct ksb_enum_names names = { n0, n1, NULL };

	return ksb_read_enum3(ksb, p, which, line, what, &names, out);
}

/* Read the declared name, argument 1. It becomes a C identifier, so it has to be
 * one. */
int ksb_read_ident(struct ksb_ctx *ksb, const char *p, int line, char *out,
		   size_t cap)
{
	const char *a = nth_arg(ksb, p, 1, line);
	size_t n = 0;

	if (!a)
		return 0;
	while (*a == ' ' || *a == '\t')
		a++;
	while (*a && *a != ',' && *a != ')' && *a != ' ' && *a != '\t') {
		int ok = (*a >= 'a' && *a <= 'z') || (*a >= 'A' && *a <= 'Z') ||
			 (*a >= '0' && *a <= '9') || *a == '_';
		if (!ok) {
			ksb_err(ksb, line, "the first argument must be a plain identifier: "
					   "it becomes the name kof_find uses");
			return 0;
		}
		if (n + 1 >= cap) {
			ksb_err(ksb, line, "declared name too long");
			return 0;
		}
		out[n++] = *a++;
	}
	out[n] = 0;
	if (n == 0) {
		ksb_err(ksb, line, "declaration without a name");
		return 0;
	}
	return 1;
}

/* Two declarations of the same kind cannot share a name: the name becomes a macro.
 * Strings and ranges are separate namespaces because they expand to different
 * identifiers, so a range and a string may be called the same thing - which is
 * awkward to read but not wrong, and forbidding it would be a rule with no failure
 * behind it. */
int ksb_str_name_taken(struct ksb_ctx *ksb, const char *nm)
{
	int i;
	for (i = 0; i < ksb->decl.npats; i++)
		if (strcmp(ksb->decl.pats[i].name, nm) == 0)
			return 1;
	return 0;
}

int ksb_rng_name_taken(struct ksb_ctx *ksb, const char *nm)
{
	int i;
	for (i = 0; i < ksb->decl.nrngs; i++)
		if (strcmp(ksb->decl.rngs[i].name, nm) == 0)
			return 1;
	return 0;
}

int ksb_blk_name_taken(struct ksb_ctx *ksb, const char *nm)
{
	int i;
	for (i = 0; i < ksb->decl.nblks; i++)
		if (strcmp(ksb->decl.blks[i].name, nm) == 0)
			return 1;
	return 0;
}

/*
 * The hashes: every argument from the third on.
 *
 * Read as unsigned 32 bit values however they are spelled, because a generator
 * writes them in hex and a person editing one may not. A value that does not
 * parse is a hard error rather than a zero, since a zero is a legal hash and
 * would sit in the block being silently wrong.
 */
int ksb_read_hashes(struct ksb_ctx *ksb, const char *p, int line,
		    struct blk *out)
{
	const char *a = nth_arg(ksb, p, 3, line);

	if (!a)
		return 0;
	out->n_hash = 0;
	/*
	 * Walked here rather than by asking nth_arg for argument 5, 6, 7 and so
	 * on: that call reports "too few arguments" when it runs off the end,
	 * which is the correct answer for a fixed arity macro and the wrong one
	 * for a list. The list ends at the closing parenthesis, so that is what
	 * this looks for.
	 */
	for (;;) {
		char *end;
		unsigned long long v;

		while (*a == ' ' || *a == '\t' || *a == '\n' || *a == '\r' ||
		       *a == ',')
			a++;
		if (!*a || *a == ')')
			break;
		if (out->n_hash >= KOF_MUTATION_MAX_HASH) {
			ksb_err(ksb, line, "more hashes than a block may carry");
			return 0;
		}
		v = strtoull(a, &end, 0);
		if (end == a) {
			ksb_err(ksb, line, "a hash that is not a number");
			return 0;
		}
		if (v > 0xffffffffull) {
			ksb_err(ksb, line, "a hash wider than 32 bits");
			return 0;
		}
		out->hash[out->n_hash++] = (uint32_t)v;
		a = end;
		/* A generated list writes them as 0x........u; skip whatever
		 * integer suffix the author or the generator used. */
		while (*a == 'u' || *a == 'U' || *a == 'l' || *a == 'L')
			a++;
	}
	if (out->n_hash < kgenome_mutation_block_min(out->mask)) {
		ksb_err(ksb, line, "too few hashes to score a block with; widen it");
		return 0;
	}
	return 1;
}

/* Read a note's name (kof_debug) into a NUL terminated buffer. */
int ksb_read_name(struct ksb_ctx *ksb, const char *p, int line, char *out,
		  size_t cap)
{
	const char *q;
	size_t n = 0;

	/* Argument 1 of kof_debug("name", value), located the same way as a pattern
	 * rather than by scanning for a quote: the value argument could contain one. */
	q = nth_arg(ksb, p, 1, line);
	if (!q)
		return 0;
	while (*q == ' ' || *q == '\t')
		q++;
	if (*q != '"') {
		ksb_err(ksb, line, "first argument of kof_debug must be a name literal");
		return 0;
	}
	q++;
	while (*q && *q != '"') {
		if (n + 1 >= cap) {
			ksb_err(ksb, line, "note name too long");
			return 0;
		}
		out[n++] = *q++;
	}
	if (*q != '"' || n == 0) {
		ksb_err(ksb, line, "malformed note name");
		return 0;
	}
	out[n] = 0;
	return 1;
}

/* Argument 1 of KOF_TARGET_NAME(TYPE, "family") - one of the bare identifiers in
 * maltype_names. An unknown one is a build error naming every type that IS known,
 * the same courtesy ksb_read_mask gives an unknown region name. */
int ksb_read_maltype(struct ksb_ctx *ksb, const char *p, int line, int *out)
{
	const char *a = nth_arg(ksb, p, 1, line);
	char tok[32];
	size_t n = 0;

	if (!a)
		return 0;
	while (*a == ' ' || *a == '\t' || *a == '\n' || *a == '\r')
		a++;
	while (*a && *a != ',' && *a != ')' && *a != ' ' && *a != '\t' &&
	       *a != '\n' && *a != '\r') {
		if (n + 1 >= sizeof tok) {
			ksb_err(ksb, line, "malware type name too long");
			return 0;
		}
		tok[n++] = *a++;
	}
	tok[n] = 0;
	if (kof_maltype_from_name(tok, out))
		return 1;
	fprintf(stderr, "%s:%d: error: \"%s\" is not a known malware type. "
			"Known:\n", ksb->src_name, line, tok);
#define X_SHOW(name, word) fprintf(stderr, "    %s\n", #name);
	KOF_MALTYPE_LIST(X_SHOW)
#undef X_SHOW
	ksb->errors++;
	return 0;
}

/* Argument 2 of KOF_TARGET_NAME(TYPE, "family") - a plain literal, read the same
 * restricted way ksb_read_hex_text and ksb_read_literal are: no escapes, quote to quote. */
int ksb_read_family(struct ksb_ctx *ksb, const char *p, int line, char *out,
		    size_t cap)
{
	const char *q = nth_arg(ksb, p, 2, line);
	size_t n = 0;

	if (!q)
		return 0;
	while (*q == ' ' || *q == '\t')
		q++;
	if (*q != '"') {
		ksb_err(ksb, line, "second argument of KOF_TARGET_NAME must be a family name "
				   "literal");
		return 0;
	}
	q++;
	while (*q && *q != '"') {
		if (n + 1 >= cap) {
			ksb_err(ksb, line, "family name too long");
			return 0;
		}
		out[n++] = *q++;
	}
	if (*q != '"' || n == 0) {
		ksb_err(ksb, line, "malformed family name");
		return 0;
	}
	out[n] = 0;
	/*
	 * THE CHARACTERS, checked here because this is the authority.
	 *
	 * kofviewer refuses them as they are typed, but a source written by
	 * hand never goes through the panel - and the name reaches a filesystem
	 * path and a C literal, so "anything between the
	 * quotes" was never the rule anyone meant. See kof_name_ok in kofsig.h.
	 */
	if (!kof_name_ok(out)) {
		ksb_err(ksb, line, "family name must be letters, digits, '-' or '_', "
				   "and at most 63 of them");
		return 0;
	}
	return 1;
}
