/*
 * ksb_read.c - Reading one declaration's arguments out of the source text:
 *    strings, enums, masks, names.
 */

#include "ksb.h"

/* The region lists, one per format: rgn_names[] below is generated from them
 * rather than restating them. */
#include <analyzers/parsers/binaries/elf/elf_parse.h>
#include <analyzers/parsers/binaries/pe/pe_parse.h>
#include <analyzers/parsers/containers/gzip_parse.h>
#include <analyzers/parsers/containers/docole_parse.h>
#include <analyzers/parsers/containers/zip_parse.h>
#include <analyzers/parsers/containers/tar_parse.h>
#include <analyzers/parsers/containers/sevenzip_parse.h>
#include <analyzers/parsers/containers/rar_parse.h>
#include <analyzers/parsers/containers/xz_parse.h>
#include <analyzers/parsers/scripts/script_parse.h>
#include <analyzers/parsers/containers/rtf_parse.h>
#include <analyzers/parsers/containers/pdf_parse.h>
#include <kofmod/amsi.h>   /* an event's two regions */

/*
 * The region names a range may be built from, bound to the enums rather than
 * copied from them.
 *
 * This table was a hand-written copy of the ELF values, with a comment claiming a
 * unit test kept it honest. No such test existed, PE regions were added to the
 * headers, and every PE signature failed to compile with "not a known region name".
 * Naming the enum removed the risk of a WRONG value, which is what that fix was
 * about, and left the other half untouched: a region added to a header is still
 * invisible here until somebody adds a line.
 *
 * That half then failed too, and larger. Four formats arrived - compound files,
 * zip, tar, 7z - with eighteen regions between them, and not one of them could be
 * named by a signature. The regions existed, the parsers filled them, kofexamine
 * printed them, and the only consumer that matters could not ask for them.
 *
 * No build-time check catches this table falling behind a format header's region
 * list - the coverage assert this comment used to claim existed here does not, on
 * either count that made the earlier claim wrong: nothing in this file or under
 * tests/ enumerates a format's declared regions and cross-checks them against
 * rgn_names[]. A region added to a header today is invisible to every signature
 * until someone remembers to add a line here, same failure this whole comment is
 * the history of - just not yet caught a third time.
 */
struct rgn_name {
	const char   *name;
	unsigned long bit;
};

#define RGN(x) { #x, (unsigned long)(x) },
/* the lists that hold the bare suffix (see ELF_REGIONS): the word is "KOF_" #x */
#define RGN_S(x) { "KOF_" #x, (unsigned long)(KGENOME_##x) },
/* the lists that hold the bare suffix (see ELF_REGIONS): the word is "KOF_" #x */
#define RGN_S(x) { "KOF_" #x, (unsigned long)(KGENOME_##x) },
static const struct rgn_name rgn_names[] = {
	RGN(KOF_SCAN_ALL)

	/*
	 * Not a format's, like the lists below are: the symbol block means the
	 * same thing for every input that has one, so kofsig.h defines these and
	 * any target may name them. A rule scoped to SYM_EXP says "this object
	 * exports these bytes", which is a narrower claim than the same bytes
	 * found loose in DATA.
	 */
	RGN(KOF_SCAN_SYM_IMP)
	RGN(KOF_SCAN_SYM_EXP)

	/*
	 * And every format's, taken from the format itself.
	 *
	 * These were fifty hand written lines, and the comment above this table
	 * said outright that nothing checked them against the headers - a region
	 * added to a format was invisible to every signature until someone
	 * remembered to add a line here. The lists moved into the headers so
	 * this could stop being a copy.
	 */
	ELF_REGIONS(RGN_S)
	PE_REGIONS(RGN_S)
	GZIP_REGIONS(RGN)
	DOCOLE_REGIONS(RGN)
	ZIP_REGIONS(RGN)
	TAR_REGIONS(RGN)
	SZ_REGIONS(RGN)
	RAR_REGIONS(RGN)
	XZ_REGIONS(RGN)
	RTF_REGIONS(RGN)
	PDF_REGIONS(RGN)
	SCRIPT_REGIONS(RGN)
	AMSI_REGIONS(RGN)
	/*
	 * AND A PROCESS'S, which were defined in proc.h and named here by
	 * nothing - the exact drift the note above says this table was
	 * generated to stop, caught on the next target that was added.
	 *
	 * The consequence was not a weaker rule, it was no rule at all:
	 * KOF_TARGET_RANGE(cmd, KOF_SCAN_PROC_CMDLINE) failed to build with
	 * "unknown region", so the command line - the one attacker-controlled
	 * field in the record, and the only one KOF_SCAN_PROC_CLAIMED offers -
	 * could not be written about.
	 *
	 * Three, not five: META and FD are FIELDS a rule reads through
	 * kof_proc(ctx), not byte ranges to search. proc.h argues that at
	 * length and KOF_SCAN_PROC_LIST is where it says so, so this names
	 * what that list names and does not second-guess it.
	 */
	KOF_SCAN_PROC_LIST(RGN)

	/*
	 * THE SENTINEL, AND WITHOUT IT EVERY LOOKUP HERE WALKS OFF THE END.
	 *
	 * Both searches of this table are written `for (i = 0;
	 * rgn_names[i].name; i++)`, so they stop on a NULL name - and there was
	 * none. A name that IS here exits the loop early and every legitimate
	 * signature therefore built; a name that is NOT - a typo in a range
	 * declaration, which is the single case the careful message below
	 * exists for - read past the last entry until it found something that
	 * was not a string, and crashed.
	 *
	 * So ksigbuilder answered a misspelled region with "Segmentation
	 * fault", from a build with no line number and nothing to look at, and
	 * the error that lists every valid region name could never be reached.
	 * Found by writing `KOF_SCAN_PDF_IMAGE` for KOF_SCAN_PDF_RESOURCE_IMAGE.
	 */
	{ NULL, 0 }
};
#undef RGN
#undef RGN

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
	q = p;
	q++;
	while (*q && *q != '"') {
		char c = *q;

		if (c == '\\') {
			/*
			 * SIX ESCAPES AND NO MORE.
			 *
			 * Three stand for themselves - a backslash, a quote and
			 * a question mark, which C would otherwise read as part
			 * of the syntax. Three are whitespace, because a marker
			 * that crosses a line has a newline in it and a
			 * researcher must be able to declare one; they are
			 * spelled the way C spells them, so this file means the
			 * same thing to a compiler as it does here.
			 *
			 * Not \\x: it is greedy, so "\\x41BC" is one escape
			 * rather than a byte and three letters, and a pattern
			 * whose length depends on what follows it is a pattern
			 * nobody can read. Hex patterns exist for bytes that
			 * are not text.
			 */
			switch (q[1]) {
			case '\\': case '"': case '?': c = q[1]; break;
			case 't': c = '\t'; break;
			case 'n': c = '\n'; break;
			case 'r': c = '\r'; break;
			default:
				ksb_err(ksb, line, "only \\\\, \\\", \\?, \\t, \\n and \\r "
						   "are supported in patterns - use a hex "
						   "pattern for anything else");
				return 0;
			}
			q++;
		}
		if (n >= MAX_LITERAL) {
			ksb_err(ksb, line, "pattern literal too long");
			return 0;
		}
		out->bytes[n++] = (uint8_t)c;
		q++;
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
			for (i = 0; rgn_names[i].name; i++)
				if (strcmp(tok, rgn_names[i].name) == 0)
					break;
			if (!rgn_names[i].name) {
				int k;
				/* The list below is the useful half; the
				 * sentence that used to be here explained why
				 * a range is an OR of names, which is not what
				 * a reader needs at the moment they mistyped
				 * one. */
				fprintf(stderr, "%s:%d: error: unknown region "
					"\"%s\". Known:\n",
					ksb->src_name, line, tok);
				for (k = 0; rgn_names[k].name; k++)
					fprintf(stderr, "    %s\n", rgn_names[k].name);
				ksb->errors++;
				return 0;
			}
			out->mask |= (uint32_t)rgn_names[i].bit;
			ksb->decl.scan_mask |= rgn_names[i].bit;
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
 * The normalizer, argument 3 of KOF_MUTATION_BLOCK.
 *
 * By name only. The value decides how the hashes were computed, so a rule whose
 * normalizer disagreed with the one the generator used would produce a block
 * that matches nothing and reports no error anywhere - which is the failure
 * every name-not-number rule in this file exists to prevent.
 */
int ksb_read_norm(struct ksb_ctx *ksb, const char *p, int line,
		  struct blk *out)
{
	static const struct { const char *name; uint32_t v; } nm[] = {
		{ "KOF_MUTATION_RAW", KGENOME_MUTATION_RAW },
		{ "KOF_MUTATION_XOR", KGENOME_MUTATION_XOR },
		{ "KOF_MUTATION_SUB", KGENOME_MUTATION_SUB },
		{ NULL, 0 }
	};
	const char *a = nth_arg(ksb, p, 3, line);
	char tok[64];
	size_t n = 0;
	int i;

	if (!a)
		return 0;
	/* nth_arg returns the byte after the comma, so the argument still has
	 * whatever the author wrote before it - a space, or a newline and a tab
	 * when the declaration is spread over several lines, which a generated
	 * one always is. */
	while (*a == ' ' || *a == '\t' || *a == '\n' || *a == '\r')
		a++;
	while (*a && *a != ',' && *a != ')' && *a != ' ' && *a != '\t' &&
	       *a != '\n' && *a != '\r' && n + 1u < sizeof tok)
		tok[n++] = *a++;
	tok[n] = 0;
	for (i = 0; nm[i].name; i++)
		if (strcmp(tok, nm[i].name) == 0) {
			out->norm = nm[i].v;
			return 1;
		}
	ksb_err(ksb, line, "unknown normalizer; use KOF_MUTATION_RAW, _XOR or _SUB");
	return 0;
}

/*
 * The hashes: every argument from the fourth on.
 *
 * Read as unsigned 32 bit values however they are spelled, because a generator
 * writes them in hex and a person editing one may not. A value that does not
 * parse is a hard error rather than a zero, since a zero is a legal hash and
 * would sit in the block being silently wrong.
 */
int ksb_read_hashes(struct ksb_ctx *ksb, const char *p, int line,
		    struct blk *out)
{
	const char *a = nth_arg(ksb, p, 4, line);

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
	if (out->n_hash < KGENOME_MUTATION_MIN_HASH) {
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
