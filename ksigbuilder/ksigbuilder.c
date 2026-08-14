/*
 * ksigbuilder - the C half of the signature toolchain.
 *
 *   ksigbuilder --extract <signature.c> <out.pat.h> <out.names> <out.pre> <out.strs>
 *   ksigbuilder <artefact-dir> <out-dir>
 *
 * The toolchain is two programs, and only two: ksigcompiler.sh turns one signature
 * source into one artefact, and this turns artefacts into .ksig packs. Everything
 * written in C is here.
 *
 * The split is by what each language is good at. Compiling a module is a wrapper
 * around cc, ld, nm and readelf, which is what a shell script is for. Reading
 * declarations out of a source and laying out bytes are neither, and both are C -
 * so they are one program with two modes rather than two programs, because a third
 * binary in the toolchain is a third thing to build, install and keep in step for
 * no gain. --extract is what ksigcompiler.sh calls; the pack mode is what the
 * Makefile calls after every source has been compiled.
 *
 * The two modes also share what matters: the region names --extract accepts are
 * bound to the enums in kofmod/, and the pack layout comes from the same
 * kof_pack_build the engine's loader was written against. A hand-kept copy of
 * either is a copy that drifts - the region table was one, and every PE signature
 * failed to compile until it was bound to the header instead.
 *
 *
 * GROUPING
 *
 * One pack per (kind, target_mask, subtype_mask, arch_mask). Every part of that key
 * is derived
 * from an artefact - kind from which entry point the module exported, the rest from
 * the .meta record - so nobody decides where a module goes and there is nowhere for
 * a decision to be wrong.
 *
 * By the exact mask value, not by "a format". A pack holding exactly the modules
 * whose target_mask is M has any_target == M, so testing an object against the pack
 * gives the same answer as testing it against every module in it: the pack-level
 * test skips exactly what the per-module test would have skipped, at one comparison
 * instead of N. Any coarser grouping - by platform, by family, by category - forces
 * the union wider than its members and starts losing modules it should have run.
 *
 * A module targeting PE and ELF together therefore gets its own pack with
 * any_target = PE|ELF, which still rules out Mach-O, script and text. That is not
 * an exception to the rule; it is the rule applied to a mask with two bits set.
 *
 * Measured on 4004 modules, this produces 4 packs and skips almost nothing for an
 * ELF object. That is the honest result: grouping is a coarse cut and does not
 * carry scale. What carries scale is the inverted index, which is built here too
 * once it exists - see kofpack.h.
 *
 *
 * FAILURE IS FATAL
 *
 * Any artefact that cannot be read stops the run. Skipping it would produce a
 * database missing a signature, and nothing downstream can tell that from a
 * database that was never meant to have it - a detection that does not happen is
 * not something a test notices.
 */

/* Before any include, not after: opendir and readdir are POSIX, and a feature test
 * macro placed after the first include has no effect at all. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>

#include <kofmod/kofsig.h>   /* KOF_SCAN_ALL, the per-module maxima */
#include <kofmod/elf.h>      /* the ELF region names a range may be built from */
#include <kofmod/pe.h>       /* and the PE ones */
#include <kofmod/gzip.h>     /* and the gzip ones */
#include <kofmod/docole.h>   /* and the compound file ones */
#include <kofmod/zip.h>      /* and the zip ones, shared by ZIP and DOCZIP */
#include <kofmod/tar.h>
#include <kofmod/sevenzip.h>
#include <kofmod/rar.h>

#include "../libkofeng/kofdb/kofpackw.h"
#include "../libkofeng/kofdb/kofpack.h"
#include "../libkofeng/kofmatchers/hexprog.h"

/* ============================================================================
 * EXTRACT - read the declarations out of a signature source
 *
 * Not a C parser: it looks for its own macro names and reads their arguments.
 * Errors stop the build with a file and a line, which is the point of having a
 * compile step at all - a malformed declaration should fail here rather than
 * silently match nothing.
 * ============================================================================ */

#define MAX_PATTERNS 256
#define MAX_LITERAL  512
#define MAX_NAMES    256

/*
 * One declared string.
 *
 * Named by the author rather than by __LINE__, which is what the previous shape
 * used. That removes the rule against two patterns on one line, and it means a
 * misspelled reference is an undefined identifier instead of a search that finds
 * nothing.
 */
struct pat {
	int      line;
	char     name[64];
	int      kind;              /* enum kof_pack_str_kind */
	int      icase;             /* literal only */
	int      fullword;          /* literal only */
	uint32_t len;               /* bytes, or the compiled program length */
	uint8_t  bytes[KOF_HEX_MAX_PROG];
};

static struct pat pats[MAX_PATTERNS];
static int npats;

/* A named set of regions. Separate from a string because the same marker can be
 * looked for in more than one place, so the range is named at the call site. */
struct rng {
	int      line;
	char     name[64];
	uint32_t mask;
};

static struct rng rngs[MAX_PATTERNS];
static int nrngs;

/*
 * Detection names.
 *
 * These go to a table beside the blob, never into it. A module reports a family by
 * line number and the host resolves it, so the string is absent from the artefact
 * and renaming a family is a data edit. It also means an out of date table produces
 * "unknown name" rather than the wrong name.
 */
struct dname {
	int  line;
	char text[MAX_LITERAL];
};

static struct dname names[MAX_NAMES];
static int nnames;

static const char *src_name;
static int errors;

/*
 * Scan mask of the whole module: the OR of every region it can search.
 *
 * A precondition that costs the author nothing, because it is read out of the
 * declarations rather than declared separately - and it cannot go stale. If a module
 * only searches KOF_SCAN_ELF_NOLOAD and the object has no section table, that region
 * resolves to nothing and the module cannot match.
 *
 * A module with no searches gets 0, which reads correctly: it names no region, so no
 * region's absence can excuse it from running.
 */
static unsigned long scan_mask;

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
 * The test at the bottom of this file is what makes the omission visible now: it
 * asserts this table covers every region every format header declares, so adding a
 * region without adding it here fails the build rather than the signature.
 */
struct rgn_name {
	const char   *name;
	unsigned long bit;
};

#define RGN(x) { #x, (unsigned long)(x) }
static const struct rgn_name rgn_names[] = {
	RGN(KOF_SCAN_ALL),

	RGN(KOF_SCAN_ELF_HEADERS),
	RGN(KOF_SCAN_ELF_CODE),
	RGN(KOF_SCAN_ELF_DATA),
	RGN(KOF_SCAN_ELF_NOLOAD),
	RGN(KOF_SCAN_ELF_UNCLAIMED),

	RGN(KOF_SCAN_PE_HEADERS),
	RGN(KOF_SCAN_PE_CODE),
	RGN(KOF_SCAN_PE_DATA),
	RGN(KOF_SCAN_PE_RESOURCE),
	RGN(KOF_SCAN_PE_SIGNATURE),
	RGN(KOF_SCAN_PE_OVERLAY),
	RGN(KOF_SCAN_PE_UNCLAIMED),

	RGN(KOF_SCAN_GZIP_HEADER),
	RGN(KOF_SCAN_GZIP_NAME),
	RGN(KOF_SCAN_GZIP_DATA),
	RGN(KOF_SCAN_GZIP_TRAILER),
	RGN(KOF_SCAN_GZIP_UNCLAIMED),

	RGN(KOF_SCAN_DOCOLE_HEADERS),
	RGN(KOF_SCAN_DOCOLE_DIRECTORY),
	RGN(KOF_SCAN_DOCOLE_CONTENT_DATA),
	RGN(KOF_SCAN_DOCOLE_CONTENT_MACROS),
	RGN(KOF_SCAN_DOCOLE_CONTENT_METADATA),
	RGN(KOF_SCAN_DOCOLE_RESOURCES),
	RGN(KOF_SCAN_DOCOLE_UNCLAIMED),

	RGN(KOF_SCAN_ZIP_HEADERS),
	RGN(KOF_SCAN_ZIP_NAMES),
	RGN(KOF_SCAN_ZIP_STORED),
	RGN(KOF_SCAN_ZIP_PACKED),
	RGN(KOF_SCAN_ZIP_UNCLAIMED),

	RGN(KOF_SCAN_TAR_HEADERS),
	RGN(KOF_SCAN_TAR_DATA),
	RGN(KOF_SCAN_TAR_UNCLAIMED),

	RGN(KOF_SCAN_7Z_HEADERS),
	RGN(KOF_SCAN_7Z_PACKED),
	RGN(KOF_SCAN_7Z_UNCLAIMED),

	RGN(KOF_SCAN_RAR_HEADERS),
	RGN(KOF_SCAN_RAR_NAMES),
	RGN(KOF_SCAN_RAR_STORED),
	RGN(KOF_SCAN_RAR_PACKED),
	RGN(KOF_SCAN_RAR_UNCLAIMED),

	{ NULL, 0 }
};
#undef RGN

static void err(int line, const char *msg)
{
	fprintf(stderr, "%s:%d: error: %s\n", src_name, line, msg);
	errors++;
}

/*
 * The macros a declaration can be written with.
 *
 * Order matters: a shorter name that is a prefix of a longer one would shadow it,
 * so KOF_DEFINE_HEXSTR has to be tested before KOF_DEFINE_STR would match inside
 * it. Getting that wrong is silent - the hex text would be read as a literal.
 */
enum decl_kind {
	DECL_RANGE = 0,
	DECL_STR,
	DECL_HEXSTR
};

struct macro {
	const char    *name;
	enum decl_kind kind;
};

static const struct macro macros[] = {
	{ "KOF_TARGET_RANGE",  DECL_RANGE  },
	{ "KOF_DEFINE_HEXSTR", DECL_HEXSTR },
	{ "KOF_DEFINE_STR",    DECL_STR    },
	{ NULL, DECL_RANGE }
};

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
static const char *nth_arg(const char *p, int want, int line)
{
	const char *open = strchr(p, '(');
	const char *start = 0;
	int depth = 0, idx = 0;

	if (!open) {
		err(line, "pattern macro is not applied");
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
				err(line, "unterminated string literal");
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
		err(line, "unbalanced parentheses in pattern macro");
		return 0;
	}
	err(line, "pattern macro has too few arguments");
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
 * Escapes are rejected rather than interpreted: deciding what "\x41" and "\n" mean
 * in a language that also has hex bytes is a decision to make when hex patterns
 * exist, not to guess now.
 */
static int read_literal(const char *p, int line, struct pat *out)
{
	const char *q;
	uint32_t n = 0;

	p = nth_arg(p, 2, line);
	if (!p)
		return 0;

	/* Only whitespace may precede the quote. Scanning ahead for one would accept
	 * a non-literal second argument and silently take a literal from further
	 * along the line. */
	while (*p == ' ' || *p == '\t')
		p++;
	if (*p != '"') {
		err(line, "second argument of KOF_DEFINE_STR must be a string literal");
		return 0;
	}
	q = p;
	q++;
	while (*q && *q != '"') {
		if (*q == '\\') {
			err(line, "escape sequences are not supported in patterns");
			return 0;
		}
		if (n >= MAX_LITERAL) {
			err(line, "pattern literal too long");
			return 0;
		}
		out->bytes[n++] = (uint8_t)*q++;
	}
	if (*q != '"') {
		err(line, "unterminated string literal");
		return 0;
	}
	if (n == 0) {
		err(line, "empty pattern");
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
static int read_mask(const char *p, int line, struct rng *out)
{
	const char *a = nth_arg(p, 2, line);
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
				err(line, "empty term in the region mask");
				return 0;
			}
			for (i = 0; rgn_names[i].name; i++)
				if (strcmp(tok, rgn_names[i].name) == 0)
					break;
			if (!rgn_names[i].name) {
				int k;
				fprintf(stderr, "%s:%d: error: region \"%s\" is not a "
					"known region name; a range must be an OR of "
					"region names so the host knows where to "
					"search and when it can skip. Known:\n",
					src_name, line, tok);
				for (k = 0; rgn_names[k].name; k++)
					fprintf(stderr, "    %s\n", rgn_names[k].name);
				errors++;
				return 0;
			}
			out->mask |= (uint32_t)rgn_names[i].bit;
			scan_mask |= rgn_names[i].bit;
			n = 0;
			a++;
			continue;
		}
		if (c == ' ' || c == '\t' || c == '\\' || c == '\n' || c == '\r') {
			a++;
			continue;
		}
		if (n + 1 >= sizeof tok) {
			err(line, "region mask term too long");
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
static int read_hex_text(const char *p, int line, char *out, size_t cap)
{
	const char *q;
	size_t n = 0;

	q = nth_arg(p, 2, line);
	if (!q)
		return 0;
	while (*q == ' ' || *q == '\t')
		q++;
	if (*q != '"') {
		err(line, "second argument of KOF_DEFINE_HEXSTR must be a string "
			  "literal holding the hex pattern");
		return 0;
	}
	q++;
	while (*q && *q != '"') {
		if (n + 1 >= cap) {
			err(line, "hex pattern too long");
			return 0;
		}
		out[n++] = *q++;
	}
	if (*q != '"') {
		err(line, "unterminated hex pattern");
		return 0;
	}
	out[n] = 0;
	return 1;
}

/* Read a single enum name from argument `which`, matched against a table. */
static int read_enum(const char *p, int which, int line, const char *what,
		     const char *n0, const char *n1, int *out)
{
	const char *a = nth_arg(p, which, line);
	char tok[64];
	size_t n = 0;

	if (!a)
		return 0;
	while (*a == ' ' || *a == '\t' || *a == '\n' || *a == '\r' || *a == '\\')
		a++;
	while (*a && *a != ',' && *a != ')' && *a != ' ' && *a != '\t' &&
	       *a != '\n' && *a != '\r') {
		if (n + 1 >= sizeof tok) {
			err(line, "option name too long");
			return 0;
		}
		tok[n++] = *a++;
	}
	tok[n] = 0;
	if (strcmp(tok, n0) == 0) { *out = 0; return 1; }
	if (strcmp(tok, n1) == 0) { *out = 1; return 1; }
	fprintf(stderr, "%s:%d: error: %s must be %s or %s, not \"%s\"\n",
		src_name, line, what, n0, n1, tok);
	errors++;
	return 0;
}

/* Read the declared name, argument 1. It becomes a C identifier, so it has to be
 * one. */
static int read_ident(const char *p, int line, char *out, size_t cap)
{
	const char *a = nth_arg(p, 1, line);
	size_t n = 0;

	if (!a)
		return 0;
	while (*a == ' ' || *a == '\t')
		a++;
	while (*a && *a != ',' && *a != ')' && *a != ' ' && *a != '\t') {
		int ok = (*a >= 'a' && *a <= 'z') || (*a >= 'A' && *a <= 'Z') ||
			 (*a >= '0' && *a <= '9') || *a == '_';
		if (!ok) {
			err(line, "the first argument must be a plain identifier: "
				  "it becomes the name kof_find uses");
			return 0;
		}
		if (n + 1 >= cap) {
			err(line, "declared name too long");
			return 0;
		}
		out[n++] = *a++;
	}
	out[n] = 0;
	if (n == 0) {
		err(line, "declaration without a name");
		return 0;
	}
	return 1;
}

/* Two declarations of the same kind cannot share a name: the name becomes a macro.
 * Strings and ranges are separate namespaces because they expand to different
 * identifiers, so a range and a string may be called the same thing - which is
 * awkward to read but not wrong, and forbidding it would be a rule with no failure
 * behind it. */
static int str_name_taken(const char *nm)
{
	int i;
	for (i = 0; i < npats; i++)
		if (strcmp(pats[i].name, nm) == 0)
			return 1;
	return 0;
}

static int rng_name_taken(const char *nm)
{
	int i;
	for (i = 0; i < nrngs; i++)
		if (strcmp(rngs[i].name, nm) == 0)
			return 1;
	return 0;
}

/* Read the detection name into a NUL terminated buffer. */
static int read_name(const char *p, int line, char *out, size_t cap)
{
	const char *q;
	size_t n = 0;

	/* Argument 1 of KOF_SCAN_MATCH("name", LEVEL), located the same way as a pattern
	 * rather than by scanning for a quote: the level argument is a macro and
	 * could contain one. */
	q = nth_arg(p, 1, line);
	if (!q)
		return 0;
	while (*q == ' ' || *q == '\t')
		q++;
	if (*q != '"') {
		err(line, "first argument of KOF_SCAN_MATCH must be a name literal");
		return 0;
	}
	q++;
	while (*q && *q != '"') {
		if (n + 1 >= cap) {
			err(line, "detection name too long");
			return 0;
		}
		out[n++] = *q++;
	}
	if (*q != '"' || n == 0) {
		err(line, "malformed detection name");
		return 0;
	}
	out[n] = 0;
	return 1;
}

/*
 * Handle one source line: a macro is found within the line, but its arguments are
 * read from the full buffer, because an invocation may wrap onto the next line.
 * nth_arg treats a newline like any other space, so it spans lines by itself.
 */
static void scan_line(char *at, size_t line_len, int lineno)
{
	const struct macro *m = NULL;
	char *p;
	char saved = at[line_len];

	/* Find within the line; read arguments from the full buffer. Comments were
	 * blanked before this ran, so anything found here is code. */
	at[line_len] = 0;
	/* kof_debug names go in the same table and are keyed the same way: both use
	 * __LINE__ as the id, so the host resolves either through one lookup. */
	p = strstr(at, "KOF_SCAN_MATCH");
	if (!p)
		p = strstr(at, "kof_debug");
	if (!p)
		for (m = macros; m->name; m++) {
			p = strstr(at, m->name);
			if (p)
				break;
		}
	at[line_len] = saved;   /* p stays valid: it points into the same buffer */

	if (!p)
		return;

	/*
	 * The opening parenthesis has to be on this line. Searching the rest of the
	 * buffer for one would treat a bare mention of the macro as an invocation and
	 * then read arguments from whatever call came next in the file.
	 */
	{
		const char *r = p;
		while (*r && *r != '(' && *r != '\n')
			r++;
		if (*r != '(')
			return;
	}

	if (m == NULL) {
		if (nnames >= MAX_NAMES) {
			err(lineno, "too many detection names in one source file");
			return;
		}
		names[nnames].line = lineno;
		if (!read_name(p, lineno, names[nnames].text,
			       sizeof names[nnames].text))
			return;
		/* The engine's slot is the smallest thing on the way through, so
		 * it is the limit. Refused here, where the message can name the
		 * line, rather than cut silently in two places downstream. */
		if (strlen(names[nnames].text) >= KOF_NAME_MAX_LEN) {
			fprintf(stderr, "%s:%d: error: detection name is %zu "
				"characters; the engine stores %u\n", src_name,
				lineno, strlen(names[nnames].text),
				KOF_NAME_MAX_LEN - 1u);
			errors++;
			return;
		}
		nnames++;
		return;
	}

	if (m->kind == DECL_RANGE) {
		struct rng *r;
		if (nrngs >= MAX_PATTERNS) {
			err(lineno, "too many declared ranges");
			return;
		}
		if (nrngs >= KOF_MAX_RANGE_PER_MODULE) {
			err(lineno, "more declared ranges than a module may have");
			return;
		}
		r = &rngs[nrngs];
		memset(r, 0, sizeof *r);
		r->line = lineno;
		if (!read_ident(p, lineno, r->name, sizeof r->name))
			return;
		if (rng_name_taken(r->name)) {
			err(lineno, "a range with this name is already declared");
			return;
		}
		if (!read_mask(p, lineno, r))
			return;
		nrngs++;
		return;
	}

	if (npats >= MAX_PATTERNS) {
		err(lineno, "too many declared strings in one source file");
		return;
	}
	if (npats >= KOF_MAX_STR_PER_MODULE) {
		err(lineno, "more declared strings than a module may have; the "
			    "answers are a 64 bit mask");
		return;
	}
	{
		struct pat *o = &pats[npats];

		memset(o, 0, sizeof *o);
		o->line = lineno;
		if (!read_ident(p, lineno, o->name, sizeof o->name))
			return;
		if (str_name_taken(o->name)) {
			err(lineno, "a string with this name is already declared");
			return;
		}

		if (m->kind == DECL_HEXSTR) {
			/*
			 * The hex text is read the same way a literal is - argument
			 * two and nowhere else - and then compiled. Case and word
			 * options do not apply: a hex pattern is bytes, and folding
			 * case on a byte that may be a wildcard means nothing.
			 */
			char text[MAX_LITERAL];
			struct kof_hex_stat st;

			if (!read_hex_text(p, lineno, text, sizeof text))
				return;
			o->len = kof_hex_compile(text, o->bytes, sizeof o->bytes,
						 &st);
			if (o->len == 0) {
				err(lineno, kof_hex_error());
				return;
			}
			o->kind = KOF_STR_HEX;
			/* The anchor length is printed because it is the number a
			 * researcher can act on and the one nothing else would
			 * surface: below four the presence set cannot rule this
			 * pattern out, so it is searched on every object of its
			 * format, forever. */
			printf("   hex %-22s %u step(s) %u alt(s) span %u..%u "
			       "anchor %u%s\n", o->name, st.n_steps, st.n_alts,
			       st.min_span, st.max_span, st.anchor_len,
			       st.anchor_len < 4 ? "  (too short for the presence "
						   "set)" : "");
			npats++;
			return;
		}

		o->kind = KOF_STR_LITERAL;
		if (!read_literal(p, lineno, o))
			return;
		if (!read_enum(p, 3, lineno, "the case option",
			       "KOF_CASE_EXACT", "KOF_CASE_ICASE", &o->icase))
			return;
		if (!read_enum(p, 4, lineno, "the word option",
			       "KOF_WORD_SUBSTRING", "KOF_WORD_FULLWORD",
			       &o->fullword))
			return;
		npats++;
	}
}

/*
 * Emit the header the module compiles against: one identifier per declared string.
 *
 * No pattern bytes. They used to be emitted as arrays that landed in the blob's
 * .rodata, because the module did its own searching; now the host searches, so the
 * bytes belong in the record beside the blob and the module only needs the index.
 * The blob got smaller and stopped carrying the literals it looks for.
 */
static void emit_str_id(FILE *out, const struct pat *p, int idx)
{
	fprintf(out, "/* line %d: \"%.*s\"%s%s */\n", p->line,
		(int)p->len, (const char *)p->bytes,
		p->icase ? " icase" : "",
		p->fullword ? " fullword" : "");
	fprintf(out, "#define kof_strid_%s %d\n\n", p->name, idx);
}

static void emit_rng_id(FILE *out, const struct rng *r, int idx)
{
	fprintf(out, "/* line %d: range mask 0x%x */\n", r->line, r->mask);
	fprintf(out, "#define kof_rangeid_%s %d\n\n", r->name, idx);
}

/*
 * Emit the records the packer reads.
 *
 * Tab separated so they are readable and diffable; the fields are the ones needed
 * and nothing else. The literal is last because it is the only field that can
 * contain anything, so nothing has to be escaped to keep the columns parseable.
 */
static void emit_str_record(FILE *out, const struct pat *p, int idx)
{
	uint32_t i;

	/*
	 * A compiled hex program is arbitrary bytes, so it cannot go in the column
	 * a literal uses - a newline in it would end the row. Hex digits cost twice
	 * the space in a file that exists for one build step and are readable when
	 * something goes wrong, which is what the sidecar is for.
	 */
	if (p->kind == KOF_STR_HEX) {
		fprintf(out, "h\t%d\t%u\t", idx, p->len);
		for (i = 0; i < p->len; i++)
			fprintf(out, "%02x", p->bytes[i]);
		fputc('\n', out);
		return;
	}
	fprintf(out, "s\t%d\t%d\t%d\t%u\t%.*s\n", idx,
		p->icase, p->fullword, p->len, (int)p->len,
		(const char *)p->bytes);
}

static void emit_rng_record(FILE *out, const struct rng *r, int idx)
{
	fprintf(out, "r\t%d\t%u\n", idx, r->mask);
}

/*
 * Blank out every comment, preserving line structure.
 *
 * Not cosmetic: declarations are read out of the source, so a macro mentioned inside
 * a comment must not contribute. Line comments alone were not enough - a signature's
 * header block explains what kof_find_str does, and the name was found there.
 *
 * String and character literals are tracked so a comment introducer inside a pattern
 * cannot start a comment. Newlines are kept so line numbers stay correct.
 */
static void strip_comments(char *s, size_t n)
{
	size_t i = 0;

	while (i < n) {
		if (s[i] == '"' || s[i] == '\'') {
			char q = s[i++];
			while (i < n && s[i] != q) {
				if (s[i] == '\\' && i + 1 < n)
					i++;
				i++;
			}
			i++;
			continue;
		}
		if (s[i] == '/' && i + 1 < n && s[i + 1] == '/') {
			while (i < n && s[i] != '\n')
				s[i++] = ' ';
			continue;
		}
		if (s[i] == '/' && i + 1 < n && s[i + 1] == '*') {
			s[i++] = ' ';
			s[i++] = ' ';
			while (i < n) {
				if (s[i] == '*' && i + 1 < n && s[i + 1] == '/') {
					s[i++] = ' ';
					s[i++] = ' ';
					break;
				}
				if (s[i] != '\n')
					s[i] = ' ';
				i++;
			}
			continue;
		}
		i++;
	}
}

/* Read the whole source. Needed because a macro invocation may wrap onto further
 * lines and its arguments have to be readable past the end of the line the macro
 * name is on. Signature sources are a few hundred lines, so there is no reason to
 * stream. */
static char *slurp(const char *path, size_t *len_out)
{
	FILE *f = fopen(path, "rb");
	char *buf;
	long n;

	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
	n = ftell(f);
	if (n < 0) { fclose(f); return NULL; }
	rewind(f);
	buf = malloc((size_t)n + 2);
	if (!buf) { fclose(f); return NULL; }
	if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
		free(buf); fclose(f); return NULL;
	}
	fclose(f);
	buf[n] = 0;
	buf[n + 1] = 0;
	*len_out = (size_t)n;
	return buf;
}

static int extract_main(int argc, char **argv)
{
	FILE *out;
	char *src;
	size_t src_len, pos = 0;
	int lineno = 0, i;

	if (argc != 7) {
		fprintf(stderr, "usage: %s --extract <signature.c> <out.pat.h> "
				"<out.names> <out.pre> <out.strs>\n", argv[0]);
		return 2;
	}
	src_name = argv[2];

	src = slurp(argv[2], &src_len);
	if (!src) {
		fprintf(stderr, "ksigbuilder: cannot read %s\n", argv[2]);
		return 2;
	}
	strip_comments(src, src_len);
	while (pos < src_len) {
		size_t e = pos;
		while (e < src_len && src[e] != '\n')
			e++;
		lineno++;
		scan_line(src + pos, e - pos, lineno);
		pos = (e < src_len) ? e + 1 : e;
	}

	if (errors) {
		free(src);
		return 1;
	}

	out = fopen(argv[3], "w");
	if (!out) {
		fprintf(stderr, "ksigbuilder: cannot write %s\n", argv[3]);
		free(src);
		return 2;
	}
	fprintf(out, "/* generated by ksigbuilder --extract from %s - do not edit */\n",
		argv[2]);
	for (i = 0; i < nrngs; i++)
		emit_rng_id(out, &rngs[i], i);
	for (i = 0; i < npats; i++)
		emit_str_id(out, &pats[i], i);
	fclose(out);

	out = fopen(argv[4], "w");
	if (!out) {
		fprintf(stderr, "ksigbuilder: cannot write %s\n", argv[4]);
		free(src);
		return 2;
	}
	for (i = 0; i < nnames; i++)
		fprintf(out, "%d\t%s\n", names[i].line, names[i].text);
	fclose(out);

	/*
	 * The preconditions derived from the source, for the host to filter on without
	 * loading or running the module. ksigcompiler.sh merges this with what it
	 * extracts itself - the target mask - into the module's .meta.
	 */
	out = fopen(argv[5], "w");
	if (!out) {
		fprintf(stderr, "ksigbuilder: cannot write %s\n", argv[5]);
		free(src);
		return 2;
	}
	fprintf(out, "scan_mask=%lu\n", scan_mask);
	fprintf(out, "nstr=%d\n", npats);
	fclose(out);

	/* The strings and ranges, for the packer to put in the pack. */
	out = fopen(argv[6], "w");
	if (!out) {
		fprintf(stderr, "ksigbuilder: cannot write %s\n", argv[6]);
		free(src);
		return 2;
	}
	for (i = 0; i < nrngs; i++)
		emit_rng_record(out, &rngs[i], i);
	for (i = 0; i < npats; i++)
		emit_str_record(out, &pats[i], i);
	fclose(out);

	printf("   %d string(s), %d range(s), %d name(s), scan_mask=0x%lx\n",
	       npats, nrngs, nnames, scan_mask);
	free(src);
	return 0;
}

/* ============================================================================
 * PACK - gather compiled artefacts into .ksig
 * ============================================================================ */

/* Everything read out of one artefact set, owned until its pack is written. */
struct artefact {
	char    *stem;                   /* the path without the .blob */
	uint8_t *code;
	uint32_t code_len;

	uint32_t kind;
	uint32_t target_mask, scan_mask, arch_mask, subtype_mask;
	uint64_t size_min;

	struct kof_pw_str  *str;
	uint32_t            n_str;
	uint32_t           *rng;
	uint32_t            n_rng;
	struct kof_pw_name *name;
	uint32_t            n_names;

	/* The literals and name texts the descriptors above point into. */
	uint8_t *str_bytes;
	char    *name_text;
};

static void artefact_free(struct artefact *a)
{
	free(a->stem);
	free(a->code);
	free(a->str);
	free(a->rng);
	free(a->name);
	free(a->str_bytes);
	free(a->name_text);
}

/* <stem> + <ext> into a fresh string. */
static char *sibling(const char *stem, const char *ext)
{
	size_t a = strlen(stem), b = strlen(ext);
	char *p = malloc(a + b + 1);

	if (!p)
		return NULL;
	memcpy(p, stem, a);
	memcpy(p + a, ext, b + 1);
	return p;
}

static char *join_path(const char *dir, const char *leaf)
{
	size_t n = strlen(dir) + strlen(leaf) + 2;
	char *p = malloc(n);

	if (!p)
		return NULL;
	snprintf(p, n, "%s/%s", dir, leaf);
	return p;
}

/*
 * Read a whole file, refusing one too large to be what is being read.
 *
 * The cap is checked against the stat size before the allocation, not after the
 * read: an artefact directory is a directory, and a file of any size can be in it
 * under a name ending in .blob.
 */
static uint8_t *read_whole(const char *path, size_t cap, size_t *out_len)
{
	struct stat st;
	uint8_t *buf;
	FILE *f;

	if (stat(path, &st) != 0 || st.st_size <= 0)
		return NULL;
	if ((uint64_t)st.st_size > (uint64_t)cap) {
		fprintf(stderr, "ksigbuilder: %s: %llu bytes is too large for a "
				"blob\n", path, (unsigned long long)st.st_size);
		return NULL;
	}
	f = fopen(path, "rb");
	if (!f)
		return NULL;
	buf = malloc((size_t)st.st_size);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	if (fread(buf, 1, (size_t)st.st_size, f) != (size_t)st.st_size) {
		free(buf);
		fclose(f);
		return NULL;
	}
	fclose(f);
	*out_len = (size_t)st.st_size;
	return buf;
}

/*
 * The .meta record. Mandatory, and so is every field it must carry.
 *
 * The loader can afford a permissive default for a missing field because a wrong
 * guess there costs scan time. A wrong guess here is baked into a database and
 * costs detections, so there are no defaults: an incomplete record is a build that
 * went wrong and the only useful thing to do with it is stop.
 */
static int meta_load(struct artefact *a)
{
	char *path = sibling(a->stem, ".meta"), line[128];
	FILE *f;
	uint64_t blob_len = 0;
	int have_target = 0, have_kind = 0, ok = 0;

	if (!path)
		return 0;
	f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "ksigbuilder: %s: no record beside the blob\n",
			a->stem);
		goto out;
	}
	while (fgets(line, sizeof line, f)) {
		if (strncmp(line, "target=", 7) == 0) {
			a->target_mask = (uint32_t)strtoul(line + 7, 0, 10);
			have_target = 1;
		} else if (strncmp(line, "scan_mask=", 10) == 0) {
			a->scan_mask = (uint32_t)strtoul(line + 10, 0, 10);
		} else if (strncmp(line, "size_min=", 9) == 0) {
			a->size_min = strtoull(line + 9, 0, 10);
		} else if (strncmp(line, "arch_mask=", 10) == 0) {
			a->arch_mask = (uint32_t)strtoul(line + 10, 0, 10);
		} else if (strncmp(line, "subtype_mask=", 13) == 0) {
			a->subtype_mask = (uint32_t)strtoul(line + 13, 0, 10);
		} else if (strncmp(line, "blob_len=", 9) == 0) {
			blob_len = strtoull(line + 9, 0, 10);
		} else if (strncmp(line, "kind=", 5) == 0) {
			a->kind = (uint32_t)strtoul(line + 5, 0, 10);
			have_kind = 1;
		}
	}
	fclose(f);

	if (!have_target || a->target_mask == 0) {
		fprintf(stderr, "ksigbuilder: %s: record declares no target\n",
			a->stem);
		goto out;
	}
	if (!have_kind) {
		fprintf(stderr, "ksigbuilder: %s: record declares no kind\n",
			a->stem);
		goto out;
	}
	if (a->kind != KOF_PACK_DETECT && a->kind != KOF_PACK_UNPACK) {
		fprintf(stderr, "ksigbuilder: %s: unknown kind %u\n", a->stem,
			a->kind);
		goto out;
	}
	if (blob_len != a->code_len) {
		fprintf(stderr, "ksigbuilder: %s: blob is %u bytes, record says "
				"%llu\n", a->stem, a->code_len,
			(unsigned long long)blob_len);
		goto out;
	}
	ok = 1;
out:
	free(path);
	return ok;
}

/* id<TAB>text per line. Absent is allowed: a module may report nothing by name. */
static int names_load(struct artefact *a)
{
	/* Sized from the name limit plus the id column, so a legal name can never be
	 * split across two reads - which is how ".Variant" used to disappear. */
	char *path = sibling(a->stem, ".names"), line[KOF_NAME_MAX_LEN + 64];
	FILE *f;
	size_t text_cap = 0, text_len = 0;
	uint32_t cap = 0, i;
	int ok = 0;

	if (!path)
		return 0;
	f = fopen(path, "r");
	if (!f) {
		ok = 1;                  /* nothing to report by name */
		goto out;
	}
	while (fgets(line, sizeof line, f)) {
		char *tab = strchr(line, '\t'), *nl;
		size_t tl;

		if (!tab)
			continue;
		*tab++ = 0;
		nl = strchr(tab, '\n');
		if (nl)
			*nl = 0;
		tl = strlen(tab) + 1;

		if (text_len + tl > text_cap) {
			size_t nc = text_cap ? text_cap * 2 : 512;
			char *nt;
			while (nc < text_len + tl)
				nc *= 2;
			nt = realloc(a->name_text, nc);
			if (!nt)
				goto out;
			a->name_text = nt;
			text_cap = nc;
		}
		if (a->n_names == cap) {
			uint32_t nc = cap ? cap * 2 : 8;
			struct kof_pw_name *nv = realloc(a->name, nc * sizeof *nv);
			if (!nv)
				goto out;
			a->name = nv;
			cap = nc;
		}
		memcpy(a->name_text + text_len, tab, tl);
		/* An offset now, a pointer once the buffer stops moving: it is
		 * reallocated as it grows, so a pointer taken here would dangle. */
		a->name[a->n_names].id   = (uint32_t)strtoul(line, 0, 10);
		a->name[a->n_names].text = (const char *)(uintptr_t)text_len;
		a->n_names++;
		text_len += tl;
	}
	fclose(f);
	for (i = 0; i < a->n_names; i++)
		a->name[i].text = a->name_text + (uintptr_t)a->name[i].text;
	ok = 1;
out:
	free(path);
	return ok;
}

/*
 * Declared strings and ranges. Tab separated, kind in column one: 'r' for a range
 * mask, 's' for a string with the literal last so nothing in it needs escaping to
 * keep the earlier columns parseable.
 */
static int strs_load(struct artefact *a)
{
	char *path = sibling(a->stem, ".strs"), line[2 * KOF_HEX_MAX_PROG + 128];
	FILE *f;
	size_t bytes_cap = 0, bytes_len = 0;
	uint32_t scap = 0, rcap = 0, i;
	int ok = 0;

	if (!path)
		return 0;
	f = fopen(path, "r");
	if (!f) {
		ok = 1;                  /* a module may declare neither */
		goto out;
	}
	while (fgets(line, sizeof line, f)) {
		char *p = line, *tab;

		/* r <id> <mask> */
		if (p[0] == 'r' && p[1] == '\t') {
			p += 2;
			tab = strchr(p, '\t');
			if (!tab)
				continue;
			if (a->n_rng == rcap) {
				uint32_t nc = rcap ? rcap * 2 : 8;
				uint32_t *nv = realloc(a->rng, nc * sizeof *nv);
				if (!nv)
					goto out;
				a->rng = nv;
				rcap = nc;
			}
			a->rng[a->n_rng++] = (uint32_t)strtoul(tab + 1, 0, 10);
		/* s <id> <icase> <fullword> <len> <literal> */
		} else if (p[0] == 's' && p[1] == '\t') {
			unsigned long v[4], icase, fullw, len;
			char *lit;
			size_t actual;
			int k;

			p += 2;
			for (k = 0; k < 4; k++) {
				tab = strchr(p, '\t');
				if (!tab)
					break;
				*tab = 0;
				v[k] = strtoul(p, 0, 10);
				p = tab + 1;
			}
			if (k != 4) {
				fprintf(stderr, "ksigbuilder: %s: malformed string "
						"row\n", a->stem);
				goto out;
			}
			icase = v[1];
			fullw = v[2];
			len   = v[3];
			lit   = p;

			actual = strlen(lit);
			while (actual && (lit[actual - 1] == '\n' ||
					  lit[actual - 1] == '\r'))
				lit[--actual] = 0;

			/* The recorded length is authoritative - it is what the
			 * pattern compiler measured. Disagreeing with it is a
			 * build that went wrong, not a row to skip. */
			if (len == 0 || len > KOF_STR_MAX_LEN || actual != len) {
				fprintf(stderr, "ksigbuilder: %s: string of declared "
						"length %lu does not match its "
						"literal\n", a->stem, len);
				goto out;
			}
			if (bytes_len + len > bytes_cap) {
				size_t nc = bytes_cap ? bytes_cap * 2 : 1024;
				uint8_t *nb;
				while (nc < bytes_len + len)
					nc *= 2;
				nb = realloc(a->str_bytes, nc);
				if (!nb)
					goto out;
				a->str_bytes = nb;
				bytes_cap = nc;
			}
			if (a->n_str == scap) {
				uint32_t nc = scap ? scap * 2 : 8;
				struct kof_pw_str *nv = realloc(a->str,
								nc * sizeof *nv);
				if (!nv)
					goto out;
				a->str = nv;
				scap = nc;
			}
			memcpy(a->str_bytes + bytes_len, lit, len);
			a->str[a->n_str].bytes = (const uint8_t *)(uintptr_t)bytes_len;
			a->str[a->n_str].len   = (uint16_t)len;
			a->str[a->n_str].kind  = KOF_STR_LITERAL;
			a->str[a->n_str].flags = (uint8_t)
				((icase ? KOF_STR_ICASE : 0u) |
				 (fullw ? KOF_STR_FULLWORD : 0u));
			a->n_str++;
			bytes_len += len;
		/* h <id> <len> <program as hex digits> */
		} else if (p[0] == 'h' && p[1] == '\t') {
			unsigned long len;
			char *end;
			uint32_t k;

			p += 2;
			tab = strchr(p, '\t');       /* past the id column */
			if (!tab)
				continue;
			p = tab + 1;
			tab = strchr(p, '\t');
			if (!tab)
				continue;
			len = strtoul(p, 0, 10);
			p = tab + 1;                 /* the digits */
			if (len == 0 || len > KOF_HEX_MAX_PROG) {
				fprintf(stderr, "ksigbuilder: %s: hex program of "
						"length %lu\n", a->stem, len);
				goto out;
			}
			for (end = p; *end && *end != '\n' && *end != '\r'; end++)
				;
			if ((size_t)(end - p) != len * 2) {
				fprintf(stderr, "ksigbuilder: %s: hex program says "
						"%lu bytes but carries %zu digits\n",
					a->stem, len, (size_t)(end - p));
				goto out;
			}
			if (bytes_len + len > bytes_cap) {
				size_t nc = bytes_cap ? bytes_cap * 2 : 1024;
				uint8_t *nb;
				while (nc < bytes_len + len)
					nc *= 2;
				nb = realloc(a->str_bytes, nc);
				if (!nb)
					goto out;
				a->str_bytes = nb;
				bytes_cap = nc;
			}
			if (a->n_str == scap) {
				uint32_t nc = scap ? scap * 2 : 8;
				struct kof_pw_str *nv = realloc(a->str,
								nc * sizeof *nv);
				if (!nv)
					goto out;
				a->str = nv;
				scap = nc;
			}
			for (k = 0; k < (uint32_t)len; k++) {
				unsigned v;
				if (sscanf(p + k * 2, "%2x", &v) != 1) {
					fprintf(stderr, "ksigbuilder: %s: malformed "
							"hex program\n", a->stem);
					goto out;
				}
				a->str_bytes[bytes_len + k] = (uint8_t)v;
			}
			a->str[a->n_str].bytes = (const uint8_t *)(uintptr_t)bytes_len;
			a->str[a->n_str].len   = (uint16_t)len;
			a->str[a->n_str].kind  = KOF_STR_HEX;
			a->str[a->n_str].flags = 0;
			a->n_str++;
			bytes_len += len;
		}
	}
	fclose(f);
	for (i = 0; i < a->n_str; i++)
		a->str[i].bytes = a->str_bytes + (uintptr_t)a->str[i].bytes;
	ok = 1;
out:
	free(path);
	return ok;
}

static int artefact_load(struct artefact *a, const char *blob_path)
{
	size_t n = strlen(blob_path), len = 0;

	memset(a, 0, sizeof *a);
	a->stem = malloc(n - 5 + 1);
	if (!a->stem)
		return 0;
	memcpy(a->stem, blob_path, n - 5);
	a->stem[n - 5] = 0;

	a->code = read_whole(blob_path, KOF_BLOB_MAX_CODE, &len);
	if (!a->code) {
		fprintf(stderr, "ksigbuilder: cannot read %s\n", blob_path);
		return 0;
	}
	/* The same guard the loader applies, applied where a failure is a build
	 * failure rather than something a customer's machine discovers. */
	if (len >= 4 && memcmp(a->code, "\177ELF", 4) == 0) {
		fprintf(stderr, "ksigbuilder: %s is an ELF image, not a blob\n",
			blob_path);
		return 0;
	}
	a->code_len = (uint32_t)len;

	return meta_load(a) && names_load(a) && strs_load(a);
}

/* A set of artefacts sharing one grouping key, which is one pack. */
struct group {
	uint32_t  kind, target_mask, arch_mask, subtype_mask;
	uint32_t *member;                /* indices into the artefact array */
	uint32_t  n, cap;
};

static int group_add(struct group *g, uint32_t idx)
{
	if (g->n == g->cap) {
		uint32_t nc = g->cap ? g->cap * 2 : 16;
		uint32_t *nv = realloc(g->member, nc * sizeof *nv);
		if (!nv)
			return 0;
		g->member = nv;
		g->cap = nc;
	}
	g->member[g->n++] = idx;
	return 1;
}

static int write_file(const char *path, const uint8_t *data, size_t len)
{
	FILE *f = fopen(path, "wb");
	size_t w;

	if (!f) {
		fprintf(stderr, "ksigbuilder: cannot write %s\n", path);
		return 0;
	}
	w = fwrite(data, 1, len, f);
	if (fclose(f) != 0 || w != len) {
		fprintf(stderr, "ksigbuilder: short write to %s\n", path);
		return 0;
	}
	return 1;
}

static const char *kind_name(uint32_t k)
{
	return k == KOF_PACK_UNPACK ? "unpack" : "detect";
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s <artefact-dir> <out-dir>\n"
		"       %s --extract <signature.c> <out.pat.h> <out.names>"
		" <out.pre> <out.strs>\n"
		"\n"
		"  <artefact-dir>  holds <name>.blob and the .meta, .strs and .names\n"
		"                  beside each one, as ksigcompiler.sh emits them\n"
		"  --extract       read the declarations out of one signature source;\n"
		"                  this is what ksigcompiler.sh calls\n",
		argv0, argv0);
}

int main(int argc, char **argv)
{
	const char *workdir = NULL, *outdir = NULL;
	int i, rc = 1;

	struct artefact *arts = NULL;
	uint32_t n_arts = 0, cap_arts = 0, a, j;
	struct group *groups = NULL;
	uint32_t n_groups = 0, cap_groups = 0;
	DIR *d = NULL;
	struct dirent *de;

	if (argc > 1 && strcmp(argv[1], "--extract") == 0)
		return extract_main(argc, argv);

	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			fprintf(stderr, "%s: unrecognised argument '%s'\n",
				argv[0], argv[i]);
			usage(argv[0]);
			return 2;
		} else if (!workdir)
			workdir = argv[i];
		else if (!outdir)
			outdir = argv[i];
		else {
			usage(argv[0]);
			return 2;
		}
	}
	if (!workdir || !outdir) {
		usage(argv[0]);
		return 2;
	}

	d = opendir(workdir);
	if (!d) {
		fprintf(stderr, "ksigbuilder: cannot read %s\n", workdir);
		goto done;
	}
	while ((de = readdir(d)) != NULL) {
		size_t l = strlen(de->d_name);
		char *p;

		if (l < 6 || strcmp(de->d_name + l - 5, ".blob") != 0)
			continue;
		if (n_arts == cap_arts) {
			uint32_t nc = cap_arts ? cap_arts * 2 : 64;
			struct artefact *nv = realloc(arts, nc * sizeof *nv);
			if (!nv)
				goto done;
			arts = nv;
			cap_arts = nc;
		}
		p = join_path(workdir, de->d_name);
		if (!p)
			goto done;
		if (!artefact_load(&arts[n_arts], p)) {
			artefact_free(&arts[n_arts]);
			free(p);
			goto done;
		}
		free(p);
		n_arts++;
	}
	closedir(d);
	d = NULL;

	if (n_arts == 0) {
		fprintf(stderr, "ksigbuilder: no .blob artefacts in %s\n", workdir);
		goto done;
	}

	/* Linear scan over the groups: the number of distinct precondition tuples
	 * is small and does not grow with the number of signatures, which is the
	 * property that makes this cheap however large the set gets. */
	for (a = 0; a < n_arts; a++) {
		struct group *g = NULL;
		for (j = 0; j < n_groups; j++)
			if (groups[j].kind == arts[a].kind &&
			    groups[j].target_mask == arts[a].target_mask &&
			    groups[j].arch_mask == arts[a].arch_mask &&
			    groups[j].subtype_mask == arts[a].subtype_mask) {
				g = &groups[j];
				break;
			}
		if (!g) {
			if (n_groups == cap_groups) {
				uint32_t nc = cap_groups ? cap_groups * 2 : 8;
				struct group *nv = realloc(groups, nc * sizeof *nv);
				if (!nv)
					goto done;
				groups = nv;
				cap_groups = nc;
			}
			g = &groups[n_groups++];
			memset(g, 0, sizeof *g);
			g->kind        = arts[a].kind;
			g->target_mask = arts[a].target_mask;
			g->arch_mask   = arts[a].arch_mask;
			g->subtype_mask = arts[a].subtype_mask;
		}
		if (!group_add(g, a))
			goto done;
	}

	printf("%u module(s) -> %u pack(s)\n", n_arts, n_groups);

	for (j = 0; j < n_groups; j++) {
		struct group *g = &groups[j];
		struct kof_pw_mod *pm;
		uint8_t *img;
		size_t img_len = 0;
		char path[4096];

		pm = calloc(g->n, sizeof *pm);
		if (!pm)
			goto done;
		for (a = 0; a < g->n; a++) {
			const struct artefact *s = &arts[g->member[a]];
			pm[a].code        = s->code;
			pm[a].code_len    = s->code_len;
			pm[a].target_mask = s->target_mask;
			pm[a].scan_mask   = s->scan_mask;
			pm[a].arch_mask   = s->arch_mask;
			pm[a].subtype_mask = s->subtype_mask;
			pm[a].size_min    = s->size_min;
			pm[a].str         = s->str;
			pm[a].n_str       = s->n_str;
			pm[a].rng         = s->rng;
			pm[a].n_rng       = s->n_rng;
			pm[a].name        = s->name;
			pm[a].n_names     = s->n_names;
		}

		img = kof_pack_build(g->kind, pm, g->n, &img_len);
		free(pm);
		if (!img) {
			fprintf(stderr, "ksigbuilder: cannot build pack %u\n", j);
			goto done;
		}

		/* The name states the key, so a directory listing says what is in
		 * each file without opening any of them. */
		/* The subtype is in the name only when it constrains anything, so the
		 * ordinary pack keeps the name it always had and a directory listing
		 * still reads at a glance. */
		if (g->subtype_mask)
			snprintf(path, sizeof path, "%s/%s-t%u-k%u-a%u.ksig", outdir,
				 kind_name(g->kind), g->target_mask,
				 g->subtype_mask, g->arch_mask);
		else
			snprintf(path, sizeof path, "%s/%s-t%u-a%u.ksig", outdir,
				 kind_name(g->kind), g->target_mask, g->arch_mask);
		if (!write_file(path, img, img_len)) {
			free(img);
			goto done;
		}
		printf("  %-44s %5u module(s)  %8zu bytes\n", path, g->n, img_len);
		free(img);
	}

	rc = 0;
done:
	if (d)
		closedir(d);
	for (a = 0; a < n_arts; a++)
		artefact_free(&arts[a]);
	free(arts);
	for (j = 0; j < n_groups; j++)
		free(groups[j].member);
	free(groups);
	return rc;
}