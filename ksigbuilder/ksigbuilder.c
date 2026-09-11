/*
 * ksigbuilder - the C half of the signature toolchain.
 *
 *   ksigbuilder --extract <signature.c> <out.pat.h> <out.names> <out.pre> <out.strs>
 *   ksigbuilder <artefact-dir> <out-dir>
 *
 * The toolchain is one program now: --module turns one signature
 * source into one artefact, and this turns artefacts into .ksig packs. Everything
 * written in C is here.
 *
 * The split is by what each language is good at. Compiling a module is a wrapper
 * around cc, ld, nm and readelf, which is what a shell script is for. Reading
 * declarations out of a source and laying out bytes are neither, and both are C -
 * so they are one program with two modes rather than two programs, because a third
 * binary in the toolchain is a third thing to build, install and keep in step for
 * no gain. --extract is what --module calls; the pack mode is what the
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
 * One pack per (kind, target_mask, arch_mask). Every part of that key is derived
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
 *
 * WHY SUBTYPE IS NOT PART OF THE KEY
 *
 * It was, and it bought nothing, because the pack header has no field for it. There
 * is any_target, any_scan and any_arch, and no any_subtype - so a pack can never be
 * ruled out by subtype however it is grouped, and splitting by one only produced two
 * files where one would do. ELF and ELF-relocatable were separate packs of four
 * kilobytes each for a test that could not be performed.
 *
 * The filtering itself is untouched: every module carries its own subtype_mask into
 * the pack and the per-module precondition test reads it there, exactly as before.
 * What was dropped is a directory entry, not a check.
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

/* _GNU_SOURCE, not _POSIX_C_SOURCE: this file includes kofplatform.h, whose
 * POSIX half calls memmem - a GNU extension that <string.h> only declares when
 * this is defined, and defining it after the first include is too late. The
 * same reason kofinspect.c and kofexamine.c give. */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>

#include <kofmod/kofsig.h>   /* KOF_SCAN_ALL, the per-module maxima */
#include <kofmod/elf.h>      /* the ELF region names a range may be built from */
#include <kofmod/pe.h>       /* and the PE image kinds, for --subtype-mask */
#include <kofmod/heur.h>     /* the phases and want-bits a rule may declare */
/* The region lists, one per format: rgn_names[] below is generated from them
 * rather than restating them. */
#include "../libkofeng/core/kofplatform.h"
#include "../libkofeng/kofparsers/binaries/elf_parse.h"
#include "../libkofeng/kofparsers/binaries/pe_parse.h"
#include "../libkofeng/kofparsers/containers/gzip_parse.h"
#include "../libkofeng/kofparsers/containers/docole_parse.h"
#include "../libkofeng/kofparsers/containers/zip_parse.h"
#include "../libkofeng/kofparsers/containers/tar_parse.h"
#include "../libkofeng/kofparsers/containers/sevenzip_parse.h"
#include "../libkofeng/kofparsers/containers/rar_parse.h"
#include "../libkofeng/kofparsers/containers/xz_parse.h"
#include "../libkofeng/kofparsers/containers/rtf_parse.h"
#include "../libkofeng/kofparsers/containers/pdf_parse.h"
#include <kofmod/pe.h>       /* and the PE ones */
#include <kofmod/gzip.h>     /* and the gzip ones */
#include <kofmod/docole.h>   /* and the compound file ones */
#include <kofmod/zip.h>      /* and the zip ones, shared by ZIP and DOCZIP */
#include <kofmod/tar.h>
#include <kofmod/sevenzip.h>
#include <kofmod/rar.h>
#include <kofmod/xz.h>
#include <kofmod/rtf.h>
#include <kofmod/amsi.h>   /* an event's two regions */

#include "../libkofeng/kofdb/kofpackw.h"
#include "../libkofeng/kofdb/kofpack.h"
#include "../libkofeng/kofmatchers/hexprog.h"
#include "../libkofeng/core/kofcore.h"   /* kof_hash_bytes/kof_hash_step - FNV-1a,
					    reused for KOF_MALVAR_AUTO's suffix and
					    for the whole-module duplicate check */

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

	/*
	 * The text as it was WRITTEN, kept only for reporting.
	 *
	 * A wide pattern's bytes are the literal with zeros interleaved, so
	 * printing them - in the generated header's comment, in the build log -
	 * shows one character and stops at the first zero. What a reader needs
	 * to see in those places is the marker they typed.
	 *
	 * Empty for anything that is already readable as its own bytes.
	 */
	char     shown[MAX_LITERAL];
	int      wide;
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
	ELF_REGIONS(RGN)
	PE_REGIONS(RGN)
	GZIP_REGIONS(RGN)
	DOCOLE_REGIONS(RGN)
	ZIP_REGIONS(RGN)
	TAR_REGIONS(RGN)
	SZ_REGIONS(RGN)
	RAR_REGIONS(RGN)
	XZ_REGIONS(RGN)
	RTF_REGIONS(RGN)
	PDF_REGIONS(RGN)
	AMSI_REGIONS(RGN)

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
	DECL_STRWIDE,
	DECL_HEXSTR,
	DECL_NAME
};

struct macro {
	const char    *name;
	enum decl_kind kind;
};

static const struct macro macros[] = {
	{ "KOF_TARGET_RANGE",  DECL_RANGE   },
	{ "KOF_TARGET_NAME",   DECL_NAME    },
	{ "KOF_DEFINE_HEXSTR", DECL_HEXSTR  },
	/* BEFORE KOF_DEFINE_STR, which is a prefix of it - see the note on the
	 * enum above. Tested the other way round, every wide declaration would
	 * be read as a plain one and silently look for the unencoded bytes. */
	{ "KOF_DEFINE_STR_WIDE", DECL_STRWIDE },
	{ "KOF_DEFINE_STR",    DECL_STR     },
	{ NULL, DECL_RANGE }
};


/*
 * KOF_TARGET_NAME's two fields, file scoped like target_mask and its siblings: one
 * file, one family. Unlike those, read at this level rather than by the caller, because
 * composing a detection name is this program's job already - see read_variant.
 */
static char g_family[80];
static int  g_maltype;
static int  g_have_name;

/*
 * The most recently seen kof_find_str_any/all/multi(...) call, as normalised text -
 * what KOF_MALVAR_AUTO hashes. Updated by capture_find_call on every line regardless
 * of what else is on it, so by the time a KOF_SCAN_INFECT/SUSPECT(KOF_MALVAR_AUTO)
 * line is reached this holds whichever call guards it, in the ordinary
 * "if (kof_find_str_x(...)) KOF_SCAN_INFECT(...);" shape every signature in this
 * tree already uses.
 */
static int      g_have_find;
static char     g_find_sig[600];
/*
 * The same call RESOLVED to what it looks for - the pattern bytes of each
 * marker and the mask of each range, not the identifiers naming them. This is
 * what KOF_MALVAR_AUTO hashes now, because the identifier text does not: two
 * signatures generated by the viewer both spell their marker `s0` and their
 * range `scan_range_code`, so the x86 and x64 meterpreter detections - wholly
 * different patterns - hashed to one variant. See hash_resolved_call.
 */
static uint32_t g_find_hash;

/*
 * WHAT A HEURISTIC RULE'S NAME HASHES: the traits it declares.
 *
 * A detector's KOF_MALVAR_AUTO hashes the find call it guards, because that is
 * what makes one detection in a family different from another. A rule guards no
 * find call - it reads fields of the parse - so what distinguishes it is the set
 * of declarations at the top of the file: what it applies to, when it runs, what
 * it asks for, and what it is called. Change any of those and it is a different
 * rule and gets a different name; rebuild without changing them and the name is
 * the one it had.
 */
static char g_heur_sig[600];

static void heur_sig_add(const char *line)
{
	size_t n = strlen(g_heur_sig), k = 0;

	while (line[k] == ' ' || line[k] == '\t')
		k++;
	while (line[k] && line[k] != '\n' && n + 1 < sizeof g_heur_sig)
		g_heur_sig[n++] = line[k++];
	g_heur_sig[n] = 0;
}

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
		char c = *q;

		if (c == '\\') {
			/* The escape's own character, not a value: these three
			 * stand for themselves and that is the whole set. */
			if (q[1] != '\\' && q[1] != '"' && q[1] != '?') {
				err(line, "only \\\\, \\\" and \\? are supported in "
					  "patterns - use a hex pattern for "
					  "anything else");
				return 0;
			}
			c = q[1];
			q++;
		}
		if (n >= MAX_LITERAL) {
			err(line, "pattern literal too long");
			return 0;
		}
		out->bytes[n++] = (uint8_t)c;
		q++;
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

/* Argument 1 of KOF_TARGET_NAME(TYPE, "family") - one of the bare identifiers in
 * maltype_names. An unknown one is a build error naming every type that IS known,
 * the same courtesy read_mask gives an unknown region name. */
static int read_maltype(const char *p, int line, int *out)
{
	const char *a = nth_arg(p, 1, line);
	char tok[32];
	size_t n = 0;

	if (!a)
		return 0;
	while (*a == ' ' || *a == '\t' || *a == '\n' || *a == '\r')
		a++;
	while (*a && *a != ',' && *a != ')' && *a != ' ' && *a != '\t' &&
	       *a != '\n' && *a != '\r') {
		if (n + 1 >= sizeof tok) {
			err(line, "malware type name too long");
			return 0;
		}
		tok[n++] = *a++;
	}
	tok[n] = 0;
	if (kof_maltype_from_name(tok, out))
		return 1;
	fprintf(stderr, "%s:%d: error: \"%s\" is not a known malware type. "
			"Known:\n", src_name, line, tok);
#define X_SHOW(name, word) fprintf(stderr, "    %s\n", #name);
	KOF_MALTYPE_LIST(X_SHOW)
#undef X_SHOW
	errors++;
	return 0;
}

/* Argument 2 of KOF_TARGET_NAME(TYPE, "family") - a plain literal, read the same
 * restricted way read_hex_text and read_literal are: no escapes, quote to quote. */
static int read_family(const char *p, int line, char *out, size_t cap)
{
	const char *q = nth_arg(p, 2, line);
	size_t n = 0;

	if (!q)
		return 0;
	while (*q == ' ' || *q == '\t')
		q++;
	if (*q != '"') {
		err(line, "second argument of KOF_TARGET_NAME must be a family name "
			  "literal");
		return 0;
	}
	q++;
	while (*q && *q != '"') {
		if (n + 1 >= cap) {
			err(line, "family name too long");
			return 0;
		}
		out[n++] = *q++;
	}
	if (*q != '"' || n == 0) {
		err(line, "malformed family name");
		return 0;
	}
	out[n] = 0;
	/*
	 * THE CHARACTERS, checked here because this is the authority.
	 *
	 * kofviewer refuses them as they are typed, but a source written by
	 * hand never goes through the panel - and the name reaches a filesystem
	 * path, a C literal and a verdict line, so "anything between the
	 * quotes" was never the rule anyone meant. See kof_name_ok in kofsig.h.
	 */
	if (!kof_name_ok(out)) {
		err(line, "family name must be letters, digits, '-' or '_', "
			  "and at most 63 of them");
		return 0;
	}
	return 1;
}

/*
 * Copy the argument text of a balanced-parenthesis call, starting right after
 * `open` (which points at the '(') up to but not including the matching ')'.
 * Quotes are honoured, same rule nth_arg applies when splitting arguments, so a
 * comma or paren inside a pattern literal does not end the capture early.
 */
static size_t capture_balanced(const char *open, char *out, size_t cap)
{
	const char *p = open + 1;
	int depth = 1;
	size_t n = 0;

	while (*p && depth > 0) {
		if (*p == '"') {
			if (n + 1 < cap) out[n++] = *p;
			p++;
			while (*p && *p != '"') {
				if (*p == '\\' && p[1] && n + 1 < cap) {
					out[n++] = *p++;
				}
				if (n + 1 < cap)
					out[n++] = *p;
				p++;
			}
			if (*p == '"') {
				if (n + 1 < cap) out[n++] = *p;
				p++;
			}
			continue;
		}
		if (*p == '(') {
			depth++;
		} else if (*p == ')') {
			depth--;
			if (depth == 0)
				break;
		}
		if (n + 1 < cap)
			out[n++] = *p;
		p++;
	}
	out[n < cap ? n : cap - 1] = 0;
	return n;
}

/* Collapse every run of whitespace to one space and trim both ends, so
 * "a,  b"  and "a,\n\tb" hash identically. What this does NOT do is resolve an
 * identifier to what it was declared as - renaming a KOF_DEFINE_STR changes this
 * text and therefore changes KOF_MALVAR_AUTO's hash. Documented at KOF_SCAN_INFECT
 * in kofsig.h; accepted here rather than solved, because solving it means resolving
 * every identifier against the pats[] table instead of just capturing text. */
static void normalize_ws(char *s)
{
	char *r = s, *w = s;
	int sp = 1;

	for (; *r; r++) {
		if (*r == ' ' || *r == '\t' || *r == '\n' || *r == '\r') {
			if (!sp) {
				*w++ = ' ';
				sp = 1;
			}
		} else {
			*w++ = *r;
			sp = 0;
		}
	}
	while (w > s && w[-1] == ' ')
		w--;
	*w = 0;
}

static uint32_t hash_text(uint32_t h, const char *s)
{
	for (; *s; s++)
		h = kof_hash_step(h, (uint8_t)*s);
	return h;
}

/*
 * Fold ONE argument of a guard call into the hash, as the thing it NAMES.
 *
 * A marker identifier becomes its compiled pattern - kind, the two literal
 * flags, then the bytes; a range identifier becomes its mask. That is what
 * makes the variant a property of what the call looks for rather than of how
 * the source spells it, so two detections that search different bytes differ
 * even when both call their marker `s0`. Anything the tables do not know - an
 * inline range macro, a numeric count - falls back to its text, which is the
 * old behaviour for exactly the tokens that cannot be resolved.
 *
 * Resolvable because a marker is declared before the kof_scan that uses it - C
 * requires the identifier in scope - so pats[]/rngs[] already hold it by the
 * time a guard line is read.
 */
static uint32_t fold_arg(uint32_t h, const char *tok, size_t len)
{
	char name[80];
	int i;

	while (len && (tok[0] == ' ' || tok[0] == '\t')) { tok++; len--; }
	while (len && (tok[len - 1] == ' ' || tok[len - 1] == '\t')) len--;
	if (len >= sizeof name)
		len = sizeof name - 1u;
	memcpy(name, tok, len);
	name[len] = 0;

	for (i = 0; i < npats; i++)
		if (strcmp(pats[i].name, name) == 0) {
			uint32_t k;

			h = kof_hash_step(h, 'S');
			h = kof_hash_step(h, (uint8_t)pats[i].kind);
			h = kof_hash_step(h, (uint8_t)pats[i].icase);
			h = kof_hash_step(h, (uint8_t)pats[i].fullword);
			for (k = 0; k < pats[i].len; k++)
				h = kof_hash_step(h, pats[i].bytes[k]);
			return h;
		}
	for (i = 0; i < nrngs; i++)
		if (strcmp(rngs[i].name, name) == 0) {
			uint32_t m = rngs[i].mask;

			h = kof_hash_step(h, 'R');
			h = kof_hash_step(h, (uint8_t)m);
			h = kof_hash_step(h, (uint8_t)(m >> 8));
			h = kof_hash_step(h, (uint8_t)(m >> 16));
			h = kof_hash_step(h, (uint8_t)(m >> 24));
			return h;
		}
	h = kof_hash_step(h, 'T');
	return hash_text(h, name);
}

/*
 * Hash a guard call by its resolved content: the call kind, then each argument
 * as what it names (see fold_arg), then any ">= N" threshold. Splits on
 * top-level commas, skipping string literals and nested parens so an inline
 * pattern or range macro does not end an argument early.
 */
static uint32_t hash_resolved_call(const char *kind, const char *args,
				   const char *thresh)
{
	uint32_t h = hash_text(KOF_HASH_INIT, kind);
	const char *tok = args, *p = args;
	int depth = 0;

	for (;;) {
		char c = *p;

		if (c == '"') {
			p++;
			while (*p && *p != '"') {
				if (*p == '\\' && p[1])
					p++;
				p++;
			}
			if (*p)
				p++;
			continue;
		}
		if (c == '(') { depth++; p++; continue; }
		if (c == ')') { if (depth) depth--; p++; continue; }
		if (c == 0 || (c == ',' && depth == 0)) {
			h = fold_arg(h, tok, (size_t)(p - tok));
			if (c == 0)
				break;
			p++;
			tok = p;
			continue;
		}
		p++;
	}
	if (thresh && thresh[0])
		h = hash_text(h, thresh);
	return h;
}

/*
 * Look for kof_find_str_any/all/multi(...) on this line and, if found, remember its
 * region/pattern text and any trailing ">= N" threshold as g_find_sig - the input
 * KOF_MALVAR_AUTO hashes. Independent of the macros[] table: these are real,
 * compiled calls, not declarative macros that expand to nothing, so they are found
 * by their own scan rather than routed through scan_line's macro dispatch.
 */
static void capture_find_call(const char *at)
{
	static const char *kinds[] = { "kof_find_str_multi", "kof_find_str_all",
					"kof_find_str_any", NULL };
	const char *best = NULL;
	const char *best_kind = NULL;
	const char *open, *after;
	char args[500];
	char thresh[16];
	int k, depth;
	size_t tn;

	for (k = 0; kinds[k]; k++) {
		const char *q = strstr(at, kinds[k]);
		if (q && (!best || q < best)) {
			best = q;
			best_kind = kinds[k];
		}
	}
	if (!best)
		return;

	open = strchr(best, '(');
	if (!open)
		return;
	capture_balanced(open, args, sizeof args);
	normalize_ws(args);

	thresh[0] = 0;
	depth = 0;
	after = open;
	while (*after) {
		if (*after == '(') {
			depth++;
		} else if (*after == ')') {
			depth--;
			if (depth == 0) {
				after++;
				break;
			}
		}
		after++;
	}
	while (*after == ' ' || *after == '\t')
		after++;
	tn = 0;
	if (after[0] == '>' && after[1] == '=') {
		after += 2;
		while (*after == ' ' || *after == '\t')
			after++;
		while (*after >= '0' && *after <= '9' && tn + 1 < sizeof thresh)
			thresh[tn++] = *after++;
	}
	thresh[tn] = 0;

	snprintf(g_find_sig, sizeof g_find_sig, "%s(%s)%s%s", best_kind, args,
		 thresh[0] ? ">=" : "", thresh);
	g_find_hash = hash_resolved_call(best_kind, args, thresh);
	g_have_find = 1;
}

/* Base36, fixed at 5 digits - long enough that a 4000 signature database has a
 * negligible chance of two AUTO variants in the same family colliding, short enough
 * to read as a tag rather than a hash dump. */
static void suffix_from_hash(char out[6], uint32_t h)
{
	static const char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
	int i;

	for (i = 4; i >= 0; i--) {
		out[i] = digits[h % 36];
		h /= 36;
	}
	out[5] = 0;
}

/* A heuristic rule hashes its declared traits as text - see g_heur_sig. */
static void auto_suffix_of(char out[6], const char *sig)
{
	suffix_from_hash(out, kof_hash_bytes(sig, strlen(sig)));
}

/* A detector hashes the RESOLVED content of the call it guards, not the text. */
static void auto_suffix(char out[6])
{
	suffix_from_hash(out, g_find_hash);
}

/*
 * Argument 1 of KOF_SCAN_INFECT/SUSPECT(variant): a quoted custom variant,
 * KOF_MALVAR_GENERIC, or KOF_MALVAR_AUTO. Composes the full detection name with the
 * KOF_TARGET_NAME this file already declared - see kofsig.h for why the three forms
 * exist and what AUTO hashes.
 */
static int read_variant(const char *p, int line, char *out, size_t cap)
{
	const char *q;
	char raw[128];
	size_t rn = 0;
	int n;

	if (!g_have_name) {
		err(line, "KOF_SCAN_INFECT/SUSPECT used before KOF_TARGET_NAME is "
			  "declared; declare the type and family first");
		return 0;
	}

	q = nth_arg(p, 1, line);
	if (!q)
		return 0;
	while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r')
		q++;

	if (*q == '"') {
		q++;
		while (*q && *q != '"') {
			if (rn + 1 >= sizeof raw) {
				err(line, "detection variant too long");
				return 0;
			}
			/*
			 * A NAME, AND ONLY THE CHARACTERS A NAME HAS.
			 *
			 * This becomes part of a detection string a scanner
			 * prints - "ELF-x64/Botnet:Mirai-0i0bq" - so letters,
			 * digits, '-' and '_' are the whole of it - the same
			 * set kof_name_ok fixes for a family, because they end
			 * up in the same detection string. Anything else
			 * is refused rather than carried, and the reason is
			 * what a quote does on the way IN to a file rather
			 * than out of it: a tool that generates signatures
			 * writes this variant back as a quoted literal, and a
			 * quote inside it ends that literal early, leaving
			 * whatever follows as C the build compiles. Checking
			 * here rather than only in the generator means a file
			 * written by hand is checked too.
			 */
			if (!kof_name_char((unsigned char)*q)) {
				err(line, "detection variant may hold letters, "
					  "digits, '-' and '_' only");
				return 0;
			}
			raw[rn++] = *q++;
		}
		if (*q != '"' || rn == 0) {
			err(line, "malformed detection variant");
			return 0;
		}
		raw[rn] = 0;
	} else {
		while (*q && *q != ',' && *q != ')' && *q != ' ' && *q != '\t' &&
		       *q != '\n' && *q != '\r') {
			if (rn + 1 >= sizeof raw) {
				err(line, "argument too long");
				return 0;
			}
			raw[rn++] = *q++;
		}
		raw[rn] = 0;

		if (strcmp(raw, "KOF_MALVAR_GENERIC") == 0) {
			/* Generic means exactly one thing: the family's one
			 * undifferentiated bucket. Nothing is appended to it -
			 * appending anything would make it stop meaning that. */
			strcpy(raw, "Generic");
		} else if (strcmp(raw, "KOF_MALVAR_AUTO") == 0) {
			/* AUTO is the opposite of generic: a stable, SPECIFIC
			 * identity for this exact pattern, distinguishable from
			 * every other AUTO variant in the same family. Prefixing
			 * it with "Generic-" said the opposite of what it is -
			 * fixed after it was pointed out. The hash stands alone. */
			if (!g_have_find) {
				err(line, "KOF_MALVAR_AUTO must directly guard a "
					  "single kof_find_str_any/all/multi(...) "
					  "condition");
				return 0;
			}
			auto_suffix(raw);
		} else {
			fprintf(stderr, "%s:%d: error: the argument to "
					"KOF_SCAN_INFECT/SUSPECT must be a quoted "
					"variant name, KOF_MALVAR_AUTO, or "
					"KOF_MALVAR_GENERIC, not \"%s\"\n",
				src_name, line, raw);
			errors++;
			return 0;
		}
	}

	/*
	 * The variant only - not composed with family or type here anymore.
	 * KOF_TARGET_NAME is one declaration per file; composing its family and
	 * type into every finding's text repeated that declaration once per
	 * finding in the name pool. The host composes the full string at
	 * report time instead, from this variant plus the module's own
	 * family_off/maltype record - see struct kof_pack_mod in kofpack.h and
	 * finding_str in scan.c.
	 */
	n = snprintf(out, cap, "%s", raw);
	if (n < 0 || (size_t)n >= cap) {
		err(line, "detection variant too long");
		return 0;
	}
	return 1;
}

/*
 * Handle one source line: a macro is found within the line, but its arguments are
 * read from the full buffer, because an invocation may wrap onto the next line.
 * nth_arg treats a newline like any other space, so it spans lines by itself.
 */
/*
 * ---------------------------------------------------------------------------
 * THE DECLARATIONS THE BUILD READS OUT OF A SOURCE.
 *
 * These were read by the shell, with grep and sed, against C source. That was
 * wrong in a way this file is already equipped to avoid: the scan below runs on
 * a buffer strip_comments has been over, so a macro NAMED IN A COMMENT is not a
 * declaration. The shell had no such notion and counted it - a signature whose
 * header block explained that it "used to be KOF_TARGET_FORMAT(KOF_FMT_PE)" was
 * refused with "2 KOF_TARGET_FORMAT declarations", which names nothing a reader
 * can act on.
 *
 * It was also learning enum values by matching this project's own headers with
 * a regex. Those values are constants to a C program, and the engine publishes
 * the identifier-to-value direction for every one of them - kof_format_from_name
 * and its siblings - so the vocabulary is inherited rather than re-derived.
 * ---------------------------------------------------------------------------
 */
#define DECL_ARG_MAX 512

struct simple_decl {
	const char *name;
	/*
	 * A SECOND SPELLING OF THE SAME DECLARATION, or NULL.
	 *
	 * One slot, two names: KOF_TARGET_EVENT and KOF_TARGET_FORMAT say the
	 * same thing about the same axis, and an author writing a rule about a
	 * script submission should not have to call it a format. Sharing the
	 * slot rather than adding one is what keeps "declared twice" working -
	 * a module that uses both spellings has answered one question twice,
	 * and gets the same error as a module that repeated either.
	 */
	const char *alias;
	int         count;
	int         line;
	char        arg[DECL_ARG_MAX];
};

enum {
	SD_FORMAT = 0, SD_ARCH, SD_SUBTYPE, SD_SIZE_MIN, SD_UNPACK_KIND,
	SD_HEUR_PHASE, SD_HEUR_LEVEL, SD_HEUR_WANT,
	SD_HEUR_NAME, SD_HEUR_PREDICT, SD_COUNT
};

static struct simple_decl g_decl[SD_COUNT] = {
	{ "KOF_TARGET_FORMAT",  "KOF_TARGET_EVENT", 0, 0, { 0 } },
	{ "KOF_TARGET_ARCH",    NULL, 0, 0, { 0 } },
	{ "KOF_TARGET_SUBTYPE", NULL, 0, 0, { 0 } },
	{ "KOF_TARGET_SIZE_MIN",NULL, 0, 0, { 0 } },
	{ "KOF_UNPACK_KIND",    NULL, 0, 0, { 0 } },
	{ "KOF_HEUR_PHASE",     NULL, 0, 0, { 0 } },
	{ "KOF_HEUR_LEVEL",     NULL, 0, 0, { 0 } },
	{ "KOF_HEUR_WANT",      NULL, 0, 0, { 0 } },
	{ "KOF_HEUR_NAME",      NULL, 0, 0, { 0 } },
	{ "KOF_HEUR_PREDICT",   NULL, 0, 0, { 0 } }
};

/*
 * The text between the parentheses, with whitespace squeezed out.
 *
 * Nesting is counted rather than stopping at the first ')', so an argument that
 * is itself a call - KOF_TARGET_SIZE_MIN(sizeof(x)) - is read whole instead of
 * being cut in half. The shell's sed pattern stopped at [^)]* and could not.
 */
static int decl_arg(const char *at, char *out, size_t cap)
{
	int depth = 0;
	size_t n = 0;

	while (*at && *at != '(')
		at++;
	if (!*at)
		return 0;
	for (; *at; at++) {
		if (*at == '(') {
			depth++;
			if (depth == 1)
				continue;
		} else if (*at == ')') {
			depth--;
			if (!depth)
				break;
		}
		if (depth >= 1 && !isspace((unsigned char)*at)) {
			if (n + 1u >= cap)
				return 0;
			out[n++] = *at;
		}
	}
	out[n] = 0;
	return depth == 0 && n > 0;
}

/* Whether `hay` names `needle` as a whole identifier, so KOF_FMT_ZIP does not
 * answer for a source that said KOF_FMT_DOCZIP. The shell matched substrings
 * and got away with it only because no two names in the enum happen to overlap;
 * the next one added could. */
static int names_ident(const char *hay, const char *needle)
{
	size_t nl = strlen(needle);
	const char *p = hay;

	while ((p = strstr(p, needle)) != NULL) {
		char before = (p == hay) ? 0 : p[-1];
		char after = p[nl];

		if (!isalnum((unsigned char)before) && before != '_' &&
		    !isalnum((unsigned char)after) && after != '_')
			return 1;
		p += nl;
	}
	return 0;
}

static void decl_collect(const char *at, int lineno)
{
	int i;

	for (i = 0; i < SD_COUNT * 2; i++) {
		struct simple_decl *d = &g_decl[i % SD_COUNT];
		const char *want = (i < SD_COUNT) ? d->name : d->alias;
		const char *p = at;
		size_t nl;

		if (!want)
			continue;
		nl = strlen(want);

		while ((p = strstr(p, want)) != NULL) {
			/* A longer identifier that merely contains this one is
			 * not this declaration. */
			if (p[nl] != '(' ||
			    (p != at && (isalnum((unsigned char)p[-1]) ||
					 p[-1] == '_'))) {
				p += nl;
				continue;
			}
			if (d->count == 0) {
				d->line = lineno;
				if (!decl_arg(p, d->arg, sizeof d->arg))
					d->arg[0] = 0;
			}
			d->count++;
			p += nl;
		}
	}
}

/* What the resolution below produces, for the caller that writes .pre. */
static uint32_t g_target_mask, g_arch_mask, g_subtype_mask;
static uint64_t g_size_min;
static int      g_unp_kind, g_heur_phase, g_heur_level, g_heur_want;
static int      g_n_targets;

/* One name at a time out of "A|B|C", which is the only shape these arguments
 * take: the declarations are masks and the language for combining them is '|'. */
static const char *decl_next(const char *p, char *out, size_t cap)
{
	size_t n = 0;

	while (*p == '|')
		p++;
	if (!*p)
		return NULL;
	while (*p && *p != '|') {
		if (n + 1u < cap)
			out[n++] = *p;
		p++;
	}
	out[n] = 0;
	return p;
}

static void resolve_format(void)
{
	const struct simple_decl *d = &g_decl[SD_FORMAT];
	char one[128];
	const char *p = d->arg;

	if (d->count > 1) {
		err(d->line, "more than one KOF_TARGET_FORMAT; use one "
			     "declaration with '|'");
		return;
	}
	if (!d->count || !d->arg[0]) {
		err(1, "no KOF_TARGET_FORMAT(...) declaration; a module must "
		       "say what it applies to");
		return;
	}
	/*
	 * ANY is every format at once, and the mask is derived from the enum
	 * rather than written down. It was once the literal 127, which stopped
	 * meaning "every format" the moment one was added - and a module that
	 * silently no longer covers a format is a detection that does not
	 * happen, which no test notices.
	 */
	if (names_ident(d->arg, "KOF_FMT_ANY")) {
		g_target_mask = (uint32_t)((1u << KOF_FMT_COUNT) - 1u);
		g_n_targets = KOF_FMT_COUNT;
		return;
	}
	while ((p = decl_next(p, one, sizeof one)) != NULL) {
		uint8_t fmt;

		if (!kof_format_from_name(one, &fmt)) {
			char msg[192];

			snprintf(msg, sizeof msg,
				 "KOF_TARGET_FORMAT names no known format: %s",
				 one);
			err(d->line, msg);
			return;
		}
		g_target_mask |= 1u << fmt;
		g_n_targets++;
	}
}

static void resolve_arch(void)
{
	const struct simple_decl *d = &g_decl[SD_ARCH];
	char one[128];
	const char *p = d->arg;

	if (!d->count)
		return;
	if (d->count > 1) {
		err(d->line, "more than one KOF_TARGET_ARCH; use one "
			     "declaration with '|'");
		return;
	}
	while ((p = decl_next(p, one, sizeof one)) != NULL) {
		uint8_t a;

		if (!kof_arch_from_name(one, &a)) {
			char msg[192];

			snprintf(msg, sizeof msg,
				 "KOF_TARGET_ARCH names no known architecture: "
				 "%s", one);
			err(d->line, msg);
			return;
		}
		g_arch_mask |= 1u << a;
	}
}

/*
 * Subtypes are the format's own vocabulary, so which header answers depends on
 * what the module targets - and naming one format's subtypes while targeting
 * another is refused here rather than left to collide at scan time. The values
 * deliberately overlap between formats; see the note on ctx->subtype.
 */
static void resolve_subtype(void)
{
	const struct simple_decl *d = &g_decl[SD_SUBTYPE];
	char one[128];
	const char *p = d->arg;
	int want_elf = (g_target_mask & (1u << KOF_FMT_ELF)) != 0;
	int want_pe = (g_target_mask & (1u << KOF_FMT_PE)) != 0;

	if (!d->count)
		return;
	if (d->count > 1) {
		err(d->line, "more than one KOF_TARGET_SUBTYPE; use one "
			     "declaration with '|'");
		return;
	}
	while ((p = decl_next(p, one, sizeof one)) != NULL) {
		uint32_t v;
		char msg[192];

		if (kof_elf_type_from_name(one, &v)) {
			if (!want_elf) {
				snprintf(msg, sizeof msg,
					 "KOF_TARGET_SUBTYPE names %s but the "
					 "module does not target ELF", one);
				err(d->line, msg);
				return;
			}
		} else if (kof_pe_image_from_name(one, &v)) {
			if (!want_pe) {
				snprintf(msg, sizeof msg,
					 "KOF_TARGET_SUBTYPE names %s but the "
					 "module does not target PE", one);
				err(d->line, msg);
				return;
			}
		} else {
			snprintf(msg, sizeof msg,
				 "KOF_TARGET_SUBTYPE names no known subtype: "
				 "%s", one);
			err(d->line, msg);
			return;
		}
		if (v >= 32u) {
			err(d->line, "subtype value is outside the mask");
			return;
		}
		g_subtype_mask |= 1u << v;
	}
}

/*
 * A plain arithmetic expression, evaluated only far enough to be a number.
 *
 * The shell required "a plain arithmetic expression" and then handed it to $((
 * )), which is a full expression evaluator with variable expansion in it. This
 * accepts a decimal or hex literal with the shifts and multiplications a size
 * is actually written with, and refuses anything else - which is the rule the
 * error message always claimed.
 */
static int decl_uint(const char *p, uint64_t *out)
{
	uint64_t acc = 0;
	int any = 0;

	while (*p) {
		uint64_t v;
		char *end;

		if (*p == '+') { p++; continue; }
		v = strtoull(p, &end, 0);
		if (end == p)
			return 0;
		p = end;
		while (*p == '<' && p[1] == '<') {
			uint64_t sh = strtoull(p + 2, &end, 0);

			if (end == p + 2 || sh > 63u)
				return 0;
			v <<= sh;
			p = end;
		}
		while (*p == '*') {
			uint64_t m = strtoull(p + 1, &end, 0);

			if (end == p + 1)
				return 0;
			v *= m;
			p = end;
		}
		acc += v;
		any = 1;
	}
	*out = acc;
	return any;
}

static void resolve_size_min(void)
{
	const struct simple_decl *d = &g_decl[SD_SIZE_MIN];

	if (!d->count)
		return;
	if (d->count > 1) {
		err(d->line, "more than one KOF_TARGET_SIZE_MIN; a module has "
			     "one minimum");
		return;
	}
	if (!decl_uint(d->arg, &g_size_min)) {
		err(d->line, "KOF_TARGET_SIZE_MIN is not a plain arithmetic "
			     "expression");
		return;
	}
	/* Zero is what a module with no declaration already has, so declaring
	 * it says nothing and reads as though it did. */
	if (!g_size_min)
		err(d->line, "KOF_TARGET_SIZE_MIN(0) constrains nothing; omit it");
}

static void resolve_unpack_kind(void)
{
	const struct simple_decl *d = &g_decl[SD_UNPACK_KIND];

	if (!d->count)
		return;
	if (d->count > 1) {
		err(d->line, "more than one KOF_UNPACK_KIND; a module is one "
			     "kind");
		return;
	}
	if (names_ident(d->arg, "KOF_UNP_PACKER"))
		g_unp_kind = KOF_UNP_PACKER;
	else if (names_ident(d->arg, "KOF_UNP_CONTAINER"))
		g_unp_kind = KOF_UNP_CONTAINER;
	else
		err(d->line, "KOF_UNPACK_KIND names no known kind; use "
			     "KOF_UNP_PACKER or KOF_UNP_CONTAINER");
}

static void resolve_heur(void)
{
	const struct simple_decl *ph = &g_decl[SD_HEUR_PHASE];
	const struct simple_decl *lv = &g_decl[SD_HEUR_LEVEL];
	const struct simple_decl *wt = &g_decl[SD_HEUR_WANT];

	if (ph->count > 1) {
		err(ph->line, "more than one KOF_HEUR_PHASE; a rule runs at "
			      "one point");
	} else if (ph->count) {
		if (names_ident(ph->arg, "KOF_HEUR_VERDICT"))
			g_heur_phase = KOF_HEUR_VERDICT;
		else if (names_ident(ph->arg, "KOF_HEUR_EXAMINE"))
			g_heur_phase = KOF_HEUR_EXAMINE;
		else
			err(ph->line, "KOF_HEUR_PHASE names no known phase; use "
				      "KOF_HEUR_EXAMINE or KOF_HEUR_VERDICT");
	}

	if (lv->count > 1) {
		err(lv->line, "more than one KOF_HEUR_LEVEL; a rule has one "
			      "level");
	} else if (lv->count) {
		uint64_t v = 0;

		if (!decl_uint(lv->arg, &v) || v < 1u || v > 2u)
			err(lv->line, "KOF_HEUR_LEVEL is not a level; use 1 or "
				      "2 - level 0 gathers nothing, so no rule "
				      "can opt into it");
		else
			g_heur_level = (int)v;
	}

	if (wt->count > 1) {
		err(wt->line, "more than one KOF_HEUR_WANT; use one "
			      "declaration with '|'");
	} else if (wt->count) {
		if (names_ident(wt->arg, "KOF_ENG_USE_EMU"))
			g_heur_want |= KOF_ENG_USE_EMU;
		else if (names_ident(wt->arg, "KOF_ENG_OPEN_CARRIED"))
			g_heur_want |= KOF_ENG_OPEN_CARRIED;
		else
			err(wt->line, "KOF_HEUR_WANT names nothing the engine "
				      "offers");
	}
}

/* The quoted text of a string declaration, without its quotes. Empty when the
 * declaration is absent, which is what an optional one looks like. */
static void decl_text(const struct simple_decl *d, char *out, size_t cap)
{
	const char *a = d->arg;
	size_t n = 0;

	out[0] = 0;
	if (!d->count || a[0] != '"')
		return;
	a++;
	while (*a && *a != '"' && n + 1u < cap)
		out[n++] = *a++;
	out[n] = 0;
}

static char g_heur_name[64], g_heur_predict[64];

/* What the module mode needs from the extract pass, which computes them. */
static unsigned long g_scan_mask_out;
static int           g_nstr_out;

static void resolve_decls(void)
{
	decl_text(&g_decl[SD_HEUR_NAME], g_heur_name, sizeof g_heur_name);
	decl_text(&g_decl[SD_HEUR_PREDICT], g_heur_predict,
		  sizeof g_heur_predict);
	resolve_format();
	resolve_arch();
	resolve_subtype();
	resolve_size_min();
	resolve_unpack_kind();
	resolve_heur();
}

/*
 * Turn a literal into the bytes a UTF-16LE target holds, in place.
 *
 * The whole of the wide support: one interleave at build time and an ordinary
 * pool entry afterwards. See KOF_DEFINE_STR_WIDE for why it is done here and
 * not as a compare mode in the matcher.
 */
static int widen(struct pat *o, int line)
{
	uint8_t out[KOF_HEX_MAX_PROG];
	uint32_t i;

	/*
	 * REFUSED, NOT ENCODED WRONG. One byte and a zero is UTF-16LE only for
	 * ASCII; for anything above it the real encoding is a different number
	 * of bytes with different values, so writing two here would produce a
	 * marker that is not the text the author wrote and would never fire.
	 */
	for (i = 0; i < o->len; i++) {
		if (o->bytes[i] >= 0x80u) {
			err(line, "a wide pattern must be ASCII - a byte above "
				  "0x7F is not one UTF-16 unit, so it cannot be "
				  "widened by interleaving zeros");
			return 0;
		}
	}
	if (o->len * 2u > sizeof out) {
		err(line, "wide pattern too long once widened");
		return 0;
	}

	/* Kept before the bytes are replaced - it is what every report shows. */
	if (o->len < sizeof o->shown) {
		memcpy(o->shown, o->bytes, o->len);
		o->shown[o->len] = '\0';
	}
	o->wide = 1;

	for (i = 0; i < o->len; i++) {
		out[i * 2u]      = o->bytes[i];
		out[i * 2u + 1u] = 0;
	}
	o->len *= 2u;
	memcpy(o->bytes, out, o->len);
	return 1;
}

static void scan_line(char *at, size_t line_len, int lineno)
{
	const struct macro *m = NULL;
	char *p;
	int is_variant = 0, is_heur_hit = 0;
	char saved = at[line_len];

	/* Find within the line; read arguments from the full buffer. Comments were
	 * blanked before this ran, so anything found here is code. */
	at[line_len] = 0;

	/* Independent of the dispatch below: a real, compiled call rather than a
	 * declarative macro, so it is found by its own scan rather than routed
	 * through it - see capture_find_call. Run on every line, whether or not the
	 * line turns out to hold a macro this function also cares about. */
	capture_find_call(at);

	/* kof_debug names go in the same table and are keyed the same way: both use
	 * __LINE__ as the id, so the host resolves either through one lookup. */
	/* The declarations a rule's name hashes, gathered as they go past. Before
	 * the dispatch below because KOF_TARGET_FORMAT is in the macros[] table
	 * and would otherwise be consumed by it. */
	if (strstr(at, "KOF_HEUR_PHASE(") || strstr(at, "KOF_HEUR_WANT(") ||
	    strstr(at, "KOF_HEUR_LEVEL(") ||
	    strstr(at, "KOF_HEUR_NAME(") || strstr(at, "KOF_TARGET_FORMAT("))
		heur_sig_add(at);

	p = strstr(at, "KOF_SCAN_INFECT");
	if (!p)
		p = strstr(at, "KOF_SCAN_SUSPECT");
	if (p)
		is_variant = 1;
	if (!p && (p = strstr(at, "KOF_HEUR_HIT")) != NULL)
		is_heur_hit = 1;
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
		if (is_heur_hit) {
			/* No argument to read: a rule has one name and it is
			 * declared, so what varies between two hits in one rule
			 * is nothing - and the hash is of the rule, not of the
			 * line. */
			auto_suffix_of(names[nnames].text, g_heur_sig);
		} else if (is_variant) {
			if (!read_variant(p, lineno, names[nnames].text,
					  sizeof names[nnames].text))
				return;
		} else if (!read_name(p, lineno, names[nnames].text,
				       sizeof names[nnames].text)) {
			return;
		}
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

	if (m->kind == DECL_NAME) {
		int type_idx;

		if (g_have_name) {
			err(lineno, "KOF_TARGET_NAME declared more than once; a "
				    "module has one family");
			return;
		}
		if (!read_maltype(p, lineno, &type_idx))
			return;
		if (!read_family(p, lineno, g_family, sizeof g_family))
			return;
		g_maltype = type_idx;
		g_have_name = 1;
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

		if (m->kind == DECL_STRWIDE && !widen(o, lineno))
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
	fprintf(out, "/* line %d: \"%.*s\"%s%s%s */\n", p->line,
		p->wide ? (int)strlen(p->shown) : (int)p->len,
		p->wide ? p->shown : (const char *)p->bytes,
		p->wide ? " wide" : "",
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
	/*
	 * A LITERAL THAT IS NOT TEXT goes in hex too, and keeps its options.
	 *
	 * The 's' row puts the bytes last so nothing in them needs escaping -
	 * which holds only while they are printable. A wide pattern is the
	 * literal with zero high bytes interleaved, so the row ended at the
	 * first character and the reader's own length check refused the build:
	 * "string of declared length 28 does not match its literal". Loud, and
	 * still a build that cannot produce a wide signature.
	 *
	 * 'h' is not the answer either - it means a compiled hex PROGRAM, and
	 * reading a literal back as one would change what the matcher does with
	 * it. So 'w': a literal, in hex, with the icase and fullword columns an
	 * 'h' row has no room for.
	 *
	 * Chosen by what the bytes ARE, not by which macro was used. Anything
	 * that cannot survive a text column takes this row, so a future pattern
	 * with a control byte in it works without anyone remembering this.
	 */
	{
		int text_safe = 1;

		for (i = 0; i < p->len; i++) {
			uint8_t c = p->bytes[i];

			if (c < 0x20u || c == 0x7fu) {
				text_safe = 0;
				break;
			}
		}
		if (!text_safe) {
			/* The wide column belongs on this row and only this
			 * row: a widened pattern has a zero above every
			 * character, so it is never text-safe and can never
			 * take the 's' path. */
			fprintf(out, "w\t%d\t%d\t%d\t%d\t%u\t", idx,
				p->icase, p->fullword, p->wide, p->len);
			for (i = 0; i < p->len; i++)
				fprintf(out, "%02x", p->bytes[i]);
			fputc('\n', out);
			return;
		}
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
/*
 * ---------------------------------------------------------------------------
 * RUNNING THE COMPILER AND THE LINKER, WITHOUT A SHELL.
 *
 * These two cannot be removed - there is no compiling C without a compiler -
 * but the SHELL that ran them can be, and that is the one a Windows host does
 * not have. Everything else the build did with grep, sed, awk, nm, readelf,
 * size and objcopy is already inside this program; this is what lets the last
 * of it move too.
 *
 * The argument vector is passed as a vector on both systems. On Windows that
 * means building a command line and quoting it by the documented rule, because
 * CreateProcess takes one string and the child is what splits it again - a
 * signature source under a path with a space in it would otherwise arrive as
 * two arguments.
 * ---------------------------------------------------------------------------
 */
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#endif

static int run_tool(const char *const *argv)
{
#ifdef _WIN32
	char cmd[8192];
	size_t at = 0;
	int i;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	DWORD code = 1;

	for (i = 0; argv[i]; i++) {
		const char *a = argv[i];
		size_t j;

		if (at + 3u >= sizeof cmd)
			return -1;
		if (i)
			cmd[at++] = ' ';
		cmd[at++] = '"';
		for (j = 0; a[j]; j++) {
			size_t bs = 0;

			while (a[j] == '\\') { bs++; j++; }
			if (!a[j]) {
				bs *= 2u;
				while (bs-- && at + 2u < sizeof cmd)
					cmd[at++] = '\\';
				break;
			}
			if (a[j] == '"')
				bs = bs * 2u + 1u;
			while (bs-- && at + 2u < sizeof cmd)
				cmd[at++] = '\\';
			if (at + 2u >= sizeof cmd)
				return -1;
			cmd[at++] = a[j];
		}
		if (at + 2u >= sizeof cmd)
			return -1;
		cmd[at++] = '"';
	}
	cmd[at] = 0;
	memset(&si, 0, sizeof si);
	si.cb = sizeof si;
	memset(&pi, 0, sizeof pi);
	if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL,
			    &si, &pi))
		return -1;
	WaitForSingleObject(pi.hProcess, INFINITE);
	GetExitCodeProcess(pi.hProcess, &code);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return (int)code;
#else
	pid_t pid = fork();
	int status = 0;

	if (pid < 0)
		return -1;
	if (pid == 0) {
		union { const char *const *c; char *const *v; } u;

		u.c = argv;
		execvp(argv[0], u.v);
		_exit(127);
	}
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
#endif
}

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

/*
 * ---------------------------------------------------------------------------
 * WHAT THE LINKED IMAGE HAS TO BE, ASKED OF THE ENGINE'S OWN PARSER.
 *
 * These questions - are there relocations, are there undefined symbols, is
 * there anything but the blob section, which entry point does it export and at
 * what offset - were asked by running readelf, nm and size and reading their
 * text. Four processes per module, a text format each, and a grep or an awk to
 * pull the answer out.
 *
 * They are all facts about an ELF file, and this program already links the
 * parser the SCANNER uses to read one. Asking that parser instead is shorter,
 * needs no toolchain beyond the compiler and linker, and - the part that
 * matters - checks the image with the same code that will later refuse it at
 * load time, rather than with a different program that might disagree.
 *
 * The symbol table is walked here rather than through kofsym.h: that layout is
 * built by the scanner for rules to match on, and what is wanted here is the
 * raw st_shndx and st_value of three specific names.
 * ---------------------------------------------------------------------------
 */
struct img_facts {
	int      have_reloc;
	char     extra_sec[128];   /* first unexpected section, or empty */
	char     undef[128];       /* first undefined symbol, or empty */
	char     entry_name[32];   /* kof_scan / kof_unpack / kof_heur */
	uint64_t entry_off;
	int      n_entry;
	uint64_t blob_off, blob_len;
	uint64_t data_bytes, bss_bytes;
};

static uint64_t rd_le(const uint8_t *p, unsigned n)
{
	uint64_t v = 0;
	unsigned i;

	for (i = 0; i < n; i++)
		v |= (uint64_t)p[i] << (8u * i);
	return v;
}

/*
 * THE SAME FACTS OUT OF A COFF OBJECT, for the Windows half of the build.
 *
 * Windows asks two different files two different questions: the linked PE for
 * relocations and sections, and the OBJECT for symbols - because lld strips the
 * image's symbol table by default, so by the time the image exists there is
 * nothing left to ask which entry point it carries.
 *
 * A COFF symbol record is eighteen bytes and the format has not moved since
 * 1993: an eight byte name field that either holds the name or, when its first
 * four bytes are zero, an offset into the string table that follows the symbol
 * table. Reading it directly is shorter than the awk that read llvm-nm's output
 * and does not depend on that program being installed.
 */
static int coff_read(const char *path, struct img_facts *out)
{
	uint8_t *b;
	size_t len;
	uint32_t symptr, nsym, strtab, i;

	memset(out, 0, sizeof *out);
	b = (uint8_t *)slurp(path, &len);
	if (!b)
		return 0;
	if (len < 20u) {
		free(b);
		return 0;
	}
	symptr = (uint32_t)rd_le(b + 8, 4);
	nsym = (uint32_t)rd_le(b + 12, 4);
	strtab = symptr + nsym * 18u;
	if (!symptr || !nsym || strtab > len) {
		free(b);
		return 0;
	}

	/*
	 * The sections, for the same question the ELF side asks of .data and
	 * .bss: does this module carry state.
	 *
	 * COFF has no single writable/non-writable pair that reads off a size
	 * report - .rdata is legitimately data and must not count - so the
	 * name is what decides, and -fdata-sections spells a global in
	 * .data$<name> or .bss$<name> rather than in a section called exactly
	 * .data. The prefix is therefore what is matched, not the whole name.
	 *
	 * A section header is forty bytes, after the twenty byte file header
	 * and whatever optional header it declares - an object declares none,
	 * but the field is read rather than assumed.
	 */
	{
		uint32_t nsec = (uint32_t)rd_le(b + 2, 2);
		uint32_t optsz = (uint32_t)rd_le(b + 16, 2);
		uint64_t at = 20u + optsz;

		for (i = 0; i < nsec; i++, at += 40u) {
			const uint8_t *s = b + at;
			char nm[9];
			uint64_t raw;

			if (at + 40u > (uint64_t)len)
				break;
			memcpy(nm, s, 8);
			nm[8] = 0;
			raw = rd_le(s + 16, 4);          /* SizeOfRawData */
			if (!strncmp(nm, ".bss", 4))
				out->bss_bytes += raw;
			else if (!strncmp(nm, ".data", 5))
				out->data_bytes += raw;
		}
	}

	for (i = 0; i < nsym; i++) {
		const uint8_t *e = b + symptr + (size_t)i * 18u;
		char name[64];
		int16_t sect;
		uint32_t value;

		if (symptr + (size_t)i * 18u + 18u > len)
			break;
		value = (uint32_t)rd_le(e + 8, 4);
		sect = (int16_t)rd_le(e + 12, 2);
		if (rd_le(e, 4) == 0) {
			uint32_t off = (uint32_t)rd_le(e + 4, 4);

			if (strtab + off >= len)
				goto next;
			snprintf(name, sizeof name, "%s",
				 (const char *)b + strtab + off);
		} else {
			size_t k;

			for (k = 0; k < 8u && e[k]; k++)
				name[k] = (char)e[k];
			name[k] = 0;
		}
		if (!name[0])
			goto next;
		/* Section 0 with a value of zero is an external nobody
		 * defined; with a non-zero value it is a common symbol, which
		 * is storage and therefore also refused. */
		if (sect == 0) {
			if (!out->undef[0] &&
			    (!strcmp(name, "kof_scan") ||
			     !strcmp(name, "kof_unpack") ||
			     !strcmp(name, "kof_heur")) == 0)
				snprintf(out->undef, sizeof out->undef, "%s",
					 name);
			goto next;
		}
		if (!strcmp(name, "kof_scan") || !strcmp(name, "kof_unpack") ||
		    !strcmp(name, "kof_heur")) {
			out->n_entry++;
			/* Bounded explicitly: the three names it can be are
			 * all shorter than the field, and saying so is what
			 * stops the compiler warning about a truncation that
			 * cannot happen. */
			snprintf(out->entry_name, sizeof out->entry_name,
				 "%.31s", name);
			out->entry_off = value;
		}
next:
		/* Auxiliary records follow and are not symbols. */
		i += e[17];
	}
	free(b);
	return 1;
}

#ifdef _WIN32
/*
 * THE LINKED PE, asked the two questions the object cannot answer.
 *
 * Read with the engine's own PE collector rather than a second parser written
 * here, for the reason the ELF side reads its image with kof_elf_parse: a
 * disagreement between how the build reads a header and how the scanner reads
 * one is a disagreement nobody would find, and there is no reason to have two
 * of them.
 *
 * Symbols are NOT read here. lld strips the image's symbol table by default,
 * so which entry point a module exports and whether anything is undefined are
 * questions only the object can still answer - see coff_read.
 */
static int pe_image_read(const char *path, struct img_facts *out)
{
	struct kof_pe_info *info;
	struct kof_obj_ctx ctx;
	uint8_t *buf;
	size_t len;
	kof_buf b;
	uint32_t i;
	int ok = 0;

	memset(out, 0, sizeof *out);
	buf = (uint8_t *)slurp(path, &len);
	if (!buf)
		return 0;
	info = calloc(1, sizeof *info);
	if (!info) {
		free(buf);
		return 0;
	}
	b.p = buf;
	b.n = len;
	memset(&ctx, 0, sizeof ctx);
	if (!kof_pe_parse(b, info, &ctx))
		goto done;

	/*
	 * A base relocation directory with anything in it means the image
	 * expects to be fixed up at whatever address it lands at, and the
	 * loader fixes up nothing: it copies the bytes and enters them.
	 */
	if (info->dir[KOF_PE_DIR_BASERELOC].size)
		out->have_reloc = 1;

	for (i = 0; i < info->sec_count; i++) {
		const struct kof_pe_sec *s = &info->sec[i];

		/* Everything was merged into .text at link time; anything else
		 * carrying content means the merge and the compiler's flags
		 * have drifted apart. */
		if (strcmp(s->name, ".text") != 0) {
			if (!out->extra_sec[0])
				snprintf(out->extra_sec, sizeof out->extra_sec,
					 "%s", s->name);
			continue;
		}
		out->blob_off = s->file_off;
		out->blob_len = s->file_size;
	}
	ok = out->blob_len != 0;
done:
	free(info);
	free(buf);
	return ok;
}
#endif /* _WIN32 */

/*
 * Every fact this build needs about one ELF, in one pass.
 *
 * `want_blob` names the section whose bytes become the module - ".blob" for the
 * linked image. When it is NULL only the object-level facts are filled, which
 * is what the pre-link check needs.
 */
static int img_read(const char *path, const char *want_blob,
		    struct img_facts *out)
{
	static const char *const allowed[] = {
		".blob", ".symtab", ".strtab", ".shstrtab", NULL
	};
	struct kof_elf_info *info;
	/* Required, not optional: kof_elf_parse writes ctx->obj_size before it
	 * looks at anything, so a null one faults. Nothing here reads it back -
	 * this wants the sections, not an object identity. */
	struct kof_obj_ctx ctx;
	uint8_t *buf;
	size_t len;
	kof_buf b;
	uint32_t i;
	int is64, ok = 0;

	memset(out, 0, sizeof *out);
	buf = (uint8_t *)slurp(path, &len);
	if (!buf)
		return 0;
	info = calloc(1, sizeof *info);
	if (!info) {
		free(buf);
		return 0;
	}
	b.p = buf;
	b.n = len;
	memset(&ctx, 0, sizeof ctx);
	if (!kof_elf_parse(b, info, &ctx))
		goto done;
	is64 = info->elf_class == KOF_ELFCLASS_64;

	for (i = 0; i < info->sec_count; i++) {
		const struct kof_elf_sec *s = &info->sec[i];
		int j, known = 0;

		/* SHT_RELA is 4, SHT_REL is 9 - a relocation section at all
		 * means the loader would have work to do, and it has none. */
		if (s->type == 4u || s->type == 9u) {
			out->have_reloc = 1;
			if (!out->extra_sec[0])
				snprintf(out->extra_sec, sizeof out->extra_sec,
					 "%s", s->name);
		}
		for (j = 0; allowed[j]; j++)
			if (!strcmp(s->name, allowed[j]))
				known = 1;
		if (!known && s->name[0] && !out->extra_sec[0] &&
		    s->type != 4u && s->type != 9u &&
		    strcmp(s->name, ".rela.blob") != 0)
			snprintf(out->extra_sec, sizeof out->extra_sec, "%s",
				 s->name);
		/* SHF_WRITE is 1. .bss is SHT_NOBITS (8) and owns no file
		 * bytes, so its size is the only place its cost shows. */
		if ((s->flags & 1u) && s->type == 8u)
			out->bss_bytes += s->file_size;
		else if ((s->flags & 1u))
			out->data_bytes += s->file_size;
		if (want_blob && !strcmp(s->name, want_blob)) {
			out->blob_off = s->file_off;
			out->blob_len = s->file_size;
		}
	}

	/* The symbol table, walked directly: three names and whether anything
	 * is undefined is all this needs, and both are one field each. */
	for (i = 0; i < info->sec_count; i++) {
		const struct kof_elf_sec *st = &info->sec[i];
		const struct kof_elf_sec *str = NULL;
		uint64_t at, esz = is64 ? 24u : 16u;
		uint32_t k;

		if (st->type != 2u)          /* SHT_SYMTAB */
			continue;
		for (k = 0; k < info->sec_count; k++)
			if (info->sec[k].type == 3u &&
			    !strcmp(info->sec[k].name, ".strtab"))
				str = &info->sec[k];
		if (!str)
			continue;
		for (at = st->file_off; at + esz <= st->file_off + st->file_size;
		     at += esz) {
			const uint8_t *e = buf + at;
			uint32_t nameoff = (uint32_t)rd_le(e, 4);
			uint16_t shndx;
			uint64_t value;
			const char *nm;

			if (at + esz > len)
				break;
			if (is64) {
				shndx = (uint16_t)rd_le(e + 6, 2);
				value = rd_le(e + 8, 8);
			} else {
				value = rd_le(e + 4, 4);
				shndx = (uint16_t)rd_le(e + 14, 2);
			}
			if (str->file_off + nameoff >= len)
				continue;
			nm = (const char *)buf + str->file_off + nameoff;
			if (!nm[0])
				continue;
			if (!shndx) {        /* SHN_UNDEF */
				if (!out->undef[0])
					snprintf(out->undef, sizeof out->undef,
						 "%s", nm);
				continue;
			}
			if (!strcmp(nm, "kof_scan") || !strcmp(nm, "kof_unpack") ||
			    !strcmp(nm, "kof_heur")) {
				out->n_entry++;
				snprintf(out->entry_name, sizeof out->entry_name,
					 "%s", nm);
				out->entry_off = value;
			}
		}
	}
	ok = 1;
done:
	free(info);
	free(buf);
	return ok;
}

/* ---- the performance lint ------------------------------------------------- */

/*
 * WHAT THE BUILD CAN SEE, AND WHY IT SHOULD SAY SO.
 *
 * Every cost in this engine that a signature author can accidentally double is
 * visible in the source. The author cannot see it: the extents a range resolves
 * to, whether the presence set can rule a marker out, which memo cell a call
 * lands in - none of that is in front of them while they are writing a rule.
 * The build has all of it, so the build is where it gets said.
 *
 * These are WARNINGS. Every one of them describes a rule that works and costs
 * more than it needs to, and a build that refused them would be refusing correct
 * signatures over a judgement about speed.
 *
 * TWO OPTIMISATIONS ARE ALREADY DONE AND ARE NOT REPEATED HERE, because knowing
 * they exist is what stops a third being invented:
 *
 *   - Two ranges with the same MASK share one memo column, across the whole
 *     database, not just within a module (kofdb.c gives each distinct mask a
 *     uid). Declaring the same region twice costs a name and nothing else.
 *   - The same marker declared by two modules is one uid and one answer.
 *
 * So what is left for a lint is the thing neither can fix: a rule that asks for
 * the same bytes twice in two different shapes.
 */
static int warnings;

static void lwarn(int line, const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s:%d: warning: ", src_name, line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	warnings++;
}

/* Which ranges each declared marker is searched in, and where. */
struct use {
	/* Searched for without naming a region - kof_find_str_where and its
	 * kind. Not a range, and still a use. */
	int      used_unranged;
	uint32_t n_rng;
	int      rng[KOF_MAX_RANGE_PER_MODULE];
	int      line[KOF_MAX_RANGE_PER_MODULE];
};

static struct use uses[MAX_PATTERNS];
static int rng_used[MAX_PATTERNS];

static int ident_at(const char *p, char *out, size_t cap)
{
	size_t n = 0;

	while (*p == ' ' || *p == '\t' || *p == '\n')
		p++;
	while ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
	       (*p >= '0' && *p <= '9') || *p == '_') {
		if (n + 1 < cap)
			out[n++] = *p;
		p++;
	}
	out[n] = 0;
	return n != 0;
}

static int pat_index(const char *name)
{
	int i;

	for (i = 0; i < npats; i++)
		if (strcmp(pats[i].name, name) == 0)
			return i;
	return -1;
}

static int rng_index(const char *name)
{
	int i;

	for (i = 0; i < nrngs; i++)
		if (strcmp(rngs[i].name, name) == 0)
			return i;
	return -1;
}

static void use_add(int pi, int ri, int line)
{
	struct use *u = &uses[pi];
	uint32_t k;

	if (ri < 0)
		return;
	for (k = 0; k < u->n_rng; k++)
		if (u->rng[k] == ri)
			return;
	if (u->n_rng >= KOF_MAX_RANGE_PER_MODULE)
		return;
	u->line[u->n_rng] = line;
	u->rng[u->n_rng++] = ri;
}


/*
 * Walk the call sites.
 *
 * A text scan, deliberately: the declarations were parsed properly above because
 * they become data in a pack, and a call site becomes nothing - it is compiled
 * code. What is wanted here is which names appear together inside one
 * kof_find_str_*(...), and that survives a scan intact. Anything this misreads
 * produces a warning that is wrong, never a pack that is.
 */
static void lint_calls(const char *src, size_t len)
{
	size_t i;
	int line = 1;

	for (i = 0; i < len; i++) {
		const char *at = src + i;
		const char *open, *close, *p;
		char first[64];
		int ri = -1, ranged;

		if (src[i] == '\n') {
			line++;
			continue;
		}
		if (strncmp(at, "kof_find_str", 12) != 0)
			continue;
		open = strchr(at, '(');
		if (!open)
			continue;
		close = strchr(open, ')');
		if (!close)
			continue;
		/*
		 * The ranged forms take a range first; the offset forms take
		 * numbers. Both USE their markers - which is what "declared and
		 * never searched for" is about - and only the ranged ones say
		 * anything about regions. Treating _where as no use at all was
		 * this lint's own first false positive: it reported the UPX
		 * magic as dead in a module that searches for it on every
		 * object.
		 */
		ranged = !(strncmp(at, "kof_find_str_at", 15) == 0 ||
			   strncmp(at, "kof_find_str_in", 15) == 0 ||
			   strncmp(at, "kof_find_str_where", 18) == 0);
		if (ranged && ident_at(open + 1, first, sizeof first)) {
			ri = rng_index(first);
			if (ri >= 0)
				rng_used[ri] = 1;
		}
		/* Every identifier inside this call that names a declared
		 * marker, whichever position it is in. */
		for (p = open + 1; p < close; p++) {
			char sname[64];
			int pi;

			if (!((*p >= 'A' && *p <= 'Z') ||
			      (*p >= 'a' && *p <= 'z') || *p == '_'))
				continue;
			if (p > open + 1 &&
			    ((p[-1] >= 'A' && p[-1] <= 'Z') ||
			     (p[-1] >= 'a' && p[-1] <= 'z') ||
			     (p[-1] >= '0' && p[-1] <= '9') || p[-1] == '_'))
				continue;

/* mid identifier */
			if (!ident_at(p, sname, sizeof sname))
				continue;
			pi = pat_index(sname);
			if (pi >= 0) {
				if (ri >= 0)
					use_add(pi, ri, line);
				else
					uses[pi].used_unranged = 1;
			}
			p += strlen(sname) - 1u;
		}
	}
}

/* The header as the source names it: beside the source, not beside the cwd. */
static FILE *open_beside(const char *src, const char *rel)
{
	char full[1024];
	const char *slash = kof_path_sep_last(src);
	size_t n;

	if (!slash)
		return fopen(rel, "r");
	n = (size_t)(slash - src) + 1u;
	if (n + strlen(rel) + 1u > sizeof full)
		return NULL;
	memcpy(full, src, n);
	strcpy(full + n, rel);
	return fopen(full, "r");
}


/*
 * A kof_debug IN AN INCLUDED HEADER REPORTS A FACT NOBODY CAN NAME.
 *
 * The macro sends __LINE__ and nothing else, and the name for that line is
 * extracted from the source file named on the command line - this one. An
 * include is never opened, so a call inside one compiles, runs, calls the
 * host's debug hook, and arrives with an id the pack has no name for. The host
 * has nothing to print and prints nothing.
 *
 * That is the worst shape a defect can take: the call is there, the code runs,
 * and the only evidence is an absence. It cost three separate measurements in
 * one afternoon, each read as "this path never executes" when the truth was
 * "this path cannot say anything".
 *
 * NOT FIXED BY FOLLOWING THE INCLUDE, which is why this warns instead. Two
 * files both have a line 63; the id is the line and carries no file, so names
 * gathered from a header would collide with the source's own. Making it work
 * would mean changing what the macro sends, and that is the module ABI.
 *
 * Local includes only - <kofmod/...> is the SDK and has no rules in it.
 */
static void lint_debug_in_headers(const char *src, size_t n)
{
	size_t i = 0;
	int line = 1;

	for (i = 0; i < n; i++) {
		char path[512];
		size_t k = 0, j;
		FILE *f;
		char buf[4096];
		int hline = 1;

		if (src[i] == '\n') {
			line++;
			continue;
		}
		if (src[i] != '#' || (i && src[i - 1] != '\n'))
			continue;
		j = i + 1u;
		while (j < n && (src[j] == ' ' || src[j] == '\t'))
			j++;
		if (j + 8u >= n || memcmp(src + j, "include", 7) != 0)
			continue;
		j += 7u;
		while (j < n && (src[j] == ' ' || src[j] == '\t'))
			j++;
		if (j >= n || src[j] != '"')
			continue;                       /* <> is the SDK */
		j++;
		while (j < n && src[j] != '"' && k + 1u < sizeof path)
			path[k++] = src[j++];
		path[k] = 0;
		f = open_beside(src_name, path);
        	if (!f)
			continue;
		while (fgets(buf, (int)sizeof buf, f)) {
			if (strstr(buf, "kof_debug("))
				lwarn(line,
				      "%s:%d calls kof_debug from an included "
				      "header; the fact has no name and the "
				      "host will drop it in silence",
				      path, hline);
			hline++;
		}
		fclose(f);
	}
}

static void lint_report(void)
{
	int i;

	for (i = 0; i < npats; i++) {
		struct use *u = &uses[i];

		if (u->n_rng == 0 && !u->used_unranged) {
			lwarn(pats[i].line,
			      "'%s' is declared and never searched for; it costs "
			      "space in the pack and can never match",
			      pats[i].name);
			continue;
		}
		/*
		 * THERE WAS A WARNING HERE, AND WHAT REPLACED IT IS A
		 * MEASUREMENT.
		 *
		 * It said that a marker searched through two ranges costs a
		 * region scanned to exhaustion before the next is looked at,
		 * and it carried a number: 13426 objects, one marker in
		 * .rodata, 185 MB through one CODE|DATA range against 869 MB
		 * through two calls - 4.7x. It then told the author to merge
		 * the two ranges into one.
		 *
		 * Neither half of that survived the region sweep.
		 *
		 * THE COST. Re-measured over 4941 ELF objects, two ranges
		 * against one merged range:
		 *
		 *   sweep firing, marker absent    2037.08 MB both ways,
		 *                                  0 searches both ways
		 *   sweep declining, absent        2037.08 MB both ways
		 *   sweep declining, present       1933.42 against 1860.03 MB
		 *                                  - 3.9%, same 700 detections
		 *
		 * The reading moved. The scanner sweeps each REGION once for
		 * every marker any module declares on it, before a module runs,
		 * and a mask over several regions is answered by an OR over
		 * what that sweep already wrote - so how many ranges name a
		 * region decides how many memo lookups happen, not how many
		 * bytes are read. Where the sweep declines
		 * (KOF_MULTIMATCH_MIN_LIVE) both forms walk the extents in file
		 * order and stop at the first hit, which is why even there the
		 * difference is a few percent and not a factor.
		 *
		 * THE ADVICE, and this is the worse half: for a pair naming a
		 * symbol half it was BACKWARDS. Those bytes are not the
		 * object's. The symbol block is built for the object, searched
		 * through a matcher of its own, and its extents are chosen by
		 * an ATTRIBUTE - import against export binding - and walked
		 * last-record-first, because a rule scoped to a symbol is
		 * nearly always asking about one of the author's, and those sit
		 * at the end of the table. None of that is a file region and
		 * none of it is what the sweep does, so "one range, one pass"
		 * was never on offer.
		 *
		 * What merging actually buys is in c_find_str: a mask naming
		 * ONLY symbol halves is memoised, a mask naming only file
		 * regions is answered from the sweep, and a MIXED mask is
		 * memoised NOWHERE - one question over two buffers cannot stamp
		 * a cell after answering half of it. So the file half of a
		 * merged mask is searched with KOF_MEMO_NONE, from scratch,
		 * every call. Measured on the same 4941 objects with CODE and
		 * SYM_EXP:
		 *
		 *   two ranges     1563.83 MB swept, 0 searches
		 *   one merged     1563.83 MB swept, 5140 searches reading
		 *                  1563.83 MB - the whole of CODE, again
		 *
		 * Twice the bytes for taking the advice. Every instance of this
		 * warning in the tree was of that kind, and all of them were
		 * false.
		 *
		 * What is left is a question about MEANING and not about cost -
		 * two calls joined by "&&" ask whether one marker is in both
		 * regions, which is unusual enough to be worth a second look -
		 * and that is not what this said, so it is not kept here.
		 */
		/*
		 * Below the presence set's key width.
		 *
		 * gram_may_contain admits everything shorter than four bytes, so
		 * a marker this short can never be ruled out without reading the
		 * object - it is scanned for in every eligible file, forever.
		 */
		if (pats[i].kind == KOF_STR_LITERAL && pats[i].len < 4u)
			lwarn(pats[i].line,
			      "'%s' is %u bytes; under four the presence set "
			      "cannot rule it out, so every eligible object is "
			      "scanned for it", pats[i].name, pats[i].len);
	}
	for (i = 0; i < nrngs; i++)
		if (!rng_used[i])
			lwarn(rngs[i].line,
			      "range '%s' is declared and never used",
			      rngs[i].name);
}

/*
 * --arch-mask "KOF_ARCH_X86|KOF_ARCH_X86_64" -> the bit mask, on stdout.
 *
 * Here rather than in a shell wrapper because a shell cannot include
 * kofsig.h, and the copy it kept instead was wrong twice over: it matched
 * substrings, so KOF_ARCH_X86 - a prefix of KOF_ARCH_X86_64 - set both bits,
 * and it listed eight of the eleven architectures. A shell that asks this
 * program cannot fall behind the header this program compiles against.
 *
 * The mask has one bit per enum value, so KOF_ARCH_ANY is bit 0 and is a real
 * choice rather than the absence of one: a rule may target objects that have no
 * architecture.
 */
static int arch_mask_main(int argc, char **argv)
{
	uint32_t mask = 0;
	const char *p;
	char tok[64];

	if (argc != 3) {
		fprintf(stderr, "usage: %s --arch-mask "
				"\"KOF_ARCH_A|KOF_ARCH_B\"\n", argv[0]);
		return 2;
	}
	for (p = argv[2]; *p; ) {
		size_t n = 0;
		uint8_t val;

		while (*p == ' ' || *p == '\t' || *p == '|')
			p++;
		while (*p && *p != '|' && *p != ' ' && *p != '\t') {
			if (n + 1 < sizeof tok)
				tok[n++] = *p;
			p++;
		}
		tok[n] = 0;
		if (!n)
			continue;
		if (!kof_arch_from_name(tok, &val)) {
			fprintf(stderr, "ksigbuilder: \"%s\" is not a known "
					"architecture. Known:\n", tok);
#define X_SHOW(name, v, word) fprintf(stderr, "    %s\n", #name);
			KOF_ARCH_LIST(X_SHOW)
#undef X_SHOW
			return 1;
		}
		mask |= 1u << val;
	}
	if (!mask) {
		fprintf(stderr, "ksigbuilder: --arch-mask names no architecture\n");
		return 1;
	}
	printf("%lu\n", (unsigned long)mask);
	return 0;
}

/*
 * --subtype-mask "KOF_ELF_EXEC|KOF_ELF_DYN" -> "<mask> <ELF|PE>" on stdout.
 *
 * Two formats' subtypes share one number space on purpose - KOF_ELF_REL and
 * KOF_PE_DLL are both 1 - so which format was named is part of the answer, and
 * naming both at once is an error rather than a union. ksigbuilder --module takes
 * the format word back and checks it against what the source targets.
 *
 * Here for the same reason as --arch-mask: the shell kept its own copies of
 * both lists and matched them as substrings, which is a bug waiting for a
 * subtype whose name is a prefix of another.
 */
static int subtype_mask_main(int argc, char **argv)
{
	uint32_t mask = 0;
	int saw_elf = 0, saw_pe = 0;
	const char *p;
	char tok[64];

	if (argc != 3) {
		fprintf(stderr, "usage: %s --subtype-mask "
				"\"KOF_ELF_A|KOF_ELF_B\"\n", argv[0]);
		return 2;
	}
	for (p = argv[2]; *p; ) {
		size_t n = 0;
		int hit = 0;

		while (*p == ' ' || *p == '\t' || *p == '|')
			p++;
		while (*p && *p != '|' && *p != ' ' && *p != '\t') {
			if (n + 1 < sizeof tok)
				tok[n++] = *p;
			p++;
		}
		tok[n] = 0;
		if (!n)
			continue;
#define X_ELF(name, val)                                                     \
		if (!hit && strcmp(tok, #name) == 0)                         \
			{ mask |= 1u << (val); saw_elf = 1; hit = 1; }
		KOF_ELF_TYPE_LIST(X_ELF)
#undef X_ELF
#define X_PE(name, val)                                                      \
		if (!hit && strcmp(tok, #name) == 0)                         \
			{ mask |= 1u << (val); saw_pe = 1; hit = 1; }
		KOF_PE_IMAGE_LIST(X_PE)
#undef X_PE
		if (!hit) {
			fprintf(stderr, "ksigbuilder: \"%s\" is not a known "
					"subtype. Known:\n", tok);
#define X_SHOW(name, val) fprintf(stderr, "    %s\n", #name);
			KOF_ELF_TYPE_LIST(X_SHOW)
			KOF_PE_IMAGE_LIST(X_SHOW)
#undef X_SHOW
			return 1;
		}
	}
	if (!mask) {
		fprintf(stderr, "ksigbuilder: --subtype-mask names no subtype\n");
		return 1;
	}
	if (saw_elf && saw_pe) {
		fprintf(stderr, "ksigbuilder: --subtype-mask mixes ELF and PE "
				"subtypes; their values collide on purpose and "
				"mean different things\n");
		return 1;
	}
	printf("%lu %s\n", (unsigned long)mask, saw_elf ? "ELF" : "PE");
	return 0;
}

/*
 * ---------------------------------------------------------------------------
 * ONE MODULE, END TO END: the whole of what ksigbuilder --module did.
 *
 * The script is gone. What it was - argument handling, artefact naming, a set
 * of greps over the source, the compiler and linker invocations, the refusals,
 * and the .meta record - is here, in the language the rest of this toolchain is
 * already written in.
 *
 * The reason is not tidiness. A shell script needs a shell, and the platform
 * this engine now builds for does not have one: every recipe that ran grep, sed
 * and awk was a reason a Windows host had to install a POSIX toolchain before
 * it could build a single signature. The last two programs, the compiler and
 * the linker, cannot be removed and are not - they are spawned from here.
 *
 * The greps are the other half of the reason. Reading C source for declarations
 * with a regex cannot tell a declaration from the same words inside a comment,
 * and this file has had a comment stripper since long before it had this mode.
 * ---------------------------------------------------------------------------
 */

/* Whether the source, comments already blanked, contains `needle`. The buffer
 * is the one extract_main scanned, so a match here is code. */
static char  *g_src_text;
static size_t g_src_len;

static int src_has(const char *needle)
{
	return g_src_text && strstr(g_src_text, needle) != NULL;
}

/* `#include <kofmod/NAME.h>`, allowing the spaces the preprocessor allows. */
static int src_includes(const char *name)
{
	char pat[64];
	const char *p = g_src_text;

	if (!p)
		return 0;
	snprintf(pat, sizeof pat, "kofmod/%s.h>", name);
	while ((p = strstr(p, pat)) != NULL) {
		const char *q = p;

		/* Walk back over "<", spaces and "include" to a '#'. */
		while (q > g_src_text && q[-1] != '\n' && q[-1] != '#')
			q--;
		if (q > g_src_text && q[-1] == '#')
			return 1;
		p += strlen(pat);
	}
	return 0;
}

struct fmt_hdr { const char *hdr; uint8_t fmt; };

static const struct fmt_hdr fmt_headers[] = {
	{ "elf",      KOF_FMT_ELF    },
	{ "pe",       KOF_FMT_PE     },
	{ "macho",    KOF_FMT_MACHO  },
	{ "gzip",     KOF_FMT_GZIP   },
	{ "docole",   KOF_FMT_DOCOLE },
	{ "tar",      KOF_FMT_TAR    },
	{ "sevenzip", KOF_FMT_7Z     },
	/*
	 * zip.h is deliberately absent, and so are the headers of the other
	 * formats whose modules target exactly one anyway.
	 *
	 * zip.h is the one header two formats share, because a zip and a zip
	 * that is a document differ in what is INSIDE them and not in how they
	 * are read. The one-header-one-format rule below would refuse a module
	 * that targets both, which is the ordinary case for an archive module.
	 */
	{ NULL, 0 }
};
/*
 * A module may include exactly one format header, and only for a format it
 * targets.
 *
 * kof_elf() and its siblings cast ctx->file_header, and that cast is sound only
 * because the module cannot run against anything else. Two headers, or a header
 * for a format the module does not declare, and the cast is a promise nothing
 * keeps.
 */
static int check_format_headers(uint32_t target_mask, int n_targets)
{
	int i, n = 0;
	const char *seen = NULL;

	for (i = 0; fmt_headers[i].hdr; i++) {
		if (!src_includes(fmt_headers[i].hdr))
			continue;
		n++;
		seen = fmt_headers[i].hdr;
		if (!(target_mask & (1u << fmt_headers[i].fmt))) {
			fprintf(stderr, "FAIL: includes kofmod/%s.h but does "
					"not target that format\n",
				fmt_headers[i].hdr);
			return 0;
		}
	}
	if (n > 1) {
		fprintf(stderr, "FAIL: module includes %d format headers; "
				"exactly one is allowed\n"
				"      split it into one module per format\n", n);
		return 0;
	}
	if (n == 1 && n_targets > 1) {
		fprintf(stderr, "FAIL: kofmod/%s.h with %d targets is unsound\n"
				"      kof_<fmt>() casts ctx->file_header; with "
				"more than one target\n"
				"      there is no single view it can return\n",
			seen, n_targets);
		return 0;
	}
	return 1;
}

/*
 * WHAT EACH KIND MAY NOT BE, checked in the source rather than hoped for.
 *
 * heur.h includes kofsig.h, so a rule has the detector's macros in scope and
 * every one of these WOULD compile. They are refused because the difference
 * between a heuristic and a signature is not a matter of degree: a family name
 * is a claim about identity, and a rule that made one would be a signature
 * filed in the wrong place and reported in the wrong words.
 */
static int kind_checks(int kind)
{
	int n_phase = g_decl[SD_HEUR_PHASE].count;
	int n_kind = g_decl[SD_UNPACK_KIND].count;

	if (kind == 0) {                        /* detector */
		if (n_phase || g_heur_name[0] || g_heur_want) {
			fprintf(stderr, "FAIL: heuristic declarations on a "
					"detector; a rule exports kof_heur and "
					"includes kofmod/heur.h\n");
			return 0;
		}
		if (n_kind) {
			fprintf(stderr, "FAIL: KOF_UNPACK_KIND on a detector; "
					"it describes an unpacker, and a "
					"detector declaring one has "
					"misunderstood what it is writing\n");
			return 0;
		}
		return 1;
	}
	if (kind == 1) {                        /* unpacker */
		if (!n_kind) {
			fprintf(stderr, "FAIL: an unpack module must declare "
				"KOF_UNPACK_KIND\n"
				"      KOF_UNPACK_KIND(KOF_UNP_PACKER)    - it "
				"hid a program\n"
				"      KOF_UNPACK_KIND(KOF_UNP_CONTAINER) - it "
				"carried files\n");
			return 0;
		}
		return 1;
	}
	/* heuristic */
	if (!n_phase) {
		fprintf(stderr, "FAIL: a heuristic rule must declare "
			"KOF_HEUR_PHASE\n"
			"      KOF_HEUR_PHASE(KOF_HEUR_EXAMINE) - what it IS\n"
			"      KOF_HEUR_PHASE(KOF_HEUR_VERDICT) - how it was "
			"reached\n");
		return 0;
	}
	if (!g_heur_name[0]) {
		fprintf(stderr, "FAIL: a heuristic rule must declare "
				"KOF_HEUR_NAME(\"word\")\n");
		return 0;
	}
	if (g_heur_want && g_heur_phase != 0) {
		fprintf(stderr, "FAIL: KOF_HEUR_WANT at KOF_HEUR_VERDICT; the "
				"object has already been opened by then, so "
				"there is nothing left to ask for\n");
		return 0;
	}
	if (src_has("KOF_SCAN_INFECT(") || src_has("KOF_SCAN_SUSPECT(") ||
	    src_has("KOF_SCAN_MATCH(")) {
		fprintf(stderr, "FAIL: a heuristic rule reports KOF_HEUR_HIT "
				"and nothing above it; naming a family is what "
				"a signature does\n");
		return 0;
	}
	if (src_has("KOF_TARGET_NAME(")) {
		fprintf(stderr, "FAIL: KOF_TARGET_NAME on a heuristic rule; a "
				"rule names a shape, not a family\n");
		return 0;
	}
	if (src_has("kof_emit(") || src_has("kof_child(") ||
	    src_has("kof_child_window(") || src_has("kof_gather(")) {
		fprintf(stderr, "FAIL: a heuristic rule produces no child "
				"objects; that is what an unpacker is for\n");
		return 0;
	}
	if (n_kind) {
		fprintf(stderr, "FAIL: KOF_UNPACK_KIND on a heuristic rule\n");
		return 0;
	}
	return 1;
}

/*
 * The lower-bound test must not be written twice.
 *
 * The declaration is what the host trusts and filters on; a copy in the body is
 * a second statement of the same rule, and the one the host cannot see is the
 * one that wins silently.
 */
static int check_size_body(void)
{
	if (g_size_min && strstr(g_src_text, "ctx->obj_size <")) {
		fprintf(stderr, "FAIL: obj_size has a lower-bound test in the "
				"body and also a KOF_TARGET_SIZE_MIN "
				"declaration;\n      the declaration is "
				"authoritative, so remove the check from "
				"kof_scan\n");
		return 0;
	}
	return 1;
}

static char g_entry_kept[32];

/*
 * THE RAW BLOB - the bytes the database stores and the loader jumps into.
 *
 * Two routes here, and they arrive at the same bytes rather than at two
 * answers: module.ld places everything in .blob at address zero and discards
 * the rest, and the image has just been checked to carry no other section. So
 * "the allocatable sections laid out by address", which is what --oformat
 * binary writes, is the contents of .blob and nothing besides it.
 *
 * The linker is asked wherever the linker can answer, so on every host that
 * has built a database so far the bytes still come from where they always
 * came from. Two hosts cannot answer. GNU ld's AArch64 backend refuses the
 * request outright - "cannot change output format whilst linking AArch64
 * binaries". lld in its link flavour has no --oformat at all, which is why
 * the Windows build used to reach for llvm-objcopy --dump-section instead.
 * Both take the bytes out of the image this build has already linked, parsed
 * and validated - which is also what removes objcopy from what a Windows
 * build has to have installed.
 *
 * Chosen by which host this is, not by running the link and reading its exit
 * code: a refusal to change output format and a link that genuinely went
 * wrong both come back as failure, and a fallback that cannot tell them apart
 * would turn a real error into a silently different blob.
 */
static int emit_raw(const char *ld, const char *lds, const char *obj,
		    const char *img, const char *raw,
		    const struct img_facts *f)
{
#if defined(_WIN32) || defined(__aarch64__) || defined(_M_ARM64)
	uint8_t *buf;
	size_t len;
	FILE *out;
	int ok;

	(void)ld;
	(void)lds;
	(void)obj;

	buf = (uint8_t *)slurp(img, &len);
	if (!buf) {
		fprintf(stderr, "FAIL: cannot re-read the linked image\n");
		return 0;
	}
	/* The offsets come from this same file, but they are still checked
	 * against its real length before either is believed. */
	if (f->blob_off > (uint64_t)len ||
	    f->blob_len > (uint64_t)len - f->blob_off) {
		fprintf(stderr, "FAIL: .blob lies outside the image\n");
		free(buf);
		return 0;
	}
	out = fopen(raw, "wb");
	if (!out) {
		fprintf(stderr, "FAIL: cannot write %s\n", raw);
		free(buf);
		return 0;
	}
	ok = fwrite(buf + f->blob_off, 1, (size_t)f->blob_len, out) ==
	     (size_t)f->blob_len;
	if (fclose(out) != 0)
		ok = 0;
	free(buf);
	if (!ok) {
		fprintf(stderr, "FAIL: writing %s\n", raw);
		return 0;
	}
	return 1;
#else
	const char *cmd[] = { ld, "-T", lds, "--gc-sections",
			      "--oformat", "binary",
			      obj, "-o", raw, NULL };
	int rc;

	(void)img;
	(void)f;

	rc = run_tool(cmd);
	if (rc != 0) {
		fprintf(stderr, "FAIL: raw link returned %d\n", rc);
		return 0;
	}
	return 1;
#endif
}

/*
 * Compile, link, validate and emit one module. Non-zero on success, with
 * *entry_out naming the entry point the image exports.
 *
 * The compiler and the linker are the only programs a build still runs, and
 * they are run from here rather than from a shell - which is what lets this
 * work on a host that has neither bash nor the GNU binutils.
 */
static int do_build(const char *src, const char *pat, const char *obj,
		    const char *img, const char *raw, const char *lds,
		    const char **entry_out)
{
	const char *cc = getenv("CC");
	const char *ld = getenv("LD");
	const char *incdir = getenv("KOF_INCLUDE");
	struct img_facts f;
	char inc[1024];
	int rc;

	if (!cc || !cc[0])
		cc = "cc";
	if (!ld || !ld[0])
		ld = "ld";
	snprintf(inc, sizeof inc, "-I%s",
		 incdir && incdir[0] ? incdir : ".");

	/*
	 * WHICH MACHINE THE BLOB IS FOR, said out loud rather than inherited.
	 *
	 * Without this the module compile is whatever `cc` defaults to, which
	 * is the machine the compiler was built for and not necessarily the
	 * one this database is being built for. The pack's own machine field
	 * comes from KOF_PACK_MACH_HOST - a property of the build that made
	 * ksigbuilder - so the two are set by different things and can
	 * disagree.
	 *
	 * They did. On an ARM64 Windows host building the x86_64 default, the
	 * tools were cross-compiled to x86_64 and stamped the pack x86_64,
	 * while every blob came out AArch64 because `cc` here is native. That
	 * database loads without a complaint - the machine field says exactly
	 * what the engine is - and then the scanner enters the first module
	 * and dies on STATUS_ILLEGAL_INSTRUCTION.
	 *
	 * Empty means "whatever cc targets", which is right for a native
	 * build and is what the Linux side uses.
	 */
	{
		const char *triple = getenv("KOF_TARGET_TRIPLE");
		char targ[256];
		const char *flags[] = {
			"-std=c11", "-Os",
			"-ffreestanding", "-fno-builtin", "-nostdlib",
			"-fno-asynchronous-unwind-tables",
			"-fno-unwind-tables",
			"-fno-ident", "-g0",
			"-fno-stack-protector", "-fno-jump-tables",
			"-ffunction-sections", "-fdata-sections",
#if (defined(__aarch64__) || defined(_M_ARM64)) && !defined(_WIN32)
			/*
			 * REACHING THE BLOB'S OWN RODATA, ON A HOST WHERE
			 * PC-RELATIVE MEANS PAGE-RELATIVE.
			 *
			 * A blob is linked at address zero and then copied to
			 * wherever the arena has room, and nothing relocates
			 * it - which works because every reference inside it
			 * is PC-relative. On x86-64 that is RIP-relative and
			 * counts in BYTES, so any load address will do.
			 *
			 * AArch64's default is adrp+add, and adrp counts in
			 * 4KB PAGES: it yields the page the instruction is
			 * in, and the add carries the link-time offset within
			 * that page. The two agree only when the blob is
			 * loaded at the same page offset it was linked at,
			 * and the loader aligns a blob to KOF_PACK_BLOB_ALIGN
			 * - sixteen bytes. So a module reading a const table
			 * of its own read whatever happened to sit at that
			 * offset from a page boundary instead.
			 *
			 * Measured before this flag: ten of the sixty-two
			 * modules in bases/ emitted adrp, and every one of
			 * them was silently reading the wrong bytes - no
			 * fault, no refusal, just a module that never
			 * matched. tests/unit/msf_xor.c is the one that
			 * noticed.
			 *
			 * -mcmodel=tiny emits adr instead, which is
			 * PC-relative in bytes and therefore correct at any
			 * load address. Its cost is a 1MB reach from the
			 * instruction to what it names; a signature module is
			 * a few kilobytes, and a blob that ever outgrew that
			 * fails at link time with a relocation overflow
			 * rather than by reading the wrong address.
			 *
			 * ELF only, and not by choice: clang refuses the tiny
			 * model for a COFF target outright - "tiny code model
			 * is only supported on ELF". AArch64 Windows has the
			 * same adrp and therefore the same bug waiting, and
			 * it needs a different remedy - most likely giving a
			 * blob a page-aligned home in the arena rather than
			 * the sixteen bytes KOF_PACK_BLOB_ALIGN promises.
			 * Nothing here is affected by that yet, because the
			 * COFF half of this function is not written.
			 */
			"-mcmodel=tiny",
#endif
#ifdef _WIN32
			/*
			 * Windows grows a stack a page at a time and has the
			 * function ask for it, by calling __chkstk once its
			 * frame passes a threshold. That is a CRT symbol, and
			 * a module links against no CRT - so a signature with
			 * a large enough local buffer fails to link, naming a
			 * function nobody wrote a call to.
			 *
			 * Raised past anything a module's own locals can
			 * plausibly need. It is not a licence to use a
			 * megabyte of stack: a module runs on whatever stack
			 * the host was already on, and the modules here budget
			 * in kilobytes. It only stops the compiler from
			 * reaching for a runtime that is not there.
			 */
			"-mstack-probe-size=1000000",
#endif
			"-Wall", "-Wextra", "-Werror",
			inc, "-include", pat, "-c", src, "-o", obj,
			NULL
		};
		const char *cmd[8 + sizeof flags / sizeof flags[0]];
		unsigned n = 0, k;

		cmd[n++] = cc;
		if (triple && triple[0]) {
			snprintf(targ, sizeof targ, "--target=%s", triple);
			cmd[n++] = targ;
		}
		for (k = 0; flags[k]; k++)
			cmd[n++] = flags[k];
		cmd[n] = NULL;

		rc = run_tool(cmd);
		if (rc != 0) {
			fprintf(stderr, "FAIL: compile returned %d\n",
				rc);
			return 0;
		}
	}

	/* No writable state, checked on the OBJECT where the sections
	 * are still separate and attributable. */
#ifdef _WIN32
	if (!coff_read(obj, &f)) {
#else
	if (!img_read(obj, NULL, &f)) {
#endif
		fprintf(stderr, "FAIL: cannot read the compiled "
				"object\n");
		return 0;
	}
	if (f.data_bytes || f.bss_bytes) {
		fprintf(stderr, "FAIL: module has writable data "
				"(.data=%llu .bss=%llu)\n"
				"      modules must hold no state; use "
				"locals or ask the host\n",
			(unsigned long long)f.data_bytes,
			(unsigned long long)f.bss_bytes);
		return 0;
	}

	{
#ifdef _WIN32
		/*
		 * COFF has no linker script, so what module.ld does for the
		 * ELF side is done with flags here.
		 *
		 * -dll -noentry: nothing is ever loaded as a PE image, so the
		 * header's own entry field is read by nobody - the host copies
		 * raw bytes into its arena and enters them by offset. -dll is
		 * only what -noentry has to be paired with; it sets a header
		 * bit nothing reads.
		 *
		 * The three -merge flags are the part that matters. Without
		 * them .rdata lands in its own separately page-aligned
		 * section, and the PC-relative loads reaching it are correct
		 * only at that gap - so dumping .text alone would carry code
		 * whose data references point past the end of what was
		 * copied. Merging first makes the linker resolve every
		 * reference assuming byte-for-byte adjacency, which is what
		 * leaves one section that is self-contained at any address.
		 */
		char outarg[1024];
		const char *cmd[] = { ld, "-flavor", "link",
				      "-dll", "-noentry",
				      "-subsystem:native", "-nodefaultlib",
				      "-merge:.rdata=.text",
				      "-merge:.data=.text",
				      "-merge:.bss=.text",
				      obj, outarg, NULL };

		(void)lds;
		snprintf(outarg, sizeof outarg, "-out:%s", img);
#else
		const char *cmd[] = { ld, "-T", lds, "--gc-sections",
				      obj, "-o", img, NULL };
#endif

		rc = run_tool(cmd);
		if (rc != 0) {
			fprintf(stderr, "FAIL: link returned %d\n", rc);
			return 0;
		}
	}
#ifdef _WIN32
	{
		/*
		 * Two files, two questions - see coff_read. The object has
		 * already answered which entry point this module exports and
		 * whether it reaches outside itself; the image answers what it
		 * alone can, and those answers are laid over the object's
		 * rather than replacing them.
		 */
		struct img_facts im;

		if (!pe_image_read(img, &im)) {
			fprintf(stderr, "FAIL: cannot read the linked "
					"image\n");
			return 0;
		}
		f.have_reloc = im.have_reloc;
		snprintf(f.extra_sec, sizeof f.extra_sec, "%s", im.extra_sec);
		f.blob_off = im.blob_off;
		f.blob_len = im.blob_len;
	}
#else
	if (!img_read(img, ".blob", &f)) {
		fprintf(stderr, "FAIL: cannot read the linked image\n");
		return 0;
	}
#endif
	if (f.have_reloc) {
		fprintf(stderr, "FAIL: relocations remain (%s)\n",
			f.extra_sec);
		return 0;
	}
	if (f.undef[0]) {
		fprintf(stderr, "FAIL: undefined symbol (module "
				"reached outside its blob): %s\n",
			f.undef);
		return 0;
	}
	if (f.extra_sec[0]) {
		fprintf(stderr, "FAIL: unexpected section in image: "
				"%s\n", f.extra_sec);
		return 0;
	}
	if (f.n_entry != 1) {
		fprintf(stderr, "FAIL: image exports %d of kof_scan, "
				"kof_unpack, kof_heur; a module is one "
				"kind\n", f.n_entry);
		return 0;
	}
	if (f.entry_off != 0) {
		fprintf(stderr, "FAIL: entry point is at 0x%llx, expected 0; "
				"check module.ld (ELF) or the .text$0 "
				"forcing (COFF)\n",
			(unsigned long long)f.entry_off);
		return 0;
	}

	/* Last, and only once the image above has been read and accepted -
	 * one of the two routes in emit_raw takes its bytes out of exactly
	 * that image, so nothing is written before there is something worth
	 * writing. */
	if (!emit_raw(ld, lds, obj, img, raw, &f))
		return 0;

	snprintf(g_entry_kept, sizeof g_entry_kept, "%.31s", f.entry_name);
	*entry_out = g_entry_kept;
	return 1;
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
		{
			char save = src[e];

			src[e] = 0;
			decl_collect(src + pos, lineno);
			src[e] = save;
		}
		scan_line(src + pos, e - pos, lineno);
		pos = (e < src_len) ? e + 1 : e;
	}

	resolve_decls();

	if (errors) {
		free(src);
		return 1;
	}

	/* Diagnosis, after the declarations are known and before anything is
	 * written: a warning about a pack that was never produced is noise. */
	lint_calls(src, src_len);
	lint_debug_in_headers(src, src_len);
	lint_report();

	/* Kept for the module mode's own checks: it asks the same buffer the
	 * declarations were read from, so a name inside a comment is invisible
	 * to it too. Freed with the process. */
	g_src_text = src;
	g_src_len = src_len;

	out = fopen(argv[3], "w");
	if (!out) {
		fprintf(stderr, "ksigbuilder: cannot write %s\n", argv[3]);
		free(src);
		return 2;
	}
	fprintf(out, "/* generated by ksigbuilder --extract from %s - do not edit */\n",
		argv[2]);
#ifdef _WIN32
	/*
	 * THE ENTRY POINT AT OFFSET ZERO, WITHOUT A LINKER SCRIPT.
	 *
	 * module.ld gives the ELF build this for free by naming
	 * .text.kof_scan/.text.kof_unpack/.text.kof_heur first, so whichever
	 * one the source defines lands at zero. COFF has no such script; what
	 * it has instead is section grouping by name - sections called
	 * "name$suffix" are concatenated into "name" in ascending suffix
	 * order. A digit sorts before every letter a C identifier can start
	 * with, so declaring the three entry points into ".text$0" here forces
	 * whichever one the source goes on to define into the leading slot,
	 * without the source ever seeing this.
	 *
	 * Declared, not defined: the source still provides the only body. An
	 * attribute on an earlier declaration of the same symbol still
	 * applies, and kofsig.h's own prototype comes later in translation
	 * unit order carrying no section of its own. The struct stays
	 * incomplete because nothing here names a field of it.
	 */
	fprintf(out, "struct kof_obj_ctx;\n");
	fprintf(out, "__attribute__((section(\".text$0\"))) "
		     "void kof_scan(const struct kof_obj_ctx *);\n");
	fprintf(out, "__attribute__((section(\".text$0\"))) "
		     "void kof_unpack(const struct kof_obj_ctx *);\n");
	fprintf(out, "__attribute__((section(\".text$0\"))) "
		     "void kof_heur(const struct kof_obj_ctx *);\n");
#endif
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
	 * loading or running the module. ksigbuilder --module merges this with what it
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
	g_scan_mask_out = scan_mask;
	g_nstr_out = npats;
	/* Empty when the source never declared one - an unpack-kind module,
	 * where KOF_TARGET_NAME is not required. ksigbuilder --module copies these
	 * into .meta unchanged; see struct kof_pack_mod for where they end up. */
	/* The declarations this tool now reads itself, for the caller that used
	 * to grep them out of the source. One parser, with comments stripped. */
	fprintf(out, "target=%u\n", g_target_mask);
	fprintf(out, "ntargets=%d\n", g_n_targets);
	fprintf(out, "arch_mask=%u\n", g_arch_mask);
	fprintf(out, "subtype_mask=%u\n", g_subtype_mask);
	fprintf(out, "size_min=%llu\n", (unsigned long long)g_size_min);
	fprintf(out, "unp_kind=%d\n", g_unp_kind);
	fprintf(out, "heur_phase=%d\n", g_heur_phase);
	fprintf(out, "heur_level=%d\n", g_heur_level);
	fprintf(out, "heur_want=%d\n", g_heur_want);
	fprintf(out, "heur_name=%s\n", g_heur_name);
	fprintf(out, "heur_predict=%s\n", g_heur_predict);
	/* The COUNTS as well as the values, because whether a declaration is
	 * present is a different question from what it says - and the checks
	 * that ask it run after the entry point is known, which is later than
	 * this. A heuristic with no KOF_HEUR_PHASE and one that declares
	 * EXAMINE both resolve to 0. */
	fprintf(out, "n_phase=%d\n", g_decl[SD_HEUR_PHASE].count);
	fprintf(out, "n_kind=%d\n", g_decl[SD_UNPACK_KIND].count);
	fprintf(out, "n_level=%d\n", g_decl[SD_HEUR_LEVEL].count);
	fprintf(out, "family=%s\n", g_have_name ? g_family : "");
	fprintf(out, "maltype=%d\n", g_have_name ? g_maltype : 0);
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
	/* src is g_src_text now - the module mode reads it after this returns,
	 * and the process is short enough that its lifetime is the program's. */
	return 0;
}

/* ============================================================================
 * PACK - gather compiled artefacts into .ksig
 * ============================================================================ */

/* Everything read out of one artefact set, owned until its pack is written. */
struct artefact {
	char    *stem;                   /* the path without the .blob */
	char    *label;                  /* what the module is called; see below */
	char    *srcpath;                /* where it lives in the bases tree */
	uint8_t *code;
	uint32_t code_len;

	uint32_t kind;
	uint32_t target_mask, scan_mask, arch_mask, subtype_mask, unp_kind;
	uint32_t heur_phase, heur_want, heur_level;
	uint64_t size_min;

	/* What KOF_TARGET_NAME declared - empty family / maltype 0 for an
	 * unpack-kind module, where it is not required. */
	char    *family;
	uint32_t maltype;

	/* What KOF_HEUR_PREDICT declared, or NULL. Only a rule has one. */
	char    *heur_predict;

	/* What this module fires on: preconditions plus the exact pattern/region
	 * set, order independent. See artefact_fingerprint. Not a security hash and
	 * not stored anywhere beyond this run - it exists only to warn when two
	 * artefacts have it in common. */
	uint32_t fp;

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
	free(a->label);
	free(a->srcpath);
	free(a->family);
	free(a->heur_predict);
	free(a->code);
	free(a->str);
	free(a->rng);
	free(a->name);
	free(a->str_bytes);
	free(a->name_text);
	/*
	 * Cleared, so freeing twice is harmless rather than merely unreached.
	 *
	 * Today it is unreached: the one caller that frees a half loaded artefact
	 * has not incremented the count yet, so the sweep at the end skips the slot
	 * it freed. That is a fact about an index, not about this function, and the
	 * next person to move an increment does not know it. Eight stores make the
	 * question stop existing.
	 */
	memset(a, 0, sizeof *a);
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
	/* Sized for the longest VALUE, not just the numeric fields: srcpath= can
	 * be a deep bases-tree path, and at line[128] fgets split it, the tail
	 * matched no key and was dropped, and the recorded source was truncated.
	 * names_load sizes its buffer the same way and for the same reason. */
	char *path = sibling(a->stem, ".meta"), line[KOF_NAME_MAX_LEN + 64];
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
		} else if (strncmp(line, "unp_kind=", 9) == 0) {
			a->unp_kind = (uint32_t)strtoul(line + 9, 0, 10);
		} else if (strncmp(line, "heur_phase=", 11) == 0) {
			a->heur_phase = (uint32_t)strtoul(line + 11, 0, 10);
		} else if (strncmp(line, "heur_want=", 10) == 0) {
			a->heur_want = (uint32_t)strtoul(line + 10, 0, 10);
		} else if (strncmp(line, "heur_level=", 11) == 0) {
			a->heur_level = (uint32_t)strtoul(line + 11, 0, 10);
		} else if (strncmp(line, "blob_len=", 9) == 0) {
			blob_len = strtoull(line + 9, 0, 10);
		} else if (strncmp(line, "kind=", 5) == 0) {
			a->kind = (uint32_t)strtoul(line + 5, 0, 10);
			have_kind = 1;
		} else if (strncmp(line, "srcpath=", 8) == 0) {
			/* The newline, like every other text field here. Left
			 * on, it goes into the name pool with the string and
			 * the entry runs into the one after it: the path came
			 * back as "signatures/x.c\np1tox" and opened nothing. */
			char *nl = strchr(line + 8, '\n');

			if (nl)
				*nl = 0;
			free(a->srcpath);
			a->srcpath = strdup(line + 8);
			if (!a->srcpath) {
				fclose(f);
				goto out;
			}
		} else if (strncmp(line, "label=", 6) == 0) {
			char *nl = strchr(line + 6, '\n');

			if (nl)
				*nl = 0;
			free(a->label);
			a->label = strdup(line + 6);
			if (!a->label) {
				fclose(f);
				goto out;
			}
		} else if (strncmp(line, "family=", 7) == 0) {
			char *nl = strchr(line + 7, '\n');

			if (nl)
				*nl = 0;
			free(a->family);
			a->family = strdup(line + 7);
			if (!a->family) {
				fclose(f);
				goto out;
			}
		} else if (strncmp(line, "maltype=", 8) == 0) {
			a->maltype = (uint32_t)strtoul(line + 8, 0, 10);
		} else if (strncmp(line, "heur_predict=", 13) == 0) {
			char *nl = strchr(line + 13, '\n');

			if (nl)
				*nl = 0;
			free(a->heur_predict);
			/* Empty stays NULL: a rule that predicts nothing must
			 * not intern a zero-length name and carry an offset
			 * that reads as a prediction of "". */
			a->heur_predict = line[13] ? strdup(line + 13) : NULL;
			if (line[13] && !a->heur_predict) {
				fclose(f);
				goto out;
			}
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
	/* Required rather than defaulted. A missing label means the artefact was
	 * written by an older compiler, and guessing one from the path would name a
	 * pack after a guess - which is the one thing a name in a directory listing
	 * must never be. Rebuilding the artefacts fixes it. */
	if (!a->label || !a->label[0]) {
		fprintf(stderr, "ksigbuilder: %s: record declares no label; "
				"rebuild the artefacts\n", a->stem);
		goto out;
	}
	/* Same reasoning as label just above: a detect-kind module always has a
	 * KOF_TARGET_NAME (the build's --extract refuses the source
	 * otherwise), so an empty family here means an artefact from before
	 * this field existed, not a module that legitimately has none. */
	if (a->kind == KOF_PACK_DETECT && (!a->family || !a->family[0])) {
		fprintf(stderr, "ksigbuilder: %s: record declares no family; "
				"rebuild the artefacts\n", a->stem);
		goto out;
	}
	/* A rule carries its word in the family slot - see ksigbuilder - and
	 * a rule with none would report a finding with nothing in the middle. */
	if (a->kind == KOF_PACK_HEUR && (!a->family || !a->family[0])) {
		fprintf(stderr, "ksigbuilder: %s: heuristic rule declares no "
				"name\n", a->stem);
		goto out;
	}
	if (a->kind != KOF_PACK_DETECT && a->kind != KOF_PACK_UNPACK &&
	    a->kind != KOF_PACK_HEUR) {
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
		/* w <id> <icase> <fullword> <len> <literal as hex digits> - a
		 * literal whose bytes cannot go in a text column. Same meaning
		 * as an 's' row in every other respect. */
		} else if (p[0] == 'w' && p[1] == '\t') {
			unsigned long v[5], icase, fullw, wide, len;
			char *end;
			uint32_t k2;
			int k;

			p += 2;
			for (k = 0; k < 5; k++) {
				tab = strchr(p, '\t');
				if (!tab)
					break;
				*tab = 0;
				v[k] = strtoul(p, 0, 10);
				p = tab + 1;
			}
			if (k != 5) {
				fprintf(stderr, "ksigbuilder: %s: malformed wide "
						"string row\n", a->stem);
				goto out;
			}
			icase = v[1];
			fullw = v[2];
			wide  = v[3];
			len   = v[4];
			if (len == 0 || len > KOF_STR_MAX_LEN) {
				fprintf(stderr, "ksigbuilder: %s: literal of "
						"length %lu\n", a->stem, len);
				goto out;
			}
			for (end = p; *end && *end != '\n' && *end != '\r'; end++)
				;
			if ((size_t)(end - p) != len * 2) {
				fprintf(stderr, "ksigbuilder: %s: literal says "
						"%lu bytes and carries %u\n",
					a->stem, len,
					(unsigned)((end - p) / 2));
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
			for (k2 = 0; k2 < len; k2++) {
				char h[3];

				h[0] = p[k2 * 2u];
				h[1] = p[k2 * 2u + 1u];
				h[2] = 0;
				a->str_bytes[bytes_len + k2] =
					(uint8_t)strtoul(h, 0, 16);
			}
			a->str[a->n_str].bytes =
				(const uint8_t *)(uintptr_t)bytes_len;
			a->str[a->n_str].len   = (uint16_t)len;
			a->str[a->n_str].kind  = KOF_STR_LITERAL;
			a->str[a->n_str].flags = (uint8_t)
				((icase ? KOF_STR_ICASE : 0u) |
				 (fullw ? KOF_STR_FULLWORD : 0u) |
				 (wide  ? KOF_STR_WIDE     : 0u));
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

/* By artefact name - the flattened path below the content tree, which is unique
 * by construction and stable across machines. */
static int artefact_cmp(const void *a, const void *b)
{
	const struct artefact *x = (const struct artefact *)a;
	const struct artefact *y = (const struct artefact *)b;

	return strcmp(x->stem ? x->stem : "", y->stem ? y->stem : "");
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

/*
 * WHICH PACK A FORMAT BELONGS IN.
 *
 * Derived from enum kof_format by a switch with no default, so a format added
 * to the engine and not assigned here fails to compile rather than silently
 * landing in a pack somebody has to notice is wrong.
 *
 * Executables stay apart by format - an ELF pack and a PE pack - because that
 * is the split a person reading a database directory expects and because they
 * are the two that will grow. Archives and documents are gathered, because
 * "which container was it" is a question the per-module column answers and not
 * one worth a file each.
 */
enum pack_bucket {
	BUCKET_NONE = -1,
	BUCKET_ELF = 0, BUCKET_PE, BUCKET_MACHO,
	BUCKET_ARCHIVE, BUCKET_DOC, BUCKET_TEXT, BUCKET_RAW
};

static int bucket_of_format(uint32_t fmt)
{
	switch (fmt) {
	case KOF_FMT_ELF:     return BUCKET_ELF;
	case KOF_FMT_PE:      return BUCKET_PE;
	case KOF_FMT_MACHO:   return BUCKET_MACHO;
	case KOF_FMT_GZIP:
	case KOF_FMT_ZIP:
	case KOF_FMT_TAR:
	case KOF_FMT_7Z:
	case KOF_FMT_RAR:
	case KOF_FMT_XZ:
	/*
	 * DOCZIP IS AN ARCHIVE HERE, not a document, and the distinction is
	 * about what an unpacker targets rather than what a user opens.
	 *
	 * A .docx IS a zip file; the unpacker that opens one is the zip
	 * unpacker, and it declares ZIP|DOCZIP. Filing DOCZIP under documents
	 * split that mask across two buckets, which made it bucketless and gave
	 * it a pack of its own sitting next to unpack-archive - the exact
	 * untidiness this grouping exists to remove. The doc bucket is for
	 * containers that are documents in their own right: OLE, RTF, PDF.
	 */
	case KOF_FMT_DOCZIP:  return BUCKET_ARCHIVE;
	case KOF_FMT_DOCOLE:
	case KOF_FMT_RTF:
	case KOF_FMT_PDF:     return BUCKET_DOC;
	case KOF_FMT_SCRIPT:
	case KOF_FMT_TEXT:    return BUCKET_TEXT;
	case KOF_FMT_UNKNOWN: return BUCKET_RAW;
	default:              return BUCKET_NONE;
	}
}

static const char *bucket_name(int b)
{
	switch (b) {
	case BUCKET_ELF:     return "elf";
	case BUCKET_PE:      return "pe";
	case BUCKET_MACHO:   return "macho";
	case BUCKET_ARCHIVE: return "archive";
	case BUCKET_DOC:     return "doc";
	case BUCKET_TEXT:    return "text";
	case BUCKET_RAW:     return "raw";
	default:             return "";
	}
}

/*
 * The bucket a whole target mask belongs to, or BUCKET_NONE when its bits do
 * not agree.
 *
 * A module targeting ELF and PE together is not an executable-bucket module,
 * it is its own thing - and it keeps its own pack rather than being filed under
 * whichever half was tested first.
 */
static int bucket_of_mask(uint32_t mask)
{
	int b = BUCKET_NONE;
	uint32_t f;

	for (f = 0; f < 32u; f++) {
		int this_b;

		if (!(mask & (1u << f)))
			continue;
		this_b = bucket_of_format(f);
		if (this_b == BUCKET_NONE)
			return BUCKET_NONE;
		if (b == BUCKET_NONE)
			b = this_b;
		else if (b != this_b)
			return BUCKET_NONE;
	}
	return b;
}

/* A set of artefacts sharing one grouping key, which is one pack. */
struct group {
	uint32_t  kind, target_mask, arch_mask;
	int       bucket;                /* enum pack_bucket, or BUCKET_NONE */
	uint32_t *member;                /* indices into the artefact array */
	uint32_t  n, cap;
};

static int cmp_u32(const void *pa, const void *pb)
{
	uint32_t a = *(const uint32_t *)pa, b = *(const uint32_t *)pb;
	return a < b ? -1 : (a > b ? 1 : 0);
}

/*
 * A fingerprint of everything that decides whether this module fires: its
 * preconditions, and the exact set of patterns and regions it searches for - not
 * its code, so two modules that reach the same verdict by different logic are not
 * "the same signature" and this does not claim they are. That is a real limitation,
 * not an oversight: a module whose kof_scan body does something beyond calling
 * kof_find_str_* is invisible to this check.
 *
 * Order independent by construction: each string and each range hashes to one
 * number of its own, and the SORTED list of those numbers is what gets hashed
 * again - so two artefacts differing only in which order their declarations were
 * typed in still fingerprint the same, which is the case this exists to catch.
 */
static uint32_t artefact_fingerprint(const struct artefact *a)
{
	uint32_t *sh = NULL, *rh = NULL;
	uint32_t i, precond[4], final = 0;
	uint8_t *buf;
	size_t buflen, w;

	if (a->n_str) {
		sh = malloc(a->n_str * sizeof *sh);
		if (!sh)
			return 0;
	}
	if (a->n_rng) {
		rh = malloc(a->n_rng * sizeof *rh);
		if (!rh) {
			free(sh);
			return 0;
		}
	}

	for (i = 0; i < a->n_str; i++) {
		uint32_t hh = KOF_HASH_INIT;
		uint32_t j;

		hh = kof_hash_step(hh, a->str[i].kind);
		hh = kof_hash_step(hh, a->str[i].flags);
		for (j = 0; j < a->str[i].len; j++)
			hh = kof_hash_step(hh, a->str[i].bytes[j]);
		sh[i] = hh;
	}
	for (i = 0; i < a->n_rng; i++)
		rh[i] = a->rng[i];

	if (a->n_str)
		qsort(sh, a->n_str, sizeof *sh, cmp_u32);
	if (a->n_rng)
		qsort(rh, a->n_rng, sizeof *rh, cmp_u32);

	precond[0] = a->target_mask;
	precond[1] = a->subtype_mask;
	precond[2] = a->arch_mask;
	precond[3] = (uint32_t)a->size_min;   /* truncated on purpose - a size floor
						* that differs only past 4GB is not
						* worth splitting a fingerprint over */

	buflen = sizeof precond + (size_t)a->n_str * sizeof *sh +
		 (size_t)a->n_rng * sizeof *rh;
	buf = malloc(buflen);
	if (!buf) {
		free(sh);
		free(rh);
		return 0;
	}
	w = 0;
	memcpy(buf + w, precond, sizeof precond);
	w += sizeof precond;
	if (a->n_str) {
		memcpy(buf + w, sh, (size_t)a->n_str * sizeof *sh);
		w += (size_t)a->n_str * sizeof *sh;
	}
	if (a->n_rng)
		memcpy(buf + w, rh, (size_t)a->n_rng * sizeof *rh);

	final = kof_hash_bytes(buf, buflen);
	free(buf);
	free(sh);
	free(rh);
	return final;
}

struct fp_idx {
	uint32_t fp;
	uint32_t idx;
};

static int cmp_fp_idx(const void *pa, const void *pb)
{
	const struct fp_idx *a = pa, *b = pb;
	return a->fp < b->fp ? -1 : (a->fp > b->fp ? 1 : 0);
}

/*
 * Warn, do not refuse: a real collision means two artefacts declare the same
 * target, region and pattern set, which is either a copy left behind or two
 * families that genuinely share one detection - and only a person reading both
 * files can tell which. Refusing the build over the second case would make a
 * legitimate database impossible to build; staying quiet about the first lets a
 * stale duplicate ride along indefinitely. A warning is the one answer that costs
 * nothing when it is the second case and loses nothing when it is the first.
 */
static void warn_duplicate_patterns(struct artefact *arts, uint32_t n_arts)
{
	struct fp_idx *fps;
	uint32_t i;

	if (n_arts < 2)
		return;
	fps = malloc(n_arts * sizeof *fps);
	if (!fps)
		return;
	for (i = 0; i < n_arts; i++) {
		arts[i].fp = artefact_fingerprint(&arts[i]);
		fps[i].fp = arts[i].fp;
		fps[i].idx = i;
	}
	qsort(fps, n_arts, sizeof *fps, cmp_fp_idx);
	for (i = 0; i + 1 < n_arts; i++) {
		if (fps[i].fp != fps[i + 1].fp)
			continue;
		/*
		 * ACROSS KINDS IT IS NOT A DUPLICATE, IT IS A PAIR.
		 *
		 * The fingerprint is target, regions and patterns, and a
		 * heuristic rule declares no patterns - so it collides with
		 * every other pattern-free module for the same format, which is
		 * every unpacker. The two say different things about the same
		 * kind of file and neither is redundant. Only two modules of the
		 * SAME kind saying it are worth a word.
		 */
		if (arts[fps[i].idx].kind != arts[fps[i + 1].idx].kind)
			continue;
		/*
		 * A MODULE THAT DECLARES NO PATTERN IS NOT COMPARABLE.
		 *
		 * The fingerprint is target, regions and patterns, so with no
		 * patterns it is only the target - and every unpacker for one
		 * format then collides with every other. The four msfvenom
		 * decoders are the case: each recognises its stub by comparing
		 * bytes inside kof_unpack, which is code and not a declaration,
		 * so all four fingerprint identically and none is redundant.
		 * Saying so anyway trains a reader to ignore the warning, which
		 * costs the one time it is real.
		 */
		if (!arts[fps[i].idx].n_str && !arts[fps[i + 1].idx].n_str)
			continue;
		fprintf(stderr,
			"ksigbuilder: warning: %s and %s declare the same target, "
			"region and pattern set - one may be redundant\n",
			arts[fps[i].idx].stem, arts[fps[i + 1].idx].stem);
	}
	free(fps);
}

/* Every field of the key, so the order is total and no two packs can tie. */
static int group_cmp(const void *pa, const void *pb)
{
	const struct group *a = pa, *b = pb;

	if (a->kind != b->kind)
		return a->kind < b->kind ? -1 : 1;
	if (a->target_mask != b->target_mask)
		return a->target_mask < b->target_mask ? -1 : 1;
	if (a->arch_mask != b->arch_mask)
		return a->arch_mask < b->arch_mask ? -1 : 1;
	return 0;
}

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
	/* "heur" reads as what it is on the filesystem, which is where somebody
	 * looks first to ask what a database contains. Grouped with the other
	 * two here rather than defaulting to "sigs", because a pack of rules
	 * named sigs- is a pack of rules nobody knows is there. */
	return k == KOF_PACK_UNPACK ? "unpack" :
	       k == KOF_PACK_HEUR   ? "heur" : "sigs";
}

/*
 * NAMING A PACK SO A DIRECTORY LISTING IS READABLE.
 *
 * The name says WHAT IS IN THE PACK. It does not encode the key, and it used to:
 * "detect-t768-a0" spelled the masks in decimal, which nobody reads off a number,
 * and the numbers moved every time a format was added. Spelling the bits instead
 * fixed the reading and left the deeper mistake in place - the masks are already in
 * the pack header, per module and unioned, so a filename that repeats them is
 * carrying the machine's copy of something the machine already has.
 *
 * What a filename is for is telling a person which database this is, in ONE SHORT
 * GENERAL WORD. Not a list. A name assembled from its contents has no upper bound -
 * "zip+doczip" is two and looks survivable, fifty formats in a filename is where the
 * same rule ends up - and it churns every time a module is added to the pack.
 *
 * So: the general word is the format, and a label is used only where it is strictly
 * more informative and cannot grow. That is a pack holding exactly one module -
 * "upx-elf" says what "elf" does not, and there is nothing there to accumulate. The
 * moment a pack holds two, the format is the honest general answer and the labels
 * are not the filename's business; a reader who wants the roster opens the pack.
 *
 * The format word is likewise ONE format - the first the mask names, not the union.
 * ZIP|DOCZIP is "zip", because a DOCZIP is a zip and the extra bit is a distinction
 * the header already records exactly. The filename is the general answer; the pack
 * header is the precise one, and only one of them has to be both.
 *
 * THE ONE RULE THAT CANNOT BEND is that the name stays unique: two groups sharing a
 * filename means the second overwrites the first and half the database silently
 * disappears. Deriving the name from the key made that true by construction, and
 * that construction is exactly what produced names like "detect-t768-a0". Naming for
 * a reader gives the guarantee up, so it is CHECKED instead - see the refusal in the
 * write loop - and a collision stops the build rather than eating a pack.
 *
 * Deliberately in that order. A general name that collides is a build failure
 * somebody fixes in a minute; a precise name that nobody can read is permanent.
 *
 * Collisions can really happen, and now more easily: two packs whose masks differ
 * only in a bit past the first both want the same format word. That is a real
 * possibility rather than a hypothetical one, and it is the price of the general
 * name - paid at build time, loudly, by the person who can do something about it.
 */
#define PACK_NAME_MAX 64u

/* Lowercased, with the word break a label carries turned into a hyphen and anything
 * else dropped: this becomes a path component on whatever filesystem the caller
 * chose. "upx_elf" is written "upx-elf"; a format name has no separator to convert. */
static void name_append(char *out, size_t cap, size_t *at, const char *s)
{
	for (; *s && *at + 1u < cap; s++) {
		char c = *s;

		if (c >= 'A' && c <= 'Z')
			c = (char)(c + ('a' - 'A'));
		if (c == '_')
			c = '-';
		if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		      c == '-'))
			continue;
		out[(*at)++] = c;
	}
	out[*at] = 0;
}

/*
 * The formats a mask names, joined - or "any" when it names all of them.
 *
 * Returns zero when the list would not fit, and the caller falls back to the mask
 * itself. Length rather than count is the test because format names differ in
 * length and a fixed count would sometimes fit and sometimes not.
 */
static int format_list(uint32_t mask, char *out, size_t cap)
{
	uint32_t all = (uint32_t)((1ull << KOF_FMT_COUNT) - 1ull);
	size_t at = 0;
	uint32_t f;

	out[0] = 0;
	if ((mask & all) == all) {
		name_append(out, cap, &at, "any");
		return 1;
	}
	for (f = 0; f < KOF_FMT_COUNT; f++) {
		if (!(mask & (1u << f)))
			continue;
		name_append(out, cap, &at, kof_format_name((uint8_t)f));
		return at != 0;
	}
	return 0;
}

/*
 * The label of a pack that holds exactly one module - which is its module's.
 *
 * Only one. A pack of two is not named by listing both: a name that grows with its
 * contents is the same mistake as spelling the mask, and it ends at fifty formats in
 * a filename. Two or more modules and the caller falls back to the format, which is
 * the general word that stays one word however many modules arrive.
 */
static int label_one(const struct artefact *arts, const uint32_t *member,
		     uint32_t n, char *out, size_t cap)
{
	size_t at = 0;

	out[0] = 0;
	if (n != 1u)
		return 0;
	name_append(out, cap, &at, arts[member[0]].label);
	return at != 0;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s <artefact-dir> <out-dir>\n"
		"       %s --extract <signature.c> <out.pat.h> <out.names>"
		" <out.pre> <out.strs>\n"
		"\n"
		"  <artefact-dir>  holds <name>.blob and the .meta, .strs and .names\n"
		"                  beside each one, as ksigbuilder --module emits them\n"
		"  --extract       read the declarations out of one signature source;\n"
		"                  this is what --module calls\n",
		argv0, argv0);
}

/*
 * ---------------------------------------------------------------------------
 * --module: one signature source in, one artefact set out.
 *
 *     ksigbuilder --module <src.c> <artefact-dir>
 *
 * Everything the old shell driver used to do. The environment carries what a build
 * system already decides for every C project - CC, LD, KOF_INCLUDE for the SDK
 * headers, KOF_BASEDIR for the tree the source was found in - and nothing else
 * is read from anywhere.
 *
 * KOF_BASEDIR exists for one reason worth stating: two sources with the same
 * basename in different kind directories - bases/decomp/zip.c and a future
 * bases/unp/zip.c - must not overwrite each other's artefacts, so the artefact
 * name carries the directory. That prefix is disambiguation, not identity; the
 * label written into the .meta is the basename, because that is what a pack is
 * named after.
 * ---------------------------------------------------------------------------
 */
/*
 * EVERY PER-MODULE GLOBAL, BACK TO NOTHING.
 *
 * The declarations, the pattern and range tables, the name pool and the error
 * count are file-scope, which was harmless while one process compiled one
 * module and exited. --tree compiles a whole tree in one process, and without
 * this the second module inherits the first's: "KOF_TARGET_NAME declared more
 * than once", "a range with this name is already declared", on a source that
 * declares each exactly once.
 *
 * Listed rather than memset over a struct because they are not in one - and
 * naming them is what makes it visible that a new global has to be added here
 * too.
 */
static void module_reset(void)
{
	int i;

	for (i = 0; i < SD_COUNT; i++) {
		g_decl[i].count = 0;
		g_decl[i].line = 0;
		g_decl[i].arg[0] = 0;
	}
	/*
	 * THE COUNTS ARE NOT THE STATE.
	 *
	 * npats/nrngs/nnames going back to zero makes the next module's
	 * pattern 0 reuse uses[0] - and uses[] was never cleared, so it still
	 * held the PREVIOUS module's range list, its line numbers and its
	 * source offsets. --module runs extract_main in this process once per
	 * source, so every module after the first inherited whatever the one
	 * before it left behind.
	 *
	 * What it produced was warnings about code that does not exist. An
	 * unpacker declaring no ranges at all and searching once with
	 * kof_find_str_where was reported as "searched in 2 ranges
	 * (scan_range_code, scan_range_sym_exp)" - a pair no source in the tree
	 * contains, because the two names came from two different files - at
	 * line numbers that landed on declarations rather than on calls. And
	 * `used_unranged` persisting the other way would have SUPPRESSED the
	 * "never searched" warning for a marker that really is never searched.
	 *
	 * So the arrays are cleared, not just their counters. They are static
	 * because they are large, which is a reason to reset them here and not
	 * a reason to trust them.
	 */
	memset(uses, 0, sizeof uses);
	memset(rng_used, 0, sizeof rng_used);
	memset(pats, 0, sizeof pats);
	memset(rngs, 0, sizeof rngs);
	memset(names, 0, sizeof names);
	npats = nrngs = nnames = errors = 0;
	scan_mask = 0;
	g_target_mask = g_arch_mask = g_subtype_mask = 0;
	g_size_min = 0;
	g_unp_kind = g_heur_phase = g_heur_level = g_heur_want = 0;
	g_n_targets = 0;
	g_heur_name[0] = g_heur_predict[0] = 0;
	g_family[0] = 0;
	g_maltype = 0;
	g_have_name = 0;
	g_find_sig[0] = 0;
	g_find_hash = 0;
	g_heur_sig[0] = 0;
	g_scan_mask_out = 0;
	g_nstr_out = 0;
	g_src_text = NULL;
	g_src_len = 0;
}

static int module_main(int argc, char **argv)
{
	const char *src = argc > 2 ? argv[2] : NULL;
	const char *outdir = argc > 3 ? argv[3] : NULL;
	const char *basedir = getenv("KOF_BASEDIR");
	const char *lds = getenv("KOF_LDSCRIPT");
	char work[512], name[200], label[128];
	char pat[800], namefile[800], pre[800], strs[800];
	char obj[800], img[800], raw[800], blob[800], meta[800];
	char *xargv[6];
	const char *entry = NULL;
	const char *rel;
	FILE *f;
	long blob_len;
	int kind, rc;

	if (argc != 4 || !src || !outdir) {
		fprintf(stderr, "usage: %s --module <src.c> <artefact-dir>\n",
			argv[0]);
		return 2;
	}
	if (!lds || !lds[0]) {
		fprintf(stderr, "ksigbuilder: KOF_LDSCRIPT is not set\n");
		return 2;
	}

	/*
	 * The artefact name: the path below the content tree, flattened.
	 * Without a tree to be below, the basename alone - which is what a
	 * one-off build of a single file wants.
	 */
	{
		/* Resolved first, because the caller names sources relatively
		 * and KOF_BASEDIR absolutely - comparing them as given would
		 * never match and every artefact would lose its directory
		 * prefix, which is what keeps two sources of the same basename
		 * from overwriting each other. */
		static char abs[4096];
		const char *under = NULL;

		if (basedir && basedir[0] && kof_abs_path(src, abs, sizeof abs))
			under = kof_path_under(abs, basedir);
		rel = under && under[0] ? under : kof_path_base(src);
	}
	{
		size_t i, n = 0;

		for (i = 0; rel[i] && n + 1u < sizeof name; i++) {
			char c = rel[i];

			if (c == '/' || c == '\\')
				c = '_';
			name[n++] = c;
		}
		name[n] = 0;
		if (n > 2u && !strcmp(name + n - 2u, ".c"))
			name[n - 2u] = 0;
	}
	snprintf(label, sizeof label, "%s", kof_path_base(src));
	{
		size_t n = strlen(label);

		if (n > 2u && !strcmp(label + n - 2u, ".c"))
			label[n - 2u] = 0;
	}

	snprintf(work, sizeof work, "%s", outdir);
	snprintf(pat, sizeof pat, "%s/%s.pat.h", work, name);
	snprintf(namefile, sizeof namefile, "%s/%s.names", outdir, name);
	snprintf(strs, sizeof strs, "%s/%s.strs", outdir, name);
	snprintf(pre, sizeof pre, "%s/%s.pre", work, name);
	snprintf(obj, sizeof obj, "%s/%s.o", work, name);
	snprintf(img, sizeof img, "%s/%s.elf", work, name);
	snprintf(raw, sizeof raw, "%s/%s.raw", work, name);
	snprintf(blob, sizeof blob, "%s/%s.blob", outdir, name);
	snprintf(meta, sizeof meta, "%s/%s.meta", outdir, name);

	module_reset();
	printf("== %s\n", src);

	/* The declarations, the patterns and the name table, in this process. */
	xargv[0] = argv[0];
	{
		static char x_extract[] = "--extract";

		xargv[1] = x_extract;
	}
	xargv[2] = (char *)(size_t)src;   /* extract_main does not write it */
	xargv[3] = pat;
	xargv[4] = namefile;
	xargv[5] = pre;
	{
		char *xa[7];

		xa[0] = xargv[0]; xa[1] = xargv[1]; xa[2] = xargv[2];
		xa[3] = xargv[3]; xa[4] = namefile; xa[5] = xargv[5];
		xa[6] = strs;
		src_name = src;
		if (extract_main(7, xa) != 0)
			return 1;
	}

	if (!check_format_headers(g_target_mask, g_n_targets))
		return 1;
	if (!check_size_body())
		return 1;

	if (!do_build(src, pat, obj, img, raw, lds, &entry))
		return 1;

	if (!strcmp(entry, "kof_heur"))
		kind = 2;
	else if (!strcmp(entry, "kof_unpack"))
		kind = 1;
	else
		kind = 0;
	if (!kind_checks(kind))
		return 1;

	/* The blob is what the linker wrote; copying it is the only step that
	 * moves bytes, and it moves them unchanged. */
	{
		char *bytes;
		size_t n;
		FILE *o;

		bytes = slurp(raw, &n);
		if (!bytes) {
			fprintf(stderr, "ksigbuilder: cannot read %s\n", raw);
			return 1;
		}
		o = fopen(blob, "wb");
		if (!o) {
			free(bytes);
			fprintf(stderr, "ksigbuilder: cannot write %s\n", blob);
			return 2;
		}
		fwrite(bytes, 1, n, o);
		fclose(o);
		free(bytes);
		blob_len = (long)n;
	}

	f = fopen(meta, "w");
	if (!f) {
		fprintf(stderr, "ksigbuilder: cannot write %s\n", meta);
		return 2;
	}
	fprintf(f, "target=%u\n", g_target_mask);
	fprintf(f, "scan_mask=%lu\n", g_scan_mask_out);
	fprintf(f, "size_min=%llu\n", (unsigned long long)g_size_min);
	fprintf(f, "arch_mask=%u\n", g_arch_mask);
	fprintf(f, "subtype_mask=%u\n", g_subtype_mask);
	fprintf(f, "unp_kind=%d\n", g_unp_kind);
	fprintf(f, "heur_phase=%d\n", g_heur_phase);
	fprintf(f, "heur_want=%d\n", g_heur_want);
	fprintf(f, "heur_level=%d\n", g_heur_level);
	fprintf(f, "heur_predict=%s\n", g_heur_predict);
	/* A heuristic rule has no family; its word goes in the same slot, and
	 * the engine writes "Heur" where a maltype would be. */
	fprintf(f, "family=%s\n", kind == 2 ? g_heur_name
					    : (g_have_name ? g_family : ""));
	fprintf(f, "maltype=%d\n", kind == 2 ? 0
					     : (g_have_name ? g_maltype : 0));
	fprintf(f, "nstr=%d\n", g_nstr_out);
	fprintf(f, "blob_len=%ld\n", blob_len);
	fprintf(f, "kind=%d\n", kind);
	fprintf(f, "label=%s\n", label);
	/* The path INSIDE the content tree, which is what a tool holding a scan
	 * result opens to find the source. Empty when the source was not under
	 * one, because then there is no tree-relative name to give. */
	fprintf(f, "srcpath=%s\n", rel != src ? rel : "");
	fclose(f);

	printf("== ok  %s  %ld bytes  kind=%s  strs=%d  target=%u scan=0x%lx\n",
	       blob, blob_len,
	       kind == 2 ? "heur" : kind == 1 ? "unpack" : "detect",
	       g_nstr_out, g_target_mask, g_scan_mask_out);
	(void)rc;
	return 0;
}

/*
 * ---------------------------------------------------------------------------
 * --tree: a content directory in, a database out, with no shell involved.
 *
 *     ksigbuilder --tree <bases-dir> <artefact-dir> <database-dir>
 *
 * Walks the tree the way the build did - the top level and one level below it,
 * so the three kind directories are directories rather than a naming convention
 * - compiles every source, then packs the artefacts.
 *
 * WHY THIS EXISTS AND NOT JUST --module. A caller that has make and a POSIX
 * shell can loop over the sources itself, and did. A caller that has neither -
 * a Windows host with a compiler and PowerShell, which is the ordinary case
 * once MSYS2 is not assumed - cannot, and should not have to: the directory
 * layout, the order, and the emptying of the artefact directory before a build
 * are all decisions this program already owns. The loop belongs with them.
 *
 * The artefact directory is emptied first, and that is not tidiness: ksigbuilder
 * packs a DIRECTORY rather than a list of files, so anything left from a
 * previous run is in the database. A signature deleted from the source would
 * otherwise keep shipping because its blob was never removed - and the build
 * succeeds either way, which is what makes it worth doing here rather than
 * trusting every caller to remember.
 * ---------------------------------------------------------------------------
 */
static int pack_main(int argc, char **argv);

static int is_c_source(const char *name)
{
	size_t n = strlen(name);

	return n > 2u && !strcmp(name + n - 2u, ".c");
}

static int tree_one(char **argv, const char *src, const char *artefacts,
		    int *built)
{
	char *xa[4];

	xa[0] = argv[0];
	xa[1] = (char *)(size_t)"--module";
	xa[2] = (char *)(size_t)src;
	xa[3] = (char *)(size_t)artefacts;
	if (module_main(4, xa) != 0)
		return 0;
	(*built)++;
	return 1;
}

static int tree_main(int argc, char **argv)
{
	const char *base = argc > 2 ? argv[2] : NULL;
	const char *artefacts = argc > 3 ? argv[3] : NULL;
	const char *db = argc > 4 ? argv[4] : NULL;
	char abs_base[4096];
	DIR *d;
	struct dirent *e;
	int built = 0;

	if (argc != 5) {
		fprintf(stderr, "usage: %s --tree <bases-dir> <artefact-dir> "
				"<database-dir>\n", argv[0]);
		return 2;
	}
	/* KOF_BASEDIR is what --module strips to name an artefact, and it has
	 * to be the absolute form of the tree being walked - set here so a
	 * caller cannot pass one that disagrees with the other argument. */
	if (!kof_abs_path(base, abs_base, sizeof abs_base)) {
		fprintf(stderr, "ksigbuilder: no such directory: %s\n", base);
		return 2;
	}
#ifdef _WIN32
	_putenv_s("KOF_BASEDIR", abs_base);
#else
	setenv("KOF_BASEDIR", abs_base, 1);
#endif

	d = opendir(base);
	if (!d) {
		fprintf(stderr, "ksigbuilder: cannot read %s\n", base);
		return 2;
	}
	while ((e = readdir(d)) != NULL) {
		char path[2048];

		if (e->d_name[0] == '.')
			continue;
		snprintf(path, sizeof path, "%s/%s", base, e->d_name);
		if (is_c_source(e->d_name)) {
			if (!tree_one(argv, path, artefacts, &built)) {
				closedir(d);
				return 1;
			}
			continue;
		}
		/* One level down, which is where the kind directories are. */
		{
			DIR *sd = opendir(path);
			struct dirent *se;

			if (!sd)
				continue;
			while ((se = readdir(sd)) != NULL) {
				char sub[4200];

				if (se->d_name[0] == '.' ||
				    !is_c_source(se->d_name))
					continue;
				snprintf(sub, sizeof sub, "%s/%s", path,
					 se->d_name);
				if (!tree_one(argv, sub, artefacts, &built)) {
					closedir(sd);
					closedir(d);
					return 1;
				}
			}
			closedir(sd);
		}
	}
	closedir(d);

	if (!built) {
		fprintf(stderr, "ksigbuilder: no sources in %s\n", base);
		return 2;
	}
	printf("   %d source(s) from %s -> %s\n", built, base, artefacts);

	/* And pack, which is what this program did before it did anything
	 * else. */
	{
		char *pa[3];

		pa[0] = argv[0];
		pa[1] = (char *)(size_t)artefacts;
		pa[2] = (char *)(size_t)db;
		return pack_main(3, pa);
	}
}

/* The pack path, and the modes that dispatch before it. Called from main below,
 * and from --tree once it has compiled everything. */
static int pack_main(int argc, char **argv)
{
	const char *workdir = NULL, *outdir = NULL;
	int i, rc = 1;

	struct artefact *arts = NULL;
	uint32_t n_arts = 0, cap_arts = 0, a, j;
	struct group *groups = NULL;
	uint32_t n_groups = 0, cap_groups = 0;
	/* Every path written so far this run, so a second pack cannot take a name a
	 * first one already has. See the naming block above format_list. */
	char **taken = NULL;
	uint32_t n_taken = 0;
	DIR *d = NULL;
	struct dirent *de;

	/*
	 * --image: everything the build needs to know about a linked module,
	 * in one call and from one parser.
	 *
	 * It replaces four programs - readelf twice, nm three times, size once
	 * - whose answers had to be recovered from their printed text with grep
	 * and awk. Those tools are also the ones a Windows host does not have
	 * without installing a POSIX toolchain, so this is what lets the build
	 * run with nothing but a compiler and a linker.
	 */
	/*
	 * --object is the same reader with the image-only refusals off.
	 *
	 * An OBJECT legitimately has .text, .rodata and a relocation section -
	 * that is what linking consumes. Only the LINKED IMAGE must have none
	 * of them, so applying the image's rules to an object refuses every
	 * module. What an object is asked here is the one thing that must be
	 * true before linking: that it holds no writable state.
	 */
	if (argc > 1 && (strcmp(argv[1], "--image") == 0 ||
			 strcmp(argv[1], "--object") == 0)) {
		int strict = strcmp(argv[1], "--image") == 0;
		struct img_facts f;

		if (argc != 4) {
			fprintf(stderr, "usage: %s --image <linked.elf> "
					"<out.blob>\n", argv[0]);
			return 2;
		}
		/*
		 * ELF or COFF, decided by what the file is rather than by a
		 * flag the caller has to pass: the build already knows which
		 * platform it is on, and a mode argument that can disagree with
		 * the file is one more thing to get wrong.
		 */
		{
			size_t n = 0;
			char *head = slurp(argv[2], &n);
			int is_elf = head && n >= 4 &&
				     (unsigned char)head[0] == 0x7f &&
				     head[1] == 'E' && head[2] == 'L' &&
				     head[3] == 'F';

			free(head);
			if (is_elf ? !img_read(argv[2], ".blob", &f)
				   : !coff_read(argv[2], &f)) {
				fprintf(stderr, "ksigbuilder: cannot read %s "
						"as ELF or COFF\n", argv[2]);
				return 2;
			}
			/* A COFF object carries no linked image to check for
			 * leftover sections, and its blob is produced by the
			 * linker rather than extracted here. */
			if (!is_elf)
				f.blob_len = 1;
		}
		if (strict && f.have_reloc) {
			fprintf(stderr, "FAIL: relocations remain (%s)\n",
				f.extra_sec);
			return 1;
		}
		if (strict && f.undef[0]) {
			fprintf(stderr, "FAIL: undefined symbol (module "
					"reached outside its blob): %s\n",
				f.undef);
			return 1;
		}
		if (strict && f.extra_sec[0]) {
			fprintf(stderr, "FAIL: unexpected section in image: "
					"%s\n", f.extra_sec);
			return 1;
		}
		if (strict && f.n_entry != 1) {
			fprintf(stderr, "FAIL: image exports %d of kof_scan, "
					"kof_unpack, kof_heur; a module is "
					"one kind\n", f.n_entry);
			return 1;
		}
		if (strict && f.entry_off != 0) {
			fprintf(stderr, "FAIL: entry point is at 0x%llx, "
					"expected 0; check module.ld\n",
				(unsigned long long)f.entry_off);
			return 1;
		}
		if (strict && !f.blob_len) {
			fprintf(stderr, "FAIL: image has no .blob section\n");
			return 1;
		}
		if (strcmp(argv[3], "/dev/null") != 0) {
			char *img;
			size_t n;
			FILE *o;

			img = slurp(argv[2], &n);
			if (!img || f.blob_off + f.blob_len > n) {
				free(img);
				fprintf(stderr, "FAIL: .blob runs past the "
						"image\n");
				return 1;
			}
			o = fopen(argv[3], "wb");
			if (!o) {
				free(img);
				fprintf(stderr, "ksigbuilder: cannot write "
						"%s\n", argv[3]);
				return 2;
			}
			fwrite(img + f.blob_off, 1, (size_t)f.blob_len, o);
			fclose(o);
			free(img);
		}
		/* What the caller still needs, on stdout so a shell can read it
		 * without a temporary file. */
		printf("entry=%s\n", f.entry_name);
		printf("blob_len=%llu\n", (unsigned long long)f.blob_len);
		printf("data=%llu\n", (unsigned long long)f.data_bytes);
		printf("bss=%llu\n", (unsigned long long)f.bss_bytes);
		return 0;
	}

	/*
	 * --build: compile, link, validate and emit one module.
	 *
	 * The middle of what the old shell driver did, moved here so the only shell
	 * left in a build is the one that chose to run it. The compiler and the
	 * linker are still separate programs - they have to be - but nothing
	 * between them is a program any more.
	 *
	 *   ksigbuilder --build <src.c> <pat.h> <obj> <img> <raw> <ldscript>
	 *
	 * The tools come from CC and LD in the environment, defaulting to the
	 * names a POSIX toolchain uses, so a caller that has already decided
	 * which compiler to use - the Makefile, a cross build - says so the same
	 * way every other C project does.
	 */
	if (argc > 1 && strcmp(argv[1], "--build") == 0) {
		const char *entry = NULL;

		if (argc != 8) {
			fprintf(stderr, "usage: %s --build <src.c> <pat.h> "
					"<obj> <img> <raw> <ldscript>\n",
				argv[0]);
			return 2;
		}
		if (!do_build(argv[2], argv[3], argv[4], argv[5], argv[6],
			      argv[7], &entry))
			return 1;
		printf("entry=%s\n", entry);
		return 0;
	}

	if (argc > 1 && strcmp(argv[1], "--module") == 0)
		return module_main(argc, argv);
	if (argc > 1 && strcmp(argv[1], "--extract") == 0)
		return extract_main(argc, argv);
	if (argc > 1 && strcmp(argv[1], "--arch-mask") == 0)
		return arch_mask_main(argc, argv);
	if (argc > 1 && strcmp(argv[1], "--subtype-mask") == 0)
		return subtype_mask_main(argc, argv);

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

	/*
	 * SORTED, BECAUSE readdir ORDER IS NOT AN ORDER.
	 *
	 * The artefacts arrive in whatever sequence the filesystem hands them
	 * back, which depends on how the directory was written and is not the
	 * same twice - a rebuild after rm -rf, a different filesystem, another
	 * machine. That order survives into the pack, and the scan loop stops
	 * at the FIRST module that names a family, so it decides which of two
	 * matching signatures is the one reported.
	 *
	 * Measured while moving the build off the shell: the same 62 sources,
	 * the same 62 blobs byte for byte, packed from two directories written
	 * in different orders - 11 files came back suspected from one database
	 * and infected from the other. Nothing about that was visible in the
	 * build, which succeeded both times.
	 *
	 * Sorting by the artefact name makes the database a function of its
	 * sources and nothing else.
	 */
	qsort(arts, n_arts, sizeof *arts, artefact_cmp);

	warn_duplicate_patterns(arts, n_arts);

	/* Linear scan over the groups: the number of distinct precondition tuples
	 * is small and does not grow with the number of signatures, which is the
	 * property that makes this cheap however large the set gets. */
	for (a = 0; a < n_arts; a++) {
		struct group *g = NULL;
		int ab = bucket_of_mask(arts[a].target_mask);

		/*
		 * BY BUCKET, AND ARCHITECTURE IS NOT PART OF THE KEY.
		 *
		 * It used to be one pack per exact (kind, target_mask,
		 * arch_mask), on the reasoning that a pack whose any_target is
		 * exactly M lets the scanner skip the whole file in one
		 * comparison instead of N.
		 *
		 * That comparison does not exist. any_target, any_scan and
		 * any_arch are written into every pack header by the writer and
		 * are read by NOTHING - grep the tree. What actually filters is
		 * KOF_SEC_PRE_TARGET and KOF_SEC_PRE_ARCH, the per-module
		 * columns the scanner sweeps at kofdb.c:569. So the split was
		 * buying a skip that was never wired up, and charging a whole
		 * file for it: sigs-elf-x86.ksig held ONE module and cost 4164
		 * bytes, of which 3132 were zeros.
		 *
		 * If a pack-level prefilter is ever implemented, the header
		 * fields are still there and still correct - the writer unions
		 * them from the members, so a merged pack gets a wider union and
		 * skips less, which costs sweeps and never a detection.
		 */
		for (j = 0; j < n_groups; j++)
			if (groups[j].kind == arts[a].kind &&
			    ((ab != BUCKET_NONE && groups[j].bucket == ab) ||
			     (ab == BUCKET_NONE &&
			      groups[j].bucket == BUCKET_NONE &&
			      groups[j].target_mask == arts[a].target_mask))) {
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
			g->bucket      = ab;
			g->target_mask = arts[a].target_mask;
			g->arch_mask   = arts[a].arch_mask;
		} else {
			/*
			 * The union, for the name. arch_mask 0 means ANY, so
			 * it absorbs rather than being absorbed - a pack
			 * holding one arch-any module is an arch-any pack, and
			 * OR-ing 0 into a specific mask would claim the
			 * opposite.
			 */
			g->target_mask |= arts[a].target_mask;
			if (g->arch_mask == 0u || arts[a].arch_mask == 0u)
				g->arch_mask = 0u;
			else
				g->arch_mask |= arts[a].arch_mask;
		}
		if (!group_add(g, a))
			goto done;
	}

	/*
	 * Order the packs by their key before any of them is named.
	 *
	 * Naming reads the names already taken, so which pack gets the plain
	 * general name and which gets the mask suffix depends on the order they are
	 * visited in - and that order was readdir's, which is the filesystem's and
	 * not the same on two machines. Same sources, same modules, "sigs-elf.ksig"
	 * holding different packs. Nothing would detect it: both databases load and
	 * both scan correctly, because the loader takes every .ksig in the directory
	 * and does not care what they are called.
	 *
	 * Sorting by the key makes it the key's order, which is the same everywhere.
	 * It also decides the tie the right way round: the smallest mask is the most
	 * specific pack, so the plain "elf" goes to the ELF pack and ELF|PE takes the
	 * suffix, rather than the other way about.
	 */
	qsort(groups, n_groups, sizeof *groups, group_cmp);

	printf("%u module(s) -> %u pack(s)\n", n_arts, n_groups);

	taken = calloc(n_groups, sizeof *taken);
	if (!taken)
		goto done;

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
			pm[a].unp_kind     = s->unp_kind;
			pm[a].heur_phase   = s->heur_phase;
			pm[a].heur_want    = s->heur_want;
			pm[a].heur_level   = s->heur_level;
			pm[a].src          = s->srcpath;
			pm[a].size_min    = s->size_min;
			pm[a].str         = s->str;
			pm[a].n_str       = s->n_str;
			pm[a].rng         = s->rng;
			pm[a].n_rng       = s->n_rng;
			pm[a].name        = s->name;
			pm[a].n_names     = s->n_names;
			pm[a].family      = s->family;
			pm[a].maltype     = s->maltype;
			pm[a].heur_predict = s->heur_predict;
		}

		img = kof_pack_build(g->kind, pm, g->n, &img_len);
		free(pm);
		if (!img) {
			fprintf(stderr, "ksigbuilder: cannot build pack %u\n", j);
			goto done;
		}

		/*
		 * The name says what is in the pack - the tools by label for an
		 * unpack pack, the formats for a sigs pack. See the block above
		 * format_list for why the two differ, and name_clash for what keeps
		 * the result unique now that it no longer is by construction.
		 *
		 * The architecture is appended only when it constrains something: an
		 * unconstrained one is the ordinary case and writing "-any" on every
		 * pack would be noise in the place a reader looks first. It stays in
		 * the name because it is the one part of the key a reader cannot
		 * infer from the contents.
		 */
		{
			char fmt[PACK_NAME_MAX], arch[PACK_NAME_MAX];
			size_t aat = 0;

			if (g->kind != KOF_PACK_UNPACK ||
			    !label_one(arts, g->member, g->n, fmt, sizeof fmt)) {
				/*
				 * The bucket names the pack when there is one:
				 * "archive" rather than "zip+tar+gzip+xz+rar+
				 * sevenzip", which is what the union spells and
				 * which nobody can read. The format list stays
				 * for a mask whose bits do not agree on a
				 * bucket, because there the exact set IS the
				 * only honest name.
				 */
				const char *bn = bucket_name(g->bucket);

				if (*bn)
					snprintf(fmt, sizeof fmt, "%s", bn);
				else if (!format_list(g->target_mask, fmt,
						      sizeof fmt))
					snprintf(fmt, sizeof fmt, "x%x",
						 g->target_mask);
			}

			/*
			 * ARCHITECTURE IS NEVER IN THE NAME ANY MORE, because
			 * it is no longer in the key: an x86-only module and an
			 * arch-any one share a pack, so a suffix naming one of
			 * them would describe the pack wrongly. Which
			 * architectures a pack covers is in its header and in
			 * the per-module column, where it is read.
			 */
			arch[0] = 0;
			if (0) {
				uint32_t ab;

				for (ab = 0; ab < 32u; ab++) {
					if (!(g->arch_mask & (1u << ab)))
						continue;
					if (aat && aat + 1u < sizeof arch)
						arch[aat++] = '+';
					name_append(arch, sizeof arch, &aat,
						    kof_arch_name((uint8_t)ab));
				}
				if (!aat)
					snprintf(arch, sizeof arch, "a%x",
						 g->arch_mask);
			}

			snprintf(path, sizeof path, "%s/%s-%s%s%s.ksig",
				 outdir, kind_name(g->kind), fmt,
				 arch[0] ? "-" : "", arch);

			/*
			 * The general name, made specific only where it has to
			 * be.
			 *
			 * A general name collides by design: "elf" is the name
			 * of the ELF pack and of the ELF|PE pack, and both are
			 * correct answers to what is in them. Refusing the build
			 * would be refusing a legitimate database over a
			 * filename, so the second one earns a suffix instead and
			 * the common case stays short.
			 *
			 * The suffix is the target mask, which makes the name a
			 * one to one image of the whole key - kind, formats,
			 * architecture - so one retry is always enough and there
			 * is no loop here. Ugly on purpose: it should read as a
			 * pack that wanted a plain name and could not have one.
			 */
			for (a = 0; a < n_taken; a++) {
				if (strcmp(taken[a], path) != 0)
					continue;
				snprintf(path, sizeof path,
					 "%s/%s-%s-x%x%s%s.ksig", outdir,
					 kind_name(g->kind), fmt,
					 g->target_mask, arch[0] ? "-" : "",
					 arch);
				break;
			}
		}

		/*
		 * Refuse rather than overwrite.
		 *
		 * The retry above resolves a collision between two general names, and
		 * a name that survives it is unique by construction. This catches the
		 * case where that reasoning is wrong - because write_file would
		 * happily replace the pack written a moment ago and the build would
		 * succeed with one database missing, which is the failure this whole
		 * file is arranged to make impossible.
		 */
		for (a = 0; a < n_taken; a++) {
			if (strcmp(taken[a], path) != 0)
				continue;
			fprintf(stderr, "ksigbuilder: two packs would both be "
					"%s; rename one of the modules in it\n",
				path);
			free(img);
			goto done;
		}
		taken[n_taken] = strdup(path);
		if (!taken[n_taken]) {
			free(img);
			goto done;
		}
		n_taken++;

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
	for (j = 0; j < n_taken; j++)
		free(taken[j]);
	free(taken);
	return rc;
}
int main(int argc, char **argv)
{
	if (argc > 1 && strcmp(argv[1], "--tree") == 0)
		return tree_main(argc, argv);
	return pack_main(argc, argv);
}
