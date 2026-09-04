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
#include <kofmod/pe.h>       /* and the PE ones */
#include <kofmod/gzip.h>     /* and the gzip ones */
#include <kofmod/docole.h>   /* and the compound file ones */
#include <kofmod/zip.h>      /* and the zip ones, shared by ZIP and DOCZIP */
#include <kofmod/tar.h>
#include <kofmod/sevenzip.h>
#include <kofmod/rar.h>
#include <kofmod/xz.h>
#include <kofmod/rtf.h>

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

#define RGN(x) { #x, (unsigned long)(x) }
static const struct rgn_name rgn_names[] = {
	RGN(KOF_SCAN_ALL),

	/*
	 * Not a format's, like the two above and below are: the symbol block
	 * means the same thing for every input that has one, so kofsig.h
	 * defines these and any target may name them. A rule scoped to
	 * SYM_EXP says "this object exports these bytes", which is a narrower
	 * claim than the same bytes found loose in DATA.
	 */
	RGN(KOF_SCAN_SYM_IMP),
	RGN(KOF_SCAN_SYM_EXP),

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

	RGN(KOF_SCAN_XZ_HEADERS),
	RGN(KOF_SCAN_XZ_PACKED),
	RGN(KOF_SCAN_XZ_UNCLAIMED),

	RGN(KOF_SCAN_RTF_BODY),
	RGN(KOF_SCAN_RTF_OBJDATA),
	RGN(KOF_SCAN_RTF_BINARY),
	RGN(KOF_SCAN_RTF_UNCLAIMED),

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
	DECL_HEXSTR,
	DECL_NAME
};

struct macro {
	const char    *name;
	enum decl_kind kind;
};

static const struct macro macros[] = {
	{ "KOF_TARGET_RANGE",  DECL_RANGE  },
	{ "KOF_TARGET_NAME",   DECL_NAME   },
	{ "KOF_DEFINE_HEXSTR", DECL_HEXSTR },
	{ "KOF_DEFINE_STR",    DECL_STR    },
	{ NULL, DECL_RANGE }
};

/*
 * enum kof_maltype (kofsig.h) as words a source may write. Only the parse
 * direction lives here now: the display word a finding shows comes from
 * kof_maltype_name (kofsig.h) at report time, not from this table at build
 * time - ksigbuilder stores the enum value on the module record and nothing
 * else, see struct kof_pack_mod. A type added to the enum and not here still
 * fails loudly, in read_maltype, rather than compiling and never being
 * reachable from a signature.
 */
struct maltype_name {
	const char *word;
	int         val;
};

static const struct maltype_name maltype_names[] = {
	{ "KOF_MALTYPE_VIRUS",    KOF_MALTYPE_VIRUS    },
	{ "KOF_MALTYPE_TROJAN",   KOF_MALTYPE_TROJAN   },
	{ "KOF_MALTYPE_ROOTKIT",  KOF_MALTYPE_ROOTKIT  },
	{ "KOF_MALTYPE_BOTNET",   KOF_MALTYPE_BOTNET   },
	{ "KOF_MALTYPE_RANSOM",   KOF_MALTYPE_RANSOM   },
	{ "KOF_MALTYPE_MINER",    KOF_MALTYPE_MINER    },
	{ "KOF_MALTYPE_ADWARE",   KOF_MALTYPE_ADWARE   },
	{ "KOF_MALTYPE_EXPLOIT",  KOF_MALTYPE_EXPLOIT  },
	{ "KOF_MALTYPE_DROPPER",  KOF_MALTYPE_DROPPER  },
	{ "KOF_MALTYPE_HACKTOOL", KOF_MALTYPE_HACKTOOL },
	{ NULL, 0 }
};

/*
 * KOF_TARGET_NAME's two fields, file scoped like target_mask and its siblings: one
 * file, one family. Unlike those, read here rather than by ksigcompiler.sh, because
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
	int i;

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
	for (i = 0; maltype_names[i].word; i++)
		if (strcmp(tok, maltype_names[i].word) == 0) {
			*out = maltype_names[i].val;
			return 1;
		}
	{
		int k;
		fprintf(stderr, "%s:%d: error: \"%s\" is not a known malware type. "
				"Known:\n", src_name, line, tok);
		for (k = 0; maltype_names[k].word; k++)
			fprintf(stderr, "    %s\n", maltype_names[k].word);
		errors++;
	}
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
	/* Where in the source each of those calls begins, so the text BETWEEN
	 * two of them can be read. What joins them decides whether one range
	 * over both would mean the same thing. */
	size_t   at[KOF_MAX_RANGE_PER_MODULE];
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

static void use_add(int pi, int ri, int line, size_t at)
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
	u->at[u->n_rng]   = at;
	u->rng[u->n_rng++] = ri;
}

/*
 * ARE TWO SEARCHES FOR ONE MARKER JOINED BY "OR", AND ONLY BY "OR".
 *
 * This is the whole of what decides whether the build may say "these two are
 * one search". "find(CODE,s) || find(DATA,s)" asks whether the marker is in
 * either, which is exactly what one range over CODE|DATA asks - and reads the
 * object once instead of twice. "find(CODE,s) && find(DATA,s)" asks whether it
 * is in BOTH, which one range cannot express at all, and merging it would
 * quietly turn a strict rule into a loose one.
 *
 * The text between the two calls is what says which. A "&&" anywhere in it, or
 * a statement boundary, and the two are not one expression - so nothing is
 * claimed. Being unsure here costs a vaguer warning; being wrong would cost a
 * signature that no longer means what its author wrote.
 */
static int joined_by_or(const char *src, size_t a, size_t b)
{
	size_t i;
	int saw_or = 0;

	if (b <= a)
		return 0;
	for (i = a; i < b; i++) {
		if (src[i] == ';' || src[i] == '{' || src[i] == '}')
			return 0;       /* different statements */
		if (src[i] == '&' && i + 1 < b && src[i + 1] == '&')
			return 0;       /* an AND is not mergeable */
		if (src[i] == '|' && i + 1 < b && src[i + 1] == '|')
			saw_or = 1;
	}
	return saw_or;
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
				continue;       /* mid identifier */
			if (!ident_at(p, sname, sizeof sname))
				continue;
			pi = pat_index(sname);
			if (pi >= 0) {
				if (ri >= 0)
					use_add(pi, ri, line,
						(size_t)(at - src));
				else
					uses[pi].used_unranged = 1;
			}
			p += strlen(sname) - 1u;
		}
	}
}

static void lint_report(const char *src)
{
	int i;
	uint32_t k;

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
		 * THE ONE THAT COSTS REAL TIME.
		 *
		 * Measured over 13426 objects with one marker in .rodata: one
		 * range covering CODE|DATA read 185 MB, two calls over CODE then
		 * DATA read 869 MB - 4.7x - and found the same 1567 objects. The
		 * extents of one range are walked in FILE ORDER and the search
		 * stops at the first hit; two ranges must exhaust the first
		 * region before the second is looked at.
		 */
		if (u->n_rng > 1) {
			uint32_t both = 0;
			char list[256];
			size_t at = 0;
			int mergeable = 1;

			for (k = 0; k < u->n_rng; k++)
				both |= rngs[u->rng[k]].mask;
			for (k = 0; k < u->n_rng; k++) {
				/*
				 * snprintf returns the length it WANTED to write,
				 * so once the joined names fill the buffer `at`
				 * must stop advancing - otherwise sizeof list - at
				 * wraps and list + at points off the end. The
				 * message is a warning; a truncated list is fine, a
				 * smashed stack is not.
				 */
				if (at < sizeof list)
					at += (size_t)snprintf(list + at,
							       sizeof list - at,
							       k ? ", %s" : "%s",
							       rngs[u->rng[k]].name);
				if (k && !joined_by_or(src, u->at[k - 1u],
						       u->at[k]))
					mergeable = 0;
			}
			/*
			 * THE COST IS THE SAME IN BOTH CASES, AND IT IS THE
			 * POINT.
			 *
			 * Whatever joins the two calls, a region the marker is
			 * NOT in is scanned to exhaustion before the next one is
			 * looked at - twice the bytes for one question about one
			 * marker. That is what this warns about, and it is said
			 * first, because it is true either way.
			 *
			 * What the join decides is only whether the fix is
			 * available. "||" asks whether the marker is in either,
			 * which one range over the union asks in a single pass.
			 * "&&" asks whether it is in BOTH, which one range
			 * cannot express - merging it would quietly turn a
			 * strict rule into a loose one - so there the answer is
			 * to check that two regions were really meant.
			 */
			lwarn(u->line[0],
			      "'%s' is searched in %u ranges (%s): a region it "
			      "is not in is scanned to the end before the next "
			      "is looked at",
			      pats[i].name, u->n_rng, list);
			if (mergeable)
				fprintf(stderr, "%s:%d: note:  the calls are "
					"joined by '||', so one "
					"KOF_TARGET_RANGE(<name>, 0x%x) and one "
					"call ask the same question in one pass\n",
					src_name, u->line[0], both);
			else
				fprintf(stderr, "%s:%d: note:  not joined by "
					"'||', so one range over 0x%x would ask "
					"a different question - check that two "
					"regions were meant\n",
					src_name, u->line[0], both);
			for (k = 1; k < u->n_rng; k++)
				fprintf(stderr, "%s:%d: note:  also here\n",
					src_name, u->line[k]);
		}
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

	/* Diagnosis, after the declarations are known and before anything is
	 * written: a warning about a pack that was never produced is noise. */
	lint_calls(src, src_len);
	lint_report(src);

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
	/* Empty when the source never declared one - an unpack-kind module,
	 * where KOF_TARGET_NAME is not required. ksigcompiler.sh copies these
	 * into .meta unchanged; see struct kof_pack_mod for where they end up. */
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
	free(src);
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
	 * KOF_TARGET_NAME (ksigcompiler.sh's --extract refuses the source
	 * otherwise), so an empty family here means an artefact from before
	 * this field existed, not a module that legitimately has none. */
	if (a->kind == KOF_PACK_DETECT && (!a->family || !a->family[0])) {
		fprintf(stderr, "ksigbuilder: %s: record declares no family; "
				"rebuild the artefacts\n", a->stem);
		goto out;
	}
	/* A rule carries its word in the family slot - see ksigcompiler.sh - and
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
	uint32_t  kind, target_mask, arch_mask;
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
	/* Every path written so far this run, so a second pack cannot take a name a
	 * first one already has. See the naming block above format_list. */
	char **taken = NULL;
	uint32_t n_taken = 0;
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

	warn_duplicate_patterns(arts, n_arts);

	/* Linear scan over the groups: the number of distinct precondition tuples
	 * is small and does not grow with the number of signatures, which is the
	 * property that makes this cheap however large the set gets. */
	for (a = 0; a < n_arts; a++) {
		struct group *g = NULL;
		for (j = 0; j < n_groups; j++)
			if (groups[j].kind == arts[a].kind &&
			    groups[j].target_mask == arts[a].target_mask &&
			    groups[j].arch_mask == arts[a].arch_mask) {
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
			    !label_one(arts, g->member, g->n, fmt, sizeof fmt))
				if (!format_list(g->target_mask, fmt, sizeof fmt))
					snprintf(fmt, sizeof fmt, "x%x",
						 g->target_mask);

			arch[0] = 0;
			if (g->arch_mask) {
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