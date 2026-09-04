/* _GNU_SOURCE, not _POSIX_C_SOURCE: this file includes kofplatform.h, whose
 * inline wrapper calls memmem, and only _GNU_SOURCE declares it - the same
 * reason kofinspect.c, kofexamine.c and kofviewer.c all say so. */
#define _GNU_SOURCE

/*
 * kofeditor.c - the signature generator, apart from the viewer that drives it.
 *
 * See kofeditor.h for why this file exists and where the boundary was drawn.
 * What is here answers questions about a DRAFT and about the source a draft is
 * written to and read from. Nothing here knows a pane is on screen.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <strings.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <pwd.h>
#include <unistd.h>
#include <time.h>

#include "kofeditor.h"
#include "../libkofeng/kofmatchers/hexprog.h"
#include "../libkofeng/kofmatchers/kofmatch.h"
#include "../libkofeng/core/kofplatform.h"




/*
 * Who is at this machine.
 *
 * The account name, because it is the one identifier that is already there and
 * already means a person to the team that shares the machine. Not a real name:
 * this tool has no way to know one and inventing a field for somebody to fill in
 * would leave it empty in every file.
 */
static const char *meta_user(void)
{
	const char *u = getenv("USER");

	if (!u || !u[0])
		u = getenv("LOGNAME");
	if (!u || !u[0]) {
		struct passwd *pw = getpwuid(getuid());

		u = pw && pw->pw_name ? pw->pw_name : "";
	}
	return u ? u : "";
}

/* Today, as the one date format that sorts and cannot be read two ways. */
static void meta_today(char *out, uint32_t cap)
{
	time_t now = time(NULL);
	struct tm tmv;

	if (localtime_r(&now, &tmv))
		strftime(out, cap, "%Y-%m-%d", &tmv);
	else
		snprintf(out, cap, "unknown");
}
static void meta_add(char tab[][128], uint32_t *n, uint32_t cap, const char *w);
static void meta_add_who(char tab[][48], uint32_t *n, uint32_t cap,
			 const char *w);

const struct kof_arch_word arch_word[] = {
	{ "ANY",     0 }, { "X86",     1 }, { "X86_64",  2 }, { "ARM",     3 },
	{ "ARM64",   4 }, { "RISCV64", 5 }, { "MIPS",    6 }, { "PPC64",   7 },
	{ "MIPS64",  8 }, { "PPC",     9 }, { "RISCV32", 10 }
};

const char *const elf_sub[] = { "NONE", "REL", "EXEC", "DYN", "CORE" };
const char *const pe_sub[]  = { "EXE", "DLL", "SYS" };



/* The subtypes, per format. The values overlap between formats, which is why
 * naming one format's values while targeting another is a build error. */
const char *const fmt_word[] = {
	/* Index 0 is the format an object has when nothing identified it, and it
	 * is a target like any other: a rule written for a decrypted payload
	 * applies to exactly that and to no ELF. It read KOF_FMT_ANY here, which
	 * is a different statement - every format - and is spelled where that is
	 * meant. */
	"KOF_FMT_UNKNOWN", "KOF_FMT_ELF", "KOF_FMT_PE",
	"KOF_FMT_MACHO", "KOF_FMT_SCRIPT", "KOF_FMT_TEXT",
	"KOF_FMT_GZIP", "KOF_FMT_DOCOLE", "KOF_FMT_ZIP",
	"KOF_FMT_DOCZIP", "KOF_FMT_TAR", "KOF_FMT_7Z",
	"KOF_FMT_RAR", "KOF_FMT_XZ", "KOF_FMT_RTF",
	"KOF_FMT_PDF"
};


/*
 * One line: how many modules this object touched, and which one the hex pane is
 * lighting up. The rest is one keypress or one click away.
 */
/*
 * The bottom line: what is known about this object on the left, what is under
 * the cursor on the right.
 *
 * They used to be the same space, so making a selection erased the marker
 * counts - the two things a reader compares while choosing bytes. They are
 * different questions with different lifetimes and they get different halves.
 *
 * The pane indicator is gone. It named the thing with the keyboard focus, which
 * the caret in that pane already says, and it was the first thing on the line
 * that nobody needed.
 */
/*
 * The draft, as it stands.
 *
 * Grouped visually by region rather than sorted, because the order markers were
 * chosen in is information - it is the order somebody read the object - and a
 * signature's declarations do not care about order at all.
 */
const char *const maltype_word[] = {
	"Virus", "Trojan", "Rootkit", "Botnet", "Ransom",
	"Miner", "Adware", "Exploit", "Dropper", "Hacktool"
};


/*
 * THE SOURCE TREE, READ ONCE.
 *
 * Every draft question that involves other rules - does this family already
 * exist, which file holds it, do these markers duplicate somebody else's -
 * needs the sources, and reading a tree of them per keystroke is not
 * affordable. Scanned on the first ask and kept; src_forget throws it away when
 * the tree on disk has changed under it.
 */
struct src_ent *g_src;
uint32_t g_n_src;
int g_src_done;




/*
 * One target declaration into a fingerprint.
 *
 * Case folded, because the two sides spell these from different places - the
 * panel holds "Rootkit" and the source says KOF_MALTYPE_ROOTKIT - and folded
 * by addition so the order the declarations appear in does not matter.
 */
uint32_t tgt_mix(uint32_t h, const char *tok)
{
	uint32_t k = 2166136261u;

	for (; *tok; tok++) {
		uint8_t c = (uint8_t)*tok;

		if (c >= 'a' && c <= 'z')
			c = (uint8_t)(c - 'a' + 'A');
		k ^= c;
		k = (uint32_t)((uint64_t)k * 16777619u);
	}
	return h + k;
}



/*
 * One spelling for one pattern, so a hash of it means something.
 *
 * The same marker is written three ways: "2E 2E 5C" in a source file, "2e2e5c"
 * by somebody who prefers lower case, and "2E2E5C" when the panel rebuilds it
 * from a pack that kept the compiled program and not the text. They are the
 * same pattern, so the duplicate check has to see one string, not three.
 */
static void hex_canon(const char *in, char *out, size_t cap)
{
	size_t n = 0;

	for (; *in && n + 1u < cap; in++) {
		if (*in == ' ' || *in == '\t')
			continue;
		out[n++] = (char)toupper((unsigned char)*in);
	}
	out[n] = 0;
}


static uint32_t pat_of(const uint8_t *b, uint32_t n, int hex)
{
	uint32_t h = 2166136261u, i;

	for (i = 0; i < n; i++) {
		h ^= b[i];
		h = (uint32_t)((uint64_t)h * 16777619u);
	}
	h ^= (uint32_t)hex;
	return h ? h : 1u;
}


/*
 * One marker's bytes, as the inside of a C string literal.
 *
 * Only the three that have to be: a quote and a backslash because C would
 * otherwise read the literal differently, and "?" because two of them in a row
 * form a trigraph. Escaping every "?" rather than only the pairs keeps this a
 * property of the byte instead of a property of its neighbour - the pair rule is
 * the kind that is right until somebody edits the string next to it.
 */
void decl_put_literal(FILE *f, const uint8_t *b, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		if (b[i] == '"' || b[i] == '\\' || b[i] == '?')
			fputc('\\', f);
		fputc(b[i], f);
	}
}

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
			if (d->fullword)
				*flags |= KOF_STR_FULLWORD;
		}
	}
	return *pat && *plen && *plen <= 0xffffu;
}

/*
 * Does a range hold bytes found in that region.
 *
 * KOF_SCAN_ALL is the whole object, so a range built on it holds everything - a
 * bit test alone would say a marker found in the code section is not inside the
 * whole file, which is the one answer that cannot be right.
 */
int rng_holds(uint32_t rmask, uint32_t region)
{
	return (rmask & KOF_SCAN_ALL) || (region & KOF_SCAN_ALL) ||
	       (rmask & region);
}

/* What this matcher searches: what it was told, or the narrowest that holds
 * what it has. */
/*
 * Does this condition's expression name matcher `g`.
 *
 * Compared as a number rather than a character, because matcher 1 and matcher
 * 12 share a digit and a substring test would report the wrong one - which
 * would show up as a row listing matchers it does not use, and only on drafts
 * big enough that nobody was checking by hand any more.
 *
 * An empty expression names all of them, which is what it generates.
 */
int cnd_uses(const struct cond *c, uint32_t g)
{
	const char *p = c->expr;

	while (*p) {
		if (*p >= '0' && *p <= '9') {
			char *end;
			unsigned long n;

			n = strtoul(p, &end, 10);
			p = end;

			if (n == (unsigned long)g + 1ul)
				return 1;
			continue;
		}
		p++;
	}
	return 0;
}

/*
 * The declared range that holds this region, made if there is not one.
 *
 * A region met for the first time becomes a range on its own; met again it
 * finds the range it is already in, merged or not. So the list of ranges grows
 * out of where markers were actually found, which is the only place a range
 * has any business coming from.
 */
/*
 * Does this range hold bytes found in that region.
 *
 * KOF_SCAN_ALL is the whole object, so a range built on it holds everything -
 * a bit test alone would have said a marker found in the code section is not
 * inside the whole file, which is the one answer that cannot be right.
 */
/*
 * A mask, spelled with the format's own region words.
 *
 * Built on demand rather than stored: a range is whatever a matcher currently
 * needs, and a name kept beside it would be one more thing to update when a
 * marker is added or taken away.
 */
void rng_name_of(const struct kof_inspect_fmt *fmt, uint32_t mask,
			char *out, size_t cap)
{
	uint32_t b, k;
	size_t at = 0;

	out[0] = 0;
	if (mask & KOF_SCAN_ALL) {
		snprintf(out, cap, "WHOLE-FILE");
		return;
	}
	/*
	 * The symbol halves name themselves.
	 *
	 * The loop below asks the FORMAT what a bit is called, and these two
	 * are not a format's - they mean the same thing for every input that
	 * has a symbol block, which is why kofsig.h defines them rather than
	 * elf.h or pe.h. Left to the loop they would come back unnamed, and an
	 * unnamed mask falls out of the bottom of this function as WHOLE-FILE:
	 * a range that says "search the exports" would have been written into
	 * a rule as "search everything".
	 */
	for (b = 30u; b < 32u && at + 1u < cap; b++) {
		if (!(mask & (1u << b)))
			continue;
		at += (size_t)snprintf(out + at, cap - at, "%s%s",
				       at ? "&" : "",
				       b == 30u ? "SYM_IMP" : "SYM_EXP");
	}
	for (b = 0; b < 30u && at + 1u < cap; b++) {
		const char *w = NULL;

		if (!(mask & (1u << b)))
			continue;
		if (fmt)
			for (k = 0; k < fmt->n_regions; k++)
				if (fmt->regions[k] == (1u << b))
					w = fmt->region_name(1u << b);
		if (!w)
			continue;
		{
			const char *t = strrchr(w, '_');

			/*
			 * "&" and not "|" for the reader.
			 *
			 * The mask is a union of region bits, so the operator
			 * that BUILDS it is or - and the generated source says
			 * so, spelling it "CODE | DATA" in C. This string is
			 * not that: it answers "where does this matcher look",
			 * and the answer is both places.
			 */
			at += (size_t)snprintf(out + at, cap - at, "%s%s",
					       at ? "&" : "", t ? t + 1 : w);
		}
	}
	if (!out[0])
		snprintf(out, cap, "WHOLE-FILE");
}

void rng_ident(const struct kof_inspect_fmt *fmt, uint32_t mask,
		      char *out, size_t cap)
{
	/* Forty, like every other rng_name_of caller. At 24 the display name of
	 * a mask over enough regions was cut before it became an identifier, so
	 * two different masks could have produced one scan_range_ name - two
	 * KOF_TARGET_RANGE declarations of the same identifier, which does not
	 * compile, in a file the tool reported as written. */
	char w[40];
	size_t i;

	/* Named the way bases/ names them - scan_range_data, not DATA. A bare
	 * region word at file scope is a short lowercase-able identifier in a
	 * translation unit that includes engine headers, which is how a draft
	 * ends up colliding with something it never mentioned. */
	/*
	 * Every separator the display name can hold becomes an underscore.
	 *
	 * This turns a string meant for a person into a C identifier, so it has
	 * to survive that string being reworded. It did not: the join moved
	 * from "|" to "&" and this still mapped only "|", so a range over two
	 * regions was declared as scan_range_code&data - a name no compiler
	 * accepts, in a file the tool reported as written.
	 */
	rng_name_of(fmt, mask, w, sizeof w);
	for (i = 0; w[i]; i++) {
		if (!((w[i] >= 'A' && w[i] <= 'Z') ||
		      (w[i] >= 'a' && w[i] <= 'z') ||
		      (w[i] >= '0' && w[i] <= '9')))
			w[i] = '_';
		else if (w[i] >= 'A' && w[i] <= 'Z')
			w[i] = (char)(w[i] - 'A' + 'a');
	}
	snprintf(out, cap, "scan_range_%s", w);
}



/* One identifier out of a comma list, trimmed. Returns where to carry on. */
const char *src_ident(const char *p, char *out, size_t cap)
{
	size_t n = 0;

	while (*p == ' ' || *p == '\t' || *p == ',')
		p++;
	while ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
	       (*p >= '0' && *p <= '9') || *p == '_') {
		if (n + 1 < cap)
			out[n++] = *p;
		p++;
	}
	out[n] = 0;
	return p;
}

/*
 * WHAT A DECLARATION HASHES TO - THE SPELLING, NOT THE BYTES.
 *
 * The source side of the duplicate check reads a .c file and hashes the text
 * between the quotes. So the draft side has to hash the text it WOULD write
 * between those quotes, or the two never agree. They never did for a hex
 * marker: the file says "2E 2E 5C" and the draft hashed the three decoded
 * bytes, so a rule was never reported as a duplicate of itself.
 *
 * And now it cannot even try, because a hex pattern with a wildcard has no
 * decoded bytes at all - which is what turned a wrong answer into a null
 * dereference.
 */
uint32_t decl_pat(const struct decl *d)
{
	char t[DECL_HEXS_CAP];
	size_t n = 0;
	uint32_t k;

	if (!d->hex)
		return pat_of(d->bytes, d->nbytes, 0);
	if (d->hexs[0]) {
		hex_canon(d->hexs, t, sizeof t);
		return pat_of((const uint8_t *)t, (uint32_t)strlen(t), 1);
	}
	/* Declared from a selection: generation writes it as plain pairs, so
	 * that is the spelling this has to hash. */
	for (k = 0; k < d->nbytes && n + 3u < sizeof t; k++)
		n += (size_t)snprintf(t + n, sizeof t - n, "%02X",
				      d->bytes[k]);
	t[n] = 0;
	return pat_of((const uint8_t *)t, (uint32_t)n, 1);
}

/*
 * DROP THE SOURCE INDEX, BECAUSE THE TREE UNDER IT HAS MOVED.
 *
 * The index is a cache of the bases tree, built once on first use and matched
 * against a fired module by the SOURCE LINE each of its detection names sits
 * on. That is a fine key while the sources hold still, and rebuilding is
 * exactly the moment they do not.
 *
 * The bug it exists for: generate a signature, press Rebuild database, and the
 * viewer showed every matcher as find_all. The new database carries the new
 * line numbers, the index still held the old ones, no source matched - so the
 * draft was rebuilt from the DATABASE, which keeps a module's strings and not
 * its logic, and a draft with no logic defaults to find_all. Closing and
 * reopening was fine because that scanned the tree again.
 *
 * Called wherever the tree changes: after a rebuild, and after a save writes a
 * source into it.
 */
void src_forget(void)
{
	free(g_src);
	g_src = NULL;
	g_n_src = 0;
	g_src_done = 0;
}

int src_read(const char *path, struct src_ent *out)
{
	FILE *f = fopen(path, "r");
	char line[1024];
	uint32_t lineno = 0;

	if (!f)
		return 0;
	out->family[0] = 0;
	out->n_line = 0;
	out->pat = 0;
	out->n_pat = 0;
	out->tgt = 0;
	while (fgets(line, sizeof line, f)) {
		char *p, *q;
		size_t n = 0;

		lineno++;
		if (!out->family[0] &&
		    (p = strstr(line, "KOF_TARGET_NAME(")) != NULL &&
		    (p = strchr(p, ',')) != NULL &&
		    (q = strchr(p, '"')) != NULL) {
			for (q++; *q && *q != '"' &&
			     n + 1 < sizeof out->family; q++)
				out->family[n++] = *q;
			out->family[n] = 0;
		}
		if ((strstr(line, "KOF_SCAN_INFECT(") ||
		     strstr(line, "KOF_SCAN_SUSPECT(")) &&
		    out->n_line < SRC_MAX_LINES)
			out->line[out->n_line++] = lineno;
		/* What it targets, as the identifiers the file actually
		 * spells - no table lookup needed on this side, and none that
		 * could drift out of step with the emitter's. */
		{
			static const char *const decl[] = {
				"KOF_TARGET_FORMAT(", "KOF_TARGET_NAME(",
				"KOF_TARGET_ARCH(", "KOF_TARGET_SUBTYPE("
			};
			size_t d;

			for (d = 0; d < sizeof decl / sizeof decl[0]; d++)
				if ((p = strstr(line, decl[d])) != NULL) {
					char w[64];

					src_ident(p + strlen(decl[d]), w,
						  sizeof w);
					if (w[0])
						out->tgt = tgt_mix(out->tgt, w);
				}
			if ((p = strstr(line, "KOF_TARGET_SIZE_MIN(")) != NULL) {
				char w[48];

				snprintf(w, sizeof w, "SIZE_MIN=%llu",
					 (unsigned long long)
					 strtoull(p + 20, NULL, 0));
				out->tgt = tgt_mix(out->tgt, w);
			}
		}
		if ((p = strstr(line, "KOF_DEFINE_STR(")) != NULL ||
		    (p = strstr(line, "KOF_DEFINE_HEXSTR(")) != NULL) {
			int hex = strstr(line, "KOF_DEFINE_HEXSTR(") != NULL;
			char text[512];

			if ((q = strchr(p, '"')) != NULL) {
				size_t m = 0;

				for (q++; *q && *q != '"' &&
				     m + 1 < sizeof text; q++)
					text[m++] = *q;
				text[m] = 0;
				if (hex) {
					char c[sizeof text];

					hex_canon(text, c, sizeof c);
					m = strlen(c);
					memcpy(text, c, m + 1u);
				}
				out->pat += pat_of((const uint8_t *)text,
						   (uint32_t)m, hex);
				out->n_pat++;
			}
		}
	}
	fclose(f);
	return out->family[0] != 0;
}

void src_scan(const char *dir, int depth)
{
	DIR *d = opendir(dir);
	struct dirent *e;

	if (!d || depth > 4)
		return;
	while ((e = readdir(d)) != NULL) {
		char path[512];
		struct stat st;
		size_t n;

		if (e->d_name[0] == '.')
			continue;
		if ((size_t)snprintf(path, sizeof path, "%s/%s", dir,
				     e->d_name) >= sizeof path)
			continue;
		if (stat(path, &st) != 0)
			continue;
		if (S_ISDIR(st.st_mode)) {
			src_scan(path, depth + 1);
			continue;
		}
		n = strlen(e->d_name);
		if (n < 3 || strcmp(e->d_name + n - 2, ".c") != 0)
			continue;
		if (g_n_src >= SRC_MAX)
			break;
		snprintf(g_src[g_n_src].path, sizeof g_src[0].path, "%s", path);
		if (src_read(path, &g_src[g_n_src]))
			g_n_src++;
	}
	closedir(d);
}

uint32_t src_mask_of(const struct kof_inspect_fmt *fmt, const char *e)
{
	uint32_t m = 0, k;

	if (strstr(e, "KOF_SCAN_ALL"))
		return KOF_SCAN_ALL;
	/* Before the format's own words and independently of them: these two
	 * are in kofsig.h, so a rule can name them with no format header at
	 * all, and reopening such a rule must give back the range it declared
	 * rather than an empty mask. */
	if (strstr(e, "KOF_SCAN_SYM_IMP"))
		m |= KOF_SCAN_SYM_IMP;
	if (strstr(e, "KOF_SCAN_SYM_EXP"))
		m |= KOF_SCAN_SYM_EXP;
	if (!fmt)
		return m;
	for (k = 0; k < fmt->n_regions; k++) {
		const char *w = fmt->region_name(fmt->regions[k]);

		if (w && strstr(e, w))
			m |= fmt->regions[k];
	}
	return m;
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

int src_quoted(const char *p, char *out, size_t cap)
{
	const char *q = strchr(p, '"');
	size_t n = 0;

	if (!q)
		return 0;
	for (q++; *q && *q != '"'; q++) {
		if (*q == '\\' &&
		    (q[1] == '"' || q[1] == '\\' || q[1] == '?'))
			q++;
		if (n + 1 < cap)
			out[n++] = *q;
	}
	out[n] = 0;
	return *q == '"';
}

uint32_t src_str_idx(struct sname *tab, uint32_t n, const char *id)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (!strcmp(tab[i].id, id))
			return tab[i].idx;
	return 0xffffffffu;
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
int decl_text_editable(const struct decl *d)
{
	uint32_t i;

	if (d->hex)
		return 1;
	for (i = 0; i < d->nbytes; i++)
		if (d->bytes[i] < 0x20 || d->bytes[i] >= 0x7f)
			return 0;
	return 1;
}

/*
 * Take one matcher out of a condition's expression.
 *
 * Rewritten from the ids that are left rather than edited in place, because
 * removing "2" from "1&2|3" by deleting characters leaves "1&|3" - and an
 * expression that has to be repaired by hand after every removal is one nobody
 * will use the buttons on. Anything the author typed that is not a plain list -
 * parentheses, a mix of & and | - is preserved only in so far as the join it
 * was written with; that is the price of a list and a text box being the same
 * field.
 */
void cnd_drop_matcher(struct cond *c, uint32_t g)
{
	char out[64];
	size_t at = 0;
	const char *p = c->expr;
	int first = 1;

	while (*p) {
		if (*p >= '0' && *p <= '9') {
			char *end;
			unsigned long n;

			n = strtoul(p, &end, 10);
			p = end;

			if (n == (unsigned long)g + 1ul)
				continue;
			at += (size_t)snprintf(out + at, sizeof out - at,
					       "%s%lu", first ? "" : (c->op
					       ? "|" : "&"), n);
			first = 0;
			continue;
		}
		p++;
	}
	out[at] = 0;
	snprintf(c->expr, sizeof c->expr, "%s", out);
}


/*
 * Write the draft out as a signature source.
 *
 * One KOF_TARGET_RANGE per distinct region, one search call per range, and the
 * calls joined with && - which is the shape every hand-written signature in
 * bases/ already has. The range comes from where each marker was found, so the
 * one thing a hand-written signature usually gets wrong is the one thing this
 * cannot get wrong.
 *
 * Never into bases/. That directory is the content that ships, and a draft is
 * not content until somebody has looked at it.
 */
/*
 * The draft, as one number.
 *
 * Compared against the number at the last save to answer "has this changed" -
 * the same trick the frame repaint uses, and for the same reason: a flag set by
 * hand at every place that mutates the draft is a flag that gets missed at the
 * next place, and the one that gets missed is the one that loses somebody's
 * work.
 */
/*
 * The status line's two voices.
 *
 * Red is for something that went wrong and stopped what was asked for: a
 * required field absent, a file that could not be written. Yellow is for
 * something worth knowing that stopped nothing - a rule already in the tree
 * carrying these markers, a draft that came back only partly read, a string
 * that is not in this object.
 *
 * They shared one colour, and the case that showed it up is "same markers as
 * HCRootkit.c": it appears AFTER a Save As that worked, because the file just
 * written now has a sibling with the same patterns. Painted red it reads as
 * the save having failed.
 */
void say_err(struct kof_editor *e, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(e->dr.warn, sizeof e->dr.warn, fmt, ap);
	va_end(ap);
	e->dr.warn_bad = 1;
}

void say_note(struct kof_editor *e, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(e->dr.warn, sizeof e->dr.warn, fmt, ap);
	va_end(ap);
	e->dr.warn_bad = 0;
}

/* Is this sample already in the rule's history. */
int meta_has_sample(struct kof_editor *e)
{
	const char *w = draft_sample(e);
	uint32_t i;

	for (i = 0; i < *e->n_sample; i++)
		if (!strcmp(e->sample[i], w))
			return 1;
	return 0;
}

/*
 * Why the draft cannot be generated yet, or NULL when it can.
 *
 * Checked as a whole rather than at the button, because the answer is also the
 * thing to say: a greyed control with no reason beside it is a control people
 * click repeatedly. The order is the order the work is done in, so the message
 * names the next thing to do rather than the last thing missing.
 */
/* The vocabulary a family or variant name is allowed to be spelled in. Empty is
 * not this function's business - a name that has not been typed yet is a
 * different message from one typed wrongly. */
int name_chars_ok(const char *s)
{
	for (; *s; s++)
		if (!isalnum((unsigned char)*s) && *s != '.' && *s != '-' &&
		    *s != '_')
			return 0;
	return 1;
}

/* Same question AND same answer to it: a copy, whatever the two are spelled as. */
int grp_same_call(struct kof_editor *e, uint32_t a, uint32_t b)
{
	return grp_same_set(e, a, b) &&
	       grp_thresh_eff(e, a) == grp_thresh_eff(e, b);
}

/*
 * The lowest numbered matcher asking the same thing as this one - the one whose
 * number names the shared variable, so the name does not move when a later
 * matcher is removed.
 */
uint32_t grp_lead(struct kof_editor *e, uint32_t g)
{
	uint32_t i;

	for (i = 0; i < g; i++)
		if (grp_same_set(e, i, g))
			return i;
	return g;
}

/* The strict question, for every caller that is describing the draft to a
 * reader rather than deciding whether one particular button works. */
const char *draft_missing(struct kof_editor *e)
{
	return draft_missing_of(e, 0);
}


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

	d->at = KOF_BROKEN;
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
	 * THE SAME CALL THE MARKER LIST MAKES.
	 *
	 * This used to be its own walk - two of them, one for the file and one
	 * for the symbol halves - with its own rule for which occurrence to
	 * report. kof_touch_object had a different rule, so the two lists named
	 * different offsets in different regions for one marker on one object.
	 * The rule is kof_locate_str's now and this only presents what it
	 * returns; see the note above it in kofinspect.h.
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



uint32_t grp_mask(struct kof_editor *e, uint32_t g)
{
	uint32_t i, need = 0;

	if (e->dr.grp[g].mask)
		return e->dr.grp[g].mask;
	for (i = 0; i < e->dr.n_decl; i++)
		if (e->dr.decl[i].grp & (1u << g))
			need |= e->dr.decl[i].mask;
	return need ? need : KOF_SCAN_ALL;
}

uint32_t grp_count(struct kof_editor *e, uint32_t g)
{
	uint32_t i, n = 0;

	for (i = 0; i < e->dr.n_decl; i++)
		n += (e->dr.decl[i].grp >> g) & 1u;
	return n;
}


int grp_has_range(struct kof_editor *e, uint32_t g)
{
	return grp_count(e, g) != 0 || e->dr.grp[g].mask != 0;
}

void grp_add(struct kof_editor *e)
{
	if (e->dr.n_grp >= MAX_GROUP)
		return;
	memset(&e->dr.grp[e->dr.n_grp], 0, sizeof e->dr.grp[0]);
	e->dr.cur_grp = e->dr.n_grp++;
	e->dr.warn[0] = 0;
}

/*
 * What a condition is called on screen: "1)" at the top level, "1-2)" for the
 * second thing nested inside the first.
 *
 * Numbered by position among its siblings rather than by its index in the
 * array, because the array is creation order and the screen is reading order.
 * A child called "2)" because it happened to be added second read as a sibling
 * of "1)" no matter how far it was indented.
 */
void cnd_label(struct kof_editor *e, uint32_t i, char *out, size_t cap)
{
	uint32_t k, mine = 0, pos = 0;

	if (e->dr.cnd[i].parent < 0) {
		for (k = 0; k < i; k++)
			pos += e->dr.cnd[k].parent < 0;
		snprintf(out, cap, "%u.", pos + 1u);
		return;
	}
	for (k = 0; k < e->dr.n_cnd; k++) {
		if (e->dr.cnd[k].parent >= 0)
			continue;
		pos++;
		if (k == (uint32_t)e->dr.cnd[i].parent)
			break;
	}
	for (k = 0; k < i; k++)
		mine += e->dr.cnd[k].parent == e->dr.cnd[i].parent;
	snprintf(out, cap, "%u.%u.", pos, mine + 1u);
}

/*
 * The expression a plain list of ids would produce, for comparing against what
 * is actually stored.
 *
 * The id row can add, remove and re-join, which covers every expression that is
 * a list. Anything else - a parenthesis, a mix of & and | - was typed, and
 * rendering that as a list would show a different condition from the one that
 * will be generated. So when the two disagree, the typed text is what is shown.
 */
void cnd_canon(struct kof_editor *e, uint32_t g, char *out, size_t cap)
{
	const struct cond *c = &e->dr.cnd[g];
	size_t at = 0;
	uint32_t m;

	out[0] = 0;
	for (m = 0; m < e->dr.n_grp; m++) {
		if (!cnd_uses(c, m))
			continue;
		at += (size_t)snprintf(out + at, cap - at, "%s%u",
				       at ? (c->op ? "|" : "&") : "", m + 1u);
	}
}

/* Is another condition still to come at this one's level, under this parent.
 * The connector below it is drawn or not drawn on the answer. */
int cnd_more_siblings(struct kof_editor *e, uint32_t i)
{
	uint32_t k;

	for (k = i + 1u; k < e->dr.n_cnd; k++)
		if (e->dr.cnd[k].parent == e->dr.cnd[i].parent)
			return 1;
	return 0;
}

/* How deep a condition sits. Two levels is the whole of it: a third would be a
 * tree to navigate, and the logic it would express is already sayable in one
 * expression box. */
int cnd_depth(struct kof_editor *e, uint32_t i)
{
	return e->dr.cnd[i].parent >= 0 ? 1 : 0;
}

/*
 * Take a matcher out, and put every reference to it right.
 *
 * The one thing on this panel that could be added and not removed. Removing it
 * is not just a shift: the conditions name matchers by number, so every
 * expression has to be renumbered or a condition that said "2" starts meaning
 * the matcher that used to be 3 - the kind of change nothing on screen shows
 * and no one would look for.
 */
void grp_remove(struct kof_editor *e, uint32_t g)
{
	uint32_t i, k;

	if (g >= e->dr.n_grp)
		return;
	for (i = 0; i < e->dr.n_decl; i++) {
		uint32_t lo = e->dr.decl[i].grp & ((1u << g) - 1u);
		uint32_t hi = e->dr.decl[i].grp >> (g + 1u);

		/* Its bit goes and every matcher above it moves down one -
		 * the same renumbering the matcher array itself gets. */
		e->dr.decl[i].grp = lo | (hi << g);
	}
	for (k = 0; k < e->dr.n_cnd; k++) {
		struct cond *c = &e->dr.cnd[k];
		char out[64];
		size_t at = 0;
		const char *p = c->expr;
		int first = 1;

		out[0] = 0;
		while (*p) {
			if (*p >= '0' && *p <= '9') {
				char *end;
				unsigned long n;

				n = strtoul(p, &end, 10);
				p = end;

				if (n == (unsigned long)g + 1ul)
					continue;
				if (n > (unsigned long)g + 1ul)
					n--;
				at += (size_t)snprintf(out + at,
						       sizeof out - at, "%s%lu",
						       first ? "" : (c->op
						       ? "|" : "&"), n);
				first = 0;
				continue;
			}
			p++;
		}
		out[at] = 0;
		snprintf(c->expr, sizeof c->expr, "%s", out);
	}
	memmove(&e->dr.grp[g], &e->dr.grp[g + 1u],
		(e->dr.n_grp - g - 1u) * sizeof e->dr.grp[0]);
	e->dr.n_grp--;
	if (e->dr.cur_grp >= e->dr.n_grp && e->dr.n_grp)
		e->dr.cur_grp = e->dr.n_grp - 1u;
}

void cnd_add(struct kof_editor *e, int nested)
{
	struct cond *c;

	if (e->dr.n_cnd >= MAX_GROUP)
		return;
	c = &e->dr.cnd[e->dr.n_cnd];
	memset(c, 0, sizeof *c);
	c->parent = nested && e->dr.n_cnd ? (int)e->dr.cur_cnd : -1;
	e->dr.cur_cnd = e->dr.n_cnd++;
	e->dr.warn[0] = 0;
}

/*
 * Drop a condition.
 *
 * Its children are lifted to the top rather than deleted with it: they are
 * separate conclusions that happened to share a gate, and taking the gate away
 * is a reason to re-read them, not a reason to lose them.
 */
void cnd_remove(struct kof_editor *e, uint32_t i)
{
	uint32_t k;

	if (i >= e->dr.n_cnd)
		return;
	for (k = 0; k < e->dr.n_cnd; k++)
		if (e->dr.cnd[k].parent == (int)i)
			e->dr.cnd[k].parent = -1;
	memmove(&e->dr.cnd[i], &e->dr.cnd[i + 1u],
		(e->dr.n_cnd - i - 1u) * sizeof e->dr.cnd[0]);
	e->dr.n_cnd--;
	for (k = 0; k < e->dr.n_cnd; k++)
		if (e->dr.cnd[k].parent > (int)i)
			e->dr.cnd[k].parent--;
	if (e->dr.cur_cnd >= e->dr.n_cnd && e->dr.n_cnd)
		e->dr.cur_cnd = e->dr.n_cnd - 1u;
}

uint32_t cnd_children(struct kof_editor *e, uint32_t i)
{
	uint32_t k, n = 0;

	for (k = 0; k < e->dr.n_cnd; k++)
		n += e->dr.cnd[k].parent == (int)i;
	return n;
}


/*
 * TWO MATCHERS, ONE SCAN.
 *
 * "at least three of these five, otherwise at least two" is one question asked
 * once, not two questions. Written as two matchers it used to compile to two
 * kof_find_str_multi calls over the same markers in the same region - the same
 * work twice, and the second one only to compare its answer against a smaller
 * number.
 *
 * So matchers that ASK THE SAME THING - same kind of call, same range, same
 * markers - share one call in the generated body, and each keeps its own
 * threshold to compare against it:
 *
 *     uint32_t m1 = kof_find_str_multi(scan_range_code, s0, s1, s2, s3, s4);
 *
 *     if (m1 >= 3)
 *             KOF_SCAN_INFECT("Strong");
 *     else if (m1 >= 2)
 *             KOF_SCAN_SUSPECT("Weak");
 *
 * Only find_multi shares. all and any carry no threshold, so two of them that
 * asked the same thing would be the same matcher written twice - which is a
 * mistake the panel refuses rather than a shape to optimise.
 */
/*
 * WHAT A MATCHER'S THRESHOLD REALLY IS.
 *
 * The three kinds are three spellings of one comparison against a count:
 * find_any is "at least one", find_all is "all of them", find_multi says the
 * number itself. Measured rather than argued - a rule written each way over the
 * same four markers agrees on every sample, including the one where none are
 * present.
 *
 * What differs is the WORK, not the answer, and that is the whole constraint on
 * folding them together: kofsig.h folds any to `a || b || c` and all to
 * `a && b && c`, so they stop at the first marker that settles the question,
 * while multi has to look for all of them to produce a count. Turning an any
 * into a count would therefore make a rule slower - unless the count is already
 * being computed for something else, which is exactly and only when this folds.
 */
uint32_t grp_thresh_eff(struct kof_editor *e, uint32_t g)
{
	if (e->dr.grp[g].rule == 1)
		return 1u;                      /* any: at least one */
	if (e->dr.grp[g].rule == 2)
		return e->dr.grp[g].thresh;
	return grp_count(e, g);                 /* all: every one of them */
}

/* The same question - same range, same markers - whatever it is spelled as. */
int grp_same_set(struct kof_editor *e, uint32_t a, uint32_t b)
{
	uint32_t i;

	if (a == b)
		return 1;
	if (grp_mask(e, a) != grp_mask(e, b))
		return 0;
	/* The same markers, and no others. Order is not part of the question:
	 * a matcher is a set. */
	for (i = 0; i < e->dr.n_decl; i++) {
		int in_a = (e->dr.decl[i].grp >> a) & 1u;
		int in_b = (e->dr.decl[i].grp >> b) & 1u;

		if (in_a != in_b)
			return 0;
	}
	return 1;
}



/* Does this matcher's call get a variable: multi, and asked more than once. */
int grp_shared(struct kof_editor *e, uint32_t g)
{
	uint32_t i, n = 0, multi = 0;

	for (i = 0; i < e->dr.n_grp; i++) {
		if (!grp_same_set(e, i, g))
			continue;
		n++;
		multi += e->dr.grp[i].rule == 2;
	}
	/*
	 * At least two asking it, and at least one of them a find_multi - that
	 * second half is what keeps the fold honest. A group of any/all
	 * matchers alone short circuits today; giving them a count would be
	 * work they currently avoid. Once ANY of them needs the number, every
	 * other one in the group gets to compare against it for free.
	 */
	return n > 1u && multi > 0u;
}



uint32_t draft_hash(struct kof_editor *e)
{
	uint32_t h = 2166136261u, i, j;

	#define MIX(b) do { h ^= (uint32_t)((uint64_t)(b) & 0xffffffffu); \
			    h = (uint32_t)((uint64_t)h * 16777619u); } while (0)
	for (i = 0; e->dr.family[i]; i++)
		MIX((uint8_t)e->dr.family[i]);
	for (i = 0; e->dr.note[i]; i++)
		MIX((uint8_t)e->dr.note[i]);
	MIX(e->dr.maltype);
	for (i = 0; i < e->dr.n_rng_add; i++)
		MIX(e->dr.rng_add[i]);
	for (i = 0; i < (uint32_t)OPT_COUNT; i++) {
		MIX(e->dr.opt_on[i]);
		MIX(e->dr.opt_val[i]);
		MIX(e->dr.opt_val[i] >> 32);
	}
	for (i = 0; i < e->dr.n_decl; i++) {
		const struct decl *d = &e->dr.decl[i];

		MIX(d->len); MIX(d->hex); MIX(d->mask);
		MIX(d->grp); MIX(d->fullword); MIX(d->icase);
		/* The spelling when there is one - it is what would be
		 * written, and `bytes` may be NULL beside it. */
		if (d->hexs[0])
			for (j = 0; d->hexs[j]; j++)
				MIX((uint8_t)d->hexs[j]);
		else
			for (j = 0; j < d->nbytes; j++)
				MIX(d->bytes[j]);
	}
	for (i = 0; i < e->dr.n_grp; i++) {
		MIX(e->dr.grp[i].rule); MIX(e->dr.grp[i].thresh); MIX(e->dr.grp[i].mask);
		for (j = 0; e->dr.grp[i].note[j]; j++)
			MIX((uint8_t)e->dr.grp[i].note[j]);
	}
	for (i = 0; i < e->dr.n_cnd; i++) {
		const struct cond *c = &e->dr.cnd[i];

		MIX(c->level); MIX(c->var_kind); MIX(c->parent);
		MIX(c->op); MIX(c->join);
		for (j = 0; c->expr[j]; j++)
			MIX((uint8_t)c->expr[j]);
		for (j = 0; c->variant[j]; j++)
			MIX((uint8_t)c->variant[j]);
	}
	#undef MIX
	return h;
}

/* The sample in front of the reader, as the metadata block names it. */
/*
 * The sample this rule was tested against: THE FILE, not the object.
 *
 * It used to name the selected object, and inside a container that is the
 * child's name - which for an unpacked payload is its index, so a rule drafted
 * against something UPX had just produced recorded "Test sample: 0".
 *
 * The file is the right answer even when the draft was written against a child,
 * because the line exists so that somebody can reproduce this: what they need
 * is the thing to feed the engine, and the engine reaches the child by itself.
 * Which child it was is not lost either - it is what the rule's target format
 * and its ranges say.
 */
const char *draft_sample(struct kof_editor *e)
{
	const char *n = (e->path && e->path[0]) ? e->path : (&e->obj[e->cur])->name;
	const char *s = strrchr(n, '/');

	return s ? s + 1 : n;
}


/*
 * HAS THE READER CHANGED ANYTHING.
 *
 * Narrower than draft_dirty, and the two are not interchangeable. draft_dirty
 * also answers yes when the draft is fine but this sample is not yet recorded in
 * it - which is a reason to offer Save, and NOT a reason to say there is work to
 * lose. Opening a file loads the signature that matched it, so on any detected
 * sample draft_dirty is true before the reader has touched a key, and using it to
 * guard "move on" made Next file dead on exactly the files somebody is stepping
 * through.
 */
int draft_edited(struct kof_editor *e)
{
	return draft_hash(e) != e->dr.saved_hash;
}

int draft_dirty(struct kof_editor *e)
{
	/*
	 * A RULE TESTED AGAINST A NEW SAMPLE HAS CHANGED.
	 *
	 * Not its logic - not one byte of what it matches - but the file on
	 * disk does not yet record that this rule was checked against this
	 * sample, and that is the fact the metadata block exists to keep. Left
	 * out, Save stayed greyed on exactly the case worth saving: open a rule,
	 * confirm it fires on a second sample, and there was no way to write
	 * that down.
	 */
	/*
	 * An EMPTY draft is not dirty, whatever the metadata says.
	 *
	 * The test below asks whether this sample has been recorded, and on a
	 * draft with nothing in it the answer is no and always will be - there
	 * is nothing to record it against. Read as dirty it made a viewer that
	 * had written nothing refuse to move on, which is how this was found.
	 */
	if (e->dr.n_decl && !meta_has_sample(e))
		return 1;
	return draft_hash(e) != e->dr.saved_hash;
}









/*
 * The file a fired module was written in - ASKED, NOT DERIVED.
 *
 * The database carries it now (kof_db_source), because the build knew it and
 * used to discard it. What stood here re-derived it: scan the bases tree once,
 * read every source, and match a module to a file on the LINE NUMBERS its
 * detection names sit on.
 *
 * That key is correct exactly while the sources hold still, and it was cached
 * for the life of the process. So pressing Rebuild database - the one action
 * whose whole purpose is that the sources changed - left an index describing
 * the tree as it had been: nothing matched, the draft fell back to the
 * database, and because a database keeps a module's strings and not its logic
 * every rule redrew as a single find_all.
 *
 * A duplicate of something the engine can answer is not just more code. It is a
 * second thing to keep true, and it goes false quietly.
 */
/*
 * Build the index of the bases tree, once, for the ONE question that still
 * needs it: does some existing source already declare this exact set of
 * markers. That is a content question over the whole tree, and no single scan
 * result answers it - unlike "which file was this module written in", which the
 * database now carries and which used to be answered from here by matching line
 * numbers. See src_of.
 */
void src_index(struct kof_editor *e)
{
	if (g_src_done)
		return;
	g_src_done = 1;
	g_src = calloc(SRC_MAX, sizeof *g_src);
	if (g_src)
		src_scan(e->basedir, 0);
}

const char *src_of(struct kof_editor *e, const struct kof_touch *t)
{
	static char path[KOF_DUMP_PATH_ROOM];
	const char *rel;

	if (!e->eng || !t->mod)
		return NULL;
	rel = kof_db_source(e->eng, t->mod);
	if (!rel || !rel[0])
		return NULL;
	/*
	 * The database records the path INSIDE the tree; where the tree is, is
	 * this viewer's own --bases. An absolute path in the database would be a
	 * fact about the machine that built it.
	 */
	if ((size_t)snprintf(path, sizeof path, "%s/%s",
			     e->basedir[0] ? e->basedir : ".", rel) >= sizeof path)
		return NULL;
	return path;
}

/*
 * A signature in the tree that searches for the same thing as this draft.
 *
 * Order independent, and independent of the names and the comments, because a
 * duplicate rarely looks like one: the usual way to make one is to write the
 * same markers again from the same sample under a slightly different family.
 * Its own file does not count as a duplicate of itself.
 *
 * Returns the path, or NULL. Also reports a near miss - the same patterns bar
 * one - because that is a variant that should have been a branch of the
 * existing rule rather than a second rule.
 */
/*
 * The same fingerprint for the draft, spelled from the same words the file
 * would be written with - so a rule saved and then read back matches itself.
 */
uint32_t draft_tgt(struct kof_editor *e)
{
	struct object *ob = &e->obj[e->dr.n_decl && e->dr.decl[0].obj < (*e->n_obj)
				    ? e->dr.decl[0].obj : 0];
	uint8_t fm = ob->ctx.format;
	uint32_t h = 0;
	char w[64];

	h = tgt_mix(h, (ob->fmt && fm < FMT_WORD_N) ? fmt_word[fm]
						    : "KOF_FMT_ANY");
	snprintf(w, sizeof w, "KOF_MALTYPE_%s",
		 e->dr.maltype < MALTYPE_N ? maltype_word[e->dr.maltype] : "VIRUS");
	h = tgt_mix(h, w);
	if (e->dr.opt_on[OPT_ARCH]) {
		snprintf(w, sizeof w, "KOF_ARCH_%s",
			 arch_word[e->dr.opt_val[OPT_ARCH] < ARCH_N
				   ? e->dr.opt_val[OPT_ARCH] : 0].word);
		h = tgt_mix(h, w);
	}
	if (e->dr.opt_on[OPT_SUBTYPE]) {
		uint64_t k = e->dr.opt_val[OPT_SUBTYPE];

		if (fm == KOF_FMT_ELF)
			snprintf(w, sizeof w, "KOF_ELF_%s",
				 elf_sub[k < elf_sub_n
					 ? k : 0]);
		else if (fm == KOF_FMT_PE)
			snprintf(w, sizeof w, "KOF_PE_%s",
				 pe_sub[k < pe_sub_n
					? k : 0]);
		else
			w[0] = 0;
		if (w[0])
			h = tgt_mix(h, w);
	}
	if (e->dr.opt_on[OPT_SIZE_MIN]) {
		snprintf(w, sizeof w, "SIZE_MIN=%llu",
			 (unsigned long long)e->dr.opt_val[OPT_SIZE_MIN]);
		h = tgt_mix(h, w);
	}
	return h;
}

const char *draft_dup(struct kof_editor *e, int *near)
{
	uint32_t pat = 0, n = 0, i, tgt;

	if (near)
		*near = 0;
	if (!e->dr.n_decl)
		return NULL;
	src_index(e);
	if (!g_src)
		return NULL;
	tgt = draft_tgt(e);
	for (i = 0; i < e->dr.n_decl; i++) {
		pat += decl_pat(&e->dr.decl[i]);
		n++;
	}
	for (i = 0; i < g_n_src; i++) {
		if (e->dr.gen_path[0] && !strcmp(g_src[i].path, e->dr.gen_path))
			continue;
		if (!g_src[i].n_pat)
			continue;
		/* Same bytes AND the same thing to run them against. Same
		 * bytes aimed at another format, another subtype or another
		 * malware type is a sibling rule, not a copy of this one. */
		if (g_src[i].tgt != tgt)
			continue;
		if (g_src[i].pat == pat && g_src[i].n_pat == n)
			return g_src[i].path;
	}
	/*
	 * Nothing identical. A file with all but one of these patterns is worth
	 * naming too, and is found by dropping each of ours in turn - cheap at
	 * these sizes, and the answer a researcher wants before adding a rule
	 * that mostly repeats one.
	 */
	for (i = 0; i < g_n_src && near; i++) {
		uint32_t k;

		if (e->dr.gen_path[0] && !strcmp(g_src[i].path, e->dr.gen_path))
			continue;
		if (g_src[i].n_pat + 1u != n && g_src[i].n_pat != n + 1u)
			continue;
		for (k = 0; k < e->dr.n_decl; k++) {
			uint32_t less = pat - decl_pat(&e->dr.decl[k]);

			if (g_src[i].pat == less &&
			    g_src[i].n_pat + 1u == n) {
				*near = 1;
				return g_src[i].path;
			}
		}
	}
	return NULL;
}


/*
 * What stops this draft being written, or NULL. `as_new` asks about Save As,
 * which is allowed in one case Save is not - see the note on (*e->foreign) below.
 */
const char *draft_missing_of(struct kof_editor *e, int as_new)
{
	uint32_t i;

	/*
	 * LOGIC THIS PANEL DOES NOT CARRY STOPS SAVE, AND ONLY SAVE.
	 *
	 * First, before anything about the draft's completeness, because it is
	 * not a complaint about the draft: the draft is fine and is a truthful
	 * view of the modelled part. It is a statement about the FILE - it
	 * holds more than this can write back, so writing it back would delete
	 * the rest.
	 *
	 * SAVE AS is a different act and used to be refused with it, which was
	 * wrong. Overwriting destroys the unmodelled logic; writing a NEW file
	 * destroys nothing, and deriving a rule from the part that is modelled
	 * is a thing a researcher does on purpose. The original stays exactly
	 * as it is, one directory entry away, to compare against.
	 *
	 * So this is asked with `as_new`, and the caller says which act it is.
	 */
	if ((*e->foreign) && !as_new)
		return "Custom logic - Save As to derive a new rule from it";
	if (!e->dr.family[0])
		return "Name the family";
	/*
	 * A NAME, AND ONLY THE CHARACTERS A NAME HAS.
	 *
	 * The family and every custom variant become part of a detection string
	 * - "ELF-x64/Botnet:Mirai-0i0bq" - and the variant is also written into
	 * the generated C as a quoted literal. Written straight, a quote in it
	 * ends that literal and everything after it is code the build compiles:
	 *
	 *     KOF_SCAN_INFECT("x", 0); system("id"); //");
	 *
	 * Refused here rather than escaped, because escaping would preserve a
	 * name nobody can have meant. ksigbuilder refuses the same set for the
	 * same reason, so a file written by hand is stopped too - this is the
	 * early, legible half of that check, not the whole of it.
	 */
	if (!name_chars_ok(e->dr.family))
		return "Family: letters, digits, . - _ only";
	for (i = 0; i < e->dr.n_cnd; i++)
		if (e->dr.cnd[i].var_kind == 2 && e->dr.cnd[i].variant[0] &&
		    !name_chars_ok(e->dr.cnd[i].variant))
			return "Variant: letters, digits, . - _ only";
	if (!e->dr.n_decl)
		return "Declare a string";
	if (!e->dr.n_grp)
		return "Add a matcher";
	/*
	 * TWO MATCHERS THAT ASK THE SAME THING, INCLUDING THE THRESHOLD.
	 *
	 * Sharing a call is what makes two thresholds over one marker set
	 * cheap, and it is exactly what makes an accidental copy invisible:
	 * a duplicate no longer costs a second scan, so nothing about the
	 * generated code would look wrong. It is still a matcher that decides
	 * nothing the other one has not already decided, and the condition
	 * naming it is dead weight - so it is refused here rather than found
	 * later by wondering which of the two a branch meant.
	 *
	 * The threshold is part of the comparison on purpose: differing there
	 * is the whole point of the shape, and only matchers that agree on it
	 * too are copies.
	 *
	 * Compared as questions rather than as spellings - see grp_thresh_eff.
	 * find_any over a set and find_multi >= 1 over the same set are one
	 * matcher written two ways, and the generated body makes that plain by
	 * emitting "m1 >= 1" twice: the second branch is unreachable. The old
	 * test compared the rule kinds first and so let that pair through.
	 */
	for (i = 0; i < e->dr.n_grp; i++) {
		uint32_t j;

		for (j = i + 1u; j < e->dr.n_grp; j++)
			if (grp_same_call(e, i, j))
				return "Two matchers ask the same thing - "
				       "remove one or change a threshold";
	}
	for (i = 0; i < e->dr.n_grp; i++)
		if (!grp_count(e, i))
			return "Every matcher needs a string";
	/*
	 * What one call can hold.
	 *
	 * KOF_FS_FOLD stops at sixteen names and the cap shows up as an
	 * undefined KOF_FS_17 - a compile error, which is the right place for
	 * it in a hand written module and the wrong place for one this tool
	 * generated. Refused here so the failure lands where the decision was
	 * made rather than in a build log.
	 */
	for (i = 0; i < e->dr.n_grp; i++)
		if (grp_count(e, i) > 16u)
			return "A matcher holds at most 16 markers - "
			       "split it in two";
	if (!e->dr.n_cnd)
		return "Add a condition";
	for (i = 0; i < e->dr.n_cnd; i++) {
		/*
		 * A condition with children and no matchers of its own is a
		 * grouping, not an omission.
		 *
		 * It is how a shape like "(1) or (2 and 3)" gets written
		 * without a free text expression: the outer one tests nothing
		 * and exists to hold the two that do. Only a branch that has to
		 * decide something needs something to decide it on.
		 */
		if (!e->dr.cnd[i].expr[0] && !cnd_children(e, i))
			return "Every condition needs a matcher";
	}

	/*
	 * Nothing declared and then left out.
	 *
	 * A string in no matcher still gets a KOF_DEFINE_STR and is never
	 * searched for; a matcher no condition names is never written into the
	 * body at all, which quietly takes its strings with it. Both compile,
	 * both look finished on screen, and neither does what the panel appears
	 * to say - so they are caught here rather than found later by wondering
	 * why a marker never fires.
	 *
	 * What is deliberately NOT checked is a matcher named more than once. It
	 * reads like a redundancy and sometimes is, but "(M1|M2) & (M1|M3)" is a
	 * real shape - the same search meaning different things on two branches
	 * - and refusing it would cost more than the tidiness is worth.
	 */
	{
		static char why[64];

		for (i = 0; i < e->dr.n_decl; i++)
			if (e->dr.decl[i].grp == 0) {
				snprintf(why, sizeof why,
					 "string %u is in no matcher", i + 1u);
				return why;
			}
		for (i = 0; i < e->dr.n_grp; i++) {
			uint32_t k, used = 0;

			for (k = 0; k < e->dr.n_cnd; k++)
				used += (uint32_t)cnd_uses(&e->dr.cnd[k], i);
			if (!used) {
				snprintf(why, sizeof why,
					 "matcher %u is in no condition",
					 i + 1u);
				return why;
			}
		}
		/*
		 * A range nothing searches.
		 *
		 * Same rule as the two above and for the same reason: a
		 * KOF_TARGET_RANGE no kof_find_str names compiles, reads as
		 * part of the signature, and does nothing.
		 */
		for (i = 0; i < e->dr.n_rng_add; i++) {
			uint32_t k, used = 0;
			char nm[24];

			for (k = 0; k < e->dr.n_grp; k++)
				used += (uint32_t)(grp_has_range(e, k) &&
						   grp_mask(e, k) ==
						   e->dr.rng_add[i]);
			if (used)
				continue;
			rng_name_of((&e->obj[e->cur])->fmt, e->dr.rng_add[i], nm,
				    sizeof nm);
			snprintf(why, sizeof why,
				 "scan range %.12s is in no matcher", nm);
			return why;
		}
	}
	return NULL;
}

/*
 * Give every matcher searching `was` the mask `now`.
 *
 * By range rather than by matcher because that is what the summary row edits:
 * the row lists distinct ranges, and two matchers sharing one are two names for
 * the same decision - changing what DATA covers changes it for both.
 */
void rng_retarget(struct kof_editor *e, uint32_t was, uint32_t now)
{
	uint32_t g, i, w = 0;

	for (g = 0; g < e->dr.n_grp; g++) {
		if (!grp_has_range(e, g) || grp_mask(e, g) != was)
			continue;
		e->dr.grp[g].mask = now;
	}
	/*
	 * AND THE DECLARED LIST, which is the half this used to miss.
	 *
	 * A range put there by [+ Scan range] lives in rng_add until a matcher
	 * is given it, and this function only ever walked the matchers. Two
	 * things went wrong from that. Extending a range NO matcher had yet did
	 * nothing at all - the loop above matched nothing - so a range could
	 * only be widened after it had been handed to a matcher. And extending
	 * one that a matcher DID have moved the matcher to the wider mask while
	 * leaving the old narrow mask sitting in rng_add, where rng_all then
	 * reported it as a second, unused range: a region that appeared out of
	 * nowhere the moment you extended.
	 *
	 * Rewritten with a dedup, because the wider mask may already be
	 * declared - two entries for one mask would draw the same range twice.
	 */
	for (i = 0; i < e->dr.n_rng_add; i++) {
		uint32_t m = e->dr.rng_add[i] == was ? now : e->dr.rng_add[i];
		uint32_t k;
		int dup = 0;

		for (k = 0; k < w; k++)
			dup |= e->dr.rng_add[k] == m;
		if (!dup)
			e->dr.rng_add[w++] = m;
	}
	e->dr.n_rng_add = w;
	/*
	 * THE STRINGS ARE LEFT ALONE.
	 *
	 * This used to rewrite every marker's own region to the matcher's new
	 * range. That is a different fact: a string's region is where it WAS
	 * FOUND and the matcher's range is where it will be LOOKED FOR - the
	 * distinction the panel spends two column headings on. Widening a
	 * matcher to CODE&DATA does not move a marker that was found in CODE,
	 * and saying it does makes the row claim a provenance the search never
	 * established. Eligibility still holds: rng_holds is an overlap, so a
	 * CODE marker remains valid for a CODE&DATA matcher.
	 */
}

/*
 * THE SCAN RANGES A READER MAY REMOVE, and which kind each one is.
 *
 * Two kinds on one list, because a reader thinks of them as one thing - the
 * ranges this draft has. An UNUSED range is a KOF_TARGET_RANGE the draft
 * declared that no matcher searches; removing it just drops the declaration. A
 * range a matcher DOES search has no life apart from that matcher - see the note
 * on grp.mask - so removing it removes the matcher, the same thing the matcher's
 * own [x] does, reached from where the reader was looking instead.
 *
 * Unused first, then the matcher ranges deduplicated. Enumerated the same way
 * where the menu is drawn and where a pick is carried out, so a row index means
 * the same on both sides.
 */
uint32_t rng_removable(struct kof_editor *e, uint32_t *mask, int *unused,
			      uint32_t cap)
{
	uint32_t n = 0, i, g, k;

	for (i = 0; i < e->dr.n_rng_add && n < cap; i++) {
		int used = 0;

		for (g = 0; g < e->dr.n_grp; g++)
			used |= grp_has_range(e, g) &&
				grp_mask(e, g) == e->dr.rng_add[i];
		if (used)
			continue;
		mask[n] = e->dr.rng_add[i];
		unused[n] = 1;
		n++;
	}
	for (g = 0; g < e->dr.n_grp && n < cap; g++) {
		uint32_t mm;
		int dup = 0;

		if (!grp_has_range(e, g))
			continue;
		mm = grp_mask(e, g);
		for (k = 0; k < n; k++)
			dup |= mask[k] == mm;
		if (dup)
			continue;
		mask[n] = mm;
		unused[n] = 0;
		n++;
	}
	return n;
}

/*
 * EVERY RANGE THE DRAFT HAS, in one order.
 *
 * The distinct masks the matchers search, then the declared ones nothing
 * searches yet. Its own function because three places need the same list in the
 * same order - the row that draws the names, the click that turns a column into
 * a range, and the menu that acts on one - and a list built three times is a
 * list that disagrees with itself about which range is which.
 */
uint32_t rng_all(struct kof_editor *e, uint32_t *mask, int *unused,
			uint32_t cap)
{
	uint32_t n = 0, g, k;

	for (g = 0; g < e->dr.n_grp && n < cap; g++) {
		uint32_t m;
		int dup = 0;

		if (!grp_has_range(e, g))
			continue;
		m = grp_mask(e, g);
		for (k = 0; k < n; k++)
			dup |= mask[k] == m;
		if (dup)
			continue;
		mask[n] = m;
		unused[n] = 0;
		n++;
	}
	for (g = 0; g < e->dr.n_rng_add && n < cap; g++) {
		int used = 0;

		for (k = 0; k < n; k++)
			used |= mask[k] == e->dr.rng_add[g];
		if (used)
			continue;
		mask[n] = e->dr.rng_add[g];
		unused[n] = 1;
		n++;
	}
	return n;
}

/* Drop an unused declared range from the draft. */
void rng_add_drop(struct kof_editor *e, uint32_t mask)
{
	uint32_t i;

	for (i = 0; i < e->dr.n_rng_add; i++)
		if (e->dr.rng_add[i] == mask) {
			memmove(&e->dr.rng_add[i], &e->dr.rng_add[i + 1u],
				(e->dr.n_rng_add - i - 1u) * sizeof e->dr.rng_add[0]);
			e->dr.n_rng_add--;
			return;
		}
}

/*
 * Remove one scan range. An unused declaration is dropped; a range a matcher
 * searches takes the matcher(s) with it - backwards, because grp_remove shifts
 * every matcher above the one it drops down by one.
 */
void rng_delete(struct kof_editor *e, uint32_t mask, int unused)
{
	if (unused) {
		rng_add_drop(e, mask);
		say_note(e, "%s", "Scan range removed");
		return;
	}
	{
		uint32_t g = e->dr.n_grp;

		while (g-- > 0)
			if (grp_has_range(e, g) && grp_mask(e, g) == mask)
				grp_remove(e, g);
	}
	say_note(e, "%s", "Scan range removed with its matcher");
}

/*
 * Carry out one line of the scan range menu.
 *
 * `target` is the range being acted on - the only one, or the one picked from
 * the second list. `here` is where this draft's markers actually are, which is
 * what every line but the last is made of. The verbs are the menu's own order,
 * so the two cannot drift apart: whatever line n says, this does.
 */
void rng_apply(struct kof_editor *e, int verb, uint32_t target, uint32_t here)
{
	switch (verb) {
	case 0:
		rng_retarget(e, target, here);
		say_note(e, "%s", "Scan range switched");
		break;
	case 1:
		rng_retarget(e, target, target | here);
		say_note(e, "%s", "Scan range extended");
		break;
	case 2: {
		/*
		 * The range and nothing else.
		 *
		 * It used to create the matcher that would name it, which put
		 * a matcher on the panel nobody had asked for and which could
		 * not be wanted yet - it has no markers, and which markers
		 * belong in it is a decision only the researcher can make. A
		 * declared range with no matcher is an ordinary half-finished
		 * state; it is listed as unused and it stops the save, which
		 * is what a half-finished state should do.
		 */
		uint32_t k;

		for (k = 0; k < e->dr.n_grp; k++)
			if (grp_has_range(e, k) && grp_mask(e, k) == here) {
				say_note(e, "%s", "A matcher already searches "
					 "that range");
				return;
			}
		for (k = 0; k < e->dr.n_rng_add; k++)
			if (e->dr.rng_add[k] == here) {
				say_note(e, "%s", "That range is already "
					 "declared");
				return;
			}
		if (e->dr.n_rng_add >= MAX_GROUP) {
			say_err(e, "%s", "No room for another range");
			return;
		}
		e->dr.rng_add[e->dr.n_rng_add++] = here;
		say_note(e, "%s", "Scan range added - give it a matcher");
		break;
	}
	case 3:
		rng_retarget(e, target, KOF_SCAN_ALL);
		say_note(e, "%s", "Scan range is now the whole file");
		break;
	default:
		break;
	}
}

/*
 * Point every marker at the region it is actually in, here.
 *
 * A family's markers do not keep one address across its own files: the same
 * five kernel symbol names sit in a data section in the rootkit object and in
 * .rodata - which is CODE, because that segment executes - in the loader that
 * installs it. A rule carried from one to the other looks right on every row
 * and cannot fire, and switching five strings one at a time to find that out is
 * work nobody should do by hand.
 *
 * A marker that is not in this object at all is LEFT ALONE and counted. It may
 * well be a real marker of the family taken from another sample, and deleting a
 * declaration because the file in front of us does not happen to contain it
 * would throw away the researcher's work to tidy up a column.
 */
void draft_refresh(struct kof_editor *e)
{
	uint32_t i, g, moved = 0, gone = 0;

	for (i = 0; i < e->dr.n_decl; i++) {
		struct decl *d = &e->dr.decl[i];

		decl_locate(e, d);
		if (d->at == KOF_BROKEN) {
			gone++;
			continue;
		}
		if (!d->at_mask)
			continue;
		if (d->mask != d->at_mask)
			moved++;
		d->mask = d->at_mask;
		snprintf(d->rgn, sizeof d->rgn, "%.23s", d->at_rgn);
		d->off_rgn = 0;
	}
	/*
	 * And the matchers follow, because a range is not an independent fact:
	 * it is the union of the regions its markers are in, which is how one
	 * gets built in the first place. Leaving them behind would move every
	 * string and still search the old place.
	 */
	for (g = 0; g < e->dr.n_grp; g++) {
		uint32_t m = 0;

		for (i = 0; i < e->dr.n_decl; i++)
			if (e->dr.decl[i].grp & (1u << g))
				m |= e->dr.decl[i].mask;
		if (m)
			e->dr.grp[g].mask = m;
	}
	if (!moved && !gone)
		say_note(e, "Every marker is already in the region searched");
	else if (!gone)
		say_note(e, "Moved %u marker(s) to where they are",
			 moved);
	else
		say_note(e, "%u moved, %u not here - left as declared",
			 moved, gone);
}

/*
 * Bring every marker's range back in step with the matchers that search it.
 *
 * Derived state, so it is recomputed from what the draft currently holds
 * rather than updated at each of the half dozen places that can change a
 * matcher's range or take a matcher away. Run from the draw, which is the one
 * point every one of those passes through, and cheap enough to: a draft holds
 * at most MAX_DECL markers and a handful of matchers, and the search below is
 * reached only when the answer actually changed.
 */
void decl_sync_ranges(struct kof_editor *e)
{
	uint32_t i;

	for (i = 0; i < e->dr.n_decl; i++) {
		struct decl *d = &e->dr.decl[i];
		uint32_t m = 0, g;

		for (g = 0; g < e->dr.n_grp; g++)
			if (d->grp & (1u << g))
				m |= e->dr.grp[g].mask;
		/* Searched by nothing: it falls back to where its bytes came
		 * from, and a marker read out of a source file has no such
		 * place - which is the dash the column shows. */
		if (!m)
			m = d->mask0;
		if (m == d->mask)
			continue;
		d->mask = m;
		if (m)
			rng_name_of(e->obj[d->obj < (*e->n_obj) ? d->obj : 0].fmt,
				    m, d->rgn, sizeof d->rgn);
		else
			snprintf(d->rgn, sizeof d->rgn, "-");
		/* The range decides which occurrence the row reports, so the
		 * marker has to be found again under the new one. */
		decl_locate(e, d);
	}
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
	struct decl *d = &e->dr.decl[i];
	size_t n = strlen(e->dr.sedit);
	uint8_t *nb;

	if (i >= e->dr.n_decl)
		return;
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
		memcpy(d->hexs, e->dr.sedit, n + 1u);
		/*
		 * Refused by the same compiler the build uses, and in its own
		 * words. A pattern the panel accepted and the build then threw
		 * out is a rule that looked right in the viewer and does not
		 * exist in the database.
		 */
		if (!decl_from_hexs(d)) {
			{
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
			}
			return;
		}
	} else {
		nb = realloc(d->bytes, n + 1u);
		if (!nb)
			return;
		d->bytes = nb;
		memcpy(d->bytes, e->dr.sedit, n);
		d->len = (uint32_t)n;
		d->nbytes = d->len;
	}
	if (!d->len) {
		say_note(e, "String %u would be empty - unchanged",
			 i + 1u);
		return;
	}
	decl_locate(e, d);
}

void decl_remove(struct kof_editor *e, uint32_t i)
{
	if (i >= e->dr.n_decl)
		return;
	free(e->dr.decl[i].bytes);
	memmove(&e->dr.decl[i], &e->dr.decl[i + 1u],
		(e->dr.n_decl - i - 1u) * sizeof e->dr.decl[0]);
	e->dr.n_decl--;
	if (e->dr.sel_decl >= e->dr.n_decl && e->dr.n_decl)
		e->dr.sel_decl = e->dr.n_decl - 1u;
}

/*
 * The counts, computed where the tables are.
 *
 * They were macros in the header, and a macro cannot count an array it cannot
 * see: the declaration had to carry a hand-written size, which made sizeof in
 * the assert meaningless and let a wrong number through as an "excess elements"
 * warning instead of an error. A variable filled by sizeof at the definition
 * cannot be wrong.
 */
const uint32_t arch_n         = sizeof arch_word     / sizeof arch_word[0];
const uint32_t elf_sub_n      = sizeof elf_sub       / sizeof elf_sub[0];
const uint32_t pe_sub_n       = sizeof pe_sub        / sizeof pe_sub[0];
const uint32_t fmt_word_n     = sizeof fmt_word      / sizeof fmt_word[0];
const uint32_t maltype_word_n = sizeof maltype_word  / sizeof maltype_word[0];





/* The call itself, without whatever is compared against it. `force_multi` asks
 * for the counting form whatever the matcher is spelled as, which is what a
 * shared call has to be. */
void emit_call_as(FILE *f, struct kof_editor *e, uint32_t g, int force_multi)
{
	const struct group *q = &e->dr.grp[g];
	char nm[RNG_IDENT_MAX];
	uint32_t i;

	rng_ident(e->obj[e->cur].fmt, grp_mask(e, g), nm, sizeof nm);
	fprintf(f, "kof_find_str_%s(%s",
		force_multi ? "multi"
			    : q->rule == 1 ? "any" : q->rule == 2 ? "multi"
							         : "all", nm);
	for (i = 0; i < e->dr.n_decl; i++)
		if (e->dr.decl[i].grp & (1u << g))
			fprintf(f, ", s%u", i);
	fprintf(f, ")");
}

void emit_call(FILE *f, struct kof_editor *e, uint32_t g)
{
	emit_call_as(f, e, g, 0);
}

void emit_call_multi(FILE *f, struct kof_editor *e, uint32_t g)
{
	emit_call_as(f, e, g, 1);
}

void emit_matcher(FILE *f, struct kof_editor *e, uint32_t g)
{
	const struct group *q = &e->dr.grp[g];

	/* The call happened once, above; this is only the comparison - and any
	 * and all become comparisons here too, which is what they are. */
	if (grp_shared(e, g)) {
		fprintf(f, "m%u >= %u", grp_lead(e, g) + 1u,
			grp_thresh_eff(e, g));
		return;
	}
	emit_call(f, e, g);
	if (q->rule == 2)
		fprintf(f, " >= %u", q->thresh);
}

/*
 * The expression, with each matcher id replaced by its call.
 *
 * Anything that is not a digit, a space, "&", "|" or a bracket is dropped
 * rather than passed through: this text becomes C, and the one thing it must
 * not do is carry something the person typing did not mean as code.
 */
void emit_expr(FILE *f, struct kof_editor *e, const char *expr)
{
	int any = 0;

	if (!expr[0]) {
		/*
		 * Nothing to test.
		 *
		 * It used to mean every matcher ANDed together - a whole
		 * signature's worth of meaning attached to an empty field. It
		 * is unreachable now anyway: a branch that decides something is
		 * refused until it names a matcher, and a grouping with none is
		 * written as a block rather than as an if.
		 */
		(void)any;
		fprintf(f, "1");
		return;
	}
	while (*expr) {
		if (*expr >= '0' && *expr <= '9') {
			uint32_t id = 0;

			while (*expr >= '0' && *expr <= '9')
				id = id * 10u + (uint32_t)(*expr++ - '0');
			if (id >= 1u && id <= e->dr.n_grp)
				emit_matcher(f, e, id - 1u);
			else
				fprintf(f, "0");
			continue;
		}
		if (*expr == '&')
			fprintf(f, " && ");
		else if (*expr == '|')
			fprintf(f, " || ");
		else if (*expr == '(' || *expr == ')')
			fputc(*expr, f);
		expr++;
	}
}

/*
 * The author's note for a matcher or a condition, as a C comment.
 *
 * On its own line above the code it belongs to, indented with it, and only when
 * there is one: a blank comment above every branch is noise, and noise in a
 * generated file is what teaches people to stop reading generated files.
 * Newlines cannot appear in these boxes and the text is bounded, so the only
 * thing to guard is a sequence that would close the comment early.
 */
void emit_note(FILE *f, const char *note, int depth)
{
	const char *p;
	int d;

	if (!note[0])
		return;
	for (d = 0; d < depth; d++)
		fputc('\t', f);
	fputs("/* ", f);
	for (p = note; *p; p++)
		fputc((*p == '*' && p[1] == '/') ? ' ' : *p, f);
	fputs(" */\n", f);
}

/* The verdict a condition reports, or nothing when it reports none. */
void emit_verdict(FILE *f, const struct cond *c, int depth)
{
	int d;

	for (d = 0; d < depth; d++)
		fputc('\t', f);
	if (c->level == LV_NONE) {
		/*
		 * Matched, reports nothing, and stops.
		 *
		 * The stop is the whole of it. Verdicts return, so everything
		 * after a branch runs only when that branch declined - and a
		 * branch that declines without returning declines nothing: the
		 * gate's verdict below would fire anyway. Returning is what
		 * makes this say "these bytes are here and they are fine".
		 */
		fprintf(f, "/* matched, and deliberately reports nothing */\n");
		for (d = 0; d < depth; d++)
			fputc('\t', f);
		fprintf(f, "return;\n");
		return;
	}
	fprintf(f, "KOF_SCAN_%s(", c->level == LV_SUSPECT ? "SUSPECT"
							  : "INFECT");
	if (c->var_kind == 2 && c->variant[0])
		fprintf(f, "\"%s\"", c->variant);
	else if (c->var_kind == 1)
		fprintf(f, "KOF_MALVAR_GENERIC");
	else
		fprintf(f, "KOF_MALVAR_AUTO");
	fprintf(f, ");\n");
}

/*
 * One branch, and the ones nested under it.
 *
 * `chained` makes this an "else if" rather than an "if". Conditions nested
 * under a gate are alternatives to each other - which variant of the thing the
 * gate established - so they chain, and the gate's own verdict becomes the else
 * that catches the case where the gate held and none of the alternatives did.
 * Without that else a gate with children concluded nothing at all when its
 * children all missed, which is the one outcome a gate is worth writing for.
 *
 * Top level conditions do not chain: they are separate detections that happen
 * to live in one module, not alternatives to one another.
 */
void emit_cond(FILE *f, struct kof_editor *e, uint32_t i, int depth,
		      int chained)
{
	const struct cond *c = &e->dr.cnd[i];
	uint32_t k;
	int d;

	/*
	 * A matcher's note goes above the branch that uses it, not beside the
	 * call: the call is one term of an expression inside an if, and a
	 * comment there would break the line that has to stay readable. Named
	 * by number so it can be told from the condition's own note when a
	 * branch carries several.
	 *
	 * A GROUPING GETS NONE OF THEM. It has no test of its own - it is a
	 * brace around some branches - so it uses no matcher, and its children
	 * carry their own notes a line or two below. The filter below used to be
	 * gated on the condition HAVING an expression, and a grouping has none,
	 * so it printed every matcher's note in the file and then each child
	 * printed its own again. Prometei_00.c came out with three notes above
	 * the brace and the same three repeated inside it.
	 *
	 * An empty expression on a LEAF is a different thing: it means the
	 * default, every matcher joined by &, so there every note belongs.
	 */
	if (!(!c->expr[0] && cnd_children(e, i)))
		for (k = 0; k < e->dr.n_grp; k++) {
			char t[120];

			if (!e->dr.grp[k].note[0])
				continue;
			if (c->expr[0] && !cnd_uses(c, k))
				continue;
			snprintf(t, sizeof t, "matcher %u: %s", k + 1u,
				 e->dr.grp[k].note);
			emit_note(f, t, depth);
		}
	for (d = 0; d < depth; d++)
		fputc('\t', f);
	if (!c->expr[0] && cnd_children(e, i)) {
		/*
		 * A grouping: no test of its own, so no if of its own.
		 *
		 * Written as a bare block rather than "if (1)", because that is
		 * what it is - a brace around some branches so the statement
		 * after them belongs to the group and not to whatever came
		 * before it. Verdicts return, so that statement is reached
		 * exactly when none of the branches inside concluded.
		 */
		fprintf(f, "{\n");
	} else {
		fprintf(f, "%sif (", chained ? "else " : "");
		emit_expr(f, e, c->expr);
		fprintf(f, ")");
	}

	if (!cnd_children(e, i)) {
		if (c->level == LV_NONE) {
			fprintf(f, " {\n");
			emit_verdict(f, c, depth + 1);
			for (d = 0; d < depth; d++)
				fputc('\t', f);
			fprintf(f, "}\n");
			return;
		}
		fprintf(f, "\n");
		emit_verdict(f, c, depth + 1);
		return;
	}

	if (c->expr[0])
		fprintf(f, " {\n");
	{
		uint32_t prev = e->dr.n_cnd;

		for (k = 0; k < e->dr.n_cnd; k++) {
			if (e->dr.cnd[k].parent != (int)i)
				continue;
			/*
			 * Chained or not, as the rule between them says.
			 *
			 * It used to be decided by depth - nested siblings
			 * always chained, top level ones never did - which made
			 * the same two rows on screen mean two different things
			 * depending on where they sat.
			 */
			emit_cond(f, e, k, depth + 1,
				  prev < e->dr.n_cnd && !e->dr.cnd[prev].join);
			prev = k;
		}
	}
	/*
	 * The gate's own verdict, after the children rather than as an else.
	 *
	 * Every KOF_SCAN_INFECT and KOF_SCAN_SUSPECT reports and returns, so a
	 * child that concluded anything has already left the function - which
	 * means the statement after the children is reached exactly when none
	 * of them concluded, which is what a gate's own verdict means.
	 *
	 * Written as "else" it bound to the LAST child's if and nothing more:
	 * with two children it fired whenever the second missed, whatever the
	 * first had done.
	 */
	if (c->level != LV_NONE)
		emit_verdict(f, c, depth + 1);
	for (d = 0; d < depth; d++)
		fputc('\t', f);
	fprintf(f, "}\n");
}

/*
 * Empty the panel and call that the saved state.
 *
 * draft_clear on its own leaves the panel looking unsaved: saved_hash still
 * describes whatever was in it, so an empty draft reads as work in progress and
 * the guards that ask "is there something to lose" all answer yes.
 *
 * This is what the New button does, and what a signature examined and then
 * abandoned needs - opening a rule to look at it loads it into the panel, and
 * the way back to a blank one should not be closing the program.
 */
void draft_reset(struct kof_editor *e)
{
	draft_clear(e);
	e->dr.saved_hash = draft_hash(e);
	e->dr.sel_decl = 0;
	e->dr.cur_grp = e->dr.cur_cnd = 0;
	e->dr.warn[0] = 0;
	say_note(e, "Panel cleared");
}

int draft_from_source(struct kof_editor *e, const char *path)
{
	FILE *f = fopen(path, "r");
	char line[1024], pend[160];
	struct sname str[MAX_DECL];
	struct { char id[48]; uint32_t mask; } rng[8];
	uint32_t n_str = 0, n_rng = 0, i;
	const struct kof_inspect_fmt *fmt = e->obj[e->cur].fmt;
	/*
	 * Which condition owns each brace depth, so a verdict lands on the one
	 * whose body it is in.
	 *
	 * A bare KOF_SCAN_ line after the children is the enclosing condition's
	 * own verdict; one that follows an if with no brace belongs to that if.
	 * Attaching every verdict to the last condition seen put the gate's
	 * fallback onto its final child, which reads as the wrong branch of the
	 * wrong rule.
	 */
	int owner[8];
	int depth = 0, body = 0, cur = -1, parent = -1, skipped = 0;
	int just_opened = 0;
	/*
	 * THE SHARED CALLS, READ BACK.
	 *
	 * The generator writes "at least three, otherwise at least two" as one
	 * call into a variable and two comparisons against it. Reading that
	 * back needs the variable remembered: the call says what to look for
	 * and where, and each "m1 >= N" is a matcher over exactly that with its
	 * own threshold. Without this the ifs referred to a name that meant
	 * nothing here and the rule came back with no matchers at all.
	 */
	struct { char id[16]; int rule; uint32_t mask, decls; } shc[8];
	uint32_t n_shc = 0;
	int pend_if = -1;
	char head[sizeof e->dr.note];
	size_t head_n = 0;
	int in_head = 0, head_done = 0, mine = 0;

	if (!f)
		return 0;
	pend[0] = 0;
	head[0] = 0;
	for (i = 0; i < sizeof owner / sizeof owner[0]; i++)
		owner[i] = -1;
	while (fgets(line, sizeof line, f)) {
		char *p;

		/*
		 * The file's own leading comment, back into the note field.
		 *
		 * The rules below treat every block comment as punctuation and
		 * skip it, which is right for the ones that annotate a branch
		 * and wrong for this one: the generator writes the author's own
		 * line about the module into the header. Skipping it meant
		 * opening a signature showed an empty note, and saving it then
		 * deleted the one sentence in the file a person had written.
		 */
		if (!head_done) {
			char *t = line, *eol;
			size_t n;

			while (*t == ' ' || *t == '\t' || *t == '\n' ||
			       *t == '\r')
				t++;
			if (!in_head) {
				if (!*t)
					continue;       /* between blocks */
				if (t[0] != '/' || t[1] != '*') {
					/* Code: the header is over, and
					 * nothing below should see this line
					 * twice. */
					head_done = 1;
					goto no_head;
				}
				in_head = 1;
				mine = 0;
				t += 2;
			}
			if ((eol = strstr(t, "*/")) != NULL)
				*eol = 0;
			while (*t == ' ' || *t == '\t' || *t == '*')
				t++;
			n = strlen(t);
			while (n && (t[n - 1] == '\n' || t[n - 1] == '\r' ||
				     t[n - 1] == ' ' || t[n - 1] == '\t'))
				n--;
			if (n) {
				/* Cut here, not just measured: what follows is
				 * stored and compared, and a trailing newline
				 * made every entry differ from the same entry
				 * read back - so nothing deduplicated and the
				 * block grew a blank line per item. */
				t[n] = 0;
				/* The banner only counts as one where it is
				 * written - opening the block. A line of prose
				 * quoting it further down is prose. */
				if (!head_n && !mine &&
				    !strncmp(t, HEAD_BANNER,
					     sizeof HEAD_BANNER - 1))
					mine = 1;
				/* Inside our own block the recognised lines
				 * are the rule's history and are kept; the
				 * author's block is prose and goes to the
				 * note. */
				if (mine)
					meta_take(e, t);
				else
					head_put(head, sizeof head, &head_n,
						 t, n);
			}
			if (eol)
				in_head = 0;    /* the next block may follow */
			continue;
		}
no_head:

		/* A comment on its own line belongs to whatever comes next -
		 * which is how the generator wrote it and how the modules in
		 * bases/ are written by hand. */
		/*
		 * A COMMENT AFTER CODE DOES NOT MAKE THE LINE A COMMENT.
		 *
		 * The two branches below treat any line holding a comment opener
		 * as one, and that dropped whole declarations. bases/ has them:
		 * ZipSlip writes its Windows marker as
		 * KOF_DEFINE_HEXSTR(path_on_ntwin, "2E 2E 5C") with a trailing
		 * comment spelling out the three bytes.
		 *
		 * That marker was never declared when the rule was opened, its
		 * matcher came up with no markers, and the comment text became
		 * the pending note that attached to the NEXT matcher - so the
		 * panel showed a rule that was not the rule in the file.
		 *
		 * So: code before the opener means the code is the line, and
		 * the comment is cut off it. Only a line that begins with the
		 * comment is a comment, which is what the branches below now
		 * see. The trailing text is dropped rather than kept, because
		 * the only place this model has to put it is "the next thing",
		 * and the next thing is not what it was written about.
		 */
		{
			char *c = strstr(line, "/*");
			char *t;
			int code = 0;

			for (t = line; c && t < c; t++)
				if (*t != ' ' && *t != '\t') {
					code = 1;
					break;
				}
			if (code) {
				char *ep = strstr(c, "*/");

				/* One that does not close here takes the rest
				 * of the line with it. */
				if (ep)
					memmove(c, ep + 2, strlen(ep + 2) + 1);
				else
					*c = 0;
			}
		}
		if ((p = strstr(line, "/*")) != NULL &&
		    strstr(line, "*/") != NULL) {
			char *q = strstr(p, "*/");
			size_t n = 0;

			for (p += 2; p < q && n + 1 < sizeof pend; p++)
				if (n || (*p != ' ' && *p != '\t'))
					pend[n++] = *p;
			while (n && (pend[n - 1] == ' ' || pend[n - 1] == '\t'))
				n--;
			pend[n] = 0;
			continue;
		}
		if (strstr(line, "/*") || strstr(line, "*/") ||
		    strstr(line, " * ")) {
			continue;               /* a block comment; skip it */
		}

		if ((p = strstr(line, "KOF_TARGET_NAME(")) != NULL) {
			char w[48];
			uint32_t k;

			src_ident(p + 16, w, sizeof w);
			for (k = 0; k < MALTYPE_N; k++) {
				char t[48];

				snprintf(t, sizeof t, "KOF_MALTYPE_%s",
					 maltype_word[k]);
				if (!strcasecmp(t, w))
					e->dr.maltype = k;
			}
			src_quoted(p, e->dr.family, sizeof e->dr.family);
			continue;
		}
		if ((p = strstr(line, "KOF_TARGET_RANGE(")) != NULL &&
		    n_rng < sizeof rng / sizeof rng[0]) {
			const char *q = src_ident(p + 17, rng[n_rng].id,
						  sizeof rng[0].id);

			rng[n_rng].mask = src_mask_of(fmt, q);
			n_rng++;
			continue;
		}
		if ((p = strstr(line, "KOF_TARGET_SIZE_MIN(")) != NULL) {
			e->dr.opt_on[OPT_SIZE_MIN] = 1;
			e->dr.opt_val[OPT_SIZE_MIN] = strtoull(p + 20, NULL, 0);
			continue;
		}
		/*
		 * The optional declarations are read back because they are
		 * written out: a rule opened, changed in one place and saved
		 * would otherwise come back without its arch or its subtype,
		 * and a signature that quietly stops being prefiltered is a
		 * signature that quietly starts running on everything.
		 */
		if ((p = strstr(line, "KOF_TARGET_ARCH(KOF_ARCH_")) != NULL) {
			char w[32];
			uint32_t k;

			src_ident(p + 25, w, sizeof w);
			for (k = 0; k < ARCH_N; k++)
				if (!strcmp(arch_word[k].word, w)) {
					e->dr.opt_on[OPT_ARCH] = 1;
					e->dr.opt_val[OPT_ARCH] = k;
				}
			continue;
		}
		if ((p = strstr(line, "KOF_TARGET_SUBTYPE(")) != NULL) {
			const char *const *tab = NULL;
			const char *sub;
			char w[32];
			uint32_t n = 0, k;

			if ((sub = strstr(p, "KOF_ELF_")) != NULL) {
				tab = elf_sub;
				n = elf_sub_n;
				src_ident(sub + 8, w, sizeof w);
			} else if ((sub = strstr(p, "KOF_PE_")) != NULL) {
				tab = pe_sub;
				n = pe_sub_n;
				src_ident(sub + 7, w, sizeof w);
			}
			for (k = 0; tab && k < n; k++)
				if (!strcmp(tab[k], w)) {
					e->dr.opt_on[OPT_SUBTYPE] = 1;
					e->dr.opt_val[OPT_SUBTYPE] = k;
				}
			continue;
		}
		if ((p = strstr(line, "KOF_DEFINE_STR(")) != NULL ||
		    (p = strstr(line, "KOF_DEFINE_HEXSTR(")) != NULL) {
			int hex = strstr(line, "KOF_DEFINE_HEXSTR(") != NULL;
			char text[512];
			struct decl *d;

			if (e->dr.n_decl >= MAX_DECL || n_str >= MAX_DECL)
				continue;
			d = &e->dr.decl[e->dr.n_decl];
			memset(d, 0, sizeof *d);
			src_ident(strchr(p, '(') + 1, str[n_str].id,
				  sizeof str[0].id);
			if (!src_quoted(p, text, sizeof text))
				continue;
			if (hex) {
				size_t n = strlen(text) / 2u, k;

				/* Verbatim, because the file already holds the
				 * pattern in the one form that can express it -
				 * and the byte conversion below turns a "??"
				 * into a 00, which is a different pattern. */
				snprintf(d->hexs, sizeof d->hexs, "%s", text);
				decl_from_hexs(d);
				(void)n; (void)k;
				d->hex = 1;
			} else {
				d->len = (uint32_t)strlen(text);
				d->bytes = malloc(d->len ? d->len : 1u);
				if (!d->bytes)
					continue;
				memcpy(d->bytes, text, d->len);
				d->nbytes = d->len;
				d->icase = strstr(line, "KOF_CASE_ICASE") != 0;
				d->fullword = strstr(line,
						     "KOF_WORD_FULLWORD") != 0;
			}
			d->obj = e->cur;
			d->grp = 0;
			snprintf(d->rgn, sizeof d->rgn, "-");
			str[n_str].idx = e->dr.n_decl;
			n_str++;
			e->dr.n_decl++;
			continue;
		}

		{
			/*
			 * The line that opens the body is not IN the body.
			 *
			 * It trips the foreign test otherwise - it is a
			 * function signature, which is code and is none of the
			 * three modelled constructs - so every ordinary rule
			 * came back read only.
			 */
			int opens = strstr(line, "kof_scan(") != NULL ||
				    strstr(line, "KOF_DEFINE_SCAN") != NULL;

			if (opens)
				body = 1;
			if (!body)
				continue;
			just_opened = opens;
		}

		{
			/*
			 * A brace with nothing testing it is a grouping, and
			 * has to come back as one: read as plain punctuation
			 * its branches would surface as siblings of whatever
			 * came before, which is a different signature.
			 */
			const char *t = line;

			while (*t == ' ' || *t == '\t')
				t++;
			if (*t == '{' && body && depth >= 1 &&
			    e->dr.n_cnd < MAX_GROUP) {
				struct cond *c = &e->dr.cnd[e->dr.n_cnd];

				memset(c, 0, sizeof *c);
				c->parent = parent;
				c->level = LV_NONE;
				if (cur >= 0 && e->dr.cnd[cur].parent == parent)
					e->dr.cnd[cur].join = 1;
				cur = (int)e->dr.n_cnd;
				pend_if = -1;
				e->dr.n_cnd++;
			}
		}
		if (strstr(line, "if (") || strstr(line, "if(")) {
			struct cond *c;

			if (e->dr.n_cnd >= MAX_GROUP) {
				skipped++;
				continue;
			}
			c = &e->dr.cnd[e->dr.n_cnd];
			memset(c, 0, sizeof *c);
			c->parent = parent;
			c->level = LV_NONE;
			c->op = strstr(line, "||") != NULL;
			/*
			 * How the previous condition at this level joins to
			 * this one, read off the source rather than assumed:
			 * "else if" chains, a fresh "if" does not. Assuming
			 * one turned three independent branches into a chain
			 * on the way back out - the same behaviour, since
			 * verdicts return, but not the same file.
			 */
			if (cur >= 0 && e->dr.cnd[cur].parent == parent)
				e->dr.cnd[cur].join = strstr(line, "else") == NULL;
			cur = (int)e->dr.n_cnd;
			pend_if = cur;
			e->dr.n_cnd++;
			/* `pend` is left alone: the comment above a branch
			 * describes the search it makes, and the search is the
			 * matcher on the same line. */
		}
		/*
		 * "uint32_t mN = <call>;" - the call, kept under its name. It
		 * is not a matcher on its own: nothing is compared against it
		 * yet, and the comparisons below are what carry the thresholds.
		 */
		if ((p = strstr(line, "kof_find_str_")) != NULL &&
		    memchr(line, '=', (size_t)(p - line)) != NULL &&
		    !strstr(line, "if (") && !strstr(line, "if(")) {
			const char *q;
			char id[48];

			if (n_shc >= sizeof shc / sizeof shc[0])
				goto shc_done;
			memset(&shc[n_shc], 0, sizeof shc[0]);
			shc[n_shc].rule = !strncmp(p + 13, "any", 3) ? 1
					: !strncmp(p + 13, "multi", 5) ? 2 : 0;
			/* The variable's own name, the identifier before "=". */
			{
				const char *ep = memchr(line, '=',
						       (size_t)(p - line));
				const char *b2 = ep;

				while (b2 > line && (b2[-1] == ' ' ||
						     b2[-1] == '\t'))
					b2--;
				{
					const char *st2 = b2;

					while (st2 > line &&
					       (isalnum((unsigned char)st2[-1])
						|| st2[-1] == '_'))
						st2--;
					snprintf(shc[n_shc].id,
						 sizeof shc[0].id, "%.*s",
						 (int)(b2 - st2), st2);
				}
			}
			q = strchr(p, '(');
			if (!q)
				goto shc_done;
			q = src_ident(q + 1, id, sizeof id);
			for (i = 0; i < n_rng; i++)
				if (!strcmp(rng[i].id, id))
					shc[n_shc].mask = rng[i].mask;
			while (*q == ',' || *q == ' ') {
				char sid[48];
				uint32_t k;

				q = src_ident(q, sid, sizeof sid);
				if (!sid[0])
					break;
				k = src_str_idx(str, n_str, sid);
				if (k < e->dr.n_decl && k < 32u)
					shc[n_shc].decls |= 1u << k;
				while (*q == ' ')
					q++;
			}
			if (shc[n_shc].id[0])
				n_shc++;
shc_done:
			continue;
		}
		/* "mN >= K" - one matcher over the remembered call. */
		if (cur >= 0 && n_shc && !strstr(line, "kof_find_str_")) {
			uint32_t si;

			for (si = 0; si < n_shc; si++) {
				const char *at = strstr(line, shc[si].id);
				const char *ge;
				struct group *g;
				uint32_t k;

				if (!at)
					continue;
				ge = strstr(at, ">=");
				if (!ge || e->dr.n_grp >= MAX_GROUP)
					continue;
				g = &e->dr.grp[e->dr.n_grp];
				memset(g, 0, sizeof *g);
				g->rule = shc[si].rule;
				g->mask = shc[si].mask;
				g->thresh = (uint32_t)strtoul(ge + 2, NULL, 10);
				for (k = 0; k < e->dr.n_decl && k < 32u; k++)
					if (shc[si].decls & (1u << k))
						e->dr.decl[k].grp |= 1u << e->dr.n_grp;
				{
					size_t l = strlen(e->dr.cnd[cur].expr);

					snprintf(e->dr.cnd[cur].expr + l,
						 sizeof e->dr.cnd[0].expr - l,
						 "%s%u",
						 l ? (e->dr.cnd[cur].op ? "|" : "&")
						   : "", e->dr.n_grp + 1u);
				}
				e->dr.n_grp++;
				break;
			}
		}
		if ((p = strstr(line, "kof_find_str_")) != NULL) {
			/*
			 * One call is one matcher, which is exactly the rule
			 * the panel is built on - a matcher is a single
			 * find_all/find_any/find_multi over one range.
			 */
			const char *q = p + 13;
			char id[48];
			struct group *g;
			int rule = 0;

			if (!strncmp(q, "any", 3))
				rule = 1;
			else if (!strncmp(q, "multi", 5))
				rule = 2;
			if (e->dr.n_grp >= MAX_GROUP || cur < 0) {
				skipped++;
				continue;
			}
			g = &e->dr.grp[e->dr.n_grp];
			memset(g, 0, sizeof *g);
			g->rule = rule;
			q = strchr(p, '(');
			if (!q)
				continue;
			q = src_ident(q + 1, id, sizeof id);
			for (i = 0; i < n_rng; i++)
				if (!strcmp(rng[i].id, id))
					g->mask = rng[i].mask;
			while (*q == ',' || *q == ' ') {
				char sid[48];
				uint32_t k;

				q = src_ident(q, sid, sizeof sid);
				if (!sid[0])
					break;
				k = src_str_idx(str, n_str, sid);
				if (k < e->dr.n_decl)
					e->dr.decl[k].grp |= 1u << e->dr.n_grp;
				while (*q == ' ')
					q++;
			}
			if (rule == 2) {
				const char *ge = strstr(p, ">=");

				g->thresh = ge ? (uint32_t)strtoul(ge + 2, NULL,
								   10) : 2u;
			}
			if (pend[0]) {
				/*
				 * The LABEL is not part of the note.
				 *
				 * generate writes "matcher N: <note>", and this
				 * kept the whole line - so the next generate
				 * prefixed a label that was already there and
				 * the file grew "matcher 1: matcher 1: ..." one
				 * layer per save. The number is derived from
				 * where the matcher sits, so reading it back is
				 * reading back something this side already
				 * knows.
				 */
				const char *note = pend;

				if (strncmp(note, "matcher ", 8) == 0) {
					const char *colon = strchr(note + 8, ':');

					if (colon) {
						note = colon + 1;
						while (*note == ' ')
							note++;
					}
				}
				snprintf(g->note, sizeof g->note, "%s", note);
				pend[0] = 0;
			}
			{
				size_t l = strlen(e->dr.cnd[cur].expr);

				snprintf(e->dr.cnd[cur].expr + l,
					 sizeof e->dr.cnd[0].expr - l, "%s%u",
					 l ? (e->dr.cnd[cur].op ? "|" : "&") : "",
					 e->dr.n_grp + 1u);
			}
			e->dr.n_grp++;
		}

		if (strstr(line, "KOF_SCAN_INFECT(") ||
		    strstr(line, "KOF_SCAN_SUSPECT(")) {
			/*
			 * An "else" on its own before it is the old shape this
			 * tool used to write, where the gate's fallback was
			 * bound to the last child's if. It was meant as the
			 * gate's, so that is where it goes.
			 */
			int at = pend_if >= 0 ? pend_if
				 : (depth > 0 && depth < 8 ? owner[depth] : -1);

			if (at < 0)
				at = cur;
			if (at >= 0) {
				struct cond *c = &e->dr.cnd[at];

				c->level = strstr(line, "SUSPECT")
					   ? LV_SUSPECT : LV_INFECT;
				if (strstr(line, "KOF_MALVAR_GENERIC"))
					c->var_kind = 1;
				else if (strchr(line, '"')) {
					c->var_kind = 2;
					src_quoted(line, c->variant,
						   sizeof c->variant);
				}
			}
			pend_if = -1;
		}
		/* Whatever this line was, was it something the panel can hold. */
		if (body && !just_opened && !body_modelled(line))
			(*e->foreign_w)++;

		for (p = line; *p; p++) {
			if (*p == '{' && body) {
				depth++;
				if (depth < 8)
					owner[depth] = cur;
				if (depth > 1 && cur >= 0)
					parent = cur;
				pend_if = -1;   /* it opened a block */
			} else if (*p == '}' && body) {
				if (depth < 8 && depth >= 0)
					owner[depth] = -1;
				depth--;
				if (depth <= 1)
					parent = -1;
			}
		}
	}
	fclose(f);

	/*
	 * A string's region column, filled from the matcher that searches it.
	 *
	 * The source says where each matcher looks, not where each string is -
	 * and where it looks is the fact the table is for. A string no matcher
	 * claimed keeps its dash, which is the truthful answer.
	 */
	for (i = 0; i < e->dr.n_decl; i++) {
		struct decl *d = &e->dr.decl[i];

		uint32_t g2;

		if (!d->grp || d->mask)
			continue;
		/* Every matcher that searches for it contributes its range. */
		for (g2 = 0; g2 < e->dr.n_grp; g2++)
			if (d->grp & (1u << g2))
				d->mask |= e->dr.grp[g2].mask;
		if (d->mask)
			rng_name_of(fmt, d->mask, d->rgn, sizeof d->rgn);
	}
	/* The source says what to look for, not where it was found. */
	for (i = 0; i < e->dr.n_decl; i++)
		decl_locate(e, &e->dr.decl[i]);
	if (head_n)
		snprintf(e->dr.note, sizeof e->dr.note, "%s", head);
	return skipped ? -1 : 1;
}

/*
 * Fill the draft from a signature that fired on this object.
 *
 * The point is a starting position, not a copy: a researcher writing a variant
 * begins from what the existing rule already knows about the family, and typing
 * its strings back in by hand is the tedious half of that.
 *
 * What comes across is everything the database holds - the family, the type,
 * each declared string with its case and word handling, and the region each one
 * was actually found in. What does not is the logic. A module's conditions are
 * compiled code; the pack keeps the strings and the names, not which of them
 * were required together or in what combination. So they all land in one
 * find_all and the row says so, for the researcher to take apart.
 */
void draft_from_touch(struct kof_editor *e, const struct kof_touch *t)
{
	uint32_t i;

	if (!t)
		return;
	{
		/* Through a local: the family may be a pointer into the very
		 * object being written to, and snprintf may not overlap. */
		char fam[64];

		snprintf(fam, sizeof fam, "%s", t->family ? t->family : "");
		snprintf(e->dr.family, sizeof e->dr.family, "%s", fam);
	}
	for (i = 0; i < MALTYPE_N; i++)
		if (t->maltype == i)
			e->dr.maltype = i;

	for (i = 0; i < t->n_str && e->dr.n_decl < MAX_DECL; i++) {
		const struct kof_touch_str *st = &t->str[i];
		struct decl *d = &e->dr.decl[e->dr.n_decl];

		if (!st->pool_len)
			continue;
		memset(d, 0, sizeof *d);
		d->hex = st->kind == KOF_STR_HEX;
		if (d->hex) {
			/*
			 * The pack holds a hex marker as a COMPILED PROGRAM.
			 * Turned back into what its author wrote, because that
			 * is the only form a person can read and the only one
			 * that can be written back out - see decl.hexs.
			 *
			 * And then read the same way the source loader reads
			 * the same spelling out of a file, deliberately: a
			 * signature opened without its source and the same
			 * signature opened with it must produce the same draft,
			 * or "is this a duplicate of a rule in the tree" gets
			 * two answers for one rule.
			 */
			size_t hn, k;

			snprintf(d->hexs, sizeof d->hexs, "%s", st->text);
			if (!d->hexs[0])
				continue;
			decl_from_hexs(d);
			(void)hn; (void)k;
		} else {
			d->bytes = malloc(st->pool_len);
			if (!d->bytes)
				break;
			memcpy(d->bytes, st->pool, st->pool_len);
			d->len = st->pool_len;
			d->nbytes = d->len;
		}
		d->icase = (st->flags & KOF_STR_ICASE) != 0;
		d->fullword = (st->flags & KOF_STR_FULLWORD) != 0;
		d->obj = e->cur;
		/*
		 * THE RANGE THE MODULE DECLARED, which the pack does keep.
		 *
		 * This used to derive a region from where the bytes turned out
		 * to be, on the grounds that "the module's range is not in the
		 * pack either". That was wrong: the pack stores each module's
		 * scan_mask, the engine reads it on every search, and
		 * kof_touch_object now carries it through.
		 *
		 * Deriving it was not merely roundabout, it was unsound. A
		 * marker declared in SYM_EXP is not in the file at all - the
		 * block's records are built - so node_at found nothing, the
		 * range came out "-", decl_locate then searched the file
		 * instead of the block, and the row called a marker absent
		 * that the scan finds every time. The engine and the panel
		 * disagreeing about one object is the one answer this pane
		 * must never give.
		 *
		 * Zero stays zero: a module that names no region cannot be
		 * skipped by region, and widening it to whole-file here would
		 * be inventing a range it never declared.
		 */
		d->mask = t->scan_mask;
		d->mask0 = t->scan_mask;
		if (d->mask)
			rng_name_of(e->obj[d->obj].fmt, d->mask, d->rgn,
				    sizeof d->rgn);
		else
			snprintf(d->rgn, sizeof d->rgn, "-");
		d->grp = 1u;             /* matcher 1, the only one here */
		d->at = st->at;
		e->dr.n_decl++;
	}
	if (!e->dr.n_decl)
		return;
	/*
	 * The pack says where ONE occurrence is; the pane wants them all.
	 *
	 * st->at is what the scan happened to stop on. Re-running the search
	 * here fills the occurrence list and settles at/at_rgn the same way the
	 * source path does, so a draft built from a database and a draft built
	 * from a file light the same bytes. The declared region above is left
	 * alone: the pack kept the strings and not the logic, so where the
	 * bytes are IS the only reading of where the module would look.
	 */
	{
		uint32_t di;

		for (di = 0; di < e->dr.n_decl; di++)
			decl_locate(e, &e->dr.decl[di]);
	}

	memset(&e->dr.grp[0], 0, sizeof e->dr.grp[0]);
	e->dr.n_grp = 1;
	e->dr.cur_grp = 0;
	/* The range is the module's own, so the matcher shows what the rule
	 * actually searches rather than WHOLE-FILE. */
	e->dr.grp[0].mask = t->scan_mask;
	snprintf(e->dr.grp[0].note, sizeof e->dr.grp[0].note,
		 "from %s - the database keeps the strings, not the logic",
		 t->family[0] ? t->family : "the database");

	memset(&e->dr.cnd[0], 0, sizeof e->dr.cnd[0]);
	snprintf(e->dr.cnd[0].expr, sizeof e->dr.cnd[0].expr, "1");
	e->dr.cnd[0].parent = -1;
	e->dr.cnd[0].level = LV_INFECT;
	e->dr.n_cnd = 1;
	e->dr.cur_cnd = 0;
	say_note(e, "Loaded %u string(s) from %s - markers only, no logic",
		 e->dr.n_decl,
		 t->family[0] ? t->family : "the database");
	e->dr.saved_hash = draft_hash(e);
}


void generate(struct kof_editor *e, int as_new)
{
	{
		/*
		 * The button is greyed when this returns something, but the
		 * key that also runs it is not - and a draft that is short of
		 * a matcher would otherwise be written out as a module that
		 * searches for nothing.
		 */
		/* The same question the button asked, with the same argument:
		 * a key runs this too, and the two must not disagree about
		 * whether Save As is allowed on a read-only rule. */
		const char *why = draft_missing_of(e, as_new);
		int near = 0;
		const char *dup;

		if (why) {
			say_err(e, "%s first", why);
			return;
		}
		dup = draft_dup(e, &near);
		if (dup && !near) {
			say_note(e, "Same markers as %s - edit that instead",
				 dup);
			return;
		}
		/*
		 * Nothing to write either way.
		 *
		 * For Save As a copy would be a duplicate; for Save the file
		 * on disk already says this. Repeated clicks used to rewrite
		 * it each time, which was harmless and looked like nothing was
		 * happening.
		 */
		if (!draft_dirty(e) && e->dr.gen_path[0]) {
			say_note(e, "%s",
				 as_new ? "Nothing changed - a copy would be a "
					  "duplicate"
					: "Nothing changed since the last save");
			return;
		}
	}
	struct object *ob = &e->obj[e->dr.decl[0].obj];
	char path[400], safe[48], fname[48];
	uint32_t i, k;
	FILE *f;
	size_t j = 0;

	/* Kept, not cleared: it is the answer to "which file is this draft's",
	 * and clearing it here made every generate look like the first one -
	 * so a draft opened from a file wrote a numbered copy beside it. */
	if (!e->dr.n_decl || !e->dr.family[0])
		return;

	for (i = 0; e->dr.family[i] && j + 1u < sizeof safe; i++)
		if (isalnum((unsigned char)e->dr.family[i]) || e->dr.family[i] == '_')
			safe[j++] = e->dr.family[i];
	safe[j] = 0;
	/*
	 * THE FILE NAME IS LOWER CASE; THE FAMILY NAME IS NOT.
	 *
	 * They share their letters and nothing else. A signature tree sorted by
	 * a tool that folds case, or read on a filesystem that does, should not
	 * depend on how a researcher typed the family into the panel - so the
	 * name on disk is settled here, once.
	 *
	 * What the module DECLARES itself to be keeps the spelling it was
	 * given: KOF_TARGET_NAME below writes `safe`, and that string is the
	 * verdict a user reads. "mirai" is not how the family is written. The
	 * two used to be one variable, which is why lowering the path lowered
	 * the verdict with it.
	 */
	for (i = 0; safe[i]; i++)
		fname[i] = (char)tolower((unsigned char)safe[i]);
	fname[i] = 0;
	if (!j)
		return;

	/*
	 * One directory serves as both the source tree and the output, because
	 * they are the same thing: what this writes IS a signature source.
	 *
	 * A content root and one of its kind-directories are both reasonable
	 * things to be given. "bases" holds signatures/, decomp/ and unp/ and a
	 * detection does not belong loose at its top; "bases/signatures" is
	 * already the right place. So a signatures/ subdirectory, where one
	 * exists, is where the file goes.
	 */
	{
		char dir[300];
		struct stat st;

		snprintf(dir, sizeof dir, "%s/signatures", e->basedir);
		if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode))
			snprintf(dir, sizeof dir, "%s", e->basedir);
		if (kof_mkdir(dir, 0777) != 0 && errno != EEXIST) {
			say_err(e, "Cannot create %.90s", dir);
			return;
		}
		/*
		 * A file this session created, or a name nothing is using.
		 *
		 * Two families are often written from the same sample and a
		 * researcher writes several drafts for one family, so a name
		 * colliding is normal rather than exceptional - and silently
		 * overwriting somebody's signature because the family matched
		 * is not a thing to do quietly.
		 *
		 * So: whatever this draft has already been written to stays
		 * its file, and generate keeps updating it. Otherwise a new
		 * one is numbered.
		 *
		 * ALWAYS NUMBERED, even when the bare name is free.
		 *
		 * A family is written more than once - a variant, a second
		 * sample, a rule for the loader beside the rule for the payload
		 * - so Mirai.c is not the name of a signature, it is the name
		 * of the first one somebody happened to write. Numbering from
		 * the start means the second file is not a special case, the
		 * set reads as a set, and no name has to be renamed later to
		 * make room. Nothing this session did not create is touched.
		 */
		e->dr.gen_ok = 0;
		if (!as_new && e->dr.gen_path[0] &&
		    !strncmp(e->dr.gen_path, dir, strlen(dir))) {
			snprintf(path, sizeof path, "%.*s",
				 (int)sizeof path - 1, e->dr.gen_path);
		} else {
			/*
			 * The first number nothing is using, and the number
			 * gets WIDER rather than running out.
			 *
			 * Two digits is the everyday width and reads well: a
			 * family with a handful of rules gets _00 to _09. A
			 * family with more than a hundred is not an error to
			 * refuse, it is a family somebody has worked on, so the
			 * width grows instead. Falling off the end of a fixed
			 * width would leave the last name - which exists -
			 * about to be overwritten, and not overwriting is the
			 * whole reason these are numbered.
			 */
			static const unsigned wide[] = { 2u, 4u, 5u };
			unsigned lim[] = { 100u, 10000u, 100000u };
			size_t w;
			int free_one = 0;

			for (w = 0; w < sizeof wide / sizeof wide[0] &&
				    !free_one; w++) {
				unsigned n;

				for (n = 0; n < lim[w]; n++) {
					struct stat es;

					snprintf(path, sizeof path,
						 "%s/%s_%0*u.c", dir, fname,
						 (int)wide[w], n);
					if (stat(path, &es) != 0) {
						free_one = 1;
						break;
					}
				}
			}
			if (!free_one) {
				say_err(e, "%.40s has no free number left",
					fname);
				return;
			}
		}
	}
	f = fopen(path, "w");
	if (!f) {
		say_err(e, "Cannot write %.90s", path);
		return;
	}

	{
		/*
		 * The sample's name, not the path it happened to be at.
		 *
		 * A path names a machine as much as a file - somebody's home
		 * directory, a mount that will not exist next week - and none
		 * of that helps whoever reads this file later. The name is the
		 * part that identifies the sample.
		 */
		const char *base = draft_sample(e);
		char today[24];
		uint32_t m;

		/*
		 * This sample and this author join what the file already
		 * recorded rather than replacing it - the list was read back
		 * out of the block when the rule was opened. Testing a rule
		 * against a second sample used to erase the first.
		 */
		meta_add(e->sample, &(*e->n_sample), MAX_META, base);
		meta_add_who(e->who, &(*e->n_who), MAX_META,
			     meta_user());
		meta_today(today, sizeof today);
		if (!(*e->made)[0])
			snprintf(*e->made, sizeof *e->made, "%s",
				 today);

		fprintf(f, "/*\n * Generated by KOFViewer.\n *\n");
		for (m = 0; m < (*e->n_sample); m++)
			fprintf(f, " * Test sample: %s\n", e->sample[m]);
		if (ob->packer[0])
			fprintf(f, " * Unpacked by: %s\n", ob->packer);
		for (m = 0; m < (*e->n_who); m++)
			fprintf(f, " * Researcher:  %s\n", e->who[m]);
		fprintf(f, " * Created %s, updated %s\n", (*e->made), today);
		/*
		 * The two version numbers that exist and that decide whether
		 * this file still works: the pack format a database must be in
		 * for this build to load it, and the module ABI the compiled
		 * signature must present. The engine has no version string of
		 * its own yet - kofeng.h says so beside kof_engine_db_version -
		 * and inventing one here would put a number in every file that
		 * nothing else in the tree could confirm.
		 */
		fprintf(f, " * Engine:      db format %u, module ABI %u\n",
			(unsigned)KOF_PACK_VERSION,
			(unsigned)KOFSIG_ABI_VERSION);
		fprintf(f, " */\n");
	}
	/*
	 * The author's own line about the module, in a block of its own.
	 *
	 * Separate from the one above deliberately. Both are leading comments
	 * and both come back through the same reader, so what tells them apart
	 * has to be structure rather than wording: the block that opens with
	 * the banner is this tool's, everything else in the header is the
	 * author's. Sharing one block meant the reader had to recognise the
	 * generated lines by their English, and anything a person wrote that
	 * happened to start "Test sample:" would have gone missing.
	 *
	 * Guarded the way every other emitted comment is: the text cannot hold
	 * a newline, so the only thing to stop is a sequence that would close
	 * the comment early.
	 */
	if (e->dr.note[0]) {
		const char *q;

		fprintf(f, "\n/*\n * ");
		for (q = e->dr.note; *q; q++)
			fputc((*q == '*' && q[1] == '/') ? ' ' : *q, f);
		fprintf(f, "\n */\n");
	}
	fprintf(f, "\n#include <kofmod/kofsig.h>\n\n");

	/* The format the object actually is, so the host can rule the module
	 * out without entering it - and so the regions above mean something. */
	fprintf(f, "KOF_TARGET_FORMAT(%s);\n",
		(ob->fmt && ob->ctx.format < FMT_WORD_N)
		? fmt_word[ob->ctx.format] : "KOF_FMT_ANY");
	fprintf(f, "KOF_TARGET_NAME(KOF_MALTYPE_%s, \"%s\");\n\n",
		e->dr.maltype == 0 ? "VIRUS" :
		e->dr.maltype == 1 ? "TROJAN" :
		e->dr.maltype == 2 ? "ROOTKIT" :
		e->dr.maltype == 3 ? "BOTNET" :
		e->dr.maltype == 4 ? "RANSOM" :
		e->dr.maltype == 5 ? "MINER" :
		e->dr.maltype == 6 ? "ADWARE" :
		e->dr.maltype == 7 ? "EXPLOIT" :
		e->dr.maltype == 8 ? "DROPPER" : "HACKTOOL", safe);

	/* One declaration per declared range, spelled as the OR of the region
	 * names it holds - which is what a source has to write and what
	 * somebody grepping for it will search for. */
	if (e->dr.opt_on[OPT_SIZE_MIN])
		fprintf(f, "KOF_TARGET_SIZE_MIN(%llu);\n",
			(unsigned long long)e->dr.opt_val[OPT_SIZE_MIN]);
	if (e->dr.opt_on[OPT_ARCH])
		fprintf(f, "KOF_TARGET_ARCH(KOF_ARCH_%s);\n",
			arch_word[e->dr.opt_val[OPT_ARCH] < ARCH_N
				  ? e->dr.opt_val[OPT_ARCH] : 0].word);
	if (e->dr.opt_on[OPT_SUBTYPE]) {
		uint8_t fm = ob->ctx.format;

		if (fm == KOF_FMT_ELF)
			fprintf(f, "KOF_TARGET_SUBTYPE(KOF_ELF_%s);\n",
				elf_sub[e->dr.opt_val[OPT_SUBTYPE] <
					elf_sub_n
					? e->dr.opt_val[OPT_SUBTYPE] : 0]);
		else if (fm == KOF_FMT_PE)
			fprintf(f, "KOF_TARGET_SUBTYPE(KOF_PE_%s);\n",
				pe_sub[e->dr.opt_val[OPT_SUBTYPE] <
				       pe_sub_n
				       ? e->dr.opt_val[OPT_SUBTYPE] : 0]);
	}
	if (e->dr.opt_on[OPT_SIZE_MIN] || e->dr.opt_on[OPT_ARCH] ||
	    e->dr.opt_on[OPT_SUBTYPE])
		fprintf(f, "\n");

	/*
	 * One declaration per distinct range the matchers actually search.
	 *
	 * Derived here rather than kept as a list, for the same reason the
	 * panel derives the summary: a range has no existence apart from a
	 * matcher naming one, and a kept list goes stale the moment a marker
	 * moves between matchers. This used to walk a list that nothing filled
	 * any more, so every generated module declared no range at all and then
	 * searched one.
	 */
	{
		uint32_t seen[MAX_GROUP], n_seen = 0, g2;

		for (g2 = 0; g2 < e->dr.n_grp; g2++) {
			uint32_t m, b, q;
			char nm[RNG_IDENT_MAX];
			int first = 1;

			if (!grp_count(e, g2))
				continue;
			m = grp_mask(e, g2);
			for (q = 0; q < n_seen; q++)
				if (seen[q] == m)
					break;
			if (q < n_seen)
				continue;
			seen[n_seen++] = m;

			rng_ident(ob->fmt, m, nm, sizeof nm);
			fprintf(f, "KOF_TARGET_RANGE(%s, ", nm);
			/*
			 * The symbol halves first, and by their own names.
			 *
			 * The loop below spells a bit by asking the FORMAT for
			 * it, and these two belong to no format - so they came
			 * out unnamed, `first` stayed set, and the range was
			 * written as KOF_SCAN_ALL. A rule meaning "search the
			 * exports" would have compiled, shipped, and searched
			 * the whole file.
			 */
			if (!(m & KOF_SCAN_ALL) && (m & KOF_SCAN_SYM_IMP)) {
				fprintf(f, "KOF_SCAN_SYM_IMP");
				first = 0;
			}
			if (!(m & KOF_SCAN_ALL) && (m & KOF_SCAN_SYM_EXP)) {
				fprintf(f, "%sKOF_SCAN_SYM_EXP",
					first ? "" : " | ");
				first = 0;
			}
			if (!(m & KOF_SCAN_ALL))
				for (b = 0; b < 30u; b++) {
					const char *w = NULL;

					if (!(m & (1u << b)))
						continue;
					if (ob->fmt)
						for (q = 0;
						     q < ob->fmt->n_regions;
						     q++)
							if (ob->fmt->regions[q]
							    == (1u << b))
								w = ob->fmt->
								  region_name(
								    1u << b);
					if (!w)
						continue;
					fprintf(f, "%s%s",
						first ? "" : " | ", w);
					first = 0;
				}
			if (first)
				fprintf(f, "KOF_SCAN_ALL");
			fprintf(f, ");\n");
		}
		if (n_seen)
			fprintf(f, "\n");
	}

	for (i = 0; i < e->dr.n_decl; i++) {
		const struct decl *d = &e->dr.decl[i];

		if (d->hex) {
			fprintf(f, "KOF_DEFINE_HEXSTR(s%u, \"", i);
			/* The spelling, when the pattern has one that bytes
			 * cannot hold. Otherwise the bytes, which for a
			 * pattern declared from a selection is exact. */
			if (d->hexs[0])
				fputs(d->hexs, f);
			else
				for (j = 0; j < d->nbytes; j++)
					fprintf(f, "%02X", d->bytes[j]);
			fprintf(f, "\");\n");
		} else {
			fprintf(f, "KOF_DEFINE_STR(s%u, \"", i);
			decl_put_literal(f, d->bytes, d->nbytes);
			fprintf(f, "\", %s, %s);\n",
				d->icase ? "KOF_CASE_ICASE" : "KOF_CASE_EXACT",
				d->fullword ? "KOF_WORD_FULLWORD"
					    : "KOF_WORD_SUBSTRING");
		}
	}

	/* Spelled out rather than through KOF_DEFINE_SCAN. The macro expands to
	 * exactly this, and every module in bases/ writes it this way - a
	 * generated file that does not look like the hand written ones is a
	 * file people hesitate to edit. */
	fprintf(f, "\nvoid kof_scan(const struct kof_obj_ctx *ctx)\n{\n");
	/*
	 * A maximum size is a line in the body, not a declaration.
	 *
	 * kofsig.h refuses to have one at KOF_TARGET_SIZE_MIN and says why: an
	 * upper bound declared to the host is escaped by appending bytes nothing
	 * reads, which would turn padding into a way of not being scanned. In
	 * the body it is the module's own logic and costs what any other check
	 * costs.
	 */
	if (e->dr.opt_on[OPT_SIZE_MAX])
		fprintf(f, "\tif (ctx->obj_size > %lluull)\n\t\treturn;\n\n",
			(unsigned long long)e->dr.opt_val[OPT_SIZE_MAX]);
	/*
	 * Conditions, nested the way they were built.
	 *
	 * A condition with children is a gate: it concludes nothing itself and
	 * its children are what happens once it holds. That is exactly the
	 * shape bases/signatures/lkm_rootkit_general.c is written in, and it is
	 * only sayable because a matcher carries no verdict of its own.
	 */
	/*
	 * The shared calls, once each, before anything tests them.
	 *
	 * Named by the matcher that leads the group - see grp_same_call - so
	 * the name does not move when a later matcher is removed.
	 */
	{
		uint32_t g, wrote = 0;

		for (g = 0; g < e->dr.n_grp; g++) {
			if (!grp_shared(e, g) || grp_lead(e, g) != g)
				continue;
			/* The shared call always counts: the group's members
			 * compare against a number, so the leader's own
			 * spelling does not decide the call's kind. */
			/*
			 * uint8_t, because the value cannot exceed 16: the
			 * count is a sum of 0/1 terms and KOF_FS_FOLD takes
			 * at most sixteen names in one call. Measured rather
			 * than assumed - the same module built both ways came
			 * out 165 bytes with uint32_t and 159 with uint8_t,
			 * the 8 bit form comparing in %al instead of loading
			 * and zero extending. Small, and it is also the type
			 * that states the bound.
			 */
			fprintf(f, "\tuint8_t m%u = ", g + 1u);
			emit_call_multi(f, e, g);
			fprintf(f, ";\n");
			wrote++;
		}
		if (wrote)
			fprintf(f, "\n");
	}
	{
		uint32_t prev = e->dr.n_cnd;

		for (k = 0; k < e->dr.n_cnd; k++) {
			if (e->dr.cnd[k].parent >= 0)
				continue;
			emit_cond(f, e, k, 1,
				  prev < e->dr.n_cnd && !e->dr.cnd[prev].join);
			prev = k;
		}
	}
	fprintf(f, "}\n");

	e->dr.gen_ok = ferror(f) == 0;
	fclose(f);
	/*
	 * The PATH, not a sentence about it.
	 *
	 * This used to hold "wrote /some/file.c", which reads well on the
	 * status line and is not a path - so the next Save could not recognise
	 * the file it had just written, fell through to "pick a name nothing is
	 * using", and produced a new numbered copy on every click. Save now
	 * overwrites, which is what Save has always meant; Save As is the one
	 * that starts a new file.
	 */
	snprintf(e->dr.gen_path, sizeof e->dr.gen_path, "%.*s",
		 (int)sizeof e->dr.gen_path - 1, path);
	if (!e->dr.gen_ok) {
		say_err(e, "Could not write the file");
		return;
	}
	/* A source has just appeared in the tree, or an existing one has moved
	 * its lines. Either way what the index knows about where each detection
	 * name sits is now about the file that was there before. */
	src_forget();
	e->dr.warn[0] = 0;
	/* What was written is now what is saved. Without this the draft stayed
	 * dirty forever: the panel kept saying "(unsaved)" and the guard that
	 * refuses a pointless Save never fired. */
	e->dr.saved_hash = draft_hash(e);
}











/*
 * Write one matcher as the call it is.
 *
 * _all and _any short-circuit and _multi cannot - kofsig.h says so at the fold -
 * so the extremes get the macro that stops early rather than a threshold that
 * happens to equal them.
 */
/*
 * The C identifier for a range, spelled from the region words.
 *
 * Both the KOF_TARGET_RANGE that declares it and the search call that names it
 * go through here, because a range that is declared under one name and searched
 * under another is a build error found by the compiler rather than by this - and
 * that used to happen, since the caller passed no format and got WHOLE_FILE for
 * everything.
 */













/* Throw the draft away. Called before loading another signature into it, and
 * only once whoever owns the unsaved work has said so. */
void draft_clear(struct kof_editor *e)
{
	uint32_t i;

	for (i = 0; i < e->dr.n_decl; i++)
		free(e->dr.decl[i].bytes);
	memset(e->dr.decl, 0, sizeof e->dr.decl);
	memset(e->dr.grp, 0, sizeof e->dr.grp);
	memset(e->dr.cnd, 0, sizeof e->dr.cnd);
	memset(e->dr.opt_on, 0, sizeof e->dr.opt_on);
	memset(e->dr.opt_val, 0, sizeof e->dr.opt_val);
	e->dr.n_decl = e->dr.n_grp = e->dr.n_cnd = 0;
	e->dr.n_rng_add = 0;
	e->dr.cur_grp = e->dr.cur_cnd = e->dr.sel_decl = 0;
	e->dr.family[0] = 0;
	e->dr.maltype = 0;
	/* The note belongs to the signature, not to the session. Left behind,
	 * it followed the researcher from one rule into the next and got
	 * written into that one's file on the next save. */
	e->dr.note[0] = 0;
	(*e->foreign_w) = 0;
	(*e->n_sample) = 0;
	(*e->n_who) = 0;
	(*e->made)[0] = 0;
	e->dr.gen_path[0] = 0;
	e->dr.gen_ok = 0;
	e->dr.from_rule = 0;
}

static void meta_add(char tab[][128], uint32_t *n, uint32_t cap, const char *w)
{
	uint32_t i;

	if (!w || !w[0])
		return;
	for (i = 0; i < *n; i++)
		if (!strcmp(tab[i], w))
			return;
	if (*n == cap) {
		memmove(tab[0], tab[1], (cap - 1u) * 128u);
		(*n)--;
	}
	snprintf(tab[*n], 128, "%.127s", w);
	(*n)++;
}

static void meta_add_who(char tab[][48], uint32_t *n, uint32_t cap,
			 const char *w)
{
	uint32_t i;

	if (!w || !w[0])
		return;
	for (i = 0; i < *n; i++)
		if (!strcmp(tab[i], w))
			return;
	if (*n == cap) {
		memmove(tab[0], tab[1], (cap - 1u) * 48u);
		(*n)--;
	}
	snprintf(tab[*n], 48, "%.47s", w);
	(*n)++;
}

/*
 * One line of an existing generated block, back into the fields it came from.
 *
 * Only the lines this writes are read back; anything else in the block is a
 * line an older build wrote or a person added, and it is dropped rather than
 * guessed at. Returns 1 when the line was one of ours.
 */
int meta_take(struct kof_editor *e, const char *t)
{
	static const struct { const char *tag; int what; } tab[] = {
		{ "Test sample:", 0 }, { "Researcher:", 1 }, { "Created", 2 }
	};
	uint32_t i;

	for (i = 0; i < sizeof tab / sizeof tab[0]; i++) {
		size_t n = strlen(tab[i].tag);

		if (strncmp(t, tab[i].tag, n))
			continue;
		t += n;
		while (*t == ' ' || *t == '\t')
			t++;
		if (!*t)
			return 1;
		if (tab[i].what == 0)
			meta_add(e->sample, &(*e->n_sample), MAX_META,
				 t);
		else if (tab[i].what == 1)
			meta_add_who(e->who, &(*e->n_who), MAX_META, t);
		else {
			/* "Created <date>, updated <date>" - the first date is
			 * the one worth keeping; the second is rewritten on
			 * every save and is read back only to be discarded. */
			uint32_t k = 0;

			while (t[k] && t[k] != ',' &&
			       k + 1u < sizeof *e->made)
				k++;
			snprintf(*e->made, sizeof *e->made, "%.*s",
				 (int)k, t);
		}
		return 1;
	}
	return 0;
}





/*
 * One line of the file's leading comment onto the note.
 *
 * Joined with a single space rather than kept as lines, because the note is one
 * field of one line - the shape it is written in and the shape it is edited in.
 */
void head_put(char *dst, size_t cap, size_t *n, const char *s, size_t len)
{
	if (*n && *n + 1 < cap)
		dst[(*n)++] = ' ';
	while (len-- && *n + 1 < cap)
		dst[(*n)++] = *s++;
	dst[*n] = 0;
}





/*
 * IS THIS LINE OF kof_scan SOMETHING THE EDITOR CAN ACTUALLY HOLD.
 *
 * The panel models one shape: matchers made of kof_find_str_* calls, conditions
 * made of ifs, and verdicts. That is most rules and it is not all of them - a
 * hand written module may compute something, loop, call a parser accessor, or
 * do arithmetic on an offset, and none of that has a control on the panel.
 *
 * The old behaviour on such a file was the dangerous one: the unrecognised
 * lines were ignored, a draft was built from whatever was left, `gen_path` was
 * pointed at the original, and Save was offered - so saving a rule the editor
 * had only partly understood REPLACED it with the editor's reduced version.
 * The custom logic was gone and nothing had said so.
 *
 * So the line is checked instead. Punctuation, else, return and the three
 * modelled constructs are accounted for; anything else means this file holds
 * logic the panel does not carry, and the rule opens read only.
 *
 * Deliberately conservative in the safe direction: a construct this does not
 * know costs a save that has to be done in an editor, and the opposite mistake
 * costs somebody's work.
 */
int body_modelled(const char *line)
{
	const char *t = line;

	if (strstr(line, "kof_find_str") || strstr(line, "KOF_SCAN_") ||
	    strstr(line, "if (") || strstr(line, "if("))
		return 1;
	for (; *t; t++) {
		if (*t == ' ' || *t == '\t' || *t == '\r' || *t == '\n')
			continue;
		if (*t == '{' || *t == '}' || *t == ';')
			continue;
		if (!strncmp(t, "else", 4)) {
			t += 3;
			continue;
		}
		if (!strncmp(t, "return", 6)) {
			t += 5;
			continue;
		}
		return 0;
	}
	return 1;
}
