/*
 * kofpat - read the declarations out of a signature source.
 *
 *   kofpat <signature.c> <out.pat.h> <out.names> <out.pre> <out.strs>
 *
 * Emits the identifiers the module compiles against, the detection names, the
 * preconditions the host filters on, and the string table the host searches with.
 * build.sh injects the header with -include, so the source needs no generated include
 * and stays readable on its own.
 *
 * Not a C parser: it looks for its own macro names and reads their arguments. Errors
 * stop the build with a file and line, which is the point of having a compile step -
 * a malformed declaration should fail here rather than silently match nothing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <kofeng/kofpat.h>

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
	int      icase;
	int      fullword;
	uint32_t len;
	uint8_t  bytes[MAX_LITERAL];
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
 * These go to a table beside the blob, never into it. A module reports a family
 * by line number and the host resolves it, so the string is absent from the
 * artifact and renaming a family is a data edit. It also means an out of date
 * table produces "unknown name" rather than the wrong name.
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
 * The region names this understands, with their values.
 *
 * Duplicated from the headers on purpose, and checked: the generator is a host
 * tool that must not include a signature-side header, since kofsig.h and elf.h are
 * written for a freestanding target. The unit test compares this table against the
 * headers so the duplication cannot drift silently.
 */
struct rgn_name {
	const char   *name;
	unsigned long bit;
};

static const struct rgn_name rgn_names[] = {
	{ "KOF_SCAN_ALL",            1ul << 0 },
	{ "KOF_SCAN_ELF_HEADERS",    1ul << 1 },
	{ "KOF_SCAN_ELF_CODE",       1ul << 2 },
	{ "KOF_SCAN_ELF_DATA",       1ul << 3 },
	{ "KOF_SCAN_ELF_NOLOAD",     1ul << 4 },
	{ "KOF_SCAN_ELF_UNCLAIMED",  1ul << 5 },
	{ NULL, 0 }
};

static void err(int line, const char *msg)
{
	fprintf(stderr, "%s:%d: error: %s\n", src_name, line, msg);
	errors++;
}

/*
 * The macros a pattern can be written with. Order matters: the longer names must
 * be tested first, otherwise "kof_find_str" would match the prefix of
 * "kof_find_str_i" and the case folding flag would be dropped silently.
 */
struct macro {
	const char *name;
	int nocase;
};

/* Longer name first: "KOF_DEFINE_STR" must not be found as a prefix of anything
 * else, and a shorter name that is a prefix of a longer one would shadow it. */
static const struct macro macros[] = {
	{ "KOF_DEFINE_RANGE", 1 },   /* nocase field reused as "is a range" */
	{ "KOF_DEFINE_STR",   0 },
	{ NULL, 0 }
};

/*
 * Find argument number `want` (1-based) of a macro invocation starting at p.
 *
 * Picking a literal by scanning for the first quote was wrong in the worst way: a call
 * like kof_find_str(rgn_sec_named(ctx, ".comment"), "GCC: (GNU)") compiled and
 * searched for ".comment". No error, just a signature looking for the wrong bytes.
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
 * KOF_STR(name, "pat", regions, casing, word).
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

	/* Only whitespace may precede the quote. Scanning ahead for one would
	 * accept a non-literal second argument and silently take a literal from
	 * further along the line. */
	while (*p == ' ' || *p == '\t')
		p++;
	if (*p != '"') {
		err(line, "second argument of KOF_STR must be a string literal");
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
 * Read the region mask, argument 2 of KOF_DEFINE_RANGE, and OR it into the module
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
				fprintf(stderr, "%s:%d: error: region \"%s\" is not a "
					"known region name; a range must be an OR of "
					"region names so the host knows where to "
					"search and when it can skip\n",
					src_name, line, tok);
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
			err(line, "the first argument of KOF_STR must be a plain "
				  "identifier: it becomes the name kof_find uses");
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
		err(line, "KOF_STR without a name");
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

	/* Argument 2 of KOF_MATCH(ctx, "name", LEVEL), located the same way as a
	 * pattern rather than by scanning for a quote: the level argument is a
	 * macro and could contain one. */
	q = nth_arg(p, 2, line);
	if (!q)
		return 0;
	while (*q == ' ' || *q == '\t')
		q++;
	if (*q != '"') {
		err(line, "second argument of KOF_MATCH must be a name literal");
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
	p = strstr(at, "KOF_MATCH");
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
	 * buffer for one would treat a bare mention of the macro as an invocation
	 * and then read arguments from whatever call came next in the file.
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
		if (read_name(p, lineno, names[nnames].text,
			      sizeof names[nnames].text))
			nnames++;
		return;
	}

	/* m->nocase is reused as "this is a range declaration". */
	if (m->nocase) {
		struct rng *r;
		if (nrngs >= MAX_PATTERNS) {
			err(lineno, "too many declared ranges");
			return;
		}
		if (nrngs >= KOF_PAT_MAX_IN_SET) {
			err(lineno, "more than 64 declared ranges");
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
	if (npats >= KOF_PAT_MAX_IN_SET) {
		err(lineno, "more than 64 declared strings; the answers are a "
			    "64 bit mask");
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
 * Emit the record the host searches with.
 *
 * Tab separated so it is readable and diffable while there is no container format;
 * the fields are the ones the host needs and nothing else. The literal is last
 * because it is the only field that can contain anything, so nothing has to be
 * escaped to keep the columns parseable.
 */
static void emit_str_record(FILE *out, const struct pat *p, int idx)
{
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

int main(int argc, char **argv)
{
	FILE *out;
	char *src;
	size_t src_len, pos = 0;
	int lineno = 0, i;

	if (argc != 6) {
		fprintf(stderr, "usage: %s <signature.c> <out.pat.h> <out.names> "
				"<out.pre> <out.strs>\n", argv[0]);
		return 2;
	}
	src_name = argv[1];

	src = slurp(argv[1], &src_len);
	if (!src) {
		fprintf(stderr, "kofpat: cannot read %s\n", argv[1]);
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

	out = fopen(argv[2], "w");
	if (!out) {
		fprintf(stderr, "kofpat: cannot write %s\n", argv[2]);
		return 2;
	}
	fprintf(out, "/* generated by kofpat from %s - do not edit */\n", argv[1]);
	for (i = 0; i < nrngs; i++)
		emit_rng_id(out, &rngs[i], i);
	for (i = 0; i < npats; i++)
		emit_str_id(out, &pats[i], i);
	fclose(out);

	out = fopen(argv[3], "w");
	if (!out) {
		fprintf(stderr, "kofpat: cannot write %s\n", argv[3]);
		return 2;
	}
	for (i = 0; i < nnames; i++)
		fprintf(out, "%d\t%s\n", names[i].line, names[i].text);
	fclose(out);

	/*
	 * The preconditions derived from the source, for the host to filter on
	 * without loading or running the module. build.sh merges this with what it
	 * extracts itself - the target mask - into the module's .meta.
	 */
	out = fopen(argv[4], "w");
	if (!out) {
		fprintf(stderr, "kofpat: cannot write %s\n", argv[4]);
		free(src);
		return 2;
	}
	fprintf(out, "scan_mask=%lu\n", scan_mask);
	fprintf(out, "nstr=%d\n", npats);
	fclose(out);

	/* The string table, for the host to search with. */
	out = fopen(argv[5], "w");
	if (!out) {
		fprintf(stderr, "kofpat: cannot write %s\n", argv[5]);
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
