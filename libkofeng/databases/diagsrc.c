/*
 * diagsrc.c - see diagsrc.h.
 *
 * THE VOCABULARY IS READ OUT OF THE REAL ENUMS through the X-macro lists below,
 * so the number a rule's word stands for comes from the header through the
 * compiler and a renumbered group cannot leave this behind. What CAN go stale is
 * a capability missing from a list, and kof_dsrc_cap_table_check refuses the
 * build when one is - the role table learnt that lesson the expensive way.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kofmod/kofsig.h>
#include <kofmod/kofpathogen.h>
#include <kofmod/elf.h>      /* KOF_PERM_*, KOF_ELF_*        */
#include <kofmod/pe.h>       /* KOF_PE_PERM_*                */
#include "../analyzers/nucleo/nucleo.h"
#include "diagsrc.h"

/*
 * A NAME TO A NUMBER, through the one table that defines both.
 *
 * The source says KOF_NUCLEO_ALLOC_EXEC and the record holds its value, and
 * the two must be the same thing or a rule means something other than what
 * it says.
 */
#define KOF_NUCLEO_IDENTS(X) \
	X(KOF_NUCLEO_ANTI_DEBUG) X(KOF_NUCLEO_CRED_SET) X(KOF_NUCLEO_CRED_PREPARE) \
	X(KOF_NUCLEO_CRYPTO) X(KOF_NUCLEO_EXEC_REG) X(KOF_NUCLEO_FD_REDIR) \
	X(KOF_NUCLEO_FD_NONBLOCK) X(KOF_NUCLEO_NET_HDRINCL) \
	X(KOF_NUCLEO_FILE_DELETE) X(KOF_NUCLEO_FILE_OPEN) X(KOF_NUCLEO_PERM_SET) \
	X(KOF_NUCLEO_READ) X(KOF_NUCLEO_FILE_RENAME) X(KOF_NUCLEO_TIMESTOMP) \
	X(KOF_NUCLEO_WRITE) X(KOF_NUCLEO_HTTP_CONNECT) X(KOF_NUCLEO_HTTP_FETCH) \
	X(KOF_NUCLEO_HTTP_OPEN) X(KOF_NUCLEO_HTTP_RECV) X(KOF_NUCLEO_HTTP_SEND) \
	X(KOF_NUCLEO_CAPTURE) X(KOF_NUCLEO_COPY_FROM_USER) X(KOF_NUCLEO_COPY_TO_USER) \
	X(KOF_NUCLEO_PROT_OFF) X(KOF_NUCLEO_HOOK) X(KOF_NUCLEO_KPROBE_REG) \
	X(KOF_NUCLEO_KPROBE_UNREG) X(KOF_NUCLEO_KSYM_LOOKUP) X(KOF_NUCLEO_LIST_HIDE) \
	X(KOF_NUCLEO_MOD_LOAD) X(KOF_NUCLEO_SYMBOL_GET) X(KOF_NUCLEO_RESOLVE) \
	X(KOF_NUCLEO_CALL_REG) X(KOF_NUCLEO_LIB_OPEN) X(KOF_NUCLEO_NAME_HASH) \
	X(KOF_NUCLEO_SELF_RESOLVE) X(KOF_NUCLEO_ALLOC_EXEC) X(KOF_NUCLEO_HEAP) \
	X(KOF_NUCLEO_ALLOC) X(KOF_NUCLEO_MEMFD) X(KOF_NUCLEO_ACTION_READ) \
	X(KOF_NUCLEO_ACTION_WRITE) X(KOF_NUCLEO_MEM_READ) X(KOF_NUCLEO_MEM_WRITE) \
	X(KOF_NUCLEO_JAIL) X(KOF_NUCLEO_NET_ACCEPT) X(KOF_NUCLEO_NET_ADDR) \
	X(KOF_NUCLEO_NET_BIND) X(KOF_NUCLEO_NET_CONNECT) X(KOF_NUCLEO_DNS) \
	X(KOF_NUCLEO_NET_LISTEN) X(KOF_NUCLEO_NET_OPEN) X(KOF_NUCLEO_NET_RAW) \
	X(KOF_NUCLEO_NET_READ) X(KOF_NUCLEO_NET_WRITE) X(KOF_NUCLEO_PIPE_OPEN) \
	X(KOF_NUCLEO_PIPE) X(KOF_NUCLEO_BACKGROUND) X(KOF_NUCLEO_PROC_EXEC) \
	X(KOF_NUCLEO_PROC_LIST) X(KOF_NUCLEO_SPAWN) X(KOF_NUCLEO_PROC_MEM) \
	X(KOF_NUCLEO_PTRACE) X(KOF_NUCLEO_EXEC_IMAGE) X(KOF_NUCLEO_REG_OPEN) \
	X(KOF_NUCLEO_REG_SET) X(KOF_NUCLEO_SELF_HIDE) X(KOF_NUCLEO_SVC_INSTALL) \
	X(KOF_NUCLEO_SLEEP) X(KOF_NUCLEO_THREAD)

/*
 * THE WORDS A CONDITION MAY BE WRITTEN IN - the facts the engine publishes
 * and the values they are compared against.
 *
 * Both halves are read out of the real enums through the X-macro, for the
 * reason the capability table above gives: the number comes from the header
 * through the compiler, so nothing here can drift from what the engine
 * means. A word missing from the list is a loud failure at build time; a
 * word with the wrong number is not possible.
 */
#define KOF_FACT_IDENTS(X) \
	X(KOF_FACT_ENTRY_PERM) X(KOF_FACT_MAP_PERM) \
	X(KOF_FACT_SECTIONS)   X(KOF_FACT_OBJ_KIND) \
	X(KOF_FACT_FORMAT)

#define KOF_WHEN_VALUES(X) \
	X(KOF_PERM_R) X(KOF_PERM_W) X(KOF_PERM_X) \
	X(KOF_PE_PERM_R) X(KOF_PE_PERM_W) X(KOF_PE_PERM_X) \
	X(KOF_ELF_REL) X(KOF_ELF_EXEC) X(KOF_ELF_DYN) X(KOF_ELF_CORE) \
	X(KOF_FMT_UNKNOWN) X(KOF_FMT_ELF) X(KOF_FMT_PE) X(KOF_FMT_MACHO) \
	X(KOF_FMT_SCRIPT) X(KOF_FMT_TEXT) X(KOF_FMT_GZIP) X(KOF_FMT_DOCOLE) \
	X(KOF_FMT_ZIP) X(KOF_FMT_DOCZIP) X(KOF_FMT_TAR) X(KOF_FMT_7Z) \
	X(KOF_FMT_RAR) X(KOF_FMT_XZ) X(KOF_FMT_RTF) X(KOF_FMT_PDF) \
	X(KOF_FMT_IMAGE) X(KOF_FMT_FONT) X(KOF_FMT_BZIP2) X(KOF_FMT_CHM) \
	X(KOF_FMT_CAB) X(KOF_FMT_LHA) X(KOF_FMT_ARJ) X(KOF_FMT_LNK) X(KOF_FMT_REG)


static const struct { const char *w; uint64_t v; } when_word[] = {
#define KDS_WHEN_ROW(id) { #id, (uint64_t)(id) },
	KOF_FACT_IDENTS(KDS_WHEN_ROW)
	KOF_WHEN_VALUES(KDS_WHEN_ROW)
#undef KDS_WHEN_ROW
};

static const struct { const char *w; uint16_t v; } cap_ident[] = {
#define KDS_CAP_ROW(id) { #id, (uint16_t)(id) },
	KOF_NUCLEO_IDENTS(KDS_CAP_ROW)
#undef KDS_CAP_ROW
};

#define N_WHEN (sizeof when_word / sizeof when_word[0])
#define N_CAP  (sizeof cap_ident / sizeof cap_ident[0])

/* ---- the vocabulary ------------------------------------------------------- */

/*
 * A CAP THE VOCABULARY HAS AND THIS LIST DOES NOT is a diagnose that cannot
 * name it, so it is a build failure and not a warning. Walking the whole
 * capability space costs a few thousand comparisons once per build.
 */
int kof_dsrc_cap_table_check(void)
{
	unsigned c, bad = 0;
	size_t i;

	for (c = 1u; c < 0x10000u; c++) {
		const char *nm;

		if (!KOF_NUCLEO_VALID(c))
			continue;
		/* "?" is what the name table answers for a value inside a
		 * group's range that no capability uses - KOF_NUCLEO_VALID is a
		 * range test and the groups are not full. */
		nm = kof_flow_cap_name((uint16_t)c);
		if (!nm || strcmp(nm, "?") == 0)
			continue;
		for (i = 0; i < N_CAP; i++)
			if (cap_ident[i].v == (uint16_t)c)
				break;
		if (i == N_CAP) {
			fprintf(stderr, "FAIL: capability \"%s\" (0x%04x) is "
					"missing from KOF_NUCLEO_IDENTS - no "
					"diagnose can name it\n", nm, c);
			bad = 1;
		}
	}
	return !bad;
}

/*
 * The source writes the ENUMERATOR, so this is a lookup and not a search.
 * It used to take the display name in quotes and walk the capability space
 * asking kof_flow_cap_name what each value was called; the display name is
 * what a report prints, and spelling a rule in it meant the vocabulary was
 * written two ways for two audiences.
 */
int kof_dsrc_cap_of(const char *w, uint16_t *out)
{
	size_t i;

	for (i = 0; i < N_CAP; i++)
		if (strcmp(w, cap_ident[i].w) == 0) {
			*out = cap_ident[i].v;
			return 1;
		}
	return 0;
}

const char *kof_dsrc_cap_word(uint16_t cap)
{
	size_t i;

	for (i = 0; i < N_CAP; i++)
		if (cap_ident[i].v == cap)
			return cap_ident[i].w;
	return NULL;
}

size_t kof_dsrc_cap_count(void)
{
	return N_CAP;
}

const char *kof_dsrc_cap_at(size_t i, uint16_t *cap)
{
	if (i >= N_CAP)
		return NULL;
	if (cap)
		*cap = cap_ident[i].v;
	return cap_ident[i].w;
}

/*
 * A word, or a plain number. `|` joins them, because a permission is a
 * mask and writing it any other way would mean the source could not say
 * "writable and executable" in the engine's own words.
 */
static int when_value(const char *w, uint64_t *out)
{
	char tmp[128];
	size_t n = strlen(w), i;
	char *tok, *next;
	uint64_t v = 0;

	if (n >= sizeof tmp)
		return 0;
	memcpy(tmp, w, n + 1u);
	*out = 0;
	/* Split on '|' by hand: strtok_r is POSIX and this is built everywhere. */
	for (tok = tmp; tok; tok = next) {
		char *e = NULL;
		unsigned long long num;

		next = strchr(tok, '|');
		if (next)
			*next++ = 0;
		while (*tok == ' ' || *tok == '\t')
			tok++;
		for (i = strlen(tok); i && (tok[i - 1u] == ' ' ||
					    tok[i - 1u] == '\t'); i--)
			tok[i - 1u] = 0;
		if (!*tok)
			return 0;
		for (i = 0; i < N_WHEN; i++)
			if (strcmp(tok, when_word[i].w) == 0)
				break;
		if (i < N_WHEN) {
			v |= when_word[i].v;
			continue;
		}
		num = strtoull(tok, &e, 0);
		if (!e || *e)
			return 0;
		v |= (uint64_t)num;
	}
	*out = v;
	return 1;
}

/* Which kind of edge a node demands, when it says. Absent is not an error:
 * see KOF_DIAG_B_PRODUCED - a diagnose that does not care accepts either. */
static int kind_of(const char *w, uint8_t *out)
{
	if (strcmp(w, "KOF_DIAG_B_PRODUCED") == 0) {
		*out = KOF_DIAG_B_PRODUCED;
		return 1;
	}
	if (strcmp(w, "KOF_DIAG_B_SHARED") == 0) {
		*out = KOF_DIAG_B_SHARED;
		return 1;
	}
	return 0;
}

/* The flags a node may demand. Small and closed; a word not here is an
 * error rather than a zero, because a demanded flag silently dropped is a
 * diagnose that matches more than it says. */
static int flag_of(const char *w, uint16_t *out)
{
	if (strcmp(w, "0") == 0)             { *out = 0; return 1; }
	if (strcmp(w, "KOF_FLOWF_WX") == 0)  { *out = KOF_FLOWF_WX; return 1; }
	return 0;
}

/* Pull the i-th comma separated argument out of "MACRO(a, b, c)". */
int kof_dsrc_arg(const char *p, int i, char *out, size_t cap)
{
	const char *q = strchr(p, '(');
	int depth = 0, n = 0;

	if (!q)
		return 0;
	q++;
	while (*q && i > 0) {
		if (*q == '(') depth++;
		else if (*q == ')') { if (!depth) return 0; depth--; }
		else if (*q == ',' && !depth) i--;
		q++;
	}
	/*
	 * ANY WHITESPACE, NEWLINE INCLUDED. This was written for a diagnose
	 * declaration, one call to a line, and a space and a tab were all that
	 * could precede an argument. A verdict's call is wrapped like any other
	 * C - kof_diag_share(CAP, A,\n\t\t\t   B) - and the argument after the
	 * break began with a newline that was kept as part of the name, so the
	 * name never matched anything.
	 */
	while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r')
		q++;
	while (*q && *q != ',' && *q != ')' && (size_t)n + 1 < cap) {
		if (*q == '(') depth++;
		if (*q == ')') { if (!depth) break; depth--; }
		out[n++] = *q++;
	}
	while (n > 0 && (out[n - 1] == ' ' || out[n - 1] == '\t' ||
			 out[n - 1] == '\n' || out[n - 1] == '\r'))
		n--;
	out[n] = 0;
	return n > 0;
}

/* ---- reading -------------------------------------------------------------- */

static void say_err(const struct kof_dsrc_report *r, int *n, int line,
		    const char *msg)
{
	(*n)++;
	if (r && r->error)
		r->error(r->ud, line, msg);
}

static void say_warn(const struct kof_dsrc_report *r, const char *msg)
{
	if (r && r->warn)
		r->warn(r->ud, msg);
}

/*
 * THE CODE OF A TEXT, with the comments blanked - every comment byte but the
 * newline becomes a space, so a position in the result is the same position in
 * the source. The reader matched a macro's name anywhere in the line, which is
 * right for a file of declarations and wrong for a file of declarations and long
 * comments: a patch deletes the line of a declaration it removes, and a comment
 * that mentioned the macro, if read as one, would be deleted with it. A string
 * is kept whole, so a comment opener inside one is text.
 */
static char *blank_comments(const char *t, size_t n)
{
	char *o = malloc(n + 1u);
	size_t i = 0;
	int in_comment = 0, in_str = 0;

	if (!o)
		return NULL;
	memcpy(o, t, n);
	o[n] = 0;
	while (i < n) {
		char c = t[i];

		if (in_comment) {
			if (c == '*' && i + 1u < n && t[i + 1u] == '/') {
				o[i] = o[i + 1u] = ' ';
				in_comment = 0;
				i += 2u;
				continue;
			}
			if (c != '\n')
				o[i] = ' ';
			i++;
			continue;
		}
		if (in_str) {
			if (c == '\\' && i + 1u < n)
				i++;
			else if (c == '"' || c == '\n')
				in_str = 0;
			i++;
			continue;
		}
		if (c == '"') {
			in_str = 1;
			i++;
			continue;
		}
		if (c == '/' && i + 1u < n && t[i + 1u] == '*') {
			o[i] = o[i + 1u] = ' ';
			in_comment = 1;
			i += 2u;
			continue;
		}
		if (c == '/' && i + 1u < n && t[i + 1u] == '/') {
			while (i < n && t[i] != '\n')
				o[i++] = ' ';
			continue;
		}
		i++;
	}
	return o;
}

/* ---- the verdict's condition ------------------------------------------------ */

static const char *ws(const char *p)
{
	while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
		p++;
	return p;
}

static int is_id(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
	       (c >= '0' && c <= '9');
}

/* The literal `w` after any whitespace, and not as the front of a longer word. */
static int lit(const char **pp, const char *w)
{
	const char *p = ws(*pp);
	size_t L = strlen(w);

	if (strncmp(p, w, L))
		return 0;
	if (is_id(w[L - 1u]) && is_id(p[L]))
		return 0;
	*pp = p + L;
	return 1;
}

static int word(const char **pp, char *out, size_t cap)
{
	const char *p = ws(*pp);
	size_t n = 0;

	while (is_id(p[n]))
		n++;
	if (!n || n >= cap || (p[0] >= '0' && p[0] <= '9'))
		return 0;
	memcpy(out, p, n);
	out[n] = 0;
	*pp = p + n;
	return 1;
}

static unsigned line_at(const char *code, size_t pos)
{
	unsigned l = 1;
	size_t i;

	for (i = 0; i < pos; i++)
		if (code[i] == '\n')
			l++;
	return l;
}

/*
 * THE CONDITION, READ STRICTLY. The shape is the whole grammar:
 *
 *     void kof_scan(...) { if ( term && term ... ) KOF_SCAN_INFECT(word); }
 *
 * and a file that reads kof_diag anywhere but in it is not read at all, with the
 * reason. `code` has its comments blanked and is the same length as the source,
 * so the positions it yields are the source's.
 */
static int cond_parse(const char *code, size_t n, struct kof_dsrc *d,
		      const struct kof_dsrc_report *r)
{
	const char *p, *q;
	struct kof_dsrc_cond *c = &d->cond;
	int errs = 0;
	unsigned line;

	(void)n;
	if (!strstr(code, "kof_diag(") && !strstr(code, "kof_diag_share(") &&
	    !strstr(code, "kof_diag_str_"))
		return 0;
	p = strstr(code, "kof_scan");
	if (!p) {
		say_err(r, &errs, 0, "a verdict that reads a diagnose has no kof_scan");
		return errs;
	}
	q = strchr(p, '{');
	if (!q) {
		say_err(r, &errs, (int)line_at(code, (size_t)(p - code)),
			"kof_scan has no body");
		return errs;
	}
	p = q + 1;
	line = line_at(code, (size_t)(p - code));
	{
		const char *ifp = ws(p);

		if (!lit(&p, "if") || !lit(&p, "(")) {
			say_err(r, &errs, (int)line,
				"the body must be one if over kof_diag terms");
			return errs;
		}
		c->at = (size_t)(ifp - code);
	}
	line = line_at(code, c->at);
	for (;;) {
		struct kof_dsrc_term *t;
		char capw[KOF_DSRC_NAME_LEN];

		if (c->n >= KOF_DSRC_MAX_TERM) {
			say_err(r, &errs, (int)line, "too many terms");
			return errs;
		}
		t = &c->t[c->n];
		memset(t, 0, sizeof *t);
		if (lit(&p, "kof_diag_share")) {
			if (!lit(&p, "(") || !word(&p, capw, sizeof capw) ||
			    !kof_dsrc_cap_of(capw, &t->cap) || !lit(&p, ",") ||
			    !word(&p, t->a, sizeof t->a) || !lit(&p, ",") ||
			    !word(&p, t->b, sizeof t->b) || !lit(&p, ")")) {
				say_err(r, &errs, (int)line,
					"kof_diag_share(KOF_NUCLEO_*, A, B)");
				return errs;
			}
			t->kind = KVT_SHARE;
		} else if (lit(&p, "kof_diag_str_any") || lit(&p, "kof_diag_str_all")) {
			t->kind = p[-1] == 'y' ? KVT_STR_ANY : KVT_STR_ALL;
			if (!lit(&p, "(") || !word(&p, t->a, sizeof t->a)) {
				say_err(r, &errs, (int)line,
					"kof_diag_str_any(NAME, \"string\", ...)");
				return errs;
			}
			while (lit(&p, ",")) {
				const char *e;
				size_t L;

				p = ws(p);
				if (*p != '"' || t->n_str >= KOF_DSRC_MAX_STR) {
					say_err(r, &errs, (int)line,
						"a quoted string, at most eight");
					return errs;
				}
				e = strchr(p + 1, '"');
				L = e ? (size_t)(e - p - 1) : 0u;
				if (!e || !L || L >= KOF_DSRC_STR_LEN ||
				    memchr(p + 1, '\\', L) || memchr(p + 1, '\n', L)) {
					say_err(r, &errs, (int)line,
						"a plain string of up to 47 bytes");
					return errs;
				}
				memcpy(t->str[t->n_str], p + 1, L);
				t->str[t->n_str][L] = 0;
				t->n_str++;
				p = e + 1;
			}
			if (!t->n_str || !lit(&p, ")")) {
				say_err(r, &errs, (int)line,
					"kof_diag_str_any(NAME, \"string\", ...)");
				return errs;
			}
		} else if (lit(&p, "kof_diag")) {
			if (!lit(&p, "(") || !word(&p, t->a, sizeof t->a) ||
			    !lit(&p, ")")) {
				say_err(r, &errs, (int)line, "kof_diag(NAME)");
				return errs;
			}
		} else {
			say_err(r, &errs, (int)line,
				"a term is kof_diag, kof_diag_share or kof_diag_str_*");
			return errs;
		}
		c->n++;
		if (lit(&p, "&&"))
			continue;
		if (lit(&p, ")"))
			break;
		say_err(r, &errs, (int)line,
			"terms are joined by && and nothing else");
		return errs;
	}
	c->end = (size_t)(p - code);
	if (!lit(&p, "KOF_SCAN_INFECT") || !lit(&p, "(") ||
	    !word(&p, c->infect, sizeof c->infect) || !lit(&p, ")") ||
	    !lit(&p, ";") || !lit(&p, "}")) {
		say_err(r, &errs, (int)line_at(code, c->end),
			"the if must be followed by KOF_SCAN_INFECT(word); and "
			"the end of the function");
		return errs;
	}
	d->has_cond = 1;
	return 0;
}

static struct kof_dsrc_item *add_item(struct kof_dsrc *d, int *errs,
				      const struct kof_dsrc_report *r,
				      unsigned line, unsigned kind)
{
	struct kof_dsrc_item *it;

	if (d->n >= KOF_DSRC_MAX_ITEM) {
		say_err(r, errs, (int)line, "too many declarations");
		return NULL;
	}
	it = &d->item[d->n];
	memset(it, 0, sizeof *it);
	it->kind = (uint8_t)kind;
	it->line = line;
	return it;
}

int kof_dsrc_parse(const char *text, size_t n, struct kof_dsrc *d,
		   const struct kof_dsrc_report *r)
{
	char line[2048], a[5][96];
	int errs = 0;
	unsigned lineno = 0;
	size_t at = 0;
	char *code = blank_comments(text, n);

	memset(d, 0, sizeof *d);
	if (!code) {
		say_err(r, &errs, 0, "out of memory");
		return errs;
	}
	while (at < n) {
		size_t e = at, len;
		char *p;
		struct kof_dsrc_item *it;

		while (e < n && text[e] != '\n')
			e++;
		len = e - at;
		lineno++;
		if (len >= sizeof line)
			len = sizeof line - 1u;
		memcpy(line, code + at, len);
		line[len] = 0;
		at = e < n ? e + 1u : e;

		if ((p = strstr(line, "KOF_DIAG_NAME(")) != NULL) {
			if (!kof_dsrc_arg(p, 0, a[0], sizeof a[0]) ||
			    strlen(a[0]) >= KOF_DSRC_NAME_LEN) {
				say_err(r, &errs, (int)lineno,
					"KOF_DIAG_NAME wants a name");
				continue;
			}
			if (!(it = add_item(d, &errs, r, lineno, KDS_NAME)))
				continue;
			memcpy(it->s1, a[0], strlen(a[0]) + 1u);
			d->n++;
		} else if (strstr(line, "KOF_DIAG_USE_EMU(") != NULL) {
			if (!(it = add_item(d, &errs, r, lineno, KDS_USE_EMU)))
				continue;
			d->n++;
		} else if ((p = strstr(line, "KOF_DIAG_ANALYSIS(")) != NULL) {
			unsigned bits = 0;

			if (strstr(p, "KOF_DIAG_ANALYSIS_SYSCALL"))
				bits |= KOF_DIAG_ANALYSIS_SYSCALL;
			if (strstr(p, "KOF_DIAG_ANALYSIS_SYMBOL"))
				bits |= KOF_DIAG_ANALYSIS_SYMBOL;
			if (strstr(p, "KOF_DIAG_ANALYSIS_EMULATE"))
				say_err(r, &errs, (int)lineno,
					"the emulator is not a way to find "
					"nodes: write KOF_DIAG_USE_EMU()");
			if (strstr(p, "KOF_DIAG_ANALYSIS_APIHASH"))
				bits |= KOF_DIAG_ANALYSIS_APIHASH;
			if (!bits) {
				say_err(r, &errs, (int)lineno,
					"KOF_DIAG_ANALYSIS names no analysis");
				continue;
			}
			if (!(it = add_item(d, &errs, r, lineno, KDS_ANALYSIS)))
				continue;
			it->a = (uint16_t)bits;
			d->n++;
		} else if ((p = strstr(line, "KOF_DIAG_DECLARE_HEAD(")) != NULL) {
			uint16_t cap, fl;

			if (!kof_dsrc_arg(p, 0, a[0], sizeof a[0]) ||
			    !kof_dsrc_arg(p, 1, a[1], sizeof a[1])) {
				say_err(r, &errs, (int)lineno,
					"KOF_DIAG_DECLARE_HEAD(cap, flags)");
				continue;
			}
			if (!kof_dsrc_cap_of(a[0], &cap)) {
				say_err(r, &errs, (int)lineno, "not a capability");
				continue;
			}
			if (!flag_of(a[1], &fl)) {
				say_err(r, &errs, (int)lineno, "not a node flag");
				continue;
			}
			if (!(it = add_item(d, &errs, r, lineno, KDS_HEAD)))
				continue;
			it->a = cap;
			it->b = fl;
			d->n++;
		} else if ((p = strstr(line, "KOF_DIAG_DECLARE_TAIL(")) != NULL) {
			uint16_t cap;
			uint8_t kb = 0;

			if (!kof_dsrc_arg(p, 0, a[0], sizeof a[0])) {
				say_err(r, &errs, (int)lineno,
					"KOF_DIAG_DECLARE_TAIL(cap[, kind])");
				continue;
			}
			if (!kof_dsrc_cap_of(a[0], &cap)) {
				say_err(r, &errs, (int)lineno, "not a capability");
				continue;
			}
			/* the optional kind - absent means either */
			if (kof_dsrc_arg(p, 1, a[1], sizeof a[1]) &&
			    !kind_of(a[1], &kb)) {
				say_err(r, &errs, (int)lineno,
					"not a link kind: want KOF_DIAG_B_PRODUCED "
					"or KOF_DIAG_B_SHARED");
				continue;
			}
			if (!(it = add_item(d, &errs, r, lineno, KDS_TAIL)))
				continue;
			it->a = cap;
			it->b = kb;
			d->n++;
		} else if ((p = strstr(line, "KOF_DIAG_ACTION(")) != NULL) {
			uint16_t hc, ac;
			char *end = NULL;
			unsigned long long v;

			if (!kof_dsrc_arg(p, 0, a[0], sizeof a[0]) ||
			    !kof_dsrc_arg(p, 1, a[1], sizeof a[1]) ||
			    !kof_dsrc_arg(p, 2, a[2], sizeof a[2])) {
				say_err(r, &errs, (int)lineno,
					"KOF_DIAG_ACTION(head, action, value)");
				continue;
			}
			if (!kof_dsrc_cap_of(a[0], &hc) ||
			    !kof_dsrc_cap_of(a[1], &ac)) {
				say_err(r, &errs, (int)lineno, "not a capability");
				continue;
			}
			v = strtoull(a[2], &end, 0);
			if (!end || *end) {
				say_err(r, &errs, (int)lineno,
					"KOF_DIAG_ACTION wants a constant");
				continue;
			}
			if (!(it = add_item(d, &errs, r, lineno, KDS_ACTION)))
				continue;
			it->a = hc;
			it->b = ac;
			it->v = (uint64_t)v;
			d->n++;
		} else if ((p = strstr(line, "KOF_DIAG_DECLARE_SYMBOL(")) != NULL) {
			size_t L;

			/* A symbol is named by a string the engine cannot know in
			 * advance, so it is the one declaration that carries a
			 * label: the relation below refers to it by that. */
			if (!kof_dsrc_arg(p, 0, a[0], sizeof a[0]) ||
			    !kof_dsrc_arg(p, 1, a[1], sizeof a[1])) {
				say_err(r, &errs, (int)lineno,
					"KOF_DIAG_DECLARE_SYMBOL(label, \"name\")");
				continue;
			}
			L = strlen(a[1]);
			if (L < 3u || a[1][0] != '"' || a[1][L - 1u] != '"' ||
			    L - 2u >= KOF_DSRC_NAME_LEN ||
			    strlen(a[0]) >= 32u ||
			    L - 2u >= KOF_DIAG_NEED_LEN) {
				say_err(r, &errs, (int)lineno,
					"KOF_DIAG_DECLARE_SYMBOL wants a short "
					"label and a quoted symbol name");
				continue;
			}
			if (!(it = add_item(d, &errs, r, lineno, KDS_SYMBOL)))
				continue;
			memcpy(it->s1, a[0], strlen(a[0]) + 1u);
			memcpy(it->s2, a[1] + 1, L - 2u);
			it->s2[L - 2u] = 0;
			d->n++;
		} else if ((p = strstr(line, "KOF_DIAG_HAS_FIELD(")) != NULL) {
			uint16_t cap;

			if (!kof_dsrc_arg(p, 0, a[0], sizeof a[0]) ||
			    !kof_dsrc_arg(p, 1, a[1], sizeof a[1]) ||
			    !kof_dsrc_cap_of(a[0], &cap)) {
				say_err(r, &errs, (int)lineno,
					"KOF_DIAG_HAS_FIELD(capability, symbol)");
				continue;
			}
			if (strlen(a[1]) >= 32u) {
				say_err(r, &errs, (int)lineno,
					"no symbol declared with that label");
				continue;
			}
			if (!(it = add_item(d, &errs, r, lineno, KDS_FIELD)))
				continue;
			it->a = cap;
			memcpy(it->s1, a[1], strlen(a[1]) + 1u);
			d->n++;
		} else if ((p = strstr(line, "KOF_TARGET_FORMAT(")) != NULL ||
			   (p = strstr(line, "KOF_TARGET_SUBTYPE(")) != NULL) {
			/* THE TARGET OF A DIAGNOSE IS DECLARED AS A SIGNATURE'S IS:
			 * the same two words, read here into the same conditions the
			 * engine already evaluates before it starts. One vocabulary
			 * for "what kind of file", two readers of it. */
			int is_fmt = strstr(line, "KOF_TARGET_FORMAT(") != NULL;
			uint64_t vv = 0;

			if (!kof_dsrc_arg(p, 0, a[0], sizeof a[0]) ||
			    !when_value(a[0], &vv)) {
				say_err(r, &errs, (int)lineno,
					"KOF_TARGET_FORMAT / KOF_TARGET_SUBTYPE "
					"want a constant or words joined by |");
				continue;
			}
			if (!(it = add_item(d, &errs, r, lineno,
					    is_fmt ? KDS_FORMAT : KDS_SUBTYPE)))
				continue;
			it->v = vv;
			/* The words as written: `KOF_FMT_ELF | KOF_FMT_UNKNOWN` is a
			 * set the number cannot say, and a line that still says what it
			 * said is kept as it is - see kof_dsrc_same. */
			if (strlen(a[0]) < sizeof it->s1)
				memcpy(it->s1, a[0], strlen(a[0]) + 1u);
			d->n++;
		} else if ((p = strstr(line, "KOF_DIAG_HAS_ATTRB(")) != NULL) {
			uint64_t fv = 0, vv = 0;

			if (!kof_dsrc_arg(p, 0, a[0], sizeof a[0]) ||
			    !kof_dsrc_arg(p, 1, a[1], sizeof a[1])) {
				say_err(r, &errs, (int)lineno,
					"KOF_DIAG_HAS_ATTRB(fact, value)");
				continue;
			}
			if (!when_value(a[0], &fv) || !fv ||
			    fv >= (uint64_t)KOF_FACT_COUNT) {
				say_err(r, &errs, (int)lineno,
					"not a fact the engine publishes");
				continue;
			}
			if (!when_value(a[1], &vv)) {
				say_err(r, &errs, (int)lineno,
					"KOF_DIAG_HAS_ATTRB wants a constant "
					"or words joined by |");
				continue;
			}
			if (!(it = add_item(d, &errs, r, lineno, KDS_ATTRB)))
				continue;
			it->a = (uint16_t)fv;
			it->v = vv;
			d->n++;
		} else if ((p = strstr(line, "KOF_TARGET_NAME(")) != NULL) {
			size_t L;

			if (!kof_dsrc_arg(p, 0, a[0], sizeof a[0]) ||
			    !kof_dsrc_arg(p, 1, a[1], sizeof a[1])) {
				say_err(r, &errs, (int)lineno,
					"KOF_TARGET_NAME(KOF_MALTYPE_*, \"family\")");
				continue;
			}
			L = strlen(a[1]);
			if (L < 2u || a[1][0] != '"' || a[1][L - 1u] != '"' ||
			    L - 2u >= KOF_DSRC_NAME_LEN ||
			    strlen(a[0]) >= KOF_DSRC_NAME_LEN) {
				say_err(r, &errs, (int)lineno,
					"KOF_TARGET_NAME wants a type and a quoted family");
				continue;
			}
			if (!(it = add_item(d, &errs, r, lineno, KDS_VNAME)))
				continue;
			memcpy(it->s1, a[0], strlen(a[0]) + 1u);
			memcpy(it->s2, a[1] + 1, L - 2u);
			it->s2[L - 2u] = 0;
			d->n++;
		} else if ((p = strstr(line, "KOF_DIAG_DECLARE_SEQUENCE(")) != NULL) {
			uint16_t cap[2];

			if (!kof_dsrc_arg(p, 0, a[0], sizeof a[0]) ||
			    !kof_dsrc_arg(p, 1, a[1], sizeof a[1]) ||
			    !kof_dsrc_cap_of(a[0], &cap[0]) ||
			    !kof_dsrc_cap_of(a[1], &cap[1])) {
				say_err(r, &errs, (int)lineno,
					"KOF_DIAG_DECLARE_SEQUENCE(first, then) "
					"wants two KOF_NUCLEO_* capabilities");
				continue;
			}
			if (!(it = add_item(d, &errs, r, lineno, KDS_SEQUENCE)))
				continue;
			it->a = cap[0];
			it->b = cap[1];
			d->n++;
		}
	}
	d->lines = lineno;
	errs += cond_parse(code, n, d, r);
	free(code);
	d->bad = (uint32_t)errs;
	return errs;
}

/* ---- the tree -------------------------------------------------------------- */

/*
 * THE RULES ABOUT WHAT A DIAGNOSE MAY SAY, in one place, in the order the file
 * says it - several are about order (a tail before the head, a sequence after
 * the head it makes) and an error names the line that broke it.
 */
int kof_dsrc_resolve(const struct kof_dsrc *d, struct kof_dsrc_view *v,
		     const struct kof_dsrc_report *r)
{
	struct { char label[32]; char name[KOF_DSRC_NAME_LEN]; int used; } sy[8];
	int n_sym = 0, errs = 0, i;
	uint32_t q;
	int last = (int)d->lines;

	memset(v, 0, sizeof *v);
	for (q = 0; q < d->n; q++) {
		const struct kof_dsrc_item *it = &d->item[q];
		int ln = (int)it->line;
		struct kof_dsrc_node *nd;
		int k;

		switch (it->kind) {
		case KDS_NAME:
			memcpy(v->name, it->s1, sizeof v->name);
			break;
		case KDS_ANALYSIS:
			v->analysis |= it->a;
			break;
		case KDS_USE_EMU:
			v->analysis |= KOF_DIAG_USES_EMU;
			break;
		case KDS_FORMAT:
		case KDS_SUBTYPE: {
			uint16_t fact = it->kind == KDS_FORMAT
					? (uint16_t)KOF_FACT_FORMAT
					: (uint16_t)KOF_FACT_OBJ_KIND;

			if (v->n_when >= (int)KOF_DIAG_MAX_WHEN) {
				say_err(r, &errs, ln, "too many conditions");
				break;
			}
			for (k = 0; k < v->n_when; k++)
				if (v->when[k].fact == fact)
					say_err(r, &errs, ln, "declared twice");
			v->when[v->n_when].fact = fact;
			v->when[v->n_when].val = it->v;
			v->n_when++;
			break;
		}
		case KDS_ATTRB:
			if (v->n_when >= (int)KOF_DIAG_MAX_WHEN) {
				say_err(r, &errs, ln, "too many conditions");
				break;
			}
			v->when[v->n_when].fact = it->a;
			v->when[v->n_when].val = it->v;
			v->n_when++;
			break;
		case KDS_HEAD:
			if (v->n_nd) {
				say_err(r, &errs, ln, "a diagnose has one head");
				break;
			}
			nd = &v->nd[0];
			nd->cap = it->a;
			nd->flags = it->b;
			v->n_nd = 1;
			break;
		case KDS_TAIL:
			if (v->n_nd >= (int)KOF_DSRC_MAX_NODE) {
				say_err(r, &errs, ln,
					"too many nodes in one diagnose");
				break;
			}
			if (!v->n_nd) {
				say_err(r, &errs, ln,
					"KOF_DIAG_DECLARE_TAIL before the head");
				break;
			}
			nd = &v->nd[v->n_nd++];
			nd->cap = it->a;
			nd->bits |= (uint8_t)it->b;
			break;
		case KDS_ACTION:
			if (v->n_nd >= (int)KOF_DSRC_MAX_NODE) {
				say_err(r, &errs, ln,
					"too many nodes in one diagnose");
				break;
			}
			/* The first word restates the head, so the line reads on
			 * its own; it must be the head this diagnose declared. */
			if (!v->n_nd || it->a != v->nd[0].cap) {
				say_err(r, &errs, ln,
					"KOF_DIAG_ACTION names a block that "
					"is not this diagnose's head");
				break;
			}
			nd = &v->nd[v->n_nd++];
			nd->cap = it->b;
			nd->val = it->v;
			nd->bits |= KOF_DIAG_B_VAL;
			break;
		case KDS_SYMBOL:
			if (n_sym >= (int)(sizeof sy / sizeof sy[0])) {
				say_err(r, &errs, ln, "too many symbols");
				break;
			}
			memcpy(sy[n_sym].label, it->s1, strlen(it->s1) + 1u);
			memcpy(sy[n_sym].name, it->s2, strlen(it->s2) + 1u);
			sy[n_sym].used = 0;
			n_sym++;
			break;
		case KDS_FIELD: {
			int hit = -1, hits = 0, si = -1;

			for (k = 0; k < n_sym; k++)
				if (!strcmp(sy[k].label, it->s1))
					si = k;
			if (si < 0) {
				say_err(r, &errs, ln,
					"no symbol declared with that label");
				break;
			}
			for (k = 0; k < v->n_nd; k++)
				if (v->nd[k].cap == it->a) {
					hit = k;
					hits++;
				}
			if (hits != 1) {
				say_err(r, &errs, ln, hits
					? "that capability is in this diagnose more than once"
					: "no node of that capability");
				break;
			}
			memcpy(v->nd[hit].sym, sy[si].name,
			       strlen(sy[si].name) + 1u);
			v->nd[hit].bits |= KOF_DIAG_B_FIELD_OF;
			sy[si].used = 1;
			/* and it is what the object must refer to, or the analysis
			 * has nothing to find: the gate is the symbol table. */
			for (k = 0; k < v->n_ref; k++)
				if (!strcmp(v->ref[k], sy[si].name))
					break;
			if (k == v->n_ref) {
				if (v->n_ref >= (int)KOF_DIAG_MAX_NEED) {
					say_err(r, &errs, ln, "too many symbols");
					break;
				}
				memcpy(v->ref[v->n_ref], sy[si].name,
				       strlen(sy[si].name) + 1u);
				v->n_ref++;
			}
			break;
		}
		case KDS_SEQUENCE:
			if (v->has_seq || !v->n_nd) {
				say_err(r, &errs, ln, v->has_seq
					? "a diagnose has one sequence"
					: "KOF_DIAG_DECLARE_SEQUENCE comes after "
					  "the head it makes");
				break;
			}
			/* What the object must import, so each has to be a name that
			 * can be imported - or the sequence can never be found. */
			if (!kof_flow_cap_named(it->a) || !kof_flow_cap_named(it->b)) {
				say_err(r, &errs, ln,
					"no imported name is that capability, so "
					"the sequence can never be found");
				break;
			}
			v->seq_first = it->a;
			v->seq_then = it->b;
			v->has_seq = 1;
			if (v->n_need + 2 > (int)KOF_DIAG_MAX_NEED) {
				say_err(r, &errs, ln, "too many signs");
				break;
			}
			v->need[v->n_need++] = it->a;
			v->need[v->n_need++] = it->b;
			break;
		default:
			break;
		}
	}

	/*
	 * A DECLARATION THAT COULD NOT BE READ is not in the list, so what is
	 * missing from the whole - a head, an analysis, a symbol's user - may be
	 * exactly that line, and saying so as well points at the wrong thing. The
	 * line that failed has been reported; the rest waits until it is fixed.
	 */
	if (d->bad)
		return errs;
	if (!v->name[0])
		say_err(r, &errs, last, "a diagnose needs KOF_DIAG_NAME");
	if (!(v->analysis & (KOF_DIAG_ANALYSIS_SYSCALL | KOF_DIAG_ANALYSIS_SYMBOL |
			     KOF_DIAG_ANALYSIS_APIHASH)))
		say_err(r, &errs, last, "a diagnose needs KOF_DIAG_ANALYSIS");
	if (!v->n_nd)
		say_err(r, &errs, last, "a diagnose needs a head");
	/*
	 * AND THE ANCHOR MUST BE RARE, which is a cost statement and not a
	 * correctness one - see the note on anchors in kofmod/kofpathogen.h.
	 * Matching starts by trying every node that could be the root, so a
	 * root of READ costs one descent per read in the object; one 1.1 MB
	 * sample here holds 447 indirect calls.
	 */
	if (v->n_nd && (v->nd[0].cap == KOF_NUCLEO_READ ||
			v->nd[0].cap == KOF_NUCLEO_WRITE ||
			v->nd[0].cap == KOF_NUCLEO_EXEC_REG))
		say_warn(r, "anchoring on a common capability - every one in "
			    "the object starts a descent");
	for (i = 0; i < n_sym; i++)
		if (!sy[i].used)
			say_err(r, &errs, last,
				"a declared symbol is attached to nothing");
	/*
	 * THE GATE IS DERIVED FROM THE HEAD AND THE TAILS, for a diagnose that only
	 * names can satisfy: with no syscall or hash analysis there is no other way
	 * for its capabilities to appear, so an object that imports none of them is
	 * not worth the analysis. A diagnose that DOES have such an analysis is not
	 * gated by imports - a stripped static binary imports nothing - and one
	 * whose head is built from a declared sequence is gated by the two calls it
	 * is built from, because the head's own capability is not what the object
	 * imports.
	 */
	if (!v->has_seq && !(v->analysis & (KOF_DIAG_ANALYSIS_SYSCALL |
					    KOF_DIAG_ANALYSIS_APIHASH)))
		for (i = 0; i < v->n_nd; i++) {
			int k;

			if (!kof_flow_cap_named(v->nd[i].cap))
				continue;       /* an action has no import name */
			for (k = 0; k < v->n_need && v->need[k] != v->nd[i].cap; k++)
				;
			if (k < v->n_need)
				continue;
			if (v->n_need >= (int)KOF_DIAG_MAX_NEED) {
				say_err(r, &errs, last, "too many signs");
				break;
			}
			v->need[v->n_need++] = v->nd[i].cap;
		}
	/* A head the engine builds out of a declared sequence is not bare: the
	 * two calls are what it is made of. */
	if (v->n_nd == 1 && !v->has_seq &&
	    !(v->nd[0].bits & (KOF_DIAG_B_VAL | KOF_DIAG_B_FIELD_OF)))
		say_warn(r, "a head with no tail, action or symbol says only "
			    "that a call exists");
	return errs;
}

/* ---- writing --------------------------------------------------------------- */

int kof_dsrc_same(const struct kof_dsrc_item *a, const struct kof_dsrc_item *b)
{
	return a->kind == b->kind && a->a == b->a && a->b == b->b &&
	       a->v == b->v && !strcmp(a->s1, b->s1) && !strcmp(a->s2, b->s2);
}

/*
 * A value as the words that make it, when the words are known: a mask is taken
 * apart into the permission names, anything else is one word or a number. The
 * number is always a spelling the reader accepts, so a value this cannot name
 * is still one a file can hold.
 */
static size_t words_of(uint64_t v, unsigned fact, char *out, size_t cap)
{
	static const char *const perm[] = { "KOF_PERM_R", "KOF_PERM_W", "KOF_PERM_X",
					    "KOF_PE_PERM_R", "KOF_PE_PERM_W",
					    "KOF_PE_PERM_X" };
	size_t i, o = 0;
	uint64_t rest = v;
	int any = 0;

	if (fact == (unsigned)KOF_FACT_ENTRY_PERM ||
	    fact == (unsigned)KOF_FACT_MAP_PERM) {
		for (i = 0; i < sizeof perm / sizeof perm[0]; i++) {
			uint64_t bit = 0;
			size_t k;

			for (k = 0; k < N_WHEN; k++)
				if (!strcmp(when_word[k].w, perm[i]))
					bit = when_word[k].v;
			if (!bit || (rest & bit) != bit || (v & bit) != bit)
				continue;
			/* the first word to claim a bit keeps it */
			if (!(rest & bit))
				continue;
			o += (size_t)snprintf(out + o, cap > o ? cap - o : 0,
					      "%s%s", any ? " | " : "", perm[i]);
			any = 1;
			rest &= ~bit;
		}
		if (any && !rest)
			return o;
		o = 0;
		any = 0;
	} else if (fact == (unsigned)KOF_FACT_FORMAT ||
		   fact == (unsigned)KOF_FACT_OBJ_KIND) {
		/* A format is a KOF_FMT word and a subtype a KOF_ELF one; the two
		 * share numbers, so the prefix is what says which. */
		const char *pre = fact == (unsigned)KOF_FACT_FORMAT ? "KOF_FMT_"
								      : "KOF_ELF_";

		for (i = 0; i < N_WHEN; i++)
			if (when_word[i].v == v && !strncmp(when_word[i].w, pre, 8))
				return (size_t)snprintf(out, cap, "%s", when_word[i].w);
	}
	return (size_t)snprintf(out, cap, v < 10u ? "%llu" : "0x%llx",
				(unsigned long long)v);
}

size_t kof_dsrc_print(const struct kof_dsrc_item *it, char *out, size_t cap)
{
	char w1[160], w2[160];
	const char *c1, *c2;
	uint64_t tv = 0;
	int n = 0;

	switch (it->kind) {
	case KDS_NAME:
		n = snprintf(out, cap, "KOF_DIAG_NAME(%s);", it->s1);
		break;
	case KDS_USE_EMU:
		n = snprintf(out, cap, "KOF_DIAG_USE_EMU();");
		break;
	case KDS_ANALYSIS: {
		const char *p[3];
		unsigned k = 0, j;

		if (it->a & KOF_DIAG_ANALYSIS_SYSCALL)
			p[k++] = "KOF_DIAG_ANALYSIS_SYSCALL";
		if (it->a & KOF_DIAG_ANALYSIS_SYMBOL)
			p[k++] = "KOF_DIAG_ANALYSIS_SYMBOL";
		if (it->a & KOF_DIAG_ANALYSIS_APIHASH)
			p[k++] = "KOF_DIAG_ANALYSIS_APIHASH";
		if (!k)
			return 0;
		n = snprintf(out, cap, "KOF_DIAG_ANALYSIS(");
		for (j = 0; j < k && n >= 0 && (size_t)n < cap; j++)
			n += snprintf(out + n, cap - (size_t)n, "%s%s",
				      j ? " | " : "", p[j]);
		if (n >= 0 && (size_t)n < cap)
			n += snprintf(out + n, cap - (size_t)n, ");");
		break;
	}
	case KDS_FORMAT:
		/* The words it was written in, while they still mean the value:
		 * an edit that changed the value is written from the value. */
		if (it->s1[0] && when_value(it->s1, &tv) && tv == it->v) {
			snprintf(w1, sizeof w1, "%s", it->s1);
			n = snprintf(out, cap, "KOF_TARGET_FORMAT(%s);", w1);
			break;
		}
		words_of(it->v, (unsigned)KOF_FACT_FORMAT, w1, sizeof w1);
		n = snprintf(out, cap, "KOF_TARGET_FORMAT(%s);", w1);
		break;
	case KDS_SUBTYPE:
		/* The words it was written in, while they still mean the value:
		 * an edit that changed the value is written from the value. */
		if (it->s1[0] && when_value(it->s1, &tv) && tv == it->v) {
			snprintf(w1, sizeof w1, "%s", it->s1);
			n = snprintf(out, cap, "KOF_TARGET_SUBTYPE(%s);", w1);
			break;
		}
		words_of(it->v, (unsigned)KOF_FACT_OBJ_KIND, w1, sizeof w1);
		n = snprintf(out, cap, "KOF_TARGET_SUBTYPE(%s);", w1);
		break;
	case KDS_ATTRB: {
		size_t k, fw = N_WHEN;

		for (k = 0; k < N_WHEN; k++)
			if (when_word[k].v == it->a &&
			    !strncmp(when_word[k].w, "KOF_FACT_", 9))
				fw = k;
		if (fw == N_WHEN)
			return 0;
		words_of(it->v, it->a, w1, sizeof w1);
		n = snprintf(out, cap, "KOF_DIAG_HAS_ATTRB(%s, %s);",
			     when_word[fw].w, w1);
		break;
	}
	case KDS_SYMBOL:
		n = snprintf(out, cap, "KOF_DIAG_DECLARE_SYMBOL(%s, \"%s\");",
			     it->s1, it->s2);
		break;
	case KDS_HEAD:
		if (!(c1 = kof_dsrc_cap_word(it->a)))
			return 0;
		n = snprintf(out, cap, "KOF_DIAG_DECLARE_HEAD(%s, %s);", c1,
			     it->b == KOF_FLOWF_WX ? "KOF_FLOWF_WX" : "0");
		break;
	case KDS_TAIL:
		if (!(c1 = kof_dsrc_cap_word(it->a)))
			return 0;
		if (it->b & KOF_DIAG_B_PRODUCED)
			n = snprintf(out, cap,
				     "KOF_DIAG_DECLARE_TAIL(%s, KOF_DIAG_B_PRODUCED);", c1);
		else if (it->b & KOF_DIAG_B_SHARED)
			n = snprintf(out, cap,
				     "KOF_DIAG_DECLARE_TAIL(%s, KOF_DIAG_B_SHARED);", c1);
		else
			n = snprintf(out, cap, "KOF_DIAG_DECLARE_TAIL(%s);", c1);
		break;
	case KDS_ACTION:
		if (!(c1 = kof_dsrc_cap_word(it->a)) ||
		    !(c2 = kof_dsrc_cap_word(it->b)))
			return 0;
		(void)w2;
		n = snprintf(out, cap, it->v < 10u ? "KOF_DIAG_ACTION(%s, %s, %llu);"
						   : "KOF_DIAG_ACTION(%s, %s, 0x%llx);",
			     c1, c2, (unsigned long long)it->v);
		break;
	case KDS_FIELD:
		if (!(c1 = kof_dsrc_cap_word(it->a)))
			return 0;
		n = snprintf(out, cap, "KOF_DIAG_HAS_FIELD(%s, %s);", c1, it->s1);
		break;
	case KDS_SEQUENCE:
		if (!(c1 = kof_dsrc_cap_word(it->a)) ||
		    !(c2 = kof_dsrc_cap_word(it->b)))
			return 0;
		n = snprintf(out, cap, "KOF_DIAG_DECLARE_SEQUENCE(%s, %s);", c1, c2);
		break;
	case KDS_VNAME:
		n = snprintf(out, cap, "KOF_TARGET_NAME(%s, \"%s\");", it->s1, it->s2);
		break;
	default:
		return 0;
	}
	return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}

/* A growing text. */
struct sbuf {
	char *p;
	size_t n, cap;
	int bad;
};

static void sb_put(struct sbuf *s, const char *t, size_t n)
{
	if (s->bad)
		return;
	if (s->n + n + 1u > s->cap) {
		size_t nc = s->cap ? s->cap : 4096u;
		char *np;

		while (s->n + n + 1u > nc)
			nc *= 2u;
		np = realloc(s->p, nc);
		if (!np) {
			s->bad = 1;
			return;
		}
		s->p = np;
		s->cap = nc;
	}
	memcpy(s->p + s->n, t, n);
	s->n += n;
	s->p[s->n] = 0;
}

static void sb_str(struct sbuf *s, const char *t)
{
	sb_put(s, t, strlen(t));
}

static void sb_line(struct sbuf *s, const struct kof_dsrc_item *it)
{
	char t[512];
	size_t n = kof_dsrc_print(it, t, sizeof t);

	if (!n)
		return;
	sb_put(s, t, n);
	sb_put(s, "\n", 1);
}

static char *patch_lines(const char *text, size_t n, const struct kof_dsrc *edited,
			 size_t *out_n)
{
	struct kof_dsrc *old = calloc(1, sizeof *old);
	struct sbuf sb = { NULL, 0, 0, 0 };
	/* What happens at each old line: 0 keep, 1 drop, 2 replace by item r. */
	unsigned char *act = NULL;
	uint32_t *rep = NULL;
	unsigned char *placed = NULL;
	uint32_t q, lineno = 0, nl = 0, first_decl = 0;
	size_t at = 0;
	int ok = 0;

	if (!old)
		return NULL;
	if (kof_dsrc_parse(text, n, old, NULL) > 0)
		goto out;               /* a file this cannot read is not patched */
	for (at = 0; at < n; at++)
		if (text[at] == '\n')
			nl++;
	if (n && text[n - 1u] != '\n')
		nl++;
	act = calloc((size_t)nl + 2u, 1);
	rep = calloc((size_t)nl + 2u, sizeof *rep);
	placed = calloc(edited->n + 1u, 1);
	if (!act || !rep || !placed)
		goto out;
	/* Every old declaration is dropped unless an edited item still carries its
	 * line; one that does is kept when it says the same, replaced when not. */
	for (q = 0; q < old->n; q++)
		act[old->item[q].line] = 1;
	for (q = 0; q < edited->n; q++) {
		const struct kof_dsrc_item *e = &edited->item[q];
		uint32_t k;

		if (!e->line || e->line > nl)
			continue;
		for (k = 0; k < old->n; k++)
			if (old->item[k].line == e->line)
				break;
		if (k == old->n)
			continue;
		if (kof_dsrc_same(&old->item[k], e)) {
			act[e->line] = 0;
		} else {
			act[e->line] = 2;
			rep[e->line] = q;
		}
		placed[q] = 1;
	}
	if (old->n)
		first_decl = old->item[0].line;

	/* Emit the old lines, and after each one the new items that follow the
	 * edited item it belongs to. A new item goes after the nearest edited item
	 * before it that has a line; one with nothing before it goes in front of
	 * the file's first declaration. */
	for (at = 0; at < n || (at == n && 0);) {
		size_t e = at;
		uint32_t anchor = 0;

		while (e < n && text[e] != '\n')
			e++;
		lineno++;
		if (lineno == first_decl) {
			for (q = 0; q < edited->n && !edited->item[q].line; q++)
				if (!placed[q]) {
					sb_line(&sb, &edited->item[q]);
					placed[q] = 1;
				}
		}
		if (act[lineno] == 0) {
			sb_put(&sb, text + at, e - at);
			if (e < n)
				sb_put(&sb, "\n", 1);
		} else if (act[lineno] == 2) {
			sb_line(&sb, &edited->item[rep[lineno]]);
		}
		anchor = lineno;
		for (q = 0; q < edited->n; q++) {
			uint32_t k;

			if (edited->item[q].line != anchor)
				continue;
			/* the new items right behind this one, up to the next with a line */
			for (k = q + 1u; k < edited->n && !edited->item[k].line; k++)
				if (!placed[k]) {
					sb_line(&sb, &edited->item[k]);
					placed[k] = 1;
				}
		}
		at = e < n ? e + 1u : e;
		if (at >= n)
			break;
	}
	/* Whatever has no place yet - a file with no declaration at all - goes at
	 * the end. */
	if (sb.n && sb.p[sb.n - 1u] != '\n')
		sb_put(&sb, "\n", 1);
	for (q = 0; q < edited->n; q++)
		if (!placed[q] && !edited->item[q].line) {
			sb_line(&sb, &edited->item[q]);
			placed[q] = 1;
		}
	ok = !sb.bad;
out:
	free(old);
	free(act);
	free(rep);
	free(placed);
	if (!ok) {
		free(sb.p);
		return NULL;
	}
	if (!sb.p)
		sb.p = calloc(1, 1);
	if (out_n)
		*out_n = sb.n;
	return sb.p;
}

/* ---- the verdict's condition, shown and compared ----------------------------- */

int kof_dsrc_cond_same(const struct kof_dsrc_cond *a, const struct kof_dsrc_cond *b)
{
	uint32_t i;

	if (a->n != b->n || strcmp(a->infect, b->infect))
		return 0;
	for (i = 0; i < a->n; i++)
	{
		uint32_t k;

		if (a->t[i].kind != b->t[i].kind || a->t[i].cap != b->t[i].cap ||
		    a->t[i].n_str != b->t[i].n_str ||
		    strcmp(a->t[i].a, b->t[i].a) || strcmp(a->t[i].b, b->t[i].b))
			return 0;
		for (k = 0; k < a->t[i].n_str; k++)
			if (strcmp(a->t[i].str[k], b->t[i].str[k]))
				return 0;
	}
	return 1;
}

/* One term as source. */
static int term_text(const struct kof_dsrc_term *t, char *out, size_t cap)
{
	const char *cw;

	if (t->kind == KVT_DIAG)
		return snprintf(out, cap, "kof_diag(%s)", t->a);
	if (t->kind == KVT_STR_ANY || t->kind == KVT_STR_ALL) {
		int o = snprintf(out, cap, "kof_diag_str_%s(%s",
				 t->kind == KVT_STR_ANY ? "any" : "all", t->a);
		unsigned k;

		for (k = 0; k < t->n_str && o >= 0 && (size_t)o < cap; k++)
			o += snprintf(out + o, cap - (size_t)o, ", \"%s\"", t->str[k]);
		if (o >= 0 && (size_t)o < cap)
			o += snprintf(out + o, cap - (size_t)o, ")");
		return o;
	}
	cw = kof_dsrc_cap_word(t->cap);
	if (!cw)
		return -1;
	return snprintf(out, cap, "kof_diag_share(%s, %s, %s)", cw, t->a, t->b);
}

/*
 * THE WRAPPING THE SHIPPED VERDICTS USE: on one line while it fits, otherwise a
 * term to a line, the continuation lined up under the first term's opening.
 * Written to stand where the old text stood, so it carries no leading tab - the
 * source's own is already in front of it.
 */
size_t kof_dsrc_cond_print(const struct kof_dsrc_cond *c, char *out, size_t cap)
{
	char t[KOF_DSRC_MAX_TERM][600];
	size_t total = 4u, o = 0;
	uint32_t i;
	int wrap;

	if (!c->n)
		return 0;
	for (i = 0; i < c->n; i++) {
		int L = term_text(&c->t[i], t[i], sizeof t[i]);

		if (L < 0 || (size_t)L >= sizeof t[i])
			return 0;
		total += (size_t)L + 4u;
	}
	wrap = total > 70u;
	o += (size_t)snprintf(out + o, cap - o, "if (");
	for (i = 0; i < c->n && o < cap; i++) {
		o += (size_t)snprintf(out + o, cap - o, "%s%s", t[i],
				      i + 1u < c->n ? (wrap ? " &&\n\t    " : " && ")
						    : ")");
	}
	return o < cap ? o : 0;
}

int kof_dsrc_verdict_check(const struct kof_dsrc *d,
			   const struct kof_dsrc_report *r)
{
	int errs = 0, fmt = 0, name = 0;
	uint32_t i, k;

	for (i = 0; i < d->n; i++) {
		fmt |= d->item[i].kind == KDS_FORMAT;
		name |= d->item[i].kind == KDS_VNAME;
	}
	if (!fmt)
		say_err(r, &errs, 0, "a verdict needs KOF_TARGET_FORMAT");
	if (!name)
		say_err(r, &errs, 0, "a verdict needs KOF_TARGET_NAME");
	if (!d->has_cond || !d->cond.n) {
		say_err(r, &errs, 0, "a verdict needs a condition over diagnoses");
		return errs;
	}
	for (i = 0; i < d->cond.n; i++) {
		const struct kof_dsrc_term *t = &d->cond.t[i];
		int a = 0, b = 0;

		if (t->kind != KVT_SHARE)
			continue;
		for (k = 0; k < d->cond.n; k++)
			if (d->cond.t[k].kind == KVT_DIAG) {
				a |= !strcmp(d->cond.t[k].a, t->a);
				b |= !strcmp(d->cond.t[k].a, t->b);
			}
		if (!a || !b)
			say_err(r, &errs, 0, "kof_diag_share joins a diagnose the "
					     "verdict does not ask for");
	}
	return errs;
}

char *kof_dsrc_verdict_new(const struct kof_dsrc *d, size_t *out_n)
{
	struct sbuf sb = { NULL, 0, 0, 0 };
	char c[2048];
	size_t L;
	uint32_t i;
	static const int order[] = { KDS_FORMAT, KDS_SUBTYPE, KDS_VNAME };
	unsigned k;

	if (kof_dsrc_verdict_check(d, NULL))
		return NULL;
	sb_str(&sb, "#include <kofmod/kofsig.h>\n#include <kofmod/kofcap.h>\n"
		    "#include <kofmod/kofpathogen.h>\n\n");
	for (k = 0; k < sizeof order / sizeof order[0]; k++)
		for (i = 0; i < d->n; i++)
			if (d->item[i].kind == order[k])
				sb_line(&sb, &d->item[i]);
	L = kof_dsrc_cond_print(&d->cond, c, sizeof c);
	if (!L) {
		free(sb.p);
		return NULL;
	}
	sb_str(&sb, "\nvoid kof_scan(const struct kof_obj_ctx *ctx)\n{\n\t");
	sb_put(&sb, c, L);
	sb_str(&sb, "\n\t\tKOF_SCAN_INFECT(");
	sb_str(&sb, d->cond.infect[0] ? d->cond.infect : "KOF_MALVAR_AUTO");
	sb_str(&sb, ");\n}\n");
	if (sb.bad) {
		free(sb.p);
		return NULL;
	}
	if (out_n)
		*out_n = sb.n;
	return sb.p;
}

/*
 * THE DECLARATIONS BY LINE, THEN THE CONDITION BY SPAN. The condition is one
 * unit with no line of its own, and the lines are patched first so the span is
 * looked up in the text that exists by then. Unchanged, the condition's bytes -
 * its wrapping, its comments inside - are never touched.
 */
char *kof_dsrc_patch(const char *text, size_t n, const struct kof_dsrc *edited,
		     size_t *out_n)
{
	size_t n1 = 0, L, k;
	char *t1 = patch_lines(text, n, edited, &n1), *t2;
	struct kof_dsrc *chk;
	char c[2048];

	if (!t1 || !edited->has_cond) {
		if (t1 && out_n)
			*out_n = n1;
		return t1;
	}
	chk = calloc(1, sizeof *chk);
	if (!chk) {
		free(t1);
		return NULL;
	}
	if (kof_dsrc_parse(t1, n1, chk, NULL) || !chk->has_cond) {
		free(chk);
		free(t1);
		return NULL;
	}
	if (kof_dsrc_cond_same(&chk->cond, &edited->cond)) {
		free(chk);
		if (out_n)
			*out_n = n1;
		return t1;
	}
	L = kof_dsrc_cond_print(&edited->cond, c, sizeof c);
	if (!L) {
		free(chk);
		free(t1);
		return NULL;
	}
	t2 = malloc(n1 - (chk->cond.end - chk->cond.at) + L + 1u);
	if (!t2) {
		free(chk);
		free(t1);
		return NULL;
	}
	k = chk->cond.at;
	memcpy(t2, t1, k);
	memcpy(t2 + k, c, L);
	memcpy(t2 + k + L, t1 + chk->cond.end, n1 - chk->cond.end);
	n1 = n1 - (chk->cond.end - chk->cond.at) + L;
	t2[n1] = 0;
	free(chk);
	free(t1);
	if (out_n)
		*out_n = n1;
	return t2;
}

size_t kof_dsrc_term_print(const struct kof_dsrc_term *t, char *out, size_t cap)
{
	int n = term_text(t, out, cap);

	return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}
