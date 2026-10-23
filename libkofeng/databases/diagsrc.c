/*
 * diagsrc.c - see diagsrc.h.
 *
 * THE VOCABULARY IS READ OUT OF THE REAL ENUMS through the X-macro lists below,
 * so the number a rule's word stands for comes from the header through the
 * compiler and a renumbered group cannot leave this behind. What CAN go stale is
 * a capability missing from a list, and kof_dsrc_cap_table_check refuses the
 * build when one is - the role table learnt that lesson the expensive way.
 */

#include "diagsrc_int.h"
#include <ctype.h>


/*
 * A NAME TO A NUMBER, through the one table that defines both.
 *
 * The source says KGENOME_NUCLEO_ALLOC_EXEC and the record holds its value, and
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
	X(KOF_NUCLEO_DECODE) X(KOF_NUCLEO_EVAL) X(KOF_NUCLEO_REQUEST) \
	X(KOF_NUCLEO_CREATE) X(KOF_NUCLEO_DYNCALL) X(KOF_NUCLEO_DYNLOAD) \
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

		if (!KGENOME_NUCLEO_VALID(c))
			continue;
		/* "?" is what the name table answers for a value inside a
		 * group's range that no capability uses - KGENOME_NUCLEO_VALID is a
		 * range test and the groups are not full. */
		nm = kgenome_nucleo_cap_name((uint16_t)c);
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
 * asking kgenome_nucleo_cap_name what each value was called; the display name is
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
int kof_dsrc_when_value(const char *w, uint64_t *out)
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
int kof_dsrc_kind_of(const char *w, uint8_t *out)
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
int kof_dsrc_flag_of(const char *w, uint16_t *out)
{
	if (strcmp(w, "0") == 0)             { *out = 0; return 1; }
	if (strcmp(w, "KOF_FLOWF_WX") == 0)  { *out = KGENOME_NUCLEO_F_WX; return 1; }
	if (strcmp(w, "KOF_FLOWF_BUILT") == 0) { *out = KGENOME_NUCLEO_F_BUILT; return 1; }
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
	/*
	 * THE ARGUMENT ENDS AT THE ',' OR ')' OF ITS OWN DEPTH. The condition used to
	 * stop at the first ',' or ')' whatever the depth, so the depth counting inside
	 * the loop never ran and `f(x)` came back as `f(x`. An argument that does not fit
	 * `cap` is REFUSED (0), not cut: two names that agree for cap-1 bytes were one
	 * name, and the caller's "wants ..." error is what reports it.
	 */
	depth = 0;
	for (; *q; q++) {
		if (*q == '(') depth++;
		else if (*q == ')') { if (!depth) break; depth--; }
		else if (*q == ',' && !depth) break;
		if ((size_t)n + 1 >= cap)
			return 0;
		out[n++] = *q;
	}
	while (n > 0 && (out[n - 1] == ' ' || out[n - 1] == '\t' ||
			 out[n - 1] == '\n' || out[n - 1] == '\r'))
		n--;
	out[n] = 0;
	return n > 0;
}

/* ---- reading -------------------------------------------------------------- */

void kof_dsrc_say_err(const struct kof_dsrc_report *r, int *n, int line,
		      const char *msg)
{
	(*n)++;
	if (r && r->error)
		r->error(r->ud, line, msg);
}

void kof_dsrc_say_warn(const struct kof_dsrc_report *r, const char *msg)
{
	if (r && r->warn)
		r->warn(r->ud, msg);
}

/*
 * EVERY COMMENT BLANKED IN PLACE - every comment byte but the newline becomes a
 * space, so a position in the result is the same position in the source and line
 * numbers stay right. The reader matched a macro's name anywhere in the line,
 * which is right for a file of declarations and wrong for a file of declarations
 * and long comments: a patch deletes the line of a declaration it removes, and a
 * comment that mentioned the macro, if read as one, would be deleted with it. A
 * string or character literal is kept whole, so a comment opener inside one is
 * text; it ends at its closing quote or at the end of its line, so one that is
 * never closed cannot swallow the rest of the file.
 *
 * ONE DEFINITION, for this reader and for the build, which has to find the same
 * declarations and the same calls in the same text.
 */
void kof_dsrc_blank_comments(char *s, size_t n)
{
	size_t i = 0;

	while (i < n) {
		char c = s[i];

		if (c == '"' || c == '\'') {
			i++;
			while (i < n && s[i] != c && s[i] != '\n') {
				if (s[i] == '\\' && i + 1u < n && s[i + 1u] != '\n')
					i++;
				i++;
			}
			if (i < n && s[i] == c)
				i++;
			continue;
		}
		if (c == '/' && i + 1u < n && s[i + 1u] == '/') {
			while (i < n && s[i] != '\n')
				s[i++] = ' ';
			continue;
		}
		if (c == '/' && i + 1u < n && s[i + 1u] == '*') {
			s[i++] = ' ';
			s[i++] = ' ';
			while (i < n) {
				if (s[i] == '*' && i + 1u < n && s[i + 1u] == '/') {
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

/* The code of a text: a copy with the comments blanked. */
char *kof_dsrc_blanked(const char *t, size_t n)
{
	char *o = malloc(n + 1u);

	if (!o)
		return NULL;
	memcpy(o, t, n);
	o[n] = 0;
	kof_dsrc_blank_comments(o, n);
	return o;
}

/*
 * THE DIAGNOSES A MODULE SOURCE READS, from the calls it makes: kof_diag(A),
 * kof_diag_share(CAP, A, B), kof_diag_str_any/all(A, "..."). Calls `fn` once per
 * name, in the order the source has them. The one scan the build and any tool share,
 * over the same blanked text the declarations are read from - a call written in a
 * comment is a mention and is not here. Nothing about the shape of the module is
 * required: how the answer is used is the module's business.
 */
static void reads_args(const char *code, const char *macro, const int *idx, size_t n_idx,
		       void (*fn)(void *ud, const char *diag), void *ud)
{
	const size_t L = strlen(macro);
	const char *p = code;

	while ((p = strstr(p, macro)) != NULL) {
		size_t k;
		int ok = (p == code || !(isalnum((unsigned char)p[-1]) || p[-1] == '_')) &&
			 p[L] == '(';

		if (ok)
			for (k = 0; k < n_idx; k++) {
				char w[KOF_DSRC_NAME_LEN];

				if (kof_dsrc_arg(p, idx[k], w, sizeof w) && w[0] &&
				    !strchr(w, '"'))
					fn(ud, w);
			}
		p += L;
	}
}

void kof_dsrc_reads(const char *text, size_t n,
		    void (*fn)(void *ud, const char *diag), void *ud)
{
	static const int a0[] = { 0 }, ab[] = { 1, 2 };
	char *code = kof_dsrc_blanked(text, n);

	if (!code)
		return;
	reads_args(code, "kof_diag", a0, 1u, fn, ud);
	reads_args(code, "kof_diag_share", ab, 2u, fn, ud);
	reads_args(code, "kof_diag_str_any", a0, 1u, fn, ud);
	reads_args(code, "kof_diag_str_all", a0, 1u, fn, ud);
	free(code);
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
	case KDS_DISEASE:
		{
			struct kof_disease_decl dd;

			dd.type = (uint8_t)it->a;
			snprintf(dd.name, sizeof dd.name, "%s", it->s1);
			return kof_disease_decl_print(&dd, out, cap);
		}
	case KDS_USE_EMU:
		n = snprintf(out, cap, "KOF_DIAG_USE_EMU();");
		break;
	case KDS_ANALYSIS: {
		const char *p[4];
		unsigned k = 0, j;

		if (it->a & KOF_DIAG_ANALYSIS_SYSCALL)
			p[k++] = "KOF_DIAG_ANALYSIS_SYSCALL";
		if (it->a & KOF_DIAG_ANALYSIS_SYMBOL)
			p[k++] = "KOF_DIAG_ANALYSIS_SYMBOL";
		if (it->a & KOF_DIAG_ANALYSIS_APIHASH)
			p[k++] = "KOF_DIAG_ANALYSIS_APIHASH";
		if (it->a & KOF_DIAG_ANALYSIS_TEXT)
			p[k++] = "KOF_DIAG_ANALYSIS_TEXT";
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
		if (it->s1[0] && kof_dsrc_when_value(it->s1, &tv) && tv == it->v) {
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
		if (it->s1[0] && kof_dsrc_when_value(it->s1, &tv) && tv == it->v) {
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
			     it->b == KGENOME_NUCLEO_F_WX ? "KOF_FLOWF_WX"
			     : it->b == KGENOME_NUCLEO_F_BUILT ? "KOF_FLOWF_BUILT" : "0");
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

static void sb_line(struct sbuf *s, const struct kof_dsrc_ops *ops,
		    const struct kof_dsrc_item *it)
{
	char t[512];
	size_t n = ops->print(it, ops->ud, t, sizeof t);

	if (!n)
		return;
	sb_put(s, t, n);
	sb_put(s, "\n", 1);
}

static char *patch_lines(const struct kof_dsrc_ops *ops, const char *text,
			 size_t n, const struct kof_dsrc *edited, size_t *out_n)
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
	if (ops->parse(text, n, old) > 0)
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
					sb_line(&sb, ops, &edited->item[q]);
					placed[q] = 1;
				}
		}
		if (act[lineno] == 0) {
			sb_put(&sb, text + at, e - at);
			if (e < n)
				sb_put(&sb, "\n", 1);
		} else if (act[lineno] == 2) {
			sb_line(&sb, ops, &edited->item[rep[lineno]]);
		}
		anchor = lineno;
		for (q = 0; q < edited->n; q++) {
			uint32_t k;

			if (edited->item[q].line != anchor)
				continue;
			/* the new items right behind this one, up to the next with a line */
			for (k = q + 1u; k < edited->n && !edited->item[k].line; k++)
				if (!placed[k]) {
					sb_line(&sb, ops, &edited->item[k]);
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
			sb_line(&sb, ops, &edited->item[q]);
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

/* The diagnose's own reading and printing, as the patcher's two questions. */
static int diag_parse(const char *text, size_t n, struct kof_dsrc *d)
{
	return kof_dsrc_parse(text, n, d, NULL);
}

static size_t diag_print(const struct kof_dsrc_item *it, void *ud, char *out,
			 size_t cap)
{
	(void)ud;
	return kof_dsrc_print(it, out, cap);
}

/*
 * THE DECLARATIONS BY LINE: the source with `edited` in place of its declarations,
 * everything that is not a declaration passing through untouched.
 *
 * ONE PATCHER FOR EVERY SOURCE THAT IS A LIST OF DECLARATIONS. What it needs from
 * a kind of file is two answers - how the file is read and how one declaration is
 * written - so those are the `ops`, and the tag sources (tagsrc.c) are patched by
 * this same loop instead of a second one.
 */
char *kof_dsrc_patch_with(const struct kof_dsrc_ops *ops, const char *text,
			  size_t n, const struct kof_dsrc *edited,
			  size_t *out_n)
{
	return patch_lines(ops, text, n, edited, out_n);
}

char *kof_dsrc_patch(const char *text, size_t n, const struct kof_dsrc *edited,
		     size_t *out_n)
{
	static const struct kof_dsrc_ops diag = { diag_parse, diag_print, NULL };

	return patch_lines(&diag, text, n, edited, out_n);
}
