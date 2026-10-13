/*
 * diagsrc_parse.c - reading a diagnose source: the condition parser and the line handlers. Split from diagsrc.c; the text is unchanged. See diagsrc.h.
 */

#include "diagsrc_int.h"

/* ---- the verdict's condition ------------------------------------------------ */

static int is_id(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
	       (c >= '0' && c <= '9');
}

/* The literal `w` after any whitespace, and not as the front of a longer word. */
static int lit(const char **pp, const char *w)
{
	const char *p = kof_skip_blank(*pp);
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
	const char *p = kof_skip_blank(*pp);
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
		kof_dsrc_say_err(r, &errs, 0, "a verdict that reads a diagnose has no kof_scan");
		return errs;
	}
	q = strchr(p, '{');
	if (!q) {
		kof_dsrc_say_err(r, &errs, (int)line_at(code, (size_t)(p - code)),
			"kof_scan has no body");
		return errs;
	}
	p = q + 1;
	line = line_at(code, (size_t)(p - code));
	{
		const char *ifp = kof_skip_blank(p);

		if (!lit(&p, "if") || !lit(&p, "(")) {
			kof_dsrc_say_err(r, &errs, (int)line,
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
			kof_dsrc_say_err(r, &errs, (int)line, "too many terms");
			return errs;
		}
		t = &c->t[c->n];
		memset(t, 0, sizeof *t);
		if (lit(&p, "kof_diag_share")) {
			if (!lit(&p, "(") || !word(&p, capw, sizeof capw) ||
			    !kof_dsrc_cap_of(capw, &t->cap) || !lit(&p, ",") ||
			    !word(&p, t->a, sizeof t->a) || !lit(&p, ",") ||
			    !word(&p, t->b, sizeof t->b) || !lit(&p, ")")) {
				kof_dsrc_say_err(r, &errs, (int)line,
					"kof_diag_share(KOF_NUCLEO_*, A, B)");
				return errs;
			}
			t->kind = KVT_SHARE;
		} else if (lit(&p, "kof_diag_str_any") || lit(&p, "kof_diag_str_all")) {
			t->kind = p[-1] == 'y' ? KVT_STR_ANY : KVT_STR_ALL;
			if (!lit(&p, "(") || !word(&p, t->a, sizeof t->a)) {
				kof_dsrc_say_err(r, &errs, (int)line,
					"kof_diag_str_any(NAME, \"string\", ...)");
				return errs;
			}
			while (lit(&p, ",")) {
				const char *e;
				size_t L;

				p = kof_skip_blank(p);
				if (*p != '"' || t->n_str >= KOF_DSRC_MAX_STR) {
					kof_dsrc_say_err(r, &errs, (int)line,
						"a quoted string, at most eight");
					return errs;
				}
				e = strchr(p + 1, '"');
				L = e ? (size_t)(e - p - 1) : 0u;
				if (!e || !L || L >= KOF_DSRC_STR_LEN ||
				    memchr(p + 1, '\\', L) || memchr(p + 1, '\n', L)) {
					kof_dsrc_say_err(r, &errs, (int)line,
						"a plain string of up to 47 bytes");
					return errs;
				}
				memcpy(t->str[t->n_str], p + 1, L);
				t->str[t->n_str][L] = 0;
				t->n_str++;
				p = e + 1;
			}
			if (!t->n_str || !lit(&p, ")")) {
				kof_dsrc_say_err(r, &errs, (int)line,
					"kof_diag_str_any(NAME, \"string\", ...)");
				return errs;
			}
		} else if (lit(&p, "kof_diag")) {
			if (!lit(&p, "(") || !word(&p, t->a, sizeof t->a) ||
			    !lit(&p, ")")) {
				kof_dsrc_say_err(r, &errs, (int)line, "kof_diag(NAME)");
				return errs;
			}
		} else {
			kof_dsrc_say_err(r, &errs, (int)line,
				"a term is kof_diag, kof_diag_share or kof_diag_str_*");
			return errs;
		}
		c->n++;
		if (lit(&p, "&&"))
			continue;
		if (lit(&p, ")"))
			break;
		kof_dsrc_say_err(r, &errs, (int)line,
			"terms are joined by && and nothing else");
		return errs;
	}
	c->end = (size_t)(p - code);
	if (!lit(&p, "KOF_SCAN_INFECT") || !lit(&p, "(") ||
	    !word(&p, c->infect, sizeof c->infect) || !lit(&p, ")") ||
	    !lit(&p, ";") || !lit(&p, "}")) {
		kof_dsrc_say_err(r, &errs, (int)line_at(code, c->end),
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
		kof_dsrc_say_err(r, errs, (int)line, "too many declarations");
		return NULL;
	}
	it = &d->item[d->n];
	memset(it, 0, sizeof *it);
	it->kind = (uint8_t)kind;
	it->line = line;
	return it;
}

/* What a line's handler reads and writes: the result, where errors go, the count of
 * them, the line number, and the argument scratch kof_dsrc_arg fills. */
struct dsrc_cx {
	struct kof_dsrc                *d;
	const struct kof_dsrc_report   *r;
	int                             errs;
	unsigned                        lineno;
	char                            a[5][96];
};

/* KOF_DIAG_NAME(name) */
static void dsrc_name(struct dsrc_cx *x, char *p)
{
	struct kof_dsrc_item *it;

	if (!kof_dsrc_arg(p, 0, x->a[0], sizeof x->a[0]) ||
	    strlen(x->a[0]) >= KOF_DSRC_NAME_LEN) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno,
			"KOF_DIAG_NAME wants a name");
		return;
	}
	if (!(it = add_item(x->d, &x->errs, x->r, x->lineno, KDS_NAME)))
		return;
	memcpy(it->s1, x->a[0], strlen(x->a[0]) + 1u);
	x->d->n++;
}

/* KOF_DECLARE_DISEASE(type, name) */
static void dsrc_disease(struct dsrc_cx *x, char *p)
{
	struct kof_dsrc_item *it;

	/* The one parser - see kofdisease.h. */
	struct kof_disease_decl dd;
	const char *why = kof_disease_decl_parse(p, &dd);

	if (why) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno, why);
		return;
	}
	if (!(it = add_item(x->d, &x->errs, x->r, x->lineno, KDS_DISEASE)))
		return;
	it->a = dd.type;
	memcpy(it->s1, dd.name, strlen(dd.name) + 1u);
	x->d->n++;
}

/* KOF_DIAG_USE_EMU() */
static void dsrc_use_emu(struct dsrc_cx *x)
{
	struct kof_dsrc_item *it;

	if (!(it = add_item(x->d, &x->errs, x->r, x->lineno, KDS_USE_EMU)))
		return;
	x->d->n++;
}

/* KOF_DIAG_ANALYSIS(...) */
static void dsrc_analysis(struct dsrc_cx *x, char *p)
{
	struct kof_dsrc_item *it;

	unsigned bits = 0;

	if (strstr(p, "KOF_DIAG_ANALYSIS_SYSCALL"))
		bits |= KOF_DIAG_ANALYSIS_SYSCALL;
	if (strstr(p, "KOF_DIAG_ANALYSIS_SYMBOL"))
		bits |= KOF_DIAG_ANALYSIS_SYMBOL;
	if (strstr(p, "KOF_DIAG_ANALYSIS_EMULATE"))
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno,
			"the emulator is not a way to find "
			"nodes: write KOF_DIAG_USE_EMU()");
	if (strstr(p, "KOF_DIAG_ANALYSIS_APIHASH"))
		bits |= KOF_DIAG_ANALYSIS_APIHASH;
	if (!bits) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno,
			"KOF_DIAG_ANALYSIS names no analysis");
		return;
	}
	if (!(it = add_item(x->d, &x->errs, x->r, x->lineno, KDS_ANALYSIS)))
		return;
	it->a = (uint16_t)bits;
	x->d->n++;
}

/* KOF_DIAG_DECLARE_HEAD(cap, flags) */
static void dsrc_head(struct dsrc_cx *x, char *p)
{
	struct kof_dsrc_item *it;

	uint16_t cap, fl;

	if (!kof_dsrc_arg(p, 0, x->a[0], sizeof x->a[0]) ||
	    !kof_dsrc_arg(p, 1, x->a[1], sizeof x->a[1])) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno,
			"KOF_DIAG_DECLARE_HEAD(cap, flags)");
		return;
	}
	if (!kof_dsrc_cap_of(x->a[0], &cap)) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno, "not a capability");
		return;
	}
	if (!kof_dsrc_flag_of(x->a[1], &fl)) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno, "not a node flag");
		return;
	}
	if (!(it = add_item(x->d, &x->errs, x->r, x->lineno, KDS_HEAD)))
		return;
	it->a = cap;
	it->b = fl;
	x->d->n++;
}

/* KOF_DIAG_DECLARE_TAIL(cap[, kind]) */
static void dsrc_tail(struct dsrc_cx *x, char *p)
{
	struct kof_dsrc_item *it;

	uint16_t cap;
	uint8_t kb = 0;

	if (!kof_dsrc_arg(p, 0, x->a[0], sizeof x->a[0])) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno,
			"KOF_DIAG_DECLARE_TAIL(cap[, kind])");
		return;
	}
	if (!kof_dsrc_cap_of(x->a[0], &cap)) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno, "not a capability");
		return;
	}
	/* the optional kind - absent means either */
	if (kof_dsrc_arg(p, 1, x->a[1], sizeof x->a[1]) &&
	    !kof_dsrc_kind_of(x->a[1], &kb)) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno,
			"not a link kind: want KOF_DIAG_B_PRODUCED "
			"or KOF_DIAG_B_SHARED");
		return;
	}
	if (!(it = add_item(x->d, &x->errs, x->r, x->lineno, KDS_TAIL)))
		return;
	it->a = cap;
	it->b = kb;
	x->d->n++;
}

/* KOF_DIAG_ACTION(head, action, value) */
static void dsrc_action(struct dsrc_cx *x, char *p)
{
	struct kof_dsrc_item *it;

	uint16_t hc, ac;
	char *end = NULL;
	unsigned long long v;

	if (!kof_dsrc_arg(p, 0, x->a[0], sizeof x->a[0]) ||
	    !kof_dsrc_arg(p, 1, x->a[1], sizeof x->a[1]) ||
	    !kof_dsrc_arg(p, 2, x->a[2], sizeof x->a[2])) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno,
			"KOF_DIAG_ACTION(head, action, value)");
		return;
	}
	if (!kof_dsrc_cap_of(x->a[0], &hc) ||
	    !kof_dsrc_cap_of(x->a[1], &ac)) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno, "not a capability");
		return;
	}
	v = strtoull(x->a[2], &end, 0);
	if (!end || *end) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno,
			"KOF_DIAG_ACTION wants a constant");
		return;
	}
	if (!(it = add_item(x->d, &x->errs, x->r, x->lineno, KDS_ACTION)))
		return;
	it->a = hc;
	it->b = ac;
	it->v = (uint64_t)v;
	x->d->n++;
}

/* KOF_DIAG_DECLARE_SYMBOL(label, "name") */
static void dsrc_symbol(struct dsrc_cx *x, char *p)
{
	struct kof_dsrc_item *it;

	size_t L;

	/* A symbol is named by a string the engine cannot know in
	 * advance, so it is the one declaration that carries a
	 * label: the relation below refers to it by that. */
	if (!kof_dsrc_arg(p, 0, x->a[0], sizeof x->a[0]) ||
	    !kof_dsrc_arg(p, 1, x->a[1], sizeof x->a[1])) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno,
			"KOF_DIAG_DECLARE_SYMBOL(label, \"name\")");
		return;
	}
	L = strlen(x->a[1]);
	if (L < 3u || x->a[1][0] != '"' || x->a[1][L - 1u] != '"' ||
	    L - 2u >= KOF_DSRC_NAME_LEN ||
	    strlen(x->a[0]) >= 32u ||
	    L - 2u >= KOF_DIAG_NEED_LEN) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno,
			"KOF_DIAG_DECLARE_SYMBOL wants a short "
			"label and a quoted symbol name");
		return;
	}
	if (!(it = add_item(x->d, &x->errs, x->r, x->lineno, KDS_SYMBOL)))
		return;
	memcpy(it->s1, x->a[0], strlen(x->a[0]) + 1u);
	memcpy(it->s2, x->a[1] + 1, L - 2u);
	it->s2[L - 2u] = 0;
	x->d->n++;
}

/* KOF_DIAG_HAS_FIELD(capability, symbol) */
static void dsrc_field(struct dsrc_cx *x, char *p)
{
	struct kof_dsrc_item *it;

	uint16_t cap;

	if (!kof_dsrc_arg(p, 0, x->a[0], sizeof x->a[0]) ||
	    !kof_dsrc_arg(p, 1, x->a[1], sizeof x->a[1]) ||
	    !kof_dsrc_cap_of(x->a[0], &cap)) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno,
			"KOF_DIAG_HAS_FIELD(capability, symbol)");
		return;
	}
	if (strlen(x->a[1]) >= 32u) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno,
			"no symbol declared with that label");
		return;
	}
	if (!(it = add_item(x->d, &x->errs, x->r, x->lineno, KDS_FIELD)))
		return;
	it->a = cap;
	memcpy(it->s1, x->a[1], strlen(x->a[1]) + 1u);
	x->d->n++;
}

/* KOF_TARGET_FORMAT / KOF_TARGET_SUBTYPE */
static void dsrc_target(struct dsrc_cx *x, char *p, const char *line)
{
	struct kof_dsrc_item *it;

	/* THE TARGET OF A DIAGNOSE IS DECLARED AS A SIGNATURE'S IS:
	 * the same two words, read here into the same conditions the
	 * engine already evaluates before it starts. One vocabulary
	 * for "what kind of file", two readers of it. */
	int is_fmt = strstr(line, "KOF_TARGET_FORMAT(") != NULL;
	uint64_t vv = 0;

	if (!kof_dsrc_arg(p, 0, x->a[0], sizeof x->a[0]) ||
	    !kof_dsrc_when_value(x->a[0], &vv)) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno,
			"KOF_TARGET_FORMAT / KOF_TARGET_SUBTYPE "
			"want a constant or words joined by |");
		return;
	}
	if (!(it = add_item(x->d, &x->errs, x->r, x->lineno,
			    is_fmt ? KDS_FORMAT : KDS_SUBTYPE)))
		return;
	it->v = vv;
	/* The words as written: `KOF_FMT_ELF | KOF_FMT_UNKNOWN` is a
	 * set the number cannot say, and a line that still says what it
	 * said is kept as it is - see kof_dsrc_same. */
	if (strlen(x->a[0]) < sizeof it->s1)
		memcpy(it->s1, x->a[0], strlen(x->a[0]) + 1u);
	x->d->n++;
}

/* KOF_DIAG_HAS_ATTRB(fact, value) */
static void dsrc_attrb(struct dsrc_cx *x, char *p)
{
	struct kof_dsrc_item *it;

	uint64_t fv = 0, vv = 0;

	if (!kof_dsrc_arg(p, 0, x->a[0], sizeof x->a[0]) ||
	    !kof_dsrc_arg(p, 1, x->a[1], sizeof x->a[1])) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno,
			"KOF_DIAG_HAS_ATTRB(fact, value)");
		return;
	}
	if (!kof_dsrc_when_value(x->a[0], &fv) || !fv ||
	    fv >= (uint64_t)KOF_FACT_COUNT) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno,
			"not a fact the engine publishes");
		return;
	}
	if (!kof_dsrc_when_value(x->a[1], &vv)) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno,
			"KOF_DIAG_HAS_ATTRB wants a constant "
			"or words joined by |");
		return;
	}
	if (!(it = add_item(x->d, &x->errs, x->r, x->lineno, KDS_ATTRB)))
		return;
	it->a = (uint16_t)fv;
	it->v = vv;
	x->d->n++;
}

/* KOF_TARGET_NAME(maltype, "family") */
static void dsrc_vname(struct dsrc_cx *x, char *p)
{
	struct kof_dsrc_item *it;

	size_t L;

	if (!kof_dsrc_arg(p, 0, x->a[0], sizeof x->a[0]) ||
	    !kof_dsrc_arg(p, 1, x->a[1], sizeof x->a[1])) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno,
			"KOF_TARGET_NAME(KOF_MALTYPE_*, \"family\")");
		return;
	}
	L = strlen(x->a[1]);
	if (L < 2u || x->a[1][0] != '"' || x->a[1][L - 1u] != '"' ||
	    L - 2u >= KOF_DSRC_NAME_LEN ||
	    strlen(x->a[0]) >= KOF_DSRC_NAME_LEN) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno,
			"KOF_TARGET_NAME wants a type and a quoted family");
		return;
	}
	if (!(it = add_item(x->d, &x->errs, x->r, x->lineno, KDS_VNAME)))
		return;
	memcpy(it->s1, x->a[0], strlen(x->a[0]) + 1u);
	memcpy(it->s2, x->a[1] + 1, L - 2u);
	it->s2[L - 2u] = 0;
	x->d->n++;
}

/* KOF_DIAG_DECLARE_SEQUENCE(first, then) */
static void dsrc_sequence(struct dsrc_cx *x, char *p)
{
	struct kof_dsrc_item *it;

	uint16_t cap[2];

	if (!kof_dsrc_arg(p, 0, x->a[0], sizeof x->a[0]) ||
	    !kof_dsrc_arg(p, 1, x->a[1], sizeof x->a[1]) ||
	    !kof_dsrc_cap_of(x->a[0], &cap[0]) ||
	    !kof_dsrc_cap_of(x->a[1], &cap[1])) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno,
			"KOF_DIAG_DECLARE_SEQUENCE(first, then) "
			"wants two KOF_NUCLEO_* capabilities");
		return;
	}
	if (!(it = add_item(x->d, &x->errs, x->r, x->lineno, KDS_SEQUENCE)))
		return;
	it->a = cap[0];
	it->b = cap[1];
	x->d->n++;
}

/* ONE LINE OF THE SOURCE: which declaration it carries, if any, and that declaration's
 * handler. The first keyword found wins, in this order. */
static void dsrc_line(struct dsrc_cx *x, char *line)
{
	char *p;

	if ((p = strstr(line, "KOF_DIAG_NAME(")) != NULL) {
		dsrc_name(x, p);
	} else if ((p = strstr(line, "KOF_DECLARE_DISEASE(")) != NULL) {
		dsrc_disease(x, p);
	} else if (strstr(line, "KOF_DIAG_USE_EMU(") != NULL) {
		dsrc_use_emu(x);
	} else if ((p = strstr(line, "KOF_DIAG_ANALYSIS(")) != NULL) {
		dsrc_analysis(x, p);
	} else if ((p = strstr(line, "KOF_DIAG_DECLARE_HEAD(")) != NULL) {
		dsrc_head(x, p);
	} else if ((p = strstr(line, "KOF_DIAG_DECLARE_TAIL(")) != NULL) {
		dsrc_tail(x, p);
	} else if ((p = strstr(line, "KOF_DIAG_ACTION(")) != NULL) {
		dsrc_action(x, p);
	} else if ((p = strstr(line, "KOF_DIAG_DECLARE_SYMBOL(")) != NULL) {
		dsrc_symbol(x, p);
	} else if ((p = strstr(line, "KOF_DIAG_HAS_FIELD(")) != NULL) {
		dsrc_field(x, p);
	} else if ((p = strstr(line, "KOF_TARGET_FORMAT(")) != NULL ||
		   (p = strstr(line, "KOF_TARGET_SUBTYPE(")) != NULL) {
		dsrc_target(x, p, line);
	} else if ((p = strstr(line, "KOF_DIAG_HAS_ATTRB(")) != NULL) {
		dsrc_attrb(x, p);
	} else if ((p = strstr(line, "KOF_TARGET_NAME(")) != NULL) {
		dsrc_vname(x, p);
	} else if ((p = strstr(line, "KOF_DIAG_DECLARE_SEQUENCE(")) != NULL) {
		dsrc_sequence(x, p);
	}
}

int kof_dsrc_parse(const char *text, size_t n, struct kof_dsrc *d,
		   const struct kof_dsrc_report *r)
{
	char line[2048];
	struct dsrc_cx x;
	size_t at = 0;
	char *code = kof_dsrc_blanked(text, n);

	memset(d, 0, sizeof *d);
	x.d = d;
	x.r = r;
	x.errs = 0;
	x.lineno = 0;
	if (!code) {
		kof_dsrc_say_err(r, &x.errs, 0, "out of memory");
		return x.errs;
	}
	while (at < n) {
		size_t e = at, len;

		while (e < n && text[e] != '\n')
			e++;
		len = e - at;
		x.lineno++;
		if (len >= sizeof line)
			len = sizeof line - 1u;
		memcpy(line, code + at, len);
		line[len] = 0;
		at = e < n ? e + 1u : e;

		dsrc_line(&x, line);
	}
	d->lines = x.lineno;
	x.errs += cond_parse(code, n, d, r);
	free(code);
	d->bad = (uint32_t)x.errs;
	return x.errs;
}
