/*
 * diagsrc_parse.c - reading a diagnose source: the line handlers. Split from diagsrc.c; the text is unchanged. See diagsrc.h.
 */

#include "diagsrc_int.h"

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
	if (strstr(p, "KOF_DIAG_ANALYSIS_TEXT"))
		bits |= KOF_DIAG_ANALYSIS_TEXT;
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
	} else if ((p = strstr(line, "KOF_DIAG_DECLARE_SEQUENCE(")) != NULL) {
		dsrc_sequence(x, p);
	}
}

int kof_dsrc_parse(const char *text, size_t n, struct kof_dsrc *d,
		   const struct kof_dsrc_report *r)
{
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
		size_t e = at;
		char ended;

		while (e < n && text[e] != '\n')
			e++;
		x.lineno++;
		/* THE LINE IS READ IN PLACE, ended at its newline and restored. It
		 * was copied into 2048 bytes and cut there, so a declaration after
		 * column 2047 was never seen and nothing said so. */
		ended = code[e];
		code[e] = 0;
		dsrc_line(&x, code + at);
		code[e] = ended;
		at = e < n ? e + 1u : e;
	}
	d->lines = x.lineno;
	free(code);
	d->bad = (uint32_t)x.errs;
	return x.errs;
}
