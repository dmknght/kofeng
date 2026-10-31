/*
 * OLD-DISEASE (owner, 2026-10-28): the parts of this file about diseases are the OLD logic - a disease as (maltype, free-text
 * behaviour path), its id and its records in the pack. The NEW disease is the pair (ACT, OBJ) of kofmod/diseaselist.h and has no
 * text. Nothing is removed yet: this is marked for review and removal in the disease rework (changing the pack layout or version is
 * the owner's decision). `grep -rn OLD-DISEASE` lists every marked place.
 */
/*
 * diagsrc_parse.c - reading a diagnose source: the line handlers. Split from diagsrc.c; the text is unchanged. See diagsrc.h.
 */

#include "diagsrc_int.h"

struct kof_dsrc_item *kof_dsrc_add_item(struct kof_dsrc *d, int *errs,
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
	char                            a[5][KOF_DSRC_WORDS_LEN];
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
	if (!(it = kof_dsrc_add_item(x->d, &x->errs, x->r, x->lineno, KDS_NAME)))
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
	if (!(it = kof_dsrc_add_item(x->d, &x->errs, x->r, x->lineno, KDS_DISEASE)))
		return;
	it->a = dd.type;
	memcpy(it->s1, dd.name, strlen(dd.name) + 1u);
	x->d->n++;
}

/* KOF_DIAG_USE_EMU() */
static void dsrc_use_emu(struct dsrc_cx *x)
{
	struct kof_dsrc_item *it;

	if (!(it = kof_dsrc_add_item(x->d, &x->errs, x->r, x->lineno, KDS_USE_EMU)))
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
	if (!(it = kof_dsrc_add_item(x->d, &x->errs, x->r, x->lineno, KDS_ANALYSIS)))
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
	if (!(it = kof_dsrc_add_item(x->d, &x->errs, x->r, x->lineno, KDS_HEAD)))
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
	if (!(it = kof_dsrc_add_item(x->d, &x->errs, x->r, x->lineno, KDS_TAIL)))
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
	if (!(it = kof_dsrc_add_item(x->d, &x->errs, x->r, x->lineno, KDS_ACTION)))
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
	if (!(it = kof_dsrc_add_item(x->d, &x->errs, x->r, x->lineno, KDS_SYMBOL)))
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
	if (!(it = kof_dsrc_add_item(x->d, &x->errs, x->r, x->lineno, KDS_FIELD)))
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
	if (!(it = kof_dsrc_add_item(x->d, &x->errs, x->r, x->lineno,
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
	if (!(it = kof_dsrc_add_item(x->d, &x->errs, x->r, x->lineno, KDS_ATTRB)))
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
	if (!(it = kof_dsrc_add_item(x->d, &x->errs, x->r, x->lineno, KDS_SEQUENCE)))
		return;
	it->a = cap[0];
	it->b = cap[1];
	x->d->n++;
}

/*
 * KOF_DIAG_FAMILY("name") / KOF_DIAG_VARIANT("name") / KOF_DIAG_TAG("name"): a catalog name in
 * quotes. Letters, digits, '_' and '-' only, so the line splits like every other declaration
 * (an argument ends at ',' or ')') and a name round-trips through the printer; a name the
 * catalogs do not have is the build's error, not the reader's.
 */
int kof_dsrc_catalog_word_ok(const char *w)
{
	size_t i, n = strlen(w);

	if (!n || n >= KOF_DSRC_NAME_LEN)
		return 0;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)w[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '_' || c == '-'))
			return 0;
	}
	return 1;
}

int kof_dsrc_variant_word_ok(const char *w)
{
	size_t i, n = strlen(w);

	if (!n || n > 8u)
		return 0;
	for (i = 0; i < n; i++)
		if (w[i] < 'A' || w[i] > 'Z')
			return 0;
	return 1;
}

static void dsrc_meta_word(struct dsrc_cx *x, char *p, unsigned kind,
			   const char *macro)
{
	struct kof_dsrc_item *it;
	size_t L;
	char msg[80];

	snprintf(msg, sizeof msg, "%s wants one quoted name (letters, digits, _ and -)", macro);
	if (!kof_dsrc_arg(p, 0, x->a[0], sizeof x->a[0])) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno, msg);
		return;
	}
	L = strlen(x->a[0]);
	if (L < 3u || x->a[0][0] != '"' || x->a[0][L - 1u] != '"' ) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno, msg);
		return;
	}
	x->a[0][L - 1u] = 0;
	if (kind == KDS_VARIANT && kof_dsrc_catalog_word_ok(x->a[0] + 1) &&
	    !kof_dsrc_variant_word_ok(x->a[0] + 1)) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno,
			"KOF_DIAG_VARIANT wants the variant's letters only (\"A\"): the family is "
			"already named by KOF_DIAG_FAMILY, so \"Mirai_A\" is refused");
		return;
	}
	if (!(kind == KDS_VARIANT ? kof_dsrc_variant_word_ok(x->a[0] + 1)
				  : kof_dsrc_catalog_word_ok(x->a[0] + 1))) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno, msg);
		return;
	}
	if (!(it = kof_dsrc_add_item(x->d, &x->errs, x->r, x->lineno, kind)))
		return;
	memcpy(it->s1, x->a[0] + 1, strlen(x->a[0] + 1) + 1u);
	x->d->n++;
}

/* KOF_DIAG_TYPE(KOF_MALTYPE_x) */
static void dsrc_type(struct dsrc_cx *x, char *p)
{
	struct kof_dsrc_item *it;
	int t = 0;

	if (!kof_dsrc_arg(p, 0, x->a[0], sizeof x->a[0]) ||
	    !kof_maltype_from_name(x->a[0], &t)) {
		kof_dsrc_say_err(x->r, &x->errs, (int)x->lineno,
			"KOF_DIAG_TYPE wants one KOF_MALTYPE_* identifier");
		return;
	}
	if (!(it = kof_dsrc_add_item(x->d, &x->errs, x->r, x->lineno, KDS_TYPE)))
		return;
	it->a = (uint16_t)t;
	x->d->n++;
}

/* A line that calls a KOF_ macro nobody here reads: said, with its line, and not an error. The
 * name is the first KOF_ identifier directly followed by '(' - blanked comments and string
 * literals have no such call in them that matters, a mention in a comment is already blank. */
static void dsrc_unknown(struct dsrc_cx *x, const char *line)
{
	const char *p = line;

	for (; *p; p++) {
		const char *q = p;
		char msg[120];
		size_t n;

		if (strncmp(p, "KOF_", 4u) || (p > line && (p[-1] == '_' ||
		    (p[-1] >= 'A' && p[-1] <= 'Z') || (p[-1] >= '0' && p[-1] <= '9') ||
		    (p[-1] >= 'a' && p[-1] <= 'z'))))
			continue;
		while ((*q >= 'A' && *q <= 'Z') || (*q >= '0' && *q <= '9') || *q == '_')
			q++;
		if (*q != '(')
			continue;
		n = (size_t)(q - p);
		snprintf(msg, sizeof msg, "line %u: unknown declaration %.*s, not read",
			 x->lineno, n > 60u ? 60 : (int)n, p);
		kof_dsrc_say_warn(x->r, msg);
		return;
	}
}

/* ONE LINE OF THE SOURCE: which declaration it carries, if any, and that declaration's
 * handler. The first keyword found wins, in this order. */
static void dsrc_line(struct dsrc_cx *x, char *line)
{
	char *p;

	/* The form's declarations are read where the line STARTS with the macro (a marker's text may hold any
	 * macro's name) and before every other, for the same reason. */
	if (kof_dsrc_form_line(x->d, x->r, &x->errs, x->lineno, line))
		return;
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
	} else if ((p = strstr(line, "KOF_DIAG_FAMILY(")) != NULL) {
		dsrc_meta_word(x, p, KDS_FAMILY, "KOF_DIAG_FAMILY");
	} else if ((p = strstr(line, "KOF_DIAG_VARIANT(")) != NULL) {
		dsrc_meta_word(x, p, KDS_VARIANT, "KOF_DIAG_VARIANT");
	} else if ((p = strstr(line, "KOF_DIAG_TYPE(")) != NULL) {
		dsrc_type(x, p);
	} else if ((p = strstr(line, "KOF_DIAG_TAG(")) != NULL) {
		dsrc_meta_word(x, p, KDS_TAG, "KOF_DIAG_TAG");
	} else {
		dsrc_unknown(x, line);
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
