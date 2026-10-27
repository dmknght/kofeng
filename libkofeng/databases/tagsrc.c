/*
 * SWITCHED OFF (owner, 2026-10-27): the Syndrome table and its tag-source backend (kofexamine/kv_syn.c, kv_syntable.c,
 * libkofeng/databases/tagsrc*, ksigbuilder/ksb_tags.c) stay in the tree and are to be removed later, when asked. The menu item
 * is Manage > Syndromes, listed and greyed. Do not extend this code.
 */
/*
 * tagsrc.c - one tag source, read, written and patched. See tagsrc.h.
 */

#include "tagsrc_int.h"
#include <kofmod/script.h>
#include <kofmod/cell.h>

/* ---- the vocabulary ---------------------------------------------------- */

/*
 * THE WORDS A FILE ATTRIBUTE MAY BE WRITTEN IN, read out of the engine's lists
 * through the X-macros the viewer's menus and the diagnose builder read: the
 * format a target names (KOF_TARGET_LIST), the architecture (KOF_ARCH_LIST) and
 * the subtype, which is one dictionary over the ELF, PE and script kinds. The
 * word is the enumerator as the engine spells it.
 */
static const char *const fmt_word[] = {
#define TAGSRC_FMT(name, val, word, grp) #name,
	KOF_TARGET_LIST(TAGSRC_FMT)
#undef TAGSRC_FMT
};

static const char *const arch_word[] = {
#define TAGSRC_ARCH(name, val, word) #name,
	KOF_ARCH_LIST(TAGSRC_ARCH)
#undef TAGSRC_ARCH
};

static const char *const sub_word[] = {
#define TAGSRC_SUB(name, val) #name,
	KOF_ELF_TYPE_LIST(TAGSRC_SUB)
	KOF_PE_IMAGE_LIST(TAGSRC_SUB)
	KOF_SCRIPT_TYPE_LIST(TAGSRC_SUB)
#undef TAGSRC_SUB
};

#define N_OF(a) (sizeof (a) / sizeof (a)[0])

size_t kof_tagsrc_vocab_n(unsigned cls)
{
	switch (cls) {
	case KOF_TAGSRC_A_FORMAT:  return N_OF(fmt_word);
	case KOF_TAGSRC_A_ARCH:    return N_OF(arch_word);
	case KOF_TAGSRC_A_SUBTYPE: return N_OF(sub_word);
	default:                   return 0;
	}
}

const char *kof_tagsrc_vocab_word(unsigned cls, size_t i)
{
	if (i >= kof_tagsrc_vocab_n(cls))
		return NULL;
	switch (cls) {
	case KOF_TAGSRC_A_FORMAT: return fmt_word[i];
	case KOF_TAGSRC_A_ARCH:   return arch_word[i];
	default:                  return sub_word[i];
	}
}

int kof_tagsrc_vocab_find(unsigned cls, const char *word)
{
	size_t i, n = kof_tagsrc_vocab_n(cls);

	for (i = 0; i < n; i++)
		if (!strcmp(kof_tagsrc_vocab_word(cls, i), word))
			return (int)i;
	return -1;
}

/* ---- names ------------------------------------------------------------- */

static const char *const kind_word[KOF_TAGSRC_K_COUNT] = {
	"", "activity", "type", "family", "tag"
};

const char *kof_tagsrc_kind_word(unsigned kind)
{
	return kind < KOF_TAGSRC_K_COUNT ? kind_word[kind] : "";
}

int kof_tagsrc_name_ok(const char *s)
{
	size_t n = strlen(s), i;

	if (!n || n >= KOF_TAGSRC_NAME_LEN)
		return 0;
	for (i = 0; i < n; i++)
		if (!((s[i] >= 'a' && s[i] <= 'z') ||
		      (s[i] >= '0' && s[i] <= '9') || s[i] == '-'))
			return 0;
	return 1;
}

size_t kof_tagsrc_name_norm(char *dst, size_t cap, const char *src)
{
	size_t n = 0;

	for (; *src && n + 1u < cap && n + 1u < KOF_TAGSRC_NAME_LEN; src++) {
		char c = *src;

		if (c >= 'A' && c <= 'Z')
			c = (char)(c + 32);
		else if (c == ' ' || c == '_')
			c = '-';
		if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		    c == '-')
			dst[n++] = c;
	}
	if (cap)
		dst[n] = 0;
	return n;
}

void kof_tagsrc_file_name(const struct kof_tagent *e, char *out, size_t cap)
{
	snprintf(out, cap, "%s_%s_%08x.c", kof_tagsrc_kind_word(e->kind),
		 e->name, (unsigned)(e->id >> 32));
}

void kof_tagsrc_id_text(uint64_t id, char *out, size_t cap)
{
	snprintf(out, cap, "0x%016llx", (unsigned long long)id);
}

/* A comment is 63 + 63 characters, in the two strings an item has. */
void kof_tagsrc_comment_get(const struct kof_dsrc_item *it, char *out,
			    size_t cap)
{
	snprintf(out, cap, "%s%s", it->s1, it->s2);
}

void kof_tagsrc_comment_set(struct kof_dsrc_item *it, const char *text)
{
	size_t n = strlen(text);

	memset(it->s1, 0, sizeof it->s1);
	memset(it->s2, 0, sizeof it->s2);
	if (n > KOF_TAGSRC_COMMENT_LEN - 1u)
		n = KOF_TAGSRC_COMMENT_LEN - 1u;
	if (n < sizeof it->s1) {
		memcpy(it->s1, text, n);
	} else {
		memcpy(it->s1, text, sizeof it->s1 - 1u);
		memcpy(it->s2, text + sizeof it->s1 - 1u,
		       n - (sizeof it->s1 - 1u));
	}
}

int kof_tagsrc_attr_class(unsigned what)
{
	switch (what) {
	case KOF_TAGSRC_W_FORMAT:  return KOF_TAGSRC_A_FORMAT;
	case KOF_TAGSRC_W_ARCH:    return KOF_TAGSRC_A_ARCH;
	case KOF_TAGSRC_W_SUBTYPE: return KOF_TAGSRC_A_SUBTYPE;
	default:                   return -1;
	}
}

/* ---- reading one line --------------------------------------------------- */

static const struct {
	const char *word;
	unsigned    what;
	int         tag_only;
} suffix[] = {
	{ "ID",       KOF_TAGSRC_W_ID,       0 },
	{ "NAME",     KOF_TAGSRC_W_NAME,     0 },
	{ "COMMENT",  KOF_TAGSRC_W_COMMENT,  0 },
	{ "ACTIVITY", KOF_TAGSRC_W_ACTIVITY, 1 },
	{ "TYPE",     KOF_TAGSRC_W_TYPE,     1 },
	{ "FAMILY",   KOF_TAGSRC_W_FAMILY,   1 },
	{ "FORMAT",   KOF_TAGSRC_W_FORMAT,   1 },
	{ "ARCH",     KOF_TAGSRC_W_ARCH,     1 },
	{ "SUBTYPE",  KOF_TAGSRC_W_SUBTYPE,  1 }
};

static const char *const kind_macro[KOF_TAGSRC_K_COUNT] = {
	"", "ACTIVITY_", "TYPE_", "FAMILY_", "TAG_"
};

struct tg_cx {
	struct kof_dsrc                *d;
	const struct kof_dsrc_report   *r;
	int                             errs;
	unsigned                        line;
};

static void tg_err(struct tg_cx *x, const char *msg)
{
	kof_dsrc_say_err(x->r, &x->errs, (int)x->line, msg);
}

static const char *skip_ws(const char *p)
{
	while (*p == ' ' || *p == '\t' || *p == '\r')
		p++;
	return p;
}

/* A number: 0x and hex digits, or decimal; 64 bits, no sign. */
static int read_number(const char **pp, uint64_t *out)
{
	const char *p = *pp;
	uint64_t v = 0;
	int digits = 0;

	if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
		p += 2;
		for (;; p++) {
			int d;

			if (*p >= '0' && *p <= '9')
				d = *p - '0';
			else if (*p >= 'a' && *p <= 'f')
				d = *p - 'a' + 10;
			else if (*p >= 'A' && *p <= 'F')
				d = *p - 'A' + 10;
			else
				break;
			if (v >> 60)
				return 0;       /* more than 64 bits */
			v = (v << 4) | (uint64_t)d;
			digits++;
		}
	} else {
		for (; *p >= '0' && *p <= '9'; p++) {
			uint64_t d = (uint64_t)(*p - '0');

			if (v > (UINT64_MAX - d) / 10u)
				return 0;
			v = v * 10u + d;
			digits++;
		}
	}
	if (!digits)
		return 0;
	*out = v;
	*pp = p;
	return 1;
}

/* A string literal, escapes \" and \\ read; cap-1 characters at most. 0 when
 * it is not closed or does not fit. */
static int read_string(const char **pp, char *out, size_t cap)
{
	const char *p = *pp;
	size_t n = 0;

	if (*p != '"')
		return 0;
	for (p++; *p && *p != '"'; p++) {
		char c = *p;

		if (c == '\\' && (p[1] == '"' || p[1] == '\\'))
			c = *++p;
		if (n + 1u >= cap)
			return 0;
		out[n++] = c;
	}
	if (*p != '"')
		return 0;
	out[n] = 0;
	*pp = p + 1;
	return 1;
}

/* An enumerator name. */
static int read_word(const char **pp, char *out, size_t cap)
{
	const char *p = *pp;
	size_t n = 0;

	while (isalnum((unsigned char)*p) || *p == '_') {
		if (n + 1u >= cap)
			return 0;
		out[n++] = *p++;
	}
	if (!n)
		return 0;
	out[n] = 0;
	*pp = p;
	return 1;
}

/* What follows a declaration's closing parenthesis: a semicolon, nothing else
 * of ours. */
static int tail_ok(const char *p)
{
	p = skip_ws(p);
	if (*p == ';')
		p = skip_ws(p + 1);
	return !strstr(p, "KOF_");
}

static struct kof_dsrc_item *tg_add(struct tg_cx *x, unsigned what,
				    unsigned kind)
{
	struct kof_dsrc_item *it;

	if (x->d->n >= KOF_DSRC_MAX_ITEM) {
		tg_err(x, "too many declarations");
		return NULL;
	}
	it = &x->d->item[x->d->n];
	memset(it, 0, sizeof *it);
	it->kind = (uint8_t)what;
	it->b = (uint16_t)kind;
	it->line = x->line;
	return it;
}

/* The argument of a declaration, by what the declaration is. */
static void tg_value(struct tg_cx *x, unsigned what, unsigned kind,
		     const char *p)
{
	struct kof_dsrc_item *it;
	char w[160];
	uint64_t v = 0;
	int cls = kof_tagsrc_attr_class(what);

	p = skip_ws(p);
	if (what == KOF_TAGSRC_W_NAME || what == KOF_TAGSRC_W_COMMENT) {
		if (!read_string(&p, w, sizeof w) ||
		    (what == KOF_TAGSRC_W_NAME &&
		     strlen(w) >= KOF_TAGSRC_NAME_LEN) ||
		    (what == KOF_TAGSRC_W_COMMENT &&
		     strlen(w) >= KOF_TAGSRC_COMMENT_LEN)) {
			tg_err(x, "a name or a comment is a quoted string "
				  "that is closed and fits");
			return;
		}
	} else if (cls >= 0) {
		if (!read_word(&p, w, sizeof w) ||
		    kof_tagsrc_vocab_find((unsigned)cls, w) < 0) {
			tg_err(x, "not a word the engine has for this "
				  "attribute");
			return;
		}
	} else if (!read_number(&p, &v)) {
		tg_err(x, "invalid id: a number of at most 64 bits");
		return;
	}
	p = skip_ws(p);
	if (*p != ')') {
		tg_err(x, "unterminated declaration");
		return;
	}
	if (!tail_ok(p + 1)) {
		tg_err(x, "more than one declaration on a line");
		return;
	}
	if (!(it = tg_add(x, what, kind)))
		return;
	it->v = v;
	if (what == KOF_TAGSRC_W_COMMENT)
		kof_tagsrc_comment_set(it, w);
	else if (what == KOF_TAGSRC_W_NAME || cls >= 0)
		memcpy(it->s1, w, strlen(w) + 1u);
	x->d->n++;
}

/* One line, comments blanked: its declaration if it begins with one. */
static void tg_line(struct tg_cx *x, const char *line)
{
	const char *p = skip_ws(line), *open;
	unsigned kind, k, what = 0;
	int known = 0;
	size_t n;

	if (strncmp(p, "KOF_", 4) != 0)
		return;
	p += 4;
	for (kind = KOF_TAGSRC_K_ACTIVITY; kind < KOF_TAGSRC_K_COUNT; kind++)
		if (!strncmp(p, kind_macro[kind], strlen(kind_macro[kind])))
			break;
	if (kind == KOF_TAGSRC_K_COUNT)
		return;                 /* not one of ours */
	p += strlen(kind_macro[kind]);
	open = p;
	while (isalnum((unsigned char)*open) || *open == '_')
		open++;
	if (*open != '(')
		return;
	n = (size_t)(open - p);
	for (k = 0; k < N_OF(suffix); k++)
		if (strlen(suffix[k].word) == n &&
		    !strncmp(p, suffix[k].word, n) &&
		    (!suffix[k].tag_only || kind == KOF_TAGSRC_K_TAG)) {
			what = suffix[k].what;
			known = 1;
			break;
		}
	if (!known) {
		/* A newer tool's declaration: said once, kept by the patch. */
		if (x->r && x->r->warn) {
			char m[160];

			snprintf(m, sizeof m, "line %u: unknown declaration "
				 "kept as written", x->line);
			x->r->warn(x->r->ud, m);
		}
		return;
	}
	tg_value(x, what, kind, open + 1);
}

int kof_tagsrc_parse(const char *text, size_t n, struct kof_dsrc *d,
		     const struct kof_dsrc_report *r)
{
	struct tg_cx x;
	size_t at = 0;
	char *code = kof_dsrc_blanked(text, n);

	memset(d, 0, sizeof *d);
	x.d = d;
	x.r = r;
	x.errs = 0;
	x.line = 0;
	if (!code) {
		kof_dsrc_say_err(r, &x.errs, 0, "out of memory");
		return x.errs;
	}
	while (at < n) {
		size_t e = at;
		char ended;

		while (e < n && text[e] != '\n')
			e++;
		x.line++;
		ended = code[e];
		code[e] = 0;
		tg_line(&x, code + at);
		code[e] = ended;
		at = e < n ? e + 1u : e;
	}
	d->lines = x.line;
	free(code);
	d->bad = (uint32_t)x.errs;
	return x.errs;
}

/* ---- the entity -------------------------------------------------------- */

struct en_cx {
	struct kof_tagent              *e;
	const struct kof_dsrc_report   *r;
	int                             errs;
	int                             has_id, has_name, has_comment;
};

static void en_err(struct en_cx *x, const struct kof_dsrc_item *it,
		   const char *msg)
{
	kof_dsrc_say_err(x->r, &x->errs, (int)it->line, msg);
}

static int has_id(const uint64_t *a, uint32_t n, uint64_t id)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (a[i] == id)
			return 1;
	return 0;
}

/* A reference: one more id in `a`, once each, and not past what a tag may
 * hold - a bound that is said, never a silent cut. */
static void en_ref(struct en_cx *x, const struct kof_dsrc_item *it,
		   uint64_t *a, uint8_t *n, const char *what)
{
	char m[96];

	if (has_id(a, *n, it->v)) {
		snprintf(m, sizeof m, "the same %s is listed twice", what);
		en_err(x, it, m);
	} else if (*n >= KOF_TAGSRC_REFS) {
		snprintf(m, sizeof m, "more than %u %ss", KOF_TAGSRC_REFS, what);
		en_err(x, it, m);
	} else {
		a[(*n)++] = it->v;
	}
}

static void en_attr(struct en_cx *x, const struct kof_dsrc_item *it)
{
	struct kof_tagent *e = x->e;
	int cls = kof_tagsrc_attr_class(it->kind), k;
	unsigned i;

	k = kof_tagsrc_vocab_find((unsigned)cls, it->s1);
	if (k < 0) {
		en_err(x, it, "not a word the engine has for this attribute");
		return;
	}
	for (i = 0; i < e->n_attr[cls]; i++)
		if (e->attr[cls][i] == (uint16_t)k) {
			en_err(x, it, "the same word is listed twice");
			return;
		}
	if (e->n_attr[cls] >= KOF_TAGSRC_ATTRS) {
		en_err(x, it, "too many words of one attribute");
		return;
	}
	e->attr[cls][e->n_attr[cls]++] = (uint16_t)k;
}

static void en_item(struct en_cx *x, const struct kof_dsrc_item *it)
{
	struct kof_tagent *e = x->e;

	switch (it->kind) {
	case KOF_TAGSRC_W_ID:
		if (x->has_id)
			en_err(x, it, "the id is declared twice");
		x->has_id = 1;
		e->id = it->v;
		break;
	case KOF_TAGSRC_W_NAME:
		if (x->has_name)
			en_err(x, it, "the name is declared twice");
		x->has_name = 1;
		memcpy(e->name, it->s1, sizeof e->name);
		break;
	case KOF_TAGSRC_W_COMMENT:
		if (x->has_comment)
			en_err(x, it, "the comment is declared twice");
		x->has_comment = 1;
		kof_tagsrc_comment_get(it, e->comment, sizeof e->comment);
		break;
	case KOF_TAGSRC_W_ACTIVITY:
		en_ref(x, it, e->act, &e->n_act, "activity");
		break;
	case KOF_TAGSRC_W_TYPE:
		en_ref(x, it, e->typ, &e->n_typ, "type");
		break;
	case KOF_TAGSRC_W_FAMILY:
		if (e->has_fam)
			en_err(x, it, "a tag has one family");
		e->has_fam = 1;
		e->fam = it->v;
		break;
	default:
		en_attr(x, it);
		break;
	}
}

int kof_tagsrc_entity(const struct kof_dsrc *d, struct kof_tagent *e,
		      const struct kof_dsrc_report *r)
{
	struct en_cx x;
	uint32_t i;

	memset(e, 0, sizeof *e);
	x.e = e;
	x.r = r;
	x.errs = 0;
	x.has_id = x.has_name = x.has_comment = 0;
	if (!d->n) {
		kof_dsrc_say_err(r, &x.errs, 0, "no declaration of an "
				 "activity, a type, a family or a tag");
		return x.errs;
	}
	/* The kind is the first declaration's, and nothing else decides it. */
	e->kind = (uint8_t)d->item[0].b;
	for (i = 0; i < d->n; i++) {
		const struct kof_dsrc_item *it = &d->item[i];

		if (it->b != e->kind) {
			en_err(&x, it, "a declaration of another kind than "
				       "the first one's");
			continue;
		}
		en_item(&x, it);
	}
	if (!x.has_id)
		kof_dsrc_say_err(r, &x.errs, 0, "no id");
	else if (e->kind == KOF_TAGSRC_K_TAG && !e->id)
		kof_dsrc_say_err(r, &x.errs, 0, "invalid id: a tag's id is "
				 "never zero, zero is no tag");
	if (!x.has_name || !e->name[0])
		kof_dsrc_say_err(r, &x.errs, 0, "empty name");
	else if (!kof_tagsrc_name_ok(e->name))
		kof_dsrc_say_err(r, &x.errs, 0, "bad characters in the name: "
				 "lower case a-z, 0-9 and '-' only");
	return x.errs;
}

/* ---- the entity back into declarations -------------------------------- */

struct it_cx {
	struct kof_dsrc        *out;
	const struct kof_dsrc  *old;
	uint8_t                 used[KOF_DSRC_MAX_ITEM];
	unsigned                kind;
};

/* Add one declaration, carrying the line of the old one that says the same,
 * or - for a declaration there is one of - the line of the one it replaces. */
static void it_put(struct it_cx *x, unsigned what, uint64_t v, const char *s1,
		   const char *s2, int single)
{
	struct kof_dsrc_item *it;
	uint32_t i, exact = KOF_DSRC_MAX_ITEM, repl = KOF_DSRC_MAX_ITEM, pick;

	if (x->out->n >= KOF_DSRC_MAX_ITEM)
		return;
	it = &x->out->item[x->out->n];
	memset(it, 0, sizeof *it);
	it->kind = (uint8_t)what;
	it->b = (uint16_t)x->kind;
	it->v = v;
	snprintf(it->s1, sizeof it->s1, "%s", s1 ? s1 : "");
	snprintf(it->s2, sizeof it->s2, "%s", s2 ? s2 : "");
	for (i = 0; x->old && i < x->old->n; i++) {
		const struct kof_dsrc_item *o = &x->old->item[i];

		if (x->used[i] || o->kind != it->kind || o->b != it->b)
			continue;
		if (kof_dsrc_same(o, it)) {
			exact = i;
			break;
		}
		if (single && repl == KOF_DSRC_MAX_ITEM)
			repl = i;
	}
	pick = exact != KOF_DSRC_MAX_ITEM ? exact : repl;
	if (pick != KOF_DSRC_MAX_ITEM) {
		x->used[pick] = 1;
		it->line = x->old->item[pick].line;
	}
	x->out->n++;
}

void kof_tagsrc_items(const struct kof_tagent *e, const struct kof_dsrc *old,
		      struct kof_dsrc *out)
{
	struct it_cx x;
	struct kof_dsrc_item tmp;
	unsigned c, i;
	static const unsigned what_of[KOF_TAGSRC_A_COUNT] = {
		KOF_TAGSRC_W_FORMAT, KOF_TAGSRC_W_ARCH, KOF_TAGSRC_W_SUBTYPE
	};

	memset(out, 0, sizeof *out);
	memset(&x, 0, sizeof x);
	x.out = out;
	x.old = old;
	x.kind = e->kind;
	it_put(&x, KOF_TAGSRC_W_ID, e->id, NULL, NULL, 1);
	it_put(&x, KOF_TAGSRC_W_NAME, 0, e->name, NULL, 1);
	if (e->comment[0]) {
		memset(&tmp, 0, sizeof tmp);
		kof_tagsrc_comment_set(&tmp, e->comment);
		it_put(&x, KOF_TAGSRC_W_COMMENT, 0, tmp.s1, tmp.s2, 1);
	}
	if (e->kind != KOF_TAGSRC_K_TAG)
		return;
	for (i = 0; i < e->n_act; i++)
		it_put(&x, KOF_TAGSRC_W_ACTIVITY, e->act[i], NULL, NULL, 0);
	for (i = 0; i < e->n_typ; i++)
		it_put(&x, KOF_TAGSRC_W_TYPE, e->typ[i], NULL, NULL, 0);
	if (e->has_fam)
		it_put(&x, KOF_TAGSRC_W_FAMILY, e->fam, NULL, NULL, 1);
	for (c = 0; c < KOF_TAGSRC_A_COUNT; c++)
		for (i = 0; i < e->n_attr[c]; i++)
			it_put(&x, what_of[c], 0,
			       kof_tagsrc_vocab_word(c, e->attr[c][i]), NULL, 0);
}

/* ---- writing ----------------------------------------------------------- */

static size_t put_quoted(char *out, size_t cap, const char *s)
{
	size_t n = 0;

	if (n + 1u < cap)
		out[n++] = '"';
	for (; *s && n + 2u < cap; s++) {
		if (*s == '"' || *s == '\\')
			out[n++] = '\\';
		out[n++] = *s;
	}
	if (n + 1u < cap)
		out[n++] = '"';
	if (cap)
		out[n] = 0;
	return n;
}

size_t kof_tagsrc_print(const struct kof_dsrc_item *it,
			const struct kof_tagset *names, char *out, size_t cap)
{
	char arg[320], c[KOF_TAGSRC_COMMENT_LEN], note[KOF_TAGSRC_NAME_LEN + 8];
	const char *suf = NULL;
	unsigned k, ek = KOF_TAGSRC_K_NONE;
	int n;

	if (it->b < KOF_TAGSRC_K_ACTIVITY || it->b >= KOF_TAGSRC_K_COUNT)
		return 0;
	for (k = 0; k < N_OF(suffix); k++)
		if (suffix[k].what == it->kind)
			suf = suffix[k].word;
	if (!suf)
		return 0;
	note[0] = 0;
	switch (it->kind) {
	case KOF_TAGSRC_W_NAME:
		put_quoted(arg, sizeof arg, it->s1);
		break;
	case KOF_TAGSRC_W_COMMENT:
		kof_tagsrc_comment_get(it, c, sizeof c);
		put_quoted(arg, sizeof arg, c);
		break;
	case KOF_TAGSRC_W_FORMAT:
	case KOF_TAGSRC_W_ARCH:
	case KOF_TAGSRC_W_SUBTYPE:
		snprintf(arg, sizeof arg, "%s", it->s1);
		break;
	default:
		kof_tagsrc_id_text(it->v, arg, sizeof arg);
		if (it->kind == KOF_TAGSRC_W_ACTIVITY)
			ek = KOF_TAGSRC_K_ACTIVITY;
		else if (it->kind == KOF_TAGSRC_W_TYPE)
			ek = KOF_TAGSRC_K_TYPE;
		else if (it->kind == KOF_TAGSRC_W_FAMILY)
			ek = KOF_TAGSRC_K_FAMILY;
		break;
	}
	if (ek != KOF_TAGSRC_K_NONE) {
		/* For people, and never read back: comments are blanked. */
		const char *nm = names ? kof_tagset_name(names, ek, it->v)
				       : NULL;

		snprintf(note, sizeof note, "%s", nm ? nm : "missing");
		n = snprintf(out, cap, "KOF_%s%s(%s);  /* %s */",
			     kind_macro[it->b], suf, arg, note);
	} else {
		n = snprintf(out, cap, "KOF_%s%s(%s);", kind_macro[it->b], suf,
			     arg);
	}
	return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}

static int ops_parse(const char *text, size_t n, struct kof_dsrc *d)
{
	return kof_tagsrc_parse(text, n, d, NULL);
}

static size_t ops_print(const struct kof_dsrc_item *it, void *ud, char *out,
			size_t cap)
{
	return kof_tagsrc_print(it, (const struct kof_tagset *)ud, out, cap);
}

char *kof_tagsrc_patch(const char *text, size_t n, const struct kof_tagent *e,
		       const struct kof_tagset *names, size_t *out_n)
{
	struct kof_dsrc *old = calloc(1, sizeof *old);
	struct kof_dsrc *ed = calloc(1, sizeof *ed);
	struct kof_dsrc_ops ops;
	char *res = NULL;

	ops.parse = ops_parse;
	ops.print = ops_print;
	ops.ud = (void *)(size_t)names;
	if (old && ed && kof_tagsrc_parse(text, n, old, NULL) == 0) {
		kof_tagsrc_items(e, old, ed);
		res = kof_dsrc_patch_with(&ops, text, n, ed, out_n);
	}
	free(old);
	free(ed);
	return res;
}

char *kof_tagsrc_new(const struct kof_tagent *e, const struct kof_tagset *names,
		     size_t *out_n)
{
	struct kof_dsrc *ed = calloc(1, sizeof *ed);
	size_t cap = 512u + (size_t)KOF_DSRC_MAX_ITEM * 400u, at = 0;
	char *buf = malloc(cap);
	uint32_t i;
	int n;

	if (!ed || !buf) {
		free(ed);
		free(buf);
		return NULL;
	}
	kof_tagsrc_items(e, NULL, ed);
	n = snprintf(buf, cap,
		     "/*\n * %s %s.\n * One declaration to a line. The comment "
		     "after an id names what it refers\n * to and is never "
		     "read; a declaration this tool does not know is\n * kept "
		     "as it is.\n */\n",
		     kof_tagsrc_kind_word(e->kind), e->name);
	at = n > 0 ? (size_t)n : 0;
	for (i = 0; i < ed->n; i++) {
		size_t l = kof_tagsrc_print(&ed->item[i], names, buf + at,
					    cap - at - 1u);

		if (!l) {
			free(ed);
			free(buf);
			return NULL;
		}
		at += l;
		buf[at++] = '\n';
	}
	buf[at] = 0;
	free(ed);
	if (out_n)
		*out_n = at;
	return buf;
}
