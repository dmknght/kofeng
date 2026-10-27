/*
 * SWITCHED OFF (owner, 2026-10-27): the Syndrome table and its tag-source backend (kofexamine/kv_syn.c, kv_syntable.c,
 * libkofeng/databases/tagsrc*, ksigbuilder/ksb_tags.c) stay in the tree and are to be removed later, when asked. The menu item
 * is Manage > Syndromes, listed and greyed. Do not extend this code.
 */
#define _GNU_SOURCE
#include "kv.h"

/*
 * kv_syn.c - the tag sources in the viewer: the model, and what each button
 * does. The drawing, the mouse and the keys are kv_syntable.c's.
 *
 * Everything that is a RULE about the data - what a name may hold, what an id
 * is, what Check says, what a file looks like and how it is written - is
 * databases/tagsrc.h's and is only asked here. This file keeps the session: the
 * set as the researcher has edited it and not yet saved, which tab is open,
 * what the search says, the form and the pick list.
 */

#define SYN_TXT_ROOM 160

/* The kind of entity each tab lists, in tab order. */
static const uint8_t tab_kind[SYN_TABS] = {
	KOF_TAGSRC_K_ACTIVITY, KOF_TAGSRC_K_TYPE, KOF_TAGSRC_K_FAMILY,
	KOF_TAGSRC_K_TAG
};

/* ---- the layers ---------------------------------------------------------- */

void syn_layer_free(struct syn_layer *ly)
{
	free(ly->line);
	free(ly->hit);
	memset(ly, 0, sizeof *ly);
}

void syn_ly_reset(struct syn_layer *ly)
{
	ly->n = 0;
	ly->nh = 0;
	ly->fixed = 0;
}

uint32_t syn_ly_line(struct syn_layer *ly)
{
	if (ly->n == ly->cap) {
		uint32_t nc = ly->cap ? ly->cap * 2u : 64u;
		struct prop_line *g = realloc(ly->line, nc * sizeof *g);

		if (!g)
			return ly->n ? ly->n - 1u : 0u;
		ly->line = g;
		ly->cap = nc;
	}
	ly->line[ly->n].text[0] = 0;
	return ly->n++;
}

int syn_ly_col(const struct syn_layer *ly, uint32_t li)
{
	return li < ly->n ? vis_cols(ly->line[li].text) : 0;
}

void syn_ly_put(struct syn_layer *ly, uint32_t li, const char *sgr,
		const char *text)
{
	char *t;
	size_t n;

	if (li >= ly->n)
		return;
	t = ly->line[li].text;
	n = strlen(t);
	snprintf(t + n, sizeof ly->line[li].text - n, "%s%s%s", sgr, text,
		 sgr[0] ? A_OFF : "");
}

void syn_ly_hit(struct syn_layer *ly, uint32_t li, int c0, int c1, int act,
		uint32_t arg)
{
	struct syn_hit *h;

	if (ly->nh == ly->caph) {
		uint32_t nc = ly->caph ? ly->caph * 2u : 64u;
		struct syn_hit *g = realloc(ly->hit, nc * sizeof *g);

		if (!g)
			return;
		ly->hit = g;
		ly->caph = nc;
	}
	h = &ly->hit[ly->nh++];
	h->line = li;
	h->c0 = (int16_t)c0;
	h->c1 = (int16_t)c1;
	h->act = (uint8_t)act;
	h->arg = arg;
}

/* ---- the session --------------------------------------------------------- */

struct kv_syn *syn_new(const char *dir, const char *diag_dir)
{
	struct kv_syn *s = calloc(1, sizeof *s);

	if (!s)
		return NULL;
	snprintf(s->dir, sizeof s->dir, "%s", dir);
	snprintf(s->diag_dir, sizeof s->diag_dir, "%s", diag_dir);
	kof_tagset_init(&s->set);
	(void)kof_tagset_load(&s->set, dir);
	kof_tagset_count(&s->set);
	kof_tagset_count_diagnoses(&s->set, diag_dir);
	return s;
}

void syn_free(struct kv_syn *s)
{
	if (!s)
		return;
	kof_tagset_free(&s->set);
	free(s->rows);
	syn_layer_free(&s->page);
	syn_layer_free(&s->res);
	syn_layer_free(&s->frm);
	syn_layer_free(&s->pick.ly);
	free(s->pick.row);
	free(s->pick.vis);
	free(s);
}

void syn_say(struct view *v, int ok, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(v->act_msg, sizeof v->act_msg, fmt, ap);
	va_end(ap);
	v->act_ok = ok;
}

int syn_modal(const struct view *v)
{
	return v->syn && (v->syn->open || v->syn->pick.open);
}

int syn_page_up(const struct view *v)
{
	return v->syn && v->syn->open;
}

uint32_t syn_dirty(const struct kv_syn *s)
{
	size_t i;
	uint32_t n = 0;

	for (i = 0; i < s->set.n; i++)
		n += s->set.e[i].dirty != 0;
	return n;
}

/* ---- the rows ------------------------------------------------------------ */

static int contains_ci(const char *hay, const char *needle, size_t nl)
{
	size_t hl = strlen(hay), i, k;

	if (nl > hl)
		return 0;
	for (i = 0; i + nl <= hl; i++) {
		for (k = 0; k < nl; k++)
			if (tolower((unsigned char)hay[i + k]) !=
			    tolower((unsigned char)needle[k]))
				break;
		if (k == nl)
			return 1;
	}
	return 0;
}

/*
 * Does the search text let this entity through. The text is words, and every
 * word has to be found - as a substring, case folded - in the name, and in a
 * tag also in the names of its activities, types and family. `fields` are the
 * strings an entity can be found by.
 */
static int words_match(const char *filt, const char *const *fields,
		       unsigned n_fields)
{
	const char *p = filt;

	while (*p) {
		const char *e;
		unsigned f;
		int hit = 0;

		while (*p == ' ')
			p++;
		if (!*p)
			break;
		for (e = p; *e && *e != ' '; e++)
			;
		for (f = 0; f < n_fields && !hit; f++)
			hit = contains_ci(fields[f], p, (size_t)(e - p));
		if (!hit)
			return 0;
		p = e;
	}
	return 1;
}

static int ent_match(const struct kv_syn *s, const struct kof_tagent *e,
		     const char *filt)
{
	char act[SYN_TXT_ROOM], typ[SYN_TXT_ROOM];
	const char *fam;
	const char *f[4];

	f[0] = e->name;
	if (e->kind != KOF_TAGSRC_K_TAG)
		return words_match(filt, f, 1);
	kof_tagset_join(&s->set, KOF_TAGSRC_K_ACTIVITY, e->act, e->n_act, act,
			sizeof act);
	kof_tagset_join(&s->set, KOF_TAGSRC_K_TYPE, e->typ, e->n_typ, typ,
			sizeof typ);
	fam = e->has_fam ? kof_tagset_name(&s->set, KOF_TAGSRC_K_FAMILY,
					   e->fam) : NULL;
	f[1] = act;
	f[2] = typ;
	f[3] = fam ? fam : "";
	return words_match(filt, f, 4);
}

void syn_rows(struct view *v)
{
	struct kv_syn *s = v->syn;
	size_t i;

	s->n_rows = 0;
	for (i = 0; i < s->set.n; i++) {
		const struct kof_tagent *e = &s->set.e[i];

		if (e->removed || e->kind != tab_kind[s->tab] ||
		    !ent_match(s, e, s->filt))
			continue;
		if (s->n_rows == s->cap_rows) {
			uint32_t nc = s->cap_rows ? s->cap_rows * 2u : 64u;
			uint32_t *g = realloc(s->rows, nc * sizeof *g);

			if (!g)
				break;
			s->rows = g;
			s->cap_rows = nc;
		}
		s->rows[s->n_rows++] = (uint32_t)i;
	}
	if (s->sel[s->tab] >= s->n_rows)
		s->sel[s->tab] = s->n_rows ? s->n_rows - 1u : 0u;
}

/* The word of a vocabulary entry as a table shows it: the engine's name, the
 * KOF_ prefix and the class of it cut off. */
static const char *short_word(const char *w)
{
	static const char *const pre[] = { "KOF_FMT_", "KOF_EVT_", "KOF_ARCH_" };
	size_t i;

	for (i = 0; i < sizeof pre / sizeof pre[0]; i++)
		if (!strncmp(w, pre[i], strlen(pre[i])))
			return w + strlen(pre[i]);
	return !strncmp(w, "KOF_", 4) ? w + 4 : w;
}

static void join_attr(const struct kof_tagent *e, unsigned cls, char *out,
		      size_t cap)
{
	size_t at = 0;
	unsigned i;

	out[0] = 0;
	for (i = 0; i < e->n_attr[cls] && at + 2u < cap; i++)
		at += (size_t)snprintf(out + at, cap - at, "%s%s",
				       i ? "," : "",
				       short_word(kof_tagsrc_vocab_word(
					       cls, e->attr[cls][i])));
}

/* The cells of one row, in the column order of its tab. */
void syn_row_cells(const struct kv_syn *s, const struct kof_tagent *e,
		   int tab, char cell[][160])
{
	snprintf(cell[0], 160, "%s", e->name);
	snprintf(cell[1], 160, "%u", e->used);
	if (tab == SYN_ACT) {
		snprintf(cell[2], 160, "%s", e->comment);
	} else if (tab == SYN_TAG) {
		const char *f = e->has_fam
			? kof_tagset_name(&s->set, KOF_TAGSRC_K_FAMILY, e->fam)
			: NULL;
		char a[SYN_TXT_ROOM] = "", t[SYN_TXT_ROOM] = "";
		char fm[48], ar[48], sb[48];

		kof_tagset_join(&s->set, KOF_TAGSRC_K_ACTIVITY, e->act,
				e->n_act, a, sizeof a);
		kof_tagset_join(&s->set, KOF_TAGSRC_K_TYPE, e->typ, e->n_typ,
				t, sizeof t);
		snprintf(cell[1], 160, "%s", a);
		snprintf(cell[2], 160, "%s", t);
		snprintf(cell[3], 160, "%s", e->has_fam ? (f ? f : "?") : "");
		join_attr(e, KOF_TAGSRC_A_FORMAT, fm, sizeof fm);
		join_attr(e, KOF_TAGSRC_A_ARCH, ar, sizeof ar);
		join_attr(e, KOF_TAGSRC_A_SUBTYPE, sb, sizeof sb);
		snprintf(cell[4], 160, "%s%s%s%s%s%s",
			 fm[0] ? "fmt " : "", fm,
			 ar[0] ? (fm[0] ? " arch " : "arch ") : "", ar,
			 sb[0] ? (fm[0] || ar[0] ? " sub " : "sub ") : "", sb);
		snprintf(cell[5], 160, "%u", e->used);
		snprintf(cell[6], 160, "%s", e->comment);
	}
}

/* ---- the page ------------------------------------------------------------ */

/*
 * WHAT NAMES A TAG: the diagnose sources of the tree (a KOF_DIAG_TAG line, read
 * from the files) and the draft in the panel, whose conditions and standalone
 * block matchers are diagnoses that are not written yet. Counted together
 * because a tag the draft is about to write is as much in use as one a file
 * already names.
 */
static void bump_use(struct kv_syn *s, uint64_t tag)
{
	struct kof_tagent *t = tag ? kof_tagset_find(&s->set,
						     KOF_TAGSRC_K_TAG, tag)
				   : NULL;

	if (t)
		t->used++;
}

static void count_uses(struct view *v)
{
	struct kv_syn *s = v->syn;
	uint32_t i;

	kof_tagset_count_diagnoses(&s->set, s->diag_dir);
	for (i = 0; i < v->ed.dr.n_cnd; i++)
		bump_use(s, v->ed.dr.cnd[i].tag);
	for (i = 0; i < v->ed.dr.n_grp; i++)
		if (grp_standalone(&v->ed, i))
			bump_use(s, v->ed.dr.grp[i].tag);
}

void syn_open(struct view *v)
{
	struct kv_syn *s = v->syn;

	if (!s)
		return;
	s->open = 1;
	s->filt[0] = 0;
	s->foff = 0;
	s->res_open = 0;
	s->form.open = 0;
	s->has_parent = 0;
	s->pick.open = 0;
	s->page.off = 0;
	v->edit = 0;
	v->act_msg[0] = 0;
	kof_tagset_count(&s->set);
	count_uses(v);
	syn_rows(v);
	if (!s->set.n && !s->set.n_prob)
		syn_say(v, 0, "no tag sources in %.150s - Add one, Save "
			"writes the directory", s->dir);
}

void syn_close(struct view *v)
{
	if (v->syn) {
		v->syn->open = 0;
		v->syn->res_open = 0;
		v->syn->form.open = 0;
		v->syn->pick.open = 0;
	}
	v->edit = 0;
}

void syn_tab_set(struct view *v, int tab)
{
	struct kv_syn *s = v->syn;

	if (tab < 0 || tab >= SYN_TABS)
		return;
	s->tab = tab;
	s->page.off = 0;
	v->edit = 0;
	syn_rows(v);
}

/* The entity the cursor is on, or NULL. */
static struct kof_tagent *sel_ent(struct view *v, size_t *idx)
{
	struct kv_syn *s = v->syn;
	uint32_t r = s->sel[s->tab];

	if (r >= s->n_rows)
		return NULL;
	if (idx)
		*idx = s->rows[r];
	return &s->set.e[s->rows[r]];
}

/* ---- the form ------------------------------------------------------------ */

static void form_focus(struct view *v, int code)
{
	v->edit = code;
	v->edit_prev = 0;
}

void syn_form_open(struct view *v, int kind, int edit)
{
	struct kv_syn *s = v->syn;
	struct syn_form *f = &s->form;
	struct kof_tagent *e;
	size_t idx = 0;

	if (kind <= 0)
		kind = tab_kind[s->tab];
	if (edit) {
		e = sel_ent(v, &idx);
		if (!e) {
			syn_say(v, 0, "Select a row to edit first");
			return;
		}
		memset(f, 0, sizeof *f);
		f->e = *e;
		f->e.text = NULL;
		f->e.path[0] = 0;
		f->ent = idx;
		kind = e->kind;
	} else {
		memset(f, 0, sizeof *f);
		f->e.kind = (uint8_t)kind;
	}
	f->open = 1;
	f->kind = (uint8_t)kind;
	f->edit = edit;
	snprintf(f->name, sizeof f->name, "%s", f->e.name);
	snprintf(f->cmt, sizeof f->cmt, "%s", f->e.comment);
	form_focus(v, ED_SYN_NAME);
	v->act_msg[0] = 0;
}

static int ent_same(const struct kof_tagent *a, const struct kof_tagent *b)
{
	unsigned c;

	if (strcmp(a->name, b->name) || strcmp(a->comment, b->comment) ||
	    a->n_act != b->n_act || a->n_typ != b->n_typ ||
	    a->has_fam != b->has_fam || (a->has_fam && a->fam != b->fam) ||
	    memcmp(a->act, b->act, a->n_act * sizeof a->act[0]) ||
	    memcmp(a->typ, b->typ, a->n_typ * sizeof a->typ[0]))
		return 0;
	for (c = 0; c < KOF_TAGSRC_A_COUNT; c++)
		if (a->n_attr[c] != b->n_attr[c] ||
		    memcmp(a->attr[c], b->attr[c],
			   a->n_attr[c] * sizeof a->attr[c][0]))
			return 0;
	return 1;
}

/* A new entity's id goes into the tag form that asked for it. */
static void parent_gets(struct syn_form *p, uint8_t kind, uint64_t id)
{
	if (kind == KOF_TAGSRC_K_ACTIVITY && p->e.n_act < KOF_TAGSRC_REFS)
		p->e.act[p->e.n_act++] = id;
	else if (kind == KOF_TAGSRC_K_TYPE && p->e.n_typ < KOF_TAGSRC_REFS)
		p->e.typ[p->e.n_typ++] = id;
	else if (kind == KOF_TAGSRC_K_FAMILY) {
		p->e.fam = id;
		p->e.has_fam = 1;
	}
}

static void form_back(struct view *v)
{
	struct kv_syn *s = v->syn;

	if (s->has_parent) {
		s->form = s->parent;
		s->has_parent = 0;
		form_focus(v, ED_SYN_NAME);
	} else {
		s->form.open = 0;
		v->edit = 0;
	}
}

void syn_form_ok(struct view *v)
{
	struct kv_syn *s = v->syn;
	struct syn_form *f = &s->form;
	struct kof_tagent *e;
	uint8_t kind = f->kind;
	int was_edit = f->edit;
	uint64_t id = 0;
	char shown[KOF_TAGSRC_NAME_LEN];

	f->err[0] = 0;
	kof_tagsrc_name_norm(f->e.name, sizeof f->e.name, f->name);
	snprintf(f->e.comment, sizeof f->e.comment, "%s", f->cmt);
	if (!f->e.name[0]) {
		snprintf(f->err, sizeof f->err, "The name is empty.");
		return;
	}
	if (f->edit) {
		e = &s->set.e[f->ent];
		id = e->id;
		if (!ent_same(e, &f->e)) {
			memcpy(e->name, f->e.name, sizeof e->name);
			memcpy(e->comment, f->e.comment, sizeof e->comment);
			memcpy(e->act, f->e.act, sizeof e->act);
			memcpy(e->typ, f->e.typ, sizeof e->typ);
			e->n_act = f->e.n_act;
			e->n_typ = f->e.n_typ;
			e->has_fam = f->e.has_fam;
			e->fam = f->e.fam;
			memcpy(e->attr, f->e.attr, sizeof e->attr);
			memcpy(e->n_attr, f->e.n_attr, sizeof e->n_attr);
			e->dirty = 1;
		}
	} else {
		const char *why = NULL;

		e = kof_tagset_add(&s->set, &f->e, NULL, NULL, &why);
		if (!e) {
			snprintf(f->err, sizeof f->err, "%s.", why ? why :
				 "Cannot add it");
			return;
		}
		id = e->id;
	}
	snprintf(shown, sizeof shown, "%s", f->e.name);
	if (s->has_parent)
		parent_gets(&s->parent, kind, id);
	form_back(v);
	kof_tagset_count(&s->set);
	syn_rows(v);
	if (!s->has_parent && s->form.open == 0) {
		uint32_t r;

		for (r = 0; r < s->n_rows; r++)
			if (s->set.e[s->rows[r]].id == id)
				s->sel[s->tab] = r;
	}
	syn_say(v, 1, "%s %s %s - Save writes it", was_edit ? "Changed" :
		"Added", kof_tagsrc_kind_word(kind), shown);
}

void syn_form_cancel(struct view *v)
{
	form_back(v);
}

void syn_form_new(struct view *v, int kind)
{
	struct kv_syn *s = v->syn;

	if (s->has_parent)
		return;
	kof_tagsrc_name_norm(s->form.e.name, sizeof s->form.e.name,
			     s->form.name);
	snprintf(s->form.e.comment, sizeof s->form.e.comment, "%s",
		 s->form.cmt);
	s->parent = s->form;
	s->has_parent = 1;
	syn_form_open(v, kind, 0);
}

/* ---- delete, check, save ------------------------------------------------- */

static void res_begin(struct kv_syn *s, const char *title)
{
	syn_ly_reset(&s->res);
	snprintf(s->res_title, sizeof s->res_title, "%s", title);
	s->res.off = 0;
	s->res.fixed = 1;
	syn_ly_line(&s->res);           /* the summary, filled when known */
	s->res_open = 1;
}

void syn_delete(struct view *v)
{
	struct kv_syn *s = v->syn;
	struct kof_tagent *e;
	const struct kof_tagent *by[24];
	size_t i, n, shown;
	char t[200];

	e = sel_ent(v, NULL);
	if (!e) {
		syn_say(v, 0, "Select a row to delete first");
		return;
	}
	n = kof_tagset_refs(&s->set, e, by, sizeof by / sizeof by[0]);
	if (!n && !(e->kind == KOF_TAGSRC_K_TAG && e->used)) {
		snprintf(t, sizeof t, "%s", e->name);
		kof_tagset_remove(&s->set, e);
		kof_tagset_count(&s->set);
		syn_rows(v);
		syn_say(v, 1, "Removed %s %s - Save removes its file",
			kof_tagsrc_kind_word(tab_kind[s->tab]), t);
		return;
	}
	res_begin(s, "Cannot delete");
	snprintf(t, sizeof t, "%s \"%s\" is still named by:",
		 kof_tagsrc_kind_word(e->kind), e->name);
	syn_ly_put(&s->res, 0, A_BAD, t);
	shown = n < sizeof by / sizeof by[0] ? n : sizeof by / sizeof by[0];
	for (i = 0; i < shown; i++) {
		uint32_t li = syn_ly_line(&s->res);

		snprintf(t, sizeof t, "  tag %s", by[i]->name);
		syn_ly_put(&s->res, li, "", t);
	}
	if (n > shown) {
		uint32_t li = syn_ly_line(&s->res);

		snprintf(t, sizeof t, "  and %zu more", n - shown);
		syn_ly_put(&s->res, li, A_DIM, t);
	}
	if (e->kind == KOF_TAGSRC_K_TAG && e->used) {
		uint32_t li = syn_ly_line(&s->res);

		snprintf(t, sizeof t, "  %u diagnose source(s) or output(s) of "
			 "the draft naming it", e->used);
		syn_ly_put(&s->res, li, "", t);
	}
	syn_say(v, 0, "Not deleted: %s still has references", e->name);
}

struct chk_cx {
	struct kv_syn *s;
	unsigned       n[3];
};

static void chk_say(void *ud, int level, const char *subject,
		    const char *msg)
{
	struct chk_cx *c = ud;
	static const char *const word[] = { "info   ", "warning", "error  " };
	static const char *const col[] = { A_DIM, A_WARN, A_BAD };
	uint32_t li;
	char t[300];

	if (level < 0 || level > 2)
		level = 0;
	c->n[level]++;
	li = syn_ly_line(&c->s->res);
	snprintf(t, sizeof t, "%s  %s: %s", word[level], subject, msg);
	syn_ly_put(&c->s->res, li, col[level], t);
}

void syn_check(struct view *v)
{
	struct kv_syn *s = v->syn;
	struct chk_cx c;
	struct kof_tagsrc_report r;
	char t[200];
	int errs;

	memset(&c, 0, sizeof c);
	c.s = s;
	res_begin(s, "Check");
	r.say = chk_say;
	r.ud = &c;
	errs = kof_tagset_check(&s->set, &r);
	snprintf(t, sizeof t, "%zu entities: %d error(s), %u warning(s), "
		 "%u note(s)", s->set.n, errs, c.n[KOF_TAGSRC_WARN],
		 c.n[KOF_TAGSRC_INFO]);
	s->res.line[0].text[0] = 0;
	syn_ly_put(&s->res, 0, errs ? A_BAD : A_SIZE, t);
	if (s->res.n == 1) {
		uint32_t li = syn_ly_line(&s->res);

		syn_ly_put(&s->res, li, A_DIM, "nothing to report");
	}
	syn_say(v, errs == 0, "Check: %d error(s), %u warning(s)", errs,
		c.n[KOF_TAGSRC_WARN]);
	syn_rows(v);
}

void syn_save(struct view *v)
{
	struct kv_syn *s = v->syn;
	char why[200];
	int n = kof_tagset_save(&s->set, why, sizeof why);

	if (n < 0) {
		syn_say(v, 0, "Save failed: %.160s", why);
		return;
	}
	kof_tagset_count(&s->set);
	count_uses(v);
	syn_rows(v);
	if (n)
		syn_say(v, 1, "Saved %d file(s) in %.120s", n, s->dir);
	else
		syn_say(v, 1, "Nothing changed: nothing written");
}

/* ---- the pick list ------------------------------------------------------- */

static struct syn_prow *pick_row(struct syn_pick *p)
{
	struct syn_prow *r;

	if (p->n == p->cap) {
		uint32_t nc = p->cap ? p->cap * 2u : 64u;
		struct syn_prow *g = realloc(p->row, nc * sizeof *g);

		if (!g)
			return NULL;
		p->row = g;
		p->cap = nc;
	}
	r = &p->row[p->n++];
	memset(r, 0, sizeof *r);
	return r;
}

static void pick_head(struct syn_pick *p, const char *a, const char *b,
		      const char *c, const char *d)
{
	const char *h[4] = { a, b, c, d };
	int i;

	for (i = 0; i < 4; i++)
		snprintf(p->head[i], sizeof p->head[i], "%s", h[i]);
}

/* The order an id was declared in, as a tick position: 1 first, 0 none. */
static uint32_t pos_of(const uint64_t *a, uint32_t n, uint64_t id)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (a[i] == id)
			return i + 1u;
	return 0;
}

/* The rows of a list of entities of one kind. */
static void pick_ents(struct kv_syn *s, uint8_t kind, const uint64_t *have,
		      uint32_t n_have, int none)
{
	struct syn_pick *p = &s->pick;
	size_t i;

	if (none) {
		struct syn_prow *r = pick_row(p);

		if (r)
			snprintf(r->col[0], sizeof r->col[0], "(none)");
	}
	for (i = 0; i < s->set.n; i++) {
		const struct kof_tagent *e = &s->set.e[i];
		struct syn_prow *r;

		if (e->removed || e->kind != kind || !(r = pick_row(p)))
			continue;
		r->id = e->id;
		r->pos = pos_of(have, n_have, e->id);
		snprintf(r->col[0], sizeof r->col[0], "%s", e->name);
		snprintf(r->col[1], sizeof r->col[1], "%s", e->comment);
	}
}

static void pick_words(struct kv_syn *s, unsigned cls,
		       const struct kof_tagent *e)
{
	struct syn_pick *p = &s->pick;
	size_t i, n = kof_tagsrc_vocab_n(cls);

	for (i = 0; i < n; i++) {
		struct syn_prow *r = pick_row(p);
		uint32_t k;

		if (!r)
			break;
		r->idx = (uint16_t)i;
		for (k = 0; k < e->n_attr[cls]; k++)
			if (e->attr[cls][k] == (uint16_t)i)
				r->pos = k + 1u;
		snprintf(r->col[0], sizeof r->col[0], "%s",
			 kof_tagsrc_vocab_word(cls, i));
	}
}

/* The rows of the tag chooser: (no tag), then every tag. */
static void pick_tags(struct kv_syn *s, uint64_t current)
{
	struct syn_pick *p = &s->pick;
	size_t i;
	struct syn_prow *r = pick_row(p);

	if (r)
		snprintf(r->col[0], sizeof r->col[0], "(no tag)");
	for (i = 0; i < s->set.n; i++) {
		const struct kof_tagent *e = &s->set.e[i];
		const char *f;

		if (e->removed || e->kind != KOF_TAGSRC_K_TAG ||
		    !(r = pick_row(p)))
			continue;
		r->id = e->id;
		snprintf(r->col[0], sizeof r->col[0], "%s", e->name);
		kof_tagset_join(&s->set, KOF_TAGSRC_K_ACTIVITY, e->act,
				e->n_act, r->col[1], sizeof r->col[1]);
		kof_tagset_join(&s->set, KOF_TAGSRC_K_TYPE, e->typ, e->n_typ,
				r->col[2], sizeof r->col[2]);
		f = e->has_fam ? kof_tagset_name(&s->set, KOF_TAGSRC_K_FAMILY,
						 e->fam) : NULL;
		snprintf(r->col[3], sizeof r->col[3], "%s", f ? f : "");
		if (e->id == current)
			p->want = (uint32_t)(p->n - 1u);
	}
}

static void pick_begin(struct view *v, int what, uint32_t arg, int multi,
		       const char *title, int ncol)
{
	struct syn_pick *p = &v->syn->pick;

	p->n = 0;
	p->what = what;
	p->arg = arg;
	p->multi = multi;
	p->ncol = ncol;
	p->ticks = 0;
	p->sel = 0;
	p->want = UINT32_MAX;
	p->foff = 0;
	p->filt[0] = 0;
	p->ly.off = 0;
	snprintf(p->title, sizeof p->title, "%s", title);
	pick_head(p, "Name", "", "", "");
	p->open = 1;
	v->edit = ED_SYN_PICK;
	v->edit_prev = 0;
}

/* After the rows are in: the ticks already made give the next one its order. */
static void pick_ticks(struct syn_pick *p)
{
	uint32_t i;

	for (i = 0; i < p->n; i++)
		if (p->row[i].pos > p->ticks)
			p->ticks = p->row[i].pos;
}

void syn_form_pick(struct view *v, int what)
{
	struct kv_syn *s = v->syn;
	const struct kof_tagent *e = &s->form.e;

	switch (what) {
	case PK_ACT:
		pick_begin(v, what, 0, 1, "Activities", 2);
		pick_head(&s->pick, "Name", "Comment", "", "");
		pick_ents(s, KOF_TAGSRC_K_ACTIVITY, e->act, e->n_act, 0);
		break;
	case PK_TYP:
		pick_begin(v, what, 0, 1, "Types", 1);
		pick_ents(s, KOF_TAGSRC_K_TYPE, e->typ, e->n_typ, 0);
		break;
	case PK_FAM:
		pick_begin(v, what, 0, 0, "Family", 1);
		pick_ents(s, KOF_TAGSRC_K_FAMILY, &e->fam, e->has_fam ? 1u : 0u,
			  1);
		break;
	case PK_FMT:
		pick_begin(v, what, 0, 1, "Formats", 1);
		pick_words(s, KOF_TAGSRC_A_FORMAT, e);
		break;
	case PK_ARCH:
		pick_begin(v, what, 0, 1, "Architectures", 1);
		pick_words(s, KOF_TAGSRC_A_ARCH, e);
		break;
	case PK_SUB:
		pick_begin(v, what, 0, 1, "Subtypes", 1);
		pick_words(s, KOF_TAGSRC_A_SUBTYPE, e);
		break;
	default:
		return;
	}
	pick_ticks(&s->pick);
}

/*
 * THE TAG CHOOSER OF THE DIAGNOSE PANEL. The shared Type and Family of the
 * draft are only where the search STARTS: they pre-fill it, so the list opens
 * on the tags of that type and family, and clearing the box shows every tag.
 * They decide nothing else.
 */
void syn_pick_tag(struct view *v, int what, uint32_t arg)
{
	struct kv_syn *s = v->syn;
	struct syn_pick *p;
	uint64_t cur = 0;
	char filt[SYN_FILT];
	size_t n = 0;

	if (!s)
		return;
	p = &s->pick;
	if (what == PK_TAG_COND && arg < v->ed.dr.n_cnd)
		cur = v->ed.dr.cnd[arg].tag;
	else if (what == PK_TAG_GRP && arg < v->ed.dr.n_grp)
		cur = v->ed.dr.grp[arg].tag;
	else
		return;
	pick_begin(v, what, arg, 0, "Tag", 4);
	pick_head(p, "Name", "Activities", "Types", "Family");
	pick_tags(s, cur);
	filt[0] = 0;
	if (v->ed.dr.maltype && v->ed.dr.maltype < MALTYPE_N)
		n += (size_t)snprintf(filt + n, sizeof filt - n, "%s",
				      maltype_word[v->ed.dr.maltype]);
	if (v->ed.dr.family[0] && n + 2u < sizeof filt)
		snprintf(filt + n, sizeof filt - n, "%s%s", n ? " " : "",
			 v->ed.dr.family);
	snprintf(p->filt, sizeof p->filt, "%s", filt);
}

void syn_pick_vis(struct view *v)
{
	struct syn_pick *p = &v->syn->pick;
	uint32_t i, k;

	p->n_vis = 0;
	p->n_real = 0;
	for (i = 0; i < p->n; i++) {
		const char *f[4];
		/* "(no tag)" and "(none)" are rows of the list and not tags:
		 * they stay whatever is typed, so the way out is never hidden. */
		int way_out = !p->multi && !p->row[i].id &&
			      p->row[i].col[0][0] == '(';

		for (k = 0; k < 4; k++)
			f[k] = p->row[i].col[k];
		if (!way_out && !words_match(p->filt, f, (unsigned)p->ncol))
			continue;
		if (p->n_vis == p->cap_vis) {
			uint32_t nc = p->cap_vis ? p->cap_vis * 2u : 64u;
			uint32_t *g = realloc(p->vis, nc * sizeof *g);

			if (!g)
				break;
			p->vis = g;
			p->cap_vis = nc;
		}
		p->vis[p->n_vis++] = i;
		p->n_real += !way_out;
	}
	if (p->want != UINT32_MAX) {
		for (i = 0; i < p->n_vis; i++)
			if (p->vis[i] == p->want)
				p->sel = i;
		p->want = UINT32_MAX;
	}
	if (p->sel >= p->n_vis)
		p->sel = p->n_vis ? p->n_vis - 1u : 0u;
}

/* After the search changed: the cursor goes to the first row that is a match,
 * not to "(none)", which stays first in the list. */
void syn_pick_home(struct view *v)
{
	struct syn_pick *p = &v->syn->pick;
	uint32_t i;

	syn_pick_vis(v);
	p->sel = 0;
	for (i = 0; i < p->n_vis; i++)
		if (p->row[p->vis[i]].id || p->multi) {
			p->sel = i;
			break;
		}
	p->ly.off = 0;
}

void syn_pick_toggle(struct view *v, uint32_t vi)
{
	struct syn_pick *p = &v->syn->pick;
	struct syn_prow *r;

	if (vi >= p->n_vis)
		return;
	p->sel = vi;
	r = &p->row[p->vis[vi]];
	if (!p->multi) {
		syn_pick_ok(v);
		return;
	}
	r->pos = r->pos ? 0u : ++p->ticks;
}

/* The ticked rows, in the order they were ticked. */
static uint32_t pick_ticked(const struct syn_pick *p, uint32_t *out,
			    uint32_t cap)
{
	uint32_t n = 0, i, j;

	for (i = 0; i < p->n && n < cap; i++)
		if (p->row[i].pos)
			out[n++] = i;
	for (i = 1; i < n; i++)
		for (j = i; j && p->row[out[j]].pos < p->row[out[j - 1u]].pos;
		     j--) {
			uint32_t t = out[j];

			out[j] = out[j - 1u];
			out[j - 1u] = t;
		}
	return n;
}

static void pick_apply_form(struct kv_syn *s)
{
	struct syn_pick *p = &s->pick;
	struct kof_tagent *e = &s->form.e;
	uint32_t *t = malloc(p->n * sizeof *t + sizeof *t);
	uint32_t n, i, cap;
	int cls = -1;

	if (!t)
		return;
	n = pick_ticked(p, t, p->n);
	switch (p->what) {
	case PK_ACT: case PK_TYP:
		cap = KOF_TAGSRC_REFS;
		if (n > cap)
			n = cap;
		if (p->what == PK_ACT) {
			e->n_act = (uint8_t)n;
			for (i = 0; i < n; i++)
				e->act[i] = p->row[t[i]].id;
		} else {
			e->n_typ = (uint8_t)n;
			for (i = 0; i < n; i++)
				e->typ[i] = p->row[t[i]].id;
		}
		break;
	case PK_FAM:
		e->has_fam = 0;
		if (p->sel < p->n_vis && p->row[p->vis[p->sel]].id) {
			e->has_fam = 1;
			e->fam = p->row[p->vis[p->sel]].id;
		}
		break;
	default:
		cls = p->what == PK_FMT ? KOF_TAGSRC_A_FORMAT
		    : p->what == PK_ARCH ? KOF_TAGSRC_A_ARCH
		    : KOF_TAGSRC_A_SUBTYPE;
		if (n > KOF_TAGSRC_ATTRS)
			n = KOF_TAGSRC_ATTRS;
		e->n_attr[cls] = (uint8_t)n;
		for (i = 0; i < n; i++)
			e->attr[cls][i] = p->row[t[i]].idx;
		break;
	}
	free(t);
}

void syn_pick_ok(struct view *v)
{
	struct kv_syn *s = v->syn;
	struct syn_pick *p = &s->pick;
	uint64_t id = 0;

	if (p->what == PK_TAG_COND || p->what == PK_TAG_GRP) {
		if (p->sel < p->n_vis)
			id = p->row[p->vis[p->sel]].id;
		if (p->what == PK_TAG_COND && p->arg < v->ed.dr.n_cnd)
			v->ed.dr.cnd[p->arg].tag = id;
		else if (p->what == PK_TAG_GRP && p->arg < v->ed.dr.n_grp)
			v->ed.dr.grp[p->arg].tag = id;
	} else {
		pick_apply_form(s);
	}
	p->open = 0;
	v->edit = s->form.open ? ED_SYN_NAME : 0;
	v->edit_prev = 0;
}

void syn_pick_cancel(struct view *v)
{
	v->syn->pick.open = 0;
	v->edit = v->syn->form.open ? ED_SYN_NAME : 0;
	v->edit_prev = 0;
}
