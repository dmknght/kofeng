#define _GNU_SOURCE

/*
 * kv_tagdata.c - the Syndromes dialog's content as data. See kv_tagdata.h for the contract.
 */

#include <stdio.h>
#include <string.h>

#include <kofmod/kofsig.h>     /* kof_disease_display */
#include "kv_tagdata.h"

static const char kv_tag_add[] = "[ Add Syndrome ]";

const char *kv_tag_label_add(void)
{
	return kv_tag_add;
}

/* The words are SHOWN through the engine's one display function (kof_disease_display: Scan, Escalation, C2); the stored ones stay lower case. */
static const char *act_label(uint32_t i, char *buf)
{
	kof_disease_display(kof_tagcat_act_name(i), buf, KV_PICK_LABEL);
	return buf;
}

static const char *obj_label(uint32_t i, char *buf)
{
	kof_disease_display(kof_tagcat_obj_name(i), buf, KV_PICK_LABEL);
	return buf;
}

struct kv_pick kv_tag_acts(void)
{
	struct kv_pick l = { kof_tagcat_act_count(), act_label, kof_tagcat_act_value };

	return l;
}

struct kv_pick kv_tag_objs(void)
{
	struct kv_pick l = { kof_tagcat_obj_count(), obj_label, kof_tagcat_obj_value };

	return l;
}

struct kv_pick kv_tag_list_of(enum kv_tag_list which)
{
	return which == KV_TAG_ACTS ? kv_tag_acts() : kv_tag_objs();
}

/* The words of the items of `mask`, comma-joined in the list's order. */
static void join_words(const struct kv_pick *l, uint32_t mask, char *out, size_t cap)
{
	char buf[KV_PICK_LABEL];
	uint32_t i, n = 0u;
	size_t at = 0;

	out[0] = 0;
	for (i = 0; i < l->n; i++) {
		if (!kv_pick_has(l, mask, i))
			continue;
		at += (size_t)snprintf(out + at, at < cap ? cap - at : 0u, "%s%s", n ? ", " : "", l->label(i, buf));
		n++;
	}
}

int32_t kv_tag_find(const struct kof_tagcat *c, const char *name)
{
	uint32_t i;

	for (i = 0; i < c->n; i++)
		if (!strcmp(c->tag[i].name, name))
			return (int32_t)i;
	return -1;
}

void kv_tag_cells(const struct kof_tagcat *c, uint32_t idx, char *name, size_t ncap, char *acts, size_t acap, char *objs, size_t ocap)
{
	struct kv_pick a = kv_tag_acts(), o = kv_tag_objs();
	const struct kof_tagcat_tag *t = kof_tagcat_get(c, idx);

	name[0] = acts[0] = objs[0] = 0;
	if (!t)
		return;
	snprintf(name, ncap, "%s", t->name);
	join_words(&a, t->acts, acts, acap);
	join_words(&o, t->objs, objs, ocap);
}

void kv_tag_comment_cell(const struct kof_tagcat *c, uint32_t idx, char *comment, size_t cap)
{
	snprintf(comment, cap, "%s", kof_tagcat_comment(c, idx));
}

void kv_tag_content_size(const struct kof_tagcat *c, int *w, int *h)
{
	char name[KOF_TAGCAT_NAME_MAX + 8], acts[192], objs[192], comment[KOF_TAGCAT_COMMENT_MAX + 1];
	uint32_t i;
	int widest = 0;

	for (i = 0; i < c->n; i++) {
		int n;

		kv_tag_cells(c, i, name, sizeof name, acts, sizeof acts, objs, sizeof objs);
		kv_tag_comment_cell(c, i, comment, sizeof comment);
		n = (int)strlen(name) + (acts[0] ? (int)KV_TAG_GAP + (int)strlen(acts) : 0) + (objs[0] ? (int)KV_TAG_GAP + (int)strlen(objs) : 0) +
		    (comment[0] ? (int)KV_TAG_COMMENT_GAP + (int)strlen(comment) : 0);
		widest = n > widest ? n : widest;
	}
	kv_dd_content_size(widest, c->n, kv_tag_add, &kv_dd_catalog_limits, w, h);
}

static void tag_cell(void *user, uint32_t row, const char **out)
{
	struct kv_tag_tab *tt = user;

	kv_tag_cells(tt->cat, row, tt->name, sizeof tt->name, tt->acts, sizeof tt->acts, tt->objs, sizeof tt->objs);
	out[0] = tt->name;
	out[1] = tt->acts;
	out[2] = tt->objs;
	kv_tag_comment_cell(tt->cat, row, tt->comment, sizeof tt->comment);
	out[3] = tt->comment;
}

static void spec_fill(struct kv_tab_spec *t, struct kv_tag_tab *tt, const struct kof_tagcat *c)
{
	memset(t, 0, sizeof *t);
	tt->cat = c;
	t->n_col = KV_TAG_COLS;
	t->n_row = c->n;
	t->flex = KV_TAG_COL_COMMENT;
	t->cell = tag_cell;
	t->user = tt;
}

/* kv_tab_measure asks for every row once; the cells are valid until the next call, which is all it reads. */
void kv_tag_spec(struct kv_tab_spec *t, struct kv_tag_tab *tt, const struct kof_tagcat *c)
{
	spec_fill(t, tt, c);
	kv_tab_measure(t);
	t->width[0] = (uint16_t)(t->width[0] + KV_TAG_GAP);
	t->width[KV_TAG_COL_ACTS] = (uint16_t)(t->width[KV_TAG_COL_ACTS] + KV_TAG_GAP);
	/* the gap before the comment column, and never narrower than an empty cell's click width (the column is clipped to its width, and
	 * it is no longer the last one, so an empty cell would otherwise answer over the gap alone) */
	t->width[KV_TAG_COL_OBJS] = (uint16_t)(t->width[KV_TAG_COL_OBJS] + KV_TAG_COMMENT_GAP);
	if (t->width[KV_TAG_COL_OBJS] < KV_TAG_EMPTY_HIT)
		t->width[KV_TAG_COL_OBJS] = KV_TAG_EMPTY_HIT;
}

void kv_tag_spec_widths(struct kv_tab_spec *t, struct kv_tag_tab *tt, const struct kof_tagcat *c, const uint16_t width[KV_TAG_COLS])
{
	spec_fill(t, tt, c);
	memcpy(t->width, width, KV_TAG_COLS * sizeof width[0]);
}

enum kv_tag_hit kv_tag_hit_of(const struct kof_tagcat *c, uint32_t idx, const struct kv_tab_geo *g, int col)
{
	char name[KOF_TAGCAT_NAME_MAX + 8], acts[192], objs[192];
	const char *cell[KV_TAG_COL_COMMENT];
	uint32_t k;
	int x0, x1;

	if (idx >= c->n)
		return KV_TAG_HIT_NONE;
	kv_tag_cells(c, idx, name, sizeof name, acts, sizeof acts, objs, sizeof objs);
	cell[0] = name;
	cell[1] = acts;
	cell[2] = objs;
	for (k = 0; k < (uint32_t)KV_TAG_COL_COMMENT; k++) {       /* the comment cell opens nothing */
		if (!kv_tab_extent(g, k, cell[k], k ? (uint32_t)KV_TAG_EMPTY_HIT : 0u, &x0, &x1) || col < x0 || col > x1)
			continue;
		return k == 0 ? KV_TAG_HIT_NAME : k == (uint32_t)KV_TAG_COL_ACTS ? KV_TAG_HIT_ACTS : KV_TAG_HIT_OBJS;
	}
	return KV_TAG_HIT_NONE;
}

int kv_tag_menu_checked(const struct kof_tagcat *c, uint32_t idx, enum kv_tag_list which, uint32_t i)
{
	struct kv_pick l = kv_tag_list_of(which);
	const struct kof_tagcat_tag *t = kof_tagcat_get(c, idx);

	return t && kv_pick_has(&l, which == KV_TAG_ACTS ? t->acts : t->objs, i);
}

enum kof_tagcat_status kv_tag_menu_toggle(struct kof_tagcat *c, uint32_t idx, enum kv_tag_list which, uint32_t i)
{
	struct kv_pick l = kv_tag_list_of(which);
	const struct kof_tagcat_tag *t = kof_tagcat_get(c, idx);

	if (!t)
		return KOF_TAGCAT_NO_TAG;
	if (which == KV_TAG_ACTS)
		return kof_tagcat_set_acts(c, idx, kv_pick_flip(&l, t->acts, i));
	return kof_tagcat_set_objs(c, idx, kv_pick_flip(&l, t->objs, i));
}

void kv_tag_error_text(const struct kof_tagcat *c, enum kof_tagcat_status st, char *out, size_t cap)
{
	if (st == KOF_TAGCAT_OK)
		snprintf(out, cap, "%s", "");
	else if (st == KOF_TAGCAT_FULL)
		snprintf(out, cap, "full: %u syndromes", (unsigned)kof_tagcat_cap(c));
	else
		snprintf(out, cap, "%s", kof_tagcat_status_text(st));
}
