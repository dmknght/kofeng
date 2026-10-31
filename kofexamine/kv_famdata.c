#define _GNU_SOURCE

/*
 * kv_famdata.c - the Pathogens dialog's content as data. See kv_famdata.h for the contract.
 */

#include <stdio.h>
#include <string.h>

#include "kv_famdata.h"

static const char kv_fam_add_variant[] = "[ Add variant ]";
static const char kv_fam_add_family[] = "[ Add family ]";

const char *kv_fam_label_add_variant(void)
{
	return kv_fam_add_variant;
}

void kv_fam_content_size(const struct kof_famcat *c, const struct kv_fam_row *rows, uint32_t n_row, int *w, int *h)
{
	char name[KOF_FAMCAT_NAME_MAX + 8], types[128], comment[KOF_FAMCAT_COMMENT_MAX + 1];
	uint32_t i;
	int widest = 0;

	for (i = 0; i < n_row; i++) {
		int n;

		if (rows[i].kind == KV_FAM_ADDVAR) {
			n = (int)KV_FAM_INDENT + (int)strlen(kv_fam_add_variant);
		} else {
			kv_fam_cells(c, &rows[i], name, sizeof name, types, sizeof types, comment, sizeof comment);
			n = (int)strlen(name) + (types[0] ? 2 + (int)strlen(types) : 0) + (comment[0] ? 2 + (int)strlen(comment) : 0);
		}
		widest = n > widest ? n : widest;
	}
	kv_dd_content_size(widest, n_row, kv_fam_add_family, &kv_dd_catalog_limits, w, h);
}

const char *kv_fam_label_add_family(void)
{
	return kv_fam_add_family;
}

uint32_t kv_fam_rows(const struct kof_famcat *c, struct kv_fam_row *out, uint32_t cap)
{
	uint32_t f, v, n = 0u;

	for (f = 0; f < c->n_fam; f++) {
		if (n < cap) {
			out[n].kind = KV_FAM_FAMILY;
			out[n].family = f;
			out[n].variant = -1;
		}
		n++;
		for (v = 0; v < c->n_var; v++) {
			if (c->var[v].family != f)
				continue;
			if (n < cap) {
				out[n].kind = KV_FAM_VARIANT;
				out[n].family = f;
				out[n].variant = (int32_t)v;
			}
			n++;
		}
		if (n < cap) {
			out[n].kind = KV_FAM_ADDVAR;
			out[n].family = f;
			out[n].variant = -1;
		}
		n++;
	}
	return n;
}

int32_t kv_fam_find_family(const struct kof_famcat *c, const char *name)
{
	uint32_t i;

	for (i = 0; i < c->n_fam; i++)
		if (!strcmp(c->fam[i].name, name))
			return (int32_t)i;
	return -1;
}

int32_t kv_fam_find_variant(const struct kof_famcat *c, const char *name)
{
	uint32_t i;

	for (i = 0; i < c->n_var; i++)
		if (!strcmp(c->var[i].name, name))
			return (int32_t)i;
	return -1;
}

int32_t kv_fam_find_family_id(const struct kof_famcat *c, uint64_t id)
{
	uint32_t i;

	for (i = 0; id && i < c->n_fam; i++)
		if (kof_famcat_fam_id_at(c, i) == id)
			return (int32_t)i;
	return -1;
}

int32_t kv_fam_find_variant_id(const struct kof_famcat *c, uint64_t id)
{
	uint32_t i;

	for (i = 0; id && i < c->n_var; i++)
		if (kof_famcat_var_id_at(c, i) == id)
			return (int32_t)i;
	return -1;
}

void kv_fam_cells(const struct kof_famcat *c, const struct kv_fam_row *r, char *name, size_t ncap, char *types,
		  size_t tcap, char *comment, size_t ccap)
{
	uint32_t i, n = 0u;

	name[0] = types[0] = comment[0] = 0;
	if (r->kind == KV_FAM_FAMILY) {
		snprintf(name, ncap, "%s", c->fam[r->family].name);
	} else if (r->kind == KV_FAM_ADDVAR) {
		snprintf(name, ncap, "%*s%s", (int)KV_FAM_INDENT, "", kv_fam_add_variant);
	} else {
		const struct kof_famcat_var *v = &c->var[r->variant];
		size_t at = 0;

		snprintf(name, ncap, "%*s%s", (int)KV_FAM_INDENT, "", v->name);
		snprintf(comment, ccap, "%s", v->comment);
		for (i = 0; i < kof_famcat_type_count(); i++) {
			if (!kv_fam_mask_has(v->types, i))
				continue;
			at += (size_t)snprintf(types + at, at < tcap ? tcap - at : 0u, "%s%s", n ? ", " : "",
					       kof_famcat_type_name(i));
			n++;
		}
		if (!n)
			snprintf(types, tcap, "(none)");
	}
}

static void fam_cell(void *user, uint32_t row, const char **out)
{
	struct kv_fam_tab *ft = user;

	kv_fam_cells(ft->cat, &ft->row[row], ft->name, sizeof ft->name, ft->types, sizeof ft->types, ft->comment,
		     sizeof ft->comment);
	out[0] = ft->name;
	out[1] = ft->types;
	out[2] = ft->comment;
	if (ft->edit_var >= 0 && ft->row[row].kind == KV_FAM_VARIANT && ft->row[row].variant == ft->edit_var)
		ft->comment[0] = 0;
}

static void fam_spec_fill(struct kv_tab_spec *t, struct kv_fam_tab *ft, const struct kof_famcat *c, const struct kv_fam_row *rows,
			  uint32_t n_row)
{
	memset(t, 0, sizeof *t);
	ft->cat = c;
	ft->row = rows;
	ft->n_row = n_row;
	ft->edit_var = -1;      /* the caller sets it after this: the columns are measured on the real comments */
	t->n_col = KV_FAM_COLS;
	t->n_row = n_row;
	t->flex = KV_FAM_COL_COMMENT;
	t->cell = fam_cell;
	t->user = ft;
}

/* kv_tab_measure asks for every row once; the cells are valid until the next call, which is all it reads. */
void kv_fam_spec(struct kv_tab_spec *t, struct kv_fam_tab *ft, const struct kof_famcat *c, const struct kv_fam_row *rows,
		 uint32_t n_row)
{
	fam_spec_fill(t, ft, c, rows, n_row);
	kv_tab_measure(t);
	/* A gap before the comment column: the types text and the comment read as two columns, not as one line (owner). */
	t->width[KV_FAM_COL_COMMENT - 1] = (uint16_t)(t->width[KV_FAM_COL_COMMENT - 1] + KV_FAM_COMMENT_GAP);   /* the types column */
}

void kv_fam_spec_widths(struct kv_tab_spec *t, struct kv_fam_tab *ft, const struct kof_famcat *c, const struct kv_fam_row *rows,
			uint32_t n_row, const uint16_t width[KV_FAM_COLS])
{
	fam_spec_fill(t, ft, c, rows, n_row);
	memcpy(t->width, width, KV_FAM_COLS * sizeof width[0]);
}

enum kv_fam_hit kv_fam_hit_of(const struct kof_famcat *c, const struct kv_fam_row *r, const struct kv_tab_geo *g, int col,
			      uint32_t *index)
{
	char name[KOF_FAMCAT_NAME_MAX + 8], types[128], comment[KOF_FAMCAT_COMMENT_MAX + 1];
	uint32_t k;
	int x0, x1;

	if (r->kind != KV_FAM_FAMILY && r->kind != KV_FAM_VARIANT)
		return KV_FAM_HIT_NONE;
	kv_fam_cells(c, r, name, sizeof name, types, sizeof types, comment, sizeof comment);
	for (k = 0; k < KV_FAM_COLS; k++) {
		const char *s = k == 0 ? name : k == 1 ? types : comment;

		if (r->kind == KV_FAM_FAMILY && k != 0)
			break;          /* a family has no types and no comment */
		if (!kv_tab_extent(g, k, s, k == (uint32_t)KV_FAM_COL_COMMENT ? (uint32_t)KV_FAM_EMPTY_HIT : 0u, &x0, &x1) ||
		    col < x0 || col > x1)
			continue;
		if (r->kind == KV_FAM_FAMILY) {
			*index = r->family;
			return KV_FAM_HIT_FAMILY;
		}
		*index = (uint32_t)r->variant;
		return k == 0 ? KV_FAM_HIT_VARIANT : k == 1 ? KV_FAM_HIT_TYPES : KV_FAM_HIT_COMMENT;
	}
	return KV_FAM_HIT_NONE;
}

int kv_fam_button_at(const struct kv_tab_geo *g, int col)
{
	int x0 = g->cx[0] + (int)KV_FAM_INDENT - (int)g->cfrom[0], x1 = x0 + (int)strlen(kv_fam_add_variant) - 1;

	if (g->n_col < 1u || g->cw[0] <= 0)
		return 0;
	return col >= x0 && col <= x1 && col >= g->cx[0] && col < g->cx[0] + g->cw[0];
}

uint32_t kv_fam_menu_count(void)
{
	return kof_famcat_type_count();
}

const char *kv_fam_menu_label(uint32_t i)
{
	return kof_famcat_type_name(i);
}

static const char *type_label(uint32_t i, char *buf)
{
	(void)buf;                          /* the engine's spelling is already what is shown */
	return kof_famcat_type_name(i);
}

struct kv_pick kv_fam_types(void)
{
	struct kv_pick l = { kof_famcat_type_count(), type_label, kof_famcat_type_value };

	return l;
}

int kv_fam_mask_has(uint32_t mask, uint32_t i)
{
	struct kv_pick l = kv_fam_types();

	return kv_pick_has(&l, mask, i);
}

uint32_t kv_fam_mask_flip(uint32_t mask, uint32_t i)
{
	struct kv_pick l = kv_fam_types();

	return kv_pick_flip(&l, mask, i);
}

int kv_fam_menu_checked(const struct kof_famcat *c, uint32_t variant, uint32_t i)
{
	return variant < c->n_var && kv_fam_mask_has(c->var[variant].types, i);
}

enum kof_famcat_status kv_fam_menu_toggle(struct kof_famcat *c, uint32_t variant, uint32_t i)
{
	if (variant >= c->n_var)
		return KOF_FAMCAT_NO_FAMILY;
	return kof_famcat_set_types(c, variant, kv_fam_mask_flip(c->var[variant].types, i));
}

void kv_fam_error_text(const struct kof_famcat *c, enum kof_famcat_status st, char *out, size_t cap)
{
	if (st == KOF_FAMCAT_OK)
		snprintf(out, cap, "%s", "");
	else if (st == KOF_FAMCAT_VARIANT_NAME)
		snprintf(out, cap, "family name over %u characters", (unsigned)kof_famcat_family_max(c));
	else if (st == KOF_FAMCAT_FULL)
		snprintf(out, cap, "full: %u families, %u variants",
			 (unsigned)kof_famcat_cap_family(c), (unsigned)kof_famcat_cap_variant(c));
	else
		snprintf(out, cap, "%s", kof_famcat_status_text(st));
}
