#define _GNU_SOURCE

/*
 * kv_props_table.c - where the dashboard page meets the table renderer (kv_table.c).
 *
 * prop_table puts a whole table into the page as page lines (the overview's process tables); prop_table_page
 * puts the one table of a table page there as its heading, which stays, and the window of rows the page's own
 * scroll is on. Both hand the renderer the page's offsets and the dialog's body size, keep the geometry and the
 * cell text it returns in the view, and nothing else: no table decides its own scroll, width or height. The
 * hit-test and the selection text are read back from that geometry (prop_cell_at, prop_cell_text). prop_block
 * draws a block of the overview's data rows (kv_dashdata.h) with the tones turned into colours.
 */

#include "kv_props_private.h"

/* Blank columns before a table's first cell: the page's own margin. */
#define PROP_MARGIN 2

/* A tone is a kind of fact; which SGR it is belongs here and nowhere in the data. */
const char *prop_tone_sgr(enum dash_tone t)
{
	switch (t) {
	case DT_DIM:  return A_DIM;
	case DT_ID:   return A_ID;
	case DT_LOC:  return A_LOC;
	case DT_SIZE: return A_SIZE;
	case DT_WARN: return A_WARN;
	case DT_BAD:  return A_BAD;
	case DT_HEUR: return A_HEUR;
	case DT_NAME: return A_S_NAME;
	case DT_TYPE: return A_S_TYPE;
	case DT_FLAG: return A_S_FLAG;
	case DT_ALT:  return A_S_SHN;
	case DT_BIND: return A_S_BIND;
	case DT_REFS: return A_D_REG;
	case DT_ENT:  return A_D_OFF;
	default:      return "";
	}
}

/* THE ONE WAY A TABLE IS DECLARED to the renderer: its columns, how many are sticky, which one takes the leftover width. */
void prop_spec(struct kv_tab_spec *t, const struct prop_col *c, uint32_t n_col, uint32_t n_row, uint32_t n_sticky, int flex,
	       void (*cell)(void *, uint32_t, const char **), void *user)
{
	uint32_t k;

	memset(t, 0, sizeof *t);
	for (k = 0; k < n_col && k < KV_TAB_COLS; k++) {
		t->col[k] = c[k].name;
		t->width[k] = c[k].width;
		t->right[k] = c[k].right;
		t->colattr[k] = c[k].attr;
	}
	t->n_col = n_col < KV_TAB_COLS ? n_col : KV_TAB_COLS;
	t->n_row = n_row;
	t->n_sticky = n_sticky;
	t->flex = flex;
	t->head_attr = A_DIM;
	t->cell = cell;
	t->user = user;
}

/* The input every table of this page is rendered with: the page's sideways offset and the dialog's body width. */
static struct kv_tab_in tab_in(const struct view *v, uint32_t row0, uint32_t rows)
{
	struct kv_tab_in in;

	in.row0 = row0;
	in.rows = rows;
	in.hoff = v->prop_hoff;
	in.width = v->prop_room_cols;
	in.margin = PROP_MARGIN;
	in.heading = 1;
	return in;
}

/* Render `t` into the page's next lines and keep what came back in the table's slot. */
static void tab_emit(struct view *v, const struct kv_tab_spec *t, const struct kv_tab_in *in, int abs_head, int abs_row)
{
	struct kv_tab_slot *s = v->prop_n_tab < PROP_TABS ? &v->prop_tab[v->prop_n_tab] : NULL;
	struct kv_tab_geo local;
	struct kv_tab_geo *g = s ? &s->geo : &local;
	uint32_t n = kv_tab_render(t, in, (char (*)[KV_TAB_LINE])g_prop[g_n_prop].text, PROP_MAX - g_n_prop, g,
				   s ? &s->rec : NULL);

	g_n_prop += n;
	if (g->hmax > v->prop_hmax)
		v->prop_hmax = g->hmax;
	if (s) {
		s->abs_head = g->has_head ? abs_head : -1;
		s->abs_row = abs_row;
		v->prop_n_tab++;
	}
}

void prop_table(struct view *v, struct kv_tab_spec *t)
{
	uint32_t room = PROP_MAX > g_n_prop + 2u ? PROP_MAX - g_n_prop - 2u : 0u;
	uint32_t rows = t->n_row < room ? t->n_row : room;
	struct kv_tab_in in = tab_in(v, 0, rows);
	int at = (int)g_n_prop;

	tab_emit(v, t, &in, at, at + 1);
	/* A cap bounds cost and is said: the page holds PROP_MAX lines. */
	if (rows < t->n_row)
		prop_say(A_WARN, "%u more rows not shown (the page holds %u lines)", t->n_row - rows, (unsigned)PROP_MAX);
}

void prop_table_page(struct view *v, struct kv_tab_spec *t, uint32_t fixed)
{
	uint32_t body = (uint32_t)v->prop_room_rows > fixed + 1u ? (uint32_t)v->prop_room_rows - fixed - 1u : 0u;
	uint32_t off = kv_tab_clamp(v->prop_off, t->n_row, body);
	struct kv_tab_in in = tab_in(v, off, body);

	v->prop_off = off;
	v->prop_fixed = fixed + 1u;
	v->prop_total = t->n_row;
	v->prop_vfirst = off;
	tab_emit(v, t, &in, (int)fixed, (int)(fixed + 1u + off));
}

/*
 * The table under a screen point, answered from the geometry the renderer returned. `r` is the page line the screen
 * row shows (the recording's own map, which already accounts for the page's scroll). 0 when the point is on no table,
 * 1 on a heading, 2 on a row (*row indexes the rows that were produced); *k is the column or -1.
 */
int prop_cell_at(const struct view *v, int y, int x, uint32_t *slot, uint32_t *row, int *k)
{
	int rr = y - v->dlg_y0, cc = x - v->dlg_x0, r;
	uint32_t i;

	if (rr < 0 || rr >= v->dlg_rows || (r = v->dlg_src[rr]) < 0)
		return 0;
	for (i = 0; i < v->prop_n_tab; i++) {
		const struct kv_tab_slot *s = &v->prop_tab[i];
		int line = -1;

		if (s->abs_head >= 0 && r == s->abs_head)
			line = 0;
		else if (r >= s->abs_row && r < s->abs_row + (int)s->geo.shown)
			line = (s->geo.has_head ? 1 : 0) + (r - s->abs_row);
		if (line >= 0) {
			*slot = i;
			return kv_tab_hit(&s->geo, line, cc, row, k);
		}
	}
	return 0;
}

/* The full text of the cell a point is on (NULL when none), and a whole row's text. */
const char *prop_cell_text(const struct view *v, uint32_t slot, uint32_t row, int k)
{
	return k < 0 ? NULL : kv_tab_rec_cell(&v->prop_tab[slot].rec, &v->prop_tab[slot].geo, row, (uint32_t)k);
}

size_t prop_row_text(const struct view *v, uint32_t slot, uint32_t row, char *out, size_t cap)
{
	return kv_tab_rec_line(&v->prop_tab[slot].rec, &v->prop_tab[slot].geo, row, out, cap);
}

void prop_tabs_free(struct view *v)
{
	uint32_t i;

	for (i = 0; i < PROP_TABS; i++)
		kv_tab_rec_free(&v->prop_tab[i].rec);
}

/*
 * Draw a block of the overview's data: its heading, then a row each - "  label " in the label's tone, then the
 * spans in theirs. A producer that was cut at its bound says how many rows it did not show.
 */
void prop_block(const struct dash_block *b)
{
	uint32_t i, k;

	/* A block's heading is bold and takes no blank line above it: the blocks of a page follow one another. */
	if (b->head[0] && (b->n || b->not_shown))
		prop_add(A_BOLD "%s" A_OFF, b->head);
	for (i = 0; i < b->n; i++) {
		const struct dash_row *r = &b->row[i];
		char line[PROP_W];
		int n = 0;

		if (r->label[0])
			n = snprintf(line, sizeof line, "  %s%-11s " A_OFF, prop_tone_sgr(r->label_tone), r->label);
		for (k = 0; k < r->n && (size_t)n < sizeof line; k++)
			n += snprintf(line + n, sizeof line - (size_t)n, "%s%s" A_OFF, prop_tone_sgr(r->s[k].tone),
				      r->s[k].text);
		if (n < 0)
			n = 0;
		if ((size_t)n >= sizeof line)
			line[sizeof line - 1u] = 0;
		else
			line[n] = 0;
		prop_add("%s", line);
	}
	if (b->not_shown)
		prop_say(A_DIM, "%u more not shown", b->not_shown);
}
