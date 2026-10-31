/*
 * kx_formdata - the small form's measures (kofexamine/kv_formdata.c), with no viewer and no screen. The invariant that was broken: a row
 * of a tick grid drawn WIDER than the form's inner width ran past the right wall (`[ ] privilege-escalation` in the Syndromes form).
 *
 *   WIDTH    for every list (the engine's two lists of activities and objects shown as the dialog shows them, the malware types, and
 *            synthetic lists whose longest label is 1..39 characters (KV_PICK_LABEL less the NUL) and whose size is 0..24 items), every width of the Name row and the
 *            other rows a mode draws, every mode (with and without Delete): the text of every grid row, the field rows, the button row
 *            and the error line is at most the inner width (the size's w - 4); the grid is exactly kv_form_grid_w wide
 *   CELLS    every item sits in exactly one cell, items run down a column, every cell is exactly the cell width, no label is cut
 *   TEXT     a label longer than its room is cut and terminated; a small buffer is cut and terminated; the tick shows
 *   SIZE     the height counts the rows, and the width is the widest row (not a constant)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kofmod/kofsig.h>
#include <verdictor/famcat.h>
#include "../../kofexamine/kv_formdata.c"

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static uint32_t bit_of(uint32_t i)
{
	return i + 1u;
}

static const char *act_label(uint32_t i, char *buf)
{
	kof_disease_display(kof_disease_act_name(i + 1u), buf, KV_PICK_LABEL);
	return buf;
}

static const char *obj_label(uint32_t i, char *buf)
{
	kof_disease_display(kof_disease_obj_name(i + 1u), buf, KV_PICK_LABEL);
	return buf;
}

static const char *type_label(uint32_t i, char *buf)
{
	(void)buf;
	return kof_famcat_type_name(i);
}

static uint32_t type_bit(uint32_t i)
{
	return kof_famcat_type_value(i);
}

static int synth_len;

static const char *synth_label(uint32_t i, char *buf)
{
	int n = synth_len - (int)(i % 3u);      /* the longest label is synth_len; the others are a little shorter */

	n = n < 1 ? 1 : n;
	memset(buf, (int)('a' + i % 26u), (size_t)n);
	buf[n] = 0;
	return buf;
}

/* The width of the text of grid row r, as kv_form.c draws it: the cells of the row, each of the cell width. */
static int grid_row_w(const struct kv_pick *l, uint32_t mask, uint32_t r, int *cells)
{
	char buf[KV_PICK_LABEL], txt[KV_PICK_LABEL + 16];
	int w = 0, c, cw = kv_form_cell_w(l);

	*cells = 0;
	for (c = 0; c < KV_FORM_TICK_COLS; c++) {
		int i = kv_form_grid_item(l->n, r, (uint32_t)c);

		if (i < 0)
			break;
		kv_form_cell_text(txt, sizeof txt, l->label((uint32_t)i, buf), kv_pick_has(l, mask, (uint32_t)i), cw);
		w += (int)strlen(txt);
		(*cells)++;
	}
	return w;
}

/* One mode: `fields` field rows of width field_w, one grid of list l. Every row must fit the inner width of the size. */
static void mode(const struct kv_pick *l, int field_w, int with_delete)
{
	int row_w[3], w, h, inner, rows, n = 0;
	uint32_t r, nr = (l->n + KV_FORM_TICK_COLS - 1u) / KV_FORM_TICK_COLS;
	int seen[64];
	uint32_t i;

	row_w[n++] = field_w;
	row_w[n++] = kv_form_grid_w(l);
	rows = 1 + kv_form_ticks_rows(l->n);
	kv_form_size(rows, row_w, (uint32_t)n, &w, &h);
	inner = w - 4;
	(void)with_delete;                  /* the button row is always sized for [ Delete ]: OK and Cancel stay where they are */
	CK(h == 2 + rows + 2);
	CK(field_w <= inner && kv_form_grid_w(l) <= inner);
	CK(kv_form_buttons_w() <= inner && KV_FORM_ERR_COLS <= inner);
	memset(seen, 0, sizeof seen);
	for (r = 0; r < nr; r++) {
		int cells, rw = grid_row_w(l, ~0u, r, &cells), rw0 = grid_row_w(l, 0u, r, &cells);

		CK(rw <= inner && rw0 == rw);
		CK(rw == cells * kv_form_cell_w(l));
		CK(rw <= kv_form_grid_w(l));
	}
	for (r = 0; r < nr; r++) {
		uint32_t c;

		for (c = 0; c < KV_FORM_TICK_COLS; c++) {
			int it = kv_form_grid_item(l->n, r, c);

			if (it >= 0) {
				CK((uint32_t)it < l->n && it < 64);
				if (it < 64)
					seen[it]++;
				CK((uint32_t)it == c * nr + r);
			}
		}
	}
	for (i = 0; i < l->n && i < 64; i++)
		CK(seen[i] == 1);
}

static void widths(void)
{
	struct kv_pick acts = { 9u, act_label, bit_of }, objs = { 8u, obj_label, bit_of }, types = { kof_famcat_type_count(), type_label, type_bit };
	struct kv_pick sy = { 0, synth_label, bit_of };
	int fw;
	uint32_t n;

	CK(kv_form_cell_w(&acts) == (int)strlen("Destruction") + 4 + KV_FORM_TICK_GAP || kv_form_cell_w(&acts) >= (int)strlen("Persistence") + 4);
	for (fw = 1; fw <= 70; fw++) {
		mode(&acts, fw, 0);
		mode(&acts, fw, 1);
		mode(&objs, fw, 0);
		mode(&types, fw, 1);
	}
	for (synth_len = 1; synth_len < KV_PICK_LABEL; synth_len++)
		for (n = 0; n <= 24; n++) {
			sy.n = n;
			for (fw = 1; fw <= 70; fw += 3)
				mode(&sy, fw, fw & 1);
		}
	/* the grid is the widest row for a wide list and a narrow field: the form follows the grid, not a constant */
	{
		int row_w[1], w1, h1, w2, h2;

		synth_len = 20;
		sy.n = 10;
		row_w[0] = kv_form_grid_w(&sy);
		kv_form_size(6, row_w, 1, &w1, &h1);
		row_w[0] = 5;
		kv_form_size(6, row_w, 1, &w2, &h2);
		CK(w1 == kv_form_grid_w(&sy) + 4 && w2 < w1 && h1 == h2 && h1 == 2 + 6 + 2);
		kv_form_size(0, NULL, 0, &w2, &h2);
		CK(w2 == (KV_FORM_ERR_COLS > kv_form_buttons_w() ? KV_FORM_ERR_COLS : kv_form_buttons_w()) + 4 && h2 == 4);
	}
	/* an empty list: no grid rows, no cell width beyond the frame of an empty cell */
	sy.n = 0;
	CK(kv_form_ticks_rows(0) == 1 && kv_form_grid_item(0, 0, 0) == -1);
}

static void text(void)
{
	char t[40];
	size_t n;

	n = kv_form_cell_text(t, sizeof t, "scan", 1, 12);
	CK(n == 12 && !strcmp(t, "[x] scan    "));
	n = kv_form_cell_text(t, sizeof t, "scan", 0, 12);
	CK(n == 12 && !strncmp(t, "[ ] scan", 8));
	/* a label longer than its room is cut, never written past it */
	n = kv_form_cell_text(t, sizeof t, "privilege-escalation", 0, 12);
	CK(n == 12 && !strcmp(t, "[ ] privileg"));
	/* a buffer too small cuts and terminates */
	n = kv_form_cell_text(t, 6, "scan", 1, 12);
	CK(n == 5 && !strcmp(t, "[x] s"));
	CK(kv_form_cell_text(t, 0, "scan", 1, 12) == 0);
	CK(kv_form_field_w("Name ", 24) == 5 + 24 + 2);
	CK(kv_form_buttons_w() == (int)(strlen("[ OK ]") + 2 + strlen("[ Cancel ]") + 2 + strlen("[ Delete ]")));
}

int main(void)
{
	widths();
	text();
	printf("kx_formdata: %d failure(s)\n", fails);
	return fails != 0;
}
