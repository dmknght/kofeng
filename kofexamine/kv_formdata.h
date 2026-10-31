/*
 * kv_formdata.h - THE MEASURES of the small form as data (kv_formdata.c): the width of a tick cell and grid, the text of a cell, which item sits
 * where, the size of the form. Pure: no terminal. kv_form.c draws with exactly these functions, and tests/unit/kx_formdata.c asserts that no
 * row they describe is wider than the form's inner width, for any list of words. Include after <stdint.h>.
 */
#ifndef KV_FORMDATA_H
#define KV_FORMDATA_H

#include <stddef.h>
#include <stdint.h>

#include "kv_pick.h"

#define KV_FORM_TICK_COLS 2     /* the tick grid: columns, filled down the first and then the next */
#define KV_FORM_TICK_GAP 2      /* blank columns after the label of a cell: a cell is "[x] " + the longest label + the gap */
#define KV_FORM_ERR_COLS 40     /* the widest error line (the longest text of kof_tagcat_status_text is 37) */

/* The width of one cell of the grid of `l` (its longest label), and of the whole grid: EVERY cell drawn is this wide, the last one of a
 * row included, so a row of a grid is exactly kv_form_grid_w columns and never more. */
int kv_form_cell_w(const struct kv_pick *l);
int kv_form_grid_w(const struct kv_pick *l);
/* Rows a tick grid takes: its title row and the rows of the grid. */
int kv_form_ticks_rows(uint32_t n);
/* The item at row r, column c of a grid of n items (items run down a column, then the next), or -1 where the grid has none. */
int kv_form_grid_item(uint32_t n, uint32_t r, uint32_t c);
/* The text of one tick cell, "[x] label" padded (and cut) to `w` columns; returns its length (w when it fits). */
size_t kv_form_cell_text(char *out, size_t cap, const char *label, int on, int w);
/* The width of a labelled field row: the label, the "[" and "]" and the `cols` of the field. */
int kv_form_field_w(const char *label, int cols);
/* The width of the button row with [ Delete ] (the widest it ever is). */
int kv_form_buttons_w(void);
/* The size of a form with `body_rows` rows above the error line, whose rows are at most the widest of row_w[0..n): THE ONE place the inner
 * width is decided. The button row with [ Delete ] and the error line are folded in, the frame is added (w = inner + 4; h = frame + rows +
 * error line + buttons). A caller lists the width of every row it draws that is not text it can bound itself (its field rows, each grid). */
void kv_form_size(int body_rows, const int *row_w, uint32_t n_w, int *w, int *h);

#endif /* KV_FORMDATA_H */
