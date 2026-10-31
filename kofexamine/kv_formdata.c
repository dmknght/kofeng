#define _GNU_SOURCE

/* kv_formdata.c - the small form's measures. See kv_formdata.h. */

#include <stdio.h>
#include <string.h>

#include "kv_formdata.h"

static const char label_ok[] = "[ OK ]";
static const char label_cancel[] = "[ Cancel ]";
static const char label_delete[] = "[ Delete ]";

int kv_form_cell_w(const struct kv_pick *l)
{
	char buf[KV_PICK_LABEL];
	uint32_t i;
	int w = 0;

	for (i = 0; i < l->n; i++) {
		int n = (int)strlen(l->label(i, buf));

		w = n > w ? n : w;
	}
	return w + 4 + KV_FORM_TICK_GAP;
}

int kv_form_grid_w(const struct kv_pick *l)
{
	return KV_FORM_TICK_COLS * kv_form_cell_w(l);
}

int kv_form_ticks_rows(uint32_t n)
{
	return 1 + (int)((n + KV_FORM_TICK_COLS - 1u) / KV_FORM_TICK_COLS);
}

int kv_form_grid_item(uint32_t n, uint32_t r, uint32_t c)
{
	uint32_t rows = (n + KV_FORM_TICK_COLS - 1u) / KV_FORM_TICK_COLS, i = c * rows + r;

	return i < n ? (int)i : -1;
}

size_t kv_form_cell_text(char *out, size_t cap, const char *label, int on, int w)
{
	int n = snprintf(out, cap, "[%c] %-*.*s", on ? 'x' : ' ', w - 4, w - 4, label);

	return n < 0 ? 0u : (size_t)n < cap ? (size_t)n : cap ? cap - 1u : 0u;
}

int kv_form_field_w(const char *label, int cols)
{
	return (int)strlen(label) + cols + 2;
}

int kv_form_buttons_w(void)
{
	return (int)strlen(label_ok) + 2 + (int)strlen(label_cancel) + 2 + (int)strlen(label_delete);
}

void kv_form_size(int body_rows, const int *row_w, uint32_t n_w, int *w, int *h)
{
	int in = kv_form_buttons_w();
	uint32_t i;

	in = KV_FORM_ERR_COLS > in ? KV_FORM_ERR_COLS : in;
	for (i = 0; i < n_w; i++)
		in = row_w[i] > in ? row_w[i] : in;
	*w = in + 4;
	*h = 2 + body_rows + 1 + 1;         /* the frame, the rows, the error line, the buttons */
}
