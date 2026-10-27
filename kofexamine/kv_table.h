/*
 * kv_table.h - THE ONE TABLE RENDERER of the dashboard (kv_table.c). Pure: no terminal, no view, no global.
 *
 * kv_tab_render takes a table spec (columns, per-column colour and alignment, a cell callback), the window it
 * has to produce (first row, how many rows, sideways offset, the width of the box) and RETURNS the lines to
 * draw - colour escapes inside, no frame, no rule, no count - and the geometry it used (kv_tab_geo). Whoever
 * draws the lines keeps the geometry; the wheel, a click, a double click (whole cell) and a triple click (whole
 * line) are answered from it with kv_tab_hit and from the cell text kv_tab_render recorded (kv_tab_rec), never
 * from the drawn text. Drawing and hit-testing therefore read one set of numbers.
 *
 * A table has NO scroll state: the first row and the sideways offset are inputs, owned by the dashboard page.
 * The first n_sticky columns stay where they are while the others slide under them; a flexible column takes
 * the width the box has left over, and a table wider than the box can be panned (geo.hmax > 0).
 *
 * Every function here is prefixed kv_tab_; nothing else in kofexamine lays a table out.
 */
#ifndef KV_TABLE_H
#define KV_TABLE_H

#include <stddef.h>
#include <stdint.h>

#define KV_TAB_COLS 12u
/* Bytes of one produced line, escapes included (the dashboard's PROP_W). */
#define KV_TAB_LINE 512u

struct kv_tab_spec {
	uint32_t    n_col, n_row, n_sticky;
	const char *col[KV_TAB_COLS];       /* headings */
	uint16_t    width[KV_TAB_COLS];     /* natural width; 0 = the heading's */
	uint8_t     right[KV_TAB_COLS];     /* right-aligned cells and heading */
	const char *colattr[KV_TAB_COLS];   /* SGR of a column's cells (NULL = default) */
	const char *head_attr;              /* SGR of the heading row */
	int         flex;                   /* column that takes leftover width, -1 none */
	/* Fill n_col cells for `row`; a cell may be NULL for "". Called once per produced row. */
	void      (*cell)(void *user, uint32_t row, const char **out);
	/* SGR that replaces the column colour for a whole row (NULL = none). */
	const char *(*rowattr)(void *user, uint32_t row);
	void       *user;
};

struct kv_tab_in {
	uint32_t row0;      /* first row to produce (clamped to the table) */
	uint32_t rows;      /* at most this many rows */
	uint32_t hoff;      /* sideways offset of the sliding columns (clamped) */
	int      width;     /* columns of the box, margin included */
	int      margin;    /* blank columns before the first cell */
	int      heading;   /* produce the heading line */
};

struct kv_tab_geo {
	uint32_t n_line;                /* lines produced: the heading, then the rows */
	int      has_head;
	uint32_t row0, shown;           /* first row produced and how many */
	uint32_t hoff, hmax;            /* the offset used, and the largest there is (0: nothing to pan) */
	int      width;                 /* columns the lines take: the box width, margin included */
	uint32_t n_col;
	int      cx[KV_TAB_COLS];       /* screen column (from the line's start) of the visible part of a column */
	int      cw[KV_TAB_COLS];       /* visible characters of its cell; 0 = scrolled out */
	uint32_t cfrom[KV_TAB_COLS];    /* characters of the cell hidden on the left */
};

/* The full text of the cells of the rows produced, so a selection takes the whole cell and not the part that
 * was visible. Owned by the caller's view; kv_tab_render refills it. */
struct kv_tab_rec {
	char     *buf;
	size_t    n, cap;
	uint32_t *off;
	uint32_t  n_off, cap_off, n_col;
	int       bad;                  /* an allocation failed: the texts are not all here */
};

/* Produce the lines (at most max_line) into `line`, fill `g`, and record the cells in `rec` when not NULL.
 * Returns the number of lines. */
uint32_t kv_tab_render(const struct kv_tab_spec *t, const struct kv_tab_in *in,
		       char (*line)[KV_TAB_LINE], uint32_t max_line,
		       struct kv_tab_geo *g, struct kv_tab_rec *rec);

/* Natural widths: every column whose width is 0 becomes the longest of its heading and its cells, asking
 * the cell callback for every row once. For tables whose data the caller has no width for. */
void kv_tab_measure(struct kv_tab_spec *t);

/* A point in the table's lines: `line` counts from the table's first produced line, `col` from the line's
 * start. 0 outside the table, 1 on the heading, 2 on a row (*row = index among the rows produced). *k is the
 * column under the point, or -1 when it is the margin or the gap between two. */
int kv_tab_hit(const struct kv_tab_geo *g, int line, int col, uint32_t *row, int *k);

/* The full text of a cell of a produced row ("" when empty, NULL when not recorded), and a whole row's cells
 * joined by two spaces (trailing blanks dropped) into `out`; returns its length. */
const char *kv_tab_rec_cell(const struct kv_tab_rec *r, const struct kv_tab_geo *g, uint32_t row, uint32_t k);
size_t kv_tab_rec_line(const struct kv_tab_rec *r, const struct kv_tab_geo *g, uint32_t row, char *out, size_t cap);
void kv_tab_rec_free(struct kv_tab_rec *r);

/* THE ONE CLAMP of a window offset: the largest start of `room` rows over `total` rows. */
uint32_t kv_tab_clamp(uint32_t off, uint32_t total, uint32_t room);

#endif /* KV_TABLE_H */
