/*
 * kv_dash_dialog.h - THE DASHBOARD DIALOG as an API (kv_dash_dialog.c). Private to the dashboard: the family
 * prefix is kv_dd_, the page bodies are kv_props*.c and the tables kv_table.c.
 *
 * The dialog is the frame, the tab strip in its top rule, the close button, the page body's rectangle, the
 * scrollbar in its right wall and the count at the right end of its bottom rule. Every function here is PURE:
 * it takes the state (struct kv_dd_in: the screen, the strip's labels, the count text, the scroll numbers) and
 * RETURNS strings to draw and the geometry (struct kv_dd_geo). draw_prop (kv_page.c) only places them on the
 * screen and keeps the geometry in the view; a click, the wheel, a drag and the copy read that geometry and
 * nothing else. Nothing here knows what a page says (that is kv_dashdata.c) and nothing here reads a view.
 */
#ifndef KV_DASH_DIALOG_H
#define KV_DASH_DIALOG_H

#include <stddef.h>
#include <stdint.h>

#define KV_DD_TABS 5
/* Narrower or shorter than this no box is drawn (the strip, the close button and the count would not fit). */
#define KV_DD_MIN_W 30
#define KV_DD_MIN_H 6

struct kv_dd_in {
	int         cols, rows;             /* the screen */
	const char *title;                  /* drawn when there is no strip */
	const char *tab[KV_DD_TABS];
	int         n_tab, tab_sel;
	const char *count;                  /* the count text, NULL for none */
	int         count_left;             /* 0: bottom-right corner (the dashboard); 1: after the corner (the help pages) */
	const char *act;                    /* the last action's message, NULL for none */
	int         act_ok;
	uint32_t    fixed;                  /* body rows that do not scroll */
	uint32_t    total, off, shown;      /* the scrolling rows: how many there are, the first shown, how many */
	int         want_w, want_h;         /* the size the content needs, 0 = the whole screen (the dashboard); clipped to the screen */
	int         dx, dy;                 /* where the reader dragged the box, from where it opens (kept by the caller, per dialog) */
};

struct kv_dd_geo {
	int ok;                             /* the box is big enough to draw */
	int top, left, w, h;
	int dx, dy;                         /* the offset the box really has: the asked one, clamped so the box stays on the screen */
	int body_y0, body_x0, body_rows, body_cols;
	int tab_y, n_tab;                   /* labels drawn (a strip wider than the box loses its last ones) */
	int tab_x0[KV_DD_TABS], tab_x1[KV_DD_TABS];
	int close_y, close_x0, close_x1;    /* close_y -1: not drawn */
	int bar_x, bar_y0, bar_rows;        /* the scrollbar's column and rows; bar_rows 0: none */
	int count_y, count_x;               /* count_x -1: dropped (too narrow) */
	int act_x;                          /* column of the action message, -1 none */
};

/* The box over the whole screen (the dashboard's), or over a box the caller placed (g->top/left/w/h set, the
 * rest zero): both fill the strip, the close button, the body, the scrollbar and the count positions. */
/* Move a box the caller placed (g->top/left/w/h) by in->dx/dy and keep it whole on the screen (not over the menu bar, row 1);
 * g->dx/dy is the offset that remains. kv_dd_layout does it; a caller that places the box itself calls it before kv_dd_fill. */
void kv_dd_place(const struct kv_dd_in *in, struct kv_dd_geo *g);
/* Is a press at (y, x) on the box's top rule and on neither a tab label nor the close button: the handle that drags the box. */
int kv_dd_grab_at(const struct kv_dd_geo *g, int y, int x);
void kv_dd_layout(const struct kv_dd_in *in, struct kv_dd_geo *g);
void kv_dd_fill(const struct kv_dd_in *in, struct kv_dd_geo *g);
/* The top rule with the strip and the close button; the bottom rule with the action and the count; the
 * walls of body row `row` (left, right: the right one carries the scrollbar cell). Each returns the bytes. */
size_t kv_dd_top(const struct kv_dd_in *in, const struct kv_dd_geo *g, char *out, size_t cap);
size_t kv_dd_bottom(const struct kv_dd_in *in, const struct kv_dd_geo *g, char *out, size_t cap);
void kv_dd_walls(const struct kv_dd_in *in, const struct kv_dd_geo *g, int row, char *left, char *right, size_t cap);
/* The scroll offset a press at screen row `y` of the scrollbar asks for. */
uint32_t kv_dd_bar_offset(const struct kv_dd_in *in, const struct kv_dd_geo *g, int y);
/* The tab under a screen point, or -1. */
int kv_dd_tab_at(const struct kv_dd_geo *g, int y, int x);
int kv_dd_close_at(const struct kv_dd_geo *g, int y, int x);

#endif /* KV_DASH_DIALOG_H */
