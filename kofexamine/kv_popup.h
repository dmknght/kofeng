/*
 * kv_popup.h - THE pop-up list of the viewer, as data: the menu bar's drop-down and its submenu, the right-click menu, the pick-lists of the
 * draft panel (the choosers, and the submenu a row of one opens), the tick menu of a table cell. One description of the rows, ONE function
 * that places the box (kv_popup_place), one text for every row (kv_popup_text), one hit test, one key step, one renderer (kv_popup_draw,
 * kofview.c). What a caller keeps is its items and the anchor; the box (x, y, w, h, which side it opened on, how far it is scrolled) is
 * returned, never worked out again at a draw, a click or a key.
 *
 * Pure: no terminal and no global. The screen is a parameter of the request, so tests/unit/kx_popup.c can ask for a box on any screen,
 * a tiny one included. The functions are defined in kofview.c with the other widgets.
 *
 * kv_box_fit is the one rule for "keep a box on the screen" and is shared with the dialogs' frames (dframe_begin, kv_dd_place).
 */
#ifndef KV_POPUP_H
#define KV_POPUP_H

#include <stddef.h>

#define KV_POP_MAX  272         /* rows a list may hold: the chooser's 256 items; a menu's items and its rules */
#define KV_POP_TEXT 64          /* bytes of a row's text, the NUL included */

/* ONE PALETTE for every pop-up (the menu bar's, the darker one). */
#define BAR_ON   "\033[100;97m"    /* an item that can be used */
#define BAR_OFF  "\033[100;37m"    /* the same panel, dimmer text */
#define BAR_CUR  "\033[107;30m"    /* the row under the cursor */

enum {
	KV_PR_RULE = 1,         /* a rule: takes a row, is never an item */
	KV_PR_OFF  = 2,         /* drawn grey, not choosable */
	KV_PR_SUB  = 4,         /* opens a submenu: ">" at the far edge */
	KV_PR_TICK = 8,         /* shows a "[ ]" box before the text */
	KV_PR_ON   = 16         /* ... and it is ticked */
};

struct kv_popup_row {
	char          text[KV_POP_TEXT];
	unsigned char flags;
	int           id;       /* the caller's number for the item (-1 for a rule) */
};

enum kv_popup_side {
	KV_SIDE_AT = 0,         /* at the anchor, as a menu opened by the pointer */
	KV_SIDE_BELOW,          /* under the control */
	KV_SIDE_ABOVE,          /* over the control, because it did not fit below */
	KV_SIDE_RIGHT,          /* beside its parent, on the right */
	KV_SIDE_LEFT,           /* beside its parent, on the left, because the right did not fit */
	KV_SIDE_COVER           /* fits nowhere: takes the whole usable height and may cover the control */
};

struct kv_popup_box {
	int y, x, w, h;         /* the box on the screen: h is the rows DRAWN */
	int cell_w;             /* the width of one column of items (w for a list, w / cols for a grid) */
	int n_rows;             /* rows the whole list takes; more than h when it scrolls */
	int off;                /* the first row drawn */
	int side;               /* enum kv_popup_side */
};

struct kv_popup {
	int                 n;          /* rows in row[] */
	int                 cols;       /* 1 = a list (rules allowed); more = a grid: items run down a column, then the next, no rules */
	struct kv_popup_row row[KV_POP_MAX];
	struct kv_popup_box box;
};

struct kv_popup_req {
	int rows, cols;                 /* the screen */
	int top, bottom;                /* the first and the last row a pop-up may use (the menu bar above, the status line below) */
	int ay, ax;                     /* the anchor: the pointer, or the cell of the control, or the parent's left column when `parent` is set */
	int anchor_h;                   /* 0: the box may start AT ay (a pointer's menu); 1: the control takes row ay and stays visible: below, else above */
	const struct kv_popup_box *parent;  /* a submenu: opens beside this box, its top on the screen row `parent_row`; NULL for none */
	int parent_row;
	int min_w;                      /* the least width of a column of items (a look, the caller's) */
	int max_w;                      /* the most (0 = the screen) */
	int off;                        /* the scroll asked for, kept in range */
};

/* Keep a box of h rows and w columns inside columns 1..cols and rows top..bottom (top wins when it cannot all fit). */
static inline void kv_box_fit(int *y, int *x, int h, int w, int top, int bottom, int cols)
{
	if (*x + w - 1 > cols)
		*x = cols - w + 1;
	if (*x < 1)
		*x = 1;
	if (*y + h - 1 > bottom)
		*y = bottom - h + 1;
	if (*y < top)
		*y = top;
}

void kv_popup_init(struct kv_popup *p, int cols);
/* Append a row; returns its index, or -1 when the list is full (the caller counts what it could not add). Text is cut to KV_POP_TEXT - 1 bytes. */
int  kv_popup_add(struct kv_popup *p, const char *text, unsigned flags, int id);
/* Decide the box: width from the longest row, height from the rows, position from the anchor, side, scroll. Idempotent for a box already placed. */
void kv_popup_place(struct kv_popup *p, const struct kv_popup_req *q);
/* The text of row r, column c, exactly cell_w columns wide, no escapes; a rule is "-" (the renderer draws the glyph); a scroll marker row of a long list is "..." with ^ or v. Returns the columns written. */
int  kv_popup_text(const struct kv_popup *p, int r, int c, char *out, size_t cap);
/* The row under (my, mx): its index, -1 inside the box on a rule or an empty cell, -2 outside the box. */
int  kv_popup_hit(const struct kv_popup *p, int my, int mx);
/* The id of the first choosable item (-1 none); and the next choosable one from item `cur_id` in direction d (-1 = from nothing, either end; cur_id again when there is none). */
int  kv_popup_first(const struct kv_popup *p);
int  kv_popup_step(const struct kv_popup *p, int cur_id, int d);
/* Row index of an item id (-1 none); the screen row it is drawn on (-1 when scrolled out). */
int  kv_popup_row_of(const struct kv_popup *p, int id);
int  kv_popup_row_y(const struct kv_popup *p, int id);
/* Scroll so that item `id` is drawn. */
void kv_popup_follow(struct kv_popup *p, int id);

#endif /* KV_POPUP_H */
