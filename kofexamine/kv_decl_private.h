/*
 * kv_decl_private.h - what the units of the draft panel share.
 *
 * kv_decl.c was one 3100-line file holding five jobs (the header row, the format/option/range
 * rows, the strings, the matchers and conditions, the blocks table). Each is a unit now
 * (kv_decl_<part>.c); what two of them call is declared here, under its old name. A function
 * only one unit calls stays static in it. NOT part of the public surface: kv_proto_decl.h holds
 * the prototypes the rest of the viewer sees.
 */
#ifndef KV_DECL_PRIVATE_H
#define KV_DECL_PRIVATE_H

#include "kv.h"
#include "kv_tags.h"
#include "../libkofeng/databases/diagsrc.h"

#define _GNU_SOURCE
#include "kv.h"
#include "kv_tags.h"
#include "../libkofeng/databases/diagsrc.h"


/* How wide the symbol column is. */
#define MTN_SYM_COL 28u

/*
 * The screen row for the next panel line, or -1 when it is scrolled out.
 *
 * `*r` counts panel rows whether or not they are drawn, so the two halves - the
 * window and the position in the list - stay one number apart and a scrolled
 * panel does not have to be laid out twice.
 */
/*
 * Where a draft row lands once the panel is scrolled, and whether it lands on
 * the screen at all.
 *
 * `r` counts rows of the draft whether or not they are visible, so one number
 * serves both the layout and the scroll position, and a draft longer than its
 * pane does not have to be laid out twice to find out what fits.
 */
#define PR(rr)     (decl_top() + 1 + (int)(rr) - (int)v->prow_off)
#define PR_VIS(rr) ((int)(rr) >= (int)v->prow_off && \
		    (int)(rr) - (int)v->prow_off < g_decl_rows - 2)

/*
 * A heading that runs the width of the screen.
 *
 * The panel is four kinds of thing stacked with nothing between them, which is
 * why it read as one long list. A bar per section costs the row the column
 * headings were already taking and gives the eye somewhere to stop.
 */
/*
 * RE-LOCATE THE STRINGS' REGIONS - a small button, in the region column's own
 * heading rather than a sentence at the end of the row.
 *
 * It reads as one of the row buttons the strings already carry ([x] and the
 * rest) because that is what it is: three characters beside the thing it acts
 * on. Spelled out at the end of the heading it was the widest thing on the row
 * and said in five words what its position says by itself.
 */
#define BTN_UPDRGN "[r]"

/*
 * "[+ str]" - DECLARE A MARKER THAT IS NOT ON THE SCREEN.
 *
 * Every other way in starts from bytes the object already has: select a run in
 * the hex pane, or pick text out of the event box. That covers the common case
 * and misses the one a researcher reaches for next - writing a marker down
 * because they know it belongs to the family, before they have a sample that
 * shows it.
 *
 * On the Strings heading, beside [r], because both are about the table under
 * them. The heading is drawn even when the table is EMPTY for this button's
 * sake: with no declarations there was no heading, so the one control that can
 * create the first declaration had nowhere to be.
 */
/*
 * THE SAME WORD THE OTHER TWO USE, ON A ROW OF ITS OWN.
 *
 * It was "[+ str]" squeezed onto the heading row beside [r], and both things
 * were wrong: the abbreviation matched nothing else in the panel, and the
 * heading is TEXT - sec_bar has already written "size  bytes" across it, so a
 * button positioned from the prefix landed on top of it and the reader saw
 * "[+ str]ytes". The add row at the foot of a table is the shape the matchers
 * and the conditions already have, it needs no column arithmetic, and there is
 * nothing on it to collide with.
 */
#define BTN_ADDSTR "[+ String]"
/* " Intron      attr       region" - the heading up to and including the
 * region title, so the button's column is measured from it rather than counted
 * by hand. "Intron" is the owner's name for the table of patterns; the word
 * marker still means a pattern that was found. */
/*
 * ONE COLUMN FOR BOTH ATTRIBUTES - see decl_attr_text in kofeditor.h.
 *
 * It was "word" and "case", nine and eleven characters wide, and twenty-one
 * columns of a row whose last field is the bytes somebody opened the file to
 * read. The cell is at most "i:pattern", so the column is nine and the table
 * gains eleven.
 */
#define STR_ATTR_W 9
#define STR_HDR_PRE " Intron      attr       region"

/*
 * A SEARCH MATCHER'S LIST ROW: the markers it is about, joined by commas, with
 * the button that adds another at the end. (A block matcher has no list: it is
 * one block, named on its first row.)
 *
 * THE SPANS ARE RECORDED AS THEY ARE DRAWN, which is what the marker row's own
 * note asked for: where an item is on the screen is a fact the drawing has, and
 * a hit test that re-derives it is a second copy of the arithmetic - which is
 * exactly how the marker row came to remove the wrong marker once an id reached
 * two digits.
 */
struct grp_list {
	struct out  *o;
	struct view *v;
	int          y;
	uint32_t     g;
	int        (*span)[2];      /* where each item landed, by slot */
	uint32_t     cap;
	uint32_t     n;             /* how many were drawn */
};

/* ---- what one part offers another -------------------------------------------- */
int decl_cols_reserve(struct view *v, uint32_t rows);
void draw_decl_head(struct out *o, struct view *v);
int draw_decl_fmts(struct out *o, struct view *v, int r);
int draw_decl_optbtn(struct out *o, struct view *v, int r);
int draw_decl_opts(struct out *o, struct view *v, int r);
int draw_decl_ranges(struct out *o, struct view *v, int r);
int draw_decl_strings(struct out *o, struct view *v, int r);
void draw_grp_note(struct out *o, struct view *v, uint32_t g);
void unit_cells(struct out *o, struct view *v, int y, int is_grp, uint32_t idx);
void glist_begin(struct grp_list *L, struct out *o, struct view *v, int y, uint32_t g, const char *title, int (*span)[2], uint32_t cap);
void glist_item(struct grp_list *L, const char *text);
void glist_end(struct grp_list *L, int can_add, const char *label);
void glist_gone(struct view *v, uint32_t g);
void ghead_lead(struct out *o, struct view *v, int y, uint32_t g, const char *word);
void grp_spans_off(struct view *v, uint32_t g);
void hit_row_matcher(struct view *v, uint32_t g);
int draw_decl_matchers(struct out *o, struct view *v, int r);
int draw_decl_conds(struct out *o, struct view *v, int r);
void at_off_edit_open(struct view *v, uint32_t g);
void hit_unit_tag(struct view *v, uint32_t unit);
void hit_unit_type(struct view *v, uint32_t unit);
void hit_grp_pct(struct view *v, uint32_t g);
int draw_decl_blocks(struct out *o, struct view *v, int r);
int mtn_foreign(const struct view *v);

#endif /* KV_DECL_PRIVATE_H */
