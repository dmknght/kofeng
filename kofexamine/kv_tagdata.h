/*
 * kv_tagdata.h - WHAT Manage > Syndromes SAYS, as data (kv_tagdata.c). Same contract as kv_famdata.h: functions that RETURN rows, cells
 * and geometry, know nothing of a terminal, and are asserted on by tests/unit/kx_tagdata.c.
 *
 * The model and every validation are the engine's (<verdictor/tagcat.h>). The table has no heading row and one row per tag, in creation
 * order, with four columns: name | activities | objects (the engine's words, comma-joined) | comment (the tag's own, the column that takes
 * the rest, drawn and cut by the same table code as the variant comment of Pathogens). Row i is the catalog's tag i. The two
 * lists are the engine's (kof_disease_act_name / kof_disease_obj_name through the catalog's accessors) and are read as kv_pick lists.
 * What the shared dialog code does (the frame, the bottom row of buttons, the click extent of a cell) is kv_dash_dialog.h, kv_table.h
 * and kv_form.h: nothing of it is repeated here.
 */
#ifndef KV_TAGDATA_H
#define KV_TAGDATA_H

#include <stddef.h>
#include <stdint.h>

#include <verdictor/tagcat.h>
#include "kv_table.h"
#include "kv_dash_dialog.h"
#include "kv_pick.h"

/* The caller's table of the session's catalog, and so the limit the dialog reports (KOF_TAGCAT_FULL). */
#define KV_TAG_MAX 64u

#define KV_TAG_COLS 4u
/* The columns: the name, the activities, the objects, the comment (a click on a comment opens nothing). */
#define KV_TAG_COL_ACTS 1
#define KV_TAG_COL_OBJS 2
#define KV_TAG_COL_COMMENT 3
/* Blank columns added after the name column and after the activities column, so the columns read as columns. */
#define KV_TAG_GAP 2u
/* Blank columns between the objects column and the comment column (the same as KV_FAM_COMMENT_GAP of Pathogens). */
#define KV_TAG_COMMENT_GAP 4u
/* An EMPTY activities or objects cell has no text to hit: it answers over this many columns from its start (the same as an empty
 * comment cell of Pathogens), so it can still be clicked. */
#define KV_TAG_EMPTY_HIT 12

/* Which list a cell or a menu is about. */
enum kv_tag_list { KV_TAG_ACTS = 0, KV_TAG_OBJS };

/* The label of the add button: one spelling for the drawing and the hit test. */
const char *kv_tag_label_add(void);

/* The two lists as the shared tick grid and menu read them (kv_pick.h: the bit of an item is its engine value). */
struct kv_pick kv_tag_acts(void);
struct kv_pick kv_tag_objs(void);
struct kv_pick kv_tag_list_of(enum kv_tag_list which);

/* The size the dialog needs: the widest row or the button row, a row each, with the frame; clipped to the screen by the layout. */
void kv_tag_content_size(const struct kof_tagcat *c, int *w, int *h);

/* The catalog's tag named `name` (exact), or -1. The diagnose panel keeps the NAME of a tag, so a rename or delete shows as "not found". */
int32_t kv_tag_find(const struct kof_tagcat *c, const char *name);

/* The first three cells of tag `idx`; a cell is "" when it has nothing. The comment cell is kv_tag_comment_cell (kept apart so this
 * function stays within the parameter limit and its callers need no change). */
void kv_tag_cells(const struct kof_tagcat *c, uint32_t idx, char *name, size_t ncap, char *acts, size_t acap, char *objs, size_t ocap);
void kv_tag_comment_cell(const struct kof_tagcat *c, uint32_t idx, char *comment, size_t cap);

/* A table spec over the tags (no headings, natural widths measured, the comment column takes the rest). */
struct kv_tag_tab {
	const struct kof_tagcat *cat;
	char name[KOF_TAGCAT_NAME_MAX + 8], acts[192], objs[192], comment[KOF_TAGCAT_COMMENT_MAX + 1];
};
void kv_tag_spec(struct kv_tab_spec *t, struct kv_tag_tab *tt, const struct kof_tagcat *c);
/* The same spec with the column widths a previous kv_tag_spec measured (t->width of that call): nothing is measured. */
void kv_tag_spec_widths(struct kv_tab_spec *t, struct kv_tag_tab *tt, const struct kof_tagcat *c, const uint16_t width[KV_TAG_COLS]);

/* What a click at column `col` (from the table line's start, the geometry's own numbers) of row `idx` opens. A cell answers only over the
 * EXTENT OF ITS TEXT (kv_tab_extent, the one function for every table), an empty activities or objects cell over KV_TAG_EMPTY_HIT
 * columns; the name cell opens the edit dialog, the activities and objects their tick menus, the comment nothing. */
enum kv_tag_hit { KV_TAG_HIT_NONE = 0, KV_TAG_HIT_NAME, KV_TAG_HIT_ACTS, KV_TAG_HIT_OBJS };
enum kv_tag_hit kv_tag_hit_of(const struct kof_tagcat *c, uint32_t idx, const struct kv_tab_geo *g, int col);

/* The tick menu of a cell: is item i of list `which` in tag `idx`; flip it (the engine decides: the status comes back). */
int kv_tag_menu_checked(const struct kof_tagcat *c, uint32_t idx, enum kv_tag_list which, uint32_t i);
enum kof_tagcat_status kv_tag_menu_toggle(struct kof_tagcat *c, uint32_t idx, enum kv_tag_list which, uint32_t i);

/* The line a dialog shows for a status ("" for OK); a full catalog names its limit. */
void kv_tag_error_text(const struct kof_tagcat *c, enum kof_tagcat_status st, char *out, size_t cap);

#endif /* KV_TAGDATA_H */
