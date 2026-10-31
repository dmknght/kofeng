/*
 * kv_famdata.h - WHAT Manage > Pathogens SAYS, as data (kv_famdata.c). Same contract as kv_dashdata.h: functions
 * that RETURN rows, cells and geometry, know nothing of a terminal, and are asserted on by tests/unit/kx_famdata.c.
 *
 * The model and every validation are the engine's (<verdictor/famcat.h>); this file lays the catalog out as table rows
 * and answers where a click lands. The table has no heading row. A family has a row of its own (no type list: the types
 * belong to the variant), its variants follow, indented, each with its types, and the family closes with an
 * "[ Add variant ]" line at the variants' indent. The "[ Add family ]" button is the dialog's last body row.
 */
#ifndef KV_FAMDATA_H
#define KV_FAMDATA_H

#include <stddef.h>
#include <stdint.h>

#include <verdictor/famcat.h>
#include "kv_table.h"
#include "kv_pick.h"
#include "kv_dash_dialog.h"

/* The caller's tables of the session's catalog, and so the limits the dialog reports (KOF_FAMCAT_FULL). */
#define KV_FAM_MAX_FAMILY 64u
#define KV_FAM_MAX_VARIANT 256u
/* Rows of the table: a family line, its variants, its add-variant line. */
#define KV_FAM_MAX_ROW (KV_FAM_MAX_FAMILY * 2u + KV_FAM_MAX_VARIANT)

/* The most types the Add variant dialog can lay out (the engine has 10 selectable). */
#define KV_FAM_TICKS 16u

#define KV_FAM_COLS 3u
/* The columns: the name, the types, the comment (a click on the comment cell edits it). */
#define KV_FAM_COL_COMMENT 2
/* Blank columns before a variant's name and before the add-variant button. */
#define KV_FAM_INDENT 2u
/* The Pathogens box never grows past this many columns and rows, whatever a comment holds (owner: a long comment must never make it
 * overflow the screen): a longer line scrolls sideways inside the table, more rows scroll down. */
#define KV_FAM_WIDTH_MAX KV_DD_CATALOG_WIDTH_MAX
#define KV_FAM_HEIGHT_MAX KV_DD_CATALOG_HEIGHT_MAX
/* Blank columns between the types column and the comment column. */
#define KV_FAM_COMMENT_GAP 4u

enum kv_fam_kind { KV_FAM_FAMILY = 0, KV_FAM_VARIANT, KV_FAM_ADDVAR };

struct kv_fam_row {
	enum kv_fam_kind kind;
	uint32_t family;
	int32_t  variant;       /* the catalog's variant index for KV_FAM_VARIANT, else -1 */
};

/* The label of the two buttons: one spelling for the drawing and for the hit test. */
const char *kv_fam_label_add_variant(void);
const char *kv_fam_label_add_family(void);

/* The table's rows in display order; returns how many there are (at most `cap` are written). */
uint32_t kv_fam_rows(const struct kof_famcat *c, struct kv_fam_row *out, uint32_t cap);

/* The size the families dialog needs for these rows: the widest row or the button row, and a row each, with the frame. The
 * dialog is as big as its content and is clipped to the screen by the layout. */
void kv_fam_content_size(const struct kof_famcat *c, const struct kv_fam_row *rows, uint32_t n_row, int *w, int *h);

/* The catalog's family named `name` (exact), or -1; the variant named `name` (exact, "Mirai_A"), or -1. The diagnose panel keeps the
 * NAMES it was given, not indices, so a rename or a delete in the dialog shows up there as "not found". */
int32_t kv_fam_find_family(const struct kof_famcat *c, const char *name);
int32_t kv_fam_find_variant(const struct kof_famcat *c, const char *name);
/* The same by the catalog ids a diagnose carries (kdb_diagnose_family / kdb_diagnose_variant, which the engine makes with the library's
 * own kof_famcat_fam_id_at / kof_famcat_var_id_at), or -1 (id 0 included). The engine SPELLS a variant "Mirai.A" for a reader and the catalog
 * NAMES it "Mirai_A", so a name from kdet_diag_of finds nothing; the id is the one fact both sides hold. */
int32_t kv_fam_find_family_id(const struct kof_famcat *c, uint64_t id);
int32_t kv_fam_find_variant_id(const struct kof_famcat *c, uint64_t id);

/* The three cells of a row: name (with its indent), types and comment (a variant's own; a family has none). A cell is "" when it
 * has nothing. */
void kv_fam_cells(const struct kof_famcat *c, const struct kv_fam_row *r, char *name, size_t ncap, char *types,
		  size_t tcap, char *comment, size_t ccap);

/* What a click at screen column `col` (from the table line's start, the geometry's own numbers) of row `r` opens, with the index (a
 * family's, or a variant's) it is about. A cell answers only over the EXTENT OF ITS TEXT, first to last character drawn (the
 * indent and the padding are not text), clipped to what the sideways scroll leaves visible; the column's width is not the
 * target. One function for every cell: the extent is the geometry `g` that kv_tab_render returned plus the cell text. A name
 * cell edits the family or the variant of its row; the types cell of a variant is the tick menu; the comment cell of a variant
 * is edited in place; a family's types and comment cells, the add-variant line, the gaps and the margin open nothing. */
enum kv_fam_hit { KV_FAM_HIT_NONE = 0, KV_FAM_HIT_FAMILY, KV_FAM_HIT_VARIANT, KV_FAM_HIT_COMMENT, KV_FAM_HIT_TYPES };
enum kv_fam_hit kv_fam_hit_of(const struct kof_famcat *c, const struct kv_fam_row *r, const struct kv_tab_geo *g, int col,
			      uint32_t *index);
/* An EMPTY comment cell has no text to hit: it answers over this many columns from its start, so it can still be clicked. */
#define KV_FAM_EMPTY_HIT 12

/* A table spec over the rows (no headings, natural widths measured, the comment column takes the rest). */
struct kv_fam_tab {
	const struct kof_famcat *cat;
	const struct kv_fam_row *row;
	uint32_t n_row;
	int32_t edit_var;       /* the variant whose comment is being edited in place: its comment cell is drawn blank (the field is drawn over it), -1 none */
	char name[KOF_FAMCAT_NAME_MAX + 8], types[128], comment[KOF_FAMCAT_COMMENT_MAX + 1];
};
void kv_fam_spec(struct kv_tab_spec *t, struct kv_fam_tab *ft, const struct kof_famcat *c, const struct kv_fam_row *rows,
		 uint32_t n_row);
/* The same spec with the column widths a previous kv_fam_spec measured (t->width of that call), for a caller that keeps them while the
 * catalog's revision has not moved: nothing is measured. */
void kv_fam_spec_widths(struct kv_tab_spec *t, struct kv_fam_tab *ft, const struct kof_famcat *c, const struct kv_fam_row *rows,
			uint32_t n_row, const uint16_t width[KV_FAM_COLS]);

/* Is screen column `col` (from the table line's start, the geometry's own numbers) on the add-variant button of a row? */
int kv_fam_button_at(const struct kv_tab_geo *g, int col);

/* The buttons of the dialog's last body row: [ Add family ] at the left, [ Save ] and [ Discard ] at the right (kv_dd_buttons, the one
 * code both catalog dialogs use). Save and Discard are enabled exactly when the catalog differs from its snapshot (`dirty`). */
#define KV_FAM_BTN_ADD_FAMILY KV_DD_BTN_ADD
#define KV_FAM_BTN_SAVE KV_DD_BTN_SAVE
#define KV_FAM_BTN_DISCARD KV_DD_BTN_DISCARD
#define KV_FAM_BTN_COUNT KV_DD_BTN_COUNT
#define kv_fam_btn kv_dd_btn                 /* the struct and the hit test are the shared ones (kv_dash_dialog.h) */
#define kv_fam_btn_at kv_dd_btn_at

/* The tick menu of a variant: item i is the i-th selectable type; its label, and whether the variant has it. */
uint32_t kv_fam_menu_count(void);
const char *kv_fam_menu_label(uint32_t i);
int kv_fam_menu_checked(const struct kof_famcat *c, uint32_t variant, uint32_t i);
/* Flip item i of variant `variant` (the engine decides: the status comes back). */
enum kof_famcat_status kv_fam_menu_toggle(struct kof_famcat *c, uint32_t variant, uint32_t i);

/* The list of selectable types as the shared tick grid and menu read it (kv_pick.h: the bit of a type is its engine value). */
struct kv_pick kv_fam_types(void);

/* The mask of the types ticked in the Add variant dialog, flipped on item i. */
uint32_t kv_fam_mask_flip(uint32_t mask, uint32_t i);
int kv_fam_mask_has(uint32_t mask, uint32_t i);

/* The line a dialog shows for a status ("" for OK); a full catalog names its limit. */
void kv_fam_error_text(const struct kof_famcat *c, enum kof_famcat_status st, char *out, size_t cap);

#endif /* KV_FAMDATA_H */
