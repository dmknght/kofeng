/*
 * kv_families.h - the state of Manage > Pathogens (kv_families.c). The content is kv_famdata.c's and the model
 * is the engine's catalog (<verdictor/famcat.h>); what is kept here is only what the screen needs to answer a click:
 * the geometry the frame and the table returned, the small dialog's field and the tick menu's place.
 *
 * STORAGE is the library's (kof_famcat_load / kof_famcat_save, famcat_store.c): the catalog is loaded from the directory the first time the
 * dialog opens, `snap` is what Discard goes back to (the loaded state, then the last Save), and Save / Discard are enabled while the
 * catalog differs from it. This file keeps the state; the library decides.
 */
#ifndef KV_FAMILIES_H
#define KV_FAMILIES_H

#include "kv_famdata.h"

enum kv_fam_dlg { KV_FAM_DLG_NONE = 0, KV_FAM_DLG_FAMILY, KV_FAM_DLG_VARIANT, KV_FAM_DLG_EDIT_FAMILY, KV_FAM_DLG_EDIT_VARIANT };
/* The two text fields of the small form: where each was drawn (a screen row and columns), for the hit test. */
enum kv_fam_fld { FAM_FLD_NAME = 0, FAM_FLD_COMMENT, FAM_FLD_COUNT };
struct kv_fam_fld_box {
	int y, x0, x1;
};

/* A rectangle the dialog covers: screen rows y0..y1, columns x0..x1 (all zero: none). */
struct kv_fam_rect {
	int y0, x0, y1, x1;
};
#define KV_FAM_COVER 3          /* the main box, the small dialog, the tick menu */

struct kv_fam_ui {
	int open;
	struct kof_famcat cat;
	struct kof_famcat_fam fam[KV_FAM_MAX_FAMILY];
	struct kof_famcat_var var[KV_FAM_MAX_VARIANT];
	struct kof_famcat snap;         /* the catalog as loaded or last saved; its tables are the two below */
	struct kof_famcat_fam snap_fam[KV_FAM_MAX_FAMILY];
	struct kof_famcat_var snap_var[KV_FAM_MAX_VARIANT];
	struct kof_famcat_store store;  /* the files the directory held when the catalog was loaded or saved */
	/* the main dialog: what the last draw returned */
	uint32_t off, hoff;             /* the first row shown, the sideways offset of the table */
	struct dlg_off main_move;       /* where the main dialog was dragged; reset when it opens */
	struct kv_dd_geo geo;
	struct kv_tab_geo tg;
	struct kv_fam_row row[KV_FAM_MAX_ROW];
	uint32_t n_row;
	/* What was derived from the catalog (the rows, the box's content size, the measured columns, the dirty flag) and the revisions it
	 * was derived at: recomputed only when kof_famcat's rev moved, not on every frame. */
	int derived;
	uint32_t rev_cat, rev_snap;
	int want_w, want_h, dirty;
	uint16_t width[KV_FAM_COLS];
	int tab_y;                      /* screen row of the table's first line */
	struct kv_fam_btn btn[KV_FAM_BTN_COUNT];   /* the bottom row's buttons and how many are drawn */
	uint32_t n_btn;
	/* the small dialog */
	enum kv_fam_dlg dlg;
	uint32_t dlg_idx;               /* the family (Add variant, Edit family) or the variant (Edit variant) the dialog is about */
	/* two past the limit plus the NUL: field_key keeps one spare, so a 65th character can be typed and the engine says too long */
	char name[KOF_FAMCAT_NAME_MAX + 3];
	uint32_t name_off, types;
	int reuse;                      /* Add variant: take the smallest free letter below the family's counter */
	/* the comment being typed (Add family: its first variant's, Add variant: the new variant's, Edit comment: that variant's); two past the limit like the name */
	char comment[KOF_FAMCAT_COMMENT_MAX + 3];
	uint32_t cmt_off;
	char vname[KOF_FAMCAT_NAME_MAX + 1];   /* the variant the Add variant dialog will create, as the library names it */
	char err[sizeof ((struct kof_famcat_store *)0)->note];   /* one line: a refusal, or what a load or save said */
	struct dframe f;
	struct kv_fam_fld_box fld[FAM_FLD_COUNT];
	int ok_x[2], cancel_x[2], delete_x[2], btn_y;
	int tick_y[KV_FAM_TICKS], tick_x0[KV_FAM_TICKS], tick_x1[KV_FAM_TICKS];
	/* the comment cell being edited in place (one at a time): the variant, the text, how far the field is scrolled */
	int cedit_on;
	uint32_t cedit_var, cbuf_off;
	char cbuf[KOF_FAMCAT_COMMENT_MAX + 3];      /* two past the limit like the dialog's comment: the engine says too long */
	/* what the last frame covered and what the frame before it had painted: the panes are painted again only when they differ */
	struct kv_fam_rect cover[KV_FAM_COVER], painted[KV_FAM_COVER];
	/* the tick menu of a variant's types */
	int menu_open;
	uint32_t menu_var;
	int menu_y, menu_x;
};

#endif /* KV_FAMILIES_H */
