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
#include "kv_ftext.h"
#include "kv_form.h"

enum kv_fam_dlg { KV_FAM_DLG_NONE = 0, KV_FAM_DLG_FAMILY, KV_FAM_DLG_VARIANT, KV_FAM_DLG_EDIT_FAMILY, KV_FAM_DLG_EDIT_VARIANT };

struct kv_fam_ui {
	int note_shown;     /* the catalog's load note has been put on the dialog's bottom rule once (by whoever loaded first: the Family list or the dialog) */
	int open;
	struct kof_famcat cat;
	struct kof_famcat_fam fam[KV_FAM_MAX_FAMILY];
	struct kof_famcat_var var[KV_FAM_MAX_VARIANT];
	struct kof_famcat snap;         /* the catalog as loaded or last saved; its tables are the two below */
	struct kof_famcat_fam snap_fam[KV_FAM_MAX_FAMILY];
	struct kof_famcat_var snap_var[KV_FAM_MAX_VARIANT];
	struct kof_catstore store;  /* the files the directory held when the catalog was loaded or saved */
	/* the main dialog: what the last draw returned */
	struct kv_main m;               /* the main dialog (kv_form.h): its place, geometry, scroll and buttons */
	struct kv_fam_row row[KV_FAM_MAX_ROW];
	uint32_t n_row;
	/* What was derived from the catalog (the rows, the box's content size, the measured columns, the dirty flag) and the revisions it
	 * was derived at: recomputed only when kof_famcat's rev moved, not on every frame. */
	int derived;
	uint32_t rev_cat, rev_snap;
	int want_w, want_h, dirty;
	uint16_t width[KV_FAM_COLS];
	/* the small dialog */
	enum kv_fam_dlg dlg;
	uint32_t dlg_idx;               /* the family (Add variant, Edit family) or the variant (Edit variant) the dialog is about */
	/* The four text fields, all one kv_ftext (kv_ftext.h): the form's Name, the family's own Note (kof_famcat_family_comment) and the
	 * variant's Comment rows (HELD until OK) and the comment cell edited in the table (LIVE: Enter commits it to the catalog at
	 * once). Each is two past its limit plus the NUL, so the engine is the one that says "too long". */
	struct kv_ftext f_name, f_family_comment, f_comment, f_cell;
	uint32_t cell_var;              /* the variant whose comment f_cell is editing */
	uint32_t types;
	uint32_t letter;                /* Add variant: the deleted letter number picked in the names menu; 0 = the counter's next letter */
	char vname[KOF_FAMCAT_NAME_MAX + 1];   /* the variant the Add variant dialog will create, as the library names it */
	char err[sizeof ((struct kof_catstore *)0)->note];   /* one line: a refusal, or what a load or save said */
	struct kv_form fm;              /* the small dialog's frame, button and tick spans (kv_form.h) */
	/* what the last frame covered and what the frame before it had painted: the panes are painted again only when they differ */
	struct kv_cover cv;
	/* the menu in front of the dialog: a variant's types (tick menu) or, with menu_names, the family's deleted variant names */
	int menu_open;
	int menu_names;
	char mname[KOF_FAMCAT_NAME_MAX + 1];   /* the label of the names menu's item being drawn */
	uint32_t menu_var;
	int menu_y, menu_x;
};

#endif /* KV_FAMILIES_H */
