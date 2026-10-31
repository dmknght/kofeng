/*
 * kv_tags.h - the state of Manage > Syndromes (kv_tags.c). The content is kv_tagdata.c's, the model is the engine's catalog
 * (<verdictor/tagcat.h>) and the screen code both catalog dialogs use is kv_form.c's; what is kept here is only what answers a click.
 *
 * STORAGE is the library's (kof_tagcat_load / kof_tagcat_save, tagcat_store.c, the same directory code as Pathogens): the catalog is
 * loaded from <bases>/syndromes (or --syndromes) the first time it is needed, `snap` is what Discard goes back to (the loaded state, then
 * the last Save), and Save / Discard are enabled while the catalog differs from it. This file keeps the state; the library decides.
 */
#ifndef KV_TAGS_H
#define KV_TAGS_H

#include "kv_tagdata.h"
#include "kv_ftext.h"
#include "kv_form.h"

enum kv_tag_dlg { KV_TAG_DLG_NONE = 0, KV_TAG_DLG_ADD, KV_TAG_DLG_EDIT };

struct kv_tag_ui {
	int open;
	struct kof_tagcat cat;
	struct kof_tagcat_tag tag[KV_TAG_MAX];
	struct kof_tagcat snap;         /* the catalog as loaded or last saved; its table is the one below */
	struct kof_tagcat_tag snap_tag[KV_TAG_MAX];
	struct kof_catstore store;      /* the files the directory held when the catalog was loaded or saved */
	int note_pending;               /* the load's line has not been shown yet (the first opening of the dialog shows it) */
	struct kv_main m;               /* the main dialog (kv_form.h) */
	/* What was derived from the catalog (the content size and the measured columns) and the revision it was derived at. */
	int derived;
	uint32_t rev_cat, rev_snap;
	int want_w, want_h, dirty;
	uint16_t width[KV_TAG_COLS];
	/* the small dialog */
	enum kv_tag_dlg dlg;
	uint32_t dlg_idx;               /* Edit: the tag the dialog is about */
	struct kv_ftext f_name;         /* HELD until OK; two past the limit plus the NUL, so the engine is the one that says "too long" */
	struct kv_ftext f_comment;      /* the Comment row under it: the same kv_ftext as the Comment row of Pathogens */
	uint32_t acts, objs;            /* the ticks of the form */
	char err[sizeof ((struct kof_catstore *)0)->note];   /* one line: a refusal, or what a load or save said */
	struct kv_form fm;
	struct kv_cover cv;
	/* the tick menu of a cell */
	int menu_open;
	uint32_t menu_idx;
	enum kv_tag_list menu_list;
	int menu_y, menu_x;
	char lbl[KV_PICK_LABEL];        /* scratch for the label of the menu item being drawn */
};

#endif /* KV_TAGS_H */
