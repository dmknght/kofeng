/*
 * kv_view.h - struct view, the whole state of one session.
 *
 * One struct. Its body is cut by region into the kv_view_<region>.inc fragments below, each
 * included in place and in the old order, so no member changed its name, type or offset and
 * no use site v->field moved. The fragments are TEXT (no guard, not compiled alone); the
 * header comment of each says which package owns it and which units use it. The fields are
 * documented where they are declared. Cutting a region into a named sub-struct would rename
 * every v->field of that region in every unit; that is a later step, region by region.
 * A part of kv.h.
 */
#ifndef KV_VIEW_H
#define KV_VIEW_H

struct kv_fam_ui;
struct kv_tag_ui;
struct kv_cfg_ui;

/* What dis_format keeps from one row to the next (kv_disasm.c): the last instruction that set the flags, and where the next one would start. One per walk of rows. */
struct dis_flow {
	struct kgenome_x86_insn fl;
	uint64_t fl_rip, next;
	uint8_t ok;
};

struct view {
#include "kv_view_mutation.inc"
#include "kv_view_session.inc"
#include "kv_view_evt.inc"
#include "kv_view_hex.inc"
#include "kv_view_dis.inc"
#include "kv_view_menu.inc"
#include "kv_view_draft.inc"
#include "kv_view_chrome.inc"
#include "kv_view_decoder.inc"
#include "kv_view_props.inc"
#include "kv_view_find.inc"
#include "kv_view_dlg.inc"
#include "kv_view_dash.inc"
#include "kv_view_filter.inc"
#include "kv_view_catalog.inc"
#include "kv_view_draft_cols.inc"
#include "kv_view_field.inc"
#include "kv_view_text.inc"
};


#endif /* KV_VIEW_H */
