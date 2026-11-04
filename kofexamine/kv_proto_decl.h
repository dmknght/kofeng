/*
 * kv_proto_decl.h - the diagnose-draft panel: what its units declare.
 *
 * IT IS A PROTOTYPE that will be redesigned (the backend of the diagnose generator is
 * not settled). Everything the viewer declares for it is here, so the redesign touches
 * one header: the prototypes of kv_decl.c, kv_declact.c, kv_draft.c and kv_chooser.c.
 * Moved here verbatim from kv.h, no declaration changed. A part of kv.h.
 */
#ifndef KV_PROTO_DECL_H
#define KV_PROTO_DECL_H

/* the draft panel, its declarations and its pick-lists */
void draft_wipe(struct view *v);
void draft_release(struct view *v);
void decl_cols_free(struct view *v);
void ch_open(struct view *v, int what, uint32_t arg, int row, int col);
void ch_follow(struct chooser *c);
void ch_take(struct view *v);
void ch_open_beside(struct view *v, int what, uint32_t arg, const struct chooser *up);
void ch_popup(const struct chooser *c, struct kv_popup *p);
void draw_chooser(struct out *o, struct view *v);
int blk_row_shown(const struct view *v, uint32_t i);
int blk_section_shown(struct view *v);
int mtn_digit(int c);
int at_digit(int c);
void mtn_sync(struct view *v);
void draw_decl(struct out *o, struct view *v);
void decl_edit_open(struct view *v, uint32_t i);
uint8_t evt_decl_target(const struct view *v, uint32_t *mask);
void decl_add_text(struct view *v, const char *text, size_t n,
			  int from_evt);
void decl_add(struct view *v, int hex);

/* kv_decl.c: the header's family and variant, and the types a unit may take from the variant (see decl_var_types). */
uint32_t decl_var_types(const struct view *v);
void decl_types_sync(struct view *v);
void decl_pick_family(struct view *v, uint32_t fam);
void decl_pick_variant(struct view *v, uint32_t var);

/* kv_keys.c: the one text-field editor. */
int  field_key(struct view *v, char *buf, size_t cap, int k,
	       int (*accept)(int));

/* The title-bar cells of the diagnose panel:
 * one widget. ` Name ` cells with " | " between, the open one reversed; the
 * printable columns of each cell (1-based, inclusive) go to c0 and c1.
 * Returns the length of the text. */
size_t tabbar_text(char *out, size_t cap, const char *const *word, uint32_t n,
		   uint32_t active, int *c0, int *c1);


#endif /* KV_PROTO_DECL_H */
