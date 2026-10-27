/*
 * kv_proto_decl.h - the diagnose-draft panel and the tag sources: what their units declare.
 *
 * BOTH ARE PROTOTYPES that will be redesigned (the backend of the diagnose generator and
 * the tag generator are not settled). Everything the viewer declares for them is here, so
 * the redesign touches one header: the prototypes of kv_decl.c, kv_declact.c, kv_draft.c
 * and kv_chooser.c, then the tag sources of kv_syn.c and kv_syntable.c. Moved here
 * verbatim from kv.h, no declaration changed. A part of kv.h.
 */
#ifndef KV_PROTO_DECL_H
#define KV_PROTO_DECL_H

/* the draft panel, its declarations and its pick-lists */
void draft_wipe(struct view *v);
void ch_open(struct view *v, int what, uint32_t arg, int row, int col);
void ch_follow(struct chooser *c);
void ch_take(struct view *v);
int ch_vis(const struct chooser *c);
void draw_chooser(struct out *o, struct view *v);
int blk_row_shown(const struct view *v, uint32_t i);
int blk_section_shown(struct view *v);
/* The open tab of the diagnose panel, and how tall its output pane is. */
uint32_t preview_rows(const struct view *v);
int mtn_digit(int c);
int at_digit(int c);
void mtn_sync(struct view *v);
uint32_t diag_shown_n(struct view *v);
void draw_decl(struct out *o, struct view *v);
void decl_edit_open(struct view *v, uint32_t i);
uint8_t evt_decl_target(const struct view *v, uint32_t *mask);
void decl_add_text(struct view *v, const char *text, size_t n,
			  int from_evt);
void decl_add(struct view *v, int hex);

/* ---- the tag sources: the Syndrome table and the tag chooser ----------------
 *
 * The data is databases/tagsrc.h's - one set of entities loaded from a
 * directory, edited in memory, written back by Save. What is here is the
 * views over it: the table page with a tab for each kind of entity, the
 * Add/Edit form, the pick list (one widget: the tag chooser of the diagnose
 * panel and every multi-select of the tag form), and the result box a Check or
 * a refused Delete speaks in. All four are pages of lines (page_draw) with the
 * clickable spans of each line recorded as it is built (syn_hit).
 */
enum syn_tab { SYN_ACT = 0, SYN_TYP, SYN_FAM, SYN_TAG, SYN_TABS };

/* What a recorded span does. */
enum syn_act {
	SYA_NONE = 0, SYA_TAB, SYA_ROW, SYA_ADD, SYA_EDIT, SYA_DEL, SYA_CHECK,
	SYA_SAVE, SYA_SEARCH, SYA_OK, SYA_CANCEL, SYA_FIELD,
	SYA_PICK, SYA_NEW, SYA_PROW
};

struct syn_hit {
	uint32_t line;          /* the line of the layer */
	int16_t  c0, c1;        /* its printable columns, inclusive */
	uint8_t  act;           /* enum syn_act */
	uint32_t arg;
};

/* One page: its lines, the spans on them and where it was drawn. */
struct syn_layer {
	struct prop_line *line;
	uint32_t          n, cap;
	uint32_t          fixed;        /* lines at the top that do not scroll */
	uint32_t          off;          /* scroll of the rest */
	struct syn_hit   *hit;
	uint32_t          nh, caph;
	int               top, left, w, h;
	uint32_t          shown;
	int               btn_y, btn_x0, btn_x1;
};

/* What a pick list is for. */
enum syn_pick_what {
	PK_NONE = 0, PK_TAG_COND, PK_TAG_GRP, PK_ACT, PK_TYP, PK_FAM, PK_FMT,
	PK_ARCH, PK_SUB
};

#define SYN_FILT 64u

struct syn_prow {
	char     col[4][KOF_TAGSRC_COMMENT_LEN];
	uint64_t id;            /* the entity's, for the tag fields */
	uint16_t idx;           /* the word's, for the attribute fields */
	uint32_t pos;           /* 0 unticked, else the order it was ticked in */
};

struct syn_pick {
	int      open;
	int      what;          /* enum syn_pick_what */
	uint32_t arg;           /* the condition or matcher the tag is for */
	int      multi;
	int      ncol;
	uint32_t ticks;
	char     title[40];
	char     head[4][16];
	char     filt[SYN_FILT];
	uint32_t foff;
	struct syn_prow *row;
	uint32_t n, cap;
	uint32_t *vis, n_vis, cap_vis;  /* the rows the filter lets through */
	uint32_t n_real;        /* of them, the ones that are not "(none)" */
	uint32_t sel;           /* the cursor, in `vis` */
	/* A row (not a `vis` place) the cursor is to start on, or UINT32_MAX:
	 * the filter decides where it is, so it is placed when `vis` is built. */
	uint32_t want;
	struct syn_layer ly;
};

/* The Add/Edit form: a working copy, which the entity gets on OK. */
struct syn_form {
	int      open;
	uint8_t  kind;          /* enum kof_tagsrc_kind */
	int      edit;          /* an existing entity, set index `ent`, or new */
	size_t   ent;
	struct kof_tagent e;
	char     name[KOF_TAGSRC_NAME_LEN];
	char     cmt[KOF_TAGSRC_COMMENT_LEN];
	uint32_t name_off, cmt_off;
	char     err[160];
};

struct kv_syn {
	struct kof_tagset set;
	char     dir[256];
	char     diag_dir[256];
	int      open;          /* the table page is up */
	int      tab;           /* enum syn_tab */
	char     filt[SYN_FILT];
	uint32_t foff;
	uint32_t sel[SYN_TABS];
	uint32_t *rows;         /* set indices the open tab shows */
	uint32_t n_rows, cap_rows;
	struct syn_layer page, res, frm;
	char     res_title[40];
	int      res_open;
	struct syn_form form, parent;   /* parent: the tag form a [+ New] hides */
	int      has_parent;
	struct syn_pick pick;
};

/* kv_syn.c: the lines of a layer and the spans on them. */
void syn_ly_reset(struct syn_layer *ly);
uint32_t syn_ly_line(struct syn_layer *ly);
int  syn_ly_col(const struct syn_layer *ly, uint32_t li);
void syn_ly_put(struct syn_layer *ly, uint32_t li, const char *sgr,
		const char *text);
void syn_ly_hit(struct syn_layer *ly, uint32_t li, int c0, int c1, int act,
		uint32_t arg);

/* kv_syn.c: the model and what the buttons do. */
struct kv_syn *syn_new(const char *dir, const char *diag_dir);
void syn_free(struct kv_syn *s);
void syn_open(struct view *v);
void syn_close(struct view *v);
int  syn_modal(const struct view *v);
int  syn_page_up(const struct view *v);
void syn_rows(struct view *v);
void syn_tab_set(struct view *v, int tab);
void syn_form_open(struct view *v, int kind, int edit);
void syn_form_ok(struct view *v);
void syn_form_cancel(struct view *v);
void syn_form_new(struct view *v, int kind);
void syn_form_pick(struct view *v, int what);
void syn_delete(struct view *v);
void syn_check(struct view *v);
void syn_save(struct view *v);
void syn_pick_tag(struct view *v, int what, uint32_t arg);
void syn_pick_vis(struct view *v);
void syn_pick_home(struct view *v);
void syn_pick_toggle(struct view *v, uint32_t vi);
void syn_pick_ok(struct view *v);
void syn_pick_cancel(struct view *v);
void syn_say(struct view *v, int ok, const char *fmt, ...);
uint32_t syn_dirty(const struct kv_syn *s);
void syn_row_cells(const struct kv_syn *s, const struct kof_tagent *e,
		   int tab, char cell[][160]);

/* kv_syntable.c: drawing, the mouse and the keys. */
void draw_syn(struct out *o, struct view *v);
int  handle_syn_key(struct view *v, int k);
int  syn_click(struct view *v);
void syn_layer_free(struct syn_layer *ly);
int  field_key(struct view *v, char *buf, size_t cap, int k,
	       int (*accept)(int));

/* The title-bar cells of the diagnose panel and of the Syndrome table: one
 * widget. ` Name ` cells with " | " between, the open one reversed; the
 * printable columns of each cell (1-based, inclusive) go to c0 and c1.
 * Returns the length of the text. */
size_t tabbar_text(char *out, size_t cap, const char *const *word, uint32_t n,
		   uint32_t active, int *c0, int *c1);


#endif /* KV_PROTO_DECL_H */
