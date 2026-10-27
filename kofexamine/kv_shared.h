/*
 * kv_shared.h - what the units share: the prototypes of every function more than one unit
 * calls, and the globals more than one unit touches.
 *
 * The prototypes of the draft panel and its pick-lists are in kv_proto_decl.h.
 * A part of kv.h, included by it and by nothing else.
 */
#ifndef KV_SHARED_H
#define KV_SHARED_H

/* ===== what the units share: functions ===== */
const char *byte_colour(uint8_t c);
void dis_paint(struct out *o, const char *text);
int hex_top(void);
int hex_bot(void);
int mark_row(void);
int dis_top(void);
int evt_top(void);
int hex_last(void);
int byte_text(uint8_t c);
int literal_safe(const uint8_t *b, uint32_t n);
uint32_t obj_region_bits(const struct object *o, uint32_t *out,
				uint32_t cap);
struct object *cur_obj(struct view *v);
const struct kgenome_func_set *mtn_funcs(struct view *v, struct object *o);
int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user);
void proc_collect(struct view *v, kof_engine *eng, uint32_t pid);
void objects_collect(struct view *v, kof_engine *eng);
const char *sym_byte_colour(const uint8_t *b, uint32_t n, uint64_t off);
int sym_view(const struct view *v);
const uint8_t *sym_block(const struct view *v, uint64_t *n);
uint32_t sym_half(const struct object *o, uint32_t mask,
			 struct kof_range *ext, uint32_t cap, uint64_t *bytes);
uint32_t sym_row_mask(uint8_t which);
uint8_t sym_which_of(uint32_t mask);
uint32_t sym_half_recs(const struct object *o, uint32_t mask,
			      struct kof_range *ext, uint32_t cap,
			      uint32_t *idx, uint32_t idx_cap);
void objects_examine_from(struct view *v, kof_engine *eng, uint32_t from);
void objects_examine(struct view *v, kof_engine *eng);
int decl_top(void);
const struct kof_parser *obj_region_vocab(const struct object *o);
void obj_label(const struct object *o, char *out, size_t cap);
void log_scan_verbs(struct view *v);
void log_window(struct view *v);
int log_window_from(struct view *v, uint64_t first);
void tree_build(struct view *v);
uint64_t hex_max(const struct view *v);
int evt_have_rec(const struct view *v);
int evt_live(const struct view *v);
const char *evt_byte_colour(const struct view *v, uint64_t off);
int evt_zones(const struct view *v, int *meta, int *n_meta,
		     int *warn, int *n_warn);
int evt_warn_lines(const struct view *v);
int evt_meta_lines(const struct view *v);
int evt_box_top(const struct view *v);
const char *evt_box_text(const struct view *v, char *buf, size_t cap,
				size_t *len);
int evt_box_total(const struct view *v);
int evt_text_at(const struct view *v, int my, int mx, int *ch);
int evt_meta_at(const struct view *v, int my, int mx);
void evt_reveal_char(struct view *v, int c);
void evt_sync_hex(struct view *v, int reveal);
size_t evt_sel_text(const struct view *v, char *out, size_t cap);
void evt_load(struct view *v);
void view_select(struct view *v);
void goto_node(struct view *v, uint32_t k);
const uint8_t *view_bytes(const struct view *v, uint64_t *n);
uint64_t view_map(const struct view *v, uint64_t at, uint64_t *run);
uint64_t view_unmap(const struct view *v, uint64_t off);
int mtn_kept_any(const struct view *v);
uint32_t mtn_at_byte(const struct view *v);
const char *mtn_lit_at(const struct view *v, uint64_t rgn_off);
void mtn_segment(struct view *v);
void mtn_rescore(struct view *v);
void row_start(struct out *o, int row, int col);
void draw_frame(struct out *o, struct view *v);
void draw_tree(struct out *o, struct view *v);
int in_sel(const struct view *v, uint64_t at);
int decl_kind(struct view *v, uint64_t off);
void sym_flag_str(uint8_t f, char *out);
void sym_shn_str(const uint8_t *r, char *out, size_t n);
uint64_t txt_line_start(struct view *v, const uint8_t *base,
			       uint64_t base_n, uint64_t at);
uint64_t txt_line_end(struct view *v, const uint8_t *base,
			     uint64_t base_n, uint64_t at);
uint64_t txt_line_of(struct view *v, const uint8_t *base,
			    uint64_t base_n, uint64_t at);
uint64_t txt_max_top(struct view *v, const uint8_t *base,
			    uint64_t base_n, int rows);
int txt_bot(const struct view *v);
void draw_text(struct out *o, struct view *v);
int text_under(struct view *v, int row, int col, uint64_t *out,
		      uint64_t *out_line, uint32_t *out_col);
void draft_seed_target(struct view *v);
void txt_hscroll(struct view *v, int by);
uint64_t txt_home_end(struct view *v);
int view_can_text(struct view *v);
void view_toggle_text(struct view *v);
int text_pane(struct view *v);
void draw_hex(struct out *o, struct view *v);
int cmatch_ok(struct view *v, uint32_t c, uint32_t m);
void prow_build(struct view *v);
void sec_bar(struct out *o, struct view *v, int row, const char *text);
int fsel_range(const struct view *v, uint32_t *lo, uint32_t *hi);
void fsel_clear(struct view *v);
void fsel_set(struct view *v, uint32_t a, uint32_t b);
int field_room(const char *text, const char *ph, int editing, int max);
void field_draw(struct out *o, const char *text, uint32_t caret,
		       uint32_t *off, int room, int editing, const char *ph);
int heur_of(const struct object *ob, struct kof_heur_facts *out,
		   int32_t *score, const char **guess);
int heur_reports(const struct object *ob, int32_t *score,
			const char **guess);
uint64_t dis_hex_shown(const struct view *v);
uint64_t dis_span_of(const struct view *v);
int64_t dis_max_bias(struct view *v);
void dis_follow_hex(struct view *v);
void dis_bias_to_sel(struct view *v);
void dis_span(const struct view *v, uint64_t *at0, int *c0,
		     uint64_t *at1, int *c1);
int dis_hex_sel(const struct view *v);
int dis_cols(const struct view *v, uint64_t at, uint64_t alen, int len,
		    int *from, int *to);
void dis_sync_bytes(struct view *v);
int dis_real_row(const struct view *v, int idx);
unsigned dis_format(struct view *v, uint64_t *at, char *line, size_t cap,
			   uint8_t *bytes_out, unsigned *ix_len_out,
			   int *ok_out, char *text_out, size_t text_cap);
uint64_t dis_sync(struct view *v, uint64_t want);
void draw_evt(struct out *o, struct view *v);
void draw_disasm(struct out *o, struct view *v);
void dis_toggle(struct view *v, uint64_t at, uint64_t len);
void dis_analyse(struct view *v);
void dis_drop_analysis(struct view *v);
const char *emu_why_tag(uint8_t why);
const char *emu_why_reason(uint8_t why);
void draw_marker_line(struct out *o, struct view *v);
int menu_enabled(struct view *v, int a);
int menu_rows(struct view *v);
int menu_at_row(struct view *v, int row);
void menu_open_at(struct view *v, int row, int col);
void menu_step(struct view *v, int d);
void draw_menu(struct out *o, struct view *v);
void copy_osc52(const char *bytes, size_t n);
void dis_copy(struct view *v);
void copy_said(struct view *v, size_t n);
void copy_offset(struct view *v, int hex);
void copy_selection(struct view *v, int as_hex);
void menu_run(struct view *v, int a);
void redraw(struct view *v);
int byte_under(struct view *v, int row, int col, uint64_t *out);
uint32_t node_at(struct view *v, uint32_t obj, uint64_t file_off);
void view_show_in(struct view *v, uint32_t obj, uint8_t sym,
			 uint64_t off, int narrow);
void view_show_decl(struct view *v, const struct decl *d, uint64_t off);
int rx_compile(const char *text, uint8_t *prog, uint32_t cap,
		      uint32_t *n_out, char *err, size_t err_n);
void find_compile(struct view *v);
void find_run(struct view *v, int back);
int bar_has_sub(int i);
int obj_maybe_code(const struct object *o);
int dump_needs_rebuild(const struct view *v, int use_emu);
int bar_enabled(struct view *v, int i);
int bar_col(int m);
void draw_bar(struct out *o, struct view *v);
int bar_item_at(struct view *v, int row, int col);
int vis_cols(const char *s);
void draw_help(struct out *o, struct view *v);
void prop_off(char *out, size_t cap, uint64_t v);
void prop_perm(char *out, size_t cap, unsigned p);
/* kv_props_table.c: a point on the page, answered from the tables' returned geometry (kv_table.h) */
int prop_cell_at(const struct view *v, int y, int x, uint32_t *slot, uint32_t *row, int *k);
const char *prop_cell_text(const struct view *v, uint32_t slot, uint32_t row, int k);
size_t prop_row_text(const struct view *v, uint32_t slot, uint32_t row, char *out, size_t cap);
void prop_tabs_free(struct view *v);
uint32_t obj_ancestors(const struct view *v, const struct object *ob,
			      const struct object **out, uint32_t cap);
void prop_build(struct view *v);
void page_draw(struct out *o, struct view *v, struct page *p);
void draw_prop(struct out *o, struct view *v);
const char *base_name(const char *path);
void editor_attach(struct view *v);
void emu_here(struct view *v);
void separate_now(struct view *v);
int tree_has_emu(const struct view *v);
void dump_all(struct view *v, int use_emu);
int dir_pick(const char *folder, const char *from, int which,
		    char *out, size_t cap);
void open_step(struct view *v, int dir);
void rebuild_db(struct view *v);
void bar_enter_sub(struct view *v, int i);
void bar_open_menu(struct view *v, int menu);
void bar_move_item(struct view *v, int dir);
void bar_run(struct view *v, int i);
enum kv_nav kv_nav_key(int key);
int kv_nav_step(int sel, int n, enum kv_nav nav);
size_t paste_src(int k, const char **out);
int key_pending(void);
int read_key(void);
void hex_step(struct view *v, long lines);
void hit_wheel_text(struct view *v, uint32_t arg);
void hit_hwheel_text(struct view *v, uint32_t arg);
uint64_t now_ms(void);
void select_run(struct view *v);
void cnd_id_click(struct view *v, uint32_t g);
void bar_to(struct view *v, int which);
int bar_under(struct view *v);
void dlg_rec_begin(struct view *v, int y0, int x0);
void dlg_rec_src(struct view *v, uint32_t idx);
int dlg_row_of_src(const struct view *v, int src);
int dlg_col_of_byte(const struct view *v, int row, uint32_t byte);
void dlg_rec_text(struct view *v, const char *plain);
int dlg_span(const struct view *v, int *r0, int *c0, int *r1, int *c1);
void dlg_paint_sel(struct out *o, struct view *v);
int dlg_at(const struct view *v, int row, int col, int *r, int *c);
void dlg_copy(struct view *v);
int dlg_click_count(struct view *v, int r, int c);
void dlg_select_full(struct view *v, int r, int c0, int c1, const char *text, size_t n);
/* kv_props_tab.c: the dashboard's pages and the controls of its tab strip */
void prop_show(struct view *v);
void prop_show_infection(struct view *v);
void prop_close(struct view *v);
void prop_page_set(struct view *v, unsigned pg);
int prop_click(struct view *v);
int prop_page_key(struct view *v, int k);
void prop_scroll(struct view *v, int dy, int dx);
void prop_bar_to(struct view *v);

void prop_filter_over(struct out *o, struct view *v, int y0, int x0, int y1, int x1);
void prop_sym_filter_compile(struct view *v);
void enc_do(struct view *v);
void draw_enc(struct out *o, struct view *v);
void enc_open_with(struct view *v, const uint8_t *p, uint32_t n);
size_t enc_sel_text(struct view *v, char *out, size_t cap);
int enc_click(struct view *v, int rclick);
void goto_take(struct view *v);
void draw_goto(struct out *o, struct view *v);
int goto_click(struct view *v);
void draw_find(struct out *o, struct view *v);
int dframe_grab(struct view *v, struct dframe *f);
void dlg_hold(struct view *v, struct dlg_off *off);
/* The framed dialogs' parts (kv_dialogs.c), shared by the dialogs that are not in that file (kv_families.c). */
int dframe_begin(struct out *o, struct dframe *f, const char *title, int want_w, int want_h, int close);
void dframe_done(struct out *o, struct dframe *f);
void dframe_row(struct out *o, const struct dframe *f, int r);
void dframe_edge(struct out *o, const struct dframe *f);
void dframe_end(struct out *o, const struct dframe *f, const char *foot);
int dframe_hit_close(const struct dframe *f, int my, int mx);
/* kv_page.c: one page line with its colour escapes onto the screen, padded to `room` columns. */
void prop_put(struct out *o, const char *s, int room, int sa, int sb);
/* kv_families.c: Manage > Pathogens. */
void fam_open(struct view *v);
void fam_free(struct view *v);
int fam_up(const struct view *v);
void draw_fam(struct out *o, struct view *v);
/* After draw_fam: did a box of the dialog move, shrink, open or close since the last frame drawn? (then the panes under it must be painted again) */
int fam_uncovered(struct view *v);
int fam_click(struct view *v, int rclick);
int handle_fam_key(struct view *v, int k);
int find_click(struct view *v);
int click_menu(struct view *v);
void hit_reset(struct view *v);
void hit_zone(struct view *v, int y0, int x0, int y1, int x1,
		     uint8_t btn, void (*fn)(struct view *, uint32_t),
		     uint32_t arg);
void hit_add(struct view *v, int y, int x0, int x1,
		    void (*fn)(struct view *, uint32_t), uint32_t arg);
int hit_run(struct view *v, uint8_t want);
void hit_row_none(struct view *v, uint32_t arg);
void hit_row_addcond(struct view *v, uint32_t arg);
void hit_row_cond(struct view *v, uint32_t g);
void click(struct view *v, int rclick);
int handle_f10(struct view *v, int k);
int handle_bar_key(struct view *v, int k);
int handle_copy_key(struct view *v, int k);
int handle_enc_key(struct view *v, int k);
int handle_prop_key(struct view *v, int k);
int handle_chooser_key(struct view *v, int k);
void on_drag(struct view *v);
void on_release(struct view *v);
int handle(struct view *v, int k);
int file_open(struct view *v, const char *path, kof_engine *eng);
size_t paste_extern(char *out, size_t cap);

/* ===== what the units share: state ===== */
extern const char *const mtn_colour[MTN_COLOURS];
extern int g_decl_rows;
extern int g_disasm_rows;
extern int g_evt_rows;
extern const char *const opt_word[OPT_COUNT];
extern int g_mx, g_my;
extern int g_wheel;
struct kv_g_fld {
	int      row, col, room;
	uint32_t off, len;
};
extern struct kv_g_fld g_fld;
struct kv_g_fsel { uint32_t lo, hi; };
extern struct kv_g_fsel g_fsel;
extern char   g_clip[8192];
extern size_t g_clip_n;
extern const char *const bar_name[BM_COUNT];
extern struct prop_line g_prop[PROP_MAX];
extern uint32_t         g_n_prop;
extern int g_mod_shift;
extern int g_mod_ctrl;
extern struct dframe g_goto_f, g_find_f, g_enc_f;


#endif /* KV_SHARED_H */
