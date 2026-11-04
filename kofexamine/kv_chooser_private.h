/*
 * kv_chooser_private.h - what the parts of the chooser share (kv_chooser.c,
 * kv_chooser_items.c, and the .inc files kv_chooser.c includes: kv_chooser_open.inc, kv_chooser_take.inc).
 *
 * Private to those files; included after "kv.h". The public face of the
 * chooser is kv_chooser.h (the state) and kv_proto_decl.h (ch_open, ch_take,
 * ch_follow, ch_popup, draw_chooser).
 */
#ifndef KV_CHOOSER_PRIVATE_H
#define KV_CHOOSER_PRIVATE_H

/* The rows of the format-kind table (the catch-all comes after them). */
extern const uint32_t ch_fmt_cat_n;
#define FMT_CAT_N ch_fmt_cat_n

/*
 * TWO NUMBERS IN ONE `arg`, because a switch submenu needs both and the
 * chooser carries one.
 *
 * The low byte is WHICH of the draft's formats was clicked - the row being
 * switched away from - and the high byte is which CATEGORY the reader then
 * opened. Packed rather than stashed in `struct view`: the chooser already
 * carries its own argument down to the taker, and a second copy living beside
 * it is a second thing to keep in step. Both fit easily - there are eighteen
 * formats and seven categories.
 */
#define FMT_SW_PACK(cat, which) (((cat) << 8) | ((which) & 0xffu))
#define FMT_SW_CAT(a)           ((a) >> 8)
#define FMT_SW_WHICH(a)         ((a) & 0xffu)

/* Rows (kv_chooser_items.c). */
void ch_add(struct chooser *c, const char *t);
void ch_add_verb(struct chooser *c, const char *t, unsigned verb);
void ch_add_sep(struct chooser *c);
void ch_add_verb_sub(struct chooser *c, const char *t, unsigned verb);
void ch_attr_items(struct chooser *c);

/* The format kinds and what a draft may still add (kv_chooser_items.c). */
uint32_t ch_fmt_cat_mask(uint32_t i);
const char *ch_fmt_cat_name(uint32_t i);
int ch_fmt_cat_langs(uint32_t i);
uint32_t ch_fmt_lang_skip(const struct view *v);
void ch_fmt_swap(struct view *v, uint32_t which, uint8_t pick);

/* One predicate for the list that offers an optional declaration and the taker that walks it. */
int ch_opt_offerable(struct view *v, int k);

/* Which regions the selected object has, as a mask. */
uint32_t ch_rng_regions(struct view *v);

#endif /* KV_CHOOSER_PRIVATE_H */
