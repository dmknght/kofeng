/*
 * kv_bar_private.h - what the parts of the menu bar share (kv_bar.c, kv_bar_items.c,
 * kv_bar_rules.c). Private to those three files; included after "kv.h". What other units
 * call is in kv_shared.h (bar_has_sub, bar_enabled, bar_col, obj_maybe_code, dump_needs_rebuild).
 */
#ifndef KV_BAR_PRIVATE_H
#define KV_BAR_PRIVATE_H

/* One row of the item table (kv_bar_items.c), in the order of enum bar_item. */
struct bar_item_def {
	const char *label;
	int         menu;
	/* The item this one hangs under, or -1 for a top-level entry. */
	int         parent;
	/*
	 * Draw a rule ABOVE this item.
	 *
	 * On the item BELOW the break rather than the one above it, so
	 * appending to a group does not move the break - which is the
	 * mistake the other spelling invites.
	 *
	 * BOTH the drawer and the hit test must count the extra row. They
	 * are two separate walks over this table and they have disagreed
	 * before - see the note on bar_col - so the row comes from one
	 * helper, bar_gap, that both call.
	 */
	int         sep;
};

extern const struct bar_item_def bar_item[BI_COUNT];

/* The verb a filter slot stands for, or -1 (kv_bar_items.c). */
int bar_filt_verb(int i);
/* The wording an item shows now (kv_bar_items.c). */
const char *bar_label(struct view *v, int i);
/* 1 when a rule is drawn above item `i` (kv_bar_items.c). */
int bar_gap(struct view *v, int i);

/* Whether the item exists for the object in hand, and why a greyed one is grey (kv_bar_rules.c). */
int bar_shown(struct view *v, int i);
const char *bar_why_off(struct view *v, int i);

#endif /* KV_BAR_PRIVATE_H */
