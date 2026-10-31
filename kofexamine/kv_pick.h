/*
 * kv_pick.h - a LIST OF CHOICES a dialog lets the person tick, as data: how many, the label of each and the bit each has in the mask the
 * catalog stores. Pure and header-only (no terminal), so the data layers (kv_famdata.c, kv_tagdata.c) and the tick grid and menu of the
 * viewer (kv_form.c) read ONE description of a list. The bit of an item is the engine's own value for it (a malware type's, an
 * activity's), never the item's position, so the mask is the one the library validates.
 */
#ifndef KV_PICK_H
#define KV_PICK_H

#include <stdint.h>

/* The room a label may take when it is MADE (a displayed word is capitalised from the engine's lower-case one): the caller's scratch. */
#define KV_PICK_LABEL 40

struct kv_pick {
	uint32_t n;
	/* The label of item i as it is SHOWN: a constant, or written into `buf` (KV_PICK_LABEL bytes) and returned. Valid until the next call. */
	const char *(*label)(uint32_t i, char *buf);
	uint32_t (*bit)(uint32_t i);
};

/* Is item i in `mask`? An index past the list is not. */
static inline int kv_pick_has(const struct kv_pick *l, uint32_t mask, uint32_t i)
{
	return i < l->n && (mask >> l->bit(i) & 1u) != 0u;
}

/* The mask with item i flipped (an index past the list changes nothing). */
static inline uint32_t kv_pick_flip(const struct kv_pick *l, uint32_t mask, uint32_t i)
{
	return i < l->n ? mask ^ (1u << l->bit(i)) : mask;
}

#endif /* KV_PICK_H */
