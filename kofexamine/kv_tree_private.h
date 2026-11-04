/*
 * kv_tree_private.h - the object tree's units: what one of them offers another.
 *
 * kv_tree.c is the tree (rows, build), kv_tree_label.c is what a row says (object, region, entry),
 * kv_tree_log.c is the event log's window over the object array. What other units of the viewer call
 * stays declared in kv_shared.h under the same names. Included after kv.h by those three files.
 */
#ifndef KV_TREE_PRIVATE_H
#define KV_TREE_PRIVATE_H

/* kv_tree.c */
void tree_add(struct view *v, uint32_t depth, uint32_t obj, uint32_t mask,
	      uint64_t bytes, const char *label);

/* kv_tree_label.c */
void region_row(struct view *v, const struct object *o, uint32_t i, uint32_t bit);
const char *ent_label(const struct object *o, const struct kof_entry *e,
		      char *out, size_t outcap);

#endif /* KV_TREE_PRIVATE_H */
