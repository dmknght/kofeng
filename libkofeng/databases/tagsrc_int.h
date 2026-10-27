/*
 * SWITCHED OFF (owner, 2026-10-27): the Syndrome table and its tag-source backend (kofexamine/kv_syn.c, kv_syntable.c,
 * libkofeng/databases/tagsrc*, ksigbuilder/ksb_tags.c) stay in the tree and are to be removed later, when asked. The menu item
 * is Manage > Syndromes, listed and greyed. Do not extend this code.
 */
/*
 * tagsrc_int.h - what the units of the tag-source module share (tagsrc.c,
 * tagsrc_set.c, tagsrc_check.c). Private to databases/.
 */

#ifndef KOFENG_TAGSRC_INT_H
#define KOFENG_TAGSRC_INT_H

#include "diagsrc_int.h"
#include "tagsrc.h"
#include <ctype.h>

/* The two halves a comment is held in, as one string. */
void kof_tagsrc_comment_get(const struct kof_dsrc_item *it, char *out,
			    size_t cap);
void kof_tagsrc_comment_set(struct kof_dsrc_item *it, const char *text);

/* The word an id is written in. */
void kof_tagsrc_id_text(uint64_t id, char *out, size_t cap);

/* The dictionary of a file attribute: the class a declaration kind is. */
int kof_tagsrc_attr_class(unsigned what);

#endif /* KOFENG_TAGSRC_INT_H */
