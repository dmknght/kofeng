#define _GNU_SOURCE

/*
 * tagcat.c - the tag catalog. See tagcat.h for the contract.
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "../kofcore/kofmod/kofsig.h"   /* kofname.h, diseaselist.h */
#include "tagcat.h"

void kof_tagcat_init(struct kof_tagcat *c, struct kof_tagcat_tag *tag, uint32_t cap)
{
	c->tag = tag;
	c->cap = tag ? cap : 0u;
	c->n = 0u;
	c->rev = 0u;
	c->hash = NULL;
	c->hash_ud = NULL;
	c->clash[0] = 0;
}

void kof_tagcat_set_idhash(struct kof_tagcat *c, kof_catid_hash_fn hash, void *ud)
{
	c->hash = hash;
	c->hash_ud = ud;
}

uint32_t kof_tagcat_cap(const struct kof_tagcat *c)
{
	return c->cap;
}

const char *kof_tagcat_status_text(enum kof_tagcat_status st)
{
	switch (st) {
	case KOF_TAGCAT_OK:           return "ok";
	case KOF_TAGCAT_EMPTY:        return "the name is empty";
	case KOF_TAGCAT_TOO_LONG:     return "name is over 63 characters";
	case KOF_TAGCAT_BAD_CHAR:     return "letters, digits and - only";
	case KOF_TAGCAT_DUPLICATE:    return "that name is already used";
	case KOF_TAGCAT_NO_ACTIVITY:  return "Select at least one Activity";
	case KOF_TAGCAT_BAD_ACTIVITY: return "that activity is not selectable";
	case KOF_TAGCAT_BAD_OBJECT:   return "that object is not selectable";
	case KOF_TAGCAT_FULL:         return "the catalog is full";
	case KOF_TAGCAT_NO_TAG:       return "no such entry";
	case KOF_TAGCAT_ID_CLASH:     return "that name makes the id of another tag";
	case KOF_TAGCAT_BAD_COMMENT:  return kof_catcomment_text(KOF_CATCOMMENT_BAD_CHAR);
	case KOF_TAGCAT_COMMENT_TOO_LONG: return kof_catcomment_text(KOF_CATCOMMENT_TOO_LONG);
	}
	return "unknown status";
}

/* ---- the two lists: the engine's (diseaselist.h), values 1..COUNT-1 ---------------------------------------------------- */

uint32_t kof_tagcat_act_count(void)
{
	return (uint32_t)KOF_DISEASE_ACT_COUNT - 1u;
}

uint32_t kof_tagcat_act_value(uint32_t i)
{
	return i + 1u;
}

const char *kof_tagcat_act_name(uint32_t i)
{
	return kof_disease_act_name(kof_tagcat_act_value(i));
}

uint32_t kof_tagcat_obj_count(void)
{
	return (uint32_t)KOF_DISEASE_OBJ_COUNT - 1u;
}

uint32_t kof_tagcat_obj_value(uint32_t i)
{
	return i + 1u;
}

const char *kof_tagcat_obj_name(uint32_t i)
{
	return kof_disease_obj_name(kof_tagcat_obj_value(i));
}

static uint32_t mask_all(uint32_t n)
{
	uint32_t m = 0u, i;

	for (i = 0; i < n; i++)
		m |= 1u << (i + 1u);
	return m;
}

uint32_t kof_tagcat_act_mask_all(void)
{
	return mask_all(kof_tagcat_act_count());
}

uint32_t kof_tagcat_obj_mask_all(void)
{
	return mask_all(kof_tagcat_obj_count());
}

/* ---- the rules ------------------------------------------------------------------------------------------------------- */

enum kof_tagcat_status kof_tagcat_name_check(const char *name)
{
	if (!name || !name[0])
		return KOF_TAGCAT_EMPTY;
	if (strnlen(name, KOF_TAGCAT_NAME_MAX + 1u) > KOF_TAGCAT_NAME_MAX)
		return KOF_TAGCAT_TOO_LONG;
	return kof_tag_name_ok(name) ? KOF_TAGCAT_OK : KOF_TAGCAT_BAD_CHAR;
}

enum kof_tagcat_status kof_tagcat_comment_check(const char *comment)
{
	switch (kof_catcomment_check(comment)) {
	case KOF_CATCOMMENT_TOO_LONG: return KOF_TAGCAT_COMMENT_TOO_LONG;
	case KOF_CATCOMMENT_BAD_CHAR: return KOF_TAGCAT_BAD_COMMENT;
	default: break;
	}
	return KOF_TAGCAT_OK;
}

uint64_t kof_tagcat_id_at(const struct kof_tagcat *c, uint32_t idx)
{
	return idx < c->n ? kof_catid_of(c->hash, c->hash_ud, 'T', c->tag[idx].name, NULL) : 0u;
}

/* THE ONE NAME CHECK of add, rename and edit: the engine's rule, then no other tag (index `skip`, or UINT32_MAX for none, is the tag
 * being changed) with the same name ignoring letter case, then no other tag whose id the name would make (catstore.h; c->clash keeps
 * both names for kof_tagcat_why). */
static enum kof_tagcat_status tag_name_status(struct kof_tagcat *c, const char *name, uint32_t skip)
{
	enum kof_tagcat_status st = kof_tagcat_name_check(name);
	uint64_t id;
	uint32_t i;

	if (st != KOF_TAGCAT_OK)
		return st;
	for (i = 0; i < c->n; i++)
		if (i != skip && !strcasecmp(c->tag[i].name, name))
			return KOF_TAGCAT_DUPLICATE;
	id = kof_catid_of(c->hash, c->hash_ud, 'T', name, NULL);
	for (i = 0; i < c->n; i++)
		if (i != skip && kof_tagcat_id_at(c, i) == id) {
			snprintf(c->clash, sizeof c->clash, "id clash: \"%s\" and \"%s\" make the same id", name, c->tag[i].name);
			return KOF_TAGCAT_ID_CLASH;
		}
	return KOF_TAGCAT_OK;
}

const char *kof_tagcat_why(const struct kof_tagcat *c, enum kof_tagcat_status st)
{
	return st == KOF_TAGCAT_ID_CLASH && c->clash[0] ? c->clash : kof_tagcat_status_text(st);
}

static enum kof_tagcat_status acts_status(uint32_t acts)
{
	if (!acts)
		return KOF_TAGCAT_NO_ACTIVITY;
	return acts & ~kof_tagcat_act_mask_all() ? KOF_TAGCAT_BAD_ACTIVITY : KOF_TAGCAT_OK;
}

static enum kof_tagcat_status objs_status(uint32_t objs)
{
	return objs & ~kof_tagcat_obj_mask_all() ? KOF_TAGCAT_BAD_OBJECT : KOF_TAGCAT_OK;
}

static enum kof_tagcat_status sets_status(uint32_t acts, uint32_t objs)
{
	enum kof_tagcat_status st = acts_status(acts);

	return st != KOF_TAGCAT_OK ? st : objs_status(objs);
}

/* THE ONE CHECK of every field: the name (the tag at `skip` is the one being changed, UINT32_MAX for none), the sets, the comment. */
static enum kof_tagcat_status fields_status(struct kof_tagcat *c, const struct kof_tagcat_fields *f, uint32_t skip)
{
	enum kof_tagcat_status st = tag_name_status(c, f->name, skip);

	if (st == KOF_TAGCAT_OK)
		st = sets_status(f->acts, f->objs);
	return st != KOF_TAGCAT_OK ? st : kof_tagcat_comment_check(f->comment);
}

/* The text of a comment into a tag (the source may be the tag's own: a move). */
static void comment_put(char *dst, const char *comment)
{
	memmove(dst, comment ? comment : "", (comment ? strlen(comment) : 0u) + 1u);
}

static void touch(struct kof_tagcat *c)
{
	c->rev++;
}

/* THE ONE ADD: add and the loader (a file's block). */
static enum kof_tagcat_status put_tag(struct kof_tagcat *c, const struct kof_tagcat_fields *f, uint32_t *idx)
{
	enum kof_tagcat_status st = fields_status(c, f, UINT32_MAX);

	if (st != KOF_TAGCAT_OK)
		return st;
	if (c->n >= c->cap)
		return KOF_TAGCAT_FULL;
	memset(&c->tag[c->n], 0, sizeof c->tag[0]);
	memcpy(c->tag[c->n].name, f->name, strlen(f->name) + 1u);
	comment_put(c->tag[c->n].comment, f->comment);
	c->tag[c->n].acts = f->acts;
	c->tag[c->n].objs = f->objs;
	if (idx)
		*idx = c->n;
	c->n++;
	touch(c);
	return KOF_TAGCAT_OK;
}

enum kof_tagcat_status kof_tagcat_add_fields(struct kof_tagcat *c, const struct kof_tagcat_fields *f, uint32_t *idx)
{
	return put_tag(c, f, idx);
}

enum kof_tagcat_status kof_tagcat_add(struct kof_tagcat *c, const char *name, uint32_t acts, uint32_t objs, uint32_t *idx)
{
	struct kof_tagcat_fields f = { name, NULL, acts, objs };

	return put_tag(c, &f, idx);
}

enum kof_tagcat_status kof_tagcat_load_tag(struct kof_tagcat *c, const struct kof_tagcat_fields *f, uint32_t *idx)
{
	return put_tag(c, f, idx);
}

uint64_t kof_tagcat_id(const struct kof_tagcat *c, const char *name)
{
	uint32_t i;

	for (i = 0; name && i < c->n; i++)
		if (!strcasecmp(c->tag[i].name, name))
			return kof_tagcat_id_at(c, i);
	return 0u;
}

/* ---- the snapshot ----------------------------------------------------------------------------------------------------- */

enum kof_tagcat_status kof_tagcat_snapshot(const struct kof_tagcat *c, struct kof_tagcat *snap)
{
	if (c->n > snap->cap)
		return KOF_TAGCAT_FULL;
	memcpy(snap->tag, c->tag, (size_t)c->n * sizeof c->tag[0]);
	snap->n = c->n;
	touch(snap);
	return KOF_TAGCAT_OK;
}

enum kof_tagcat_status kof_tagcat_restore(struct kof_tagcat *c, const struct kof_tagcat *snap)
{
	return kof_tagcat_snapshot(snap, c);
}

/* By value, field by field: the bytes after a name's terminator are not part of the catalog. */
int kof_tagcat_dirty(const struct kof_tagcat *c, const struct kof_tagcat *snap)
{
	uint32_t i;

	if (c->n != snap->n)
		return 1;
	for (i = 0; i < c->n; i++)
		if (c->tag[i].acts != snap->tag[i].acts || c->tag[i].objs != snap->tag[i].objs ||
		    strcmp(c->tag[i].name, snap->tag[i].name) || strcmp(c->tag[i].comment, snap->tag[i].comment))
			return 1;
	return 0;
}

enum kof_tagcat_status kof_tagcat_edit_fields(struct kof_tagcat *c, uint32_t idx, const struct kof_tagcat_fields *f)
{
	enum kof_tagcat_status st;

	if (idx >= c->n)
		return KOF_TAGCAT_NO_TAG;
	st = fields_status(c, f, idx);
	if (st != KOF_TAGCAT_OK)
		return st;
	memmove(c->tag[idx].name, f->name, strlen(f->name) + 1u);   /* a rename passes the tag's own name */
	comment_put(c->tag[idx].comment, f->comment);
	c->tag[idx].acts = f->acts;
	c->tag[idx].objs = f->objs;
	touch(c);
	return KOF_TAGCAT_OK;
}

enum kof_tagcat_status kof_tagcat_edit(struct kof_tagcat *c, uint32_t idx, const char *name, uint32_t acts, uint32_t objs)
{
	struct kof_tagcat_fields f;

	if (idx >= c->n)
		return KOF_TAGCAT_NO_TAG;
	f.name = name;
	f.comment = c->tag[idx].comment;      /* the tag's own: unchanged */
	f.acts = acts;
	f.objs = objs;
	return kof_tagcat_edit_fields(c, idx, &f);
}

const char *kof_tagcat_comment(const struct kof_tagcat *c, uint32_t idx)
{
	return idx < c->n ? c->tag[idx].comment : "";
}

enum kof_tagcat_status kof_tagcat_set_comment(struct kof_tagcat *c, uint32_t idx, const char *comment)
{
	struct kof_tagcat_fields f;

	if (idx >= c->n)
		return KOF_TAGCAT_NO_TAG;
	f.name = c->tag[idx].name;
	f.comment = comment;
	f.acts = c->tag[idx].acts;
	f.objs = c->tag[idx].objs;
	return kof_tagcat_edit_fields(c, idx, &f);
}

enum kof_tagcat_status kof_tagcat_rename(struct kof_tagcat *c, uint32_t idx, const char *name)
{
	if (idx >= c->n)
		return KOF_TAGCAT_NO_TAG;
	return kof_tagcat_edit(c, idx, name, c->tag[idx].acts, c->tag[idx].objs);
}

enum kof_tagcat_status kof_tagcat_set_acts(struct kof_tagcat *c, uint32_t idx, uint32_t acts)
{
	if (idx >= c->n)
		return KOF_TAGCAT_NO_TAG;
	return kof_tagcat_edit(c, idx, c->tag[idx].name, acts, c->tag[idx].objs);
}

enum kof_tagcat_status kof_tagcat_set_objs(struct kof_tagcat *c, uint32_t idx, uint32_t objs)
{
	if (idx >= c->n)
		return KOF_TAGCAT_NO_TAG;
	return kof_tagcat_edit(c, idx, c->tag[idx].name, c->tag[idx].acts, objs);
}

enum kof_tagcat_status kof_tagcat_delete(struct kof_tagcat *c, uint32_t idx)
{
	if (idx >= c->n)
		return KOF_TAGCAT_NO_TAG;
	memmove(&c->tag[idx], &c->tag[idx + 1u], (size_t)(c->n - idx - 1u) * sizeof c->tag[0]);
	c->n--;
	touch(c);
	return KOF_TAGCAT_OK;
}

const struct kof_tagcat_tag *kof_tagcat_get(const struct kof_tagcat *c, uint32_t idx)
{
	return idx < c->n ? &c->tag[idx] : NULL;
}
