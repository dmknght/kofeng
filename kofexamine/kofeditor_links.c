#define _GNU_SOURCE

/*
 * kofeditor_links.c - the link between a unit of the draft and a file already in the tree: which are loaded, which removed, and the verb that links one.
 *
 * A part of the diagnose panel's draft model (see kofeditor.h for why it is apart from
 * the viewer); the types and what the parts share are in kofeditor_private.h.
 * Moved verbatim from kofeditor.c.
 */

#include "kofeditor_private.h"


uint32_t *kofeditor_unit_link_of(struct kof_editor *e, const struct draft_unit *u)
{
	return u->is_grp ? &e->dr.grp[u->idx].link : &e->dr.cnd[u->idx].link;
}

/* The loaded entry of id `id`, or -1. */
int kofeditor_loaded_find(const struct kof_editor *e, uint32_t id)
{
	uint32_t i;

	for (i = 0; id && i < e->dr.n_loaded; i++)
		if (e->dr.loaded[i].id == id)
			return (int)i;
	return -1;
}

/* How many matchers and conditions of the draft carry the link `id` (every one, a unit or not). */
uint32_t kofeditor_link_carriers(const struct kof_editor *e, uint32_t id)
{
	uint32_t i, n = 0;

	for (i = 0; i < e->dr.n_grp; i++)
		n += id && e->dr.grp[i].link == id;
	for (i = 0; i < e->dr.n_cnd; i++)
		n += id && e->dr.cnd[i].link == id;
	return n;
}

void draft_links_reset(struct kof_editor *e)
{
	uint32_t i;

	for (i = 0; i < MAX_GROUP; i++) {
		e->dr.grp[i].link = 0;
		e->dr.cnd[i].link = 0;
	}
	memset(e->dr.loaded, 0, sizeof e->dr.loaded);
	e->dr.n_loaded = 0;
}

uint32_t draft_unit_link(const struct kof_editor *e, int is_grp, uint32_t idx)
{
	if (is_grp)
		return idx < e->dr.n_grp ? e->dr.grp[idx].link : 0u;
	return idx < e->dr.n_cnd ? e->dr.cnd[idx].link : 0u;
}

uint32_t draft_links_loaded(const struct kof_editor *e)
{
	return e->dr.n_loaded;
}

uint32_t draft_links_removed(const struct kof_editor *e)
{
	uint32_t i, n = 0;

	for (i = 0; i < e->dr.n_loaded; i++)
		n += !kofeditor_link_carriers(e, e->dr.loaded[i].id);
	return n;
}

/*
 * LINK UNIT (is_grp, idx) TO THE DIAGNOSE `name` it was loaded from - only when the draft says EXACTLY what that file says: the unit is
 * regenerated from the loaded state and compared with the file by the builder's identity (kof_dsrc_view_same). A diagnose the panel
 * cannot represent whole (several matchers, an expression written by hand, a threshold or block that differs) therefore never gets a link, and
 * what has no link is never modified or deleted. The file must be a regular file of the tree (no symlink), named `name`.c and carrying that
 * name. Refused too: a unit that is already linked, a name another unit carries, a full list. 1 when linked, else 0.
 */
int draft_link_unit(struct kof_editor *e, int is_grp, uint32_t idx, const char *dir, uint32_t did, const char *name)
{
	struct draft_unit ul[DRAFT_UNIT_MAX];
	struct kof_dsrc *d = NULL, *old = NULL, *cand = NULL;
	struct draft_loaded id;
	char *have = NULL;
	size_t on = 0;
	mode_t mode;
	int k, linked = 0;

	if (!did || !kofeditor_link_name_ok(name) || e->dr.n_loaded >= DRAFT_LOADED_MAX || kofeditor_link_carriers(e, did) || kofeditor_loaded_find(e, did) >= 0)
		return 0;
	(void)draft_units(e, ul, DRAFT_UNIT_MAX);
	k = draft_unit_find(e, is_grp, idx);
	if (k < 0 || draft_unit_link(e, is_grp, idx))
		return 0;
	d = calloc(1, sizeof *d);
	old = calloc(1, sizeof *old);
	cand = calloc(1, sizeof *cand);
	have = d && old && cand ? kofeditor_tree_file(dir, name, &on, &mode) : NULL;
	memset(&id, 0, sizeof id);
	if (have && kofeditor_unit_in_file(e, name, ul, (uint32_t)k, have, on, 1, d, old, cand, &id) && !strcmp(id.name, name)) {
		*kofeditor_unit_link_of(e, &ul[k]) = did;
		id.id = did;
		e->dr.loaded[e->dr.n_loaded++] = id;
		linked = 1;
	}
	free(have);
	free(d);
	free(old);
	free(cand);
	return linked;
}
