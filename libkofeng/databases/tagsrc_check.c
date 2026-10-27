/*
 * SWITCHED OFF (owner, 2026-10-27): the Syndrome table and its tag-source backend (kofexamine/kv_syn.c, kv_syntable.c,
 * libkofeng/databases/tagsrc*, ksigbuilder/ksb_tags.c) stay in the tree and are to be removed later, when asked. The menu item
 * is Manage > Syndromes, listed and greyed. Do not extend this code.
 */
/*
 * tagsrc_check.c - the rules a set of tag sources must keep. See tagsrc.h.
 *
 * One function, for the viewer's Check and for `ksigbuilder --tags`, so what
 * one calls an error the other calls an error.
 */

#include "tagsrc_int.h"
#include <stdarg.h>

struct ck {
	const struct kof_tagsrc_report *r;
	int                             errs;
};

static const char *base_of(const char *path)
{
	const char *s = strrchr(path, '/');

	return s ? s + 1 : path;
}

static void ck_say(struct ck *c, int level, const char *subject,
		   const char *fmt, ...)
{
	char m[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(m, sizeof m, fmt, ap);
	va_end(ap);
	if (level == KOF_TAGSRC_ERROR)
		c->errs++;
	if (c->r && c->r->say)
		c->r->say(c->r->ud, level, subject, m);
}

/* The two sets hold the same ids, in whatever order. */
static int same_ids(const uint64_t *a, uint32_t n, const uint64_t *b,
		    uint32_t m)
{
	uint32_t i, j, hit = 0;

	if (n != m)
		return 0;
	for (i = 0; i < n; i++) {
		for (j = 0; j < m && b[j] != a[i]; j++)
			;
		hit += j < m;
	}
	return hit == n;
}

static const char *relation(const uint64_t *a, uint32_t n, const uint64_t *b,
			    uint32_t m)
{
	uint32_t i, j, inter = 0;

	for (i = 0; i < n; i++)
		for (j = 0; j < m; j++)
			inter += a[i] == b[j];
	if (inter == n && n == m)
		return "equal";
	if (inter == n || inter == m)
		return "subset";
	return inter ? "overlap" : "disjoint";
}

/* Two names one edit apart: one character changed, added or dropped. */
static int one_edit(const char *a, const char *b)
{
	size_t la = strlen(a), lb = strlen(b), i = 0;

	if (la > lb + 1u || lb > la + 1u || !strcmp(a, b))
		return 0;
	while (i < la && i < lb && a[i] == b[i])
		i++;
	if (la == lb)
		return !strcmp(a + i + 1u, b + i + 1u);
	if (la > lb)
		return !strcmp(a + i + 1u, b + i);
	return !strcmp(a + i, b + i + 1u);
}

static void subject_of(const struct kof_tagent *e, char *out, size_t cap)
{
	snprintf(out, cap, "%s", base_of(e->path));
}

/* The rules about one entity alone. */
static void ck_entity(struct ck *c, const struct kof_tagset *s,
		      const struct kof_tagent *e, const char *sub)
{
	uint32_t i;

	if (!e->name[0])
		ck_say(c, KOF_TAGSRC_ERROR, sub, "empty name");
	else if (!kof_tagsrc_name_ok(e->name))
		ck_say(c, KOF_TAGSRC_ERROR, sub, "bad characters in the name "
		       "\"%s\": lower case a-z, 0-9 and '-' only", e->name);
	if (e->kind != KOF_TAGSRC_K_TAG)
		return;
	if (!e->n_act && !e->n_typ)
		ck_say(c, KOF_TAGSRC_ERROR, sub, "tag \"%s\" has neither an "
		       "activity nor a type", e->name);
	for (i = 0; i < e->n_act; i++)
		if (!kof_tagset_find(s, KOF_TAGSRC_K_ACTIVITY, e->act[i]))
			ck_say(c, KOF_TAGSRC_ERROR, sub, "tag \"%s\" names an "
			       "activity that does not exist: 0x%016llx",
			       e->name, (unsigned long long)e->act[i]);
	for (i = 0; i < e->n_typ; i++)
		if (!kof_tagset_find(s, KOF_TAGSRC_K_TYPE, e->typ[i]))
			ck_say(c, KOF_TAGSRC_ERROR, sub, "tag \"%s\" names a "
			       "type that does not exist: 0x%016llx", e->name,
			       (unsigned long long)e->typ[i]);
	if (e->has_fam && !kof_tagset_find(s, KOF_TAGSRC_K_FAMILY, e->fam))
		ck_say(c, KOF_TAGSRC_ERROR, sub, "tag \"%s\" names a family "
		       "that does not exist: 0x%016llx", e->name,
		       (unsigned long long)e->fam);
}

/* Two tags that share a name: one meaning twice, or how they differ. */
static void ck_pair(struct ck *c, const struct kof_tagent *a,
		    const struct kof_tagent *b)
{
	char sub[KOF_TAGSRC_PATH];

	snprintf(sub, sizeof sub, "%s", base_of(b->path));
	if (same_ids(a->act, a->n_act, b->act, b->n_act) &&
	    same_ids(a->typ, a->n_typ, b->typ, b->n_typ) &&
	    a->has_fam == b->has_fam && (!a->has_fam || a->fam == b->fam)) {
		ck_say(c, KOF_TAGSRC_WARN, sub, "tag \"%s\" says the same as "
		       "%s (same activities, types and family) under another "
		       "id", b->name, base_of(a->path));
		return;
	}
	ck_say(c, KOF_TAGSRC_INFO, sub, "name shared with %s: type sets %s",
	       base_of(a->path), relation(a->typ, a->n_typ, b->typ, b->n_typ));
}

int kof_tagset_check(struct kof_tagset *s, const struct kof_tagsrc_report *r)
{
	struct ck c;
	size_t i, j;
	char sub[KOF_TAGSRC_PATH];

	c.r = r;
	c.errs = 0;
	kof_tagset_count(s);
	for (i = 0; i < s->n_prob; i++)
		ck_say(&c, KOF_TAGSRC_ERROR, s->prob[i].file, "%s",
		       s->prob[i].msg);
	for (i = 0; i < s->n; i++) {
		const struct kof_tagent *e = &s->e[i];

		if (e->removed)
			continue;
		subject_of(e, sub, sizeof sub);
		for (j = 0; j < i; j++)
			if (!s->e[j].removed && s->e[j].id == e->id)
				ck_say(&c, KOF_TAGSRC_ERROR, sub, "duplicate "
				       "id 0x%016llx (also %s)",
				       (unsigned long long)e->id,
				       base_of(s->e[j].path));
		ck_entity(&c, s, e, sub);
		if (e->kind != KOF_TAGSRC_K_TAG && !e->used)
			ck_say(&c, KOF_TAGSRC_WARN, sub, "%s \"%s\" is used by "
			       "no tag", kof_tagsrc_kind_word(e->kind),
			       e->name);
		for (j = 0; j < i; j++) {
			const struct kof_tagent *o = &s->e[j];

			if (o->removed || o->kind != e->kind)
				continue;
			if (e->kind == KOF_TAGSRC_K_TAG &&
			    !strcmp(o->name, e->name))
				ck_pair(&c, o, e);
			else if (one_edit(o->name, e->name))
				ck_say(&c, KOF_TAGSRC_WARN, sub, "names \"%s\" "
				       "and \"%s\" of %s are one edit apart: "
				       "one of them may be a typo", o->name,
				       e->name, kof_tagsrc_kind_word(e->kind));
		}
	}
	return c.errs;
}
