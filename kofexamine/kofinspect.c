/*
 * kofinspect.c - see kofinspect.h.
 *
 * WHY THIS RUNS THE MATCHER RATHER THAN READING A SCAN RESULT
 *
 * A scan is lazy on purpose: a module asks for a marker and the host answers,
 * memoised, so the only markers ever searched for are the ones some module's
 * logic reached. That is the right economics for scanning and the wrong shape
 * for this - the markers of a module whose first condition failed were never
 * looked for at all, and those are exactly the ones being asked about here.
 *
 * So this drives the matcher directly, over every marker the database declares.
 * It is affordable for the same reason the scan path is: the presence set answers
 * most markers with one hash of four bytes and never touches the object.
 *
 * kof_match_where rather than kof_match_lookup, and not for the offset alone.
 * lookup is memoised by (pattern, region) slot and returns "absent" outright when
 * no memo is attached - correct for the scan path that always attaches one, and a
 * silent wrong answer here. The ad-hoc entry points have no such dependency.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>

#include "kofinspect.h"
#include "../libkofeng/kofmatchers/kofmatch.h"
#include "../libkofeng/kofscanners/scan.h"

const char *kof_touch_kind_name(enum kof_touch_kind k)
{
	switch (k) {
	/* Not "every marker": the count beside it already says how many of how
	 * many, so the word would be the same fact twice and the two would have
	 * to agree. The kinds only have to name what a count cannot. */
	case KOF_TOUCH_COMPLETE:   return "markers";
	case KOF_TOUCH_PARTIAL:    return "some markers";
	case KOF_TOUCH_ELSEWHERE:  return "wrong region";
	case KOF_TOUCH_INELIGIBLE: return "did not run";
	}
	return "?";
}

/*
 * The preconditions, in the order the scan path applies them.
 *
 * Mirrored from kof_scan rather than reasoned out again: a module is ruled out
 * here exactly when it would have been ruled out there, or the "did not run"
 * answer is a guess about the engine rather than a report of it.
 */
static const char *ruled_out_by(const struct kof_module *m,
				const struct kof_obj_ctx *ctx, uint64_t size)
{
	if (!(m->target_mask & (1u << ctx->format)))
		return "targets another format";
	if (size < m->size_min)
		return "object is below its minimum size";
	if (m->arch_mask &&
	    (ctx->arch >= 32 || !(m->arch_mask & (1u << ctx->arch))))
		return "targets another architecture";
	if (m->subtype_mask &&
	    (ctx->subtype >= 32 || !(m->subtype_mask & (1u << ctx->subtype))))
		return "targets another kind of this format";
	return NULL;
}

/*
 * Where is this marker, searching the extents given?
 *
 * The first hit and not all of them: a viewer scrolls to one place, and a marker
 * that occurs forty times is not forty findings. KOF_BROKEN when it is in none of
 * them, which is the value the rest of this engine uses for "applies, but not
 * determined" and reads correctly as absent here.
 */
static uint64_t where_in(struct kof_match_ctx *m, const struct kof_range *ext,
			 uint32_t n_ext, const struct kof_touch_str *s)
{
	uint32_t i;

	for (i = 0; i < n_ext; i++) {
		uint64_t at = kof_match_where(m, ext[i].off, ext[i].len,
					      s->bytes, s->len, s->kind,
					      s->flags);
		if (at != KOF_BROKEN)
			return at;
	}
	return KOF_BROKEN;
}

/* Most interesting first; within a kind, the one with more markers present. */
static int cmp_touch(const void *a, const void *b)
{
	const struct kof_touch *x = a, *y = b;

	if (x->kind != y->kind)
		return (int)x->kind - (int)y->kind;
	if (x->n_in_rgn != y->n_in_rgn)
		return x->n_in_rgn < y->n_in_rgn ? 1 : -1;
	if (x->n_present != y->n_present)
		return x->n_present < y->n_present ? 1 : -1;
	return 0;
}

int kof_touch_object(struct kof_engine *eng, kof_buf buf,
		     const struct kof_obj_ctx *ctx,
		     struct kof_touch **out, uint32_t *n_out)
{
	struct kof_match_ctx m;
	struct kof_range *whole = NULL, *named = NULL;
	struct kof_touch *v = NULL;
	uint32_t n = 0, i, j, n_whole = 0;
	int ok = 0;

	*out = NULL;
	*n_out = 0;
	if (!eng || !eng->n_mods)
		return 1;

	/*
	 * A memo is deliberately not attached - see the note at the top - but the
	 * presence set is, because it is what makes asking about every marker in the
	 * database affordable rather than merely possible.
	 */
	memset(&m, 0, sizeof m);
	if (!kof_match_state_init(&m, eng->n_str, 0))
		return 0;
	kof_match_begin(&m, buf);

	whole = malloc(KOF_SCAN_MAX_EXTENTS * sizeof *whole);
	named = malloc(KOF_SCAN_MAX_EXTENTS * sizeof *named);
	v     = calloc(eng->n_mods, sizeof *v);
	if (!whole || !named || !v)
		goto out;

	/* The object entire, which is what "is this marker here at all" means. One
	 * extent in practice; resolved rather than assumed because KOF_SCAN_ALL is
	 * the host's answer and this should not have a second one. */
	n_whole = kof_scan_resolve_range(ctx, KOF_SCAN_ALL, whole);
	if (n_whole == 0 && buf.n) {
		/*
		 * Nothing identified the object, so the parse never set obj_size
		 * and the host's answer for KOF_SCAN_ALL is empty. The buffer is
		 * still the object, and an unrecognised blob full of a family's
		 * markers is one of the few things worth being told about - a
		 * memory dump, a carved payload, a stub nothing parses yet.
		 */
		whole[0].off = 0;
		whole[0].len = buf.n;
		n_whole = 1;
	}

	for (i = 0; i < eng->n_mods; i++) {
		const struct kof_module *mod = &eng->mods[i];
		struct kof_touch *t = &v[n];
		uint32_t n_named = 0;
		const char *why;

		memset(t, 0, sizeof *t);
		t->mod     = mod;
		t->maltype = mod->maltype;
		t->family  = kof_db_family(eng, mod);
		if (!t->family)
			t->family = "";
		t->n_str   = mod->n_str;

		if (mod->n_names) {
			t->name = calloc(mod->n_names, sizeof *t->name);
			if (!t->name)
				goto out;
			for (j = 0; j < mod->n_names; j++)
				t->name[j] = kof_db_name_at(eng, mod, j);
			t->n_names = mod->n_names;
		}

		why = ruled_out_by(mod, ctx, buf.n);

		/*
		 * A module ruled out still gets its markers looked for, because
		 * "all five of its markers are here and it targets the wrong
		 * format" is a real thing to see - a family ported, or a sample
		 * mis-identified. What it does not get is a region resolve: its
		 * regions belong to a format this object is not.
		 */
		if (!why)
			n_named = kof_scan_resolve_range(ctx, mod->scan_mask,
							 named);

		if (mod->n_str) {
			t->str = calloc(mod->n_str, sizeof *t->str);
			if (!t->str)
				goto out;
		}

		for (j = 0; j < mod->n_str; j++) {
			const struct kof_str_ent *e;
			struct kof_touch_str *s = &t->str[j];
			const uint8_t *bytes = NULL;

			e = kof_db_str(eng, mod, j, &bytes);
			if (!e || !bytes) {
				s->at = KOF_BROKEN;
				continue;
			}
			s->bytes = bytes;
			s->len   = e->len;
			s->kind  = e->kind;
			s->flags = e->flags;
			s->uid   = eng->packs[mod->pack_id].uid_base + e->uid;

			s->at = where_in(&m, whole, n_whole, s);
			if (s->at != KOF_BROKEN)
				t->n_present++;

			if (n_named && where_in(&m, named, n_named, s) !=
					KOF_BROKEN) {
				s->in_rgn = 1;
				t->n_in_rgn++;
			}
		}

		/* Not evidence, and at database scale it would be the whole list. */
		if (t->n_present == 0) {
			free(t->str);
			free((void *)t->name);
			t->str = NULL;
			t->name = NULL;
			continue;
		}

		if (why) {
			t->kind = KOF_TOUCH_INELIGIBLE;
			t->ruled_out = why;
		} else if (t->n_in_rgn == 0) {
			t->kind = KOF_TOUCH_ELSEWHERE;
		} else if (t->n_in_rgn == t->n_str) {
			t->kind = KOF_TOUCH_COMPLETE;
		} else {
			t->kind = KOF_TOUCH_PARTIAL;
		}
		n++;
	}

	if (n > 1)
		qsort(v, n, sizeof *v, cmp_touch);
	*out = v;
	*n_out = n;
	v = NULL;
	ok = 1;

out:
	if (v)
		kof_touch_free(v, eng->n_mods);
	free(whole);
	free(named);
	kof_match_state_free(&m);
	return ok;
}

void kof_touch_free(struct kof_touch *v, uint32_t n)
{
	uint32_t i;

	if (!v)
		return;
	for (i = 0; i < n; i++) {
		free(v[i].str);
		free((void *)v[i].name);
	}
	free(v);
}
