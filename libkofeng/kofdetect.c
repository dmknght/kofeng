/*
 * kofdetect.c - the detection questions a tool asks (kofeng.h, kdet_*).
 *
 * The API layer, like kofeng.c: it composes the public kdb_* and kscan_* calls and reaches no engine object. Nothing here runs
 * in a scan: kdet_info / kdet_diag read a result the scan delivered, kscan_explain is a scan the caller asked for.
 */

#include "kofeng.h"
#include "scanners/scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void kdet_info(const kof_engine *e, const struct kof_result *r, struct kdet_info *out)
{
	memset(out, 0, sizeof *out);
	if (!r || !r->has_verdict)
		return;
	out->has_verdict = 1;
	out->incomplete = r->verdict_incomplete;
	out->verdict = r->verdict.name;
	out->n_diag = r->verdict.n_diag;
	out->diag_total = r->verdict.diag_total;
	if (!r->cat.level)
		return;
	out->level = r->cat.level;
	out->cover = r->cat.cover;
	out->jaccard = r->cat.jaccard;
	out->groups = r->cat.n_groups;
	out->fired = r->cat.n_fired;
	out->cut = r->cat.cut;
	kdb_family_name(e, r->cat.family_id, out->family, sizeof out->family);
	kdb_variant_name(e, r->cat.variant_id, out->variant, sizeof out->variant);
	kdb_tag_name(e, r->cat.tag_id, out->tag, sizeof out->tag);
}

int kdet_diag_of(const kof_engine *e, uint32_t id, struct kdet_diag *out)
{
	memset(out, 0, sizeof *out);
	out->id = id;
	out->name = kdb_diagnose_name(e, id);
	out->disease = kdb_diagnose_disease(e, id);
	out->type = kdb_diagnose_type(e, id);
	out->has_catalog = kdb_diagnose_family(e, id) != 0;
	kdb_family_name(e, kdb_diagnose_family(e, id), out->family, sizeof out->family);
	kdb_variant_name(e, kdb_diagnose_variant(e, id), out->variant, sizeof out->variant);
	kdb_tag_name(e, kdb_diagnose_tag(e, id), out->tag, sizeof out->tag);
	out->has_form = kdb_diagnose_form(e, id, &out->form);
	out->kind = !out->name ? 0 : out->has_form ? KDET_KIND_FORM : KDET_KIND_GRAPH;
	if (out->has_form)
		(void)kdb_diagnose_form_expr(e, id, out->expr, sizeof out->expr);
	return out->name != NULL;
}

int kdet_diag(const kof_engine *e, const struct kof_result *r, uint32_t i, struct kdet_diag *out)
{
	if (!r || !r->has_verdict || i >= r->verdict.n_diag) {
		memset(out, 0, sizeof *out);
		return 0;
	}
	(void)kdet_diag_of(e, r->verdict.diag[i], out);
	return 1;                /* the verdict lists it, held by the database or not (name NULL then) */
}

int kdet_matcher_text(const struct kof_diag_match *x, char *out, size_t cap)
{
	if (!out || !cap)
		return KDET_M_NOT_ASKED;
	out[0] = 0;
	if (!x)
		return KDET_M_NOT_ASKED;
	if (x->result == KDET_M_NOT_ASKED)
		snprintf(out, cap, "not asked (the expression did not need it)");
	else if (x->kind == KDET_M_SIMILAR)
		snprintf(out, cap, "similarity %u%% of the %u block(s), %u%% demanded", (unsigned)x->pct, (unsigned)x->n, (unsigned)x->need);
	else
		snprintf(out, cap, "%u of %u marker(s) found, regions %#x", (unsigned)x->found, (unsigned)x->n, (unsigned)x->mask);
	return x->result;
}

int kdet_part_text(const struct kof_diag_part *p, char *out, size_t cap)
{
	char reg[24], where[96];

	if (!out || !cap)
		return 0;
	out[0] = 0;
	if (!p)
		return 0;
	if (p->mask_name)
		snprintf(reg, sizeof reg, "%s", p->mask_name);
	else
		snprintf(reg, sizeof reg, "%#x", (unsigned)p->mask);
	if (p->kind == KDET_P_MARKER) {
		if (p->place)
			snprintf(out, cap, "marker %u found at %#llx (%u bytes)", (unsigned)p->id, (unsigned long long)p->off, (unsigned)p->n);
		else if (p->hit)
			snprintf(out, cap, "marker %u found in %s (no offset: not a place in the file)", (unsigned)p->id, reg);
		else
			snprintf(out, cap, "marker %u not found in %s", (unsigned)p->id, reg);
		return p->hit;
	}
	if (p->place)
		snprintf(where, sizeof where, "place %#llx +%llu in %s%s%s holds %u", (unsigned long long)p->off, (unsigned long long)p->plen,
			 p->region_name ? p->region_name : "?", p->func[0] ? ", " : "", p->func, (unsigned)p->place_hits);
	else
		snprintf(where, sizeof where, "no unit of the object holds any of it");
	snprintf(out, cap, "block %08x %s: holds %u of %u hashes (%u%%), cut from %s; %s", (unsigned)p->id, p->hit ? "yes" : "no",
		 (unsigned)p->matched, (unsigned)p->n, (unsigned)p->pct, reg, where);
	return p->hit;
}

struct kdet_run {
	struct kdet_object *obj;
	struct kof_diag_report **rep;      /* the owned copy of each object's report, parallel to obj */
	char **own;                        /* the owned copy of each object's name, parallel to obj */
	uint32_t n, cap, status;
};

/* One object of the scan: a copy of what the callback lends, with the borrowed pointers cut. */
static int collect(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct kdet_run *run = user;
	struct kdet_object *o;
	struct kof_diag_report *rep = NULL;

	(void)bytes;
	(void)len;
	if (run->n == run->cap) {
		uint32_t nc = run->cap ? run->cap * 2u : 16u;
		struct kdet_object *no = realloc(run->obj, nc * sizeof *no);
		struct kof_diag_report **nr;

		if (!no) {
			run->status |= KDET_RUN_NOMEM;
			return 1;
		}
		run->obj = no;
		nr = realloc(run->rep, nc * sizeof *nr);
		if (!nr) {
			run->status |= KDET_RUN_NOMEM;
			return 1;
		}
		run->rep = nr;
		{
			char **ow = realloc(run->own, nc * sizeof *ow);

			if (!ow) {
				run->status |= KDET_RUN_NOMEM;
				return 1;
			}
			run->own = ow;
		}
		run->cap = nc;
	}
	if (res->n_diag && res->diag) {
		rep = malloc(res->n_diag * sizeof *rep);
		if (!rep) {
			run->status |= KDET_RUN_NOMEM;
			return 1;
		}
		memcpy(rep, res->diag, res->n_diag * sizeof *rep);
	}
	o = &run->obj[run->n];
	run->own[run->n] = malloc(strlen(name) + 1u);
	if (!run->own[run->n]) {
		free(rep);
		run->status |= KDET_RUN_NOMEM;
		return 1;
	}
	strcpy(run->own[run->n], name);
	o->name = run->own[run->n];
	o->res = *res;
	o->res.syms = NULL;
	o->res.n_syms = 0;
	o->res.fixed = NULL;
	o->res.n_fixed = 0;
	o->res.packer_build = NULL;
	o->res.opened_by = NULL;
	o->res.diag = rep;
	run->rep[run->n] = rep;
	run->n++;
	return 0;
}

kdet_run *kscan_explain(kof_scanner *sc, const void *bytes, uint64_t n, const char *name, const struct kof_scan_option *base)
{
	struct kof_scan_option opt;
	struct kdet_run *run;
	int rc;

	if (!sc || !bytes || !name)
		return NULL;
	run = calloc(1, sizeof *run);
	if (!run)
		return NULL;
	if (base)
		opt = *base;
	else
		memset(&opt, 0, sizeof opt);
	if (!kof_scan_set_explain(sc, 1)) {
		run->status |= KDET_RUN_NOMEM;   /* the budget refused the report's tables: an empty run says so, it does not guess */
		return run;
	}
	opt.reader = 1;
	rc = kscan_bytes(sc, bytes, n, name, &opt, collect, run);
	(void)kof_scan_set_explain(sc, 0);
	if (rc < 0)
		run->status |= KDET_RUN_SCAN_ERR;
	return run;
}

uint32_t kdet_run_count(const kdet_run *run)
{
	return run ? run->n : 0;
}

const struct kdet_object *kdet_run_at(const kdet_run *run, uint32_t i)
{
	return run && i < run->n ? &run->obj[i] : NULL;
}

const struct kdet_object *kdet_run_find(const kdet_run *run, const char *name)
{
	uint32_t i;

	for (i = 0; run && name && i < run->n; i++)
		if (!strcmp(run->obj[i].name, name))
			return &run->obj[i];
	return NULL;
}

const struct kdet_object *kdet_run_verdict(const kdet_run *run)
{
	uint32_t i;

	for (i = 0; run && i < run->n; i++)
		if (run->obj[i].res.has_verdict)
			return &run->obj[i];
	return NULL;
}

static int kdet_has_match(const struct kof_result *r)
{
	uint32_t i;

	for (i = 0; r->diag && i < r->n_diag; i++)
		if (r->diag[i].state == KOF_DIAG_ST_MATCH)
			return 1;
	return 0;
}

const struct kof_diag_report *kdet_run_decided(const kdet_run *run, const struct kdet_object *obj, uint32_t *n)
{
	*n = 0;
	if (!obj)
		return NULL;
	if (!kdet_has_match(&obj->res) && !strstr(obj->name, KOF_OBJ_SEP)) {
		obj = kdet_run_verdict(run);
		if (!obj)
			return NULL;
	}
	if (!kdet_has_match(&obj->res))
		return NULL;
	*n = obj->res.n_diag;
	return obj->res.diag;
}

const struct kof_diag_part *kdet_block_part(const struct kof_diag_report *diag, uint32_t n, uint32_t block_id, const struct kof_diag_report **from)
{
	uint32_t i, j;

	for (i = 0; diag && i < n; i++) {
		if (diag[i].state != KOF_DIAG_ST_MATCH || !diag[i].form)
			continue;
		for (j = 0; j < diag[i].n_part; j++)
			if (diag[i].part[j].kind == KDET_P_BLOCK && diag[i].part[j].hit && diag[i].part[j].place && diag[i].part[j].unit_id == block_id) {
				if (from)
					*from = &diag[i];
				return &diag[i].part[j];
			}
	}
	return NULL;
}

unsigned kdet_part_need(const struct kof_diag_report *from, const struct kof_diag_part *part)
{
	if (!from || !part || part->matcher >= KOF_DIAG_REPORT_MATCH || part->matcher >= from->n_match_total)
		return 0;
	return from->match[part->matcher].need;
}

uint32_t kdet_run_status(const kdet_run *run)
{
	return run ? run->status : 0;
}

void kdet_run_free(kdet_run *run)
{
	uint32_t i;

	if (!run)
		return;
	for (i = 0; i < run->n; i++) {
		free(run->rep[i]);
		free(run->own[i]);
	}
	free(run->rep);
	free(run->own);
	free(run->obj);
	free(run);
}
