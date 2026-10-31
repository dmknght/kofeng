/*
 * catnames.c - the id -> name table of an engine (catnames.h). The catalogs' own loaders read the files; this file sizes the tables
 * against the budget, keeps the result and spells ids.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../kofcore/kofbudget.h"
#include "../kofcore/kofdebug.h"
#include "../kofcore/kofmod/kofname.h"
#include "catnames.h"
#include "catstore.h"
#include "famcat.h"
#include "tagcat.h"
#include "verdict.h"

/* One row of an id -> item table: the id the catalog's ONE id function (catstore.h) makes from the item's name, and the item's index.
 * The tables are built once, when the catalogs are loaded, and sorted by id: a lookup is a binary search, never a re-hash of the names. */
struct cn_ent {
	uint64_t id;
	uint32_t idx;
};

struct kof_catnames {
	struct kof_famcat fams;
	struct kof_tagcat tags;
	struct cn_ent *fam_tab, *var_tab, *tag_tab;   /* n_fam, n_var, n tags rows */
	struct kof_catnames_info info;
	uint64_t charged;
	kof_catnames_fallback fb;
	const void *fb_ctx;
};

static uint64_t fam_bytes(uint32_t nf, uint32_t nv)
{
	return (uint64_t)nf * (sizeof(struct kof_famcat_fam) + sizeof(struct cn_ent)) +
	       (uint64_t)nv * (sizeof(struct kof_famcat_var) + sizeof(struct cn_ent));
}

static uint64_t tag_bytes(uint32_t nt)
{
	return (uint64_t)nt * (sizeof(struct kof_tagcat_tag) + sizeof(struct cn_ent));
}

static int ent_cmp(const void *a, const void *b)
{
	const struct cn_ent *x = a, *y = b;

	return x->id < y->id ? -1 : x->id > y->id;
}

/* The sorted table of n ids, id_at(c, i) for i < n; NULL for n == 0 and when the allocation fails (*fail set). */
static struct cn_ent *build_tab(const void *c, uint32_t n, uint64_t (*id_at)(const void *c, uint32_t i), int *fail)
{
	struct cn_ent *t;
	uint32_t i;

	if (!n)
		return NULL;
	t = malloc((size_t)n * sizeof *t);
	if (!t) {
		*fail = 1;
		return NULL;
	}
	for (i = 0; i < n; i++) {
		t[i].id = id_at(c, i);
		t[i].idx = i;
	}
	qsort(t, n, sizeof *t, ent_cmp);
	return t;
}

static const struct cn_ent *find_ent(const struct cn_ent *t, uint32_t n, uint64_t id)
{
	struct cn_ent key;

	key.id = id;
	key.idx = 0u;
	return id && t ? bsearch(&key, t, n, sizeof *t, ent_cmp) : NULL;
}

static uint64_t fam_at(const void *c, uint32_t i) { return kof_famcat_fam_id_at(c, i); }
static uint64_t var_at(const void *c, uint32_t i) { return kof_famcat_var_id_at(c, i); }
static uint64_t tag_at(const void *c, uint32_t i) { return kof_tagcat_id_at(c, i); }

static void free_tabs(struct kof_catnames *n)
{
	free(n->fam_tab);
	free(n->var_tab);
	free(n->tag_tab);
	n->fam_tab = n->var_tab = n->tag_tab = NULL;
}

/*
 * ONE CATALOG, SIZED BEFORE IT IS READ. The catalogs' loaders fill a table the caller owns and refuse a file that does not fit, so the
 * table is sized from what the directory holds: kof_catstore_dir_size says how many files and bytes, and no item is shorter than the
 * least a block can be written in (a tag block is at least 48 bytes, a variant line at least 32, a family is a file), which bounds the
 * count from above. That bound is then cut to what the budget grants (`room`); a file that does not fit what is left is refused by the
 * loader and counted, and the cut is said (OVER_BUDGET with the number of files not read). When the bound was too generous (comments are
 * bytes that hold no item) the table is trimmed to what was read before it is charged, so the budget pays for the names and not for the
 * bound.
 */
#define TAG_MIN_BYTES 48u
#define VAR_MIN_BYTES 32u

static void *trim(void *p, uint32_t n, size_t each)
{
	void *q = realloc(p, (n ? n : 1u) * each);

	return q ? q : p;
}

static uint32_t load_fams(struct kof_catnames *n, const char *dir, uint64_t room)
{
	struct kof_catstore *st;
	struct kof_famcat_fam *fam;
	struct kof_famcat_var *var;
	struct kof_famcat c;
	uint64_t bytes;
	uint32_t files, nf, nv, flags = 0;
	int reduced = 0;

	if (kof_catstore_dir_size(dir, &bytes, &files) != KOF_CATSTORE_IO_OK)
		return KOF_CATNAMES_UNREADABLE;
	if (!files)
		return 0;
	nf = files < KOF_CATSTORE_FILES_MAX ? files : KOF_CATSTORE_FILES_MAX;
	nv = (uint32_t)(bytes / VAR_MIN_BYTES) + 1u;
	if (fam_bytes(nf, nv) > room) {
		reduced = 1;
		const uint64_t fam_row = sizeof *fam + sizeof(struct cn_ent), var_row = sizeof *var + sizeof(struct cn_ent);

		if ((uint64_t)nf * 2u * fam_row > room)
			nf = (uint32_t)(room / (2u * fam_row));
		nv = (uint32_t)((room - (uint64_t)nf * fam_row) / var_row);
	}
	if (files > KOF_CATSTORE_FILES_MAX) {
		n->info.files_refused += files - KOF_CATSTORE_FILES_MAX;      /* the loader reads the first 256 by name */
		flags |= KOF_CATNAMES_FILES_REFUSED;
	}
	if (!nf || !nv) {
		n->info.files_refused += files;
		return flags | KOF_CATNAMES_OVER_BUDGET | KOF_CATNAMES_FILES_REFUSED;
	}
	st = calloc(1, sizeof *st);
	fam = calloc(nf, sizeof *fam);
	var = calloc(nv, sizeof *var);
	if (!st || !fam || !var) {
		free(st);
		free(fam);
		free(var);
		return flags | KOF_CATNAMES_NOMEM;
	}
	kof_famcat_init(&c, fam, nf, var, nv);
	if (kof_famcat_load(&c, st, dir) != KOF_CATSTORE_IO_OK) {
		free(st);
		free(fam);
		free(var);
		return flags | KOF_CATNAMES_UNREADABLE;
	}
	if (st->n_bad) {
		flags |= KOF_CATNAMES_FILES_REFUSED | (reduced ? KOF_CATNAMES_OVER_BUDGET : 0u);
		n->info.files_refused += st->n_bad;
	}
	/* Keep what was read, trimmed: the budget is charged for the names and not for the bound. */
	c.fam = trim(fam, c.n_fam, sizeof *fam);
	c.var = trim(var, c.n_var, sizeof *var);
	c.cap_fam = c.n_fam;
	c.cap_var = c.n_var;
	n->fams = c;
	free(st);
	return flags;
}

static uint32_t load_tags(struct kof_catnames *n, const char *dir, uint64_t room)
{
	struct kof_catstore *st;
	struct kof_tagcat_tag *tag;
	struct kof_tagcat c;
	uint64_t bytes;
	uint32_t files, nt, flags = 0;
	int reduced = 0;

	if (kof_catstore_dir_size(dir, &bytes, &files) != KOF_CATSTORE_IO_OK)
		return KOF_CATNAMES_UNREADABLE;
	if (!files)
		return 0;
	nt = (uint32_t)(bytes / TAG_MIN_BYTES) + 1u;
	if (tag_bytes(nt) > room) {
		reduced = 1;
		nt = (uint32_t)(room / (sizeof *tag + sizeof(struct cn_ent)));
	}
	if (files > KOF_CATSTORE_FILES_MAX) {
		n->info.files_refused += files - KOF_CATSTORE_FILES_MAX;
		flags |= KOF_CATNAMES_FILES_REFUSED;
	}
	if (!nt) {
		n->info.files_refused += files;
		return flags | KOF_CATNAMES_OVER_BUDGET | KOF_CATNAMES_FILES_REFUSED;
	}
	st = calloc(1, sizeof *st);
	tag = calloc(nt, sizeof *tag);
	if (!st || !tag) {
		free(st);
		free(tag);
		return flags | KOF_CATNAMES_NOMEM;
	}
	kof_tagcat_init(&c, tag, nt);
	if (kof_tagcat_load(&c, st, dir) != KOF_CATSTORE_IO_OK) {
		free(st);
		free(tag);
		return flags | KOF_CATNAMES_UNREADABLE;
	}
	if (st->n_bad) {
		flags |= KOF_CATNAMES_FILES_REFUSED | (reduced ? KOF_CATNAMES_OVER_BUDGET : 0u);
		n->info.files_refused += st->n_bad;
	}
	c.tag = trim(tag, c.n, sizeof *tag);
	c.cap = c.n;
	n->tags = c;
	free(st);
	return flags;
}

kof_catnames *kof_catnames_load(const char *pathogens, const char *syndromes, struct kof_budget *b, struct kof_catnames_info *info)
{
	struct kof_catnames *n = calloc(1, sizeof *n);
	uint64_t room;
	uint32_t f;

	if (!n || (b && !kof_budget_charge(b, sizeof *n))) {
		free(n);
		if (info) {
			memset(info, 0, sizeof *info);
			info->flags = KOF_CATNAMES_NOMEM;
		}
		return NULL;
	}
	n->charged = sizeof *n;
	/* No catalog yet: an empty one, so a lookup never meets a NULL array. */
	kof_famcat_init(&n->fams, NULL, 0, NULL, 0);
	kof_tagcat_init(&n->tags, NULL, 0);
	room = KOF_CATNAMES_MAX_BYTES;
	if (b) {
		uint64_t r = kof_budget_ask(b, room);

		room = r / 8u < room ? r / 8u : room;
	}
	/* The allowance is one number for both catalogs: the second asks for what the first kept. */
	if (pathogens && pathogens[0]) {
		f = load_fams(n, pathogens, room);
		n->info.flags |= f;
		room -= fam_bytes(n->fams.cap_fam, n->fams.cap_var) < room ? fam_bytes(n->fams.cap_fam, n->fams.cap_var) : room;
	}
	if (syndromes && syndromes[0])
		n->info.flags |= load_tags(n, syndromes, room);
	n->info.families = n->fams.n_fam;
	n->info.variants = n->fams.n_var;
	n->info.tags = n->tags.n;
	{
		int fail = 0;

		n->fam_tab = build_tab(&n->fams, n->fams.n_fam, fam_at, &fail);
		n->var_tab = build_tab(&n->fams, n->fams.n_var, var_at, &fail);
		n->tag_tab = build_tab(&n->tags, n->tags.n, tag_at, &fail);
		if (fail) {
			/* No table, no names from either catalog, said (the same answer as a budget that moved). */
			free_tabs(n);
			free(n->fams.fam);
			free(n->fams.var);
			free(n->tags.tag);
			kof_famcat_init(&n->fams, NULL, 0, NULL, 0);
			kof_tagcat_init(&n->tags, NULL, 0);
			n->info.families = n->info.variants = n->info.tags = 0;
			n->info.flags |= KOF_CATNAMES_NOMEM;
		}
	}
	{
		uint64_t held = fam_bytes(n->fams.cap_fam, n->fams.cap_var) + tag_bytes(n->tags.cap);

		if (b && held && !kof_budget_charge(b, held)) {
			/* The budget moved under us (another thread took it): no names from either catalog, said. */
			free_tabs(n);
			free(n->fams.fam);
			free(n->fams.var);
			free(n->tags.tag);
			kof_famcat_init(&n->fams, NULL, 0, NULL, 0);
			kof_tagcat_init(&n->tags, NULL, 0);
			n->info.families = n->info.variants = n->info.tags = 0;
			n->info.flags |= KOF_CATNAMES_NOMEM;
			held = 0;
		}
		n->charged += held;
	}
	n->info.bytes = n->charged;
	KOF_TRACE("[mem] catalog table built: %u family(ies), %u variant(s), %u tag(s), %llu bytes charged to the ledger (flags %x)\n", (unsigned)n->info.families,
		  (unsigned)n->info.variants, (unsigned)n->info.tags, (unsigned long long)n->charged, (unsigned)n->info.flags);
	if (b)
		b->db += n->charged;     /* part of what the engine holds privately, so a scanner's share is made after it */
	if (info)
		*info = n->info;
	return n;
}

void kof_catnames_free(kof_catnames *n, struct kof_budget *b)
{
	if (!n)
		return;
	KOF_TRACE("[mem] catalog table freed: %llu bytes released from the ledger\n", (unsigned long long)n->charged);
	if (b) {
		b->db = n->charged > b->db ? 0 : b->db - n->charged;
		kof_budget_release(b, n->charged);
	}
	free_tabs(n);
	free(n->fams.fam);
	free(n->fams.var);
	free(n->tags.tag);
	free(n);
}

void kof_catnames_info_of(const kof_catnames *n, struct kof_catnames_info *info)
{
	if (info) {
		if (n)
			*info = n->info;
		else
			memset(info, 0, sizeof *info);
	}
}

/*
 * A NAME OF THE TABLE IS A NAME OF ITS KIND because the table is filled only by the catalogs' loaders, and those refuse a file whose
 * family fails kof_name_ok or whose tag fails kof_tag_name_ok (letters, digits, '-', and '_' in a family: none of the verdict's
 * separators '#', '/', ':', '!', '?', '.'). The rule is not checked a second time here; tests/unit/verdict_catalog.c case_hostile pins
 * it from the file to the verdict.
 */
const char *kof_catnames_family(const kof_catnames *n, uint64_t id)
{
	const struct cn_ent *e = n ? find_ent(n->fam_tab, n->fams.n_fam, id) : NULL;

	if (e)
		return n->fams.fam[e->idx].name;
	return n && n->fb ? n->fb(n->fb_ctx, 'F', id) : NULL;
}

const char *kof_catnames_tag(const kof_catnames *n, uint64_t id)
{
	const struct cn_ent *e = n ? find_ent(n->tag_tab, n->tags.n, id) : NULL;

	if (e)
		return n->tags.tag[e->idx].name;
	return n && n->fb ? n->fb(n->fb_ctx, 'T', id) : NULL;
}

/* "Family" + "." + letters from the catalog, else the database's own text; 0 when neither holds the variant. */
static int variant_name(const kof_catnames *n, uint64_t id, char *out, size_t cap)
{
	const struct cn_ent *e = n ? find_ent(n->var_tab, n->fams.n_var, id) : NULL;
	const struct kof_famcat_var *v;
	char letters[16];

	if (!e) {
		const char *t = n && n->fb ? n->fb(n->fb_ctx, 'V', id) : NULL;

		if (!t)
			return 0;
		snprintf(out, cap, "%s", t);
		return 1;
	}
	v = &n->fams.var[e->idx];
	if (v->family >= n->fams.n_fam || !kof_famcat_letter_text(v->letter, letters, sizeof letters))
		return 0;
	snprintf(out, cap, "%s.%s", n->fams.fam[v->family].name, letters);
	return 1;
}

int kof_catnames_family_text(const kof_catnames *n, uint64_t id, char *out, size_t cap)
{
	const char *s = kof_catnames_family(n, id);

	if (!cap)
		return 0;
	if (s) {
		snprintf(out, cap, "%s", s);
		return 1;
	}
	kverdict_catalog_word(out, cap, id);
	return 0;
}

int kof_catnames_variant_text(const kof_catnames *n, uint64_t id, char *out, size_t cap)
{
	if (!cap)
		return 0;
	if (variant_name(n, id, out, cap))
		return 1;
	kverdict_catalog_word(out, cap, id);
	return 0;
}

int kof_catnames_tag_text(const kof_catnames *n, uint64_t id, char *out, size_t cap)
{
	const char *s = kof_catnames_tag(n, id);

	if (!cap)
		return 0;
	if (s) {
		snprintf(out, cap, "%s", s);
		return 1;
	}
	kverdict_catalog_word(out, cap, id);
	return 0;
}

void kof_catnames_slot(const kof_catnames *n, uint64_t family_id, uint64_t variant_id, uint64_t tag_id, char *out, size_t cap)
{
	char a[12], b[12];

	if (!cap)
		return;
	if (!variant_id) {
		const char *t = kof_catnames_tag(n, tag_id);

		if (t) {
			snprintf(out, cap, "%s", t);
		} else {
			kverdict_catalog_word(b, sizeof b, tag_id);
			snprintf(out, cap, "T%s", b);
		}
		return;
	}
	if (variant_name(n, variant_id, out, cap))
		return;
	{
		const char *f = kof_catnames_family(n, family_id);

		kverdict_catalog_word(b, sizeof b, variant_id);
		if (f) {
			snprintf(out, cap, "%s.V%s", f, b);
		} else {
			kverdict_catalog_word(a, sizeof a, family_id);
			snprintf(out, cap, "F%s.V%s", a, b);
		}
	}
}

void kof_catnames_set_fallback(kof_catnames *n, kof_catnames_fallback fn, const void *ctx)
{
	if (n) {
		n->fb = fn;
		n->fb_ctx = ctx;
	}
}
