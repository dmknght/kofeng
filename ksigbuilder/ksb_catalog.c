/*
 * ksb_catalog.c - the catalogs, as the builder asks for them. THE ONE PLACE that calls the
 * Pathogens and Syndromes catalog libraries (verdictor/famcat, tagcat): every other unit asks
 * these functions, so a change in the libraries' names or signatures is an edit here.
 *
 */

#include "ksb.h"
#include <verdictor/famcat.h>
#include <verdictor/tagcat.h>

#define KSB_CAT_TAGS 4096u
#define KSB_CAT_FAMS 1024u
#define KSB_CAT_VARS 8192u

struct ksb_catalog {
	struct kof_tagcat tags;
	struct kof_famcat fams;
	struct kof_tagcat_tag *tag;
	struct kof_famcat_fam *fam;
	struct kof_famcat_var *var;
	/* What the diagnoses of this run use (ksb_catalog_use): by index into the catalogs; names.kdig carries only these. */
	uint8_t *used_tag, *used_fam, *used_var;
};

void ksb_catalog_close(struct ksb_catalog *c)
{
	if (!c)
		return;
	free(c->tag);
	free(c->fam);
	free(c->var);
	free(c->used_tag);
	free(c->used_fam);
	free(c->used_var);
	free(c);
}

/*
 * THE BUILDER READS NAMES AND NOTHING ELSE. The catalog files hold no id (catstore.h): the id of a family, a variant or a tag is made
 * here, from its name, by the one function the engine and the tools use (kof_catid_of), and goes into the pack. A file that still has
 * the old id lines loads (they are counted as ignored and said), and nothing is ever written back to a source from this tool. Two
 * names that make one id are refused by the catalog's own add (KOF_*_ID_CLASH) and the load stops naming both.
 */
static void said_ignored(const struct kof_catstore *s, const char *dir)
{
	if (s->n_ignored)
		fprintf(stderr, "ksigbuilder: %s: %u line(s) not understood and ignored (an old id line is one: ids are made from names)\n", dir,
			(unsigned)s->n_ignored);
}

static int load_pathogens(struct ksb_catalog *c, struct kof_catstore *s, const char *dir, char *why, size_t cap)
{
	if (kof_famcat_load(&c->fams, s, dir) != KOF_CATSTORE_IO_OK || s->n_bad) {
		snprintf(why, cap, "%s", s->note);
		return 0;
	}
	said_ignored(s, dir);
	return 1;
}

static int load_syndromes(struct ksb_catalog *c, struct kof_catstore *s, const char *dir, char *why, size_t cap)
{
	if (kof_tagcat_load(&c->tags, s, dir) != KOF_CATSTORE_IO_OK || s->n_bad) {
		snprintf(why, cap, "%s", s->note);
		return 0;
	}
	said_ignored(s, dir);
	return 1;
}

struct ksb_catalog *ksb_catalog_open(const char *pathogens, const char *syndromes,
				     char *why, size_t cap)
{
	struct ksb_catalog *c = calloc(1, sizeof *c);
	struct kof_catstore *st;

	if (c) {
		c->tag = calloc(KSB_CAT_TAGS, sizeof *c->tag);
		c->fam = calloc(KSB_CAT_FAMS, sizeof *c->fam);
		c->var = calloc(KSB_CAT_VARS, sizeof *c->var);
		c->used_tag = calloc(KSB_CAT_TAGS, 1u);
		c->used_fam = calloc(KSB_CAT_FAMS, 1u);
		c->used_var = calloc(KSB_CAT_VARS, 1u);
	}
	if (!c || !c->tag || !c->fam || !c->var || !c->used_tag || !c->used_fam || !c->used_var) {
		snprintf(why, cap, "out of memory");
		ksb_catalog_close(c);
		return NULL;
	}
	kof_tagcat_init(&c->tags, c->tag, KSB_CAT_TAGS);
	kof_famcat_init(&c->fams, c->fam, KSB_CAT_FAMS, c->var, KSB_CAT_VARS);
	why[0] = 0;
	st = calloc(1, sizeof *st);
	if (!st) {
		snprintf(why, cap, "out of memory");
		ksb_catalog_close(c);
		return NULL;
	}
	kof_catstore_init(st);
	if ((pathogens && !load_pathogens(c, st, pathogens, why, cap)) ||
	    (syndromes && !load_syndromes(c, st, syndromes, why, cap))) {
		free(st);
		ksb_catalog_close(c);
		return NULL;
	}
	free(st);
	return c;
}

uint64_t ksb_catalog_tag(const struct ksb_catalog *c, const char *tag)
{
	return kof_tagcat_id(&c->tags, tag);
}

uint64_t ksb_catalog_family(const struct ksb_catalog *c, const char *family)
{
	return kof_famcat_family_id(&c->fams, family);
}

int ksb_catalog_variant(const struct ksb_catalog *c, const char *family, const char *letters,
			uint64_t *id, uint32_t *types)
{
	/* The catalog names a variant "<family>_<letters>"; the id function takes the letters. */
	*id = kof_famcat_variant_id(&c->fams, family, letters);
	*types = kof_famcat_variant_types(&c->fams, family, letters);
	return *id && *types ? KSB_VAR_OK : KSB_VAR_NONE;
}

int ksb_catalog_variant_deleted(const struct ksb_catalog *c, const char *family, const char *letters)
{
	return kof_famcat_variant_state(&c->fams, family, letters) == KOF_FAMCAT_LS_DELETED;
}

/* A diagnose that built uses these ids: remember the catalog items they are made from. */
void ksb_catalog_use(struct ksb_catalog *c, uint64_t family, uint64_t variant, uint64_t tag)
{
	uint32_t i;

	if (!c)
		return;
	for (i = 0; i < c->fams.n_fam; i++)
		if (family && kof_famcat_fam_id_at(&c->fams, i) == family)
			c->used_fam[i] = 1;
	for (i = 0; i < c->fams.n_var; i++)
		if (variant && kof_famcat_var_id_at(&c->fams, i) == variant)
			c->used_var[i] = 1;
	for (i = 0; i < c->tags.n; i++)
		if (tag && kof_tagcat_id_at(&c->tags, i) == tag)
			c->used_tag[i] = 1;
}

/* The rows of names.kdig, in the order the file wants them ('F', 'V', 'T'; by id): into *rows, a malloc'd array the caller frees. */
static int row_cmp(const void *a, const void *b)
{
	const struct ksb_name_row *x = a, *y = b;

	if (x->kind != y->kind)
		return x->kind < y->kind ? -1 : 1;
	return x->id < y->id ? -1 : x->id > y->id;
}

uint32_t ksb_catalog_names(const struct ksb_catalog *c, struct ksb_name_row **rows)
{
	uint32_t i, n = 0, cap = 0;

	*rows = NULL;
	if (!c)
		return 0;
	for (i = 0; i < c->fams.n_fam; i++)
		cap += c->used_fam[i];
	for (i = 0; i < c->fams.n_var; i++)
		cap += c->used_var[i];
	for (i = 0; i < c->tags.n; i++)
		cap += c->used_tag[i];
	if (!cap || !(*rows = calloc(cap, sizeof **rows)))
		return 0;
	for (i = 0; i < c->fams.n_fam; i++)
		if (c->used_fam[i]) {
			(*rows)[n].kind = 'F';
			(*rows)[n].id = kof_famcat_fam_id_at(&c->fams, i);
			snprintf((*rows)[n].name, sizeof (*rows)[n].name, "%s", c->fams.fam[i].name);
			n++;
		}
	for (i = 0; i < c->fams.n_var; i++)
		if (c->used_var[i]) {
			char letters[8];

			if (!kof_famcat_letter_text(c->fams.var[i].letter, letters, sizeof letters))
				continue;
			(*rows)[n].kind = 'V';
			(*rows)[n].id = kof_famcat_var_id_at(&c->fams, i);
			snprintf((*rows)[n].name, sizeof (*rows)[n].name, "%s.%s", c->fams.fam[c->fams.var[i].family].name, letters);
			n++;
		}
	for (i = 0; i < c->tags.n; i++)
		if (c->used_tag[i]) {
			(*rows)[n].kind = 'T';
			(*rows)[n].id = kof_tagcat_id_at(&c->tags, i);
			snprintf((*rows)[n].name, sizeof (*rows)[n].name, "%s", c->tags.tag[i].name);
			n++;
		}
	qsort(*rows, n, sizeof **rows, row_cmp);
	return n;
}
