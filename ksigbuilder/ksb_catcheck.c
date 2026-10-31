/*
 * ksb_catcheck.c - the checks of a diagnose's catalog references (KOF_DIAG_FAMILY, _VARIANT,
 * _TYPE, _TAG), one set for the build and for `ksigbuilder --catalog`.
 *
 * WHAT IS REFUSED, each with the file and the line of the declaration at fault:
 *   a variant letter the family never issued (a typo);
 *   a type the variant does not declare, and the type Packer (not a malware type);
 *   two diagnoses with one name (see below);
 *   a catalog the build was not given (--pathogens, --syndromes) for a diagnose that names one.
 *
 * WHAT IS ONLY WARNED (owner, 2026-10-31 and 2026-11-01): a family or a tag the catalog does not have, or a variant that was DELETED (kof_famcat_variant_state:
 * a letter below the family's counter that no variant has). The state is derived from the catalog, never stored in a diagnose; the diagnose is left out of
 * the pack, so the scanner never reads it, and the build goes on (one warning per diagnose, naming what is missing). An error elsewhere in the same
 * diagnose (a letter never issued, the type) still refuses it.
 *
 * TWO DIAGNOSES COLLIDE when they carry the same name (the name is the diagnose's runtime id), and for no other reason. Family, variant, type and
 * tag say which family and which kind a diagnose belongs to; they are never a gate. (The build used to refuse a copy - the same four and the same
 * nodes and conditions - as a collision; the owner ruled that out 2026-10-29.)
 */

#include "ksb.h"
#include <databases/diagsrc.h>
#include <dirent.h>

static void say(const struct kof_dsrc_report *r, int line, const char *msg)
{
	if (r && r->error)
		r->error(r->ud, line, msg);
}

static void warn(const struct kof_dsrc_report *r, const char *msg)
{
	if (r && r->warn)
		r->warn(r->ud, msg);
}

static int line_of(const struct kof_dsrc *d, unsigned kind)
{
	uint32_t q;

	for (q = 0; q < d->n; q++)
		if (d->item[q].kind == kind)
			return (int)d->item[q].line;
	return 0;
}

int ksb_meta_check(const struct ksb_catalog *cat, const struct kof_dsrc *d,
		   const struct kof_dsrc_view *v, struct ksb_meta *m,
		   const struct kof_dsrc_report *r)
{
	char msg[320], why[260] = "";
	size_t at = 0;
	uint32_t types = 0;
	int bad = 0;
	int ln_fam = line_of(d, KDS_FAMILY), ln_var = line_of(d, KDS_VARIANT);
	int ln_typ = line_of(d, KDS_TYPE);
	int vr, t;

	memset(m, 0, sizeof *m);
	if (!cat) {
		say(r, ln_fam, "this diagnose names a family, variant and tag, and the build was "
		    "given no catalogs: pass --pathogens <dir> and --syndromes <dir>");
		return 0;
	}
	m->family = ksb_catalog_family(cat, v->family);
	vr = m->family ? ksb_catalog_variant(cat, v->family, v->variant, &m->variant, &types)
		       : KSB_VAR_NONE;
	/* An ABSENT family, an ABSENT tag and a DELETED variant are one case: the diagnose is disabled, with ONE warning that names what is missing
	 * (the family first: without it the variant cannot be judged). */
	if (!m->family) {
		at += (size_t)snprintf(why + at, sizeof why - at, "family \"%s\" is not in the Pathogens catalog", v->family);
	} else if (vr == KSB_VAR_NONE && ksb_catalog_variant_deleted(cat, v->family, v->variant)) {
		at += (size_t)snprintf(why + at, sizeof why - at, "variant \"%s\" of family \"%s\" was deleted from the Pathogens catalog",
				       v->variant, v->family);
	} else if (vr == KSB_VAR_NONE) {
		snprintf(msg, sizeof msg, "variant \"%s\" of family \"%s\" is not in the Pathogens catalog",
			 v->variant, v->family);
		say(r, ln_var, msg);
		bad = 1;
	}
	t = (int)v->type;
	if (t == (int)KOF_MALTYPE_PACKER) {
		say(r, ln_typ, "the type Packer is not a malware type: a packer is recognised by an "
		    "unpacker, not described by a diagnose");
		bad = 1;
	} else if (vr == KSB_VAR_OK && !((types >> (unsigned)t) & 1u)) {
		char have[200];
		unsigned k, hv = 0;

		have[0] = 0;
		for (k = 0; k < (unsigned)KOF_MALTYPE_COUNT && hv + 24u < sizeof have; k++)
			if ((types >> k) & 1u)
				hv += (unsigned)snprintf(have + hv, sizeof have - hv, "%s%s",
							 hv ? ", " : "", kof_maltype_name(k));
		snprintf(msg, sizeof msg, "type %s is not one of the types variant \"%s\" declares (%s)",
			 kof_maltype_name((uint32_t)t), v->variant, have);
		say(r, ln_typ, msg);
		bad = 1;
	}
	m->tag = ksb_catalog_tag(cat, v->tag);
	if (!m->tag)
		snprintf(why + at, sizeof why - at, "%stag \"%s\" is not in the Syndromes catalog", at ? "; " : "", v->tag);
	if (why[0] && !bad) {
		snprintf(msg, sizeof msg, "diagnose \"%s\": %s: the diagnose is not in the pack", v->name, why);
		warn(r, msg);
		m->disabled = 1;
	}
	m->type = (uint8_t)t;
	return !bad;
}

struct ksb_catalog *ksb_catalog_get(struct ksb_ctx *ksb)
{
	char why[400];

	if (ksb->diag.cat_tried)
		return ksb->diag.cat;
	ksb->diag.cat_tried = 1;
	if (!ksb->opt.pathogens && !ksb->opt.syndromes)
		return NULL;
	ksb->diag.cat = ksb_catalog_open(ksb->opt.pathogens, ksb->opt.syndromes, why, sizeof why);
	if (!ksb->diag.cat)
		fprintf(stderr, "ksigbuilder: the catalogs cannot be read: %s\n", why);
	return ksb->diag.cat;
}

/* ---- the whole directory --------------------------------------------------- */

struct seen {
	char     name[KOF_DSRC_NAME_LEN];
	char     file[260];
	struct ksb_meta m;
	int      has_meta;
};

static int cmp_str(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

/* The sorted *.c names of `dir`, or NULL with *n 0 when it cannot be listed. */
static char **list_sources(const char *dir, size_t *n)
{
	DIR *dd = opendir(dir);
	struct dirent *de;
	char **l = NULL;

	*n = 0;
	while (dd && (de = readdir(dd)) != NULL) {
		char **g;

		if (de->d_name[0] == '.' || !ksb_is_c_source(de->d_name))
			continue;
		g = realloc(l, (*n + 1u) * sizeof *l);
		if (!g)
			break;
		l = g;
		l[*n] = strdup(de->d_name);
		if (!l[*n])
			break;
		(*n)++;
	}
	if (dd)
		closedir(dd);
	if (l)
		qsort(l, *n, sizeof *l, cmp_str);
	return l;
}

int ksb_catalog_check_dir(struct ksb_ctx *ksb, const char *dir, int quiet)
{
	size_t n = 0, i, k, with_meta = 0;
	char **names = list_sources(dir, &n);
	struct seen *seen = calloc(n ? n : 1u, sizeof *seen);
	static struct kof_dsrc d;
	struct kof_dsrc_view v;
	/* The build's own pass over each source says its warnings; this prepass would say them twice. */
	const struct kof_dsrc_report rep = { ksb_dsrc_error, quiet ? NULL : ksb_dsrc_warn, ksb };
	int errs0 = ksb->errors;
	struct ksb_catalog *cat = NULL;
	int cat_loaded = 0;

	if (!seen) {
		fprintf(stderr, "ksigbuilder: out of memory\n");
		ksb->errors++;
		return 1;
	}
	for (i = 0; i < n; i++) {
		char path[4400], msg[400];
		size_t tn = 0;
		char *text;
		struct seen *me = &seen[i];
		int before = ksb->errors;

		snprintf(path, sizeof path, "%s/%s", dir, names[i]);
		snprintf(me->file, sizeof me->file, "%s", names[i]);
		text = ksb_slurp(path, &tn);
		ksb->src_name = path;
		if (!text) {
			ksb_err(ksb, 0, "cannot read the file");
			continue;
		}
		kof_dsrc_parse(text, tn, &d, &rep);
		kof_dsrc_resolve(&d, &v, &rep);
		free(text);
		if (ksb->errors != before) {
			kof_dsrc_view_free(&v);
			continue;
		}
		snprintf(me->name, sizeof me->name, "%s", v.name);
		if (v.meta == KOF_DSRC_META_ALL) {
			if (!cat_loaded) {
				cat = ksb_catalog_get(ksb);
				cat_loaded = 1;
			}
			if (ksb_meta_check(cat, &d, &v, &me->m, &rep)) {
				me->has_meta = 1;
				with_meta++;
			}
		}
		kof_dsrc_view_free(&v);
		for (k = 0; k < i; k++) {
			if (!seen[k].name[0])
				continue;
			if (!strcmp(seen[k].name, me->name)) {
				snprintf(msg, sizeof msg, "the name \"%s\" is also the name of %s: "
					 "a diagnose is called by its name, so two cannot share one",
					 me->name, seen[k].file);
				ksb_err(ksb, line_of(&d, KDS_NAME), msg);
				break;
			}
		}
	}
	if (!quiet)
		printf("catalog: %zu diagnose(s), %zu with family/variant/type/tag, %d error(s)\n",
		       n, with_meta, ksb->errors - errs0);
	for (i = 0; i < n; i++)
		free(names[i]);
	free(names);
	free(seen);
	return ksb->errors - errs0;
}

int ksb_catalog_main(struct ksb_ctx *ksb, int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: %s --catalog <diagnoses-dir> [--pathogens <dir>] "
			"[--syndromes <dir>]\n", argv[0]);
		return 2;
	}
	return ksb_catalog_check_dir(ksb, argv[2], 0) ? 1 : 0;
}
