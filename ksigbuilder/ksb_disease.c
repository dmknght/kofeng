/*
 * ksb_disease.c - The diseases and the syndromes of a database.
 */

#include "ksb.h"

#include <dirent.h>
#include <databases/syndsrc.h>

/*
 * THE DISEASES OF A DATABASE, as the build sees them: every name a detector
 * declares and every name a syndrome mentions, once, with the type it was
 * declared with. What the packs carry is the id (kofdisease.h); this is where
 * two names that hash alike, or one name declared with two types, are caught -
 * both would make one disease answer for another, silently.
 *
 *     "KDIS"   magic
 *     u8       version, 1
 *     u8 x 3   0
 *     u32      count
 *     count x  { u32 id, u8 maltype, u8 length, the name }     ascending by id
 *
 * The id to name table the tools read; a scan never does. A name only a
 * syndrome mentions has no declared type and carries 0xff.
 */

/* 1 when the name is now known, 0 (and the reason on stderr) when it cannot be. */
int ksb_disease_note(struct ksb_ctx *ksb, const char *name, unsigned type,
		     unsigned by)
{
	uint32_t id = kof_disease_id(name);
	size_t i;

	for (i = 0; i < ksb->diseases.n; i++) {
		if (ksb->diseases.ent[i].id != id)
			continue;
		if (strcmp(ksb->diseases.ent[i].name, name)) {
			fprintf(stderr, "FAIL: the diseases \"%s\" and \"%s\" hash to one id - "
				"rename one\n", ksb->diseases.ent[i].name, name);
			return 0;
		}
		if (type != DIS_TYPE_UNKNOWN && ksb->diseases.ent[i].type != DIS_TYPE_UNKNOWN &&
		    ksb->diseases.ent[i].type != type) {
			fprintf(stderr, "FAIL: the disease \"%s\" is declared with two types, %s "
				"and %s\n", name, kof_maltype_ident(ksb->diseases.ent[i].type),
				kof_maltype_ident(type));
			return 0;
		}
		if (ksb->diseases.ent[i].type == DIS_TYPE_UNKNOWN)
			ksb->diseases.ent[i].type = type;
		ksb->diseases.ent[i].by |= by;
		return 1;
	}
	if (ksb->diseases.n == ksb->diseases.cap) {
		size_t nc = ksb->diseases.cap ? ksb->diseases.cap * 2u : 64u;
		struct dis_ent *g = realloc(ksb->diseases.ent, nc * sizeof *g);

		if (!g) {
			fprintf(stderr, "FAIL: out of memory\n");
			return 0;
		}
		ksb->diseases.ent = g;
		ksb->diseases.cap = nc;
	}
	ksb->diseases.ent[ksb->diseases.n].id = id;
	ksb->diseases.ent[ksb->diseases.n].type = type;
	ksb->diseases.ent[ksb->diseases.n].by = by;
	snprintf(ksb->diseases.ent[ksb->diseases.n].name, sizeof ksb->diseases.ent[ksb->diseases.n].name, "%s", name);
	ksb->diseases.n++;
	return 1;
}

static int dis_cmp(const void *a, const void *b)
{
	const struct dis_ent *x = a, *y = b;

	return x->id < y->id ? -1 : x->id > y->id;
}

int ksb_write_diseases(struct ksb_ctx *ksb, const char *db)
{
	char path[4400];
	unsigned char *out;
	size_t i, at, total = 12u;

	snprintf(path, sizeof path, "%s/diseases.kdig", db);
	/* Nothing registered: the file must not exist. Otherwise it is replaced
	 * by rename below, never removed first - a name that is absent for a
	 * moment is a database a scanner opening now would load without it. */
	if (!ksb->diseases.n) {
		(void)remove(path);
		return 1;
	}
	/*
	 * THE TWO WAYS A SYNDROME AND A DETECTOR CAN DISAGREE, read off the one table
	 * every source registered in. A disease a syndrome names and no detector
	 * declares can never be found; and once any syndrome exists, a disease none of
	 * them names answers "unresolved" for every file a detector finds it on,
	 * because a behaviour nobody verified is evidence for no type. Warnings, not
	 * errors: both are what a database looks like part way through being written.
	 */
	{
		int any_syndrome = 0;

		for (i = 0; i < ksb->diseases.n; i++)
			any_syndrome |= (ksb->diseases.ent[i].by & DIS_BY_SYNDROME) != 0;
		for (i = 0; i < ksb->diseases.n; i++) {
			if ((ksb->diseases.ent[i].by & DIS_BY_SYNDROME) && !(ksb->diseases.ent[i].by & DIS_BY_DETECTOR))
				fprintf(stderr, "ksigbuilder: warning: a syndrome names the "
					"disease \"%s\" and no detector declares it\n",
					ksb->diseases.ent[i].name);
			if (any_syndrome && (ksb->diseases.ent[i].by & DIS_BY_DETECTOR) &&
			    !(ksb->diseases.ent[i].by & DIS_BY_SYNDROME))
				fprintf(stderr, "ksigbuilder: warning: no syndrome names the "
					"disease \"%s\", so a file a detector finds it on is "
					"never typed by it\n", ksb->diseases.ent[i].name);
		}
	}
	qsort(ksb->diseases.ent, ksb->diseases.n, sizeof *ksb->diseases.ent, dis_cmp);
	for (i = 0; i < ksb->diseases.n; i++)
		total += 6u + strlen(ksb->diseases.ent[i].name);
	out = calloc(1, total);
	if (!out)
		return 0;
	memcpy(out, "KDIS", 4);
	out[4] = 1;
	out[8] = (unsigned char)ksb->diseases.n;
	out[9] = (unsigned char)(ksb->diseases.n >> 8);
	out[10] = (unsigned char)(ksb->diseases.n >> 16);
	out[11] = (unsigned char)(ksb->diseases.n >> 24);
	at = 12u;
	for (i = 0; i < ksb->diseases.n; i++) {
		size_t l = strlen(ksb->diseases.ent[i].name);

		out[at++] = (unsigned char)ksb->diseases.ent[i].id;
		out[at++] = (unsigned char)(ksb->diseases.ent[i].id >> 8);
		out[at++] = (unsigned char)(ksb->diseases.ent[i].id >> 16);
		out[at++] = (unsigned char)(ksb->diseases.ent[i].id >> 24);
		out[at++] = (unsigned char)ksb->diseases.ent[i].type;
		out[at++] = (unsigned char)l;
		memcpy(out + at, ksb->diseases.ent[i].name, l);
		at += l;
	}
	if (!ksb_write_file(path, out, total)) {
		free(out);
		return 0;
	}
	free(out);
	printf("== %s  %zu disease(s), %zu bytes\n", path, ksb->diseases.n, total);
	return 1;
}

/*
 * THE SYNDROMES OF A DATABASE, in one pack: syndromes.kdig.
 *
 *     "KSYN"   magic
 *     u8       version, 1
 *     u8       0
 *     u16      count
 *     count x  { u32 offset, u32 length }       from the start of the file
 *     the records:  u32 type mask, u8 n, then n x u32 disease id
 *
 * The header is a diagnose pack's, so one reader of the table serves both. A
 * pack of its own and not a section of a diagnose pack: a diagnose is a thing
 * to look for and a syndrome is what a set of findings is read against, and the
 * second changes when somebody verifies a sample, not when the code is.
 *
 * Records are in the order of their file names, so the same sources give the
 * same bytes whatever order the directory listed them in.
 */
static int ssrc_name_cmp(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

static void ssrc_error(void *ud, int line, const char *msg)
{
	struct ksb_ctx *ksb = ud;

	ksb_err(ksb, line, msg);
}

int ksb_build_syndromes(struct ksb_ctx *ksb, const char *base, const char *db)
{
	char dpath[4200], path[4400];
	const struct kof_dsrc_report rep = { ssrc_error, ksb_dsrc_warn, ksb };
	DIR *dd;
	struct dirent *de;
	char **pnames = NULL;
	size_t n_names = 0, i, k;
	unsigned char **rec = NULL;
	size_t *rlen = NULL, total = 0, at;

	snprintf(path, sizeof path, "%s/syndromes.kdig", db);
	(void)remove(path);
	snprintf(dpath, sizeof dpath, "%s/syndromes", base);
	dd = opendir(dpath);
	if (!dd)
		return 1;
	while ((de = readdir(dd)) != NULL) {
		char **g;

		if (de->d_name[0] == '.' || !ksb_is_c_source(de->d_name))
			continue;
		g = realloc(pnames, (n_names + 1u) * sizeof *pnames);
		if (!g) {
			closedir(dd);
			return 0;
		}
		pnames = g;
		if (!(pnames[n_names] = ksb_dup_n(de->d_name, strlen(de->d_name)))) {
			closedir(dd);
			return 0;
		}
		n_names++;
	}
	closedir(dd);
	if (!n_names)
		return 1;
	qsort(pnames, n_names, sizeof *pnames, ssrc_name_cmp);
	if (n_names > 0xffffu) {
		fprintf(stderr, "ksigbuilder: more syndromes than a pack holds\n");
		return 0;
	}
	rec = calloc(n_names, sizeof *rec);
	rlen = calloc(n_names, sizeof *rlen);
	if (!rec || !rlen)
		return 0;
	for (i = 0; i < n_names; i++) {
		static struct kof_ssrc ps;
		char *text;
		size_t tn = 0, L = 4u + 1u;

		snprintf(path, sizeof path, "%s/%s", dpath, pnames[i]);
		text = ksb_slurp(path, &tn);
		if (!text) {
			fprintf(stderr, "FAIL: cannot open %s\n", path);
			return 0;
		}
		ksb->src_name = pnames[i];
		(void)kof_ssrc_parse(text, tn, &ps, &rep);
		free(text);
		if (ksb->errors)
			return 0;
		L += 4u * ps.n_dis;
		rec[i] = calloc(1, L);
		if (!rec[i])
			return 0;
		rec[i][0] = (unsigned char)ps.type_mask;
		rec[i][1] = (unsigned char)(ps.type_mask >> 8);
		rec[i][2] = (unsigned char)(ps.type_mask >> 16);
		rec[i][3] = (unsigned char)(ps.type_mask >> 24);
		rec[i][4] = (unsigned char)ps.n_dis;
		at = 5u;
		for (k = 0; k < ps.n_dis; k++) {
			uint32_t id = kof_disease_id(ps.dis[k]);

			if (!ksb_disease_note(ksb, ps.dis[k], DIS_TYPE_UNKNOWN, DIS_BY_SYNDROME))
				return 0;
			rec[i][at++] = (unsigned char)id;
			rec[i][at++] = (unsigned char)(id >> 8);
			rec[i][at++] = (unsigned char)(id >> 16);
			rec[i][at++] = (unsigned char)(id >> 24);
		}
		rlen[i] = L;
	}
	snprintf(path, sizeof path, "%s/syndromes.kdig", db);
	if (!ksb_write_krec_pack(path, "KSYN", rec, rlen, n_names, &total))
		return 0;
	printf("== %s  %zu syndrome(s), %zu bytes\n", path, n_names, total);
	for (i = 0; i < n_names; i++) {
		free(pnames[i]);
		free(rec[i]);
	}
	free(pnames);
	free(rec);
	free(rlen);
	return 1;
}
