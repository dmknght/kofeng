/*
 * ksb_disease.c - The diseases of a database.
 */

#include "ksb.h"


/*
 * THE DISEASES OF A DATABASE, as the build sees them: every name a detector or
 * a diagnose declares, once, with the type it was declared with. What the packs carry is the id (kofdisease.h); this is where
 * two names that hash alike, or one name declared with two types, are caught -
 * both would make one disease answer for another, silently.
 *
 *     "KDIS"   magic
 *     u8       version, 1
 *     u8 x 3   0
 *     u32      count
 *     count x  { u32 id, u8 maltype, u8 length, the name }     ascending by id
 *
 * The id to name table the verdict's names and the tools read.
 */

/* 1 when the name is now known, 0 (and the reason on stderr) when it cannot be. */
int ksb_disease_note(struct ksb_ctx *ksb, const char *name, unsigned type)
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
		if (ksb->diseases.ent[i].type != type) {
			fprintf(stderr, "FAIL: the disease \"%s\" is declared with two types, %s "
				"and %s\n", name, kof_maltype_ident(ksb->diseases.ent[i].type),
				kof_maltype_ident(type));
			return 0;
		}
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
