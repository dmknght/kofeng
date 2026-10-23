/*
 * ksb_diagpack.c - The diagnoses of a database, in packs by kind:
 *    diag-<kind>.kdig.
 */

#include "ksb.h"

#include <dirent.h>
#include <databases/pack/dbtables.h>   /* KOF_DB_MAX_DIAG: what the loader holds */

/*
 * THE DIAGNOSES OF A DATABASE, in packs by KIND: diag-<kind>.kdig.
 *
 *     "KDGP"   magic
 *     u8       version, 1
 *     u8       0
 *     u16      count
 *     count x  { u32 offset, u32 length }       from the start of the file
 *     the records, each exactly what ksb_diagnose_main wrote - one diagnose
 *
 * The kind is the first word of the source's name - net_, pe_, syscall_,
 * kernel_ - the same type_family_NN.c convention the signatures follow, so a
 * pack is named for what its diagnoses are about the way sigs-elf and unpack-pe
 * are named for theirs: diag-net.kdig, diag-syscall.kdig. One file per diagnose
 * made the set a database held depend on a directory listing; one file for all
 * of them made a change to one diagnose a change to every pack consumer's file.
 *
 * A file of their own and not a section of a .ksig: the pack header carries a
 * fixed section table, so one more section there is a change to the format of
 * every database in existence, and none of what a pack exists to carry applies
 * to a diagnose. Records are sorted by NAME before they are written, so the same
 * sources give the same bytes whatever order the directory listed them in.
 */
char *ksb_dup_n(const char *p, size_t n)
{
	char *o = malloc(n + 1u);

	if (o) {
		memcpy(o, p, n);
		o[n] = 0;
	}
	return o;
}

struct diag_rec {
	unsigned char *b;
	size_t         n;
	char          *kind;            /* the pack it goes in */
};

static int diag_rec_cmp(const void *x, const void *y)
{
	const struct diag_rec *a = x, *c = y;
	size_t la = a->b[3], lc = c->b[3];
	int r = memcmp(a->b + 4, c->b + 4, la < lc ? la : lc);

	if (r)
		return r;
	return la < lc ? -1 : la > lc;
}

/* What an earlier build wrote - one diag-NAME.kdig each, or one diagnoses.kdig -
 * is removed first, so a database directory cannot hold two generations. */
static void clear_diag_packs(const char *db)
{
	char path[4200];
	DIR *dd = opendir(db);
	struct dirent *de;

	while (dd && (de = readdir(dd)) != NULL) {
		size_t l = strlen(de->d_name);

		if ((l > 10u && !strncmp(de->d_name, "diag-", 5u) &&
		     !strcmp(de->d_name + l - 5u, ".kdig")) ||
		    !strcmp(de->d_name, "diagnoses.kdig")) {
			snprintf(path, sizeof path, "%s/%s", db, de->d_name);
			(void)remove(path);
		}
	}
	if (dd)
		closedir(dd);
}

/*
 * A PACK OF RECORDS, written: the header every .kdig of this shape has - the
 * magic, version 1, a u16 count and a table of { u32 offset, u32 length } - then
 * the records, in the order given. The diagnose packs are
 * this shape, and the layout is written here once. Returns the file's size in
 * `*total`, or 0 on failure with the reason on stderr.
 */
int ksb_write_krec_pack(const char *path, const char *magic,
			unsigned char *const *rec, const size_t *rlen,
			size_t n, size_t *total_out)
{
	size_t i, at, total = 8u + n * 8u;
	unsigned char *out;

	if (n > 0xffffu) {
		fprintf(stderr, "FAIL: more records than a pack holds (%s)\n", path);
		return 0;
	}
	for (i = 0; i < n; i++)
		total += rlen[i];
	if (total > 0xffffffffu)
		return 0;
	out = calloc(1, total);
	if (!out)
		return 0;
	memcpy(out, magic, 4);
	out[4] = 1;
	out[6] = (unsigned char)n;
	out[7] = (unsigned char)(n >> 8);
	at = 8u + n * 8u;
	for (i = 0; i < n; i++) {
		unsigned char *e = out + 8u + i * 8u;
		uint32_t off = (uint32_t)at, len = (uint32_t)rlen[i];

		e[0] = (unsigned char)off; e[1] = (unsigned char)(off >> 8);
		e[2] = (unsigned char)(off >> 16); e[3] = (unsigned char)(off >> 24);
		e[4] = (unsigned char)len; e[5] = (unsigned char)(len >> 8);
		e[6] = (unsigned char)(len >> 16); e[7] = (unsigned char)(len >> 24);
		memcpy(out + at, rec[i], rlen[i]);
		at += rlen[i];
	}
	if (!ksb_write_file(path, out, total)) {
		free(out);
		return 0;
	}
	free(out);
	*total_out = total;
	return 1;
}

/* One pack: the records of `r[0..n)` that belong to `kind`. */
static int write_one_diag_pack(const char *db, const char *kind,
			       struct diag_rec *r, size_t n_all)
{
	char path[4200];
	unsigned char **rec;
	size_t *rlen, i, n = 0, total = 0;
	int ok;

	rec = calloc(n_all ? n_all : 1u, sizeof *rec);
	rlen = calloc(n_all ? n_all : 1u, sizeof *rlen);
	if (!rec || !rlen) {
		free(rec);
		free(rlen);
		return 0;
	}
	for (i = 0; i < n_all; i++)
		if (!strcmp(r[i].kind, kind)) {
			rec[n] = r[i].b;
			rlen[n] = r[i].n;
			n++;
		}
	if (!n) {
		free(rec);
		free(rlen);
		return 1;
	}
	snprintf(path, sizeof path, "%s/diag-%s.kdig", db, kind);
	ok = ksb_write_krec_pack(path, "KDGP", rec, rlen, n, &total);
	if (ok)
		printf("== %s  %zu diagnose(s), %zu bytes\n", path, n, total);
	free(rec);
	free(rlen);
	return ok;
}

/* All the packs. `recs[i]` is a record file and `kinds[i]` the kind of the
 * source it was built from. */
/*
 * THE BUILD REFUSES A DATABASE THE LOADER WOULD CUT.
 *
 * Two ways a diagnose can be in the packs and not in the engine, and both used to
 * be silent in the scan (tests/unit/caps_db.c):
 *
 *   TWO NAMES, ONE ID. A rule calls a diagnose by KOF_DIAG_ID(name), the 32-bit
 *   hash of the name, and the loader keeps the first of two diagnoses with one id.
 *   The id was 16 bits and with 256 names the chance that some pair collided was
 *   about 40%; at 32 bits it is about one in a million for 256 names, and still
 *   refused here, naming both, so the author renames one rather than a diagnose
 *   silently not existing.
 *
 *   MORE DIAGNOSES THAN THE LOADER HOLDS (KOF_DB_MAX_DIAG): the ones past it are
 *   not loaded. Refused here for the same reason.
 *
 * The id is computed from the record's own name (its length at byte 3, the name
 * from byte 4 - the layout diag_rec_cmp reads), by the function the modules use.
 */
static int diag_ids_distinct(const struct diag_rec *r, size_t n)
{
	size_t i, j;
	uint32_t *id;
	int rc = 1;

	if (n > KOF_DB_MAX_DIAG) {
		fprintf(stderr, "ksigbuilder: %zu diagnoses; the loader holds at most "
			"%u, the rest would not be loaded\n", n, KOF_DB_MAX_DIAG);
		return 0;
	}
	id = malloc((n ? n : 1u) * sizeof *id);
	if (!id)
		return 0;
	for (i = 0; i < n; i++) {
		char nm[256];
		size_t l = r[i].b[3];

		if (l > r[i].n - 4u)
			l = r[i].n - 4u;
		memcpy(nm, r[i].b + 4, l);
		nm[l] = 0;
		id[i] = kof_diag_id32_(nm);
	}
	for (i = 0; i < n; i++)
		for (j = 0; j < i; j++)
			if (id[i] == id[j]) {
				fprintf(stderr, "ksigbuilder: the diagnoses '%.*s' and "
					"'%.*s' hash to the same 32-bit id (%u): a rule could "
					"not tell them apart and the loader would keep only one "
					"- rename one\n",
					(int)r[j].b[3], (const char *)r[j].b + 4,
					(int)r[i].b[3], (const char *)r[i].b + 4,
					(unsigned)id[i]);
				rc = 0;
			}
	free(id);
	return rc;
}

int ksb_write_diag_packs(const char *db, char **recs, char **kinds,
			 size_t n_recs)
{
	struct diag_rec *r;
	size_t i, j;
	int rc = 1;

	clear_diag_packs(db);
	if (!n_recs)
		return 1;
	r = calloc(n_recs, sizeof *r);
	if (!r)
		return 0;
	for (i = 0; i < n_recs && rc; i++) {
		FILE *in = fopen(recs[i], "rb");
		long len;

		r[i].kind = kinds[i];
		if (!in || fseek(in, 0, SEEK_END) != 0 ||
		    (len = ftell(in)) < 4 || fseek(in, 0, SEEK_SET) != 0) {
			fprintf(stderr, "ksigbuilder: cannot read %s\n", recs[i]);
			if (in) fclose(in);
			rc = 0;
			break;
		}
		r[i].n = (size_t)len;
		r[i].b = malloc(r[i].n);
		if (!r[i].b || fread(r[i].b, 1, r[i].n, in) != r[i].n) {
			fprintf(stderr, "ksigbuilder: cannot read %s\n", recs[i]);
			rc = 0;
		}
		fclose(in);
	}
	if (rc)
		rc = diag_ids_distinct(r, n_recs);
	if (rc) {
		qsort(r, n_recs, sizeof *r, diag_rec_cmp);
		/* One pack per kind, each once, in the sorted order. */
		for (i = 0; i < n_recs && rc; i++) {
			for (j = 0; j < i; j++)
				if (!strcmp(r[j].kind, r[i].kind))
					break;
			if (j == i)
				rc = write_one_diag_pack(db, r[i].kind, r, n_recs);
		}
	}
	for (i = 0; i < n_recs; i++)
		free(r[i].b);
	free(r);
	return rc;
}
