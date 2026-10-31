/*
 * ksb_names.c - names.kdig: the NAMES of the family, variant and tag ids the diagnoses of a database carry, written beside diseases.kdig
 * and read the same way (libkofeng/databases/dbloader_packs.c, kof_db_load_names has the layout). The ids are the ones the build just made
 * from the catalog names (catstore.h) and the names are those same catalog names, so a scan with only --db says "Mirai.A" and not hex.
 * Only the items a diagnose of THIS database uses are written: the file stays as small as the database.
 *
 * Nothing is read back from the file and nothing is written into a source: the file is an output of the build and is replaced by rename.
 */

#include "ksb.h"

int ksb_write_names(struct ksb_ctx *ksb, const char *db)
{
	char path[4400];
	struct ksb_name_row *rows = NULL;
	uint32_t n = ksb_catalog_names(ksb->diag.cat, &rows), i;
	size_t total = 16u, at = 16u;
	uint8_t *out;
	uint32_t crc;

	snprintf(path, sizeof path, "%s/names.kdig", db);
	if (!n) {
		(void)remove(path);        /* a database whose diagnoses name nothing has no table; a stale one must not outlive it */
		return 1;
	}
	for (i = 0; i < n; i++)
		total += 10u + strlen(rows[i].name);
	out = calloc(1, total);
	if (!out) {
		free(rows);
		return 0;
	}
	memcpy(out, "KDNM", 4);
	out[4] = 1;
	for (i = 0; i < 4u; i++)
		out[8u + i] = (uint8_t)(n >> (8u * i));
	for (i = 0; i < n; i++) {
		size_t l = strlen(rows[i].name), k;

		out[at++] = rows[i].kind;
		for (k = 0; k < 8u; k++)
			out[at++] = (uint8_t)(rows[i].id >> (8u * k));
		out[at++] = (uint8_t)l;
		memcpy(out + at, rows[i].name, l);
		at += l;
	}
	crc = kof_crc32(out + 16, total - 16u);
	for (i = 0; i < 4u; i++)
		out[12u + i] = (uint8_t)(crc >> (8u * i));
	i = (uint32_t)ksb_write_file(path, out, total);
	free(out);
	free(rows);
	if (i)
		printf("== %s  %u name(s), %zu bytes\n", path, (unsigned)n, total);
	return (int)i;
}
