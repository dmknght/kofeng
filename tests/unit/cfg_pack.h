/*
 * cfg_pack.h - what the tests of the CFG signature share to make a pack at run time: the catalogs of a family and two tags, one diagnose per
 * threshold 1 .. n holding the same CODE block (the keys), ksigbuilder --tree, and the plain file helpers. Needs `root` (the scratch directory),
 * `builder` and `dbdir` from the including file, and the headers kofeng.h, kofplatform.h, famcat.h, tagcat.h.
 */
#ifndef KOF_TESTS_CFG_PACK_H
#define KOF_TESTS_CFG_PACK_H

/* ---- the catalogs, the diagnoses, the pack ------------------------------------------------------------------------------------------ */

static int write_file(const char *path, const void *p, size_t n)
{
	FILE *f = fopen(path, "wb");

	if (!f)
		return 0;
	if (n && fwrite(p, 1, n, f) != n) {
		fclose(f);
		return 0;
	}
	return fclose(f) == 0;
}

static uint8_t *read_file(const char *path, size_t *n)
{
	FILE *f = fopen(path, "rb");
	uint8_t *b;
	long L;

	if (!f)
		return NULL;
	fseek(f, 0, SEEK_END);
	L = ftell(f);
	fseek(f, 0, SEEK_SET);
	b = malloc((size_t)L + 1u);
	if (b && fread(b, 1, (size_t)L, f) != (size_t)L) {
		free(b);
		b = NULL;
	}
	fclose(f);
	if (b)
		*n = (size_t)L;
	return b;
}

static void write_catalogs(const char *base)
{
	struct kof_famcat_fam fam[8];
	struct kof_famcat_var var[8];
	struct kof_catstore *st = calloc(1, sizeof *st);
	struct kof_tagcat_tag tag[8];
	struct kof_tagcat tc;
	struct kof_famcat c;
	char dir[500];
	uint32_t f;

	snprintf(dir, sizeof dir, "%s/pathogens", base);
	kof_mkdir(dir, 0700);
	kof_famcat_init(&c, fam, 8, var, 8);
	kof_catstore_init(st);
	(void)kof_famcat_add_family(&c, "Mirai", NULL, (1u << KOF_MALTYPE_BOTNET) | (1u << KOF_MALTYPE_ROOTKIT), &f);
	(void)kof_famcat_save(&c, st, dir);
	snprintf(dir, sizeof dir, "%s/syndromes", base);
	kof_mkdir(dir, 0700);
	kof_tagcat_init(&tc, tag, 8);
	kof_catstore_init(st);
	(void)kof_tagcat_add(&tc, "flood", 1u << KOF_DISEASE_ACT_SCAN, 1u << KOF_DISEASE_OBJ_NETWORK, NULL);
	(void)kof_tagcat_add(&tc, "c2", 1u << KOF_DISEASE_ACT_C2, 1u << KOF_DISEASE_OBJ_NETWORK, NULL);
	(void)kof_tagcat_save(&tc, st, dir);
	free(st);
}


struct scene {
	char base[400], art[400], db[400], gen[420], err[400];
};

/* The pack: one diagnose per threshold 1, 2, ... 99, each holding the same block (`keys`, region CODE, norm RAW). Returns the builder's status. */
static int make_pack(struct scene *s, const char *tag, const uint32_t *keys, uint32_t n_key, uint32_t n_thresh, uint32_t step)
{
	char p[700], a[500], cmd[4400];
	uint32_t k, j;
	size_t n = 0;
	uint8_t *b;

	snprintf(s->base, sizeof s->base, "%s/%s_base", root, tag);
	snprintf(s->art, sizeof s->art, "%s/%s_art", root, tag);
	snprintf(s->db, sizeof s->db, "%s/%s_db", root, tag);
	snprintf(s->gen, sizeof s->gen, "%s/diagnoses", s->base);
	snprintf(s->err, sizeof s->err, "%s/%s_err.txt", root, tag);
	kof_mkdir(s->base, 0700);
	kof_mkdir(s->art, 0700);
	kof_mkdir(s->db, 0700);
	kof_mkdir(s->gen, 0700);
	write_catalogs(s->base);
	snprintf(a, sizeof a, "%s/sigs-any.ksig", dbdir);
	snprintf(p, sizeof p, "%s/sigs-any.ksig", s->db);
	b = read_file(a, &n);
	if (b)
		(void)write_file(p, b, n);
	free(b);
	/* the release pack that opens archives: the zip case needs a module that unpacks one */
	snprintf(a, sizeof a, "build/release/databases/unpack-archive.ksig");
	snprintf(p, sizeof p, "%s/unpack-archive.ksig", s->db);
	b = read_file(a, &n);
	if (b)
		(void)write_file(p, b, n);
	free(b);
	for (k = 1; k <= n_thresh; k++) {
		char text[4096];
		int w = 0;

		w += snprintf(text + w, sizeof text - (size_t)w, "KOF_DIAG_NAME(botnet_mirai_flood_%02u);\nKOF_TARGET_FORMAT(KOF_FMT_ELF);\nKOF_DIAG_FAMILY(\"Mirai\");\n"
			      "KOF_DIAG_VARIANT(\"A\");\nKOF_DIAG_TYPE(KOF_MALTYPE_BOTNET);\nKOF_DIAG_TAG(\"flood\");\n", k);
		w += snprintf(text + w, sizeof text - (size_t)w, "KOF_MUTATION_BLOCK(b0, KOF_SCAN_ELF_CODE");
		for (j = 0; j < n_key; j++)
			w += snprintf(text + w, sizeof text - (size_t)w, ", 0x%08xu", keys[j]);
		w += snprintf(text + w, sizeof text - (size_t)w, ");\nKOF_DIAG_SIMILAR(m1, %u, b0);\n", k * step);
		snprintf(p, sizeof p, "%s/botnet_mirai_flood_%02u.c", s->gen, k);
		write_file(p, text, (size_t)w);
	}
	snprintf(cmd, sizeof cmd, "%s --tree '%s' '%s' '%s' --pathogens '%s/pathogens' --syndromes '%s/syndromes' --basedir '%s' "
		 ">'%s.out' 2>'%s'", builder, s->base, s->art, s->db, s->base, s->base, s->base, s->err, s->err);
	return system(cmd);
}


#endif /* KOF_TESTS_CFG_PACK_H */
