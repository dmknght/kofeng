/*
 * names_pack - names.kdig: the NAMES of the family, variant and tag ids a database's diagnoses carry, written by the build and read by the engine
 * with only --db (no --bases). It travels the road the disease table (diseases.kdig) travels: read whole by the loader, a sorted table in the
 * engine, kdb_*_name. This is a NEW FILE of the database directory; no record or section of an existing pack changed.
 *   BUILD     a tree of catalogs and diagnoses builds a names.kdig that names exactly the items the diagnoses use (not the whole catalog), by the
 *             ids catid_oracle.h computes; a build whose diagnoses name nothing leaves no file (a stale one is removed)
 *   ENGINE    keng_open over that directory names the ids with no catalog given: "Mirai", "Mirai.A", "flood"; an id it was not given is hex; a
 *             database without the file is as before (hex); keng_catalog_load names more and overrides (letter case of a name), the rest still
 *             comes from the database
 *   HOSTILE   a file that is cut at every length, has a flipped byte anywhere, a wrong magic or version, rows out of order, a repeated row, a
 *             name with a verdict separator, a reserved id, a count that lies, trailing bytes: the database still opens with its diagnoses, the
 *             names are hex, kdb_diag_packs_refused says so, nothing crashes
 *   SOURCES   a full build over a copy of the real bases' catalogs and diagnoses does not change ONE byte of any source file (every file is hashed
 *             before and after; ksigbuilder once wrote ids into the catalogs)
 * Why the old tests missed what this pins: (a) there was no such file; the old verdict could only be named with --bases.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofcore.h"
#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/verdictor/famcat.h"
#include "../../libkofeng/verdictor/tagcat.h"
#include "catid_oracle.h"

static int fails;
static char root[256];
static const char *dbdir = "build/test/databases-sigs";
static const char *builder = "build/release/bin/ksigbuilder";

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static void sh(const char *fmt, const char *a, const char *b, const char *c)
{
	char cmd[2000];

	snprintf(cmd, sizeof cmd, fmt, a, b, c);
	(void)system(cmd);
}

static void wr(const char *dir, const char *leaf, const char *text)
{
	char p[500];
	FILE *f;

	snprintf(p, sizeof p, "%s/%s", dir, leaf);
	f = fopen(p, "wb");
	if (f) {
		fputs(text, f);
		fclose(f);
	}
}

static uint8_t *slurp(const char *path, size_t *n)
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

static void spit(const char *path, const uint8_t *b, size_t n)
{
	FILE *f = fopen(path, "wb");

	if (f) {
		fwrite(b, 1, n, f);
		fclose(f);
	}
}

/* ---- one tree: catalogs (Mirai A/B, Gafgyt A; tags flood, c2) and two diagnoses that use Mirai A and flood -------------------------- */

static char base[300], art[300], db[300];

/* <base>/<leaf>, valid until the next call. */
static const char *dirs(const char *leaf)
{
	static char d[400];

	snprintf(d, sizeof d, "%s/%s", base, leaf);
	return d;
}

static void tree(const char *tag, int with_diag)
{
	snprintf(base, sizeof base, "%s/%s_base", root, tag);
	snprintf(art, sizeof art, "%s/%s_art", root, tag);
	snprintf(db, sizeof db, "%s/%s_db", root, tag);
	sh("mkdir -p '%s/pathogens' '%s/syndromes' '%s/diagnoses'", base, base, base);
	sh("mkdir -p '%s' '%s'", art, db, "");
	sh("cp '%s/sigs-any.ksig' '%s/'", dbdir, db, "");
	wr(dirs("pathogens"), "mirai.c", "KOF_MALWARE_FAMILY_NAME(\"Mirai\");\nKOF_MALWARE_NEXT_VARIANT(\"C\");\n"
	   "KOF_MALWARE_VARIANT(\"A\", KOF_MALTYPE_BOTNET);\nKOF_MALWARE_VARIANT(\"B\", KOF_MALTYPE_ROOTKIT);\n");
	wr(dirs("pathogens"), "gafgyt.c", "KOF_MALWARE_FAMILY_NAME(\"Gafgyt\");\nKOF_MALWARE_VARIANT(\"A\", KOF_MALTYPE_BOTNET);\n");
	wr(dirs("syndromes"), "network_scan.c", "KOF_TAG_NAME(\"flood\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\nKOF_TAG_OBJS(KOF_DISEASE_OBJ_NETWORK);\n");
	wr(dirs("syndromes"), "network_c2.c", "KOF_TAG_NAME(\"c2\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_C2);\nKOF_TAG_OBJS(KOF_DISEASE_OBJ_NETWORK);\n");
	if (with_diag)
		wr(dirs("diagnoses"), "botnet_mirai_flood_01.c",
		   "KOF_DIAG_NAME(botnet_mirai_flood_01);\nKOF_DIAG_FAMILY(\"Mirai\");\nKOF_DIAG_VARIANT(\"A\");\nKOF_DIAG_TYPE(KOF_MALTYPE_BOTNET);\n"
		   "KOF_DIAG_TAG(\"flood\");\nKOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYSCALL | KOF_DIAG_ANALYSIS_SYMBOL);\n"
		   "KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);\nKOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n");
}

static int build(void)
{
	char cmd[2400];

	snprintf(cmd, sizeof cmd, "%s --tree '%s' '%s' '%s' --pathogens '%s/pathogens' --syndromes '%s/syndromes' --basedir '%s' >/dev/null 2>/dev/null",
		 builder, base, art, db, base, base, base);
	return system(cmd);
}

static char names_path[400];

static const char *npath(void)
{
	snprintf(names_path, sizeof names_path, "%s/names.kdig", db);
	return names_path;
}

static int hexish(const char *s)
{
	return strlen(s) == 8u;
}

static void say(kof_engine *e, uint64_t fam, uint64_t var, uint64_t tag, char f[100], char v[100], char t[100], int r[3])
{
	r[0] = kdb_family_name(e, fam, f, 100);
	r[1] = kdb_variant_name(e, var, v, 100);
	r[2] = kdb_tag_name(e, tag, t, 100);
}

static void build_and_engine(void)
{
	char f[100], v[100], t[100];
	int r[3];
	size_t n = 0;
	uint8_t *raw;
	kof_engine *e;

	tree("names", 1);
	CK(build() == 0);
	raw = slurp(npath(), &n);
	CK(raw && n > 16u && !memcmp(raw, "KDNM", 4) && raw[4] == 1);
	/* exactly the used items: the family Mirai, its variant A, the tag flood: three rows (Gafgyt, Mirai.B and c2 are not used) */
	CK(raw && n >= 16u && raw[8] == 3 && raw[9] == 0 && raw[10] == 0 && raw[11] == 0);
	CK(raw && n == 16u + 3u * 10u + strlen("Mirai") + strlen("Mirai.A") + strlen("flood"));
	if (raw && n > 17u)
		CK(raw[16] == 'F' && raw[16u + 10u + 5u] == 'T' && raw[16u + 20u + 5u + 5u] == 'V');   /* sorted by kind byte: F, T, V */
	free(raw);
	e = keng_open(db);
	CK(e && kdb_diagnoses(e) == 1u && kdb_diag_packs_refused(e) == 0u);
	if (e) {
		say(e, oracle_family("Mirai"), oracle_variant("Mirai", "A"), oracle_tag("flood"), f, v, t, r);
		CK(r[0] == 1 && !strcmp(f, "Mirai") && r[1] == 1 && !strcmp(v, "Mirai.A") && r[2] == 1 && !strcmp(t, "flood"));
		/* not used by a diagnose: not in the file (the catalogs were not given to this engine) */
		say(e, oracle_family("Gafgyt"), oracle_variant("Mirai", "B"), oracle_tag("c2"), f, v, t, r);
		CK(r[0] == 0 && r[1] == 0 && r[2] == 0 && hexish(f) && hexish(v) && hexish(t));
		/* a host catalog adds what the database does not name, and its spelling wins; the rest still comes from the database */
		{
			char p[400], s[400];

			snprintf(p, sizeof p, "%s/names_hostcat", root);
			snprintf(s, sizeof s, "%s/syndromes", base);
			sh("mkdir -p '%s'", p, "", "");
			sh("cp '%s/pathogens/gafgyt.c' '%s/'", base, p, "");
			wr(p, "mirai.c", "KOF_MALWARE_FAMILY_NAME(\"MIRAI\");\nKOF_MALWARE_NEXT_VARIANT(\"B\");\nKOF_MALWARE_VARIANT(\"A\", KOF_MALTYPE_BOTNET);\n");
			CK(keng_catalog_load(e, p, s) == 0u);
			say(e, oracle_family("Mirai"), oracle_variant("Mirai", "A"), oracle_tag("flood"), f, v, t, r);
			CK(r[0] == 1 && !strcmp(f, "MIRAI") && r[1] == 1 && !strcmp(v, "MIRAI.A") && r[2] == 1 && !strcmp(t, "flood"));
			say(e, oracle_family("Gafgyt"), oracle_variant("Gafgyt", "A"), oracle_tag("c2"), f, v, t, r);
			CK(r[0] == 1 && !strcmp(f, "Gafgyt") && r[1] == 1 && !strcmp(v, "Gafgyt.A") && r[2] == 1 && !strcmp(t, "c2"));
			CK(keng_catalog_load(e, NULL, NULL) == 0u);                 /* the host takes its catalog away: the database's names remain */
			say(e, oracle_family("Mirai"), oracle_variant("Mirai", "A"), oracle_tag("flood"), f, v, t, r);
			CK(r[0] == 1 && !strcmp(f, "Mirai") && r[1] == 1 && r[2] == 1);
		}
		keng_close(e);
	}
	/* THE TOOL: kofscanner with --db and nothing else prints the names (a string-form diagnose matches the word "alpha") */
	{
		char cmd[2000], file[400], out[4096];
		FILE *p;
		size_t got;

		wr(dirs("diagnoses"), "botnet_mirai_flood_02.c",
		   "KOF_DIAG_NAME(botnet_mirai_flood_02);\nKOF_DIAG_FAMILY(\"Mirai\");\nKOF_DIAG_VARIANT(\"A\");\nKOF_DIAG_TYPE(KOF_MALTYPE_BOTNET);\n"
		   "KOF_DIAG_TAG(\"flood\");\nKOF_TARGET_RANGE(whole, KOF_SCAN_ALL);\nKOF_DEFINE_STR(s0, \"alpha\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
		   "KOF_DIAG_FIND(m0, KOF_FIND_ANY, whole, s0);\n");
		CK(build() == 0);
		snprintf(file, sizeof file, "%s/sample.txt", root);
		wr(root, "sample.txt", "xx alpha yy");
		snprintf(cmd, sizeof cmd, "ulimit -v 4194304; build/release/bin/kofscanner --db '%s' --no-cache -v --scan-files '%s' 2>&1", db, file);
		p = popen(cmd, "r");
		got = p ? fread(out, 1, sizeof out - 1u, p) : 0;
		if (p)
			pclose(p);
		out[got] = 0;
		CK(strstr(out, "Botnet:Mirai.A!Diagnose") != NULL);
		if (!strstr(out, "Botnet:Mirai.A!Diagnose"))
			printf("%s\n", out);
		sh("rm -f '%s/diagnoses/botnet_mirai_flood_02.c'", base, "", "");
		CK(build() == 0);
	}
	/* a database with no names.kdig (an old one, or one whose diagnoses name nothing) is as before: hex */
	CK(remove(npath()) == 0);
	e = keng_open(db);
	CK(e && kdb_diagnoses(e) == 1u && kdb_diag_packs_refused(e) == 0u);
	if (e) {
		say(e, oracle_family("Mirai"), oracle_variant("Mirai", "A"), oracle_tag("flood"), f, v, t, r);
		CK(r[0] == 0 && r[1] == 0 && r[2] == 0 && hexish(f));
		keng_close(e);
	}
	/* a second build puts it back, byte for byte the same; a build whose diagnoses name nothing removes it */
	CK(build() == 0);
	{
		size_t n2 = 0;
		uint8_t *again = slurp(npath(), &n2);

		CK(again && n2 == n);
		free(again);
	}
	sh("rm -f '%s/diagnoses/'*.c", base, "", "");
	wr(dirs("diagnoses"), "botnet_x_01.c", "KOF_DIAG_NAME(botnet_x_01);\nKOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYSCALL | KOF_DIAG_ANALYSIS_SYMBOL);\n"
	   "KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);\nKOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n");
	CK(build() == 0 && access(npath(), F_OK) != 0);
}

/* every way the file can be wrong, over the good bytes of the first build */
static void hostile(void)
{
	uint8_t *good, *bad;
	size_t n = 0, i, k;
	char f[100], v[100], t[100];
	int r[3];
	kof_engine *e;

	tree("hostile", 1);
	CK(build() == 0);
	good = slurp(npath(), &n);
	CK(good && n > 40u);
	if (!good)
		return;
	bad = malloc(n + 8u);
	for (k = 0; k < 6u + n * 2u; k++) {
		size_t len = n;
		const char *what = "";

		memcpy(bad, good, n);
		if (k < n) {                                 /* cut at every length 0..n-1 */
			len = k;
			what = "cut";
		} else if (k < 2u * n) {                      /* one byte flipped at every offset */
			bad[k - n] ^= 0x40;
			what = "flip";
		} else {
			what = "special";
			switch (k - 2u * n) {
			case 0: memcpy(bad, "KDNX", 4); break;                                   /* magic */
			case 1: bad[4] = 2; break;                                               /* version */
			case 2: bad[8] = 0xff; bad[9] = 0xff; break;                             /* a count that lies (CRC still right) */
			case 3: bad[n] = 0; len = n + 1u; break;                                 /* a trailing byte, CRC over it differs */
			case 4: for (i = 0; i < 4; i++) bad[12 + i] ^= 1; break;                  /* the CRC itself */
			default: len = 3; break;
			}
		}
		spit(npath(), bad, len);
		e = keng_open(db);
		if (!e) {
			CK(0 && "the database must still open");
			continue;
		}
		say(e, oracle_family("Mirai"), oracle_variant("Mirai", "A"), oracle_tag("flood"), f, v, t, r);
		/* every one of these differs from the good file: refused whole (three hex names), counted, and the diagnose is still there */
		CK(kdb_diagnoses(e) == 1u && r[0] == 0 && r[1] == 0 && r[2] == 0 && kdb_diag_packs_refused(e) == 1u);
		if (kdb_diag_packs_refused(e) != 1u)
			printf("    %s at %zu\n", what, k);
		keng_close(e);
	}
	free(bad);
	/* a file whose CRC is RIGHT and whose content is not: the rows are checked, not only the sum */
	{
		struct row { uint8_t kind; uint64_t id; const char *name; };
		static const struct row bads[][2] = {
			{ { 'T', 0x10001, "a#b" }, { 0, 0, NULL } },                          /* a separator in a tag */
			{ { 'F', 0x10001, "Mi.rai" }, { 0, 0, NULL } },                       /* a dot in a family */
			{ { 'V', 0x10001, "Mirai" }, { 0, 0, NULL } },                        /* a variant without letters */
			{ { 'V', 0x10001, "Mirai.a" }, { 0, 0, NULL } },                      /* lower-case letters */
			{ { 'F', 0xffff, "Mirai" }, { 0, 0, NULL } },                         /* a reserved id */
			{ { 'F', 0x20000, "A" }, { 'F', 0x10001, "B" } },                     /* descending */
			{ { 'F', 0x20000, "A" }, { 'F', 0x20000, "B" } },                     /* a repeat */
			{ { 'X', 0x20000, "A" }, { 0, 0, NULL } },                            /* a kind that is not one */
			{ { 'T', 0x20000, "" }, { 0, 0, NULL } },                             /* an empty name */
		};
		unsigned b;

		for (b = 0; b < sizeof bads / sizeof bads[0]; b++) {
			uint8_t buf[300];
			size_t at = 16u, rows = 0, j;
			uint32_t crc;

			memset(buf, 0, sizeof buf);
			memcpy(buf, "KDNM", 4);
			buf[4] = 1;
			for (j = 0; j < 2u && bads[b][j].kind; j++) {
				size_t L = strlen(bads[b][j].name), q;

				buf[at++] = bads[b][j].kind;
				for (q = 0; q < 8u; q++)
					buf[at++] = (uint8_t)(bads[b][j].id >> (8u * q));
				buf[at++] = (uint8_t)L;
				memcpy(buf + at, bads[b][j].name, L);
				at += L;
				rows++;
			}
			buf[8] = (uint8_t)rows;
			crc = kof_crc32(buf + 16, at - 16u);
			for (j = 0; j < 4u; j++)
				buf[12 + j] = (uint8_t)(crc >> (8u * j));
			spit(npath(), buf, at);
			e = keng_open(db);
			CK(e && kdb_diagnoses(e) == 1u && kdb_diag_packs_refused(e) == 1u);
			if (e) {
				char nm[100];

				CK(kdb_family_name(e, 0x10001, nm, sizeof nm) == 0 && kdb_family_name(e, 0x20000, nm, sizeof nm) == 0);
				keng_close(e);
			}
		}
	}
	free(good);
}

/* ---- the sources are never touched ---------------------------------------------------------------------------------------------- */

static uint64_t hash_tree(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *de;
	uint64_t h = 1469598103934665603ull;
	char *names[4096];
	size_t n = 0, i;

	if (!d)
		return 0;
	while ((de = readdir(d)) != NULL && n < 4096u)
		if (strcmp(de->d_name, ".") && strcmp(de->d_name, ".."))
			names[n++] = strdup(de->d_name);
	closedir(d);
	for (i = 0; i < n; i++)
		for (size_t j = i + 1u; j < n; j++)
			if (strcmp(names[i], names[j]) > 0) {
				char *t = names[i];

				names[i] = names[j];
				names[j] = t;
			}
	for (i = 0; i < n; i++) {
		char p[600];
		struct stat st;
		const char *s;

		snprintf(p, sizeof p, "%s/%s", dir, names[i]);
		for (s = names[i]; *s; s++)
			h = (h ^ (uint8_t)*s) * 1099511628211ull;
		if (stat(p, &st) == 0 && S_ISDIR(st.st_mode)) {
			h = (h ^ hash_tree(p)) * 1099511628211ull;
		} else {
			size_t len = 0, q;
			uint8_t *b = slurp(p, &len);

			for (q = 0; b && q < len; q++)
				h = (h ^ b[q]) * 1099511628211ull;
			h = (h ^ len) * 1099511628211ull;
			free(b);
		}
		free(names[i]);
	}
	return h;
}

static void sources_untouched(void)
{
	char real[400];
	uint64_t before, after;
	size_t n = 0;
	uint8_t *raw;

	tree("real", 0);
	sh("rm -rf '%s/pathogens' '%s/syndromes' '%s/diagnoses'", base, base, base);
	snprintf(real, sizeof real, "%s", "bases");
	/* the owner's own catalogs and diagnoses, copied */
	sh("cp -r bases/pathogens '%s/pathogens'", base, "", "");
	sh("cp -r bases/syndromes '%s/syndromes'", base, "", "");
	sh("cp -r bases/diagnoses '%s/diagnoses'", base, "", "");
	before = hash_tree(base);
	CK(before != 0);
	CK(build() == 0);
	after = hash_tree(base);
	CK(before == after);
	if (before != after)
		printf("    a source changed during the build\n");
	/* and the build did what it is for: the names of the shipped diagnoses are in the file */
	raw = slurp(npath(), &n);
	CK(raw && n > 16u);
	free(raw);
	CK(build() == 0 && hash_tree(base) == before);                    /* twice */
}

int main(int argc, char **argv)
{
	if (argc > 1)
		dbdir = argv[1];
	snprintf(root, sizeof root, "build/test/namespack_%d", (int)getpid());
	if (kof_mkdir(root, 0700) != 0 || access(builder, X_OK) != 0) {
		printf("names_pack: cannot start\n");
		return 1;
	}
	build_and_engine();
	hostile();
	sources_untouched();
	sh("rm -rf '%s'", root, "", "");
	printf("names_pack: %s\n", fails ? "FAILED" : "all ok");
	return fails != 0;
}
