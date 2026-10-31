/*
 * verdict_catalog - the verdict made of the catalog facts of the matched diagnoses (family, variant, tag, ONE type each),
 * from the source line to the name a scan prints: ksigbuilder -> pack -> scan -> kof_vmatch -> kof_vdecide ->
 * kof_verdict_make_cat -> kof_result.verdict / kof_result.cat -> kdb_diagnose_* (what kofscanner -v shows).
 *
 * WHAT IS PINNED
 *   one          a lone diagnose names its (family, variant): "<Type>:F<8 hex>.V<8 hex>!Diagnose", cat.level VARIANT, cover 1000
 *   same variant two diagnoses of one variant with two tags: one matched is cover 500, both is 1000; the name is the same
 *   two families the group with the most of its variant seen leads (cover), then the more matched tags; n_groups says there were two
 *   variants     of one family: only the variant that matched is named
 *   types        each diagnose keeps its own type: the lowest leads, the other is the reason ("?Botnet")
 *   old model    a diagnose with a disease and no catalog facts is named as before; nothing matched = no verdict
 *   cap          more matched diagnoses than kof_vmatch takes (KOF_VMATCH_FIRED_MAX): the verdict is still made, the cut is
 *                said (cat.cut, kof_stats.limit_hits) and the total is true (cat.n_fired)
 *   decision     kof_vdecide alone: ties, only a diagnose with no variant (level TAG), a candidate past the profile bound
 *
 * NAMES (feat_names): the host hands the engine the two catalog directories (keng_catalog_load[_bases]) and the verdict reads
 * "<Family>.<Letter>" / the tag's name; an id the table does not hold stays hex.
 *   named        catalog loaded: ":Mirai.A!Diagnose"; kdb_family/variant/tag_name say 1 and the names; no catalog: hex, say 0
 *   partial      only pathogens: variant named, tag hex; only syndromes: "F<hex>.V<hex>", tag named; a catalog without the variant:
 *                "Mirai.V<hex>"
 *   hostile      a family or tag name with a separator of the verdict ('#', '.', ':', '/', ' ') or too long is a file the catalog's
 *                loader refuses: flagged FILES_REFUSED and spelled in hex; a 59-character family is named whole
 *   budget       a table that does not fit the engine's budget (cap 16 MiB) says OVER_BUDGET, charges what it holds (keng_memory_db),
 *                names what it read and spells the rest in hex; a second load replaces the first without growing the charge
 *   engines      two engines, two catalogs, each names with its own
 *   scanner      kofscanner --bases: the verdict and the -v lines carry names; without --bases hex
 * Why the old tests missed it (names): (a) nothing existed - the verdict had hex only, and no test read a name from a catalog.
 *
 * Why the old tests missed it: (a) nothing carried the facts into a verdict - on the old tree a diagnose with catalog facts and
 * no disease is read by nobody, so every scan case here has no verdict (RED).
 * A MUTANT proves the cases bite: see the report of the change (lead rule inverted, cover taken from the wrong kind).
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/verdictor/famcat.h"
#include "../../libkofeng/verdictor/tagcat.h"
#include "catid_oracle.h"
#include "../../libkofeng/verdictor/vmatch.h"
#include "../../libkofeng/verdictor/vdecide.h"
#include <kofmod/kofsig.h>

static int failures;
static char root[256];
static const char *dbdir = "build/test/databases-sigs";
static const char *builder = "build/release/bin/ksigbuilder";

#define OKF(cond, ...) do { if (!(cond)) { printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); failures++; } } while (0)

static int write_text(const char *path, const char *t)
{
	FILE *f = fopen(path, "wb");

	if (!f)
		return 0;
	fputs(t, f);
	return fclose(f) == 0;
}

static int copy_pack(const char *to_dir)
{
	char cmd[900];

	snprintf(cmd, sizeof cmd, "cp '%s/sigs-any.ksig' '%s/'", dbdir, to_dir);
	return system(cmd);
}

/* ---- the scene: catalogs (Mirai A/B, Gafgyt A; tags flood, c2, scan) and a tree of diagnoses ------------------------------- */

struct scene {
	char base[300], art[300], db[300], err[300];
	const char *famname;
	uint64_t mirai, mirai_a, mirai_b, gaf, gaf_a, flood, c2, scan;
};

static void write_catalogs(struct scene *s)
{
	struct kof_famcat_fam fam[8];
	struct kof_famcat_var var[16];
	struct kof_catstore *st = calloc(1, sizeof *st);
	struct kof_tagcat_tag *tag = calloc(1200, sizeof *tag);
	struct kof_tagcat tc;
	struct kof_famcat c;
	char dir[400];
	uint32_t f, v;

	snprintf(dir, sizeof dir, "%s/pathogens", s->base);
	kof_mkdir(dir, 0700);
	kof_famcat_init(&c, fam, 8, var, 16);
	kof_catstore_init(st);
	(void)kof_famcat_add_family(&c, s->famname, NULL, (1u << KOF_MALTYPE_BOTNET) | (1u << KOF_MALTYPE_ROOTKIT), &f);
	(void)kof_famcat_add_variant(&c, f, NULL, 1u << KOF_MALTYPE_BOTNET, 0, &v);
	(void)kof_famcat_add_family(&c, "Gafgyt", NULL, 1u << KOF_MALTYPE_BOTNET, &f);
	(void)kof_famcat_save(&c, st, dir);
	snprintf(dir, sizeof dir, "%s/syndromes", s->base);
	kof_mkdir(dir, 0700);
	kof_tagcat_init(&tc, tag, 1200);
	kof_catstore_init(st);
	(void)kof_tagcat_add(&tc, "flood", 1u << KOF_DISEASE_ACT_SCAN, 1u << KOF_DISEASE_OBJ_NETWORK, NULL);
	(void)kof_tagcat_add(&tc, "c2", 1u << KOF_DISEASE_ACT_C2, 1u << KOF_DISEASE_OBJ_NETWORK, NULL);
	(void)kof_tagcat_add(&tc, "scan", 1u << KOF_DISEASE_ACT_SCAN, 1u << KOF_DISEASE_OBJ_NETWORK, NULL);
	(void)kof_tagcat_save(&tc, st, dir);
	free(st);
	/* the ids the BUILD makes: computed here by the oracle (catid_oracle.h), which shares no code with the library, from the names alone */
	s->mirai = oracle_family(s->famname);
	s->mirai_a = oracle_variant(s->famname, "A");
	s->mirai_b = oracle_variant(s->famname, "B");
	s->gaf = oracle_family("Gafgyt");
	s->gaf_a = oracle_variant("Gafgyt", "A");
	s->flood = oracle_tag("flood");
	s->c2 = oracle_tag("c2");
	s->scan = oracle_tag("scan");
	free(tag);
}

static void scene_new_fam(struct scene *s, const char *tag, const char *famname)
{
	char d[400];

	memset(s, 0, sizeof *s);
	s->famname = famname;
	snprintf(s->base, sizeof s->base, "%s/%s_base", root, tag);
	snprintf(s->art, sizeof s->art, "%s/%s_art", root, tag);
	snprintf(s->db, sizeof s->db, "%s/%s_db", root, tag);
	snprintf(s->err, sizeof s->err, "%s/%s_err.txt", root, tag);
	kof_mkdir(s->base, 0700);
	kof_mkdir(s->art, 0700);
	kof_mkdir(s->db, 0700);
	snprintf(d, sizeof d, "%s/diagnoses", s->base);
	kof_mkdir(d, 0700);
	write_catalogs(s);
	(void)copy_pack(s->db);
}

static void scene_new(struct scene *s, const char *tag)
{
	scene_new_fam(s, tag, "Mirai");
}

/* A string-form diagnose: matches when the sample holds `word`. fam == NULL: a diagnose of the old model with a disease. */
static void diag_src(const struct scene *s, const char *name, const char *fam, const char *var, const char *type,
		     const char *tag, const char *word)
{
	char p[700], t[1500];
	size_t at;

	at = (size_t)snprintf(t, sizeof t, "KOF_DIAG_NAME(%s);\n", name);
	if (fam) {
		at += (size_t)snprintf(t + at, sizeof t - at, "KOF_DIAG_FAMILY(\"%s\");\nKOF_DIAG_VARIANT(\"%s\");\n"
				       "KOF_DIAG_TYPE(%s);\nKOF_DIAG_TAG(\"%s\");\n", fam, var, type, tag);
	} else {
		at += (size_t)snprintf(t + at, sizeof t - at, "KOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, \"old/model\");\n");
	}
	snprintf(t + at, sizeof t - at, "KOF_TARGET_RANGE(whole, KOF_SCAN_ALL);\n"
		 "KOF_DEFINE_STR(s0, \"%s\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\nKOF_DIAG_FIND(m0, KOF_FIND_ANY, whole, s0);\n", word);
	snprintf(p, sizeof p, "%s/diagnoses/%s.c", s->base, name);
	(void)write_text(p, t);
}

static int scene_build(const struct scene *s)
{
	char cmd[2400];

	int rc;

	snprintf(cmd, sizeof cmd, "%s --tree '%s' '%s' '%s' --pathogens '%s/pathogens' --syndromes '%s/syndromes' --basedir '%s' "
		 ">/dev/null 2>'%s'", builder, s->base, s->art, s->db, s->base, s->base, s->base, s->err);
	rc = system(cmd);
	/* THIS FILE TESTS THE HOST'S CATALOG (keng_catalog_load, --bases): its scenes must not find the names the build now writes into the database
	 * (names.kdig), or every "the catalog does not hold it, so hex" case would name it anyway. tests/unit/names_pack.c tests that file. */
	snprintf(cmd, sizeof cmd, "%s/names.kdig", s->db);
	(void)remove(cmd);
	return rc;
}

/* ---- scanning ------------------------------------------------------------------------------------------------------- */

struct seen {
	int      has;
	char     name[240];
	struct kof_verdict_cat cat;
	uint32_t n_diag;
	uint32_t diag[KOF_VERDICT_TRACE];
	uint8_t  broken;
	uint64_t limit_hits;
	/* the engine's own text of the lead's ids (kdb_*_name) and whether the catalog named each */
	char     fam_txt[100], var_txt[100], tag_txt[100];
	int      fam_named, var_named, tag_named;
	uint32_t cat_flags;
	struct keng_catalog_info cat_info;
	uint64_t mem_db;
};

static int on_object(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct seen *s = user;

	(void)name; (void)bytes; (void)len;
	if (res && res->has_verdict && !s->has) {
		s->has = 1;
		snprintf(s->name, sizeof s->name, "%s", res->verdict.name);
		s->cat = res->cat;
		s->n_diag = res->verdict.n_diag;
		memcpy(s->diag, res->verdict.diag, sizeof s->diag);
	}
	if (res && res->broken)
		s->broken = (uint8_t)res->broken;
	return 0;
}

/* One scan on an engine of its own; `pathogens` / `syndromes` (either may be NULL) are the catalog directories it is given first. */
static void scan_cat(const struct scene *s, const char *text, const char *pathogens, const char *syndromes, struct seen *out)
{
	kof_engine *eng = keng_open(s->db);
	kof_scanner *scn;
	struct kof_scan_option opt;

	memset(out, 0, sizeof *out);
	memset(&opt, 0, sizeof opt);
	if (!eng) {
		OKF(0, "the database does not open");
		return;
	}
	if (pathogens || syndromes)
		out->cat_flags = keng_catalog_load(eng, pathogens, syndromes);
	keng_catalog_info(eng, &out->cat_info);
	out->mem_db = keng_memory_db(eng);
	scn = kscan_new(eng);
	if (!scn) {
		OKF(0, "the scanner is not made");
		keng_close(eng);
		return;
	}
	kscan_bytes(scn, text, strlen(text), "sample", &opt, on_object, out);
	out->limit_hits = kscan_stats(scn)->limit_hits;
	out->fam_named = kdb_family_name(eng, out->cat.family_id, out->fam_txt, sizeof out->fam_txt);
	out->var_named = kdb_variant_name(eng, out->cat.variant_id, out->var_txt, sizeof out->var_txt);
	out->tag_named = kdb_tag_name(eng, out->cat.tag_id, out->tag_txt, sizeof out->tag_txt);
	kscan_free(scn);
	keng_close(eng);
}

static void scan(const struct scene *s, const char *text, struct seen *out)
{
	scan_cat(s, text, NULL, NULL, out);
}

/* The name one lead should have: the engine's own spelling of the ids. */
static void want_name(char *out, size_t cap, const char *type, uint64_t fam, uint64_t var, const char *reason)
{
	char a[12], b[12];

	kverdict_catalog_word(a, sizeof a, fam);
	kverdict_catalog_word(b, sizeof b, var);
	snprintf(out, cap, ":F%s.V%s!Diagnose%s%s", a, b, reason ? "?" : "", reason ? reason : "");
	(void)type;
}

static int name_ends(const struct seen *x, const char *type, const char *tail)
{
	char head[40];
	const char *p;

	snprintf(head, sizeof head, "/%s", type);
	p = strstr(x->name, head);
	return x->has && strncmp(x->name, "Infected#", 9) == 0 && p && strcmp(p + strlen(head), tail) == 0;
}

static void case_one(void)
{
	struct scene s;
	struct seen x;
	char tail[100];

	scene_new(&s, "one");
	diag_src(&s, "d_one", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood", "alpha");
	OKF(scene_build(&s) == 0, "one: the tree builds");
	scan(&s, "xx alpha yy", &x);
	want_name(tail, sizeof tail, "Botnet", s.mirai, s.mirai_a, NULL);
	OKF(name_ends(&x, "Botnet", tail), "one: the verdict names the variant (%s)", x.has ? x.name : "no verdict");
	OKF(x.cat.level == KOF_VCAT_VARIANT && x.cat.cover == 1000 && x.cat.n_groups == 1 && x.cat.n_fired == 1,
	    "one: level %u cover %u groups %u fired %u", x.cat.level, x.cat.cover, x.cat.n_groups, x.cat.n_fired);
	OKF(x.cat.family_id == s.mirai && x.cat.variant_id == s.mirai_a && x.cat.tag_id == s.flood && x.cat.type == KOF_MALTYPE_BOTNET,
	    "one: the ids and the type of the lead are the pack's");
	OKF(x.n_diag == 1, "one: the verdict lists its diagnose");
	scan(&s, "nothing here", &x);
	OKF(!x.has, "one: a sample with nothing matched has no verdict");
}

static void case_same_variant(void)
{
	struct scene s;
	struct seen x;
	char tail[100];

	scene_new(&s, "samevar");
	diag_src(&s, "d_a", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood", "alpha");
	diag_src(&s, "d_b", "Mirai", "A", "KOF_MALTYPE_BOTNET", "c2", "beta");
	OKF(scene_build(&s) == 0, "samevar: the tree builds");
	want_name(tail, sizeof tail, "Botnet", s.mirai, s.mirai_a, NULL);
	scan(&s, "alpha", &x);
	OKF(name_ends(&x, "Botnet", tail) && x.cat.cover == 500 && x.cat.n_fired == 1, "samevar: one of two tags is cover 500 (%u)", x.cat.cover);
	OKF(x.cat.tag_id == s.flood, "samevar: the lead tag is the matched one");
	scan(&s, "alpha beta", &x);
	OKF(name_ends(&x, "Botnet", tail) && x.cat.cover == 1000 && x.cat.n_fired == 2 && x.n_diag == 2,
	    "samevar: both tags is cover 1000 (%u), 2 fired", x.cat.cover);
}

static void case_two_families(void)
{
	struct scene s;
	struct seen x;
	char tail[100];

	scene_new(&s, "twofam");
	diag_src(&s, "m_a", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood", "alpha");
	diag_src(&s, "m_b", "Mirai", "A", "KOF_MALTYPE_BOTNET", "c2", "beta");
	diag_src(&s, "g_a", "Gafgyt", "A", "KOF_MALTYPE_BOTNET", "scan", "gamma");
	OKF(scene_build(&s) == 0, "twofam: the tree builds");
	scan(&s, "alpha gamma", &x);	/* Mirai 1 of 2 tags (500), Gafgyt 1 of 1 (1000) */
	want_name(tail, sizeof tail, "Botnet", s.gaf, s.gaf_a, NULL);
	OKF(name_ends(&x, "Botnet", tail) && x.cat.n_groups == 2 && x.cat.cover == 1000,
	    "twofam: the variant with the most of itself seen leads (%s, groups %u)", x.name, x.cat.n_groups);
	scan(&s, "alpha beta gamma", &x);	/* both 1000: more matched tags leads */
	want_name(tail, sizeof tail, "Botnet", s.mirai, s.mirai_a, NULL);
	OKF(name_ends(&x, "Botnet", tail) && x.cat.n_groups == 2 && x.cat.n_fired == 3,
	    "twofam: a tie on cover goes to the group with more matched tags (%s)", x.name);
}

static void case_variants_and_types(void)
{
	struct scene s;
	struct seen x;
	char tail[100];

	scene_new(&s, "vartype");
	diag_src(&s, "v_a", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood", "alpha");
	diag_src(&s, "v_b", "Mirai", "B", "KOF_MALTYPE_BOTNET", "flood", "beta");
	diag_src(&s, "v_rk", "Mirai", "A", "KOF_MALTYPE_ROOTKIT", "c2", "gamma");
	OKF(scene_build(&s) == 0, "vartype: the tree builds");
	scan(&s, "beta", &x);
	want_name(tail, sizeof tail, "Botnet", s.mirai, s.mirai_b, NULL);
	OKF(name_ends(&x, "Botnet", tail) && x.cat.n_groups == 1, "vartype: only the variant that matched is named (%s)", x.name);
	scan(&s, "alpha gamma", &x);
	want_name(tail, sizeof tail, "Rootkit", s.mirai, s.mirai_a, "Botnet");
	OKF(name_ends(&x, "Rootkit", tail) && x.cat.type == KOF_MALTYPE_ROOTKIT,
	    "vartype: each diagnose keeps its own type, the lowest leads, the other is the reason (%s)", x.name);
}

static void case_old_model(void)
{
	struct scene s;
	struct seen x;

	scene_new(&s, "old");
	diag_src(&s, "o_dis", NULL, NULL, NULL, NULL, "omega");
	diag_src(&s, "n_new", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood", "alpha");
	OKF(scene_build(&s) == 0, "old: the tree builds");
	scan(&s, "omega", &x);
	OKF(x.has && strstr(x.name, "/Trojan:old.model") && x.cat.level == KOF_VCAT_NONE, "old: a disease-only diagnose is named as before (%s)", x.name);
	scan(&s, "omega alpha", &x);
	OKF(x.has && strstr(x.name, ":F") && x.n_diag == 2, "old: both matched: the catalog names it, both diagnoses are listed (%s)", x.name);
}

/* More matched diagnoses than kof_vmatch takes: the same family, variant and tag, so the profile stays one tag (and a word of its own each). */
static void case_cap(void)
{
	struct scene s;
	struct seen x;
	char name[40], tail[100];
	unsigned i, n = KOF_VMATCH_FIRED_MAX + 6u;
	char *sample = calloc(n, 8);	/* every diagnose has a word of its own (identical sources collide in the builder) */
	char word[16];

	scene_new(&s, "cap");
	for (i = 0; i < n; i++) {
		snprintf(name, sizeof name, "c_%04u", i);
		snprintf(word, sizeof word, "w%04u", i);
		strcat(sample, word);
		strcat(sample, " ");
		diag_src(&s, name, "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood", word);
	}
	OKF(scene_build(&s) == 0, "cap: the tree builds");
	scan(&s, sample, &x);
	free(sample);
	want_name(tail, sizeof tail, "Botnet", s.mirai, s.mirai_a, NULL);
	OKF(name_ends(&x, "Botnet", tail), "cap: the verdict is still made past the bound (%s)", x.has ? x.name : "none");
	OKF(x.cat.cut == 1 && x.cat.n_fired == n && x.limit_hits >= 1u,
	    "cap: the cut is said (cut %u, true total %u of %u, limit_hits %u)", x.cat.cut, x.cat.n_fired, n, (unsigned)x.limit_hits);
	OKF(x.n_diag == KOF_VERDICT_TRACE, "cap: the trace is bounded");
}


/* ---- the names -------------------------------------------------------------------------------------------------------------- */

static void dirs_of(const struct scene *s, char *path, char *syn, size_t cap)
{
	snprintf(path, cap, "%s/pathogens", s->base);
	snprintf(syn, cap, "%s/syndromes", s->base);
}

static void hex_of(char *out, size_t cap, uint64_t id)
{
	kverdict_catalog_word(out, cap, id);
}

/* Copy every *.c of `from` into `to` (made), replacing the first `a` of each by `b`; the number of files that held `a`. */
static int patch_dir(const char *from, const char *to, const char *a, const char *b)
{
	DIR *d = opendir(from);
	struct dirent *de;
	int hit = 0;

	kof_mkdir(to, 0700);
	while (d && (de = readdir(d)) != NULL) {
		char in[600], out[600], *buf = calloc(1, 300000), *at;
		FILE *f;
		size_t n;

		if (de->d_name[0] == '.' || !buf) {
			free(buf);
			continue;
		}
		snprintf(in, sizeof in, "%s/%s", from, de->d_name);
		snprintf(out, sizeof out, "%s/%s", to, de->d_name);
		f = fopen(in, "rb");
		n = f ? fread(buf, 1, 299000, f) : 0;
		if (f)
			fclose(f);
		f = fopen(out, "wb");
		at = a ? strstr(buf, a) : NULL;
		if (f && at) {
			fwrite(buf, 1, (size_t)(at - buf), f);
			fputs(b, f);
			fwrite(at + strlen(a), 1, n - (size_t)(at - buf) - strlen(a), f);
			hit++;
		} else if (f) {
			fwrite(buf, 1, n, f);
		}
		if (f)
			fclose(f);
		free(buf);
	}
	if (d)
		closedir(d);
	return hit;
}

/* Copy `from` into `to`, dropping every line that holds `drop`. */
static void drop_lines(const char *from, const char *to, const char *drop)
{
	DIR *d = opendir(from);
	struct dirent *de;

	kof_mkdir(to, 0700);
	while (d && (de = readdir(d)) != NULL) {
		char in[600], out[600], line[2000];
		FILE *f, *g;

		if (de->d_name[0] == '.')
			continue;
		snprintf(in, sizeof in, "%s/%s", from, de->d_name);
		snprintf(out, sizeof out, "%s/%s", to, de->d_name);
		f = fopen(in, "rb");
		g = fopen(out, "wb");
		while (f && g && fgets(line, sizeof line, f))
			if (!strstr(line, drop))
				fputs(line, g);
		if (f)
			fclose(f);
		if (g)
			fclose(g);
	}
	if (d)
		closedir(d);
}

static void case_named(void)
{
	struct scene s;
	struct seen x, y;
	char p[400], t[400], hf[12], hv[12], ht[12], want[200];

	scene_new(&s, "named");
	diag_src(&s, "d_one", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood", "alpha");
	OKF(scene_build(&s) == 0, "named: the tree builds");
	dirs_of(&s, p, t, sizeof p);
	scan_cat(&s, "xx alpha yy", p, t, &x);
	OKF(x.cat_flags == 0 && x.cat_info.families == 2 && x.cat_info.variants == 3 && x.cat_info.tags == 3 && x.cat_info.bytes > 0,
	    "named: the catalog loads whole (flags %u, %u families, %u variants, %u tags)", x.cat_flags, x.cat_info.families,
	    x.cat_info.variants, x.cat_info.tags);
	OKF(name_ends(&x, "Botnet", ":Mirai.A!Diagnose"), "named: the verdict says Mirai.A (%s)", x.has ? x.name : "none");
	OKF(x.cat.family_id == s.mirai && x.cat.variant_id == s.mirai_a && x.cat.tag_id == s.flood, "named: the ids are the pack's, the name is not");
	OKF(x.fam_named == 1 && !strcmp(x.fam_txt, "Mirai") && x.var_named == 1 && !strcmp(x.var_txt, "Mirai.A") && x.tag_named == 1 &&
	    !strcmp(x.tag_txt, "flood"), "named: kdb_*_name (%s %s %s)", x.fam_txt, x.var_txt, x.tag_txt);
	/* no catalog: hex, as before, and the text functions say so */
	scan(&s, "xx alpha yy", &y);
	hex_of(hf, sizeof hf, s.mirai);
	hex_of(hv, sizeof hv, s.mirai_a);
	hex_of(ht, sizeof ht, s.flood);
	snprintf(want, sizeof want, ":F%s.V%s!Diagnose", hf, hv);
	OKF(name_ends(&y, "Botnet", want), "named: without a catalog the name is hex (%s)", y.has ? y.name : "none");
	OKF(y.fam_named == 0 && !strcmp(y.fam_txt, hf) && y.var_named == 0 && !strcmp(y.var_txt, hv) && y.tag_named == 0 && !strcmp(y.tag_txt, ht),
	    "named: without a catalog kdb_*_name answers 0 and the hex word");
	/* the engine always holds a table now (the database's own names answer through it): empty, a few hundred bytes, no family */
	OKF(y.cat_info.bytes < 1024u && y.cat_info.families == 0, "named: no catalog costs next to nothing (%llu bytes)", (unsigned long long)y.cat_info.bytes);
	/* same verdict, the difference is the name only */
	OKF(x.cat.cover == y.cat.cover && x.n_diag == y.n_diag && x.cat.level == y.cat.level, "named: the catalog changes the name and nothing else");
}

static void case_partial(void)
{
	struct scene s;
	struct seen x;
	char p[400], t[400], q[400], hf[12], hv[12], want[200];

	scene_new(&s, "partial");
	diag_src(&s, "d_one", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood", "alpha");
	OKF(scene_build(&s) == 0, "partial: the tree builds");
	dirs_of(&s, p, t, sizeof p);
	hex_of(hf, sizeof hf, s.mirai);
	hex_of(hv, sizeof hv, s.mirai_a);
	scan_cat(&s, "alpha", p, NULL, &x);
	OKF(name_ends(&x, "Botnet", ":Mirai.A!Diagnose") && x.tag_named == 0 && x.cat_flags == 0, "partial: pathogens only: the variant is named, the tag is hex (%s)", x.name);
	scan_cat(&s, "alpha", NULL, t, &x);
	snprintf(want, sizeof want, ":F%s.V%s!Diagnose", hf, hv);
	OKF(name_ends(&x, "Botnet", want) && x.tag_named == 1 && !strcmp(x.tag_txt, "flood"),
	    "partial: syndromes only: the family and variant are hex, the tag is named (%s)", x.name);
	/* a catalog that holds the family and not the variant */
	snprintf(q, sizeof q, "%s/cut_pathogens", s.base);
	drop_lines(p, q, "\"A\"");
	scan_cat(&s, "alpha", q, t, &x);
	snprintf(want, sizeof want, ":Mirai.V%s!Diagnose", hv);
	OKF(name_ends(&x, "Botnet", want) && x.fam_named == 1 && x.var_named == 0, "partial: the family named, the variant not: %s (%s)", want, x.name);
	/* a directory that does not exist is an empty catalog, not an error */
	snprintf(q, sizeof q, "%s/nowhere", s.base);
	scan_cat(&s, "alpha", q, q, &x);
	OKF(x.cat_flags == 0 && x.cat_info.families == 0 && strstr(x.name, ":F"), "partial: a missing directory is an empty catalog");
}

static void case_hostile(void)
{
	static const char *bad_fam[] = { "Mir#ai", "Mir.ai", "Mir:ai", "Mir/ai", "Mir ai", "Mir!ai", "Mir?ai",
		"Mirai0123456789012345678901234567890123456789012345678901234567890" };
	static const char *bad_tag[] = { "fl.ood", "fl:ood", "fl#ood", "fl/ood", "fl ood", "fl_ood", "fl?ood", "fl!ood" };
	struct scene s;
	struct seen x;
	char p[400], t[400], q[400], r[400], rep[100];
	unsigned i;

	scene_new(&s, "hostile");
	diag_src(&s, "d_one", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood", "alpha");
	OKF(scene_build(&s) == 0, "hostile: the tree builds");
	dirs_of(&s, p, t, sizeof p);
	for (i = 0; i < sizeof bad_fam / sizeof *bad_fam; i++) {
		snprintf(q, sizeof q, "%s/bf%u", s.base, i);
		snprintf(rep, sizeof rep, "KOF_MALWARE_FAMILY_NAME(\"%s\")", bad_fam[i]);
		OKF(patch_dir(p, q, "KOF_MALWARE_FAMILY_NAME(\"Mirai\")", rep) == 1, "hostile: the family file is patched (%u)", i);
		scan_cat(&s, "alpha", q, t, &x);
		OKF((x.cat_flags & KENG_CAT_FILES_REFUSED) && x.cat_info.files_refused >= 1 && x.fam_named == 0 && x.var_named == 0 &&
		    strstr(x.name, ":F") && !strstr(x.name, bad_fam[i]),
		    "hostile: family name '%s' is refused and spelled in hex (flags %u, %s)", bad_fam[i], x.cat_flags, x.name);
	}
	for (i = 0; i < sizeof bad_tag / sizeof *bad_tag; i++) {
		snprintf(r, sizeof r, "%s/bt%u", s.base, i);
		snprintf(rep, sizeof rep, "KOF_TAG_NAME(\"%s\")", bad_tag[i]);
		OKF(patch_dir(t, r, "KOF_TAG_NAME(\"flood\")", rep) == 1, "hostile: the tag file is patched (%u)", i);
		scan_cat(&s, "alpha", p, r, &x);
		OKF((x.cat_flags & KENG_CAT_FILES_REFUSED) && x.tag_named == 0 && !strstr(x.tag_txt, bad_tag[i]),
		    "hostile: tag name '%s' is refused and spelled in hex (flags %u, '%s')", bad_tag[i], x.cat_flags, x.tag_txt);
	}
	/* the other way round: a name that is legal is not refused (upper case, digit, hyphen, underscore in a family). The id is made from the
	 * name, so the pack is built from sources that already carry it: a rename after the build is a new id and the old pack's id is
	 * unknown to the host's catalog (pinned by case_renamed). */
	scene_new_fam(&s, "hostile_ok", "Mi_rai-9X");
	diag_src(&s, "d_one", "Mi_rai-9X", "A", "KOF_MALTYPE_BOTNET", "flood", "alpha");
	OKF(scene_build(&s) == 0, "hostile: the tree with the legal name builds");
	dirs_of(&s, p, t, sizeof p);
	scan_cat(&s, "alpha", p, t, &x);
	OKF(x.cat_flags == 0 && name_ends(&x, "Botnet", ":Mi_rai-9X.A!Diagnose"), "hostile: a legal name is used whole (%s)", x.name);
}

/* THE CONSEQUENCE OF AN ID MADE FROM THE NAME: a pack built for "Mirai" and a catalog in which the family was renamed afterwards do not
 * agree, and the verdict says so in the one way it always says an id the catalog does not hold (hex); rebuilding from the renamed
 * sources makes them agree again. A rename in letter case only changes nothing. */
static void case_renamed(void)
{
	struct scene s;
	struct seen x;
	char p[400], t[400], q[400];

	scene_new(&s, "renamed");
	diag_src(&s, "d_one", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood", "alpha");
	OKF(scene_build(&s) == 0, "renamed: the tree builds");
	dirs_of(&s, p, t, sizeof p);
	snprintf(q, sizeof q, "%s/renamed", s.base);
	OKF(patch_dir(p, q, "KOF_MALWARE_FAMILY_NAME(\"Mirai\")", "KOF_MALWARE_FAMILY_NAME(\"Mirai2\")") == 1, "renamed: the family file is patched");
	scan_cat(&s, "alpha", q, t, &x);
	OKF(x.cat_flags == 0 && x.fam_named == 0 && x.var_named == 0 && strstr(x.name, ":F"), "renamed: the old id is not named by the renamed catalog (%s)", x.name);
	snprintf(q, sizeof q, "%s/recase", s.base);
	OKF(patch_dir(p, q, "KOF_MALWARE_FAMILY_NAME(\"Mirai\")", "KOF_MALWARE_FAMILY_NAME(\"MIRAI\")") == 1, "renamed: the family file is recased");
	scan_cat(&s, "alpha", q, t, &x);
	OKF(x.cat_flags == 0 && x.fam_named == 1 && name_ends(&x, "Botnet", ":MIRAI.A!Diagnose"), "renamed: a case-only rename keeps every id (%s)", x.name);
}

static void case_maxlen(void)
{
	struct scene s;
	struct seen x;
	char fam[80], p[400], t[400], want[120];

	/* 59: with the builder's table (8192 variants, three letters) the longest family is 59, the rule of famcat.h */
	memset(fam, 'x', 59);
	fam[0] = 'M';
	fam[59] = 0;
	scene_new_fam(&s, "maxlen", fam);
	diag_src(&s, "d_one", fam, "A", "KOF_MALTYPE_BOTNET", "flood", "alpha");
	OKF(scene_build(&s) == 0, "maxlen: the tree builds");
	dirs_of(&s, p, t, sizeof p);
	scan_cat(&s, "alpha", p, t, &x);
	snprintf(want, sizeof want, ":%s.A!Diagnose", fam);
	OKF(name_ends(&x, "Botnet", want) && !x.cat_flags, "maxlen: a 59-character family is named whole (%s)", x.has ? x.name : "none");
	OKF(strlen(x.var_txt) == 61 && x.var_named == 1, "maxlen: kdb_variant_name holds it (%zu)", strlen(x.var_txt));
	/* a buffer that is too small is cut and still terminated */
	{
		kof_engine *e = keng_open(s.db);
		char tiny[8];

		OKF(e != NULL, "maxlen: the engine opens");
		if (e) {
			keng_catalog_load(e, p, t);
			OKF(kdb_variant_name(e, s.mirai_a, tiny, sizeof tiny) == 1 && strlen(tiny) == 7 && !strncmp(tiny, "Mxxxxxx", 7), "maxlen: cut at cap, terminated");
			OKF(kdb_variant_name(e, s.mirai_a, tiny, 0) == 0, "maxlen: cap 0 writes nothing");
			keng_close(e);
		}
	}
}

/* A tag catalog bigger than the engine's budget lets the table be: degraded, said, charged, and the ids it read are still named. */
static void case_budget(void)
{
	struct scene s;
	struct seen x;
	char p[400], t[400], big[400], f[500], line[400];
	unsigned i, n, files;
	uint64_t cap = 16ull << 20, room;
	kof_engine *e;
	struct keng_catalog_info a, b;
	uint64_t empty;
	uint64_t db0, db1;

	scene_new(&s, "budget");
	diag_src(&s, "d_one", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood", "alpha");
	OKF(scene_build(&s) == 0, "budget: the tree builds");
	dirs_of(&s, p, t, sizeof p);
	e = keng_open(s.db);
	if (!e) {
		OKF(0, "budget: the engine opens");
		return;
	}
	OKF(keng_set_memory_cap(e, cap) == 1, "budget: the cap is set");
	db0 = keng_memory_db(e);
	keng_catalog_info(e, &a);                 /* the engine always holds a table, empty until a catalog is loaded: its own bytes are in db0 */
	empty = a.bytes;
	room = (cap - db0) / 8u;
	/* more tags than the table that fits can hold: the largest power-of-two table that fits is more than half of `room` */
	n = (unsigned)(room / sizeof(struct kof_tagcat_tag)) + 600u;
	snprintf(big, sizeof big, "%s/bigtags", s.base);
	kof_mkdir(big, 0700);
	for (files = 0; files * 1000u < n; files++) {
		FILE *fp;

		snprintf(f, sizeof f, "%s/t%03u.c", big, files);
		fp = fopen(f, "wb");
		for (i = files * 1000u; fp && i < (files + 1u) * 1000u && i < n; i++) {
			snprintf(line, sizeof line, "KOF_TAG_NAME(\"T%05u\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n"
				 "KOF_TAG_OBJS(KOF_DISEASE_OBJ_NETWORK);\n\n", i);
			fputs(line, fp);
		}
		if (fp)
			fclose(fp);
	}
	b.flags = keng_catalog_load(e, NULL, big);
	keng_catalog_info(e, &a);
	db1 = keng_memory_db(e);
	OKF((b.flags & KENG_CAT_OVER_BUDGET) && (b.flags & KENG_CAT_FILES_REFUSED), "budget: said OVER_BUDGET and FILES_REFUSED (flags %u)", b.flags);
	OKF(a.files_refused >= 1u && a.tags > 0u && a.tags < n, "budget: %u of %u tags read, %u file(s) left", a.tags, n, a.files_refused);
	OKF(a.bytes <= room + 4096u, "budget: the table stays under an eighth of what is left (%llu of %llu)", (unsigned long long)a.bytes, (unsigned long long)room);
	OKF(db1 - db0 + empty == a.bytes, "budget: what the table holds is charged to the engine (%llu + %llu vs %llu)", (unsigned long long)(db1 - db0), (unsigned long long)empty, (unsigned long long)a.bytes);
	{
		char nm[100], tname[16];
		unsigned named = 0;

		OKF(kdb_tag_name(e, oracle_tag("T00000"), nm, sizeof nm) == 1 && !strcmp(nm, "T00000"), "budget: an id of a file that was read is named (%s)", nm);
		/* a file that does not fit is refused whole, a later small one may still fit: so count, tag by tag, which ids the table names */
		for (i = 0; i < n; i++) {
			snprintf(tname, sizeof tname, "T%05u", i);
			named += (unsigned)kdb_tag_name(e, oracle_tag(tname), nm, sizeof nm);
		}
		OKF(named == a.tags && named < n, "budget: exactly the %u tags that were read are named, the %u left unread are hex (%u named)", a.tags, n - a.tags, named);
	}
	/* loading again replaces the table: the charge does not grow, and an empty load gives it all back */
	(void)keng_catalog_load(e, NULL, big);
	OKF(keng_memory_db(e) == db1, "budget: a second load does not add to the charge");
	(void)keng_catalog_load(e, NULL, NULL);
	OKF(keng_memory_db(e) == db0, "budget: an empty load gives the charge back (%llu vs %llu)", (unsigned long long)keng_memory_db(e), (unsigned long long)db0);
	keng_close(e);
	/* the engine without the cap set is unaffected */
	scan_cat(&s, "alpha", p, t, &x);
	OKF(x.cat_flags == 0 && name_ends(&x, "Botnet", ":Mirai.A!Diagnose"), "budget: the default budget names it");
}

static void case_engines(void)
{
	struct scene s;
	char p[400], t[400], p2[400];
	kof_engine *e1, *e2;
	kof_scanner *s1, *s2;
	struct kof_scan_option opt;
	struct seen x1, x2;
	const char *text = "alpha";

	scene_new(&s, "engines");
	diag_src(&s, "d_one", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood", "alpha");
	OKF(scene_build(&s) == 0, "engines: the tree builds");
	dirs_of(&s, p, t, sizeof p);
	snprintf(p2, sizeof p2, "%s/pathogens2", s.base);
	OKF(patch_dir(p, p2, "KOF_MALWARE_FAMILY_NAME(\"Mirai\")", "KOF_MALWARE_FAMILY_NAME(\"Hajime\")") == 1, "engines: the second catalog is made");
	e1 = keng_open(s.db);
	e2 = keng_open(s.db);
	OKF(e1 && e2, "engines: two engines open");
	if (!e1 || !e2) {
		keng_close(e1);
		keng_close(e2);
		return;
	}
	(void)keng_catalog_load(e1, p, t);
	(void)keng_catalog_load(e2, p2, NULL);
	s1 = kscan_new(e1);
	s2 = kscan_new(e2);
	memset(&x1, 0, sizeof x1);
	memset(&x2, 0, sizeof x2);
	memset(&opt, 0, sizeof opt);
	if (s1 && s2) {
		kscan_bytes(s1, text, strlen(text), "sample", &opt, on_object, &x1);
		kscan_bytes(s2, text, strlen(text), "sample", &opt, on_object, &x2);
		OKF(name_ends(&x1, "Botnet", ":Mirai.A!Diagnose"), "engines: the first names its own catalog (%s)", x1.name);
		/* the pack's ids are Mirai's: the second engine's catalog holds Hajime, so it does not know them (hex) */
		OKF(strstr(x2.name, ":F") && !strstr(x2.name, "Mirai") && !strstr(x2.name, "Hajime"), "engines: the second does not know the pack's ids (%s)", x2.name);
	} else {
		OKF(0, "engines: the scanners are made");
	}
	/* closing one does not touch the other */
	kscan_free(s1);
	keng_close(e1);
	{
		char nm[100];

		OKF(kdb_variant_name(e2, oracle_variant("Hajime", "A"), nm, sizeof nm) == 1 && !strcmp(nm, "Hajime.A"), "engines: the other still names its own (%s)", nm);
		OKF(kdb_variant_name(e2, s.mirai_a, nm, sizeof nm) == 0, "engines: and still does not know the first's (%s)", nm);
	}
	kscan_free(s2);
	keng_close(e2);
}

/* kofscanner --bases: the engine names, the tool prints. */
static char *run_scanner(const char *cmd)
{
	FILE *f = popen(cmd, "r");
	char *buf = calloc(1, 20000);
	size_t n = 0, r;

	while (f && buf && n < 19999 && (r = fread(buf + n, 1, 19999 - n, f)) > 0)
		n += r;
	if (f)
		pclose(f);
	return buf;
}

static void case_scanner(void)
{
	struct scene s;
	char file[400], cmd[1600], p[400], t[400], hf[12], hv[12], hex_line[200];
	char *out;

	scene_new(&s, "tool");
	diag_src(&s, "d_one", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood", "alpha");
	OKF(scene_build(&s) == 0, "tool: the tree builds");
	dirs_of(&s, p, t, sizeof p);
	snprintf(file, sizeof file, "%s/sample.txt", s.base);
	(void)write_text(file, "xx alpha yy");
	snprintf(cmd, sizeof cmd, "ulimit -v 4194304; build/release/bin/kofscanner --db '%s' --bases '%s' --no-cache -v --scan-files '%s' 2>&1", s.db, s.base, file);
	out = run_scanner(cmd);
	OKF(out && strstr(out, ":Mirai.A!Diagnose"), "tool: --bases: the verdict line names the variant");
	OKF(out && strstr(out, "family=Mirai variant=Mirai.A tag=flood"), "tool: --bases: -v lists the diagnose's family, variant and tag by name");
	OKF(out && strstr(out, "basis variant family=Mirai variant=Mirai.A tag=flood"), "tool: --bases: the basis line is by name");
	free(out);
	snprintf(cmd, sizeof cmd, "ulimit -v 4194304; build/release/bin/kofscanner --db '%s' --no-cache -v --scan-files '%s' 2>&1", s.db, file);
	out = run_scanner(cmd);
	hex_of(hf, sizeof hf, s.mirai);
	hex_of(hv, sizeof hv, s.mirai_a);
	snprintf(hex_line, sizeof hex_line, ":F%s.V%s!Diagnose", hf, hv);
	OKF(out && strstr(out, hex_line) && !strstr(out, "Mirai"), "tool: without --bases the same ids are hex");
	free(out);
	snprintf(cmd, sizeof cmd, "ulimit -v 4194304; build/release/bin/kofscanner --db '%s' --bases '%s/nowhere' --no-cache -v --scan-files '%s' 2>&1", s.db, s.base, file);
	out = run_scanner(cmd);
	OKF(out && strstr(out, hex_line), "tool: --bases with no catalog in it: hex");
	free(out);
}

/* ---- kof_vdecide alone ------------------------------------------------------------------------------------------------------ */

static void decide(const struct kof_vmatch_fired *f, uint32_t nf, const struct kof_vmatch_cand *c, uint32_t nc, struct kof_vdecision *d,
		   struct kof_vmatch_group *g, struct kof_vmatch_entry *e)
{
	struct kof_vmatch_score sc[8];
	struct kof_vmatch_req rq;
	struct kof_vmatch_res res;

	memset(&rq, 0, sizeof rq);
	rq.fired = f;
	rq.n_fired = nf;
	rq.cand = c;
	rq.n_cand = nc;
	rq.x_kinds = 7u;
	rq.group = g;
	rq.group_cap = 8;
	rq.entry = e;
	rq.entry_cap = 8;
	rq.score = sc;
	rq.score_cap = 8;
	kof_vmatch(&rq, &res);
	OKF(res.status == KOF_VMATCH_OK || res.status == KOF_VMATCH_TRUNCATED || (res.status == KOF_VMATCH_TOO_LARGE && res.n_groups), "decide: vmatch answered (the element lists are not asked for)");
	kof_vdecide(&res, g, e, sc, d);
}

static void case_decide(void)
{
	struct kof_vmatch_group g[8];
	struct kof_vmatch_entry e[8];
	struct kof_vdecision d;
	static struct kof_vmatch_elem big[KOF_VMATCH_SET_MAX + 1u];
	const struct kof_vmatch_elem pa[] = { { KOF_VMATCH_TAG, 1, 0 }, { KOF_VMATCH_TAG, 2, 0 } };
	const struct kof_vmatch_elem pb[] = { { KOF_VMATCH_TAG, 3, 0 } };
	struct kof_vmatch_cand c[2];
	struct kof_vmatch_fired f[3];
	uint32_t i;

	/* nothing fired: no level */
	memset(f, 0, sizeof f);
	decide(f, 0, NULL, 0, &d, g, e);
	OKF(d.level == KOF_VCAT_NONE && d.lead_group == KOF_VMATCH_NONE, "decide: nothing fired, no lead");
	/* only a diagnose with no variant: level TAG, its tag and type, no cover */
	f[0].diag = 7; f[0].tag = 5; f[0].type = KOF_MALTYPE_MINER; f[0].has_variant = 0;
	decide(f, 1, NULL, 0, &d, g, e);
	OKF(d.level == KOF_VCAT_TAG && d.cover == 0 && e[d.lead_entry].tag == 5 && e[d.lead_entry].type == KOF_MALTYPE_MINER,
	    "decide: only an unattributed diagnose is level TAG");
	/* group A (tags 1,2: one fired, cover 500) against B (tag 3: fired, cover 1000): B leads, and the order of the fired does not matter */
	c[0] = (struct kof_vmatch_cand){ 1, 1, pa, 2 };
	c[1] = (struct kof_vmatch_cand){ 1, 2, pb, 1 };
	for (i = 0; i < 2; i++) {
		memset(f, 0, sizeof f);
		f[i].diag = 10; f[i].tag = 1; f[i].type = KOF_MALTYPE_BOTNET; f[i].family = 1; f[i].variant = 1; f[i].has_variant = 1;
		f[1 - i].diag = 11; f[1 - i].tag = 3; f[1 - i].type = KOF_MALTYPE_BOTNET; f[1 - i].family = 1; f[1 - i].variant = 2; f[1 - i].has_variant = 1;
		decide(f, 2, c, 2, &d, g, e);
		OKF(d.level == KOF_VCAT_VARIANT && d.cover == 1000 && e[d.lead_entry].diag == 11, "decide: the fuller variant leads (order %u)", i);
	}
	/* a candidate whose profile is past the bound has cover 0 and does not lead against a measured one */
	for (i = 0; i < KOF_VMATCH_SET_MAX + 1u; i++) {
		big[i].kind = KOF_VMATCH_TAG;
		big[i].a = i;
	}
	c[0] = (struct kof_vmatch_cand){ 1, 1, big, KOF_VMATCH_SET_MAX + 1u };
	decide(f, 2, c, 2, &d, g, e);
	OKF(d.cover == 1000 && e[d.lead_entry].diag == 11, "decide: a skipped profile has cover 0 (the other leads)");
	/* the lead's tag and type come from its lowest-type diagnose, and the other types are reported */
	memset(f, 0, sizeof f);
	f[0].diag = 1; f[0].tag = 1; f[0].type = KOF_MALTYPE_BOTNET; f[0].family = 1; f[0].variant = 1; f[0].has_variant = 1;
	f[1].diag = 2; f[1].tag = 2; f[1].type = KOF_MALTYPE_ROOTKIT; f[1].family = 1; f[1].variant = 1; f[1].has_variant = 1;
	c[0] = (struct kof_vmatch_cand){ 1, 1, pa, 2 };
	decide(f, 2, c, 1, &d, g, e);
	OKF(e[d.lead_entry].type == KOF_MALTYPE_ROOTKIT && d.other_types == (1u << KOF_MALTYPE_BOTNET) && d.cover == 1000,
	    "decide: lowest type leads, the other is in other_types");
}

int main(void)
{
	if (access(builder, X_OK) != 0) {
		printf("verdict_catalog: %s is not built\n", builder);
		return 2;
	}
	snprintf(root, sizeof root, "build/kof_verdict_catalog_XXXXXX");
	if (!mkdtemp(root)) {
		printf("verdict_catalog: cannot make a scratch directory\n");
		return 2;
	}
	case_decide();
	case_one();
	case_same_variant();
	case_two_families();
	case_variants_and_types();
	case_old_model();
	case_cap();
	case_named();
	case_partial();
	case_hostile();
	case_renamed();
	case_maxlen();
	case_budget();
	case_engines();
	case_scanner();
	if (!failures) {
		char cmd[400];

		snprintf(cmd, sizeof cmd, "rm -rf '%s'", root);
		(void)system(cmd);
	}
	if (failures) {
		printf("verdict_catalog: %d FAIL\n", failures);
		return 1;
	}
	printf("verdict_catalog: ok\n");
	return 0;
}
