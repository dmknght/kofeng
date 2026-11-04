/*
 * diag_deleted_variant - a diagnose whose VARIANT was deleted from the Pathogens catalog (CAT-1, owner 2026-10-31).
 *
 * THE RULE: a letter the family ISSUED (below its counter, KOF_MALWARE_NEXT_VARIANT) that no variant has any more is DELETED. A diagnose that
 * names one is WARNED about (diagnose name, file, family, variant), is left out of the pack - the scanner reads only the pack, so it is not
 * used - and the build and `--catalog` go on and exit 0. The state is derived from the catalog; nothing is stored in a diagnose. Still ERRORS:
 * a letter at or above the counter (never issued: a typo), a type problem. A family or a tag the catalog does not have is DISABLED the same way
 * (owner 2026-11-01; one warning naming what is missing).
 *
 *   LIBRARY   kof_famcat_variant_state over every counter 1..4, every subset of the issued letters that stays declared, and the letters A..F
 *             (exhaustive): live / deleted / never issued, plus an absent family, a name that is not letters, and "<family>_<letters>".
 *   BUILDER   ksigbuilder --tree over run-time catalogs and diagnoses: first, middle and last issued letter deleted; at and above the
 *             counter (errors); several diagnoses of one deleted variant; one deleted and one live diagnose in one tree (the live one is in
 *             the pack and the real scanner finds the word with it, the deleted one is not in the pack and names.kdig does not carry it);
 *             the warning names every skipped diagnose and its file; a family, a tag or both absent: disabled with one warning, beside a live
 *             diagnose, either file order; the order of the files does not matter (pack and names.kdig byte for byte the same);
 *             `--catalog` warns and exits 0.
 *
 * Why the old tests missed it: (a) no line decided "deleted" - the builder had one outcome for a letter the catalog lacked (the error), and
 * diag_meta.c only used letters that were never issued (Z, B of a family whose counter is 2), so the deleted case was never executed;
 * (b) the boundary was never an input: the counter, one letter below it and the letter at it were not tried against a catalog with a gap.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "../../libkofeng/verdictor/famcat.h"

static int fails;
static char root[256], base[320], art[320], db[320], errf[320];
static const char *dbdir = "build/test/databases-sigs";
static const char *builder = "build/release/bin/ksigbuilder";

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static void sh(const char *fmt, const char *a, const char *b, const char *c)
{
	char cmd[2400];

	snprintf(cmd, sizeof cmd, fmt, a, b, c);
	(void)system(cmd);
}

static void wr(const char *dir, const char *leaf, const char *text)
{
	char p[700];
	FILE *f;

	snprintf(p, sizeof p, "%s/%s", dir, leaf);
	f = fopen(p, "wb");
	if (f) {
		fputs(text, f);
		fclose(f);
	}
}

static char *slurp(const char *path, size_t *n)
{
	FILE *f = fopen(path, "rb");
	char *b;
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
	if (b) {
		b[L] = 0;
		*n = (size_t)L;
	}
	return b;
}

/* ---- LIBRARY: kof_famcat_variant_state, exhaustive ------------------------------------------------------------------ */

static const char *const LET = "ABCDEF";

static void library(void)
{
	struct kof_famcat_fam fam[4];
	struct kof_famcat_var var[16];
	struct kof_famcat c;
	unsigned next, mask, l, cases = 0;

	for (next = 1; next <= 4; next++)
		for (mask = 0; mask < (1u << (next - 1u)); mask++) {
			uint32_t f, v, k;
			char letter[2] = { 0, 0 };

			kof_famcat_init(&c, fam, 4, var, 16);
			CK(kof_famcat_load_family(&c, "Mirai", NULL, &f) == KOF_FAMCAT_OK);
			for (k = 0; k + 1u < next; k++)
				if ((mask >> k) & 1u)
					CK(kof_famcat_load_variant(&c, f, k + 1u, NULL, 1u << KOF_MALTYPE_BOTNET, &v) == KOF_FAMCAT_OK);
			CK(kof_famcat_load_next(&c, f, next) == KOF_FAMCAT_OK);
			for (l = 1; l <= 6; l++) {
				enum kof_famcat_letter_state want, got;
				char whole[16];

				letter[0] = LET[l - 1u];
				if (l < next)
					want = ((mask >> (l - 1u)) & 1u) ? KOF_FAMCAT_LS_LIVE : KOF_FAMCAT_LS_DELETED;
				else
					want = KOF_FAMCAT_LS_NEVER;
				got = kof_famcat_variant_state(&c, "Mirai", letter);
				if (got != want)
					printf("  next=%u mask=%x letter=%s got %d want %d\n", next, mask, letter, (int)got, (int)want);
				CK(got == want);
				snprintf(whole, sizeof whole, "Mirai_%s", letter);
				CK(kof_famcat_variant_state(&c, "mirai", whole) == want);   /* letter case of the family, whole name */
				cases++;
			}
			CK(kof_famcat_variant_state(&c, "Nope", "A") == KOF_FAMCAT_LS_NO_FAMILY);
			CK(kof_famcat_variant_state(&c, NULL, "A") == KOF_FAMCAT_LS_NO_FAMILY);
			CK(kof_famcat_variant_state(&c, "Mirai", "") == KOF_FAMCAT_LS_BAD);
			CK(kof_famcat_variant_state(&c, "Mirai", NULL) == KOF_FAMCAT_LS_BAD);
			CK(kof_famcat_variant_state(&c, "Mirai", "a") == KOF_FAMCAT_LS_BAD);
			CK(kof_famcat_variant_state(&c, "Mirai", "A1") == KOF_FAMCAT_LS_BAD);
		}
	printf("  library: %u (counter, declared set, letter) cases\n", cases);
	CK(cases == (1u + 2u + 4u + 8u) * 6u);
}

/* ---- BUILDER ------------------------------------------------------------------------------------------------------- */

/* A fresh tree: <tag>_base with Mirai (counter `next`, the variants whose letter is in `declared`, all BOTNET) and the tags flood and c2. */
static void fresh(const char *tag, const char *next, const char *declared)
{
	char d[400], t[800];
	size_t at, i;

	snprintf(base, sizeof base, "%s/%s_base", root, tag);
	snprintf(art, sizeof art, "%s/%s_art", root, tag);
	snprintf(db, sizeof db, "%s/%s_db", root, tag);
	snprintf(errf, sizeof errf, "%s/%s_err.txt", root, tag);
	sh("mkdir -p '%s/pathogens' '%s/syndromes' '%s/diagnoses'", base, base, base);
	sh("mkdir -p '%s' '%s'%s", art, db, "");
	sh("cp '%s/sigs-any.ksig' '%s/'%s", dbdir, db, "");
	snprintf(d, sizeof d, "%s/pathogens", base);
	at = (size_t)snprintf(t, sizeof t, "KOF_MALWARE_FAMILY_NAME(\"Mirai\");\nKOF_MALWARE_NEXT_VARIANT(\"%s\");\n", next);
	for (i = 0; declared[i]; i++)
		at += (size_t)snprintf(t + at, sizeof t - at, "KOF_MALWARE_VARIANT(\"%c\", KOF_MALTYPE_BOTNET);\n", declared[i]);
	wr(d, "mirai.c", t);
	snprintf(d, sizeof d, "%s/syndromes", base);
	wr(d, "network_scan.c", "KOF_TAG_NAME(\"flood\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\nKOF_TAG_OBJS(KOF_DISEASE_OBJ_NETWORK);\n");
}

/* A string-form diagnose that matches `word` anywhere. */
static void diag(const char *leaf, const char *fam, const char *var, const char *tag, const char *word)
{
	char d[400], t[1200], name[200];

	snprintf(d, sizeof d, "%s/diagnoses", base);
	snprintf(name, sizeof name, "%s", leaf);
	name[strlen(name) - 2u] = 0;
	snprintf(t, sizeof t,
		 "KOF_DIAG_NAME(%s);\nKOF_DIAG_FAMILY(\"%s\");\nKOF_DIAG_VARIANT(\"%s\");\nKOF_DIAG_TYPE(KOF_MALTYPE_BOTNET);\n"
		 "KOF_DIAG_TAG(\"%s\");\nKOF_TARGET_RANGE(whole, KOF_SCAN_ALL);\n"
		 "KOF_DEFINE_STR(s0, \"%s\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\nKOF_DIAG_FIND(m0, KOF_FIND_ANY, whole, s0);\n",
		 name, fam, var, tag, word);
	wr(d, leaf, t);
}

static int build(void)
{
	char cmd[3000];

	snprintf(cmd, sizeof cmd, "ulimit -v 4194304; timeout -s KILL 120 %s --tree '%s' '%s' '%s' --pathogens '%s/pathogens' --syndromes '%s/syndromes' "
		 "--basedir '%s' >/dev/null 2>'%s'", builder, base, art, db, base, base, base, errf);
	return system(cmd);
}

static int catalog_check(void)
{
	char cmd[3000];

	snprintf(cmd, sizeof cmd, "ulimit -v 4194304; timeout -s KILL 60 %s --catalog '%s/diagnoses' --pathogens '%s/pathogens' "
		 "--syndromes '%s/syndromes' >'%s' 2>&1", builder, base, base, base, errf);
	return system(cmd);
}

static int said(const char *needle)
{
	size_t n = 0;
	char *t = slurp(errf, &n);
	int r = t && strstr(t, needle) != NULL;

	free(t);
	return r;
}

static unsigned count_said(const char *needle)
{
	size_t n = 0;
	char *t = slurp(errf, &n), *p;
	unsigned k = 0;

	for (p = t; p && (p = strstr(p, needle)) != NULL; p += strlen(needle))
		k++;
	free(t);
	return k;
}

struct scan_got {
	int has;
	char name[224];
	uint32_t n_diag;
	char diag0[96];
};

static int on_obj(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct scan_got *g = user;

	(void)name; (void)bytes; (void)len;
	if (res && res->has_verdict) {
		g->has = 1;
		snprintf(g->name, sizeof g->name, "%s", res->verdict.name);
		g->n_diag = res->verdict.n_diag;
	}
	return 0;
}

/* Open the build's db and scan a plain string. The diagnoses it holds are counted into *n. */
static struct scan_got scan_text(const char *text, unsigned *n)
{
	struct scan_got g;
	kof_engine *e = keng_open(db);
	kof_scanner *sc = e ? kscan_new(e) : NULL;
	struct kof_scan_option o;

	memset(&g, 0, sizeof g);
	memset(&o, 0, sizeof o);
	*n = e ? kdb_diagnoses(e) : 99u;
	if (sc)
		(void)kscan_bytes(sc, text, strlen(text), "plain.txt", &o, on_obj, &g);
	CK(sc != NULL);
	if (sc)
		kscan_free(sc);
	if (e)
		keng_close(e);
	return g;
}

static char *pack_of(const char *leaf, size_t *n)
{
	char p[700];

	snprintf(p, sizeof p, "%s/%s", db, leaf);
	return slurp(p, n);
}

/* One letter against one catalog: the builder's answer. `want`: 0 built with a warning-free live diagnose, 1 deleted (warn, rc 0, nothing in
 * the pack), 2 error (rc != 0). */
static void one_letter(const char *tag, const char *next, const char *declared, const char *letter, int want)
{
	unsigned n;
	int rc;

	fresh(tag, next, declared);
	diag("botnet_x_01.c", "Mirai", letter, "flood", "alpha");
	rc = build();
	if (want == 2) {
		CK(rc != 0);
		CK(said("is not in the Pathogens catalog"));
		CK(!said("was deleted from the Pathogens catalog"));
		return;
	}
	CK(rc == 0);
	(void)scan_text("xx alpha yy", &n);
	if (want == 1) {
		CK(said("warning: diagnose \"botnet_x_01\": variant \"") && said("was deleted from the Pathogens catalog"));
		CK(n == 0u);
	} else {
		CK(!said("was deleted"));
		CK(n == 1u);
	}
}

static void builder_cases(void)
{
	/* the letter at the three places of an issued range: first, middle, last deleted (counter D = 3 issued letters) */
	one_letter("first", "D", "BC", "A", 1);
	one_letter("middle", "D", "AC", "B", 1);
	one_letter("last", "D", "AB", "C", 1);
	one_letter("allgone", "D", "", "B", 1);                 /* a family that lost every variant keeps its counter */
	/* the live letter beside them, and the boundary: the counter itself and above it were never issued */
	one_letter("live", "D", "AC", "C", 0);
	one_letter("atcounter", "D", "AB", "D", 2);
	one_letter("above", "D", "AB", "F", 2);
	one_letter("typoz", "C", "AB", "Z", 2);
	one_letter("counter1", "A", "", "A", 2);                /* counter 1: nothing was ever issued */

	/* several diagnoses of ONE deleted variant: each is named, none is in the pack, rc 0, --catalog says the same and exits 0 */
	{
		unsigned n;

		fresh("several", "C", "A");
		diag("botnet_s1_01.c", "Mirai", "B", "flood", "alpha");
		diag("botnet_s2_01.c", "Mirai", "B", "flood", "alpha");
		diag("netflow_s3_01.c", "Mirai", "B", "flood", "alpha");
		CK(build() == 0);
		CK(said("botnet_s1_01") && said("botnet_s2_01") && said("netflow_s3_01"));
		CK(said("botnet_s1_01.c") || said("diagnoses/botnet_s1_01.c: warning"));
		CK(said("family \"Mirai\"") && said("was deleted from the Pathogens catalog: the diagnose is not in the pack"));
		CK(count_said("warning:") == 3u);                   /* once each, not twice (the prepass is quiet) */
		(void)scan_text("alpha", &n);
		CK(n == 0u);
		CK(catalog_check() == 0);
		CK(said("botnet_s1_01") && said("botnet_s2_01") && said("netflow_s3_01") && said("0 error(s)"));
		CK(count_said("warning:") == 3u);
	}

	/* ONE DELETED AND ONE LIVE in the same tree: the live one is in the pack and the scanner finds its word; the deleted one is not */
	{
		unsigned n;
		struct scan_got g;
		size_t nn = 0;
		char *names;

		fresh("mixed", "C", "A");
		diag("botnet_dead_01.c", "Mirai", "B", "flood", "alpha");
		diag("botnet_live_01.c", "Mirai", "A", "flood", "alpha");
		CK(build() == 0);
		CK(said("botnet_dead_01") && !said("botnet_live_01"));
		g = scan_text("xx alpha yy", &n);
		CK(n == 1u);
		CK(g.has && g.n_diag == 1u && strstr(g.name, "Mirai.A") != NULL && strstr(g.name, "Mirai.B") == NULL);
		if (!(g.has && strstr(g.name, "Mirai.A")))
			printf("  verdict: %s\n", g.has ? g.name : "(none)");
		CK(!scan_text("xx nothing yy", &n).has);
		names = pack_of("names.kdig", &nn);
		CK(names != NULL);
		CK(names && !memmem(names, nn, "Mirai.B", 7u) && memmem(names, nn, "Mirai.A", 7u));
		free(names);
	}

	/* ABSENT family, ABSENT tag, BOTH (owner 2026-11-01: disabled like a deleted variant, ONE warning naming what is missing; the family is said first
	 * and the variant is not judged without it), each beside a LIVE diagnose: the live one is in the pack and the scanner fires it, the disabled one is
	 * not in the pack and names.kdig does not hold its name; the order of the files does not matter. */
	{
		static const struct { const char *tag, *fam, *tg, *need; } c[] = {
			{ "nofam",  "Nope",  "flood",   "family \"Nope\" is not in the Pathogens catalog" },
			{ "notag",  "Mirai", "nothing", "tag \"nothing\" is not in the Syndromes catalog" },
			{ "noboth", "Nope",  "nothing", "family \"Nope\" is not in the Pathogens catalog; tag \"nothing\" is not in the Syndromes catalog" },
		};
		unsigned i, o;

		for (i = 0; i < 3u; i++) {
			for (o = 0; o < 2u; o++) {
				unsigned n;
				struct scan_got g;
				size_t nn = 0;
				char *names;

				char dirtag[40];

				snprintf(dirtag, sizeof dirtag, "%s%u", c[i].tag, o);
				fresh(dirtag, "C", "A");
				diag(o ? "botnet_a_live_01.c" : "botnet_z_live_01.c", "Mirai", "A", "flood", "alpha");
				diag(o ? "botnet_z_gone_01.c" : "botnet_a_gone_01.c", c[i].fam, "B", c[i].tg, "alpha");
				CK(build() == 0);
				CK(said(c[i].need) && said("_gone_01") && !said("_live_01"));
				CK(count_said("warning:") == 1u);
				CK(!said("error"));
				g = scan_text("xx alpha yy", &n);
				CK(n == 1u && g.has && g.n_diag == 1u && strstr(g.name, "Mirai.A") != NULL);
				names = pack_of("names.kdig", &nn);
				CK(names && memmem(names, nn, "Mirai.A", 7u) && !memmem(names, nn, "_gone_01", 8u));
				free(names);
				CK(catalog_check() == 0);
				CK(said(c[i].need) && said("0 error(s)") && count_said("warning:") == 1u);
			}
		}
		/* a tree whose only diagnose has an absent family builds an empty set */
		fresh("onlyabs", "C", "A");
		diag("botnet_x_01.c", "Nope", "B", "nothing", "alpha");
		CK(build() == 0);
		{
			unsigned n;

			(void)scan_text("alpha", &n);
			CK(n == 0u);
		}
		/* one error among deleted ones: the error is reported and the build stops */
		fresh("errmix", "C", "A");
		diag("botnet_d_01.c", "Mirai", "B", "flood", "alpha");
		diag("botnet_e_01.c", "Mirai", "Z", "flood", "alpha");
		CK(build() != 0 && said("variant \"Z\" of family \"Mirai\" is not in the Pathogens catalog"));
	}

	/* ORDER OF THE FILES: the deleted diagnose sorting first or last, the pack and names.kdig are the same bytes */
	{
		size_t a1 = 0, a2 = 0, b1 = 0, b2 = 0;
		char *pa, *pb, *na, *nb;

		fresh("ord1", "C", "A");
		diag("botnet_a_01.c", "Mirai", "B", "flood", "alpha");
		diag("botnet_m_01.c", "Mirai", "A", "flood", "alpha");
		CK(build() == 0);
		pa = pack_of("diag-botnet.kdig", &a1);
		na = pack_of("names.kdig", &a2);
		fresh("ord2", "C", "A");
		diag("botnet_m_01.c", "Mirai", "A", "flood", "alpha");
		diag("botnet_z_01.c", "Mirai", "B", "flood", "alpha");
		CK(build() == 0);
		pb = pack_of("diag-botnet.kdig", &b1);
		nb = pack_of("names.kdig", &b2);
		CK(pa && pb && a1 == b1 && memcmp(pa, pb, a1) == 0);
		CK(na && nb && a2 == b2 && memcmp(na, nb, a2) == 0);
		free(pa); free(pb); free(na); free(nb);
	}

	/* a tree whose ONLY diagnose is deleted builds an empty diagnose set (and no names) without failing */
	{
		unsigned n;

		fresh("onlydead", "C", "A");
		diag("botnet_x_01.c", "Mirai", "B", "flood", "alpha");
		CK(build() == 0);
		(void)scan_text("alpha", &n);
		CK(n == 0u);
	}
}

int main(int argc, char **argv)
{
	if (argc > 1)
		dbdir = argv[1];
	snprintf(root, sizeof root, "build/test/diagdeleted_%d", (int)getpid());
	if (kof_mkdir(root, 0700) != 0) {
		printf("diag_deleted_variant: cannot make a work directory\n");
		return 1;
	}
	if (access(builder, X_OK) != 0) {
		printf("diag_deleted_variant: %s is not built\n", builder);
		sh("rm -rf '%s'%s%s", root, "", "");
		return 1;
	}
	printf("diag_deleted_variant:\n");
	library();
	builder_cases();
	sh("rm -rf '%s'%s%s", root, "", "");
	printf("diag_deleted_variant: %s\n", fails ? "FAILED" : "all ok");
	return fails ? 1 : 0;
}
