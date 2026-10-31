/*
 * catalog_ids - THE ONE FUNCTION that makes the id of a family, a variant and a tag from its name (libkofeng/verdictor/catstore.c,
 * catstore.h), and the engine's table of those ids (catnames.c) built from the same function.
 *   FROZEN    known answers written out as numbers (computed outside this tree, by a Python transcription of the rule): changing the hash,
 *             the key or the folding changes EVERY id of every pack and every host catalog, so it must break here first
 *   ORACLE    every name of a small alphabet, as family, variant (three letters) and tag, equals catid_oracle.h, which shares no code with
 *             the library; the ids of one kind are all different, and a family, a variant and a tag of one name differ (the kind is in the key)
 *   CASE      one id in any letter case; empty, NULL and a key that does not fit have no id (0)
 *   RESERVED  a hash inside the reserved range (below KOF_CATID_SEED_MAX) is moved out of it by the fixed rule, the same number for the same
 *             value, and a value outside it is left alone
 *   NAMES     kof_catnames_load over catalog directories names every id the oracle computes (family, variant "Family.A", tag), spells an id
 *             it does not hold as hex, and an engine's table is per engine (it does not know a name that is only in another's directory)
 * Why the old tests missed it: (c) ids were random and stored, so a test could only compare an id with itself after a round trip.
 * Files live under build/kof_catalog_ids_XXXXXX and are removed at the end.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <kofmod/kofsig.h>
#include "../../libkofeng/verdictor/catnames.h"
#include "../../libkofeng/verdictor/famcat.h"
#include "../../libkofeng/verdictor/tagcat.h"
#include "catid_oracle.h"

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static char dir[128];

/* NULL-safe: a wrong answer must be a FAIL line, not a crash */
static int streq(const char *a, const char *b)
{
	return a && b && !strcmp(a, b);
}

static void frozen(void)
{
	CK(kof_catid_family("Mirai") == 0xb3c9f41b6dcad538ull && kof_catid_family("mirai") == 0xb3c9f41b6dcad538ull);
	CK(kof_catid_variant("Mirai", "A") == 0x820ff82fa9a1961bull && kof_catid_variant("MIRAI", "a") == 0x820ff82fa9a1961bull);
	CK(kof_catid_tag("Mirai-flood") == 0xf7f4b4e21475d132ull && kof_catid_tag("MIRAI-FLOOD") == 0xf7f4b4e21475d132ull);
	CK(kof_catid_tag("flood") == 0x3176da05d0a8f6e7ull && kof_catid_family("Gafgyt") == 0xbc1ea992803ab09bull);
}

static uint64_t hash_fixed(void *ud, const char *key, size_t len)
{
	(void)key;
	(void)len;
	return *(uint64_t *)ud;
}

static int cmp64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y;
}

/* every name over the alphabet up to length 5, as the three kinds */
static void exhaustive(void)
{
	static const char alpha[] = "aB-1_";
	static uint64_t fam[3905], tag[3905], var[3905 * 3];
	unsigned n = 0, k = 0, len, i, j;
	static const char *const letters[3] = { "A", "B", "AA" };

	for (len = 1; len <= 5; len++) {
		unsigned count = 1;

		for (i = 0; i < len; i++)
			count *= 5u;
		for (i = 0; i < count; i++) {
			char name[8];
			unsigned m = i;

			for (j = 0; j < len; j++, m /= 5u)
				name[j] = alpha[m % 5u];
			name[len] = 0;
			fam[n] = kof_catid_family(name);
			tag[n] = kof_catid_tag(name);
			CK(fam[n] == oracle_family(name) && tag[n] == oracle_tag(name) && fam[n] >= KOF_CATID_SEED_MAX);
			CK(fam[n] != tag[n]);
			for (j = 0; j < 3; j++) {
				var[k] = kof_catid_variant(name, letters[j]);
				CK(var[k] == oracle_variant(name, letters[j]));
				k++;
			}
			n++;
		}
	}
	CK(n == 5u + 25u + 125u + 625u + 3125u && k == n * 3u);
	/* the names differ only in case in pairs ("aB" is not "ab": the alphabet has no 'b'), so every id of a kind is distinct except nothing */
	qsort(fam, n, sizeof fam[0], cmp64);
	qsort(tag, n, sizeof tag[0], cmp64);
	qsort(var, k, sizeof var[0], cmp64);
	for (i = 1; i < n; i++)
		CK(fam[i] != fam[i - 1u] && tag[i] != tag[i - 1u]);
	for (i = 1; i < k; i++)
		CK(var[i] != var[i - 1u]);
}

static void edges(void)
{
	char big[200];

	CK(kof_catid_family(NULL) == 0u && kof_catid_family("") == 0u && kof_catid_tag(NULL) == 0u && kof_catid_tag("") == 0u);
	CK(kof_catid_variant("Mirai", NULL) == 0u && kof_catid_variant("Mirai", "") == 0u && kof_catid_variant(NULL, "A") == 0u && kof_catid_variant("", "A") == 0u);
	/* the longest family name the catalogs take (63) with its longest letters fits; a name no catalog could hold does not */
	memset(big, 'x', 63);
	big[63] = 0;
	CK(kof_catid_family(big) == oracle_family(big) && kof_catid_variant(big, "AAAAA") == oracle_variant(big, "AAAAA"));
	memset(big, 'x', 199);
	big[199] = 0;
	CK(kof_catid_family(big) == 0u && kof_catid_tag(big) == 0u && kof_catid_variant("a", big) == 0u);
	/* the kind is part of the key: one name, three kinds, three ids */
	CK(kof_catid_family("flood") != kof_catid_tag("flood") && kof_catid_family("a") != kof_catid_variant("a", "a"));
	/* a variant is its family and its letters: another family or another letter is another id; "A" is not "a.A" */
	CK(kof_catid_variant("mirai", "A") != kof_catid_variant("mirai", "B") && kof_catid_variant("mirai", "A") != kof_catid_variant("mirai2", "A"));
	CK(kof_catid_variant("ab", "A") != kof_catid_variant("a", "bA"));
}

static void reserved(void)
{
	static const uint64_t low[] = { 0, 1, 0x7fff, 0xffff };
	uint64_t v, r[4];
	unsigned i;

	for (i = 0; i < 4; i++) {
		v = low[i];
		r[i] = kof_catid_of(hash_fixed, &v, 'F', "x", NULL);
		CK(r[i] >= KOF_CATID_SEED_MAX && r[i] == oracle_valid(v) && r[i] >> 63);
		CK(kof_catid_of(hash_fixed, &v, 'F', "y", NULL) == r[i]);          /* the same value, the same number */
		CK(kof_catid_of(hash_fixed, &v, 'T', "x", NULL) == r[i]);          /* the seam sees the key; this one ignores it */
	}
	CK(r[0] != r[1] && r[1] != r[2] && r[2] != r[3]);
	v = 0x10000;
	CK(kof_catid_of(hash_fixed, &v, 'F', "x", NULL) == 0x10000u);
	v = UINT64_MAX;
	CK(kof_catid_of(hash_fixed, &v, 'F', "x", NULL) == UINT64_MAX);
	CK(!kof_catid_valid(0) && !kof_catid_valid(0xffff) && kof_catid_valid(0x10000));
}

/* ---- the engine's table ----------------------------------------------------------------------------------------------- */

static void put(const char *sub, const char *name, const char *text)
{
	char p[300];
	FILE *f;

	snprintf(p, sizeof p, "%s/%s", dir, sub);
	mkdir(p, 0700);
	snprintf(p, sizeof p, "%s/%s/%s", dir, sub, name);
	f = fopen(p, "wb");
	if (f) {
		fputs(text, f);
		fclose(f);
	}
}

static void rmtree(void)
{
	char cmd[400];

	snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
	(void)system(cmd);
}

static void names(void)
{
	char pdir[300], sdir[300], pdir2[300], out[128], text[2048];
	kof_catnames *n, *n2;
	struct kof_catnames_info info;
	unsigned i;

	put("p1", "mirai.c", "KOF_MALWARE_FAMILY_NAME(\"Mirai\");\nKOF_MALWARE_NEXT_VARIANT(\"C\");\n"
	    "KOF_MALWARE_VARIANT(\"A\", KOF_MALTYPE_BOTNET);\nKOF_MALWARE_VARIANT(\"B\", KOF_MALTYPE_TROJAN);\n");
	put("p1", "gafgyt.c", "KOF_MALWARE_FAMILY_NAME(\"GaFgyt\");\nKOF_MALWARE_VARIANT(\"A\", KOF_MALTYPE_BOTNET);\n");
	/* an old file with id lines, as bases/pathogens/mirai.c was: loads, the ids are the oracle's */
	put("p1", "old.c", "KOF_MALWARE_FAMILY_NAME(\"Old_One\");\nKOF_MALWARE_FAMILY_ID(0x1234567);\n"
	    "KOF_MALWARE_VARIANT(\"A\", KOF_MALTYPE_ROOTKIT);\nKOF_MALWARE_VARIANT_ID(\"A\", 0x7654321);\n");
	put("p2", "other.c", "KOF_MALWARE_FAMILY_NAME(\"Hajime\");\nKOF_MALWARE_VARIANT(\"A\", KOF_MALTYPE_BOTNET);\n");
	snprintf(text, sizeof text, "KOF_TAG_NAME(\"Mirai-flood\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n"
		 "KOF_TAG_NAME(\"c2\");\nKOF_TAG_ID(0x42);\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n");
	put("s1", "none_scan.c", text);
	snprintf(pdir, sizeof pdir, "%s/p1", dir);
	snprintf(pdir2, sizeof pdir2, "%s/p2", dir);
	snprintf(sdir, sizeof sdir, "%s/s1", dir);

	n = kof_catnames_load(pdir, sdir, NULL, &info);
	CK(n && info.flags == 0 && info.families == 3 && info.variants == 4 && info.tags == 2);
	CK(n && streq(kof_catnames_family(n, oracle_family("mirai")), "Mirai") && streq(kof_catnames_family(n, oracle_family("GAFGYT")), "GaFgyt"));
	CK(n && streq(kof_catnames_family(n, oracle_family("old_one")), "Old_One"));
	CK(n && kof_catnames_family_text(n, oracle_family("Mirai"), out, sizeof out) == 1 && !strcmp(out, "Mirai"));
	CK(n && kof_catnames_variant_text(n, oracle_variant("Mirai", "A"), out, sizeof out) == 1 && !strcmp(out, "Mirai.A"));
	CK(n && kof_catnames_variant_text(n, oracle_variant("mirai", "B"), out, sizeof out) == 1 && !strcmp(out, "Mirai.B"));
	CK(n && kof_catnames_variant_text(n, oracle_variant("gafgyt", "A"), out, sizeof out) == 1 && !strcmp(out, "GaFgyt.A"));
	CK(n && kof_catnames_variant_text(n, oracle_variant("old_one", "A"), out, sizeof out) == 1 && !strcmp(out, "Old_One.A"));
	CK(n && kof_catnames_tag_text(n, oracle_tag("mirai-FLOOD"), out, sizeof out) == 1 && !strcmp(out, "Mirai-flood"));
	CK(n && kof_catnames_tag_text(n, oracle_tag("c2"), out, sizeof out) == 1 && !strcmp(out, "c2"));
	/* the old numbers of the files name nothing, and what is not held is hex, never a name */
	CK(n && kof_catnames_family(n, 0x1234567) == NULL && kof_catnames_tag(n, 0x42) == NULL && kof_catnames_family(n, 0) == NULL);
	CK(n && kof_catnames_variant_text(n, 0x7654321, out, sizeof out) == 0 && strlen(out) == 8);
	CK(n && kof_catnames_variant_text(n, oracle_variant("mirai", "C"), out, sizeof out) == 0);
	CK(n && kof_catnames_tag_text(n, oracle_family("mirai"), out, sizeof out) == 0);        /* a family's id is not a tag's */
	CK(n && kof_catnames_family_text(n, oracle_variant("mirai", "A"), out, sizeof out) == 0);   /* nor a variant's a family's */
	/* the slot of a verdict: the variant, the tag, a variant of a family the table holds with a letter it does not */
	if (n) {
		kof_catnames_slot(n, oracle_family("mirai"), oracle_variant("mirai", "A"), 0, out, sizeof out);
		CK(!strcmp(out, "Mirai.A"));
		kof_catnames_slot(n, 0, 0, oracle_tag("c2"), out, sizeof out);
		CK(!strcmp(out, "c2"));
		kof_catnames_slot(n, oracle_family("mirai"), oracle_variant("mirai", "D"), 0, out, sizeof out);
		CK(!strncmp(out, "Mirai.V", 7));
	}
	/* a second engine's table over another directory is its own */
	n2 = kof_catnames_load(pdir2, NULL, NULL, &info);
	CK(n2 && info.families == 1 && info.variants == 1 && info.tags == 0);
	CK(n2 && kof_catnames_variant_text(n2, oracle_variant("Hajime", "A"), out, sizeof out) == 1 && !strcmp(out, "Hajime.A"));
	CK(n2 && kof_catnames_variant_text(n2, oracle_variant("Mirai", "A"), out, sizeof out) == 0);
	CK(n && kof_catnames_variant_text(n, oracle_variant("Hajime", "A"), out, sizeof out) == 0);
	kof_catnames_free(n, NULL);
	kof_catnames_free(n2, NULL);
	/* a large catalog: every id the oracle computes is found (the table is sorted by id and searched, so one wrong comparison loses some) */
	{
		char big[300];
		static char tags[60000];
		unsigned nt = 0;

		snprintf(big, sizeof big, "%s/big", dir);
		mkdir(big, 0700);
		for (i = 0; i < 200; i++) {
			char fn[64], body[300];

			snprintf(fn, sizeof fn, "f%03u.c", i);
			snprintf(body, sizeof body, "KOF_MALWARE_FAMILY_NAME(\"Fam%03u\");\nKOF_MALWARE_NEXT_VARIANT(\"C\");\n"
				 "KOF_MALWARE_VARIANT(\"A\", KOF_MALTYPE_BOTNET);\nKOF_MALWARE_VARIANT(\"B\", KOF_MALTYPE_TROJAN);\n", i);
			put("big", fn, body);
		}
		for (i = 0; i < 250; i++)
			nt += (unsigned)snprintf(tags + nt, sizeof tags - nt, "KOF_TAG_NAME(\"t%03u\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n", i);
		put("bigs", "none_scan.c", tags);
		snprintf(big, sizeof big, "%s/big", dir);
		snprintf(sdir, sizeof sdir, "%s/bigs", dir);
		n = kof_catnames_load(big, sdir, NULL, &info);
		CK(n && info.families == 200 && info.variants == 400 && info.tags == 250 && info.flags == 0);
		for (i = 0; n && i < 200; i++) {
			char nm[16], want[32];

			snprintf(nm, sizeof nm, "Fam%03u", i);
			CK(kof_catnames_family_text(n, oracle_family(nm), out, sizeof out) == 1 && !strcmp(out, nm));
			snprintf(want, sizeof want, "%s.B", nm);
			CK(kof_catnames_variant_text(n, oracle_variant(nm, "B"), out, sizeof out) == 1 && !strcmp(out, want));
		}
		for (i = 0; n && i < 250; i++) {
			char nm[16];

			snprintf(nm, sizeof nm, "t%03u", i);
			CK(kof_catnames_tag_text(n, oracle_tag(nm), out, sizeof out) == 1 && !strcmp(out, nm));
		}
		kof_catnames_free(n, NULL);
	}
}

int main(void)
{
	char tmpl[] = "build/kof_catalog_ids_XXXXXX";

	if (!mkdtemp(tmpl)) {
		printf("catalog_ids: cannot make a scratch directory\n");
		return 1;
	}
	snprintf(dir, sizeof dir, "%s", tmpl);
	frozen();
	exhaustive();
	edges();
	reserved();
	names();
	rmtree();
	printf("catalog_ids: %d failure(s)\n", fails);
	return fails != 0;
}
