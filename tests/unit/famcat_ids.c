/*
 * famcat_ids - the ids of families and variants (libkofeng/verdictor/famcat.c, famcat_store.c, catstore.c). An id is a function of the
 * names (catstore.h) and is stored nowhere; every expectation here is computed by catid_oracle.h, which shares no code with the library.
 *   ORACLE    the id of every family and variant of a catalog equals the oracle's, in any letter case of the lookup
 *   STABLE    set types, set comment, delete a sibling, add another, save and load again: the id of an item does not change; a RENAME of
 *             the family changes its id and every variant's; deleting a family and adding it again gives the same ids back
 *   ORDER     the same items added in another order, or read from files in another order, have the same ids
 *   CLASH     a hash that makes two names one id (seam kof_famcat_set_idhash): add_family (family against family, family against variant,
 *             first variant against its family), add_variant, load_family, load_variant and rename_family (the renamed family against
 *             another, a renamed variant against a sibling) refuse with KOF_FAMCAT_ID_CLASH, change nothing, and kof_famcat_why names BOTH
 *   OLD FILE  a file an older tool saved, with KOF_MALWARE_FAMILY_ID / KOF_MALWARE_VARIANT_ID lines (even malformed, reserved or equal
 *             ones), loads: the lines are counted as ignored, the ids are the oracle's and the old numbers are used nowhere; Save writes
 *             a file with no id line
 *   BYTES     save, load, save is byte-identical and the text holds no id; an unknown line is counted
 *   API       kof_famcat_family_id / _variant_id / _variant_types, kof_famcat_fam_id_at / var_id_at, kof_famcat_load_dir
 * Why the old tests missed what this pins: (c) they compared an id with another call of the same library, never with a value computed
 * outside it, so a function that returned any stable number would have passed.
 * Files live under build/kof_famcat_ids_XXXXXX and are removed at the end.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <kofmod/kofsig.h>
#include "../../libkofeng/verdictor/famcat.h"
#include "catid_oracle.h"

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

#define BOT (1u << KOF_MALTYPE_BOTNET)
#define TRO (1u << KOF_MALTYPE_TROJAN)
#define ROOT (1u << KOF_MALTYPE_ROOTKIT)

static char dir[128];
static struct kof_famcat_fam F[8], F2[8];
static struct kof_famcat_var V[16], V2[16];
static struct kof_famcat C, C2;
static struct kof_catstore ST;

/* A hash that makes two keys of one LENGTH one number: "F:alpha" and "F:gamma" collide, "F:beta" does not. */
static uint64_t hash_len(void *ud, const char *key, size_t len)
{
	(void)ud;
	(void)key;
	return 0x20000u + len;
}

/* One number for every key. */
static uint64_t hash_const(void *ud, const char *key, size_t len)
{
	(void)ud;
	(void)key;
	(void)len;
	return 0x20000u;
}

/* Five numbers, spread by the real hash: a collision is common and depends on every character of the key. */
static uint64_t hash_mod5(void *ud, const char *key, size_t len)
{
	return 0x20000u + kof_catid_hash(ud, key, len) % 5u;
}

static void fresh(struct kof_famcat *c, struct kof_famcat_fam *f, struct kof_famcat_var *v)
{
	memset(f, 0, 8 * sizeof *f);
	memset(v, 0, 16 * sizeof *v);
	kof_famcat_init(c, f, 8, v, 16);
}

static void both(void)
{
	fresh(&C, F, V);
	fresh(&C2, F2, V2);
	kof_catstore_init(&ST);
}

static void put(const char *name, const char *text)
{
	char p[256];
	FILE *f;

	snprintf(p, sizeof p, "%s/%s", dir, name);
	f = fopen(p, "wb");
	if (f) {
		fwrite(text, 1, strlen(text), f);
		fclose(f);
	}
}

static char *slurp(const char *name)
{
	char p[256];
	FILE *f;
	char *b;
	size_t k;

	snprintf(p, sizeof p, "%s/%s", dir, name);
	f = fopen(p, "rb");
	if (!f)
		return NULL;
	b = malloc(1u << 16);
	k = fread(b, 1, (1u << 16) - 1u, f);
	fclose(f);
	b[k] = 0;
	return b;
}

static void wipe(void)
{
	DIR *d = opendir(dir);
	struct dirent *e;

	if (!d)
		return;
	while ((e = readdir(d)) != NULL) {
		char p[512];

		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
		unlink(p);
	}
	closedir(d);
}


/* every item of the catalog has the id the oracle computes */
static int all_oracle(const struct kof_famcat *c)
{
	uint32_t i;
	char letters[16];

	for (i = 0; i < c->n_fam; i++)
		if (kof_famcat_fam_id_at(c, i) != oracle_family(c->fam[i].name))
			return 0;
	for (i = 0; i < c->n_var; i++) {
		if (!kof_famcat_letter_text(c->var[i].letter, letters, sizeof letters))
			return 0;
		if (kof_famcat_var_id_at(c, i) != oracle_variant(c->fam[c->var[i].family].name, letters))
			return 0;
	}
	return 1;
}

/* no two items of the catalog have one id: THE invariant a refused call must keep */
static int all_distinct(const struct kof_famcat *c)
{
	uint32_t i, j, n = c->n_fam + c->n_var;

	for (i = 0; i < n; i++)
		for (j = i + 1u; j < n; j++) {
			uint64_t a = i < c->n_fam ? kof_famcat_fam_id_at(c, i) : kof_famcat_var_id_at(c, i - c->n_fam);
			uint64_t b = j < c->n_fam ? kof_famcat_fam_id_at(c, j) : kof_famcat_var_id_at(c, j - c->n_fam);

			if (a == b)
				return 0;
		}
	return 1;
}

static void oracle_cases(void)
{
	uint32_t f;

	both();
	CK(kof_famcat_add_family(&C, "Mirai", NULL, BOT, &f) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 0, NULL) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_family(&C, "Gafgyt", NULL, ROOT, NULL) == KOF_FAMCAT_OK);
	CK(all_oracle(&C) && all_distinct(&C));
	CK(kof_famcat_family_id(&C, "Mirai") == oracle_family("mirai") && kof_famcat_family_id(&C, "MIRAI") == oracle_family("Mirai"));
	CK(kof_famcat_variant_id(&C, "Mirai", "A") == oracle_variant("mirai", "a"));
	CK(kof_famcat_variant_id(&C, "mirai", "Mirai_B") == oracle_variant("MIRAI", "B"));
	/* the ids are above the reserved range, and the first variant is not its family */
	CK(kof_famcat_fam_id_at(&C, 0) != kof_famcat_var_id_at(&C, 0) && kof_famcat_fam_id_at(&C, 0) >= KOF_CATID_SEED_MAX);
	CK(kof_famcat_fam_id_at(&C, 2) == 0u && kof_famcat_var_id_at(&C, 3) == 0u);
}

static void stable(void)
{
	uint32_t v;
	uint64_t fid, aid, bid;

	both();
	CK(kof_famcat_add_family(&C, "Mirai", "c", BOT, NULL) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 0, &v) == KOF_FAMCAT_OK);
	fid = kof_famcat_fam_id_at(&C, 0);
	aid = kof_famcat_var_id_at(&C, 0);
	bid = kof_famcat_var_id_at(&C, 1);
	CK(kof_famcat_set_types(&C, 0, ROOT) == KOF_FAMCAT_OK && kof_famcat_set_comment(&C, 1, "x") == KOF_FAMCAT_OK &&
	   kof_famcat_set_variant(&C, 1, "y", BOT | TRO) == KOF_FAMCAT_OK);
	CK(kof_famcat_fam_id_at(&C, 0) == fid && kof_famcat_var_id_at(&C, 0) == aid && kof_famcat_var_id_at(&C, 1) == bid);
	/* save, load: the same ids */
	wipe();
	CK(kof_famcat_save(&C, &ST, dir) == KOF_CATSTORE_IO_OK);
	CK(kof_famcat_load(&C2, &ST, dir) == KOF_CATSTORE_IO_OK && C2.n_fam == 1 && C2.n_var == 2);
	CK(kof_famcat_fam_id_at(&C2, 0) == fid && kof_famcat_var_id_at(&C2, 0) == aid && kof_famcat_var_id_at(&C2, 1) == bid && all_oracle(&C2));
	/* a RENAME is a new id for the family and for every variant; the old name has none any more */
	CK(kof_famcat_rename_family(&C, 0, "Mirai2") == KOF_FAMCAT_OK);
	CK(kof_famcat_fam_id_at(&C, 0) != fid && kof_famcat_var_id_at(&C, 0) != aid && kof_famcat_var_id_at(&C, 1) != bid && all_oracle(&C));
	CK(kof_famcat_family_id(&C, "Mirai2") == oracle_family("mirai2") && kof_famcat_family_id(&C, "Mirai") == 0u);
	CK(kof_famcat_variant_id(&C, "Mirai2", "B") == oracle_variant("mirai2", "b"));
	/* a case-only rename keeps every id (a name is one name in any case) */
	CK(kof_famcat_rename_family(&C, 0, "MIRAI2") == KOF_FAMCAT_OK && all_oracle(&C) && kof_famcat_family_id(&C, "mirai2") == oracle_family("Mirai2"));
	CK(kof_famcat_rename_family(&C, 0, "mirai2") == KOF_FAMCAT_OK && kof_famcat_family_id(&C, "MIRAI2") == oracle_family("Mirai2"));
	/* delete a variant and add another: the letter is not reused by default; the new id is the oracle's */
	CK(kof_famcat_delete_variant(&C, 1) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 0, &v) == KOF_FAMCAT_OK);
	CK(!strcmp(C.var[v].name, "mirai2_C") && kof_famcat_var_id_at(&C, v) == oracle_variant("mirai2", "c") && all_oracle(&C));
	/* delete the family and make it again: the same ids come back (no random part, no memory of the deleted one) */
	CK(kof_famcat_delete_family(&C, 0) == KOF_FAMCAT_OK && C.n_fam == 0);
	CK(kof_famcat_add_family(&C, "Mirai", NULL, BOT, NULL) == KOF_FAMCAT_OK && kof_famcat_fam_id_at(&C, 0) == fid && kof_famcat_var_id_at(&C, 0) == aid);
	/* an id is not part of the catalog's value: the dirty test follows the names */
	{
		static struct kof_famcat_fam sf[8];
		static struct kof_famcat_var sv[16];
		struct kof_famcat snap;

		kof_famcat_init(&snap, sf, 8, sv, 16);
		CK(kof_famcat_snapshot(&C, &snap) == KOF_FAMCAT_OK && !kof_famcat_dirty(&C, &snap));
		CK(kof_famcat_rename_family(&C, 0, "Mirai9") == KOF_FAMCAT_OK && kof_famcat_dirty(&C, &snap));
		CK(kof_famcat_restore(&C, &snap) == KOF_FAMCAT_OK && !kof_famcat_dirty(&C, &snap) && kof_famcat_fam_id_at(&C, 0) == fid);
	}
}

/* The same items put in a catalog in another order, or read back from files, have the same ids. */
static void order(void)
{
	static const char *const names[] = { "Zeta", "Alpha", "Mirai", "Gafgyt" };
	unsigned i;

	both();
	for (i = 0; i < 4; i++)
		CK(kof_famcat_add_family(&C, names[i], NULL, BOT, NULL) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_variant(&C, 1, NULL, TRO, 0, NULL) == KOF_FAMCAT_OK);
	for (i = 0; i < 4; i++)
		CK(kof_famcat_add_family(&C2, names[3u - i], NULL, BOT, NULL) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_variant(&C2, 2, NULL, TRO, 0, NULL) == KOF_FAMCAT_OK);   /* Alpha is index 2 here */
	for (i = 0; i < 4; i++)
		CK(kof_famcat_family_id(&C, names[i]) == kof_famcat_family_id(&C2, names[i]) && kof_famcat_family_id(&C, names[i]) != 0u);
	CK(kof_famcat_variant_id(&C, "Alpha", "B") == kof_famcat_variant_id(&C2, "Alpha", "B") && kof_famcat_variant_id(&C, "Alpha", "B") != 0u);
	wipe();
	CK(kof_famcat_save(&C, &ST, dir) == KOF_CATSTORE_IO_OK);
	fresh(&C2, F2, V2);
	CK(kof_famcat_load(&C2, &ST, dir) == KOF_CATSTORE_IO_OK && C2.n_fam == 4 && all_oracle(&C2));
	for (i = 0; i < 4; i++)
		CK(kof_famcat_family_id(&C2, names[i]) == kof_famcat_family_id(&C, names[i]));
}

static int why_names(const char *why, const char *a, const char *b)
{
	char x[80], y[80];

	snprintf(x, sizeof x, "\"%s\"", a);
	snprintf(y, sizeof y, "\"%s\"", b);
	return strstr(why, x) && strstr(why, y) && strstr(why, "same id");
}

static void clash(void)
{
	const char *why = "";
	uint32_t ign, rev, v;
	char text[400], note[400];

	/* family against family: "Alpha" and "Gamma" have keys of one length */
	both();
	kof_famcat_set_idhash(&C, hash_len, NULL);
	CK(kof_famcat_add_family(&C, "Alpha", NULL, BOT, NULL) == KOF_FAMCAT_OK);
	rev = C.rev;
	CK(kof_famcat_add_family(&C, "Gamma", NULL, BOT, NULL) == KOF_FAMCAT_ID_CLASH);
	CK(C.n_fam == 1 && C.n_var == 1 && C.rev == rev && why_names(kof_famcat_why(&C, KOF_FAMCAT_ID_CLASH), "Gamma", "Alpha"));
	CK(kof_famcat_add_family(&C, "Beta", NULL, BOT, NULL) == KOF_FAMCAT_OK);
	CK(!strcmp(kof_famcat_why(&C, KOF_FAMCAT_FULL), kof_famcat_status_text(KOF_FAMCAT_FULL)));
	CK(!strcmp(kof_famcat_status_text(KOF_FAMCAT_ID_CLASH), "that name makes the id of another item"));
	/* a family against a VARIANT: "Ab" has F:ab (4) and V:ab.a (6); the family "Abcd" is F:abcd (6) */
	both();
	kof_famcat_set_idhash(&C, hash_len, NULL);
	CK(kof_famcat_add_family(&C, "Ab", NULL, BOT, NULL) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_family(&C, "Abcd", NULL, BOT, NULL) == KOF_FAMCAT_ID_CLASH && C.n_fam == 1);
	CK(why_names(kof_famcat_why(&C, KOF_FAMCAT_ID_CLASH), "Abcd", "Ab_A"));
	/* a variant against its SIBLING: every variant of "Ab" is V:ab.? (6); the counter does not move */
	rev = C.rev;
	CK(kof_famcat_add_variant(&C, 0, NULL, TRO, 0, NULL) == KOF_FAMCAT_ID_CLASH && C.n_var == 1 && C.fam[0].next == 2u && C.rev == rev);
	CK(why_names(kof_famcat_why(&C, KOF_FAMCAT_ID_CLASH), "Ab_B", "Ab_A"));
	/* the first variant against its own family: a hash that gives every key one number */
	both();
	kof_famcat_set_idhash(&C, hash_const, NULL);
	CK(kof_famcat_add_family(&C, "X", NULL, BOT, NULL) == KOF_FAMCAT_ID_CLASH && C.n_fam == 0 && C.n_var == 0);
	CK(why_names(kof_famcat_why(&C, KOF_FAMCAT_ID_CLASH), "X_A", "X"));
	/* a loaded file: all or none, and the reason names both */
	both();
	kof_famcat_set_idhash(&C, hash_len, NULL);
	snprintf(text, sizeof text, "KOF_MALWARE_FAMILY_NAME(\"Alpha\");\nKOF_MALWARE_VARIANT(\"A\", KOF_MALTYPE_BOTNET);\n");
	CK(kof_famcat_load_text(&C, text, strlen(text), &ign, &why) == 1 && C.n_fam == 1);
	snprintf(text, sizeof text, "KOF_MALWARE_FAMILY_NAME(\"Gamma\");\n");
	CK(kof_famcat_load_text(&C, text, strlen(text), &ign, &why) == 0 && C.n_fam == 1 && why_names(why, "Gamma", "Alpha"));
	snprintf(text, sizeof text, "KOF_MALWARE_FAMILY_NAME(\"Ab\");\nKOF_MALWARE_VARIANT(\"A\", KOF_MALTYPE_BOTNET);\n"
		 "KOF_MALWARE_VARIANT(\"B\", KOF_MALTYPE_TROJAN);\n");
	CK(kof_famcat_load_text(&C, text, strlen(text), &ign, &why) == 0 && C.n_fam == 1 && C.n_var == 1 && why_names(why, "Ab_B", "Ab_A"));
	/* a directory: the second file is refused and the note names both families */
	both();
	wipe();
	put("alpha.c", "KOF_MALWARE_FAMILY_NAME(\"Alpha\");\nKOF_MALWARE_VARIANT(\"A\", KOF_MALTYPE_BOTNET);\n");
	put("gamma.c", "KOF_MALWARE_FAMILY_NAME(\"Gamma\");\nKOF_MALWARE_VARIANT(\"A\", KOF_MALTYPE_BOTNET);\n");
	kof_famcat_set_idhash(&C, hash_len, NULL);
	CK(kof_famcat_load(&C, &ST, dir) == KOF_CATSTORE_IO_OK && ST.n_bad == 1 && C.n_fam == 1);
	CK(strstr(ST.note, "gamma.c") && why_names(ST.note, "Gamma", "Alpha"));
	snprintf(note, sizeof note, "%s", ST.note);
	both();
	kof_famcat_set_idhash(&C, hash_len, NULL);
	CK(kof_famcat_load_dir(&C, dir, note, sizeof note) == KOF_CATSTORE_IO_OK && why_names(note, "Gamma", "Alpha"));
	/* a rename: the renamed family against another family's items */
	both();
	kof_famcat_set_idhash(&C, hash_len, NULL);
	CK(kof_famcat_add_family(&C, "Ab", NULL, BOT, NULL) == KOF_FAMCAT_OK && kof_famcat_add_family(&C, "Q", NULL, BOT, NULL) == KOF_FAMCAT_OK);
	rev = C.rev;
	CK(kof_famcat_rename_family(&C, 1, "Qrst") == KOF_FAMCAT_ID_CLASH && !strcmp(C.fam[1].name, "Q") && !strcmp(C.var[1].name, "Q_A") && C.rev == rev);
	CK(why_names(kof_famcat_why(&C, KOF_FAMCAT_ID_CLASH), "Qrst", "Ab_A"));
	/* a renamed family's items are checked as NEW ids, not against their own old ones: Q (F:q 3, V:q.a 5) -> Qrs (F:qrs 5, V:qrs.a 7) */
	CK(kof_famcat_rename_family(&C, 1, "Qrs") == KOF_FAMCAT_OK && !strcmp(C.var[1].name, "Qrs_A") && all_distinct(&C));
	(void)v;
}

/* A hash with five values: clashes are everywhere. Whatever is asked, the catalog never holds two items of one id, and a refused call
 * changes nothing (the revision included). */
static void property(void)
{
	static const char *const names[] = { "a", "b", "c", "d", "e", "ab", "ba", "abc", "cba", "q", "qq", "r1", "r2", "s_s", "T-t" };
	unsigned step, refused = 0, done = 0;
	uint32_t seed = 12345u;

	both();
	kof_famcat_set_idhash(&C, hash_mod5, NULL);
	for (step = 0; step < 4000u; step++) {
		uint32_t rev = C.rev, nf = C.n_fam, nv = C.n_var, r;
		enum kof_famcat_status st;

		seed = seed * 1103515245u + 12345u;
		r = seed >> 8;
		switch (r % 6u) {
		case 0:
		case 1:
			st = kof_famcat_add_family(&C, names[(r >> 4) % 15u], NULL, BOT << ((r >> 9) % 3u), NULL);
			break;
		case 2:
			st = C.n_fam ? kof_famcat_add_variant(&C, (r >> 4) % C.n_fam, NULL, 1u << (KOF_MALTYPE_BOTNET + (r >> 9) % 5u), (int)(r >> 14 & 1u), NULL) : KOF_FAMCAT_OK;
			break;
		case 3:
			st = C.n_fam ? kof_famcat_rename_family(&C, (r >> 4) % C.n_fam, names[(r >> 9) % 15u]) : KOF_FAMCAT_OK;
			break;
		case 4:
			st = C.n_fam > 5u ? kof_famcat_delete_family(&C, (r >> 4) % C.n_fam) : KOF_FAMCAT_OK;
			break;
		default:
			st = C.n_var > 8u ? kof_famcat_delete_variant(&C, (r >> 4) % C.n_var) : KOF_FAMCAT_OK;
			break;
		}
		CK(all_distinct(&C));
		if (st == KOF_FAMCAT_ID_CLASH) {
			refused++;
			CK(C.rev == rev && C.n_fam == nf && C.n_var == nv && strstr(kof_famcat_why(&C, st), "same id"));
		} else if (st == KOF_FAMCAT_OK) {
			done++;
		}
		if (fails > 20)
			break;
	}
	/* the property is empty when nothing was ever refused or ever done */
	CK(refused > 50u && done > 200u);
}

static void old_file(void)
{
	static const char old[] =
		"// Generated by Manage > Pathogens; edit by hand with care.\n"
		"KOF_MALWARE_FAMILY_NAME(\"Mirai\");\n"
		"KOF_MALWARE_FAMILY_ID(0xc627704b844b1723);\n"
		"KOF_MALWARE_NEXT_VARIANT(\"C\");\n"
		"// Well known IOT botnet\n"
		"KOF_MALWARE_VARIANT(\"A\", KOF_MALTYPE_BOTNET);\n"
		"KOF_MALWARE_VARIANT_ID(\"A\", 0x1358c2d70def8cc0);\n"
		"KOF_MALWARE_VARIANT(\"B\", KOF_MALTYPE_TROJAN);\n"
		"KOF_MALWARE_VARIANT_ID(\"B\", 0x1);\n"           /* reserved: was an error, is only ignored now */
		"KOF_MALWARE_VARIANT_ID(\"B\", 0x1);\n"           /* twice */
		"KOF_MALWARE_FAMILY_ID(0x2000g);\n";             /* malformed */
	char *t1, *t2;
	uint64_t fid, aid, bid;

	both();
	wipe();
	put("mirai.c", old);
	CK(kof_famcat_load(&C, &ST, dir) == KOF_CATSTORE_IO_OK && ST.n_bad == 0 && C.n_fam == 1 && C.n_var == 2);
	CK(ST.n_ignored == 5 && strstr(ST.note, "5 lines ignored"));
	/* the old numbers are used nowhere: the ids are the oracle's */
	fid = kof_famcat_family_id(&C, "Mirai");
	aid = kof_famcat_variant_id(&C, "Mirai", "A");
	bid = kof_famcat_variant_id(&C, "Mirai", "B");
	CK(fid == oracle_family("mirai") && aid == oracle_variant("mirai", "a") && bid == oracle_variant("mirai", "b"));
	CK(fid != 0xc627704b844b1723ull && aid != 0x1358c2d70def8cc0ull && bid != 1u);
	CK(C.var[0].comment[0] && !strcmp(C.var[0].comment, "Well known IOT botnet"));   /* the id line did not take the comment */
	t1 = slurp("mirai.c");
	CK(t1 && !strcmp(t1, old));                       /* loading wrote nothing */
	/* Save writes the file without the lines, and a load of that has nothing to ignore */
	CK(kof_famcat_save(&C, &ST, dir) == KOF_CATSTORE_IO_OK);
	t2 = slurp("mirai.c");
	CK(t2 && !strstr(t2, "_ID(") && strstr(t2, "// Well known IOT botnet\nKOF_MALWARE_VARIANT(\"A\"") && strstr(t2, "KOF_MALWARE_NEXT_VARIANT(\"C\")"));
	CK(kof_famcat_load(&C2, &ST, dir) == KOF_CATSTORE_IO_OK && ST.n_ignored == 0 && kof_famcat_family_id(&C2, "Mirai") == fid &&
	   kof_famcat_variant_id(&C2, "Mirai", "B") == bid);
	free(t1);
	free(t2);
	/* the same lines with the family's name AFTER an id line, or an id line alone, are still only ignored */
	both();
	{
		uint32_t ign = 0;
		const char *why = "";
		static const char odd[] = "KOF_MALWARE_FAMILY_ID(0x20000);\nKOF_MALWARE_FAMILY_NAME(\"Mirai\");\nKOF_MALWARE_VARIANT_ID(\"A\", 0x30000);\n";

		CK(kof_famcat_load_text(&C, odd, strlen(odd), &ign, &why) == 1 && ign == 2 && C.n_fam == 1 && C.n_var == 0);
	}
}

static void bytes(void)
{
	static const char with_unknown[] =
		"// Generated by Manage > Pathogens; edit by hand with care.\n"
		"KOF_MALWARE_FAMILY_NAME(\"Mirai\");\n"
		"SOME_FUTURE_LINE(1);\n"
		"KOF_MALWARE_NEXT_VARIANT(\"B\");\n"
		"KOF_MALWARE_VARIANT(\"A\", KOF_MALTYPE_BOTNET);\n";
	char *t;

	both();
	wipe();
	CK(kof_famcat_add_family(&C, "Mirai", "one", BOT, NULL) == KOF_FAMCAT_OK && kof_famcat_add_variant(&C, 0, NULL, TRO, 0, NULL) == KOF_FAMCAT_OK);
	CK(kof_famcat_add_family(&C, "Gafgyt", NULL, ROOT, NULL) == KOF_FAMCAT_OK);
	CK(kof_famcat_save(&C, &ST, dir) == KOF_CATSTORE_IO_OK);
	/* save, load, save to the same files: identical bytes, and no file holds an id */
	{
		char *a = slurp("mirai.c"), *b = slurp("gafgyt.c");

		CK(a && b && !strstr(a, "_ID") && !strstr(b, "_ID") && !strstr(a, "0x") && !strstr(b, "0x"));
		CK(kof_famcat_load(&C2, &ST, dir) == KOF_CATSTORE_IO_OK && ST.n_ignored == 0);
		CK(kof_famcat_save(&C2, &ST, dir) == KOF_CATSTORE_IO_OK);
		{
			char *a2 = slurp("mirai.c"), *b2 = slurp("gafgyt.c");

			CK(a2 && b2 && !strcmp(a, a2) && !strcmp(b, b2));
			free(a2);
			free(b2);
		}
		free(a);
		free(b);
	}
	/* an unknown line is counted and a save writes the model only */
	both();
	wipe();
	put("mirai.c", with_unknown);
	CK(kof_famcat_load(&C, &ST, dir) == KOF_CATSTORE_IO_OK && ST.n_bad == 0 && ST.n_ignored == 1 && strstr(ST.note, "1 line ignored"));
	CK(kof_famcat_save(&C, &ST, dir) == KOF_CATSTORE_IO_OK);
	t = slurp("mirai.c");
	CK(t && !strstr(t, "SOME_FUTURE_LINE"));
	free(t);
	wipe();
}

static void api(void)
{
	char note[320] = "x";

	both();
	wipe();
	CK(kof_famcat_add_family(&C, "Mirai", NULL, BOT | ROOT, NULL) == KOF_FAMCAT_OK && kof_famcat_add_variant(&C, 0, NULL, TRO, 0, NULL) == KOF_FAMCAT_OK);
	CK(kof_famcat_family_id(&C, "Mirai") == kof_famcat_fam_id_at(&C, 0) && kof_famcat_family_id(&C, "mIRAI") == kof_famcat_fam_id_at(&C, 0));
	CK(kof_famcat_variant_id(&C, "Mirai", "A") == kof_famcat_var_id_at(&C, 0) && kof_famcat_variant_id(&C, "Mirai", "B") == kof_famcat_var_id_at(&C, 1));
	CK(kof_famcat_variant_id(&C, "Mirai", "Mirai_B") == kof_famcat_var_id_at(&C, 1) && kof_famcat_variant_id(&C, "mirai", "Mirai_A") == kof_famcat_var_id_at(&C, 0));
	CK(kof_famcat_variant_types(&C, "Mirai", "A") == (BOT | ROOT) && kof_famcat_variant_types(&C, "Mirai", "B") == TRO);
	CK(kof_famcat_family_id(&C, "Nope") == 0u && kof_famcat_family_id(&C, NULL) == 0u && kof_famcat_family_id(&C, "") == 0u);
	CK(kof_famcat_variant_id(&C, "Mirai", "C") == 0u && kof_famcat_variant_id(&C, "Mirai", "a") == 0u && kof_famcat_variant_id(&C, "Mirai", NULL) == 0u);
	CK(kof_famcat_variant_id(&C, "Nope", "A") == 0u && kof_famcat_variant_id(&C, "Mirai", "Other_A") == 0u && kof_famcat_variant_id(&C, "Mirai", "") == 0u);
	CK(kof_famcat_variant_types(&C, "Mirai", "Z") == 0u);
	CK(kof_famcat_save(&C, &ST, dir) == KOF_CATSTORE_IO_OK);
	/* the loader a build tool calls: no store, no dialog */
	CK(kof_famcat_load_dir(&C2, dir, note, sizeof note) == KOF_CATSTORE_IO_OK && note[0] == 0 && C2.n_fam == 1 && C2.n_var == 2);
	CK(kof_famcat_family_id(&C2, "Mirai") == kof_famcat_family_id(&C, "Mirai") && kof_famcat_variant_id(&C2, "Mirai", "B") == oracle_variant("mirai", "b"));
	CK(kof_famcat_load_dir(&C2, "", note, sizeof note) == KOF_CATSTORE_IO_NO_DIR && strstr(note, "no pathogens directory") && C2.n_fam == 0);
	CK(kof_famcat_load_dir(&C2, NULL, NULL, 0) == KOF_CATSTORE_IO_NO_DIR);
	{
		char missing[200];

		snprintf(missing, sizeof missing, "%s/nowhere", dir);
		CK(kof_famcat_load_dir(&C2, missing, note, sizeof note) == KOF_CATSTORE_IO_OK && C2.n_fam == 0);
	}
	wipe();
}

int main(void)
{
	char tmpl[] = "build/kof_famcat_ids_XXXXXX";

	if (!mkdtemp(tmpl)) {
		printf("famcat_ids: cannot make a scratch directory\n");
		return 1;
	}
	snprintf(dir, sizeof dir, "%s", tmpl);
	oracle_cases();
	stable();
	order();
	clash();
	property();
	old_file();
	bytes();
	api();
	wipe();
	rmdir(dir);
	printf("famcat_ids: %d failure(s)\n", fails);
	return fails != 0;
}
