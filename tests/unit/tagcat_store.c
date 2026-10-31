/*
 * tagcat_store - the ids and the files of the tag catalog (libkofeng/verdictor/tagcat.c, tagcat_store.c, catstore.c):
 *   NAME      the file name `<objects>_<activities>.c` of every set of 1..3 activities against every set of 0..3 objects, against an
 *             oracle written here (words sorted, joined with '-'); distinct pairs give distinct names, one '_' each
 *   FILES     tags with the same two sets are one file, different sets two; an edit of the sets moves the tag, an emptied file is removed
 *   IDS       the id of a tag is a function of its NAME (catstore.h), checked against catid_oracle.h which shares no code with the library:
 *             an edit of the sets, a save and a load keep it, a rename changes it, a deleted and re-made tag has it back; a hash that makes
 *             two names one id (kof_tagcat_set_idhash) makes add, edit, rename and the loader refuse with KOF_TAGCAT_ID_CLASH, nothing
 *             changed, both names in kof_tagcat_why; a property run over a five-valued hash keeps every id distinct
 *   LOAD      a missing or wrong activity, a repeated line or a bad name refuses the file whole; a file with the OLD id lines
 *             (KOF_TAG_ID, even malformed or reserved) loads, the lines are counted as ignored and Save writes none; a moved file is
 *             still read; unknown lines are counted
 *   BYTES     save, load, save is byte-identical over files of several tags
 *   API       kof_tagcat_id / kof_tagcat_id_at / kof_tagcat_load_dir, snapshot / restore / dirty field by field
 * Files live under build/kof_tagcat_store_XXXXXX and are removed at the end.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include <kofmod/kofsig.h>
#include "../../libkofeng/verdictor/tagcat.h"
#include "catid_oracle.h"

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

#define A(n) (1u << (n))         /* the activity / object with engine value n */

static char dir[128];
static struct kof_tagcat_tag T[64], T2[64], TS[64];
static struct kof_tagcat C, C2, S;
static struct kof_catstore ST;

/* The loader's step with no comment. */
static enum kof_tagcat_status ld(const char *name, uint32_t acts, uint32_t objs)
{
	struct kof_tagcat_fields f = { name, NULL, acts, objs };

	return kof_tagcat_load_tag(&C, &f, NULL);
}

/* A hash that makes two keys of one LENGTH one number: "T:flood" and "T:block" collide, "T:scan" does not. */
static uint64_t hash_len(void *ud, const char *key, size_t len)
{
	(void)ud;
	(void)key;
	return 0x20000u + len;
}

/* Five numbers, spread by the real hash: a collision is common and depends on every character of the key. */
static uint64_t hash_mod5(void *ud, const char *key, size_t len)
{
	return 0x20000u + kof_catid_hash(ud, key, len) % 5u;
}

static void fresh(struct kof_tagcat *c, struct kof_tagcat_tag *t)
{
	memset(t, 0, 64 * sizeof *t);
	kof_tagcat_init(c, t, 64);
}

static void all(void)
{
	fresh(&C, T);
	fresh(&C2, T2);
	fresh(&S, TS);
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

static int exists(const char *name)
{
	char p[256];
	struct stat st;

	snprintf(p, sizeof p, "%s/%s", dir, name);
	return stat(p, &st) == 0;
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

static unsigned count_files(void)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	unsigned n = 0;

	while (d && (e = readdir(d)) != NULL)
		n += e->d_name[0] != '.';
	if (d)
		closedir(d);
	return n;
}

/* ---- the file name rule, against an oracle ---------------------------------------------------------------------------- */

static void oracle_set(uint32_t mask, uint32_t n, const char *(*word)(uint32_t), const char *none, char *out)
{
	const char *w[16];
	uint32_t i, j, k = 0;

	for (i = 0; i < n; i++)
		if (mask >> (i + 1u) & 1u)
			w[k++] = word(i);
	if (!k)
		w[k++] = none;
	for (i = 1; i < k; i++)                       /* an insertion sort: not the library's qsort */
		for (j = i; j > 0 && strcmp(w[j - 1], w[j]) > 0; j--) {
			const char *t = w[j];

			w[j] = w[j - 1];
			w[j - 1] = t;
		}
	out[0] = 0;
	for (i = 0; i < k; i++) {
		if (i)
			strcat(out, "-");
		strcat(out, w[i]);
	}
}

static int row_cmp(const void *a, const void *b)
{
	return strcmp(a, b);
}

static void names(void)
{
	static char seen[12000][100];
	uint32_t na = kof_tagcat_act_count(), no = kof_tagcat_obj_count(), a, o;
	unsigned n = 0, i, total = 0;
	char want[256], oo[100], aa[100], got[200];

	CK(na == 9 && no == 8);
	for (a = 1; a < (1u << na); a++) {
		unsigned pa = (unsigned)__builtin_popcount(a);

		if (pa > 3)
			continue;
		for (o = 0; o < (1u << no); o++) {
			unsigned po = (unsigned)__builtin_popcount(o);

			if (po > 3)
				continue;
			oracle_set(a << 1, na, kof_tagcat_act_name, "none", aa);
			oracle_set(o << 1, no, kof_tagcat_obj_name, "none", oo);
			snprintf(want, sizeof want, "%s_%s.c", oo, aa);
			kof_tagcat_file_name(a << 1, o << 1, got, sizeof got);
			CK(!strcmp(got, want));
			CK(strchr(got, '_') && !strchr(strchr(got, '_') + 1, '_') && strlen(got) < KOF_TAGCAT_FILENAME_MAX);
			for (i = 0; i < strlen(got); i++)
				CK((got[i] >= 'a' && got[i] <= 'z') || (got[i] >= '0' && got[i] <= '9') || got[i] == '-' || got[i] == '_' || got[i] == '.');
			CK(strlen(got) < sizeof seen[0]);
			if (n < 12000)
				memcpy(seen[n++], got, strlen(got) + 1u);
			total++;
		}
	}
	/* 129 non-empty sets of 1..3 of 9 against 93 sets of 0..3 of 8 (empty = none): every pair has its own name */
	CK(total == (9u + 36u + 84u) * (1u + 8u + 28u + 56u) && n == total);
	{
		unsigned bad = 0;

		qsort(seen, n, sizeof seen[0], row_cmp);
		for (i = 1; i < n; i++)
			bad += !strcmp(seen[i], seen[i - 1u]);
		CK(bad == 0);
	}
	/* the two samples in the owner's words, and a name that does not fit is empty, never cut */
	kof_tagcat_file_name(A(KOF_DISEASE_ACT_SCAN) | A(KOF_DISEASE_ACT_STEAL), A(KOF_DISEASE_OBJ_NETWORK) | A(KOF_DISEASE_OBJ_FILE), got, sizeof got);
	CK(!strcmp(got, "file-network_scan-steal.c"));
	kof_tagcat_file_name(A(KOF_DISEASE_ACT_HIDDEN), 0, got, sizeof got);
	CK(!strcmp(got, "none_hidden.c"));
	kof_tagcat_file_name(A(KOF_DISEASE_ACT_HIDDEN), 0, got, 13);
	CK(got[0] == 0);
	kof_tagcat_file_name(A(KOF_DISEASE_ACT_HIDDEN), 0, got, 14);
	CK(!strcmp(got, "none_hidden.c"));
	kof_tagcat_file_name(A(KOF_DISEASE_ACT_HIDDEN), 0, got, 0);
	/* the largest: every activity and every object fits the file system's limit */
	kof_tagcat_file_name(kof_tagcat_act_mask_all(), kof_tagcat_obj_mask_all(), got, sizeof got);
	CK(got[0] && strlen(got) < KOF_TAGCAT_FILENAME_MAX);
}

/* ---- files ------------------------------------------------------------------------------------------------------------ */

#define SCAN A(KOF_DISEASE_ACT_SCAN)
#define STEAL A(KOF_DISEASE_ACT_STEAL)
#define NET A(KOF_DISEASE_OBJ_NETWORK)
#define FIL A(KOF_DISEASE_OBJ_FILE)

static void files(void)
{
	char *t;
	uint32_t i;

	all();
	wipe();
	CK(kof_tagcat_add(&C, "flood", SCAN | STEAL, NET | FIL, NULL) == KOF_TAGCAT_OK);
	CK(kof_tagcat_add(&C, "lonely", A(KOF_DISEASE_ACT_HIDDEN), 0, NULL) == KOF_TAGCAT_OK);
	CK(kof_tagcat_add(&C, "syn-flood", SCAN | STEAL, NET | FIL, NULL) == KOF_TAGCAT_OK);
	CK(kof_tagcat_file_count(&C) == 2);
	CK(kof_tagcat_save(&C, &ST, dir) == KOF_CATSTORE_IO_OK && ST.n_file == 2 && count_files() == 2);
	CK(exists("file-network_scan-steal.c") && exists("none_hidden.c"));
	t = slurp("file-network_scan-steal.c");
	{
		static const char want[] =
			 "// Generated by Manage > Syndromes; edit by hand with care.\n"
			 "\n"
			 "KOF_TAG_NAME(\"flood\");\n"
			 "KOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN, KOF_DISEASE_ACT_STEAL);\n"
			 "KOF_TAG_OBJS(KOF_DISEASE_OBJ_NETWORK, KOF_DISEASE_OBJ_FILE);\n"
			 "\n"
			 "KOF_TAG_NAME(\"syn-flood\");\n"
			 "KOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN, KOF_DISEASE_ACT_STEAL);\n"
			 "KOF_TAG_OBJS(KOF_DISEASE_OBJ_NETWORK, KOF_DISEASE_OBJ_FILE);\n";

		CK(t && !strcmp(t, want));
	}
	free(t);
	t = slurp("none_hidden.c");
	CK(t && strstr(t, "KOF_TAG_NAME(\"lonely\");") && strstr(t, "KOF_TAG_ACTS(KOF_DISEASE_ACT_HIDDEN);\nKOF_TAG_OBJS();\n") && !strstr(t, "flood"));
	free(t);
	/* the same tags load back whatever the order of the files, and every id is as it was */
	CK(kof_tagcat_load(&C2, &ST, dir) == KOF_CATSTORE_IO_OK && ST.n_bad == 0 && C2.n == 3);
	for (i = 0; i < 3; i++)
		CK(kof_tagcat_id(&C2, C.tag[i].name) == oracle_tag(C.tag[i].name) && kof_tagcat_id(&C2, C.tag[i].name) == kof_tagcat_id_at(&C, i) &&
		   kof_tagcat_get(&C2, 0) != NULL);
	/* an edit of the sets moves the tag; the old file keeps the others; emptied, it is removed */
	CK(kof_tagcat_set_acts(&C, 2, STEAL) == KOF_TAGCAT_OK && kof_tagcat_file_count(&C) == 3);
	CK(kof_tagcat_save(&C, &ST, dir) == KOF_CATSTORE_IO_OK && count_files() == 3 && exists("file-network_steal.c"));
	t = slurp("file-network_scan-steal.c");
	CK(t && strstr(t, "\"flood\"") && !strstr(t, "syn-flood"));
	free(t);
	CK(kof_tagcat_set_acts(&C, 0, STEAL) == KOF_TAGCAT_OK && kof_tagcat_file_count(&C) == 2);
	CK(kof_tagcat_save(&C, &ST, dir) == KOF_CATSTORE_IO_OK && count_files() == 2 && !exists("file-network_scan-steal.c"));
	t = slurp("file-network_steal.c");
	CK(t && strstr(t, "\"flood\"") && strstr(t, "\"syn-flood\""));
	free(t);
	/* a delete removes the file of a pair nobody has any more */
	CK(kof_tagcat_delete(&C, 1) == KOF_TAGCAT_OK && kof_tagcat_save(&C, &ST, dir) == KOF_CATSTORE_IO_OK && !exists("none_hidden.c") && count_files() == 1);
	/* a file that was not loaded is not touched and is in the way of the one with its name */
	all();
	wipe();
	put("file-network_scan-steal.c", "// not ours: nobody loaded it\n");
	CK(kof_tagcat_add(&C, "flood", SCAN | STEAL, NET | FIL, NULL) == KOF_TAGCAT_OK);
	CK(kof_tagcat_save(&C, &ST, dir) == KOF_CATSTORE_IO_COLLISION && strstr(ST.note, "not loaded"));
	t = slurp("file-network_scan-steal.c");
	CK(t && !strcmp(t, "// not ours: nobody loaded it\n"));
	free(t);
	/* no directory named */
	CK(kof_tagcat_save(&C, &ST, "") == KOF_CATSTORE_IO_NO_DIR && strstr(ST.note, "no syndromes directory"));
	CK(kof_tagcat_load(&C2, &ST, NULL) == KOF_CATSTORE_IO_NO_DIR && strstr(ST.note, "--syndromes"));
	wipe();
}

/* ---- ids -------------------------------------------------------------------------------------------------------------- */

static int tag_all_distinct(const struct kof_tagcat *c)
{
	uint32_t i, j;

	for (i = 0; i < c->n; i++)
		for (j = i + 1u; j < c->n; j++)
			if (kof_tagcat_id_at(c, i) == kof_tagcat_id_at(c, j))
				return 0;
	return 1;
}

static int why_names(const char *why, const char *a, const char *b)
{
	char x[80], y[80];

	snprintf(x, sizeof x, "\"%s\"", a);
	snprintf(y, sizeof y, "\"%s\"", b);
	return strstr(why, x) && strstr(why, y) && strstr(why, "same id");
}

static void ids(void)
{
	uint64_t id0;
	uint32_t i, rev;
	static const char *const nm[] = { "flood", "Scan", "c2", "Mirai-flood", "x-1" };

	all();
	for (i = 0; i < 5; i++)
		CK(kof_tagcat_add(&C, nm[i], SCAN, 0, NULL) == KOF_TAGCAT_OK);
	for (i = 0; i < 5; i++)
		CK(kof_tagcat_id_at(&C, i) == oracle_tag(nm[i]) && kof_tagcat_id(&C, nm[i]) == oracle_tag(nm[i]) && kof_tagcat_id_at(&C, i) >= KOF_CATID_SEED_MAX);
	CK(tag_all_distinct(&C));
	/* a lookup ignores letter case like the uniqueness rule; an unknown name, NULL and "" have no id; an index past the end has none */
	CK(kof_tagcat_id(&C, "FLOOD") == oracle_tag("flood") && kof_tagcat_id(&C, "scan") == oracle_tag("SCAN"));
	CK(kof_tagcat_id(&C, "nope") == 0u && kof_tagcat_id(&C, NULL) == 0u && kof_tagcat_id(&C, "") == 0u && kof_tagcat_id_at(&C, 5) == 0u);
	/* a tag id is not a family's id of the same name (the kind is in the key) */
	CK(oracle_tag("mirai") != oracle_family("mirai"));
	/* an edit of the sets, a change of one set: the id stays; a rename is a new id; a case-only rename is not */
	id0 = kof_tagcat_id_at(&C, 0);
	CK(kof_tagcat_edit(&C, 0, "flood", STEAL, NET) == KOF_TAGCAT_OK && kof_tagcat_id_at(&C, 0) == id0);
	CK(kof_tagcat_set_objs(&C, 0, 0) == KOF_TAGCAT_OK && kof_tagcat_set_acts(&C, 0, SCAN | STEAL) == KOF_TAGCAT_OK && kof_tagcat_id_at(&C, 0) == id0);
	CK(kof_tagcat_set_comment(&C, 0, "note") == KOF_TAGCAT_OK && kof_tagcat_id_at(&C, 0) == id0);
	CK(kof_tagcat_rename(&C, 0, "FLOOD") == KOF_TAGCAT_OK && kof_tagcat_id_at(&C, 0) == id0);
	CK(kof_tagcat_rename(&C, 0, "flood2") == KOF_TAGCAT_OK && kof_tagcat_id_at(&C, 0) == oracle_tag("flood2") && kof_tagcat_id_at(&C, 0) != id0);
	CK(kof_tagcat_id(&C, "flood") == 0u && kof_tagcat_id(&C, "flood2") == oracle_tag("flood2"));
	/* delete and make again: the same id (no random part, no memory of the deleted one) */
	CK(kof_tagcat_delete(&C, 0) == KOF_TAGCAT_OK && kof_tagcat_id(&C, "flood2") == 0u);
	CK(kof_tagcat_add(&C, "flood", SCAN, 0, NULL) == KOF_TAGCAT_OK && kof_tagcat_id(&C, "flood") == id0);
	/* the order of adding does not matter */
	all();
	for (i = 0; i < 5; i++)
		CK(kof_tagcat_add(&C2, nm[4u - i], SCAN, 0, NULL) == KOF_TAGCAT_OK);
	for (i = 0; i < 5; i++)
		CK(kof_tagcat_id(&C2, nm[i]) == oracle_tag(nm[i]));
	/* the loader's step: the rules of add stay (a duplicate, no activity) */
	all();
	CK(ld("a", SCAN, 0) == KOF_TAGCAT_OK && ld("A", SCAN, 0) == KOF_TAGCAT_DUPLICATE && ld("d", 0, 0) == KOF_TAGCAT_NO_ACTIVITY && C.n == 1);
	/* the tag table is the caller's: a full one is FULL */
	{
		static struct kof_tagcat_tag one[1];
		struct kof_tagcat tiny;

		kof_tagcat_init(&tiny, one, 1);
		CK(kof_tagcat_add(&tiny, "a", SCAN, 0, NULL) == KOF_TAGCAT_OK && kof_tagcat_add(&tiny, "b", SCAN, 0, NULL) == KOF_TAGCAT_FULL);
	}
	/* CLASH: add, edit, rename, the loader; the catalog and its revision are as they were; the reason names both */
	all();
	kof_tagcat_set_idhash(&C, hash_len, NULL);
	CK(kof_tagcat_add(&C, "flood", SCAN, 0, NULL) == KOF_TAGCAT_OK);
	rev = C.rev;
	CK(kof_tagcat_add(&C, "block", SCAN, 0, NULL) == KOF_TAGCAT_ID_CLASH && C.n == 1 && C.rev == rev);
	CK(why_names(kof_tagcat_why(&C, KOF_TAGCAT_ID_CLASH), "block", "flood"));
	CK(!strcmp(kof_tagcat_why(&C, KOF_TAGCAT_FULL), kof_tagcat_status_text(KOF_TAGCAT_FULL)));
	CK(!strcmp(kof_tagcat_status_text(KOF_TAGCAT_ID_CLASH), "that name makes the id of another tag"));
	CK(ld("block", SCAN, 0) == KOF_TAGCAT_ID_CLASH && C.n == 1);
	CK(kof_tagcat_add(&C, "scan", SCAN, 0, NULL) == KOF_TAGCAT_OK);
	rev = C.rev;
	CK(kof_tagcat_rename(&C, 1, "flaps") == KOF_TAGCAT_ID_CLASH && !strcmp(C.tag[1].name, "scan") && C.rev == rev);
	CK(why_names(kof_tagcat_why(&C, KOF_TAGCAT_ID_CLASH), "flaps", "flood"));
	CK(kof_tagcat_edit(&C, 1, "flaps", STEAL, 0) == KOF_TAGCAT_ID_CLASH && C.tag[1].acts == SCAN);
	CK(kof_tagcat_rename(&C, 1, "sc") == KOF_TAGCAT_OK && kof_tagcat_rename(&C, 0, "flood") == KOF_TAGCAT_OK);   /* itself: not a clash */
	/* a loaded file: all or none, and the reason names both */
	{
		const char *why = "";
		uint32_t ign;
		static const char two[] = "KOF_TAG_NAME(\"zeta\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n"
					  "KOF_TAG_NAME(\"beta\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n";

		all();
		kof_tagcat_set_idhash(&C, hash_len, NULL);
		CK(kof_tagcat_load_text(&C, two, strlen(two), &ign, &why) == 0 && C.n == 0 && why_names(why, "beta", "zeta"));
		wipe();
		put("a_scan.c", "KOF_TAG_NAME(\"zeta\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n");
		put("b_scan.c", "KOF_TAG_NAME(\"beta\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n");
		CK(kof_tagcat_load(&C, &ST, dir) == KOF_CATSTORE_IO_OK && ST.n_bad == 1 && C.n == 1 && strstr(ST.note, "b_scan.c") && why_names(ST.note, "beta", "zeta"));
		wipe();
	}
	/* property: over a hash with five values, whatever is asked, ids stay distinct and a refused call changes nothing */
	{
		static const char *const pool[] = { "a", "b", "c", "d", "e", "ab", "ba", "abc", "cba", "q", "qq", "r1", "r2", "s-s", "T-t" };
		unsigned step, refused = 0, done = 0;
		uint32_t seed = 777u;

		all();
		kof_tagcat_set_idhash(&C, hash_mod5, NULL);
		for (step = 0; step < 3000u; step++) {
			uint32_t r, r0, n0;
			enum kof_tagcat_status st;

			seed = seed * 1103515245u + 12345u;
			r = seed >> 8;
			r0 = C.rev;
			n0 = C.n;
			if (r % 4u == 0u && C.n)
				st = kof_tagcat_rename(&C, (r >> 4) % C.n, pool[(r >> 9) % 15u]);
			else if (r % 4u == 1u && C.n > 4u)
				st = kof_tagcat_delete(&C, (r >> 4) % C.n);
			else
				st = kof_tagcat_add(&C, pool[(r >> 9) % 15u], SCAN, 0, NULL);
			CK(tag_all_distinct(&C));
			if (st == KOF_TAGCAT_ID_CLASH) {
				refused++;
				CK(C.rev == r0 && C.n == n0 && strstr(kof_tagcat_why(&C, st), "same id"));
			} else if (st == KOF_TAGCAT_OK) {
				done++;
			}
			if (fails > 20)
				break;
		}
		CK(refused > 50u && done > 150u);
	}
}

/* ---- loading ---------------------------------------------------------------------------------------------------------- */

static void loading(void)
{
	static const char one[] = "KOF_TAG_NAME(\"a\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n";
	static const struct { const char *text; const char *why; } bad[] = {
		{ "KOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\nKOF_TAG_NAME(\"a\");\n", "activities before the tag name" },
		{ "KOF_TAG_OBJS(KOF_DISEASE_OBJ_FILE);\n", "objects before the tag name" },
		{ "KOF_TAG_NAME(\"a\");\n", "Select at least one Activity" },
		{ "KOF_TAG_NAME(\"a\");\nKOF_TAG_ACTS();\n", "Select at least one Activity" },
		{ "KOF_TAG_NAME(\"a\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\nKOF_TAG_ACTS(KOF_DISEASE_ACT_STEAL);\n", "activities given twice" },
		{ "KOF_TAG_NAME(\"a\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\nKOF_TAG_OBJS();\nKOF_TAG_OBJS();\n", "objects given twice" },
		{ "KOF_TAG_NAME(\"a\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_NOPE);\n", "malformed line" },
		{ "KOF_TAG_NAME(\"a\");\nKOF_TAG_ACTS(KOF_DISEASE_OBJ_FILE);\n", "malformed line" },
		{ "KOF_TAG_NAME(\"a\");\nKOF_TAG_ACTS(SCAN);\n", "malformed line" },
		{ "KOF_TAG_NAME(\"a\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN,);\n", "malformed line" },
		{ "KOF_TAG_NAME(\"a\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN KOF_DISEASE_ACT_STEAL);\n", "malformed line" },
		{ "KOF_TAG_NAME(\"a\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\nKOF_TAG_OBJS(KOF_DISEASE_ACT_SCAN);\n", "malformed line" },
		{ "KOF_TAG_NAME(\"a\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN)\n", "malformed line" },
		{ "KOF_TAG_NAME(\"Up_per\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n", "letters, digits and - only" },
		{ "KOF_TAG_NAME(\"\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n", "the name is empty" },
		{ "KOF_TAG_NAME(a);\n", "malformed line" },
		{ "KOF_TAG_NAME(\"a\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\nKOF_TAG_NAME(\"A\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n", "that name is already used" },
		{ "KOF_TAG_NAME(\"a\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\nKOF_TAG_NAME(\"a\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_STEAL);\n", "that name is already used" },
		{ "// only a comment\n\n", "no tag name" },
		{ "", "no tag name" },
	};
	unsigned i;
	const char *why;
	uint32_t ign;
	char *t;

	for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		all();
		why = "";
		/* the first tag of the file is good in most rows: refusal is the whole file, not the bad part */
		CK(kof_tagcat_load_text(&C, bad[i].text, strlen(bad[i].text), &ign, &why) == 0 && !strcmp(why, bad[i].why) && C.n == 0);
		if (strcmp(why, bad[i].why))
			printf("    row %u: '%s'\n", i, why);
	}
	/* all or nothing against tags already in the catalog */
	all();
	CK(kof_tagcat_load_text(&C, one, strlen(one), &ign, &why) == 1 && C.n == 1 && ign == 0);
	CK(kof_tagcat_load_text(&C, one, strlen(one), &ign, &why) == 0 && !strcmp(why, "that name is already used") && C.n == 1);
	/* every spelling that is accepted */
	all();
	{
		static const char good2[] =
			"KOF_TAG_NAME(\"x-1\");\n"
			"KOF_TAG_ACTS(KOF_DISEASE_ACT_C2, KOF_DISEASE_ACT_SCAN, KOF_DISEASE_ACT_SCAN);\n"
			"KOF_TAG_OBJS(KOF_DISEASE_OBJ_KERNEL,KOF_DISEASE_OBJ_FILE);\n"
			"UNKNOWN(1);\n";

		CK(kof_tagcat_load_text(&C, good2, strlen(good2), &ign, &why) == 1 && ign == 1 && C.n == 1);
		CK(C.tag[0].acts == (A(KOF_DISEASE_ACT_C2) | SCAN) && C.tag[0].objs == (A(KOF_DISEASE_OBJ_KERNEL) | FIL));
	}
	/* a file with the OLD id lines: loads, nothing written, the lines are counted as ignored (even a malformed, a reserved and a repeated one),
	 * the ids are the oracle's and not the file's, Save writes the file without them and under the name of its sets; a moved file is read */
	all();
	wipe();
	put("whatever_name.c", "// Generated by Manage > Syndromes; edit by hand with care.\n\n// a note\nKOF_TAG_NAME(\"flood\");\nKOF_TAG_ID(0x7b5c9a6b3eff2038);\n"
	    "KOF_TAG_ID(0x1);\nKOF_TAG_ID(0x2000g);\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\nKOF_TAG_OBJS(KOF_DISEASE_OBJ_NETWORK);\n"
	    "KOF_TAG_ID(0x20000);\nKOF_TAG_NAME(\"c2\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_C2);\n");
	CK(kof_tagcat_load(&C, &ST, dir) == KOF_CATSTORE_IO_OK && ST.n_bad == 0 && C.n == 2);
	CK(ST.n_ignored == 4 && strstr(ST.note, "4 lines ignored"));
	CK(!strcmp(kof_tagcat_comment(&C, 0), "a note"));
	CK(kof_tagcat_id(&C, "flood") == oracle_tag("flood") && kof_tagcat_id(&C, "c2") == oracle_tag("c2") && kof_tagcat_id(&C, "flood") != 0x7b5c9a6b3eff2038ull);
	CK(kof_tagcat_save(&C, &ST, dir) == KOF_CATSTORE_IO_OK);
	CK(!exists("whatever_name.c") && exists("network_scan.c") && exists("none_c2.c") && count_files() == 2);
	t = slurp("network_scan.c");
	CK(t && !strstr(t, "KOF_TAG_ID") && !strstr(t, "0x") && strstr(t, "// a note\nKOF_TAG_NAME(\"flood\");"));
	free(t);
	CK(kof_tagcat_load(&C2, &ST, dir) == KOF_CATSTORE_IO_OK && ST.n_ignored == 0 && kof_tagcat_id(&C2, "flood") == oracle_tag("flood"));
	/* a bad file is named and the others load; unknown lines counted in the note */
	all();
	wipe();
	put("a_scan.c", "KOF_TAG_NAME(\"good\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\nSOMETHING_NEW(1);\n");
	put("b_scan.c", "KOF_TAG_NAME(\"B_AD\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n");
	CK(kof_tagcat_load(&C, &ST, dir) == KOF_CATSTORE_IO_OK && C.n == 1 && ST.n_bad == 1 && ST.n_ignored == 1 &&
	   strstr(ST.note, "not loaded: b_scan.c") && strstr(ST.note, "1 line ignored"));
	/* the caller's table bounds what is read: a file that does not fit is not loaded, whole */
	{
		struct kof_tagcat_tag cell[1];
		struct kof_tagcat tiny;

		kof_tagcat_init(&tiny, cell, 1);
		wipe();
		put("a_scan.c", "KOF_TAG_NAME(\"one\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\nKOF_TAG_NAME(\"two\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n");
		CK(kof_tagcat_load(&tiny, &ST, dir) == KOF_CATSTORE_IO_OK && tiny.n == 0 && ST.n_bad == 1 && strstr(ST.note, "the catalog is full"));
	}
	wipe();
}

/* ---- bytes, the loader a tool calls, the snapshot --------------------------------------------------------------------- */

static void bytes_api(void)
{
	static const char *const fn[] = { "file-network_scan-steal.c", "none_hidden.c", "network_c2.c", "kernel-process_escalation-evasion.c" };
	char *a[4], *b[4];
	char note[320] = "x";
	unsigned i;

	all();
	wipe();
	CK(kof_tagcat_add(&C, "flood", SCAN | STEAL, NET | FIL, NULL) == KOF_TAGCAT_OK);
	CK(kof_tagcat_add(&C, "beacon", A(KOF_DISEASE_ACT_C2), NET, NULL) == KOF_TAGCAT_OK);
	CK(kof_tagcat_add(&C, "hide-me", A(KOF_DISEASE_ACT_HIDDEN), 0, NULL) == KOF_TAGCAT_OK);
	CK(kof_tagcat_add(&C, "rk", A(KOF_DISEASE_ACT_ESCALATION) | A(KOF_DISEASE_ACT_EVASION), A(KOF_DISEASE_OBJ_KERNEL) | A(KOF_DISEASE_OBJ_PROCESS), NULL) == KOF_TAGCAT_OK);
	CK(kof_tagcat_add(&C, "syn-flood", SCAN | STEAL, NET | FIL, NULL) == KOF_TAGCAT_OK);
	CK(kof_tagcat_save(&C, &ST, dir) == KOF_CATSTORE_IO_OK && count_files() == 4);
	for (i = 0; i < 4; i++)
		a[i] = slurp(fn[i]);
	CK(a[0] && a[1] && a[2] && a[3]);
	/* save, load, save: every file the same bytes (the catalog's order across files changes, the files do not) */
	CK(kof_tagcat_load(&C2, &ST, dir) == KOF_CATSTORE_IO_OK && ST.n_bad == 0 && ST.n_ignored == 0 && C2.n == 5);
	CK(kof_tagcat_save(&C2, &ST, dir) == KOF_CATSTORE_IO_OK && count_files() == 4);
	for (i = 0; i < 4; i++) {
		b[i] = slurp(fn[i]);
		CK(b[i] && a[i] && !strcmp(a[i], b[i]));
		free(a[i]);
		free(b[i]);
	}
	/* the loader a build tool calls, and the lookups on what it read */
	all();
	CK(kof_tagcat_load_dir(&C, dir, note, sizeof note) == KOF_CATSTORE_IO_OK && note[0] == 0 && C.n == 5);
	CK(kof_tagcat_id(&C, "syn-flood") == oracle_tag("syn-flood") && kof_tagcat_id(&C, "rk") == oracle_tag("RK"));
	CK(kof_tagcat_load_dir(&C, "", note, sizeof note) == KOF_CATSTORE_IO_NO_DIR && strstr(note, "no syndromes directory") && C.n == 0);
	CK(kof_tagcat_load_dir(&C, NULL, NULL, 0) == KOF_CATSTORE_IO_NO_DIR);
	{
		char missing[200];

		snprintf(missing, sizeof missing, "%s/nowhere", dir);
		CK(kof_tagcat_load_dir(&C, missing, note, sizeof note) == KOF_CATSTORE_IO_OK && C.n == 0);
	}
	/* the snapshot: each field a change can touch makes it dirty, restore undoes it */
	all();
	CK(kof_tagcat_add(&C, "a", SCAN, 0, NULL) == KOF_TAGCAT_OK && kof_tagcat_add(&C, "b", STEAL, NET, NULL) == KOF_TAGCAT_OK);
	CK(kof_tagcat_dirty(&C, &S) == 1);
	CK(kof_tagcat_snapshot(&C, &S) == KOF_TAGCAT_OK && !kof_tagcat_dirty(&C, &S));
	CK(kof_tagcat_rename(&C, 0, "a2") == KOF_TAGCAT_OK && kof_tagcat_dirty(&C, &S));
	CK(kof_tagcat_restore(&C, &S) == KOF_TAGCAT_OK && !kof_tagcat_dirty(&C, &S) && !strcmp(C.tag[0].name, "a"));
	CK(kof_tagcat_set_acts(&C, 1, STEAL | SCAN) == KOF_TAGCAT_OK && kof_tagcat_dirty(&C, &S));
	CK(kof_tagcat_restore(&C, &S) == KOF_TAGCAT_OK && !kof_tagcat_dirty(&C, &S));
	CK(kof_tagcat_set_objs(&C, 1, FIL) == KOF_TAGCAT_OK && kof_tagcat_dirty(&C, &S));
	CK(kof_tagcat_restore(&C, &S) == KOF_TAGCAT_OK && !kof_tagcat_dirty(&C, &S));
	CK(kof_tagcat_delete(&C, 0) == KOF_TAGCAT_OK && kof_tagcat_dirty(&C, &S));
	CK(kof_tagcat_restore(&C, &S) == KOF_TAGCAT_OK && C.n == 2 && !kof_tagcat_dirty(&C, &S));
	/* the bytes after a name's terminator are not the catalog: a rename and a rename back is clean */
	CK(kof_tagcat_rename(&C, 0, "abc") == KOF_TAGCAT_OK && kof_tagcat_rename(&C, 0, "a") == KOF_TAGCAT_OK && !kof_tagcat_dirty(&C, &S));
	/* too small a snapshot */
	{
		static struct kof_tagcat_tag one[1];
		struct kof_tagcat tiny;

		kof_tagcat_init(&tiny, one, 1);
		all();
		CK(kof_tagcat_add(&C, "a", SCAN, 0, NULL) == KOF_TAGCAT_OK && kof_tagcat_add(&C, "b", SCAN, 0, NULL) == KOF_TAGCAT_OK);
		CK(kof_tagcat_snapshot(&C, &tiny) == KOF_TAGCAT_FULL && tiny.n == 0 && kof_tagcat_restore(&tiny, &C) == KOF_TAGCAT_FULL);
	}
	wipe();
}

/* The comment above a tag and the capitals in a name: the exact text, the round trip, the lines that must not become a comment. */
static void comments(void)
{
	static const char want[] =
		"// Generated by Manage > Syndromes; edit by hand with care.\n"
		"\n"
		"// Scans hosts before an attack\n"
		"KOF_TAG_NAME(\"Recon-A\");\n"
		"KOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n"
		"KOF_TAG_OBJS();\n"
		"\n"
		"KOF_TAG_NAME(\"plain\");\n"
		"KOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n"
		"KOF_TAG_OBJS();\n";
	static char buf[8192], buf2[8192];
	struct kof_tagcat_fields f = { "Recon-A", "Scans hosts before an attack", SCAN, 0 };
	const char *why = "";
	uint32_t ign = 9, i, len;
	char text[1024];
	int ch;

	all();
	CK(kof_tagcat_add_fields(&C, &f, NULL) == KOF_TAGCAT_OK && kof_tagcat_add(&C, "plain", SCAN, 0, NULL) == KOF_TAGCAT_OK);
	CK(kof_tagcat_file_count(&C) == 1u);
	len = (uint32_t)kof_tagcat_file_text(&C, 0, buf, sizeof buf);
	CK(len == strlen(want) && !strcmp(buf, want));
	/* the file name is lower case whatever the names hold */
	kof_tagcat_file_of(&C, 0, text, sizeof text);
	CK(!strcmp(text, "none_scan.c"));
	/* load, write: the same bytes; the comment and the capitals came back */
	all();
	CK(kof_tagcat_load_text(&C, buf, len, &ign, &why) == 1 && ign == 0u && C.n == 2u);
	CK(!strcmp(C.tag[0].name, "Recon-A") && !strcmp(kof_tagcat_comment(&C, 0), "Scans hosts before an attack") && !kof_tagcat_comment(&C, 1)[0]);
	CK(kof_tagcat_file_text(&C, 0, buf2, sizeof buf2) == len && !strcmp(buf, buf2));
	/* what is not a comment of a tag: a blank line, the header, a line not understood, text after the tag's own lines */
	all();
	snprintf(text, sizeof text, "// Generated by Manage > Syndromes; edit by hand with care.\nKOF_TAG_NAME(\"a\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n"
		 "// after\n\nKOF_TAG_NAME(\"b\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n// one\n//\n//   two\nKOF_TAG_NAME(\"c\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n"
		 "// x\nUNKNOWN(1);\nKOF_TAG_NAME(\"d\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n");
	CK(kof_tagcat_load_text(&C, text, strlen(text), &ign, &why) == 1 && ign == 1u && C.n == 4u);
	CK(!kof_tagcat_comment(&C, 0)[0] && !kof_tagcat_comment(&C, 1)[0] && !strcmp(kof_tagcat_comment(&C, 2), "one   two") && !kof_tagcat_comment(&C, 3)[0]);
	/* a file with no comment at all (every file saved before this) loads clean */
	all();
	snprintf(text, sizeof text, "KOF_TAG_NAME(\"flood\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n");
	CK(kof_tagcat_load_text(&C, text, strlen(text), &ign, &why) == 1 && ign == 0u && !kof_tagcat_comment(&C, 0)[0]);
	/* too long and a refused character in a file: the file is refused, named by the one comment text */
	all();
	memset(text, 'x', 130);
	memcpy(text, "// ", 3);
	snprintf(text + 130, sizeof text - 130, "\nKOF_TAG_NAME(\"a\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n");
	CK(kof_tagcat_load_text(&C, text, strlen(text), &ign, &why) == 0 && !strcmp(why, "comment is over 120 characters") && C.n == 0u);
	snprintf(text, sizeof text, "// a*b\nKOF_TAG_NAME(\"a\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n");
	CK(kof_tagcat_load_text(&C, text, strlen(text), &ign, &why) == 0 && !strcmp(why, "comment: no * or / and printable only") && C.n == 0u);
	/* every printable byte as a comment, inside <> so the line's trim keeps it: save-load-save is byte-identical */
	for (ch = 0x20; ch < 0x7f; ch++) {
		char c[8] = { '<', (char)ch, '>', 0 };

		all();
		f.name = "t";
		f.comment = c;
		if (kof_tagcat_add_fields(&C, &f, NULL) != KOF_TAGCAT_OK) {
			CK(ch == '*' || ch == '/');
			continue;
		}
		len = (uint32_t)kof_tagcat_file_text(&C, 0, buf, sizeof buf);
		all();
		CK(kof_tagcat_load_text(&C, buf, len, &ign, &why) == 1 && !strcmp(kof_tagcat_comment(&C, 0), c));
		CK(kof_tagcat_file_text(&C, 0, buf2, sizeof buf2) == len && !strcmp(buf, buf2));
	}
	/* the longest comment, and every name of a small alphabet with capitals (the duplicates by letter case are refused, the rest come back) */
	{
		static const char alpha[] = "aA0-";
		char nm[4], big[KOF_TAGCAT_COMMENT_MAX + 1];
		uint32_t a, b, c3, added = 0u;

		memset(big, 'y', KOF_TAGCAT_COMMENT_MAX);
		big[KOF_TAGCAT_COMMENT_MAX] = 0;
		all();
		for (a = 0; a < 4; a++)
			for (b = 0; b < 5; b++)
				for (c3 = 0; c3 < 5; c3++) {
					nm[0] = alpha[a];
					nm[1] = b ? alpha[b - 1u] : 0;
					nm[2] = b && c3 ? alpha[c3 - 1u] : 0;
					nm[3] = 0;
					if (!b && c3)
						continue;
					f.name = nm;
					f.comment = (a + b + c3) & 1u ? big : "";
					added += kof_tagcat_add_fields(&C, &f, NULL) == KOF_TAGCAT_OK;
				}
		CK(added > 20u && added == C.n);
		for (i = 0; i < C.n; i++)       /* no two of them differ only in case */
			for (a = i + 1u; a < C.n; a++)
				CK(strcasecmp(C.tag[i].name, C.tag[a].name) != 0);
		for (i = 0; i < kof_tagcat_file_count(&C); i++) {
			static char t1[262144], t2[262144];
			size_t n1;

			n1 = kof_tagcat_file_text(&C, i, t1, sizeof t1);
			CK(n1 < sizeof t1);
			fresh(&C2, T2);
			CK(kof_tagcat_load_text(&C2, t1, n1, &ign, &why) == 1 && ign == 0u);
			CK(kof_tagcat_file_text(&C2, 0, t2, sizeof t2) == n1 && !strcmp(t1, t2));
		}
	}
}

int main(void)
{
	char tmpl[] = "build/kof_tagcat_store_XXXXXX";

	if (!mkdtemp(tmpl)) {
		printf("tagcat_store: cannot make a scratch directory\n");
		return 1;
	}
	snprintf(dir, sizeof dir, "%s", tmpl);
	names();
	files();
	ids();
	loading();
	bytes_api();
	comments();
	wipe();
	rmdir(dir);
	printf("tagcat_store: %d failure(s)\n", fails);
	return fails != 0;
}
