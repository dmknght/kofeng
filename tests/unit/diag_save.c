#define _GNU_SOURCE
/*
 * diag_save - what the diagnose draft's Save does about what was ADDED and what was REMOVED.
 *
 * PINNED: ADD and REMOVE are one mechanism, the LINK between a unit and the diagnose it was loaded from (struct group.link, struct
 * cond.link; the loaded list kof_draft.loaded). A unit with no link is new (a new file, the first free number); a loaded link that no unit
 * carries any more is removed (its file is deleted); a linked unit that still equals its file is untouched; a linked unit that no longer
 * equals its file is MODIFIED: reported ("N modified diagnose(s) not saved: editing is not done"), neither written nor the cause of a
 * deletion. Safety: a unit is linked only when the draft regenerates the file exactly (a file the panel cannot represent is never touched);
 * only a LOADED link can delete, the list is reset on arrival and on discard; one block of two unticked is a modification, not a removal;
 * the plan is made before the disk is touched and a failure part way puts the tree back; only the exact file `dir`/`name`.c, a regular
 * file, is unlinked; the link follows its unit through every move; a number freed by this Save is not reused by it.
 * The round trips run on the REAL files of bases/diagnoses copied into a scratch directory.
 *
 * Why the old tests missed it: (a) nothing deleted a file and nothing loaded a diagnose into a draft - draft_generate only ever created,
 * so no line of the removal and no link existed to execute; (b) the "present" rows ran the same draft twice and never a draft that LOST
 * a unit it had been loaded with, nor a file changed, linked twice or swapped for a symlink since the load; (c) the Generate rows checked
 * the count of files written, not that every other file in the directory was byte for byte as before.
 */

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include "../../kofexamine/kofeditor.h"
#include "../../libkofeng/databases/diagsrc.h"
#include "../../libkofeng/kofcore/kofplatform.h"
#include <celllysis/mutation.h>
#include <kofmod/elf.h>

static int fails;

static struct kof_editor E;
static char dir[256];
static char msg[800];

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

#define CKM(cond, what) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s [%s] msg=%s\n", __FILE__, __LINE__, #cond, what, msg); \
		fails++; \
	} \
} while (0)

static const char *const FLOOD[] = {
	"botnet_mirai_mirai-flood_01", "botnet_mirai_mirai-flood_02", "botnet_mirai_mirai-flood_03",
	"botnet_mirai_mirai-flood_04", "botnet_mirai_mirai-flood_05", "botnet_mirai_mirai-flood_06",
};
#define ALL8_FILE(i) (file_of(ALL8[i]))
static const char *file_of(const char *stem);
static const char *const ALL8[] = {
	"botnet_mirai_mirai-flood_01", "botnet_mirai_mirai-flood_02", "botnet_mirai_mirai-flood_03",
	"botnet_mirai_mirai-flood_04", "botnet_mirai_mirai-flood_05", "botnet_mirai_mirai-flood_06",
	"botnet_mirai_mirai-wordlist_01", "botnet_mirai_mirai-ops-str_01",
};

static int fake_ids;       /* ids that are NOT a function of the name, in an order that is neither the file order nor the draft order */

/* The db id of a diagnose by name. With fake_ids the id is an arbitrary value (a permutation of the files), so a test that passes proves the
 * model never derives an identity from the name or from where anything sits. */
static uint32_t idof(const char *name)
{
	unsigned i;

	if (!name)
		return 1u;
	if (fake_ids)
		for (i = 0; i < 8u; i++)
			if (!strcmp(name, ALL8[i]))
				return 0x5100u + (i * 5u + 3u) % 8u * 0x111u;
	return kof_diag_id32_(name);
}

static const char *file_of(const char *stem)
{
	static char b[8][100];
	static unsigned n;
	char *r = b[n++ % 8u];

	snprintf(r, 100, "%s.c", stem);
	return r;
}

/* ---- files -------------------------------------------------------------------------------------------------------- */

static char *slurp_path(const char *path, size_t *n)
{
	FILE *f = fopen(path, "rb");
	char *b;
	long L;

	if (!f)
		return NULL;
	fseek(f, 0, SEEK_END);
	L = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (L < 0 || L > (1L << 30)) {  /* not a regular file (a FIFO, a device; a directory answers LONG_MAX): no size worth reading - malloc(LONG_MAX + 1) asks for 8 EiB */
		fclose(f);
		return NULL;
	}
	b = malloc((size_t)L + 1u);
	if (b && fread(b, 1, (size_t)L, f) != (size_t)L) {
		free(b);
		b = NULL;
	}
	fclose(f);
	if (b) {
		b[L] = 0;
		if (n)
			*n = (size_t)L;
	}
	return b;
}

static char *slurp(const char *leaf, size_t *n)
{
	char path[600];

	snprintf(path, sizeof path, "%s/%s", dir, leaf);
	return slurp_path(path, n);
}

static void put_file(const char *leaf, const char *text)
{
	char path[800];
	FILE *f;

	snprintf(path, sizeof path, "%s/%s", dir, leaf);
	f = fopen(path, "wb");
	if (f) {
		fputs(text, f);
		fclose(f);
	}
}

static int exists(const char *stem)
{
	char path[400];

	snprintf(path, sizeof path, "%s/%s.c", dir, stem);
	return access(path, F_OK) == 0;
}

static int cmpstr(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

/* The directory as it is: every name with the length and a hash of its bytes, sorted. Two snapshots equal = the tree is as before. */
static char *snap(void)
{
	DIR *d = opendir(dir);
	struct dirent *de;
	char *names[256];
	unsigned n = 0, i;
	char *out = calloc(1, 65536);
	size_t at = 0;

	while (d && (de = readdir(d)) != NULL && n < 256u)
		if (de->d_name[0] != '.')
			names[n++] = strdup(de->d_name);
	if (d)
		closedir(d);
	qsort(names, n, sizeof names[0], cmpstr);
	for (i = 0; i < n; i++) {
		size_t len = 0, k;
		uint32_t h = 2166136261u;
		char *b = slurp(names[i], &len);
		char path[400];
		struct stat st;

		for (k = 0; b && k < len; k++)
			h = (h ^ (uint8_t)b[k]) * 16777619u;
		snprintf(path, sizeof path, "%s/%s", dir, names[i]);
		(void)lstat(path, &st);
		at += (size_t)snprintf(out + at, 65536u - at, "%s:%zu:%08x:%o\n", names[i], len, h, (unsigned)(st.st_mode & 07777u));
		free(b);
		free(names[i]);
	}
	return out;
}

static unsigned count_files(void)
{
	DIR *d = opendir(dir);
	struct dirent *de;
	unsigned n = 0;

	while (d && (de = readdir(d)) != NULL)
		n += de->d_name[0] != '.';
	if (d)
		closedir(d);
	return n;
}

static void clean(void)
{
	char cmd[700];

	chmod(dir, 0700);
	snprintf(cmd, sizeof cmd, "rm -rf '%s'/* '%s'/.[a-z]*", dir, dir);
	(void)system(cmd);
}

static void copy_real(const char *stem)
{
	char from[400], to[400];
	size_t n = 0;
	char *b;
	FILE *f;

	/* THE REAL FILES THE ROWS NAME ARE THE OWNER'S, AND THE OWNER RENAMED AND REMADE THEM: the six `mirai-flood_01..06`, `mirai-wordlist_01` and `mirai-ops-str_01` the rows were written for are now
	 * five `flood_01..05` and the data diagnoses `mirai-strings_01`, `_02`. The rows keep their names and take the bytes of what stands in their place (the model is the editor's: which
	 * bytes a block holds is not what the rows ask): flood_0N for N <= 5; the sixth is the fifth again; the two data ones are the two data diagnoses. The name inside is the name of the row. */
	static const struct { const char *row, *real, *real_tag, *row_tag; int tweak; } src[] = {
		/* flood_01 and flood_02 of the real set hold the SAME block: the rows need six different ones, so the second takes flood_03 and so on, and the last two are flood_05 and flood_01 with the last key of
		 * the block moved by one (`tweak`: another block, which no row compares by content) */
		{ "botnet_mirai_mirai-flood_01", "botnet_mirai_flood_01", "Flood", "Mirai-flood", 0 }, { "botnet_mirai_mirai-flood_02", "botnet_mirai_flood_03", "Flood", "Mirai-flood", 0 },
		{ "botnet_mirai_mirai-flood_03", "botnet_mirai_flood_04", "Flood", "Mirai-flood", 0 }, { "botnet_mirai_mirai-flood_04", "botnet_mirai_flood_05", "Flood", "Mirai-flood", 0 },
		{ "botnet_mirai_mirai-flood_05", "botnet_mirai_flood_05", "Flood", "Mirai-flood", 1 }, { "botnet_mirai_mirai-flood_06", "botnet_mirai_flood_01", "Flood", "Mirai-flood", 1 },
		{ "botnet_mirai_mirai-wordlist_01", "botnet_mirai_mirai-strings_01", "Mirai-Strings", "Mirai-wordlist", 0 },
		{ "botnet_mirai_mirai-ops-str_01", "botnet_mirai_mirai-strings_02", "Mirai-Strings", "Mirai-Ops-Str", 0 },
	};
	unsigned si;

	for (si = 0; si < sizeof src / sizeof src[0]; si++)
		if (!strcmp(stem, src[si].row)) {
			char *t;

			snprintf(from, sizeof from, "bases/diagnoses/%s.c", src[si].real);
			t = slurp_path(from, &n);
			CK(t != NULL);
			if (t) {
				char *q = strstr(t, src[si].real), *w;
				const size_t rl = strlen(src[si].real), sl = strlen(stem);
				char *o = malloc(n + sl + 1u);

				if (q && o) {
					size_t pre = (size_t)(q - t), len = n - rl + sl;
					char needle[96], *tg;

					memcpy(o, t, pre);
					memcpy(o + pre, stem, sl);
					memcpy(o + pre + sl, q + rl, n - pre - rl);
					o[len] = 0;
					if (src[si].tweak) {
						char *e = strstr(o, "u);\nKOF_DIAG_SIMILAR");

						if (e)
							e[-1] = e[-1] == 'f' ? 'e' : (char)(e[-1] + 1);
					}
					snprintf(needle, sizeof needle, "KOF_DIAG_TAG(\"%s\");", src[si].real_tag);
					tg = strstr(o, needle);
					w = NULL;
					snprintf(to, sizeof to, "%s/%s.c", dir, stem);
					f = fopen(to, "wb");
					if (f && tg) {
						const size_t head = (size_t)(tg - o), nl = strlen(needle);
						char tagline[96];

						snprintf(tagline, sizeof tagline, "KOF_DIAG_TAG(\"%s\");", src[si].row_tag);
						fwrite(o, 1, head, f);
						fwrite(tagline, 1, strlen(tagline), f);
						fwrite(o + head + nl, 1, len - head - nl, f);
					} else if (f) {
						CK(0);
					}
					if (f)
						fclose(f);
				} else {
					CK(0);
				}
				free(o);
				free(t);
			}
			return;
		}
	snprintf(from, sizeof from, "bases/diagnoses/%s.c", stem);
	snprintf(to, sizeof to, "%s/%s.c", dir, stem);
	b = slurp_path(from, &n);
	if (!b) {
		/* The diagnoses whose blocks are CODE are moved to docs/disabled/diagnoses while function-content signatures are off
		 * (prototype 2026-10-30): the same real files, read from where they are kept. */
		snprintf(from, sizeof from, "docs/disabled/diagnoses/%s.c", stem);
		b = slurp_path(from, &n);
	}
	CK(b != NULL);
	f = b ? fopen(to, "wb") : NULL;
	if (f) {
		fwrite(b, 1, n, f);
		fclose(f);
	}
	free(b);
}

static void copy_real_all(void)
{
	unsigned i;

	for (i = 0; i < 8u; i++)
		copy_real(ALL8[i]);
}

/* ---- the draft: the way the viewer builds it on arrival -------------------------------------------------------------- */

static struct kof_dsrc *DS;

static void new_draft(void)
{
	uint32_t i;

	for (i = 0; i < E.dr.n_decl; i++)
		free(E.dr.decl[i].bytes);
	free(E.dr.decl);
	free(E.dr.blk);
	memset(&E.dr, 0, sizeof E.dr);
	E.dr.blk = calloc(64, sizeof *E.dr.blk);
	E.dr.fmt_mask = 1u << KOF_FMT_ELF;
	snprintf(E.dr.family, sizeof E.dr.family, "Mirai");
	snprintf(E.dr.variant, sizeof E.dr.variant, "Mirai_A");
}

/* One block of a real file into the block table, as the engine's carve offers it. */
static uint32_t block_of_file(const struct kof_dsrc_item *it)
{
	struct mtn_block *k = &E.dr.blk[E.dr.n_blk];
	const char *words = it->t1;

	memset(k, 0, sizeof *k);
	k->n_hash = it->n2 / (uint32_t)sizeof k->hash[0];
	memcpy(k->hash, it->t2, it->n2);
	k->side = it->b ? (uint8_t)KGENOME_MUTATION_SIDE_LIB : 0;
	snprintf(k->rgn_enum, sizeof k->rgn_enum, "%s", words);
	k->id = 0x1000u + E.dr.n_blk;
	return E.dr.n_blk++;
}

/*
 * LOAD BY TICKING, the arrival path of mtn_from_match: the block is in the table, the tick makes the matcher (blk_set_picked), the matcher
 * takes the diagnose's tag, type and threshold, the header takes its family and variant, and the link is asked for last. Returns the
 * matcher's index; *linked says whether the link was made.
 */
static uint32_t load_file(const char *stem, int *linked)
{
	struct kof_dsrc_view v;
	struct kof_dsrc_report none = { NULL, NULL, NULL };
	char *text;
	size_t n = 0, i;
	uint32_t blk = 0, g;
	unsigned pct = 0;

	text = slurp(stem, &n);
	if (!text) {
		char leaf[200];

		snprintf(leaf, sizeof leaf, "%s.c", stem);
		text = slurp(leaf, &n);
	}
	CK(text != NULL);
	memset(DS, 0, sizeof *DS);
	memset(&v, 0, sizeof v);
	CK(kof_dsrc_parse(text, n, DS, &none) == 0);
	CK(kof_dsrc_resolve(DS, &v, &none) == 0);
	for (i = 0; i < DS->n; i++) {
		if (DS->item[i].kind == KDS_BLOCK)
			blk = block_of_file(&DS->item[i]);
		if (DS->item[i].kind == KDS_SIMILAR)
			pct = DS->item[i].a;
	}
	snprintf(E.dr.family, sizeof E.dr.family, "%.40s", v.family);
	snprintf(E.dr.variant, sizeof E.dr.variant, "%.40s_%.20s", v.family, v.variant);
	blk_set_picked(&E, blk, 1);
	g = grp_of_block(&E, blk);
	snprintf(E.dr.grp[g].tag, sizeof E.dr.grp[g].tag, "%s", v.tag);
	E.dr.grp[g].utype = (uint8_t)(v.type + 1u);
	E.dr.grp[g].pct = (uint8_t)pct;
	*linked = draft_link_unit(&E, 1, g, dir, idof(stem), stem);
	kof_dsrc_view_free(&v);
	free(text);
	return g;
}

static void load_n(unsigned n)
{
	unsigned i;
	int ok;

	new_draft();
	for (i = 0; i < n; i++) {
		(void)load_file(ALL8[i], &ok);
		CKM(ok, ALL8[i]);
	}
}

static void load_all8(void)
{
	load_n(8u);
}

/* A block of its own (bytes nothing in the tree has), ticked into a new matcher of the Mirai-flood tag: a NEW unit. */
static uint32_t add_new_unit(uint32_t seed, const char *tag)
{
	struct mtn_block *k = &E.dr.blk[E.dr.n_blk];
	uint32_t i, blk = E.dr.n_blk++, g;

	memset(k, 0, sizeof *k);
	k->n_hash = 40;
	for (i = 0; i < k->n_hash; i++)
		k->hash[i] = seed * 2654435761u + i * 40503u;
	snprintf(k->rgn_enum, sizeof k->rgn_enum, "KOF_SCAN_ELF_CODE");
	k->id = 0x9000u + blk;
	blk_set_picked(&E, blk, 1);
	g = grp_of_block(&E, blk);
	snprintf(E.dr.grp[g].tag, sizeof E.dr.grp[g].tag, "%s", tag);
	E.dr.grp[g].utype = (uint8_t)(KOF_MALTYPE_BOTNET + 1u);
	E.dr.grp[g].pct = 70;
	return g;
}

static int untick(const char *stem)
{
	uint32_t g;

	for (g = 0; g < E.dr.n_grp; g++)
		if (E.dr.grp[g].link == idof(stem)) {
			uint32_t k;

			for (k = 0; k < E.dr.grp[g].n_sim; k++)
				if (E.dr.grp[g].sim[k].what == SIM_IT_BLOCK) {
					blk_set_picked(&E, E.dr.grp[g].sim[k].blk, 0);
					return 1;
				}
		}
	return 0;
}

static int save(void)
{
	return draft_generate(&E, dir, msg, sizeof msg);
}

static int same_text(const char *a, const char *b)
{
	return a && b && !strcmp(a, b);
}

/* ---- the cases ------------------------------------------------------------------------------------------------------ */

/* Rule 1 and the round trip: every real file is linked by ticking, and Save with nothing changed writes and deletes nothing. */
static void round_trip(void)
{
	char *before, *after;
	unsigned i;

	clean();
	copy_real_all();
	load_all8();
	CK(draft_links_loaded(&E) == 8u);
	for (i = 0; i < E.dr.n_grp; i++)
		CK(draft_unit_link(&E, 1, i) == idof(ALL8[i]));
	CK(draft_links_removed(&E) == 0u);
	before = snap();
	CK(save() == 0);
	CKM(strstr(msg, "Nothing new to write") != NULL, "unchanged");
	after = snap();
	CK(same_text(before, after));
	CK(count_files() == 8u);
	free(before);
	free(after);
}

/* Untick one block: exactly that file goes. Then all six flood files, then all eight. */
static void removal(void)
{
	char *before, *after;
	unsigned i;

	clean();
	copy_real_all();
	load_all8();
	before = snap();
	CK(untick("botnet_mirai_mirai-flood_03"));
	CK(draft_links_removed(&E) == 1u);
	CK(save() == 0);
	CKM(strstr(msg, "Deleted 1 file") != NULL && strstr(msg, "botnet_mirai_mirai-flood_03") != NULL, "deleted by name");
	CKM(strstr(msg, "Wrote") == NULL, "nothing written");
	CK(!exists("botnet_mirai_mirai-flood_03"));
	for (i = 0; i < 8u; i++)
		CK(i == 2u || exists(ALL8[i]));
	CK(count_files() == 7u);
	CK(draft_links_loaded(&E) == 7u);
	after = snap();
	CK(!same_text(before, after));
	/* a second Save finds nothing more to do */
	CK(save() == 0 && strstr(msg, "Nothing new to write") != NULL);
	CK(count_files() == 7u);
	free(before);
	free(after);

	/* the six flood diagnoses, not the other two */
	clean();
	copy_real_all();
	load_all8();
	for (i = 0; i < 6u; i++)
		CK(untick(FLOOD[i]));
	CK(save() == 0);
	CKM(strstr(msg, "Deleted 6 files") != NULL, "six");
	for (i = 0; i < 6u; i++) {
		CK(!exists(FLOOD[i]));
		CK(strstr(msg, FLOOD[i]) != NULL);
	}
	CK(exists("botnet_mirai_mirai-wordlist_01") && exists("botnet_mirai_mirai-ops-str_01") && count_files() == 2u);

	/* all eight: the draft holds no unit at all and Save still deletes */
	clean();
	copy_real_all();
	load_all8();
	for (i = 0; i < 8u; i++)
		CK(untick(ALL8[i]));
	CK(draft_unit_count(&E) == 0u && draft_links_removed(&E) == 8u);
	CK(save() == 0 && strstr(msg, "Deleted 8 files") != NULL);
	CK(count_files() == 0u);
	CK(draft_links_loaded(&E) == 0u);
	/* and with nothing loaded and nothing in the draft, the old answer */
	CK(save() < 0 && strstr(msg, "Nothing to write") != NULL);
}

/* ADD: one new unit = one new file, the others untouched; remove + add in one Save; rule 7. */
static void addition(void)
{
	char *before, *after;
	int rc;

	clean();
	copy_real_all();
	load_n(6u);
	before = snap();
	(void)add_new_unit(1, "Mirai-flood");
	rc = save();
	CKM(rc == 1, "one new file");
	CKM(strstr(msg, "Wrote 1 file") != NULL && strstr(msg, "botnet_mirai_mirai-flood_07") != NULL, "named");
	CK(exists("botnet_mirai_mirai-flood_07") && count_files() == 9u);   /* 8 files and the new one */
	after = snap();
	CK(strstr(after, "botnet_mirai_mirai-flood_01.c") && strstr(before, "botnet_mirai_mirai-flood_01.c"));
	free(before);
	free(after);

	/* remove 02 and add one in the same Save: the new file does NOT take 02 (rule 7: the number of a file deleted by this Save is taken
	 * for this Save), it takes 07; a later Save, with the file really gone, may reuse the number. */
	clean();
	copy_real_all();
	load_n(6u);
	CK(untick("botnet_mirai_mirai-flood_02"));
	(void)add_new_unit(2, "Mirai-flood");
	rc = save();
	CKM(rc == 1 && strstr(msg, "Wrote 1 file") != NULL && strstr(msg, "Deleted 1 file") != NULL, "remove and add");
	CK(!exists("botnet_mirai_mirai-flood_02") && exists("botnet_mirai_mirai-flood_07"));
	CK(count_files() == 8u);
	(void)add_new_unit(3, "Mirai-flood");
	rc = save();
	CKM(rc == 1 && exists("botnet_mirai_mirai-flood_02"), "a later Save takes the free number");
	/* the new files were written as new units: they are not linked, so a Save does not touch them again */
	CK(save() == 0 && count_files() == 9u);
}

/* Rule 3 and the modified unit. */
static void modified(void)
{
	char *before, *after;
	uint32_t g, k;
	int ok;

	clean();
	copy_real_all();
	load_all8();
	/* a threshold changed: a different algorithm, reported, never written, never deleted, never duplicated */
	for (g = 0; g < E.dr.n_grp; g++)
		if (E.dr.grp[g].link == idof("botnet_mirai_mirai-flood_01"))
			E.dr.grp[g].pct = 90;
	before = snap();
	CK(save() == 0);
	CKM(strstr(msg, "1 modified diagnose not saved: editing is not done") != NULL, "reported");
	CKM(strstr(msg, "Wrote") == NULL && strstr(msg, "Deleted") == NULL, "only reported");
	after = snap();
	CK(same_text(before, after));
	free(after);
	CK(save() == 0 && strstr(msg, "1 modified diagnose not saved") != NULL);   /* and again, the same */
	/* modified and removed in one Save: only the removed file goes */
	CK(untick("botnet_mirai_mirai-flood_02"));
	CK(save() == 0);
	CKM(strstr(msg, "Deleted 1 file") != NULL && strstr(msg, "1 modified diagnose not saved: editing is not done") != NULL, "both said");
	CK(!exists("botnet_mirai_mirai-flood_02") && exists("botnet_mirai_mirai-flood_01") && count_files() == 7u);
	free(before);

	/* a linked matcher that is no unit any more (turned into a string matcher): it carries its link, so it is a modification and its file stays */
	clean();
	copy_real_all();
	load_all8();
	E.dr.grp[2].kind = (uint8_t)GRP_KIND_STR;
	before = snap();
	CK(save() == 0);
	CKM(strstr(msg, "1 modified diagnose not saved") != NULL && strstr(msg, "Deleted") == NULL, "a linked matcher that is no unit");
	after = snap();
	CK(same_text(before, after));
	free(before);
	free(after);

	/* the tag changed on a linked unit: modified as well */
	clean();
	copy_real_all();
	load_all8();
	snprintf(E.dr.grp[3].tag, sizeof E.dr.grp[3].tag, "other");
	before = snap();
	CK(save() == 0 && strstr(msg, "1 modified diagnose") != NULL);
	after = snap();
	CK(same_text(before, after));
	free(before);
	free(after);

	/* RULE 3, one block unticked of a matcher that holds two: a modification, not a removal. Take 01, add a second block to its matcher. */
	clean();
	copy_real_all();
	new_draft();
	g = load_file("botnet_mirai_mirai-flood_01", &ok);
	CK(ok);
	k = add_new_unit(7, "Mirai-flood");              /* a block of its own in a matcher of its own ... */
	{
		uint32_t blk = E.dr.grp[k].sim[0].blk;

		blk_set_picked(&E, blk, 0);                  /* ... which goes again ... */
		CK(E.dr.n_grp == 1u);
		E.dr.blk[blk].picked = 1;
		CK(grp_sim_add(&E, g, SIM_IT_BLOCK, blk) != 0);   /* ... and joins the matcher that was loaded */
		CK(E.dr.grp[g].n_sim == 2u);
		before = snap();
		CK(save() == 0);
		CKM(strstr(msg, "1 modified diagnose not saved") != NULL && strstr(msg, "Deleted") == NULL, "two blocks: modified");
		after = snap();
		CK(same_text(before, after));
		free(before);
		free(after);
		/* take the second block out again: the matcher is whole again and nothing is removed */
		blk_set_picked(&E, blk, 0);
		CK(E.dr.n_grp == 1u && E.dr.grp[g].n_sim == 1u && E.dr.grp[g].link == idof("botnet_mirai_mirai-flood_01"));
		CK(save() == 0 && strstr(msg, "Nothing new to write") != NULL);
		/* and the last block out removes the matcher, which IS a removal */
		CK(untick("botnet_mirai_mirai-flood_01"));
		CK(E.dr.n_grp == 0u);
		CK(save() == 0 && strstr(msg, "Deleted 1 file") != NULL && !exists("botnet_mirai_mirai-flood_01"));
	}
}

/* Rule 1: what the panel cannot represent whole is never linked, so never modified or deleted. */
static void not_linked(void)
{
	char *before, *after;
	int ok;
	uint32_t g;

	clean();
	copy_real_all();
	/* a hand-written file: two matchers and an expression over them, which the panel cannot represent */
	put_file("botnet_mirai_mirai-flood_01.c", "KOF_DIAG_NAME(botnet_mirai_mirai-flood_01);\nKOF_TARGET_FORMAT(KOF_FMT_ELF);\nKOF_DIAG_FAMILY(\"Mirai\");\n"
		 "KOF_DIAG_VARIANT(\"A\");\nKOF_DIAG_TYPE(KOF_MALTYPE_BOTNET);\nKOF_DIAG_TAG(\"Mirai-flood\");\n"
		 "KOF_DEFINE_STR(s0, \"abc\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\nKOF_TARGET_RANGE(r0, KOF_SCAN_ALL);\n"
		 "KOF_DIAG_FIND(m1, KOF_FIND_ALL, r0, s0);\nKOF_DIAG_FIND(m2, KOF_FIND_ALL, r0, s0);\nKOF_DIAG_EXPR(m1&m2);\n");
	new_draft();
	/* the draft holds the block of the real file 02 but is asked to link it to 01 (a hand-written expression): refused */
	(void)load_file("botnet_mirai_mirai-flood_02", &ok);
	CK(ok);
	CK(draft_link_unit(&E, 1, 0, dir, idof("botnet_mirai_mirai-flood_01"), "botnet_mirai_mirai-flood_01") == 0);       /* the unit is linked to 02 already */
	CK(draft_links_loaded(&E) == 1u);
	new_draft();
	g = add_new_unit(5, "Mirai-flood");
	CK(draft_link_unit(&E, 1, g, dir, idof("botnet_mirai_mirai-flood_01"), "botnet_mirai_mirai-flood_01") == 0);       /* a file the editor cannot represent */
	CK(draft_unit_link(&E, 1, g) == 0u && draft_links_loaded(&E) == 0u);
	/* unticking it deletes nothing */
	blk_set_picked(&E, E.dr.grp[g].sim[0].blk, 0);
	before = snap();
	CK(save() < 0);
	after = snap();
	CK(same_text(before, after));
	free(before);
	free(after);

	/* a different threshold, a different tag, a different type, a different block: no link */
	clean();
	copy_real_all();
	new_draft();
	(void)load_file("botnet_mirai_mirai-flood_01", &ok);
	CK(ok);
	g = 0;
	{
		struct group saved = E.dr.grp[0];
		struct kof_draft keep_dr;

		memset(&keep_dr, 0, sizeof keep_dr);
		E.dr.grp[0].link = 0;
		E.dr.n_loaded = 0;
		E.dr.grp[0].pct = 60;
		CK(draft_link_unit(&E, 1, 0, dir, idof("botnet_mirai_mirai-flood_01"), "botnet_mirai_mirai-flood_01") == 0);
		E.dr.grp[0].pct = saved.pct;
		E.dr.grp[0].utype = (uint8_t)(KOF_MALTYPE_TROJAN + 1u);
		CK(draft_link_unit(&E, 1, 0, dir, idof("botnet_mirai_mirai-flood_01"), "botnet_mirai_mirai-flood_01") == 0);
		E.dr.grp[0].utype = saved.utype;
		E.dr.grp[0].tag[0] = 'X';
		CK(draft_link_unit(&E, 1, 0, dir, idof("botnet_mirai_mirai-flood_01"), "botnet_mirai_mirai-flood_01") == 0);
		E.dr.grp[0].tag[0] = saved.tag[0];
		CK(draft_link_unit(&E, 1, 0, dir, idof("botnet_mirai_mirai-flood_02"), "botnet_mirai_mirai-flood_02") == 0);   /* another diagnose's file */
		CK(draft_link_unit(&E, 1, 0, dir, idof("botnet_mirai_mirai-flood_01"), "botnet_mirai_mirai-flood_01") == 1);   /* and the right one links */
	}
	/* a file whose name line says another name is not the diagnose that was asked for */
	clean();
	copy_real("botnet_mirai_mirai-flood_01");
	{
		size_t m = 0;
		char *t = slurp("botnet_mirai_mirai-flood_01.c", &m), *p;

		p = strstr(t, "mirai-flood_01");
		CK(p != NULL);
		p[13] = '7';
		put_file("botnet_mirai_mirai-flood_01.c", t);
		free(t);
	}
	new_draft();
	(void)load_file("botnet_mirai_mirai-flood_01", &ok);
	CK(!ok && draft_links_loaded(&E) == 0u);
}

/* Hostile names and files: nothing is linked, nothing outside the diagnoses directory is read or deleted. */
static void hostile(void)
{
	static const char *const BAD[] = { "", "..", "../x", "a/b", "/etc/passwd", ".hidden", "a.b", "x\ny", "with space", "a;rm -rf", "%s%n" };
	char longname[200];
	char outside[300], link[400];
	char *before, *after;
	unsigned i;
	int ok;
	uint32_t g;

	clean();
	copy_real_all();
	new_draft();
	g = add_new_unit(9, "Mirai-flood");
	for (i = 0; i < sizeof BAD / sizeof BAD[0]; i++)
		CKM(draft_link_unit(&E, 1, g, dir, idof(BAD[i]), BAD[i]) == 0, BAD[i]);
	/* names a file could really have: the diagnose of flood 01 under each, so only the name rule stands between them and a link */
	{
		static const char *const NAMES[] = { "a.b", "a b", "a;b", "$HOME", "a~", "a:b" };
		size_t m = 0, q;
		char *t;

		copy_real("botnet_mirai_mirai-flood_01");
		t = slurp("botnet_mirai_mirai-flood_01.c", &m);
		for (q = 0; q < sizeof NAMES / sizeof NAMES[0]; q++) {
			char leaf[100], *body = malloc(m + 100u), *p;

			snprintf(body, m + 100u, "%s", t);
			p = strstr(body, "botnet_mirai_mirai-flood_01");
			memmove(p + strlen(NAMES[q]), p + strlen("botnet_mirai_mirai-flood_01"), strlen(p + strlen("botnet_mirai_mirai-flood_01")) + 1u);
			memcpy(p, NAMES[q], strlen(NAMES[q]));
			snprintf(leaf, sizeof leaf, "%s.c", NAMES[q]);
			put_file(leaf, body);
			free(body);
		}
		free(t);
		new_draft();
		(void)load_file("botnet_mirai_mirai-flood_01", &ok);
		CK(ok);
		E.dr.n_loaded = 0;
		E.dr.grp[0].link = 0;
		for (q = 0; q < sizeof NAMES / sizeof NAMES[0]; q++)
			CKM(draft_link_unit(&E, 1, 0, dir, idof(NAMES[q]), NAMES[q]) == 0, NAMES[q]);
		clean();
		copy_real_all();
		new_draft();
		g = add_new_unit(9, "Mirai-flood");
	}
	memset(longname, 'a', sizeof longname - 1u);
	longname[sizeof longname - 1u] = 0;
	CK(draft_link_unit(&E, 1, g, dir, idof(longname), longname) == 0);
	CK(draft_link_unit(&E, 1, g, dir, idof(NULL), NULL) == 0);
	CK(draft_link_unit(&E, 1, 99u, dir, idof("botnet_mirai_mirai-flood_01"), "botnet_mirai_mirai-flood_01") == 0);     /* no such unit */
	CK(draft_link_unit(&E, 0, 0, dir, idof("botnet_mirai_mirai-flood_01"), "botnet_mirai_mirai-flood_01") == 0);
	CK(draft_links_loaded(&E) == 0u);

	/* a link forged into the struct (never loaded) leads to no deletion: the list of loaded diagnoses is the only authority */
	E.dr.grp[g].link = idof("botnet_mirai_mirai-flood_02");
	before = snap();
	CK(save() == 1);                                 /* a link that was not loaded means nothing: the unit is a NEW one */
	CKM(strstr(msg, "modified") == NULL && strstr(msg, "Deleted") == NULL, "forged link");
	after = snap();
	CK(exists("botnet_mirai_mirai-flood_02") && exists("botnet_mirai_mirai-flood_07"));
	CK(strstr(after, "botnet_mirai_mirai-flood_02.c") != NULL);
	free(before);
	free(after);
	E.dr.grp[g].link = 0;

	/* a file replaced by a symlink to a file outside the directory since it was loaded: not followed, not deleted, not linked */
	clean();
	copy_real_all();
	load_all8();
	snprintf(outside, sizeof outside, "%s.outside", dir);
	{
		size_t m = 0;
		char *t = slurp("botnet_mirai_mirai-flood_04.c", &m);
		FILE *f = fopen(outside, "wb");

		fwrite(t, 1, m, f);
		fclose(f);
		free(t);
	}
	snprintf(link, sizeof link, "%s/botnet_mirai_mirai-flood_04.c", dir);
	{
		char target[300];

		snprintf(target, sizeof target, "../%s", strrchr(outside, '/') + 1);
		CK(unlink(link) == 0 && symlink(target, link) == 0);
	}
	CK(untick("botnet_mirai_mirai-flood_04"));
	CK(untick("botnet_mirai_mirai-flood_05"));
	before = snap();
	CK(save() < 0);
	CKM(strstr(msg, "Not written") != NULL, "a symlink is not deleted");
	after = snap();
	CK(same_text(before, after));
	CK(access(outside, F_OK) == 0);                   /* the target outside is intact */
	/* and a symlink is not linked at load either */
	new_draft();
	(void)load_file("botnet_mirai_mirai-flood_04", &ok);
	CK(!ok);
	free(before);
	free(after);
	unlink(outside);

	/* a directory with the name of a file */
	clean();
	copy_real_all();
	load_all8();
	snprintf(link, sizeof link, "%s/botnet_mirai_mirai-flood_06.c", dir);
	CK(unlink(link) == 0 && mkdir(link, 0700) == 0);
	CK(untick("botnet_mirai_mirai-flood_06"));
	before = snap();
	CK(save() < 0 && strstr(msg, "not a regular file") != NULL);     /* a directory is not deleted */
	after = snap();
	CK(same_text(before, after));
	free(before);
	free(after);
	rmdir(link);
}

/* Rule 2: only what was loaded can be deleted. */
static void loaded_only(void)
{
	unsigned i;
	int ok;

	clean();
	copy_real_all();
	new_draft();
	/* three of the eight are loaded; unticking them deletes those three and no other */
	for (i = 0; i < 3u; i++) {
		(void)load_file(FLOOD[i], &ok);
		CK(ok);
	}
	for (i = 0; i < 3u; i++)
		CK(untick(FLOOD[i]));
	CK(save() == 0 && strstr(msg, "Deleted 3 files") != NULL);
	CK(count_files() == 5u);
	for (i = 3; i < 8u; i++)
		CK(exists(ALL8[i]));

	/* arrival at another object resets the list (mtn_sync): what was loaded for the old object is not deleted from the new one */
	clean();
	copy_real_all();
	load_all8();
	draft_links_reset(&E);
	CK(draft_links_loaded(&E) == 0u && draft_links_removed(&E) == 0u);
	for (i = 0; i < E.dr.n_grp; i++)
		CK(draft_unit_link(&E, 1, i) == 0u);
	for (i = 0; i < 8u; i++)
		(void)untick(ALL8[i]);                       /* no link left to match: nothing unticks by link */
	for (i = E.dr.n_grp; i-- > 0; )
		blk_set_picked(&E, E.dr.grp[i].sim[0].blk, 0);
	CK(save() < 0);
	CK(count_files() == 8u);

	/* Discard (draft_reset) and draft_clear forget the links and the list */
	clean();
	copy_real_all();
	load_all8();
	draft_reset(&E);
	CK(draft_links_loaded(&E) == 0u && E.dr.n_grp == 0u);
	CK(save() < 0 && count_files() == 8u);
	load_all8();
	draft_clear(&E);
	CK(draft_links_loaded(&E) == 0u && E.dr.loaded[0].name[0] == 0);
	CK(save() < 0 && count_files() == 8u);
	/* a loaded diagnose whose file is gone: its unit is a new unit now (written again under the first free number), nothing fails */
	clean();
	copy_real_all();
	load_all8();
	{
		char path[400];

		snprintf(path, sizeof path, "%s/botnet_mirai_mirai-flood_01.c", dir);
		CK(unlink(path) == 0);
	}
	CK(untick("botnet_mirai_mirai-flood_02"));
	CK(save() == 1);
	CK(!exists("botnet_mirai_mirai-flood_02") && exists("botnet_mirai_mirai-flood_01") && count_files() == 7u);
	CK(draft_links_loaded(&E) == 7u);                   /* 6 left of the 8, and the unit that was written again */
	CK(draft_unit_link(&E, 1, 0) != idof("botnet_mirai_mirai-flood_01") || !fake_ids);   /* the stale id is gone from the unit */
	CK(draft_unit_link(&E, 1, 0) == kof_diag_id32_("botnet_mirai_mirai-flood_01"));       /* it carries the id of the file just written */
}

/* A file changed since it was loaded is not the diagnose that was loaded: the Save refuses, deletes nothing. */
static void changed_since_load(void)
{
	char *before, *after;
	char path[400];
	FILE *f;

	clean();
	copy_real_all();
	load_all8();
	snprintf(path, sizeof path, "%s/botnet_mirai_mirai-flood_03.c", dir);
	f = fopen(path, "ab");
	fputs("KOF_DIAG_EXPR(m1);\n", f);                 /* a line the author added by hand since */
	fclose(f);
	CK(untick("botnet_mirai_mirai-flood_03"));
	CK(untick("botnet_mirai_mirai-flood_04"));
	before = snap();
	CK(save() < 0);
	CKM(strstr(msg, "changed") != NULL && strstr(msg, "botnet_mirai_mirai-flood_03") != NULL, "refused");
	after = snap();
	CK(same_text(before, after));
	free(before);
	free(after);
}

/* Two units linked to the same file. */
static void same_file_twice(void)
{
	char *before, *after;
	int ok;
	uint32_t g;

	clean();
	copy_real_all();
	load_all8();
	E.dr.grp[1].link = E.dr.grp[0].link;
	before = snap();
	CK(save() < 0 && strstr(msg, "two units are linked") != NULL);
	after = snap();
	CK(same_text(before, after));
	free(before);
	free(after);
	/* the API does not make the second link */
	new_draft();
	(void)load_file("botnet_mirai_mirai-flood_01", &ok);
	CK(ok);
	g = add_new_unit(11, "Mirai-flood");
	CK(draft_link_unit(&E, 1, g, dir, idof("botnet_mirai_mirai-flood_01"), "botnet_mirai_mirai-flood_01") == 0);
	CK(draft_link_unit(&E, 1, 0, dir, idof("botnet_mirai_mirai-flood_01"), "botnet_mirai_mirai-flood_01") == 0);   /* and not the same twice */
	CK(draft_links_loaded(&E) == 1u);
}

/* Unticking a block and ticking it again: the file stays, is not duplicated, and the unit is linked to it again. */
static void re_added(void)
{
	char *before, *after;
	uint32_t g, blk;
	int ok;

	clean();
	copy_real_all();
	new_draft();
	g = load_file("botnet_mirai_mirai-flood_01", &ok);
	CK(ok);
	blk = E.dr.grp[g].sim[0].blk;
	blk_set_picked(&E, blk, 0);
	CK(E.dr.n_grp == 0u && draft_links_removed(&E) == 1u);
	blk_set_picked(&E, blk, 1);
	g = grp_of_block(&E, blk);
	snprintf(E.dr.grp[g].tag, sizeof E.dr.grp[g].tag, "Mirai-flood");
	E.dr.grp[g].utype = (uint8_t)(KOF_MALTYPE_BOTNET + 1u);
	E.dr.grp[g].pct = 70;
	before = snap();
	CK(save() == 0);
	CKM(strstr(msg, "Deleted") == NULL && strstr(msg, "Wrote") == NULL, "re-added");
	after = snap();
	CK(same_text(before, after));
	CK(draft_unit_link(&E, 1, g) == idof("botnet_mirai_mirai-flood_01") && draft_links_loaded(&E) == 1u);
	free(before);
	free(after);
}

/* Rule 6: the link follows its unit through every function that moves, removes, copies or reorders units. */
static void link_follows_unit(void)
{
	uint32_t to[64], i, g;
	int ok;

	clean();
	copy_real_all();
	load_all8();
	/* remove the middle: the others keep their own links */
	CK(untick("botnet_mirai_mirai-flood_03"));
	for (g = 0; g < E.dr.n_grp; g++)
		CK(draft_unit_link(&E, 1, g) == idof(ALL8[g < 2u ? g : g + 1u]));
	/* a matcher taken out by grp_remove directly (the row's [x]) is a removal like an untick */
	grp_remove(&E, 0);
	CK(draft_unit_link(&E, 1, 0) == idof("botnet_mirai_mirai-flood_02"));
	CK(draft_links_removed(&E) == 2u);
	/* the blocks reordered whole: groups stay put, and each still names its own block (the link is on the matcher) */
	for (i = 0; i < E.dr.n_blk; i++)
		to[i] = E.dr.n_blk - 1u - i;
	{
		struct mtn_block *tmp = malloc(E.dr.n_blk * sizeof *tmp);

		for (i = 0; i < E.dr.n_blk; i++)
			tmp[to[i]] = E.dr.blk[i];
		memcpy(E.dr.blk, tmp, E.dr.n_blk * sizeof *tmp);
		free(tmp);
	}
	blk_permute(&E, to, E.dr.n_blk);
	CK(draft_unit_link(&E, 1, 0) == idof("botnet_mirai_mirai-flood_02"));
	CK(save() == 0);                                  /* every linked matcher still equals its file: only the two removed go */
	CKM(strstr(msg, "Deleted 2 files") != NULL && strstr(msg, "modified") == NULL, "after a permute");
	CK(!exists("botnet_mirai_mirai-flood_01") && !exists("botnet_mirai_mirai-flood_03") && count_files() == 6u);
	/* grp_add and cnd_add give a slot with no link even when the slot held one */
	new_draft();
	(void)load_file("botnet_mirai_mirai-flood_02", &ok);
	grp_remove(&E, 0);
	grp_add(&E);
	CK(E.dr.grp[0].link == 0u);
	cnd_add(&E);
	E.dr.cnd[0].link = 7u;
	cnd_remove(&E, 0);
	cnd_add(&E);
	CK(E.dr.cnd[0].link == 0u);
}

/* AFTER A SAVE the units just written carry their ids: taking one out later deletes the file the first Save wrote; a second Save sees nothing new. */
static void after_save_link(void)
{
	uint32_t g;
	char *before, *after;

	clean();
	new_draft();
	g = add_new_unit(41, "Mirai-flood");
	CK(draft_unit_link(&E, 1, g) == 0u);
	CK(save() == 1 && exists("botnet_mirai_mirai-flood_01"));
	CK(draft_unit_link(&E, 1, g) == kof_diag_id32_("botnet_mirai_mirai-flood_01") && draft_links_loaded(&E) == 1u);
	before = snap();
	CK(save() == 0 && strstr(msg, "Nothing new to write") != NULL);
	after = snap();
	CK(same_text(before, after));
	free(before);
	free(after);
	blk_set_picked(&E, E.dr.grp[g].sim[0].blk, 0);
	CK(save() == 0 && strstr(msg, "Deleted 1 file") != NULL && !exists("botnet_mirai_mirai-flood_01") && count_files() == 0u);
	CK(draft_links_loaded(&E) == 0u);
	/* two new units, one taken out, one kept */
	new_draft();
	(void)add_new_unit(42, "Mirai-flood");
	(void)add_new_unit(43, "Mirai-flood");
	CK(save() == 2 && exists("botnet_mirai_mirai-flood_01") && exists("botnet_mirai_mirai-flood_02"));
	blk_set_picked(&E, E.dr.grp[1].sim[0].blk, 0);
	CK(save() == 0 && exists("botnet_mirai_mirai-flood_01") && !exists("botnet_mirai_mirai-flood_02"));
}

/* THE NAME THE PANEL SHOWS is the name Save writes: a linked unit shows its file, a new one the first free number; nothing is numbered by position. */
static void panel_names(void)
{
	char a[200], b[500], c[200];
	uint32_t g;
	unsigned i;

	clean();
	copy_real_all();
	load_n(6u);
	draft_set_tree_dir(&E, dir);
	for (i = 0; i < 6u; i++) {
		draft_unit_name(&E, 1, i, a, sizeof a);
		CKM(!strcmp(a, ALL8_FILE(i)), a);
	}
	/* remove the third: the others keep their names, none shifts */
	CK(untick(ALL8[2]));
	draft_unit_name(&E, 1, 0, a, sizeof a);
	draft_unit_name(&E, 1, 2, b, sizeof b);
	CK(!strcmp(a, "botnet_mirai_mirai-flood_01.c") && !strcmp(b, "botnet_mirai_mirai-flood_04.c"));
	/* a new unit shows the next free number against the directory (07), a second new one the one after (08) */
	g = add_new_unit(51, "Mirai-flood");
	draft_unit_name(&E, 1, g, a, sizeof a);
	CK(!strcmp(a, "botnet_mirai_mirai-flood_07.c"));
	g = add_new_unit(52, "Mirai-flood");
	draft_unit_name(&E, 1, g, b, sizeof b);
	draft_unit_name(&E, 1, g - 1u, a, sizeof a);
	CK(!strcmp(a, "botnet_mirai_mirai-flood_07.c") && !strcmp(b, "botnet_mirai_mirai-flood_08.c"));
	grp_file_name(&E, g, c, sizeof c);
	CK(!strcmp(c, b));
	/* what Save writes is what was shown */
	CK(save() == 2);
	CK(exists("botnet_mirai_mirai-flood_07") && exists("botnet_mirai_mirai-flood_08") && !exists("botnet_mirai_mirai-flood_03"));
	for (i = 0; i < E.dr.n_grp; i++) {
		draft_unit_name(&E, 1, i, a, sizeof a);
		snprintf(b, sizeof b, "%s/%s", dir, a);
		CKM(access(b, F_OK) == 0, a);                  /* every shown name is a file now */
	}
}

/* P-6: a file that exists but cannot be opened counts as TAKEN (the number is not given to a new unit). P-11: a write that fails at fclose leaves
 * no file this call made. (P-10, the panel naming another file than Save writes, is panel_names.) */
static void audit_rows(void)
{
	char path[500];
	struct rlimit lim, was;
	int rc;

	clean();
	copy_real("botnet_mirai_mirai-flood_01");
	snprintf(path, sizeof path, "%s/botnet_mirai_mirai-flood_01.c", dir);
	CK(chmod(path, 0) == 0);
	new_draft();
	(void)add_new_unit(61, "Mirai-flood");
	rc = save();
	CKM(rc == 1 && exists("botnet_mirai_mirai-flood_02") && count_files() == 2u, "an unreadable file is a taken number");
	chmod(path, 0600);

	clean();
	new_draft();
	(void)add_new_unit(62, "Mirai-flood");
	(void)add_new_unit(63, "Mirai-flood");
	signal(SIGXFSZ, SIG_IGN);
	getrlimit(RLIMIT_FSIZE, &was);
	lim = was;
	lim.rlim_cur = 100;
	CK(setrlimit(RLIMIT_FSIZE, &lim) == 0);
	rc = save();
	setrlimit(RLIMIT_FSIZE, &was);
	CKM(rc < 0 && strstr(msg, "Not written") != NULL && count_files() == 0u, "a write that fails leaves nothing");
}

/* Limits and the failures of the failure path itself. */
static FILE *plain_create(void *ud, const char *path)
{
	(void)ud;
	return fopen(path, "wbx");
}

struct failing_put_back {
	const char *dir;
	int         calls;
};

static int unlink_then_lock(void *ud, const char *path)
{
	struct failing_put_back *w = ud;
	int rc = unlink(path);

	if (++w->calls == 2)
		chmod(w->dir, 0500);          /* the next unlink fails and the put back cannot create a file */
	return w->calls == 3 ? -1 : rc;
}

static void limits(void)
{
	char *before, *after;
	char path[500], small[60];
	unsigned i;
	int rc;

	/* 99 numbers taken: a new unit says so and nothing is written */
	clean();
	for (i = 1; i <= 99u; i++) {
		snprintf(path, sizeof path, "botnet_mirai_mirai-flood_%02u.c", i);
		put_file(path, "KOF_DIAG_NAME(x);\n");
	}
	new_draft();
	(void)add_new_unit(71, "Mirai-flood");
	before = snap();
	CK(save() < 0 && strstr(msg, "no free number") != NULL);
	after = snap();
	CK(same_text(before, after));
	free(before);
	free(after);

	/* a name too long for a diagnose */
	clean();
	new_draft();
	(void)add_new_unit(72, "Mirai-flood");
	memset(E.dr.family, 'a', 60u);
	E.dr.family[60] = 0;
	snprintf(E.dr.variant, sizeof E.dr.variant, "%s_A", E.dr.family);
	rc = save();
	CKM(rc < 0 && count_files() == 0u, "a long name");

	/* the status line does not overflow the room it was given: it ends in "..." */
	clean();
	copy_real_all();
	load_all8();
	for (i = 0; i < 8u; i++)
		CK(untick(ALL8[i]));
	rc = draft_generate(&E, dir, small, sizeof small);
	CK(rc == 0 && strlen(small) == sizeof small - 1u && !strcmp(small + sizeof small - 4u, "..."));
	CK(count_files() == 0u);

	/* a linked file that became a directory: refused, nothing touched */
	clean();
	copy_real_all();
	load_n(3u);
	snprintf(path, sizeof path, "%s/botnet_mirai_mirai-flood_02.c", dir);
	CK(unlink(path) == 0 && mkdir(path, 0700) == 0);
	before = snap();
	CK(save() < 0 && strstr(msg, "not a regular file") != NULL);
	after = snap();
	CK(same_text(before, after));
	free(before);
	free(after);
	rmdir(path);

	/* the put back itself fails: the message says which file could not be put back */
	clean();
	copy_real_all();
	load_n(3u);
	CK(untick(ALL8[0]) && untick(ALL8[1]) && untick(ALL8[2]));
	{
		struct failing_put_back w = { dir, 0 };
		struct draft_fs fs = { &w, NULL, unlink_then_lock };

		fs.create = plain_create;
		if (geteuid() != 0) {
			w.calls = 0;
			rc = draft_generate_fs(&E, dir, msg, sizeof msg, 1, &fs);
			chmod(dir, 0700);
			CKM(rc < 0 && strstr(msg, "could not be put back") != NULL, "put back fails");
		}
		chmod(dir, 0700);
	}
}

/* THE LINK IS A VALUE: ids that are not a function of the name, loaded in an order that is neither the file order nor the draft's, and the
 * right files are still deleted. */
static void ids_are_values(void)
{
	static const unsigned ORDER[8] = { 5, 0, 7, 2, 6, 1, 4, 3 };
	unsigned i;
	int ok;

	fake_ids = 1;
	clean();
	copy_real_all();
	new_draft();
	for (i = 0; i < 8u; i++) {
		(void)load_file(ALL8[ORDER[i]], &ok);
		CKM(ok, ALL8[ORDER[i]]);
	}
	CK(draft_links_loaded(&E) == 8u);
	CK(untick(ALL8[2]) && untick(ALL8[6]) && untick(ALL8[0]));
	CK(save() == 0 && strstr(msg, "Deleted 3 files") != NULL);
	for (i = 0; i < 8u; i++)
		CKM((i == 0u || i == 2u || i == 6u) ? !exists(ALL8[i]) : exists(ALL8[i]), ALL8[i]);
	CK(draft_links_loaded(&E) == 5u);
	fake_ids = 0;
}

/* The condition side: a Patterns condition linked to its file is removed with the condition; a matcher taken out from under a condition that
 * stays is a modification. (No loader builds a condition from a file yet - only the link API reaches this path.) */
static void conditions(void)
{
	struct decl *d;
	struct group *q;
	struct cond *c;
	char *before, *after;
	char path[400];
	int rc;

	clean();
	new_draft();
	d = decl_push(&E);
	memset(d, 0, sizeof *d);
	d->bytes = malloc(8);
	memcpy(d->bytes, "alpha-ma", 8);
	d->nbytes = d->len = 8;
	d->grp = 1u;
	q = &E.dr.grp[E.dr.n_grp++];
	memset(q, 0, sizeof *q);
	q->kind = (uint8_t)GRP_KIND_STR;
	q->rule = 1;
	q->mask = KOF_SCAN_ELF_CODE;
	c = &E.dr.cnd[E.dr.n_cnd++];
	memset(c, 0, sizeof *c);
	snprintf(c->expr, sizeof c->expr, "1");
	c->utype = (uint8_t)(KOF_MALTYPE_BOTNET + 1u);
	snprintf(c->tag, sizeof c->tag, "flood");
	snprintf(E.dr.family, sizeof E.dr.family, "Mirai");
	snprintf(E.dr.variant, sizeof E.dr.variant, "Mirai_A");
	E.dr.fmt_mask = 1u << KOF_FMT_ELF;
	rc = save();
	CKM(rc == 1, "the condition is written");
	snprintf(path, sizeof path, "%s/botnet_mirai_flood_01.c", dir);
	CK(access(path, F_OK) == 0);
	/* the file just written is the diagnose of this unit from now on: it took the engine's id of the name */
	CK(draft_links_loaded(&E) == 1u && draft_unit_link(&E, 0, 0) == kof_diag_id32_("botnet_mirai_flood_01"));
	CK(draft_unit_link(&E, 0, 0) == idof("botnet_mirai_flood_01"));
	before = snap();
	CK(save() == 0 && strstr(msg, "Nothing new to write") != NULL);
	after = snap();
	CK(same_text(before, after));
	free(before);
	free(after);
	/* the string matcher goes from under the condition that stays: the condition no longer says what its file says - modified, not removed */
	grp_remove(&E, 0);
	CK(draft_links_removed(&E) == 0u);
	rc = save();
	CKM(rc == 0 && strstr(msg, "1 modified diagnose not saved: editing is not done") != NULL, "a matcher removed under a condition is a modification");
	CK(access(path, F_OK) == 0);
	/* the condition itself removed: the file goes */
	cnd_remove(&E, 0);
	CK(draft_links_removed(&E) == 1u);
	CK(save() == 0 && strstr(msg, "Deleted 1 file") != NULL);
	CK(access(path, F_OK) != 0);
	free(d->bytes);
	d->bytes = NULL;
}

/* ---- failure injection ---------------------------------------------------------------------------------------------- */

struct inj {
	const char *fail_unlink;      /* the unlink of this path fails */
	const char *fail_create;      /* the create of a path ending in this fails */
	int         unlinks;
};

static FILE *inj_create(void *ud, const char *path)
{
	struct inj *j = ud;
	size_t L = j->fail_create ? strlen(j->fail_create) : 0, P = strlen(path);

	if (L && P >= L && !strcmp(path + P - L, j->fail_create))
		return NULL;
	return fopen(path, "wbx");
}

static int inj_unlink(void *ud, const char *path)
{
	struct inj *j = ud;
	size_t L = j->fail_unlink ? strlen(j->fail_unlink) : 0, P = strlen(path);

	if (L && P >= L && !strcmp(path + P - L, j->fail_unlink))
		return -1;
	j->unlinks++;
	return unlink(path);
}

/* The file of a removal is replaced by a symlink AFTER the plan was made (when the first new file is created): the Save must not unlink or
 * follow it, and must put the tree back. */
struct swap {
	const char *victim;
	const char *target;
};

static FILE *swap_create(void *ud, const char *path)
{
	struct swap *w = ud;
	char vp[400];

	snprintf(vp, sizeof vp, "%s/%s", dir, w->victim);
	(void)unlink(vp);
	(void)symlink(w->target, vp);
	return fopen(path, "wbx");
}

static int real_unlink(void *ud, const char *path)
{
	(void)ud;
	return unlink(path);
}

static void failures(void)
{
	char *before, *after;
	struct inj j = { NULL, NULL, 0 };
	struct draft_fs fs = { &j, inj_create, inj_unlink };
	char path[400];
	int rc;

	/* the third of three deletions fails: the two that went come back, byte for byte and with their mode, and the new file is removed */
	clean();
	copy_real_all();
	snprintf(path, sizeof path, "%s/botnet_mirai_mirai-flood_01.c", dir);
	chmod(path, 0640);
	load_all8();
	CK(untick("botnet_mirai_mirai-flood_01"));
	CK(untick("botnet_mirai_mirai-flood_02"));
	CK(untick("botnet_mirai_mirai-flood_03"));
	(void)add_new_unit(21, "Mirai-flood");
	before = snap();
	j.fail_unlink = "mirai-flood_03.c";
	rc = draft_generate_fs(&E, dir, msg, sizeof msg, 1, &fs);
	CKM(rc < 0 && strstr(msg, "Not written: cannot delete botnet_mirai_mirai-flood_03.c") != NULL, "unlink fails");
	CK(j.unlinks == 2);
	after = snap();
	CKM(same_text(before, after), "the tree is as before");
	CK(draft_links_loaded(&E) == 8u && draft_links_removed(&E) == 3u);       /* the draft still holds the removals: Save again works */
	free(before);
	free(after);
	j.fail_unlink = NULL;
	j.unlinks = 0;
	rc = draft_generate_fs(&E, dir, msg, sizeof msg, 1, &fs);
	CKM(rc == 1 && j.unlinks == 3 && count_files() == 6u, "the retry goes through");

	/* a swap between the plan and the apply */
	clean();
	copy_real_all();
	load_n(6u);
	CK(untick("botnet_mirai_mirai-flood_05"));
	(void)add_new_unit(25, "Mirai-flood");
	{
		char outside[400];
		struct swap w;
		struct draft_fs sfs = { &w, swap_create, real_unlink };
		FILE *f;

		snprintf(outside, sizeof outside, "%s.target", dir);
		f = fopen(outside, "wb");
		fputs("precious\n", f);
		fclose(f);
		w.victim = "botnet_mirai_mirai-flood_05.c";
		w.target = strrchr(outside, '/') + 1;      /* the same directory as the diagnoses directory's parent: "../x" below */
		{
			char rel[300];

			snprintf(rel, sizeof rel, "../%s", w.target);
			w.target = rel;
			rc = draft_generate_fs(&E, dir, msg, sizeof msg, 1, &sfs);
		}
		CKM(rc < 0 && strstr(msg, "cannot delete botnet_mirai_mirai-flood_05.c") != NULL, "a swapped file is not unlinked");
		CK(!exists("botnet_mirai_mirai-flood_07"));          /* the file this call created is removed */
		{
			char *t = slurp_path(outside, NULL);

			CK(t && !strcmp(t, "precious\n"));
			free(t);
		}
		unlink(outside);
	}

	/* the create of the new file fails: nothing was deleted */
	clean();
	copy_real_all();
	load_n(6u);
	CK(untick("botnet_mirai_mirai-flood_05"));
	(void)add_new_unit(22, "Mirai-flood");
	(void)add_new_unit(23, "Mirai-flood");
	before = snap();
	j.fail_create = "flood_08.c";
	rc = draft_generate_fs(&E, dir, msg, sizeof msg, 1, &fs);
	CKM(rc < 0 && strstr(msg, "Not written: cannot create") != NULL, "create fails");
	after = snap();
	CKM(same_text(before, after), "the first new file was removed and nothing deleted");
	free(before);
	free(after);
	j.fail_create = NULL;

	/* a read-only directory: the plan is sound but the disk refuses; the tree is as before (skipped for root, which ignores modes) */
	clean();
	copy_real_all();
	load_all8();
	CK(untick("botnet_mirai_mirai-flood_06"));
	(void)add_new_unit(24, "Mirai-flood");
	before = snap();
	chmod(dir, 0500);
	if (geteuid() != 0) {
		rc = save();
		CKM(rc < 0, "read-only directory");
		chmod(dir, 0700);
		after = snap();
		CK(same_text(before, after));
		free(after);
	} else {
		printf("  (running as root: the read-only directory row is skipped)\n");
		chmod(dir, 0700);
	}
	free(before);
	/* a directory that is not a directory */
	CK(draft_generate(&E, "build/test/no_such_directory_for_diag_save", msg, sizeof msg) < 0 && strstr(msg, "is not a directory") != NULL);

	/* a draft that is incomplete refuses before the plan: a unit with no type */
	clean();
	copy_real_all();
	load_all8();
	CK(untick("botnet_mirai_mirai-flood_01"));
	E.dr.grp[0].utype = 0;
	before = snap();
	CK(save() < 0 && strstr(msg, "Not written") != NULL);
	after = snap();
	CK(same_text(before, after));
	free(before);
	free(after);
}

/* The with_form seam (catalog lines only) takes the same links: the same Save logic runs. */
static void seam(void)
{
	uint32_t g;

	clean();
	new_draft();
	snprintf(E.dr.family, sizeof E.dr.family, "Mirai");
	snprintf(E.dr.variant, sizeof E.dr.variant, "Mirai_A");
	g = add_new_unit(31, "flood");
	(void)g;
	CK(draft_generate_with(&E, dir, msg, sizeof msg, 0) == 1);
	/* link by hand (a seam draft has no detection part to compare) */
	E.dr.grp[0].link = kof_diag_id32_("botnet_mirai_flood_01");
	E.dr.loaded[0].id = E.dr.grp[0].link;
	snprintf(E.dr.loaded[0].name, sizeof E.dr.loaded[0].name, "botnet_mirai_flood_01");
	E.dr.n_loaded = 1;
	CK(draft_generate_with(&E, dir, msg, sizeof msg, 0) == 0 && strstr(msg, "Nothing new to write") != NULL);
	snprintf(E.dr.grp[0].tag, sizeof E.dr.grp[0].tag, "other");
	CK(draft_generate_with(&E, dir, msg, sizeof msg, 0) == 0 && strstr(msg, "modified diagnose not saved") != NULL);
}

int main(void)
{
	DS = calloc(1, sizeof *DS);
	snprintf(dir, sizeof dir, "build/test/diagsave_%d", (int)getpid());
	CK(kof_mkdir("build/test", 0700) == 0 || 1);
	CK(kof_mkdir(dir, 0700) == 0);

	round_trip();
	removal();
	addition();
	modified();
	not_linked();
	hostile();
	loaded_only();
	changed_since_load();
	same_file_twice();
	re_added();
	link_follows_unit();
	conditions();
	after_save_link();
	panel_names();
	ids_are_values();
	audit_rows();
	limits();
	failures();
	seam();

	clean();
	rmdir(dir);
	free(DS);
	if (fails) {
		printf("diag_save: %d failure(s)\n", fails);
		return 1;
	}
	printf("diag_save: added is written, removed is deleted, modified is reported, every failure puts the tree back - ok\n");
	return 0;
}
