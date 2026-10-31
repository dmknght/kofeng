#define _GNU_SOURCE
/*
 * diag_write - what the Generate button writes: one diagnose source per unit, through diagsrc.
 *
 * PINNED: the files are written with the name the panel composes (<type>_<family>_<tag>_NN.c) and
 * every one reads back through the shared reader with the declarations of the draft - the name, the
 * header's format, and the four catalog lines (family and variant from the header, type and tag from
 * the unit); a draft that is not complete writes NOTHING (the header has no family or no variant, a
 * unit has no type or no tag) and says which unit and why; GENERATE REFUSES A UNIT WITH NO DETECTION PART (a condition whose
 * expression names no matcher, a block matcher that holds no block) with that reason and writes nothing - the writing of the
 * detection part itself is diag_form_generate's; a file that exists is never replaced; a unit the tree
 * already holds (same declarations) is not written again, a new unit takes the first free number of its prefix in the DIRECTORY (not the
 * draft's own count), and the others are written beside them; a directory that is not there is refused.
 *
 * Why the old tests missed it: (a) nothing wrote a file - the button only listed, so no row could ask
 * whether a refusal leaves the directory empty; (b) the "exists" rows ran Generate twice on the SAME draft, and never a new unit beside
 * files that were already there - which is what adding a diagnose to a tree is.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#include "../../kofexamine/kofeditor.h"
#include "../../libkofeng/databases/diagsrc.h"
#include "../../libkofeng/kofcore/kofplatform.h"

static int fails;
static struct kof_editor E;
static char dir[256];

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

/* The writer's own mechanics, catalog lines only (with_form 0): the drafts here have no matcher to write, which Generate
 * itself refuses (see refuses_incomplete_units); diag_form_generate writes the detection part. */
static int gen(struct kof_editor *e, const char *d, char *msg, size_t cap)
{
	return draft_generate_with(e, d, msg, cap, 0);
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

static char *slurp(const char *leaf, size_t *n)
{
	char path[400];
	FILE *f;
	char *b;
	long L;

	snprintf(path, sizeof path, "%s/%s", dir, leaf);
	f = fopen(path, "rb");
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

static void clean(void)
{
	char cmd[400];

	snprintf(cmd, sizeof cmd, "rm -rf '%s'/*", dir);
	(void)system(cmd);
}

/* A complete draft: Mirai / Mirai_A, ELF, two conditions (Botnet flood, Rootkit c2) and one block matcher (Botnet flood). */
static void draft(void)
{
	memset(&E.dr, 0, sizeof E.dr);
	snprintf(E.dr.family, sizeof E.dr.family, "Mirai");
	snprintf(E.dr.variant, sizeof E.dr.variant, "Mirai_A");
	E.dr.fmt_mask = 1u << KOF_FMT_ELF;
	E.dr.n_cnd = 2;
	E.dr.cnd[0].utype = (uint8_t)(KOF_MALTYPE_BOTNET + 1);
	snprintf(E.dr.cnd[0].tag, sizeof E.dr.cnd[0].tag, "flood");
	E.dr.cnd[1].utype = (uint8_t)(KOF_MALTYPE_ROOTKIT + 1);
	snprintf(E.dr.cnd[1].tag, sizeof E.dr.cnd[1].tag, "c2");
	E.dr.n_grp = 1;
	E.dr.grp[0].kind = (uint8_t)GRP_KIND_SIM;
	E.dr.grp[0].utype = (uint8_t)(KOF_MALTYPE_BOTNET + 1);
	snprintf(E.dr.grp[0].tag, sizeof E.dr.grp[0].tag, "flood");
}

static int head_errs;
static void on_err(void *ud, int line, const char *msg)
{
	(void)ud; (void)line;
	head_errs += strstr(msg, "needs a head") != NULL;
}

static void reads_back(const char *leaf, const char *type, const char *tag)
{
	static struct kof_dsrc d;
	struct kof_dsrc_view v;
	size_t n = 0, L = strlen(leaf);
	char *t = slurp(leaf, &n), stem[200];
	int ty = 0;

	CK(t != NULL);
	if (!t)
		return;
	snprintf(stem, sizeof stem, "%.*s", (int)(L - 2u), leaf);
	CK(kof_dsrc_parse(t, n, &d, NULL) == 0);
	/* the name is the file's stem and the first line */
	CK(d.n >= 5u && d.item[0].kind == KDS_NAME && !strcmp(d.item[0].s1, stem) && d.item[0].line == 1u);
	/* the file is a patch of nothing: what it holds is a declaration per line and nothing else */
	CK((size_t)d.lines == (size_t)d.n);
	{
		struct kof_dsrc_report rp = { on_err, NULL, NULL };

		head_errs = 0;
		/* RED reproduction of the reported failure: the file as the panel writes it has no head, so the builder
		 * refuses it ("a diagnose needs a head") - which is why Generate must not write it until the form is decided. */
		CK(kof_dsrc_resolve(&d, &v, &rp) > 0 && head_errs == 1);
	}
	CK(v.meta == KOF_DSRC_META_ALL && !strcmp(v.family, "Mirai") && !strcmp(v.variant, "A") &&
	   !strcmp(v.tag, tag));
	CK(kof_maltype_from_name(type, &ty) && v.type == (uint8_t)ty);
	CK(strstr(t, "KOF_TARGET_FORMAT(KOF_FMT_ELF);") != NULL);
	free(t);
}

/* Generate itself: a unit with no detection part is refused with the reason, whatever else is complete, and nothing is written.
 * (This row pinned "owner decision pending" for every unit while the source could not say a form: flipped with the form.) */
static void refuses_incomplete_units(void)
{
	char msg[300];

	draft();
	CK(draft_generate(&E, dir, msg, sizeof msg) < 0 && count_files() == 0u);
	CK(strstr(msg, "condition 1") && strstr(msg, "its expression names no matcher") && !strstr(msg, "owner decision"));
	draft();
	E.dr.n_cnd = 0;                                    /* only a block matcher */
	CK(draft_generate(&E, dir, msg, sizeof msg) < 0 && count_files() == 0u);
	CK(strstr(msg, "block matcher 1") && strstr(msg, "it holds no block") && !strstr(msg, "owner decision"));
	draft();
	E.dr.cnd[0].tag[0] = 0;                            /* the earlier refusals still come first */
	CK(draft_generate(&E, dir, msg, sizeof msg) < 0 && strstr(msg, "condition 1 it has no tag") != NULL);
}

/* A Blocks-only draft: one file per block matcher, the running id per prefix. */
static void blocks_only(void)
{
	char msg[300];

	draft();
	E.dr.n_cnd = 0;
	E.dr.n_grp = 3;
	E.dr.grp[1] = E.dr.grp[0];
	E.dr.grp[2] = E.dr.grp[0];
	E.dr.grp[2].utype = (uint8_t)(KOF_MALTYPE_ROOTKIT + 1);
	snprintf(E.dr.grp[2].tag, sizeof E.dr.grp[2].tag, "c2");
	CK(gen(&E, dir, msg, sizeof msg) == 3 && count_files() == 3u);
	reads_back("botnet_mirai_flood_01.c", "KOF_MALTYPE_BOTNET", "flood");
	reads_back("botnet_mirai_flood_02.c", "KOF_MALTYPE_BOTNET", "flood");
	reads_back("rootkit_mirai_c2_01.c", "KOF_MALTYPE_ROOTKIT", "c2");
	clean();
}

int main(void)
{
	char msg[300], path[400];
	int rc;
	FILE *f;
	size_t n = 0;
	char *keep;

	snprintf(dir, sizeof dir, "build/test/diagwrite_%d", (int)getpid());
	CK(kof_mkdir("build/test", 0700) == 0 || 1);
	CK(kof_mkdir(dir, 0700) == 0);

	refuses_incomplete_units();
	blocks_only();

	/* A complete draft: three files, the names the panel composes, each read back. */
	draft();
	rc = gen(&E, dir, msg, sizeof msg);
	CK(rc == 3);
	CK(count_files() == 3u);
	reads_back("botnet_mirai_flood_01.c", "KOF_MALTYPE_BOTNET", "flood");
	reads_back("rootkit_mirai_c2_01.c", "KOF_MALTYPE_ROOTKIT", "c2");
	reads_back("botnet_mirai_flood_02.c", "KOF_MALTYPE_BOTNET", "flood");
	CK(strstr(msg, "Wrote 3 files") != NULL);

	/* Nothing is replaced and nothing is written twice: the second press finds every unit already in the tree (same declarations, whatever
	 * their file's comments) and writes nothing, and the files are the first's byte for byte. */
	keep = slurp("botnet_mirai_flood_01.c", &n);
	rc = gen(&E, dir, msg, sizeof msg);
	CK(rc == 0 && strstr(msg, "Nothing new to write") != NULL);
	{
		size_t m = 0;
		char *again = slurp("botnet_mirai_flood_01.c", &m);

		CK(keep && again && m == n && !memcmp(keep, again, n));
		free(again);
	}
	free(keep);
	CK(count_files() == 3u);

	/* A NEW, INDEPENDENT UNIT beside the old ones (which are not touched): only the new one is written. It sits among the conditions, so
	 * the draft's own count gives the old block matcher (flood_02) a different place in the list: the old files must still be recognised. */
	E.dr.n_cnd = 3;
	E.dr.cnd[2].utype = (uint8_t)(KOF_MALTYPE_BOTNET + 1);
	snprintf(E.dr.cnd[2].tag, sizeof E.dr.cnd[2].tag, "udp");
	rc = gen(&E, dir, msg, sizeof msg);
	CK(rc == 1 && strstr(msg, "Wrote 1 file") != NULL && strstr(msg, "3 already there") != NULL);
	CK(count_files() == 4u);
	reads_back("botnet_mirai_udp_01.c", "KOF_MALTYPE_BOTNET", "udp");
	rc = gen(&E, dir, msg, sizeof msg);
	CK(rc == 0 && count_files() == 4u);
	clean();

	/* A file of that name that says something else is somebody else's: never replaced and not a reason to refuse the rest - the unit takes the
	 * next free number, and the three others are written. */
	snprintf(path, sizeof path, "%s/rootkit_mirai_c2_01.c", dir);
	draft();
	f = fopen(path, "wb");
	CK(f != NULL);
	if (f) {
		fputs("mine\n", f);
		fclose(f);
	}
	rc = gen(&E, dir, msg, sizeof msg);
	CK(rc == 3 && count_files() == 4u);
	reads_back("rootkit_mirai_c2_02.c", "KOF_MALTYPE_ROOTKIT", "c2");
	keep = slurp("rootkit_mirai_c2_01.c", &n);
	CK(keep && !strcmp(keep, "mine\n"));
	free(keep);
	clean();

	/* The refusals, each leaves the directory empty and says what is missing. */
	draft();
	E.dr.family[0] = 0;
	rc = gen(&E, dir, msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "the header has no family") != NULL && count_files() == 0u);
	draft();
	E.dr.variant[0] = 0;
	rc = gen(&E, dir, msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "the header has no variant") != NULL && count_files() == 0u);
	draft();
	E.dr.cnd[1].utype = 0;
	rc = gen(&E, dir, msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "condition 2 it has no type") != NULL && count_files() == 0u);
	draft();
	E.dr.cnd[0].tag[0] = 0;
	rc = gen(&E, dir, msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "condition 1 it has no tag") != NULL && count_files() == 0u);
	draft();
	E.dr.grp[0].utype = 0;
	rc = gen(&E, dir, msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "block matcher 1 it has no type") != NULL && count_files() == 0u);
	draft();
	snprintf(E.dr.cnd[0].tag, sizeof E.dr.cnd[0].tag, "a b");
	rc = gen(&E, dir, msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "character") != NULL && count_files() == 0u);
	draft();
	E.dr.n_cnd = 0;
	E.dr.n_grp = 0;
	rc = gen(&E, dir, msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "Nothing to write") != NULL && count_files() == 0u);
	draft();
	rc = gen(&E, "build/test/no_such_directory_for_diag_write", msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "is not a directory") != NULL);

	/* The file carries the letters, never the catalog's full name; a name that is not <family>_<letters> is refused. */
	draft();
	E.dr.n_grp = 0;
	rc = gen(&E, dir, msg, sizeof msg);
	CK(rc == 2);
	keep = slurp("botnet_mirai_flood_01.c", &n);
	CK(keep && strstr(keep, "KOF_DIAG_VARIANT(\"A\");\n") && !strstr(keep, "Mirai_A"));
	free(keep);
	clean();
	draft();
	snprintf(E.dr.variant, sizeof E.dr.variant, "Gafgyt_A");
	rc = gen(&E, dir, msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "<family>_<letters>") != NULL && count_files() == 0u);
	clean();

	/* A header with no format and no subtype writes none of those lines: only the name and the four. */
	draft();
	E.dr.fmt_mask = 0;
	E.dr.n_grp = 0;
	rc = gen(&E, dir, msg, sizeof msg);
	CK(rc == 2);
	keep = slurp("botnet_mirai_flood_01.c", &n);
	CK(keep && !strstr(keep, "KOF_TARGET_FORMAT") && strstr(keep, "KOF_DIAG_TYPE(KOF_MALTYPE_BOTNET);\n"));
	free(keep);

	clean();
	rmdir(dir);
	if (fails) {
		printf("diag_write: %d failure(s)\n", fails);
		return 1;
	}
	printf("diag_write: files written through diagsrc, refusals write nothing, nothing replaced - ok\n");
	return 0;
}
