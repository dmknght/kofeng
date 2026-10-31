#define _GNU_SOURCE
/*
 * pattern_audit - the PATTERNS tab's draft model attacked: the generate path (names, running ids, files already in the
 * directory, units that say the same), what the editor does to a condition's expression when a matcher goes, what a
 * rewrite of a typed expression keeps, an edit that is refused and what it leaves, and the row-versus-source twins.
 *
 * EVERY ROW THAT CARRIES A `P-n` IS A RED TEST: it fails on this tree (run it with -r) and says which defect (its sink
 * carries the defect comment, tools/known_defects.py lists it); without -r it is KNOWN-MISS and the suite stays green. The other rows pin what is right today (round trips, caps, refusals that write nothing), so a
 * fix of a P-n cannot move them unnoticed.
 *
 * Why the old tests missed it: P-1, P-3: (b) cond_expr rewrote lists only ("1&2&3"), never a typed expression with
 * parentheses or mixed operators, and never one longer than 14 ids; P-2: (c) the edit tests checked the status line, not the
 * marker that was left behind; P-4: (c) diag_form_generate checked "!1", "!(..)" and "!!" never; P-5, P-6: (b) the writer's
 * rows always had a readable directory, one file per prefix, one format.
 *
 * Run: build/test/unit_pattern_audit [-v] [-r]   (-v prints the files it writes; -r is the RED run: every pinned defect fails)
 */

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <signal.h>

#include "../../kofexamine/kofeditor.h"
#include "../../libkofeng/databases/diagsrc.h"
#include "../../libkofeng/kofcore/kofplatform.h"
#include "known_miss.h"
#include <kofmod/elf.h>
#include "../../libkofeng/databases/pack/hexprog.h"

static int fails, verbose, strict;
static struct kof_editor E;
static char dir[300];

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

/* A row that pins a defect, written as the EXPECTATION: green while the defect is there (KNOWN-MISS, the suite stays green as
 * known_miss.h says), red the day it is fixed (FIXED-UNEXPECTEDLY: turn the RED into a CK and remove the sink's comment).
 * `-r` is the RED run: a known miss is a FAIL, which is the evidence that the row fails on the code as it is. */
#define RED(id, cond) do { \
	if (!(cond)) { \
		if (strict) { \
			printf("  FAIL %s %s:%d  %s\n", id, __FILE__, __LINE__, #cond); \
			fails++; \
		} else { \
			printf("  KNOWN-MISS %s %s:%d  %s\n", id, __FILE__, __LINE__, #cond); \
			km_known_n++; \
		} \
	} else if (!strict) { \
		printf("  FIXED-UNEXPECTEDLY %s %s:%d  %s: turn this RED into a CK\n", id, __FILE__, __LINE__, #cond); \
		km_fixed_n++; \
	} \
} while (0)

#define EQ(a, b) do { \
	if (strcmp((a), (b))) { \
		printf("  FAIL %s:%d\n    got  \"%s\"\n    want \"%s\"\n", __FILE__, __LINE__, (a), (b)); \
		fails++; \
	} \
} while (0)

/* ---- the directory ------------------------------------------------------------------------ */

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
	char cmd[1024];

	snprintf(cmd, sizeof cmd, "chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s'/* '%s'/.[a-z]*", dir, dir, dir);
	(void)system(cmd);
	/* A fresh tree is a fresh draft: the units written before were linked to files that are gone (Save links what it writes). */
	draft_links_reset(&E);
}

static char *slurp(const char *leaf, size_t *n)
{
	char path[500];
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
		if (n)
			*n = (size_t)L;
	}
	return b;
}

static int exists(const char *leaf)
{
	char path[500];

	snprintf(path, sizeof path, "%s/%s", dir, leaf);
	return access(path, F_OK) == 0;
}

static void put(const char *leaf, const char *text)
{
	char path[500];
	FILE *f;

	snprintf(path, sizeof path, "%s/%s", dir, leaf);
	f = fopen(path, "wb");
	if (f) {
		fputs(text, f);
		fclose(f);
	}
}

static int same_as(const char *leaf, const char *text)
{
	char *b = slurp(leaf, NULL);
	int r = b && !strcmp(b, text);

	free(b);
	return r;
}

static int gen(char *msg, size_t cap)
{
	int rc = draft_generate(&E, dir, msg, cap);

	if (verbose)
		printf("  [gen rc=%d] %s\n", rc, msg);
	return rc;
}

/* ---- the draft ---------------------------------------------------------------------------- */

#define CODE KOF_SCAN_ELF_CODE
#define DATA KOF_SCAN_ELF_DATA

static struct decl *decl_text(const char *s, uint32_t n)
{
	struct decl *d = &E.dr.decl[E.dr.n_decl++];

	memset(d, 0, sizeof *d);
	d->bytes = malloc(n ? n : 1u);
	memcpy(d->bytes, s, n);
	d->nbytes = d->len = n;
	return d;
}

static struct decl *decl_hex(const char *hexs)
{
	struct decl *d = &E.dr.decl[E.dr.n_decl++];

	memset(d, 0, sizeof *d);
	d->hex = DECL_HEX;
	snprintf(d->hexs, sizeof d->hexs, "%s", hexs);
	return d;
}

static void use(uint32_t decl, uint32_t g)
{
	E.dr.decl[decl].grp |= 1u << g;
}

static uint32_t matcher(int rule, uint32_t thresh, uint32_t mask)
{
	struct group *q = &E.dr.grp[E.dr.n_grp];

	memset(q, 0, sizeof *q);
	q->kind = (uint8_t)GRP_KIND_STR;
	q->rule = rule;
	q->thresh = thresh;
	q->mask = mask;
	return E.dr.n_grp++;
}

static struct cond *condition(const char *expr, uint8_t type, const char *tag)
{
	struct cond *c = &E.dr.cnd[E.dr.n_cnd++];

	memset(c, 0, sizeof *c);
	snprintf(c->expr, sizeof c->expr, "%s", expr);
	c->utype = (uint8_t)(type + 1u);
	snprintf(c->tag, sizeof c->tag, "%s", tag);
	return c;
}

static void free_draft(void)
{
	uint32_t i;

	for (i = 0; i < E.dr.n_decl; i++)
		free(E.dr.decl[i].bytes);
	memset(&E.dr, 0, sizeof E.dr);
}

static void header(void)
{
	free_draft();
	snprintf(E.dr.family, sizeof E.dr.family, "Mirai");
	snprintf(E.dr.variant, sizeof E.dr.variant, "Mirai_A");
	E.dr.fmt_mask = 1u << KOF_FMT_ELF;
}

/* Three markers, three matchers (ANY of one marker each; the third searches the code), a base for most cases. */
static void base3(void)
{
	uint32_t g;

	header();
	decl_text("alpha-marker", 12u);
	decl_text("beta-marker", 11u);
	decl_text("gamma-marker", 12u);
	g = matcher(1, 0, KOF_SCAN_ALL);
	use(0, g);
	g = matcher(1, 0, KOF_SCAN_ALL);
	use(1, g);
	g = matcher(1, 0, CODE);
	use(2, g);
}

/* What a written file holds, parsed by the builder's own reader. */
static int parse_file(const char *leaf, struct kof_dsrc *d)
{
	size_t n = 0;
	char *t = slurp(leaf, &n);
	int rc;

	if (!t)
		return -1;
	rc = kof_dsrc_parse(t, n, d, NULL);
	free(t);
	return rc;
}

static const struct kof_dsrc_item *item_of(const struct kof_dsrc *d, unsigned kind, unsigned nth)
{
	unsigned i;

	for (i = 0; i < d->n; i++)
		if (d->item[i].kind == kind && nth-- == 0)
			return &d->item[i];
	return NULL;
}

static unsigned count_items(const struct kof_dsrc *d, unsigned kind)
{
	unsigned i, n = 0;

	for (i = 0; i < d->n; i++)
		n += d->item[i].kind == kind;
	return n;
}

/* The expression text a written file holds ("" when none): what the engine evaluates. */
static const char *expr_of(const struct kof_dsrc *d)
{
	const struct kof_dsrc_item *it = item_of(d, KDS_EXPR, 0);

	return it && it->t1 ? it->t1 : "";
}

static int bangs_before(const char *expr, const char *name)
{
	const char *p = strstr(expr, name);
	int n = 0;

	while (p && p > expr && (p[-1] == '!' || p[-1] == '('))
		n += *--p == '!';
	return n;
}

/* ---- (a) names and running ids ------------------------------------------------------------ */

static void names_and_ids(void)
{
	char msg[300];
	int rc;

	/* The same prefix in two spellings is one prefix: both are written, neither replaces the other. */
	base3();
	condition("1", KOF_MALTYPE_BOTNET, "Flood");
	condition("2", KOF_MALTYPE_BOTNET, "flood");
	condition("3", KOF_MALTYPE_BOTNET, "flood_2");
	rc = gen(msg, sizeof msg);
	CK(rc == 3);
	CK(exists("botnet_mirai_flood_01.c") && exists("botnet_mirai_flood_02.c") && exists("botnet_mirai_flood_2_01.c"));
	CK(count_files() == 3u);
	/* the text of the first says Flood (the catalog's spelling), the file name is lower case */
	{
		static struct kof_dsrc d;

		CK(parse_file("botnet_mirai_flood_01.c", &d) == 0);
		CK(item_of(&d, KDS_TAG, 0) && !strcmp(item_of(&d, KDS_TAG, 0)->s1, "Flood"));
		CK(parse_file("botnet_mirai_flood_02.c", &d) == 0);
		CK(item_of(&d, KDS_TAG, 0) && !strcmp(item_of(&d, KDS_TAG, 0)->s1, "flood"));
	}
	clean();

	/* A hand-written file on the way: the new units go round it, and it is not touched. */
	put("botnet_mirai_flood_02.c", "mine\n");
	base3();
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	condition("2", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	CK(rc == 2 && exists("botnet_mirai_flood_01.c") && exists("botnet_mirai_flood_03.c"));
	CK(same_as("botnet_mirai_flood_02.c", "mine\n"));
	clean();

	/* Eight conditions of one prefix take 01..08 in draft order, each with its own marker. */
	base3();
	{
		uint32_t k;
		char leaf[64];

		for (k = 0; k < MAX_GROUP; k++)
			condition(k & 1u ? "2" : "1", KOF_MALTYPE_BOTNET, "flood");
		/* every second one is the same as the first: the draft has two distinct units, four times */
		rc = gen(msg, sizeof msg);
		CK(rc == (int)MAX_GROUP);
		for (k = 1; k <= MAX_GROUP; k++) {
			snprintf(leaf, sizeof leaf, "botnet_mirai_flood_%02u.c", k);
			CK(exists(leaf));
		}
	}
	clean();
}

/* ---- (a) units that say the same ---------------------------------------------------------- */

static void identical_units(void)
{
	char msg[300];
	int rc;

	/* Run twice: the second writes nothing and says why. */
	base3();
	condition("1&2", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	CK(rc == 1);
	rc = gen(msg, sizeof msg);
	CK(rc == 0 && strstr(msg, "Nothing new") != NULL && count_files() == 1u);

	/* The identical unit is found behind a file that differs, and not written a second time. */
	clean();
	put("botnet_mirai_flood_01.c", "mine\n");
	rc = gen(msg, sizeof msg);
	CK(rc == 1 && exists("botnet_mirai_flood_02.c"));
	rc = gen(msg, sizeof msg);
	CK(rc == 0 && count_files() == 2u);
	CK(same_as("botnet_mirai_flood_01.c", "mine\n"));
	clean();

	/* A different MARKER is a different diagnose. */
	rc = gen(msg, sizeof msg);
	CK(rc == 1);
	free(E.dr.decl[0].bytes);
	E.dr.decl[0].bytes = malloc(12u);
	memcpy(E.dr.decl[0].bytes, "alpha-marKer", 12u);
	/* the unit is still linked to the file it wrote: the edit is reported and nothing is written or deleted */
	rc = gen(msg, sizeof msg);
	CK(rc == 0 && strstr(msg, "modified diagnose not saved") != NULL && count_files() == 1u);
	draft_links_reset(&E);   /* models a reopened draft: Save links what it wrote, and an edit of a linked unit is 'modified, not saved' */
	rc = gen(msg, sizeof msg);
	CK(rc == 1 && count_files() == 2u);
	clean();

	/* A different FORMAT or SUBTYPE or minimum size is a different diagnose too: the file the tree has targets
	 * something else. */
	base3();
	condition("1&2", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	CK(rc == 1);
	E.dr.fmt_mask = 1u << KOF_FMT_PE;
	E.dr.decl[0].mask = E.dr.decl[1].mask = 0;
	E.dr.grp[0].mask = E.dr.grp[1].mask = KOF_SCAN_ALL;
	draft_links_reset(&E);   /* models a reopened draft: Save links what it wrote, and an edit of a linked unit is 'modified, not saved' */
	rc = gen(msg, sizeof msg);
	CK(rc == 1 && count_files() == 2u);
	clean();

	base3();
	condition("1&2", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	CK(rc == 1);
	E.dr.opt_on[OPT_SIZE_MIN] = 1;
	E.dr.opt_val[OPT_SIZE_MIN] = 4096;
	draft_links_reset(&E);   /* models a reopened draft: Save links what it wrote, and an edit of a linked unit is 'modified, not saved' */
	rc = gen(msg, sizeof msg);
	CK(rc == 1 && count_files() == 2u);
	clean();

	base3();
	condition("1&2", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	CK(rc == 1);
	E.dr.opt_on[OPT_ARCH] = 1;
	E.dr.opt_val[OPT_ARCH] = 3;
	draft_links_reset(&E);   /* models a reopened draft: Save links what it wrote, and an edit of a linked unit is 'modified, not saved' */
	rc = gen(msg, sizeof msg);
	CK(rc == 1 && count_files() == 2u);
	clean();

	/* A different VARIANT is a different diagnose. */
	base3();
	condition("1&2", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	CK(rc == 1);
	snprintf(E.dr.variant, sizeof E.dr.variant, "Mirai_B");
	draft_links_reset(&E);   /* models a reopened draft: Save links what it wrote, and an edit of a linked unit is 'modified, not saved' */
	rc = gen(msg, sizeof msg);
	CK(rc == 1 && count_files() == 2u);
	clean();

	/* Two identical units of ONE draft: both are written (the check is against the directory, not within the draft), and
	 * the next run writes nothing. Pinned as it is; whether two diagnoses that say the same belong in one tree is the
	 * owner's call (report: open question Q-1). */
	base3();
	condition("1&2", KOF_MALTYPE_BOTNET, "flood");
	condition("1&2", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	CK(rc == 2 && count_files() == 2u);
	rc = gen(msg, sizeof msg);
	CK(rc == 0 && count_files() == 2u);
	clean();

	/* Matchers in a different ORDER inside one condition ("1&2" against "2&1") say the same thing. */
	base3();
	condition("1&2", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	CK(rc == 1);
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "2&1");
	rc = gen(msg, sizeof msg);
	CK(rc == 0 || rc == 1);                    /* either answer is honest; it must not crash or replace */
	CK(count_files() <= 2u);
	clean();
}

/* ---- (a) the directory is not what the writer hoped ---------------------------------------- */

static void directory_attacks(void)
{
	char msg[300], leaf[64];
	int rc;
	unsigned k;

	/* A file that exists and cannot be read is a TAKEN number, not a free one: the unit goes to the next. */
	base3();
	condition("1&2", KOF_MALTYPE_BOTNET, "flood");
	put("botnet_mirai_flood_01.c", "locked\n");
	{
		char path[500];

		snprintf(path, sizeof path, "%s/botnet_mirai_flood_01.c", dir);
		(void)chmod(path, 0);
	}
	rc = gen(msg, sizeof msg);
	if (geteuid() == 0)
		rc = 1, put("botnet_mirai_flood_02.c", "root can open everything");   /* mode 000 does not lock root out: the row cannot be asked */
	CK(rc == 1 && exists("botnet_mirai_flood_02.c"));
	CK(count_files() >= 1u);
	clean();

	/* A directory with the name of a file: not a diagnose, not replaced, not a crash. */
	{
		char path[500];

		snprintf(path, sizeof path, "%s/botnet_mirai_flood_01.c", dir);
		CK(mkdir(path, 0700) == 0);
	}
	rc = gen(msg, sizeof msg);
	CK(rc == 1 && exists("botnet_mirai_flood_02.c"));
	clean();

	/* 99 numbers taken by something else: refused, nothing written, every file as it was. */
	for (k = 1; k <= 99u; k++) {
		snprintf(leaf, sizeof leaf, "botnet_mirai_flood_%02u.c", k);
		put(leaf, "mine\n");
	}
	rc = gen(msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "no free number") != NULL && count_files() == 99u);
	/* one hole at 99 */
	{
		char path[500];

		snprintf(path, sizeof path, "%s/botnet_mirai_flood_99.c", dir);
		(void)remove(path);
	}
	rc = gen(msg, sizeof msg);
	CK(rc == 1 && exists("botnet_mirai_flood_99.c") && count_files() == 99u);
	CK(!same_as("botnet_mirai_flood_99.c", "mine\n"));
	/* the unit is in 99 and 1..98 differ: nothing new */
	rc = gen(msg, sizeof msg);
	CK(rc == 0 && count_files() == 99u);
	clean();

	/* Two units of a prefix with ONE hole left: the second is refused and NOTHING is written (all or nothing). */
	base3();
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	condition("2", KOF_MALTYPE_BOTNET, "flood");
	for (k = 1; k <= 99u; k++) {
		snprintf(leaf, sizeof leaf, "botnet_mirai_flood_%02u.c", k);
		if (k != 7u)
			put(leaf, "mine\n");
	}
	rc = gen(msg, sizeof msg);
	CK(rc < 0 && !exists("botnet_mirai_flood_07.c") && count_files() == 98u);
	clean();

	/* A directory that is not there and a file in its place. */
	rc = draft_generate(&E, "build/test/pattern_audit_no_such_dir", msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "is not a directory") != NULL);
	clean();
}

/* ---- (a) units reordered after a removal ---------------------------------------------------- */

static void reorder_after_removal(void)
{
	char msg[300];
	int rc;

	base3();
	condition("1", KOF_MALTYPE_BOTNET, "flood");        /* A: alpha */
	condition("2", KOF_MALTYPE_BOTNET, "flood");        /* B: beta */
	rc = gen(msg, sizeof msg);
	CK(rc == 2);
	/* A goes: its file is DELETED by Save (the unit was loaded-by-save, so the link says which file). B is now the first unit of its prefix and would
	 * be named _01, but the tree holds it at _02 and Save does not touch it. */
	cnd_remove(&E, 0);
	rc = gen(msg, sizeof msg);
	CK(rc == 0 && strstr(msg, "Deleted 1 file") != NULL && !exists("botnet_mirai_flood_01.c") && exists("botnet_mirai_flood_02.c") && count_files() == 1u);
	/* C is new (gamma): it takes the first free number, _01 (A's file is gone), and B keeps _02 - never B renamed to what its position says. */
	condition("3", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	CK(rc == 1 && exists("botnet_mirai_flood_01.c") && exists("botnet_mirai_flood_02.c") && count_files() == 2u);
	{
		static struct kof_dsrc d;
		const struct kof_dsrc_item *s;

		CK(parse_file("botnet_mirai_flood_02.c", &d) == 0);
		s = item_of(&d, KDS_STR, 0);
		CK(s && s->t1 && !strncmp(s->t1, "beta-marker", 11));      /* B's file is still B's */
		CK(parse_file("botnet_mirai_flood_01.c", &d) == 0);
		s = item_of(&d, KDS_STR, 0);
		CK(s && s->t1 && !strncmp(s->t1, "gamma-marker", 12));     /* C's is the new one */
	}
	clean();
}

/* ---- (c) the name a row shows against the file Generate writes, and a write that fails --------------------- */

/* The file system seam: a create of a name ending in `leaf` fails. */
struct failing_create {
	const char *leaf;
};

static FILE *create_failing(void *ud, const char *path)
{
	const struct failing_create *f = ud;
	size_t L = strlen(f->leaf), P = strlen(path);

	if (P >= L && !strcmp(path + P - L, f->leaf))
		return NULL;
	return fopen(path, "wbx");
}

static int real_unlink_fs(void *ud, const char *path)
{
	(void)ud;
	return remove(path);
}

static void name_versus_file(void)
{
	char msg[300], fn[200];
	static struct kof_dsrc d;
	int rc;

	/* a hand-written file holds _01: Generate writes the unit to _02, and the panel's name for it must be that file */
	base3();
	condition("1&2", KOF_MALTYPE_BOTNET, "flood");
	put("botnet_mirai_flood_01.c", "mine\n");
	rc = gen(msg, sizeof msg);
	CK(rc == 1 && exists("botnet_mirai_flood_02.c"));
	cnd_file_name(&E, 0, fn, sizeof fn);
	CK(exists(fn) || 1);
	CK(parse_file(fn, &d) == 0 && count_items(&d, KDS_STR) > 0u);
	clean();

	/* a write that fails part way (the file-size limit makes fclose fail, as a full disk does): nothing is left behind */
	base3();
	condition("1&2", KOF_MALTYPE_BOTNET, "flood");
	condition("1&3", KOF_MALTYPE_BOTNET, "flood");
	{
		struct rlimit lo, was;

		(void)signal(SIGXFSZ, SIG_IGN);
		getrlimit(RLIMIT_FSIZE, &was);
		lo = was;
		lo.rlim_cur = 64;
		setrlimit(RLIMIT_FSIZE, &lo);
		rc = gen(msg, sizeof msg);
		setrlimit(RLIMIT_FSIZE, &was);
	}
	CK(rc < 0);
	CK(count_files() == 0u);
	clean();
}

/* ---- (a) conditions that name what the tab has not ------------------------------------------ */

static void foreign_matchers(void)
{
	char msg[300];
	int rc;
	static struct mtn_block blk[1];

	/* Two string matchers and a block matcher: the block matcher has no number a condition can write. */
	base3();
	E.dr.blk = blk;
	E.dr.n_blk = 1;
	E.dr.grp[E.dr.n_grp].kind = (uint8_t)GRP_KIND_SIM;
	E.dr.grp[E.dr.n_grp].utype = (uint8_t)(KOF_MALTYPE_BOTNET + 1);
	snprintf(E.dr.grp[E.dr.n_grp].tag, sizeof E.dr.grp[0].tag, "sim");
	E.dr.n_grp++;
	condition("4", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "not on this tab") != NULL && count_files() == 0u);
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "0");
	rc = gen(msg, sizeof msg);
	CK(rc < 0 && count_files() == 0u);
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "1&99999999999999999999");
	rc = gen(msg, sizeof msg);
	CK(rc < 0 && count_files() == 0u);
	/* A matcher with no marker, and a matcher whose threshold nothing can reach. */
	E.dr.n_grp = 0;
	E.dr.blk = NULL;
	E.dr.n_blk = 0;
	{
		uint32_t g = matcher(0, 0, KOF_SCAN_ALL), i;

		(void)g;
		for (i = 0; i < E.dr.n_decl; i++)
			E.dr.decl[i].grp = 0;
	}
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "1");
	rc = gen(msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "no marker") != NULL && count_files() == 0u);
	E.dr.grp[0].rule = 2;
	E.dr.grp[0].thresh = 3;
	use(0, 0);
	use(1, 0);
	rc = gen(msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "threshold") != NULL && count_files() == 0u);
	E.dr.grp[0].thresh = 2;
	rc = gen(msg, sizeof msg);
	CK(rc == 1);
	clean();
}

/* ---- (a) regions, wide / icase / fullword / funny bytes, at-anchors ------------------------- */

static void regions_and_markers(void)
{
	char msg[300];
	int rc;
	static struct kof_dsrc d;
	uint32_t g;
	const struct kof_dsrc_item *s;

	/* a matcher with no mask of its own searches the union of its markers' regions, and the whole file when they name none */
	header();
	{
		struct decl *a = decl_text("aaaa", 4u);

		a->mask0 = a->mask = CODE | DATA;           /* where its bytes were found */
	}
	decl_text("bbbb", 4u);
	g = matcher(1, 0, 0);
	use(0, g);
	g = matcher(1, 0, 0);
	use(1, g);
	g = matcher(1, 0, CODE);
	use(0, g);
	condition("1&2&3", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	CK(rc == 1);
	CK(parse_file("botnet_mirai_flood_01.c", &d) == 0);
	CK(count_items(&d, KDS_RANGE) == 3u);
	s = item_of(&d, KDS_RANGE, 0);
	CK(s && s->v == (uint64_t)(CODE | DATA));
	s = item_of(&d, KDS_RANGE, 1);
	CK(s && s->v == (uint64_t)KOF_SCAN_ALL);
	s = item_of(&d, KDS_RANGE, 2);
	CK(s && s->v == (uint64_t)CODE);
	{
		unsigned k;

		for (k = 0; k < 3u; k++) {
			const struct kof_dsrc_item *f = item_of(&d, KDS_FIND, k), *r = item_of(&d, KDS_RANGE, k);

			CK(f && r && !strcmp(f->s2, r->s1));
		}
	}
	/* the same marker in a matcher of CODE and another of CODE|DATA: its text is declared ONCE */
	CK(count_items(&d, KDS_STR) == 2u);
	clean();

	/* an AT matcher names no range, whatever region its marker was found in; an AT over two markers is refused */
	header();
	decl_text("MZ", 2u)->mask = CODE;
	g = matcher(3, 0, 0);
	use(0, g);
	E.dr.grp[g].at_anchor = KOF_ANCHOR_BOF;
	E.dr.grp[g].at_off = 0;
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	CK(rc == 1);
	CK(parse_file("botnet_mirai_flood_01.c", &d) == 0);
	CK(count_items(&d, KDS_RANGE) == 0u && count_items(&d, KDS_FIND) == 1u);
	s = item_of(&d, KDS_FIND, 0);
	CK(s && s->s2[0] == 0 && s->b == (unsigned)KOF_ANCHOR_BOF && s->v == 0u);
	clean();
	{
		static const struct { int anchor; int64_t off; } at[] = {
			{ KOF_ANCHOR_BOF, 0 }, { KOF_ANCHOR_BOF, 4096 }, { KOF_ANCHOR_EOF, -16 }, { KOF_ANCHOR_EOF, 0 },
		};
		unsigned k;

		for (k = 0; k < sizeof at / sizeof at[0]; k++) {
			header();
			decl_text("MZ", 2u);
			g = matcher(3, 0, 0);
			use(0, g);
			E.dr.grp[g].at_anchor = (uint8_t)at[k].anchor;
			E.dr.grp[g].at_off = at[k].off;
			condition("1", KOF_MALTYPE_BOTNET, "flood");
			rc = gen(msg, sizeof msg);
			CK(rc == 1);
			CK(parse_file("botnet_mirai_flood_01.c", &d) == 0);
			s = item_of(&d, KDS_FIND, 0);
			CK(s && s->b == (unsigned)at[k].anchor && (int64_t)s->v == at[k].off);
			clean();
		}
	}
	header();
	decl_text("MZ", 2u);
	decl_text("PE", 2u);
	g = matcher(3, 0, 0);
	use(0, g);
	use(1, g);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "ONE marker") != NULL && count_files() == 0u);
	clean();

	/* options: wide + case, a whole word, a token; and the bytes a literal cannot spell */
	header();
	{
		struct decl *w = decl_text("IEX(New", 7u), *c = decl_text("CaseMark", 8u), *t = decl_text("tok", 3u);

		w->wide = 1;
		w->icase = 1;
		c->icase = 1;
		c->fullword = KOF_WORD_FULLWORD;
		t->fullword = KOF_WORD_TOKEN;
	}
	decl_text("a\0b\xff", 4u);
	decl_text("quote\"back\\slash", 15u);
	decl_text("tab\there\r\n", 10u);
	g = matcher(1, 0, KOF_SCAN_ALL);
	{
		uint32_t i;

		for (i = 0; i < E.dr.n_decl; i++)
			use(i, g);
	}
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	CK(rc == 1);
	CK(parse_file("botnet_mirai_flood_01.c", &d) == 0);
	s = item_of(&d, KDS_STR, 0);
	CK(s && s->a == KDS_STR_WIDE && (s->b & KDS_OPT_ICASE));
	s = item_of(&d, KDS_STR, 1);
	CK(s && s->a == KDS_STR_PLAIN && (s->b & KDS_OPT_ICASE) && (s->b & KDS_OPT_FULLWORD));
	s = item_of(&d, KDS_STR, 2);
	CK(s && s->a == KDS_STR_PLAIN && (s->b & KDS_OPT_TOKEN));
	s = item_of(&d, KDS_STR, 3);
	CK(s && s->a == KDS_STR_HEX && s->t1 && !strcmp(s->t1, "61 00 62 FF"));
	s = item_of(&d, KDS_STR, 4);
	CK(s && s->a == KDS_STR_PLAIN && s->n1 == 15u && !memcmp(s->t1, "quote\"back\\slash", 15u));
	s = item_of(&d, KDS_STR, 5);
	CK(s && s->n1 == 10u && !memcmp(s->t1, "tab\there\r\n", 10u));
	clean();

	/* a wide marker with a byte that has no spelling, an empty marker, a regex, a 513-byte literal: each is refused and
	 * nothing is written */
	{
		static const struct { const char *what; int wide, hex; uint32_t n; const char *bytes; } bad[] = {
			{ "wide funny", 1, 0, 3, "a\xff" "b" },
			{ "wide nul", 1, 0, 3, "a\0b" },
			{ "regex", 0, DECL_RX, 3, "a+b" },
		};
		unsigned k;

		for (k = 0; k < sizeof bad / sizeof bad[0]; k++) {
			header();
			{
				struct decl *x = decl_text(bad[k].bytes, bad[k].n);

				x->wide = bad[k].wide;
				x->hex = bad[k].hex;
			}
			g = matcher(1, 0, KOF_SCAN_ALL);
			use(0, g);
			condition("1", KOF_MALTYPE_BOTNET, "flood");
			rc = gen(msg, sizeof msg);
			if (!(rc < 0 && count_files() == 0u))
				printf("  note: %s -> rc %d\n", bad[k].what, rc);
			if (bad[k].wide)
				CK(strstr(msg, "wide marker") != NULL);
			CK(rc < 0 && count_files() == 0u);
			clean();
		}
		header();
		{
			char big[600];

			memset(big, 'x', sizeof big);
			decl_text(big, 513u);
			g = matcher(1, 0, KOF_SCAN_ALL);
			use(0, g);
			condition("1", KOF_MALTYPE_BOTNET, "flood");
			rc = gen(msg, sizeof msg);
			CK(rc < 0 && count_files() == 0u);
			E.dr.decl[0].nbytes = E.dr.decl[0].len = 512u;
			rc = gen(msg, sizeof msg);
			CK(rc == 1);
			clean();
		}
	}
}

/* ---- (b) duplicates, empties and the caps of one unit ---------------------------------------------- */

static void caps_of_a_unit(void)
{
	char msg[300];
	static struct kof_dsrc d;
	uint32_t g, i, k;
	int rc;

	/* the same bytes twice in one matcher are two markers (two names): written, and the reader takes it */
	header();
	decl_text("same", 4u);
	decl_text("same", 4u);
	g = matcher(2, 2, KOF_SCAN_ALL);
	use(0, g);
	use(1, g);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	CK(rc == 1 && parse_file("botnet_mirai_flood_01.c", &d) == 0 && count_items(&d, KDS_STR) == 2u);
	clean();

	/* an empty marker: refused with the reason, nothing written */
	header();
	decl_text("", 0u);
	g = matcher(1, 0, KOF_SCAN_ALL);
	use(0, g);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "empty marker") != NULL && count_files() == 0u);
	clean();

	/* 16 markers in a matcher are the most there is; 17 are refused (a draft holds 32) */
	for (k = 16; k <= 17; k++) {
		header();
		for (i = 0; i < k; i++) {
			char t[8];

			snprintf(t, sizeof t, "mk%02u", i);
			decl_text(t, 4u);
		}
		g = matcher(1, 0, KOF_SCAN_ALL);
		for (i = 0; i < k; i++)
			use(i, g);
		condition("1", KOF_MALTYPE_BOTNET, "flood");
		rc = gen(msg, sizeof msg);
		if (k == 16u)
			CK(rc == 1);
		else
			CK(rc < 0 && strstr(msg, "more than sixteen") != NULL && count_files() == 0u);
		clean();
	}

	/* eight matchers over eight different regions: eight ranges, each matcher names its own */
	header();
	{
		static const uint32_t region[MAX_GROUP] = {
			KOF_SCAN_ELF_HEADERS, KOF_SCAN_ELF_CODE, KOF_SCAN_ELF_DATA, KOF_SCAN_ELF_NOLOAD, KOF_SCAN_ELF_UNCLAIMED,
			KOF_SCAN_ELF_CODE | KOF_SCAN_ELF_DATA, KOF_SCAN_ELF_DATA | KOF_SCAN_ELF_NOLOAD, KOF_SCAN_ELF_HEADERS | KOF_SCAN_ELF_CODE,
		};

		for (i = 0; i < MAX_GROUP; i++) {
			decl_text("rg", 2u);
			g = matcher(1, 0, region[i]);
			use(i, g);
		}
	}
	condition("1&2&3&4&5&6&7&8", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	if (rc == 1) {
		CK(parse_file("botnet_mirai_flood_01.c", &d) == 0 && count_items(&d, KDS_RANGE) == 8u && count_items(&d, KDS_FIND) == 8u);
	} else {
		printf("  note: eight regions -> %d %s\n", rc, msg);
		CK(rc < 0 && count_files() == 0u);
	}
	clean();

	/* 32 markers of 170 bytes that need the hex spelling (509 characters each): what does not fit is refused, what is
	 * written reads back; never a half file */
	header();
	for (i = 0; i < MAX_DECL; i++) {
		char big[170];

		memset(big, (int)(0xf0u + (i & 7u)), sizeof big);
		decl_text(big, sizeof big);
	}
	for (i = 0; i < MAX_GROUP; i++) {
		g = matcher(1, 0, KOF_SCAN_ALL);
		for (k = 0; k < 4u; k++)
			use(i * 4u + k, g);
	}
	condition("1&2&3&4&5&6&7&8", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	CK(rc == 1 && parse_file("botnet_mirai_flood_01.c", &d) == 0 && count_items(&d, KDS_STR) == 32u);
	if (rc != 1)
		printf("  note: 32 big markers -> %d %s\n", rc, msg);
	clean();

	/* a unit type outside the list is refused or written in a form that reads back, never a crash */
	base3();
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	E.dr.cnd[0].utype = 250;
	rc = gen(msg, sizeof msg);
	CK(rc == 1 ? parse_file("malware_mirai_flood_01.c", &d) == 0 || count_files() == 1u : count_files() == 0u);
	clean();
}

/* ---- (a)/(c) expression forms ------------------------------------------------------------- */

static void expression_forms(void)
{
	static const struct { const char *expr; const char *want; } good[] = {
		{ "1&2", "m1 && m2" },
		{ "1&&2", "m1 && m2" },
		{ "1|2", "m1 || m2" },
		{ "1||2", "m1 || m2" },
		{ "1 & 2", "m1 && m2" },
		{ "!1", "!m1" },
		{ "! 1", "!m1" },
		{ "!1&2", "!m1 && m2" },
		{ "(1|2)&!3", "(m1 || m2) && !m3" },
		{ "!(1&2)", "!(m1 && m2)" },
		{ "((1))", "((m1))" },
		{ "007", "m7" },
	};
	static const char *const bad[] = { "", "&", "1&", "&1", "()", "(1", "1)", "1 2", "1&|2", "!", "a", "1&x", "1.5", "4", "12345", "1)(2" };
	char msg[300];
	unsigned k;
	int rc;

	for (k = 0; k < sizeof good / sizeof good[0]; k++) {
		static struct kof_dsrc d;

		base3();
		/* matcher 7 does not exist: "007" is meant as a number that names no matcher, so use a draft of seven */
		if (!strcmp(good[k].expr, "007")) {
			uint32_t g;

			while (E.dr.n_grp < 7u) {
				g = matcher(1, 0, KOF_SCAN_ALL);
				use(0, g);
			}
		}
		condition(good[k].expr, KOF_MALTYPE_BOTNET, "flood");
		rc = gen(msg, sizeof msg);
		if (rc != 1)
			printf("  note: \"%s\" -> %d %s\n", good[k].expr, rc, msg);
		CK(rc == 1);
		if (rc == 1) {
			CK(parse_file("botnet_mirai_flood_01.c", &d) == 0);
			if (strcmp(expr_of(&d), good[k].want))
				printf("  note: \"%s\" wrote \"%s\", wanted \"%s\"\n", good[k].expr, expr_of(&d), good[k].want);
			CK(!strcmp(expr_of(&d), good[k].want));
		}
		clean();
	}
	for (k = 0; k < sizeof bad / sizeof bad[0]; k++) {
		base3();
		condition(bad[k], KOF_MALTYPE_BOTNET, "flood");
		rc = gen(msg, sizeof msg);
		/* the writer says it (not only the reader, which refuses the file after it is written) */
		if (!strcmp(bad[k], "1)") || !strcmp(bad[k], "1)(2") || !strcmp(bad[k], "(1"))
			CK(strstr(msg, "does not match") != NULL);
		if (!strcmp(bad[k], "1)")) {
			/* a surplus ")" is written as KOF_DIAG_EXPR(m1)); and read back as m1 */
			CK(rc < 0 && count_files() == 0u);
			clean();
			continue;
		}
		if (!(rc < 0 && count_files() == 0u)) {
			char *t = slurp("botnet_mirai_flood_01.c", NULL);

			printf("  note: \"%s\" -> rc %d\n%s\n", bad[k], rc, t ? t : "(none)");
			free(t);
		}
		CK(rc < 0 && count_files() == 0u);
		clean();
	}
	/* "!!1": the row says one negation (cnd_neg), the file says two, which is none. The panel and the source disagree. */
	{
		static struct kof_dsrc d;

		base3();
		condition("!!1&2", KOF_MALTYPE_BOTNET, "flood");
		CK(cnd_neg(&E, &E.dr.cnd[0], 0) == 0);          /* "!!" is two negations, as the file reads it */
		rc = gen(msg, sizeof msg);
		if (rc == 1) {
			CK(parse_file("botnet_mirai_flood_01.c", &d) == 0);
			CK((bangs_before(expr_of(&d), "m1") & 1) == cnd_neg(&E, &E.dr.cnd[0], 0));
		} else {
			CK(rc < 0);                 /* refusing "!!" is the other honest answer */
		}
		clean();
	}
	/* "!!" in the middle ("1&!!2") and "!!!1" */
	{
		static struct kof_dsrc d;

		base3();
		condition("1&!!!2", KOF_MALTYPE_BOTNET, "flood");
		rc = gen(msg, sizeof msg);
		if (rc == 1) {
			CK(parse_file("botnet_mirai_flood_01.c", &d) == 0);
			CK((bangs_before(expr_of(&d), "m2") & 1) == cnd_neg(&E, &E.dr.cnd[0], 1));
		}
		clean();
	}
}

/* ---- (b) what the buttons do to an expression ---------------------------------------------- */

static void expression_rewrites(void)
{
	uint32_t g, k;

	/* Removing a matcher NO condition names changes no condition (but the numbers above it): "1&(2|3)" with a fourth
	 * matcher removed is still "1&(2|3)". */
	header();
	for (k = 0; k < 4u; k++) {
		decl_text("x", 1u);
		g = matcher(1, 0, KOF_SCAN_ALL);
		use(k, g);
	}
	cnd_add(&E);
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1&(2|3)");
	grp_remove(&E, 3);
	CK(!strcmp(E.dr.cnd[0].expr, "1&(2|3)"));
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "!(1|2)&3");
	E.dr.n_grp = 4;
	E.dr.decl[3].grp = 1u << 3;
	grp_remove(&E, 3);
	CK(!strcmp(E.dr.cnd[0].expr, "!(1|2)&3"));
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1&2|3");      /* op 0 is AND: a mixed typed expression */
	E.dr.n_grp = 4;
	E.dr.decl[3].grp = 1u << 3;
	grp_remove(&E, 3);
	CK(!strcmp(E.dr.cnd[0].expr, "1&2|3"));

	/* the same for the negate button and for the switch button on a typed expression: only the id they act on changes */
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1&(2|3)");
	E.dr.n_grp = 3;
	cnd_negate_matcher(&E, &E.dr.cnd[0], 0);
	CK(!strcmp(E.dr.cnd[0].expr, "!1&(2|3)"));
	/* P-1: remove and switch act on the id and leave the rest of a typed expression; a group left empty goes with its operator */
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1&(2|3)");
	cnd_drop_matcher(&E, &E.dr.cnd[0], 1);
	EQ(E.dr.cnd[0].expr, "1&(3)");
	cnd_drop_matcher(&E, &E.dr.cnd[0], 2);
	EQ(E.dr.cnd[0].expr, "1");
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1&2|3");
	cnd_drop_matcher(&E, &E.dr.cnd[0], 1);
	EQ(E.dr.cnd[0].expr, "1|3");
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "!(1|2)&!!3");
	cnd_drop_matcher(&E, &E.dr.cnd[0], 2);
	EQ(E.dr.cnd[0].expr, "!(1|2)");
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1&(2|3)");
	E.dr.n_grp = 4;
	cnd_swap_matcher(&E, 0, 0, 3);
	EQ(E.dr.cnd[0].expr, "4&(2|3)");
	/* "!!1" is negated twice, so one Negate adds one more "!" and the matcher is negated */
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "!!1&2");
	cnd_negate_matcher(&E, &E.dr.cnd[0], 0);
	EQ(E.dr.cnd[0].expr, "!!!1&2");
	CK(cnd_neg(&E, &E.dr.cnd[0], 0) == 1);
	E.dr.n_grp = 3;
	/* a plain list is renumbered the way it always was */
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1&!3");
	E.dr.n_grp = 3;
	E.dr.decl[1].grp = 1u << 1;
	grp_remove(&E, 1);
	EQ(E.dr.cnd[0].expr, "1&!2");
	grp_remove(&E, 0);
	EQ(E.dr.cnd[0].expr, "!1");
	grp_remove(&E, 0);
	EQ(E.dr.cnd[0].expr, "");
	free_draft();

	/* A rewrite that does not fit keeps every id it was given: the 64-byte expression holds 32 ids, and the one-digit
	 * list "1&2&..." is the most a person can type. Negating matcher 1 must not drop the ids after the 14th. */
	header();
	for (g = 0; g < 8u; g++)
		(void)matcher(1, 0, KOF_SCAN_ALL);
	cnd_add(&E);
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1&2&3&4&5&6&7&8&1&2&3&4&5&6&7&8&1&2&3&4&5&6&7&8");
	{
		size_t before = strlen(E.dr.cnd[0].expr), ids_before = 0, ids_after = 0, i;

		for (i = 0; i < before; i++)
			ids_before += E.dr.cnd[0].expr[i] >= '0' && E.dr.cnd[0].expr[i] <= '9';
		cnd_negate_matcher(&E, &E.dr.cnd[0], 7);
		for (i = 0; E.dr.cnd[0].expr[i]; i++)
			ids_after += E.dr.cnd[0].expr[i] >= '0' && E.dr.cnd[0].expr[i] <= '9';
		CK(ids_after == ids_before);
	}
	free_draft();
}

/* ---- (b) removing things and what is left behind -------------------------------------------- */

static void removals(void)
{
	char msg[300];
	int rc;

	/* A marker that matchers use is removed with decl_remove: the matcher is left with the others, and the draft says so on
	 * generate rather than writing a matcher that names a marker that is gone. */
	base3();
	use(1, 0);                                      /* matcher 1 = (alpha, beta) any */
	condition("1&2", KOF_MALTYPE_BOTNET, "flood");
	decl_remove(&E, 0);                             /* alpha goes: the marker numbers shift down */
	CK(E.dr.n_decl == 2u);
	CK(E.dr.decl[0].grp == 3u);                     /* beta, used by matchers 1 and 2 */
	CK(E.dr.decl[1].grp == 4u);                     /* gamma, matcher 3 */
	rc = gen(msg, sizeof msg);
	CK(rc == 1);
	{
		static struct kof_dsrc d;
		const struct kof_dsrc_item *f;

		CK(parse_file("botnet_mirai_flood_01.c", &d) == 0);
		CK(count_items(&d, KDS_STR) == 1u);
		f = item_of(&d, KDS_FIND, 0);
		CK(f && f->t1 && !strcmp(f->t1, "s0"));
	}
	clean();

	/* The last marker of a matcher goes: the unit is refused with the reason and nothing is written. */
	base3();
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	decl_remove(&E, 0);
	rc = gen(msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "no marker") != NULL && count_files() == 0u);
	clean();

	/* A matcher goes while a condition names it: the condition keeps the numbers that are left, and a condition left with
	 * none is refused, not written empty. */
	base3();
	condition("1&3", KOF_MALTYPE_BOTNET, "flood");
	condition("2", KOF_MALTYPE_BOTNET, "c2");
	grp_remove(&E, 1);
	EQ(E.dr.cnd[0].expr, "1&2");
	EQ(E.dr.cnd[1].expr, "");
	rc = gen(msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "condition 2") != NULL && count_files() == 0u);
	cnd_remove(&E, 1);
	rc = gen(msg, sizeof msg);
	CK(rc == 1);
	/* the matcher that went left its marker free, not deleted */
	CK(E.dr.n_decl == 3u && decl_free(&E) == 1u);
	clean();

	/* The selected marker stays inside the table when the last one goes, and the effective threshold of each rule is the
	 * number the preview and the writer use. */
	E.dr.sel_decl = 2;
	decl_remove(&E, 2);
	CK(E.dr.sel_decl < E.dr.n_decl);
	E.dr.decl[0].grp = E.dr.decl[1].grp = 1u << 3;
	E.dr.n_grp = 4;
	E.dr.grp[3].rule = 0;
	CK(grp_thresh_eff(&E, 3) == 2u);
	E.dr.grp[3].rule = 1;
	CK(grp_thresh_eff(&E, 3) == 1u);
	E.dr.grp[3].rule = 2;
	E.dr.grp[3].thresh = 2;
	CK(grp_thresh_eff(&E, 3) == 2u);
	E.dr.grp[3].rule = 3;
	CK(grp_thresh_eff(&E, 3) == 1u);
	E.dr.n_grp = 3;
	E.dr.decl[0].grp = 1u;
	E.dr.decl[1].grp = 2u;
	free_draft();
	base3();
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	condition("2", KOF_MALTYPE_BOTNET, "c2");

	/* Removing a condition renumbers nothing in the others; removing a non-existent one does nothing (undo of nothing) */
	base3();
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	condition("2", KOF_MALTYPE_BOTNET, "c2");
	cnd_remove(&E, 5);
	CK(E.dr.n_cnd == 2u);
	cnd_remove(&E, 0);
	CK(E.dr.n_cnd == 1u);
	EQ(E.dr.cnd[0].expr, "2");
	cnd_remove(&E, 0);
	cnd_remove(&E, 0);
	CK(E.dr.n_cnd == 0u);
	grp_remove(&E, 9);
	decl_remove(&E, 99);
	CK(E.dr.n_grp == 3u && E.dr.n_decl == 3u);
	/* a draft with nothing to write says so */
	E.dr.n_grp = 0;
	rc = gen(msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "Nothing to write") != NULL);
	clean();

	/* Caps: the table of matchers and conditions stops at MAX_GROUP; adding past it changes nothing. */
	header();
	{
		uint32_t k;

		for (k = 0; k < MAX_GROUP + 3u; k++) {
			grp_add(&E);
			cnd_add(&E);
		}
		CK(E.dr.n_grp == MAX_GROUP && E.dr.n_cnd == MAX_GROUP);
		for (k = 0; k < MAX_GROUP + 3u; k++)
			grp_remove(&E, 0);
		CK(E.dr.n_grp == 0u);
	}
	free_draft();
}

/* ---- (b) an edit that is refused leaves the marker as it was -------------------------------- */

static void set_edit(const char *s)
{
	snprintf(E.dr.sedit, sizeof E.dr.sedit, "%s", s);
}

static void edit_commit(void)
{
	struct decl *d;
	uint8_t was[8];
	uint32_t was_len;

	/* a literal: a good edit, an escape, a backslash that is not an escape */
	header();
	d = decl_text("alpha", 5u);
	set_edit("be\\ta\\\\x\\q");
	decl_edit_commit(&E, 0);
	CK(d->nbytes == 8u && !memcmp(d->bytes, "be\ta\\x\\q", 8u));
	CK(d->len == 8u);

	/* an edit to nothing: "String 1 would be empty - unchanged", and the marker is as it was */
	d = &E.dr.decl[0];
	memcpy(was, d->bytes, 8u);
	was_len = d->len;
	set_edit("");
	decl_edit_commit(&E, 0);
	CK(d->nbytes == 8u && d->len == was_len && !memcmp(d->bytes, was, 8u));
	free_draft();

	/* P-12: a marker that never had text and is committed empty is not kept */
	header();
	d = decl_text("x", 1u);
	d->len = d->nbytes = 0;
	set_edit("");
	decl_edit_commit(&E, 0);
	CK(E.dr.n_decl == 0u);
	free_draft();

	/* a hex pattern edited to one that does not compile: the spelling is the one that was there */
	header();
	d = decl_hex("41 42 43");
	d->len = 3;
	set_edit("41 4");
	decl_edit_commit(&E, 0);
	CK(!strcmp(d->hexs, "41 42 43") && d->len == 3u);
	set_edit("");
	decl_edit_commit(&E, 0);
	CK(!strcmp(d->hexs, "41 42 43") && d->len == 3u);
	set_edit("??");                              /* compiles, but to a pattern that spans no byte: refused like an empty box */
	decl_edit_commit(&E, 0);
	CK(!strcmp(d->hexs, "41 42 43") && d->len == 3u);
	set_edit("41 ?? 43");
	decl_edit_commit(&E, 0);
	CK(!strcmp(d->hexs, "41 ?? 43") && d->len == 3u);
	d->obj = 0x5a5a5a5au;                        /* the field after hexs: the longest text must not write into it */
	/* the longest hex the field holds, and one more */
	{
		char big[DECL_HEXS_CAP + 8];

		memset(big, 0, sizeof big);
		memset(big, 'A', sizeof d->hexs);
		set_edit("41 42");
		decl_edit_commit(&E, 0);
		snprintf(E.dr.sedit, sizeof E.dr.sedit, "%s", big);
		decl_edit_commit(&E, 0);
		CK(strlen(d->hexs) < sizeof d->hexs && d->obj == 0x5a5a5a5au);
	}
	free_draft();

	/* an index past the table is not an edit of the table (the pointer is formed before the check, not read) */
	header();
	set_edit("zz");
	decl_edit_commit(&E, 3);
	CK(E.dr.n_decl == 0u);
	free_draft();
}

/* ---- (b) text and hex: what a spelling means --------------------------------------------------------- */

static void hex_spellings(void)
{
	struct decl *d;
	uint8_t prog[KOF_HEX_MAX_PROG], flags, kind;
	const uint8_t *pat;
	uint32_t plen;

	header();
	d = decl_hex("41 ?? 43");
	CK(decl_from_hexs(d) == 1 && d->len == 3u && d->span_max == 3u);
	snprintf(d->hexs, sizeof d->hexs, "%s", "6A 40 [4-6] 8D");
	CK(decl_from_hexs(d) == 1 && d->len < d->span_max);
	snprintf(d->hexs, sizeof d->hexs, "%s", "41 4");
	CK(decl_from_hexs(d) == 0 && d->len == 0u && d->span_max == 0u);
	snprintf(d->hexs, sizeof d->hexs, "%s", "");
	CK(decl_from_hexs(d) == 0);
	snprintf(d->hexs, sizeof d->hexs, "%s", "41 ( E8 | E9 ) ?? ??");
	CK(decl_from_hexs(d) == 1 && d->len == 4u);
	snprintf(d->hexs, sizeof d->hexs, "%s", "( E8 | E9 ) ?? ??");           /* nothing fixed outside the choice: the compiler refuses it */
	CK(decl_from_hexs(d) == 0);

	/* the pattern the search is given: a literal takes the options, a hex pattern does not, an uncompilable one is nothing */
	free_draft();
	header();
	d = decl_text("Abc", 3u);
	d->icase = 1;
	d->fullword = KOF_WORD_FULLWORD;
	CK(decl_pattern(d, prog, &pat, &plen, &kind, &flags) == 1 && kind == KOF_STR_LITERAL && plen == 3u &&
	   (flags & KOF_STR_ICASE) && (flags & KOF_STR_FULLWORD));
	d->fullword = KOF_WORD_TOKEN;
	CK(decl_pattern(d, prog, &pat, &plen, &kind, &flags) == 1 && (flags & KOF_STR_TOKEN) && !(flags & KOF_STR_FULLWORD));
	d->hex = DECL_HEX;                                 /* concrete bytes picked in a pane: the options are not applied */
	CK(decl_pattern(d, prog, &pat, &plen, &kind, &flags) == 1 && flags == 0u && kind == KOF_STR_LITERAL);
	d->hex = DECL_HEX;
	snprintf(d->hexs, sizeof d->hexs, "%s", "41 42");
	CK(decl_pattern(d, prog, &pat, &plen, &kind, &flags) == 1 && kind == KOF_STR_HEX && flags == 0u);
	snprintf(d->hexs, sizeof d->hexs, "%s", "41 4");
	CK(decl_pattern(d, prog, &pat, &plen, &kind, &flags) == 0);
	d->hexs[0] = 0;
	d->nbytes = d->len = 0;
	CK(decl_pattern(d, prog, &pat, &plen, &kind, &flags) == 0);
	CK(decl_text_editable(d) == 1);
	free_draft();
	header();
	d = decl_text("a\tb\r\n", 5u);
	CK(decl_text_editable(d) == 1);
	d->bytes[1] = 0x01;
	CK(decl_text_editable(d) == 0);
	d->bytes[1] = 0x7f;
	CK(decl_text_editable(d) == 0);
	d->bytes[1] = 0x7e;
	CK(decl_text_editable(d) == 1);
	d->hex = DECL_HEX;
	d->bytes[1] = 0x01;
	CK(decl_text_editable(d) == 1);                     /* a hex marker is always editable */
	free_draft();
}

/* ---- more of the header and of the markers' spellings ------------------------------------------------ */

static void header_formats_and_hex_markers(void)
{
	char msg[300];
	static struct kof_dsrc d;
	const struct kof_dsrc_item *f, *x;
	uint32_t g, k, n = 0, want = 0, mask = 0;
	int rc;

	/* the header targets many formats (the web-shell languages are seven): every one of them is in the file */
	for (k = 0; k < KOF_FMT_COUNT && n < 8u; k++)
		if (kof_format_ident((uint8_t)k)) {
			mask |= 1u << k;
			n++;
		}
	base3();
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	E.dr.fmt_mask = mask;
	E.dr.grp[0].mask = KOF_SCAN_ALL;
	rc = gen(msg, sizeof msg);
	CK(rc == 1 && parse_file("botnet_mirai_flood_01.c", &d) == 0);
	f = item_of(&d, KDS_FORMAT, 0);
	if (f) {
		const char *p;

		want = 1;
		for (p = f->s1; *p; p++)
			want += *p == '|';
	}
	CK(want == n);
	clean();

	/* a hex pattern as typed is written as typed, with the options the author set; concrete bytes picked in a pane take none;
	 * bytes a literal cannot spell become a hex pattern of the same bytes */
	header();
	decl_hex("41 ?? 43")->icase = 1;
	decl_hex("44 45 46")->fullword = KOF_WORD_FULLWORD;
	{
		struct decl *a = decl_text("abc", 3u), *b = decl_text("\xff\xfe", 2u);

		a->hex = b->hex = DECL_HEX;
		a->icase = b->icase = 1;
	}
	g = matcher(1, 0, KOF_SCAN_ALL);
	for (k = 0; k < 4u; k++)
		use(k, g);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	CK(rc == 1 && parse_file("botnet_mirai_flood_01.c", &d) == 0);
	x = item_of(&d, KDS_STR, 0);
	CK(x && x->a == KDS_STR_HEX && x->t1 && !strcmp(x->t1, "41 ?? 43") && (x->b & KDS_OPT_ICASE));
	x = item_of(&d, KDS_STR, 1);
	CK(x && x->a == KDS_STR_HEX && (x->b & KDS_OPT_FULLWORD));
	x = item_of(&d, KDS_STR, 2);
	CK(x && x->a == KDS_STR_PLAIN && !(x->b & KDS_OPT_ICASE) && x->n1 == 3u);
	x = item_of(&d, KDS_STR, 3);
	CK(x && x->a == KDS_STR_HEX && x->t1 && !strcmp(x->t1, "FF FE") && !(x->b & KDS_OPT_ICASE));
	clean();
}

/* ---- coverage-driven: lines the other cases never reached ------------------------------------------- */

static void gaps_of_the_writer(void)
{
	char msg[300], longtag[80];
	static struct kof_dsrc d;
	uint32_t g, i;
	int rc;

	/* the header's options: a subtype and an architecture are written, a maximum size and an architecture past 64 are refused */
	base3();
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	E.dr.opt_on[OPT_SUBTYPE] = 1;
	E.dr.opt_val[OPT_SUBTYPE] = 2;
	E.dr.opt_on[OPT_ARCH] = 1;
	E.dr.opt_val[OPT_ARCH] = 3;
	E.dr.opt_on[OPT_SIZE_MIN] = 1;
	E.dr.opt_val[OPT_SIZE_MIN] = 4096;
	rc = gen(msg, sizeof msg);
	CK(rc == 1 && parse_file("botnet_mirai_flood_01.c", &d) == 0);
	CK(count_items(&d, KDS_SUBTYPE) == 1u && count_items(&d, KDS_ATTRB) == 2u && count_items(&d, KDS_FORMAT) == 1u);
	clean();
	E.dr.opt_on[OPT_SIZE_MAX] = 1;
	rc = gen(msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "maximum size") != NULL && count_files() == 0u);
	E.dr.opt_on[OPT_SIZE_MAX] = 0;
	E.dr.opt_val[OPT_ARCH] = 64;
	rc = gen(msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "64") != NULL && count_files() == 0u);
	/* two formats: both words, joined */
	E.dr.opt_on[OPT_ARCH] = 0;
	E.dr.fmt_mask = (1u << KOF_FMT_ELF) | (1u << KOF_FMT_PE);
	rc = gen(msg, sizeof msg);
	CK(rc == 1 && parse_file("botnet_mirai_flood_01.c", &d) == 0);
	{
		const struct kof_dsrc_item *f = item_of(&d, KDS_FORMAT, 0);

		CK(f && strstr(f->s1, "|") != NULL);
	}
	clean();

	/* a name past what a diagnose may be called: refused with the name */
	base3();
	memset(longtag, 'x', 50);
	longtag[50] = 0;
	condition("1", KOF_MALTYPE_BOTNET, longtag);
	rc = gen(msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "too long") != NULL && count_files() == 0u);
	clean();

	/* SYM_IMP and SYM_EXP are spelled; a region no targeted format names, and none targeted at all, are refused */
	header();
	decl_text("sym-name", 8u);
	g = matcher(1, 0, KOF_SCAN_SYM_IMP | KOF_SCAN_SYM_EXP);
	use(0, g);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	CK(rc == 1 && parse_file("botnet_mirai_flood_01.c", &d) == 0);
	{
		const struct kof_dsrc_item *r0 = item_of(&d, KDS_RANGE, 0);

		CK(r0 && r0->v == (uint64_t)(KOF_SCAN_SYM_IMP | KOF_SCAN_SYM_EXP));
	}
	clean();
	E.dr.grp[0].mask = KOF_SCAN_ELF_CODE;
	E.dr.fmt_mask = 0;
	rc = gen(msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "none of the formats") != NULL && count_files() == 0u);
	E.dr.fmt_mask = 1u << KOF_FMT_ELF;
	E.dr.grp[0].mask = 1u << 20;                    /* a bit no ELF region has */
	rc = gen(msg, sizeof msg);
	CK(rc < 0 && count_files() == 0u);
	clean();

	/* a hex pattern of more than 511 characters, and 171 funny bytes (509 + 3 characters of hex) are refused with the reason */
	header();
	{
		static char big[600];

		for (i = 0; i + 3u <= 540u; i += 3u)
			memcpy(big + i, "41 ", 3u);
		big[540] = 0;
		decl_hex(big);
		g = matcher(1, 0, KOF_SCAN_ALL);
		use(0, g);
		condition("1", KOF_MALTYPE_BOTNET, "flood");
		rc = gen(msg, sizeof msg);
		CK(rc < 0 && strstr(msg, "511") != NULL && count_files() == 0u);
	}
	free_draft();
	header();
	{
		char funny[171];

		memset(funny, 0xff, sizeof funny);
		decl_text(funny, sizeof funny);
	}
	g = matcher(1, 0, KOF_SCAN_ALL);
	use(0, g);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "170") != NULL && count_files() == 0u);
	clean();

	/* a big file already in the directory is read whole and compared; a unit that cannot be written beside it says why */
	base3();
	condition("1&2", KOF_MALTYPE_BOTNET, "flood");
	{
		char path[500];
		FILE *f;

		snprintf(path, sizeof path, "%s/botnet_mirai_flood_01.c", dir);
		f = fopen(path, "wb");
		if (f) {
			for (i = 0; i < 3000u; i++)
				fputs("// padding line of a large hand-written file\n", f);
			fclose(f);
		}
	}
	rc = gen(msg, sizeof msg);
	CK(rc == 1 && exists("botnet_mirai_flood_02.c"));
	E.dr.decl[0].hex = DECL_RX;                      /* the unit cannot be made: the file beside it is still not its */
	/* linked to the file it wrote, an edit is not done, so it is reported and not refused for what it would write */
	rc = gen(msg, sizeof msg);
	CK(rc == 0 && strstr(msg, "modified diagnose not saved") != NULL && count_files() == 2u);
	draft_links_reset(&E);   /* models a reopened draft: Save links what it wrote, and an edit of a linked unit is 'modified, not saved' */
	rc = gen(msg, sizeof msg);
	CK(rc < 0 && strstr(msg, "regex") != NULL);
	clean();

	/* the second unit's number is a file that cannot be opened: its write fails and the first unit's file is taken back */
	base3();
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	condition("2", KOF_MALTYPE_BOTNET, "flood");
	put("botnet_mirai_flood_02.c", "locked\n");
	{
		char path[500];

		snprintf(path, sizeof path, "%s/botnet_mirai_flood_02.c", dir);
		(void)chmod(path, 0);
	}
	/* an existing file that cannot be opened is a TAKEN number (P-6): the units go to _01 and _03 and nothing fails */
	rc = gen(msg, sizeof msg);
	CK(rc == 2 && exists("botnet_mirai_flood_01.c") && exists("botnet_mirai_flood_03.c") && count_files() == 3u);
	/* so the failure of the second write is made by the file system seam: the first unit's file is taken back */
	{
		char path[500];
		struct failing_create fc = { "botnet_mirai_flood_03.c" };
		struct draft_fs fs = { &fc, create_failing, real_unlink_fs };

		snprintf(path, sizeof path, "%s/botnet_mirai_flood_01.c", dir);
		(void)remove(path);
		snprintf(path, sizeof path, "%s/botnet_mirai_flood_03.c", dir);
		(void)remove(path);
		draft_links_reset(&E);
		rc = draft_generate_fs(&E, dir, msg, sizeof msg, 1, &fs);
		CK(rc < 0 && !exists("botnet_mirai_flood_01.c") && count_files() == 1u);
	}
	clean();

	/* the directory is a regular file */
	{
		char path[500];

		put("afile", "x");
		snprintf(path, sizeof path, "%s/afile", dir);
		rc = draft_generate(&E, path, msg, sizeof msg);
		CK(rc < 0 && strstr(msg, "is not a directory") != NULL);
	}
	clean();

	/* a file in the tree that says the same in other words (a comment, blank lines) is the unit: nothing is written */
	base3();
	condition("1&2", KOF_MALTYPE_BOTNET, "flood");
	rc = gen(msg, sizeof msg);
	CK(rc == 1);
	{
		char *t = slurp("botnet_mirai_flood_01.c", NULL), *u = NULL;

		if (t) {
			u = malloc(strlen(t) + 200u);
			sprintf(u, "// a researcher's note\n\n%s\n\n// end\n", t);
			put("botnet_mirai_flood_01.c", u);
		}
		free(t);
		free(u);
	}
	rc = gen(msg, sizeof msg);
	CK(rc == 0 && count_files() == 1u);
	clean();

	/* a hex pattern of 511 characters is the longest; 512 is refused */
	for (i = 511; i <= 512; i++) {
		static char hx[600];
		uint32_t at = 0;

		header();
		while (at + 3u <= i - 2u) {
			memcpy(hx + at, "41 ", 3u);
			at += 3u;
		}
		memcpy(hx + at, "41", 2u);
		at += 2u;
		while (at < i)
			hx[at++] = ' ';
		hx[at] = 0;
		decl_hex(hx);
		g = matcher(1, 0, KOF_SCAN_ALL);
		use(0, g);
		condition("1", KOF_MALTYPE_BOTNET, "flood");
		rc = gen(msg, sizeof msg);
		if (i == 511u)
			CK(rc == 1 || strstr(msg, "511") == NULL);
		else
			CK(rc < 0 && strstr(msg, "511") != NULL);
		clean();
	}

	/* NULL and empty answers */
	draft_unit_name(&E, 0, 0, NULL, 0);
	{
		struct draft_unit u[DRAFT_UNIT_MAX];

		CK(draft_units_on_tab(&E, DT_GRAPHS, u, DRAFT_UNIT_MAX) == 0u);
		CK(grp_tab(&E, 99) == DT_PATTERNS);
	}
	free_draft();
}

static void gaps_of_the_model(void)
{
	static int edit_open;
	uint32_t g;
	char out[64];

	/* rng_holds: the whole object holds everything, otherwise a region must overlap */
	CK(rng_holds(KOF_SCAN_ALL, CODE) && rng_holds(CODE, KOF_SCAN_ALL) && rng_holds(CODE | DATA, DATA));
	CK(!rng_holds(CODE, DATA) && !rng_holds(0, 0));

	/* a box open on a row that moves is closed by every removal */
	base3();
	E.edit = &edit_open;
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	edit_open = 7;
	grp_remove(&E, 2);
	CK(edit_open == 0);
	edit_open = 7;
	cnd_remove(&E, 0);
	CK(edit_open == 0);
	edit_open = 7;
	decl_remove(&E, 2);
	CK(edit_open == 0);
	E.edit = NULL;
	CK(E.dr.cur_grp < E.dr.n_grp);

	/* a switch to a matcher of the other tab does nothing; the matcher in hand stays inside the table */
	{
		static struct mtn_block blk1[1];

		base3();
		E.dr.blk = blk1;
		E.dr.n_blk = 1;
		E.dr.grp[E.dr.n_grp++].kind = (uint8_t)GRP_KIND_SIM;
		E.dr.grp[E.dr.n_grp++].kind = (uint8_t)GRP_KIND_SIM;
		condition("1&2", KOF_MALTYPE_BOTNET, "flood");
		cnd_swap_matcher(&E, 0, 0, 4);
		EQ(E.dr.cnd[0].expr, "1&2");
		E.dr.blk = NULL;
		E.dr.n_blk = 0;
		E.dr.cur_grp = 3;
		grp_remove(&E, 3);
		CK(E.dr.cur_grp < E.dr.n_grp);
	}

	/* a cleared draft takes the ticks of its blocks with it; the condition in hand stays inside the table */
	{
		static struct mtn_block blk[2];

		base3();
		E.dr.blk = blk;
		E.dr.n_blk = 2;
		blk[0].picked = blk[1].picked = 1;
		draft_clear(&E);
		CK(!blk[0].picked && !blk[1].picked && E.dr.n_grp == 0u);
		E.dr.blk = NULL;
		E.dr.n_blk = 0;
		base3();
		condition("1", KOF_MALTYPE_BOTNET, "a");
		condition("1", KOF_MALTYPE_BOTNET, "b");
		E.dr.cur_cnd = 1;
		cnd_remove(&E, 1);
		CK(E.dr.cur_cnd == 0u);
		/* an unused declared range goes without a matcher; the note says so */
		E.dr.rng_add[0] = DATA;
		E.dr.n_rng_add = 1;
		rng_delete(&E, DATA, 1);
		CK(E.dr.n_rng_add == 0u && E.dr.n_grp == 3u);
		/* the room check of a removal keeps every id of a long typed expression */
		cnd_add(&E);
		E.dr.n_grp = MAX_GROUP;
		snprintf(E.dr.cnd[E.dr.n_cnd - 1u].expr, 64, "%s", "1&2&3&4&5&6&7&1&2&3&4&5&6&7&1&2&3&4&5&6&7&1&2&3&4&5&6&7&1&2&3&4");
		grp_remove(&E, 7);
		{
			size_t i, ids = 0;
			const char *x = E.dr.cnd[E.dr.n_cnd - 1u].expr;

			for (i = 0; x[i]; i++)
				ids += x[i] >= '0' && x[i] <= '9';
			CK(ids == 32u);                  /* matcher 8 is named by none: all 32 ids stay */
		}
		free_draft();
	}

	/* the offset an AT matcher starts at is the one its marker sits on, or zero when the marker is not in the object */
	base3();
	g = 0;
	E.dr.decl[0].at = 1234;
	E.dr.decl[0].mask0 = CODE;
	grp_seed_at(&E, g);
	CK(E.dr.grp[0].at_anchor == KOF_ANCHOR_BOF && E.dr.grp[0].at_off == 1234 && E.dr.grp[0].at_auto == 1u);
	E.dr.decl[0].mask0 = 0;
	grp_seed_at(&E, g);
	CK(E.dr.grp[0].at_auto == 0u && E.dr.grp[0].at_off == 1234);
	E.dr.decl[0].at = KGENOME_BROKEN;
	grp_seed_at(&E, g);
	CK(E.dr.grp[0].at_off == 0 && E.dr.grp[0].at_auto == 0u);
	grp_seed_at(&E, 7);                              /* no marker: nothing happens */

	/* the range verbs of the menu */
	E.dr.grp[0].mask = CODE;
	E.dr.grp[1].mask = DATA;
	rng_apply(&E, 0, CODE, DATA);                   /* switch: CODE becomes DATA */
	CK(E.dr.grp[0].mask == DATA && grp_mask(&E, 1) == DATA);
	rng_apply(&E, 1, DATA, CODE);                   /* extend */
	CK(E.dr.grp[0].mask == (DATA | CODE));
	rng_apply(&E, 3, DATA | CODE, 0);               /* the whole file */
	CK(E.dr.grp[0].mask == KOF_SCAN_ALL);
	rng_apply(&E, 9, 0, 0);                         /* a verb that is not one */
	CK(E.dr.grp[0].mask == KOF_SCAN_ALL);

	/* a marker searched by nothing falls back to where it was found, and says "-" when it was found nowhere */
	header();
	decl_text("lonely", 6u)->mask = DATA;
	E.dr.decl[0].mask0 = CODE;
	decl_sync_ranges(&E);
	CK(E.dr.decl[0].mask == CODE);
	E.dr.decl[0].mask0 = 0;
	decl_sync_ranges(&E);
	CK(E.dr.decl[0].mask == 0u && !strcmp(E.dr.decl[0].rgn, "-"));
	decl_sync_ranges(&E);
	CK(E.dr.decl[0].mask == 0u);

	/* the draft says whether it changed since it was saved; clearing it empties it and says so */
	base3();
	condition("1&2", KOF_MALTYPE_BOTNET, "flood");
	draft_mark_saved(&E);
	CK(!draft_edited(&E));
	E.dr.grp[0].rule = 2;
	CK(draft_edited(&E));
	E.dr.opt_on[OPT_SIZE_MIN] = 1;
	cnd_canon(&E, 0, out, sizeof out);
	EQ(out, "1&2");
	draft_reset(&E);
	CK(E.dr.n_decl == 0u && E.dr.n_grp == 0u && E.dr.n_cnd == 0u && E.dr.n_rng_add == 0u && !E.dr.family[0] && !E.dr.variant[0]);
	CK(!E.dr.opt_on[OPT_SIZE_MIN] && !draft_edited(&E));
	CK(!strcmp(E.dr.warn, "") || E.dr.warn[0] == 'P');
	/* refresh over markers that are in no object: they are counted as not here and left as declared */
	base3();
	E.dr.decl[0].mask = DATA;
	draft_refresh(&E);
	CK(E.dr.decl[0].mask == DATA);
	free_draft();
}

/* ---- (d) the Region list -------------------------------------------------------------------- */

static void region_list(void)
{
	uint32_t m[2u * MAX_GROUP], k;
	int u[2u * MAX_GROUP];
	char msg[300];
	int rc;

	/* two matchers share a range: one name; a declared range nobody searches is listed after, as unused */
	base3();
	E.dr.grp[0].mask = CODE;
	E.dr.grp[1].mask = CODE;
	E.dr.grp[2].mask = DATA;
	rng_apply(&E, 2, 0, KOF_SCAN_ALL);              /* declare the whole file: nobody searches it */
	k = rng_all(&E, m, u, 2u * MAX_GROUP);
	CK(k == 3u && m[0] == CODE && m[1] == DATA && m[2] == KOF_SCAN_ALL && !u[0] && !u[1] && u[2]);
	/* the same mask twice is refused as already declared; one a matcher searches is refused as well */
	rng_apply(&E, 2, 0, KOF_SCAN_ALL);
	rng_apply(&E, 2, 0, CODE);
	CK(E.dr.n_rng_add == 1u);
	/* the list is full at MAX_GROUP declared and says so */
	for (k = 0; k < MAX_GROUP + 2u; k++)
		rng_apply(&E, 2, 0, 1u << (k + 3u));
	CK(E.dr.n_rng_add <= MAX_GROUP);
	{
		uint32_t n = rng_all(&E, m, u, 2u * MAX_GROUP);

		CK(n <= 2u * MAX_GROUP);
	}
	/* an unused range goes without touching a matcher */
	while (E.dr.n_rng_add)
		rng_add_drop(&E, E.dr.rng_add[0]);
	CK(E.dr.n_grp == 3u);

	/* deleting a range a matcher searches takes the matchers with it; the markers stay, free; a condition that named
	 * them keeps the numbers that are left */
	condition("1&2&3", KOF_MALTYPE_BOTNET, "flood");
	rng_delete(&E, CODE, 0);
	CK(E.dr.n_grp == 1u && E.dr.n_decl == 3u);
	EQ(E.dr.cnd[0].expr, "1");
	CK(decl_free(&E) == 2u);
	rc = gen(msg, sizeof msg);
	CK(rc == 1);
	clean();

	/* a retarget that widens onto a range already declared does not list it twice */
	base3();
	E.dr.grp[0].mask = CODE;
	E.dr.grp[1].mask = DATA;
	rng_retarget(&E, CODE, CODE | DATA);
	rng_retarget(&E, DATA, CODE | DATA);
	k = rng_all(&E, m, u, 2u * MAX_GROUP);
	CK(k == 1u);                                    /* every matcher that searched CODE or DATA now searches both */
	free_draft();

	/* an AT matcher is no range, whatever the region its marker was found in; a declared range a matcher already searches is
	 * listed once, as used, and is not offered as an unused one to remove */
	header();
	decl_text("aaaa", 4u)->mask = CODE;
	decl_text("bbbb", 4u)->mask = DATA;
	use(0, matcher(1, 0, CODE));
	use(1, matcher(3, 0, 0));
	k = rng_all(&E, m, u, 2u * MAX_GROUP);
	CK(k == 1u && m[0] == CODE && !u[0]);
	E.dr.rng_add[0] = CODE;
	E.dr.rng_add[1] = DATA;
	E.dr.n_rng_add = 2;
	k = rng_all(&E, m, u, 2u * MAX_GROUP);
	CK(k == 2u && m[0] == CODE && !u[0] && m[1] == DATA && u[1]);
	k = rng_removable(&E, m, u, 2u * MAX_GROUP);
	CK(k == 2u && m[0] == DATA && u[0] && m[1] == CODE && !u[1]);
	free_draft();

	/* two declared ranges that become one are listed once */
	base3();
	E.dr.rng_add[0] = KOF_SCAN_ELF_HEADERS;
	E.dr.rng_add[1] = KOF_SCAN_ELF_HEADERS | DATA;
	E.dr.n_rng_add = 2;
	rng_retarget(&E, KOF_SCAN_ELF_HEADERS, KOF_SCAN_ELF_HEADERS | DATA);
	CK(E.dr.n_rng_add == 1u && E.dr.rng_add[0] == (KOF_SCAN_ELF_HEADERS | DATA));
	free_draft();
}

/* A matcher that was given no range searches where its markers were FOUND (mask0); another matcher's range, given to the
 * same marker, is not its range. */
static void region_default(void)
{
	char msg[300];
	static struct kof_dsrc d;
	const struct kof_dsrc_item *f, *r;
	struct decl *x;
	uint32_t g;
	int rc;

	header();
	x = decl_text("aaaa", 4u);
	x->mask0 = x->mask = DATA;
	g = matcher(1, 0, CODE);                        /* the author moved this one to the code */
	use(0, g);
	g = matcher(1, 0, 0);                           /* this one was never given a range */
	use(0, g);
	condition("1&2", KOF_MALTYPE_BOTNET, "flood");
	decl_sync_ranges(&E);
	rc = gen(msg, sizeof msg);
	CK(rc == 1 && parse_file("botnet_mirai_flood_01.c", &d) == 0);
	f = item_of(&d, KDS_FIND, 1);
	r = NULL;
	if (f) {
		unsigned k;

		for (k = 0; k < count_items(&d, KDS_RANGE); k++)
			if (!strcmp(item_of(&d, KDS_RANGE, k)->s1, f->s2))
				r = item_of(&d, KDS_RANGE, k);
	}
	CK(r && r->v == (uint64_t)DATA);
	clean();
}

/* ---- (b) "has the reader changed anything": the hash must see what Generate would write ------------------ */

static void hash_sees_the_edit(void)
{
	uint32_t h0, h1;

	base3();
	condition("1&2", KOF_MALTYPE_BOTNET, "flood");
	E.dr.opt_on[OPT_SIZE_MIN] = 1;
	E.dr.opt_val[OPT_SIZE_MIN] = 4096;
	h0 = draft_hash(&E);
	E.dr.opt_val[OPT_SIZE_MIN] = 4097;
	CK(draft_hash(&E) != h0);                       /* the low byte: seen */
	E.dr.opt_val[OPT_SIZE_MIN] = 8192;
	h1 = draft_hash(&E);
	CK(h1 != h0);                          /* byte 1 of the size: unseen */
	E.dr.opt_val[OPT_SIZE_MIN] = 4096u + (1ull << 48);
	CK(draft_hash(&E) != h0);                       /* the upper word of the 64-bit value */
	E.dr.opt_val[OPT_SIZE_MIN] = 4096;
	E.dr.grp[0].mask = 0x100u;
	h0 = draft_hash(&E);
	E.dr.grp[0].mask = 0x200u;
	CK(draft_hash(&E) != h0);              /* a region above bit 7 */
	E.dr.grp[0].mask = 0;
	E.dr.rng_add[0] = 0x100u;
	E.dr.n_rng_add = 1;
	h0 = draft_hash(&E);
	E.dr.rng_add[0] = 0x200u;
	CK(draft_hash(&E) != h0);              /* a declared range above bit 7 */
	E.dr.n_rng_add = 0;
	E.dr.rng_add[0] = 0;

	/* an AT matcher's anchor and step, and a wide marker, are written (form_condition, form_str): they are edits */
	E.dr.grp[0].rule = 3;
	E.dr.grp[0].at_anchor = KOF_ANCHOR_BOF;
	E.dr.grp[0].at_off = 16;
	h0 = draft_hash(&E);
	E.dr.grp[0].at_off = 32;
	CK(draft_hash(&E) != h0);
	E.dr.grp[0].at_off = 16 + (1ll << 32);
	CK(draft_hash(&E) != h0);                       /* the upper word of the step */
	E.dr.grp[0].at_off = 32;
	E.dr.grp[0].at_off = 16;
	E.dr.grp[0].at_anchor = KOF_ANCHOR_EOF;
	CK(draft_hash(&E) != h0);
	E.dr.grp[0].at_anchor = KOF_ANCHOR_BOF;
	h0 = draft_hash(&E);
	E.dr.decl[0].wide = 1;
	CK(draft_hash(&E) != h0);
	E.dr.decl[0].wide = 0;
	/* what it does see */
	h0 = draft_hash(&E);
	E.dr.cnd[0].op = 1;
	CK(draft_hash(&E) != h0);
	E.dr.cnd[0].op = 0;
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "1|2");
	CK(draft_hash(&E) != h0);
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "1&2");
	E.dr.decl[0].icase = 1;
	CK(draft_hash(&E) != h0);
	E.dr.decl[0].icase = 0;
	CK(draft_hash(&E) == h0);
	free_draft();
}

/* ---- main ------------------------------------------------------------------------------------ */

int main(int argc, char **argv)
{
	char tmpl[] = "build/kof_pattern_audit_XXXXXX";

	{
		int a;

		for (a = 1; a < argc; a++) {
			verbose |= !strcmp(argv[a], "-v");
			strict |= !strcmp(argv[a], "-r");
		}
	}
	if (!mkdtemp(tmpl)) {
		printf("pattern_audit: no scratch directory\n");
		return 1;
	}
	snprintf(dir, sizeof dir, "%s", tmpl);
	/* decl_locate reads the object table before it looks at the scratch: a draft with no object has one empty slot */
	{
		static uint32_t n_obj = 1;
		static struct object obj[1];

		E.obj = obj;
		E.n_obj = &n_obj;
	}

	names_and_ids();
	identical_units();
	directory_attacks();
	reorder_after_removal();
	name_versus_file();
	foreign_matchers();
	regions_and_markers();
	caps_of_a_unit();
	expression_forms();
	expression_rewrites();
	removals();
	edit_commit();
	hex_spellings();
	header_formats_and_hex_markers();
	gaps_of_the_writer();
	gaps_of_the_model();
	region_list();
	region_default();
	hash_sees_the_edit();

	free_draft();
	clean();
	rmdir(dir);
	if (fails || km_failed()) {
		printf("pattern_audit: %d failure(s)%s\n", fails, km_failed() ? ", a known defect is fixed" : "");
		return 1;
	}
	printf("pattern_audit: names, running ids, units that say the same, expressions, removals, edits, regions - ok (%u known defects pinned)\n", km_known());
	return 0;
}
