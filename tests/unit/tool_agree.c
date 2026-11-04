/*
 * tool_agree - what the TOOLS say of an object is what the ENGINE answers for it (owner 2026-10-29: tests that catch a tool computing for itself what the
 * engine already answers).
 *
 * THE CLASS OF DEFECT. A tool may only show; the engine decides (kofeng/CLAUDE.md 2 and 11). Two real cases: the viewer composed "which child carries the file's
 * verdict" with a loop of its own and showed "no verdict X in child", and the examiner spelled a detection name with '-' after the engine moved to '#'. Both
 * looked right until the day the engine changed; no test compared the two. The old tests of the tools checked a string they had been given (t_detect.py greps for
 * "Infected#ELF-x64/Botnet:Mirai.A"), which is also what a hard-coded copy would print.
 *
 * HOW THIS CATCHES IT.
 *   DIFFERENTIAL  for each sample (run1: the Mirai build the product's diagnoses detect; a tar holding it, whose verdict is in a child; a clean system binary; a
 *                 PE) the engine is asked through the pull API (kscan_path, kdet_info, kdet_diag, kverdict_filemap_*) and kofscanner -v and kofexaminer are run on the
 *                 same path. What the engine answers is written here as the lines each tool must print, and every line is looked for in the tool's output; and the
 *                 tool must print nothing the engine did not say (the number of verdict lines, of diagnose lines and the three counts of the summary).
 *   MUTATED DATA  the same samples against three databases built from the sources under tests/agree: the family, variant letter, tag, type and diagnose names are
 *                 others (Zorg / C / Zorg-wave / Trojan), and the diagnose list is six, three and zero matches. A tool that hard-codes a name, recomputes the
 *                 letter or counts for itself does not follow. The old names (Mirai, Botnet) must not appear in what the tool prints for those databases.
 *   --truth       prints the engine's answer in one canonical text (tests/tui/t_agree.py compares the viewer's screen with it): `tool_agree --truth <db> <bases> <path>`.
 *
 * A tool that is not built, a database that is not built, a sample that is not there: reported by name and a non-zero exit, never a silent pass; the one sample
 * allowed to be absent is run1 (it lives outside the tree), and then the samples made of it are not run and the output says so.
 *
 * usage: tool_agree                (the differential; needs make, make test-sigs and make fixtures)
 *        tool_agree --truth <db> <bases> <path>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "form_pack.h"
#include "../../libkofeng/kofeng.h"

static int failures;
#define CK(cond, ...) do { if (!(cond)) { printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); failures++; } } while (0)

#define MAXOBJ 64u
#define MAXDIAG 16u

struct tdiag {
	char name[128], family[KDET_TEXT_MAX], variant[KDET_TEXT_MAX], tag[KDET_TEXT_MAX];
	int type;
};

struct tobj {
	char name[512];
	int has_verdict, level;
	char verdict[256];
	uint32_t cover, jaccard, groups, fired, n_diag, diag_total;
	struct tdiag diag[MAXDIAG];
	int broken;
};

struct truth {
	struct tobj obj[MAXOBJ];
	unsigned n;
	int rc;
	uint64_t files;                 /* kverdict_filemap_files */
	unsigned infected_files;        /* files with a verdict in their tree */
	char file_verdict[256];         /* the verdict of the root file: kverdict_filemap */
	char file_obj[512];             /* the object that carries it */
	int file_has_verdict;
};

static kof_engine *T_eng;
static kverdict_filemap *T_map;

static int collect(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct truth *t = user;
	struct tobj *o;
	struct kdet_info in;
	uint32_t i;

	(void)bytes; (void)len;
	kverdict_filemap_fold(T_map, name, res, 1);
	if (t->n >= MAXOBJ)
		return 0;
	o = &t->obj[t->n++];
	snprintf(o->name, sizeof o->name, "%s", name);
	o->broken = (int)res->broken;
	kdet_info(T_eng, res, &in);
	o->has_verdict = in.has_verdict;
	if (!in.has_verdict)
		return 0;
	snprintf(o->verdict, sizeof o->verdict, "%s", in.verdict);
	o->level = in.level;
	o->cover = in.cover;
	o->jaccard = in.jaccard;
	o->groups = in.groups;
	o->fired = in.fired;
	o->n_diag = in.n_diag;
	o->diag_total = in.diag_total;
	for (i = 0; i < in.n_diag && i < MAXDIAG; i++) {
		struct kdet_diag d;

		if (!kdet_diag(T_eng, res, i, &d))
			continue;
		snprintf(o->diag[i].name, sizeof o->diag[i].name, "%s", d.name ? d.name : "");
		snprintf(o->diag[i].family, sizeof o->diag[i].family, "%s", d.family);
		snprintf(o->diag[i].variant, sizeof o->diag[i].variant, "%s", d.variant);
		snprintf(o->diag[i].tag, sizeof o->diag[i].tag, "%s", d.tag);
		o->diag[i].type = d.type;
	}
	return 0;
}

/* The engine's answer for `path`, asked the way a host asks: the pull API only. */
static int ask_engine(const char *db, const char *bases, const char *path, struct truth *t)
{
	kof_scanner *sc;
	struct kof_scan_option opt;
	const struct kverdict_file *f;
	size_t i;

	memset(t, 0, sizeof *t);
	T_eng = keng_open(db);
	if (!T_eng) {
		printf("  cannot open the database %s\n", db);
		return 0;
	}
	(void)keng_catalog_load_bases(T_eng, bases);
	sc = kscan_new(T_eng);
	T_map = kverdict_filemap_new();
	memset(&opt, 0, sizeof opt);
	opt.recurse_dirs = 1;
	t->rc = kscan_path(sc, path, &opt, collect, t);
	t->files = kverdict_filemap_files(T_map);
	for (i = 0; i < kverdict_filemap_count(T_map); i++) {
		f = kverdict_filemap_at(T_map, i);
		if (f->has_verdict) {
			t->infected_files++;
			if (!t->file_has_verdict) {
				t->file_has_verdict = 1;
				snprintf(t->file_verdict, sizeof t->file_verdict, "%s", f->name);
			}
		}
	}
	if (t->file_has_verdict) {
		unsigned k;

		for (k = 0; k < t->n; k++)
			if (t->obj[k].has_verdict) {
				snprintf(t->file_obj, sizeof t->file_obj, "%s", t->obj[k].name);
				break;
			}
	}
	kverdict_filemap_free(T_map);
	kscan_free(sc);
	return 1;
}

static void close_engine(void)
{
	keng_close(T_eng);
	T_eng = NULL;
}

/* ---- the canonical text of the engine's answer (--truth) -------------------------------------------------- */

static void print_truth(const struct truth *t)
{
	unsigned i, j;

	printf("objects %u\nfiles %llu\ninfected_files %u\n", t->n, (unsigned long long)t->files, t->infected_files);
	if (t->file_has_verdict)
		printf("file_verdict %s\nfile_object %s\n", t->file_verdict, t->file_obj);
	for (i = 0; i < t->n; i++) {
		const struct tobj *o = &t->obj[i];

		printf("object %s\n", o->name);
		if (!o->has_verdict)
			continue;
		printf("verdict %s\nbasis level=%d cover=%u jaccard=%u groups=%u matched=%u\nndiag %u\n", o->verdict, o->level, o->cover, o->jaccard, o->groups, o->fired, o->n_diag);
		for (j = 0; j < o->n_diag && j < MAXDIAG; j++)
			printf("diag %s family=%s variant=%s tag=%s type=%s\n", o->diag[j].name, o->diag[j].family, o->diag[j].variant, o->diag[j].tag,
			       o->diag[j].type < 0 ? "-" : kof_maltype_name((uint32_t)o->diag[j].type));
	}
}

/* ---- running a tool ----------------------------------------------------------------------------------------- */

static char *run_tool(const char *cmd)
{
	char full[2048];
	FILE *p;
	size_t cap = 1u << 16, n = 0, r;
	char *buf = malloc(cap);

	snprintf(full, sizeof full, "ulimit -v 4194304; timeout -s KILL 120 %s 2>&1", cmd);
	p = popen(full, "r");
	if (!p) {
		free(buf);
		return NULL;
	}
	while ((r = fread(buf + n, 1, cap - n - 1u, p)) > 0) {
		n += r;
		if (n + 1u >= cap) {
			if (cap > (64u << 20))
				break;
			cap *= 2u;
			buf = realloc(buf, cap);
		}
	}
	pclose(p);
	buf[n] = 0;
	return buf;
}

/* whole-line search: `want` is a line of `out` once its leading blanks and trailing blanks are dropped */
static int has_line(const char *out, const char *want)
{
	const char *p = out;
	size_t wl = strlen(want);

	while (*p) {
		const char *e = strchr(p, '\n'), *s = p;
		size_t l = e ? (size_t)(e - p) : strlen(p);

		while (l && (*s == ' ' || *s == '\t')) {
			s++;
			l--;
		}
		while (l && (s[l - 1u] == ' ' || s[l - 1u] == '\r'))
			l--;
		if (l == wl && !memcmp(s, want, wl))
			return 1;
		if (!e)
			break;
		p = e + 1;
	}
	return 0;
}

static unsigned count_prefix(const char *out, const char *prefix)
{
	const char *p = out;
	unsigned n = 0;
	size_t pl = strlen(prefix);

	while (*p) {
		if (!strncmp(p, prefix, pl))
			n++;
		p = strchr(p, '\n');
		if (!p)
			break;
		p++;
	}
	return n;
}

/* Whether a line the tool prints ABOUT THE DETECTION (verdict, family, diagnose) holds `word`. The rest of an examiner's output is the sample's own bytes - a Mirai
 * binary carries the word in its symbols - and says nothing of what the tool took from the engine. */
static int detection_lines_have(const char *out, const char *word)
{
	const char *p = out;

	while (*p) {
		const char *e = strchr(p, '\n');
		size_t l = e ? (size_t)(e - p) : strlen(p);
		const char *s = p;

		while (l && *s == ' ') {
			s++;
			l--;
		}
		if ((!strncmp(s, "verdict", 7) || !strncmp(s, "family=", 7) || !strncmp(s, "diagnose ", 9) || !strncmp(s, "Infected#", 9) || !strncmp(s, "basis ", 6)) && l) {
			char line[1024];

			snprintf(line, sizeof line, "%.*s", (int)(l < sizeof line - 1u ? l : sizeof line - 1u), s);
			if (strstr(line, word))
				return 1;
		}
		if (!e)
			break;
		p = e + 1;
	}
	return 0;
}

static const char *type_word(int t)
{
	return t < 0 ? "-" : kof_maltype_name((uint32_t)t);
}

/* ---- kofscanner -v against the engine ------------------------------------------------------------------------ */

static void check_scanner(const char *label, const char *db, const char *bases, const char *path, const struct truth *t)
{
	char cmd[1500], want[1200];
	char *out;
	unsigned i, j, verdict_objs = 0, diag_lines = 0;

	snprintf(cmd, sizeof cmd, "build/release/bin/kofscanner --db %s --bases %s --no-cache -v --scan-files %s", db, bases, path);
	out = run_tool(cmd);
	if (!out) {
		CK(0, "%s: cannot run kofscanner", label);
		return;
	}
	for (i = 0; i < t->n; i++) {
		const struct tobj *o = &t->obj[i];

		if (!o->has_verdict)
			continue;
		verdict_objs++;
		snprintf(want, sizeof want, "%s %s", o->verdict, o->name);
		CK(has_line(out, want), "%s: kofscanner does not print the engine's verdict line\n    wanted: %s\n    output:\n%s", label, want, out);
		for (j = 0; j < o->n_diag && j < MAXDIAG; j++) {
			diag_lines++;
			snprintf(want, sizeof want, "diagnose %s  family=%s variant=%s tag=%s type=%s", o->diag[j].name, o->diag[j].family, o->diag[j].variant,
				 o->diag[j].tag, type_word(o->diag[j].type));
			CK(has_line(out, want), "%s: kofscanner does not print the engine's diagnose line\n    wanted: %s\n    output:\n%s", label, want, out);
		}
		if (o->level) {
			snprintf(want, sizeof want, "basis %s family=%s variant=%s tag=%s cover=%u jaccard=%u groups=%u matched=%u", o->level == KOF_VCAT_VARIANT ? "variant" : "tag",
				 o->n_diag ? o->diag[0].family : "", o->level == KOF_VCAT_VARIANT && o->n_diag ? o->diag[0].variant : "-", o->n_diag ? o->diag[0].tag : "",
				 o->cover, o->jaccard, o->groups, o->fired);
			if (!has_line(out, want))
				printf("  note %s: basis line differs from the guess made from the first diagnose (%s); not asserted\n", label, want);
		}
	}
	/* nothing the engine did not say */
	CK(count_prefix(out, "  diagnose ") == diag_lines, "%s: kofscanner prints %u diagnose lines, the engine lists %u", label, count_prefix(out, "  diagnose "), diag_lines);
	CK(count_prefix(out, "  basis ") <= verdict_objs, "%s: kofscanner prints more basis lines than there are verdicts", label);
	{
		char sum[200];
		unsigned long long objs = 0, files = 0;
		const char *s;

		s = strstr(out, "scanned ");
		CK(s && sscanf(s, "scanned %llu object(s) in %llu file(s)", &objs, &files) == 2, "%s: no 'scanned' line", label);
		CK(files == t->files, "%s: kofscanner says %llu files, the engine folded %llu", label, files, (unsigned long long)t->files);
		CK(objs == (unsigned long long)t->n || (t->rc >= 0 && objs == (unsigned long long)t->rc), "%s: kofscanner says %llu objects, the engine delivered %u (rc %d)", label, objs, t->n, t->rc);
		s = strstr(out, "infected ");
		snprintf(sum, sizeof sum, "infected  %u file(s)", t->infected_files);
		CK(s && has_line(s, sum), "%s: kofscanner's infected count is not the engine's (%s)", label, sum);
	}
	free(out);
}

/* ---- kofexaminer against the engine ----------------------------------------------------------------------------- */

static void check_examiner(const char *label, const char *db, const char *bases, const char *path, const struct truth *t)
{
	char cmd[1500], want[1200];
	char *out;
	unsigned i, j;
	const struct tobj *lead = NULL;

	snprintf(cmd, sizeof cmd, "build/release/bin/kofexaminer --db %s --bases %s %s", db, bases, path);
	out = run_tool(cmd);
	if (!out) {
		CK(0, "%s: cannot run kofexaminer", label);
		return;
	}
	for (i = 0; i < t->n; i++)
		if (t->obj[i].has_verdict) {
			lead = &t->obj[i];
			break;
		}
	if (!lead) {
		CK(count_prefix(out, "  verdict ") == 0, "%s: kofexaminer prints a verdict, the engine has none:\n%s", label, out);
		CK(count_prefix(out, "    diagnose ") == 0, "%s: kofexaminer lists diagnoses, the engine matched none", label);
		free(out);
		return;
	}
	snprintf(want, sizeof want, "verdict   %s", lead->verdict);
	{
		/* the examiner pads the word: compare the verdict text on its line, not the padding */
		char w2[300];

		snprintf(w2, sizeof w2, "verdict %s", lead->verdict);
		CK(has_line(out, want) || has_line(out, w2), "%s: kofexaminer does not print the engine's verdict\n    wanted: %s\n    output (verdict lines):\n%s", label, lead->verdict, strstr(out, "verdict") ? strstr(out, "verdict") : "(none)");
	}
	snprintf(want, sizeof want, "family=%s variant=%s tag=%s", lead->diag[0].family, lead->diag[0].variant, lead->diag[0].tag);
	CK(has_line(out, want), "%s: kofexaminer family/variant/tag line is not the engine's (%s)", label, want);
	for (j = 0; j < lead->n_diag && j < MAXDIAG; j++) {
		snprintf(want, sizeof want, "diagnose %s", lead->diag[j].name);
		CK(has_line(out, want), "%s: kofexaminer does not list diagnose %s", label, lead->diag[j].name);
	}
	CK(count_prefix(out, "    diagnose ") == lead->n_diag, "%s: kofexaminer lists %u diagnoses, the engine %u", label, count_prefix(out, "    diagnose "), lead->n_diag);
	free(out);
}

/* ---- the table ---------------------------------------------------------------------------------------------------- */

static char scratch[256];

static int exists(const char *p)
{
	struct stat st;

	return stat(p, &st) == 0;
}

/* A database the tools can open: the release unpackers (they open the tar and make the normalised view) and the diagnoses and names of `alt`. */
static void make_alt_db(const char *dir, const char *alt)
{
	static const char *const unp[] = { "unpack-archive.ksig", "unpack-doc.ksig", "unpack-elf.ksig", "unpack-pe.ksig", "unpack-raw.ksig", "unpack-raw-x7.ksig" };
	char from[300];
	unsigned i;

	kof_mkdir(dir, 0700);
	for (i = 0; i < sizeof unp / sizeof unp[0]; i++)
		CK(copy_pack("build/release/databases", unp[i], dir), "cannot copy %s", unp[i]);
	snprintf(from, sizeof from, "build/test/databases-%s", alt);
	CK(copy_pack(from, "diag-trojan.kdig", dir), "cannot copy the diagnoses of %s", alt);
	CK(copy_pack(from, "names.kdig", dir), "cannot copy the names of %s", alt);
}

struct dbcase {
	const char *tag, *db, *bases;
	unsigned want_diag;             /* what the data says the sample matches (asserted independently of the tools) */
	const char *family, *variant, *tag_name, *type;
	const char *old_name;           /* a word that must NOT be in what a tool prints for this database */
};

static int run_sample(const struct dbcase *c, const char *sname, const char *path, int should_be_infected)
{
	struct truth *t = calloc(1, sizeof *t);
	char label[200];
	unsigned i;
	int found = 0;

	snprintf(label, sizeof label, "%s/%s", c->tag, sname);
	if (!ask_engine(c->db, c->bases, path, t)) {
		CK(0, "%s: engine did not open", label);
		free(t);
		return 0;
	}
	for (i = 0; i < t->n; i++)
		if (t->obj[i].has_verdict)
			found = 1;
	if (should_be_infected) {
		CK(found == (c->want_diag > 0u), "%s: the engine's verdict (%d) is not what the data says (%u matching diagnoses)", label, found, c->want_diag);
		for (i = 0; i < t->n; i++)
			if (t->obj[i].has_verdict) {
				const struct tobj *o = &t->obj[i];

				/* the release database also holds the owner's other diagnoses (they may match this sample too): at least the six it was built for */
				CK(c->old_name ? o->n_diag == c->want_diag : o->n_diag >= c->want_diag, "%s: the engine lists %u diagnoses, the data has %u", label, o->n_diag, c->want_diag);
				CK(o->n_diag && !strcmp(o->diag[0].family, c->family) && !strcmp(o->diag[0].variant, c->variant) && !strcmp(o->diag[0].tag, c->tag_name) &&
				   !strcmp(type_word(o->diag[0].type), c->type), "%s: the engine names %s / %s / %s / %s, the data says %s / %s / %s / %s", label,
				   o->n_diag ? o->diag[0].family : "-", o->n_diag ? o->diag[0].variant : "-", o->n_diag ? o->diag[0].tag : "-", o->n_diag ? type_word(o->diag[0].type) : "-",
				   c->family, c->variant, c->tag_name, c->type);
			}
	} else {
		CK(!found, "%s: the engine found a verdict in a clean sample", label);
	}
	check_scanner(label, c->db, c->bases, path, t);
	check_examiner(label, c->db, c->bases, path, t);
	/* a tool that kept the old names would print them here: the whole output of both tools was read in the checks above for the NEW ones; the old ones are asked of the scanner once more */
	if (c->old_name) {   /* for alt_none no verdict is made at all, and no line may carry the old name either */
		char cmd[1500], *out;

		snprintf(cmd, sizeof cmd, "build/release/bin/kofscanner --db %s --bases %s --no-cache -v --scan-files %s", c->db, c->bases, path);
		out = run_tool(cmd);
		CK(out && !detection_lines_have(out, c->old_name), "%s: kofscanner prints the old name %s for data that does not carry it", label, c->old_name);
		free(out);
		snprintf(cmd, sizeof cmd, "build/release/bin/kofexaminer --db %s --bases %s %s", c->db, c->bases, path);
		out = run_tool(cmd);
		CK(out && !detection_lines_have(out, c->old_name), "%s: kofexaminer prints the old name %s for data that does not carry it", label, c->old_name);
		free(out);
	}
	printf("  %-28s %u object(s), %llu file(s), %u infected, tools agree with the engine\n", label, t->n, (unsigned long long)t->files, t->infected_files);
	free(t);
	return 1;
}

int main(int argc, char **argv)
{
	static const char *const run1_path = "/mnt/games/normtest/scan_run1/run1";
	char run1[400], tarp[400], lsp[400], pep[400], dbA[400], dbB[400], dbN[400], cmd[2400];
	struct dbcase cases[4];
	unsigned k;
	int have_run1;

	if (argc >= 5 && !strcmp(argv[1], "--truth")) {
		struct truth *t = calloc(1, sizeof *t);

		if (!ask_engine(argv[2], argv[3], argv[4], t))
			return 2;
		print_truth(t);
		close_engine();
		return 0;
	}
	if (access("build/release/bin/kofscanner", X_OK) || access("build/release/bin/kofexaminer", X_OK) || access("build/release/databases/names.kdig", R_OK) ||
	    access("build/test/databases-alt_a/names.kdig", R_OK) || access("build/test/databases-alt_b/names.kdig", R_OK) || access("build/test/databases-alt_none/names.kdig", R_OK)) {
		printf("tool_agree: kofscanner / kofexaminer / the databases (make, make test-sigs) are not built\n");
		return 2;
	}
	snprintf(scratch, sizeof scratch, "build/kof_agree_XXXXXX");
	if (!mkdtemp(scratch)) {
		printf("tool_agree: no scratch directory\n");
		return 2;
	}
	snprintf(dbA, sizeof dbA, "%s/db_a", scratch);
	snprintf(dbB, sizeof dbB, "%s/db_b", scratch);
	snprintf(dbN, sizeof dbN, "%s/db_n", scratch);
	make_alt_db(dbA, "alt_a");
	make_alt_db(dbB, "alt_b");
	make_alt_db(dbN, "alt_none");
	/* Function units carry no similarity signature (prototype 2026-10-30, kgenome_mutation_signature): a diagnose whose block is cut from a function
	 * is not scored on run1. What matches is what the DATA blocks say: of the release database's, the data ones (the tag the owner renamed from
	 * Mirai-Ops-Str to Mirai-Strings in bases/syndromes: the lead is Mirai-Strings); of alt_a (6 function diagnoses + trojan_zorg_zorg-wave_07) and alt_b (3 + _04), the one data diagnose. */
	cases[0] = (struct dbcase){ "release", "build/release/databases", "bases", 2u, "Mirai", "Mirai.A", "Mirai-Strings", "Botnet", NULL };
	cases[1] = (struct dbcase){ "alt_a(6+1)", dbA, "tests/agree/alt_a", 1u, "Zorg", "Zorg.C", "Zorg-wave", "Trojan", "Mirai" };
	cases[2] = (struct dbcase){ "alt_b(3+1)", dbB, "tests/agree/alt_b", 1u, "Zorg", "Zorg.C", "Zorg-wave", "Trojan", "Mirai" };
	cases[3] = (struct dbcase){ "alt_none(0)", dbN, "tests/agree/alt_none", 0u, "", "", "", "", "Mirai" };

	/* the samples: copies, read-only (a tool must not touch an original) */
	snprintf(lsp, sizeof lsp, "%s/ls.copy", scratch);
	snprintf(cmd, sizeof cmd, "cp /bin/ls %s && chmod a-w %s", lsp, lsp);
	CK(system(cmd) == 0, "cannot copy /bin/ls");
	snprintf(pep, sizeof pep, "%s/synth-pe64.exe", scratch);
	snprintf(cmd, sizeof cmd, "cp build/test/fixtures/synth-pe64.exe %s && chmod a-w %s", pep, pep);
	CK(system(cmd) == 0, "cannot copy the PE fixture (make fixtures)");
	have_run1 = exists(run1_path);
	snprintf(run1, sizeof run1, "%s/run1.elf", scratch);
	snprintf(tarp, sizeof tarp, "%s/holds_run1.tar", scratch);
	if (have_run1) {
		snprintf(cmd, sizeof cmd, "cp %s %s && chmod a-w %s && tar -C %s -cf %s run1.elf", run1_path, run1, run1, scratch, tarp);
		(void)0;
		CK(system(cmd) == 0, "cannot make the run1 samples");
		chmod(tarp, 0444);
	} else {
		printf("  note: %s is not there: the Mirai samples (run1 and the tar that holds it) are not run\n", run1_path);
	}
	for (k = 0; k < 4u; k++) {
		if (have_run1) {
			run_sample(&cases[k], "run1", run1, 1);
			run_sample(&cases[k], "tar-with-run1", tarp, 1);
		}
		run_sample(&cases[k], "clean-ls", lsp, 0);
		run_sample(&cases[k], "pe", pep, 0);
	}
	if (!failures)
		rm_all(scratch);
	if (failures) {
		printf("tool_agree: %d FAIL\n", failures);
		return 1;
	}
	printf("tool_agree: ok\n");
	return 0;
}
