#define _GNU_SOURCE
/*
 * cfg_sig_gen - a FUNCTION ROW ticked in the table becomes a diagnose (Generate), is built into a pack, MATCHES an object through the normal verdict
 * path, and the draft's Save keeps adding and removing it by the link of merge 77/79.
 *
 * WHAT IT PINS (CFG step 2c, stage 3). Functions assembled at run time (cfg_scene.h: an ELF64 x86-64 object of inert functions with a symbol
 * table), signed by kof_cfgsign_function - the engine function the table's rows come from - ticked into a draft exactly as the table does it
 * (blk_set_picked on a block whose hashes are the unit's keys, region KOF_SCAN_ELF_CODE, norm RAW), then
 *   generate  one file per matcher; the block is `KOF_MUTATION_BLOCK(bN, KOF_SCAN_ELF_CODE, <n keys>)` with the 24 and the 14 keys
 *             of the two functions (a CODE block of 12..32 hashes is a block like any other: the reader the builder uses read it back before it wrote)
 *   floor     a CODE block of one key (a function of one reachable block) is written; of none, refused ("too few or too many hashes"); a DATA block
 *             keeps its 16. It was 12 keys written and 11 refused: the floor of 12 reachable blocks is gone (owner, 2026-11-01)
 *   small     a function of 6 reachable blocks: its row is ticked and saved, the builder packs it, the engine (keng_open + kscan_explain) fires the
 *             diagnose on an object holding that function and not on an object whose small function has another shape
 *   verdict   ksigbuilder builds the pack from the generated directory; the engine scan of the object fires both diagnoses (the thresholds are
 *             the author's), the verdict name is the lead disease's, an object without those shapes fires neither; a SECOND build of the same
 *             files is byte-identical (the block carries no state of the run)
 *   save      the generated files are loaded into a draft by ticking (the arrival path), the link of each unit is its file; Save with nothing
 *             changed writes and deletes nothing; unticking one deletes that file and no other; a changed threshold is a MODIFIED unit, reported,
 *             neither written nor the cause of a deletion; a unit ticked after the load is written under the first free number
 * Why the old tests missed it: (a) no function row could be ticked (the row had no signature), so Generate never met a block cut from a
 * function; (b) a CODE block under 16 hashes was refused at the editor, the builder and the loader, so 12 keys were unreachable.
 */

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../../kofexamine/kofeditor.h"
#include "../../libkofeng/databases/diagsrc.h"
#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/verdictor/famcat.h"
#include "../../libkofeng/verdictor/tagcat.h"
#include "../../libkofeng/analyzers/cfgsign.h"
#include "../../libkofeng/scanners/scan.h"
#include <celllysis/mutation.h>
#include <celllysis/cfg.h>
#include <kofmod/elf.h>

#include "cfg_scene.h"

static int fails;
static struct kof_editor E;
static char dir[400], root[300], msg[800];
static const char *builder = "build/release/bin/ksigbuilder";
static const char *dbdir = "build/test/databases-sigs";

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

#define CKM(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("  [msg=%s]\n", msg); \
		fails++; \
	} \
} while (0)

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

static int exists(const char *stem)
{
	char path[800];

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
		char path[800];
		struct stat st;

		for (k = 0; b && k < len; k++)
			h = (h ^ (uint8_t)b[k]) * 16777619u;
		snprintf(path, sizeof path, "%s/%s", dir, names[i]);
		(void)lstat(path, &st);
		at += (size_t)snprintf(out + at, 65536u - at, "%s:%zu:%08x:%o\n", names[i], len, h, (unsigned)(st.st_mode & 07777u)); if (at > 60000u) at = 60000u;
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
	char cmd[1000];

	chmod(dir, 0700);
	snprintf(cmd, sizeof cmd, "rm -rf '%s'/* '%s'/.[a-z]*", dir, dir);
	(void)system(cmd);
}

static struct kof_dsrc *DS;

static void new_draft(void)
{
	uint32_t i;

	for (i = 0; i < E.dr.n_decl; i++)
		free(E.dr.decl[i].bytes);
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
	*linked = draft_link_unit(&E, 1, g, dir, kof_diag_id32_(stem), stem);
	kof_dsrc_view_free(&v);
	free(text);
	return g;
}


static int untick(const char *stem)
{
	uint32_t g;

	for (g = 0; g < E.dr.n_grp; g++)
		if (E.dr.grp[g].link == kof_diag_id32_(stem)) {
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

static uint8_t *read_file(const char *path, size_t *n)
{
	return (uint8_t *)slurp_path(path, n);
}

static int write_file(const char *path, const void *p, size_t n)
{
	FILE *f = fopen(path, "wb");

	if (!f)
		return 0;
	if (n && fwrite(p, 1, n, f) != n) {
		fclose(f);
		return 0;
	}
	return fclose(f) == 0;
}

/* ---- the scene and the pack ---------------------------------------------------------------------------------------------------- */

static void write_catalogs(const char *base)
{
	struct kof_famcat_fam fam[8];
	struct kof_famcat_var var[8];
	struct kof_catstore *st = calloc(1, sizeof *st);
	struct kof_tagcat_tag tag[8];
	struct kof_tagcat tc;
	struct kof_famcat c;
	char d[500];
	uint32_t f;

	snprintf(d, sizeof d, "%s/pathogens", base);
	kof_mkdir(d, 0700);
	kof_famcat_init(&c, fam, 8, var, 8);
	kof_catstore_init(st);
	(void)kof_famcat_add_family(&c, "Mirai", NULL, (1u << KOF_MALTYPE_BOTNET) | (1u << KOF_MALTYPE_ROOTKIT), &f);
	(void)kof_famcat_save(&c, st, d);
	snprintf(d, sizeof d, "%s/syndromes", base);
	kof_mkdir(d, 0700);
	kof_tagcat_init(&tc, tag, 8);
	kof_catstore_init(st);
	(void)kof_tagcat_add(&tc, "flood", 1u << KOF_DISEASE_ACT_SCAN, 1u << KOF_DISEASE_OBJ_NETWORK, NULL);
	(void)kof_tagcat_add(&tc, "c2", 1u << KOF_DISEASE_ACT_C2, 1u << KOF_DISEASE_OBJ_NETWORK, NULL);
	(void)kof_tagcat_save(&tc, st, d);
	free(st);
}

static struct cs_obj O;

static enum kof_cfgsign_state sign_fn(const struct cs_obj *o, uint32_t k, struct kof_cfgsign *cs)
{
	struct kgenome_elf_info ei;
	struct kof_obj_ctx c;
	struct kof_cfgsign_req rq;

	memset(&c, 0, sizeof c);
	memset(&ei, 0, sizeof ei);
	ei.elf_data = 1;
	c.format = KOF_FMT_ELF;
	c.arch = KGENOME_ARCH_X86_64;
	c.obj_size = o->n;
	c.file_header = &ei;
	memset(&rq, 0, sizeof rq);
	rq.ctx = &c;
	rq.data.p = o->b;
	rq.data.n = o->n;
	rq.off = o->f_off[k];
	rq.len = o->f_len[k];
	return kof_cfgsign_function(&rq, cs);
}

static void chain(struct cs_spec *g, uint32_t nb)
{
	uint32_t i;

	memset(g, 0, sizeof *g);
	g->nb = nb;
	for (i = 0; i + 1u < nb; i++) {
		g->kind[i] = CS_COND;
		g->t[i] = i + 2u < nb ? i + 2u : nb - 1u;
	}
	g->kind[nb - 1u] = CS_EXIT;
}

/* A unit of the table as the viewer makes it for a signed function row: the keys are the hashes, the region is CODE, the norm RAW, the author's side. */
static uint32_t function_row(const struct kgenome_cfg_sign *s)
{
	struct mtn_block *k = &E.dr.blk[E.dr.n_blk];
	const uint32_t blk = E.dr.n_blk++;

	memset(k, 0, sizeof *k);
	k->n_hash = s->n_key;
	memcpy(k->hash, s->key, (size_t)s->n_key * sizeof s->key[0]);
	k->id = kof_mutation_fold(s->key, s->n_key);
	snprintf(k->rgn_enum, sizeof k->rgn_enum, "KOF_SCAN_ELF_CODE");
	snprintf(k->rgn, sizeof k->rgn, "CODE");
	return blk;
}

static uint32_t tick(uint32_t blk, const char *tag, unsigned pct)
{
	uint32_t g;

	blk_set_picked(&E, blk, 1);
	g = grp_of_block(&E, blk);
	snprintf(E.dr.grp[g].tag, sizeof E.dr.grp[g].tag, "%s", tag);
	E.dr.grp[g].utype = (uint8_t)(KOF_MALTYPE_BOTNET + 1u);
	E.dr.grp[g].pct = (uint8_t)pct;
	return g;
}

static int build_pack(const char *art, const char *db, const char *errf)
{
	char cmd[4400], a[500], p[500];
	size_t n = 0;
	uint8_t *b;

	kof_mkdir(art, 0700);
	kof_mkdir(db, 0700);
	snprintf(a, sizeof a, "%s/sigs-any.ksig", dbdir);
	snprintf(p, sizeof p, "%s/sigs-any.ksig", db);
	b = read_file(a, &n);
	if (b)
		(void)write_file(p, b, n);
	free(b);
	snprintf(cmd, sizeof cmd, "%s --tree '%s' '%s' '%s' --pathogens '%s/pathogens' --syndromes '%s/syndromes' --basedir '%s' >'%s.out' 2>'%s'",
		 builder, root, art, db, root, root, root, errf, errf);
	return system(cmd);
}

struct seen {
	int      flood_hi, flood_lo;      /* the two diagnoses fired */
	char     verdict[160];
	unsigned n;
};

static void scan_obj(kof_scanner *sc, kof_engine *eng, const void *p, size_t n, struct seen *out)
{
	kdet_run *run;
	const struct kdet_object *o;

	memset(out, 0, sizeof *out);
	run = kscan_explain(sc, p, n, "sample", NULL);
	if (!run)
		return;
	o = kdet_run_find(run, "sample");
	if (o) {
		struct kdet_info info;
		uint32_t i;

		kdet_info(eng, &o->res, &info);
		if (info.verdict)
			snprintf(out->verdict, sizeof out->verdict, "%s", info.verdict);
		for (i = 0; i < o->res.n_diag; i++) {
			if (o->res.diag[i].state == KOF_DIAG_ST_MATCH) {
				out->n++;
				out->flood_hi |= strstr(o->res.diag[i].name, "flood_01") != NULL;
				out->flood_lo |= strstr(o->res.diag[i].name, "flood_02") != NULL;
			}
		}
	}
	kdet_run_free(run);
}

static unsigned count_of(const char *t, const char *needle)
{
	unsigned n = 0;

	for (; (t = strstr(t, needle)) != NULL; t += strlen(needle))
		n++;
	return n;
}

/* ---- the cases ------------------------------------------------------------------------------------------------------------------- */

static struct kgenome_cfg_sign S0, S1;

static void generate_and_match(void)
{
	char *t0, *t1, art[400], db[400], errf[400], art2[400], db2[400];
	struct seen s;
	kof_engine *eng;
	kof_scanner *sc;
	uint32_t b0, b1;
	struct cs_spec g[3];
	struct kof_cfgsign cs;
	struct cs_obj other;

	clean();
	new_draft();
	b0 = function_row(&S0);
	b1 = function_row(&S1);
	tick(b0, "flood", 90);
	tick(b1, "flood", 60);
	CKM(save() == 2, "two function blocks are two files");
	CK(count_files() == 2u);
	t0 = slurp("botnet_mirai_flood_01.c", NULL);
	t1 = slurp("botnet_mirai_flood_02.c", NULL);
	CK(t0 && t1);
	if (t0 && t1) {
		CK(strstr(t0, "KOF_MUTATION_BLOCK(b0, KOF_SCAN_ELF_CODE, 0x") != NULL);
		CKM(count_of(t0, ", 0x") == S0.n_key && S0.n_key == 24u, "the first block carries its %u keys (%u)", S0.n_key, count_of(t0, ", 0x"));
		CKM(count_of(t1, ", 0x") == S1.n_key && S1.n_key == 14u, "the second block carries its %u keys (%u)", S1.n_key, count_of(t1, ", 0x"));
		CK(strstr(t0, "KOF_DIAG_SIMILAR(m1, 90, b0);") != NULL || strstr(t0, "KOF_DIAG_SIMILAR(m1, 60, b0);") != NULL);
	}
	free(t0);
	free(t1);
	/* the builder reads the generated directory as a tree: the diagnoses are the files Generate wrote */
	snprintf(art, sizeof art, "%s/art", root);
	snprintf(db, sizeof db, "%s/db", root);
	snprintf(errf, sizeof errf, "%s/err.txt", root);
	snprintf(art2, sizeof art2, "%s/art2", root);
	snprintf(db2, sizeof db2, "%s/db2", root);
	CKM(build_pack(art, db, errf) == 0, "the generated diagnoses build (see %s)", errf);
	CKM(build_pack(art2, db2, errf) == 0, "the second build");
	{
		char c1[900], c2[900];
		size_t n1 = 0, n2 = 0;
		uint8_t *a, *b;
		DIR *d = opendir(db);
		struct dirent *de;

		while (d && (de = readdir(d)) != NULL) {
			if (de->d_name[0] == '.' || !strstr(de->d_name, "diag"))
				continue;
			snprintf(c1, sizeof c1, "%s/%s", db, de->d_name);
			snprintf(c2, sizeof c2, "%s/%s", db2, de->d_name);
			a = read_file(c1, &n1);
			b = read_file(c2, &n2);
			CKM(a && b && n1 == n2 && !memcmp(a, b, n1), "two builds of the same files give the same %s", de->d_name);
			free(a);
			free(b);
		}
		if (d)
			closedir(d);
	}
	eng = keng_open(db);
	sc = eng ? kscan_new(eng) : NULL;
	if (!sc) {
		CK(0 && "the pack does not open");
		return;
	}
	CKM(kdb_diagnoses(eng) == 2u && kdb_diag_refused(eng) == 0u, "two diagnoses loaded, none refused (%u, %u)", (unsigned)kdb_diagnoses(eng), (unsigned)kdb_diag_refused(eng));
	scan_obj(sc, eng, O.b, O.n, &s);
	CKM(s.flood_hi && s.flood_lo, "fired: 01=%d 02=%d (%u matched), verdict \"%s\"", s.flood_hi, s.flood_lo, s.n, s.verdict);
	CKM(!strncmp(s.verdict, "Infected#", 9) && strstr(s.verdict, "Botnet"), "verdict \"%s\"", s.verdict);
	/* an object whose functions have other shapes fires neither */
	chain(&g[0], 30);
	g[0].kind[3] = CS_JUMP;
	g[0].t[3] = 7;
	g[1] = g[0];
	g[1].kind[10] = CS_JUMP;
	g[1].t[10] = 14;
	CK(cs_build(&other, g, 2, 0));
	(void)sign_fn(&other, 0, &cs);
	scan_obj(sc, eng, other.b, other.n, &s);
	CKM(!s.flood_hi, "a function of another shape fires the 90%% diagnose (blocks %u)", cs.sign.n_blk);
	kscan_free(sc);
	keng_close(eng);
}

static void floor_of_the_block(void)
{
	char *t;
	uint32_t b, i, n;

	/* a CODE block: none refused; one, two and twelve written and read back */
	for (n = 0; n <= 12; n += (n < 2u ? 1u : 10u)) {
		struct kgenome_cfg_sign s;

		clean();
		new_draft();
		memset(&s, 0, sizeof s);
		s.n_key = n;
		for (i = 0; i < n; i++)
			s.key[i] = 0x01000000u * (i + 1u) + 0x1234u;
		b = function_row(&s);
		tick(b, "flood", 70);
		if (n == 0) {
			CKM(save() < 0 && count_files() == 0u && strstr(msg, "too few or too many hashes"), "no key is refused: %d", 0);
		} else {
			CKM(save() == 1 && count_files() == 1u, "%u keys are written", n);
			t = slurp("botnet_mirai_flood_01.c", NULL);
			CKM(t && count_of(t, ", 0x") == n, "%u keys in the file", n);
			free(t);
		}
	}
	/* a DATA block keeps the window floor of 16 */
	{
		struct kgenome_cfg_sign s;

		clean();
		new_draft();
		memset(&s, 0, sizeof s);
		s.n_key = 15;
		for (i = 0; i < 15; i++)
			s.key[i] = 0x02000000u * (i + 1u) + 99u;
		b = function_row(&s);
		snprintf(E.dr.blk[b].rgn_enum, sizeof E.dr.blk[b].rgn_enum, "KOF_SCAN_ELF_DATA");
		tick(b, "flood", 70);
		CKM(save() < 0 && strstr(msg, "too few or too many hashes"), "15 DATA hashes are refused");
	}
}

/* THE SMALL FUNCTION, end to end: the engine's sketch of a 6-block function -> a ticked row -> Save -> the builder -> keng_open -> kscan_explain. */
static void small_function_round_trip(void)
{
	static struct cs_obj OA, OB;     /* static: two objects on the stack are over the frame-size limit */
	struct cs_spec a, b;
	uint32_t i;
	struct kof_cfgsign ca, cb;
	char art[400], db[400], errf[400];
	struct seen s;
	kof_engine *eng;
	kof_scanner *sc;
	char *t;

	chain(&a, 6);
	chain(&b, 6);
	b.kind[1] = CS_JUMP;
	b.t[1] = 3;
	for (i = 0; i < 6u; i++)        /* nops that change no shape: a function under the cut's minimum (FN_MIN, 64 bytes) is no unit at all */
		a.pad[i] = b.pad[i] = 8;
	CK(cs_build(&OA, &a, 1, 0x40));
	CK(cs_build(&OB, &b, 1, 0x40));
	CK(sign_fn(&OA, 0, &ca) == KOF_CFGSIGN_SIGNED && ca.sign.n_blk == 6u && ca.sign.n_key == 6u);
	CK(sign_fn(&OB, 0, &cb) == KOF_CFGSIGN_SIGNED && cb.sign.n_blk == 6u);
	CKM(kgenome_cfg_pct(&ca.sign, &cb.sign) < 100u, "the two small functions have different sketches (pct %u)", kgenome_cfg_pct(&ca.sign, &cb.sign));
	clean();
	new_draft();
	tick(function_row(&ca.sign), "flood", 100);
	CKM(save() == 1 && count_files() == 1u, "a 6-key CODE block is written");
	t = slurp("botnet_mirai_flood_01.c", NULL);
	CKM(t && count_of(t, ", 0x") == 6u, "its 6 keys are in the file");
	free(t);
	snprintf(art, sizeof art, "%s/art_small", root);
	snprintf(db, sizeof db, "%s/db_small", root);
	snprintf(errf, sizeof errf, "%s/err_small.txt", root);
	CKM(build_pack(art, db, errf) == 0, "the 6-key block builds (see %s)", errf);
	eng = keng_open(db);
	sc = eng ? kscan_new(eng) : NULL;
	if (!sc) {
		CK(0 && "the pack of the small block does not open");
		return;
	}
	CKM(kdb_diagnoses(eng) == 1u && kdb_diag_refused(eng) == 0u, "the diagnose is loaded, not refused (%u, %u)", (unsigned)kdb_diagnoses(eng), (unsigned)kdb_diag_refused(eng));
	scan_obj(sc, eng, OA.b, OA.n, &s);
	CKM(s.flood_hi, "the object holding the small function fires its diagnose (%u matched)", s.n);
	scan_obj(sc, eng, OB.b, OB.n, &s);
	CKM(!s.flood_hi, "an object whose small function has another shape does not");
	kscan_free(sc);
	keng_close(eng);
}

static void save_round_trip(void)
{
	uint32_t g;
	int ok = 0;
	char *before, *after;

	clean();
	new_draft();
	{
		const uint32_t b0 = function_row(&S0), b1 = function_row(&S1);

		tick(b0, "flood", 90);
		tick(b1, "flood", 60);
	}
	CKM(save() == 2, "two files");
	/* load them back by ticking (the arrival path), link each unit to its file */
	new_draft();
	(void)load_file("botnet_mirai_flood_01", &ok);
	CK(ok);
	ok = 0;
	(void)load_file("botnet_mirai_flood_02", &ok);
	CK(ok);
	CKM(draft_links_loaded(&E) == 2u, "both files are linked (%u)", (unsigned)draft_links_loaded(&E));
	before = snap();
	CKM(save() == 0 && strstr(msg, "Nothing new to write") != NULL, "unchanged: nothing written, nothing deleted");
	after = snap();
	CK(!strcmp(before, after));
	free(before);
	free(after);
	/* untick the second: that file goes and no other */
	CK(untick("botnet_mirai_flood_02"));
	CK(save() == 0);
	CKM(strstr(msg, "Deleted 1 file") != NULL && strstr(msg, "botnet_mirai_flood_02") != NULL, "deleted by name");
	CK(exists("botnet_mirai_flood_01") && !exists("botnet_mirai_flood_02") && count_files() == 1u);
	/* a changed threshold is a modification: reported, neither written nor a deletion */
	for (g = 0; g < E.dr.n_grp; g++)
		if (E.dr.grp[g].link == kof_diag_id32_("botnet_mirai_flood_01"))
			E.dr.grp[g].pct = 80;
	before = snap();
	CK(save() == 0);
	CKM(strstr(msg, "modified") != NULL, "an edited threshold is reported as modified");
	after = snap();
	CK(!strcmp(before, after));
	free(before);
	free(after);
	/* a unit ticked after the load is written under the first free number */
	{
		const uint32_t b1 = function_row(&S1);

		tick(b1, "flood", 55);
	}
	CKM(save() >= 1 && exists("botnet_mirai_flood_02"), "a new function block is written under the first free number");
}

int main(void)
{
	struct cs_spec g[3];
	struct kof_cfgsign cs;
	char cmd[400];

	if (access(builder, X_OK) != 0) {
		printf("cfg_sig_gen: %s is not built\n", builder);
		return 2;
	}
	DS = calloc(1, sizeof *DS);
	snprintf(root, sizeof root, "build/kof_cfgsiggen_XXXXXX");
	if (!mkdtemp(root)) {
		printf("cfg_sig_gen: cannot make a scratch directory\n");
		return 2;
	}
	snprintf(dir, sizeof dir, "%s/diagnoses", root);
	kof_mkdir(dir, 0700);
	write_catalogs(root);
	chain(&g[0], 24);
	chain(&g[1], 14);
	chain(&g[2], 8);
	CK(cs_build(&O, g, 3, 0x40));
	CK(sign_fn(&O, 0, &cs) == KOF_CFGSIGN_SIGNED);
	S0 = cs.sign;
	CK(sign_fn(&O, 1, &cs) == KOF_CFGSIGN_SIGNED);
	S1 = cs.sign;
	CK(sign_fn(&O, 2, &cs) == KOF_CFGSIGN_SIGNED && cs.sign.n_blk == 8u);    /* 8 blocks: below the old floor, signed now */
	generate_and_match();
	floor_of_the_block();
	save_round_trip();
	small_function_round_trip();
	if (!fails) {
		snprintf(cmd, sizeof cmd, "rm -rf '%s'", root);
		(void)system(cmd);
	}
	if (fails) {
		printf("cfg_sig_gen: %d FAIL\n", fails);
		return 1;
	}
	printf("cfg_sig_gen: ok\n");
	return 0;
}
