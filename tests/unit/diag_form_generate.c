/*
 * diag_form_generate - GENERATE writes the detection part of a unit, and what it writes is detected.
 *
 * The owner's decision: the declarations a signature used to make (strings, a region, a similarity block, an expression over
 * matchers) are a diagnose's now, and the editor's Generate button writes them. This is the whole chain from a DRAFT to a
 * verdict, with no hand-written source in the middle:
 *
 *   a draft         the panel's own model: markers (text, hex, wide, case and word options), matchers (ALL, ANY, at least n,
 *                   AT), conditions (an expression over matcher numbers), a block and its matcher
 *   Generate        draft_generate: one `<type>_<family>_<tag>_NN.c` per unit, four catalog lines and the detection part
 *   the builder     ksigbuilder --tree, with the catalogs of the fixture
 *   the engine      the database is opened and ELF files made for the purpose are scanned
 *
 * EVERY CASE ASKS BOTH ANSWERS - a file that must match and one that must not. WHAT IS PINNED
 *   writes     one file per unit with the composed name, every file read back by the reader the builder uses (Generate does
 *              it itself before it writes, and so does this), no file is half written
 *   semantics  a marker with a byte a literal cannot spell (0x01, 0xFF) is found as the same bytes through a hex pattern;
 *              a hex pattern keeps its wildcard; a wide marker is found as UTF-16; case and whole-word options reach the
 *              engine; a threshold of 2 of 3 is 2 of 3; an AT matcher compares at the start of the file; the expression
 *              (&, |, !, parentheses) is the author's; a block is scored by the set it was cut for
 *   refusals   what a source cannot say is refused with its reason and NOTHING is written: a regex (the panel has no wire), a
 *              wide marker with a byte above 0x7F, an AT matcher over two markers, an empty marker, a hex pattern of more than
 *              511 characters, an expression naming no matcher or one that is not there, a condition naming a block matcher, a
 *              block of 15 hashes, a region none of the header's formats names, more than sixteen markers in a matcher
 *   work       a draft's output, built, loaded and run is deterministic: Generate twice into two directories gives the same bytes
 *
 * Why the old tests missed it: (a) Generate refused every unit ("owner decision pending"), so no row could ask whether what it
 * would write is right; the first assertion of every case below fails on the old tree.
 */

#define _GNU_SOURCE

#include <dirent.h>
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
#include <celllysis/mutation.h>
#include <kofmod/elf.h>
#include "../../libkofeng/scanners/scan.h"
#include "../../libkofeng/analyzers/parsers/kofformat.h"
#include "../../libkofeng/detectors/linkage/kofdiag.h"
#include <celllysis/nucleo.h>

static int failures;
static struct kof_editor E;
static char root[300];
static const char *dbdir = "build/test/databases-sigs";
static const char *builder = "build/release/bin/ksigbuilder";

static void ok(const char *what, int cond)
{
	if (!cond) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

#define OKF(cond, ...) do { if (!(cond)) { printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); failures++; } } while (0)

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

static uint8_t *read_file(const char *path, size_t *n)
{
	FILE *f = fopen(path, "rb");
	uint8_t *b;
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

static unsigned count_files(const char *dir)
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

static void rm_all(const char *dir)
{
	char cmd[800];

	snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
	(void)system(cmd);
}

/* THE CATALOG FIXTURE: family Mirai (Botnet and Rootkit), tags flood and c2 - what the draft's header and units name. */
static void write_catalogs(const char *base)
{
	struct kof_famcat_fam fam[8];
	struct kof_famcat_var var[8];
	struct kof_catstore *st = calloc(1, sizeof *st);
	struct kof_tagcat_tag tag[8];
	struct kof_tagcat tc;
	struct kof_famcat c;
	char dir[500];
	uint32_t f;

	snprintf(dir, sizeof dir, "%s/pathogens", base);
	kof_mkdir(dir, 0700);
	kof_famcat_init(&c, fam, 8, var, 8);
	kof_catstore_init(st);
	(void)kof_famcat_add_family(&c, "Mirai", NULL, (1u << KOF_MALTYPE_BOTNET) | (1u << KOF_MALTYPE_ROOTKIT), &f);
	(void)kof_famcat_save(&c, st, dir);
	snprintf(dir, sizeof dir, "%s/syndromes", base);
	kof_mkdir(dir, 0700);
	kof_tagcat_init(&tc, tag, 8);
	kof_catstore_init(st);
	(void)kof_tagcat_add(&tc, "flood", 1u << KOF_DISEASE_ACT_SCAN, 1u << KOF_DISEASE_OBJ_NETWORK, NULL);
	(void)kof_tagcat_add(&tc, "c2", 1u << KOF_DISEASE_ACT_C2, 1u << KOF_DISEASE_OBJ_NETWORK, NULL);
	(void)kof_tagcat_save(&tc, st, dir);
	free(st);
}

/* ---- the draft ----------------------------------------------------------------------- */

static struct decl *decl_text(const uint8_t *p, uint32_t n)
{
	struct decl *d = decl_push(&E);

	memset(d, 0, sizeof *d);
	d->bytes = malloc(n);
	memcpy(d->bytes, p, n);
	d->nbytes = d->len = n;
	return d;
}

static struct decl *decl_hex(const char *hexs)
{
	struct decl *d = decl_push(&E);

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

static void condition(const char *expr, uint8_t type, const char *tag)
{
	struct cond *c = &E.dr.cnd[E.dr.n_cnd++];

	memset(c, 0, sizeof *c);
	snprintf(c->expr, sizeof c->expr, "%s", expr);
	c->utype = (uint8_t)(type + 1u);
	snprintf(c->tag, sizeof c->tag, "%s", tag);
}

static void free_draft(void)
{
	uint32_t i;

	for (i = 0; i < E.dr.n_decl; i++)
		free(E.dr.decl[i].bytes);
	free(E.dr.decl);
	free(E.dr.blk);
	memset(&E.dr, 0, sizeof E.dr);
}

static void header(void)
{
	memset(&E.dr, 0, sizeof E.dr);
	snprintf(E.dr.family, sizeof E.dr.family, "Mirai");
	snprintf(E.dr.variant, sizeof E.dr.variant, "Mirai_A");
	E.dr.fmt_mask = 1u << KOF_FMT_ELF;
}

/* ---- the objects ----------------------------------------------------------------------- */

static void put16(uint8_t *b, unsigned at, uint16_t v) { b[at] = (uint8_t)v; b[at + 1u] = (uint8_t)(v >> 8); }
static void put32(uint8_t *b, unsigned at, uint32_t v) { put16(b, at, (uint16_t)v); put16(b, at + 2u, (uint16_t)(v >> 16)); }
static void put64(uint8_t *b, unsigned at, uint64_t v) { put32(b, at, (uint32_t)v); put32(b, at + 4u, (uint32_t)(v >> 32)); }

/* An ELF64 with the code at [0, 0x400) (R+X, entry 0x100) and data at [0x400, 0x600) (R+W). `code` and `data` are what the
 * test puts there: a list of (offset, bytes) pairs. */
struct put {
	uint32_t off, n;
	const void *p;
};

static size_t make_elf(uint8_t *b, const struct put *puts, unsigned np)
{
	unsigned i;

	memset(b, 0, 0x600);
	memcpy(b, "\177ELF\2\1\1", 7);
	put16(b, 16, 2);
	put16(b, 18, 0x3e);
	put32(b, 20, 1);
	put64(b, 24, 0x400100u);
	put64(b, 32, 64);
	put16(b, 52, 64);
	put16(b, 54, 56);
	put16(b, 56, 2);
	put32(b, 64, 1);
	put32(b, 68, 5);
	put64(b, 72, 0);
	put64(b, 80, 0x400000u);
	put64(b, 96, 0x400u);
	put64(b, 104, 0x400u);
	put64(b, 112, 0x1000u);
	put32(b, 120, 1);
	put32(b, 124, 6);
	put64(b, 128, 0x400u);
	put64(b, 136, 0x600400u);
	put64(b, 152, 0x200u);
	put64(b, 160, 0x200u);
	put64(b, 168, 0x1000u);
	for (i = 0; i < np; i++)
		memcpy(b + puts[i].off, puts[i].p, puts[i].n);
	return 0x600;
}

struct seen {
	char     matched[32][96];
	unsigned n;
};

static int on_object(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct seen *s = user;
	uint32_t i;

	(void)name; (void)bytes; (void)len;
	for (i = 0; res && i < res->n_diag; i++)
		if (res->diag[i].state == KOF_DIAG_ST_MATCH && s->n < 32u) {
			unsigned k;

			for (k = 0; k < s->n; k++)
				if (!strcmp(s->matched[k], res->diag[i].name))
					break;
			if (k == s->n)
				snprintf(s->matched[s->n++], sizeof s->matched[0], "%s", res->diag[i].name);
		}
	return 0;
}

static int has(const struct seen *s, const char *name)
{
	unsigned i;

	for (i = 0; i < s->n; i++)
		if (!strcmp(s->matched[i], name))
			return 1;
	return 0;
}

static void scan(kof_scanner *sc, const void *p, size_t n, struct seen *out)
{
	struct kof_scan_option opt;

	memset(&opt, 0, sizeof opt);
	memset(out, 0, sizeof *out);
	(void)kof_scan_set_explain(sc, 1);
	kscan_bytes(sc, p, n, "sample", &opt, on_object, out);
}

/* ---- the whole draft ---------------------------------------------------------------------- */

#define CODE KOF_SCAN_ELF_CODE
#define DATA KOF_SCAN_ELF_DATA

static const uint8_t FUNNY[] = { 0x01, 0x02, 'a', 'b', 'c', 0xff };

static void full_draft(void)
{
	uint32_t g0, g1, g2, g3, g4, g5;

	header();
	/* markers */
	decl_text((const uint8_t *)"alpha-marker", 12u);                       /* 0 */
	decl_text(FUNNY, sizeof FUNNY);                                         /* 1: bytes a literal cannot spell */
	decl_hex("DE AD ?? EF 00 11");                                          /* 2 */
	{
		struct decl *w = decl_text((const uint8_t *)"IEX(New", 7u);     /* 3: UTF-16 */

		w->wide = 1;
	}
	{
		struct decl *c = decl_text((const uint8_t *)"CaseMark", 8u);    /* 4: case folded, a whole word */

		c->icase = 1;
		c->fullword = KOF_WORD_FULLWORD;
	}
	decl_text((const uint8_t *)"\x7f" "ELF", 4u);                             /* 5: the ELF magic, at the start */
	decl_text((const uint8_t *)"plain-data", 10u);                          /* 6 */
	/* matchers */
	g0 = matcher(1, 0, CODE);                      /* ANY of 0, 1 in the code */
	use(0, g0);
	use(1, g0);
	g1 = matcher(0, 0, CODE);                      /* ALL of 2, 4 in the code */
	use(2, g1);
	use(4, g1);
	g2 = matcher(2, 2, CODE);                      /* 2 of (0, 3, 4) in the code */
	use(0, g2);
	use(3, g2);
	use(4, g2);
	g3 = matcher(3, 0, 0);                         /* 5 AT the start */
	E.dr.grp[g3].at_anchor = KOF_ANCHOR_BOF;
	E.dr.grp[g3].at_off = 0;
	use(5, g3);
	g4 = matcher(1, 0, DATA);                      /* ANY of 6 in the data */
	use(6, g4);
	g5 = matcher(1, 0, KOF_SCAN_ALL);              /* ANY of 6 anywhere */
	use(6, g5);
	/* conditions: 1 & 2   |   3 | !1   |   4 & 5 (at the start and plain data in data)   |   (1 | 2) & !5 */
	condition("1&2", KOF_MALTYPE_BOTNET, "flood");
	condition("3|!1", KOF_MALTYPE_BOTNET, "flood");
	condition("4&5", KOF_MALTYPE_ROOTKIT, "c2");
	condition("(1|2)&!5", KOF_MALTYPE_ROOTKIT, "c2");
	(void)g4; (void)g5;
}

#define BLK 2048u

static void make_bytes(uint8_t *b, uint32_t seed)
{
	uint32_t i;

	for (i = 0; i < BLK; i++) {
		seed ^= seed << 13;
		seed ^= seed >> 17;
		seed ^= seed << 5;
		b[i] = (uint8_t)seed;
	}
}

/* A block of the seeded bytes, as the panel makes one when the researcher marks it: hashes from the engine, regions in the
 * engine's spelling. */
static uint32_t add_block(uint32_t seed, const char *rgn_enum)
{
	uint8_t b[BLK];
	struct mtn_block *k;

	if (!E.dr.blk)
		E.dr.blk = calloc(8, sizeof *E.dr.blk);
	make_bytes(b, seed);
	k = &E.dr.blk[E.dr.n_blk];
	memset(k, 0, sizeof *k);
	k->n_hash = kgenome_mutation_minhash(b, BLK, k->hash);
	snprintf(k->rgn_enum, sizeof k->rgn_enum, "%s", rgn_enum);
	return E.dr.n_blk++;
}

static uint32_t sim_matcher(uint32_t blk, uint8_t pct, uint8_t type, const char *tag)
{
	struct group *q = &E.dr.grp[E.dr.n_grp];

	memset(q, 0, sizeof *q);
	q->kind = (uint8_t)GRP_KIND_SIM;
	q->n_sim = 1;
	q->sim[0].what = SIM_IT_BLOCK;
	q->sim[0].blk = blk;
	q->pct = pct;
	q->utype = (uint8_t)(type + 1u);
	snprintf(q->tag, sizeof q->tag, "%s", tag);
	return E.dr.n_grp++;
}

/* ---- run it: generate, build, load, scan ---------------------------------------------------- */

struct scene {
	char base[400], art[400], db[400], gen[420], err[400];
};

static void scene_new(struct scene *s, const char *tag)
{
	char p[500], a[500];
	size_t n = 0;
	uint8_t *b;

	snprintf(s->base, sizeof s->base, "%s/%s_base", root, tag);
	snprintf(s->art, sizeof s->art, "%s/%s_art", root, tag);
	snprintf(s->db, sizeof s->db, "%s/%s_db", root, tag);
	snprintf(s->gen, sizeof s->gen, "%s/diagnoses", s->base);
	snprintf(s->err, sizeof s->err, "%s/%s_err.txt", root, tag);
	kof_mkdir(s->base, 0700);
	kof_mkdir(s->art, 0700);
	kof_mkdir(s->db, 0700);
	kof_mkdir(s->gen, 0700);
	write_catalogs(s->base);
	snprintf(a, sizeof a, "%s/sigs-any.ksig", dbdir);
	snprintf(p, sizeof p, "%s/sigs-any.ksig", s->db);
	b = read_file(a, &n);
	if (b)
		(void)write_file(p, b, n);
	free(b);
}

static int build(struct scene *s)
{
	char cmd[4400];

	snprintf(cmd, sizeof cmd, "%s --tree '%s' '%s' '%s' --pathogens '%s/pathogens' --syndromes '%s/syndromes' --basedir '%s' "
		 ">'%s.out' 2>'%s'", builder, s->base, s->art, s->db, s->base, s->base, s->base, s->err, s->err);
	return system(cmd);
}

/* The text of a file Generate wrote. */
static char *gen_file(const struct scene *s, const char *leaf)
{
	char p[700];
	size_t n = 0;

	snprintf(p, sizeof p, "%s/%s", s->gen, leaf);
	return (char *)read_file(p, &n);
}

/* ---- what each field of a draft becomes in the file, and the edges of what can be written ---------------------------------- */

static int count_of(const char *t, const char *needle)
{
	int n = 0;

	for (; (t = strstr(t, needle)) != NULL; t += strlen(needle))
		n++;
	return n;
}

static char *generated(struct scene *sc, const char *tag, const char *leaf)
{
	char msg[300];

	scene_new(sc, tag);
	if (draft_generate(&E, sc->gen, msg, sizeof msg) < 0) {
		printf("    %s: %s\n", tag, msg);
		return NULL;
	}
	return gen_file(sc, leaf);
}

static void field_semantics(void)
{
	struct scene sc;
	char *t;
	uint32_t g1, g2, g3, g4;

	/* markers: a pattern declared from a selection (hex, no text) has no options; a literal has them; a pattern has the author's */
	header();
	decl_text((const uint8_t *)"abcd", 4u)->icase = 1;
	E.dr.decl[0].hex = DECL_HEX;                      /* concrete bytes of a hex selection: the panel applied no option to them */
	decl_text((const uint8_t *)"efgh", 4u)->fullword = KOF_WORD_TOKEN;
	decl_hex("DE AD BE EF 00");
	E.dr.decl[2].icase = 1;                           /* an option the author set on a pattern: kept */
	decl_hex("CA FE BA BE 00");
	g1 = matcher(1, 0, CODE);
	use(0, g1); use(1, g1); use(2, g1); use(3, g1);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	t = generated(&sc, "f_opts", "botnet_mirai_flood_01.c");
	OKF(t != NULL, "the options draft is written");
	if (t) {
		OKF(strstr(t, "KOF_DEFINE_STR(s0, \"abcd\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);"), "bytes of a hex selection carry no option: %s", t);
		OKF(strstr(t, "KOF_DEFINE_STR(s1, \"efgh\", KOF_CASE_EXACT, KOF_WORD_TOKEN);"), "a literal's whole-token option is written");
		OKF(strstr(t, "KOF_DEFINE_HEXSTR(s2, \"DE AD BE EF 00\", KOF_CASE_ICASE, KOF_WORD_SUBSTRING);"), "an option the author set on a pattern is kept");
		OKF(strstr(t, "KOF_DEFINE_HEXSTR(s3, \"CA FE BA BE 00\");"), "a pattern with no option is the short form");
		free(t);
	}
	free_draft();

	/* bytes that need hex: the options of a literal go with them */
	header();
	{
		static const uint8_t funny[] = { 0x01, 'a', 'b', 'c', 0xff };
		struct decl *d = decl_text(funny, sizeof funny);

		d->icase = 1;
		d->fullword = KOF_WORD_FULLWORD;
	}
	g1 = matcher(1, 0, CODE);
	use(0, g1);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	t = generated(&sc, "f_funnyopt", "botnet_mirai_flood_01.c");
	OKF(t && strstr(t, "KOF_DEFINE_HEXSTR(s0, \"01 61 62 63 FF\", KOF_CASE_ICASE, KOF_WORD_FULLWORD);"), "a literal with hex bytes keeps its options (upper case hex)");
	free(t);
	free_draft();

	/* a wide marker and an exact 170 byte marker that needs hex are fine; the boundary is 171 (refused above) */
	header();
	{
		uint8_t b[170];

		memset(b, 0x02, sizeof b);
		decl_text(b, sizeof b);
	}
	g1 = matcher(1, 0, CODE);
	use(0, g1);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	t = generated(&sc, "f_170", "botnet_mirai_flood_01.c");
	OKF(t != NULL && count_of(t, "02") >= 170, "a 170 byte marker that needs hex is written");
	free(t);
	free_draft();
	/* a hex pattern of exactly 511 characters */
	header();
	{
		char h[600];
		size_t at = 0;
		unsigned i;

		/* 170 tokens and 169 separators are 509 characters; two of the separators doubled make exactly 511 */
		for (i = 0; i < 170u; i++)
			at += (size_t)snprintf(h + at, sizeof h - at, "%s41", i ? ((i == 50u || i == 100u) ? "  " : " ") : "");
		decl_hex(h);
	}
	g1 = matcher(1, 0, CODE);
	use(0, g1);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	t = generated(&sc, "f_hex511", "botnet_mirai_flood_01.c");
	OKF(t != NULL, "a hex pattern of 511 characters is written");
	free(t);
	free_draft();

	/* ranges: matchers over the same mask share one; the whole file is KOF_SCAN_ALL; another mask is another range */
	header();
	decl_text((const uint8_t *)"abc", 3u);
	decl_text((const uint8_t *)"def", 3u);
	decl_text((const uint8_t *)"ghi", 3u);
	g1 = matcher(1, 0, CODE);
	g2 = matcher(0, 0, CODE);
	g3 = matcher(1, 0, KOF_SCAN_ALL);
	g4 = matcher(1, 0, DATA);
	use(0, g1); use(1, g2); use(2, g3); use(0, g4);
	condition("1&2&3&4", KOF_MALTYPE_BOTNET, "flood");
	t = generated(&sc, "f_ranges", "botnet_mirai_flood_01.c");
	OKF(t != NULL, "the ranges draft is written");
	if (t) {
		OKF(count_of(t, "KOF_TARGET_RANGE(") == 3, "four matchers over three distinct masks make three ranges (%d)", count_of(t, "KOF_TARGET_RANGE("));
		OKF(strstr(t, "KOF_TARGET_RANGE(r0, KOF_SCAN_ELF_CODE);") && strstr(t, "KOF_TARGET_RANGE(r1, KOF_SCAN_ALL);") &&
		    strstr(t, "KOF_TARGET_RANGE(r2, KOF_SCAN_ELF_DATA);"), "in the order the matchers use them, spelled in the format's words");
		OKF(strstr(t, "KOF_DIAG_FIND(m1, KOF_FIND_ANY, r0, s0);") && strstr(t, "KOF_DIAG_FIND(m2, KOF_FIND_ALL, r0, s1);") &&
		    strstr(t, "KOF_DIAG_FIND(m3, KOF_FIND_ANY, r1, s2);") && strstr(t, "KOF_DIAG_FIND(m4, KOF_FIND_ANY, r2, s0);"),
		    "each matcher names its own range and its own markers (a marker two matchers use is declared once)");
		OKF(strstr(t, "KOF_DIAG_EXPR(m1 && m2 && m3 && m4);"), "and the expression is over them");
		OKF(count_of(t, "KOF_DEFINE_STR(") == 3, "three markers, once each");
		free(t);
	}
	free_draft();

	/* AT from each anchor, with a step */
	header();
	decl_text((const uint8_t *)"abc", 3u);
	g1 = matcher(3, 0, 0);
	E.dr.grp[g1].at_anchor = KOF_ANCHOR_ENTRY;
	E.dr.grp[g1].at_off = 8;
	use(0, g1);
	g2 = matcher(3, 0, 0);
	E.dr.grp[g2].at_anchor = KOF_ANCHOR_EOF;
	E.dr.grp[g2].at_off = -4;
	use(0, g2);
	g3 = matcher(3, 0, 0);
	E.dr.grp[g3].at_anchor = KOF_ANCHOR_BOF;
	E.dr.grp[g3].at_off = 100;
	use(0, g3);
	condition("1&2&3", KOF_MALTYPE_BOTNET, "flood");
	t = generated(&sc, "f_at", "botnet_mirai_flood_01.c");
	OKF(t != NULL, "the AT draft is written");
	if (t) {
		OKF(strstr(t, "KOF_DIAG_FIND(m1, KOF_FIND_AT(KOF_ANCHOR_ENTRY, 8), s0);") != NULL, "AT the entry point, 8 after it");
		OKF(strstr(t, "KOF_DIAG_FIND(m2, KOF_FIND_AT(KOF_ANCHOR_EOF, -4), s0);") != NULL, "AT the end, 4 before it");
		OKF(strstr(t, "KOF_DIAG_FIND(m3, KOF_FIND_AT(KOF_ANCHOR_BOF, 100), s0);") != NULL, "AT the start, 100 after it");
		OKF(count_of(t, "KOF_TARGET_RANGE(") == 0, "an AT matcher names no range");
		free(t);
	}
	free_draft();

	/* a threshold of 2 of 3: written, and 3 of 3 as ALL */
	header();
	decl_text((const uint8_t *)"abc", 3u);
	decl_text((const uint8_t *)"def", 3u);
	decl_text((const uint8_t *)"ghi", 3u);
	g1 = matcher(2, 3, CODE);
	use(0, g1); use(1, g1); use(2, g1);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	t = generated(&sc, "f_multi", "botnet_mirai_flood_01.c");
	OKF(t && strstr(t, "KOF_FIND_MULTI(3)"), "a threshold of 3 of 3 is written as asked");
	free(t);
	free_draft();

	/* blocks: the normalizer, the side and the region are the block's own */
	header();
	g1 = add_block(0xA11CE5u, "KOF_SCAN_ELF_CODE");
	E.dr.blk[g1].side = (uint8_t)KGENOME_MUTATION_SIDE_LIB;
	sim_matcher(g1, 80, KOF_MALTYPE_BOTNET, "flood");
	g2 = add_block(0xB0B0B0u, "KOF_SCAN_ALL");
	sim_matcher(g2, 33, KOF_MALTYPE_ROOTKIT, "c2");
	scene_new(&sc, "f_blocks");
	{
		char msg[300];

		OKF(draft_generate(&E, sc.gen, msg, sizeof msg) == 2, "two block units are written (%s)", msg);
	}
	t = gen_file(&sc, "botnet_mirai_flood_01.c");
	OKF(t && strstr(t, "KOF_MUTATION_BLOCK_LIB(b0, KOF_SCAN_ELF_CODE, 0x") && strstr(t, "KOF_DIAG_SIMILAR(m1, 80, b0);"),
	    "a library block cut from the code, at 80 percent");
	OKF(t && !strstr(t, "KOF_MUTATION_RAW") && !strstr(t, "KOF_MUTATION_XOR") && !strstr(t, "KOF_MUTATION_SUB") &&
	    !strstr(t, "KOF_MUTATION_ROT"), "the generator writes no normalizer word at all (the argument is gone, and with it XOR and SUB)");
	free(t);
	t = gen_file(&sc, "rootkit_mirai_c2_01.c");
	OKF(t && strstr(t, "KOF_MUTATION_BLOCK(b1, KOF_SCAN_ALL, 0x") && strstr(t, "KOF_DIAG_SIMILAR(m2, 33, b1);"),
	    "an ordinary block taken from anywhere, at 33 percent");
	free(t);
	free_draft();
}

static void whole_chain(void)
{
	struct scene sc;
	char msg[300];
	int n;
	kof_engine *eng;
	kof_scanner *scn;
	struct seen s;
	uint8_t elf[0x600];
	uint8_t wide[14];
	unsigned i;
	char *t;
	struct kof_dsrc *d = calloc(1, sizeof *d);
	struct kof_dsrc_view v;
	static const char *const files[4] = { "botnet_mirai_flood_01.c", "botnet_mirai_flood_02.c", "rootkit_mirai_c2_01.c",
					      "rootkit_mirai_c2_02.c" };

	for (i = 0; i < 7u; i++)
		wide[i * 2u] = (uint8_t)"IEX(New"[i], wide[i * 2u + 1u] = 0;
	scene_new(&sc, "chain");
	full_draft();
	n = draft_generate(&E, sc.gen, msg, sizeof msg);
	OKF(n == 4, "Generate writes four files (%s)", msg);
	OKF(count_files(sc.gen) == 4u, "and four are there");
	for (i = 0; i < 4u; i++) {
		t = gen_file(&sc, files[i]);
		OKF(t != NULL, "%s was written", files[i]);
		if (t) {
			struct kof_dsrc_report rp = { NULL, NULL, NULL };

			memset(&v, 0, sizeof v);
			OKF(kof_dsrc_parse(t, strlen(t), d, &rp) == 0 && kof_dsrc_resolve(d, &v, &rp) == 0 && v.form,
			    "%s reads and resolves with the builder's own reader", files[i]);
			OKF(strstr(t, "KOF_DIAG_FAMILY(\"Mirai\");") && strstr(t, "KOF_DIAG_VARIANT(\"A\");") && strstr(t, "KOF_DIAG_TAG("),
			    "%s carries the four catalog lines", files[i]);
			kof_dsrc_view_free(&v);
		}
		free(t);
	}
	/* what the first one says: strings 0, 1, 2, 4 as the engine will search for them */
	t = gen_file(&sc, files[0]);
	if (t) {
		OKF(strstr(t, "KOF_DEFINE_STR(s0, \"alpha-marker\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);"), "a plain marker is a literal");
		OKF(strstr(t, "KOF_DEFINE_HEXSTR(s1, \"01 02 61 62 63 FF\");"), "a marker with bytes a literal cannot spell is a hex pattern of the same bytes");
		OKF(strstr(t, "KOF_DEFINE_HEXSTR(s2, \"DE AD ?? EF 00 11\");"), "a hex pattern keeps its wildcard, and no options it did not have");
		OKF(strstr(t, "KOF_DEFINE_STR(s4, \"CaseMark\", KOF_CASE_ICASE, KOF_WORD_FULLWORD);"), "case and word options are written");
		OKF(strstr(t, "KOF_TARGET_RANGE(r0, KOF_SCAN_ELF_CODE);"), "the range is the format's own word");
		OKF(strstr(t, "KOF_DIAG_FIND(m1, KOF_FIND_ANY, r0, s0, s1);") && strstr(t, "KOF_DIAG_FIND(m2, KOF_FIND_ALL, r0, s2, s4);"),
		    "the matchers are the author's rules over the author's markers");
		OKF(strstr(t, "KOF_DIAG_EXPR(m1 && m2);"), "and the expression is the author's: 1&2");
		OKF(!strstr(t, "s3") && !strstr(t, "s5") && !strstr(t, "m3"), "a marker or a matcher the condition does not name is not in its file");
		free(t);
	}
	t = gen_file(&sc, files[1]);
	if (t) {
		OKF(strstr(t, "KOF_DEFINE_STR_WIDE(s3, \"IEX(New\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);"), "a wide marker is a wide literal");
		OKF(strstr(t, "KOF_FIND_MULTI(2)") != NULL, "at least two of three is MULTI(2)");
		OKF(strstr(t, "KOF_DIAG_EXPR(m3 || !m1);") != NULL, "3|!1 is m3 || !m1");
		free(t);
	}
	t = gen_file(&sc, files[2]);
	if (t) {
		OKF(strstr(t, "KOF_DIAG_FIND(m4, KOF_FIND_AT(KOF_ANCHOR_BOF, 0), s5);") != NULL, "AT carries its anchor and step");
		OKF(strstr(t, "KOF_DEFINE_HEXSTR(s5, \"7F 45 4C 46\");") != NULL, "a byte a literal cannot spell (0x7F) is hex");
		free(t);
	}
	OKF(build(&sc) == 0, "the generated files build");
	eng = keng_open(sc.db);
	scn = eng ? kscan_new(eng) : NULL;
	if (!scn) {
		OKF(0, "the generated database does not open");
		free(d);
		return;
	}
	OKF(kdb_diagnoses(eng) == 4u && kdb_diag_refused(eng) == 0u, "four diagnoses loaded, none refused");
	{
		/* 1: everything in the code: alpha, the funny bytes, DE AD xx EF 00 11, CaseMark, IEX wide, plain-data in data */
		static const uint8_t dead[] = { 0xde, 0xad, 0x99, 0xef, 0x00, 0x11 };
		struct put all[] = { { 0x120, 12u, "alpha-marker" }, { 0x140, sizeof FUNNY, FUNNY }, { 0x160, sizeof dead, dead },
				     { 0x180, 8u, "CaseMark" }, { 0x1a0, 14u, wide }, { 0x500, 10u, "plain-data" } };

		make_elf(elf, all, 6u);
		scan(scn, elf, 0x600, &s);
		ok("everything present: 1&2 fires", has(&s, "botnet_mirai_flood_01"));
		ok("3|!1: 3 (2 of 3) holds, so it fires", has(&s, "botnet_mirai_flood_02"));
		ok("4&5: the magic at the start and the plain data in the data fires", has(&s, "rootkit_mirai_c2_01"));
		ok("(1|2)&!5: 1 holds and 5 holds, so the NOT fails", !has(&s, "rootkit_mirai_c2_02"));
	}
	{
		/* the hex wildcard really is one: the byte after DE AD is not what the test of 'everything' used */
		static const uint8_t dead[] = { 0xde, 0xad, 0x00, 0xef, 0x00, 0x11 };
		struct put some[] = { { 0x120, 12u, "alpha-marker" }, { 0x140, sizeof FUNNY, FUNNY }, { 0x160, sizeof dead, dead },
				      { 0x180, 8u, "CASEMARK" } };

		make_elf(elf, some, 4u);
		scan(scn, elf, 0x600, &s);
		ok("a hex wildcard is any byte, and CASEMARK is found by a case folded marker", has(&s, "botnet_mirai_flood_01"));
		ok("without the plain data in the data 5 is false, so (1|2)&!5 fires", has(&s, "rootkit_mirai_c2_02"));
		ok("and 4&5 does not", !has(&s, "rootkit_mirai_c2_01") || 0);
	}
	{
		/* a whole word: CaseMark followed by a word byte is not it */
		static const uint8_t dead[] = { 0xde, 0xad, 0x00, 0xef, 0x00, 0x11 };
		struct put nw[] = { { 0x120, 12u, "alpha-marker" }, { 0x160, sizeof dead, dead }, { 0x180, 9u, "CaseMarkX" } };

		make_elf(elf, nw, 3u);
		scan(scn, elf, 0x600, &s);
		ok("CaseMarkX is not the whole word CaseMark: 1&2 does not fire", !has(&s, "botnet_mirai_flood_01"));
	}
	{
		/* the markers in the DATA when the range names the code: no */
		static const uint8_t dead[] = { 0xde, 0xad, 0x00, 0xef, 0x00, 0x11 };
		struct put wrong[] = { { 0x420, 12u, "alpha-marker" }, { 0x440, sizeof FUNNY, FUNNY }, { 0x460, sizeof dead, dead },
				       { 0x480, 8u, "CaseMark" } };

		make_elf(elf, wrong, 4u);
		scan(scn, elf, 0x600, &s);
		ok("markers in the data are not found by a range that names the code", !has(&s, "botnet_mirai_flood_01"));
	}
	{
		/* nothing: 3|!1 is true on an empty file (the NOT), the others are not */
		make_elf(elf, NULL, 0u);
		scan(scn, elf, 0x600, &s);
		ok("an ELF with none of it: !1 holds, so 3|!1 fires, and nothing else does",
		   has(&s, "botnet_mirai_flood_02") && !has(&s, "botnet_mirai_flood_01") && !has(&s, "rootkit_mirai_c2_01"));
	}
	{
		/* AT the start of the file: the ELF magic is there in every ELF; a file that starts otherwise is not it */
		uint8_t other[0x600];
		struct put none[1];

		(void)none;
		make_elf(other, NULL, 0u);
		other[0] = 0x00;
		scan(scn, other, 0x600, &s);
		ok("a file whose first bytes are not the magic does not fire AT", !has(&s, "rootkit_mirai_c2_01"));
	}
	kscan_free(scn);
	keng_close(eng);
	free(d);
}

static void determinism(void)
{
	struct scene a, b;
	char msg[300];
	unsigned i;
	char *ta, *tb;
	static const char *const files[4] = { "botnet_mirai_flood_01.c", "botnet_mirai_flood_02.c", "rootkit_mirai_c2_01.c",
					      "rootkit_mirai_c2_02.c" };

	scene_new(&a, "det_a");
	scene_new(&b, "det_b");
	full_draft();
	OKF(draft_generate(&E, a.gen, msg, sizeof msg) == 4 && draft_generate(&E, b.gen, msg, sizeof msg) == 4, "two Generates write");
	for (i = 0; i < 4u; i++) {
		ta = gen_file(&a, files[i]);
		tb = gen_file(&b, files[i]);
		OKF(ta && tb && !strcmp(ta, tb), "%s is the same bytes both times", files[i]);
		free(ta);
		free(tb);
	}
	/* Generate never replaces a file, and never writes a unit twice: the second press finds the four in the tree and writes none */
	OKF(draft_generate(&E, a.gen, msg, sizeof msg) == 0 && strstr(msg, "Nothing new to write") != NULL, "a second Generate into the same directory writes nothing: %s", msg);
	OKF(count_files(a.gen) == 4u, "and leaves the four files as they were");
}

/* ---- blocks --------------------------------------------------------------------------------- */

static void block_units(void)
{
	struct scene sc;
	char msg[400];
	kof_engine *eng;
	kof_scanner *scn;
	struct seen s;
	uint8_t a[BLK], b[BLK], c[BLK], ab[2u * BLK];
	uint32_t k;
	char *t;

	scene_new(&sc, "blocks");
	header();
	E.dr.fmt_mask = 1u << KOF_FMT_UNKNOWN;            /* the objects below are blobs */
	k = add_block(0xA11CE5u, "KOF_SCAN_ALL");
	sim_matcher(k, 60, KOF_MALTYPE_BOTNET, "flood");
	k = add_block(0xB0B0B0u, "KOF_SCAN_ALL");
	sim_matcher(k, 60, KOF_MALTYPE_ROOTKIT, "c2");
	OKF(draft_generate(&E, sc.gen, msg, sizeof msg) == 2, "two block matchers are two files (%s)", msg);
	t = gen_file(&sc, "botnet_mirai_flood_01.c");
	if (t) {
		OKF(strstr(t, "KOF_TARGET_FORMAT(KOF_FMT_UNKNOWN);") != NULL, "the header's format");
		OKF(strstr(t, "KOF_MUTATION_BLOCK(b0, KOF_SCAN_ALL, 0x") != NULL, "a block anywhere in the file is ALL");
		OKF(strstr(t, "KOF_DIAG_SIMILAR(m1, 60, b0);") != NULL, "the matcher carries the author's percentage");
		free(t);
	}
	OKF(build(&sc) == 0, "the block files build");
	eng = keng_open(sc.db);
	scn = eng ? kscan_new(eng) : NULL;
	if (!scn) {
		OKF(0, "the block database does not open");
		return;
	}
	make_bytes(a, 0xA11CE5u);
	make_bytes(b, 0xB0B0B0u);
	make_bytes(c, 0xC0FFEEu);
	memcpy(ab, a, BLK);
	memcpy(ab + BLK, b, BLK);
	scan(scn, a, BLK, &s);
	ok("the block of A scores on A: its diagnose fires and the other does not", has(&s, "botnet_mirai_flood_01") && !has(&s, "rootkit_mirai_c2_01"));
	scan(scn, b, BLK, &s);
	ok("the block of B scores on B and not on A's", has(&s, "rootkit_mirai_c2_01") && !has(&s, "botnet_mirai_flood_01"));
	scan(scn, c, BLK, &s);
	ok("an unrelated object scores nothing", !s.n);
	scan(scn, ab, 2u * BLK, &s);
	ok("the two together: each fires", has(&s, "rootkit_mirai_c2_01") && has(&s, "botnet_mirai_flood_01"));
	{
		/* the same blob in an ELF header's company: the format of the header is UNKNOWN, an ELF is another shape */
		uint8_t elf[0x600];

		make_elf(elf, &(struct put){ 0x40, 0x400u - 0x40u, a }, 1u);
		scan(scn, elf, 0x600, &s);
		ok("an object of another format is not asked (the header says UNKNOWN)", !has(&s, "botnet_mirai_flood_01"));
	}
	kscan_free(scn);
	keng_close(eng);
	free_draft();
}

/* ---- the options a signature's targets had: a minimum size and an architecture ------------------- */

static char why_buf[400];

static int fires_with(const char *tag, int opt, uint64_t val, const char **why_out)
{
	struct scene sc;
	char msg[400];
	kof_engine *eng;
	kof_scanner *scn;
	struct seen s;
	uint8_t elf[0x600];
	int hit = -1;
	static const char *const file = "botnet_mirai_flood_01";

	scene_new(&sc, tag);
	header();
	decl_text((const uint8_t *)"alpha-marker", 12u);
	use(0, matcher(1, 0, CODE));
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	E.dr.opt_on[opt] = 1;
	E.dr.opt_val[opt] = val;
	if (draft_generate(&E, sc.gen, msg, sizeof msg) != 1) {
		memcpy(why_buf, msg, sizeof why_buf);   /* msg is this frame's: the caller reads a copy that outlives it */
		*why_out = why_buf;
		free_draft();
		return -2;
	}
	{
		char *t = gen_file(&sc, "botnet_mirai_flood_01.c");

		if (t && opt == OPT_SIZE_MIN)
			OKF(strstr(t, "KOF_DIAG_HAS_ATTRB(KOF_FACT_SIZE_MIN, ") != NULL, "%s: the size is a line of the file", tag);
		if (t && opt == OPT_ARCH)
			OKF(strstr(t, "KOF_DIAG_HAS_ATTRB(KOF_FACT_ARCH_SET, ") != NULL, "%s: the architecture is a line of the file", tag);
		free(t);
	}
	if (build(&sc) == 0 && (eng = keng_open(sc.db)) != NULL) {
		static const struct put code[] = { { 0x120, 12u, "alpha-marker" } };

		scn = kscan_new(eng);
		make_elf(elf, code, 1u);
		if (scn) {
			scan(scn, elf, 0x600, &s);
			hit = has(&s, file);
		}
		kscan_free(scn);
		keng_close(eng);
	}
	free_draft();
	return hit;
}

static void options(void)
{
	const char *why = "";

	ok("a minimum size the file has: the diagnose fires", fires_with("opt_size_ok", OPT_SIZE_MIN, 0x600u, &why) == 1);
	ok("one byte more than the file has: it does not", fires_with("opt_size_big", OPT_SIZE_MIN, 0x601u, &why) == 0);
	ok("the file's architecture: it fires", fires_with("opt_arch_ok", OPT_ARCH, KOF_ARCH_X86_64, &why) == 1);
	ok("another architecture: it does not", fires_with("opt_arch_no", OPT_ARCH, KOF_ARCH_ARM64, &why) == 0);
	ok("a maximum size is refused (no condition for it), not dropped", fires_with("opt_size_max", OPT_SIZE_MAX, 0x600u, &why) == -2 &&
	   strstr(why, "maximum size") != NULL);
	ok("an architecture past the 64 a set holds is refused", fires_with("opt_arch_far", OPT_ARCH, 200u, &why) == -2 &&
	   strstr(why, "64") != NULL);
}

/* ---- refusals: what a source cannot say is refused with its reason, and nothing is written ---------- */

static void refusal(const char *what, const char *why, void (*mk)(void))
{
	struct scene sc;
	char msg[400];
	char tag[64];
	int rc;

	snprintf(tag, sizeof tag, "ref_%u", (unsigned)failures + (unsigned)(uintptr_t)what % 1000u);
	scene_new(&sc, tag);
	mk();
	rc = draft_generate(&E, sc.gen, msg, sizeof msg);
	if (rc >= 0 || !strstr(msg, why) || count_files(sc.gen) != 0u)
		printf("  %s: rc %d, \"%s\", %u file(s)\n", what, rc, msg, count_files(sc.gen));
	OKF(rc < 0 && strstr(msg, why) != NULL, "%s is refused with \"%s\"", what, why);
	OKF(count_files(sc.gen) == 0u, "%s writes nothing", what);
	free_draft();
}

static void one_cond(const char *expr, int rule, uint32_t thresh, uint32_t mask)
{
	uint32_t g = matcher(rule, thresh, mask);

	(void)expr;
	use(0, g);
}

static void mk_regex(void)
{
	header();
	decl_text((const uint8_t *)"abc", 3u);
	E.dr.decl[0].hex = DECL_RX;
	snprintf(E.dr.decl[0].hexs, sizeof E.dr.decl[0].hexs, "a[0-9]c");
	one_cond("1", 1, 0, CODE);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
}

static void mk_wide_high(void)
{
	static const uint8_t hi[] = { 'c', 'a', 'f', 0xc3, 0xa9 };

	header();
	decl_text(hi, sizeof hi)->wide = 1;
	one_cond("1", 1, 0, CODE);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
}

static void mk_at_two(void)
{
	header();
	decl_text((const uint8_t *)"abc", 3u);
	decl_text((const uint8_t *)"def", 3u);
	{
		uint32_t g = matcher(3, 0, 0);

		use(0, g);
		use(1, g);
	}
	condition("1", KOF_MALTYPE_BOTNET, "flood");
}

static void mk_empty_marker(void)
{
	header();
	decl_text((const uint8_t *)"abc", 3u);
	E.dr.decl[0].nbytes = 0;
	one_cond("1", 1, 0, CODE);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
}

static void mk_long_hex(void)
{
	char h[800];
	size_t at = 0;
	unsigned i;

	header();
	for (i = 0; i < 200u; i++)
		at += (size_t)snprintf(h + at, sizeof h - at, "%s41", i ? " " : "");
	decl_hex(h);
	one_cond("1", 1, 0, CODE);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
}

static void mk_no_matcher(void)
{
	header();
	decl_text((const uint8_t *)"abc", 3u);
	one_cond("1", 1, 0, CODE);
	condition("", KOF_MALTYPE_BOTNET, "flood");
}

static void mk_foreign(void)
{
	header();
	decl_text((const uint8_t *)"abc", 3u);
	one_cond("1", 1, 0, CODE);
	condition("1&7", KOF_MALTYPE_BOTNET, "flood");
}

static void mk_bad_char(void)
{
	header();
	decl_text((const uint8_t *)"abc", 3u);
	one_cond("1", 1, 0, CODE);
	condition("1^1", KOF_MALTYPE_BOTNET, "flood");
}

static void mk_few_hashes(void)
{
	uint32_t k;

	header();
	k = add_block(0xA11CE5u, "KOF_SCAN_ALL");
	E.dr.blk[k].n_hash = 15;
	sim_matcher(k, 60, KOF_MALTYPE_BOTNET, "flood");
}

static void mk_no_region_word(void)
{
	header();
	E.dr.fmt_mask = 0;                    /* no format: a code region has no name */
	decl_text((const uint8_t *)"abc", 3u);
	one_cond("1", 1, 0, CODE);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
}

static void mk_17_markers(void)
{
	uint32_t g, i;
	char w[8];

	header();
	g = matcher(1, 0, CODE);
	for (i = 0; i < 17u; i++) {
		snprintf(w, sizeof w, "mark%03u", i);
		decl_text((const uint8_t *)w, 7u);
		use(i, g);
	}
	condition("1", KOF_MALTYPE_BOTNET, "flood");
}

static void mk_sim_pct(void)
{
	uint32_t k;

	header();
	k = add_block(0xA11CE5u, "KOF_SCAN_ALL");
	sim_matcher(k, 101, KOF_MALTYPE_BOTNET, "flood");
}

static void mk_no_block(void)
{
	header();
	sim_matcher(0, 60, KOF_MALTYPE_BOTNET, "flood");
	E.dr.grp[0].n_sim = 0;
}

static void mk_bad_rgn(void)
{
	uint32_t k;

	header();
	k = add_block(0xA11CE5u, "KOF_SCAN_NOT_A_REGION");
	sim_matcher(k, 60, KOF_MALTYPE_BOTNET, "flood");
}

static void mk_thresh_over(void)
{
	uint32_t g;

	header();
	decl_text((const uint8_t *)"abc", 3u);
	decl_text((const uint8_t *)"def", 3u);
	decl_text((const uint8_t *)"ghi", 3u);
	g = matcher(2, 4, CODE);
	use(0, g);
	use(1, g);
	use(2, g);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
}

static void mk_matcher_empty(void)
{
	header();
	decl_text((const uint8_t *)"abc", 3u);
	(void)matcher(1, 0, CODE);                /* no marker uses it */
	condition("1", KOF_MALTYPE_BOTNET, "flood");
}

static void mk_wide_80(void)
{
	static const uint8_t hi[] = { 'a', 0x80 };

	header();
	decl_text(hi, sizeof hi)->wide = 1;
	one_cond("1", 1, 0, CODE);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
}

static void mk_funny_171(void)
{
	uint8_t b[171];

	memset(b, 0x01, sizeof b);
	header();
	decl_text(b, sizeof b);
	one_cond("1", 1, 0, CODE);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
}

static void mk_hex_512(void)
{
	char h[600];
	size_t at = 0;
	unsigned i;

	header();
	for (i = 0; i < 171u; i++)
		at += (size_t)snprintf(h + at, sizeof h - at, "%s41", i ? " " : "");
	h[at] = 0;                           /* 171 tokens and 170 separators: exactly 512 characters */
	decl_hex(h);
	one_cond("1", 1, 0, CODE);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
}

static void mk_hex_bad(void)
{
	header();
	decl_hex("ZZ ?? 41");
	one_cond("1", 1, 0, CODE);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
}

static void mk_hex_quote(void)
{
	header();
	decl_hex("41 \" 42 43 44 45");
	one_cond("1", 1, 0, CODE);
	condition("1", KOF_MALTYPE_BOTNET, "flood");
}

static void refusals(void)
{
	refusal("a regex marker", "regex marker", mk_regex);
	refusal("a wide marker with a byte above 0x7F", "wide marker", mk_wide_high);
	refusal("an AT matcher over two markers", "an AT matcher compares ONE marker", mk_at_two);
	refusal("an empty marker", "empty marker", mk_empty_marker);
	refusal("a hex pattern over 511 characters", "hex pattern over 511", mk_long_hex);
	refusal("a condition with no expression", "expression names no matcher", mk_no_matcher);
	refusal("a condition naming a matcher that is not there", "matcher that is not on this tab", mk_foreign);
	refusal("an expression with a character a diagnose cannot say", "character a diagnose cannot say", mk_bad_char);
	refusal("a block of 15 hashes", "a block has too few or too many hashes", mk_few_hashes);
	refusal("a region no format of the header names", "none of the formats the header targets", mk_no_region_word);
	refusal("a matcher of 17 markers", "a matcher lists more than sixteen markers", mk_17_markers);
	refusal("a threshold of 4 over 3 markers", "a threshold the matcher cannot reach", mk_thresh_over);
	refusal("a matcher with no marker", "names a matcher with no marker", mk_matcher_empty);
	refusal("a wide marker with the byte 0x80", "wide marker with a byte", mk_wide_80);
	refusal("a 171 byte marker that needs hex", "more than 170 bytes", mk_funny_171);
	refusal("a hex pattern of 512 characters", "hex pattern over 511 characters", mk_hex_512);
	refusal("a hex pattern the compiler refuses", "does not read", mk_hex_bad);
	refusal("a hex pattern with a quote in it", "cannot be written as source", mk_hex_quote);
	refusal("a threshold of 101 percent", "its threshold is not a percentage from 1 to 100", mk_sim_pct);
	refusal("a block matcher with no block", "holds no block", mk_no_block);
	refusal("a block whose region the reader does not know", "no name the source reader knows", mk_bad_rgn);
}

/* ---- the gate of the signature on the draft (kofeditor_gate.c): the engine's lists, the draft, Generate, the engine -----------
 *
 * Why the old tests missed it: (a) there was no gate - nothing here compiles against the old tree (draft_gate_offer,
 * kof_draft.gate, KOF_FACT_ANOMALY do not exist), the RED of a feature that was not there.
 *
 *   offers     the draft's anomaly offers ARE the bits of the engine's word for the object (kof_result.anomalies) and its
 *              nucleo offers ARE the engine's list for the object (kdet_nucleo_seen over the explain run), element for
 *              element; an offer the draft already states is not offered again
 *   add        a condition twice, NONE, an unknown anomaly value and the seventeenth are refused; the draft is edited by one
 *   Generate   writes KOF_DIAG_HAS_ANOMALY / KOF_DIAG_HAS_NUCLEO lines that the shared reader reads back, the builder builds and
 *              the engine answers: the draft's own sample fires, a capability it does not show blocks; sixteen gate conditions
 *              and a format line are seventeen, which Save refuses with the reader's reason and writes nothing
 *   run1       the golden fixture (tests/tui/golden/SAMPLES.txt): the viewer's lists (draft_gate_offer) equal the engine's, and
 *              every condition picked from them passes the engine's gate on run1 (YES, never UNKNOWN). A missing fixture FAILS.
 */
struct gstate {
	char    name[64][48];
	uint8_t state[64], gate[64];
	unsigned n;
	int     first;
	uint16_t caps[512];
	uint32_t n_caps;
	struct kof_result res;      /* the file's result, its borrowed pointers cleared (only n_* and the scalars are kept) */
};

static int on_gstate(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct gstate *g = user;
	uint32_t i;

	(void)bytes; (void)len;
	if (!res || g->first || strstr(name, KOF_OBJ_SEP))
		return 0;
	g->first = 1;
	g->n_caps = kdet_nucleo_seen(res, g->caps, 512u);
	for (i = 0; i < res->n_diag && g->n < 64u; i++) {
		snprintf(g->name[g->n], sizeof g->name[0], "%s", res->diag[i].name);
		g->state[g->n] = res->diag[i].state;
		/* the LAST condition: a generated unit states its format first and its gate after it */
		g->gate[g->n] = res->diag[i].n_gate ? res->diag[i].gate[res->diag[i].n_gate - 1u] : 0u;
		g->n++;
	}
	return 0;
}

static void gstate_scan(kof_scanner *sc, const void *p, size_t n, struct gstate *g)
{
	struct kof_scan_option opt;

	memset(&opt, 0, sizeof opt);
	memset(g, 0, sizeof *g);
	(void)kof_scan_set_explain(sc, 1);
	kscan_bytes(sc, p, n, "sample", &opt, on_gstate, g);
}

static int gstate_of(const struct gstate *g, const char *name, uint8_t *gate)
{
	unsigned i;

	for (i = 0; i < g->n; i++)
		if (!strcmp(g->name[i], name)) {
			*gate = g->gate[i];
			return g->state[i];
		}
	return -1;
}

/* The engine's explain run of `p` (the viewer's view_explain asks the same: kscan_explain); the caller frees the run. */
static kdet_run *explain_of(const char *db, const uint8_t *p, size_t n, const struct kof_result **res)
{
	kof_engine *eng = keng_open(db);
	kof_scanner *sc = eng ? kscan_new(eng) : NULL;
	kdet_run *run = NULL;
	struct kof_scan_option opt;
	const struct kdet_object *k;

	if (sc) {
		memset(&opt, 0, sizeof opt);
		run = kscan_explain(sc, p, n, "sample", &opt);
	}
	kscan_free(sc);
	keng_close(eng);
	k = run ? kdet_run_find(run, "sample") : NULL;
	*res = k ? &k->res : NULL;
	return run;
}

static const char MMAP_STUB[] = "\x31\xff\x6a\x09\x58\x99\xb6\x10\x48\x89\xd6\x4d\x31\xc9\x6a\x22\x41\x5a\x6a\x07\x5a\x0f\x05";

/* The offers equal the engine's lists (the result's anomaly word, bit by bit; kdet_nucleo_seen), element for element; the counts
 * come back through the pointers. */
static void offers_are_engine(const char *what, const struct kof_result *res, uint32_t *na, uint32_t *nn)
{
	struct kof_diag_when w[256];
	uint16_t caps[256];
	uint32_t a, n, nc, k, same = 1;

	a = draft_gate_offer(&E, (uint16_t)KOF_FACT_ANOMALY, res, w, 256u);
	for (k = 0, n = 0; k < 64u; k++) {
		uint64_t val = ((uint64_t)res->anomaly_fmt << 32) | k;

		if (((res->anomalies >> k) & 1u) && kof_diag_gate_valid((uint16_t)KOF_FACT_ANOMALY, val)) {
			same &= (uint32_t)(n < a && w[n].fact == KOF_FACT_ANOMALY && w[n].val == val);
			n++;
		}
	}
	OKF(same && a == n, "%s: the anomaly offers are the engine's word (%u offers, %u named bits)", what, a, n);
	*na = a;
	n = draft_gate_offer(&E, (uint16_t)KOF_FACT_NUCLEO, res, w, 256u);
	nc = kdet_nucleo_seen(res, caps, 256u);
	for (k = 0, same = 1; k < nc && k < 256u; k++)
		same &= (uint32_t)(k < n && w[k].fact == KOF_FACT_NUCLEO && w[k].val == caps[k]);
	OKF(same && n == nc, "%s: the nucleo offers are the engine's list (kdet_nucleo_seen): %u offers, %u listed", what, n, nc);
	*nn = n;
}

static void gate_draft(void)
{
	static uint8_t elf[0x600];
	static const struct put code[] = { { 0x100, sizeof MMAP_STUB - 1u, MMAP_STUB }, { 0x200, 12u, "alpha-marker" } };
	struct scene sc;
	const struct kof_result *res;
	struct kof_diag_when w[64];
	kdet_run *run;
	uint32_t na = 0, nn = 0, h0;
	char msg[400], txt[96];
	uint16_t absent = 0;

	make_elf(elf, code, 2u);
	/* THE LIST IS MADE WITH THE DATABASE THE GATE IS ANSWERED WITH: what the analysis runs (the emulator among it) follows the
	 * database's modules, so the list and the answer are compared over one database - here Generate of the same draft without
	 * a gate, the database of every scene below (sigs-any and one form). */
	scene_new(&sc, "gate_base");
	header();
	decl_text((const uint8_t *)"alpha-marker", 12u);
	use(0, matcher(1, 0, CODE));
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	OKF(draft_generate(&E, sc.gen, msg, sizeof msg) == 1 && build(&sc) == 0, "the draft without a gate is written and built: %s", msg);
	free_draft();
	run = explain_of(sc.db, elf, sizeof elf, &res);
	scene_new(&sc, "gate_list");
	OKF(run && res, "the engine explains the ELF");
	if (!run || !res) {
		kdet_run_free(run);
		return;
	}
	header();
	offers_are_engine("the ELF", res, &na, &nn);
	OKF(na >= 1u && nn >= 1u, "the ELF offers an anomaly (%u) and a nucleo (%u)", na, nn);
	/* add: the draft is edited by one; the same twice, NONE and an unknown value are refused; what is stated is not offered */
	h0 = draft_hash(&E);
	(void)draft_gate_offer(&E, (uint16_t)KOF_FACT_ANOMALY, res, w, 64u);
	OKF(draft_gate_add(&E, w[0].fact, w[0].val) == 1 && draft_hash(&E) != h0, "an anomaly is added and the draft is edited");
	OKF(draft_gate_add(&E, w[0].fact, w[0].val) == 0 && E.dr.n_gate == 1u, "the same anomaly twice is refused");
	OKF(draft_gate_offer(&E, (uint16_t)KOF_FACT_ANOMALY, res, NULL, 0) == na - 1u, "a stated anomaly is not offered again");
	OKF(draft_gate_text(&E.dr.gate[0], txt, sizeof txt) && !strncmp(txt, "ELF ", 4u), "an anomaly reads \"ELF <name>\": %s", txt);
	(void)draft_gate_offer(&E, (uint16_t)KOF_FACT_NUCLEO, res, w, 64u);
	OKF(draft_gate_add(&E, w[0].fact, w[0].val) == 1, "a nucleo the file shows is added");
	OKF(draft_gate_text(&E.dr.gate[1], txt, sizeof txt) && !strcmp(txt, kgenome_nucleo_cap_name((uint16_t)w[0].val)),
	    "a nucleo reads as its nucleo name: %s", txt);
	OKF(draft_gate_add(&E, (uint16_t)KOF_FACT_NUCLEO, 0) == 0 && draft_gate_add(&E, (uint16_t)KOF_FACT_ANOMALY, 0xffffffffffull) == 0 &&
	    draft_gate_add(&E, (uint16_t)KOF_FACT_SIZE_MIN, 1) == 0 && E.dr.n_gate == 2u, "NONE, an unknown anomaly and another fact are refused");
	/* Generate: the lines, read back by the shared reader, built, and answered by the engine */
	decl_text((const uint8_t *)"alpha-marker", 12u);
	use(0, matcher(1, 0, CODE));
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	OKF(draft_generate(&E, sc.gen, msg, sizeof msg) == 1, "the gated draft is written: %s", msg);
	{
		char *t = gen_file(&sc, "botnet_mirai_flood_01.c");
		struct kof_dsrc *d = calloc(1, sizeof *d);
		struct kof_dsrc_view v;
		int e = 1;

		OKF(t && strstr(t, "KOF_DIAG_HAS_ANOMALY(KOF_FMT_ELF, ") && strstr(t, "KOF_DIAG_HAS_NUCLEO(KOF_NUCLEO_"),
		    "the file states the anomaly and the nucleo");
		memset(&v, 0, sizeof v);
		if (t && d && kof_dsrc_parse(t, strlen(t), d, NULL) == 0)
			e = kof_dsrc_resolve(d, &v, NULL);
		OKF(e == 0 && v.n_when == 3 && v.when[1].fact == KOF_FACT_ANOMALY && v.when[1].val == E.dr.gate[0].val &&
		    v.when[2].fact == KOF_FACT_NUCLEO && v.when[2].val == E.dr.gate[1].val,
		    "the shared reader reads back the format and the two gate conditions, in order");
		kof_dsrc_view_free(&v);
		free(d);
		free(t);
	}
	OKF(build(&sc) == 0, "the gated diagnose builds");
	{
		kof_engine *eng = keng_open(sc.db);
		kof_scanner *scn = eng ? kscan_new(eng) : NULL;
		struct gstate *g = calloc(1, sizeof *g);
		uint8_t gs = 0;

		if (scn && g) {
			gstate_scan(scn, elf, sizeof elf, g);
			OKF(gstate_of(g, "botnet_mirai_flood_01", &gs) == KOF_DIAG_ST_MATCH, "the draft's own sample passes the gate it was picked from");
		} else {
			OKF(0, "the gated database does not open");
		}
		free(g);
		kscan_free(scn);
		keng_close(eng);
	}
	free_draft();
	/* a capability the file does not show blocks */
	{
		size_t i;
		uint16_t c;
		uint16_t caps[256];
		uint32_t nc = kdet_nucleo_seen(res, caps, 256u);

		for (i = 0; kof_dsrc_cap_at(i, &c) && !absent; i++) {
			uint32_t j;
			int in = 0;

			for (j = 0; j < nc && j < 256u; j++)
				in |= caps[j] == c;
			if (!in)
				absent = c;
		}
	}
	scene_new(&sc, "gate_absent");
	header();
	decl_text((const uint8_t *)"alpha-marker", 12u);
	use(0, matcher(1, 0, CODE));
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	OKF(absent && draft_gate_add(&E, (uint16_t)KOF_FACT_NUCLEO, absent) == 1, "a capability the file does not show can be stated");
	OKF(draft_generate(&E, sc.gen, msg, sizeof msg) == 1 && build(&sc) == 0, "and it is written and built: %s", msg);
	{
		kof_engine *eng = keng_open(sc.db);
		kof_scanner *scn = eng ? kscan_new(eng) : NULL;
		struct gstate *g = calloc(1, sizeof *g);
		uint8_t gs = 0;

		if (scn && g) {
			gstate_scan(scn, elf, sizeof elf, g);
			OKF(gstate_of(g, "botnet_mirai_flood_01", &gs) != KOF_DIAG_ST_MATCH && gs == KOF_GATE_NO,
			    "a capability the file does not show (%s) is NO and blocks (gate %u)", kof_dsrc_cap_word(absent), gs);
		}
		free(g);
		kscan_free(scn);
		keng_close(eng);
	}
	free_draft();
	/* sixteen gate conditions and the format line: seventeen, refused by Save with the reader's reason */
	scene_new(&sc, "gate_cap");
	header();
	decl_text((const uint8_t *)"alpha-marker", 12u);
	use(0, matcher(1, 0, CODE));
	condition("1", KOF_MALTYPE_BOTNET, "flood");
	{
		size_t i;
		uint16_t c;
		uint32_t added = 0;

		for (i = 0; kof_dsrc_cap_at(i, &c) && added < 17u; i++)
			added += (uint32_t)draft_gate_add(&E, (uint16_t)KOF_FACT_NUCLEO, c);
		OKF(added == 16u && E.dr.n_gate == 16u, "the draft holds sixteen conditions and refuses the seventeenth (%u)", added);
	}
	OKF(draft_generate(&E, sc.gen, msg, sizeof msg) < 0 && strstr(msg, "too many conditions") && count_files(sc.gen) == 0u,
	    "sixteen gates and a format are refused by Save with the reader's reason, nothing written: %s", msg);
	free_draft();
	kdet_run_free(run);

	/* run1: the golden fixture */
	{
		static const char *const r1 = "/mnt/games/normtest/golden_samples/run1";
		size_t n1 = 0;
		uint8_t *b1 = read_file(r1, &n1);
		struct scene s1;
		const struct kof_result *res1;
		kdet_run *run1;
		uint32_t a1 = 0, n1n = 0, yes = 0, total = 0;
		struct kof_diag_when ow[128];

		OKF(b1 && n1 == 64608u, "the run1 fixture is there (%s, 64608 bytes): the list equality is not checked without it", r1);
		if (!b1) {
			free(b1);
			return;
		}
		header();
		run1 = explain_of("build/release/databases", b1, n1, &res1);
		OKF(run1 && res1, "the engine explains run1");
		/* SG-D1, measured: the engine's normalised view of run1 holds the parent's description and its word, which has no
		 * anomaly, where the dashboard (its own parse of the view's bytes) lists three (golden run1_norm_dash_overview). */
		{
			const struct kdet_object *view = run1 ? kdet_run_find(run1, "sample" KOF_OBJ_SEP "0:norm") : NULL;

			OKF(view && view->res.anomaly_fmt == KOF_FMT_ELF && view->res.anomalies == 0u,
			    "run1's view: the engine's word is the parent's (none): fmt %d word %llx", view ? view->res.anomaly_fmt : -1,
			    view ? (unsigned long long)view->res.anomalies : 0ull);
		}
		if (run1 && res1) {
			offers_are_engine("run1", res1, &a1, &n1n);
			OKF(n1n >= 1u, "run1 offers nucleo (%u)", n1n);
			/* every condition picked from the lists passes the engine's gate on run1 */
			scene_new(&s1, "gate_run1");
			{
				uint32_t m = draft_gate_offer(&E, (uint16_t)KOF_FACT_ANOMALY, res1, ow, 64u), q;

				m += draft_gate_offer(&E, (uint16_t)KOF_FACT_NUCLEO, res1, ow + (m < 64u ? m : 64u), 64u);
				for (q = 0; q < m && q < 128u; q++) {
					char src[1200], nm[48];

					snprintf(nm, sizeof nm, "r1_%u", (unsigned)q);
					if (ow[q].fact == KOF_FACT_ANOMALY)
						snprintf(src, sizeof src, "KOF_DIAG_NAME(%s);\nKOF_TARGET_RANGE(whole, KOF_SCAN_ALL);\n"
							 "KOF_DEFINE_STR(e, \"ELF\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\nKOF_DIAG_FIND(m0, KOF_FIND_ANY, whole, e);\n"
							 "KOF_DIAG_HAS_ANOMALY(%s, %s);\n", nm, kof_format_ident((uint8_t)(ow[q].val >> 32)),
							 kof_parser_of((uint8_t)(ow[q].val >> 32))->anomaly_name((unsigned)(ow[q].val & 63u)));
					else
						snprintf(src, sizeof src, "KOF_DIAG_NAME(%s);\nKOF_TARGET_RANGE(whole, KOF_SCAN_ALL);\n"
							 "KOF_DEFINE_STR(e, \"ELF\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\nKOF_DIAG_FIND(m0, KOF_FIND_ANY, whole, e);\n"
							 "KOF_DIAG_HAS_NUCLEO(%s);\n", nm, kof_dsrc_cap_word((uint16_t)ow[q].val));
					{
						char p[700];

						snprintf(p, sizeof p, "%s/%s.c", s1.gen, nm);
						(void)write_file(p, src, strlen(src));
					}
					total++;
				}
			}
			OKF(build(&s1) == 0, "the run1 gates build");
			{
				kof_engine *eng = keng_open(s1.db);
				kof_scanner *scn = eng ? kscan_new(eng) : NULL;
				struct gstate *g = calloc(1, sizeof *g);

				if (scn && g) {
					uint32_t q;

					gstate_scan(scn, b1, n1, g);
					for (q = 0; q < total; q++) {
						char nm[48];
						uint8_t gs = 0;

						snprintf(nm, sizeof nm, "r1_%u", (unsigned)q);
						if (gstate_of(g, nm, &gs) == KOF_DIAG_ST_MATCH && gs == KOF_GATE_YES)
							yes++;
						else
							printf("    %s: state %d gate %u\n", nm, gstate_of(g, nm, &gs), gs);
					}
				}
				free(g);
				kscan_free(scn);
				keng_close(eng);
			}
			OKF(total >= 1u && yes == total, "every condition picked from run1's lists passes the engine's gate on run1: %u of %u", yes,
			    total);
		}
		free_draft();
		kdet_run_free(run1);
		free(b1);
	}
}

int main(void)
{
	if (access(builder, X_OK) != 0) {
		printf("diag_form_generate: %s is not built\n", builder);
		return 2;
	}
	snprintf(root, sizeof root, "build/kof_diagform_gen_XXXXXX");
	if (!mkdtemp(root)) {
		printf("diag_form_generate: cannot make a scratch directory\n");
		return 2;
	}
	whole_chain();
	free_draft();
	field_semantics();
	determinism();
	free_draft();
	block_units();
	options();
	refusals();
	gate_draft();
	if (!failures)
		rm_all(root);       /* a failing run leaves its scratch tree for whoever reads the failure */
	if (failures) {
		printf("diag_form_generate: %d FAIL\n", failures);
		return 1;
	}
	printf("diag_form_generate: ok\n");
	return 0;
}
