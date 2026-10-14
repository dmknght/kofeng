/*
 * syndrome_pack - a syndrome source, the pack the build writes from it, and what
 * the loader makes of it; and the disease a diagnose record carries.
 *
 * The same properties diag_pack pins for a diagnose pack, for the new one: a
 * header that does not add up refuses the WHOLE pack, a record that does not is
 * skipped and its siblings still load, and a damaged syndrome pack never takes the
 * signature packs beside it down.
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/databases/dbloader.h"
#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/databases/syndsrc.h"
#include "../../libkofeng/analyzers/diseases/kofdisease.h"
#include "../../libkofeng/detectors/linkage/kofdiag.h"
#include "../../libkofeng/kofcore/kofmod/kofcap.h"
#include "../../libkofeng/kofcore/kofmod/kofsig.h"

static int failures;
static char root[256];
static const char *dbdir = "build/test/databases-sigs";

static void ok(const char *what, int cond)
{
	printf("  %s %s\n", cond ? "ok  " : "FAIL", what);
	if (!cond)
		failures++;
}

/* ---- the source ------------------------------------------------------------ */

static int parse(const char *text, struct kof_ssrc *p)
{
	static const struct kof_dsrc_report rep = { NULL, NULL, NULL };

	return kof_ssrc_parse(text, strlen(text), p, &rep);
}

static void writing(void)
{
	static struct kof_ssrc a, b;
	static char text[4096];
	char line[160];
	size_t n;

	memset(&a, 0, sizeof a);
	a.type_mask = (1u << KOF_MALTYPE_BOTNET) | (1u << KOF_MALTYPE_EXPLOIT);
	a.n_dis = 2;
	snprintf(a.dis[0], sizeof a.dis[0], "%s", "cnc/recv");
	snprintf(a.dis[1], sizeof a.dis[1], "%s", "flood/raw");
	n = kof_ssrc_source(&a, "Mirai x86 from Bazaar.\nA comment must never end here */ so.", text, sizeof text);
	ok("a source is written", n > 0 && n < sizeof text);
	ok("and read back to the same syndrome",
	   parse(text, &b) == 0 && b.type_mask == a.type_mask && b.n_dis == 2u &&
	   !strcmp(b.dis[0], "cnc/recv") && !strcmp(b.dis[1], "flood/raw"));
	ok("a star-slash in the header does not end the comment",
	   strstr(text, "never end here * /") != NULL);
	ok("without a header it is still a source",
	   kof_ssrc_source(&a, NULL, text, sizeof text) > 0 && parse(text, &b) == 0);
	n = kof_ssrc_source(&a, "x", text, 8);
	ok("a short buffer is cut, terminated, and the true length returned",
	   n > 8u && strlen(text) == 7u);
	b = a;
	b.n_dis = 0;
	ok("a syndrome with no disease is not written", kof_ssrc_source(&b, "x", text, sizeof text) == 0);
	b = a;
	snprintf(b.dis[1], sizeof b.dis[1], "%s", "Bad Name");
	ok("one with a disease that is not well formed is not written",
	   kof_ssrc_source(&b, "x", text, sizeof text) == 0);
	ok("the two lines a patch uses are written as a source has them",
	   kof_ssrc_print_type(KOF_MALTYPE_BOTNET, line, sizeof line) > 0 &&
	   !strcmp(line, "KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);") &&
	   kof_ssrc_print_dis("cnc/recv", line, sizeof line) > 0 &&
	   !strcmp(line, "KOF_DECLARE_SYNDROME_HAS(\"cnc/recv\");"));
	ok("a type that is no maltype and a disease that is no word are not written",
	   kof_ssrc_print_type(KOF_MALTYPE_COUNT, line, sizeof line) == 0 &&
	   kof_ssrc_print_dis("A", line, sizeof line) == 0);
}

static void source(void)
{
	static struct kof_ssrc p;
	char many[8192];
	unsigned i;
	size_t at = 0;

	ok("a syndrome of one type and two behaviours reads",
	   parse("/* a sample */\n"
		 "KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\n"
		 "KOF_DECLARE_SYNDROME_HAS(\"cnc/recv\");\n"
		 "KOF_DECLARE_SYNDROME_HAS(\"flood/raw\");\n", &p) == 0 &&
	   p.type_mask == (1u << KOF_MALTYPE_BOTNET) && p.n_dis == 2u &&
	   !strcmp(p.dis[1], "flood/raw"));
	ok("two types are a sample that was both",
	   parse("KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\nKOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_EXPLOIT);\n"
		 "KOF_DECLARE_SYNDROME_HAS(\"a/b\");\n", &p) == 0 &&
	   p.type_mask == ((1u << KOF_MALTYPE_BOTNET) | (1u << KOF_MALTYPE_EXPLOIT)));
	ok("a declaration inside a comment is a mention, not a declaration",
	   parse("KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\nKOF_DECLARE_SYNDROME_HAS(\"a/b\");\n"
		 "/* KOF_DECLARE_SYNDROME_HAS(\"c/d\"); */\n", &p) == 0 && p.n_dis == 1u);
	ok("no type is refused", parse("KOF_DECLARE_SYNDROME_HAS(\"a/b\");\n", &p) > 0);
	ok("no behaviour is refused", parse("KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\n", &p) > 0);
	ok("a word that is not a type is refused",
	   parse("KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_NOPE);\nKOF_DECLARE_SYNDROME_HAS(\"a/b\");\n", &p) > 0);
	ok("upper case is refused",
	   parse("KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\nKOF_DECLARE_SYNDROME_HAS(\"A/b\");\n", &p) > 0);
	ok("an empty part is refused",
	   parse("KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\nKOF_DECLARE_SYNDROME_HAS(\"a//b\");\n", &p) > 0);
	ok("the same behaviour twice is refused",
	   parse("KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\nKOF_DECLARE_SYNDROME_HAS(\"a/b\");\n"
		 "KOF_DECLARE_SYNDROME_HAS(\"a/b\");\n", &p) > 0);
	for (i = 0; i < KOF_SSRC_MAX_DIS + 2u; i++)
		at += (size_t)snprintf(many + at, sizeof many - at, "KOF_DECLARE_SYNDROME_HAS(\"x/b%u\");\n", i);
	snprintf(many + at, sizeof many - at, "KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\n");
	ok("more behaviours than a sample can have is refused, not truncated",
	   parse(many, &p) > 0);
}

/* ---- records and packs, spelled out byte by byte ---------------------------- */

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* One syndrome record: type mask, count, then the ids of its diseases. */
static size_t prec(uint8_t *b, uint32_t types, const char *const *dis, unsigned n)
{
	size_t at = 0;
	unsigned i;

	put32(b, types);
	at = 4;
	b[at++] = (uint8_t)n;
	for (i = 0; i < n; i++) {
		put32(b + at, kof_disease_id(dis[i]));
		at += 4;
	}
	return at;
}

static size_t ppack(uint8_t *b, unsigned n, const uint32_t *types,
		    const char *const *const *dis, const unsigned *cnt)
{
	size_t at = 8u + (size_t)n * 8u;
	unsigned i;

	memcpy(b, "KSYN", 4);
	b[4] = 1; b[5] = 0;
	b[6] = (uint8_t)n; b[7] = (uint8_t)(n >> 8);
	for (i = 0; i < n; i++) {
		size_t l = prec(b + at, types[i], dis[i], cnt[i]);

		put32(b + 8u + i * 8u, (uint32_t)at);
		put32(b + 12u + i * 8u, (uint32_t)l);
		at += l;
	}
	return at;
}

static int write_file(const char *dir, const char *leaf, const void *p, size_t n)
{
	char path[640];
	FILE *f;

	snprintf(path, sizeof path, "%s/%s", dir, leaf);
	f = fopen(path, "wb");
	if (!f)
		return 0;
	if (n && fwrite(p, 1, n, f) != n) {
		fclose(f);
		return 0;
	}
	return fclose(f) == 0;
}

static int copy_good_pack(const char *dir)
{
	char src[640];
	FILE *f;
	static uint8_t buf[1u << 20];
	size_t n;

	snprintf(src, sizeof src, "%s/sigs-any.ksig", dbdir);
	f = fopen(src, "rb");
	if (!f)
		return 0;
	n = fread(buf, 1, sizeof buf, f);
	fclose(f);
	return n > 0 && write_file(dir, "sigs-any.ksig", buf, n);
}

static void rm_all(const char *dir)
{
	char cmd[700];

	snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
	(void)system(cmd);
}

/* An engine over a directory holding the good signature pack and this syndrome pack. */
static struct kof_engine *open_with(const char *tag, char *dir, size_t cap,
				    const uint8_t *pk, size_t n)
{
	snprintf(dir, cap, "%s/%s", root, tag);
	if (kof_mkdir(dir, 0700) != 0 || !copy_good_pack(dir))
		return NULL;
	if (pk && !write_file(dir, "syndromes.kdig", pk, n))
		return NULL;
	return kof_db_load(dir);
}

static unsigned T(unsigned t)
{
	return 1u << t;
}

static void loader(void)
{
	static uint8_t good[512], bad[512];
	static const char *const bot[] = { "cnc/recv", "flood/raw" };
	static const char *const mine[] = { "cnc/recv" };
	static const char *const *const dis[] = { bot, mine };
	static const unsigned cnt[] = { 2, 1 };
	const uint32_t types[] = { T(KOF_MALTYPE_BOTNET), T(KOF_MALTYPE_MINER) };
	struct kof_synd_result r;
	const char *q[] = { "cnc/recv", "flood/raw" };
	char dir[640];
	struct kof_engine *e;
	size_t gl;

	gl = ppack(good, 2, types, dis, cnt);

	e = open_with("good", dir, sizeof dir, good, gl);
	ok("an engine with a syndrome pack loads", e != NULL);
	ok("and carries its two syndromes", e && kof_synd_count(e->synd) == 2u);
	if (e) {
		{
			uint32_t ids[2] = { kof_disease_id(q[0]), kof_disease_id(q[1]) };

			kof_synd_infer(e->synd, ids, 2, &r);
		}
		ok("what it was loaded with proves what the syndrome shows",
		   r.guaranteed == T(KOF_MALTYPE_BOTNET));
		kof_db_free(e);
	}
	rm_all(dir);

	e = open_with("none", dir, sizeof dir, NULL, 0);
	ok("an engine without one is an ordinary engine", e != NULL && e->synd == NULL);
	if (e)
		kof_db_free(e);
	rm_all(dir);

	/* a header that does not add up: refused whole, the engine still loads */
	memcpy(bad, good, gl);
	bad[4] = 9;
	e = open_with("version", dir, sizeof dir, bad, gl);
	ok("a version this build does not read refuses the pack, not the engine",
	   e != NULL && e->synd == NULL);
	if (e)
		kof_db_free(e);
	rm_all(dir);

	memcpy(bad, good, gl);
	bad[6] = 200;
	e = open_with("table", dir, sizeof dir, bad, gl);
	ok("a table longer than the file refuses the pack",
	   e != NULL && e->synd == NULL);
	if (e)
		kof_db_free(e);
	rm_all(dir);

	/* a record that does not: skipped, the sibling loads */
	memcpy(bad, good, gl);
	put32(bad + 12, 3);             /* the first record is shorter than its header */
	e = open_with("record", dir, sizeof dir, bad, gl);
	ok("a bad record is skipped and its sibling loads",
	   e != NULL && e->synd && kof_synd_count(e->synd) == 1u);
	if (e)
		kof_db_free(e);
	rm_all(dir);

	e = open_with("truncated", dir, sizeof dir, good, gl - 4u);
	ok("a pack cut short loses the record it cut and not the engine",
	   e != NULL);
	if (e)
		kof_db_free(e);
	rm_all(dir);
}

/* ---- the disease in a diagnose record ----------------------------------- */

static size_t drec(uint8_t *b, uint32_t id, unsigned type, unsigned len_byte)
{
	static const char *const nm = "DIAG_X";
	size_t at = 0, nl = strlen(nm);
	uint16_t cap = (uint16_t)KGENOME_NUCLEO_NET_OPEN;

	b[at++] = 1; b[at++] = 0;
	b[at++] = KOF_DIAG_ANALYSIS_SYSCALL;
	b[at++] = (uint8_t)nl;
	memcpy(b + at, nm, nl); at += nl;
	b[at++] = (uint8_t)cap; b[at++] = (uint8_t)(cap >> 8);
	b[at++] = 0; b[at++] = 0;
	b[at++] = KOF_DIAG_NO_PARENT;
	b[at++] = 0; b[at++] = 0; b[at++] = 0;
	b[at++] = 0;                            /* the legacy name count */
	b[at++] = KDIG_SEC_DISEASE;
	b[at++] = (uint8_t)len_byte;
	put32(b + at, id); at += 4;
	b[at++] = (uint8_t)type;
	return at;
}

static void disease(void)
{
	uint8_t b[128];
	struct kof_diag d;
	struct kof_diag_node node[2];
	char name[KOF_DB_DIAG_NAME], needs[sizeof b + 1u];   /* a store never needs more than the record */
	const struct kof_diag_store st = { node, name, needs, sizeof name, sizeof needs, 2 };
	const uint32_t id = kof_disease_id("cnc/recv-syscall");
	size_t at;

	at = drec(b, id, KOF_MALTYPE_BOTNET, 5);
	memset(&d, 0, sizeof d);
	ok("a record with a disease loads",
	   kof_diag_load(kof_buf_make(b, at), &d, &st) == 1);
	ok("and carries its id and its type",
	   d.disease == id && d.disease_type == KOF_MALTYPE_BOTNET);
	memset(&d, 0, sizeof d);
	ok("a record without one has none",
	   kof_diag_load(kof_buf_make(b, at - 7u), &d, &st) == 1 && d.disease == 0);
	/* a section that is not an id and a type refuses the record whole */
	at = drec(b, id, KOF_MALTYPE_BOTNET, 4);
	ok("a length that is not five refuses the record",
	   kof_diag_load(kof_buf_make(b, at), &d, &st) == 0);
	at = drec(b, id, KOF_MALTYPE_COUNT, 5);
	ok("a type that is no maltype refuses the record",
	   kof_diag_load(kof_buf_make(b, at), &d, &st) == 0);
	at = drec(b, 0, KOF_MALTYPE_BOTNET, 5);
	ok("the id zero, which means no disease, refuses the record",
	   kof_diag_load(kof_buf_make(b, at), &d, &st) == 0);
}

/* ---- the database the build makes from tests/sigs ------------------------- */

/*
 * The whole path, once: sources through the builder, the diagnose pack that
 * carries ids, the syndrome pack, the table of names, and what the engine makes
 * of them. Nothing here is written by hand, so what is checked is the build.
 */
static void database(void)
{
	struct kof_engine *e = kof_db_load(dbdir);
	const struct kof_disease_ent *d;
	struct kof_synd_result r;
	uint32_t id = kof_disease_id("kernel/giveroot"), i;
	int carried = 0;
	char nm[64];

	ok("the engine loads the database the build made", e != NULL);
	if (!e)
		return;
	/* botnet_00, dropper_00, rootkit_00 and the four vd_*_00 exemplars that
	 * tests/unit/verdict_branches.c reads sets of diseases against */
	ok("it holds the seven syndromes of the fixtures", kof_synd_count(e->synd) == 7u);
	d = kof_db_disease(e, id);
	ok("a disease id is turned back into its name and its type",
	   d && !strcmp(d->name, "kernel/giveroot") && d->type == KOF_MALTYPE_ROOTKIT);
	{
		/* The type a DETECTOR declared reaches the table: the module packs are
		 * made after the diagnoses and syndromes, and a table written before
		 * them named this disease with no type. */
		const struct kof_disease_ent *u = kof_db_disease(e, kof_disease_id("flood-network/udp"));

		ok("a disease a signature declared has its type in the table",
		   u && u->type == KOF_MALTYPE_BOTNET);
	}
	ok("an id nobody carries is not named", kof_db_disease(e, kof_disease_id("no/such")) == NULL);
	for (i = 0; i < e->n_diag; i++)
		if (e->diag[i].disease == id)
			carried = e->diag[i].disease_type == KOF_MALTYPE_ROOTKIT;
	ok("the diagnose carries the id and the type it declared", carried);
	{
		uint32_t prev = 0, k, n = kof_db_disease_count(e);
		int ascending = n > 0;

		for (k = 0; k < n; k++) {
			const struct kof_disease_ent *x = kof_db_disease_at(e, k);

			if (!x || x->id <= prev)
				ascending = 0;
			else
				prev = x->id;
		}
		ok("the names can be listed, ascending by id", ascending);
		ok("and a list ends where it ends", kof_db_disease_at(e, n) == NULL);
	}
	{
		uint32_t tm, nd, k, found = 0;
		const uint32_t *dd;

		for (k = 0; kof_synd_get(e->synd, k, &tm, &nd, &dd); k++)
			if (tm == (1u << KOF_MALTYPE_ROOTKIT) && nd == 1u && dd[0] == id)
				found = 1;
		ok("the verified samples can be read back as ids", found && k == 7u);
	}
	kof_synd_infer(e->synd, &id, 1, &r);
	kof_synd_name(&r, nm, sizeof nm);
	ok("and the inference reads that id as a rootkit", !strcmp(nm, "Rootkit:Agent"));
	kof_db_free(e);
}

/* ---- a detector that is not a diagnose finds a disease --------------------- */

static int g_has;
static char g_name[96];
static uint32_t g_guar;

static int on_obj(const char *name, const void *bytes, uint64_t len,
		  const struct kof_result *res, void *user)
{
	(void)name; (void)bytes; (void)len; (void)user;
	g_has = res->has_syndrome;
	g_guar = res->syndrome.guaranteed;
	kof_synd_name(&res->syndrome, g_name, sizeof g_name);
	return 0;
}

static void detector(void)
{
	kof_engine *eng = keng_open(dbdir);
	kof_scanner *sc;
	struct kof_scan_option opt;
	uint8_t hit[256], miss[256];

	ok("the engine opens the database", eng != NULL);
	if (!eng)
		return;
	sc = kscan_new(eng);
	memset(hit, 'x', sizeof hit);
	memset(miss, 'x', sizeof miss);
	memcpy(hit + 40, "DISEASE_FIXTURE_MARKER", 22);
	memset(&opt, 0, sizeof opt);
	opt.report_diag = 1;
	opt.all_matches = 1;

	g_has = 0;
	kscan_bytes(sc, hit, sizeof hit, "hit", &opt, on_obj, NULL);
	ok("an object a detector reports on carries that detector's disease",
	   g_has == 1 && (g_guar & (1u << KOF_MALTYPE_BOTNET)));
	ok("and the syndrome reads it as a botnet", !strcmp(g_name, "Botnet:Agent"));

	g_has = 0;
	kscan_bytes(sc, miss, sizeof miss, "miss", &opt, on_obj, NULL);
	ok("an object nothing reports on has no syndrome and no disease", g_has == 0);

	/* the next object does not inherit the last one's disease */
	g_has = 0;
	kscan_bytes(sc, hit, sizeof hit, "hit2", &opt, on_obj, NULL);
	kscan_bytes(sc, miss, sizeof miss, "miss2", &opt, on_obj, NULL);
	ok("a disease belongs to the object it was found on", g_has == 0);
	kscan_free(sc);
	keng_close(eng);
}

int main(int argc, char **argv)
{
	if (argc > 1)
		dbdir = argv[1];
	snprintf(root, sizeof root, "build/test/profpack_%d", (int)getpid());
	if (kof_mkdir(root, 0700) != 0) {
		printf("syndrome_pack: cannot make a work directory\n");
		return 1;
	}
	printf("syndrome_pack:\n");
	source();
	writing();
	loader();
	disease();
	database();
	detector();
	rm_all(root);
	if (failures) {
		printf("syndrome_pack: %d failure(s)\n", failures);
		return 1;
	}
	printf("syndrome_pack: a syndrome source is read and its errors refused, the pack "
	       "loads and a damaged one costs only itself, a diagnose carries its "
	       "disease - ok\n");
	return 0;
}
