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
#include "../../libkofeng/databases/syndsrc.h"
#include "../../libkofeng/detectors/pathogen/diagnoses/kofdiag.h"
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

static void source(void)
{
	static struct kof_ssrc p;
	char many[8192];
	unsigned i;
	size_t at = 0;

	ok("a syndrome of one type and two behaviours reads",
	   parse("/* a sample */\n"
		 "KOF_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\n"
		 "KOF_SYNDROME_HAS(\"cnc/recv\");\n"
		 "KOF_SYNDROME_HAS(\"flood/raw\");\n", &p) == 0 &&
	   p.type_mask == (1u << KOF_MALTYPE_BOTNET) && p.n_dis == 2u &&
	   !strcmp(p.dis[1], "flood/raw"));
	ok("two types are a sample that was both",
	   parse("KOF_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\nKOF_SYNDROME_TYPE(KOF_MALTYPE_EXPLOIT);\n"
		 "KOF_SYNDROME_HAS(\"a/b\");\n", &p) == 0 &&
	   p.type_mask == ((1u << KOF_MALTYPE_BOTNET) | (1u << KOF_MALTYPE_EXPLOIT)));
	ok("a declaration inside a comment is a mention, not a declaration",
	   parse("KOF_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\nKOF_SYNDROME_HAS(\"a/b\");\n"
		 "/* KOF_SYNDROME_HAS(\"c/d\"); */\n", &p) == 0 && p.n_dis == 1u);
	ok("no type is refused", parse("KOF_SYNDROME_HAS(\"a/b\");\n", &p) > 0);
	ok("no behaviour is refused", parse("KOF_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\n", &p) > 0);
	ok("a word that is not a type is refused",
	   parse("KOF_SYNDROME_TYPE(KOF_MALTYPE_NOPE);\nKOF_SYNDROME_HAS(\"a/b\");\n", &p) > 0);
	ok("upper case is refused",
	   parse("KOF_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\nKOF_SYNDROME_HAS(\"A/b\");\n", &p) > 0);
	ok("an empty part is refused",
	   parse("KOF_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\nKOF_SYNDROME_HAS(\"a//b\");\n", &p) > 0);
	ok("the same behaviour twice is refused",
	   parse("KOF_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\nKOF_SYNDROME_HAS(\"a/b\");\n"
		 "KOF_SYNDROME_HAS(\"a/b\");\n", &p) > 0);
	for (i = 0; i < KOF_SSRC_MAX_DIS + 2u; i++)
		at += (size_t)snprintf(many + at, sizeof many - at, "KOF_SYNDROME_HAS(\"x/b%u\");\n", i);
	snprintf(many + at, sizeof many - at, "KOF_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\n");
	ok("more behaviours than a sample can have is refused, not truncated",
	   parse(many, &p) > 0);
}

/* ---- records and packs, spelled out byte by byte ---------------------------- */

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* One syndrome record: type mask, count, then length-prefixed diseases. */
static size_t prec(uint8_t *b, uint32_t types, const char *const *dis, unsigned n)
{
	size_t at = 0;
	unsigned i;

	put32(b, types);
	at = 4;
	b[at++] = (uint8_t)n;
	for (i = 0; i < n; i++) {
		size_t l = strlen(dis[i]);

		b[at++] = (uint8_t)l;
		memcpy(b + at, dis[i], l);
		at += l;
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
		kof_synd_infer(e->synd, q, 2, &r);
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

static void disease(void)
{
	static const char *const names[] = { "DIAG_X" };
	uint8_t b[128];
	struct kof_diag d;
	struct kof_diag_node node[2];
	char name[KOF_DB_DIAG_NAME], needs[KOF_DB_DIAG_NEEDS];
	size_t at = 0, nl = strlen(names[0]);
	const char *an = "cnc/recv-syscall";
	uint16_t cap = (uint16_t)KOF_NUCLEO_NET_OPEN;

	b[at++] = 1; b[at++] = 0;
	b[at++] = KOF_DIAG_ANALYSIS_SYSCALL;
	b[at++] = (uint8_t)nl;
	memcpy(b + at, names[0], nl); at += nl;
	b[at++] = (uint8_t)cap; b[at++] = (uint8_t)(cap >> 8);
	b[at++] = 0; b[at++] = 0;
	b[at++] = KOF_DIAG_NO_PARENT;
	b[at++] = 0; b[at++] = 0; b[at++] = 0;
	b[at++] = 0;                            /* the legacy name count */
	b[at++] = KDIG_SEC_DISEASE;
	b[at++] = (uint8_t)strlen(an);
	memcpy(b + at, an, strlen(an)); at += strlen(an);

	memset(&d, 0, sizeof d);
	ok("a record with a disease loads",
	   kof_diag_load(b, at, &d, node, 2, name, sizeof name, needs, sizeof needs) == 1);
	ok("and carries it", d.disease && !strcmp(d.disease, an));
	ok("a record without one has none",
	   kof_diag_load(b, at - 2u - strlen(an), &d, node, 2, name, sizeof name,
			 needs, sizeof needs) == 1 && d.disease == NULL);
	/* a length that runs past the record refuses it whole */
	b[at - 1u - strlen(an)] = 200;
	ok("a length past the record refuses it",
	   kof_diag_load(b, at, &d, node, 2, name, sizeof name, needs, sizeof needs) == 0);
	b[at - 1u - strlen(an)] = (uint8_t)strlen(an);
	/* one the store cannot hold refuses it too, instead of cutting it */
	ok("a disease the store cannot hold refuses the record",
	   kof_diag_load(b, at, &d, node, 2, name, sizeof name, needs, 8u) == 0);
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
	loader();
	disease();
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
