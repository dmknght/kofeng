/*
 * diag_meta - the catalog facts of a diagnose (family, variant, ONE type, tag): from the source
 * line to the record to the loader to the API.
 *
 * WHAT IS PINNED, and which of the old tests could not have caught it:
 *
 *   LOADER   a record with the META section (KDIG_SEC_META, tag 9, 25 bytes) loads with its three
 *            ids and its type; one without it loads with zeros (an old pack); a reader that does
 *            not know the tag - an old one - skips it by its length and reads the rest the same;
 *            a section of the wrong length, an id of zero, the type Packer or no type at all
 *            refuses THAT record and not its siblings.
 *   BUILDER  ksigbuilder resolves the names to ids from the catalogs and writes the section; it
 *            refuses, with file:line, a family, a variant or a tag that does not exist, a variant
 *            of another family, a type the variant does not declare, Packer, a source with only
 *            some of the four lines, two diagnoses that collide, and a build given no catalogs.
 *            The legacy count byte is written when the section is the only thing that follows
 *            the nodes (a record an old reader would otherwise misread). Two builds are
 *            byte-identical.
 *
 *   IDS      THE IDS ARE MADE FROM THE NAMES at build time (catstore.h) and stored in no source: the pack's ids equal catid_oracle.h's (shared
 *            with no library code); a catalog without id lines builds and is left byte for byte as it was; a catalog saved by an older
 *            tool WITH id lines builds the same pack as one without (the lines are said as ignored, never used); the catalog written in
 *            another order gives the same pack; a rename changes the tag's id; a catalog file that does not load refuses the build.
 *
 * Why the old tests missed it: (a) nothing of this existed - the reader ignored an unknown
 * KOF_DIAG_ line silently and the record had no such section, so the first assertion of each
 * builder case fails on the old builder (a RED test) and every refusal passes there with rc 0.
 *
 * THE CATALOG FIXTURE is built in ONE place (write_catalogs) and the expected ids are asked of ONE
 * function (expect): they follow the catalogs' own storage and id functions, so that when those
 * move this is the one edit.
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
#include "../../libkofeng/kofcore/kofmod/kofcap.h"
#include "../../libkofeng/kofcore/kofmod/kofdiagtree.h"
#include "../../libkofeng/verdictor/famcat.h"
#include "../../libkofeng/verdictor/tagcat.h"
#include "../../libkofeng/scanners/scan_state.h"
#include "../../libkofeng/scanners/objctx_int.h"
#include "catid_oracle.h"

static int failures;
static char root[256];
static const char *dbdir = "build/test/databases-sigs";
static const char *builder = "build/release/bin/ksigbuilder";

static void ok(const char *what, int cond)
{
	printf("  %s %s\n", cond ? "ok  " : "FAIL", what);
	if (!cond)
		failures++;
}

/* ---- files ------------------------------------------------------------------ */

static int write_file(const char *dir, const char *leaf, const void *p, size_t n)
{
	char path[700];
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

static int write_text(const char *dir, const char *leaf, const char *t)
{
	return write_file(dir, leaf, t, strlen(t));
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
	if (b)
		*n = (size_t)L;
	return b;
}

static int copy_good_pack(const char *dir)
{
	char src[700];
	uint8_t *b;
	size_t n = 0;
	int r;

	snprintf(src, sizeof src, "%s/sigs-any.ksig", dbdir);
	b = read_file(src, &n);
	r = b && n && write_file(dir, "sigs-any.ksig", b, n);
	free(b);
	return r;
}

static void rm_all(const char *dir)
{
	char cmd[800];

	snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
	(void)system(cmd);
}

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* ---- the loader, over records spelled out byte by byte ------------------------ */

struct meta_spec {
	int      present;       /* write the section at all */
	unsigned tag;           /* the section's tag byte: KDIG_SEC_META, or what an old reader sees it as */
	unsigned len;           /* its length byte (and the bytes that follow) */
	uint64_t fam, var, tg;
	unsigned type;
	int      twice;         /* two sections */
};

static const struct meta_spec good_meta = { 1, KDIG_SEC_META, KDIG_META_LEN,
					    0x1122334455667788ull, 0x0102030405060708ull,
					    0xa1a2a3a4a5a6a7a8ull, KOF_MALTYPE_BOTNET, 0 };

static size_t put_meta(uint8_t *b, size_t at, const struct meta_spec *m)
{
	unsigned i;
	uint64_t id[3];

	id[0] = m->fam; id[1] = m->var; id[2] = m->tg;
	b[at++] = (uint8_t)m->tag;
	b[at++] = (uint8_t)m->len;
	for (i = 0; i < m->len; i++) {
		unsigned z = i / 8u;

		if (i == 24u)
			b[at++] = (uint8_t)m->type;
		else if (z < 3u)
			b[at++] = (uint8_t)(id[z] >> ((i % 8u) * 8u));
		else
			b[at++] = 0;
	}
	return at;
}

static size_t rec(uint8_t *b, const char *name, const struct meta_spec *m)
{
	size_t nl = strlen(name), at = 0;
	uint16_t cap = (uint16_t)KGENOME_NUCLEO_NET_OPEN;

	b[at++] = 1; b[at++] = 0;
	b[at++] = KOF_DIAG_ANALYSIS_SYSCALL;
	b[at++] = (uint8_t)nl;
	memcpy(b + at, name, nl); at += nl;
	b[at++] = (uint8_t)cap; b[at++] = (uint8_t)(cap >> 8);
	b[at++] = 0; b[at++] = 0;
	b[at++] = KOF_DIAG_NO_PARENT;
	b[at++] = 0; b[at++] = 0; b[at++] = 0;
	if (m && m->present) {
		b[at++] = 0;                            /* the legacy name count */
		at = put_meta(b, at, m);
		if (m->twice)
			at = put_meta(b, at, m);
	}
	return at;
}

static size_t pack(uint8_t *b, const char *const *names, const struct meta_spec *const *specs, unsigned n)
{
	size_t at = 8u + (size_t)n * 8u;
	unsigned i;

	memcpy(b, "KDGP", 4);
	b[4] = 1; b[5] = 0;
	b[6] = (uint8_t)n; b[7] = (uint8_t)(n >> 8);
	for (i = 0; i < n; i++) {
		size_t l = rec(b + at, names[i], specs[i]);

		put32(b + 8u + i * 8u, (uint32_t)at);
		put32(b + 12u + i * 8u, (uint32_t)l);
		at += l;
	}
	return at;
}

static struct kof_engine *load_pack(const char *tag, char *dir, size_t cap,
				    const uint8_t *pk, size_t n)
{
	snprintf(dir, cap, "%s/%s", root, tag);
	if (kof_mkdir(dir, 0700) != 0 || !copy_good_pack(dir) ||
	    !write_file(dir, "diag-x.kdig", pk, n))
		return NULL;
	return kof_db_load(dir);
}

static const struct kof_diag *find(const struct kof_engine *e, const char *name)
{
	uint32_t i;

	for (i = 0; e && i < e->n_diag; i++)
		if (!strcmp(e->diag[i].name, name))
			return &e->diag[i];
	return NULL;
}

/* One record `r` with `m`, next to a plain sibling: what loaded. */
static struct kof_engine *one(const char *tag, const struct meta_spec *m)
{
	static uint8_t pk[512];
	const char *const names[2] = { "meta_a", "plain_b" };
	const struct meta_spec *specs[2];
	char dir[700];
	struct kof_engine *e;
	size_t n;

	specs[0] = m;
	specs[1] = NULL;
	n = pack(pk, names, specs, 2);
	e = load_pack(tag, dir, sizeof dir, pk, n);
	rm_all(dir);
	return e;
}

static void loader(void)
{
	struct kof_engine *e;
	const struct kof_diag *d;
	struct meta_spec m;

	e = one("good", &good_meta);
	d = find(e, "meta_a");
	ok("a record with the section loads", d != NULL);
	ok("the three ids and the type are read, little endian",
	   d && d->family_id == good_meta.fam && d->variant_id == good_meta.var &&
	   d->tag_id == good_meta.tg && d->type == KOF_MALTYPE_BOTNET);
	ok("the API gives the same four facts",
	   d && kdb_diagnose_family(e, d->id) == good_meta.fam &&
	   kdb_diagnose_variant(e, d->id) == good_meta.var &&
	   kdb_diagnose_tag(e, d->id) == good_meta.tg &&
	   kdb_diagnose_type(e, d->id) == (int)KOF_MALTYPE_BOTNET);
	d = find(e, "plain_b");
	ok("its sibling without the section loads with zeros (an old pack)",
	   d && !d->family_id && !d->variant_id && !d->tag_id &&
	   kdb_diagnose_family(e, d->id) == 0u && kdb_diagnose_type(e, d->id) == -1);
	ok("an id the database does not hold answers 0 and -1",
	   kdb_diagnose_family(e, 0xdeadbeefu) == 0u && kdb_diagnose_type(e, 0xdeadbeefu) == -1 &&
	   kdb_diagnose_tag(NULL, 1u) == 0u);
	if (e)
		kof_db_free(e);

	m = good_meta;
	m.type = KOF_MALTYPE_VIRUS;
	e = one("virus", &m);
	d = find(e, "meta_a");
	ok("a diagnose of type Virus reads back as type 0, not as none",
	   d && kdb_diagnose_type(e, d->id) == (int)KOF_MALTYPE_VIRUS);
	if (e)
		kof_db_free(e);

	/* AN OLD READER: it does not know tag 9 and skips it by its length. What it does is
	 * what the loader does with any unknown tag, so the record is read with the tag byte
	 * an old reader would see as unknown, and everything else must be equal. */
	m = good_meta;
	m.tag = 0x7e;
	e = one("old", &m);
	d = find(e, "meta_a");
	ok("a reader that does not know the tag skips the section by its length and loads the record",
	   d && d->n_node == 1u && !d->family_id && !d->tag_id && find(e, "plain_b") != NULL);
	if (e)
		kof_db_free(e);

	m = good_meta;
	m.len = 24;
	e = one("short", &m);
	ok("a section of 24 bytes refuses that record and keeps its sibling",
	   e && !find(e, "meta_a") && find(e, "plain_b"));
	if (e)
		kof_db_free(e);
	m = good_meta;
	m.len = 26;
	e = one("long", &m);
	ok("a section of 26 bytes refuses that record", e && !find(e, "meta_a") && find(e, "plain_b"));
	if (e)
		kof_db_free(e);
	m = good_meta;
	m.fam = 0;
	e = one("zero_fam", &m);
	ok("a family id of zero refuses the record", e && !find(e, "meta_a"));
	if (e)
		kof_db_free(e);
	m = good_meta;
	m.tg = 0;
	e = one("zero_tag", &m);
	ok("a tag id of zero refuses the record", e && !find(e, "meta_a"));
	if (e)
		kof_db_free(e);
	m = good_meta;
	m.type = KOF_MALTYPE_PACKER;
	e = one("packer", &m);
	ok("the type Packer refuses the record", e && !find(e, "meta_a"));
	if (e)
		kof_db_free(e);
	m = good_meta;
	m.type = KOF_MALTYPE_COUNT;
	e = one("badtype", &m);
	ok("a type that is no maltype refuses the record", e && !find(e, "meta_a"));
	if (e)
		kof_db_free(e);
	m = good_meta;
	m.twice = 1;
	e = one("twice", &m);
	ok("two sections refuse the record: half an identity names another", e && !find(e, "meta_a"));
	if (e)
		kof_db_free(e);
}

/* ---- the builder, over a tiny tree --------------------------------------------- */

static char base[300], art[300], db[300], err[300];

static const char *const head =
	"KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYSCALL | KOF_DIAG_ANALYSIS_SYMBOL);\n"
	"KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);\n"
	"KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n";

/* THE CATALOG FIXTURE, the one place: families Mirai (Botnet and Rootkit) and Gafgyt (Botnet), tags flood and c2. */
static void write_catalogs_order(int rev)
{
	struct kof_famcat_fam fam[8];
	struct kof_famcat_var var[8];
	struct kof_catstore *st = calloc(1, sizeof *st);
	struct kof_tagcat_tag tag[8];
	struct kof_tagcat tc;
	struct kof_famcat c;
	char dir[400];
	uint32_t f;

	snprintf(dir, sizeof dir, "%s/pathogens", base);
	kof_mkdir(dir, 0700);
	kof_famcat_init(&c, fam, 8, var, 8);
	kof_catstore_init(st);
	if (rev)
		(void)kof_famcat_add_family(&c, "Gafgyt", NULL, 1u << KOF_MALTYPE_BOTNET, &f);
	(void)kof_famcat_add_family(&c, "Mirai", NULL,
				    (1u << KOF_MALTYPE_BOTNET) | (1u << KOF_MALTYPE_ROOTKIT), &f);
	if (!rev)
		(void)kof_famcat_add_family(&c, "Gafgyt", NULL, 1u << KOF_MALTYPE_BOTNET, &f);
	(void)kof_famcat_save(&c, st, dir);
	snprintf(dir, sizeof dir, "%s/syndromes", base);
	kof_mkdir(dir, 0700);
	kof_tagcat_init(&tc, tag, 8);
	kof_catstore_init(st);
	if (rev)
		(void)kof_tagcat_add(&tc, "c2", 1u << KOF_DISEASE_ACT_C2, 1u << KOF_DISEASE_OBJ_NETWORK, NULL);
	(void)kof_tagcat_add(&tc, "flood", 1u << KOF_DISEASE_ACT_SCAN, 1u << KOF_DISEASE_OBJ_NETWORK, NULL);
	if (!rev)
		(void)kof_tagcat_add(&tc, "c2", 1u << KOF_DISEASE_ACT_C2, 1u << KOF_DISEASE_OBJ_NETWORK, NULL);
	(void)kof_tagcat_save(&tc, st, dir);
	free(st);
}

/* The ids the catalogs give: THE ONE FUNCTION that asks them. */
static int expect(const char *fam, const char *var, const char *tag, uint64_t out[3])
{
	struct kof_famcat_fam f[8];
	struct kof_famcat_var v[8];
	struct kof_tagcat_tag t[8];
	struct kof_famcat fc;
	struct kof_tagcat tc;
	char dir[400], why[200];

	kof_famcat_init(&fc, f, 8, v, 8);
	kof_tagcat_init(&tc, t, 8);
	snprintf(dir, sizeof dir, "%s/pathogens", base);
	if (kof_famcat_load_dir(&fc, dir, why, sizeof why) != KOF_CATSTORE_IO_OK)
		return 0;
	snprintf(dir, sizeof dir, "%s/syndromes", base);
	if (kof_tagcat_load_dir(&tc, dir, why, sizeof why) != KOF_CATSTORE_IO_OK)
		return 0;
	out[0] = kof_famcat_family_id(&fc, fam);
	out[1] = kof_famcat_variant_id(&fc, fam, var);
	out[2] = kof_tagcat_id(&tc, tag);
	return out[0] && out[1] && out[2];
}

/* <base>/<leaf> as a string that lives until the next call. */
static const char *dir_of(const char *leaf)
{
	static char d[400];

	snprintf(d, sizeof d, "%s/%s", base, leaf);
	return d;
}

static void fresh_order(const char *tag, int rev)
{
	char d[400];

	snprintf(base, sizeof base, "%s/%s_base", root, tag);
	snprintf(art, sizeof art, "%s/%s_art", root, tag);
	snprintf(db, sizeof db, "%s/%s_db", root, tag);
	snprintf(err, sizeof err, "%s/%s_err.txt", root, tag);
	kof_mkdir(base, 0700);
	kof_mkdir(art, 0700);
	kof_mkdir(db, 0700);
	snprintf(d, sizeof d, "%s/diagnoses", base);
	kof_mkdir(d, 0700);
	write_catalogs_order(rev);
	(void)copy_good_pack(db);
}

static void fresh(const char *tag)
{
	fresh_order(tag, 0);
}

static void fresh_rev(const char *tag)
{
	fresh_order(tag, 1);
}

static void diag_src(const char *leaf, const char *name, const char *fam, const char *var,
		     const char *type, const char *tag)
{
	char d[400], t[1500];
	size_t at;

	snprintf(d, sizeof d, "%s/diagnoses", base);
	at = (size_t)snprintf(t, sizeof t, "KOF_DIAG_NAME(%s);\n", name);
	if (fam)
		at += (size_t)snprintf(t + at, sizeof t - at, "KOF_DIAG_FAMILY(\"%s\");\n", fam);
	if (var)
		at += (size_t)snprintf(t + at, sizeof t - at, "KOF_DIAG_VARIANT(\"%s\");\n", var);
	if (type)
		at += (size_t)snprintf(t + at, sizeof t - at, "KOF_DIAG_TYPE(%s);\n", type);
	if (tag)
		at += (size_t)snprintf(t + at, sizeof t - at, "KOF_DIAG_TAG(\"%s\");\n", tag);
	snprintf(t + at, sizeof t - at, "%s", head);
	write_text(d, leaf, t);
}

/* Run the tree build. Returns the exit status (0 = built); stderr goes to `err`. */
static int build(int with_catalogs)
{
	char cmd[2400];
	int rc;

	if (with_catalogs)
		snprintf(cmd, sizeof cmd, "%s --tree '%s' '%s' '%s' --pathogens '%s/pathogens' "
			 "--syndromes '%s/syndromes' --basedir '%s' >/dev/null 2>'%s'",
			 builder, base, art, db, base, base, base, err);
	else
		snprintf(cmd, sizeof cmd, "%s --tree '%s' '%s' '%s' --basedir '%s' >/dev/null 2>'%s'",
			 builder, base, art, db, base, err);
	rc = system(cmd);
	return rc;
}

static int said(const char *needle)
{
	size_t n = 0;
	uint8_t *b = read_file(err, &n);
	int r;
	char *t;

	if (!b)
		return 0;
	t = malloc(n + 1u);
	memcpy(t, b, n);
	t[n] = 0;
	r = strstr(t, needle) != NULL;
	free(b);
	free(t);
	return r;
}

/* The engine over the build's db directory, or NULL. */
static struct kof_engine *engine(void)
{
	return kof_db_load(db);
}

static void refused(const char *tag, const char *what, const char *msg_part, const char *line_part,
		    const char *fam, const char *var, const char *type, const char *tg)
{
	int rc;
	char label[200];

	fresh(tag);
	diag_src("botnet_x_01.c", "botnet_x_01", fam, var, type, tg);
	rc = build(1);
	snprintf(label, sizeof label, "refused, rc != 0: %s", what);
	ok(label, rc != 0);
	snprintf(label, sizeof label, "says why (\"%s\") ...", msg_part);
	ok(label, said(msg_part));
	snprintf(label, sizeof label, "... with the file and the line (%s)", line_part);
	ok(label, said(line_part));
	{
		struct kof_engine *e = engine();

		ok("... and no diagnose reaches the database", e && kdb_diagnoses(e) == 0u);
		if (e)
			kof_db_free(e);
	}
}

/* A family or a tag the catalog lacks (owner 2026-11-01): the build WARNS (the diagnose and what is missing), exits 0, and nothing reaches the database. */
static void disabled(const char *tag, const char *what, const char *msg_part,
		     const char *fam, const char *var, const char *tg)
{
	char label[200];

	fresh(tag);
	diag_src("botnet_x_01.c", "botnet_x_01", fam, var, "KOF_MALTYPE_BOTNET", tg);
	snprintf(label, sizeof label, "disabled, rc 0: %s", what);
	ok(label, build(1) == 0);
	snprintf(label, sizeof label, "warns (\"%s\") ...", msg_part);
	ok(label, said("warning:") && said("botnet_x_01") && said(msg_part));
	{
		struct kof_engine *e = engine();

		ok("... and no diagnose reaches the database", e && kdb_diagnoses(e) == 0u);
		if (e)
			kof_db_free(e);
	}
}

static void builder_cases(void)
{
	uint64_t id[3] = { 0, 0, 0 };
	struct kof_engine *e;
	const struct kof_diag *d;
	char dir[400], p1[700], p2[700];
	uint8_t *a, *b;
	size_t na = 0, nb = 0;

	/* A valid diagnose builds, and the section carries the catalogs' ids. */
	fresh("good");
	diag_src("botnet_mirai_flood_01.c", "botnet_mirai_flood_01", "Mirai", "A",
		 "KOF_MALTYPE_BOTNET", "flood");
	ok("a diagnose with valid names builds", build(1) == 0);
	ok("the catalog fixture gives ids", expect("Mirai", "A", "flood", id));
	ok("and they are the oracle's, made from the names alone",
	   id[0] == oracle_family("Mirai") && id[1] == oracle_variant("Mirai", "A") && id[2] == oracle_tag("flood"));
	e = engine();
	d = find(e, "botnet_mirai_flood_01");
	ok("it is in the database", d != NULL);
	ok("its section carries the family, variant and tag ids of the catalogs and the type",
	   d && d->family_id == id[0] && d->variant_id == id[1] && d->tag_id == id[2] &&
	   d->type == KOF_MALTYPE_BOTNET);
	ok("the ids in the pack are the oracle's, not the library's own answer",
	   d && d->family_id == oracle_family("Mirai") && d->variant_id == oracle_variant("Mirai", "A") && d->tag_id == oracle_tag("flood"));
	ok("a diagnose with catalog facts is not told it declares no disease", !said("declares no disease"));
	if (d) {
		/* the engine: a diagnose that carries the facts and has no rule and no disease is READ (by the verdict) */
		kof_scanner *sc = kscan_new(e);

		ok("a diagnose with a tag is run by the engine (oc_diag_used)",
		   sc && d->tag_id && oc_diag_used(sc, d));
		kscan_free(sc);
	}
	ok("the API answers the same",
	   d && kdb_diagnose_family(e, d->id) == id[0] && kdb_diagnose_type(e, d->id) == (int)KOF_MALTYPE_BOTNET);
	if (e)
		kof_db_free(e);

	/* Two builds from the same sources are the same bytes. */
	snprintf(p1, sizeof p1, "%s/diag-botnet.kdig", db);
	a = read_file(p1, &na);
	snprintf(dir, sizeof dir, "%s_second", art);
	kof_mkdir(dir, 0700);
	{
		char d2[400];

		snprintf(d2, sizeof d2, "%s_db2", db);
		kof_mkdir(d2, 0700);
		(void)copy_good_pack(d2);
		{
			char cmd[2400];

			snprintf(cmd, sizeof cmd, "%s --tree '%s' '%s' '%s' --pathogens '%s/pathogens' "
				 "--syndromes '%s/syndromes' --basedir '%s' >/dev/null 2>&1",
				 builder, base, dir, d2, base, base, base);
			ok("a second build succeeds", system(cmd) == 0);
		}
		snprintf(p2, sizeof p2, "%s/diag-botnet.kdig", d2);
		b = read_file(p2, &nb);
	}
	ok("two builds are byte-identical", a && b && na == nb && !memcmp(a, b, na));
	ok("and the record ends with the section: tag 9, length 25",
	   a && na > 27u && a[na - 27u] == KDIG_SEC_META && a[na - 26u] == KDIG_META_LEN && a[na - 28u] == 0);
	free(a);
	free(b);

	/* The legacy count byte, for a record whose only extra is the section: standalone --diagnose
	 * writes no USERS, so nothing else follows the nodes. Without the byte an old reader would
	 * take tag 9 for a count of nine names. */
	{
		char cmd[2400], out[400], src[400];
		size_t n = 0, nl = strlen("botnet_mirai_flood_01");
		uint8_t *r;

		snprintf(src, sizeof src, "%s/diagnoses/botnet_mirai_flood_01.c", base);
		snprintf(out, sizeof out, "%s/one.rec", art);
		snprintf(cmd, sizeof cmd, "%s --diagnose '%s' '%s' --pathogens '%s/pathogens' "
			 "--syndromes '%s/syndromes' >/dev/null 2>&1", builder, src, out, base, base);
		ok("--diagnose builds the record", system(cmd) == 0);
		r = read_file(out, &n);
		/* header 4, name, two nodes of 8, the count byte, then the section; no other section follows */
		ok("the count byte (0) stands between the nodes and the section tag",
		   r && n >= 4u + nl + 16u + 1u + 27u && r[n - 27u - 1u] == 0 && r[n - 27u] == KDIG_SEC_META);
		ok("and the record is exactly nodes + count + section (nothing else was added)",
		   r && n == 4u + nl + 16u + 1u + 27u);
		free(r);
	}

	/* A source without the new lines builds as it always did: no section, zeros. */
	fresh("old");
	diag_src("botnet_x_01.c", "botnet_x_01", NULL, NULL, NULL, NULL);
	ok("a diagnose without the four lines builds (with no catalogs given)", build(0) == 0);
	e = engine();
	d = find(e, "botnet_x_01");
	ok("and loads with zeros", d && !d->family_id && !d->tag_id && kdb_diagnose_type(e, d->id) == -1);
	if (e)
		kof_db_free(e);

	/* The refusals. Each names the file and the line of the declaration at fault. */
	disabled("nofam", "a family not in the catalog", "family \"Nope\" is not in the Pathogens catalog", "Nope", "A", "flood");
	refused("novar", "a variant not in the family", "variant \"Z\" of family \"Mirai\" is not in the Pathogens catalog",
		"botnet_x_01.c:3:", "Mirai", "Z", "KOF_MALTYPE_BOTNET", "flood");
	refused("fullname", "the full catalog name as the variant", "letters only",
		"botnet_x_01.c:3:", "Mirai", "Mirai_A", "KOF_MALTYPE_BOTNET", "flood");
	refused("othfam", "the letters of a variant the family does not have (Gafgyt has A only)",
		"variant \"B\" of family \"Gafgyt\" is not in the Pathogens catalog",
		"botnet_x_01.c:3:", "Gafgyt", "B", "KOF_MALTYPE_BOTNET", "flood");
	refused("badtype", "a type the variant does not declare", "is not one of the types variant \"A\" declares",
		"botnet_x_01.c:4:", "Gafgyt", "A", "KOF_MALTYPE_ROOTKIT", "flood");
	refused("packer", "the type Packer", "the type Packer is not a malware type",
		"botnet_x_01.c:4:", "Mirai", "A", "KOF_MALTYPE_PACKER", "flood");
	disabled("notag", "a tag not in the catalog", "tag \"nothing\" is not in the Syndromes catalog", "Mirai", "A", "nothing");
	refused("partial", "only three of the four lines",
		"written together or not at all", "botnet_x_01.c:",
		"Mirai", "A", "KOF_MALTYPE_BOTNET", NULL);

	/* No catalogs given to a build that needs them. */
	fresh("nocat");
	diag_src("botnet_x_01.c", "botnet_x_01", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood");
	ok("a build given no catalogs refuses a diagnose that names a family", build(0) != 0);
	ok("... and says to pass --pathogens and --syndromes", said("--pathogens") && said("botnet_x_01.c:2:"));

	/* Collisions: the same name twice. Diagnoses MAY share family, variant, type and tag, copies included. */
	fresh("collide");
	diag_src("botnet_mirai_flood_01.c", "botnet_mirai_flood_01", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood");
	diag_src("botnet_mirai_flood_02.c", "botnet_mirai_flood_01", "Mirai", "A", "KOF_MALTYPE_BOTNET", "c2");
	ok("two diagnoses with one name are refused", build(1) != 0 && said("is also the name of"));
	fresh("copy");
	diag_src("botnet_mirai_flood_01.c", "botnet_mirai_flood_01", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood");
	diag_src("botnet_mirai_flood_02.c", "botnet_mirai_flood_02", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood");
	ok("a copy (same facts, same nodes and conditions) is NOT refused: family, variant, type and tag are never a gate",
	   build(1) == 0 && !said("collides"));
	fresh("share");
	diag_src("botnet_mirai_flood_01.c", "botnet_mirai_flood_01", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood");
	{
		char d2[400], t[1500];

		snprintf(d2, sizeof d2, "%s/diagnoses", base);
		snprintf(t, sizeof t, "KOF_DIAG_NAME(botnet_mirai_flood_02);\nKOF_DIAG_FAMILY(\"Mirai\");\n"
			 "KOF_DIAG_VARIANT(\"A\");\nKOF_DIAG_TYPE(KOF_MALTYPE_BOTNET);\nKOF_DIAG_TAG(\"flood\");\n"
			 "KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYSCALL | KOF_DIAG_ANALYSIS_SYMBOL);\n"
			 "KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);\n"
			 "KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_EXEC_REG);\n");
		write_text(d2, "botnet_mirai_flood_02.c", t);
	}
	ok("two diagnoses of one family, variant, type and tag that look for different things are fine",
	   build(1) == 0);

	/* --catalog: the validation mode, non-zero on an error. */
	{
		char cmd[2400];
		int rc_abs;

		fresh("catmode");
		diag_src("botnet_mirai_flood_01.c", "botnet_mirai_flood_01", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood");
		snprintf(cmd, sizeof cmd, "%s --catalog '%s/diagnoses' --pathogens '%s/pathogens' "
			 "--syndromes '%s/syndromes' >'%s' 2>&1", builder, base, base, base, err);
		ok("--catalog over a good tree exits 0 and prints its count",
		   system(cmd) == 0 && said("1 diagnose(s), 1 with family/variant/type/tag, 0 error(s)"));
		diag_src("botnet_x_02.c", "botnet_x_02", "Mirai", "Z", "KOF_MALTYPE_BOTNET", "flood");
		diag_src("botnet_x_03.c", "botnet_x_03", "Mirai", "A", "KOF_MALTYPE_PACKER", "flood");
		ok("--catalog reports every error (not the first) and exits non-zero",
		   system(cmd) != 0 && said("botnet_x_02.c:3:") && said("botnet_x_03.c:4:") &&
		   said("2 error(s)"));
		/* an absent family or tag is a warning each (the diagnose is disabled), not an error: exit 0 */
		fresh("catabs");
		snprintf(cmd, sizeof cmd, "%s --catalog '%s/diagnoses' --pathogens '%s/pathogens' "
			 "--syndromes '%s/syndromes' >'%s' 2>&1", builder, base, base, base, err);
		diag_src("botnet_x_02.c", "botnet_x_02", "Mirai", "A", "KOF_MALTYPE_BOTNET", "gone");
		diag_src("botnet_x_03.c", "botnet_x_03", "Zzz", "A", "KOF_MALTYPE_BOTNET", "flood");
		rc_abs = system(cmd);
		ok("--catalog warns for an absent tag and an absent family and exits 0",
		   rc_abs == 0 && said("botnet_x_02") && said("botnet_x_03") && said("0 error(s)"));
	}

	/* A catalog file with no id line (every file an owner writes now, and bases/pathogens/mirai.c): the build gives the family the oracle's id
	 * and WRITES NOTHING BACK to the source (the builder once saved ids into it). */
	{
		char cmd[2400], path[400], *txt;
		FILE *f;
		long n;
		static const char plain[] = "KOF_MALWARE_FAMILY_NAME(\"Mirai\");\nKOF_MALWARE_NEXT_VARIANT(\"B\");\n"
					    "KOF_MALWARE_VARIANT(\"A\", KOF_MALTYPE_BOTNET);\n";

		fresh("noids");
		snprintf(path, sizeof path, "%s/pathogens/mirai.c", base);
		ok("a catalog file without ids is written", write_text(dir_of("pathogens"), "mirai.c", plain));
		diag_src("botnet_mirai_flood_01.c", "botnet_mirai_flood_01", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood");
		snprintf(cmd, sizeof cmd, "%s --catalog '%s/diagnoses' --pathogens '%s/pathogens' "
			 "--syndromes '%s/syndromes' >'%s' 2>&1", builder, base, base, base, err);
		ok("--catalog over a catalog file without ids exits 0", system(cmd) == 0 && said("0 error(s)"));
		f = fopen(path, "r");
		txt = calloc(1, 4096);
		n = f && txt ? (long)fread(txt, 1, 4095, f) : 0;
		if (f)
			fclose(f);
		ok("the source is exactly as written: no id was written back", n == (long)strlen(plain) && !strcmp(txt, plain));
		free(txt);
		ok("a build over it succeeds and the source is still untouched", build(1) == 0);
		f = fopen(path, "r");
		txt = calloc(1, 4096);
		n = f && txt ? (long)fread(txt, 1, 4095, f) : 0;
		if (f)
			fclose(f);
		ok("... after the build too", n == (long)strlen(plain) && !strcmp(txt, plain));
		free(txt);
	}

	/* A catalog saved by an older tool, WITH id lines: the same pack as without them, the lines said as ignored and used nowhere. */
	{
		uint8_t *plain_pack, *old_pack;
		size_t np = 0, no = 0;
		char q1[700], q2[700], d2[400];
		static const char old[] = "KOF_MALWARE_FAMILY_NAME(\"Mirai\");\nKOF_MALWARE_FAMILY_ID(0xc627704b844b1723);\n"
					  "KOF_MALWARE_NEXT_VARIANT(\"B\");\nKOF_MALWARE_VARIANT(\"A\", KOF_MALTYPE_BOTNET);\n"
					  "KOF_MALWARE_VARIANT_ID(\"A\", 0x1358c2d70def8cc0);\n";
		static const char oldtag[] = "KOF_TAG_NAME(\"flood\");\nKOF_TAG_ID(0x7b5c9a6b3eff2038);\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\n"
					     "KOF_TAG_OBJS(KOF_DISEASE_OBJ_NETWORK);\n";

		fresh("oldids");
		diag_src("botnet_mirai_flood_01.c", "botnet_mirai_flood_01", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood");
		ok("a build over the written catalogs succeeds", build(1) == 0);
		snprintf(q1, sizeof q1, "%s/diag-botnet.kdig", db);
		plain_pack = read_file(q1, &np);
		snprintf(d2, sizeof d2, "%s_old", base);
		kof_mkdir(d2, 0700);
		rm_all(dir_of("pathogens"));
		rm_all(dir_of("syndromes"));
		kof_mkdir(dir_of("pathogens"), 0700);
		kof_mkdir(dir_of("syndromes"), 0700);
		ok("the old catalog files are written", write_text(dir_of("pathogens"), "mirai.c", old) && write_text(dir_of("syndromes"), "network_scan.c", oldtag));
		ok("a build over them succeeds", build(1) == 0);
		ok("and says the lines were ignored", said("not understood and ignored"));
		snprintf(q2, sizeof q2, "%s/diag-botnet.kdig", db);
		old_pack = read_file(q2, &no);
		ok("the pack is byte-identical to the one built without id lines: the old numbers are used nowhere",
		   plain_pack && old_pack && np == no && !memcmp(plain_pack, old_pack, np));
		{
			struct kof_engine *e2 = engine();
			const struct kof_diag *d2p = find(e2, "botnet_mirai_flood_01");

			ok("and the ids in it are not the file's", d2p && d2p->family_id != 0xc627704b844b1723ull && d2p->tag_id != 0x7b5c9a6b3eff2038ull &&
			   d2p->family_id == oracle_family("Mirai"));
			if (e2)
				kof_db_free(e2);
		}
		free(plain_pack);
		free(old_pack);
	}

	/* The same catalogs written in another ORDER give the same pack (nothing in an id follows the order of anything). */
	{
		uint8_t *a1, *b1;
		size_t n1 = 0, n2 = 0;
		char q1[700], q2[700];

		fresh("order_a");
		diag_src("botnet_mirai_flood_01.c", "botnet_mirai_flood_01", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood");
		ok("order: the first build succeeds", build(1) == 0);
		snprintf(q1, sizeof q1, "%s/diag-botnet.kdig", db);
		a1 = read_file(q1, &n1);
		fresh_rev("order_b");
		diag_src("botnet_mirai_flood_01.c", "botnet_mirai_flood_01", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood");
		ok("order: the second build (catalogs written in the other order) succeeds", build(1) == 0);
		snprintf(q2, sizeof q2, "%s/diag-botnet.kdig", db);
		b1 = read_file(q2, &n2);
		ok("order: the packs are byte-identical", a1 && b1 && n1 == n2 && !memcmp(a1, b1, n1));
		free(a1);
		free(b1);
	}

	/* A RENAME is a new id: the tag renamed in the catalog and in the diagnose gets the oracle's id of the new name. */
	{
		char path[400], cat[400];
		struct kof_engine *e2;
		const struct kof_diag *d2p;

		fresh("rename");
		snprintf(path, sizeof path, "%s/syndromes", base);
		rm_all(path);
		kof_mkdir(path, 0700);
		snprintf(cat, sizeof cat, "KOF_TAG_NAME(\"flood2\");\nKOF_TAG_ACTS(KOF_DISEASE_ACT_SCAN);\nKOF_TAG_OBJS(KOF_DISEASE_OBJ_NETWORK);\n");
		ok("the renamed tag file is written", write_text(path, "network_scan.c", cat));
		diag_src("botnet_mirai_flood_01.c", "botnet_mirai_flood_01", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood2");
		ok("a build with the renamed tag succeeds", build(1) == 0);
		e2 = engine();
		d2p = find(e2, "botnet_mirai_flood_01");
		ok("its tag id is the new name's, not the old one's", d2p && d2p->tag_id == oracle_tag("flood2") && d2p->tag_id != oracle_tag("flood"));
		if (e2)
			kof_db_free(e2);
		diag_src("botnet_mirai_flood_01.c", "botnet_mirai_flood_01", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood");
		ok("the old name is no longer in the catalog: the diagnose is disabled, the build goes on",
		   build(1) == 0 && said("\"flood\" is not in the Syndromes catalog"));
	}

	/* A catalog file that does not load refuses the build (it was skipped and the build said "not in the catalog" about the wrong thing),
	 * and a build never writes into the catalogs. */
	{
		fresh("badfile");
		ok("a bad catalog file is written", write_text(dir_of("pathogens"), "bad.c", "KOF_MALWARE_FAMILY_NAME(\"Bad name\");\n"));
		diag_src("botnet_mirai_flood_01.c", "botnet_mirai_flood_01", "Mirai", "A", "KOF_MALTYPE_BOTNET", "flood");
		ok("the build is refused", build(1) != 0);
		ok("and names the file", said("bad.c"));
	}
}

int main(int argc, char **argv)
{
	if (argc > 1)
		dbdir = argv[1];
	snprintf(root, sizeof root, "build/test/diagmeta_%d", (int)getpid());
	if (kof_mkdir(root, 0700) != 0) {
		printf("diag_meta: cannot make a work directory\n");
		return 1;
	}
	if (access(builder, X_OK) != 0) {
		printf("diag_meta: %s is not built\n", builder);
		rm_all(root);
		return 1;
	}
	printf("diag_meta:\n");
	loader();
	builder_cases();
	rm_all(root);
	printf("diag_meta: %s\n", failures ? "FAILED" : "all ok");
	return failures ? 1 : 0;
}
