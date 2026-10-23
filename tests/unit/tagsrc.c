/*
 * tagsrc - the tag sources, read, written back and checked.
 *
 * What is pinned: a file is PATCHED, never regenerated (a line whose
 * declaration is unchanged stays byte for byte, the author's comments and a
 * declaration this tool does not know survive a save); the seeds in
 * bases/syndromes are exactly what the tool writes and load without an error;
 * every Check rule fires on the file that breaks it and on no other; an id is
 * never reused and never below the seeds'; a new file never overwrites another
 * entity's; and a hostile file (truncated, huge, a bad id, a declaration twice)
 * is reported and is not an entity.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../libkofeng/databases/tagsrc.h"

static int fails;

#define CHECK(c, ...) do { \
	if (!(c)) { \
		printf("  FAIL %s:%d: ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		fails++; \
	} \
} while (0)

/* ---- a scratch directory beside the build output ---------------------------- */

static char dir[64];

static void scratch_open(void)
{
	snprintf(dir, sizeof dir, "build/kof_tagsrc_XXXXXX");
	if (!mkdtemp(dir)) {
		printf("  FAIL cannot make a scratch directory\n");
		exit(1);
	}
}

static void scratch_clear(void)
{
	DIR *d = opendir(dir);
	struct dirent *de;
	char p[512];

	while (d && (de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.')
			continue;
		snprintf(p, sizeof p, "%s/%s", dir, de->d_name);
		remove(p);
	}
	if (d)
		closedir(d);
}

static void scratch_close(void)
{
	scratch_clear();
	rmdir(dir);
}

static void put(const char *name, const char *text, size_t n)
{
	char p[256];
	FILE *f;

	snprintf(p, sizeof p, "%s/%s", dir, name);
	f = fopen(p, "wb");
	if (f) {
		fwrite(text, 1, n, f);
		fclose(f);
	}
}

static void puts_(const char *name, const char *text)
{
	put(name, text, strlen(text));
}

static char *slurp(const char *path, size_t *n)
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
		*n = (size_t)L;
	}
	return b;
}

static int has_file(const char *name)
{
	char p[256];

	snprintf(p, sizeof p, "%s/%s", dir, name);
	return access(p, F_OK) == 0;
}

/* ---- reports ------------------------------------------------------------------ */

struct log {
	char     text[16384];
	unsigned n[3];
};

static void say(void *ud, int level, const char *subject, const char *msg)
{
	struct log *l = ud;
	size_t at = strlen(l->text);

	l->n[level]++;
	snprintf(l->text + at, sizeof l->text - at, "%d %s: %s\n", level,
		 subject, msg);
}

static int check(struct kof_tagset *s, struct log *l)
{
	struct kof_tagsrc_report r;

	memset(l, 0, sizeof *l);
	r.say = say;
	r.ud = l;
	return kof_tagset_check(s, &r);
}

static int said(const struct log *l, const char *what)
{
	return strstr(l->text, what) != NULL;
}

static void load(struct kof_tagset *s)
{
	kof_tagset_init(s);
	CHECK(kof_tagset_load(s, dir), "load of %s", dir);
}

/* ---- the files used below ------------------------------------------------------- */

#define ACT_NET "KOF_ACTIVITY_ID(0x100);\nKOF_ACTIVITY_NAME(\"network\");\n"
#define ACT_MEM "KOF_ACTIVITY_ID(0x101);\nKOF_ACTIVITY_NAME(\"memory\");\n"
#define TYP_BOT "KOF_TYPE_ID(3);\nKOF_TYPE_NAME(\"botnet\");\n"
#define TYP_TRO "KOF_TYPE_ID(1);\nKOF_TYPE_NAME(\"trojan\");\n"
#define FAM_MIR "KOF_FAMILY_ID(0x3f9a1c42b7d05e11);\n" \
		"KOF_FAMILY_NAME(\"mirai\");\n"

static void base_files(void)
{
	puts_("activity_network_00000000.c", ACT_NET);
	puts_("activity_memory_00000000.c", ACT_MEM);
	puts_("type_botnet_00000000.c", TYP_BOT);
	puts_("type_trojan_00000000.c", TYP_TRO);
}

static const char tag_c2[] =
	"/* the author's evidence stays */\n"
	"KOF_TAG_ID(0x200);\n"
	"KOF_TAG_NAME(\"c2\");\n"
	"KOF_TAG_ACTIVITY(0x100);  /* network */\n"
	"KOF_TAG_TYPE(3);\n"
	"KOF_TAG_SOMETHING_NEW(7);   /* a newer tool's declaration */\n"
	"KOF_TAG_COMMENT(\"takes orders\");\n";

/* ---- the seeds ----------------------------------------------------------------- */

static void seeds(void)
{
	struct kof_tagset s;
	struct log l;
	DIR *d = opendir("bases/syndromes");
	size_t i, act = 0, typ = 0, fam = 0, tag = 0;

	CHECK(d != NULL, "bases/syndromes is not here");
	if (!d)
		return;
	kof_tagset_init(&s);
	CHECK(kof_tagset_load(&s, "bases/syndromes"), "seeds load");
	CHECK(s.n_prob == 0, "seeds have %zu problem(s): %s", s.n_prob,
	      s.n_prob ? s.prob[0].msg : "");
	CHECK(check(&s, &l) == 0, "seeds have errors:\n%s", l.text);
	for (i = 0; i < s.n; i++) {
		const struct kof_tagent *e = &s.e[i];
		char fn[160], path[600];
		size_t n = 0, tn = 0;
		char *file, *fresh;

		act += e->kind == KOF_TAGSRC_K_ACTIVITY;
		typ += e->kind == KOF_TAGSRC_K_TYPE;
		fam += e->kind == KOF_TAGSRC_K_FAMILY;
		tag += e->kind == KOF_TAGSRC_K_TAG;
		CHECK(e->id < KOF_TAGSRC_ID_SEED_MAX, "%s: not a seed id",
		      e->name);
		kof_tagsrc_file_name(e, fn, sizeof fn);
		snprintf(path, sizeof path, "bases/syndromes/%s", fn);
		file = slurp(path, &n);
		CHECK(file != NULL, "%s is not named from its own id", fn);
		if (!file)
			continue;
		/* The file is what the tool writes: nothing in it is by hand. */
		fresh = kof_tagsrc_new(e, &s, &tn);
		CHECK(fresh && tn == n && !memcmp(fresh, file, n),
		      "%s is not what kof_tagsrc_new writes", fn);
		free(fresh);
		/* And a save with nothing changed writes the same bytes. */
		fresh = kof_tagsrc_patch(file, n, e, &s, &tn);
		CHECK(fresh && tn == n && !memcmp(fresh, file, n),
		      "%s changes under a patch that changes nothing", fn);
		free(fresh);
		free(file);
	}
	CHECK(act == 3 && typ == 10 && fam == 0 && tag == 3,
	      "seeds: %zu activities %zu types %zu families %zu tags", act, typ,
	      fam, tag);
	/* One type per KOF_MALTYPE value that is malware, its id the value.
	 * Packer (the last value) is a recognised wrapper, not a type. */
	for (i = 0; i < 10; i++) {
		const struct kof_tagent *e = kof_tagset_find(&s,
							     KOF_TAGSRC_K_TYPE, i);

		CHECK(e != NULL, "no type with the id of maltype %zu", i);
	}
	closedir(d);
	kof_tagset_free(&s);
}

/* ---- read, print, patch ------------------------------------------------------------ */

static void round_trip(void)
{
	struct kof_dsrc *d = calloc(1, sizeof *d);
	struct kof_tagent e;
	struct kof_tagset s;
	size_t n = sizeof tag_c2 - 1u, pn = 0, i;
	char *p, *q;
	size_t qn = 0;

	scratch_open();
	base_files();
	puts_("tag_c2_00000000.c", tag_c2);
	load(&s);
	CHECK(kof_tagsrc_parse(tag_c2, n, d, NULL) == 0, "parse");
	CHECK(kof_tagsrc_entity(d, &e, NULL) == 0, "entity");
	CHECK(e.kind == KOF_TAGSRC_K_TAG && e.id == 0x200 &&
	      !strcmp(e.name, "c2") && e.n_act == 1 && e.act[0] == 0x100 &&
	      e.n_typ == 1 && e.typ[0] == 3 && !strcmp(e.comment, "takes orders"),
	      "what was read");

	/* Nothing changed: the same bytes, the unknown line and the prose too. */
	p = kof_tagsrc_patch(tag_c2, n, &e, &s, &pn);
	CHECK(p && pn == n && !memcmp(p, tag_c2, n), "unchanged is not identical");
	free(p);

	/* A rename touches the name line and no other. */
	snprintf(e.name, sizeof e.name, "command-and-control");
	p = kof_tagsrc_patch(tag_c2, n, &e, &s, &pn);
	CHECK(p && strstr(p, "KOF_TAG_NAME(\"command-and-control\");") &&
	      strstr(p, "/* the author's evidence stays */") &&
	      strstr(p, "KOF_TAG_SOMETHING_NEW(7);   /* a newer tool's "
			"declaration */") &&
	      strstr(p, "KOF_TAG_ACTIVITY(0x100);  /* network */") &&
	      !strstr(p, "\"c2\""), "rename: %s", p ? p : "(null)");
	/* An added type is a new line, written with the name of what it names. */
	e.typ[e.n_typ++] = 1;
	free(p);
	p = kof_tagsrc_patch(tag_c2, n, &e, &s, &pn);
	CHECK(p && strstr(p, "KOF_TAG_TYPE(0x0000000000000001);  /* trojan */"),
	      "added type: %s", p ? p : "(null)");
	/* The comment after an id is for people: changing it changes nothing. */
	if (p) {
		for (q = p; (q = strstr(q, "/* trojan */")) != NULL;)
			memcpy(q, "/* banana */", 12);
		d->n = 0;
		kof_tagsrc_parse(p, pn, d, NULL);
		kof_tagsrc_entity(d, &e, NULL);
		CHECK(e.n_typ == 2 && e.typ[1] == 1, "the trailing comment was read");
	}
	free(p);
	/* Removing what the file has removes its line and keeps the rest. */
	e.n_typ = 0;
	e.has_fam = 0;
	p = kof_tagsrc_patch(tag_c2, n, &e, &s, &pn);
	CHECK(p && !strstr(p, "KOF_TAG_TYPE(") &&
	      strstr(p, "KOF_TAG_SOMETHING_NEW"), "removed type: %s",
	      p ? p : "(null)");
	free(p);
	/* A file that cannot be read is not patched. */
	q = kof_tagsrc_patch("KOF_TAG_NAME(\"broken", 21, &e, &s, &qn);
	CHECK(q == NULL, "a file that does not read was patched");
	/* The family, the three attributes, and the line they print as. */
	memset(&e, 0, sizeof e);
	e.kind = KOF_TAGSRC_K_TAG;
	e.id = 0x4000;
	snprintf(e.name, sizeof e.name, "t");
	e.n_act = 1;
	e.act[0] = 0x100;
	e.has_fam = 1;
	e.fam = 0x3f9a1c42b7d05e11ull;
	e.attr[KOF_TAGSRC_A_FORMAT][e.n_attr[KOF_TAGSRC_A_FORMAT]++] =
		(uint16_t)kof_tagsrc_vocab_find(KOF_TAGSRC_A_FORMAT,
						"KOF_FMT_ELF");
	e.attr[KOF_TAGSRC_A_ARCH][e.n_attr[KOF_TAGSRC_A_ARCH]++] =
		(uint16_t)kof_tagsrc_vocab_find(KOF_TAGSRC_A_ARCH,
						"KOF_ARCH_X86_64");
	e.attr[KOF_TAGSRC_A_SUBTYPE][e.n_attr[KOF_TAGSRC_A_SUBTYPE]++] =
		(uint16_t)kof_tagsrc_vocab_find(KOF_TAGSRC_A_SUBTYPE,
						"KOF_ELF_EXEC");
	CHECK(e.attr[0][0] < 100 && kof_tagsrc_vocab_find(1, "KOF_ARCH_X86_64")
	      >= 0 && kof_tagsrc_vocab_find(2, "KOF_ELF_EXEC") >= 0,
	      "the engine's words are not in the vocabulary");
	p = kof_tagsrc_new(&e, &s, &pn);
	CHECK(p && strstr(p, "KOF_TAG_FAMILY(0x3f9a1c42b7d05e11);  /* missing */")
	      && strstr(p, "KOF_TAG_FORMAT(KOF_FMT_ELF);") &&
	      strstr(p, "KOF_TAG_ARCH(KOF_ARCH_X86_64);") &&
	      strstr(p, "KOF_TAG_SUBTYPE(KOF_ELF_EXEC);"), "new: %s",
	      p ? p : "(null)");
	if (p) {
		d->n = 0;
		CHECK(kof_tagsrc_parse(p, pn, d, NULL) == 0, "new does not parse");
		memset(&e, 0, sizeof e);
		CHECK(kof_tagsrc_entity(d, &e, NULL) == 0, "new is no entity");
		CHECK(e.has_fam && e.n_attr[0] == 1 && e.n_attr[1] == 1 &&
		      e.n_attr[2] == 1, "new read back");
	}
	free(p);
	/* The vocabulary has every format of the engine's list. */
	for (i = 0; i < kof_tagsrc_vocab_n(KOF_TAGSRC_A_FORMAT); i++)
		CHECK(!strncmp(kof_tagsrc_vocab_word(0, i), "KOF_", 4), "word");
	free(d);
	kof_tagset_free(&s);
	scratch_close();
}

/* ---- the rules ------------------------------------------------------------------------ */

static void rule(const char *what, const char *file, const char *text,
		 const char *expect, int want_errors)
{
	struct kof_tagset s;
	struct log l;
	int errs;

	scratch_open();
	base_files();
	puts_("tag_c2_00000000.c", tag_c2);
	if (file)
		puts_(file, text);
	load(&s);
	errs = check(&s, &l);
	CHECK(want_errors ? errs > 0 : errs == 0, "%s: %d error(s):\n%s", what,
	      errs, l.text);
	CHECK(!expect || said(&l, expect), "%s: expected \"%s\" in:\n%s", what,
	      expect, l.text);
	kof_tagset_free(&s);
	scratch_close();
}

static void rules(void)
{
	struct kof_tagset s;
	struct log l;

	rule("clean", NULL, NULL, NULL, 0);
	rule("duplicate id", "activity_dup_00000000.c",
	     "KOF_ACTIVITY_ID(0x100);\nKOF_ACTIVITY_NAME(\"dup\");\n",
	     "duplicate id 0x0000000000000100", 1);
	rule("same id in another kind", "type_dup_00000000.c",
	     "KOF_TYPE_ID(0x100);\nKOF_TYPE_NAME(\"dup\");\n",
	     "duplicate id", 1);
	rule("invalid id", "type_x_00000000.c",
	     "KOF_TYPE_ID(0xZZ);\nKOF_TYPE_NAME(\"x\");\n", "invalid id", 1);
	rule("id past 64 bits", "type_x_00000000.c",
	     "KOF_TYPE_ID(0x11111111111111111);\nKOF_TYPE_NAME(\"x\");\n",
	     "invalid id", 1);
	rule("negative id", "type_x_00000000.c",
	     "KOF_TYPE_ID(-1);\nKOF_TYPE_NAME(\"x\");\n", "invalid id", 1);
	rule("empty id", "type_x_00000000.c",
	     "KOF_TYPE_ID();\nKOF_TYPE_NAME(\"x\");\n", "invalid id", 1);
	rule("no id", "type_x_00000000.c", "KOF_TYPE_NAME(\"x\");\n", "no id", 1);
	rule("tag id zero", "tag_z_00000000.c",
	     "KOF_TAG_ID(0);\nKOF_TAG_NAME(\"z\");\nKOF_TAG_TYPE(3);\n",
	     "never zero", 1);
	rule("empty name", "type_x_00000000.c",
	     "KOF_TYPE_ID(0x50);\nKOF_TYPE_NAME(\"\");\n", "empty name", 1);
	rule("no name", "type_x_00000000.c", "KOF_TYPE_ID(0x50);\n",
	     "empty name", 1);
	rule("bad characters", "type_x_00000000.c",
	     "KOF_TYPE_ID(0x50);\nKOF_TYPE_NAME(\"Bad Name\");\n",
	     "bad characters", 1);
	rule("tag with nothing", "tag_n_00000000.c",
	     "KOF_TAG_ID(0x300);\nKOF_TAG_NAME(\"n\");\n",
	     "neither an activity nor a type", 1);
	rule("tag with an activity only", "tag_n_00000000.c",
	     "KOF_TAG_ID(0x300);\nKOF_TAG_NAME(\"n\");\n"
	     "KOF_TAG_ACTIVITY(0x100);\n", NULL, 0);
	rule("missing activity", "tag_n_00000000.c",
	     "KOF_TAG_ID(0x300);\nKOF_TAG_NAME(\"n\");\nKOF_TAG_TYPE(3);\n"
	     "KOF_TAG_ACTIVITY(0x999);\n", "activity that does not exist", 1);
	rule("missing type", "tag_n_00000000.c",
	     "KOF_TAG_ID(0x300);\nKOF_TAG_NAME(\"n\");\nKOF_TAG_TYPE(0x999);\n",
	     "type that does not exist", 1);
	rule("missing family", "tag_n_00000000.c",
	     "KOF_TAG_ID(0x300);\nKOF_TAG_NAME(\"n\");\nKOF_TAG_TYPE(3);\n"
	     "KOF_TAG_FAMILY(0x999);\n", "family that does not exist", 1);
	/* Warnings: not errors. */
	rule("same meaning", "tag_c2b_00000000.c",
	     "KOF_TAG_ID(0x301);\nKOF_TAG_NAME(\"c2\");\n"
	     "KOF_TAG_ACTIVITY(0x100);\nKOF_TAG_TYPE(3);\n",
	     "says the same", 0);
	rule("unused entity", "activity_idle_00000000.c",
	     "KOF_ACTIVITY_ID(0x103);\nKOF_ACTIVITY_NAME(\"idle\");\n",
	     "is used by no tag", 0);
	rule("one edit apart", "activity_networks_00000000.c",
	     "KOF_ACTIVITY_ID(0x104);\nKOF_ACTIVITY_NAME(\"networks\");\n",
	     "one edit apart", 0);
	/* Information: the same name, the relation of the type sets. */
	scratch_open();
	base_files();
	puts_("tag_c2_00000000.c", tag_c2);
	puts_("tag_c2c_00000000.c", "KOF_TAG_ID(0x302);\nKOF_TAG_NAME(\"c2\");\n"
	      "KOF_TAG_ACTIVITY(0x100);\nKOF_TAG_TYPE(1);\n");
	puts_("tag_c2d_00000000.c", "KOF_TAG_ID(0x303);\nKOF_TAG_NAME(\"c2\");\n"
	      "KOF_TAG_ACTIVITY(0x100);\nKOF_TAG_TYPE(3);\nKOF_TAG_TYPE(1);\n");
	load(&s);
	CHECK(check(&s, &l) == 0, "relations are not errors:\n%s", l.text);
	CHECK(said(&l, "type sets disjoint") && said(&l, "type sets subset"),
	      "relations missing:\n%s", l.text);
	kof_tagset_free(&s);
	scratch_close();
}

/* ---- hostile files --------------------------------------------------------------------- */

static void hostile(void)
{
	struct kof_tagset s;
	struct log l;
	char *big = malloc(70000u);
	size_t i;

	scratch_open();
	base_files();
	/* Truncated mid-declaration. */
	puts_("tag_t1_00000000.c", "KOF_TAG_ID(0x400);\nKOF_TAG_NAME(\"abc");
	puts_("tag_t2_00000000.c", "KOF_TAG_ID(0x401);\nKOF_TAG_NAME(\"t2\");\n"
	      "KOF_TAG_TYPE(3");
	/* Truncated at a line boundary: valid text, an entity missing a part. */
	puts_("tag_t3_00000000.c", "KOF_TAG_ID(0x402);\n");
	/* Declared twice. */
	puts_("type_d1_00000000.c", "KOF_TYPE_ID(0x40);\nKOF_TYPE_ID(0x41);\n"
	      "KOF_TYPE_NAME(\"d1\");\n");
	puts_("type_d2_00000000.c", "KOF_TYPE_ID(0x42);\nKOF_TYPE_NAME(\"a\");\n"
	      "KOF_TYPE_NAME(\"b\");\n");
	puts_("tag_d3_00000000.c", "KOF_TAG_ID(0x403);\nKOF_TAG_NAME(\"d3\");\n"
	      "KOF_TAG_ACTIVITY(0x100);\nKOF_TAG_ACTIVITY(0x100);\n");
	/* Two kinds in one file, and two declarations on one line. */
	puts_("tag_k_00000000.c", "KOF_TAG_ID(0x404);\nKOF_TAG_NAME(\"k\");\n"
	      "KOF_TYPE_NAME(\"other\");\nKOF_TAG_TYPE(3);\n");
	puts_("tag_l_00000000.c", "KOF_TAG_ID(0x405); KOF_TAG_NAME(\"l\");\n"
	      "KOF_TAG_TYPE(3);\n");
	/* A word the engine does not have. */
	puts_("tag_w_00000000.c", "KOF_TAG_ID(0x406);\nKOF_TAG_NAME(\"w\");\n"
	      "KOF_TAG_TYPE(3);\nKOF_TAG_FORMAT(KOF_FMT_NOPE);\n");
	/* Larger than a file may be. */
	for (i = 0; i < 70000u; i++)
		big[i] = i % 64u == 63u ? '\n' : 'x';
	put("tag_big_00000000.c", big, 70000u);
	/* More declarations than a file can hold. */
	{
		char *many = calloc(1, 8192u);
		size_t at = (size_t)snprintf(many, 8192u, "KOF_TAG_ID(0x407);\n"
					     "KOF_TAG_NAME(\"many\");\n");

		for (i = 0; i < 120u; i++)
			at += (size_t)snprintf(many + at, 8192u - at,
					       "KOF_TAG_TYPE(%zu);\n", i + 1u);
		puts_("tag_many_00000000.c", many);
		free(many);
	}
	/* Not text at all. */
	put("tag_bin_00000000.c", "\0\1\2\3\377\376KOF_", 11u);
	load(&s);
	CHECK(check(&s, &l) > 0, "hostile files gave no error");
	CHECK(s.n == 4u, "only the good files are entities: %zu", s.n);
	CHECK(said(&l, "tag_t1_00000000.c") && said(&l, "unterminated"),
	      "truncated name:\n%s", l.text);
	CHECK(said(&l, "tag_t2_00000000.c"), "truncated type:\n%s", l.text);
	CHECK(said(&l, "tag_t3_00000000.c") && said(&l, "empty name"),
	      "cut at a line:\n%s", l.text);
	CHECK(said(&l, "the id is declared twice"), "two ids:\n%s", l.text);
	CHECK(said(&l, "the name is declared twice"), "two names:\n%s", l.text);
	CHECK(said(&l, "listed twice"), "an activity twice:\n%s", l.text);
	CHECK(said(&l, "another kind"), "two kinds:\n%s", l.text);
	CHECK(said(&l, "more than one declaration on a line"), "two on a line:\n%s",
	      l.text);
	CHECK(said(&l, "not a word the engine has"), "a made-up word:\n%s",
	      l.text);
	CHECK(said(&l, "tag_big_00000000.c") && said(&l, "larger than"),
	      "a huge file:\n%s", l.text);
	CHECK(said(&l, "tag_many_00000000.c"), "too many:\n%s", l.text);
	free(big);
	kof_tagset_free(&s);
	scratch_close();
}

/* ---- ids, add and remove --------------------------------------------------------------- */

struct seq {
	uint64_t v[8];
	unsigned n, at;
};

static uint64_t seq_gen(void *ud)
{
	struct seq *q = ud;
	uint64_t v = q->v[q->at < q->n ? q->at : q->n - 1u];

	q->at++;
	return v;
}

static void ids(void)
{
	struct kof_tagset s;
	struct kof_tagent proto, *e;
	struct seq q;
	uint64_t id = 0, a, b;
	const char *why = NULL;

	scratch_open();
	base_files();
	puts_("tag_c2_00000000.c", tag_c2);
	load(&s);

	/* Free of the seeds' range and of every id there is. */
	q.v[0] = 5;                     /* below the seeds' */
	q.v[1] = 0x200;                 /* the tag's */
	q.v[2] = 0xdeadbeef12345678ull;
	q.n = 3;
	q.at = 0;
	CHECK(kof_tagset_new_id(&s, seq_gen, &q, &id) && id == q.v[2] &&
	      q.at == 3, "id %llx after %u tries", (unsigned long long)id, q.at);
	/* A generator that only repeats what exists is refused, not obeyed. */
	q.v[0] = 0x200;
	q.n = 1;
	q.at = 0;
	CHECK(!kof_tagset_new_id(&s, seq_gen, &q, &id), "a collision was reused");
	CHECK(q.at == 64u, "gave up after %u tries", q.at);
	/* The real source gives ids that are never the seeds'. */
	for (a = 0; a < 50; a++) {
		CHECK(kof_tagset_new_id(&s, NULL, NULL, &b) &&
		      b >= KOF_TAGSRC_ID_SEED_MAX, "random id %llx",
		      (unsigned long long)b);
	}

	/* Add: the id is the generator's, the name of the file is made from it. */
	memset(&proto, 0, sizeof proto);
	proto.kind = KOF_TAGSRC_K_FAMILY;
	snprintf(proto.name, sizeof proto.name, "mirai");
	proto.id = 0x77;                /* ignored */
	q.v[0] = 0x3f9a1c42b7d05e11ull;
	q.n = 1;
	q.at = 0;
	e = kof_tagset_add(&s, &proto, seq_gen, &q, &why);
	CHECK(e && e->id == 0x3f9a1c42b7d05e11ull && e->fresh && e->dirty &&
	      strstr(e->path, "family_mirai_3f9a1c42.c"), "add: %s",
	      why ? why : "?");
	/* Another entity's file is never overwritten: the next id is tried. */
	{
		char path[600];
		struct seq q2;

		snprintf(path, sizeof path, "%s/family_ship_aaaaaaaa.c", dir);
		puts_("family_ship_aaaaaaaa.c", FAM_MIR);
		memset(&proto, 0, sizeof proto);
		proto.kind = KOF_TAGSRC_K_FAMILY;
		snprintf(proto.name, sizeof proto.name, "ship");
		q2.v[0] = 0xaaaaaaaa11111111ull;
		q2.v[1] = 0xbbbbbbbb22222222ull;
		q2.n = 2;
		q2.at = 0;
		e = kof_tagset_add(&s, &proto, seq_gen, &q2, &why);
		CHECK(e && e->id == 0xbbbbbbbb22222222ull, "the file of another "
		      "entity was taken: %s", e ? e->path : why);
	}
	/* A bad name is refused whole. */
	memset(&proto, 0, sizeof proto);
	proto.kind = KOF_TAGSRC_K_TYPE;
	snprintf(proto.name, sizeof proto.name, "Bad Name");
	CHECK(kof_tagset_add(&s, &proto, NULL, NULL, &why) == NULL && why,
	      "a bad name was added");
	CHECK(kof_tagsrc_name_ok("a-1") && !kof_tagsrc_name_ok("A") &&
	      !kof_tagsrc_name_ok("") && !kof_tagsrc_name_ok("a b"), "name_ok");
	{
		char n[64];

		CHECK(kof_tagsrc_name_norm(n, sizeof n, "Hello World_9!") == 13u &&
		      !strcmp(n, "hello-world-9"), "norm: %s", n);
	}
	kof_tagset_free(&s);
	scratch_close();
}

static void refs_and_save(void)
{
	struct kof_tagset s;
	struct kof_tagent *e, *c2, proto;
	const struct kof_tagent *by[4];
	size_t n, before_n = 0, after_n = 0;
	char *before, *after, why[200];
	int saved;
	struct seq q;

	scratch_open();
	base_files();
	puts_("tag_c2_00000000.c", tag_c2);
	load(&s);
	/* Who still names an activity: what a delete has to refuse with. */
	e = kof_tagset_find(&s, KOF_TAGSRC_K_ACTIVITY, 0x100);
	CHECK(e && kof_tagset_refs(&s, e, by, 4) == 1 &&
	      !strcmp(by[0]->name, "c2"), "refs of network");
	e = kof_tagset_find(&s, KOF_TAGSRC_K_ACTIVITY, 0x101);
	CHECK(e && kof_tagset_refs(&s, e, NULL, 0) == 0, "refs of memory");
	kof_tagset_count(&s);
	e = kof_tagset_find(&s, KOF_TAGSRC_K_TYPE, 3);
	CHECK(e && e->used == 1, "used of botnet");

	/* Save writes what changed and nothing else. */
	before = slurp(kof_tagset_find(&s, KOF_TAGSRC_K_TAG, 0x200)->path,
		       &before_n);
	c2 = kof_tagset_find(&s, KOF_TAGSRC_K_TAG, 0x200);
	snprintf(c2->comment, sizeof c2->comment, "takes orders from a server");
	c2->dirty = 1;
	memset(&proto, 0, sizeof proto);
	proto.kind = KOF_TAGSRC_K_FAMILY;
	snprintf(proto.name, sizeof proto.name, "mirai");
	q.v[0] = 0x3f9a1c42b7d05e11ull;
	q.n = 1;
	q.at = 0;
	CHECK(kof_tagset_add(&s, &proto, seq_gen, &q, NULL) != NULL, "add");
	e = kof_tagset_find(&s, KOF_TAGSRC_K_TYPE, 1);
	{
		/* Removing a type that exists on disk removes its file at save. */
		kof_tagset_remove(&s, e);
	}
	saved = kof_tagset_save(&s, why, sizeof why);
	CHECK(saved == 3, "saved %d: %s", saved, why);
	CHECK(has_file("family_mirai_3f9a1c42.c"), "the new file is not there");
	CHECK(!has_file("type_trojan_00000000.c"), "the removed file is there");
	CHECK(has_file("type_botnet_00000000.c"), "an untouched file is gone");
	{
		char path[600];

		snprintf(path, sizeof path, "%s/tag_c2_00000000.c", dir);
		after = slurp(path, &after_n);
	}
	CHECK(before && after && strstr(after, "takes orders from a server") &&
	      strstr(after, "KOF_TAG_SOMETHING_NEW(7);") &&
	      strstr(after, "the author's evidence stays") &&
	      after_n != before_n, "the tag file after save:\n%s",
	      after ? after : "(none)");
	/* Nothing dirty now: a second save writes nothing. */
	CHECK(kof_tagset_save(&s, why, sizeof why) == 0, "a second save wrote");
	/* No temporary left beside the files. */
	{
		DIR *d = opendir(dir);
		struct dirent *de;
		int stray = 0;

		while (d && (de = readdir(d)) != NULL) {
			size_t l = strlen(de->d_name);

			if (de->d_name[0] != '.' &&
			    (l < 2u || strcmp(de->d_name + l - 2u, ".c")))
				stray++;
		}
		if (d)
			closedir(d);
		CHECK(!stray, "%d stray file(s) after a save", stray);
	}
	/* Reload: what was saved is what loads, and the family has its id. */
	kof_tagset_free(&s);
	load(&s);
	n = s.n;
	CHECK(n == 5u, "entities after the save: %zu", n);
	CHECK(kof_tagset_find(&s, KOF_TAGSRC_K_FAMILY, 0x3f9a1c42b7d05e11ull) &&
	      kof_tagset_find(&s, KOF_TAGSRC_K_TAG, 0x200)->n_typ == 1u,
	      "reload");
	free(before);
	free(after);
	kof_tagset_free(&s);
	scratch_close();
}

static void failed_write(void)
{
	struct kof_tagset s;
	struct kof_tagent *c2;
	char why[200], path[600], *before, *after;
	size_t bn = 0, an = 0;

	if (geteuid() == 0) {
		printf("  (running as root: the unwritable directory is "
		       "not tested)\n");
		return;
	}
	scratch_open();
	base_files();
	puts_("tag_c2_00000000.c", tag_c2);
	load(&s);
	snprintf(path, sizeof path, "%s/tag_c2_00000000.c", dir);
	before = slurp(path, &bn);
	c2 = kof_tagset_find(&s, KOF_TAGSRC_K_TAG, 0x200);
	snprintf(c2->comment, sizeof c2->comment, "changed");
	c2->dirty = 1;
	chmod(dir, 0555);
	CHECK(kof_tagset_save(&s, why, sizeof why) == -1, "a write into a "
	      "read-only directory succeeded");
	chmod(dir, 0755);
	after = slurp(path, &an);
	CHECK(before && after && bn == an && !memcmp(before, after, bn),
	      "the file changed when the save failed");
	CHECK(c2->dirty, "a failed save forgot the change");
	free(before);
	free(after);
	kof_tagset_free(&s);
	scratch_close();
}

static void diagnose_uses(void)
{
	struct kof_tagset s;
	struct kof_tagent *t;

	scratch_open();
	base_files();
	puts_("tag_c2_00000000.c", tag_c2);
	puts_("diag_a_00.c", "KOF_DIAG_NAME(a);\nKOF_DIAG_TAG(0x200);\n"
	      "/* KOF_DIAG_TAG(0x200); is only a mention */\n");
	puts_("diag_b_00.c", "KOF_DIAG_TAG( 0x200 );\nKOF_DIAG_TAG(0x999);\n");
	load(&s);
	kof_tagset_count_diagnoses(&s, dir);
	t = kof_tagset_find(&s, KOF_TAGSRC_K_TAG, 0x200);
	CHECK(t && t->used == 2u, "diagnoses naming the tag: %u",
	      t ? t->used : 99u);
	kof_tagset_count_diagnoses(&s, "build/does-not-exist");
	CHECK(t->used == 0, "a missing directory counts none");
	kof_tagset_free(&s);
	scratch_close();
}

int main(void)
{
	seeds();
	round_trip();
	rules();
	hostile();
	ids();
	refs_and_save();
	failed_write();
	diagnose_uses();
	printf(fails ? "tagsrc: %d FAILED\n" : "tagsrc: ok\n", fails);
	return fails ? 1 : 0;
}
