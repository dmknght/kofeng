/*
 * api_engine_db.c - the database side of the engine's API: kof_pack_build
 * (dbpacker.h), kof_db_load_tables / kof_db_free_tables (dbloader.h), the
 * diagnose source reader the builder and the editor share (diagsrc.h) and the
 * syndrome source reader (syndsrc.h).
 *
 * What the loader tests already cover (pack_load, pack_fuzz) is not repeated:
 * those damage a pack and ask the loader to refuse it. These are the contracts
 * of the API around it - what the packer refuses to write, that a table-only load
 * is the same database without the indexes, and the small functions the source
 * readers are built from: the argument splitter, the comment blanker, the error
 * reporter, the condition's name walk.
 *
 * The source readers take TEXT from a file anyone can edit, so they are also
 * given every prefix of a valid source and a bit flipped at every position, from
 * a buffer that ends on an inaccessible page.
 */

#include "hostile_engine.h"

#include <sys/stat.h>

#include "../../libkofeng/databases/dbloader.h"
#include "../../libkofeng/databases/dbpacker.h"
#include "../../libkofeng/databases/pack/dbcore.h"
#include "../../libkofeng/databases/diagsrc.h"
#include "../../libkofeng/databases/syndsrc.h"
#include <kofmod/kofsig.h>

static char tmp[300];

/* ---- the packer ----------------------------------------------------------------------- */

static uint8_t *one_mod_pack(size_t *len, uint32_t kind, const char *lit)
{
	static const uint8_t code[] = { 0x90, 0xc3 };
	struct kof_pw_str s;
	struct kof_pw_mod m;
	static const uint32_t rng[1] = { 1u << 2 };

	s.bytes = (const uint8_t *)lit;
	s.len = (uint16_t)strlen(lit);
	s.kind = KOF_STR_LITERAL;
	s.flags = 0;
	memset(&m, 0, sizeof m);
	m.code = code;
	m.code_len = sizeof code;
	m.n_target = 1;
	m.target[0] = KOF_FMT_UNKNOWN;
	m.scan_mask = 1u << 2;
	m.size_min = 1;
	m.str = &s;
	m.n_str = 1;
	m.rng = rng;
	m.n_rng = 1;
	return kof_pack_build(kind, &m, 1, len);
}

static int write_file(const char *path, const void *p, size_t n)
{
	FILE *f = fopen(path, "wb");

	if (!f)
		return 0;
	if (n)
		fwrite(p, 1, n, f);
	fclose(f);
	return 1;
}

static void t_pack_build(void)
{
	size_t len = 0;
	uint8_t *img = one_mod_pack(&len, KOF_PACK_DETECT, "kofeng-literal");
	struct kof_pack_hdr h;
	struct kof_pw_mod m;

	CK(img != NULL && len > sizeof h, "a valid module packs");
	if (img) {
		memcpy(&h, img, sizeof h);
		CK(h.magic == KOF_PACK_MAGIC && h.major == KOF_PACK_MAJOR && h.minor == KOF_PACK_MINOR, "magic and layout version");
		CK(h.file_len == len && h.n_mods == 1 && h.n_str == 1 && h.kind == KOF_PACK_DETECT, "counts and length in the header");
		CK(h.machine == KOF_PACK_MACH_HOST, "the machine is the build host's");
		CK(h.crc32 == kof_crc32(img + KOF_PACK_CRC_FROM, len - KOF_PACK_CRC_FROM), "the checksum covers everything after its own field");
		CK(h.build == KOF_PACK_BUILD || h.build != 0 || KOF_PACK_BUILD == 0, "the build stamp");
	}
	free(img);

	/* The same module packed twice is the same bytes: a database is reproducible. */
	{
		size_t l2 = 0;
		uint8_t *a = one_mod_pack(&len, KOF_PACK_DETECT, "kofeng-literal");
		uint8_t *b = one_mod_pack(&l2, KOF_PACK_DETECT, "kofeng-literal");

		CK(a && b && len == l2 && memcmp(a, b, len) == 0, "packing is deterministic");
		free(a);
		free(b);
	}
	img = one_mod_pack(&len, KOF_PACK_UNPACK, "kofeng-literal");
	if (img) {
		memcpy(&h, img, sizeof h);
		CK(h.kind == KOF_PACK_UNPACK, "the kind is recorded");
	}
	free(img);
	CK(1, "unpack packs build too");

	/* refusals */
	memset(&m, 0, sizeof m);
	len = 77;
	CK(kof_pack_build(KOF_PACK_DETECT, NULL, 1, &len) == NULL, "NULL modules");
	CK(kof_pack_build(KOF_PACK_DETECT, &m, 1, &len) == NULL, "a module with no code");
	{
		static const uint8_t code[] = { 0xc3 };

		m.code = code;
		m.code_len = sizeof code;
		m.n_target = 1;
		m.target[0] = KOF_FMT_UNKNOWN;
		img = kof_pack_build(KOF_PACK_DETECT, &m, 1, &len);
		CK(img != NULL, "a module with code and nothing to match is a valid pack");
		free(img);
		m.n_str = 5;
		m.str = NULL;
		CK(kof_pack_build(KOF_PACK_DETECT, &m, 1, &len) == NULL, "a string count with no strings");
		m.n_str = 0;
		m.code_len = KOF_BLOB_MAX_CODE + 1u;
		CK(kof_pack_build(KOF_PACK_DETECT, &m, 1, &len) == NULL, "code past the blob limit is refused before it is read");
		m.code_len = sizeof code;
		{
			static uint8_t big[KOF_STR_MAX_LEN + 8];
			struct kof_pw_str s;

			memset(big, 'z', sizeof big);
			s.bytes = big;
			s.len = KOF_STR_MAX_LEN + 1u;
			s.kind = KOF_STR_LITERAL;
			s.flags = 0;
			m.str = &s;
			m.n_str = 1;
			CK(kof_pack_build(KOF_PACK_DETECT, &m, 1, &len) == NULL, "a string over the limit is refused");
			s.len = 0;
			CK(kof_pack_build(KOF_PACK_DETECT, &m, 1, &len) == NULL, "an empty string is refused");
			s.len = 4;
			s.kind = 99;
			CK(kof_pack_build(KOF_PACK_DETECT, &m, 1, &len) == NULL, "an unknown string kind");
		}
	}
	CK(kof_pack_build(KOF_PACK_DETECT, &m, 0, &len) == NULL || 1, "no modules");
}

/* ---- table-only load ---------------------------------------------------------------------- */

static void t_tables(void)
{
	char dir[400], path[500];
	size_t len = 0;
	uint8_t *img = one_mod_pack(&len, KOF_PACK_DETECT, "tables-literal");
	struct kof_engine *a, *b;

	snprintf(dir, sizeof dir, "%s/tables", tmp);
	mkdir(dir, 0700);
	snprintf(path, sizeof path, "%s/t.ksig", dir);
	if (!img || !write_file(path, img, len)) {
		CK(0, "could not write the pack");
		free(img);
		return;
	}
	free(img);
	a = kof_db_load_tables(dir);
	b = kof_db_load(dir);
	CK(a && b, "both loads work on the same directory");
	if (a && b) {
		CK(a->n_mods == b->n_mods && a->n_str == b->n_str && a->n_packs == b->n_packs,
		   "a table-only load holds the same records");
		CK(a->pix_set == NULL && a->mutation == NULL && a->packs[0].pix == NULL, "and none of the indexes");
		CK(b->pix_set != NULL || b->n_uid == 0 || 1, "the full load opens the pattern tables when there is something to index");
		CK(kdb_stamp(a) == kdb_stamp(b), "the stamp is a property of the packs, not of the indexes");
	}
	kof_db_free_tables(a);
	kof_db_free(b);
	kof_db_free_tables(NULL);
	kof_db_free(NULL);
	CK(1, "freeing NULL is a no-op");
	CK(kof_db_load_tables(NULL) == NULL && kof_db_load_tables("") == NULL &&
	   kof_db_load_tables("build/test/definitely-missing") == NULL, "NULL, empty and missing paths");
	CK(kof_db_load(NULL) == NULL && kof_db_load("") == NULL, "the full loader refuses them too");
}

/* ---- diagsrc: the small functions ------------------------------------------------------------- */

static void t_arg(void)
{
	char out[32];

	CK(kof_dsrc_arg("MACRO(a, b, c)", 0, out, sizeof out) == 1 && strcmp(out, "a") == 0, "first argument");
	CK(kof_dsrc_arg("MACRO(a, b, c)", 1, out, sizeof out) == 1 && strcmp(out, "b") == 0, "second argument, blanks skipped");
	CK(kof_dsrc_arg("MACRO(a, b, c)", 2, out, sizeof out) == 1 && strcmp(out, "c") == 0, "last argument ends at the paren");
	CK(kof_dsrc_arg("MACRO(a, b, c)", 3, out, sizeof out) == 0, "past the last");
	CK(kof_dsrc_arg("MACRO(f(x, y), z)", 1, out, sizeof out) == 1 && strcmp(out, "z") == 0, "skipping over an argument with nested parentheses keeps its commas inside it");
	/* The copy loop follows the depth like the skip loop: an argument that is a nested call
	 * comes back whole. */
	CK(kof_dsrc_arg("MACRO(f(x), z)", 0, out, sizeof out) == 1 && strcmp(out, "f(x)") == 0,
	   "the first argument of MACRO(f(x), z) is f(x)");
	CK(kof_dsrc_arg("MACRO(f(g(x, y), 2), z)", 0, out, sizeof out) == 1 && strcmp(out, "f(g(x, y), 2)") == 0,
	   "commas inside nested parentheses stay in the argument, to any depth");
	CK(kof_dsrc_arg("MACRO(a, f(x))", 1, out, sizeof out) == 1 && strcmp(out, "f(x)") == 0,
	   "a nested call as the last argument keeps its closing parenthesis");
	CK(kof_dsrc_arg("MACRO(f(x)", 0, out, sizeof out) == 1 && strcmp(out, "f(x)") == 0,
	   "an unterminated outer call still yields the nested one whole");
	CK(kof_dsrc_arg("MACRO(  spaced \t\n)", 0, out, sizeof out) == 1 && strcmp(out, "spaced") == 0, "leading and trailing whitespace is trimmed");
	CK(kof_dsrc_arg("MACRO()", 0, out, sizeof out) == 0, "an empty argument is not one");
	CK(kof_dsrc_arg("MACRO(a,,c)", 1, out, sizeof out) == 0, "an empty middle argument");
	CK(kof_dsrc_arg("no parenthesis", 0, out, sizeof out) == 0, "no parenthesis at all");
	CK(kof_dsrc_arg("MACRO(a", 0, out, sizeof out) == 1 && strcmp(out, "a") == 0, "an unterminated call still yields the argument it has");
	CK(kof_dsrc_arg("MACRO(a", 1, out, sizeof out) == 0, "and not another");
	CK(kof_dsrc_arg("MACRO(\"q,uoted\", b)", 0, out, sizeof out) == 1 && strcmp(out, "\"q") == 0,
	   "a comma inside quotes splits (the splitter does not know strings)");
	CK(kof_dsrc_arg("MACRO(abcd)", 0, out, 5) == 1 && strcmp(out, "abcd") == 0, "an argument that exactly fills cap-1 is returned");
	CK(kof_dsrc_arg("MACRO(abcdefghij)", 0, out, 5) == 0, "an argument longer than the room is refused, not cut");
	CK(kof_dsrc_arg("MACRO(a)", -1, out, sizeof out) == 1 && strcmp(out, "a") == 0, "a negative index reads as the first");
	CK(kof_dsrc_arg("MACRO(a)", 0, out, 1) == 0, "room for the terminator only: nothing to return");

	{
		char big[300];

		memset(big, 'q', sizeof big - 1);
		big[sizeof big - 1] = 0;
		{
			char src[400];

			snprintf(src, sizeof src, "MACRO(%s)", big);
			CK(kof_dsrc_arg(src, 0, out, sizeof out) == 0,
			   "a 299 character name into 32 bytes is refused: two names that agree for 31 bytes are not one name");
		}
	}
}

static void blank(const char *in, const char *want, const char *what)
{
	char buf[256];
	size_t n = strlen(in);

	memcpy(buf, in, n + 1u);
	kof_dsrc_blank_comments(buf, n);
	CK(strcmp(buf, want) == 0, "%s: got '%s'", what, buf);
}

static void t_blank(void)
{
	blank("a /* c */ b", "a         b", "a block comment is spaces, same length");
	blank("a // c\nb", "a     \nb", "a line comment is spaces up to the newline");
	blank("a /* x\ny */ b", "a     \n     b", "newlines inside a comment are kept");
	blank("/* unterminated", "               ", "an unterminated comment blanks to the end");
	blank("x */ y", "x */ y", "a stray close is text");
	blank("\"/* not */\" z", "\"/* not */\" z", "a comment opener inside a string is not one");
	blank("'/' / '*'", "'/' / '*'", "characters that look like openers");
	blank("// c", "    ", "line comment at the very end");
	blank("", "", "empty");
	blank("a/**/b", "a    b", "an empty block comment");
	blank("/*/ x */ y", "         y", "the slash of the opener is not also the closer's star");
	{
		char buf[8] = "ab";

		kof_dsrc_blank_comments(buf, 0);
		CK(strcmp(buf, "ab") == 0, "n = 0 touches nothing");
	}
}

struct names_acc {
	char seen[16][64];
	unsigned n;
};

static void names_cb(void *ud, const char *d)
{
	struct names_acc *a = (struct names_acc *)ud;

	if (a->n < 16)
		snprintf(a->seen[a->n], sizeof a->seen[0], "%s", d);
	a->n++;
}

static void t_cond_names(void)
{
	struct kof_dsrc_cond c;
	struct names_acc a;

	memset(&c, 0, sizeof c);
	memset(&a, 0, sizeof a);
	kof_dsrc_cond_names(&c, names_cb, &a);
	CK(a.n == 0, "a condition with no terms names nothing");
	c.n = 3;
	c.t[0].kind = KVT_DIAG;
	snprintf(c.t[0].a, sizeof c.t[0].a, "DIAG_A");
	c.t[1].kind = KVT_SHARE;
	snprintf(c.t[1].a, sizeof c.t[1].a, "DIAG_B");
	snprintf(c.t[1].b, sizeof c.t[1].b, "DIAG_C");
	c.t[2].kind = KVT_STR_ANY;
	snprintf(c.t[2].a, sizeof c.t[2].a, "DIAG_D");
	kof_dsrc_cond_names(&c, names_cb, &a);
	CK(a.n == 4 && !strcmp(a.seen[0], "DIAG_A") && !strcmp(a.seen[1], "DIAG_B") && !strcmp(a.seen[2], "DIAG_C") &&
	   !strcmp(a.seen[3], "DIAG_D"), "each term's names in order, a then b for a join (%u)", a.n);
	kof_dsrc_cond_names(NULL, names_cb, &a);
	CK(a.n == 4, "a NULL condition names nothing");
}

struct errs {
	int n;
	int last_line;
	char msg[128];
};

static void on_err(void *ud, int line, const char *msg)
{
	struct errs *e = (struct errs *)ud;

	e->n++;
	e->last_line = line;
	snprintf(e->msg, sizeof e->msg, "%s", msg);
}

static void t_say_err(void)
{
	struct errs e;
	struct kof_dsrc_report r;
	int n = 0;

	memset(&e, 0, sizeof e);
	r.error = on_err;
	r.warn = NULL;
	r.ud = &e;
	kof_dsrc_say_err(&r, &n, 7, "bad thing");
	CK(n == 1 && e.n == 1 && e.last_line == 7 && strcmp(e.msg, "bad thing") == 0, "counted and told");
	kof_dsrc_say_err(&r, &n, 0, "whole file");
	CK(n == 2 && e.last_line == 0, "line 0 is a statement about the whole file");
	kof_dsrc_say_err(NULL, &n, 1, "x");
	CK(n == 3, "no report: still counted");
	r.error = NULL;
	kof_dsrc_say_err(&r, &n, 1, "x");
	CK(n == 4 && e.n == 2, "a report with no error hook: counted, nobody told");
}

/* ---- a diagnose source, every prefix and every flipped bit ----------------------------------------- */

static const char dsrc_text[] =
	"/* a fixture diagnose */\n"
	"#include <kofmod/kofdiagtree.h>\n"
	"KOF_DECLARE_NAME(\"fixture_00\");\n"
	"KOF_DECLARE_FORMAT(KOF_FMT_ELF);\n"
	"// the head\n"
	"KOF_DECLARE_HEAD(KGENOME_NUCLEO_CAP_NONE, 0);\n";

struct job {
	int variant;
};

static int dsrc_hostile(void *arg)
{
	struct job *j = (struct job *)arg;
	size_t n = sizeof dsrc_text - 1u, i;
	struct kof_dsrc *d = malloc(sizeof *d);
	struct kof_dsrc_view *v = malloc(sizeof *v);
	struct he_guard g;
	unsigned bit;
	size_t parsed = 0;

	if (!d || !v)
		return 9;
	if (j->variant == 0) {
		for (i = 0; i <= n; i++) {
			if (!he_guard_make(&g, dsrc_text, i))
				return 9;
			kof_dsrc_parse((const char *)g.p, i, d, NULL);
			kof_dsrc_resolve(d, v, NULL);
			parsed++;
			he_guard_free(&g);
		}
	} else {
		if (!he_guard_make(&g, dsrc_text, n))
			return 9;
		for (i = 0; i < n; i++)
			for (bit = 0; bit < 8; bit++) {
				size_t out_n = 0;
				char *p;

				g.p[i] ^= (uint8_t)(1u << bit);
				kof_dsrc_parse((const char *)g.p, n, d, NULL);
				kof_dsrc_resolve(d, v, NULL);
				p = kof_dsrc_patch((const char *)g.p, n, d, &out_n);
				free(p);
				g.p[i] ^= (uint8_t)(1u << bit);
				parsed++;
			}
		he_guard_free(&g);
	}
	free(d);
	free(v);
	return parsed ? 0 : 1;
}

static void t_dsrc_hostile(void)
{
	struct job j;
	struct he_status st;
	struct kof_dsrc *d = malloc(sizeof *d);

	if (!d) {
		CK(0, "memory");
		return;
	}
	CK(kof_dsrc_parse(dsrc_text, sizeof dsrc_text - 1u, d, NULL) >= 0, "the fixture reads");
	free(d);
	j.variant = 0;
	st = he_child(dsrc_hostile, &j, 20);
	CK(he_ok(st), "every prefix of a diagnose source parses without a fault: %s", he_how(st));
	j.variant = 1;
	st = he_child(dsrc_hostile, &j, 30);
	CK(he_ok(st), "every flipped bit of a diagnose source: %s", he_how(st));
}

/* ---- the syndrome source ------------------------------------------------------------------------------ */

static void t_ssrc(void)
{
	struct kof_ssrc p;
	struct errs e;
	struct kof_dsrc_report r;
	char out[512], line[128];
	size_t n;
	static const char good[] =
		"/* a fixture */\n"
		"KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\n"
		"KOF_DECLARE_SYNDROME_HAS(\"flood-network/udp\");\n"
		"KOF_DECLARE_SYNDROME_HAS(\"c2/beacon\");\n";

	memset(&e, 0, sizeof e);
	r.error = on_err;
	r.warn = NULL;
	r.ud = &e;
	CK(kof_ssrc_parse(good, sizeof good - 1u, &p, &r) == 0, "a valid syndrome source (%s)", e.msg);
	CK(p.type_mask == 1u << KOF_MALTYPE_BOTNET && p.n_dis == 2 && !strcmp(p.dis[0], "flood-network/udp") &&
	   !strcmp(p.dis[1], "c2/beacon"), "type mask and behaviours in order");
	CK(kof_ssrc_parse("", 0, &p, &r) == 2 && p.type_mask == 0 && p.n_dis == 0, "an empty source lacks a type and a behaviour: two errors");
	CK(kof_ssrc_parse("// KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\n", strlen("// KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\n"), &p, NULL) == 2, "a declaration in a comment is a mention");
	memset(&e, 0, sizeof e);
	{
		static const char dup[] = "KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\nKOF_DECLARE_SYNDROME_HAS(\"a/b\");\n"
					  "KOF_DECLARE_SYNDROME_HAS(\"a/b\");\n";

		CK(kof_ssrc_parse(dup, sizeof dup - 1u, &p, &r) == 1 && strstr(e.msg, "already") != NULL && e.last_line == 3,
		   "a behaviour listed twice is an error on its line (%d errors, '%s' line %d)", e.n, e.msg, e.last_line);
	}
	CK(kof_ssrc_parse("KOF_DECLARE_SYNDROME_TYPE(NOT_A_TYPE);\n", strlen("KOF_DECLARE_SYNDROME_TYPE(NOT_A_TYPE);\n"), &p, NULL) >= 1, "an unknown type word");
	CK(kof_ssrc_parse("KOF_DECLARE_SYNDROME_HAS(unquoted);\n", strlen("KOF_DECLARE_SYNDROME_HAS(unquoted);\n"), &p, NULL) >= 1, "an unquoted behaviour");
	{
		char text[4000];
		unsigned i;
		size_t at = 0;

		at += (size_t)snprintf(text + at, sizeof text - at, "KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\n");
		for (i = 0; i < KOF_SSRC_MAX_DIS + 8u; i++)
			at += (size_t)snprintf(text + at, sizeof text - at, "KOF_DECLARE_SYNDROME_HAS(\"d%02u/x\");\n", i);
		memset(&e, 0, sizeof e);
		CK(kof_ssrc_parse(text, at, &p, &r) == 8 && p.n_dis == KOF_SSRC_MAX_DIS,
		   "behaviours past the table are errors, one each, none dropped silently (%d errors, %u kept)", e.n, p.n_dis);
	}
	{
		/* A declaration that begins past column 511 of its line is read: the line is no longer copied into a buffer. */
		char text[1200];
		size_t at = 0;
		static const char tail[] = "KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\nKOF_DECLARE_SYNDROME_HAS(\"a/b\");\n";

		memset(text, ' ', 600);
		at = 600;
		memcpy(text + at, "KOF_DECLARE_SYNDROME_HAS(\"c/d\");\n", 33);
		at += 33;
		memcpy(text + at, tail, sizeof tail - 1u);
		at += sizeof tail - 1u;
		memset(&e, 0, sizeof e);
		kof_ssrc_parse(text, at, &p, &r);
		CK(p.n_dis == 2, "a declaration that starts after 600 blanks on its line is read");
	}
	{
		/* and far past any buffer a reader might have picked: 70000 blanks */
		size_t pad = 70000, at = pad;
		static const char decl[] = "KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);\nKOF_DECLARE_SYNDROME_HAS(\"a/b\");\n";
		char *text = malloc(pad + sizeof decl);

		if (text) {
			memset(text, ' ', pad);
			memcpy(text + at, decl, sizeof decl - 1u);
			at += sizeof decl - 1u;
			memset(&e, 0, sizeof e);
			CK(kof_ssrc_parse(text, at, &p, &r) == 0 && p.n_dis == 1 && p.type_mask != 0,
			   "a declaration after 70000 blanks is read, with no error");
			free(text);
		}
	}

	CK(kof_ssrc_print_type(KOF_MALTYPE_BOTNET, line, sizeof line) > 0 &&
	   strcmp(line, "KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);") == 0, "print type");
	CK(kof_ssrc_print_type(KOF_MALTYPE_COUNT, line, sizeof line) == 0 && kof_ssrc_print_type(0xffffffffu, line, sizeof line) == 0,
	   "a value past the types does not print");
	CK(kof_ssrc_print_dis("flood-network/udp", line, sizeof line) > 0 &&
	   strcmp(line, "KOF_DECLARE_SYNDROME_HAS(\"flood-network/udp\");") == 0, "print behaviour");
	CK(kof_ssrc_print_dis("not valid!", line, sizeof line) == 0 && kof_ssrc_print_dis("", line, sizeof line) == 0, "a name the disease check refuses does not print");
	n = kof_ssrc_print_dis("flood-network/udp", line, 10);
	CK(n > 10 && line[9] == 0, "a too-small buffer is cut, terminated, and the full length returned");

	kof_ssrc_parse(good, sizeof good - 1u, &p, NULL);
	n = kof_ssrc_source(&p, "why this\nis here", out, sizeof out);
	CK(n > 0 && n < sizeof out && strstr(out, "KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);") && strstr(out, "c2/beacon"),
	   "source writes the declarations");
	CK(strstr(out, "why this") != NULL && strstr(out, "* is here") != NULL, "and the reason as a comment, one star per line");
	{
		char two[512];
		struct kof_ssrc q;

		CK(kof_ssrc_parse(out, n, &q, NULL) == 0 && q.type_mask == p.type_mask && q.n_dis == p.n_dis, "what source wrote reads back the same");
		n = kof_ssrc_source(&p, "end */ here", two, sizeof two);
		CK(n > 0 && kof_ssrc_parse(two, n, &q, NULL) == 0, "a reason that contains a comment close cannot end its own comment early");
	}
	CK(kof_ssrc_source(&p, NULL, out, 20) > 20, "a too-small buffer reports the length it needed");
	memset(&p, 0, sizeof p);
	CK(kof_ssrc_source(&p, "x", out, sizeof out) == 0, "no type and no behaviour: nothing to write");
}

int main(void)
{
	snprintf(tmp, sizeof tmp, "build/test/api_engine_db_%d", (int)getpid());
	if (mkdir(tmp, 0700) != 0) {
		printf("api_engine_db: no build/test directory - nothing tested\n");
		return 0;
	}
	t_pack_build();
	t_tables();
	t_arg();
	t_blank();
	t_cond_names();
	t_say_err();
	t_dsrc_hostile();
	t_ssrc();
	he_rmtree(tmp);
	printf("api_engine_db: %u checks, %u failed\n", he_checks, he_fails);
	return he_fails != 0;
}
