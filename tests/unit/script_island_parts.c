/*
 * script_island_parts - the engine's side of a script's islands (celllysis/script_islands.h), from constructed text only:
 *
 *   SP-16  the similarity cut of a context with NO live scan (kofexaminer, kofviewer: kof_scan_mutation_units with a caller's fixed range
 *          buffer) offers every piece of a page with more pieces than the buffer holds. RED on the code before the island package: the
 *          resolver wrote into the tool's 16-range buffer and cut the rest with nothing said, so no unit lay past the 16th piece. Why the
 *          old tests missed it: (b) no page had more pieces than the tool's buffer.
 *   IS-1   two eval sites that run the SAME string give ONE child (design point 5: one child per distinct string, read once). RED before:
 *          one child per call site, the same program scanned twice. Why missed: (b) every eval test had one site.
 *   IS-2   an eval nested inside an eval's string is a child ONCE: the walk that resolved the outer one follows it (diag_text_walk.c's
 *          layers). NOT a defect: GREEN on the base too (a guard of design point 5, written when the coordinator's brief suspected one;
 *          a skip added for it was removed as dead code - the island child collects nothing of its own).
 *   IS-3   an island child is code from its first byte by its entry (kof_script_from_code), not by a parse's tag_len read as a flag; a
 *          parsed script is not (entry KOF_NA), and a tool rebuilding a context passes the engine's entry kind on (kof_script_mark_code).
 */

#include <stdio.h>
#include <string.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "../../libkofeng/kofcore/kofmod/script.h"
#include "../../libkofeng/scanners/scan.h"
#include "../../libkofeng/analyzers/parsers/scripts/script_parse.h"
#include "../../libkofeng/analyzers/parsers/scripts/script_route.h"

static int failures;

#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); failures++; } } while (0)

/* ---- SP-16 ------------------------------------------------------------------------------------------------------------------ */

struct units {
	uint64_t last_end;
	uint32_t n;
};

static int unit_cb(void *user, uint32_t mask, uint64_t off, uint64_t len, uint32_t side, const struct kgenome_func *first)
{
	struct units *u = user;

	(void)mask; (void)side; (void)first;
	u->n++;
	if (off + len > u->last_end)
		u->last_end = off + len;
	return 0;
}

static void sp16(void)
{
	static char page[4096];
	static struct kof_script_info si;
	static struct kof_range ext[16];
	struct kof_ext_buf fixed = kof_ext_fixed(ext, 16u);
	struct kof_obj_ctx ctx;
	struct units u;
	size_t k = 0;
	uint32_t i;

	/* 20 pieces, each with code long enough to be a unit of its own */
	for (i = 0; i < 20u; i++)
		k += (size_t)snprintf(page + k, sizeof page - k, "<p>row %u</p>\n<?php echo strtoupper(substr($row_%u, 0, 40)); ?>\n", i, i);
	memset(&ctx, 0, sizeof ctx);
	CK(kof_script_parse(kof_buf_make(page, k), &si, &ctx) == 1 && ctx.subtype == KOF_SCRIPT_PHP, "the page parses as php");
	CK(kof_scan_of(&ctx) == NULL, "no live scan: the tool's path");
	memset(&u, 0, sizeof u);
	kof_scan_mutation_units(&ctx, kof_buf_make(page, k), ~0u, NULL, &fixed, unit_cb, &u);
	CK(u.last_end > (uint64_t)(strstr(page, "$row_19") - page), "SP-16: a unit of the 20th piece is offered (last unit ends at %llu of %zu)",
	   (unsigned long long)u.last_end, k);
}

/* ---- IS-1, IS-2: eval children ---------------------------------------------------------------------------------------------- */

/* hoho.php's shape (tests/unit/script_island_child.c): create_function's code built by a join, reached through a variable */
#define HEAD "<?php\n$l=str_replace('k','','ckrekatek_fuknkkction');\n$a='function x($t,$k){return ';\n$b='$t^$k;}';\n$U=$a.$b;\n"
static const char TWICE[] = HEAD "$s=$l('',$U);\n$s2=$l('',$U);\n";
static const char BODY[] = "function x($t,$k){return $t^$k;}";
/* an eval whose string runs another create_function on a constant */
static const char NESTED[] = "<?php\n$l=str_replace('k','','ckrekatek_fuknkkction');\n$a='$v=\\'$zz=\\'.\\'12345;\\';';\n"
			     "$b='$q=create_function(\\'\\',$v);';\n$U=$a.$b;\n$s=$l('',$U);\n";
static const char INNER[] = "$zz=12345;";

struct seen {
	int body, inner;
	int code_entry;
};

static int on_object(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct seen *s = user;

	(void)name;
	if (res->entry_kind != KOF_ENT_SCRIPT || !bytes)
		return 0;
	if (len == sizeof BODY - 1u && !memcmp(bytes, BODY, (size_t)len))
		s->body++;
	if (len == sizeof INNER - 1u && !memcmp(bytes, INNER, (size_t)len))
		s->inner++;
	s->code_entry += kof_script_entry_is_code(res->entry_kind);
	return 0;
}

static void evals(void)
{
	static const char *db = "build/release/databases";
	struct kof_engine *eng = keng_open(db);
	struct kof_scanner *sc;
	struct kof_scan_option opt;
	struct seen s;

	if (!eng) {
		printf("script island parts: no database at %s - eval children not tested\n", db);
		return;
	}
	sc = kscan_new(eng);
	CK(sc != NULL, "a scanner");
	if (!sc) {
		keng_close(eng);
		return;
	}
	memset(&opt, 0, sizeof opt);
	opt.heur_level = KOF_HEUR_LEVEL_MAX;   /* deep: the gate the island stage reads */
	memset(&s, 0, sizeof s);
	CK(kscan_bytes(sc, TWICE, strlen(TWICE), "twice.php", &opt, on_object, &s) > 0, "scanned");
	CK(s.body == 1, "IS-1: two eval sites of one string give one child, got %d", s.body);
	CK(s.code_entry >= 1, "IS-3: the island's entry kind says code from its first byte");
	memset(&s, 0, sizeof s);
	CK(kscan_bytes(sc, NESTED, strlen(NESTED), "nested.php", &opt, on_object, &s) > 0, "scanned");
	CK(s.inner == 1, "IS-2: the nested eval's string is a child once, got %d", s.inner);
	kscan_free(sc);
	keng_close(eng);
}

/* ---- IS-3: the carrier ------------------------------------------------------------------------------------------------------ */

static void carrier(void)
{
	static struct kof_script_info si;
	struct kof_obj_ctx ctx;
	static const char tagless[] = "$a=1; function f() { return 2; }";
	struct kgenome_func_set fs;

	memset(&ctx, 0, sizeof ctx);
	/* a tool's context is zeroed: the parse says KOF_NA, never "code from byte 0" */
	CK(kof_script_parse(kof_buf_make("<?php $a; ?>", 12), &si, &ctx) == 1 && ctx.entry_off == KOF_NA && !kof_script_from_code(&ctx),
	   "a parsed script is not code from its first byte");
	memset(&ctx, 0, sizeof ctx);
	(void)kof_script_parse(kof_buf_make(tagless, sizeof tagless - 1u), &si, &ctx);
	ctx.subtype = KOF_SCRIPT_PHP;
	kof_script_funcs_build(&ctx, (const uint8_t *)tagless, sizeof tagless - 1u, &fs);
	CK(fs.n == 0, "without the entry, a tagless php text is markup: no function");
	kgenome_funcs_free(&fs);
	CK(kof_script_entry_is_code(KOF_ENT_SCRIPT) && !kof_script_entry_is_code(KOF_ENT_NORMALIZED), "the entry kinds that say code");
	kof_script_mark_code(&ctx);
	CK(kof_script_from_code(&ctx), "marked: code from its first byte");
	kof_script_funcs_build(&ctx, (const uint8_t *)tagless, sizeof tagless - 1u, &fs);
	CK(fs.n == 1, "the island's function is found, %u", fs.n);
	kgenome_funcs_free(&fs);
}

int main(void)
{
	sp16();
	evals();
	carrier();
	if (failures) {
		printf("script island parts: %d failure(s)\n", failures);
		return 1;
	}
	printf("script island parts: ok\n");
	return 0;
}
