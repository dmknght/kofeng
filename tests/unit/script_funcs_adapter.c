#define _GNU_SOURCE
/*
 * script_funcs_adapter - kof_script_funcs_build: the ONE call every place that builds a script's
 * function table makes (objctx_diag.c's funcs_of for the scan feed, kofexaminer_blocks.c, kofviewer's
 * kv_mutation.c mtn_funcs), and the parse's answer to "are these bytes a tagless fragment" read once,
 * inside it (SP-11, 2026-11-14).
 *
 * RED on the tree before the fix, by what the three callers did: the scan feed and kofexaminer chose a
 * second entry point for a tagless island (a copy behind a made-up "<?php\n"), kofviewer's mtn_funcs
 * called the plain one - which lexes an island's php as MARKUP - so the blocks table of an island
 * listed no function while the scan fed one (measured on the base tree: the plain call on
 * "function a() { }" with KOF_SCRIPT_PHP answers 0 entries, the fragment call 1). Why no test caught
 * it: (a) no test built an island's table through the viewer's call; each caller's own decision was
 * never compared with the others'.
 *
 * Every case: the island and the same code in a tagged file give the same functions, at the same offsets
 * relative to the code; a non-page language is unaffected by the flag; the functions of an island are never
 * shifted (the made-up tag had to be subtracted from every offset, name included).
 *
 * THE CARRIER MOVED (island package, 2026-11-14, design point 5): "code from its first byte" is the object's
 * ENTRY (ctx->entry_off 0, kof_script_from_code), which the producer of an island declares, and no longer the
 * parse's tag_len read as a flag - a made-up kof_script_info was the template the owner named. The adapter takes
 * the object's context.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kofmod/kofsig.h>
#include <kofmod/script.h>
#include <kgenome.h>
#include "../../libkofeng/analyzers/parsers/scripts/script_route.h"

static unsigned ok_n, bad_n;

#define CK(cond, ...) do { \
	if (cond) { \
		ok_n++; \
	} else { \
		bad_n++; \
		printf("  FAIL %s:%d  %s  ", __FILE__, __LINE__, #cond); \
		printf(__VA_ARGS__); \
		printf("\n"); \
	} \
} while (0)

/* A script context of `kind`; `code` says the producer declared it code from its first byte (an island). */
static void ctx_of(struct kof_obj_ctx *ctx, uint8_t kind, int code)
{
	memset(ctx, 0, sizeof *ctx);
	ctx->format = KOF_FMT_SCRIPT;
	ctx->subtype = kind;
	ctx->entry_off = KOF_NA;
	if (code)
		kof_script_mark_code(ctx);
}

static void table(const struct kof_obj_ctx *ctx, const char *src, struct kgenome_func_set *fs)
{
	memset(fs, 0, sizeof *fs);
	kof_script_funcs_build(ctx, (const uint8_t *)src, strlen(src), fs);
}

/* An island and the same code after a tag: the same functions, the island's at the island's own offsets, names included. */
static void island_equals_tagged_file(void)
{
	static const char code[] = "function a($x) { return 1; }\n$f = static function () { };\nfunction b() { }\n";
	static const char tag[] = "<?php\n";
	char file[256];
	struct kof_obj_ctx island, tagged;
	struct kgenome_func_set fi, ff;
	uint32_t i;

	ctx_of(&island, KOF_SCRIPT_PHP, 1);
	ctx_of(&tagged, KOF_SCRIPT_PHP, 0);
	snprintf(file, sizeof file, "%s%s", tag, code);
	table(&island, code, &fi);
	table(&tagged, file, &ff);
	CK(fi.n == 3u, "an island's functions: %u, want 3", fi.n);
	CK(ff.n == fi.n, "a tagged file %u, the island %u", ff.n, fi.n);
	for (i = 0; i < fi.n && i < ff.n; i++) {
		CK(fi.v[i].off + strlen(tag) == ff.v[i].off, "entry %u at %llu in the island, %llu in the file", i,
		   (unsigned long long)fi.v[i].off, (unsigned long long)ff.v[i].off);
		CK(fi.v[i].len == ff.v[i].len, "entry %u length", i);
		CK(fi.v[i].name_len == ff.v[i].name_len &&
		   (!fi.v[i].name_len || fi.v[i].name_off + strlen(tag) == ff.v[i].name_off), "entry %u name", i);
	}
	CK(fi.n && fi.v[0].off == 0 && fi.v[0].name_off == 9u, "the island's first function at its own byte 0, named at 9");
	kgenome_funcs_free(&fi);
	kgenome_funcs_free(&ff);
}

/* What the object's entry says decides, not the bytes: a php object whose bytes hold no tag is markup to php (no function) unless
 * its producer declared it code. */
static void the_entry_decides(void)
{
	static const char code[] = "function a() { }\n";
	struct kof_obj_ctx file;
	struct kgenome_func_set fs;

	ctx_of(&file, KOF_SCRIPT_PHP, 0);
	table(&file, code, &fs);
	CK(fs.n == 0u, "a php FILE with no tag is markup: %u function(s)", fs.n);
	kgenome_funcs_free(&fs);
	CK(kof_script_from_code(NULL) == 0, "no context is not code from its first byte");
	CK(kof_script_from_code(&file) == 0, "a parsed script (entry KOF_NA) is not");
	file.entry_off = 0;
	CK(kof_script_from_code(&file) == 1, "entry 0 is");
	file.format = KOF_FMT_ELF;
	CK(kof_script_from_code(&file) == 0, "an ELF whose entry is 0 is not a script");
}

/* A language with no tag reads the same either way (bat, a content-guessed js or psh: the flag must not move them). */
static void non_page_languages_unmoved(void)
{
	static const struct { uint8_t kind; const char *src; uint32_t n; } c[] = {
		{ KOF_SCRIPT_JS,    "function a({x}) { }\nfunction b() { }\n", 2 },
		{ KOF_SCRIPT_SHELL, "a() { echo }; }\nfunction b { :; }\n",   2 },
		{ KOF_SCRIPT_PERL,  "sub A::a { }\nsub b { }\n",              2 },
		{ KOF_SCRIPT_PSH,   "function Get-A { }\nfilter B { }\n",     2 },
		/* python has a strategy since the island package (celllysis/script_funcs_py.c): it was 0, the language had none */
		{ KOF_SCRIPT_PYTHON, "def a():\n  pass\n",                    1 },
	};
	unsigned k;

	for (k = 0; k < sizeof c / sizeof c[0]; k++) {
		struct kof_obj_ctx frag, file;
		struct kgenome_func_set a, b;
		uint32_t i;

		ctx_of(&frag, c[k].kind, 1);
		ctx_of(&file, c[k].kind, 0);
		table(&frag, c[k].src, &a);
		table(&file, c[k].src, &b);
		CK(a.n == c[k].n && b.n == c[k].n, "kind %u: %u and %u function(s), want %u", c[k].kind, a.n, b.n, c[k].n);
		for (i = 0; i < a.n && i < b.n; i++)
			CK(a.v[i].off == b.v[i].off && a.v[i].len == b.v[i].len, "kind %u entry %u moved", c[k].kind, i);
		kgenome_funcs_free(&a);
		kgenome_funcs_free(&b);
	}
}

int main(void)
{
	island_equals_tagged_file();
	the_entry_decides();
	non_page_languages_unmoved();
	printf("script_funcs_adapter: %u ok, %u failed\n", ok_n, bad_n);
	return bad_n != 0;
}
