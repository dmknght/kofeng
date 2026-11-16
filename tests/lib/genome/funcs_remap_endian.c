/*
 * funcs_remap_endian - kgenome_funcs_remap_endian (funcs.c), which tests/unit/funcs_remap.c
 * never calls: gcov on the x86-64 fntab audit (2026-11-13) measured 0% coverage of this
 * function and of funcs_remap's endian-plan branch (the realloc-growth path, the `plan &&
 * plan->n` arm), against ONE real caller in the whole tree (scanners/scan_norm_endian.c,
 * sx_endian_funcs: the big-endian normalised view's function table).
 *
 * `par` holds a function's bytes as a BIG-ENDIAN object keeps them (4-byte instruction
 * words, as MIPS/ARM-BE32/PPC64/SH/MicroBlaze are swapped - endian.h); `plan` is what
 * kgenome_endian_plan_build would answer for that object (built here by hand: one
 * KGENOME_ENDIAN_L_W4 span over the function, the shape kgenome_endian_range reads);
 * `view` holds the SAME object after the plan's swap (what sx_endian_apply produces) at a
 * DIFFERENT offset, so a find that returns the view's own offset - not the parent's - is
 * proof the search, not an identity copy, is what matched.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <kgenome.h>
#include <genotype/image/funcs.h>
#include <genotype/image/endian.h>

static int failures;

static void ok(const char *what, int cond)
{
	if (!cond) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

/* One big-endian 4-byte word, written as the architectures endian.h names do. */
static void be_word(uint8_t *p, uint32_t w)
{
	p[0] = (uint8_t)(w >> 24);
	p[1] = (uint8_t)(w >> 16);
	p[2] = (uint8_t)(w >> 8);
	p[3] = (uint8_t)w;
}

static void le_word(uint8_t *p, uint32_t w)
{
	p[0] = (uint8_t)w;
	p[1] = (uint8_t)(w >> 8);
	p[2] = (uint8_t)(w >> 16);
	p[3] = (uint8_t)(w >> 24);
}

int main(void)
{
	/* par: function A at 0 (8 words, 32 bytes), function B at 64 (16 words, 64 bytes) -
	 * B is longer, so the second remap forces funcs_remap's realloc of `pat` (pat_cap
	 * starts at A's 32 bytes, B's 64 need it to grow). */
	uint8_t par[128], view[256];
	struct kgenome_func f[2];
	struct kgenome_func_set pf, out;
	struct kgenome_endian_span sp[1];
	struct kgenome_endian_plan plan;
	uint32_t i;
	uint64_t a_at_view, b_at_view;

	memset(par, 0, sizeof par);
	for (i = 0; i < 8; i++)
		be_word(par + i * 4u, 0x10203040u + i);
	for (i = 0; i < 16; i++)
		be_word(par + 64 + i * 4u, 0x50607080u + i);

	/* view: padding, then A's words swapped to little-endian, more padding, then B's. */
	memset(view, 0xaa, sizeof view);
	a_at_view = 20;
	for (i = 0; i < 8; i++)
		le_word(view + a_at_view + i * 4u, 0x10203040u + i);
	b_at_view = a_at_view + 32u + 40u;
	for (i = 0; i < 16; i++)
		le_word(view + b_at_view + i * 4u, 0x50607080u + i);

	memset(f, 0, sizeof f);
	f[0].off = 0;  f[0].len = 32; f[0].value = 0x1000; f[0].shndx = 1;
	f[1].off = 64; f[1].len = 64; f[1].value = 0x2000; f[1].shndx = 2;
	pf.v = f; pf.n = 2; pf.status = KGENOME_OK;

	memset(sp, 0, sizeof sp);
	sp[0].off = 0;   sp[0].len = 128; sp[0].lay = KGENOME_ENDIAN_L_W4;     /* the whole code unit, both functions */
	memset(&plan, 0, sizeof plan);
	plan.v = sp; plan.n = 1; plan.code_unit = 4;

	kgenome_funcs_remap_endian(par, sizeof par, &pf, &plan, view, b_at_view + 64u, &out);
	ok("both functions found by their SWAPPED bytes", out.n == 2);
	if (out.n == 2) {
		ok("A is at the view's offset, not the parent's", out.v[0].off == a_at_view && out.v[0].len == 32);
		ok("A keeps its symbol fields across the swap", out.v[0].value == 0x1000 && out.v[0].shndx == 1);
		/* the realloc path: B (64 bytes) is bigger than A (32), forcing pat_cap to grow */
		ok("B (the longer one, after the realloc) is found at its own view offset",
		   out.v[1].off == b_at_view && out.v[1].len == 64);
		ok("B keeps its symbol fields", out.v[1].value == 0x2000 && out.v[1].shndx == 2);
	}
	kgenome_funcs_free(&out);

	/* the plain (non-endian) search on the SAME inputs must NOT find them: the view holds
	 * the swapped bytes, and a search for the parent's own (big-endian) bytes is a search
	 * for the wrong pattern - proof the endian variant is doing real work, not a no-op that
	 * happens to pass because the two searches are equivalent on this input. */
	kgenome_funcs_remap(par, sizeof par, &pf, view, b_at_view + 64u, &out);
	ok("the non-endian search does not find big-endian bytes inside a swapped view", out.n == 0);
	kgenome_funcs_free(&out);

	/* a function whose swapped bytes are not in the view at all: skipped, not a false match or a crash */
	{
		uint8_t stray[128];
		struct kgenome_func g;
		struct kgenome_func_set pg;

		memset(stray, 0, sizeof stray);
		for (i = 0; i < 8; i++)
			be_word(stray + i * 4u, 0x99999999u);
		memset(&g, 0, sizeof g);
		g.off = 0; g.len = 32;
		pg.v = &g; pg.n = 1; pg.status = KGENOME_OK;
		kgenome_funcs_remap_endian(stray, sizeof stray, &pg, &plan, view, b_at_view + 64u, &out);
		ok("a function absent from the view (even after the swap) is not matched", out.n == 0);
		kgenome_funcs_free(&out);
	}

	/* no plan at all (code_unit 0, n 0: a canonical object's own empty plan) is the plain search */
	{
		struct kgenome_endian_plan empty;

		memset(&empty, 0, sizeof empty);
		kgenome_funcs_remap_endian(par, sizeof par, &pf, &empty, par, sizeof par, &out);
		ok("an empty plan on an already-canonical parent finds functions at their own offsets",
		   out.n == 2 && out.v[0].off == 0 && out.v[1].off == 64);
		kgenome_funcs_free(&out);
	}

	/* hostile: no parent, no view, zero functions - all empty answers, never a crash */
	kgenome_funcs_remap_endian(NULL, 0, &pf, &plan, view, b_at_view + 64u, &out);
	ok("no parent: empty", out.n == 0 && !out.v);
	pf.n = 0;
	kgenome_funcs_remap_endian(par, sizeof par, &pf, &plan, view, b_at_view + 64u, &out);
	ok("no functions: empty", out.n == 0 && !out.v);

	if (failures) {
		printf("funcs_remap_endian: %d failure(s)\n", failures);
		return 1;
	}
	printf("funcs_remap_endian: swapped search, realloc growth, non-endian differential, hostile - ok\n");
	return 0;
}
