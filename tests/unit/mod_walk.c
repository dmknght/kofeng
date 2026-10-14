/*
 * mod_walk.c - the order the scan runs the modules of a format in.
 *
 * The loader keeps one list of module indices per format and ONE list for the modules that name no format
 * (they used to be copied into all of them: 29 entries, 116 bytes a module, for a rule that is "generic");
 * the scan merges the format's list with the generic one (kof_mod_walk). The merge has to give the order each
 * format had when it held its own copy: every module that names the format or none, cheapest kind of data
 * first (kof_module_tier), and in module order inside a kind. This builds a pack of random modules - generic,
 * one format, two formats; with no strings, with a block, with a string - loads it, and compares the walk of
 * every format with a brute-force reference that sorts all of them. And the walk with no index: the flat array.
 *
 * Scratch files go under build/, never /tmp.
 */

#include "hostile_engine.h"

#include <stddef.h>
#include <sys/stat.h>

#include "../../libkofeng/databases/dbloader.h"
#include "../../libkofeng/databases/dbpacker.h"
#include "../../libkofeng/databases/pack/dbcore.h"
#include "../../libkofeng/databases/pack/dbtables.h"
#include <kofmod/kofsig.h>

#define NM 600u

static char tmp[300];

static int cmp_key(const void *A, const void *B)
{
	const uint64_t *a = A, *b = B;

	return *a < *b ? -1 : *a > *b;
}

int main(void)
{
	static uint8_t code[] = { 0x90, 0xc3 };
	static struct kof_pw_mod mods[NM];
	static struct kof_pw_str str[NM];
	static struct kof_pw_name names[1] = { { 1, "Test.Walk" } };
	static const uint32_t rng[1] = { 1u };
	static struct kof_mutation_block blk[NM];
	static uint32_t pool[NM * 32u];
	static char strs[NM][16];
	uint32_t i, fmt, shape[NM];
	uint8_t *img;
	size_t len = 0;
	char dir[400], path[500];
	struct kof_engine *e;
	FILE *f;

	snprintf(tmp, sizeof tmp, "build/kof_mod_walk_%d", (int)getpid());
	if (mkdir(tmp, 0700) != 0) {
		printf("mod_walk: no build directory - nothing tested\n");
		return 0;
	}
	he_seed(0x3a1ce5ull);
	for (i = 0; i < NM; i++) {
		struct kof_pw_mod *m = &mods[i];
		uint32_t t = he_below(4u), kind = he_below(3u), j;

		shape[i] = t;
		memset(m, 0, sizeof *m);
		m->code = code;
		m->code_len = sizeof code;
		m->size_min = 1;
		m->scan_mask = 1u;
		m->rng = rng;
		m->n_rng = 1;
		m->name = names;
		m->n_names = 1;
		if (t == 1u) {
			m->n_target = 1;
			m->target[0] = KOF_FMT_ELF;
		} else if (t == 2u) {
			m->n_target = 1;
			m->target[0] = KOF_FMT_PE;
		} else if (t == 3u) {
			m->n_target = 2;
			m->target[0] = KOF_FMT_ELF;
			m->target[1] = KOF_FMT_PE;
		}                                       /* t == 0: names none, so every format */
		if (kind == 1u) {                       /* a string: tier 2 */
			snprintf(strs[i], sizeof strs[i], "walk-%05u", i);
			str[i].bytes = (const uint8_t *)strs[i];
			str[i].len = (uint16_t)strlen(strs[i]);
			str[i].kind = KOF_STR_LITERAL;
			m->str = &str[i];
			m->n_str = 1;
		} else if (kind == 2u) {                /* a block: tier 1 */
			for (j = 0; j < 32u; j++)
				pool[i * 32u + j] = (uint32_t)he_below(0xfffffff0u) + 1u + j;
			blk[i].first_hash = 0;
			blk[i].n_hash = 32;
			blk[i].scan_mask = 1;
			m->blk = &blk[i];
			m->n_blk = 1;
			m->pool = &pool[i * 32u];
			m->n_pool = 32;
		}
	}
	img = kof_pack_build(KOF_PACK_DETECT, mods, NM, &len);
	CK(img != NULL, "the pack builds");
	if (!img)
		return 1;
	snprintf(dir, sizeof dir, "%s/db", tmp);
	mkdir(dir, 0700);
	snprintf(path, sizeof path, "%s/db/p.ksig", tmp);
	f = fopen(path, "wb");
	CK(f != NULL && fwrite(img, 1, len, f) == len, "the pack is written");
	if (f)
		fclose(f);
	free(img);
	e = kof_db_load(dir);
	CK(e != NULL && e->n_mods == NM, "it loads (%u modules)", e ? e->n_mods : 0u);
	if (!e)
		return 1;
	{
		uint32_t n_any = 0;

		for (i = 0; i < NM; i++)
			n_any += shape[i] == 0u;
		CK(e->n_mod_any == n_any && e->mod_any != NULL, "the generic modules are one list of %u, not a copy in every format (%u)", n_any, e->n_mod_any);
	}
	/* the index costs one entry a module naming a format and one for a generic one, whatever the format count */
	{
		uint32_t named = 0;

		for (i = 0; i < NM; i++)
			named += shape[i] == 1u || shape[i] == 2u ? 1u : shape[i] == 3u ? 2u : 0u;
		CK(e->mod_at[KOF_TARGET_COUNT] == named, "the formats' lists hold %u entries for %u modules that name one or two (%u)", named, NM,
		   e->mod_at[KOF_TARGET_COUNT]);
	}
	for (fmt = 0; fmt < KOF_TARGET_COUNT + 1u; fmt++) {
		uint64_t ref[NM];
		uint32_t n_ref = 0, k = 0, mi, bad = 0, pass;

		for (i = 0; i < NM; i++) {
			const struct kof_module *m = &e->mods[i];

			if (fmt < KOF_TARGET_COUNT && !kof_module_targets(m, (uint8_t)fmt))
				continue;
			ref[n_ref++] = ((uint64_t)kof_module_tier(m) << 32) | i;
		}
		if (fmt == KOF_TARGET_COUNT) {          /* past the axis: no index, the flat array in module order */
			for (pass = 0; pass < n_ref; pass++)
				ref[pass] = pass;
		} else {
			qsort(ref, n_ref, sizeof ref[0], cmp_key);
		}
		{
			struct kof_mod_walk w;

			kof_mod_walk_begin(&w, e, fmt);
			CK(kof_mod_walk_count(&w) == n_ref || fmt == KOF_TARGET_COUNT, "format %u: the walk yields %u modules, the reference %u", fmt,
			   kof_mod_walk_count(&w), n_ref);
			while (kof_mod_walk_next(&w, &mi)) {
				if (k >= n_ref || (uint32_t)ref[k] != mi)
					bad++;
				k++;
			}
			CK(k == n_ref && bad == 0, "format %u: the walk is the reference's order (%u modules, %u out of place)", fmt, k, bad);
		}
	}
	/* no index at all (it could not be allocated): the flat array, every module once, in module order */
	{
		uint32_t *keep = e->mod_by_target, mi, k = 0;
		struct kof_mod_walk w;

		e->mod_by_target = NULL;
		kof_mod_walk_begin(&w, e, KOF_FMT_ELF);
		while (kof_mod_walk_next(&w, &mi)) {
			if (mi != k)
				break;
			k++;
		}
		CK(k == NM, "with no index the walk is the flat array (%u of %u)", k, NM);
		e->mod_by_target = keep;
	}
	kof_db_free(e);
	he_rmtree(tmp);
	printf("mod_walk: %u checks, %u failed\n", he_checks, he_fails);
	return he_fails != 0;
}
