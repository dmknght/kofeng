/*
 * lineage_dangle - kof_result.lineage must survive past the object it was reported for,
 * for exactly as long as the diag[] array next to it does.
 *
 * kscan_explain's collect() (kofdetect.c) deep-copies res->diag into a buffer it mallocs
 * and owns, for one stated reason: st_report's own comment says the scanner's report
 * tables are "one buffer for the scanner's life... lent to the caller for its callback" -
 * a borrowed pointer that the NEXT object's report is free to reuse. st_report_lineage
 * (scan_pipeline.c) has the identical shape for res->lineage ("REALLOC'D TO FIT... kept
 * until the object ends because a later ask in the SAME callback reads the same records"),
 * but collect() never gave it the same deep copy res->diag got - every kdet_object but the
 * LAST of a multi-object kscan_explain run is left holding a dangling/overwritten lineage
 * pointer once a later sibling's own (bigger) report reallocs the shared buffer.
 *
 * FOUND 2026-11-13 scanning real MalwareBazaar.2026.08 samples (and samples/msfvenom-encr)
 * through a kscan_explain-based driver: AddressSanitizer heap-use-after-free, freed by
 * st_report_lineage's realloc (scan_pipeline.c:546), 12 of 95 real x86-64 samples.
 *
 * THE FIXTURE is a tar of two real, minimal x86-64 ELF executables (cf_elf64/cf_stager64/
 * cf_filler64, caps_fix.h): "a_small" has few filler reads (a small lineage graph), "b_big"
 * has many more (a bigger one) - so b_big's own report forces st_report_lineage's realloc to
 * grow past a_small's capacity, which is exactly the shape that moves or overwrites the
 * shared buffer. The database is the unpack packs only (no diagnose needed: kscan_explain's
 * own format-servable widening runs the SYSCALL route on any ELF, database or not).
 */

#define _GNU_SOURCE
#include <unistd.h>

#include "caps_fix.h"
#include "../../libkofeng/kofcore/kofplatform.h"

static uint64_t build_elf(uint8_t *img, uint64_t cap, unsigned k)
{
	static uint8_t code[1u << 16];
	unsigned n = 0, i;

	for (i = 0; i < k; i++)
		n = cf_filler64(code, n, i);
	n = cf_stager64(code, n);
	return cf_elf64(img, cap, code, n);
}

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
	if (b)
		*n = (size_t)L;
	return b;
}

/* The ground truth for one file alone: its own n_lineage and a checksum of every record,
 * from its OWN kscan_explain run (one object, nothing else to share a buffer with). */
static void solo_lineage(kof_engine *e, const uint8_t *img, uint64_t len, const char *name,
			  uint32_t *out_n, uint32_t *out_sum)
{
	kof_scanner *sc = kscan_new(e);
	kdet_run *run;
	const struct kdet_object *o;
	uint32_t sum = 0, i, k;

	*out_n = 0;
	*out_sum = 0;
	if (!sc)
		return;
	run = kscan_explain(sc, img, len, name, NULL);
	o = run ? kdet_run_find(run, name) : NULL;
	if (o) {
		*out_n = o->res.n_lineage;
		for (i = 0; i < o->res.n_lineage; i++) {
			const struct kof_diag_lineage_rec *r = &o->res.lineage[i];

			sum = sum * 16777619u + (uint32_t)r->at;
			sum = sum * 16777619u + (uint32_t)r->n_in;
			for (k = 0; k < r->n_in && k < 4u; k++)
				sum = sum * 16777619u + r->in[k].from + ((uint32_t)r->in[k].role << 8);
		}
	}
	*out_sum = sum;
	kdet_run_free(run);
	kscan_free(sc);
}

int main(void)
{
	char root[256], dir[300], tarp[300], cmd[2400];
	uint8_t small_img[1u << 12], big_img[1u << 16];
	uint64_t small_len, big_len;
	uint8_t *tb;
	size_t tn = 0;
	kof_engine *e;
	kof_scanner *sc;
	kdet_run *run;
	const struct kdet_object *o_small, *o_big;
	uint32_t want_small_n, want_small_sum, want_big_n, want_big_sum;

	snprintf(root, sizeof root, "build/kof_lineage_dangle_XXXXXX");
	if (!mkdtemp(root)) {
		printf("lineage_dangle: cannot make a scratch directory\n");
		return 2;
	}

	small_len = build_elf(small_img, sizeof small_img, 3u);
	big_len = build_elf(big_img, sizeof big_img, 400u);

	snprintf(dir, sizeof dir, "%s/mem", root);
	kof_mkdir(dir, 0700);
	{
		char p[400];

		snprintf(p, sizeof p, "%s/a_small.elf", dir);
		CK(write_file(p, small_img, (size_t)small_len));
		snprintf(p, sizeof p, "%s/b_big.elf", dir);
		CK(write_file(p, big_img, (size_t)big_len));
	}
	snprintf(tarp, sizeof tarp, "%s/pair.tar", root);
	snprintf(cmd, sizeof cmd, "tar -C %s -cf %s --sort=name a_small.elf b_big.elf 2>/dev/null || tar -C %s -cf %s a_small.elf b_big.elf",
		 dir, tarp, dir, tarp);
	CK(system(cmd) == 0);
	tb = read_file(tarp, &tn);
	CK(tb != NULL);

	e = keng_open("build/release/databases");
	CK(e != NULL);
	if (!e || !tb) {
		printf("lineage_dangle: cannot set up the fixture\n");
		return 2;
	}

	/* the ground truth: each file's own lineage, scanned alone */
	solo_lineage(e, small_img, small_len, "a_small.elf", &want_small_n, &want_small_sum);
	solo_lineage(e, big_img, big_len, "b_big.elf", &want_big_n, &want_big_sum);
	CK(want_small_n > 0u);
	CK(want_big_n > want_small_n);          /* the fixture's whole point: b_big's report must force a bigger realloc */

	/* now both in ONE tar, ONE kscan_explain run - st_report_lineage's shared, scanner-lifetime
	 * buffer is realloc'd once for a_small and again (bigger) for b_big, while collect() is
	 * supposed to have already taken a_small's own copy before that second realloc runs */
	sc = kscan_new(e);
	run = sc ? kscan_explain(sc, tb, tn, "pair.tar", NULL) : NULL;
	CK(run && kdet_run_count(run) >= 2u);
	o_small = run ? kdet_run_find(run, "pair.tar//0:a_small.elf") : NULL;
	o_big = run ? kdet_run_find(run, "pair.tar//1:b_big.elf") : NULL;
	CK(o_small != NULL);
	CK(o_big != NULL);
	if (o_small) {
		uint32_t sum = 0, i, k;

		CK(o_small->res.n_lineage == want_small_n);
		for (i = 0; i < o_small->res.n_lineage; i++) {
			const struct kof_diag_lineage_rec *r = &o_small->res.lineage[i];

			sum = sum * 16777619u + (uint32_t)r->at;
			sum = sum * 16777619u + (uint32_t)r->n_in;
			for (k = 0; k < r->n_in && k < 4u; k++)
				sum = sum * 16777619u + r->in[k].from + ((uint32_t)r->in[k].role << 8);
		}
		CK(sum == want_small_sum);
		/* LINEAGE-DANGLE-1's own reproducer: without the fix, a_small's res.lineage still
		 * points at the scanner's one shared buffer, which b_big's own (bigger) report
		 * already realloc'd for itself - so a_small's checksum here is b_big's, or the
		 * read above is a use-after-free under ASAN. */
	}
	if (o_big) {
		CK(o_big->res.n_lineage == want_big_n);
	}
	kdet_run_free(run);
	kscan_free(sc);
	keng_close(e);
	free(tb);

	if (!fails) {
		snprintf(cmd, sizeof cmd, "rm -rf '%s'", root);
		(void)system(cmd);
	}
	printf("lineage_dangle: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
