/*
 * hunt_wrap_sites - the list of socketcall sites the wrapper analysis is left holding.
 *
 * FOUND BY timing hostile-shaped objects: an i386 ELF whose code is `mov eax,0x66; int 0x80`
 * repeated (every one a candidate, ebx never read) took 0.07 s at 128 KB, 0.93 s at 512 KB,
 * 3.2 s at 1 MB, 12 s at 2 MB and 59 s at 4 MB. The list was searched for the site before
 * every append and again, in full, once per site by kgenome_diag_wrapper_site_wrapped.
 *
 * Checked here: the list is settled once (each site once, in discovery order, a sorted copy
 * for the question) and a 1.4 MB object of 200000 such sites answers in seconds, with one
 * opaque node per site as before.
 */

#include "caps_fix.h"
#include "../../libgenome/phenotype/diag_wrapper_private.h"

#include <time.h>

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

static void settle_semantics(void)
{
	struct kgenome_diag_scan *s = calloc(1, sizeof *s);
	static const uint64_t in[] = { 50, 10, 50, 30, 10, 20, 30, 50, 70 };
	static const uint64_t want[] = { 50, 10, 30, 20, 70 };
	unsigned i;

	if (!s) {
		CK(0);
		return;
	}
	kgenome_ledger_init(&s->led, 1u << 20);
	s->wrap = malloc(sizeof in);
	memcpy(s->wrap, in, sizeof in);
	s->n_wrap = s->cap_wrap = (uint32_t)(sizeof in / sizeof in[0]);
	/* before: the scan answers membership */
	CK(kgenome_diag_wrapper_site_wrapped(s, 30) == 1 && kgenome_diag_wrapper_site_wrapped(s, 31) == 0);
	kgenome_diag_wrap_settle(s);
	CK(s->n_wrap == sizeof want / sizeof want[0]);
	for (i = 0; i < s->n_wrap && i < sizeof want / sizeof want[0]; i++)
		CK(s->wrap[i] == want[i]);              /* first occurrence, discovery order */
	CK(s->wrap_sorted && s->n_wrap_sorted == 5);
	for (i = 0; i < 100; i++)
		CK(kgenome_diag_wrapper_site_wrapped(s, i) == (i == 10 || i == 20 || i == 30 || i == 50 || i == 70));
	kgenome_diag_wrap_settle(s);                    /* a second call changes nothing */
	CK(s->n_wrap == 5);
	free(s->wrap);
	free(s->wrap_sorted);
	free(s);
}

static unsigned char view[1u << 22];
static uint8_t img[3u << 20];
static uint8_t code[2u << 20];

static void many_sites(void)
{
	struct kof_obj_ctx ctx;
	struct kgenome_diag_scan *s;
	enum { N = 200000 };
	unsigned n = 0, i, opaque = 0;
	uint64_t len;
	double t0;

	for (i = 0; i < N; i++) {
		code[n++] = 0xb8; code[n++] = 0x66; code[n++] = 0; code[n++] = 0; code[n++] = 0;
		code[n++] = 0xcd; code[n++] = 0x80;
	}
	memset(view, 0, sizeof view);
	len = cf_elf32(img, sizeof img, code, n);
	t0 = now();
	s = cf_scan(img, len, KGENOME_DIAG_RUN_SYSCALL, &ctx, view);
	CK(now() - t0 < 5.0);
	for (i = 0; s && i < kgenome_diag_scan_count(s); i++)
		opaque += (kgenome_diag_scan_at(s, i)->bits & KGENOME_DIAG_H_OPAQUE) != 0;
	CK(s != NULL);
	CK(opaque == N || kgenome_diag_scan_status(s) != KGENOME_OK);   /* one per site, or said partial */
	kgenome_diag_scan_free(s);
}

int main(void)
{
	settle_semantics();
	many_sites();
	if (fails)
		return 1;
	printf("hunt_wrap_sites: ok\n");
	return 0;
}
