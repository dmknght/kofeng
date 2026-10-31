/*
 * arm_index - the derived indexes of the ARM state, Thumb state and AArch64 decoders are CONST DATA that matches their rows, and
 * a decode is safe on many threads.
 *
 * They were built by code on the first decode into writable static storage (.bss 0x12030 for ARM and Thumb, 0x1020 for
 * AArch64) behind a compare-and-swap and a spin; a lib "is safe on many threads" and keeps no writable global state. Now
 * tools/genotype/arm_index_gen.c writes them and the output is checked in (arm32_index_tab.c, arm64_l1_tab.c).
 *
 *   segments  every table lies in a loaded segment that is not writable (dl_iterate_phdr). Before: all of them were in .bss.
 *   drift     the generator is included here (ARMIDX_NO_MAIN) and what it makes from the rows is compared, entry by entry, with
 *             the checked-in tables: a row changed without `make genotype-arm-index` fails here.
 *   threads   eight threads decode the same words from a standing start and every one gets the answer of one thread.
 *
 * MUTATION CHECK, measured: a row of arm32_rows.c changed without regenerating fails `drift`; one entry of arm32_index_tab.c
 * changed fails `drift`; the checked-in tables moved back to writable storage (const dropped) fail `segments`.
 */
#define _GNU_SOURCE
#include <link.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ARMIDX_NO_MAIN
#include "../../../tools/genotype/arm_index_gen.c"

#include <genotype/arm32/arm32.h>
#include <genotype/arm32/thumb.h>
#include <genotype/arm64/arm64.h>

static int failures;

static void ck(int ok, const char *what)
{
	if (!ok) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

/* ---- segments ------------------------------------------------------------------------------------------------ */

struct seg_q { uintptr_t lo, hi; int found, writable; };

static int seg_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	struct seg_q *q = data;
	int i;

	(void)size;
	for (i = 0; i < info->dlpi_phnum; i++) {
		const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
		uintptr_t lo = info->dlpi_addr + ph->p_vaddr;

		if (ph->p_type != PT_LOAD)
			continue;
		if (q->lo >= lo && q->hi <= lo + ph->p_memsz) {
			q->found = 1;
			q->writable = (ph->p_flags & PF_W) != 0;
		}
	}
	return 0;
}

static void in_readonly(const void *p, size_t n, const char *what)
{
	struct seg_q q = { (uintptr_t)p, (uintptr_t)p + n, 0, 1 };
	char msg[160];

	dl_iterate_phdr(seg_cb, &q);
	snprintf(msg, sizeof msg, "%s lies in a loaded segment that is not writable (found %d, writable %d)", what, q.found, q.writable);
	ck(q.found && !q.writable, msg);
}

static void segments(struct armidx *o)
{
	in_readonly(kgenome_arm32_idx, sizeof kgenome_arm32_idx, "the ARM state index");
	in_readonly(kgenome_arm32_lists, o->arm_used * sizeof kgenome_arm32_lists[0], "the ARM state lists");
	in_readonly(kgenome_thumb_idx_narrow, sizeof kgenome_thumb_idx_narrow, "the Thumb narrow index");
	in_readonly(kgenome_thumb_idx_wide, sizeof kgenome_thumb_idx_wide, "the Thumb wide index");
	in_readonly(kgenome_thumb_lists, o->thumb_used * sizeof kgenome_thumb_lists[0], "the Thumb lists");
	in_readonly(kgenome_arm64_l1, sizeof kgenome_arm64_l1, "the AArch64 level-1 lookup");
}

/* ---- drift --------------------------------------------------------------------------------------------------- */

static int rows_same(const struct kgenome_arm32_row *a, const struct kgenome_arm32_row *b, unsigned n)
{
	unsigned i;

	for (i = 0; i < n; i++)
		if (a[i].mask != b[i].mask || a[i].value != b[i].value || a[i].id != b[i].id)
			return 0;
	return 1;
}

static void drift(struct armidx *o)
{
	struct kgenome_arm32_stats st;

	kgenome_arm32_stats(&st);
	ck(st.lists_arm32 == o->arm_used && st.lists_thumb == o->thumb_used, "the pools hold what the rows make");
	ck(st.shadowed_arm32 == o->shadowed_arm32 && st.shadowed_thumb == o->shadowed_thumb, "the shadowed-row counts are the rows'");
	ck(!memcmp(kgenome_arm32_idx, o->arm_idx, sizeof o->arm_idx), "the ARM state index is what the rows make (make genotype-arm-index)");
	ck(rows_same(kgenome_arm32_lists, o->arm_lists, o->arm_used), "the ARM state lists are what the rows make");
	ck(!memcmp(kgenome_thumb_idx_narrow, o->thumb_narrow, sizeof o->thumb_narrow), "the Thumb narrow index is what the rows make");
	ck(!memcmp(kgenome_thumb_idx_wide, o->thumb_wide, sizeof o->thumb_wide), "the Thumb wide index is what the rows make");
	ck(rows_same(kgenome_thumb_lists, o->thumb_lists, o->thumb_used), "the Thumb lists are what the rows make");
	ck(!memcmp(kgenome_arm64_l1, o->l1, sizeof o->l1), "the AArch64 level-1 lookup is what the tree makes");
}

/* ---- threads ------------------------------------------------------------------------------------------------- */

#define NTHREADS 8
#define NWORDS 400000u

static pthread_barrier_t go;

static uint64_t decode_all(void)
{
	uint64_t h = 1469598103934665603ull, rs = 88172645463325252ull;
	unsigned i;

	for (i = 0; i < NWORDS; i++) {
		struct kgenome_arm32_insn a;
		struct kgenome_arm64_insn b;
		struct kgenome_thumb_insn t;
		uint32_t w;

		rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17;
		w = (uint32_t)(rs >> 16);
		kgenome_arm32_decode(&a, w);
		kgenome_arm64_decode(&b, w);
		kgenome_thumb_decode_narrow(&t, w & 0xffffu);
		h = (h ^ a.id) * 1099511628211ull;
		h = (h ^ b.id) * 1099511628211ull;
		h = (h ^ t.id) * 1099511628211ull;
		kgenome_thumb_decode_wide(&t, w >> 16, w & 0xffffu);
		h = (h ^ t.id) * 1099511628211ull;
	}
	return h;
}

static void *thr(void *p)
{
	pthread_barrier_wait(&go);
	*(uint64_t *)p = decode_all();
	return NULL;
}

static void threads(void)
{
	pthread_t th[NTHREADS];
	uint64_t got[NTHREADS], want;
	unsigned k, bad = 0;

	pthread_barrier_init(&go, NULL, NTHREADS);
	for (k = 0; k < NTHREADS; k++)
		pthread_create(&th[k], NULL, thr, &got[k]);
	for (k = 0; k < NTHREADS; k++)
		pthread_join(th[k], NULL);
	want = decode_all();
	for (k = 0; k < NTHREADS; k++)
		bad += got[k] != want;
	ck(bad == 0, "eight threads decoding from a standing start all get the answer of one thread");
}

int main(void)
{
	static struct armidx o;

	/* the threads first: the decoders have not been touched by this process yet */
	threads();
	armidx_build(&o);
	segments(&o);
	drift(&o);
	printf("arm_index: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
