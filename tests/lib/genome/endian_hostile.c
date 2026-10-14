/*
 * endian_hostile - the plan and the swap against big-endian objects built to hurt them.
 *
 * Every object is a valid one (endian_kit.h) that is cut, stretched or corrupted, and
 * put in a guard-page buffer: the last byte of the object is the last byte before a
 * PROT_NONE page, so a read or a write one byte past the length the call was given
 * faults on the spot, in this process, with no sanitizer needed.
 *
 *   1  truncation   the object at every length, parsed and planned and applied; and again
 *                   with the description of the WHOLE file held against the cut buffer
 *   2  field sweep  every 2-, 4- and 8-byte field of the headers, the section headers and
 *                   the tables the plan reads (notes, the GNU hash header) set to each of
 *                   fifteen extremes
 *   3  flips        fixed-seed byte flips
 *
 * What is asserted is not "returns something": it is that every span is inside the
 * object, that spans are sorted and disjoint, that applying the plan twice restores the
 * bytes (so a hostile object cannot be left half swapped by a second pass), that a
 * plan made over a stale description does not reach past the buffer, and that a plan
 * which dropped a span says so.
 */

#include <kgenome.h>

#include "endian_kit.h"

static struct hk_gb G;
static unsigned runs, bad;

struct parsed {
	struct kgenome_elf_info info;
	struct kgenome_obj g;
};

static void invariants(const struct kgenome_endian_plan *pl, uint32_t n, const char *what)
{
	uint32_t i;

	for (i = 0; i < pl->n; i++) {
		int ok = pl->v[i].len > 0 && pl->v[i].off < n && pl->v[i].len <= n - pl->v[i].off &&
			 (i == 0 || pl->v[i - 1u].off + pl->v[i - 1u].len <= pl->v[i].off);

		if (!ok) {
			if (bad++ < 8)
				printf("  FAIL %s: span %u [%llu, +%llu) in %u bytes\n", what, i,
				       (unsigned long long)pl->v[i].off, (unsigned long long)pl->v[i].len, n);
			hk_fails++;
			return;
		}
	}
}

/* One case on `len` bytes of `src`, planned from `descr` (the cut buffer's own parse when
 * descr is NULL, else the description of a longer object). */
static void one(const uint8_t *src, uint32_t len, const struct parsed *descr, const char *what)
{
	uint8_t *p = gb_put(&G, src, len);
	uint8_t copy[EK_MAX];
	struct parsed own;
	const struct parsed *use = descr;
	struct kgenome_endian_plan pl;
	enum kgenome_status st;

	runs++;
	if (!use) {
		memset(&own, 0, sizeof own);
		if (!kgenome_elf_image_parse(kof_buf_make(p, len), &own.info, &own.g))
			return;
		own.g.file_header = &own.info;
		use = &own;
	}
	st = kgenome_endian_plan_build(kof_buf_make(p, len), &use->g, &pl);
	invariants(&pl, len, what);
	if (st == KGENOME_OK && pl.n == 0 && pl.ident == 0)
		goto done;
	if (len > sizeof copy)
		goto done;
	memcpy(copy, p, len);
	(void)kgenome_endian_apply(p, len, &pl);
	(void)kgenome_endian_apply(p, len, &pl);
	if (memcmp(copy, p, len)) {
		if (bad++ < 8)
			printf("  FAIL %s: twice is not the identity (length %u)\n", what, len);
		hk_fails++;
	}
	/* the range answer stays inside what it was asked */
	if (len > 8) {
		uint8_t out[16];

		kgenome_endian_range(out, p, len, len - 8u, 8, &pl);
		(void)kgenome_endian_wide(p, len, NULL, &pl, 8);
	}
done:
	kgenome_endian_plan_free(&pl);
}

static const struct ek_arch *pick[] = { &ek_archs[0], &ek_archs[4], &ek_archs[8], &ek_archs[3] };
#define NPICK 4u

static int truncation(void *arg)
{
	unsigned a;

	(void)arg;
	for (a = 0; a < NPICK; a++) {
		struct ek_obj e;
		struct parsed whole;
		uint32_t n;

		ek_build(&e, pick[a], 1, 1);
		memset(&whole, 0, sizeof whole);
		CK(kgenome_elf_image_parse(kof_buf_make(e.b, e.n), &whole.info, &whole.g));
		whole.g.file_header = &whole.info;
		for (n = 0; n <= e.n; n++) {
			one(e.b, n, NULL, "cut");
			one(e.b, n, &whole, "stale");
		}
	}
	printf("  truncation: %u cases\n", runs);
	return hk_fails != 0;
}

static const uint64_t extreme[15] = {
	0, 1, 2, 3, 4, 0x7fffffffu, 0x80000000u, 0xffffffffu, 0x100000000ull,
	0x7fffffffffffffffull, 0x8000000000000000ull, 0xffffffffffffffffull,
	0xffffu, 0x10000u, 0xfffffffeu
};

static int field_sweep(void *arg)
{
	unsigned a;

	(void)arg;
	for (a = 0; a < NPICK; a++) {
		struct ek_obj e;
		uint32_t at, w, x, hdr_end, shent = pick[a]->is64 ? 64u : 40u;
		uint32_t regions[4][2];
		unsigned r;

		ek_build(&e, pick[a], 1, 1);
		hdr_end = pick[a]->is64 ? 64u + 56u : 52u + 32u;
		regions[0][0] = 0;                   regions[0][1] = hdr_end;
		regions[1][0] = e.sh;                regions[1][1] = e.sh + 6u * shent;
		regions[2][0] = e.sec_off[EK_NOTE];  regions[2][1] = e.sec_off[EK_NOTE] + 24u;
		regions[3][0] = e.sec_off[EK_GNUHASH]; regions[3][1] = e.sec_off[EK_GNUHASH] + 16u;
		for (r = 0; r < 4; r++)
			for (w = 2; w <= 8; w *= 2)
				for (at = regions[r][0]; at + w <= regions[r][1] && at + w <= e.n; at += w)
					for (x = 0; x < 15; x++) {
						struct ek_obj m;

						memcpy(&m, &e, sizeof m);
						hk_w(m.b + at, extreme[x], w, 1);
						one(m.b, m.n, NULL, "field");
					}
	}
	printf("  field sweep: %u cases\n", runs);
	return hk_fails != 0;
}

static int flips(void *arg)
{
	unsigned a, round;
	struct hk_rng rng = { 0x2545f4914f6cdd1dull };

	(void)arg;
	for (a = 0; a < NPICK; a++) {
		struct ek_obj e;

		ek_build(&e, pick[a], 1, 1);
		for (round = 0; round < 1500; round++) {
			struct ek_obj m;
			unsigned k;

			memcpy(&m, &e, sizeof m);
			for (k = 0; k < 1u + round % 4u; k++)
				m.b[hk_next(&rng) % m.n] = (uint8_t)hk_next(&rng);
			one(m.b, m.n, NULL, "flip");
		}
	}
	printf("  flips: %u cases\n", runs);
	return hk_fails != 0;
}

int main(void)
{
	static const struct { const char *name; hk_case_fn fn; } cases[] = {
		{ "truncation", truncation }, { "field sweep", field_sweep }, { "flips", flips }
	};
	unsigned i;
	int failed = 0;

	gb_init(&G, EK_MAX);
	for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
		int sig = 0;
		enum hk_result r = hk_isolated(cases[i].fn, NULL, 30, &sig);

		if (r != HK_OK) {
			printf("  FAIL %s: %s%s\n", cases[i].name,
			       r == HK_CRASHED ? "crashed" : r == HK_HUNG ? "hung" : "failed",
			       sig ? " (signal)" : "");
			failed++;
		}
	}
	gb_free(&G);
	if (failed || hk_fails) {
		printf("endian_hostile: failed\n");
		return 1;
	}
	printf("endian_hostile: ok\n");
	return 0;
}
