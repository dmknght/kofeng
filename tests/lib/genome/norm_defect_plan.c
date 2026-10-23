/*
 * norm_defect_plan - N4 of the normalise audit: the endian plan keeps its spans sorted by inserting
 * into an array, and an object that lists its sections from the highest offset down made every
 * insert a move of the whole array (a 0.72 MB big-endian MIPS object: 0.56 s against 0.01 s for the
 * same sections in the other order).
 *
 * The oracle is a counter and not the clock: memmove is wrapped (UNIT_LIBS_norm_defect_plan) and the
 * bytes it was asked to move while one plan is built are compared between the two orders of the SAME
 * three note sections. The plan itself must be the same in both orders (the same spans), and the
 * descending order may cost no more than a small multiple of the ascending one's span bytes.
 */

#define _GNU_SOURCE

#include <kgenome.h>

#include "hk.h"

static uint64_t moved;

void *__real_memmove(void *d, const void *s, size_t n);
void *__wrap_memmove(void *d, const void *s, size_t n);

void *__wrap_memmove(void *d, const void *s, size_t n)
{
	moved += n;
	return __real_memmove(d, s, n);
}

#define NOTES      4000u                 /* 12-byte notes in each section */
#define NSEC       3u
#define SECLEN     (NOTES * 12u)
#define SHENT      40u
#define FILE_N     (52u + 32u + NSEC * SECLEN + (NSEC + 1u) * SHENT + 64u)

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

/* A big-endian MIPS32 object: header, one PT_LOAD over the file, NSEC SHT_NOTE sections of NOTES notes
 * (name size 0, descriptor size 0: twelve bytes each). `desc` lists the sections from the last to the first. */
static uint32_t build(uint8_t *b, int desc)
{
	const uint32_t ph = 52, data = 84, sh = data + NSEC * SECLEN;
	uint32_t i, k;

	memset(b, 0, FILE_N);
	b[0] = 0x7f; b[1] = 'E'; b[2] = 'L'; b[3] = 'F'; b[4] = 1; b[5] = 2; b[6] = 1;
	put16(b + 16, 2);
	put16(b + 18, 8);                    /* EM_MIPS */
	put32(b + 20, 1);
	put32(b + 24, 0x400000u + data);
	put32(b + 28, ph);
	put32(b + 32, sh);
	put32(b + 36, 0x1007u);
	put16(b + 40, 52);
	put16(b + 42, 32);
	put16(b + 44, 1);
	put16(b + 46, SHENT);
	put16(b + 48, NSEC + 1u);
	put16(b + 50, 0);
	put32(b + ph, 1);
	put32(b + ph + 8, 0x400000u);
	put32(b + ph + 12, 0x400000u);
	put32(b + ph + 16, sh);
	put32(b + ph + 20, sh);
	put32(b + ph + 24, 4);
	put32(b + ph + 28, 0x1000);
	for (i = 0; i < NSEC; i++) {
		uint32_t at = data + i * SECLEN;
		uint8_t *h = b + sh + (1u + (desc ? NSEC - 1u - i : i)) * SHENT;

		/* the notes: namesz 0, descsz 0, type 1 (twelve bytes, three big-endian words) */
		for (k = 0; k < NOTES; k++)
			put32(b + at + 12u * k + 8u, 1);
		put32(h + 4, 7);                 /* SHT_NOTE */
		put32(h + 12, 0x400000u + at);
		put32(h + 16, at);
		put32(h + 20, SECLEN);
		put32(h + 32, 4);
	}
	return sh + (NSEC + 1u) * SHENT;
}

struct built {
	uint64_t moved;
	uint32_t n;
	enum kgenome_status st;
	uint64_t sum;
};

static int plan_of(const uint8_t *b, uint32_t n, struct built *r)
{
	struct kgenome_elf_info info;
	struct kgenome_obj g;
	struct kgenome_endian_plan pl;
	uint32_t i;

	memset(&info, 0, sizeof info);
	memset(&g, 0, sizeof g);
	if (!kgenome_elf_image_parse(kof_buf_make(b, n), &info, &g))
		return 0;
	g.file_header = &info;
	moved = 0;
	r->st = kgenome_endian_plan_build(kof_buf_make(b, n), &g, &pl);
	r->moved = moved;
	r->n = pl.n;
	r->sum = 0;
	for (i = 0; i < pl.n; i++)
		r->sum = r->sum * 1000003u + pl.v[i].off * 31u + pl.v[i].len * 7u + pl.v[i].lay;
	kgenome_endian_plan_free(&pl);
	return 1;
}

int main(void)
{
	static uint8_t asc[FILE_N], dsc[FILE_N];
	struct built a, d;
	uint32_t na = build(asc, 0), nd = build(dsc, 1);
	const uint64_t span_bytes = (uint64_t)NSEC * NOTES * sizeof(struct kgenome_endian_span);

	CK(plan_of(asc, na, &a) && plan_of(dsc, nd, &d));
	printf("N4 ascending : %u spans, %llu bytes moved, status %d\n", a.n, (unsigned long long)a.moved, (int)a.st);
	printf("N4 descending: %u spans, %llu bytes moved, status %d (span bytes %llu)\n", d.n,
	       (unsigned long long)d.moved, (int)d.st, (unsigned long long)span_bytes);
	CK(a.st == KGENOME_OK && d.st == KGENOME_OK);
	CK(a.n >= NSEC * NOTES);                           /* every note is a span: the object does reach the loop */
	CK(a.n == d.n && a.sum == d.sum);                  /* the same plan whatever the order */
	CK(d.moved <= 16u * span_bytes);                   /* near-linear: the old insert moved ~ n^2/2 spans */
	if (hk_fails) {
		printf("norm_defect_plan: %d check(s) failed\n", hk_fails);
		return 1;
	}
	printf("norm_defect_plan: ok\n");
	return 0;
}
