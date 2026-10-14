/*
 * endian_wide - UTF-16BE text made UTF-16LE, and nothing else.
 *
 * The rule (endian.h): a run of 8 or more aligned units (00, printable ASCII) is a
 * big-endian wide string, and each of its pairs is swapped; a unit starting at an odd
 * offset is not looked at, which is what lets a little-endian string alone, and what
 * makes the pass idempotent. What is checked:
 *
 *   1  twin           the BE object's wide string equals the LE twin's after the pass
 *   2  idempotent     a second pass finds nothing
 *   3  left alone     UTF-16LE, ASCII, an odd-aligned BE string, a run under the
 *                     minimum, a run broken by a non-ASCII unit
 *   4  boundaries     a kept byte, a plan span and the end of the buffer stop a run
 *   5  reference      random buffers with injected runs, against a plain re-statement of
 *                     the rule written without the walk's cursor
 *   6  guard page     every length 0..N under a PROT_NONE page: no read past the end
 */

#include <kgenome.h>

#include "endian_kit.h"

#define MIN 8u

static void twin(void)
{
	unsigned k;

	for (k = 0; k < EK_NARCH; k++) {
		struct ek_obj be, le;
		struct kgenome_endian_plan pl;
		struct parsed_t { struct kgenome_elf_info info; struct kgenome_obj g; } p;

		ek_build(&be, &ek_archs[k], 1, ek_archs[k].unit != 0);
		ek_build(&le, &ek_archs[k], 0, 1);
		memset(&p, 0, sizeof p);
		CK(kgenome_elf_image_parse(kof_buf_make(be.b, be.n), &p.info, &p.g));
		p.g.file_header = &p.info;
		CK(kgenome_endian_plan_build(kof_buf_make(be.b, be.n), &p.g, &pl) == KGENOME_OK);
		(void)kgenome_endian_apply(be.b, be.n, &pl);
		CK(kgenome_endian_wide(be.b, be.n, NULL, &pl, MIN) == 1);
		CK(memcmp(be.b + be.wide_at, le.b + le.wide_at, 2u * be.wide_chars) == 0);
		CK(kgenome_endian_wide(be.b, be.n, NULL, &pl, MIN) == 0);       /* idempotent */
		kgenome_endian_plan_free(&pl);
	}
}

static void put_be(uint8_t *p, const char *s)
{
	unsigned i;

	for (i = 0; s[i]; i++) {
		p[2u * i] = 0;
		p[2u * i + 1u] = (uint8_t)s[i];
	}
}

static void left_alone(void)
{
	uint8_t b[256], c[256];
	unsigned i;

	/* little-endian text at an even offset and at an odd one */
	memset(b, 0xee, sizeof b);
	for (i = 0; i < 12; i++) {
		b[16 + 2u * i] = (uint8_t)('a' + i);
		b[16 + 2u * i + 1u] = 0;
		b[101 + 2u * i] = (uint8_t)('a' + i);
		b[101 + 2u * i + 1u] = 0;
	}
	memcpy(c, b, sizeof b);
	CK(kgenome_endian_wide(b, sizeof b, NULL, NULL, MIN) == 0);
	CK(memcmp(b, c, sizeof b) == 0);

	/* a big-endian string right behind a printable byte: indistinguishable from the
	 * little-endian text above it, and left alone */
	memset(b, 0xee, sizeof b);
	b[63] = 'x';
	put_be(b + 64, "abcdefghijkl");
	memcpy(c, b, sizeof b);
	CK(kgenome_endian_wide(b, sizeof b, NULL, NULL, MIN) == 0);
	CK(memcmp(b, c, sizeof b) == 0);

	/* a big-endian string that starts at an odd offset: not seen */
	memset(b, 0xee, sizeof b);
	put_be(b + 33, "abcdefghijkl");
	memcpy(c, b, sizeof b);
	CK(kgenome_endian_wide(b, sizeof b, NULL, NULL, MIN) == 0);
	CK(memcmp(b, c, sizeof b) == 0);

	/* ASCII, and a string one unit short of the minimum, and one the non-ASCII breaks */
	memset(b, 0xee, sizeof b);
	memcpy(b + 8, "just some ascii text here", 25);
	put_be(b + 64, "1234567");
	put_be(b + 100, "abcdefgh");
	b[100 + 9] = 0xe9;                       /* the fifth unit is (00, e9): not ASCII */
	b[100 + 8] = 0;
	memcpy(c, b, sizeof b);
	CK(kgenome_endian_wide(b, sizeof b, NULL, NULL, MIN) == 0);
	CK(memcmp(b, c, sizeof b) == 0);

	/* exactly the minimum: swapped */
	memset(b, 0xee, sizeof b);
	put_be(b + 64, "12345678");
	CK(kgenome_endian_wide(b, sizeof b, NULL, NULL, MIN) == 1);
	CK(b[64] == '1' && b[65] == 0 && b[78] == '8' && b[79] == 0);
}

static void boundaries(void)
{
	uint8_t b[256], keep[32];
	struct kgenome_endian_span sp = { 64, 8, KGENOME_ENDIAN_L_W4 };
	struct kgenome_endian_plan pl = { .v = &sp, .n = 1, .cap = 1 };

	/* a kept byte in the middle of a 16-unit run: two runs of 8 and 7 around it */
	memset(b, 0xee, sizeof b);
	put_be(b + 32, "abcdefghijklmnop");
	memset(keep, 0, sizeof keep);
	keep[(32 + 17) >> 3] |= (uint8_t)(1u << ((32 + 17) & 7));       /* the 9th unit's low byte */
	CK(kgenome_endian_wide(b, sizeof b, keep, NULL, MIN) == 1);     /* the first 8 only */
	CK(b[32] == 'a' && b[33] == 0 && b[46] == 'h' && b[47] == 0);
	CK(b[48] == 0 && b[49] == 'i');                                 /* kept: still big-endian */

	/* a plan span claims part of the run: the part before it is a run of 4, below the
	 * minimum, so nothing moves */
	memset(b, 0xee, sizeof b);
	put_be(b + 56, "abcdefghijkl");
	CK(kgenome_endian_wide(b, sizeof b, NULL, &pl, MIN) == 0);
	CK(b[56] == 0 && b[57] == 'a');

	/* the end of the buffer ends the run, and the last unit is whole */
	memset(b, 0xee, sizeof b);
	put_be(b + 256 - 16, "abcdefgh");
	CK(kgenome_endian_wide(b, sizeof b, NULL, NULL, MIN) == 1);
	CK(b[255] == 0 && b[254] == 'h');
	/* an odd length: the last byte alone is not a unit */
	memset(b, 0xee, sizeof b);
	put_be(b + 256 - 17, "abcdefgh");
	CK(kgenome_endian_wide(b, 255, NULL, NULL, MIN) == 0);          /* misaligned by one */
}

/* The rule restated plainly: for every even i, count the units from i; a run of at
 * least MIN, none of whose bytes is kept or inside a span, is swapped. */
static int in_span(const struct kgenome_endian_plan *pl, uint64_t i)
{
	uint32_t k;

	for (k = 0; pl && k < pl->n; k++)
		if (i >= pl->v[k].off && i < pl->v[k].off + pl->v[k].len)
			return 1;
	return 0;
}

static int kept_at(const uint8_t *keep, uint64_t i)
{
	return keep && (keep[i >> 3] >> (i & 7u)) & 1u;
}

static int ok_unit(const uint8_t *b, uint64_t n, const uint8_t *keep,
		   const struct kgenome_endian_plan *pl, uint64_t i)
{
	return i + 1u < n && b[i] == 0 && (uint8_t)(b[i + 1u] - 0x20u) < 0x5fu &&
	       !kept_at(keep, i) && !kept_at(keep, i + 1u) && !in_span(pl, i) && !in_span(pl, i + 1u);
}

static uint32_t reference(uint8_t *b, uint64_t n, const uint8_t *keep,
			  const struct kgenome_endian_plan *pl)
{
	uint64_t i = 0, k, q;
	uint32_t runs = 0;

	while (i + 1u < n) {
		if (!ok_unit(b, n, keep, pl, i) || (i && (uint8_t)(b[i - 1u] - 0x20u) < 0x5fu)) {
			i += 2;
			continue;
		}
		for (k = i; ok_unit(b, n, keep, pl, k); k += 2)
			;
		if ((k - i) / 2u >= MIN) {
			for (q = i; q < k; q += 2) {
				uint8_t t = b[q];

				b[q] = b[q + 1u];
				b[q + 1u] = t;
			}
			runs++;
		}
		i = k;
	}
	return runs;
}

static void against_reference(void)
{
	struct hk_rng r = { 0x9e3779b97f4a7c15ull };
	unsigned round;

	for (round = 0; round < 400; round++) {
		uint8_t a[600], b[600], keep[75];
		struct kgenome_endian_span sp[2];
		struct kgenome_endian_plan pl = { .v = sp, .n = 0, .cap = 2 };
		uint64_t n = 64u + hk_next(&r) % 536u;
		uint32_t i, ra, rb;

		for (i = 0; i < n; i++)
			a[i] = (hk_next(&r) & 3u) == 0 ? (uint8_t)hk_next(&r) : 0;
		/* injected runs of random length, at random offsets */
		for (i = 0; i < 6; i++) {
			uint64_t at = hk_next(&r) % (n - 40u), len = 2u * (4u + hk_next(&r) % 14u), j;

			for (j = 0; j < len && at + j + 1u < n; j += 2) {
				a[at + j] = 0;
				a[at + j + 1u] = (uint8_t)(0x20 + hk_next(&r) % 0x5f);
			}
		}
		memset(keep, 0, sizeof keep);
		for (i = 0; i < 4 && (round & 1u); i++) {
			uint64_t at = hk_next(&r) % n;

			keep[at >> 3] |= (uint8_t)(1u << (at & 7u));
		}
		if (round & 2u) {
			sp[0].off = hk_next(&r) % n; sp[0].len = 4; sp[0].lay = KGENOME_ENDIAN_L_W4;
			if (sp[0].off + 4u > n)
				sp[0].off = n - 4u;
			pl.n = 1;
		} else {
			pl.n = 0;
		}
		memcpy(b, a, n);
		ra = kgenome_endian_wide(a, n, (round & 1u) ? keep : NULL, pl.n ? &pl : NULL, MIN);
		rb = reference(b, n, (round & 1u) ? keep : NULL, pl.n ? &pl : NULL);
		if (ra != rb || memcmp(a, b, n)) {
			printf("  FAIL round %u: %u runs against the reference's %u\n", round, ra, rb);
			hk_fails++;
			return;
		}
	}
}

static void guard_page(void)
{
	struct hk_gb g;
	uint8_t src[300];
	uint32_t n;

	memset(src, 0xee, sizeof src);
	put_be(src + 40, "abcdefghijklmnopqrstuvwx");
	put_be(src + 120, "ABCDEFGHIJKL");
	gb_init(&g, sizeof src);
	for (n = 0; n <= sizeof src; n++) {
		uint8_t *p = gb_put(&g, src, n);
		uint8_t keep[40];

		memset(keep, 0, sizeof keep);
		(void)kgenome_endian_wide(p, n, NULL, NULL, MIN);
		memcpy(p, src, n);
		(void)kgenome_endian_wide(p, n, keep, NULL, MIN);
	}
	gb_free(&g);
	CK(1);
}

int main(void)
{
	twin();
	left_alone();
	boundaries();
	against_reference();
	guard_page();
	if (hk_fails) {
		printf("endian_wide: %d failure(s)\n", hk_fails);
		return 1;
	}
	printf("endian_wide: ok\n");
	return 0;
}
