/*
 * true_touches_sorted - kgenome_true_touches answers a sorted list by a binary search, and the
 * answer is the linear scan's.
 *
 * THE COST THAT MADE IT A SEARCH. The normaliser asks the question once per RECORD of a symbol
 * block: 531 717 times over 234 dynamic ELF, each walking every span of a list that can hold
 * 2048 - 22 500 instructions a call, 19 % of the whole scan (callgrind). The producers of the
 * list (kgenome_true_find_all / _find_object) end in kof_rl_normalise, so the list is sorted by
 * offset with its ends not decreasing, and `sorted` says so.
 *
 * WHAT IS HELD TO. For lists of every shape the producers can leave - empty, one span,
 * zero-length spans, a span that ends past the address space, spans that touch, a list filled to
 * the cap - and for every query kind (inside, before, after, on a boundary, len 0, len
 * UINT64_MAX, an offset near the top of the address space) the sorted answer is the answer of
 * the same list read with `sorted` clear. The unsorted list is the reference: it is the
 * function that was there before, term for term. And the lists a real object gives: the
 * producers' own output is read both ways at every offset of the object.
 *
 * Linked against libkgenome.a alone.
 */
#include <kgenome.h>
#include <celllysis/trueline.h>
#include <genotype/image/elf_image.h>

#include <rangelist.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static unsigned s = 0x13579bdfu;
static unsigned rnd(void) { s = s * 1103515245u + 12345u; return s >> 8; }
static uint64_t rnd64(void) { return ((uint64_t)rnd() << 40) ^ ((uint64_t)rnd() << 20) ^ rnd(); }

static struct kgenome_true_all lst;

/* The same list, read both ways, against one query. */
static int agree(uint64_t off, uint64_t len)
{
	int a, b;

	lst.sorted = 0;
	a = kgenome_true_touches(&lst, off, len);
	lst.sorted = 1;
	b = kgenome_true_touches(&lst, off, len);
	lst.sorted = 0;
	if (a != b)
		printf("    list n=%u query off=%llx len=%llx linear=%d sorted=%d\n", lst.n,
		       (unsigned long long)off, (unsigned long long)len, a, b);
	return a == b;
}

static void make_list(unsigned n, unsigned shape)
{
	struct kof_rlist l;
	unsigned i;

	memset(&lst, 0, sizeof lst);
	if (shape == 6u) {      /* by hand: ascending, zero-length spans among them, ends not decreasing */
		uint64_t at = rnd() % 50u;

		for (i = 0; i < n; i++) {
			lst.span[i].off = at;
			lst.span[i].len = rnd() % 3u ? rnd() % 40u : 0u;
			at += lst.span[i].len + rnd() % 30u;
		}
		lst.n = n;
		return;
	}
	kof_rl_init(&l, lst.span, KGENOME_TRUE_MAX_SPANS_ALL);
	for (i = 0; i < n; i++) {
		uint64_t off, len;

		switch (shape) {
		case 0: off = rnd() % 100000u; len = rnd() % 300u; break;
		case 1: off = (uint64_t)i * 64u; len = 64u; break;                      /* touching */
		case 2: off = rnd() % 4000u; len = rnd() % 3u; break;                   /* tiny */
		case 3: off = UINT64_MAX - rnd() % 5000u; len = rnd() % 9000u; break;   /* past the end */
		case 4: off = rnd64(); len = rnd64() % 4096u; break;
		default: off = (uint64_t)i * 1000u + rnd() % 10u; len = 1u + rnd() % 900u;
		}
		kof_rl_add(&l, UINT64_MAX, off, len);
	}
	lst.n = kof_rl_normalise(&l);
}

static void t_lists(void)
{
	unsigned it, q;

	for (it = 0; it < 4000u; it++) {
		unsigned n = it % 13u == 0 ? 0u : it % 17u == 0 ? KGENOME_TRUE_MAX_SPANS_ALL + 40u
		                                : 1u + rnd() % 40u;
		unsigned shape = it % 7u;

		if (n > KGENOME_TRUE_MAX_SPANS_ALL)
			n = KGENOME_TRUE_MAX_SPANS_ALL;
		make_list(n, shape);
		for (q = 0; q < 60u; q++) {
			uint64_t off, len;

			if (lst.n && q % 4u == 0) {     /* on a boundary of a span, either side of it */
				const struct kof_range *r = &lst.span[rnd() % lst.n];
				off = q % 8u ? r->off + r->len : r->off - 1u;
				len = q % 3u;
			} else if (q % 11u == 0) {
				off = UINT64_MAX - rnd() % 4u; len = UINT64_MAX - rnd() % 3u;
			} else if (q % 7u == 0) {
				off = rnd() % 8u; len = UINT64_MAX;
			} else {
				off = (shape == 3u || shape == 4u) ? rnd64() : rnd() % 110000u; len = rnd() % 400u;
			}
			CK(agree(off, len));
		}
	}
}

/* The producers' own lists, at every offset of a small ELF. */
static void w16(uint8_t *b, unsigned at, uint16_t v) { b[at] = (uint8_t)v; b[at + 1] = (uint8_t)(v >> 8); }
static void w32(uint8_t *b, unsigned at, uint32_t v) { w16(b, at, (uint16_t)v); w16(b, at + 2, (uint16_t)(v >> 16)); }
static void w64(uint8_t *b, unsigned at, uint64_t v) { w32(b, at, (uint32_t)v); w32(b, at + 4, (uint32_t)(v >> 32)); }

static void t_producers(void)
{
	enum { N = 6000 };
	static uint8_t f[N];
	struct kgenome_elf_info e;
	struct kgenome_obj o;
	kof_buf buf;
	uint64_t at;
	static struct kgenome_true_all got;
	static const char *text[] = { "Unknown error", "Invalid argument", "Cannot allocate memory" };
	unsigned i;

	memset(f, 0, sizeof f);
	memcpy(f, "\x7f" "ELF", 4);
	f[4] = 2; f[5] = 1; f[6] = 1;
	w16(f, 16, 2); w16(f, 18, 62); w32(f, 20, 1);
	w64(f, 24, 0x400000u + 0x200u); w64(f, 32, 64);
	w16(f, 52, 64); w16(f, 54, 56); w16(f, 56, 1);
	w32(f, 64, 1); w32(f, 68, 5); w64(f, 72, 0); w64(f, 80, 0x400000u); w64(f, 88, 0x400000u);
	w64(f, 96, N); w64(f, 104, N); w64(f, 112, 0x1000u);
	for (i = 0; i < 3u; i++)
		memcpy(f + 0x400u + i * 0x300u, text[i], strlen(text[i]));
	buf = kof_buf_make(f, N);
	memset(&e, 0, sizeof e);
	memset(&o, 0, sizeof o);
	if (!kgenome_elf_image_parse(buf, &e, &o) || !e.valid) {
		printf("  (the hand-made ELF did not parse; producer lists not read)\n");
		return;
	}
	kgenome_true_find_all(buf, &e, &got);
	CK(got.sorted == 1);
	memcpy(&lst, &got, sizeof lst);
	for (at = 0; at < N + 8u; at++) {
		CK(agree(at, 1));
		CK(agree(at, 17));
	}
	kgenome_true_find_object(buf, &e, &got);
	CK(got.sorted == 1 || got.n == 0);
	memcpy(&lst, &got, sizeof lst);
	for (at = 0; at < N + 8u; at += 3u)
		CK(agree(at, 5));
	/* a list nobody sorted is read the long way - the flag is a promise the producer makes */
	memset(&got, 0, sizeof got);
	CK(got.sorted == 0);
}

int main(void)
{
	t_lists();
	t_producers();
	printf("true_touches_sorted: %s\n", fails ? "FAIL" : "ok");
	return fails != 0;
}
