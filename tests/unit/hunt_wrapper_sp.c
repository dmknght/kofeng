/*
 * hunt_wrapper_sp - the wrapper analysis's stack counter on a hostile frame.
 *
 * FOUND BY running the engine under UBSan over mutated stripped i386 binaries
 * (a mutation of an immediate in a function prologue). The counter that follows
 * `esp` through a candidate wrapper is 32 bits and the immediate of `sub esp, imm32`
 * is the sample's: two of them near 0x7fffffff overflowed it (signed overflow,
 * undefined), and `add esp, 0x80000000` negated INT_MIN. Neither is a frame real code
 * has, so the answer to give is "the same as for any frame that big", not a crash
 * under a sanitiser and not a different answer from build to build.
 *
 * What is asserted: the scan finishes, says OK or a stated limit, and gives the same
 * answer twice. The overflow itself is seen by `make unit-asan` (halting UBSan); a
 * build without it passes this test before the fix too, because the wrap is benign
 * there - that is why the sanitiser is the evidence and this is the regression guard.
 */

#include "caps_fix.h"

static unsigned char view[1u << 22];
static uint8_t img[1u << 22];
static uint8_t code[1u << 16];

/* uClibc's socketcall wrapper, as diag_wrapper_limits.c has it */
static const uint8_t body[] = {
	0x83, 0xec, 0x08, 0x8b, 0x54, 0x24, 0x10, 0x8b, 0x4c, 0x24, 0x14, 0x87, 0xd3,
	0xb8, 0x66, 0x00, 0x00, 0x00, 0xcd, 0x80, 0x87, 0xd3, 0x83, 0xc4, 0x08, 0x5b, 0xc3
};

static uint32_t nodes(const uint8_t *pre, unsigned pre_n, unsigned *opaque, enum kgenome_status *st)
{
	struct kof_obj_ctx ctx;
	struct kgenome_diag_scan *s;
	unsigned n = 28, i;
	uint32_t c;
	uint64_t len;

	memset(code, 0x90, 28);
	code[0] = 0x50; code[1] = 0x6a; code[2] = 3;
	code[3] = 0xe8; put32(code, 4, 28u - 8u);
	code[8] = 0x83; code[9] = 0xc4; code[10] = 8; code[11] = 0xc3;
	code[n++] = 0x53;                       /* push ebx */
	if (pre_n)
		memcpy(code + n, pre, pre_n);
	n += pre_n;
	memcpy(code + n, body, sizeof body);
	n += (unsigned)sizeof body;
	memset(view, 0, sizeof view);
	len = cf_elf32(img, sizeof img, code, n);
	s = cf_scan(img, len, KGENOME_DIAG_RUN_SYSCALL, &ctx, view);
	c = cf_count_cap(s, KGENOME_NUCLEO_NET_CONNECT);
	*st = kgenome_diag_scan_status(s);
	*opaque = 0;
	for (i = 0; s && i < kgenome_diag_scan_count(s); i++)
		*opaque += (kgenome_diag_scan_at(s, i)->bits & KGENOME_DIAG_H_OPAQUE) != 0;
	kgenome_diag_scan_free(s);
	return c;
}

int main(void)
{
	/* sub esp,0x7fffffff x3; add esp,0x80000000; sub esp,0x80000000 */
	static const uint8_t sub3[] = {
		0x81, 0xec, 0xff, 0xff, 0xff, 0x7f, 0x81, 0xec, 0xff, 0xff, 0xff, 0x7f,
		0x81, 0xec, 0xff, 0xff, 0xff, 0x7f
	};
	static const uint8_t addmin[] = { 0x81, 0xc4, 0x00, 0x00, 0x00, 0x80 };
	static const uint8_t mix[] = {
		0x81, 0xc4, 0x00, 0x00, 0x00, 0x80, 0x81, 0xc4, 0x00, 0x00, 0x00, 0x80,
		0x81, 0xec, 0x00, 0x00, 0x00, 0x80, 0x81, 0xec, 0x00, 0x00, 0x00, 0x80
	};
	static const struct { const uint8_t *p; unsigned n; } cases[] = {
		{ NULL, 0 }, { sub3, sizeof sub3 }, { addmin, sizeof addmin }, { mix, sizeof mix }
	};
	unsigned k;

	for (k = 0; k < sizeof cases / sizeof cases[0]; k++) {
		unsigned op1, op2;
		enum kgenome_status s1, s2;
		uint32_t a = nodes(cases[k].p, cases[k].n, &op1, &s1);
		uint32_t b = nodes(cases[k].p, cases[k].n, &op2, &s2);

		CK(a == b && op1 == op2 && s1 == s2);
		CK(s1 == KGENOME_OK || s1 == KGENOME_TRUNCATED);
	}
	/* The ordinary wrapper still resolves: the clamp did not move a normal frame. */
	{
		unsigned op;
		enum kgenome_status st;

		CK(nodes(NULL, 0, &op, &st) == 1 && op == 0 && st == KGENOME_OK);
	}
	if (fails)
		return 1;
	printf("hunt_wrapper_sp: ok\n");
	return 0;
}
