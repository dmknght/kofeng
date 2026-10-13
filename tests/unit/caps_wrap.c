/*
 * caps_wrap - limits of the wrapper analysis (diag_wrap.c): a syscall whose
 * number or argument is the CALLER'S, resolved at the call sites. Evidence just
 * INSIDE and just OUTSIDE each limit.
 *
 * WHAT THIS CATCHES. All of these were a MISS on a static, stripped binary
 * whose libc wraps its syscalls (the corpus of IoT bots the pass was built
 * for), where the wrapper is not the 33-byte glibc one the constants were
 * measured on:
 *
 *   W_SPAN (256)       was a wrapper whose entry is more than 256 bytes before its
 *                      kernel entry: not summarised. Now the span is the
 *                      function's own length (to the next call target, at least
 *                      256), bounded by a TOTAL step budget of summarise() -
 *                      max(4096, 8 x span) - because lifting the span with the
 *                      per-path numbers was measured to hang. The 240-byte
 *                      wrapper is a node; the 3000-byte one is still stopped, by
 *                      W_BODY below, and says so (KGENOME_TRUNCATED).
 *   W_BODY (was 48)    a wrapper of more than 48 instructions on one path was not
 *                      summarised, however small the object. Now a path may read as
 *                      many instructions as the function has bytes (its span, at
 *                      least 256), the whole summary is bounded by its step
 *                      budget, and a cut is still said (KGENOME_TRUNCATED).
 *   W_VARIANTS (was 4) a wrapper that branches kept four summaries; the real one
 *                      could be the fifth. Now max(4, span / 8) up to 64, the table
 *                      held once; a variant past it is still said.
 *   W_PENDING (was 6)  six forward branches could be queued; the seventh was not
 *                      AND ended the path it was on. Now max(6, span / 8), grown on
 *                      demand and charged to the scan's ledger; an arm still not
 *                      queued is said.
 *   nesting (2 levels) was: a wrapper of a wrapper of a wrapper of the syscall
 *                      is summarised, a fourth was not. Now iterated to a
 *                      fixpoint, bounded by the step budget and not by a depth
 *                      (it was a fixed 64); the budget running out is said.
 *   W_LEVELS_MAX_TGT   was: past 20000 call targets the levels were not searched
 *                      AT ALL. Gone - the cost per level is linear.
 *
 * WHAT IS REPORTED HONESTLY TODAY, as a normal check: the site the wrapper
 * analysis could not explain stays in the graph as an OPAQUE node, so the loss
 * is visible at node level (kgenome_diag_hit.bits) even though it is not at the
 * verdict level - see flag_readers.c.
 */

#include "caps_fix.h"
#include "known_miss.h"

static unsigned char view[1u << 22];
static uint8_t img[1u << 22];
static uint8_t code[1u << 21];

/* ---- i386: uClibc's socketcall wrapper, padded ------------------------------- */

static const uint8_t wrap32[] = {
	0x83, 0xec, 0x08,                   /* sub esp,8           */
	0x8b, 0x54, 0x24, 0x10,             /* mov edx,[esp+0x10]  */
	0x8b, 0x4c, 0x24, 0x14,             /* mov ecx,[esp+0x14]  */
	0x87, 0xd3,                         /* xchg ebx,edx        */
	0xb8, 0x66, 0x00, 0x00, 0x00,       /* mov eax,0x66        */
	0xcd, 0x80,                         /* int 0x80            */
	0x87, 0xd3,                         /* xchg ebx,edx        */
	0x83, 0xc4, 0x08,                   /* add esp,8           */
	0x5b,                               /* pop ebx             */
	0xc3                                /* ret                 */
};

/*
 * main: push eax; push 3; call w; add esp,8; ret      (connect = sub-call 3)
 * w:    push ebx; <pad>; the body above.
 * `kind` 0 pads with 6-byte `lea esi,[esi]` (bytes), 1 with 1-byte nops
 * (instructions).
 */
static enum kgenome_status last_status;

static uint32_t connect_nodes(unsigned pad, int kind, unsigned *opaque)
{
	struct kof_obj_ctx ctx;
	struct kgenome_diag_scan *s;
	unsigned n = 28, k, i;
	uint32_t c;
	uint64_t len;

	memset(code, 0x90, 28);
	code[0] = 0x50; code[1] = 0x6a; code[2] = 3;
	code[3] = 0xe8; put32(code, 4, 28u - 8u);
	code[8] = 0x83; code[9] = 0xc4; code[10] = 8; code[11] = 0xc3;
	code[n++] = 0x53;
	if (kind == 0)
		for (k = 0; k < pad / 6u; k++) {
			code[n] = 0x8d; code[n + 1] = 0xb6; put32(code, n + 2, 0);
			n += 6;
		}
	else
		for (k = 0; k < pad; k++)
			code[n++] = 0x90;
	n = cf_emit(code, n, wrap32, sizeof wrap32);
	memset(view, 0, sizeof view);
	len = cf_elf32(img, sizeof img, code, n);
	s = cf_scan(img, len, KGENOME_DIAG_RUN_SYSCALL, &ctx, view);
	c = cf_count_cap(s, KGENOME_NUCLEO_NET_CONNECT);
	last_status = kgenome_diag_scan_status(s);
	if (opaque) {
		*opaque = 0;
		for (i = 0; s && i < kgenome_diag_scan_count(s); i++)
			*opaque += (kgenome_diag_scan_at(s, i)->bits & KGENOME_DIAG_H_OPAQUE) != 0;
	}
	kgenome_diag_scan_free(s);
	return c;
}

static void span_and_body(void)
{
	unsigned op;

	/* inside: the wrapper starts ~190 bytes before its int 0x80 */
	CK(connect_nodes(0, 0, &op) == 1 && op == 0);
	CK(last_status == KGENOME_OK);
	CK(connect_nodes(180, 0, &op) == 1 && op == 0);
	/* ~260 bytes: past the old fixed 256 - the span is the function's now, so the
	 * node for the call that pushed 3 IS made (this was W_SPAN). */
	CK(connect_nodes(240, 0, &op) == 1 && op == 0);
	CK(last_status == KGENOME_OK);
	/* 3000 bytes of padding is 500 instructions: far past the old 48 an
	 * instruction path could read (W_BODY). The bound follows the function's span
	 * now, so the node for the call that pushed 3 IS made and nothing was cut. */
	CK(connect_nodes(3000, 0, &op) == 1 && op == 0);
	CK(last_status == KGENOME_OK);

	/* instruction count: 9 instructions of the wrapper itself + pad */
	CK(connect_nodes(30, 1, &op) == 1 && op == 0);
	CK(last_status == KGENOME_OK);
	CK(connect_nodes(44, 1, &op) == 1 && op == 0);
	CK(last_status == KGENOME_OK);
	CK(connect_nodes(400, 1, &op) == 1 && op == 0);
	CK(last_status == KGENOME_OK);
}

/* ---- x86-64: syscall(nr, a1..a5) with branches and chains -------------------- */

/* rax=rdi; rdi=rsi; rsi=rdx; rdx=rcx; r10=r8; r8=r9; syscall; ret */
static const uint8_t right_arm[] = {
	0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0x48, 0x89, 0xca,
	0x4d, 0x89, 0xc2, 0x4d, 0x89, 0xc8, 0x0f, 0x05, 0xc3
};
/* rax=rdi; syscall; ret: a different, wrong, reading of the same call */
static const uint8_t junk_arm[] = { 0x48, 0x89, 0xf8, 0x0f, 0x05, 0xc3 };

/* The call site: mmap(0, 0x1000, 7, 0x22) through the generic wrapper, then
 * read into the result and jump into it. 41 bytes; the call's rel32 at +30. */
static const uint8_t caller[] = {
	0xbf, 9, 0, 0, 0,                   /* mov edi,9   nr        */
	0xbe, 0, 0, 0, 0,                   /* mov esi,0   addr      */
	0xba, 0, 0x10, 0, 0,                /* mov edx,0x1000 len    */
	0xb9, 7, 0, 0, 0,                   /* mov ecx,7   prot      */
	0x41, 0xb8, 0x22, 0, 0, 0,          /* mov r8d,0x22          */
	0x45, 0x31, 0xc9,                   /* xor r9d,r9d           */
	0xe8, 0, 0, 0, 0,                   /* call wrapper          */
	0x48, 0x89, 0xc6, 0x31, 0xff, 0xba, 0, 0x10, 0, 0, 0x31, 0xc0, 0x0f, 0x05,
	0xff, 0xe6
};
#define CALL_AT 29u

/*
 * Is the allocation at the call site an ALLOC_EXEC node: the wrapper's summary
 * evaluated at the call, with prot = 7 from the caller. Used instead of the
 * whole rwx_exec tree, which needs the link from the call's RESULT to the read
 * and is a second question.
 */
static enum kgenome_status alloc_status;

static unsigned alloc_exec(unsigned n)
{
	struct kof_obj_ctx ctx;
	struct kgenome_diag_scan *s;
	unsigned c;
	uint64_t len;

	memset(view, 0, sizeof view);
	len = cf_elf64(img, sizeof img, code, n);
	s = cf_scan(img, len, KGENOME_DIAG_RUN_SYSCALL, &ctx, view);
	c = cf_count_cap(s, KGENOME_NUCLEO_ALLOC_EXEC);
	alloc_status = kgenome_diag_scan_status(s);
	kgenome_diag_scan_free(s);
	return c;
}

/*
 * A wrapper of `jccs` forward branches (cmp r9d,k ; je arm_k - r9 is 0 at the
 * call so the branches decide nothing) whose arms are `arm_of(k)`. The
 * fall-through is walked first, then the queued arms LIFO, so the arm of the
 * FIRST branch is the last to be reached. `right` is the index of the arm that
 * maps the arguments correctly.
 */
static unsigned branchy(unsigned jccs, unsigned right, int ret_arms)
{
	unsigned n = cf_emit(code, 0, caller, sizeof caller), hdr = n, k;
	unsigned jpos[32], apos[32];

	put32(code, CALL_AT + 1u, hdr - (CALL_AT + 5u));
	for (k = 0; k < jccs; k++) {
		code[n++] = 0x41; code[n++] = 0x83; code[n++] = 0xf9;
		code[n++] = (uint8_t)(k + 1u);
		jpos[k] = n;
		code[n++] = 0x74; code[n++] = 0;
	}
	if (ret_arms)
		code[n++] = 0xc3;
	else
		n = cf_emit(code, n, junk_arm, sizeof junk_arm);
	for (k = 0; k < jccs; k++) {
		apos[k] = n;
		if (k == right)
			n = cf_emit(code, n, right_arm, sizeof right_arm);
		else if (ret_arms)
			code[n++] = 0xc3;
		else
			n = cf_emit(code, n, junk_arm, sizeof junk_arm);
	}
	for (k = 0; k < jccs; k++)
		code[jpos[k] + 1u] = (uint8_t)(apos[k] - (jpos[k] + 2u));
	return n;
}

static void variants_and_pending(void)
{
	/* W_VARIANTS: arms all end in a syscall. The right arm is the target of
	 * the first branch, reached last. 3 branches = 4 paths: inside. */
	CK(alloc_exec(branchy(3, 0, 0)) == 1);
	CK(alloc_exec(branchy(3, 2, 0)) == 1);
	/* 4 branches = 5 paths and 10 branches = 11: the right arm is the fifth and
	 * the eleventh, and was dropped past the old four variants. The cap follows the
	 * span now (at least 32 for a function of 256 bytes), so both are found whole. */
	CK(alloc_status == KGENOME_OK);
	CK(alloc_exec(branchy(4, 0, 0)) == 1);
	CK(alloc_status == KGENOME_OK);
	CK(alloc_exec(branchy(10, 0, 0)) == 1);
	CK(alloc_status == KGENOME_OK);

	/* W_PENDING: arms that only return (no summary of their own, so the
	 * variant cap is not what is measured). The right arm behind the 6th
	 * branch was found, behind the 7th and 8th it was not: the queue grows with
	 * the function now. */
	CK(alloc_exec(branchy(8, 5, 1)) == 1);
	CK(alloc_exec(branchy(8, 6, 1)) == 1);
	CK(alloc_exec(branchy(8, 7, 1)) == 1);
	/* Nothing was cut, so nothing is said: every arm but the right one only
	 * returns, and the walk reached all of them. */
	CK(alloc_status == KGENOME_OK);
}

/*
 * A chain of `depth` wrappers above the syscall one, each `call next ; ret`,
 * laid out with the CALLERS AT LOWER ADDRESSES. That order is what makes each
 * level a separate pass: a callee at a higher address is not yet summarised
 * when its caller is reached, and only the next level sees it.
 * `extra` distinct call targets (a call each to a 1-byte function) follow, to
 * grow the object's call-target count.
 */
static unsigned chain(unsigned depth, unsigned extra)
{
	unsigned M = sizeof caller, n, j, a, k;

	n = cf_emit(code, 0, caller, sizeof caller);
	put32(code, CALL_AT + 1u, M - (CALL_AT + 5u));
	for (j = depth;; j--) {
		a = M + 8u * (depth - j);
		if (j == 0) {
			n = cf_emit(code, a, right_arm, sizeof right_arm);
			break;
		}
		code[a] = 0xe8;
		put32(code, a + 1u, (M + 8u * (depth - j + 1u)) - (a + 5u));
		code[a + 5] = 0xc3; code[a + 6] = 0xcc; code[a + 7] = 0xcc;
	}
	if (extra) {
		unsigned fn = n + 5u * extra;

		for (k = 0; k < extra; k++) {
			code[n] = 0xe8;
			put32(code, n + 1u, fn + k - (n + 5u));
			n += 5;
		}
		for (k = 0; k < extra; k++)
			code[n++] = 0xc3;
	}
	return n;
}

static void levels(void)
{
	/* the syscall wrapper itself, and wrappers above it */
	CK(alloc_exec(chain(0, 0)) == 1);
	CK(alloc_exec(chain(1, 0)) == 1);
	CK(alloc_exec(chain(2, 0)) == 1);
	/* three and five levels above: were "nesting levels (2)", a fixed two; now a
	 * fixpoint */
	CK(alloc_exec(chain(3, 0)) == 1 && alloc_status == KGENOME_OK);
	CK(alloc_exec(chain(5, 0)) == 1 && alloc_status == KGENOME_OK);
	/* THE DEPTH IS NOT CAPPED (it was 64): a chain of 70 is found, and so is one of
	 * 600. What ends a chain is the step budget the walk is given (64 steps per
	 * byte of code, at least 1M), each level paying for a pass over the call
	 * targets - so a chain of 3000, which needs three thousand passes over three
	 * thousand targets, is stopped where the budget runs out, and it is said. */
	CK(alloc_exec(chain(63, 0)) == 1 && alloc_status == KGENOME_OK);
	CK(alloc_exec(chain(70, 0)) == 1 && alloc_status == KGENOME_OK);
	CK(alloc_exec(chain(600, 0)) == 1 && alloc_status == KGENOME_OK);
	(void)alloc_exec(chain(3000, 0));
	CK(alloc_status == KGENOME_OVER_BUDGET);

	/* W_LEVELS_MAX_TGT is gone: ONE wrapper of the syscall wrapper, in an object
	 * with few call targets and in ones with 19000 and 25000 */
	CK(alloc_exec(chain(1, 19000)) == 1);
	CK(alloc_exec(chain(1, 25000)) == 1);
}

int main(void)
{
	span_and_body();
	variants_and_pending();
	levels();
	printf("caps wrap: %u known miss(es) recorded, %s\n", km_known(),
	       fails || km_failed() ? "FAILED" : "ok");
	return fails != 0 || km_failed();
}
