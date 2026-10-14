/*
 * diag_wrapper_scale - the wrapper analysis (diag_wrapper*.c) and the node merge
 * (merge_sites in diag_scan.c) give the SAME answer at a size where they used to be
 * quadratic, and in the orders that stress how the table of summaries is kept.
 *
 * WHAT CHANGED UNDERNEATH. The table of wrapper summaries was kept sorted by moving
 * 240-byte records for every insertion; it is now a pool in the order made with a
 * sorted index. The merge of nodes at one site and capability scanned every node kept
 * so far for each node; it is now a table. The end of the walk asked, for every
 * summary, a question that read every node and every call target; it is now one pass
 * against a sorted set. A change like that is right only if the answers are the same,
 * so the answers are built here from first principles:
 *
 *   chain      F0 calls F1 ... calls F(D-1) calls the generic syscall wrapper W, laid out
 *              in ASCENDING address order, so each pass of the fixpoint finds ONE more
 *              function and inserts it BELOW everything already in the table: the
 *              worst case of the old insertion, and the order that tests the index.
 *              main calls F0 with mmap's arguments, so exactly ONE allocation node
 *              with W+X exists - at the call in main - for any D, and the scan is whole.
 *   callers    ONE function of N calls to W, each with mmap's arguments: N allocation
 *              nodes, one per call, and a scan that is whole.
 *   interleaved C chains of depth D laid out level by level: summaries go into the
 *              MIDDLE of the table on every pass; one node per chain.
 *   merge      after the routes ran together no two nodes hold the same site and
 *              capability (a node with no site is not folded).
 *   sorted     every syscall table is in number order, which its search needs.
 */

#include "caps_fix.h"
#include "../../libkofeng/analyzers/genome_obj.h"
#include <celllysis/nucleo.h>

static unsigned char view[1u << 22];
static uint8_t img[1u << 23];
static uint8_t code[1u << 22];

/* rax=rdi; rdi=rsi; rsi=rdx; rdx=rcx; r10=r8; r8=r9; syscall; ret */
static const uint8_t wrap[] = {
	0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0x48, 0x89, 0xca,
	0x4d, 0x89, 0xc2, 0x4d, 0x89, 0xc8, 0x0f, 0x05, 0xc3
};

/* mmap(0, 0x1000, 7, 0x22) through the wrapper: the arguments, then `call rel32`
 * (at offset 25 of the 30 bytes). */
static const uint8_t args[] = {
	0xbf, 9, 0, 0, 0,                   /* mov edi,9   nr        */
	0xbe, 0, 0, 0, 0,                   /* mov esi,0   addr      */
	0xba, 0, 0x10, 0, 0,                /* mov edx,0x1000 len    */
	0xb9, 7, 0, 0, 0,                   /* mov ecx,7   prot      */
	0x41, 0xb8, 0x22, 0, 0, 0,          /* mov r8d,0x22          */
	0x45, 0x31, 0xc9                    /* xor r9d,r9d           */
};

/* Between everything and W: the sweep reads 256 bytes before a syscall (4096 on a
 * second try), so with this much padding it does not see the arguments and the
 * number is the wrapper's analysis to find - without it the sweep reads the
 * caller's constants straight through W and the wrapper is never needed. */
#define PAD 5000u

static unsigned emit_call(unsigned at, unsigned target)
{
	code[at] = 0xe8;
	put32(code, at + 1, target - (at + 5u));
	return at + 5u;
}

static struct kgenome_diag_scan *scan_code(unsigned n, unsigned run, struct kof_obj_ctx *ctx)
{
	uint64_t len = cf_elf64(img, sizeof img, code, n);

	memset(view, 0, sizeof view);
	return cf_scan(img, len, run, ctx, view);
}

/* main, then F0..F(d-1) ascending, then W. Returns the length. */
static unsigned chain_code(unsigned d)
{
	const unsigned main_len = (unsigned)sizeof args + 5u + 1u;
	unsigned f0 = main_len, w, n, i;

	/* every F is `call next ; ret` = 6 bytes */
	w = f0 + 6u * d + PAD;
	n = cf_emit(code, 0, args, sizeof args);
	n = emit_call(n, d ? f0 : w);
	code[n++] = 0xc3;
	for (i = 0; i < d; i++) {
		n = emit_call(n, i + 1u < d ? f0 + 6u * (i + 1u) : w);
		code[n++] = 0xc3;
	}
	memset(code + n, 0xcc, PAD);
	return cf_emit(code, n + PAD, wrap, sizeof wrap);
}

static void chain(void)
{
	static const unsigned depth[] = { 0, 1, 2, 3, 8, 50, 200 };
	unsigned k;

	for (k = 0; k < sizeof depth / sizeof depth[0]; k++) {
		struct kof_obj_ctx ctx;
		unsigned n = chain_code(depth[k]);
		struct kgenome_diag_scan *s = scan_code(n, KGENOME_DIAG_RUN_SYSCALL, &ctx);

		CK(s != NULL);
		if (!s)
			continue;
		if (cf_count_cap(s, KGENOME_NUCLEO_ALLOC_EXEC) != 1u)
			printf("  chain depth %u: %u allocation node(s)\n", depth[k],
			       cf_count_cap(s, KGENOME_NUCLEO_ALLOC_EXEC));
		CK(cf_count_cap(s, KGENOME_NUCLEO_ALLOC_EXEC) == 1u);
		CK(kgenome_diag_scan_status(s) == KGENOME_OK);
		kgenome_diag_scan_free(s);
	}
}

/* C independent chains of depth D, laid out LEVEL BY LEVEL: the functions of level i
 * of every chain, then those of level i+1, ... then W. A chain's function calls the
 * next level's, which is at a HIGHER address, so every pass of the fixpoint adds one
 * level of summaries and each goes into the middle of the table. main calls the head
 * of each chain with mmap's arguments: one allocation node per chain. */
static void interleaved(void)
{
	static const unsigned cd[][2] = { { 1, 1 }, { 5, 3 }, { 200, 20 }, { 50, 100 } };
	unsigned k;

	for (k = 0; k < sizeof cd / sizeof cd[0]; k++) {
		const unsigned c = cd[k][0], d = cd[k][1], per = (unsigned)sizeof args + 5u;
		const unsigned main_len = per * c + 1u, f0 = main_len,
			       w = f0 + 6u * c * d + PAD;
		struct kof_obj_ctx ctx;
		struct kgenome_diag_scan *s;
		unsigned n = 0, i, l;

		for (i = 0; i < c; i++) {
			n = cf_emit(code, n, args, sizeof args);
			n = emit_call(n, f0 + 6u * i);
		}
		code[n++] = 0xc3;
		for (l = 0; l < d; l++)
			for (i = 0; i < c; i++) {
				n = emit_call(n, l + 1u < d ? f0 + 6u * (c * (l + 1u) + i) : w);
				code[n++] = 0xc3;
			}
		memset(code + n, 0xcc, PAD);
		n = cf_emit(code, n + PAD, wrap, sizeof wrap);
		s = scan_code(n, KGENOME_DIAG_RUN_SYSCALL, &ctx);
		CK(s != NULL);
		if (!s)
			continue;
		if (cf_count_cap(s, KGENOME_NUCLEO_ALLOC_EXEC) != c)
			printf("  %u chains of %u: %u allocation node(s), status %d\n", c, d,
			       cf_count_cap(s, KGENOME_NUCLEO_ALLOC_EXEC),
			       (int)kgenome_diag_scan_status(s));
		CK(cf_count_cap(s, KGENOME_NUCLEO_ALLOC_EXEC) == c);
		CK(kgenome_diag_scan_status(s) == KGENOME_OK);
		kgenome_diag_scan_free(s);
	}
}

static void callers(void)
{
	static const unsigned count[] = { 1, 10, 500, 3000 };
	unsigned k;

	for (k = 0; k < sizeof count / sizeof count[0]; k++) {
		struct kof_obj_ctx ctx;
		/* one function of N calls - each with mmap's arguments - then W */
		const unsigned per = (unsigned)sizeof args + 5u, w = per * count[k] + 1u + PAD;
		unsigned n = 0, i;
		struct kgenome_diag_scan *s;

		for (i = 0; i < count[k]; i++) {
			n = cf_emit(code, n, args, sizeof args);
			n = emit_call(n, w);
		}
		code[n++] = 0xc3;
		memset(code + n, 0xcc, PAD);
		n = cf_emit(code, n + PAD, wrap, sizeof wrap);
		s = scan_code(n, KGENOME_DIAG_RUN_SYSCALL, &ctx);
		CK(s != NULL);
		if (!s)
			continue;
		if (cf_count_cap(s, KGENOME_NUCLEO_ALLOC_EXEC) != count[k])
			printf("  %u calls: %u allocation node(s)\n", count[k],
			       cf_count_cap(s, KGENOME_NUCLEO_ALLOC_EXEC));
		CK(cf_count_cap(s, KGENOME_NUCLEO_ALLOC_EXEC) == count[k]);
		CK(kgenome_diag_scan_status(s) == KGENOME_OK);
		kgenome_diag_scan_free(s);
	}
}

/* No two nodes hold the same site and capability once the routes ran together. */
static void merged(void)
{
	unsigned n = 0, i, a, b;
	struct kof_obj_ctx ctx;
	struct kgenome_diag_scan *s;
	int dup = 0;

	for (i = 0; i < 400; i++)
		n = cf_filler64(code, n, i);
	n = cf_stager64(code, n);
	s = scan_code(n, KGENOME_DIAG_RUN_ALL, &ctx);
	CK(s != NULL);
	if (!s)
		return;
	for (a = 0; a < kgenome_diag_scan_count(s); a++)
		for (b = a + 1u; b < kgenome_diag_scan_count(s); b++) {
			const struct kgenome_diag_hit *x = kgenome_diag_scan_at(s, a);
			const struct kgenome_diag_hit *y = kgenome_diag_scan_at(s, b);

			if (x->at != KGENOME_BROKEN && x->at == y->at && x->cap == y->cap)
				dup = 1;
		}
	CK(!dup);
	CK(kgenome_diag_scan_count(s) >= 400u);
	kgenome_diag_scan_free(s);
}

static void tables(void)
{
	CK(kgenome_nucleo_sys_ordered() == 1);
	/* spot checks through the public lookups, numbers read from unistd_64.h / unistd_32.h */
	CK(strcmp(kgenome_nucleo_sys_name(64, 9), "mmap") == 0);
	CK(strcmp(kgenome_nucleo_sys_name(64, 41), "socket") == 0);
	CK(strcmp(kgenome_nucleo_sys_name(64, 280), "utimensat") == 0);
	CK(strcmp(kgenome_nucleo_sys_name(32, 102), "socketcall") == 0);
	CK(strcmp(kgenome_nucleo_sys_name(32, 358), "execveat") == 0);
	CK(kgenome_nucleo_sys_name(64, 1000) == NULL);
	CK(kgenome_nucleo_sys_name(32, 7) == NULL);
}

int main(void)
{
	chain();
	callers();
	interleaved();
	merged();
	tables();
	printf("diag wrapper scale: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
