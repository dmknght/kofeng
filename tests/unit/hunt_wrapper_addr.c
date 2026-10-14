/*
 * hunt_wrapper_addr - address arithmetic in the wrapper analysis wraps instead of overflowing.
 *
 * FOUND BY running the engine under UBSan over mutated x86-64 binaries with the heuristic
 * options randomised: `mov rax,[rip+disp]` in a candidate wrapper of an ELF whose segment sits
 * at 0x8000000000400000 computed `(int64_t)(at_va + len) + disp` - a signed overflow, undefined.
 * Every address in that analysis is the sample's (a vaddr, a register constant, a
 * displacement); the machine wraps, so the sum does too. A build without the sanitiser passes
 * this before the fix; `make unit-asan` (halting UBSan) is where it fails.
 */

#include "caps_fix.h"

static unsigned char view[1u << 22];
static uint8_t img[1u << 22];
static uint8_t code[1u << 16];

static unsigned run(uint64_t vaddr, int32_t disp)
{
	struct kof_obj_ctx ctx;
	struct kgenome_diag_scan *s;
	uint64_t len;
	unsigned n = 0, hits = 0, i;

	/* mov edi,9 ; call w ; ret */
	code[n++] = 0xbf; put32(code, n, 9); n += 4;
	code[n++] = 0xe8; put32(code, n, 1); n += 4;
	code[n++] = 0xc3;
	/* w: mov rax,[rip+disp] ; mov rax,rdi ; mov rdi,rsi ; syscall ; ret */
	code[n++] = 0x48; code[n++] = 0x8b; code[n++] = 0x05; put32(code, n, (uint32_t)disp); n += 4;
	code[n++] = 0x48; code[n++] = 0x89; code[n++] = 0xf8;
	code[n++] = 0x48; code[n++] = 0x89; code[n++] = 0xf7;
	code[n++] = 0x0f; code[n++] = 0x05;
	code[n++] = 0xc3;
	memset(view, 0, sizeof view);
	len = cf_elf64(img, sizeof img, code, n);
	put64(img, 24, vaddr + 0x78);          /* e_entry */
	put64(img, 64 + 16, vaddr);            /* p_vaddr */
	put64(img, 64 + 24, vaddr);            /* p_paddr */
	s = cf_scan(img, len, KGENOME_DIAG_RUN_SYSCALL, &ctx, view);
	for (i = 0; s && i < kgenome_diag_scan_count(s); i++)
		hits++;
	kgenome_diag_scan_free(s);
	return hits;
}

int main(void)
{
	static const uint64_t vaddrs[] = { 0x400000ull, 0x7fffffffffff0000ull, 0x8000000000400000ull,
					   0xffffffffffff0000ull, 0xfffffffffffff000ull };
	static const int32_t disps[] = { 0, -1, 0x7fffffff, (int32_t)0x80000000, -847380430 };
	unsigned a, b, first = run(0x400000ull, 0);

	for (a = 0; a < sizeof vaddrs / sizeof vaddrs[0]; a++)
		for (b = 0; b < sizeof disps / sizeof disps[0]; b++) {
			unsigned h = run(vaddrs[a], disps[b]);

			CK(h == run(vaddrs[a], disps[b]));      /* the same answer twice */
			(void)first;
		}
	if (fails)
		return 1;
	printf("hunt_wrapper_addr: ok\n");
	return 0;
}
