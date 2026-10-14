/*
 * diag_sweep_cand.c - where the walk has to look: candidate positions of a kernel entry, and what counts as one.
 * Part of the diagnose scan; see diag_scan.c for what it is for and diag_scan_private.h for what the
 * files share.
 */
#include "diag_scan_private.h"

/* The first window kgenome_diag_cand_at searches; see there. */
#define CAND_WIN 256u

/*
 * ---- WHERE THE WALK HAS TO LOOK ------------------------------------------
 *
 * EVERY NODE IS BORN AT A SYSCALL, and that is what makes the rest of this
 * section legitimate. The two hit_add calls in kgenome_diag_at_syscall are the only ones
 * that put a FRESH index into the origin map; the third, the indirect
 * branch, fires only when the register it jumps through already carries one.
 * So an instruction with no syscall anywhere near it cannot contribute.
 *
 * The three encodings are the whole set this walk acts on - `0f 05` syscall,
 * `0f 34` sysenter, `cd 80` int 0x80 - see the KGENOME_CELL_SYSCALL arm of class_of
 * and the int-0x80 test in the loop.
 *
 * A BYTE THAT IS NOT AN INSTRUCTION STILL COUNTS, and must. `0f 05` inside a
 * displacement answers yes and costs a window that finds nothing; that is a
 * wasted decode, not a missed node. The other direction would be a lie - an
 * instruction that is not in the bytes cannot be decoded out of them.
 *
 * WHY THE WHOLE-REGION TEST IS NOT ENOUGH, which is where this started.
 * Asking only "does this segment contain the bytes" was MEASURED on a frozen
 * copy of /usr/bin: it rejects 67% of the x86-64 files but only 7.4% of the
 * executable BYTES, because the big segments all contain the pair somewhere
 * by chance - at one in 65536 per position, a megabyte of code is certain to.
 * The same measurement counted 1491 candidate positions in 182.5 MB, so the
 * useful unit is the POSITION and not the segment.
 */
uint64_t kgenome_diag_cand_at(const uint8_t *p, uint64_t from, uint64_t n)
{
	uint64_t i = from, win = CAND_WIN;

	/*
	 * THE SEARCH IS BOUNDED BY A WINDOW THAT GROWS ONLY WHEN NOTHING WAS IN IT.
	 * This was two memchr calls over the WHOLE rest of the object per candidate
	 * and per false lead: when one of the two lead bytes is absent (all `cd 80`,
	 * or all `0f 05`, or `0f 0b` with no 0xcd anywhere) the other search ran to
	 * the end of the object every time, so n/2 positions cost n/2 x n bytes.
	 * Measured on a hand-built ELF of repeated `ud2`: 0.035 s at 128 KB, 0.67 s at
	 * 512 KB, 3.2 s at 1 MB, 16 s at 2 MB (quadratic), and the same for `syscall`,
	 * `int 0x80`, `cpuid` and `rdtsc` repeated. With a window each call costs the
	 * distance to the hit, within a constant, and the next call starts after it.
	 * Which positions are returned has not changed: the window only decides how far
	 * one memchr looks, and an empty window is searched again from its end.
	 */
	while (i + 1u < n) {
		uint64_t end = n - 1u - i > win ? i + win : n - 1u;
		const uint8_t *q = memchr(p + i, 0x0f, (size_t)(end - i));
		const uint8_t *r = memchr(p + i, 0xcd, (size_t)(end - i));
		uint64_t at;

		if (!q && !r) {
			i = end;
			if (win < ((uint64_t)1 << 40))
				win *= 2u;
			continue;
		}
		if (!q || (r && r < q)) {
			at = (uint64_t)(r - p);
			if (p[at + 1u] == 0x80u)
				return at;
		} else {
			at = (uint64_t)(q - p);
			if (p[at + 1u] == 0x05u || p[at + 1u] == 0x34u)
				return at;
		}
		i = at + 1u;
	}
	return n;
}

/*
 * A32 `svc` AS LINUX USES IT, and not every word the instruction set allows.
 *
 * The bare mask (cond:1111 imm24) matched 159 words in one 190 KB Mirai
 * build, nearly all of them literal-pool data after a `bx lr` - 0x7f807f81 is
 * `svcvc 0x807f81` and is a pair of halfwords, not a call. Real code is
 * always-execute: EABI is `svc 0`, the old ABI is `svc 0x9000nn`, and the
 * ARM-private calls (cacheflush) are `svc 0x0f000n`. Anything else is data.
 */
static int svc_a32(uint32_t x)
{
	uint32_t imm = x & 0xffffffu;

	if ((x >> 24) != 0xefu)         /* cond AL, 1111 */
		return 0;
	return imm == 0 || (imm >> 16) == 0x90u || (imm >> 16) == 0x0fu;
}

/*
 * THE FIXED-WIDTH CANDIDATE: an aligned word that is an `svc`.
 *
 * No byte search: instructions sit on 4-byte boundaries, so every word is
 * looked at once. A64 `svc #0` is the one word 0xd4000001 - Linux passes no
 * immediate, and the 65536 other `svc` words are data far more often than code.
 * `off` is where `p` sits in the file, because alignment is the file's and not
 * the slice's.
 */
uint64_t kgenome_diag_cand_fixed(const struct kgenome_obj *obj, const uint8_t *p,
			   uint64_t off, uint64_t from, uint64_t n)
{
	uint64_t i = from + ((4u - ((off + from) & 3u)) & 3u);
	int be = obj->arch == KGENOME_ARCH_ARM && kgenome_obj_big_endian(obj) &&
		 !kgenome_obj_code_little_endian(obj);

	for (; i + 4u <= n; i += 4u) {
		uint32_t x = be ? ((uint32_t)p[i] << 24 | (uint32_t)p[i + 1] << 16 |
				   (uint32_t)p[i + 2] << 8 | p[i + 3])
				: kof_ld_le32(p + i);

		if (obj->arch == KGENOME_ARCH_ARM ? svc_a32(x) : x == 0xd4000001u)
			return i;
	}
	return n;
}

/*
 * IS THIS INSTRUCTION A WAY INTO THE KERNEL ON *THIS* OBJECT.
 *
 * The three encodings are not interchangeable, and treating them as one set
 * accepts things that cannot execute:
 *
 *   0f 05  syscall    64-bit mode only. In a 32-bit image it is not a way
 *                     into the kernel on any system this engine targets.
 *   0f 34  sysenter   32-bit. Windows x86 uses it, but only inside ntdll;
 *                     Linux i386 reaches it through the vDSO.
 *   cd 80  int 0x80   LINUX's i386 entry, and nothing else's. On a PE it is
 *                     an interrupt into a vector Windows does not serve.
 *
 * MEASURED on 300 PE samples: the only three sites whose syscall number the
 * walk could read were a `cd 80` and an `0f 05` in a 32-bit image, and an
 * `0f 34` outside ntdll - all three coincidental bytes inside packed data,
 * and all three accepted because the test looked at the bytes and not at
 * what the object is. None of them can run.
 *
 * ONE TEST FOR EVERY WALK. The sweep below and the wrapper analysis's walk
 * (diag_wrapper.c) each had their own copy; they agreed on every ELF the engine
 * walks (the wrapper walk only runs on x86 ELF), but one of them could have
 * drifted. `vec80` is "this is a software interrupt with vector 0x80", which
 * each caller reads from its own form of the instruction.
 *
 * THIS IS NOT THE DIRECT-SYSCALL TEST, and must not be mistaken for one. A
 * Hell's Gate stub is `mov r10,rcx; mov eax,SSN; syscall` in a 64-bit PE,
 * which this accepts - as it should - along with every stray `0f 05` in a
 * 64-bit packed section. Telling those apart needs the r10 shape, and that
 * is a separate piece of work.
 */
int kgenome_diag_kernel_entry(const struct kgenome_obj *obj, unsigned op,
			  int vec80, const uint8_t *p)
{
	int bits64 = obj->arch == KGENOME_ARCH_X86_64;

	if (kgenome_diag_fixed_arch(obj))
		return op == KGENOME_CELL_SYSCALL;
	if (op == KGENOME_CELL_SYSCALL)
		return p[0] == 0x0fu && p[1] == 0x05u ? bits64 : !bits64;
	if (op == KGENOME_CELL_INT && vec80)
		return obj->format == KGENOME_FMT_ELF;
	return 0;
}
