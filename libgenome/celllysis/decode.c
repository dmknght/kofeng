/*
 * decode.c - the one way in: bytes and an architecture, a cell_insn out.
 *
 * WHICH DECODER, by the architecture - the one place that says. Everything above
 * this reads struct cell_insn and nothing else, so adding an architecture is a
 * decoder and a line here, and no consumer changes.
 *
 * ARM IS READ AS ARM STATE, and that is a limit and not a decision: an ELF has no
 * per-instruction ISA bit, a Thumb function is told apart by its symbol or by
 * the low bit of the address that branches to it, and neither is available to a
 * caller that is only handed bytes. Thumb state is decoded (cell_decode_thumb) for the
 * caller that knows; the cursor does not yet.
 */
#include "kofmod/cell.h"
#include "decode.h"

uint32_t cell_decode(unsigned arch, int be, const uint8_t *p, uint32_t n,
		     uint64_t va, struct cell_insn *out)
{
	switch (arch) {
	case KOF_ARCH_ARM64:
		return cell_decode_arm64(p, n, va, out);
	case KOF_ARCH_ARM:
		return cell_decode_arm32(p, n, va, be, out);
	case KOF_ARCH_MIPS:
	case KOF_ARCH_MIPS64:
		return cell_decode_mips(p, n, va, be, out);
	default:
		return cell_decode_x86(p, n, va,
				       arch == KOF_ARCH_X86_64 ? 64u : 32u, out);
	}
}
