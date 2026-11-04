/*
 * decode.c - the one way in: bytes and an architecture, a kgenome_cell_insn out.
 *
 * WHICH DECODER, by the architecture - the one place that says. Everything above
 * this reads struct kgenome_cell_insn and nothing else, so adding an architecture is a
 * decoder and a line here, and no consumer changes.
 *
 * ARM IS READ AS ARM STATE, and that is a limit and not a decision: an ELF has no
 * per-instruction ISA bit, a Thumb function is told apart by its symbol or by
 * the low bit of the address that branches to it, and neither is available to a
 * caller that is only handed bytes. Thumb state is decoded (kgenome_cell_decode_thumb) for the
 * caller that knows; the cursor does not yet.
 */
#include <celllysis/cell.h>
#include "decode.h"

/* The operands from `n_op` on are absent, and are written as such: the decoders of some architectures keep a scratch value (a branch's displacement) in a slot they report as
 * absent, and what a reader of the decode (the walk's trace keeps `n_op` operands, kgenome_diag_wrapper_trace_get_cell) must give back is the same instruction. */
static void absent_clear(struct kgenome_cell_insn *out)
{
	unsigned i;

	for (i = out->n_op > 3u ? 3u : out->n_op; i < 3u; i++) {
		struct kgenome_cell_operand *o = &out->o[i];

		o->kind = KGENOME_CELL_O_NONE;
		o->reg = o->index = o->seg = KGENOME_CELL_REG_NONE;
		o->scale = o->size = o->flags = 0;
		o->_pad = 0;
		o->disp = 0;
		o->imm = 0;
	}
}

static uint32_t decode_arch(unsigned arch, int be, const uint8_t *p, uint32_t n,
			    uint64_t va, struct kgenome_cell_insn *out)
{
	switch (arch) {
	case KGENOME_ARCH_ARM64:
		return kgenome_cell_decode_arm64(p, n, va, out);
	case KGENOME_ARCH_ARM:
		return kgenome_cell_decode_arm32(p, n, va, be, out);
	case KGENOME_ARCH_MIPS:
	case KGENOME_ARCH_MIPS64:
		return kgenome_cell_decode_mips(p, n, va, be, out);
	case KGENOME_ARCH_PPC:
		return kgenome_cell_decode_ppc(p, n, va, be, 0, out);
	case KGENOME_ARCH_PPC64:
		return kgenome_cell_decode_ppc(p, n, va, be, 1, out);
	case KGENOME_ARCH_X86:
	case KGENOME_ARCH_X86_64:
		return kgenome_cell_decode_x86(p, n, va,
				       arch == KGENOME_ARCH_X86_64 ? 64u : 32u, out);
	default:
		return 0;       /* no decoder for it: "cannot answer", never another ISA's reading */
	}
}

uint32_t kgenome_cell_decode(unsigned arch, int be, const uint8_t *p, uint32_t n,
		     uint64_t va, struct kgenome_cell_insn *out)
{
	const uint32_t len = decode_arch(arch, be, p, n, va, out);

	if (len)
		absent_clear(out);
	return len;
}
