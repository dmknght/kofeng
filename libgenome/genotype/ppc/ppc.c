/*
 * ppc.c - the PowerPC decoder proper: walk ppc_tab.c to an identity, check the mode, and read
 * fields out of the word when asked. Nothing here knows an encoding except the isel test.
 */
#include "ppc.h"
#include "ppc_private.h"

static int64_t sx(uint32_t v, unsigned bits)
{
	uint32_t m = 1u << (bits - 1u);

	return (int64_t)(v ^ m) - (int64_t)m;
}

static unsigned ppc_find(uint32_t w)
{
	const struct kgenome_ppc_prim *p = &kgenome_ppc_prim[w >> 26];
	const struct kgenome_ppc_row *r;

	switch (p->kind) {
	case KGENOME_PPC_PK_ID:
		return p->id;
	case KGENOME_PPC_PK_ROWS:
		for (r = p->rows; (w & r->mask) != r->val; r++)
			;
		return r->id;
	default:
		/* isel: bits 26..30 = 01111, the one five-bit extended opcode of this opcode */
		if ((w & 0x3Eu) == 0x1Eu)
			return KGENOME_PPC_I_ISEL;
		return kgenome_ppc_x31[(w >> 1) & 1023u];
	}
}

enum kgenome_status kgenome_ppc_decode(struct kgenome_ppc_insn *out, uint32_t w, int wide)
{
	unsigned id = ppc_find(w), at = kgenome_ppc_attr[id];

	if (((at & KGENOME_PPC_A_P64) && !wide) || ((at & KGENOME_PPC_A_RC1) && !(w & 1u)) ||
	    ((at & KGENOME_PPC_A_L64) && !wide && (w & 0x00200000u)) ||
	    /* bcctr with BO bit 2 clear asks for "decrement CTR and branch to CTR": the architecture says that form is invalid */
	    (id == KGENOME_PPC_I_BCCTR && !(w & 0x00800000u)))
		id = KGENOME_PPC_I_INVALID;
	out->word = w;
	out->id = (uint16_t)id;
	return id == KGENOME_PPC_I_INVALID ? KGENOME_INVALID
	     : id == KGENOME_PPC_I_UNSUPPORTED ? KGENOME_UNSUPPORTED : KGENOME_OK;
}

const char *kgenome_ppc_name(unsigned id)
{
	return id < KGENOME_PPC_I_COUNT ? kgenome_ppc_names[id] : "?";
}

int64_t kgenome_ppc_branch_off(const struct kgenome_ppc_insn *in)
{
	if (in->id == KGENOME_PPC_I_B)
		return sx(in->word & 0x03fffffcu, 26);
	if (in->id == KGENOME_PPC_I_BC)
		return sx(in->word & 0xfffcu, 16);
	return 0;
}

uint64_t kgenome_ppc_branch_target(const struct kgenome_ppc_insn *in, uint64_t pc, int wide, int *has)
{
	uint64_t t;

	if (in->id != KGENOME_PPC_I_B && in->id != KGENOME_PPC_I_BC) {
		*has = 0;
		return 0;
	}
	*has = 1;
	t = (uint64_t)kgenome_ppc_branch_off(in);
	if (!kgenome_ppc_aa(in))
		t += pc;
	return wide ? t : (t & 0xffffffffu);
}
