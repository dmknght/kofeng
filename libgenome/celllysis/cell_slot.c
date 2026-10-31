/*
 * cell_slot.c - kgenome_cell_slot_of: the fixed address a memory-operand branch goes through. See cell.h.
 *
 * It was written twice, once for the ELF import route (diag_elfimp.c, with the i386 GOT register) and once for the PE one (diag_pe.c, without the
 * segment test), and a third reader - the call-name table - needed it. One function now; the stricter of the two is the rule (a segment other than
 * ds is thread data, an index register is a table).
 *
 * The rest of what the ELF import route and the call-name table both did to every instruction - which sections hold stubs, the i386 GOT register, the
 * `endbr` in front of an IBT stub - is kgenome_cell_plt_* below, written once (it was in diag_elfimp.c and in callnames.c, line for line).
 */
#include "cell.h"
#include "arch.h"
#include "../genotype/image/elf_types.h"

#include <string.h>

uint64_t kgenome_cell_slot_of(const struct kgenome_cell_insn *in, int wide, uint64_t gotbase)
{
	const struct kgenome_cell_operand *o = &in->o[0];

	if (!in->n_op || o->kind != KGENOME_CELL_O_MEM || o->index != KGENOME_CELL_REG_NONE)
		return KGENOME_BROKEN;
	if (o->seg != KGENOME_CELL_REG_NONE && o->seg != KGENOME_CELL_SEG_DS)
		return KGENOME_BROKEN;          /* fs: and gs: are thread data */
	if (o->flags & KGENOME_CELL_OF_RIPREL)
		return in->at_va == KGENOME_BROKEN ? KGENOME_BROKEN : in->at_va + in->len + (uint64_t)o->disp;
	if (o->reg == KGENOME_CELL_REG_NONE)
		return wide ? (uint64_t)o->disp : (uint64_t)o->disp & 0xffffffffu;
	if (!wide && o->reg == KGENOME_CELL_REG_BX && gotbase)
		return (gotbase + (uint64_t)o->disp) & 0xffffffffu;
	return KGENOME_BROKEN;
}

_Static_assert(KGENOME_CELL_PLT_SECTIONS == KGENOME_ELF_MAX_SECTIONS, "the plt state holds as many sections as an ELF parse keeps");

void kgenome_cell_plt_init(struct kgenome_cell_plt *p, const uint8_t *base, uint64_t size, int wide)
{
	memset(p, 0, sizeof *p);
	p->base = base;
	p->size = size;
	p->wide = wide;
}

void kgenome_cell_plt_import(struct kgenome_cell_plt *p, uint64_t slot, uint32_t reloc_type)
{
	if (reloc_type == 7u && (!p->min_jslot || slot < p->min_jslot))
		p->min_jslot = slot;            /* R_*_JUMP_SLOT */
}

void kgenome_cell_plt_ready(struct kgenome_cell_plt *p, const struct kgenome_elf_info *ei)
{
	uint32_t i;

	p->n_stubsec = 0;
	p->no_sections = ei == NULL || ei->sec_count == 0;
	if (ei)
		for (i = 0; i < ei->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++)
			if (kgenome_elf_sec_is_stub(ei, i)) {
				p->stubsec[p->n_stubsec].lo = ei->sec[i].mem_addr;
				p->stubsec[p->n_stubsec++].hi = ei->sec[i].mem_addr + ei->sec[i].file_size;
			}
	/* The i386 GOT register: only when the lowest slot is where the psABI puts the first one. */
	p->gotbase = !p->wide && p->min_jslot >= 12u ? p->min_jslot - 12u : 0;
}

void kgenome_cell_plt_reset(struct kgenome_cell_plt *p)
{
	p->prev_endbr = 0;
}

static int plt_in_stub_area(const struct kgenome_cell_plt *p, uint64_t va)
{
	uint32_t i;

	if (p->no_sections)
		return 1;
	for (i = 0; i < p->n_stubsec; i++)
		if (va >= p->stubsec[i].lo && va < p->stubsec[i].hi)
			return 1;
	return 0;
}

/* `endbr64` / `endbr32`: f3 0f 1e fa / fb. The decoder classes it OTHER (it writes nothing and has no class of its own), so the bytes say it. */
static int plt_is_endbr(const struct kgenome_cell_plt *p, const struct kgenome_cell_insn *in)
{
	const uint8_t *b;

	if (in->len != 4u || in->at > p->size || p->size - in->at < 4u)
		return 0;
	b = p->base + in->at;
	return b[0] == 0xf3u && b[1] == 0x0fu && b[2] == 0x1eu && (b[3] == 0xfau || b[3] == 0xfbu);
}

int kgenome_cell_plt_at(struct kgenome_cell_plt *p, const struct kgenome_cell_insn *in, struct kgenome_cell_plt_site *out)
{
	int kind = KGENOME_CELL_PLT_NONE;
	uint64_t slot;

	if (!in) {
		p->prev_endbr = 0;
		return KGENOME_CELL_PLT_NONE;
	}
	if ((in->op == KGENOME_CELL_CALL || in->op == KGENOME_CELL_JMP) && (in->flags & KGENOME_CELL_F_INDIRECT) &&
	    in->n_op && in->o[0].kind == KGENOME_CELL_O_MEM &&
	    (slot = kgenome_cell_slot_of(in, p->wide, p->gotbase)) != KGENOME_BROKEN) {
		kind = in->op == KGENOME_CELL_JMP && plt_in_stub_area(p, in->at_va) ? KGENOME_CELL_PLT_STUB : KGENOME_CELL_PLT_SLOT;
		out->slot = slot;
		out->kind = (uint8_t)kind;
		out->has_endbr = (uint8_t)(kind == KGENOME_CELL_PLT_STUB && p->prev_endbr && p->prev_end_va == in->at_va);
		out->endbr_at = p->prev_at;
		out->endbr_va = p->prev_va;
	}
	p->prev_endbr = (uint8_t)plt_is_endbr(p, in);
	p->prev_va = in->at_va;
	p->prev_at = in->at;
	p->prev_end_va = in->at_va + in->len;
	return kind;
}
