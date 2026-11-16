/*
 * emu_interp.c - the interpreter's one entry point and its dispatch table. See emu.h for what the
 * emulator is for, and struct kgenome_emu_arch (emu_private.h) for how it is cut.
 *
 * ONE CORE AND ONE ENTRY PER ARCHITECTURE. The core - memory and pages (emu_mem.c), budgets and their
 * accounting, the run loop and its stops (emu_run_private.h), the Linux environment (emu_sys.c) and
 * the Windows one (emu_win*.c) - is written once. An entry supplies the decode through its genotype
 * decoder, the execution of an instruction by its id, its register roles, its system call conventions
 * and its loader's assumptions; x86 and x86-64 are the first entry (emu_x86.c). A run follows ONE
 * pointer, the entry's own instance of the loop; nothing per instruction goes through this file.
 */
#include "emu_private.h"

enum kgenome_emu_stop kgenome_emu_run(struct kgenome_emu *e)
{
	if (!e)
		return KGENOME_EMU_STOP_FAULT;  /* as kgenome_emu_step answers it */
	return e->arch->run(e);
}

/*
 * THE ENTRY A MACHINE IS MADE WITH. One today: the decoder the interpreter runs on decodes x86 and
 * x86-64, and kgenome_emu_cfg.bits picks the width inside that entry. A second architecture is a
 * second row here and an entry of its own, never a branch inside the x86 one.
 */
const struct kgenome_emu_arch *kgenome_emu_arch_of(const struct kgenome_emu_cfg *cfg)
{
	(void)cfg;
	return kgenome_emu_arch_x86();
}

void kgenome_emu_arch_seed(struct kgenome_emu *e, uint64_t entry)
{
	unsigned k;

	if (!e)
		return;
	for (k = 0; k < e->arch->n_seed; k++)
		e->gpr[e->arch->seed[k]] = entry;
}
