/*
 * diag_lineage_arch.c - THE ROWS: what the lineage stages ask a machine and an ABI. Part of the lineage stages; see
 * diag_lineage_private.h (struct kgenome_lineage_abi) for what a row holds and why the core never asks the architecture.
 *
 * WHY A TABLE. The convention was an `if` on the architecture and another on the format in the driver (abi_init), the stack
 * pointer and the result register were the x86 numbers written into the transfer function, the join and the seed, and the
 * system call's registers were a third copy (kgenome_diag_arg_regs, the routes' own). A new architecture was a change in four
 * files and a forgotten one was a silent wrong link. Now it is a row: the registers with a role, the call convention, the system
 * call convention, and the transfer function of one instruction.
 *
 * WHAT EACH ARCHITECTURE WITHOUT A ROW LACKS (the stages run on none of them; the routes still make their nodes and links):
 *   ARM32 / AArch64  a transfer function: the decoder's PUSH/POP are register LISTS (`push {r4-r7, lr}`), a load or store moves the
 *                    base register (pre/post index writeback), a call leaves its return address in a register (lr) and not in a
 *                    stack slot, and a predicated instruction writes on one path only - each a rule kgenome_lineage_step_x86 has no
 *                    counterpart for, and none is written here without a test that builds the bytes (the lineage tests' assembler
 *                    and image builder, tests/lib/genome/lineage_asm.h and lineage_img.h, are x86 only).
 *   MIPS / PPC / SPARC / RISC-V / SH / m68k  the same, plus a delay slot (MIPS, SPARC, SH) that the frame's graph keeps in the
 *                    branch's block (cfg_isa.c) but whose effect on the provenance state precedes the branch.
 * The call and system call conventions of all of them exist (nucleo's ABI rows, kgenome_nucleo_abi_of): what is missing is the step,
 * and the tests.
 */
#include "diag_lineage_private.h"

static const uint8_t win64_arg[4] = { KGENOME_CELL_REG_CX, KGENOME_CELL_REG_DX, 8u, 9u };
static const uint8_t clob_sysv[9] = { 0, 1, 2, 6, 7, 8, 9, 10, 11 };
static const uint8_t clob_win64[7] = { 0, 1, 2, 8, 9, 10, 11 };
static const uint8_t clob_i386[3] = { 0, 1, 2 };
/* what `syscall` destroys besides rax: rcx takes the return address and r11 the flags (the instruction set manual, SYSCALL); `int 0x80`
 * destroys only eax, which holds the answer */
static const uint8_t sysclob_x64[2] = { KGENOME_CELL_REG_CX, 11u };

#define X86_REGS .sp = KGENOME_CELL_REG_SP, .fp = KGENOME_CELL_REG_BP, .ret = KGENOME_CELL_REG_AX, .sys_nr = KGENOME_CELL_REG_AX, \
		 .step = kgenome_lineage_step_x86

static const struct kgenome_lineage_abi rows[] = {
	{ .name = "x86-64 sysv", .arch = KGENOME_ARCH_X86_64, .fmt = KGENOME_FMT_ELF, X86_REGS,
	  .arg = kgenome_diag_sysv_arg, .n_arg = 6, .clob = clob_sysv, .n_clob = 9, .wide = 1, .w = 8, .stack_first = 6,
	  .sys_clob = sysclob_x64, .n_sys_clob = 2 },
	/* Windows x64: four register arguments and the callee's 32 bytes of shadow space above the return address */
	{ .name = "x86-64 win64", .arch = KGENOME_ARCH_X86_64, .fmt = KGENOME_FMT_PE, X86_REGS,
	  .arg = win64_arg, .n_arg = 4, .clob = clob_win64, .n_clob = 7, .wide = 1, .w = 8, .stack_first = 4, .stack_off = 32,
	  .sys_clob = sysclob_x64, .n_sys_clob = 2 },
	{ .name = "i386 cdecl", .arch = KGENOME_ARCH_X86, .fmt = KGENOME_FMT_ELF, X86_REGS,
	  .clob = clob_i386, .n_clob = 3, .w = 4 },
	/* PE x86: an API is stdcall, its callee pops what was pushed for it (kgenome_lineage_state_call) */
	{ .name = "i386 stdcall", .arch = KGENOME_ARCH_X86, .fmt = KGENOME_FMT_PE, X86_REGS,
	  .clob = clob_i386, .n_clob = 3, .w = 4, .callee_pops = 1 },
};

int kgenome_lineage_arch_of(const struct kgenome_obj *obj, struct kgenome_lineage_abi *out)
{
	unsigned i;

	if (!obj)
		return 0;
	for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
		const uint8_t *sa;
		int n;

		if (rows[i].arch != obj->arch || (rows[i].fmt && rows[i].fmt != obj->format))
			continue;
		*out = rows[i];
		/* the system call's argument registers are the routes' table, read and not copied */
		n = kgenome_diag_arg_regs(obj, &sa);
		out->sys_arg = sa;
		out->n_sys_arg = (uint8_t)(n > 0 ? n : 0);
		return 1;
	}
	return 0;
}
