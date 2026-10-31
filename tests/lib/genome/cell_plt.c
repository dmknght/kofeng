/*
 * cell_plt - kgenome_cell_plt_*: the one place that decides what a `call`/`jmp` through a slot is, for the ELF import route and the call-name table.
 *
 * Why the old tests could not have caught anything in it: it was two copies (diag_elfimp.c, callnames.c), each exercised only through a whole route on
 * images that never reach the i386 GOT register - no test mutated `gotbase` to zero and failed (measured: the callnames and diag_graph_bin lib tests stay green).
 * What is pinned here, on instructions made by hand so the decision is read next to the input that makes it:
 *   KIND      `jmp [slot]` in a stub area is a STUB, `call [slot]` is a SLOT, a `jmp [slot]` in the program's own code (a tail call) is a SLOT, a register
 *             branch, a thread-data slot and a direct branch are none
 *   SECTIONS  with a section table only the sections kgenome_elf_sec_is_stub names are stub areas (the entry's section is not); with none, or for a PE, every one is
 *   GOT       the i386 `[ebx+disp]` slot is resolved only when the lowest JUMP_SLOT is at least 12 (the three reserved words), against `lowest - 12`, and never in a 64-bit object
 *   ENDBR     the `endbr64` / `endbr32` that ends exactly where a stub starts is joined to it; one that does not, a reset, a NULL and a non-stub are not
 */
#include <kgenome.h>

#include "hk.h"

#define BASE_SZ 0x40u

static const uint8_t endbr64[4] = { 0xf3, 0x0f, 0x1e, 0xfa };

static void mem_branch(struct kgenome_cell_insn *in, unsigned op, uint64_t va, unsigned len, unsigned reg, int64_t disp, unsigned flags)
{
	memset(in, 0, sizeof *in);
	in->op = (uint8_t)op;
	in->flags = KGENOME_CELL_F_INDIRECT;
	in->n_op = 1;
	in->len = (uint8_t)len;
	in->at = va & 0x3fu;            /* the file offset: inside the 0x40 bytes of the buffer */
	in->at_va = va;
	in->target = in->target_va = KGENOME_BROKEN;
	in->o[0].kind = KGENOME_CELL_O_MEM;
	in->o[0].reg = (uint8_t)reg;
	in->o[0].index = KGENOME_CELL_REG_NONE;
	in->o[0].seg = KGENOME_CELL_REG_NONE;
	in->o[0].scale = 1;
	in->o[0].size = 8;
	in->o[0].flags = (uint8_t)flags;
	in->o[0].disp = disp;
}

static void kinds_and_sections(void)
{
	static struct kgenome_elf_info ei;
	struct kgenome_cell_plt p;
	struct kgenome_cell_plt_site site;
	struct kgenome_cell_insn in;
	uint8_t buf[BASE_SZ];

	memset(buf, 0, sizeof buf);
	/* no section table (and a PE): every `jmp [slot]` is a stub, `call [slot]` a call site */
	kgenome_cell_plt_init(&p, buf, sizeof buf, 1);
	kgenome_cell_plt_ready(&p, NULL);
	mem_branch(&in, KGENOME_CELL_JMP, 0x1000, 6, KGENOME_CELL_REG_NONE, 0x3000, 0);
	in.o[0].reg = KGENOME_CELL_REG_NONE;
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_STUB && site.slot == 0x3000 && site.kind == KGENOME_CELL_PLT_STUB && !site.has_endbr);
	mem_branch(&in, KGENOME_CELL_CALL, 0x1006, 6, KGENOME_CELL_REG_NONE, 0x3008, 0);
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_SLOT && site.slot == 0x3008);
	/* rip-relative: the slot is the end of the instruction plus the displacement */
	mem_branch(&in, KGENOME_CELL_CALL, 0x1010, 6, KGENOME_CELL_REG_NONE, 0x100, KGENOME_CELL_OF_RIPREL);
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_SLOT && site.slot == 0x1010u + 6u + 0x100u);
	/* not a slot: a thread-data operand, an indexed table, a register branch, a direct branch, an unknown address */
	mem_branch(&in, KGENOME_CELL_CALL, 0x1020, 6, KGENOME_CELL_REG_NONE, 0x10, 0);
	in.o[0].seg = 4;
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_NONE);
	mem_branch(&in, KGENOME_CELL_CALL, 0x1020, 6, KGENOME_CELL_REG_NONE, 0x10, 0);
	in.o[0].index = 1;
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_NONE);
	mem_branch(&in, KGENOME_CELL_CALL, 0x1020, 6, KGENOME_CELL_REG_NONE, 0x10, 0);
	in.o[0].kind = KGENOME_CELL_O_REG;
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_NONE);
	mem_branch(&in, KGENOME_CELL_CALL, 0x1020, 6, KGENOME_CELL_REG_NONE, 0x10, 0);
	in.flags = 0;
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_NONE);
	mem_branch(&in, KGENOME_CELL_CALL, KGENOME_BROKEN, 6, KGENOME_CELL_REG_NONE, 0x10, KGENOME_CELL_OF_RIPREL);
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_NONE);
	mem_branch(&in, KGENOME_CELL_MOV, 0x1020, 6, KGENOME_CELL_REG_NONE, 0x10, 0);
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_NONE);

	/* a section table: the entry is in .text, .plt is the other executable section */
	memset(&ei, 0, sizeof ei);
	ei.valid = 1;
	ei.sec_count = 2;
	ei.entry_addr = 0x1010;
	ei.sec[0].type = KGENOME_ELF_SHT_PROGBITS;
	ei.sec[0].flags = KGENOME_ELF_SHF_EXEC;
	ei.sec[0].mem_addr = 0x1000;
	ei.sec[0].file_size = 0x100;
	ei.sec[1].type = KGENOME_ELF_SHT_PROGBITS;
	ei.sec[1].flags = KGENOME_ELF_SHF_EXEC;
	ei.sec[1].mem_addr = 0x2000;
	ei.sec[1].file_size = 0x40;
	CK(kgenome_elf_sec_is_stub(&ei, 1) && !kgenome_elf_sec_is_stub(&ei, 0));
	kgenome_cell_plt_init(&p, buf, sizeof buf, 1);
	kgenome_cell_plt_ready(&p, &ei);
	mem_branch(&in, KGENOME_CELL_JMP, 0x2010, 6, KGENOME_CELL_REG_NONE, 0x3000, 0);
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_STUB);
	mem_branch(&in, KGENOME_CELL_JMP, 0x203f, 6, KGENOME_CELL_REG_NONE, 0x3000, 0);
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_STUB);
	mem_branch(&in, KGENOME_CELL_JMP, 0x2040, 6, KGENOME_CELL_REG_NONE, 0x3000, 0);
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_SLOT);      /* one past the stub section: a tail call */
	mem_branch(&in, KGENOME_CELL_JMP, 0x1010, 6, KGENOME_CELL_REG_NONE, 0x3000, 0);
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_SLOT);      /* a tail call in the program's own code */
	mem_branch(&in, KGENOME_CELL_CALL, 0x2010, 6, KGENOME_CELL_REG_NONE, 0x3000, 0);
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_SLOT);      /* a call is never a stub, wherever it is */
	/* an ELF with a section count of zero says nothing: every `jmp [slot]` is a stub again */
	ei.sec_count = 0;
	kgenome_cell_plt_ready(&p, &ei);
	mem_branch(&in, KGENOME_CELL_JMP, 0x1010, 6, KGENOME_CELL_REG_NONE, 0x3000, 0);
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_STUB);
}

static void got_register(void)
{
	struct kgenome_cell_plt p;
	struct kgenome_cell_plt_site site;
	struct kgenome_cell_insn in;
	uint8_t buf[BASE_SZ];

	memset(buf, 0, sizeof buf);
	/* i386: the lowest JUMP_SLOT 0x3010 is the first slot after the three reserved words, so ebx = 0x3004 and `jmp [ebx+0xc]` goes through 0x3010 */
	kgenome_cell_plt_init(&p, buf, sizeof buf, 0);
	kgenome_cell_plt_import(&p, 0x3014, 7);
	kgenome_cell_plt_import(&p, 0x3010, 7);
	kgenome_cell_plt_import(&p, 0x2000, 6);         /* not a JUMP_SLOT: it does not lower the minimum */
	kgenome_cell_plt_ready(&p, NULL);
	CK(p.gotbase == 0x3004u);
	mem_branch(&in, KGENOME_CELL_JMP, 0x1000, 6, KGENOME_CELL_REG_BX, 0xc, 0);
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_STUB && site.slot == 0x3010u);
	mem_branch(&in, KGENOME_CELL_JMP, 0x1006, 6, 5 /* ebp */, 0xc, 0);
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_NONE);
	/* the lowest slot below 12 cannot be the first after the reserved words: no register is guessed */
	kgenome_cell_plt_init(&p, buf, sizeof buf, 0);
	kgenome_cell_plt_import(&p, 11, 7);
	kgenome_cell_plt_ready(&p, NULL);
	CK(p.gotbase == 0);
	mem_branch(&in, KGENOME_CELL_JMP, 0x1000, 6, KGENOME_CELL_REG_BX, 0xc, 0);
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_NONE);
	kgenome_cell_plt_init(&p, buf, sizeof buf, 0);
	kgenome_cell_plt_import(&p, 12, 7);
	kgenome_cell_plt_ready(&p, NULL);
	CK(p.gotbase == 0);                             /* 12 - 12 is no address: the same as unknown */
	/* a 64-bit object has no such register, whatever its slots say */
	kgenome_cell_plt_init(&p, buf, sizeof buf, 1);
	kgenome_cell_plt_import(&p, 0x3010, 7);
	kgenome_cell_plt_ready(&p, NULL);
	CK(p.gotbase == 0);
	mem_branch(&in, KGENOME_CELL_JMP, 0x1000, 6, KGENOME_CELL_REG_BX, 0xc, 0);
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_NONE);
}

static void endbr_join(void)
{
	struct kgenome_cell_plt p;
	struct kgenome_cell_plt_site site;
	struct kgenome_cell_insn in, eb;
	uint8_t buf[BASE_SZ];

	memset(buf, 0, sizeof buf);
	memcpy(buf + 0x10, endbr64, 4);                 /* the endbr64 is at file offset 0x10, address 0x1010 */
	kgenome_cell_plt_init(&p, buf, sizeof buf, 1);
	kgenome_cell_plt_ready(&p, NULL);
	memset(&eb, 0, sizeof eb);
	eb.op = KGENOME_CELL_OTHER;
	eb.len = 4;
	eb.at = 0x10;
	eb.at_va = 0x1010;
	/* endbr64 then the stub, directly after it: joined, and the endbr's own offset and address come back */
	CK(kgenome_cell_plt_at(&p, &eb, &site) == KGENOME_CELL_PLT_NONE);
	mem_branch(&in, KGENOME_CELL_JMP, 0x1014, 6, KGENOME_CELL_REG_NONE, 0x3000, 0);
	in.at = 0x14;
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_STUB && site.has_endbr && site.endbr_at == 0x10 && site.endbr_va == 0x1010);
	/* the stub itself is not an endbr: a second stub right after it is not joined to it */
	mem_branch(&in, KGENOME_CELL_JMP, 0x101a, 6, KGENOME_CELL_REG_NONE, 0x3008, 0);
	in.at = 0x1a;
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_STUB && !site.has_endbr);
	/* a gap between them: not joined */
	CK(kgenome_cell_plt_at(&p, &eb, &site) == KGENOME_CELL_PLT_NONE);
	mem_branch(&in, KGENOME_CELL_JMP, 0x1015, 6, KGENOME_CELL_REG_NONE, 0x3000, 0);
	in.at = 0x15;
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_STUB && !site.has_endbr);
	/* a reset between them (a new code extent), and a NULL instruction, break the join */
	CK(kgenome_cell_plt_at(&p, &eb, &site) == KGENOME_CELL_PLT_NONE);
	kgenome_cell_plt_reset(&p);
	mem_branch(&in, KGENOME_CELL_JMP, 0x1014, 6, KGENOME_CELL_REG_NONE, 0x3000, 0);
	in.at = 0x14;
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_STUB && !site.has_endbr);
	CK(kgenome_cell_plt_at(&p, &eb, &site) == KGENOME_CELL_PLT_NONE);
	CK(kgenome_cell_plt_at(&p, NULL, NULL) == KGENOME_CELL_PLT_NONE);
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_STUB && !site.has_endbr);
	/* an endbr before a call is not a stub: nothing is joined, and the answer is a SLOT */
	CK(kgenome_cell_plt_at(&p, &eb, &site) == KGENOME_CELL_PLT_NONE);
	mem_branch(&in, KGENOME_CELL_CALL, 0x1014, 6, KGENOME_CELL_REG_NONE, 0x3000, 0);
	in.at = 0x14;
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_SLOT && !site.has_endbr);
	/* four bytes that are not an endbr, and an endbr whose bytes lie past the buffer */
	memset(buf + 0x10, 0x90, 4);
	CK(kgenome_cell_plt_at(&p, &eb, &site) == KGENOME_CELL_PLT_NONE);
	mem_branch(&in, KGENOME_CELL_JMP, 0x1014, 6, KGENOME_CELL_REG_NONE, 0x3000, 0);
	in.at = 0x14;
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_STUB && !site.has_endbr);
	memcpy(buf + 0x10, endbr64, 4);
	eb.at = BASE_SZ - 2u;
	CK(kgenome_cell_plt_at(&p, &eb, &site) == KGENOME_CELL_PLT_NONE);
	mem_branch(&in, KGENOME_CELL_JMP, 0x1012, 6, KGENOME_CELL_REG_NONE, 0x3000, 0);
	in.at = 0x12;
	CK(kgenome_cell_plt_at(&p, &in, &site) == KGENOME_CELL_PLT_STUB && !site.has_endbr);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	kinds_and_sections();
	got_register();
	endbr_join();
	if (hk_fails) {
		printf("cell_plt: %d failure(s)\n", hk_fails);
		return 1;
	}
	printf("cell_plt: ok\n");
	return 0;
}
