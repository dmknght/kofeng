/*
 * elf_sec_stub - which executable section is the program's own and which is the
 * loader's or the linker's, decided by flags and the entry point, never by a name.
 *
 * The xref sweep marks "startup" regions so that what they call is not taken as use.
 * It used to be every executable section whose NAME was not ".text" (.init, .fini, the
 * PLT). That is a name deciding what is evidence: a program whose body is not called
 * ".text" (a packed or hand-linked one) was all startup, and a ".text" that is not
 * where the entry point is was never. Now: an executable (PROGBITS + EXECINSTR)
 * section other than the one the entry point lies in.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <genotype/image/elf_image.h>

static int fails;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static void sec(struct kgenome_elf_info *e, unsigned i, const char *name, uint64_t addr, uint64_t size,
		uint32_t type, uint64_t flags)
{
	memset(&e->sec[i], 0, sizeof e->sec[i]);
	snprintf(e->sec[i].name, sizeof e->sec[i].name, "%s", name);
	e->sec[i].mem_addr = addr;
	e->sec[i].file_size = size;
	e->sec[i].type = type;
	e->sec[i].flags = flags;
}

static struct kgenome_elf_info e;

static void layout(const char *body_name, const char *stub_name, uint64_t entry)
{
	memset(&e, 0, sizeof e);
	e.valid = 1;
	e.sec_count = 5;
	e.entry_addr = entry;
	sec(&e, 0, "", 0, 0, 0, 0);
	sec(&e, 1, stub_name, 0x1000, 0x20, KGENOME_ELF_SHT_PROGBITS, KGENOME_ELF_SHF_EXEC);   /* .init */
	sec(&e, 2, ".plt", 0x1020, 0x60, KGENOME_ELF_SHT_PROGBITS, KGENOME_ELF_SHF_EXEC);
	sec(&e, 3, body_name, 0x1100, 0x800, KGENOME_ELF_SHT_PROGBITS, KGENOME_ELF_SHF_EXEC);
	sec(&e, 4, ".data", 0x3000, 0x100, KGENOME_ELF_SHT_PROGBITS, 0);
}

int main(void)
{
	/* the ordinary shape: entry in .text, .init and .plt are stubs */
	layout(".text", ".init", 0x1100);
	CK(!kgenome_elf_sec_is_stub(&e, 3));
	CK(kgenome_elf_sec_is_stub(&e, 1));
	CK(kgenome_elf_sec_is_stub(&e, 2));
	CK(!kgenome_elf_sec_is_stub(&e, 4));            /* not code at all */
	CK(!kgenome_elf_sec_is_stub(&e, 0));
	CK(!kgenome_elf_sec_is_stub(&e, 99));           /* out of range */

	/* the name decides nothing: the body is called ".code" and a stub ".text" */
	layout(".code", ".text", 0x1100);
	CK(!kgenome_elf_sec_is_stub(&e, 3));            /* the old rule called this startup */
	CK(kgenome_elf_sec_is_stub(&e, 1));             /* and this the program */
	layout(".text", ".text", 0x1005);               /* entry inside the first section */
	CK(!kgenome_elf_sec_is_stub(&e, 1));
	CK(kgenome_elf_sec_is_stub(&e, 3));

	/* the entry in no executable section (or none declared): nothing to compare with */
	layout(".text", ".init", 0x3010);               /* entry in .data */
	CK(!kgenome_elf_sec_is_stub(&e, 1) && !kgenome_elf_sec_is_stub(&e, 3));
	layout(".text", ".init", 0);
	CK(!kgenome_elf_sec_is_stub(&e, 1) && !kgenome_elf_sec_is_stub(&e, 3));
	layout(".text", ".init", 0x1100 + 0x800);       /* one past the end of the body */
	CK(!kgenome_elf_sec_is_stub(&e, 1) && !kgenome_elf_sec_is_stub(&e, 3));
	e.valid = 0;
	layout(".text", ".init", 0x1100);
	e.valid = 0;
	CK(!kgenome_elf_sec_is_stub(&e, 1));

	if (fails) {
		printf("elf_sec_stub: %d check(s) failed\n", fails);
		return 1;
	}
	printf("elf_sec_stub: startup stubs are the executable sections the entry is not in, by flags\n");
	return 0;
}
