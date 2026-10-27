/*
 * elf_semantics - kgenome_elf_shape, kgenome_elf_entry_sec.
 * Oracle: views built by hand (no parse), each linking case, stripped and not, with and without debug, an entry in no section,
 * in a NOBITS section, hostile counts, addresses 0 and UINT64_MAX. Linked against libkgenome.a alone.
 */
#include <kgenome.h>

#include "hk.h"

static struct kgenome_elf_info I;

static void reset(void)
{
	memset(&I, 0, sizeof I);
	I.valid = 1;
}

static void seg(uint32_t t)
{
	I.seg[I.seg_count++].type = t;
}

static void sec(const char *name, uint32_t type, uint64_t flags, uint64_t addr, uint64_t size)
{
	struct kgenome_elf_sec *s = &I.sec[I.sec_count++];

	snprintf(s->name, sizeof s->name, "%s", name);
	s->type = type;
	s->flags = flags;
	s->mem_addr = addr;
	s->file_size = size;
}

static void shape(void)
{
	struct kgenome_elf_shape s;

	reset(); seg(1);
	kgenome_elf_shape(&I, &s);
	CK(s.linking == KGENOME_ELF_LINK_STATIC && !s.has_symtab && !s.has_debug);
	reset(); seg(1); seg(2); seg(3);
	kgenome_elf_shape(&I, &s);
	CK(s.linking == KGENOME_ELF_LINK_DYNAMIC);
	reset(); seg(1); seg(2);
	kgenome_elf_shape(&I, &s);
	CK(s.linking == KGENOME_ELF_LINK_DYNAMIC_NOINTERP);
	reset();
	kgenome_elf_shape(&I, &s);
	CK(s.linking == KGENOME_ELF_LINK_NONE);
	/* symbol table: only a SHT_SYMTAB of non-zero size; a .dynsym or an empty .symtab is not it */
	reset(); seg(1); sec(".symtab", 2, 0, 0, 0x100);
	kgenome_elf_shape(&I, &s);
	CK(s.has_symtab && !s.has_debug);
	reset(); seg(1); sec(".symtab", 2, 0, 0, 0); sec(".dynsym", 11, 2, 0, 64);
	kgenome_elf_shape(&I, &s);
	CK(!s.has_symtab);
	/* debug: the name prefix, not a name that merely contains it */
	reset(); seg(1); sec(".debug_info", 1, 0, 0, 4);
	kgenome_elf_shape(&I, &s);
	CK(s.has_debug && !s.has_symtab);
	reset(); seg(1); sec(".mydebug_x", 1, 0, 0, 4); sec(".debug", 1, 0, 0, 4);
	kgenome_elf_shape(&I, &s);
	CK(!s.has_debug);
	reset(); seg(1); sec(".symtab", 2, 0, 0, 8); sec(".debug_line", 1, 0, 0, 8);
	kgenome_elf_shape(&I, &s);
	CK(s.has_symtab && s.has_debug);
	/* an invalid view and hostile counts */
	reset(); I.valid = 0; seg(1);
	kgenome_elf_shape(&I, &s);
	CK(s.linking == KGENOME_ELF_LINK_NONE);
	reset(); I.seg_count = 0xffffffffu; I.sec_count = 0xffffffffu;
	kgenome_elf_shape(&I, &s);
	CK(s.linking == KGENOME_ELF_LINK_NONE);
}

static void entry(void)
{
	uint32_t i = 99;
	uint64_t d = 99;

	reset();
	sec("", 0, 0, 0, 0);
	sec(".text", 1, 6, 0x80b0, 0x120ac);
	sec(".bss", 8, 3, 0x30000, 0x100);
	sec(".comment", 1, 0, 0x50000, 0x10);                /* no SHF_ALLOC */
	I.entry_addr = 0x8190;
	CK(kgenome_elf_entry_sec(&I, &i, &d) == 0 && i == 1 && d == 0xe0);
	I.entry_addr = 0x80b0;
	CK(kgenome_elf_entry_sec(&I, &i, &d) == 0 && i == 1 && d == 0);
	I.entry_addr = 0x80b0 + 0x120ac;                     /* one past the end */
	i = 99; d = 99;
	CK(kgenome_elf_entry_sec(&I, &i, &d) == -1 && i == 99 && d == 99);
	I.entry_addr = 0x30010;                              /* inside a NOBITS section: not code */
	CK(kgenome_elf_entry_sec(&I, &i, &d) == -1);
	I.entry_addr = 0x50004;                              /* not allocated */
	CK(kgenome_elf_entry_sec(&I, &i, &d) == -1);
	I.entry_addr = 0;                                    /* the NULL section and addr 0 */
	CK(kgenome_elf_entry_sec(&I, &i, &d) == -1);
	I.entry_addr = UINT64_MAX;
	CK(kgenome_elf_entry_sec(&I, &i, &d) == -1);
	/* a section at the top of the address space: addr + size would wrap, the range test must not */
	reset();
	sec(".hi", 1, 2, UINT64_MAX - 0x10, UINT64_MAX);
	I.entry_addr = UINT64_MAX;
	CK(kgenome_elf_entry_sec(&I, &i, &d) == 0 && d == 0x10);
	I.entry_addr = 0x5;
	CK(kgenome_elf_entry_sec(&I, &i, &d) == -1);
	/* overlap: the first wins; invalid view; hostile count */
	reset();
	sec("a", 1, 2, 0x1000, 0x100); sec("b", 1, 2, 0x1000, 0x100);
	I.entry_addr = 0x1010;
	CK(kgenome_elf_entry_sec(&I, &i, &d) == 0 && i == 0);
	I.valid = 0;
	CK(kgenome_elf_entry_sec(&I, &i, &d) == -1);
	I.valid = 1; I.sec_count = 0xffffffffu;
	CK(kgenome_elf_entry_sec(&I, &i, &d) == 0);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	shape();
	entry();
	printf("elf_semantics: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
