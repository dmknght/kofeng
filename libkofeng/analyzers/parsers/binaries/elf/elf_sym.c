/*
 * elf_sym.c - build the KSYM block for an ELF.
 *
 * The layout and the reason for it are in kofmod/kofsym.h. This is the half that
 * reads ELF and fills it in, and the whole of what it has to get right is that
 * ELF states the same facts two different ways depending on the class:
 *
 *   Elf64_Sym  name(4) info(1) other(1) shndx(2) value(8) size(8)   24 bytes
 *   Elf32_Sym  name(4) value(4) size(4) info(1) other(1) shndx(2)   16 bytes
 *
 * Not the same fields in a smaller space - a DIFFERENT ORDER. A reader that
 * assumed one and met the other would take a size for an address and an address
 * for a name, and every field after the first would be wrong while still looking
 * like a number. That divergence is the clearest argument for re-presenting them
 * at all: one layout out, whatever came in.
 *
 * AND THE READING OF IT IS NOT HERE. kgenome_elf_symtab_of and kgenome_elf_symbol_at
 * in elf_parse.c do that, because by the time the sweep needed function
 * boundaries and relocation symbols the same twelve-way unpacking had been
 * written out three times. What is left here is the ENCODING - the KSYM
 * record, the flags that say what the fields only imply, the printable-only
 * policy and the `_start` search - and none of those is a fact about ELF.
 */

#include <string.h>

#include <kofcore.h>
#include <kofmod/kofsig.h>
#include <kofmod/elf.h>
#include <kofmod/kofsym.h>
#include "elf_sym.h"
#include "elf_parse.h"
#include "../funcs.h"
#include "../sym_pool.h"
#include <stdlib.h>

/*
 * One symbol, from what the shared reader has already unpacked, handed to the
 * writer. The name is read WHOLE - up to KOF_SYM_NAME_MAX, which is a DoS bound
 * and says so when it bites (the record's NAMECUT byte).
 */
static int one_rec(struct kof_symw *w, kof_buf strtab, const struct kgenome_elf_info *e,
		   const struct kgenome_elf_symbol *sy, char *nm, uint32_t *nm_len)
{
	struct kof_symrec r;
	uint32_t flags = 0, i;

	r.type = (uint8_t)(sy->info & 0xfu);
	r.bind = (uint8_t)(sy->info >> 4);
	r.vis  = (uint8_t)(sy->other & 0x3u);

	/*
	 * The flags say what the fields only imply, tested once here instead of
	 * by every rule that cares. IN_WRITABLE and IN_EXEC are the flags of the
	 * SECTION the symbol lands in, which is how a rule asks "is this data
	 * something the program could jump into" without re-deriving it.
	 */
	if (sy->shndx == KGENOME_ELF_SHN_UNDEF) {
		flags |= KOF_SYM_F_UNDEFINED;
	} else {
		flags |= KOF_SYM_F_DEFINED;
		if (sy->shndx < e->sec_count &&
		    sy->shndx < KGENOME_ELF_MAX_SECTIONS) {
			uint64_t sf = e->sec[sy->shndx].flags;

			if (sf & KGENOME_ELF_SHF_WRITE) flags |= KOF_SYM_F_IN_WRITABLE;
			if (sf & KGENOME_ELF_SHF_EXEC)  flags |= KOF_SYM_F_IN_EXEC;
		}
	}
	if (sy->size)
		flags |= KOF_SYM_F_HAS_SIZE;
	r.flags = (uint8_t)flags;

	/* 0xffff for anything that is not a real index, so a rule comparing the
	 * field never has to know which reserved value it met. */
	r.shndx = sy->shndx >= 0xff00u ? 0xffffu : (uint16_t)sy->shndx;
	r.value = sy->value;
	r.size  = sy->size;

	for (i = 0; i < KOF_SYM_NAME_MAX; i++) {
		uint8_t c = 0;

		if (!kof_rd_u8(strtab, (uint64_t)sy->nameoff + i, &c) || c == 0)
			break;
		/* Printable only: the name is compared against text in a rule,
		 * and a control byte from a hostile string table would end the
		 * pattern early or, worse, match one. */
		nm[i] = (char)(kof_is_print(c) ? c : '?');
	}
	/* The loop stopped on the bound and not on the end of the name: say the
	 * name goes on. */
	r.cut = 0;
	if (i == KOF_SYM_NAME_MAX) {
		uint8_t c = 0;

		if (kof_rd_u8(strtab, (uint64_t)sy->nameoff + i, &c) && c != 0)
			r.cut = 1;
	}
	r.name = nm;
	r.name_len = i;
	*nm_len = i;
	return kof_symw_put(w, &r);
}

/*
 * Fill `out` with the block. Returns the bytes written, which is at least the
 * header - a file with no symbols still gets a well-formed empty block, because
 * "there are none" is an answer and a reader should not have to tell it apart
 * from "this was never built".
 */
uint32_t kof_elf_syms(kof_buf file, const struct kgenome_elf_info *e,
		      uint8_t *out, uint32_t cap)
{
	struct kgenome_elf_symtab t;
	struct kof_symw w;
	uint32_t i, start = KOF_SYM_NO_START, want;
	uint64_t count;
	kof_buf strtab;
	char nm[KOF_SYM_NAME_MAX + 1u];

	if (!out || cap < KOF_SYM_HDRLEN || !e || !e->valid)
		return 0;

	/*
	 * .symtab, or .dynsym when the file was stripped - the shared reader
	 * makes that choice and reports which it made, so a rule that only
	 * makes sense against a full table can check rather than assume.
	 */
	if (!kgenome_elf_symtab_of(file, e, KGENOME_ELF_SYMTAB_BEST, &t) ||
	    !t.n_decl || !t.strn || t.str >= file.n) {
		/* An empty block is an answer: "there are none". */
		kof_symw_begin(&w, out, cap, 0, 0);
		out[KOF_SYM_H_ORIGIN] = KOF_SYM_ORIGIN_NONE;
		return kof_symw_end(&w);
	}
	strtab.p = file.p + t.str;
	/* A string table the file cuts short is read as far as it goes. */
	strtab.n = t.strn < file.n - t.str ? t.strn : file.n - t.str;

	/*
	 * THE COUNT THE FILE DECLARES, because `trunc` is a statement about
	 * what did not fit in `out` - not about what did not fit in the file,
	 * which the walk below discovers for itself when a read is refused.
	 */
	count = t.n_decl;
	want = count > 0xffffffffu ? 0xffffffffu : (uint32_t)count;
	kof_symw_begin(&w, out, cap, want, 0);

	for (i = 0; i < (uint32_t)count; i++) {
		struct kgenome_elf_symbol sy;
		uint32_t nlen = 0;

		if (!kgenome_elf_symbol_at(file, &t, i, &sy))
			break;
		if (!one_rec(&w, strtab, e, &sy, nm, &nlen))
			break;
		/*
		 * `_start`, noticed on the way past.
		 *
		 * Free here and nowhere else: the name has just been read, so
		 * this looks at memory that is already hot, and it is one
		 * comparison per symbol against a walk of every name that a
		 * caller would otherwise have to do for itself.
		 *
		 * The FIRST one wins. A well-formed object has one `_start`,
		 * but a hand-built or hostile table can repeat it, and taking
		 * the last would let a later duplicate push the starting point
		 * past records a caller must see. The first is the conservative
		 * choice: it can only make the walk longer.
		 */
		if (start == KOF_SYM_NO_START && nlen == 6u &&
		    !memcmp(nm, "_start", 6u))
			start = w.n - 1u;
	}
	i = kof_symw_end(&w);
	out[KOF_SYM_H_ORIGIN] = t.origin;
	kof_st_le16(out + KOF_SYM_H_START, (uint16_t)start);
	return i;
}


/* How many records the file's symbol table declares, for a caller that sizes the
 * block by the table it has. 0 when there is none to read. */
uint32_t kof_elf_syms_declared(kof_buf file, const struct kgenome_elf_info *e)
{
	struct kgenome_elf_symtab t;

	if (!e || !e->valid ||
	    !kgenome_elf_symtab_of(file, e, KGENOME_ELF_SYMTAB_BEST, &t) ||
	    !t.n_decl || !t.strn || t.str >= file.n)
		return 0;
	return t.n_decl > 0xffffffffu ? 0xffffffffu : (uint32_t)t.n_decl;
}
