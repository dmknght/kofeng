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
 * AND THE READING OF IT IS NOT HERE. kof_elf_symtab_of and kof_elf_symbol_at
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

#define SHN_UNDEF_  0
#define SHF_WRITE_  0x1
#define SHF_EXEC_   0x4

static void put16(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t v)
{
	put16(p, v & 0xffffu); put16(p + 2, v >> 16);
}

static void put64(uint8_t *p, uint64_t v)
{
	put32(p, (uint32_t)v); put32(p + 4, (uint32_t)(v >> 32));
}

/* One record, from a symbol the shared reader has already unpacked. */
static void one_rec(kof_buf strtab, const struct kof_elf_info *e,
		    const struct kof_elf_symbol *sy, uint8_t *rec)
{
	uint32_t flags = 0, i;

	memset(rec, 0, KOF_SYM_RECLEN);
	rec[KOF_SYM_R_TYPE] = (uint8_t)(sy->info & 0xfu);
	rec[KOF_SYM_R_BIND] = (uint8_t)(sy->info >> 4);
	rec[KOF_SYM_R_VIS]  = (uint8_t)(sy->other & 0x3u);

	/*
	 * The flags say what the fields only imply, tested once here instead of
	 * by every rule that cares. IN_WRITABLE and IN_EXEC are the flags of the
	 * SECTION the symbol lands in, which is how a rule asks "is this data
	 * something the program could jump into" without re-deriving it.
	 */
	if (sy->shndx == SHN_UNDEF_) {
		flags |= KOF_SYM_F_UNDEFINED;
	} else {
		flags |= KOF_SYM_F_DEFINED;
		if (sy->shndx < e->sec_count &&
		    sy->shndx < KOF_ELF_MAX_SECTIONS) {
			uint64_t sf = e->sec[sy->shndx].flags;

			if (sf & SHF_WRITE_) flags |= KOF_SYM_F_IN_WRITABLE;
			if (sf & SHF_EXEC_)  flags |= KOF_SYM_F_IN_EXEC;
		}
	}
	if (sy->size)
		flags |= KOF_SYM_F_HAS_SIZE;
	rec[KOF_SYM_R_FLAGS] = (uint8_t)flags;

	/* 0xffff for anything that is not a real index, so a rule comparing the
	 * field never has to know which reserved value it met. */
	put16(rec + KOF_SYM_R_SHNDX,
	      sy->shndx >= 0xff00u ? 0xffffu : (uint32_t)sy->shndx);
	put64(rec + KOF_SYM_R_VALUE, sy->value);
	put64(rec + KOF_SYM_R_SIZE,  sy->size);

	for (i = 0; i + 1u < KOF_SYM_NAMELEN; i++) {
		uint8_t c = 0;

		if (!kof_rd_u8(strtab, (uint64_t)sy->nameoff + i, &c) || c == 0)
			break;
		/* Printable only: the field is compared against text in a rule,
		 * and a control byte from a hostile string table would end the
		 * pattern early or, worse, match one. */
		rec[KOF_SYM_R_NAME + i] = kof_is_print(c) ? c : '?';
	}
}

/*
 * Fill `out` with the block. Returns the bytes written, which is at least the
 * header - a file with no symbols still gets a well-formed empty block, because
 * "there are none" is an answer and a reader should not have to tell it apart
 * from "this was never built".
 */
uint32_t kof_elf_syms(kof_buf file, const struct kof_elf_info *e,
		      uint8_t *out, uint32_t cap)
{
	struct kof_elf_symtab t;
	uint32_t i, n = 0, want, trunc = 0, start = KOF_SYM_NO_START;
	uint64_t count;
	kof_buf strtab;

	if (!out || cap < KOF_SYM_HDRLEN || !e || !e->valid)
		return 0;
	memset(out, 0, KOF_SYM_HDRLEN);
	out[KOF_SYM_H_MAGIC + 0] = KOF_SYM_MAGIC0;
	out[KOF_SYM_H_MAGIC + 1] = KOF_SYM_MAGIC1;
	out[KOF_SYM_H_MAGIC + 2] = KOF_SYM_MAGIC2;
	out[KOF_SYM_H_MAGIC + 3] = KOF_SYM_MAGIC3;
	put16(out + KOF_SYM_H_VERSION, KOF_SYM_VERSION);
	put16(out + KOF_SYM_H_RECLEN,  KOF_SYM_RECLEN);
	/*
	 * ABSENT, written before anything can return early.
	 *
	 * The memset above leaves this field zero, and zero is a VALID INDEX -
	 * a reader would take it as "`_start` is record 0, begin at record 1"
	 * and skip the first record of a block that has no `_start` at all.
	 * The two early returns below - no string table, or one that does not
	 * fit the file - both reach a caller through this header, so the honest
	 * value has to be in place before them rather than at the end with the
	 * count.
	 */
	put16(out + KOF_SYM_H_START, KOF_SYM_NO_START);

	/*
	 * .symtab, or .dynsym when the file was stripped - the shared reader
	 * makes that choice and reports which it made, so a rule that only
	 * makes sense against a full table can check rather than assume.
	 */
	if (!kof_elf_symtab_of(file, e, KOF_ELF_SYMTAB_BEST, &t) ||
	    !t.n_decl || !t.strn ||
	    t.str > file.n || t.str + t.strn > file.n) {
		out[KOF_SYM_H_ORIGIN] = KOF_SYM_ORIGIN_NONE;
		return KOF_SYM_HDRLEN;
	}
	strtab.p = file.p + t.str;
	strtab.n = t.strn;

	/*
	 * THE COUNT THE FILE DECLARES, because `trunc` is a statement about
	 * what did not fit in `out` - not about what did not fit in the file,
	 * which the walk below discovers for itself when a read is refused.
	 */
	count = t.n_decl;
	want  = (uint32_t)((cap - KOF_SYM_HDRLEN) / KOF_SYM_RECLEN);
	if (want > KOF_SYM_MAX_RECS)
		want = KOF_SYM_MAX_RECS;
	if (count > want) { count = want; trunc = 1; }

	for (i = 0; i < (uint32_t)count; i++) {
		uint8_t *rec = out + KOF_SYM_HDRLEN +
			       (uint64_t)n * KOF_SYM_RECLEN;
		struct kof_elf_symbol sy;

		if (!kof_elf_symbol_at(file, &t, i, &sy))
			break;
		one_rec(strtab, e, &sy, rec);
		/*
		 * `_start`, noticed on the way past.
		 *
		 * Free here and nowhere else: the record's name has just been
		 * written, so this reads memory that is already hot, and it is
		 * seven bytes compared once per symbol against a walk of every
		 * name that a caller would otherwise have to do for itself.
		 *
		 * The FIRST one wins. A well-formed object has one `_start`,
		 * but a hand-built or hostile table can repeat it, and taking
		 * the last would let a later duplicate push the starting point
		 * past records a caller must see. The first is the conservative
		 * choice: it can only make the walk longer.
		 */
		if (start == KOF_SYM_NO_START &&
		    rec[KOF_SYM_R_NAME + 0] == '_' &&
		    rec[KOF_SYM_R_NAME + 1] == 's' &&
		    rec[KOF_SYM_R_NAME + 2] == 't' &&
		    rec[KOF_SYM_R_NAME + 3] == 'a' &&
		    rec[KOF_SYM_R_NAME + 4] == 'r' &&
		    rec[KOF_SYM_R_NAME + 5] == 't' &&
		    rec[KOF_SYM_R_NAME + 6] == 0)
			start = n;
		n++;
	}
	out[KOF_SYM_H_ORIGIN] = t.origin;
	out[KOF_SYM_H_TRUNC]  = (uint8_t)trunc;
	put32(out + KOF_SYM_H_COUNT, n);
	put16(out + KOF_SYM_H_START, start);
	return KOF_SYM_HDRLEN + n * KOF_SYM_RECLEN;
}
