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
 */

#include <string.h>

#include <kofcore.h>
#include <kofmod/kofsig.h>
#include <kofmod/elf.h>
#include <kofmod/kofsym.h>

#define SHT_SYMTAB_ 2
#define SHT_DYNSYM_ 11
#define SHT_STRTAB_ 3
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

/*
 * The string table that belongs to a symbol table, found BY NAME.
 *
 * sh_link is what ELF actually uses for this and it is not in the parsed
 * section - kof_elf_sec keeps what the region partition needs and no more. The
 * pairing is fixed by the ABI either way (.symtab with .strtab, .dynsym with
 * .dynstr), so the name answers it without re-reading the raw header. A file
 * that renames them loses its symbol block, which is the same thing stripping
 * does and is reported the same way: a count of zero.
 */
static const struct kof_elf_sec *strtab_for(const struct kof_elf_info *e,
					    const char *want)
{
	uint32_t i;

	for (i = 0; i < e->sec_count && i < KOF_ELF_MAX_SECTIONS; i++)
		if (e->sec[i].type == SHT_STRTAB_ &&
		    !strcmp(e->sec[i].name, want))
			return &e->sec[i];
	return 0;
}

/* One record. Returns 0 when the entry could not be read whole. */
static int one_rec(kof_buf file, const struct kof_elf_info *e, int be, int is64,
		   uint64_t ent, kof_buf strtab, uint8_t *rec)
{
	uint64_t value = 0, size = 0;
	uint32_t nameoff = 0;
	uint8_t info = 0, other = 0;
	uint16_t shndx = 0;
	uint32_t flags = 0, i;

	if (is64) {
		if (!kof_rd_u32(file, ent + 0,  be, &nameoff) ||
		    !kof_rd_u8 (file, ent + 4,      &info)    ||
		    !kof_rd_u8 (file, ent + 5,      &other)   ||
		    !kof_rd_u16(file, ent + 6,  be, &shndx)   ||
		    !kof_rd_u64(file, ent + 8,  be, &value)   ||
		    !kof_rd_u64(file, ent + 16, be, &size))
			return 0;
	} else {
		uint32_t v32 = 0, s32 = 0;

		if (!kof_rd_u32(file, ent + 0,  be, &nameoff) ||
		    !kof_rd_u32(file, ent + 4,  be, &v32)     ||
		    !kof_rd_u32(file, ent + 8,  be, &s32)     ||
		    !kof_rd_u8 (file, ent + 12,     &info)    ||
		    !kof_rd_u8 (file, ent + 13,     &other)   ||
		    !kof_rd_u16(file, ent + 14, be, &shndx))
			return 0;
		value = v32;
		size  = s32;
	}

	memset(rec, 0, KOF_SYM_RECLEN);
	rec[KOF_SYM_R_TYPE] = (uint8_t)(info & 0xfu);
	rec[KOF_SYM_R_BIND] = (uint8_t)(info >> 4);
	rec[KOF_SYM_R_VIS]  = (uint8_t)(other & 0x3u);

	/*
	 * The flags say what the fields only imply, tested once here instead of
	 * by every rule that cares. IN_WRITABLE and IN_EXEC are the flags of the
	 * SECTION the symbol lands in, which is how a rule asks "is this data
	 * something the program could jump into" without re-deriving it.
	 */
	if (shndx == SHN_UNDEF_) {
		flags |= KOF_SYM_F_UNDEFINED;
	} else {
		flags |= KOF_SYM_F_DEFINED;
		if (shndx < e->sec_count && shndx < KOF_ELF_MAX_SECTIONS) {
			uint64_t sf = e->sec[shndx].flags;

			if (sf & SHF_WRITE_) flags |= KOF_SYM_F_IN_WRITABLE;
			if (sf & SHF_EXEC_)  flags |= KOF_SYM_F_IN_EXEC;
		}
	}
	if (size)
		flags |= KOF_SYM_F_HAS_SIZE;
	rec[KOF_SYM_R_FLAGS] = (uint8_t)flags;

	/* 0xffff for anything that is not a real index, so a rule comparing the
	 * field never has to know which reserved value it met. */
	put16(rec + KOF_SYM_R_SHNDX,
	      shndx >= 0xff00u ? 0xffffu : (uint32_t)shndx);
	put64(rec + KOF_SYM_R_VALUE, value);
	put64(rec + KOF_SYM_R_SIZE,  size);

	for (i = 0; i + 1u < KOF_SYM_NAMELEN; i++) {
		uint8_t c = 0;

		if (!kof_rd_u8(strtab, (uint64_t)nameoff + i, &c) || c == 0)
			break;
		/* Printable only: the field is compared against text in a rule,
		 * and a control byte from a hostile string table would end the
		 * pattern early or, worse, match one. */
		rec[KOF_SYM_R_NAME + i] = (c >= 0x20u && c < 0x7fu) ? c : '?';
	}
	return 1;
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
	const struct kof_elf_sec *sym = 0, *str = 0;
	uint32_t i, n = 0, want, trunc = 0;
	uint8_t origin = KOF_SYM_ORIGIN_NONE;
	uint64_t entsz, count;
	kof_buf strtab;
	int is64, be;

	if (!out || cap < KOF_SYM_HDRLEN || !e || !e->valid)
		return 0;
	memset(out, 0, KOF_SYM_HDRLEN);
	out[KOF_SYM_H_MAGIC + 0] = KOF_SYM_MAGIC0;
	out[KOF_SYM_H_MAGIC + 1] = KOF_SYM_MAGIC1;
	out[KOF_SYM_H_MAGIC + 2] = KOF_SYM_MAGIC2;
	out[KOF_SYM_H_MAGIC + 3] = KOF_SYM_MAGIC3;
	put16(out + KOF_SYM_H_VERSION, KOF_SYM_VERSION);
	put16(out + KOF_SYM_H_RECLEN,  KOF_SYM_RECLEN);

	is64 = e->elf_class == KOF_ELFCLASS_64;
	be   = e->elf_data  == KOF_ELFDATA_BE;
	entsz = is64 ? 24u : 16u;

	/*
	 * .symtab first, .dynsym only when there is none.
	 *
	 * .symtab is the whole table and .dynsym is the part dynamic linking
	 * needs; a stripped file keeps the second and loses the first. Preferring
	 * the fuller one means a rule sees every symbol when the file still has
	 * them, and the header's origin byte says which it got - so a rule that
	 * only makes sense against a full table can check rather than assume.
	 */
	for (i = 0; i < e->sec_count && i < KOF_ELF_MAX_SECTIONS; i++)
		if (e->sec[i].type == SHT_SYMTAB_) { sym = &e->sec[i]; break; }
	if (sym) {
		str = strtab_for(e, ".strtab");
		origin = KOF_SYM_ORIGIN_SYMTAB;
	} else {
		for (i = 0; i < e->sec_count && i < KOF_ELF_MAX_SECTIONS; i++)
			if (e->sec[i].type == SHT_DYNSYM_) { sym = &e->sec[i]; break; }
		if (sym) {
			str = strtab_for(e, ".dynstr");
			origin = KOF_SYM_ORIGIN_DYNSYM;
		}
	}
	if (!sym || !str || sym->file_size < entsz) {
		out[KOF_SYM_H_ORIGIN] = KOF_SYM_ORIGIN_NONE;
		return KOF_SYM_HDRLEN;
	}

	strtab.p = file.p + str->file_off;
	strtab.n = str->file_size;
	if (str->file_off > file.n || str->file_off + str->file_size > file.n) {
		out[KOF_SYM_H_ORIGIN] = KOF_SYM_ORIGIN_NONE;
		return KOF_SYM_HDRLEN;
	}

	count = sym->file_size / entsz;
	want  = (uint32_t)((cap - KOF_SYM_HDRLEN) / KOF_SYM_RECLEN);
	if (want > KOF_SYM_MAX_RECS)
		want = KOF_SYM_MAX_RECS;
	if (count > want) { count = want; trunc = 1; }

	for (i = 0; i < (uint32_t)count; i++) {
		uint8_t *rec = out + KOF_SYM_HDRLEN + (uint64_t)n * KOF_SYM_RECLEN;

		if (!one_rec(file, e, be, is64,
			     sym->file_off + (uint64_t)i * entsz, strtab, rec))
			break;
		n++;
	}
	out[KOF_SYM_H_ORIGIN] = origin;
	out[KOF_SYM_H_TRUNC]  = (uint8_t)trunc;
	put32(out + KOF_SYM_H_COUNT, n);
	return KOF_SYM_HDRLEN + n * KOF_SYM_RECLEN;
}
