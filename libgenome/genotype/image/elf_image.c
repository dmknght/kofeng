/*
 * elf_image.c - the structure of an ELF: header, program and section tables,
 * claims, and the tables walked on demand (symbols, imports, relocations).
 *
 * The BODY of what libkofeng/analyzers/parsers/binaries/elf/elf_parse.c was.
 * What stayed there is the engine side: the scan-region partition
 * (elf_resolve_scan), the names for tools and kof_elf_parse, the adapter that
 * calls kgenome_elf_image_parse and attaches the partition. Nothing here includes
 * the engine. The original file comment follows, unchanged.
 */

/*
 * elf_parse.c - ELF header, program header and section header collector.
 *
 * Segments are read before sections and treated as authoritative. That is not
 * an ordering convenience: the kernel loader needs only the program headers, so
 * an object whose section table has been stripped or forged still runs. Any
 * reasoning about what executes should come from segments, with section
 * disagreement reported as signal rather than resolved silently.
 *
 * Two rules hold throughout:
 *
 *   - never fail, always describe. A malformed field produces an anomaly bit,
 *     not an early return. Refusing would go blind on exactly the inputs worth
 *     looking at, and the malformation is itself evidence.
 *
 *   - every read goes through kofcore. No pointer arithmetic, no local bounds
 *     checks, and no count taken from the file is trusted before it is clamped.
 */

#include "elf_image.h"
#include <kofcmp.h>
#include <kofdebug.h>
#include <rangelist.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* e_ident indices */
#define EI_MAG0		0
#define EI_CLASS	4
#define EI_DATA		5
#define EI_VERSION	6
#define EI_OSABI	7
#define EI_ABIVERSION	8

#define ELFCLASS32	1
#define ELFCLASS64	2
#define ELFDATA2LSB	1
#define ELFDATA2MSB	2
#define EV_CURRENT	1

/* Header sizes per class. */
#define EHDR32_SIZE	52
#define EHDR64_SIZE	64
#define PHDR32_SIZE	32
#define PHDR64_SIZE	56
#define SHDR32_SIZE	40
#define SHDR64_SIZE	64

/* e_machine values worth normalising. Anything else becomes KGENOME_ARCH_OTHER. */
#define EM_386		3
#define EM_MIPS		8
#define EM_PPC		20
#define EM_PPC64	21
#define EM_ARM		40
#define EM_ARC_COMPACT	93
#define EM_ARC_COMPACT2	195
#define EM_ARC		45
#define EM_SPARC	2
#define EM_68K		4
#define EM_SPARC32PLUS	18
#define EM_SH		42
#define EM_SPARCV9	43
#define EM_OPENRISC	92
#define EM_XTENSA	94
#define EM_CRIS		113
#define EM_MICROBLAZE	189
#define EM_X86_64	62
#define EM_AARCH64	183
#define EM_RISCV	243

/*
 * e_phnum == PN_XNUM means the real count lives in the section table. Not
 * handled yet; flagged so the gap shows up in a corpus rather than silently.
 */
#define PN_XNUM		0xffff

/* See elf.h for which view is which, and why both exist. */
int kgenome_elf_seg_is_code(const struct kgenome_elf_seg *g)
{
	return g->type == KGENOME_ELF_PT_LOAD && (g->perm & KGENOME_PERM_X) != 0;
}

uint64_t kgenome_elf_seg_extent(const struct kgenome_elf_seg *g, uint64_t obj_size,
			    uint64_t *off)
{
	*off = g->file_off;
	return kof_clip_len(obj_size, g->file_off, g->file_size);
}

int kgenome_elf_sec_is_code(const struct kgenome_elf_sec *s)
{
	return s->type == KGENOME_ELF_SHT_PROGBITS && (s->flags & KGENOME_ELF_SHF_EXEC) != 0;
}

int kgenome_elf_sec_is_stub(const struct kgenome_elf_info *e, uint32_t i)
{
	uint32_t k, home = e->sec_count;

	if (!e->valid || !e->entry_addr || i >= e->sec_count ||
	    i >= KGENOME_ELF_MAX_SECTIONS || !kgenome_elf_sec_is_code(&e->sec[i]))
		return 0;
	/* The program's own code is the executable section the entry point is in; the
	 * others are the loader's and the linker's (.init, .fini, the PLT, ...). An
	 * entry in no executable section says nothing about which is which. */
	for (k = 0; k < e->sec_count && k < KGENOME_ELF_MAX_SECTIONS; k++) {
		const struct kgenome_elf_sec *s = &e->sec[k];

		if (kgenome_elf_sec_is_code(s) && e->entry_addr >= s->mem_addr &&
		    e->entry_addr - s->mem_addr < s->file_size) {
			home = k;
			break;
		}
	}
	return home < e->sec_count && home != i;
}

uint64_t kgenome_elf_sec_extent(const struct kgenome_elf_sec *s, uint64_t obj_size,
			    uint64_t *off)
{
	*off = s->file_off;
	return kof_clip_len(obj_size, s->file_off, s->file_size);
}

static uint32_t perm_from_pflags(uint32_t f)
{
	uint32_t p = 0;
	if (f & KGENOME_ELF_PF_X) p |= KGENOME_PERM_X;
	if (f & KGENOME_ELF_PF_W) p |= KGENOME_PERM_W;
	if (f & KGENOME_ELF_PF_R) p |= KGENOME_PERM_R;
	return p;
}

/*
 * Normalise e_machine. Only the common tier uses this; a module that needs the
 * exact value reads e_machine from the ELF view, where the constant it compares
 * against is an ELF constant and therefore comparable.
 *
 * MIPS and RISC-V name one machine for both widths, so the class decides which it
 * is. PowerPC names two. Getting the width from the class rather than defaulting
 * to 64 is what makes an m32 object report m32 instead of being filed with m64 -
 * and a precondition on architecture is only worth declaring if it is that exact.
 */
static uint8_t arch_from_machine(uint16_t m, int is64)
{
	switch (m) {
	case EM_386:     return KGENOME_ARCH_X86;
	case EM_X86_64:  return KGENOME_ARCH_X86_64;
	case EM_ARM:     return KGENOME_ARCH_ARM;
	case EM_AARCH64: return KGENOME_ARCH_ARM64;
	case EM_RISCV:   return is64 ? KGENOME_ARCH_RISCV64 : KGENOME_ARCH_RISCV32;
	case EM_MIPS:    return is64 ? KGENOME_ARCH_MIPS64  : KGENOME_ARCH_MIPS;
	case EM_PPC:     return KGENOME_ARCH_PPC;
	case EM_PPC64:   return KGENOME_ARCH_PPC64;
	/*
	 * ARC IS THREE MACHINE NUMBERS FOR ONE ARCHITECTURE. 45 is the
	 * original, 93 is ARCompact and 195 is ARCv2; a toolchain picks one and
	 * a rule written about "arc" means whichever it was built with. They
	 * are not different targets to anything that reads this - a precondition
	 * on architecture is about which instruction set the bytes are, and all
	 * three are ARC.
	 */
	case EM_ARC:
	case EM_ARC_COMPACT:
	case EM_ARC_COMPACT2: return KGENOME_ARCH_ARC;
	/*
	 * The rest of the cross-compile set a botnet makefile ships. See
	 * KGENOME_ARCH_LIST for the counts these were chosen from and for the
	 * three that were deliberately left reporting OTHER.
	 */
	case EM_SH:      return KGENOME_ARCH_SH;
	case EM_68K:     return KGENOME_ARCH_M68K;
	/* v8plus is 32-bit SPARC with v9 instructions available; the object
	 * is still a 32-bit one and every existing pair in this switch is
	 * split by width. */
	case EM_SPARC:
	case EM_SPARC32PLUS: return KGENOME_ARCH_SPARC;
	case EM_SPARCV9: return KGENOME_ARCH_SPARC64;
	case EM_MICROBLAZE: return KGENOME_ARCH_MICROBLAZE;
	case EM_XTENSA:  return KGENOME_ARCH_XTENSA;
	case EM_CRIS:    return KGENOME_ARCH_CRIS;
	case EM_OPENRISC: return KGENOME_ARCH_OR1K;
	default:         return KGENOME_ARCH_OTHER;
	}
}

/* FNV-1a over a NUL terminated name, bounded by the buffer it lives in. Used so
 * a name comparison survives the truncation applied to the stored copy. */
static uint32_t name_hash(kof_buf strtab, uint64_t off, int *out_truncated)
{
	uint32_t h = KOF_HASH_INIT;
	uint64_t i;

	*out_truncated = 0;
	for (i = 0; i < KGENOME_ELF_SECNAME_SCAN; i++) {
		uint8_t c;
		if (!kof_rd_u8(strtab, off + i, &c) || c == 0)
			break;
		h = kof_hash_step(h, c);
	}
	/*
	 * Truncated whether the name outran the stored copy or the scan bound: both
	 * mean the printed name is shorter than the real one, and the second is also
	 * how a hostile string table is stopped from being scanned end to end. See
	 * KGENOME_ELF_SECNAME_SCAN.
	 */
	if (i >= KGENOME_ELF_SECNAME_MAX)
		*out_truncated = 1;
	return h;
}

/*
 * Read one program header. The field order differs between classes in a way
 * that is easy to get wrong: p_flags sits after p_type in ELF64 but after
 * p_memsz in ELF32. Keeping both layouts in one place makes the difference
 * reviewable instead of scattered.
 */
static int read_phdr(kof_buf ph, int is64, int be, struct kgenome_elf_seg *s,
		     uint32_t *out_flags)
{
	if (is64) {
		return kof_rd_u32(ph,  0, be, &s->type)      &&
		       kof_rd_u32(ph,  4, be, out_flags)     &&
		       kof_rd_u64(ph,  8, be, &s->file_off)  &&
		       kof_rd_u64(ph, 16, be, &s->mem_addr)  &&
		       kof_rd_u64(ph, 32, be, &s->file_size) &&
		       kof_rd_u64(ph, 40, be, &s->mem_size);
	}
	{
		uint32_t off32, vaddr32, filesz32, memsz32;
		if (!(kof_rd_u32(ph,  0, be, &s->type)  &&
		      kof_rd_u32(ph,  4, be, &off32)    &&
		      kof_rd_u32(ph,  8, be, &vaddr32)  &&
		      kof_rd_u32(ph, 16, be, &filesz32) &&
		      kof_rd_u32(ph, 20, be, &memsz32)  &&
		      kof_rd_u32(ph, 24, be, out_flags)))
			return 0;
		s->file_off  = off32;
		s->mem_addr  = vaddr32;
		s->file_size = filesz32;
		s->mem_size  = memsz32;
		return 1;
	}
}

/* sh_link and sh_info, which sit after the fields the section needs to be counted at
 * all: a header cut off before them is still a section (it was one before they were read
 * and stays one), with the two words zero, which no consumer reads as a link. */
static int link_info(kof_buf sh, uint64_t at, int be, uint32_t *link, uint32_t *info)
{
	if (!kof_rd_u32(sh, at, be, link))
		*link = 0;
	if (!kof_rd_u32(sh, at + 4u, be, info))
		*info = 0;
	return 1;
}

/* Read one section header. Returns the name index separately: resolving it
 * needs the string table, which is itself one of the sections. */
static int read_shdr(kof_buf sh, int is64, int be, struct kgenome_elf_sec *s,
		     uint32_t *out_name_idx, uint32_t *out_link, uint32_t *out_info)
{
	if (is64) {
		return kof_rd_u32(sh,  0, be, out_name_idx)  &&
		       kof_rd_u32(sh,  4, be, &s->type)      &&
		       kof_rd_u64(sh,  8, be, &s->flags)     &&
		       kof_rd_u64(sh, 16, be, &s->mem_addr)  &&
		       kof_rd_u64(sh, 24, be, &s->file_off)  &&
		       kof_rd_u64(sh, 32, be, &s->file_size) &&
		       link_info(sh, 40, be, out_link, out_info);
	}
	{
		uint32_t flags32, addr32, off32, size32;
		if (!(kof_rd_u32(sh,  0, be, out_name_idx) &&
		      kof_rd_u32(sh,  4, be, &s->type)     &&
		      kof_rd_u32(sh,  8, be, &flags32)     &&
		      kof_rd_u32(sh, 12, be, &addr32)      &&
		      kof_rd_u32(sh, 16, be, &off32)       &&
		      kof_rd_u32(sh, 20, be, &size32)      &&
		      link_info(sh, 24, be, out_link, out_info)))
			return 0;
		s->flags     = flags32;
		s->mem_addr  = addr32;
		s->file_off  = off32;
		s->file_size = size32;
		return 1;
	}
}

/* Overlap in the virtual address space of two PT_LOAD segments. */
static int vaddr_overlap(const struct kgenome_elf_seg *a, const struct kgenome_elf_seg *b)
{
	uint64_t a_end, b_end;
	if (a->mem_size == 0 || b->mem_size == 0)
		return 0;
	/* mem_size is untrusted; saturate instead of wrapping. */
	a_end = kof_sat_add(a->mem_addr, a->mem_size);
	b_end = kof_sat_add(b->mem_addr, b->mem_size);
	return a->mem_addr < b_end && b->mem_addr < a_end;
}

static void parse_sections(kof_buf file, struct kgenome_elf_info *info,
			   int is64, int be, uint64_t *anom)
{
	uint64_t shdr_size = is64 ? SHDR64_SIZE : SHDR32_SIZE;
	uint32_t name_idx[KGENOME_ELF_MAX_SECTIONS];
	kof_buf strtab;
	uint32_t i;

	if (info->shentsize != 0 && info->shentsize != shdr_size)
		*anom |= KGENOME_ELF_ANOM_SHENTSIZE_ODD;

	info->shnum = info->shnum_claimed;
	if (info->shnum > KGENOME_ELF_MAX_SECTIONS) {
		info->shnum = KGENOME_ELF_MAX_SECTIONS;
		*anom |= KGENOME_ELF_ANOM_SHNUM_CLAMPED;
	}
	if (info->shnum != 0 && info->shoff >= file.n) {
		*anom |= KGENOME_ELF_ANOM_SHOFF_PAST_EOF;
		info->shnum = 0;
	}
	if (info->shnum == 0) {
		/* Stripped, or the table was unusable. Either way the section
		 * view is absent and only segments can be trusted. */
		*anom |= KGENOME_ELF_ANOM_SECTAB_MISSING;
		return;
	}

	/*
	 * Stride by the size this class mandates, not by the header's claim: a
	 * wrong shentsize would otherwise walk arbitrary offsets. The claim is
	 * still reported.
	 */
	for (i = 0; i < info->shnum; i++) {
		kof_buf sh = kof_slice(file, info->shoff + i * shdr_size,
				       shdr_size);
		struct kgenome_elf_sec *s = &info->sec[info->sec_count];

		if (sh.n == 0) {
			*anom |= KGENOME_ELF_ANOM_SEC_PAST_EOF;
			break;
		}
		memset(s, 0, sizeof *s);
		if (!read_shdr(sh, is64, be, s, &name_idx[info->sec_count],
			       &info->sec_link[info->sec_count],
			       &info->sec_info[info->sec_count])) {
			*anom |= KGENOME_ELF_ANOM_SEC_PAST_EOF;
			break;
		}

		/* SHT_NOBITS occupies no file bytes, so its file_off says
		 * nothing and must not be range checked as if it did. */
		if (s->type != KGENOME_ELF_SHT_NOBITS && s->type != KGENOME_ELF_SHT_NULL &&
		    !kof_in_range(file, s->file_off, s->file_size))
			*anom |= KGENOME_ELF_ANOM_SEC_PAST_EOF;

		info->sec_count++;
	}

	/* Resolve names. The string table is one of the sections just read, so
	 * this cannot be folded into the loop above. */
	if (info->shstrndx == KGENOME_ELF_SHN_UNDEF || info->shstrndx >= info->sec_count) {
		if (info->shstrndx != KGENOME_ELF_SHN_UNDEF)
			*anom |= KGENOME_ELF_ANOM_SHSTRNDX_BAD;
		return;
	}

	strtab = kof_slice(file, info->sec[info->shstrndx].file_off,
			   info->sec[info->shstrndx].file_size);
	if (strtab.n == 0) {
		*anom |= KGENOME_ELF_ANOM_SHSTRNDX_BAD;
		return;
	}

	for (i = 0; i < info->sec_count; i++) {
		struct kgenome_elf_sec *s = &info->sec[i];
		int truncated = 0;
		uint32_t k;

		if (name_idx[i] >= strtab.n) {
			*anom |= KGENOME_ELF_ANOM_SECNAME_UNREAD;
			continue;
		}
		s->name_hash = name_hash(strtab, name_idx[i], &truncated);
		if (truncated)
			*anom |= KGENOME_ELF_ANOM_SECNAME_TRUNC;

		for (k = 0; k + 1 < KGENOME_ELF_SECNAME_MAX; k++) {
			uint8_t c;
			if (!kof_rd_u8(strtab, name_idx[i] + k, &c) || c == 0)
				break;
			s->name[k] = (char)c;
		}
		s->name[k] = 0;
	}
}

/*
 * Region resolution.
 *
 * Nothing is stored on the context. Every range is computed from info->seg[] and
 * info->sec[], which the parse already filled and which hold every fact needed. A
 * stored region table was tried and removed: it duplicated resident data, so it could
 * disagree with its source, and it needed a cap on extents per region - which for a
 * complement like UNCLAIMED meant merging across claimed bytes.
 *
 * The five ELF regions partition the object: HEADERS, CODE, DATA, NOLOAD and
 * UNCLAIMED cover every byte and overlap in none. So OR-ing bits together scans no
 * byte twice, which is why coalescing is all the deduplication a union needs.
 */

static uint64_t front_end(const struct kgenome_elf_info *e);

/*
 * Settle which bytes each structure owns.
 *
 * The regions have to be disjoint or they are not a partition, and ELF
 * guarantees the opposite: segments and sections describe the same file twice,
 * on purpose, and a normal object has them overlapping everywhere. What kept the
 * property before was one trim of DATA against the header block - one of four
 * ways two regions can collide, and generated hostile headers found the others
 * within twenty thousand tries:
 *
 *   an executable load at offset zero        CODE against HEADERS
 *   a non-allocated section inside a load    NOLOAD against CODE or DATA
 *   a section header table inside a load     HEADERS against CODE or DATA
 *   an executable and a data load overlapping   CODE against DATA
 *
 * So ownership is decided once, here, rather than by each region trimming
 * against whichever neighbour someone remembered. Claimants are taken in offset
 * order and the earlier one keeps the bytes; ties go to the more authoritative,
 * which is why the header block outranks a segment that also starts at zero.
 *
 * Front trimming alone is enough to leave every claim contiguous: sorted by
 * offset, a claimant can only ever collide with what is already behind it.
 *
 * What a structure declared stays in file_off and file_size for a module to read.
 * What it owns goes in claim_off and claim_len.
 */
enum {
	CL_HDR = 0,     /* the ELF header plus the program header table */
	CL_SHTAB,       /* the section header table */
	CL_SEG,         /* a PT_LOAD segment */
	CL_SEC          /* a section not covered by any load */
};

/* Which structure a settled claim belongs to, packed into the tag the settler
 * carries through: the kind in the low bits, the index above it. */
#define CL_TAG(kind, idx) (((uint32_t)(idx) << 2) | (uint32_t)(kind))
#define CL_KIND(tag)      ((tag) & 3u)
#define CL_IDX(tag)       ((tag) >> 2)

static void settle_claims(struct kgenome_elf_info *e, uint64_t obj_size)
{
	struct kof_claim c[2 + KGENOME_ELF_MAX_SEGMENTS + KGENOME_ELF_MAX_SECTIONS];
	const uint32_t cap = (uint32_t)(sizeof c / sizeof c[0]);
	uint32_t n = 0, i;

	e->hdr_claim_off = e->hdr_claim_len = 0;
	e->shtab_claim_off = e->shtab_claim_len = 0;
	for (i = 0; i < e->seg_count; i++)
		e->seg[i].claim_off = e->seg[i].claim_len = 0;
	for (i = 0; i < e->sec_count; i++)
		e->sec[i].claim_off = e->sec[i].claim_len = 0;

	c[n].off = 0;
	c[n].len = front_end(e);
	c[n].rank = CL_HDR;
	c[n].tag = CL_TAG(CL_HDR, 0);
	n++;

	if (e->shnum && e->shentsize) {
		c[n].off = e->shoff;
		c[n].len = (uint64_t)e->shnum * e->shentsize;
		c[n].rank = CL_SHTAB;
		c[n].tag = CL_TAG(CL_SHTAB, 0);
		n++;
	}
	for (i = 0; i < e->seg_count && n < cap; i++) {
		if (!kgenome_elf_seg_is_load(&e->seg[i]))
			continue;
		c[n].off = e->seg[i].file_off;
		c[n].len = e->seg[i].file_size;
		c[n].rank = CL_SEG;
		c[n].tag = CL_TAG(CL_SEG, i);
		n++;
	}
	for (i = 0; i < e->sec_count && n < cap; i++) {
		/*
		 * A section that will be loaded is normally left to the segment that
		 * loads it - two claims on the same bytes, and the segment is the one
		 * a loader acts on.
		 *
		 * Unless there are no segments. A relocatable object has none: a
		 * kernel module is ET_REL, its sections are the ONLY description of
		 * it, and skipping the allocatable ones left .text and .data claimed
		 * by nothing at all. On diamorphine.ko that put 6472 bytes - every
		 * byte of the module's actual code - into UNCLAIMED, with CODE and
		 * DATA empty, so the prefilter ruled out every module targeting ELF
		 * code before it ran. A Linux rootkit is exactly this file shape.
		 */
		if (e->sec[i].type == KGENOME_ELF_SHT_NULL || e->sec[i].type == KGENOME_ELF_SHT_NOBITS ||
		    !e->sec[i].file_size)
			continue;
		if (e->seg_count && (e->sec[i].flags & KGENOME_ELF_SHF_ALLOC))
			continue;
		c[n].off = e->sec[i].file_off;
		c[n].len = e->sec[i].file_size;
		c[n].rank = CL_SEC;
		c[n].tag = CL_TAG(CL_SEC, i);
		n++;
	}

	kof_rl_settle(c, n, obj_size);

	for (i = 0; i < n; i++) {
		uint32_t idx = CL_IDX(c[i].tag);

		switch (CL_KIND(c[i].tag)) {
		case CL_HDR:
			e->hdr_claim_off = c[i].got_off;
			e->hdr_claim_len = c[i].got_len;
			break;
		case CL_SHTAB:
			e->shtab_claim_off = c[i].got_off;
			e->shtab_claim_len = c[i].got_len;
			break;
		case CL_SEG:
			e->seg[idx].claim_off = c[i].got_off;
			e->seg[idx].claim_len = c[i].got_len;
			break;
		default:
			e->sec[idx].claim_off = c[i].got_off;
			e->sec[idx].claim_len = c[i].got_len;
			break;
		}
	}
}

/* End of the front header structures: the ELF header plus the program header
 * table. Where DATA starts, since the first load usually begins at offset 0 and
 * those bytes belong to HEADERS. */
static uint64_t front_end(const struct kgenome_elf_info *e)
{
	uint64_t h = (e->elf_class == KGENOME_ELFCLASS_64) ? EHDR64_SIZE : EHDR32_SIZE;

	if (e->phnum && e->phentsize) {
		uint64_t t = e->phoff + (uint64_t)e->phnum * e->phentsize;
		if (t > h)
			h = t;
	}
	return h;
}


int kgenome_elf_image_parse(kof_buf file, struct kgenome_elf_info *info,
		  struct kgenome_obj *obj)
{
	uint64_t anom = 0;
	int is64, be;
	uint64_t ehdr_size, phdr_size;
	uint8_t cls, data, ver, osabi, abiver;
	uint32_t i, j;

	/*
	 * Only the header and the counts are cleared. The segment and section
	 * arrays are left alone: nothing past seg_count or sec_count is ever
	 * read, and zeroing 11KB for every file in a scan would be pure waste.
	 */
	memset(info, 0, offsetof(struct kgenome_elf_info, seg));
	info->version = KGENOME_ELF_INFO_VERSION;
	info->min_vaddr = KGENOME_NA;

	obj->obj_size = file.n;
	obj->entry_off = KGENOME_NA;
	obj->arch = KGENOME_ARCH_ANY;
	obj->file_header = 0;
	/* The engine's adapter (kof_elf_parse) clears the region resolver on the
	 * way in: a failed identification must not leave a resolver from a
	 * previous file on a reused context. KOF_SCAN_ALL still works without
	 * one, since the host answers that itself. */

	/* Magic is the only thing that decides "is this ELF". */
	if (!kof_in_range(file, EI_MAG0, 4) ||
	    memcmp(file.p + EI_MAG0, "\177ELF", 4) != 0) {
		info->anomalies = KGENOME_ELF_ANOM_BAD_MAGIC;
		return 0;
	}
	info->valid    = 1;
	obj->format = KGENOME_FMT_ELF;
	obj->file_header = info;

	if (!kof_rd_u8(file, EI_CLASS, &cls))         cls = 0;
	if (!kof_rd_u8(file, EI_DATA, &data))         data = 0;
	if (!kof_rd_u8(file, EI_VERSION, &ver))       ver = 0;
	if (!kof_rd_u8(file, EI_OSABI, &osabi))       osabi = 0;
	if (!kof_rd_u8(file, EI_ABIVERSION, &abiver)) abiver = 0;

	info->os_abi      = osabi;
	info->abi_version = abiver;

	switch (cls) {
	case ELFCLASS32: info->elf_class = KGENOME_ELFCLASS_32; is64 = 0; break;
	case ELFCLASS64: info->elf_class = KGENOME_ELFCLASS_64; is64 = 1; break;
	default:
		info->elf_class = KGENOME_ELFCLASS_NONE;
		anom |= KGENOME_ELF_ANOM_BAD_CLASS;
		/* Assume 32 bit to keep collecting. Widths may be wrong but the
		 * anomaly says so, and partial facts beat none. */
		is64 = 0;
		break;
	}

	switch (data) {
	case ELFDATA2LSB: info->elf_data = KGENOME_ELFDATA_LE; be = 0; break;
	case ELFDATA2MSB: info->elf_data = KGENOME_ELFDATA_BE; be = 1; break;
	default:
		info->elf_data = KGENOME_ELFDATA_NONE;
		anom |= KGENOME_ELF_ANOM_BAD_ENDIAN;
		be = 0;
		break;
	}

	if (ver != EV_CURRENT)
		anom |= KGENOME_ELF_ANOM_BAD_VERSION;

	ehdr_size = is64 ? EHDR64_SIZE : EHDR32_SIZE;
	phdr_size = is64 ? PHDR64_SIZE : PHDR32_SIZE;

	if (file.n < ehdr_size)
		anom |= KGENOME_ELF_ANOM_TRUNCATED_HEADER;

	/* Offsets 16..24 are class independent. */
	kof_rd_u16(file, 16, be, &info->e_type);
	/*
	 * e_type verbatim, as the prefilter's subtype. Here and not beside
	 * obj->format above, because that runs before the header has been read.
	 *
	 * Clamped to what a 32 bit mask can name; a value above it is one no module
	 * can have declared, so it matches nothing - the same treatment an
	 * architecture outside the mask already gets. Two objects in a 7221 file
	 * collection carry one.
	 */
	obj->subtype = info->e_type < 32u ? (uint8_t)info->e_type : 0xffu;
	kof_rd_u16(file, 18, be, &info->e_machine);
	kof_rd_u32(file, 20, be, &info->e_version);

	info->e_flags = 0;
	if (is64) {
		kof_rd_u64(file, 24, be, &info->entry_addr);
		kof_rd_u64(file, 32, be, &info->phoff);
		kof_rd_u64(file, 40, be, &info->shoff);
		kof_rd_u16(file, 54, be, &info->phentsize);
		kof_rd_u16(file, 56, be, &info->phnum_claimed);
		kof_rd_u16(file, 58, be, &info->shentsize);
		kof_rd_u16(file, 60, be, &info->shnum_claimed);
		kof_rd_u16(file, 62, be, &info->shstrndx);
		kof_rd_u32(file, 48, be, &info->e_flags);
	} else {
		uint32_t v;
		if (kof_rd_u32(file, 24, be, &v)) info->entry_addr = v;
		if (kof_rd_u32(file, 28, be, &v)) info->phoff = v;
		if (kof_rd_u32(file, 32, be, &v)) info->shoff = v;
		kof_rd_u16(file, 42, be, &info->phentsize);
		kof_rd_u16(file, 44, be, &info->phnum_claimed);
		kof_rd_u16(file, 46, be, &info->shentsize);
		kof_rd_u16(file, 48, be, &info->shnum_claimed);
		kof_rd_u16(file, 50, be, &info->shstrndx);
		kof_rd_u32(file, 36, be, &info->e_flags);
	}

	obj->arch = arch_from_machine(info->e_machine, is64);

	/*
	 * A zero entry point is only anomalous for ET_EXEC. Measured over
	 * /usr/bin and /usr/lib, 535 of 1316 objects are shared libraries with a
	 * legitimately zero e_entry and 12 more are relocatable objects; an
	 * unconditional bit fires on 42% of clean files and discriminates
	 * nothing. ET_DYN covers both PIE executables and shared libraries, so
	 * e_type cannot separate those and neither is anomalous.
	 */
	if (info->entry_addr == 0 && info->e_type == KGENOME_ELF_EXEC)
		anom |= KGENOME_ELF_ANOM_ENTRY_ZERO;

	/* ---- program headers -------------------------------------------- */

	if (info->phnum_claimed == PN_XNUM)
		anom |= KGENOME_ELF_ANOM_PHNUM_CLAMPED; /* real count is in shdr[0] */

	if (info->phentsize != 0 && info->phentsize != phdr_size)
		anom |= KGENOME_ELF_ANOM_PHENTSIZE_ODD;

	info->phnum = info->phnum_claimed;
	if (info->phnum > KGENOME_ELF_MAX_SEGMENTS) {
		info->phnum = KGENOME_ELF_MAX_SEGMENTS;
		anom |= KGENOME_ELF_ANOM_PHNUM_CLAMPED;
	}
	if (info->phnum != 0 && info->phoff >= file.n) {
		anom |= KGENOME_ELF_ANOM_PHOFF_PAST_EOF;
		info->phnum = 0;
	}

	for (i = 0; i < info->phnum; i++) {
		kof_buf ph = kof_slice(file, info->phoff + i * phdr_size,
				       phdr_size);
		struct kgenome_elf_seg *s = &info->seg[info->seg_count];
		uint32_t flags = 0;

		if (ph.n == 0) {
			anom |= KGENOME_ELF_ANOM_SEG_PAST_EOF;
			break;
		}
		memset(s, 0, sizeof *s);
		if (!read_phdr(ph, is64, be, s, &flags)) {
			anom |= KGENOME_ELF_ANOM_SEG_PAST_EOF;
			break;
		}
		s->perm = perm_from_pflags(flags);
		info->seg_count++;

		if (s->type != KGENOME_ELF_PT_LOAD)
			continue;

		if (s->file_size > s->mem_size)
			anom |= KGENOME_ELF_ANOM_SEG_FILESZ_GT_MEM;
		if (!kof_in_range(file, s->file_off, s->file_size))
			anom |= KGENOME_ELF_ANOM_SEG_PAST_EOF;

		if (info->min_vaddr == KGENOME_NA || s->mem_addr < info->min_vaddr)
			info->min_vaddr = s->mem_addr;
		{
			uint64_t end = (s->mem_addr > UINT64_MAX - s->mem_size)
					? UINT64_MAX : s->mem_addr + s->mem_size;
			if (end > info->max_vaddr)
				info->max_vaddr = end;
		}
		info->load_count++;
	}

	/*
	 * Relocatable objects have no PT_LOAD by design, and a truncated header
	 * already reports itself; flagging either here only adds noise. Only an
	 * executable or shared object with nothing to load is odd.
	 */
	if (info->load_count == 0 &&
	    (info->e_type == KGENOME_ELF_EXEC || info->e_type == KGENOME_ELF_DYN))
		anom |= KGENOME_ELF_ANOM_NO_LOAD_SEGMENT;

	/* Pairwise overlap over PT_LOAD only. seg_count is clamped, so bounded. */
	for (i = 0; i < info->seg_count && !(anom & KGENOME_ELF_ANOM_SEG_OVERLAP); i++) {
		if (info->seg[i].type != KGENOME_ELF_PT_LOAD)
			continue;
		for (j = i + 1; j < info->seg_count; j++) {
			if (info->seg[j].type != KGENOME_ELF_PT_LOAD)
				continue;
			if (vaddr_overlap(&info->seg[i], &info->seg[j])) {
				anom |= KGENOME_ELF_ANOM_SEG_OVERLAP;
				break;
			}
		}
	}

	/* ---- entry point ------------------------------------------------- */

	/*
	 * Three outcomes are kept distinct because they mean different things:
	 * not mapped at all, mapped but only as zero fill so the bytes are
	 * absent from the file, and mapped into a region that is not executable.
	 * Collapsing them would discard the strongest signals available here.
	 */
	if (info->entry_addr != 0 && info->load_count != 0) {
		int found = 0;
		for (i = 0; i < info->seg_count; i++) {
			const struct kgenome_elf_seg *s = &info->seg[i];
			uint64_t delta;

			if (s->type != KGENOME_ELF_PT_LOAD || info->entry_addr < s->mem_addr)
				continue;
			delta = info->entry_addr - s->mem_addr;
			if (delta >= s->mem_size)
				continue;

			found = 1;
			info->entry_perm = s->perm;
			if (!kgenome_elf_seg_is_code(s))
				anom |= KGENOME_ELF_ANOM_ENTRY_NOT_EXEC;

			if (delta >= s->file_size) {
				anom |= KGENOME_ELF_ANOM_ENTRY_ZEROFILL;
				obj->entry_off = KGENOME_BROKEN;
			} else {
				uint64_t off = s->file_off + delta;
				if (kof_in_range(file, off, 1))
					obj->entry_off = off;
				else {
					anom |= KGENOME_ELF_ANOM_SEG_PAST_EOF;
					obj->entry_off = KGENOME_BROKEN;
				}
			}
			break;
		}
		if (!found) {
			anom |= KGENOME_ELF_ANOM_ENTRY_UNMAPPED;
			obj->entry_off = KGENOME_BROKEN;
		}
	} else if (info->entry_addr != 0) {
		/* Declares an entry but has nothing loaded to resolve it in. */
		obj->entry_off = KGENOME_BROKEN;
	}

	/* ---- section headers -------------------------------------------- */

	parse_sections(file, info, is64, be, &anom);

	/* After every structure has been read, and before any region can be asked
	 * for: the regions are defined in terms of what settling decided. */
	settle_claims(info, file.n);

	/* The region resolver is NOT set here: the region partition is the engine's,
	 * attached by the adapter kof_elf_parse in elf_parse.c. */

	info->anomalies = anom;
	return 1;
}


int kgenome_elf_sniff(kof_buf file)
{
	return file.n >= 4 && memcmp(file.p, "\177ELF", 4) == 0;
}

/*
 * ---- THE TABLES, WALKED ON DEMAND -----------------------------------------
 *
 * See elf_parse.h for why these are here and what the line is between what
 * they answer and what a caller decides. Below this point nothing knows what
 * any name MEANS.
 */

/* The string section a symbol table's sh_link names, or NULL when it names none (zero,
 * past the table, or a section that is not a string table). */
static const struct kgenome_elf_sec *sec_strtab_of(const struct kgenome_elf_info *p, uint32_t i)
{
	uint32_t l = p->sec_link[i];

	if (!l || l >= p->sec_count || l >= KGENOME_ELF_MAX_SECTIONS ||
	    p->sec[l].type != KGENOME_ELF_SHT_STRTAB)
		return NULL;
	return &p->sec[l];
}

int kgenome_elf_symtab_of(kof_buf f, const struct kgenome_elf_info *p,
		      enum kgenome_elf_symtab_want want,
		      struct kgenome_elf_symtab *t)
{
	static const struct { uint32_t sht; uint8_t origin; }
	tab[2] = {
		{ KGENOME_ELF_SHT_SYMTAB, 1u },   /* KOF_SYM_ORIGIN_SYMTAB */
		{ KGENOME_ELF_SHT_DYNSYM, 2u }    /* KOF_SYM_ORIGIN_DYNSYM */
	};
	uint32_t k, lo = want == KGENOME_ELF_SYMTAB_DYN ? 1u : 0u;
	uint32_t hi = want == KGENOME_ELF_SYMTAB_FULL ? 0u : 1u;

	if (!t)
		return 0;
	memset(t, 0, sizeof *t);
	if (!f.p || !p || !p->valid)
		return 0;
	t->elf64 = p->elf_class == KGENOME_ELFCLASS_64;
	t->be = p->elf_data == KGENOME_ELFDATA_BE;
	t->mips64 = t->elf64 && p->e_machine == EM_MIPS;
	t->recsize = t->elf64 ? 24u : 16u;

	/*
	 * .symtab first and .dynsym only when there is none - .symtab is the
	 * whole table and .dynsym the part dynamic linking needs, so a
	 * stripped file keeps the second and loses the first. A caller that
	 * must have one or the other says so.
	 *
	 * A TABLE WITHOUT ITS STRINGS IS STILL A TABLE, and `strn` zero is
	 * how that is said. The pairing is by sh_link, which is what the
	 * format says a symbol table's strings are (info->sec_link), and NOT by
	 * the section's name: ".strtab" and ".dynstr" are the linker's
	 * spelling, a file that renames them runs the same, and a pairing by
	 * name lost every symbol name of such a file (measured by the test
	 * names_structural: the same object with its string sections renamed
	 * gave strn 0). A file that dropped the string section, or whose
	 * sh_link names something that is not one, still has addresses, sizes
	 * and types, and a caller after function BOUNDARIES needs none of the
	 * names.
	 *
	 * It is still the weaker find, so a nameless .symtab does not beat a
	 * complete .dynsym: the loop remembers it and only falls back to it
	 * once nothing better turns up. Refusing it outright is what this
	 * did for one revision, and it cost the function boundaries of every
	 * object whose string section was gone.
	 */
	for (k = lo; k <= hi; k++) {
		uint32_t i;
		const struct kgenome_elf_sec *sym = 0, *str = 0;

		for (i = 0; i < p->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
			if (p->sec[i].type == tab[k].sht) {
				sym = &p->sec[i];
				str = sec_strtab_of(p, i);
				break;
			}
		}
		if (!sym)
			continue;
		if (!str && k < hi && !t->off) {
			/* Remembered, in case the other table is no better. */
			t->off = sym->file_off;
			t->n_decl = sym->file_size / t->recsize;
			t->n = kof_clip_len(f.n, sym->file_off,
					    sym->file_size) / t->recsize;
			t->origin = tab[k].origin;
			continue;
		}
		t->off = sym->file_off;
		t->n_decl = sym->file_size / t->recsize;
		t->n = kof_clip_len(f.n, sym->file_off, sym->file_size) /
		       t->recsize;
		t->str = str ? str->file_off : 0;
		t->strn = str ? str->file_size : 0;
		t->origin = tab[k].origin;
		return 1;
	}
	return t->off != 0;
}

int kgenome_elf_symbol_at(kof_buf f, const struct kgenome_elf_symtab *t, uint64_t i,
		      struct kgenome_elf_symbol *s)
{
	uint64_t at;

	if (!t || !s || !t->off)
		return 0;
	memset(s, 0, sizeof *s);
	/* The record's offset is table + i*recsize and an index near 2^64 wraps it onto a
	 * record of the table: refuse what does not fit in the address space. */
	if (t->recsize && i > (UINT64_MAX - t->off) / t->recsize)
		return 0;
	at = t->off + i * t->recsize;
	/*
	 * TWO ORDERS, NOT TWO WIDTHS. Elf64_Sym is name,info,other,shndx,
	 * value,size; Elf32_Sym is name,value,size,info,other,shndx. The
	 * fields are the same and only their places move, which is why this
	 * is one function and not two files.
	 */
	if (t->elf64) {
		if (!kof_rd_u32(f, at + 0u,  t->be, &s->nameoff) ||
		    !kof_rd_u8 (f, at + 4u,         &s->info)    ||
		    !kof_rd_u8 (f, at + 5u,         &s->other)   ||
		    !kof_rd_u16(f, at + 6u,  t->be, &s->shndx)   ||
		    !kof_rd_u64(f, at + 8u,  t->be, &s->value)   ||
		    !kof_rd_u64(f, at + 16u, t->be, &s->size))
			return 0;
	} else {
		uint32_t v32 = 0, s32 = 0;

		if (!kof_rd_u32(f, at + 0u,  t->be, &s->nameoff) ||
		    !kof_rd_u32(f, at + 4u,  t->be, &v32)        ||
		    !kof_rd_u32(f, at + 8u,  t->be, &s32)        ||
		    !kof_rd_u8 (f, at + 12u,        &s->info)    ||
		    !kof_rd_u8 (f, at + 13u,        &s->other)   ||
		    !kof_rd_u16(f, at + 14u, t->be, &s->shndx))
			return 0;
		s->value = v32;
		s->size  = s32;
	}
	return 1;
}

/* A NUL-terminated name out of a string table, into the caller's buffer.
 * Empty rather than absent on a read that is refused: a visitor is never
 * handed a pointer that has not been written. */
static int str_read(kof_buf f, uint64_t at, char *dst, uint32_t dstn)
{
	uint32_t q;
	int cut = 0;

	for (q = 0; q + 1u < dstn; q++) {
		uint8_t c8 = 0;

		if (!kof_rd_u8(f, at + q, &c8) || !c8)
			break;
		dst[q] = (char)c8;
	}
	dst[q] = 0;
	if (dstn && q + 1u == dstn) {           /* full, and the name goes on: cut */
		uint8_t c8 = 0;

		cut = kof_rd_u8(f, at + q, &c8) && c8;
	}
	return cut;
}

/*
 * One relocation, unpacked. r_info is the type in the low word and the symbol
 * in the high one on 64-bit, and a byte of type under three of symbol on
 * 32-bit - a different packing, not a narrower one.
 */
static int rel_at(kof_buf f, const struct kgenome_elf_symtab *t, uint64_t base,
		  uint64_t *roff, uint32_t *rty, uint32_t *si)
{
	if (t->mips64) {
		/* The symbol is a word in the file's order; the type is the last byte, which
		 * is the same byte in both orders. r_type2 and r_type3 compose further
		 * relocations on the same site and are not read. */
		uint8_t ty = 0;

		if (!kof_rd_u64(f, base, t->be, roff) ||
		    !kof_rd_u32(f, base + 8u, t->be, si) ||
		    !kof_rd_u8(f, base + 15u, &ty))
			return 0;
		*rty = ty;
	} else if (t->elf64) {
		uint64_t info = 0;

		if (!kof_rd_u64(f, base, t->be, roff) ||
		    !kof_rd_u64(f, base + 8u, t->be, &info))
			return 0;
		*rty = (uint32_t)(info & 0xffffffffu);
		*si = (uint32_t)(info >> 32);
	} else {
		uint32_t lo = 0, info = 0;

		if (!kof_rd_u32(f, base, t->be, &lo) ||
		    !kof_rd_u32(f, base + 4u, t->be, &info))
			return 0;
		*roff = lo;
		*rty = info & 0xffu;
		*si = info >> 8;
	}
	return 1;
}

#define REL_STEP(t, rela) ((rela) ? ((t)->elf64 ? 24u : 12u) \
				  : ((t)->elf64 ? 16u : 8u))

/*
 * WHICH SECTION A RELOCATION SECTION APPLIES TO is its sh_info (info->sec_info),
 * which is what the format says - and not its NAME. `.rela.text` relocating
 * `.text` was a convention of the linker, read off the spelling; renaming the
 * sections (which breaks nothing that runs) emptied the relocation table, and
 * with it every call to an import of a relocatable object (measured by the test
 * names_structural).
 *
 * Returns the target's FILE OFFSET and says whether it holds code, so a
 * caller picks its own reading - a call graph wants code only, an image that
 * must run wants the tables too. A target with no bytes in the file (.bss) is
 * refused: there is nothing to patch at a file offset that does not exist. A
 * section that names itself, or none (sh_info 0), or one past the table, has no
 * target.
 */
static uint64_t rel_target(const struct kgenome_elf_info *p, uint32_t i, int *is_code)
{
	uint32_t j = p->sec_info[i];

	if (!j || j == i || j >= p->sec_count || j >= KGENOME_ELF_MAX_SECTIONS)
		return 0;
	if (p->sec[j].type == KGENOME_ELF_SHT_NOBITS)
		return 0;
	*is_code = kgenome_elf_sec_is_code(&p->sec[j]);
	return p->sec[j].file_off;
}

static int reloc_section(const struct kgenome_elf_info *p, uint32_t i,
			 unsigned want, uint64_t *tgt_off, int *is_code)
{
	*is_code = 0;
	if (p->sec[i].type != KGENOME_ELF_SHT_RELA)
		return 0;               /* REL has no addend to report */
	*tgt_off = rel_target(p, i, is_code);
	if (!*tgt_off)
		return 0;
	return (want & (*is_code ? KGENOME_ELF_RELOC_CODE : KGENOME_ELF_RELOC_DATA)) != 0;
}

/*
 * IS THIS RELOCATION THE ONE A CALL COMPILES TO - decided once, when the table
 * is built, and kept in `call`.
 *
 * Only on the architectures whose displacement rule is written down in
 * kgenome_elf_reloc_call_at: the numbers are reused - type 2 is R_386_PC32 and also
 * R_PPC_ADDR32 - so a machine this does not know is a machine where every
 * match would be a coincidence. Only in a relocatable object, because only
 * there is `where` a file offset. The symbol must have a name (an undefined
 * one is known by nothing else), and a DEFINED one must be code: a call to a
 * data symbol, or to SHN_ABS or SHN_COMMON, is not a call graph edge.
 *
 * PC32 and PLT32 are 2 and 4 on both x86-64 and i386; the agreement is luck, so
 * it is written down rather than relied on silently. ARM's PLT32, CALL and
 * JUMP24 are 27, 28 and 29.
 *
 * MIPS WILL NEVER BE HERE. R_MIPS_26 leaves a 26-bit field of zero, so `jal 0`
 * resolves to the same address for every call site in the section - there is
 * no unique target to report, and the whole trick this rests on does not hold.
 */
static int reloc_is_call(const struct kgenome_elf_info *p,
			 const struct kgenome_elf_symtab *t, uint32_t rty,
			 uint32_t si, const struct kgenome_elf_symbol *sy)
{
	if (p->e_type != KGENOME_ELF_REL)
		return 0;
	if (p->e_machine == 40u) {
		if (rty != 27u && rty != 28u && rty != 29u)
			return 0;
	} else if (p->e_machine == 3u || p->e_machine == 62u) {
		if (rty != 2u && rty != 4u)
			return 0;
	} else {
		return 0;
	}
	if (!si || si >= t->n)
		return 0;
	if (!sy->nameoff || sy->nameoff >= t->strn)
		return 0;
	if (sy->shndx) {
		if (sy->shndx >= p->sec_count ||
		    sy->shndx >= KGENOME_ELF_MAX_SECTIONS)
			return 0;
		if (!kgenome_elf_sec_is_code(&p->sec[sy->shndx]))
			return 0;
	}
	return 1;
}

/* Ordered by `where`, which kof_cmp_u64 reads as the first member. */
_Static_assert(offsetof(struct kgenome_elf_reloc, where) == 0,
	       "kof_cmp_u64 reads the key from the start of the element");

uint32_t kgenome_elf_reloc_table(kof_buf f, const struct kgenome_elf_info *p,
			     unsigned want, struct kgenome_elf_relocs *out)
{
	struct kgenome_elf_symtab t;
	uint32_t i, total = 0, n = 0;

	out->v = NULL;
	out->n = 0;
	out->status = KGENOME_OK;
	if (!p || !p->valid || !kgenome_elf_symtab_of(f, p, KGENOME_ELF_SYMTAB_FULL, &t))
		return 0;

	for (i = 0; i < p->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
		uint64_t tgt_off;
		int is_code;

		if (!reloc_section(p, i, want, &tgt_off, &is_code))
			continue;
		total += (uint32_t)(kof_clip_len(f.n, p->sec[i].file_off,
						 p->sec[i].file_size) /
				    REL_STEP(&t, 1));
	}
	if (!total)
		return 0;
	out->v = malloc((size_t)total * sizeof *out->v);
	if (!out->v) {
		/* "could not build" is not "no relocations": an ET_REL's every call to an
		 * import is in this table, and an empty one reads as a program that calls
		 * nothing. */
		out->status = KGENOME_NOMEM;
		KOF_TRACE("[cut] kgenome_elf_reloc_table: %u records not allocated\n", total);
		return 0;
	}

	for (i = 0; i < p->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
		uint64_t k, step, have, tgt_off;
		int is_code;

		if (!reloc_section(p, i, want, &tgt_off, &is_code))
			continue;
		step = REL_STEP(&t, 1);
		have = kof_clip_len(f.n, p->sec[i].file_off,
				    p->sec[i].file_size);
		for (k = 0; k + step <= have && n < total; k += step) {
			struct kgenome_elf_symbol sy;
			struct kgenome_elf_reloc *r = &out->v[n];
			uint64_t roff = 0, add = 0;
			uint32_t rty = 0, si = 0;

			if (!rel_at(f, &t, p->sec[i].file_off + k,
				    &roff, &rty, &si))
				break;
			if (t.elf64) {
				if (!kof_rd_u64(f, p->sec[i].file_off + k + 16u,
						t.be, &add))
					break;
			}
			/* A site is a place in the object. r_offset is the file's number: past the
			 * end it names nothing, and the sum with the section's offset must not wrap. */
			if (tgt_off >= f.n || roff >= f.n - tgt_off)
				continue;
			r->where = tgt_off + roff;
			r->type = rty;
			r->addend = (int64_t)add;
			r->sym = 0;
			r->nameoff = 0;
			r->defined = 0;
			r->call = 0;
			r->code = (uint8_t)(is_code != 0);
			if (kgenome_elf_symbol_at(f, &t, si, &sy)) {
				if (sy.nameoff && sy.nameoff < t.strn)
					r->nameoff = t.str + sy.nameoff;
				if (sy.shndx &&
				    sy.shndx < p->sec_count &&
				    sy.shndx < KGENOME_ELF_MAX_SECTIONS) {
					r->sym = p->sec[sy.shndx].file_off +
						 sy.value;
					r->defined = 1;
				}
				r->call = (uint8_t)(is_code &&
					reloc_is_call(p, &t, rty, si, &sy));
			}
			n++;
		}
	}
	out->n = n;
	if (n > 1u)
		qsort(out->v, n, sizeof *out->v, kof_cmp_u64);
	return n;
}

void kgenome_elf_reloc_table_free(struct kgenome_elf_relocs *t)
{
	if (!t)
		return;
	free(t->v);
	t->v = NULL;
	t->n = 0;
}

const struct kgenome_elf_reloc *kgenome_elf_reloc_in(const struct kgenome_elf_relocs *t,
					     uint64_t at, uint8_t len)
{
	uint32_t lo = 0, hi;

	if (!t || !t->n)
		return NULL;
	hi = t->n;
	while (lo < hi) {                       /* first record with where >= at */
		uint32_t mid = lo + (hi - lo) / 2u;

		if (t->v[mid].where < at)
			lo = mid + 1u;
		else
			hi = mid;
	}
	for (; lo < t->n && t->v[lo].where < at + (uint64_t)len; lo++)
		if (t->v[lo].code && t->v[lo].nameoff)
			return &t->v[lo];
	return NULL;
}

static uint64_t kgenome_elf_reloc_call_at(const struct kgenome_elf_info *p,
			       const struct kgenome_elf_reloc *r)
{
	/*
	 * WHERE THE DECODER WILL THINK THE CALL GOES.
	 *
	 * An unlinked `call` is `e8 00000000`, so its target reads as the next
	 * instruction, and the relocation sits on the four displacement bytes -
	 * r_offset + 4. ARM reads PC as the instruction plus eight and its
	 * relocations sit on the `bl` itself, so there it is r_offset + 8.
	 */
	return r->where + (p->e_machine == 40u /* EM_ARM */ ? 8u : 4u);
}

uint32_t kgenome_elf_relcalls(kof_buf f, const struct kgenome_elf_info *p,
			  const struct kgenome_elf_relocs *t,
			  kgenome_elf_relcall_fn fn, void *user,
			  enum kgenome_status *status)
{
	uint32_t i, n = 0;

	if (status)
		*status = KGENOME_OK;
	if (!f.p || !p || !t || !fn)
		return 0;
	for (i = 0; i < t->n; i++) {
		const struct kgenome_elf_reloc *r = &t->v[i];
		char nm[KGENOME_SYMNAME_MAX];

		if (!r->call)
			continue;
		if (str_read(f, r->nameoff, nm, sizeof nm) && status)
			*status = kgenome_status_merge(*status, KGENOME_TRUNCATED);
		/* `sym` is the symbol's section plus its value when this
		 * object defines it - an ET_REL section declares address zero,
		 * so the file offset is the address - and zero when it does
		 * not. */
		fn(user, kgenome_elf_reloc_call_at(p, r), r->sym, nm);
		n++;
	}
	return n;
}

/*
 * The loadable segment whose FILE half holds an address, or a file offset;
 * NULL when none does. The first in table order, which is the one every
 * translation here answers through: kgenome_elf_va_to_off, the object-wide
 * kgenome_image_* pair (image_addr.h) and the cell space (celllysis/space.c) all ask this
 * and add their own policy on top.
 */
static const struct kgenome_elf_seg *kgenome_elf_load_at_va(const struct kgenome_elf_info *e,
						 uint64_t va)
{
	uint32_t s;

	for (s = 0; s < e->seg_count && s < KGENOME_ELF_MAX_SEGMENTS; s++) {
		const struct kgenome_elf_seg *g = &e->seg[s];

		if (kgenome_elf_seg_is_load(g) && va >= g->mem_addr &&
		    va - g->mem_addr < g->file_size)
			return g;
	}
	return NULL;
}

const struct kgenome_elf_seg *kgenome_elf_load_at_off(const struct kgenome_elf_info *e,
						  uint64_t off)
{
	uint32_t s;

	for (s = 0; s < e->seg_count && s < KGENOME_ELF_MAX_SEGMENTS; s++) {
		const struct kgenome_elf_seg *g = &e->seg[s];

		if (kgenome_elf_seg_is_load(g) && off >= g->file_off &&
		    off - g->file_off < g->file_size)
			return g;
	}
	return NULL;
}

int kgenome_elf_va_to_off(const struct kgenome_elf_info *e, uint64_t va, uint64_t sz,
		      uint64_t *off)
{
	const struct kgenome_elf_seg *g = kgenome_elf_load_at_va(e, va);

	if (!g)
		return 0;
	if (sz > g->file_size - (va - g->mem_addr))
		return 0;       /* it runs past the file half */
	*off = g->file_off + (va - g->mem_addr);
	return 1;
}
