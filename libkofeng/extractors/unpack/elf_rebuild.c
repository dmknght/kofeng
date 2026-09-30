/*
 * elf_rebuild.c - see elf_rebuild.h.
 */

#include <stdlib.h>
#include <string.h>

#include <kofmod/pe.h>   /* KOF_PE_PERM_* - the permission bits a declaration uses */

#include "elf_rebuild.h"

#define EHDR64      64u
#define PHENT64     56u
#define SHENT64     64u
#define PT_LOAD     1u

/* Bounds on what a header may claim before it is not describing a program. */
#define MAX_PHNUM   256u
#define MAX_SHNUM   4096u
#define DEF_CAP     (256ull << 20)

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }

static uint32_t rd32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p)
{
	return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

int kof_elf_rebuild(uint64_t base, kof_elf_rebuild_rd rd, void *user,
		    uint64_t cap, uint8_t **out, uint64_t *out_len,
		    uint64_t *covered_lo, uint64_t *covered_hi)
{
	uint8_t eh[EHDR64], *ph = NULL, *file = NULL;
	uint64_t phoff, shoff, end = 0, lo = ~0ull, hi = 0, min_vaddr = ~0ull;
	uint64_t bias;
	uint16_t phentsize, phnum, shentsize, shnum;
	uint32_t i, loads = 0;
	int have_sh;

	if (!rd || !out || !out_len)
		return 0;
	if (!cap)
		cap = DEF_CAP;
	if (!rd(user, base, eh, EHDR64))
		return 0;
	/* ELF64, little endian, and nothing else: this rebuilds what the
	 * emulator can run, and the emulator is amd64. */
	if (memcmp(eh, "\177ELF", 4) || eh[4] != 2 || eh[5] != 1)
		return 0;

	phoff     = rd64(eh + 0x20);
	shoff     = rd64(eh + 0x28);
	phentsize = rd16(eh + 0x36);
	phnum     = rd16(eh + 0x38);
	shentsize = rd16(eh + 0x3a);
	shnum     = rd16(eh + 0x3c);

	if (phentsize != PHENT64 || !phnum || phnum > MAX_PHNUM)
		return 0;
	if (phoff > cap)
		return 0;

	ph = malloc((size_t)phnum * PHENT64);
	if (!ph)
		return 0;
	/*
	 * The program headers are read at base + e_phoff, which assumes the
	 * first PT_LOAD maps file offset zero at `base`. That is the same
	 * assumption AT_PHDR encodes and it is what every loader relies on; a
	 * header where it does not hold simply fails the checks below.
	 */
	if (!rd(user, base + phoff, ph, (uint32_t)(phnum * PHENT64)))
		goto no;

	/* First pass: is this a program, and how big is the file it describes. */
	for (i = 0; i < phnum; i++) {
		const uint8_t *p = ph + (uint64_t)i * PHENT64;
		uint64_t off, vaddr, fsz;

		if (rd32(p) != PT_LOAD)
			continue;
		off   = rd64(p + 0x08);
		vaddr = rd64(p + 0x10);
		fsz   = rd64(p + 0x20);
		if (!fsz)
			continue;
		if (off > cap || fsz > cap || off + fsz > cap)
			goto no;                /* claims more than may be built */
		if (vaddr < min_vaddr)
			min_vaddr = vaddr;
		if (off + fsz > end)
			end = off + fsz;
		loads++;
	}
	if (!loads || !end)
		goto no;

	/*
	 * Where the image was actually placed, against where it says it is
	 * linked. For ET_EXEC the two agree and this is zero; for ET_DYN the
	 * loader chose, and every p_vaddr has to be read through the same
	 * offset the header block was found at.
	 */
	/*
	 * The lowest PT_LOAD is the one the header block sits in, so its vaddr
	 * cannot be above the address the header was found at. A header saying
	 * otherwise makes this subtraction wrap, and every segment is then read
	 * from an address nowhere near the image - which is not a rebuild that
	 * fails, it is one that quietly returns the wrong bytes.
	 */
	if (min_vaddr == ~0ull || min_vaddr > base)
		goto no;
	bias = base - min_vaddr;

	/*
	 * THE SECTION TABLE IS USUALLY NOT THERE TO COPY, and reading whatever
	 * is at its address instead is worse than admitting it.
	 *
	 * e_shoff is a FILE offset, and the section table lives past the last
	 * PT_LOAD's file content - so a loader never maps it and a run never
	 * has it. The address still READS, because something else is mapped
	 * there, and copying that produced a file whose program headers were
	 * byte-identical to a static unpacker's while its sections were noise:
	 * the collector raised SHSTRNDX_BAD and SEC_PAST_EOF, and the region
	 * partition came back CODE=0 with 2.7 MB filed under NOLOAD, which is
	 * the opposite of the point of rebuilding at all.
	 *
	 * Section header zero is defined to be all zeroes, so one read settles
	 * whether the address holds a section table or something that merely
	 * lives there. When it does not, the rebuilt header says so - a
	 * stripped file, which is the truth about what was recovered, and one
	 * the collector partitions by its segments alone.
	 */
	have_sh = 0;
	if (shoff && shentsize == SHENT64 && shnum && shnum <= MAX_SHNUM &&
	    shoff <= cap && (uint64_t)shnum * SHENT64 <= cap - shoff) {
		uint8_t probe[SHENT64];
		unsigned k;

		if (rd(user, bias + shoff, probe, SHENT64)) {
			for (k = 0; k < SHENT64; k++)
				if (probe[k])
					break;
			have_sh = k == SHENT64;
		}
	}
	if (have_sh && shoff + (uint64_t)shnum * SHENT64 > end)
		end = shoff + (uint64_t)shnum * SHENT64;

	if (end > cap)
		goto no;
	file = calloc(1, (size_t)end);
	if (!file)
		goto no;

	memcpy(file, eh, EHDR64);
	if (phoff + (uint64_t)phnum * PHENT64 <= end)
		memcpy(file + phoff, ph, (size_t)phnum * PHENT64);

	for (i = 0; i < phnum; i++) {
		const uint8_t *p = ph + (uint64_t)i * PHENT64;
		uint64_t off, vaddr, fsz;

		if (rd32(p) != PT_LOAD)
			continue;
		off   = rd64(p + 0x08);
		vaddr = rd64(p + 0x10);
		fsz   = rd64(p + 0x20);
		if (!fsz || off + fsz > end)
			continue;
		/*
		 * A segment that cannot be read is left as the zeroes calloc
		 * gave, rather than failing the whole rebuild. A run stopped
		 * partway has some of its segments and not others, and a file
		 * holding the ones it does have is worth more than no file.
		 */
		if (!rd(user, bias + vaddr, file + off, (uint32_t)fsz))
			continue;
		if (bias + vaddr < lo)
			lo = bias + vaddr;
		if (bias + vaddr + fsz > hi)
			hi = bias + vaddr + fsz;
	}
	if (lo == ~0ull) {
		free(file);
		goto no;                        /* nothing could be read back */
	}
	if (have_sh && shoff + (uint64_t)shnum * SHENT64 <= end)
		rd(user, bias + shoff, file + shoff,
		   (uint32_t)((uint64_t)shnum * SHENT64));
	else if (!have_sh) {
		/*
		 * Say stripped rather than carry a table that is not one - and
		 * say it AFTER the segments are laid down, not before. The
		 * first PT_LOAD covers file offset zero in every ordinary ELF,
		 * so copying it puts the guest's original header back over
		 * anything written here first. Patched ahead of that copy, this
		 * had no effect at all and the broken table went out in the
		 * rebuilt file.
		 */
		memset(file + 0x28, 0, 8);      /* e_shoff     */
		memset(file + 0x3a, 0, 2);      /* e_shentsize */
		memset(file + 0x3c, 0, 2);      /* e_shnum     */
		memset(file + 0x3e, 0, 2);      /* e_shstrndx  */
	}

	free(ph);
	*out = file;
	*out_len = end;
	if (covered_lo)
		*covered_lo = lo;
	if (covered_hi)
		*covered_hi = hi;
	return 1;
no:
	free(ph);
	return 0;
}

/* ---- a header from a declared layout ------------------------------------- */

static void ew32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static void ew64(uint8_t *p, uint64_t v)
{
	ew32(p, (uint32_t)v);
	ew32(p + 4, (uint32_t)(v >> 32));
}

static void ew16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

uint64_t kof_elf_write_hdr(uint8_t *out, uint64_t cap, int is64,
			   uint16_t machine, uint64_t base,
			   const struct kof_sec_decl *sec, uint32_t n,
			   uint64_t entry_rva, int has_entry,
			   uint64_t image_end)
{
	const uint64_t eh = is64 ? 64u : 52u;
	const uint64_t ph = is64 ? 56u : 32u;
	uint64_t need = eh + ph;
	uint8_t *p;
	uint32_t i, flags = 0;

	if (!out || !n || !sec || need > cap || !image_end)
		return 0;
	/*
	 * The header has to end where the first section begins, or the two
	 * describe different files. A caller that left more room is not wrong -
	 * the gap is padding - but one that left less is.
	 */
	if (sec[0].rva < need)
		return 0;

	for (i = 0; i < n; i++) {
		if (sec[i].perm & KOF_PE_PERM_X)
			flags |= 1u;         /* PF_X */
		if (sec[i].perm & KOF_PE_PERM_W)
			flags |= 2u;         /* PF_W */
		if (sec[i].perm & KOF_PE_PERM_R)
			flags |= 4u;         /* PF_R */
	}
	if (!flags)
		flags = 4u;

	memset(out, 0, (size_t)need);
	out[0] = 0x7f; out[1] = 'E'; out[2] = 'L'; out[3] = 'F';
	out[4] = (uint8_t)(is64 ? 2 : 1);        /* EI_CLASS   */
	out[5] = 1;                              /* ELFDATA2LSB */
	out[6] = 1;                              /* EV_CURRENT  */
	/*
	 * ET_EXEC ONLY WHEN THE PRODUCER SAID WHERE EXECUTION STARTS.
	 *
	 * It was unconditionally ET_EXEC, and that made it impossible to
	 * DECLARE the one thing a carved blob honestly is: bytes lifted out of
	 * a loader's variable, which have no entry point because nothing ever
	 * jumped to their first byte. Expressed as ET_EXEC with e_entry 0 the
	 * parser raises KOF_ELF_ANOM_ENTRY_ZERO - correctly, that combination
	 * is nonsense - so the engine would have flagged its own
	 * reconstruction, and a module that wanted to avoid it had to write
	 * the header itself. bases/unp/scpayload_00.c did exactly that.
	 *
	 * ET_DYN is not a workaround for the anomaly; it is what the object is.
	 * The parser's own note says why nothing fires on it: measured over
	 * /usr/bin and /usr/lib, 535 of 1316 objects are shared libraries with
	 * a legitimately zero e_entry, so a zero entry is only anomalous where
	 * the type promises one.
	 */
	ew16(out + 0x10, (uint16_t)(has_entry ? 2 : 3));  /* ET_EXEC/ET_DYN */
	ew16(out + 0x12, machine);
	ew32(out + 0x14, 1);                     /* e_version   */

	if (is64) {
		ew64(out + 0x18, has_entry ? base + entry_rva : 0);
		ew64(out + 0x20, eh);                /* e_phoff     */
		ew16(out + 0x34, (uint16_t)eh);      /* e_ehsize    */
		ew16(out + 0x36, (uint16_t)ph);      /* e_phentsize */
		ew16(out + 0x38, 1);                 /* e_phnum     */
	} else {
		ew32(out + 0x18, (uint32_t)(has_entry ? base + entry_rva : 0));
		ew32(out + 0x1c, (uint32_t)eh);
		ew16(out + 0x28, (uint16_t)eh);
		ew16(out + 0x2a, (uint16_t)ph);
		ew16(out + 0x2c, 1);
	}

	p = out + eh;
	if (is64) {
		ew32(p + 0x00, 1);                   /* PT_LOAD  */
		ew32(p + 0x04, flags);
		ew64(p + 0x08, 0);                   /* p_offset */
		ew64(p + 0x10, base);                /* p_vaddr  */
		ew64(p + 0x18, base);                /* p_paddr  */
		ew64(p + 0x20, image_end);           /* p_filesz */
		ew64(p + 0x28, image_end);           /* p_memsz  */
		ew64(p + 0x30, 0x1000);              /* p_align  */
	} else {
		ew32(p + 0x00, 1);
		ew32(p + 0x04, 0);
		ew32(p + 0x08, (uint32_t)base);
		ew32(p + 0x0c, (uint32_t)base);
		ew32(p + 0x10, (uint32_t)image_end);
		ew32(p + 0x14, (uint32_t)image_end);
		ew32(p + 0x18, flags);
		ew32(p + 0x1c, 0x1000);
	}
	return need;
}
