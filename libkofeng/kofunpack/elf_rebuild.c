/*
 * elf_rebuild.c - see elf_rebuild.h.
 */

#include <stdlib.h>
#include <string.h>

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
