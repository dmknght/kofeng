/*
 * embedded.c - see embedded.h.
 */

#include <string.h>

#include <kofmod/kofsig.h>

#include "embedded.h"

#define EHDR64  64u
#define EHDR32  52u

static uint16_t r16(const uint8_t *p, int be)
{
	return be ? (uint16_t)((p[0] << 8) | p[1])
		  : (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t r32(const uint8_t *p, int be)
{
	return be ? ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
		    ((uint32_t)p[2] << 8) | p[3]
		  : (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
		    ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t r64(const uint8_t *p, int be)
{
	return be ? ((uint64_t)r32(p, 1) << 32) | r32(p + 4, 1)
		  : (uint64_t)r32(p, 0) | ((uint64_t)r32(p + 4, 0) << 32);
}

/*
 * The machines worth believing.
 *
 * Not every value the standard allows - a list that accepts anything accepts
 * two random bytes, and two random bytes is what most occurrences of the magic
 * are followed by. These are the ones malware is actually built for, which is
 * also the set a scanner could do anything with.
 */
static int machine_known(uint16_t m)
{
	switch (m) {
	case 3:    /* x86      */
	case 8:    /* MIPS     */
	case 20:   /* PPC      */
	case 21:   /* PPC64    */
	case 40:   /* ARM      */
	case 62:   /* x86-64   */
	case 183:  /* AArch64  */
	case 243:  /* RISC-V   */
		return 1;
	default:
		return 0;
	}
}

/*
 * How far the embedded ELF reaches, from its own headers.
 *
 * The furthest of every PT_LOAD's file extent and the section table, which is
 * what the file itself claims to be. Clamped to the parent, because a length
 * read out of a header found inside another file is the least trustworthy
 * number in this function - and a child bounded by its parent is always a real
 * range, however wrong the header is.
 */
static uint64_t elf_extent(const uint8_t *p, uint64_t avail, int cls, int be)
{
	uint64_t phoff, shoff, end;
	uint16_t phent, phnum, shent, shnum;
	uint32_t i;

	if (cls == 2) {
		end   = EHDR64;
		phoff = r64(p + 0x20, be);
		shoff = r64(p + 0x28, be);
		phent = r16(p + 0x36, be);
		phnum = r16(p + 0x38, be);
		shent = r16(p + 0x3a, be);
		shnum = r16(p + 0x3c, be);
	} else {
		end   = EHDR32;
		phoff = r32(p + 0x1c, be);
		shoff = r32(p + 0x20, be);
		phent = r16(p + 0x2a, be);
		phnum = r16(p + 0x2c, be);
		shent = r16(p + 0x2e, be);
		shnum = r16(p + 0x30, be);
	}
	/*
	 * An implausible count discards THAT TABLE, not the file.
	 *
	 * Bailing out entirely was wrong and the test caught it: a header
	 * planted in a buffer of filler had a section count of 0x4141, and the
	 * program headers beside it were perfectly good. A file whose section
	 * table cannot be believed is an ordinary stripped or damaged file, and
	 * its segments still say how long it is.
	 */
	if (phnum > 128u)
		phnum = 0;
	if (shnum > 4096u)
		shnum = 0;

	for (i = 0; i < phnum; i++) {
		uint64_t at = phoff + (uint64_t)i * phent, off, fsz;

		if (phent < (cls == 2 ? 56u : 32u) || at + phent > avail)
			break;
		if (r32(p + at, be) != 1u)
			continue;           /* PT_LOAD only */
		if (cls == 2) {
			off = r64(p + at + 0x08, be);
			fsz = r64(p + at + 0x20, be);
		} else {
			off = r32(p + at + 0x04, be);
			fsz = r32(p + at + 0x10, be);
		}
		if (off > avail || fsz > avail - off)
			continue;           /* claims past the parent: ignore */
		if (off + fsz > end)
			end = off + fsz;
	}
	if (shoff && shent && shnum && shoff < avail &&
	    (uint64_t)shnum * shent <= avail - shoff &&
	    shoff + (uint64_t)shnum * shent > end)
		end = shoff + (uint64_t)shnum * shent;

	return end > avail ? avail : end;
}

int kof_embedded_at(const uint8_t *p, uint64_t n, uint64_t off,
		    struct kof_embedded *out)
{
	const uint8_t *h;
	uint64_t avail;

	/* Offset zero is the object itself, and reporting it as a child of
	 * itself would put every executable inside a copy of itself. */
	if (!p || !out || !off || off >= n)
		return 0;
	h = p + off;
	avail = n - off;

	if (avail >= EHDR32 && !memcmp(h, "\177ELF", 4)) {
		int cls = h[4], dat = h[5], be;
		uint16_t et, em, ehsize;
		uint64_t len;

		if ((cls != 1 && cls != 2) || (dat != 1 && dat != 2) || h[6] != 1)
			return 0;
		if (cls == 2 && avail < EHDR64)
			return 0;
		be = dat == 2;
		et     = r16(h + 0x10, be);
		em     = r16(h + 0x12, be);
		ehsize = r16(h + (cls == 2 ? 0x34 : 0x28), be);
		/* ET_REL, ET_EXEC, ET_DYN, ET_CORE and nothing else. */
		if (et < 1u || et > 4u || !machine_known(em))
			return 0;
		if (ehsize != (cls == 2 ? EHDR64 : EHDR32))
			return 0;
		len = elf_extent(h, avail, cls, be);
		if (len < (cls == 2 ? EHDR64 : EHDR32))
			return 0;
		out->off = off;
		out->len = len;
		out->fmt = KOF_FMT_ELF;
		return 1;
	}

	/*
	 * PE, reached the way a loader reaches it: the DOS stub's e_lfanew,
	 * then the signature it points at. Two independent agreements, which is
	 * what makes "MZ" mean something - on its own it is two letters.
	 */
	if (avail >= 0x40u && h[0] == 'M' && h[1] == 'Z') {
		uint32_t lfa = r32(h + 0x3c, 0);
		uint16_t mach;
		uint32_t nsec, i, end = 0;

		if (lfa < 4u || lfa > avail || avail - lfa < 24u)
			return 0;
		if (memcmp(h + lfa, "PE\0\0", 4))
			return 0;
		mach = r16(h + lfa + 4, 0);
		if (mach != 0x14cu && mach != 0x8664u &&
		    mach != 0x1c0u && mach != 0xaa64u)
			return 0;
		nsec = r16(h + lfa + 6, 0);
		if (nsec > 96u)
			return 0;
		{
			uint16_t opt = r16(h + lfa + 20, 0);
			uint64_t sec = lfa + 24u + opt;

			end = (uint32_t)(sec > avail ? avail : sec);
			for (i = 0; i < nsec && sec + 40u <= avail; i++, sec += 40u) {
				uint32_t raw = r32(h + sec + 20, 0);
				uint32_t rsz = r32(h + sec + 16, 0);

				if (raw > avail || rsz > avail - raw)
					continue;
				if (raw + rsz > end)
					end = raw + rsz;
			}
		}
		if (end < 0x40u)
			return 0;
		out->off = off;
		out->len = end > avail ? avail : end;
		out->fmt = KOF_FMT_PE;
		return 1;
	}
	return 0;
}
