/*
 * mpress_pe.c - unpack an MPRESS packed PE.
 *
 * Written because the emulator was doing this job and failing at it. On one
 * sample - a 2,770,432 byte PE32+ - kof_emu_unp_gate_pe answered DENSE, the
 * interpreter spent its entire 268,435,456 instruction ceiling and produced
 * nothing, and the scan cost 21.35 seconds against 0.015 with the emulator off.
 * Nothing was recovered for the 21 seconds; the object was reported exactly as
 * it is reported when no emulator runs at all.
 *
 * There is no anti-emulation in that stub and this is not a workaround for one.
 * Its 918 decoded instructions contain no rdtsc, no cpuid, no PEB read, no
 * indirect call and no syscall: it is a straight LZMA decompressor, which is
 * precisely the shape emu_unpack.h says an interpreter reaches. It fails on
 * SIZE alone. The stub must decode 8,183,808 bytes, and LZMA costs on the order
 * of a hundred guest instructions per output byte, so the work is around a
 * billion instructions against a ceiling of 268 million. The gate could have
 * known that before starting: the number is the section's VirtualSize, which is
 * in the header.
 *
 * So this module exists for the ordinary reason a static unpacker exists - it
 * reads the header and calls the decoder, and on that sample it produced all
 * 8,183,808 bytes in milliseconds.
 *
 *
 * THE CONTAINER
 *
 * MPRESS writes two sections: the payload, and a stub. The payload section
 * begins with six bytes of header followed by two bytes of LZMA properties and
 * then the stream:
 *
 *     +0  u16   the uncompressed size, in 4096 byte units
 *     +2  u32   the compressed size, counting the two property bytes
 *     +6  u8    pb in the high nibble, lp in the low nibble
 *     +7  u8    lc
 *     +8        a raw LZMA1 stream, standard five byte range coder init
 *
 * Read off the stub's own entry code rather than from a specification: the
 * entry reads the word, shifts it left by twelve and keeps it as the output
 * length; reads the dword and uses it as a copy length; then takes the two
 * property bytes apart with `shr $4` and `and $0xf` and sizes a probability
 * array of 0x300 << (lc + lp) entries on the stack, which is LZMA's and only
 * LZMA's.
 *
 * Confirmed by decoding, on the seven files in one collection that carry this
 * container. FIVE decode to exactly the length the section declares, not
 * approximately and not in part:
 *
 *     PE32+  lc=5 lp=0 pb=2   0x7ce000 of 0x7ce000
 *     PE32   lc=5 lp=0 pb=2   0x4f1000 of 0x4f1000
 *     PE32   lc=5 lp=0 pb=2   0x592000 of 0x592000
 *     PE32   lc=7 lp=0 pb=2   0xda8000 of 0xda8000
 *     PE32   lc=4 lp=0 pb=2   0x0b4000 of 0x0b4000
 *
 * Both widths, three values of lc, and the width is not what varies with it -
 * a PE32 and a PE32+ share lc=5. So nothing here branches on pe32_plus: the
 * parameters are in the file because the packer put them there.
 *
 * Note lc + lp = 5 on four of those. liblzma refuses that combination - LZMA1
 * in xz requires lc + lp <= 4 - which is why a decode through the system
 * library reports an internal error on these files and this engine's decoder
 * does not. KOF_LZMA_MAX_LC is 8 because the specification says 8.
 *
 *
 * THE OTHER TWO, WHICH ARE NOT LZMA AT ALL
 *
 * The remaining two carry the same six byte size header - the word still times
 * 4096 to exactly the section's VirtualSize - and then something else. Their
 * property bytes are 0x6a 0x00, which would be pb=6 and lp=10, and both are
 * outside what LZMA allows; the range check below is what notices.
 *
 * It is not a corrupt file and the disassembly says so. Their stub reads the
 * same word and the same dword, performs the same backward copy, and then
 * calls its decoder with nothing but a source and a destination - no property
 * bytes read, no probability array sized, none of the `shr $4` / `and $0xf`
 * the LZMA stub does. An earlier MPRESS with a different coding, and the two
 * bytes this reads as properties are the first two bytes of its stream.
 *
 * So they are reported KOF_UNP_UNSUPPORTED, which is what they are: a version
 * this build lacks. Adding that coding is a separate piece of work with its own
 * measurement, and until it happens these two objects are honestly described
 * rather than quietly declared clean.
 *
 * A stream of that older kind whose first two bytes happened to parse as valid
 * properties would be decoded as LZMA and produce garbage - and then `got`
 * falls short of what the section declared, the comparison at the end notices,
 * and the object is reported not fully examined. Wrong in the same safe
 * direction the rest of this directory is wrong in.
 *
 *
 * FINDING THE PAYLOAD SECTION WITHOUT ITS NAME
 *
 * The sections are called .MPRESS1 and .MPRESS2 and this does not look at the
 * names, for the reason upx_pe.c gives about UPX1: a name is a string whoever
 * built the file chose, and renaming one is free.
 *
 * What cannot be renamed is that the header's size field and the section's
 * VirtualSize are the same number written twice. The stub reads the word at the
 * payload's first byte, shifts it left by twelve, and decompresses that many
 * bytes into the section - so a section whose VirtualSize is not exactly
 * (u16 << 12) is not one MPRESS wrote, and one whose VirtualSize is cannot be a
 * coincidence in any file that also passes the three checks below. Two
 * independent numbers agreeing, at a cost of eight bytes read per section.
 *
 * The entry section is excluded because it is the stub, and a section is
 * required to be at least two pages so the agreement is a statement rather than
 * arithmetic on a small number.
 *
 * MEASURED, because an invariant that costs nothing is still worth nothing if
 * it fires on ordinary files: over 7909 PE files from one malware collection,
 * this matches 0. All seven matches in the other collection are MPRESS, by the
 * section name this deliberately does not read.
 *
 *
 * WHAT THIS DOES NOT DO
 *
 * It does not rebuild the PE, and cannot: what comes out is the image from
 * VirtualAddress 0x1000 upward, and the original headers are not in it - MPRESS
 * wrote its own. So the child is handed over as KOF_FORM_RAW and identifies as
 * nothing in particular, which is what it is. Whether the file's own headers
 * are close enough to the original's to splice on is a question for
 * measurement, not for assumption.
 */

#include <kofmod/kofsig.h>
#include <kofmod/heur.h>
#include <kofmod/pe.h>
#include <kofunpack/pe_reassemble.h>

KOF_UNPACK_KIND(KOF_UNP_PACKER);

KOF_TARGET_FORMAT(KOF_FMT_PE);

#define MP_HDR       8u         /* six bytes of sizes, two of properties */
#define MP_UNIT      12u        /* the uncompressed size is in 4096s */
#define MP_MIN_MEM   0x2000u    /* two pages, below which the match is noise */


/*
 * WHERE THE UNPACKED PROGRAM STARTS, READ OUT OF THE STUB RATHER THAN GUESSED.
 *
 * The stub does not jump to the payload. It OVERWRITES ITS OWN ENTRY POINT
 * with a jump and then falls into it, and the two instructions that do the
 * overwriting carry the destination as an immediate:
 *
 *     b0 e9        mov  al, 0xe9        the opcode of a near jump
 *     aa           stosb                written at the entry point
 *     b8 <imm32>   mov  eax, imm32      its displacement
 *     ab           stosd                written just after
 *
 * so after the patch the entry point reads `jmp entry + 5 + imm32`. At that
 * address is a second `e9`, and THAT one lands in the decompressed image - it
 * is the second stage, the part that resolves imports and finally reaches the
 * original program.
 *
 * Both hops are checked, and anything unexpected gives up rather than
 * improvises: an entry point of zero says "this could not be recovered", which
 * the host can act on, where a wrong one says "start here" about an address
 * nothing is at.
 *
 * Measured on the PE32+ sample: imm32 = 0xae2, so the patched jump sits at
 * rva 0x7cfb6c, its own displacement is -0x5d30e7, and the second stage is at
 * rva 0x1fca8a - which is inside the section this module decompresses, as it
 * has to be.
 */
static uint64_t mp_stage2_rva(const struct kof_obj_ctx *ctx,
			      const struct kof_pe_sec *stub, uint64_t entry_rva)
{
	uint64_t at, end;

	if (!stub->file_size)
		return 0;
	end = stub->file_off + stub->file_size;
	for (at = stub->file_off; at + 9u <= end; at++) {
		uint64_t site, rel, s2;

		if (kof_u8(at) != 0xb0u || kof_u8(at + 1u) != 0xe9u ||
		    kof_u8(at + 2u) != 0xaau || kof_u8(at + 3u) != 0xb8u ||
		    kof_u8(at + 8u) != 0xabu)
			continue;
		site = entry_rva + 5u + kof_u32(at + 4u);
		if (site < stub->mem_rva ||
		    site + 5u > stub->mem_rva + stub->file_size)
			return 0;               /* not inside the stub */
		site = stub->file_off + (site - stub->mem_rva);
		if (kof_u8(site) != 0xe9u)
			return 0;               /* not the jump it should be */
		rel = kof_u32(site + 1u);
		/* Both the site and the displacement are 32-bit and the
		 * arithmetic wraps, which is what the processor does. */
		s2 = (uint64_t)(uint32_t)((uint32_t)(site - stub->file_off +
						     stub->mem_rva) + 5u +
					  (uint32_t)rel);
		return s2;
	}
	return 0;
}

/*
 * ---- WHICH MPRESS THIS IS, FROM THE STUB ----------------------------------
 *
 * MPRESS writes no version anywhere in the file - no string, no header field -
 * but the stub tells you anyway: the dword at EP+8 is the offset of the fix
 * imports stub, and that offset is different in every build. RetDec's MPRESS
 * plugin turns that into an identification by keeping a table of the offsets
 * it has seen, and rejects anything above 0xC00 as a corrupted stub. The idea
 * and the table are theirs - see THIRD-PARTY.md.
 *
 * Measured on the seven MPRESS files here: four are 0xb5a and two are 0x29f,
 * which the table names 2.12-2.19 LZMA and 2.12-2.19 LZMAT, and the seventh is
 * PE32+ and matches nothing - RetDec does not handle PE32+ at all, so its
 * table has no x64 entry and the number there is not an offset of this kind.
 *
 * WHAT IT IS FOR HERE. A build this module has not seen is one whose stub may
 * be laid out differently, and running an interpreter over its output costs
 * seconds for a run that has no reason to go anywhere. So the version gates
 * that request, and is worth reporting on its own.
 */
/* The name is an ARRAY and not a pointer: a table of pointers needs a
 * relocation for each one, which lands in writable data, and a module may hold
 * no state. */
struct mp_build {
	uint32_t sig;   /* the dword at EP+8, which is the fix stub's offset */
	uint32_t pco;   /* EP+this holds the packed section's relative address */
	uint32_t fso;   /* EP+this holds the fix stub's relative address */
	uint32_t lzmat; /* the coding: 1 for LZMAT, 0 for LZMA */
	char name[24];
};

static const struct mp_build mp_builds[] = {
	{ 0x2b6u, 0x2bcu, 0x2b8u, 1u, "MPRESS 1.01-1.05 LZMAT" },
	{ 0x29eu, 0x2a4u, 0x2a0u, 1u, "MPRESS 1.07-1.27 LZMAT" },
	{ 0x299u, 0x29fu, 0x29bu, 1u, "MPRESS 2.01 LZMAT"      },
	{ 0xb57u, 0xb5du, 0xb59u, 0u, "MPRESS 2.05 LZMA"       },
	{ 0x29cu, 0x2a2u, 0x29eu, 1u, "MPRESS 2.05 LZMAT"      },
	{ 0xb5au, 0xb60u, 0xb5cu, 0u, "MPRESS 2.12-2.19 LZMA"  },
	{ 0x29fu, 0x2a5u, 0x2a1u, 1u, "MPRESS 2.12-2.19 LZMAT" }
};

/*
 * The fix stub itself comes in three shapes, told apart by one byte seven
 * bytes into it, and each says where the import hints and the original entry
 * point are written relative to its own start. RetDec's table - see
 * THIRD-PARTY.md.
 */
struct mp_fix {
	uint32_t mark;  /* the byte at fixStub + 7 */
	uint32_t hints; /* and where the hints offset is written */
	uint32_t oep;   /* and where the entry point offset is */
};

static const struct mp_fix mp_fixes[] = {
	{ 0x8bu, 0x0c1u, 0x0bdu },      /* 1.0x   */
	{ 0x45u, 0x138u, 0x134u },      /* 1.27-2.0x */
	{ 0x35u, 0x128u, 0x124u }       /* 2.1x   */
};

/* The table's name for this file's stub, or NULL when it is not one of them. */
static const struct mp_build *mp_build_of(const struct kof_obj_ctx *ctx,
					  const struct kof_pe_info *pe)
{
	const struct kof_pe_sec *es;
	uint64_t at;
	uint32_t sig;
	unsigned k;

	if (pe->entry_sec >= pe->sec_count)
		return 0;
	es = &pe->sec[pe->entry_sec];
	if (pe->entry_rva < es->mem_rva)
		return 0;
	at = es->file_off + (pe->entry_rva - es->mem_rva) + 8u;
	if (!kof_in_obj(at, 4u))
		return 0;
	sig = kof_u32(at);
	if (sig >= 0xc00u)
		return 0;               /* not an offset into the stub */
	for (k = 0; k < sizeof mp_builds / sizeof mp_builds[0]; k++)
		if (mp_builds[k].sig == sig)
			return &mp_builds[k];
	return 0;
}

/*
 * ---- THE ORIGINAL ENTRY POINT, OUT OF WHAT WAS JUST PRODUCED --------------
 *
 * MPRESS keeps the program's real entry point in a fix-up stub that it
 * compressed together with the program, so it is knowable only after the
 * content exists. kunp_rcstruct_read reaches back into the produced child to find it
 * and kunp_rcstruct_entry says what it is; see produced_read in kofsig.h for why
 * unpack_peek cannot do this.
 *
 * The child is a flat image - file offset equals RVA, which is how the
 * sections above are laid - so an offset inside the packed section is that
 * section's RVA plus the offset.
 *
 * Returns the entry RVA, or 0 when any step does not hold. Every read is
 * checked: this walks offsets a file supplied.
 */
/* Where the fix stub is, as an offset inside the packed section, and which of
 * the three shapes it has. 1 when both are known. */
static int mp_fixup(const struct kof_obj_ctx *ctx, const struct kof_pe_info *pe,
		    const struct mp_build *b, uint32_t found,
		    uint32_t *fix_out, uint32_t *row_out)
{
	const struct kof_pe_sec *es, *ps;
	uint64_t ep_off;
	uint32_t fix, pcs, k;
	uint8_t mark = 0;

	if (!b || found >= pe->sec_count || pe->entry_sec >= pe->sec_count)
		return 0;
	es = &pe->sec[pe->entry_sec];
	ps = &pe->sec[found];
	if (pe->entry_rva < es->mem_rva)
		return 0;
	ep_off = es->file_off + (pe->entry_rva - es->mem_rva);
	if (!kof_in_obj(ep_off + b->pco, 4u) || !kof_in_obj(ep_off + b->fso, 4u))
		return 0;

	/* Where the packed section is, said relative to the stub. */
	pcs = (uint32_t)pe->entry_rva + b->pco + kof_u32(ep_off + b->pco);
	if (pcs != ps->mem_rva)
		return 0;               /* not the section this decompressed */

	/* And the fix stub, as an offset inside that section. */
	fix = (uint32_t)pe->entry_rva + b->fso + 4u +
	      kof_u32(ep_off + b->fso) - pcs;
	if (fix >= ps->mem_size)
		return 0;
	if (kunp_rcstruct_read((uint64_t)ps->mem_rva + fix + 7u, &mark, 1u) != 1u)
		return 0;
	for (k = 0; k < sizeof mp_fixes / sizeof mp_fixes[0]; k++)
		if (mp_fixes[k].mark == mark) {
			*fix_out = fix;
			*row_out = k;
			return 1;
		}
	return 0;
}

/* The entry point the program actually has. 0 when it is not recoverable. */
static uint32_t mp_oep_of(const struct kof_obj_ctx *ctx,
			  const struct kof_pe_info *pe,
			  const struct mp_build *b, uint32_t found)
{
	uint32_t fix = 0, row = 0, at;
	uint64_t sect_rva;
	uint8_t raw[4];

	if (!mp_fixup(ctx, pe, b, found, &fix, &row))
		return 0;
	sect_rva = pe->sec[found].mem_rva;
	at = fix + mp_fixes[row].oep;
	if (at + 4u > pe->sec[found].mem_size)
		return 0;
	if (kunp_rcstruct_read(sect_rva + at, raw, 4u) != 4u)
		return 0;
	return (uint32_t)sect_rva + fix + mp_fixes[row].hints +
	       ((uint32_t)raw[0] | ((uint32_t)raw[1] << 8) |
		((uint32_t)raw[2] << 16) | ((uint32_t)raw[3] << 24));
}

/*
 * ---- THE IMPORT TABLE, REBUILT FROM THE HINTS ------------------------------
 *
 * MPRESS throws the original import directory away and leaves a compact list
 * in its place, compressed with the program: for each library, a delta to the
 * IAT slot its functions go in, the library's name, then the names or ordinals
 * of its functions, and -1 at the end. The stub walks that list at run time
 * and writes the addresses into the IAT. RetDec's plugin rebuilds a real
 * directory from it - see THIRD-PARTY.md - and this does the same.
 *
 * WHY IT MATTERS HERE. Without it the child has no import directory at all:
 * the names are in it as loose strings, so a rule looking for text finds them,
 * but nothing that asks the object WHAT IT IMPORTS gets an answer, and that is
 * most of what a PE's imports are worth to a scan. Measured on one sample:
 * five descriptors, seventeen functions, four libraries.
 *
 * The rebuilt directory goes in a section appended after the image, and the
 * header emitted before any of this existed is corrected to point at it - see
 * produced_poke in kofsig.h.
 */
#define MP_IMP_MAX_MOD 32u
#define MP_IMP_MAX_FN  512u
#define MP_IMP_CAP     (32u * 1024u)
#define MP_IMP_NAME    64u

/* A NUL terminated string out of the produced child. Returns its length, or
 * MP_IMP_NAME when it does not end inside the cap - which is not a name. */
static uint32_t mp_str_at(const struct kof_obj_ctx *ctx, uint64_t off,
			  char *out, uint32_t cap)
{
	uint32_t n = 0;

	while (n + 1u < cap) {
		uint8_t c = 0;

		if (kunp_rcstruct_read(off + n, &c, 1u) != 1u)
			return cap;
		out[n] = (char)c;
		if (!c)
			return n;
		n++;
	}
	return cap;
}

/*
 * Walk the hint list. With `img` NULL this only counts; with it, the directory
 * is written at `base`. Returns the bytes the directory needs, or 0.
 */
static uint32_t mp_imports(const struct kof_obj_ctx *ctx,
			   const struct kof_pe_info *pe, uint32_t found,
			   uint32_t hints_rva, uint32_t base,
			   uint8_t *img, uint32_t cap,
			   uint32_t *iat_lo, uint32_t *iat_hi)
{
	uint64_t sect = pe->sec[found].mem_rva;
	uint32_t lim = (uint32_t)pe->sec[found].mem_size;
	uint32_t rp = hints_rva, dest = (uint32_t)sect + hints_rva;
	uint32_t nmod = 0, nfn = 0, strn = 0, m;
	uint32_t ilt_at, str_at, w_ilt, w_str;
	char nm[MP_IMP_NAME];
	uint8_t f4[4];

	/* ---- pass one: how many, and how much text ---- */
	for (m = 0; m < MP_IMP_MAX_MOD; m++) {
		uint8_t raw[4];
		int32_t diff;
		uint32_t len, cnt = 0;

		if (rp + 4u > lim || kunp_rcstruct_read(sect + rp, raw, 4u) != 4u)
			return 0;
		diff = (int32_t)((uint32_t)raw[0] | ((uint32_t)raw[1] << 8) |
				 ((uint32_t)raw[2] << 16) |
				 ((uint32_t)raw[3] << 24));
		if (diff == -1)
			break;
		dest += (uint32_t)diff;
		rp += 4u;
		len = mp_str_at(ctx, sect + rp, nm, MP_IMP_NAME);
		if (len >= MP_IMP_NAME || !len)
			return 0;
		strn += len + 1u;
		rp += len + 1u;
		for (;;) {
			uint8_t b = 0;

			if (rp >= lim || kunp_rcstruct_read(sect + rp, &b, 1u) != 1u)
				return 0;
			if (!b)
				break;
			if (b <= 0x20u) {
				rp += 3u;       /* by ordinal */
			} else {
				len = mp_str_at(ctx, sect + rp, nm,
						MP_IMP_NAME);
				if (len >= MP_IMP_NAME)
					return 0;
				strn += 2u + len + 1u;
				rp += len + 1u;
			}
			if (++cnt > MP_IMP_MAX_FN)
				return 0;
			nfn++;
		}
		rp++;
		if (iat_lo && (!*iat_lo || dest < *iat_lo))
			*iat_lo = dest;
		if (iat_hi && dest + cnt * 4u > *iat_hi)
			*iat_hi = dest + cnt * 4u;
		dest += cnt * 4u;
		nmod++;
	}
	if (!nmod || nfn > MP_IMP_MAX_FN)
		return 0;

	ilt_at = (nmod + 1u) * 20u;
	str_at = ilt_at + (nfn + nmod) * 4u;
	if (str_at + strn > cap)
		return 0;
	if (!img)
		return str_at + strn;

	/* ---- pass two: write it ---- */
	for (m = 0; m < str_at + strn; m++)
		img[m] = 0;
	rp = hints_rva;
	dest = (uint32_t)sect + hints_rva;
	w_ilt = ilt_at;
	w_str = str_at;
	for (m = 0; m < nmod; m++) {
		uint8_t raw[4];
		int32_t diff;
		uint32_t len, d = m * 20u, step = 0, name_rva;

		if (kunp_rcstruct_read(sect + rp, raw, 4u) != 4u)
			return 0;
		diff = (int32_t)((uint32_t)raw[0] | ((uint32_t)raw[1] << 8) |
				 ((uint32_t)raw[2] << 16) |
				 ((uint32_t)raw[3] << 24));
		dest += (uint32_t)diff;
		rp += 4u;
		len = mp_str_at(ctx, sect + rp, nm, MP_IMP_NAME);
		name_rva = base + w_str;
		for (; w_str < str_at + strn && nm[w_str - name_rva + base]; )
			break;                  /* placeholder: copied below */
		{
			uint32_t k;

			for (k = 0; k <= len; k++)
				img[w_str + k] = (uint8_t)nm[k];
			w_str += len + 1u;
		}
		rp += len + 1u;

		pei_put32(img + d + 0u, base + w_ilt);   /* OriginalFirstThunk */
		pei_put32(img + d + 12u, name_rva);      /* Name */
		pei_put32(img + d + 16u, dest);          /* FirstThunk = the IAT */

		for (;;) {
			uint8_t b = 0;

			if (kunp_rcstruct_read(sect + rp, &b, 1u) != 1u)
				return 0;
			if (!b)
				break;
			if (b <= 0x20u) {
				uint8_t o2[2] = { 0, 0 };

				if (kunp_rcstruct_read(sect + rp + 1u, o2, 2u) != 2u)
					return 0;
				pei_put32(img + w_ilt,
					  0x80000000u |
					  ((uint32_t)o2[0] |
					   ((uint32_t)o2[1] << 8)));
				rp += 3u;
			} else {
				uint32_t k;

				len = mp_str_at(ctx, sect + rp, nm,
						MP_IMP_NAME);
				pei_put32(img + w_ilt, base + w_str);
				img[w_str] = 0;
				img[w_str + 1u] = 0;    /* the hint */
				for (k = 0; k <= len; k++)
					img[w_str + 2u + k] = (uint8_t)nm[k];
				w_str += 2u + len + 1u;
				rp += len + 1u;
			}
			/*
			 * AND THE SAME VALUE INTO THE IAT ITSELF.
			 *
			 * The stub filled these slots at run time and they are
			 * zero in what this module produced; a loader reading
			 * the file finds an import directory pointing at an
			 * empty IAT. Written here with the lookup entry, which
			 * is what the thunk holds before binding.
			 *
			 * Measured against Avast's own unpacked output of the
			 * same file: 1264 of 1265 pages already matched byte
			 * for byte, and the one that did not was this table.
			 */
			f4[0] = img[w_ilt];      f4[1] = img[w_ilt + 1u];
			f4[2] = img[w_ilt + 2u]; f4[3] = img[w_ilt + 3u];
			kunp_rcstruct_poke(dest + step, f4, 4u);
			w_ilt += 4u;
			step += 4u;
		}
		rp++;
		w_ilt += 4u;                    /* the null thunk */
		dest += step;
	}
	return str_at + strn;
}

/*
 * Build the directory, append it as a section, and correct the header that was
 * emitted before any of it existed.
 */
static void mp_emit_imports(const struct kof_obj_ctx *ctx,
			    const struct kof_pe_info *pe, uint32_t found,
			    uint32_t hints_rva, uint32_t need)
{
	uint8_t img[MP_IMP_CAP];
	uint32_t base = (uint32_t)pei_image_end(pe);

	if (need > sizeof img)
		return;
	if (mp_imports(ctx, pe, found, hints_rva, base, img, sizeof img,
		       0, 0) != need)
		return;
	/*
	 * WRITTEN WHERE IT BELONGS, AND SAID TO BE THERE.
	 *
	 * This used to emit the bytes at whatever the sink had reached, then
	 * poke five fields into a header the module had built: a section entry,
	 * NumberOfSections, the import directory's address and size, and
	 * SizeOfImage. Every one of those is now a consequence of the
	 * declaration rather than a thing to keep in step by hand - and
	 * `.kofimp` was reserved in the layout before the image existed, so the
	 * room is already there.
	 */
	if (!kunp_rcstruct_at(base) || !kunp_rcstruct_write(img, need))
		return;
	kunp_rcstruct_section(".kofimp", base, need, KOF_PE_PERM_R,
			KOF_SECF_DATA | KOF_SECF_SYNTHETIC);
	kunp_rcstruct_dir(KOF_PE_DIR_IMPORT, base, need);
}

/*
 * ---- THE ONE BIG SECTION, CUT BACK INTO SEVERAL ---------------------------
 *
 * What comes out of the decompressor is the original image's bytes in one
 * span, and the layout declared before it existed describes them as one
 * section - the packer's. That is wrong in a way a scanner feels: the region partition
 * is what decides which rules run over what, and a single RWX span means the
 * whole image reads as code. Measured on one sample, that span was 5.18 MB of
 * which 3.4 MB is zero.
 *
 * RetDec's plugin cuts it up from four landmarks the steps above already
 * found - the import hints, the IAT, the fix-up stub and the entry point -
 * on the rule that the hints and the stub sit at the END of the original
 * sections and the IAT is a section of its own. Then it walks the code piece
 * at section alignment and splits wherever the preceding 64 bytes are all
 * zero. See THIRD-PARTY.md.
 *
 * Here the child is a flat image, so this moves no bytes: it rewrites the
 * section table and nothing else.
 */
#define MP_SPLIT_MAX 12u

static int mp_zero_run(const struct kof_obj_ctx *ctx, uint64_t at, uint32_t n)
{
	uint8_t b[64];
	uint32_t got, k;

	while (n) {
		uint32_t want = n > sizeof b ? (uint32_t)sizeof b : n;

		got = kunp_rcstruct_read(at, b, want);
		if (got != want)
			return 0;
		for (k = 0; k < got; k++)
			if (b[k])
				return 0;
		at += got;
		n -= got;
	}
	return 1;
}

static void mp_split(const struct kof_obj_ctx *ctx,
		     const struct kof_pe_info *pe, uint32_t found,
		     uint32_t fix, uint32_t hints, uint32_t oep,
		     uint32_t iat_lo, uint32_t iat_hi)
{
	struct { uint32_t rva, len, code; char nm[8]; } sec[MP_SPLIT_MAX];
	uint32_t cut[5], n_cut = 0, n = 0, i, j;
	uint32_t base = (uint32_t)pe->sec[found].mem_rva;
	uint32_t span = (uint32_t)pe->sec[found].mem_size;
	uint32_t oep_off = oep > base ? oep - base : 0u;
	uint32_t imp_base = (uint32_t)pei_image_end(pe);
	uint32_t data_n = 0;

	/* oep_off of zero is an entry at the very start of the section, which
	 * two samples here have; only an entry OUTSIDE the section is a reason
	 * not to do this. */
	if (!span || oep < base || oep_off >= span)
		return;

	/*
	 * The landmarks, each rounded UP to a page: a split has to fall on a
	 * boundary the loader could have used.
	 *
	 * THE ENTRY POINT IS NOT ONE OF THEM. It decides which side of a split
	 * the code is on - and so which piece gets the code characteristics -
	 * but it is not itself a boundary: a program's entry is somewhere in
	 * its text, not at the start of it. Cutting there put the start of
	 * .text 0x33000 later than Avast's own output of the same file, which
	 * is what caught it.
	 */
	cut[n_cut++] = (hints + PEI_PAGE - 1u) & ~(PEI_PAGE - 1u);
	cut[n_cut++] = (fix + PEI_PAGE - 1u) & ~(PEI_PAGE - 1u);
	if (iat_hi > base)
		cut[n_cut++] = ((iat_hi - base) + PEI_PAGE - 1u) &
			       ~(PEI_PAGE - 1u);
	if (iat_lo > base)
		cut[n_cut++] = (iat_lo - base) & ~(PEI_PAGE - 1u);

	/* Sorted, deduplicated, and inside the span. */
	for (i = 0; i < n_cut; i++)
		for (j = i + 1u; j < n_cut; j++)
			if (cut[j] < cut[i]) {
				uint32_t t = cut[i]; cut[i] = cut[j]; cut[j] = t;
			}

	for (i = 0; i < n_cut && n + 2u < MP_SPLIT_MAX; i++) {
		uint32_t at = cut[i];
		uint32_t prev = n ? sec[n - 1u].rva + sec[n - 1u].len : base;

		if (!at || at >= span || base + at <= prev)
			continue;
		sec[n].rva = prev;
		sec[n].len = base + at - prev;
		sec[n].code = 0;
		n++;
	}
	if (n >= MP_SPLIT_MAX - 1u)
		return;
	{
		uint32_t prev = n ? sec[n - 1u].rva + sec[n - 1u].len : base;

		if (base + span <= prev)
			return;
		sec[n].rva = prev;
		sec[n].len = base + span - prev;
		sec[n].code = 0;
		n++;
	}
	if (n < 2u)
		return;                 /* nothing to say that the header did not */

	/* The piece the entry point is in is the code. */
	for (i = 0; i < n; i++)
		if (base + oep_off >= sec[i].rva &&
		    base + oep_off < sec[i].rva + sec[i].len)
			sec[i].code = 1;

	/*
	 * AND THE ZERO TAIL OUT OF IT. A code section whose last megabytes are
	 * zero is not code there, and leaving them in is what makes the whole
	 * image read as one span. Trimmed a page at a time from the end.
	 */
	for (i = 0; i < n; i++) {
		uint32_t keep;

		if (!sec[i].code || sec[i].len <= PEI_PAGE || n >= MP_SPLIT_MAX)
			continue;
		keep = sec[i].len;
		while (keep > PEI_PAGE &&
		       mp_zero_run(ctx, sec[i].rva + keep - PEI_PAGE, PEI_PAGE))
			keep -= PEI_PAGE;
		if (keep == sec[i].len)
			continue;
		for (j = n; j > i + 1u; j--)
			sec[j] = sec[j - 1u];
		sec[i + 1u].rva = sec[i].rva + keep;
		sec[i + 1u].len = sec[i].len - keep;
		sec[i + 1u].code = 0;
		sec[i].len = keep;
		n++;
		break;
	}

	/* Names, once the pieces are settled. */
	for (i = 0; i < n; i++) {
		unsigned k;

		for (k = 0; k < 8u; k++)
			sec[i].nm[k] = 0;
		if (sec[i].code) {
			sec[i].nm[0] = '.'; sec[i].nm[1] = 't';
			sec[i].nm[2] = 'e'; sec[i].nm[3] = 'x';
			sec[i].nm[4] = 't';
		} else {
			sec[i].nm[0] = '.'; sec[i].nm[1] = 'd';
			sec[i].nm[2] = 'a'; sec[i].nm[3] = 't';
			sec[i].nm[4] = 'a';
			sec[i].nm[5] = (char)('0' + (data_n++ % 10u));
		}
	}

	/*
	 * THE WHOLE LAYOUT SAID AGAIN, in address order: the pieces in place of
	 * the packed section, every other section as it was, and the import
	 * directory this module stood up.
	 *
	 * Said rather than written. This block used to assemble forty bytes per
	 * section and poke them into a header the module had built itself -
	 * one of thirteen such pokes, and the one that had to get
	 * NumberOfSections right by hand as well. What it is now is the
	 * statement that was always behind it.
	 *
	 * RESET FIRST, because the pieces do not line up with what was declared
	 * before the content existed: they sit between the old boundaries, and
	 * correcting entries one at a time cannot express that.
	 */
	if (!kunp_rcstruct_reset())
		return;
	for (i = 0; i < pe->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *t = &pe->sec[i];
		uint32_t q;

		if (i == found) {
			for (q = 0; q < n; q++) {
				char nm[9];
				unsigned c;

				for (c = 0; c < 8u; c++)
					nm[c] = sec[q].nm[c];
				nm[8] = 0;
				if (kunp_rcstruct_section(nm, sec[q].rva, sec[q].len,
						    sec[q].code
						    ? (KOF_PE_PERM_R |
						       KOF_PE_PERM_X)
						    : (KOF_PE_PERM_R |
						       KOF_PE_PERM_W),
						    (sec[q].code
						     ? KOF_SECF_CODE
						     : KOF_SECF_DATA) |
						    KOF_SECF_REBUILT) < 0)
					return;
			}
			continue;
		}
		/*
		 * AND THE TAIL OF EACH OTHER SECTION, WHICH IS PADDING AND IS
		 * SAID TO BE.
		 *
		 * A section occupies its span because the next one starts at
		 * its own address, but it CONTAINS only its VirtualSize. The
		 * difference was inside the section and the partition handed it
		 * to DATA - measured on update_v103.exe, a DATA region of 3972
		 * bytes with not one non-zero byte in it.
		 */
		if (kunp_rcstruct_section(t->name, t->mem_rva, t->mem_size, t->perm,
				    ((t->perm & KOF_PE_PERM_X) ? KOF_SECF_CODE
							       : KOF_SECF_DATA) |
				    KOF_SECF_READ) < 0)
			return;
		if (pei_span(t) > t->mem_size &&
		    kunp_rcstruct_section("", t->mem_rva + t->mem_size,
				    pei_span(t) - t->mem_size, t->perm,
				    KOF_SECF_PAD | KOF_SECF_READ) < 0)
			return;
	}
	/*
	 * And the import directory. SYNTHETIC because it is not a recovery of
	 * anything that was in the file: MPRESS keeps a hint list, not a table,
	 * and what goes here is one this module built to match it. A reader has
	 * to be able to tell that from an import table that was read.
	 */
	kunp_rcstruct_section(".kofimp", imp_base, PEI_PAGE,
			KOF_PE_PERM_R, KOF_SECF_DATA | KOF_SECF_SYNTHETIC);
}

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_pe_info *pe = kof_pe(ctx);
	uint64_t stream, u_len, got, s2;
	uint32_t c_len, i, found;
	unsigned lc, lp, pb;
	const struct mp_build *build;

	if (!pe->valid || pe->sec_count < 2u ||
	    pe->entry_sec >= pe->sec_count)
		return;
	found = pe->sec_count;
	build = mp_build_of(ctx, pe);

	for (i = 0; i < pe->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *s = &pe->sec[i];

		if (i == pe->entry_sec)
			continue;               /* that one holds the stub */
		if (s->mem_size < MP_MIN_MEM || !s->file_off)
			continue;
		if (!kof_in_obj(s->file_off, MP_HDR))
			continue;
		/*
		 * The agreement. Both sides are read as written - the header's
		 * word from the file and VirtualSize from the section table -
		 * and a mismatch ends this section here, before anything else
		 * is read.
		 */
		if (((uint64_t)kof_u16(s->file_off) << MP_UNIT) != s->mem_size)
			continue;
		/*
		 * And the compressed stream has to fit in the bytes the section
		 * actually owns. c_len counts from the property bytes, so the
		 * six header bytes ahead of them are added back.
		 */
		c_len = kof_u32(s->file_off + 2);
		if (c_len <= 2u || (uint64_t)c_len + 6u > s->file_size)
			continue;
		found = i;
		break;
	}
	if (found >= pe->sec_count)
		return;                         /* not this packer */

	stream = pe->sec[found].file_off;
	u_len  = pe->sec[found].mem_size;
	c_len  = kof_u32(stream + 2);
	pb     = kof_u8(stream + 6) >> 4;
	lp     = kof_u8(stream + 6) & 0xfu;
	lc     = kof_u8(stream + 7);

	/*
	 * What was recognised, before anything is decided about it - the three
	 * numbers that decide whether a sample is one this module handles, so
	 * they are reported whatever happens next.
	 */
	kof_debug("MPRESS.PE.lc", lc);
	kof_debug("MPRESS.PE.lp", lp);
	kof_debug("MPRESS.PE.pb", pb);

	/*
	 * THE PROPERTY BYTES ARE LZMA'S AND AN LZMAT STREAM HAS NONE.
	 *
	 * The two codings share the six byte header and differ from there:
	 * LZMA writes lc, lp and pb after it, LZMAT writes its first byte.
	 * Reading one as the other is what made every LZMAT file here look
	 * like a version this build lacked - measured, two of the seven, whose
	 * "properties" read as pb=6 lp=10 because they are compressed data.
	 * The build says which coding it is, so it decides, not the bytes.
	 */
	if (build && build->lzmat) {
		lc = 0u; lp = 0u; pb = 0u;
	} else if (lc > KOF_LZMA_MAX_LC || lp > KOF_LZMA_MAX_LP ||
	    pb > KOF_LZMA_MAX_PB) {
		/*
		 * The agreement held and the parameters did not, which is the
		 * earlier MPRESS described at the top: the same size header
		 * over a coding this engine does not have. UNSUPPORTED and not
		 * DAMAGED - the file is intact and it is this build that falls
		 * short, and kofsig.h reserves each word for exactly that.
		 */
		KUNP_RCSTRUCT_BROKEN(KOF_UNP_UNSUPPORTED);
	}

	/*
	 * u_len sizes the buffer and bounds nothing: it is a number out of the
	 * file, so the host clamps it to what the memory ceiling allows and the
	 * comparison at the end is what notices a stream that did not hold what
	 * the section said it held.
	 */
	/*
	 * THE CALL FILTER IS PART OF THE CODING, not an extra this module
	 * could leave off.
	 *
	 * MPRESS rewrites the displacement of every E8 and E9 - and on 64 bit
	 * also every FF15/FF17 and 8D05 - from relative to absolute before
	 * compressing, and its stub converts them back before jumping. Bytes
	 * handed over without that step are the right length and the wrong
	 * program: measured on the PE32+ sample, 8649 displacements differ, so
	 * a hex pattern written over any code containing a call does not match
	 * what a scan would see.
	 *
	 * Asked for through the method id because the transform needs the
	 * whole decoded output and a module has no buffer to hold it - the
	 * host does the decode, so the host does the undo, exactly as it
	 * already does for KOF_UNP_LZMA2_BCJ_X86.
	 *
	 * THE WIDTH COMES FROM THE FILE, and it has to: the two stubs convert
	 * different opcodes, and the wide rule applied to a 32 bit image
	 * rewrites four bytes after every 0x8D the packer never touched.
	 */
	/*
	 * THE HEADER FIRST, THEN THE IMAGE. The child is built in order - see
	 * kofsig.h on kunp_static_decode, which says plainly that a module may
	 * "put more after the decompressed bytes", so it may equally put
	 * something before them.
	 *
	 * Without it the child identifies as nothing: measured, kofexaminer
	 * reported "format unrecognised, 8183808 bytes" on 8 MB of real
	 * x86-64 code, which means no region partition, no PE-scoped rule, and
	 * no emulator - kof_scan_emu_unpack returns at its first line for an
	 * object whose format is not PE.
	 */
	s2 = mp_stage2_rva(ctx, &pe->sec[pe->entry_sec], pe->entry_rva);
	/*
	 * ---- THE LAYOUT, THEN THE IMAGE --------------------------------------
	 *
	 * Addresses and extents only, and one page reserved past the end for an
	 * import directory this module may or may not build. What each section
	 * IS is not said here: nothing has been decompressed yet, so any answer
	 * would describe the packed file rather than the child. mp_split says
	 * it further down, once the landmarks it needs exist.
	 */
	for (i = 0; i < pe->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *t = &pe->sec[i];

		/*
		 * THE EXTENT IS WHAT THE SECTION CONTAINS, and the difference
		 * up to the page boundary is declared as padding rather than
		 * left inside it. That difference was being counted as
		 * content: measured on update_v103.exe, a DATA region of 3972
		 * bytes without one non-zero byte in it.
		 */
		if (kunp_rcstruct_section(t->name, t->mem_rva, t->mem_size, t->perm,
				    KOF_SECF_DATA | KOF_SECF_READ) < 0)
			kunp_rcstruct_broken(KOF_UNP_LIMIT);
		/*
		 * AND NOT AFTER THE LAST ONE.
		 *
		 * Padding between sections is padding; padding past the final
		 * section is past the last byte anything claims, and that is
		 * what the partition calls an OVERLAY - a statement that this
		 * file carries something appended to it, which is false about
		 * its own alignment fill. Measured on update_v103.exe: 3972
		 * bytes that moved out of DATA and straight into OVERLAY.
		 *
		 * The module knows which is last because it declares them all,
		 * and `build` says whether `.kofimp` will follow.
		 */
		if (pei_span(t) > t->mem_size &&
		    (build || i + 1u < pe->sec_count) &&
		    kunp_rcstruct_section("", t->mem_rva + t->mem_size,
				    pei_span(t) - t->mem_size, t->perm,
				    KOF_SECF_PAD | KOF_SECF_READ) < 0)
			kunp_rcstruct_broken(KOF_UNP_LIMIT);
	}
	/*
	 * A PAGE PAST THE END, RESERVED ONLY WHERE IT COULD BE USED.
	 *
	 * The engine sizes the image from this table, and whether an import
	 * directory can be rebuilt is not knowable until the content exists -
	 * so the room has to be taken now or not at all. It is taken only when
	 * the build is one this module knows how to find a fix-up stub in,
	 * because without that there will be no imports and the page would
	 * simply sit past the last claimed byte, reading as an overlay on a
	 * file that has none.
	 */
	if (build &&
	    kunp_rcstruct_section("", pei_image_end(pe), PEI_PAGE, KOF_PE_PERM_R,
			    KOF_SECF_PAD | KOF_SECF_READ) < 0)
		kunp_rcstruct_broken(KOF_UNP_LIMIT);
	if (!kunp_rcstruct_image())
		kunp_rcstruct_broken(KOF_UNP_LIMIT);
	/*
	 * The second stage's entry, which is all that is knowable here. The
	 * program's own is read out of the fix-up stub once the content exists
	 * and replaces this - see mp_oep_of below. A child with no entry at all
	 * is a PE nothing will run or disassemble from.
	 */
	kunp_rcstruct_entry(s2);

	/*
	 * THE SECTIONS IN VIRTUAL ADDRESS ORDER, which is the order the header
	 * above laid them out in and therefore the order they have to arrive.
	 *
	 * The parser sorts sec[] by offset and MPRESS writes them in the same
	 * order as their addresses, so walking the table is walking the image.
	 * A file where those two orders disagree would produce a child whose
	 * bytes are not where its own header says - so the walk checks, and
	 * stops rather than writing something that describes itself wrongly.
	 */
	/*
	 * AND WHAT HAS TO BE DONE TO IT, SAID BEFORE IT EXISTS.
	 *
	 * What comes out is the image, not the program: its code is ordinary -
	 * measured, 4,462 `sub rsp, imm8` and 2.82% REX.W prefixes in 8 MB -
	 * and the payload is three encrypted blocks the program decrypts with
	 * its own code at run time. Nothing static opens those: they have no
	 * container, no declared length and no coding this engine could name.
	 *
	 * The emulator's entropy gate will refuse this child, and correctly:
	 * the executable section averages 4.6 bits per byte, because 1.2 MB of
	 * ciphertext inside 8 MB of real code disappears into the mean. So the
	 * module says it, here, where it is known - see child_want in kofsig.h
	 * on why a declaration beats anything a later look at the bytes can
	 * infer.
	 *
	 * LEVEL 2, because running an object is what --heur 2 is for. A caller
	 * who asked for less gets the unpacked image and no interpreter, which
	 * is the trade that level exists to express.
	 */
	/*
	 * AND ONLY FOR THE BUILD THIS MODULE HAS BEEN MEASURED AGAINST.
	 *
	 * s2 is non-zero when the stub carried the patched jump this module
	 * knows how to read - `mov al,0xe9; stos; mov eax,imm32; stos` and the
	 * `jmp rel32` it writes. That shape is what identifies the generation:
	 * MPRESS has no version string anywhere in the file, so the structure
	 * is the only thing that says which one this is.
	 *
	 * WHY GATE IT AT ALL. Asking for the interpreter is not free any more:
	 * a child a module declares gets the longer stall ceiling, and this one
	 * then runs its program to ExitProcess - 107404062 instructions, twelve
	 * seconds. That is worth paying where it produces something, and
	 * measured it does: two command line strings that are in neither the
	 * packed file nor this module's own output. It is not worth paying for
	 * a build whose stub this module did not recognise, where the run has
	 * no reason to go anywhere.
	 */
	/*
	 * AND THE INTERPRETER IS NOT ASKED FOR, WHICH IS A CHANGE.
	 *
	 * This module used to declare KOF_ENG_USE_EMU on its child, on the
	 * argument that what came out was the image and not the program - the
	 * payload being blocks the program decrypts with its own code at run
	 * time. That was true when all this module produced was a decompressed
	 * span. It is not what it produces now: the entry point the program
	 * actually has, an import directory rebuilt from the packer's own
	 * hints, and the span cut back into the sections it came from.
	 *
	 * Measured after that, on the two samples where it mattered most:
	 *
	 *   111.exe          heur1  2 obj  8.17 MB   144 ms
	 *                    heur2  2 obj  8.17 MB   169 ms  (22 instructions)
	 *   update_v103.exe  heur1  3 obj 18.35 MB   174 ms
	 *                    heur2  4 obj 10.52 MB 10431 ms  (107404062)
	 *
	 * The first runs twenty-two instructions and faults, because what is
	 * under MPRESS there is VMProtect and an interpreter does not get
	 * through it. The second spends ten seconds to reach ExitProcess and
	 * what it brings back that the static unpack does not is two command
	 * line strings. Ten seconds of a scan for two strings is not a trade
	 * this can defend, so it is not made.
	 */

	/*
	 * ---- THE CONTENT, WRITTEN WHERE IT BELONGS ---------------------------
	 *
	 * Addresses, not a stream. The walk that was here laid the image out by
	 * padding to each section in turn, which meant it had to get every gap
	 * and every alignment tail right by hand - and the LAST tail was a
	 * special case in its own right, deferred so that a section nothing
	 * followed would not carry 3972 bytes of zero into DATA. The engine
	 * owns the layout now: the image is already the right size and zero
	 * filled, so a gap is simply somewhere nothing is written.
	 */
	got = 0;
	for (i = 0; i < pe->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *t = &pe->sec[i];
		uint64_t span = pei_span(t), wrote;

		if (!kunp_rcstruct_at(t->mem_rva))
			kunp_rcstruct_broken(KOF_UNP_LIMIT);
		if (i == found) {
			/* LZMAT starts right after the six byte header; LZMA
			 * starts two property bytes further on. */
			wrote = (build && build->lzmat)
			      ? kunp_static_decode(
				    pe->pe32_plus ? KOF_UNP_LZMAT_MPRESS64
						  : KOF_UNP_LZMAT_MPRESS32,
				    stream + 6u, c_len, u_len, KOF_FORM_RAW)
			      : kunp_static_decode(
				    KOF_UNP_LZMA_MPRESS_PROPS(
					lc, lp, pb, pe->pe32_plus ? 64u : 32u),
				    stream + MP_HDR, c_len - 2u, u_len,
				    KOF_FORM_RAW);
			got = wrote;
			if (!wrote)
				KUNP_RCSTRUCT_BROKEN(KOF_UNP_DAMAGED);
		} else {
			wrote = t->file_size;
			if (wrote > span)
				wrote = span;
			if (wrote && !pei_copy(ctx, t->file_off, wrote))
				kunp_rcstruct_broken(KOF_UNP_LIMIT);
		}
	}
	if (got == 0)
		KUNP_RCSTRUCT_BROKEN(KOF_UNP_DAMAGED);
	if (got == 0)
		KUNP_RCSTRUCT_BROKEN(KOF_UNP_DAMAGED);

	/*
	 * AND NOW THE ENTRY POINT THE PROGRAM ACTUALLY HAS.
	 *
	 * The SECOND STAGE's entry was declared before the content existed,
	 * because that is all mp_stage2_rva can read out of the stub. The
	 * program's own entry is inside the content and only now can it be
	 * read - see mp_oep_of - so it is declared again, and the second word
	 * stands.
	 *
	 * The correction is made only when every step held. A child whose entry
	 * is the second stage is still a correct description of itself; one
	 * pointing at an address invented from an offset that did not check out
	 * is not.
	 */
	{
		uint32_t oep = mp_oep_of(ctx, pe, build, found);

		/*
		 * SAID, NOT POKED. This wrote the four bytes at 0xa8 of a
		 * header the module had built itself - and wrote them at 0x98
		 * first, which is Magic, so every child read back as a PE with
		 * magic 0xfb2b. There is no offset to get wrong any more.
		 */
		if (oep && oep < pei_image_end(pe))
			kunp_rcstruct_entry(oep);
	}


	/*
	 * The handover is checked, like every container in this directory
	 * checks it: refused by the host and not reported, the module would be
	 * saying it unpacked the object while having produced nothing.
	 */
	/*
	 * AND WHERE THE PROGRAM WILL BE, SO THE RUN STOPS WHEN IT ARRIVES.
	 *
	 * MPRESS HAS EXACTLY TWO STAGES, and that is what makes this sayable.
	 * The first is the stub in the entry section; it decompresses and jumps
	 * into the section this module just rebuilt, where the second stage
	 * rebuilds the import table. When THAT finishes it jumps to the
	 * original entry point - and MPRESS appends its second stage after the
	 * program, so the original entry is at a LOWER address in the same
	 * section.
	 *
	 * So the run is over the moment execution goes below s2 inside that
	 * section, or into any other section. Said as ranges the program will
	 * be in, which is what the host's watch takes.
	 *
	 * THE TWO-STAGE COUNT IS UNIPACKER'S OBSERVATION, not this module's -
	 * its MPRESS unpacker allows .MPRESS2, lets execution leave it ONCE
	 * while narrowing the allowed range to [arrival, end of that section],
	 * and treats the second departure as the dump point. See THIRD-PARTY.md.
	 *
	 * Without this the run has no end to reach: measured on update_v103.exe
	 * it ran 4261616 instructions and stopped only because it had written
	 * no new page for four million of them, and with every bound lifted it
	 * ran 5662007 and died calling an import it could not resolve. Neither
	 * is the stub finishing.
	 */
	if (s2)
		for (i = 0; i < pe->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
			const struct kof_pe_sec *t = &pe->sec[i];

			if (!t->mem_size)
				continue;
			if (s2 >= t->mem_rva && s2 < t->mem_rva + t->mem_size) {
				/* The part of the second stage's own section
				 * that is below it - the program. */
				if (s2 > t->mem_rva)
					kunp_emu_oep_range(t->mem_rva,
						      s2 - t->mem_rva);
				continue;
			}
			if (i == pe->entry_sec)
				continue;       /* the first stage's own */
			kunp_emu_oep_range(t->mem_rva, t->mem_size);
		}

	/*
	 * AND THE IMPORT DIRECTORY, APPENDED AND THEN POINTED AT.
	 *
	 * See mp_imports. The section goes after the image because there is
	 * nowhere inside it that is free, and the header - written before any
	 * of this was knowable - is corrected once the bytes exist.
	 */
	{
		uint32_t fix = 0, row = 0;

		if (build && mp_fixup(ctx, pe, build, found, &fix, &row)) {
			uint8_t raw[4];
			uint64_t sect = pe->sec[found].mem_rva;
			uint32_t hp, need, iat_lo, iat_hi;

			if (kunp_rcstruct_read(sect + fix + mp_fixes[row].hints,
					 raw, 4u) == 4u) {
				hp = fix + mp_fixes[row].hints +
				     ((uint32_t)raw[0] |
				      ((uint32_t)raw[1] << 8) |
				      ((uint32_t)raw[2] << 16) |
				      ((uint32_t)raw[3] << 24));
				iat_lo = 0; iat_hi = 0;
				need = mp_imports(ctx, pe, found, hp,
						  (uint32_t)pei_image_end(pe),
						  0, MP_IMP_CAP,
						  &iat_lo, &iat_hi);
				if (need)
					mp_emit_imports(ctx, pe, found, hp,
							need);
				/*
				 * AND THE ONE BIG SECTION CUT BACK INTO
				 * SEVERAL. See mp_split. Done last, because
				 * every landmark it uses - the hints, the IAT,
				 * the fix stub, the entry point - is something
				 * the steps above worked out.
				 */
				if (need)
					mp_split(ctx, pe, found, fix, hp,
						 mp_oep_of(ctx, pe, build,
							   found),
						 iat_lo, iat_hi);
			}
		}
	}

	if (!kunp_rcstruct_done())
		kunp_rcstruct_broken(KOF_UNP_LIMIT);

	if (got < u_len)
		kunp_rcstruct_broken(KOF_UNP_DAMAGED);
}
