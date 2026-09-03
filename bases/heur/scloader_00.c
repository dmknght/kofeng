/*
 * scloader_00.c - an ELF with almost no code, carrying a payload in a global.
 *
 * THE SHAPE. A shellcode loader built from the usual template is a few hundred
 * bytes of code and one global array holding the payload: `unsigned char
 * shellcode[] = {...}`, or `code[]`, or whatever it was called that day. The
 * code decrypts or copies the array and jumps into it. What identifies the
 * family is therefore not the code and not the array's NAME - which is the
 * mistake the static signature makes, and why it dies on a rename - but the
 * pairing: a file too small to do anything else, carrying a blob too varied to
 * be data.
 *
 *
 * HOW IT LOOKS FOR THE BLOB, and why it is cheap
 *
 * Through the symbol records the engine builds (kofmod/kofsym.h). Every record
 * is KOF_SYM_RECLEN bytes at a constant offset from KOF_SYM_HDRLEN, so the rule
 * STEPS rather than searches: four byte-compares at the front of each record
 * decide it, and the expensive test runs only on what survives.
 *
 * Measured over 294,721 records in 170 files: 4 bytes per record against 64 is
 * a 16x reduction in bytes read, and 5.03% of records survive the four. The
 * blob test - which reads the payload itself - therefore runs on one record in
 * twenty rather than on all of them.
 *
 * The four bytes are the same on every sample measured: 01 01 00 15.
 *
 *     type  01  STT_OBJECT     it is data, not a function
 *     bind  01  STB_GLOBAL     it is exported, not a static
 *     vis   00  STV_DEFAULT
 *     flags 15  DEFINED | IN_WRITABLE | HAS_SIZE
 *
 *
 * WHAT WAS MEASURED
 *
 *  10 of 253   ELF objects in MalwareLab/LinuxMalwareDetected - the loader
 *              family, and nothing else in that set.
 *   0 of 35598 objects under /usr, scanned IN FULL rather than sampled. An
 *              earlier measurement said 0 of 2098 and was a sample of that
 *              tree; the full walk found one it had missed - see the note on
 *              PT_INTERP below - which is why this number is a whole tree now
 *              and not a selection from one.
 *   0 of 4     purpose-built small programs with global arrays - `char
 *              buffer[512]`, `unsigned char table[256] = {1,2,3}`, `char
 *              key[128]` - which is the false positive this rule most invites
 *              and the one an earlier draft actually had.
 *
 * IT DOES NOT READ THE NAME. `code`, `shellcode` and `random` all fire, which
 * is the whole improvement over matching the identifier.
 *
 *
 * THE TWO TERMS THAT DO THE WORK, and one that was removed
 *
 * A high-entropy writable global on its own is a LOOKUP TABLE, not a payload:
 * crypto/aes.te0, runtime.fastlog2Table, GostR3411_94_*, and in clean code
 * BZ2_crc32Table and libmpfr's __bid_* decimal tables. Those were the only two
 * clean files that fired before the code bound went in. So it is the PAIRING
 * that identifies the family - a blob like that in a file with 425 to 489 bytes
 * of code, where the nearest clean file that carries one has 58,875.
 *
 * A term excluding files that import mprotect/mmap/memfd_create was tried and
 * REMOVED: it cost six true positives and removed no false positives. The
 * reasoning behind it - that a loader allocating RWX at runtime is a different
 * shape - was not what the data said.
 *
 *
 * THE LIMIT, stated because it is the one a reader should know
 *
 * The code bound assumes the loader is small. A larger one evades this rule.
 * That is the template-specific half, and it is why the rule is a heuristic
 * that asks for a closer look rather than a verdict.
 */

#include <kofmod/heur.h>
#include <kofmod/elf.h>
#include <kofmod/kofsym.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF);

/* EXAMINE: everything read here is a field of the parse or of the symbol block
 * the engine builds from it, and both are finished by then. */
KOF_HEUR_PHASE(KOF_HEUR_EXAMINE);
KOF_HEUR_NAME("SCLoader");

/*
 * No KOF_HEUR_PREDICT. The shape says a payload is carried; it does not say
 * whose, and the samples measured carry several different ones. A guess here
 * would be reported as a family - Heur:<guess>#v?SCLoader - on the strength of
 * nothing, and the question mark is meant to be honest about what is not known.
 */

/* ELF's own numbering, spelled out because the parse keeps sh_type and
 * sh_flags raw. */
#define SHT_PROGBITS_   1u
#define SHF_EXECINSTR_  0x4u
#define PT_INTERP_      3u

/*
 * The file has to be too small to be anything but a loader.
 *
 * Executable PROGBITS only: .text and its friends, not .bss, not the section
 * table, not the strings. That is what makes 2048 a bound on CODE rather than
 * on file size - these files are 8-18KB, mostly headers and padding, and a
 * bound on the whole file would be measuring the linker's habits.
 */
#define SCL_CODE_MAX    2048u

/*
 * How varied the blob has to be, as a count of DISTINCT BYTE VALUES.
 *
 * Shannon entropy is the natural measure and was what this was developed with -
 * the payloads run 4.90 to 7.55 bits and the nearest false positive is 0.11 -
 * but it needs a logarithm, and a rule that pulls in libm to make one decision
 * is a cost paid on every object for the sake of one. Distinct values separate
 * the same two populations with the same margin and are a 256-bit set: the
 * payloads have 41 to 228 distinct values, `table[256] = {1,2,3}` has 4.
 *
 * Both were run over the full corpus and agree exactly - 10, 0 and 0.
 *
 * The count stops at the threshold. There is nothing to learn from the
 * difference between 32 and 228, and stopping turns the worst case on a large
 * blob into a short loop.
 */
#define SCL_DISTINCT    32u

#define SCL_SIZE_MIN    64u
#define SCL_SIZE_MAX    8192u

KOF_DEFINE_HEUR
{
	const struct kof_elf_info *e = kof_elf(ctx);
	const uint8_t *b, *r;
	uint32_t n = 0, i, code = 0;

	if (!e || !e->valid)
		return;

	/*
	 * IT HAS TO BE A PROGRAM, not a library.
	 *
	 * PT_INTERP is the kernel being told which dynamic loader to run this
	 * with, so only something meant to be EXECUTED carries one - a shared
	 * object has none. That difference is the whole of this test, and it
	 * is what separates a loader from the one clean file that otherwise
	 * matches everything below: frei0r's dither.so, a video plugin with
	 * 1831 bytes of code carrying ditherOrdered8x8Matrix and nine more
	 * dither matrices in .data. Those are lookup tables in a library, which
	 * is the same shape as a payload in a program and a different thing.
	 *
	 * Found by scanning /usr/lib in full rather than the sample an earlier
	 * measurement used - which is why it is here and not in the first draft.
	 */
	{
		uint32_t k;
		int interp = 0;

		for (k = 0; k < e->seg_count && k < KOF_ELF_MAX_SEGMENTS; k++)
			if (e->seg[k].type == PT_INTERP_)
				interp = 1;
		if (!interp)
			return;
	}

	/*
	 * The code bound first: it is arithmetic over a table already parsed,
	 * it rejects almost every object, and it costs nothing. Building the
	 * symbol block for a file this rule cannot fire on would be the one
	 * expensive thing here.
	 */
	for (i = 0; i < e->sec_count && i < KOF_ELF_MAX_SECTIONS; i++)
		if (e->sec[i].type == SHT_PROGBITS_ &&
		    (e->sec[i].flags & SHF_EXECINSTR_))
			code += (uint32_t)e->sec[i].file_size;
	if (!code || code > SCL_CODE_MAX)
		return;

	b = kof_syms(&n);
	if (!b)
		return;                 /* stripped, or nothing to walk */

	/*
	 * BEGIN AFTER `_start`, which the engine recorded while it built the
	 * block - see KOF_SYM_H_START.
	 *
	 * `_start` comes from crt1.o and the link puts crt1.o before the object
	 * a person wrote, so a program's own globals are emitted after it. On
	 * the loaders measured that turns 63 to 66 records into 6 or 7. The
	 * index is free to use because the builder noticed it on the way past;
	 * a rule finding it for itself would have to walk the names, which is
	 * the search this avoids.
	 *
	 * kof_sym_first answers 0 when there is no `_start` - a stripped table,
	 * a shared object, anything not linked the usual way - so the loop
	 * degrades to the whole block rather than to nothing.
	 *
	 * THE TRADE, stated because it is a real one: a payload emitted BEFORE
	 * `_start` is not seen. Order among global symbols is the linker's, not
	 * the format's, so a static link, -nostartfiles or a different linker
	 * could produce that. It holds on all ten samples measured and on the
	 * toolchain this template is built with, and it is the reason this is a
	 * heuristic rather than a verdict.
	 */
	for (i = kof_sym_first(b, n); (r = kof_sym_rec(b, n, i)) != 0; i++) {
		uint64_t sz, val, fo;
		uint32_t shndx, k, distinct = 0;
		uint32_t seen[8];

		/* The four bytes, and nothing else is read unless they pass. */
		if (r[KOF_SYM_R_TYPE]  != 1u   || r[KOF_SYM_R_BIND] != 1u ||
		    r[KOF_SYM_R_VIS]   != 0u   || r[KOF_SYM_R_FLAGS] != 0x15u)
			continue;

		sz = kof_sym_u64(r, KOF_SYM_R_SIZE);
		if (sz < SCL_SIZE_MIN || sz > SCL_SIZE_MAX)
			continue;

		shndx = (uint32_t)r[KOF_SYM_R_SHNDX] |
			((uint32_t)r[KOF_SYM_R_SHNDX + 1] << 8);
		if (shndx >= e->sec_count || shndx >= KOF_ELF_MAX_SECTIONS)
			continue;
		/*
		 * PROGBITS, so the blob HAS bytes in the file. This is not a
		 * detail: `char buffer[512]` is a GLOBAL OBJECT in a writable
		 * section too, and it lands in .bss with nothing behind it.
		 * Nothing that has no content can be a payload.
		 */
		if (e->sec[shndx].type != SHT_PROGBITS_)
			continue;

		val = kof_sym_u64(r, KOF_SYM_R_VALUE);
		if (val < e->sec[shndx].mem_addr)
			continue;
		fo = e->sec[shndx].file_off +
		     (val - e->sec[shndx].mem_addr);
		/* The record's own numbers, so they are checked rather than
		 * trusted: a size that runs past the object is a broken symbol,
		 * not a large payload. */
		if (fo >= ctx->obj_size || sz > ctx->obj_size - fo)
			continue;

		for (k = 0; k < 8u; k++)
			seen[k] = 0;
		for (k = 0; k < (uint32_t)sz; k++) {
			uint8_t c = kof_u8(fo + k);

			if (seen[c >> 5] & (1u << (c & 31u)))
				continue;
			seen[c >> 5] |= 1u << (c & 31u);
			if (++distinct >= SCL_DISTINCT)
				break;
		}
		if (distinct >= SCL_DISTINCT)
			KOF_HEUR_HIT();
	}
}
