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
 * A loader whose payload is small next to its code is not seen - the ratio is
 * the shape being looked for, so a file that does not have it is not this
 * shape. That is the template-specific half, and it is why the rule is a
 * heuristic that asks for a closer look rather than a verdict.
 *
 * The code ceiling is 8192 rather than the 2048 this rule started with, so a
 * loader up to sixteen times the size of the ones measured still trips it -
 * but there IS a ceiling, and a loader above it is not seen. The ratio alone
 * had none, which sounded better and was worse: it let a half-megabyte program
 * through on proportion and reported one of its tables as a payload.
 */

#include <kofmod/heur.h>
#include <kofmod/elf.h>
#include <kofmod/kofsym.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF);

/* EXAMINE: everything read here is a field of the parse or of the symbol block
 * the engine builds from it, and both are finished by then. */
KOF_HEUR_PHASE(KOF_HEUR_EXAMINE);
/*
 * LEVEL 2, so a default scan does not pay for this.
 *
 * Everything above it in this rule is arithmetic over tables the parse has
 * already built, but the walk itself needs the SYMBOL BLOCK, and building that
 * means reading the symbol table and its string table - the one piece of real
 * work here. The gates in front keep it to 1.80% of objects, which is cheap
 * but not free, and it buys evidence that is a heuristic rather than a verdict.
 * A caller who wants that asks for it with --heur 2.
 */
KOF_HEUR_LEVEL(2);
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
#define SHF_WRITE_      0x1u
#define PT_INTERP_      3u

/*
 * THE FILE HAS TO BE MOSTLY DATA, AS A RATIO - not under a fixed size.
 *
 * A loader is a few hundred bytes of code carrying a payload, so its writable
 * data is comparable to its code or larger. A program that does something has
 * far more code than data. Both sides are executable and writable PROGBITS
 * only - .text and .data, not .bss, not the section table, not the strings -
 * because those are the two things being compared and a whole-file measure
 * would be measuring the linker's padding habits.
 *
 * A RATIO RATHER THAN A CAP, and the difference matters. This was `code <=
 * 2048`, which worked on every sample and carried a limitation stated in its
 * own comment: a bigger loader walks straight past it. The ratio has no such
 * ceiling - a twenty kilobyte loader carrying an eight kilobyte payload trips
 * it exactly as a four hundred byte one does - and it costs nothing to check,
 * because both numbers are already in the parsed section table.
 *
 * MEASURED, on the same corpus the rest of the rule was:
 *
 *   loaders           data/code 0.41 to 2.40
 *   libbz2            0.06        crypto table in a real library
 *   libmpfr           0.07        decimal tables
 *   frei0r dither.so  1.86        inside the range, excluded by PT_INTERP
 *
 * One fifth is chosen against the 0.41 floor rather than at it - a threshold
 * set at the lowest sample measured is a threshold fitted to the samples.
 *
 * It is also the GATE, and that was the other reason to prefer it. Of the ELF
 * objects under /usr, 34.95% carry PT_INTERP and would have the symbol block
 * built if this rule asked for it unconditionally; with this ratio in front,
 * 3.63% do. The cap it replaces let 2.73% through, so the scale-invariance is
 * bought for almost nothing.
 *
 * Expressed as `data * 5 >= code` because a module has no business doing
 * floating point for a comparison this is.
 */
#define SCL_DATA_NUM    5u

/*
 * AND AN ABSOLUTE CEILING ON THE CODE, because the ratio alone does not bound
 * how big the program is.
 *
 * A ratio is blind to scale, which is its virtue and also a hole: PingPull has
 * 473,137 bytes of code and 100,624 of data, a ratio of 0.21, and it sails
 * through a test that only asks about proportion. It is not a small loader
 * carrying a payload, it is a large program that happens to hold a lot of
 * tables - and one of those tables is what the rule then reported.
 *
 * The two together are what the shape actually is: mostly data, AND not much
 * program. Measured across everything that passes the ratio:
 *
 *   the 12 loaders          code  409 to    489
 *   the nearest thing that is not      24,265   (Reaper CnC)
 *                                     473,137   (PingPull)
 *
 * 8192 sits sixteen times above the loaders and three times below the nearest
 * non-loader. The bound this rule started with was 2048, only four times above
 * them - so this is both safer against a bigger loader AND stricter against a
 * big program, which the ratio is what makes possible.
 *
 * It is also cheaper. Of the ELF objects under /usr that carry PT_INTERP and
 * pass the ratio, this ceiling leaves 1.80% to build a symbol block for -
 * against 3.63% for the ratio alone and 2.73% for the old ceiling alone.
 */
#define SCL_CODE_MAX    8192u

/*
 * NO SINGLE BYTE VALUE MAY BE MORE THAN A QUARTER OF THE BLOB.
 *
 * Shannon entropy is the natural measure - payloads run 4.90 to 7.58 bits -
 * but it needs a logarithm, and a rule that pulls in libm for one decision
 * pays for it on every object. This is the integer stand-in, and it is the
 * SECOND one tried: the first counted DISTINCT byte values, which separated
 * shellcode from `table[256] = {1,2,3}` and nothing else. It was wrong about
 * the case that matters.
 *
 * A POINTER TABLE HAS MANY DISTINCT BYTES AND ALMOST NO ENTROPY. OpenSSL's
 * ssl3_ciphers has 91 distinct values in 2880 bytes and passed a distinct
 * count easily - but three quarters of it is zero, because it is an array of
 * structs full of small integers and null padding. Same for Reaper's
 * knownBots, a table of pointers: 75 distinct values, 62% zero. Both were
 * reported as payloads.
 *
 * Measured, and the two populations do not touch:
 *
 *   payloads          top byte  1.5% to 12.0%
 *   ssl3_ciphers      top byte  75.7%
 *   knownBots         top byte  62.5%
 *   char table[256]   top byte  ~99%
 *
 * A quarter sits between them with room on both sides. Expressed as
 * `top * 4 >= sz` so nothing here divides.
 *
 * This costs a full pass where the distinct count could stop early, but the
 * blob is at most SCL_SIZE_MAX and the pass only happens on a record that has
 * already passed every cheaper test.
 */
#define SCL_TOP_DENOM   4u

#define SCL_SIZE_MIN    64u
#define SCL_SIZE_MAX    8192u

KOF_DEFINE_HEUR
{
	const struct kof_elf_info *e = kof_elf(ctx);
	const uint8_t *b, *r;
	uint32_t n = 0, i, code = 0, data = 0;

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
	 * The shape of the file first: it is arithmetic over a table already
	 * parsed, it rejects 96% of what reaches here, and it costs nothing.
	 * Building the symbol block for a file this rule cannot fire on would
	 * be the one expensive thing it does.
	 */
	for (i = 0; i < e->sec_count && i < KOF_ELF_MAX_SECTIONS; i++) {
		if (e->sec[i].type != SHT_PROGBITS_)
			continue;
		if (e->sec[i].flags & SHF_EXECINSTR_)
			code += (uint32_t)e->sec[i].file_size;
		else if (e->sec[i].flags & SHF_WRITE_)
			data += (uint32_t)e->sec[i].file_size;
	}
	/*
	 * THE RATIO IS THE FIRST ANCHOR, the ceiling second.
	 *
	 * That order is the claim being made: the shape is "mostly data", and
	 * the ceiling is a guard on it rather than the thing being looked for.
	 * Reversed, the rule reads as "small files, of which the mostly-data
	 * ones" - which is what it used to be, and what made the ceiling look
	 * like the point when it is the weaker of the two.
	 *
	 * Both are arithmetic over one pass of a table already parsed, so the
	 * order costs nothing either way; it is the order a reader should
	 * understand them in.
	 */
	if (!code || (uint64_t)data * SCL_DATA_NUM < (uint64_t)code)
		return;
	if (code > SCL_CODE_MAX)
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
		uint32_t shndx, k, top = 0;
		uint32_t freq[256];

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

		for (k = 0; k < 256u; k++)
			freq[k] = 0;
		for (k = 0; k < (uint32_t)sz; k++) {
			uint8_t c = kof_u8(fo + k);

			if (++freq[c] > top)
				top = freq[c];
		}
		/* A byte that owns a quarter of the blob makes it a table, not
		 * a payload. See the note on SCL_TOP_DENOM. */
		if (top * SCL_TOP_DENOM < (uint32_t)sz) {
			/*
			 * WHICH symbol, before saying THAT there is one.
			 *
			 * The finding says a payload was found; this says where,
			 * and a reader looking at the file needs the second to
			 * act on the first. Reported as the symbol's own value
			 * rather than its record index: the index is a position
			 * in the block the engine built, and anything that
			 * re-groups those records - kofviewer splits them into
			 * imports and exports - renumbers them, while the value
			 * is the symbol's own and survives.
			 *
			 * Size goes with it because "a payload at 0x4060" and
			 * "949 bytes at 0x4060" are different amounts of help.
			 *
			 * Before KOF_HEUR_HIT because that macro returns.
			 */
			kof_debug("SCLoader.payload", val);
			kof_debug("SCLoader.length", sz);
			KOF_HEUR_HIT();
		}
	}
}
