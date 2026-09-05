/*
 * scfind.h - where a shellcode loader keeps its payload.
 *
 * SHARED BY TWO MODULES ON PURPOSE, and it is worth saying why rather than
 * leaving it to be discovered.
 *
 * The search below answers one question - does this program carry a blob that
 * looks like a payload, and where is it - and two different modules need that
 * answer for two different reasons. bases/heur/scloader_00.c scores the file:
 * a loader is a shape, and a shape is a heuristic's business. bases/unp/
 * scpayload_00.c produces the payload as an object of its own, so that every
 * signature in the database gets a chance at it - which only an unpacker may
 * do, because in this engine only an unpacker yields children.
 *
 * A header rather than two copies, for the reason bases/unp/msf_elf32.h gives
 * for being one: the modules differ in what they DO with the answer, not in how
 * they arrive at it. Two searches would be two chances to disagree about where
 * a payload is, and the pane showing it would be reading one while the scanner
 * scored the other.
 *
 * IT WAS NOT ALWAYS SHARED. The search was here, in the heuristic, and it
 * reported the offset it found as a debug fact and stopped. Nothing turned that
 * fact into an object, so the payload was never scanned by anything: kofviewer
 * carved it out of the debug value and wrapped it itself, purely for its own
 * pane, and the scanner walked past those bytes entirely.
 */
#ifndef SCFIND_H
#define SCFIND_H

#include <kofmod/kofsig.h>
#include <kofmod/heur.h>
#include <kofmod/elf.h>
#include <kofmod/kofsym.h>

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

/*
 * ---- THE POINTER-SHAPED VARIANT ------------------------------------------
 *
 * `char shellcode[] = "..."` puts the bytes IN the symbol, and the walk below
 * measures them. `char *shellcode = "..."` puts an ADDRESS in the symbol and
 * the bytes in .rodata, so the symbol's size is the width of a pointer and the
 * size gate refuses it - which is how a loader carrying its payload in clear
 * went unseen. Measured on 8e33bf25...: eight bytes at 0x4038 holding 0x2004,
 * and the twenty-three bytes there are the ordinary Linux x86
 * execve("/bin//sh") in clear.
 *
 * Followed ONCE, never recursively: a pointer to a pointer is not a shape a
 * compiler produces for this, and chasing further is walking data as addresses.
 *
 * WHAT SEPARATES IT FROM `char *message = "..."`, which is the same shape:
 *
 *   The target is NOT EXECUTABLE. This is the one that matters. Without it the
 *   walk finds every function pointer in .data - 313 of them in 300 clean
 *   binaries - because a pointer into .text is of course not text.
 *
 *   The blob is not mostly printable. A message is; SCL_NPR_PCT of the bytes
 *   must be outside printable ASCII. Alone this leaves 2 in 300.
 *
 *   It is not a table, by the same top-byte test the inline case uses. That
 *   takes it to 1 in 300 - a size_t that happened to look binary.
 *
 *   IT MAKES A SYSCALL. Linux shellcode has to; a data blob does not. This is
 *   what takes it to 0 in 300 clean binaries while keeping the one real
 *   payload, and it is also what drops a 21-byte candidate that turned out to
 *   be a Discord name written in UTF-8 emoji.
 *
 * The cost is stated rather than hidden: a cleartext payload that reaches the
 * kernel some other way - through a resolved libc pointer, say - is not found
 * by this. The alternative measured worse: eleven false positives, ten of them
 * OpenSSL curve tables in statically linked samples.
 */
#define SCL_PTR_MIN     16u     /* shorter than this is not a payload */
#define SCL_NPR_PCT     15u     /* of the blob must be non-printable */
#define SHF_EXECINSTR_X SHF_EXECINSTR_


/* Base64, decoded, because that is the one wrapper that can be undone with no
 * guesswork: the alphabet is fixed and the transform is reversible. Returns the
 * bytes written, or 0 when the input is not base64 - which is most payloads,
 * and not a failure. */
static uint32_t scf_b64(const uint8_t *in, uint32_t n, uint8_t *out,
			uint32_t cap)
{
	uint32_t i, k = 0, acc = 0, bits = 0;

	/*
	 * Refused on the first byte that is not in the alphabet, rather than
	 * skipped. A payload with a few base64-looking bytes in it is not
	 * base64, and decoding the parts that happen to fit would produce a
	 * blob that means nothing and looks like an answer.
	 */
	if (n < 8u)
		return 0;
	for (i = 0; i < n; i++) {
		uint32_t sixbit;
		uint8_t c = in[i];

		/*
		 * A NUL ENDS THE INPUT, it does not fail it.
		 *
		 * These blobs are declared as C string literals - `char code[]
		 * = "SDHJ..."` - so sizeof includes the terminator and the
		 * symbol's size is one more than the text. Treating that last
		 * byte as "not base64" refused every one of them, and the
		 * dialog said "looks like ?" over a screen of visibly base64
		 * ASCII.
		 *
		 * Only at the END, though: a NUL with data after it is not a
		 * string and not base64, so the loop stops rather than skipping
		 * and the tail is never decoded as if it belonged.
		 */
		if (!c)
			break;
		if (c == '=' || c == '\n' || c == '\r')
			continue;
		/* The alphabet as arithmetic rather than a table lookup: a
		 * module links against nothing, so there is no strchr here. */
		if (c >= 'A' && c <= 'Z')      sixbit = (uint32_t)(c - 'A');
		else if (c >= 'a' && c <= 'z') sixbit = (uint32_t)(c - 'a') + 26u;
		else if (c >= '0' && c <= '9') sixbit = (uint32_t)(c - '0') + 52u;
		else if (c == '+')             sixbit = 62u;
		else if (c == '/')             sixbit = 63u;
		else                           return 0;
		acc = (acc << 6) | sixbit;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (k >= cap)
				return 0;
			out[k++] = (uint8_t)(acc >> bits);
		}
	}
	return k;
}


/*
 * WHAT "CARRIES A PAYLOAD" MEANS, IN THIS FILE AND NOWHERE ELSE.
 *
 * The engine reports mechanical facts about a data address - read, written,
 * called, jumped to, in a register at a call - and says nothing about what any
 * of them is evidence of. This is where they become a claim, because this is
 * where the vocabulary of malware lives.
 *
 * EXECUTED is the claim being made: control reached the bytes. Called or jumped
 * to, because a loader may do either and the two are the same statement about
 * the data.
 *
 * STAGED is the shape this cannot yet see and is written down so the next
 * person does not have to work out that it is missing: a payload handed to
 * mprotect or memcpy and executed in a mapping of its own is an ARGUMENT and
 * never a call target. Adding it is a line here, not a change to the engine -
 * which is the whole point of the engine reporting facts rather than verdicts.
 */
#define SCF_EXECUTED  (KOF_XREF_CALL | KOF_XREF_JUMP)

/*
 * WHAT WAS MEASURED, AND WHAT EACH HALF OF THE GATE IS WORTH.
 *
 * Over three hundred binaries from /usr/bin - all of them clean - taking every
 * OBJECT symbol sized between 64 and 8192 bytes, which is what this rule
 * considers at all. 155 such variables:
 *
 *     CALL or JUMP                    0 of 155     0.0%
 *     RGN_ICALL                      22 of 155    14.2%
 *     ARG                            33 of 155    21.3%
 *     ARG and (RGN_ICALL or NEAR)    25 of 155    16.1%
 *
 * So no region fact is usable ALONE, and the reason is structural rather than
 * incidental: every dynamically linked binary calls __libc_start_main through
 * the GOT, which is an indirect call, from the region its entry point is in -
 * 107 of 107 over /usr/bin. Startup code alone guarantees a region with an
 * indirect call in any binary at all.
 *
 * THE GATE IS AN AND WITH THE BYTE TESTS BELOW, and that is what makes the
 * loose half safe. Measured at RULE level rather than at variable level:
 * enabling STAGED changed the hit count over 4940 real ELF files not at all
 * (13 either way) and added no finding on /usr/bin at --heur 2. The zero
 * belongs to the COMBINATION - relax the shape tests below to recover some lost
 * detection and this number moves without anything here warning about it.
 *
 * The two shapes STAGED exists for, neither of which any file in that lab
 * exhibits - they are exercised only by purpose-built controls:
 *
 *   - the address handed to a helper that calls its parameter
 *   - the payload copied into a fresh mapping and called there, which gcc
 *     inlines to MOVs so nothing is even passed to a call
 */
/*
 * A PREDICATE AND NOT A MASK, because the rule is an AND.
 *
 * There was a KOF_XREF_ARG|RGN_ICALL|RGN_NEAR mask beside this that nothing
 * used, and it read as "any of these" - which is the wrong rule and the loose
 * one. ARG is required: the control that only reads a lookup table has ARG
 * clear and RGN_NEAR set, so the mask would have accepted it.
 */
#define SCF_IS_STAGED(x) (((x) & KOF_XREF_ARG) && \
			  ((x) & (KOF_XREF_RGN_ICALL | KOF_XREF_RGN_NEAR)))

/*
 * AND WHERE THE ENGINE CANNOT LOOK, THIS GATE DOES NOT APPLY.
 *
 * The sweep behind kof_data_xref reads x86. On an ARM or a MIPS object it
 * answers KOF_XREF_PARTIAL and nothing else, which says "not analysed" rather
 * than "not referred to" - and gating on it regardless would reject every
 * candidate on every such file without a word. It did, for one build.
 *
 * So: where the answer is real, require it. Where it is not, fall through to
 * the byte tests, which is what this rule had before the sweep existed.
 */
#define SCF_NO_XREF(x)  (((x) & KOF_XREF_PARTIAL) && !((x) & SCF_EXECUTED))


/* What the search found. `at` is a file offset and is what an unpacker reads;
 * `va` is the symbol's own value and is what a report shows, because an offset
 * into a block the engine built means nothing to a reader looking at the file.
 * `bits` is 32 or 64 where the payload said so, and 0 where it did not. */
struct scf_hit {
	uint64_t at;
	uint64_t va;
	uint64_t len;
	unsigned bits;
	/*
	 * WHEN THE PAYLOAD IS NOT IN THE OBJECT.
	 *
	 * A loader may keep its payload base64 encoded, and then the bytes that
	 * matter are not at `at` - they are what `at` decodes to. Non-zero here
	 * says the caller's `dec` buffer holds them and how many; `at` and `len`
	 * still describe the encoded text, because that is what a report should
	 * point a reader at in the file they have open.
	 *
	 * A caller that only wants to know WHERE passes no buffer and never
	 * sees this set.
	 */
	uint32_t dec_n;
};

/*
 * Undo a wrapper, if there is one to undo.
 *
 * Reads the payload out of the object a byte at a time - kof_u8 is the only way
 * a module sees it - and hands the result to the one decoder that needs no
 * guessing. Zero means "what is at `at` IS the payload", which is the usual
 * answer and not a failure.
 *
 * It lived in kofviewer, where it fed a pane and nothing else: a base64 payload
 * was legible on screen and was never scanned, because the decoded bytes existed
 * only inside the tool.
 */
static uint32_t scf_decode(const struct kof_obj_ctx *ctx,
			   const struct scf_hit *h, uint8_t *dec, uint32_t cap)
{
	uint8_t enc[SCL_SIZE_MAX];
	uint32_t i, n;

	if (!dec || !cap || h->len > SCL_SIZE_MAX)
		return 0;
	n = (uint32_t)h->len;
	for (i = 0; i < n; i++)
		enc[i] = kof_u8(h->at + i);
	return scf_b64(enc, n, dec, cap);
}


/*
 * Where a symbol's own bytes are in the file, or 0 when the record's numbers do
 * not describe a place in it.
 *
 * The record's shndx, value and the section's own addresses are all read out of
 * the file, so every one of them is checked rather than trusted: a forged index
 * or an address below the section it claims to be in must fail the test, not
 * produce an offset.
 */
static uint64_t scl_sym_off(const struct kof_obj_ctx *ctx,
			    const struct kof_elf_info *e, const uint8_t *r,
			    uint64_t need)
{
	uint32_t shndx = (uint32_t)r[KOF_SYM_R_SHNDX] |
			 ((uint32_t)r[KOF_SYM_R_SHNDX + 1] << 8);
	uint64_t val, fo;

	if (shndx >= e->sec_count || shndx >= KOF_ELF_MAX_SECTIONS)
		return 0;
	if (e->sec[shndx].type != SHT_PROGBITS_)
		return 0;
	val = kof_sym_u64(r, KOF_SYM_R_VALUE);
	if (val < e->sec[shndx].mem_addr)
		return 0;
	fo = e->sec[shndx].file_off + (val - e->sec[shndx].mem_addr);
	if (fo >= ctx->obj_size || need > ctx->obj_size - fo)
		return 0;
	if (fo < e->sec[shndx].file_off ||
	    need > e->sec[shndx].file_size -
		   (fo - e->sec[shndx].file_off))
		return 0;
	return fo;
}

/*
 * Does this symbol hold a pointer to a cleartext payload.
 *
 * Hands the offset back the same way the inline case does, so a caller
 * and the scanner see one shape of answer whichever branch found it.
 */
static int scl_pointer(const struct kof_obj_ctx *ctx,
		       const struct kof_elf_info *e, const uint8_t *r,
		       struct scf_hit *out, uint8_t *dec, uint32_t dec_cap)
{
	uint64_t fo = scl_sym_off(ctx, e, r,
				  e->elf_class == KOF_ELFCLASS_64 ? 8u : 4u);
	uint64_t sym_va = kof_sym_u64(r, KOF_SYM_R_VALUE);
	uint64_t pv = 0, po, len, k;
	uint32_t w = e->elf_class == KOF_ELFCLASS_64 ? 8u : 4u;
	uint32_t i, npr = 0, top = 0, freq[256], sys = 0;

	if (!fo)
		return 0;
	for (k = 0; k < w; k++)
		pv |= (uint64_t)kof_u8(fo + k) << (8u * k);
	if (!pv)
		return 0;

	/* The section the address lands in, and it must not be code: without
	 * this the walk finds every function pointer in .data. */
	for (i = 0; i < e->sec_count && i < KOF_ELF_MAX_SECTIONS; i++) {
		const struct kof_elf_sec *sc = &e->sec[i];

		if (sc->type != SHT_PROGBITS_ || (sc->flags & SHF_EXECINSTR_))
			continue;
		if (pv < sc->mem_addr || pv >= sc->mem_addr + sc->file_size)
			continue;
		po = sc->file_off + (pv - sc->mem_addr);
		if (po >= ctx->obj_size)
			return 0;
		len = sc->file_off + sc->file_size - po;
		if (len > ctx->obj_size - po)
			len = ctx->obj_size - po;
		if (len > SCL_SIZE_MAX)
			len = SCL_SIZE_MAX;
		/* A `char *` initialiser is a string, so the payload ends where
		 * the compiler put its terminator. */
		for (k = 0; k < len; k++)
			if (kof_u8(po + k) == 0u) {
				len = k;
				break;
			}
		if (len < SCL_PTR_MIN)
			return 0;
		/*
		 * THE SAME QUESTION, ASKED OF THE POINTER.
		 *
		 * `fo` is where the pointer variable sits and `po` is what it
		 * points at, and it is the POINTER the code calls: the loader
		 * loads the variable and calls the register. Asking about the
		 * target would ask about an address the code never names.
		 */
		{
			uint32_t x = kof_data_xref(sym_va, w);

			if (!SCF_NO_XREF(x) && !(x & SCF_EXECUTED) && !SCF_IS_STAGED(x))
				return 0;
		}
		for (k = 0; k < 256u; k++)
			freq[k] = 0;
		for (k = 0; k < len; k++) {
			uint8_t c = kof_u8(po + k);

			if (++freq[c] > top)
				top = freq[c];
			if (c < 0x20u || c >= 0x7fu)
				npr++;
			/* int 0x80, syscall, sysenter - the whole of how a
			 * payload on Linux reaches the kernel. */
			if (k + 1u < len) {
				uint8_t d = kof_u8(po + k + 1u);

				/*
				 * WHICH one, not merely that there is one.
				 *
				 * int 0x80 and sysenter are how a 32-bit
				 * payload reaches the kernel and `syscall` is
				 * how a 64-bit one does, so the marker settles
				 * the width - and the width decides how the
				 * payload is disassembled. The alternative was
				 * for whoever displays it to guess again from
				 * the same bytes, which is one fact in two
				 * places and the second one was wrong: a
				 * cleartext x86 payload inside an ELF64 loader
				 * came out labelled x64.
				 */
				if (c == 0xcdu && d == 0x80u)
					sys = 32u;
				else if (c == 0x0fu && d == 0x34u)
					sys = 32u;
				else if (c == 0x0fu && d == 0x05u)
					sys = 64u;
			}
		}
		if (npr * 100u < (uint32_t)len * SCL_NPR_PCT)
			return 0;
		if (top * SCL_TOP_DENOM >= (uint32_t)len)
			return 0;       /* a table, not a payload */
		if (!sys)
			return 0;
		out->at    = po;
		out->va    = pv;
		out->len   = len;
		out->bits  = sys;
		out->dec_n = scf_decode(ctx, out, dec, dec_cap);
		return 1;
	}
	return 0;
}




/*
 * Returns 1 and fills `out` when this object looks like a loader carrying a
 * payload. Every early exit is "not that shape", not an error.
 */
static int scf_find(const struct kof_obj_ctx *ctx, struct scf_hit *out,
		    uint8_t *dec, uint32_t dec_cap)
{
	const struct kof_elf_info *e = kof_elf(ctx);
	const uint8_t *b, *r;
	uint32_t n = 0, i, code = 0, data = 0;

	if (!e || !e->valid)
			return 0;

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
				return 0;
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
			return 0;
	if (code > SCL_CODE_MAX)
			return 0;

	b = kof_syms(&n);
	if (!b)
		return 0;                 /* stripped, or nothing to walk */

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
	/*
	 * BACKWARDS, from the last record to `_start`.
	 *
	 * The WINDOW is the same either way - `_start` bounds it at one end and
	 * the last record at the other, about six records on the samples
	 * measured - so this is not a shorter search. It changes two things.
	 *
	 * It optimises the BEST case and leaves the worst alone: the payload
	 * sits within the last six records in every sample measured, and four
	 * of twelve are the very last, so backwards usually finds it on the
	 * first or second test rather than after walking the whole window.
	 *
	 * And it decides WHICH candidate is reported when a file has more than
	 * one. Two to four records pass the attribute test and up to two pass
	 * everything; forwards reports the first, backwards the last. The
	 * blob's position was measured for this: it ends exactly at its
	 * section's end in twelve of twelve, so the later candidate is the more
	 * likely payload.
	 *
	 * The loop condition is `i-- > lo`, which compares before it decrements,
	 * so it visits [lo, cnt) and stops without ever letting an unsigned
	 * index wrap below zero.
	 */
	/*
	 * EVERY RECORD, BACKWARDS - and the `_start` anchor that used to bound
	 * this is gone.
	 *
	 * It bounded the walk to the records after `_start`, where this
	 * toolchain emits a program's own globals: 63 records became 6 or 7,
	 * and all thirteen payloads found across a 4940 file lab are in that
	 * window. It looked like a clear win and it was not measurable. Three
	 * interleaved runs over the corpus: anchored 0.26/0.22/0.22, whole
	 * block 0.24/0.24/0.22. The walk is microseconds against half a
	 * gigabyte of scanning, so the tenfold cut in iterations bought
	 * nothing.
	 *
	 * What it COST was real: the ordering is the linker's, not the
	 * format's, so -nostartfiles or another translation unit order puts a
	 * global before `_start` and the payload was never looked at. A
	 * purposely built loader does exactly that.
	 *
	 * Backwards is kept - it decides WHICH candidate is reported when a
	 * file has more than one, and the blob sits at the end.
	 */
	for (i = kof_sym_count(b, n); i-- > 0; ) {
		uint64_t sz, val, fo;
		uint32_t shndx, k, top = 0;
		uint32_t freq[256];

		r = kof_sym_rec(b, n, i);
		if (!r)
			continue;

		/* The four bytes, and nothing else is read unless they pass. */
		if (r[KOF_SYM_R_TYPE]  != 1u   || r[KOF_SYM_R_BIND] != 1u ||
		    r[KOF_SYM_R_VIS]   != 0u   || r[KOF_SYM_R_FLAGS] != 0x15u)
			continue;

		sz = kof_sym_u64(r, KOF_SYM_R_SIZE);
		if (sz == (e->elf_class == KOF_ELFCLASS_64 ? 8u : 4u) &&
		    e->elf_data == KOF_ELFDATA_LE) {
			/* A pointer, followed once - see the note above. Only
			 * little-endian, because reading an address the wrong
			 * way round yields a number that lands nowhere and the
			 * walk would look like it had simply found nothing. */
			if (scl_pointer(ctx, e, r, out, dec, dec_cap))
				return 1;
			continue;
		}
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

		/*
		 * IS IT EXECUTED?
		 *
		 * The question the byte tests below cannot answer. They ask
		 * what the blob LOOKS like - how evenly its bytes are spread -
		 * and encoding the payload defeats every one of them, which is
		 * the first thing anyone does to a payload. This asks what the
		 * CODE does with the variable, and no encoding of the data
		 * reaches the code.
		 *
		 * Required, not merely preferred: a variable nothing calls is
		 * not a payload however its bytes are distributed. The one
		 * thing that could be lost is a loader that copies the blob
		 * somewhere else before calling it, and that shape is not
		 * visible to a sweep this cheap - see kofdisasm/xref.h, which
		 * says so.
		 *
		 * FIRST, because it is the cheapest and the most selective.
		 * It sat after the histogram below, so every candidate this
		 * rejects had already paid a pass over its whole blob - up to
		 * eight kilobytes read one byte at a time through the module
		 * boundary - to compute a number that was then thrown away.
		 * The sweep behind this is paid once for the object; the
		 * lookup is a hash probe.
		 */
		{
			uint32_t x = kof_data_xref(val, sz);

			if (!SCF_NO_XREF(x) && !(x & SCF_EXECUTED) && !SCF_IS_STAGED(x))
				continue;
		}
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
			 * The caller decides what to say about it; this only
			 * says where it is.
			 */
			out->at    = fo;
			out->va    = val;
			out->len   = sz;
			out->bits  = 0;        /* nothing here said a width */
			out->dec_n = scf_decode(ctx, out, dec, dec_cap);
			return 1;
		}
	}
	return 0;
}

#endif /* SCFIND_H */
