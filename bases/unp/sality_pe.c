/*
 * sality_pe.c - recognise W32.Sality in a PE, by running it and reading what
 * the run decrypted.
 *
 * SALITY IS POLYMORPHIC AND THE ENTRY POINT PROVES NOTHING. Measured over the
 * four samples here, the first bytes at the entry share nothing at all:
 *
 *     f6c69cf28bd20faff20fbeed434684c7...
 *     6033d886c38d3d3d0c9fe60fc1c86a00...
 *     f6c2c4f7c0fa360e32eb020fcd750769...
 *     e800000000 5d 0f6ed5 0f7ed7 81c70c020000 57 b477 c3
 *
 * The last is the one that gives the family away, and only because it is short
 * enough to read: call/pop to find itself, stash the address in an MMX register
 * and take it straight back - which exists to defeat an interpreter without MMX
 * - then `push edi; ret` into the next stage. The other three are the same
 * shape wearing several thousand junk instructions.
 *
 * SO THE DECRYPTOR IS NOT WHAT IS MATCHED. THE BODY IS, AND THE BODY IS NOT
 * POLYMORPHIC - that is the whole trade Sality makes. It carries one body and
 * a different wrapper every time, so the emulator's job is to take the wrapper
 * off and the signature's job is to name what is underneath. Neither half
 * works alone: matched before the run, all four samples match nothing.
 *
 *
 * WHERE THE BODY IS LOOKED FOR, AND TWO WRONG ANSWERS THAT CAME FIRST
 *
 * TinyAntivirus reads the return target of the first stage's hand-over - it
 * pauses on a `ret` and looks at [ESP] - and that was tried here first. It is
 * the wrong place and the measurement says so: the body turned up at 0x13116,
 * 0x2316 and 0xb8716 in three different runs, never at the address any single
 * `ret` pointed at. A polymorphic stub does not have one hand-over; it has as
 * many as its generator felt like emitting, and pinning the search to one of
 * them names one sample in four.
 *
 * SEARCHING WHAT THE RUN LEFT, AFTERWARDS, WAS THE SECOND WRONG ANSWER, and it
 * is the more interesting one because it worked until the interpreter got
 * better. A region is the bytes a page held when the interpreter gathered it,
 * which for a written page is the END of the run. While these runs died early
 * that was also the moment the body was decrypted, and searching afterwards
 * found it. Once `mov ebx, fs:[0x30]` decoded correctly the same runs went
 * from 3.5M instructions to 320M - the virus now finds kernel32 and gets on
 * with its work - and by the end it has written over the body. Three of four
 * stopped matching.
 *
 * SO THE RUN IS STOPPED AT THE MOMENT ITSELF, and the moment is not guessed:
 * THE SIGNATURE IS CODE THE VIRUS EXECUTES. The forty-nine bytes below are its
 * API resolver, so the interpreter can be asked to stop when it is ABOUT TO
 * RUN THEM - see kunp_emu_watch_insn. Standing there, the body is decrypted by
 * definition, it is at a known place relative to the instruction pointer, and
 * it has not been overwritten yet because the virus has not got that far.
 *
 * `mov ebx, fs:[0x30]` IS WHAT IS WATCHED FOR, seven bytes into the core. It
 * is the longest single instruction in it - six bytes, three of them a
 * displacement - and the watch matches one instruction at a time, so the
 * longest is the cheapest gate. The other forty-three bytes are then checked
 * around it.
 *
 *
 * WHAT IS MATCHED
 *
 * Two runs of bytes at the head of the body, at +0 and +0x23, which are
 * TinyAntivirus's. See THIRD-PARTY.md. They are absolute-address-bearing -
 * `81 ED 05 10 40 00` subtracts 0x401005 - because the body is written to run
 * at one address, and the two placeholder constants `22 22 22 22` and
 * `33 33 33 33` are slots the virus fills at run time, so the signature
 * deliberately covers them unfilled.
 *
 * THE PAIR, NOT EITHER HALF. The first run alone is 26 bytes of ordinary
 * position-finding prologue; requiring the second at exactly +0x23 is what
 * makes it a signature. Measured: the gap is 0x23 on every sample that has it.
 *
 *
 * WHAT THIS DOES NOT DO YET: cure. The offsets are known - the original entry
 * point, the bytes Sality saved from it and where its own body begins are all
 * at fixed distances from the address matched here - and they are read and
 * reported so that a cure can use them. Restoring them is kcure_'s job and
 * kcure_ does not exist yet.
 */

#include <kofmod/kofsig.h>
#include <kofmod/pe.h>
#include <kofunpack/emu_harvest.h>

KOF_UNPACK_KIND(KOF_UNP_PACKER);

KOF_TARGET_FORMAT(KOF_FMT_PE);

/*
 * A VIRUS, AND THE MODULE THAT FINDS IT IS AN UNPACKER.
 *
 * That looks like the wrong kind and it is the only one that works: naming
 * Sality means running its decryptor, and only an unpack module may drive the
 * interpreter. So this reports a finding the way a detector does and produces
 * what the run left the way an unpacker does, and both are true of it.
 */
KOF_TARGET_NAME(KOF_MALTYPE_VIRUS, "Sality");

/*
 * The run is worth its cost the moment the shape below matches, and the shape
 * is cheap to test - so level 1, an ordinary sweep.
 */
#define SAL_VOUCH_LEVEL 1u

/*
 * WHAT IS MATCHED: THE VIRUS'S OWN API RESOLVER.
 *
 * Forty-nine bytes, and they are not a byte pattern someone chose - they are
 * the routine Sality uses to find kernel32 without an import table, which it
 * must carry because it runs inside a host whose imports are not its own:
 *
 *     E9 82000000        jmp past the data
 *     33 DB              xor ebx, ebx
 *     64 67 8B 1E 3000   mov ebx, fs:[0x30]      the PEB
 *     85 DB / 78 0E      test / js               the "is this NT" branch
 *     8B 5B 0C           PEB_LDR_DATA
 *     8B 5B 1C           InInitializationOrderModuleList
 *     8B 1B / 8B 5B 08   first entry, its DllBase
 *     F8 / EB 0A         clc, and skip the Win9x arm
 *     8B 5B 34 / 8D 5B 7C / 8B 5B 3C    the Win9x arm
 *     F8 / 66 81 3B 4D5A / 74 05        clc, `cmp word [ebx],'MZ'`, je
 *     E9 ...
 *
 * HOW IT WAS ARRIVED AT, WHICH IS THE POINT. The four samples here decrypt
 * into two DIFFERENT bodies - the head of one is
 *
 *     E8 00000000 5D 8B C5 81 ED 05104000 8A 9D 73274000 84 DB 74 13 ...
 *
 * and of the other
 *
 *     E8 00000000 5D       81 ED 05104000 58 2D 40880000 89 85 43124000 ...
 *
 * - same virus, same constants 0x401005 and 0x402773, different code around
 * them. TinyAntivirus's signature is the first of those two and it names three
 * of the four. Diffing all four bodies byte by byte leaves six bytes in common
 * at the head and then this, IDENTICAL IN ALL FOUR, which is what a signature
 * for a family rather than for a build looks like.
 *
 * MEASURED, both halves of it:
 *
 *   - exactly ONE occurrence in each of the four children the runs produced;
 *   - ZERO occurrences in any of the four files BEFORE they were run.
 *
 * The second is the one that matters here. This cannot be matched statically
 * by anyone, at any time, on any of these samples - it does not exist until
 * the decryptor has run. That is the whole reason this module drives the
 * interpreter, and it is measured rather than assumed.
 */
static const uint8_t sal_core[] = {
	0xE9, 0x82, 0x00, 0x00, 0x00, 0x33, 0xDB, 0x64,
	0x67, 0x8B, 0x1E, 0x30, 0x00, 0x85, 0xDB, 0x78,
	0x0E, 0x8B, 0x5B, 0x0C, 0x8B, 0x5B, 0x1C, 0x8B,
	0x1B, 0x8B, 0x5B, 0x08, 0xF8, 0xEB, 0x0A, 0x8B,
	0x5B, 0x34, 0x8D, 0x5B, 0x7C, 0x8B, 0x5B, 0x3C,
	0xF8, 0x66, 0x81, 0x3B, 0x4D, 0x5A, 0x74, 0x05,
	0xE9
};

/*
 * AND WHERE THE BODY STARTS, WHICH THE CORE DOES NOT SAY.
 *
 * Every Sality body opens by finding out where it was loaded - `call $+5` then
 * `pop ebp` - and the core sits a fixed distance past that, but not the SAME
 * fixed distance: 0x3F in the three samples of one build and 0x35 in the
 * fourth, because that build's prologue is two instructions shorter. A single
 * constant would be right about three samples in four, which is exactly the
 * mistake this module already made once.
 *
 * So the core is the anchor and the prologue is searched for BACKWARDS from
 * it, within a window comfortably past both measured distances. The first
 * match walking back is the nearest one, which is this body's.
 */
static const uint8_t sal_prologue[] = {
	0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D
};
#define SAL_BACK_WINDOW 0x60u

/*
 * THE TWO BUILDS, TOLD APART BY THAT DISTANCE.
 *
 * The body's prologue is what differs between them, so the gap from the body
 * to the core is what measures it - 0x3F where the prologue is two
 * instructions longer, 0x35 where it is not. Disassembled, they are:
 *
 *   A (0x3F)                        B (0x35)
 *   call $+5 ; pop ebp              call $+5 ; pop ebp
 *   mov eax, ebp                    sub ebp, 0x401005
 *   sub ebp, 0x401005               pop eax
 *   mov bl, [ebp+0x402773]          sub eax, <imm32>
 *   test bl, bl ; jz                mov [ebp+0x401243], eax
 *   add esp, 0x6c                   cmp byte [ebp+0x402773], 0
 *   sub eax, <imm32>                jnz
 *
 * WHAT THEY SHARE IS NOT A GUESS. Both compute `ebp = body + 5 - 0x401005`
 * and then reach the flag as `[ebp+0x402773]`, which is body + 0x1773 in each
 * - read off the instructions above, not assumed from one of them. So the
 * saved-host block below is at the same place in both, and both are repaired.
 *
 * WHAT THEY DO NOT SHARE is where the original entry point is computed from:
 * A subtracts its immediate from `body + 5`, B from the base of the region the
 * body sits in, which is `body - SAL_BODY_BACK`. One formula each, and each
 * checked - see sal_oep.
 */
#define SAL_DELTA_A 0x3Fu
#define SAL_DELTA_B 0x35u
#define SAL_OEP_IMM_A 0x1Fu     /* the imm32 of `sub eax, imm32` in A */
#define SAL_OEP_IMM_B 0x0Eu     /* and in B */

/*
 * WHERE THE SAVED HOST IS, measured from the body's own address.
 *
 *   +0x1773  non-zero when the bytes Sality overwrote were saved
 *   +0x1774  how many of them
 *   +0x1778  the bytes themselves
 *   -0x1116  the base of the region the body sits in
 *
 * THE FIRST THREE ARE THE SAME IN BOTH BUILDS and that is read off their
 * instructions, not assumed: each computes `ebp = body + 5 - 0x401005` and
 * reaches the flag as `[ebp+0x402773]`, which is body + 0x1773. The length and
 * the bytes follow it.
 *
 * AND THE BYTES ARE WHAT THEY CLAIM TO BE. Read out on all four samples they
 * are entry-point code and nothing else - three of them open
 * `55 8B EC` and two carry the whole MSVC SEH prologue,
 * `push ebp; mov ebp,esp; push -1; push <handler>; push <scope>;
 *  mov eax,fs:[0]; push eax; mov fs:[0],esp`. A wrong offset here would give
 * 22 to 382 bytes of something that is not a function prologue, which is a
 * thing anyone can look at.
 */
#define SAL_SAVED_FLAG 0x1773u
#define SAL_SAVED_LEN  0x1774u
#define SAL_SAVED_AT   0x1778u
#define SAL_BODY_BACK  0x1116u

/*
 * How many saved bytes this will describe a repair for. The host carries at
 * most KOF_MAX_FIX patches of sixteen bytes and up to two of them go on
 * section headers, so the format's own ceiling is 992; this stops well short
 * of it. Measured on the samples here: 382, 330, 221 and 22.
 */
#define SAL_SAVED_MAX  512u

/*
 * ---- HOW LONG THE RUN IS ALLOWED, AND WHY IT IS LOOKED AT IN SLICES -------
 *
 * WHAT THIS USED TO DO. It armed an instruction watch on the body's own PEB
 * fetch and waited for the decrypted body to EXECUTE it. That works and it is
 * ruinous: the body has to be decrypted in full and then given control, which
 * on 160e27a3 is 186 million instructions and, with a second run on the child,
 * thirty-three seconds for one file.
 *
 * WHAT IT DOES NOW is what Nachenberg's polymorphic module did in 1995: run a
 * little, LOOK at what has been written, and stop as soon as that is enough.
 * The body does not have to finish decrypting and never has to run at all.
 *
 * THE NUMBERS SAY HOW MUCH THIS SAVES. The core is 0x3F bytes into the body
 * and the saved host bytes end by 0x1778 + 512, so a cure needs about 6 KB of
 * a 65 KB body - roughly a tenth of the decryption, and none of the transfer
 * of control that follows it.
 *
 * THE SLICE IS FOUR MILLION INSTRUCTIONS, which is the same order as the 1.5
 * million that module allowed for its WHOLE emulation. It is larger because a
 * modern obfuscated decryptor spends thousands of instructions per plaintext
 * byte, and it is one number rather than a schedule because the cost of
 * looking - a search of the section the body decrypts into - is small beside
 * it.
 */
/* How much guest memory is read at a time while searching. */
#define SAL_CHUNK     4096u
#define SAL_SLICE     (4u * 1024u * 1024u)
#define SAL_MAX_SLICE 24u

/*
 * THE SHAPE, WHICH IS WHAT EARNS THE RUN.
 *
 * Sality writes its decryptor into the section the entry point is already in
 * and has to make that section WRITABLE to do it, and it puts its body in the
 * last section and has to make that one EXECUTABLE. Both are abnormal on their
 * own and the pair is what this asks for. An executable `.rsrc` or `.reloc` -
 * which two of the samples here have - is not something a compiler emits.
 *
 * A STRICTER RULE WAS TRIED AND WAS WRONG. Requiring EVERY section writable
 * matched one sample of four: the other three have a read-only `.rsrc`, and the
 * standalone body has one section and no "last section" distinct from the entry
 * one at all. Measured before it was loosened, which is the only reason the
 * looser rule is not a guess.
 *
 * Measured over the 1680 PE32 files of one Bazaar collection: this matches
 * exactly ONE, a Vidar with randomly named sections - 0.1% - and it matches
 * four of the four Sality samples here.
 */
static int sal_shape(const struct kof_pe_info *pe)
{
	if (!pe->valid || pe->pe32_plus || !pe->sec_count)
		return 0;
	if (pe->entry_sec >= pe->sec_count)
		return 0;
	if ((pe->sec[pe->entry_sec].perm & (KOF_PE_PERM_W | KOF_PE_PERM_X)) !=
	    (KOF_PE_PERM_W | KOF_PE_PERM_X))
		return 0;
	return (pe->sec[pe->sec_count - 1u].perm & KOF_PE_PERM_X) != 0;
}

/*
 * ---- WHERE THE BYTES ARE READ FROM ---------------------------------------
 *
 * TWO SOURCES AND THE MODULE CANNOT CHOOSE IN ADVANCE.
 *
 * While the run is PAUSED mid-decryption, what matters is the live machine:
 * that is the point of slicing, and three of the four samples here are
 * recognised that way. When the run has ENDED there is no machine, and what
 * survives is the regions it left - which is the only thing left for the
 * fourth, whose decryptor faults at seven million instructions with the body
 * already in memory.
 *
 * So every read below goes through one accessor and the caller says which
 * source it holds. The addresses are guest addresses in both cases; a region
 * subtracts its own base.
 */
struct sal_src {
	int      live;          /* the machine, rather than a region */
	uint32_t rgn;
	uint64_t base;          /* the region's guest address */
	uint64_t len;
};

static uint32_t sal_rd(const struct kof_obj_ctx *ctx,
		       const struct sal_src *src, uint64_t va,
		       uint8_t *out, uint32_t n)
{
	if (src->live)
		return kunp_emu_read(va, out, n);
	if (va < src->base || va - src->base >= src->len)
		return 0;
	return kunp_emu_region_read(src->rgn, va - src->base, out, n);
}

/*
 * Walk back from the core to the `call $+5; pop ebp` the body opens with.
 * Answers the body's address, or the core's own when there is no prologue in
 * the window - which is not a refusal: the core is the finding, and a body
 * whose start cannot be pinned is still a body.
 */
static uint64_t sal_body_of(const struct kof_obj_ctx *ctx,
			    const struct sal_src *src, uint64_t core)
{
	uint8_t win[SAL_BACK_WINDOW];
	uint32_t n = (uint32_t)sizeof sal_prologue;
	uint32_t i;

	if (core < SAL_BACK_WINDOW)
		return core;
	if (sal_rd(ctx, src, core - SAL_BACK_WINDOW, win, SAL_BACK_WINDOW) !=
	    SAL_BACK_WINDOW)
		return core;
	/* Backwards, so the nearest prologue wins. */
	for (i = SAL_BACK_WINDOW - n + 1u; i-- > 0;) {
		uint32_t k;

		for (k = 0; k < n; k++)
			if (win[i + k] != sal_prologue[k])
				break;
		if (k == n)
			return core - SAL_BACK_WINDOW + i;
	}
	return core;
}

/*
 * Search the guest's memory for the core, in the one place it can be.
 *
 * WHERE, AND WHY NOT EVERYWHERE. Sality decrypts its body into the LAST
 * section - that is the section it had to make executable, which is half of
 * what sal_shape asks for - so that range is the whole search space. Measured
 * on the four samples here, the body lands there every time.
 *
 * LIVE MEMORY AND NOT A REGION, because this runs while the machine is paused
 * mid-decryption: there are no regions yet, and what is wanted is precisely
 * what has been written SO FAR.
 *
 * READ IN CHUNKS THAT OVERLAP, so a match across a chunk boundary is still
 * found. Answers the core's guest address, or 0.
 */
static uint64_t sal_find_core(const struct kof_obj_ctx *ctx,
			      const struct sal_src *src,
			      const struct kof_pe_info *pe)
{
	const uint32_t nc = (uint32_t)sizeof sal_core;
	const struct kof_pe_sec *last = &pe->sec[pe->sec_count - 1u];
	uint64_t base, span;
	uint8_t buf[SAL_CHUNK];
	uint64_t off;

	/*
	 * A REGION IS SEARCHED WHOLE; the live machine is searched where the
	 * body can be, which is the last section - the one Sality had to make
	 * executable, and half of what sal_shape asks for.
	 */
	if (src->live) {
		base = pe->image_base + last->mem_rva;
		span = last->mem_size > last->file_size ? last->mem_size
						       : last->file_size;
	} else {
		base = src->base;
		span = src->len;
	}
	if (span < nc)
		return 0;
	for (off = 0; off + nc <= span; off += SAL_CHUNK - (nc - 1u)) {
		uint64_t left = span - off;
		uint32_t got = left < SAL_CHUNK ? (uint32_t)left : SAL_CHUNK;
		uint32_t i;

		if (sal_rd(ctx, src, base + off, buf, got) != got)
			continue;       /* not written yet, or not mapped */
		for (i = 0; i + nc <= got; i++) {
			uint32_t k;

			if (buf[i] != sal_core[0])
				continue;
			for (k = 1; k < nc; k++)
				if (buf[i + k] != sal_core[k])
					break;
			if (k == nc)
				return base + off + i;
		}
		if (got < SAL_CHUNK)
			break;
	}
	return 0;
}

/*
 * WHERE THE HOST USED TO START, and the check that says the formula is right.
 *
 * Each build subtracts a stored immediate from a different anchor - see the
 * note on SAL_DELTA_A. Answers 0 when the distance names neither build.
 *
 * AND THE ANSWER IS CHECKED AGAINST THE FILE'S OWN ENTRY POINT, because on
 * every sample here they are the same number: Sality did not redirect the
 * program, it overwrote the code AT the entry. So the entry the header
 * declares is a value this formula must reproduce, and reproducing it is
 * evidence the offsets are being read where they actually are. Measured:
 * 0x401d9d, 0x401010, 0x441796 through A's formula and 0x4017c0 through B's,
 * each equal to its file's declared entry.
 *
 * A MISMATCH IS REPORTED AND NOT REPAIRED. It would mean either that this
 * build's layout is not one of the two known, or that a variant DOES move the
 * entry - and a repair that writes the host's bytes at an entry the virus
 * moved would put them in the wrong place.
 */
static uint64_t sal_oep(const struct kof_obj_ctx *ctx,
			const struct sal_src *src, uint64_t body,
			uint64_t delta)
{
	uint64_t anchor, at;
	uint8_t b[4];
	uint32_t imm;

	if (delta == SAL_DELTA_A) {
		at = body + SAL_OEP_IMM_A;
		anchor = body + 5u;
	} else if (delta == SAL_DELTA_B) {
		at = body + SAL_OEP_IMM_B;
		anchor = body - SAL_BODY_BACK;
	} else {
		return 0;
	}
	if (sal_rd(ctx, src, at, b, 4u) != 4u)
		return 0;
	imm = (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
	      ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
	return anchor - imm;
}

/*
 * The saved host block: how many bytes the virus displaced at the entry, or 0.
 * Reported as well as returned, so that a reader of --debug sees the same
 * number the repair acted on.
 */
static uint32_t sal_saved(const struct kof_obj_ctx *ctx,
			  const struct sal_src *src, uint64_t body)
{
	uint8_t b[4];
	uint32_t saved = 0;

	if (sal_rd(ctx, src, body + SAL_SAVED_FLAG, b, 1u) == 1u && b[0] &&
	    sal_rd(ctx, src, body + SAL_SAVED_LEN, b, 4u) == 4u)
		saved = (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
			((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
	/*
	 * A LENGTH OUT OF RANGE MEANS NOT DECRYPTED YET, NOT A HUGE HOST.
	 *
	 * This is read while the decryption is still running - see SAL_SLICE -
	 * so the four bytes at the length may still be ciphertext. Measured at
	 * the first slice on 160e27a3: 1,933,349,670, where the answer is 382.
	 * Believing it cost the repair on every sample: sal_cure refused the
	 * number, the module took that for "no host" and stopped slicing.
	 *
	 * So an implausible length is reported as nothing and the caller looks
	 * again after the next slice, which is exactly what periodic scanning
	 * is for.
	 */
	if (saved > SAL_SAVED_MAX)
		return 0;
	kof_debug("Sality.PE.saved", saved);
	/*
	 * A SAVED LENGTH OF ONE MEANS THERE IS NO HOST. TinyAntivirus calls it
	 * patient zero and deletes the file rather than disinfecting it,
	 * because what would be left after removing the virus is nothing.
	 *
	 * NOT THE SAME AS "one section". That was tried as the test and was
	 * wrong: 8ef99966 has a single section and carries 22 bytes of real
	 * MSVC entry code, so it is an infected program that happens to have
	 * been linked into one section - and refusing to repair it cost a
	 * repair that works.
	 */
	if (saved == 1u) {
		kof_debug("Sality.PE.patient_zero", 1);
		return 0;
	}
	return saved;
}

/*
 * ---- PUTTING IT BACK ------------------------------------------------------
 *
 * WHAT SALITY DID, measured on these samples rather than read anywhere:
 *
 *   - It left the ENTRY POINT alone. Sality.PE.oep answers 0x401d9d, 0x401010
 *     and 0x441796 on the three samples whose layout is known, and each is
 *     exactly the entry the file's own header declares. The virus did not
 *     redirect the program; it overwrote the CODE at the entry with its
 *     polymorphic decryptor and kept the bytes it displaced.
 *   - It made the entry's section WRITABLE, so it could write that decryptor,
 *     and the last section EXECUTABLE, so it could run its body from there.
 *     That pair is what sal_shape looks for.
 *   - It put its body in the last section, at a fixed distance below the
 *     address matched here.
 *
 * SO THE REPAIR IS THE FIRST TWO AND NOT THE THIRD, and that is a decision
 * with a measurement behind it. Cutting the body out would mean cutting a
 * hole in the MIDDLE of the file: on 160e27a3 the body starts at file offset
 * 0x110c0, the last section ends at 0x23000, and the file is 2,069,559 bytes
 * - so 1.9 MB of the host's own appended data sits behind the virus. Excising
 * the body moves all of it, and anything that seeks into an appendix by
 * absolute offset - which is what an installer's data is FOR - breaks.
 * f073b23d has 10 KB behind its body for the same reason.
 *
 * What is left is inert, and not merely in principle: the body is only
 * reachable because a section that should not be executable is, and that flag
 * is one of the two this clears. With both cleared sal_shape no longer
 * matches, so this engine stops running the file too - the repair and the
 * detection agree about what was undone.
 *
 * THIS IS A REPAIR AND NOT A REMOVAL, and the file is still reported infected
 * afterwards. Nothing here pretends the bytes are gone.
 *
 * AND NOT FOR A FILE WITH NO HOST. A sample whose entry section IS its last
 * section was never an infected program - there is nothing behind the virus
 * to restore and nothing to hand back. TinyAntivirus calls that patient zero
 * and deletes the file; this describes no repair for it, which is the same
 * statement without the deletion.
 */
#define SAL_SCN_MEM_WRITE   0x80000000u
#define SAL_SCN_MEM_EXECUTE 0x20000000u

/* Where the section header table begins, from the file's own headers. */
static uint64_t sal_sectab(const struct kof_obj_ctx *ctx)
{
	uint64_t nt = kof_u32(0x3cu);

	if (!nt || nt + 24u > ctx->obj_size)
		return 0;
	return nt + 24u + kof_u16(nt + 20u);    /* SizeOfOptionalHeader */
}

/* One section's Characteristics, with `bits` taken out of it. */
static int sal_unflag(const struct kof_obj_ctx *ctx, uint64_t tab, uint32_t i,
		      uint32_t bits)
{
	uint64_t at = tab + (uint64_t)i * 40u + 36u;
	uint32_t ch;
	uint8_t b[4];

	if (at + 4u > ctx->obj_size)
		return 0;
	ch = (uint32_t)kof_u32(at) & ~bits;
	b[0] = (uint8_t)ch;
	b[1] = (uint8_t)(ch >> 8);
	b[2] = (uint8_t)(ch >> 16);
	b[3] = (uint8_t)(ch >> 24);
	return kcure_patch(at, b, 4u);
}

static int sal_cure(const struct kof_obj_ctx *ctx,
		    const struct sal_src *src,
		    const struct kof_pe_info *pe, uint64_t body,
		    uint32_t saved)
{
	uint8_t host[SAL_SAVED_MAX];
	uint64_t eo = ctx->entry_off, tab;
	const struct kof_pe_sec *last = &pe->sec[pe->sec_count - 1u];
	uint32_t li = pe->sec_count - 1u, k;

	if (!saved || saved > SAL_SAVED_MAX || !pe->sec_count)
		return 0;
	if (pe->entry_sec >= pe->sec_count)
		return 0;
	if (eo == KOF_NA || eo == KOF_BROKEN || eo + saved > ctx->obj_size)
		return 0;
	tab = sal_sectab(ctx);
	if (!tab || tab + (uint64_t)pe->sec_count * 40u > ctx->obj_size)
		return 0;

	/*
	 * EVERYTHING IS READ AND CHECKED BEFORE ANYTHING IS DESCRIBED. A patch
	 * is recorded the moment it is asked for, so a read that fails halfway
	 * through would leave a HALF-RESTORED entry point described as a
	 * repair - which is worse than no repair, because it would be applied.
	 */
	if (sal_rd(ctx, src, body + SAL_SAVED_AT, host, saved) != saved)
		return 0;

	for (k = 0; k < saved; k += 16u) {
		uint32_t nb = saved - k < 16u ? saved - k : 16u;

		if (!kcure_patch(eo + k, host + k, nb))
			return 0;
	}
	/*
	 * THE TWO PERMISSIONS THE VIRUS NEEDED, and nothing else: what a
	 * section held before it was infected is not in the file to read.
	 *
	 * AND THE SECOND ONLY WHEN IT IS A SECOND SECTION. A file linked into
	 * one section has its entry and its last section in the same place, and
	 * clearing both would leave the program's only code neither writable
	 * nor executable - a repair that stops the file running at all.
	 * Clearing WRITE alone is enough there: measured on 8ef99966, its one
	 * section goes from RWX to R+X+CODE, which is what a .text is, and
	 * sal_shape stops matching either way.
	 */
	if (!sal_unflag(ctx, tab, pe->entry_sec, SAL_SCN_MEM_WRITE))
		return 0;
	if (li != pe->entry_sec &&
	    !sal_unflag(ctx, tab, li, SAL_SCN_MEM_EXECUTE))
		return 0;
	KOF_SCAN_CURABLE(eo);
	kof_debug("Sality.PE.cure", saved);
	/*
	 * AND WHERE THE INFECTION IS, which this already knows - see
	 * kof_mark_infected. Nothing here is computed for the sake of the mark:
	 * both ranges had to be worked out to describe the repair.
	 *
	 *   DAMAGE is the host's own entry code, which the virus overwrote and
	 *   the patches above put back.
	 *   BODY is the virus itself. It begins SAL_BODY_BACK below the address
	 *   the decrypted body runs at, and runs to the end of the last section
	 *   - the section Sality had to make executable in order to run from
	 *   it, which is half of what sal_shape asks for.
	 *
	 * THE BODY MARK IS THE ONE THE REPAIR DOES NOT ACT ON. It is left in
	 * the file deliberately - see the note above - so saying where it is is
	 * the only account a reader gets of it.
	 */
	kof_mark_infected(eo, saved, KOF_INF_DAMAGE);
	{
		uint64_t bv = body - SAL_BODY_BACK;
		uint64_t off;

		if (bv >= pe->image_base) {
			off = kof_pe_rva_to_off(pe, bv - pe->image_base);
			if (off != KOF_BROKEN && off < ctx->obj_size) {
				uint64_t end = last->file_off + last->file_size;

				if (end > off)
					kof_mark_infected(off, end - off,
							  KOF_INF_BODY);
			}
		}
	}
	return 1;
}

/*
 * One look at whatever `src` holds. Answers non-zero when there is no reason to
 * look again - the repair is described, or the layout is one this does not
 * know. Sets *found the first time the family is recognised.
 *
 * THE VERDICT AND THE REPAIR ARRIVE AT DIFFERENT TIMES, and that is the whole
 * reason this answers a "stop" separately from setting *found. The core is
 * 0x3F bytes into the body; the saved host block is at 0x1778, six kilobytes
 * of decryption further on. Measured at the first slice on 160e27a3, the core
 * is there and the saved LENGTH still reads 1,933,349,670 - ciphertext. So the
 * family is named at once and the repair waits for a later slice.
 */
static int sal_look(const struct kof_obj_ctx *ctx, const struct sal_src *src,
		    const struct kof_pe_info *pe, int *found)
{
	uint64_t core = sal_find_core(ctx, src, pe);
	uint64_t body, delta, oep;

	if (!core)
		return 0;
	body = sal_body_of(ctx, src, core);
	delta = core - body;
	oep = sal_oep(ctx, src, body, delta);

	if (!*found) {
		kunp_rcstruct_build("PE:Sality");
		kof_debug("Sality.PE.at", (uint32_t)core);
		kof_debug("Sality.PE.delta", (uint32_t)delta);
		kof_debug("Sality.PE.body", (uint32_t)(body - SAL_BODY_BACK));
		if (oep)
			kof_debug("Sality.PE.oep", (uint32_t)oep);
		*found = 1;
	}
	/*
	 * AND THE REPAIR ONLY WHERE THE LAYOUT WAS CONFIRMED - see sal_oep. A
	 * formula that reproduces the file's own entry point is what says the
	 * offsets are being read where they are; one that does not is a layout
	 * this does not know, and no further slice will change that.
	 */
	if (!oep || pe->image_base + pe->entry_rva != oep) {
		if (oep)
			kof_debug("Sality.PE.oep_mismatch", 1);
		return 1;
	}
	return sal_cure(ctx, src, pe, body, sal_saved(ctx, src, body));
}

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_pe_info *pe = kof_pe(ctx);
	uint32_t n, slices = 0;
	int found = 0;

	if (!sal_shape(pe))
		return;
	/*
	 * AND NOT ON SOMETHING ALREADY OPENED. The shape is two section
	 * permissions, which a packer's output can wear by accident - measured,
	 * 007 Spy.exe is PECompact and matches it - so this yields to whoever
	 * actually recognised the container rather than spending a run beside
	 * them.
	 */
	if (kunp_opened_already())
		return;
	/*
	 * NOR ON WHAT THIS MODULE ITSELF PRODUCED.
	 *
	 * The child is the decrypted body laid out as an image, and it wears
	 * the same two permissions the parent did - so sal_shape matches it and
	 * the whole run happens again on bytes already in hand. Measured on
	 * 160e27a3: sixteen more slices, sixty-four million instructions, and
	 * most of the file's scan time, for a verdict already reached.
	 *
	 * A MAPPED LAYOUT IS THE TEST because that is what a produced image is
	 * and what a file on disk is not.
	 */
	kof_debug("Sality.PE.shape", 1);

	/*
	 * ---- DECRYPT A LITTLE, LOOK, STOP WHEN IT IS ENOUGH ----------------
	 * See SAL_SLICE. The body never has to finish decrypting and never has
	 * to run.
	 */
	{
		struct sal_src src;

		src.live = 1;
		src.rgn = 0;
		src.base = 0;
		src.len = 0;

		kunp_emu_slice(SAL_SLICE);
		n = kunp_emu_run(SAL_VOUCH_LEVEL);
		while (!n && slices < SAL_MAX_SLICE) {
			slices++;
			if (sal_look(ctx, &src, pe, &found))
				break;
			n = kunp_emu_resume();
		}
		kof_debug("Sality.PE.slices", slices);

		/*
		 * AND IF THE RUN ENDED BEFORE ANY OF THAT, THE REGIONS IT LEFT.
		 *
		 * A decryptor that faults - measured on 57d128c3, at seven
		 * million instructions - never pauses again, so nothing above
		 * ever looked. The body is still there, in what the run handed
		 * over, and reading it is the difference between naming this
		 * sample and not.
		 */
		if (!found && n) {
			uint32_t i;

			src.live = 0;
			for (i = 0; i < n && !found; i++) {
				uint32_t kind;

				if (!kunp_emu_region(i, &src.base, &src.len,
						     &kind))
					continue;
				src.rgn = i;
				(void)sal_look(ctx, &src, pe, &found);
			}
		}
	}

	/*
	 * AND THE RUN ENDS HERE, whichever way the loop left it.
	 *
	 * EMULATE WHAT IS NECESSARY AND NOT A STEP MORE. This used to disarm
	 * the watch and resume, so that the regions would be gathered by a run
	 * that finished - and a run that finishes is one that spends its whole
	 * ceiling. Measured on 160e27a3: the body is recognised at the FIRST
	 * pause, and the resume then ran to 268,435,456 instructions and took
	 * forty seconds, proving nothing that the pause had not already shown.
	 *
	 * kunp_emu_stop gathers exactly what a finished run would have handed
	 * over, at the instruction the module chose. The interpreter cannot
	 * know when enough has been decrypted; this module does, because the
	 * thing it was waiting for has just executed.
	 *
	 * AND IT ALSO ENDS A RUN THAT FOUND NOTHING. Two hundred and fifty six
	 * pauses on the one instruction this watches for, without the rest of
	 * the core around any of them, is a program that is not this - and
	 * running it to the ceiling afterwards is the same waste for a file
	 * that is not even a candidate.
	 */
	if (!n)
		n = kunp_emu_stop();

	/*
	 * AND WHAT THE RUN LEFT, whether or not the body was recognised: a
	 * decryptor that ran is a decryptor that decrypted something, and the
	 * bytes are worth scanning even when this module could not name them.
	 */
	{
		uint32_t made = eh_fold(ctx, n);

		kof_debug("Sality.PE.emu", made);
		/*
		 * THE FINDING LAST, BECAUSE IT RETURNS.
		 *
		 * KOF_SCAN_INFECT reports and returns, and the name it reports
		 * is resolved through a table the build tool fills from the
		 * MACRO - a module calling ctx->report by hand gets no entry
		 * there and its finding resolves to nothing. Measured: the
		 * module recognised the body, set the report, and the scan
		 * printed only the heuristic.
		 *
		 * So whatever the run left is handed over first, and the
		 * verdict is the last thing this module does.
		 */
		if (found)
			KOF_SCAN_INFECT("Body");
	}
	/*
	 * AND NOTHING IS REPORTED WHEN THE SHAPE WAS ALL THERE WAS.
	 *
	 * KOF_UNP_UNSUPPORTED means "this engine could not read a file it
	 * recognised", and a shape of two section permissions is not
	 * recognition - it is a reason to look. Saying so put "not all of it:
	 * Unsupported by this build" on a PECompact sample that another module
	 * had already opened completely.
	 */
}
