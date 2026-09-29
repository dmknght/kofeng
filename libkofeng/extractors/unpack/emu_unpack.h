/*
 * emu_unpack.h - the bridge between what the ELF collector already worked out
 * and the interpreter in libkofemu.
 *
 * libkofemu knows nothing about ELF and must not: it maps memory, runs
 * instructions and reports what got written. Everything about the file - where
 * the segments are, whether the header can be believed, whether the object even
 * looks packed - has already been established by the collector, and asking a
 * second parser the same questions would be two answers to disagree about. So
 * this is the only place the two meet, and it reads `struct kof_elf_info`
 * rather than the file.
 *
 * Two jobs, deliberately separate:
 *
 *   the gate   decides whether emulating is worth a budget at all
 *   the run    builds a process image and hands back what the run produced
 *
 * They are separate because the gate has to be cheap enough to ask about every
 * object and the run is not, and because a caller that already knows it wants
 * to emulate - the viewer, told so by a person - should not have to satisfy a
 * heuristic first.
 */

#ifndef KOFENG_EMU_UNPACK_H
#define KOFENG_EMU_UNPACK_H

#include <kofmod/elf.h>
#include <kofmod/pe.h>
#include <kofmod/kofsig.h>
#include "../../../libkofemu/kofemu.h"

/*
 * Why this object is worth emulating - and the answer is never "because it
 * might be". Each of these is a positive statement about the file.
 */
enum kof_emu_unp_why {
	KOF_EMU_UNP_NO = 0,

	/*
	 * The executable segments are too dense to be code. Measured over the
	 * clean corpus: a threshold of 7.5 bits per byte over PT_LOAD|PF_X
	 * selects 294 objects with no false positive on 2 252 clean ELF files,
	 * and every one of them is x86-64. Something in the file writes its own
	 * code before running it, and no unpacker here knows which packer did
	 * it - which is exactly when running it is the only way to find out.
	 */
	KOF_EMU_UNP_WHY_DENSE = 1,

	/*
	 * The header cannot be loaded as written, and THIS IS THE FAIL-SAFE.
	 *
	 * A hand-written loader, a stripped and patched binary, a file whose
	 * program header table was overwritten by the thing that packed it: the
	 * collector reports these as anomalies rather than refusing, so the
	 * facts to act on are already in hand. A static unpacker has nothing to
	 * work with here - it needs structure to read - while an interpreter
	 * needs only somewhere to start, and can be given one. So the case that
	 * defeats every other module is the case this handles best.
	 */
	KOF_EMU_UNP_WHY_BROKEN = 2,

	/*
	 * A payload sits ENCRYPTED in a segment that is not code, and the file
	 * imports something that can turn memory into code.
	 *
	 * This is the C-loader shape: the executable segments decode as ordinary
	 * code, so the DENSE test says nothing, but a block of a writable or
	 * read-only segment has the entropy of ciphertext and the object imports
	 * mprotect or memfd_create - the two ways a program hands itself a page
	 * it can execute. Neither fact alone is worth a run: a resource, a
	 * certificate or a compressed asset is a high-entropy block with no
	 * intent, and mprotect is imported by anything with a JIT. Together they
	 * are a program carrying code it means to run and hide until it does.
	 *
	 * Measured over 846 clean binaries: a block of at least 8 KB at 7.2 bits
	 * per byte in a non-executable PT_LOAD, AND the string "mprotect" or
	 * "memfd_create" present, fires on none of them. It only sees STRONG
	 * encryption - a single-byte XOR leaves code at the entropy of code and
	 * passes straight through, which is a limit of the signal, not a bug in
	 * it. What it catches is the RC4/AES-wrapped payload an interpreter can
	 * decrypt by running the loader that was written to decrypt it.
	 */
	KOF_EMU_UNP_WHY_LOADER = 3,
	/*
	 * THE ENTRY POINT IS IN THE LAST SECTION, and there is compressed data
	 * somewhere in the file. A PE reason; the ELF gate never returns it.
	 *
	 * This is the shape a packer leaves whatever its codec: it appends a
	 * stub section, points AddressOfEntryPoint at it, and puts the
	 * compressed original wherever it likes. A linker does the opposite -
	 * code goes first and the entry goes with it.
	 *
	 * Measured over 2678 clean x86/x64 PEs from System32 and SysWOW64, and
	 * the distribution is not close:
	 *
	 *   entry in section 0                  2331
	 *   entry in section 1                     7
	 *   entry in no section at all           340   (resource-only DLLs)
	 *   ENTRY IN THE LAST SECTION              0
	 *
	 *   a >= 16KB high-entropy blob          144   (5.4%)
	 *   both together                          0
	 *
	 * WHY IT IS HERE AND DENSE WAS NOT ENOUGH. DENSE measures the entropy
	 * of EXECUTABLE sections, so it only sees a packer that leaves its
	 * compressed data somewhere the CPU could run from. The record this
	 * project kept of its own ASPack sample says that one did not: it had
	 * "the zero-raw section without the writable-executable one" - the
	 * compressed original was not in an executable section, so DENSE reads
	 * the stub, finds ordinary code entropy, and says no. A whole family
	 * of packers was therefore invisible to the gate while matching the
	 * most obvious structural tell there is.
	 *
	 * IT SELECTS "PACKED", NOT "MALICIOUS", and that is the right job for
	 * a gate: it decides whether to spend an emulation budget. A legitimate
	 * installer that is genuinely packed will fire, and firing on it is
	 * correct - it IS packed. The corpus above is Microsoft system
	 * binaries, which is a narrow sample of "clean" and is named rather
	 * than dressed up as the whole world.
	 */
	KOF_EMU_UNP_WHY_APPENDED = 4
};

/* What the run did, for the caller to report rather than guess at. */
struct kof_emu_unp_report {
	enum kof_emu_unp_why why;
	enum kof_emu_stop    stop;
	uint64_t             insn;
	uint64_t             entry;      /* where it was started */
	int                  improvised; /* the entry or the mapping was guessed */
	uint32_t             images;     /* snapshots taken at a W->X mprotect */
	uint32_t             written;    /* runs of written memory */
	/*
	 * THE STACK THIS RUN WAS GIVEN, so a harvest can leave it alone.
	 *
	 * A stub pushes, and what it pushed is not something it unpacked - but
	 * the written-memory set cannot tell the difference, so a scan of a
	 * 32-bit payload came back carrying a 4 KB page that was 94% zeros as
	 * though it were a recovered object. Reported rather than recomputed by
	 * the caller, because where the stack went is a decision made here and
	 * differs by width.
	 */
	uint64_t             stack_lo, stack_hi;
	/*
	 * AND THE SAME FOR THE EXCEPTION RECORDS, for exactly the reason above.
	 *
	 * An EXCEPTION_RECORD and a CONTEXT are written by the HOST into guest
	 * memory so that a guest handler can read them. They are therefore
	 * written memory, and the written-memory harvest cannot tell them from
	 * anything else the guest produced - so a run that faulted once came
	 * back carrying sixteen kilobytes of register dump as though it were a
	 * recovered object. Zero when no exception was raised.
	 */
	uint64_t             exc_lo, exc_hi;
	/*
	 * THE STUB RETURNED TO ITS CALLER - a PE ending, and a successful one.
	 *
	 * An ELF entry point is jumped to and finishes by calling exit or by
	 * handing off; a PE entry point is CALLED, so the ordinary way for one
	 * to finish is `ret`. build_stack_pe puts an unmapped sentinel there
	 * deliberately, which means that ordinary ending arrives as
	 * KOF_EMU_STOP_FAULT - the same stop as "ran off into nothing", which
	 * it is not.
	 *
	 * Set when the run faulted at exactly that sentinel, so a caller can
	 * tell the two apart without parsing `detail` and without the harvest
	 * having to treat every fault as a finished run. Never set by the ELF
	 * path, where returning is not how a stub ends.
	 */
	int                  returned;
	const char          *detail;     /* the emulator's own last word */
	/*
	 * Why no run was attempted at all, or NULL if one was.
	 *
	 * Distinct from a run that stopped early, and the distinction matters
	 * to whoever is reading: "the emulator could not unpack this" and "this
	 * file does not contain the code that would have unpacked it" are
	 * different findings, and only the second one is about the file.
	 */
	const char          *refused;
};

/*
 * Cheap enough to ask about every ELF object: one pass over the executable
 * segments, and only when the object is x86-64 to begin with.
 */
enum kof_emu_unp_why kof_emu_unp_gate(const struct kof_obj_ctx *ctx,
				      const struct kof_elf_info *info,
				      const uint8_t *file, uint64_t n);

/*
 * Build a process image and run it. Returns the emulator on success - the
 * caller walks kof_emu_next_snapshot and kof_emu_next_written and then calls
 * kof_emu_free - or NULL if no image could be built at all.
 *
 * `max_insn` and `max_pages` may be zero for the emulator's own defaults.
 */
struct kof_emu *kof_emu_unp_run(const uint8_t *file, uint64_t n,
				const struct kof_elf_info *info,
				uint64_t max_insn, uint64_t max_pages,
				struct kof_emu_unp_report *rep);

/*
 * ---- THE SAME TWO JOBS, FOR A PE -----------------------------------------
 *
 * WHY THIS EXISTS AT ALL, GIVEN WHAT kofemu.h SAYS
 *
 * kofemu.h states the position plainly: on ELF the boundary worth stubbing is
 * the syscall, and "the Windows API surface that makes emulation an arms race
 * is simply not present here". That is still true and nothing below changes
 * it. What it does NOT say, and what was being read into it, is that a PE
 * cannot usefully be run at all.
 *
 * A stub does two things: it computes, and it calls. The computing half - the
 * XOR loop, the LZ decompressor, the RC4 schedule - is arithmetic over the
 * file's own bytes and needs no API whatsoever. The calling half is where an
 * API layer would be needed, and it comes AFTER: a packer must decode its
 * payload before it has anything to allocate for, so the API call marks the
 * END of the part worth emulating rather than the start.
 *
 * So a run with no API layer is not a crippled run. It is a run that goes
 * exactly as far as the arithmetic and then stops - and kof_emu_unp_run's
 * contract already says a stop is not a failure: every snapshot and every
 * written page is collected whatever the reason, because the whole design is
 * "a memory dumper with a budget". A stub that decodes 400 KB and then faults
 * reading the PEB has still decoded 400 KB.
 *
 * WHAT THIS THEREFORE DOES AND DOES NOT REACH
 *
 * Reaches: single-stage crypters and stub decoders whose work is arithmetic -
 * the shape most custom packers have, and the shape a static unpacker cannot
 * follow because nobody wrote a module for that one packer.
 *
 * Does not reach: anything whose decode is driven THROUGH the API - a stub
 * that allocates first and decodes into what it got back stops at the
 * allocation with nothing written. Nor anything resolving imports by walking
 * the PEB, which faults on the first read. Those need the PEB/LDR and the
 * handful of memory APIs, and that is a separate decision to make on evidence
 * this produces rather than ahead of it.
 *
 * x86 AND x86-64 ONLY, because bddisasm decodes those. An ARM64 PE is refused
 * by the gate rather than started and left to fault on its first instruction.
 *
 * TWO REASONS, NOT THREE. The gate answers DENSE or BROKEN and never LOADER:
 * the conjunction that reason is built on loses its discriminating half on
 * Windows, where 16.6% of clean system binaries name VirtualAlloc. The
 * measurement is beside kof_emu_unp_gate_pe in the .c, along with what a
 * Windows-shaped replacement would have to be.
 */
enum kof_emu_unp_why kof_emu_unp_gate_pe(const struct kof_obj_ctx *ctx,
					 const struct kof_pe_info *info,
					 const uint8_t *file, uint64_t n);

/*
 * `oep` and `n_oep` are ranges, as RVAs, where the object's program will be
 * once its loader has run - declared by the module that recognised the
 * container, because nothing structural tells a packer's own sections from the
 * program's. A fetch from one ends the run as KOF_EMU_STOP_HANDOFF, which is
 * the moment the memory is worth harvesting. NULL and 0 are normal.
 */
struct kof_emu_oep { uint64_t rva, len; };

/*
 * ---- PUTTING A RUN'S SECTIONS BACK INTO A FILE ----------------------------
 *
 * What a run leaves is regions, and only some of them are the program. Taken
 * from a PECompact2 sample, in the order the interpreter reports them:
 *
 *     0x401000   6,488,064   .text at its own address - the decompressed image
 *     0xc3b000      32,768   .rsrc at its own address
 *     0x20000000  ..299,008  three regions: memory the guest asked for
 *     0x2f000000     4,096   the host's exception records
 *     0x7ffe1000     4,096   the thread block
 *     0xfff7e000     4,096   the stack
 *
 * A region that STARTS EXACTLY at a section's virtual address is that section
 * as the loader meant it to be. Nothing else does: an allocation lands where
 * the allocator put it, and the block, the scratch and the stack are the
 * host's own. That one test separates them with no threshold in it.
 *
 * So this assembles a file from those regions and the parent's header, each at
 * its own address. The entry point is left at zero - where the unpacked
 * program starts is decided at run time and is not in the file - and nothing
 * else is invented: machine, image base, subsystem and the section table are
 * the parent's, and a section no region covered is left as zeroes.
 *
 * Returns 0 when no region starts at a section, which is the ordinary answer
 * for a run that unpacked nothing.
 */
/* How many allocations the assembled image can carry as sections of its own.
 * A stub makes a handful; a program that makes dozens is running, not
 * unpacking, and the rest come back as their own objects either way. */
#define KOF_PE_RUN_CHUNKS 8u

int kof_pe_image_from_run(struct kof_emu *e, const struct kof_pe_info *info,
			  uint64_t base, uint64_t cap,
			  uint8_t **out, uint64_t *out_len);

struct kof_emu *kof_emu_unp_run_pe(const uint8_t *file, uint64_t n,
				   const struct kof_pe_info *info,
				   uint64_t max_insn, uint64_t max_pages,
				   uint64_t idle,
				   const struct kof_emu_oep *oep,
				   unsigned n_oep,
				   struct kof_emu_unp_report *rep);

#endif /* KOFENG_EMU_UNPACK_H */
