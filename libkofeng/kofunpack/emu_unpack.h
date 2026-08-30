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
#include <kofmod/kofsig.h>
#include "../../libkofemu/kofemu.h"

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
	KOF_EMU_UNP_WHY_BROKEN = 2
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
	const char          *detail;     /* the emulator's own last word */
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

#endif /* KOFENG_EMU_UNPACK_H */
