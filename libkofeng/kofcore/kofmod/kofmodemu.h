/*
 * kofmodemu.h - driving the interpreter from a module, and reading the machine
 * and the code it leaves.
 *
 * Part of the module ABI; a module includes <kofmod/kofsig.h>, never this file.
 */

#ifndef KOFENG_KOFMODEMU_H
#define KOFENG_KOFMODEMU_H

#include <stdint.h>
#include "kofctx.h"

/*
 * What a producer may ask the engine to do with the child it is about to make: a
 * mask, so the vocabulary can grow without moving a value.
 */
enum kof_eng_want {
	KOF_ENG_USE_EMU = 1u << 0   /* interpret this object's entry point */
};

/*
 * Declare what the next child needs and from what --heur level up.
 *
 *     kunp_emu_want(KOF_ENG_USE_EMU, 2);
 *     kunp_static_decode(...);
 *     kunp_rcstruct_done();
 *
 * See child_want for why this is said rather than worked out later.
 */
#define kunp_emu_want(w, lvl)                                             \
	((void)((ctx)->content->child_want ?                                \
		((ctx)->content->child_want((ctx), (uint32_t)(w),           \
					    (uint32_t)(lvl)), 0) : 0))

/*
 * Tell the interpreter where this object's program will be.
 *
 *     for (each section that is not the packer's own)
 *             kunp_emu_oep_range(sec->mem_rva, sec->mem_size);
 *
 * Named for what it declares rather than for what reads it: kof_emu_watch is
 * already the interpreter's own single-address watch, and two spellings one
 * letter apart would be a macro quietly rewriting a function declaration.
 *
 * See emu_watch for why only a module can say this.
 */

/*
 * A register of the machine the last run left, or 0.
 *
 *     sp = kunp_emu_reg(KUNP_REG_SP);
 *     if (kunp_emu_read(sp, b, 4u) == 4u)
 *             ...                     -- where the RET was going
 *
 * See `emu_reg` for the numbering and for how long the answer is good for.
 */
#define KUNP_REG_AX 0u
#define KUNP_REG_CX 1u
#define KUNP_REG_DX 2u
#define KUNP_REG_BX 3u
#define KUNP_REG_SP 4u
#define KUNP_REG_BP 5u
#define KUNP_REG_SI 6u
#define KUNP_REG_DI 7u
/*
 * AND WHERE THE MACHINE IS. Not a general purpose register and numbered past
 * them on purpose: a module that paused a run stands at an instruction it
 * named, and everything it wants to check - what surrounds that instruction,
 * what it is part of - is relative to this.
 */
#define KUNP_REG_IP 16u

#define kunp_emu_reg(gpr)                                                   \
	((ctx)->content->emu_reg                                            \
	 ? (ctx)->content->emu_reg((ctx), (uint32_t)(gpr)) : (uint64_t)0)

/* Bytes of the guest's memory at a virtual address. Answers how many were
 * read, which is 0 for an address the run never mapped. */
#define kunp_emu_read(va, out, n)                                           \
	((ctx)->content->emu_read                                           \
	 ? (ctx)->content->emu_read((ctx), (uint64_t)(va), (out),           \
				    (uint32_t)(n)) : 0u)

#define kunp_emu_oep_range(rva, len)                                            \
	((void)((ctx)->content->emu_watch ?                                 \
		((ctx)->content->emu_watch((ctx), (uint64_t)(rva),          \
					   (uint64_t)(len)), 0) : 0))

/* What a run left. See `emu_run` in struct kof_content. */
#define KOF_EMU_RGN_IMAGE   0u
#define KOF_EMU_RGN_EXEC    1u
#define KOF_EMU_RGN_WRITTEN 2u

#define kunp_emu_run(vouch_level)                                          \
	((ctx)->content->emu_run                                           \
	 ? (ctx)->content->emu_run((ctx), (uint32_t)(vouch_level)) : 0u)

/*
 * Pause the run on an instruction, and carry on - see `emu_watch_insn`.
 *
 *     kunp_emu_watch_insn(ret, 1, 1);        // a one-byte C3
 *     n = kunp_emu_run(2);
 *     while (!n && still_paused) {   // 0 from run or resume = paused
 *             ...read the machine, decide...
 *             n = kunp_emu_resume();
 *     }
 */
#define kunp_emu_watch_insn(bytes, n, len)                                 \
	((ctx)->content->emu_watch_insn                                    \
	 ? (ctx)->content->emu_watch_insn((ctx), (bytes), (uint32_t)(n),   \
					  (uint32_t)(len)) : (void)0)

/*
 * End a paused run and take its regions - see `emu_stop`. This and not a
 * disarm-and-resume is how a module that has what it came for finishes.
 */
/*
 * ---- CHANGING A PAUSED MACHINE - see `emu_set_reg` ------------------------
 *
 *     if (!kunp_emu_reg(KUNP_REG_AX)) {
 *             kunp_emu_set_reg(KUNP_REG_AX, 1);   // what the call would have
 *             kunp_emu_set_ip(after);             // returned, had it worked
 *     }
 *     n = kunp_emu_resume();
 *
 * KUNP_REG_IP works through kunp_emu_set_reg too, and means the same thing as
 * kunp_emu_set_ip.
 */
#define kunp_emu_set_reg(gpr, value)                                       \
	((ctx)->content->emu_set_reg                                       \
	 ? (ctx)->content->emu_set_reg((ctx), (uint32_t)(gpr),             \
				       (uint64_t)(value)) : (void)0)

#define kunp_emu_set_ip(va)                                                \
	((ctx)->content->emu_set_ip                                        \
	 ? (ctx)->content->emu_set_ip((ctx), (uint64_t)(va)) : (void)0)

#define kunp_emu_write(va, bytes, n)                                       \
	((ctx)->content->emu_write                                         \
	 ? (ctx)->content->emu_write((ctx), (uint64_t)(va), (bytes),       \
				     (uint32_t)(n)) : 0u)

/* Run in slices - see `emu_slice`. Set once, before kunp_emu_run. */
#define kunp_emu_slice(n)                                                  \
	((ctx)->content->emu_slice                                         \
	 ? (ctx)->content->emu_slice((ctx), (uint64_t)(n)) : (void)0)

#define kunp_emu_stop()                                                    \
	((ctx)->content->emu_stop ? (ctx)->content->emu_stop((ctx)) : 0u)

#define kunp_emu_resume()                                                  \
	((ctx)->content->emu_resume ? (ctx)->content->emu_resume((ctx)) : 0u)

/*
 * Declare, before kunp_emu_run - see `emu_api_returns` and `emu_patch`.
 *
 *     kunp_emu_api_returns("IsDebuggerPresent", 0);
 *     kunp_emu_patch(check, nop, 2u);        // `check` and `nop` are 2 bytes
 *     n = kunp_emu_run(2);
 */
#define kunp_emu_api_returns(name, ret)                                    \
	((ctx)->content->emu_api_returns                                   \
	 ? (ctx)->content->emu_api_returns((ctx), (name), (uint64_t)(ret)) : 0u)

#define kunp_emu_patch(find, rep, n)                                       \
	((ctx)->content->emu_patch                                         \
	 ? (ctx)->content->emu_patch((ctx), (find), (rep), (uint32_t)(n)) : 0u)

#define kunp_emu_region(i, va, len, kind)                               \
	((ctx)->content->emu_region                                        \
	 ? (ctx)->content->emu_region((ctx), (uint32_t)(i), (va), (len),   \
				      (kind)) : 0)

#define kunp_emu_take(i)                                                \
	((ctx)->content->emu_take                                          \
	 ? (ctx)->content->emu_take((ctx), (uint32_t)(i)) : 0)

/*
 * ---- THE CODE READER - see kofmod/cell.h ---------------------------------
 *
 *     struct cell_insn in;
 *
 *     cell_seek(ctx->entry_off, 0);
 *     while (cell_next(&in)) {
 *             if (in.op == CELL_JMP && in.target != KOF_BROKEN) {
 *                     cell_seek(in.target, 1);      // step through junk
 *                     continue;
 *             }
 *             if (in.op == CELL_XOR && in.o[0].kind == CELL_O_MEM)
 *                     ...                           // a decrypt loop
 *     }
 */
#define cell_seek(off, keep)                                               \
	((ctx)->content->dis_seek                                          \
	 ? (ctx)->content->dis_seek((ctx), (uint64_t)(off), (keep)) : 0)

#define cell_next(out)                                                     \
	((ctx)->content->dis_next ? (ctx)->content->dis_next((ctx), (out)) : 0)

#define cell_reg(r, out)                                                   \
	((ctx)->content->dis_reg                                           \
	 ? (ctx)->content->dis_reg((ctx), (uint8_t)(r), (out)) : 0)

/*
 * Read from a gathered region's SNAPSHOT - see `emu_region_read`. This and not
 * kunp_emu_read is what a module looks at once its run has ENDED.
 */
#define kunp_emu_region_read(i, off, out, n)                               \
	((ctx)->content->emu_region_read                                   \
	 ? (ctx)->content->emu_region_read((ctx), (uint32_t)(i),           \
					   (uint64_t)(off), (out),         \
					   (uint32_t)(n)) : 0u)

#endif /* KOFENG_KOFMODEMU_H */
