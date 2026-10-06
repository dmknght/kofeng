/*
 * diag_emu.c - the link between two nodes, established by RUNNING the code
 * between them instead of modelling it.
 *
 * WHY A SECOND ROUTINE AND NOT A BETTER FIRST ONE.
 *
 * The static walk carries a value in a register and loses it everywhere else.
 * That is not a bug to fix; it is what reading forwards without executing can
 * honestly claim. MEASURED, on two ELFs identical but for one instruction:
 *
 *     p = mmap(RWX); read(fd, p, n); jmp p;         3 nodes, 2 links
 *     p = mmap(RWX); v = p; read(fd, v, n); jmp v;  2 nodes, 0 links
 *
 * One local variable. The same program, the same behaviour, and the diagnose
 * stops matching - the read loses its buffer link and the jump stops being a
 * node at all, because the register it branches through carries nothing.
 *
 * THE VARIABLE IS NOT A NODE. It is a step on a LINK: nothing happens at it,
 * no capability is exercised, and a model that needs a word for it has the
 * wrong shape. What is needed is not more node kinds but a link that survives
 * a trip through memory - and the cheapest correct way to follow a value
 * through memory is to put the value in memory and look.
 *
 * WHAT IT COSTS, measured here: 16.2 M instructions a second against 16.9 for
 * decoding the same stream and doing nothing with it. Interpreting is 1.04x
 * the price of reading, so which to use is not a question about speed.
 *
 *
 * ---- A LOOP MUST NOT PRODUCE A SECOND NODE, OR A SECOND LINK --------------
 *
 * The first version of this read the emulator's syscall LOG, which records
 * what was called and not where from. MEASURED on meter1_x86, which retries
 * connect ten times before giving up: thirty nodes, for three sites. Those
 * are not findings, they are the same finding counted again, and an analyzer
 * that reports them has stopped describing the program.
 *
 * A NODE IS A SITE. The instruction is at one file offset however many times
 * control reaches it; running it twice is a fact about the run, not about the
 * program. So this stops AT each syscall, takes rip, and keys the node on the
 * offset - which is also what lets a node from a run and a node from the
 * static sweep be recognised as the same node later.
 *
 * A LINK IS A TRIPLE. (child, parent, role) seen again is the same link.
 * kof_diag_note_in is told once.
 *
 *
 * ---- STATIC STEERS, THE RUN RESOLVES --------------------------------------
 *
 * The two routines are not two attempts at one job. The sweep reads the file
 * and says WHERE the interesting places are - every syscall site, at a file
 * offset, on every path including the ones no run takes. The run says WHICH
 * VALUE REACHED WHICH PLACE, which is the one question reading cannot answer
 * once a value goes through memory.
 *
 * SO NOTHING HERE RECOGNISES AN INSTRUCTION BY ITS BYTES. An earlier version
 * of the handover test listed the encodings of jmp and call through a
 * register and of ret - sixteen forms plus the prefixed ones - and that list
 * is a list of the ways we happen to know about. An author who hands over
 * some other way is not in it, and nothing says so. What is used instead is
 * the behaviour: control arrived inside a region an allocation handed back.
 * Whatever instruction took it there, and whether we have heard of that
 * instruction, does not enter into it.
 *
 * ---- STEERING, AND WHY IT CANNOT LIE --------------------------------------
 *
 * A run goes where its values take it. meter1 retries connect to
 * 127.0.0.1:9999 and exits; with nothing listening the run never reaches the
 * read or the jump that make it a stager, while the static sweep sees both
 * because layout does not care which arm executes.
 *
 * So when a call fails, this substitutes a success. NOT to assert that it
 * succeeded - to walk the path on which it did, which is the path the
 * diagnose is about.
 *
 * AND THAT CANNOT MANUFACTURE A LINK. A link is recorded only when a value
 * IS in an argument register at a real call site; steering decides which
 * code runs, never what a register holds. A wrong steer costs a wasted run
 * and cannot produce a finding - which is why the heuristic here is allowed
 * to be crude, and why the same crudeness in a static model would not be.
 *
 *
 * ---- WHAT IT STILL CANNOT DO ----------------------------------------------
 *
 * ONE PATH PER RUN. Choosing the success arm covers the branch that turns on
 * a call's result, which is the common one. A branch on a payload byte or a
 * counter is not steered and the other arm is not seen. The static sweep is
 * the complement, and neither is a fallback for the other.
 *
 * IT PROVES PRESENCE. A link it did not see is not a link that is not there.
 */

#include <stdint.h>
#include <string.h>

#include "kofdiag.h"
#include "diag_int.h"
#include "../../kofcore/kofcore.h"
#include "../../kofcore/kofmod/kofcap.h"
#include "../../kofcore/kofmod/elf.h"
#include "../../analyzers/parsers/binaries/disasm/nucleo.h"
#include "../../analyzers/parsers/binaries/disasm/decode.h"
#include "../../disinfect/pzero.h"
#include "../../analyzers/parsers/binaries/elf/elf_parse.h"
#include "../../extractors/unpack/emu_unpack.h"
#include "../../../libkofemu/kofemu.h"

/*
 * WHAT THE RUN IS ALLOWED TO COST.
 *
 * Bounds on the INPUT, not on the results - rule 4. Whatever was found when
 * one bites is kept, and kof_diag_scan_ran says the routine ran, so a caller
 * can tell "nothing linked" from "never attempted".
 *
 * DIAG_EMU_STOPS is the number of syscalls stopped at, not an instruction
 * count: it is what bounds a program that calls in a loop forever, and 256 is
 * far past any stager measured here - the longest, meter1_x86 with its ten
 * retries, reaches 34.
 */
#define DIAG_EMU_INSN  2000000ull
#define DIAG_EMU_PAGES 0ull           /* the emulator's own default */
#define DIAG_EMU_STOPS 256u
#define DIAG_EMU_LEAD  256u
/* Where a relocatable object's stack goes: far above anything a file
 * occupies, so no section can overlap it. */
#define DIAG_REL_STACK 0x7ffff0000000ull
/* Room past the file for .bss and anything else that is declared but not
 * stored. */
#define DIAG_REL_SLACK 0x40000ull
/* Where %gs points: the per-cpu area and the stack guard. */
#define DIAG_REL_PERCPU 0x30000000ull
/* Where the file image sits. Offset zero is the null page and cannot be
 * mapped; the bias is private to this file. */
#define DIAG_REL_BASE  0x100000ull
/* The token arena: one page per producing call, dereferenceable, and far
 * from both the image and the stack. */
#define DIAG_TOK_BASE  0x20000000ull
#define DIAG_TOK_SPAN  256u

/* One syscall site, and what the run saw there. */
struct site {
	uint64_t off;         /* file offset of the instruction          */
	uint16_t node;        /* index in the scan                       */
};

/*
 * A value an earlier call handed back, and the node that handed it back.
 *
 * `len` is non-zero when the value is a REGION rather than a handle, and it
 * is what makes an entry into that region attributable: control arriving at
 * base+k belongs to the call that produced base, and to no other.
 */
struct made {
	uint64_t val, len;
	uint16_t node;
};

#define DIAG_EMU_SITES 64u
#define DIAG_EMU_MADE  64u

/*
 * IS THIS RETURN VALUE SOMETHING A LATER CALL COULD CARRY.
 *
 * Zero and the error range are excluded. write() returns a count and close()
 * returns 0, so a later read() on fd 0 would "link" to every one of them;
 * -1..-4095 is how Linux returns errno and a failed call produced no object.
 */
static int ret_is_carryable(uint64_t ret)
{
	return ret != 0u && (int64_t)ret > -4096;
}

/*
 * DOES THIS CALL HAND SOMETHING ON.
 *
 * Keyed on the CAPABILITY and never on the syscall's name: the name differs
 * between i386 and amd64 for the same act - socketcall against socket - and
 * between a syscall and the import that means the same thing. The capability
 * is what both resolve to, which is the whole reason it exists.
 */
static int cap_hands_on_value(uint16_t cap)
{
	switch (cap) {
	case KOF_NUCLEO_ALLOC:
	case KOF_NUCLEO_ALLOC_EXEC:
	case KOF_NUCLEO_HEAP:
	case KOF_NUCLEO_NET_OPEN:
	case KOF_NUCLEO_NET_RAW:
	case KOF_NUCLEO_NET_ACCEPT:
	case KOF_NUCLEO_FILE_OPEN:
	case KOF_NUCLEO_MEMFD:
	case KOF_NUCLEO_PIPE_OPEN:
		return 1;
	default:
		return 0;
	}
}


/*
 * ---- EVERY CALL MUST BRANCH THE SUCCESSFUL WAY ----------------------------
 *
 * A sandbox has no peer to connect to, no file to open and nothing on the
 * other end of a read, so the program under a faithful run takes the failure
 * arm of everything and exits. MEASURED on meter1: socket, then straight to
 * exit, with the read and the jump that make it a stager never reached.
 *
 * So a call that failed is given a success. NOT a claim that it succeeded -
 * the path on which it did is the path the diagnose describes, and walking it
 * is the only way to see the rest. See the note on steering at the top for
 * why this cannot manufacture a link.
 *
 * AND SUCCESS HAS A DIFFERENT SHAPE PER CALL, which is the whole of this
 * function. Returning 0 from socket() is not success, it is fd 0; returning 0
 * from connect() is. Four shapes:
 *
 *   ZERO        connect, bind, listen, dup2 - the calls whose success is
 *               the absence of an error.
 *   A HANDLE    socket, open, accept, memfd, pipe. It must also be DISTINCT:
 *               two sockets that both "succeed" as fd 3 would make a later
 *               send(3) link to whichever was remembered last, which is a
 *               link the program never had. A counter gives each its own.
 *   A COUNT     read, write, recv, send. The length that was ASKED for -
 *               a short count is what makes a stager loop, and a zero is
 *               what makes it give up.
 *   LEFT ALONE  mmap and the allocators. A pointer has to be memory that can
 *               then be written, and only the emulator's own implementation
 *               can hand one out; a fabricated address would fault at the
 *               first store into it. mprotect is here too and for a worse
 *               reason: it shares KOF_NUCLEO_ALLOC with mmap, so the capability
 *               alone cannot say whether 0 or a pointer is the success. That
 *               is a thing to fix in the vocabulary, not to guess at here.
 */
enum force_kind { FORCE_NONE = 0, FORCE_ZERO, FORCE_HANDLE, FORCE_COUNT };

static enum force_kind cap_force_kind(uint16_t cap)
{
	switch (cap) {
	case KOF_NUCLEO_NET_CONNECT:
	case KOF_NUCLEO_NET_BIND:
	case KOF_NUCLEO_NET_LISTEN:
	case KOF_NUCLEO_FD_REDIR:
	/*
	 * AND THE KERNEL COPIES, WHOSE SUCCESS VALUE IS ZERO AND NOT A COUNT.
	 * copy_from_user and copy_to_user return the number of bytes they
	 * could NOT move, so every caller reads `if (err) goto out`.
	 *
	 * MEASURED: given a non-zero result these two were read as having
	 * failed, and Diamorphine's hooked getdents went straight from the
	 * first copy to its error path - freeing the buffer and leaving - so
	 * the second copy, which is the whole of the hiding, was never on the
	 * path the run took.
	 */
	case KOF_NUCLEO_COPY_FROM_USER:
	case KOF_NUCLEO_COPY_TO_USER:
		return FORCE_ZERO;
	case KOF_NUCLEO_NET_OPEN:
	case KOF_NUCLEO_NET_RAW:
	case KOF_NUCLEO_NET_ACCEPT:
	case KOF_NUCLEO_FILE_OPEN:
	case KOF_NUCLEO_MEMFD:
	case KOF_NUCLEO_PIPE_OPEN:
		return FORCE_HANDLE;
	/* The generic descriptor calls AND the file-specific ones: the role
	 * an argument plays is the same whatever the descriptor turns out to
	 * be, and the word is corrected later - see diag_refine. Listing only
	 * the file spelling is how the links vanished when read(2) was moved
	 * out of KOF_CG_FILE. */
	case KOF_NUCLEO_MEM_READ:
	case KOF_NUCLEO_MEM_WRITE:
	case KOF_NUCLEO_READ:
	case KOF_NUCLEO_WRITE:
	case KOF_NUCLEO_NET_READ:
	case KOF_NUCLEO_NET_WRITE:
		return FORCE_COUNT;
	default:
		return FORCE_NONE;
	}
}

/* A handle nothing else will hand out. Above every real descriptor the
 * emulator issues and far below anything that could be a pointer. */
#define DIAG_EMU_FD0 0x200u

/*
 * ---- FILLING A FORCED READ: KEPT, DISABLED, AND NOT DEPENDED ON ----------
 *
 * A read whose result is forced returns n without putting n bytes anywhere,
 * which is a state no real machine is ever in. The obvious repair is to write
 * the buffer, and this did - with nops.
 *
 * IT IS OFF BECAUSE IT IS NOT DURABLE. The content would be THIS ROUTINE'S,
 * and a finding resting on it rests on a fabrication an author defeats
 * without effort: a stager that looks at what it received before using it - a
 * magic byte, a declared length, a checksum, a decryption that has to produce
 * something - compares against nops, fails, takes the other arm, and never
 * reaches the handover. The evasion costs three instructions.
 *
 * AND IT TURNED OUT TO BE UNNECESSARY, which is the better reason. It was
 * added on the claim that control entering a region is noticed only once the
 * page has been written. That was wrong: what was missing was
 * kof_emu_hop_add, declaring the range. MEASURED with it off - meter1,
 * meter2, meter3_encoded, meter4_encoded, rc4_1 and shikata_ga_nai each still
 * yield 5 nodes and 4 links, exec-memory among them.
 *
 * Left in rather than deleted because a forced read that writes nothing is
 * still a lie about the machine, and a routine that needs the buffer to hold
 * something - one following a decryptor - will want it. Whatever turns it on
 * must not let a finding depend on the bytes.
 */
#define DIAG_EMU_FILL 4096u
#define DIAG_EMU_FILL_ON 0

#if DIAG_EMU_FILL_ON

static void fill_buffer(struct kof_emu *em, uint64_t at, uint64_t n)
{
	static const uint8_t nop[64] = {
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
	};
	uint64_t done = 0;

	if (!at || n > DIAG_EMU_FILL)
		n = n > DIAG_EMU_FILL ? DIAG_EMU_FILL : n;
	while (done < n) {
		unsigned k = (unsigned)(n - done);

		if (k > sizeof nop)
			k = (unsigned)sizeof nop;
		if (!kof_emu_write(em, at + done, nop, k))
			return;         /* unmapped: nothing to fill */
		done += k;
	}
}
#endif /* DIAG_EMU_FILL_ON */

/* rax on amd64, eax on i386 - the same register number either way. */
#define DIAG_EMU_RET KOF_EMU_RAX

static const unsigned arg_reg64[6] = {
	KOF_EMU_RDI, KOF_EMU_RSI, KOF_EMU_RDX,
	KOF_EMU_R10, KOF_EMU_R8,  KOF_EMU_R9
};
static const unsigned arg_reg32[6] = {
	KOF_EMU_RBX, KOF_EMU_RCX, KOF_EMU_RDX,
	KOF_EMU_RSI, KOF_EMU_RDI, KOF_EMU_RBP
};


/*
 * ---- AN IMAGE FOR A RELOCATABLE OBJECT -----------------------------------
 *
 * A .ko has no program header, so kof_emu_unp_build has nothing to lay out
 * and the routine above never reaches a kernel module at all. What it has is
 * SECTIONS, and for a run that starts between two known call sites that is
 * enough: map every allocatable one where the file holds it, at the offset
 * the file holds it at.
 *
 * THE FILE IS THE ADDRESS SPACE, which is not a convenience but the only
 * coherent reading. sh_addr in an ET_REL is zero - the linker has not placed
 * anything - and kof_elf_relcalls reports its sites as file offsets, so the
 * decoder, the relocation table and this mapping all speak the same numbers.
 * kdis_off_to_va makes the same choice for the same reason.
 *
 * RELOCATIONS ARE NOT APPLIED, and that is the boundary of what this can do.
 * A call to an import is `e8 00 00 00 00`, so it is never EXECUTED here - the
 * run stops before it, and the routine supplies the result. A RIP-relative
 * data reference is also a hole, and one in the span between two sites sends
 * a load or a store to the wrong address; the run faults, the span yields
 * nothing, and nothing wrong is reported. Diamorphine's give_root has no such
 * reference between its two calls. Its init_module does - `mov %rax,.bss+0x3c`
 * - and that span is one this cannot read yet.
 */
/*
 * ---- APPLYING THE RELOCATIONS ---------------------------------------------
 *
 * Without this every pointer the module loads is the hole the linker was
 * supposed to fill, so two calls handed the same object both receive zero and
 * nothing can tell they were handed the same thing. It is the single reason
 * the kprobe pair, list_del's THIS_MODULE and the syscall table reads were
 * all invisible.
 *
 * ONLY THE FOUR THAT PLACE AN ADDRESS, and only for a symbol this object
 * defines. PLT32 is a call, which this routine steps over rather than takes;
 * an undefined symbol is a promise to the loader and there is nothing here to
 * point at, so its hole is left as a hole and the span that needs it ends
 * quietly.
 *
 * THE PATCH GOES INTO THE EMULATOR'S MEMORY, not into the caller's file. The
 * object on disk is evidence and is never written to - see the note in
 * CLAUDE.md on scans that repair in place.
 */
struct relapply { struct kof_emu *em; uint64_t size; };

static void apply_reloc(void *user, uint64_t where, uint32_t type,
			uint64_t sym, int defined, int64_t addend)
{
	struct relapply *a = user;
	uint64_t p = DIAG_REL_BASE + where;
	uint64_t s = DIAG_REL_BASE + sym;
	uint8_t b[8];
	unsigned n = 0, i;
	uint64_t v = 0;

	if (!defined || where + 4u > a->size)
		return;
	switch (type) {
	case 1u:                                /* R_X86_64_64   S + A      */
		v = s + (uint64_t)addend; n = 8u; break;
	case 2u:                                /* R_X86_64_PC32 S + A - P  */
		v = s + (uint64_t)addend - p; n = 4u; break;
	case 10u:                               /* R_X86_64_32   S + A      */
	case 11u:                               /* R_X86_64_32S  S + A      */
		v = s + (uint64_t)addend; n = 4u; break;
	default:
		return;
	}
	if (where + n > a->size)
		return;
	for (i = 0; i < n; i++)
		b[i] = (uint8_t)(v >> (8u * i));
	kof_emu_write(a->em, p, b, n);
}

static struct kof_emu *build_rel_image(const struct kof_obj_ctx *ctx,
				       const struct kof_elf_info *ei,
				       const uint8_t *base, uint64_t size)
{
	struct kof_emu_cfg cfg;
	struct kof_emu *em;

	memset(&cfg, 0, sizeof cfg);
	cfg.max_insn = DIAG_EMU_INSN;
	cfg.max_pages = DIAG_EMU_PAGES;
	cfg.bits = ctx->arch == KOF_ARCH_X86_64 ? 64u : 32u;
	em = kof_emu_new(&cfg);
	if (!em)
		return 0;

	/*
	 * THE WHOLE FILE AS ONE REGION, AT ZERO.
	 *
	 * NOT SECTION BY SECTION, which was the first attempt and mapped
	 * nothing: a section's file offset is aligned to eight or sixteen
	 * bytes, never to a page, and a mapping has to start on one. Every
	 * call failed, the image came back empty, and the routine returned
	 * without a word - the symptom was that gap emulation added exactly
	 * zero links and looked like it had simply found nothing.
	 *
	 * Mapping the file whole is also the honest shape. The address space
	 * of a relocatable object IS its file - sh_addr is zero, the
	 * relocation table reports file offsets, and kdis_off_to_va makes the
	 * same identity. One region keeps all three agreeing, and a section
	 * table that disagrees with itself cannot send a step somewhere the
	 * file does not reach.
	 *
	 * THE SLACK IS FOR .bss, which holds no bytes in the file and is
	 * written to all the same.
	 *
	 * AND IT IS NOT AT ZERO. The identity the file enjoys is with OFFSETS,
	 * and offset zero is the null page - a mapping there is refused, which
	 * is right and was the second thing to make the image come back empty.
	 * The region sits at DIAG_REL_BASE and this routine adds it on the way
	 * in and takes it off on the way out; nothing outside sees the bias.
	 */
	if (!kof_emu_map(em, DIAG_REL_BASE, base, size,
			 (size + DIAG_REL_SLACK + KOF_EMU_PAGE - 1u) &
			 ~(uint64_t)(KOF_EMU_PAGE - 1u),
			 KOF_EMU_R | KOF_EMU_W | KOF_EMU_X)) {
		kof_emu_free(em);
		return 0;
	}

	/*
	 * AND AN ARENA FOR THE TOKENS, because a token is dereferenced.
	 *
	 * prepare_creds hands back a struct the caller then WRITES into -
	 * `movq $0x0,0x8(%rax)`, four times, zeroing the uid and gid fields.
	 * A token that is merely a distinctive number is an unmapped address
	 * the moment that happens, and the span dies three instructions in.
	 * MEASURED: every gap faulted at step 3 or 4 until this was here.
	 *
	 * ONE PAGE PER PRODUCER, so a value can be attributed to the call it
	 * came from, and so that a program adding a field offset to it stays
	 * inside that page and stays attributable.
	 */
	if (!kof_emu_map(em, DIAG_TOK_BASE, 0, 0,
			 DIAG_TOK_SPAN * KOF_EMU_PAGE,
			 KOF_EMU_R | KOF_EMU_W)) {
		kof_emu_free(em);
		return 0;
	}

	/* A stack, high and away from anything the file occupies. */
	if (!kof_emu_map(em, DIAG_REL_STACK - 0x10000u, 0, 0, 0x10000u,
			 KOF_EMU_R | KOF_EMU_W)) {
		kof_emu_free(em);
		return 0;
	}
	kof_emu_set_reg(em, KOF_EMU_RSP, DIAG_REL_STACK - 0x8000u);
	kof_emu_set_reg(em, KOF_EMU_RBP, DIAG_REL_STACK - 0x8000u);

	/*
	 * AND SOMEWHERE FOR %gs TO POINT, which kernel code reads in its
	 * third instruction.
	 *
	 * Every function compiled with the stack protector begins
	 * `mov %gs:0x0(%rip),%rdi`, and the per-cpu area lives there too.
	 * With the base left at zero that is a read of address zero and the
	 * span dies before it has done anything - MEASURED, Diamorphine's
	 * init_module got three instructions in, 157 bytes short of the
	 * `mov cr0` the walk had been opened for.
	 *
	 * The page is scratch and its contents are not read as the program's:
	 * what comes back is a guard value the code only ever compares
	 * against itself.
	 */
	if (kof_emu_map(em, DIAG_REL_PERCPU, 0, 0, KOF_EMU_PAGE * 16u,
			KOF_EMU_R | KOF_EMU_W))
		kof_emu_set_seg_base(em, 5u, DIAG_REL_PERCPU);

	{
		struct relapply ra;
		kof_buf f;

		f.p = base;
		f.n = size;
		ra.em = em;
		ra.size = size;
		kof_elf_relocs(f, ei, apply_reloc, &ra);
	}
	return em;
}


/*
 * ---- THE GAP BETWEEN TWO KNOWN SITES, FOR A KERNEL MODULE ---------------
 *
 * EVERYTHING THE SYMBOL ROUTINE ALREADY FOUND IS THE INPUT. It read the
 * relocation table and put a node at every call to an import, at a file
 * offset, without decoding anything. What it could not answer is which value
 * reached which call once the value went through memory - and that is the
 * only question asked here.
 *
 * SO NOTHING RUNS FROM THE TOP. There is no init_module to execute, no
 * runtime, no loader. One span at a time: start where a producing call
 * returns, with its result replaced by a token nothing else can hold, and
 * single-step until control reaches another site. A token in an argument
 * register there is a link, and one the span demonstrated rather than one a
 * model asserted.
 *
 * SINGLE-STEPPING AND NOT A WATCH, because a watch matches BYTES and the
 * thing being waited for is an ADDRESS. Listing the encodings of call would
 * be a list of the forms we happen to know; stepping knows none. The spans
 * are tens of instructions, so the cost of stepping them is not a question.
 *
 * AND AN UNLINKED CALL IS HARMLESS TO EXECUTE. Its displacement is a hole, so
 * `e8 00 00 00 00` pushes a return address and falls through to the next
 * instruction - which is exactly the address the relocation table reports as
 * the site. The run never jumps into an unresolved import, and the argument
 * registers are intact when it arrives.
 */
#define DIAG_REL_STEPS 4096u

/*
 * HOW OFTEN ONE BACKWARD BRANCH MAY BE TAKEN before the run is made to leave
 * the loop. Two full passes: the first covers every site in the body, the
 * second lets a value that is carried between iterations settle. A third
 * cannot produce a node that is not already there, because a node is a site.
 */
#define DIAG_REL_SPINS 2u

/*
 * HOW MANY FAULTS ON SYNTHETIC MEMORY ONE SPAN MAY STEP OVER. A DoS bound and
 * nothing else: a span faulting on every other instruction is not being
 * walked, it is being guessed at, and it should end.
 */
#define DIAG_REL_FAULTS 32u

/*
 * ---- WHEN THE RUN IS MOVED ON, AND WHY IT IS NOT RUN AGAIN --------------
 *
 * THIS ROUTINE DOES NOT EXECUTE THE PROGRAM. It resolves whether the value a
 * known node produced is the value another known node receives, and the only
 * reason it steps instructions at all is that the arithmetic in between -
 * a move, an add, a spill and reload - is easier to RUN than to model. The
 * sites themselves are not discovered by running: the relocation table names
 * every one of them before a single instruction is stepped.
 *
 * SO CONTROL FLOW IS NAVIGATION, NOT EVIDENCE. A loop adds nothing after its
 * first pass, and a conditional branch out of the function leads nowhere this
 * span can use - both are obstacles between one site and the next, and the
 * run exists to step AROUND them.
 *
 * WHEN THE RUN STALLS - it leaves the function, faults on memory that was
 * stated rather than read, or spends its budget - the span MOVES TO THE NEXT
 * SITE and carries on. One pass, each site seated at most once.
 *
 * AND NOT BY RUNNING THE SPAN AGAIN. That was tried and it was the wrong
 * shape: six runs of one function, each following a different arbitrary path,
 * to collect what one pass over the known sites collects directly. It cost
 * 3.5x on 900 kernel modules and it is the thing this design exists to avoid.
 *
 * WHAT IT ASSUMES, SAID PLAINLY: after a re-seat the registers are the ones
 * the previous stretch left. That is a claim about DATA, not about a path -
 * the same claim the whole routine makes when it states a skipped call's
 * result - and a link is still only recorded when a register actually holds
 * a token some node produced.
 */
#define DIAG_REL_SEATS 64u

/*
 * HOW MANY INSTRUCTIONS ONE GAP MAY TAKE.
 *
 * THE BUDGET BELONGS TO THE GAP, NOT TO THE SPAN. A span-wide budget is spent
 * by whichever stretch is slowest, and everything after it is never looked at
 * - MEASURED: diamondxe's filtering loop used all 4096 instructions and its
 * copy_to_user, a site the relocation table had named before the run started,
 * was never once seated. The symptom is indistinguishable from "that call has
 * no link", which is the worst shape a fault can have.
 *
 * A gap is a stretch between two calls. 512 is far past any of them: the
 * longest in either Diamorphine build is under 80 instructions, and a stretch
 * that needs more than 512 is looping, which is the thing to step around.
 */
#define DIAG_REL_GAP 512u

/* How far into an object a displacement may reach and still be a field of
 * it. A struct kprobe is 0x58 bytes; nothing this routine looks at is near
 * a page. A bound on what counts as one object, not on results. */
#define DIAG_OBJ_SPAN 0x200u
#define DIAG_REL_TOKEN 0x5A6E0000DEAD0000ull

/*
 * EVERY CALL IN THE SPAN IS SKIPPED, AND ITS RESULT IS SUPPLIED.
 *
 * Not executed. The span exists to answer "does the value this call produced
 * reach that call", and what the callee does on the way is not part of the
 * question:
 *
 *   AN INTERNAL CALL WOULD BE EXECUTED FOR REAL. Its displacement is not a
 *   hole, so stepping it jumps into the callee and runs code that has nothing
 *   to do with the relation being asked about - at best a detour, at worst a
 *   fault that ends the span.
 *   AN IMPORTED CALL CANNOT BE EXECUTED AT ALL. prepare_creds is not in the
 *   file; there is nothing at the other end. Its displacement is a hole, so
 *   stepping it merely falls through - and leaves the result register holding
 *   whatever was there, which is the one thing the span needs to be right.
 *
 * WHERE THE CALL INSTRUCTION IS, WITHOUT GUESSING AT OPCODES. The relocation
 * sits on the displacement, which the parser reports as `at` = r_offset + 4;
 * the four displacement bytes are the last four of the instruction, so it
 * begins at `at` - 5. That is read off the relocation, not off a list of
 * encodings we happen to know.
 */
#define DIAG_REL_CALLLEN 5u

struct skipsite {
	uint64_t call_at;       /* where the call instruction begins */
	uint64_t resume;        /* and where control continues       */
	uint64_t callee;        /* an INTERNAL call's target, else 0 */
	uint16_t cap;           /* KOF_NUCLEO_NONE for an internal call */
};

struct skipgather {
	struct skipsite *site;
	uint32_t         n, cap_n;
};

static void gather_skip(void *user, uint64_t at, uint64_t target,
			const char *name)
{
	struct skipgather *g = user;

	if (g->n >= g->cap_n || at < DIAG_REL_CALLLEN)
		return;
	g->site[g->n].call_at = at - DIAG_REL_CALLLEN;
	g->site[g->n].resume = at;
	g->site[g->n].callee = target;
	/* An internal call names a capability only by accident; it is here to
	 * be skipped, not to be a node. */
	g->site[g->n].cap = target ? KOF_NUCLEO_NONE
				   : (name ? kof_flow_cap_of_name(name)
					   : KOF_NUCLEO_NONE);
	g->n++;
}

#define DIAG_REL_SKIPS 1024u
#define DIAG_REL_FUNCS 512u

struct funcspan { uint64_t va, size; };
struct funcgather { struct funcspan *fn; uint32_t n, cap_n; };

static void gather_fn(void *user, uint64_t va, uint64_t sz, const char *nm)
{
	struct funcgather *g = user;

	(void)nm;
	if (!sz || g->n >= g->cap_n)
		return;
	g->fn[g->n].va = va;
	g->fn[g->n].size = sz;
	g->n++;
}

/*
 * IS THIS VALUE AN OBJECT THIS MODULE OWNS.
 *
 * Only an address inside the mapped image or the token arena is remembered.
 * Zero, a small integer, a length and a stack address are passed by half the
 * calls in any program; remembering one would relate every call that happened
 * to use it, which is not a relation but a coincidence.
 */
static int worth_remembering(uint64_t v, uint64_t size)
{
	/*
	 * AN ANONYMOUS TOKEN COUNTS, BUT ONLY INSIDE ITS OWN SPAN.
	 *
	 * It stands for a call nothing here explains - kzalloc, say - and two
	 * calls in the same function receiving it ARE holding one object:
	 * copy_from_user(buf, ubuf, n) then copy_to_user(ubuf, buf, n) is the
	 * hooked getdents, and the buffer is exactly such a token.
	 *
	 * ACROSS SPANS IT IS MEANINGLESS. The pages are handed out from the
	 * top of the arena downwards starting fresh each time, so the first
	 * anonymous page of one function is the same address as the first of
	 * the next. MEASURED when the table was made to persist:
	 * hacked_getdents' buffer linked to hacked_getdents64's, two
	 * unrelated buffers in two unrelated functions, and the spurious
	 * matches pushed real links out of the four slots a node has.
	 *
	 * The table is per span, which is what keeps this sound. Anything
	 * that wants to relate two FUNCTIONS has to rest on a fixed address -
	 * a relocation - and that is known without running at all.
	 */
	if (v >= DIAG_TOK_BASE &&
	    v < DIAG_TOK_BASE + (uint64_t)DIAG_TOK_SPAN * KOF_EMU_PAGE)
		return 1;
	return v > DIAG_REL_BASE &&
	       v < DIAG_REL_BASE + size + DIAG_REL_SLACK;
}

/*
 * ONE SPAN PER FUNCTION, AND EVERY SITE IN IT IS OBSERVED.
 *
 * The first shape ran a span per PRODUCER - a call that hands a value back -
 * and could therefore only ever find relations of the form "B consumed what A
 * produced". MEASURED on Diamorphine: of fourteen nodes exactly one is a
 * producer, so two spans ran and two links came out, and the rest of the
 * module's relations were not missed so much as never asked about.
 *
 * THE OTHER RELATION IS A SHARED ARGUMENT. register_kprobe and
 * unregister_kprobe are one idiom because they are handed THE SAME struct
 * kprobe - an address in .bss, not a value either of them produced. Nothing
 * in a provenance model expresses that, and it is the relation that makes the
 * pair evidence rather than two unrelated calls.
 *
 * So a run covers a FUNCTION, which is the scope an address means anything
 * in, and at every call site it reads the arguments and asks two questions of
 * each: is this a value an earlier site produced, and is it a value an
 * earlier site was also given. Both are links; the first is provenance and
 * the second is identity.
 *
 * WHAT MAY BE REMEMBERED is bounded on purpose. Only a value inside the
 * mapped image or the token arena - an object this module owns. Zero, a small
 * integer and a stack address are shared by half the calls in any program and
 * remembering them would relate everything to everything.
 */
#define DIAG_REL_SEEN 64u
/*
 * HOW MANY TIMES THE SPANS ARE RUN.
 *
 * A caller analysed before its callee learns what that callee returns on the
 * following pass, so the number bounds how deep a chain of helpers can be
 * followed - four covers resolve_sym inside findmyinterest inside
 * init_module with one to spare. It stops early when a pass changes nothing,
 * which is the usual case after two.
 */
#define DIAG_REL_PASSES 4u

/*
 * A VALUE, THE NODE IT BELONGS TO, AND WHICH OF TWO RELATIONS THAT IS.
 *
 * They are not the same relation and one table recorded them as if they
 * were:
 *
 *   PRODUCED  the node RETURNED this value. kzalloc hands back the buffer;
 *             prepare_creds hands back the credentials. A later call holding
 *             it is holding what this call made - that is provenance, and it
 *             is what a link means.
 *   RECEIVED  the node was HANDED this value and made nothing. Both halves
 *             of the kprobe pair are given the same struct kprobe; neither
 *             produced it. Two receivers share an object, which is a real
 *             relation and a different one.
 *
 * WITH ONE FLAG FOR BOTH, a value that was produced once and received twice
 * put three nodes in the table and a later argument linked to all of them -
 * so copy_to_user, which has exactly one source, came back with two parents
 * both wearing `source`. Overwriting the earlier entry made the output
 * tidy and the answer wrong: it recorded copy_from_user as the producer of
 * a buffer kzalloc had produced.
 *
 * So the kind is kept, and a link prefers the producer. Where there is none -
 * the kprobe struct, which is a module global nobody returned - the earliest
 * receiver stands for the object, which is what makes the pair one idiom.
 */
struct seenval {
	uint64_t val;
	uint16_t node;
	uint8_t  produced;
};

/*
 * A CALLEE THIS MODULE DEFINES: PART OF THIS CHAIN, OR A FUNCTION OF ITS OWN.
 *
 * An internal call is stepped over like any other, and the question is what
 * its result should then be. Two answers and the difference matters:
 *
 *   IT CARRIES A CAPABILITY. The callee contains nodes - it resolves a
 *   symbol, it allocates, it opens something - so what it hands back is an
 *   object this chain produced, and a later site holding that object is
 *   linked to it. Diamorphine's findmyinterest is the case: the kprobe pair
 *   lives inside it and the syscall table address comes out of it.
 *   IT CARRIES NONE. Then it is an independent function. Its result relates
 *   to nothing here, the register is left undefined, and the function is
 *   examined on its own turn - every function gets one.
 *
 * WHICH NODE REPRESENTS THE CALLEE - MEASURED, NOT ASSUMED.
 *
 * The first answer was "a function with exactly one node inside it is a
 * wrapper for that node". True, and too narrow: it requires knowing which
 * functions are wrappers before looking, and a helper that does two things
 * and returns one of them -
 *
 *     int get_sock(void) { int s = socket(); connect(s, ..); return s; }
 *
 * - has two nodes, so it is refused, so the caller loses the descriptor and
 * every relation downstream of it. A function nobody steps into is invisible,
 * and what it hands back vanishes with it.
 *
 * SO THE ANSWER IS TAKEN FROM THE RUN. Each function's span already carries
 * tokens; whichever token is in the result register when the span ends is
 * what that function returns, and that is a measurement. The spans are run
 * repeatedly until the answers stop changing - a caller analysed before its
 * callee simply learns nothing that pass and learns it on the next, which is
 * a topological order without having to build one.
 *
 * `ret_node` below is that table. `callee_node` remains for the first pass,
 * where nothing has been measured yet.
 *
 * ---- THE OLD RULE, KEPT FOR THE FIRST PASS ---------------------------------
 *
 * A link needs a node index and a callee is not a node, so something has to
 * stand for it. Taking the first node inside was the first answer and it is
 * a CHOICE rather than a fact: in a function that does several things the
 * first node is whichever the compiler laid out first, and attributing the
 * return value to it invents a relation.
 *
 * EXACTLY ONE NODE IS THE CASE WHERE IT IS NOT A CHOICE. A function whose
 * whole capability is one call is a wrapper for that call, and its result IS
 * that call's result - resolve_sym around the kprobe idiom is the shape, and
 * it is the shape a kernel module uses constantly. With two or more there is
 * no honest representative, so the register is left undefined and the callee
 * is examined on its own turn, where its nodes relate to each other properly.
 *
 * This is the same wrapper that defeats the static model from the other side
 * - there the node is libc's wrapper and the caller is invisible; here the
 * caller is in hand and the wrapper is what makes the attribution sound.
 */
static uint16_t callee_node(const struct kof_diag_scan *s,
			    const struct funcspan *fns, uint32_t n_fn,
			    uint64_t callee)
{
	uint32_t j, i, n = kof_diag_scan_count(s);

	for (j = 0; j < n_fn; j++) {
		uint16_t only = 0xffffu;
		uint32_t cnt = 0;

		if (fns[j].va != callee)
			continue;
		for (i = 0; i < n; i++) {
			const struct kof_diag_hit *p = kof_diag_scan_at(s, i);

			if (!p || p->at < fns[j].va ||
			    p->at >= fns[j].va + fns[j].size)
				continue;
			/* A promoted wrapper IS the function - see
			 * promote_wrappers - so it answers for it however
			 * many nodes are inside. */
			if (p->at == fns[j].va &&
			    p->cap == KOF_NUCLEO_KSYM_LOOKUP)
				return (uint16_t)i;
			only = (uint16_t)i;
			cnt++;
		}
		return cnt == 1u ? only : 0xffffu;
	}
	return 0xffffu;
}

/*
 * DOES THIS FUNCTION CONTAIN A CONTROL-REGISTER WRITE.
 *
 * The node count alone is the wrong gate, and it threw away the one function
 * that mattered: Diamorphine's init_module calls no import this vocabulary
 * has a word for, so it held zero nodes and was refused - while containing
 * the `mov cr0` that is the centre of the rootkit. A bound on cost must not
 * delete evidence.
 *
 * BYTES TO DECIDE WHETHER TO LOOK, THE DECODER TO DECIDE WHAT IT IS. `0f 22`
 * in a displacement answers yes and costs one walk; an instruction that is
 * not in the bytes cannot be decoded out of them. The same over-approximation
 * the syscall routine uses for `0f 05`, for the same reason.
 */
static int has_cr_write(const uint8_t *p, uint64_t n)
{
	uint64_t i;

	for (i = 0; i + 1u < n; i++)
		if (p[i] == 0x0fu && p[i + 1u] == 0x22u)
			return 1;
	return 0;
}

/*
 * ---- A FUNCTION THAT IS ONE ACT BECOMES ONE NODE ------------------------
 *
 * findmyinterest is three calls - register_kprobe, an indirect call, and
 * unregister_kprobe - and it is not three acts. It is ONE: resolve a name to
 * an address. The module calls it the way it would call a syscall, and its
 * caller cares about the address that comes back and nothing else.
 *
 * THE INDIRECT CALL IN THE MIDDLE IS NOT LINKED TO THE OTHER TWO, and must
 * not be. Its target was decided wherever the pointer was stored, not by
 * either probe call; what relates the three is that they are IN ONE
 * FUNCTION, which is co-location and not provenance. Forcing a link there
 * would be asserting a derivation the program does not have.
 *
 * SO THE SHAPE IS RECOGNISED, NOT FOLLOWED. A function whose capability
 * nodes are exactly the probe pair - put one on, take it off - is a symbol
 * lookup whatever happens between them, because that is the only reason to
 * do it. The node is emitted at the function's own offset, and callers then
 * see one act with a word, the same way they would see dup2.
 *
 * WHY IT MATTERS BEYOND THE NAME: a caller's `table = findmyinterest()` is
 * the start of the hook chain, and until the callee had a capability its
 * result was an anonymous token - a value belonging to no node, which no
 * link can end at. One node here gives the whole chain somewhere to begin.
 */
static void promote_wrappers(struct kof_diag_scan *s,
			     const struct funcspan *fns, uint32_t n_fn)
{
	uint32_t i, n = kof_diag_scan_count(s);

	/*
	 * ---- THE HOOK-DECLARATION BLOCK IS FOUND FIRST, AND AS A BLOCK ----
	 *
	 * Since 5.7 the kernel stopped exporting kallsyms_lookup_name, and the
	 * way round it is to register a kprobe on the name, read kp.addr and
	 * unregister. That PAIR is the lookup. It is one act, and until it is
	 * recognised as one the analysis is looking at two unrelated calls
	 * with an address appearing between them for no reason - the read of
	 * kp.addr links to NEITHER of them, because nothing in the kernel's
	 * symbol design connects them by a value.
	 *
	 * IT IS A BLOCK, NOT A FUNCTION. This used to require that the
	 * function contain the pair AND NOTHING ELSE, which only catches an
	 * author who wrote a tidy little wrapper. What identifies it is the
	 * ORDER - a register, then an unregister, with no other capability
	 * between them - and that holds wherever the two sit.
	 *
	 * AND IT IS DONE BEFORE ANY SPAN RUNS, so that when a caller is
	 * walked, the call into this function is already known to hand back a
	 * resolved symbol rather than being one more opaque call.
	 */
	for (i = 0; i < n; i++) {
		const struct kof_diag_hit *p = kof_diag_scan_at(s, i);
		uint32_t t, j;
		uint64_t reg_at, unreg_at = 0;
		int paired = 0;

		if (!p || p->cap != KOF_NUCLEO_KPROBE_REG)
			continue;
		reg_at = p->at;

		/*
		 * THE NEAREST UNREGISTER AFTER IT, and WHATEVER LIES BETWEEN.
		 *
		 * Requiring nothing in between was wrong and it was wrong in
		 * the obvious way: the thing between them is the POINT - the
		 * read of kp.addr, which is the resolved symbol the whole
		 * manoeuvre exists to get. Author code puts more there too.
		 * What identifies the block is the pair, not the gap being
		 * empty.
		 */
		for (t = 0; t < n; t++) {
			const struct kof_diag_hit *q = kof_diag_scan_at(s, t);

			if (!q || q->at <= reg_at ||
			    q->cap != KOF_NUCLEO_KPROBE_UNREG)
				continue;
			if (!unreg_at || q->at < unreg_at) {
				unreg_at = q->at;
				paired = 1;
			}
		}
		if (!paired)
			continue;

		/*
		 * THE NODE GOES AT THE FUNCTION THAT HOLDS THE BLOCK, because
		 * that is the address a caller's `call` names - which is what
		 * lets the caller be told it is getting a resolved symbol.
		 * With no function covering it, the block stands where the
		 * register does.
		 */
		for (j = 0; j < n_fn; j++)
			if (reg_at >= fns[j].va &&
			    unreg_at < fns[j].va + fns[j].size)
				break;
		kof_diag_hit_add(s, j < n_fn ? fns[j].va : reg_at,
				 KOF_NUCLEO_KSYM_LOOKUP, 0);
	}
}


/*
 * IS THERE A PRINTABLE, NUL-TERMINATED NAME AT THIS OFFSET.
 *
 * A symbol name, not a string in general: short, printable, and ending. The
 * bound is what the kernel's own symbol table allows, and the floor keeps a
 * stray byte that happens to be followed by a NUL from being read as a name.
 */
#define DIAG_NAME_MIN 3u
#define DIAG_NAME_MAX 64u

static int name_at(const uint8_t *base, uint64_t size, uint64_t off)
{
	uint64_t i;

	if (off >= size)
		return 0;
	for (i = 0; i < DIAG_NAME_MAX && off + i < size; i++) {
		uint8_t c = base[off + i];

		if (!c)
			return i >= DIAG_NAME_MIN;
		/*
		 * A SYMBOL NAME, NOT ANY PRINTABLE RUN. Accepting every
		 * printable byte caught a compiler version string -
		 * ".2.0-19) 14.2.0" - on a clean module, because a register
		 * happened to point at it. A C identifier is letters, digits
		 * and underscore; the dot and dollar are there because the
		 * kernel and the linker both use them in real names, and a
		 * space or a bracket ends it.
		 */
		if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		      (c >= '0' && c <= '9') || c == '_' || c == '.' ||
		      c == '$'))
			return 0;
	}
	return 0;
}

/*
 * WHAT A STORE PUT THERE, when the instruction carries it - see
 * KOF_DIAG_H_VAL.
 *
 * ONE PLACE, because three branches below make a field node - a
 * RIP-relative object, a base register holding one, and the token region -
 * and a value recorded at two of the three is a diagnose that matches on
 * some builds of the same program.
 *
 * `mi` is the operand that is the memory: 0 for a store, and only a store
 * writes anything. The source has to be an IMMEDIATE; a register source is
 * a value the model may have lost, and a lost value reads as zero.
 */
static void field_value(struct kof_diag_hit *fh, const struct kdis_insn *ci,
			unsigned mi)
{
	if (!fh || mi != 0u || ci->n_op < 2u || ci->o[1].kind != KDIS_O_IMM)
		return;
	fh->val = ci->o[1].imm;
	fh->bits |= KOF_DIAG_H_VAL;
}

static void run_rel_gaps(struct kof_diag_scan *s,
			 const struct kof_obj_ctx *ctx,
			 const struct kof_elf_info *ei,
			 const uint8_t *base, uint64_t size)
{
	static struct skipsite skips[DIAG_REL_SKIPS];
	static struct funcspan fns[DIAG_REL_FUNCS];
	static uint16_t ret[DIAG_REL_FUNCS];
	static uint8_t dirty[DIAG_REL_FUNCS], next_dirty[DIAG_REL_FUNCS];
	struct skipgather sg;
	struct funcgather fg;
	kof_buf f;
	uint32_t n = kof_diag_scan_count(s), q, j, pass;

	if (ctx->arch != KOF_ARCH_X86_64 || !n)
		return;

	f.p = base;
	f.n = size;
	memset(&sg, 0, sizeof sg);
	sg.site = skips;
	sg.cap_n = DIAG_REL_SKIPS;
	kof_elf_relcalls(f, ei, gather_skip, &sg);
	memset(&fg, 0, sizeof fg);
	fg.fn = fns;
	fg.cap_n = DIAG_REL_FUNCS;
	kof_elf_funcs(f, ei, gather_fn, &fg);
	if (!sg.n || !fg.n)
		return;
	promote_wrappers(s, fns, fg.n);
	for (j = 0; j < fg.n; j++)
		ret[j] = 0xffffu;

	for (j = 0; j < fg.n; j++)
		dirty[j] = 1;           /* the first pass walks everything */

	for (pass = 0; pass < DIAG_REL_PASSES; pass++) {
	int changed = 0;

	for (j = 0; j < fg.n; j++) {
		/*
		 * RESET AT EVERY FUNCTION, and this was tried the other way.
		 *
		 * An address looks like it should survive the function it was
		 * seen in - module_hide and module_show hand the same
		 * THIS_MODULE->list to list_del and list_add, and that
		 * relation is real. But each span BUILDS ITS OWN IMAGE, so a
		 * local in one function lands at the same emulated address as
		 * an unrelated local in the next. MEASURED: hacked_getdents'
		 * buffer linked to hacked_getdents64's, two different
		 * functions and two different buffers, and the spurious
		 * matches pushed the kprobe pairs out of the four slots a
		 * node has.
		 *
		 * A relation between functions is real only for an object
		 * with a fixed address, and a fixed address is a RELOCATION -
		 * known without running anything. That is where list_del and
		 * list_add belong, not here.
		 */
		/*
		 * ---- A LATER PASS WALKS ONLY WHAT COULD HAVE MOVED -------
		 *
		 * The passes exist so that a caller learns what an internal
		 * call returns, which is only known once the callee has been
		 * walked. If no callee of this function reported anything new,
		 * walking it again cannot produce anything new either.
		 *
		 * MEASURED: a second pass over EVERYTHING produced exactly the
		 * same 19327 nodes and 488 chains on 900 clean kernel modules
		 * and on both Diamorphine builds - it was a confirmation pass
		 * that cost a complete re-run.
		 */
		if (!dirty[j])
			continue;

		struct seenval seen[DIAG_REL_SEEN];
		struct kof_emu *em;
		uint32_t n_seen = 0, step, anon = DIAG_TOK_SPAN - 1u;
		uint64_t n_fd = 0;
		/* Which sites this span has already been seated at, so one
		 * pass cannot circle. */
		static uint8_t vis[DIAG_REL_SKIPS];
		uint32_t n_seat = 0, gap_steps = 0;
		uint64_t run_lo, run_hi;
		uint64_t last_in;
		/* Which backward branches this span has arrived at, and how
		 * often. Per span: a loop in one function says nothing about
		 * a loop in the next. */
		struct { uint64_t at; uint32_t n; } latch[32];
		uint32_t n_latch = 0, n_fault = 0;
		uint64_t lo = fns[j].va, hi;

		if (lo >= size)
			continue;
		hi = lo + fns[j].size;

		/*
		 * A FUNCTION WITH FEWER THAN TWO NODES IN IT CANNOT HOLD A
		 * LINK, so it is not run.
		 *
		 * EXACT, not a heuristic: a link relates two nodes, and both
		 * ends have to be inside the scope a register means anything
		 * in. The site table already says where every node is, so the
		 * check costs a comparison per site.
		 *
		 * AND IT IS WHAT KEEPS THIS SURVIVABLE ON A BLOATED BINARY,
		 * which is the reason it matters rather than a saving. A
		 * module written in C has tens of functions; a Go program has
		 * thousands, almost all of them runtime, and a routine that
		 * built an image and stepped a span for each would not finish.
		 * The gate is what makes the cost proportional to the number
		 * of NODES rather than to the number of functions - which is
		 * the only quantity the analysis is actually about.
		 *
		 * MEASURED: diamorphine.ko 7 of 13 functions run, diamondxe.ko
		 * 8 of 32. The rejected ones are the hooked syscall bodies and
		 * the helpers, holding one node or none.
		 */
		{
			uint32_t in_fn = 0, t;

			for (t = 0; t < n; t++) {
				const struct kof_diag_hit *p =
					kof_diag_scan_at(s, t);

				if (p && p->at >= lo && p->at < hi)
					in_fn++;
			}
			/*
			 * AND A FUNCTION WITH ONE NODE STILL COUNTS IF IT
			 * CALLS ONE THAT HAS THEM. init_module holds few
			 * nodes of its own and calls findmyinterest, which
			 * holds the kprobe pair - the chain crosses the
			 * boundary and a check that only counted nodes
			 * inside would refuse to walk it.
			 */
			if (in_fn < 2u) {
				uint32_t w, reach = in_fn;

				for (w = 0; w < sg.n; w++) {
					if (skips[w].call_at < lo ||
					    skips[w].call_at >= hi)
						continue;
					if (skips[w].cap != KOF_NUCLEO_NONE ||
					    (skips[w].callee &&
					     callee_node(s, fns, fg.n,
							 skips[w].callee) !=
					     0xffffu))
						reach++;
				}
				/* AND A FUNCTION THAT TOUCHES cr0 IS WALKED
				 * WHATEVER ELSE IS IN IT - see has_cr_write. */
				if (reach < 2u &&
				    !(hi <= size &&
				      has_cr_write(base + lo, hi - lo)))
					continue;
			}
		}

		memset(vis, 0, sizeof vis);

		/*
		 * ---- CAN THIS FUNCTION CARRY A LINK AT ALL -----------------
		 *
		 * Answered before a single instruction is stepped, from the
		 * site list the relocation table already gave us. It is a
		 * precondition, not a budget: if it holds, the WHOLE function
		 * is walked.
		 *
		 *   a site that HANDS SOMETHING ON, or
		 *   two sites that TAKE AN ARGUMENT - a shared relation has no
		 *   producer at all; both halves of a kprobe pair are merely
		 *   handed the same struct.
		 *
		 * With neither, nothing in this function can be linked to
		 * anything: a field access needs a token in a register, and a
		 * token only exists because some call produced one.
		 *
		 * AND THE STRETCH IS NOT CUT SHORT. Trimming it at the last
		 * CALL site was tried and it deleted evidence - 405 chains on
		 * 900 clean modules, nearly all of them
		 * `mem-alloc-heap -> mem-field-write`. A token can be
		 * dereferenced anywhere after it is produced, field accesses
		 * are not in the relocation table, and so there is no sound
		 * place to stop early. Cost belongs to the loop bounds below,
		 * not to a gate on how much of the function is looked at.
		 */
		{
			uint32_t t, takers = 0;
			int producer = 0;

			for (t = 0; t < sg.n; t++) {
				uint64_t a = skips[t].call_at;
				unsigned k;

				if (a < lo || a >= hi)
					continue;
				if (kof_diag_sym_hands_on(skips[t].cap) ||
				    (skips[t].callee &&
				     callee_node(s, fns, fg.n,
						 skips[t].callee) != 0xffffu))
					producer = 1;
				for (k = 0; k < 6u; k++)
					if (kof_diag_role_of_arg(skips[t].cap, k)
					    != KOF_DIAG_ROLE_NONE) {
						takers++;
						break;
					}
			}
			if (!producer && takers < 2u &&
			    !(hi <= size && has_cr_write(base + lo, hi - lo)))
				continue;
			run_lo = lo;
			run_hi = hi;
		}

		em = build_rel_image(ctx, ei, base, size);
		if (!em)
			return;
		kof_emu_set_rip(em, DIAG_REL_BASE + run_lo);
		last_in = run_lo;

		for (step = 0; step < DIAG_REL_STEPS; step++) {
			uint64_t rip = kof_emu_get_rip(em) - DIAG_REL_BASE;
			enum kof_emu_stop st;
			int skipped = 0, ended = 0;

			if (rip < run_lo || rip >= run_hi)
				goto stalled;   /* left the stretch */
			/*
			 * AND A GAP THAT WILL NOT FINISH IS ONE TO STEP
			 * AROUND - see DIAG_REL_GAP. Spinning here is not a
			 * finding, and the sites after it are still listed.
			 */
			if (gap_steps++ > DIAG_REL_GAP)
				goto stalled;
			last_in = rip;

			for (q = 0; q < sg.n; q++) {
				uint16_t node = 0xffffu;
				unsigned k, i;

				if (skips[q].call_at != rip)
					continue;
				vis[q] = 1;
				/*
				 * ---- THE NAME THIS CALL WAS GIVEN ---------
				 *
				 * Artifact rather than relation. The links
				 * already say a lookup happened and that what
				 * came back was indexed; this says WHAT was
				 * looked up, which is the difference between
				 * a tracing module and one reaching for the
				 * syscall table.
				 *
				 * ON THE CALLEE'S NODE, not the one at the
				 * return address. A hook-declaration block is
				 * promoted to a single node sitting at the
				 * function it occupies - see
				 * promote_wrappers - and that is the node a
				 * caller means when it calls into it.
				 *
				 * Recorded as the OFFSET of the bytes, never
				 * a copy: see KOF_DIAG_H_ATTR_STR.
				 */
				if (skips[q].call_at == rip) {
					uint16_t cn = skips[q].callee
						? callee_node(s, fns, fg.n,
							      skips[q].callee)
						: 0xffffu;
					struct kof_diag_hit *ch;
					uint64_t a0 = kof_emu_get_reg(em,
						kof_diag_sysv_arg[0]);

					/*
					 * TWO PLACES THE SAME NAME CAN BE, and
					 * the two Diamorphine builds have one
					 * each.
					 *
					 * diamondxe keeps findmyinterest as a
					 * function, so the caller hands the
					 * name IN and the name belongs to the
					 * callee's node.
					 *
					 * diamorphine inlined it, so the block
					 * itself loads the name and passes it
					 * ON - here through a retpoline thunk,
					 * which is an import and names no
					 * callee at all. The name then belongs
					 * to the node promoted over THIS
					 * function.
					 *
					 * Both are the same statement: this
					 * hook-declaration block was reaching
					 * for that symbol.
					 */
					if (cn == 0xffffu)
						cn = callee_node(s, fns, fg.n, lo);
					ch = cn == 0xffffu ? 0
							   : kof_diag_hit_of(s, cn);
					if (ch && !ch->attr && a0 > DIAG_REL_BASE &&
					    name_at(base, size, a0 - DIAG_REL_BASE)) {
						ch->attr = a0 - DIAG_REL_BASE;
						ch->bits |= KOF_DIAG_H_ATTR_STR;
					}
				}

				for (i = 0; i < n; i++) {
					const struct kof_diag_hit *p =
						kof_diag_scan_at(s, i);

					if (p && p->at == skips[q].resume) {
						node = (uint16_t)i;
						break;
					}
				}

				if (node != 0xffffu) {
					struct kof_diag_hit *h =
						kof_diag_hit_of(s, node);

					for (k = 0; k < 6u && h; k++) {
						uint8_t role =
						  kof_diag_role_of_arg(
							h->cap, k);
						uint64_t v = kof_emu_get_reg(em,
						  kof_diag_sysv_arg[k]);
						uint32_t t;

						if (role == KOF_DIAG_ROLE_NONE)
							continue;
						/*
						 * EVERY EARLIER HOLDER OF THIS
						 * VALUE IS A RELATION, and each
						 * one is said in its own words:
						 * the node that RETURNED it is
						 * where it came from, a node
						 * that was merely handed it
						 * shares the object. See enum
						 * kof_diag_kind - collapsing
						 * the two left one argument
						 * with two parents under one
						 * role, and the engine then
						 * had to choose, which is how
						 * a receiver came to be
						 * recorded as a producer.
						 */
						for (t = 0; t < n_seen; t++) {
							const struct kof_diag_hit *o;

							if (seen[t].val != v ||
							    seen[t].node == node)
								continue;
							/*
							 * A SHARED EDGE IS
							 * RECORDED ONCE, FROM
							 * THE LATER SITE TO THE
							 * EARLIER ONE.
							 *
							 * Sharing an object is
							 * symmetric, but what
							 * carries the meaning is
							 * the ORDER - a buffer
							 * is filled and then
							 * written back out, and
							 * that is the hook.
							 * Recorded both ways it
							 * is a cycle: each
							 * kprobe call became the
							 * other's parent, no
							 * node was a root, and
							 * the pair stopped
							 * appearing as a chain
							 * at all while both
							 * links were in the
							 * data.
							 *
							 * Provenance needs no
							 * such rule: a producer
							 * is earlier by
							 * construction.
							 */
							o = kof_diag_scan_at(s,
								seen[t].node);
							if (!seen[t].produced &&
							    o && o->at >= h->at)
								continue;
							kof_diag_note_in(
								  h,
								  seen[t].node,
								  role,
								  seen[t].produced
								  ? KOF_DIAG_KIND_PRODUCED
								  : KOF_DIAG_KIND_SHARED);
						}
						/*
						 * AND THIS NODE NOW HOLDS IT
						 * TOO. Recorded even where a
						 * producer entry already
						 * stands for the value: that
						 * entry answers where the
						 * object came from and this
						 * one answers who has touched
						 * it, and the next holder
						 * needs both. A buffer
						 * kzalloc made, filled by
						 * copy_from_user and written
						 * back by copy_to_user is
						 * three entries and the third
						 * call links to the other two
						 * - the ordering IS the hook.
						 *
						 * One entry per (value, node),
						 * so a loop round the same
						 * call adds nothing.
						 */
						if (worth_remembering(v, size)) {
							uint32_t e;

							for (e = 0; e < n_seen; e++)
								if (seen[e].val == v &&
								    seen[e].node == node)
									break;
							if (e == n_seen &&
							    n_seen < DIAG_REL_SEEN) {
								seen[e].val = v;
								seen[e].node = node;
								seen[e].produced = 0;
								n_seen++;
							}
						}
					}
				}

				/*
				 * OVER THE CALL, NEVER THROUGH IT, and the
				 * result stated rather than computed - see
				 * the note on skipping above. A producer's
				 * token is remembered the same way an
				 * argument is, so the next site holding it
				 * links back here.
				 */
				kof_emu_set_rip(em, DIAG_REL_BASE +
						skips[q].resume);
				{
					uint16_t src = 0xffffu;

					if (node != 0xffffu &&
					    kof_diag_sym_hands_on(skips[q].cap))
						src = node;
					else if (skips[q].callee) {
						uint32_t t;

						/* What that function was
						 * MEASURED to return, from an
						 * earlier pass; the one-node
						 * rule only while nothing has
						 * been measured yet. */
						src = 0xffffu;
						for (t = 0; t < fg.n; t++)
							if (fns[t].va ==
							    skips[q].callee) {
								src = ret[t];
								break;
							}
						if (src == 0xffffu)
							src = callee_node(s,
								fns, fg.n,
								skips[q].callee);
					}
					if (src != 0xffffu &&
					    src < DIAG_TOK_SPAN) {
						uint64_t tok = DIAG_TOK_BASE +
						  (uint64_t)src * KOF_EMU_PAGE;

						kof_emu_set_reg(em,
								KOF_EMU_RAX,
								tok);
						if (n_seen < DIAG_REL_SEEN) {
							seen[n_seen].val = tok;
							seen[n_seen].node = src;
							seen[n_seen].produced = 1;
							n_seen++;
						}
					} else if (cap_force_kind(skips[q].cap)
						   != FORCE_NONE) {
						/*
						 * WHAT THIS CALL HANDS BACK IS
						 * ALREADY WRITTEN DOWN, once,
						 * in cap_force_kind - and this
						 * routine used to ignore it and
						 * give every call the same
						 * anonymous page. For a call
						 * whose success is ZERO that
						 * said the opposite of what was
						 * meant.
						 */
						uint64_t r = 0;

						switch (cap_force_kind(
								skips[q].cap)) {
						case FORCE_HANDLE:
							r = DIAG_EMU_FD0 +
							    n_fd++;
							break;
						case FORCE_COUNT:
							r = kof_emu_get_reg(em,
							  kof_diag_sysv_arg[2]);
							break;
						default:
							r = 0;  /* FORCE_ZERO */
							break;
						}
						kof_emu_set_reg(em,
								KOF_EMU_RAX, r);
					} else if (anon) {
						/*
						 * A CALL WHOSE RESULT NOTHING
						 * HERE EXPLAINS STILL HAS TO
						 * LOOK LIKE SUCCESS.
						 *
						 * Clearing the register leaves
						 * zero, and zero is what every
						 * caller tests for failure.
						 * MEASURED: Diamorphine's
						 * init_module calls
						 * findmyinterest, reads zero
						 * back, decides the lookup
						 * failed and jumps to its
						 * error return - nine
						 * instructions in, past
						 * nothing, 110 bytes short of
						 * the cr0 write the walk was
						 * opened for.
						 *
						 * An anonymous page from the
						 * arena is non-zero so the
						 * branch goes the other way,
						 * mapped so dereferencing it
						 * does not fault, and belongs
						 * to no node so it can never
						 * be mistaken for a link.
						 */
						kof_emu_set_reg(em,
							KOF_EMU_RAX,
							DIAG_TOK_BASE +
							(uint64_t)(--anon) *
							KOF_EMU_PAGE);
					}
				}
				/*
				 * ---- AND A TAIL JUMP IS AN EXIT ----------
				 *
				 * The relocation table lists `jmp foo` beside
				 * `call foo` and nothing in it says which. A
				 * call's `resume` is where the callee comes
				 * back to; a JUMP never comes back, so the
				 * bytes after it are not a continuation of
				 * anything - they belong to whatever block
				 * the compiler laid there next.
				 *
				 * MEASURED, and it is why Diamorphine's
				 * hacked_getdents had no link at all. The
				 * function ends
				 *
				 *     mov %rbx,%rax ; add $0x10,%rsp
				 *     pop %rbx,%rbp,%r12,%r13,%r14,%r15
				 *     jmp <reloc>            <- the exit
				 *     cmp %r13,0x12(%rbx)    <- loop body
				 *     jne  ...
				 *
				 * Resuming after the jump walked into the
				 * loop body with every callee-saved register
				 * just popped off a stack this run never
				 * built - so the kernel buffer was 0 - and
				 * the loop then ran until the step budget
				 * ended it, 11 bytes short of the
				 * copy_to_user the span was opened for.
				 *
				 * THE LINKS ARE NOTED FIRST, above. A tail
				 * call IS a call to that import and its
				 * arguments are set up in the usual way -
				 * god_mode ends `jmp commit_creds` - so the
				 * node and its links are real. Only the
				 * resumption is not.
				 *
				 * Asked of the decoder, not of a byte: an
				 * encoding list is the thing this engine
				 * does not keep twice.
				 */
				if (rip < size) {
					struct kdis_insn ji;
					uint32_t jl = kof_decode_x86(base + rip,
						(uint32_t)(size - rip > 16u
							   ? 16u : size - rip),
						rip, 64u, &ji);

					if (jl && ji.op == KDIS_JMP) {
						ended = 1;
						break;
					}
				}
				skipped = 1;
				break;
			}
			if (ended)
				goto stalled;   /* the function returned */
			if (skipped)
				continue;

			/*
			 * ---- A PROTECTION TURNED OFF, WHICH HAS NO NAME ---
			 *
			 * `mov cr0, reg` is how a kernel rootkit makes the
			 * kernel's own text writable before it patches a
			 * syscall table. It is INLINE ASSEMBLY: no symbol, no
			 * relocation, no call, so nothing the relocation
			 * table lists ever stops on it and the centre of the
			 * rootkit was invisible.
			 *
			 * RECOGNISED THROUGH THE ENGINE'S DECODER, not a list
			 * of bytes. kof_decode_x86 already classifies a
			 * control-register move as KDIS_MOV_SPECIAL with
			 * KDIS_SR_CR; asking it is asking the one thing in
			 * the tree that knows x86 encodings. The vocabulary
			 * has had a row for this since it was written -
			 * mov_cr0 -> kmodule-cr-write - and nothing had ever
			 * reached it.
			 *
			 * ONE NODE PER SITE, as everywhere else: Diamorphine
			 * clears the bit and puts it back, and a loop that
			 * hooks and unhooks arrives at the same two
			 * instructions each time.
			 */
			if (rip < size) {
				struct kdis_insn ci;
				/*
				 * ---- DECODED FROM WHAT ACTUALLY RUNS ------
				 *
				 * The file's bytes are NOT what this run
				 * executes. A relocatable object leaves every
				 * branch displacement as a hole and
				 * build_rel_image fills them IN THE
				 * EMULATOR'S MEMORY, so decoding `base + rip`
				 * reads zeros where the target is and answers
				 * "it jumps to the next instruction".
				 *
				 * MEASURED on diamondxe, and it defeated two
				 * repairs before it was found: the filtering
				 * loop ends `jbe <hole>` and the file says
				 * that branch stays in the function, while the
				 * run jumped 0xa8b bytes away into a cold
				 * block and left the span. Every test below
				 * that looks at a TARGET was being answered
				 * from the wrong bytes.
				 */
				uint8_t ib[16];
				uint32_t ilen = (uint32_t)(size - rip > 16u
							   ? 16u : size - rip);
				uint32_t clen;

				if (!kof_emu_read(em, DIAG_REL_BASE + rip,
						  ib, ilen))
					memcpy(ib, base + rip, ilen);
				clen = kof_decode_x86(ib, ilen, rip, 64u, &ci);

				/*
				 * AND OVER AN INDIRECT CALL. `call *(pv_ops+k)`
				 * goes through a pointer the loader fills; the
				 * symbol is undefined here so the slot is zero
				 * and stepping it calls address zero. Diamorphine
				 * reads cr0 that way, two instructions before it
				 * writes it, so the span died before reaching
				 * the thing it was opened for. The decoder says
				 * it is a call through memory; no list of
				 * encodings is involved.
				 */
				/*
				 * ---- A LOOP IS LET ROUND, NOT RUN OUT -----
				 *
				 * THE BUDGET WAS THE WRONG BOUND. A span had
				 * 4096 instructions and a loop ate all of
				 * them, so the span died INSIDE the loop and
				 * everything after it was lost - MEASURED on
				 * Diamorphine's hacked_getdents, which filters
				 * a directory listing and then copies it back:
				 * the run stopped 11 bytes short of that copy,
				 * and the hiding behaviour read as absent.
				 *
				 * WHY THE LOOP DOES NOT END BY ITSELF. It is
				 * bounded by the byte count the original
				 * syscall returned, and that call is skipped -
				 * so the count is a stated value, not a real
				 * one. No stated value is both a plausible
				 * pointer and a small number of iterations.
				 *
				 * SO BOUND THE ITERATIONS, WHICH IS THE INPUT,
				 * and let what comes after be whatever it is.
				 * A loop body is fully covered by its first
				 * pass - a node is a SITE, and a link already
				 * refuses a repeat - so a third arrival at the
				 * same backward branch has nothing left to
				 * show. Taking the fall-through there is the
				 * loop's own exit, not a path invented for it.
				 *
				 * A FORWARD branch is not touched: it is a
				 * choice between two paths, not a repetition,
				 * and forcing one would be inventing a run.
				 */
				/*
				 * ---- AND A CONDITIONAL BRANCH OUT OF THE SPAN --
				 *
				 * A span covers ONE function and asks which of its
				 * sites are linked. An arm that leaves the function
				 * cannot reach any of them, so following it answers
				 * nothing and ends the walk; the arm that stays is
				 * the only one with anything to say.
				 *
				 * THIS IS NOT A CLAIM ABOUT WHICH WAY THE PROGRAM
				 * GOES. The condition is computed from values this
				 * run STATED - a count from a skipped call, a page
				 * from an arena - so neither arm was demonstrated
				 * and choosing the one that can carry evidence
				 * asserts nothing the other way.
				 *
				 * MEASURED on diamondxe: its filtering loop ends
				 * `jbe <reloc>` into a cold block at 0xd0b, and the
				 * synthetic comparison took it - the span left the
				 * function with the copy back still ahead of it.
				 * diamorphine, built from the same source, keeps
				 * that block inline and never showed the fault.
				 */
				if (clen && (ci.op == KDIS_JCC ||
					     ci.op == KDIS_LOOP) &&
				    ci.target != KOF_BROKEN &&
				    (ci.target < run_lo ||
				     ci.target >= run_hi)) {
					kof_emu_set_rip(em, DIAG_REL_BASE +
							rip + ci.len);
					continue;
				}
				if (clen && (ci.op == KDIS_JCC ||
					     ci.op == KDIS_LOOP ||
					     ci.op == KDIS_JMP) &&
				    ci.target != KOF_BROKEN &&
				    ci.target < rip) {
					uint32_t t;

					for (t = 0; t < n_latch; t++)
						if (latch[t].at == rip)
							break;
					if (t == n_latch && n_latch <
					    (uint32_t)(sizeof latch /
						       sizeof latch[0])) {
						latch[t].at = rip;
						latch[t].n = 0;
						n_latch++;
					}
					/*
					 * EVERY BACKWARD TRANSFER, not only the
					 * conditional ones: a loop whose latch
					 * is `jmp` was not counted at all and
					 * ran until something else stopped it.
					 *
					 * AND IT STALLS RATHER THAN FALLING
					 * THROUGH. Falling through is a path
					 * this run did not take; stalling hands
					 * the span to the seat logic, which
					 * moves to the next site - the same
					 * answer the routine gives for every
					 * other obstacle, and the reason the
					 * gap budget almost never has to.
					 */
					if (t < n_latch &&
					    ++latch[t].n > DIAG_REL_SPINS)
						goto stalled;
				}
				/*
				 * ---- A DIRECT CALL THE TABLE DID NOT LIST ----
				 *
				 * EVERY call in a span is skipped - that is the
				 * design above - and the relocation table was only
				 * how they were FOUND. It does not list them all: a
				 * call to a static function in the same section is
				 * resolved by the assembler, so there is no
				 * relocation and nothing put it in the skip list.
				 *
				 * Such a call was therefore EXECUTED, and execution
				 * leaves the function - which ends the span, because
				 * a span is one function. MEASURED on diamondxe: its
				 * filtering loop calls a local helper and the walk
				 * left at 0xd0b, two sites short of the copy back.
				 *
				 * The result is stated the same way as any other
				 * skipped call - see the note on the arena page.
				 */
				if (clen && ci.op == KDIS_CALL && ci.n_op &&
				    ci.o[0].kind == KDIS_O_REL) {
					if (anon)
						kof_emu_set_reg(em, KOF_EMU_RAX,
							DIAG_TOK_BASE +
							(uint64_t)(--anon) *
							KOF_EMU_PAGE);
					kof_emu_set_rip(em, DIAG_REL_BASE +
							rip + ci.len);
					continue;
				}
				if (clen && ci.op == KDIS_CALL && ci.n_op &&
				    ci.o[0].kind != KDIS_O_REL) {
					/*
					 * AND IT HANDS SOMETHING BACK. Stepping
					 * over a call while leaving the result
					 * register alone states nothing - it
					 * leaves whatever happened to be there,
					 * and the program then tests THAT.
					 *
					 * MEASURED: Diamorphine's hooked
					 * getdents calls the original through
					 * the syscall table, keeps the result
					 * as a byte count and checks
					 * `count > 0x7fffffff`. A stale
					 * register held an address, the check
					 * failed, and the run took the error
					 * path - freeing the buffer and
					 * leaving - so the copy the hook
					 * exists for was never on the path at
					 * all.
					 *
					 * An arena page is the same answer the
					 * named skip gives and for the same
					 * reasons: non-zero, so a failure test
					 * goes the other way; mapped, so a
					 * dereference does not fault; below
					 * 2^31, so it is plausible where the
					 * program treats it as a size; and
					 * owned by no node, so it can never be
					 * mistaken for a link.
					 */
					if (anon)
						kof_emu_set_reg(em, KOF_EMU_RAX,
							DIAG_TOK_BASE +
							(uint64_t)(--anon) *
							KOF_EMU_PAGE);
					kof_emu_set_rip(em, DIAG_REL_BASE +
							rip + ci.len);
					continue;
				}
				/*
				 * ---- A VALUE READ OUT OF AN OBJECT A NODE
				 * PRODUCED --------------------------------
				 *
				 * THE STEP THAT CARRIES THE MEANING, and the
				 * one the model had no place for. Between
				 * two calls the program does something to
				 * the object the first returned, and that
				 * something is what the pair is FOR:
				 *
				 *   kallsyms_lookup_name_ = *(kp + 0x2d)
				 *       the probe's resolved address, which
				 *       is why the probe was registered
				 *   pure_getdents = *(table + 0x270)
				 *       the syscall entry about to be hooked
				 *
				 * A load through a register holding a token
				 * yields a value that still belongs to that
				 * node - it came OUT of its object - so the
				 * destination inherits the token and a later
				 * call holding it links back.
				 *
				 * THE OFFSET IS NOT KEPT YET. 0x2d and 0x270
				 * are what name WHICH field and WHICH
				 * syscall, and they belong in the node's
				 * attribute run, which nothing writes. The
				 * link is the half that can be had now.
				 */
				/*
				 * EITHER DIRECTION: a field read out of the
				 * object, or written into it. The write is
				 * the one that matters most - it is what a
				 * rootkit does to the listing it intercepted
				 * - and it is the one a model built around
				 * calls had no way to see at all.
				 */
				if (clen && ci.op == KDIS_MOV && ci.n_op > 1u) {
					unsigned mi = ci.o[0].kind ==
						      KDIS_O_MEM ? 0u : 1u;

					/*
					 * ---- A GLOBAL STRUCT, REACHED WITHOUT
					 * A BASE REGISTER -------------------
					 *
					 * `kp` is a module global, so the read
					 * of kp.addr is
					 *
					 *     mov 0x0(%rip),%rbx
					 *
					 * with the displacement filled by a
					 * relocation. There is no base register
					 * at all, and the test below wanted one
					 * - so the one access that CONFIRMS a
					 * kprobe pair, the resolved symbol
					 * being collected between the register
					 * and the unregister, was invisible.
					 *
					 * The object's address is known: it is
					 * what register_kprobe was handed, and
					 * seen[] is holding it. An absolute
					 * target that lands inside that object
					 * is a field of it.
					 */
					if (ci.o[mi].kind == KDIS_O_MEM &&
					    ci.o[mi].reg == KDIS_REG_NONE &&
					    ci.o[mi].index == KDIS_REG_NONE) {
						uint64_t tg = rip + ci.len +
							(uint64_t)ci.o[mi].disp +
							DIAG_REL_BASE;
						uint32_t z;

						for (z = 0; z < n_seen; z++)
							if (tg >= seen[z].val &&
							    tg - seen[z].val <
							    DIAG_OBJ_SPAN)
								break;
						if (z < n_seen) {
							struct kof_diag_hit *fh;
							uint32_t t2, lv =
							  kof_diag_scan_count(s);
							int dup2 = 0;

							for (t2 = 0; t2 < lv; t2++) {
								const struct kof_diag_hit *e =
								  kof_diag_scan_at(s, t2);
								/* ONLY ANOTHER FIELD
								 * NODE COUNTS. A node's
								 * `at` is a call's RESUME
								 * address, which is the
								 * very next instruction -
								 * and in diamorphine that
								 * instruction IS the read
								 * of kp.addr, so the two
								 * collided and the read
								 * was dropped. */
								if (e && e->at == rip &&
								    (e->cap == KOF_NUCLEO_FIELD_READ ||
								     e->cap == KOF_NUCLEO_FIELD_WRITE))
									dup2 = 1;
							}
							fh = dup2 ? NULL
							   : kof_diag_hit_add(s, rip,
								mi == 0u
								? KOF_NUCLEO_FIELD_WRITE
								: KOF_NUCLEO_FIELD_READ, 0);
							if (fh) {
								fh->attr = tg -
								  seen[z].val;
								field_value(fh, &ci, mi);
								kof_diag_note_in(fh,
								  seen[z].node,
								  mi == 0u
								  ? KOF_DIAG_ROLE_BUFFER
								  : KOF_DIAG_ROLE_SOURCE,
								  seen[z].produced
								  ? KOF_DIAG_KIND_PRODUCED
								  : KOF_DIAG_KIND_SHARED);
							}
						}
					}
					if (ci.o[mi].kind == KDIS_O_MEM &&
					    ci.o[mi].reg != KDIS_REG_NONE &&
					    ci.o[mi].index == KDIS_REG_NONE) {
						uint64_t b = kof_emu_get_reg(em,
							ci.o[mi].reg);

						/*
						 * ---- A FIELD OF AN OBJECT A
						 * NODE WAS HANDED --------------
						 *
						 * A token stands for something a
						 * call RETURNED. The kprobe
						 * struct is not that: it is a
						 * module global, its address is a
						 * relocation into .bss, and it
						 * reaches register_kprobe as an
						 * argument. So the read of
						 * kp.addr between the register
						 * and the unregister - which is
						 * the whole reason the pair
						 * exists, the resolved symbol
						 * being collected - matched
						 * nothing and was invisible.
						 *
						 * ANY ADDRESS A NODE HAS BEEN
						 * SEEN HOLDING counts. That is
						 * what seen[] already is, and it
						 * is what confirms the block:
						 * register and unregister share
						 * an object, and in between
						 * something READS a field of it.
						 */
						if (b < DIAG_TOK_BASE ||
						    b >= DIAG_TOK_BASE +
							(uint64_t)DIAG_TOK_SPAN *
							KOF_EMU_PAGE) {
							uint32_t z;

							for (z = 0; z < n_seen; z++)
								if (seen[z].val == b)
									break;
							if (z < n_seen) {
								struct kof_diag_hit *fh;
								uint32_t t2,
								  lv = kof_diag_scan_count(s);
								int dup2 = 0;

								for (t2 = 0; t2 < lv; t2++) {
									const struct kof_diag_hit *e =
									  kof_diag_scan_at(s, t2);
									if (e && e->at == rip)
										dup2 = 1;
								}
								fh = dup2 ? NULL
								   : kof_diag_hit_add(s, rip,
									mi == 0u
									? KOF_NUCLEO_FIELD_WRITE
									: KOF_NUCLEO_FIELD_READ,
									0);
								if (fh) {
									fh->attr = (uint64_t)
									  ci.o[mi].disp;
									field_value(fh, &ci, mi);
									kof_diag_note_in(fh,
									  seen[z].node,
									  mi == 0u
									  ? KOF_DIAG_ROLE_BUFFER
									  : KOF_DIAG_ROLE_SOURCE,
									  seen[z].produced
									  ? KOF_DIAG_KIND_PRODUCED
									  : KOF_DIAG_KIND_SHARED);
								}
							}
						}
						if (b >= DIAG_TOK_BASE &&
						    b < DIAG_TOK_BASE +
							(uint64_t)DIAG_TOK_SPAN *
							KOF_EMU_PAGE) {
							uint64_t page = b -
							  (b - DIAG_TOK_BASE) %
							  KOF_EMU_PAGE;
							uint32_t own =
							  (uint32_t)((page -
							   DIAG_TOK_BASE) /
							   KOF_EMU_PAGE);
							uint32_t t, live =
							  kof_diag_scan_count(s);
							int dup = 0;

							for (t = 0; t < live; t++) {
								const struct kof_diag_hit *e =
								  kof_diag_scan_at(s, t);
								if (e && e->at == rip)
									dup = 1;
							}
							if (!dup) {
								struct kof_diag_hit *fh =
								  kof_diag_hit_add(s, rip,
								    mi == 0u
								    ? KOF_NUCLEO_FIELD_WRITE
								    : KOF_NUCLEO_FIELD_READ,
								    0);
								if (fh) {
									fh->attr =
									  (uint64_t)
									  ci.o[mi].disp;
									field_value(fh, &ci, mi);
									if (own < live)
										kof_diag_note_in(fh,
										  (uint16_t)own,
										  mi == 0u
										  ? KOF_DIAG_ROLE_BUFFER
										  : KOF_DIAG_ROLE_SOURCE,
										  KOF_DIAG_KIND_PRODUCED);
								}
							}
							/* a load still hands
							 * the object on */
							if (mi == 1u &&
							    ci.o[0].kind ==
							    KDIS_O_REG) {
								kof_emu_step(em);
								kof_emu_set_reg(em,
								  ci.o[0].reg, page);
								continue;
							}
						}
					}
				}

				/*
				 * ONE OPERAND, NOT TWO. decode_x86 keeps only
				 * the operands a sweep tracks, and a control
				 * register is not one - so `mov cr0,rax`
				 * arrives with the GPR in o[0] and nothing
				 * else. Requiring two was why this never
				 * fired although the walk reached the
				 * instruction.
				 *
				 * The GPR being READ is what makes it a write
				 * TO cr0 rather than a read of it.
				 */
				if (clen && ci.op == KDIS_MOV_SPECIAL &&
				    ci.cond == KDIS_SR_CR && ci.n_op &&
				    ci.o[0].kind == KDIS_O_REG &&
				    (ci.o[0].flags & KDIS_OF_READ)) {
					uint32_t t, live = kof_diag_scan_count(s);
					int seen_site = 0;

					/* LIVE COUNT, not the one taken
					 * before the walk: a node added by
					 * this very loop has to be visible
					 * to it, or the same site is added
					 * again on the next pass. A node is
					 * a site, however many times the
					 * walk arrives. */
					for (t = 0; t < live; t++) {
						const struct kof_diag_hit *p =
						  kof_diag_scan_at(s, t);

						if (p && p->at == rip &&
						    p->cap == KOF_NUCLEO_PROT_OFF)
							seen_site = 1;
					}
					if (!seen_site)
						kof_diag_hit_add(s, rip,
							KOF_NUCLEO_PROT_OFF, 0);
					/*
					 * AND STEP OVER IT. The interpreter
					 * answers UNSUPPORTED for a control
					 * register move - correctly, it does
					 * not model one - and that ends the
					 * span at the exact instruction the
					 * span was opened for. Everything
					 * after it is the hook itself: the
					 * stores into the table and the
					 * second write that puts the
					 * protection back.
					 *
					 * Skipping is sound here because
					 * nothing downstream depends on
					 * cr0's value. The guest never reads
					 * it back for anything but restoring
					 * it, and no link is ever carried
					 * through a control register.
					 */
					kof_emu_set_rip(em, DIAG_REL_BASE +
							rip + ci.len);
					continue;
				}
			}

			/*
			 * A SPAN THAT CANNOT BE WALKED ENDS QUIETLY. An
			 * unapplied relocation sends a load somewhere the
			 * file does not reach; the run stops and the span
			 * reports nothing, which is the honest answer rather
			 * than a wrong one.
			 */
			st = kof_emu_step(em);
			/*
			 * ---- A FAULT ON SYNTHETIC MEMORY IS NOT A FACT -----
			 *
			 * The data this run works on was STATED, not read: a
			 * skipped allocator hands back one arena page, and a
			 * skipped call hands back a count nobody measured. So a
			 * loop that walks "the buffer" runs off the end of the
			 * only page there is and the emulator faults - on an
			 * address the PROGRAM never computes, because in the
			 * program the buffer is as long as the count says.
			 *
			 * THAT FAULT IS ABOUT THE SYNTHESIS AND THE SPAN MUST NOT
			 * DIE OF IT. MEASURED on diamondxe: once the copies were
			 * given their true success value the run took the REAL
			 * path for the first time, walked the listing, faulted,
			 * and the copy back - the whole of the hiding - was never
			 * reached. It had only ever been reached before by taking
			 * the ERROR path, which is the right answer for the wrong
			 * reason.
			 *
			 * STEPPING OVER IT IS SOUND because what the instruction
			 * would have loaded is not known either way. The registers
			 * it writes are CLEARED rather than left: a stale value
			 * could still equal a token and would then read as a link
			 * the run never demonstrated. Zero belongs to no node and
			 * worth_remembering refuses it.
			 *
			 * A DECODE OR UNSUPPORTED INSTRUCTION STILL ENDS THE SPAN:
			 * there the engine does not know what the instruction
			 * DOES, so everything after it would be a guess.
			 */
			if (st == KOF_EMU_STOP_FAULT &&
			    n_fault < DIAG_REL_FAULTS && rip < size) {
				struct kdis_insn fi;
				uint32_t fl = kof_decode_x86(base + rip,
					(uint32_t)(size - rip > 16u ? 16u
						   : size - rip),
					rip, 64u, &fi);

				if (fl) {
					unsigned z;

					for (z = 0; z < fi.n_op; z++)
						if (fi.o[z].kind == KDIS_O_REG &&
						    (fi.o[z].flags & KDIS_OF_WRITE))
							kof_emu_set_reg(em,
								fi.o[z].reg, 0);
					kof_emu_set_rip(em, DIAG_REL_BASE +
							rip + fl);
					n_fault++;
					continue;
				}
			}
			if (st != KOF_EMU_STOP_FAULT &&
			    st != KOF_EMU_STOP_DECODE &&
			    st != KOF_EMU_STOP_UNSUPPORTED)
				continue;
stalled:
			/*
			 * ---- ON TO THE NEXT SITE ---------------------------
			 *
			 * The run has stopped being able to walk - it left the
			 * function, it returned, or it met an instruction this
			 * build does not carry. None of that is a finding; the
			 * sites it has not reached yet are still listed in the
			 * relocation table, and the span's job is to arrive at
			 * them.
			 *
			 * STRICTLY FORWARD, so one pass cannot circle: the next
			 * seat is the lowest site above the last address the
			 * run was really at. That is also why no "already
			 * seated" flag is needed.
			 */
			{
				uint32_t w, bq = sg.n, pv = sg.n;
				uint64_t seat;

				/*
				 * THE NEXT SITE IS THE NEXT ONE NOT YET
				 * LOOKED AT - not the next one by address.
				 *
				 * Seating strictly forwards was tried and it
				 * abandons sites silently: a branch that
				 * carries the run from 0x2d0 to 0x380 puts
				 * every site between them permanently behind
				 * it. MEASURED on diamondxe, whose
				 * copy_to_user at 0x365 was jumped over and
				 * then never seated - and a site that is
				 * never looked at reads exactly like a call
				 * with no link.
				 *
				 * vis[] is what makes this terminate: a site
				 * is marked when it is REACHED and when it is
				 * SEATED, so each one is tried at most once
				 * and the pass is still finite.
				 */
				/*
				 * FORWARD FIRST, STRAGGLERS AFTER.
				 *
				 * The next site AHEAD of where the run really
				 * got to is the one whose arguments the code
				 * just walked was setting up, so it is tried
				 * first - taking the lowest unvisited site
				 * instead put diamorphine's copy_to_user in a
				 * gap that never loaded its buffer.
				 *
				 * ONLY WHEN NOTHING IS AHEAD does the span go
				 * back for what it jumped over. Seating
				 * strictly forwards abandons those silently -
				 * MEASURED on diamondxe, whose copy_to_user at
				 * 0x365 was branched over and never seated,
				 * which reads exactly like a call with no
				 * link.
				 *
				 * vis[] is marked both when a site is REACHED
				 * and when it is SEATED, so each is tried at
				 * most once and the pass stays finite.
				 */
				/*
				 * ---- THE SEATS ARE THE NODES, NOT THE CALLS
				 *
				 * What the span is trying to do is VERIFY A
				 * NODE: a position that matched the
				 * vocabulary, whose arguments are the thing a
				 * link is made of. A call to something the
				 * dictionary has no word for is not a node,
				 * cannot carry a link, and is worth stepping
				 * over when it turns up - never worth moving
				 * the run to.
				 *
				 * THAT WAS THE HOLE. The seat list was every
				 * call site, so "where to go next" was decided
				 * by address arithmetic over a list that is
				 * mostly noise, and the order it produced was
				 * tuned by hand against one sample at a time -
				 * each adjustment resolving one Diamorphine
				 * build and breaking the other. The routine
				 * did not know which node it still had to
				 * verify.
				 */
				for (w = 0; w < sg.n; w++) {
					if (vis[w] ||
					    skips[w].cap == KOF_NUCLEO_NONE ||
					    skips[w].call_at <= last_in ||
					    skips[w].call_at < run_lo ||
					    skips[w].call_at >= run_hi)
						continue;
					if (bq == sg.n ||
					    skips[w].call_at < skips[bq].call_at)
						bq = w;
				}
				if (bq == sg.n)
					for (w = 0; w < sg.n; w++) {
						if (vis[w] ||
						    skips[w].cap ==
						    KOF_NUCLEO_NONE ||
						    skips[w].call_at < run_lo ||
						    skips[w].call_at >= run_hi)
							continue;
						if (bq == sg.n ||
						    skips[w].call_at <
						    skips[bq].call_at)
							bq = w;
					}
				if (bq == sg.n || n_seat >= DIAG_REL_SEATS)
					break;
				/*
				 * SEATED AT THE START OF THE GAP, NOT AT THE
				 * CALL.
				 *
				 * Landing on the call itself skips the very
				 * instructions that put its arguments in
				 * place - MEASURED: diamondxe's copy_to_user
				 * was reached and its kernel buffer register
				 * was empty, because `mov %r14,%rsi` is three
				 * instructions before the call and the seat
				 * jumped over it.
				 *
				 * The stretch between two sites is exactly
				 * what this routine was built to emulate, and
				 * the previous site's RESUME is a known
				 * instruction boundary - it is a return
				 * address - so no search for one is needed.
				 */
				for (w = 0; w < sg.n; w++) {
					if (skips[w].resume >= run_lo &&
					    skips[w].resume <=
					    skips[bq].call_at &&
					    (pv == sg.n ||
					     skips[w].resume >
					     skips[pv].resume))
						pv = w;
				}
				seat = pv == sg.n ? skips[bq].call_at
						  : skips[pv].resume;
				/*
				 * AND THE ARGUMENT REGISTERS ARE CLEARED.
				 *
				 * The run did not walk here; it was placed
				 * here. Whatever a volatile register held
				 * belongs to the stretch that stalled, and
				 * keeping it lets a value from one call be
				 * read as the argument of another - MEASURED:
				 * diamorphine's list_del was recorded taking
				 * the struct prepare_creds returned, which
				 * nothing in the program does.
				 *
				 * Only the volatile ones. rbx, rbp and r12-r15
				 * are where a function keeps what it carries
				 * across calls - the hooked getdents holds its
				 * buffer in r14 - and clearing those would
				 * throw away the links this span exists for.
				 */
				for (w = 0; w < 6u; w++)
					kof_emu_set_reg(em,
						kof_diag_sysv_arg[w], 0);
				kof_emu_set_reg(em, KOF_EMU_RAX, 0);
				vis[bq] = 1;
				n_seat++;
				gap_steps = 0;
				last_in = seat;
				kof_emu_set_rip(em, DIAG_REL_BASE + seat);
			}
		}
		/*
		 * AND WHAT THIS FUNCTION HANDS BACK, for whoever calls it:
		 * the token left in the result register when its span ended.
		 * Recorded rather than reasoned about, and read by the next
		 * pass.
		 */
		{
			uint64_t rv = kof_emu_get_reg(em, KOF_EMU_RAX);
			uint16_t was = ret[j];

			if (rv >= DIAG_TOK_BASE &&
			    rv < DIAG_TOK_BASE +
				 (uint64_t)DIAG_TOK_SPAN * KOF_EMU_PAGE)
				ret[j] = (uint16_t)((rv - DIAG_TOK_BASE) /
						    KOF_EMU_PAGE);
			if (ret[j] != was) {
				uint32_t w;

				changed = 1;
				/* whoever calls this function may now see a
				 * different value come back */
				for (w = 0; w < sg.n; w++)
					if (skips[w].callee == fns[j].va) {
						uint32_t g;

						for (g = 0; g < fg.n; g++)
							if (skips[w].call_at >=
							    fns[g].va &&
							    skips[w].call_at <
							    fns[g].va +
							    fns[g].size)
								next_dirty[g] = 1;
					}
			}
		}
		kof_emu_free(em);

	}
	if (!changed)
		break;
	memcpy(dirty, next_dirty, sizeof dirty);
	memset(next_dirty, 0, sizeof next_dirty);
	}
}

void kof_diag_run_emulate(struct kof_diag_scan *s,
			  const struct kof_obj_ctx *ctx,
			  const uint8_t *base, uint64_t size)
{
	static const uint8_t pat_syscall[2] = { 0x0f, 0x05 };
	static const uint8_t pat_int80[2]   = { 0xcd, 0x80 };
	const struct kof_elf_info *ei;
	struct kof_emu_unp_report rep;
	struct kof_emu *em;
	struct site sites[DIAG_EMU_SITES];
	struct made made[DIAG_EMU_MADE];
	const unsigned *areg;
	unsigned n_site = 0, n_made = 0, stops = 0, n_fd = 0, bits;

	/*
	 * AN ELF WITH A PROGRAM HEADER, because that is what there is an image
	 * builder for - see kof_emu_unp_build. A raw payload has no segments
	 * to map and no entry to start at; the static routine reads those and
	 * has already run.
	 */
	if (!ctx || ctx->format != KOF_FMT_ELF)
		return;
	ei = kof_elf(ctx);
	if (!ei || !ei->valid)
		return;
	bits = ctx->arch == KOF_ARCH_X86_64 ? 64u : 32u;
	areg = bits == 64u ? arg_reg64 : arg_reg32;

	/*
	 * A RELOCATABLE OBJECT TAKES THE OTHER PATH ENTIRELY - there is no
	 * entry point to start from and no syscall to stop at. See
	 * run_rel_gaps.
	 */
	if (!ei->seg_count) {
		run_rel_gaps(s, ctx, ei, base, size);
		return;
	}

	memset(&rep, 0, sizeof rep);
	em = kof_emu_unp_build(base, size, ei, DIAG_EMU_INSN, DIAG_EMU_PAGES,
			       &rep);
	if (!em)
		return;

	/*
	 * ---- START AT THE NODES, NOT AT THE ENTRY -------------------------
	 *
	 * This ran the program from its entry point, which is running the
	 * whole file to reach the part that matters. Two things were wrong
	 * with it and both were measured:
	 *
	 *   IT NEVER ARRIVES ON A REAL PROGRAM. 100 dynamically linked and 5
	 *   statically linked binaries from /usr/bin yielded zero nodes: the
	 *   run ends in the runtime's startup, hundreds of thousands of
	 *   instructions before any of the program's own calls.
	 *   IT IS THE WRONG QUESTION. What is wanted is not "what does this
	 *   program do" but "does the value this call produced reach that
	 *   call" - a relation between two places the static routines have
	 *   ALREADY located, at file offsets, without running anything.
	 *
	 * So the run begins a short way before the FIRST node the static
	 * routines found, with just enough lead-in to execute the
	 * instructions that set that call's arguments up. Everything before
	 * it - the loader, the runtime, the startup - is not executed because
	 * it is not part of any relation being asked about.
	 *
	 * THE LEAD-IN IS THE SAME 256 BYTES the static window uses, and for
	 * the same measured reason: msfvenom's longest argument set-up is 41.
	 */
	{
		uint64_t first = (uint64_t)-1, va;
		uint32_t q;

		for (q = 0; q < kof_diag_scan_count(s); q++) {
			uint64_t a = kof_diag_scan_at(s, q)->at;

			if (a != KOF_BROKEN && a < first)
				first = a;
		}
		if (first != (uint64_t)-1) {
			uint64_t lo = first > DIAG_EMU_LEAD
				      ? first - DIAG_EMU_LEAD : 0;

			/*
			 * AND NOT BEFORE THE ENTRY POINT, which is the one
			 * offset in the object certainly at an instruction
			 * boundary. An executable segment usually begins at
			 * file offset zero and therefore CONTAINS THE ELF
			 * HEADER: a lead-in that runs back into it starts the
			 * machine on `7f E L F 02 01 01` and faults at once.
			 * MEASURED - meter1's first node is at 0x8d, so 256
			 * bytes of lead-in reached 0 and the run died before
			 * its first instruction.
			 */
			if (lo < ctx->entry_off)
				lo = ctx->entry_off;
			va = kof_pz_off_to_addr(ctx, lo);
			if (va != KOF_BROKEN)
				kof_emu_set_rip(em, va);
		}
	}

	/*
	 * STOP BEFORE EVERY WAY INTO THE KERNEL. Both encodings, because i386
	 * reaches it through a software interrupt and amd64 through an
	 * instruction, and a stager is one or the other.
	 */
	kof_emu_watch_insn(em, pat_syscall, sizeof pat_syscall);
	kof_emu_watch_insn(em, pat_int80, sizeof pat_int80);

	while (stops++ < DIAG_EMU_STOPS) {
		enum kof_emu_stop st = kof_emu_run(em);
		uint64_t rip, off, arg[6], nr, ret;
		struct kof_diag_hit *h;
		uint16_t cap, node;
		uint8_t fl = 0;
		unsigned i, k;

		if (st != KOF_EMU_STOP_INSN)
			break;          /* exited, faulted, or ran out */

		rip = kof_emu_get_rip(em);
		off = kof_pz_addr_to_off(ctx, rip);

		/* The NUMBER is in the result register before the call and the
		 * RESULT is in it after, so it has to be taken now. */
		nr = kof_emu_get_reg(em, DIAG_EMU_RET);
		for (i = 0; i < 6u; i++)
			arg[i] = kof_emu_get_reg(em, areg[i]);


		/*
		 * LET THE EMULATOR MAKE THE CALL. Stepping rather than
		 * inventing a result: mmap has to return a mapping the
		 * program can then write into, and only the emulator's own
		 * implementation gives one out. kof_emu_step exists because
		 * the watch pauses BEFORE the instruction and resuming would
		 * pause on it again.
		 */
		kof_emu_step(em);
		ret = kof_emu_get_reg(em, DIAG_EMU_RET);

		cap = kof_flow_cap_of_syscall(bits, (uint32_t)nr, arg, &fl);

		/*
		 * ---- i386's socketcall KEEPS ITS ARGUMENTS IN MEMORY ------
		 *
		 * Every socket operation on i386 goes through one syscall,
		 * 102, with the operation in ebx and A POINTER TO THE REAL
		 * ARGUMENTS in ecx. Reading registers gives that demux pair
		 * and nothing else, so a connect has no descriptor and the
		 * network half of an i386 stager has nodes and no edges -
		 * measured on meter1_x86, where every node is present and
		 * net-connect has no parent.
		 *
		 * AFTER THE DEMUX, NOT BEFORE. The first attempt overwrote
		 * arg[] where it stood, which is where kof_flow_cap_of_syscall
		 * reads arg[0] to learn WHICH socket call this is - so the
		 * operation was gone before it was used.
		 */
		if (bits == 32u && nr == 102u) {
			uint64_t vec = arg[1];
			unsigned ai;

			for (ai = 0; ai < 6u; ai++) {
				uint8_t w[4];

				if (!kof_emu_read(em, vec + ai * 4u, w,
						  sizeof w))
					break;
				arg[ai] = (uint64_t)w[0] |
					  ((uint64_t)w[1] << 8) |
					  ((uint64_t)w[2] << 16) |
					  ((uint64_t)w[3] << 24);
			}
		}


		/*
		 * THE SAME SITE IS THE SAME NODE, however many times the run
		 * arrives - see the note on loops at the top.
		 */
		node = 0xffffu;
		for (i = 0; i < n_site; i++)
			if (sites[i].off == off) {
				node = sites[i].node;
				break;
			}
		if (node == 0xffffu) {
			if (cap == KOF_NUCLEO_NONE)
				continue;   /* no word for it; not a node */
			h = kof_diag_hit_add(s, off, cap, fl);
			if (!h)
				break;
			node = (uint16_t)(s->n_hit - 1u);
			if (n_site < DIAG_EMU_SITES) {
				sites[n_site].off = off;
				sites[n_site].node = node;
				n_site++;
			}
		} else {
			h = kof_diag_hit_of(s, node);
		}

		/*
		 * AND THE LINKS. An argument that IS a value an earlier call
		 * handed back is a link, and it is one the run demonstrated:
		 * the bytes travelled there, through whatever the program put
		 * in between. kof_diag_note_in ignores a repeat, so a loop
		 * records the link once.
		 */
		for (k = 0; k < 6u && h; k++) {
			uint8_t role = kof_diag_role_of_arg(cap, k);

			if (role == KOF_DIAG_ROLE_NONE)
				continue;
			for (i = n_made; i-- > 0; )
				if (made[i].val == arg[k]) {
					kof_diag_note_in(h, made[i].node, role,
							 KOF_DIAG_KIND_PRODUCED);
					break;
				}
		}

		/*
		 * FAILED. Walk the path on which it did not - see the note on
		 * success above. Nothing about the real world is asserted by
		 * doing so, and no link can come of it.
		 */
		if ((int64_t)ret < 0 && (int64_t)ret > -4096) {
			switch (cap_force_kind(cap)) {
			case FORCE_ZERO:
				ret = 0;
				break;
			case FORCE_HANDLE:
				ret = DIAG_EMU_FD0 + n_fd++;
				break;
			case FORCE_COUNT:
				ret = arg[2];
				/*
				 * A READ THAT SUCCEEDED PUT BYTES SOMEWHERE,
				 * and saying it returned n without writing n
				 * is a state no real machine is ever in. It
				 * also loses the finding: a stager's jump
				 * into its mapping is recorded as a hop only
				 * when the page has been WRITTEN, so a
				 * mapping that was never filled is one the
				 * run can enter without anything noticing.
				 *
				 * THE CONTENT IS OURS AND NOTHING MAY READ
				 * IT AS THE PROGRAM'S. Nops, so that control
				 * entering the region runs forward to its
				 * end rather than into whatever an
				 * uninitialised page decodes as. Nothing
				 * downstream looks at these bytes - a link
				 * comes from a register at a call site, not
				 * from memory - and if anything ever does,
				 * it will be reading this routine's writing.
				 */
				/* The buffer is NOT written - see the note on
				 * DIAG_EMU_FILL_ON. */
#if DIAG_EMU_FILL_ON
				fill_buffer(em, arg[1], arg[2]);
#endif
				break;
			default:
				break;
			}
			if (cap_force_kind(cap) != FORCE_NONE)
				kof_emu_set_reg(em, DIAG_EMU_RET, ret);
		}

		if (cap_hands_on_value(cap) && ret_is_carryable(ret)) {
			for (i = 0; i < n_made; i++)
				if (made[i].node == node)
					break;
			if (i == n_made && n_made < DIAG_EMU_MADE)
				n_made++;
			if (i < DIAG_EMU_MADE) {
				made[i].val = ret;
				/* An allocation's second argument is its
				 * length on every spelling of mmap this
				 * targets. A handle has no extent and gets
				 * zero, which is what keeps a descriptor
				 * from "containing" an address. */
				made[i].len = (cap == KOF_NUCLEO_ALLOC ||
					       cap == KOF_NUCLEO_ALLOC_EXEC ||
					       cap == KOF_NUCLEO_HEAP)
					      ? arg[1] : 0u;
				made[i].node = node;
				/*
				 * AND ASK THE INTERPRETER TO NOTICE IF
				 * CONTROL EVER ARRIVES HERE.
				 *
				 * This is what makes KOF_NUCLEO_EXEC_REG
				 * findable by a run: the jump into a mapping
				 * is not a syscall and nothing else would
				 * stop on it. The range is declared the
				 * moment the call hands it back, which is
				 * the only moment it is known - a region is
				 * not in the file and cannot be registered
				 * before the run.
				 */
				if (made[i].len)
					kof_emu_hop_add(em, ret,
							ret + made[i].len, 0);
			}
		}
	}

	/*
	 * ---- AND WHERE CONTROL WENT ------------------------------------
	 *
	 * The jump into the mapping is not a syscall, so nothing above sees
	 * it. The interpreter records a HOP whenever control enters a page
	 * the run wrote, and a hop that lands inside a region one of these
	 * calls produced is the whole of KOF_NUCLEO_EXEC_REG: code that was
	 * fetched, written, and then entered.
	 *
	 * ATTRIBUTED BY RANGE AND NOT BY GUESS. base+k belongs to the call
	 * that returned base and to no other, which is why `len` is kept.
	 * A hop into a page the run wrote that is NOT inside such a region -
	 * a stub relocating itself, a decoder rewriting its own body - is
	 * not this and is left alone.
	 *
	 * ONLY THE FIRST AND THE LAST are available without turning on the
	 * instruction trace, which kofemu.h says is a diagnostic and never
	 * something a scan runs with. For a stager there is one hop that
	 * matters and both report it; a run with many is one this routine
	 * under-reports rather than one it gets wrong.
	 *
	 * hop_count is how many ARRIVALS there were, not how many ranges are
	 * watched - zero means control never entered one of them.
	 */
	{
		uint64_t hop[2] = { 0, 0 };
		uint32_t n_hop = 0;
		unsigned q;

		kof_emu_first_hop(em, &(uint64_t){ 0 }, &hop[0]);
		kof_emu_last_hop(em, &hop[1], &n_hop);
		for (q = 0; q < 2u && n_hop; q++) {
			unsigned i;

			if (!hop[q])
				continue;
			if (q == 1u && hop[1] == hop[0])
				break;          /* one hop, reported twice */
			for (i = 0; i < n_made; i++) {
				struct kof_diag_hit *h;
				uint64_t off;

				if (!made[i].len ||
				    hop[q] < made[i].val ||
				    hop[q] - made[i].val >= made[i].len)
					continue;
				/*
				 * THE SITE IS NOT IN THE FILE, and saying it
				 * is would be the lie. Control is executing
				 * bytes the run produced; kof_pz_addr_to_off
				 * answers KOF_BROKEN for them, which is the
				 * engine's word for "applies, could not be
				 * determined" and is the truth here.
				 */
				off = kof_pz_addr_to_off(ctx, hop[q]);
				h = kof_diag_hit_add(s, off,
						     KOF_NUCLEO_EXEC_REG, 0);
				if (h)
					kof_diag_note_in(h, made[i].node,
							 KOF_DIAG_ROLE_TARGET,
							 KOF_DIAG_KIND_PRODUCED);
				break;
			}
		}
	}

	kof_emu_free(em);
}
