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
	case KOF_CAP_ALLOC:
	case KOF_CAP_ALLOC_EXEC:
	case KOF_CAP_HEAP:
	case KOF_CAP_NET_OPEN:
	case KOF_CAP_NET_RAW:
	case KOF_CAP_NET_ACCEPT:
	case KOF_CAP_FILE_OPEN:
	case KOF_CAP_MEMFD:
	case KOF_CAP_PIPE_OPEN:
		return 1;
	default:
		return 0;
	}
}

/*
 * WHICH INPUT OF THE CHILD THIS ARGUMENT IS.
 *
 * By capability and argument index: the role is a property of what the call
 * MEANS, the index is where the ABI happens to put it.
 */
static uint8_t role_of_arg(uint16_t cap, unsigned i)
{
	switch (cap) {
	/* The generic descriptor calls AND the file-specific ones: the role
	 * an argument plays is the same whatever the descriptor turns out to
	 * be, and the word is corrected later - see diag_refine. Listing only
	 * the file spelling is how the links vanished when read(2) was moved
	 * out of KOF_CG_FILE. */
	case KOF_CAP_MEM_READ:
	case KOF_CAP_MEM_WRITE:
	case KOF_CAP_READ:
	case KOF_CAP_WRITE:
	case KOF_CAP_NET_READ:
	case KOF_CAP_NET_WRITE:
		return i == 1u ? KOF_DIAG_ROLE_BUFFER
		     : i == 0u ? KOF_DIAG_ROLE_FD
			       : KOF_DIAG_ROLE_NONE;
	case KOF_CAP_NET_CONNECT:
	case KOF_CAP_NET_BIND:
	case KOF_CAP_NET_LISTEN:
	case KOF_CAP_NET_ACCEPT:
	case KOF_CAP_FD_REDIR:
		return i == 0u ? KOF_DIAG_ROLE_FD : KOF_DIAG_ROLE_NONE;
	case KOF_CAP_EXEC_IMAGE:
		return i == 0u ? KOF_DIAG_ROLE_PATH : KOF_DIAG_ROLE_NONE;
	default:
		return KOF_DIAG_ROLE_NONE;
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
 *               reason: it shares KOF_CAP_ALLOC with mmap, so the capability
 *               alone cannot say whether 0 or a pointer is the success. That
 *               is a thing to fix in the vocabulary, not to guess at here.
 */
enum force_kind { FORCE_NONE = 0, FORCE_ZERO, FORCE_HANDLE, FORCE_COUNT };

static enum force_kind cap_force_kind(uint16_t cap)
{
	switch (cap) {
	case KOF_CAP_NET_CONNECT:
	case KOF_CAP_NET_BIND:
	case KOF_CAP_NET_LISTEN:
	case KOF_CAP_FD_REDIR:
		return FORCE_ZERO;
	case KOF_CAP_NET_OPEN:
	case KOF_CAP_NET_RAW:
	case KOF_CAP_NET_ACCEPT:
	case KOF_CAP_FILE_OPEN:
	case KOF_CAP_MEMFD:
	case KOF_CAP_PIPE_OPEN:
		return FORCE_HANDLE;
	/* The generic descriptor calls AND the file-specific ones: the role
	 * an argument plays is the same whatever the descriptor turns out to
	 * be, and the word is corrected later - see diag_refine. Listing only
	 * the file spelling is how the links vanished when read(2) was moved
	 * out of KOF_CG_FILE. */
	case KOF_CAP_MEM_READ:
	case KOF_CAP_MEM_WRITE:
	case KOF_CAP_READ:
	case KOF_CAP_WRITE:
	case KOF_CAP_NET_READ:
	case KOF_CAP_NET_WRITE:
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
	uint16_t cap;           /* KOF_CAP_NONE for an internal call */
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
	g->site[g->n].cap = target ? KOF_CAP_NONE
				   : (name ? kof_flow_cap_of_name(name)
					   : KOF_CAP_NONE);
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

struct seenval {
	uint64_t val;
	uint16_t node;
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

			if (p && p->at >= fns[j].va &&
			    p->at < fns[j].va + fns[j].size) {
				only = (uint16_t)i;
				cnt++;
			}
		}
		return cnt == 1u ? only : 0xffffu;
	}
	return 0xffffu;
}

static void run_rel_gaps(struct kof_diag_scan *s,
			 const struct kof_obj_ctx *ctx,
			 const struct kof_elf_info *ei,
			 const uint8_t *base, uint64_t size)
{
	static struct skipsite skips[DIAG_REL_SKIPS];
	static struct funcspan fns[DIAG_REL_FUNCS];
	static uint16_t ret[DIAG_REL_FUNCS];
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
	for (j = 0; j < fg.n; j++)
		ret[j] = 0xffffu;

	for (pass = 0; pass < DIAG_REL_PASSES; pass++) {
	int changed = 0;

	for (j = 0; j < fg.n; j++) {
		struct seenval seen[DIAG_REL_SEEN];
		struct kof_emu *em;
		uint32_t n_seen = 0, step;
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
					if (skips[w].cap != KOF_CAP_NONE ||
					    (skips[w].callee &&
					     callee_node(s, fns, fg.n,
							 skips[w].callee) !=
					     0xffffu))
						reach++;
				}
				if (reach < 2u)
					continue;
			}
		}

		em = build_rel_image(ctx, ei, base, size);
		if (!em)
			return;
		kof_emu_set_rip(em, DIAG_REL_BASE + lo);

		for (step = 0; step < DIAG_REL_STEPS; step++) {
			uint64_t rip = kof_emu_get_rip(em) - DIAG_REL_BASE;
			enum kof_emu_stop st;
			int skipped = 0;

			if (rip < lo || rip >= hi)
				break;          /* left the function */

			for (q = 0; q < sg.n; q++) {
				uint16_t node = 0xffffu;
				unsigned k, i;

				if (skips[q].call_at != rip)
					continue;

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
						  kof_diag_sym_role_of_arg(
							h->cap, k);
						uint64_t v = kof_emu_get_reg(em,
						  kof_diag_sysv_arg[k]);
						uint32_t t;

						if (role == KOF_DIAG_ROLE_NONE)
							continue;
						for (t = 0; t < n_seen; t++)
							if (seen[t].val == v &&
							    seen[t].node != node)
								kof_diag_note_in(
								  h,
								  seen[t].node,
								  role);
						if (worth_remembering(v, size) &&
						    n_seen < DIAG_REL_SEEN) {
							seen[n_seen].val = v;
							seen[n_seen].node = node;
							n_seen++;
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
							n_seen++;
						}
					}
				}
				skipped = 1;
				break;
			}
			if (skipped)
				continue;

			/*
			 * A SPAN THAT CANNOT BE WALKED ENDS QUIETLY. An
			 * unapplied relocation sends a load somewhere the
			 * file does not reach; the run stops and the span
			 * reports nothing, which is the honest answer rather
			 * than a wrong one.
			 */
			st = kof_emu_step(em);
			if (st == KOF_EMU_STOP_FAULT ||
			    st == KOF_EMU_STOP_DECODE ||
			    st == KOF_EMU_STOP_UNSUPPORTED)
				break;
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
			if (ret[j] != was)
				changed = 1;
		}
		kof_emu_free(em);
	}
	if (!changed)
		break;
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
			if (cap == KOF_CAP_NONE)
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
			uint8_t role = role_of_arg(cap, k);

			if (role == KOF_DIAG_ROLE_NONE)
				continue;
			for (i = n_made; i-- > 0; )
				if (made[i].val == arg[k]) {
					kof_diag_note_in(h, made[i].node, role);
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
				made[i].len = (cap == KOF_CAP_ALLOC ||
					       cap == KOF_CAP_ALLOC_EXEC ||
					       cap == KOF_CAP_HEAP)
					      ? arg[1] : 0u;
				made[i].node = node;
				/*
				 * AND ASK THE INTERPRETER TO NOTICE IF
				 * CONTROL EVER ARRIVES HERE.
				 *
				 * This is what makes KOF_CAP_EXEC_REG
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
	 * calls produced is the whole of KOF_CAP_EXEC_REG: code that was
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
						     KOF_CAP_EXEC_REG, 0);
				if (h)
					kof_diag_note_in(h, made[i].node,
							 KOF_DIAG_ROLE_TARGET);
				break;
			}
		}
	}

	kof_emu_free(em);
}
