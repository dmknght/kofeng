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
	if (!ei || !ei->valid || !ei->seg_count)
		return;
	bits = ctx->arch == KOF_ARCH_X86_64 ? 64u : 32u;
	areg = bits == 64u ? arg_reg64 : arg_reg32;

	memset(&rep, 0, sizeof rep);
	em = kof_emu_unp_build(base, size, ei, DIAG_EMU_INSN, DIAG_EMU_PAGES,
			       &rep);
	if (!em)
		return;

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
