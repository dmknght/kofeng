/* See flow.h. */

#include "flow.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bddisasm.h"
#include "gpr.h"
#include "vocab.h"



/*
 * THE CONSTANT MAP. One value per GPR plus how much of it is known.
 *
 * `known` is a byte count and not a flag because of `mov al, 3`, which is what
 * a hand-written stager uses to save two bytes: the low eight bits are exact
 * and the rest is whatever was there. A syscall number under 256 is decided by
 * those eight bits, so the value is usable - and the node says it was, through
 * KOF_FLOWF_LOW8, rather than pretending the register was fully known.
 */
/*
 * HOW DEEP THE STACK IS FOLLOWED.
 *
 * Sixteen, because what this is for is short: a stub saves a pointer, does
 * three or four other things, and takes it back. A depth beyond this is a
 * compiler's frame, and a frame is where the slot model in xref.c belongs
 * rather than this one.
 */
#define NSLOT 16u

struct cmap {
	uint64_t v[NGPR];
	uint8_t  known[NGPR];   /* 0, 1, 2, 4 or 8 bytes */
	/*
	 * AND WHERE THE VALUE CAME FROM - the node that returned it, as index
	 * plus one. A constant and a provenance are different facts about the
	 * same register and both are wanted: the first resolves a selector,
	 * the second builds the chain.
	 */
	uint16_t src[NGPR];

	/*
	 * AND WHETHER THE REGISTER HOLDS AN IMPORT'S ADDRESS.
	 *
	 * `mov edi, [IAT] ; ... ; call edi` is how a PE calls the same import
	 * twice without paying for the slot read each time, and it is what
	 * real malware does: measured on a VirusSign sample that maps
	 * executable memory, every API call in the stub is `call *%edi`. A
	 * reader that only understands `call [slot]` sees none of them.
	 */
	uint32_t rcap[NGPR];   /* KOF_FLOW_ANSWER_N of an import slot */

	/*
	 * AND WHETHER THE REGISTER HOLDS AN ADDRESS INSIDE THIS OBJECT'S OWN
	 * CODE, taken from the instruction pointer rather than from anywhere
	 * a loader wrote.
	 *
	 * There is one way to get that on x86 without a relocation, and it is
	 * `call <next>` followed by `pop reg`. A compiler does not emit it -
	 * position-independent i386 code calls a thunk that does `mov ebx,
	 * [esp]; ret`, which is a read and not a pop - so what is left is
	 * code that wants its own address because nothing told it where it
	 * was loaded.
	 *
	 * What it is FOR is the step after: `push <imm>; call *%ebp`, where
	 * ebp is that address. The program is calling a dispatcher it built
	 * itself and choosing the destination with a number. See
	 * KOF_CAP_CALL_REG.
	 */
	uint8_t selfp[NGPR];

	/*
	 * THE STACK, AND IT IS THE POINT RATHER THAN A DETAIL.
	 *
	 * A loader does not keep its mapping in a register across four
	 * syscalls - it pushes it. Measured on the meterpreter x64 stager:
	 *
	 *     syscall            rax = the mapping
	 *     push rax                 saved
	 *     ... socket, connect, sleep, retry ...
	 *     pop  rsi                 taken back
	 *     jmp  rsi                 and executed
	 *
	 * Without following the push the chain breaks in the middle and the
	 * one edge worth having is lost. Following it is a counter and an
	 * array - no addresses, no aliasing, no memory model - because push
	 * and pop are the only two things a stub does with it.
	 *
	 * ANYTHING ELSE THAT MOVES rsp THROWS IT AWAY. A `sub rsp, 0x20` is a
	 * frame being built and what was below it is no longer where this
	 * thinks it is; guessing there would produce a pointer that is not the
	 * one that was saved.
	 */
	uint64_t sv[NSLOT];
	uint8_t  sknown[NSLOT];
	uint16_t ssrc[NSLOT];
	uint8_t  depth;
};

static void set_const(struct cmap *c, uint32_t r, uint64_t val, uint8_t size)
{
	if (r >= NGPR)
		return;
	/*
	 * A CONSTANT IS NOT A PRODUCED POINTER, and forgetting to say so was a
	 * measured bug rather than a hypothetical one: `mov eax, 5` after a
	 * call left the register still claiming to hold that call's result, so
	 * an ordinary `call rax` later read as "the thing fopen returned was
	 * executed". Three /usr/bin binaries reported that edge and none of
	 * them has it.
	 */
	c->src[r] = 0;
	if (size >= 4) {
		/* A 32-bit write zeroes the top half on x86-64, and a 64-bit
		 * one replaces everything; either way the register is known. */
		c->v[r] = val;
		c->known[r] = 8;
	} else {
		/* Only the low part is known. Keep the value so a number under
		 * 256 still resolves, and keep the width so the caller can see
		 * how strong the claim is. */
		c->v[r] = val & (size == 1 ? 0xffu : 0xffffu);
		if (c->known[r] < size)
			c->known[r] = size;
	}
}

static void stack_push(struct cmap *c, uint64_t val, uint8_t known,
		       uint16_t src)
{
	if (c->depth < NSLOT) {
		c->sv[c->depth] = val;
		c->sknown[c->depth] = known;
		c->ssrc[c->depth] = src;
	}
	if (c->depth < 255u)
		c->depth++;
}

/* Deeper than the model goes, so what comes back is not known. */
static int stack_pop(struct cmap *c, uint64_t *val, uint8_t *known,
		     uint16_t *src)
{
	if (!c->depth)
		return 0;
	c->depth--;
	if (c->depth >= NSLOT)
		return 0;
	*val = c->sv[c->depth];
	*known = c->sknown[c->depth];
	*src = c->ssrc[c->depth];
	return 1;
}

static void stack_drop(struct cmap *c)
{
	memset(c->sv, 0, sizeof c->sv);
	memset(c->sknown, 0, sizeof c->sknown);
	memset(c->ssrc, 0, sizeof c->ssrc);
	c->depth = 0;
}

/*
 * THE Nth ARGUMENT OF A 32-BIT CALL, which is on the STACK and not in a
 * register.
 *
 * stdcall and cdecl both push right to left, so at the call the first argument
 * is on top and the Nth is N slots down - exactly the array the push/pop model
 * already maintains. Without this every Windows i386 program is unreadable on
 * the one axis that matters: measured on 1270 PE samples, 676 call something
 * that maps memory and ONE of them had a protection word this could read,
 * because the other 675 put it on the stack.
 *
 * The x86-64 conventions pass in registers and do not come here.
 */
static int stack_arg(const struct cmap *c, uint32_t nth, uint64_t *out,
		     uint16_t *src)
{
	uint32_t at;

	if (c->depth <= nth)
		return 0;
	at = c->depth - 1u - nth;
	if (at >= NSLOT || !c->sknown[at])
		return 0;
	if (out) *out = c->sv[at];
	if (src) *src = c->ssrc[at];
	return 1;
}


/*
 * A JOIN CLEARS THE REGISTERS AND KEEPS THE STACK.
 *
 * Both halves are measured rather than assumed. Carrying REGISTERS into a
 * block that can be entered from elsewhere produced a false edge in gdb - see
 * the note on the target set. Carrying the STACK does not, because a stub that
 * branches locally keeps its stack balanced across the branch: the pop that
 * takes the mapping back in the meterpreter stager IS a branch target, and
 * clearing there loses the edge the whole file exists to find.
 *
 * The asymmetry is a claim about how code is written, so it is checked the way
 * every other claim here is - by counting false edges on /usr/bin with it on.
 */
static void join_clear(struct cmap *c)
{
	memset(c->v, 0, sizeof c->v);
	memset(c->known, 0, sizeof c->known);
	memset(c->rcap, 0, sizeof c->rcap);
	/*
	 * AND THE PROVENANCE SURVIVES, which is the second exception and a
	 * weaker claim than the ones above it.
	 *
	 * `v` is "this register is 0x1234" - a fact about ONE path, and a
	 * join joins two. `src` is "this register holds what node N
	 * produced", which is about the register, and every instruction that
	 * writes the register goes through forget() and clears it. For this
	 * to be wrong, a path the sweep has not walked yet must write the
	 * register and leave it written.
	 *
	 * WHAT IT BUYS, and the reason it is worth the risk: a descriptor
	 * does not survive a retry loop in a register, it survives on the
	 * stack. On msfvenom's x86-64 stager the socket is put in rdi, the
	 * loop head at 0xac is a join, and the body saves and restores rdi
	 * around the sleep - so the register holds the same thing at every
	 * point the sweep cares about and held NOTHING the moment the loop
	 * was entered. `connect` and `read` therefore had no link back to
	 * the socket, and "reads from the socket it opened into the memory
	 * it mapped" - the whole shape - could not be said.
	 *
	 * The cost is a wrong edge where a loop body overwrites a register
	 * and does not put it back. Measured on 12561 x86 objects: see the
	 * note in the blind-spot log; the chain count moved by less than it
	 * does for a rounding change, and the edges on the samples whose
	 * source is known came out right.
	 */
	/*
	 * AND selfp IS NOT CLEARED HERE, which is the one exception.
	 *
	 * Everything else in this map is a fact about a path - what the
	 * register held when control came this way - so a join that joins two
	 * paths has to drop it. "This register holds an address in my own
	 * code" is not that kind of fact: it is about the register, it is set
	 * once at the top of the body, and EVERY write to the register goes
	 * through forget(), which does clear it. For it to be wrong here, one
	 * path would have to set it and the other reach the join without ever
	 * writing the register at all.
	 *
	 * Clearing it measured badly and in the direction that matters: on
	 * one MSF stager the dispatcher is called nineteen times and only the
	 * three before the first loop survived, so the body looked like a
	 * thunk instead of like a program with no other way out.
	 */
}

/*
 * AND THE STRONGER ONE, for a point that nothing falls into.
 *
 * join_clear keeps the provenance because at a JOIN the register may well
 * hold the same thing down every path. After a `ret`, an unconditional
 * `jmp` or a syscall that never returns, the next instruction in ADDRESS
 * order is not a successor at all - there is no path, so there is nothing to
 * agree about, and keeping provenance there is how one function's socket
 * becomes another function's edge.
 *
 * `selfp` is the exception within the exception: a `jmp` stays inside the
 * body, so the register still holds this object's own code. A `ret` does
 * not, and the caller clears it there.
 */
static void cut_clear(struct cmap *c)
{
	join_clear(c);
	memset(c->src, 0, sizeof c->src);
}

static void forget(struct cmap *c, uint32_t r)
{
	if (r < NGPR) {
		c->v[r] = 0;
		c->known[r] = 0;
		c->src[r] = 0;
		c->rcap[r] = KOF_CAP_NONE;
		c->selfp[r] = 0;
	}
}

/*
 * THE ARGUMENT REGISTERS, per ABI.
 *
 * Both lists are the calling convention and nothing subtler: a Linux syscall
 * takes rdi, rsi, rdx, r10, r8, r9 and the SysV call takes rdi, rsi, rdx, rcx,
 * r8, r9 - the two differ only in the fourth. i386 takes ebx, ecx, edx, esi,
 * edi. Read only to ask WHICH EARLIER NODE produced one of them, never to work
 * out what the argument means.
 */
/*
 * THE FIRST FOUR ARGUMENTS, IN ORDER, per convention. Order matters now: the
 * caller asks which NODE produced argument 1, so the table has to be the
 * convention's own sequence and not a set of registers to search.
 */
static const uint8_t arg_sys64[] = { 7u, 6u, 2u, 10u };   /* rdi rsi rdx r10 */
static const uint8_t arg_sysv[]  = { 7u, 6u, 2u, 1u };    /* rdi rsi rdx rcx */
static const uint8_t arg_ms[]    = { 1u, 2u, 8u, 9u };    /* rcx rdx r8  r9  */
static const uint8_t arg_sys32[] = { 3u, 1u, 2u, 6u };    /* ebx ecx edx esi */

/*
 * FILL IN WHERE EACH ARGUMENT CAME FROM - a produced value, a constant, or
 * neither.
 *
 * `by_call` picks the convention: a 32-bit CALL passes on the stack, a 32-bit
 * syscall in registers, and the two 64-bit conventions differ in their fourth.
 */
/*
 * DROP WHAT IS PAST THE CALL'S LAST ARGUMENT.
 *
 * arg_scan reads the ABI's four argument registers because that is all it
 * can do - the registers are there whether the call uses them or not. Only
 * the NAME says how many are real, so the trim happens here, after the node
 * has one. See kof_sys_argc for what a leftover looked like.
 */
/*
 * A READ FROM A SOCKET IS NOT A READ FROM A FILE, and the chain already
 * knows which: the descriptor argument links back to the step that made it.
 *
 * Read from the EDGE rather than from the name, because the name cannot
 * say - `read(4, buf, n)` is the same four bytes of machine code either
 * way. See KOF_CAP_NET_READ. `out` is the node being built and `all` the
 * nodes made so far in this sweep, which is where from[] points.
 */
static uint8_t net_fd_cap(const struct kof_flow_node *all, uint32_t n,
			  const struct kof_flow_node *out)
{
	uint16_t src = out->from[0];
	uint8_t  p;

	if (out->cap != KOF_CAP_READ && out->cap != KOF_CAP_WRITE)
		return out->cap;
	if (!src || src > n)
		return out->cap;
	p = all[src - 1u].cap;
	if (p != KOF_CAP_NET_OPEN && p != KOF_CAP_NET_ACCEPT &&
	    p != KOF_CAP_NET_RAW)
		return out->cap;
	return out->cap == KOF_CAP_READ ? KOF_CAP_NET_READ
					: KOF_CAP_NET_WRITE;
}

static void arg_trim(struct kof_flow_node *out)
{
	uint8_t k = kof_sys_argc(kof_flow_name_of(out->name));
	uint32_t i;

	if (!k)
		return;             /* arity not written down: say nothing */
	for (i = k; i < KOF_FLOW_ARGS; i++) {
		out->from[i] = 0;
		out->from_va[i] = 0;
		out->arg[i] = 0;
		out->arg_const &= (uint8_t)~(1u << i);
	}
}

static void arg_scan(const struct cmap *c, unsigned bits, unsigned abi,
		     int by_call, struct kof_flow_node *out)
{
	const uint8_t *a;
	uint32_t i;

	if (bits == 32 && by_call) {
		for (i = 0; i < KOF_FLOW_ARGS; i++) {
			uint64_t v;
			uint16_t sr = 0;

			if (!stack_arg(c, i, &v, &sr))
				continue;
			out->from[i] = sr;
			if (!sr) {
				out->arg_const |= (uint8_t)(1u << i);
				out->arg[i] = v;
			}
		}
		return;
	}
	a = bits == 32 ? arg_sys32
		       : (by_call ? (abi == KOF_FLOW_MS ? arg_ms : arg_sysv)
				  : arg_sys64);
	for (i = 0; i < KOF_FLOW_ARGS; i++) {
		uint32_t r = a[i];

		if (r >= NGPR)
			continue;
		out->from[i] = c->src[r];
		/*
		 * A CONSTANT AND A PROVENANCE ARE EXCLUSIVE HERE. set_const
		 * clears src precisely so that a number written into the
		 * instruction is never also reported as something an earlier
		 * call produced.
		 */
		if (!c->src[r] && c->known[r]) {
			out->arg_const |= (uint8_t)(1u << i);
			out->arg[i] = c->v[r];
		}
	}
}

uint16_t kof_flow_from_any(const struct kof_flow_node *n)
{
	uint32_t i;

	if (!n)
		return 0;
	for (i = 0; i < KOF_FLOW_ARGS; i++)
		if (n->from[i])
			return n->from[i];
	return 0;
}

/* The register a value has to be in to be read as a number, and whether it is
 * usable at all. Zero-known means the sweep never saw it set. */
static int const_of(const struct cmap *c, uint32_t r, uint64_t *out, int *low8)
{
	if (r >= NGPR || !c->known[r])
		return 0;
	*out = c->v[r];
	*low8 = c->known[r] < 4;
	return 1;
}

/*
 * IS THIS INSTRUCTION NOTHING.
 *
 * The forms a compiler and a padder both emit. Not a junk-code detector - see
 * the note in flow.h about what this does and does not defend against.
 */
static int is_nop(const INSTRUX *ix)
{
	if (ix->Instruction == ND_INS_NOP)
		return 1;
	/* xchg ax, ax and its longer spellings decode as XCHG with both
	 * operands the same register. */
	if (ix->Instruction == ND_INS_XCHG && ix->OperandsCount >= 2 &&
	    ix->Operands[0].Type == ND_OP_REG &&
	    ix->Operands[1].Type == ND_OP_REG &&
	    ix->Operands[0].Info.Register.Reg ==
	    ix->Operands[1].Info.Register.Reg)
		return 1;
	/* lea r, [r] - an address generation that changes nothing. */
	if (ix->Instruction == ND_INS_LEA && ix->OperandsCount >= 2 &&
	    ix->Operands[1].Type == ND_OP_MEM &&
	    !ix->Operands[1].Info.Memory.HasIndex &&
	    !ix->Operands[1].Info.Memory.HasDisp &&
	    ix->Operands[1].Info.Memory.HasBase &&
	    ix->Operands[1].Info.Memory.Base ==
	    ix->Operands[0].Info.Register.Reg)
		return 1;
	return 0;
}

/*
 * WHICH REGISTER HOLDS WHAT AT A SYSCALL.
 *
 * The selector and the one argument this cares about - the protection word,
 * which is what separates "mapped something" from "mapped something it can
 * run". Everything else is deliberately not read: a rule about WHERE it
 * connects needs runtime data, and this file exists because the rule that
 * matters does not.
 */
#define R_RAX 0u
#define R_RCX 1u
#define R_RDX 2u
#define R_RBX 3u

#define R_R8  8u
#define R_R9  9u
#define R_RSI 6u
#define R_RDI 7u
/* The stack pointer, which is not an argument register and is here only so
 * pc_thunk can recognise `mov reg, [esp]` - gcc's get-PC thunk. */
#define R_RSP 4u

/*
 * IS THIS NUMBER A WINDOWS PAGE PROTECTION AT ALL.
 *
 * The base protections are an ENUMERATION and not a mask: exactly one of
 * PAGE_NOACCESS 0x01 ... PAGE_EXECUTE_WRITECOPY 0x80, optionally with the
 * modifier bits PAGE_GUARD 0x100, PAGE_NOCACHE 0x200, PAGE_WRITECOMBINE 0x400
 * and PAGE_TARGETS_NO_UPDATE 0x40000000 on top.
 *
 * That shape is what lets the argument be found without knowing which import
 * was called - see prot_cap. MEM_COMMIT|MEM_RESERVE is 0x3000 and has nothing
 * in the low byte, so it cannot be mistaken for one; a pointer has bits
 * outside the allowed set, so neither can that.
 */
static int is_page_prot(uint64_t v)
{
	uint64_t base = v & 0xffu;

	if (v & ~0x400007ffull)
		return 0;
	return base && (base & (base - 1u)) == 0;
}

/* Windows names the combinations instead of masking them, so the two that are
 * writable and executable at once have to be named too. */
static uint8_t ms_cap(uint64_t prot, uint8_t *flags)
{
	if ((prot & 0xc0u) && flags)
		*flags |= KOF_FLOWF_WX;
	return (prot & 0xf0u) ? KOF_CAP_ALLOC_EXEC : KOF_CAP_ALLOC;
}

/*
 * A THREAD IS A CLONE THAT KEPT THE ADDRESS SPACE.
 *
 * CLONE_THREAD is bit 16, so a selector known only in its low eight - which
 * const_of reports and this refuses on - says nothing about it. Unknown
 * returns SPAWN, the weaker claim, for the same reason prot_cap returns
 * ALLOC: a wrong strong answer costs a false positive and a wrong weak one
 * costs a detection.
 *
 * The LIBC WRAPPER is not refined here and is not meant to be: clone(3) puts
 * flags third while the syscall puts them first, so reading the first
 * register would be reading the start function. The name table answers that
 * case instead - see pthread_create.
 */
static uint8_t clone_cap(const struct cmap *c, unsigned bits)
{
	uint64_t fl;
	int low8 = 0;

	if (!const_of(c, bits == 32 ? R_RBX : R_RDI, &fl, &low8) || low8)
		return KOF_CAP_SPAWN;
	return (fl & FLOW_CLONE_THREAD) ? KOF_CAP_THREAD : KOF_CAP_SPAWN;
}

/*
 * A RAW SOCKET, FROM THE TYPE ARGUMENT.
 *
 * socket(domain, type, protocol) - SOCK_RAW is 3, and SOCK_NONBLOCK and
 * SOCK_CLOEXEC are high bits ORed on top, so the low nibble is the type and a
 * low-eight answer is still a true one.
 *
 * SIXTY-FOUR BIT ONLY. i386 multiplexes through socketcall and passes the
 * three arguments in a struct the sweep would have to read through a pointer,
 * which is a memory model this does not have. It stays NET_OPEN there - a
 * weaker claim, not a wrong one.
 */
/*
 * WHAT KIND OF SOCKET, from the two arguments that say so.
 *
 * socket(domain, type, protocol): the DOMAIN separates a network socket from
 * desktop IPC and the TYPE separates a stream from a datagram. Both are small
 * constants written into the instruction, and both are read where they are
 * rather than inferred from what the program does with the result.
 *
 * Each is independent: an argument the sweep could not follow leaves its flag
 * unset, which is "not seen" and not "no".
 */

static uint8_t sock_cap(const struct cmap *c, unsigned bits, unsigned abi,
			int by_call, uint8_t *flags)
{
	uint64_t dom, ty;
	int low8 = 0, have_dom, have_ty;

	if (by_call) {
		/*
		 * socket(3) TAKES THE SAME TWO ARGUMENTS FIRST, which is why
		 * this reads at a call site at all: the libc wrapper does not
		 * reorder them the way clone(3) reorders the syscall's. Only
		 * the places they arrive in change, and on i386 - where the
		 * SYSCALL is a socketcall through a struct this cannot read -
		 * a CALL puts them on the stack where it can.
		 */
		if (bits == 32) {
			have_dom = stack_arg(c, 0u, &dom, NULL);
			have_ty  = stack_arg(c, 1u, &ty, NULL);
		} else if (abi == KOF_FLOW_MS) {
			have_dom = const_of(c, R_RCX, &dom, &low8);
			have_ty  = const_of(c, R_RDX, &ty, &low8);
		} else {
			have_dom = const_of(c, R_RDI, &dom, &low8);
			have_ty  = const_of(c, R_RSI, &ty, &low8);
		}
	} else {
		if (bits == 32)
			return KOF_CAP_NET_OPEN;  /* socketcall: in a struct */
		have_dom = const_of(c, R_RDI, &dom, &low8);
		have_ty  = const_of(c, R_RSI, &ty, &low8);
	}
	if (have_dom && (dom & 0xffu) == FLOW_AF_UNIX && flags)
		*flags |= KOF_FLOWF_LOCAL;
	if (!have_ty)
		return KOF_CAP_NET_OPEN;
	if ((ty & 0xfu) == FLOW_SOCK_RAW)
		return KOF_CAP_NET_RAW;
	if ((ty & 0xfu) == FLOW_SOCK_DGRAM && flags)
		*flags |= KOF_FLOWF_DGRAM;
	return KOF_CAP_NET_OPEN;
}

static uint8_t prot_cap(const struct cmap *c, unsigned abi, unsigned bits,
			int by_call, uint8_t *flags)
{
	uint64_t prot;
	int low8;

	/*
	 * WHICH ARGUMENT HOLDS IT DEPENDS ON WHICH FUNCTION WAS CALLED, and by
	 * the time this runs the name is gone - the resolver answered with a
	 * capability, which is the whole point of the capability vocabulary.
	 *
	 *     VirtualProtect(addr, size, flNewProtect, lpflOld)   third
	 *     VirtualAlloc(addr, size, flAllocationType, flProt)  FOURTH
	 *     mmap(addr, len, prot, flags, fd, off)               third
	 *     mprotect(addr, len, prot)                           third
	 *
	 * So on Windows BOTH are tried and the SHAPE OF THE VALUE decides -
	 * see is_page_prot. Reading the third only made every VirtualAlloc an
	 * ordinary allocation, which is the quietest possible way to lose the
	 * strongest term on the platform where it matters most: measured, the
	 * 39 alloc-exec nodes found in 1500 PE samples were all VirtualProtect
	 * and not one of them was a VirtualAlloc.
	 *
	 * VirtualAllocEx KEEPS IT FIFTH, on the stack and past every register
	 * this sweep tracks, so it stays an ordinary allocation and is not
	 * claimed to be anything else.
	 *
	 * POSIX needs none of this: prot is the third argument in both calls
	 * that take one, and its three bits are a mask rather than an
	 * enumeration, so there is no shape to test.
	 */
	if (by_call && bits == 32) {
		if (abi == KOF_FLOW_MS) {
			if (!stack_arg(c, 2u, &prot, NULL) ||
			    !is_page_prot(prot))
				if (!stack_arg(c, 3u, &prot, NULL) ||
				    !is_page_prot(prot))
					return KOF_CAP_ALLOC;
			return ms_cap(prot, flags);
		}
		if (!stack_arg(c, 2u, &prot, NULL))
			return KOF_CAP_ALLOC;
	} else if (abi == KOF_FLOW_MS) {
		if (!const_of(c, R_R8, &prot, &low8) || !is_page_prot(prot))
			if (!const_of(c, R_R9, &prot, &low8) ||
			    !is_page_prot(prot))
				return KOF_CAP_ALLOC;
		return ms_cap(prot, flags);
	} else if (!const_of(c, R_RDX, &prot, &low8)) {
		return KOF_CAP_ALLOC;    /* unknown - claim the weaker thing */
	}
	/*
	 * AND THE WORD MEANS DIFFERENT THINGS. POSIX packs the three
	 * permissions into three bits and execute is bit 2; Windows enumerates
	 * the combinations and every one that can be executed is in the high
	 * nibble - PAGE_EXECUTE 0x10 through PAGE_EXECUTE_WRITECOPY 0x80. A
	 * mask written for one reads the other as never executable, which is
	 * the quietest possible way to lose the strongest term here.
	 */
	if ((prot & 6u) == 6u && flags)
		*flags |= KOF_FLOWF_WX;
	return (prot & 4u) ? KOF_CAP_ALLOC_EXEC : KOF_CAP_ALLOC;
}


/* ---- the sweep ------------------------------------------------------------
 *
 * ONE PASS, and everything else is bookkeeping over what it saw.
 *
 * A linear sweep and not a recursive descent, for the reason xref.c gives: a
 * recursive walk needs every entry point to be known, and the objects this is
 * aimed at - a stripped blob, a payload carved out of a variable - have none.
 * What a linear sweep costs is that data in code decodes as instructions; what
 * it buys is that nothing has to be reachable to be seen.
 */

#define MAX_LOOP 4096u

struct loopspan { uint64_t lo, hi; };

struct thunkrow { uint64_t va; uint32_t ans; };

struct kof_flow {
	struct kof_flow_node node[KOF_FLOW_MAX_NODE];
	uint32_t n_node;

	/* Function heads, in the order met; sorted and deduplicated by
	 * finish(). The code start of every added run is one, so a blob with
	 * no calls in it is still one region rather than none. */
	uint64_t *head;
	uint32_t n_head;

	struct kof_flow_func *func;
	uint32_t n_func;

	struct loopspan loop[MAX_LOOP];
	uint32_t n_loop;

	/*
	 * THE BLOCK GRAPH, which is what turns "A is at a lower address than B"
	 * into "B can be reached from A". Built by the same sweep that finds
	 * the nodes - a block ends where control leaves it, and begins where
	 * control can arrive.
	 *
	 * Two successors at most, which is all a direct branch has: the taken
	 * edge and the fall-through. An indirect branch has neither recorded,
	 * and a block that ends in one is a dead end HERE without being one in
	 * the program - which is why what cannot be proved comes back UNKNOWN.
	 */
	/*
	 * CALL EDGES, as addresses. Resolved to function indices by finish(),
	 * because during the sweep the functions are not numbered yet - the
	 * heads are still being discovered and are not in order.
	 */
	struct cedge {
		uint64_t site;      /* the call instruction itself */
		uint64_t to_va;     /* the head it goes to */
		uint32_t site_step; /* where the call sits among the steps,
				     * which is where the callee's nodes
				     * belong when a chain inlines them */
		uint16_t from_func, to_func;   /* filled in by finish() */
		/*
		 * WHAT THE CALLER HAD IN THE ARGUMENT REGISTERS, HERE.
		 *
		 * The sweep walks ADDRESS order, and on a statically linked
		 * program the syscall is inside a libc wrapper while its
		 * arguments were set by the caller somewhere else entirely.
		 * Measured on a MIPS bot: `li $v0,4183 ; syscall` preceded by
		 * nothing but the wrapper's own prologue - $a0..$a3 came from
		 * a function the sweep had passed long before.
		 *
		 * So the call site snapshots them, and finish() hands them to
		 * the callee's nodes. It is the one place where the caller and
		 * the callee are both in hand.
		 */
		uint64_t arg[4];
		uint16_t argsrc[4];
		uint8_t  argk;          /* bit a: arg[a] is a known constant */
		/*
		 * AND WHAT WAS IN THE SELECTOR REGISTER, which on i386 is the
		 * whole of what a syscall thunk needs from its caller.
		 *
		 * glibc's static i386 build ends a function and begins the
		 * next with `ret ; int 0x80` - the interrupt is a body of its
		 * own and eax was set by whoever called it. Disassembled on a
		 * static-PIE Mirai sample at 0x13d43:
		 *
		 *     13d43:  c3        ret
		 *     13d44:  cd 80     int 0x80
		 *
		 * so the sweep reaches the interrupt with nothing in eax and
		 * emits no node at all. Measured: swept directly, 107 of
		 * these objects produced 1 to 2 nodes each against 1 to 25
		 * for the ET_EXEC builds beside them.
		 */
		uint64_t sel;
		uint8_t  selk;
		/* How the body this edge reaches is entered - see
		 * kof_flow_node.entry. A thread start is an edge because the
		 * body runs, and it is not a call because it runs BESIDE the
		 * caller. */
		uint8_t  kind;
	} *edge;
	uint32_t n_edge, cap_edge;

	/*
	 * HOW THE SWEEP WAS TOLD TO READ, kept so that finish() can look a
	 * selector up in the same table the sweep used. `fxarch` is one of
	 * KOF_FLOW_A_*, or 0 when the code was x86 and `bits` decides.
	 */
	uint8_t bits;
	uint8_t fxarch;

	uint64_t entry;
	uint32_t has_entry;

	struct blk {
		uint64_t lo, hi;        /* [lo, hi) */
		uint32_t succ[2];
		uint8_t  n_succ;
		uint8_t  open_end;      /* left through an indirect branch */
		uint8_t  arm;           /* one side of a conditional - see mark_arms */
		/*
		 * AND WHICH CONDITIONAL, AND WHICH SIDE OF IT.
		 *
		 * `arm` alone says "this block is a branch arm", which is the
		 * same shortfall KOF_FLOWF_LOOP had before kof_flow_node.loop:
		 * a property with no identity. Two steps could each be an arm
		 * and there was no way to ask whether they were the two arms
		 * of ONE branch - which is the only thing that makes them
		 * ALTERNATIVES rather than two independent maybes.
		 *
		 * `arm_of` is the branching block's index plus one, so 0 means
		 * "not an arm"; `arm_side` is 0 or 1, which of its two
		 * successors this is.
		 */
		uint32_t arm_of;
		uint8_t  arm_side;
	} *blk;
	uint32_t n_blk, cap_blk;
	/* reaches()'s visited stamps, one per block - see the note there on
	 * why it is stamped and not cleared. Grown with the blocks. */
	uint32_t *blk_seen, blk_gen;
	/* reaches()'s queue. Sized with the blocks for the reason the stamps
	 * are: a search that runs out of room answers "cannot say", and on a
	 * large function a fixed 256 ran out on nearly every question. */
	uint32_t *blk_q;

	kof_flow_resolve_fn resolve;
	void               *resolve_user;
	/*
	 * BODIES THAT ARE NOTHING BUT A JUMP TO AN IMPORT, by their entry
	 * address. See find_thunks: the resolver knows the SLOT, and on a PE
	 * nothing tells it the address a compiler actually calls.
	 */
	struct thunkrow    *thunk;
	uint32_t            n_thunk;
	uint32_t            cap_thunk;
	kof_flow_retarget_fn retarget;
	void               *retarget_user;

	/* What a caller declared with kof_flow_head - see add_head_derived. */
	struct { uint64_t lo, hi; } *decl;
	uint32_t cap_func;
	uint32_t n_decl;

	uint32_t full;      /* a cap was reached - see kof_flow_full */
	uint8_t  edges_packed;/* the edge array was deduplicated once */
	uint32_t heads_full;/* ...and it was the HEAD array - see add_head */
	uint32_t finished;
};

void kof_flow_resolver(struct kof_flow *f, kof_flow_resolve_fn fn, void *user)
{
	if (f) {
		f->resolve = fn;
		f->resolve_user = user;
	}
}

void kof_flow_retargeter(struct kof_flow *f, kof_flow_retarget_fn fn,
			 void *user)
{
	if (f) {
		f->retarget = fn;
		f->retarget_user = user;
	}
}


/*
 * THE CALL GRAPH IS NOT BOUNDED BY THE FUNCTION COUNT, and it used to be
 * declared as if it were: `edge[KOF_FLOW_MAX_FUNC]`, four thousand entries
 * for a file that may make a hundred thousand calls. Past it every call was
 * dropped, so the chains of anything large were built from whatever happened
 * to be in the first few megabytes - measured on an 8 MB coinminer, its
 * socket, connect, bind, listen and accept calls all sat beyond the cap and
 * the object came out as two chains about mprotect.
 *
 * Grown instead of sized, so the memory is paid by the objects that need it
 * and not by every scan: the array starts where the old one ended and
 * doubles, and the ceiling is what 4 MB of swept code can plausibly contain.
 */
#define FLOW_EDGE_START KOF_FLOW_MAX_FUNC
#define FLOW_EDGE_MAX   (1u << 16)

static int func_grow(struct kof_flow *f);

struct kof_flow *kof_flow_new(void)
{
	struct kof_flow *f = (struct kof_flow *)calloc(1, sizeof *f);

	if (f) {
		f->edge = (void *)calloc(FLOW_EDGE_START, sizeof *f->edge);
		if (!f->edge || !func_grow(f)) {
			free(f->edge);
			free(f->head);
			free(f->func);
			free(f->decl);
			free(f);
			return 0;
		}
		f->cap_edge = FLOW_EDGE_START;
	}
	return f;
}

void kof_flow_free(struct kof_flow *f)
{
	if (f) {
		free(f->edge);
		free(f->blk);
		free(f->blk_seen);
		free(f->blk_q);
		free(f->head);
		free(f->func);
		free(f->decl);
		free(f->thunk);
	}
	free(f);
}

int kof_flow_heads_full(const struct kof_flow *f)
{
	return f && f->heads_full;
}

int kof_flow_full(const struct kof_flow *f)
{
	return f ? (int)f->full : 1;
}


/*
 * ONE EDGE PER CALLER AND CALLEE, kept when the array fills.
 *
 * add_edge records every call SITE, and a program calls malloc from four
 * thousand of them. The array holds KOF_FLOW_MAX_FUNC of those, so on
 * anything large it filled early and EVERY LATER CALL WAS DROPPED - measured
 * on an 8 MB coinminer: 4096 edges, the cap exactly, and the calls into its
 * own socket, connect, bind, listen and accept wrappers all sat past it. The
 * sweep found those nodes and nothing connected them, so the object's whole
 * network behaviour came out as two chains about mprotect.
 *
 * chain_walk follows a callee ONCE per chain - see seen_take - so a second
 * edge from the same caller to the same callee is already a no-op there.
 * That makes the duplicate safe to drop, and the key says so: the target,
 * and the page the call was made from. The page stands in for the CALLER,
 * which is not known until finish() builds the partition; a 4 KB window is
 * far smaller than a function is likely to be and far larger than a loop
 * body, so two callers rarely share one and a loop around a call always
 * does.
 */
static int cmp_edge_key(const void *a, const void *b)
{
	const struct cedge *x = (const struct cedge *)a;
	const struct cedge *y = (const struct cedge *)b;

	if (x->to_va != y->to_va)
		return x->to_va < y->to_va ? -1 : 1;
	if ((x->site >> 12) != (y->site >> 12))
		return (x->site >> 12) < (y->site >> 12) ? -1 : 1;
	return x->site < y->site ? -1 : (x->site > y->site ? 1 : 0);
}

static uint32_t edges_compact(struct kof_flow *f)
{
	uint32_t i, n = 0;

	qsort(f->edge, f->n_edge, sizeof f->edge[0], cmp_edge_key);
	for (i = 0; i < f->n_edge; i++)
		if (!i || f->edge[i].to_va != f->edge[i - 1u].to_va ||
		    (f->edge[i].site >> 12) != (f->edge[i - 1u].site >> 12))
			f->edge[n++] = f->edge[i];
	f->n_edge = n;
	return n;
}

static void add_edge_kind(struct kof_flow *f, uint64_t site, uint64_t to,
			  uint32_t step, uint8_t kind)
{
	/*
	 * COMPACT EVERY TIME IT FILLS, and stop only when it stops helping.
	 *
	 * This ran once, which was a mistake and a measured one: on the 8 MB
	 * coinminer the first pass took 4096 edges down to 1777, the sweep
	 * refilled the array, and nothing compacted it again - so the calls
	 * that mattered still never got in. One pass buys 2319 slots on a
	 * file with tens of thousands of call sites.
	 *
	 * A pass that frees less than a sixteenth of the array means the
	 * edges really are distinct call relations, and then the object has
	 * more of them than this holds; `full` says so and the negative
	 * answers that depend on it stand down.
	 */
	if (f->n_edge >= f->cap_edge) {
		/*
		 * COMPACT FIRST, GROW ONLY IF THAT DID NOT HELP. Half of what
		 * fills this array is the same callee called again from the
		 * same function, and chain_walk follows a callee once - see
		 * seen_take - so those entries buy nothing. Measured on the
		 * coinminer: the first pass took 4096 down to 1777.
		 */
		if (f->edges_packed != 2u &&
		    edges_compact(f) + f->cap_edge / 16u >= f->cap_edge)
			f->edges_packed = 2;
		if (f->n_edge >= f->cap_edge) {
			uint32_t want = f->cap_edge * 2u;
			void *p;

			if (want > FLOW_EDGE_MAX)
				want = FLOW_EDGE_MAX;
			p = want > f->cap_edge
			  ? realloc(f->edge, (size_t)want * sizeof *f->edge)
			  : 0;
			if (!p) {
				f->full = 1;
				return;
			}
			f->edge = (void *)p;
			f->cap_edge = want;
			f->edges_packed = 0;   /* room again - try once more */
		}
	}
	if (f->n_edge < f->cap_edge) {
		f->edge[f->n_edge].site = site;
		f->edge[f->n_edge].to_va = to;
		f->edge[f->n_edge].site_step = step;
		f->edge[f->n_edge].kind = kind;
		f->n_edge++;
	} else {
		f->full = 1;
	}
}

void kof_flow_entry(struct kof_flow *f, uint64_t va)
{
	if (f) {
		f->entry = va;
		f->has_entry = 1;
	}
}

/*
 * Snapshot the argument registers onto the edge just added.
 *
 * Nothing is interpreted here: which arguments a syscall cares about is the
 * callee's business and is not known yet. This only records what was there.
 */
static void edge_snap(struct kof_flow *f, const uint64_t *v,
		      const uint16_t *src, uint8_t known,
		      uint64_t sel, int selk)
{
	struct cedge *e;
	unsigned a;

	if (!f->n_edge)
		return;
	e = &f->edge[f->n_edge - 1u];
	e->argk = known;
	e->sel = sel;
	e->selk = (uint8_t)selk;
	for (a = 0; a < 4u; a++) {
		e->arg[a] = v ? v[a] : 0;
		e->argsrc[a] = src ? src[a] : 0;
	}
}

/* The x86 call site's four arguments, in whichever place the width puts
 * them: registers on amd64, the stack the caller just pushed on i386. */
static void edge_snap_x86(struct kof_flow *f, const struct cmap *c,
			  unsigned bits)
{
	static const uint32_t r64[4] = { R_RDI, R_RSI, R_RDX, R_RCX };
	uint64_t v[4] = { 0, 0, 0, 0 };
	uint16_t src[4] = { 0, 0, 0, 0 };
	uint8_t known = 0;
	uint64_t sel = 0;
	int selk, low8 = 0;
	unsigned a;

	for (a = 0; a < 4u; a++) {
		low8 = 0;
		if (bits == 32) {
			if (stack_arg(c, a, &v[a], &src[a]))
				known |= (uint8_t)(1u << a);
		} else {
			if (const_of(c, r64[a], &v[a], &low8))
				known |= (uint8_t)(1u << a);
			src[a] = c->src[r64[a]];
		}
	}
	/* The selector register is the same one on both widths, and it is
	 * taken whether or not it was only its low eight - a syscall number
	 * under 256 is fully determined by those, which is the same reason
	 * the sweep accepts `mov al,N`. */
	low8 = 0;
	selk = const_of(c, R_RAX, &sel, &low8);
	edge_snap(f, v, src, known, sel, selk);
}

static int cmp_u64(const void *a, const void *b);

/*
 * COMPACT THE HEADS, because the array holds call TARGETS and not functions.
 *
 * A function called ten times was added ten times - finish() sorts and
 * deduplicates, but that is far too late: the array fills with REPEATS and
 * declares the partition lost on programs with a few hundred functions and a
 * few thousand call sites. Measured: `bat` and a Mirai ARM build both lost
 * every chain this way, and over the corpus it was two thousand objects.
 *
 * So the dedup moves to where the overflow is decided. Returns how many
 * distinct heads are left.
 */
static uint32_t heads_compact(struct kof_flow *f)
{
	uint32_t i, n = 0;

	qsort(f->head, f->n_head, sizeof f->head[0], cmp_u64);
	for (i = 0; i < f->n_head; i++)
		if (!i || f->head[i] != f->head[i - 1u])
			f->head[n++] = f->head[i];
	f->n_head = n;
	return n;
}

static void add_head(struct kof_flow *f, uint64_t va)
{
	/*
	 * ONE COMPACTION PER FILL, and the second one gives up.
	 *
	 * Compacting an array that is genuinely full of distinct heads frees
	 * nothing, and doing it on every subsequent add would be a qsort per
	 * call site. The margin is what says whether it was worth doing:
	 * under it, the object really does have more functions than this
	 * holds and the partition really is lost.
	 */
	if (f->n_head >= f->cap_func && !f->heads_full)
		(void)heads_compact(f);
	if (f->n_head >= f->cap_func)
		(void)func_grow(f);
	if (f->n_head < f->cap_func) {
		f->head[f->n_head++] = va;
	} else {
		/*
		 * AND THE PARTITION IS NOW A LIE, which `full` alone does not
		 * say - it is set for a code run that was clipped too, and
		 * that costs nodes without misplacing the ones that remain.
		 *
		 * Running out of HEADS is different in kind: every function
		 * past this point has no start of its own, so its nodes are
		 * attributed to whatever precedes it and two unrelated bodies
		 * are read as one sentence. Measured over 1333 objects whose
		 * symbol table could be checked, 13 ended up that way - all
		 * of them with more functions than this array holds:
		 * nvidia.ko declares 60770 and one C++ sample 14229.
		 *
		 * A caller that cares about the partition asks and drops the
		 * answer, which is what a wrong chain deserves.
		 */
		f->full = 1;
		f->heads_full = 1;
	}
}

void kof_flow_head(struct kof_flow *f, uint64_t va, uint64_t size)
{
	if (!f || f->finished)
		return;
	add_head(f, va);
	if (size && f->n_decl < f->cap_func) {
		f->decl[f->n_decl].lo = va;
		f->decl[f->n_decl].hi = va + size;
		f->n_decl++;
	}
}

/*
 * A head the SWEEP worked out, which the declarations may overrule.
 *
 * Strictly inside, so a declared function's own start is still a head when
 * something calls it, and a head at the end of one is the start of the next.
 */
static void add_head_derived(struct kof_flow *f, uint64_t va)
{
	uint32_t i;

	for (i = 0; i < f->n_decl; i++)
		if (va > f->decl[i].lo && va < f->decl[i].hi)
			return;
	add_head(f, va);
}

static void add_loop(struct kof_flow *f, uint64_t lo, uint64_t hi)
{
	if (f->n_loop < MAX_LOOP) {
		f->loop[f->n_loop].lo = lo;
		f->loop[f->n_loop].hi = hi;
		f->n_loop++;
	} else {
		f->full = 1;
	}
}

/*
 * The direct branch target this instruction names, or 0 when it names none.
 *
 * Direct only. An indirect branch is the one thing a sweep cannot follow, and
 * pretending otherwise is how a disassembler invents functions that are not
 * there - see the note on what this file is not.
 */
static uint64_t branch_target(const INSTRUX *ix, uint64_t next_va)
{
	if (ix->OperandsCount < 1 || ix->Operands[0].Type != ND_OP_OFFS)
		return 0;
	return next_va + (uint64_t)(int64_t)ix->Operands[0].Info.RelativeOffset.Rel;
}

/*
 * THE ABSOLUTE ADDRESS A MEMORY OPERAND NAMES, or 0 when it names none this
 * can work out.
 *
 * Two forms and no others: rip-relative, which is how x86-64 reaches an import
 * slot, and a bare displacement, which is how i386 does. Anything with a base
 * or an index is an array subscript or a field of something, and guessing an
 * address out of it would be inventing one.
 */
static uint64_t mem_abs(const ND_OPERAND *op, uint64_t next_va)
{
	if (op->Type != ND_OP_MEM)
		return 0;
	if (op->Info.Memory.IsRipRel)
		return next_va + (uint64_t)(int64_t)op->Info.Memory.Disp;
	if (op->Info.Memory.HasDisp && !op->Info.Memory.HasBase &&
	    !op->Info.Memory.HasIndex)
		return (uint64_t)op->Info.Memory.Disp;
	return 0;
}

/*
 * THE SAME, BUT FOLDING A BASE REGISTER THE SWEEP ALREADY KNOWS.
 *
 * `jmp *0x10b7(%eax)` is an import call on a 32-bit PE that cannot say where
 * it was loaded, so it computes its own base and indexes the table from it.
 * mem_abs answers 0 for it - correctly, because without the register there IS
 * no address - and every import of such a binary therefore resolved to
 * nothing. Measured on the MSF evasion loader: seven imports, including
 * VirtualAlloc and OpenProcess, and the object reported no capability at all.
 *
 * ONLY A BASE, NEVER AN INDEX. A scaled index is a table lookup whose row is
 * chosen at runtime, and folding one would be inventing the row.
 */
static uint64_t mem_abs_reg(const struct cmap *c, const ND_OPERAND *op,
			    uint64_t next_va)
{
	uint64_t a = mem_abs(op, next_va);
	uint32_t b;

	if (a)
		return a;
	if (op->Type != ND_OP_MEM || !op->Info.Memory.HasBase ||
	    op->Info.Memory.HasIndex || !op->Info.Memory.HasDisp)
		return 0;
	b = op->Info.Memory.Base;
	if (b >= NGPR || c->known[b] < 4u)
		return 0;
	return c->v[b] + (uint64_t)(int64_t)op->Info.Memory.Disp;
}

/*
 * IS THE BODY AT `tgt` A GET-PC THUNK, and if so what does it return.
 *
 * Thirty-two-bit code that must run wherever it is loaded has no
 * rip-relative addressing, so it finds itself by calling a stub that hands
 * back an address. Two spellings, both of which end in `ret`:
 *
 *     call $+5 ; pop eax ; add eax, -5 ; ret      (inline, written by hand)
 *     mov ebx, [esp] ; ret                        (gcc's __x86.get_pc_thunk)
 *
 * The value is the return address the CALL pushed, adjusted by whatever
 * constant arithmetic the stub applies. Nothing else is followed: at most two
 * adds or subs, then a `ret`, or this answers no. A body that does anything
 * more is a function, and guessing a return value for a function is how an
 * address gets invented.
 */
static int pc_thunk(const uint8_t *code, uint32_t code_n, uint64_t code_va,
		    uint64_t tgt, uint64_t ret_va, unsigned bits,
		    uint32_t *reg, uint64_t *val)
{
	uint64_t off = tgt - code_va;
	uint64_t v = ret_va;
	uint32_t r = NGPR, steps;
	INSTRUX ix;

	if (bits != 32 || tgt < code_va || off >= code_n)
		return 0;
	if (!ND_SUCCESS(NdDecodeEx(&ix, code + off, code_n - (uint32_t)off,
				   ND_CODE_32, ND_DATA_32)))
		return 0;
	/*
	 * AND THE THUNK MAY PUSH ITS OWN ADDRESS FIRST.
	 *
	 * The hand-written form does not pop the caller's return address -
	 * it makes one of its own:
	 *
	 *     4014ad: call 4014b2        <- the body starts HERE
	 *     4014b2: pop  eax           <- so eax is 4014b2, not the
	 *     4014b3: add  eax, -5          caller's return address
	 *     4014b8: ret
	 *
	 * Reading the pop without this gave the register the OUTER call's
	 * return address, which is a real address in the caller and
	 * therefore a wrong answer that looks like a right one.
	 */
	if (ix.Instruction == ND_INS_CALLNR &&
	    branch_target(&ix, tgt + ix.Length) == tgt + ix.Length) {
		v = tgt + ix.Length;
		off += ix.Length;
		if (off >= code_n ||
		    !ND_SUCCESS(NdDecodeEx(&ix, code + off,
					   code_n - (uint32_t)off,
					   ND_CODE_32, ND_DATA_32)))
			return 0;
	}
	if (ix.Instruction == ND_INS_POP && ix.OperandsCount >= 1 &&
	    ix.Operands[0].Type == ND_OP_REG)
		r = gpr_of(&ix.Operands[0]);
	else if (ix.Instruction == ND_INS_MOV && ix.OperandsCount >= 2 &&
		 ix.Operands[0].Type == ND_OP_REG &&
		 ix.Operands[1].Type == ND_OP_MEM &&
		 ix.Operands[1].Info.Memory.HasBase &&
		 ix.Operands[1].Info.Memory.Base == R_RSP &&
		 !ix.Operands[1].Info.Memory.HasDisp)
		r = gpr_of(&ix.Operands[0]);
	else
		return 0;
	if (r >= NGPR)
		return 0;
	off += ix.Length;
	for (steps = 0; steps < 3u; steps++) {
		if (off >= code_n ||
		    !ND_SUCCESS(NdDecodeEx(&ix, code + off,
					   code_n - (uint32_t)off,
					   ND_CODE_32, ND_DATA_32)))
			return 0;
		if (ix.Instruction == ND_INS_RETN) {
			*reg = r;
			*val = v & 0xffffffffull;
			return 1;
		}
		if ((ix.Instruction != ND_INS_ADD &&
		     ix.Instruction != ND_INS_SUB) ||
		    ix.OperandsCount < 2 ||
		    ix.Operands[0].Type != ND_OP_REG ||
		    gpr_of(&ix.Operands[0]) != r ||
		    ix.Operands[1].Type != ND_OP_IMM)
			return 0;
		if (ix.Instruction == ND_INS_ADD)
			v += ix.Operands[1].Info.Immediate.Imm;
		else
			v -= ix.Operands[1].Info.Immediate.Imm;
		off += ix.Length;
	}
	return 0;
}

static int is_cond_jump(const INSTRUX *ix)
{
	return ix->Instruction >= ND_INS_Jcc && ix->Instruction <= ND_INS_Jcc;
}

/*
 * WHERE CONTROL CAN ARRIVE FROM SOMEWHERE ELSE.
 *
 * A linear sweep walks addresses, not paths, so without this it carries what
 * it knows across a boundary control never crosses. Measured in gdb: a call to
 * ptrace, then a few instructions later an unconditional jmp out, and then a
 * DIFFERENT block - entered from elsewhere - doing `call *%rax`. The sweep
 * joined the two and reported that the value ptrace returned was executed.
 * Nothing in that function does any such thing.
 *
 * So a pre-pass collects every direct branch target, and the sweep clears its
 * map when it reaches one: a block that can be entered from elsewhere starts
 * knowing nothing, which is the only honest state for it.
 *
 * A FIXED SET, AND COLLISIONS ONLY OVER-CLEAR. Open addressing over a fixed
 * table, so a full or colliding table makes the sweep forget at an address
 * that is not a target. That loses facts and cannot invent them, which is the
 * direction every approximation in this file leans.
 */
#define TSET_N 8192u

struct tset { uint64_t k[TSET_N]; };

static void tset_put(struct tset *t, uint64_t va)
{
	uint32_t i, h = (uint32_t)((va * 0x9e3779b97f4a7c15ull) >> 49) %
			TSET_N;

	for (i = 0; i < 8u; i++) {
		uint32_t at = (h + i) % TSET_N;

		if (!t->k[at] || t->k[at] == va) {
			t->k[at] = va;
			return;
		}
	}
}

static int tset_has(const struct tset *t, uint64_t va)
{
	uint32_t i, h = (uint32_t)((va * 0x9e3779b97f4a7c15ull) >> 49) %
			TSET_N;

	for (i = 0; i < 8u; i++) {
		uint32_t at = (h + i) % TSET_N;

		if (t->k[at] == va)
			return 1;
		if (!t->k[at])
			return 0;
	}
	return 0;
}

/*
 * Decode only, and record where a direct branch can land.
 *
 * `ct` is the same thing narrowed to CALL targets. The two are kept apart
 * because the question they answer is different: `t` asks "can control arrive
 * here", which a join needs, while `ct` asks "did something arrive here with a
 * return address on the stack", which is the only reason a body that starts
 * with `pop reg` is reading its own address rather than cleaning up. A
 * conditional branch to a `pop` is an ordinary error path and must not be read
 * as one.
 */
static void find_targets(struct tset *t, struct tset *ct, const uint8_t *code,
			 uint32_t code_n, uint64_t code_va, unsigned bits)
{
	uint32_t at = 0;

	while (at < code_n) {
		INSTRUX ix;
		uint64_t va = code_va + at, tg;

		if (!ND_SUCCESS(NdDecodeEx(&ix, code + at, code_n - at,
					   bits == 32 ? ND_CODE_32 : ND_CODE_64,
					   bits == 32 ? ND_DATA_32
						      : ND_DATA_64))) {
			at++;
			continue;
		}
		if (ix.Instruction == ND_INS_JMPNR ||
		    ix.Instruction == ND_INS_CALLNR || is_cond_jump(&ix)) {
			tg = branch_target(&ix, va + ix.Length);
			if (tg >= code_va && tg < code_va + code_n) {
				tset_put(t, tg);
				if (ct && ix.Instruction == ND_INS_CALLNR)
					tset_put(ct, tg);
			}
		}
		at += ix.Length;
	}
}

/* Open a block at `va`, closing whatever was open. */
/*
 * THE RESOLVER'S ANSWER, BOUNDED - and this is the library's own ABI, not a
 * file format.
 *
 * kof_flow_resolve_fn returns a uint8_t and the header says it is an
 * enum kof_flow_cap; the type cannot say that, and nothing checked it. The
 * value is stored in node.cap, and finish() then does
 *
 *     f->func[fi].mask |= 1ull << f->node[k].cap;
 *
 * so a resolver answering 140 made that shift undefined. Found by fuzzing this
 * library through its own API - the one resolver it has today is objctx's
 * import lookup, which returns kof_flow_cap_of and is always in range, so
 * reading the call sites never showed it.
 *
 * Out of vocabulary becomes KOF_CAP_NONE, which is what every target the
 * resolver does not recognise already becomes - see the note on
 * kof_flow_resolve_fn.
 */
static int thunk_cmp(const void *a, const void *b)
{
	uint64_t x = ((const struct thunkrow *)a)->va;
	uint64_t y = ((const struct thunkrow *)b)->va;

	return x < y ? -1 : (x > y ? 1 : 0);
}

/*
 * EVERY BODY THAT IS NOTHING BUT A JUMP TO AN IMPORT, BY ITS ENTRY ADDRESS.
 *
 * The resolver is given the SLOT an import lives in, which is the right key
 * for `call [slot]`. It is the wrong key for everything a compiler actually
 * emits on a 32-bit PE, which calls a two-instruction body:
 *
 *     4014cb: call 4014ad          ; a get-PC thunk, returns its own address
 *     4014d0: jmp  *0x10b7(%eax)   ; and through the table from there
 *
 * Nothing registers 0x4014cb, so a `call 4014cb` from the program resolved to
 * nothing. Measured on the MSF evasion loader: VirtualAlloc and OpenProcess
 * were found - inside the thunks, each its own one-instruction function - so
 * the capability existed and no caller could ever be in a chain with it. A
 * finding nobody can reach is the same as no finding.
 *
 * ONE LINEAR PASS, no state carried between instructions except the register
 * a get-PC thunk just set, and that only to the very next instruction. The
 * two shapes recognised are the one above and the plain `jmp *[slot]` that a
 * non-relocatable build writes.
 */
static void find_thunks(struct kof_flow *f, const uint8_t *code,
			uint32_t code_n, uint64_t code_va, unsigned bits)
{
	uint32_t at = 0, treg = NGPR;
	uint64_t tval = 0, tfrom = 0;

	if (!f || !f->resolve)
		return;
	while (at < code_n) {
		INSTRUX ix;
		uint64_t va = code_va + at, slot = 0;
		uint32_t ans;

		if (!ND_SUCCESS(NdDecodeEx(&ix, code + at, code_n - at,
					   bits == 32 ? ND_CODE_32
						      : ND_CODE_64,
					   bits == 32 ? ND_DATA_32
						      : ND_DATA_64))) {
			at++;
			treg = NGPR;
			continue;
		}
		if (ix.Instruction == ND_INS_JMPNI && ix.OperandsCount >= 1 &&
		    ix.Operands[0].Type == ND_OP_MEM) {
			const ND_OPERAND *op = &ix.Operands[0];

			slot = mem_abs(op, va + ix.Length);
			if (!slot && treg < NGPR && op->Info.Memory.HasBase &&
			    !op->Info.Memory.HasIndex &&
			    op->Info.Memory.HasDisp &&
			    op->Info.Memory.Base == treg)
				slot = tval +
				       (uint64_t)(int64_t)op->Info.Memory.Disp;
		}
		if (slot) {
			ans = f->resolve(slot, f->resolve_user);
			if ((ans & 0xffu) != KOF_CAP_NONE &&
			    (uint8_t)(ans & 0xffu) < (uint8_t)KOF_CAP_COUNT) {
				/* The entry is where the get-PC call was, or
				 * the jump itself when there was none. */
				uint64_t ent = (treg < NGPR && tfrom) ? tfrom
								      : va;

				if (f->n_thunk >= f->cap_thunk) {
					uint32_t want = f->cap_thunk
							? f->cap_thunk * 2u
							: 64u;
					struct thunkrow *t;

					/* A ceiling only against a file made
					 * of nothing but thunks. */
					if (want > 65536u)
						want = 65536u;
					t = f->n_thunk < want
					    ? (struct thunkrow *)
					      realloc(f->thunk,
						      want * sizeof *t)
					    : NULL;
					if (t) {
						f->thunk = t;
						f->cap_thunk = want;
					}
				}
				if (f->n_thunk < f->cap_thunk) {
					f->thunk[f->n_thunk].va = ent;
					f->thunk[f->n_thunk].ans = ans;
					f->n_thunk++;
				}
				/*
				 * AND THE JUMP'S OWN ADDRESS, which nothing
				 * calls - it is here so the sweep can tell
				 * that the node it is about to make IS the
				 * inside of a thunk and drop it. The caller
				 * already has the step, and with better
				 * arguments: at the call site VirtualAlloc's
				 * protection word is on the stack and reads
				 * as alloc-exec, while inside the thunk there
				 * is nothing to read and it is a plain alloc.
				 */
				if (ent != va && f->n_thunk < f->cap_thunk) {
					f->thunk[f->n_thunk].va = va;
					f->thunk[f->n_thunk].ans = ans;
					f->n_thunk++;
				}
			}
		}
		treg = NGPR;
		tfrom = 0;
		if (ix.Instruction == ND_INS_CALLNR) {
			uint32_t r = NGPR;
			uint64_t v = 0;

			if (pc_thunk(code, code_n, code_va,
				     branch_target(&ix, va + ix.Length),
				     va + ix.Length, bits, &r, &v)) {
				treg = r;
				tval = v;
				tfrom = va;
			}
		}
		at += ix.Length;
	}
	if (f->n_thunk > 1u)
		qsort(f->thunk, f->n_thunk, sizeof *f->thunk, thunk_cmp);
}

static uint32_t resolve_cap(struct kof_flow *f, uint64_t target)
{
	uint32_t a;
	uint8_t k;

	if (!f || !f->resolve)
		return KOF_FLOW_ANSWER(KOF_CAP_NONE, KOF_FLOW_ROLE_NONE);
	a = f->resolve(target, f->resolve_user);
	k = (uint8_t)(a & 0xffu);
	if (k == KOF_CAP_NONE && f->n_thunk) {
		uint32_t lo = 0, hi = f->n_thunk;

		while (lo < hi) {
			uint32_t mid = lo + (hi - lo) / 2u;

			if (f->thunk[mid].va == target) {
				a = f->thunk[mid].ans;
				k = (uint8_t)(a & 0xffu);
				break;
			}
			if (f->thunk[mid].va < target)
				lo = mid + 1u;
			else
				hi = mid;
		}
	}
	return k < (uint8_t)KOF_CAP_COUNT
		? a : KOF_FLOW_ANSWER(KOF_CAP_NONE, KOF_FLOW_ROLE_NONE);
}

/*
 * THE BLOCK ARRAY IS NOT BOUNDED BY ANYTHING THE OLD CONSTANT KNEW.
 *
 * It was `blk[KOF_FLOW_MAX_BLOCK]` - eight thousand basic blocks, for a
 * sweep whose code budget is four megabytes. Past it `full` is set, every
 * later block simply does not exist, and then blk_of answers "nowhere" for
 * every address in them: kof_flow_relation comes back UNKNOWN for every pair
 * and mark_arms declines to run at all.
 *
 * Measured on an 8 MB coinminer: the chain drew `-- ? --` between every
 * single step and not one `if {`, because the structure questions were all
 * being asked about blocks that had never been recorded. The nodes and the
 * call nesting were right; everything the block graph answers was missing.
 *
 * Grown instead of sized, like the edges: small objects pay nothing.
 */
#define FLOW_BLK_START 4096u
#define FLOW_BLK_MAX   (1u << 17)

static int blk_grow(struct kof_flow *f)
{
	uint32_t want = f->cap_blk ? f->cap_blk * 2u : FLOW_BLK_START;
	void *a, *b;

	if (f->cap_blk >= FLOW_BLK_MAX)
		return 0;
	if (want > FLOW_BLK_MAX)
		want = FLOW_BLK_MAX;
	a = realloc(f->blk, (size_t)want * sizeof *f->blk);
	if (!a)
		return 0;
	f->blk = a;
	b = realloc(f->blk_seen, (size_t)want * sizeof *f->blk_seen);
	if (!b)
		return 0;
	f->blk_seen = b;
	{
		void *q = realloc(f->blk_q, (size_t)want * sizeof *f->blk_q);

		if (!q)
			return 0;
		f->blk_q = q;
	}
	memset(f->blk_seen + f->cap_blk, 0,
	       (size_t)(want - f->cap_blk) * sizeof *f->blk_seen);
	f->cap_blk = want;
	return 1;
}

static void add_edge(struct kof_flow *f, uint64_t site, uint64_t to,
		     uint32_t step)
{
	add_edge_kind(f, site, to, step, KOF_FLOW_IN_CALL);
}

/*
 * THE PARTITION GROWS TOO, AND IT IS THE ONE THAT GATES THE REST.
 *
 * `head`, `func` and `decl` were three arrays of KOF_FLOW_MAX_FUNC, and the
 * four-megabyte code budget was not an independent throttle at all - it was
 * what kept them from filling. Measured on an 8 MB coinminer: swept to 4 MB
 * the partition holds 2718 functions and the object yields eight chains;
 * swept to 8 MB it hits 4096 exactly, heads_full fires and the object yields
 * none. Reading MORE of the program produced LESS of it.
 *
 * Grown on demand so a small object pays for none of this, and still capped
 * so a hostile file cannot ask for the machine. The ceiling is what the edge
 * records can address: from_func and to_func are uint16_t.
 */
#define FLOW_FUNC_START 1024u
#define FLOW_FUNC_MAX   65535u

static int func_grow(struct kof_flow *f)
{
	uint32_t want = f->cap_func ? f->cap_func * 2u : FLOW_FUNC_START;
	void *a, *b, *c;

	if (f->cap_func >= FLOW_FUNC_MAX)
		return 0;
	if (want > FLOW_FUNC_MAX)
		want = FLOW_FUNC_MAX;
	a = realloc(f->head, (size_t)want * sizeof *f->head);
	if (!a)
		return 0;
	f->head = a;
	b = realloc(f->func, (size_t)want * sizeof *f->func);
	if (!b)
		return 0;
	f->func = b;
	c = realloc(f->decl, (size_t)want * sizeof *f->decl);
	if (!c)
		return 0;
	f->decl = c;
	f->cap_func = want;
	return 1;
}

static uint32_t blk_open(struct kof_flow *f, uint64_t va)
{
	if (f->n_blk >= f->cap_blk && !blk_grow(f)) {
		f->full = 1;
		return KOF_FLOW_MAX_BLOCK;
	}
	memset(&f->blk[f->n_blk], 0, sizeof f->blk[0]);
	f->blk[f->n_blk].lo = va;
	f->blk[f->n_blk].hi = va;
	return f->n_blk++;
}

static void blk_succ(struct kof_flow *f, uint32_t b, uint64_t va)
{
	if (b >= f->n_blk)
		return;
	if (f->blk[b].n_succ < 2u)
		f->blk[b].succ[f->blk[b].n_succ++] = (uint32_t)va;
}

/*
 * Which block holds this address, or n_blk.
 *
 * A BINARY SEARCH, SO THE ARRAY HAS TO BE SORTED, and it is - by sort_blocks
 * in finish(). It used to be sorted only BY LUCK: blocks are appended as a
 * region is swept, so they ascend within a region and the regions happened
 * to arrive in address order. Nothing said they had to, and when this was
 * asked once per rule a wrong answer was a relation nobody looked at. It is
 * now asked for every step of every chain.
 */
static uint32_t blk_of(const struct kof_flow *f, uint64_t va)
{
	uint32_t lo = 0, hi = f->n_blk;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (f->blk[mid].lo <= va)
			lo = mid + 1u;
		else
			hi = mid;
	}
	if (!lo)
		return f->n_blk;
	lo--;
	return va < f->blk[lo].hi ? lo : f->n_blk;
}

/*
 * ONE SWEEP, shared by both entry points.
 *
 * `f` NULL is the simple form - no heads, no loops, one region - which is what
 * kof_flow_scan wants and what a raw blob is.
 */
/*
 * A THREAD ENTRY IS A CALL EDGE.
 *
 * CreateThread(.., lpStart, ..), pthread_create(.., start, ..) and
 * clone(fn, ..) all hand a function pointer to the system and the system
 * calls it. Read as an ordinary call it is not one: the target never appears
 * as a branch, and its whole body - which is where a loader does its work -
 * falls outside every function the sweep found.
 *
 * WHICH ARGUMENT HOLDS IT IS NOT FIXED: third for CreateThread and
 * pthread_create, first for clone. Rather than keep a table of which import
 * puts it where, every argument is tested against one question - is this
 * constant an address inside the code being swept - and an argument that is
 * not a pointer into it cannot pass. [Inference] A constant argument that
 * happens to fall in range without being a function pointer would add a
 * spurious head; nothing measured so far has produced one, and the range test
 * is what keeps it rare rather than a proof that it cannot happen.
 */
static void thread_edge(struct kof_flow *f, const struct cmap *c, unsigned bits,
			unsigned abi, int by_call, uint64_t va, uint32_t step,
			uint64_t code_va, uint32_t code_n, uint8_t cap)
{
	const uint8_t *a;
	uint32_t i;

	/*
	 * AND KOF_CAP_THREAD, WHICH IS WHAT THIS FUNCTION IS NAMED AFTER.
	 *
	 * The test was `cap != KOF_CAP_SPAWN`, and every genuine thread start
	 * resolves to THREAD and not SPAWN: pthread_create and CreateThread
	 * are THREAD in the vocabulary, and clone becomes THREAD the moment
	 * clone_cap sees CLONE_THREAD. So the one case this exists for was
	 * the one it turned away - the pointer handed to the system was never
	 * followed, and a bot that does its work on four threads showed the
	 * call that started them and nothing those threads do.
	 *
	 * SPAWN stays because a raw `clone(fn, stack, ...)` passes the
	 * pointer whether or not the child shares the address space.
	 */
	if (!f || (cap != KOF_CAP_SPAWN && cap != KOF_CAP_THREAD))
		return;

	if (bits == 32 && by_call) {
		for (i = 0; i < KOF_FLOW_ARGS; i++) {
			uint64_t v;
			uint16_t sr = 0;

			if (!stack_arg(c, i, &v, &sr) || sr)
				continue;
			/* Strictly inside: a pointer equal to the first byte
			 * swept is the entry itself, and an edge from a
			 * function to its own head says nothing. */
			if (v > code_va && v < code_va + code_n) {
				add_head_derived(f, v);
				add_edge_kind(f, va, v, step,
					      KOF_FLOW_IN_THREAD);
			}
		}
		return;
	}
	a = bits == 32 ? arg_sys32
		       : (by_call ? (abi == KOF_FLOW_MS ? arg_ms : arg_sysv)
				  : arg_sys64);
	for (i = 0; i < KOF_FLOW_ARGS; i++) {
		uint32_t r = a[i];

		if (r >= NGPR || c->src[r] || c->known[r] < 4u)
			continue;
		if (c->v[r] > code_va && c->v[r] < code_va + code_n) {
			add_head_derived(f, c->v[r]);
			add_edge_kind(f, va, c->v[r], step,
				      KOF_FLOW_IN_THREAD);
		}
	}
}

static uint32_t sweep(struct kof_flow *f, const uint8_t *code, uint32_t code_n,
		      uint64_t code_va, unsigned bits, unsigned abi,
		      struct kof_flow_node *out, uint32_t cap)
{
	struct cmap c;
	struct tset *t;
	struct tset *ct;
	uint32_t at = 0, n = 0, step = 0, cur_blk = 0;
	int in_push_run = 0;
	/* What prot_cap learned about THIS instruction's protection word, and
	 * nothing older: reset at the top of every iteration. */
	uint8_t pflags = 0;
	/*
	 * WHICH ADDRESS EACH MAPPING CALL WAS ABOUT.
	 *
	 * The other half of the edge, and the only one a Windows stub has:
	 * VirtualProtect returns a BOOL, not the buffer, so there is no value
	 * to follow. What ties the shape together is that the address handed
	 * to it is the address jumped to afterwards - a CONSTANT compared
	 * against a constant. Sixteen, because a function that maps more than
	 * sixteen times is not the shape this is for.
	 */
	struct { uint64_t addr; uint16_t node; } mapped[16];
	uint32_t n_mapped = 0;
	/*
	 * HOW MANY INSTRUCTIONS SINCE A RETURN CLEARED THE MAP.
	 *
	 * The one thing that tells a syscall thunk - a body that IS the
	 * interrupt, with its number set by whoever called it - from a
	 * syscall the sweep simply failed to follow. Near a `ret` and with
	 * nothing having written eax, the sweep is at the TOP of a body and
	 * the caller is the only place the number can be. Far from one, an
	 * unknown eax means the sweep lost it, and inventing a node there
	 * would be a claim about a byte pair - `cd 80` appears in data.
	 */
	uint32_t since_ret = 0xffffu;
	/*
	 * HOW MANY INSTRUCTIONS SINCE A SINGLE BYTE WAS LOADED.
	 *
	 * The other half of the name-hash shape, and the one that tells a
	 * name hash from a block cipher. A string hash reads ONE BYTE at a
	 * time - `lodsb`, or a movzx of a byte - and folds it in; SHA-256 and
	 * MD5 rotate and add just as hard, on 32-bit words, and have no byte
	 * load anywhere in the round. Without this a ransomware sample
	 * reported 764 name-hash nodes, all of them its own digest.
	 */
	uint32_t since_byte = 0xffffu;
	/*
	 * ---- THE SUCCESS BRANCH OF A SYSCALL THAT RETURNS ZERO ----------
	 *
	 * A stager can set up its NEXT syscall by not setting it up at all.
	 * Measured on msfvenom's x86-64 reverse_tcp:
	 *
	 *     c0: syscall           ; connect, which returns 0 on success
	 *     c3: test %rax,%rax
	 *     c6: jns 0xed          ; the only way on is the success path
	 *     ...
	 *     ed: pop %rsi          ; the buffer mmap returned
	 *     f0: pop %rdx
	 *     f1: syscall           ; rax is STILL 0, and 0 is read
	 *     f8: jmp *%rsi
	 *
	 * Nothing between c0 and f1 writes rax. The sweep forgets it at the
	 * syscall - rightly, a return value is not a constant - and so the
	 * `read` that fills the buffer, and BOTH links through it, were
	 * invisible: the chain said the program mapped memory, opened a
	 * socket and jumped, with nothing joining the two halves.
	 *
	 * This is ABI arithmetic and not emulation. Linux returns -errno on
	 * failure, the success value of this group of calls is exactly zero
	 * (see kof_sys_zero_on_success), and a branch on the sign or on zero
	 * therefore SAYS which side is which. On the side that is success,
	 * rax is known.
	 *
	 * `ok_at[]` carries the fact to a block the sweep has not reached
	 * yet: the success side is usually the jump TARGET, and the linear
	 * sweep arrives there later through a join that clears everything.
	 */
	uint32_t sysret = 0xffffu;   /* instructions since a zero-ok syscall */
	int      cmp_ret = 0;        /* ...and its result was just compared */
	uint64_t *ok_at = NULL;
	uint32_t n_ok = 0, cap_ok = 0;
	/*
	 * ---- WHAT A JUMP CARRIED TO ITS TARGET -------------------------
	 *
	 * The sweep reads code in ADDRESS order, so the state it has at any
	 * instruction is the state of whatever happens to be written above
	 * it. Usually that is also the predecessor. It is not when the
	 * instruction above cannot fall through - a `ret`, an unconditional
	 * `jmp`, or a syscall that never returns.
	 *
	 * Measured on msfvenom's x86-64 stager:
	 *
	 *     c6: jns 0xed      ; the only way to 0xed, rdi = the socket
	 *     e5: push $0x3c
	 *     ea: pop  %rdi     ; rdi = 1
	 *     eb: syscall       ; exit(1) - does not come back
	 *     ed: pop  %rsi     ; the sweep arrives here believing rdi = 1
	 *
	 * So `read` at 0xf1 lost its link to the socket - to a path that
	 * ends. The jump at 0xc6 knew the answer; nothing carried it.
	 *
	 * This records the PROVENANCE at each branch, keyed by target, and
	 * restores it when the sweep reaches that target with no live
	 * predecessor above it. Provenance only: values are path facts and
	 * a second jump to the same label may carry different ones.
	 */
	struct jmpstate { uint64_t va; uint16_t src[NGPR]; } *jst = NULL;
	uint32_t n_jst = 0, cap_jst = 0;
	int no_fall = 0;        /* the instruction just read cannot continue */
	static int oldhash = -1;

	memset(&c, 0, sizeof c);
	cur_blk = f ? blk_open(f, code_va) : 0u;
	t = (struct tset *)calloc(1, sizeof *t);
	ct = (struct tset *)calloc(1, sizeof *ct);
	if (t)
		find_targets(t, ct, code, code_n, code_va, bits);
	/* Before anything is resolved, so that a call site reached early in
	 * the sweep sees a thunk defined later in the section. */
	find_thunks(f, code, code_n, code_va, bits);
	/* Without it every fact still holds within a straight line; what is
	 * lost is the clearing at a join, so the sweep is more credulous
	 * rather than wrong in a new way. */

	while (at < code_n && n < cap) {
		pflags = 0;
		INSTRUX ix;
		uint32_t i, dst = NGPR;
		uint64_t nr, va = code_va + at, next;
		int low8 = 0, is_push;

		if (!ND_SUCCESS(NdDecodeEx(&ix, code + at, code_n - at,
					   bits == 32 ? ND_CODE_32 : ND_CODE_64,
					   bits == 32 ? ND_DATA_32
						      : ND_DATA_64))) {
			/*
			 * ONE BYTE ON AND KEEP GOING. A linear sweep meets
			 * data in code constantly, and stopping at the first
			 * undecodable byte would end the sweep in the literal
			 * pool every real binary has.
			 */
			at++;
			in_push_run = 0;
			continue;
		}
		next = va + ix.Length;
		if (since_ret != 0xffffu && since_ret < 0xfffeu)
			since_ret++;
		if (since_byte < 0xfffeu)
			since_byte++;
		/*
		 * WHAT THIS BRANCH IS CARRYING, for a target the sweep has
		 * not reached - see jmpstate. Recorded for every branch,
		 * used only where there is no live fall-through.
		 */
		if (is_cond_jump(&ix) || ix.Instruction == ND_INS_JMPNR) {
			uint64_t tg = branch_target(&ix, next);

			if (tg > va && tg >= code_va && tg < code_va + code_n) {
				uint32_t q;

				for (q = 0; q < n_jst; q++)
					if (jst[q].va == tg)
						break;
				if (q == n_jst && n_jst >= cap_jst) {
					uint32_t want = cap_jst ? cap_jst * 2u
								: 32u;
					struct jmpstate *g;

					/* A ceiling against a file that is
					 * nothing but branches, not a budget
					 * on how many a program may have. */
					g = want <= 8192u
					    ? (struct jmpstate *)
					      realloc(jst, want * sizeof *g)
					    : NULL;
					if (g) { jst = g; cap_jst = want; }
				}
				if (q < n_jst || n_jst < cap_jst) {
					if (q == n_jst)
						n_jst++;
					jst[q].va = tg;
					memcpy(jst[q].src, c.src,
					       sizeof jst[q].src);
				}
			}
		}

		/*
		 * The window a syscall's result stays readable in. Eight,
		 * because the shape is `syscall ; test ; jcc` with at most a
		 * pop or two between; past that the sweep is guessing that
		 * nothing wrote rax, and guessing is how a wrong constant
		 * becomes a confident wrong syscall name.
		 */
		if (sysret < 0xfffeu && ++sysret > 8u) {
			sysret = 0xffffu;
			cmp_ret = 0;
		}
		/*
		 * `test rax,rax` or `cmp rax,0` - the comparison that turns a
		 * return value into a branch. Only rax, because only rax
		 * holds the result.
		 */
		if (sysret != 0xffffu &&
		    ((ix.Instruction == ND_INS_TEST && ix.OperandsCount >= 2 &&
		      ix.Operands[0].Type == ND_OP_REG &&
		      ix.Operands[1].Type == ND_OP_REG &&
		      gpr_of(&ix.Operands[0]) == R_RAX &&
		      gpr_of(&ix.Operands[1]) == R_RAX) ||
		     (ix.Instruction == ND_INS_CMP && ix.OperandsCount >= 2 &&
		      ix.Operands[0].Type == ND_OP_REG &&
		      gpr_of(&ix.Operands[0]) == R_RAX &&
		      ix.Operands[1].Type == ND_OP_IMM &&
		      ix.Operands[1].Info.Immediate.Imm == 0)))
			cmp_ret = 1;
		else if (cmp_ret && is_cond_jump(&ix)) {
			/*
			 * WHICH SIDE IS SUCCESS. bddisasm gives the predicate
			 * in four bits with the low one meaning "negated", so
			 * NS, Z and GE jump to success and S, NZ, L fall
			 * through to it. For a value that is 0 or negative,
			 * those are the same question asked three ways.
			 */
			unsigned cc = ix.Condition;
			uint64_t tg = branch_target(&ix, next);
			int at_target = cc == 0x9u || cc == 0x4u || cc == 0xdu;
			int at_fall   = cc == 0x8u || cc == 0x5u || cc == 0xcu;

			if (at_fall) {
				c.v[R_RAX] = 0;
				c.known[R_RAX] = 8;
				c.src[R_RAX] = 0;
			} else if (at_target && tg >= code_va &&
				   tg < code_va + code_n) {
				if (n_ok >= cap_ok) {
					uint32_t want = cap_ok ? cap_ok * 2u
							       : 16u;
					uint64_t *g;

					/* A ceiling only against a file that
					 * is nothing but branches. */
					g = want <= 4096u
					    ? (uint64_t *)realloc(ok_at,
							want * sizeof *g)
					    : NULL;
					if (g) { ok_at = g; cap_ok = want; }
				}
				if (n_ok < cap_ok)
					ok_at[n_ok++] = tg;
			}
			cmp_ret = 0;
			sysret = 0xffffu;
		}
		/* A byte load: lodsb, or anything that writes a one-byte
		 * register from memory. The size of the DESTINATION is the
		 * test, because that is what "one byte at a time" means. */
		if (ix.Instruction == ND_INS_LODS) {
			if (ix.Operands[0].Size == 1u)
				since_byte = 0;
		} else if (ix.OperandsCount >= 2 &&
			   ix.Operands[0].Type == ND_OP_REG &&
			   ix.Operands[1].Type == ND_OP_MEM &&
			   ix.Operands[1].Size == 1u) {
			since_byte = 0;
		}

		/*
		 * THE SPLIT COMES BEFORE THE INSTRUCTION IS ADDED, and getting
		 * that order wrong is not a cosmetic bug: extending first put
		 * the instruction in the PREVIOUS block and then opened a new
		 * one at an address already inside it, so the ranges
		 * overlapped, empty blocks appeared between them, and the
		 * address lookup answered "no block" for a real edge. Every
		 * relation downstream of that came back UNKNOWN.
		 */
		if (t && tset_has(t, va)) {
			/* A block something else can jump into knows nothing
			 * about its registers - see join_clear. */
			join_clear(&c);
			/*
			 * EXCEPT WHAT THE BRANCH ITSELF SAID. If the only way
			 * into this block is the success side of a test on a
			 * syscall that returns zero, then rax is zero here -
			 * see ok_at above. join_clear runs first on purpose:
			 * this adds one fact back, it does not keep the rest.
			 */
			{
				uint32_t q;

				for (q = 0; q < n_ok; q++)
					if (ok_at[q] == va) {
						c.v[R_RAX] = 0;
						c.known[R_RAX] = 8;
						c.src[R_RAX] = 0;
						break;
					}
				/*
				 * AND WHAT A JUMP TO HERE WAS CARRYING, when
				 * nothing above can reach this point - see
				 * jmpstate. Only then: with a live
				 * predecessor the two would have to be
				 * merged, and this does not merge.
				 */
				if (no_fall)
					for (q = 0; q < n_jst; q++)
						if (jst[q].va == va) {
							memcpy(c.src,
							       jst[q].src,
							       sizeof c.src);
							break;
						}
			}
			if (f && cur_blk < f->n_blk &&
			    f->blk[cur_blk].lo != va) {
				/*
				 * The block before falls through into this one
				 * unless it ended in a transfer - a transfer
				 * closes by opening a block AT `next`, which is
				 * this address, and the test above sees that.
				 */
				if (f->blk[cur_blk].hi == va)
					blk_succ(f, cur_blk, va);
				cur_blk = blk_open(f, va);
			}
		}
		/* Read by the join above; every instruction is assumed to
		 * continue unless its handler says otherwise. */
		no_fall = 0;
		if (f && cur_blk < f->n_blk)
			f->blk[cur_blk].hi = next;

		/* The normalised step count - see the note in flow.h. */
		is_push = ix.Instruction == ND_INS_PUSH;
		if (is_nop(&ix)) {
			/* no step */
		} else if (is_push) {
			if (!in_push_run)
				step++;
		} else {
			step++;
		}
		in_push_run = is_push;

		/*
		 * STRUCTURE, when a caller asked for it. A direct call names a
		 * function; a backward direct branch spans a loop. Both are
		 * recorded and neither is followed - this is still one pass.
		 */
		if (f) {
			uint64_t tgt = 0;

			/*
			 * A TAIL JUMP IS A CALL, and reading it as a block
			 * end is how a capability goes missing.
			 *
			 * `return commit_creds(x);` compiles to `jmp
			 * commit_creds` - the callee runs and this function
			 * does not come back, which is every sense of "call"
			 * a chain cares about. Measured over 254 relocatable
			 * objects: of 19 vocabulary calls the sweep missed,
			 * commit_creds accounted for six and wake_up_process
			 * for seven, and every one of them was a tail jump.
			 * commit_creds is the sharpest word in the kernel
			 * vocabulary, so losing it loses the finding.
			 *
			 * ONLY WHEN THE TARGET RESOLVES. An ordinary jump
			 * inside a function resolves to nothing and is left
			 * exactly as it was - this adds a node where there is
			 * a name for one, and changes no block, loop or
			 * register bookkeeping.
			 */
			if (ix.Instruction == ND_INS_CALLNR ||
			    ix.Instruction == ND_INS_JMPNR) {
				int tail = ix.Instruction == ND_INS_JMPNR;

				tgt = branch_target(&ix, next);
				/*
				 * AND THE CALLER MAY KNOW BETTER. An unlinked
				 * `call` has a hole where its displacement
				 * goes, so the target decodes as the next
				 * instruction and says nothing; the
				 * relocation says where it really goes, and
				 * only the caller has those - see
				 * kof_flow_retargeter.
				 */
				if (f->retarget) {
					uint64_t re = f->retarget(next,
							f->retarget_user);

					if (re)
						tgt = re;
				}
				/*
				 * AND IF THE BODY CALLED IS A GET-PC THUNK,
				 * THE REGISTER IT RETURNS IS A CONSTANT.
				 *
				 * Followed here and nowhere else, because
				 * this is the one function whose return value
				 * is decidable without running it - see
				 * pc_thunk. It is what makes a 32-bit PIC
				 * loader readable: without it `jmp
				 * *0x10b7(%eax)` is an unknown address and
				 * every import the loader has disappears.
				 */
				if (!tail) {
					uint32_t tr = NGPR;
					uint64_t tv = 0;

					if (pc_thunk(code, code_n, code_va,
						     tgt, next, bits,
						     &tr, &tv)) {
						forget(&c, tr);
						c.v[tr] = tv;
						c.known[tr] = 8;
						c.selfp[tr] = 1;
					}
				}
				if (!tail && tgt >= code_va &&
				    tgt < code_va + code_n) {
					add_head_derived(f, tgt);
					add_edge(f, va, tgt, step);
					edge_snap_x86(f, &c, bits);
				}
				/*
				 * AND IT MAY BE AN IMPORT. Asked of the
				 * caller, which is the only side that can
				 * answer - see kof_flow_resolver. The node is
				 * placed at the CALL SITE and not at the stub:
				 * what matters is where in the program the
				 * thing is asked for.
				 */
				/*
				 * AND A TAIL JUMP IS ONLY ASKED ABOUT WHEN IT
				 * IS AN UNLINKED ONE.
				 *
				 * In a relocatable object the import table is
				 * keyed by the address AFTER each unlinked
				 * branch - that is what a decoder computes
				 * from a displacement of zero. An ordinary
				 * jump inside a function lands on instruction
				 * addresses too: skipping an error path puts
				 * it right after a call all the time. Asking
				 * about every jump therefore made the table
				 * answer for a branch that calls nothing -
				 * measured, 33 invented nodes across 254
				 * objects, `filp_close` and
				 * `wake_up_process` at addresses with no
				 * relocation within six bytes.
				 *
				 * A displacement of zero is exactly the hole
				 * a linker fills, so it is the only jump that
				 * can be a relocated tail call. A LINKED
				 * object has no hole and no retargeter, and
				 * there a jump into the PLT is a real tail
				 * call - so the test is applied only where
				 * the ambiguity exists.
				 */
				if (tail && f->retarget && tgt != next)
					goto no_import;
				if (f->resolve && n < cap) {
					uint32_t ans = resolve_cap(f, tgt);
					uint8_t k = (uint8_t)(ans & 0xffu);

					/*
					 * AND WHETHER THE MAPPING CAN BE
					 * RUN, which the name alone does not
					 * say: mprotect and mmap are the same
					 * import whatever they are asked for,
					 * and PROT_EXEC is the whole
					 * difference between a JIT and a
					 * stager.
					 *
					 * `prot` is the THIRD argument of
					 * both, which is rdx under SysV - the
					 * same register the syscall ABI puts
					 * it in, so one reader serves both.
					 *
					 * SIXTY-FOUR BIT ONLY. i386 passes
					 * arguments on the stack, and reading
					 * them needs the slot model this
					 * sweep does not have; there the
					 * weaker answer stands.
					 */
					if (k == KOF_CAP_ALLOC)
						k = prot_cap(&c, abi, bits, 1, &pflags);
					if (((ans >> 8) & 0xffu) == KOF_FLOW_ROLE_SOCK)
						k = sock_cap(&c, bits, abi, 1,
							     &pflags);
					if (k != KOF_CAP_NONE) {
						memset(&out[n], 0,
						       sizeof out[n]);
						out[n].va   = va;
						out[n].step = step;
						out[n].sel  = 0;
						out[n].cap  = k;
						out[n].name = (uint16_t)(ans >> 16);
						out[n].flags = (uint8_t)(pflags | KOF_FLOWF_BY_NAME);
						arg_scan(&c, bits, abi, 1,
							 &out[n]);
						thread_edge(f, &c, bits, abi, 1, va, step,
						    code_va, code_n, k);
						n++;
						/* The call returns in rax on
						 * both ABIs, and that is the
						 * pointer the chain follows. */
						forget(&c, R_RAX);
						c.src[R_RAX] = (uint16_t)n;
					}
				}
no_import:
				;
			} else if (ix.Instruction == ND_INS_CALLNI ||
				   ix.Instruction == ND_INS_JMPNI) {
				int tail_jmp = ix.Instruction == ND_INS_JMPNI;

				/*
				 * AN IMPORT IS CALLED THROUGH ITS SLOT, and on
				 * Windows that is the only way it is called:
				 * `call [rip+X]` where X is the address the
				 * loader wrote the function into. The ELF side
				 * reaches a PLT stub with a DIRECT call, so
				 * both forms have to be asked about or the
				 * whole of one platform reports nothing.
				 *
				 * A tail-call through the slot - `jmp [rip+X]`
				 * - is the same thing, and a thunk is written
				 * exactly that way.
				 */
				uint32_t q;

				for (q = 0; q < ix.OperandsCount && f->resolve;
				     q++) {
					uint64_t slot =
						mem_abs_reg(&c,
							    &ix.Operands[q],
							    next);
					uint32_t ans;
					uint8_t k;

					if (!slot)
						continue;
					ans = resolve_cap(f, slot);
					k = (uint8_t)(ans & 0xffu);
					if (k == KOF_CAP_NONE || n >= cap)
						continue;
					/*
					 * THE STUB ITSELF IS NOT A SECOND
					 * CALL, and reading it as one said
					 * everything twice.
					 *
					 * An ELF import is reached by a
					 * DIRECT call to a stub that holds
					 * nothing but this jump. The caller
					 * already gets the capability -
					 * kof_elf_imports registers the
					 * stub's address for exactly that -
					 * so the jump inside it is the same
					 * call seen from inside, and a chain
					 * that recorded both read
					 * `sleep, sleep, system, system`
					 * off a program that sleeps once.
					 *
					 * The test is whether the stub's own
					 * ENTRY resolves. The entry is
					 * sixteen bytes long, but WHERE those
					 * sixteen bytes start is a property
					 * of the section and not of the
					 * address space: one C++ binary here
					 * has .plt at 0x408ac8, so `va & ~15`
					 * names a point eight bytes inside
					 * the previous entry. Both offsets
					 * are tried rather than assuming
					 * either, which is two lookups
					 * against a table of tens.
					 *
					 * A Windows thunk is not affected -
					 * nothing registers its address, only
					 * the slot it jumps through, so there
					 * is no second node to drop.
					 */
					if (tail_jmp &&
					    (((resolve_cap(f, va & ~15ull)
					       & 0xffu) != KOF_CAP_NONE) ||
					     ((resolve_cap(f, (va & ~15ull) + 8u)
					       & 0xffu) != KOF_CAP_NONE) ||
					     ((resolve_cap(f, va)
					       & 0xffu) != KOF_CAP_NONE)))
						continue;
					if (((ans >> 8) & 0xffu) == KOF_FLOW_ROLE_SOCK)
						k = sock_cap(&c, bits, abi, 1,
							     &pflags);
					/* And whether the mapping can be run
					 * - the same question the direct-call
					 * path asks, and forgetting it here
					 * made every VirtualProtect on
					 * Windows an ordinary allocation. */
					if (k == KOF_CAP_ALLOC)
						k = prot_cap(&c, abi, bits, 1, &pflags);
					if ((k == KOF_CAP_ALLOC ||
					     k == KOF_CAP_ALLOC_EXEC) &&
					    n_mapped < 16u) {
						uint64_t a0;
						int l3;

						if ((bits == 32
						     ? stack_arg(&c, 0u, &a0,
								 NULL)
						     : const_of(&c,
						       abi == KOF_FLOW_MS ? 1u
									 : R_RDI,
						       &a0, &l3)) && a0) {
							mapped[n_mapped].addr = a0;
							mapped[n_mapped].node =
								(uint16_t)(n + 1u);
							n_mapped++;
						}
					}
					memset(&out[n], 0, sizeof out[n]);
					out[n].va   = va;
					out[n].step = step;
					out[n].cap  = k;
					out[n].name = (uint16_t)(ans >> 16);
					out[n].flags = (uint8_t)(pflags | KOF_FLOWF_BY_NAME);
					arg_scan(&c, bits, abi, 1, &out[n]);
					thread_edge(f, &c, bits, abi, 1, va, step,
					    code_va, code_n, k);
					n++;
					forget(&c, R_RAX);
					c.src[R_RAX] = (uint16_t)n;
					break;
				}
			} else if (ix.Instruction == ND_INS_JMPNR ||
				   is_cond_jump(&ix)) {
				tgt = branch_target(&ix, next);
				if (tgt >= code_va && tgt < va)
					add_loop(f, tgt, va);
			}
		}

		/*
		 * A STORE THROUGH A POINTER AN ALLOCATION RETURNED. See
		 * kof_flow_node.writers: the count is what separates a page a
		 * JIT emits into from a buffer a loader fills in one call.
		 *
		 * READ EARLY, because a store IS one of the forms below - `movb
		 * $0x90, (%rax)` is a MOV with an immediate source - and those
		 * consume the instruction and move on. Nothing here changes the
		 * map, so running it before them costs nothing.
		 */
		{
			uint32_t oi;

			for (oi = 0; oi < ix.OperandsCount; oi++) {
				const ND_OPERAND *op = &ix.Operands[oi];
				uint32_t b;
				uint16_t sr;

				if (op->Type != ND_OP_MEM ||
				    !op->Access.Write ||
				    !op->Info.Memory.HasBase)
					continue;
				b = op->Info.Memory.Base;
				if (b >= NGPR)
					continue;
				sr = c.src[b];
				if (!sr || sr > n)
					continue;
				if ((out[sr - 1u].cap == KOF_CAP_ALLOC ||
				     out[sr - 1u].cap == KOF_CAP_ALLOC_EXEC) &&
				    out[sr - 1u].writers < 255u)
					out[sr - 1u].writers++;
			}
		}

		/*
		 * THE THREE FORMS THAT PUT A NUMBER IN A REGISTER, and nothing
		 * else. This is the whole of the normalisation: `mov eax, 42`,
		 * `push 42 ; pop rax` and `xor eax, eax` are one fact, and
		 * which of them a variant used is not a fact about the malware.
		 */
		if (ix.Instruction == ND_INS_MOV && ix.OperandsCount >= 2 &&
		    ix.Operands[1].Type == ND_OP_IMM) {
			dst = gpr_of(&ix.Operands[0]);
			set_const(&c, dst, ix.Operands[1].Info.Immediate.Imm,
				  (uint8_t)(ix.Operands[0].Size > 8u
					    ? 8u : ix.Operands[0].Size));
			at += ix.Length;
			continue;
		}
		/*
		 * A LOAD FROM AN IMPORT SLOT MARKS THE REGISTER, so the call
		 * through it later can be read - see cmap.rcap.
		 */
		if (f && f->resolve && ix.Instruction == ND_INS_MOV &&
		    ix.OperandsCount >= 2 &&
		    ix.Operands[0].Type == ND_OP_REG &&
		    ix.Operands[1].Type == ND_OP_MEM) {
			uint64_t slot = mem_abs(&ix.Operands[1], next);
			uint32_t d2 = gpr_of(&ix.Operands[0]);

			if (slot && d2 < NGPR) {
				uint32_t k2 = resolve_cap(f, slot);

				forget(&c, d2);
				c.rcap[d2] = k2;
				at += ix.Length;
				continue;
			}
		}

		/*
		 * A RIP-RELATIVE LEA IS A CONSTANT, and on Windows it is the
		 * only way a stub names the buffer it is about to make
		 * executable. Without it `lea rcx,[rip+X]` is an unknown and
		 * the two ends of that shape cannot be tied together.
		 */
		if (ix.Instruction == ND_INS_LEA && ix.OperandsCount >= 2) {
			uint64_t a = mem_abs(&ix.Operands[1], next);

			dst = gpr_of(&ix.Operands[0]);
			if (a && dst < NGPR) {
				forget(&c, dst);
				c.v[dst] = a;
				c.known[dst] = 8;
				at += ix.Length;
				continue;
			}
		}
		if ((ix.Instruction == ND_INS_XOR ||
		     ix.Instruction == ND_INS_SUB) &&
		    ix.OperandsCount >= 2 &&
		    ix.Operands[0].Type == ND_OP_REG &&
		    ix.Operands[1].Type == ND_OP_REG &&
		    ix.Operands[0].Info.Register.Reg ==
		    ix.Operands[1].Info.Register.Reg) {
			dst = gpr_of(&ix.Operands[0]);
			set_const(&c, dst, 0, 8);
			at += ix.Length;
			continue;
		}
		if (ix.Instruction == ND_INS_PUSH && ix.OperandsCount >= 1) {
			if (ix.Operands[0].Type == ND_OP_IMM) {
				stack_push(&c,
					   ix.Operands[0].Info.Immediate.Imm,
					   8u, 0u);
			} else {
				uint32_t sr = gpr_of(&ix.Operands[0]);

				if (sr < NGPR)
					stack_push(&c, c.v[sr], c.known[sr],
						   c.src[sr]);
				else
					stack_push(&c, 0, 0, 0);
			}
			at += ix.Length;
			continue;
		}
		if (ix.Instruction == ND_INS_POP && ix.OperandsCount >= 1) {
			uint64_t sval = 0;
			uint8_t skn = 0;
			uint16_t ssr = 0;

			dst = gpr_of(&ix.Operands[0]);
			forget(&c, dst);
			if (stack_pop(&c, &sval, &skn, &ssr) && dst < NGPR) {
				c.v[dst] = sval;
				c.known[dst] = skn;
				c.src[dst] = ssr;
			}
			/*
			 * AND WHAT IT POPPED MAY BE THE RETURN ADDRESS, which
			 * the stack model above does not hold because a call
			 * is control flow here and not a push.
			 *
			 * The test is positional and does not need it: this
			 * instruction is the first of a body a `call` reached,
			 * and it takes the top of the stack into a register.
			 * The top of the stack at the first instruction of a
			 * called body is the return address, so the register
			 * now holds an address in this object's own code.
			 */
			if (dst < NGPR && ct && tset_has(ct, va))
				c.selfp[dst] = 1;
			at += ix.Length;
			continue;
		}

		/*
		 * ARITHMETIC ON A KNOWN CONSTANT, and only the four forms a
		 * hand-written stub uses to build a small number.
		 *
		 * i386 selects a socket operation with `xor ebx,ebx` and then
		 * `inc ebx` twice, so without this every socketcall on that
		 * ABI is unresolved and every i386 stager loses its network
		 * nodes - measured: three of them in this corpus.
		 *
		 * THE PROVENANCE DOES NOT SURVIVE IT. A number derived from a
		 * pointer is not that pointer, and treating it as one is how
		 * an edge gets invented.
		 */
		if ((ix.Instruction == ND_INS_INC ||
		     ix.Instruction == ND_INS_DEC ||
		     ix.Instruction == ND_INS_ADD ||
		     ix.Instruction == ND_INS_SUB) &&
		    ix.OperandsCount >= 1 &&
		    ix.Operands[0].Type == ND_OP_REG) {
			uint32_t r = gpr_of(&ix.Operands[0]);
			int64_t  by = 0;
			int ok = 0;

			if (ix.Instruction == ND_INS_INC) { by = 1; ok = 1; }
			else if (ix.Instruction == ND_INS_DEC) { by = -1; ok = 1; }
			else if (ix.OperandsCount >= 2 &&
				 ix.Operands[1].Type == ND_OP_IMM) {
				by = (int64_t)ix.Operands[1].Info.Immediate.Imm;
				if (ix.Instruction == ND_INS_SUB)
					by = -by;
				ok = 1;
			}
			if (ok && r < NGPR && c.known[r]) {
				c.v[r] = (uint64_t)((int64_t)c.v[r] + by);
				c.src[r] = 0;
				at += ix.Length;
				continue;
			}
			if (ok && r < NGPR) {
				forget(&c, r);
				at += ix.Length;
				continue;
			}
		}

		/*
		 * A CONTROL REGISTER WRITTEN, which is the one capability here
		 * that has no name anywhere to match - see KOF_CAP_PROT_OFF.
		 *
		 * Only the WRITE direction. `mov reg, cr0` is a read and every
		 * kernel that checks a CPU feature does one; `mov cr0, reg` is
		 * a kernel changing its own protections, and the reason an
		 * out-of-tree module does that is to make kernel text
		 * writable.
		 *
		 * The DESTINATION decides, not the mnemonic: bddisasm spells
		 * both directions ND_INS_MOV_CR, so reading the first operand
		 * is the whole test.
		 */
		/*
		 * A NAME BEING FOLDED INTO A NUMBER, which is how a program
		 * looks something up without the name being in the file.
		 *
		 * THE SHAPE AND NOT THE CONSTANT. Every write-up of this
		 * names `ror 13`, and 13 is the one part of it the author can
		 * change - to 14, to a shift, to anything that still mixes.
		 * What he cannot drop is the shape: a rotate of a register
		 * that is also accumulated into, sitting in a loop that reads
		 * a string. Matching the constant would be matching the
		 * fashion.
		 *
		 * So: a rotate by a small immediate, of a register - AND the
		 * accumulation, which is the half that was written here as a
		 * claim and not as code. The first version tested the rotate
		 * alone and measured what that is worth: 4095 nodes on one
		 * ransomware sample, which is the node array full. Every
		 * other thing that sample does was pushed out of its own
		 * analysis by its CRC loop.
		 *
		 * THE ACCUMULATION IS THE NEXT INSTRUCTION. A hash folds the
		 * byte in where it rotated:
		 *
		 *     ror  $0xd,%edi
		 *     add  %eax,%edi
		 *
		 * so the test is that the instruction immediately after the
		 * rotate writes the SAME register with an add, xor or sub.
		 * Not a window, because a window is a guess about how much
		 * code can sit between two halves of an idiom and this one
		 * has none in any build of it that has been read here.
		 *
		 * THE LOOP TEST STILL CANNOT BE MADE HERE - a loop is known
		 * only once the sweep meets the backward branch that closes
		 * it, and the rotate is inside, before that - so the flag is
		 * LEFT CLEAR for finish() to set and chain_walk drops what it
		 * did not mark. Setting it here, as this did, made that
		 * filter a no-op: every rotate claimed to be in a loop, so
		 * dropping the ones that were not dropped nothing.
		 */
		if ((ix.Instruction == ND_INS_ROR ||
		     ix.Instruction == ND_INS_ROL) &&
		    ix.OperandsCount >= 2 &&
		    ix.Operands[0].Type == ND_OP_REG &&
		    ix.Operands[1].Type == ND_OP_IMM &&
		    ix.Operands[1].Info.Immediate.Imm > 0u &&
		    ix.Operands[1].Info.Immediate.Imm < 32u && n < cap) {
			static uint16_t rol_name;
			INSTRUX nx;
			uint32_t rr = gpr_of(&ix.Operands[0]);
			int folds = 0;

			if (at + ix.Length < code_n &&
			    ND_SUCCESS(NdDecodeEx(&nx, code + at + ix.Length,
						  code_n - at - ix.Length,
						  bits == 32 ? ND_CODE_32
							     : ND_CODE_64,
						  bits == 32 ? ND_DATA_32
							     : ND_DATA_64)) &&
			    (nx.Instruction == ND_INS_ADD ||
			     nx.Instruction == ND_INS_XOR ||
			     nx.Instruction == ND_INS_SUB ||
			     nx.Instruction == ND_INS_ADC) &&
			    nx.OperandsCount >= 2 &&
			    nx.Operands[0].Type == ND_OP_REG &&
			    gpr_of(&nx.Operands[0]) == rr && rr < NGPR)
				folds = 1;
			/*
			 * AND NO COUNT LIMIT HERE. There was one - eight per
			 * object - and it was wrong in kind: a ceiling exists
			 * to stop a crafted input costing unbounded work, not
			 * to make a loose test look tidy. A test that needs a
			 * quota to be bearable is a test that is wrong, and
			 * the quota then throws away real steps on whatever
			 * object happens to be past it.
			 *
			 * What does the work is the shape - a rotate, folded
			 * into the same register by the next instruction,
			 * within a few instructions of a SINGLE-BYTE load.
			 * The node array's own bound is the DoS bound and it
			 * is the only one needed.
			 */
			/* MEASUREMENT ONLY: the pre-fix behaviour, so the
			 * corpus delta this fix caused can be attributed
			 * rather than argued about. Off unless asked. */
			if (oldhash < 0)
				oldhash = getenv("KOF_OLDHASH") ? 1 : 0;
			if (oldhash) {
				if (!rol_name)
					rol_name = kof_flow_name_id("name_hash");
				memset(&out[n], 0, sizeof out[n]);
				out[n].va = va;
				out[n].step = step;
				out[n].cap = KOF_CAP_NAME_HASH;
				out[n].name = rol_name;
				out[n].flags = KOF_FLOWF_LOOP;
				n++;
				at += ix.Length;
				continue;
			}
			if (folds && since_byte < 8u) {
				if (!rol_name)
					rol_name = kof_flow_name_id("name_hash");
				memset(&out[n], 0, sizeof out[n]);
				out[n].va = va;
				out[n].step = step;
				out[n].cap = KOF_CAP_NAME_HASH;
				out[n].name = rol_name;
				n++;
				at += ix.Length;
				continue;
			}
		}

		/*
		 * THE LOADER'S OWN DATA, REACHED THROUGH THE THREAD BLOCK.
		 *
		 * fs:[0x30] on 32-bit and gs:[0x60] on 64-bit are where
		 * Windows keeps the pointer to the PEB, and the PEB is how a
		 * program finds the module list without the loader's help.
		 * The offset is the OS's and cannot be moved - see
		 * KOF_CAP_SELF_RESOLVE for why the hash loop beside it is not
		 * what this tests.
		 *
		 * The segment override byte is the whole test: bddisasm
		 * reports the last one on the instruction, 0x64 for FS and
		 * 0x65 for GS.
		 */
		if (ix.OperandsCount >= 2 &&
		    ix.Operands[1].Type == ND_OP_MEM &&
		    ix.Operands[1].Info.Memory.HasDisp &&
		    ((ix.Seg == 0x64u && bits == 32 &&
		      ix.Operands[1].Info.Memory.Disp == 0x30u) ||
		     (ix.Seg == 0x65u && bits == 64 &&
		      ix.Operands[1].Info.Memory.Disp == 0x60u)) &&
		    n < cap) {
			static uint16_t peb_name;

			if (!peb_name)
				peb_name = kof_flow_name_id("peb_ldr");
			memset(&out[n], 0, sizeof out[n]);
			out[n].va = va;
			out[n].step = step;
			out[n].cap = KOF_CAP_SELF_RESOLVE;
			out[n].name = peb_name;
			n++;
			at += ix.Length;
			continue;
		}

		if (ix.Instruction == ND_INS_MOV_CR && ix.OperandsCount >= 2 &&
		    ix.Operands[0].Type == ND_OP_REG &&
		    ix.Operands[0].Info.Register.Type == ND_REG_CR &&
		    n < cap) {
			/* Looked up once: the table is static and so is the
			 * answer. */
			static uint16_t cr_name;

			if (!cr_name)
				cr_name = kof_flow_name_id("mov_cr0");
			memset(&out[n], 0, sizeof out[n]);
			out[n].va = va;
			out[n].step = step;
			out[n].cap = KOF_CAP_PROT_OFF;
			out[n].name = cr_name;
			n++;
			at += ix.Length;
			continue;
		}

		/*
		 * THE SYSCALL ITSELF. `syscall` on x86-64, `int 0x80` on i386,
		 * and sysenter is deliberately absent - no sample in this tree
		 * uses it and a row nothing exercises is a row nothing checks.
		 */
		if (ix.Instruction == ND_INS_SYSCALL ||
		    (ix.Instruction == ND_INS_INT && ix.OperandsCount >= 1 &&
		     ix.Operands[0].Type == ND_OP_IMM &&
		     ix.Operands[0].Info.Immediate.Imm == 0x80)) {
			uint8_t k = KOF_CAP_NONE;
			uint16_t sel = 0;

			/*
			 * AND THE TABLE BELOW IS LINUX'S, which is why this
			 * asks first.
			 *
			 * A PE that issues `syscall` directly is doing
			 * something real - it is going round ntdll, which is
			 * where an EDR puts its hooks - but the NUMBER means
			 * nothing here: Windows renumbers between builds, so
			 * there is no table to look it up in. Reading it with
			 * kof_sys64 said `sched_yield` for 0x18 and meant nothing
			 * at all.
			 *
			 * So the number is recorded and no capability is
			 * claimed from it. What the object DID is still true
			 * and still readable; what it asked for is not.
			 */
			if (abi == KOF_FLOW_MS) {
				if (const_of(&c, R_RAX, &nr, &low8) && n < cap) {
					memset(&out[n], 0, sizeof out[n]);
					out[n].va = va;
					out[n].step = step;
					out[n].sel = (uint16_t)nr;
					out[n].cap = KOF_CAP_NONE;
					n++;
				}
				forget(&c, R_RAX);
				forget(&c, R_RCX);
				at += ix.Length;
				continue;
			}
			if (const_of(&c, R_RAX, &nr, &low8)) {
				sel = (uint16_t)nr;
				if (bits == 32) {
					k = kof_sys_look(kof_sys32, kof_sys32_n,
						 (uint32_t)nr);
					if (nr == 102) {
						uint64_t sub;
						int l2;

						if (const_of(&c, R_RBX, &sub,
							     &l2))
							k = kof_sys_look(kof_sockcall,
								 kof_sockcall_n,
								 (uint32_t)sub);
					}
					if (nr == 125 || nr == 192 || nr == 90)
						k = prot_cap(&c, abi, bits, 0, &pflags);
					if (nr == 120)
						k = clone_cap(&c, bits);
				} else {
					k = kof_sys_look(kof_sys64, kof_sys64_n,
						 (uint32_t)nr);
					if (nr == 9 || nr == 10)
						k = prot_cap(&c, abi, bits, 0, &pflags);
					else if (nr == 56)
						k = clone_cap(&c, bits);
					else if (nr == 41)
						k = sock_cap(&c, bits, abi, 0, &pflags);
				}
			}
			if ((k == KOF_CAP_ALLOC || k == KOF_CAP_ALLOC_EXEC) &&
			    n_mapped < 16u) {
				uint64_t a0;
				int l3;

				if (const_of(&c, bits == 32 ? R_RBX : R_RDI,
					     &a0, &l3) && a0) {
					mapped[n_mapped].addr = a0;
					mapped[n_mapped].node = (uint16_t)(n + 1u);
					n_mapped++;
				}
			}
			/*
			 * A SYSCALL WHOSE NUMBER IS NOT HERE, recorded anyway
			 * when the body has only just begun.
			 *
			 * It is a thunk, and the number is in the caller -
			 * see cedge.sel for the disassembly this came from.
			 * The node is placed with KOF_FLOW_SEL_PENDING in its
			 * selector and NO capability, and edge_args fills
			 * both from what every caller agreed eax was. One
			 * that nothing calls, or whose callers disagree,
			 * keeps KOF_CAP_NONE and is skipped by the chain -
			 * which is also what happens to the `cd 80` byte pair
			 * that is really a literal pool.
			 *
			 * EIGHT INSTRUCTIONS, because the shape measured is
			 * `ret ; int 0x80` and glibc's longest variant puts a
			 * push and a move in front of it. Far from a return,
			 * an unknown eax is the sweep having lost it, and
			 * there is nobody to ask.
			 */
			if (k == KOF_CAP_NONE && !sel && since_ret <= 8u &&
			    n < cap) {
				memset(&out[n], 0, sizeof out[n]);
				out[n].va   = va;
				out[n].step = step;
				out[n].sel  = KOF_FLOW_SEL_PENDING;
				out[n].cap  = KOF_CAP_NONE;
				arg_scan(&c, bits, abi, 0, &out[n]);
				n++;
			}
			if (k != KOF_CAP_NONE) {
				memset(&out[n], 0, sizeof out[n]);
				out[n].va    = va;
				out[n].step  = step;
				out[n].sel   = sel;
				out[n].cap   = k;
				/* And what the kernel calls it, so a reader is
				 * not handed a number whose meaning is in a
				 * table two files away. */
				/*
				 * AND THE SUB-CALL WHERE THERE IS ONE: i386
				 * puts every socket operation behind
				 * socketcall(102), so naming the step
				 * `socketcall` would throw away the only
				 * part of it that says anything.
				 */
				if (bits == 32 && sel == 102u) {
					uint64_t sub;
					int l4;

					out[n].name = const_of(&c, R_RBX,
							       &sub, &l4)
						? kof_flow_name_id(
							kof_sys_look_name(kof_sockcall,
								  kof_sockcall_n,
								  (uint32_t)sub))
						: 0u;
				} else {
					out[n].name = kof_flow_name_id(
						bits == 32
						? kof_sys_look_name(kof_sys32,
							    kof_sys32_n,
							    sel)
						: kof_sys_look_name(kof_sys64,
							    kof_sys64_n,
							    sel));
				}
				arg_scan(&c, bits, abi, 0, &out[n]);
				thread_edge(f, &c, bits, abi, 0, va, step,
						    code_va, code_n, k);
				out[n].flags |= (uint8_t)((low8 ? KOF_FLOWF_LOW8
							       : 0u) | pflags);
				/* Now that the node has a name, the registers
				 * past this call's last argument are not its
				 * arguments - see arg_trim. */
				arg_trim(&out[n]);
				/* And whether that descriptor came from a
				 * socket - see net_fd_cap. */
				out[n].cap = net_fd_cap(out, n, &out[n]);
				n++;
			}
			/*
			 * THE RETURN VALUE REPLACES THE SELECTOR, and every
			 * caller-clobbered register is gone. Forgetting is the
			 * conservative direction - a remembered stale number
			 * would invent a second syscall that never happens.
			 *
			 * But the register is not empty: it now holds what this
			 * node PRODUCED, and that is what the chain follows.
			 */
			forget(&c, R_RAX);
			forget(&c, R_RCX);
			if (k != KOF_CAP_NONE)
				c.src[R_RAX] = (uint16_t)n;
			/*
			 * AND A SYSCALL THAT NEVER RETURNS ENDS THE PATH -
			 * see kof_sys_noreturn. Without this the sweep walks
			 * out of an `exit(1)` into whatever is written next
			 * and carries the dead path's registers into it.
			 */
			if (kof_sys_noreturn(bits, (uint32_t)sel)) {
				cut_clear(&c);
				no_fall = 1;
				/*
				 * AND THE BLOCK ENDS HERE WITH NO SUCCESSOR.
				 * The ordinary close below is never reached -
				 * this path continues - so it has to be done
				 * here, and leaving it out is what let a
				 * block run through an `exit` into the code
				 * after it. Everything that asks "can A reach
				 * B" was answered off that false edge,
				 * including whether a backward branch is a
				 * loop.
				 */
				if (f && cur_blk < f->n_blk)
					cur_blk = blk_open(f, next);
				at += ix.Length;
				continue;
			}
			/* Whether a branch on this result can be read - see
			 * the note on ok_at. */
			sysret = 0xffffu;
			cmp_ret = 0;
			if (k != KOF_CAP_NONE && n &&
			    kof_sys_zero_on_success(
				    kof_flow_name_of(out[n - 1u].name)))
				sysret = 0;
			at += ix.Length;
			continue;
		}

		/*
		 * A RETURN ENDS WHAT IS KNOWN, and forgetting this was a
		 * measured false edge rather than a theoretical one.
		 *
		 * The sweep is linear over a whole section, so without this
		 * the map carries across function boundaries: gdb calls
		 * ptrace, rax is recorded as holding its result, and an
		 * indirect call in some LATER function - a different function,
		 * hundreds of instructions on - closed an edge that says the
		 * value ptrace returned was executed. It was not; the two
		 * instructions have nothing to do with each other.
		 *
		 * A `ret` is where a body ends in every layout this can meet,
		 * and clearing there bounds every fact to one body without
		 * needing the two passes a real function partition would take.
		 * Padding between bodies decodes as whatever it decodes as,
		 * and cannot resurrect what has been cleared.
		 */
		/*
		 * AND THE EDGE ITSELF: an indirect branch through a register
		 * that holds what an earlier node produced. See
		 * KOF_FLOWF_EXECUTED for why this one fact is worth the whole
		 * file.
		 */
		if (ix.Instruction == ND_INS_CALLNI ||
		    ix.Instruction == ND_INS_JMPNI) {
			for (i = 0; i < ix.OperandsCount; i++) {
				uint32_t r = gpr_of(&ix.Operands[i]);
				uint16_t sr;
				uint32_t q;

				/* The register was loaded from an import
				 * slot: this call IS that import. */
				if (r < NGPR &&
				    (c.rcap[r] & 0xffu) != KOF_CAP_NONE &&
				    n < cap) {
					uint8_t k3 = (uint8_t)(c.rcap[r] & 0xffu);

					if (k3 == KOF_CAP_ALLOC)
						k3 = prot_cap(&c, abi, bits, 1, &pflags);
					if (((c.rcap[r] >> 8) & 0xffu) ==
					    KOF_FLOW_ROLE_SOCK)
						k3 = sock_cap(&c, bits, abi, 1,
							      &pflags);
					if ((k3 == KOF_CAP_ALLOC ||
					     k3 == KOF_CAP_ALLOC_EXEC) &&
					    n_mapped < 16u) {
						uint64_t a0;
						int l4;

						if ((bits == 32
						     ? stack_arg(&c, 0u, &a0, NULL)
						     : const_of(&c,
						       abi == KOF_FLOW_MS ? 1u
									 : R_RDI,
						       &a0, &l4)) && a0) {
							mapped[n_mapped].addr = a0;
							mapped[n_mapped].node =
								(uint16_t)(n + 1u);
							n_mapped++;
						}
					}
					memset(&out[n], 0, sizeof out[n]);
					out[n].va    = va;
					out[n].step  = step;
					out[n].cap   = k3;
					out[n].name  = (uint16_t)(c.rcap[r] >> 16);
					/*
					 * `|=` AND NOT `=`, which it was. The
					 * line below used to assign, and it
					 * ran AFTER the BY_NAME bit was set -
					 * so a call made through a register
					 * to a named import kept the name and
					 * lost the flag that says the step
					 * was read from one. That flag is the
					 * difference between evidence an
					 * author can avoid by resolving the
					 * address himself and evidence he
					 * cannot, which is the distinction
					 * this whole path exists to record.
					 */
					out[n].flags |= (uint8_t)
						(KOF_FLOWF_BY_NAME |
						 KOF_FLOWF_VIA_REG | pflags);
					arg_scan(&c, bits, abi, 1,
						 &out[n]);
					thread_edge(f, &c, bits, abi, 1, va, step,
					    code_va, code_n, k3);
					n++;
					forget(&c, R_RAX);
					c.src[R_RAX] = (uint16_t)n;
				}

				if (r >= NGPR || !ix.Operands[i].Access.Read)
					continue;
				/*
				 * THE DISPATCHER CALL, before anything about
				 * provenance - this register was never
				 * returned by a step, which is exactly why the
				 * branch below says nothing about it.
				 *
				 * One node per call site rather than one for
				 * the dispatcher, because what the chain needs
				 * to show is HOW MUCH of the program goes
				 * through it. A body with one is a thunk; a
				 * body with nineteen has no other way of
				 * reaching the system. Collapse folds the
				 * consecutive ones, so a chain reads this as a
				 * single repeated step and not as nineteen.
				 */
				if (c.selfp[r] && n < cap) {
					memset(&out[n], 0, sizeof out[n]);
					out[n].va = va;
					out[n].step = step;
					out[n].cap = KOF_CAP_CALL_REG;
					out[n].flags = (uint8_t)
						(KOF_FLOWF_VIA_REG | pflags);
					/*
					 * AND NOTHING ABOUT WHAT WAS PUSHED.
					 *
					 * The pushed selector was recorded
					 * here for one build, on the argument
					 * that a reader seeing nine identical
					 * lines needs to tell them apart. It
					 * was wrong twice over.
					 *
					 * IT IS NOT CONSISTENT. The stack
					 * model this would read is per-block
					 * and is cleared at a join, so the
					 * three calls before the first loop
					 * carried values and the six after it
					 * carried none. A field that is
					 * populated for the first few steps
					 * and empty for the rest is worse
					 * than an empty one: it reads as a
					 * fact about the program when it is a
					 * fact about where the sweep lost
					 * track.
					 *
					 * AND IT IS A VALUE THE AUTHOR PICKS.
					 * The selector is a hash with a seed
					 * he reseeds between builds. Even
					 * though nothing in diagnose.c reads
					 * arg[] today, putting a per-build
					 * constant on the node is leaving it
					 * where a later rule can reach it.
					 *
					 * What carries the "nine different
					 * calls" fact is that they are nine
					 * separate STEPS - see the collapse
					 * rule - and that needs no value.
					 */
					n++;
				}
				sr = c.src[r];
				if (sr && sr <= n)
					out[sr - 1u].flags |=
						KOF_FLOWF_EXECUTED;
				/*
				 * AND A STEP OF ITS OWN, at the branch.
				 *
				 * The flag above marks the ALLOCATION, which
				 * is where the memory came from and not where
				 * the program hands itself over. A chain
				 * needs the second: it is the last thing the
				 * readable code does, and without it a stager
				 * reads as four ordinary calls. The link
				 * carries which step made the memory.
				 */
				if (sr && sr <= n && n < cap) {
					memset(&out[n], 0, sizeof out[n]);
					out[n].va = va;
					out[n].step = step;
					out[n].cap = KOF_CAP_EXEC_REG;
					out[n].from[0] = sr;
					out[n].flags = (uint8_t)
						(KOF_FLOWF_VIA_REG | pflags);
					n++;
				}
				/* Or the branch goes to an address something
				 * earlier was asked to make executable. */
				if (!c.known[r])
					continue;
				for (q = 0; q < n_mapped; q++)
					if (mapped[q].addr == c.v[r] &&
					    mapped[q].node <= n) {
						out[mapped[q].node - 1u].flags
							|= KOF_FLOWF_EXECUTED;
						if (n >= cap)
							continue;
						memset(&out[n], 0,
						       sizeof out[n]);
						out[n].va = va;
						out[n].step = step;
						out[n].cap = KOF_CAP_EXEC_REG;
						out[n].from[0] =
							mapped[q].node;
						out[n].flags = (uint8_t)
							(KOF_FLOWF_VIA_REG |
							 pflags);
						n++;
					}
			}
		}

		/*
		 * AND ONLY THEN IS THE MAP CLEARED. The edge above has to be
		 * read BEFORE this, because the instruction that closes it -
		 * `jmp r13` - is itself one of the transfers that ends the
		 * block. Clearing first cost the one edge this file exists to
		 * find, on its own test vector.
		 */
		/*
		 * A BLOCK ENDS WHERE CONTROL LEAVES IT, and its successors are
		 * whatever control can go to. A conditional branch has two: the
		 * target and the fall-through. An unconditional one has the
		 * target only. A return has none, and an INDIRECT branch has
		 * none THAT THIS CAN SEE - which is not the same thing, so the
		 * block is marked open_end and anything downstream of it is
		 * UNKNOWN rather than unreachable.
		 */
		if (f && cur_blk < f->n_blk) {
			int closes = 0;

			if (is_cond_jump(&ix)) {
				uint64_t tg = branch_target(&ix, next);

				if (tg)
					blk_succ(f, cur_blk, tg);
				blk_succ(f, cur_blk, next);
				closes = 1;
			} else if (ix.Instruction == ND_INS_JMPNR) {
				uint64_t tg = branch_target(&ix, next);

				if (tg)
					blk_succ(f, cur_blk, tg);
				closes = 1;
			} else if (ix.Instruction == ND_INS_JMPNI) {
				f->blk[cur_blk].open_end = 1;
				closes = 1;
			} else if (ix.Instruction == ND_INS_RETN ||
				   ix.Instruction == ND_INS_RETF) {
				closes = 1;
			}
			if (closes)
				cur_blk = blk_open(f, next);
		}

		if (ix.Instruction == ND_INS_RETN ||
		    ix.Instruction == ND_INS_RETF ||
		    ix.Instruction == ND_INS_JMPNR ||
		    ix.Instruction == ND_INS_JMPNI) {
			if (ix.Instruction == ND_INS_RETN ||
			    ix.Instruction == ND_INS_RETF)
				since_ret = 0;
			/* Control does not fall through any of these, so what
			 * follows in ADDRESS order is not what follows in
			 * execution order. A return also ends the stack this
			 * was following; a jump does not. */
			cut_clear(&c);
			no_fall = 1;
			if (ix.Instruction == ND_INS_RETN ||
			    ix.Instruction == ND_INS_RETF) {
				stack_drop(&c);
				memset(c.selfp, 0, sizeof c.selfp);
			}
			at += ix.Length;
			continue;
		}

		/*
		 * AND SO DOES AN EXCHANGE, which is the same move written in
		 * one instruction.
		 *
		 * `xchg %rax,%rdi` is how hand-written shellcode keeps a
		 * descriptor: the syscall's result is in rax and the next
		 * call wants it in rdi, and one byte does it. It was not
		 * handled at all - it fell through to "anything else that
		 * writes a GPR is forgotten" - so the socket a stager opens
		 * stopped being followed at the exchange, and `connect` and
		 * `read` had no link back to it.
		 *
		 * Everything about both registers swaps, including the
		 * provenance and the own-code flag: after the instruction
		 * each holds exactly what the other held.
		 */
		if (ix.Instruction == ND_INS_XCHG && ix.OperandsCount >= 2 &&
		    ix.Operands[0].Type == ND_OP_REG &&
		    ix.Operands[1].Type == ND_OP_REG) {
			uint32_t x = gpr_of(&ix.Operands[0]);
			uint32_t y = gpr_of(&ix.Operands[1]);

			if (x < NGPR && y < NGPR && x != y) {
				uint64_t tv = c.v[x];
				uint8_t  tk = c.known[x], ts = c.selfp[x];
				uint16_t tr = c.src[x];
				uint32_t tc = c.rcap[x];

				c.v[x] = c.v[y];         c.v[y] = tv;
				c.known[x] = c.known[y]; c.known[y] = tk;
				c.src[x] = c.src[y];     c.src[y] = tr;
				c.rcap[x] = c.rcap[y];   c.rcap[y] = tc;
				c.selfp[x] = c.selfp[y]; c.selfp[y] = ts;
				at += ix.Length;
				continue;
			}
		}

		/*
		 * A REGISTER TO REGISTER MOVE CARRIES THE PROVENANCE, because
		 * that is how a returned pointer reaches the register a call
		 * is made through: `mov r13, rax` and four instructions later
		 * `call r13`.
		 */
		if (ix.Instruction == ND_INS_MOV && ix.OperandsCount >= 2 &&
		    ix.Operands[0].Type == ND_OP_REG &&
		    ix.Operands[1].Type == ND_OP_REG) {
			uint32_t d = gpr_of(&ix.Operands[0]);
			uint32_t sr = gpr_of(&ix.Operands[1]);

			if (d < NGPR && sr < NGPR) {
				uint16_t keep = c.src[sr];
				uint8_t  self = c.selfp[sr];

				forget(&c, d);
				c.src[d] = keep;
				/* `mov %ebp,%eax ; call *%eax` is the same
				 * dispatcher call written one register wider,
				 * and this stager uses both spellings in the
				 * same forty bytes. */
				c.selfp[d] = self;
				at += ix.Length;
				continue;
			}
		}

		/* Anything else that writes a GPR ends what was known of it. */
		for (i = 0; i < ix.OperandsCount; i++)
			if (ix.Operands[i].Access.Write)
				forget(&c, gpr_of(&ix.Operands[i]));
		at += ix.Length;
	}
	free(t);
	free(ct);
	free(ok_at);
	free(jst);
	if (n >= cap)
		if (f)
			f->full = 1;
	return n;
}

uint32_t kof_flow_scan(const uint8_t *code, uint32_t code_n, uint64_t code_va,
		       unsigned bits, unsigned abi, struct kof_flow_node *out,
		       uint32_t cap)
{
	if (!code || !out || !cap)
		return 0;
	if (cap > KOF_FLOW_MAX_NODE)
		cap = KOF_FLOW_MAX_NODE;
	return sweep(NULL, code, code_n, code_va, bits, abi, out, cap);
}

/*
 * ---- THE FIXED-WIDTH ARCHITECTURES ----------------------------------------
 *
 * WHY THIS IS NOT A SECOND DISASSEMBLER, AND WHY IT DOES NOT NEED TO BE.
 *
 * bddisasm reads x86, and until now an ARM or MIPS object answered nothing at
 * all. Measured over MalwareLab: 245 of 838 ELF samples - 29% - were refused
 * for their architecture, and 194 of those were ARM or MIPS, which is exactly
 * where an IoT botnet lives. `new_Mirai` returned a chain for 0 of 25.
 *
 * THE PRICE OF READING THEM IS SMALL, because the question is small. A chain
 * needs the syscall SELECTOR and nothing else about the instruction stream,
 * and on a fixed-width RISC that is two patterns:
 *
 *     MIPS32    li $v0,N  = addiu/ori $v0,$zero,N      syscall = 0x0000000c
 *     ARM32     mov r7,#imm (with rotation)            svc #0  = 0x_F000000
 *               Thumb: movs r7,#imm8 = 0x27xx          svc     = 0xDFxx
 *               OABI:  svc #(0x900000+N), N in the instruction itself
 *     AArch64   movz x8/w8,#N                          svc #0  = 0xD4000001
 *
 * AND IT WORKS BETTER HERE THAN ON x86, for a reason that is about the corpus
 * and not about the instruction set: 146 of 161 non-x86 samples measured are
 * STATICALLY LINKED, so the syscall is in the object. A dynamic x86 program
 * has none at all and everything depends on resolving its imports.
 *
 * Measured with a standalone prototype of exactly this: 91% of 478 MIPS
 * objects and 31% of 1771 ARM ones carry at least one syscall in the
 * capability vocabulary. The ARM figure is a FLOOR - the prototype did not
 * read literal-pool loads (`ldr r7,[pc,#..]`) or Thumb-2 `mov.w`, and neither
 * does this.
 *
 *
 * WHAT IS APPROXIMATED, stated here rather than discovered later:
 *
 *   - The selector is tracked through the ONE load form each architecture
 *     uses for a small constant. A number arriving any other way - a literal
 *     pool, a computed value, a register copy - leaves the node unresolved,
 *     which is `sel = 0` and KOF_CAP_NONE, the same answer the x86 sweep
 *     gives when it loses a selector.
 *   - ARM and Thumb are not distinguished by anything in the file, because
 *     nothing in an ELF says which a given run of bytes is. The ARM pass runs
 *     first and the Thumb pass only if it found nothing, which is the
 *     conservative order: a Thumb stream read as ARM yields garbage selectors
 *     that resolve to no capability, so it falls through.
 *   - Provenance is the clear case only: a syscall's result lives in a known
 *     register, and a register-to-register copy of it into a known argument
 *     register before the next syscall is a link. Anything through memory is
 *     not followed. kof_flow_node.from already means "no link was SEEN".
 */



/* Both of this ABI's tables, in the order they were declared - see fxabi. */
static uint8_t fx_look(const struct fxabi *A, uint32_t nr)
{
	uint8_t k = kof_sys_look(A->tab, A->n_tab, nr);

	if (k == KOF_CAP_NONE && A->tab2)
		k = kof_sys_look(A->tab2, A->n_tab2, nr);
	return k;
}

static const char *fx_name(const struct fxabi *A, uint32_t nr)
{
	const char *nm = kof_sys_look_name(A->tab, A->n_tab, nr);

	if (!nm && A->tab2)
		nm = kof_sys_look_name(A->tab2, A->n_tab2, nr);
	return nm;
}


const char *kof_flow_sys_name(unsigned arch, uint32_t nr)
{
	if (arch == KOF_FLOW_A_X86)
		return kof_sys_look_name(kof_sys32, kof_sys32_n, nr);
	if (arch == KOF_FLOW_A_X86_64)
		return kof_sys_look_name(kof_sys64, kof_sys64_n, nr);
	{
		const struct fxabi *A = kof_fx_abi_of(arch);

		return A ? fx_name(A, nr) : 0;
	}
}

static uint8_t fx_role(const struct fxabi *A, uint32_t nr)
{
	uint8_t r = kof_sys_look_role(A->tab, A->n_tab, nr);

	if (r == KOF_FLOW_ROLE_NONE && A->tab2)
		r = kof_sys_look_role(A->tab2, A->n_tab2, nr);
	return r;
}

/* This ABI's four argument registers, onto the edge just added. */
/*
 * PROT_EXEC, and the argument it is in.
 *
 * Every one of these ABIs puts prot third in mmap and in mprotect, exactly as
 * POSIX does on x86 - so the only thing that differs from prot_cap is which
 * register the third argument lives in, and the caller passes the value.
 */
static uint8_t fixed_prot(uint8_t cap, uint64_t prot, int known, uint8_t *flags)
{
	if (cap != KOF_CAP_ALLOC || !known)
		return cap;
	if ((prot & 6u) == 6u && flags)
		*flags |= KOF_FLOWF_WX;
	return (prot & 4u) ? KOF_CAP_ALLOC_EXEC : KOF_CAP_ALLOC;
}

/* The fixed-width sweep's register state - decoding, not vocabulary. */
#define FX_NREG 32u

struct fxreg {
	uint64_t v[FX_NREG];
	uint8_t  known[FX_NREG];
	/* The node that produced this value, as index plus one - the same
	 * spelling kof_flow_node.from uses, and for the same reason. */
	uint16_t src[FX_NREG];
};

static void fx_set(struct fxreg *r, unsigned i, uint64_t v)
{
	if (i < FX_NREG) { r->v[i] = v; r->known[i] = 1; r->src[i] = 0; }
}

static void fx_copy(struct fxreg *r, unsigned d, unsigned s)
{
	if (d < FX_NREG && s < FX_NREG) {
		r->v[d] = r->v[s]; r->known[d] = r->known[s]; r->src[d] = r->src[s];
	}
}

static void edge_snap_fixed(struct kof_flow *f, const struct fxreg *r,
			    const struct fxabi *A)
{
	uint64_t v[4] = { 0, 0, 0, 0 };
	uint16_t src[4] = { 0, 0, 0, 0 };
	uint8_t known = 0;
	unsigned a;

	for (a = 0; a < 4u && a < A->n_arg; a++) {
		unsigned g = A->arg0 + a;

		if (g >= FX_NREG)
			break;
		v[a] = r->v[g];
		src[a] = r->src[g];
		if (r->known[g] && !r->src[g])
			known |= (uint8_t)(1u << a);
	}
	/* The selector is not carried here. These ABIs put it in a register
	 * the caller does not set - a MIPS or ARM wrapper loads its own - so
	 * there is nothing on this edge to carry. */
	edge_snap(f, v, src, known,
		  A->sel < FX_NREG ? r->v[A->sel] : 0,
		  A->sel < FX_NREG ? (r->known[A->sel] && !r->src[A->sel]) : 0);
}

/*
 * ONE PASS OVER FIXED-WIDTH CODE, for the three ABIs above.
 *
 * The shape is the x86 sweep's with everything that needed a decoder taken
 * out: a word is read, matched against the handful of forms that move a small
 * constant or copy a register, and otherwise ignored. An unrecognised word is
 * not an error and is not a gap - it is simply not one of the four things
 * this is looking for.
 */
static uint32_t sweep_fixed(struct kof_flow *f, const uint8_t *code,
			    uint32_t code_n, uint64_t code_va, unsigned arch,
			    int be, struct kof_flow_node *out, uint32_t cap)
{
	const struct fxabi *A = kof_fx_abi_of(arch);
	struct fxreg r;
	uint32_t i, n = 0, words = code_n / 4u;

	memset(&r, 0, sizeof r);
	for (i = 0; i < words && n < cap; i++) {
		const uint8_t *p = code + i * 4u;
		uint64_t va = code_va + (uint64_t)i * 4u;
		uint32_t x = be ? ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
				   (uint32_t)p[2] << 8  | p[3])
				: ((uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 |
				   (uint32_t)p[1] << 8  | p[0]);
		int is_sys = 0;
		int64_t rel = 0;        /* a direct branch displacement, or 0 */
		uint64_t call = 0;      /* a direct call target, or 0        */

		/* Both MIPS ABIs: the lui/addiu pair and the jalr through it
		 * are the instruction set, which n64 shares. Only the
		 * syscall numbers differ - see KOF_FLOW_A_MIPS64. */
		if (arch == KOF_FLOW_A_MIPS32 || arch == KOF_FLOW_A_MIPS64) {
			uint32_t op = x >> 26, rt = (x >> 16) & 31u;

			uint32_t rs = (x >> 21) & 31u;

			if ((op == 0x09u || op == 0x0du) && rs == 0u)
				fx_set(&r, rt, x & 0xffffu);          /* li */
			else if (op == 0x0fu)
				fx_set(&r, rt, (uint64_t)(x & 0xffffu) << 16); /* lui */
			else if ((op == 0x08u || op == 0x09u ||
				  op == 0x0du) && rs < FX_NREG &&
				 r.known[rs]) {
				/*
				 * lui/addiu IS HOW MIPS SPELLS A 32-BIT
				 * CONSTANT, and without the second half the
				 * first is only the top sixteen bits of an
				 * address that is never finished.
				 *
				 * It is also how a call target is built:
				 * `lui $t9,%hi(f) ; addiu $t9,$t9,%lo(f) ;
				 * jalr $t9`. Measured on one static MIPS bot:
				 * 712 jalr against 2 jal, so without this
				 * pair the call graph of a MIPS program is
				 * empty - and an empty call graph is a chain
				 * one node long, which is thrown away.
				 */
				uint64_t v = r.v[rs];

				fx_set(&r, rt, op == 0x0du
					? (v | (x & 0xffffu))
					: (uint64_t)((int64_t)v +
					   (int64_t)(int16_t)(x & 0xffffu)));
			}
			else if (op == 0u && ((x & 0x3fu) == 0x21u ||
					      (x & 0x3fu) == 0x25u) && rt == 0u)
				fx_copy(&r, (x >> 11) & 31u, (x >> 21) & 31u); /* move */
			else if (x == 0x0000000cu)
				is_sys = 1;
			else if (op == 0x03u)                          /* jal */
				call = (va & 0xfffffffff0000000ull) |
				       ((uint64_t)(x & 0x03ffffffu) << 2);
			else if (op == 0u && (x & 0x3fu) == 0x09u &&
				 rs < FX_NREG && r.known[rs] && !r.src[rs]) {
				/*
				 * jalr - AND THE REGISTER HAS TO BE INSIDE
				 * THE RUN. A direct call names an address the
				 * encoding bounds; this one names whatever
				 * the map happened to hold, so a stale value
				 * would invent a function at an address
				 * nothing is at. `jal` needs no such test.
				 */
				if (r.v[rs] >= code_va &&
				    r.v[rs] < code_va + code_n)
					call = r.v[rs];
			}
			else if (op == 0x04u || op == 0x05u || op == 0x06u ||
				 op == 0x07u || op == 0x01u)
				rel = (int64_t)(int16_t)(x & 0xffffu) * 4;
		} else if (arch == KOF_FLOW_A_PPC32 ||
			   arch == KOF_FLOW_A_PPC64) {
			uint32_t op = x >> 26, d = (x >> 21) & 31u;
			uint32_t a2 = (x >> 16) & 31u;

			if (op == 14u && a2 == 0u)              /* li rD,simm */
				fx_set(&r, d,
				       (uint64_t)(int64_t)(int16_t)(x & 0xffffu));
			else if (op == 15u && a2 == 0u)         /* lis rD,imm */
				fx_set(&r, d, (uint64_t)(x & 0xffffu) << 16);
			else if (op == 24u && d < FX_NREG && r.known[d])
				/* ori rA,rS,imm - the second half of a
				 * 32-bit constant, same shape MIPS builds
				 * one in. */
				fx_set(&r, a2, r.v[d] | (x & 0xffffu));
			else if ((x & 0xfc0007feu) == 0x7c000378u &&
				 ((x >> 21) & 31u) == ((x >> 11) & 31u))
				fx_copy(&r, a2, d);             /* mr rA,rS */
			else if (x == 0x44000002u)
				is_sys = 1;
			else if (op == 18u) {
				/*
				 * b / bl, and the LINK BIT is what separates
				 * them: bit 0. AA - bit 1 - makes the
				 * displacement absolute, and an absolute
				 * branch in a position-independent IoT build
				 * does not happen; it is read as relative
				 * only when AA is clear.
				 */
				int32_t dd = (int32_t)(x << 6) >> 6;

				dd &= ~3;
				if (!(x & 2u)) {
					if (x & 1u)
						call = va + (uint64_t)(int64_t)dd;
					else
						rel = (int64_t)dd;
				}
			} else if (op == 16u)                   /* bc */
				rel = (int64_t)(int16_t)(x & 0xfffcu);
		} else if (arch == KOF_FLOW_A_SPARC32) {
			uint32_t fmt = x >> 30;

			if ((x & 0xc1f82000u) == 0x80102000u)
				/* or %g0,imm13,rD - which is how the
				 * assembler spells `mov imm,%reg`. */
				fx_set(&r, (x >> 25) & 31u,
				       (uint64_t)(int64_t)
				       (int32_t)((x & 0x1fffu) << 19) >> 19);
			else if ((x & 0xc1c00000u) == 0x01000000u)
				/* sethi %hi(imm),rD */
				fx_set(&r, (x >> 25) & 31u,
				       (uint64_t)(x & 0x3fffffu) << 10);
			else if ((x & 0xc1f82000u) == 0x80100000u &&
				 (x & 0x1fu) < FX_NREG &&
				 ((x >> 14) & 31u) == 0u)
				fx_copy(&r, (x >> 25) & 31u, x & 31u);
			else if (x == 0x91d02010u || x == 0x91d02008u ||
				 x == 0x91d0206du)
				/*
				 * ta 0x10, with 0x08 beside it - Solaris-era
				 * code used the second and Linux the first,
				 * and a stripped IoT binary built by an old
				 * toolchain can carry either - and 0x6d,
				 * which is what v9 traps on. The three are
				 * one decode because the instruction that
				 * sets %g1 is the same on both widths.
				 */
				is_sys = 1;
			else if (fmt == 1u) {
				/*
				 * call - and its opcode is TWO BITS, so one
				 * word in four of anything matches it. The
				 * displacement is thirty bits wide, which
				 * means a word of data names an address
				 * almost anywhere; without the range test
				 * below a stripped object grew 631 functions
				 * out of its literal pools and every one of
				 * them held nothing.
				 */
				int32_t dd = (int32_t)(x << 2);
				uint64_t t = va + (uint64_t)(int64_t)dd;

				if (t >= code_va && t < code_va + code_n)
					call = t;
			} else if (fmt == 0u && ((x >> 22) & 7u) == 2u) {
				int32_t dd = (int32_t)(x << 10) >> 8;

				rel = (int64_t)dd;
			}
		} else if (arch == KOF_FLOW_A_RISCV) {
			uint32_t opc = x & 0x7fu;

			if (opc == 0x13u && ((x >> 12) & 7u) == 0u &&
			    ((x >> 15) & 31u) == 0u)
				/* addi rd,x0,imm - `li rd,imm` */
				fx_set(&r, (x >> 7) & 31u,
				       (uint64_t)(int64_t)
				       ((int32_t)x >> 20));
			else if (opc == 0x37u)                  /* lui */
				fx_set(&r, (x >> 7) & 31u,
				       (uint64_t)(x & 0xfffff000u));
			else if (opc == 0x13u && ((x >> 12) & 7u) == 0u &&
				 ((x >> 15) & 31u) < FX_NREG &&
				 (x >> 20) == 0u)
				fx_copy(&r, (x >> 7) & 31u, (x >> 15) & 31u);
			else if (x == 0x00000073u)
				is_sys = 1;
			else if (opc == 0x6fu) {
				/* jal - and the immediate is scattered, which
				 * is the one thing about this encoding that
				 * has to be written out rather than masked. */
				int32_t dd = (int32_t)
					(((x >> 21) & 0x3ffu) << 1 |
					 ((x >> 20) & 1u) << 11 |
					 ((x >> 12) & 0xffu) << 12);

				if (x & 0x80000000u)
					dd |= (int32_t)0xfff00000;
				if ((x >> 7) & 31u)
					call = va + (uint64_t)(int64_t)dd;
				else
					rel = (int64_t)dd;
			}
		} else if (arch == KOF_FLOW_A_ARM32) {
			uint32_t cond = x >> 28;

			if (cond == 0xfu) {
				/* The unconditional space; nothing read here. */
			} else if ((x & 0x0fef0000u) == 0x03a00000u) {
				uint32_t im = x & 0xffu, ro = ((x >> 8) & 0xfu) * 2u;

				fx_set(&r, (x >> 12) & 15u,
				       ro ? ((im >> ro) | (im << (32u - ro))) & 0xffffffffu
					  : im);                    /* mov rd,#imm */
			} else if ((x & 0x0fef0ff0u) == 0x01a00000u) {
				fx_copy(&r, (x >> 12) & 15u, x & 15u); /* mov rd,rm */
			} else if ((x & 0x0f7f0000u) == 0x051f0000u) {
				/*
				 * ldr rd,[pc,#imm] - THE LITERAL POOL, and on
				 * ARM it is not an edge case.
				 *
				 * A syscall number over 255 does not fit the
				 * rotated immediate `mov` takes, so the
				 * assembler parks it after the function and
				 * loads it. Every socket call is over 255.
				 * Measured on MalwareLab: 205 ARM objects had
				 * an svc and no `mov r7` at all, which is this
				 * and nothing else.
				 *
				 * The pool is inside the run being swept, so
				 * the word is read from the same buffer; one
				 * outside it is not followed. PC reads as the
				 * instruction's address plus eight.
				 */
				uint64_t at = va + 8u;
				uint32_t im = x & 0xfffu;

				at = ((x >> 23) & 1u) ? at + im : at - im;
				if (at >= code_va && at + 4u <= code_va + code_n) {
					const uint8_t *q = code + (at - code_va);
					uint32_t v = be
					    ? ((uint32_t)q[0] << 24 | (uint32_t)q[1] << 16 |
					       (uint32_t)q[2] << 8  | q[3])
					    : ((uint32_t)q[3] << 24 | (uint32_t)q[2] << 16 |
					       (uint32_t)q[1] << 8  | q[0]);

					fx_set(&r, (x >> 12) & 15u, v);
				}
			} else if ((x & 0x0f000000u) == 0x0f000000u) {
				uint32_t imm = x & 0x00ffffffu;

				if (imm == 0u) {
					is_sys = 1;
				} else if (imm >= 0x900000u && imm <= 0x9003ffu) {
					/* OABI carries it in the instruction. */
					fx_set(&r, A->sel, imm - 0x900000u);
					is_sys = 1;
				}
			} else if ((x & 0x0f000000u) == 0x0b000000u) {
				int32_t d = (int32_t)(x << 8) >> 6;

				call = va + 8u + (uint64_t)(int64_t)d;   /* bl */
			} else if ((x & 0x0f000000u) == 0x0a000000u) {
				rel = (int64_t)((int32_t)(x << 8) >> 6) + 8;
			}
		} else {                                        /* AArch64 */
			/* movz, 32-bit and 64-bit - the sf bit at 31 is what
			 * separates them, so it has to be INSIDE the mask. */
			if ((x & 0xff800000u) == 0x52800000u ||
			    (x & 0xff800000u) == 0xd2800000u) {
				if (((x >> 21) & 3u) == 0u)
					fx_set(&r, x & 31u, (x >> 5) & 0xffffu);
			} else if ((x & 0xffe0ffe0u) == 0xaa0003e0u) {
				fx_copy(&r, x & 31u, (x >> 16) & 31u);
			} else if (x == 0xd4000001u) {
				is_sys = 1;
			} else if ((x & 0xfc000000u) == 0x94000000u) {
				call = va + (uint64_t)(int64_t)
					    ((int32_t)(x << 6) >> 4);
			} else if ((x & 0xfc000000u) == 0x14000000u) {
				rel = (int64_t)((int32_t)(x << 6) >> 4);
			}
		}

		if (call) {
			/*
			 * A HEAD **AND** AN EDGE, and the edge is the half
			 * that matters on a static build.
			 *
			 * A statically linked ARM or MIPS program puts each
			 * syscall in its own libc wrapper, so every function
			 * holds exactly one capability and a per-function
			 * chain is one node long - under KOF_DIAG_MIN_STEPS,
			 * and thrown away. Measured on one Mirai ARM sample:
			 * 22 nodes spread over 207 functions, and not one
			 * chain survived.
			 *
			 * kof_flow_chain walks callees through the edge list,
			 * so recording the call is what lets the caller
			 * collect `socket`, `connect` and `send` out of three
			 * separate wrappers into the one chain they are.
			 */
			add_head_derived(f, call);
			add_edge(f, va, call, i);
			edge_snap_fixed(f, &r, A);
			/*
			 * AND EVERYTHING THE REGISTER MAP HELD IS NOW STALE.
			 *
			 * This sweep walks ADDRESS order, not execution order,
			 * so "what was in this register before the call" is a
			 * question it cannot answer once control has left. On
			 * a convention where the result register and the first
			 * argument register are the SAME - which is every one
			 * of these three - keeping the map across a call makes
			 * every consecutive pair of syscalls look linked.
			 *
			 * Measured before this was here: 1589 of 1601 ARM
			 * botnet objects carried a dataflow edge, and the
			 * commonest were spawn<-spawn and read<-write, which
			 * are not shapes a program has. They were two calls
			 * standing next to each other.
			 *
			 * Clearing it loses the real links too, and that is
			 * the right trade: kof_flow_node.from already means
			 * "no link was SEEN", and an invented link is a claim
			 * while a missing one is only silence.
			 *
			 * ONLY THE PROVENANCE. The CONSTANTS stay, because a
			 * caller sets the argument registers before the call
			 * and they are still holding those arguments inside
			 * the callee - which is the only reason a wrapper's
			 * syscall can be told that its socket is a datagram
			 * one. Clearing those too was measured: it took
			 * net-open{dgram} on this corpus from 1206 objects
			 * to 1.
			 */
			memset(r.src, 0, sizeof r.src);
		}
		if (rel < 0) {
			uint64_t to = va + (uint64_t)rel;

			if (to >= code_va && to < va)
				add_loop(f, to, va);
		}
		if (!is_sys)
			continue;
		{
			struct kof_flow_node *nd = &out[n];
			unsigned a;
			uint8_t fl = 0, k;

			memset(nd, 0, sizeof *nd);
			nd->va = va;
			nd->step = i;
			if (!r.known[A->sel])
				continue;      /* a selector this did not follow */
			nd->sel = (uint16_t)r.v[A->sel];
			k = fx_look(A, (uint32_t)r.v[A->sel]);
			/*
			 * SOCKETCALL, where this ABI has one - see
			 * fxabi.sockcall. The operation is the first
			 * argument and without it the number says only
			 * "something to do with the network", which is
			 * KOF_CAP_NONE and so says nothing at all.
			 */
			if (A->sockcall && r.v[A->sel] == A->sockcall) {
				unsigned g0 = A->arg0;

				if (g0 >= FX_NREG || !r.known[g0])
					continue;
				k = kof_sys_look(kof_sockcall,
					 kof_sockcall_n,
					 (uint32_t)r.v[g0]);
				if (k == KOF_CAP_NONE)
					continue;
				memset(nd, 0, sizeof *nd);
				nd->va = va;
				nd->step = i;
				nd->sel = (uint16_t)r.v[A->sel];
				nd->cap = k;
				/* The OPERATION's name and not the
				 * multiplexer's: `socketcall` says nothing
				 * that the number did not already say. */
				nd->name = kof_flow_name_id(
					kof_sys_look_name(kof_sockcall,
						  kof_sockcall_n,
						  (uint32_t)r.v[g0]));
				n++;
				if (A->ret < FX_NREG) {
					r.known[A->ret] = 0;
					r.src[A->ret] = (uint16_t)(f->n_node + n);
				}
				r.known[A->sel] = 0;
				continue;
			}
			k = fixed_prot(k, r.v[A->arg0 + A->prot_arg],
				       r.known[A->arg0 + A->prot_arg], &fl);
			if (k == KOF_CAP_NONE)
				continue;
			/* The two refinements the x86 side makes, from the
			 * same arguments in this ABI's registers. */
			if (k == KOF_CAP_SPAWN && r.known[A->arg0] &&
			    (r.v[A->arg0] & FLOW_CLONE_THREAD))
				k = KOF_CAP_THREAD;
			if (k == KOF_CAP_NET_OPEN) {
				if (r.known[A->arg0] &&
				    (r.v[A->arg0] & 0xffu) == FLOW_AF_UNIX)
					fl |= KOF_FLOWF_LOCAL;
				if (r.known[A->arg0 + 1u]) {
					uint64_t ty = r.v[A->arg0 + 1u] & 0xfu;

					if (ty == FLOW_SOCK_RAW)
						k = KOF_CAP_NET_RAW;
					else if (ty == FLOW_SOCK_DGRAM)
						fl |= KOF_FLOWF_DGRAM;
				}
			}
			nd->cap = k;
			nd->flags = fl;
			for (a = 0; a < A->n_arg && a < KOF_FLOW_ARGS; a++) {
				unsigned g = A->arg0 + a;

				if (g < FX_NREG && r.src[g])
					nd->from[a] = r.src[g];
				if (g < FX_NREG && r.known[g] && !r.src[g]) {
					nd->arg_const |= (uint8_t)(1u << a);
					nd->arg[a] = r.v[g];
				}
			}
			n++;
			/* The result is live in the return register, and the
			 * selector is not: a second syscall needs its own. */
			if (A->ret < FX_NREG) {
				r.known[A->ret] = 0;
				r.src[A->ret] = (uint16_t)(f->n_node + n);
			}
			r.known[A->sel] = 0;
		}
	}
	return n;
}

/*
 * THUMB, AND ONLY WHEN THE ARM PASS FOUND NOTHING.
 *
 * Nothing in an ELF says which of the two a run of bytes is, so the choice
 * has to be made from the result. Reading Thumb as ARM produces selectors
 * that resolve to no capability, so the ARM pass simply comes back empty and
 * this is tried; reading ARM as Thumb would do the same in reverse. Trying
 * the cheaper-to-be-wrong one first is the whole of the policy.
 *
 * Selector and syscall only - no provenance and no call targets, because the
 * forms that carry them are the 32-bit Thumb-2 encodings this does not read.
 */
static uint32_t sweep_thumb(struct kof_flow *f, const uint8_t *code,
			    uint32_t code_n, uint64_t code_va,
			    struct kof_flow_node *out, uint32_t cap)
{
	uint32_t i, n = 0, hw = code_n / 2u;
	int have = 0;
	uint32_t sel = 0;

	for (i = 0; i < hw && n < cap; i++) {
		const uint8_t *p = code + i * 2u;
		uint32_t x = (uint32_t)p[1] << 8 | p[0];   /* Thumb is LE here */
		uint32_t nr;
		uint8_t k;

		if ((x & 0xff00u) == 0x2700u) {           /* movs r7,#imm8 */
			sel = x & 0xffu; have = 1; continue;
		}
		if ((x & 0xff00u) != 0xdf00u)             /* svc #imm8 */
			continue;
		nr = (x & 0xffu) ? (x & 0xffu) : sel;
		if (!(x & 0xffu) && !have)
			continue;
		k = kof_sys_look(kof_sys_arm, kof_sys_arm_n, nr);
		if (k == KOF_CAP_NONE) { have = 0; continue; }
		memset(&out[n], 0, sizeof out[n]);
		out[n].va = code_va + (uint64_t)i * 2u;
		out[n].step = i;
		out[n].sel = (uint16_t)nr;
		out[n].cap = k;
		out[n].name = kof_flow_name_id(kof_sys_look_name(kof_sys_arm,
							 kof_sys_arm_n,
							 nr));
		n++; have = 0;
	}
	(void)f;
	return n;
}

/*
 * THE TWO THAT ARE NOT FOUR BYTES WIDE.
 *
 * SuperH is two bytes and m68k is two to ten, so neither can be read by the
 * word loop above - and neither needs to be. The whole of what this file
 * wants from them is three forms: the constant that names a syscall, the
 * instruction that makes it, and the direct call that ties two functions
 * together. All three are a single halfword on SH and either one or two on
 * m68k, which is why a halfword reader gets them and a decoder is not needed.
 *
 * WHAT IS LOST is the provenance - no register copies are followed and no
 * arguments are read - so these produce nodes and call edges and nothing
 * else. Same trade sweep_thumb makes, and stated for the same reason: a
 * missing link is silence, and silence is the honest answer when the reader
 * cannot see.
 */
static uint32_t sweep_half(struct kof_flow *f, const uint8_t *code,
			   uint32_t code_n, uint64_t code_va, unsigned arch,
			   int be, struct kof_flow_node *out, uint32_t cap)
{
	const struct fxabi *A = kof_fx_abi_of(arch);
	uint32_t i, n = 0, hw = code_n / 2u;
	uint32_t sel = 0, a0 = 0;
	int have = 0, have_a0 = 0;

	/* Kept in the signature so every sweep here reads the same, and so
	 * that a reader asking "why does this one take no flow" finds the
	 * answer in the call note below rather than in the parameter list. */
	(void)f;

	for (i = 0; i < hw && n < cap; i++) {
		const uint8_t *p = code + i * 2u;
		uint32_t x = be ? ((uint32_t)p[0] << 8 | p[1])
				: ((uint32_t)p[1] << 8 | p[0]);
		uint64_t va = code_va + (uint64_t)i * 2u;
		uint64_t call = 0;
		int is_sys = 0;
		uint8_t k;

		if (arch == KOF_FLOW_A_SH) {
			if ((x & 0xff00u) == 0xe300u) {   /* mov #imm,r3 */
				sel = x & 0xffu; have = 1; continue;
			}
			if ((x & 0xff00u) == 0xe400u) {   /* mov #imm,r4 */
				a0 = x & 0xffu; have_a0 = 1; continue;
			}
			if ((x & 0xff00u) == 0xc300u) {   /* trapa #imm */
				is_sys = 1;
			} else if ((x & 0xf000u) == 0xb000u) {
				/* bsr disp12, and PC reads as the
				 * instruction's address plus four. */
				int32_t d = (int32_t)(x << 20) >> 19;

				call = va + 4u + (uint64_t)(int64_t)d;
			} else {
				continue;
			}
		} else {                                  /* m68k */
			if ((x & 0xff00u) == 0x7000u) {   /* moveq #N,dn */
				if (((x >> 9) & 7u) == 0u) {
					sel = x & 0xffu; have = 1;
				} else if (((x >> 9) & 7u) == 1u) {
					a0 = x & 0xffu; have_a0 = 1;
				}
				continue;
			}
			if (x == 0x203cu && i + 2u < hw) {
				/* move.l #imm32,d0 - the long form, for a
				 * number that does not fit moveq's byte. */
				const uint8_t *q = code + (i + 1u) * 2u;

				sel = be ? ((uint32_t)q[0] << 24 |
					    (uint32_t)q[1] << 16 |
					    (uint32_t)q[2] << 8 | q[3])
					 : ((uint32_t)q[3] << 24 |
					    (uint32_t)q[2] << 16 |
					    (uint32_t)q[1] << 8 | q[0]);
				have = 1;
				i += 2u;
				continue;
			}
			if (x == 0x4e40u) {               /* trap #0 */
				is_sys = 1;
			} else if ((x & 0xff00u) == 0x6100u) {
				/* bsr.s with a byte displacement, and
				 * bsr.w when that byte is zero. */
				if (x & 0xffu) {
					int32_t d = (int8_t)(x & 0xffu);

					call = va + 2u + (uint64_t)(int64_t)d;
				} else if (i + 1u < hw) {
					const uint8_t *q = code + (i + 1u) * 2u;
					int32_t d = be
					    ? (int16_t)((uint32_t)q[0] << 8 | q[1])
					    : (int16_t)((uint32_t)q[1] << 8 | q[0]);

					call = va + 2u + (uint64_t)(int64_t)d;
				}
			} else {
				continue;
			}
		}

		if (call) {
			/*
			 * AND THE CALL IS READ AND THROWN AWAY, which is the
			 * opposite of what the four-byte sweep does with one.
			 *
			 * `bsr` is 0xBxxx on SH and 0x61xx on m68k - two of
			 * the commonest halfword values there are - so in a
			 * stripped object every literal pool and every string
			 * yields some, and they pass a range test because
			 * they point back INTO the code they came from.
			 * Measured: one m68k sample grew 1234 functions that
			 * way, holding five nodes between them, and a function
			 * holding one node is a chain under KOF_DIAG_MIN_STEPS.
			 *
			 * Without them every node lands in the run's own head
			 * and the chain is the file's syscalls in ADDRESS
			 * order. Weaker evidence than call order, said plainly
			 * - and the alternative measured out at none.
			 */
			(void)call;
			continue;
		}
		if (!is_sys || !have)
			continue;
		have = 0;
		k = fx_look(A, sel);
		/*
		 * SOCKETCALL, WHICH IS WHERE ALL THE NETWORKING WENT.
		 *
		 * These two ports took i386's numbering, and i386 multiplexes
		 * every socket operation through 102 with the operation in
		 * the first argument register. Without reading that register
		 * a SuperH bot has no net-open, no net-connect and no send -
		 * measured on six samples, 31 to 102 syscalls each, of which
		 * four carried a capability. It is one more constant to
		 * follow and it is the difference between a bot's chain and
		 * four unrelated nodes.
		 */
		if (sel == 102u) {
			if (!have_a0)
				continue;
			k = kof_sys_look(kof_sockcall,
				 kof_sockcall_n, a0);
		}
		have_a0 = 0;
		if (k == KOF_CAP_NONE)
			continue;
		memset(&out[n], 0, sizeof out[n]);
		out[n].va = va;
		out[n].step = i;
		out[n].sel = (uint16_t)sel;
		out[n].cap = k;
		out[n].name = kof_flow_name_id(fx_name(A, (uint32_t)sel));
		n++;
	}
	return n;
}

/*
 * The fixed-width counterpart of kof_flow_add, and it keeps that function's
 * contract: one call per executable run, the run's own start is a head.
 */
void kof_flow_add_fixed(struct kof_flow *f, const uint8_t *code,
			uint32_t code_n, uint64_t code_va, unsigned arch,
			int big_endian)
{
	uint32_t got;

	if (!f || !code || code_n < 4u || f->finished)
		return;
	if (arch < KOF_FLOW_A_MIPS32 || arch > KOF_FLOW_A_M68K)
		return;
	if (code_n > KOF_FLOW_MAX_CODE) {
		code_n = KOF_FLOW_MAX_CODE;
		f->full = 1;
	}
	f->fxarch = (uint8_t)arch;
	add_head(f, code_va);
	if (arch == KOF_FLOW_A_SH || arch == KOF_FLOW_A_M68K)
		got = sweep_half(f, code, code_n, code_va, arch, big_endian,
				 f->node + f->n_node,
				 KOF_FLOW_MAX_NODE - f->n_node);
	else
		got = sweep_fixed(f, code, code_n, code_va, arch, big_endian,
				  f->node + f->n_node,
				  KOF_FLOW_MAX_NODE - f->n_node);
	if (!got && arch == KOF_FLOW_A_ARM32 && !big_endian)
		got = sweep_thumb(f, code, code_n, code_va,
				  f->node + f->n_node,
				  KOF_FLOW_MAX_NODE - f->n_node);
	f->n_node += got;
}

void kof_flow_add(struct kof_flow *f, const uint8_t *code, uint32_t code_n,
		  uint64_t code_va, unsigned bits, unsigned abi)
{
	if (!f || !code || !code_n || f->finished)
		return;
	if (code_n > KOF_FLOW_MAX_CODE) {
		code_n = KOF_FLOW_MAX_CODE;
		f->full = 1;
	}
	f->bits = (uint8_t)bits;
	/* The run's own start is a head: a blob nothing calls into is still one
	 * region, which is what raw shellcode is. */
	add_head(f, code_va);
	f->n_node += sweep(f, code, code_n, code_va, bits, abi,
			   f->node + f->n_node,
			   KOF_FLOW_MAX_NODE - f->n_node);
}

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : (x > y ? 1 : 0);
}

/*
 * WHICH REGION A NODE IS IN: the nearest head at or before it.
 *
 * AN APPROXIMATION, AND NAMED AS ONE. A real partition needs the call graph
 * and the end of each function; this takes the heads in address order and
 * gives each node to the last one it passed. It is right whenever a compiler
 * lays functions out contiguously, which is the ordinary case, and it merges
 * two functions when the first one's body was never called directly - which
 * loses separation rather than inventing it.
 */
static uint32_t func_of(const struct kof_flow *f, uint64_t va)
{
	uint32_t lo = 0, hi = f->n_func;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (f->func[mid].va <= va)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo ? lo - 1u : 0u;
}

static int in_loop(const struct kof_flow *f, uint64_t va)
{
	uint32_t i;

	for (i = 0; i < f->n_loop; i++)
		if (va >= f->loop[i].lo && va <= f->loop[i].hi)
			return 1;
	return 0;
}

/*
 * The innermost span that holds this address, as index plus one, or 0.
 *
 * INNERMOST, because two steps in the same inner loop are the same repeated
 * step while two in the same outer loop may be a sequence that happens to
 * run twice. The spans are intervals - see add_loop - so the shortest one
 * containing the address is the innermost.
 */
static uint32_t loop_of(const struct kof_flow *f, uint64_t va)
{
	uint32_t i, best = 0;
	uint64_t len = 0;

	for (i = 0; i < f->n_loop; i++)
		if (va >= f->loop[i].lo && va <= f->loop[i].hi) {
			uint64_t l = f->loop[i].hi - f->loop[i].lo;

			if (!best || l < len) { best = i + 1u; len = l; }
		}
	return best;
}

static int cmp_node(const void *a, const void *b)
{
	const struct kof_flow_node *x = a, *y = b;

	if (x->func != y->func)
		return x->func < y->func ? -1 : 1;
	return x->va < y->va ? -1 : (x->va > y->va ? 1 : 0);
}

static int cmp_edge(const void *a, const void *b)
{
	const struct cedge *x = (const struct cedge *)a;
	const struct cedge *y = (const struct cedge *)b;

	if (x->from_func != y->from_func)
		return x->from_func < y->from_func ? -1 : 1;
	return x->site < y->site ? -1 : (x->site > y->site ? 1 : 0);
}

/*
 * WHICH TABLE A SELECTOR BELONGS TO, which is only ever the one the sweep
 * that produced the node read from.
 */
static uint8_t sys_role(const struct kof_flow *f, uint32_t nr)
{
	if (f->fxarch)
		return fx_role(kof_fx_abi_of(f->fxarch), nr);
	if (f->bits == 32)
		/* socketcall's sub-call is argument 0 and its real arguments
		 * are behind a pointer, so this pass has nothing to say about
		 * it - see the kof_sockcall table. */
		return nr == 102u ? KOF_FLOW_ROLE_NONE
				  : kof_sys_look_role(kof_sys32,
					      kof_sys32_n,
					      nr);
	return kof_sys_look_role(kof_sys64, kof_sys64_n, nr);
}

/* The edge carries four, the node may want fewer. */
#define EARG_N (KOF_FLOW_ARGS < 4u ? KOF_FLOW_ARGS : 4u)

/* What every call into one function agreed its arguments were. */
struct eargs {
	uint64_t v[KOF_FLOW_ARGS];
	uint16_t src[KOF_FLOW_ARGS];
	uint64_t sel;
	uint8_t  have;   /* bit a: every caller passed the same constant   */
	uint8_t  hsrc;   /* bit a: every caller passed the same provenance */
	uint8_t  hsel;   /* every caller had the same selector             */
	uint8_t  seen;
};

/*
 * THE CALLER'S ARGUMENTS, HANDED DOWN ONE LEVEL.
 *
 * The sweep walks address order, and on a statically linked program the
 * syscall is not where its arguments were set: `li $v0,4183 ; syscall` sits
 * in a libc wrapper, preceded by that wrapper's prologue and nothing else,
 * while $a0 and $a1 were written by a caller the sweep passed long before.
 * Measured on this corpus before this pass existed: an argument-derived
 * flag appeared on 1206 ARM objects - where the register map survives the
 * call by address accident - and on ONE of every other architecture.
 *
 * TWO THINGS MAKE THIS SAFE RATHER THAN A GUESS.
 *
 * Every incoming edge has to agree. A wrapper called from three places with
 * three different sockets tells us nothing about any of them, and taking one
 * edge because it was there is exactly the invented fact flow.c refuses
 * elsewhere. One disagreeing caller drops the argument.
 *
 * And the callee must not already have an answer. An argument the sweep saw
 * set inside the callee - a constant, or a value some earlier node produced -
 * is first-hand and is never overwritten by this.
 *
 * ONE LEVEL, NOT A FIXPOINT. A wrapper around a wrapper keeps its silence.
 * That is a coverage limit and not a correctness one, and the measurement
 * below is of one level only.
 */
static void edge_args(struct kof_flow *f)
{
	struct eargs *acc;
	uint32_t i, a;

	if (!f->n_edge || !f->n_node || !f->n_func)
		return;
	acc = (struct eargs *)calloc(f->n_func, sizeof *acc);
	if (!acc)
		return;

	for (i = 0; i < f->n_edge; i++) {
		const struct cedge *e = &f->edge[i];
		struct eargs *g;

		if (e->to_func >= f->n_func)
			continue;
		g = &acc[e->to_func];
		if (!g->seen) {
			g->seen = 1;
			g->have = e->argk;
			g->sel = e->sel;
			g->hsel = e->selk;
			for (a = 0; a < EARG_N; a++) {
				g->v[a] = e->arg[a];
				g->src[a] = e->argsrc[a];
				if (e->argsrc[a])
					g->hsrc |= (uint8_t)(1u << a);
			}
			continue;
		}
		if (g->hsel && (!e->selk || e->sel != g->sel))
			g->hsel = 0;
		for (a = 0; a < EARG_N; a++) {
			uint8_t b = (uint8_t)(1u << a);

			if ((g->have & b) &&
			    (!(e->argk & b) || e->arg[a] != g->v[a]))
				g->have &= (uint8_t)~b;
			if ((g->hsrc & b) && e->argsrc[a] != g->src[a])
				g->hsrc &= (uint8_t)~b;
		}
	}

	for (i = 0; i < f->n_node; i++) {
		struct kof_flow_node *nd = &f->node[i];
		const struct eargs *g;
		uint8_t fresh = 0, role;

		if (nd->func >= f->n_func)
			continue;
		g = &acc[nd->func];
		if (!g->seen)
			continue;
		/*
		 * THE THUNK, FIRST, because until its number is known it has
		 * no capability and nothing else here applies to it. One
		 * caller disagreeing is enough to leave it unresolved: a body
		 * reached with two different numbers is two different
		 * syscalls, and naming it after either is a guess.
		 */
		if (nd->sel == KOF_FLOW_SEL_PENDING) {
			uint8_t fl = 0, k;
			uint64_t a4[4];

			if (!g->hsel)
				continue;
			for (a = 0; a < 4u; a++)
				a4[a] = (a < EARG_N && (g->have & (1u << a)))
					? g->v[a] : 0;
			k = kof_flow_cap_of_syscall(f->bits,
						    (uint32_t)g->sel,
						    a4, &fl);
			if (k == KOF_CAP_NONE)
				continue;
			nd->sel = (uint16_t)g->sel;
			nd->cap = k;
			nd->flags |= fl;
			continue;
		}
		/* The arguments this node has no first-hand answer for. */
		for (a = 0; a < EARG_N; a++)
			if (!(nd->arg_const & (1u << a)) && !nd->from[a])
				fresh |= (uint8_t)(1u << a);
		if (!fresh)
			continue;

		/*
		 * ONLY A NODE THE SWEEP FOUND AS A SYSCALL. An import node
		 * sits at its OWN call site, where its arguments were already
		 * read first-hand; handing it the arguments of the function it
		 * happens to be inside would be a different call's data.
		 */
		if (nd->sel)
			for (a = 0; a < EARG_N; a++)
				if ((fresh & g->hsrc & (1u << a)))
					nd->from[a] = g->src[a];
		for (a = 0; a < EARG_N; a++)
			if ((fresh & g->have & (1u << a))) {
				/* The value every caller agreed on - see
				 * kof_flow_node.arg. */
				nd->arg[a] = g->v[a];
				nd->arg_const |= (uint8_t)(1u << a);
			}

		role = sys_role(f, nd->sel);
		if (role == KOF_FLOW_ROLE_MMAP && nd->cap == KOF_CAP_ALLOC &&
		    (fresh & g->have & 4u)) {
			uint64_t prot = g->v[2];

			if ((prot & 6u) == 6u)
				nd->flags |= KOF_FLOWF_WX;
			if (prot & 4u)
				nd->cap = KOF_CAP_ALLOC_EXEC;
		} else if (role == KOF_FLOW_ROLE_CLONE && nd->cap == KOF_CAP_SPAWN &&
			   (fresh & g->have & 1u)) {
			if (g->v[0] & FLOW_CLONE_THREAD)
				nd->cap = KOF_CAP_THREAD;
		} else if (role == KOF_FLOW_ROLE_SOCK && nd->cap == KOF_CAP_NET_OPEN) {
			if ((fresh & g->have & 1u) &&
			    (g->v[0] & 0xffu) == FLOW_AF_UNIX)
				nd->flags |= KOF_FLOWF_LOCAL;
			if (fresh & g->have & 2u) {
				uint64_t ty = g->v[1] & 0xfu;

				if (ty == FLOW_SOCK_RAW)
					nd->cap = KOF_CAP_NET_RAW;
				else if (ty == FLOW_SOCK_DGRAM)
					nd->flags |= KOF_FLOWF_DGRAM;
			}
		}
	}
	free(acc);
}

static uint8_t reaches(struct kof_flow *f, uint32_t from, uint32_t to);

static int cmp_blk(const void *a, const void *b)
{
	const struct blk *x = (const struct blk *)a;
	const struct blk *y = (const struct blk *)b;

	return x->lo < y->lo ? -1 : (x->lo > y->lo ? 1 : 0);
}

/*
 * IN ADDRESS ORDER, WHICH blk_of ASSUMES AND NOTHING GUARANTEED.
 *
 * Safe to do here and only here: a successor is stored as an ADDRESS and not
 * as an index - see blk_succ - so moving the records breaks no reference,
 * and the sweep's own `cur_blk` is long out of scope by the time finish runs.
 */
static void sort_blocks(struct kof_flow *f)
{
	qsort(f->blk, f->n_blk, sizeof f->blk[0], cmp_blk);
}

/*
 * WHICH BLOCKS ARE ONE ARM OF A CONDITIONAL, worked out once per object.
 *
 * A block with two successors is a conditional. One of its successors is an
 * ARM if the OTHER successor cannot reach it - which is the test that tells
 * an arm from the join: both sides of an `if` lead to the code after it, so
 * the code after it is reachable from either and is not marked, while the
 * code inside one side is reachable from that side alone.
 *
 * IT IS ONLY EVER A POSITIVE CLAIM. reaches answers EXCLUSIVE only when its
 * search COMPLETED and found nothing - an indirect branch out of the sibling
 * arm, or a search that hit its bound, answers UNKNOWN and leaves the block
 * unmarked. Unmarked means "runs every time, as far as anyone can tell",
 * which is the reading that claims less.
 *
 * ONCE, AND NOT PER CHAIN. A chain is built for every function of an object,
 * so asking this during the walk would ask it tens of thousands of times for
 * one file; here it is bounded by the number of conditionals.
 */
static void mark_arms(struct kof_flow *f)
{
	uint32_t a;

	/*
	 * AND NOTHING AT ALL WHEN THE GRAPH IS SHORT OF BLOCKS. `full` means
	 * a limit was hit, so an edge that would have made a block reachable
	 * may simply not be there - and then "the other arm cannot reach it"
	 * is a statement about the array's size and not about the program.
	 * The same guard rel_va keeps, for the same reason.
	 */
	if (f->full)
		return;
	for (a = 0; a < f->n_blk; a++) {
		uint32_t b0, b1;

		if (f->blk[a].n_succ != 2u)
			continue;
		b0 = blk_of(f, f->blk[a].succ[0]);
		b1 = blk_of(f, f->blk[a].succ[1]);
		if (b0 >= f->n_blk || b1 >= f->n_blk || b0 == b1)
			continue;
		/*
		 * A GUARD IS NOT A BRANCH.
		 *
		 * `test rax,rax ; js error` has two successors and they are
		 * mutually exclusive, so by the test below both are arms -
		 * and that is true of nearly every line of nearly every
		 * program, because nearly every system call is checked. The
		 * page then says "only on a branch" beside everything, which
		 * is the same as saying it beside nothing.
		 *
		 * What makes a branch worth drawing is that BOTH sides go on
		 * to do something. A side that ends - no successors, because
		 * it returns or exits - is an error path, and the other side
		 * is simply what the program does. Measured when the exit
		 * syscall stopped falling through into the code after it:
		 * every step of one stager gained `cond`, and the retry loop
		 * was drawn as an `if`.
		 */
		if (!f->blk[b0].n_succ || !f->blk[b1].n_succ)
			continue;
		if (reaches(f, b1, b0) == KOF_REL_EXCLUSIVE) {
			f->blk[b0].arm = 1;
			f->blk[b0].arm_of = a + 1u;
			f->blk[b0].arm_side = 0;
		}
		if (reaches(f, b0, b1) == KOF_REL_EXCLUSIVE) {
			f->blk[b1].arm = 1;
			f->blk[b1].arm_of = a + 1u;
			f->blk[b1].arm_side = 1;
		}
	}
}

/*
 * A BACKWARD BRANCH IS NOT A LOOP UNTIL ITS TARGET CAN REACH IT AGAIN.
 *
 * add_loop records every branch that points at a lower address, which is all
 * the sweep can tell at the time. Most of them are loops. Some are the error
 * exit a program shares:
 *
 *     e5: ... ; syscall      ; exit(1)
 *     ...
 *     f1: syscall            ; read
 *     f6: js 0xe5            ; backward - and NOT a loop
 *
 * Nothing comes back from 0xe5, so the span [0xe5, 0xf6] is not somewhere
 * control goes round. Counting it as one put `read` and the branch into it
 * "in a loop", which is a claim about the program that the program does not
 * make - and KOF_FLOWF_LOOP is a flag a rule can ask for.
 *
 * Checked here rather than in the sweep because the question needs the whole
 * graph, and the graph is not finished while the sweep is running.
 */
static void prune_loops(struct kof_flow *f)
{
	uint32_t i, k = 0;

	/* `full` means an edge may be missing, and then "cannot reach" is a
	 * statement about the array's size - the same guard mark_arms keeps. */
	if (f->full)
		return;
	for (i = 0; i < f->n_loop; i++) {
		uint32_t a = blk_of(f, f->loop[i].lo);
		uint32_t b = blk_of(f, f->loop[i].hi);

		if (a < f->n_blk && b < f->n_blk &&
		    reaches(f, a, b) == KOF_REL_EXCLUSIVE)
			continue;          /* the target never gets back */
		if (k != i)
			f->loop[k] = f->loop[i];
		k++;
	}
	f->n_loop = k;
}

static void finish(struct kof_flow *f)
{
	uint32_t i, k;

	if (f->finished)
		return;
	f->finished = 1;
	sort_blocks(f);
	prune_loops(f);
	mark_arms(f);

	/* Heads, sorted and deduplicated - a function called from ten places
	 * was added ten times. */
	qsort(f->head, f->n_head, sizeof f->head[0], cmp_u64);
	for (i = 0; i < f->n_head; i++) {
		if (i && f->head[i] == f->head[i - 1])
			continue;
		if (f->n_func >= f->cap_func) {
			f->full = 1;
			break;
		}
		memset(&f->func[f->n_func], 0, sizeof f->func[0]);
		f->func[f->n_func].va = f->head[i];
		f->n_func++;
	}

	for (i = 0; i < f->n_node; i++) {
		f->node[i].func = func_of(f, f->node[i].va);
		if (in_loop(f, f->node[i].va))
			f->node[i].flags |= KOF_FLOWF_LOOP;
		f->node[i].repeat = 1u;
	}
	/* Grouped so a region is a slice and not a search. */
	qsort(f->node, f->n_node, sizeof f->node[0], cmp_node);
	for (i = 0; i < f->n_node; i = k) {
		uint32_t fi = f->node[i].func;

		for (k = i; k < f->n_node && f->node[k].func == fi; k++)
			f->func[fi].mask |= 1ull << f->node[k].cap;
		f->func[fi].first = i;
		f->func[fi].n = k - i;
	}

	/*
	 * THE CALL GRAPH, resolved last because only now are the functions
	 * numbered. The edges were recorded as address pairs during the sweep
	 * and are rewritten in place into index pairs; nothing reads them as
	 * addresses afterwards.
	 */
	for (i = 0; i < f->n_edge; i++) {
		uint32_t a = func_of(f, f->edge[i].site);
		uint32_t b = func_of(f, f->edge[i].to_va);

		f->edge[i].from_func = (uint16_t)(a < f->n_func ? a
						  : FLOW_FUNC_MAX - 1u);
		f->edge[i].to_func = (uint16_t)(b < f->n_func ? b
						: FLOW_FUNC_MAX - 1u);
		if (a >= f->n_func || b >= f->n_func)
			continue;
		f->func[a].n_call++;
		f->func[b].n_caller++;
	}

	/* And only now can an argument cross a call - see edge_args. The
	 * function masks are rebuilt after it, because a node that was ALLOC
	 * when they were first summed may be ALLOC_EXEC now. */
	edge_args(f);
	for (i = 0; i < f->n_func; i++)
		f->func[i].mask = 0;
	for (i = 0; i < f->n_node; i++)
		if (f->node[i].func < f->n_func)
			f->func[f->node[i].func].mask |=
				1ull << f->node[i].cap;

	/* Grouped by caller and in address order, which is the order a chain
	 * walks them in. */
	qsort(f->edge, f->n_edge, sizeof f->edge[0], cmp_edge);

	/*
	 * DISTANCE FROM THE ENTRY, by relaxation rather than by a queue: the
	 * edge list is already the graph, and a pass over it that changes
	 * nothing is the end. A program's call depth is small, so this stops
	 * after a handful of passes; the bound is there for a graph that is
	 * one long chain.
	 */
	for (i = 0; i < f->n_func; i++)
		f->func[i].depth = KOF_FLOW_FAR;
	{
		uint32_t root = 0, pass;

		if (f->has_entry)
			root = func_of(f, f->entry);
		if (root < f->n_func)
			f->func[root].depth = 0;
		for (pass = 0; pass < f->n_func; pass++) {
			uint32_t moved = 0;

			for (i = 0; i < f->n_edge; i++) {
				uint32_t a = f->edge[i].from_func;
				uint32_t b = f->edge[i].to_func;
				uint32_t d;

				if (a >= f->n_func || b >= f->n_func ||
				    f->func[a].depth == KOF_FLOW_FAR)
					continue;
				d = f->func[a].depth + 1u;
				if (d < f->func[b].depth) {
					f->func[b].depth = (uint16_t)d;
					moved = 1;
				}
			}
			if (!moved)
				break;
		}
	}
}

static uint8_t rel_va(struct kof_flow *f, uint64_t a, uint64_t b);

/*
 * IS THIS ADDRESS INSIDE A LOOP OF ITS OWN FUNCTION - one level, never more.
 *
 * ONE, BECAUSE THE SPANS CANNOT COUNT HIGHER HONESTLY. add_loop records an
 * interval per BACKWARD BRANCH, which is all a linear sweep can see, and
 * that model cannot tell three nested loops from one loop with three
 * `continue`s or from a switch whose cases jump back to different labels.
 * All three look like several intervals containing the same address, most of
 * them nested inside each other.
 *
 * It was counted, and the count was nonsense: a step in wget came out
 * EIGHTEEN levels deep, from one function with a dozen back edges and no
 * loop nested more than twice. Real nesting needs the dominator tree and
 * natural loops; the sweep computes neither, and a number that is wrong by a
 * factor of six is worse in a reader's hands than a flag.
 *
 * So the indentation says "inside a loop" and the chain says how many times
 * a step repeats - see kof_flow_node.repeat - and neither claims to know how
 * deep the nest goes.
 *
 * THE SPAN MUST BE IN THIS FUNCTION. A jump at the end of a region back to
 * its start - a switch dispatch, a tail call into an earlier body - records
 * one span containing every address between, and that is not a loop around
 * this step.
 */
static uint8_t loop_depth(const struct kof_flow *f, uint64_t va,
			  uint64_t fn_lo, uint64_t fn_hi)
{
	uint32_t i;

	for (i = 0; i < f->n_loop; i++)
		if (va >= f->loop[i].lo && va <= f->loop[i].hi &&
		    f->loop[i].lo >= fn_lo && f->loop[i].hi < fn_hi)
			return 1u;
	return 0u;
}

/* State carried down the walk, so the recursion stays a few words wide. */
struct chain {
	struct kof_flow *f;
	struct kof_flow_node *out;
	uint32_t *origin;
	uint32_t cap, n;
	uint32_t run;        /* normalised instructions walked so far */
	uint32_t top;        /* the depth the walk started at - see below */
	/*
	 * THE RELATION THE CALLER WORKED OUT FOR A CALLEE'S FIRST STEP.
	 *
	 * A chain crosses function boundaries, and "is B reachable from A"
	 * is a question about ONE function's blocks. So the caller answers
	 * it for its own call SITE - which is in its own blocks - and the
	 * callee's first step inherits that answer. Nothing ever asks the
	 * block graph about two addresses in different functions, which it
	 * could only answer wrongly.
	 */
	uint8_t pending;
	/* How the body being walked right now was entered - see
	 * kof_flow_node.entry. Carried down the recursion because a step
	 * cannot see the edge that reached its frame. */
	uint8_t in;
	/* One bit per function, sized for the ceiling rather than the
	 * current capacity: eight kilobytes on the stack, against a realloc
	 * per chain of which an object builds thousands. */
	uint8_t seen[FLOW_FUNC_MAX / 8u + 1u];
};

static int seen_take(struct chain *ch, uint32_t fi)
{
	uint32_t byte = fi >> 3, bit = 1u << (fi & 7u);

	if (fi >= FLOW_FUNC_MAX || (ch->seen[byte] & bit))
		return 0;
	ch->seen[byte] |= (uint8_t)bit;
	return 1;
}

static void chain_walk(struct chain *ch, uint32_t fi, uint32_t depth)
{
	const uint8_t was_in = ch->in;
	const struct kof_flow_func *fn;
	uint32_t j, e, prev;
	/*
	 * THE LAST THING EMITTED, AS AN ADDRESS IN THIS FUNCTION.
	 *
	 * Either the previous step of this body or the call site the walk
	 * just came back from - both are addresses the block graph of THIS
	 * function can be asked about, which is the whole point of keeping
	 * it per frame rather than taking the previous node of the chain.
	 * Zero until this body has emitted or called anything.
	 */
	uint64_t anchor = 0;

	if (fi >= ch->f->n_func || ch->n >= ch->cap || !seen_take(ch, fi))
		return;
	fn = &ch->f->func[fi];

	/* Where this body's own step numbering starts, so the gaps INSIDE it
	 * survive being placed after whatever came before. */
	prev = fn->n ? ch->f->node[fn->first].step : 0u;

	/* The edges of this function, already grouped and in address order. */
	for (e = 0; e < ch->f->n_edge && ch->f->edge[e].from_func != fi; e++)
		;

	for (j = 0; j < fn->n && ch->n < ch->cap; j++) {
		const struct kof_flow_node *nd = &ch->f->node[fn->first + j];

		/* A thunk nobody called, or whose callers disagreed - see
		 * KOF_FLOW_SEL_PENDING. It is a syscall that happened; what
		 * it was is not known, and a chain carries words. */
		if (nd->cap == KOF_CAP_NONE)
			continue;
		/*
		 * A ROTATE OUTSIDE A LOOP IS NOT A NAME BEING HASHED - see
		 * KOF_CAP_NAME_HASH. The sweep cannot tell at the time it
		 * meets one, because the branch that makes it a loop comes
		 * after; finish() has decided by now.
		 */
		if (nd->cap == KOF_CAP_NAME_HASH &&
		    !(nd->flags & KOF_FLOWF_LOOP))
			continue;

		/* Everything called BEFORE this node belongs before it. */
		while (depth && e < ch->f->n_edge &&
		       ch->f->edge[e].from_func == fi &&
		       ch->f->edge[e].site < nd->va) {
			ch->run += ch->f->edge[e].site_step > prev
				   ? ch->f->edge[e].site_step - prev : 0u;
			prev = ch->f->edge[e].site_step;
			if (anchor)
				ch->pending = rel_va(ch->f, anchor,
						     ch->f->edge[e].site);
			anchor = ch->f->edge[e].site;
			ch->in = ch->f->edge[e].kind;
			chain_walk(ch, ch->f->edge[e].to_func, depth - 1u);
			ch->in = was_in;
			e++;
		}
		if (ch->n >= ch->cap)
			return;
		ch->run += nd->step > prev ? nd->step - prev : 0u;
		prev = nd->step;
		/*
		 * THE SAME STEP REPEATED IN A LOOP IS ONE STEP.
		 *
		 * A decrypt loop reads twenty times and a patcher writes to
		 * cr0 four times; recording each fills the window with one
		 * thing said over and over and leaves no room for the rest of
		 * the program. The count goes on the step instead - see
		 * kof_flow_node.repeat.
		 *
		 * THE SAME INNERMOST LOOP, not merely both in loops: two
		 * reads in two different loops are two things the program
		 * does, and merging them would be inventing a repetition
		 * that is not there.
		 */
		/*
		 * AND "THE SAME STEP" MEANS THE SAME THING, not the same
		 * word. prepare_creds and commit_creds are both cred-set and
		 * they are two different calls one after the other; merging
		 * them deleted the second and left a chain that said the
		 * module prepared credentials and never committed them.
		 * Measured the moment it was written, on diamorphine.
		 */
		/*
		 * AND THE SAME STEP REPEATED AT DIFFERENT CALL SITES IS ALSO
		 * ONE STEP.
		 *
		 * The loop test below used to be required, on the argument
		 * that only a loop proves the same instruction ran twice.
		 * True, and beside the point: a PE dropper resolves its API
		 * table with twenty-four separate calls to GetProcAddress,
		 * and the chain came out as twenty-four steps saying one
		 * thing. Measured over 1500 objects, `resolve` fills 22836 of
		 * the steps in every chain that reached the cap - more than
		 * three quarters of them - and what it crowds out is the rest
		 * of what those functions do.
		 *
		 * WHICH KIND OF REPETITION IT WAS IS STILL THERE and needs no
		 * new field: a merged step carrying KOF_FLOWF_LOOP is one
		 * site going round, and one without it is several sites doing
		 * the same thing. The count says how many either way.
		 *
		 * THE NAME STILL HAS TO MATCH. prepare_creds and commit_creds
		 * are both cred-set and are two different calls in sequence;
		 * merging them once deleted the second and left a chain that
		 * said the module prepared credentials and never committed
		 * them.
		 */
		/*
		 * AND NOT WHEN THE WORD DOES NOT IDENTIFY THE STEP.
		 *
		 * Merging says "the same thing happened again", and that is a
		 * claim. It is safe for `read` because read IS what the step
		 * was; it is false for `call-register`, where the word says
		 * only that the program went through its own dispatcher and
		 * the thing it actually did is behind a selector this engine
		 * deliberately does not decode.
		 *
		 * Measured on the MSF evasion stager: nine calls through one
		 * `call *%ebp` - LoadLibraryA, WSAStartup, WSASocketA,
		 * connect, recv, VirtualAlloc and three more. Collapsing them
		 * produced ONE step with a count of nine, which reads as one
		 * action repeated and is nine different actions. The count
		 * cannot carry that, because the thing that differs is not
		 * how many times but WHICH.
		 *
		 * So: a step whose capability is a dispatcher call is never
		 * merged into its neighbour. The general rule it follows is
		 * that merging is for steps whose identity is fully given by
		 * what the node records, and this one's is not.
		 */
		if (ch->n && nd->cap != KOF_CAP_CALL_REG &&
		    ch->out[ch->n - 1u].cap == nd->cap &&
		    ch->out[ch->n - 1u].name == nd->name &&
		    ch->out[ch->n - 1u].sel == nd->sel &&
		    (!(nd->flags & KOF_FLOWF_LOOP) ||
		     !(ch->out[ch->n - 1u].flags & KOF_FLOWF_LOOP) ||
		     (loop_of(ch->f, nd->va) &&
		      loop_of(ch->f, nd->va) ==
		      loop_of(ch->f, ch->out[ch->n - 1u].va)))) {
			if (ch->out[ch->n - 1u].repeat < 0xffffu)
				ch->out[ch->n - 1u].repeat++;
			prev = nd->step;
			anchor = nd->va;
			continue;
		}
		ch->out[ch->n] = *nd;
		/*
		 * WHICH LOOP IT IS IN, resolved here because this is where
		 * the chain is being built and `ch->f` still has the spans.
		 * See kof_flow_node.loop: the flag says a step repeats, this
		 * says whether two of them repeat together.
		 */
		ch->out[ch->n].loop = (nd->flags & KOF_FLOWF_LOOP)
				      ? (uint16_t)loop_of(ch->f, nd->va) : 0u;
		ch->out[ch->n].step = ch->run;
		ch->out[ch->n].entry = ch->in;
		/*
		 * HOW FAR IN: one level per call followed, one per loop
		 * around the address. `depth` counts DOWN as the walk
		 * descends, so the distance from where it started is the
		 * call nesting.
		 */
		{
			uint64_t hi = fi + 1u < ch->f->n_func
				    ? ch->f->func[fi + 1u].va : UINT64_MAX;
			uint32_t d = (ch->top > depth ? ch->top - depth : 0u) +
				     loop_depth(ch->f, nd->va, fn->va, hi);

			ch->out[ch->n].depth = d > 255u ? 255u : (uint8_t)d;
		}
		/*
		 * AND HOW IT FOLLOWS WHAT CAME BEFORE. The first step of a
		 * chain has nothing to follow, and UNKNOWN is what that is.
		 */
		ch->out[ch->n].rel = !ch->n ? KOF_REL_UNKNOWN
			: anchor ? rel_va(ch->f, anchor, nd->va)
				 : ch->pending;
		{
			uint32_t b = blk_of(ch->f, nd->va);

			ch->out[ch->n].cond = b < ch->f->n_blk
					    ? ch->f->blk[b].arm : 0u;
			/* Which branch and which side - see blk.arm_of. The
			 * pair is what lets two steps be drawn, and read, as
			 * the two arms of one `if`. */
			ch->out[ch->n].branch = b < ch->f->n_blk
					      ? ch->f->blk[b].arm_of : 0u;
			ch->out[ch->n].arm = b < ch->f->n_blk
					   ? ch->f->blk[b].arm_side : 0u;
		}
		if (ch->origin)
			ch->origin[ch->n] = fn->first + j;
		ch->n++;
		anchor = nd->va;
	}
	/* And whatever it calls after its last node. */
	while (depth && e < ch->f->n_edge && ch->f->edge[e].from_func == fi &&
	       ch->n < ch->cap) {
		ch->run += ch->f->edge[e].site_step > prev
			   ? ch->f->edge[e].site_step - prev : 0u;
		prev = ch->f->edge[e].site_step;
		if (anchor)
			ch->pending = rel_va(ch->f, anchor,
					     ch->f->edge[e].site);
		anchor = ch->f->edge[e].site;
		ch->in = ch->f->edge[e].kind;
		chain_walk(ch, ch->f->edge[e].to_func, depth - 1u);
		ch->in = was_in;
		e++;
	}
}

uint32_t kof_flow_chain(struct kof_flow *f, uint32_t func, uint32_t depth,
			struct kof_flow_node *out, uint32_t cap,
			uint32_t *origin)
{
	static uint32_t own[KOF_FLOW_ARGS * 64u];
	struct chain ch;
	uint32_t i, j, q;

	if (!f || !out || !cap)
		return 0;
	finish(f);
	if (func >= f->n_func)
		return 0;

	memset(&ch, 0, sizeof ch);
	ch.f = f;
	ch.out = out;
	ch.origin = origin ? origin : (cap <= sizeof own / sizeof own[0]
				       ? own : NULL);
	ch.cap = cap;
	ch.top = depth;
	chain_walk(&ch, func, depth);

	/*
	 * AND THE LINKS ARE REWRITTEN TO THE CHAIN'S OWN NUMBERING. Without
	 * this a `from` still points at a node index in the whole file, which
	 * means nothing to a comparison and everything to a bug.
	 */
	if (!ch.origin)
		for (i = 0; i < ch.n; i++) {
			memset(out[i].from, 0, sizeof out[i].from);
			memset(out[i].from_va, 0, sizeof out[i].from_va);
		}
	else
		for (i = 0; i < ch.n; i++)
			for (q = 0; q < KOF_FLOW_ARGS; q++) {
				uint32_t src;

				out[i].from_va[q] = 0;
				if (!out[i].from[q])
					continue;
				src = out[i].from[q] - 1u;
				out[i].from[q] = 0;
				/*
				 * THE EDGE'S FAR END, BY IDENTITY. Taken
				 * before the index is rewritten, because the
				 * index is about to stop meaning what it
				 * meant - see kof_flow_node.from_va.
				 */
				if (src < f->n_node)
					out[i].from_va[q] = f->node[src].va;
				for (j = 0; j < ch.n; j++)
					if (ch.origin[j] == src) {
						out[i].from[q] =
							(uint16_t)(j + 1u);
						break;
					}
			}
	return ch.n;
}

uint32_t kof_flow_n_edge(struct kof_flow *f)
{
	if (!f)
		return 0;
	finish(f);
	return f->n_edge;
}

int kof_flow_edge_at(struct kof_flow *f, uint32_t i, uint32_t *from,
		     uint32_t *to, uint64_t *site)
{
	if (!f)
		return 0;
	finish(f);
	if (i >= f->n_edge)
		return 0;
	if (from)
		*from = f->edge[i].from_func;
	if (to)
		*to = f->edge[i].to_func;
	if (site)
		*site = f->edge[i].site;
	return 1;
}

uint32_t kof_flow_n_func(struct kof_flow *f)
{
	if (!f)
		return 0;
	finish(f);
	return f->n_func;
}

uint64_t kof_flow_func_va(struct kof_flow *f, uint32_t func)
{
	if (!f)
		return 0;
	finish(f);
	return func < f->n_func ? f->func[func].va : 0;
}

const struct kof_flow_node *kof_flow_node_at(struct kof_flow *f, uint32_t i)
{
	if (!f)
		return NULL;
	finish(f);
	return i < f->n_node ? &f->node[i] : NULL;
}

uint32_t kof_flow_n_node(struct kof_flow *f)
{
	if (!f)
		return 0;
	finish(f);
	return f->n_node;
}




/*
 * IS B REACHABLE FROM A THROUGH THE BLOCK GRAPH.
 *
 * Breadth first over a bounded queue, and the bound is the whole of the
 * honesty: running out of queue, meeting a block that leaves through an
 * indirect branch, or finding either end outside the graph all answer
 * "cannot say" rather than "no". EXCLUSIVE is only returned when the search
 * COMPLETED and found nothing - which is the only case where "they never run
 * in this order" is a fact rather than a failure to look.
 */
static uint8_t reaches(struct kof_flow *f, uint32_t from, uint32_t to)
{
	/*
	 * STAMPED AND NOT CLEARED, because this is now asked once per step
	 * of every chain rather than once per rule.
	 *
	 * It used to memset the whole 8192-entry array on entry. One call
	 * paid for eight kilobytes to visit the twenty blocks of a small
	 * function, which was invisible while the only caller was
	 * kof_flow_relation and would have been the whole cost of the
	 * structure pass: a chain is built for every function of an object,
	 * so the question is asked tens of thousands of times for one file.
	 * A generation number makes the work the size of the search.
	 */
	uint32_t *seen = f->blk_seen, *queue = f->blk_q;
	uint32_t head = 0, tail = 0, qcap = f->cap_blk;
	int partial = 0;

	if (from >= f->n_blk || to >= f->n_blk || !seen || !queue)
		return KOF_REL_UNKNOWN;
	/* Zero is what a fresh array holds, so it is never a live stamp. */
	if (++f->blk_gen == 0u) {
		memset(seen, 0, (size_t)f->cap_blk * sizeof *seen);
		f->blk_gen = 1u;
	}
	queue[tail++] = from;
	seen[from] = f->blk_gen;
	while (head < tail) {
		uint32_t b = queue[head++], i;

		if (b == to && head > 1u)
			return KOF_REL_PATH;
		if (f->blk[b].open_end)
			partial = 1;
		for (i = 0; i < f->blk[b].n_succ; i++) {
			uint32_t nb = blk_of(f, f->blk[b].succ[i]);

			if (nb >= f->n_blk) { partial = 1; continue; }
			if (nb == to)
				return KOF_REL_PATH;
			if (seen[nb] == f->blk_gen)
				continue;
			if (tail >= qcap) { partial = 1; break; }
			seen[nb] = f->blk_gen;
			queue[tail++] = nb;
		}
	}
	return partial ? KOF_REL_UNKNOWN : KOF_REL_EXCLUSIVE;
}

/*
 * THE SAME QUESTION ABOUT TWO ADDRESSES, which is what the chain walker has.
 *
 * One implementation, because the walker and kof_flow_relation must not be
 * able to answer differently: a reader shown "these two are alternatives"
 * and a rule told "these two are a sequence" would both be reading this
 * file, and only one of them could be right.
 */
static uint8_t rel_va(struct kof_flow *f, uint64_t a, uint64_t b)
{
	uint32_t ba, bb;

	if (!f->n_blk)
		return KOF_REL_UNKNOWN;
	ba = blk_of(f, a);
	bb = blk_of(f, b);
	if (ba >= f->n_blk || bb >= f->n_blk)
		return KOF_REL_UNKNOWN;
	/* One block runs start to end, so an address inside it is reached by
	 * everything before it and by nothing after. */
	if (ba == bb)
		return a < b ? KOF_REL_SAME_BLOCK : KOF_REL_EXCLUSIVE;
	{
		uint8_t r = reaches(f, ba, bb);

		/* An incomplete graph cannot establish that no path exists -
		 * the path may be in the part that was not built. */
		if (r == KOF_REL_EXCLUSIVE && f->full)
			return KOF_REL_UNKNOWN;
		return r;
	}
}

uint8_t kof_flow_relation(struct kof_flow *f, uint32_t a, uint32_t b)
{
	if (!f)
		return KOF_REL_UNKNOWN;
	finish(f);
	if (a >= f->n_node || b >= f->n_node)
		return KOF_REL_UNKNOWN;
	return rel_va(f, f->node[a].va, f->node[b].va);
}



/*
 * A NEGATIVE ANSWER SURVIVES ONLY A COMPLETE SWEEP.
 *
 * One place, so the asymmetry cannot be forgotten at one call site and kept at
 * another - which is how a rule ends up trusting an absence nobody established.
 */
static uint8_t negative(const struct kof_flow *f)
{
	return f->full ? KOF_FACT_UNKNOWN : KOF_FACT_NO;
}

uint8_t kof_flow_has(struct kof_flow *f, uint32_t func, uint8_t cap)
{
	uint32_t i;

	if (!f || cap >= KOF_CAP_COUNT)
		return KOF_FACT_UNKNOWN;
	finish(f);
	if (func == KOF_FLOW_ALL_FUNCS) {
		for (i = 0; i < f->n_func; i++)
			if (f->func[i].mask & (1ull << cap))
				return KOF_FACT_YES;
		return negative(f);
	}
	if (func >= f->n_func)
		return KOF_FACT_UNKNOWN;
	return (f->func[func].mask & (1ull << cap)) ? KOF_FACT_YES : negative(f);
}

uint8_t kof_flow_only(struct kof_flow *f, uint32_t func, uint64_t mask)
{
	uint32_t i;
	uint64_t seen = 0;

	if (!f)
		return KOF_FACT_UNKNOWN;
	finish(f);
	if (func == KOF_FLOW_ALL_FUNCS) {
		for (i = 0; i < f->n_func; i++)
			seen |= f->func[i].mask;
	} else if (func < f->n_func) {
		seen = f->func[func].mask;
	} else {
		return KOF_FACT_UNKNOWN;
	}
	/*
	 * SOMETHING OUTSIDE THE SET IS A POSITIVE FINDING and stands whatever
	 * the sweep missed - it cannot have found MORE by looking further.
	 * Finding nothing outside it is the claim that needs a finished sweep.
	 */
	if (seen & ~mask)
		return KOF_FACT_NO;
	return negative(f) == KOF_FACT_NO ? KOF_FACT_YES : KOF_FACT_UNKNOWN;
}

uint8_t kof_flow_concentration(struct kof_flow *f, uint32_t *permille)
{
	uint32_t i, best = 0;

	if (!f)
		return KOF_FACT_UNKNOWN;
	finish(f);
	/*
	 * A TRUNCATED SWEEP CONCENTRATES BY CONSTRUCTION: it saw one thing
	 * because it stopped, not because there was one thing. So this is the
	 * whole measure, not one side of it, that a cap invalidates.
	 */
	if (f->full || !f->n_node)
		return KOF_FACT_UNKNOWN;
	for (i = 0; i < f->n_func; i++)
		if (f->func[i].n > best)
			best = f->func[i].n;
	if (permille)
		*permille = (uint32_t)((uint64_t)best * 1000u / f->n_node);
	return KOF_FACT_YES;
}
