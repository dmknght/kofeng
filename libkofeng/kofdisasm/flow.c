/* See flow.h. */

#include "flow.h"

#include <stdlib.h>
#include <string.h>

#include "bddisasm.h"

#define NGPR 16u

/*
 * WHAT A SYSCALL NUMBER MEANS, per ABI.
 *
 * Two tables and not one: i386 and x86-64 Linux do not share a numbering, and
 * a table that pretended they did would report `read` for `write` on half the
 * samples. Only the numbers a stager uses are here - this is a capability
 * reader, not a strace.
 */
struct sysrow { uint16_t nr; uint8_t cap; };

/* Linux x86-64. */
static const struct sysrow sys64[] = {
	{   0, KOF_CAP_READ },
	{   1, KOF_CAP_WRITE },
	{   2, KOF_CAP_FILE_OPEN },
	{   9, KOF_CAP_ALLOC },        /* mmap - prot decides, see prot_cap */
	{  10, KOF_CAP_ALLOC },        /* mprotect - same */
	{  35, KOF_CAP_SLEEP },
	{  41, KOF_CAP_NET_OPEN },
	{  42, KOF_CAP_NET_CONNECT },
	{  43, KOF_CAP_NET_ACCEPT },
	{  44, KOF_CAP_WRITE },        /* sendto */
	{  45, KOF_CAP_READ },         /* recvfrom */
	{  56, KOF_CAP_SPAWN },        /* clone */
	{  57, KOF_CAP_SPAWN },        /* fork */
	{  58, KOF_CAP_SPAWN },        /* vfork */
	{  59, KOF_CAP_EXEC_IMAGE },
	{ 257, KOF_CAP_FILE_OPEN },    /* openat */
	{ 319, KOF_CAP_MEMFD },
	{ 322, KOF_CAP_EXEC_IMAGE }    /* execveat */
};

/* Linux i386. */
static const struct sysrow sys32[] = {
	{   2, KOF_CAP_SPAWN },        /* fork */
	{   3, KOF_CAP_READ },
	{   4, KOF_CAP_WRITE },
	{   5, KOF_CAP_FILE_OPEN },
	{  11, KOF_CAP_EXEC_IMAGE },
	{  90, KOF_CAP_ALLOC },        /* old_mmap */
	{ 102, KOF_CAP_NONE },         /* socketcall - the sub-call is in ebx */
	{ 120, KOF_CAP_SPAWN },        /* clone */
	{ 125, KOF_CAP_ALLOC },        /* mprotect */
	{ 162, KOF_CAP_SLEEP },
	{ 192, KOF_CAP_ALLOC },        /* mmap2 */
	{ 295, KOF_CAP_FILE_OPEN },    /* openat */
	{ 356, KOF_CAP_MEMFD },
	{ 358, KOF_CAP_EXEC_IMAGE }    /* execveat */
};

/* i386 multiplexes every socket operation through socketcall, with the
 * operation in ebx. Left as its own table rather than folded into the one
 * above, because it is a different axis and merging them would need a second
 * key nothing else uses. */
static const struct sysrow sockcall[] = {
	{ 1, KOF_CAP_NET_OPEN },       /* SYS_SOCKET */
	{ 3, KOF_CAP_NET_CONNECT },
	{ 5, KOF_CAP_NET_ACCEPT },
	{ 9, KOF_CAP_WRITE },          /* SYS_SEND */
	{ 10, KOF_CAP_READ },          /* SYS_RECV */
	{ 11, KOF_CAP_WRITE },         /* SYS_SENDTO */
	{ 12, KOF_CAP_READ }           /* SYS_RECVFROM */
};

static uint8_t look(const struct sysrow *t, uint32_t n, uint32_t nr)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (t[i].nr == nr)
			return t[i].cap;
	return KOF_CAP_NONE;
}

/*
 * WHAT AN IMPORTED NAME IS, in the same vocabulary.
 *
 * Longest-sensible match and no prefix guessing: "recv" and "recvfrom" are
 * both here rather than matched by a prefix, because "recvmmsg" and "recvmsg"
 * would fall out of a prefix test and so would anything a future libc adds.
 *
 * WINDOWS NAMES SIT BESIDE POSIX ONES on purpose. VirtualAlloc and mmap are
 * the same fact about a program, and a rule written over these words is the
 * one thing that can be shared between the two platforms - see the note on
 * enum kof_flow_cap.
 */
static const struct { const char *name; uint8_t cap; } names[] = {
	/* POSIX */
	{ "mmap",           KOF_CAP_ALLOC },
	{ "mmap64",         KOF_CAP_ALLOC },
	{ "mprotect",       KOF_CAP_ALLOC },
	{ "socket",         KOF_CAP_NET_OPEN },
	{ "socketpair",     KOF_CAP_NET_OPEN },
	{ "connect",        KOF_CAP_NET_CONNECT },
	{ "accept",         KOF_CAP_NET_ACCEPT },
	{ "accept4",        KOF_CAP_NET_ACCEPT },
	{ "bind",           KOF_CAP_NET_OPEN },
	{ "listen",         KOF_CAP_NET_OPEN },
	{ "recv",           KOF_CAP_READ },
	{ "recvfrom",       KOF_CAP_READ },
	{ "recvmsg",        KOF_CAP_READ },
	{ "read",           KOF_CAP_READ },
	{ "send",           KOF_CAP_WRITE },
	{ "sendto",         KOF_CAP_WRITE },
	{ "sendmsg",        KOF_CAP_WRITE },
	{ "write",          KOF_CAP_WRITE },
	{ "open",           KOF_CAP_FILE_OPEN },
	{ "open64",         KOF_CAP_FILE_OPEN },
	{ "openat",         KOF_CAP_FILE_OPEN },
	{ "fopen",          KOF_CAP_FILE_OPEN },
	{ "memfd_create",   KOF_CAP_MEMFD },
	{ "execve",         KOF_CAP_EXEC_IMAGE },
	{ "execv",          KOF_CAP_EXEC_IMAGE },
	{ "execl",          KOF_CAP_EXEC_IMAGE },
	{ "execlp",         KOF_CAP_EXEC_IMAGE },
	{ "execvp",         KOF_CAP_EXEC_IMAGE },
	{ "system",         KOF_CAP_EXEC_IMAGE },
	{ "popen",          KOF_CAP_EXEC_IMAGE },
	{ "fork",           KOF_CAP_SPAWN },
	{ "vfork",          KOF_CAP_SPAWN },
	{ "clone",          KOF_CAP_SPAWN },
	{ "daemon",         KOF_CAP_SPAWN },
	{ "sleep",          KOF_CAP_SLEEP },
	{ "usleep",         KOF_CAP_SLEEP },
	{ "nanosleep",      KOF_CAP_SLEEP },
	{ "ptrace",         KOF_CAP_PTRACE },
	/* Windows, for the same words */
	{ "VirtualAlloc",   KOF_CAP_ALLOC },
	{ "VirtualAllocEx", KOF_CAP_ALLOC },
	{ "VirtualProtect", KOF_CAP_ALLOC },
	{ "WSASocketA",     KOF_CAP_NET_OPEN },
	{ "WSASocketW",     KOF_CAP_NET_OPEN },
	{ "InternetOpenA",  KOF_CAP_NET_OPEN },
	{ "InternetOpenW",  KOF_CAP_NET_OPEN },
	{ "WSAConnect",     KOF_CAP_NET_CONNECT },
	{ "InternetConnectA", KOF_CAP_NET_CONNECT },
	{ "InternetConnectW", KOF_CAP_NET_CONNECT },
	{ "CreateFileA",    KOF_CAP_FILE_OPEN },
	{ "CreateFileW",    KOF_CAP_FILE_OPEN },
	{ "WriteFile",      KOF_CAP_WRITE },
	{ "ReadFile",       KOF_CAP_READ },
	{ "CreateProcessA", KOF_CAP_EXEC_IMAGE },
	{ "CreateProcessW", KOF_CAP_EXEC_IMAGE },
	{ "WinExec",        KOF_CAP_EXEC_IMAGE },
	{ "ShellExecuteA",  KOF_CAP_EXEC_IMAGE },
	{ "ShellExecuteW",  KOF_CAP_EXEC_IMAGE },
	{ "CreateThread",   KOF_CAP_SPAWN },
	{ "Sleep",          KOF_CAP_SLEEP }
};

uint8_t kof_flow_cap_of_name(const char *sym)
{
	size_t i;

	if (!sym || !*sym)
		return KOF_CAP_NONE;
	/* An ELF import may carry a version suffix - "open64@@GLIBC_2.2.5" is
	 * the same function as "open64", and the caller should not have to
	 * know that this file cares. */
	for (i = 0; i < sizeof names / sizeof names[0]; i++) {
		const char *a = names[i].name, *b = sym;

		while (*a && *a == *b) { a++; b++; }
		if (!*a && (!*b || *b == '@'))
			return names[i].cap;
	}
	return KOF_CAP_NONE;
}

const char *kof_flow_cap_name(uint8_t cap)
{
	switch (cap) {
	case KOF_CAP_ALLOC:        return "alloc";
	case KOF_CAP_ALLOC_EXEC:   return "alloc-exec";
	case KOF_CAP_NET_OPEN:     return "net-open";
	case KOF_CAP_NET_CONNECT:  return "net-connect";
	case KOF_CAP_NET_ACCEPT:   return "net-accept";
	case KOF_CAP_READ:         return "read";
	case KOF_CAP_WRITE:        return "write";
	case KOF_CAP_FILE_OPEN:    return "file-open";
	case KOF_CAP_MEMFD:        return "memfd";
	case KOF_CAP_EXEC_IMAGE:   return "exec-image";
	case KOF_CAP_SPAWN:        return "spawn";
	case KOF_CAP_SLEEP:        return "sleep";
	case KOF_CAP_PTRACE:       return "ptrace";
	default:                   return "?";
	}
}

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
	uint8_t  rcap[NGPR];

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

static uint32_t gpr_of(const ND_OPERAND *op)
{
	if (op->Type != ND_OP_REG || op->Info.Register.Type != ND_REG_GPR)
		return NGPR;
	return op->Info.Register.Reg < NGPR ? op->Info.Register.Reg : NGPR;
}

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
	memset(c->src, 0, sizeof c->src);
	memset(c->rcap, 0, sizeof c->rcap);
}

static void forget(struct cmap *c, uint32_t r)
{
	if (r < NGPR) {
		c->v[r] = 0;
		c->known[r] = 0;
		c->src[r] = 0;
		c->rcap[r] = KOF_CAP_NONE;
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
			if (!sr)
				out->arg_const |= (uint8_t)(1u << i);
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
		if (!c->src[r] && c->known[r])
			out->arg_const |= (uint8_t)(1u << i);
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
#define R_RDI 7u

static uint8_t prot_cap(const struct cmap *c, unsigned abi, unsigned bits,
			int by_call)
{
	uint64_t prot;
	int low8;

	/*
	 * THE THIRD ARGUMENT, wherever this convention keeps it: the stack for
	 * a 32-bit call, r8 for Microsoft's 64-bit one, rdx for SysV and for
	 * the Linux syscall ABI.
	 */
	if (by_call && bits == 32) {
		if (!stack_arg(c, 2u, &prot, NULL))
			return KOF_CAP_ALLOC;
	} else if (!const_of(c, abi == KOF_FLOW_MS ? R_R8 : R_RDX, &prot,
			     &low8))
		return KOF_CAP_ALLOC;    /* unknown - claim the weaker thing */
	/*
	 * AND THE WORD MEANS DIFFERENT THINGS. POSIX packs the three
	 * permissions into three bits and execute is bit 2; Windows enumerates
	 * the combinations and every one that can be executed is in the high
	 * nibble - PAGE_EXECUTE 0x10 through PAGE_EXECUTE_WRITECOPY 0x80. A
	 * mask written for one reads the other as never executable, which is
	 * the quietest possible way to lose the strongest term here.
	 */
	if (abi == KOF_FLOW_MS)
		return (prot & 0xf0u) ? KOF_CAP_ALLOC_EXEC : KOF_CAP_ALLOC;
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

struct kof_flow {
	struct kof_flow_node node[KOF_FLOW_MAX_NODE];
	uint32_t n_node;

	/* Function heads, in the order met; sorted and deduplicated by
	 * finish(). The code start of every added run is one, so a blob with
	 * no calls in it is still one region rather than none. */
	uint64_t head[KOF_FLOW_MAX_FUNC];
	uint32_t n_head;

	struct kof_flow_func func[KOF_FLOW_MAX_FUNC];
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
	struct cedge { uint64_t from_va, to_va; } edge[KOF_FLOW_MAX_FUNC];
	uint32_t n_edge;

	uint64_t entry;
	uint32_t has_entry;

	struct blk {
		uint64_t lo, hi;        /* [lo, hi) */
		uint32_t succ[2];
		uint8_t  n_succ;
		uint8_t  open_end;      /* left through an indirect branch */
	} blk[KOF_FLOW_MAX_BLOCK];
	uint32_t n_blk;

	kof_flow_resolve_fn resolve;
	void               *resolve_user;

	uint32_t full;      /* a cap was reached - see kof_flow_full */
	uint32_t finished;
};

void kof_flow_resolver(struct kof_flow *f, kof_flow_resolve_fn fn, void *user)
{
	if (f) {
		f->resolve = fn;
		f->resolve_user = user;
	}
}

struct kof_flow *kof_flow_new(void)
{
	struct kof_flow *f = (struct kof_flow *)calloc(1, sizeof *f);

	return f;
}

void kof_flow_free(struct kof_flow *f)
{
	free(f);
}

int kof_flow_full(const struct kof_flow *f)
{
	return f ? (int)f->full : 1;
}

static void add_edge(struct kof_flow *f, uint64_t from, uint64_t to)
{
	if (f->n_edge < KOF_FLOW_MAX_FUNC) {
		f->edge[f->n_edge].from_va = from;
		f->edge[f->n_edge].to_va = to;
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

static void add_head(struct kof_flow *f, uint64_t va)
{
	if (f->n_head < KOF_FLOW_MAX_FUNC)
		f->head[f->n_head++] = va;
	else
		f->full = 1;
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

/* Decode only, and record where a direct branch can land. */
static void find_targets(struct tset *t, const uint8_t *code, uint32_t code_n,
			 uint64_t code_va, unsigned bits)
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
			if (tg >= code_va && tg < code_va + code_n)
				tset_put(t, tg);
		}
		at += ix.Length;
	}
}

/* Open a block at `va`, closing whatever was open. */
static uint32_t blk_open(struct kof_flow *f, uint64_t va)
{
	if (f->n_blk >= KOF_FLOW_MAX_BLOCK) {
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

/* Which block holds this address, or n_blk. Linear because a region's blocks
 * are few and the array is in address order. */
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
			unsigned abi, int by_call, uint64_t va,
			uint64_t code_va, uint32_t code_n, uint8_t cap)
{
	const uint8_t *a;
	uint32_t i;

	if (!f || cap != KOF_CAP_SPAWN)
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
				add_head(f, v);
				add_edge(f, va, v);
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
			add_head(f, c->v[r]);
			add_edge(f, va, c->v[r]);
		}
	}
}

static uint32_t sweep(struct kof_flow *f, const uint8_t *code, uint32_t code_n,
		      uint64_t code_va, unsigned bits, unsigned abi,
		      struct kof_flow_node *out, uint32_t cap)
{
	struct cmap c;
	struct tset *t;
	uint32_t at = 0, n = 0, step = 0, cur_blk = 0;
	int in_push_run = 0;
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

	memset(&c, 0, sizeof c);
	cur_blk = f ? blk_open(f, code_va) : 0u;
	t = (struct tset *)calloc(1, sizeof *t);
	if (t)
		find_targets(t, code, code_n, code_va, bits);
	/* Without it every fact still holds within a straight line; what is
	 * lost is the clearing at a join, so the sweep is more credulous
	 * rather than wrong in a new way. */

	while (at < code_n && n < cap) {
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

			if (ix.Instruction == ND_INS_CALLNR) {
				tgt = branch_target(&ix, next);
				if (tgt >= code_va && tgt < code_va + code_n) {
					add_head(f, tgt);
					add_edge(f, va, tgt);
				}
				/*
				 * AND IT MAY BE AN IMPORT. Asked of the
				 * caller, which is the only side that can
				 * answer - see kof_flow_resolver. The node is
				 * placed at the CALL SITE and not at the stub:
				 * what matters is where in the program the
				 * thing is asked for.
				 */
				if (f->resolve && n < cap) {
					uint8_t k = f->resolve(tgt,
							f->resolve_user);

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
						k = prot_cap(&c, abi, bits, 1);
					if (k != KOF_CAP_NONE) {
						memset(&out[n], 0,
						       sizeof out[n]);
						out[n].va   = va;
						out[n].step = step;
						out[n].sel  = 0;
						out[n].cap  = k;
						arg_scan(&c, bits, abi, 1,
							 &out[n]);
						thread_edge(f, &c, bits, abi,
							    1, va, code_va,
							    code_n, k);
						n++;
						/* The call returns in rax on
						 * both ABIs, and that is the
						 * pointer the chain follows. */
						forget(&c, R_RAX);
						c.src[R_RAX] = (uint16_t)n;
					}
				}
			} else if (ix.Instruction == ND_INS_CALLNI ||
				   ix.Instruction == ND_INS_JMPNI) {
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
					uint64_t slot = mem_abs(&ix.Operands[q],
							 next);
					uint8_t k;

					if (!slot)
						continue;
					k = f->resolve(slot, f->resolve_user);
					if (k == KOF_CAP_NONE || n >= cap)
						continue;
					/* And whether the mapping can be run
					 * - the same question the direct-call
					 * path asks, and forgetting it here
					 * made every VirtualProtect on
					 * Windows an ordinary allocation. */
					if (k == KOF_CAP_ALLOC)
						k = prot_cap(&c, abi, bits, 1);
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
					arg_scan(&c, bits, abi, 1, &out[n]);
					thread_edge(f, &c, bits, abi, 1, va,
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
				uint8_t k2 = f->resolve(slot, f->resolve_user);

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

			if (const_of(&c, R_RAX, &nr, &low8)) {
				sel = (uint16_t)nr;
				if (bits == 32) {
					k = look(sys32, sizeof sys32 /
						 sizeof sys32[0],
						 (uint32_t)nr);
					if (nr == 102) {
						uint64_t sub;
						int l2;

						if (const_of(&c, R_RBX, &sub,
							     &l2))
							k = look(sockcall,
								 sizeof sockcall
								 / sizeof
								 sockcall[0],
								 (uint32_t)sub);
					}
					if (nr == 125 || nr == 192 || nr == 90)
						k = prot_cap(&c, abi, bits, 0);
				} else {
					k = look(sys64, sizeof sys64 /
						 sizeof sys64[0],
						 (uint32_t)nr);
					if (nr == 9 || nr == 10)
						k = prot_cap(&c, abi, bits, 0);
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
			if (k != KOF_CAP_NONE) {
				memset(&out[n], 0, sizeof out[n]);
				out[n].va    = va;
				out[n].step  = step;
				out[n].sel   = sel;
				out[n].cap   = k;
				arg_scan(&c, bits, abi, 0, &out[n]);
				thread_edge(f, &c, bits, abi, 0, va, code_va,
					    code_n, k);
				out[n].flags = low8 ? KOF_FLOWF_LOW8 : 0;
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
				if (r < NGPR && c.rcap[r] != KOF_CAP_NONE &&
				    n < cap) {
					uint8_t k3 = c.rcap[r];

					if (k3 == KOF_CAP_ALLOC)
						k3 = prot_cap(&c, abi, bits, 1);
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
					out[n].flags = KOF_FLOWF_VIA_REG;
					arg_scan(&c, bits, abi, 1,
						 &out[n]);
					thread_edge(f, &c, bits, abi, 1, va,
						    code_va, code_n, k3);
					n++;
					forget(&c, R_RAX);
					c.src[R_RAX] = (uint16_t)n;
				}

				if (r >= NGPR || !ix.Operands[i].Access.Read)
					continue;
				sr = c.src[r];
				if (sr && sr <= n)
					out[sr - 1u].flags |=
						KOF_FLOWF_EXECUTED;
				/* Or the branch goes to an address something
				 * earlier was asked to make executable. */
				if (!c.known[r])
					continue;
				for (q = 0; q < n_mapped; q++)
					if (mapped[q].addr == c.v[r] &&
					    mapped[q].node <= n)
						out[mapped[q].node - 1u].flags
							|= KOF_FLOWF_EXECUTED;
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
			/* Control does not fall through any of these, so what
			 * follows in ADDRESS order is not what follows in
			 * execution order. A return also ends the stack this
			 * was following; a jump does not. */
			join_clear(&c);
			if (ix.Instruction == ND_INS_RETN ||
			    ix.Instruction == ND_INS_RETF)
				stack_drop(&c);
			at += ix.Length;
			continue;
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

				forget(&c, d);
				c.src[d] = keep;
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

void kof_flow_add(struct kof_flow *f, const uint8_t *code, uint32_t code_n,
		  uint64_t code_va, unsigned bits, unsigned abi)
{
	if (!f || !code || !code_n || f->finished)
		return;
	if (code_n > KOF_FLOW_MAX_CODE) {
		code_n = KOF_FLOW_MAX_CODE;
		f->full = 1;
	}
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

static int cmp_node(const void *a, const void *b)
{
	const struct kof_flow_node *x = a, *y = b;

	if (x->func != y->func)
		return x->func < y->func ? -1 : 1;
	return x->va < y->va ? -1 : (x->va > y->va ? 1 : 0);
}

static void finish(struct kof_flow *f)
{
	uint32_t i, k;

	if (f->finished)
		return;
	f->finished = 1;

	/* Heads, sorted and deduplicated - a function called from ten places
	 * was added ten times. */
	qsort(f->head, f->n_head, sizeof f->head[0], cmp_u64);
	for (i = 0; i < f->n_head; i++) {
		if (i && f->head[i] == f->head[i - 1])
			continue;
		if (f->n_func >= KOF_FLOW_MAX_FUNC) {
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
	}
	/* Grouped so a region is a slice and not a search. */
	qsort(f->node, f->n_node, sizeof f->node[0], cmp_node);
	for (i = 0; i < f->n_node; i = k) {
		uint32_t fi = f->node[i].func;

		for (k = i; k < f->n_node && f->node[k].func == fi; k++)
			f->func[fi].mask |= 1u << f->node[k].cap;
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
		uint32_t a = func_of(f, f->edge[i].from_va);
		uint32_t b = func_of(f, f->edge[i].to_va);

		f->edge[i].from_va = a;
		f->edge[i].to_va = b;
		if (a >= f->n_func || b >= f->n_func)
			continue;
		f->func[a].n_call++;
		f->func[b].n_caller++;
	}

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
				uint32_t a = (uint32_t)f->edge[i].from_va;
				uint32_t b = (uint32_t)f->edge[i].to_va;
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

uint32_t kof_flow_n_func(struct kof_flow *f)
{
	if (!f)
		return 0;
	finish(f);
	return f->n_func;
}

uint32_t kof_flow_n_node(struct kof_flow *f)
{
	if (!f)
		return 0;
	finish(f);
	return f->n_node;
}

const struct kof_flow_func *kof_flow_func_at(struct kof_flow *f, uint32_t i)
{
	if (!f)
		return NULL;
	finish(f);
	return i < f->n_func ? &f->func[i] : NULL;
}

const struct kof_flow_node *kof_flow_node_at(struct kof_flow *f, uint32_t i)
{
	if (!f)
		return NULL;
	finish(f);
	return i < f->n_node ? &f->node[i] : NULL;
}

const char *kof_flow_rel_name(uint8_t rel)
{
	switch (rel) {
	case KOF_REL_SAME_BLOCK: return "same-block";
	case KOF_REL_PATH:       return "path";
	case KOF_REL_EXCLUSIVE:  return "exclusive";
	default:                 return "unknown";
	}
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
	static uint8_t seen[KOF_FLOW_MAX_BLOCK];
	uint32_t queue[256], head = 0, tail = 0;
	int partial = 0;

	if (from >= f->n_blk || to >= f->n_blk)
		return KOF_REL_UNKNOWN;
	memset(seen, 0, f->n_blk);
	queue[tail++] = from;
	seen[from] = 1;
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
			if (seen[nb])
				continue;
			if (tail >= 256u) { partial = 1; break; }
			seen[nb] = 1;
			queue[tail++] = nb;
		}
	}
	return partial ? KOF_REL_UNKNOWN : KOF_REL_EXCLUSIVE;
}

uint8_t kof_flow_relation(struct kof_flow *f, uint32_t a, uint32_t b)
{
	uint32_t ba, bb;

	if (!f)
		return KOF_REL_UNKNOWN;
	finish(f);
	if (a >= f->n_node || b >= f->n_node || !f->n_blk)
		return KOF_REL_UNKNOWN;
	ba = blk_of(f, f->node[a].va);
	bb = blk_of(f, f->node[b].va);
	if (ba >= f->n_blk || bb >= f->n_blk)
		return KOF_REL_UNKNOWN;
	if (ba == bb)
		return f->node[a].va < f->node[b].va ? KOF_REL_SAME_BLOCK
						     : KOF_REL_EXCLUSIVE;
	{
		uint8_t r = reaches(f, ba, bb);

		/* An incomplete graph cannot establish that no path exists -
		 * the path may be in the part that was not built. */
		if (r == KOF_REL_EXCLUSIVE && f->full)
			return KOF_REL_UNKNOWN;
		return r;
	}
}

const char *kof_fact_name(uint8_t v)
{
	switch (v) {
	case KOF_FACT_YES: return "yes";
	case KOF_FACT_NO:  return "no";
	default:           return "unknown";
	}
}

void kof_flow_mark_partial(struct kof_flow *f)
{
	if (f)
		f->full = 1;
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
			if (f->func[i].mask & (1u << cap))
				return KOF_FACT_YES;
		return negative(f);
	}
	if (func >= f->n_func)
		return KOF_FACT_UNKNOWN;
	return (f->func[func].mask & (1u << cap)) ? KOF_FACT_YES : negative(f);
}

uint8_t kof_flow_only(struct kof_flow *f, uint32_t func, uint32_t mask)
{
	uint32_t i, seen = 0;

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
