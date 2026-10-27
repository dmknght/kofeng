/*
 * emu_win_exc.c - the Windows environment: structured exception dispatch, the call event log and the socket model.
 * Part of the interpreter; see emu_interp.c and emu_private.h.
 */
#define _POSIX_C_SOURCE 199309L

#include "emu_private.h"

/* ---- exception dispatch --------------------------------------------------
 *
 * WHY THIS IS NEEDED AT ALL, WHICH IS NOT "FOR CORRECTNESS".
 *
 * A fault is normally the end of a run and that is usually right. It is wrong
 * for a protected binary, because a protector FAULTS ON PURPOSE. Measured: one
 * of the four Themida samples walks down its own stack until it runs off the
 * bottom. Giving it four times the stack did not help and was not meant to -
 * it ran 7 million instructions further and faulted again exactly one megabyte
 * lower, because what it is doing is finding the end, not needing the room.
 * On Windows the fault it provokes is delivered to a handler and the program
 * carries on. Here it was simply the end.
 *
 * So the run loop has to be able to call guest code and come back, and that is
 * the whole shape of what follows: a fault builds the records Windows would
 * have built, calls the handler as a function, and the loop recognises its
 * return by the address it returns to - one nothing maps, so it can never be a
 * real one.
 *
 * TWO MECHANISMS, IN THE ORDER WINDOWS USES THEM.
 *
 *   VEH   a flat list, registered by the guest, consulted first, and the same
 *         on both widths. Protectors like it for exactly that reason.
 *   SEH   the FS:[0] chain, i386 only. amd64 replaced it with tables in
 *         .pdata, which are not implemented here - so a 64-bit guest gets VEH
 *         and nothing else, and a 64-bit guest relying on table SEH still
 *         stops. That is a gap and is left visible rather than approximated.
 *
 * WHAT A HANDLER MAY DO. Return "continue execution", having possibly edited
 * the CONTEXT - which is the case that matters, because editing the CONTEXT is
 * how a stack prober says "put me back here and skip that instruction". Return
 * "continue search", and the next handler is tried. Unwinding is NOT supported:
 * RtlUnwind is not provided, so a handler that wants to unwind finds nothing
 * to call and the run ends where it would have unwound from.
 */
/*
 * ONE ADDRESS FOR BOTH WIDTHS, unlike the stack and the thread block above.
 * Those needed two because a 32-bit guest cannot represent the 64-bit value;
 * this one is under 4 GB, so the same number is correct in either mode and a
 * second constant would only be a second thing to keep in step.
 */
#define WIN_EXC_BASE     0x2f000000ull
#define WIN_EXC_PAGES    4u
#define EXC_REC_OFF      0x000u   /* EXCEPTION_RECORD */
#define EXC_CTX_OFF      0x400u   /* CONTEXT */
#define EXC_PTR_OFF      0xf00u   /* EXCEPTION_POINTERS, for a VEH */
#define WIN_RET_MAGIC    0x2ff00000ull
#define WIN_EXC_MAX_DEPTH 4u

#define EXC_ACCESS_VIOLATION 0xc0000005u
#define EXC_INT_DIVIDE_BY_ZERO 0xc0000094u      /* DIV, IDIV: a zero divisor              */
#define EXC_INT_OVERFLOW       0xc0000095u
#define EXC_PRIVILEGED_INSTRUCTION 0xc0000096u  /* IN, OUT, CLI, STI at ring 3 */      /* DIV, IDIV: a quotient that does not fit */
/* A handle for the process heap: distinct, non-zero, and never dereferenced. */
/* The process heap handle IS its address: Windows hands back a pointer to the
 * HEAP structure, and a guest that reads Flags through it is reading memory
 * rather than interpreting a token. A made-up token faults the moment it is
 * dereferenced - which is what 0x18 did. */

uint64_t kgenome_emu_win_ret_magic(const struct kgenome_emu *e)
{
	(void)e;
	return WIN_RET_MAGIC;
}

static int win_exc_ready(struct kgenome_emu *e)
{
	uint64_t base = WIN_EXC_BASE;

	if (e->exc_base)
		return 1;
	if (!kgenome_emu_vma_add(e, base, (uint64_t)WIN_EXC_PAGES * KGENOME_EMU_PAGE, 0,
		     KGENOME_EMU_R | KGENOME_EMU_W, 0))
		return 0;
	e->exc_base = base;
	return 1;
}

/*
 * The CONTEXT offsets, which are the architecture's published layout and are
 * the one thing here that cannot be chosen. A handler reads and writes this
 * structure directly - it is the documented way to resume somewhere else - so
 * a wrong offset is not a crash, it is a resume at an address made of the
 * wrong field.
 */
#define CTX32_FLAGS  0x000u
#define CTX32_EDI    0x09cu
#define CTX32_EIP    0x0b8u
#define CTX32_EFLAGS 0x0c0u
#define CTX32_ESP    0x0c4u
#define CTX32_SIZE   0x2ccu

#define CTX64_FLAGS  0x030u
#define CTX64_EFLAGS 0x044u
#define CTX64_RAX    0x078u
#define CTX64_RIP    0x0f8u
#define CTX64_SIZE   0x4d0u

/* i386 CONTEXT keeps the six GPRs in this order from CTX32_EDI. */
static const unsigned ctx32_ord[6] = {
	KGENOME_EMU_RDI, KGENOME_EMU_RSI, KGENOME_EMU_RBX,
	KGENOME_EMU_RDX, KGENOME_EMU_RCX, KGENOME_EMU_RAX
};
/* amd64 CONTEXT, from CTX64_RAX: rax rcx rdx rbx rsp rbp rsi rdi r8..r15. */
static const unsigned ctx64_ord[16] = {
	KGENOME_EMU_RAX, KGENOME_EMU_RCX, KGENOME_EMU_RDX, KGENOME_EMU_RBX,
	KGENOME_EMU_RSP, KGENOME_EMU_RBP, KGENOME_EMU_RSI, KGENOME_EMU_RDI,
	KGENOME_EMU_R8,  KGENOME_EMU_R9,  KGENOME_EMU_R10, KGENOME_EMU_R11,
	KGENOME_EMU_R12, KGENOME_EMU_R13, KGENOME_EMU_R14, KGENOME_EMU_R15
};

static void ctx_save(struct kgenome_emu *e, uint64_t ctx)
{
	uint8_t zero[CTX64_SIZE];
	unsigned i;

	memset(zero, 0, sizeof zero);
	kgenome_emu_mem_wr(e, ctx, zero, e->bits == 32 ? CTX32_SIZE : CTX64_SIZE);

	if (e->bits == 32) {
		uint32_t flags = 0x0001003fu;   /* CONTEXT_FULL, i386 */
		uint32_t v;

		kgenome_emu_mem_wr(e, ctx + CTX32_FLAGS, &flags, 4u);
		for (i = 0; i < 6u; i++) {
			v = (uint32_t)e->gpr[ctx32_ord[i]];
			kgenome_emu_mem_wr(e, ctx + CTX32_EDI + 4u * i, &v, 4u);
		}
		v = (uint32_t)e->gpr[KGENOME_EMU_RBP];
		kgenome_emu_mem_wr(e, ctx + CTX32_EDI + 4u * 6u, &v, 4u);   /* Ebp */
		v = (uint32_t)e->rip;
		kgenome_emu_mem_wr(e, ctx + CTX32_EIP, &v, 4u);
		v = (uint32_t)e->flags;
		kgenome_emu_mem_wr(e, ctx + CTX32_EFLAGS, &v, 4u);
		v = (uint32_t)e->gpr[KGENOME_EMU_RSP];
		kgenome_emu_mem_wr(e, ctx + CTX32_ESP, &v, 4u);
		return;
	}
	{
		uint32_t flags = 0x0010001fu;   /* what the kernel delivers: full, segments, floating point, debug registers */
		uint32_t ef = (uint32_t)e->flags;
		uint32_t mx = 0x1f80u;          /* MxCsr's power-on value */
		uint16_t seg[6] = { 0x33u, 0x2bu, 0x2bu, 0x53u, 0x2bu, 0x2bu };  /* cs ds es fs gs ss of a 64-bit process */
		uint64_t v;

		kgenome_emu_mem_wr(e, ctx + CTX64_FLAGS, &flags, 4u);
		kgenome_emu_mem_wr(e, ctx + 0x34u, &mx, 4u);
		kgenome_emu_mem_wr(e, ctx + 0x38u, seg, sizeof seg);
		kgenome_emu_mem_wr(e, ctx + CTX64_EFLAGS, &ef, 4u);
		for (i = 0; i < 16u; i++) {
			v = e->gpr[ctx64_ord[i]];
			kgenome_emu_mem_wr(e, ctx + CTX64_RAX + 8u * i, &v, 8u);
		}
		v = e->rip;
		kgenome_emu_mem_wr(e, ctx + CTX64_RIP, &v, 8u);
	}
}

static void ctx_load(struct kgenome_emu *e, uint64_t ctx)
{
	unsigned i;
	uint64_t v = 0;

	if (e->bits == 32) {
		for (i = 0; i < 6u; i++)
			if (kgenome_emu_mem_rd(e, ctx + CTX32_EDI + 4u * i, &v, 4u))
				e->gpr[ctx32_ord[i]] = v & 0xffffffffu;
		if (kgenome_emu_mem_rd(e, ctx + CTX32_EDI + 4u * 6u, &v, 4u))
			e->gpr[KGENOME_EMU_RBP] = v & 0xffffffffu;
		if (kgenome_emu_mem_rd(e, ctx + CTX32_EIP, &v, 4u))
			e->rip = v & 0xffffffffu;
		if (kgenome_emu_mem_rd(e, ctx + CTX32_EFLAGS, &v, 4u))
			e->flags = v & 0xffffffffu;
		if (kgenome_emu_mem_rd(e, ctx + CTX32_ESP, &v, 4u))
			e->gpr[KGENOME_EMU_RSP] = v & 0xffffffffu;
		return;
	}
	for (i = 0; i < 16u; i++)
		if (kgenome_emu_mem_rd(e, ctx + CTX64_RAX + 8u * i, &v, 8u))
			e->gpr[ctx64_ord[i]] = v;
	if (kgenome_emu_mem_rd(e, ctx + CTX64_RIP, &v, 8u))
		e->rip = v;
	if (kgenome_emu_mem_rd(e, ctx + CTX64_EFLAGS, &v, 4u))
		e->flags = v & 0xffffffffu;
}

/*
 * Call a guest function and arrange to be told when it returns.
 *
 * The return address is an address nothing maps, so the loop's check for it
 * can never collide with a real return - and if the check were ever removed
 * the guest would fault there rather than run on into nothing.
 */
static int win_call(struct kgenome_emu *e, uint64_t fn, const uint64_t *arg,
		    unsigned n)
{
	uint64_t magic = kgenome_emu_win_ret_magic(e);
	unsigned i;

	if (e->bits == 32) {
		for (i = n; i > 0; i--)
			if (!kgenome_emu_push(e, arg[i - 1]))
				return 0;
		if (!kgenome_emu_push(e, magic))
			return 0;
	} else {
		static const unsigned r[4] = {
			KGENOME_EMU_RCX, KGENOME_EMU_RDX, KGENOME_EMU_R8, KGENOME_EMU_R9
		};

		for (i = 0; i < n && i < 4u; i++)
			e->gpr[r[i]] = arg[i];
		/* The shadow space a callee is entitled to spill into, then the
		 * return address - and the pair leaves rsp 16-aligned before
		 * the call, which is what the ABI promises a callee. */
		e->gpr[KGENOME_EMU_RSP] = (e->gpr[KGENOME_EMU_RSP] - 32u) & ~15ull;
		if (!kgenome_emu_push(e, magic))
			return 0;
	}
	e->rip = fn;
	return 1;
}

/* Hand the current exception to handler number `i` of the current phase, or
 * report that there is none left to try. */
static int win_exc_dispatch(struct kgenome_emu *e)
{
	uint64_t rec = e->exc_base + EXC_REC_OFF;
	uint64_t ctx = e->exc_base + EXC_CTX_OFF;
	uint64_t arg[4];

	if (e->exc_phase == 1u) {
		uint64_t ptrs = e->exc_base + EXC_PTR_OFF;

		while (e->exc_veh_i < e->n_veh) {
			uint64_t h = e->win_veh[e->exc_veh_i++];

			if (!h)
				continue;
			if (e->bits == 32) {
				uint32_t a = (uint32_t)rec, b = (uint32_t)ctx;

				kgenome_emu_mem_wr(e, ptrs, &a, 4u);
				kgenome_emu_mem_wr(e, ptrs + 4u, &b, 4u);
			} else {
				kgenome_emu_mem_wr(e, ptrs, &rec, 8u);
				kgenome_emu_mem_wr(e, ptrs + 8u, &ctx, 8u);
			}
			arg[0] = ptrs;
			return win_call(e, h, arg, 1u);
		}
		/* No vectored handler took it: fall through to the chain. */
		e->exc_phase = 2u;
		if (e->bits == 32) {
			uint64_t head = 0;

			if (kgenome_emu_mem_rd(e, e->fs_base, &head, 4u))
				e->exc_seh_frame = head & 0xffffffffu;
			else
				e->exc_seh_frame = 0xffffffffu;
		} else {
			e->exc_seh_frame = 0xffffffffu;   /* table SEH: absent */
		}
	}

	/*
	 * THE CHAIN IS BOUNDED, because the guest writes it. A registration
	 * record whose `prev` points at itself is a loop that this walk would
	 * follow for as long as the instruction budget lasts, calling the same
	 * handler over and over and pushing a frame each time. Thirty-two is
	 * far past any real nesting and the limit is on the WALK rather than on
	 * the guest, so a legitimate deep chain is still followed to its end.
	 */
	if (e->exc_phase == 2u && e->exc_seh_depth++ > 32u)
		return 0;

	while (e->exc_phase == 2u && e->exc_seh_frame &&
	       e->exc_seh_frame != 0xffffffffull) {
		uint64_t h = 0;

		if (!kgenome_emu_mem_rd(e, e->exc_seh_frame + 4u, &h, 4u))
			break;
		h &= 0xffffffffu;
		if (!h)
			break;
		arg[0] = rec;
		arg[1] = e->exc_seh_frame;
		arg[2] = ctx;
		arg[3] = 0;
		return win_call(e, h, arg, 4u);
	}

	/*
	 * AND LAST, THE TOP LEVEL FILTER, which is what Windows calls when
	 * nothing else took the exception.
	 *
	 * SetUnhandledExceptionFilter stored one and nothing ever called it,
	 * which made that entry point a place to put a pointer rather than a
	 * way to receive an exception. A guest that installs one and no other
	 * handler - which is the ordinary shape for a program that wants to
	 * survive its own faults without wrapping every call - was getting the
	 * run ended at the fault.
	 *
	 * It takes EXCEPTION_POINTERS, like a vectored handler, and its
	 * returns are numbered differently: 1 is EXCEPTION_EXECUTE_HANDLER,
	 * which for a top level filter means the process is ending, and -1 is
	 * EXCEPTION_CONTINUE_EXECUTION. win_exc_return reads phase 3 on those
	 * terms.
	 */
	if (e->exc_phase == 2u && e->win_top_filter) {
		uint64_t ptrs = e->exc_base + EXC_PTR_OFF;

		e->exc_phase = 3u;
		if (e->bits == 32) {
			uint32_t a = (uint32_t)rec, b = (uint32_t)ctx;

			kgenome_emu_mem_wr(e, ptrs, &a, 4u);
			kgenome_emu_mem_wr(e, ptrs + 4u, &b, 4u);
		} else {
			kgenome_emu_mem_wr(e, ptrs, &rec, 8u);
			kgenome_emu_mem_wr(e, ptrs + 8u, &ctx, 8u);
		}
		arg[0] = ptrs;
		return win_call(e, e->win_top_filter, arg, 1u);
	}
	return 0;                       /* nothing left to try */
}

/*
 * A fault arrived. Build what Windows would have built and start dispatching,
 * or report that there is nobody to dispatch to.
 */
int kgenome_emu_win_exc_begin(struct kgenome_emu *e)
{
	uint64_t rec, ctx;
	uint32_t w32;
	uint64_t w64;
	int is_write = e->fault_kind[0] == 'w';
	uint32_t nparam;

	if (!e->win_k32_base)
		return 0;               /* not a Windows guest */
	if (e->exc_depth >= WIN_EXC_MAX_DEPTH)
		return 0;               /* a handler faulting inside a handler */
	if (!win_exc_ready(e))
		return 0;

	rec = e->exc_base + EXC_REC_OFF;
	ctx = e->exc_base + EXC_CTX_OFF;

	/*
	 * EXCEPTION_RECORD. The two parameters of an access violation are the
	 * kind of access and the address, in that order.
	 *
	 * THE CODE IS NOT ALWAYS AN ACCESS VIOLATION, and writing that one in
	 * regardless is how a raised exception went unhandled. A protector
	 * raises its own - measured, an MPRESS sample raises 0xc000008e,
	 * STATUS_FLOAT_DIVIDE_BY_ZERO, on purpose and its handler continues
	 * from there - and a handler that looks at ExceptionCode before
	 * deciding sees the wrong number and declines. exc_code carries what
	 * RaiseException was given; zero means this is a real fault.
	 */
	/* #DE (kgenome_emu_fault_de) is an integer exception with no parameters; every other fault
	 * is the access violation it always was. */
	if (e->exc_code)
		w32 = e->exc_code;
	else if (!strcmp(e->fault_kind, "divzero"))
		w32 = EXC_INT_DIVIDE_BY_ZERO;
	else if (!strcmp(e->fault_kind, "divovf"))
		w32 = EXC_INT_OVERFLOW;
	else if (!strcmp(e->fault_kind, "priv"))
		w32 = EXC_PRIVILEGED_INSTRUCTION;
	else
		w32 = EXC_ACCESS_VIOLATION;
	nparam = w32 == EXC_INT_DIVIDE_BY_ZERO || w32 == EXC_INT_OVERFLOW || w32 == EXC_PRIVILEGED_INSTRUCTION ? 0u : 2u;
	if (e->exc_code)
		nparam = e->exc_np;     /* what RaiseException was given, not a fault's pair */
	kgenome_emu_mem_wr(e, rec, &w32, 4u);
	w32 = e->exc_code ? e->exc_flags : 0u;  kgenome_emu_mem_wr(e, rec + 4u, &w32, 4u);
	if (e->bits == 32) {
		w32 = 0;                       kgenome_emu_mem_wr(e, rec + 8u, &w32, 4u);
		w32 = e->exc_code ? (uint32_t)kgenome_emu_win_addr_of(e, "RaiseException") : (uint32_t)e->rip;
		kgenome_emu_mem_wr(e, rec + 12u, &w32, 4u);
		w32 = nparam;                  kgenome_emu_mem_wr(e, rec + 16u, &w32, 4u);
		if (e->exc_code) {
			unsigned k;

			for (k = 0; k < nparam; k++) {
				w32 = (uint32_t)e->exc_info[k];
				kgenome_emu_mem_wr(e, rec + 20u + 4u * k, &w32, 4u);
			}
		} else {
			w32 = is_write ? 1u : 0u;      kgenome_emu_mem_wr(e, rec + 20u, &w32, 4u);
			w32 = (uint32_t)e->fault_va;   kgenome_emu_mem_wr(e, rec + 24u, &w32, 4u);
		}
	} else {
		w64 = 0;                       kgenome_emu_mem_wr(e, rec + 8u, &w64, 8u);
		/*
		 * A RAISED EXCEPTION IS AT THE FUNCTION THAT RAISED IT. RaiseException
		 * builds its record with ExceptionAddress set to its own address, not to
		 * the instruction after the call; a handler that places the exception by
		 * the function it came from (a protector's does) reads this to decide
		 * whether it is looking at one of its own.
		 */
		w64 = e->exc_code ? kgenome_emu_win_addr_of(e, "RaiseException") : e->rip;
		kgenome_emu_mem_wr(e, rec + 16u, &w64, 8u);
		w32 = nparam;                  kgenome_emu_mem_wr(e, rec + 24u, &w32, 4u);
		if (e->exc_code) {
			unsigned k;

			for (k = 0; k < nparam; k++)
				kgenome_emu_mem_wr(e, rec + 32u + 8u * k, &e->exc_info[k], 8u);
		} else {
			w64 = is_write ? 1u : 0u;      kgenome_emu_mem_wr(e, rec + 32u, &w64, 8u);
			w64 = e->fault_va;             kgenome_emu_mem_wr(e, rec + 40u, &w64, 8u);
		}
	}

	ctx_save(e, ctx);

	e->exc_phase = 1u;
	e->exc_veh_i = 0;
	e->exc_seh_depth = 0;
	e->exc_depth++;
	e->exc_raised++;
	if (win_exc_dispatch(e)) {
		/*
		 * CLEARED ONLY NOW, AND THAT ORDER IS THE POINT. The marks are
		 * what `unsupported:` reads to tell a fault from an
		 * instruction this build lacks, so clearing them before
		 * knowing whether a handler exists turned "faulted reading
		 * 0x3c" into "unsupported: MOV ax, word ptr [rsi]" - a true
		 * sentence about the wrong thing, and the exact opposite of
		 * what the stop reasons are for.
		 */
		e->fault_kind[0] = 0;
		return 1;
	}
	e->exc_phase = 0;
	e->exc_depth--;
	return 0;
}

/*
 * A handler returned to the magic address. Read its answer and either resume
 * the guest where the CONTEXT now says, or try the next handler.
 */
int kgenome_emu_win_exc_return(struct kgenome_emu *e)
{
	uint64_t ret = e->gpr[KGENOME_EMU_RAX] &
		       (e->bits == 32 ? 0xffffffffu : ~0ull);
	int resume = 0;

	if (e->exc_phase == 1u)
		resume = (uint32_t)ret == 0xffffffffu;  /* CONTINUE_EXECUTION */
	else if (e->exc_phase == 2u)
		resume = ret == 0;                      /* ContinueExecution */
	else if (e->exc_phase == 3u)
		resume = (uint32_t)ret == 0xffffffffu;  /* CONTINUE_EXECUTION */

	if (resume) {
		e->exc_taken++;
		ctx_load(e, e->exc_base + EXC_CTX_OFF);
		e->exc_phase = 0;
		if (e->exc_depth)
			e->exc_depth--;
		return 1;
	}
	if (e->exc_phase == 3u) {
		/* The top level filter is the last one there is. */
		e->exc_phase = 0;
		if (e->exc_depth)
			e->exc_depth--;
		return 0;
	}
	if (e->exc_phase == 2u) {
		uint64_t prev = 0;

		if (kgenome_emu_mem_rd(e, e->exc_seh_frame, &prev, 4u))
			e->exc_seh_frame = prev & 0xffffffffu;
		else
			e->exc_seh_frame = 0xffffffffu;
	}
	if (win_exc_dispatch(e))
		return 1;
	/* Nobody handled it. The run ends where the fault was, which is what
	 * would have happened without any of this. */
	e->exc_phase = 0;
	if (e->exc_depth)
		e->exc_depth--;
	return 0;
}

uint64_t kgenome_emu_exc_scratch(const struct kgenome_emu *e, uint64_t *len)
{
	if (len)
		*len = e && e->exc_base ? (uint64_t)WIN_EXC_PAGES * KGENOME_EMU_PAGE : 0;
	return e ? e->exc_base : 0;
}

/*
 * WHAT THE GUEST ASKED FOR, on request.
 *
 * The same argument as KGENOME_EMU_TRACE in objctx.c: a call that returns zero and
 * a call that was never made look identical from a stop reason, and the two
 * lead to completely different work. A guest faulting at NULL+0x3c has been
 * handed a zero module handle and has parsed it; which module it asked for is
 * the only thing that says what to add.
 */
void kgenome_emu_win_trace(struct kgenome_emu *e, const char *api, const char *arg,
		      uint64_t ret)
{
	(void)e;
	/* KOF_TRACING is a build constant (kofdebug.h): read it where it is used.
	 * It was cached in a function-local static, a writable global for a value
	 * that cannot change - one more thing a lib shared by many threads must not
	 * own (see the thread-safety note in kgenome.h). */
	if (KOF_TRACING)
		fprintf(stderr, "[win] %-24s %-32s -> %#llx\n", api,
			arg ? arg : "", (unsigned long long)ret);
}

/*
 * ---- WHAT THE GUEST CALLED ------------------------------------------------
 *
 * One record per distinct (call site, API), with a count - see
 * struct kgenome_emu_win_event for why and for what the fields are. Not capped:
 * the log grows with the number of places the program calls from, which is
 * bounded by its code, and a cap would be a place where a call that happened
 * went unrecorded.
 */
/* KNOWN DEFECT REV-D7h (2026-10-25, Inference) [sev L]: wev_hash / wev_insert (emu_win_exc.c) are a hand-rolled
 * open-addressing index of the guest API events with its own multiplier, which kof_hash64_slot (kofcore.h) already
 * spells. Trigger: a guest that calls many distinct (site, API) pairs. Effect: none measured; the multiplier and
 * the probe loop are written a second time. Reproducer: none. Fix: key it with kof_hash64_slot and the shared
 * oatab helper. */
static uint32_t wev_hash(uint64_t site, unsigned api)
{
	return (uint32_t)(((site ^ ((uint64_t)api << 56)) *
			   0x9e3779b97f4a7c15ull) >> 32);
}

static void wev_insert(struct kgenome_emu *e, uint32_t idx)
{
	const struct kgenome_emu_win_event *w = &e->wev[idx];
	uint32_t i = wev_hash(w->site, w->api) & e->wev_mask;

	while (e->wev_tab[i])
		i = (i + 1u) & e->wev_mask;
	e->wev_tab[i] = idx + 1u;
}

void kgenome_emu_win_event_note(struct kgenome_emu *e, unsigned api, uint64_t ret)
{
	struct kgenome_emu_win_event *w;
	uint32_t i;

	if (e->wev_tab) {
		for (i = wev_hash(e->last_call_at, api) & e->wev_mask;
		     e->wev_tab[i]; i = (i + 1u) & e->wev_mask) {
			w = &e->wev[e->wev_tab[i] - 1u];
			if (w->site == e->last_call_at && w->api == api) {
				if (w->count != 0xffffffffu)
					w->count++;
				w->ret = ret;
				return;
			}
		}
	}
	if (e->n_wev == e->cap_wev) {
		/* KNOWN DEFECT REV-D8l (2026-10-25, Inference) [sev L]: kgenome_emu_win_event_note (emu_win_exc.c) doubles a
		 * uint32 capacity (guest API events) with no overflow guard and no ledger charge. Trigger: an object with 2^31 or
		 * more elements of this kind (input over 2 GiB; the engine caps an object at 512 MiB, so only a host using the lib
		 * directly). Reproducer: none (read). Fix: use kof_tab_grow (kofcore/tabgrow.h, guards the doubling) or test cap
		 * against UINT32_MAX / 2 before doubling. */
		uint32_t nc = e->cap_wev ? e->cap_wev * 2u : 64u, k;
		struct kgenome_emu_win_event *nw = realloc(e->wev, (size_t)nc * sizeof *nw);
		uint32_t *nt;

		if (!nw) {
			KGENOME_EMU_REFUSED(e, KGENOME_EMU_HIT_MEM, "API event table not grown, a call is not recorded");
			return;
		}
		e->wev = nw;
		nt = calloc((size_t)nc * 2u, sizeof *nt);
		if (!nt) {
			KGENOME_EMU_REFUSED(e, KGENOME_EMU_HIT_MEM, "API event index not allocated, a call is not recorded");
			return;
		}
		free(e->wev_tab);
		e->wev_tab = nt;
		e->wev_mask = nc * 2u - 1u;
		e->cap_wev = nc;
		for (k = 0; k < e->n_wev; k++)
			wev_insert(e, k);
	}
	w = &e->wev[e->n_wev];
	memset(w, 0, sizeof *w);
	w->site = e->last_call_at;
	w->api = api;
	w->count = 1;
	for (i = 0; i < 4u; i++)
		w->arg[i] = kgenome_emu_win_arg(e, i);
	w->ret = ret;
	wev_insert(e, e->n_wev);
	e->n_wev++;
}

uint64_t kgenome_emu_last_branch_at(const struct kgenome_emu *e)
{
	return e ? e->last_branch_at : 0;
}

uint32_t kgenome_emu_win_event_count(const struct kgenome_emu *e)
{
	return e ? e->n_wev : 0;
}

int kgenome_emu_win_event_at(const struct kgenome_emu *e, uint32_t i,
			 struct kgenome_emu_win_event *out)
{
	if (!e || !out || i >= e->n_wev)
		return 0;
	*out = e->wev[i];
	return 1;
}

/* A handle for a socket the guest asked for. Values a program can hold and
 * compare, and that are never INVALID_SOCKET. */
uint64_t kgenome_emu_win_sock_new(struct kgenome_emu *e)
{
	uint64_t h;

	if (!e->win_sock_next)
		e->win_sock_next = 0x100u;
	h = e->win_sock_next;
	e->win_sock_next += 4u;
	return h;
}

int kgenome_emu_win_sock_first_read(struct kgenome_emu *e, uint64_t s)
{
	uint32_t i;

	for (i = 0; i < e->n_sock_seen; i++)
		if (e->sock_seen[i] == s)
			return 0;
	/* More than sixteen sockets read from: the rest are treated as already
	 * read, which only means they are not given the length prefix. */
	if (e->n_sock_seen >= 16u)
		return 0;
	e->sock_seen[e->n_sock_seen++] = s;
	return 1;
}
