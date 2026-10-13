/*
 * kofemu_int.h - what the interpreter's files share. NOT PART OF THE SURFACE.
 *
 * kofemu.h is what a caller reads. This is what the files that make up the
 * emulator read from each other: the structs the run state is built of, the
 * constants that bound a run, and the functions one file offers another. They
 * are in separate files for size and for meaning (memory, the Linux
 * environment, the Windows one, the x87 and vector instruction groups), and
 * the instruction dispatch stays in one file so the compiler can see all of
 * it. Private to libgenome/phenotype/.
 */
#ifndef KGENOME_EMU_INT_H
#define KGENOME_EMU_INT_H

#include <stdio.h>
#include <kofdebug.h>
#include <kofcore.h>   /* kof_ld_le16/32 */
#include <genotype/image/cmp.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>
#include <ctype.h>

#include "kofemu.h"
#include <x86/x86.h>


/*
 * A DECODED INSTRUCTION WITH ITS OPERANDS BUILT, which is what the interpreter
 * executes and what the instruction cache keeps. genotype builds operands on
 * request; the interpreter asks for all of them once, at decode, so that the
 * execute switch reads plain fields and a cached instruction costs nothing to
 * run again.
 */
struct kgenome_emu_insn {
	struct kgenome_x86_insn h;
	unsigned           n;               /* operands built, implicit ones included */
	struct kgenome_x86_op   op[KGENOME_X86_MAX_OPS];
};

#define KGENOME_EMU_DEF_MAX_INSN   (2u * 1000u * 1000u)
#define KGENOME_EMU_VSYSCALL_BASE  0xffffffffff600000ull
#define KGENOME_EMU_DEF_MAX_PAGES  KGENOME_EMU_DEF_PAGES  /* 64 MB of emulated space */

/* How many unresolved imports a run may call before the answers stop being
 * plausible - see the null page check in the loop. */
#define KGENOME_EMU_NULL_CALLS 256u

/* Instructions a candidate handover must go unchallenged - see oep_cand. */
#define KGENOME_EMU_OEP_QUIET (1ull << 20)

/*
 * HOW LARGE WHAT A CANDIDATE ENTERS HAS TO BE, in pages the guest wrote around
 * the target. Measured: every UPX / ASPack-class candidate on the corpus enters
 * 24 pages or more (24, 29, 62, 82, 171, 175, 202, 329, 496, 654, 660), and a
 * Themida loader makes over a hundred candidate transfers into runs of 1, 3
 * and 7 pages - its own stages - before the one that matters. Without this a
 * quiet window of a million instructions inside the loader read as "the
 * program" and stopped the run at 1.3 million instead of 22.6 million. The
 * cost is an image smaller than 64 KB, which is not recognised this way.
 */
#define KGENOME_EMU_OEP_MIN_PAGES 16u

/* Stores to new lines that may each postpone the stall verdict - see mem_wr.
 * A bound on COST, not on evidence: past it the stall test is the old one. */
#define KGENOME_EMU_IDLE_CREDIT_MAX (1u << 20)

/* How many exceptions a run may raise with nothing to catch them before it is
 * no longer unpacking - see KGENOME_EMU_WIN_RaiseException. */
#define KGENOME_EMU_UNHANDLED_MAX 64u

/* How far a write-then-execute snapshot reaches either way from the page that
 * fired it, in pages. A megabyte each side is past any one function. */
#define KGENOME_EMU_WEX_SPAN_PAGES 256u

/* ---- memory ---------------------------------------------------------------
 *
 * Sparse, because a packer maps a few megabytes inside a 47 bit address space
 * and a flat array of that is not a thing. Open addressing on the page number:
 * the table is sized from the page budget at construction so it never has to
 * grow while an emulation is in flight.
 */
#define KGENOME_EMU_ICACHE 2048u

struct kgenome_emu_page {
	uint64_t va;                  /* page aligned; 0 means the slot is free */
	uint8_t *data;
	unsigned prot;
	int      written;             /* the stub wrote here - this is the payload */
	/*
	 * AND WHETHER THE GUEST IS WHAT WROTE IT.
	 *
	 * `written` is set by every store, and the HOST makes some: it fills
	 * the IAT before the run so the guest's calls resolve, and import
	 * thunks routinely share a page with code. Those bytes really do
	 * differ from the file, so the region walk is right to take them -
	 * which is why this is a second flag and not a correction to the
	 * first.
	 *
	 * The hand-over test is the one that must not see them. It accepts a
	 * jump whose target is on a page the run WROTE, on the argument that
	 * the target is then code the stub produced rather than code it came
	 * with - and a page the host merely prepared carries the file's own
	 * code. Measured on a Sality body, whose IAT is at the very start of
	 * its only section: the test fired EIGHT INSTRUCTIONS IN, on the
	 * `push edi; ret` that ends the first stage, and the run stopped
	 * having decrypted nothing. With this, the same run goes 4,515,539
	 * instructions and hands a child back.
	 */
	int      gwritten;
	/*
	 * HOW FAR INTO THE PAGE A WRITE ACTUALLY REACHED, as one past the
	 * last byte stored. Zero while nothing has been written.
	 *
	 * `written` says the page is part of what the stub produced; it does
	 * not say how much of it is. A page is committed zero-filled, so a
	 * stub that decrypts 1,900 bytes into a fresh page still hands back
	 * 4,096 - and the 2,196 zeroes after the payload are not something
	 * the program made, they are the page it was given. Measured on
	 * samples/msfvenom-encr/poly: 4,096 bytes recovered of which about
	 * half is the page.
	 *
	 * ONLY THE HIGH WATER MARK. A low one would let the region start
	 * mid-page, which moves the address the region is reported at, and
	 * every reader of that address would have to learn the new rule. The
	 * tail is where the waste is.
	 */
	uint16_t wr_hi;
	int      snapped;             /* and it has since been executed and taken */
	/* `data` belongs to the emulator this one was forked from - see
	 * kgenome_emu_fork. Copied on the first store, never freed here. */
	int      shared;
};

/*
 * A half-open range a run is watching, and the two operations on a table of
 * them. The write watch and the exec watch are the same table with a different
 * question asked of it (a store into it, a fetch from it), so there is one
 * place that enforces the cap and the empty-range refusal and one place that
 * answers "is this address in one".
 */
struct kgenome_emu_wrange { uint64_t lo, hi; };

static inline void kgenome_emu_wrange_add(struct kgenome_emu_wrange *r, uint32_t *n, uint64_t lo, uint64_t hi)
{
	if (hi <= lo || *n >= KGENOME_EMU_EXEC_WATCH)
		return;
	r[*n].lo = lo;
	r[*n].hi = hi;
	(*n)++;
}

static inline int kgenome_emu_wrange_has(const struct kgenome_emu_wrange *r, uint32_t n, uint64_t va)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (va >= r[i].lo && va < r[i].hi)
			return 1;
	return 0;
}

struct kgenome_emu {
	struct kgenome_emu_page *tab;
	uint32_t     tab_mask;        /* size - 1; size is a power of two */
	uint32_t     n_pages, max_pages;

	/*
	 * THE LAST PAGE LOOKED UP, so a run of bytes in one page pays for one
	 * hash instead of one per byte. See page_lookup: an instruction fetch is
	 * sixteen bytes of the same page, and mem_rd/mem_wr resolve every byte
	 * on its own, so without this each fetch ran the mixing hash sixteen
	 * times. Safe to hold a raw pointer because a page, once created, is
	 * never moved or freed until the whole emulator is (the table is
	 * allocated once and open-addressing entries do not relocate); the one
	 * thing that could go stale is a NULL - an unmapped base that a later
	 * mmap fills - so only a non-NULL page is ever cached.
	 */
	uint64_t     cache_base;
	struct kgenome_emu_page *cache_page;

	uint64_t gpr[KGENOME_EMU_NGPR];
	uint64_t rip;
	uint64_t flags;               /* only the six that matter, see FL_* */

	uint64_t max_insn, insn;
	uint64_t idle;          /* KGENOME_EMU_IDLE unless set */
	uint64_t deadline_ms;   /* wall clock; 0 for none */
	uint64_t started_ms;
	int      stop_on_written_jump;
	/* Instruction patterns a module asked to be paused on - see
	 * kgenome_emu_watch_insn. `iw_len` is the whole instruction's length when
	 * the module pinned it, 0 when it did not. */
	struct { uint8_t b[KGENOME_EMU_INSN_WATCH_LEN]; uint8_t n; } iw[KGENOME_EMU_INSN_WATCH];
	uint32_t n_iw;
	unsigned iw_len;
	/* Whether guest code is what is executing - see `gwritten`. The host
	 * prepares the image before this is set and after it is cleared. */
	int      running;
	/* 32 or 64. See kgenome_emu_cfg.bits; everything it changes is marked with
	 * a reference back to this field. */
	unsigned bits;
	/* The address the last failed access asked for. A fault with no address
	 * is a fault nobody can act on. */
	uint64_t fault_va;
	char     fault_kind[8];

	/*
	 * ---- THE DECODED INSTRUCTION CACHE ---------------------------------
	 *
	 * WHY IT IS WORTH 245 KILOBYTES. Every instruction used to cost a
	 * sixteen-byte fetch - sixteen page lookups, one per byte - and a full
	 * NdDecodeEx, and a decryption loop runs the SAME twenty instructions
	 * millions of times. Measured on a Sality sample: 186 million
	 * instructions executed, and the loop that produced them fits in a
	 * cache line's worth of addresses.
	 *
	 * Direct mapped on the address, and an entry is good only while the
	 * PAGE it came from has not been written since - which is the whole
	 * difficulty, because the code a packer runs is code it just wrote.
	 * The page's `wgen` answers that in one comparison.
	 *
	 * AN INSTRUCTION THAT CROSSES A PAGE BOUNDARY IS NOT CACHED. Its bytes
	 * depend on two pages and this checks one; the case is rare and
	 * refusing it is cheaper than tracking both.
	 */
	struct icache_ent {
		uint64_t          va;
		const struct kgenome_emu_page *pg;
		/*
		 * THE BYTES IT WAS DECODED FROM, and comparing them is what
		 * makes the entry valid - not a generation counter on the page.
		 *
		 * A PAGE COUNTER WAS TRIED FIRST AND IS WRONG FOR THIS JOB. A
		 * decryption loop writes into the very page it runs from, so
		 * every store threw away the decoding of every instruction on
		 * it; measured, that capped the hit rate at 90.5% on a loop of
		 * 361 instructions that should never miss twice.
		 *
		 * Comparing the bytes is also EXACTLY right where a counter is
		 * only conservative: code that was overwritten with the same
		 * bytes decodes the same, and code that was not is caught
		 * whether or not anything else on the page moved.
		 */
		uint8_t           bytes[16];
		uint8_t           len;
		uint8_t           valid;
		/*
		 * DECIDED ONCE, AT DECODE, AND NEVER AGAIN - see nop_insn.
		 * An instruction that cannot change anything observable is
		 * stepped over without entering the execute switch at all.
		 */
		uint8_t           inert;
		struct kgenome_emu_insn   ix;
	}       *ic;

	/* A hot-address histogram, built only under KOF_EMU_HOT. It answers one
	 * question: is a run's time spent in a small loop, or spread out? */
	struct { uint64_t va; uint64_t n; } *hot;
	uint64_t ic_hit, ic_miss;
	uint32_t hot_mask;

	uint64_t trace[KGENOME_EMU_TRACE];
	/* The instruction trace - see kgenome_emu_itrace. NULL unless asked for. */
	struct itrace { uint64_t rip; uint64_t gpr[KGENOME_EMU_NGPR]; char txt[96]; }
		*itr;
	uint32_t itr_cap, itr_n;
	uint64_t itr_at;   /* freeze the ring here; 0 for never */
	uint64_t itr_until;
	int      itr_on_null;  /* freeze at the first unresolved import */
	int      itr_frozen;
	uint64_t trace_n;

	/*
	 * MAPPINGS THAT HAVE NOT COST ANYTHING YET.
	 *
	 * A Go runtime commits its heap in 64 MB pieces and touches a few
	 * kilobytes of each. Materialising those eagerly exhausted the page
	 * budget during start-up and the runtime quit with "out of memory"
	 * before running any of the packer's own code. A range recorded here
	 * becomes real one page at a time, when something actually reads or
	 * writes it - which is what the kernel does too.
	 */
	struct vma { uint64_t base, len, off; unsigned prot; int backed; } *vma;
	uint32_t n_vma, max_vma;

	/*
	 * What the RUN is allowed to cost the host, as against what the guest
	 * thinks it has. Every one of these is reachable from guest code doing
	 * something legal in a loop, so each is a ceiling rather than a
	 * guideline - a guest that hits one is told no and carries on.
	 */
	uint64_t snap_bytes;

	/* Where the next hintless mmap lands. Its OWN cursor: deriving it from
	 * the page count made two mappings overlap whenever anything else added
	 * a page between them, which is a corruption the stub then executes. */
	uint64_t mmap_next;

	uint32_t unksys[KGENOME_EMU_UNKSYS];
	uint32_t n_unksys;
	struct kgenome_emu_syscall syslog[KGENOME_EMU_SYSLOG];
	uint32_t n_syslog;

	/*
	 * SSE, BECAUSE A GO RUNTIME CANNOT START WITHOUT IT.
	 *
	 * Not vector arithmetic - the moves, the bitwise ops and the byte
	 * compare that memmove, memset and the string routines are built from.
	 * That is what a packer's runtime executes before it ever reaches its
	 * own unpacking code.
	 */
	uint8_t xmm[16][16];
	/*
	 * THE MMX REGISTERS, AND THEY ARE HERE BECAUSE A VIRUS HIDES IN THEM.
	 *
	 * Nothing that unpacks a payload needs MMX arithmetic, and this does
	 * not have any. What it has is the eight registers, because they are
	 * used as a PLACE TO PUT SOMETHING an emulator will not follow:
	 * Sality's decryptor begins
	 *
	 *     call $+5 ; pop ebp      the address of itself
	 *     movd mm2, ebp           put it somewhere unusual
	 *     movd edi, mm2           take it back
	 *     add edi, 0x20c ; push edi ; ret
	 *
	 * and an interpreter without these registers either stops at the movd
	 * or reads back a zero and returns into nothing. Measured: the run
	 * ended after THREE instructions, "MOVD mm2, ebp", on every Sality
	 * sample here.
	 *
	 * SEPARATE FROM THE x87 STACK, which is a simplification and not the
	 * hardware: on a real CPU mm0-mm7 ARE st(0)-st(7)'s mantissas, and
	 * writing one is visible in the other. A program that deliberately
	 * interleaved the two would see them as independent here. Nothing that
	 * hides an address in an MMX register does that - the point of the
	 * trick is that the value comes back unchanged - and modelling the
	 * alias would mean modelling the x87 tag word for no reader's benefit.
	 */
	uint8_t mmx[8][8];

	/*
	 * ---- THE x87 REGISTER STACK, AND WHY IT IS HERE AT ALL -------------
	 *
	 * It used to not be. x87 was carried only far enough to answer "where
	 * am I" - FNSTENV reports the address of the last x87 instruction, and
	 * every Metasploit x86 encoder uses that to find itself - so the
	 * instructions a GetPC sequence picks from were executed as no-ops that
	 * set `fpu_rip`, and everything that COMPUTES was deliberately left to
	 * the unsupported path. The argument was sound: an object that really
	 * divides would otherwise run on with a wrong st0 and never say so.
	 *
	 * WHAT CHANGED IS THAT SOMETHING REALLY DIVIDED. A Sality sample
	 * reaches `FDIV st0, dword ptr [edx]` seven million instructions in and
	 * the run ends there. Polymorphic bodies use the FPU as filler, and
	 * filler is still executed. So the choice is between stopping on it and
	 * computing it, and computing it correctly is not a large thing.
	 *
	 * EIGHT DOUBLES AND A TOP POINTER. The hardware's registers are 80-bit
	 * extended, and these are 64-bit doubles: eleven bits of mantissa and
	 * some exponent range are lost. That is a real difference and it is the
	 * right trade here - a guest whose control flow depends on the 64th
	 * mantissa bit of an intermediate is not a thing that has been
	 * measured, and modelling extended precision in software would cost far
	 * more than every x87 instruction this has ever met.
	 *
	 * The memory formats ARE exact: m32, m64 and m80 are read and written
	 * at their true widths, so a value stored and reloaded round-trips
	 * through whatever the guest chose - it is only the register that is
	 * narrower.
	 *
	 * ST(i) IS st[(top + i) & 7]. the decoder reports an x87 operand's `Reg`
	 * as that relative index already, so a case here never computes it.
	 */
	double   st[8];
	uint8_t  st_tag[8];     /* 0 empty, 1 valid */
	uint8_t  st_top;
	/*
	 * The status word's condition codes. C0, C2 and C3 are what a compare
	 * leaves and what FNSTSW hands to a guest that branches on it; C1 is
	 * the stack-fault direction and nothing here reads it.
	 */
	uint16_t fsw;

	/* The thread pointer, as arch_prctl set it - or, for a Windows guest,
	 * as emu_unpack.c's thread block builder set it. */
	uint64_t fs_base, gs_base;
	int      iw_skip;       /* suppress the instruction watch once */

	/*
	 * The Windows environment's three addresses and its error word. Zero
	 * on a Linux guest, and every entry point below checks them, so an ELF
	 * run cannot reach any of it.
	 */
	/* Regions where ENTERING means the loader has handed over. */
	struct kgenome_emu_wrange xwatch[KGENOME_EMU_EXEC_WATCH];
	uint32_t n_xwatch;
	/*
	 * Whether the last instruction fetched was already inside one of them.
	 *
	 * A handover is a jump INTO the program, so what ends the run is the
	 * EDGE and not the address: a run that begins inside a watched range,
	 * or that is still running through one, has not handed anything over.
	 * See kgenome_emu_watch_exec.
	 */
	int xw_was_in, xw_have_prev;
	/* Ranges whose first WRITE means the loader is decrypting the program
	 * - see kgenome_emu_watch_write. */
	struct kgenome_emu_wrange wwatch[KGENOME_EMU_EXEC_WATCH];
	uint32_t n_wwatch;
	int      wwatch_hit;
	uint64_t stub_lo, stub_hi;
	uint64_t img_lo, img_hi;   /* the image, for the dump at the handover */
	uint64_t sp0;              /* RSP as the run started - see the OEP test */
	int      sp0_set;
	int      oep_watch;        /* the handover test above is armed */
	int      oep_cand;         /* a transfer from file code into written code, waiting out KGENOME_EMU_OEP_QUIET */
	uint64_t oep_cand_insn, oep_cand_rip;
	int      img_dumped;
	uint64_t stack_lo, stack_hi;
	struct { uint64_t lo, hi; uint8_t seen; } hop[KGENOME_EMU_EXEC_WATCH];
	uint32_t n_hop;
	/*
	 * THE SPAN OF THE HOPS NOT YET ENTERED, so the per-instruction test is one
	 * range compare and not a walk of the table. MEASURED on a 5.5 MB PE with
	 * twenty-odd images: the walk was 21% of every instruction the interpreter
	 * ran, to answer "is rip in a region nothing has run in" - which is false
	 * for nearly all of them. hop_unseen is how many remain; the bounds are
	 * meaningful only while it is non-zero.
	 */
	uint32_t hop_unseen;
	uint64_t hop_lo, hop_hi;
	uint64_t hop_first_insn, hop_first_rip;
	uint64_t fetch_page;   /* never a page base until one is set */
	uint32_t null_calls;   /* imports this environment did not have */
	uint32_t win_miss;     /* names answered with a miss thunk - see kgenome_emu_win_resolve */
	struct { uint32_t id; uint64_t ret; } shim[KGENOME_EMU_SHIM_MAX]; /* see kgenome_emu_shim_api */
	uint32_t n_shim;
	char     win_fake[16][32]; /* libraries handed a handle with no image - see win_fake_lib */
	uint32_t n_win_fake;
	uint64_t cmdline[2];   /* [0] ANSI, [1] UTF-16; 0 until asked for */
	uint64_t hop_last_rip;
	uint32_t hop_count;

	uint64_t win_image_base, win_k32_base, win_heap;
	/* The CALL instruction that most recently ran: the site of the API call a
	 * stub is about to answer. */
	uint64_t last_call_at;
	/* The instruction that last TRANSFERRED control (jmp, call, ret, a taken
	 * jcc): where a run that ends by jumping somewhere left from. */
	uint64_t last_branch_at;
	/* What the guest called - see struct kgenome_emu_win_event. An open-addressed
	 * table of 1-based indices over the log, sized to twice its capacity. */
	struct kgenome_emu_win_event *wev;
	uint32_t n_wev, cap_wev, *wev_tab, wev_mask;
	/* The scripted peer's sockets: the next handle, and the handles that have
	 * already been read from once. */
	uint32_t win_sock_next, n_sock_seen;
	uint64_t sock_seen[16];
	uint64_t mod_reads[KGENOME_EMU_WIN_MOD_COUNT];
	uint8_t  count_mod_reads;
	uint64_t win_mod_base[KGENOME_EMU_WIN_MOD_COUNT];
	uint64_t mmap32_next, winmap_next;
	uint32_t win_last_error;

	/*
	 * EXCEPTION DISPATCH, which is a state machine because a handler is
	 * GUEST code: it has to be called, run to its own `ret`, and answered
	 * - and the only thing that runs guest code is the loop this lives in.
	 * So a fault sets this up, the loop notices the handler returning to an
	 * address nothing maps, and the answer is read there.
	 */
	uint64_t win_veh[8];
	uint32_t n_veh;
	uint32_t exc_phase;        /* 0 idle, 1 VEH, 2 an SEH frame, 3 the
				    * top level filter */
	uint32_t exc_veh_i;        /* which vectored handler is running */
	uint32_t exc_depth;        /* a handler that faults, and its handler */
	uint64_t exc_seh_frame;    /* the registration record being tried */
	uint32_t exc_seh_depth;    /* how far down the chain this walk has gone */
	uint64_t exc_base;         /* the scratch region, mapped on first use */
	uint64_t idle_max;     /* the longest the run went without a new page */
	uint32_t null_reads;   /* fields read off a null pointer */
	uint32_t exc_unhandled; /* raises nobody took, and we carried on */
	uint32_t exc_code;     /* what to put in the record; 0 = a fault */
	uint64_t exc_rip;      /* the guest address to blame; 0 = e->rip */
	uint32_t exc_raised, exc_taken;   /* faults offered, and faults handled */
	uint64_t win_tls[64];
	uint32_t win_tls_next;
	uint64_t win_top_filter;

	/*
	 * THE CLOCK, WHICH IS AN ANTI-EMULATION SURFACE AND NOT A CONVENIENCE.
	 *
	 * It advances with instructions retired rather than with real time, so a
	 * run is reproducible and so the RATIO a stub measures stays plausible:
	 * code that does more work reads a larger delta, which is the only thing
	 * a timing check is really looking at. Real time would make the same
	 * scan answer differently twice, and a frozen clock announces the
	 * emulator to anything that reads it twice.
	 *
	 * `tsc_skew` is time that passed without instructions - a sleep granted
	 * in full without waiting for it.
	 */
	uint64_t tsc_skew;

	/*
	 * How a delay loop ends.
	 *
	 * A stub that spins on the clock until N ticks have gone by would
	 * otherwise run until the budget is gone, having done nothing. Reading
	 * the clock twice in quick succession with no work between is what that
	 * loop looks like from here and looks like nothing else - ordinary code
	 * does not ask the time in a tight loop - so the wait is granted in
	 * jumps that grow until the loop's own condition is met. Nothing else
	 * accelerates: a check that times a piece of REAL work sees the honest
	 * per-instruction rate.
	 */
	uint64_t tsc_last_insn;
	uint32_t tsc_spin;
	/*
	 * A COUNTED DELAY LOOP IS ACCOUNTED BY ITERATIONS, NOT RUN - see
	 * kofemu_loop.c. `dl_at` is the backward branch taken last and `dl_n` how
	 * many times in a row it was; `ff_insn` is the instructions the loops that
	 * were skipped would have executed. They are NOT in `insn`: the budget is a
	 * bound on work done, and the stall test reads `insn`, so a skipped wait
	 * neither spends the one nor trips the other. The guest's clock does see
	 * them (kgenome_emu_tsc_read), so a timing check around a delay reads the
	 * time the loop would have taken.
	 */
	uint64_t dl_at;
	uint32_t dl_n;
	uint64_t ff_insn;
	/*
	 * WHAT THE RUN HAD PRODUCED at the previous clock read.
	 *
	 * The instruction gap alone was the wrong test and a measured one: a
	 * loop with sixty nops in its body between the two reads walked past
	 * it, because sixty is more than the window and nops are free to
	 * write. Measured on this build - pad 0, 16 and 32 escaped in 77, 365
	 * and 653 instructions; pad 60 and up burnt 4 194 305 and ended
	 * STALLED, which is not a hang but IS the run being killed at the
	 * delay loop with the payload still packed.
	 *
	 * Junk is junk because it PRODUCES nothing, so that is what to ask
	 * about. last_new_page already records the run's unit of progress for
	 * KGENOME_EMU_IDLE; this remembers where it stood last time the guest
	 * asked the time, and a read with no new page since the last one is a
	 * wait however many instructions were spent looking busy.
	 */
	uint64_t tsc_last_page;

	/* Thread ids handed to clone, none of which ever run. */
	uint64_t next_tid;

	/* The address of the last futex wait, and how many in a row. */
	uint64_t futex_va;
	uint32_t futex_spin;

	/* How many reads of standard input have been answered end-of-file in a
	 * row. See EMU_SYS_READ: a prompt that ignores EOF asks forever. */
	uint32_t stdin_eof;

	/* The address of the last x87 instruction that was not a control one.
	 * FNSTENV reports it, and that report is the only reason x87 is here at
	 * all - see the note on the FPU cases in the run loop. */
	uint64_t fpu_rip;

	/* When a page was last written to for the first time - the clock the
	 * idle test below runs on. */
	uint64_t last_new_page;
	uint64_t last_wr_line;     /* the cache line of the last store that earned an idle credit */
	uint32_t idle_credit;      /* credits earned since the last new page - see mem_wr */

	/*
	 * ---- IS THE GUEST DECRYPTING RIGHT NOW --------------------------
	 *
	 * WHY A MEMORY PATTERN AND NOT AN OPCODE. A polymorphic generator
	 * chooses the instructions, the registers and the encoding of its
	 * decryption loop, and re-chooses all three for every copy - so
	 * nothing about HOW it is written survives. What does not change is
	 * what it must DO: read a byte of ciphertext, write the plaintext
	 * back, and move on to the next address. That trace is the work
	 * itself, and no re-encoding can avoid producing it.
	 *
	 * So an "active instruction" here is a READ of an address followed by
	 * a WRITE to that same address, where the previous such pair was at a
	 * NEARBY address - the loop stepping through a buffer. Junk between
	 * them costs nothing: the pair is recognised whenever it happens, not
	 * at a fixed distance.
	 *
	 * WHAT IT IS FOR is knowing when to stop. A run that has not seen one
	 * of these for a while is a run whose decryption has finished, and
	 * everything after that is the payload doing its own work - which this
	 * exists to recover, not to watch. Measured: the interpreter otherwise
	 * has only a page-granularity idle test, which is far coarser.
	 */
	/*
	 * A RING AND NOT ONE ADDRESS. The read and the write that make a pair
	 * are two separate instructions and a generator puts junk between
	 * them - junk that reads memory of its own. Keeping only the last read
	 * address let one junk load erase the pair, and measured, that made
	 * the run stop 272,939 instructions in with the body barely started.
	 */
#define KGENOME_EMU_RDRING 8u
	uint64_t last_read[KGENOME_EMU_RDRING];
	unsigned last_read_n;
	uint64_t pair_va;       /* where the last read-then-write pair was */
	uint64_t active_n;      /* how many active instructions were seen */
	uint64_t since_active;  /* instructions since the last one */
	unsigned in_fetch;      /* reads made to FETCH are not data reads */
	unsigned quiet_on;      /* KGENOME_EMU_QUIET armed - see the run loop */
	unsigned softread;      /* KOF_EMU_SOFTREAD - see mem_rd */
	unsigned softwrite;     /* KOF_EMU_SOFTWRITE - see mem_wr */
	uint64_t soft_reads, soft_writes;
	uint64_t gap_max;
	uint64_t m_empty, m_va, m_pg, m_bytes;

	/*
	 * The SSE control word, remembered and otherwise ignored: scalar
	 * arithmetic here runs on the host's own double, so a rounding mode
	 * stored in it would change nothing. Kept so a caller that saves it and
	 * restores it reads back what it wrote, which is all any of them check.
	 */
	uint32_t mxcsr;

	/* The opening bytes of whatever the guest wrote to stdout or stderr. */
	char     say[KGENOME_EMU_SAY];
	uint32_t n_say;

	/* The one open file an emulated process has: itself. */
	const uint8_t *self;
	uint64_t       self_n, self_pos;

	/* Payload images caught at the mprotect that made them executable. */
	struct snap { uint64_t va, len; uint8_t *bytes; } *snap;
	uint32_t n_snap, max_snap;

	uint64_t watch_va;
	int      watch_on;
	uint64_t watch_rip[KGENOME_EMU_WATCH_MAX], watch_val[KGENOME_EMU_WATCH_MAX];
	unsigned watch_n;
	enum kgenome_emu_stop stop;
	/* 112: the longest message (the quiet stop, two 64-bit counts and its words)
	 * is 102 bytes with the NUL; at 96 it could be cut, and the compiler said so. */
	char     detail[112];

	/* Sorted page list, built on demand by kgenome_emu_next_written, and the
	 * one run handed out at a time - freed when the next is asked for, so a
	 * caller never has to. */
	uint64_t *sorted;
	uint32_t  n_sorted;
	uint8_t  *run_buf;
};

#define KGENOME_EMU_FL_CF  (1u << 0)
#define KGENOME_EMU_FL_PF  (1u << 2)
#define KGENOME_EMU_FL_AF  (1u << 4)
#define KGENOME_EMU_FL_ZF  (1u << 6)
#define KGENOME_EMU_FL_SF  (1u << 7)
#define KGENOME_EMU_FL_DF  (1u << 10)
#define KGENOME_EMU_FL_OF  (1u << 11)

/* ---- the Windows API ids, shared by the table and the dispatch ---- */

#define KGENOME_EMU_WIN_API_BASE   0x57494e00u      /* 'W','I','N',0 */

enum {
	KGENOME_EMU_WIN_GetModuleHandleA = 0,
	KGENOME_EMU_WIN_GetModuleHandleW,
	KGENOME_EMU_WIN_GetProcAddress,
	KGENOME_EMU_WIN_LoadLibraryA,
	KGENOME_EMU_WIN_LoadLibraryW,
	KGENOME_EMU_WIN_VirtualAlloc,
	KGENOME_EMU_WIN_VirtualFree,
	KGENOME_EMU_WIN_VirtualProtect,
	KGENOME_EMU_WIN_ExitProcess,
	KGENOME_EMU_WIN_GetCurrentProcess,
	KGENOME_EMU_WIN_IsDebuggerPresent,
	KGENOME_EMU_WIN_GetLastError,
	KGENOME_EMU_WIN_SetLastError,
	KGENOME_EMU_WIN_GetVersion,
	KGENOME_EMU_WIN_GetCurrentProcessId,
	KGENOME_EMU_WIN_GetTickCount,
	KGENOME_EMU_WIN_AddVectoredExceptionHandler,
	KGENOME_EMU_WIN_RemoveVectoredExceptionHandler,
	KGENOME_EMU_WIN_GetProcessHeap,
	KGENOME_EMU_WIN_HeapAlloc,
	KGENOME_EMU_WIN_HeapFree,
	KGENOME_EMU_WIN_HeapReAlloc,
	KGENOME_EMU_WIN_HeapSize,
	KGENOME_EMU_WIN_VirtualQuery,
	KGENOME_EMU_WIN_GetSystemInfo,
	KGENOME_EMU_WIN_Sleep,
	KGENOME_EMU_WIN_QueryPerformanceCounter,
	KGENOME_EMU_WIN_QueryPerformanceFrequency,
	KGENOME_EMU_WIN_GetSystemTimeAsFileTime,
	KGENOME_EMU_WIN_GetCurrentThreadId,
	KGENOME_EMU_WIN_GetCurrentThread,
	KGENOME_EMU_WIN_TlsAlloc,
	KGENOME_EMU_WIN_TlsGetValue,
	KGENOME_EMU_WIN_TlsSetValue,
	KGENOME_EMU_WIN_TlsFree,
	KGENOME_EMU_WIN_InitializeCriticalSection,
	KGENOME_EMU_WIN_EnterCriticalSection,
	KGENOME_EMU_WIN_LeaveCriticalSection,
	KGENOME_EMU_WIN_DeleteCriticalSection,
	KGENOME_EMU_WIN_FlushInstructionCache,
	KGENOME_EMU_WIN_GetStdHandle,
	KGENOME_EMU_WIN_CloseHandle,
	KGENOME_EMU_WIN_SetUnhandledExceptionFilter,
	KGENOME_EMU_WIN_GetModuleFileNameA,
	KGENOME_EMU_WIN_GetModuleFileNameW,
	KGENOME_EMU_WIN_GetCommandLineA,
	KGENOME_EMU_WIN_GetCommandLineW,
	KGENOME_EMU_WIN_lstrlenA,
	KGENOME_EMU_WIN_RtlAddFunctionTable,
	KGENOME_EMU_WIN_RtlAllocateHeap,
	KGENOME_EMU_WIN_RtlFreeHeap,
	KGENOME_EMU_WIN_NtQueryInformationProcess,
	KGENOME_EMU_WIN_FreeLibrary,
	KGENOME_EMU_WIN_LocalAlloc,
	KGENOME_EMU_WIN_LocalFree,
	KGENOME_EMU_WIN_GlobalAlloc,
	KGENOME_EMU_WIN_GlobalFree,
	KGENOME_EMU_WIN_lstrcmpA,
	KGENOME_EMU_WIN_lstrcmpiA,
	KGENOME_EMU_WIN_lstrcpyA,
	KGENOME_EMU_WIN_lstrcatA,
	KGENOME_EMU_WIN_lstrlenW,
	KGENOME_EMU_WIN_MultiByteToWideChar,
	KGENOME_EMU_WIN_WideCharToMultiByte,
	KGENOME_EMU_WIN_OutputDebugStringA,
	KGENOME_EMU_WIN_SetErrorMode,
	KGENOME_EMU_WIN_GetStartupInfoA,
	KGENOME_EMU_WIN_GetStartupInfoW,
	KGENOME_EMU_WIN_GetSystemDirectoryA,
	KGENOME_EMU_WIN_GetWindowsDirectoryA,
	KGENOME_EMU_WIN_GetTempPathA,
	KGENOME_EMU_WIN_GetFileAttributesA,
	KGENOME_EMU_WIN_CreateFileA,
	KGENOME_EMU_WIN_ReadFile,
	KGENOME_EMU_WIN_WriteFile,
	KGENOME_EMU_WIN_SetFilePointer,
	KGENOME_EMU_WIN_GetFileSize,
	KGENOME_EMU_WIN_CreateThread,
	KGENOME_EMU_WIN_ResumeThread,
	KGENOME_EMU_WIN_WaitForSingleObject,
	KGENOME_EMU_WIN_TerminateProcess,
	KGENOME_EMU_WIN_RaiseException,
	KGENOME_EMU_WIN_UnhandledExceptionFilter,
	KGENOME_EMU_WIN_InterlockedIncrement,
	KGENOME_EMU_WIN_InterlockedDecrement,
	KGENOME_EMU_WIN_NtProtectVirtualMemory,
	KGENOME_EMU_WIN_NtAllocateVirtualMemory,
	KGENOME_EMU_WIN_RtlGetVersion,
	KGENOME_EMU_WIN_LdrLoadDll,
	KGENOME_EMU_WIN_LdrGetProcedureAddress,
	KGENOME_EMU_WIN_InitializeCriticalSectionAndSpinCount,
	KGENOME_EMU_WIN_IsProcessorFeaturePresent,
	KGENOME_EMU_WIN_IsValidCodePage,
	KGENOME_EMU_WIN_IsBadReadPtr,
	KGENOME_EMU_WIN_IsBadWritePtr,
	KGENOME_EMU_WIN_InterlockedExchange,
	KGENOME_EMU_WIN_InterlockedCompareExchange,
	KGENOME_EMU_WIN_SetHandleCount,
	KGENOME_EMU_WIN_SetStdHandle,
	KGENOME_EMU_WIN_SetEnvironmentVariableA,
	KGENOME_EMU_WIN_SetEnvironmentVariableW,
	KGENOME_EMU_WIN_SetConsoleCtrlHandler,
	KGENOME_EMU_WIN_FreeEnvironmentStringsA,
	KGENOME_EMU_WIN_FreeEnvironmentStringsW,
	KGENOME_EMU_WIN_FlushFileBuffers,
	KGENOME_EMU_WIN_FindClose,
	KGENOME_EMU_WIN_DecodePointer,
	KGENOME_EMU_WIN_EncodePointer,
	KGENOME_EMU_WIN_DeleteFileA,
	KGENOME_EMU_WIN_DisableThreadLibraryCalls,
	KGENOME_EMU_WIN_HeapCreate,
	KGENOME_EMU_WIN_HeapDestroy,
	KGENOME_EMU_WIN_GetCPInfo,
	KGENOME_EMU_WIN_GetACP,
	KGENOME_EMU_WIN_GetOEMCP,
	KGENOME_EMU_WIN_IsUserAnAdmin,
	KGENOME_EMU_WIN_SHGetFolderPathA,
	KGENOME_EMU_WIN_CoInitialize,
	KGENOME_EMU_WIN_CoUninitialize,
	/* ws2_32. The environment is a SCRIPTED PEER - see winapi_do. */
	KGENOME_EMU_WIN_WSAStartup,
	KGENOME_EMU_WIN_WSACleanup,
	KGENOME_EMU_WIN_WSASocketA,
	KGENOME_EMU_WIN_WSASocketW,
	KGENOME_EMU_WIN_socket,
	KGENOME_EMU_WIN_connect,
	KGENOME_EMU_WIN_recv,
	KGENOME_EMU_WIN_send,
	KGENOME_EMU_WIN_sendto,
	KGENOME_EMU_WIN_recvfrom,
	KGENOME_EMU_WIN_closesocket,
	KGENOME_EMU_WIN_bind,
	KGENOME_EMU_WIN_listen,
	KGENOME_EMU_WIN_accept,
	KGENOME_EMU_WIN_shutdown,
	KGENOME_EMU_WIN_setsockopt,
	KGENOME_EMU_WIN_ioctlsocket,
	/*
	 * THE COUNT COMES FROM THE ENUM AND THE ENUM IS CHECKED AGAINST THE
	 * TABLE, because writing it by hand is how this broke.
	 *
	 * KGENOME_EMU_WIN_API_COUNT was a literal, the table grew by 34 entries and the
	 * literal was set to 53 for 52 of them, and the one-past read crashed
	 * the scanner in win_eq_nocase against a name pointer that was never
	 * written. The header already says of the table that "a table in each
	 * place is a table that disagrees after the first edit"; a hand
	 * written length is the same mistake one step smaller.
	 */
	KGENOME_EMU_WIN_API__LAST
};

#define KGENOME_EMU_WIN_API_COUNT ((unsigned)KGENOME_EMU_WIN_API__LAST)

/* The x87 status word's condition codes. */
#define KGENOME_EMU_FSW_C0 (1u << 8)
#define KGENOME_EMU_FSW_C1 (1u << 9)
#define KGENOME_EMU_FSW_C2 (1u << 10)
#define KGENOME_EMU_FSW_C3 (1u << 14)

/* ---- what one file offers another ---- */

int kgenome_emu_page_own(struct kgenome_emu_page *p);
struct kgenome_emu_page *kgenome_emu_page_find(struct kgenome_emu *e, uint64_t va);
struct kgenome_emu_page *kgenome_emu_page_add(struct kgenome_emu *e, uint64_t base, unsigned prot);
struct kgenome_emu_page *kgenome_emu_page_add_zero(struct kgenome_emu *e, uint64_t base, 				  unsigned prot);
int kgenome_emu_vma_add(struct kgenome_emu *e, uint64_t base, uint64_t len, 		   uint64_t off, unsigned prot, int backed);
int kgenome_emu_mem_rd(struct kgenome_emu *e, uint64_t va, void *dst, unsigned n);

/* A backward branch (at, `at_len` long) to `top` was taken for the Nth time running:
 * skip the rest of the loop when it is a counted delay. See kofemu_loop.c. */
#define KGENOME_EMU_DELAY_PROBE 16u
void kgenome_emu_delay_note(struct kgenome_emu *e, uint64_t top, uint64_t at, unsigned at_len);
int kgenome_emu_mem_wr(struct kgenome_emu *e, uint64_t va, const void *src, unsigned n);
uint64_t kgenome_emu_now_ms(void);
void kgenome_emu_hop_bounds(struct kgenome_emu *e);
void kgenome_emu_snap_take(struct kgenome_emu *e, uint64_t va, uint64_t len);
unsigned kgenome_emu_written_run_pages(struct kgenome_emu *e, uint64_t va, unsigned cap);
uint64_t kgenome_emu_tsc_read(struct kgenome_emu *e);
uint64_t kgenome_emu_do_syscall(struct kgenome_emu *e, int *stop_out);
uint64_t kgenome_emu_win_miss_thunk(struct kgenome_emu *e);
uint64_t kgenome_emu_win_fake_lib(struct kgenome_emu *e, const char *name);
int kgenome_emu_win_is_fake(const struct kgenome_emu *e, uint64_t h);
uint64_t kgenome_emu_win_mod_of(struct kgenome_emu *e, const char *name);
uint64_t kgenome_emu_win_arg(struct kgenome_emu *e, unsigned i);
void kgenome_emu_win_str(struct kgenome_emu *e, uint64_t va, char *out, unsigned cap, 		    int wide);
uint64_t kgenome_emu_win_alloc(struct kgenome_emu *e, uint64_t want, unsigned prot);
uint64_t kgenome_emu_win_alloc32(struct kgenome_emu *e, uint64_t want, unsigned prot);
unsigned kgenome_emu_win_prot(uint64_t p);
uint64_t kgenome_emu_win_ret_magic(const struct kgenome_emu *e);
int kgenome_emu_win_exc_begin(struct kgenome_emu *e);
int kgenome_emu_win_exc_return(struct kgenome_emu *e);
void kgenome_emu_win_trace(struct kgenome_emu *e, const char *api, const char *arg, 		      uint64_t ret);
void kgenome_emu_win_event_note(struct kgenome_emu *e, unsigned api, uint64_t ret);
uint64_t kgenome_emu_win_sock_new(struct kgenome_emu *e);
int kgenome_emu_win_sock_first_read(struct kgenome_emu *e, uint64_t s);
uint64_t kgenome_emu_winapi_do(struct kgenome_emu *e, unsigned id, int *stop_out);
uint64_t kgenome_emu_mask_of(unsigned bytes);
uint64_t kgenome_emu_sext(uint64_t v, unsigned bytes);
uint64_t kgenome_emu_reg_rd(const struct kgenome_emu *e, unsigned r, unsigned bytes, 		       int high8);
void kgenome_emu_reg_wr(struct kgenome_emu *e, unsigned r, unsigned bytes, int high8, 		   uint64_t v);
uint16_t kgenome_emu_host_dshift16(uint16_t dst, uint16_t src, uint8_t cnt, 			      int left, uint64_t *fl);
void kgenome_emu_fl_logic(struct kgenome_emu *e, uint64_t r, unsigned bytes);
void kgenome_emu_fl_add(struct kgenome_emu *e, uint64_t a, uint64_t b, uint64_t cin, 		   unsigned bytes);
void kgenome_emu_fl_sub(struct kgenome_emu *e, uint64_t a, uint64_t b, uint64_t bin, 		   unsigned bytes);
int kgenome_emu_ea_of(struct kgenome_emu *e, const struct kgenome_emu_insn *ix, const struct kgenome_x86_op *op, 		 uint64_t *out);
int kgenome_emu_op_rd(struct kgenome_emu *e, const struct kgenome_emu_insn *ix, const struct kgenome_x86_op *op, 		 uint64_t *out);
int kgenome_emu_vec_rd(struct kgenome_emu *e, const struct kgenome_emu_insn *ix, const struct kgenome_x86_op *op, 		  uint8_t *buf, unsigned *sz);
int kgenome_emu_vec_wr(struct kgenome_emu *e, const struct kgenome_emu_insn *ix, const struct kgenome_x86_op *op, 		  const uint8_t *buf, unsigned sz);
int kgenome_emu_op_wr(struct kgenome_emu *e, const struct kgenome_emu_insn *ix, const struct kgenome_x86_op *op, 		 uint64_t v);
int kgenome_emu_push(struct kgenome_emu *e, uint64_t v);
int kgenome_emu_pop(struct kgenome_emu *e, uint64_t *v);

/*
 * The instruction groups moved out of the loop, one function each. They return one of these: OK is
 * the end of the switch, the others are the labels the loop would have jumped to, and NOT_MINE says
 * the id is not the group's own.
 */
enum {
	KGENOME_EMU_RUN_OK = 0,
	KGENOME_EMU_RUN_UNSUPPORTED,
	KGENOME_EMU_RUN_FAULT,
	KGENOME_EMU_RUN_DONE,
	KGENOME_EMU_RUN_NOT_MINE
};
int kgenome_emu_run_str(struct kgenome_emu *e, struct kgenome_emu_insn *ixp);
int kgenome_emu_run_misc(struct kgenome_emu *e, struct kgenome_emu_insn *ixp);
int kgenome_emu_run_shift(struct kgenome_emu *e, struct kgenome_emu_insn *ixp);
int kgenome_emu_run_sys(struct kgenome_emu *e, struct kgenome_emu_insn *ixp);
int kgenome_emu_run_vec(struct kgenome_emu *e, struct kgenome_emu_insn *ixp);
int kgenome_emu_run_x87(struct kgenome_emu *e, struct kgenome_emu_insn *ixp);
int kgenome_emu_run_bcd(struct kgenome_emu *e, struct kgenome_emu_insn *ixp);

static inline struct kgenome_emu_page *kgenome_emu_page_lookup(struct kgenome_emu *e, uint64_t va)
{
	uint64_t base = va & ~(uint64_t)(KGENOME_EMU_PAGE - 1u);
	struct kgenome_emu_page *p;

	if (e->cache_page && e->cache_base == base)
		return e->cache_page;
	p = kgenome_emu_page_find(e, va);
	if (p) {
		e->cache_base = base;
		e->cache_page = p;
	}
	return p;
}

#endif /* KGENOME_EMU_INT_H */
