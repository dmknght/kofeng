/*
 * emu_private.h - what the interpreter's files share. NOT PART OF THE SURFACE.
 *
 * emu.h is what a caller reads. This is what the files that make up the
 * emulator's CORE read from each other: the structs the run state is built of,
 * the constants that bound a run, the dispatch table an architecture is an
 * entry of (struct kgenome_emu_arch), and the functions one file offers
 * another. The core is memory (emu_mem.c), construction and the host's
 * setters (emu_api.c), the run loop (emu_run_private.h, made once per entry),
 * the Linux environment (emu_sys.c) and the Windows one (emu_win*.c, whose own
 * header is emu_win_private.h). The x86 entry's files share emu_x86_private.h.
 * Private to libgenome/phenotype/.
 */
#ifndef KGENOME_EMU_PRIVATE_H
#define KGENOME_EMU_PRIVATE_H

#include <stdio.h>
#include <kofdebug.h>

/* A bound or an allocation of the machine refused: sticky in kgenome_emu_hit(), and in a DEBUG
 * build one "[cut]" line naming the place and the thing. `bit` is a KGENOME_EMU_HIT_* word. */
#define KGENOME_EMU_REFUSED(e, bit, what) \
	do { (e)->hit |= (bit); KOF_TRACE("[cut] %s: %s\n", __func__, (what)); } while (0)
#include <kofcore.h>   /* kof_ld_le16/32 */
#include <kofcmp.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>
#include <ctype.h>

#include "emu.h"
#include <genotype/x86/x86.h>


/*
 * A DECODED INSTRUCTION WITH ITS OPERANDS BUILT, which is what the interpreter
 * executes and what the instruction cache keeps. The x86 entry's form (the one
 * entry today); a second architecture's decoded form joins it here, because the
 * cache the core keeps holds whichever the machine runs. genotype builds operands on
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
 * them. HALF-OPEN [lo, hi) AND NOT (offset, length) like struct kof_range, on
 * purpose (the tree's interval types are catalogued in range.h): these are
 * guest virtual addresses, the only question asked of them is "is this address
 * inside", and the end of one range is the start of the next, with no off + len
 * to wrap at the top of the address space. The write watch and the exec watch are the same table with a different
 * question asked of it (a store into it, a fetch from it), so there is one
 * place that enforces the cap and the empty-range refusal and one place that
 * answers "is this address in one".
 */
struct kgenome_emu_wrange { uint64_t lo, hi; };

/* A growing table of ranges: `*r` has room for `*cap`, `*n` are in use, and `max` is the ceiling
 * (the page budget). 1 when the range is kept or there was nothing to keep (empty), 0 when the
 * ceiling or the allocator refused it - the caller records that, it is not a silent drop. */
static inline int kgenome_emu_wrange_add(struct kgenome_emu_wrange **r, uint32_t *n, uint32_t *cap,
					 uint32_t max, uint64_t lo, uint64_t hi)
{
	if (hi <= lo)
		return 1;
	if (*n >= (max > KGENOME_EMU_EXEC_WATCH ? max : KGENOME_EMU_EXEC_WATCH))
		return 0;
	if (*n == *cap) {
		uint32_t m = *cap ? *cap * 2u : KGENOME_EMU_EXEC_WATCH;
		struct kgenome_emu_wrange *t = realloc(*r, (size_t)m * sizeof **r);

		if (!t)
			return 0;
		*r = t;
		*cap = m;
	}
	(*r)[*n].lo = lo;
	(*r)[*n].hi = hi;
	(*n)++;
	return 1;
}

static inline int kgenome_emu_wrange_has(const struct kgenome_emu_wrange *r, uint32_t n, uint64_t va)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (va >= r[i].lo && va < r[i].hi)
			return 1;
	return 0;
}

/*
 * THE x86 ENTRY'S OWN REGISTER STATE BEYOND THE GENERAL REGISTERS: the vector, MMX and x87 files and
 * their control words. Only the x86 entry of the dispatch table (emu_x86.c and the instruction groups
 * of emu_x86_private.h) reads or writes it; the general registers, the program counter and the flags
 * word stay in struct kgenome_emu because the core (the loop, the environments) reads them through the
 * entry's register roles (struct kgenome_emu_arch).
 */
struct kgenome_emu_x86 {
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
	/* 0 empty; 1 in use, its tag read off the value (valid, zero or special); 2-4 in use with the tag a restore loaded
	 * (FLDENV, FRSTOR): valid, zero, special - 2 + the architectural 2-bit tag. The next write of the register makes
	 * it 1 again. */
	uint8_t  st_tag[8];
	uint8_t  st_top;
	/*
	 * The status word's condition codes. C0, C2 and C3 are what a compare
	 * leaves and what FNSTSW hands to a guest that branches on it; C1 is
	 * the stack-fault direction and nothing here reads it.
	 */
	uint16_t fsw;
	/*
	 * The control word (FLDCW sets it, FNSTCW, FNSTENV and FXSAVE report it, FINIT resets it to 037FH) and
	 * the opcode of the last non-control x87 instruction (FOP, 11 bits). Only its RC field is acted on, by
	 * FIST/FISTP and FRNDINT; every exception stays masked and the arithmetic rounds to nearest.
	 */
	uint16_t fcw;
	uint16_t fop;

	/* The address of the last x87 instruction that was not a control one.
	 * FNSTENV reports it, and that report is the only reason x87 is here at
	 * all - see the note on the FPU cases in the run loop. */
	uint64_t fpu_rip;
	/* The operand address of the last x87 instruction that had a memory operand (FDP). */
	uint64_t fpu_dp;

	/*
	 * The SSE control word, remembered and otherwise ignored: scalar
	 * arithmetic here runs on the host's own double, so a rounding mode
	 * stored in it would change nothing. Kept so a caller that saves it and
	 * restores it reads back what it wrote, which is all any of them check.
	 */
	uint32_t mxcsr;
};

struct kgenome_emu_arch;

struct kgenome_emu {
	/* The entry of the dispatch table this machine runs: see struct kgenome_emu_arch. */
	const struct kgenome_emu_arch *arch;
	struct kgenome_emu_page *tab;
	uint32_t     tab_mask;        /* size - 1; size is a power of two */
	uint32_t     n_pages, max_pages;
	/* The caller's accounting (cfg.account): what it has been asked for, and the
	 * part of that granted for private pages and not yet used. */
	int        (*account)(void *user, int64_t bytes);
	void        *account_user;
	uint64_t     acct, page_credit;

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
	uint64_t *insn_spent;   /* kgenome_emu_cfg.insn_spent: added to once, at free */
	uint64_t idle;          /* KGENOME_EMU_IDLE unless set */
	uint64_t deadline_ms;   /* wall clock; 0 for none */
	uint64_t started_ms;
	int      stop_on_written_jump;
	/* Instruction patterns a module asked to be paused on - see
	 * kgenome_emu_watch_insn. `iw_len` is the whole instruction's length when
	 * the module pinned it, 0 when it did not. */
	struct kgenome_emu_iw { uint8_t b[KGENOME_EMU_INSN_WATCH_LEN]; uint8_t n; } *iw;
	uint32_t n_iw, cap_iw;
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

	/* The x86 entry's vector and FPU state - see struct kgenome_emu_x86. */
	struct kgenome_emu_x86 x86;



	/* The thread pointer, as arch_prctl set it - or, for a Windows guest,
	 * as emu_unpack_pe_teb.c's thread block builder set it. */
	uint64_t fs_base, gs_base;
	int      iw_skip;       /* suppress the instruction watch once */

	/*
	 * The Windows environment's three addresses and its error word. Zero
	 * on a Linux guest, and every entry point below checks them, so an ELF
	 * run cannot reach any of it.
	 */
	/* Regions where ENTERING means the loader has handed over. */
	struct kgenome_emu_wrange *xwatch;
	uint32_t n_xwatch, cap_xwatch;
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
	struct kgenome_emu_wrange *wwatch;
	uint32_t n_wwatch, cap_wwatch;
	int      wwatch_hit;
	uint64_t stub_lo, stub_hi;
	uint64_t img_lo, img_hi;   /* the image, for the dump at the handover */
	uint64_t sp0;              /* RSP as the run started - see the OEP test */
	int      sp0_set;
	int      oep_watch;        /* the handover test above is armed */
	int      oep_cand;         /* a transfer from file code into written code, waiting out KGENOME_EMU_OEP_QUIET */
	uint64_t oep_cand_insn, oep_cand_rip;
	uint64_t stack_lo, stack_hi;
	struct kgenome_emu_hop { uint64_t lo, hi; uint8_t seen; } *hop;
	uint32_t n_hop, cap_hop;
	/* Which bounds refused something: enum kgenome_emu_hit_bit, sticky. */
	unsigned hit;
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
	uint32_t unmodelled_guess; /* of them, i386 calls of a name with no known stdcall count */
	uint32_t unmodelled;   /* calls to a name that has a stub and no model (emu_win_names.c) */
	uint32_t win_loaded;   /* bit per module past KGENOME_EMU_WIN_MOD_RESIDENT that a LoadLibrary brought in */
	/*
	 * The size of every block HeapAlloc/RtlAllocateHeap/HeapReAlloc handed out, for HeapSize and for the copy
	 * HeapReAlloc owes. The arena only grows, so blocks are appended in address order and found by binary
	 * search; a freed block keeps its entry with `size` = KGENOME_EMU_HBLK_FREED. One entry (16 bytes) per
	 * block, and a block is at least a page of guest memory that the run is already charged for, so the table
	 * follows the guest's allocations and needs no cap of its own.
	 */
	struct kgenome_emu_hblk { uint64_t va, size; } *hblk;
	uint32_t hblk_n, hblk_cap;
	uint64_t cmdline[2];   /* [0] ANSI, [1] UTF-16; 0 until asked for */
	uint64_t hop_last_rip;
	uint32_t hop_count;

	uint64_t win_image_base, win_k32_base, win_heap;
	/* The CALL instruction that most recently ran: the site of the API call a
	 * stub is about to answer. */
	uint64_t last_call_at;
	/* ...and the one before it: with last_call_at, WHO CALLED - see kgenome_emu_last_calls. */
	uint64_t prev_call_at;
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
	uint32_t exc_flags;    /* ExceptionFlags and the parameters, for a code a guest raised itself */
	uint32_t exc_np;
	uint64_t exc_info[15];
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
	 * emu_loop.c. `dl_at` is the backward branch taken last and `dl_n` how
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


	/* When a page was last written to for the first time - the clock the
	 * idle test below runs on. */
	uint64_t last_new_page;
	uint64_t last_wr_line;     /* the cache line of the last store that earned an idle credit */
	uint32_t idle_credit;      /* credits earned since the last new page - see mem_wr */


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

	/* Sorted page list, built on demand by kgenome_emu_next_written (dropped when a page
	 * is added or first written, so the next walk sees it), and the runs handed out:
	 * every one stays owned here until the emulator is freed, as emu.h says. A run asked
	 * for again is the same buffer, refreshed; `runs_bytes` is bounded by the page
	 * budget, as the snapshots are, and `runs_refused` counts what that bound refused. */
	uint64_t *sorted;
	uint32_t  n_sorted;
	struct kgenome_emu_runbuf { uint64_t va; uint32_t npg; uint8_t *buf; } *runs;
	uint32_t  n_runs, max_runs;
	uint64_t  runs_bytes;
};


/* The Windows environment's ids and functions: emu_win_private.h. */


/* ---- what one file offers another ---- */

int kgenome_emu_page_own(struct kgenome_emu *e, struct kgenome_emu_page *p);
struct kgenome_emu_page *kgenome_emu_page_find(struct kgenome_emu *e, uint64_t va);
struct kgenome_emu_page *kgenome_emu_page_add(struct kgenome_emu *e, uint64_t base, unsigned prot);
int kgenome_emu_acct(struct kgenome_emu *e, uint64_t bytes);
struct kgenome_emu_page *kgenome_emu_page_add_borrow(struct kgenome_emu *e, uint64_t base,
				  unsigned prot, const uint8_t *src);
struct kgenome_emu_page *kgenome_emu_page_add_zero(struct kgenome_emu *e, uint64_t base,
		unsigned prot);
int kgenome_emu_vma_add(struct kgenome_emu *e, uint64_t base, uint64_t len,
		uint64_t off, unsigned prot, int backed);
int kgenome_emu_mem_rd(struct kgenome_emu *e, uint64_t va, void *dst, unsigned n);

int kgenome_emu_mem_wr(struct kgenome_emu *e, uint64_t va, const void *src, unsigned n);
uint64_t kgenome_emu_now_ms(void);
void kgenome_emu_hop_bounds(struct kgenome_emu *e);
void kgenome_emu_snap_take(struct kgenome_emu *e, uint64_t va, uint64_t len);
unsigned kgenome_emu_written_run_pages(struct kgenome_emu *e, uint64_t va, unsigned cap);
uint64_t kgenome_emu_tsc_read(struct kgenome_emu *e);
uint64_t kgenome_emu_do_syscall(struct kgenome_emu *e, int *stop_out);
/* The i386 Linux numbering translated to the amd64 one the environment is written in (emu_sys.c): the
 * canon of the x86 entry's 32-bit convention. */
uint64_t kgenome_emu_sys_i386_nr(uint64_t nr);

/*
 * What an entry's execution of ONE instruction answers the loop (struct kgenome_emu_arch.exec), and
 * what each of the x86 entry's instruction groups answers its switch: OK is the end of the
 * instruction (the loop steps on, or follows the transfer), UNSUPPORTED is an instruction or operand
 * this build cannot carry out (or an operand it could not reach: the loop tells the two apart by
 * `fault_kind`), FAULT a guest fault, DONE a stop the instruction itself set in `stop`, REDIRECT an
 * instruction that started a guest handler and left rip at its entry (the loop must not step to
 * `next`), and NOT_MINE says the id is not a group's own.
 */
enum {
	KGENOME_EMU_RUN_OK = 0,
	KGENOME_EMU_RUN_UNSUPPORTED,
	KGENOME_EMU_RUN_FAULT,
	KGENOME_EMU_RUN_DONE,
	KGENOME_EMU_RUN_NOT_MINE,
	KGENOME_EMU_RUN_REDIRECT
};

/* The instruction about to run, as the loop hands it to an entry: emu_run_private.h. */
struct kgenome_emu_run_step;

/*
 * A SYSTEM CALL CONVENTION, as the registers that carry it. The environment (emu_sys.c) reads the
 * number and the arguments through it and never names a register, so a second architecture is a
 * second row and not a second environment. The answer is -errno in `ret` on failure, as x86 has it
 * (and ARM and AArch64); a convention that flags an error elsewhere (MIPS a3, PowerPC CR0.SO) adds
 * that to its row when its entry is made. `mask` is the guest word: a 32-bit convention reads the
 * low half of each register. `canon` turns the guest's number into the numbering the Linux
 * environment is written in (amd64's), or is NULL when they are the same; a number with no
 * counterpart comes back with bit 32 set, so it cannot collide with one.
 */
struct kgenome_emu_sysabi {
	uint8_t  nr;                      /* the register holding the number     */
	uint8_t  ret;                     /* the register the answer goes to     */
	uint8_t  arg[6];                  /* the argument registers, in order    */
	uint64_t mask;
	uint64_t (*canon)(uint64_t nr);
};

/*
 * ONE ENTRY OF THE DISPATCH TABLE: everything about an architecture the core has to ask.
 *
 * The core (memory and pages, budgets and their accounting, the run loop and its stops, the Linux and
 * Windows environments) is written once; an entry supplies the decode, the execution of a decoded
 * instruction by its id, its register roles, its syscall conventions and what its loader assumes.
 * The loop itself is emu_run_private.h, made once per entry INSIDE the entry's own file
 * (kgenome_emu_run_core with the entry's table), so the questions below that the loop asks of every
 * instruction - decode, len, inert, exec - are direct calls the compiler inlines, not a call through
 * a pointer per instruction; `run` is that instance and the one pointer the core follows
 * (kgenome_emu_run). x86 and x86-64 are the first entry (emu_x86.c), one entry for both widths because
 * the decoder and the handlers take the width from the mode (kgenome_emu.bits).
 */
/* How many times in a row one backward branch is taken before the loop asks the entry whether it is a
 * counted delay (struct kgenome_emu_arch.delay, emu_loop.c). */
#define KGENOME_EMU_DELAY_PROBE 16u

struct kgenome_emu_arch {
	const char *name;
	enum kgenome_emu_stop (*run)(struct kgenome_emu *e);
	/* Decode the instruction at e->rip from `code` (`n` bytes, zero-padded past what is mapped) into
	 * *ix: 1 when it decoded, 0 when the bytes are no instruction. */
	int      (*decode)(struct kgenome_emu *e, const uint8_t *code, unsigned n, struct kgenome_emu_insn *ix);
	unsigned (*len)(const struct kgenome_emu_insn *ix);
	/* 1 when the instruction provably changes nothing: decided once, when the cache keeps it. */
	int      (*inert)(const struct kgenome_emu_insn *ix);
	/* Carry out the instruction in *st (e->rip is its address). *next is the fall-through address on
	 * entry and may be moved (a counted branch); *jumped is set when the instruction moved e->rip
	 * itself. Answers a KGENOME_EMU_RUN_* value. */
	int      (*exec)(struct kgenome_emu *e, const struct kgenome_emu_run_step *st, uint64_t *next, int *jumped);
	/* The text of the instruction, for a refusal and the instruction trace: 1 when written. */
	int      (*text)(const struct kgenome_emu_insn *ix, uint64_t va, char *buf, size_t n);
	/* 1 when the transfer that just ran (its `len` bytes at `b`) has one of the shapes a loader ends
	 * with - the handover test of the loop. */
	int      (*tail)(const uint8_t *b, unsigned len);
	/* A backward branch at `at` to `top` was taken KGENOME_EMU_DELAY_PROBE times in a row: skip the
	 * rest of the loop when the entry recognises a counted delay. */
	void     (*delay)(struct kgenome_emu *e, uint64_t top, uint64_t at, unsigned at_len);
	/* A call reached an address nothing maps below the first page (an import the environment does not
	 * have): take the return address the call left, as the convention leaves it. 1 when one was read
	 * (the stack has moved past it), 0 when it could not be. */
	int      (*ret_pop)(struct kgenome_emu *e, uint64_t *ret);
	/* Reset the entry's own state and map what its loader assumes is always there (x86: the MXCSR and
	 * x87 control words, the vsyscall page). Called once by kgenome_emu_new. */
	void     (*init)(struct kgenome_emu *e);
	unsigned text_max;                /* the longest `text` writes, with its NUL       */
	/* The register roles: the stack pointer, the register a call's answer comes back in. */
	uint8_t  sp, acc;
	/* The registers a loader points at the entry before the run - see kgenome_emu_arch_seed. */
	const uint8_t *seed;
	uint8_t  n_seed;
	/* The system call conventions, by guest word: [0] for 32 bits, [1] for 64. */
	struct kgenome_emu_sysabi sys[2];
};

/* The entry an emulator is made with (emu_interp.c), and the x86 entry itself (emu_x86.c). */
const struct kgenome_emu_arch *kgenome_emu_arch_of(const struct kgenome_emu_cfg *cfg);
const struct kgenome_emu_arch *kgenome_emu_arch_x86(void);

/* The system call convention in force for the call being made: the entry's row for the guest word. */
static inline const struct kgenome_emu_sysabi *kgenome_emu_sysabi_of(const struct kgenome_emu *e)
{
	return &e->arch->sys[e->bits == 32 ? 0 : 1];
}

/* Argument `i` (0-5) of the system call being made, as the convention passes it. */
static inline uint64_t kgenome_emu_sys_arg(const struct kgenome_emu *e, unsigned i)
{
	const struct kgenome_emu_sysabi *a = kgenome_emu_sysabi_of(e);

	return i < 6u ? e->gpr[a->arg[i]] & a->mask : 0;
}

/* Point the entry's seed registers at `entry`: the loader's assumption about the general registers at
 * the first instruction (see emu_unpack_elf.c for why it is the entry and not zero). */
void kgenome_emu_arch_seed(struct kgenome_emu *e, uint64_t entry);


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

#endif /* KGENOME_EMU_PRIVATE_H */
