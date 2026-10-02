/*
 * kofemu.c - the interpreter. See kofemu.h for what it is for.
 *
 *
 * HOW AN INSTRUCTION IS CARRIED OUT
 *
 * Not as one switch over several hundred mnemonics. bddisasm hands back a
 * decoded operand list - for each operand: is it a register, a memory
 * reference or an immediate, how wide, and is it read, written or both. So the
 * shape here is
 *
 *      read every source operand generically
 *      switch on the mnemonic to compute a result   <- small
 *      write the destination generically
 *
 * and the switch holds arithmetic rather than addressing. Adding an
 * instruction is then usually one case, and the addressing modes it inherits
 * are the ones already tested by every other instruction.
 *
 *
 * FLAGS ARE COMPUTED EAGERLY
 *
 * A real CPU defers them and so do fast emulators. This one does not: a packer
 * stub is a few hundred thousand instructions, the budget stops it long before
 * the difference is measurable, and a lazy flag bug is the kind that shows up
 * as one wrong branch a hundred thousand instructions later. Correctness that
 * can be read beats speed that cannot.
 */

/* clock_gettime, for the wall clock bound - see kof_emu_set_deadline. The
 * project's other users of it reach for _GNU_SOURCE for the same reason. */
#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>

#include "kofemu.h"
#include "bddisasm.h"

#define DEF_MAX_INSN   (2u * 1000u * 1000u)
#define VSYSCALL_BASE  0xffffffffff600000ull
#define DEF_MAX_PAGES  (16u * 1024u)          /* 64 MB of emulated space */

/* How many unresolved imports a run may call before the answers stop being
 * plausible - see the null page check in the loop. */
#define EMU_NULL_CALLS 256u

/* How many exceptions a run may raise with nothing to catch them before it is
 * no longer unpacking - see WIN_RaiseException. */
#define EMU_UNHANDLED_MAX 64u

/* How far a write-then-execute snapshot reaches either way from the page that
 * fired it, in pages. A megabyte each side is past any one function. */
#define WEX_SPAN_PAGES 256u

/* ---- memory ---------------------------------------------------------------
 *
 * Sparse, because a packer maps a few megabytes inside a 47 bit address space
 * and a flat array of that is not a thing. Open addressing on the page number:
 * the table is sized from the page budget at construction so it never has to
 * grow while an emulation is in flight.
 */
#define KOF_EMU_ICACHE 2048u

struct page {
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
};

struct kof_emu {
	struct page *tab;
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
	struct page *cache_page;

	uint64_t gpr[KOF_EMU_NGPR];
	uint64_t rip;
	uint64_t flags;               /* only the six that matter, see FL_* */

	uint64_t max_insn, insn;
	uint64_t idle;          /* KOF_EMU_IDLE unless set */
	uint64_t deadline_ms;   /* wall clock; 0 for none */
	uint64_t started_ms;
	int      stop_on_written_jump;
	/* Instruction patterns a module asked to be paused on - see
	 * kof_emu_watch_insn. `iw_len` is the whole instruction's length when
	 * the module pinned it, 0 when it did not. */
	struct { uint8_t b[KOF_EMU_INSN_WATCH_LEN]; uint8_t n; } iw[KOF_EMU_INSN_WATCH];
	uint32_t n_iw;
	unsigned iw_len;
	/* Whether guest code is what is executing - see `gwritten`. The host
	 * prepares the image before this is set and after it is cleared. */
	int      running;
	/* 32 or 64. See kof_emu_cfg.bits; everything it changes is marked with
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
		const struct page *pg;
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
		INSTRUX           ix;
	}       *ic;

	/* A hot-address histogram, built only under KOF_EMU_HOT. It answers one
	 * question: is a run's time spent in a small loop, or spread out? */
	struct { uint64_t va; uint64_t n; } *hot;
	uint64_t ic_hit, ic_miss;
	uint32_t hot_mask;

	uint64_t trace[KOF_EMU_TRACE];
	/* The instruction trace - see kof_emu_itrace. NULL unless asked for. */
	struct itrace { uint64_t rip; uint64_t gpr[KOF_EMU_NGPR]; char txt[96]; }
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

	uint32_t unksys[KOF_EMU_UNKSYS];
	uint32_t n_unksys;
	struct kof_emu_syscall syslog[KOF_EMU_SYSLOG];
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
	 * ST(i) IS st[(top + i) & 7]. bddisasm reports an x87 operand's `Reg`
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

	/*
	 * The Windows environment's three addresses and its error word. Zero
	 * on a Linux guest, and every entry point below checks them, so an ELF
	 * run cannot reach any of it.
	 */
	/* Regions where ENTERING means the loader has handed over. */
	struct { uint64_t lo, hi; } xwatch[KOF_EMU_EXEC_WATCH];
	uint32_t n_xwatch;
	/*
	 * Whether the last instruction fetched was already inside one of them.
	 *
	 * A handover is a jump INTO the program, so what ends the run is the
	 * EDGE and not the address: a run that begins inside a watched range,
	 * or that is still running through one, has not handed anything over.
	 * See kof_emu_watch_exec.
	 */
	int xw_was_in, xw_have_prev;
	/* Ranges whose first WRITE means the loader is decrypting the program
	 * - see kof_emu_watch_write. */
	struct { uint64_t lo, hi; } wwatch[KOF_EMU_EXEC_WATCH];
	uint32_t n_wwatch;
	int      wwatch_hit;
	uint64_t stub_lo, stub_hi;
	uint64_t img_lo, img_hi;   /* the image, for the dump at the handover */
	uint64_t sp0;              /* RSP as the run started - see the OEP test */
	int      sp0_set;
	int      oep_watch;        /* the handover test above is armed */
	int      img_dumped;
	uint64_t stack_lo, stack_hi;
	struct { uint64_t lo, hi; uint8_t seen; } hop[KOF_EMU_EXEC_WATCH];
	uint32_t n_hop;
	uint64_t hop_first_insn, hop_first_rip;
	uint64_t fetch_page;   /* never a page base until one is set */
	uint32_t null_calls;   /* imports this environment did not have */
	uint64_t cmdline[2];   /* [0] ANSI, [1] UTF-16; 0 until asked for */
	uint64_t hop_last_rip;
	uint32_t hop_count;

	uint64_t win_image_base, win_k32_base, win_heap;
	uint64_t mod_reads[KOF_EMU_WIN_MOD_COUNT];
	uint8_t  count_mod_reads;
	uint64_t win_mod_base[KOF_EMU_WIN_MOD_COUNT];
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
	 * KOF_EMU_IDLE; this remembers where it stood last time the guest
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
#define KOF_EMU_RDRING 8u
	uint64_t last_read[KOF_EMU_RDRING];
	unsigned last_read_n;
	uint64_t pair_va;       /* where the last read-then-write pair was */
	uint64_t active_n;      /* how many active instructions were seen */
	uint64_t since_active;  /* instructions since the last one */
	unsigned in_fetch;      /* reads made to FETCH are not data reads */
	unsigned quiet_on;      /* KOF_EMU_QUIET armed - see the run loop */
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
	char     say[KOF_EMU_SAY];
	uint32_t n_say;

	/* The one open file an emulated process has: itself. */
	const uint8_t *self;
	uint64_t       self_n, self_pos;

	/* Payload images caught at the mprotect that made them executable. */
	struct snap { uint64_t va, len; uint8_t *bytes; } *snap;
	uint32_t n_snap, max_snap;

	uint64_t watch_va;
	int      watch_on;
	uint64_t watch_rip[KOF_EMU_WATCH_MAX], watch_val[KOF_EMU_WATCH_MAX];
	unsigned watch_n;
	enum kof_emu_stop stop;
	char     detail[48];

	/* Sorted page list, built on demand by kof_emu_next_written, and the
	 * one run handed out at a time - freed when the next is asked for, so a
	 * caller never has to. */
	uint64_t *sorted;
	uint32_t  n_sorted;
	uint8_t  *run_buf;
};

#define FL_CF  (1u << 0)
#define FL_PF  (1u << 2)
#define FL_AF  (1u << 4)
#define FL_ZF  (1u << 6)
#define FL_SF  (1u << 7)
#define FL_DF  (1u << 10)
#define FL_OF  (1u << 11)

static uint32_t page_hash(uint64_t pn)
{
	pn ^= pn >> 33; pn *= 0xff51afd7ed558ccdull;
	pn ^= pn >> 29; pn *= 0xc4ceb9fe1a85ec53ull;
	return (uint32_t)(pn ^ (pn >> 32));
}

static struct page *vma_commit(struct kof_emu *e, uint64_t base);

static struct page *page_find(struct kof_emu *e, uint64_t va)
{
	uint64_t base = va & ~(uint64_t)(KOF_EMU_PAGE - 1u);
	uint32_t i = page_hash(base) & e->tab_mask, n = 0;

	if (!base)
		return NULL;          /* page zero is never mapped: a NULL deref
				       * has to fault rather than read zeroes */
	while (n++ <= e->tab_mask) {
		struct page *p = &e->tab[i];

		if (!p->va)
			return vma_commit(e, base);
		if (p->va == base)
			return p;
		i = (i + 1u) & e->tab_mask;
	}
	return NULL;
}

static struct page *page_add(struct kof_emu *e, uint64_t base, unsigned prot)
{
	uint32_t i, n = 0;

	if (e->n_pages >= e->max_pages || !base)
		return NULL;
	i = page_hash(base) & e->tab_mask;
	while (n++ <= e->tab_mask) {
		struct page *p = &e->tab[i];

		if (p->va == base)
			return p;
		if (!p->va) {
			p->data = calloc(1, KOF_EMU_PAGE);
			if (!p->data)
				return NULL;
			p->va = base;
			p->prot = prot;
			e->n_pages++;
			free(e->sorted);
			e->sorted = NULL;
			return p;
		}
		i = (i + 1u) & e->tab_mask;
	}
	return NULL;
}

/* Record a mapping without committing any of it. */
static int vma_add(struct kof_emu *e, uint64_t base, uint64_t len,
		   uint64_t off, unsigned prot, int backed)
{
	struct vma *v;

	/*
	 * A ceiling on the number of live mappings, not on their size.
	 *
	 * mmap is the one call a guest can make in a loop that costs the HOST
	 * memory without costing the guest a page: a reservation commits
	 * nothing, so a loop of them grows this list and nothing else stops it.
	 * Real programs use tens; a Go runtime reserving its arenas uses a few
	 * hundred.
	 */
	if (e->n_vma >= KOF_EMU_MAX_VMA)
		return 0;
	if (e->n_vma == e->max_vma) {
		uint32_t m = e->max_vma ? e->max_vma * 2u : 8u;
		struct vma *t = realloc(e->vma, (size_t)m * sizeof *t);

		if (!t)
			return 0;
		e->vma = t;
		e->max_vma = m;
	}
	v = &e->vma[e->n_vma++];
	v->base = base; v->len = len; v->off = off;
	v->prot = prot; v->backed = backed;
	return 1;
}

/*
 * Turn one page of a recorded mapping into a real one. Later mappings win, so
 * the search runs backwards: a MAP_FIXED over part of an earlier range is what
 * that address means now.
 */
static struct page *vma_commit(struct kof_emu *e, uint64_t base)
{
	uint32_t k = e->n_vma;

	while (k--) {
		struct vma *v = &e->vma[k];
		struct page *p;

		if (base < v->base || base - v->base >= v->len)
			continue;
		p = page_add(e, base, v->prot);
		if (!p)
			return NULL;
		if (v->backed && e->self) {
			uint64_t o = v->off + (base - v->base);
			uint64_t n = o < e->self_n ? e->self_n - o : 0;

			if (n > KOF_EMU_PAGE)
				n = KOF_EMU_PAGE;
			if (n)
				memcpy(p->data, e->self + o, (size_t)n);
		}
		return p;
	}
	return NULL;
}

/*
 * page_find with a one-entry memo of the last non-NULL result.
 *
 * mem_rd/mem_wr resolve one byte at a time, and consecutive bytes share a page
 * except at a boundary, so the memo answers all but the first byte of an
 * access without hashing. It never memoises a miss - see the note on
 * cache_page - so a base that is unmapped now and filled later still resolves
 * through page_find, and the per-byte straddle behaviour is unchanged: every
 * byte still resolves its own page independently, just more cheaply.
 */
static struct page *page_lookup(struct kof_emu *e, uint64_t va)
{
	uint64_t base = va & ~(uint64_t)(KOF_EMU_PAGE - 1u);
	struct page *p;

	if (e->cache_page && e->cache_base == base)
		return e->cache_page;
	p = page_find(e, va);
	if (p) {
		e->cache_base = base;
		e->cache_page = p;
	}
	return p;
}

/*
 * Every read and write goes through these, one byte at a time.
 *
 * A byte at a time because an access may straddle a page boundary and the two
 * pages need not be adjacent in the table - and because a straddling access
 * that half succeeds is the bug this design exists to make impossible. The
 * per-byte page resolution goes through page_lookup so that a within-page run
 * costs one hash rather than one per byte.
 */
static int mem_rd(struct kof_emu *e, uint64_t va, void *dst, unsigned n)
{
	uint8_t *d = dst;
	unsigned i;

	/*
	 * A READ THROUGH A NULL POINTER IS ZERO, NOT THE END OF THE RUN.
	 *
	 * On Windows it faults and the process dies. Here the process dying is
	 * the thing to avoid: what the run is FOR is the plaintext the guest
	 * writes, and a guest that took a null from something this environment
	 * could not answer - a function in a library whose export list is
	 * empty, a handle it never got - then reads a field off it, and the
	 * run used to end there with the payload still encrypted. Measured on
	 * an MPRESS sample: `read at 0x14`, one field off a null pointer, at
	 * 16477255 instructions.
	 *
	 * READS ONLY. Execution at zero is still a fault and still means
	 * "called an import this environment does not have"; a write is still
	 * a fault, because a write that goes nowhere loses the very bytes this
	 * exists to collect. The two cases stay apart from this one.
	 *
	 * Only the first page, and only where the guest mapped nothing: a guest
	 * that genuinely mapped page zero is reading its own memory.
	 */
	if (va < KOF_EMU_PAGE && (uint64_t)n <= KOF_EMU_PAGE - va &&
	    !page_lookup(e, va)) {
		e->null_reads++;
		memset(d, 0, n);
		return 1;
	}

	/*
	 * READS INTO A LIBRARY IMAGE, COUNTED ONLY WHEN ASKED FOR.
	 *
	 * "It called nothing" and "it walked the export table and found
	 * nothing" look identical from a stop reason and mean opposite things:
	 * the first says the environment's function list is beside the point,
	 * the second says exactly which name is missing. Counting the reads
	 * separates them.
	 *
	 * Behind a flag because this is the hottest path in the interpreter and
	 * eight range tests per byte would be measurable; with the flag clear
	 * it is one predictable branch.
	 */
	if (e->count_mod_reads) {
		unsigned m;

		for (m = 0; m < KOF_EMU_WIN_MOD_COUNT; m++) {
			uint64_t b = e->win_mod_base[m];

			if (b && va >= b && va < b + (256u * KOF_EMU_PAGE)) {
				e->mod_reads[m]++;
				break;
			}
		}
	}

	for (i = 0; i < n; i++) {
		struct page *p = page_lookup(e, va + i);

		if (!p) {
			/*
			 * A DATA READ FROM NOWHERE ANSWERS ZERO, UNDER
			 * MEASUREMENT - see KOF_EMU_SOFTREAD.
			 *
			 * The engine already makes this trade for page zero,
			 * with the argument written beside it: what a run is
			 * FOR is the plaintext the guest writes, and a read of
			 * a field off a pointer the environment could not
			 * supply should not end it. The same argument applies
			 * to a pointer that is garbage rather than null, and
			 * the published designs call a run that dies this way
			 * an INCORRECT termination - something to recover from
			 * rather than to report.
			 *
			 * Measured before it is believed: 125 of 129 runs over
			 * a Windows corpus end in a fault. Whether tolerating
			 * them produces anything is the question this flag
			 * exists to answer, so it is off by default.
			 */
			if (e->softread && !e->in_fetch && e->running) {
				e->soft_reads++;
				d[i] = 0;
				continue;
			}
			e->fault_va = va + i;
			memcpy(e->fault_kind, "read", 5);
			return 0;
		}
		d[i] = p->data[(va + i) & (KOF_EMU_PAGE - 1u)];
	}
	/* A DATA read, not the fetch of an instruction - see `last_read_va`.
	 * The fetch reads memory too and counting it would make every program
	 * look like it was decrypting itself. */
	if (e->running && !e->in_fetch) {
		e->last_read[e->last_read_n % KOF_EMU_RDRING] = va;
		e->last_read_n++;
	}
	return 1;
}

static int mem_wr(struct kof_emu *e, uint64_t va, const void *src, unsigned n)
{
	const uint8_t *s = src;
	unsigned i;

	for (i = 0; i < n; i++) {
		struct page *p = page_lookup(e, va + i);

		if (!p) {
			/*
			 * A WRITE TO NOWHERE GETS A PAGE, UNDER MEASUREMENT -
			 * see KOF_EMU_SOFTWRITE.
			 *
			 * THE ARGUMENT FOR REFUSING IS THE ARGUMENT FOR THIS.
			 * The note beside the read path says a write that goes
			 * nowhere "loses the very bytes this exists to
			 * collect" - and refusing it loses them just as
			 * completely, by ending the run. Giving the guest the
			 * page keeps them, and keeps whatever it writes next.
			 *
			 * Measured over 300 Windows samples: of seventeen runs
			 * that ended in a fault, SEVEN were a write to an
			 * address nothing mapped.
			 *
			 * STILL BOUNDED. page_add refuses past the page budget,
			 * so a guest that writes at random addresses buys a
			 * fixed number of pages and then ends exactly as it
			 * does today.
			 */
			if (e->softwrite && e->running) {
				p = page_add(e, (va + i) &
					     ~(uint64_t)(KOF_EMU_PAGE - 1u),
					     KOF_EMU_R | KOF_EMU_W);
				if (p)
					e->soft_writes++;
			}
			if (!p) {
				e->fault_va = va + i;
				memcpy(e->fault_kind, "write", 6);
				return 0;
			}
		}
		{
			uint32_t po = (uint32_t)((va + i) &
						 (KOF_EMU_PAGE - 1u));

			p->data[po] = s[i];
			if (po + 1u > p->wr_hi)
				p->wr_hi = (uint16_t)(po + 1u);
		}
		/*
		 * A WRITE BACK TO WHAT WAS JUST READ, near where the last one
		 * was - see `last_read_va`. Eight bytes of slack, so a loop
		 * working a dword or a qword at a time is still one stride.
		 */
		/*
		 * ---- IS THE GUEST STILL DECRYPTING --------------------------
		 *
		 * A WRITE NEXT TO THE LAST ONE. See `last_read` for why the
		 * signal has to be a memory trace rather than an opcode; this
		 * is which trace, and it was measured rather than assumed.
		 *
		 * THE PUBLISHED HEURISTIC IS A READ FOLLOWED BY A WRITE BACK TO
		 * THE SAME ADDRESS - decryption in place - AND IT DOES NOT FIT
		 * THIS FAMILY. Measured on a Sality body: of 408,441 guest
		 * writes, 350,346 were indeed writes back to something just
		 * read, and every one of them was the STACK - push and pop
		 * touching the same slot. The decryption itself reads from one
		 * place and writes to another, so it never made that pattern
		 * once in twenty million instructions.
		 *
		 * What it does make is a SEQUENTIAL WRITE STREAM: 58,076 writes
		 * landing within eight bytes of the one before, against 58,066
		 * loop iterations counted independently. That is the output of
		 * the decryption, and a decryptor cannot avoid producing it
		 * whatever instructions it is spelled with.
		 *
		 * THE STACK IS EXCLUDED, and it has to be: a run of pushes is
		 * also a sequential write stream, and without this every
		 * function prologue would read as decryption.
		 */
		if (e->running && !i) {
			uint64_t sp = e->gpr[KOF_EMU_RSP];
			uint64_t d = va > sp ? va - sp : sp - va;

			if (d > (64u << 10)) {
				d = va > e->pair_va ? va - e->pair_va
						    : e->pair_va - va;
				if (e->pair_va && d && d <= 8u) {
					if (e->active_n &&
					    e->since_active > e->gap_max)
						e->gap_max = e->since_active;
					e->active_n++;
					e->since_active = 0;
				}
				e->pair_va = va;
			}
		}
		/* The first write to a page is the unit of progress: see
		 * KOF_EMU_IDLE. Recorded here, where it happens, so nothing
		 * else has to remember to. */
		if (!p->written)
			e->last_new_page = e->insn;
		p->written = 1;
		/* Only while the guest is the one running - see `gwritten`. */
		if (e->running)
			p->gwritten = 1;
		/*
		 * A WRITE INTO CIPHERTEXT IS THE MOMENT THE PROGRAM APPEARS.
		 *
		 * A protector's loader decrypts the program's own sections in
		 * place, so the first write into one of them is the only signal
		 * that does not depend on guessing where it will jump
		 * afterwards. themida-dumper watches exactly this from outside
		 * the process - it fingerprints the encrypted sections and
		 * polls them for change - and this is the same test made from
		 * inside, where it costs a range check instead of a poll. See
		 * THIRD-PARTY.md.
		 *
		 * The image is taken ONCE, at the first such write, and the run
		 * carries on: a loader decrypts several sections and stopping at
		 * the first would take the image before the rest exist. The
		 * snapshot is of the whole image because a section decrypted
		 * alone is not a program.
		 */
		if (e->n_wwatch && !e->wwatch_hit) {
			uint32_t q;

			for (q = 0; q < e->n_wwatch; q++)
				if (va + i >= e->wwatch[q].lo &&
				    va + i < e->wwatch[q].hi) {
					e->wwatch_hit = 1;
					break;
				}
		}
		if (e->watch_on && va + i == e->watch_va &&
		    e->watch_n < KOF_EMU_WATCH_MAX) {
			e->watch_rip[e->watch_n] = e->rip;
			e->watch_val[e->watch_n] = s[i];
			e->watch_n++;
		}
	}
	return 1;
}

/* ---- construction --------------------------------------------------------- */

static uint32_t pow2_at_least(uint32_t n)
{
	uint32_t v = 16;

	while (v < n)
		v <<= 1;
	return v;
}

struct kof_emu *kof_emu_new(const struct kof_emu_cfg *cfg)
{
	struct kof_emu *e = calloc(1, sizeof *e);
	uint64_t pages = cfg && cfg->max_pages ? cfg->max_pages : DEF_MAX_PAGES;

	if (!e)
		return NULL;
	if (pages > (1u << 22))
		pages = 1u << 22;
	e->max_pages = (uint32_t)pages;
	/* Lazily sized once, here, so the run loop never allocates. A failure
	 * is not fatal: the cache is an optimisation and the loop checks for
	 * it - see `ic`. */
	e->ic = calloc(KOF_EMU_ICACHE, sizeof *e->ic);
	e->quiet_on = getenv("KOF_EMU_QUIET") != NULL;
	e->softread = getenv("KOF_EMU_SOFTREAD") != NULL;
	e->softwrite = getenv("KOF_EMU_SOFTWRITE") != NULL;
	if (getenv("KOF_EMU_HOT")) {
		e->hot_mask = (1u << 16) - 1u;
		e->hot = calloc(e->hot_mask + 1u, sizeof *e->hot);
	}
	/* Off on demand, so the cache's worth can be measured rather than
	 * asserted - the same shape as KOF_EMU_TRACE and KOF_EMU_NOLIMIT. */
	if (e->ic && getenv("KOF_EMU_NOCACHE")) {
		free(e->ic);
		e->ic = NULL;
	}
	/* Twice the budget, so the table never passes half full and the probe
	 * chains stay short whatever the addresses look like. */
	e->tab_mask = pow2_at_least((uint32_t)pages * 2u) - 1u;
	e->tab = calloc((size_t)e->tab_mask + 1u, sizeof *e->tab);
	if (!e->tab) {
		free(e);
		return NULL;
	}
	/* Not a page base - page bases are aligned - so the first fetch always
	 * takes the slow path and checks execute permission. See the fetch. */
	e->fetch_page = ~(uint64_t)0;
	e->mxcsr = 0x1f80u;             /* the reset value: all exceptions masked */
	e->max_insn = cfg && cfg->max_insn ? cfg->max_insn : DEF_MAX_INSN;
	e->idle = KOF_EMU_IDLE;
	e->stop_on_written_jump = cfg ? cfg->stop_on_written_jump : 0;
	/* 0 means 64: a caller written before the field existed asks for what
	 * it always got. */
	e->bits = (cfg && cfg->bits == 32) ? 32u : 64u;
	/*
	 * THE VSYSCALL PAGE, WHICH A REAL KERNEL ALWAYS PROVIDES.
	 *
	 * A runtime with no vDSO in its auxv falls back to calling the fixed
	 * addresses here, and finding nothing at them looks like a wild jump to
	 * 0xffffffffff600000 rather than the ordinary fallback it is. Three
	 * entries at their architectural offsets, each doing the syscall it
	 * stands for: mov eax, nr / syscall / ret.
	 */
	{
		static const uint16_t nrs[3] = { 96, 201, 309 }; /* gettimeofday,
								 * time, getcpu */
		uint8_t pg[KOF_EMU_PAGE];
		unsigned k;

		memset(pg, 0xcc, sizeof pg);
		for (k = 0; k < 3; k++) {
			uint8_t *p = pg + k * 0x400u;

			p[0] = 0xb8;                             /* mov eax, */
			p[1] = (uint8_t)nrs[k];
			p[2] = (uint8_t)(nrs[k] >> 8);
			p[3] = 0; p[4] = 0;
			p[5] = 0x0f; p[6] = 0x05;                /* syscall */
			p[7] = 0xc3;                             /* ret     */
		}
		kof_emu_map(e, VSYSCALL_BASE, pg, sizeof pg, sizeof pg,
			    KOF_EMU_R | KOF_EMU_X);
	}
	return e;
}

void kof_emu_free(struct kof_emu *e)
{
	if (e)
		free(e->itr);
	uint32_t i;

	if (!e)
		return;
	if (e->hot) {
		uint64_t tot = 0, top = 0, best;
		uint32_t q, n_used = 0, j, k, bi;

		for (q = 0; q <= e->hot_mask; q++)
			if (e->hot[q].n) { tot += e->hot[q].n; n_used++; }
		fprintf(stderr, "[act] active=%llu gapmax=%llu tail=%llu\n",
			(unsigned long long)e->active_n,
			(unsigned long long)e->gap_max,
			(unsigned long long)e->since_active);
		fprintf(stderr, "[hot] miss: empty=%llu va=%llu pg=%llu bytes=%llu\n",
			(unsigned long long)e->m_empty,
			(unsigned long long)e->m_va,
			(unsigned long long)e->m_pg,
			(unsigned long long)e->m_bytes);
		fprintf(stderr, "[hot] icache hit=%llu miss=%llu (%.2f%%)\n",
			(unsigned long long)e->ic_hit,
			(unsigned long long)e->ic_miss,
			e->ic_hit + e->ic_miss ? 100.0 * (double)e->ic_hit /
				(double)(e->ic_hit + e->ic_miss) : 0.0);
		fprintf(stderr, "[hot] distinct=%u total=%llu\n", n_used,
			(unsigned long long)tot);
		for (j = 0; j < 12u; j++) {
			best = 0; bi = 0;
			for (k = 0; k <= e->hot_mask; k++)
				if (e->hot[k].n > best) {
					best = e->hot[k].n; bi = k;
				}
			if (!best)
				break;
			top += best;
			fprintf(stderr, "[hot] %2u %#010llx %llu (%.1f%%)\n",
				j, (unsigned long long)e->hot[bi].va,
				(unsigned long long)best,
				tot ? 100.0 * (double)best / (double)tot : 0.0);
			e->hot[bi].n = 0;
		}
		fprintf(stderr, "[hot] top12 = %.1f%% of the run\n",
			tot ? 100.0 * (double)top / (double)tot : 0.0);
	}
	free(e->hot);
	free(e->ic);
	for (i = 0; i <= e->tab_mask; i++)
		free(e->tab[i].data);
	free(e->tab);
	free(e->sorted);
	free(e->run_buf);
	free(e->vma);
	for (i = 0; i < e->n_snap; i++)
		free(e->snap[i].bytes);
	free(e->snap);
	free(e);
}

int kof_emu_map(struct kof_emu *e, uint64_t va, const uint8_t *src, uint64_t n,
		uint64_t memsz, unsigned prot)
{
	uint64_t base = va & ~(uint64_t)(KOF_EMU_PAGE - 1u);
	uint64_t end, off;

	if (!e || memsz < n)
		memsz = n;
	if (!e || !memsz)
		return 0;
	end = va + memsz;
	if (end < va)
		return 0;                     /* wrapped: refuse rather than clamp */
	for (off = base; off < end; off += KOF_EMU_PAGE)
		if (!page_add(e, off, prot))
			return 0;
	/*
	 * Written through page_add's pages directly rather than through mem_wr:
	 * loading an image is not the stub writing, and marking these pages
	 * dirty would hand the whole file back as "what the stub produced".
	 */
	for (off = 0; off < n; off++) {
		struct page *p = page_find(e, va + off);

		if (!p)
			return 0;
		p->data[(va + off) & (KOF_EMU_PAGE - 1u)] = src ? src[off] : 0;
	}
	return 1;
}

void kof_emu_set_self(struct kof_emu *e, const uint8_t *b, uint64_t n)
{
	e->self = b;
	e->self_n = n;
	e->self_pos = 0;
}

void kof_emu_set_rip(struct kof_emu *e, uint64_t rip) { e->rip = rip; }
void kof_emu_set_reg(struct kof_emu *e, unsigned g, uint64_t v)
{
	if (g < KOF_EMU_NGPR)
		e->gpr[g] = v;
}
void kof_emu_set_seg_base(struct kof_emu *e, unsigned seg, uint64_t base)
{
	if (seg == 4u)
		e->fs_base = base;
	else if (seg == 5u)
		e->gs_base = base;
}
uint64_t kof_emu_get_reg(const struct kof_emu *e, unsigned g)
{
	return g < KOF_EMU_NGPR ? e->gpr[g] : 0;
}

uint64_t kof_emu_get_rip(const struct kof_emu *e)
{
	return e ? e->rip : 0;
}
uint64_t kof_emu_rip(const struct kof_emu *e) { return e->rip; }
/*
 * How many faults were offered to a guest handler, and how many a handler
 * actually took. The pair is the measurement that says whether exception
 * dispatch is reaching anything: raised without taken means the records are
 * being built and nobody is registered to receive them, which is a different
 * problem from not building them.
 */
void kof_emu_exc_counts(const struct kof_emu *e, uint32_t *raised,
			uint32_t *taken, uint32_t *veh)
{
	if (raised) *raised = e->exc_raised;
	if (taken)  *taken  = e->exc_taken;
	if (veh)    *veh    = e->n_veh;
}

uint64_t kof_emu_last_write(const struct kof_emu *e)
{
	return e->last_new_page;
}

static uint64_t now_ms(void)
{
	struct timespec t;

	if (clock_gettime(CLOCK_MONOTONIC, &t))
		return 0;
	return (uint64_t)t.tv_sec * 1000ull + (uint64_t)(t.tv_nsec / 1000000);
}

unsigned kof_emu_null_calls(const struct kof_emu *e)
{
	return e ? e->null_calls : 0u;
}

unsigned kof_emu_unhandled(const struct kof_emu *e)
{
	return e ? e->exc_unhandled : 0u;
}

unsigned kof_emu_null_reads(const struct kof_emu *e)
{
	return e ? e->null_reads : 0u;
}

/* The longest the run went without touching a new page - what the stall
 * ceiling has to clear for a run like this one to finish. */
uint64_t kof_emu_idle_max(const struct kof_emu *e)
{
	return e ? e->idle_max : 0u;
}

void kof_emu_set_idle(struct kof_emu *e, uint64_t n)
{
	if (e && n)
		e->idle = n;
}

void kof_emu_set_deadline(struct kof_emu *e, uint64_t ms)
{
	if (!e)
		return;
	e->deadline_ms = ms;
	e->started_ms = ms ? now_ms() : 0;
}

void kof_emu_set_max_insn(struct kof_emu *e, uint64_t n)
{
	if (e && n > e->max_insn)
		e->max_insn = n;
}

uint64_t kof_emu_insn_count(const struct kof_emu *e) { return e->insn; }
const char *kof_emu_stop_detail(const struct kof_emu *e) { return e->detail; }

void kof_emu_watch(struct kof_emu *e, uint64_t va)
{
	e->watch_va = va;
	e->watch_on = 1;
	e->watch_n = 0;
}

unsigned kof_emu_watch_hits(const struct kof_emu *e, uint64_t *rip,
			    uint64_t *val, unsigned n)
{
	unsigned k, got = e->watch_n < n ? e->watch_n : n;

	for (k = 0; k < got; k++) { rip[k] = e->watch_rip[k]; val[k] = e->watch_val[k]; }
	return got;
}

/*
 * THE RANGE IS CHECKED BEFORE ANY OF IT IS COPIED, and that is what makes the
 * contract above true rather than nearly true.
 *
 * `mem_rd` is the interpreter's own path and it copies byte by byte, stopping
 * at the first page the guest does not have - so by the time it refuses, the
 * bytes before the hole are already in the caller's buffer. The interpreter
 * does not care: a refusal there ends the run. A MODULE does care, because a
 * module reads a span it is about to search or parse, and a refusal it does
 * not check leaves it looking at a mixture of new bytes and whatever the
 * buffer held before. Measured by tests/unit/emu_span_read.
 *
 * The check is per PAGE, not per byte, so a 4096-byte span costs two lookups
 * and the interpreter's hot path is not touched at all.
 *
 * THE NULL PAGE IS LEFT TO mem_rd. A read off a null pointer answers zeros by
 * design - see the note there - and pre-rejecting it as unmapped would undo
 * that.
 */
int kof_emu_read(struct kof_emu *e, uint64_t va, void *dst, unsigned n)
{
	uint64_t pg, last;

	if (!e || !dst)
		return 0;
	if (!n)
		return 1;
	if (va + n < va)                        /* the span wraps */
		return 0;
	if (!(va < KOF_EMU_PAGE && (uint64_t)n <= KOF_EMU_PAGE - va)) {
		last = (va + n - 1u) & ~(uint64_t)(KOF_EMU_PAGE - 1u);
		for (pg = va & ~(uint64_t)(KOF_EMU_PAGE - 1u);; pg += KOF_EMU_PAGE) {
			if (!page_lookup(e, pg)) {
				e->fault_va = pg < va ? va : pg;
				memcpy(e->fault_kind, "read", 5);
				return 0;
			}
			if (pg == last)
				break;
		}
	}
	return mem_rd(e, va, dst, n);
}

/*
 * Write into the guest before it runs, which is what a loader does and what
 * nothing else should.
 *
 * It goes through mem_wr rather than round the side of it, so a write to an
 * address the guest does not have fails here instead of silently landing
 * somewhere - and so a page this touches is marked written exactly as one the
 * guest touched would be.
 */
int kof_emu_write(struct kof_emu *e, uint64_t va, const void *src, unsigned n)
{
	return mem_wr(e, va, src, n);
}


void kof_emu_hop_add(struct kof_emu *e, uint64_t lo, uint64_t hi, int seen)
{
	if (!e || hi <= lo || e->n_hop >= KOF_EMU_EXEC_WATCH)
		return;
	e->hop[e->n_hop].lo = lo;
	e->hop[e->n_hop].hi = hi;
	e->hop[e->n_hop].seen = (uint8_t)(seen != 0);
	e->n_hop++;
}

/* The first instruction executed in a region nothing has run in yet. Returns
 * the region, marking it seen, or -1. */
static int hop_first(struct kof_emu *e, uint64_t rip)
{
	uint32_t i;

	for (i = 0; i < e->n_hop; i++)
		if (!e->hop[i].seen && rip >= e->hop[i].lo &&
		    rip < e->hop[i].hi) {
			e->hop[i].seen = 1;
			return (int)i;
		}
	return -1;
}

/* Where the image is, so the run can dump it at the moment it hands over. */
/* Arm the handover test - see the note where it fires. Off by default so a
 * caller that wants the old behaviour keeps it. */
void kof_emu_set_oep_watch(struct kof_emu *e, int on)
{
	if (e)
		e->oep_watch = on;
}

void kof_emu_set_image_range(struct kof_emu *e, uint64_t lo, uint64_t hi)
{
	if (e) {
		e->img_lo = lo;
		e->img_hi = hi;
	}
}

void kof_emu_set_stack_range(struct kof_emu *e, uint64_t lo, uint64_t hi)
{
	if (e && hi > lo) {
		e->stack_lo = lo;
		e->stack_hi = hi;
	}
}

void kof_emu_set_stub_range(struct kof_emu *e, uint64_t lo, uint64_t hi)
{
	if (e && hi > lo) {
		e->stub_lo = lo;
		e->stub_hi = hi;
	}
}

/* Where the ciphertext is, so the run can tell when it stops being ciphertext.
 * See the write path for what happens then. */
void kof_emu_watch_write(struct kof_emu *e, uint64_t lo, uint64_t hi)
{
	if (!e || hi <= lo || e->n_wwatch >= KOF_EMU_EXEC_WATCH)
		return;
	e->wwatch[e->n_wwatch].lo = lo;
	e->wwatch[e->n_wwatch].hi = hi;
	e->n_wwatch++;
}

/* 1 once anything has been written into one of those ranges. */
int kof_emu_write_seen(const struct kof_emu *e)
{
	return e ? e->wwatch_hit : 0;
}

void kof_emu_watch_insn(struct kof_emu *e, const uint8_t *bytes, unsigned n)
{
	if (!e)
		return;
	/*
	 * NO BYTES DISARMS, and a module needs that as much as it needs the
	 * watch. A run paused more times than the module is willing to look at
	 * still has to FINISH - what it decrypted is worth having whether or
	 * not the module could name it - and without a way to stop pausing the
	 * only exit was to abandon the machine ungathered. Measured: three of
	 * four Sality samples produced nothing at all for exactly that reason.
	 */
	if (!bytes || !n) {
		e->n_iw = 0;
		e->iw_len = 0;
		return;
	}
	if (n > KOF_EMU_INSN_WATCH_LEN || e->n_iw >= KOF_EMU_INSN_WATCH)
		return;
	memcpy(e->iw[e->n_iw].b, bytes, n);
	e->iw[e->n_iw].n = (uint8_t)n;
	e->n_iw++;
}

void kof_emu_watch_insn_len(struct kof_emu *e, unsigned len)
{
	if (e)
		e->iw_len = len;
}

/* Does the instruction about to run begin with a pattern a module named? */
static int iwatch_hit(const struct kof_emu *e, const uint8_t *b, unsigned len)
{
	uint32_t i;

	if (!e->n_iw)
		return 0;
	if (e->iw_len && len != e->iw_len)
		return 0;
	for (i = 0; i < e->n_iw; i++)
		if (len >= e->iw[i].n &&
		    !memcmp(b, e->iw[i].b, e->iw[i].n))
			return 1;
	return 0;
}

void kof_emu_watch_exec(struct kof_emu *e, uint64_t lo, uint64_t hi)
{
	if (!e || hi <= lo || e->n_xwatch >= KOF_EMU_EXEC_WATCH)
		return;
	e->xwatch[e->n_xwatch].lo = lo;
	e->xwatch[e->n_xwatch].hi = hi;
	e->n_xwatch++;
}

/* Is rip inside a watched region? The edge is what matters - see xw_was_in. */
static int xwatch_hit(const struct kof_emu *e, uint64_t rip)
{
	uint32_t i;

	for (i = 0; i < e->n_xwatch; i++)
		if (rip >= e->xwatch[i].lo && rip < e->xwatch[i].hi)
			return 1;
	return 0;
}

/*
 * Keep a copy of [va, va+len) if the run wrote any of it. Pages it never
 * touched are the file's own bytes and are already scannable from the file, so
 * a mapping with nothing written under it is not a payload and is skipped.
 */
static void snap_take(struct kof_emu *e, uint64_t va, uint64_t len)
{
	uint64_t base = va & ~(uint64_t)(KOF_EMU_PAGE - 1u), off, n;
	struct page *p;
	struct snap *s;
	int any = 0;

	len = (va - base) + len;
	n = (len + KOF_EMU_PAGE - 1u) & ~(uint64_t)(KOF_EMU_PAGE - 1u);
	if (!n || n > (uint64_t)e->n_pages * KOF_EMU_PAGE)
		return;
	for (off = 0; off < n; off += KOF_EMU_PAGE) {
		p = page_find(e, base + off);
		if (p && p->written) {
			any = 1;
			break;
		}
	}
	if (!any)
		return;
	/*
	 * Snapshots are copies, so they are the one thing here that can cost
	 * the host more memory than the guest was ever given: mprotect(PROT_EXEC)
	 * over written pages, in a loop, would copy the whole address space
	 * once per call. Bounded by both count and total bytes, because either
	 * alone leaves the other free - a thousand small ones, or one enormous
	 * one repeated.
	 */
	if (e->n_snap >= KOF_EMU_MAX_SNAP ||
	    e->snap_bytes + n > (uint64_t)e->max_pages * KOF_EMU_PAGE)
		return;
	if (e->n_snap == e->max_snap) {
		uint32_t m = e->max_snap ? e->max_snap * 2u : 8u;
		struct snap *t = realloc(e->snap, (size_t)m * sizeof *t);

		if (!t)
			return;
		e->snap = t;
		e->max_snap = m;
	}
	s = &e->snap[e->n_snap];
	s->bytes = malloc((size_t)n);
	if (!s->bytes)
		return;
	for (off = 0; off < n; off += KOF_EMU_PAGE) {
		p = page_find(e, base + off);
		if (p)
			memcpy(s->bytes + off, p->data, KOF_EMU_PAGE);
		else
			memset(s->bytes + off, 0, KOF_EMU_PAGE);
	}
	s->va = base;
	s->len = n;
	e->snap_bytes += n;
	e->n_snap++;
}

void kof_emu_snap_written(struct kof_emu *e)
{
	uint32_t it = 0;
	uint64_t va, len;
	const uint8_t *b;

	while (kof_emu_next_written(e, &it, &va, &b, &len))
		snap_take(e, va, len);
}


int kof_emu_next_snapshot(struct kof_emu *e, uint32_t *it, uint64_t *va,
			  const uint8_t **bytes, uint64_t *len)
{
	if (*it >= e->n_snap)
		return 0;
	*va    = e->snap[*it].va;
	*bytes = e->snap[*it].bytes;
	*len   = e->snap[*it].len;
	(*it)++;
	return 1;
}

/*
 * Roughly a cycle per instruction, which is what a real machine retires. The
 * number only has to keep the ratio between two readings believable.
 */
#define TSC_PER_INSN  1u

/* The jump a recognised delay loop is granted, doubling while it persists. */
#define TSC_SPIN_MIN  (1u << 16)
#define TSC_SPIN_AT   8u
/*
 * The widest gap between two clock reads that may still be called a wait.
 *
 * Not a tuning knob so much as the line between "looking busy" and "being
 * busy". Padding a delay loop is free - nops, dead arithmetic, an opaque
 * predicate - so any bound here can be padded past; what cannot be padded past
 * is the productivity test beside it, and this exists only so that a loop doing
 * thousands of instructions of genuine register work per iteration is left to
 * run at the honest rate.
 */
#define TSC_SPIN_GAP  4096u

static uint64_t tsc_read(struct kof_emu *e)
{
	uint64_t gap = e->insn - e->tsc_last_insn;
	/*
	 * A WAIT IS A READ THAT FOLLOWS NO PROGRESS, not a read that follows
	 * few instructions - see tsc_last_page.
	 *
	 * The instruction gap stays as a GUARD rather than as the test. A loop
	 * whose body is thousands of instructions of real computation and which
	 * happens to touch no new page is doing work, and its own timing
	 * condition will be satisfied at the honest rate soon enough; it is not
	 * something to hurry along. TSC_SPIN_GAP is far above any padding that
	 * is worth writing - the whole point of junk is that it is cheap - and
	 * far below a body that is actually computing something.
	 */
	int idle = e->last_new_page == e->tsc_last_page && gap < TSC_SPIN_GAP;

	e->tsc_last_page = e->last_new_page;
	if (idle) {
		/* Asked again having done nothing: a wait, not a measurement. */
		if (++e->tsc_spin > TSC_SPIN_AT) {
			uint32_t k = e->tsc_spin - TSC_SPIN_AT;

			e->tsc_skew += (uint64_t)TSC_SPIN_MIN <<
				       (k > 20u ? 20u : k);
		}
	} else {
		e->tsc_spin = 0;
	}
	e->tsc_last_insn = e->insn;
	return e->insn * TSC_PER_INSN + e->tsc_skew;
}

/* Nanoseconds, from the same clock. A tick is taken to be a nanosecond: the
 * unit is arbitrary and one that needs no conversion is one that cannot be
 * converted wrongly. */
static uint64_t tsc_ns(struct kof_emu *e)
{
	return tsc_read(e);
}

static uint64_t syscall_do(struct kof_emu *e, int *stop_out);
static uint64_t sysarg(const struct kof_emu *e, unsigned i);

static uint64_t do_syscall(struct kof_emu *e, int *stop_out)
{
	struct kof_emu_syscall *s;
	uint64_t ret;

	s = &e->syslog[e->n_syslog % KOF_EMU_SYSLOG];
	/* The number AS THE GUEST GAVE IT, not the translated one: a reader of
	 * the log is looking at a 32-bit program and expects to see i386
	 * numbers. What it was translated to is the dispatcher's business. */
	s->nr     = e->bits == 32 ? (e->gpr[KOF_EMU_RAX] & 0xffffffffu)
				  : e->gpr[KOF_EMU_RAX];
	s->arg[0] = e->bits == 32 ? (e->gpr[KOF_EMU_RBX] & 0xffffffffu)
				  : e->gpr[KOF_EMU_RDI];
	s->arg[1] = e->bits == 32 ? (e->gpr[KOF_EMU_RCX] & 0xffffffffu)
				  : e->gpr[KOF_EMU_RSI];
	s->arg[2] = e->bits == 32 ? (e->gpr[KOF_EMU_RDX] & 0xffffffffu)
				  : e->gpr[KOF_EMU_RDX];
	s->arg[3] = sysarg(e, 0);
	s->arg[4] = sysarg(e, 1);
	s->arg[5] = sysarg(e, 2);
	ret = syscall_do(e, stop_out);
	s->ret = ret;
	e->n_syslog++;
	return ret;
}


unsigned kof_emu_syscall_log(const struct kof_emu *e,
			     struct kof_emu_syscall *out, unsigned n)
{
	unsigned k, got = e->n_syslog < KOF_EMU_SYSLOG ? e->n_syslog : KOF_EMU_SYSLOG;
	uint32_t first = e->n_syslog - got;

	if (got > n)
		got = n;
	for (k = 0; k < got; k++)
		out[k] = e->syslog[(first + k) % KOF_EMU_SYSLOG];
	return got;
}

unsigned kof_emu_unknown_syscalls(const struct kof_emu *e, uint32_t *out,
				  unsigned n)
{
	unsigned k, got = e->n_unksys < n ? e->n_unksys : n;

	for (k = 0; k < got; k++)
		out[k] = e->unksys[k];
	return got;
}

unsigned kof_emu_trace(const struct kof_emu *e, uint64_t *out, unsigned n)
{
	uint64_t have = e->trace_n < KOF_EMU_TRACE ? e->trace_n : KOF_EMU_TRACE;
	unsigned k, got = (unsigned)(have < n ? have : n);

	for (k = 0; k < got; k++)
		out[k] = e->trace[(e->trace_n - got + k) % KOF_EMU_TRACE];
	return got;
}

const char *kof_emu_stop_name(enum kof_emu_stop s)
{
	switch (s) {
	case KOF_EMU_STOP_BUDGET:      return "budget";
	case KOF_EMU_STOP_EXIT:        return "exit";
	case KOF_EMU_STOP_HANDOFF:     return "handoff";
	case KOF_EMU_STOP_FAULT:       return "fault";
	case KOF_EMU_STOP_UNSUPPORTED: return "unsupported";
	case KOF_EMU_STOP_DECODE:      return "decode";
	case KOF_EMU_STOP_STALLED:     return "stalled";
	case KOF_EMU_STOP_INSN:        return "watched instruction";
	case KOF_EMU_STOP_QUIET:       return "decryption finished";
	}
	return "?";
}

/* ---- registers ------------------------------------------------------------
 *
 * x86 register writes are not uniform and the irregularity is load bearing: a
 * 32 bit write ZEROES the upper half, an 8 or 16 bit write PRESERVES it, and
 * AH/CH/DH/BH address byte one of the first four registers rather than byte
 * zero of the second four. Getting any of those wrong produces a stub that
 * runs for a while and then computes one wrong address.
 */
static uint64_t mask_of(unsigned bytes)
{
	return bytes >= 8 ? ~(uint64_t)0 : ((uint64_t)1 << (bytes * 8)) - 1u;
}

/* Sign-extend the low `bytes` bytes of v to 64 bits. */
static uint64_t sext(uint64_t v, unsigned bytes)
{
	uint64_t m;

	if (bytes >= 8)
		return v;
	m = (uint64_t)1 << (bytes * 8u - 1u);
	v &= mask_of(bytes);
	return (v ^ m) - m;
}


static uint64_t reg_rd(const struct kof_emu *e, unsigned r, unsigned bytes,
		       int high8)
{
	uint64_t v;

	if (high8)
		return (e->gpr[r & 3u] >> 8) & 0xffu;
	if (r >= KOF_EMU_NGPR)
		return 0;
	v = e->gpr[r];
	return bytes >= 8 ? v : v & mask_of(bytes);
}

static void reg_wr(struct kof_emu *e, unsigned r, unsigned bytes, int high8,
		   uint64_t v)
{
	if (high8) {
		unsigned i = r & 3u;

		e->gpr[i] = (e->gpr[i] & ~(uint64_t)0xff00) |
			    ((v & 0xffu) << 8);
		return;
	}
	if (r >= KOF_EMU_NGPR)
		return;
	if (bytes >= 8)
		e->gpr[r] = v;
	else if (bytes == 4)
		e->gpr[r] = v & 0xffffffffu;     /* zero extends - the one that bites */
	else
		e->gpr[r] = (e->gpr[r] & ~mask_of(bytes)) | (v & mask_of(bytes));
}

/* ---- flags ---------------------------------------------------------------- */

static int parity8(uint64_t v)
{
	unsigned x = (unsigned)(v & 0xffu), c = 0;

	while (x) { c ^= 1u; x &= x - 1u; }
	return !c;                                /* PF is set when EVEN */
}

/*
 * ---- THE UNDEFINED CORNER OF A 16 BIT DOUBLE SHIFT ------------------------
 *
 * SHRD and SHLD mask their count with 31, so a 16 bit form can be asked to
 * shift by 17..31 - past the operand size, where Intel calls the result
 * undefined. Real silicon still produces something, consistently, and
 * VMProtect uses exactly that as an anti-emulation trap: it folds the result
 * AND the flags into a rolling key, so an interpreter that invents either
 * value stops matching within a few instructions.
 *
 * THE VALUE IS NOT DERIVABLE. It is microarchitecture specific - XVolkolak's
 * XEmulator says so and solves it the same way, by running the instruction on
 * the host. This does that where the host is x86-64, which is the only place
 * the answer would be right anyway.
 *
 * Elsewhere the run stops on the instruction rather than guessing: a wrong
 * answer here is worse than no answer, because it is the guest's key that goes
 * wrong and the failure surfaces somewhere else entirely.
 */
#if defined(__x86_64__)
#define KOF_HOST_DSHIFT 1
static uint16_t host_dshift16(uint16_t dst, uint16_t src, uint8_t cnt,
			      int left, uint64_t *fl)
{
	uint16_t r = dst;
	uint64_t f = 0;

	if (left)
		__asm__ volatile ("shldw %%cl, %2, %0\n\t"
				  "pushfq\n\t"
				  "popq %1"
				  : "+r"(r), "=r"(f)
				  : "r"(src), "c"(cnt)
				  : "cc");
	else
		__asm__ volatile ("shrdw %%cl, %2, %0\n\t"
				  "pushfq\n\t"
				  "popq %1"
				  : "+r"(r), "=r"(f)
				  : "r"(src), "c"(cnt)
				  : "cc");
	*fl = f;
	return r;
}
#endif

static void fl_logic(struct kof_emu *e, uint64_t r, unsigned bytes)
{
	uint64_t m = mask_of(bytes);

	r &= m;
	e->flags &= ~(uint64_t)(FL_CF | FL_OF | FL_ZF | FL_SF | FL_PF | FL_AF);
	if (!r)                       e->flags |= FL_ZF;
	if (r >> (bytes * 8u - 1u))   e->flags |= FL_SF;
	if (parity8(r))               e->flags |= FL_PF;
}

static void fl_add(struct kof_emu *e, uint64_t a, uint64_t b, uint64_t cin,
		   unsigned bytes)
{
	uint64_t m = mask_of(bytes), r = (a + b + cin) & m;
	uint64_t sign = (uint64_t)1 << (bytes * 8u - 1u);

	fl_logic(e, r, bytes);
	if ((a & m) + (b & m) + cin > m)                       e->flags |= FL_CF;
	if (~((a ^ b)) & (a ^ r) & sign)                       e->flags |= FL_OF;
	if (((a & 0xfu) + (b & 0xfu) + cin) > 0xfu)            e->flags |= FL_AF;
}

static void fl_sub(struct kof_emu *e, uint64_t a, uint64_t b, uint64_t bin,
		   unsigned bytes)
{
	uint64_t m = mask_of(bytes), r = (a - b - bin) & m;
	uint64_t sign = (uint64_t)1 << (bytes * 8u - 1u);

	fl_logic(e, r, bytes);
	/* Borrow. The b+bin form overflows the mask only when b is all ones in
	 * the width and bin is 1 - at sz==8 that wraps to 0 and the naive a<0
	 * test misses a borrow that in fact always happens - so that one case is
	 * taken out before the comparison that would misread it. */
	if ((b & m) == m && bin)                               e->flags |= FL_CF;
	else if ((a & m) < (b & m) + bin)                      e->flags |= FL_CF;
	if ((a ^ b) & (a ^ r) & sign)                          e->flags |= FL_OF;
	if ((a & 0xfu) < (b & 0xfu) + bin)                     e->flags |= FL_AF;
}

static int cond_true(const struct kof_emu *e, unsigned cc)
{
	uint64_t f = e->flags;
	int r;

	switch (cc >> 1) {
	case 0: r = (f & FL_OF) != 0; break;                    /* O   */
	case 1: r = (f & FL_CF) != 0; break;                    /* B   */
	case 2: r = (f & FL_ZF) != 0; break;                    /* Z   */
	case 3: r = (f & (FL_CF | FL_ZF)) != 0; break;          /* BE  */
	case 4: r = (f & FL_SF) != 0; break;                    /* S   */
	case 5: r = (f & FL_PF) != 0; break;                    /* P   */
	case 6: r = ((f & FL_SF) != 0) != ((f & FL_OF) != 0); break;   /* L  */
	default: r = (((f & FL_SF) != 0) != ((f & FL_OF) != 0)) ||
		     (f & FL_ZF) != 0; break;                   /* LE  */
	}
	return (cc & 1u) ? !r : r;
}

/*
 * DOES THIS INSTRUCTION CHANGE ANYTHING AT ALL?
 *
 * ONLY THE FORMS THAT PROVABLY CANNOT, which is a short list and deliberately
 * so. `xchg eax, eax` and `mov edi, edi` write a register the value they just
 * read and touch no flag; NOP is the architecture saying the same thing. A
 * junk generator emits them by the dozen because they cost a disassembler a
 * line and cost the program nothing.
 *
 * NOT A DEAD-CODE ANALYSIS, and the difference is the whole safety of it.
 * Measured on a Sality decryption loop, these account for 8 of 256
 * instructions - about three percent. The other junk there is `imul`, `test`
 * and `lea` writing registers nothing reads again, and removing THOSE needs
 * liveness over three internal branches INCLUDING the flags; getting it wrong
 * produces a wrong answer silently, which is the one failure this interpreter
 * must not have. Three percent that is certain beats fifty that is not.
 *
 * A PREFIX DOES NOT MAKE IT ACTIVE. The same generator writes `rep` on
 * instructions that are not string operations, where the architecture ignores
 * it - eight more in the same loop. bddisasm reports the instruction it
 * really is, so those arrive here already stripped.
 */
static int nop_insn(const INSTRUX *ix)
{
	const ND_OPERAND *a, *b;

	if (ix->Instruction == ND_INS_NOP)
		return 1;
	if (ix->Instruction != ND_INS_MOV && ix->Instruction != ND_INS_XCHG)
		return 0;
	if (ix->OperandsCount < 2u)
		return 0;
	a = &ix->Operands[0];
	b = &ix->Operands[1];
	/*
	 * BOTH THE SAME GENERAL REGISTER, AT THE SAME WIDTH AND THE SAME HALF.
	 * `mov ah, al` is two different registers inside one; `mov eax, ax`
	 * is not even the same width. Neither is inert and neither is spelled
	 * differently from one that is.
	 */
	if (a->Type != ND_OP_REG || b->Type != ND_OP_REG)
		return 0;
	if (a->Info.Register.Type != ND_REG_GPR ||
	    b->Info.Register.Type != ND_REG_GPR)
		return 0;
	if (a->Info.Register.Reg != b->Info.Register.Reg)
		return 0;
	if (a->Info.Register.Size != b->Info.Register.Size)
		return 0;
	if (a->Info.Register.IsHigh8 != b->Info.Register.IsHigh8)
		return 0;
	/*
	 * AND NOT A 32-BIT WRITE IN 64-BIT MODE. `mov eax, eax` zeroes the top
	 * half of RAX on x86-64 - it is the shortest way to truncate a
	 * register, and treating it as a no-op loses half of a value.
	 */
	if (ix->DefCode == ND_CODE_64 && a->Info.Register.Size == 4u)
		return 0;
	return 1;
}

/* ---- operands -------------------------------------------------------------- */

static int ea_of(struct kof_emu *e, const INSTRUX *ix, const ND_OPERAND *op,
		 uint64_t *out)
{
	const ND_OPDESC_MEMORY *m = &op->Info.Memory;
	uint64_t a = 0;

	if (m->IsRipRel) {
		*out = e->rip + ix->Length + m->Disp;
		return 1;
	}
	if (m->HasBase)
		a += reg_rd(e, m->Base, m->BaseSize, 0);
	if (m->HasIndex)
		a += reg_rd(e, m->Index, m->IndexSize, 0) * (m->Scale ? m->Scale : 1u);
	if (m->HasDisp)
		a += m->Disp;
	/*
	 * FS AND GS ARE A BASE, NOT A REFUSAL.
	 *
	 * A Go-built packer sets its thread pointer with arch_prctl and then
	 * addresses everything through fs:. Refusing the segment stopped Ezuri
	 * 48 instructions in - the runtime saw arch_prctl fail and executed its
	 * own deliberate trap. There is one thread here, so one base each is all
	 * a segment means.
	 */
	if (m->HasSeg) {
		if (m->Seg == 4)
			a += e->fs_base;
		else if (m->Seg == 5)
			a += e->gs_base;
	}
	/*
	 * A 32-bit process computes addresses in 32 bits: a base+disp that runs
	 * past 4 GB wraps rather than reaching into a 64-bit address space the
	 * guest does not have. RIP-relative returned above and does not reach
	 * here, so nothing 64-bit is masked by mistake.
	 */
	if (e->bits == 32)
		a &= 0xffffffffu;
	*out = a;
	return 1;
}

/* ---- the x87 stack ---------------------------------------------------------
 *
 * See `st` in struct kof_emu for what is modelled and what is not.
 */

#define FSW_C0 (1u << 8)
#define FSW_C1 (1u << 9)
#define FSW_C2 (1u << 10)
#define FSW_C3 (1u << 14)

/*
 * The 80-bit extended format, which is the one x87 stores to memory when a
 * guest asks for `tbyte ptr`. Sign and a 15-bit exponent in the top two bytes,
 * and a 64-bit mantissa WITH ITS LEADING ONE WRITTEN OUT - unlike every other
 * IEEE format, where that bit is implied. So the value is simply
 * mantissa * 2^(exponent - 16383 - 63), and no bit has to be put back.
 */
static double f80_rd(const uint8_t *b)
{
	uint64_t m = 0;
	unsigned i, e16 = (unsigned)b[8] | ((unsigned)b[9] << 8);
	int ex = (int)(e16 & 0x7fffu), sign = (int)(e16 >> 15);
	double v;

	for (i = 0; i < 8u; i++)
		m |= (uint64_t)b[i] << (8u * i);
	if (ex == 0x7fff) {
		/* Infinity when only the explicit leading one is set, and a NaN
		 * otherwise. Both are values a guest can store and reload. */
		v = (m << 1) ? (double)NAN : (double)INFINITY;
		return sign ? -v : v;
	}
	if (!ex && !m)
		return sign ? -0.0 : 0.0;
	v = ldexp((double)m, ex - 16383 - 63);
	return sign ? -v : v;
}

static void f80_wr(uint8_t *b, double v)
{
	unsigned e16 = 0;
	uint64_t m = 0;
	int sign = 0, ex;

	if (signbit(v)) {
		sign = 1;
		v = -v;
	}
	if (isnan(v)) {
		e16 = 0x7fffu;
		m = 0xc000000000000000ull;
	} else if (isinf(v)) {
		e16 = 0x7fffu;
		m = 0x8000000000000000ull;
	} else if (v != 0.0) {
		double f = frexp(v, &ex);       /* v = f * 2^ex, 0.5 <= f < 1 */

		m = (uint64_t)ldexp(f, 64);     /* so 2^63 <= m < 2^64 */
		e16 = (unsigned)(ex - 1 + 16383) & 0x7fffu;
	}
	{
		unsigned i;

		for (i = 0; i < 8u; i++)
			b[i] = (uint8_t)(m >> (8u * i));
	}
	e16 |= (unsigned)sign << 15;
	b[8] = (uint8_t)e16;
	b[9] = (uint8_t)(e16 >> 8);
}

static double st_get(const struct kof_emu *e, unsigned i)
{
	return e->st[(e->st_top + i) & 7u];
}

static void st_set(struct kof_emu *e, unsigned i, double v)
{
	unsigned k = (e->st_top + i) & 7u;

	e->st[k] = v;
	e->st_tag[k] = 1;
}

static void st_push(struct kof_emu *e, double v)
{
	e->st_top = (uint8_t)((e->st_top - 1u) & 7u);
	e->st[e->st_top] = v;
	e->st_tag[e->st_top] = 1;
}

static void st_pop(struct kof_emu *e)
{
	e->st_tag[e->st_top] = 0;
	e->st_top = (uint8_t)((e->st_top + 1u) & 7u);
}

/*
 * One x87 source operand as a double. `is_int` picks how a MEMORY operand is
 * read - the instruction says which, not the operand: FILD's m32 and FLD's m32
 * are the same four bytes and mean different numbers.
 */
static int fp_rd(struct kof_emu *e, const INSTRUX *ix, const ND_OPERAND *op,
		 int is_int, double *out)
{
	uint64_t ea;
	uint8_t b[10];
	unsigned n = op->Size;

	if (op->Type == ND_OP_REG) {
		if (op->Info.Register.Type != ND_REG_FPU)
			return 0;
		*out = st_get(e, op->Info.Register.Reg);
		return 1;
	}
	if (op->Type != ND_OP_MEM || !ea_of(e, ix, op, &ea))
		return 0;
	if (n != 2u && n != 4u && n != 8u && n != 10u)
		return 0;
	if (!mem_rd(e, ea, b, n))
		return 0;
	if (is_int) {
		int64_t v = 0;
		unsigned i;

		for (i = 0; i < n; i++)
			v |= (int64_t)((uint64_t)b[i] << (8u * i));
		/* Sign extended from its own width, because that is what the
		 * integer formats are - m16int, m32int, m64int. */
		if (n < 8u && (b[n - 1u] & 0x80u))
			v |= (int64_t)(~(uint64_t)0 << (8u * n));
		*out = (double)v;
		return 1;
	}
	if (n == 4u) {
		uint32_t u = (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
			     ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
		float f;

		memcpy(&f, &u, 4);
		*out = (double)f;
		return 1;
	}
	if (n == 8u) {
		double d;

		memcpy(&d, b, 8);
		*out = d;
		return 1;
	}
	if (n == 10u) {
		*out = f80_rd(b);
		return 1;
	}
	return 0;
}

/* And one destination. Same rule about `is_int`. */
static int fp_wr(struct kof_emu *e, const INSTRUX *ix, const ND_OPERAND *op,
		 int is_int, double v)
{
	uint64_t ea;
	uint8_t b[10];
	unsigned n = op->Size, i;

	if (op->Type == ND_OP_REG) {
		if (op->Info.Register.Type != ND_REG_FPU)
			return 0;
		st_set(e, op->Info.Register.Reg, v);
		return 1;
	}
	if (op->Type != ND_OP_MEM || !ea_of(e, ix, op, &ea))
		return 0;
	if (is_int) {
		int64_t q;

		if (n != 2u && n != 4u && n != 8u)
			return 0;
		/*
		 * OUT OF RANGE IS THE "INDEFINITE" VALUE, which is what the
		 * hardware stores rather than wrapping: the most negative
		 * integer of the destination's width. A guest that stores a
		 * huge float into a word gets that on a real CPU too.
		 */
		if (!(v >= -9.2233720368547758e18) || !(v <= 9.2233720368547758e18))
			q = (int64_t)0x8000000000000000ull;
		else
			q = (int64_t)v;
		for (i = 0; i < n; i++)
			b[i] = (uint8_t)((uint64_t)q >> (8u * i));
		return mem_wr(e, ea, b, n);
	}
	if (n == 4u) {
		float f = (float)v;
		uint32_t u;

		memcpy(&u, &f, 4);
		for (i = 0; i < 4u; i++)
			b[i] = (uint8_t)(u >> (8u * i));
		return mem_wr(e, ea, b, 4u);
	}
	if (n == 8u) {
		memcpy(b, &v, 8);
		return mem_wr(e, ea, b, 8u);
	}
	if (n == 10u) {
		f80_wr(b, v);
		return mem_wr(e, ea, b, 10u);
	}
	return 0;
}

/* The three condition codes a compare leaves in the status word. */
static void fp_cmp_cc(struct kof_emu *e, double a, double b)
{
	e->fsw &= (uint16_t)~(FSW_C0 | FSW_C2 | FSW_C3);
	if (isnan(a) || isnan(b))
		e->fsw |= (uint16_t)(FSW_C0 | FSW_C2 | FSW_C3);
	else if (a < b)
		e->fsw |= FSW_C0;
	else if (a == b)
		e->fsw |= FSW_C3;
}


/*
 * THE SEGMENT SELECTORS A WINDOWS USER MODE THREAD ACTUALLY HAS.
 *
 * Not decoration and not invented: a protector reads CS to tell a 64-bit
 * process from a 32-bit one under WOW64 - 0x33 against 0x23 - and reads DS or
 * ES to check it is in the flat model it expects. `mov bx, ds` is what stopped
 * two samples here, an MPRESS one and a Themida one, at thirteen million
 * instructions each.
 *
 * The bases are a separate matter and stay where they are: FS on 32-bit and GS
 * on 64-bit point at the TEB through kof_emu_set_seg_base, and everything else
 * is flat. This returns the SELECTOR, which is the number the guest sees.
 *
 * bddisasm numbers them ES, CS, SS, DS, FS, GS - the same order
 * kof_emu_set_seg_base is called with.
 */
static uint64_t seg_selector(const struct kof_emu *e, unsigned r)
{
	static const uint16_t sel64[6] = {
		0x002bu, 0x0033u, 0x002bu, 0x002bu, 0x0053u, 0x002bu
	};
	static const uint16_t sel32[6] = {
		0x0023u, 0x001bu, 0x0023u, 0x0023u, 0x003bu, 0x0000u
	};

	if (r >= 6u)
		return 0;
	return e->bits == 32 ? sel32[r] : sel64[r];
}

static int op_rd(struct kof_emu *e, const INSTRUX *ix, const ND_OPERAND *op,
		 uint64_t *out)
{
	unsigned sz = op->Size ? op->Size : 8u;

	switch (op->Type) {
	case ND_OP_REG:
		if (op->Info.Register.Type == ND_REG_SEG) {
			*out = seg_selector(e, op->Info.Register.Reg);
			return 1;
		}
		if (op->Info.Register.Type != ND_REG_GPR)
			return 0;
		*out = reg_rd(e, op->Info.Register.Reg, op->Info.Register.Size,
			      op->Info.Register.IsHigh8);
		return 1;
	case ND_OP_IMM:
		*out = op->Info.Immediate.Imm;
		return 1;
	case ND_OP_CONST:
		*out = op->Info.Constant.Const;
		return 1;
	case ND_OP_OFFS:
		*out = e->rip + ix->Length + op->Info.RelativeOffset.Rel;
		return 1;
	case ND_OP_MEM: {
		uint64_t ea, v = 0;

		if (!ea_of(e, ix, op, &ea))
			return 0;
		if (sz > 8)
			return 0;                 /* vector width: not carried */
		if (!mem_rd(e, ea, &v, sz))
			return 0;
		*out = v;
		return 1;
	}
	default:
		return 0;
	}
}

/*
 * Read a vector operand into `buf`, returning its width in bytes. A register
 * operand wider than 16 is a YMM/ZMM this does not keep, and is refused rather
 * than silently truncated to its low half.
 */
static int vec_rd(struct kof_emu *e, const INSTRUX *ix, const ND_OPERAND *op,
		  uint8_t *buf, unsigned *sz)
{
	unsigned n = op->Size ? op->Size : 16u;

	if (n > 16)
		return 0;
	memset(buf, 0, 16);
	switch (op->Type) {
	case ND_OP_REG:
		if (op->Info.Register.Type == ND_REG_SSE) {
			if (op->Info.Register.Reg >= 16)
				return 0;
			memcpy(buf, e->xmm[op->Info.Register.Reg], n);
		} else if (op->Info.Register.Type == ND_REG_MMX) {
			if (op->Info.Register.Reg >= 8 || n > 8)
				return 0;
			memcpy(buf, e->mmx[op->Info.Register.Reg], n);
		} else if (op->Info.Register.Type == ND_REG_GPR) {
			uint64_t v = reg_rd(e, op->Info.Register.Reg,
					    op->Info.Register.Size, 0);

			memcpy(buf, &v, n > 8 ? 8u : n);
		} else {
			return 0;
		}
		*sz = n;
		return 1;
	case ND_OP_MEM: {
		uint64_t ea;

		if (!ea_of(e, ix, op, &ea) || !mem_rd(e, ea, buf, n))
			return 0;
		*sz = n;
		return 1;
	}
	default:
		return 0;
	}
}

/*
 * Write `sz` bytes back. Writing a vector register always clears what is above
 * the bytes written, which is what the non-VEX encodings do for the 128-bit
 * register this keeps.
 */
static int vec_wr(struct kof_emu *e, const INSTRUX *ix, const ND_OPERAND *op,
		  const uint8_t *buf, unsigned sz)
{
	unsigned n = op->Size ? op->Size : 16u;

	if (n > 16 || sz > 16)
		return 0;
	if (n > sz)
		n = sz;
	switch (op->Type) {
	case ND_OP_REG:
		if (op->Info.Register.Type == ND_REG_SSE) {
			if (op->Info.Register.Reg >= 16)
				return 0;
			memset(e->xmm[op->Info.Register.Reg], 0, 16);
			memcpy(e->xmm[op->Info.Register.Reg], buf, n);
			return 1;
		}
		if (op->Info.Register.Type == ND_REG_MMX) {
			/*
			 * A 64-bit register, so a 4-byte MOVD clears the top
			 * half rather than leaving what was there - which is
			 * what the instruction does and what makes the pair
			 * `movd mm, r32` / `movd r32, mm` a faithful round
			 * trip.
			 */
			if (op->Info.Register.Reg >= 8 || n > 8)
				return 0;
			memset(e->mmx[op->Info.Register.Reg], 0, 8);
			memcpy(e->mmx[op->Info.Register.Reg], buf, n);
			return 1;
		}
		if (op->Info.Register.Type == ND_REG_GPR) {
			uint64_t v = 0;

			memcpy(&v, buf, n > 8 ? 8u : n);
			reg_wr(e, op->Info.Register.Reg,
			       op->Info.Register.Size, 0, v);
			return 1;
		}
		return 0;
	case ND_OP_MEM: {
		uint64_t ea;

		if (!ea_of(e, ix, op, &ea))
			return 0;
		return mem_wr(e, ea, buf, n);
	}
	default:
		return 0;
	}
}

static int op_wr(struct kof_emu *e, const INSTRUX *ix, const ND_OPERAND *op,
		 uint64_t v)
{
	unsigned sz = op->Size ? op->Size : 8u;

	switch (op->Type) {
	case ND_OP_REG:
		if (op->Info.Register.Type != ND_REG_GPR)
			return 0;
		reg_wr(e, op->Info.Register.Reg, op->Info.Register.Size,
		       op->Info.Register.IsHigh8, v);
		return 1;
	case ND_OP_MEM: {
		uint64_t ea;

		if (!ea_of(e, ix, op, &ea))
			return 0;
		if (sz > 8)
			return 0;
		return mem_wr(e, ea, &v, sz);
	}
	default:
		return 0;
	}
}

/*
 * A push is one machine word, and how wide that is is the mode - see
 * kof_emu.bits. Getting this wrong is not a small error: every call, every
 * return address and every GetPC trick reads the stack at the width the code
 * wrote it, so a 32-bit stub on an 8-byte stack loses its own address on the
 * first `call`.
 */
static unsigned wordsz(const struct kof_emu *e)
{
	return e->bits == 32 ? 4u : 8u;
}

/*
 * THE STACK MOVES BY THE OPERAND SIZE, NOT BY THE WORD SIZE.
 *
 * A 16-bit PUSH or POP - `push word ptr [rsi]`, `pop ax`, `push r10w`, any of
 * them written with the 0x66 prefix - moves RSP by TWO. This used to move it
 * by eight in 64-bit mode and four in 32-bit, which is what the default
 * operand size would be, and for ordinary code that is the same number.
 *
 * It is not the same number for code that pushes a word on purpose, and an
 * obfuscator does. Measured on an MPRESS sample, its resolver read the export
 * ordinal it had just looked up and hid it behind a constant:
 *
 *      push  word ptr [rsi]          ; the ordinal, 3
 *      push  r10w
 *      mov   r10w, 0x7db2
 *      add   word ptr [rsp+2], r10w  ; hide it
 *      pop   r10w
 *      push  word ptr [rsp]
 *      pop   ax
 *      sub   ax, 0x7db2              ; and take it back
 *      shl   rax, 2
 *
 * With an eight-byte push the `[rsp+2]` in the middle addresses a slot that is
 * not the ordinal, so the value added was never taken back: `sub ax, 0x7db2`
 * ran on 3 rather than on 0x7db5 and produced 0x8251, the shift made that
 * 0x20944, and the resolver read its function table at that offset instead of
 * at 12. It got a zero, added it to the module base, and called the module's
 * MZ header. Everything after that - 310000 instructions of it - was this
 * arithmetic.
 *
 * PUSH imm8 is not a two-byte push: its operand is one byte and the value is
 * sign extended to the stack width, so only a size of exactly two is special.
 */
static int push_w(struct kof_emu *e, uint64_t v, unsigned w)
{
	if (w != 2u)
		w = wordsz(e);
	e->gpr[KOF_EMU_RSP] -= w;
	if (wordsz(e) == 4u)
		e->gpr[KOF_EMU_RSP] &= 0xffffffffu;
	return mem_wr(e, e->gpr[KOF_EMU_RSP], &v, w);
}

static int pop_w(struct kof_emu *e, uint64_t *v, unsigned w)
{
	uint64_t t = 0;

	if (w != 2u)
		w = wordsz(e);
	if (!mem_rd(e, e->gpr[KOF_EMU_RSP], &t, w))
		return 0;
	e->gpr[KOF_EMU_RSP] += w;
	if (wordsz(e) == 4u)
		e->gpr[KOF_EMU_RSP] &= 0xffffffffu;
	*v = t;
	return 1;
}

static int push(struct kof_emu *e, uint64_t v)
{
	return push_w(e, v, wordsz(e));
}

static int pop(struct kof_emu *e, uint64_t *v)
{
	return pop_w(e, v, wordsz(e));
}

/* ---- syscalls -------------------------------------------------------------
 *
 * The whole environment, and it is this short on purpose. A packer stub wants
 * memory and then it wants to hand over; everything else it asks for can be
 * answered with a plausible number, because nothing downstream of this module
 * depends on the answer being true. What matters is that the stub keeps going
 * far enough to write its payload.
 *
 * An unknown call returns -ENOSYS rather than stopping. A stub that checks is
 * rare, and a stub that stops because we stopped it learns more than one that
 * gets a refusal it was already coded to survive.
 */
/*
 * EMU_SYS_ RATHER THAN SYS_, AND THE PREFIX IS NOT DECORATION.
 *
 * mingw-w64's <stdio.h> defines SYS_OPEN - an MSVC-era constant for how many
 * files a process may have open - so an unprefixed enumerator here collided
 * with a macro from a header nothing in this file includes on purpose, and the
 * entire Windows build stopped: this object is inside libkofeng.a, so the
 * failure took the library, both tools that link it, and every test, on x86_64
 * and ARM64 alike.
 *
 * The names are this file's alone - nothing outside it refers to one - so the
 * prefix costs nothing and removes the whole class of collision rather than the
 * one instance of it. A guard around the include order would have fixed today's
 * symbol and left the next one to be found by a build that breaks.
 */
enum {
	EMU_SYS_READ = 0, EMU_SYS_WRITE = 1, EMU_SYS_OPEN = 2, EMU_SYS_CLOSE = 3,
	EMU_SYS_FSTAT = 5, EMU_SYS_LSEEK = 8,
	EMU_SYS_MMAP = 9, EMU_SYS_MPROTECT = 10, EMU_SYS_MUNMAP = 11, EMU_SYS_BRK = 12,
	EMU_SYS_PREAD64 = 17, EMU_SYS_FTRUNCATE = 77, EMU_SYS_READLINK = 89,
	EMU_SYS_ARCH_PRCTL = 158, EMU_SYS_EXECVE = 59, EMU_SYS_EXIT = 60, EMU_SYS_EXIT_GROUP = 231,
	EMU_SYS_OPENAT = 257, EMU_SYS_NEWFSTATAT = 262, EMU_SYS_MEMFD_CREATE = 319,
	EMU_SYS_IOCTL = 16, EMU_SYS_SCHED_YIELD = 24, EMU_SYS_NANOSLEEP = 35,
	EMU_SYS_GETPID = 39, EMU_SYS_CLONE = 56, EMU_SYS_RT_SIGACTION = 13,
	EMU_SYS_RT_SIGPROCMASK = 14, EMU_SYS_SIGALTSTACK = 131, EMU_SYS_GETTID = 186,
	EMU_SYS_FUTEX = 202, EMU_SYS_SCHED_GETAFFINITY = 204, EMU_SYS_SET_TID_ADDRESS = 218,
	EMU_SYS_CLOCK_GETTIME = 228, EMU_SYS_SET_ROBUST_LIST = 273, EMU_SYS_PRLIMIT64 = 302,
	EMU_SYS_GETRANDOM = 318, EMU_SYS_MADVISE = 28, EMU_SYS_TGKILL = 234,
	EMU_SYS_RSEQ = 334, EMU_SYS_SIGRETURN = 15,
	EMU_SYS_GETTIMEOFDAY = 96, EMU_SYS_TIME = 201, EMU_SYS_GETCPU = 309,
	EMU_SYS_CLOCK_NANOSLEEP = 230, EMU_SYS_ALARM = 37, EMU_SYS_SETITIMER = 38,
	EMU_SYS_TIMER_CREATE = 222, EMU_SYS_TIMER_SETTIME = 223, EMU_SYS_PTRACE = 101,
	EMU_SYS_PAUSE = 34, EMU_SYS_SELECT = 23, EMU_SYS_POLL = 7, EMU_SYS_KILL = 62,
	/*
	 * WHAT A STUB ASKS BEFORE IT UNPACKS ANYTHING.
	 *
	 * None of these move a byte of payload, and that is exactly why they
	 * were worth adding: a packer asks who it is running as, on what
	 * kernel, with how much memory and from where, and -ENOSYS to any of
	 * them is an answer no real Linux ever gives. A stub that checks gets
	 * a louder signal from the refusal than it would from a slow machine -
	 * the same reasoning the sleep above is written under.
	 */
	EMU_SYS_UNAME = 63, EMU_SYS_GETUID = 102, EMU_SYS_GETGID = 104,
	EMU_SYS_GETEUID = 107, EMU_SYS_GETEGID = 108, EMU_SYS_GETPPID = 110,
	EMU_SYS_SYSINFO = 99, EMU_SYS_TIMES = 100, EMU_SYS_CLOCK_GETRES = 229,
	EMU_SYS_GETCWD = 79, EMU_SYS_PRCTL = 157, EMU_SYS_PERSONALITY = 135,
	EMU_SYS_GETRLIMIT = 97, EMU_SYS_SETRLIMIT = 160,
	EMU_SYS_ACCESS = 21, EMU_SYS_FACCESSAT = 269, EMU_SYS_FACCESSAT2 = 439,
	EMU_SYS_READLINKAT = 267, EMU_SYS_STAT = 4, EMU_SYS_LSTAT = 6,
	EMU_SYS_STATFS = 137, EMU_SYS_FSTATFS = 138,
	/*
	 * DESCRIPTORS, WHICH AN IN-MEMORY LOADER ACTUALLY USES.
	 *
	 * memfd_create, write the payload into it, dup it somewhere known,
	 * fexecve - that is the whole of a fileless ELF loader, and two of
	 * those four were already here. Every descriptor this emulator hands
	 * out names the same one file, so duplicating one is answering with a
	 * number; what matters is that the call succeeds.
	 */
	EMU_SYS_DUP = 32, EMU_SYS_DUP2 = 33, EMU_SYS_DUP3 = 292,
	EMU_SYS_FCNTL = 72, EMU_SYS_WRITEV = 20, EMU_SYS_READV = 19,
	EMU_SYS_PWRITE64 = 18, EMU_SYS_PIPE = 22, EMU_SYS_PIPE2 = 293,
	/* Growing a decompression buffer in place, which is what a stub does
	 * when it guessed the unpacked size too low. */
	EMU_SYS_MREMAP = 25
};

/*
 * A GUEST WORD, because half of these write a struct of longs and a long is
 * four bytes to a 32-bit guest.
 *
 * The stat above writes an amd64 struct whatever the guest is, which is safe
 * only because nothing reads past st_size. A struct of longs is different: a
 * 32-bit caller allocated half the bytes, so writing the 64-bit layout scribbles
 * past what it gave us - into its own heap, with the emulator as the corruptor.
 */
static unsigned gw(const struct kof_emu *e)
{
	return e->bits == 32 ? 4u : 8u;
}

/*
 * A stat, of the size the guest allocated for one.
 *
 * The only field anybody here reads is st_size - a stub asking how big it is -
 * and the rest stays zero. The SIZE matters though, and it used to not: this
 * wrote the 144-byte amd64 struct whatever the guest was, so a 32-bit caller
 * that allocated a 96-byte struct stat64 had forty-eight bytes of its own
 * memory overwritten by the emulator answering its question. st_size sits at a
 * different offset in each, which is the other half of the same fact.
 */
static uint64_t stat_out(struct kof_emu *e, uint64_t va);

/* Put one guest-sized word into a byte buffer and advance the cursor. */
static void gw_put(const struct kof_emu *e, uint8_t *b, unsigned *at, uint64_t v)
{
	if (gw(e) == 4u) {
		uint32_t w = (uint32_t)v;

		memcpy(b + *at, &w, 4);
		*at += 4u;
	} else {
		memcpy(b + *at, &v, 8);
		*at += 8u;
	}
}

static uint64_t stat_out(struct kof_emu *e, uint64_t va)
{
	uint8_t st[144];
	unsigned n   = e->bits == 32 ? 96u : 144u;
	unsigned off = e->bits == 32 ? 44u : 48u;

	memset(st, 0, sizeof st);
	memcpy(st + off, &e->self_n, 8);
	if (!mem_wr(e, va, st, n))
		return (uint64_t)-14;
	return 0;
}

/* The descriptor an emulated process gets for itself, and for anything else it
 * opens - there is only one file here and pretending otherwise would need a
 * filesystem nobody is going to write. */
#define EMU_SELF_FD  3

static uint64_t self_read(struct kof_emu *e, uint64_t va, uint64_t off,
			  uint64_t want)
{
	uint64_t n;

	if (!e->self || off >= e->self_n)
		return 0;
	n = e->self_n - off;
	if (n > want)
		n = want;
	if (!mem_wr(e, va, e->self + off, (unsigned)(n > 4096u ? 4096u : n)))
		return (uint64_t)-14;                           /* EFAULT */
	/* Written in page-sized bites so a large read cannot be half applied
	 * and then fail; the loop is here rather than in mem_wr because only
	 * this caller has a length the stub chose. */
	{
		uint64_t done = n > 4096u ? 4096u : n;

		while (done < n) {
			uint64_t chunk = n - done > 4096u ? 4096u : n - done;

			if (!mem_wr(e, va + done, e->self + off + done,
				    (unsigned)chunk))
				break;
			done += chunk;
		}
		return done;
	}
}

/* Where an mmap with no hint lands. High, and far from anything an ELF asks
 * for, so a stub that stores a returned pointer cannot be confused with one
 * that computed an address inside its own image. */
#define EMU_MMAP_BASE  0x00007f0000000000ull

/*
 * THE i386 SYSCALL NUMBERS THE STUBS HERE ACTUALLY USE, translated to the
 * amd64 ones the dispatcher below is written in.
 *
 * The two tables are unrelated - i386 write is 4 and amd64 write is 1 - so a
 * 32-bit stub run against the amd64 dispatcher asks for whatever happens to
 * share its number, which is worse than not running it at all: exit(1) on i386
 * is number 1, and amd64 number 1 is write. Translated rather than duplicated,
 * because what the syscalls DO is identical and only their numbering is not.
 *
 * A number with no row here returns -ENOSYS through the dispatcher's default,
 * the same as an unknown amd64 one. It is not the whole i386 table and does not
 * need to be.
 *
 * What it DOES need to be is as wide as the dispatcher, and it was not. This
 * table was written from the stubs measured when 32-bit mode was added, and the
 * dispatcher has grown since without it following: counted, the dispatcher
 * answered 52 numbers meaningfully and this table could reach 24 of them, so 28
 * considered answers sat unreachable from 32-bit code. Some of those matter to
 * what this interpreter is for - openat is what modern code calls instead of
 * open, fstat64 is how a stub finds its own size, clock_gettime is the timing
 * check the amd64 side deliberately answers - and a stub asking for one got
 * -ENOSYS while its 64-bit twin was served.
 *
 * The rows below are the ones whose numbers were read out of
 * asm/unistd_32.h rather than remembered. Anything still missing is missing on
 * purpose or has simply not been met yet; the gap to close was never "the whole
 * table", it was "everything this file already knows how to answer".
 */
static uint64_t i386_nr(uint64_t nr)
{
	switch (nr) {
	case 1:   return EMU_SYS_EXIT;
	case 2:   return EMU_SYS_GETPID;        /* fork; nothing here forks */
	/*
	 * THE ROWS ADDED WITH THE CALLS THEY REACH - see the note above about
	 * the two tables drifting apart. Numbers read out of asm/unistd_32.h.
	 *
	 * The *64 variants are DELIBERATELY ABSENT where their struct differs
	 * from the one the dispatcher writes: i386 stat64 and statfs64 carry
	 * 64-bit fields that a guest-word layout would fill wrongly, and a
	 * wrongly filled struct is worse than -ENOSYS because the guest
	 * believes it. The 16-bit id calls are absent for the same reason in
	 * reverse - nothing modern asks for them.
	 */
	case 21:  return EMU_SYS_ACCESS;
	case 22:  return EMU_SYS_PIPE;
	case 25:  return EMU_SYS_GETPID;        /* stime; not ours to set */
	case 33:  return EMU_SYS_ACCESS;
	case 41:  return EMU_SYS_DUP;
	case 42:  return EMU_SYS_PIPE;
	case 43:  return EMU_SYS_TIMES;
	case 55:  return EMU_SYS_FCNTL;
	case 63:  return EMU_SYS_DUP2;
	case 64:  return EMU_SYS_GETPPID;
	case 75:  return EMU_SYS_SETRLIMIT;
	case 76:  return EMU_SYS_GETRLIMIT;
	case 99:  return EMU_SYS_STATFS;
	case 100: return EMU_SYS_FSTATFS;
	case 116: return EMU_SYS_SYSINFO;
	case 122: return EMU_SYS_UNAME;
	case 136: return EMU_SYS_PERSONALITY;
	case 145: return EMU_SYS_READV;
	case 146: return EMU_SYS_WRITEV;
	case 163: return EMU_SYS_MREMAP;
	case 172: return EMU_SYS_PRCTL;
	case 181: return EMU_SYS_PWRITE64;
	case 183: return EMU_SYS_GETCWD;
	case 191: return EMU_SYS_GETRLIMIT;     /* ugetrlimit */
	case 199: return EMU_SYS_GETUID;
	case 200: return EMU_SYS_GETGID;
	case 201: return EMU_SYS_GETEUID;
	case 202: return EMU_SYS_GETEGID;
	case 221: return EMU_SYS_FCNTL;         /* fcntl64 */
	case 266: return EMU_SYS_CLOCK_GETRES;
	case 305: return EMU_SYS_READLINKAT;
	case 307: return EMU_SYS_FACCESSAT;
	case 330: return EMU_SYS_DUP3;
	case 331: return EMU_SYS_PIPE2;
	case 439: return EMU_SYS_FACCESSAT2;
	case 3:   return EMU_SYS_READ;
	case 4:   return EMU_SYS_WRITE;
	case 5:   return EMU_SYS_OPEN;
	case 6:   return EMU_SYS_CLOSE;
	case 11:  return EMU_SYS_EXECVE;
	case 13:  return EMU_SYS_TIME;
	case 19:  return EMU_SYS_LSEEK;
	case 20:  return EMU_SYS_GETPID;
	case 45:  return EMU_SYS_BRK;
	case 54:  return EMU_SYS_IOCTL;
	case 78:  return EMU_SYS_GETTIMEOFDAY;
	case 90:  return EMU_SYS_MMAP;          /* old_mmap, via a struct */
	case 91:  return EMU_SYS_MUNMAP;
	case 93:  return EMU_SYS_FTRUNCATE;
	case 125: return EMU_SYS_MPROTECT;
	case 85:  return EMU_SYS_READLINK;      /* /proc/self/exe             */
	case 120: return EMU_SYS_CLONE;
	case 158: return EMU_SYS_SCHED_YIELD;
	case 162: return EMU_SYS_NANOSLEEP;
	case 192: return EMU_SYS_MMAP;          /* mmap2 */
	case 174: return EMU_SYS_RT_SIGACTION;
	case 175: return EMU_SYS_RT_SIGPROCMASK;
	case 180: return EMU_SYS_PREAD64;
	case 197: return EMU_SYS_FSTAT;        /* fstat64; only st_size is read */
	case 219: return EMU_SYS_MADVISE;
	case 224: return EMU_SYS_GETTID;
	case 240: return EMU_SYS_FUTEX;
	case 242: return EMU_SYS_SCHED_GETAFFINITY;
	case 265: return EMU_SYS_CLOCK_GETTIME;
	case 267: return EMU_SYS_CLOCK_NANOSLEEP;
	case 270: return EMU_SYS_TGKILL;
	case 295: return EMU_SYS_OPENAT;
	case 26:  return EMU_SYS_PTRACE;
	case 252: return EMU_SYS_EXIT_GROUP;
	case 355: return EMU_SYS_GETRANDOM;
	case 356: return EMU_SYS_MEMFD_CREATE;
	default:  return nr | (1ull << 32);  /* no such i386 call: cannot collide */
	}
}


/* ---- the Windows environment ----------------------------------------------
 *
 * WHY THERE IS ONE AT ALL, GIVEN WHAT kofemu.h SAYS ABOUT SYSCALLS.
 *
 * The Linux environment above is short because a packer stub "wants memory and
 * then it wants to hand over". A Windows stub wants the same two things and
 * cannot ask for them the same way: there is no syscall it may use, so it asks
 * kernel32, and to ask kernel32 it must first find it. That is the whole of
 * what this provides - a kernel32 to find, and answers to the handful of calls
 * a stub makes once it has.
 *
 * WHAT SAID IT WAS WORTH BUILDING. Four Themida protected PEs, measured: each
 * ran between 22 and 48 million instructions of its own arithmetic and then
 * stopped, three of them fetching from an address inside their own .idata -
 * an import thunk the Windows loader fills before the entry point runs and
 * which nothing here had filled. Every one of the four imports exactly one
 * function, kernel32!GetModuleHandleA, which is a protector's way of saying
 * "give me the base and I will find the rest myself".
 *
 * SO THE EXPORT DIRECTORY IS THE POINT, not the import thunk. Filling the
 * thunk alone answers the first call and nothing after it; a loader that has
 * the base walks the exports by name. emu_unpack.c builds an image with a real
 * export directory whose every entry points at a stub below.
 *
 * HOW A STUB REACHES HERE. Each exported function is eight bytes that load an
 * id and trap - `syscall` on 64 bit, `int 0x80` on 32 - so the dispatch this
 * file already has for Linux carries these too. The ids are checked BEFORE the
 * i386 translation and sit in a range no kernel uses, so an ELF guest cannot
 * reach them by accident and a Windows guest cannot reach a Linux syscall by
 * accident either.
 */
#define WIN_API_BASE   0x57494e00u      /* 'W','I','N',0 */

enum {
	WIN_GetModuleHandleA = 0,
	WIN_GetModuleHandleW,
	WIN_GetProcAddress,
	WIN_LoadLibraryA,
	WIN_LoadLibraryW,
	WIN_VirtualAlloc,
	WIN_VirtualFree,
	WIN_VirtualProtect,
	WIN_ExitProcess,
	WIN_GetCurrentProcess,
	WIN_IsDebuggerPresent,
	WIN_GetLastError,
	WIN_SetLastError,
	WIN_GetVersion,
	WIN_GetCurrentProcessId,
	WIN_GetTickCount,
	WIN_AddVectoredExceptionHandler,
	WIN_RemoveVectoredExceptionHandler,
	WIN_GetProcessHeap,
	WIN_HeapAlloc,
	WIN_HeapFree,
	WIN_HeapReAlloc,
	WIN_HeapSize,
	WIN_VirtualQuery,
	WIN_GetSystemInfo,
	WIN_Sleep,
	WIN_QueryPerformanceCounter,
	WIN_QueryPerformanceFrequency,
	WIN_GetSystemTimeAsFileTime,
	WIN_GetCurrentThreadId,
	WIN_GetCurrentThread,
	WIN_TlsAlloc,
	WIN_TlsGetValue,
	WIN_TlsSetValue,
	WIN_TlsFree,
	WIN_InitializeCriticalSection,
	WIN_EnterCriticalSection,
	WIN_LeaveCriticalSection,
	WIN_DeleteCriticalSection,
	WIN_FlushInstructionCache,
	WIN_GetStdHandle,
	WIN_CloseHandle,
	WIN_SetUnhandledExceptionFilter,
	WIN_GetModuleFileNameA,
	WIN_GetModuleFileNameW,
	WIN_GetCommandLineA,
	WIN_GetCommandLineW,
	WIN_lstrlenA,
	WIN_RtlAddFunctionTable,
	WIN_RtlAllocateHeap,
	WIN_RtlFreeHeap,
	WIN_NtQueryInformationProcess,
	WIN_FreeLibrary,
	WIN_LocalAlloc,
	WIN_LocalFree,
	WIN_GlobalAlloc,
	WIN_GlobalFree,
	WIN_lstrcmpA,
	WIN_lstrcmpiA,
	WIN_lstrcpyA,
	WIN_lstrcatA,
	WIN_lstrlenW,
	WIN_MultiByteToWideChar,
	WIN_WideCharToMultiByte,
	WIN_OutputDebugStringA,
	WIN_SetErrorMode,
	WIN_GetStartupInfoA,
	WIN_GetStartupInfoW,
	WIN_GetSystemDirectoryA,
	WIN_GetWindowsDirectoryA,
	WIN_GetTempPathA,
	WIN_GetFileAttributesA,
	WIN_CreateFileA,
	WIN_ReadFile,
	WIN_WriteFile,
	WIN_SetFilePointer,
	WIN_GetFileSize,
	WIN_CreateThread,
	WIN_ResumeThread,
	WIN_WaitForSingleObject,
	WIN_TerminateProcess,
	WIN_RaiseException,
	WIN_UnhandledExceptionFilter,
	WIN_InterlockedIncrement,
	WIN_InterlockedDecrement,
	WIN_NtProtectVirtualMemory,
	WIN_NtAllocateVirtualMemory,
	WIN_RtlGetVersion,
	WIN_LdrLoadDll,
	WIN_LdrGetProcedureAddress,
	WIN_InitializeCriticalSectionAndSpinCount,
	WIN_IsProcessorFeaturePresent,
	WIN_IsValidCodePage,
	WIN_IsBadReadPtr,
	WIN_IsBadWritePtr,
	WIN_InterlockedExchange,
	WIN_InterlockedCompareExchange,
	WIN_SetHandleCount,
	WIN_SetStdHandle,
	WIN_SetEnvironmentVariableA,
	WIN_SetEnvironmentVariableW,
	WIN_SetConsoleCtrlHandler,
	WIN_FreeEnvironmentStringsA,
	WIN_FreeEnvironmentStringsW,
	WIN_FlushFileBuffers,
	WIN_FindClose,
	WIN_DecodePointer,
	WIN_EncodePointer,
	WIN_DeleteFileA,
	WIN_DisableThreadLibraryCalls,
	WIN_HeapCreate,
	WIN_HeapDestroy,
	WIN_GetCPInfo,
	WIN_GetACP,
	WIN_GetOEMCP,
	WIN_IsUserAnAdmin,
	WIN_SHGetFolderPathA,
	WIN_CoInitialize,
	WIN_CoUninitialize,
	/*
	 * THE COUNT COMES FROM THE ENUM AND THE ENUM IS CHECKED AGAINST THE
	 * TABLE, because writing it by hand is how this broke.
	 *
	 * WIN_API_COUNT was a literal, the table grew by 34 entries and the
	 * literal was set to 53 for 52 of them, and the one-past read crashed
	 * the scanner in win_eq_nocase against a name pointer that was never
	 * written. The header already says of the table that "a table in each
	 * place is a table that disagrees after the first edit"; a hand
	 * written length is the same mistake one step smaller.
	 */
	WIN_API__LAST
};

#define WIN_API_COUNT ((unsigned)WIN_API__LAST)

/*
 * THE NAMES AND THE ARGUMENT COUNTS, IN ONE PLACE BECAUSE TWO READERS NEED
 * THEM TO AGREE.
 *
 * This file dispatches on the id; emu_unpack.c writes an export directory that
 * maps each NAME to the stub for that id, and writes the stub, which on i386
 * must end in `ret n` with n the argument count because Windows makes the
 * callee pop. A table in each place is a table that disagrees after the first
 * edit, so there is one and it is exported.
 */
static const struct {
	uint8_t     mod;        /* an index into win_mod below */
	const char *name;
	uint8_t     argc;
} win_api[] = {
	{ KOF_EMU_WIN_MOD_K32, "GetModuleHandleA",    1 },
	{ KOF_EMU_WIN_MOD_K32, "GetModuleHandleW",    1 },
	{ KOF_EMU_WIN_MOD_K32, "GetProcAddress",      2 },
	{ KOF_EMU_WIN_MOD_K32, "LoadLibraryA",        1 },
	{ KOF_EMU_WIN_MOD_K32, "LoadLibraryW",        1 },
	{ KOF_EMU_WIN_MOD_K32, "VirtualAlloc",        4 },
	{ KOF_EMU_WIN_MOD_K32, "VirtualFree",         3 },
	{ KOF_EMU_WIN_MOD_K32, "VirtualProtect",      4 },
	{ KOF_EMU_WIN_MOD_K32, "ExitProcess",         1 },
	{ KOF_EMU_WIN_MOD_K32, "GetCurrentProcess",   0 },
	{ KOF_EMU_WIN_MOD_K32, "IsDebuggerPresent",   0 },
	{ KOF_EMU_WIN_MOD_K32, "GetLastError",        0 },
	{ KOF_EMU_WIN_MOD_K32, "SetLastError",        1 },
	{ KOF_EMU_WIN_MOD_K32, "GetVersion",          0 },
	{ KOF_EMU_WIN_MOD_K32, "GetCurrentProcessId", 0 },
	{ KOF_EMU_WIN_MOD_K32, "GetTickCount",        0 },
	{ KOF_EMU_WIN_MOD_K32, "AddVectoredExceptionHandler",    2 },
	{ KOF_EMU_WIN_MOD_K32, "RemoveVectoredExceptionHandler", 1 },
	{ KOF_EMU_WIN_MOD_K32, "GetProcessHeap",       0 },
	{ KOF_EMU_WIN_MOD_K32, "HeapAlloc",            3 },
	{ KOF_EMU_WIN_MOD_K32, "HeapFree",             3 },
	{ KOF_EMU_WIN_MOD_K32, "HeapReAlloc",          4 },
	{ KOF_EMU_WIN_MOD_K32, "HeapSize",             3 },
	{ KOF_EMU_WIN_MOD_K32, "VirtualQuery",         3 },
	{ KOF_EMU_WIN_MOD_K32, "GetSystemInfo",        1 },
	{ KOF_EMU_WIN_MOD_K32, "Sleep",                1 },
	{ KOF_EMU_WIN_MOD_K32, "QueryPerformanceCounter",   1 },
	{ KOF_EMU_WIN_MOD_K32, "QueryPerformanceFrequency", 1 },
	{ KOF_EMU_WIN_MOD_K32, "GetSystemTimeAsFileTime",   1 },
	{ KOF_EMU_WIN_MOD_K32, "GetCurrentThreadId",   0 },
	{ KOF_EMU_WIN_MOD_K32, "GetCurrentThread",     0 },
	{ KOF_EMU_WIN_MOD_K32, "TlsAlloc",             0 },
	{ KOF_EMU_WIN_MOD_K32, "TlsGetValue",          1 },
	{ KOF_EMU_WIN_MOD_K32, "TlsSetValue",          2 },
	{ KOF_EMU_WIN_MOD_K32, "TlsFree",              1 },
	{ KOF_EMU_WIN_MOD_K32, "InitializeCriticalSection", 1 },
	{ KOF_EMU_WIN_MOD_K32, "EnterCriticalSection", 1 },
	{ KOF_EMU_WIN_MOD_K32, "LeaveCriticalSection", 1 },
	{ KOF_EMU_WIN_MOD_K32, "DeleteCriticalSection", 1 },
	{ KOF_EMU_WIN_MOD_K32, "FlushInstructionCache", 3 },
	{ KOF_EMU_WIN_MOD_K32, "GetStdHandle",         1 },
	{ KOF_EMU_WIN_MOD_K32, "CloseHandle",          1 },
	{ KOF_EMU_WIN_MOD_K32, "SetUnhandledExceptionFilter", 1 },
	{ KOF_EMU_WIN_MOD_K32, "GetModuleFileNameA",   3 },
	{ KOF_EMU_WIN_MOD_K32, "GetModuleFileNameW",   3 },
	{ KOF_EMU_WIN_MOD_K32, "GetCommandLineA",      0 },
	{ KOF_EMU_WIN_MOD_K32, "GetCommandLineW",      0 },
	{ KOF_EMU_WIN_MOD_K32, "lstrlenA",             1 },
	/*
	 * ntdll's, and RtlAddFunctionTable is the one that matters on amd64:
	 * a protector that generates code at run time registers an unwind
	 * table for it, and a call that goes nowhere is a call through a null
	 * pointer. Answering "done" is truthful here in the only sense that
	 * matters - there is no unwinder in this build for the table to feed.
	 */
	{ KOF_EMU_WIN_MOD_NTDLL, "RtlAddFunctionTable",       3 },
	{ KOF_EMU_WIN_MOD_NTDLL, "RtlAllocateHeap",           3 },
	{ KOF_EMU_WIN_MOD_NTDLL, "RtlFreeHeap",               3 },
	{ KOF_EMU_WIN_MOD_NTDLL, "NtQueryInformationProcess", 5 },
	{ KOF_EMU_WIN_MOD_K32, "FreeLibrary",           1 },
	{ KOF_EMU_WIN_MOD_K32, "LocalAlloc",            2 },
	{ KOF_EMU_WIN_MOD_K32, "LocalFree",             1 },
	{ KOF_EMU_WIN_MOD_K32, "GlobalAlloc",           2 },
	{ KOF_EMU_WIN_MOD_K32, "GlobalFree",            1 },
	{ KOF_EMU_WIN_MOD_K32, "lstrcmpA",              2 },
	{ KOF_EMU_WIN_MOD_K32, "lstrcmpiA",             2 },
	{ KOF_EMU_WIN_MOD_K32, "lstrcpyA",              2 },
	{ KOF_EMU_WIN_MOD_K32, "lstrcatA",              2 },
	{ KOF_EMU_WIN_MOD_K32, "lstrlenW",              1 },
	{ KOF_EMU_WIN_MOD_K32, "MultiByteToWideChar",   6 },
	{ KOF_EMU_WIN_MOD_K32, "WideCharToMultiByte",   8 },
	{ KOF_EMU_WIN_MOD_K32, "OutputDebugStringA",    1 },
	{ KOF_EMU_WIN_MOD_K32, "SetErrorMode",          1 },
	{ KOF_EMU_WIN_MOD_K32, "GetStartupInfoA",       1 },
	{ KOF_EMU_WIN_MOD_K32, "GetStartupInfoW",       1 },
	{ KOF_EMU_WIN_MOD_K32, "GetSystemDirectoryA",   2 },
	{ KOF_EMU_WIN_MOD_K32, "GetWindowsDirectoryA",  2 },
	{ KOF_EMU_WIN_MOD_K32, "GetTempPathA",          2 },
	{ KOF_EMU_WIN_MOD_K32, "GetFileAttributesA",    1 },
	{ KOF_EMU_WIN_MOD_K32, "CreateFileA",           7 },
	{ KOF_EMU_WIN_MOD_K32, "ReadFile",              5 },
	{ KOF_EMU_WIN_MOD_K32, "WriteFile",             5 },
	{ KOF_EMU_WIN_MOD_K32, "SetFilePointer",        4 },
	{ KOF_EMU_WIN_MOD_K32, "GetFileSize",           2 },
	{ KOF_EMU_WIN_MOD_K32, "CreateThread",          6 },
	{ KOF_EMU_WIN_MOD_K32, "ResumeThread",          1 },
	{ KOF_EMU_WIN_MOD_K32, "WaitForSingleObject",   2 },
	{ KOF_EMU_WIN_MOD_K32, "TerminateProcess",      2 },
	{ KOF_EMU_WIN_MOD_K32, "RaiseException",        4 },
	{ KOF_EMU_WIN_MOD_K32, "UnhandledExceptionFilter", 1 },
	{ KOF_EMU_WIN_MOD_K32, "InterlockedIncrement",  1 },
	{ KOF_EMU_WIN_MOD_K32, "InterlockedDecrement",  1 },
	{ KOF_EMU_WIN_MOD_NTDLL, "NtProtectVirtualMemory",   5 },
	{ KOF_EMU_WIN_MOD_NTDLL, "NtAllocateVirtualMemory",  6 },
	{ KOF_EMU_WIN_MOD_NTDLL, "RtlGetVersion",            1 },
	{ KOF_EMU_WIN_MOD_NTDLL, "LdrLoadDll",               4 },
	{ KOF_EMU_WIN_MOD_NTDLL, "LdrGetProcedureAddress",   4 },
	{ KOF_EMU_WIN_MOD_K32, "InitializeCriticalSectionAndSpinCount", 2 },
	{ KOF_EMU_WIN_MOD_K32, "IsProcessorFeaturePresent", 1 },
	{ KOF_EMU_WIN_MOD_K32, "IsValidCodePage",         1 },
	{ KOF_EMU_WIN_MOD_K32, "IsBadReadPtr",            2 },
	{ KOF_EMU_WIN_MOD_K32, "IsBadWritePtr",           2 },
	{ KOF_EMU_WIN_MOD_K32, "InterlockedExchange",     2 },
	{ KOF_EMU_WIN_MOD_K32, "InterlockedCompareExchange", 3 },
	{ KOF_EMU_WIN_MOD_K32, "SetHandleCount",          1 },
	{ KOF_EMU_WIN_MOD_K32, "SetStdHandle",            2 },
	{ KOF_EMU_WIN_MOD_K32, "SetEnvironmentVariableA", 2 },
	{ KOF_EMU_WIN_MOD_K32, "SetEnvironmentVariableW", 2 },
	{ KOF_EMU_WIN_MOD_K32, "SetConsoleCtrlHandler",   2 },
	{ KOF_EMU_WIN_MOD_K32, "FreeEnvironmentStringsA", 1 },
	{ KOF_EMU_WIN_MOD_K32, "FreeEnvironmentStringsW", 1 },
	{ KOF_EMU_WIN_MOD_K32, "FlushFileBuffers",        1 },
	{ KOF_EMU_WIN_MOD_K32, "FindClose",               1 },
	{ KOF_EMU_WIN_MOD_K32, "DecodePointer",           1 },
	{ KOF_EMU_WIN_MOD_K32, "EncodePointer",           1 },
	{ KOF_EMU_WIN_MOD_K32, "DeleteFileA",             1 },
	{ KOF_EMU_WIN_MOD_K32, "DisableThreadLibraryCalls", 1 },
	{ KOF_EMU_WIN_MOD_K32, "HeapCreate",              3 },
	{ KOF_EMU_WIN_MOD_K32, "HeapDestroy",             1 },
	{ KOF_EMU_WIN_MOD_K32, "GetCPInfo",               2 },
	{ KOF_EMU_WIN_MOD_K32, "GetACP",                  0 },
	{ KOF_EMU_WIN_MOD_K32, "GetOEMCP",                0 },
	{ KOF_EMU_WIN_MOD_SHELL32, "IsUserAnAdmin",       0 },
	{ KOF_EMU_WIN_MOD_SHELL32, "SHGetFolderPathA",    5 },
	{ KOF_EMU_WIN_MOD_OLE32, "CoInitialize",          1 },
	{ KOF_EMU_WIN_MOD_OLE32, "CoUninitialize",        0 },
};

/*
 * THE MODULES, AND WHY THERE IS MORE THAN ONE.
 *
 * kernel32 alone was enough to get a protector started and not to keep it
 * going. Measured with KOF_WIN_TRACE on one of the Themida samples: it takes
 * the kernel32 base, and then asks for five more libraries in a row -
 * user32, advapi32, ntdll, shell32, shlwapi - is told no to every one, and
 * dereferences one of the zeros it was given. The fault it stopped on was
 * never an exception to be handled; it was a module that was not there.
 *
 * A MODULE IS AN IMAGE, not an entry in a list, for the reason build_k32_pe
 * gives: a resolver that has a base walks the export directory at it. Each one
 * therefore gets its own image and its own stubs INSIDE that image, so that an
 * address resolved from a module falls within that module's range - which a
 * careful resolver checks, and which a shared stub page would fail.
 *
 * An empty module is still worth having. It answers "yes, loaded, here it is",
 * which is what the guest is testing for, and a name it then fails to resolve
 * comes back zero from a directory that really does not list it - the same
 * answer the real library would give for a name that is not in it.
 */
static const struct {
	const char *name;
	uint64_t    base64, base32;
} win_mod[KOF_EMU_WIN_MOD_COUNT] = {
	{ "kernel32.dll", 0x0000000180000000ull, 0x76000000ull },
	{ "ntdll.dll",    0x0000000181000000ull, 0x77000000ull },
	{ "user32.dll",   0x0000000182000000ull, 0x75000000ull },
	{ "advapi32.dll", 0x0000000183000000ull, 0x74000000ull },
	{ "shell32.dll",  0x0000000184000000ull, 0x73000000ull },
	{ "shlwapi.dll",  0x0000000185000000ull, 0x72000000ull },
	{ "msvcrt.dll",   0x0000000186000000ull, 0x71000000ull },
	{ "ole32.dll",    0x0000000187000000ull, 0x70000000ull },
	{ "kernelbase.dll", 0x0000000188000000ull, 0x6f000000ull }
};

_Static_assert(sizeof win_api / sizeof win_api[0] == (size_t)WIN_API__LAST,
	       "the Windows API table and its enum have drifted apart");

unsigned    kof_emu_win_api_count(void) { return WIN_API_COUNT; }
const char *kof_emu_win_api_name(unsigned i)
{
	return i < WIN_API_COUNT ? win_api[i].name : 0;
}
unsigned    kof_emu_win_api_argc(unsigned i)
{
	return i < WIN_API_COUNT ? win_api[i].argc : 0;
}
unsigned    kof_emu_win_api_mod(unsigned i)
{
	return i < WIN_API_COUNT ? win_api[i].mod : 0;
}
uint32_t    kof_emu_win_api_trap(unsigned i) { return WIN_API_BASE + i; }

unsigned    kof_emu_win_mod_count(void) { return KOF_EMU_WIN_MOD_COUNT; }
const char *kof_emu_win_mod_name(unsigned i)
{
	return i < KOF_EMU_WIN_MOD_COUNT ? win_mod[i].name : 0;
}
uint64_t    kof_emu_win_mod_base(unsigned i, unsigned bits)
{
	if (i >= KOF_EMU_WIN_MOD_COUNT)
		return 0;
	return bits == 32u ? win_mod[i].base32 : win_mod[i].base64;
}

/*
 * Where an export sits INSIDE its own module: the stubs of one module are
 * numbered from zero within it, so the n-th function of user32 is at user32's
 * stub base plus n, not at the global index.
 */
unsigned kof_emu_win_api_slot(unsigned i)
{
	unsigned k, slot = 0;

	if (i >= WIN_API_COUNT)
		return 0;
	for (k = 0; k < i; k++)
		if (win_api[k].mod == win_api[i].mod)
			slot++;
	return slot;
}

void kof_emu_win_setup(struct kof_emu *e, uint64_t image_base)
{
	e->win_image_base = image_base;
}

void kof_emu_win_set_heap(struct kof_emu *e, uint64_t heap)
{
	e->win_heap = heap;
}

void kof_emu_count_mod_reads(struct kof_emu *e, int on)
{
	e->count_mod_reads = (uint8_t)(on != 0);
}

/* When the run first left the section it started in, and where it went. The
 * number says how much of a budget is spent reaching a stage a static unpacker
 * may already have produced. */
int kof_emu_itrace(struct kof_emu *e, unsigned n)
{
	if (!e)
		return 0;
	free(e->itr);
	e->itr = NULL;
	e->itr_cap = e->itr_n = 0;
	if (!n)
		return 1;
	if (n > KOF_EMU_ITRACE_MAX)
		n = KOF_EMU_ITRACE_MAX;
	e->itr = calloc(n, sizeof *e->itr);
	if (!e->itr)
		return 0;
	e->itr_cap = n;
	e->itr_frozen = 0;
	return 1;
}

void kof_emu_itrace_at(struct kof_emu *e, uint64_t rip)
{
	if (e)
		e->itr_at = rip;
}

void kof_emu_itrace_until(struct kof_emu *e, uint64_t insn)
{
	if (e)
		e->itr_until = insn;
}

/* Or at the first import this environment could not resolve, which is upstream
 * of every wrong value that follows it. */
void kof_emu_itrace_on_null(struct kof_emu *e, int on)
{
	if (e)
		e->itr_on_null = on;
}

unsigned kof_emu_itrace_count(const struct kof_emu *e)
{
	if (!e || !e->itr)
		return 0;
	return e->itr_n < e->itr_cap ? e->itr_n : e->itr_cap;
}

/* Oldest first, so a caller reading 0..count-1 reads them in the order they
 * ran - which is the only order in which "where did that value come from"
 * can be answered. */
int kof_emu_itrace_get(const struct kof_emu *e, unsigned k, uint64_t *rip,
		       const char **text, const uint64_t **gpr)
{
	unsigned have = kof_emu_itrace_count(e), at;

	if (!have || k >= have)
		return 0;
	at = e->itr_n <= e->itr_cap ? k
				    : (unsigned)((e->itr_n - have + k) %
						 e->itr_cap);
	if (rip)  *rip  = e->itr[at].rip;
	if (text) *text = e->itr[at].txt;
	if (gpr)  *gpr  = e->itr[at].gpr;
	return 1;
}

void kof_emu_first_hop(const struct kof_emu *e, uint64_t *insn, uint64_t *rip)
{
	if (insn) *insn = e->hop_first_insn;
	if (rip)  *rip  = e->hop_first_rip;
}

/* And the last one, which is where execution had got to when the run ended:
 * the address Unipacker's dump writes as the entry point. See THIRD-PARTY.md.
 * hop_count says how many stages there were, so one hop can be told from ten. */
void kof_emu_last_hop(const struct kof_emu *e, uint64_t *rip, uint32_t *count)
{
	if (rip)   *rip   = e->hop_last_rip;
	if (count) *count = e->hop_count;
}

uint64_t kof_emu_mod_reads(const struct kof_emu *e, unsigned i)
{
	return i < KOF_EMU_WIN_MOD_COUNT ? e->mod_reads[i] : 0;
}

void kof_emu_win_set_module(struct kof_emu *e, unsigned i, uint64_t base)
{
	if (i < KOF_EMU_WIN_MOD_COUNT)
		e->win_mod_base[i] = base;
	if (i == KOF_EMU_WIN_MOD_K32)
		e->win_k32_base = base;
}

static int win_eq_nocase(const char *a, const char *b)
{
	for (; *a && *b; a++, b++) {
		char x = *a, y = *b;

		if (x >= 'A' && x <= 'Z') x = (char)(x + 32);
		if (y >= 'A' && y <= 'Z') y = (char)(y + 32);
		if (x != y)
			return 0;
	}
	return *a == *b;
}

/*
 * The address of an exported function by name, which is three things at once:
 * what GetProcAddress answers with, what an export directory has to point at,
 * and what an import thunk has to be filled with. Public for the third, since
 * filling the thunks is the loader's job and emu_unpack.c is the loader here.
 */
uint64_t kof_emu_win_addr_of(struct kof_emu *e, const char *name)
{
	unsigned i;

	for (i = 0; i < WIN_API_COUNT; i++) {
		uint64_t base;

		if (!win_eq_nocase(win_api[i].name, name))
			continue;
		base = e->win_mod_base[win_api[i].mod];
		if (!base)
			return 0;       /* that module was not mapped */
		return base + KOF_EMU_WIN_STUB_RVA +
		       (uint64_t)kof_emu_win_api_slot(i) * KOF_EMU_WIN_STUB;
	}
	return 0;
}

/* A module handle by name, which is what GetModuleHandle and LoadLibrary both
 * come down to. */
static uint64_t win_mod_of(struct kof_emu *e, const char *name)
{
	unsigned i;

	for (i = 0; i < KOF_EMU_WIN_MOD_COUNT; i++) {
		const char *n = win_mod[i].name;
		unsigned len = (unsigned)strlen(n);

		if (win_eq_nocase(n, name))
			return e->win_mod_base[i];
		/* "kernel32" for "kernel32.dll": a guest may leave the suffix
		 * off and Windows supplies it. */
		if (len > 4u && !strncmp(n + len - 4u, ".dll", 4u)) {
			char bare[64];

			if (len - 4u < sizeof bare) {
				memcpy(bare, n, len - 4u);
				bare[len - 4u] = 0;
				if (win_eq_nocase(bare, name))
					return e->win_mod_base[i];
			}
		}
	}
	return 0;
}

/*
 * The calling conventions, and they are not the same one.
 *
 * amd64 Windows passes the first four in rcx, rdx, r8, r9 - a different set
 * from the System V order this file's Linux side reads. i386 Windows passes
 * them on the stack, and the CALLEE pops them, which is why the stubs end in
 * `ret n` rather than `ret` and why the argument count has to be known here as
 * well as there.
 */
static uint64_t win_arg(struct kof_emu *e, unsigned i)
{
	static const unsigned r64[4] = {
		KOF_EMU_RCX, KOF_EMU_RDX, KOF_EMU_R8, KOF_EMU_R9
	};
	uint64_t v = 0;

	if (e->bits == 32) {
		/* [esp] is the return address the stub's caller pushed. */
		if (!mem_rd(e, (e->gpr[KOF_EMU_RSP] + 4u + 4u * i) & 0xffffffffu,
			    &v, 4u))
			return 0;
		return v;
	}
	if (i < 4u)
		return e->gpr[r64[i]];
	if (!mem_rd(e, e->gpr[KOF_EMU_RSP] + 8u + 8u * i, &v, 8u))
		return 0;
	return v;
}

/* A NUL terminated guest string into a host buffer, bounded and always
 * terminated. A pointer that faults yields the empty string rather than a
 * failure: a stub asking for a module by a name it cannot read is asking for
 * nothing, and "not found" is the honest answer to that. */
static void win_str(struct kof_emu *e, uint64_t va, char *out, unsigned cap,
		    int wide)
{
	unsigned i;

	for (i = 0; i + 1u < cap; i++) {
		uint64_t c = 0;

		if (!mem_rd(e, va + (wide ? 2u * i : i), &c, wide ? 2u : 1u))
			break;
		if (!c)
			break;
		out[i] = (char)(c & 0xffu);
	}
	out[i] = 0;
}


/*
 * Reserve guest memory, the way the Linux side's mmap does and from the same
 * arena - one allocator, so a guest that somehow used both could not be handed
 * the same page twice.
 */
/*
 * THE ARENA IS ITS OWN, AND THAT IS AN ANTI-EMULATION POINT RATHER THAN
 * TIDINESS.
 *
 * EMU_MMAP_BASE is 0x7f0000000000, which is where LINUX puts an mmap. Windows
 * does not: a VirtualAlloc comes back low, and a guest that stores the pointer,
 * or compares it against its own image base, or simply truncates it into a
 * 32-bit field it declared, learns something true about the machine it is on
 * and false about the machine it is meant to be on. A protector looking for
 * exactly that is the reason this number is not shared.
 */
#define EMU_WINALLOC_BASE 0x0000000030000000ull
/* The largest single reservation this will make. A guest with a real use for
 * more than this is not one a short interpreted run is going to finish. */
#define EMU_WINALLOC_MAX  (256ull << 20)

static uint64_t win_alloc(struct kof_emu *e, uint64_t want, unsigned prot)
{
	uint64_t len;
	uint64_t at;

	/*
	 * THE SIZE IS A NUMBER THE GUEST CHOSE, so it is bounded before it is
	 * rounded. `want + PAGE - 1` wraps to a small value for a request near
	 * 2^64, which would then map a few pages and report success - and the
	 * guest would write far past them. The ceiling is the arena itself:
	 * nothing this interpreter runs has any use for a gigabyte, and a
	 * refusal is an answer a caller already has to handle.
	 */
	if (!want || want > EMU_WINALLOC_MAX)
		return 0;
	len = (want + KOF_EMU_PAGE - 1u) & ~(uint64_t)(KOF_EMU_PAGE - 1u);
	if (!len)
		return 0;
	if (!e->winmap_next)
		e->winmap_next = EMU_WINALLOC_BASE;
	at = e->winmap_next;
	/* A guard page between mappings, so a guest that runs off the end of
	 * one faults here rather than scribbling on the next - the same reason
	 * the Linux mmap leaves one. */
	e->winmap_next += len + KOF_EMU_PAGE;
	if (!vma_add(e, at, len, 0, prot & 7u, 0))
		return 0;
	return at;
}

/*
 * The 32-bit arena, which cannot be the 64-bit one: EMU_MMAP_BASE is above
 * 4 GB, so a 32-bit guest storing the pointer truncates it and then writes to
 * an address nothing mapped. The same reasoning as STACK_TOP_32 in
 * emu_unpack.c, and the same class of bug it was written for.
 */
#define EMU_MMAP_BASE_32 0x20000000ull

static uint64_t win_alloc32(struct kof_emu *e, uint64_t want, unsigned prot)
{
	uint64_t len;
	uint64_t at;

	if (!want || want > EMU_WINALLOC_MAX)
		return 0;               /* see win_alloc on why this is first */
	len = (want + KOF_EMU_PAGE - 1u) & ~(uint64_t)(KOF_EMU_PAGE - 1u);
	if (!len)
		return 0;
	if (!e->mmap32_next)
		e->mmap32_next = EMU_MMAP_BASE_32;
	at = e->mmap32_next;
	e->mmap32_next += len + KOF_EMU_PAGE;
	if (at + len > 0xfffff000ull)
		return 0;
	if (!vma_add(e, at, len, 0, prot & 7u, 0))
		return 0;
	return at;
}

/*
 * PAGE_* to this emulator's three bits. Anything with an EXECUTE in it gets X,
 * anything writable gets W, and everything readable gets R - the distinctions
 * Windows draws that this does not (guard pages, write-combine, no-cache) are
 * about caching and faulting behaviour rather than about what the memory is.
 */
static unsigned win_prot(uint64_t p)
{
	unsigned r = 0;

	switch (p & 0xffu) {
	case 0x01: r = 0; break;                                  /* NOACCESS */
	case 0x02: r = KOF_EMU_R; break;                          /* READONLY */
	case 0x04: r = KOF_EMU_R | KOF_EMU_W; break;              /* READWRITE */
	case 0x08: r = KOF_EMU_R | KOF_EMU_W; break;              /* WRITECOPY */
	case 0x10: r = KOF_EMU_X; break;                          /* EXECUTE */
	case 0x20: r = KOF_EMU_R | KOF_EMU_X; break;              /* E_READ */
	case 0x40: r = KOF_EMU_R | KOF_EMU_W | KOF_EMU_X; break;  /* E_RW */
	case 0x80: r = KOF_EMU_R | KOF_EMU_W | KOF_EMU_X; break;  /* E_WC */
	default:   r = KOF_EMU_R | KOF_EMU_W; break;
	}
	return r;
}


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
/* A handle for the process heap: distinct, non-zero, and never dereferenced. */
/* The process heap handle IS its address: Windows hands back a pointer to the
 * HEAP structure, and a guest that reads Flags through it is reading memory
 * rather than interpreting a token. A made-up token faults the moment it is
 * dereferenced - which is what 0x18 did. */

static uint64_t win_ret_magic(const struct kof_emu *e)
{
	(void)e;
	return WIN_RET_MAGIC;
}

static int win_exc_ready(struct kof_emu *e)
{
	uint64_t base = WIN_EXC_BASE;

	if (e->exc_base)
		return 1;
	if (!vma_add(e, base, (uint64_t)WIN_EXC_PAGES * KOF_EMU_PAGE, 0,
		     KOF_EMU_R | KOF_EMU_W, 0))
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
	KOF_EMU_RDI, KOF_EMU_RSI, KOF_EMU_RBX,
	KOF_EMU_RDX, KOF_EMU_RCX, KOF_EMU_RAX
};
/* amd64 CONTEXT, from CTX64_RAX: rax rcx rdx rbx rsp rbp rsi rdi r8..r15. */
static const unsigned ctx64_ord[16] = {
	KOF_EMU_RAX, KOF_EMU_RCX, KOF_EMU_RDX, KOF_EMU_RBX,
	KOF_EMU_RSP, KOF_EMU_RBP, KOF_EMU_RSI, KOF_EMU_RDI,
	KOF_EMU_R8,  KOF_EMU_R9,  KOF_EMU_R10, KOF_EMU_R11,
	KOF_EMU_R12, KOF_EMU_R13, KOF_EMU_R14, KOF_EMU_R15
};

static void ctx_save(struct kof_emu *e, uint64_t ctx)
{
	uint8_t zero[CTX64_SIZE];
	unsigned i;

	memset(zero, 0, sizeof zero);
	mem_wr(e, ctx, zero, e->bits == 32 ? CTX32_SIZE : CTX64_SIZE);

	if (e->bits == 32) {
		uint32_t flags = 0x0001003fu;   /* CONTEXT_FULL, i386 */
		uint32_t v;

		mem_wr(e, ctx + CTX32_FLAGS, &flags, 4u);
		for (i = 0; i < 6u; i++) {
			v = (uint32_t)e->gpr[ctx32_ord[i]];
			mem_wr(e, ctx + CTX32_EDI + 4u * i, &v, 4u);
		}
		v = (uint32_t)e->gpr[KOF_EMU_RBP];
		mem_wr(e, ctx + CTX32_EDI + 4u * 6u, &v, 4u);   /* Ebp */
		v = (uint32_t)e->rip;
		mem_wr(e, ctx + CTX32_EIP, &v, 4u);
		v = (uint32_t)e->flags;
		mem_wr(e, ctx + CTX32_EFLAGS, &v, 4u);
		v = (uint32_t)e->gpr[KOF_EMU_RSP];
		mem_wr(e, ctx + CTX32_ESP, &v, 4u);
		return;
	}
	{
		uint32_t flags = 0x0010000bu;   /* CONTEXT_FULL, amd64 */
		uint32_t ef = (uint32_t)e->flags;
		uint64_t v;

		mem_wr(e, ctx + CTX64_FLAGS, &flags, 4u);
		mem_wr(e, ctx + CTX64_EFLAGS, &ef, 4u);
		for (i = 0; i < 16u; i++) {
			v = e->gpr[ctx64_ord[i]];
			mem_wr(e, ctx + CTX64_RAX + 8u * i, &v, 8u);
		}
		v = e->rip;
		mem_wr(e, ctx + CTX64_RIP, &v, 8u);
	}
}

static void ctx_load(struct kof_emu *e, uint64_t ctx)
{
	unsigned i;
	uint64_t v = 0;

	if (e->bits == 32) {
		for (i = 0; i < 6u; i++)
			if (mem_rd(e, ctx + CTX32_EDI + 4u * i, &v, 4u))
				e->gpr[ctx32_ord[i]] = v & 0xffffffffu;
		if (mem_rd(e, ctx + CTX32_EDI + 4u * 6u, &v, 4u))
			e->gpr[KOF_EMU_RBP] = v & 0xffffffffu;
		if (mem_rd(e, ctx + CTX32_EIP, &v, 4u))
			e->rip = v & 0xffffffffu;
		if (mem_rd(e, ctx + CTX32_EFLAGS, &v, 4u))
			e->flags = v & 0xffffffffu;
		if (mem_rd(e, ctx + CTX32_ESP, &v, 4u))
			e->gpr[KOF_EMU_RSP] = v & 0xffffffffu;
		return;
	}
	for (i = 0; i < 16u; i++)
		if (mem_rd(e, ctx + CTX64_RAX + 8u * i, &v, 8u))
			e->gpr[ctx64_ord[i]] = v;
	if (mem_rd(e, ctx + CTX64_RIP, &v, 8u))
		e->rip = v;
	if (mem_rd(e, ctx + CTX64_EFLAGS, &v, 4u))
		e->flags = v & 0xffffffffu;
}

/*
 * Call a guest function and arrange to be told when it returns.
 *
 * The return address is an address nothing maps, so the loop's check for it
 * can never collide with a real return - and if the check were ever removed
 * the guest would fault there rather than run on into nothing.
 */
static int win_call(struct kof_emu *e, uint64_t fn, const uint64_t *arg,
		    unsigned n)
{
	uint64_t magic = win_ret_magic(e);
	unsigned i;

	if (e->bits == 32) {
		for (i = n; i > 0; i--)
			if (!push(e, arg[i - 1]))
				return 0;
		if (!push(e, magic))
			return 0;
	} else {
		static const unsigned r[4] = {
			KOF_EMU_RCX, KOF_EMU_RDX, KOF_EMU_R8, KOF_EMU_R9
		};

		for (i = 0; i < n && i < 4u; i++)
			e->gpr[r[i]] = arg[i];
		/* The shadow space a callee is entitled to spill into, then the
		 * return address - and the pair leaves rsp 16-aligned before
		 * the call, which is what the ABI promises a callee. */
		e->gpr[KOF_EMU_RSP] = (e->gpr[KOF_EMU_RSP] - 32u) & ~15ull;
		if (!push(e, magic))
			return 0;
	}
	e->rip = fn;
	return 1;
}

/* Hand the current exception to handler number `i` of the current phase, or
 * report that there is none left to try. */
static int win_exc_dispatch(struct kof_emu *e)
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

				mem_wr(e, ptrs, &a, 4u);
				mem_wr(e, ptrs + 4u, &b, 4u);
			} else {
				mem_wr(e, ptrs, &rec, 8u);
				mem_wr(e, ptrs + 8u, &ctx, 8u);
			}
			arg[0] = ptrs;
			return win_call(e, h, arg, 1u);
		}
		/* No vectored handler took it: fall through to the chain. */
		e->exc_phase = 2u;
		if (e->bits == 32) {
			uint64_t head = 0;

			if (mem_rd(e, e->fs_base, &head, 4u))
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

		if (!mem_rd(e, e->exc_seh_frame + 4u, &h, 4u))
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

			mem_wr(e, ptrs, &a, 4u);
			mem_wr(e, ptrs + 4u, &b, 4u);
		} else {
			mem_wr(e, ptrs, &rec, 8u);
			mem_wr(e, ptrs + 8u, &ctx, 8u);
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
static int win_exc_begin(struct kof_emu *e)
{
	uint64_t rec, ctx;
	uint32_t w32;
	uint64_t w64;
	int is_write = e->fault_kind[0] == 'w';

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
	w32 = e->exc_code ? e->exc_code : EXC_ACCESS_VIOLATION;
	mem_wr(e, rec, &w32, 4u);
	w32 = 0;                     mem_wr(e, rec + 4u, &w32, 4u);
	if (e->bits == 32) {
		w32 = 0;                       mem_wr(e, rec + 8u, &w32, 4u);
		w32 = (uint32_t)e->rip;        mem_wr(e, rec + 12u, &w32, 4u);
		w32 = 2u;                      mem_wr(e, rec + 16u, &w32, 4u);
		w32 = is_write ? 1u : 0u;      mem_wr(e, rec + 20u, &w32, 4u);
		w32 = (uint32_t)e->fault_va;   mem_wr(e, rec + 24u, &w32, 4u);
	} else {
		w64 = 0;                       mem_wr(e, rec + 8u, &w64, 8u);
		w64 = e->rip;                  mem_wr(e, rec + 16u, &w64, 8u);
		w32 = 2u;                      mem_wr(e, rec + 24u, &w32, 4u);
		w64 = is_write ? 1u : 0u;      mem_wr(e, rec + 32u, &w64, 8u);
		w64 = e->fault_va;             mem_wr(e, rec + 40u, &w64, 8u);
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
static int win_exc_return(struct kof_emu *e)
{
	uint64_t ret = e->gpr[KOF_EMU_RAX] &
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

		if (mem_rd(e, e->exc_seh_frame, &prev, 4u))
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

uint64_t kof_emu_exc_scratch(const struct kof_emu *e, uint64_t *len)
{
	if (len)
		*len = e->exc_base ? (uint64_t)WIN_EXC_PAGES * KOF_EMU_PAGE : 0;
	return e->exc_base;
}

/*
 * WHAT THE GUEST ASKED FOR, on request.
 *
 * The same argument as KOF_EMU_TRACE in objctx.c: a call that returns zero and
 * a call that was never made look identical from a stop reason, and the two
 * lead to completely different work. A guest faulting at NULL+0x3c has been
 * handed a zero module handle and has parsed it; which module it asked for is
 * the only thing that says what to add.
 */
static void win_trace(struct kof_emu *e, const char *api, const char *arg,
		      uint64_t ret)
{
	static int on = -1;

	(void)e;
	if (on < 0)
		on = getenv("KOF_WIN_TRACE") ? 1 : 0;
	if (on)
		fprintf(stderr, "[win] %-24s %-32s -> %#llx\n", api,
			arg ? arg : "", (unsigned long long)ret);
}

static uint64_t winapi_do(struct kof_emu *e, unsigned id, int *stop_out)
{
	char name[128];

	*stop_out = 0;
	win_trace(e, kof_emu_win_api_name(id), "(call)", 0);
	switch (id) {
	case WIN_GetModuleHandleA:
	case WIN_GetModuleHandleW: {
		uint64_t p = win_arg(e, 0);

		/*
		 * NULL means "this program", which is the image's own base -
		 * the one thing here that is definitely true. Any other name
		 * resolves to the one module this environment has.
		 */
		if (!p) {
			win_trace(e, "GetModuleHandle", "(self)",
				  e->win_image_base);
			return e->win_image_base;
		}
		win_str(e, p, name, sizeof name, id == WIN_GetModuleHandleW);
		{
			uint64_t h = win_mod_of(e, name);

			win_trace(e, "GetModuleHandle", name, h);
			return h;       /* zero is "not loaded", which is true */
		}
	}
	case WIN_LoadLibraryA:
	case WIN_LoadLibraryW: {
		uint64_t p = win_arg(e, 0);

		win_str(e, p, name, sizeof name, id == WIN_LoadLibraryW);
		{
			uint64_t h = win_mod_of(e, name);

			win_trace(e, "LoadLibrary", name, h);
			/*
			 * A library this has no image for fails rather than
			 * returning a plausible handle. A handle that cannot
			 * be backed with an export directory is worse than
			 * none: the guest would take it, resolve a name
			 * against nothing, and call whatever came back.
			 */
			return h;
		}
	}
	case WIN_GetProcAddress: {
		uint64_t h = win_arg(e, 0), p = win_arg(e, 1);

		{
			unsigned mi;
			int known = 0;

			for (mi = 0; mi < KOF_EMU_WIN_MOD_COUNT; mi++)
				if (h && h == e->win_mod_base[mi])
					known = 1;
			if (!known) {
				/* A handle this environment did not hand out.
				 * Silent until now, and a zero from here is
				 * indistinguishable from a name that is not
				 * exported - two different things to fix. */
				win_trace(e, "GetProcAddress", "(handle?)", h);
				return 0;
			}
		}
		/* An ordinal, not a name: the high bits are zero. */
		if (p < 0x10000u) {
			win_trace(e, "GetProcAddress", "(by ordinal)", p);
			return 0;
		}
		win_str(e, p, name, sizeof name, 0);
		{
			uint64_t a = kof_emu_win_addr_of(e, name);

			win_trace(e, "GetProcAddress", name, a);
			return a;
		}
	}
	case WIN_VirtualAlloc: {
		uint64_t at  = win_arg(e, 0), sz = win_arg(e, 1);
		uint64_t pr  = win_arg(e, 3);
		unsigned prot = win_prot(pr);

		if (getenv("KOF_WIN_TRACE"))
			fprintf(stderr,
				"[win]   VirtualAlloc(at=%#llx sz=%#llx type=%#llx prot=%#llx) rip=%#llx\n",
				(unsigned long long)at, (unsigned long long)sz,
				(unsigned long long)win_arg(e, 2),
				(unsigned long long)pr,
				(unsigned long long)e->rip);
		if (!sz)
			return 0;
		if (at) {
			/*
			 * NOT OVER A LIBRARY'S IMAGE, BECAUSE WINDOWS REFUSES.
			 *
			 * VirtualAlloc with an explicit address inside a mapped
			 * image fails there - the range is already committed as
			 * part of the section view, and MEM_RESERVE over it
			 * returns NULL. Succeeding is therefore an answer no
			 * real machine gives, and a protector that asks is
			 * usually asking precisely because of that.
			 *
			 * Measured on Themida: the loader calls
			 * VirtualAlloc(kernel32 + 0x1000, 0x1000,
			 * MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE) four
			 * times over - the page holding this environment's own
			 * export stubs - and carried on down a path whose
			 * pointers were garbage within a few thousand
			 * instructions.
			 */
			unsigned mi;

			for (mi = 0; mi < KOF_EMU_WIN_MOD_COUNT; mi++) {
				uint64_t mb = e->win_mod_base[mi];

				if (mb && at >= mb && at - mb < KOF_EMU_WIN_MOD_SPAN) {
					win_trace(e, "VirtualAlloc",
						  "(over a module image)", 0);
					return 0;
				}
			}
			/* A guest asking for a specific address usually already
			 * owns it - the Windows call succeeds on memory it has
			 * reserved. Mapping over it is what MEM_COMMIT does. */
			uint64_t base = at & ~(uint64_t)(KOF_EMU_PAGE - 1u);
			uint64_t len = (sz + (at - base) + KOF_EMU_PAGE - 1u) &
				       ~(uint64_t)(KOF_EMU_PAGE - 1u);

			if (!vma_add(e, base, len, 0, prot, 0))
				return 0;
			return at;
		}
		return e->bits == 32 ? win_alloc32(e, sz, prot)
				     : win_alloc(e, sz, prot);
	}
	case WIN_VirtualProtect: {
		uint64_t at = win_arg(e, 0), sz = win_arg(e, 1);
		uint64_t pr = win_arg(e, 2), old = win_arg(e, 3);
		uint64_t base = at & ~(uint64_t)(KOF_EMU_PAGE - 1u);
		uint64_t len = (sz + (at - base) + KOF_EMU_PAGE - 1u) &
			       ~(uint64_t)(KOF_EMU_PAGE - 1u);
		uint32_t four = 0x40u;

		(void)base; (void)len;
		if (!sz)
			return 0;
		/*
		 * THIS IS THE ONE THAT MATTERS TO A SCAN, and it does exactly
		 * what EMU_SYS_MPROTECT does a few cases down - takes a
		 * snapshot and reports success, without moving any permission.
		 *
		 * The snapshot is the point: a program saying "this is code
		 * now" about memory it just wrote is a payload saying so about
		 * itself, and that is what the harvest collects. Not moving the
		 * permission is the Linux side's decision and is kept here
		 * rather than diverged from - a run is short, nothing in it
		 * benefits from being denied access it asked for, and two
		 * protection models in one interpreter is how they drift.
		 */
		if (win_prot(pr) & KOF_EMU_X)
			snap_take(e, at, sz);
		if (old)
			mem_wr(e, old, &four, 4u);
		return 1;
	}
	case WIN_VirtualFree:
		/* Nothing is reclaimed: a run is short and its memory is what a
		 * harvest reads afterwards. Freeing would throw away the thing
		 * this whole interpreter exists to collect. */
		return 1;
	case WIN_ExitProcess:
		*stop_out = KOF_EMU_STOP_EXIT + 1;
		return 0;
	case WIN_GetCurrentProcess:
		return (uint64_t)-1;            /* the pseudo handle */
	case WIN_IsDebuggerPresent:
		return 0;
	case WIN_GetLastError:
		return e->win_last_error;
	case WIN_SetLastError:
		e->win_last_error = (uint32_t)win_arg(e, 0);
		return 0;
	case WIN_GetVersion:
		/*
		 * MAJOR IS THE LOW BYTE. This returned 0x0a00, which reads as
		 * major 0, minor 10 - and a program that starts by checking
		 * `LOBYTE(LOWORD(v)) >= 5` sees major zero and takes its
		 * failure path. Measured on an MPRESS sample: it read this,
		 * carried a null pointer from there, tested it with
		 * IsBadWritePtr, and raised STATUS_FLOAT_DIVIDE_BY_ZERO with
		 * no handler registered - fourteen and a half million
		 * instructions in.
		 *
		 * 10.0 build 19045, which is what RtlGetVersion above already
		 * says; the two used to disagree.
		 */
		return (19045u << 16) | (0u << 8) | 10u;
	case WIN_GetCurrentProcessId:
		return 0x1000u;
	case WIN_AddVectoredExceptionHandler: {
		uint64_t first = win_arg(e, 0), h = win_arg(e, 1);
		unsigned i;

		if (!h || e->n_veh >= sizeof e->win_veh / sizeof e->win_veh[0])
			return 0;
		if (first) {
			/* FIRST means first CALLED, so it goes at the front and
			 * the rest move down - the order of this list is the
			 * order they are tried in. */
			for (i = e->n_veh; i > 0; i--)
				e->win_veh[i] = e->win_veh[i - 1];
			e->win_veh[0] = h;
		} else {
			e->win_veh[e->n_veh] = h;
		}
		e->n_veh++;
		/* The handle IS the handler address. Windows returns an opaque
		 * value and a guest may only pass it back to Remove, so the
		 * simplest value that round-trips is the right one. */
		return h;
	}
	case WIN_RemoveVectoredExceptionHandler: {
		uint64_t h = win_arg(e, 0);
		unsigned i, j;

		for (i = 0, j = 0; i < e->n_veh; i++)
			if (e->win_veh[i] != h)
				e->win_veh[j++] = e->win_veh[i];
		if (j == e->n_veh)
			return 0;
		e->n_veh = j;
		return 1;
	}
	/*
	 * A HEAP, WHICH IS ONE ARENA AND NO FREE LIST.
	 *
	 * A run is short and its memory is what the harvest reads afterwards,
	 * so reclaiming would throw away the thing this exists to collect -
	 * the same decision VirtualFree makes above. HeapAlloc therefore hands
	 * out fresh pages every time and HeapFree does nothing, which is
	 * wasteful and cannot be wrong.
	 */
	case WIN_GetProcessHeap:
		return e->win_heap;
	case WIN_HeapAlloc:
	case WIN_RtlAllocateHeap: {
		uint64_t sz = win_arg(e, 2), fl = win_arg(e, 1);
		uint64_t at = e->bits == 32
			      ? win_alloc32(e, sz, KOF_EMU_R | KOF_EMU_W)
			      : win_alloc(e, sz, KOF_EMU_R | KOF_EMU_W);

		/* HEAP_ZERO_MEMORY is bit 3, and the pages are fresh, so the
		 * flag is already honoured whether it was asked for or not. */
		(void)fl;
		return at;
	}
	case WIN_HeapReAlloc: {
		uint64_t sz = win_arg(e, 3);

		/* A new block, and the old contents are NOT copied - which is
		 * wrong, and is left wrong deliberately rather than guessed
		 * at: the old size is not knowable here, so a copy would be a
		 * copy of a length this made up. A caller that depends on it
		 * will fault or read zeroes, and the trace will say where. */
		return e->bits == 32 ? win_alloc32(e, sz, KOF_EMU_R | KOF_EMU_W)
				     : win_alloc(e, sz, KOF_EMU_R | KOF_EMU_W);
	}
	case WIN_HeapFree:
	case WIN_RtlFreeHeap:
		return 1;
	case WIN_HeapSize:
		return 0;
	case WIN_VirtualQuery: {
		uint64_t at = win_arg(e, 0), out = win_arg(e, 1);
		uint64_t page = at & ~(uint64_t)(KOF_EMU_PAGE - 1u);
		uint32_t w32;

		if (!out)
			return 0;
		/* MEMORY_BASIC_INFORMATION, the fields a stub reads: the base,
		 * the size, the state and the protection. Reported as one
		 * committed readable-writable-executable page, because that is
		 * what this interpreter's memory is - it does not model the
		 * distinctions the rest of the structure draws. */
		if (e->bits == 32) {
			w32 = (uint32_t)page;      mem_wr(e, out, &w32, 4u);
			w32 = (uint32_t)page;      mem_wr(e, out + 4u, &w32, 4u);
			w32 = 0x40u;               mem_wr(e, out + 8u, &w32, 4u);
			w32 = KOF_EMU_PAGE;        mem_wr(e, out + 12u, &w32, 4u);
			w32 = 0x1000u;             mem_wr(e, out + 16u, &w32, 4u);
			w32 = 0x40u;               mem_wr(e, out + 20u, &w32, 4u);
			w32 = 0x20000u;            mem_wr(e, out + 24u, &w32, 4u);
			return 28u;
		}
		mem_wr(e, out, &page, 8u);
		mem_wr(e, out + 8u, &page, 8u);
		w32 = 0x40u;                  mem_wr(e, out + 16u, &w32, 4u);
		{ uint64_t sz = KOF_EMU_PAGE; mem_wr(e, out + 24u, &sz, 8u); }
		w32 = 0x1000u;                mem_wr(e, out + 32u, &w32, 4u);
		w32 = 0x40u;                  mem_wr(e, out + 36u, &w32, 4u);
		w32 = 0x20000u;               mem_wr(e, out + 40u, &w32, 4u);
		return 48u;
	}
	case WIN_GetSystemInfo: {
		uint64_t out = win_arg(e, 0);
		uint32_t w32;

		if (!out)
			return 0;
		w32 = 9u;          mem_wr(e, out, &w32, 4u);        /* AMD64/INTEL */
		w32 = KOF_EMU_PAGE; mem_wr(e, out + 4u, &w32, 4u);  /* page size */
		w32 = 1u;          mem_wr(e, out + (e->bits == 32 ? 20u : 32u),
					  &w32, 4u);               /* one CPU */
		return 0;
	}
	case WIN_Sleep:
		/* See the Linux side's note on sleeping: it is the cheapest
		 * anti-emulation trick there is, and the answer is to return
		 * at once rather than to refuse. */
		return 0;
	case WIN_QueryPerformanceCounter: {
		uint64_t out = win_arg(e, 0);
		uint64_t v = e->insn;      /* monotonic, and it is the clock */

		if (out)
			mem_wr(e, out, &v, 8u);
		return 1;
	}
	case WIN_QueryPerformanceFrequency: {
		uint64_t out = win_arg(e, 0);
		uint64_t v = 1000000ull;

		if (out)
			mem_wr(e, out, &v, 8u);
		return 1;
	}
	case WIN_GetSystemTimeAsFileTime: {
		uint64_t out = win_arg(e, 0);
		/* A fixed date plus the instruction count, so it is plausible,
		 * monotonic, and the same on every run of the same file. */
		uint64_t v = 0x01d80000ull * 0x100000000ull + e->insn;

		if (out)
			mem_wr(e, out, &v, 8u);
		return 0;
	}
	case WIN_GetCurrentThreadId:
		return 0x2000u;
	case WIN_GetCurrentThread:
		return (uint64_t)-2;            /* the pseudo handle */
	case WIN_TlsAlloc:
		return e->win_tls_next < 64u ? e->win_tls_next++
					     : (uint64_t)-1;
	case WIN_TlsGetValue: {
		uint64_t i = win_arg(e, 0);

		return i < 64u ? e->win_tls[i] : 0;
	}
	case WIN_TlsSetValue: {
		uint64_t i = win_arg(e, 0);

		if (i < 64u)
			e->win_tls[i] = win_arg(e, 1);
		return 1;
	}
	case WIN_TlsFree:
		return 1;
	case WIN_InitializeCriticalSection:
	case WIN_EnterCriticalSection:
	case WIN_LeaveCriticalSection:
	case WIN_DeleteCriticalSection:
		/* One thread, so a lock is never contended and a critical
		 * section is a structure nobody has to read. */
		return 1;
	case WIN_FlushInstructionCache:
		return 1;
	case WIN_GetStdHandle:
		return 0x10u;                   /* a handle, and a distinct one */
	case WIN_CloseHandle:
		return 1;
	case WIN_SetUnhandledExceptionFilter: {
		uint64_t old = e->win_top_filter;

		e->win_top_filter = win_arg(e, 0);
		return old;
	}
	case WIN_GetModuleFileNameA:
	case WIN_GetModuleFileNameW: {
		uint64_t out = win_arg(e, 1), cap = win_arg(e, 2);
		static const char path[] = "C:\\Windows\\System32\\image.exe";
		unsigned i, len = (unsigned)sizeof path - 1u;
		int wide = id == WIN_GetModuleFileNameW;

		if (!out || !cap)
			return 0;
		if (len + 1u > cap)
			len = (unsigned)cap - 1u;
		for (i = 0; i <= len; i++) {
			uint32_t c = i < len ? (uint8_t)path[i] : 0u;

			mem_wr(e, out + (wide ? 2u * i : i), &c, wide ? 2u : 1u);
		}
		return len;
	}
	case WIN_GetCommandLineA:
	case WIN_GetCommandLineW: {
		/*
		 * A REAL POINTER, BECAUSE THE CALLER DEREFERENCES IT.
		 *
		 * This used to return 0 on the argument that a caller
		 * following a null pointer is the visible failure. It is
		 * visible, and it is also where two samples ended: measured,
		 * an MPRESS one reached `cmp byte ptr [rdi], 0x22` with rdi
		 * zero at 13317906 instructions - the CRT looking for the
		 * quote around argv[0]. Nothing about the run was wrong except
		 * this answer.
		 *
		 * The string is the one GetModuleFileName already invents,
		 * quoted the way Windows quotes it, so the two answers agree
		 * with each other. Allocated once per run and kept, which is
		 * what a caller holding the pointer needs; asking twice gets
		 * the same address, as it does on Windows.
		 */
		static const char cl[] = "\"C:\\Windows\\System32\\image.exe\"";
		int wide = id == WIN_GetCommandLineW;
		unsigned len = (unsigned)sizeof cl - 1u, i;
		uint64_t at = e->cmdline[wide];

		if (at)
			return at;
		at = e->bits == 32 ? win_alloc32(e, KOF_EMU_PAGE,
						 KOF_EMU_R | KOF_EMU_W)
				   : win_alloc(e, KOF_EMU_PAGE,
					       KOF_EMU_R | KOF_EMU_W);
		if (!at)
			return 0;
		for (i = 0; i <= len; i++) {
			uint32_t c = i < len ? (uint8_t)cl[i] : 0u;

			mem_wr(e, at + (wide ? 2u * i : i), &c, wide ? 2u : 1u);
		}
		e->cmdline[wide] = at;
		return at;
	}
	case WIN_lstrlenA: {
		uint64_t p = win_arg(e, 0), i = 0, c = 0;

		while (i < 0x10000u && mem_rd(e, p + i, &c, 1u) && c)
			i++;
		return i;
	}
	case WIN_RtlAddFunctionTable:
		return 1;
	case WIN_NtQueryInformationProcess:
		/*
		 * Every class is refused with STATUS_INVALID_INFO_CLASS rather
		 * than answered. Two of the classes a protector asks for -
		 * ProcessDebugPort and ProcessDebugObjectHandle - are debugger
		 * checks, and the honest answer to those is "no debugger",
		 * which is what a failed query leaves the caller's buffer
		 * saying: untouched, and it was zeroed before the call.
		 */
		return 0xc0000003ull;
	/*
	 * THE SECOND BATCH: what a protector reaches for once it has kernel32
	 * and has started work.
	 *
	 * Each one answers the least eventful thing that is true of this
	 * machine, which is the same rule the Linux side states for the
	 * services a runtime demands. Where the truthful answer is "that did
	 * not happen" - a file opened, a thread started - it is a failure and
	 * not a plausible handle, for the reason LoadLibrary refuses a library
	 * it has no image for: a handle nothing backs is taken, used, and
	 * followed into memory that was never there.
	 */
	case WIN_FreeLibrary:
		return 1;
	case WIN_LocalAlloc:
	case WIN_GlobalAlloc: {
		uint64_t sz = win_arg(e, 1);

		return e->bits == 32 ? win_alloc32(e, sz, KOF_EMU_R | KOF_EMU_W)
				     : win_alloc(e, sz, KOF_EMU_R | KOF_EMU_W);
	}
	case WIN_LocalFree:
	case WIN_GlobalFree:
		return 0;               /* NULL is success for both */
	case WIN_lstrcmpA:
	case WIN_lstrcmpiA: {
		uint64_t a = win_arg(e, 0), b = win_arg(e, 1), i = 0;

		for (; i < 0x10000u; i++) {
			uint64_t x = 0, y = 0;

			if (!mem_rd(e, a + i, &x, 1u) ||
			    !mem_rd(e, b + i, &y, 1u))
				return 0;
			if (id == WIN_lstrcmpiA) {
				if (x >= 'A' && x <= 'Z') x += 32u;
				if (y >= 'A' && y <= 'Z') y += 32u;
			}
			if (x != y)
				return x < y ? (uint64_t)-1 : 1u;
			if (!x)
				return 0;
		}
		return 0;
	}
	case WIN_lstrcpyA:
	case WIN_lstrcatA: {
		uint64_t d = win_arg(e, 0), sp = win_arg(e, 1), i = 0, c = 0;

		if (id == WIN_lstrcatA)
			while (i < 0x10000u && mem_rd(e, d + i, &c, 1u) && c)
				i++;
		{
			uint64_t k = 0;

			do {
				if (!mem_rd(e, sp + k, &c, 1u))
					return 0;
				if (!mem_wr(e, d + i + k, &c, 1u))
					return 0;
				k++;
			} while (c && k < 0x10000u);
		}
		return d;
	}
	case WIN_lstrlenW: {
		uint64_t p = win_arg(e, 0), i = 0, c = 0;

		while (i < 0x10000u && mem_rd(e, p + 2u * i, &c, 2u) && c)
			i++;
		return i;
	}
	case WIN_MultiByteToWideChar:
	case WIN_WideCharToMultiByte:
		/* Nothing is converted and nothing is written. Reporting zero
		 * characters is the answer for a conversion that did not
		 * happen; writing a length into a buffer this did not fill
		 * would be the lie. */
		return 0;
	case WIN_OutputDebugStringA:
		return 0;
	case WIN_SetErrorMode:
		return 0;
	case WIN_GetStartupInfoA:
	case WIN_GetStartupInfoW: {
		uint64_t out = win_arg(e, 0);
		uint32_t cb = e->bits == 32 ? 68u : 104u;

		/* Only cb, which is the field a caller checks. The rest was
		 * zeroed by whoever allocated it and zero is what a process
		 * started with no console or redirection has. */
		if (out)
			mem_wr(e, out, &cb, 4u);
		return 0;
	}
	case WIN_GetSystemDirectoryA:
	case WIN_GetWindowsDirectoryA:
	case WIN_GetTempPathA: {
		uint64_t out = win_arg(e, id == WIN_GetTempPathA ? 1u : 0u);
		uint64_t cap = win_arg(e, id == WIN_GetTempPathA ? 0u : 1u);
		static const char sys[]  = "C:\\Windows\\System32";
		static const char win[]  = "C:\\Windows";
		static const char tmp[]  = "C:\\Windows\\Temp\\";
		const char *p = id == WIN_GetSystemDirectoryA ? sys
			      : id == WIN_GetWindowsDirectoryA ? win : tmp;
		unsigned i, len = 0;

		while (p[len])
			len++;
		if (!out || cap <= len)
			return len + 1u;
		for (i = 0; i <= len; i++) {
			uint32_t c = (uint8_t)p[i];

			mem_wr(e, out + i, &c, 1u);
		}
		return len;
	}
	case WIN_GetFileAttributesA:
		return (uint64_t)-1;            /* INVALID_FILE_ATTRIBUTES */
	case WIN_CreateFileA:
		return (uint64_t)-1;            /* INVALID_HANDLE_VALUE */
	case WIN_ReadFile:
	case WIN_WriteFile:
	case WIN_SetFilePointer:
		return 0;
	case WIN_GetFileSize:
		return (uint64_t)-1;
	case WIN_CreateThread:
		/*
		 * NO THREAD, AND SAID SO. There is one instruction pointer
		 * here, so a thread reported as started is a thread that will
		 * never run - and the Linux side has the measurement for what
		 * that costs: a runtime handed a slot to a thread clone had
		 * reported starting, and then waited on it forever.
		 */
		return 0;
	case WIN_ResumeThread:
		return (uint64_t)-1;
	case WIN_WaitForSingleObject:
		return 0;                       /* WAIT_OBJECT_0 */
	case WIN_TerminateProcess:
		*stop_out = KOF_EMU_STOP_EXIT + 1;
		return 1;
	case WIN_RaiseException:
		/*
		 * A GUEST RAISING ITS OWN EXCEPTION, handed to the same
		 * dispatcher a fault is. Protectors use this deliberately -
		 * it is a control transfer their handler completes - so
		 * refusing it ends the run on the ordinary path of the code
		 * rather than on an error.
		 */
		/*
		 * THE ADDRESS TO BLAME IS THE CALLER'S, not this stub's. A
		 * 64-bit handler is found by looking an address up in the
		 * image's exception directory, and the stub lives in a
		 * fabricated kernel32 that has none - so the lookup has to be
		 * made with the return address, which is the instruction
		 * RaiseException interrupted.
		 */
		e->fault_va = win_arg(e, 0);
		memcpy(e->fault_kind, "raise", 6);
		e->exc_code = (uint32_t)win_arg(e, 0);
		{
			uint64_t back = 0;

			if (mem_rd(e, e->gpr[KOF_EMU_RSP], &back,
				   e->bits == 32 ? 4u : 8u))
				e->exc_rip = back;
		}
		if (win_exc_begin(e)) {
			e->exc_code = 0;
			e->exc_rip = 0;
			return 0;
		}
		e->exc_code = 0;
		e->exc_rip = 0;
		e->fault_kind[0] = 0;
		/*
		 * NOBODY TOOK IT, AND THE RUN CARRIES ON ANYWAY.
		 *
		 * On Windows an unhandled exception ends the process, and this
		 * used to end the run for the same reason. That is the wrong
		 * trade for an unpacker. What the run is FOR is the plaintext
		 * the guest writes, and a guest that raises on purpose - a
		 * licence check that failed, an anti-analysis trap, a path this
		 * environment pushed it down by answering something
		 * imperfectly - has usually not written it yet. Measured on an
		 * MPRESS sample: 0xc000008e, STATUS_FLOAT_DIVIDE_BY_ZERO, at
		 * 14.5 million instructions, with no VEH, no top level filter
		 * and no exception directory in the image - so no handler
		 * exists to find and stopping here is all this could do.
		 *
		 * Returning instead puts the guest back after the call with
		 * the exception simply not having happened, which is what a
		 * handler that returned EXCEPTION_CONTINUE_EXECUTION would
		 * have done.
		 *
		 * BOUNDED, because a guest raising forever is not producing.
		 * Past EMU_UNHANDLED_MAX the run ends as it used to, and the
		 * count is reported either way.
		 */
		if (e->exc_unhandled++ < EMU_UNHANDLED_MAX)
			return 0;
		snprintf(e->detail, sizeof e->detail,
			 "unhandled raise %#llx at rip %#llx, %u of them",
			 (unsigned long long)win_arg(e, 0),
			 (unsigned long long)e->rip, e->exc_unhandled);
		*stop_out = KOF_EMU_STOP_EXIT + 1;
		return 0;
	case WIN_UnhandledExceptionFilter:
		return 1;                       /* EXECUTE_HANDLER */
	/*
	 * THE C RUNTIME'S OWN IMPORTS.
	 *
	 * Not chosen from a list of what Windows has: measured. A resolver in
	 * an MPRESS sample walks this module's export directory and, when the
	 * name is not there, gets a zero and calls it. Recording the first
	 * letter of each key it searched for gave I, S, F and D - four full
	 * scans of eighty-one names that found nothing - and those are the
	 * letters of the CRT startup set. Each answer below is the one the real
	 * function gives when there is nothing to report, not a number picked
	 * to get past a check.
	 */
	case WIN_InitializeCriticalSectionAndSpinCount:
		return 1;                       /* TRUE: the section is ready */
	case WIN_IsProcessorFeaturePresent:
		return 0;                       /* this machine has no optional
						 * feature, which is true of it */
	case WIN_IsValidCodePage:
		return 1;
	case WIN_IsBadReadPtr:
	case WIN_IsBadWritePtr: {
		uint64_t p = win_arg(e, 0), n = win_arg(e, 1), c = 0;

		/* The honest answer, and this environment can give it: walk the
		 * range and say whether it is there. */
		if (!p)
			return 1;
		if (n > 0x10000u)
			n = 0x10000u;
		while (n--)
			if (!mem_rd(e, p++, &c, 1u))
				return 1;
		return 0;
	}
	case WIN_InterlockedExchange: {
		uint64_t p = win_arg(e, 0), v = win_arg(e, 1), old = 0;

		if (!mem_rd(e, p, &old, 4u))
			return 0;
		mem_wr(e, p, &v, 4u);
		return (uint32_t)old;
	}
	case WIN_InterlockedCompareExchange: {
		uint64_t p = win_arg(e, 0), nv = win_arg(e, 1);
		uint64_t cmp = win_arg(e, 2), old = 0;

		if (!mem_rd(e, p, &old, 4u))
			return 0;
		if ((uint32_t)old == (uint32_t)cmp)
			mem_wr(e, p, &nv, 4u);
		return (uint32_t)old;
	}
	case WIN_SetHandleCount:
		return win_arg(e, 0);           /* what it returns on NT */
	case WIN_SetStdHandle:
	case WIN_SetEnvironmentVariableA:
	case WIN_SetEnvironmentVariableW:
	case WIN_SetConsoleCtrlHandler:
	case WIN_FreeEnvironmentStringsA:
	case WIN_FreeEnvironmentStringsW:
	case WIN_FlushFileBuffers:
	case WIN_FindClose:
	case WIN_DeleteFileA:
	case WIN_DisableThreadLibraryCalls:
	case WIN_HeapDestroy:
		return 1;                       /* TRUE */
	case WIN_DecodePointer:
	case WIN_EncodePointer:
		/* With no process cookie these are the identity, which is what
		 * they are on a system where the cookie is zero. A guest that
		 * encodes and then decodes gets its pointer back either way,
		 * and that is the only property anything depends on. */
		return win_arg(e, 0);
	case WIN_HeapCreate:
		/* One heap, the one GetProcessHeap already hands out. A guest
		 * that makes its own and a guest that uses the process heap
		 * then behave the same, which is what this environment can
		 * honestly support. */
		return e->win_heap;
	case WIN_GetCPInfo: {
		uint64_t out = win_arg(e, 1);
		uint32_t two = 2u, zero = 0;

		/* MaxCharSize 2, DefaultChar "?", no lead byte ranges - a
		 * double byte code page with nothing special about it. */
		if (!out)
			return 0;
		mem_wr(e, out, &two, 4u);
		two = (uint32_t)'?';
		mem_wr(e, out + 4u, &two, 1u);
		mem_wr(e, out + 5u, &zero, 1u);
		mem_wr(e, out + 6u, &zero, 4u);
		return 1;
	}
	case WIN_GetACP:
		return 1252u;                   /* the Latin-1 code page */
	case WIN_GetOEMCP:
		return 437u;
	case WIN_IsUserAnAdmin:
		/* FALSE. An unpacker's guest is not privileged and saying so
		 * is both true here and the answer that keeps a program on its
		 * ordinary path. */
		return 0;
	case WIN_CoInitialize:
		return 0;                       /* S_OK */
	case WIN_CoUninitialize:
		return 0;
	case WIN_SHGetFolderPathA:
		return 0x80004005u;             /* E_FAIL: no such folder here */

	case WIN_InterlockedIncrement:
	case WIN_InterlockedDecrement: {
		uint64_t p = win_arg(e, 0), v = 0;

		if (!mem_rd(e, p, &v, 4u))
			return 0;
		v = (uint32_t)(id == WIN_InterlockedIncrement ? v + 1u : v - 1u);
		mem_wr(e, p, &v, 4u);
		return v;
	}
	case WIN_NtProtectVirtualMemory: {
		uint64_t at = 0, sz = 0;

		/* The addresses arrive by POINTER, which is what makes this
		 * different from VirtualProtect and easy to get wrong. */
		mem_rd(e, win_arg(e, 1), &at, e->bits == 32 ? 4u : 8u);
		mem_rd(e, win_arg(e, 2), &sz, e->bits == 32 ? 4u : 8u);
		if (sz && (win_prot(win_arg(e, 3)) & KOF_EMU_X))
			snap_take(e, at, sz);
		return 0;                       /* STATUS_SUCCESS */
	}
	case WIN_NtAllocateVirtualMemory: {
		uint64_t pbase = win_arg(e, 1), psz = win_arg(e, 3);
		uint64_t sz = 0, at;

		mem_rd(e, psz, &sz, e->bits == 32 ? 4u : 8u);
		at = e->bits == 32 ? win_alloc32(e, sz, KOF_EMU_R | KOF_EMU_W)
				   : win_alloc(e, sz, KOF_EMU_R | KOF_EMU_W);
		if (!at)
			return 0xc0000017ull;   /* NO_MEMORY */
		mem_wr(e, pbase, &at, e->bits == 32 ? 4u : 8u);
		return 0;
	}
	case WIN_RtlGetVersion: {
		uint64_t out = win_arg(e, 0);
		uint32_t v;

		if (!out)
			return 0xc000000dull;
		v = 284u; mem_wr(e, out, &v, 4u);        /* dwOSVersionInfoSize */
		v = 10u;  mem_wr(e, out + 4u, &v, 4u);   /* MajorVersion */
		v = 0u;   mem_wr(e, out + 8u, &v, 4u);   /* MinorVersion */
		v = 19045u; mem_wr(e, out + 12u, &v, 4u);/* BuildNumber */
		return 0;
	}
	case WIN_LdrLoadDll:
		return 0xc0000135ull;           /* DLL_NOT_FOUND */
	case WIN_LdrGetProcedureAddress:
		return 0xc0000139ull;           /* ENTRYPOINT_NOT_FOUND */
	case WIN_GetTickCount:
		/*
		 * MONOTONIC AND DERIVED FROM THE INSTRUCTION COUNT, not a
		 * constant. A stub that times a loop against a clock that
		 * never moves sees zero elapsed and can conclude it is being
		 * emulated; one that sees the clock go backwards can conclude
		 * the same. This moves forward, slowly, and only forward.
		 */
		return (e->insn >> 16) & 0xffffffffu;
	default:
		return 0;
	}
}

/*
 * Arguments three, four and five.
 *
 * Two and below are handled where they are read - amd64's rdx and i386's edx
 * are the same register, so arg2 needs no translation at all, and the first two
 * are taken once at the top of syscall_do. These three differ and are read in
 * only a handful of places, so they get an accessor rather than three more
 * ternaries at each site.
 */
static uint64_t sysarg(const struct kof_emu *e, unsigned i)
{
	static const unsigned amd64[3] = { KOF_EMU_R10, KOF_EMU_R8, KOF_EMU_R9 };
	static const unsigned i386[3]  = { KOF_EMU_RSI, KOF_EMU_RDI, KOF_EMU_RBP };
	uint64_t v;

	if (i >= 3)
		return 0;
	v = e->gpr[e->bits == 32 ? i386[i] : amd64[i]];
	return e->bits == 32 ? (v & 0xffffffffu) : v;
}

static uint64_t syscall_do(struct kof_emu *e, int *stop_out)
{
	/*
	 * i386 passes the number in eax and the arguments in ebx, ecx, edx,
	 * esi, edi, ebp - a different register for every one of them than amd64
	 * uses. Read here rather than by moving the guest's registers about,
	 * because the guest is entitled to find them unchanged when the call
	 * returns.
	 */
	uint64_t nr = e->bits == 32 ? i386_nr(e->gpr[KOF_EMU_RAX] & 0xffffffffu)
				    : e->gpr[KOF_EMU_RAX];
	uint64_t a0 = e->bits == 32 ? (e->gpr[KOF_EMU_RBX] & 0xffffffffu)
				    : e->gpr[KOF_EMU_RDI];
	uint64_t a1 = e->bits == 32 ? (e->gpr[KOF_EMU_RCX] & 0xffffffffu)
				    : e->gpr[KOF_EMU_RSI];

	/*
	 * The Windows ids first, and against the RAW register rather than `nr`:
	 * a 32-bit guest's number goes through i386_nr, which maps i386 numbers
	 * onto amd64 ones and would turn one of these into something else
	 * entirely. See the Windows environment above for why the range is safe.
	 */
	{
		uint32_t raw = (uint32_t)(e->gpr[KOF_EMU_RAX] & 0xffffffffu);

		if (raw >= WIN_API_BASE && raw < WIN_API_BASE + WIN_API_COUNT)
			{
				unsigned wid = raw - WIN_API_BASE;
				uint64_t r = winapi_do(e, wid, stop_out);

				/* The ANSWER, not just the question. A call
				 * that was made and a call that was answered
				 * wrongly look the same from the entry line,
				 * and the second is what sends a program down
				 * its failure path. */
				win_trace(e, kof_emu_win_api_name(wid),
					  "= ", r);
				return r;
			}
	}

	*stop_out = 0;
	switch (nr) {
	case EMU_SYS_EXIT:
	case EMU_SYS_EXIT_GROUP:
		*stop_out = KOF_EMU_STOP_EXIT + 1;
		return 0;
	case EMU_SYS_EXECVE:
		/* The stub is done and is handing control to what it produced.
		 * Everything worth dumping has already been written. */
		*stop_out = KOF_EMU_STOP_HANDOFF + 1;
		return 0;
	case EMU_SYS_MMAP: {
		uint64_t len = (a1 + KOF_EMU_PAGE - 1u) & ~(uint64_t)(KOF_EMU_PAGE - 1u);
		uint64_t prot = e->gpr[KOF_EMU_RDX];
		/*
		 * The descriptor is an int, and a caller that sets it with a
		 * 32-bit MOV leaves 0x00000000ffffffff in the register - which
		 * read as a valid fd, so every anonymous mapping was filled
		 * with the scanned file's bytes. A Go runtime allocated its
		 * heap that way and then followed a pointer made of file data.
		 * MAP_ANONYMOUS settles it regardless of what the fd looks
		 * like.
		 */
		int32_t  fd    = (int32_t)sysarg(e, 1);
		uint64_t flags = sysarg(e, 0);
		uint64_t off = sysarg(e, 2);
		uint64_t at;

		if (!len)
			return (uint64_t)-12;                   /* ENOMEM */
		if (a0) {
			at = a0 & ~(uint64_t)(KOF_EMU_PAGE - 1u);
		} else {
			if (!e->mmap_next)
				e->mmap_next = EMU_MMAP_BASE;
			at = e->mmap_next;
			/* A guard page between mappings, so a stub that runs off
			 * the end of one faults here rather than silently
			 * scribbling on the next. */
			e->mmap_next += len + KOF_EMU_PAGE;
		}
		/*
		 * PROT_NONE is a reservation and never becomes memory: nothing
		 * can read or write it while it stays that way, and Go reserves
		 * its heap in pieces far larger than this emulator would ever
		 * commit.
		 */
		if (!(prot & (KOF_EMU_R | KOF_EMU_W | KOF_EMU_X)))
			return at;
		/*
		 * A FILE-BACKED MAPPING IS HOW A STUB READS ITSELF.
		 *
		 * UPX never calls read(): it opens /proc/self/exe and maps the
		 * file, so the compressed image simply appears at an address.
		 * Answering that with anonymous zeroes hands the decompressor
		 * an empty buffer, and it fails without complaining - it walks
		 * an all-zero ELF header, finds e_phnum == 0, skips the whole
		 * load and returns a nonsense entry point. Every descriptor
		 * this emulator hands out refers to the scanned file, so any
		 * mapping of one is a window onto its bytes.
		 */
		if (!vma_add(e, at, len, off, (unsigned)prot & 7u,
			     fd >= 0 && !(flags & 0x20u) && e->self != NULL))
			return (uint64_t)-12;
		return at;
	}
	case EMU_SYS_MPROTECT:
		if (e->gpr[KOF_EMU_RDX] & KOF_EMU_X)
			snap_take(e, a0, a1);
		return 0;
	case EMU_SYS_MUNMAP:
	case EMU_SYS_BRK:
	case EMU_SYS_FTRUNCATE:
	case EMU_SYS_CLOSE:
		return 0;
	/*
	 * SERVICES A RUNTIME DEMANDS AND A PACKER NEVER USES.
	 *
	 * None of this changes a byte of what gets unpacked, but a Go runtime
	 * checks the return of each one and executes its own trap when the
	 * answer is -ENOSYS - so refusing them stops the emulation before the
	 * packer's own code runs at all. Each answers the least eventful thing
	 * that is true of this machine: one thread, one CPU, no signals, a
	 * clock that only moves forward.
	 */
	case EMU_SYS_FUTEX:
		/*
		 * A WAIT NOBODY WILL END.
		 *
		 * clone reports a thread id and nothing runs behind it, so the
		 * wake this caller wants can never arrive. Returning "woken"
		 * leaves it re-checking the word forever; writing the word a
		 * wakeup would have written was worse - measured, it let a Go
		 * scheduler run on past a handoff it had not really made, and
		 * it died on its own consistency check. So the wait is answered
		 * honestly, and a caller that keeps asking about the same
		 * address is recognised as stuck rather than humoured.
		 */
		if ((a1 & 0x7fu) == 0) {                    /* FUTEX_WAIT */
			if (a0 == e->futex_va && ++e->futex_spin > 64u) {
				*stop_out = KOF_EMU_STOP_STALLED + 1;
				return 0;
			}
			if (a0 != e->futex_va) {
				e->futex_va = a0;
				e->futex_spin = 0;
			}
		}
		return 0;
	/*
	 * A DELAY IS GRANTED IN FULL AND WAITED FOR NOT AT ALL.
	 *
	 * Sleeping is the cheapest anti-emulation trick there is: a stub that
	 * sleeps thirty seconds before unpacking costs an analyst nothing to
	 * run and costs an automated scan its entire time budget. Returning
	 * immediately and leaving the clock alone is the wrong fix, because the
	 * next thing such a stub does is ask what time it is - and a sleep that
	 * took no time is a louder signal than a slow machine. So the requested
	 * interval is added to the clock and the call returns at once: from
	 * inside, the sleep happened.
	 */
	case EMU_SYS_NANOSLEEP:
	case EMU_SYS_CLOCK_NANOSLEEP: {
		uint64_t req = (nr == EMU_SYS_NANOSLEEP) ? a0 : e->gpr[KOF_EMU_RDX];
		uint64_t ts[2], rem[2] = { 0, 0 };
		uint64_t back = (nr == EMU_SYS_NANOSLEEP) ? a1 : sysarg(e, 0);

		if (req && mem_rd(e, req, ts, sizeof ts))
			e->tsc_skew += ts[0] * 1000000000u + ts[1];
		/* Nothing was interrupted, so nothing remains. */
		if (back)
			mem_wr(e, back, rem, sizeof rem);
		return 0;
	}
	case EMU_SYS_PAUSE:
	case EMU_SYS_SELECT:
	case EMU_SYS_POLL:
		/*
		 * Waiting for something outside this process, which is a place
		 * nothing here can come from. Answered as a timeout - no
		 * descriptor is ready - so a caller that loops on it makes
		 * progress instead of blocking on an event that cannot arrive.
		 */
		return 0;
	case EMU_SYS_ALARM:
	case EMU_SYS_SETITIMER:
	case EMU_SYS_TIMER_CREATE:
	case EMU_SYS_TIMER_SETTIME:
		/* Armed, and it will never fire: signals are not delivered here.
		 * A watchdog that never goes off is the harmless direction. */
		return 0;
	case EMU_SYS_KILL:
		/* Including a stub signalling itself to die on a failed check.
		 * Refused rather than obeyed - the run ends on its own terms. */
		return (uint64_t)-1;                        /* EPERM */
	case EMU_SYS_PTRACE:
		/*
		 * PTRACE_TRACEME succeeds, which is what a process that is NOT
		 * already being debugged sees. The trick is to call it and
		 * treat failure as proof of a debugger; answering 0 says there
		 * is none.
		 */
		return 0;
	case EMU_SYS_MADVISE:
	case EMU_SYS_SCHED_YIELD:
	case EMU_SYS_SET_ROBUST_LIST:
	case EMU_SYS_SIGALTSTACK:
	case EMU_SYS_TGKILL:
	case EMU_SYS_RSEQ:
		return 0;
	case EMU_SYS_GETPID:
	case EMU_SYS_GETTID:
	case EMU_SYS_SET_TID_ADDRESS:
		return 1;
	case EMU_SYS_IOCTL:
		return (uint64_t)-25;                       /* ENOTTY: not a tty */
	case EMU_SYS_CLONE:
		/*
		 * The parent's half of a clone, and only that. This returns
		 * once, with a thread id, and the child never runs - there is
		 * one instruction pointer here. Refusing instead was worse: a
		 * Go runtime treats a failed thread creation as fatal and quits
		 * before reaching the packer's code. A child that is never
		 * scheduled is a thread that has not got started yet, which is
		 * a state every threaded program is written to tolerate.
		 */
		e->next_tid++;
		return e->next_tid;
	case EMU_SYS_RT_SIGACTION:
	case EMU_SYS_RT_SIGPROCMASK: {
		/* The old value, if asked for, is "nothing was set". */
		uint64_t old = (nr == EMU_SYS_RT_SIGACTION) ? e->gpr[KOF_EMU_RDX] : a1;
		uint8_t z[152];

		if (old) {
			memset(z, 0, sizeof z);
			mem_wr(e, old, z, nr == EMU_SYS_RT_SIGACTION ? 32u : 8u);
		}
		return 0;
	}
	case EMU_SYS_SCHED_GETAFFINITY: {
		uint64_t mask = 1;                          /* one CPU, cpu 0 */

		if (a1 < 8 || !mem_wr(e, e->gpr[KOF_EMU_RDX], &mask, 8))
			return (uint64_t)-22;               /* EINVAL */
		return 8;
	}
	case EMU_SYS_GETTIMEOFDAY: {
		uint64_t now = tsc_ns(e), tv[2];

		tv[0] = now / 1000000000u;
		tv[1] = (now % 1000000000u) / 1000u;
		if (a0 && !mem_wr(e, a0, tv, sizeof tv))
			return (uint64_t)-14;
		return 0;
	}
	case EMU_SYS_TIME: {
		uint64_t now = tsc_ns(e) / 1000000000u;

		if (a0 && !mem_wr(e, a0, &now, 8))
			return (uint64_t)-14;
		return now;
	}
	case EMU_SYS_GETCPU: {
		uint64_t z = 0;

		if (a0 && !mem_wr(e, a0, &z, 4))
			return (uint64_t)-14;
		if (a1 && !mem_wr(e, a1, &z, 4))
			return (uint64_t)-14;
		return 0;
	}
	case EMU_SYS_CLOCK_GETTIME: {
		/* Same clock RDTSC reports, in nanoseconds. */
		uint64_t now = tsc_ns(e), ts[2];

		ts[0] = now / 1000000000u;
		ts[1] = now % 1000000000u;
		if (!mem_wr(e, a1, ts, sizeof ts))
			return (uint64_t)-14;
		return 0;
	}
	case EMU_SYS_PRLIMIT64: {
		/* 8 MB of stack, and as many descriptors as anyone asks for. */
		uint64_t lim[2] = { 8u * 1024u * 1024u, ~(uint64_t)0 };

		if (sysarg(e, 0) &&
		    !mem_wr(e, sysarg(e, 0), lim, sizeof lim))
			return (uint64_t)-14;
		return 0;
	}
	case EMU_SYS_GETRANDOM: {
		/*
		 * Deterministic on purpose. A scan that returns a different
		 * answer each run cannot be tested, and nothing that unpacks a
		 * payload takes its key from here - the key travels with the
		 * file.
		 */
		uint64_t n = a1, k;
		uint8_t b[256];

		/*
		 * Bounded, because this loop is inside ONE guest instruction
		 * and the instruction budget therefore does not see it. A guest
		 * asking for a terabyte of randomness would spin here with the
		 * budget untouched. The real call is capped too, so a short
		 * return is an answer a caller is written to handle.
		 */
		if (n > (1u << 20))
			n = 1u << 20;
		for (k = 0; k < n; k += sizeof b) {
			uint64_t c = n - k < sizeof b ? n - k : sizeof b, j;

			for (j = 0; j < c; j++)
				b[j] = (uint8_t)((k + j) * 37u + 11u);
			if (!mem_wr(e, a0 + k, b, (unsigned)c))
				return (uint64_t)-14;
		}
		return n;
	}
	case EMU_SYS_ARCH_PRCTL:
		/* ARCH_SET_FS / ARCH_SET_GS. The two GET codes report where the
		 * emulator put them, so a runtime that reads its own thread
		 * pointer back gets what it wrote. */
		if (a0 == 0x1002)      { e->fs_base = a1; return 0; }
		if (a0 == 0x1001)      { e->gs_base = a1; return 0; }
		if (a0 == 0x1003 || a0 == 0x1004) {
			uint64_t v = (a0 == 0x1003) ? e->fs_base : e->gs_base;

			if (!mem_wr(e, a1, &v, 8))
				return (uint64_t)-14;
			return 0;
		}
		return (uint64_t)-22;                       /* EINVAL */
	case EMU_SYS_MEMFD_CREATE:
	case EMU_SYS_OPEN:
	case EMU_SYS_OPENAT:
		return EMU_SELF_FD;
	/*
	 * EVERY PATH EXISTS AND IS READABLE, which is the same lie open()
	 * above already tells and is the consistent one. A stub checking for
	 * /proc/self/status before it will run gets the answer a real machine
	 * gives; -ENOENT here and a successful open two lines later would be
	 * an inconsistency worth noticing.
	 */
	case EMU_SYS_ACCESS:
	case EMU_SYS_FACCESSAT:
	case EMU_SYS_FACCESSAT2:
		return 0;
	case EMU_SYS_STAT:
	case EMU_SYS_LSTAT:
		return stat_out(e, a1);
	case EMU_SYS_STATFS:
	case EMU_SYS_FSTATFS: {
		/*
		 * AN ORDINARY DISK, and the choice of magic is the whole point.
		 *
		 * A sandbox check does not ask whether the filesystem works, it
		 * asks what KIND it is: overlayfs (0x794c7630) says container,
		 * tmpfs (0x01021994) says the file was dropped into RAM by
		 * something. ext4 says a machine somebody uses.
		 */
		uint8_t sf[120];
		unsigned at = 0;

		memset(sf, 0, sizeof sf);
		gw_put(e, sf, &at, 0xEF53u);          /* f_type: ext2/3/4    */
		gw_put(e, sf, &at, 4096u);            /* f_bsize             */
		gw_put(e, sf, &at, 26214400u);        /* f_blocks: 100 GB    */
		gw_put(e, sf, &at, 13107200u);        /* f_bfree:  half free */
		gw_put(e, sf, &at, 13107200u);        /* f_bavail            */
		gw_put(e, sf, &at, 6553600u);         /* f_files             */
		gw_put(e, sf, &at, 6000000u);         /* f_ffree             */
		if (!mem_wr(e, (nr == EMU_SYS_FSTATFS) ? a1
						      : e->gpr[KOF_EMU_RSI],
			    sf, at))
			return (uint64_t)-14;
		return 0;
	}
	case EMU_SYS_READLINKAT: {
		/* readlink's answer, one argument along. */
		static const char path[] = "/proc/self/exe";
		uint64_t n = sizeof path - 1u, room = sysarg(e, 0);

		if (n > room)
			n = room;
		if (!mem_wr(e, e->gpr[KOF_EMU_RDX], path, (unsigned)n))
			return (uint64_t)-14;
		return n;
	}
	case EMU_SYS_GETCWD: {
		static const char cwd[] = "/tmp";
		uint64_t n = sizeof cwd;              /* the NUL is included */

		if (n > a1)
			return (uint64_t)-34;           /* ERANGE */
		if (!mem_wr(e, a0, cwd, (unsigned)n))
			return (uint64_t)-14;
		return n;
	}
	case EMU_SYS_UNAME: {
		/*
		 * SIX FIXED-WIDTH NAMES, and a plausible one in each.
		 *
		 * A stub reads `machine` to pick a code path and `release` to
		 * decide whether a syscall it wants exists. A kernel version
		 * old enough to lack memfd_create would send a loader down a
		 * path this emulator then has to carry, so the release named
		 * here is recent enough that the modern path is the one taken.
		 */
		char u[6 * 65];
		unsigned i;
		static const char *fld[6] = {
			"Linux", "localhost", "6.1.0-18-amd64",
			"#1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1",
			NULL, ""
		};

		memset(u, 0, sizeof u);
		for (i = 0; i < 6u; i++) {
			const char *t = fld[i];

			if (i == 4u)
				t = e->bits == 32 ? "i686" : "x86_64";
			memcpy(u + i * 65u, t, strlen(t));
		}
		if (!mem_wr(e, a0, u, sizeof u))
			return (uint64_t)-14;
		return 0;
	}
	/*
	 * ROOT-LESS AND ORDINARY. uid 1000 rather than 0: a stub that only
	 * unpacks when it is root would otherwise take a path this emulator
	 * cannot follow to anywhere useful, and a stub that refuses to run AS
	 * root - malware avoiding an analyst's box - would refuse.
	 */
	case EMU_SYS_GETUID:
	case EMU_SYS_GETEUID:  return 1000;
	case EMU_SYS_GETGID:
	case EMU_SYS_GETEGID:  return 1000;
	case EMU_SYS_GETPPID:  return 1;
	case EMU_SYS_SYSINFO: {
		/*
		 * A MACHINE SOMEBODY USES, measured against what a sandbox
		 * check looks for: too little RAM and too short an uptime are
		 * the two it keys on. Eight gigabytes and eleven days.
		 */
		uint8_t si[128];
		unsigned at = 0;

		memset(si, 0, sizeof si);
		gw_put(e, si, &at, 987654u);                  /* uptime, s    */
		gw_put(e, si, &at, 12000u);                   /* loads[0]     */
		gw_put(e, si, &at, 14000u);
		gw_put(e, si, &at, 16000u);
		gw_put(e, si, &at, 8ull * 1024 * 1024 * 1024);/* totalram     */
		gw_put(e, si, &at, 3ull * 1024 * 1024 * 1024);/* freeram      */
		gw_put(e, si, &at, 0);                        /* sharedram    */
		gw_put(e, si, &at, 512ull * 1024 * 1024);     /* bufferram    */
		gw_put(e, si, &at, 2ull * 1024 * 1024 * 1024);/* totalswap    */
		gw_put(e, si, &at, 2ull * 1024 * 1024 * 1024);/* freeswap     */
		si[at++] = 214; si[at++] = 0;                 /* procs        */
		at += 2u;                                     /* pad          */
		if (gw(e) == 8u)
			at += 4u;                             /* alignment    */
		gw_put(e, si, &at, 0);                        /* totalhigh    */
		gw_put(e, si, &at, 0);                        /* freehigh     */
		at += 4u;                                     /* mem_unit = 1 */
		si[at - 4u] = 1;
		if (!mem_wr(e, a0, si, at))
			return (uint64_t)-14;
		return 0;
	}
	case EMU_SYS_TIMES: {
		/* Four clock_t of CPU time, from the same clock as everything
		 * else. 100 ticks a second is what _SC_CLK_TCK is everywhere
		 * this matters. */
		uint64_t t = tsc_ns(e) / 10000000u;
		uint8_t tms[32];
		unsigned at = 0;

		memset(tms, 0, sizeof tms);
		gw_put(e, tms, &at, t);
		gw_put(e, tms, &at, t / 4u);
		gw_put(e, tms, &at, 0);
		gw_put(e, tms, &at, 0);
		if (a0 && !mem_wr(e, a0, tms, at))
			return (uint64_t)-14;
		return t;
	}
	case EMU_SYS_CLOCK_GETRES: {
		/* A nanosecond, which is the unit the clock here counts in. */
		uint8_t ts[16];
		unsigned at = 0;

		gw_put(e, ts, &at, 0);
		gw_put(e, ts, &at, 1);
		if (a1 && !mem_wr(e, a1, ts, at))
			return (uint64_t)-14;
		return 0;
	}
	case EMU_SYS_PRCTL: {
		/*
		 * PR_GET_DUMPABLE answers 1 - a process being traced by
		 * somebody would read 0, and that is the check. Everything
		 * else is a setter and succeeds.
		 */
		if (a0 == 3u) {                         /* PR_GET_DUMPABLE */
			uint32_t one = 1u;

			if (a1 && !mem_wr(e, a1, &one, 4))
				return (uint64_t)-14;
			return 1;
		}
		return 0;
	}
	case EMU_SYS_PERSONALITY:
		/* The previous personality, which was the ordinary one. Some
		 * packers turn ASLR off before mapping; nothing here moves. */
		return 0;
	case EMU_SYS_GETRLIMIT:
	case EMU_SYS_SETRLIMIT: {
		uint8_t lim[16];
		unsigned at = 0;

		if (nr == EMU_SYS_SETRLIMIT)
			return 0;
		gw_put(e, lim, &at, 8ull * 1024 * 1024);      /* soft: stack */
		gw_put(e, lim, &at, ~(uint64_t)0);            /* hard        */
		if (a1 && !mem_wr(e, a1, lim, at))
			return (uint64_t)-14;
		return 0;
	}
	/*
	 * There is one file and one descriptor for it, so a duplicate is a
	 * number. dup2 and dup3 are told which number to answer with and are
	 * obliged to; dup picks one that is not already spoken for.
	 */
	case EMU_SYS_DUP:   return EMU_SELF_FD;
	case EMU_SYS_DUP2:
	case EMU_SYS_DUP3:  return a1;
	case EMU_SYS_FCNTL:
		switch (a1) {
		case 0:  return EMU_SELF_FD;            /* F_DUPFD      */
		case 1:  return 0;                      /* F_GETFD      */
		case 3:  return 0;                      /* F_GETFL: RDONLY */
		default: return 0;                      /* every setter */
		}
	case EMU_SYS_PIPE:
	case EMU_SYS_PIPE2: {
		/* Both ends name the same file, like every other descriptor
		 * here. A stub that pipes to itself makes progress; one that
		 * expects to read back what it wrote does not, and neither
		 * outcome unpacks anything. */
		uint32_t fds[2] = { EMU_SELF_FD, EMU_SELF_FD };

		if (!mem_wr(e, a0, fds, sizeof fds))
			return (uint64_t)-14;
		return 0;
	}
	case EMU_SYS_PWRITE64:
		return e->gpr[KOF_EMU_RDX];             /* wrote it all */
	case EMU_SYS_WRITEV:
	case EMU_SYS_READV: {
		/*
		 * A VECTOR OF (base, len) IN GUEST WORDS. glibc writes through
		 * writev rather than write, so a stub that prints anything at
		 * all arrives here and not at WRITE - and answering -ENOSYS
		 * made the common case of "it told us what it was doing" into
		 * a stop.
		 */
		uint64_t vec = a1, n = e->gpr[KOF_EMU_RDX], i, done = 0;
		unsigned w = gw(e);

		if (n > 1024u)
			n = 1024u;
		for (i = 0; i < n; i++) {
			uint8_t ent[16];
			uint64_t base = 0, len = 0;

			if (!mem_rd(e, vec + i * 2u * w, ent, 2u * w))
				break;
			if (w == 4u) {
				uint32_t b32, l32;

				memcpy(&b32, ent, 4);
				memcpy(&l32, ent + 4, 4);
				base = b32; len = l32;
			} else {
				memcpy(&base, ent, 8);
				memcpy(&len, ent + 8, 8);
			}
			if (nr == EMU_SYS_WRITEV) {
				/* Kept, up to what the say buffer holds, the
				 * same way WRITE keeps it. */
				if (a0 <= 2u && e->n_say < KOF_EMU_SAY) {
					uint64_t room = KOF_EMU_SAY - e->n_say;

					if (len < room)
						room = len;
					if (mem_rd(e, base,
						   e->say + e->n_say,
						   (unsigned)room))
						e->n_say += (uint32_t)room;
				}
				done += len;
			} else {
				uint64_t got = self_read(e, base, len,
							 e->self_pos);

				e->self_pos += got;
				done += got;
				if (got < len)
					break;
			}
		}
		return done;
	}
	case EMU_SYS_MREMAP: {
		/*
		 * GROW BY MOVING, because nothing here ever gives memory back -
		 * see MUNMAP, which is a no-op. So the old mapping stays where
		 * it is and the new one is somewhere else with the bytes copied
		 * across, which is what MREMAP_MAYMOVE promises anyway.
		 *
		 * Without that flag a kernel would try to extend in place and
		 * answer -ENOMEM when it cannot; the guest handles that, and
		 * pretending to succeed would hand it an address it believes
		 * is contiguous with something it is not.
		 */
		uint64_t old_len = (a1 + KOF_EMU_PAGE - 1u) &
				   ~(uint64_t)(KOF_EMU_PAGE - 1u);
		uint64_t new_len = (e->gpr[KOF_EMU_RDX] + KOF_EMU_PAGE - 1u) &
				   ~(uint64_t)(KOF_EMU_PAGE - 1u);
		uint64_t flags = sysarg(e, 0), at, done;

		if (!new_len)
			return (uint64_t)-22;                   /* EINVAL */
		if (new_len <= old_len)
			return a0;                    /* shrink in place */
		if (!(flags & 1u))
			return (uint64_t)-12;                   /* ENOMEM */
		if (!e->mmap_next)
			e->mmap_next = EMU_MMAP_BASE;
		at = e->mmap_next;
		e->mmap_next += new_len + KOF_EMU_PAGE;
		if (!vma_add(e, at, new_len, 0,
			     KOF_EMU_R | KOF_EMU_W, 0))
			return (uint64_t)-12;
		for (done = 0; done < old_len; ) {
			uint8_t page[KOF_EMU_PAGE];
			uint64_t chunk = old_len - done;

			if (chunk > KOF_EMU_PAGE)
				chunk = KOF_EMU_PAGE;
			if (!mem_rd(e, a0 + done, page, (unsigned)chunk))
				break;
			if (!mem_wr(e, at + done, page, (unsigned)chunk))
				break;
			done += chunk;
		}
		return at;
	}
	case EMU_SYS_READLINK: {
		/* Whatever was asked about is this process. The path only has to
		 * be openable, and every open here answers with the same file. */
		static const char path[] = "/proc/self/exe";
		uint64_t n = sizeof path - 1u;

		if (n > e->gpr[KOF_EMU_RDX])
			n = e->gpr[KOF_EMU_RDX];
		if (!mem_wr(e, a1, path, (unsigned)n))
			return (uint64_t)-14;
		return n;
	}
	case EMU_SYS_LSEEK: {
		uint64_t whence = e->gpr[KOF_EMU_RDX];

		if (whence == 0)      e->self_pos = a1;
		else if (whence == 1) e->self_pos += a1;
		else                  e->self_pos = e->self_n + a1;
		return e->self_pos;
	}
	case EMU_SYS_PREAD64:
		return self_read(e, a1, sysarg(e, 0), e->gpr[KOF_EMU_RDX]);
	case EMU_SYS_FSTAT:
	case EMU_SYS_NEWFSTATAT: {
		uint64_t at = (nr == EMU_SYS_FSTAT) ? a1 : e->gpr[KOF_EMU_RDX];

		return stat_out(e, at);
	}
	case EMU_SYS_WRITE: {
		uint64_t n = e->gpr[KOF_EMU_RDX];

		if (a0 <= 2 && e->n_say < KOF_EMU_SAY) {
			uint64_t room = KOF_EMU_SAY - e->n_say;

			if (n < room)
				room = n;
			if (mem_rd(e, a1, e->say + e->n_say, (unsigned)room))
				e->n_say += (uint32_t)room;
		}
		return n;                                       /* wrote it all */
	}
	case EMU_SYS_READ: {
		uint64_t got;

		/*
		 * READING STANDARD INPUT IS END OF FILE, and answering it any
		 * other way costs an entire budget.
		 *
		 * Every open here hands back EMU_SELF_FD, so a descriptor of 0,
		 * 1 or 2 was never opened: it is the terminal the process
		 * inherited, and there is no terminal. Serving those reads from
		 * the scanned file - which is what ignoring the descriptor did -
		 * feeds a stub the packed image one byte at a time and never
		 * reaches an end, so a stub that waits for input waits forever.
		 *
		 * Measured on midgetpack, which asks for a password: 61 reads of
		 * stdin answered with file bytes, then four million instructions
		 * of nothing, 0.47 s per object and 75 s over 200 of them, with
		 * no payload recovered because there was never a password to
		 * recover it with. Answering 0 ends the prompt on its first
		 * read, the stub gives up the way it would on a closed pipe, and
		 * the run stops in milliseconds.
		 *
		 * EOF rather than EAGAIN or EIO: a closed input is an ordinary
		 * thing a program is written to handle, and an error is not.
		 *
		 * AND A PROMPT THAT IGNORES EOF ASKS FOREVER, which is the same
		 * shape as the futex wait above and is answered the same way.
		 * midgetpack's prompt does not check the return at all - it
		 * loops until it sees a newline - so end-of-file alone does not
		 * end it; measured, it still spent the whole budget. A caller
		 * that has been told the input is over and asks again has
		 * stopped making progress, and after a handful of those the run
		 * is stuck rather than working. The handful is what separates it
		 * from a program that legitimately probes stdin once or twice
		 * before giving up on its own.
		 */
		if ((int64_t)a0 >= 0 && a0 <= 2) {
			if (++e->stdin_eof > 8u) {
				*stop_out = KOF_EMU_STOP_STALLED + 1;
				return 0;
			}
			return 0;
		}
		e->stdin_eof = 0;
		got = self_read(e, a1, e->self_pos, e->gpr[KOF_EMU_RDX]);
		if ((int64_t)got > 0)
			e->self_pos += got;
		return got;
	}
	default:
		if (e->n_unksys < KOF_EMU_UNKSYS) {
			uint32_t i;

			for (i = 0; i < e->n_unksys; i++)
				if (e->unksys[i] == (uint32_t)nr)
					break;
			if (i == e->n_unksys)
				e->unksys[e->n_unksys++] = (uint32_t)nr;
		}
		return (uint64_t)-38;                           /* ENOSYS */
	}
}

/* ---- the loop -------------------------------------------------------------- */

static void fail(struct kof_emu *e, enum kof_emu_stop s, const INSTRUX *ix)
{
	e->stop = s;
	if (s == KOF_EMU_STOP_FAULT) {
		snprintf(e->detail, sizeof e->detail, "%s at %#llx from rip %#llx",
			 e->fault_kind[0] ? e->fault_kind : "access",
			 (unsigned long long)e->fault_va,
			 (unsigned long long)e->rip);
		return;
	}
	if (ix && s == KOF_EMU_STOP_UNSUPPORTED) {
		char t[ND_MIN_BUF_SIZE];

		if (ND_SUCCESS(NdToText(ix, e->rip, sizeof t, t))) {
			/*
			 * The WHOLE text. "MOV" is not a thing to go and
			 * implement - every build already has MOV - whereas
			 * "MOV rax, fs:[0x0]" names the actual gap.
			 */
			size_t i = 0;

			while (i + 1u < sizeof e->detail && t[i]) {
				e->detail[i] = t[i];
				i++;
			}
			while (i && e->detail[i - 1u] == ' ')
				i--;
			e->detail[i] = 0;
		}
	}
}

enum kof_emu_stop kof_emu_run(struct kof_emu *e)
{
	e->stop = KOF_EMU_STOP_BUDGET;
	e->detail[0] = 0;
	e->running = 1;

	while (e->insn < e->max_insn) {
		uint8_t code[16];
		INSTRUX ixbuf;
		INSTRUX *ixp;
		struct icache_ent *ent;
		struct page *fpg;
		NDSTATUS st;
		uint64_t a = 0, b = 0, r = 0, next;
		unsigned sz;
		int jumped = 0;
		/* The instruction being executed, kept for the handover test
		 * below - by then e->rip is the TARGET. */
		uint64_t at = 0;
		unsigned at_len = 0;
		const uint8_t *at_b = code;

		/*
		 * AN EXCEPTION HANDLER RETURNING, recognised by the address it
		 * returns to. Checked before the fetch because the address is
		 * deliberately unmapped: reaching the fetch with it would be a
		 * fault, which is the safe way for this to fail if it is ever
		 * removed.
		 */
		/*
		 * THE HANDOFF, CHECKED BEFORE THE FETCH. See kof_emu_watch_exec
		 * for what the ranges are and where the idea came from. Whatever
		 * the loader has written is in memory now and the harvest is
		 * about to read it; going on would run the program itself,
		 * which is not what an unpacker is for.
		 */
		/*
		 * A STAGE THIS RUN HAS NOT BEEN IN BEFORE. Copied and left
		 * running - see kof_emu_hop_add.
		 */
		if (e->n_hop) {
			int h = hop_first(e, e->rip);

			if (h >= 0) {
				if (!e->hop_first_insn) {
					e->hop_first_insn = e->insn ? e->insn : 1;
					e->hop_first_rip = e->rip;
				}
				e->hop_last_rip = e->rip;
				e->hop_count++;
				snap_take(e, e->hop[h].lo,
					  e->hop[h].hi - e->hop[h].lo);
			}
		}

		if (e->n_xwatch) {
			/*
			 * THE EDGE, NOT THE ADDRESS.
			 *
			 * This was "rip is inside a watched range", which is
			 * right for a packer whose program sits where the
			 * loader never executes - MPRESS, Oreans - and wrong
			 * for one that shares a section with it. Measured on a
			 * PECompact2 sample: the entry section is the one the
			 * image decompresses into AND the one the entry point
			 * is in, so naming it ended the run at instruction 0,
			 * and naming every other section ended it six
			 * instructions later at the stub's own first jump.
			 *
			 * A handover is the loader LEAVING and the program
			 * being entered, so it is a transition. For a range the
			 * loader never runs in, every arrival is a transition
			 * and nothing changes; for one it starts in, the run
			 * has to leave before coming back can mean anything.
			 */
			int in = xwatch_hit(e, e->rip);

			if (in && e->xw_have_prev && !e->xw_was_in) {
				e->stop = KOF_EMU_STOP_HANDOFF;
				snprintf(e->detail, sizeof e->detail,
					 "handed over at %#llx",
					 (unsigned long long)e->rip);
				goto done;
			}
			e->xw_was_in = in;
			e->xw_have_prev = 1;
		}

		if (e->exc_phase && e->rip == win_ret_magic(e)) {
			if (win_exc_return(e))
				continue;
			fail(e, KOF_EMU_STOP_FAULT, NULL);
			goto done;
		}

		/*
		 * A CALL TO ADDRESS ZERO IS AN IMPORT THIS ENVIRONMENT DOES
		 * NOT HAVE, AND IT IS NOT A CRASH.
		 *
		 * A stub that resolves its own imports walks a module's export
		 * directory, compares names, and on a match adds the function's
		 * RVA to the module base. This environment's kernel32 exports
		 * eighty-odd names against the real one's fifteen hundred, so a
		 * name it wants and this does not have comes back as a zero RVA
		 * - and the stub calls the module base, or, where it had the
		 * address in a register, calls zero.
		 *
		 * WHAT WINDOWS WOULD HAVE DONE is return from a function this
		 * file does not implement, so that is what happens here: pop
		 * the return address, put 0 in the accumulator and carry on.
		 * The stub gets a useless answer to a question this build
		 * cannot answer, which is exactly what every other unimplemented
		 * API here gives it, and keeps going.
		 *
		 * FAULTING INSTEAD THROWS THE RUN AWAY. Measured on an MPRESS
		 * sample: it resolved LoadLibraryA, loaded five libraries,
		 * resolved SetLastError and GetLastError, and then called one
		 * name too many at instruction 5662007 - and a fault at rip 0
		 * ends the run with its payload unharvested.
		 *
		 * BOUNDED, because a guest that does this forever is not
		 * unpacking. Past EMU_NULL_CALLS the answer is no longer
		 * plausible and the fault it would have been happens instead.
		 *
		 * Only the UNMAPPED null page. A guest that genuinely mapped
		 * page zero and put code there is executing its own code.
		 */
		if (e->rip < KOF_EMU_PAGE && !page_lookup(e, e->rip)) {
			uint64_t ret = 0;

			if (e->null_calls < EMU_NULL_CALLS &&
			    pop(e, &ret) && ret) {
				/* Freeze the instruction trace at the FIRST of
				 * these: the call that could not be resolved
				 * is upstream of every wrong value after it. */
				if (e->itr && e->itr_on_null && !e->null_calls)
					e->itr_frozen = 1;
				e->null_calls++;
				e->gpr[KOF_EMU_RAX] = 0;
				e->rip = ret;
				continue;
			}
			e->fault_va = e->rip;
			memcpy(e->fault_kind, "call0", 6);
			fail(e, KOF_EMU_STOP_FAULT, NULL);
			goto done;
		}

		/*
		 * EXECUTE PERMISSION, CHECKED ONCE PER PAGE.
		 *
		 * Not per instruction: a straight run stays on one page and the
		 * answer cannot change under it, so the page it last fetched
		 * from is remembered and only a move to another page pays for a
		 * lookup. That makes the check a compare in the common case.
		 *
		 * What it is for: a guest that walks a library's export
		 * directory for a name this environment does not list gets 0
		 * back, adds it to the module base and calls the module's own
		 * MZ header. Without this the header is executable, the zeroes
		 * decode as `add [rax],al`, and the run marches two bytes at a
		 * time until something faults far away - measured on an MPRESS
		 * sample, 310701 instructions ending at an address built out of
		 * header bytes. With it the fault is AT THE BASE, which names
		 * the module and says the miss was an export lookup.
		 */
		if ((e->rip & ~(uint64_t)(KOF_EMU_PAGE - 1u)) != e->fetch_page) {
			struct page *fp = page_lookup(e, e->rip);

			/*
			 * WRITTEN AND THEN EXECUTED: TAKE IT AND CARRY ON.
			 *
			 * Memory a run wrote and then ran is the definition of
			 * something it produced, and it is the only signal that
			 * works when a program decrypts a piece of ITSELF - no
			 * mprotect, no section, no packer to declare anything.
			 * stop_on_written_jump saw the same thing and STOPPED,
			 * which is why it is off by default: measured, a
			 * PECompact2 sample stopped eighteen instructions in.
			 * Snapshotting and continuing is Unipacker's lesson
			 * about section hopping applied to the same signal -
			 * see THIRD-PARTY.md.
			 *
			 * WHOLE CONTIGUOUS RUN, because a decrypted function is
			 * not one page and a snapshot per page hands back
			 * rubble. Bounded, and each page is taken once.
			 *
			 * NOT THE STACK. A return address is written and then
			 * executed at every call, and the stack is where this
			 * would otherwise fire constantly and collect nothing.
			 */
			if (fp && fp->written && !fp->snapped &&
			    (fp->prot & KOF_EMU_X) &&
			    !(e->rip >= e->stack_lo && e->rip < e->stack_hi)) {
				uint64_t base = e->rip &
						~(uint64_t)(KOF_EMU_PAGE - 1u);
				uint64_t lo = base, hi = base + KOF_EMU_PAGE;
				unsigned k;
				struct page *q;

				for (k = 0; k < WEX_SPAN_PAGES; k++) {
					if (lo < KOF_EMU_PAGE)
						break;
					q = page_lookup(e, lo - KOF_EMU_PAGE);
					if (!q || !q->written || q->snapped)
						break;
					lo -= KOF_EMU_PAGE;
				}
				for (k = 0; k < WEX_SPAN_PAGES; k++) {
					q = page_lookup(e, hi);
					if (!q || !q->written || q->snapped)
						break;
					hi += KOF_EMU_PAGE;
				}
				for (base = lo; base < hi;
				     base += KOF_EMU_PAGE) {
					q = page_lookup(e, base);
					if (q)
						q->snapped = 1;
				}
				snap_take(e, lo, hi - lo);

			}

			if (fp && !(fp->prot & KOF_EMU_X)) {
				e->fault_va = e->rip;
				memcpy(e->fault_kind, "exec", 5);
				fail(e, KOF_EMU_STOP_FAULT, NULL);
				goto done;
			}
			if (fp)
				e->fetch_page = e->rip &
						~(uint64_t)(KOF_EMU_PAGE - 1u);
		}

		/*
		 * THE CACHE FIRST - see `ic`. A hit skips both the fetch and
		 * the decode, which together are most of what an interpreted
		 * instruction costs.
		 */
		ent = NULL;
		fpg = e->ic ? page_lookup(e, e->rip) : NULL;
		if (fpg) {
			unsigned poff = (unsigned)(e->rip & (KOF_EMU_PAGE - 1u));

			{
				ent = &e->ic[((e->rip * 0x9e3779b97f4a7c15ull) >> 40) &
					     (KOF_EMU_ICACHE - 1u)];
				if (ent->valid && ent->va == e->rip &&
				    ent->pg == fpg &&
				    poff + ent->len <= KOF_EMU_PAGE &&
				    !memcmp(fpg->data + poff, ent->bytes,
					    ent->len)) {
					/*
					 * POINTED AT, NOT COPIED. An INSTRUX is
					 * 480 bytes and this path runs tens of
					 * millions of times - measured on one
					 * Sality slice, 17.2 million hits, which
					 * is 8.3 GB of memcpy for bytes that are
					 * already in the right place.
					 */
					ixp = &ent->ix;
					e->ic_hit++;
					goto decoded;
				}
				e->ic_miss++;
				if (!ent->valid)
					e->m_empty++;
				else if (ent->va != e->rip)
					e->m_va++;
				else if (ent->pg != fpg)
					e->m_pg++;
				else
					e->m_bytes++;
				ent->valid = 0;
				ent->pg = fpg;
				ent->va = e->rip;
			}
			/*
			 * AND THE FETCH STRAIGHT OUT OF THE PAGE when the whole
			 * of it lies inside one. mem_rd walks the page table
			 * ONCE PER BYTE - sixteen lookups for every instruction
			 * decoded - and the page is already in hand here.
			 */
			if (poff + sizeof code <= KOF_EMU_PAGE) {
				memcpy(code, fpg->data + poff, sizeof code);
				goto fetched;
			}
		}
		e->in_fetch = 1;
		if (!mem_rd(e, e->rip, code, sizeof code)) {
			/* The tail of a mapping is a legitimate place to be: try
			 * the shortest fetch that can still hold an instruction
			 * before calling it a fault. */
			unsigned got = 0;

			while (got < sizeof code &&
			       mem_rd(e, e->rip + got, code + got, 1))
				got++;
			if (got < 1) {
				e->fault_va = e->rip;
				memcpy(e->fault_kind, "fetch", 6);
				fail(e, KOF_EMU_STOP_FAULT, NULL);
				break;
			}
			memset(code + got, 0, sizeof code - got);
		}
fetched:
		e->in_fetch = 0;
		/*
		 * DECODED INTO THE CACHE SLOT ITSELF, so that filling it costs
		 * nothing beyond the decode. The length is not known until
		 * afterwards, so whether it may be KEPT is decided then - an
		 * instruction straddling a page boundary depends on two pages
		 * and this checks one.
		 */
		ixp = ent ? &ent->ix : &ixbuf;
		st = NdDecodeEx(ixp, code, sizeof code,
				e->bits == 32 ? ND_CODE_32 : ND_CODE_64,
				e->bits == 32 ? ND_DATA_32 : ND_DATA_64);
		if (!ND_SUCCESS(st)) { fail(e, KOF_EMU_STOP_DECODE, NULL); break; }
		/* Kept only when it lies inside one page - see `ic`. */
		if (ent && ((e->rip + ixp->Length - 1u) &
			    ~(uint64_t)(KOF_EMU_PAGE - 1u))
			   == (e->rip & ~(uint64_t)(KOF_EMU_PAGE - 1u))) {
			memcpy(ent->bytes, code, ixp->Length);
			ent->len = ixp->Length;
			ent->inert = (uint8_t)nop_insn(ixp);
			ent->valid = 1;
		}
decoded:

		if (!e->sp0_set) {
			e->sp0 = e->gpr[KOF_EMU_RSP];
			e->sp0_set = 1;
		}
		at = e->rip;
		at_len = ixp->Length;
		/*
		 * PAUSED ON WHAT IS ABOUT TO RUN, BEFORE IT RUNS.
		 *
		 * Here and not after the execute, because the point is to see
		 * the machine as the guest left it AT that instruction: for a
		 * `ret`, the address it is about to return to is still on the
		 * stack, and one instruction later it is not. See
		 * kof_emu_watch_insn.
		 *
		 * The run is resumable from here - rip has not moved - so the
		 * module reads what it wants and calls kof_emu_run again.
		 */
		if (iwatch_hit(e, at_b, at_len)) {
			snprintf(e->detail, sizeof e->detail,
				 "watched instruction at %#llx",
				 (unsigned long long)e->rip);
			e->stop = KOF_EMU_STOP_INSN;
			goto done;
		}
		if (e->hot) {
			uint32_t h = (uint32_t)((e->rip * 2654435761u) >> 8) &
				     e->hot_mask;
			uint32_t q;

			for (q = 0; q < 8u; q++) {
				uint32_t k = (h + q) & e->hot_mask;

				if (!e->hot[k].n || e->hot[k].va == e->rip) {
					e->hot[k].va = e->rip;
					e->hot[k].n++;
					break;
				}
			}
		}
		/*
		 * AND HAS THE DECRYPTION STOPPED - see KOF_EMU_QUIET. Counted
		 * per instruction here, reset by the write that completes a
		 * read-write pair, and only ever consulted once the guest has
		 * shown it decrypts at all.
		 */
		/*
		 * OFF UNTIL IT IS RIGHT - see KOF_EMU_QUIET.
		 *
		 * The signal is measured and real; the THRESHOLD is not settled.
		 * Measured on four Sality samples: three stop correctly and the
		 * fourth stops 11,066 instructions in, having decrypted
		 * nothing, because a handful of sequential writes before the
		 * decryption starts arm the test. A stop rule that is right
		 * three times in four is a rule that loses a detection, so it
		 * stays behind a flag until the arming condition is measured
		 * across more than one family.
		 */
		if (e->active_n)
			e->since_active++;
		if (e->quiet_on && e->active_n &&
		    e->since_active > KOF_EMU_QUIET) {
			snprintf(e->detail, sizeof e->detail,
				 "%llu instructions since the last decryption "
				 "write, after %llu of them",
				 (unsigned long long)e->since_active,
				 (unsigned long long)e->active_n);
			e->stop = KOF_EMU_STOP_QUIET;
			goto done;
		}
		e->trace[e->trace_n++ % KOF_EMU_TRACE] = e->rip;
		if (e->itr && !e->itr_frozen &&
		    ((e->itr_at && e->rip == e->itr_at) ||
		     (e->itr_until && e->insn >= e->itr_until))) {
			const char *pk = getenv("KOF_EMU_PEEK");

			e->itr_frozen = 1;
			/* And what memory looked like AT THE FREEZE, which is
			 * the only moment a key a guest is comparing against
			 * is still where it was put. Reading it when the run
			 * stops is far too late. */
			while (pk && *pk) {
				/* Named apart from the instruction address
				 * `at` this shadows - see where that one is
				 * declared, and what the handover test below
				 * reads it for. */
				uint64_t keyat = (uint64_t)strtoull(pk, NULL, 0);
				uint8_t bf[128];
				unsigned q;

				if (mem_rd(e, keyat, bf, sizeof bf)) {
					fprintf(stderr, "[frz] %#llx ",
						(unsigned long long)keyat);
					for (q = 0; q < sizeof bf; q++)
						fputc(bf[q] >= 32 &&
						      bf[q] < 127
						      ? bf[q] : '.', stderr);
					fputc('\n', stderr);
				}
				pk = strchr(pk, ',');
				if (pk)
					pk++;
			}
		}
		if (e->itr && !e->itr_frozen) {
			struct itrace *it = &e->itr[e->itr_n++ % e->itr_cap];
			char t[ND_MIN_BUF_SIZE];
			unsigned q = 0;

			it->rip = e->rip;
			memcpy(it->gpr, e->gpr, sizeof it->gpr);
			/* The registers are copied BEFORE the instruction runs,
			 * which is the point: they are its inputs. */
			if (ND_SUCCESS(NdToText(ixp, e->rip, sizeof t, t)))
				while (q + 1u < sizeof it->txt && t[q]) {
					it->txt[q] = t[q];
					q++;
				}
			it->txt[q] = 0;
		}
		/* Cleared per instruction so the stop below can tell an operand
		 * this build cannot express from one it simply could not read.
		 * They were reported the same way, and an ordinary CMP against
		 * an unmapped address read as a missing instruction. */
		e->fault_va = 0;
		e->fault_kind[0] = 0;
		/*
		 * STOP WHEN IT STOPS PRODUCING.
		 *
		 * The instruction budget bounds a run that is working; nothing
		 * bounded one that is not. An unexpected object - junk padding,
		 * a loop waiting on something that will not happen, a decoder
		 * fed input it cannot use - would spin to the ceiling and cost
		 * a scan every second of it for nothing.
		 *
		 * Producing means touching a page for the first time, because
		 * that is what unpacking IS. Measured against the densest real
		 * work here, an interpreted LZMA decoder writing 2.7 MB over
		 * 250 million instructions: a new page every ~370 000. The
		 * ceiling below is an order of magnitude above that, so it
		 * cannot interrupt work, and it cuts an idle run to a fraction
		 * of a second whatever the budget allows.
		 */
		if (e->insn - e->last_new_page > e->idle_max)
			e->idle_max = e->insn - e->last_new_page;
		if (e->insn - e->last_new_page > e->idle) {
			fail(e, KOF_EMU_STOP_STALLED, NULL);
			break;
		}
		/* And the clock, when one was set - see kof_emu_set_deadline.
		 * Masked so the read happens once every 64K instructions. */
		if (e->deadline_ms && !(e->insn & 0xffffu) &&
		    now_ms() - e->started_ms > e->deadline_ms) {
			snprintf(e->detail, sizeof e->detail,
				 "deadline after %llu ms, %llu instructions",
				 (unsigned long long)(now_ms() - e->started_ms),
				 (unsigned long long)e->insn);
			e->stop = KOF_EMU_STOP_BUDGET;
			break;
		}
		next = e->rip + ixp->Length;
		sz = ixp->Operands[0].Size ? ixp->Operands[0].Size : 8u;
		e->insn++;

		/*
		 * AN INSTRUCTION THAT CANNOT CHANGE ANYTHING IS STEPPED OVER -
		 * see nop_insn, which decided this once when the entry was
		 * decoded.
		 *
		 * AFTER ALL THE BOOKKEEPING AND BEFORE THE SWITCH, deliberately:
		 * the instruction still counts, still enters the trace, still
		 * satisfies a module's watch and still moves the deadline. The
		 * only thing skipped is the work of executing something whose
		 * result is the state it started from. A junk generator emits
		 * these by the dozen - measured, eight of the 256 instructions
		 * in one Sality decryption loop.
		 *
		 * ONLY FROM THE CACHE. Deciding it on a miss would cost the test
		 * on every first sight of an instruction to save the execution
		 * of a handful, and the miss path is already the expensive one.
		 */
		if (ent && ent->inert) {
			e->rip = next;
			continue;
		}

		switch (ixp->Instruction) {
		/*
		 * Nothing to do, for a reason rather than by omission. The
		 * fences order accesses between threads and there is one
		 * thread; PAUSE hints at a spin loop; the prefetches move no
		 * architectural state; ENDBR is a landing pad.
		 */
		case ND_INS_NOP:
		case ND_INS_LFENCE: case ND_INS_SFENCE: case ND_INS_MFENCE:
		case ND_INS_PAUSE:  case ND_INS_ENDBR:
		case ND_INS_PREFETCHT0: case ND_INS_PREFETCHT1:
		case ND_INS_PREFETCHT2: case ND_INS_PREFETCHNTA:
		case ND_INS_PREFETCHW:
			break;

		/*
		 * ---- x87 ------------------------------------------------------
		 *
		 * WHAT THIS USED TO BE, because the shape is still visible. Only
		 * the instructions a GetPC sequence picks from were carried, and
		 * they were carried as NO-OPS that set `fpu_rip` and nothing
		 * else: a 32-bit shellcode encoder cannot say `lea eax, [rip]`,
		 * so it executes any x87 instruction and then FNSTENV, whose
		 * twelfth byte onward holds that instruction's address.
		 *
		 *     dd c3              ffree  st(3)      <- a marker, nothing else
		 *     d9 74 24 f4        fnstenv [esp-0xc]
		 *     5a                 pop    edx        <- edx = &ffree
		 *
		 * Those encoders never read a value, so no value was kept, and
		 * everything that COMPUTES was left to the unsupported path on
		 * purpose - running on with a wrong st0 and not saying so is the
		 * one failure an interpreter must not have.
		 *
		 * NOW THE VALUES ARE KEPT - see `st` in struct kof_emu - so the
		 * distinction is gone and these are executed for real. The GetPC
		 * sequences are unaffected: `fpu_rip` is still set by every one
		 * of them, and computing FFREE correctly is a superset of
		 * ignoring it.
		 *
		 * WHAT IS STILL ABSENT is the transcendental set - FSIN, FCOS,
		 * FPTAN, FYL2X and the rest - which keeps reaching the
		 * unsupported path. Not because they are hard, but because
		 * nothing measured has executed one, and an instruction nobody
		 * has met is an instruction whose implementation nobody can
		 * check.
		 */
		case ND_INS_FNOP:
			e->fpu_rip = e->rip;
			break;

		case ND_INS_FFREE:
		case ND_INS_FFREEP:
			e->fpu_rip = e->rip;
			if (ixp->OperandsCount &&
			    ixp->Operands[0].Type == ND_OP_REG &&
			    ixp->Operands[0].Info.Register.Type == ND_REG_FPU)
				e->st_tag[(e->st_top +
					   ixp->Operands[0].Info.Register.Reg) & 7u] = 0;
			if (ixp->Instruction == ND_INS_FFREEP)
				st_pop(e);
			break;

		case ND_INS_FDECSTP:
			e->fpu_rip = e->rip;
			e->st_top = (uint8_t)((e->st_top - 1u) & 7u);
			break;
		case ND_INS_FINCSTP:
			e->fpu_rip = e->rip;
			e->st_top = (uint8_t)((e->st_top + 1u) & 7u);
			break;

		case ND_INS_FXCH: {
			double t;
			unsigned i = 1u;

			e->fpu_rip = e->rip;
			if (ixp->OperandsCount > 1u &&
			    ixp->Operands[1].Type == ND_OP_REG &&
			    ixp->Operands[1].Info.Register.Type == ND_REG_FPU)
				i = ixp->Operands[1].Info.Register.Reg;
			t = st_get(e, 0);
			st_set(e, 0, st_get(e, i));
			st_set(e, i, t);
			break;
		}

		/*
		 * The constants. FLDZ and FLD1 were already here as no-ops and
		 * now push what they name; the other five never were, and they
		 * are the same instruction with a different number.
		 */
		case ND_INS_FLDZ:   e->fpu_rip = e->rip; st_push(e, 0.0); break;
		case ND_INS_FLD1:   e->fpu_rip = e->rip; st_push(e, 1.0); break;
		case ND_INS_FLDPI:  e->fpu_rip = e->rip;
			st_push(e, 3.14159265358979323846); break;
		case ND_INS_FLDL2E: e->fpu_rip = e->rip;
			st_push(e, 1.44269504088896340736); break;
		case ND_INS_FLDL2T: e->fpu_rip = e->rip;
			st_push(e, 3.32192809488736234787); break;
		case ND_INS_FLDLG2: e->fpu_rip = e->rip;
			st_push(e, 0.30102999566398119521); break;
		case ND_INS_FLDLN2: e->fpu_rip = e->rip;
			st_push(e, 0.69314718055994530942); break;

		case ND_INS_FABS: e->fpu_rip = e->rip;
			st_set(e, 0, fabs(st_get(e, 0))); break;
		case ND_INS_FCHS: e->fpu_rip = e->rip;
			st_set(e, 0, -st_get(e, 0)); break;
		case ND_INS_FSQRT: e->fpu_rip = e->rip;
			st_set(e, 0, sqrt(st_get(e, 0))); break;
		case ND_INS_FRNDINT: e->fpu_rip = e->rip;
			st_set(e, 0, nearbyint(st_get(e, 0))); break;

		/*
		 * FLD and FILD PUSH; they do not write their first operand.
		 * bddisasm names st0 as that operand because that is where the
		 * result ends up, but the register underneath it is a different
		 * one after the push - so the source is read first and the push
		 * is the whole of the write.
		 */
		case ND_INS_FLD:
		case ND_INS_FILD: {
			double v;

			e->fpu_rip = e->rip;
			if (ixp->OperandsCount < 2u ||
			    !fp_rd(e, ixp, &ixp->Operands[1],
				   ixp->Instruction == ND_INS_FILD, &v))
				goto unsupported;
			st_push(e, v);
			break;
		}

		case ND_INS_FST:
		case ND_INS_FSTP:
		case ND_INS_FIST:
		case ND_INS_FISTP:
		case ND_INS_FISTTP: {
			int is_int = ixp->Instruction != ND_INS_FST &&
				     ixp->Instruction != ND_INS_FSTP;
			double v = st_get(e, 0);

			e->fpu_rip = e->rip;
			/* FISTTP truncates toward zero whatever the rounding
			 * mode says; the others follow it, and this rounds to
			 * nearest, which is the mode a guest starts in. */
			if (ixp->Instruction == ND_INS_FISTTP)
				v = trunc(v);
			else if (is_int)
				v = nearbyint(v);
			if (!ixp->OperandsCount ||
			    !fp_wr(e, ixp, &ixp->Operands[0], is_int, v))
				goto unsupported;
			if (ixp->Instruction != ND_INS_FST &&
			    ixp->Instruction != ND_INS_FIST)
				st_pop(e);
			break;
		}

		/*
		 * THE ARITHMETIC, AS ONE CASE, because the only things that
		 * differ between twenty-odd mnemonics are the operator, whether
		 * the operands are swapped, whether the memory side is an
		 * integer, and whether the stack is popped afterwards. Writing
		 * them out separately is twenty chances to get one wrong.
		 *
		 * THE REVERSED FORMS ARE NOT A DETAIL. `FSUB` computes
		 * dst - src and `FSUBR` computes src - dst; a guest that divides
		 * with FDIVR and gets FDIV's answer has every later value wrong
		 * and nothing says so.
		 */
		case ND_INS_FADD: case ND_INS_FADDP: case ND_INS_FIADD:
		case ND_INS_FMUL: case ND_INS_FMULP: case ND_INS_FIMUL:
		case ND_INS_FSUB: case ND_INS_FSUBP: case ND_INS_FISUB:
		case ND_INS_FSUBR: case ND_INS_FSUBRP: case ND_INS_FISUBR:
		case ND_INS_FDIV: case ND_INS_FDIVP: case ND_INS_FIDIV:
		case ND_INS_FDIVR: case ND_INS_FDIVRP: case ND_INS_FIDIVR: {
			double fa, fb, fr;
			int is_int = 0, rev = 0, pop = 0;

			e->fpu_rip = e->rip;
			switch (ixp->Instruction) {
			case ND_INS_FIADD: case ND_INS_FIMUL:
			case ND_INS_FISUB: case ND_INS_FISUBR:
			case ND_INS_FIDIV: case ND_INS_FIDIVR:
				is_int = 1;
				break;
			default:
				break;
			}
			switch (ixp->Instruction) {
			case ND_INS_FSUBR: case ND_INS_FSUBRP: case ND_INS_FISUBR:
			case ND_INS_FDIVR: case ND_INS_FDIVRP: case ND_INS_FIDIVR:
				rev = 1;
				break;
			default:
				break;
			}
			switch (ixp->Instruction) {
			case ND_INS_FADDP: case ND_INS_FMULP:
			case ND_INS_FSUBP: case ND_INS_FSUBRP:
			case ND_INS_FDIVP: case ND_INS_FDIVRP:
				pop = 1;
				break;
			default:
				break;
			}
			if (ixp->OperandsCount < 2u ||
			    !fp_rd(e, ixp, &ixp->Operands[0], 0, &fa) ||
			    !fp_rd(e, ixp, &ixp->Operands[1], is_int, &fb))
				goto unsupported;
			if (rev) {
				double t = fa;

				fa = fb;
				fb = t;
			}
			switch (ixp->Instruction) {
			case ND_INS_FADD: case ND_INS_FADDP: case ND_INS_FIADD:
				fr = fa + fb; break;
			case ND_INS_FMUL: case ND_INS_FMULP: case ND_INS_FIMUL:
				fr = fa * fb; break;
			case ND_INS_FSUB: case ND_INS_FSUBP: case ND_INS_FISUB:
			case ND_INS_FSUBR: case ND_INS_FSUBRP: case ND_INS_FISUBR:
				fr = fa - fb; break;
			default:
				/*
				 * DIVIDING BY ZERO IS A VALUE, NOT A FAULT.
				 * Unmasked it would raise #DE; a guest that has
				 * not unmasked it - which is every guest here,
				 * since nothing writes the control word - gets
				 * an infinity and carries on, and so does this.
				 */
				fr = fa / fb; break;
			}
			if (!fp_wr(e, ixp, &ixp->Operands[0], 0, fr))
				goto unsupported;
			if (pop)
				st_pop(e);
			break;
		}

		/*
		 * THE COMPARES, which used to be here for their address alone.
		 * Two families: the FCOM group leaves its answer in the status
		 * word's condition codes, where a guest reads it with FNSTSW and
		 * branches on AH; the FCOMI group puts it straight in EFLAGS.
		 */
		case ND_INS_FCOM:  case ND_INS_FCOMP:  case ND_INS_FCOMPP:
		case ND_INS_FUCOM: case ND_INS_FUCOMP: case ND_INS_FUCOMPP:
		case ND_INS_FICOM: case ND_INS_FICOMP:
		case ND_INS_FTST: {
			double fa = st_get(e, 0), fb = 0.0;
			int is_int = ixp->Instruction == ND_INS_FICOM ||
				     ixp->Instruction == ND_INS_FICOMP;

			e->fpu_rip = e->rip;
			if (ixp->Instruction != ND_INS_FTST) {
				if (ixp->OperandsCount < 2u ||
				    !fp_rd(e, ixp, &ixp->Operands[1], is_int, &fb))
					goto unsupported;
			}
			fp_cmp_cc(e, fa, fb);
			switch (ixp->Instruction) {
			case ND_INS_FCOMP: case ND_INS_FUCOMP:
			case ND_INS_FICOMP:
				st_pop(e);
				break;
			case ND_INS_FCOMPP: case ND_INS_FUCOMPP:
				st_pop(e);
				st_pop(e);
				break;
			default:
				break;
			}
			break;
		}

		case ND_INS_FCOMI: case ND_INS_FCOMIP:
		case ND_INS_FUCOMI: case ND_INS_FUCOMIP: {
			double fa = st_get(e, 0), fb;

			e->fpu_rip = e->rip;
			if (ixp->OperandsCount < 2u ||
			    !fp_rd(e, ixp, &ixp->Operands[1], 0, &fb))
				goto unsupported;
			e->flags &= ~(uint64_t)(FL_ZF | FL_PF | FL_CF);
			if (isnan(fa) || isnan(fb))
				e->flags |= FL_ZF | FL_PF | FL_CF;
			else if (fa < fb)
				e->flags |= FL_CF;
			else if (fa == fb)
				e->flags |= FL_ZF;
			if (ixp->Instruction == ND_INS_FCOMIP ||
			    ixp->Instruction == ND_INS_FUCOMIP)
				st_pop(e);
			break;
		}

		/*
		 * FXAM classifies st0 into C3/C2/C0. It was a no-op here and a
		 * GetPC does not read it, but a guest that branches on "is this
		 * zero" does, and the classification is three comparisons.
		 */
		case ND_INS_FXAM: {
			double v = st_get(e, 0);

			e->fpu_rip = e->rip;
			e->fsw &= (uint16_t)~(FSW_C0 | FSW_C1 | FSW_C2 | FSW_C3);
			if (signbit(v))
				e->fsw |= FSW_C1;
			if (!e->st_tag[e->st_top])
				e->fsw |= (uint16_t)(FSW_C3 | FSW_C0);  /* empty */
			else if (isnan(v))
				e->fsw |= FSW_C0;
			else if (isinf(v))
				e->fsw |= (uint16_t)(FSW_C2 | FSW_C0);
			else if (v == 0.0)
				e->fsw |= FSW_C3;
			else
				e->fsw |= FSW_C2;                       /* normal */
			break;
		}

		/*
		 * The status word, which is how a guest reads a compare it made
		 * with the FCOM family: `fnstsw ax` then `sahf` or `test ah`.
		 * TOP sits in bits 11..13 and is part of what is reported.
		 */
		case ND_INS_FNSTSW: {
			uint64_t v = (uint64_t)(e->fsw |
					(uint16_t)((e->st_top & 7u) << 11));

			e->fpu_rip = e->rip;
			if (!ixp->OperandsCount ||
			    !op_wr(e, ixp, &ixp->Operands[0], v))
				goto unsupported;
			break;
		}

		/*
		 * The conditional moves. They were no-ops and the condition was
		 * never looked at; now the value moves when EFLAGS says it
		 * should, which is what a guest that used one is expecting.
		 */
		case ND_INS_FCMOVB:  case ND_INS_FCMOVBE: case ND_INS_FCMOVE:
		case ND_INS_FCMOVNB: case ND_INS_FCMOVNBE: case ND_INS_FCMOVNE:
		case ND_INS_FCMOVU:  case ND_INS_FCMOVNU: {
			int cf = (e->flags & FL_CF) != 0;
			int zf = (e->flags & FL_ZF) != 0;
			int pf = (e->flags & FL_PF) != 0;
			int take;
			double v;

			e->fpu_rip = e->rip;
			switch (ixp->Instruction) {
			case ND_INS_FCMOVB:   take = cf; break;
			case ND_INS_FCMOVE:   take = zf; break;
			case ND_INS_FCMOVBE:  take = cf || zf; break;
			case ND_INS_FCMOVU:   take = pf; break;
			case ND_INS_FCMOVNB:  take = !cf; break;
			case ND_INS_FCMOVNE:  take = !zf; break;
			case ND_INS_FCMOVNBE: take = !cf && !zf; break;
			default:              take = !pf; break;
			}
			if (!take)
				break;
			if (ixp->OperandsCount < 2u ||
			    !fp_rd(e, ixp, &ixp->Operands[1], 0, &v))
				goto unsupported;
			st_set(e, 0, v);
			break;
		}

		/*
		 * The control-word and state instructions that a guest issues to
		 * put the FPU in a known state. Nothing here reads the control
		 * word - rounding is always to nearest and every exception is
		 * masked - so these are accepted and only FINIT has an effect
		 * that anything can observe.
		 */
		case ND_INS_FLDCW:
		case ND_INS_FNSTCW:
		case ND_INS_FNCLEX:
			e->fpu_rip = e->rip;
			if (ixp->Instruction == ND_INS_FNSTCW && ixp->OperandsCount &&
			    !op_wr(e, ixp, &ixp->Operands[0], 0x037fu))
				goto unsupported;
			if (ixp->Instruction == ND_INS_FNCLEX)
				e->fsw = 0;
			break;

		case ND_INS_FNINIT: {
			unsigned q;

			e->fpu_rip = e->rip;
			for (q = 0; q < 8u; q++) {
				e->st[q] = 0.0;
				e->st_tag[q] = 0;
			}
			e->st_top = 0;
			e->fsw = 0;
			break;
		}

		/*
		 * The environment block, and the one field in it that matters.
		 *
		 * 28 bytes in 32 bit protected mode, and the address of the last
		 * non-control x87 instruction sits at offset 12. Everything else is
		 * written as zero: a control word, a status word and tag bits that
		 * nothing here maintains, and inventing values for them would be
		 * three more numbers a reader could mistake for real state.
		 *
		 * FNSTENV does not check for pending exceptions, which is why the
		 * encoders use it rather than FSTENV, and why nothing is checked
		 * here either.
		 */
		case ND_INS_FNSTENV: {
			uint8_t env[28];
			/* The operand's effective address. Named apart from
			 * `at`, the instruction address the handover test
			 * reads - see where that is declared. */
			uint64_t ea;

			memset(env, 0, sizeof env);
			env[12] = (uint8_t)(e->fpu_rip);
			env[13] = (uint8_t)(e->fpu_rip >> 8);
			env[14] = (uint8_t)(e->fpu_rip >> 16);
			env[15] = (uint8_t)(e->fpu_rip >> 24);
			if (ixp->Operands[0].Type != ND_OP_MEM ||
			    !ea_of(e, ixp, &ixp->Operands[0], &ea))
				goto unsupported;
			if (!mem_wr(e, ea, env, sizeof env))
				goto fault;
			break;
		}

		/*
		 * FXSAVE - THE OTHER GetPC, and the reason it is here.
		 *
		 * It saves the whole x87/SSE state, 512 bytes of it, and one
		 * field is the address of the last x87 instruction - the same
		 * value FNSTENV reports and the same use a stub makes of it.
		 * x64/zutto_dekiru opens with `fxsave [r8]` and died on its
		 * fifth instruction without it.
		 *
		 * The layout differs between the two forms and the difference
		 * matters, because a stub reads one exact offset:
		 *
		 *   FXSAVE64   FIP is 64 bits at offset 8
		 *   FXSAVE     FIP is 32 bits at offset 8, its selector at 12
		 *
		 * Everything else is written as zero. A run that needed the
		 * control word or a live xmm register out of this block would
		 * be doing arithmetic on the FPU, which nothing this interprets
		 * does - and a wrong answer there would be visible, not silent,
		 * because the stub would fetch from the wrong address.
		 */
		case ND_INS_FXSAVE:
		case ND_INS_FXSAVE64: {
			uint8_t area[512];
			uint64_t ea;         /* see FNSTENV above */

			memset(area, 0, sizeof area);
			if (ixp->Instruction == ND_INS_FXSAVE64) {
				unsigned k;

				for (k = 0; k < 8u; k++)
					area[8 + k] = (uint8_t)(e->fpu_rip >>
								(k * 8));
			} else {
				area[8]  = (uint8_t)(e->fpu_rip);
				area[9]  = (uint8_t)(e->fpu_rip >> 8);
				area[10] = (uint8_t)(e->fpu_rip >> 16);
				area[11] = (uint8_t)(e->fpu_rip >> 24);
			}
			if (ixp->Operands[0].Type != ND_OP_MEM ||
			    !ea_of(e, ixp, &ixp->Operands[0], &ea))
				goto unsupported;
			if (!mem_wr(e, ea, area, sizeof area))
				goto fault;
			break;
		}

		/*
		 * A clock that only moves forward. Real time would make a run
		 * unreproducible, and a stub that times itself is looking for a
		 * debugger - a steady tick reads as an ordinary machine.
		 */
		case ND_INS_RDTSC: case ND_INS_RDTSCP: {
			uint64_t now = tsc_read(e);

			reg_wr(e, KOF_EMU_RAX, 4, 0, now & 0xffffffffu);
			reg_wr(e, KOF_EMU_RDX, 4, 0, now >> 32);
			if (ixp->Instruction == ND_INS_RDTSCP)
				reg_wr(e, KOF_EMU_RCX, 4, 0, 0);
			break;
		}

		/*
		 * The SSE control word, read and written but never acted on:
		 * this interprets scalar arithmetic with the host's own double,
		 * so a rounding mode it stored would change nothing. Kept so
		 * that a caller which saves it and restores it sees what it
		 * wrote, which is all any of them check.
		 */
		case ND_INS_STMXCSR:
			if (!op_wr(e, ixp, &ixp->Operands[0], e->mxcsr))
				goto unsupported;
			break;
		case ND_INS_LDMXCSR:
			if (!op_rd(e, ixp, &ixp->Operands[0], &a))
				goto unsupported;
			e->mxcsr = (uint32_t)a;
			break;

		/* XCR0: x87 and SSE enabled, nothing wider - which is the truth
		 * about this machine, and keeps a runtime off the AVX paths. */
		case ND_INS_XGETBV:
			reg_wr(e, KOF_EMU_RAX, 4, 0, 3);
			reg_wr(e, KOF_EMU_RDX, 4, 0, 0);
			break;

		/*
		 * The atomics a runtime starts on. LOCK is a no-op here - one
		 * thread, so the read-modify-write is already indivisible.
		 */
		case ND_INS_CMPXCHG: {
			uint64_t dst, src, acc = reg_rd(e, KOF_EMU_RAX, sz, 0);

			if (!op_rd(e, ixp, &ixp->Operands[0], &dst) ||
			    !op_rd(e, ixp, &ixp->Operands[1], &src))
				goto unsupported;
			fl_sub(e, acc, dst, 0, sz);
			if (((acc ^ dst) & mask_of(sz)) == 0) {
				if (!op_wr(e, ixp, &ixp->Operands[0], src))
					goto unsupported;
			} else {
				reg_wr(e, KOF_EMU_RAX, sz, 0, dst);
			}
			break;
		}

		case ND_INS_XADD: {
			uint64_t dst, src;

			if (!op_rd(e, ixp, &ixp->Operands[0], &dst) ||
			    !op_rd(e, ixp, &ixp->Operands[1], &src))
				goto unsupported;
			fl_add(e, dst, src, 0, sz);
			if (!op_wr(e, ixp, &ixp->Operands[1], dst) ||
			    !op_wr(e, ixp, &ixp->Operands[0], dst + src))
				goto unsupported;
			break;
		}

		/*
		 * Unsigned multiply and both divides. The 128-bit dividend a
		 * 64-bit DIV can take is not representable here, so that one
		 * case stops rather than returning a wrong quotient - and a
		 * divide by zero stops too, since there is no #DE to raise.
		 */
		case ND_INS_MUL: {
			uint64_t acc = reg_rd(e, KOF_EMU_RAX, sz, 0), hi;

			if (!op_rd(e, ixp, &ixp->Operands[0], &a))
				goto unsupported;
			if (sz == 8) {
				uint64_t al = acc & 0xffffffffu, ah = acc >> 32;
				uint64_t bl = a & 0xffffffffu, bh = a >> 32;
				uint64_t m0 = al * bl, m1 = al * bh, m2 = ah * bl;
				uint64_t carry = ((m0 >> 32) + (m1 & 0xffffffffu) +
						  (m2 & 0xffffffffu)) >> 32;

				hi = ah * bh + (m1 >> 32) + (m2 >> 32) + carry;
				reg_wr(e, KOF_EMU_RAX, 8, 0, acc * a);
				reg_wr(e, KOF_EMU_RDX, 8, 0, hi);
			} else {
				uint64_t r64 = (acc & mask_of(sz)) * (a & mask_of(sz));

				hi = (r64 >> (sz * 8u)) & mask_of(sz);
				/* 8-bit MUL lands the whole 16-bit product in AX;
				 * every wider size splits it AX/DX. */
				if (sz == 1) {
					reg_wr(e, KOF_EMU_RAX, 2, 0, r64);
				} else {
					reg_wr(e, KOF_EMU_RAX, sz, 0, r64);
					reg_wr(e, KOF_EMU_RDX, sz, 0, hi);
				}
			}
			e->flags = hi ? (e->flags | FL_CF | FL_OF)
				      : (e->flags & ~(uint64_t)(FL_CF | FL_OF));
			break;
		}

		case ND_INS_DIV: case ND_INS_IDIV: {
			uint64_t lo = reg_rd(e, KOF_EMU_RAX, sz, 0);
			uint64_t hi = reg_rd(e, KOF_EMU_RDX, sz, 0);

			if (!op_rd(e, ixp, &ixp->Operands[0], &a))
				goto unsupported;
			a &= mask_of(sz);
			if (!a || (sz == 8 && hi))
				goto unsupported;
			if (sz == 8) {
				if (ixp->Instruction == ND_INS_DIV) {
					reg_wr(e, KOF_EMU_RAX, 8, 0, lo / a);
					reg_wr(e, KOF_EMU_RDX, 8, 0, lo % a);
				} else {
					int64_t n, d = (int64_t)a;

					/*
					 * hi is 0 here, so the true dividend is the
					 * non-negative value lo. If lo's top bit is
					 * set, (int64_t)lo reads back negative and the
					 * signed division would be wrong - stop rather
					 * than answer wrongly, as the hi!=0 case above
					 * already does.
					 */
					if ((int64_t)lo < 0)
						goto unsupported;
					n = (int64_t)lo;
					reg_wr(e, KOF_EMU_RAX, 8, 0, (uint64_t)(n / d));
					reg_wr(e, KOF_EMU_RDX, 8, 0, (uint64_t)(n % d));
				}
			} else {
				uint64_t n = (hi << (sz * 8u)) | (lo & mask_of(sz));

				if (ixp->Instruction == ND_INS_IDIV) {
					int64_t sn = (int64_t)sext(n, sz * 2u);
					int64_t sd = (int64_t)sext(a, sz);

					if (!sd)
						goto unsupported;
					reg_wr(e, KOF_EMU_RAX, sz, 0, (uint64_t)(sn / sd));
					reg_wr(e, KOF_EMU_RDX, sz, 0, (uint64_t)(sn % sd));
				} else {
					reg_wr(e, KOF_EMU_RAX, sz, 0, n / a);
					reg_wr(e, KOF_EMU_RDX, sz, 0, n % a);
				}
			}
			break;
		}

		/* Bit test and set/reset/complement: CPU feature bitmaps. */
		case ND_INS_BT: case ND_INS_BTS: case ND_INS_BTR: case ND_INS_BTC: {
			uint64_t bit, val;
			unsigned w = sz * 8u;

			if (!op_rd(e, ixp, &ixp->Operands[0], &val) ||
			    !op_rd(e, ixp, &ixp->Operands[1], &bit))
				goto unsupported;
			bit &= w - 1u;
			e->flags = (e->flags & ~FL_CF) |
				   (((val >> bit) & 1u) ? FL_CF : 0u);
			if (ixp->Instruction == ND_INS_BTS)      val |=  (uint64_t)1 << bit;
			else if (ixp->Instruction == ND_INS_BTR) val &= ~((uint64_t)1 << bit);
			else if (ixp->Instruction == ND_INS_BTC) val ^=  (uint64_t)1 << bit;
			if (ixp->Instruction != ND_INS_BT &&
			    !op_wr(e, ixp, &ixp->Operands[0], val))
				goto unsupported;
			break;
		}

		/* Scan for the first or last set bit; ZF says there was none. */
		case ND_INS_BSF: case ND_INS_BSR:
		case ND_INS_TZCNT: case ND_INS_LZCNT: {
			uint64_t v, k;
			unsigned w = sz * 8u;

			if (!op_rd(e, ixp, &ixp->Operands[1], &v))
				goto unsupported;
			if (!v) {
				e->flags |= FL_ZF;
				if (ixp->Instruction == ND_INS_TZCNT ||
				    ixp->Instruction == ND_INS_LZCNT) {
					e->flags |= FL_CF;
					if (!op_wr(e, ixp, &ixp->Operands[0], w))
						goto unsupported;
				}
				break;
			}
			e->flags &= ~(uint64_t)(FL_ZF | FL_CF);
			if (ixp->Instruction == ND_INS_BSF ||
			    ixp->Instruction == ND_INS_TZCNT) {
				for (k = 0; !((v >> k) & 1u); k++)
					;
			} else {
				for (k = w - 1u; !((v >> k) & 1u); k--)
					;
				if (ixp->Instruction == ND_INS_LZCNT)
					k = w - 1u - k;
			}
			if (!op_wr(e, ixp, &ixp->Operands[0], k))
				goto unsupported;
			break;
		}

		case ND_INS_POPCNT: {
			uint64_t v, n = 0;

			if (!op_rd(e, ixp, &ixp->Operands[1], &v))
				goto unsupported;
			while (v) { n += v & 1u; v >>= 1; }
			e->flags = (e->flags & ~(uint64_t)(FL_ZF | FL_CF | FL_OF |
							   FL_SF | FL_PF | FL_AF)) |
				   (n ? 0u : FL_ZF);
			if (!op_wr(e, ixp, &ixp->Operands[0], n))
				goto unsupported;
			break;
		}

		/*
		 * The SSE a runtime uses to move and compare bytes. Vector
		 * arithmetic is deliberately absent: nothing that unpacks a
		 * payload needs it, and guessing at it would produce wrong
		 * bytes instead of an honest stop.
		 */
		case ND_INS_MOVUPS: case ND_INS_MOVAPS:
		case ND_INS_MOVUPD: case ND_INS_MOVAPD:
		case ND_INS_MOVDQU: case ND_INS_MOVDQA:
		case ND_INS_MOVSS:  case ND_INS_MOVSD:
		case ND_INS_MOVD:   case ND_INS_MOVQ:
		/* The half-register loads and stores a memcpy is built from. */
		case ND_INS_MOVLPS: case ND_INS_MOVLPD: {
			uint8_t v[16];
			unsigned n;

			if (!vec_rd(e, ixp, &ixp->Operands[1], v, &n) ||
			    !vec_wr(e, ixp, &ixp->Operands[0], v, n))
				goto unsupported;
			break;
		}

		case ND_INS_XORPS: case ND_INS_XORPD: case ND_INS_PXOR:
		case ND_INS_POR:   case ND_INS_PAND:  case ND_INS_PANDN:
		case ND_INS_ORPS:  case ND_INS_ORPD:
		case ND_INS_ANDPS: case ND_INS_ANDPD:
		case ND_INS_ANDNPS: case ND_INS_ANDNPD:
		case ND_INS_PCMPEQB: case ND_INS_PSUBB: {
			uint8_t x[16], y[16];
			unsigned nx, ny, k;

			if (!vec_rd(e, ixp, &ixp->Operands[0], x, &nx) ||
			    !vec_rd(e, ixp, &ixp->Operands[1], y, &ny))
				goto unsupported;
			for (k = 0; k < 16; k++)
				switch (ixp->Instruction) {
				case ND_INS_XORPS: case ND_INS_XORPD:
				case ND_INS_PXOR:    x[k] ^= y[k]; break;
				case ND_INS_POR:  case ND_INS_ORPS:
				case ND_INS_ORPD:    x[k] |= y[k]; break;
				case ND_INS_PAND: case ND_INS_ANDPS:
				case ND_INS_ANDPD:   x[k] &= y[k]; break;
				case ND_INS_PANDN: case ND_INS_ANDNPS:
				case ND_INS_ANDNPD:  x[k] = (uint8_t)(~x[k] & y[k]); break;
				case ND_INS_PSUBB:   x[k] = (uint8_t)(x[k] - y[k]); break;
				default:             x[k] = x[k] == y[k] ? 0xffu : 0u; break;
				}
			if (!vec_wr(e, ixp, &ixp->Operands[0], x, nx))
				goto unsupported;
			break;
		}

		/*
		 * SCALAR DOUBLE AND SINGLE, WHICH IS NOT OPTIONAL EITHER.
		 *
		 * No packer needs floating point to unpack, but a Go runtime
		 * checks its own arithmetic before running anything and traps
		 * when the answers are wrong - so a Go-built packer never
		 * reaches its payload without these. The host is IEEE754 and
		 * so is the guest, so the host's own double does the work.
		 */
		case ND_INS_ADDSD: case ND_INS_SUBSD: case ND_INS_MULSD:
		case ND_INS_DIVSD: case ND_INS_MAXSD: case ND_INS_MINSD:
		case ND_INS_SQRTSD:
		case ND_INS_ADDSS: case ND_INS_SUBSS: case ND_INS_MULSS:
		case ND_INS_DIVSS: {
			uint8_t x[16], y[16];
			unsigned nx, ny;
			int dbl = ixp->Instruction == ND_INS_ADDSD ||
				  ixp->Instruction == ND_INS_SUBSD ||
				  ixp->Instruction == ND_INS_MULSD ||
				  ixp->Instruction == ND_INS_DIVSD ||
				  ixp->Instruction == ND_INS_MAXSD ||
				  ixp->Instruction == ND_INS_MINSD ||
				  ixp->Instruction == ND_INS_SQRTSD;
			double u, v, w;
			float  fu, fv, fw;

			if (!vec_rd(e, ixp, &ixp->Operands[0], x, &nx) ||
			    !vec_rd(e, ixp, &ixp->Operands[1], y, &ny))
				goto unsupported;
			if (dbl) { memcpy(&u, x, 8); memcpy(&v, y, 8); }
			else     { memcpy(&fu, x, 4); memcpy(&fv, y, 4); u = fu; v = fv; }
			switch (ixp->Instruction) {
			case ND_INS_ADDSD: case ND_INS_ADDSS: w = u + v; break;
			case ND_INS_SUBSD: case ND_INS_SUBSS: w = u - v; break;
			case ND_INS_MULSD: case ND_INS_MULSS: w = u * v; break;
			case ND_INS_DIVSD: case ND_INS_DIVSS: w = u / v; break;
			case ND_INS_MAXSD: w = v > u ? v : u; break;
			case ND_INS_MINSD: w = v < u ? v : u; break;
			default:           w = v >= 0 ? sqrt(v) : (v - v) / (v - v); break;
			}
			if (dbl) { memcpy(x, &w, 8); }
			else     { fw = (float)w; memcpy(x, &fw, 4); }
			if (!vec_wr(e, ixp, &ixp->Operands[0], x, nx))
				goto unsupported;
			break;
		}

		case ND_INS_UCOMISD: case ND_INS_COMISD:
		case ND_INS_UCOMISS: case ND_INS_COMISS: {
			uint8_t x[16], y[16];
			unsigned nx, ny;
			int dbl = ixp->Instruction == ND_INS_UCOMISD ||
				  ixp->Instruction == ND_INS_COMISD;
			double u, v;
			float fu, fv;

			if (!vec_rd(e, ixp, &ixp->Operands[0], x, &nx) ||
			    !vec_rd(e, ixp, &ixp->Operands[1], y, &ny))
				goto unsupported;
			if (dbl) { memcpy(&u, x, 8); memcpy(&v, y, 8); }
			else     { memcpy(&fu, x, 4); memcpy(&fv, y, 4); u = fu; v = fv; }
			e->flags &= ~(uint64_t)(FL_ZF | FL_PF | FL_CF | FL_OF |
						FL_SF | FL_AF);
			if (u != u || v != v)          /* unordered */
				e->flags |= FL_ZF | FL_PF | FL_CF;
			else if (u < v)                e->flags |= FL_CF;
			else if (u == v)               e->flags |= FL_ZF;
			break;
		}

		case ND_INS_CVTSI2SD: case ND_INS_CVTSI2SS:
		case ND_INS_CVTSD2SS: case ND_INS_CVTSS2SD: {
			uint8_t x[16] = { 0 }, y[16];
			unsigned ny;
			double d;
			float f;

			if (ixp->Instruction == ND_INS_CVTSI2SD ||
			    ixp->Instruction == ND_INS_CVTSI2SS) {
				if (!op_rd(e, ixp, &ixp->Operands[1], &a))
					goto unsupported;
				d = (double)(int64_t)sext(a,
					ixp->Operands[1].Size ? ixp->Operands[1].Size : 8u);
			} else {
				if (!vec_rd(e, ixp, &ixp->Operands[1], y, &ny))
					goto unsupported;
				if (ixp->Instruction == ND_INS_CVTSS2SD) {
					memcpy(&f, y, 4); d = f;
				} else {
					memcpy(&d, y, 8);
				}
			}
			if (ixp->Instruction == ND_INS_CVTSI2SS ||
			    ixp->Instruction == ND_INS_CVTSD2SS) {
				f = (float)d; memcpy(x, &f, 4);
			} else {
				memcpy(x, &d, 8);
			}
			if (!vec_wr(e, ixp, &ixp->Operands[0], x, 16))
				goto unsupported;
			break;
		}

		case ND_INS_CVTTSD2SI: case ND_INS_CVTTSS2SI: {
			uint8_t y[16];
			unsigned ny;
			double d;
			float f;

			if (!vec_rd(e, ixp, &ixp->Operands[1], y, &ny))
				goto unsupported;
			if (ixp->Instruction == ND_INS_CVTTSD2SI)
				memcpy(&d, y, 8);
			else { memcpy(&f, y, 4); d = f; }
			if (!op_wr(e, ixp, &ixp->Operands[0], (uint64_t)(int64_t)d))
				goto unsupported;
			break;
		}

		/*
		 * The high half, and the one-word insert and extract. Present
		 * because real samples stopped on them: a UPX payload's own
		 * startup used MOVHPS and another used PINSRW, and one
		 * unimplemented opcode ends a run that had otherwise reached
		 * its payload.
		 */
		case ND_INS_MOVHPS: case ND_INS_MOVHPD: {
			uint8_t x[16], y[16];
			unsigned nx, ny;

			if (ixp->Operands[0].Type == ND_OP_MEM) {
				/* store: the high half goes to memory */
				if (!vec_rd(e, ixp, &ixp->Operands[1], y, &ny))
					goto unsupported;
				if (!vec_wr(e, ixp, &ixp->Operands[0], y + 8, 8))
					goto unsupported;
			} else {
				if (!vec_rd(e, ixp, &ixp->Operands[0], x, &nx) ||
				    !vec_rd(e, ixp, &ixp->Operands[1], y, &ny))
					goto unsupported;
				memcpy(x + 8, y, 8);
				if (!vec_wr(e, ixp, &ixp->Operands[0], x, 16))
					goto unsupported;
			}
			break;
		}

		case ND_INS_PINSRW: {
			uint8_t x[16];
			unsigned nx;
			uint64_t v, sel;

			if (!vec_rd(e, ixp, &ixp->Operands[0], x, &nx) ||
			    !op_rd(e, ixp, &ixp->Operands[1], &v) ||
			    !op_rd(e, ixp, &ixp->Operands[2], &sel))
				goto unsupported;
			x[(sel & 7u) * 2u]      = (uint8_t)v;
			x[(sel & 7u) * 2u + 1u] = (uint8_t)(v >> 8);
			if (!vec_wr(e, ixp, &ixp->Operands[0], x, 16))
				goto unsupported;
			break;
		}

		case ND_INS_PEXTRW: {
			uint8_t y[16];
			unsigned ny;
			uint64_t sel;

			if (!vec_rd(e, ixp, &ixp->Operands[1], y, &ny) ||
			    !op_rd(e, ixp, &ixp->Operands[2], &sel))
				goto unsupported;
			if (!op_wr(e, ixp, &ixp->Operands[0],
				   (uint64_t)y[(sel & 7u) * 2u] |
				   ((uint64_t)y[(sel & 7u) * 2u + 1u] << 8)))
				goto unsupported;
			break;
		}

		case ND_INS_PMOVMSKB: {
			uint8_t y[16];
			unsigned ny, k;
			uint64_t m = 0;

			if (!vec_rd(e, ixp, &ixp->Operands[1], y, &ny))
				goto unsupported;
			for (k = 0; k < 16; k++)
				m |= (uint64_t)(y[k] >> 7) << k;
			if (!op_wr(e, ixp, &ixp->Operands[0], m))
				goto unsupported;
			break;
		}

		case ND_INS_PSLLDQ: case ND_INS_PSRLDQ: {
			uint8_t x[16], q[16] = { 0 };
			unsigned nx, k;
			uint64_t sh;

			if (!vec_rd(e, ixp, &ixp->Operands[0], x, &nx) ||
			    !op_rd(e, ixp, &ixp->Operands[1], &sh))
				goto unsupported;
			if (sh < 16)
				for (k = 0; k < 16u - sh; k++) {
					if (ixp->Instruction == ND_INS_PSLLDQ)
						q[k + sh] = x[k];
					else
						q[k] = x[k + sh];
				}
			if (!vec_wr(e, ixp, &ixp->Operands[0], q, 16))
				goto unsupported;
			break;
		}

		case ND_INS_PUNPCKLBW: {
			uint8_t x[16], y[16], q[16];
			unsigned nx, ny, k;

			if (!vec_rd(e, ixp, &ixp->Operands[0], x, &nx) ||
			    !vec_rd(e, ixp, &ixp->Operands[1], y, &ny))
				goto unsupported;
			for (k = 0; k < 8; k++) {
				q[k * 2u]      = x[k];
				q[k * 2u + 1u] = y[k];
			}
			if (!vec_wr(e, ixp, &ixp->Operands[0], q, 16))
				goto unsupported;
			break;
		}

		case ND_INS_PSHUFD: {
			uint8_t y[16], q[16];
			unsigned ny, k;
			uint64_t sel;

			if (!vec_rd(e, ixp, &ixp->Operands[1], y, &ny) ||
			    !op_rd(e, ixp, &ixp->Operands[2], &sel))
				goto unsupported;
			for (k = 0; k < 4; k++)
				memcpy(q + k * 4u, y + ((sel >> (k * 2u)) & 3u) * 4u, 4);
			if (!vec_wr(e, ixp, &ixp->Operands[0], q, 16))
				goto unsupported;
			break;
		}

		case ND_INS_MOV:
		case ND_INS_MOVZX:
			if (!op_rd(e, ixp, &ixp->Operands[1], &b) ||
			    !op_wr(e, ixp, &ixp->Operands[0], b))
				goto unsupported;
			break;

		case ND_INS_MOVSX:
		case ND_INS_MOVSXD: {
			unsigned sb = ixp->Operands[1].Size ? ixp->Operands[1].Size : 1u;

			if (!op_rd(e, ixp, &ixp->Operands[1], &b))
				goto unsupported;
			if (sb < 8 && (b >> (sb * 8u - 1u)) & 1u)
				b |= ~mask_of(sb);
			if (!op_wr(e, ixp, &ixp->Operands[0], b))
				goto unsupported;
			break;
		}

		case ND_INS_LEA: {
			uint64_t ea;

			if (!ea_of(e, ixp, &ixp->Operands[1], &ea) ||
			    !op_wr(e, ixp, &ixp->Operands[0], ea))
				goto unsupported;
			break;
		}

		case ND_INS_XCHG:
			if (!op_rd(e, ixp, &ixp->Operands[0], &a) ||
			    !op_rd(e, ixp, &ixp->Operands[1], &b) ||
			    !op_wr(e, ixp, &ixp->Operands[0], b) ||
			    !op_wr(e, ixp, &ixp->Operands[1], a))
				goto unsupported;
			break;

		case ND_INS_ADD: case ND_INS_ADC:
		case ND_INS_SUB: case ND_INS_SBB: case ND_INS_CMP:
		case ND_INS_AND: case ND_INS_OR:  case ND_INS_XOR:
		case ND_INS_TEST: {
			uint64_t cin = 0;

			if (!op_rd(e, ixp, &ixp->Operands[0], &a) ||
			    !op_rd(e, ixp, &ixp->Operands[1], &b))
				goto unsupported;
			if (ixp->Instruction == ND_INS_ADC ||
			    ixp->Instruction == ND_INS_SBB)
				cin = (e->flags & FL_CF) ? 1u : 0u;
			switch (ixp->Instruction) {
			case ND_INS_ADD: case ND_INS_ADC:
				r = a + b + cin; fl_add(e, a, b, cin, sz); break;
			case ND_INS_SUB: case ND_INS_SBB: case ND_INS_CMP:
				r = a - b - cin; fl_sub(e, a, b, cin, sz); break;
			case ND_INS_AND: case ND_INS_TEST:
				r = a & b; fl_logic(e, r, sz); break;
			case ND_INS_OR:
				r = a | b; fl_logic(e, r, sz); break;
			default:
				r = a ^ b; fl_logic(e, r, sz); break;
			}
			if (ixp->Instruction != ND_INS_CMP &&
			    ixp->Instruction != ND_INS_TEST &&
			    !op_wr(e, ixp, &ixp->Operands[0], r))
				goto unsupported;
			break;
		}

		case ND_INS_INC: case ND_INS_DEC: {
			uint64_t cf = e->flags & FL_CF;

			if (!op_rd(e, ixp, &ixp->Operands[0], &a))
				goto unsupported;
			if (ixp->Instruction == ND_INS_INC) {
				r = a + 1u; fl_add(e, a, 1u, 0, sz);
			} else {
				r = a - 1u; fl_sub(e, a, 1u, 0, sz);
			}
			/* INC and DEC leave CF alone - the one thing that makes
			 * them different from ADD/SUB by one, and the reason a
			 * carry-chained loop written with them still works. */
			e->flags = (e->flags & ~(uint64_t)FL_CF) | cf;
			if (!op_wr(e, ixp, &ixp->Operands[0], r))
				goto unsupported;
			break;
		}

		case ND_INS_NEG:
			if (!op_rd(e, ixp, &ixp->Operands[0], &a))
				goto unsupported;
			r = 0u - a;
			fl_sub(e, 0, a, 0, sz);
			if (!op_wr(e, ixp, &ixp->Operands[0], r))
				goto unsupported;
			break;

		case ND_INS_NOT:
			if (!op_rd(e, ixp, &ixp->Operands[0], &a) ||
			    !op_wr(e, ixp, &ixp->Operands[0], ~a))
				goto unsupported;
			break;

		/*
		 * RCL / RCR - THE ROTATE THAT INCLUDES CF, AND THAT IS THE
		 * WHOLE DIFFERENCE FROM THE PAIR BELOW.
		 *
		 * ROL and ROR rotate w bits; these rotate w+1, with the carry
		 * flag as the extra bit. So the count is taken modulo w+1 and
		 * not modulo w, and a protector that uses them as a checksum -
		 * which is what they are for outside of multiprecision
		 * arithmetic - gets a different answer from either mistake.
		 *
		 * Measured: two of the four protected samples stopped here,
		 * with "unsupported: RCR ax, 1", having run 25.9 and 26.7
		 * million instructions to reach it.
		 */
		case ND_INS_RCL: case ND_INS_RCR: {
			unsigned n, rc, w = sz * 8u, i;
			uint64_t m = mask_of(sz), cf;

			if (!op_rd(e, ixp, &ixp->Operands[0], &a) ||
			    !op_rd(e, ixp, &ixp->Operands[1], &b))
				goto unsupported;
			n = (unsigned)(b & (sz == 8 ? 63u : 31u));
			/*
			 * 8- and 16-bit forms take the count modulo 9 and 17;
			 * the wider ones are already below w+1 after the mask
			 * above. The architecture says so and it is not an
			 * optimisation - a count of 9 on a byte is a full turn
			 * and leaves the operand alone.
			 */
			rc = n % (w + 1u);
			if (!rc) break;
			a &= m;
			cf = (e->flags & FL_CF) ? 1u : 0u;
			/*
			 * One step at a time, w+1 bits wide. A closed form
			 * needs three shifts and two conditionals per
			 * direction and is where this kind of code goes wrong;
			 * the count is at most 64 and these run once.
			 */
			for (i = 0; i < rc; i++) {
				if (ixp->Instruction == ND_INS_RCL) {
					uint64_t top = (a >> (w - 1u)) & 1u;

					a = ((a << 1) | cf) & m;
					cf = top;
				} else {
					uint64_t bot = a & 1u;

					a = ((a >> 1) | (cf << (w - 1u))) & m;
					cf = bot;
				}
			}
			r = a;
			e->flags &= ~(uint64_t)FL_CF;
			if (cf)
				e->flags |= FL_CF;
			/* OF is defined for a count of one alone, as above. */
			if (n == 1) {
				e->flags &= ~(uint64_t)FL_OF;
				if (ixp->Instruction == ND_INS_RCL) {
					if (((r >> (w - 1u)) & 1u) ^ (cf & 1u))
						e->flags |= FL_OF;
				} else {
					if (((r >> (w - 1u)) & 1u) ^
					    ((r >> (w - 2u)) & 1u))
						e->flags |= FL_OF;
				}
			}
			if (!op_wr(e, ixp, &ixp->Operands[0], r))
				goto unsupported;
			break;
		}

		/*
		 * SHIFTS and ROTATES are split, because they touch DIFFERENT
		 * flags: a shift sets SF/ZF/PF from its result like a logical op,
		 * a rotate leaves those four alone and moves only CF and OF. The
		 * old code ran both through fl_logic and so clobbered SF/ZF/PF on
		 * every rotate and left CF/OF wrong - a `rol; jc` read a carry
		 * that was always zero.
		 *
		 * The count is masked to five bits (six at 64) as the hardware
		 * does, and then - the second thing the old code got wrong -
		 * BOUNDED to the operand width before it reaches a C shift. A
		 * `sar al, 12` delivers a count of 12 against an 8-bit value, and
		 * `>> 12` past a byte sign-extended into 64 bits is a shift of 68:
		 * undefined in C, and on the host it wraps mod 64 to a wrong
		 * answer rather than the all-sign-bits x86 produces.
		 */
		/*
		 * SHRD AND SHLD, which an obfuscator reaches for because they
		 * are the one shift that mixes two registers - measured, a
		 * VMProtect stub reaches one 78 instructions in and nothing
		 * else in this build decoded it.
		 *
		 * The count is masked like the other shifts; a count of zero
		 * leaves the flags alone, and a count past the width is
		 * UNDEFINED on the hardware, so it is refused rather than
		 * invented.
		 */
		case ND_INS_SHRD: case ND_INS_SHLD: {
			unsigned n, w = sz * 8u;
			uint64_t m = mask_of(sz), src;

			if (!op_rd(e, ixp, &ixp->Operands[0], &a) ||
			    !op_rd(e, ixp, &ixp->Operands[1], &src) ||
			    !op_rd(e, ixp, &ixp->Operands[2], &b))
				goto unsupported;
			n = (unsigned)(b & (sz == 8 ? 63u : 31u));
			if (!n)
				break;
			a &= m;
			src &= m;
			/*
			 * A COUNT PAST THE OPERAND SIZE, WHICH ONLY 16 BIT
			 * OPERANDS CAN HAVE - the mask is 31, so 32 and 64 bit
			 * forms never reach it.
			 *
			 * Intel calls the result undefined here, and that is
			 * precisely why a protector uses it: the hardware still
			 * produces something, consistently, because the shift
			 * runs on a 32 bit datapath over the concatenation of
			 * the two operands. An interpreter that refuses the
			 * instruction is telling the guest it is not a CPU.
			 * Measured, a VMProtect stub reaches `shrd cx, ax, 0x51`
			 * - count 17 on a 16 bit pair - 78 instructions in.
			 *
			 * So it is computed the way the datapath does it, and
			 * the comment says that this is a choice about
			 * undefined behaviour rather than an architectural
			 * fact.
			 */
			if (n >= w) {
#ifdef KOF_HOST_DSHIFT
				uint64_t hf = 0;

				if (sz != 2u)
					goto unsupported;
				r = host_dshift16((uint16_t)a, (uint16_t)src,
						  (uint8_t)n,
						  ixp->Instruction == ND_INS_SHLD,
						  &hf);
				/* The host's own flags, for the bits this
				 * models - the guest reads them back with
				 * pushf and folds them in. */
				{
					uint64_t keep = FL_CF | FL_PF | FL_AF |
							FL_ZF | FL_SF | FL_OF;

					e->flags = (e->flags & ~keep) |
						   (hf & keep);
				}
				if (!op_wr(e, ixp, &ixp->Operands[0], r))
					goto unsupported;
				break;
#else
				goto unsupported;
#endif
			}
			if (ixp->Instruction == ND_INS_SHRD) {
				r = ((a >> n) | (src << (w - n))) & m;
				if ((a >> (n - 1u)) & 1u)
					b = 1;
				else
					b = 0;
			} else {
				r = ((a << n) | (src >> (w - n))) & m;
				b = (a >> (w - n)) & 1u;
			}
			fl_logic(e, r, sz);
			/* AF is architecturally undefined after a shift and
			 * real x86 SETS it; a protector reading the flags back
			 * notices the difference. See host_dshift16. */
			e->flags |= FL_AF;
			if (b)
				e->flags |= FL_CF;
			/* OF is defined only for a count of one, and is the
			 * sign changing - the same rule the single bit shifts
			 * above follow. */
			if (n == 1u && ((r ^ a) >> (w - 1u)) & 1u)
				e->flags |= FL_OF;
			if (!op_wr(e, ixp, &ixp->Operands[0], r))
				goto unsupported;
			break;
		}

		/* SAL is SHL under another name - the encoding is the same and
		 * bddisasm reports both. */
		case ND_INS_SAL:
		case ND_INS_SHL: case ND_INS_SHR: case ND_INS_SAR: {
			unsigned n, w = sz * 8u;
			uint64_t m = mask_of(sz);

			if (!op_rd(e, ixp, &ixp->Operands[0], &a) ||
			    !op_rd(e, ixp, &ixp->Operands[1], &b))
				goto unsupported;
			n = (unsigned)(b & (sz == 8 ? 63u : 31u));
			if (!n) break;                    /* no shift, no flags */
			a &= m;
			switch (ixp->Instruction) {
			case ND_INS_SAL:
			case ND_INS_SHL: r = n >= w ? 0 : (a << n) & m; break;
			case ND_INS_SHR: r = n >= w ? 0 : a >> n; break;
			default: /* SAR: sign-extend, then an arithmetic right shift
				  * capped at w-1 so it saturates to all sign bits. */
				r = (uint64_t)(((int64_t)sext(a, sz)) >>
					       (n >= w ? w - 1u : n)) & m;
				break;
			}
			fl_logic(e, r, sz);
			/* AF is architecturally undefined after a shift and real
			 * x86 SETS it - see host_dshift16 on why that matters. */
			e->flags |= FL_AF;
			/* CF is the last bit shifted out, and zero once the count
			 * has cleared the whole width. */
			if (ixp->Instruction == ND_INS_SHL ||
			    ixp->Instruction == ND_INS_SAL) {
				if (n <= w && (a >> (w - n)) & 1u)
					e->flags |= FL_CF;
			} else if (ixp->Instruction == ND_INS_SHR) {
				if (n <= w && (a >> (n - 1u)) & 1u)
					e->flags |= FL_CF;
			} else {   /* SAR: bit n-1, or the sign once past the width */
				unsigned cb = n <= w ? n - 1u : w - 1u;

				if ((a >> cb) & 1u)
					e->flags |= FL_CF;
			}
			if (!op_wr(e, ixp, &ixp->Operands[0], r))
				goto unsupported;
			break;
		}

		case ND_INS_ROL: case ND_INS_ROR: {
			unsigned n, rc, w = sz * 8u;
			uint64_t m = mask_of(sz);

			if (!op_rd(e, ixp, &ixp->Operands[0], &a) ||
			    !op_rd(e, ixp, &ixp->Operands[1], &b))
				goto unsupported;
			n = (unsigned)(b & (sz == 8 ? 63u : 31u));
			if (!n) break;                    /* masked count 0: no flags */
			a &= m;
			rc = n % w;                       /* a rotate is modulo width */
			if (ixp->Instruction == ND_INS_ROL)
				r = rc ? ((a << rc) | (a >> (w - rc))) & m : a;
			else
				r = rc ? ((a >> rc) | (a << (w - rc))) & m : a;
			/*
			 * ONLY CF and OF - SF/ZF/PF/AF are untouched, so fl_logic
			 * must not run here. CF takes the bit that landed in the
			 * position the rotate feeds it; OF is defined for a count
			 * of one alone and left as-is otherwise.
			 */
			e->flags &= ~(uint64_t)FL_CF;
			if (ixp->Instruction == ND_INS_ROL) {
				if (r & 1u)
					e->flags |= FL_CF;          /* LSB of result */
				if (n == 1) {
					e->flags &= ~(uint64_t)FL_OF;
					if (((r >> (w - 1u)) & 1u) ^ (r & 1u))
						e->flags |= FL_OF;
				}
			} else {
				if ((r >> (w - 1u)) & 1u)
					e->flags |= FL_CF;          /* MSB of result */
				if (n == 1) {
					e->flags &= ~(uint64_t)FL_OF;
					if (((r >> (w - 1u)) & 1u) ^
					    ((r >> (w - 2u)) & 1u))
						e->flags |= FL_OF;
				}
			}
			if (!op_wr(e, ixp, &ixp->Operands[0], r))
				goto unsupported;
			break;
		}

		case ND_INS_PUSH:
			if (!op_rd(e, ixp, &ixp->Operands[0], &a) ||
			    !push_w(e, a, ixp->Operands[0].Size))
				goto fault;
			break;

		case ND_INS_POP:
			if (!pop_w(e, &a, ixp->Operands[0].Size) ||
			    !op_wr(e, ixp, &ixp->Operands[0], a))
				goto fault;
			break;

		/*
		 * PUSHF / POPF - THE PROTECTORS USE THEM, AND FOR THE FLAGS.
		 *
		 * Not carried until now, and what it cost was measured rather
		 * than guessed: three Themida protected PEs ran 25.5, 22.3 and
		 * 44.2 MILLION instructions each - so the loader is reachable,
		 * it computes, and none of the API refusals that emu_unpack.h
		 * warns about had stopped it - and then every one of them
		 * stopped on "unsupported: PUSHFQ". One instruction between a
		 * run that got nowhere and a run that might.
		 *
		 * A protector reaches for these because they are how you save
		 * the flags across a sequence that clobbers them; that a
		 * hardened loader also reads them for its own reasons is a
		 * separate matter and does not change what the instruction is.
		 *
		 * WHAT IS PUSHED IS WHAT THIS BUILD MODELS, plus the two bits
		 * that are not conditions. FL_* already sit at their real
		 * EFLAGS positions, so the value needs no rearranging; bit 1 is
		 * hardwired to 1 on every x86 and bit 9 (IF) is set in every
		 * user mode process, and code that pushes the flags to look at
		 * them would find a zero there suspicious in a way the hardware
		 * never produces.
		 *
		 * WHAT POPF TAKES BACK is only the modelled bits. The rest of
		 * the word is discarded rather than stored, because storing
		 * bits nothing reads would let a later PUSHF hand back a value
		 * this interpreter never reasoned about - and IOPL, NT, RF and
		 * VM are not things a user mode stub can set anyway.
		 */
#define FL_MODELLED (FL_CF | FL_PF | FL_AF | FL_ZF | FL_SF | FL_DF | FL_OF)
#define FL_ALWAYS_1 (1u << 1)
#define FL_IF       (1u << 9)

		case ND_INS_PUSHF:
			if (!push(e, e->flags | FL_ALWAYS_1 | FL_IF))
				goto fault;
			break;

		case ND_INS_POPF:
			if (!pop(e, &a))
				goto fault;
			e->flags = (e->flags & ~(uint64_t)FL_MODELLED) |
				   (a & (uint64_t)FL_MODELLED);
			break;

		/*
		 * PUSHAD / POPAD - 32-BIT ONLY, AND THE STUBS USE THEM.
		 *
		 * amd64 dropped both, so the interpreter never needed them and
		 * did not carry them. A 32-bit encoder reaches for them the
		 * moment it wants to save state around a decode loop:
		 * single_static_bit stopped on its fifteenth instruction with
		 * "unsupported: PUSHAD".
		 *
		 * The order is the architecture's and not a choice: eax, ecx,
		 * edx, ebx, the ORIGINAL esp, ebp, esi, edi. POPAD restores
		 * them in reverse and DISCARDS the saved esp - the stack pointer
		 * is where the pops left it, not what was written.
		 */
		case ND_INS_PUSHA:
		case ND_INS_PUSHAD: {
			static const unsigned ord[8] = {
				KOF_EMU_RAX, KOF_EMU_RCX, KOF_EMU_RDX,
				KOF_EMU_RBX, KOF_EMU_RSP, KOF_EMU_RBP,
				KOF_EMU_RSI, KOF_EMU_RDI
			};
			uint64_t sp0 = e->gpr[KOF_EMU_RSP];
			unsigned k;

			for (k = 0; k < 8u; k++)
				if (!push(e, ord[k] == KOF_EMU_RSP
					     ? sp0 : e->gpr[ord[k]]))
					goto fault;
			break;
		}

		case ND_INS_POPA:
		case ND_INS_POPAD: {
			static const unsigned ord[8] = {
				KOF_EMU_RDI, KOF_EMU_RSI, KOF_EMU_RBP,
				KOF_EMU_RSP, KOF_EMU_RBX, KOF_EMU_RDX,
				KOF_EMU_RCX, KOF_EMU_RAX
			};
			unsigned k;

			for (k = 0; k < 8u; k++) {
				uint64_t t;

				if (!pop(e, &t))
					goto fault;
				if (ord[k] != KOF_EMU_RSP)
					e->gpr[ord[k]] = t;   /* esp: discarded */
			}
			break;
		}

		/*
		 * THE BCD ADJUSTS, and they are here because Alpha2 uses them
		 * as arithmetic rather than as decimal.
		 *
		 * An alphanumeric encoder can only emit bytes in a narrow range,
		 * so it builds its values out of whatever instructions fall in
		 * that range - and AAA, AAS and their siblings do. What the
		 * decoder needs from them is the exact register and flag result,
		 * which is why these are implemented rather than skipped: a stub
		 * computing an offset through AAA and getting the wrong AF back
		 * reads its payload from the wrong place.
		 *
		 * 32-bit only, like PUSHAD - amd64 removed them.
		 */
		case ND_INS_AAA:
		case ND_INS_AAS: {
			uint32_t ax = (uint32_t)(e->gpr[KOF_EMU_RAX] & 0xffffu);
			unsigned al = ax & 0xffu, ah = (ax >> 8) & 0xffu;
			int adj = (al & 0x0fu) > 9u || (e->flags & FL_AF);

			if (adj) {
				if (ixp->Instruction == ND_INS_AAA) {
					al = (al + 6u) & 0xffu;
					ah = (ah + 1u) & 0xffu;
				} else {
					al = (al - 6u) & 0xffu;
					ah = (ah - 1u) & 0xffu;
				}
				e->flags |= FL_AF | FL_CF;
			} else {
				e->flags &= ~(uint64_t)(FL_AF | FL_CF);
			}
			al &= 0x0fu;
			e->gpr[KOF_EMU_RAX] =
				(e->gpr[KOF_EMU_RAX] & ~0xffffull) |
				((uint64_t)ah << 8) | al;
			break;
		}

		case ND_INS_DAA:
		case ND_INS_DAS: {
			unsigned al = (unsigned)(e->gpr[KOF_EMU_RAX] & 0xffu);
			unsigned old = al;
			int oldcf = (e->flags & FL_CF) != 0;
			int sub = ixp->Instruction == ND_INS_DAS;

			e->flags &= ~(uint64_t)FL_CF;
			if ((al & 0x0fu) > 9u || (e->flags & FL_AF)) {
				al = sub ? (al - 6u) & 0xffu : (al + 6u) & 0xffu;
				if (sub && old < 6u)
					e->flags |= FL_CF;
				e->flags |= FL_AF;
			} else {
				e->flags &= ~(uint64_t)FL_AF;
			}
			if (old > 0x99u || oldcf) {
				al = sub ? (al - 0x60u) & 0xffu
					 : (al + 0x60u) & 0xffu;
				e->flags |= FL_CF;
			}
			e->gpr[KOF_EMU_RAX] =
				(e->gpr[KOF_EMU_RAX] & ~0xffull) | al;
			break;
		}

		case ND_INS_LEAVE:
			e->gpr[KOF_EMU_RSP] = e->gpr[KOF_EMU_RBP];
			if (!pop(e, &e->gpr[KOF_EMU_RBP]))
				goto fault;
			break;

		case ND_INS_CALLNR:
		case ND_INS_CALLNI:
			if (!op_rd(e, ixp, &ixp->Operands[0], &a) || !push(e, next))
				goto fault;
			e->rip = a; jumped = 1;
			break;

		case ND_INS_RETN:
			if (!pop(e, &a))
				goto fault;
			if (ixp->OperandsCount > 0 &&
			    ixp->Operands[0].Type == ND_OP_IMM)
				e->gpr[KOF_EMU_RSP] += ixp->Operands[0].Info.Immediate.Imm;
			e->rip = a; jumped = 1;
			break;

		case ND_INS_JMPNR:
		case ND_INS_JMPNI:
			if (!op_rd(e, ixp, &ixp->Operands[0], &a))
				goto unsupported;
			e->rip = a; jumped = 1;
			break;

		case ND_INS_Jcc:
			if (!op_rd(e, ixp, &ixp->Operands[0], &a))
				goto unsupported;
			if (cond_true(e, ixp->Condition)) { e->rip = a; jumped = 1; }
			break;

		case ND_INS_SETcc:
			if (!op_wr(e, ixp, &ixp->Operands[0],
				   cond_true(e, ixp->Condition) ? 1u : 0u))
				goto unsupported;
			break;

		case ND_INS_CMOVcc:
			if (!op_rd(e, ixp, &ixp->Operands[1], &b))
				goto unsupported;
			if (cond_true(e, ixp->Condition) &&
			    !op_wr(e, ixp, &ixp->Operands[0], b))
				goto unsupported;
			break;

		/* Sign of the accumulator into the whole of RDX/DX. */
		case ND_INS_CWD:
			reg_wr(e, KOF_EMU_RDX, 2, 0,
			       (int16_t)e->gpr[KOF_EMU_RAX] < 0 ? 0xffffu : 0u);
			break;
		case ND_INS_CDQ: case ND_INS_CQO:
			e->gpr[KOF_EMU_RDX] =
				(ixp->Instruction == ND_INS_CQO)
				? ((int64_t)e->gpr[KOF_EMU_RAX] < 0 ? ~(uint64_t)0 : 0)
				: (uint64_t)(uint32_t)((int32_t)e->gpr[KOF_EMU_RAX] >> 31);
			break;

		/* Widen the accumulator in place. */
		case ND_INS_CBW:
			reg_wr(e, KOF_EMU_RAX, 2, 0,
			       (uint64_t)(uint16_t)(int16_t)(int8_t)e->gpr[KOF_EMU_RAX]);
			break;
		case ND_INS_CWDE:
			e->gpr[KOF_EMU_RAX] =
				(uint64_t)(uint32_t)(int32_t)(int16_t)e->gpr[KOF_EMU_RAX];
			break;
		case ND_INS_CDQE:
			e->gpr[KOF_EMU_RAX] = (uint64_t)(int64_t)(int32_t)e->gpr[KOF_EMU_RAX];
			break;

		/*
		 * BRANCH ON THE COUNTER BEING ZERO, and it does NOT decrement.
		 *
		 * The one member of this family that reads RCX without
		 * touching it. Missing, a kkrunchy-packed binary stopped
		 * 4111 instructions in with "JECXZ" as the reason - the
		 * decompressor's inner loop is built on it - and all five
		 * samples here produced nothing at all.
		 *
		 * The operand size that matters is the ADDRESS size, not the
		 * data size: the same encoding reads CX, ECX or RCX depending
		 * on the address-size prefix and the mode, which is what
		 * bddisasm reports in AddrMode.
		 */
		case ND_INS_JrCXZ: {
			uint64_t cnt = e->gpr[KOF_EMU_RCX];

			if (ixp->AddrMode == ND_ADDR_32)
				cnt = (uint32_t)cnt;
			else if (ixp->AddrMode == ND_ADDR_16)
				cnt = (uint16_t)cnt;
			if (!cnt) {
				if (!op_rd(e, ixp, &ixp->Operands[0], &a))
					goto unsupported;
				next = a;
			}
			break;
		}

		/* The count-and-branch forms. RCX is the counter and is NOT a
		 * flag setter - only the branch decision reads ZF. */
		case ND_INS_LOOP: case ND_INS_LOOPZ: case ND_INS_LOOPNZ: {
			uint64_t cnt = --e->gpr[KOF_EMU_RCX];
			int take = cnt != 0;

			if (ixp->Instruction == ND_INS_LOOPZ)
				take = take && (e->flags & FL_ZF);
			else if (ixp->Instruction == ND_INS_LOOPNZ)
				take = take && !(e->flags & FL_ZF);
			if (take) {
				if (!op_rd(e, ixp, &ixp->Operands[0], &a))
					goto unsupported;
				next = a;
			}
			break;
		}

		case ND_INS_BSWAP:
			if (!op_rd(e, ixp, &ixp->Operands[0], &a))
				goto unsupported;
			r = 0;
			for (unsigned i = 0; i < sz; i++)
				r |= ((a >> (i * 8u)) & 0xffu) << ((sz - 1u - i) * 8u);
			if (!op_wr(e, ixp, &ixp->Operands[0], r))
				goto unsupported;
			break;

		/*
		 * Count only the operands the encoding spells out. The full
		 * count includes the implicit RFLAGS, so a two-operand
		 * "IMUL rdx, rdi" looked like the three-operand form and read
		 * the flags register as its multiplier.
		 */
		case ND_INS_IMUL:
			if (ixp->ExpOperandsCount >= 3) {
				if (!op_rd(e, ixp, &ixp->Operands[1], &a) ||
				    !op_rd(e, ixp, &ixp->Operands[2], &b) ||
				    !op_wr(e, ixp, &ixp->Operands[0], a * b))
					goto unsupported;
			} else if (ixp->ExpOperandsCount == 2) {
				if (!op_rd(e, ixp, &ixp->Operands[0], &a) ||
				    !op_rd(e, ixp, &ixp->Operands[1], &b) ||
				    !op_wr(e, ixp, &ixp->Operands[0], a * b))
					goto unsupported;
			} else {
				/* One operand: the widening form, into RDX:RAX. */
				uint64_t acc = reg_rd(e, KOF_EMU_RAX, sz, 0);
				int64_t  x, y;

				if (!op_rd(e, ixp, &ixp->Operands[0], &b))
					goto unsupported;
				x = (int64_t)sext(acc, sz);
				y = (int64_t)sext(b, sz);
				reg_wr(e, KOF_EMU_RAX, sz, 0, (uint64_t)(x * y));
				if (sz < 8)
					reg_wr(e, KOF_EMU_RDX, sz, 0,
					       (uint64_t)((x * y) >> (sz * 8u)));
				else
					reg_wr(e, KOF_EMU_RDX, 8, 0,
					       (uint64_t)((x < 0) != (y < 0) ? -1 : 0));
			}
			break;

		/*
		 * STRING OPERATIONS, ONE ITERATION AT A TIME.
		 *
		 * UPX's NRV decompressor is built out of these and a REP MOVS
		 * is how the payload actually lands, so this is not an optional
		 * corner. The repeat runs here rather than by re-entering the
		 * decoder, but every iteration still costs a unit of budget:
		 * a REP over a megabyte IS a megabyte of work and a budget that
		 * pretended otherwise would be a budget that does not bound
		 * anything.
		 */
		/* The flag instructions, which cost a line each and stop real
		 * samples when they are missing. */
		case ND_INS_STC: e->flags |= FL_CF;  break;
		case ND_INS_CLC: e->flags &= ~(uint64_t)FL_CF; break;
		case ND_INS_CMC: e->flags ^= FL_CF;  break;
		case ND_INS_SAHF:
			e->flags = (e->flags & ~(uint64_t)(FL_SF | FL_ZF | FL_AF |
							   FL_PF | FL_CF)) |
				   (reg_rd(e, KOF_EMU_RAX, 2, 0) >> 8 &
				    (FL_SF | FL_ZF | FL_AF | FL_PF | FL_CF));
			break;
		case ND_INS_LAHF:
			reg_wr(e, KOF_EMU_RAX, 1, 1,
			       (e->flags & (FL_SF | FL_ZF | FL_AF | FL_PF |
					    FL_CF)) | 2u);
			break;

		/*
		 * SALC - `AL = CF ? 0xFF : 0`, one byte, opcode D6, and not in
		 * any Intel manual. It exists because it is short and because a
		 * disassembler that does not know it stops there, which is
		 * exactly why a polymorphic generator emits it. Measured: a
		 * Sality body reaches one 186 million instructions in and the
		 * run ended on it.
		 */
		case ND_INS_SALC:
			reg_wr(e, KOF_EMU_RAX, 1, 0,
			       (e->flags & FL_CF) ? 0xffu : 0u);
			break;

		case ND_INS_LODS: case ND_INS_STOS:
		case ND_INS_MOVS: case ND_INS_SCAS: case ND_INS_CMPS: {
			/* WHAT THE GUEST IS MEASURING OR COMPARING, on request.
			 * A stub that resolves its own imports runs strlen
			 * over the name it wants before it looks for it, and
			 * RDI is pointing at that name here - the one place it
			 * is nameable. Printed once per distinct string. */
			static int str_on = -1;

			if (str_on < 0)
				str_on = getenv("KOF_STR_TRACE") ? 1 : 0;
			if (str_on) {
				char nm[64];
				uint64_t c = 0;
				unsigned q;

				for (q = 0; q + 1 < sizeof nm; q++) {
					if (!mem_rd(e, e->gpr[KOF_EMU_RDI] + q,
						    &c, 1u) || !c)
						break;
					if (c < 32u || c > 126u)
						break;
					nm[q] = (char)c;
				}
				nm[q] = 0;
				if (q >= 5u && !c)
					fprintf(stderr, "[str] %s\n", nm);
			}
			unsigned w = ixp->Operands[0].Size ? ixp->Operands[0].Size : 1u;
			int64_t step = (e->flags & FL_DF) ? -(int64_t)w : (int64_t)w;
			uint64_t iter = 1;

			if (ixp->IsRepeated) {
				iter = e->gpr[KOF_EMU_RCX];
				if (!iter) break;
				if (iter > e->max_insn - e->insn)
					iter = e->max_insn - e->insn;
			}
			while (iter--) {
				uint64_t v = 0;

				switch (ixp->Instruction) {
				case ND_INS_LODS:
					if (!mem_rd(e, e->gpr[KOF_EMU_RSI], &v, w))
						goto fault;
					reg_wr(e, KOF_EMU_RAX, w, 0, v);
					e->gpr[KOF_EMU_RSI] += (uint64_t)step;
					break;
				case ND_INS_STOS:
					v = reg_rd(e, KOF_EMU_RAX, w, 0);
					if (!mem_wr(e, e->gpr[KOF_EMU_RDI], &v, w))
						goto fault;
					e->gpr[KOF_EMU_RDI] += (uint64_t)step;
					break;
				case ND_INS_MOVS:
					if (!mem_rd(e, e->gpr[KOF_EMU_RSI], &v, w) ||
					    !mem_wr(e, e->gpr[KOF_EMU_RDI], &v, w))
						goto fault;
					e->gpr[KOF_EMU_RSI] += (uint64_t)step;
					e->gpr[KOF_EMU_RDI] += (uint64_t)step;
					break;
				case ND_INS_CMPS: {
					uint64_t rhs;

					if (!mem_rd(e, e->gpr[KOF_EMU_RSI], &a, w) ||
					    !mem_rd(e, e->gpr[KOF_EMU_RDI], &rhs, w))
						goto fault;
					fl_sub(e, a, rhs, 0, w);
					e->gpr[KOF_EMU_RSI] += (uint64_t)step;
					e->gpr[KOF_EMU_RDI] += (uint64_t)step;
					break;
				}
				default:
					if (!mem_rd(e, e->gpr[KOF_EMU_RDI], &v, w))
						goto fault;
					a = reg_rd(e, KOF_EMU_RAX, w, 0);
					fl_sub(e, a, v, 0, w);
					e->gpr[KOF_EMU_RDI] += (uint64_t)step;
					break;
				}
				if (ixp->IsRepeated) {
					e->gpr[KOF_EMU_RCX]--;
					e->insn++;
					/* REPZ/REPNZ on a compare stop on the flag
					 * as well as on the count; REP on a move
					 * only on the count. */
					if (ixp->Instruction == ND_INS_SCAS ||
					    ixp->Instruction == ND_INS_CMPS) {
						int z = (e->flags & FL_ZF) != 0;

						if (ixp->Rep == 0xF3 ? !z : z)
							break;
					}
				}
			}
			break;
		}

		case ND_INS_CLD: e->flags &= ~(uint64_t)FL_DF; break;
		case ND_INS_STD: e->flags |=  (uint64_t)FL_DF; break;

		/*
		 * CPUID, answered rather than refused.
		 *
		 * A stub asks in order to pick a code path, and the safest
		 * answer is a plain old CPU: no AVX, no fancy string support,
		 * so whatever it selects is the simple path this interpreter
		 * has the best chance of carrying. Refusing instead would stop
		 * the run at the first sample that merely wanted to know.
		 */
		case ND_INS_CPUID: {
			uint32_t leaf = (uint32_t)e->gpr[KOF_EMU_RAX];

			e->gpr[KOF_EMU_RAX] = e->gpr[KOF_EMU_RBX] =
			e->gpr[KOF_EMU_RCX] = e->gpr[KOF_EMU_RDX] = 0;
			if (leaf == 0) {
				e->gpr[KOF_EMU_RAX] = 1;          /* max leaf */
				e->gpr[KOF_EMU_RBX] = 0x756e6547;  /* "Genu" */
				e->gpr[KOF_EMU_RDX] = 0x49656e69;  /* "ineI" */
				e->gpr[KOF_EMU_RCX] = 0x6c65746e;  /* "ntel" */
			} else if (leaf == 1) {
				e->gpr[KOF_EMU_RAX] = 0x000306a9;  /* a plausible model */
				e->gpr[KOF_EMU_RDX] = 0x078bfbff;  /* fpu..sse2, no avx */
			}
			break;
		}

		/*
		 * `int 0x80` IS THE 32-BIT SYSCALL, and the only interrupt this
		 * runs.
		 *
		 * Every other vector is refused rather than ignored: an
		 * `int 3` is a debugger trap and an `int 0x2e` is Windows, and
		 * a stub reaching either is doing something this environment
		 * cannot answer for. Returning from them as though they had
		 * worked would let the run carry on into a state the guest
		 * never actually reached.
		 *
		 * Accepted in 64-bit mode too. Linux still honours int 0x80
		 * from a 64-bit process - with the i386 table - so a stub that
		 * uses it there is doing something real, and refusing it would
		 * be this emulator disagreeing with the kernel.
		 */
		case ND_INS_INT: {
			int s = 0;
			uint64_t ret;
			unsigned was = e->bits;

			if (ixp->Operands[0].Type != ND_OP_IMM ||
			    ixp->Operands[0].Info.Immediate.Imm != 0x80)
				goto unsupported;
			/* int 0x80 is the i386 convention whatever the mode. */
			e->bits = 32;
			ret = do_syscall(e, &s);
			e->bits = was;
			if (s) { e->stop = (enum kof_emu_stop)(s - 1); goto done; }
			e->gpr[KOF_EMU_RAX] = ret;
			break;
		}

		case ND_INS_SYSCALL: {
			int s = 0;
			uint64_t ret = do_syscall(e, &s);

			if (s) { e->stop = (enum kof_emu_stop)(s - 1); goto done; }
			e->gpr[KOF_EMU_RAX] = ret;
			break;
		}

		default:
			goto unsupported;
		}

		if (!jumped)
			e->rip = next;
		else {
			/*
			 * A jump into a page the run wrote LOOKS like the
			 * handoff, and often is not - see
			 * kof_emu_cfg.stop_on_written_jump for what UPX does to
			 * that idea. Off unless the caller asked.
			 */
			/*
			 * A WRITTEN PAGE AND OUTSIDE THE STUB. See
			 * kof_emu_set_stub_range: the first half alone fires on
			 * a stub unpacking into its own section, which is the
			 * commonest shape there is.
			 */
			struct page *p = e->stop_on_written_jump
					 ? page_find(e, e->rip) : NULL;

			/*
			 * NOR THE STACK. A handler that resumes through a
			 * thunk it built on the stack has written a page and
			 * jumped to it, and that is not a program starting -
			 * it is the same code carrying on. Measured on a
			 * PECompact2 sample, which does exactly this out of
			 * its own exception handler eighteen instructions in.
			 */
			if (p && p->written && e->stub_hi &&
			    e->rip >= e->stub_lo && e->rip < e->stub_hi)
				p = NULL;
			if (p && p->written && e->stack_hi &&
			    e->rip >= e->stack_lo && e->rip < e->stack_hi)
				p = NULL;

			if (p && p->written) {
				snprintf(e->detail, sizeof e->detail,
					 "written jump to %#llx",
					 (unsigned long long)e->rip);
				e->stop = KOF_EMU_STOP_HANDOFF;
				goto done;
			}

			/*
			 * ---- THE HANDOVER, BY THE SHAPE OF THE TRANSFER ----
			 *
			 * A stub ends by giving control to the program with
			 * the stack exactly as it found it. That last part is
			 * the whole discriminator: a stub CALLING something
			 * has pushed a return address, a stub HANDING OVER has
			 * not - it has undone every push it made. XVolkolak's
			 * XEmulUnpacker builds its per-packer OEP predicates
			 * on that one invariant, and its MPRESS, PECompact and
			 * Themida rules differ only in which tail instruction
			 * they accept. See THIRD-PARTY.md.
			 *
			 * WHAT IS REQUIRED OF THE TARGET: inside the image, and
			 * on a page this run WROTE. Together those say the
			 * destination is code the stub produced rather than
			 * code it came with, which is what an unpacker is
			 * looking for.
			 *
			 * WHAT IS REQUIRED OF THE TAIL: one of the four shapes
			 * a packer ends with. Without this the balanced-stack
			 * test alone fires on ordinary returns inside the stub.
			 */
			if (e->oep_watch && e->sp0_set &&
			    e->gpr[KOF_EMU_RSP] == e->sp0 &&
			    e->img_hi > e->img_lo &&
			    e->rip >= e->img_lo && e->rip < e->img_hi &&
			    !(e->stack_hi && e->rip >= e->stack_lo &&
			      e->rip < e->stack_hi)) {
				struct page *t = page_find(e, e->rip);
				int tail = 0;

				/* jmp rel32 / call rel32 */
				if (at_len == 5u &&
				    (at_b[0] == 0xe9u || at_b[0] == 0xe8u))
					tail = 1;
				/* ret, and ret imm16 */
				else if (at_len == 1u && at_b[0] == 0xc3u)
					tail = 1;
				else if (at_len == 3u && at_b[0] == 0xc2u)
					tail = 1;
				/* jmp reg / call reg */
				else if (at_len == 2u && at_b[0] == 0xffu &&
					 (at_b[1] == 0xe0u || at_b[1] == 0xd0u))
					tail = 1;

				/*
				 * AND THE DIRECTION, WHICH IS WHAT KEEPS THIS
				 * FROM FIRING INSIDE THE STUB.
				 *
				 * A loader jumping about within itself does
				 * every other part of this test: the stack is
				 * balanced after a `popfq; ret`, the target is
				 * in the image, and the page is written
				 * because the loader expanded into it.
				 * Measured on a Themida sample, that fired
				 * 25440 instructions in on a jump DOWN from
				 * one part of the loader to another.
				 *
				 * XEmulUnpacker's rules each carry a direction
				 * - Themida wants a jump UP, PECompact one
				 * DOWN and out of a region that is not the
				 * image. Both are the same statement: the
				 * transfer leaves where the stub was working.
				 * Without a module to say which packer this
				 * is, the union of the two is what can be
				 * required, and it is still enough to drop the
				 * intra-loader case above.
				 */
				if (tail && t && t->gwritten &&
				    (at < e->rip ||
				     at < e->img_lo || at >= e->img_hi)) {
					snprintf(e->detail, sizeof e->detail,
						 "handover to %#llx, stack "
						 "balanced", 
						 (unsigned long long)e->rip);
					e->stop = KOF_EMU_STOP_HANDOFF;
					goto done;
				}
			}
		}
		continue;

unsupported:
		/*
		 * MOST FAULTS ARRIVE HERE AND NOT AT `fault:`, which is why
		 * this test is in both places.
		 *
		 * An operand read that cannot reach its memory returns failure
		 * to the decode arm it was called from, and those arms say
		 * `goto unsupported` - the label then sorts the two apart by
		 * whether a fault was recorded. Hooking only `fault:` caught
		 * the minority: measured, three of four protected samples
		 * reported a read fault and none of them ever reached the
		 * dispatcher.
		 */
		if (e->fault_kind[0] && win_exc_begin(e))
			continue;
		fail(e, e->fault_kind[0] ? KOF_EMU_STOP_FAULT
					 : KOF_EMU_STOP_UNSUPPORTED, ixp);
		goto done;
fault:
		/*
		 * A WINDOWS GUEST MAY HAVE ASKED FOR THIS. See the exception
		 * dispatcher: a protector faults on purpose and expects to be
		 * handed the fault. Nothing changes for an ELF run, which has
		 * no win_k32_base and is refused at the first line of it.
		 */
		if (win_exc_begin(e))
			continue;
		fail(e, KOF_EMU_STOP_FAULT, NULL);
		goto done;
	}
done:
	/* The host prepares and harvests around the run; its stores are not the
	 * guest's - see `gwritten`. */
	e->running = 0;
	return e->stop;
}

/* ---- what came out --------------------------------------------------------- */

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y ? 1 : 0;
}

int kof_emu_next_written(struct kof_emu *e, uint32_t *it, uint64_t *va,
			 const uint8_t **bytes, uint64_t *len)
{
	uint32_t i;

	if (!e->sorted) {
		uint32_t n = 0;

		e->sorted = calloc(e->n_pages ? e->n_pages : 1u, sizeof *e->sorted);
		if (!e->sorted)
			return 0;
		for (i = 0; i <= e->tab_mask; i++)
			if (e->tab[i].va && e->tab[i].written)
				e->sorted[n++] = e->tab[i].va;
		qsort(e->sorted, n, sizeof *e->sorted, cmp_u64);
		e->n_sorted = n;
	}
	if (*it >= e->n_sorted)
		return 0;
	{
		/*
		 * One run rather than one page: a decompressed payload is
		 * megabytes of neighbours, and handing the scanner three
		 * hundred separate children of four kilobytes each would lose
		 * every marker that straddles a page.
		 */
		uint32_t s = *it, n = 1;
		struct page *p;
		uint8_t *buf;
		uint64_t k, trim;

		while (s + n < e->n_sorted &&
		       e->sorted[s + n] == e->sorted[s + n - 1u] + KOF_EMU_PAGE)
			n++;
		buf = malloc((size_t)n * KOF_EMU_PAGE);
		if (!buf)
			return 0;
		for (k = 0; k < n; k++) {
			p = page_find(e, e->sorted[s + k]);
			memcpy(buf + k * KOF_EMU_PAGE, p->data, KOF_EMU_PAGE);
		}
		/*
		 * AND THE RUN ENDS WHERE THE WRITING DID - see page.wr_hi.
		 * Only the LAST page of the run is trimmed: an interior page
		 * is followed by another written page, so its tail is between
		 * two things the stub made and cutting it would put a hole in
		 * the middle of a payload.
		 */
		p = page_find(e, e->sorted[s + n - 1u]);
		trim = (uint64_t)(n - 1u) * KOF_EMU_PAGE +
		       (p && p->wr_hi ? p->wr_hi : KOF_EMU_PAGE);
		/* Owned by the emulator, replaced on the next call. One live run
		 * at a time is all a caller needs and all this has to track. */
		free(e->run_buf);
		e->run_buf = buf;
		*va = e->sorted[s];
		*bytes = buf;
		*len = trim;
		*it = s + n;
		return 1;
	}
}
