/*
 * kofemu.h - an x86-64 interpreter, for getting a packer stub to unpack itself.
 *
 * WHAT THIS IS FOR, AND WHAT IT IS NOT
 *
 * It is a memory dumper with a budget. The goal is never a faithful CPU: it is
 * to run a stub far enough that it writes its payload somewhere, and then to
 * hand those bytes to the scanner. An emulation that got sixty percent of the
 * way still produces bytes a signature can name, and a signature naming a
 * family beats any amount of correctness nobody reads.
 *
 * That is the whole reason this is affordable. A behavioural emulator has to be
 * right about everything the sample touches, forever; this one has to be right
 * about the few hundred instructions between an entry point and a decompressed
 * buffer, and it may give up loudly at any point.
 *
 *
 * WHY IT IS SAFE
 *
 * Nothing is executed. Every instruction is decoded by bddisasm and applied to
 * registers and memory this module owns, so there is no privilege to escape
 * from - which is a stronger property than a virtual machine has, not a weaker
 * one. `rip` is an index into a page table kept here; a jump to a wild address
 * is a fault in this file rather than anything the host notices.
 *
 * The risk that IS real is the ordinary one: this is C parsing bytes an
 * attacker chose. It belongs under the sanitizers and the fuzzers like every
 * other parser in the tree, and the build puts it there.
 *
 *
 * WHY SYSCALLS AND NOT AN API TABLE
 *
 * On ELF the boundary worth stubbing is the syscall. bases/unp/ezuri.c records
 * that its stub "calls memfd_create and fork by their amd64 Linux syscall
 * numbers", and UPX's stub is the same shape. That surface is small - a stub
 * uses a handful - and the Linux syscall ABI does not move. The Windows API
 * surface that makes emulation an arms race is simply not present here.
 */

#ifndef KOFENG_KOFEMU_H
#define KOFENG_KOFEMU_H

#include <stdint.h>

struct kof_emu;

/* Page size of the emulated address space. Not the host's; this is a property
 * of what is being emulated and the ELF images it loads. */
#define KOF_EMU_PAGE      4096u

/* General purpose registers, in bddisasm's encoding order so a decoded operand
 * indexes this array directly rather than through a translation nobody would
 * keep in step. */
enum {
	KOF_EMU_RAX = 0, KOF_EMU_RCX, KOF_EMU_RDX, KOF_EMU_RBX,
	KOF_EMU_RSP,     KOF_EMU_RBP, KOF_EMU_RSI, KOF_EMU_RDI,
	KOF_EMU_R8,      KOF_EMU_R9,  KOF_EMU_R10, KOF_EMU_R11,
	KOF_EMU_R12,     KOF_EMU_R13, KOF_EMU_R14, KOF_EMU_R15,
	KOF_EMU_NGPR
};

/* Why the run ended. Only BUDGET and the two DONE reasons are ordinary; the
 * rest say the emulation went somewhere this build cannot follow, and are worth
 * counting because they are the map of what to implement next. */
enum kof_emu_stop {
	KOF_EMU_STOP_BUDGET = 0,   /* ran out of instructions - dump anyway */
	KOF_EMU_STOP_EXIT,         /* the stub called exit/exit_group */
	KOF_EMU_STOP_HANDOFF,      /* execve, or a jump into a page it wrote */
	KOF_EMU_STOP_FAULT,        /* read, wrote or fetched an unmapped address */
	KOF_EMU_STOP_UNSUPPORTED,  /* an instruction this build does not carry */
	KOF_EMU_STOP_DECODE,       /* bddisasm refused the bytes */
	/*
	 * Waiting for something that is never going to happen. There is one
	 * instruction pointer here, so a guest blocking on another thread is
	 * blocking on nobody: a Go runtime handed a scheduler slot to a thread
	 * clone had reported starting and then waited on it, which would
	 * otherwise consume the entire budget in a loop three instructions
	 * long. Whatever has been written is still worth dumping.
	 */
	KOF_EMU_STOP_STALLED,
	/*
	 * THE INSTRUCTION ABOUT TO RUN IS ONE A MODULE ASKED TO SEE.
	 *
	 * Not a failure and not the end: the run is PAUSED with the guest's
	 * state intact, the module reads what it wants, and kof_emu_run called
	 * again carries on from the same place. See kof_emu_watch_insn.
	 */
	KOF_EMU_STOP_INSN,
	/*
	 * THE DECRYPTION FINISHED. Not a failure and not a budget: the guest
	 * decrypted something and then stopped doing so, which is exactly the
	 * moment everything this interpreter exists for has already happened.
	 * See KOF_EMU_QUIET.
	 */
	KOF_EMU_STOP_QUIET
};

/*
 * WHAT ONE RUN MAY COST THE HOST, AND WHAT IT CANNOT COST AT ALL.
 *
 * The second half first, because it is the part that is structural rather than
 * tuned. This translation unit calls no system call, opens no file, starts no
 * process and no thread: the whole of what it uses from a C library is malloc,
 * free, the memory moves, qsort, snprintf and sqrt. A guest instruction is
 * decoded and SIMULATED - nothing is jitted, nothing is mapped executable,
 * nothing reaches the host's CPU as code. A guest syscall is answered from
 * synthesised state; the only file it can ever see is the buffer handed to
 * kof_emu_set_self, and every descriptor it opens refers to that. So a run
 * cannot read the machine it is running on, write to it, talk to a network, or
 * outlive the call.
 *
 * What remains is resource growth, and that is bounded rather than prevented,
 * because a guest is allowed to ask. Four things grow with guest BEHAVIOUR
 * rather than with the object's size:
 *
 *   instructions   cfg.max_insn - the CPU bound, counted per instruction and
 *                  per REP iteration, so a repeat over a megabyte costs a
 *                  megabyte of budget rather than one instruction's worth
 *   pages          cfg.max_pages - guest address space that has been touched
 *   live mappings  KOF_EMU_MAX_VMA - mmap costs the host a record even when it
 *                  commits no page, so a loop of reservations needs a ceiling
 *   snapshots      KOF_EMU_MAX_SNAP and a byte total - these are COPIES, the
 *                  one thing here that can cost the host more than the guest
 *                  was given
 *
 * Hitting any of them is answered the way a kernel answers it - a refusal the
 * guest can see and carry on from - and never by growing.
 *
 * The instruction budget is a CPU bound rather than a time bound on purpose: a
 * wall-clock limit would make the same scan answer differently on a loaded
 * machine, and an answer that depends on what else is running is not one a
 * corpus measurement can be repeated against.
 */
/*
 * How long a run may go without writing to a page it has not written before.
 *
 * The instruction budget bounds work; this bounds the absence of it. Ten times
 * the densest interval measured on real decompression, so productive runs never
 * see it and an unproductive one ends in a fraction of a second.
 */
#define KOF_EMU_IDLE      (4u << 20)

/*
 * HOW LONG A RUN CARRIES ON AFTER THE DECRYPTION STOPS - AND WHY IT IS OFF.
 *
 * An "active instruction" is a write landing within a few bytes of the last
 * one, away from the stack: the output of a decryption loop. See the note in
 * kofemu.c for why the signal is a memory trace and not an opcode, and for the
 * measurement that chose this trace over the published one.
 *
 * THE SIGNAL IS REAL AND THE THRESHOLD IS NOT. A run that has not produced one
 * for a while has finished decrypting - that much is sound, and the actives
 * land exactly on the decrypted body on every sample here. What does not exist
 * is one number that says "a while". Measured, the largest gap between two
 * consecutive actives WITHIN a decryption that had not finished:
 *
 *     Sality 160e27a3        395
 *     Sality 8ef99966        335
 *     Sality f073b23d        418
 *     Sality 57d128c3      7,992
 *     Themida telvm.exe    3,973
 *     PECompact 007 Spy  1,209,199
 *
 * Three and a half orders of magnitude. The 1500 below is the figure the
 * technique's original description uses, and it was chosen against DOS-era
 * viruses whose decryptors were tight; a modern packer interleaves long
 * phases that write nothing and is still decrypting. Setting the bar high
 * enough for PECompact saves nothing at all, and setting it anywhere lower
 * loses a detection - measured, 57d128c3 stops after 11,066 instructions
 * having decrypted nothing.
 *
 * So this stays behind KOF_EMU_QUIET, off, with the numbers written down. A
 * relative rule - a multiple of the gaps seen so far - is the obvious next
 * thing to try and has not been measured.
 */
#define KOF_EMU_QUIET     1500u

#define KOF_EMU_MAX_VMA   1024u
#define KOF_EMU_MAX_SNAP  64u

struct kof_emu_cfg {
	uint64_t max_insn;    /* instruction budget; 0 takes the default */
	uint64_t max_pages;   /* pages this emulation may own; 0 takes the default */
	/*
	 * STOP WHEN CONTROL ENTERS A PAGE THE RUN WROTE.
	 *
	 * Tempting as a universal "it has unpacked itself" signal, and wrong as
	 * one: a stub that relocates itself and carries on trips it long before
	 * the payload exists. Measured on UPX - it fires at 8 KB written where
	 * running to the budget yields the whole 38 KB image.
	 *
	 * So it is off by default. It is worth having for a stub that never
	 * exits and never execve's, where it is the only thing that would end
	 * the run early, but a caller asking for it should know it is a guess.
	 */
	int stop_on_written_jump;

	/*
	 * 32 or 64, and 0 means 64 - so a caller written before this existed
	 * still asks for what it used to get.
	 *
	 * WHAT IT CHANGES, and it is less than it looks: how bddisasm is asked
	 * to decode, how wide a push and a pop are, and which syscall
	 * convention `int 0x80` and `syscall` name. The instruction handlers
	 * are already width-agnostic because they work from the operand sizes
	 * bddisasm reports rather than from a machine word, and the loader
	 * reads the parser's normalised segment list, which is the same shape
	 * for an ELF32 and an ELF64.
	 */
	unsigned bits;
};

/* Page protection, as PT_LOAD's p_flags spells it. */
#define KOF_EMU_X   1u
#define KOF_EMU_W   2u
#define KOF_EMU_R   4u

struct kof_emu *kof_emu_new(const struct kof_emu_cfg *cfg);
void            kof_emu_free(struct kof_emu *e);

/*
 * Map `n` bytes of `src` at `va`, in a region `memsz` long - the tail past `n`
 * reads as zero, which is what a PT_LOAD with memsz > filesz means. `src` may
 * be NULL for a region that is all zero, which is how a stack is made.
 */
int kof_emu_map(struct kof_emu *e, uint64_t va, const uint8_t *src, uint64_t n,
		uint64_t memsz, unsigned prot);

/*
 * THE FILE BEING EMULATED, AS THE STUB WILL ASK FOR IT.
 *
 * Not a convenience. UPX's ELF stub does readlink("/proc/self/exe") and opens
 * the result, then reads its compressed data back off disk rather than
 * carrying it in memory - measured, it is why a run without this ends with the
 * stub closing a file descriptor of -ENOSYS. So an emulated process has to be
 * able to read itself, and this is the bytes it reads.
 *
 * Borrowed, not copied: the caller keeps them alive for the emulation.
 */
void     kof_emu_set_self(struct kof_emu *e, const uint8_t *bytes, uint64_t n);

/*
 * The FS or GS base, for a guest whose thread block the host builds.
 *
 * A Linux guest sets its own with arch_prctl and this is not needed. A WINDOWS
 * guest never does: the base is installed by the loader before a single
 * instruction of the image runs, so an interpreter that starts at the entry
 * point has to supply what the loader would have. Measured without it - four
 * Themida protected PEs, each of which ran between 22 and 48 million
 * instructions and then faulted reading gs:[0x30], which is the TEB's pointer
 * to itself.
 *
 * `seg` is 4 for FS and 5 for GS, which is bddisasm's numbering and the only
 * numbering this interpreter uses for segments anywhere.
 */
void     kof_emu_set_seg_base(struct kof_emu *e, unsigned seg, uint64_t base);

/*
 * ---- THE WINDOWS ENVIRONMENT ----------------------------------------------
 *
 * A Windows guest has no syscall it may use: it asks kernel32, and to ask it
 * must first find it. kofemu.c carries the answers; emu_unpack.c builds the
 * kernel32 to find. The two have to agree on the name, the trap number and -
 * on i386, where the callee pops - the argument count of every function, so
 * the table lives in kofemu.c and is read through these.
 *
 * KOF_EMU_WIN_STUB is how far apart the stubs are. Eight bytes is what one
 * needs (load the trap number, trap, return) and sixteen leaves the next one
 * aligned, which matters only in that a disassembly of the page is readable.
 */
#define KOF_EMU_WIN_STUB 16u
/* Where the stubs sit inside every module image. One number, because the
 * images are all built the same way and a resolver never sees it. */
#define KOF_EMU_WIN_STUB_RVA 0x1000u

/* The libraries this environment can hand out a base for. kernel32 is first
 * because it is the one a stub always asks for and the one a report names. */
#define KOF_EMU_WIN_MOD_K32   0u
#define KOF_EMU_WIN_MOD_NTDLL 1u
/* The rest of win_mod[], in its order. Only the first two had names, so an
 * export belonging to any other module could not be written down. */
#define KOF_EMU_WIN_MOD_USER32   2u
#define KOF_EMU_WIN_MOD_ADVAPI32 3u
#define KOF_EMU_WIN_MOD_SHELL32  4u
#define KOF_EMU_WIN_MOD_SHLWAPI  5u
#define KOF_EMU_WIN_MOD_MSVCRT   6u
#define KOF_EMU_WIN_MOD_OLE32    7u
/*
 * AND KERNELBASE, WHICH IS NOT AN ALIAS FOR KERNEL32.
 *
 * A modern kernel32 forwards most of itself to kernelbase, so answering
 * GetModuleHandle("kernelbase.dll") with kernel32's base resolves exports
 * correctly and was what this did. It is wrong for the other thing a guest
 * does with that handle: a protector PATCHES kernelbase - measured, a Themida
 * loader takes the handle and VirtualAllocs four pages inside it - and with
 * one image behind both names those writes land on kernel32's export
 * directory. Its own image costs a mapping and keeps the two apart.
 */
#define KOF_EMU_WIN_MOD_KBASE    8u
#define KOF_EMU_WIN_MOD_COUNT 9u

/*
 * How much address space one synthetic library occupies. The builder in
 * emu_unpack.c writes this as each module's SizeOfImage, and the interpreter
 * needs the same number to answer "is this address inside a library" - which
 * VirtualAlloc must know, because Windows refuses an explicit allocation
 * there and a protector asks in order to find out whether it is being
 * emulated.
 */
#define KOF_EMU_WIN_MOD_SPAN (256u * KOF_EMU_PAGE)

unsigned    kof_emu_win_api_count(void);
const char *kof_emu_win_api_name(unsigned i);
unsigned    kof_emu_win_api_argc(unsigned i);
unsigned    kof_emu_win_api_mod(unsigned i);
unsigned    kof_emu_win_api_slot(unsigned i);
uint32_t    kof_emu_win_api_trap(unsigned i);

unsigned    kof_emu_win_mod_count(void);
const char *kof_emu_win_mod_name(unsigned i);
uint64_t    kof_emu_win_mod_base(unsigned i, unsigned bits);
void        kof_emu_win_set_module(struct kof_emu *e, unsigned i,
				   uint64_t base);
/* Where the process heap structure is. GetProcessHeap hands this back, and a
 * guest reads its Flags through it - so it is an address and not a token. */
void        kof_emu_win_set_heap(struct kof_emu *e, uint64_t heap);

/* Count reads that land inside a library image, so "never asked" can be told
 * from "asked and was not answered". Off by default - see mem_rd. */
void        kof_emu_count_mod_reads(struct kof_emu *e, int on);
uint64_t    kof_emu_mod_reads(const struct kof_emu *e, unsigned i);
/*
 * ---- INSTRUCTION TRACE ----------------------------------------------------
 *
 * The last N instructions, each with the registers AS THEY WERE BEFORE IT RAN.
 *
 * WHY THE REGISTERS AND NOT JUST THE ADDRESSES. kof_emu_first_hop and the rip
 * ring above answer "where did it go"; they cannot answer "where did that
 * address come from", and that is the question a wrong address always raises.
 * Measured on an MPRESS sample: the stub read a library at base+0x2296c
 * through `mov eax, [rsi]`, and knowing the instruction said nothing at all -
 * the work was finding what had put that value in RSI, which is upstream of
 * every address in the rip ring.
 *
 * OFF BY DEFAULT AND NOT CHEAP. Every instruction is disassembled to text and
 * sixteen registers are copied, which is far more work than interpreting most
 * of them. This is a diagnostic to turn on for one file, never something a
 * scan runs with.
 *
 * n is rounded down to KOF_EMU_ITRACE_MAX and 0 turns it off, freeing the
 * ring. Entries are read oldest first: k from 0 to kof_emu_itrace_count.
 *
 * THE RING KEEPS THE LAST N, WHICH IS USUALLY THE WRONG N. A run that goes
 * wrong at instruction 60000 and then wanders for another 250000 leaves
 * nothing of the mistake in a ring of any affordable size. kof_emu_itrace_at
 * names the address to stop recording at, so the ring holds the N
 * instructions BEFORE it - which is where the value that address was built
 * from came from. 0 records to the end.
 */
#define KOF_EMU_ITRACE_MAX 262144u

int         kof_emu_itrace(struct kof_emu *e, unsigned n);
void        kof_emu_itrace_at(struct kof_emu *e, uint64_t rip);
/* Or freeze at an instruction NUMBER, which an address cannot express: an
 * address inside a dispatch loop is reached thousands of times and the first
 * hit is never the interesting one. 0 for never. */
void        kof_emu_itrace_until(struct kof_emu *e, uint64_t insn);
void        kof_emu_itrace_on_null(struct kof_emu *e, int on);
unsigned    kof_emu_itrace_count(const struct kof_emu *e);
int         kof_emu_itrace_get(const struct kof_emu *e, unsigned k,
			       uint64_t *rip, const char **text,
			       const uint64_t **gpr);

void        kof_emu_first_hop(const struct kof_emu *e, uint64_t *insn,
			      uint64_t *rip);
/* And the last hop, plus how many there were: where execution had got to when
 * the run ended, which is the address a dump writes as its entry point. */
void        kof_emu_last_hop(const struct kof_emu *e, uint64_t *rip,
			     uint32_t *count);

/*
 * Tell the interpreter where the three Windows regions are. Until this is
 * called every entry point in that environment answers zero, so an ELF run
 * cannot reach any of it.
 */
void kof_emu_win_setup(struct kof_emu *e, uint64_t image_base);

/* The address a named export resolves to, for filling an import thunk. Zero
 * for a name this environment does not carry, which is a thunk to leave as the
 * file wrote it - see fill_iat_pe in emu_unpack.c for why that is better than
 * a stub that shrugs. */
uint64_t kof_emu_win_addr_of(struct kof_emu *e, const char *name);

void     kof_emu_set_rip(struct kof_emu *e, uint64_t rip);
void     kof_emu_set_reg(struct kof_emu *e, unsigned gpr, uint64_t v);
uint64_t kof_emu_get_reg(const struct kof_emu *e, unsigned gpr);
/*
 * Where the machine is. A module that PAUSED a run - see kof_emu_watch_insn -
 * is standing at an instruction it asked to stop at, and cannot check what
 * surrounds it without knowing where it is.
 */
uint64_t kof_emu_get_rip(const struct kof_emu *e);
uint64_t kof_emu_rip(const struct kof_emu *e);

enum kof_emu_stop kof_emu_run(struct kof_emu *e);

/*
 * ---- RUNNING ON, WHEN THE RUN IS STILL PRODUCING -------------------------
 *
 * A budget is a guess about how much work an object needs, and the guess is
 * wrong in both directions. Too small on a real one: measured on a PECompact2
 * sample, the run reached the ceiling after 168 million instructions having
 * decompressed 6.5 of the 8.6 megabytes its own header declares - it was
 * stopped two thirds of the way through something that was working. Too large
 * on a crafted one, where the whole ceiling buys nothing.
 *
 * So the ceiling is raised only for a run that has EARNED it, and the evidence
 * is the one the interpreter already keeps: kof_emu_last_write says how far
 * back the last page it had never written before was. A run still touching
 * fresh memory is still unpacking; one that has not for millions of
 * instructions is spinning, which is what KOF_EMU_STOP_STALLED already says
 * about a shorter version of the same thing.
 *
 * THE CALLER OWNS THE POLICY. This pair only reports and permits: how many
 * instructions have run, when memory was last first-written, and a new
 * ceiling. What a total limit should be, and how many times to grant one, is a
 * decision about a scan rather than about an interpreter - see emu_unpack.c.
 * Memory is NOT extended with it: max_pages and the snapshot budget are
 * unchanged, so a longer run cannot hold more than a short one.
 */
uint64_t kof_emu_last_write(const struct kof_emu *e);
void     kof_emu_set_max_insn(struct kof_emu *e, uint64_t n);

/*
 * THE TWO BOUNDS THAT ARE NOT AN INSTRUCTION COUNT.
 *
 * kof_emu_set_idle replaces KOF_EMU_IDLE for this run: how many instructions
 * may pass with no page touched for the first time before the run is called
 * finished. The default is the right answer for a scan; a diagnostic that
 * wants to see how far a guest WOULD get raises it, and takes on the risk the
 * default exists to avoid.
 *
 * kof_emu_set_deadline is a WALL CLOCK bound and is the only one that holds
 * when the others are lifted. An instruction budget bounds work, not time, and
 * the two stop being the same number as soon as the budget is large: a guest
 * that would run for an hour is not made safe by permitting it. 0 disables it.
 *
 * The clock is read once every 64K instructions, so it costs one masked
 * compare per instruction and is accurate to a few milliseconds.
 */
/* How many times the run called an import this environment does not export -
 * see the null page check in the loop. A high number is a list to extend. */
unsigned kof_emu_null_calls(const struct kof_emu *e);
/* And how many exceptions it raised that nothing caught. */
unsigned kof_emu_unhandled(const struct kof_emu *e);
/* And how many fields it read off a null pointer. */
unsigned kof_emu_null_reads(const struct kof_emu *e);
uint64_t kof_emu_idle_max(const struct kof_emu *e);
void     kof_emu_set_idle(struct kof_emu *e, uint64_t n);
void     kof_emu_set_deadline(struct kof_emu *e, uint64_t ms);

/*
 * Copy every run of written memory into the snapshot set, now.
 *
 * FOR THE MOMENT BEFORE A RUN IS ALLOWED TO CARRY ON. A snapshot survives
 * whatever the run does next; written memory is only harvested for some
 * endings, so work that was finished and then followed by a fault is thrown
 * away. Measured: a PECompact2 sample decompressed 6.5 MB, was granted more
 * budget, and faulted in the extra slice - and the 6.5 MB went with it.
 *
 * Taking a copy at each extension makes the grant safe: the state that earned
 * it is kept before the risk is taken. Bounded by the same snapshot budget as
 * every other snapshot, so this cannot grow memory without limit.
 */
void     kof_emu_snap_written(struct kof_emu *e);

/* How many instructions were retired, and where it stopped. For deciding
 * whether a dump is worth taking and for reporting what a build cannot do. */
uint64_t    kof_emu_insn_count(const struct kof_emu *e);

/* Faults offered to a guest exception handler, faults a handler took, and how
 * many vectored handlers the guest registered. See the exception dispatcher in
 * kofemu.c for why the first two are counted separately. */
void kof_emu_exc_counts(const struct kof_emu *e, uint32_t *raised,
			uint32_t *taken, uint32_t *veh);

/* Where the exception records were built, so a harvest can leave them alone -
 * the same reason kof_emu_unp_report carries the stack. Zero when no exception
 * was ever raised, in which case nothing was built. */
uint64_t kof_emu_exc_scratch(const struct kof_emu *e, uint64_t *len);
const char *kof_emu_stop_name(enum kof_emu_stop s);
/* The mnemonic that ended an UNSUPPORTED run, or "" - this is the list that
 * says what to implement next, so it is kept rather than merely counted. */
const char *kof_emu_stop_detail(const struct kof_emu *e);

/*
 * THE LAST FEW ADDRESSES EXECUTED, NEWEST LAST.
 *
 * A run that ends at `rip 0` says nothing on its own; the twenty instructions
 * before it say which call returned zero. Kept always rather than behind a
 * build flag because the cost is a ring of sixteen words and the alternative is
 * rebuilding to ask a question that only reproduces sometimes.
 *
 * Returns how many were written into `out`.
 */
#define KOF_EMU_TRACE   256u
unsigned kof_emu_trace(const struct kof_emu *e, uint64_t *out, unsigned n);

/*
 * Read emulated memory. Returns 0 if any byte of the range is unmapped, and
 * touches nothing then - a partial read is the failure mode this whole module
 * is arranged to make impossible, so it is not offered here either.
 */
int kof_emu_read(struct kof_emu *e, uint64_t va, void *dst, unsigned n);
int kof_emu_write(struct kof_emu *e, uint64_t va, const void *src, unsigned n);

/*
 * ---- WHERE THE ORIGINAL PROGRAM WILL BE, AND STOPPING WHEN IT RUNS --------
 *
 * A packer that hollows an image leaves its original sections with a size and
 * no bytes, fills them at run time and jumps in. The moment of that jump is
 * the one worth stopping at: everything before it is the loader and everything
 * after it is the program, and the memory at that instant is the unpacked
 * image.
 *
 * THIS IS NOT stop_on_written_jump, and the difference is why that one is off.
 * A jump into any page the run wrote "LOOKS like the handoff, and often is
 * not" - UPX writes and jumps within its own stub constantly. A range declared
 * here is narrower by construction: it is a region the FILE said exists and
 * did not supply, so nothing but the run could have put code there.
 *
 * THE TECHNIQUE IS NOT MINE - see THIRD-PARTY.md, under "Read, not taken",
 * which is where this project records what it learned from whom. Kept there
 * rather than here so that a reader looking for what kofeng owes anyone finds
 * all of it in one file instead of by grepping the source.
 *
 * WHAT ENDS THE RUN IS ENTERING A RANGE, NOT BEING IN ONE. A run that starts
 * inside a watched range, or is still executing through it, has handed nothing
 * over; only a fetch that crosses IN from outside has. For a range the loader
 * never runs in - which is every case this was first written for - the two
 * readings are the same, because every arrival crosses in. They part company
 * on a packer that shares a section with the program it unpacks: PECompact
 * decompresses into the section its own entry point is in, so "being in one"
 * ended the run at instruction 0.
 *
 * Ranges are half open. At most KOF_EMU_EXEC_WATCH of them; more are dropped,
 * since a file declaring dozens of hollow sections is describing something
 * other than a packed program.
 */
#define KOF_EMU_EXEC_WATCH 16u

void kof_emu_watch_exec(struct kof_emu *e, uint64_t lo, uint64_t hi);

/*
 * ---- STOPPING ON WHAT IS ABOUT TO RUN, RATHER THAN ON WHERE ----------------
 *
 * kof_emu_watch_exec names an ADDRESS, and that is the wrong question for
 * three families this engine meets:
 *
 *   - PECompact copies its loader to 0x20000000 and finishes there, so the
 *     bytes that hand over are never executed at the address they occupy in
 *     the file. The public OllyDbg scripts search them IN MEMORY.
 *   - Petite ends the same way, at `9D 5F F3 AA 61 66 9D 83 C4 08`.
 *   - Sality is polymorphic: the whole first stage differs per sample and the
 *     only fixed thing about it is that it ends in a one-byte `C3`.
 *
 * So a module names BYTES. The run stops when the instruction about to execute
 * begins with them, and that is a pause: registers and memory are as the guest
 * left them, kof_emu_reg and kof_emu_read answer about that moment, and calling
 * kof_emu_run again continues from it.
 *
 * WHY A PAUSE AND NOT A CALLBACK. A callback would put module code inside the
 * loop that executes hostile bytes, and the one architectural rule here is that
 * the interpreter has no path out to a module - it gathers, and the module
 * decides afterwards. A pause keeps that: the module is the caller throughout,
 * and what it gets is a machine that has stopped.
 *
 * This is how TinyAntivirus finds Sality - hook every instruction, wait for a
 * one-byte C3, read [ESP] and check what is there - expressed without a hook.
 * See THIRD-PARTY.md.
 *
 * `n` is 1 to KOF_EMU_INSN_WATCH_LEN bytes. Up to KOF_EMU_INSN_WATCH patterns.
 */
#define KOF_EMU_INSN_WATCH     8u
#define KOF_EMU_INSN_WATCH_LEN 8u

void kof_emu_watch_insn(struct kof_emu *e, const uint8_t *bytes, unsigned n);

/*
 * AND WHETHER THE WHOLE INSTRUCTION IS THAT LONG, which is what tells `C3`
 * from `C2 imm16` and from a longer instruction that merely starts with those
 * bytes. 0 means "do not care".
 */
void kof_emu_watch_insn_len(struct kof_emu *e, unsigned len);

/*
 * AND WHERE THE CIPHERTEXT IS.
 *
 * A protector decrypts the program's sections in place, so the first write
 * into one of them says the plaintext is arriving - which is a statement about
 * the DATA rather than about where execution goes, and is the only signal
 * available when the loader never hands over in any recognisable way.
 * themida-dumper polls the same sections from outside the process for the same
 * reason; see THIRD-PARTY.md.
 */
void kof_emu_watch_write(struct kof_emu *e, uint64_t lo, uint64_t hi);
int  kof_emu_write_seen(const struct kof_emu *e);

/*
 * WHERE THE STUB ITSELF LIVES, so that a jump into a page it wrote is only a
 * handover when it LEAVES.
 *
 * stop_on_written_jump on its own is the signal kofemu.h warns about: a stub
 * that decompresses into its own section and jumps there has written and
 * executed without handing anything over. Measured with it alone, a PECompact2
 * sample stopped after eighteen instructions and a Themida sample lost a child
 * it had been producing.
 *
 * Adding "and the target is outside this range" is the second half of the
 * condition, and the pair is what Unpacker (github.com/anpa1200/Unpacker, MIT)
 * documents Unipacker as using - section hopping OR write-and-execute. See
 * THIRD-PARTY.md. Given as the entry point's section, which is the stub's own
 * by definition.
 */
void kof_emu_set_stub_range(struct kof_emu *e, uint64_t lo, uint64_t hi);
/* And the stack, for the same test and the same reason. */
void kof_emu_set_stack_range(struct kof_emu *e, uint64_t lo, uint64_t hi);
/* And where the image is - see the dump at the handover in the run loop. */
void kof_emu_set_image_range(struct kof_emu *e, uint64_t lo, uint64_t hi);

/*
 * THE HANDOVER, BY THE SHAPE OF THE TRANSFER RATHER THAN BY ITS ADDRESS.
 *
 * A stub ends by giving control to the program with the stack exactly as it
 * found it - every push undone. A stub CALLING something has not. That one
 * invariant, plus a target inside the image on a page this run wrote, plus a
 * tail instruction of the shape a packer ends with, is what XVolkolak's
 * XEmulUnpacker builds every one of its per-packer OEP rules on; see
 * THIRD-PARTY.md. It needs no ranges from a module and no guess about where
 * the program will be.
 */
void kof_emu_set_oep_watch(struct kof_emu *e, int on);

/*
 * ---- SECTION HOPPING ------------------------------------------------------
 *
 * A region execution has not been in before is a stage that has just been
 * built: the run starts in the stub's section and everything else it reaches
 * was written while it ran. Entering one for the first time is worth a
 * SNAPSHOT.
 *
 * SNAPSHOT AND CARRY ON, NOT STOP. A packed sample can have several stages and
 * stopping at the first gets one of them; taking a copy and letting the run
 * continue gets all of them, and costs a memory copy. The region is added to
 * the seen set as it is taken, so a loop inside it copies nothing more.
 *
 * NOT THE SAME AS stop_on_written_jump, which stays off. That fires on a stub
 * decompressing into its own section - measured, a PECompact2 sample stopped
 * eighteen instructions in and a Themida sample lost a stage. Unipacker
 * (github.com/unipacker/unipacker, GPL-2) keeps it off by default too and
 * makes section hopping the ordinary mechanism; its source was read to
 * understand that and none of it is reproduced here. See THIRD-PARTY.md.
 */
void kof_emu_hop_add(struct kof_emu *e, uint64_t lo, uint64_t hi, int seen);

/*
 * WATCH ONE ADDRESS, so "nothing ever wrote it" can be told apart from "the
 * write went somewhere else".
 *
 * A stub that jumps through a slot holding zero has either not written the slot
 * or written a different one, and reading the code cannot settle which. Records
 * the rip and value of every write that touches the byte at `va`.
 */
#define KOF_EMU_WATCH_MAX 16u
void     kof_emu_watch(struct kof_emu *e, uint64_t va);
unsigned kof_emu_watch_hits(const struct kof_emu *e, uint64_t *rip,
			    uint64_t *val, unsigned n);

/*
 * THE SYSCALLS THIS BUILD REFUSED, newest last.
 *
 * A stub that asks for something unimplemented gets -ENOSYS and carries on,
 * which is usually right and is occasionally the reason it later computes
 * nonsense - UPX stores the answer as a file descriptor and closes it. So the
 * numbers are kept: they are the list of what to implement next, and without
 * them a wrong result looks like an emulation bug rather than a missing stub.
 */
#define KOF_EMU_UNKSYS  8u
unsigned kof_emu_unknown_syscalls(const struct kof_emu *e, uint32_t *out,
				  unsigned n);

/*
 * EVERY SYSCALL THE STUB MADE, newest last, capped at the last KOF_EMU_SYSLOG.
 *
 * kof_emu_unknown_syscalls says what was refused; this says what was asked and
 * what it was told, which is a different question. A stub that gets a plausible
 * answer to the wrong question fails silently much later - a read served short,
 * an fstat size the decompressor then trusts - and there is no way to see that
 * from the register dump at the end.
 */
#define KOF_EMU_SYSLOG 64u
struct kof_emu_syscall {
	uint64_t nr, arg[6], ret;
};
unsigned kof_emu_syscall_log(const struct kof_emu *e,
			     struct kof_emu_syscall *out, unsigned n);

/*
 * WHAT THE GUEST PRINTED, from the beginning and no more than KOF_EMU_SAY.
 *
 * A runtime that refuses to start says why on its standard error, and that
 * sentence is worth more than any register dump: a Go-built packer printed a
 * traceback naming the function it died in, which is how the missing pieces
 * were found. The FIRST bytes are kept, not the last - a panic explains itself
 * on its opening lines and then prints a stack that pushes them out of a ring.
 * Returns the number of bytes placed in `out`; nothing is NUL-terminated for
 * the caller.
 */
#define KOF_EMU_SAY 4096u

/*
 * WHAT THE STUB DECOMPRESSED, CAUGHT WHILE IT STILL EXISTS.
 *
 * A packer that means to run what it unpacked has to make those bytes
 * executable, and it does that in one place - an mprotect granting PROT_EXEC
 * over memory the run itself wrote. That instant is the payload's complete
 * form, and it is the only reliable one: reading the same addresses at the end
 * of the run can find anything at all there. Measured on a UPX-packed
 * PyInstaller binary, the unpacked bootloader ran, opened a file and mapped a
 * second image over its own text, so the final memory held the packed header
 * again - the payload was gone from the address it had just been built at.
 *
 * Walk with *it = 0 until it returns 0. Snapshots are owned by the emulator.
 * A packer that maps its payload PROT_EXEC from the start never mprotects, and
 * leaves nothing here; kof_emu_next_written still has those pages.
 */
int kof_emu_next_snapshot(struct kof_emu *e, uint32_t *it, uint64_t *va,
			  const uint8_t **bytes, uint64_t *len);

/*
 * WHAT THE STUB WROTE, WHICH IS THE ENTIRE POINT.
 *
 * Walks the pages that were written to during the run, coalescing neighbours so
 * a caller gets runs rather than a page at a time. Start with *it = 0 and call
 * until it returns 0. The bytes stay owned by the emulator and are valid until
 * it is freed.
 */
int kof_emu_next_written(struct kof_emu *e, uint32_t *it, uint64_t *va,
			 const uint8_t **bytes, uint64_t *len);

#endif /* KOFENG_KOFEMU_H */
