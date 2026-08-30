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
	KOF_EMU_STOP_STALLED
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

void     kof_emu_set_rip(struct kof_emu *e, uint64_t rip);
void     kof_emu_set_reg(struct kof_emu *e, unsigned gpr, uint64_t v);
uint64_t kof_emu_get_reg(const struct kof_emu *e, unsigned gpr);
uint64_t kof_emu_rip(const struct kof_emu *e);

enum kof_emu_stop kof_emu_run(struct kof_emu *e);

/* How many instructions were retired, and where it stopped. For deciding
 * whether a dump is worth taking and for reporting what a build cannot do. */
uint64_t    kof_emu_insn_count(const struct kof_emu *e);
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
unsigned kof_emu_said(const struct kof_emu *e, char *out, unsigned n);

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
