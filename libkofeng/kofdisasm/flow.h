/*
 * flow.h - what a run of code will DO, read out of it without running it.
 *
 * THE QUESTION THIS ANSWERS.
 *
 * A stager is four things in a row: get a mapping that can be executed, pull
 * bytes down a socket into it, jump into it, and sleep between attempts. None
 * of those is a byte pattern - they are syscalls - and every byte rule written
 * for one of them is really a rule about ONE ENCODING of the syscall number.
 *
 * bases/signatures/meterp_00.c is exactly that and is worth reading beside
 * this file:
 *
 *     6a 2a 58        push 0x2a ; pop rax      rax = 42 = connect
 *     0f 05           syscall
 *     [8-15]                                   <- the gap, in BYTES
 *     6a 23 58        push 0x23 ; pop rax      rax = 35 = nanosleep
 *
 * `mov eax, 42` is the same program and defeats it. So this resolves the
 * NUMBER instead of matching the bytes that produce it, and reports the
 * capability rather than the number.
 *
 *
 * WHY THE UNIT IS A FUNCTION AND NOT A FILE.
 *
 * In a stager the sequence IS the malware. In a miner or a bot it is twenty
 * nodes among two thousand, and anything scored over the whole file drowns.
 * The loader FEATURE inside a larger trojan is the same problem: one segment
 * of a long sequence, which is the shape local alignment exists for.
 *
 * So the object here is a REGION - a function, and optionally what it calls -
 * and a file is a set of them. Raw shellcode has no functions, so the whole
 * blob is one region; the same machinery covers both without a special case.
 *
 *
 * WHAT IT IS NOT. Not an emulator. One linear sweep, a constant map over
 * sixteen registers, branch targets collected as they are met. The same
 * honesty as xref.c next door: it reads what is in front of it, and a value
 * that arrives through a branch or off the stack is not resolved rather than
 * guessed. Two approximations are named where they are made - see
 * kof_flow_func_of and the loop intervals.
 *
 * IT RUNS ON DECODED BYTES ONLY. A packed stager has no syscalls to find until
 * something has unpacked it; that is libkofemu's job and this is what runs
 * after it.
 *
 * NO SCORE AND NO VERDICT. This produces facts. Comparing two of them is
 * libkofeng/kofoverlord's - it already owns similarity and already refuses to
 * reduce a comparison to one number.
 */
#ifndef KOFENG_FLOW_H
#define KOFENG_FLOW_H

#include <stdint.h>

/*
 * WHAT A NODE MEANS, and the vocabulary is deliberately NOT syscall numbers.
 *
 * The middle of a stager is identical on both platforms - allocate something
 * executable, read from the network, jump into it - and only the way of asking
 * differs: a syscall number on Linux, an import on Windows, a hashed export in
 * Windows shellcode. A rule written against these words survives that
 * difference; one written against 42 does not. Same argument kofevt makes for
 * its verbs, one layer down.
 *
 * Kept under 32 so a set of them is one word - see kof_flow_func.mask, which
 * is the prefilter that decides whether two regions are worth comparing at all.
 */
enum kof_flow_cap {
	KOF_CAP_NONE = 0,
	KOF_CAP_ALLOC,        /* a mapping, without execute permission */
	KOF_CAP_ALLOC_EXEC,   /* ... with it - mmap/mprotect and PROT_EXEC */
	KOF_CAP_NET_OPEN,     /* socket */
	KOF_CAP_NET_CONNECT,
	KOF_CAP_NET_ACCEPT,
	KOF_CAP_READ,         /* read/recvfrom */
	KOF_CAP_WRITE,        /* write/sendto */
	KOF_CAP_FILE_OPEN,
	KOF_CAP_MEMFD,        /* a file that never touches a filesystem */
	KOF_CAP_EXEC_IMAGE,   /* execve/execveat */
	KOF_CAP_SPAWN,        /* fork/vfork/clone */
	KOF_CAP_SLEEP,
	KOF_CAP_PTRACE,
	KOF_CAP_COUNT
};

const char *kof_flow_cap_name(uint8_t cap);

/* The selector was known only in its low 8 bits - "mov al, 3" with the rest of
 * eax never set in this sweep. Accepted because a syscall number under 256 is
 * fully determined by it, and flagged because the claim is weaker. */
#define KOF_FLOWF_LOW8   (1u << 0)
/*
 * The node sits inside a backward branch's span.
 *
 * "Sends TCP" and "sends TCP in a loop" are different claims and the second is
 * the one worth a rule - a bot's beacon, a scanner's probe, a stager's retry.
 * APPROXIMATED BY AN INTERVAL, not by a dominator: a backward direct branch
 * from S to T marks everything in [T, S]. That over-reports when two unrelated
 * loops nest and under-reports a loop built out of indirect branches, and both
 * are stated here rather than discovered later.
 */
#define KOF_FLOWF_LOOP   (1u << 1)
/*
 * WHAT THIS NODE PRODUCED WAS LATER USED AS A BRANCH TARGET.
 *
 * This is the edge the whole file exists for. "Allocated something executable"
 * is a fact about a JIT as much as about a stager; "allocated something
 * executable AND JUMPED INTO IT" is a different claim, and it is the one a
 * rule wants. The pointer is followed from the register the call returned it
 * in to the operand of an indirect call or jump.
 *
 * REGISTER TO REGISTER ONLY. A pointer spilled to the stack and reloaded is
 * lost - that needs the slot model xref.c has and this does not. Losing it
 * costs a detection; inventing it would cost a false one, so the sweep loses.
 */
#define KOF_FLOWF_EXECUTED (1u << 2)
/*
 * THE IMPORT WAS CALLED THROUGH A REGISTER, not through its slot.
 *
 * `call [VirtualAlloc]` is what a compiler emits and what a reader of the
 * import table can see at the call site. `mov edi,[VirtualAlloc] ; ... ; call
 * edi` reaches the same function while leaving nothing at the call site that
 * names it - which is the point: it is one of the cheapest ways to make a
 * static reader lose the reference.
 *
 * NOT A VERDICT. A compiler does this too when the same import is called in a
 * loop, so on its own it says very little. It is a fact about HOW the call was
 * written, and what it is worth is measured beside the others.
 */
#define KOF_FLOWF_VIA_REG  (1u << 3)

#define KOF_FLOW_ARGS 4u

struct kof_flow_node {
	uint64_t va;      /* where the syscall instruction is */
	uint32_t step;    /* the NORMALISED instruction index - see below */
	uint32_t func;    /* index of the region it was found in */
	uint16_t sel;     /* the syscall number, or 0 when it did not resolve */
	/*
	 * WHICH EARLIER NODE PRODUCED EACH ARGUMENT, as index plus one, or 0.
	 *
	 * The chain, and the reason a sequence of capabilities is more than a
	 * list of them. "alloc-exec, then read, then an indirect jump" is a
	 * shape half the programs on a machine have somewhere; "read INTO what
	 * alloc-exec returned, then jump to THAT" is a stager and very little
	 * else.
	 *
	 * PER ARGUMENT AND NOT ONE PER NODE, because the arguments say
	 * different things. `read(fd, buf, len)` has the socket in one and the
	 * mapping in another, and "reads from the socket it opened" and "reads
	 * into the memory it mapped" are two separate claims - a single slot
	 * kept whichever was found first and threw the other away.
	 */
	uint16_t from[KOF_FLOW_ARGS];

	/*
	 * WHICH ARGUMENTS WERE A KNOWN CONSTANT - bit i for argument i.
	 *
	 * A LOADER HARDCODES; A SUBSYSTEM COMPUTES. A JIT maps a region whose
	 * size is the length of the code it just compiled - a value it worked
	 * out. A stub maps 0x1000 with prot 7, both written into the
	 * instruction. That difference survives junk insertion and
	 * re-encoding, because it is about where the value came from and not
	 * about how it was spelled.
	 *
	 * An argument with neither this bit nor a `from` entry is one the
	 * sweep could not follow - which is a third state and not a "no".
	 */
	uint8_t  arg_const;
	uint8_t  cap;     /* enum kof_flow_cap */
	uint8_t  flags;   /* KOF_FLOWF_* */

	/*
	 * HOW MANY PLACES WRITE INTO WHAT THIS NODE ALLOCATED.
	 *
	 * Only meaningful on an ALLOC or ALLOC_EXEC node, and counted as store
	 * instructions whose base register holds this node's return value.
	 *
	 * A LOADER FILLS ITS BUFFER FROM ONE PLACE - a read, a memcpy, a
	 * decrypt loop - so the count is small or zero, the copy itself having
	 * been made by a call whose argument provenance already records it. A
	 * JIT EMITS, so the page it mapped is written from many unrelated
	 * sites. Saturates at 255.
	 */
	uint8_t  writers;
};

/* The first argument that an earlier node produced, or 0 - the old
 * one-slot question, for a caller that does not care which argument. */
uint16_t kof_flow_from_any(const struct kof_flow_node *n);

/*
 * A REGION: one function's own nodes, as a slice of the node array.
 *
 * `mask` is the set of capabilities it holds, one bit per enum value. It is
 * the whole of the prefilter: two regions with no capability in common are not
 * worth aligning, and that is one AND to find out.
 */
struct kof_flow_func {
	uint64_t va;
	uint32_t first;   /* index into the node array */
	uint32_t n;
	uint32_t mask;    /* 1u << enum kof_flow_cap */
	uint32_t n_call;  /* direct calls out of it */

	/*
	 * HOW MANY PLACES CALL IT.
	 *
	 * A loader stub is called from one place or from none - it IS the
	 * entry. A subsystem's allocator is called from everywhere. The
	 * difference is structural and survives everything an obfuscator does
	 * to the instructions.
	 */
	uint32_t n_caller;

	/*
	 * HOW FAR FROM THE ENTRY POINT, in calls. 0 is the entry itself,
	 * KOF_FLOW_FAR when no chain of direct calls reaches it.
	 *
	 * The stub's work happens at depth 0 or 1. A JIT's mapping call is
	 * deep, and the depth is not something junk code can change without
	 * restructuring the program.
	 */
	uint16_t depth;
	uint16_t _pad;
};

#define KOF_FLOW_FAR 0xffffu

/*
 * THE GAP IS COUNTED IN NORMALISED INSTRUCTIONS, NOT IN BYTES.
 *
 * meterp_00 spells its gap "[8-15]", which is a byte count, and re-encoding
 * one instruction moves it. Two rules make the count survive more than that:
 *
 *   A RUN OF PUSHES IS ONE STEP. Several pushes in a row are one argument
 *   setup, not several things happening - "push 0 ; push 5 ; mov rdi, rsp" is
 *   a timespec being built. Counting them singly makes the gap depend on how
 *   many arguments the call happens to take.
 *
 *   A NOP IS NO STEP. Multi-byte nops, xchg ax,ax and lea r,[r] included.
 *   This is the first and cheapest junk-code defence; it is NOT a general one,
 *   and a polymorphic engine that inserts real-looking work still dilutes the
 *   count. Measured: six junk instructions between two nodes moved the gap
 *   from 11 to 16. That number is why a rule wants a RANGE and not a value.
 *
 * ONLY THE DELTA BETWEEN NODES IS A FACT ABOUT THE CODE. The first node's step
 * is an absolute position and moves when the prologue does - measured at 5 and
 * 3 for the same program before and after re-encoding.
 */

/*
 * WHAT A RELATION BETWEEN TWO NODES IS WORTH, and it is not one thing.
 *
 * A LINEAR SWEEP WALKS ADDRESSES, NOT PATHS, and without this it reports an
 * order that execution never takes:
 *
 *     if (cond)  socket();
 *     else       mmap(PROT_EXEC);
 *
 * Two calls that can never both run come out as a chain. That is worse than a
 * missing fact - a fabricated relation is exactly what a miner would then go
 * and find a pattern in.
 *
 * So every relation carries the domain it is valid in, and a caller that wants
 * "A then B" has to say which domain it will accept. The four are not degrees
 * of confidence; they are different statements:
 *
 *   SAME_BLOCK   one straight run of instructions. Order and adjacency are
 *                facts, and so is the gap between them.
 *   PATH         B is reachable from A through the block graph. Order is a
 *                fact; adjacency is not, because the path may branch.
 *   EXCLUSIVE    neither reaches the other. They may both run - in different
 *                calls of the same function - but NOT in this order and
 *                possibly not in the same execution at all. Only
 *                co-occurrence is a fact.
 *   UNKNOWN      the sweep could not answer: a cap was hit, the flow leaves
 *                through an indirect branch, or the two are in different
 *                threads. Must never be read as EXCLUSIVE.
 *
 * ACROSS THREADS THERE IS NO ORDER AT ALL, and that is not this file being
 * careful - kofevt.h states the same thing about collected events, for the
 * same reason one layer up: "a rule engine that matches A-then-B-then-C
 * against the arrival order is not matching what the machine did".
 */
enum kof_flow_rel {
	KOF_REL_UNKNOWN = 0,
	KOF_REL_SAME_BLOCK,
	KOF_REL_PATH,
	KOF_REL_EXCLUSIVE
};

struct kof_flow;

/*
 * THREE STATES, AND UNKNOWN IS ZERO.
 *
 * "It does not do X" and "I could not tell whether it does X" are different
 * claims, and collapsing them is the quietest way to manufacture a false
 * positive. The whole value of the strongest term measured so far - a region
 * that asks the machine for ONE thing and nothing else - rests on the
 * difference: a packed file, or a sweep that stopped at its bound, also asks
 * for one thing as far as anyone can see.
 *
 * UNKNOWN IS ZERO so that a zeroed structure, a forgotten field and an
 * unanswered question all read as "do not know" rather than as "no". The safe
 * value has to be the cheap one, or it will not be the one that gets used.
 *
 * TRUNCATION INVALIDATES ABSENCE, NOT PRESENCE. Having found something is
 * still having found it however early the sweep stopped; having found nothing
 * means nothing if the sweep did not finish. Every accessor below follows that
 * asymmetry.
 */
enum kof_fact {
	KOF_FACT_UNKNOWN = 0,
	KOF_FACT_NO,
	KOF_FACT_YES
};

const char *kof_fact_name(uint8_t v);

/*
 * THE CALLER CAN SAY THE PICTURE IS INCOMPLETE, and often it is the only side
 * that knows: a packed object sweeps to the end without error and shows almost
 * nothing, and no amount of looking at the instructions says so. The entropy
 * gate, the unpacker and the format parse all know. They tell this, the same
 * way a client tells the engine where an event's content is rather than the
 * engine learning to read records.
 *
 * Once marked, every NO becomes UNKNOWN.
 */
void kof_flow_mark_partial(struct kof_flow *f);

const char *kof_flow_rel_name(uint8_t rel);

/*
 * The relation between two nodes, by index. Order matters: relation(a, b) asks
 * whether B follows A, and the answer for (b, a) is a different question.
 */
uint8_t kof_flow_relation(struct kof_flow *f, uint32_t a, uint32_t b);

/*
 * THE MOST BLOCKS ONE RUN WILL HOLD.
 *
 * Past it the graph is incomplete, `full` is set, and every relation this
 * cannot prove comes back UNKNOWN rather than EXCLUSIVE - see the note on the
 * enum for why that direction is the only safe one.
 */
#define KOF_FLOW_MAX_BLOCK 8192u

#define KOF_FLOW_MAX_NODE 2048u
#define KOF_FLOW_MAX_FUNC 4096u

/*
 * THE MOST CODE ONE BUILD WILL READ, for the reason xref.h gives about its own
 * bound: a caller can check it before committing, and an object whose code is
 * larger than this is one nothing here can answer about cheaply.
 */
#define KOF_FLOW_MAX_CODE (4u * 1024u * 1024u)

struct kof_flow;

/*
 * THE CAPABILITY A FUNCTION NAME IS, or KOF_CAP_NONE.
 *
 * The same vocabulary from the other direction. A dynamically linked program
 * contains no syscall instruction at all - measured on /usr/bin: 846 x86-64
 * binaries, 76510 regions, FORTY ONE nodes - because the instruction is in
 * libc and the program only calls connect@plt. Reading imports is therefore
 * not an extra source, it is the only one an ordinary file has.
 *
 * Names and not numbers, so one table serves an ELF import, a PE import and a
 * Windows export resolved from a hash.
 */
uint8_t kof_flow_cap_of_name(const char *sym);

/*
 * WHICH CALLING CONVENTION THE CODE USES, which a decoder cannot tell from the
 * bytes and the caller always knows.
 *
 * It decides two things and both are wrong without it: which register holds an
 * argument this cares about - the protection word of a mapping call is the
 * THIRD argument, which is rdx under SysV and r8 under Microsoft's - and which
 * registers to look at when asking where an argument came from.
 *
 * Measured the day it was missing: the msfvenom PE stub calls VirtualProtect
 * with PROT constants in r8, this read rdx, and a mapping made executable came
 * back as an ordinary one.
 */
enum kof_flow_abi {
	KOF_FLOW_SYSV = 0,   /* Linux, and the Linux syscall ABI with it */
	KOF_FLOW_MS          /* Windows x64 */
};

/*
 * WHERE EXECUTION STARTS, if the caller knows - an ELF's e_entry, a PE's
 * AddressOfEntryPoint. Without it the lowest address swept is assumed, which
 * is right for a blob and wrong for a program.
 */
void kof_flow_entry(struct kof_flow *f, uint64_t va);

struct kof_flow *kof_flow_new(void);
void kof_flow_free(struct kof_flow *);

/*
 * WHO TURNS A CALL TARGET INTO A CAPABILITY - the caller, never this file.
 *
 * A direct call names an address. Which import that address is takes the ELF's
 * relocations or the PE's import table, and neither belongs in a decoder: the
 * same argument amsi_parse.h makes for being TOLD where the content is rather
 * than learning to read a record. So the sweep reports the target and asks,
 * and whoever holds the parse answers.
 *
 * Returning KOF_CAP_NONE means "not an import I care about", which is the
 * answer for almost every call in a program.
 */
typedef uint8_t (*kof_flow_resolve_fn)(uint64_t target, void *user);
void kof_flow_resolver(struct kof_flow *f, kof_flow_resolve_fn fn, void *user);

/*
 * Sweep one run of code. ONE CALL PER EXECUTABLE SECTION, and the caller makes
 * all of them - the same contract kof_xref_add has, for the same reason: the
 * first executable section of an ordinary ELF is .init and holds nothing.
 *
 * `code_va` is where the first byte is mapped, which is what makes a direct
 * branch target resolvable. `bits` is 32 or 64.
 */
void kof_flow_add(struct kof_flow *f, const uint8_t *code, uint32_t code_n,
		  uint64_t code_va, unsigned bits, unsigned abi);

/* Finish: sort the function heads, assign nodes to them, apply loop spans.
 * Called once, by the first accessor, so a caller cannot forget it. */
uint32_t kof_flow_n_func(struct kof_flow *f);
uint32_t kof_flow_n_node(struct kof_flow *f);
const struct kof_flow_func *kof_flow_func_at(struct kof_flow *f, uint32_t i);
const struct kof_flow_node *kof_flow_node_at(struct kof_flow *f, uint32_t i);

/*
 * HOW CONCENTRATED THE CAPABILITIES ARE, per mille of the file's nodes held by
 * the single busiest region.
 *
 * Near 1000 for a stager, where the sequence is the whole program. Low for a
 * miner or a bot, where the interesting part is a fraction of what the program
 * asks for. This is the fact that says WHICH KIND OF THING is in hand, and it
 * costs one pass over an array that is already built.
 */
/*
 * Does this region hold the capability. `func` of KOF_FLOW_ALL_FUNCS asks
 * about the whole object.
 */
#define KOF_FLOW_ALL_FUNCS 0xffffffffu
uint8_t kof_flow_has(struct kof_flow *f, uint32_t func, uint8_t cap);

/*
 * DOES IT ASK FOR ANYTHING OUTSIDE `mask` - the complement, and the one
 * question that must never be answered from an incomplete sweep.
 *
 * KOF_FACT_NO means "nothing else, and the sweep finished". That is the
 * statement a rule about a stub is built on.
 */
uint8_t kof_flow_only(struct kof_flow *f, uint32_t func, uint32_t mask);

/*
 * How concentrated the capabilities are, per mille of the object's nodes held
 * by the busiest region. Returns the fact state; `permille` is written only
 * when that is KOF_FACT_YES.
 *
 * Near 1000 for a stub, where the sequence is the whole program. Low for a
 * miner or a bot, where the interesting part is a fraction of what the program
 * asks for. UNKNOWN when the sweep did not finish, because a truncated sweep
 * concentrates by construction - it saw one thing because it stopped.
 */
uint8_t kof_flow_concentration(struct kof_flow *f, uint32_t *permille);

/* Non-zero when a cap stopped the build. A caller that needs "there is no such
 * capability here" rather than "here is one" has to treat that as unknown. */
int kof_flow_full(const struct kof_flow *f);

/*
 * The simple form: one region, the whole run, no function structure. What raw
 * shellcode wants, and what the unit tests use.
 */
uint32_t kof_flow_scan(const uint8_t *code, uint32_t code_n, uint64_t code_va,
		       unsigned bits, unsigned abi, struct kof_flow_node *out,
		       uint32_t cap);

#endif /* KOFENG_FLOW_H */
