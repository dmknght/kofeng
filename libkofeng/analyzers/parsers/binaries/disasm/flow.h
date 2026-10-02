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
#include "vocab.h"

/* The vocabulary itself is the contract a RULE is written against, so it
 * lives where a rule can see it. */
#include <kofmod/kofpathogen.h>


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
	 * AND THE SAME LINK BY THE PRODUCER'S IDENTITY, not by its position.
	 *
	 * `from[]` is an INDEX, and which index depends on how the chain was
	 * cut: the sweep numbers nodes over the whole object, kof_flow_chain
	 * renumbers them into the chain, collapse merges some away and the
	 * window keeps 24 of them. A link that means "the step N along" is a
	 * link that changes when none of the program did.
	 *
	 * This is the link as an EDGE BETWEEN TWO NODES, with the node named
	 * by the one identity it has that no re-cutting can move: the address
	 * of the instruction it was read at. `mmap -> exec-register` and
	 * `socket -> connect` are then two edges, each naming its own ends,
	 * and a reader - or a renderer giving them variable names - follows
	 * the edge rather than counting rows.
	 *
	 * 0 where the argument was not produced by a step this chain holds.
	 */
	uint64_t from_va[KOF_FLOW_ARGS];

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
	/*
	 * THE ARGUMENT VALUES THEMSELVES, where the sweep could follow them.
	 *
	 * Read and then thrown away for every revision until this one: the
	 * sweep worked out `prot`, `type` and `flags` well enough to decide
	 * three things - ALLOC_EXEC, DGRAM, THREAD - and dropped the numbers.
	 * Everything that needed a FOURTH question had to go without.
	 *
	 * The questions that need them are the ones that separate a behaviour
	 * from a capability: "create a file" and "create an EXECUTABLE file"
	 * differ by O_CREAT and 0755; "talk to a socket" and "beacon to a
	 * hardcoded port" differ by the port. Measured, the composite
	 * `file-open, write` tells malware from clean at 1.6x while
	 * `net-connect, write, read, sleep` manages 43x - and the difference
	 * is that the second needs no argument to be meaningful and the
	 * first does.
	 *
	 * NOT CONTENT. These are the values the program hands the KERNEL, in
	 * registers the ABI fixes - the same kind of fact the syscall number
	 * is, and no more the author's to choose.
	 *
	 * Only meaningful where arg_const says so; a value with its bit clear
	 * is whatever happened to be in the register.
	 */
	uint64_t arg[KOF_FLOW_ARGS];

	uint8_t  arg_const;
	uint8_t  cap;     /* enum kof_flow_cap */
	uint8_t  flags;   /* KOF_FLOWF_* */

	/*
	 * WHICH NAME THIS WAS, as kof_flow_name_of reads it back, or 0.
	 *
	 * The capability is what a RULE is written against, and that is the
	 * whole argument for having one: `register_kprobe` and
	 * `ftrace_set_filter_ip` are one fact about a program and a rule that
	 * had to list both would be a rule about one kernel.
	 *
	 * But a PERSON reading a chain is not matching it. "hook, hook,
	 * cred-set" is three words that could be almost anything;
	 * "register_kprobe, unregister_kprobe, commit_creds" is a module
	 * putting a probe on a symbol it was not given, reading the address,
	 * taking the probe away and then handing out root - which is a
	 * sentence. The word is for the engine; the name is for the reader,
	 * and throwing it away cost nothing but understanding.
	 *
	 * An index and not a pointer: the table is static and the node is
	 * copied, hashed and stored, so a pointer into it would be the one
	 * field that cannot survive being written to a file.
	 */
	uint16_t name;

	/*
	 * HOW MANY TIMES THIS STEP IS THE SAME STEP, when a loop repeats it.
	 *
	 * A chain used to spend its length on repetition: four `mov cr0` in
	 * one function, twenty reads in one decrypt loop, and a window of
	 * twenty-four nodes filled by one thing said over and over. That is
	 * not what the program does - it does the thing once, in a loop.
	 *
	 * So consecutive steps that are the same capability inside the same
	 * loop become ONE step carrying the count. 1 for a step that is only
	 * itself. Nothing is lost that was there: the count says what the
	 * repetition said, and the room it used is given back to the rest of
	 * the program.
	 */
	uint16_t repeat;

	/*
	 * WHICH LOOP, and not merely whether there is one.
	 *
	 * KOF_FLOWF_LOOP says a step repeats. `depth` adds at most one level
	 * for it and cannot say more, because a node knows the spans it sits
	 * in and not how a reader should nest them. Neither answers the
	 * question a chain actually needs: are these two steps going round
	 * TOGETHER?
	 *
	 * The difference is a claim about the program. An MSF stager hashes
	 * in two loops - one over the module list, one over a module's
	 * exports - and with only the flag to go on both steps looked like
	 * one loop doing both, which is a structure the program does not
	 * have. A chain that misstates the structure is a chain a rule is
	 * written against wrongly.
	 *
	 * The identity is the innermost containing span's index plus one, so
	 * 0 means "not in a loop" and equality means "the same loop". It is
	 * meaningful only WITHIN one object's chain - it is an index into
	 * that sweep's spans and nothing else.
	 */
	uint16_t loop;

	/*
	 * WHICH CONDITIONAL THIS STEP IS AN ARM OF, and which arm.
	 *
	 * `cond` says the step is inside one side of a two-way branch.
	 * That is enough to write `only on a branch` beside it and not
	 * enough to write `if { A } else { B }`, because two steps each
	 * marked `cond` may be two arms of one branch - alternatives, where
	 * exactly one runs - or two unrelated maybes, where both may. The
	 * claims are different and the flag cannot tell them apart.
	 *
	 * `branch` is the branching block's index plus one (0 = not an arm)
	 * and `arm` is 0 or 1. Two steps are alternatives when their
	 * `branch` matches and their `arm` differs. Like `loop`, the number
	 * means something only within one object's chain.
	 */
	uint32_t branch;
	uint8_t  arm;

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

	/*
	 * ---- WHERE THIS STEP SITS IN THE PROGRAM'S SHAPE ----------------
	 *
	 * Filled by kof_flow_chain and meaningless on a node read straight
	 * out of the file: both answer "how does this step stand to the one
	 * before it IN THIS CHAIN", and a node has no chain of its own.
	 *
	 * A CHAIN USED TO BE A LIST and a program is not one. "socket,
	 * connect, read, write, socket, bind, listen" reads as one sequence
	 * of seven things; what the program has is a connect path and a
	 * listen path that never both run, with the loop in the middle
	 * running twenty times. Flattening that asserts an order no
	 * execution ever takes.
	 */

	/*
	 * HOW DEEPLY NESTED: one for each call followed to get here, one for
	 * each loop around it. This is the indentation of the thing, and it
	 * is exact - the call depth is how far the walk recursed and the
	 * loop count is how many of the spans contain the address. Neither
	 * is inferred.
	 */
	uint8_t  depth;

	/*
	 * HOW IT FOLLOWS THE STEP BEFORE IT, as enum kof_flow_rel.
	 *
	 * KOF_REL_SAME_BLOCK and KOF_REL_PATH are a sequence: the earlier
	 * step can reach this one. KOF_REL_EXCLUSIVE is the interesting one
	 * and says they are ALTERNATIVES - no execution runs both in this
	 * order, so a branch sits between them.
	 *
	 * KOF_REL_UNKNOWN on the first step of a chain, and wherever the
	 * block graph could not answer: an indirect branch out of a block,
	 * a search that hit its bound, a sweep that was clipped. UNKNOWN is
	 * not "sequential" and must never be drawn as one - see the note on
	 * enum kof_flow_rel for why the negative is the expensive claim.
	 */
	uint8_t  rel;

	/*
	 * THIS STEP ONLY RUNS ON A BRANCH.
	 *
	 * Set when the block holding it is entered through a conditional
	 * jump AND THE OTHER ARM CANNOT REACH IT - which is what separates
	 * an arm from the join below it. Both arms of an `if` lead to the
	 * code after it, so the code after it is not conditional; the code
	 * inside one arm is.
	 *
	 * WHY IT IS NOT ENOUGH TO LOOK AT rel. EXCLUSIVE is rare in real
	 * code - measured, three steps in one bot's hundred and sixty-seven
	 * - and the reason is loops: a step in the `then` arm and a step in
	 * the `else` arm of a loop body DO both run, one iteration apart, so
	 * saying they are alternatives would be false. `cond` asks a
	 * different and much more common question: does this step run every
	 * time its function does, or only sometimes.
	 *
	 * Zero also means "could not tell": an indirect branch out of the
	 * sibling arm, or a search that hit its bound, leaves this unset
	 * rather than guessing. Unconditional is the safe reading because
	 * it claims less about the program.
	 */
	uint8_t  cond;

	/*
	 * HOW THE BODY HOLDING THIS STEP WAS ENTERED.
	 *
	 * KOF_FLOW_IN_ROOT when the step is in the function the chain is
	 * rooted at, KOF_FLOW_IN_CALL when a direct call reached it, and
	 * KOF_FLOW_IN_THREAD when the body is a thread entry - a pointer
	 * handed to clone, pthread_create or CreateThread and called by the
	 * system rather than by the program.
	 *
	 * NOT THE ADDRESS, WHICH IS WHAT THIS FIELD HELD FIRST. A frame
	 * labelled `call 0x3d3980` answers "which one" with a number that
	 * moves when the image is rebased or the linker reorders - the same
	 * kind of author-chosen value the whole vocabulary avoids, printed
	 * where a reader would learn to rely on it. The MECHANISM does not
	 * move: a thread body runs beside its caller and a called body runs
	 * inside it, and that difference is a fact about the program.
	 */
	uint8_t  entry;
};

enum {
	KOF_FLOW_IN_ROOT = 0,
	KOF_FLOW_IN_CALL,
	KOF_FLOW_IN_THREAD
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
	uint64_t mask;    /* 1ull << enum kof_flow_cap */
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
 * WHICH ARGUMENT A CALL DECIDES ITSELF BY, or KOF_FLOW_ROLE_NONE.
 *
 * Three things in the vocabulary are not one fact but two: mmap is a buffer
 * or a payload depending on prot, clone is a process or a thread depending on
 * its flags, and socket is a stream, a datagram or a raw socket depending on
 * its type. The capability alone cannot carry that, and the NAME is gone by
 * the time the sweep has a capability in hand - so the role travels beside it.
 *
 * It matters because "socket" and "bind" are both KOF_CAP_NET_OPEN: reading
 * the second argument of a bind as a socket type would read a POINTER as one.
 */
/* The roles live in vocab.h, with the tables that name them. */

uint8_t kof_flow_role_of_name(const char *sym);

/*
 * The name's own number, 1-based, or 0 for a name the table does not have.
 * kof_flow_name_of reads it back. Together they are how a node remembers
 * WHICH name gave it its capability without carrying a pointer.
 */
/*
 * WHAT THE KERNEL CALLS SYSCALL `nr` ON `arch`, or NULL.
 *
 * THE TABLE THAT RESOLVED THE NUMBER IS THE ONE THAT CAN NAME IT, and it is
 * in here. A number alone says nothing - 9 is mmap on x86-64 and link on
 * i386 - so anything displaying a step read from a syscall either asks this
 * or keeps a copy that will drift. kofviewer kept one, amd64 only, limited
 * to what the interpreter implements, and it printed `syscall_9` for
 * everything outside it.
 *
 * Only the calls the vocabulary has a word for are named: this is the same
 * table the capability comes from, not a complete syscall list.
 */
/*
 * AN ARGUMENT'S VALUE, SPELLED THE WAY THE ABI SPELLS IT.
 *
 * `socket(0x2, 0x1)` and `socket(AF_INET, SOCK_STREAM)` are the same fact
 * and only one of them can be read. The numbers are the kernel's, fixed by
 * the ABI and not by whoever wrote the program - the same reason a syscall
 * number is admissible - so decoding them adds no assumption.
 *
 * `name` is the step's name id and `cap` its capability; together they say
 * which call this is, and `idx` which of its arguments. Writes into `out`
 * and returns it, or returns NULL when this argument has no vocabulary -
 * a length, a file descriptor, a pointer - and the caller should print the
 * number.
 */
const char *kof_flow_arg_name(uint16_t name, uint8_t cap, uint32_t idx,
			      uint64_t v, char *out, uint32_t n);

const char *kof_flow_sys_name(unsigned arch, uint32_t nr);

uint16_t kof_flow_name_id(const char *sym);
const char *kof_flow_name_of(uint16_t id);

/*
 * THE SELECTOR OF A SYSCALL THE SWEEP FOUND BUT COULD NOT NUMBER.
 *
 * A thunk - `ret ; int 0x80` - is a body whose whole content is the
 * interrupt, and the number is in the register its caller set. The node is
 * recorded with this in its selector and no capability, and the pass that
 * knows the call graph resolves both. A node still carrying it when a
 * caller reads the flow is one nothing called, or one whose callers
 * disagreed; it has KOF_CAP_NONE and the chain skips it.
 */
#define KOF_FLOW_SEL_PENDING 0xffffu

/*
 * A LINUX SYSCALL AS A GUEST MADE IT -> the same vocabulary, same tables.
 *
 * The sweep reads syscall numbers out of code it never runs; an interpreter
 * has them from a run. Those are two SOURCES for one fact, and they have to
 * land on the same word or a rule written from one will not match the other -
 * so this exports the tables that were already here rather than letting a
 * second reader keep its own copy. A table in each place is a table that
 * disagrees after the first edit.
 *
 * `bits` is the guest's width because i386 and x86-64 do not share a
 * numbering. `arg` is the call's six arguments and may be NULL; it is read
 * only where the number says an argument refines the answer - PROT_EXEC makes
 * an allocation an executable one, and i386 keeps its socket operation in the
 * first argument of socketcall. `flags` may be NULL and otherwise receives
 * KOF_FLOWF_WX where that applies, never any other bit: whether a node is in
 * a loop or was jumped into is a fact about CODE, and a log of calls does not
 * carry it.
 *
 * KOF_CAP_NONE for everything else, which is most of what a program does.
 */
uint8_t kof_flow_cap_of_syscall(unsigned bits, uint32_t nr,
				const uint64_t *arg, uint8_t *flags);

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
 *
 * THE ANSWER CARRIES TWO THINGS: the capability in the low byte and the role
 * from kof_flow_role_of_name in the high one. A resolver that only knows the
 * capability returns it alone and loses nothing but the refinement.
 */
#define KOF_FLOW_ANSWER(cap, role) ((uint32_t)((uint8_t)(cap) | \
					       ((uint32_t)(role) << 8)))
/* And the same with the name the capability was read from - see
 * kof_flow_name_id, whose answer goes in the top sixteen bits. */
#define KOF_FLOW_ANSWER_N(cap, role, id) (KOF_FLOW_ANSWER(cap, role) | \
					  ((uint32_t)(id) << 16))
typedef uint32_t (*kof_flow_resolve_fn)(uint64_t target, void *user);
void kof_flow_resolver(struct kof_flow *f, kof_flow_resolve_fn fn, void *user);

/*
 * WHERE A CALL REALLY GOES, when the file has not been linked yet.
 *
 * A relocatable object's `call` is `e8 00000000`: the displacement is a hole
 * for the linker, so a decoder reads the target as the NEXT instruction and
 * every call in the file appears to go one byte past itself. Measured on
 * diamorphine.ko: 184 of its 248 call relocations are to symbols the module
 * DEFINES, so without this the module's own call graph is empty - every
 * function an island, and a chain that cannot cross from the one that turns
 * write-protect off to the one that writes.
 *
 * The relocation says where it goes, and only the caller holds the
 * relocations - the same division kof_flow_resolver makes, for the same
 * reason. Answering 0 means "I have nothing for this site", which is every
 * call in an ordinary linked program.
 */
typedef uint64_t (*kof_flow_retarget_fn)(uint64_t site_next, void *user);
void kof_flow_retargeter(struct kof_flow *f, kof_flow_retarget_fn fn,
			 void *user);

/*
 * A FUNCTION STARTS HERE, said by a caller that knows.
 *
 * The sweep works function boundaries out from CALL TARGETS, which is all it
 * can do with code alone - and it is wrong whenever a function is never
 * called. A compiler that inlines one leaves the out-of-line copy in the
 * section with nothing pointing at it, and its nodes are then attributed to
 * whichever function happens to precede it in address order.
 *
 * Measured on diamorphine.ko: `give_root` was inlined into `hacked_kill`, so
 * the standalone copy at 0x06e1 had no caller, and its `prepare_creds` landed
 * in `get_syscall_table_bf` - producing the chain "register_kprobe,
 * unregister_kprobe, prepare_creds", which is two unrelated functions read as
 * one. The module's own symbol table names all eleven boundaries.
 *
 * AND THE SIZE WITH IT, because the declaration is worth more than one head.
 * A linear sweep meets data inside .text constantly and some of it decodes
 * as `call`, which puts a head in the MIDDLE of a real function and cuts its
 * chain into fragments - each one then under KOF_DIAG_MIN_STEPS and gone.
 * Measured over 1287 objects whose symbol table could be read: 25.8% had at
 * least one function split that way, against 1.0% merged.
 *
 * So a head the sweep DERIVES is refused when it falls strictly inside a
 * declared function. Derived heads elsewhere are kept - a symbol table may
 * be partial, and refusing those would merge what it did not mention.
 *
 * Before the first kof_flow_add; after that the partition is settled.
 */
void kof_flow_head(struct kof_flow *f, uint64_t va, uint64_t size);

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

/*
 * THE FIXED-WIDTH ARCHITECTURES, which have no decoder and do not need one.
 *
 * Named here rather than taken from enum kof_arch because this header
 * deliberately includes nothing but <stdint.h> - it is read by the sweep and
 * by rule-side code, and a dependency on the scanner's vocabulary would be
 * paid by both. The caller maps its own architecture onto these three.
 */
enum kof_flow_arch {
	KOF_FLOW_A_MIPS32 = 1,
	/*
	 * AND MIPS64, WHICH IS A DIFFERENT ABI AND NOT A WIDER MIPS32.
	 *
	 * The instructions are the same - `li $v0,N` then `syscall` - so one
	 * decoder reads both. The NUMBERS are not: o32 bases its syscalls at
	 * 4000 and n64 at 5000, and they are not an offset apart either, so
	 * one table cannot serve. Reading an n64 object against the o32
	 * table resolves nothing at all: measured, 40 of 40 MIPS64 objects
	 * in the corpus produced ZERO capabilities while the sweep ran
	 * happily over every instruction.
	 *
	 * Corroborated before the table was written: every `li $v0`
	 * constant found across those 40 objects is >= 5000, and 5040,
	 * 5041, 5043 and 5044 - socket, connect, sendto, recvfrom - are the
	 * ones that recur, which is the profile of a network client and not
	 * of a mis-numbered table.
	 */
	KOF_FLOW_A_MIPS64,
	KOF_FLOW_A_ARM32,
	KOF_FLOW_A_ARM64,
	/*
	 * AND THE REST OF WHAT AN IoT BUILDER SHIPS. Measured over 20075
	 * executable objects of one Bazaar collection plus the lab here:
	 * 601 PowerPC, 349 SuperH, 345 m68k, 281 SPARC, 42 RISC-V - 8.8% of
	 * the corpus, and every one of them refused by the sweep before these
	 * existed. A botnet's build matrix is not a list of the architectures
	 * anyone develops on.
	 */
	KOF_FLOW_A_PPC32,
	KOF_FLOW_A_PPC64,
	KOF_FLOW_A_SPARC32,
	KOF_FLOW_A_RISCV,
	/*
	 * The two that are not four bytes wide. SuperH is two, and m68k is
	 * two to ten - so neither is swept by the word loop the four above
	 * share, and both get a reader of their own that reads HALFWORDS.
	 * Named here anyway, because what a caller has to say is still only
	 * "this is the architecture" - see kof_flow_add_fixed.
	 */
	KOF_FLOW_A_SH,
	KOF_FLOW_A_M68K,
	/*
	 * AND THE TWO THE VARIABLE-LENGTH SWEEP HANDLES ITSELF.
	 *
	 * x86 and x86-64 never needed an entry here because kof_flow_add
	 * takes `bits` and picks its own table. kof_flow_sys_name is asked
	 * from OUTSIDE the sweep, by something holding an object's
	 * architecture and a number, and "the architectures the fixed-width
	 * sweep knows" is not the question it is asking.
	 */
	KOF_FLOW_A_X86,
	KOF_FLOW_A_X86_64
};

/*
 * Sweep one run of fixed-width code. The same contract as kof_flow_add: one
 * call per executable run, and the run's own start becomes a head.
 *
 * `big_endian` is the object's, because MIPS ships both ways and an IoT
 * builder picks per target. Thumb is tried only when the ARM pass found
 * nothing - see sweep_thumb for why that is the whole of the policy.
 */
void kof_flow_add_fixed(struct kof_flow *f, const uint8_t *code,
			uint32_t code_n, uint64_t code_va, unsigned arch,
			int big_endian);

/* Finish: sort the function heads, assign nodes to them, apply loop spans.
 * Called once, by the first accessor, so a caller cannot forget it. */
uint32_t kof_flow_n_func(struct kof_flow *f);

/*
 * THE CALL GRAPH, AS A GRAPH.
 *
 * kof_flow_chain hands back one WALK through it, already flattened into a
 * sequence - which is what a rule matches against and the wrong shape for a
 * reader. A program is not a list: it has functions, and functions call
 * functions, and a view that shows the walk has asserted an order the
 * program may never take.
 *
 * So the edges are published too, and whoever wants the structure can have
 * it. Each is "the function at `from` calls the one at `to`, from this
 * address". Ordered by caller, then by site.
 */
uint32_t kof_flow_n_edge(struct kof_flow *f);
int kof_flow_edge_at(struct kof_flow *f, uint32_t i, uint32_t *from,
		     uint32_t *to, uint64_t *site);

uint32_t kof_flow_n_node(struct kof_flow *f);

/*
 * One node by index, after finish() has settled the partition, or NULL.
 *
 * A measurement hook: with it a caller can tell "the sweep never saw this
 * call" from "the chain set did not keep it", which are two different faults
 * with two different fixes and look identical from the chains alone.
 */
const struct kof_flow_node *kof_flow_node_at(struct kof_flow *f, uint32_t i);

/*
 * THE CHAIN: what a call to this function DOES, with what it calls inlined
 * where it calls it.
 *
 * WHY THE FUNCTION IS THE WRONG UNIT, measured rather than argued: of the 61
 * alloc-exec nodes found in 1500 PE samples, 45 sit ALONE in their function -
 * a region of exactly one node. A loader written as
 *
 *     main() { buf = setup(); fill(buf); run(buf); }
 *
 * is four capabilities and four functions, so at function granularity every
 * one of them is a single point with nothing around it, and no amount of
 * comparing points recovers the shape. The sequence only exists along the
 * CALL PATH, so that is what gets compared.
 *
 * WHAT IS AND IS NOT DONE HERE:
 *
 *   A function is expanded ONCE per chain. A helper called from ten places
 *   would otherwise multiply the chain by ten while saying nothing new, and
 *   recursion would not terminate at all.
 *
 *   Order is the order of the CALL SITES, which is the order of the
 *   addresses. That is the static order and not an execution order - a branch
 *   may skip a call entirely, and kof_flow_relation is what answers whether
 *   two of them can happen together.
 *
 *   Only DIRECT calls, plus the thread entries that KOF_FLOWF_* records.
 *   A call through a function pointer is not an edge here, so a chain is a
 *   lower bound on what the code does, never an upper one.
 *
 * `depth` is how many calls deep to follow; 0 is the function alone, which is
 * what the old region was. `origin`, when given, receives the node index each
 * entry was copied from, so kof_flow_relation still has something to answer
 * about. Returns how many nodes were written.
 *
 * `from` is REWRITTEN to positions within the chain, and an argument whose
 * producer did not make it into the chain becomes 0 - unknown, which is the
 * honest answer and not a claim that there was none.
 */
uint32_t kof_flow_chain(struct kof_flow *f, uint32_t func, uint32_t depth,
			struct kof_flow_node *out, uint32_t cap,
			uint32_t *origin);

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
uint8_t kof_flow_only(struct kof_flow *f, uint32_t func, uint64_t mask);

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
/*
 * WHERE A REGION STARTS, so a caller can ask whose code it is.
 *
 * The nodes of a chain are not enough for that question: on a statically
 * linked program EVERY syscall node is inside libc - `connect` is a libc
 * wrapper - so judging a chain by where its nodes are would throw away every
 * chain there is. What separates the author's from the library's is where the
 * chain is ROOTED, and that is this.
 */
uint64_t kof_flow_func_va(struct kof_flow *f, uint32_t func);

int kof_flow_full(const struct kof_flow *f);

/*
 * AND WHETHER IT WAS THE FUNCTION PARTITION THAT OVERFLOWED.
 *
 * A clipped code run loses nodes; a clipped HEAD list misplaces the ones it
 * keeps, because a function with no start of its own is read as part of the
 * one before it. The second is not a smaller answer, it is a wrong one, and
 * a caller building chains should throw it away.
 */
int kof_flow_heads_full(const struct kof_flow *f);

/*
 * The simple form: one region, the whole run, no function structure. What raw
 * shellcode wants, and what the unit tests use.
 */
uint32_t kof_flow_scan(const uint8_t *code, uint32_t code_n, uint64_t code_va,
		       unsigned bits, unsigned abi, struct kof_flow_node *out,
		       uint32_t cap);

#endif /* KOFENG_FLOW_H */
