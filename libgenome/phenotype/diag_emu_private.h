/*
 * diag_emu_private.h - what the files of the emulate route share. NOT PART OF THE SURFACE.
 *
 * The route is one routine (see diag_emu.c) in several files, one per stage: steering a call to
 * succeed, building an image for a relocatable object, the gaps between known sites, and the
 * walk of one function's span in steps. This is the state they hand each other and the stage
 * functions one calls in another. Private to libgenome/phenotype/.
 */
#ifndef KGENOME_DIAG_EMU_PRIVATE_H
#define KGENOME_DIAG_EMU_PRIVATE_H

#include <stdint.h>
#include <string.h>

#include <stdint.h>
#include <string.h>
#include "diag_scan.h"
#include "diag_private.h"
#include <kofcore.h>
#include <celllysis/capability.h>
#include <celllysis/nucleo.h>
#include <celllysis/celllysis.h>
#include <genotype/image/image_addr.h>
#include <genotype/image/elf_image.h>
#include <phenotype/emu_unpack.h>
#include <phenotype/emu.h>

/*
 * WHAT THE RUN IS ALLOWED TO COST.
 *
 * Bounds on the INPUT, not on the results - rule 4. Whatever was found when
 * one bites is kept, and kgenome_diag_scan_ran says the routine ran, so a caller
 * can tell "nothing linked" from "never attempted". AND EACH ONE THAT BITES SAYS
 * SO on the scan (kgenome_diag_scan_status) - see kgenome_diag_emu_stop_status.
 *
 * THE INSTRUCTION BUDGET is the scan's (kgenome_budget.max_insn: the caller's,
 * else max(2M, 64 x code bytes)); it was a fixed 2M, which a delay loop of a
 * million iterations before a decoder - the cheapest anti-analysis there is -
 * used up with the object unread. The pages the run may touch come out of what
 * the ledger has left, at most the emulator's own default.
 *
 * THE RUN IS FOR REACHING SYSCALL SITES, and what ends it is the run having stopped
 * reaching new ones - not a count of stops. A node is a site, so the second stop
 * at an address is the same finding again and a polling loop makes a thousand of
 * them; the same loop is also what a bound on the NUMBER of stops (it was 256,
 * scaled by the sites the static routes found) was written against. But a number
 * cannot tell that loop from a decoder that makes 254 different harmless calls
 * (getpid, gettimeofday - no node, so nothing remembers them) in front of its
 * stager: both are 256 stops. What tells them apart is whether the stop is one the run
 * has not made before. A STOP'S IDENTITY IS WHERE IT IS AND WHO REACHED IT (route_identity
 * in diag_emu.c: the address and the two most recent call instructions,
 * kgenome_emu_last_calls) - not the address alone, because a libc syscall wrapper is one
 * address however many places call it, and each call from a new place is new work.
 * KGENOME_DIAG_EMU_QUIET is how many stops in a row may repeat an identity already seen
 * before the run is called turned round and ended, KGENOME_TRUNCATED; a stop with a new
 * identity starts the count again. A genuine poll - the same site reaching the same
 * instruction, again and again - repeats from its third visit (the call history can differ for
 * the first two) and is ended after 256 of them; consecutive stops from new call sites are
 * bounded only by what bounds the run (the budget, the page ledger, the deadline) and by
 * KGENOME_DIAG_EMU_SITES below. The identities are bounded by KGENOME_DIAG_EMU_SITES, the DoS
 * bound: a program that makes new stops without end is said to have been cut
 * (KGENOME_TRUNCATED), not followed, and not silently dropped. Everything that bounded the
 * run before still does, so a bot that spins between two stops pays what it paid.
 *
 * WHAT THE COUNT SEES: every stop the emulator makes at a syscall instruction, the first visit
 * and every later one. (Until the instruction cache was made to fill the same per-step record as
 * a fresh decode - run_step in emu_interp.c - the watch compared the fetch buffer a cache HIT
 * did not fill, so a polled call paused once however many times it ran and a cached non-call was
 * paused on as one; a fixture of one getpid polled 1000 times made ONE stop. That is fixed, and
 * tests/unit/emu_syscall_watch.c holds it.) Counting every stop is why the identity above is
 * not the address: with the stops right, a wrapper called from 300 places would have read as 300
 * repeats of one address.
 *
 * THE TWO TIME BOUNDS OF THIS RUN THAT ARE NOT SCALED - the instruction budget's
 * floor (KGENOME_INSN_MIN) and the emulator's own "no new page for
 * KGENOME_EMU_IDLE (4M) instructions" stop - STAY, AND THAT IS A MEASURED CHOICE.
 * Lifting either was tried and the scan of a Mirai sample measured (callgrind Ir,
 * the same file before and after): the floor and the stall stop lifted to the
 * budget made a 223 KB sample 4.05G -> 11.2G (x2.8) and a 58 KB one x1.9, and the
 * stop limit scaled with the budget one sample x12; counting only the REPEATED
 * stops against the old limit was still +45% and +59% on two others. A bot that
 * polls or spins after its first syscall runs to whatever bound it is given. What
 * a delay is, and a spin is not, is a COUNTER: the emulator accounts a counted
 * delay loop by its iterations instead of running them (emu_loop.c), so the
 * wait costs the run neither budget nor idle time, and the bounds are the same
 * ones for a program that spins. A wait that is not a counted register-only loop
 * (it loads, stores, calls) is still what the budget is for. The PE resolver run,
 * which ends when the program goes silent and so does not pay this, has its own
 * larger floor (KGENOME_RESOLVE_MIN).
 *
 * KGENOME_DIAG_EMU_LEAD is where the run STARTS - a short way before the first node,
 * not before the entry point - and is a design choice about which question the
 * run answers (see route_aim), not a window on evidence, so it sets no status.
 */
#define KGENOME_DIAG_EMU_QUIET 256u

#define KGENOME_DIAG_EMU_SITES 32768u

#define KGENOME_DIAG_EMU_LEAD  256u

/* Where a relocatable object's stack goes: far above anything a file
 * occupies, so no section can overlap it. */
#define KGENOME_DIAG_REL_STACK 0x7ffff0000000ull

/* Room past the file for .bss and anything else that is declared but not
 * stored. */
#define KGENOME_DIAG_REL_SLACK 0x40000ull

/* Where %gs points: the per-cpu area and the stack guard. */
#define KGENOME_DIAG_REL_PERCPU 0x30000000ull

/* Where the file image sits. Offset zero is the null page and cannot be
 * mapped; the bias is private to this file. */
#define KGENOME_DIAG_REL_BASE  0x100000ull

/* The token arena: one page per producing call, dereferenceable, and far
 * from both the image and the stack. */
#define KGENOME_DIAG_TOK_BASE  0x20000000ull

/* The arena is a reserved range of the guest's address space, one page per producing node, and a
 * node index is 16 bits: the range is 65536 pages and ends where the per-cpu area begins. How much of
 * it is MAPPED follows the object's node count and the page budget, never less than
 * KGENOME_DIAG_TOK_SPAN pages (rel_tok_lim / rel_tok_span in the scan). */
#define KGENOME_DIAG_TOK_SPAN  256u
#define KGENOME_DIAG_TOK_MAX   0x10000u

/* One syscall site, and what the run saw there. */
struct kgenome_diag_emu_site {
	uint64_t off;         /* file offset of the instruction          */
	uint16_t node;        /* index in the scan                       */
};

/*
 * A value an earlier call handed back, and the node that handed it back.
 *
 * `len` is non-zero when the value is a REGION rather than a handle, and it
 * is what makes an entry into that region attributable: control arriving at
 * base+k belongs to the call that produced base, and to no other.
 */
struct kgenome_diag_emu_made {
	uint64_t val, len;
	uint16_t node;
};

/*
 * ---- EVERY CALL MUST BRANCH THE SUCCESSFUL WAY ----------------------------
 *
 * A sandbox has no peer to connect to, no file to open and nothing on the
 * other end of a read, so the program under a faithful run takes the failure
 * arm of everything and exits. MEASURED on meter1: socket, then straight to
 * exit, with the read and the jump that make it a stager never reached.
 *
 * So a call that failed is given a success. NOT a claim that it succeeded -
 * the path on which it did is the path the diagnose describes, and walking it
 * is the only way to see the rest. See the note on steering at the top for
 * why this cannot manufacture a link.
 *
 * AND SUCCESS HAS A DIFFERENT SHAPE PER CALL, which is the whole of this
 * function. Returning 0 from socket() is not success, it is fd 0; returning 0
 * from connect() is. Four shapes:
 *
 *   ZERO        connect, bind, listen, dup2 - the calls whose success is
 *               the absence of an error.
 *   A HANDLE    socket, open, accept, memfd, pipe. It must also be DISTINCT:
 *               two sockets that both "succeed" as fd 3 would make a later
 *               send(3) link to whichever was remembered last, which is a
 *               link the program never had. A counter gives each its own.
 *   A COUNT     read, write, recv, send. The length that was ASKED for -
 *               a short count is what makes a stager loop, and a zero is
 *               what makes it give up.
 *   LEFT ALONE  mmap and the allocators. A pointer has to be memory that can
 *               then be written, and only the emulator's own implementation
 *               can hand one out; a fabricated address would fault at the
 *               first store into it. mprotect is here too and for a worse
 *               reason: it shares KGENOME_NUCLEO_ALLOC with mmap, so the capability
 *               alone cannot say whether 0 or a pointer is the success. That
 *               is a thing to fix in the vocabulary, not to guess at here.
 */
enum kgenome_diag_emu_force_kind { KGENOME_DIAG_EMU_FORCE_NONE = 0, KGENOME_DIAG_EMU_FORCE_ZERO, KGENOME_DIAG_EMU_FORCE_HANDLE, KGENOME_DIAG_EMU_FORCE_COUNT };

/* A handle nothing else will hand out. Above every real descriptor the
 * emulator issues and far below anything that could be a pointer. */
#define KGENOME_DIAG_EMU_FD0 0x200u

#define KGENOME_DIAG_EMU_FILL_ON 0

/* rax on amd64, eax on i386 - the same register number either way. */
#define KGENOME_DIAG_EMU_RET KGENOME_EMU_RAX

/*
 * ---- THE GAP BETWEEN TWO KNOWN SITES, FOR A KERNEL MODULE ---------------
 *
 * EVERYTHING THE SYMBOL ROUTINE ALREADY FOUND IS THE INPUT. It read the
 * relocation table and put a node at every call to an import, at a file
 * offset, without decoding anything. What it could not answer is which value
 * reached which call once the value went through memory - and that is the
 * only question asked here.
 *
 * SO NOTHING RUNS FROM THE TOP. There is no init_module to execute, no
 * runtime, no loader. One span at a time: start where a producing call
 * returns, with its result replaced by a token nothing else can hold, and
 * single-step until control reaches another site. A token in an argument
 * register there is a link, and one the span demonstrated rather than one a
 * model asserted.
 *
 * SINGLE-STEPPING AND NOT A WATCH, because a watch matches BYTES and the
 * thing being waited for is an ADDRESS. Listing the encodings of call would
 * be a list of the forms we happen to know; stepping knows none. The spans
 * are tens of instructions, so the cost of stepping them is not a question.
 *
 * AND AN UNLINKED CALL IS HARMLESS TO EXECUTE. Its displacement is a hole, so
 * `e8 00 00 00 00` pushes a return address and falls through to the next
 * instruction - which is exactly the address the relocation table reports as
 * the site. The run never jumps into an unresolved import, and the argument
 * registers are intact when it arrives.
 */
#define KGENOME_DIAG_REL_STEPS 4096u

/*
 * HOW OFTEN ONE BACKWARD BRANCH MAY BE TAKEN before the run is made to leave
 * the loop. Two full passes: the first covers every site in the body, the
 * second lets a value that is carried between iterations settle. A third
 * cannot produce a node that is not already there, because a node is a site.
 */
#define KGENOME_DIAG_REL_SPINS 2u

/*
 * HOW MANY FAULTS ON SYNTHETIC MEMORY ONE SPAN MAY STEP OVER. A DoS bound and
 * nothing else: a span faulting on every other instruction is not being
 * walked, it is being guessed at, and it should end.
 */
#define KGENOME_DIAG_REL_FAULTS 32u

/*
 * ---- WHEN THE RUN IS MOVED ON, AND WHY IT IS NOT RUN AGAIN --------------
 *
 * THIS ROUTINE DOES NOT EXECUTE THE PROGRAM. It resolves whether the value a
 * known node produced is the value another known node receives, and the only
 * reason it steps instructions at all is that the arithmetic in between -
 * a move, an add, a spill and reload - is easier to RUN than to model. The
 * sites themselves are not discovered by running: the relocation table names
 * every one of them before a single instruction is stepped.
 *
 * SO CONTROL FLOW IS NAVIGATION, NOT EVIDENCE. A loop adds nothing after its
 * first pass, and a conditional branch out of the function leads nowhere this
 * span can use - both are obstacles between one site and the next, and the
 * run exists to step AROUND them.
 *
 * WHEN THE RUN STALLS - it leaves the function, faults on memory that was
 * stated rather than read, or spends its budget - the span MOVES TO THE NEXT
 * SITE and carries on. One pass, each site seated at most once.
 *
 * AND NOT BY RUNNING THE SPAN AGAIN. That was tried and it was the wrong
 * shape: six runs of one function, each following a different arbitrary path,
 * to collect what one pass over the known sites collects directly. It cost
 * 3.5x on 900 kernel modules and it is the thing this design exists to avoid.
 *
 * WHAT IT ASSUMES, SAID PLAINLY: after a re-seat the registers are the ones
 * the previous stretch left. That is a claim about DATA, not about a path -
 * the same claim the whole routine makes when it states a skipped call's
 * result - and a link is still only recorded when a register actually holds
 * a token some node produced.
 */
#define KGENOME_DIAG_REL_SEATS 64u

/*
 * HOW MANY INSTRUCTIONS ONE GAP MAY TAKE.
 *
 * THE BUDGET BELONGS TO THE GAP, NOT TO THE SPAN. A span-wide budget is spent
 * by whichever stretch is slowest, and everything after it is never looked at
 * - MEASURED: diamondxe's filtering loop used all 4096 instructions and its
 * copy_to_user, a site the relocation table had named before the run started,
 * was never once seated. The symptom is indistinguishable from "that call has
 * no link", which is the worst shape a fault can have.
 *
 * A gap is a stretch between two calls. 512 is far past any of them: the
 * longest in either Diamorphine build is under 80 instructions, and a stretch
 * that needs more than 512 is looping, which is the thing to step around.
 */
#define KGENOME_DIAG_REL_GAP 512u

/* How far into an object a displacement may reach and still be a field of
 * it. A struct kprobe is 0x58 bytes; nothing this routine looks at is near
 * a page. A bound on what counts as one object, not on results. */
#define KGENOME_DIAG_OBJ_SPAN 0x200u

struct kgenome_diag_emu_skipsite {
	uint64_t call_at;       /* where the call instruction begins */
	uint64_t resume;        /* and where control continues       */
	uint64_t callee;        /* an INTERNAL call's target, else 0 */
	uint16_t cap;           /* KGENOME_NUCLEO_NONE for an internal call */
};

/* GROWN WITH THE OBJECT, and not a static array of 1024: a bound on a result
 * drops every call after it without a word, and a static is shared by every
 * thread scanning a module at once. */
struct kgenome_diag_emu_skipgather {
	struct kgenome_diag_emu_skipsite *site;
	uint32_t         n, cap_n;
	int              oom;
};

/*
 * ONE SPAN PER FUNCTION, AND EVERY SITE IN IT IS OBSERVED.
 *
 * The first shape ran a span per PRODUCER - a call that hands a value back -
 * and could therefore only ever find relations of the form "B consumed what A
 * produced". MEASURED on Diamorphine: of fourteen nodes exactly one is a
 * producer, so two spans ran and two links came out, and the rest of the
 * module's relations were not missed so much as never asked about.
 *
 * THE OTHER RELATION IS A SHARED ARGUMENT. register_kprobe and
 * unregister_kprobe are one idiom because they are handed THE SAME struct
 * kprobe - an address in .bss, not a value either of them produced. Nothing
 * in a provenance model expresses that, and it is the relation that makes the
 * pair evidence rather than two unrelated calls.
 *
 * So a run covers a FUNCTION, which is the scope an address means anything
 * in, and at every call site it reads the arguments and asks two questions of
 * each: is this a value an earlier site produced, and is it a value an
 * earlier site was also given. Both are links; the first is provenance and
 * the second is identity.
 *
 * WHAT MAY BE REMEMBERED is bounded on purpose. Only a value inside the
 * mapped image or the token arena - an object this module owns. Zero, a small
 * integer and a stack address are shared by half the calls in any program and
 * remembering them would relate everything to everything.
 */
#define KGENOME_DIAG_REL_SEEN 64u       /* the table starts with this many; it grows with the node count */

/*
 * HOW MANY TIMES THE SPANS ARE RUN.
 *
 * A caller analysed before its callee learns what that callee returns on the
 * following pass, so the number bounds how deep a chain of helpers can be
 * followed - four covers resolve_sym inside findmyinterest inside
 * init_module with one to spare. It stops early when a pass changes nothing,
 * which is the usual case after two.
 */
#define KGENOME_DIAG_REL_PASSES 4u

/*
 * A VALUE, THE NODE IT BELONGS TO, AND WHICH OF TWO RELATIONS THAT IS.
 *
 * They are not the same relation and one table recorded them as if they
 * were:
 *
 *   PRODUCED  the node RETURNED this value. kzalloc hands back the buffer;
 *             prepare_creds hands back the credentials. A later call holding
 *             it is holding what this call made - that is provenance, and it
 *             is what a link means.
 *   RECEIVED  the node was HANDED this value and made nothing. Both halves
 *             of the kprobe pair are given the same struct kprobe; neither
 *             produced it. Two receivers share an object, which is a real
 *             relation and a different one.
 *
 * WITH ONE FLAG FOR BOTH, a value that was produced once and received twice
 * put three nodes in the table and a later argument linked to all of them -
 * so copy_to_user, which has exactly one source, came back with two parents
 * both wearing `source`. Overwriting the earlier entry made the output
 * tidy and the answer wrong: it recorded copy_from_user as the producer of
 * a buffer kzalloc had produced.
 *
 * So the kind is kept, and a link prefers the producer. Where there is none -
 * the kprobe struct, which is a module global nobody returned - the earliest
 * receiver stands for the object, which is what makes the pair one idiom.
 */
struct kgenome_diag_emu_seenval {
	uint64_t val;
	uint16_t node;
	uint8_t  produced;
};

/*
 * What the walk of one object's functions shares across every function and
 * pass.
 */
struct kgenome_diag_emu_rel_walk {
	struct kgenome_diag_scan *s;
	const struct kgenome_obj *obj;
	const uint8_t *base;
	uint64_t size;
	struct kgenome_diag_emu_skipsite *skips;
	const struct kgenome_func *fns;
	struct kgenome_diag_emu_skipgather sg;
	struct kgenome_func_set fg;
	uint16_t *ret;
	uint8_t *dirty, *next_dirty, *vis;
	struct kgenome_emu **tmpl;
	uint32_t n;                     /* nodes BEFORE kgenome_diag_emu_promote_wrappers */
	int changed;                    /* this pass learned a new return token */
};

/* What the walk of ONE function - one span - holds while it steps. */
struct kgenome_diag_emu_rel_span {
	struct kgenome_diag_emu_seenval *seen;  /* grown on demand, owned by the walk, freed with it */
	struct kgenome_emu *em;
	uint32_t n_seen, cap_seen, anon, anon_floor;
	uint64_t n_fd;
	/* Which sites this span has already been seated at, so one
	 * pass cannot circle. */
	uint32_t n_seat, gap_steps;
	uint64_t run_lo, run_hi;
	uint64_t last_in;
	/* Which backward branches this span has arrived at, and how
	 * often. Per span: a loop in one function says nothing about
	 * a loop in the next. */
	struct { uint64_t at; uint32_t n; } latch[32];
	uint32_t n_latch, n_fault;
	uint64_t lo, hi;
};

/* What one phase of a step decided: carry on with the step's later phases,
 * go straight to the next step, or end the stretch and seat the span at the
 * next site. */
enum kgenome_diag_emu_rel_act { KGENOME_DIAG_EMU_REL_ON, KGENOME_DIAG_EMU_REL_NEXT, KGENOME_DIAG_EMU_REL_STALL };

/* ---- what one stage offers another ---- */

int kgenome_diag_emu_ret_is_carryable(uint64_t ret);
int kgenome_diag_emu_cap_hands_on_value(uint16_t cap, const char *nm);
enum kgenome_diag_emu_force_kind kgenome_diag_emu_cap_force_kind(uint16_t cap);
void kgenome_diag_emu_fill_buffer(struct kgenome_emu *em, uint64_t at, uint64_t n);
extern const unsigned kgenome_diag_emu_arg_reg64[6];
extern const unsigned kgenome_diag_emu_arg_reg32[6];
unsigned kgenome_diag_emu_guest_name(struct kgenome_diag_scan *s, struct kgenome_emu *em, uint64_t va, char *out);
void kgenome_diag_emu_capture_names(struct kgenome_diag_scan *s, struct kgenome_emu *em,
		uint16_t cap, uint16_t node);
uint64_t kgenome_diag_emu_pages_charge(struct kgenome_diag_scan *s);
void kgenome_diag_emu_pages_release(struct kgenome_diag_scan *s);
int kgenome_diag_emu_account(void *user, int64_t bytes);
void kgenome_diag_emu_stop_status(struct kgenome_diag_scan *s, enum kgenome_emu_stop st);
struct kgenome_emu *kgenome_diag_emu_build_rel_image(struct kgenome_diag_scan *s,
		const struct kgenome_obj *obj,
		const uint8_t *base, uint64_t size);
void kgenome_diag_emu_gather_skip(struct kgenome_diag_emu_skipgather *g,
		const struct kgenome_diag_rcall *rc);
int kgenome_diag_emu_skip_cmp(const void *a, const void *b);
uint32_t kgenome_diag_emu_skip_first(const struct kgenome_diag_emu_skipsite *v, uint32_t n, uint64_t at);
int kgenome_diag_emu_worth_remembering(uint64_t v, uint64_t size);
uint16_t kgenome_diag_emu_callee_node(const struct kgenome_diag_scan *s,
		const struct kgenome_func *fns, uint32_t n_fn,
		uint64_t callee);
int kgenome_diag_emu_has_cr_write(const uint8_t *p, uint64_t n);
void kgenome_diag_emu_promote_wrappers(struct kgenome_diag_scan *s,
		const struct kgenome_func *fns, uint32_t n_fn);
void kgenome_diag_emu_field_value(struct kgenome_diag_hit *fh, const struct kgenome_cell_insn *ci,
		unsigned mi);
int kgenome_diag_emu_rel_span_too_sparse(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S);
int kgenome_diag_emu_rel_span_no_producer(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S);
int kgenome_diag_emu_rel_span_open(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S);
enum kgenome_diag_emu_rel_act kgenome_diag_emu_rel_step_enter(struct kgenome_diag_emu_rel_span *S, uint64_t rip);
enum kgenome_diag_emu_rel_act kgenome_diag_emu_rel_step_sites(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S,
		uint64_t rip);
enum kgenome_diag_emu_rel_act kgenome_diag_emu_rel_step_decode(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S,
		uint64_t rip);
enum kgenome_diag_emu_rel_act kgenome_diag_emu_rel_step_emulate(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S,
		uint64_t rip);
void kgenome_diag_emu_run_rel_gaps(struct kgenome_diag_scan *s,
		const struct kgenome_obj *obj,
		const uint8_t *base, uint64_t size);

#endif /* KGENOME_DIAG_EMU_PRIVATE_H */
