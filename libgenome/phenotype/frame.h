/*
 * frame.h - THE FRAME OF A FUNCTION: what is a plain fact of its decoded code, found once and read by everyone after.
 *
 * WHY. The signing of a function (the CFG signature) and the lineage each took a function's instructions and built the same graph from them, each its own
 * way (the signature with the real byte order, the lineage with `.be = 0` and a different block rule). A fact of the code is decided where the instructions are, once, and kept (kofeng/CLAUDE.md rule 5).
 * Lineage runs ITS OWN analysis (links, shared values, summaries, value flow) on top of the frame: that is not stored here, because it is not a fact of the
 * code - it needs the node table, the other functions and the state the solve builds.
 *
 * WHAT A FRAME HOLDS, with one meaning each (coordinates: FILE OFFSETS unless a field says address):
 *   off, len     the function's extent in the file, as the caller asked (a table entry's, from the function table: its end_source says how firm it is)
 *   va           the address of the entry (an object with no address map: the offset, as every branch of it is relative to it); `mapped` says the map was used
 *   fn           the index of the function in the table the frame was made for, KGENOME_FUNCS_NONE for an extent that is not a table entry
 *   n_insn       instructions decoded in [off, off + len); n_skip bytes that decoded as nothing; `cut` 1 when any did (the graph is then a cut one: status TRUNCATED)
 *   be           the code's byte order (1: big-endian code); the graph was built with it
 *   cfg          the control-flow graph (celllysis/cfg.h): blocks in layout order with their first instruction INDEX, byte start `at`, terminator and successor
 *                BLOCK INDICES, `reach`, and the calls and system calls of the reachable ones. Built with no SPLIT_EXITS: a conditional branch that leaves the extent
 *                does not end a block (the signature's rule, which a pack's hashes fix; the lineage was measured to give the same links on it - 319 objects).
 *                The block indices `first` and `n_insn` index the instructions of this function in the order the shared reader (kgenome_diag_code_run) gives them
 *                for [off, off + len): a consumer that reads them again through it gets the same array.
 *   bits[b]      per block, the facts of its instructions that need no other input (KGENOME_FRAME_B_*, below). A MEMO: NULL until the first kgenome_frame_facts, which reads the
 *                instructions once (the signing never asks, and measured 17% of the frame's own cost went to them for a reader that did not want them)
 *   framed       1 when the function opens with `push rbp; mov rbp, rsp` and nothing else writes rbp but the epilogue: `[rbp+x]` is then a slot of the frame and
 *                not a place (already applied to `bits`, said here because the lineage's slot model is the other reader of it); valid once `bits` is
 *   state        KGENOME_FRAME_OK, or why there is no graph: UNDECODABLE (nothing decodes at the entry), UNSUPPORTED (no control-flow rules for the architecture),
 *                OVER_BUDGET (this function is more than one call's allowance), NOMEM; `status` is the worst status of the decode and the graph
 *   in           the instructions themselves, only when the frame was made with KGENOME_FRAME_KEEP_INSN (a viewer that draws them); every other consumer reads them again
 *                through the shared reader, which serves them from the object's walk (x86) and decodes nothing
 *
 * WHAT IT DOES NOT KNOW (so a consumer does not look for it): which call is a node, which target is a function of the object, what a register holds, what a
 * callee does. Those come from the node table, the function table and the stage that asks.
 *
 * COST. One decode (or one read of the walk's trace) and one graph per function, built on the first ask and kept by the cache until the object ends (up to its bound). A frame
 * is 176 bytes of header, 36 bytes a block, 16 a call, and two bytes a block once the facts are asked. Memory goes through the caller's allocator (the scan's ledger); a refusal is
 * a state, never a crash, and the function is then asked for again by whoever needs it next (nothing is cached for a function that could not be made).
 */
#ifndef KGENOME_FRAME_H
#define KGENOME_FRAME_H

#include <stddef.h>
#include <stdint.h>

#include "../kgenome_status.h"
#include "../genotype/image/obj.h"
#include "../genotype/image/funcs.h"
#include "../celllysis/cell.h"
#include "../celllysis/cfg.h"

struct kgenome_diag_walk;

enum kgenome_frame_state {
	KGENOME_FRAME_OK = 0,
	KGENOME_FRAME_UNDECODABLE,      /* the extent is not in the object, or no instruction decodes at its entry */
	KGENOME_FRAME_UNSUPPORTED,      /* no control-flow rules for the architecture */
	KGENOME_FRAME_OVER_BUDGET,      /* the function is more than one call's allowance (kgenome_frame_src.max_bytes) */
	KGENOME_FRAME_NOMEM
};

/* Facts of the instructions of a block (kgenome_frame.bits). */
#define KGENOME_FRAME_B_MEMCELL  0x01u  /* a memory operand that is not the stack pointer's own and, when the function has a frame pointer, not [rbp+x] */
#define KGENOME_FRAME_B_MEMSTORE 0x02u  /* ... that the instruction writes (not a call, jump, compare, test or push through it) */
#define KGENOME_FRAME_B_PUSH     0x04u  /* a push */
#define KGENOME_FRAME_B_CALL     0x08u  /* a call (direct or not) */
#define KGENOME_FRAME_B_JMP      0x10u  /* a jump of the unconditional kind (direct or through a register or memory) */
#define KGENOME_FRAME_B_RET      0x20u  /* a `ret` (not an iret) */
#define KGENOME_FRAME_B_RUNS_OUT 0x80u  /* the block is the last of the extent, ends with no branch, and its last instruction is not a call or a system call: control runs on into whatever follows the extent */
#define KGENOME_FRAME_B_LEAVES   0x40u  /* a jump, a conditional jump or a loop that goes out of the extent [va, va + len), has no target the image holds, or goes through a register or memory */

#define KGENOME_FRAME_KEEP_INSN 1u      /* kgenome_frame_make flag: hand back the decoded instructions too */

struct kgenome_frame {
	uint64_t off, len;
	uint64_t va;
	uint64_t n_skip;
	uint32_t fn;
	uint32_t n_insn;
	uint8_t  state;                 /* enum kgenome_frame_state */
	uint8_t  be, mapped, framed, cut;
	enum kgenome_status status;
	struct kgenome_cfg cfg;
	uint16_t *bits;                 /* cfg.n_all entries; NULL until kgenome_frame_facts */
	struct kgenome_cfg_mem mem_;    /* private: the allocator the frame was made through (the memo is allocated and given back through it) */
	struct kgenome_cell_insn *in;   /* n_insn entries, only with KGENOME_FRAME_KEEP_INSN */
	/* private: the sizes handed back to the allocator */
	size_t   self_bytes_, bits_bytes_, in_bytes_;
};

/*
 * INSTRUCTIONS THE CALLER ALREADY DECODED for the extent [off, len): the frame is then made from them and decodes nothing. The lineage reads a function's instructions
 * itself (it steps them), and without this a function of an object whose walk has no trace (PE) was decoded once for the graph and once for the lineage. `v` is what
 * kgenome_diag_code_run gave for the extent, in order; `skipped` the bytes that decoded as nothing.
 */
struct kgenome_frame_insns {
	const struct kgenome_cell_insn *v;
	uint32_t n;
	uint64_t skipped;
	uint64_t off, len;              /* the extent they are the decode of (checked against the request: a frame is never made from another function's) */
};

/* What a frame is made from. */
struct kgenome_frame_src {
	const struct kgenome_obj *obj;
	const uint8_t *base;
	uint64_t size;
	const struct kgenome_func_set *fs;      /* the object's function table, for `fn` and for the cache's slots; NULL for an extent of no table */
	struct kgenome_diag_walk *wk;           /* the object's walk: its trace is the decode (x86); NULL decodes */
	struct kgenome_cfg_mem mem;             /* the caller's allocator for kgenome_frame_make (NULL members: malloc and free); a cache uses its own */
	/*
	 * REACH_INDIRECT (cfg.h, KGENOME_CFG_T_SWITCH), optional: passed straight through to `kgenome_cfg_req.switch_src` (plumbing
	 * only - frame.c copies the field, it reads and resolves nothing of its own). NULL read_at (every caller today: the signing
	 * through kof_cfgsign_function, the lineage, codenotes, cfgview, kofexaminer) means kgenome_cfg_build never attempts switch
	 * resolution, so the frame's graph, its `n_all`/`n_blk`/`n_edge`/reach and every existing caller's output are byte-for-byte
	 * what they were before this field existed. A caller with image/VA access (fntab_reach.c's REACH_INDIRECT gap, its own header
	 * comment) may fill it to let a switch's real targets become `fr.cfg.switch_tgt[]`; wiring that up is NOT done here - the two
	 * structural fields (this one and cfg_req.switch_src) are the whole of this work package's plumbing, deliberately, to stay
	 * disjoint from concurrent work on fntab_reach.c's own padding-walk logic.
	 */
	struct kgenome_cfg_switch_src switch_src;
	uint64_t max_bytes;                     /* what ONE function may hold while it is made (0: 64 MiB) */
	const struct kgenome_frame_insns *pre;  /* the decode of the function being asked for, when the caller has it (not kept: read during the call) */
	int facts;                              /* 1: record the facts of the blocks in the same pass that makes the graph (a caller that reads them always: the lineage); 0: a memo, made on the first ask */
};

/*
 * Make the frame of the function [off, off + len). `out` is zeroed first; `*out` itself is caller storage and kgenome_frame_release gives back what hangs
 * off it. Returns out->state. THE ONE DECODE-AND-GRAPH OF A FUNCTION: nothing else in the tree builds a graph of a function from instructions.
 */
enum kgenome_frame_state kgenome_frame_make(const struct kgenome_frame_src *s, uint64_t off, uint64_t len, unsigned flags,
					    struct kgenome_frame *out);
void kgenome_frame_release(struct kgenome_frame *f, const struct kgenome_cfg_mem *mem);

/*
 * THE FACTS OF THE BLOCKS (`bits`, `framed`), filled once, on the first ask, from the instructions the caller read for this function (the same array the graph indexes: n_insn of them).
 * A memo inside a frame that is otherwise read only, so it takes the frame as a const view: the frame is the cache's or the caller's own and was never const-defined. Returns the
 * bits, or NULL when the frame has no graph or memory was refused (nothing is then recorded: the next ask tries again).
 */
const uint16_t *kgenome_frame_facts(const struct kgenome_frame *f, const struct kgenome_cell_insn *in);
/* The same for a caller that holds no instructions of this function (a callee): they are read again through the shared reader (the walk's trace on x86, the decoder where there is none)
 * for [f->off, f->off + f->len), from `s`; once, and the memo is then there for every later ask. NULL as above, or when that read could not be held. */
const uint16_t *kgenome_frame_facts_of(const struct kgenome_frame *f, const struct kgenome_frame_src *s);

/* The words of a state, for a report. */
const char *kgenome_frame_state_name(enum kgenome_frame_state s);

/*
 * THE CACHE: one per object, the frames of its table's functions, each made on the first ask and kept. `kgenome_frame_get` answers the frame of table entry
 * `fi` (NULL when it could not be allocated at all; a frame whose `state` is not OK is a kept answer, "this function has no graph, and why").
 * The pointer stays valid until the cache is freed. `fs` of the source must be the table every call is made with (its length sets the slots).
 */
struct kgenome_frame_cache;
/*
 * `mem`: the allocator every frame of the cache is charged to and given back through (NULL: malloc and free). It outlives any one caller.
 * `max_bytes`: the most the cache KEEPS (0: KGENOME_FRAME_CACHE_MAX). A frame is about twice the bytes of its function (measured: 1235 bytes a function, 9.3 a decoded
 * instruction, 36 stripped x86-64 files), so a hostile object of a very large code would otherwise keep the object's whole graph to its end and the ledger would refuse the signing of
 * the functions after it: a bound of COST that deleted evidence (rule 4). At the bound a frame is not kept: `kgenome_frame_get` answers NULL and `kgenome_frame_of_extent` makes the frame for
 * the one use, as it was before a cache existed; the bound's hits are counted (`kgenome_frame_cache_refused`) and cost time, never an answer.
 */
#define KGENOME_FRAME_CACHE_MAX (64ull << 20)
struct kgenome_frame_cache *kgenome_frame_cache_new(const struct kgenome_cfg_mem *mem, uint64_t max_bytes);
const struct kgenome_frame *kgenome_frame_get(struct kgenome_frame_cache *c, const struct kgenome_frame_src *s, uint32_t fi);   /* NULL too at the cache's bound */
/* The frame of the function that starts at `off` with length `len` when it is an entry of the table (the cache's), else made once and NOT kept: `*own` holds it
 * (the caller releases it), and the return is `own`. NULL when nothing could be allocated. */
const struct kgenome_frame *kgenome_frame_of_extent(struct kgenome_frame_cache *c, const struct kgenome_frame_src *s, uint64_t off, uint64_t len,
						    struct kgenome_frame *own);
/* Frames made / answered from the cache: the statistics of the product, read by the tests that say "built once". */
uint32_t kgenome_frame_cache_built(const struct kgenome_frame_cache *c);
uint32_t kgenome_frame_cache_hits(const struct kgenome_frame_cache *c);
/* Frames the cache did not keep because it was at its bound (the caller made them for the one use). */
uint32_t kgenome_frame_cache_refused(const struct kgenome_frame_cache *c);
/* Bytes the cache's frames hold (the ledger's charge for them). */
uint64_t kgenome_frame_cache_bytes(const struct kgenome_frame_cache *c);
void kgenome_frame_cache_free(struct kgenome_frame_cache *c);

#endif /* KGENOME_FRAME_H */
