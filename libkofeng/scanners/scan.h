/*
 * scan.h - scan one object.
 *
 * This is the leaf of the scan tree and the only place a module is ever entered. It
 * takes bytes, never a path: producing bytes - from a file now, from a descriptor,
 * memory or a decompressor later - belongs to whatever calls this.
 *
 * All mutable state lives in kof_scanner, one per thread, and the engine it points
 * at is immutable. That split is what makes the expensive parts affordable: the
 * presence table is 32MB, so it is allocated once per thread and reused for every
 * object, not per file and not per module.
 */

#ifndef KOFENG_SCAN_H
#define KOFENG_SCAN_H

#include "objsrc.h"
#include "../kofeng.h"
#include "../databases/dbloader.h"
#include "../detector/matchers/kofmatch.h"
#include "../detector/matchers/kofplague.h"
#include "../detector/overlord/kofoverlord.h"
#include "../analyzer/parsers/binaries/elf_parse.h"
#include "../analyzer/parsers/binaries/pe_parse.h"
#include "../extractor/unpack/pe_rebuild.h"
#include "../analyzer/parsers/containers/gzip_parse.h"
#include "../analyzer/parsers/containers/docole_parse.h"
#include "../analyzer/parsers/containers/zip_parse.h"
#include "../analyzer/parsers/containers/tar_parse.h"
#include "../analyzer/parsers/containers/sevenzip_parse.h"
#include "../analyzer/parsers/containers/rar_parse.h"
#include "../analyzer/parsers/containers/xz_parse.h"
#include "../analyzer/parsers/containers/rtf_parse.h"
#include "../analyzer/parsers/containers/pdf_parse.h"
#include "objsrc.h"
#include "../extractor/decomp/inflate.h"
#include "../extractor/decomp/textcode.h"
#include "../extractor/decomp/lzw.h"
#include "../extractor/decomp/bzip2.h"
#include "../extractor/decomp/lzx.h"
#include "../extractor/decomp/lzhuf.h"
#include "../extractor/decomp/nrv2.h"
#include "../extractor/decomp/lzma.h"

/*
 * Everything mutable, one per thread.
 *
 * The engine it points at is immutable and shared. Splitting them is what keeps the
 * 32MB presence table out of the per-file path: it belongs to the thread, is allocated
 * once, and is reused for every object.
 */
struct kof_flow_set;   /* scanners/objctx.c - the swept call chains */

/*
 * "This child is raw, and I mean it" - see pend_fmt below. Out of the range of
 * enum kof_format on purpose: it is a declaration, not a format, and identify
 * turns it back into KOF_FMT_UNKNOWN once it has skipped the sniff.
 */
#define KOF_FMT_DECLARED_RAW 0xffu

struct kof_scanner {
	const struct kof_engine *eng;

	struct kof_match_ctx m;
	/*
	 * The similarity counters, one set per thread.
	 *
	 * Beside the pattern matcher's state and for the same reason: the index
	 * they count against belongs to the engine and is shared, and only the
	 * counting is per object. Empty when no loaded block exists, which is
	 * what keeps a build with no plague rules from allocating anything.
	 */
	struct kof_plague_ctx plague;
	/*
	 * THIS OBJECT'S OWN OVERLORD DESCRIPTOR, for kof_ovl_blocks.
	 *
	 * Built once per object in the same prepass the plague feed runs in,
	 * and only when some loaded module could ask - see ovl_wanted. A
	 * pointer because the descriptor carries a four-thousand entry pool and
	 * a scanner that never meets an ELF should not hold one.
	 */
	struct kof_ovl_desc *ovl;
	/*
	 * AND THE OBJECT'S CALL CHAINS, swept once and shared by every rule
	 * that asks - see kof_content.ovl_chain. A sweep costs a pass over the
	 * code regions with a decoder, so the first ask pays for it and the
	 * rest do not.
	 */
	struct kof_flow_set *fchain;
	int                  ovl_ready;
	int                  fchain_ready;

	/*
	 * AND THE TWO BATCHED PASSES, ON THE SAME TERMS AS THE TWO ABOVE.
	 *
	 * The multi-pattern sweep and the similarity feed used to run at the
	 * top of scan_object for every object, before the first module was
	 * asked anything. That is the right cost when the modules that need
	 * them are going to run - and the wrong one the moment anything can
	 * end the scan of an object early, because the most expensive work was
	 * already done by then and no verdict could ever avoid it.
	 *
	 * So they are demand-driven now, like the overlord descriptor and the
	 * call chains: the first module that DECLARES markers pays for the
	 * sweep, the first that declares blocks pays for the feed, and an
	 * object whose verdict came from a module declaring neither pays for
	 * neither. Measured on 5248 real ELF samples, 167 objects reached the
	 * end of the module loop with no marker-carrying detector surviving the
	 * prefilter at all: 25 MB swept for nobody.
	 *
	 * WHAT A MODULE DECLARES IS THE TEST, not what it does, because that is
	 * the thing the loader knows without running anything - see
	 * kof_module.n_str and n_block. A module with no markers has nothing to
	 * look up: the sweep sizes its own tables from exactly this count (see
	 * multi_prepass), so a module that could search without declaring would
	 * already be mis-sized today.
	 *
	 * Reset per object beside every other per-object fact. kof_plague_begin
	 * is NOT deferred with the feed - it is a generation bump, O(1), and
	 * leaving it eager is what keeps a block from reading the last object's
	 * answer when this object never fed anything.
	 */
	int                  multi_ready;
	int                  plague_ready;
	/* What regions this object has, worked out once in scan_object and kept
	 * because the deferred passes above need it at a point where only the
	 * scanner is still in scope. */
	uint32_t             cur_present;
	/* And whether this object came out of a packer, which the feed reads
	 * for the same reason and cannot recover on its own. */
	uint8_t              cur_from_packer;
	/*
	 * THE HEURISTIC LEVEL THIS SCAN ASKED FOR, as kof_scan_option spells
	 * it: 0 when heuristics are off, otherwise 1 and up.
	 *
	 * Kept here because the two most expensive similarity measures are
	 * gated on it and the content hooks that answer them have no option
	 * to read - see c_ovl_blocks and c_ovl_chain. Set once per object,
	 * beside the two ready flags and for the same reason.
	 */
	uint32_t             heur_lvl;
	/*
	 * WHETHER A SIMILARITY MEASURE ANSWERED, and with what.
	 *
	 * The same pair of facts plague_asked and plague_hit are, for the
	 * measures that carry a reference in the module's own rodata rather
	 * than a declared block - kof_ovl_blocks, kof_ovl_chain,
	 * kof_ovl_shape. A verdict reached through one of
	 * those is named for it, exactly as a plague verdict is, so a reader
	 * of the name knows what recognised the object.
	 *
	 * The HIGHEST answer, not the last: a rule may ask twice, and what
	 * the reader wants is the measurement the verdict could have rested
	 * on. -1 until something asks.
	 */
	/*
	 * A MODULE OFFERED TO REPAIR THIS OBJECT, and where it says the
	 * damage starts - see kof_content.cure_offer.
	 *
	 * Recorded and not acted on here: what a scan does with an offer is
	 * the caller's, and a scan that repaired files because it could would
	 * be a scan nobody could run twice.
	 */
	int                  cure_have;
	uint64_t             cure_at;
	/*
	 * AND WHAT THE CURE ASKED FOR, collected and not applied.
	 *
	 * A repair rewrites somebody's binary; a scan that did that because
	 * it could would be a scan nobody could run twice. So the requests
	 * are gathered here and the caller decides - see kof_content's
	 * cure_patch and cure_truncate.
	 *
	 * SIXTY-FOUR, and eight was the first guess. Putting an entry point
	 * back is one patch of four, which is what eight was sized for - but
	 * a repair that cuts a run out of an ELF then has to move every
	 * section and segment offset that pointed past the cut, and there are
	 * twenty-six sections in the sample this was measured on. A cap below
	 * what the format needs is a cap that makes correct repairs
	 * impossible to express.
	 */
	struct {
		uint64_t off;
		uint32_t n;
		uint8_t  b[16];
	}                    cure_fix[64];
	uint32_t             n_cure_fix;
	uint64_t             cure_trunc;
	int                  cure_trunc_set;
	int                  ovl_asked;
	uint32_t             ovl_pct;
	/*
	 * THE HIGHEST PLAGUE SCORE THE MODULE BEING RUN HAS ASKED ABOUT.
	 *
	 * A similarity verdict is a MEASUREMENT, and the name it is reported
	 * under should carry it: "Botnet:Mirai#83!Plague" says how alike the
	 * sample was, which is the one thing a reader of such a verdict needs
	 * and the one thing a hand-written variant cannot know. Recorded where
	 * it is produced - see c_plague_score - because nothing downstream can
	 * work out afterwards which block a rule looked at, or whether it
	 * looked at one at all.
	 *
	 * Reset per module, not per object: two rules on one object are two
	 * verdicts, each naming what IT measured. -1 is "this module has not
	 * asked", which is what keeps every other rule's name untouched.
	 */
	int plague_asked;
	/*
	 * AND WHICH BLOCKS THOSE WERE - ALL OF THEM, not the best one.
	 *
	 * Two rules of one family reported the same thing - the family and a
	 * percentage - so a reader could not tell which of them fired or which
	 * block did it. The block's name is the fold of its hashes, which is
	 * exactly what the source writes after blk_, so a verdict can be taken
	 * back to the line that produced it.
	 *
	 * A CONDITION MAY NAME SEVERAL. "block A and block B" is one verdict
	 * about the pair: naming it after whichever scored highest described a
	 * part of the rule and left the other part unmentioned, and two rules
	 * sharing that one block reported the same name. So every block the
	 * module asked about is kept, and the verdict is named after the SET -
	 * see kof_plague_name_of, which sorts them so the order a C expression
	 * evaluated them in cannot change the answer.
	 *
	 * The score is the set's too: `hit` and `tot` are matched hashes and
	 * declared hashes summed over these blocks, so the percentage says how
	 * much of what the rule is made of is in this object. A block asked
	 * about twice is counted once - see c_plague_score.
	 */
	uint32_t plague_blk[KOF_PLAGUE_NAME_MAX];
	uint32_t n_plague_blk;
	uint32_t plague_hit;
	uint32_t plague_tot;
	/*
	 * AND THE BEST ANY ONE OF THEM SCORED, which is what the verdict
	 * reports.
	 *
	 * `hit` and `tot` summed over the set answer "how much of A and B is
	 * here", and that is the rule's question only when the rule demanded
	 * both. A rule that accepts EITHER asks about both blocks all the same
	 * - two conditions written as separate statements do not short-circuit,
	 * and even one `||` evaluates its right side whenever its left is false
	 * - so the sum described a pair the rule had never required together.
	 *
	 * Measured on
	 * HEUR-Backdoor.Linux.Mirai.b-020fd6b946c52e68ea21a1533d6ed5f9f3b50fc1d19eef0c1fd6e8c18802505b:
	 * 26 of one block's 30 hashes and 26 of another's 128, over a rule
	 * demanding 80 of either. It reported "Plague?32" - a number belonging
	 * to neither block, and below the threshold the branch that fired had
	 * just cleared.
	 *
	 * WHICH OPERATOR IT WAS CANNOT BE SEEN FROM HERE. It lives in the
	 * module's compiled condition and all that reaches the engine is the
	 * call. So the number reported is the best single block's containment,
	 * which is the one statement that is true either way: for "either of
	 * these" it is the block that carried the verdict, and for "both of
	 * these" it is the strongest part of a rule whose every part cleared
	 * its own threshold. It is never a figure no block has and never below
	 * what the rule demanded.
	 *
	 * THE NAME IS STILL THE SET'S - see kof_plague_name_of. What a rule is
	 * made of and how much of it is here are two different questions, and
	 * naming after the best block alone made two rules sharing that block
	 * report the same thing.
	 */
	uint32_t plague_best;
	/*
	 * One parsed view per format, allocated the first time an object of that
	 * format is seen and kept for the life of the scanner.
	 *
	 * Not all of them up front: a view is kilobytes, and a scanner on a Linux
	 * host never meets a PE, so allocating every format's view would make the
	 * cost of supporting a format something every scanner pays whether or not
	 * it ever meets one. Not per object either, which is what this was avoiding
	 * in the first place - that puts a malloc of kilobytes in the hot path for
	 * every file.
	 *
	 * Indexed by enum kof_format, so adding a format adds a table row and no
	 * field here.
	 */
	/*
	 * Indexed by TARGET VALUE, not by file-format count. Event targets are
	 * numbered above the file formats - KOF_EVT_AMSI is 19 - so a table
	 * sized by KOF_FMT_COUNT would be written past by the first event
	 * scanned.
	 */
	void *view[KOF_TARGET_COUNT];

	/* Set while a module runs: find_str is called from inside one, and the ids it
	 * passes are module local, so the host has to know whose they are. */
	const struct kof_module *cur_mod;

	/*
	 * Where a region resolve puts its extents.
	 *
	 * Here rather than on the stack of whoever asks, because KOF_SCAN_MAX_EXTENTS
	 * is sized for an archive whose regions come apart into thousands of runs -
	 * and a buffer that size in every frame that resolves a region is a stack
	 * cost paid on every object to hold the worst archive anyone has seen.
	 *
	 * Two, not one, and they are never live at the same moment for the same
	 * reason: `ext` answers a search, `ext_gather` feeds a copy, and a module doing
	 * one is not doing the other. Kept apart anyway, because the day one calls the
	 * other the failure would be silent.
	 */
	struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	struct kof_range ext_gather[KOF_SCAN_MAX_EXTENTS];

	/* What the running module reported. A module cannot hold state, so a finding
	 * has to land here. */
	uint32_t rep_level, rep_name_id;
	int      rep_valid;

	/*
	 * PRODUCING CHILDREN
	 *
	 * Set only while an unpacker runs. `cur_src` is the object it is unpacking,
	 * which a window child has to reference so the parent's mapping outlives
	 * it; `kids` collects what it produced, and the caller drains that once the
	 * module has returned.
	 *
	 * Collected rather than scanned as they arrive: a child cannot be scanned
	 * while its parent's parsed view is live, because there is one view per
	 * format per scanner and the child's parse would overwrite the parent's.
	 * Draining afterwards keeps exactly one view of each format in use and
	 * keeps the object tree off the C stack.
	 */
	struct kof_objsrc  *cur_src;
	struct kof_objsrc **kids;
	/*
	 * Per child: was it produced by an EXECUTABLE PACKER rather than by a
	 * container. Parallel to `kids` because it is a property of the child's
	 * provenance and has to travel with it onto the work list, where the
	 * module that made it is long out of scope.
	 */
	uint8_t            *kid_packer;
	/*
	 * The family the producing unpacker DECODES, per child, or NULL.
	 *
	 * A pointer into a pack mapping (kof_db_family), which outlives the
	 * scan, so it is safe to keep. It is what lets a child inherit its
	 * parent's family as a prediction: an intermediate layer msf_xor peeled
	 * is formatless, so no heuristic fires on it and it would otherwise lose
	 * the Meterp guess its parent carried - and with it the family-first
	 * fast path. See the push loop in the walk.
	 */
	const char        **kid_family;
	uint32_t            n_kids, cap_kids;

	/*
	 * WHICH OF THIS OBJECT'S FINDINGS SURVIVE IT OPENING.
	 *
	 * One bit per slot in kof_result.v, set when a heuristic rule that
	 * declared KOF_ENG_KEEP_ON_OPEN appended one. Read once, by the drop
	 * beside the n_kids test in scan_one.
	 *
	 * A mask and not a flag on the finding: struct kof_finding is the
	 * public result ABI, every host copies it by value, and this is a fact
	 * about how the scan reached the finding rather than about the finding
	 * - no reader of a result would ever have a use for it.
	 *
	 * KOF_MAX_FINDINGS is 16, so a uint32 covers every slot with room to
	 * spare; a finding past the cap is counted and never stored, so there
	 * is no bit for it to need.
	 */
	uint32_t            heur_keep;

	/*
	 * Did a packer open THIS object.
	 *
	 * The fact belongs to the file that was packed, not to what came out of
	 * it - and that is the bug it exists to fix. "Packed" used to be derived
	 * from an object's depth, which credits it to the CHILD: the packed file
	 * itself, sitting at depth 0, was never scored for being packed, and the
	 * child that got the credit is by construction the clean-looking program
	 * the packer was hiding.
	 *
	 * Cleared per object in unpack_object, read by heur_object after it.
	 */
	int                 packed_here;

	/*
	 * Set while the emulator stage runs, and read where children are
	 * recorded. What that stage produces is a packer's payload by
	 * definition - it is memory a program wrote before running it - but no
	 * module made it, so the usual test on `cur_mod` would file it as a
	 * container entry and lose the distinction downstream.
	 */
	int                 emu_stage;

	/*
	 * What the next child produced should be called, already sanitised.
	 *
	 * Held here rather than passed to each producer because there are two ways to
	 * make a child and a module names them the same way whichever it uses. Cleared
	 * as it is consumed, and cleared when a module returns, so a name set for a
	 * child that never appeared cannot drift onto the following one.
	 */
	char pend_label[KOF_SRC_LABEL_MAX];
	/*
	 * How long it is, rather than where its first NUL is.
	 *
	 * A name is a range of the object and the object chooses its bytes, so a NUL
	 * inside one is the file's business and not a terminator. A compound file
	 * puts one after every character - its names are UTF-16 - and measuring with
	 * strlen turned "ThisDocument" into "T".
	 */
	uint32_t pend_label_len;
	/*
	 * And what the next child IS, declared by whatever is about to produce
	 * it.
	 *
	 * KOF_FMT_DECLARED_RAW IS HOW "RAW" IS SAID, because KOF_FMT_UNKNOWN
	 * cannot say it. That constant is 0, and 0 is also what this field
	 * holds when nobody declared anything - so "this child is a run of
	 * bytes and must not be sniffed" and "no claim was made" were the same
	 * value, and the first of the two was unsayable.
	 *
	 * It mattered for exactly one producer and it mattered a lot. The
	 * normalised view of an ELF still begins \x7fELF, so with no way to
	 * say otherwise it was sniffed back into an ELF, parsed against
	 * headers that no longer describe it, and reported as a damaged one:
	 * gawk's view came back ELF-other/Heur:Appended, which is a finding
	 * about the normaliser.
	 *
	 * HOST SIDE ONLY. A module still says KOF_FMT_UNKNOWN to mean "I will
	 * not name this one" - see c_child_format - and that reading is
	 * unchanged. This value is out of the range of enum kof_format and no
	 * module can produce it. Consumed by kid_push exactly as the label is, and for the same
	 * reason: a claim that outlived its child would be attached to the next
	 * one, which is the one way this could name the wrong object.
	 */
	uint8_t  pend_fmt;
	/*
	 * HOW MANY OF n_kids ARE VIEWS RATHER THAN PAYLOADS.
	 *
	 * "This object produced children" is read as "something came out of it,
	 * so a rule that guessed at what it was has been answered by the thing
	 * itself" - and on that reading every rule heuristic on the object is
	 * withdrawn. See where out->v is filtered in scan.c.
	 *
	 * A normalised view breaks that reading. Nothing came out of the
	 * object; the same object was written down again more plainly. Counting
	 * it withdrew findings that were correct, and it did so on almost every
	 * binary, because a view is made for any executable of 4 KB or more
	 * with a long zero run in it. Measured as a silent detection loss: an
	 * ELF of the exact shape Heur:Shellcode exists for reported it at 176
	 * bytes and said nothing at 4216, with no difference between the two
	 * but the view.
	 *
	 * Counted rather than flagged because a view is still a child in every
	 * other respect - it is scanned, it is budgeted, it is freed - and only
	 * this one question needs to tell them apart.
	 */
	uint32_t n_views;

	/*
	 * And how many are CARVED - a payload found by searching, not a
	 * rendering and not an unpacking.
	 *
	 * The analysis steps stop at the first one that produces a child,
	 * because a child usually replaces its parent as the subject. A carve
	 * does not: nothing declared that an ELF is carrying a file, so the
	 * host is a whole program that happens to have something glued to it
	 * and is still worth every later step. Counted out for the same reason
	 * n_views is - see KOF_UNP_CARVE.
	 */
	uint32_t n_carved;

	/*
	 * The declared region table of the object being scanned, if it has one.
	 *
	 * Held on the scanner because a resolver is reached through ctx and ctx
	 * carries no room of its own - the same route every other host accessor
	 * takes. Filled from the source at the top of scan_object and empty for
	 * every object that was identified rather than declared.
	 */
	struct kof_src_region cur_rgn[KOF_SRC_MAX_REGIONS];
	uint32_t              n_cur_rgn;
	uint8_t               cur_rgn_fmt;
	/* Whether the object being scanned is a rendering - see
	 * kof_src_declare_view. */
	uint8_t               cur_is_view;

	/*
	 * WHICH BYTES OF THIS OBJECT ARE THE STATIC LIBRARY'S, WORKED OUT ONCE.
	 *
	 * At the top of scan_object, beside the parse that it needs and that
	 * every reader of it would otherwise have to wait for anyway - so it is
	 * a FACT ABOUT THE OBJECT, like its format or its regions, and not a
	 * question each consumer asks for itself.
	 *
	 * It was the second kind. The normaliser worked it out to decide what
	 * to leave out of the view, the block builder worked it out again to
	 * decide which side of enum kof_plague_side each block was on, and
	 * kofoverlord a third time - three walks of the same bytes, three
	 * places for the answer to differ, and no way for a reader to see one
	 * answer and know the others matched it.
	 *
	 * Empty for anything that is not an ELF, and for a VIEW, whose headers
	 * describe the file its parent was: kof_lib_find reads segment offsets,
	 * and on a view they point at bytes that have moved.
	 */
	struct kof_lib_all    cur_lib;
	uint8_t               cur_lib_ok;

	/* And what the NEXT child's regions are, spent by kid_push exactly as
	 * pend_fmt is and cleared there whatever happens to the child. */
	struct kof_src_region pend_rgn[KOF_SRC_MAX_REGIONS];
	uint32_t              n_pend_rgn;
	uint8_t               pend_rgn_fmt;
	/* And whether the next child is one. Spent by kid_push like the rest. */
	uint8_t               pend_view;

	/*
	 * AND THE SYMBOL RECORDS THE NEXT CHILD IS TO BE READ WITH.
	 *
	 * A rendering cannot build its own - its headers describe the file
	 * before the transform - so the producer hands them over with the
	 * bytes, exactly as it hands over the region table. Spent by kid_push
	 * and cleared there whatever becomes of the child, so a block made for
	 * one view can never be attached to the next.
	 *
	 * Heap, because KOF_SYM_MAX_BYTES is a quarter of a megabyte and this
	 * is a scanner that runs one per thread; allocated the first time
	 * anything renders and kept for the rest of the scan.
	 */
	uint8_t              *pend_syms;
	uint32_t              n_pend_syms;
	/* And what it is for, which is also its name when nothing named it. */
	uint32_t pend_kind;
	/* And which entry it is the content of, or KOF_ENTRY_NONE. */
	uint32_t pend_entry;

	/* The object being emitted, before it becomes a child. Heap while it is
	 * small, an unnamed temporary file once it is not - see objsrc.h. */
	uint8_t  *sink_mem;
	size_t    sink_len, sink_cap;
	int       sink_fd;
	uint64_t  sink_spilled;   /* bytes already written to sink_fd */

	/*
	 * What is left of the produced-bytes budget for this top level object, and
	 * whether it ran out. Charged across the whole tree, not per child.
	 */
	uint64_t budget;        /* total bytes this tree may still produce */
	uint32_t kids_left;

	/*
	 * Produced bytes alive right now: the object being emitted, plus every
	 * child that has been produced and not yet finished with. This is the
	 * number the 128MB ceiling is about, and the only one that bounds memory -
	 * `budget` bounds work over time and would allow any amount of it at once.
	 */
	uint64_t resident, resident_max;

	/*
	 * The most one produced object may hold. Past it the object is closed with
	 * what it has and the rest of that entry is dropped - see KOF_OBJ_CAP.
	 * Never above resident_max, or the cap could not be reached.
	 */
	uint64_t obj_cap;

	/*
	 * The DEFLATE decoder, allocated the first time one is needed.
	 *
	 * 32KB of sliding window, and it is per thread rather than per stream for
	 * the same reason the parsed views are: an archive of a thousand entries
	 * would otherwise be a thousand allocations of it, and a scanner that never
	 * meets a compressed file never pays for it at all. Nothing carries over
	 * between streams - kof_inflate resets every field, including zeroing the
	 * window, which is what keeps one entry's bytes out of the next.
	 */
	struct kof_inflate *inf;
	/* 20KB of dictionary, allocated on the first LZW stream and reused for
	 * the rest - the same treatment `inf` gets, and for the same reason:
	 * most scans never meet one. */
	struct kof_lzw     *lzw;
	/*
	 * And 3.7MB for bzip2, on the same terms - allocated when the first
	 * stream needs it and never per stream.
	 *
	 * It is two orders of magnitude larger than the other two, and that is
	 * the format rather than a choice: the last stage is a permutation of a
	 * whole block, so the block and a link per byte have to exist at once
	 * before any of it can be produced. A scan that never meets a .bz2 pays
	 * nothing, which is what makes the size affordable.
	 */
	struct kof_bunzip  *bz;
	/*
	 * And 2.1MB for LZX, on the same terms.
	 *
	 * The size is the window: the format allows 2MB of it, a help file is
	 * free to say so, and the window has to exist before the first match
	 * can be copied out of it. Sizing it to the stream is not open either -
	 * the width comes from the container, so a scanner would be
	 * reallocating whenever a cabinet and a help file disagreed.
	 */
	struct kof_lzx     *lzx;
	/*
	 * And 90KB for LHA's and ARJ's coding, on the same terms: a dictionary
	 * wide enough for the largest variant, plus its three decoding tables.
	 */
	struct kof_lzhuf   *lzh;

	/*
	 * Where notes go, when anybody wants them.
	 *
	 * NULL in every scan that did not ask, which is every scan that is not
	 * somebody debugging a module - so the cost of a module leaving its notes
	 * in is one NULL test at the call.
	 */
	kof_on_debug debug_cb;
	void        *debug_user;

	/*
	 * Why this object was not finished, or zero. The FIRST reason recorded is
	 * kept: whatever stopped things first is what explains everything after it,
	 * and a budget running out because a decoder had already given up is not
	 * news about the budget.
	 */
	uint32_t broken;
	/*
	 * Production has stopped, which only a LIMIT causes.
	 *
	 * Separate from `broken` because the two answer different questions: broken
	 * is what the caller is told about this object, stop is whether there is any
	 * point continuing. Damage is worth reporting and worth carrying on from.
	 */
	uint32_t stop;

	/*
	 * A RULE ASKED FOR EVERYTHING THIS OBJECT CARRIES TO BE OPENED.
	 *
	 * KOF_ENG_OPEN_CARRIED, read off the findings of the object about to be
	 * opened - see the bit in kofmod/heur.h and fmt_wanted in kofmod/kofsig.h.
	 *
	 * PER OBJECT, and set from unpack_object's own `want` parameter rather
	 * than accumulated: the value comes from the EXAMINE pass of this
	 * object, so there is no path by which one document's evidence raises
	 * the next document's policy. Set in the same block that clears `stop`
	 * and for the same reason - before any early return, so a refusal
	 * cannot leave the previous object's answer standing.
	 */
	int      raise_carried;

	/*
	 * THE OBJECT'S SYMBOL RECORDS, built at most once per object.
	 *
	 * Lazily: most objects are never asked, and the block is up to a quarter
	 * megabyte, so building it for every object would be a walk of the
	 * symbol table nothing reads. Allocated once for the scanner and reused
	 * across objects rather than per object - the size is fixed by the cap,
	 * so there is nothing to gain by freeing and taking it again.
	 *
	 * `sym_done` is what makes it once-per-object rather than once-per-ask:
	 * a file with no symbols must not be re-walked by every module that
	 * asks, and "built, and the answer was nothing" has to be
	 * distinguishable from "not built yet".
	 */
	uint8_t  *sym;
	uint32_t  sym_n;
	uint8_t   sym_done;
	/*
	 * WHAT THE CODE DOES WITH EACH DATA ADDRESS, swept once for the same
	 * reason the symbol block is built once: the sweep costs a decode per
	 * instruction, and every module that asks would otherwise pay for it
	 * again. `use_done` separates "swept, and it named nothing" from "not
	 * swept yet", exactly as sym_done does.
	 */
	struct kof_xref *use;
	uint8_t            use_done;
	/*
	 * A SECOND MATCHER, BOUND TO THAT BLOCK.
	 *
	 * `m` is bound to the object's bytes, and the block is not in the
	 * object - so a search scoped to KOF_SCAN_SYM_IMP has a different
	 * buffer to run over and cannot borrow it. Everything else is the same
	 * machinery, which is the point: the extents of one half of the block
	 * are a kof_range list like any other, so the matcher answers them the
	 * way it answers a region.
	 *
	 * Initialised with NO presence table and NO memo. Both exist to make a
	 * database-sized number of searches over a file-sized buffer
	 * affordable, and this buffer is at most a quarter megabyte and usually
	 * a few kilobytes - building a 32MB table to avoid scanning it would
	 * cost more than every search it could ever save.
	 */
	struct kof_match_ctx msym;
	uint8_t   msym_bound;       /* bound to the block built for THIS object */

	/*
	 * HOW MANY MARKERS ARE LIVE ON EACH REGION, FOR THIS OBJECT.
	 *
	 * Refilled per object from the modules the preconditions left, and read
	 * by the multi-pattern prepass to decide whether a region is worth one
	 * pass. One counter per region bit - tens of bytes, not a table.
	 *
	 * `found` is the other half: one word per marker in the database, where
	 * bit b says that marker was seen in region b. The sweeps fill it and
	 * the fold reads it, which is what lets a mask naming CODE|DATA be
	 * answered by an OR instead of a second pass over the bytes.
	 *
	 * NULL when the allocation failed, and that is not an error: no counts
	 * and no record means no sweep, which is the behaviour this engine had
	 * before there was one.
	 */
	uint32_t *live;
	uint32_t *found;
	/*
	 * THE TWO HALVES' EXTENTS, BUILT AT MOST ONCE PER OBJECT.
	 *
	 * Which records are imports and which are exports is a property of the
	 * OBJECT, not of the pattern being looked for - so building the list
	 * inside every search was a walk of every record per marker, and a
	 * database with two hundred symbol-scoped markers paid it two hundred
	 * times over for one unchanging answer.
	 *
	 * Allocated on the first symbol search a scanner ever does, and kept:
	 * two lists at the extent cap is 128KB against the presence table's
	 * 32MB, and a scanner that never meets a symbol range never takes it.
	 */
	struct kof_range *sym_ext[2];
	uint32_t  sym_ext_n[2];
	uint8_t   sym_ext_done[2];

	struct kof_stats st;
};

/* Give a top level object its budget. Children inherit what is left. */
void kof_scan_budget(struct kof_scanner *, uint64_t obj_size,
		     const struct kof_scan_option *);

/* Release anything a module left half-produced, and hand back what it finished. */
void kof_scan_kids_reset(struct kof_scanner *);


struct kof_scanner *kof_scan_new(const struct kof_engine *);
void                 kof_scan_free(struct kof_scanner *);

const struct kof_stats *kof_scan_stats(const struct kof_scanner *);

/*
 * Present an object to a module: fills in every field a module can reach.
 *
 * Defined in objctx.c, which is the whole untrusted boundary - every entry bounds
 * checks, and nothing else in the tree lets module code near memory.
 */
void kof_mod_attach(struct kof_obj_ctx *, struct kof_scanner *);

/* Swap the producing surface in for the length of one unpacker, and out again. */
void kof_mod_unpack_mode(struct kof_obj_ctx *, int on);

/*
 * THE LAST RESORT: run the object and keep what it writes.
 *
 * Entered when every module that could have opened this object has run and none
 * of them did, and the gate in emu_unpack.h says the object either hides its
 * code behind something dense or cannot be loaded as written. `force` skips the
 * gate, for a caller who has asked for this object specifically rather than
 * scanned a tree.
 * Lives here rather than in scan.c because producing a child is this file's
 * business - the same ceilings, the same sink, the same accounting.
 *
 * Returns non-zero if it ATTEMPTED the object - which is not the same as
 * having produced anything from it. The difference is what lets a refusal be
 * reported: "the entry point is not in this file" is a fact about the object,
 * and an object nobody tried to open must not carry it, while an object that
 * was tried and could not be opened must.
 */
uint32_t kof_scan_emu_unpack(const struct kof_obj_ctx *ctx, int force);

/*
 * The script in the form a signature should be written on, handed over as ONE
 * child: how it was typed taken out of it, and with `deep` what it builds out
 * of its own literals built first. Answers the child's length, or 0 when there
 * was nothing worth a child. See the note over the definition.
 */
uint32_t kof_scan_script_forms(const struct kof_obj_ctx *ctx, int deep);


/* Turn a named range into extents. objctx.c needs it; the parse is what knows. */
uint32_t kof_scan_resolve_range(const struct kof_obj_ctx *, uint32_t scan_mask,
				struct kof_range *ext);

/* Recover the scanner from a context handed to a module. */
struct kof_scanner *kof_scan_of(const struct kof_obj_ctx *);

/*
 * Scan whatever a path names. Returns the number of objects scanned or a KOF_ERR_*.
 * The facade in kofeng.c is the only intended caller.
 */
int kof_scan_walk(struct kof_scanner *, const char *path,
		  const struct kof_scan_option *, kof_on_object cb, void *user);

/*
 * The same walk, spread over several scanners.
 *
 * One thread finds the files and the rest scan them, which is the split the
 * shape of the work already had: enumerating a directory is a syscall per entry
 * and scanning a file is a pass over its bytes, and only the second one is worth
 * a core. Measured over 12.9GB, a scan is 71% memmem and 100% of one core, so
 * the ceiling on a single thread is the one core it uses.
 *
 * The caller supplies the scanners because making one is the caller's job in
 * this API and always has been - the engine is immutable and shared, the
 * scanner is per thread. Handing in an array rather than a count keeps it that
 * way: nothing here allocates a scanner, and a caller that wants different
 * budgets per worker can set them.
 *
 * The callback is serialised, so a caller writes it exactly as it would for the
 * single threaded walk. What is NOT preserved is the ORDER objects arrive in:
 * files come back as the workers finish them. A caller that needs the old order
 * passes one scanner.
 */
int kof_scan_walk_mt(struct kof_scanner **, unsigned n_sc, const char *path,
		     const struct kof_scan_option *, kof_on_object cb, void *user);

#endif /* KOFENG_SCAN_H */