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
#include "../analyzers/parsers/binaries/disasm/kdis.h"
#include "../analyzers/parsers/binaries/elf/elf_parse.h"
#include "../extractors/unpack/pe_rebuild.h"
#include "../kofeng.h"
/* KOF_EMU_EXEC_WATCH bounds the per-object list below; the interpreter owns
 * the number because it owns the list it is copied into. */
#include "../../libkofemu/kofemu.h"
#include "../extractors/unpack/emu_unpack.h"
#include "../databases/dbloader.h"
#include "../detectors/overlord/matchers/kofmatch.h"
#include "../detectors/overlord/plague/kofplague.h"
/* KOF_NUCLEO_COUNT, for the profile below. */
#include "../detectors/overlord/kofoverlord.h"
#include "../analyzers/parsers/binaries/elf/elf_parse.h"
#include "../analyzers/parsers/binaries/pe/pe_parse.h"
#include "../extractors/unpack/pe_rebuild.h"
#include "../analyzers/parsers/containers/gzip_parse.h"
#include "../analyzers/parsers/containers/docole_parse.h"
#include "../analyzers/parsers/containers/zip_parse.h"
#include "../analyzers/parsers/containers/tar_parse.h"
#include "../analyzers/parsers/containers/sevenzip_parse.h"
#include "../analyzers/parsers/containers/rar_parse.h"
#include "../analyzers/parsers/containers/xz_parse.h"
#include "../analyzers/parsers/containers/rtf_parse.h"
#include "../analyzers/parsers/containers/pdf_parse.h"
#include "objsrc.h"
#include "../extractors/decomp/inflate.h"
#include "../extractors/decomp/textcode.h"
#include "../extractors/decomp/lzw.h"
#include "../extractors/decomp/bzip2.h"
#include "../extractors/decomp/lzx.h"
#include "../extractors/decomp/lzhuf.h"
#include "../extractors/decomp/nrv2.h"
#include "../extractors/decomp/lzma.h"

/*
 * Everything mutable, one per thread.
 *
 * The engine it points at is immutable and shared. Splitting them is what keeps the
 * 32MB presence table out of the per-file path: it belongs to the thread, is allocated
 * once, and is reused for every object.
 */
/*
 * THE SWEPT CALL CHAINS OF ONE OBJECT STOOD HERE, and the set that held
 * them, and the sweep that filled it. All of it is gone - see the note on
 * the removed macros in kofmod/kofsig.h for why a chain could not hold a
 * producer with several consumers, a step joined by control, or a rule that
 * an inserted instruction cannot shift.
 *
 * TWO THINGS THE SET GOT WRONG ARE WORTH KEEPING, because the replacement
 * has to not repeat them. It capped the RESULT at eight chains and evicted
 * the weakest by a count of distinct words - MEASURED on one bot, the chain
 * joining `pipe` to the `dup2` on it, the whole of a redirected shell, was
 * stored and then thrown away for a longer chain that listed more words and
 * joined none of them. And choosing between shapes at all is a selection the
 * engine has no business making: what replaces this stores NODES AND TYPED
 * EDGES and offers all of them.
 */

/*
 * "This child is raw, and I mean it" - see pend_fmt below. Out of the range of
 * enum kof_format on purpose: it is a declaration, not a format, and identify
 * turns it back into KOF_FMT_UNKNOWN once it has skipped the sniff.
 */
#define KOF_FMT_DECLARED_RAW 0xffu

/* Room for a module's own name - "VMProtect.PE" and the like. */
#define KOF_MOD_TAG 48

/* How many regions one run may report, and what each one is. */
/* How many interpreter runs one scan will spend, whatever asks. */
#define KOF_SCAN_EMU_MAX 512u

#define KOF_EMU_RGN_MAX 64u
#define KOF_EMU_RGN_IMAGE   0u  /* a PE or ELF a stub assembled */
#define KOF_EMU_RGN_EXEC    1u  /* memory it wrote and then made executable */
#define KOF_EMU_RGN_WRITTEN 2u  /* memory it merely wrote */

/*
 * ---- WHAT IS COMPUTED AT MOST ONCE FOR ONE OBJECT -------------------------
 *
 * Each is a result the scanner derives from the object's bytes the first time
 * something asks and then keeps, so a second rule asking the same question does
 * not pay for it twice. They used to be nine fields, each with its own spelling
 * (`_done`, `_ready`) and each cleared at a place of its own; one was never
 * cleared at all (the serialised graph, so every object after the first read the
 * FIRST object's graph block). One array, one `memset` in obj_begin, and a new
 * latch that is not listed here cannot exist - which is the point.
 *
 * A latch says "has been computed for THIS object". What it guards - a buffer, a
 * table - is released by obj_begin as well, and that is the only place.
 */
enum kof_obj_latch {
	KOF_OL_SYM,             /* the symbol block                         */
	KOF_OL_USE,             /* the address-use map of the code          */
	KOF_OL_DIAG_GATE,       /* which diagnoses' signs are present       */
	KOF_OL_DIAG,            /* the pathogen walk has run                */
	KOF_OL_RELOCS,          /* the relocation table                     */
	KOF_OL_APIHASH,         /* what a PE resolves for itself            */
	KOF_OL_GRAPH_BLOCK,     /* the graph serialised for a rule          */
	KOF_OL_MULTI,           /* the multi-pattern set is bound           */
	KOF_OL_PLAGUE,          /* the similarity set is bound              */
	KOF_OL_COUNT
};

struct kof_scanner {
	/* See enum kof_obj_latch. Cleared for every object, in obj_begin. */
	uint8_t  latch[KOF_OL_COUNT];
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
	 * THIS OBJECT'S OWN OVERLORD DESCRIPTOR, for kof_plague_blocks.
	 *
	 * Built once per object in the same prepass the plague feed runs in,
	 * and only when some loaded module could ask - see ovl_wanted. A
	 * pointer because the descriptor carries a four-thousand entry pool and
	 * a scanner that never meets an ELF should not hold one.
	 */
	/*
	 * WHICH DIAGNOSES THIS OBJECT CARRIES, worked out once.
	 *
	 * DEMAND DRIVEN, on the same terms as everything else here: reading
	 * the nodes out of an object costs a decode of its code regions, and
	 * an object whose verdict comes from a rule that names no diagnose
	 * must not pay for it. The first rule that asks pays; the rest read
	 * the answer.
	 */
	uint8_t  diag_hit[32];          /* one bit per diagnose id          */
	/*
	 * WHICH DIAGNOSES' GATES THIS OBJECT PASSES, one bit each, worked out
	 * ONCE per object for all of them - see diag_gates.
	 *
	 * It was asked per diagnose, at two places, and each ask that carried
	 * a symbol sign walked the object's whole symbol table for that one
	 * diagnose: N diagnoses cost 2N walks of the same table. The answer to
	 * "which of these objects' signs are present" is one fact about the
	 * object, so it is one walk and one bitmap.
	 */
	uint8_t  diag_gate[32];
	/*
	 * THE OBJECT'S RELOCATIONS, derived once - see struct kof_elf_relocs. The
	 * gate reads them for KOF_DIAG_REFS and the diag routes read the same table
	 * through kof_diag_scan_with_inputs; both used to walk the relocation
	 * sections themselves. Built on first need, freed with the object.
	 */
	struct kof_elf_relocs *relocs;
	/* A serving diagnose added names to sym - see sym_serve. Per object. */
	int      sym_served;
	/*
	 * WHAT THE PE RESOLVES FOR ITSELF - see struct kof_apihash. An analysis
	 * result and not a diag-route detail: the graph reads it and so does the
	 * normaliser, and whichever asks first pays for it once. Freed with the
	 * object, like the relocations.
	 */
	struct kof_apihash *apihash;
	/*
	 * WHICH NODE EACH DIAGNOSE BOUND EACH OF ITS OWN NODES TO - see
	 * kof_diag_share.
	 *
	 * A match used to be a bit and nothing else, so "both of these
	 * happened" was all a rule could ask. Two diagnoses are a SHAPE only
	 * when they meet: a W+X region filled by a read, and a socket whose
	 * descriptor that same read uses, are a stager - and the same two
	 * findings about two different reads are a packer and a downloader
	 * in one file. Only the node index tells them apart.
	 *
	 * ALL OF THEM, not the ones a diagnose marked. The mark was a fact
	 * about a pair of behaviours written into the declaration of one of
	 * them; the verdict asks for the join now, so the engine has to be
	 * able to answer about any node. 16 KB, once per scanner, bounded by
	 * the database and not by the object.
	 */
	uint16_t diag_bind[KOF_DB_MAX_DIAG][KOF_DB_MAX_DIAG_NODE];
	uint8_t  diag_n_bind[KOF_DB_MAX_DIAG];
	/* see kof_scan_option.want_diag */
	/*
	 * THE GRAPH ITSELF, kept for as long as the object is.
	 *
	 * A diagnose is a definition of WHAT TO LOOK FOR; what the analysis
	 * produces is a graph of nodes and the relations between them, and
	 * that graph - not a yes or no - is what a verdict matches on. Freed
	 * the moment matching finished, every later reader would have to ask
	 * for the whole analysis again.
	 *
	 * It is pruned to the capabilities some loaded diagnose named before
	 * it gets here, so what is held is bounded by the DATABASE and not by
	 * the object: measured, a stager's six nodes become three.
	 *
	 * Per object, and released with the other per-object state - a graph
	 * that outlived its object would answer the next one's questions
	 * about the wrong bytes.
	 */
	struct kof_diag_scan *diag_graph;
	/*
	 * And the same graph as the RECORD BLOCK a rule reads - see
	 * kofmod/kofpathogen.h. Serialised on the first ask and kept until the
	 * object ends, because every later ask reads the same bytes.
	 */
	uint8_t  *gr;
	uint32_t  gr_n;

	/*
	 * THREE FIELDS STOOD HERE and all three went with the chain: the
	 * swept reference, the flag saying the sweep had run, and the
	 * flattened profile derived from it. By the end none of them was
	 * read - one was only freed, two were only written - which is what a
	 * removed subsystem leaves behind when the state outlives the code
	 * that filled it.
	 */

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
	 * So they are demand-driven now: the first module that DECLARES markers pays for the
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
	/* What regions this object has, worked out once in scan_object and kept
	 * because the deferred passes above need it at a point where only the
	 * scanner is still in scope. */
	uint32_t             cur_present;
	/* And whether this object came out of a packer, which the feed reads
	 * for the same reason and cannot recover on its own. */
	uint8_t              cur_from_packer;
	/* And what its producer declared it needs, travelling with it the same
	 * way cur_from_packer does - the module that said it is long gone by
	 * the time the object is scanned. */
	uint32_t             cur_want, cur_want_level;
	/* Where the module that recognised this object says its program will
	 * be. Per OBJECT, not per child - see emu_watch in kofsig.h. */
	struct { uint64_t rva, len; } xw[KOF_EMU_EXEC_WATCH];
	uint32_t             n_xw;
	/* Whether the emulator has produced a child from the object in hand.
	 * Cleared per object and published in kof_result.emu_unpacked. */
	uint8_t              emu_produced;
	const char          *res_why;
	/* A run a module asked to be paused on, and the report it will be
	 * gathered with when it finishes - see `emu_resume` in kofsig.h. */
	struct kof_emu_unp_report *emu_rep_p;
	int                  emu_paused;
	/* Instruction patterns a module named before the run - see
	 * `emu_watch_insn` in kofsig.h. */
	struct kof_emu_iwatch pend_iw[KOF_EMU_INSN_WATCH];
	uint32_t             pend_n_iw;
	uint32_t             pend_iw_len;
	/*
	 * THE HEURISTIC LEVEL THIS SCAN ASKED FOR, as kof_scan_option spells
	 * it: 0 when heuristics are off, otherwise 1 and up.
	 *
	 * Kept here because the two most expensive similarity measures are
	 * gated on it and the content hooks that answer them have no option
	 * to read - see c_plague_blocks and c_pth_match. Set once per object,
	 * beside the two ready flags and for the same reason.
	 */
	uint32_t             heur_lvl;
	/*
	 * WHETHER A SIMILARITY MEASURE ANSWERED, and with what.
	 *
	 * The same pair of facts plague_asked and plague_hit are, for the
	 * measures that carry a reference in the module's own rodata rather
	 * than a declared block - kof_plague_blocks,
	 * kof_plague_shape. A verdict reached through one of
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
	/* Where a module said the infection is - see struct kof_infected. */
	struct kof_infected  infect[KOF_MAX_INFECTED];
	uint32_t             n_infect;
	/*
	 * HOW MANY INSTRUCTIONS A RUN MAY GO BEFORE HANDING CONTROL BACK.
	 *
	 * Zero means "as far as the host's ceiling allows", which is what
	 * every run did before. A module that sets it gets the machine back,
	 * alive and paused, every `emu_slice` instructions - so it can look at
	 * what has been decrypted SO FAR and stop as soon as that is enough.
	 *
	 * This is the primitive periodic scanning needs. Measured on a Sality
	 * sample: the data a cure needs is about 6 KB into a 65 KB body, so
	 * roughly a tenth of the decryption is worth 186 million instructions
	 * less than all of it.
	 */
	uint64_t             emu_slice;
	uint64_t             emu_full;   /* the host's real ceiling */
	/* The module-facing code reader's cursor - see analyzers/parsers/binaries/disasm/kdis.h.
	 * One per object, because a module walks one run of code at a time. */
	struct kof_kdis      kdis;
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
	 * AND WHETHER A DECLARED STRING OF THIS MODULE WAS FOUND, which is
	 * what says the plague residue is not the explanation.
	 *
	 * plague_asked plus plague_hit answer "was a block asked about, and
	 * did it find anything". They do not answer "is that what recognised
	 * the object", and the name claims exactly that - see the contract on
	 * the similarity fields below: a reader of the name knows what
	 * recognised it.
	 *
	 * A RULE HAS SEVERAL MATCHERS AND THEY ARE NOT ONE EXPRESSION:
	 *
	 *     if (kof_find_str_multi(code, s0..s6) >= 2 ||
	 *         kof_plague_score(blk) >= 70u)   KOF_SCAN_INFECT(...);
	 *     if (kof_find_str_any(sym_exp, s7..s13))  KOF_SCAN_INFECT(...);
	 *
	 * `||` short-circuits when its LEFT side is true, so a string that
	 * carries the first matcher keeps kof_plague_score from ever running
	 * and plague_asked stays -1. What it does not cover is the first
	 * matcher failing BOTH ways and the SECOND one firing: the block was
	 * scored, found 17 per cent of itself - far under the 70 the rule
	 * wanted, and under any threshold a rule would use - and a Gafgyt
	 * sample recognised by an exported symbol came back named
	 * "#51f88b7c!Plague?17". The number was real and the sentence it
	 * formed was false.
	 *
	 * SO: a string of this module matched, and the name belongs to the
	 * string. It costs a combined rule nothing that it had - all three
	 * mixed rules shipped are `string || plague`, where a matching string
	 * means the plague call never happened.
	 *
	 * Reset per module beside the plague fields and for the same reason.
	 */
	int str_hit;
	/*
	 * THIS MODULE READ THE NODE GRAPH - see KOF_ENGINE_PATHOGEN.
	 *
	 * Beside str_hit and reset with it, because it answers the same
	 * question about the same scope: what did THIS module use to reach
	 * its finding. The verdict's method word is that answer, and a
	 * finding reached through kof_diag printed as !Pattern sends a
	 * reader looking for bytes that were never matched.
	 *
	 * PER MODULE AND NOT PER OBJECT. Kept beside ovl_asked at first,
	 * which is per object - so one rule reading the graph relabelled
	 * another rule's byte match on the same file.
	 */
	int diag_read;
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
	/* What each child's producer declared it needs. Parallel to `kids` for
	 * the reason kid_packer is: the claim is the child's and the module
	 * that made it is out of scope by the time the child is reached. */
	uint32_t           *kid_want;
	uint32_t           *kid_want_level;
	/* One count and KOF_EMU_EXEC_WATCH (rva,len) pairs per child, flat. */
	uint32_t           *kid_n_xw;
	uint64_t           *kid_xw;
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
	/*
	 * The name the module currently running last called itself, and which
	 * module that was. Kept so a child can be stamped with its producer's
	 * own name rather than with a file path: a reader knows "MPRESS.PE",
	 * and "unp/mpress_pe.c" is this project's directory layout leaking
	 * onto their screen.
	 *
	 * `mod_tag_of` is what stops it being inherited. Without it a module
	 * that emits no debug note at all would be labelled with whatever the
	 * previous one said, which is the defect this whole field exists to
	 * remove.
	 */
	char                mod_tag[KOF_MOD_TAG];
	const struct kof_module *mod_tag_of;
	/*
	 * And which module opened THE OBJECT BEING SCANNED - see
	 * kof_result.opened_by. Set where that module produces a child,
	 * because producing one is what "opened it" means, and cleared per
	 * object beside sc->broken.
	 */
	char                opened_by[KOF_MOD_TAG];
	/*
	 * AND WHICH BUILD OF THE PACKER IT IS, as the module that recognised it
	 * said - see kof_result.packer_build. Copied rather than pointed at: a
	 * module's string lives in its blob and the answer has to outlive the
	 * call. Cleared per object, beside opened_by.
	 */
	char                packer_build[48];
	/*
	 * AND WHAT THE MODULE CURRENTLY RUNNING SAID, WHICH IS NOT THE SAME
	 * THING.
	 *
	 * Every unpacker in the database is offered every object, so several
	 * speak about one file and only one of them opens it. A build written
	 * straight through was therefore the LAST module to guess rather than
	 * the one that was right: on 111.exe, which is MPRESS, VMProtect's
	 * module ran afterwards, found no props pair, and overwrote
	 * "MPRESS 2.12-2.19 LZMA" with "VMProtect 3.9+".
	 *
	 * So a module's claim waits here and is committed where `opened_by` is
	 * - producing a child is what makes a claim about the object worth
	 * keeping. Cleared per module, like the rest of the pending set.
	 */
	char                pend_build[48];
	const struct kof_module *pend_build_of;
	/*
	 * THE MODULE THAT DERIVED THE CHILD BEING BUILT, and then the one that
	 * derived each child - see `derive` in kofsig.h.
	 *
	 * A derived object is the parent with ranges changed, so offering it
	 * back to the module that changed them is offering a module its own
	 * output. That is what the three hand-written recursion guards were
	 * for. A NEW object carries NULL here and is offered to everyone,
	 * which is what keeps a zip inside a zip working.
	 */
	/*
	 * THE SECTIONS A MODULE DECLARED FOR THE CHILD IT IS BUILDING.
	 *
	 * Allocated on first use, like every other expensive fixed-size piece
	 * of per-scan state - most objects never produce a child and no object
	 * that produces a flat payload declares one. Spent by the push, beside
	 * the region table and the symbols.
	 */
	struct kof_sec_decl      *pend_sec;
	uint32_t                  n_pend_sec;
	uint64_t                  pend_entry_rva;
	int                       pend_entry_set;
	/* Directories a module rebuilt, which override the parent's - see
	 * `child_dir` in kofsig.h. */
	struct kof_dir_decl       pend_dir[16];
	/* The child is an image laid out by those sections, and the engine
	 * writes its header - see kof_pe_write_hdr. */
	int                       pend_image;

	/*
	 * WHAT THE CHILD IMPORTS, as the producer declared it - see `import`
	 * in kofsig.h, and kof_pe_write_imports, which turns this into a real
	 * directory when the child closes.
	 *
	 * HELD HERE RATHER THAN WRITTEN AS IT ARRIVES, for the reason the
	 * sections are: a module may keep declaring until it closes the child,
	 * and the table's own size is not known until the last one is in. The
	 * pool is one blob because the strings are short and the count is
	 * bounded - 32 libraries and 512 functions is what the one module
	 * doing this meets, and a per-entry allocation for a name that averages
	 * fifteen bytes would cost more in bookkeeping than in text.
	 */
	struct kof_imp_decl      *pend_imp;
	uint32_t                  n_pend_imp;
	char                     *imp_pool;
	uint32_t                  imp_pool_n;
	uint64_t                  pend_imp_at;
	int                       pend_imp_set;

	/*
	 * WHAT A RUN LEFT BEHIND, HELD RATHER THAN HANDED OVER.
	 *
	 * The interpreter is not a producer. It gathers, and a MODULE decides
	 * what any of it is and gives that to the engine - see
	 * DESIGN-object-pipeline.md. Two reasons, and the second is the one
	 * that matters: only a module knows what a family's run means, and a
	 * component that both runs hostile code and creates objects is a wider
	 * surface than one that only runs it.
	 *
	 * `emu_live` is the machine itself, kept alive while the regions below
	 * still point into its memory, and released when the module that asked
	 * for the run returns.
	 */
	struct kof_emu           *emu_live;
	/*
	 * AND WHETHER THIS OBJECT HAS ALREADY HAD ITS RUN.
	 *
	 * The machine is released as soon as the module that asked for it
	 * returns - its regions point into the machine's memory and are not
	 * valid past that - so `emu_live` cannot double as "already run". This
	 * can. One interpretation per object: the modules after the one that
	 * drove are offered the object, not a second run of it, and a file that
	 * five modules all decline must not cost five runs.
	 *
	 * Per object, cleared beside packed_here.
	 */
	int                       emu_ran;
	/*
	 * WHETHER A MODULE SAID THIS OBJECT IS ONLY A WRAPPER - see `supersede`
	 * in kofsig.h. Per object, cleared in obj_begin; read where the walk
	 * reports an object, and ignored at the top level.
	 *
	 * SET ONLY WHEN A CHILD IS ACTUALLY PUSHED, from `pend_superseded` below:
	 * the module says "what I am about to produce is me", and a module whose
	 * child was then refused (the child cap, a failed close) produced nothing, so
	 * its object is still the thing to report.
	 */
	int                       superseded;
	int                       pend_superseded;   /* said, not yet spent */
	/*
	 * WHAT THE DECLARED IMAGE IS TO BE WRITTEN AS - see `as_format` in
	 * kofsig.h. Pending like every other declaration: set before the child
	 * is closed, cleared with the rest of the pending set. Zero `as_fmt`
	 * means "the parent's format", which is what a packer wants.
	 */
	uint8_t                   pend_as_fmt, pend_as_arch;
	/* The format of the object a declared image was built ON, kept for the
	 * region vocabulary - see decl_sec_to_regions. */
	uint8_t                   pend_img_fmt;
	uint64_t                  pend_as_base;
	/* An image a run ASSEMBLED rather than left lying in its memory - the
	 * un-mapped PE, the rebuilt ELF. It is the engine's allocation, so the
	 * engine holds it for as long as a region points at it. */
	uint8_t                  *emu_own;
	struct kof_emu_rgn {
		const uint8_t *p;
		/*
		 * WHEN THE ENGINE OWNS THOSE BYTES, AND IT USUALLY MUST.
		 *
		 * `kof_emu_next_written` hands back a buffer the emulator owns
		 * and REPLACES ON THE NEXT CALL - it says so beside itself.
		 * That was safe while the interpreter emitted each run as it
		 * walked them; it is not safe now that the regions are gathered
		 * first and handed to a module afterwards, because every
		 * pointer but the last is freed before the module ever sees it.
		 *
		 * Measured on msfvenom's `poly`: the module was handed a
		 * four-kilobyte region whose bytes had become the scanner's own
		 * section table by the time it copied them, so the child came
		 * out as a correct ELF header in front of 4012 zero bytes.
		 *
		 * So a gathered region is copied, and this is the copy to free.
		 * NULL where the bytes belong to something with a longer life -
		 * a snapshot lives in the machine and the machine outlives the
		 * module - and then `p` points into that.
		 */
		uint8_t       *own;
		uint64_t       va, n;
		uint32_t       kind;    /* KOF_EMU_RGN_* */
	}                         emu_rgn[KOF_EMU_RGN_MAX];
	uint32_t                  n_emu_rgn;

	const struct kof_module  *pend_derived_by;
	/* And the one that derived the object being SCANNED, so it can be
	 * skipped - see unp_eligible. */
	const struct kof_module  *cur_derived_by;
	const struct kof_module **kid_derived_by;
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
	/* And the language that goes with it - see kof_src_declare_lang. Spent
	 * by c_child beside pend_fmt and cleared there the same way. */
	uint8_t  pend_subtype;
	uint8_t  pend_subfam;
	uint8_t  pend_lang;
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

	/*
	 * ---- THE ONE PLACE A FILE'S VERDICT IS KEPT ----------------------
	 *
	 * One file, one verdict. The findings array is per OBJECT, and a
	 * file is many objects: itself, what unpacked out of it, the
	 * normalised view of that. Those are REPRESENTATIONS of the same
	 * bytes, not separate things that are infected, and printing one
	 * line each said `Heur:Infected` twice for one program.
	 *
	 * So the name belongs to the file, and the representations share it
	 * - which is also why the variant is the parent's: a child is the
	 * same sample decoded, and naming it separately would be naming the
	 * engine's own steps.
	 *
	 * HOW IT IS REPLACED. By rank, kverdict_level_rank: a named
	 * detection beats a rule's guess, so `Virus:Sality#Body` takes the
	 * slot a `Heur:Infected` was holding. EQUAL RANK KEEPS THE FIRST -
	 * whichever matcher the engine happened to reach first is the one
	 * that answered, and that is a question about call order rather
	 * than about naming. Under all_matches there is no interrupt, so
	 * the later one overwrites and the caller gets what it asked for.
	 *
	 * `verdict_lvl` of 0 means the slot is empty. Reset per FILE, in
	 * scan_tree, because that is the scope it belongs to.
	 */
	struct kof_finding    verdict;
	uint32_t              verdict_lvl;
	uint8_t               verdict_have;
	/* The language this object's producer declared, carried the same way
	 * cur_rgn is - see kof_src_declare_lang. */
	uint8_t               cur_subtype;
	uint8_t               cur_subfam;
	uint8_t               cur_lang;

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
	 * describe the file its parent was: kof_true_find reads segment offsets,
	 * and on a view they point at bytes that have moved.
	 */
	struct kof_true_all    cur_lib;
	uint8_t               cur_lib_ok;

	/* And what the NEXT child's regions are, spent by kid_push exactly as
	 * pend_fmt is and cleared there whatever happens to the child. */
	struct kof_src_region pend_rgn[KOF_SRC_MAX_REGIONS];
	uint32_t              n_pend_rgn;
	uint8_t               pend_rgn_fmt;
	/* And whether the next child is one. Spent by kid_push like the rest. */

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
	/* And what the producing module says has to be DONE to it, in the same
	 * KOF_ENG_* vocabulary a heuristic rule uses, with the lowest --heur
	 * level the ask is honoured at. See child_want in kofsig.h. */
	uint32_t pend_want, pend_want_level;
	/*
	 * AND THE OEP RANGES THE NEXT CHILD IS TO BE WATCHED AT.
	 *
	 * Declared by a module while the PARENT is in front of it and meant for
	 * the CHILD, so they travel the same road as pend_want: set here, spent
	 * by kid_push, handed back when that child is the object being scanned.
	 * Kept in sc->xw while it is. They used to be written straight into
	 * sc->xw, which is cleared per object - so a module declared them, the
	 * child was pushed, the clear ran, and every run saw none.
	 */
	uint32_t pend_n_xw;
	struct { uint64_t rva, len; } pend_xw[KOF_EMU_EXEC_WATCH];

	/* The object being emitted, before it becomes a child. Heap while it is
	 * small, an unnamed temporary file once it is not - see objsrc.h. */
	uint8_t  *sink_mem;
	size_t    sink_len, sink_cap;
	int       sink_fd;
	uint64_t  sink_spilled;   /* bytes already written to sink_fd */
	/*
	 * The sink is a FIXED extent - a copy of the parent, or an image laid
	 * out from declared sections - written at addresses rather than
	 * appended to. See `derive` and `image` in kofsig.h. It never spills.
	 *
	 * `sink_at` is where the next emit lands, which is what lets a
	 * decompressor write straight into a section: every decoder in the
	 * engine funnels through c_emit, so moving the cursor is all it takes
	 * and not one of them has to know.
	 */
	int       sink_fixed;
	uint64_t  sink_at;

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
	 * DID ANYTHING ASK FOR THE PATHOGEN ANALYSIS on this object - see
	 * KOF_ENG_USE_PATHOGEN. Per object and recomputed, like emu_ask: an
	 * ask that survived into the next object would be the leak the
	 * declaration exists to prevent.
	 */
	int      diag_ask;

	/*
	 * WHETHER SOMEBODY ALREADY SPOKE FOR THE INTERPRETER ON THIS OBJECT,
	 * AND WHETHER IT IS ALLOWED AT ALL.
	 *
	 * A module asks for a run with kunp_emu_run and may VOUCH for it - a
	 * family module that recognised its packer knows the run is worth
	 * paying for. The generic receiver cannot vouch, because it is on the
	 * object nobody recognised; what speaks for that object is the
	 * DATABASE, through a heuristic rule that declared KOF_ENG_USE_EMU, or
	 * through the producer that made the object and said its output needs
	 * running.
	 *
	 * Both of those are the host's knowledge and neither is reachable from
	 * a module, so they are resolved here, once, and or-ed into the
	 * module's vouch inside c_emu_run. Without this the ask was collected
	 * in unpack_object and then dropped: the entropy gate refuses a
	 * meterpreter payload for being smaller than its estimate needs, which
	 * is exactly the object the rule fires on.
	 *
	 * `emu_banned` is the other direction and is not a budget: --emu never,
	 * and the packer-depth ceiling, which no vouch may talk past.
	 *
	 * PER OBJECT, set in the same block as raise_carried and for the same
	 * reason.
	 */
	int      emu_ask;
	int      emu_banned;
	/* Whether a run nobody asked for is permitted at all - emu_use above
	 * KOF_EMU_NEVER. It gates the AUTO case and the producer's ask; a
	 * rule's ask does not read it, for the reason unpack_object gives. */
	int      emu_default_ok;
	/* KOF_EMU_ONLY - the interpreter REPLACES the packer modules, so a
	 * static unpacker having opened this object is not a refusal. */
	int      emu_only;

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
	/*
	 * WHAT THE CODE DOES WITH EACH DATA ADDRESS, swept once for the same
	 * reason the symbol block is built once: the sweep costs a decode per
	 * instruction, and every module that asks would otherwise pay for it
	 * again. `use_done` separates "swept, and it named nothing" from "not
	 * swept yet", exactly as sym_done does.
	 */
	struct kof_xref *use;
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
	 * WHICH MASKS A SWEEP CAN ANSWER FOR, THIS OBJECT.
	 *
	 * multi_prepass used to hand the answer to every marker under every
	 * answerable mask - see uid_slot in kofmultimatch.h for the measurement
	 * that made that untenable at scale. It now records only WHICH masks
	 * are answerable, and kof_multimatch_answer reads `found` when one is
	 * asked about. One byte per mask, cleared per object.
	 */
	uint8_t  *mask_ok;
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
void kof_scan_sink_discard(struct kof_scanner *);



/*
 * THE CHAIN BUILDERS STOOD HERE - one on the scanner and one for a caller
 * that had an object and no scan, so the viewer and the engine read an object
 * the same way. They are gone with the chain. What is kept from them is the
 * rule that made them one function: a second copy is what kofviewer had, and
 * it answered for two architectures while the engine read ten.
 *
 * AND THAT AN EMPTY ANSWER NEEDS A REASON. The builder returned one line
 * saying which gate it stopped at - the architecture, the bytes, the
 * regions, the partition - because a page that just says nothing tells a
 * reader nothing. Before that the reasons went to stderr behind an
 * environment variable, which is worse than nothing and is also rule 1.
 */


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
/*
 * Run the interpreter and GATHER. Answers how many regions it left; it creates
 * nothing - see kof_scan_emu_take_all and the note on kof_scanner.emu_live.
 */
uint32_t kof_scan_emu_unpack(const struct kof_obj_ctx *ctx, int force);
/* The engine's own receiver, for an object no module claimed. */
int      kof_scan_emu_take_all(const struct kof_obj_ctx *ctx);
/* What the run left, for whoever is receiving it. */
uint32_t kof_scan_emu_count(const struct kof_scanner *sc);
int      kof_scan_emu_region(const struct kof_scanner *sc, uint32_t i,
			     uint64_t *va, uint64_t *len, uint32_t *kind);
/* The machine and its regions let go - called when the receiver returns. */
void     kof_scan_emu_release(struct kof_scanner *sc);

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

/*
 * A LOADED DIAGNOSE DECLARED SIGNS THIS OBJECT CARRIES - see KOF_DIAG_WHEN
 * and KOF_DIAG_NEEDS. Non-zero means the analysis is worth starting on this
 * object, which is the routing a heuristic rule used to do by hand.
 */
int kof_scan_diag_sign_asks(const struct kof_obj_ctx *ctx);
/* The symbol block the engine completed for this object, or NULL when it added
 * nothing - see kof_result.syms. */
const uint8_t *kof_scan_served_syms(const struct kof_obj_ctx *ctx, uint32_t *n);

#endif /* KOFENG_SCAN_H */
void kof_scan_diag_force(const struct kof_obj_ctx *);
