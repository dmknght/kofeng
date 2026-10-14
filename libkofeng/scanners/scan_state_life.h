/*
 * scan_state_life.h - the scanner's state that is wiped on a schedule: per object
 * (sc->obj, by sx_obj_begin) and per module (sc->mod, by sx_mod_begin).
 *
 * Part of struct kof_scanner (scan_state.h); include scan.h, not this file.
 */

#ifndef KOFENG_SCAN_STATE_LIFE_H
#define KOFENG_SCAN_STATE_LIFE_H

#include "scan_types.h"

/*
 * sc->obj.sym
 *
 * the symbol block of ONE object
 *
 * Owner: objctx_diag.c (built on first ask), scan.c (reset). Files that touch
 * it: objctx_diag.c, scan.c, objctx.c.
 */
struct kof_scan_obj_sym {
	/* A decrypt step added names to sym - see sym_declared. Per object. */
	int served;
	uint32_t n_decl;
	uint32_t n;
	/* The functions the same symbols name, built once beside the block - see
	 * oc_funcs. */
	struct kgenome_func_set funcs;
	uint8_t bound;       /* bound to the block built for THIS object */
	uint8_t ext_done[2];
};

/*
 * sc->obj.diag
 *
 * the analysis products derived from ONE object
 *
 * Owner: objctx_diag.c builds them, objprod.c lends and takes them, scan.c
 * releases them. Files that touch it: objctx_diag.c, objctx.c, scan.c,
 * objprod.c, tests/unit/diag_ledger_e2e.c, scan_pipeline.c, scan_verdict.c,
 * scan_unpack.c.
 */
struct kof_scan_obj_diag {
	/* The scan's diagnose lines were said for this object (oc_diag_trace_scan). */
	uint8_t traced;
	/*
	 * THE OBJECT'S RELOCATIONS, derived once - see struct kgenome_elf_relocs. The
	 * gate reads them for KOF_DIAG_DECLARE_SYMBOL and the diag routes read the same table
	 * through kgenome_diag_scan_with_inputs; both used to walk the relocation
	 * sections themselves. Built on first need, freed with the object.
	 */
	struct kgenome_elf_relocs *relocs;
	/*
	 * WHAT THE PE RESOLVES FOR ITSELF - see struct kgenome_diag_apihash_set. An analysis
	 * result and not a diag-route detail: the graph reads it and so does the
	 * normaliser, and whichever asks first pays for it once. Freed with the
	 * object, like the relocations.
	 */
	struct kgenome_diag_apihash_set *apihash;
	/*
	 * THE PE'S IMPORT DIRECTORY, WALKED ONCE - see kgenome_pe_imptab. The symbol
	 * block spells it as records and the PE diagnose matches call sites
	 * against its slots; whichever asks first pays for the walk. Freed with
	 * the object.
	 */
	struct kgenome_pe_imptab pe_imp;
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
	struct kgenome_diag_scan *graph;
	/*
	 * WHAT THE GRAPH COST AND WHETHER IT IS WHOLE, read back from the lib after
	 * the scan (kgenome_diag_scan_bytes, kgenome_diag_scan_status). The bytes are
	 * charged to this scanner's own memory ceiling (`resident`) for as long as
	 * the graph lives, and given back with it - see kof_scan_diag_drop - so a
	 * child scanned while the graph is held sees the room that is really left.
	 * The status is KGENOME_OK or the worst limit a routine of the scan reached,
	 * the memory allowance included: see kof_scan_diag_status.
	 */
	uint64_t charged;
	enum kgenome_status status;
	uint32_t refused;          /* names the scan refused (kgenome_diag_scan_refused) */
	uint32_t gr_n;
	/* The code-use sweep stopped at its byte budget with code unswept - see
	 * kof_data_xref. Per object, cleared in obj_begin. */
	uint8_t use_cut;
	/*
	 * DID ANYTHING ASK FOR THE DIAGNOSE ANALYSIS on this object - see
	 * KOF_ENG_USE_DIAGNOSE. Per object and recomputed, like emu_stance: an
	 * ask that survived into the next object would be the leak the
	 * declaration exists to prevent.
	 */
	int ask;
	/*
	 * A TOOL ASKED ABOUT EVERY DIAGNOSE on this object, read by a verdict or
	 * not - see kof_scan_diag_report. Per object, like diag_ask: a scan
	 * normally runs only what a rule reads (KDIG_SEC_USERS), and a
	 * researcher looking at a file wants the answer for a diagnose nothing
	 * reads yet, which is exactly the one that is being written.
	 */
	int all;
	/* The walk of the code, decoded once for whoever needs it: the entries the
	 * functions are cut from and the wrapper resolution's sites and trace.
	 * Filled by the first reader - see oc_walk. Per object. */
	struct kgenome_diag_walk *walk;
	/*
	 * WHAT THE CODE DOES WITH EACH DATA ADDRESS, swept once for the same
	 * reason the symbol block is built once: the sweep costs a decode per
	 * instruction, and every module that asks would otherwise pay for it
	 * again. `use_done` separates "swept, and it named nothing" from "not
	 * swept yet", exactly as sym_done does.
	 */
	struct kgenome_xref *use;
};

/*
 * sc->obj.emu
 *
 * what the interpreter was asked and has done for ONE object
 *
 * Owner: objctx_emu.c, scan_unpack.c (the stance). Files that touch it:
 * objctx_emu.c, objctx_child.c, scan_unpack.c, scan.c, scan_heur.c.
 */
struct kof_scan_obj_emu {
	/* Whether the emulator has produced a child from the object in hand.
	 * Cleared per object and published in kof_result.emu_unpacked. */
	uint8_t produced;
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
	uint64_t slice;
	uint64_t full;   /* the host's real ceiling; per object */
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
	int ran;
	/* The tree's allowance of runs was spent when this object asked: said once
	 * for the object (oc_scan_limit), not once per module that asks after. */
	uint8_t refused;
	/* Instructions of this object's own unpack run already taken from the tree's
	 * allowance (oc_emu_charge): a paused run is charged for what it did since. */
	uint64_t spent;
	/*
	 * THE MODULE THAT RAN THE INTERPRETER ON THIS OBJECT, for its own turn.
	 * The one carrier for "a run produced what this module is about to push":
	 * kid_push marks such a child derived (a module is not offered its own
	 * output) and sets emu_produced, where it used to read emu_live for the
	 * second and the length of the region table for the first - two predicates
	 * for one fact, which disagreed after a resumed run. Cleared in mod_begin.
	 */
	const struct kof_module *run_by;
	/*
	 * WHAT THE INTERPRETER MAY DO ON THIS OBJECT, as ONE value.
	 *
	 * It was four ints - ask, banned, default_ok, only - every one of them
	 * recomputed per object in unpack_object and combined again in oc_emu_run,
	 * which is the same fact in two places and a way for the two to disagree.
	 * Set once by unpack_object, read by oc_emu_run, reset to BANNED by obj_begin
	 * so an object that never reached unpack_object cannot run on the previous
	 * one's answer. A module cannot see it: a module asks, the host answers.
	 */
	enum kof_emu_stance stance;
};

/*
 * sc->obj.open
 *
 * how ONE object came to exist, and whether it ran out of room
 *
 * Owner: objctx_child.c, scan_walk.c, scan_unpack.c, scan_pipeline.c,
 * scan_facts.c. Files that touch it: objctx_child.c, objctx.c, scan_unpack.c,
 * scan_walk.c, scan_heur.c, scan_pipeline.c, objctx_emu.c, scan.c,
 * scan_facts.c.
 */
struct kof_scan_obj_open {
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
	char mod_tag[KOF_MOD_TAG];
	const struct kof_module *mod_tag_of;
	/*
	 * A BOUND CUT THIS OBJECT'S EVIDENCE - see oc_scan_limit. Not `broken`: that
	 * one is read by the open stages, and an unpack loop stops on any value of it
	 * (a table that filled in the PARSE would have stopped the unpackers before
	 * they opened the members the table did hold - measured: two cabinets lost
	 * their children). This is the report and nothing else: it changes no control
	 * flow, and the verdict stage turns it into KOF_BROKEN_LIMIT on the result
	 * when no earlier reason is there. Per object, cleared in obj_begin.
	 */
	uint8_t cut;
	/*
	 * And which module opened THE OBJECT BEING SCANNED - see
	 * kof_result.opened_by. Set where that module produces a child,
	 * because producing one is what "opened it" means, and cleared per
	 * object beside sc->broken.
	 */
	char opened_by[KOF_MOD_TAG];
	/*
	 * AND WHICH BUILD OF THE PACKER IT IS, as the module that recognised it
	 * said - see kof_result.packer_build. Copied rather than pointed at: a
	 * module's string lives in its blob and the answer has to outlive the
	 * call. Cleared per object, beside opened_by.
	 */
	char packer_build[48];
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
	char pend_build[48];
	const struct kof_module *pend_build_of;
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
	int superseded;
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
	uint32_t heur_keep;
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
	int packed_here;
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
};

/*
 * sc->obj: struct kof_scan_obj
 *
 * PER OBJECT: everything that must not outlive the object it was derived from.
 * sx_obj_begin (scan.c) is the ONE place it is cleared: the things the fields
 * own are released first, then the whole struct is wiped by one memset, so a
 * field added here is reset without anyone remembering to. A field belongs
 * here if a stale value from the last object would be a defect; what is
 * derived once per object and kept is in latch[], a field of its own because
 * its meaning is the same for every stage.
 *
 * Owner: sx_obj_begin (scan.c) clears it; the stage units named on each sub-
 * struct fill it. Files that touch it: objctx_diag.c, objprod.c, scan_feed.c,
 * scan.c, scan_verdict.c, objctx.c.
 */
struct kof_scan_obj {
	/* See enum kof_obj_latch. Cleared for every object, in obj_begin. */
	uint8_t latch[KOF_OL_COUNT];
	/* See enum kof_prodkind: how many times each product was made for this object. */
	uint8_t prod_runs[KOF_PROD_COUNT];
	uint32_t n_dis_set;
	struct kof_scan_obj_sym sym;
	struct kof_scan_obj_diag diag;
	struct kof_scan_obj_emu emu;
	struct kof_scan_obj_open open;
};

/*
 * sc->mod: struct kof_scan_mod
 *
 * PER MODULE, written while a module runs and wiped by sx_mod_begin (scan.c)
 * before the next one. The counts and flags are reset by hand there and not by
 * a memset: three of these are arrays (cure_fix, mutation_blk, infect) whose
 * bytes do not need clearing and whose clearing would be paid for every module
 * of every object.
 *
 * Owner: the report/repair half in objctx.c (what a module says through the
 * ABI), the verdict half in scan_verdict.c (what the finding is named after).
 * Files that touch it: objctx.c, scan.c, scan_verdict.c, objctx_child.c,
 * scan_pipeline.c, scan_heur.c, scan_unpack.c, objctx_diag.c, objctx_emu.c.
 */
struct kof_scan_mod {
	/*
	 * WHETHER A SIMILARITY MEASURE ANSWERED, and with what.
	 *
	 * The same pair of facts mutation_asked and mutation_hit are, for the
	 * measures that carry a reference in the module's own rodata rather
	 * than a declared block - kof_mutation_blocks. A verdict reached through
	 * one of those is named for it, exactly as a mutation verdict is, so a reader
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
	int cure_have;
	uint64_t cure_at;
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
	uint32_t n_cure_fix;
	uint64_t cure_trunc;
	int cure_trunc_set;
	/* Where a module said the infection is - see struct kof_infected. */
	struct kof_infected infect[KOF_MAX_INFECTED];
	uint32_t n_infect;
	/*
	 * THE HIGHEST MUTATION SCORE THE MODULE BEING RUN HAS ASKED ABOUT.
	 *
	 * A similarity verdict is a MEASUREMENT, and the name it is reported
	 * under should carry it: "Botnet:Mirai#83!Mutation" says how alike the
	 * sample was, which is the one thing a reader of such a verdict needs
	 * and the one thing a hand-written variant cannot know. Recorded where
	 * it is produced - see c_mutation_score - because nothing downstream can
	 * work out afterwards which block a rule looked at, or whether it
	 * looked at one at all.
	 *
	 * Reset per module, not per object: two rules on one object are two
	 * verdicts, each naming what IT measured. -1 is "this module has not
	 * asked", which is what keeps every other rule's name untouched.
	 */
	int mutation_asked;
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
	 * see kof_mutation_name_of, which sorts them so the order a C expression
	 * evaluated them in cannot change the answer.
	 *
	 * The score is the set's too: `hit` and `tot` are matched hashes and
	 * declared hashes summed over these blocks, so the percentage says how
	 * much of what the rule is made of is in this object. A block asked
	 * about twice is counted once - see c_mutation_score.
	 */
	uint32_t mutation_blk[KOF_MUTATION_NAME_MAX];
	uint32_t n_mutation_blk;
	uint32_t mutation_hit;
	uint32_t mutation_tot;
	/*
	 * AND WHETHER A DECLARED STRING OF THIS MODULE WAS FOUND, which is
	 * what says the mutation residue is not the explanation.
	 *
	 * mutation_asked plus mutation_hit answer "was a block asked about, and
	 * did it find anything". They do not answer "is that what recognised
	 * the object", and the name claims exactly that - see the contract on
	 * the similarity fields below: a reader of the name knows what
	 * recognised it.
	 *
	 * A RULE HAS SEVERAL MATCHERS AND THEY ARE NOT ONE EXPRESSION:
	 *
	 *     if (kof_find_str_multi(code, s0..s6) >= 2 ||
	 *         kof_mutation_score(blk) >= 70u)   KOF_SCAN_INFECT(...);
	 *     if (kof_find_str_any(sym_exp, s7..s13))  KOF_SCAN_INFECT(...);
	 *
	 * `||` short-circuits when its LEFT side is true, so a string that
	 * carries the first matcher keeps kof_mutation_score from ever running
	 * and mutation_asked stays -1. What it does not cover is the first
	 * matcher failing BOTH ways and the SECOND one firing: the block was
	 * scored, found 17 per cent of itself - far under the 70 the rule
	 * wanted, and under any threshold a rule would use - and a Gafgyt
	 * sample recognised by an exported symbol came back named
	 * "#51f88b7c!Mutation?17". The number was real and the sentence it
	 * formed was false.
	 *
	 * SO: a string of this module matched, and the name belongs to the
	 * string. It costs a combined rule nothing that it had - all three
	 * mixed rules shipped are `string || mutation`, where a matching string
	 * means the mutation call never happened.
	 *
	 * Reset per module beside the mutation fields and for the same reason.
	 */
	int str_hit;
	/*
	 * THIS MODULE READ THE NODE GRAPH - see KOF_ENGINE_DIAGNOSE.
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
	 * demanding 80 of either. It reported "Mutation?32" - a number belonging
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
	 * THE NAME IS STILL THE SET'S - see kof_mutation_name_of. What a rule is
	 * made of and how much of it is here are two different questions, and
	 * naming after the best block alone made two rules sharing that block
	 * report the same thing.
	 */
	uint32_t mutation_best;
	/* Set while a module runs: find_str is called from inside one, and the ids it
	 * passes are module local, so the host has to know whose they are. */
	const struct kof_module *cur;
	/* What the running module reported. A module cannot hold state, so a finding
	 * has to land here. */
	uint32_t rep_level, rep_name_id;
	int rep_valid;
	/* The last reason the running module recorded for an object it could not
	 * finish (KOF_BROKEN_*), 0 for none. An unpacker that names a packer it
	 * cannot open reports and records in either order, and the finding has
	 * to say WHY - see finding_str. Cleared with the report by mod_begin. */
	uint32_t rep_reason;
};

#endif
