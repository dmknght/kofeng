/*
 * kofresult.h - what a scan answers with: the level words, a finding, a repair, the
 * diagnose report, kof_result, the verdictor's input and the statistics. *
 * A part of <koftypes.h>, which includes it: a host still includes koftypes.h (or
 * kofeng.h) and nothing else. Split from it by purpose; nothing was changed.
 */

#ifndef KOFRESULT_H
#define KOFRESULT_H

#include <stddef.h>
#include <stdint.h>
#include "kofobjname.h"
#include <kofmod/infected.h>


/* How strongly a finding is asserted. Mirrors enum kof_level on the module side; a
 * host must not have to include the module ABI to read a result. */
#define KOF_LEVEL_SUSPECT 0
#define KOF_LEVEL_INFECT  1
/*
 * Decided by structure rather than by a signature, and counted apart from both.
 *
 * Its own level and not a kind of SUSPECT, because the two answer differently to
 * an operator: a SUSPECT came from a module that names a family and chose the
 * weaker verdict, while this came from traces that name nothing. Folding them
 * together meant a heuristic could not be measured, tuned or switched off in the
 * report - which is most of what anyone wants to do with one.
 */
#define KOF_LEVEL_HEUR    2

/*
 * WHICH VERDICT IS STRONGER.
 *
 * The numbers above do not say. SUSPECT is 0, INFECT is 1 and HEUR is 2, so
 * comparing the constants gets the order exactly wrong, and every host that
 * needed to pick the worst of several findings worked the order out for itself
 * - the scanner in a switch returning 3/2/1, the viewer in a chain of ifs
 * beside a comment restating the same rule. Two spellings of one fact, neither
 * of them here, where the constants are.
 *
 * Higher is stronger. The values are ranks and nothing else: do not store them,
 * do not send them anywhere, and do not assume the gaps mean anything.
 */
static inline int kverdict_level_rank(uint32_t level)
{
	if (level == KOF_LEVEL_INFECT)
		return 3;
	if (level == KOF_LEVEL_SUSPECT)
		return 2;
	return level == KOF_LEVEL_HEUR ? 1 : 0;
}


/*
 * Findings are accumulated, not overwritten: two families can match one object, and
 * keeping only the last silently drops one. Over the cap they are counted, because a
 * truncated list that says nothing about being truncated reads as a complete list.
 */
#define KOF_MAX_FINDINGS 16

/*
 * THE LAST SLOT IS THE VERDICT'S. Evidence (a detector's, a rule's, a
 * heuristic's finding) stops one short of the array, so the syndrome verdict,
 * which is added after every detector has run, always has a place: with the
 * array full of evidence the verdict was the one dropped, and an object with
 * sixteen findings had no verdict at all (tests/unit/verdict_branches.c).
 * kof_result.dropped still counts the evidence that did not fit.
 */
#define KOF_MAX_EVIDENCE (KOF_MAX_FINDINGS - 1)

/*
 * WHERE ONE PART OF A NAME SITS INSIDE IT.
 *
 * Offsets rather than pointers, because a finding is copied by value all over
 * this tree and a pointer into a struct does not survive that. `n` of 0 means
 * the part is absent; the text is name[at] for n bytes and is NOT terminated
 * there, so print it with "%.*s".
 */
struct kof_name_span {
	uint16_t at, n;
};

struct kof_finding {
	uint32_t level;                  /* KOF_LEVEL_* */

	/*
	 * <target>/<maltype>:<family>#<variant>, composed by the engine - for
	 * example "ELF-x64/Botnet:Mirai#Gen", and for a heuristic
	 * "ELF-x64/Heur:Meterp#g7q2x?Shellcode". The target is not authored, so
	 * a module cannot claim a format it was not run against.
	 */
	char     name[224];

	/*
	 * THE SAME NAME, ALREADY TAKEN APART.
	 *
	 * Because the alternative was every reader taking it apart again. The
	 * scanner walked the string for the '!' and then for the '#' to group
	 * heuristics by shape; the examiner cut at the '/' to compare the rest;
	 * each knew the punctuation the engine had just finished writing. A
	 * separator that changed - and one has, '-' to '#' - broke them
	 * silently, one at a time.
	 *
	 * The engine knows all five parts before it joins them, so it says so.
	 * `shape` is the word after the '!': a heuristic's shape, or the word
	 * Mutation on a similarity verdict. It is
	 * what the rule actually recognised, where `family` is only what it
	 * guesses the object is.
	 */
	struct kof_name_span target, maltype, family, variant, shape;
	/* The optional tail of the formula: why, for a finding that has a
	 * why to give. Empty for the ones that do not. */
	struct kof_name_span reason;

	/*
	 * WHAT A SIMILARITY VERDICT MEASURED, AS A NUMBER.
	 *
	 * The engine works this out and then writes it into the name -
	 * "#20a2ecee!Mutation?74" - and for a while that text was the only place
	 * it existed. A host that wanted the number had to parse the name it
	 * had just been handed, which is the thing the spans above exist to
	 * stop; and a panel that wanted to show the engine's number instead
	 * measured the object again for itself.
	 *
	 * So the number comes first and the name is crafted from it. `sim_pct`
	 * is 0..100 and zero for every finding that is not a similarity one -
	 * which is also what a similarity verdict that measured nothing would
	 * be, and that verdict is never reported, so the two cannot be
	 * confused. `sim_of` is the fold that names the SET it was measured
	 * over, the same value the variant carries, so a host can tell which
	 * blocks the number is about.
	 */
	uint8_t  sim_pct;
	uint8_t  sim_kind;          /* enum kof_sim_kind */
	uint32_t sim_of;

	/*
	 * IS THIS THE SUBJECT'S VERDICT, or one of the things that led to it.
	 *
	 * A subject - a file, or one member of an archive - gets ONE verdict,
	 * and the engine keeps it in one place; see kof_scanner.verdict. The
	 * findings array still holds everything that fired, because an
	 * examiner wants to see the working, and this bit says which of them
	 * the scan is actually reporting.
	 *
	 * WHY IT IS A BIT AND NOT A FILTER. Dropping the others would make
	 * the array lie about what matched, and the note above
	 * KOF_MAX_FINDINGS is there because that has been tried: two families
	 * can match one object and keeping only one silently loses the other.
	 * Nothing is lost here - a reader that wants the verdict reads this,
	 * a reader that wants the evidence reads the array.
	 *
	 * Set when the finding took the slot. A later, stronger finding takes
	 * it in turn, and the earlier object has already been reported by
	 * then - which is what streaming output means and not a defect in the
	 * slot.
	 */
	uint8_t  is_verdict;

	/*
	 * ---- WHAT THE ENGINE STORES, AS VALUES ---------------------------
	 *
	 * The name above is a STRING, and a string is a decoded thing: it
	 * has a word order, separators and spellings, and every one of those
	 * is a presentation decision that does not belong in a result. These
	 * are the facts behind it, each an enum, and kof_verdict_name is the
	 * one place that turns them into the line a person reads.
	 *
	 * `name` is still here and still filled - by that same function, so
	 * there is one spelling and not two. A reader that wants the line
	 * takes it; a reader that wants to GROUP or FILTER takes these and
	 * does not parse anything.
	 *
	 * `family`, `variant` and `reason` stay as spans into `name`. They
	 * are not enums and cannot be: a family is a word a researcher
	 * chose, and the anomaly model's and mutation's are computed per
	 * object. What is enumerable is enumerated.
	 */
	uint8_t  verdict;        /* enum kof_verdict_id - how sure      */
	uint8_t  engine;         /* enum kof_engine_id  - what looked   */
	uint8_t  type;           /* enum kof_maltype    - what it is    */
	uint8_t  fmt;            /* enum kof_format     - of the object */
	uint8_t  arch;           /* enum kgenome_arch                       */
	/*
	 * The type is not always one of enum kof_maltype: a rule that
	 * recognised a shape has not established a class, and the anomaly
	 * model never does. This says so, rather than a sentinel inside the
	 * type - KOF_MALTYPE_VIRUS is 0 and "nothing declared" must not read
	 * as "virus".
	 */
	uint8_t  type_known;
};

/* Which measure a finding's sim_pct came from. */
enum kof_sim_kind {
	KOF_SIM_NONE = 0,
	KOF_SIM_MUTATION              /* the declared blocks - kof_mutation_score */
};

/* Non-zero when this finding is a heuristic's - the maltype word is "Heur",
 * which is the engine's and never a module's family. */
static inline int kverdict_is_heur(const struct kof_finding *f)
{
	return f->maltype.n == 4 &&
	       f->name[f->maltype.at + 0] == 'H' &&
	       f->name[f->maltype.at + 1] == 'e' &&
	       f->name[f->maltype.at + 2] == 'u' &&
	       f->name[f->maltype.at + 3] == 'r';
}

/*
 * "This object did not come from an entry" - the root of a walk, a payload an
 * emulator wrote, anything a container did not describe.
 *
 * Not zero, because zero is a real entry index and the first one at that. Not
 * KGENOME_NA either: that is UINT64_MAX and this field is 32 bits, so spelling it
 * with the wider constant would truncate to 0xffffffff by accident rather than
 * by decision. One name, stated once, is what stops the two being confused.
 */
#define KOF_ENTRY_NONE 0xffffffffu

/*
 * A REPAIR A MODULE DESCRIBED, and did not perform.
 *
 * A rule that recognised an infected file may also know how to undo the
 * infection - see KOF_SCAN_CURABLE in kofmod/kofsig.h. What it produces is
 * this: a list of byte ranges to overwrite and, optionally, a length to cut
 * the object to. Nothing has been written; the caller decides whether to.
 *
 * SEPARATE FROM THE FINDINGS because it is not one. The verdict stands
 * whether or not anybody repairs anything, and a caller that ignores this
 * field gets exactly the scanner it had before.
 *
 * `n_fix` of zero means nothing was offered, which is the ordinary case.
 */
#define KOF_MAX_FIX 64u

struct kof_repair {
	struct {
		uint64_t off;
		uint32_t n;
		uint8_t  b[16];
	}        fix[KOF_MAX_FIX];
	uint32_t n_fix;
	/* Where the object should end, or 0 for "leave the length alone". */
	uint64_t truncate;
};

/*
 * ---- WHERE THE INFECTION IS ----------------------------------------------
 *
 * A MODULE THAT CAN CURE ALREADY KNOWS THIS, which is the whole argument for
 * carrying it. Nothing can describe a repair without having located the
 * damage first - the Sality module computes where the virus body begins and
 * how many of the host's bytes it overwrote in order to put them back - and
 * until now that knowledge went into `kof_repair` as a list of patches and
 * was otherwise thrown away.
 *
 * A patch is not the same statement. "Write these 382 bytes at offset 0x1d9d"
 * says how to undo the damage; it does not say that the 65 KB at the end of
 * the file are the virus. A reader wants both, and a reader that only repairs
 * wants the first while a reader that is looking at the file wants the second.
 *
 * TWO KINDS, BECAUSE THEY CALL FOR OPPOSITE ACTIONS. BODY is the malware's own
 * bytes - what a removal would cut out. DAMAGE is the host's own bytes that
 * were overwritten - what a repair puts back. Marking them the same colour
 * would tell a reader to delete the program's entry point.
 *
 * DECLARED, NEVER INFERRED. The engine does not guess a range from a finding;
 * a module says so or nothing is said.
 */
#define KOF_MAX_INFECTED 16u

struct kof_infected {
	uint64_t off;
	uint64_t len;
	uint32_t kind;       /* KOF_INF_* */
	uint32_t _pad;
};

/* The most declared regions one object reports - see kof_result.region. Matched
 * to KOF_SRC_MAX_REGIONS, which is what a producer may declare. */
#define KOF_MAX_REGIONS 16u

/*
 * WHAT EACH LOADED DIAGNOSE MAKES OF AN OBJECT - delivered in kof_result.diag
 * to a caller that asked for it with kof_scan_option.report_diag.
 *
 * ONE STATE PER DIAGNOSE, in the order the checks run - the first that fails is
 * the reason, so a state also says how far the diagnose got:
 *
 *   SHAPE     the file is not the kind this diagnose is about (its conditions)
 *   NO_ROUTE  the analysis it is written for is not one this file offers
 *   SIGNS     the file lacks an import or a symbol reference the diagnose needs
 *   SEEN      the gate is open and the analysis ran, but the nodes did not
 *             form the diagnose's tree. It says NOTHING about how close: a
 *             diagnose that declares only an analysis has its gate open on
 *             every file that offers it (measured: 122 of 255 ELF)
 *   MATCH     the tree was found; `at` says where each node is
 *
 */
#define KOF_DIAG_REPORT_NODES 32u

enum kof_diag_state {
	KOF_DIAG_ST_SHAPE = 1,
	KOF_DIAG_ST_NO_ROUTE,
	KOF_DIAG_ST_SIGNS,
	KOF_DIAG_ST_SEEN,
	KOF_DIAG_ST_MATCH
};

struct kof_diag_report {
	const char *name;
	uint32_t    id;                     /* kof_diag_id32_(name) */
	uint8_t     state;                  /* enum kof_diag_state */
	uint8_t     n_node;                 /* nodes the diagnose declares */
	uint8_t     n_bound;                /* nodes found: n_node on MATCH, else 0 */
	uint16_t    cap[KOF_DIAG_REPORT_NODES];  /* what node k is */
	uint64_t    at[KOF_DIAG_REPORT_NODES];   /* where, as an offset into the object */
};


/*
 * WHAT THE DIAGNOSES THAT MATCHED MAKE, by type - delivered in kof_result.syndrome
 * to a caller that asked for kof_scan_option.report_diag, when at least one
 * diagnose that names a disease matched and the database carries syndromes. Types are bits of
 * 1u << kof_maltype. See databases/pack/kofsyndrome.h for what each means and
 * for the name it renders to.
 */
struct kof_synd_result {
	uint32_t guaranteed;    /* types the evidence proves */
	uint32_t possible;      /* types still compatible and not proven */
	uint32_t n_compat;      /* verified samples the evidence is no more than */
	uint32_t n_query;       /* diseases asked about */
	uint32_t n_unknown;     /* ...that no verified sample carries */
	/*
	 * NON-ZERO WHEN THE ANSWER IS NOT WHOLE: at least one diagnose that was
	 * going to be asked could not say, because a limit was reached on the
	 * analysis it reads (a node store full, a run stopped while still going) or
	 * the symbol block was cut short. A 'no' from such a diagnose is not
	 * evidence, so the set above may be missing diseases. Appended: the fields
	 * above keep their layout.
	 */
	uint32_t incomplete;
};

struct kof_result {
	struct kof_finding v[KOF_MAX_FINDINGS];
	uint32_t n;
	uint32_t dropped;

	/* What a module offered to put back - see struct kof_repair. */
	struct kof_repair repair;

	/* And where it found the infection - see struct kof_infected. */
	struct kof_infected infected[KOF_MAX_INFECTED];
	uint32_t n_infected;

	/*
	 * THE DIAGNOSES AN OBJECT CARRIES ARE NOT REPORTED HERE, and the
	 * array that used to be was removed rather than left empty.
	 *
	 * A diagnose is a STEP, not an answer: it says a shape is present,
	 * which is true of a packer and a stager alike, and the rule that
	 * reads it is where the verdict lives. Publishing the step made the
	 * engine narrate its own routine - every scan that happened to run
	 * the analysis printed lines a reader could do nothing with - and it
	 * gave a second, weaker way to ask what a file does, beside the
	 * verdict that is the answer.
	 */
	/*
	 * The engine stopped before it had finished with this object, because a
	 * limit ran out - almost always the produced-bytes budget on something
	 * that expands far beyond its own size.
	 *
	 * A separate field and not a level, because it is not a finding: the
	 * verdict is "do not know", and it has to be distinguishable from "clean".
	 * Reporting an exhausted budget as clean is what turns a decompression
	 * bomb from a nuisance into a way of not being scanned.
	 *
	 * The VALUE says why, because the three reasons call for different actions
	 * and a single bit made them one word. A limit is the caller's own setting
	 * and can be raised; an unsupported coding is this engine's gap and a bug
	 * report; a damaged object is the file's own problem and neither of those.
	 * Telling somebody "not fully examined" when the answer is "this build has
	 * no LZMA" wastes their afternoon.
	 */
	uint32_t broken;      /* enum kof_broken, zero when the object was finished */

	/*
	 * HOW MANY MODULES ACTUALLY RAN ON THIS OBJECT.
	 *
	 * Zero means NOTHING EVALUATED IT, and that has to be distinguishable
	 * from "everything applicable evaluated it and found nothing" - for the
	 * same reason `broken` above is a separate field. Both are the verdict
	 * "do not know" arriving by different routes, and both were being
	 * reported as clean.
	 *
	 * It happens: a formatless blob - a payload lifted out of a variable,
	 * a decoder's output, anything with no header - matches no module's
	 * declared target, so the prefilter excludes every one of them and the
	 * object comes back with no findings. Measured on one: 40 modules
	 * considered, 0 ran, all 40 excluded by target. That object reported
	 * exactly as /usr/bin/ls, which had 31 run on it.
	 *
	 * A COUNT and not a flag, because "one module ran" and "thirty-one ran"
	 * are different amounts of confidence in a clean verdict, and a caller
	 * that wants to say so has the number.
	 */
	uint32_t examined;

	/*
	 * WHICH ENTRY OF ITS PARENT THIS OBJECT CAME FROM, or KOF_ENTRY_NONE.
	 *
	 * The link between the two halves of what a parse says about one thing.
	 * ctx->entries describes a stream WHERE IT LIES IN THE FILE - coded,
	 * with its chain and its length; the child is that stream's CONTENT,
	 * which has no offset in the file at all. They are one thing in two
	 * states, and nothing connected them: a host saw a row for the coded
	 * stream and a row for the decoded object and had no way to know they
	 * were the same stream.
	 *
	 * IN THE RESULT AND NOT IN THE NAME. A host learns about a child
	 * through the scan callback, which hands it a name, some bytes and this
	 * - so the result is the only channel that reaches it. Putting the index
	 * in the composed name instead would have changed what every dump
	 * filename and every finding is called, to carry one number.
	 *
	 * Appended rather than inserted, like every other field here: a caller
	 * built against an older header still reads the ones it knows.
	 */
	uint32_t entry_of;

	/*
	 * WHAT THE PRODUCER SAID THIS OBJECT IS - enum kof_entry_kind.
	 *
	 * Beside entry_of because a host needs both and for the same reason:
	 * the FORMAT of decoded content is almost always KOF_FMT_UNKNOWN, so a
	 * host deciding what to offer for an object cannot decide it from the
	 * format alone. "Disassemble" is right for a payload a decoder peeled
	 * out of a stub and wrong for a page description stream, and both
	 * arrive formatless.
	 *
	 * KOF_ENT_UNKNOWN when nothing said, which is the honest default and
	 * is what an unidentified blob genuinely is.
	 */
	uint32_t entry_kind;

	/*
	 * WHICH MODULE OPENED THIS OBJECT, by the name it gives ITSELF -
	 * "MPRESS.PE", "VMProtect.PE" - or NULL when nothing did.
	 *
	 * IT NAMES WHAT THE OBJECT IS, NOT WHERE IT CAME FROM, and getting
	 * that backwards is worse than saying nothing. 111.exe IS an MPRESS
	 * file; what MPRESS hands back is a VMProtect one; what VMProtect
	 * hands back carries an encrypted string table. Written as "which
	 * module produced this", every row said the layer ABOVE it - the file
	 * was labelled with nothing and its child was labelled MPRESS, so a
	 * reader saw MPRESS on the wrong object and counted a layer that is
	 * not there.
	 *
	 * The name is the one in front of every debug note the module emits,
	 * which is the only place a module says what it is called. A module
	 * that emits no note is named by its source file instead, which nobody
	 * says out loud but beats showing nothing.
	 *
	 * Valid for the duration of the callback, like everything else here.
	 */
	const char *opened_by;

	/*
	 * AND WHICH BUILD OF IT, when the module could tell - "MPRESS 2.12-2.19
	 * LZMAT", "UPX 3.9x LZMA" - or NULL when it could not or did not look.
	 *
	 * WHY THIS IS A FACT ABOUT THE OBJECT AND NOT A DEBUG NOTE. It decides
	 * what the rest of the numbers mean. MPRESS writes no version anywhere
	 * in the file, and the seven builds this engine knows put the packed
	 * section's address, the fix stub's address and the coding at DIFFERENT
	 * offsets from the entry point - so a module that reads them without
	 * first knowing which build it has is reading whatever is there. The
	 * same is true of every packer with more than one layout, and it is why
	 * the version has to be settled BEFORE the unpacking and not reported
	 * after it.
	 *
	 * It travelled as a debug note until now, which is the wrong channel
	 * twice over: a note is dropped unless somebody asked for notes, and
	 * kofviewer had to guess which note belonged to which object by
	 * remembering the last one anybody emitted.
	 *
	 * A RANGE IS AN HONEST ANSWER. "2.12-2.19" is what the evidence
	 * supports when several builds share a stub layout, and narrowing it to
	 * one would be inventing precision. RetDec's tables read the same way
	 * and for the same reason - see THIRD-PARTY.md.
	 *
	 * Valid for the duration of the callback, like everything else here.
	 */
	const char *packer_build;

	/*
	 * WHAT THE HEURISTIC MADE OF THIS OBJECT, WHETHER OR NOT IT REPORTED.
	 *
	 * Here rather than left to be recomputed, because it was being
	 * recomputed and the copy drifted. kofviewer built its own facts from
	 * what it could see - tree depth, a name it had been handed - and once
	 * the engine learned to tell a packer from a container the two answers
	 * stopped agreeing. A panel that scores an object differently from the
	 * scanner is worse than one that shows nothing: both look authoritative
	 * and only one is.
	 *
	 * So the engine computes it once, on the object it is looking at, with
	 * the facts only it has, and hands the whole of it back. A caller that
	 * wants to explain the number reads the model - kof_heur_default() - for
	 * the words, and never re-derives the evidence.
	 *
	 * `heur_scored` is 0 when the heuristic did not run (switched off) or no
	 * model covers this format, and that is NOT the same as a score of zero.
	 */
	uint8_t  heur_scored;
	uint8_t  heur_depth;        /* executable packer layers above this object */
	/*
	 * Was this object produced BY an executable packer, as opposed to having
	 * been carried by a container. The viewer's own name-matching guess at
	 * this is exactly what this field exists to retire.
	 */
	uint8_t  from_packer;
	/*
	 * THE EMULATOR RAN ON THIS OBJECT AND SOMETHING CAME OUT.
	 *
	 * Published rather than kept inside the scan, because it answers a
	 * question every reader of a result asks and none of them can work out
	 * for themselves: kofviewer offers "unpack with the emulator" as an
	 * action, and without this it offers it again on an object that has
	 * already been unpacked that way - spending a second run of up to 268
	 * million instructions to produce the children that are already on the
	 * tree beside it.
	 *
	 * SUCCESS ONLY, AND THAT IS THE WHOLE OF ITS MEANING. A run that
	 * produced nothing leaves this zero, so the action stays available: a
	 * failed run says the emulator did not reach anything THIS TIME, which
	 * a larger budget or a later build may change, and marking it would
	 * turn "we tried" into "there is nothing here". The two are different
	 * claims and only one of them is true.
	 */
	uint8_t  emu_unpacked;
	int32_t  heur_score;        /* centinats */
	uint32_t heur_flags;        /* KOF_HEUR_FL(KOF_HEUR_F_*) */
	uint64_t heur_anomalies;    /* the format's own anomaly word */

	/*
	 * THE SYMBOL RECORDS THIS OBJECT IS TO BE READ WITH, when its own bytes
	 * cannot produce them.
	 *
	 * Only a RENDERING carries these. A normalised view's headers describe
	 * the file before the transform, so every offset in them is stale
	 * wherever something collapsed ahead of it and the builder finds
	 * nothing: measured on a static bot, the file yields 677 records and
	 * its view yields zero - no SYM_EXP and no SYM_IMP at all, which is the
	 * half of an object a similarity question is most often about.
	 *
	 * So the producer hands them over, and the engine hands them on. A host
	 * that builds its own block - kofviewer does - must prefer this one,
	 * for the reason every other field here exists: a second answer
	 * computed from what the host can see drifts from the engine's, and
	 * both look authoritative.
	 *
	 * BORROWED FOR THE CALL. The bytes belong to the object and are valid
	 * until the callback returns; a host that wants them afterwards copies
	 * them, as it already copies the regions. NULL and 0 for everything the
	 * engine did not render.
	 */
	const uint8_t *syms;
	uint32_t n_syms;

	/*
	 * WHAT EACH DIAGNOSE MADE OF THIS OBJECT, when the caller asked - see
	 * kof_scan_option.report_diag. NULL and 0 otherwise.
	 *
	 * THIS IS NOT THE LISTING THAT WAS REMOVED, and it is not a way to ask what
	 * a file does: a diagnose is a step and the verdict is the answer. It is for
	 * a tool that helps someone WRITE a rule, which has to see the step to build
	 * on it. Opt-in for that reason, and costed as the scan's own analysis: it
	 * runs the diagnoses no verdict reads, so it is not free and no scan asks
	 * for it by default.
	 *
	 * BORROWED FOR THE CALL, like syms: valid until the callback returns - the
	 * array and what it holds. The one exception is each `name`, which is the
	 * database's own string and lives as long as the engine does, so a host that
	 * copies the array keeps names that are still good.
	 */
	const struct kof_diag_report *diag;
	uint32_t n_diag;
	/* What the matched diagnoses make, with the same opt-in and the same
	 * cost as `diag`. `has_syndrome` is 1 when `syndrome` was computed. */
	struct kof_synd_result syndrome;
	uint8_t has_syndrome;

	/*
	 * REGIONS THE PRODUCER DECLARED, when nothing could parse them out.
	 *
	 * Empty for almost every object: a file is identified and its parser
	 * says where its parts are. A NORMALISED VIEW is the exception, and it
	 * is an exception a reader cannot recover on its own. The view keeps its
	 * parent's header byte for byte, so anything that identifies it from its
	 * bytes gets an ELF or a PE and believes the offsets in that header -
	 * which describe the parent, before the padding came out. The regions it
	 * computes are then off by however much was collapsed before them.
	 *
	 * Reported here so a host does not have to guess. kofviewer had exactly
	 * that fault: it re-identified every object it was given, so a view's
	 * data region was drawn at the parent's offsets, landed partly in kept
	 * code, and showed the padding there as though the view still carried
	 * it.
	 */
	struct kof_scan_region {
		uint32_t mask;      /* the region bit, in the parent's vocabulary */
		uint64_t off, len;  /* where it is in THIS object */
	} region[KOF_MAX_REGIONS];
	uint32_t n_region;
	/* Which format's region vocabulary region[].mask is written in - the
	 * PARENT's. A bit is meaningless without it: 1u << 5 is UNCLAIMED in an
	 * ELF and OVERLAY in a PE. Zero when n_region is zero. */
	uint8_t  region_fmt;

	/*
	 * WHAT LANGUAGE THIS OBJECT IS, when a reading of its bytes would say
	 * something else.
	 *
	 * The same problem region[] is here for, one field along. A normalised
	 * script is declared its parent's format, and its LANGUAGE is the
	 * parent's too - but the decode rewrites the view's own text, so a host
	 * that identifies the bytes it was handed can come back with a
	 * different answer: a shell dropper whose payload decodes to PHP reads
	 * as PHP. The engine scans it as the shell script it is a view of, and
	 * a host that re-sniffs then contradicts the verdict it was given -
	 * kofexaminer printed "skipped: targets another kind of this format"
	 * beside a rule the engine had just fired.
	 *
	 * `subtype` is the format's own vocabulary, as ctx->subtype carries it;
	 * `subfamily` is the script family. Both are meaningful only when
	 * `lang_known` is set, which is when the producer declared them.
	 */
	uint8_t  subtype;
	uint8_t  subfamily;
	uint8_t  lang_known;
};

/*
 * Why an object was not finished. Ordered by how specific the reason is, which is
 * also the order they take precedence in: the first reason recorded is kept, since
 * whatever stopped things first is what explains the rest.
 */
enum kof_broken {
	KOF_BROKEN_NONE = 0,
	/* A budget, a memory ceiling or a child count ran out. The caller set
	 * these and can set them higher. */
	KOF_BROKEN_LIMIT,
	/* A compression method, packer version or format this build does not
	 * implement. The object is fine; the engine is short of something. */
	KOF_BROKEN_UNSUPPORTED,
	/* The object's own structure does not hold together - a stream that does
	 * not decode, a header that contradicts itself. */
	KOF_BROKEN_DAMAGED,
	/*
	 * The content is encrypted and no key was supplied.
	 *
	 * Its own reason rather than a kind of UNSUPPORTED, because the two lead
	 * somewhere different. UNSUPPORTED is a gap in this build that a later one can
	 * close; this cannot be closed by any amount of work on the engine, and an
	 * operator reading it needs to know that the file will keep coming back the
	 * same way. Every container format that carries encryption reports it with this
	 * value, so a scan says the same thing whether the archive was a zip, a
	 * document, a RAR or a 7z.
	 */
	KOF_BROKEN_ENCRYPTED,

	/*
	 * One past the last, so a caller can size a table of reasons.
	 *
	 * Here because the alternative was a literal, and the literal was wrong the
	 * moment a reason was added: the scanner counted reasons below 4 and printed
	 * reasons below 4, so the first new one was tallied into the total and then
	 * left out of the breakdown - 81 objects broken, 53 accounted for. A count
	 * that does not add up is worse than no count.
	 */
	KOF_BROKEN_COUNT
};

/*
 * WHAT THE VERDICTOR IS GIVEN to name an object from its diseases: the
 * inference's result and the two facts about the object a name carries. The
 * scanner fills it; the verdictor reads nothing else of the scan.
 */
struct kof_verdict_in {
	const struct kof_synd_result *synd;
	uint8_t fmt;            /* enum kof_format of the object */
	uint8_t arch;           /* enum kgenome_arch */
};

/*
 * What a scan cost. Exposed because the design rests on a module being cheap for the
 * objects it does not detect, and a number nobody can read is a number nobody keeps
 * honest.
 *
 * `ran` against `considered` is how much the preconditions removed; `bytes_searched`
 * against `object_bytes` is how many times over the content was read.
 */
struct kof_stats {
	uint64_t objects, object_bytes;

	/* Objects the walk reached but could not read. Counted, because the walk is the
	 * engine's now: without this the caller has no way to learn that a file was
	 * skipped, and a scan that silently omits what it could not open reads as a
	 * scan that found nothing there. */
	uint64_t unreadable;

	/*
	 * Files the walk did not open because the caller said it already had an
	 * answer - see cache_seen. Counted for the same reason `unreadable` is:
	 * a scan that quietly visits a tenth of what it was pointed at reads as
	 * a scan of a tree that has nothing in it.
	 */
	uint64_t cached;

	uint64_t considered, ran;
	uint64_t by_target, by_size, by_arch, by_subtype, by_region;

	uint64_t gram_bytes;             /* cost of building presence sets */
	uint64_t gram_answers;           /* searches answered without scanning */

	/*
	 * WHAT THE BATCHED SWEEP DID, AND WHAT IT COST.
	 *
	 * `multi_bytes` against `bytes_searched` is the whole claim this engine
	 * makes about its own scaling: the first is what a region cost read once
	 * for all of its markers, the second is what was left to read one marker
	 * at a time. A build where the second grows with the database and the
	 * first does not is a build where the sweep stopped working, and there is
	 * no other way to see that from outside.
	 *
	 * `multi_hash4` and `multi_wumanber` say which routine the router picked,
	 * split because they are picked for opposite reasons - short markers and
	 * long ones - and a base drifting from one to the other is worth seeing.
	 */
	uint64_t multi_passes;           /* regions read once for all their markers */
	uint64_t multi_hash4, multi_wumanber;   /* which routine did it */
	uint64_t multi_bytes;            /* bytes those passes walked */
	uint64_t multi_answers;            /* answers written without a search */

	uint64_t searches, bytes_searched;

	/*
	 * The most produced data alive at once, over the whole scan.
	 *
	 * The one number that says whether the memory ceiling actually held. Peak
	 * rather than current, because the interesting question about a bomb is not
	 * where it ended up but how high it got, and reported rather than merely
	 * enforced: a limit nothing can observe is a limit nobody can show works.
	 */
	uint64_t peak_resident;

	/*
	 * HOW A BUFFERED DECODE GOT ITS OUTPUT BUFFER.
	 *
	 * A coding whose whole output must stay addressable while it decodes -
	 * LZMA, NRV2, aPLib, ASPack - needs a flat buffer the size of what it
	 * produces. When the caller is filling a DECLARED IMAGE the sink
	 * already is one, and the decode writes straight into it;
	 * `decode_inplace` counts those. Otherwise a scratch buffer is taken
	 * and copied across afterwards, and `decode_scratch` counts those.
	 *
	 * Published because the difference is a whole extra copy of the output
	 * and it is invisible from outside: measured on a VMProtect-under-
	 * MPRESS sample, the scratch path peaked at 15.31 MB where the objects
	 * alone are 10.21. A caller watching these can see which path its
	 * workload takes without reading the engine.
	 */
	uint64_t decode_inplace;
	uint64_t decode_scratch;

	/*
	 * How many times a heuristic rule's ask for the emulator was honoured.
	 *
	 * Reported because it is a cost a FILE's contents can choose - a rule
	 * fires on what it finds, and interpreting is the most expensive thing
	 * this engine does. There is a ceiling on it; this is how a reader sees
	 * how close a scan came to it. See KOF_HEUR_WANT in kofmod/heur.h.
	 */
	uint64_t heur_emu;
};

#endif /* KOFRESULT_H */
