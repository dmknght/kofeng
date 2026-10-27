/*
 * kofresult.h - what a scan answers with: the verdict (a finding), the diagnose report,
 * kof_result, the verdictor's input and the statistics. *
 * A part of <koftypes.h>, which includes it: a host still includes koftypes.h (or
 * kofeng.h) and nothing else. Split from it by purpose; nothing was changed.
 */

#ifndef KOFRESULT_H
#define KOFRESULT_H

#include <stddef.h>
#include <stdint.h>
#include "kofobjname.h"
#include <kofmod/infected.h>

struct kof_range;

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

/* The ids a verdict lists of the diagnoses and of the diseases (kof_finding.diag,
 * .disease). Over it the list is cut and the total says so. */
#define KOF_VERDICT_TRACE 16u

/*
 * THE VERDICT OF AN OBJECT - the only finding there is. It is made from the diseases the
 * object has (kof_verdict_make) and says which diagnoses matched; nothing else in a
 * result is named like it.
 */
struct kof_finding {
	/*
	 * <verdict word>#<target>/<Type>:<behaviour>[!<engine>][?<other types>], composed
	 * by the verdictor from the diseases - see kof_verdict_make. The target is
	 * not authored, so a module cannot claim a format it was not run against.
	 */
	char     name[224];

	/*
	 * THE SAME NAME, ALREADY TAKEN APART.
	 *
	 * Because the alternative was every reader taking it apart again, each
	 * knowing the punctuation the engine had just finished writing. The engine
	 * knows every part before it joins them, so it says where each landed.
	 * `family` is the behaviour path of the lead disease, `shape` the word after
	 * the '!' (the engine that answered), `reason` what follows the '?'.
	 */
	struct kof_name_span target, maltype, family, shape;
	struct kof_name_span reason;

	/*
	 * NON-ZERO WHEN `name` HAD TO BE CUT. The name is a fixed array; the part that
	 * gives is the FAMILY, so the engine word and the reason are kept whole and
	 * `family.n` is shorter than the behaviour the disease declared. The flag says so.
	 */
	uint8_t  name_cut;

	/*
	 * ---- WHAT THE ENGINE STORES, AS VALUES ---------------------------
	 *
	 * The name above is a STRING, and a string is a decoded thing: it has a word
	 * order, separators and spellings. These are the facts behind it, each an enum,
	 * and kof_verdict_name is the one place that turns them into the line a person
	 * reads. A reader that wants to GROUP or FILTER takes these and parses nothing.
	 */
	uint8_t  verdict;        /* enum kof_verdict_id - how sure      */
	uint8_t  engine;         /* enum kof_engine_id  - what answered */
	uint8_t  type;           /* enum kof_maltype    - what it is    */
	uint8_t  fmt;            /* enum kof_format     - of the object */
	uint8_t  arch;           /* enum kgenome_arch                       */
	uint8_t  type_known;     /* 0 when a disease the database does not name led it */

	/*
	 * ---- WHAT THE VERDICT IS MADE OF -------------------------------------
	 *
	 * A verdict is the diseases the object has and the diagnoses that matched and
	 * declare them; the name is composed from the diseases (kof_verdict_make), and
	 * these are the way back from the name to its causes:
	 *
	 *   diag[]     ids of the matched diagnoses that declared a disease, in
	 *              database order; kdb_diagnose_name turns one into its name and
	 *              kdb_diagnose_disease into the disease it declares
	 *   disease[]  ids of every disease of the verdict, each once;
	 *              kdb_disease_name / kdb_disease_type
	 *
	 * BOUNDED, AND SAYING SO. `n_*` is how many ids are stored (at most
	 * KOF_VERDICT_TRACE), `*_total` how many there were: total > n is a verdict
	 * that was composed from every disease and lists only the first n of them.
	 */
	uint32_t n_diag, diag_total;
	uint32_t diag[KOF_VERDICT_TRACE];
	uint32_t n_disease, disease_total;
	uint32_t disease[KOF_VERDICT_TRACE];
};

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
 * ---- WHERE THE INFECTION IS ----------------------------------------------
 *
 * A module that has located damage can say where, and a reader that is looking
 * at the file wants it: BODY is the malware's own bytes, DAMAGE is the host's own
 * bytes that were overwritten. Marking them the same colour would tell a reader to
 * delete the program's entry point.
 *
 * A FACT ABOUT A PLACE, not a verdict: the object is named by its diseases
 * (kof_result.verdict) whether or not a module marks anything here.
 *
 * DECLARED, NEVER INFERRED. The engine does not guess a range; a module says so or
 * nothing is said.
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
/* KNOWN DEFECT N-REGION16b (2026-10-24, R) [sev L]: the comment above is stale: KOF_SRC_MAX_REGIONS no longer bounds what a
 * producer may declare (tables are dynamic since fix_normalize N3), so "matched to" is false and the 16 here is a
 * silent ABI clip. Trigger: any object declaring more than 16 regions. Effect: see N-REGION16 in scan_pipeline.c.
 * Reproducer: corp300/015_240fe. Fix: reword with the clip, or raise it with the n_region total (ABI decision). */
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
	uint8_t     n_node;                 /* nodes the diagnose declares, at most
					 * KOF_DIAG_REPORT_NODES: a diagnose of more
					 * reports its first ones (it matches on all) */
	uint8_t     n_bound;                /* nodes found: n_node on MATCH, else 0 */
	uint16_t    cap[KOF_DIAG_REPORT_NODES];  /* what node k is */
	uint64_t    at[KOF_DIAG_REPORT_NODES];   /* where, as an offset into the object */
};


struct kof_result {
	/* And where it found the infection - see struct kof_infected. */
	struct kof_infected infected[KOF_MAX_INFECTED];
	uint32_t n_infected;

	/*
	 * THE DIAGNOSES AN OBJECT CARRIES ARE NOT REPORTED HERE, and the
	 * array that used to be was removed rather than left empty.
	 *
	 * A diagnose is a STEP, not an answer: it says a shape is present,
	 * which is true of a packer and a stager alike, and the disease it
	 * declares is where the verdict comes from. Publishing the step made the
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
	 * THE UNITS OF THE PARENT'S CUT THAT A VIEW'S DECODE REWROTE, in this object's own
	 * offsets, sorted and apart. A view is cut again by what its bytes hold, and a decoded
	 * payload is not what the parent's strings were, so the cut would come out different -
	 * these are the units it leaves whole. A host that cuts a view into blocks passes them
	 * to the cut (kof_scan_cut.fixed) for the reason every field here exists: the units it
	 * shows are the ones the scanner credits.
	 *
	 * BORROWED FOR THE CALL, like syms. NULL and 0 for everything but a view whose decode
	 * rewrote something.
	 */
	const struct kof_range *fixed;
	uint32_t n_fixed;

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
	/*
	 * APPENDED: the object's own diagnose analysis ran out of its budget and the
	 * object is NOT marked broken, because it opened into a child that carries the
	 * evidence (a packer's stub: the emulate route spent its instructions on it).
	 * What would have been `KOF_BROKEN_LIMIT` is said here instead, for -v and an
	 * examiner; kof_stats.analysis_moot counts them. Zero for every other object,
	 * and always zero on one whose cut was its ONLY analysis (that one is LIMIT).
	 */
	uint8_t  analysis_moot;

	/*
	 * THE OBJECT'S VERDICT, when it has diseases: `has_verdict` is 1 and
	 * `verdict` is the finding composed from them (kof_verdict_make), carrying the
	 * ids of the diagnoses that matched and of the diseases they and the modules
	 * declared - see the last fields of struct kof_finding. Detection is at least
	 * one disease; the name is a function of the diseases' type and behaviour and
	 * nothing else.
	 */
	struct kof_finding verdict;
	uint8_t has_verdict;
	/*
	 * NON-ZERO WHEN THE SET OF DISEASES THE VERDICT WAS READ FROM MAY BE MISSING ONE:
	 * an allocation failed, or a diagnose that was going to be asked could not say
	 * because a limit was reached on the analysis it reads. A 'no' from such a diagnose
	 * is not evidence. With no verdict and nothing else found the object is marked
	 * broken; this says so for an object that has findings or a verdict already.
	 */
	uint8_t verdict_incomplete;
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
 * WHAT THE VERDICTOR IS GIVEN to name an object: the diseases it has, resolved to
 * their type and behaviour, the ids of the diagnoses that matched, and the two
 * facts about the object a name carries. The scanner fills it; the verdictor reads
 * nothing else of the scan.
 *
 * `name` is the behaviour as the database spells it ("flood-network/raw-header"),
 * NULL when the database does not name the id; `type` is a kof_maltype, or 0xff
 * when it is not known.
 */
struct kof_verdict_disease {
	uint32_t    id;
	uint8_t     type;
	const char *name;
};

struct kof_verdict_in {
	const struct kof_verdict_disease *dis;
	uint32_t n_dis;
	const uint32_t *diag;   /* ids of the matched diagnoses that declare a disease */
	uint32_t n_diag;
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
	 * `multi_degraded` is the sweeps that could NOT finish: the object reached its read bound
	 * (a hostile file makes every position a candidate), a read of the pack failed or came
	 * back short (a truncated pack), a slice of the table failed its checksum, or the table of
	 * what was found was full. Each is reported here and the region is then answered by the
	 * per-marker path, which is exact - so a nonzero count is time lost, never a detection.
	 * `multi_reads` is the reads of the pack those sweeps made: the table's records and the
	 * markers' bytes, which stay in the pack and are read as a candidate needs them.
	 */
	uint64_t multi_passes;           /* regions read once for all their markers */
	uint64_t multi_degraded;         /* sweeps that did not finish (see above) */
	uint64_t multi_reads;            /* reads of the pack made by sweeps */
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
	 * How many times an ask for the emulator was honoured.
	 *
	 * Reported because it is a cost a FILE's contents can choose - a diagnose
	 * asks on what it finds, and interpreting is the most expensive thing
	 * this engine does. There is a ceiling on it; this is how a reader sees
	 * how close a scan came to it. See KOF_ENG_USE_EMU in kofmod/kofmodemu.h.
	 */
	uint64_t heur_emu;

	/*
	 * HOW MANY OBJECTS A BOUND CUT, AND SAID SO.
	 *
	 * A bound that exists to stop a hostile object (a table of a parser, the
	 * rounds of a decode, a pending list) may cut a real one short. It never does
	 * so quietly: the object it cut is marked KOF_BROKEN_LIMIT (unless an earlier
	 * reason is there) and this counts the object, so a scan of a tree can tell a
	 * clean answer from one that was bounded. Zero is the normal value.
	 */
	uint64_t limit_hits;

	/*
	 * THE SIMILARITY MATCHER'S WORK, and whether its bound cut any.
	 * `mutation_visits` is the entries of shared block lists this scanner walked,
	 * `mutation_trunc_objects` the objects on which the per-object visit budget
	 * refused a walk (their block counts are lower bounds; zero is normal).
	 */
	uint64_t mutation_visits;
	uint64_t mutation_trunc_objects;
	/*
	 * APPENDED FIELDS (memory work; struct kof_stats is read through a pointer
	 * the engine owns, so a host built against the older header never reads
	 * past the old end).
	 *
	 * `trace_capped`: objects whose decode trace was refused room - by the cap that
	 * follows the caller's allowance (a quarter of max_resident_bytes, at most
	 * 32 MiB) or by the ledger. The trace is a cache; the code is decoded again and
	 * the answer is the same, so this is a cost report and never an incompleteness.
	 * `peak_norm`: the most the normaliser's working buffers held at once.
	 * `scan_trims`: calls of kscan_trim that found something to give back.
	 */
	uint64_t trace_capped;
	uint64_t peak_norm;
	uint64_t scan_trims;
	/*
	 * A produced object that could not be spilled to a file, said by reason. Each counts an
	 * event where the engine fell back to memory under the ceiling (or refused the object):
	 * `spill_unavailable` no directory a file can be made in, `spill_small` too little
	 * free space, `spill_full` a write failed mid-object (the object is dropped, not
	 * cut), `spill_ram` the default directory is a RAM filesystem so the object stayed in
	 * heap, `spill_ceiling` the memory ceiling was reached while the file was not an option
	 * (the object is refused and marked KOF_BROKEN_LIMIT, limit_hits moves).
	 */
	uint64_t spill_unavailable, spill_small, spill_full, spill_ram, spill_ceiling;
	/* Assembled images the emulator run handed to the child instead of copying into it. */
	uint64_t emu_adopted;
	/* APPENDED: container members whose NAME was longer than the container's format
	 * allows (see oc_name_limit in scanners/objctx_child.c for the limit of each and its
	 * standard). Such a member is opened without a name, its object is reported
	 * KOF_BROKEN_DAMAGED and this counts it; zero is the normal value. */
	uint64_t names_invalid;
	/*
	 * APPENDED (similarity index in the pack): `mutation_io_objects` is the objects on
	 * which the matcher could not read all it needed from the pack's index file - the
	 * object's read allowance ran out (KOF_MTN_S_IO_BUDGET), a read failed because the
	 * file is shorter than it was (KOF_MTN_S_IO_ERROR), or a 64 KiB slice did not match its
	 * checksum (KOF_MTN_S_SLICE_CRC). Their block counts are lower bounds; zero is normal.
	 * `mutation_io_bytes` is what this scanner has read from that file.
	 */
	uint64_t mutation_io_objects;
	uint64_t mutation_io_bytes;
	/*
	 * APPENDED (tree-wide interpreter allowance, kof_scan_option.max_emu_insn):
	 * `emu_insn` is the instructions the interpreter executed for the trees this scanner
	 * has scanned (unpack runs, heuristic runs, the diagnose scan's emulations);
	 * `emu_budget_denied` is the objects whose run or emulating route was refused or cut
	 * because their tree had spent its allowance. Those objects read KOF_BROKEN_LIMIT and
	 * are in limit_hits as well. Zero is the normal value of the second.
	 */
	uint64_t emu_insn;
	uint64_t emu_budget_denied;
	/* APPENDED: objects whose own analysis was cut by its budget while a child they
	 * opened into carries the evidence - not broken, counted here and in
	 * kof_result.analysis_moot (scanners/scan_verdict.c, sx_verdict_make). */
	uint64_t analysis_moot;
	/* APPENDED: the engine's check, per top-level file, of a host that registered
	 * on_event_detected: `verdicts_counted` files had a verdict (a roll-up counts
	 * them), `verdicts_delivered` of those were given a verdict event, and
	 * `verdict_lost` is the difference. Zero is the only correct value; a nonzero
	 * one is a defect of the engine and kofscanner prints it as an error. */
	uint64_t verdicts_counted, verdicts_delivered, verdict_lost;
};

#endif /* KOFRESULT_H */
