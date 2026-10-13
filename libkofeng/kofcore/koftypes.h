/*
 * koftypes.h - the types a scan is asked with and answers with: the result, its
 * findings, the level words, the object-name vocabulary, the options, the
 * callbacks and the statistics.
 *
 * In core and not in kofeng.h because every layer of the engine fills or reads
 * these types: the detectors write findings, the verdictor composes the
 * verdict, the scanners take the options and hand the result out. They were
 * defined in the public API header, which put each of those layers above the
 * API. kofeng.h keeps the functions and includes this file, so a host still
 * needs only <kofeng.h>.
 */

#ifndef KOFTYPES_H
#define KOFTYPES_H

#include <stdint.h>
#include <stddef.h>

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
 * WHERE ONE OBJECT'S NAME ENDS AND ITS CHILD'S BEGINS.
 *
 * The engine joins a container to what it holds with this, so a result name is
 * "archive.zip//inner.elf" and a payload two layers down carries two of them.
 * It is written in scan.c and it was read - as the bare literal "//" - in the
 * scanner, in the examiner and in the viewer, each with its own loop.
 *
 * The word for what the tools do with it: a file's verdict is the worst of
 * everything under it, so they need the top level name, and a tree needs the
 * depth. Both are here so the separator is spelled once.
 */
#define KOF_OBJ_SEP     "//"
#define KOF_OBJ_SEP_LEN 2u

/* Length of the top-level file's name: everything before the first separator,
 * or the whole name when the object IS the file. */
static inline size_t kobj_toplevel_len(const char *name)
{
	const char *p = name;

	while (*p) {
		if (p[0] == '/' && p[1] == '/')
			return (size_t)(p - name);
		p++;
	}
	return (size_t)(p - name);
}

/* How many containers deep: 0 for the file itself. */
/*
 * The LAST segment of an object's name: what this object is, inside its parent.
 *
 * "archive.zip//3:bin/x86" gives "3:bin/x86", and a name with no separator at
 * all gives the whole thing - which is the right answer for the file itself.
 *
 * Here rather than in each tool because a tool that cut at the last '/' instead
 * got it right only while no label contained one: an archive member called
 * bin/x86 came out as "x86", and a name whose separator was missing came out as
 * the file's own basename. Both read as a different object from the one on the
 * row.
 */
static inline const char *kobj_leaf(const char *name)
{
	const char *p = name, *last = name;

	while (*p) {
		if (p[0] == KOF_OBJ_SEP[0] && p[1] == KOF_OBJ_SEP[1]) {
			p += KOF_OBJ_SEP_LEN;
			last = p;
			continue;
		}
		p++;
	}
	return last;
}

/*
 * WHAT THE ENGINE CALLED THIS OBJECT, out of its leaf.
 *
 * A produced object's leaf is "<index>:<label>" - "0:norm", "3:SCRIPT" - and
 * the label is the engine's own word for what it made. Spelled here for the
 * reason KOF_OBJ_SEP is: it is written in scan.c and read by the tools, and a
 * tool that spells it itself is a second vocabulary for one fact.
 *
 * NULL when the leaf carries no label, which is every object the engine did
 * not produce - a file, an archive member named after itself.
 */
static inline const char *kobj_label(const char *leaf)
{
	const char *p = leaf;

	if (!leaf || !*leaf)
		return NULL;
	while (*p >= '0' && *p <= '9')
		p++;
	return (p != leaf && *p == ':' && p[1]) ? p + 1 : NULL;
}

/* The label a NORMALISED VIEW carries - see norm_emit in scan.c, which is
 * what writes it. A view is not a sample: it is something the engine made out
 * of one, so a tool that records where a rule came from names the parent. */
#define KOF_OBJ_LABEL_NORM "norm"

static inline uint32_t kobj_depth(const char *name)
{
	uint32_t n = 0;
	const char *p = name;

	while (*p) {
		if (p[0] == '/' && p[1] == '/') {
			n++;
			p += 2;
		} else {
			p++;
		}
	}
	return n;
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
	 * are the facts behind it, each an enum, and kof_verdict_text is the
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
 * 1u << kof_maltype. See verdictor/syndromes/kofsyndrome.h for what each means and
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

const char *kverdict_broken_name(uint32_t reason);

/*
 * HOW A DETECTION IS SPELLED, IN ONE PLACE.
 *
 *     kverdict_compose(buf, sizeof buf, "ELF-x64", "Botnet", "Mirai", "Gen")
 *     -> "ELF-x64/Botnet:Mirai#Gen"
 *
 * The engine composes this for every finding, and three other things reproduce
 * it: kofexaminer and kofviewer to show a marker row, and kofinspect to decide
 * WHICH module a scan result belongs to. That last one is not display - it is
 * one half of a string comparison whose other half the engine wrote - so a
 * spelling that drifts there does not look wrong, it silently stops matching.
 *
 * It drifted exactly that way: the family/variant separator moved from "-" to
 * "#" in the engine, kofinspect kept the "-", and every detected sample
 * reported "Hit 0, Skip 1" in the viewer and no verdict at all in kofexaminer
 * while the scanner called the same file infected.
 *
 * `target` and `variant` may be NULL or empty and are left out when they are.
 */
void kverdict_compose(char *out, size_t cap, const char *target,
		      const char *maltype, const char *family,
		      const char *variant);

/*
 * The same composition, onto a finding, recording where each part landed.
 *
 * This is what the engine itself uses; kverdict_compose above stays for a
 * caller that only wants the string - kofinspect builds one to compare against
 * a result it did not produce.
 *
 * `shape` is the heuristic's, appended after a '!'. NULL or empty for a
 * detector's finding, which has no such thing to admit.
 */
void kverdict_name(struct kof_finding *f, const char *target,
		      const char *maltype, const char *family,
		      const char *variant, const char *shape);

/*
 * GET THE VERDICT NAME: the one place the standard form is written.
 *
 *     <verdict>#<target>-<arch>/<Type>:<Family>.<variant>!<engine>?<reason>
 *
 *     Infected#PE-x86/Virus:Sality.01!Pattern
 *     Heur#PE-x86/Anomalies:WriteExec!Analyzer
 *
 * EVERY FIELD IS OPTIONAL EXCEPT THE TYPE AND THE FAMILY, and an absent one
 * takes its separator with it - a trailing `#` or a bare `?` would read as a
 * field the engine failed to fill rather than one it had nothing to say in.
 *
 * WHY A FUNCTION AND NOT A CONVENTION. The order, the separators and the
 * words were decided in five places in scan.c, each composing the string it
 * needed; a sixth would have decided again. The engine now stores VALUES -
 * see the enums on kof_finding - and this is the only code that knows how
 * they are written down. Change the form here and every reader changes with
 * it, including the ones in other programs.
 *
 * Writes into `f->name` and sets the spans, so a caller that wants a part
 * rather than the line does not search for a separator this just placed.
 */
void kof_verdict_name(struct kof_finding *f, const char *family,
		      const char *variant, const char *reason);

/*
 * WHAT TO CALL AN OBJECT, from the state the engine holds about it.
 *
 * One answer, crafted here, so a tool shows it and does not compose it:
 *
 *   "Unwrap:Gzip?Deflate"  the module that opened it, when one did - what the
 *                          engine said in kof_result.packer_build
 *   "Norm"                 a normalised view of another object
 *   "PHP"                  a script, by its language
 *   "PE", "ELF"            anything else, by the name of its format
 *
 * `packer` may be NULL or empty. `subtype` is the format's own vocabulary and
 * is read only for a script. Cut at `cap`, never past it.
 */
void kof_object_label(uint32_t entry_kind, const char *packer, uint8_t format,
		      uint8_t subtype, char *out, size_t cap);

/*
 * The target word a finding is scoped to: "ELF-x64", or "ELF" when the object
 * has no architecture to speak of.
 *
 * Composed in three places inside the scanner before this, with the same
 * two-line rule about KGENOME_ARCH_ANY written out each time.
 */
void kverdict_target(char *out, size_t cap, uint8_t format, uint8_t arch);

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

/* The syndrome verdict as a finding: "Infected <type>:Agent", the Predict and
 * Ambiguous forms, or Unresolved. Call only when synd->n_query is non-zero. */
void kof_verdict_syndrome(const struct kof_verdict_in *in, struct kof_finding *f);

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

typedef struct kof_engine  kof_engine;
typedef struct kof_scanner kof_scanner;

/*
 * Reported once per object the engine scanned, including ones with no findings.
 *
 * `name` is what the object was reached by - a path for a file, later a member name
 * inside an archive - so one callback covers the whole tree with no special case for
 * the root. Return 0 to carry on, non-zero to abort the walk.
 *
 * A callback rather than one result per call, because an object can yield children: a
 * directory yields files, and an archive will yield members. One result cannot hold a
 * tree, and a caller that had to poll for the next one would be reimplementing the
 * walk it just delegated.
 */
/*
 * Called once per object, including the ones the engine produced itself.
 *
 * `bytes` and `len` are the object as it was scanned, and for a produced object -
 * a decompressed archive entry, an unpacked executable - they are the only place
 * it exists: it was never a file and it is gone once this returns. A host that
 * wants to write out what an unpacker recovered has nothing else to write, which
 * is why they are here rather than left to a second, richer callback that could
 * disagree with this one.
 *
 * The pointer is valid for the duration of the call and no longer. Copy what you
 * mean to keep.
 *
 * Return non-zero to abandon the walk.
 */
typedef int (*kof_on_object)(const char *name, const void *bytes, uint64_t len,
			     const struct kof_result *res, void *user);

/*
 * A VERDICT WAS REACHED. Called once per verdict, with it already decoded.
 *
 * This exists because the alternative was every host walking the findings
 * array and deciding which entries count - and that decision is the
 * ENGINE'S. A scanner is an interface: it takes what the user asked for and
 * shows what the engine answered. The moment it filters findings it is
 * deciding what a scan reports, and the next tool decides differently.
 *
 * `verdict` is the composed line, through kof_verdict_name, so a host never
 * assembles one and two hosts cannot assemble it differently. `f` is behind
 * it for a host that wants the parts as values rather than as text - the
 * enums on kof_finding - and `object` is where it was found, which is the
 * object's name and not the file's.
 *
 * WHEN IT FIRES. Once per finding the engine is reporting: one per subject
 * normally, and once per match when the caller asked for all of them. A
 * finding that fired and was superseded does not reach here; it is still in
 * kof_result for an examiner that wants to see the working.
 */
typedef void (*kof_on_event_detected)(const char *object,
				      const char *verdict,
				      const struct kof_finding *f,
				      void *user);

/*
 * How a scan is allowed to spread, and how thorough it has to be.
 *
 * Data, and passed per scan rather than set on the engine: a limit is the caller's
 * business, not a property of the database, and two callers in one process must be
 * able to differ.
 *
 * Zeroing the struct gives the conservative answer everywhere - no recursion - so a
 * caller that forgets a field does not get a surprise, it gets less.
 */
/*
 * Values for kof_scan_option.emu_use, and NEVER is the one a memset gives.
 *
 * The other options here default to the useful setting because they cost
 * nothing when they do not apply. This one is different: interpreting an object
 * is the largest thing a scan can do - measured, a UPX-with-LZMA sample needs
 * forty million instructions to reach its payload and the biggest in the corpus
 * needed two hundred and fifty - so a caller gets it by asking, not by omitting
 * a field. kofscanner asks for it at --heur 2.
 */
enum kof_emu_use {
	KOF_EMU_NEVER = 0,  /* interpret nothing, whatever the object looks like */
	KOF_EMU_AUTO  = 1,  /* after every unpacker declined, if the gate fires */
	KOF_EMU_ONLY  = 2   /* interpret instead of the packer modules, ungated */
};

/*
 * The highest heuristic level this build knows.
 *
 * For a caller that means "everything" rather than a particular number -
 * kofexaminer and kofviewer both do, because they look at one object somebody
 * is sitting in front of. Named so that adding a level moves this and not
 * every caller, which is what the comment in kofexaminer has always said it
 * wanted and could not have until levels existed.
 */
#define KOF_HEUR_LEVEL_MAX 2u

struct kof_scan_option {
	/*
	 * Where a verdict goes when the engine reaches one - see
	 * kof_on_event_detected. NULL for a caller that only wants the results.
	 */
	kof_on_event_detected on_event_detected;
	void                 *event_user;

	/*
	 * WHETHER A SCAN DECIDES TO ANALYSE IS THE DATABASE'S: a diagnose
	 * declares the symbols or the file attributes that make an object worth
	 * the walk, and the engine routes on that declaration. There is no switch
	 * that turns the analysis on for every object, because a switch beside the
	 * declaration was a second way to make one decision, and the one that
	 * could not be measured - it ran the most expensive thing the engine does
	 * on files nothing had recognised.
	 *
	 * report_diag IS A DIFFERENT QUESTION: not "should this object be
	 * analysed" but "tell me what each diagnose made of it", asked by a tool
	 * for the one object a person is looking at. It is not a verdict and it
	 * changes none: the report is built after every verdict is final. See
	 * kof_result.diag.
	 */
	int      report_diag;

	int      recurse_dirs;     /* descend into directories */
	/*
	 * HOW DEEP INTO DIRECTORIES, and that is now all it means.
	 *
	 * It used to mean both: the walk applied it to directory depth AND to
	 * object depth, so a caller asking for three levels of folders also
	 * said "stop unpacking after three layers", and a caller wanting a
	 * flat scan of a deep tree could not say so at all. Two policies on
	 * one number, and neither expressible alone.
	 *
	 * That is the same mistake this file already fixed once, and said so:
	 * see `pdepth` in scan.c, split from `depth` because "conflating them
	 * was the bug". This is the third axis and it gets its own field for
	 * the same reason.
	 */
	uint32_t max_depth;        /* 0 -> a built-in ceiling applies */
	/*
	 * THERE IS NO SEPARATE DEEP-SCAN FLAG. It is heur_off, below.
	 *
	 * There WAS one, and a second switch for it was the mistake: --heur 0
	 * already means "name families and nothing else - gather no facts, score
	 * nothing, produce no evidence that is not a match", and descending into
	 * a file is exactly that kind of evidence. A caller asking for the
	 * cheapest possible pass was therefore asking for both, and two switches
	 * meant they could be set inconsistently - a scan that gathered nothing
	 * and still paid to open every container, or the reverse.
	 *
	 * So: heur 0 does not descend, heur 1 and above do. One question, one
	 * field, and the levels already document what each one is for.
	 *
	 * What NOT descending does not turn off: the parse. A container still
	 * declares what it holds - see ctx->entries - so a caller still learns
	 * that there are twenty-five images inside without paying to open one,
	 * and a region still covers their bytes so a rule can still search them.
	 * Not descending means "do not open", never "do not look".
	 */
	/*
	 * HOW DEEP INTO THE OBJECT TREE, when descending at all.
	 *
	 * Zero means the built-in allowance, which is not a constant: it falls
	 * with the size of the thing being descended into, from 64 layers for
	 * something small to a floor of 4 for anything past 64MB. See
	 * depth_allowance in scan.c for why a floor matters as much as a
	 * ceiling.
	 */
	uint32_t max_object_depth;
	int      follow_symlinks;  /* off is the only safe default: a link into an
				    * ancestor turns a walk into a loop */

	/*
	 * Keep going after the first finding on an object.
	 *
	 * Off by default, which is both the cheap answer and the conservative one:
	 * once an object has been named, running the rest of the database on it buys
	 * a longer list and nothing else. An on-access hook only ever needs to know
	 * whether to block.
	 *
	 * On costs the whole database per infected object and is what a report wants:
	 * an object can belong to two families, and a list that stops at one is a
	 * list that says nothing about the other.
	 *
	 * The trade to know about: with this off, which name is reported depends on
	 * where the matching module happens to sit in the database, because the scan
	 * stops at the first one that fires. Every scanner that stops early has this
	 * property; naming it here is cheaper than rediscovering it from a bug report
	 * about a sample that changed its name after a database update.
	 */
	int      all_matches;

	/*
	 * SCAN THESE BYTES AS THIS FORMAT, skipping the sniff chain.
	 *
	 * Zero - what a memset gives - identifies the object the ordinary way,
	 * from its bytes, and that is right for anything that came off a disk.
	 *
	 * It is not right for everything. A collected event has no magic to
	 * sniff and a submitted script block is not a file format at all, so
	 * both come out unidentified - and an unidentified object is offered to
	 * no module, because format is what the prefilter rules on. The caller
	 * that pulled the record off a channel is the only side that knows what
	 * it is holding, so this is how it says.
	 *
	 * The declared format's parser still runs and may still refuse: being
	 * told is not being right, and a refusal leaves the object unidentified
	 * exactly as a failed sniff would.
	 */
	uint8_t  as_format;

	/*
	 * WHAT THE BYTES DO NOT SAY, for the parser named by as_format.
	 *
	 * as_format says what this object is. This says the part of "what it
	 * is" that is not in the object at all, and there are two of those
	 * already. A collected event carries its submitted content somewhere in
	 * the middle of the record, and only the client that took the record
	 * off the channel knows where. An image read out of a process is a PE
	 * whose sections sit at their VIRTUAL addresses rather than their file
	 * offsets, and only the caller that read it knows that; a PE parsed the
	 * ordinary way would resolve every region to the wrong bytes and match
	 * nothing, quietly.
	 *
	 * Both are already fields of the parser's own view - kof_amsi_view has
	 * obj_off, kgenome_pe_info has layout - so this is a PREFIX OF THAT VIEW,
	 * copied in before the parse runs. Not a second vocabulary: adding a
	 * declared input to a format means adding a field to its view near the
	 * front, and nothing here changes.
	 *
	 * WHY IT HAD TO EXIST. Before it, the view on the declared path was
	 * zeroed on the first scan and reused unzeroed on every one after, so
	 * an AMSI object's content extent was 0 the first time - OBJDATA
	 * swallowed the metadata and METADATA came back empty - and stale the
	 * rest of the time. The two regions did not partition anything and no
	 * caller could make them.
	 *
	 * Borrowed for the duration of the call. Ignored without as_format, and
	 * ignored - not truncated - if it is longer than the view it is for: a
	 * caller and an engine that disagree about a view's size disagree about
	 * its layout too, and half-copying one would put arbitrary bytes into
	 * fields the parse trusts.
	 */
	const void *as_view;
	uint32_t    as_view_len;

	/*
	 * THE HEURISTIC'S OFF SWITCH, AND WHY IT IS AN OFF SWITCH.
	 *
	 * Zero - the default a memset gives - RUNS the heuristic. It used to be
	 * the other way round and that was wrong: the evidence level 0 scores is
	 * evidence the parse and the unpackers have already produced by the time
	 * this is reached, so having to ask for it meant paying for the facts and
	 * then throwing them away. A caller who wants nothing but named families
	 * sets this, and then nothing is gathered and nothing is scored - the
	 * collector is not entered at all.
	 *
	 * What a heuristic reports is always its own level and never INFECT. It
	 * works from traces that cannot establish identity, only that something
	 * is worth a look, and a verdict that named a family from this evidence
	 * would be claiming more than it measured.
	 */
	uint32_t heur_off;

	/*
	 * WHICH --heur LEVEL THIS SCAN IS, so a rule can be gated to one.
	 *
	 * ZERO MEANS UNSTATED and is read as 1, which is what every rule ran at
	 * before there was a choice. That is deliberate rather than tidy: there
	 * is no initialiser for this struct - callers declare it on the stack
	 * and clear it - so a field whose useful default is 1 arrives as 0, and
	 * treating 0 as "off" would silently disable every heuristic for every
	 * caller that has not been updated.
	 *
	 * Level 0 is not spelled here either; it is heur_off above. A rule
	 * declaring KOF_HEUR_LEVEL higher than this is not entered. See
	 * kofmod/heur.h.
	 */
	uint32_t heur_level;

	/*
	 * WHEN THE INTERPRETER RUNS, and zero is the useful default - like
	 * heur_off above and for a related reason: it costs nothing on an
	 * object it declines.
	 *
	 * It is entered only after every unpacker has declined the object, and
	 * only when the object either hides its code behind something too dense
	 * to be code or carries a header that cannot be loaded as written.
	 * Measured over 1 246 clean binaries - /usr/bin and the unpacked half
	 * of the packed-ELF corpus - that gate selects none of them, so an
	 * ordinary scan never reaches the interpreter at all.
	 *
	 * KOF_EMU_NEVER is for a caller whose answer must not depend on running
	 * anything: the interpreter never executes a guest instruction on the
	 * host, but it is still the largest thing a scan can be asked to do,
	 * and a caller with a hard time bound has a right to refuse it.
	 *
	 * KOF_EMU_ONLY is not a faster AUTO and is not for scanning. It skips
	 * the packer modules and interprets whatever it is given, gate or no
	 * gate, because a person has asked to see what the object does rather
	 * than what a module says about it. Comparing the two answers is the
	 * whole point of having it - a static unpacker and an interpreter
	 * disagreeing about the same file is a finding.
	 */
	uint32_t emu_use;

	/*
	 * The caller said never and means it, so a heuristic rule may not ask
	 * for the emulator on any object.
	 *
	 * A separate flag because emu_use cannot tell the two apart: --heur 1
	 * leaves it NEVER meaning "not on by default", and --emu never leaves it
	 * NEVER meaning "not at all". A rule's ask is exactly the thing that
	 * should turn the first into emulation and must not touch the second.
	 */
	uint32_t emu_forbidden;


	/*
	 * What producing children is allowed to cost.
	 *
	 * Two different limits, because they answer two different questions and
	 * conflating them was a mistake worth recording. One bounds MEMORY AT ANY
	 * INSTANT; the other bounds TOTAL WORK over the whole tree. A single number
	 * cannot do both: made small enough to protect memory it refuses ordinary
	 * archives, and made large enough for those it stops protecting memory.
	 *
	 * max_resident_bytes is the hard one, and the reason this engine exists in
	 * the shape it does. Objects are mapped, not read, so a 12GB scan holds a
	 * few megabytes; producing children is the only path that allocates, and it
	 * must not throw that away. Default 128MB. Counted over everything produced
	 * and still alive - the object being emitted plus every child not yet
	 * scanned - and released as each child is finished with.
	 *
	 * It is counted even for output written to a temporary file. That looks
	 * over-cautious and is not: a temporary directory is very often tmpfs, where
	 * the "spill to disk" is still memory and is additionally capped by a mount
	 * option this engine cannot see.
	 *
	 * max_produced_bytes is the bomb defence: total bytes a whole tree may
	 * yield, not per child. Per-child limits are how a container full of entries
	 * that are each individually reasonable adds up to something that is not.
	 * A single layer of DEFLATE reaches about 1000:1, so a bomb needs no nesting
	 * and a depth limit never sees it. Zero means max(64MB, object size x 64).
	 *
	 * max_object_bytes is the third, and it is the one that decides how much
	 * WORK a scan does rather than how much memory it holds. The other two are
	 * reached only by an object that is trying; this one is reached constantly,
	 * because inflating an entry is the expensive thing a scan does and most
	 * entries are tiny while a few are enormous. Measured over 1352 real zip
	 * entries: median 255 bytes, 95th percentile 92KB, and the handful above
	 * 8MB accounted for 98.2% of every byte decoded.
	 *
	 * Zero means 16MB, which is as low as it goes without losing a detection -
	 * 8MB was measured and drops one, because a UPX packed miner unpacking to
	 * 13MB is a large object rather than a padded one. Raising it buys the tails
	 * of large entries and costs decompression on every archive holding one.
	 *
	 * A child that is a window into its parent costs none of the three: nothing
	 * was produced and nothing is resident that was not already. Those are
	 * bounded by max_children and max_depth.
	 */
	uint64_t max_resident_bytes;
	uint64_t max_produced_bytes;
	uint64_t max_object_bytes;
	uint32_t max_children;     /* 0 -> a built-in ceiling applies */

	/*
	 * ALREADY ANSWERED, AND THE ENGINE NEVER LEARNS WHAT ANSWERED IT.
	 *
	 * A sweep of a machine meets the same files every time, and reading the
	 * whole database against a file that has not changed since the last run
	 * is the work a cache exists to avoid. The walk that meets those files
	 * is in here - see kscan_path, and the note there on why a directory
	 * and an archive are the same shape - so the question has to be asked
	 * from in here too.
	 *
	 * WHAT MUST NOT BE IN HERE IS THE CACHE. Two reasons, and they point
	 * the same way:
	 *
	 *   - THE LAYERING. libkoforbit may know this library's types; this
	 *     library must never know orbit's. An identity is whatever the
	 *     PLATFORM says about a file, and a platform is the thing libkofeng
	 *     is deliberately free of - it takes bytes and says what they are.
	 *
	 *   - THE TRUST. Whoever can write a cache decides what this scanner
	 *     calls clean. That is a policy about a machine, and it belongs to
	 *     the tool that was configured for that machine rather than to an
	 *     engine that is the same everywhere.
	 *
	 * So the engine says three things through pointers and is told nothing
	 * else: `seen` before opening a file, `keep` after finding it clean,
	 * `drop` after finding it not. The key is opaque bytes; the engine does
	 * not compute it, read it, or know what it is made of.
	 *
	 * WHY `drop` EXISTS, WHICH IS NOT SYMMETRY WITH `keep`.
	 *
	 * A finding on a file that a cache elsewhere calls clean is the one
	 * piece of news a cache must not miss. It arrives whenever the scan
	 * that found it did not consult that cache - a run told not to trust it
	 * on a machine somebody else has been on, or one under a database whose
	 * answers the stored ones predate. Without this the deep run reports the
	 * detection, the stale entry survives it, and the NEXT ordinary run
	 * skips the file in silence.
	 *
	 * IN A PARALLEL WALK these are called from the worker threads, several at
	 * once, and unlike the object callback they are NOT serialised: a host
	 * whose cache is not safe to share has to lock it itself.
	 *
	 * All NULL - the default - and nothing is cached and nothing is asked.
	 */
	int  (*cache_seen)(void *user, const char *path);
	void (*cache_keep)(void *user, const char *path);
	void (*cache_drop)(void *user, const char *path);
	void  *cache_user;

	/*
	 * ASKED, OFTEN, WHETHER TO GIVE UP. Non-zero means stop.
	 *
	 * The callback already lets a host abandon a walk - "Return non-zero to
	 * abandon the walk" - and for a directory of ordinary files that is
	 * enough, because the callback runs once per object and an object is
	 * quick. It is not enough for the object that is slow: a caller which
	 * asked to stop waits for the CURRENT object to finish first, and
	 * measured on /usr/lib that was 150 to 456 milliseconds, bounded by
	 * whatever the largest shared object in the tree happens to cost.
	 *
	 * So this is asked INSIDE an object as well - between modules, and
	 * between the children an unpacker produced - where the callback
	 * cannot reach. The engine stops at the next one of those rather than
	 * at the next object.
	 *
	 * IT MUST BE CHEAP AND IT MUST NOT BLOCK. It is called on a hot path
	 * and may be called from several threads at once; reading a flag is
	 * what it is for. It must not print, allocate or take a lock that the
	 * caller's own callback also takes.
	 *
	 * AN OBJECT STOPPED THIS WAY is reported with what it had found so far, and
	 * is never offered to cache_keep - it was not fully examined, and a cache
	 * that remembered it as clean would skip the file for good.
	 *
	 * NULL - the default - is never asked, and nothing changes for a host
	 * that does not want this.
	 */
	int  (*should_stop)(void *user);
	void  *stop_user;
};

/*
 * Told what a module worked out, as it works it out.
 *
 * `what` is the module's own name for what it worked out and `value` the one
 * number it attached - a version, a count. Called during the module's run, so it
 * arrives before any finding that module goes on to report, which is the order
 * that makes it useful when the finding never comes.
 *
 * Diagnostics, not results: nothing here is a verdict and no scan depends on it.
 * Set it and a debugging tool sees a module's reasoning; leave it unset, which is
 * the default, and modules that emit notes cost a NULL test each.
 */
/*
 * A NOTE, WITH A NUMBER TO MATCH ON RATHER THAN A NAME TO PARSE.
 *
 * `what` is the authored text - "UPX.ELF.version", "Rar.entries" - and is for
 * showing. `fact` is a stable id for the FIELD part of it, the text after the
 * last dot, so a consumer that wants "the version, whoever said it" compares one
 * integer instead of finding a dot and running strcmp.
 *
 * Stable by construction: it is a hash of the field text, so the same field from
 * a later build or a different module is the same id, and a module adding a new
 * field needs no registry and no allocation. Two modules that choose the same
 * field word do collide - which is the same thing that was true when consumers
 * matched on that word, and the module name is right there to tell them apart.
 *
 * Costs nothing to ignore. It exists because the note channel is turning into
 * something a scan path may read per object, and finding a dot in a string per
 * fact per object is the wrong shape for that.
 */
typedef void (*kof_on_debug)(uint32_t fact, const char *what, uint64_t value,
			     void *user);

/*
 * The id for a field name, so a caller can compute the handful it cares about
 * once and then compare integers:
 *
 *     static uint32_t f_version;
 *     if (!f_version) f_version = kverdict_fact_id("version");
 *     if (fact == f_version) ...
 *
 * Takes the field alone, not the full name - kverdict_fact_id("version"), not
 * kverdict_fact_id("UPX.ELF.version").
 */
uint32_t kverdict_fact_id(const char *field);

#endif /* KOFTYPES_H */
