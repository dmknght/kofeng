/*
 * kofmod/heur.h - writing a rule-based heuristic.
 *
 * NOT kofsig.h WITH A LOWER CEILING. A heuristic answers a different question
 * and is allowed to do less, and both of those are why it has its own header
 * and its own module kind rather than a convention inside the detector's.
 *
 *   a signature says   "these bytes ARE that family"
 *   a heuristic says   "this object has a shape clean software does not"
 *
 * So a rule here names no family, reports nothing above KOF_LVL_HEUR, and
 * produces no child objects. The build refuses all three - see ksigcompiler.sh -
 * because a rule that could report INFECT would be a signature written in the
 * wrong file, and the difference matters to a reader of the output: a family
 * name is a claim about identity, a heuristic word is a claim about shape.
 *
 *
 * THE TWO PHASES, AND WHY THERE ARE EXACTLY TWO
 *
 * An object's life in the scanner is: parse, run the signatures, open it
 * (unpack, and the children recurse), then score. A rule declares which of two
 * points it wants, and the phase is a PREFILTER FIELD - a rule that asked for
 * one is not considered at the other, at no cost.
 *
 *   KOF_HEUR_EXAMINE   after the signatures, BEFORE the object is opened.
 *                      Sees the bytes and the parse. This is the only phase
 *                      that can still change what the engine does with the
 *                      object, because opening it has not happened yet.
 *
 *   KOF_HEUR_VERDICT   after it has been opened and its children scanned.
 *                      Sees everything EXAMINE sees plus how the unpacking
 *                      went - packed, gave up part way, too many layers.
 *
 * A rule that wants to say "this is a shape" wants EXAMINE. A rule that wants to
 * say "this was reached in a way clean software is not" wants VERDICT.
 *
 *
 * ASKING THE ENGINE FOR SOMETHING
 *
 * A rule may ask for work to be done on the object it just fired on - today the
 * only thing to ask for is the emulator. The ask is DECLARED, not called:
 *
 *     KOF_HEUR_WANT(KOF_ENG_USE_EMU);
 *
 * Declared for three reasons, and they are worth more than the flexibility a
 * runtime call would add. It is greppable - which rules can turn the emulator
 * on is a question with an answer in the source. It is fixed at build time, so
 * a hostile object cannot steer the engine by what it contains, only by whether
 * it matches. And it CANNOT LEAK: there is no state to set, so "this object
 * asked for the emulator" cannot become "the rest of the scan uses it" - the
 * bug that would otherwise be waiting in a runtime switch.
 *
 * The engine may still refuse. An explicit --emu never on the command line
 * wins, --heur 0 skips these modules entirely at the prefilter, and there is a
 * ceiling on how many times a scan will honour the ask. A rule asks; it does
 * not decide.
 *
 * Only meaningful at EXAMINE - at VERDICT the object has already been opened -
 * and the build says so rather than letting it read as working.
 */

#ifndef KOFMOD_HEUR_H
#define KOFMOD_HEUR_H

#include "kofsig.h"

/*
 * When the rule runs. Exactly one per module, and required: a rule with no
 * phase is a rule whose author has not decided what it is looking at.
 */
enum kof_heur_phase_id {
	KOF_HEUR_EXAMINE = 0,
	KOF_HEUR_VERDICT = 1
};

/* What a rule may ask the engine to do with the object it fired on. A mask, so
 * two rules asking for the same thing is the same request. */
enum kof_eng_want {
	KOF_ENG_USE_EMU = 1u << 0    /* interpret this object's entry point */
};

/*
 * All three expand to nothing: ksigbuilder reads them out of the source, the
 * same way KOF_TARGET_FORMAT is read. See the note on that macro in kofsig.h
 * for why a declaration the compiler cannot see is the right shape here.
 */
#define KOF_HEUR_PHASE(p)
#define KOF_HEUR_WANT(w)

/*
 * What the rule is called - the word that appears where a family name would.
 *
 * "Shellcode", not "Trojan:Shellcode": the engine writes the Heur part, and a
 * rule that spelled a maltype would be claiming to have identified something.
 */
#define KOF_HEUR_NAME(word)

/*
 * WHAT THE RULE THINKS THIS WILL TURN OUT TO BE. Optional.
 *
 * A guess about identity, kept apart from KOF_HEUR_NAME because the two are
 * different claims and a reader has to be able to tell them apart:
 *
 *     KOF_HEUR_NAME("Shellcode")    the SHAPE, which the rule established
 *     KOF_HEUR_PREDICT("Meterp")    the FAMILY it expects, which it has not
 *
 * It is written into the finding after a '?', so the object reads
 *
 *     ELF-x64/Heur:Shellcode?Meterp
 *
 * and the question mark is the whole point: this is a prediction and nothing
 * has confirmed it. The moment a signature matches on real bytes - the payload
 * an unpacker or the emulator recovered - that signature's name supersedes the
 * finding entirely and the guess is gone. A prediction never becomes a verdict
 * by being repeated; it is replaced by evidence or it stays a question.
 *
 * It also STEERS: an object predicted to be family F has F's decoders tried
 * first. That is a reordering and never a filter - every decoder still runs when
 * the predicted one produces nothing - so a wrong prediction costs the ordering
 * and nothing else. See unp_order in scan.c.
 */
#define KOF_HEUR_PREDICT(family)

/*
 * Entry point. One per module, and a module exporting kof_scan or kof_unpack as
 * well is refused - the three ABIs are different and a module is one kind.
 */
void kof_heur(const struct kof_obj_ctx *ctx);

#define KOF_DEFINE_HEUR void kof_heur(const struct kof_obj_ctx *ctx)

/*
 * Fire.
 *
 * Reports and returns in one statement, the way KOF_SCAN_INFECT does and for
 * the same reason: neither half can then be forgotten. The variant is a hash of
 * the line that fired, so the name is stable across rebuilds without a registry
 * - again as the detector's macros work.
 */
#define KOF_HEUR_HIT()                                                      \
	do {                                                                \
		(ctx)->report((ctx), (uint32_t)KOF_LVL_HEUR,                \
			      (uint32_t)__LINE__);                          \
		return;                                                     \
	} while (0)

#endif /* KOFMOD_HEUR_H */
