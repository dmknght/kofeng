/*
 * kofevt.h - deciding whether what a machine DID was malicious.
 *
 * WHAT THIS OWNS, and it is one job stated three ways: an event, normalised
 * to bytes. The verb it happened under, where it happened, which technique
 * that location IS, the record those go in, and the log those records are
 * written to.
 *
 * WHAT IT DOES NOT OWN: collecting. libkoforbit/grille reads ETW and a Linux twin
 * will read whatever Linux offers; both of them produce what is defined here
 * and neither defines any of it. A tool then picks a collector by what it was
 * built for and reads the same record either way.
 *
 * THE ENUMS ARE HERE AND NOWHERE ELSE. They used to be declared in
 * kofgrille.h and mirrored here, which is a shape that works exactly until the
 * two copies disagree - and then a conversion between them compiles, runs, and
 * silently files every module load as a process start. One definition, included
 * by the collector, is the only version of this that cannot rot.
 *
 *
 * WHY IT IS HERE AND NOT IN core/kofmod/
 *
 * It was in core/kofmod/, and that was wrong. That directory is elf.h, pe.h,
 * zip.h, pdf.h, tar.h - descriptions of what a SCANNED TARGET looks like, which
 * a compiled module in bases/ includes in order to read one. An event record is
 * none of those things: it is a format this toolset defines for itself, in the
 * same sense databases/pack/dbcore.h defines .ksig, and filing it beside the
 * target parsers makes both harder to find.
 *
 * The rule, stated so the next file lands correctly: core/kofmod/ is what a
 * compiled module in bases/ includes. Everything else the toolset defines for
 * its own use goes with the code that owns it.
 *
 * NOTHING HERE INCLUDES ANYTHING ELSE FROM libkofeng, and that is structural
 * rather than a promise. This directory is under libkofeng because events are
 * the engine's business eventually, but the files use stdint, stddef and stdio
 * and nothing more - so libkoforbit/grille can include them without acquiring a
 * dependency on the engine, and kofgrille.h's rule that it never includes
 * kofeng.h stays true.
 *
 *
 * WHERE IT SITS
 *
 *     libkoforbit/grille (Windows)  ---\
 *                                 >--- struct kof_evt ---> event rules (designed, not built)
 *     a Linux collector       ---/
 *
 * libkofeng takes bytes and says what they are. This takes a machine's own
 * activity and says the same thing about it. The two meet at a caller, not at
 * an #include: kofgrille.h does not include kofeng.h and must not start.
 *
 * So the record below is NOT struct kofw_evt. kofw_evt is what one collector on
 * one operating system produces; this is what a rule is written against, and a
 * rule that names an ETW event id is a rule that cannot fire on Linux. The
 * translation happens once, in each collector, at the edge - the same argument
 * kofgrille.h already makes for classifying a path there rather than in every
 * consumer.
 *
 *
 * THE ONE FACT THAT SHAPES EVERY DECISION BELOW
 *
 * EVENTS DO NOT ARRIVE IN ORDER. kofgrille.h says it plainly: ETW buffers are
 * per processor, so records cross CPUs out of order and a consumer that needs a
 * sequence has to sort over a window. Linux is no kinder - a perf ring is per
 * CPU too.
 *
 * Every "sequence matching" design collapses on that sentence. A rule engine
 * that matches A-then-B-then-C against the arrival order is not matching what
 * the machine did, it is matching how the buffers drained, and it will miss on
 * a loaded machine and hit on an idle one. It is also the failure mode nobody
 * notices, because the rule still fires sometimes.
 *
 * So the model here is NOT a sequence automaton. It is a set of FACTS per
 * subject, each stamped with when it was first true, and a rule is a predicate
 * over that set. Order, where a rule genuinely needs it, is asked for
 * explicitly as a comparison between two stamps with a tolerance - which is a
 * question the data can actually answer.
 *
 *
 * WHAT IS DELIBERATELY NOT HERE
 *
 * NO SCORE. Not an oversight and not a stage to be added later: every scoring
 * approach over this engine's findings was measured and rejected, the depth
 * term and the heuristic levels were removed after measuring them, and nothing
 * here reopens that. A rule fires or it does not. Two rules firing is two
 * findings, not a bigger number - a reader can see two findings and cannot see
 * what went into a 73.
 *
 * The text is in two parts by purpose, included below: kofevt_vocab.h (the words)
 * and kofevt_record.h (the record and what is done with it).
 */

#ifndef KOFEVT_H
#define KOFEVT_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "../../libkofeng/kofcore/kofdebug.h"   /* KOFENG_BUILD - see below */

#include "kofevt_vocab.h"
#include "kofevt_record.h"

#endif /* KOFEVT_H */
