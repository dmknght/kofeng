/*
 * kofgrille.h - collecting what Windows is doing, as seen from outside.
 *
 * THE NAME. A grille is the barred lattice over a window: the thing you watch
 * through, and the thing that decides what gets through. Both halves are the
 * job - the library watches Windows, and since classification and filtering
 * moved in here it is also what everything passes through on the way out. A
 * consumer sees what the grille let by, and kofw_health says how much it did
 * not.
 *
 * This is a sibling of libkofeng, not a part of it. The engine takes bytes and
 * says what they are; this takes the machine's own activity and turns it into
 * records. The two meet only where a caller decides to hand one to the other,
 * and nothing in this header includes kofeng.h - the first version collects, it
 * does not judge.
 *
 * The symbols stay `kofw_`, deliberately. The pun names the library; the prefix
 * says which platform it collects from, and that is what somebody reading a
 * call site needs to know.
 *
 * Shape:
 *
 *     struct kofw_mon *m = kofw_mon_open(&opt, &err);
 *
 *     struct kofw_evt e;
 *     while (kofw_mon_next(m, &e, 200))
 *             ... e.type, e.pid, kofw_evt_image(&e) ...
 *
 *     kofw_mon_close(m);
 *
 *
 * WHY THE RECORD IS NORMALISED AND NOT AN EVENT_RECORD
 *
 * Three reasons, and the third is the one that pays for the other two.
 *
 *   - An ETW record is only meaningful while its buffer is live, and that
 *     buffer belongs to a callback which must not block. Copying into a fixed
 *     record is what lets the callback return immediately.
 *   - The provider's field layout differs by Windows build. Deciding what a
 *     field MEANS once, at the edge, keeps that difference out of everything
 *     downstream.
 *   - A fixed record can be WRITTEN TO A FILE AND REPLAYED. That is what makes
 *     any of this testable: a detection rule that cannot be run against a
 *     recorded trace cannot be regression tested, and a false positive nobody
 *     can reproduce cannot be fixed. The replay path needs no Windows API at
 *     all, so it also builds and runs on the CI this library could not
 *     otherwise have.
 *
 *
 * WHAT THIS DELIBERATELY DOES NOT DO YET
 *
 * No autologger, so activity before the session starts is not seen - which is
 * the gap that matters most, because a payload that runs at boot runs before
 * this does.
 *
 * WHAT THIS PARAGRAPH USED TO SAY, and did for long after it stopped being
 * true: "No file, registry or network provider. No detection of any kind."
 * There are six providers now - process, file, registry, network, DNS and
 * AMSI - and kofwatchman scans what they carry. A header that undersells the
 * library is not harmless: it is the first thing anybody reads, and somebody
 * deciding whether to add a registry rule would have concluded there was
 * nothing to write one against.
 *
 * What remains absent is DETECTION CONTENT rather than collection. The
 * providers deliver; the database has almost nothing written against what they
 * deliver, and that is the honest statement of where this stands.
 *
 * The text is in three parts by purpose, included below: kofgrille_evt.h (the event
 * record), kofgrille_mon.h (the monitor) and kofgrille_filter.h (filtering,
 * tracking and the rest of the monitor's calls).
 */

#ifndef KOFGRILLE_H
#define KOFGRILLE_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/*
 * THE VOCABULARY COMES FROM THERE, NOT FROM HERE.
 *
 * Verbs, locations and techniques are defined once in libkoforbit/evt and
 * this file uses them. They were declared here and mirrored there for one
 * afternoon, which is a shape that works exactly until the two copies
 * disagree - and then the conversion between them compiles, runs, and files
 * every module load as a process start.
 *
 * This is not a dependency on the engine. kofevt includes stdio, stdint,
 * stddef and nothing else - no kofeng.h, no OS header - which is the property
 * that lets this collector include it and keeps the rule at the top of this
 * file true.
 */
#include "kofevt.h"
#include "kofgrille_evt.h"
#include "kofgrille_mon.h"
#include "kofgrille_filter.h"

#endif /* KOFGRILLE_H */
