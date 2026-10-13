/*
 * wproc.h - what is running right now, and what is inside it.
 *
 * THE OTHER HALF OF THE GRILLE, AND IT LOOKS THE OPPOSITE WAY.
 *
 * kofgrille.h collects a STREAM: things that happen, in the order they happen,
 * from the moment the session opened. That has one property it can never fix -
 * it cannot see backwards. A machine that was compromised on Tuesday and had a
 * sensor installed on Thursday produces a perfectly clean stream, because
 * everything that mattered happened before anything was watching, and the
 * payload that is still resident has not raised an event since.
 *
 * This is the SNAPSHOT: every process that exists at this instant, every module
 * it has mapped, every committed region of its address space, and the bytes in
 * any of them. It answers "what is here" rather than "what happened", and those
 * two questions have never been answerable by one mechanism.
 *
 * Shape:
 *
 *     struct kofw_plist *l = kofw_plist_open(NULL, &err);
 *     struct kofw_proc   p;
 *
 *     while (kofw_plist_next(l, &p)) {
 *             struct kofw_pmem  *m = kofw_pmem_open(p.pid, p.create_time,
 *                                                   NULL, &err);
 *             struct kofw_region r;
 *
 *             if (!m)
 *                     continue;
 *             while (kofw_pmem_next_region(m, &r))
 *                     if (r.flags & KOFW_RGF_UNBACKED)
 *                             ... kofw_pmem_read(m, r.base, buf, n) ...
 *             kofw_pmem_close(m);
 *     }
 *     kofw_plist_close(l);
 *
 *
 * STILL NO JUDGING, AND THAT IS NOT A TECHNICALITY HERE.
 *
 * Nothing in this file includes kofeng.h, for the reason the top of
 * kofgrille.h gives: the engine takes bytes and says what they are, and this
 * takes the machine's own state and turns it into records. What makes the rule
 * worth restating is that this is the file where it is TEMPTING to break -
 * "executable, private, and a PE header in it" is three facts away from a
 * verdict, and a scanner that shipped the verdict would be a scanner nobody
 * can tune, test against a corpus, or disagree with.
 *
 * So kofw_region carries the three facts. Whoever put them together owns the
 * conclusion, and the raw protection value and the raw path sit beside them so
 * that conclusion can be checked. Every flag below is something that is TRUE of
 * a region, never something that is WRONG with it - a JIT compiler produces
 * unbacked executable memory all day, and so does every .NET process on the
 * machine.
 *
 *
 * WHAT THIS COSTS, SAID BEFORE IT IS PAID
 *
 * A stream costs a callback per event. A snapshot costs a handle per process
 * and a kernel query per region, and a busy workstation has four hundred
 * processes and tens of thousands of committed regions. That is not a
 * background activity, and nothing here pretends otherwise: every field that
 * costs an extra syscall is behind a bit in the option struct, and the walk is
 * an iterator rather than a list so a caller that wants twelve processes pays
 * for twelve.
 *
 *
 * IT WILL BE REFUSED, ROUTINELY, AND THAT IS REPORTED RATHER THAN HIDDEN
 *
 * Protected processes - PPL: the antimalware services, csrss, the DRM host -
 * cannot be opened for memory access by anything, elevated or not. A scanner
 * that quietly skipped them would report "checked every process" over a set it
 * never saw, which is the failure mode this tree treats as worse than an error:
 * see kof_broken and kofw_health for the same argument in two other places. So
 * the process still appears in the list, carrying KOFW_PF_REFUSED, and the
 * caller learns the difference between clean and never-looked-at.
 *
 * The text is in three parts by purpose, included below: wproc_proc.h (a process and
 * a module), wproc_region.h (a region) and wproc_pmem.h (one process, opened).
 */

#ifndef KOFGRILLE_WPROC_H
#define KOFGRILLE_WPROC_H

#include <stdint.h>
#include <stddef.h>

/*
 * For the KOFW_ERR_* codes and kofw_err_name, which are the collector's and
 * are shared rather than duplicated: a caller that already handles them for
 * kofw_mon_open should not have to learn a second set of numbers for the same
 * five failures. kofgrille.h includes kofevt.h and nothing from the engine, so
 * this inherits that property too.
 */
#include "kofgrille.h"
#include "wproc_proc.h"
#include "wproc_region.h"
#include "wproc_pmem.h"

#endif /* KOFGRILLE_WPROC_H */
