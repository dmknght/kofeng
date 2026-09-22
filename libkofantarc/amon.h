/*
 * amon.h - BOTH Linux collectors behind one kof_mon_api.
 *
 * WHY THIS IS A UNIT AND NOT A FEW LINES IN A TOOL.
 *
 * Linux answers "what is this machine doing" with two mechanisms that have
 * nothing in common: fanotify for files and the netlink process connector for
 * execs and exits. A caller that wants what Windows gets from one ETW session
 * therefore has to open two things, drain both without starving either, and
 * know that they report one event twice.
 *
 * That knowledge is about ANTARC'S OWN COLLECTORS, so it belongs here. It did
 * not: it lived inside kofwatchtower as three static functions, which meant
 * kofmontrace - the other tool, doing the same job interactively - had only
 * the file half, and a Linux trace showed no process starts at all while the
 * Windows build of the same tool showed seven providers. Moving it is what
 * makes the two platforms comparable, which is the whole point of the neutral
 * kof_mon_api.
 *
 * WHAT A CALLER GETS THAT IT WOULD NOT GET BY OPENING BOTH ITSELF:
 *
 *   NEITHER STREAM STARVES. Each call drains both with no wait before either
 *   blocks, and then waits on both descriptors at once. Asking one with the
 *   full budget hands the machine to whichever is busier - on a build host
 *   that is the file stream, and process records age in a socket nobody is
 *   reading. Measured: `whoami` exists for 0.5 ms and `ls` for 0.74 ms, and
 *   their command line is read out of /proc, which is empty the moment they
 *   are gone.
 *
 *   ONE EXEC IS NOT TWO EVENTS. fanotify sees the binary opened with intent
 *   to execute and files an image load; the connector sees the exec and files
 *   a process start. Both are correct and both are wanted - an image load is
 *   how a library dropped in /tmp becomes visible - but a program's OWN binary
 *   produces one of each. The image load is the one dropped, because the start
 *   carries the parent, the command line and the verdict-bearing path.
 *
 *   THE PATH TRAVELS BETWEEN THEM. fanotify got the image path from the
 *   kernel without racing anything; the connector is about to need exactly
 *   that path and its own source is /proc. The hand-off happens here because
 *   here is the only place holding both.
 *
 * NEITHER COLLECTOR MAY DECIDE ANY OF THIS ALONE: afan running by itself is
 * the only thing reporting that exec, so a library that suppressed it would
 * turn a duplicate into a gap.
 */

#ifndef KOFANTARC_AMON_H
#define KOFANTARC_AMON_H

#include "kofantarc.h"
#include "afan.h"
#include "apev.h"
#include "kofmon.h"

struct kofa_mon;

struct kofa_mon_option {
	/* Passed through to the file collector - see kofa_fan_option. */
	struct kofa_fan_option fan;

	/*
	 * OPEN THE PROCESS COLLECTOR TOO. On by default, which is what the
	 * zeroed struct means: `no_procs` rather than `procs`, so a caller
	 * that memsets and fills nothing gets both halves. A caller wanting
	 * only files - a watch on one path, where a process stream would be
	 * noise - says so.
	 */
	int no_procs;
};

/*
 * Opens what it can and SAYS what it got rather than failing when one half is
 * refused: the process connector needs a privilege the file one does not, and
 * a session with files alone is still a session. NULL only when neither
 * opened; *err is then the file collector's reason.
 */
struct kofa_mon *kofa_mon_open(const struct kofa_mon_option *opt, int *err);
const struct kof_mon_api *kofa_mon_api(struct kofa_mon *);
void kofa_mon_free(struct kofa_mon *);

/*
 * The two halves, for a caller that has to report on them separately - the
 * fanotify mode and the reason the process connector was refused are things an
 * operator needs and the neutral api has no field for. NULL when that half is
 * not open.
 */
struct kofa_fan *kofa_mon_fan(struct kofa_mon *);
struct kofa_pev *kofa_mon_pev(struct kofa_mon *);
int              kofa_mon_pev_err(struct kofa_mon *);

#endif /* KOFANTARC_AMON_H */
