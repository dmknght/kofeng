/*
 * apev.h - what processes are being started and stopped, from the netlink
 * process connector.
 *
 * THE THIRD COLLECTOR, and the one the other two cannot stand in for. aproc.h
 * answers "what is here" and afan.h answers "what did the filesystem do"; this
 * answers "what ran". A dropper that writes a file and executes it produces
 * one record in afan and one here, and only the pair says what happened.
 *
 *
 * ============================================================
 * WHY THERE IS NO UNPRIVILEGED MODE, WITH THE NUMBERS
 * ============================================================
 *
 * afan runs in a degraded mode when it cannot have the privileged one, because
 * a directory mark still reports real events and is worth having. There is no
 * equivalent here, and it is not for want of looking.
 *
 * The only unprivileged way to see processes on Linux is to scan /proc and
 * diff, and a scan cannot see a process that has already exited. Measured on
 * this machine - 150 children per run, born every 5 ms, each reaped by its
 * parent as soon as it was gone, which is what makes a zombie stop standing in
 * for a process that is still there:
 *
 *   scan every   | exits at once | lives 20 ms | lives 200 ms
 *   -------------+---------------+-------------+--------------
 *    1000 ms     |       0%      |      0%     |      0%
 *     250 ms     |       0%      |      6%     |     74%
 *     100 ms     |       0%      |     14%     |     89%
 *      20 ms     |       0%      |     74%     |     99%
 *
 * A process that exits immediately is caught NEVER, at any interval anybody
 * would run. That is not a reduced answer: `sh -c "curl ...| sh"` is the shape
 * of the thing being looked for, and it lives microseconds. A collector built
 * on polling would report the long-running processes - which aproc already
 * enumerates, without pretending to be a stream - and silently miss every
 * short one. So this library does not offer it.
 *
 * What is left is the netlink process connector, which needs CAP_NET_ADMIN.
 *
 *
 * ============================================================
 * THE KERNEL DOES NOT SAY NO, SO THE SESSION HAS TO ASK
 * ============================================================
 *
 * Measured unprivileged on this kernel (7.0.7), every step reporting success:
 *
 *   socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR)   ok
 *   bind(nl_groups = CN_IDX_PROC)                       ok
 *   setsockopt(NETLINK_ADD_MEMBERSHIP, CN_IDX_PROC)     ok
 *   getsockname -> nl_groups                            0x00000001
 *   send(PROC_CN_MCAST_LISTEN)                          ok
 *   ... and then nothing arrives. No event, no ack, no NLMSG_ERROR.
 *
 * There is no errno to branch on. A collector that assumed the stream was
 * live because nothing failed would sit silent forever and report a quiet
 * machine, which is the worst thing a sensor can do.
 *
 * SO THE SESSION PROVES IT INSTEAD. kofa_pev_open raises an event it knows the
 * answer to - it forks a child that does nothing but exit - and waits briefly
 * for that child to come back out of the socket. A stream that delivers the
 * probe is live; one that does not is reported as KOFA_ERR_DENIED and the
 * session is not opened. It tests the thing itself rather than a proxy for it,
 * which also means it keeps working if a kernel changes which capability it
 * wants or how it refuses.
 *
 *
 * WHAT A RECORD CARRIES, AND WHAT IT CANNOT.
 *
 * The connector reports pids and nothing else - no path, no command line. Both
 * are read from /proc the moment the event arrives, and that is a race the
 * collector cannot win: a process that has already exited has no /proc entry
 * left to read. The fields are then reported MISSING rather than empty, for
 * the reason afan.h gives about a pid of zero.
 *
 * NOTIFY ONLY, like afan: this watches and never decides whether an exec
 * succeeds.
 */

#ifndef KOFANTARC_APEV_H
#define KOFANTARC_APEV_H

#include <stdint.h>

#include "kofantarc.h"
#include "kofmon.h"

struct kofa_pev_option {
	/*
	 * REPORT THIS PROCESS'S OWN CHILDREN. Off by default.
	 *
	 * A scanner that spawns helpers would otherwise watch itself work.
	 * Same bargain as kofa_fan_option.trace_self, and with the same trap
	 * reversed: here the probe in kofa_pev_open is this process's own
	 * child, so the filter is applied AFTER the probe rather than to it.
	 */
	int trace_self;

	/*
	 * How long kofa_pev_open waits for its own probe to come back, in
	 * milliseconds. 0 takes a default.
	 *
	 * It is a timeout on a local socket carrying an event this process
	 * just caused, so it is short; it is configurable because a loaded
	 * machine can make anything late and a sensor that refused to start
	 * on a busy host would be useless exactly when it is wanted.
	 */
	uint32_t probe_ms;
};

struct kofa_pev;

/*
 * Open a session. NULL on failure with *err set.
 *
 *   KOFA_ERR_UNSUPPORTED  the kernel has no process connector at all
 *   KOFA_ERR_DENIED       it has one and this process may not listen - see
 *                         the note above on why that is discovered by probing
 */
struct kofa_pev *kofa_pev_open(const struct kofa_pev_option *opt, int *err);

/* The collector as a sensor sees it - see libkoforbit/mon/kofmon.h. */
const struct kof_mon_api *kofa_pev_api(struct kofa_pev *);

/*
 * IS THIS EXEC-OPEN THE BINARY OF A PROCESS THAT JUST STARTED?
 *
 * THE TWO COLLECTORS SAY THE SAME THING ABOUT ONE EXEC. fanotify reports
 * FAN_OPEN_EXEC when a file is opened with intent to execute, which afan files
 * as an image load; the connector reports the exec itself, which this files as
 * a process start. Run together - and running both is the point - a program's
 * own binary produces both records, and a consumer counting executions counts
 * it twice.
 *
 * The answer lives here because only this session knows which pid started with
 * which image and when. It is NOT applied here: afan run on its own is the
 * only thing reporting that exec at all, and a library that suppressed it
 * would turn a duplicate into a gap. The sensor asks, because the sensor is
 * what knows both are running.
 *
 * `now_ns` is a CLOCK_MONOTONIC-ish stamp in the connector's own units, or 0
 * when the caller has none - then the image match alone decides. A long-lived
 * process re-opening its own binary is a real event, not the start already
 * reported, which is what the window is for.
 */
int kofa_pev_is_own_image(struct kofa_pev *, uint32_t pid, const char *path,
			  uint64_t now_ns);

/*
 * THE PATH FROM SOMEWHERE THAT DID NOT HAVE TO RACE FOR IT.
 *
 * The connector names a pid and nothing else, so this collector reads the
 * image out of /proc - and a process that has already exited has no /proc
 * entry left. Observed on a real host: an obfuscated shell running `whoami`
 * produced three starts and none of them could be named.
 *
 * fanotify does not have that problem. FAN_OPEN_EXEC fires when the kernel
 * opens a binary in order to execute it, it carries the path as a file handle
 * the kernel resolves, and it arrives BEFORE the exec completes - so a sensor
 * running both collectors already holds the answer this one is racing for.
 *
 * It is a HINT and not an assertion: the pid is recorded against the path and
 * used for the next start on that pid, and a start that already has an image
 * keeps it. The caller is the sensor, because the sensor is what has both
 * streams - see the note on kofa_pev_is_own_image, which the same table
 * answers.
 *
 * WHAT THIS CANNOT FIX IS THE COMMAND LINE. fanotify reports the file, not the
 * arguments; argv exists only in the exiting process's own memory and in
 * /proc, so it stays a race that only audit or eBPF can take out. A record
 * that lost it says so - see KOF_EF_CMDLINE_RACED.
 */
void kofa_pev_hint_image(struct kofa_pev *, uint32_t pid, const char *path);

void kofa_pev_close(struct kofa_pev *);

#endif /* KOFANTARC_APEV_H */
