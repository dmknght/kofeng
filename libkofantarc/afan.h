/*
 * afan.h - what the filesystem is doing, from fanotify.
 *
 * THE STREAM HALF of libkofantarc, and the sibling of aproc.h: that one
 * answers "what is here", this one answers "what just happened". A machine
 * compromised before this started produces a perfectly clean stream, which is
 * why both halves exist.
 *
 * NOTIFY ONLY. There is no FAN_CLASS_CONTENT here and no FAN_*_PERM: this
 * watches and never decides whether an open succeeds. Blocking is a separate
 * design with a failure mode that hangs the whole machine - a decision loop
 * that dies or falls behind makes every open() on the system wait - and it is
 * not being smuggled in early.
 *
 *
 * ============================================================
 * TWO MODES, AND ONE OF THEM CANNOT SEE WHO DID IT
 * ============================================================
 *
 * Measured on this kernel, as an ordinary user and as root:
 *
 *   fanotify_init(FAN_CLASS_NOTIF)                  EPERM unprivileged
 *   fanotify_init(NOTIF | FAN_REPORT_DFID_NAME)     works unprivileged
 *   fanotify_init(NOTIF | FAN_REPORT_PIDFD)         EPERM unprivileged
 *   fanotify_mark(FAN_MARK_FILESYSTEM, "/")         EPERM unprivileged
 *   fanotify_mark(FAN_MARK_ADD, "/some/dir")        works unprivileged
 *
 * So an unprivileged listener runs. What it gets back is the problem:
 *
 *   pid=80712  CREATE  self.txt     <- an event THIS process caused
 *   pid=0      CREATE  kid.txt      <- an event anything else caused
 *
 * The kernel fills `pid` only for events the listener itself raised and zeroes
 * it for everything else, deliberately, so an unprivileged listener cannot
 * learn which process touched what. For a security sensor that is not a
 * reduced answer, it is the WRONG HALF of the answer: "a file appeared in
 * /tmp" with no actor is not evidence of anything, and kofgrille says the same
 * thing from the Windows side - for a file event the raiser IS the actor and
 * is the single most important column in the record.
 *
 * The second loss is coverage. A DIRECTORY mark reports only dirent events -
 * create, delete, move - because the mark is on the directory and not on the
 * files in it. FAN_CLOSE_WRITE, FAN_MODIFY and FAN_OPEN_EXEC never arrive.
 * Measured: marking a directory with all three and writing a file in it
 * produced CREATE and nothing else. Reaching those needs a MOUNT or
 * FILESYSTEM mark, which needs CAP_SYS_ADMIN.
 *
 * WHAT THIS LIBRARY DOES ABOUT IT: it runs in either mode and SAYS WHICH. A
 * degraded session is reported through kofa_fan_mode and every record it
 * produces carries KOF_F_PID in `miss` rather than a pid of zero - because
 * zero is a legal pid and a consumer that cannot tell "absent" from "zero"
 * will eventually decide something on a field nobody supplied.
 *
 * The unprivileged mode earns its keep as a TEST SURFACE, not as a product:
 * every line below - the event walk, the name assembly, the verb mapping, the
 * record - is exercised by it on a machine with no root, which is what a CI is.
 */

#ifndef KOFANTARC_AFAN_H
#define KOFANTARC_AFAN_H

#include <stdint.h>

#include "kofantarc.h"
#include "kofmon.h"

/* What a session actually got. */
enum kofa_fan_mode {
	/*
	 * CAP_SYS_ADMIN: a filesystem or mount mark, real pids, and the
	 * per-file events. This is the product.
	 */
	KOFA_FAN_FULL = 0,

	/*
	 * Unprivileged: directory marks, dirent events only, and a pid on
	 * nothing but this process's own actions. Useful for testing the
	 * pipeline and for nothing else - see the note above.
	 */
	KOFA_FAN_DEGRADED = 1
};

const char *kofa_fan_mode_name(int mode);

struct kofa_fan_option {
	/*
	 * Directories to watch, NULL-terminated, or NULL for the whole
	 * filesystem.
	 *
	 * WHOLE-FILESYSTEM IS THE DEFAULT AND NEEDS PRIVILEGE. A sensor that
	 * watched a list of directories would miss a dropper that picked one
	 * that is not on it, and the list nobody can complete is exactly the
	 * shape of an evasion that costs an attacker nothing. When the mark
	 * is refused this falls back to the directories given - and when
	 * there are none, to the caller's own temporary directory, so a test
	 * has something to watch.
	 */
	const char *const *dirs;

	/*
	 * REPORT THIS PROCESS'S OWN EVENTS. Off by default.
	 *
	 * A scanner reads files; reading them raises events; those events
	 * make it read more. That is the feedback loop the self-filter
	 * exists to break, and it is the same one kofw_mon_option.trace_self
	 * describes.
	 *
	 * IT IS A TRAP IN THE DEGRADED MODE AND THE TRAP IS WORTH NAMING:
	 * unprivileged, the only events that carry a pid at all are this
	 * process's own, so the self-filter drops exactly the events that
	 * have an actor and keeps the ones that do not. A test that wants to
	 * see its own writes has to set this.
	 */
	int trace_self;

	/* Ring capacity in records; 0 takes a default. */
	uint32_t capacity;
};

struct kofa_fan;

/*
 * Open a session. NULL on failure with *err set to a kofa_err.
 *
 * KOFA_ERR_UNSUPPORTED when the kernel has no fanotify at all, which is
 * different from KOFA_ERR_DENIED - one is fixed by privilege and the other is
 * not fixed.
 */
struct kofa_fan *kofa_fan_open(const struct kofa_fan_option *opt, int *err);

/* Which of the two modes this session got. */
int kofa_fan_mode(const struct kofa_fan *);

/* How many paths it is actually watching, and the i'th of them. */
uint32_t    kofa_fan_watch_count(const struct kofa_fan *);
const char *kofa_fan_watch_at(const struct kofa_fan *, uint32_t i);

/*
 * The collector as a sensor sees it - see libkoforbit/kofmon/kofmon.h.
 *
 * Borrowed, valid for the session's life. This is the whole reason the record
 * conversion is in here: the sensor holds one of these and never learns which
 * platform filled it.
 */
const struct kof_mon_api *kofa_fan_api(struct kofa_fan *);

void kofa_fan_close(struct kofa_fan *);

#endif /* KOFANTARC_AFAN_H */
