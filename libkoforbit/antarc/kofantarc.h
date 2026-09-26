/*
 * kofantarc.h - collecting what Linux is doing, as seen from outside.
 *
 * THE NAME. Antarctica, because the penguin lives there. The pun names the
 * library; the `kofa_` prefix says which platform it collects from, and that
 * is what somebody reading a call site needs to know. Same bargain libkoforbit/grille
 * made with `kofw_`, for the same reason.
 *
 * This is a SIBLING of libkoforbit/grille, not a port of it. The two answer the same
 * two questions - what happened, and what is here - and answer them with
 * mechanisms that have nothing in common. Where a decision is the same it is
 * the same because the argument is the same, not because the code was copied;
 * where Linux cannot answer what Windows answers, this says so rather than
 * guessing. See aproc.h, which is mostly a list of those places.
 *
 * Nothing here includes kofeng.h. The engine takes bytes and says what they
 * are; this takes the machine's own state and turns it into records. The two
 * meet only where a caller decides to hand one to the other.
 *
 *
 * WHAT THIS FILE IS FOR, since the interesting parts are next door.
 *
 * The errors and the version, shared by every collector here. Each of them
 * includes this, so a caller who already handles kofa_err_name for one does not
 * have to learn a second set of numbers for the next.
 *
 * The stream APIs are in the files that own them - afan.h and apev.h - rather
 * than sketched here, because the first version of the Windows one taught that
 * the shape of a collector is decided by what the stream actually looks like.
 *
 *
 * THE THREE COLLECTORS, and they do not substitute for one another.
 *
 *   aproc.h   what is HERE - every process at this instant, its address space,
 *             and the bytes in any of it. The half a stream cannot supply,
 *             because a stream cannot see backwards.
 *   afan.h    what the FILESYSTEM did, from fanotify. Notify only: no
 *             FAN_CLASS_CONTENT and no FAN_*_PERM. Two modes, and it says
 *             which one it got - see enum kofa_fan_mode.
 *   apev.h    what RAN, from the netlink process connector. A dropper that
 *             writes a file and executes it produces one record in afan and
 *             one here, and only the pair says what happened.
 *
 * amon.h puts all three behind one kof_mon_api, because knowing that two of
 * them report one event twice is knowledge about ANTARC'S OWN collectors.
 *
 *
 * WHAT IS NOT BUILT YET, said plainly.
 *
 * Blocking. FAN_*_PERM is a separate design with a failure mode that hangs the
 * whole machine - a decision loop that dies or falls behind makes every open()
 * on the system wait - and it is not being smuggled in early.
 *
 * (This paragraph read "no event stream: no fanotify, no process events, no
 * detection of any kind" for as long as that was true, and for a while after
 * it stopped being. A header that describes a library it no longer matches is
 * worse than one that says nothing, because it is believed.)
 */

#ifndef KOFANTARC_H
#define KOFANTARC_H

#include <stdint.h>
#include <stddef.h>

/*
 * THE VOCABULARY COMES FROM THERE, NOT FROM HERE.
 *
 * Verbs, locations and techniques are defined once in libkoforbit/kofevt and
 * this library uses them. kofgrille declared its own for one afternoon and
 * mirrored them into kofevt, which is a shape that works exactly until the two
 * copies disagree - and then the conversion between them compiles, runs, and
 * files every module load as a process start.
 *
 * The Linux column of enum kof_evt_loc is already written: systemd units,
 * cron, ~/.config/autostart, .bashrc, /etc/ld.so.preload, authorized_keys,
 * /etc/shadow, /lib/modules, /var/www, /etc/hosts. This library FILLS that in.
 * It does not add to it without the same rule being true on Windows.
 *
 * Not a dependency on the engine: kofevt includes stdio, stdint and stddef and
 * nothing else.
 */
#include "kofevt.h"

/*
 * THE COLLECTOR'S OWN VERSION, separate from the engine's and separate from
 * kofgrille's.
 *
 * It can be built, shipped and replaced without libkofeng changing, and a
 * reader of a log wants to know which COLLECTOR produced it. Not the build
 * stamp either - that is a date, and a date answers "is this the binary I just
 * made". This answers "which contract do these records follow".
 */
#define KOFA_MAJOR 0u
#define KOFA_MINOR 1u

/*
 * WHAT WENT WRONG, and the set is small on purpose.
 *
 * A caller can act on exactly four things: it asked for something that does
 * not exist, it was not allowed, the machine was out of something, or the
 * kernel here does not do this. Everything else is detail that belongs in a
 * message, not in a branch. `errno` is preserved by every call that sets
 * KOFA_ERR_OS, so the detail is there for whoever wants to print it.
 */
enum kofa_err {
	KOFA_OK = 0,

	/* The process is gone, or the path is not there. On a /proc walk this
	 * is ROUTINE and not a failure: processes exit while being enumerated,
	 * and a walk that treated it as an error would fail on any busy
	 * machine. */
	KOFA_ERR_GONE,

	/* Refused. Another user's process, or one whose /proc entry is hidden
	 * by hidepid. Reported rather than skipped, for the reason wproc.h
	 * gives about protected processes: a scanner that quietly skipped them
	 * would report "checked every process" over a set it never saw. */
	KOFA_ERR_DENIED,

	/* Out of memory. */
	KOFA_ERR_NOMEM,

	/* The kernel does not offer this: no /proc/<pid>/pagemap, no
	 * process_vm_readv. Distinct from DENIED, because one is fixed by
	 * privilege and the other is not fixed at all. */
	KOFA_ERR_UNSUPPORTED,

	/* Anything else, with errno left intact. */
	KOFA_ERR_OS,

	KOFA_ERR_COUNT
};

/* "ok", "gone", "denied", ... Never NULL. */
const char *kofa_err_name(int err);

#endif /* KOFANTARC_H */
