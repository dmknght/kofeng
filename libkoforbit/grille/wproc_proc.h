/*
 * wproc_proc.h - a process and a module: the records, the list walk. *
 * A part of <wproc.h>, which includes it: include that, not this. Split from it by
 * purpose; the text is unchanged.
 */

#ifndef KOFGRILLE_WPROC_PROC_H
#define KOFGRILLE_WPROC_PROC_H

#include <stdint.h>
#include <stddef.h>
#include "kofgrille.h"

/* ------------------------------------------------------------- a process */

/*
 * WHAT THE PROCESS IS BUILT FOR, which on this tree's own build host is not a
 * rhetorical question.
 *
 * An ARM64 Windows machine runs ARM64 processes, ARM64EC processes, x64
 * processes under emulation and 32-bit ARM processes, and the system directory
 * a given one of those resolves is different for each. A rule written as "not
 * under System32" is wrong for three of the four unless it knows which it is
 * looking at.
 *
 *
 * THE VOCABULARY IS kofevt's, AND THIS FILE NO LONGER HAS ONE OF ITS OWN.
 *
 * There was an enum kofw_arch here - UNKNOWN, X86, X64, ARM, ARM64 - and it was
 * a value-for-value copy of enum kof_evt_arch, which kofevt.h already declares
 * and which this header already has in scope. Nothing was gained by the second
 * spelling and one thing was risked: kofw_proc.arch is a uint8_t that a record
 * or a report will eventually be filled from, and those fields are typed as
 * kof_evt_arch. The two agreed today by coincidence of ordering, so the
 * conversion compiled, ran, and would have gone on being right until either
 * list gained a value.
 *
 * That is the failure kofgrille.h describes at its own top, about verbs: two
 * copies of one list "works exactly until the two copies disagree - and then
 * the conversion between them compiles, runs, and files every module load as a
 * process start". One list, declared where the neutral vocabulary lives.
 *
 * So: KOF_EARCH_* and kof_evt_arch_name. What stays local is enum
 * kofw_integrity below, because a mandatory label is a Windows concept and
 * there is no neutral one to defer to.
 */

/*
 * The mandatory label, which is the cheapest answer to "could this have
 * touched that".
 *
 * A medium-integrity process cannot write to a high-integrity one, cannot open
 * it for memory access, and cannot have injected into it. Half of the "who did
 * this" questions a snapshot raises are settled by comparing two of these
 * before anything else is looked at.
 */
enum kofw_integrity {
	KOFW_INTEG_UNKNOWN = 0,
	KOFW_INTEG_UNTRUSTED,
	KOFW_INTEG_LOW,
	KOFW_INTEG_MEDIUM,
	KOFW_INTEG_HIGH,
	KOFW_INTEG_SYSTEM,
	KOFW_INTEG_COUNT
};

/* "untrusted", "low", "medium", "high", "system", or "?". Never NULL. */
const char *kofw_integrity_name(uint8_t integ);

/* kofw_proc.flags */
enum {
	/* A 32-bit process on a 64-bit machine. Its System32 is SysWOW64, and
	 * its PEB is not the one this library reads - see wcmdline.c. */
	KOFW_PF_WOW64        = 1u << 0,

	/* The token says elevated. Not the same as high integrity and not
	 * implied by it: a service running as SYSTEM is system-integrity and
	 * was never elevated by anybody. */
	KOFW_PF_ELEVATED     = 1u << 1,

	/*
	 * NO HANDLE. The process is protected, or it is at a higher integrity
	 * than this one, or it went away between the snapshot and the query.
	 *
	 * Everything that needed a handle - the full path, the creation time,
	 * the token, the architecture - is absent, and this flag is the only
	 * thing that distinguishes that from a process which genuinely has
	 * none of them. kofw_pmem_open on it will fail for the same reason.
	 */
	KOFW_PF_REFUSED      = 1u << 2,

	/* The image path could not be read, so `image` is the base name the
	 * snapshot carried - a name, not a location, and never openable. */
	KOFW_PF_NO_PATH      = 1u << 3,

	/*
	 * The command line was asked for and not obtained. Distinct from an
	 * empty one for the reason KOFW_EF_CMDLINE_RACED exists: a process
	 * started with no arguments and a process nobody could read are
	 * different facts, and only one of them is about the program.
	 */
	KOFW_PF_CMDLINE_LOST = 1u << 4,

	/* This process. Set so a scanner can decline to scan itself, which it
	 * otherwise does on every run and reports its own pattern tables. */
	KOFW_PF_SELF         = 1u << 5,

	/* The image path, the command line, or both were longer than the
	 * buffer. Flagged for the reason KOFW_EF_TRUNCATED is: a cut path
	 * still looks like a path. */
	KOFW_PF_TRUNCATED    = 1u << 6
};

struct kofw_proc {
	/*
	 * WHEN IT STARTED, in the units kofw_evt.stamp uses, and it is here
	 * for the same reason it is there: a pid is reused, so the pid alone
	 * does not name a process. Anything that looks a pid up later and acts
	 * on it - opening it, scanning it, killing it - acts on whatever holds
	 * that number now, and the pair is what makes that safe.
	 *
	 * kofw_pmem_open takes it and checks it, which is the whole reason a
	 * snapshot can be walked slowly without becoming a hazard.
	 *
	 * Zero when no handle could be obtained - KOFW_PF_REFUSED.
	 */
	uint64_t create_time;

	uint32_t pid;

	/*
	 * The parent's pid, AS THE SNAPSHOT RECORDS IT - which is to say, a
	 * number and not a process. Windows keeps the number after the parent
	 * exits and reuses it like any other, so a long-running child very
	 * often names a parent that is something else entirely now. It is
	 * worth having and it is not evidence on its own; the stream half of
	 * this library is where a parentage that was WITNESSED comes from.
	 */
	uint32_t ppid;

	uint32_t session_id;
	uint32_t threads;      /* as of the snapshot */
	uint32_t flags;        /* KOFW_PF_* */

	uint8_t  arch;         /* enum kof_evt_arch - kofevt.h, not a local copy */
	uint8_t  integrity;    /* enum kofw_integrity */
	uint8_t  loc;          /* enum kof_evt_loc, of `image` */
	uint8_t  reserved;
	uint16_t attack;       /* enum kof_attack, of `image` */
	uint16_t reserved2;

	/*
	 * TWO BORROWED STRINGS, NEVER NULL, VALID UNTIL THE NEXT CALL on the
	 * handle that produced them - the next kofw_plist_next, or the
	 * kofw_pmem_close.
	 *
	 * Borrowed rather than inline, because a command line is up to 32767
	 * characters and a struct that could hold one would be 64KB, copied
	 * once per process, to carry a field most callers never read. A caller
	 * that keeps a table copies what it wants, which is the same bargain
	 * kofw_mon_tracked_nth makes.
	 */
	const char *image;     /* the full path, or the base name - see
				* KOFW_PF_NO_PATH */
	const char *cmdline;   /* "" when not asked for, or lost */
};

/* kofw_plist_option.want */
enum {
	/*
	 * Nothing beyond what the snapshot itself carries: pid, ppid, thread
	 * count, base name, session. No handle is opened, so nothing can be
	 * refused and no process is missed.
	 *
	 * Implied by every other bit. Set it ALONE to ask for a list that
	 * costs one syscall in total.
	 */
	KOFW_PW_BASIC   = 1u << 0,

	/* The full image path, the creation time and the architecture. One
	 * handle per process. */
	KOFW_PW_PATH    = 1u << 1,

	/* Integrity level and elevation. One token open per process, on top of
	 * the handle KOFW_PW_PATH already needs. */
	KOFW_PW_TOKEN   = 1u << 2,

	/*
	 * The command line, read out of each process's own PEB.
	 *
	 * BY FAR THE MOST EXPENSIVE BIT HERE, and the only one that needs
	 * PROCESS_VM_READ - which is a materially stronger right than the rest
	 * of this file asks for, and which several processes will refuse on a
	 * hardened machine.
	 */
	KOFW_PW_CMDLINE = 1u << 3,

	KOFW_PW_ALL     = KOFW_PW_BASIC | KOFW_PW_PATH | KOFW_PW_TOKEN |
			  KOFW_PW_CMDLINE
};

struct kofw_plist_option {
	/* A mask of KOFW_PW_*. Zero - which is what a memset gives - takes
	 * KOFW_PW_ALL, because the caller who has not thought about it wants
	 * the whole picture rather than the fast one. */
	uint32_t want;

	/* Just this process, and nothing else. 0 walks every one of them. The
	 * cheap way to ask about one pid without opening it. */
	uint32_t only_pid;
};

struct kofw_plist;

/*
 * Take the snapshot. NULL on failure, and *err is a KOFW_ERR_*. `err` may be
 * NULL.
 *
 * NEEDS NO ELEVATION FOR THE LIST ITSELF - every process is enumerated whoever
 * asks. What elevation buys is how many of them will grant a handle, and that
 * difference shows up as KOFW_PF_REFUSED rather than as a shorter list.
 */
struct kofw_plist *kofw_plist_open(const struct kofw_plist_option *, int *err);

/*
 * The next process. 1 if one was filled in, 0 at the end.
 *
 * The snapshot is a snapshot: a process that exits during the walk is still
 * reported, and one that starts during it is not. That is the property that
 * makes the walk terminate, and it is why every use of a pid from here goes
 * back through create_time.
 */
int kofw_plist_next(struct kofw_plist *, struct kofw_proc *out);

void kofw_plist_close(struct kofw_plist *);

/* -------------------------------------------------------------- a module */

/* kofw_module.flags */
enum {
	/* The process's own image, rather than something it loaded. */
	KOFW_MDF_MAIN    = 1u << 0,

	/*
	 * THE FILE BEHIND IT IS NOT THERE ANY MORE.
	 *
	 * A module is mapped from a file and the mapping keeps that file
	 * alive, so the path resolving to nothing means it was deleted or
	 * renamed AFTER the load. That is what a dropper does to its own
	 * payload, and it is one of the few facts in this file that is hard to
	 * produce by accident - though an installer replacing its own files
	 * mid-run produces it too.
	 */
	KOFW_MDF_NO_FILE = 1u << 1,

	/* No path at all: the loader has no name for this one. */
	KOFW_MDF_UNNAMED = 1u << 2,

	/*
	 * THE MAPPED FILE IS GONE AND SOMETHING ELSE IS AT ITS PATH NOW.
	 *
	 * A module was updated underneath a running process: the old file was
	 * unlinked - it stays alive because the mapping holds it - and a new
	 * one was written at the same path. The process goes on running the old
	 * bytes until it restarts.
	 *
	 * IT IS THE SAME OBSERVATION AS KOFW_MDF_NO_FILE AND A DIFFERENT FACT,
	 * which is the whole reason it has its own bit. Both say "the file this
	 * mapping came from has been unlinked". Only one of them says anybody
	 * removed anything: here the path still resolves, to a NEWER file, and
	 * that is what an update looks like from the outside.
	 *
	 * MEASURED, and it is why this exists. Three modules on this machine
	 * had NO_FILE set - VCRUNTIME140, VCRUNTIME140_1 and MSVCP140, all
	 * inside Office ClickToRun, all mapped from \$Extend\$Deleted, and all
	 * three of their original paths still holding a file. Office had
	 * updated its own runtime while its process was running. A rule reading
	 * NO_FILE as "a dropper removed its payload" fires on every machine
	 * with Office on it and is right about none of them.
	 *
	 * COMMON ON LINUX, WHERE IT HAS ALWAYS BEEN KNOWN. aproc.h says it of
	 * KOFA_RGF_DELETED in as many words - "what every in-place package
	 * upgrade leaves behind, which is why it is a fact and not a finding",
	 * measured at 94 mappings on an ordinary desktop. Every apt upgrade of
	 * a running service produces them. The Windows half said the opposite
	 * about the same condition; this is the distinction that lets both be
	 * right.
	 */
	KOFW_MDF_REPLACED = 1u << 3
};

struct kofw_module {
	uint64_t base;
	uint64_t size;
	uint64_t entry;
	uint32_t flags;        /* KOFW_MDF_* */
	uint8_t  loc;          /* enum kof_evt_loc, of `path` */
	uint8_t  reserved[3];
	uint16_t attack;       /* enum kof_attack, of `path` */
	uint16_t reserved2;

	/* Borrowed, never NULL, valid until the next call on this handle. */
	const char *path;
};

#endif /* KOFGRILLE_WPROC_PROC_H */
