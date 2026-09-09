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
 */
enum kofw_arch {
	KOFW_ARCH_UNKNOWN = 0,
	KOFW_ARCH_X86,
	KOFW_ARCH_X64,
	KOFW_ARCH_ARM,
	KOFW_ARCH_ARM64,
	KOFW_ARCH_COUNT
};

/* "x86", "x64", "arm", "arm64", or "?". Never NULL. */
const char *kofw_arch_name(uint8_t arch);

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

	uint8_t  arch;         /* enum kofw_arch */
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
	KOFW_MDF_UNNAMED = 1u << 2
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

/* -------------------------------------------------------------- a region */

/*
 * WHAT THE MEMORY IS, as the kernel accounts for it, and the three answers are
 * not degrees of the same thing.
 *
 * IMAGE   mapped from a PE by the loader. The kernel knows the file, shares
 *         the pages with every other process that mapped it, and can prove
 *         where they came from.
 * MAPPED  a section that is not an image: a data file, or the page file.
 * PRIVATE VirtualAlloc. Nothing backs it, nothing else sees it, and the only
 *         account of how the bytes got there is that something wrote them.
 *
 * Executable code in the third is not rare and not evidence, but it is the only
 * one of the three where nobody can say what the code is supposed to be.
 */
enum kofw_rgn_kind {
	KOFW_RGN_PRIVATE = 0,
	KOFW_RGN_MAPPED,
	KOFW_RGN_IMAGE,
	KOFW_RGN_COUNT
};

/* "private", "mapped", "image". Never NULL. */
const char *kofw_rgn_kind_name(uint8_t kind);

/*
 * WHAT THE MEMORY IS FOR, which is this library's reading rather than the
 * kernel's account - and it is a SECOND field rather than a replacement for
 * `kind`, for the reason kofw_evt keeps obj_loc beside the raw path: a
 * classification is a decision that can be wrong, and what it was decided from
 * is the only thing that lets somebody check.
 *
 *
 * THIS IS NOT A REGION VOCABULARY FOR THE ENGINE, AND THE DIFFERENCE MATTERS.
 *
 * There was a version of this that was: a memory format with its own declared
 * regions, the way an AMSI event has META and OBJ. It is the obvious design and
 * it is wrong, because of what it does to the rules that already exist.
 *
 * A manually mapped DLL in private memory IS A PE. Handed over as a "memory
 * object" it is offered to whatever modules target memory - which is nothing,
 * on the day the format is added - and every PE signature in the database sits
 * the scan out. The format axis is what the prefilter rules on, so declaring a
 * new one does not ADD a way to look at these bytes, it REPLACES the one that
 * was already there and already had rules written for it.
 *
 * So there is no memory format. A region that carries a PE goes to the engine
 * as a PE and the existing modules run on it unchanged; a region that carries
 * anything else goes as bytes, exactly as any unidentified object does. What
 * this enum decides is which of those two a region is, and whether it is worth
 * handing over at all - a scan policy and a provenance record, not a partition
 * for a rule author to name.
 *
 *
 * WHAT A MEMORY SCAN ACTUALLY BUYS, since it is less than it first looks.
 *
 * Everything a loaded module's memory holds is also in the file it came from,
 * minus relocations and imports. Scanning it finds what scanning the file would
 * have found, so the value is entirely in the DELTA: bytes that are in memory
 * and are not in any file. Unpacked code, a decrypted configuration, a payload
 * that only ever existed in a buffer.
 *
 * And that delta has no guaranteed lifetime. A decoded config is freed as soon
 * as it is parsed; a stager's buffer is gone microseconds after the transfer.
 * So a memory scan that finds nothing has not established that nothing was
 * there - it has established that nothing was there WHEN IT LOOKED, which is a
 * much smaller claim and is the honest one.
 *
 * Two things follow, and both are why the defaults below are what they are. The
 * regions worth scanning are the ones whose contents PERSIST - a module's code
 * lives as long as the module, and private executable memory lives as long as
 * anything can call into it - which is exactly the set KOFW_MW_EXEC_ONLY
 * selects. And a scan is worth far more when something triggered it than when a
 * timer did, because the trigger is what says the bytes are still there.
 */
enum kofw_rgn_use {
	/* Not committed, or not worked out. */
	KOFW_USE_UNKNOWN = 0,

	/* Mapped from a PE by the loader. Comparable against the file it came
	 * from, which is what makes hook and hollow detection possible. */
	KOFW_USE_IMAGE,

	/* Executable, with no file behind it: a manually mapped module, a
	 * reflective loader's payload, plain shellcode. The one value here
	 * that is worth an alert on its own strength. */
	KOFW_USE_CODE,

	/*
	 * Private, writable, not a stack.
	 *
	 * Named HEAP because that is what nearly all of it is, and read as
	 * "the process's own working data" rather than as "the heap manager's
	 * segments" - nothing here reads the heap manager's own structures, so
	 * a plain VirtualAlloc of a buffer lands here too.
	 *
	 * THE WEAKEST PLACE IN THIS ENUM TO MATCH, for two reasons that
	 * compound rather than overlap.
	 *
	 * Every byte the process has ever read passes through here: an
	 * installer holds its payload here, a browser holds a download here,
	 * and a scanner holds whatever it was scanning here. A pattern found
	 * in this region says the process TOUCHED those bytes and says nothing
	 * whatever about the process being the thing that made them.
	 *
	 * And what is here stays only as long as the program has a use for it,
	 * which is very often microseconds. So a match is weak evidence and a
	 * MISS IS NOT EVIDENCE AT ALL - the buffer that would have matched was
	 * probably freed before anything came to look. That is the argument
	 * for KOFW_MW_HEAP being off by default rather than on.
	 */
	KOFW_USE_HEAP,

	/* A thread stack - recognised by the guard page beneath it. Not read
	 * from any thread's own record of where its stack is; see
	 * kofw_pmem_next_region. */
	KOFW_USE_STACK,

	/* Everything else committed: mapped data files, the read-only tail of
	 * whatever the loader left behind. */
	KOFW_USE_DATA,

	KOFW_USE_COUNT
};

/* "image", "code", "heap", "stack", "data", or "?". Never NULL. */
const char *kofw_rgn_use_name(uint8_t use);

/* kofw_region.flags */
enum {
	KOFW_RGF_EXEC        = 1u << 0,
	KOFW_RGF_WRITE       = 1u << 1,

	/* Writable and executable AT THE SAME TIME. Compilers stopped emitting
	 * this decades ago and DEP made it a deliberate request; what still
	 * asks for it is a JIT, a packer, and a loader that has not finished
	 * unpacking itself. */
	KOFW_RGF_RWX         = 1u << 2,

	/* PAGE_GUARD. Reads of it fail, which is why it is said rather than
	 * left to look like a refusal. */
	KOFW_RGF_GUARD       = 1u << 3,

	/*
	 * EXECUTABLE, AND NO FILE BEHIND IT.
	 *
	 * The single most useful bit in this file, and the reason the snapshot
	 * half exists at all. A reflectively loaded DLL, a manually mapped
	 * payload and plain shellcode all end here: they allocate, they copy,
	 * they fix their own relocations, and no section is ever mapped from a
	 * file - so the stream half sees no IMAGE_LOAD, because the event does
	 * not exist. KOFW_EF_UNBACKED is the same fact caught from the other
	 * direction, one thread start at a time, and only in a process the
	 * session watched from birth. This one needs no history.
	 *
	 * It is set for a pagefile-backed MAPPED region too - a section with
	 * no name is backed by nothing anybody can point at either.
	 *
	 * A MAPPED region is only judged unbacked when KOFW_MW_PATHS actually
	 * asked and got no name. With that off, a mapped region is taken as
	 * backed: a check that was not performed must not come back as the
	 * interesting answer, and reading "no name" as "no file" turned every
	 * executable page of every loaded module into a finding.
	 */
	KOFW_RGF_UNBACKED    = 1u << 4,

	/*
	 * A PE HEADER SITS AT THE ALLOCATION BASE, and the allocation is not
	 * an image mapping.
	 *
	 * Which is to say: something laid a whole module out here by hand.
	 * Unbacked memory says "code from nowhere"; this says the code from
	 * nowhere is a DLL, which narrows a JIT's output out of the set almost
	 * completely - a JIT emits functions, not PE headers.
	 *
	 * Set on every run of the allocation, not only the run the header is
	 * in, because the header and the code it describes are different runs
	 * with different protections and the interesting one is the code.
	 *
	 * NEVER SET WHERE A FILE ACCOUNTS FOR THE HEADER. A .mui, a
	 * resource-only DLL, or any other PE that something mapped as data has
	 * a PE header because it IS a PE - seven of them in one powershell.exe,
	 * measured - and reporting those would be seven true statements and no
	 * finding. Needs KOFW_MW_PATHS to make that distinction for a mapped
	 * region; without it, a mapped region is taken as backed and this is
	 * not set. Private memory needs no query, since nothing backs it by
	 * definition.
	 */
	KOFW_RGF_PE          = 1u << 5,

	/*
	 * AN IMAGE PAGE THAT IS PRIVATE TO THIS PROCESS.
	 *
	 * Image pages are shared, by construction, with every process that
	 * mapped the same file - that sharing is what makes the loader cheap.
	 * A page that has stopped being shared is a page somebody WROTE, and
	 * the copy-on-write that followed is the kernel's own record of it.
	 *
	 * That covers inline hooks, IAT patching, an AMSI or ETW stub blown
	 * away, and process hollowing - all of which restore the original page
	 * protection afterwards and are invisible to anything that only looks
	 * at PAGE_* values. Comparing the bytes against the file on disk
	 * answers it too and costs a file read per module; this costs one
	 * query per region and is the reason to look.
	 *
	 * Needs KOFW_MW_DIRTY, and says nothing about pages that are not
	 * resident: an unshared page trimmed out of the working set is not
	 * visible to the query, so this is a floor and not a count.
	 */
	KOFW_RGF_DIRTY_IMAGE = 1u << 6,

	/*
	 * EXECUTABLE, AND THE FILE BEHIND IT IS MAPPED AS DATA.
	 *
	 * Windows has two ways to map a file: as an image, which the loader
	 * does and which the kernel records as such, and as a section, which
	 * anybody can do to anything. Code running out of the second one is a
	 * program that opened a file, mapped it, and jumped into it - which is
	 * how module stomping hides a payload behind a signed file's name, and
	 * is not something a compiler, a loader or a JIT ever produces.
	 */
	KOFW_RGF_DATA_EXEC   = 1u << 7,

	/* The region is larger than kofw_pmem_option.max_region, so its
	 * contents were not examined for the flags that need reading. Said,
	 * rather than left as an absence, for the usual reason. */
	KOFW_RGF_UNEXAMINED  = 1u << 8
};

struct kofw_region {
	uint64_t base;
	uint64_t size;

	/*
	 * THE START OF THE WHOLE ALLOCATION this run belongs to, which is what
	 * groups runs back into the thing that was allocated.
	 *
	 * One manually mapped DLL comes back as four or five separate runs -
	 * the header read-only, .text RX, .data RW - because the walk reports
	 * runs of IDENTICAL PROTECTION. A caller that treats each run as a
	 * find reports one payload five times, and scans its header separately
	 * from its code.
	 */
	uint64_t alloc_base;

	/* Raw PAGE_* values, exactly as Windows reports them. The flags above
	 * are this library's reading of them, and these are what lets somebody
	 * disagree. */
	uint32_t protect;
	uint32_t alloc_protect;

	uint32_t flags;        /* KOFW_RGF_* */
	uint8_t  kind;         /* enum kofw_rgn_kind - the kernel's account */
	uint8_t  use;          /* enum kofw_rgn_use - this library's reading */
	uint8_t  loc;          /* enum kof_evt_loc, of `path` */
	uint8_t  reserved;

	/*
	 * The file behind it, as a DRIVE-LETTER PATH, or "" when nothing backs
	 * it. Never NULL. Borrowed, valid until the next call on this handle.
	 *
	 * Converted rather than passed through, and that is the one place this
	 * file does real work on a string. The kernel names a mapped file as
	 * \Device\HarddiskVolume3\..., and kofwatchman already says what is
	 * wrong with that: a path from an event is not a path a scanner can
	 * open. A region path exists to be handed to whoever scans the file
	 * behind it, so it is converted here, once, where the process is
	 * already open - rather than in each caller, none of which would agree
	 * about the edge cases.
	 *
	 * Needs KOFW_MW_PATHS.
	 */
	const char *path;
};

/*
 * Render one region as a line: address, size, protection, kind, and what is
 * notable about it. Returns bytes written, excluding the NUL, and never writes
 * past `cap`.
 *
 * Here rather than in a tool for the reason kofw_health_print is here: the
 * flags are this library's vocabulary, and three tools printing them three ways
 * is three chances to print a bit that no longer means what the printer thinks.
 */
size_t kofw_region_describe(const struct kofw_region *, char *buf, size_t cap);

/* --------------------------------------------------- one process, opened */

/* kofw_pmem_option.want */
enum {
	/* Resolve the file behind each mapped region. One kernel query and one
	 * path conversion per named region. */
	KOFW_MW_PATHS     = 1u << 0,

	/* Ask which image pages have gone private - KOFW_RGF_DIRTY_IMAGE. One
	 * query per executable image region, over an array of one entry per
	 * page. */
	KOFW_MW_DIRTY     = 1u << 1,

	/* What kofw_pmem_open gives a caller that passes NULL. */
	KOFW_MW_DEFAULT   = KOFW_MW_PATHS | KOFW_MW_DIRTY,

	/*
	 * ONLY REGIONS THAT CAN EXECUTE.
	 *
	 * Off by default, because "what is in this process" is a different
	 * question from "what could run in it", and only the caller knows
	 * which one it is asking. On, it is the difference between three
	 * thousand regions and forty on a browser, and a scanner looking for
	 * code has no use for the other two thousand nine hundred and sixty.
	 */
	KOFW_MW_EXEC_ONLY = 1u << 2,

	/*
	 * REPORT KOFW_USE_HEAP REGIONS AT ALL. Off by default, and the default
	 * is the one every real-time product on the market ships.
	 *
	 * Not because a payload is never there - it very often is, staged in a
	 * buffer before anything makes it executable - but because of what a
	 * match there would MEAN. Every byte a process has ever read passes
	 * through its writable private memory: an installer holds its own
	 * payload there, a browser holds a download there, and a scanner holds
	 * whatever it was just scanning there. A pattern found in a heap says
	 * the process TOUCHED those bytes, and the process that touched a
	 * payload is very often the one that was handling it legitimately.
	 *
	 * So this is the bit that turns a memory scan from "what is running in
	 * here" into "what has been through here", and those are different
	 * questions with different answers and very different false-positive
	 * rates. The caller says which one it is asking.
	 *
	 * KOFW_MW_EXEC_ONLY excludes these whatever this says: a heap that can
	 * execute is KOFW_USE_CODE and was never a heap by this library's
	 * reading.
	 */
	KOFW_MW_HEAP      = 1u << 3
};

struct kofw_pmem_option {
	/* A mask of KOFW_MW_*. Zero takes KOFW_MW_DEFAULT. */
	uint32_t want;

	/*
	 * Regions bigger than this are REPORTED AND NOT EXAMINED - they come
	 * back with KOFW_RGF_UNEXAMINED and without the flags that need their
	 * contents read.
	 *
	 * It exists because a single committed region can be gigabytes: a
	 * database's buffer pool, a .NET GC heap, a VM's guest memory. Reading
	 * a header out of one is free; asking the working-set query about one
	 * is an array of a quarter of a million entries. 0 takes the default,
	 * which is stated in the .c beside the reasoning.
	 *
	 * It does NOT limit kofw_pmem_read, which does exactly what it is
	 * asked.
	 */
	uint64_t max_region;
};

struct kofw_pmem;

/*
 * Open one process for inspection. NULL on failure, and *err is a KOFW_ERR_*.
 * `err` may be NULL.
 *
 * `create_time` is the value kofw_plist_next or an event reported, and it is
 * CHECKED: if the pid now belongs to a different process the open fails with
 * KOFW_ERR_GONE rather than succeeding against the wrong one. Pass 0 only when
 * there is genuinely no discriminator to be had - it means "whatever holds this
 * number now", which is a decision and should look like one at the call site.
 *
 * Needs PROCESS_QUERY_INFORMATION and PROCESS_VM_READ, so in practice it needs
 * elevation for anything outside the caller's own session, and it is refused
 * outright for a protected process however elevated the caller is.
 */
struct kofw_pmem *kofw_pmem_open(uint32_t pid, uint64_t create_time,
				 const struct kofw_pmem_option *, int *err);

/*
 * Who it opened, filled in as far as the handle allowed. Never NULL, and its
 * strings live as long as the handle rather than until the next call.
 *
 * The way to ask about ONE process without enumerating every one of them.
 */
const struct kofw_proc *kofw_pmem_proc(const struct kofw_pmem *);

/*
 * The next mapped module. 1 if one was filled in, 0 at the end.
 *
 * THE LOADER'S OWN LIST, which means it is exactly as honest as the loader. A
 * module unlinked from the PEB list by whoever loaded it - two stores, and the
 * oldest trick in the file - is not here, and the region walk is where it still
 * shows up. The two are worth running together for that reason, and not because
 * either is incomplete on its own.
 *
 *
 * HOW A MODULE LINES UP WITH ITS REGIONS, since a caller needs both walks.
 *
 * An image region's `alloc_base` IS the module's `base`. One module is several
 * regions - the header read-only, the code RX, the data RW - and that field is
 * what joins them back up, exactly as it does for a hand-laid-out allocation.
 *
 *
 * WHY MOST MODULE MEMORY IS NOT WORTH SCANNING, which is the thing that decides
 * what a caller does with this walk.
 *
 * A module's pages are shared with every other process that mapped the same
 * file, and they are shared BECAUSE they are identical to it. Scanning them
 * finds what scanning the file would have found, on a machine where two hundred
 * processes have mapped the same forty DLLs - so the work is repeated hundreds
 * of times to reach an answer that was already available from one file read.
 *
 * The exception is the whole point: a page that has STOPPED being shared is one
 * somebody wrote, and it is the only part of a module that differs from its
 * file. KOFW_RGF_DIRTY_IMAGE marks the regions where that has happened.
 *
 * So the two halves are scanned differently and only one of them is cacheable:
 *
 *   clean module   scan the FILE, and remember the answer against the file's
 *                  identity - not its path, which is chosen by whoever put it
 *                  there and stays the same when the file behind it does not.
 *   dirty region   scan the MEMORY, because that is where the difference is.
 *                  Nothing to cache: this copy exists in one process only,
 *                  which is also why there is so little of it.
 */
int kofw_pmem_next_module(struct kofw_pmem *, struct kofw_module *out);

/*
 * The next committed region. 1 if one was filled in, 0 at the end.
 *
 * COMMITTED ONLY: reserved and free address space is not reported, because
 * there is nothing in it. A 64-bit process reserves terabytes it has never
 * touched, and reporting those would make the walk about the address space
 * rather than about the memory.
 *
 *
 * HOW `use` IS DECIDED, SAID IN FULL, BECAUSE IT IS WHAT A RULE WILL REST ON
 *
 * Four of the six come straight from what the kernel already said, and are as
 * reliable as the kernel is:
 *
 *   IMAGE   Type is MEM_IMAGE.
 *   CODE    the protection allows execution and no file backs it.
 *   DATA    committed, not executable, and something does back it.
 *   UNKNOWN nothing committed here.
 *
 * The other two are told apart by ONE THING - a PAGE_GUARD run immediately
 * below, inside the same allocation, which is how Windows makes a stack grow
 * and is not something a heap has. A private writable allocation with that
 * beneath it is STACK; a private writable allocation without it is HEAP.
 *
 * WHAT THAT TEST CANNOT DO, and it is worth knowing before writing a rule that
 * assumes otherwise:
 *
 *   - A stack whose guard page has already been consumed - a thread that ran
 *     itself close to the end - looks like a heap.
 *   - A fibre's stack, or a stack somebody allocated by hand, has no guard
 *     page and is a heap by this test.
 *   - Nothing stops a program allocating a guard page under a buffer.
 *
 * The alternative is reading every thread's own record of where its stack is,
 * which is exact and needs a structure Windows does not document the layout
 * of. That is a refinement worth having and it is not a foundation worth
 * standing on: whoever is being looked for here can edit those structures, and
 * a walk that DEPENDED on them would report nothing at all about a process
 * that had messed with them - which is the worst possible failure for this
 * particular walk. So the guard-page test decides `use`, from what the memory
 * manager itself reports, and anything read out of the process's own
 * bookkeeping can only ever ADD to what is already there.
 */
int kofw_pmem_next_region(struct kofw_pmem *, struct kofw_region *out);

/*
 * Read from the process. Returns bytes read, which is 0 or short whenever the
 * process refuses, exits, or has an unreadable page in the way.
 *
 * SHORT RATHER THAN FAILED, deliberately. A region with a guard page in the
 * middle of it is normal - every thread stack has one - and a read that
 * returned nothing because the last page of forty refused would throw away the
 * thirty-nine that are the point. So it reads page by page and stops at the
 * first refusal, and the caller scans what came back and knows how much that
 * was.
 *
 * The bytes are a COPY OF A MOVING TARGET. The process keeps running while this
 * reads, so a large read can return a first page from before some write and a
 * last page from after it. That is inherent - there is no way to suspend a
 * process from here that is not worse - and it matters for exactly one thing: a
 * scan of live memory that finds nothing has not proved anything was not there.
 */
size_t kofw_pmem_read(struct kofw_pmem *, uint64_t addr, void *buf, size_t n);

void kofw_pmem_close(struct kofw_pmem *);

#endif /* KOFGRILLE_WPROC_H */
