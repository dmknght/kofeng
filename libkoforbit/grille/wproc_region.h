/*
 * wproc_region.h - a memory region: its kind, its use, its flags and the record. *
 * A part of <wproc.h>, which includes it: include that, not this. Split from it by
 * purpose; the text is unchanged.
 */

#ifndef KOFGRILLE_WPROC_REGION_H
#define KOFGRILLE_WPROC_REGION_H

#include <stdint.h>
#include <stddef.h>
#include "kofgrille.h"

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
	KOFW_RGF_UNEXAMINED  = 1u << 8,

	/*
	 * AN IMAGE THE LOADER DOES NOT ADMIT TO HAVING.
	 *
	 * The region is a real image section - the kernel mapped it with
	 * SEC_IMAGE and there is a file behind it - but its allocation base is
	 * not in the process's module list. That is the shape of LDR
	 * UNLINKING: a module loaded normally and then removed from the
	 * loader's own lists so that anything asking the loader is told it is
	 * not there.
	 *
	 * WHY THIS IS NOT KOFW_RGF_UNBACKED, and the distinction is the whole
	 * point. `UNBACKED` asks "is there a FILE behind this executable
	 * memory", which catches a payload copied into VirtualAlloc. An
	 * unlinked module answers that question perfectly well - it has a file,
	 * GetMappedFileNameW names it - so it was never questioned. The
	 * question this asks is a different one: "does the LOADER know about
	 * it". Two lists that should agree and do not.
	 *
	 * BOTH SETS WERE ALREADY COLLECTED. The region walk had them and the
	 * module walk had them and nothing compared the two, which is why a
	 * technique that leaves both halves intact went unseen.
	 *
	 * NOT A VERDICT ON ITS OWN. A resource-only image - a .mui, anything
	 * mapped with LOAD_LIBRARY_AS_IMAGE_RESOURCE - is deliberately absent
	 * from the module list and is entirely ordinary. See the note in
	 * wproc.c on what separates the two and on what the measured rate is.
	 */
	KOFW_RGF_UNLINKED    = 1u << 9,

	/*
	 * A THREAD STARTED IN THIS REGION - see KOFW_MW_THREADS.
	 *
	 * The flag that turns "there is executable memory here" into "code
	 * here has been run", and it is the second half of every unbacked
	 * finding this walk makes. A decoded buffer nobody jumped to and a
	 * payload with a thread in it are the same bytes in the same kind of
	 * page; only this separates them.
	 *
	 * ON ITS OWN IT IS ORDINARY. Every thread of every process starts in
	 * some region, so this is set on the main image of everything running
	 * - measured, 1167 of 1167 threads on an idle workstation started
	 * inside a mapped image. It means something only in company: with
	 * UNBACKED, with a manual map, with DATA_EXEC. The flag states the
	 * fact and the rule decides.
	 *
	 * SET ONLY WHERE THREADS WERE ASKED FOR. Without KOFW_MW_THREADS it is
	 * never set, which means its absence is not evidence of anything.
	 */
	KOFW_RGF_THREAD      = 1u << 10
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
 * Here rather than in a tool for the reason kofw_health_print_extra is here: the
 * flags are this library's vocabulary, and three tools printing them three ways
 * is three chances to print a bit that no longer means what the printer thinks.
 */
size_t kofw_region_describe(const struct kofw_region *, char *buf, size_t cap);

#endif /* KOFGRILLE_WPROC_REGION_H */
