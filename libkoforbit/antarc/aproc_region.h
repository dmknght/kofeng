/*
 * aproc_region.h - a memory region: its use, its flags and the record that describes one. *
 * A part of <aproc.h>, which includes it: include that, not this. Split from it by
 * purpose; the text is unchanged.
 */

#ifndef KOFANTARC_APROC_REGION_H
#define KOFANTARC_APROC_REGION_H

#include <stdint.h>
#include <stddef.h>
#include "kofantarc.h"

/* ----------------------------------------------------------------- a region */

/*
 * WHAT THE MEMORY IS FOR - this library's reading, and it is the only
 * classification here because Linux offers no second opinion. See the top of
 * this file on why there is no `kind`.
 *
 * NOT A REGION VOCABULARY FOR THE ENGINE, and the difference matters. There is
 * no memory format: a region carrying an ELF goes to the engine AS an ELF, so
 * every ELF rule in the database runs on it unchanged; anything else goes as
 * bytes. Declaring a new format would not ADD a way to look at these bytes, it
 * would REPLACE the one that already has rules written for it. This enum
 * decides which of those two a region is and whether it is worth handing over
 * at all - a scan policy, not a partition for a rule author to name.
 */
enum kofa_rgn_use {
	/*
	 * NO ACCESS AT ALL - `---p`. Linux's way of saying MEM_RESERVE: an
	 * address range claimed so nothing else takes it, holding nothing and
	 * readable by no one. Measured at 9.1 TB across seven Chromium
	 * processes on an ordinary desktop, which is why it is filtered out by
	 * default rather than merely classified. See the top of this file.
	 *
	 * Also the value for a region this library could not work out.
	 */
	KOFA_USE_UNKNOWN = 0,

	/* Executable and file-backed: a mapped shared object or the main
	 * executable. Comparable against the file it came from, which is what
	 * makes scanning the FILE instead the right move - see
	 * kofa_pmem_next_region on why. */
	KOFA_USE_IMAGE,

	/*
	 * EXECUTABLE WITH NO FILE BEHIND IT, and the reason this half exists.
	 *
	 * Shellcode, a payload mmap'd and mprotect'd into place, a JIT's
	 * output. Measured at 43 regions and about 12 MB across this machine,
	 * which is small enough to scan all of, every time.
	 */
	KOFA_USE_CODE,

	/*
	 * Private, writable, not executable, not a stack. See the long note on
	 * KOFA_MW_HEAP - this is the weakest place in this enum to match and
	 * the most expensive to read.
	 */
	KOFA_USE_HEAP,

	/* A thread stack: [stack], or an anonymous mapping carrying the guard
	 * page pattern below it. */
	KOFA_USE_STACK,

	/* Everything else mapped: file-backed data, [vdso], [vvar], the
	 * read-only tail of a loaded object. */
	KOFA_USE_DATA,

	KOFA_USE_COUNT
};

/* kofa_region.flags */
enum {
	KOFA_RGF_READ  = 1u << 0,
	KOFA_RGF_WRITE = 1u << 1,
	KOFA_RGF_EXEC  = 1u << 2,

	/*
	 * WRITABLE AND EXECUTABLE AT ONCE, and on Linux this is much weaker
	 * evidence than the equivalent bit on Windows.
	 *
	 * Measured on this machine: seven anonymous rwxp regions of 512 MB,
	 * in seven processes, every one of them V8. Electron put them there.
	 * A rule that fires on rwx alone fires on every developer workstation
	 * and every machine running a browser.
	 *
	 * It is carried because combined with size, with what is IN it, and
	 * with what else the process looks like, it still contributes. Alone
	 * it contributes nothing.
	 */
	KOFA_RGF_WX = 1u << 3,

	/*
	 * EXECUTABLE AND NOTHING IS BEHIND IT. The single most useful bit
	 * here, and the reason to walk regions rather than trust the loader's
	 * own list of mapped objects - which is exactly as honest as the
	 * loader, and an object unlinked from it is invisible there and still
	 * shows up as a region.
	 */
	KOFA_RGF_UNBACKED = 1u << 4,

	/*
	 * THE FILE BEHIND IT HAS BEEN UNLINKED: maps says "(deleted)".
	 *
	 * The bytes are still here and there is nothing on disk to scan, so
	 * this is the case where reading them out of the process is the ONLY
	 * way to see them. Also what every in-place package upgrade leaves
	 * behind, which is why it is a fact and not a finding. Measured: 94
	 * such mappings on an ordinary desktop.
	 */
	KOFA_RGF_DELETED = 1u << 5,

	/*
	 * BACKED BY A memfd. Fileless execution, in the only form Linux has -
	 * see KOFA_PF_EXE_MEMFD. Distinguished from KOFA_RGF_DELETED because
	 * a deleted file once existed and a memfd never did, and only one of
	 * those has an innocent explanation that happens daily.
	 */
	KOFA_RGF_MEMFD = 1u << 6,

	/*
	 * The backing file lives somewhere that does not survive a reboot -
	 * tmpfs, /dev/shm, /run. Not evidence; a great deal of legitimate
	 * software stages there. It is carried because "executed from a
	 * filesystem that keeps no history" is a fact worth having when
	 * something else has already made the process interesting.
	 */
	KOFA_RGF_VOLATILE = 1u << 7,

	/*
	 * RESIDENT IS FAR BELOW VIRTUAL - under a tenth. Set from the pagemap
	 * pass, so only on regions that had one.
	 *
	 * Recorded because it is the thing that surprised everyone who has
	 * built this: it says the reservation is a reservation. A caller
	 * printing region sizes without it reports 512 MB of executable
	 * anonymous memory that does not exist.
	 */
	KOFA_RGF_SPARSE = 1u << 8,

	/*
	 * THE REGION WAS NOT EXAMINED: it is larger than
	 * kofa_pmem_option.max_region, or a byte budget ran out before it.
	 *
	 * Said rather than left as an absence. A region that was skipped and a
	 * region that was read and found uninteresting are different facts,
	 * and a scanner that cannot tell them apart reports "checked
	 * everything" over a set it never saw.
	 */
	KOFA_RGF_UNEXAMINED = 1u << 9,

	/*
	 * pagemap could not be read for this region, so `rss` is the region
	 * size and the read was blind. Happens without privilege on another
	 * user's process, and on kernels built without CONFIG_PROC_PAGE_MONITOR.
	 */
	KOFA_RGF_NO_PAGEMAP = 1u << 10,

	/*
	 * `rss` WAS ACTUALLY MEASURED, rather than being the region size
	 * standing in for an answer nobody asked for.
	 *
	 * This flag exists because leaving it out was a real bug in the first
	 * working version, and the shape of that bug is the reason this tree
	 * distinguishes "checked and found nothing" from "never looked". Every
	 * region under `pagemap_min` was given rss = size - a defensible upper
	 * bound - and the walk then SUMMED those into its resident total. The
	 * summary reported 10.5 TB resident on a machine with 16 GB, and it
	 * reported it confidently, because nothing in the record said which of
	 * those numbers had been measured and which had been assumed.
	 *
	 * An upper bound is a fine thing to carry and a terrible thing to add
	 * up. So: `rss` is ALWAYS an upper bound, this flag says whether it is
	 * a tight one, and kofa_pmem_stat keeps the two sums apart.
	 */
	KOFA_RGF_RSS_MEASURED = 1u << 11,

	/*
	 * PAGEMAP CLAIMS FAR MORE PRESENT THAN smaps CHARGES AS RESIDENT: the
	 * difference is shared zero pages, so most of what pagemap points at
	 * is 4096 zeroes.
	 *
	 * It means one of two things and a caller cannot tell which:
	 * something read the whole region once - a debugger, a core dumper,
	 * another scanner, or an earlier run of this one - or the process
	 * itself read across a reservation it never wrote.
	 *
	 * Either way the runs from pagemap are nearly all empty, and a caller
	 * that reads them is reading zeroes at full price. Carried so that it
	 * can decide not to, and so the divergence is visible rather than
	 * showing up as a region that is somehow always fully resident.
	 */
	KOFA_RGF_ZERO_HEAVY = 1u << 12,

	/*
	 * AN EXECUTABLE FILE-BACKED REGION WITH PRIVATE DIRTY PAGES: somebody
	 * WROTE to code that came from a file.
	 *
	 * Windows needs a working-set query per region to learn this
	 * (KOFW_RGF_DIRTY_IMAGE). Linux gives it away in smaps' Private_Dirty,
	 * which this walk already reads for Rss - so it costs nothing at all.
	 *
	 * WHY IT IS A STRONG SIGNAL HERE AND ONLY A HINT ON WINDOWS. A mapped
	 * ELF's executable segment is BYTE-IDENTICAL to its file: measured at
	 * 42.8 MB across 592 file-backed executable regions of one Chromium
	 * process, and 3.0 MB across a shell, with ZERO bytes differing in
	 * either. x86-64 PIE code is RIP-relative, so no dynamic relocation
	 * lands in .text - they all go to .got, .got.plt and .data.rel.ro,
	 * which is exactly why those pages are shareable between processes in
	 * the first place. A PE's .text is rewritten by base relocations and
	 * has no such property, which is why pe_unmap.h has to exist and why
	 * nothing like it is needed here.
	 *
	 * So code pages are identical to the file unless something changed
	 * them, and the machine agrees: 0 kB of private-dirty across all 1079
	 * executable file-backed regions on this desktop. An inline hook, a
	 * patched GOT resolver stub, a stomped function - each is the only
	 * thing that moves this off zero.
	 *
	 * STILL NOT A VERDICT. A debugger's breakpoint is a written code page,
	 * and so is any legitimate runtime patching. It is a fact at the
	 * strength of a fact that is normally zero.
	 */
	KOFA_RGF_DIRTY_CODE = 1u << 13,

	/*
	 * THE KERNEL PUT THIS HERE, not the program: [vdso], [vsyscall],
	 * [vvar] and their relatives.
	 *
	 * [vdso] IS EXECUTABLE AND HAS NO FILE, which is the exact shape of
	 * the thing this library exists to find - measured, 31 of them on this
	 * machine, one per process. What separates them from shellcode is not
	 * anything about the bytes: it is that the kernel maps them into
	 * everybody, identically, and no program chose their contents.
	 *
	 * Carried as a flag rather than left to whoever looks at the path,
	 * because the alternative is every consumer testing for a leading '['
	 * privately, and one of them forgetting. A rule that means "executable
	 * with no file behind it" has to exclude these, and now it can say so.
	 */
	KOFA_RGF_KERNEL_MAPPED = 1u << 14
};

struct kofa_region {
	uint64_t base;
	uint64_t size;          /* the RESERVATION. See the top of this file. */

	/*
	 * HOW MUCH OF IT EXISTS, IN BYTES, AND ALWAYS AN UPPER BOUND.
	 *
	 * Two separate reasons it is a bound rather than a count, and a caller
	 * has to respect both:
	 *
	 *   - Transparent huge pages make pagemap's granularity 2 MB, so a
	 *     single touched page can be reported as 512 present ones.
	 *   - When pagemap was not consulted at all - the region is under
	 *     `pagemap_min`, over `max_region`, or pagemap is unavailable -
	 *     this is simply `size`, which is the loosest bound there is.
	 *
	 * KOFA_RGF_RSS_MEASURED says which of those two it is. NEVER SUM THIS
	 * ACROSS REGIONS WITHOUT CHECKING THAT FLAG; see the note on it for
	 * what happens when you do.
	 *
	 * This is the number that decides how much work there is. `size`
	 * decides nothing.
	 */
	uint64_t rss;

	uint64_t file_off;
	uint64_t inode;
	uint64_t dev;

	/*
	 * WHICH GROUP OF ADJACENT REGIONS THIS BELONGS TO - Linux's
	 * substitute for an AllocationBase, and it is this library's guess.
	 *
	 * One mapped shared object arrives as three or four VMAs, split where
	 * the protection changes: r--p for the headers, r-xp for the text,
	 * rw-p for the data. A caller that treats each as a find reports one
	 * object three times and scans its header separately from its code.
	 *
	 * Regions sharing a group_id are adjacent and either share a backing
	 * inode or are all anonymous. It is the base address of the first
	 * region in the group, so it is stable and comparable without a table.
	 */
	uint64_t group_id;

	uint32_t flags;         /* KOFA_RGF_* */
	uint8_t  use;           /* enum kofa_rgn_use */
	uint8_t  loc;           /* enum kof_evt_loc, of `path` */
	uint8_t  _pad[2];

	/*
	 * The backing file, or "" when nothing backs it. Never NULL. Borrowed,
	 * valid until the next call on this handle.
	 *
	 * The " (deleted)" suffix is STRIPPED and reported in flags instead,
	 * and a "/memfd:name" pseudo-path is left as it is and flagged. Both
	 * for the same reason kofa_proc.exe does it: a caller that has to
	 * decide whether a path is openable by looking for a magic suffix is a
	 * caller that will one day forget.
	 */
	const char *path;
};

/* One line: address, size, resident, protection, use, and what backs it.
 * Here rather than in each tool, so two tools cannot print it differently.
 * Returns bytes written excluding the NUL and never writes past `cap`. */
size_t kofa_region_describe(const struct kofa_region *, char *buf, size_t cap);

#endif /* KOFANTARC_APROC_REGION_H */
