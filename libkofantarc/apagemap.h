/*
 * apagemap.h - which pages of a mapping actually exist.
 *
 * INTERNAL. The public shape of this is kofa_pmem_runs in aproc.h; this is the
 * part that talks to the kernel, kept separate so it can be tested against a
 * process whose resident set the test itself decided.
 *
 *
 * WHAT IT IS FOR, in one measurement: an anonymous rwxp region of 512 MB in a
 * real V8 process has 4.76 MB resident. Reading the region costs 80.7 ms;
 * reading its pagemap costs 0.4 ms and says which 4.76 MB to read, which then
 * costs 0.5 ms. Eight bytes per page buys the right to skip the other 4088.
 *
 *
 * PRESENT IS NOT THE SAME AS "HAS CONTENT", and the difference is why bit 62
 * is handled separately.
 *
 *   bit 63  PRESENT   the page is in RAM. Reading it is a memcpy.
 *   bit 62  SWAPPED   the page exists and is on disk. Reading it through
 *                     process_vm_readv FAULTS IT BACK IN: it costs a disk
 *                     read, it grows the target's RSS, and it evicts
 *                     something else to make room.
 *
 * So a swapped page is content this walk could see and deliberately does not.
 * A scanner that swapped in every anonymous page of every process would be a
 * scanner that thrashes the machine it is protecting, and it would do it to
 * reach bytes that the process itself has not touched recently enough to keep.
 *
 * They are COUNTED, not silently dropped - see kofa_pm_scan's `swapped`. A
 * caller that genuinely wants them can ask for them, and the number is what
 * lets anyone see how much was left behind.
 *
 *
 * IT IS AN UPPER BOUND, because of transparent huge pages.
 *
 * Measured: a child that touched 100 scattered pages across 512 MB came back
 * with 205 MB resident and AnonHugePages: 204800 kB - THP promoted each touch
 * to a 2 MB page, so pagemap reports 512 present 4 KB entries for every one
 * page that was written. On real processes the overshoot is small, because
 * real allocations are not scattered on purpose. But nothing may treat the
 * resident count as exact.
 */

#ifndef KOFANTARC_APAGEMAP_H
#define KOFANTARC_APAGEMAP_H

#include <stdint.h>
#include <stddef.h>

#include "aproc.h"

#define KOFA_PAGE_SHIFT 12
#define KOFA_PAGE_SIZE  (1u << KOFA_PAGE_SHIFT)

/* What one scan of a region's pagemap found. */
struct kofa_pm_result {
	/* Bytes whose pages are PRESENT. An upper bound - see THP above. */
	uint64_t resident;

	/* Bytes whose pages are SWAPPED: content that exists and was not
	 * turned into runs. */
	uint64_t swapped;

	/* Runs written to the caller's array. */
	int runs;

	/* Non-zero when the array filled and resident pages were left
	 * undescribed. The runs that were written are still correct; they are
	 * a prefix. */
	int more;
};

/*
 * Open /proc/<pid>/pagemap. Returns the fd, or -1 with *err set.
 *
 * KOFA_ERR_UNSUPPORTED when the file does not exist - a kernel built without
 * CONFIG_PROC_PAGE_MONITOR - and KOFA_ERR_DENIED when it exists and will not
 * open. The caller can carry on in both cases; it just reads blind.
 */
int kofa_pm_open(uint32_t pid, int *err);

/*
 * Turn [base, base+size) into runs of present pages.
 *
 * `scratch` is a caller-owned buffer of `scratch_ents` pagemap entries, used
 * to read the map in batches - so a gigabyte region costs a fixed buffer
 * rather than eight megabytes of entries. It must hold at least 64.
 *
 * Runs are COALESCED ACROSS BATCH BOUNDARIES: a run that spans two reads comes
 * back as one run. Getting that wrong would not have been visible in a test
 * with small regions and would have doubled the number of reads on real ones.
 *
 * Returns 0 on success, or a kofa_err. A failure means nothing was learned,
 * and the caller reads blind.
 */
int kofa_pm_scan(int pmfd, uint64_t base, uint64_t size,
		 uint64_t *scratch, size_t scratch_ents,
		 struct kofa_run *out, int max_runs,
		 struct kofa_pm_result *res);

#endif /* KOFANTARC_APAGEMAP_H */
