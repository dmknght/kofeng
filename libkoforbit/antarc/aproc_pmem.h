/*
 * aproc_pmem.h - walking one process: the options, the handle, reading, runs, chunks
 * and the statistics. *
 * A part of <aproc.h>, which includes it: include that, not this. Split from it by
 * purpose; the text is unchanged.
 */

#ifndef KOFANTARC_APROC_PMEM_H
#define KOFANTARC_APROC_PMEM_H

#include <stdint.h>
#include <stddef.h>
#include "kofantarc.h"
#include "aproc_proc.h"
#include "aproc_region.h"

/* ------------------------------------------------------- walking one process */

/* kofa_pmem_option.want */
enum {
	/*
	 * ONLY REGIONS THAT CAN EXECUTE.
	 *
	 * On, it is the difference between ten thousand regions and about
	 * eleven hundred on this machine, and a scanner looking for code has
	 * no use for the rest. Off by default because "what is in this
	 * process" is a different question from "what could run in it", and
	 * only the caller knows which it is asking.
	 */
	KOFA_MW_EXEC_ONLY = 1u << 0,

	/*
	 * USE pagemap TO FIND OUT WHAT IS RESIDENT. On by default, and turning
	 * it off makes every read blind - see the measurements at the top for
	 * what that costs. The option exists so the cost can be measured
	 * again rather than believed.
	 */
	KOFA_MW_PAGEMAP = 1u << 1,

	/*
	 * TAKE `rss` FROM smaps INSTEAD OF FROM pagemap. On by default, and it
	 * is a correctness switch rather than a thoroughness one.
	 *
	 * pagemap's PRESENT bit counts pages that have a PTE, and an untouched
	 * anonymous page that anything has ever READ has a PTE pointing at the
	 * shared zero page - see the long note at the top of this file. smaps
	 * Rss does not count those, because the kernel does not charge them to
	 * anybody. So smaps is the only in-box answer to "how much of this is
	 * real".
	 *
	 * IT COSTS THE DIFFERENCE BETWEEN READING maps AND READING smaps:
	 * measured at 1 ms against 7 ms for a process with 1343 regions, since
	 * the kernel walks the page tables to produce it. That is the price of
	 * not reporting half a gigabyte of shared zeroes as a payload.
	 *
	 * Off, `rss` comes from pagemap and is a much looser upper bound. A
	 * caller that only wants to know WHERE to look, and will read and
	 * judge the bytes anyway, can afford that.
	 */
	KOFA_MW_SMAPS = 1u << 4,

	/*
	 * REPORT KOFA_USE_HEAP REGIONS AT ALL. Off by default, and the default
	 * is not a compromise - it is the measured answer twice over.
	 *
	 * THE COST. Heap is 1867 MB resident on this machine against 12 MB for
	 * every anonymous executable region put together: one hundred and
	 * fifty-five times the bytes, to look in the place where a match means
	 * least.
	 *
	 * THE FALSE POSITIVES, which are not a tuning problem but a property
	 * of what the memory IS. Every byte a process has ever read passes
	 * through its writable private memory: an installer holds its payload
	 * there, a browser holds a download there, and a scanner holds
	 * whatever it just scanned there. The case that settled it, from a
	 * YARA deployment: a CLI tool ran a test binary that contained a
	 * signature string; the test binary matched, and so did the PARENT
	 * shell's heap, because the child's output had passed through the
	 * parent's stdio buffer on its way to the terminal. The parent was
	 * not infected with anything. It had READ something.
	 *
	 * So a match here says the process TOUCHED those bytes and says
	 * nothing whatever about the process being the thing that made them.
	 * A miss says even less: the buffer that would have matched was very
	 * probably freed before anything came to look.
	 *
	 * WHAT TURNING IT OFF ACTUALLY MISSES, since "off" is not free either
	 * and the misses are real:
	 *
	 *   - A DECRYPTED CONFIGURATION. Domain lists, keys, campaign ids.
	 *     Encrypted on disk, plaintext only here, never executable. This
	 *     is what commodity Linux bots keep, and it is a genuine miss.
	 *   - AN INTERPRETED PAYLOAD. A script pulled over a socket and passed
	 *     to exec() lives in the interpreter's heap and nowhere else. No
	 *     page of it is ever executable and no file ever holds it.
	 *
	 * Both are DATA rather than code, which is why no amount of looking at
	 * executable memory finds them.
	 *
	 * THE ANSWER IS NOT A SWITCH, IT IS A SIZE. See max_heap_region below:
	 * 90.4% of heap regions on this machine are under 1 MB and hold 9.3%
	 * of the bytes. A decrypted configuration is kilobytes. A browser's JS
	 * heap - which is where both the cost and most of the noise live - is
	 * tens of megabytes. Capping per region recovers the misses above for
	 * a tenth of the cost, which a switch cannot do in either position.
	 *
	 * KOFA_MW_EXEC_ONLY excludes heap whatever this says: a heap that can
	 * execute is KOFA_USE_CODE and was never a heap by this library's
	 * reading.
	 */
	KOFA_MW_HEAP = 1u << 2,

	/*
	 * REPORT INACCESSIBLE RESERVATIONS (`---p`, KOFA_USE_UNKNOWN).
	 *
	 * Off by default. They cannot be read and hold nothing, and there are
	 * 9.1 TB of them on a desktop running a browser. On, for a caller that
	 * is mapping out an address space rather than scanning it.
	 */
	KOFA_MW_RESERVED = 1u << 3,

	/* What kofa_pmem_open gives a caller that passes NULL. */
	KOFA_MW_DEFAULT = KOFA_MW_PAGEMAP | KOFA_MW_SMAPS
};

/*
 * A BUDGET SHARED BY A WHOLE SWEEP, and the reason it is a separate object.
 *
 * kofa_pmem is per process, so a per-process ceiling bounds one process and
 * nothing else: four hundred processes at 256 MB each is a hundred gigabytes,
 * which is not a bound, it is arithmetic. What a caller actually needs bounded
 * is the WALK, and the walk is many handles.
 *
 * So the caller owns one of these and points every handle at it. Nothing here
 * allocates it and nothing here locks it - a walk is single threaded for the
 * same reason a kof_scanner is, and a caller running several shares nothing
 * between them.
 *
 * RUNNING OUT IS REPORTED, NEVER SILENT. A region that could not be read comes
 * back flagged KOFA_RGF_UNEXAMINED and counted in `regions_refused`, because a
 * scanner that quietly stopped reading would report "checked everything" over
 * a set it abandoned half way.
 */
struct kofa_sweep {
	/* What the whole walk may read. 0 means no limit, which is a choice a
	 * caller makes rather than a default it falls into. */
	uint64_t max_bytes;

	uint64_t used;             /* read so far */
	uint64_t refused;          /* bytes a region wanted and did not get */
	uint32_t regions_refused;  /* regions flagged UNEXAMINED for it */
	uint32_t _pad;
};

struct kofa_pmem_option {
	/* A mask of KOFA_MW_*. Zero takes KOFA_MW_DEFAULT. */
	uint32_t want;

	/*
	 * Regions whose RESERVATION exceeds this are reported with
	 * KOFA_RGF_UNEXAMINED and not read.
	 *
	 * Compared against `size` rather than `rss` on purpose: it is a guard
	 * against a pathological mapping, and the pagemap read needed to learn
	 * rss is itself proportional to size. 0 takes the default stated in
	 * the .c.
	 */
	uint64_t max_region;

	/*
	 * WHAT A HEAP REGION MAY COST, and the whole reason heap is not simply
	 * off. Only consulted when KOFA_MW_HEAP is set; compared against
	 * `rss`, because for heap the resident size IS the work.
	 *
	 * 0 takes the default stated in the .c, which is 1 MB and is chosen
	 * from the distribution in the note on KOFA_MW_HEAP.
	 */
	uint64_t max_heap_region;

	/*
	 * Total bytes read out of this one process. 0 takes the default.
	 * Reaching it flags the remaining regions KOFA_RGF_UNEXAMINED rather
	 * than ending the walk, so the caller still learns they exist.
	 *
	 * THE DEFAULT IS NOT MEASURED, AND SAYING SO IS THE POINT. Every other
	 * number in this file came from a measurement on this machine, taken
	 * as an ordinary user - which sees 34 processes. A privileged sweep
	 * sees roughly ten times as many, and the shape of what it finds is
	 * not known: the per-process ceiling and kofa_sweep.max_bytes were
	 * both picked to be obviously large rather than to be right.
	 *
	 * What would settle them is one run of the walk as root, reporting
	 * bytes_resident and bytes_read per process. Until that exists these
	 * two are guards against a pathological process, not a budget anybody
	 * measured.
	 */
	uint64_t max_bytes;

	/*
	 * Regions smaller than this are read without consulting pagemap: one
	 * pread of the pagemap costs more than reading the region would.
	 *
	 * 0 takes the default stated in the .c. THE BREAK-EVEN POINT HAS NOT
	 * BEEN MEASURED - the current value is reasoned, not observed, and is
	 * one of the open questions in PLAN.md.
	 */
	uint64_t pagemap_min;

	/*
	 * Bytes one CHUNK may be - see kofa_pmem_next_chunk. A resident run
	 * can be hundreds of megabytes and a caller that wanted it in one
	 * piece would be asking this library to allocate it. 0 takes the
	 * default stated in the .c.
	 */
	uint64_t chunk_max;

	/*
	 * The walk's shared budget, or NULL for none. Borrowed; the caller
	 * owns it and reads it when the walk is done.
	 */
	struct kofa_sweep *sweep;
};

struct kofa_pmem;

/*
 * Open one process for reading. NULL on failure with *err set.
 *
 * `start_time` is checked against /proc/<pid>/stat and the open FAILS with
 * KOFA_ERR_GONE if it differs - the pid has been reused and this is a
 * different process. Pass 0 to skip the check, which is what a caller that
 * genuinely means "whatever holds this pid now" does, and it should be rare
 * enough to look odd at the call site.
 */
struct kofa_pmem *kofa_pmem_open(uint32_t pid, uint64_t start_time,
				 const struct kofa_pmem_option *opt, int *err);

/* The process this handle is for. Borrowed, valid for the handle's life. */
const struct kofa_proc *kofa_pmem_proc(const struct kofa_pmem *);

/*
 * Next region, 1 on success and 0 at the end.
 *
 * REGIONS ARE FILTERED BY THE OPTIONS, so a caller that asked for
 * KOFA_MW_EXEC_ONLY does not see the others at all and does not pay for them.
 * What it does still see is the accounting: kofa_pmem_stat reports how many
 * were skipped, so "I looked at forty regions" never gets confused with
 * "there were forty regions".
 *
 * `rss` is filled from pagemap unless the region is under `pagemap_min` or
 * pagemap could not be read - see KOFA_RGF_NO_PAGEMAP.
 *
 * WHY A FILE-BACKED EXECUTABLE REGION IS STILL REPORTED even though the right
 * move is almost always to scan its FILE instead: the region walk is what tells
 * a caller the file is there. Its pages are shared with every other process
 * that mapped the same object precisely BECAUSE they are identical to it, so
 * reading eight thousand mappings to reach an answer that fifty file reads
 * already give is what makes a memory scan take an hour. The caller decides;
 * this reports. See koffridge.h for the cache that makes those fifty reads
 * happen once.
 */
int kofa_pmem_next_region(struct kofa_pmem *, struct kofa_region *out);

/*
 * Read bytes out of the process. Returns how many were read, which may be
 * short and may be 0 - the process can exit at any point and a region can be
 * unmapped between being listed and being read.
 *
 * IT DOES NOT CONSULT pagemap. A caller that wants only resident bytes asks
 * for the runs - see kofa_pmem_runs - and reads those. This does exactly what
 * it is asked, including reading a hole, which comes back as zeroes without
 * disturbing the target (measured; see the top of this file).
 */
size_t kofa_pmem_read(struct kofa_pmem *, uint64_t addr, void *buf, size_t n);

/*
 * THE RESIDENT RUNS INSIDE A REGION, which is how a caller turns 512 MB of
 * reservation into the 4.76 MB that exists.
 *
 * Fills up to `max` runs and returns how many. A return equal to `max` means
 * there may be more and the caller should either take a bigger array or accept
 * that it is reading a prefix - it is told which by `more`, which is set
 * non-zero when runs were left undescribed.
 *
 * Returns 0 and sets *more to 0 when pagemap is unavailable, which is NOT the
 * same as a region with nothing resident. The region's KOFA_RGF_NO_PAGEMAP
 * flag is what separates them.
 */
struct kofa_run {
	uint64_t addr;
	uint64_t len;
};

/*
 * ONE PIECE OF A REGION THAT IS WORTH LOOKING AT, already read.
 *
 * `p` is borrowed and valid until the next call on this handle.
 */
struct kofa_chunk {
	uint64_t    addr;   /* where it is in the process */
	const void *p;
	uint64_t    len;
};

/*
 * WALK A REGION'S CONTENT, one chunk at a time. 1 and *out filled, or 0 at the
 * end of the region.
 *
 * THIS IS THE WAY TO READ A REGION, and kofa_pmem_read is the way to read an
 * address. The difference matters because reading an address is how a caller
 * accidentally reads BLIND, and a blind read is not merely slow - it
 * instantiates a zero-page PTE for every untouched page it touches, so the
 * pagemap of that process reports them present from then on, for this scanner
 * and for every other tool on the machine. See the note at the top of this
 * file. A caller that only ever uses this cannot do that.
 *
 * IT SKIPS PAGES THAT ARE ENTIRELY ZERO, and that is the larger half of what
 * it is for. Measured across every anonymous executable region of 64 KB or
 * more on this machine: 1132.54 MB came back resident by pagemap, and 1086.71
 * MB of it - 96.0% - was nothing but zeroes. The 45.8 MB left is the code. A
 * caller handing the engine the unfiltered set would be asking it to search
 * twenty-four times what is there.
 *
 * WHY DROPPING THEM CANNOT LOSE A MATCH. The longest pattern the database can
 * hold is KOF_STR_MAX_LEN, 512 bytes; a page is 4096. A match that began
 * before a dropped page and ended after it would have to span eight times the
 * longest pattern, so there is no such match. One lying entirely inside a
 * dropped page would have to BE 4096 zero bytes, which is not a signature
 * anybody would write and which would match every zero page on the machine if
 * they did.
 *
 * CHUNKS ARE NEVER CONCATENATED. Two runs that are not adjacent in the process
 * are two chunks, because joining them would create a byte sequence that never
 * existed at any address - and a signature matching across that splice is a
 * detection of something that is not there.
 *
 * The cost of the test itself, measured: 3.67 GB/s, against a saving of 24x in
 * what the engine is then asked to search.
 */
int kofa_pmem_next_chunk(struct kofa_pmem *, const struct kofa_region *,
			 struct kofa_chunk *out);

void kofa_pmem_close(struct kofa_pmem *);

/*
 * WHAT THE WALK DID, AND WHY IT IS NOT OPTIONAL.
 *
 * The numbers that say whether the design above is working on THIS machine
 * rather than on the one it was measured on. `bytes_virtual` against
 * `bytes_resident` is the ratio the whole thing rests on; if it is near 1 the
 * pagemap pass is buying nothing and is pure cost. `regions_skipped` climbing
 * means the budgets are below the working set and the caller is being told it
 * checked things it did not.
 */
struct kofa_pmem_stat {
	uint64_t regions_seen;      /* matched the filter */
	uint64_t regions_filtered;  /* excluded by `want` */
	uint64_t regions_skipped;   /* KOFA_RGF_UNEXAMINED */
	uint64_t bytes_virtual;     /* sum of size over regions_seen */

	/*
	 * THE TWO RESIDENT SUMS, KEPT APART ON PURPOSE - see
	 * KOFA_RGF_RSS_MEASURED for the bug that made this necessary.
	 *
	 * `bytes_resident` is the sum over regions whose pagemap was actually
	 * read, and is the only one of these that means what it says.
	 * `bytes_unmeasured` is the sum of `size` over the rest: an upper
	 * bound on what is still unaccounted for. They are never added
	 * together by anything here, and a caller that adds them is producing
	 * the same wrong number by hand.
	 */
	uint64_t bytes_resident;
	uint64_t bytes_unmeasured;
	uint64_t regions_measured;

	uint64_t bytes_read;        /* what was moved out of the process */

	/*
	 * WHAT THE ZERO FILTER REMOVED, so its earn is visible rather than
	 * assumed - the audit asks every filter for this. `bytes_zero` is
	 * what was read and dropped; bytes_read minus it is what a caller was
	 * handed.
	 */
	uint64_t bytes_zero;
	uint64_t chunks;

	uint64_t pagemap_reads;
	uint64_t pagemap_failed;
};

void kofa_pmem_stats(const struct kofa_pmem *, struct kofa_pmem_stat *);

#endif /* KOFANTARC_APROC_PMEM_H */
