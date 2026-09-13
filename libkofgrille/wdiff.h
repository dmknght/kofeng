/*
 * wdiff.h - what a loaded module's memory says that its file does not.
 *
 * THE ONE QUESTION A MEMORY SCAN ANSWERS THAT A FILE SCAN CANNOT.
 *
 * Everything a loaded module holds is also in the file it came from - that is
 * why its pages are shared with every other process that mapped the same file,
 * and it is why wwalk.c hands the FILE over rather than reading eight thousand
 * mappings. So scanning a module's memory finds what scanning its file would
 * have found, and the whole value of looking at the memory at all is the
 * DIFFERENCE: bytes that are in the process and are in no file.
 *
 * That difference is where these live, and nothing else in this tree sees any
 * of them:
 *
 *   - an inline hook, where a payload rewrote the first instructions of a
 *     function it wants to watch or neuter;
 *   - a security stub blown away in the process's own address space -
 *     patching ntdll!EtwEventWrite stops that process's own AMSI submissions
 *     from ever being reported, which is a thing the EVENT pipeline is blind
 *     to BY CONSTRUCTION: see the note at the top of wevt_decode.c. The patch
 *     is what stops the events, so it can never itself be an event;
 *   - a hollowed section, where the file on disk is the innocent original.
 *
 * WHY IT IS NOT A KIND OF SCAN. A scan takes bytes and says what they are.
 * This takes TWO copies of the same object and says where they disagree - a
 * comparison, not an identification - and the bytes it finds are then scanned
 * like anything else.
 *
 *
 * WINDOWS ONLY, AND THAT IS WHY IT IS HERE.
 *
 * What makes a mapped image differ from its file is the LOADER'S work, and the
 * Windows loader's work is this library's subject. Applied base relocations, a
 * resolved import table, an ImageBase field rewritten in the mapped copy -
 * every one of those is a legitimate difference that has to be accounted for
 * before what is left can be called a modification. Get that wrong and the
 * output is not a weaker finding, it is thousands of false ones.
 *
 * It includes engine headers - the PE parse - so like wwalk.c it is compiled
 * INTO whatever links the engine and is not part of libkofgrille.a.
 *
 *
 * WHAT IT READS, AND WHY THAT IS THE WHOLE DESIGN
 *
 * The first version of this read the WHOLE module out of the process, read the
 * WHOLE file off the disk, and built a third whole copy by un-mapping the
 * image so the loader's relocations were undone before comparing. Measured on
 * one machine sweep:
 *
 *     561 module comparisons, 1514 MB read, over 31 DISTINCT FILES
 *     ntdll.dll, KERNEL32.dll, KERNELBASE.dll ... 34 times each
 *
 * 1514 MB to find 167 KB of differing bytes. Two things were wrong and they
 * compounded.
 *
 * A WRITTEN-TO IMAGE PAGE IS NOT RARE. It was assumed to be - "two modules in
 * seventy-seven" - and that is simply false on Windows: the loader applies
 * import optimisation per process, which writes into .text, which makes those
 * pages private. ntdll is written to in EVERY process on the machine. The
 * comparison therefore ran for nearly every core DLL of nearly every process.
 *
 * AND NOTHING WAS SHARED between those runs, because the un-map needs a whole
 * image and a whole image is what was read.
 *
 * So this version reads NEITHER whole copy:
 *
 *   ONLY THE DIRTY PAGES come out of the process. The region walk already
 *   knows exactly which ranges have stopped being shared - that is what
 *   KOFW_RGF_DIRTY_IMAGE means - and the rest of the module is by definition
 *   identical to the file. A few pages instead of two megabytes.
 *
 *   ONLY THE MATCHING RANGES come off the disk, through a cached handle.
 *
 *   THE UN-MAP IS GONE. It existed to answer one question - "is this byte
 *   different because the loader relocated it" - and it answered it by
 *   rewriting an entire image. The file's own .reloc table answers the same
 *   question directly, for one page, and answers it BETTER: knowing the load
 *   delta, a relocated pointer must equal its file value plus that delta, so a
 *   reloc target that does NOT match is a modified pointer and is reported
 *   rather than silently subtracted away.
 *
 *   THE FILE'S METADATA IS PARSED ONCE per distinct file - section table,
 *   relocation directory, IAT range - and reused across every process that
 *   mapped it. 31 parses instead of 561.
 *
 *
 * WHAT IS STILL EXCLUDED, AND WHY EACH ONE HAD TO BE
 *
 *   RELOCATIONS, as above: verified against the load delta rather than
 *   assumed.
 *
 *   WRITABLE AND DISCARDABLE SECTIONS, skipped whole. A .data section is
 *   SUPPOSED to differ from its file - that is what writable means.
 *
 *   THE IMPORT ADDRESS TABLE, by range. Every thunk in it is an address the
 *   loader wrote that exists only in this process.
 *
 *   WHAT THE IMAGE REWRITES IN ITSELF, out of its own dynamic relocation
 *   table - see dv_load in the .c, which also carries the measurement that
 *   identified it. On this ARM64 host that is most of the noise: a sweep went
 *   from 359 differing runs over 57346 bytes to 135 over 2055.
 *
 *   Counted, in kofw_diff_stat.dvrt_explained, and not merely dropped. A
 *   report that stopped showing them would leave a reader unable to tell a
 *   quiet machine from a filter that had swallowed the evidence.
 *
 *
 * WHAT IS NOT EXCLUDED AND SHOULD BE, said plainly rather than discovered.
 *
 * Of the 135 runs that survive on this host, the ones that were looked at are
 * still the loader's own work reaching bytes by a route this does not yet
 * follow:
 *
 *   CONTROL FLOW GUARD POINTERS. A pointer in .rdata read 0x7ffdd26e7040 in
 *   memory against 0x180004160 in the file - an address inside ntdll, which
 *   the file cannot name and the loader fills in. GuardCFCheckFunctionPointer
 *   and its XFG relatives are named in the load configuration, so excluding
 *   them is the same shape as the IAT exclusion and is simply not written.
 *
 *   THE DELAY-LOAD IMPORT TABLE, for the same reason as the IAT: its thunks
 *   are addresses that exist only in this process.
 *
 *   ARM64EC THUNK SECTIONS - the two longest survivors are in a section named
 *   `fothk`, which is not something this has looked into.
 *
 * Until those are followed, kofw_diff_stat.small_runs counts the short ones
 * apart so that "ninety four-byte writes" and "one sixty-byte write" do not
 * arrive as the same number.
 */

#ifndef KOFGRILLE_WDIFF_H
#define KOFGRILLE_WDIFF_H

#include <stdint.h>
#include <stddef.h>

#include "wproc.h"

/*
 * ONE RUN OF BYTES THAT DIFFER, already joined.
 *
 * Joined because a hook is not one byte. A branch written over a function's
 * opening instructions differs in several adjacent places, and reporting each
 * as its own finding is a report nobody can count. Runs closer together than
 * KOFW_DIFF_GAP are one run.
 */
struct kofw_diff_run {
	uint64_t addr;      /* where it is in the process */
	uint64_t rva;       /* where it is in the image */
	uint64_t file_off;  /* the same place in the file */
	uint32_t len;

	/* Which section it landed in, as the file names it. Always
	 * NUL-terminated; "" when it fell outside every section. */
	char     section[16];
};

/*
 * Called once per differing run.
 *
 * `mem` and `file` point at that run's bytes in each copy - `len` of each - so
 * a caller can scan them, hash them, print them, or ignore them. Both are
 * BORROWED and are gone when kofw_diff_module returns.
 *
 * Return non-zero to stop the comparison. That is not an error; it is how a
 * caller that has seen enough stops paying for the rest.
 */
typedef int (*kofw_diff_cb)(const struct kofw_diff_run *run,
			    const uint8_t *mem, const uint8_t *file,
			    void *user);

/* Bytes this far apart or closer belong to one run - see kofw_diff_run. */
#define KOFW_DIFF_GAP 16u

/*
 * A run of this length or shorter, inside an executable section, is counted in
 * `small_runs` as well as in `runs`. Not a filter and not a verdict: it is the
 * length import optimisation produces, so it is the length a caller cannot yet
 * tell from a hook. See the header note.
 */
#define KOFW_DIFF_SMALL 8u

/*
 * ONE RANGE OF THE IMAGE WORTH COMPARING - a run of pages that has stopped
 * being shared with the file.
 *
 * The caller supplies these because the caller is the one that walked the
 * regions; asking this file to find them again would mean a second pass over
 * the address space to learn what the first pass already established.
 */
struct kofw_diff_range {
	uint64_t addr;      /* in the process */
	uint64_t len;
};

/*
 * THE PER-FILE CACHE, and it is the difference between 31 parses and 561.
 *
 * Holds a distinct file's section table, relocation directory and IAT range -
 * everything the comparison needs that depends on the FILE rather than on the
 * process. A sweep meets the same thirty or so system DLLs in every process on
 * the machine, and none of that changes between them.
 *
 * NOT A VERDICT CACHE and nothing to do with koffridge. It caches what a file
 * IS, not what was concluded about it, so there is no staleness question
 * beyond the file being replaced on disk mid-sweep - which invalidates by
 * identity like everything else.
 *
 * Optional: pass NULL and every call parses for itself. Not thread safe, for
 * the reason koffridge is not - it is a per-walk object.
 */
struct kofw_diff_cache;

struct kofw_diff_cache *kofw_diff_cache_open(uint32_t max_files);
void kofw_diff_cache_close(struct kofw_diff_cache *);

/* files held, files asked for, files parsed. For saying what the cache saved. */
void kofw_diff_cache_stats(const struct kofw_diff_cache *,
			   uint32_t *held, uint64_t *asked, uint64_t *parsed);

struct kofw_diff_option {
	/* Stop after this many runs. 0 takes a built-in ceiling. The COUNT in
	 * the stat keeps rising after the callback stops being called, so a
	 * capped comparison still reports how much it found. */
	uint32_t max_runs;

	/* Compare writable sections too. Off by default and rarely right: a
	 * writable section differing from its file is what writable MEANS. */
	int      with_writable;
};

struct kofw_diff_stat {
	uint32_t runs;          /* runs handed to the callback */
	uint64_t bytes;         /* their total length */
	uint32_t small_runs;    /* of `runs`, how many are short - see above */
	uint64_t mem_read;      /* bytes taken out of the process */
	uint64_t file_read;     /* bytes taken off the disk */
	int      capped;        /* there were more runs than max_runs */

	/*
	 * Differing bytes that the file's relocation table accounted for, and
	 * ones where it did NOT.
	 *
	 * The second is the interesting number and is why the relocations are
	 * verified rather than subtracted: a byte inside a relocation target
	 * whose value is not the file's plus the load delta is a POINTER
	 * SOMEBODY CHANGED, which the old un-map-and-subtract approach turned
	 * into a clean byte by construction.
	 */
	uint64_t reloc_explained;
	uint64_t reloc_wrong;

	/*
	 * Differing bytes the image's OWN dynamic relocation table accounts
	 * for - see dv_load. On an ARM64X image this is most of them, and a
	 * report that simply stopped showing them would give a reader no way
	 * to tell a quiet machine from a filter that had swallowed the
	 * evidence.
	 */
	uint64_t dvrt_explained;

	/*
	 * The comparison was not performed because the load delta could not be
	 * established - the file's own ImageBase could not be read. A module
	 * counted here is NOT a module that came back clean.
	 */
	int      base_unknown;
};

/*
 * Compare the dirty parts of one loaded module against the file it came from.
 *
 * `m` is the open process, `md` the module, and `ranges` the parts of it that
 * have stopped being shared - typically a handful of pages. Only those are
 * read and only those are compared; the rest of the module is identical to the
 * file by definition, which is what being shared means.
 *
 * `cache` may be NULL. `st` may be NULL. Returns 1 when the comparison ran.
 */
int kofw_diff_module(struct kofw_pmem *m, const struct kofw_module *md,
		     const struct kofw_diff_range *ranges, uint32_t n_ranges,
		     struct kofw_diff_cache *cache,
		     const struct kofw_diff_option *opt,
		     kofw_diff_cb cb, void *user, struct kofw_diff_stat *st);

#endif /* KOFGRILLE_WDIFF_H */
