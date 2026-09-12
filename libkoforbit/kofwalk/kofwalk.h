/*
 * kofwalk.h - what a scanner needs from a machine's running processes, and
 * nothing about which machine it is.
 *
 * WHY IT IS THIS SMALL.
 *
 * The obvious interface is the collector's own: a process struct, a region
 * struct, a flag vocabulary, an iterator for each. Both collectors already
 * have all of that - kofw_proc and kofa_proc, kofw_region and kofa_region -
 * and a neutral copy would be a THIRD vocabulary that has to be kept in step
 * with two that are already correct for their own platform.
 *
 * So this is not the union of them. It is what the SCANNER actually asks,
 * which turns out to be two questions:
 *
 *     what process is this, in the form the engine scans one     (next_proc)
 *     and what is in it that I should look at                    (next_item)
 *
 * and the second has exactly two answers: a FILE, which is scanned as a file
 * and remembered by its identity, or BYTES, which exist only in that process
 * and must be scanned every time. Everything a collector knows that does not
 * change one of those answers stays in the collector.
 *
 *
 * next_proc HANDS BACK A kof_proc_build, WHICH IS NOT AN ACCIDENT.
 *
 * That struct is what libkoforbit/kofproc turns into the record the engine
 * scans a process as, and it is already platform-neutral with a per-platform
 * tail - see kofmod/proc.h. Handing it back directly means the walk fills the
 * thing the scanner was going to fill anyway, and there is no third struct
 * between them that somebody has to remember to copy a field into.
 *
 *
 * A FILE IS NOT READ OUT OF THE PROCESS, and that is the whole performance
 * story. Measured on this tree's Linux host: 5795 file-backed mappings behind
 * 335 distinct files, libc mapped a hundred times. A walk that handed over
 * bytes for those would ask the engine to scan libc a hundred times; handing
 * over the PATH lets the caller identify it once and never look again. See
 * koffridge.h, which is where the caller puts the answer.
 */

#ifndef KOFORBIT_KOFWALK_H
#define KOFORBIT_KOFWALK_H

#include <stdint.h>
#include <stddef.h>

#include "kofproc.h"

/* What next_item found. */
enum kof_walk_kind {
	/* Nothing more in this process. */
	KOF_WALK_END = 0,

	/*
	 * A FILE BEHIND A MAPPING. Scan the file, not the mapping: its pages
	 * are shared with every other process that mapped it precisely
	 * BECAUSE they are identical to it, and the file has an identity a
	 * cache can key on while a mapping has none.
	 */
	KOF_WALK_FILE,

	/*
	 * BYTES THAT ARE IN NO FILE. A payload mapped into place, a
	 * decompressed stub, plain shellcode. This copy exists in one process
	 * at one instant, so there is nothing to key a cache on and nothing
	 * to come back to - it is scanned now or not at all.
	 */
	KOF_WALK_BYTES
};

struct kof_walk_item {
	int kind;                  /* enum kof_walk_kind */

	/* KOF_WALK_FILE. Borrowed, valid until the next call. */
	const char *path;

	/* KOF_WALK_BYTES. `p` is borrowed and valid until the next call;
	 * `addr` is where it is in the process, which is what a finding has
	 * to be reported against. */
	uint64_t    addr;
	const void *p;
	uint64_t    len;

	/*
	 * WHAT THE BYTES CANNOT SAY ABOUT THEMSELVES, for KOF_WALK_BYTES.
	 * Zero when there is nothing to declare, which is the ordinary case
	 * and what a memset gives.
	 *
	 * THIS EXISTS BECAUSE OF ONE FACT THAT IS SILENT WHEN IT IS WRONG. An
	 * executable image a loader mapped states its file offsets and its
	 * virtual addresses in the same section table, and which pair is
	 * correct depends on how the bytes were obtained - which the bytes
	 * themselves do not record. Resolve them from the wrong pair and every
	 * scan region points at another section's bytes: no error, no anomaly,
	 * and no rule matches. The walk read the memory, so the walk is the
	 * only thing that knows, and this is how it says so.
	 *
	 * The fields are kof_scan_option's own - `as_format` and the view
	 * behind it - and a caller copies them straight across. They are typed
	 * as a byte and a blob HERE on purpose: this header names no format
	 * and no platform, so a Windows walk declaring a mapped PE and a Linux
	 * walk declaring nothing need no vocabulary in common.
	 *
	 * `as_view` is borrowed on the same terms as `p`.
	 */
	uint8_t     as_format;
	const void *as_view;
	uint32_t    as_view_len;

	/*
	 * WHAT KIND OF MEMORY THIS IS, for KOF_WALK_BYTES: "MEM_HEAP",
	 * "MEM_STACK", "MEM_ANON" and so on. "" when the walk has no word for
	 * it.
	 *
	 * A CALLER SHOWING THIS TO SOMEBODY NEEDS A WORD, NOT AN ADDRESS. The
	 * address is in `addr` and is what a finding is reported against, but
	 * a row reading "00007fce21b7f000" tells a reader nothing they can act
	 * on - they have to go and work out what lives there, which is
	 * precisely what the collector already knows.
	 *
	 * Borrowed, valid until the next call, like every other string here.
	 * Spelled in the region vocabulary this tree uses - capitals, MEM_ for
	 * what came from the running process rather than from a file.
	 */
	const char *label;
};

/*
 * WHICH PROCESSES. NULL means every one the walk can open.
 *
 * A LIST IS NOT A CONVENIENCE HERE. "Scan the machine" is one job and "scan
 * this pid" is another: the second is what a host does when something else
 * already decided a process is interesting - an event arrived, an operator
 * asked, a rule fired on a file that process had open - and walking four
 * hundred processes to reach one of them is the whole cost of the sweep paid
 * for nothing.
 *
 * A pid in the list that does not exist, or that this walk may not open, is
 * skipped like any other refusal and counted in the stats. It is not an error:
 * the process may have exited between the caller deciding and the walk
 * starting, which is the ordinary case for exactly the processes worth asking
 * about.
 */
/*
 * WHAT THE CALLER IS DOING, because the right set of regions is not the same
 * for both and is not a matter of taste.
 *
 * A SCANNER wants code with no file behind it: a reflective loader's payload,
 * a decompressed stub, plain shellcode. The rest of an address space is the
 * process's own working data, and searching it reports what a process TOUCHED
 * rather than what it is - measured on this tree: a parent shell's heap
 * matched a string that had merely passed through it.
 *
 * SOMEBODY LOOKING wants the address space. The heap is where a decrypted
 * configuration lives and is exactly what an analyst opens a process to read;
 * refusing it because a SCAN would false-positive on it is answering a
 * question nobody asked.
 *
 * A PURPOSE AND NOT A FLAG SET, so this header still names no platform. The
 * two collectors have their own vocabularies for this - KOFA_MW_* and
 * KOFW_MW_* - and each maps the purpose onto its own, where the reasoning is
 * visible beside the flags it chooses.
 */
enum kof_walk_intent {
	/* Zero, so an option struct that was memset keeps the behaviour every
	 * existing caller already has. */
	KOF_WALK_SCAN = 0,
	KOF_WALK_MAP
};

struct kof_walk_option {
	const uint32_t *pids;
	uint32_t        n_pids;

	/* enum kof_walk_intent. */
	int intent;

	/* Report processes that could not be opened, so a caller can tell
	 * "clean" from "never looked at". On by default when the struct is
	 * zeroed - see the negative sense. */
	int no_refused;
};

/*
 * The walk, as a scanner sees it. `self` is the collector's own handle and
 * every call takes it back - a vtable and a handle, for the reason
 * kof_mon_api is one.
 */
struct kof_walk_api {
	void *self;

	/*
	 * The next process, filled into the form the engine scans one.
	 * 1 on success, 0 at the end of the walk.
	 *
	 * The strings in *out are BORROWED from the walk and are replaced by
	 * the next call, so a caller that keeps them keeps a copy. That is
	 * the same contract kofa_plist_next and kofw_plist_next already have,
	 * and the reason neither allocates.
	 */
	int (*next_proc)(void *self, struct kof_proc_build *out);

	/*
	 * The next thing worth looking at in the process next_proc returned.
	 * 1 and *out filled, or 0 when there is nothing more.
	 *
	 * Calling it after next_proc has moved on is a caller error and
	 * returns 0; the walk does not keep two processes open.
	 */
	int (*next_item)(void *self, struct kof_walk_item *out);

	/* Numbers a caller reports: processes seen and refused, regions, and
	 * bytes actually read out of processes. May be NULL. */
	void (*stats)(void *self, uint64_t *procs, uint64_t *refused,
		      uint64_t *regions, uint64_t *bytes);

	void (*close)(void *self);
};

/*
 * Open a walk. NULL on failure with *err set to the collector's own error
 * code - kofa_err_name or kofw_err_name will name it, and a caller that wants
 * to print one already knows which collector it linked.
 *
 * DECLARED HERE AND DEFINED PER PLATFORM: libkofantarc provides it on Linux,
 * libkofgrille on Windows, and a host links exactly one of them. That is the
 * whole of the platform decision - everything above this line is the same
 * code on both.
 */
struct kof_walk_api *kof_walk_open(const struct kof_walk_option *, int *err);

#endif /* KOFORBIT_KOFWALK_H */
