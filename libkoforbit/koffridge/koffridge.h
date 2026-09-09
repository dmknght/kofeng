/* SPDX-License-Identifier: Apache-2.0 */
/*
 * koffridge.h - what has already been scanned, and what it came to.
 *
 * WHY A MEMORY SCAN NEEDS THIS AND A FILE SCAN DOES NOT.
 *
 * A directory walk meets each file once. A process walk does not: forty DLLs
 * are mapped by two hundred processes, so a snapshot of a workstation offers
 * the same ntdll.dll two hundred times, and scanning it two hundred times
 * produces the same answer two hundred times at two hundred times the cost.
 * Measured on any Windows machine, the module list across all processes is
 * roughly fifty distinct files behind several thousand mappings.
 *
 * So the cache is not a speed optimisation bolted on afterwards - without it a
 * full memory scan is quadratic in the wrong thing, and with it the walk costs
 * about what scanning the machine's loaded modules once costs.
 *
 *
 * WHAT IT IS KEYED ON, WHICH IS THE ONLY DECISION THAT MATTERS.
 *
 * NOT the path. A path is chosen by whoever put the file there, stays the same
 * when the bytes behind it do not, and is the one property an attacker
 * controls completely. A cache keyed on paths says "C:\Windows\System32\
 * foo.dll was clean an hour ago" about a file that has been replaced since.
 *
 * The key is an IDENTITY the caller supplies: bytes that change when the thing
 * changes. koffridge_fileid below is what that means for a file, and the
 * caller fills it because only the caller knows what it is holding. Nothing
 * here interprets the bytes - they are hashed to find the slot and then
 * COMPARED IN FULL, so a hash collision cannot return another object's
 * verdict.
 *
 *
 * WHAT IS NOT CACHEABLE, said here because getting it wrong is silent.
 *
 * Only bytes with a stable identity. A loaded module's file has one. A dirty
 * image page, an unbacked executable region, a heap buffer - none do: that
 * copy exists in one process, at one instant, and nothing about it will ever
 * be seen again. There is nothing to key on and nothing to reuse, which is
 * also why there is so little of it. See wproc.h on why the two halves of a
 * memory scan are scanned differently.
 *
 *
 * IT LIVES IN ORBIT, not in the engine, and the rule is the one kofevt follows:
 * orbit may know the engine's types, the engine must never know orbit's. A
 * verdict cache is a HOST'S policy - how long an answer stays good, what
 * identity means on this platform, when to give up and rescan - and a scanner
 * that made those decisions internally would be a scanner nobody could give
 * different ones to.
 *
 *
 * NOT THREAD SAFE, deliberately. It is a per-walk object like a kof_scanner,
 * and a caller that runs several scanners shares nothing between them except
 * the engine. Locking it internally would put a contended lock on the fast
 * path of every object to serve a caller who has not appeared.
 */
#ifndef KOFFRIDGE_H
#define KOFFRIDGE_H

#include <stdint.h>
#include <stddef.h>

#include "../../libkofeng/kofeng.h"

/*
 * The longest identity a key may be.
 *
 * Inline in the entry rather than in an arena, because it is compared on every
 * probe and because a bound this small removes a whole allocator from a
 * structure whose entire job is to be cheaper than the thing it replaces. An
 * identity that does not fit is not truncated - it is REFUSED, and the caller
 * gets a miss and scans. Truncating would make two different things equal.
 */
#define KOFFRIDGE_ID_MAX 48u

/*
 * WHAT IDENTIFIES A FILE, and the fields are the ones that change when the
 * bytes do without costing a read to obtain.
 *
 * On Windows: dwVolumeSerialNumber, nFileIndexHigh:nFileIndexLow, nFileSize,
 * ftLastWriteTime, all from one GetFileInformationByHandle on the handle that
 * is already open. On Linux: st_dev, st_ino, st_size, st_mtime from one stat.
 *
 * IT IS NOT A HASH OF THE CONTENT and does not pretend to be. A file rewritten
 * in place with the same length and a restored timestamp has the same identity
 * here and would be served a stale verdict. That is a real hole and it is the
 * standard bargain: the alternative is reading and hashing every file, which is
 * the work the cache exists to avoid. A caller that cannot accept it passes a
 * content hash as the identity instead - this struct is a convention, not a
 * requirement, and nothing here reads its fields.
 */
struct koffridge_fileid {
	uint64_t volume;
	uint64_t index;
	uint64_t size;
	uint64_t mtime;
};

/*
 * THE ANSWER, WHICH IS THE VERDICT AND NOT THE REPORT.
 *
 * One name, not the list. The engine's default is to stop at the first finding
 * - see kof_scan_option.all_matches - so in the shape this cache is for there
 * IS only one, and carrying sixteen would multiply the table by fifteen to hold
 * what nothing wrote.
 *
 * `findings` is the count the scan produced, so a caller can see when there
 * were more than the one kept. A caller that needs the whole list of an
 * infected object rescans it, and that is cheap for the reason it sounds like:
 * infected objects are rare, and it happens once each.
 */
struct koffridge_verdict {
	/* KOF_LEVEL_*, and only meaningful when findings is non-zero. */
	uint32_t level;

	/* How many findings the scan produced. 0 is the clean answer, and it
	 * is the answer this cache exists to serve. */
	uint32_t findings;

	/* enum kof_broken as the scan reported it: zero when the object was
	 * finished. A cached "do not know" stays "do not know" rather than
	 * being remembered as clean. */
	uint32_t broken;

	/* The worst finding's name, or "" when clean. Same text as
	 * kof_finding.name. */
	char name[224];
};

struct koffridge;

/*
 * Open a cache of at most `capacity` verdicts. NULL on failure.
 *
 * `capacity` 0 takes a default stated in the .c. It is rounded UP to a power of
 * two, so ask for what you want rather than a round number.
 *
 * `db_stamp` identifies the database whose answers these are - the build id the
 * engine was opened with. Every verdict in a cache is only true of one
 * database, so mixing two is how a cache serves an answer the current rules
 * would no longer give. Nothing here can enforce that on a caller who opens two
 * engines and one fridge; it is recorded, returned by koffridge_db_stamp, and
 * it is what any on-disk form of this must be keyed on first.
 */
struct koffridge *koffridge_open(uint32_t capacity, uint64_t db_stamp);

void koffridge_close(struct koffridge *);

uint64_t koffridge_db_stamp(const struct koffridge *);

/*
 * Look one up. 1 and *out filled on a hit, 0 on a miss.
 *
 * `out` may be NULL to test for presence without copying, which is not an
 * optimisation worth reaching for: the copy is 240 bytes and the caller almost
 * always wants it.
 */
int koffridge_get(struct koffridge *, const void *id, uint32_t id_len,
		  struct koffridge_verdict *out);

/*
 * Remember what a scan came to. 1 if it was stored, 0 if it was not - the
 * identity was too long, or the table refused it.
 *
 * `res` NULL stores the clean answer, for a caller that has a verdict and not a
 * result. Storing is not an error path: a caller that ignores the return value
 * gets a cache that is merely less useful, never wrong.
 */
int koffridge_put(struct koffridge *, const void *id, uint32_t id_len,
		  const struct kof_result *res);

/* Forget everything. The table keeps its capacity. */
void koffridge_clear(struct koffridge *);

/*
 * WHAT IT DID, AND WHY IT IS NOT OPTIONAL.
 *
 * A cache that is not measured is a cache nobody knows is working. These are
 * the four numbers that say: a hit rate near zero means the identity is wrong
 * (a path crept in, or a timestamp that moves), and evictions climbing means
 * the capacity is below the working set and the walk is paying for a cache that
 * throws away what it is about to need.
 */
struct koffridge_stat {
	uint64_t hits;
	uint64_t misses;
	uint64_t stores;
	uint64_t evictions;
	uint64_t refused;    /* identity too long, or no slot could be made */
	uint32_t used;
	uint32_t capacity;
};

void koffridge_stats(const struct koffridge *, struct koffridge_stat *);

/* One line: "fridge: 3921 hit, 57 miss (98.6%), 57 stored, 0 evicted". Returns
 * bytes written excluding the NUL, and never writes past `cap`. Here rather
 * than in each tool for the reason kofw_region_describe is where it is. */
size_t koffridge_describe(const struct koffridge *, char *buf, size_t cap);

#endif /* KOFFRIDGE_H */
