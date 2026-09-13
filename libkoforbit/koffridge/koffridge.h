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
 * THREAD SAFE, AND IT WAS DELIBERATELY NOT.
 *
 * What stood here said so, and gave a reason worth keeping: a lock on the fast
 * path of every object looked up, to serve "a caller who has not appeared".
 * That caller has appeared - the scanner threads, and the work it would
 * parallelise is measured at four fifths of a whole-machine sweep - so the
 * premise expired and the decision went with it.
 *
 * The objection was answered rather than overruled. The table is SHARDED: a
 * key belongs to exactly one shard, each shard is an independent small table
 * with its own lock, and a probe run and any eviction it performs stay inside
 * one. Two threads working on different keys do not meet. See struct shard.
 *
 * WHAT IS SAFE: koffridge_get, koffridge_put and koffridge_identify, from any
 * number of threads at once.
 *
 * WHAT IS NOT, and is not worth making so: open, close and clear are lifecycle,
 * and a caller that clears a cache while another thread reads it has a problem
 * no lock here can fix. save and load take each shard's lock in turn, so they
 * are safe against concurrent use and are not an INSTANT of it - a save that
 * overlaps a scan writes a cache from somewhere in the middle of it, which is
 * a true cache and not a snapshot.
 *
 * The statistics are summed shard by shard for the same reason: correct, and
 * not simultaneous. They are read when a walk is over, which is when that
 * distinction stops mattering.
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
 * is already open. On Linux: st_dev, st_ino, st_size and st_mtim from one stat.
 *
 * `mtime` IS IN NANOSECONDS on both, and the unit is not decoration. It was
 * whole seconds, and three rewrites of one file in place - same inode, same
 * length - produced three identical identities, so the cache served the first
 * scan's verdict for the third file's bytes. A write takes microseconds; an
 * attacker did not have to restore anything, only to be quick. Measured:
 *
 *     mtime seconds  1789209554 1789209554 1789209554
 *     mtime nsec      370836748  371003014  371007003
 *
 * IT IS NOT A HASH OF THE CONTENT and does not pretend to be. A file rewritten
 * in place with the same length and a restored timestamp has the same identity
 * here and would be served a stale verdict. That is a real hole and it is the
 * standard bargain: the alternative is reading and hashing every file, which is
 * the work the cache exists to avoid. A caller that cannot accept it passes a
 * content hash as the identity instead - this struct is a convention, not a
 * requirement, and nothing here reads its fields.
 *
 *
 * ON SOME SYSTEMS THE TIMESTAMP IS NOT A FIELD AT ALL, AND THE HOLE IS WIDER
 * THAN THE PARAGRAPH ABOVE DESCRIBES.
 *
 * That paragraph assumes an attacker has to RESTORE the timestamp, which costs
 * them a step. On a machine that normalises mtimes there is no step to take -
 * the timestamp is already the same on every file and contributes nothing.
 *
 * Measured on the development host, which uses an overlay store of the kind
 * reproducible builds produce:
 *
 *     /usr/lib/x86_64-linux-gnu/libc.so.6    mtime=0
 *     /bin/ls                                mtime=0
 *     1465 of 1962 system files              mtime=0   (74%)
 *
 * There the identity is effectively (dev, ino, size), and a file rewritten in
 * place at the same length is indistinguishable from the original. Nix stores,
 * many container images and any tree built for bit-reproducibility are in this
 * state; an ordinary distribution install is not, and /etc on the same machine
 * has real timestamps.
 *
 * A HOST THAT CANNOT ACCEPT THAT PASSES A CONTENT HASH, which this struct
 * already permits and which kof_sha256_file already computes. What that costs
 * is a read of every file - the work the cache exists to avoid - so it is a
 * decision about the machine rather than a default anything here can pick.
 */
struct koffridge_fileid {
	uint64_t volume;
	uint64_t index;
	uint64_t size;
	uint64_t mtime;
};

/*
 * Fill `out` with the identity of the file at `path`. Non-zero on success.
 *
 * ONE IMPLEMENTATION FOR BOTH PLATFORMS, and it is here because the struct
 * above is here. The paragraph describing what each field is on Windows and on
 * Linux was written before either was implemented, and the only code that ever
 * filled it in was a private static inside kofmemscan - which is a Windows-only
 * tool, so half of a documented contract had no implementation at all and the
 * other half could not be reached by anything else. A cache whose key nobody
 * else can compute is a cache nobody else can use.
 *
 * Windows: one GetFileInformationByHandle. POSIX: one stat. Neither reads a
 * byte of the content, which is the property the whole bargain rests on.
 *
 * ZERO ON FAILURE, and a caller that gets zero must scan WITHOUT caching rather
 * than cache under a key it could not establish - a key built from a failed
 * query is a key that collides with every other failed query.
 */
int koffridge_identify(const char *path, struct koffridge_fileid *out);

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

/* ------------------------------------------------------------ persistence */

/*
 * A SWEEP THAT REPEATS IS THE POINT, AND IN MEMORY THE CACHE DIES WITH THE
 * PROCESS.
 *
 * Measured on this tree's build host, a whole-machine memory scan: 3103 modules
 * across 53 processes collapse to 539 distinct files, and scanning those files
 * is 2.65 of the 3.26 seconds the sweep takes - 81% of it. Walking the memory
 * is the other 0.61. So a second sweep five minutes later pays the 2.65 again
 * to reach an answer it already had, and on a sensor that sweeps periodically
 * that is nearly all the work it will ever do.
 *
 * Saved and reloaded, the same sweep is the 0.61 plus a single read of a few
 * hundred KB. That is what makes a periodic memory scan something a machine can
 * actually run.
 *
 *
 * WHAT INVALIDATES THE WHOLE FILE, wholesale and without argument:
 *
 *   - a different `db_stamp`. A database update can change any verdict in it,
 *     including every clean one, so one changed database discards the lot.
 *     This is what koffridge_open's db_stamp argument was always for.
 *   - a different entry layout or version. The entries are written as the
 *     structs they are, so a build whose struct differs cannot read them.
 *
 * Nothing is partially salvaged in either case. A cache that kept the entries
 * it could still parse would be a cache that answers from a contract it has
 * already admitted it does not share.
 *
 *
 * IT IS A TRUST INPUT, AND THAT IS NOT A DETAIL TO FIND OUT LATER.
 *
 * Whoever can write this file decides what this scanner calls clean. An
 * attacker who can put one entry in it - the identity of their own payload,
 * with findings 0 - has turned the scanner off for that file and left no trace
 * in any report, because a served hit looks exactly like a file that was
 * examined.
 *
 * So it belongs somewhere only the account running the scanner can write, and
 * it must never be read from a path an unprivileged process can influence.
 *
 * THAT IS A CONSTRAINT ON THE PATH, NOT AN ARGUMENT FOR A FLAG.
 *
 * This used to say a scanner must not enable it by default, so that "the
 * operator says where it lives, which is the moment they decide who can write
 * it". That reasoning was wrong in a way worth naming: it moved a safety
 * property out of the code and into a decision somebody has to make correctly
 * every time, and the cost of not making it is a sweep five times slower -
 * measured, 5.21s against 1.03s. A protection that is off by default for most
 * people is not a protection with a good default; it is a fast path most people
 * never get, guarded by a question most people answer by not asking it.
 *
 * The property is kept by CHOOSING the path instead. koffridge_default_path
 * gives a per-user location - %LOCALAPPDATA% on Windows, $XDG_CACHE_HOME or
 * ~/.cache elsewhere - which no other unprivileged account can write. An
 * operator who wants it somewhere else still says so, and now that is an
 * override rather than a precondition.
 *
 * The stored checksum is NOT security. It catches a truncated write and a
 * corrupted sector; anyone editing the file deliberately recomputes it in four
 * lines. Said plainly because a checksum in a file format invites exactly the
 * wrong conclusion.
 */

/*
 * Write the cache to `path`. Non-zero on success.
 *
 * Written to a temporary beside the target and renamed over it, so an
 * interrupted save leaves the previous cache rather than a half of this one.
 */
/*
 * NOT const, AND THE REASON IS THE LOCKS.
 *
 * These three read the table, and reading it means taking each shard's mutex -
 * see the note beside struct shard. A pointer-to-const that locks is a
 * declaration that says the object does not change while the code changes it,
 * and the cast needed to make it compile is the compiler being told to stop
 * noticing. The signature tells the truth instead.
 */
int koffridge_save(struct koffridge *, const char *path);

/*
 * Load entries from `path` into the cache, returning how many were admitted.
 *
 * Zero is the ordinary answer the first time and is not an error; `*why`
 * explains it either way and is never NULL-terminated nonsense - it is a
 * literal. `why` itself may be NULL.
 *
 * Entries go in through the same insertion the live path uses, so capacity,
 * probing and eviction behave identically - a loaded entry is an ordinary
 * entry. They are marked as the OLDEST, so anything this run touches outlives
 * them when the table has to make room.
 */
/*
 * Where the cache lives when nobody said otherwise. Non-zero on success.
 *
 * A PER-USER DIRECTORY, and that is the whole of the safety argument above:
 * %LOCALAPPDATA%\kofeng on Windows, $XDG_CACHE_HOME/kofeng or ~/.cache/kofeng
 * elsewhere. No other unprivileged account can write there, so a cache found
 * at this path was written by this user or by something already running as
 * them - at which point the cache is not the weakest thing they can reach.
 *
 * The directory is created if it is missing. Zero when there is no home to put
 * it in, and a caller that gets zero runs WITHOUT a cache rather than falling
 * back to somewhere writable - a temporary directory shared with every other
 * account is exactly the path this is avoiding.
 */
int koffridge_default_path(char *buf, size_t cap);

uint32_t koffridge_load(struct koffridge *, const char *path,
			const char **why);

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

void koffridge_stats(struct koffridge *, struct koffridge_stat *);

/* One line: "fridge: 3921 hit, 57 miss (98.6%), 57 stored, 0 evicted". Returns
 * bytes written excluding the NUL, and never writes past `cap`. Here rather
 * than in each tool for the reason kofw_region_describe is where it is. */
size_t koffridge_describe(struct koffridge *, char *buf, size_t cap);

#endif /* KOFFRIDGE_H */
