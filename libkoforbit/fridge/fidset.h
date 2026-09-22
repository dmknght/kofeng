/*
 * fidset.h - the set of files this database has already called clean.
 *
 * WHAT IT IS. One 64-bit key per file identity, sorted, on disk, searched
 * WHERE IT LIES. Not loaded, not parsed, not turned into a hash table: the
 * file's layout is the lookup structure, and a query touches one page of it.
 *
 * WHY NOT THE TABLE THAT WAS HERE. koffridge keeps a sharded open-addressing
 * table whose entries carry the identity bytes AND a verdict, and save/load
 * writes and reads the whole of it. That is the right shape for a few thousand
 * live processes; it is the wrong shape for every file on a machine, where the
 * cache is read far more often than written and the reader wants one answer
 * rather than the set.
 *
 *
 * A KEY IS A FILE IDENTITY, AND IT IS NOT A CONTENT HASH.
 *
 * That is a decision with a cost and it should be read before this is used.
 * The identity is what the filesystem says about a file - where it is, how big,
 * when it was made and last written - and every one of those is settable by
 * whoever already has rights on the machine. A file patched IN PLACE at the
 * same length, with its timestamps put back, has the same key.
 *
 * Kaspersky's iChecker keyed on exactly this and was sound anyway, because the
 * thing that invalidated an entry was not the timestamp: it was a filesystem
 * filter driver that saw every write. The stamp was a cheap consistency check
 * for what the driver could not see - a volume modified while mounted
 * elsewhere.
 *
 * So the same holds here: THIS IS SOUND WHILE SOMETHING IS WATCHING. On Linux
 * that is libkoforbit/antarc's fanotify; on Windows libkoforbit/grille. Without a watcher -
 * a one-shot sweep of a machine somebody else has been on - a metadata key can
 * be made to lie, and the honest tool for that is --no-cache.
 *
 * It is written down here rather than left to be discovered because the failure
 * is silent: a file that should have been scanned is not, and nothing says so.
 *
 *
 * CLEAN ONLY, AND NOTHING ELSE IS STORED.
 *
 * A key is present or it is not. There is no payload, no verdict, no name and
 * no path - so an entry is eight bytes and a hundred thousand files are eight
 * hundred kilobytes.
 *
 * An object that was NOT clean is simply not added, so it is scanned again next
 * time and reported in full. That costs a rescan of the rare file and buys
 * three things: the smallest possible entry, no stale verdict that could name
 * something since replaced, and a report that is never a one-line summary of
 * what an older run happened to find first.
 */

#ifndef KOFORBIT_FIDSET_H
#define KOFORBIT_FIDSET_H

#include <stdint.h>
#include <stddef.h>

/*
 * WHAT THE PLATFORM SAYS ABOUT A FILE, normalised.
 *
 * Filled by the platform module - libkoforbit/antarc on Linux, libkoforbit/grille on
 * Windows - and never here: this layer has no business knowing whether the
 * answer came from stat or from GetFileInformationByHandle, and a struct that
 * did would be a struct that cannot be filled on the other one. That is the
 * fault this replaces: the only code that ever filled the old identity was a
 * private static inside a Windows-only tool, so half of a documented contract
 * had no implementation and the other half nothing could reach.
 *
 * NO ACCESS TIME AND NO PERMISSION BITS.
 *
 * Reading a file changes its access time, so a scanner that keyed on one would
 * invalidate every entry by looking at it. Permissions change without the
 * content changing - one chmod across a tree would throw the cache away for
 * nothing. Kaspersky dropped FILE_ATTRIBUTE_ARCHIVE for the same reason and
 * said so: "Backup agents may change archive attribute."
 *
 * Sixteen bytes for each of volume and node because Windows needs them: a
 * volume GUID and a 128-bit file reference. Linux uses the first eight of each
 * and leaves the rest zero, which costs eight bytes per lookup and keeps one
 * struct instead of two.
 */
struct kof_fid {
	uint8_t  volume[16];   /* dev_t            | volume serial + object id */
	uint8_t  node[16];     /* ino_t            | 128-bit file reference    */
	uint64_t size;
	uint64_t born;         /* st_ctime (ns)    | CreationTime              */
	uint64_t written;      /* st_mtime (ns)    | LastWriteTime             */
};

/*
 * The key for an identity. FNV-1a over the struct's bytes.
 *
 * NON-CRYPTOGRAPHIC ON PURPOSE, and it is not a compromise. A stronger hash
 * would buy resistance to someone constructing a second identity with the same
 * key - but the identity ITSELF is settable by that same someone, so the
 * strength would be spent guarding the outer door of a room with no wall. What
 * guards this is the watcher; see the note at the top.
 */
uint64_t kof_fid_key(const struct kof_fid *);

/*
 * FILL `out` WITH THE IDENTITY OF THE FILE AT `path`. Non-zero on success.
 *
 * DECLARED HERE, DEFINED BY THE PLATFORM - libkoforbit/antarc/afid.c on Linux,
 * libkoforbit/grille/wfid.c on Windows, one compiled per host. That is exactly the
 * arrangement kof_walk_open has, and it is here for the same reason: the caller
 * is the same scanner on both platforms and must not be reading an #ifdef to
 * find out where it is. Declaring is not implementing, so this layer still
 * knows nothing about stat or GetFileInformationByHandle.
 *
 * ZERO ON FAILURE, AND A CALLER THAT GETS ZERO MUST NOT CACHE. A key that could
 * not be established must not be invented: a zeroed struct is a perfectly good
 * key that every unidentifiable file would share, and one of them being called
 * clean would speak for all of them.
 *
 * Only a regular file succeeds. A directory has no content to cache, and a
 * symlink is identified AS THE LINK and then refused - two links to one target
 * must not share a key, because a link is what an attacker repoints afterwards.
 */
int kof_fid_of(const char *path, struct kof_fid *out);

struct kof_fidset;

/*
 * TWO STAMPS, BECAUSE TWO THINGS CAN MAKE A STORED ANSWER WRONG.
 *
 * `db_stamp` is the DATABASE these answers belong to. A database update can
 * change any verdict in it, including every clean one.
 *
 * `eng_stamp` is the ENGINE that produced them, and it is not the same
 * question. The rules can be identical and the answer still change: what a
 * parser calls a region, what a normalise pass produces, which bytes an
 * unpacker hands over - all of that is the engine's, and a file called clean by
 * an older one was called clean about bytes a newer one carves differently.
 * Measured on this tree in one afternoon: recognising the "<?" short tag,
 * carving ColdFusion tags, and refusing to hand a literal over as a child each
 * changed what a scan finds with the database untouched.
 *
 * A file written under a different value of EITHER is not merged, not partially
 * salvaged and not read - see kof_fidset_load.
 *
 * WHAT THE ENGINE STAMP CANNOT DO. It is a version, and a version moves when
 * somebody moves it: two builds of an hour apart share one, so a developer
 * changing a parser between two scans is not protected by it. That is what
 * --no-cache is for, and it is why this is a stamp rather than a promise.
 */
struct kof_fidset *kof_fidset_open(uint64_t db_stamp, uint64_t eng_stamp);
void kof_fidset_close(struct kof_fidset *);

/*
 * Map a set file. Non-zero when one is now backing this set; zero when there
 * was none, it was unreadable, or it belongs to another database - all of
 * which mean the same thing to a caller, which is that every lookup will miss.
 *
 * The mapping is READ ONLY and is never written through. Saving writes a new
 * file; see kof_fidset_save.
 */
int kof_fidset_load(struct kof_fidset *, const char *path);

/* Is this key in the set - the mapped part or what this run has added. */
int kof_fidset_has(struct kof_fidset *, uint64_t key);

/* Add a key. Adding one that is already there is free and changes nothing. */
int kof_fidset_add(struct kof_fidset *, uint64_t key);

/*
 * TAKE A KEY OUT - this file is not clean after all.
 *
 * The only way a set learns that. Nothing that is skipped is ever scanned, so
 * the news arrives from a run that did NOT consult this set: a --no-cache sweep
 * of a machine somebody else has been on, or one under a newer database. Both
 * are exactly the runs whose findings the stored set would otherwise outlive,
 * and a cache that keeps calling a detected file clean is worse than no cache.
 *
 * Dropped keys are held apart from the mapping, which is read only: a lookup
 * answers no for them from this point, and the next save writes the set without
 * them. Dropping a key that is not there is free, changes nothing, and is not
 * counted - every file a scan finds something in is offered here, and on a tree
 * of samples almost none of them were ever cached.
 */
int kof_fidset_drop(struct kof_fidset *, uint64_t key);

/*
 * Write the mapped set and this run's additions out as one sorted file.
 *
 * Through a temporary and a rename, so a reader either sees the whole of the
 * old file or the whole of the new one. A half-written cache that still parses
 * is the worst outcome available here.
 */
int kof_fidset_save(struct kof_fidset *, const char *path);

struct kof_fidset_stat {
	uint64_t mapped;    /* keys in the file that was loaded */
	uint64_t added;     /* keys this run put in */
	uint64_t dropped;   /* keys this run took out - see kof_fidset_drop */
	/*
	 * WHEN THE FILE THAT WAS LOADED WAS WRITTEN - seconds since the epoch,
	 * 0 when no file was loaded or it did not say.
	 *
	 * Reported, never acted on: what makes a cache stale is the DATABASE it
	 * was built against, and an age that expired entries would be a second
	 * rule saying what the stamp already says. This is here so a person can
	 * ask how old the answers are.
	 */
	uint64_t made;
	uint64_t hit;
	uint64_t miss;
	uint64_t pages;     /* how many distinct pages lookups have touched */
};
void kof_fidset_stats(const struct kof_fidset *, struct kof_fidset_stat *);

#endif /* KOFORBIT_FIDSET_H */
