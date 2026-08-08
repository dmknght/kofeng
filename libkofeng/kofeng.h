/*
 * kofeng.h - the engine, as seen from outside.
 *
 * This is the whole public surface for a host that wants to scan things. Everything
 * else under libkofeng is internal: the parsers, the matcher, the database loader, the
 * per-object routine. A consumer that needs one of those is a consumer this header has
 * failed, and the fix belongs here rather than in an include path.
 *
 * There is a second, separate public surface with a different audience: core/kofmod/
 * is the ABI a signature module is written against. The two never meet - a host does
 * not include kofmod, a module does not include this.
 *
 * Shape:
 *
 *     kof_engine  *eng = kof_engine_open("/var/lib/kofeng/db");
 *     kof_scanner *sc  = kof_scanner_new(eng);          // one per thread
 *
 *     struct kof_result r;
 *     if (kof_scan_path(sc, path, &r) > 0)
 *             for (i = 0; i < r.n; i++) ... r.v[i].name ...
 *
 *     kof_scanner_free(sc);
 *     kof_engine_close(eng);
 *
 * The engine is immutable once open, so one engine serves every thread. That is safe
 * rather than safe-by-convention: module code has no writable data and needs no
 * relocation, so the mapped code is read-only. The mutable and expensive parts - a
 * 32MB presence table, the search memo, the parsed view - belong to the scanner and
 * are allocated per thread and reused across objects.
 */

#ifndef KOFENG_H
#define KOFENG_H

#include <stdint.h>

/* How strongly a finding is asserted. Mirrors enum kof_level on the module side; a
 * host must not have to include the module ABI to read a result. */
#define KOF_LEVEL_SUSPECT 0
#define KOF_LEVEL_INFECT  1

/*
 * Findings are accumulated, not overwritten: two families can match one object, and
 * keeping only the last silently drops one. Over the cap they are counted, because a
 * truncated list that says nothing about being truncated reads as a complete list.
 */
#define KOF_MAX_FINDINGS 16

struct kof_finding {
	uint32_t level;                  /* KOF_LEVEL_* */
	/* <format>.<arch>.<family>, composed by the engine. The prefix is not
	 * authored, so a module cannot claim a format it was not run against. */
	char     name[224];
};

struct kof_result {
	struct kof_finding v[KOF_MAX_FINDINGS];
	uint32_t n;
	uint32_t dropped;
};

/*
 * What a scan cost. Exposed because the design rests on a module being cheap for the
 * objects it does not detect, and a number nobody can read is a number nobody keeps
 * honest.
 *
 * `ran` against `considered` is how much the preconditions removed; `bytes_searched`
 * against `object_bytes` is how many times over the content was read.
 */
struct kof_stats {
	uint64_t objects, object_bytes;

	/* Objects the walk reached but could not read. Counted, because the walk is the
	 * engine's now: without this the caller has no way to learn that a file was
	 * skipped, and a scan that silently omits what it could not open reads as a
	 * scan that found nothing there. */
	uint64_t unreadable;

	uint64_t considered, ran;
	uint64_t by_target, by_size, by_arch, by_region;

	uint64_t gram_bytes;             /* cost of building presence sets */
	uint64_t gram_answers;           /* searches answered without scanning */

	uint64_t searches, bytes_searched;
};

typedef struct kof_engine  kof_engine;
typedef struct kof_scanner kof_scanner;

/*
 * Open a database: a directory of modules, or a single one.
 *
 * Loose files today - <name>.blob plus the .meta, .strs and .names the build emits
 * beside it. A packed container replaces that without changing this call, which is
 * why no format appears here.
 *
 * NULL if nothing could be loaded.
 */
kof_engine *kof_engine_open(const char *db_path);
void        kof_engine_close(kof_engine *);

uint32_t    kof_engine_modules(const kof_engine *);
uint32_t    kof_engine_strings(const kof_engine *);

/* One scanner per thread. The engine it is made from must outlive it. */
kof_scanner *kof_scanner_new(const kof_engine *);
void         kof_scanner_free(kof_scanner *);

const struct kof_stats *kof_scanner_stats(const kof_scanner *);

/* Error returns, distinct from a finding count of zero. */
#define KOF_ERR_OPEN (-1)      /* could not be opened, or is not a regular file */
#define KOF_ERR_READ (-2)      /* could not be mapped */
#define KOF_ERR_ARG  (-3)

/*
 * Reported once per object the engine scanned, including ones with no findings.
 *
 * `name` is what the object was reached by - a path for a file, later a member name
 * inside an archive - so one callback covers the whole tree with no special case for
 * the root. Return 0 to carry on, non-zero to abort the walk.
 *
 * A callback rather than one result per call, because an object can yield children: a
 * directory yields files, and an archive will yield members. One result cannot hold a
 * tree, and a caller that had to poll for the next one would be reimplementing the
 * walk it just delegated.
 */
typedef int (*kof_on_object)(const char *name, const struct kof_result *res,
			     void *user);

/*
 * How a scan is allowed to spread.
 *
 * Data, and passed per scan rather than set on the engine: a limit is the caller's
 * policy, not a property of the database, and two callers in one process must be able
 * to differ.
 *
 * Zeroing the struct gives the conservative answer everywhere - no recursion - so a
 * caller that forgets a field does not get a surprise, it gets less.
 */
struct kof_policy {
	int      recurse_dirs;     /* descend into directories */
	uint32_t max_depth;        /* 0 -> a built-in ceiling applies */
	int      follow_symlinks;  /* off is the only safe default: a link into an
				    * ancestor turns a walk into a loop */
};

/*
 * Scan whatever `path` names.
 *
 * A file is one object. A directory is a container the engine walks, which is where it
 * belongs: a directory yielding files and an archive yielding members are the same
 * shape, and having the caller do one of them means the walk exists twice.
 *
 * Returns the number of objects scanned, or a KOF_ERR_*. Findings arrive through the
 * callback; zero findings on an object is a result and is still reported.
 */
int kof_scan_path(kof_scanner *, const char *path, const struct kof_policy *,
		  kof_on_object cb, void *user);

#endif /* KOFENG_H */