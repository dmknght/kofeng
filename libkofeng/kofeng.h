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
 * Decided by structure rather than by a signature, and counted apart from both.
 *
 * Its own level and not a kind of SUSPECT, because the two answer differently to
 * an operator: a SUSPECT came from a module that names a family and chose the
 * weaker verdict, while this came from traces that name nothing. Folding them
 * together meant a heuristic could not be measured, tuned or switched off in the
 * report - which is most of what anyone wants to do with one.
 */
#define KOF_LEVEL_HEUR    2

/*
 * Everything the heuristic in this build can be asked to look at.
 *
 * A number rather than a name was the wrong thing to make callers write. A tool
 * that examines ONE file on purpose - kofexamine, kofviewer - wants the most
 * evidence available, and the cost that makes a level optional for a scanner
 * walking a filesystem does not apply to it. Naming the top means those tools
 * keep asking for the top as levels are added, instead of each of them pinning
 * whatever number happened to be the maximum on the day it was written.
 *
 * See kof_scan_option.heur_level for what the levels are.
 */
#define KOF_HEUR_LEVEL_MAX 1u


/*
 * Findings are accumulated, not overwritten: two families can match one object, and
 * keeping only the last silently drops one. Over the cap they are counted, because a
 * truncated list that says nothing about being truncated reads as a complete list.
 */
#define KOF_MAX_FINDINGS 16

struct kof_finding {
	uint32_t level;                  /* KOF_LEVEL_* */

	/* <target>.<family.variant>, composed by the engine - for example
	 * "ELF-x64.Mirai.Gen". The target is not authored, so a module cannot claim
	 * a format it was not run against. */
	char     name[224];
};

struct kof_result {
	struct kof_finding v[KOF_MAX_FINDINGS];
	uint32_t n;
	uint32_t dropped;

	/*
	 * The engine stopped before it had finished with this object, because a
	 * limit ran out - almost always the produced-bytes budget on something
	 * that expands far beyond its own size.
	 *
	 * A separate field and not a level, because it is not a finding: the
	 * verdict is "do not know", and it has to be distinguishable from "clean".
	 * Reporting an exhausted budget as clean is what turns a decompression
	 * bomb from a nuisance into a way of not being scanned.
	 *
	 * The VALUE says why, because the three reasons call for different actions
	 * and a single bit made them one word. A limit is the caller's own setting
	 * and can be raised; an unsupported coding is this engine's gap and a bug
	 * report; a damaged object is the file's own problem and neither of those.
	 * Telling somebody "not fully examined" when the answer is "this build has
	 * no LZMA" wastes their afternoon.
	 */
	uint32_t broken;      /* enum kof_broken, zero when the object was finished */
};

/*
 * Why an object was not finished. Ordered by how specific the reason is, which is
 * also the order they take precedence in: the first reason recorded is kept, since
 * whatever stopped things first is what explains the rest.
 */
enum kof_broken {
	KOF_BROKEN_NONE = 0,
	/* A budget, a memory ceiling or a child count ran out. The caller set
	 * these and can set them higher. */
	KOF_BROKEN_LIMIT,
	/* A compression method, packer version or format this build does not
	 * implement. The object is fine; the engine is short of something. */
	KOF_BROKEN_UNSUPPORTED,
	/* The object's own structure does not hold together - a stream that does
	 * not decode, a header that contradicts itself. */
	KOF_BROKEN_DAMAGED,
	/*
	 * The content is encrypted and no key was supplied.
	 *
	 * Its own reason rather than a kind of UNSUPPORTED, because the two lead
	 * somewhere different. UNSUPPORTED is a gap in this build that a later one can
	 * close; this cannot be closed by any amount of work on the engine, and an
	 * operator reading it needs to know that the file will keep coming back the
	 * same way. Every container format that carries encryption reports it with this
	 * value, so a scan says the same thing whether the archive was a zip, a
	 * document, a RAR or a 7z.
	 */
	KOF_BROKEN_ENCRYPTED,

	/*
	 * One past the last, so a caller can size a table of reasons.
	 *
	 * Here because the alternative was a literal, and the literal was wrong the
	 * moment a reason was added: the scanner counted reasons below 4 and printed
	 * reasons below 4, so the first new one was tallied into the total and then
	 * left out of the breakdown - 81 objects broken, 53 accounted for. A count
	 * that does not add up is worse than no count.
	 */
	KOF_BROKEN_COUNT
};

const char *kof_broken_name(uint32_t reason);

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
	uint64_t by_target, by_size, by_arch, by_subtype, by_region;

	uint64_t gram_bytes;             /* cost of building presence sets */
	uint64_t gram_answers;           /* searches answered without scanning */

	uint64_t searches, bytes_searched;

	/*
	 * The most produced data alive at once, over the whole scan.
	 *
	 * The one number that says whether the memory ceiling actually held. Peak
	 * rather than current, because the interesting question about a bomb is not
	 * where it ended up but how high it got, and reported rather than merely
	 * enforced: a limit nothing can observe is a limit nobody can show works.
	 */
	uint64_t peak_resident;
};

typedef struct kof_engine  kof_engine;
typedef struct kof_scanner kof_scanner;

/*
 * Open a database: a directory of packs, or a single one.
 *
 * NULL if nothing could be loaded.
 */
kof_engine *kof_engine_open(const char *db_path);
void        kof_engine_close(kof_engine *);

/*
 * What the database holds, counted as two numbers because it is two things.
 *
 * A RECORD is one detection: something that names a family and can call an object
 * bad. An UNPACKER opens containers and names nothing. Adding them gives a number
 * that answers no question anybody has - "how much do I detect" is the records,
 * and "what can I see inside" is the unpackers - and a database of ten unpackers
 * and no detections would report ten and find nothing.
 *
 * Neither is the number of literals. That is larger, moves when a signature is
 * rewritten without any signature being added, and is a fact about the engine's
 * internals rather than about the database.
 */
uint32_t    kof_engine_records(const kof_engine *);
uint32_t    kof_engine_unpackers(const kof_engine *);

/*
 * The database format version every loaded pack matched.
 *
 * A constant of this build rather than something read out of a file, and it is one
 * precisely because the loader refuses any pack that disagrees with it: there is no
 * state in which a loaded database has some other version. It is reported so that
 * an operator looking at a scanner and a database directory can tell whether they
 * belong together, which is the question this answers.
 *
 * The engine's own version belongs beside this and is not here yet.
 */
uint32_t    kof_engine_db_version(const kof_engine *);

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
/*
 * Called once per object, including the ones the engine produced itself.
 *
 * `bytes` and `len` are the object as it was scanned, and for a produced object -
 * a decompressed archive entry, an unpacked executable - they are the only place
 * it exists: it was never a file and it is gone once this returns. A host that
 * wants to write out what an unpacker recovered has nothing else to write, which
 * is why they are here rather than left to a second, richer callback that could
 * disagree with this one.
 *
 * The pointer is valid for the duration of the call and no longer. Copy what you
 * mean to keep.
 *
 * Return non-zero to abandon the walk.
 */
typedef int (*kof_on_object)(const char *name, const void *bytes, uint64_t len,
			     const struct kof_result *res, void *user);

/*
 * How a scan is allowed to spread, and how thorough it has to be.
 *
 * Data, and passed per scan rather than set on the engine: a limit is the caller's
 * business, not a property of the database, and two callers in one process must be
 * able to differ.
 *
 * Zeroing the struct gives the conservative answer everywhere - no recursion - so a
 * caller that forgets a field does not get a surprise, it gets less.
 */
struct kof_scan_option {
	int      recurse_dirs;     /* descend into directories */
	uint32_t max_depth;        /* 0 -> a built-in ceiling applies */
	int      follow_symlinks;  /* off is the only safe default: a link into an
				    * ancestor turns a walk into a loop */

	/*
	 * Keep going after the first finding on an object.
	 *
	 * Off by default, which is both the cheap answer and the conservative one:
	 * once an object has been named, running the rest of the database on it buys
	 * a longer list and nothing else. An on-access hook only ever needs to know
	 * whether to block.
	 *
	 * On costs the whole database per infected object and is what a report wants:
	 * an object can belong to two families, and a list that stops at one is a
	 * list that says nothing about the other.
	 *
	 * The trade to know about: with this off, which name is reported depends on
	 * where the matching module happens to sit in the database, because the scan
	 * stops at the first one that fires. Every scanner that stops early has this
	 * property; naming it here is cheaper than rediscovering it from a bug report
	 * about a sample that changed its name after a database update.
	 */
	int      all_matches;

	/*
	 * THE HEURISTIC'S OFF SWITCH, AND WHY IT IS AN OFF SWITCH.
	 *
	 * Zero - the default a memset gives - RUNS the heuristic. It used to be
	 * the other way round and that was wrong: the evidence level 0 scores is
	 * evidence the parse and the unpackers have already produced by the time
	 * this is reached, so having to ask for it meant paying for the facts and
	 * then throwing them away. A caller who wants nothing but named families
	 * sets this, and then nothing is gathered and nothing is scored - the
	 * collector is not entered at all.
	 *
	 * What a heuristic reports is always its own level and never INFECT. It
	 * works from traces that cannot establish identity, only that something
	 * is worth a look, and a verdict that named a family from this evidence
	 * would be claiming more than it measured.
	 */
	uint32_t heur_off;

	/*
	 * HOW MUCH EVIDENCE THE HEURISTIC MAY GO AND FETCH.
	 *
	 * 0 - the default. Structure only: what the format parse found wrong with
	 *     the object, and what the unpackers made of it. No extra searching
	 *     and no extra pass; every fact at this level already exists.
	 * 1 - also marker evidence: asking the presence set about markers that no
	 *     module's logic reached, and locating them. NOT IMPLEMENTED yet, and
	 *     behind its own number rather than folded into the default because
	 *     it is the level that costs a pass over the object - the reason the
	 *     free level runs for everybody and this one does not.
	 *
	 * Separate from heur_off so that "should this run" and "how far should it
	 * look" stay separate questions. Rolling them into one number would make
	 * the value that means off sit at one end of a ladder whose other end is
	 * the most expensive setting, and every caller would have to know which
	 * end was which.
	 *
	 * A caller that wants everything this build can offer should say so with
	 * KOF_HEUR_LEVEL_MAX rather than with a number. An analysis tool asks for
	 * the most because it is looking at one file on purpose - it is not the
	 * scanner walking a filesystem, and the cost that makes a level optional
	 * there does not apply - and it should keep asking for the most as levels
	 * are added, without an edit to every such tool.
	 */
	uint32_t heur_level;

	/*
	 * What producing children is allowed to cost.
	 *
	 * Two different limits, because they answer two different questions and
	 * conflating them was a mistake worth recording. One bounds MEMORY AT ANY
	 * INSTANT; the other bounds TOTAL WORK over the whole tree. A single number
	 * cannot do both: made small enough to protect memory it refuses ordinary
	 * archives, and made large enough for those it stops protecting memory.
	 *
	 * max_resident_bytes is the hard one, and the reason this engine exists in
	 * the shape it does. Objects are mapped, not read, so a 12GB scan holds a
	 * few megabytes; producing children is the only path that allocates, and it
	 * must not throw that away. Default 128MB. Counted over everything produced
	 * and still alive - the object being emitted plus every child not yet
	 * scanned - and released as each child is finished with.
	 *
	 * It is counted even for output written to a temporary file. That looks
	 * over-cautious and is not: a temporary directory is very often tmpfs, where
	 * the "spill to disk" is still memory and is additionally capped by a mount
	 * option this engine cannot see.
	 *
	 * max_produced_bytes is the bomb defence: total bytes a whole tree may
	 * yield, not per child. Per-child limits are how a container full of entries
	 * that are each individually reasonable adds up to something that is not.
	 * A single layer of DEFLATE reaches about 1000:1, so a bomb needs no nesting
	 * and a depth limit never sees it. Zero means max(64MB, object size x 64).
	 *
	 * max_object_bytes is the third, and it is the one that decides how much
	 * WORK a scan does rather than how much memory it holds. The other two are
	 * reached only by an object that is trying; this one is reached constantly,
	 * because inflating an entry is the expensive thing a scan does and most
	 * entries are tiny while a few are enormous. Measured over 1352 real zip
	 * entries: median 255 bytes, 95th percentile 92KB, and the handful above
	 * 8MB accounted for 98.2% of every byte decoded.
	 *
	 * Zero means 16MB, which is as low as it goes without losing a detection -
	 * 8MB was measured and drops one, because a UPX packed miner unpacking to
	 * 13MB is a large object rather than a padded one. Raising it buys the tails
	 * of large entries and costs decompression on every archive holding one.
	 *
	 * A child that is a window into its parent costs none of the three: nothing
	 * was produced and nothing is resident that was not already. Those are
	 * bounded by max_children and max_depth.
	 */
	uint64_t max_resident_bytes;
	uint64_t max_produced_bytes;
	uint64_t max_object_bytes;
	uint32_t max_children;     /* 0 -> a built-in ceiling applies */
};

/*
 * Told what a module worked out, as it works it out.
 *
 * `what` is the module's own name for what it worked out and `value` the one
 * number it attached - a version, a count. Called during the module's run, so it
 * arrives before any finding that module goes on to report, which is the order
 * that makes it useful when the finding never comes.
 *
 * Diagnostics, not results: nothing here is a verdict and no scan depends on it.
 * Set it and a debugging tool sees a module's reasoning; leave it unset, which is
 * the default, and modules that emit notes cost a NULL test each.
 */
/*
 * A NOTE, WITH A NUMBER TO MATCH ON RATHER THAN A NAME TO PARSE.
 *
 * `what` is the authored text - "UPX.ELF.version", "Rar.entries" - and is for
 * showing. `fact` is a stable id for the FIELD part of it, the text after the
 * last dot, so a consumer that wants "the version, whoever said it" compares one
 * integer instead of finding a dot and running strcmp.
 *
 * Stable by construction: it is a hash of the field text, so the same field from
 * a later build or a different module is the same id, and a module adding a new
 * field needs no registry and no allocation. Two modules that choose the same
 * field word do collide - which is the same thing that was true when consumers
 * matched on that word, and the module name is right there to tell them apart.
 *
 * Costs nothing to ignore. It exists because the note channel is turning into
 * something a scan path may read per object, and finding a dot in a string per
 * fact per object is the wrong shape for that.
 */
typedef void (*kof_on_debug)(uint32_t fact, const char *what, uint64_t value,
			     void *user);

/*
 * The id for a field name, so a caller can compute the handful it cares about
 * once and then compare integers:
 *
 *     static uint32_t f_version;
 *     if (!f_version) f_version = kof_fact_id("version");
 *     if (fact == f_version) ...
 *
 * Takes the field alone, not the full name - kof_fact_id("version"), not
 * kof_fact_id("UPX.ELF.version").
 */
uint32_t kof_fact_id(const char *field);

void kof_scanner_on_debug(kof_scanner *, kof_on_debug, void *user);

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
int kof_scan_path(kof_scanner *, const char *path, const struct kof_scan_option *,
		  kof_on_object cb, void *user);

#endif /* KOFENG_H */