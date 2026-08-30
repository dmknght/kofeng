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
#include <stddef.h>

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

	/*
	 * WHAT THE HEURISTIC MADE OF THIS OBJECT, WHETHER OR NOT IT REPORTED.
	 *
	 * Here rather than left to be recomputed, because it was being
	 * recomputed and the copy drifted. kofviewer built its own facts from
	 * what it could see - tree depth, a name it had been handed - and once
	 * the engine learned to tell a packer from a container the two answers
	 * stopped agreeing. A panel that scores an object differently from the
	 * scanner is worse than one that shows nothing: both look authoritative
	 * and only one is.
	 *
	 * So the engine computes it once, on the object it is looking at, with
	 * the facts only it has, and hands the whole of it back. A caller that
	 * wants to explain the number reads the model - kof_heur_default() - for
	 * the words, and never re-derives the evidence.
	 *
	 * `heur_scored` is 0 when the heuristic did not run (switched off) or no
	 * model covers this format, and that is NOT the same as a score of zero.
	 */
	uint8_t  heur_scored;
	uint8_t  heur_depth;        /* executable packer layers above this object */
	/*
	 * Was this object produced BY an executable packer, as opposed to having
	 * been carried by a container. The viewer's own name-matching guess at
	 * this is exactly what this field exists to retire.
	 */
	uint8_t  from_packer;
	int32_t  heur_score;        /* centinats */
	uint32_t heur_flags;        /* KOF_HEUR_FL(KOF_HEUR_F_*) */
	uint64_t heur_anomalies;    /* the format's own anomaly word */
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
 * HOW A DETECTION IS SPELLED, IN ONE PLACE.
 *
 *     kof_name_compose(buf, sizeof buf, "ELF-x64", "Botnet", "Mirai", "Gen")
 *     -> "ELF-x64/Botnet:Mirai#Gen"
 *
 * The engine composes this for every finding, and three other things reproduce
 * it: kofexamine and kofviewer to show a marker row, and kofinspect to decide
 * WHICH module a scan result belongs to. That last one is not display - it is
 * one half of a string comparison whose other half the engine wrote - so a
 * spelling that drifts there does not look wrong, it silently stops matching.
 *
 * It drifted exactly that way: the family/variant separator moved from "-" to
 * "#" in the engine, kofinspect kept the "-", and every detected sample
 * reported "Hit 0, Skip 1" in the viewer and no verdict at all in kofexamine
 * while the scanner called the same file infected.
 *
 * `target` and `variant` may be NULL or empty and are left out when they are.
 */
void kof_name_compose(char *out, size_t cap, const char *target,
		      const char *maltype, const char *family,
		      const char *variant);


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
/*
 * Values for kof_scan_option.emu_use, and NEVER is the one a memset gives.
 *
 * The other options here default to the useful setting because they cost
 * nothing when they do not apply. This one is different: interpreting an object
 * is the largest thing a scan can do - measured, a UPX-with-LZMA sample needs
 * forty million instructions to reach its payload and the biggest in the corpus
 * needed two hundred and fifty - so a caller gets it by asking, not by omitting
 * a field. kofscanner asks for it at --heur 2.
 */
enum kof_emu_use {
	KOF_EMU_NEVER = 0,  /* interpret nothing, whatever the object looks like */
	KOF_EMU_AUTO  = 1,  /* after every unpacker declined, if the gate fires */
	KOF_EMU_ONLY  = 2   /* interpret instead of the packer modules, ungated */
};

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
	 * WHEN THE INTERPRETER RUNS, and zero is the useful default - like
	 * heur_off above and for a related reason: it costs nothing on an
	 * object it declines.
	 *
	 * It is entered only after every unpacker has declined the object, and
	 * only when the object either hides its code behind something too dense
	 * to be code or carries a header that cannot be loaded as written.
	 * Measured over 1 246 clean binaries - /usr/bin and the unpacked half
	 * of the packed-ELF corpus - that gate selects none of them, so an
	 * ordinary scan never reaches the interpreter at all.
	 *
	 * KOF_EMU_NEVER is for a caller whose answer must not depend on running
	 * anything: the interpreter never executes a guest instruction on the
	 * host, but it is still the largest thing a scan can be asked to do,
	 * and a caller with a hard time bound has a right to refuse it.
	 *
	 * KOF_EMU_ONLY is not a faster AUTO and is not for scanning. It skips
	 * the packer modules and interprets whatever it is given, gate or no
	 * gate, because a person has asked to see what the object does rather
	 * than what a module says about it. Comparing the two answers is the
	 * whole point of having it - a static unpacker and an interpreter
	 * disagreeing about the same file is a finding.
	 */
	uint32_t emu_use;


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
/*
 * Scan bytes the caller already holds, under a name of its choosing.
 *
 * For a tool that has scanned a file and now wants to ask a different question
 * about ONE object inside it - the viewer runs the interpreter on a node the
 * reader picked, having built the tree with the static unpackers. Re-scanning
 * the file with different options would answer that question about every
 * object rather than the one that was asked about.
 *
 * The bytes are borrowed and must outlive the call. Returns the number of
 * objects scanned, or a KOF_ERR_*.
 */
int kof_scan_bytes(kof_scanner *, const void *bytes, uint64_t n,
		   const char *name, const struct kof_scan_option *,
		   kof_on_object, void *user);

int kof_scan_path(kof_scanner *, const char *path, const struct kof_scan_option *,
		  kof_on_object cb, void *user);

#endif /* KOFENG_H */