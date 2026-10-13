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
 *     kof_engine  *eng = keng_open("/var/lib/kofeng/db");
 *     kof_scanner *sc  = kscan_new(eng);          // one per thread
 *
 *     struct kof_result r;
 *     if (kscan_path(sc, path, &r) > 0)
 *             for (i = 0; i < r.n; i++) ... r.v[i].name ...
 *
 *     kscan_free(sc);
 *     keng_close(eng);
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

#include <kofmod/infected.h>
#include <kofhash.h>   /* SHA-256 and KOF_ERR_* - see core */
#include <kofdebug.h>   /* KOFENG_BUILD, the stamp the Makefile passes - see core */

#include <koftypes.h>   /* the scan's types: result, options, callbacks, stats - see core */
#include "verdictor/verdict.h"   /* how a detection is named */

/* What KOF_BROKEN_* reason means, as a noun phrase - see the definition. */
const char *kverdict_broken_name(uint32_t reason);

/*
 * The id for a field name, so a caller can compute the handful it cares about
 * once and then compare integers:
 *
 *     static uint32_t f_version;
 *     if (!f_version) f_version = kverdict_fact_id("version");
 *     if (fact == f_version) ...
 *
 * Takes the field alone, not the full name - kverdict_fact_id("version"), not
 * kverdict_fact_id("UPX.ELF.version").
 */
uint32_t kverdict_fact_id(const char *field);

/*
 * Open a database: a directory of packs, or a single one.
 *
 * NULL if nothing could be loaded.
 */
kof_engine *keng_open(const char *db_path);
void        keng_close(kof_engine *);

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
uint32_t    kdb_records(const kof_engine *);
uint32_t    kdb_unpackers(const kof_engine *);
/* How many heuristic rules the database holds. Its own count because a rule is
 * neither a record nor an unpacker, and a database whose rules were invisible in
 * the banner is one nobody checks the loading of. */
uint32_t    kmatch_rules(const kof_engine *);
/*
 * HOW MANY DIAGNOSES THE DATABASE HOLDS. Introspection, like kmatch_rules
 * beside it: a database whose diagnoses failed to load is one nobody checks.
 *
 * THERE IS NO kdb_diag_name. It existed to turn an id out of
 * kof_result.diag back into a word, and nothing reports diagnoses to a
 * caller any more - see the note there. A rule names a diagnose by its own
 * name through kof_diag(), which the build hashes; no string travels.
 */
uint32_t    kdb_diagnoses(const kof_engine *);
/*
 * DID EVERY DIAGNOSE THE PACKS CARRY LOAD. kdb_diagnoses counts what loaded and
 * cannot tell "256 of 300" from "256": this says the database had more than the
 * engine will hold (KOF_DB_MAX_DIAG, a bound against a hostile pack), which a
 * scan can never notice. 1 means some diagnose was not loaded.
 *
 * kdb_diag_collisions is the other way one is lost: its 32-bit id (KOF_DIAG_ID)
 * equals one already loaded, so the engine refused it - the count of those, each
 * also named on stderr. ksigbuilder refuses to build such a pack; a pack built by
 * something else is caught here.
 */
int         kdb_diag_full(const kof_engine *);
uint32_t    kdb_diag_collisions(const kof_engine *);

/*
 * WHAT THE MULTI-PATTERN TABLES COST, AND HOW BAD THEIR WORST BUCKET IS.
 *
 * Two numbers this design rests on, and neither is visible from anywhere else.
 *
 * `bytes` is the memory the tables took. It is CHOSEN and not incurred - the
 * bucket counts are derived from the marker count and bounded - and the claim
 * that a base can grow without the matcher's footprint following it is only
 * checkable if the footprint can be read.
 *
 * `max_chain` is the longest bucket in any of them, which is what bounds the
 * worst case: a bucket hit costs one verify per marker on its chain, so a base
 * where many markers share their first four bytes turns a file full of those
 * bytes into a slow scan. Four on the shipping base. Nothing in the engine acts
 * on it yet - a threshold cannot be fitted on a hundred markers - so it is
 * reported rather than enforced, which is the honest state of it.
 *
 * Either pointer may be NULL. Zero-filled and non-zero return when the database
 * has no tables, which is not an error: it means every marker is searched one
 * at a time, as this engine did before 2.0.
 */
int         kmatch_tables(const kof_engine *, uint64_t *bytes,
				  uint32_t *max_chain);

/*
 * WHAT THE LOADED DATABASE ACTUALLY SAYS ABOUT ITSELF.
 *
 * Read out of the packs, not taken from a constant of this build - and the
 * difference is new. While a pack was refused unless its version matched
 * exactly, the loaded value could only be this build's, so a constant was the
 * same answer; the comment here said so. A minor that is accepted when it is
 * LOWER ends that: an engine at 1.7 happily loads a 1.3 database, and reporting
 * 1.7 would be reporting the reader rather than what was read.
 *
 * THE OLDEST OF THE PACKS, because that is the question an operator is asking.
 * A database directory is many files, and it is only as fresh as its stalest
 * part: reporting the newest would hide exactly the pack that needs updating.
 *
 * Zero-filled and non-zero return when there is no database.
 */
/*
 * THE ENGINE'S OWN VERSION, AND IT GATES NOTHING.
 *
 * Worth saying first, because a number in a header invites a comparison. Every
 * compatibility question here is already answered by a field that describes an
 * ARTEFACT: a pack says which layout it has and which module ABI its code was
 * built against, and the loader refuses on those. There is nothing left for an
 * engine version to decide, and a check written against one would be inventing
 * a rule rather than enforcing one.
 *
 * What it is for: the number a person quotes in a bug report, and the line an
 * operator reads to see whether the binary in front of them is the one they
 * think it is.
 *
 * A FUNCTION AND NOT JUST THE MACROS, because the two answer different
 * questions once this is a shared library: the macros say what the caller was
 * COMPILED against, the call says what is actually loaded. When they disagree
 * that is itself the bug being reported.
 */
/*
 * 3.0 - DETECTION STOPPED BEING ONE PASS AND STARTED BEING A LADDER.
 *
 * A major for the same reason 2.0 was one: the shape of the scan changed, and
 * an operator quoting a number should see it move.
 *
 * WHAT CHANGED. The two batched passes - the multi-pattern sweep and the
 * similarity feed - ran before the first module was asked anything. They are
 * demand driven now: the first module that DECLARES a marker pays for the
 * sweep, the first that declares a block pays for the feed, and the module
 * index is ordered so that the modules asking for least come first. Paired
 * with it, a detector's verdict ends the analysis chain rather than being
 * collected beside the rest of it. Worst case is unchanged - nothing is
 * skipped that would have run - and the happy case stopped paying for work
 * its answer made unnecessary. Measured over 5248 real ELF samples: 18734 ms
 * to 16005 ms, with the same 1341 files detected and byte-identical output on
 * 954 system binaries.
 *
 * AND ONE MEASURE IS GONE. The string set - kof_mutation_strings - was removed from
 * the engine, the generator and the signature base. That is a module ABI break
 * and is gated there, by KOFSIG_ABI_MIN; this number does not gate it and does
 * not pretend to.
 *
 * 2.0 - THE SCAN STOPPED BEING ONE SEARCH PER MARKER.
 *
 * A region is read once for every marker declared against it, by a routine the
 * build chooses from the marker set. Nothing about the artefacts moved.
 */
#define KOFENG_MAJOR 3u
/*
 * 1 - the database loader and writer changed together.
 *
 * dbpacker stopped page aligning the code section and dbloader stopped expecting
 * it to be, which is a change in this library's own code and so belongs here as
 * well as in KOF_PACK_MINOR. It still gates nothing: a pack says its own layout
 * and that is what the loader refuses on.
 *
 * 2 - the object tree: entries, children and smart deep scan.
 *
 * A capability rather than a layout move, which is what this number is for.
 * What a caller can do that it could not before:
 *
 *   READ WHAT A CONTAINER DECLARES without opening any of it. ctx->entries
 *   publishes one row per thing the parse found - kind, name, coding chain -
 *   so a host can show a document's contents without a decompressor running.
 *
 *   SEPARATE ON DEMAND. heur_off gates opening those rows into objects, so a
 *   caller can look first and descend afterwards, and a region still covers
 *   every byte either way.
 *
 *   HAVE THE ENGINE NOT OPEN WHAT NOTHING WOULD LOOK AT. A producer asks
 *   fmt_wanted and the answer comes from the loaded database, so what a scan
 *   spends follows the rules it was given rather than a list in the engine.
 *
 * THE DATABASE FORMAT DID NOT MOVE, and that is not an oversight. Everything
 * above rides in fields the pack already had - one more bit in a module's
 * heur_want mask, two more values on the format axis - so KOF_PACK_MINOR
 * stays where it is, exactly as the rule beside it in dbcore.h requires:
 * that number moves when the LAYOUT moves and not when the engine grows a
 * capability. A rebuild is needed; a refusal is not.
 *
 * 3 - objects that are not files: memory, events, and what they carry.
 *
 * The theme is that an object need no longer have come off a disk, and a rule
 * need no longer be about the bytes alone. What a caller can do that it could
 * not before:
 *
 *   SCAN AN IMAGE THE LOADER MAPPED. enum kgenome_pe_layout tells the PE parse
 *   which of the two layouts a section table describes, so the scan regions of
 *   an image read out of a process resolve to the right bytes - they resolved
 *   to other sections' bytes before, with no error anywhere. kgenome_pe_unmap turns
 *   one back into a file, undoing the loader's base relocations, which is what
 *   makes the file corpus apply to a module that was never written to disk.
 *
 *   TELL A PARSER WHAT THE BYTES CANNOT SAY. kof_scan_option.as_view carries
 *   the declared inputs a parse needs and cannot read - where a submission's
 *   content sits inside a collected record, which layout an image is in - and
 *   the declared path now wipes the view per object, which it did not, so one
 *   object stopped inheriting the last one's answers.
 *
 *   NAME THE PARTS OF A .NET ASSEMBLY, wherever it is carried. The CLR region
 *   bits in kofmod/clr.h mean the same thing in every format that can host an
 *   assembly, so a rule about a type name is written once; PE resolves them
 *   today, and the metadata reader itself knows nothing about PE.
 *
 *   OPEN WHAT AN EVENT CARRIED. An AMSI submission that IS an executable
 *   declares it as an entry, so the engine's ordinary declared-children walk
 *   opens it as a PE child - by the same road a zip member takes, instead of a
 *   second scan of the same bytes under the event's own name.
 *
 *   ASK ABOUT A REGION WITHOUT READING IT. region_shape answers how a region is
 *   laid out - how many runs, how long the longest, where it starts - and
 *   region_entropy and entropy_at answer what kind of bytes are in one. A rule
 *   could ask what a region CONTAINED and could not ask either of those, and
 *   could not compute them: the bytes are scattered and a module has no
 *   writable data to keep a histogram in.
 *
 *   SAY THAT A FINDING IS ABOUT THIS OBJECT. KOF_ENG_KEEP_ON_OPEN. A rule's
 *   heuristic is dropped when the object produces children, which is right for
 *   a rule that means "I could not identify this" and deletes the finding of
 *   one that means "this carries something" - the child is an ordinary file
 *   that nothing fires on, so there is no leaf for the signal to move to.
 *
 * THE DATABASE FORMAT DID NOT MOVE HERE EITHER, and for the same reason: a bit
 * in heur_want, bits in the scan mask that no format used, values in the
 * subtype mask, and fields appended to view structs that only grow at the end.
 * KOF_PACK_MINOR stayed at 1 through all of it. A rebuild is needed; a refusal
 * is not.
 */
/*
 * 0 - THE MINOR RESTARTS WITH THE MAJOR.
 *
 * Nothing has been added on top of 3.0 yet. The three notes above describe
 * what 2.1, 2.2 and 2.3 were and are kept because a number an operator quoted
 * a year ago should still mean something when it is looked up.
 *
 * UNLIKE 2.x, THIS MAJOR DID MOVE THE ARTEFACTS, and both of them: the pack
 * layout to 2.0 - see KOF_PACK_MAJOR - and the module ABI to 3, floor and
 * ceiling together, because a vtable slot was removed rather than added. A
 * database built before this is refused rather than read, which is the first
 * time that has been true of an engine bump here and is the reason to say it
 * twice.
 */
#define KOFENG_MINOR 0u

/* KOFENG_BUILD, the stamp the Makefile passes, is defaulted in <kofdebug.h>. */

struct kof_version {
	uint16_t major;
	uint16_t minor;
	uint32_t build;      /* YYYYMMDDHH in UTC, as the database's is */
};

void        keng_version(struct kof_version *);

struct kof_db_version {
	uint16_t major;
	uint16_t minor;
	uint32_t build;      /* YYYYMMDDHH in UTC; 0 when the pack did not say */
	uint32_t machine;    /* enum kof_pack_machine, as the packs were built */
};

int         kdb_version(const kof_engine *, struct kof_db_version *);

/*
 * ONE NUMBER FOR THE DATABASE AS IT IS LOADED, for a cache to key on. Zero when
 * nothing is loaded.
 *
 * WHY THE BUILD STAMP IS NOT THAT NUMBER. kdb_version reports the
 * OLDEST pack's build, to an hour, and a build stamp is a date rather than a
 * description of content:
 *
 *   - removing a pack leaves the oldest one where it was, so a database with a
 *     whole family taken out of it has the same stamp as the one it came from.
 *     Measured: a cache written with the text signatures present was reused by
 *     a scan of the same tree without them, and the other way about, which is
 *     the case a verdict cache must never get wrong;
 *   - adding a newer pack does not move a minimum either;
 *   - and two builds in one hour share a stamp whatever changed between them.
 *
 * So this is over CONTENT: every loaded pack's checksum, length and build,
 * combined so that the ORDER packs were loaded in cannot change the answer -
 * a directory walk is not required to hand them over twice the same way. The
 * checksums are already computed and verified at load, so this costs no read
 * of the database and no hash of it.
 *
 * A DIFFERENT ANSWER MEANS RESCAN, NOT REFUSE. A database update is an update:
 * every stored verdict predates it and is worth nothing, and the cache that
 * holds them is discarded and rebuilt. Nothing about the scan is blocked - see
 * kof_fidset_load, which reads a set written under another stamp as an empty
 * one.
 */
uint64_t    kdb_stamp(const kof_engine *);

/* One scanner per thread. The engine it is made from must outlive it. */
kof_scanner *kscan_new(const kof_engine *);
void         kscan_free(kof_scanner *);

const struct kof_stats *kscan_stats(const kof_scanner *);





void kscan_on_debug(kof_scanner *, kof_on_debug, void *user);

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
int kscan_bytes(kof_scanner *, const void *bytes, uint64_t n,
		   const char *name, const struct kof_scan_option *,
		   kof_on_object, void *user);

int kscan_path(kof_scanner *, const char *path, const struct kof_scan_option *,
		  kof_on_object cb, void *user);

/*
 * The same scan, over several scanners at once.
 *
 * WHY IT EXISTS, in one measurement: a scan of 12.9GB spends 71% of its
 * instructions in memmem and keeps exactly one core busy. Nothing in the engine
 * was waiting for a disk - the work is literal search - so the only thing left
 * to give it is more than one core.
 *
 * The caller supplies the scanners, one per thread, because that has always been
 * this API's division: the engine is immutable and shared, a scanner is not. A
 * caller that wants four threads makes four scanners from one engine and hands
 * them in. Nothing here allocates one, so per-worker budgets stay the caller's
 * to set - and they SHOULD be set: max_resident_bytes is per scanner, so four
 * workers with the default may hold four times what one did.
 *
 * `path` a directory: the files under it are spread across the scanners. `path`
 * a file, or n_sc of 1: identical to kscan_path, threads and all skipped.
 *
 * The callback is serialised and needs no locking of its own. The ORDER objects
 * arrive in is not preserved - they come back as workers finish - which is the
 * one thing a caller gives up by asking for this.
 *
 * Returns the number of objects scanned, or a KOF_ERR_*.
 */
#include <kofentropy.h>   /* kentropy_eighths, kentropy_hist - see core */


int kscan_path_mt(kof_scanner **, unsigned n_scanners, const char *path,
		     const struct kof_scan_option *, kof_on_object cb, void *user);

#endif /* KOFENG_H */