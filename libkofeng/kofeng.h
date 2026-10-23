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
 *     // the callback gets a struct kof_result per object:
 *     //     if (res->has_verdict) ... res->verdict.name ...
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
 * A RECORD is one detector module. An UNPACKER opens containers and names nothing. Adding them gives a number
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
/*
 * HOW MANY DIAGNOSES THE DATABASE HOLDS. Introspection, like the two counts above:
 * a database whose diagnoses failed to load is one nobody checks.
 *
 * THE WAY BACK FROM A VERDICT. kof_result.verdict lists the ids of the diagnoses that
 * matched (kof_finding.diag) and of the diseases they and the modules declared
 * (kof_finding.disease); these turn an id into what a person reads.
 *
 *   kdb_diagnose_name     the diagnose's name, or NULL for an id the database does not hold
 *   kdb_diagnose_disease  the id of the disease it declares, 0 when it declares none
 *   kdb_disease_name      the disease's behaviour ("flood-network/raw-header"), or NULL
 *   kdb_disease_type      the kof_maltype it was declared with, -1 when the id is not named
 *
 * The strings are the engine's own, read out of the loaded packs, and live as long as
 * it does. A rule still names a diagnose by its own name through kof_diag(), which
 * the build hashes; no string travels to a module.
 */
const char *kdb_diagnose_name(const kof_engine *, uint32_t id);
uint32_t    kdb_diagnose_disease(const kof_engine *, uint32_t id);
const char *kdb_disease_name(const kof_engine *, uint32_t id);
int         kdb_disease_type(const kof_engine *, uint32_t id);
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
 * WHAT THE LOADER REFUSED, AS COUNTS. kdb_diag_refused is the diagnose records
 * that did not read (a field this build does not accept, a record that runs past
 * its pack): each is a diagnose that is not there. kdb_diag_packs_refused is the
 * .kdig files (diagnoses, diseases, and the one an older build wrote) not read whole - a header that does
 * not add up, or a file past the allowance of the load. Both are also written to
 * stderr when met; these are what a host linked to the library can read. Zero is
 * the normal value.
 */
uint32_t    kdb_diag_refused(const kof_engine *);
uint32_t    kdb_diag_packs_refused(const kof_engine *);
/*
 * WHAT BUILDING THE SIMILARITY INDEX SAID. The KOF_MTN_B_* word (kofmutation.h):
 * 0 is clean, KOF_MTN_B_FILTER_DEGRADED means the filter in front of the index holds
 * fewer than 12 bits a hash because the engine's memory ledger (or the filter's cap) gave
 * it less (slower, not less accurate), KOF_MTN_B_IN_RAM means a pack with no index trailer
 * had its index built in memory (repack it), and an OVER_BUDGET bit means the index did not
 * fit the ledger and similarity rules score nothing. `bytes` is what the index holds
 * resident - directories and the filter, plus the bodies of packs without a trailer - shared
 * by all scanners; `keys` its distinct hashes.
 */
uint32_t    kdb_mutation_status(const kof_engine *, uint64_t *bytes, uint32_t *keys);

/*
 * WHAT THE PATTERN TABLES COST, AND HOW BAD THEIR WORST KEY IS.
 *
 * Two numbers this design rests on, and neither is visible from anywhere else.
 *
 * `bytes` is the memory the tables hold - for every pack together, and it does not follow the
 * number of markers: the markers themselves stay in the pack (detectors/pattern/kofpix.h), and what
 * is resident is a filter whose size the engine's ledger grants and the exact set of the distinct
 * keys (about two bytes a key). The claim that a base can grow without the matcher's footprint
 * following it is only checkable if the footprint can be read.
 *
 * `max_chain` is the longest run of markers that share their key hash, which is what bounds the
 * worst case: a hit on that key costs one record check per marker of the run, so a base where
 * many markers share the key a file is full of makes a scan slow. The scan's reads of the pack are
 * bounded per object (the sweep stops, says so, and the exact per-marker path answers instead), so
 * it is reported rather than enforced.
 *
 * Either pointer may be NULL. Zero-filled and non-zero return when the database has no tables,
 * which is not an error: it means every marker is searched one at a time, as this engine did before
 * 2.0.
 */
int         kmatch_tables(const kof_engine *, uint64_t *bytes,
				  uint32_t *max_chain);

/*
 * WHAT LOADING THE PATTERN TABLES SAID. The KOF_PIX_B_* word (detectors/pattern/kofpix.h): 0 is
 * clean; DEGRADED means the filter in front of the key set is coarser than its default because
 * the engine's memory ledger gave less (slower, as exact); IN_RAM that a pack with a large table
 * and no table in its tail had one built in memory (repack it); OVER_BUDGET, OPEN_FAILED and NOMEM
 * that a pack's table is not in use and its markers are searched one at a time (exact, and slower).
 * `bytes` is what the tables hold in memory, `markers` how many markers they key. Either may be NULL.
 */
uint32_t    kdb_pattern_status(const kof_engine *, uint64_t *bytes, uint64_t *markers);

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
 * THE DATABASE FORMAT DID NOT MOVE HERE EITHER, and for the same reason: a bit
 * in a rule's want-mask, bits in the scan mask that no format used, values in the
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

/*
 * THE ENGINE'S MEMORY BUDGET: the whole engine - the database, every scanner, every buffer -
 * stays under one number, 512 MiB unless the host sets another; there is no "unlimited".
 * The model is in kofcore/kofbudget.h. keng_set_memory_cap takes effect for scanners made and
 * objects started afterwards, and is refused (0) below what is already held or below 16 MiB; zero restores the
 * default. keng_memory_db is what the loaded database holds privately (charged first),
 * keng_memory_peak the most the budget ever held. kscan_new answers NULL when the budget
 * cannot afford another scanner (the fixed cost of one, see kofbudget.h) - a caller that asked
 * for more jobs than that gets fewer, and says so.
 */
uint64_t keng_memory_cap(const kof_engine *);
int      keng_set_memory_cap(kof_engine *, uint64_t bytes);
uint64_t keng_memory_db(const kof_engine *);
uint64_t keng_memory_peak(const kof_engine *);

/*
 * One scanner per thread. The engine it is made from must outlive it.
 *
 * kscan_new is the short form: NULL says the scanner was not made, and nothing about why.
 * kscan_new_ex says it, in *why (when not NULL), with no state shared between calls and
 * so none between threads:
 *
 *   KSCAN_NEW_OK         made (the result is not NULL)
 *   KSCAN_NEW_NO_ENGINE  the engine was NULL
 *   KSCAN_NEW_BUDGET     the engine's memory budget cannot afford the fixed cost of another
 *                        scanner (the cap, the database and the scanners already made leave
 *                        less): free one, or raise the cap - asking again changes nothing
 *   KSCAN_NEW_NOMEM      the C library refused an allocation: asking again may work
 *
 * kscan_new_why_str is the one spelling of each, for a tool that prints it. The values are
 * enum kscan_new_status (kofcore/kofhash.h, beside the KOF_ERR_* codes, because the scanner
 * unit that answers them cannot include this header).
 */
kof_scanner *kscan_new(const kof_engine *);
kof_scanner *kscan_new_ex(const kof_engine *, int *why);
const char  *kscan_new_why_str(int why);
void         kscan_free(kof_scanner *);

const struct kof_stats *kscan_stats(const kof_scanner *);

/*
 * GIVE BACK WHAT THIS SCANNER KEEPS BETWEEN OBJECTS - for a host that lives a long time.
 *
 * A scanner keeps, for the next object, the parsed view of every format it has met, its
 * decompressor states, the matcher's presence table (up to 32 MiB), the symbol block and the
 * last object's analysis; and the C library keeps what was freed. A process that scanned one
 * 30 MB object holds that much for the rest of its life (measured: 71 MB steady after 700
 * scans against 4.8 MB for the median object; 9.9 MB with the heap handed back between
 * objects). The engine does not call mallopt or malloc_trim on its own - allocator policy is
 * the process's - so the host asks:
 *
 *   KSCAN_TRIM_CACHES  free the scanner's own caches and the last object's products. Cheap
 *                      (a few frees, no system call): fit to call after every object.
 *   KSCAN_TRIM_HEAP    ask the C library to return its free pages to the OS (malloc_trim
 *                      where there is one). Costs a walk of the heap: measured +2.6% CPU
 *                      when done after every one of 3000 scans, so once per batch or per
 *                      idle moment is the usual use.
 *   0                  both.
 *
 * Between scans only, on the thread that owns the scanner: a call made while a scan is
 * running on it (from a callback) is a no-op. Idempotent; thread-safe across DIFFERENT
 * scanners (nothing here is shared, and the heap call is the C library's own). Everything it
 * drops is made again on demand, so the next scan finds what it would have found.
 * `kof_stats.scan_trims` counts the calls that had something to give back.
 *
 * Within one scan the engine already lets go at its own stage boundaries, with nothing for
 * the host to do: the decode trace before the normaliser builds its view; the normaliser's
 * working buffer when the view has been handed to the sink; the emulator and the image it
 * rebuilt when the module that asked for the run returns; the diagnose graph, symbol
 * state and analysis products when the next object begins.
 */
#define KSCAN_TRIM_CACHES 1u
#define KSCAN_TRIM_HEAP   2u
void kscan_trim(kof_scanner *, unsigned flags);





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
 * objects scanned, or a KOF_ERR_*: KOF_ERR_NOMEM when memory ran out before any object reached
 * the callback; a tree cut short by it after that keeps its count and moves
 * kof_stats.limit_hits.
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