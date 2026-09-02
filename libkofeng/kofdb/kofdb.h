/*
 * kofdb.h - the loaded database.
 *
 * Turns whatever the database is on disk into a kof_engine: module code mapped
 * executable, plus the tables the host needs to decide which modules to run and
 * what to call a finding.
 *
 * Not scan logic. Nothing here looks at an object under scan; it only materialises
 * the database. The split matters for two reasons:
 *
 *   - a kof_engine is immutable once loaded, so one can be shared by every thread.
 *     Our modules make that genuinely safe rather than safe by convention: they
 *     have no writable data and need no relocation, so the mapped code is read-only
 *     and position independent.
 *   - the mutable, expensive per-scan state - the presence table, the memo, the
 *     match context - belongs to the scanner and is allocated per thread. Keeping
 *     it out of here is what stops a 32MB table from being paid per file.
 */

#ifndef KOFENG_KOFDB_H
#define KOFENG_KOFDB_H

#include <stddef.h>
#include <stdint.h>

#include <kofmod/kofsig.h>
#include "../core/kofcore.h"   /* kof_crc32, kof_round_up */
#include "kofpack.h"       /* KOF_STR_MAX_LEN, KOF_BLOB_MAX_CODE */

/*
 * How many distinct region masks a database may hold.
 *
 * A mask names regions of one format, and the formats define five or six each, so
 * the live combinations across a whole database are dozens at most. The cap exists
 * so the dedup below can scan a fixed array instead of the whole table.
 */
#define KOF_MAX_DISTINCT_MASKS 256u

/* Both entry points have the same signature; which one a module exported is what
 * its pack's kind records, and the engine keeps the two in separate lists. */
typedef void (*kof_scan_fn)(const struct kof_obj_ctx *);

/*
 * One declared string, as the host needs it.
 *
 * The content lives here and not in the blob, which is what allows the host to
 * search on the module's behalf - and therefore to answer many modules' strings in
 * one pass rather than each module scanning for itself.
 *
 * An offset into a shared pool, not an inline buffer, and the record is the pack's
 * record unchanged. The inline form was 516 bytes per string against a measured
 * 12.7 byte average literal - 8.25MB of table for sixteen thousand strings, nearly
 * all of it padding. It also could not hold a compiled hex pattern at all: those run
 * to kilobytes, and sizing every slot for the largest would have made the table
 * 131MB.
 */
struct kof_str_ent {
	uint32_t off;             /* into the pack's string pool */
	uint16_t len;
	uint8_t  kind;            /* enum kof_pack_str_kind */
	uint8_t  flags;           /* KOF_STR_ICASE | KOF_STR_FULLWORD; literal only */
	uint32_t uid;             /* shared by every module declaring these bytes */
};

/*
 * A pack, still mapped.
 *
 * Detection names are never copied out of it - see kof_db_name - so the mapping has
 * to outlive the load that made it. Nothing else here points into a pack.
 */
struct kof_db_pack {
	void  *map;
	size_t len;
	/*
	 * Where this pack's pattern ids start once every pack is loaded.
	 *
	 * Each pack numbers its own patterns from zero, because a pack is built
	 * without knowing what it will be loaded beside. Adding the base makes the
	 * id unique across the database, which is what the memo needs: two packs
	 * must not share a slot by accident, and two modules in one pack must share
	 * it on purpose.
	 */
	uint32_t uid_base;
	uint32_t n_uid;
};

/*
 * One loaded module.
 *
 * Everything except fn is a precondition or a table slice - that is, everything the
 * host needs in order to decide *not* to call fn. At database scale the interesting
 * number is how many modules can be ruled out per object without being entered, so
 * the record has to carry enough to rule them out.
 *
 * The preconditions come from the build: target, size and arch are declared in the
 * source, scan_mask is derived from the searches the module contains. None of them
 * requires reading the blob.
 *
 * The slices index shared tables rather than owning arrays. Inline arrays were tried
 * and were a mistake worth recording: at 64 name entries of 196 bytes each, the table
 * cost 12.5KB per module whether or not the module had two names, so eight thousand
 * modules would have spent 100MB on name storage alone - the dominant term in any
 * memory measurement.
 */
struct kof_module {
	kof_scan_fn fn;

	uint32_t target_mask;
	uint32_t scan_mask;   /* 0: names no region, so cannot be skipped that way */
	uint64_t size_min;    /* 0: no minimum. No maximum by design - see
			       * KOF_TARGET_SIZE_MIN in kofsig.h. */
	uint32_t arch_mask;   /* 0: any architecture */
	uint32_t subtype_mask;/* 0: any kind of that format - see ctx->subtype */

	/*
	 * name_base indexes THE PACK'S OWN name descriptors, not a table of the
	 * engine's, because there is no longer a table of the engine's - so the
	 * module has to say which pack as well as where in it.
	 */
	uint32_t pack_id;
	uint32_t name_base, n_names;
	uint32_t str_base,  n_str;
	uint32_t rng_base,  n_rng;

	/* What KOF_TARGET_NAME declared - see struct kof_pack_mod in kofpack.h
	 * and kof_db_family below. Meaningless and unread for an unpack-kind
	 * module, same as on the pack record this is copied from. */
	uint32_t family_off;
	uint32_t maltype;     /* enum kof_maltype */

	/* KOF_UNP_CONTAINER or KOF_UNP_PACKER; see KOF_UNPACK_KIND in kofsig.h.
	 * Meaningless and unread for a detector. */
	uint32_t unp_kind;

	/* For a heuristic rule: which phase it runs in, and what it asks the
	 * engine to do with an object it fires on. See kofmod/heur.h. */
	uint32_t heur_phase;
	uint32_t heur_want;

	/* The family a rule predicts, into the pack's name pool, or 0. Read with
	 * kof_db_heur_predict(). */
	uint32_t heur_predict_off;

	/*
	 * enum kof_pack_kind, from the pack this came out of.
	 *
	 * The three arrays above already say which kind a module is, so this is
	 * for the one place that has a module and not the array it came from:
	 * composing a finding's name, where a rule's word is written "Heur" and
	 * a detector's is its maltype.
	 */
	uint8_t  kind;

	/* Where this module's source lives inside the bases tree, or 0. Read
	 * with kof_db_source(). */
	uint32_t src_off;
};

/*
 * The database, materialised. Immutable once kof_db_load returns.
 *
 * The code arena is deliberately never unmapped: the module table holds function
 * pointers into it for the life of the engine.
 */
struct kof_engine {
	uint8_t *code;        /* arena base, mapped read + execute */
	size_t   code_cap;

	/*
	 * Detectors and unpackers, in separate arrays.
	 *
	 * Not one array with a kind field: the scan loop walks every detector for
	 * every object, and the unpack decision walks every unpacker once the
	 * object has a verdict. Mixed, each loop would step over records it must
	 * then reject - the same argument kofpack.h makes for one kind per pack,
	 * applied to the loaded form.
	 */
	struct kof_module   *mods;
	uint32_t             n_mods;

	struct kof_module   *unp;
	uint32_t             n_unp;

	/*
	 * The heuristic rules, in their own array for the same reason: they run
	 * at two points of their own in an object's life, and neither of the two
	 * loops above is one of them.
	 */
	struct kof_module   *heur;
	uint32_t             n_heur;

	/*
	 * How many patterns the whole database declares. A COUNT AND NOT A TABLE:
	 * the descriptors and the bytes both stay in the packs and are reached through
	 * kof_db_str. The matcher needs the number to size its presence table, which
	 * is the only thing left that wants it.
	 */
	uint32_t             n_str;

	uint32_t            *rng_tab;   /* a range is just a region mask, but named */
	uint32_t             n_rng;

	/*
	 * The distinct region masks, densely numbered, and the id of each rng_tab
	 * entry among them.
	 *
	 * The memo is keyed by (pattern, region mask) because those two decide the
	 * answer and nothing else does. A mask is a bitfield with a handful of live
	 * values across a whole database - one per way a module can name a region -
	 * so numbering them densely turns the second half of the key into something
	 * small enough to multiply by.
	 */
	uint32_t            *rng_uid;   /* parallel to rng_tab */
	uint32_t             n_masks;

	/* Patterns the whole database declares, after identical ones are merged. */
	uint32_t             n_uid;

	/*
	 * The packs, kept mapped for their names alone.
	 *
	 * THE NAME TABLE USED TO BE HERE and it was the largest thing in the engine:
	 * an id and a text per record, resident from the first object to the last, to
	 * serve a lookup that happens when a module reports a finding - a few dozen
	 * times in a scan of thirty four thousand objects. Millions of entries held
	 * for tens of uses.
	 *
	 * So they are not held. The pack already stores names as a pool with an id
	 * and an offset beside it, which is a perfectly good on-disk index, and a
	 * mapping costs address space rather than memory: a page of names is read the
	 * first time a detection needs it and never before. Nothing is faulted in on
	 * a clean scan, which is nearly every scan.
	 *
	 * The mappings are also why kof_db_name validates what it reads instead of
	 * trusting the load time check. A copy could be trusted afterwards because
	 * nothing could change it; a mapping is a view of a file that another process
	 * may still write to.
	 */
	struct kof_db_pack  *packs;
	uint32_t             n_packs;

	/*
	 * Memo cells: one per (pattern, region mask), which is what decides an answer.
	 *
	 * It used to be one per (module, string, range), and that gave every module
	 * its own slot for a question another module had already answered. Keying by
	 * the merged pattern id instead means the table SHRINKS by the duplication
	 * factor rather than growing - and it turns "usually not searched twice" into
	 * "cannot be searched twice", because every pair has a slot of its own.
	 *
	 * The old objection to a shared memo was the cost of clearing it. That is
	 * gone: the memo is stamped with a generation, so starting an object is O(1).
	 */
	uint32_t memo_size;

	/*
	 * Every region any module names, OR-ed together.
	 *
	 * Lets the scanner resolve only the regions somebody asked about. Without it,
	 * each object pays for every region the format defines - and one of them,
	 * KOF_SCAN_ELF_UNCLAIMED, is a complement: it builds the whole claimed set and
	 * sorts it. Paying for that on every object when no module names it is the kind
	 * of cost that hides because it is spread evenly.
	 */
	uint32_t scan_mask;
};

/*
 * Load from a single .ksig pack or a directory of them.
 *
 * A database is one or more packs; kofpack.h defines what is in one. Given a
 * directory, every *.ksig in it is loaded and the tables above are the concatenation
 * of theirs - a pack that fails validation is refused on its own and the rest still
 * load, so one corrupt file does not take the database with it.
 *
 * Returns NULL if nothing loaded.
 */
struct kof_engine *kof_db_load(const char *path);
void               kof_db_free(struct kof_engine *);

/* Resolve a name id reported by a module. NULL if the table is out of step with the
 * blob, which is the failure mode to want: "unknown" rather than another family's
 * name. */
/*
 * One of a module's declared patterns: its descriptor, and where its bytes are.
 *
 * Read from the pack rather than from a table of the engine's, for the reason
 * kof_db_name gives and one more: a pattern is only touched when a module that
 * declares it actually runs, so the pages of a database nobody matched are pages
 * that never enter memory. Copying them in defeats every filter above it.
 *
 * NULL if anything does not hold, checked here rather than trusted from load time -
 * see kof_db_name for why a mapping cannot be trusted afterwards.
 */
const struct kof_str_ent *kof_db_str(const struct kof_engine *,
				     const struct kof_module *, uint32_t id,
				     const uint8_t **bytes);

const char *kof_db_name(const struct kof_engine *, const struct kof_module *,
			uint32_t name_id);

/*
 * The same names, in the order the module declares them, for a caller that wants
 * to list what a module can report rather than to resolve one it already has.
 * NULL past the end, and NULL for a record that does not hold together.
 *
 * `id_out` takes the id the module reports for that name, which ksigbuilder set
 * from the source line of the KOF_SCAN_INFECT that names it. That number is the
 * only thread back from a database to the text somebody wrote - the pack carries
 * no path - so a tool that wants to show the logic behind a finding needs it and
 * a source tree of its own. Pass NULL when the text is all that is wanted.
 */
const char *kof_db_name_at(const struct kof_engine *, const struct kof_module *,
			   uint32_t index, uint32_t *id_out);

/* The family KOF_TARGET_NAME declared for this module, read from the pack the
 * same way kof_db_name reads a finding's variant - out of the mapping, bounds
 * checked on every call rather than trusted from load time, for the reason
 * kof_db_name's own comment gives. NULL if the record does not hold together;
 * "" (not NULL) for a module that legitimately declared none. */
const char *kof_db_family(const struct kof_engine *, const struct kof_module *);

/* The family a heuristic rule predicts, or NULL. See KOF_HEUR_PREDICT. */
const char *kof_db_heur_predict(const struct kof_engine *,
				const struct kof_module *);

/*
 * Where this module's source lives inside the bases tree, or NULL.
 *
 * Carried by the build rather than re-derived: a tool that has a scan result and
 * wants the rule's source should ask, not go looking. See kof_pack_mod.src_off
 * for the bug that came of looking.
 */
const char *kof_db_source(const struct kof_engine *, const struct kof_module *);

#endif /* KOFENG_KOFDB_H */