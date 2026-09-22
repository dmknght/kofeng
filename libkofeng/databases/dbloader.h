/*
 * dbloader.h - the loaded database.
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

#ifndef KOFENG_DBLOADER_H
#define KOFENG_DBLOADER_H

#include <stddef.h>
#include <stdint.h>

#include <kofmod/kofsig.h>
#include <kofmod/kofplague.h>
#include <kofmod/script.h>   /* kof_script_fam_mask - the subfamily test below */
#include "../kofcore/kofcore.h"   /* kof_crc32, kof_round_up */
#include "dbcore.h"       /* KOF_STR_MAX_LEN, KOF_BLOB_MAX_CODE */

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
struct kof_multimatch_set;

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
	/*
	 * AND HOW TO UNDO WHAT IT FOUND, or NULL.
	 *
	 * Resolved the same way fn is - blob plus an offset the build wrote
	 * down - because the loader reads no symbols. NULL for nearly every
	 * module: knowing that a file is infected and knowing how to put it
	 * back are different pieces of work and only the first is usually
	 * done. See kof_pack_mod.cure_off.
	 */
	kof_scan_fn cure;

	/*
	 * WHAT THIS MODULE IS FOR, AS A LIST OF TARGET IDS.
	 *
	 * It was a BITMASK, one bit per format, and that made the number of
	 * formats this engine could ever have equal to the width of a word.
	 * Nineteen were spent and four of the remainder were event verbs
	 * sharing the same numbering, so the twentieth format could not be
	 * added at all - see kofsig.h, where the axis is described.
	 *
	 * A list removes the ceiling without moving it: a target id is an
	 * ORDINARY NUMBER, so format 3 is 3 rather than the third bit, and the
	 * space is as wide as the byte holding it. What a mask bought - "does
	 * this module apply here" in one AND - is not lost either, because that
	 * question is not asked module by module on the hot path: the loader
	 * builds an inverted index from target id to modules (see mod_by_target
	 * below), and the list is walked only by the precondition, where the
	 * overwhelmingly common case is n_target == 1 and one comparison.
	 *
	 * `n_target` of ZERO IS "ANY", which is what KOF_FMT_ANY compiles to. A
	 * module that named everything used to carry every bit; it now carries
	 * nothing, which is both smaller and the honest spelling of it.
	 */
	uint8_t  n_target;
	uint8_t  target[KOF_TARGET_LIST_MAX];

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
	/*
	 * And where this module's similarity blocks start in the ENGINE's block
	 * table, which is every loaded pack's blocks laid end to end.
	 *
	 * A base rather than a per-pack index because the matcher indexes all of
	 * them at once: one inverted index over every block any pack brought is
	 * what makes a scan cost the same whether one pack is loaded or twelve.
	 * Zero and zero for the overwhelming majority of modules, which declare
	 * no block at all.
	 */
	uint32_t block_base, n_block;

	/* What KOF_TARGET_NAME declared - see struct kof_pack_mod in dbcore.h
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
	uint32_t heur_level;
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
 * WHETHER A MODULE MAY RUN ON THIS OBJECT AT ALL.
 *
 * The preconditions a module declares, in the order they are applied, and the
 * one place they are applied from. There were three: the detector loop, the
 * unpacker loop, and a mirror in kofinspect whose own comment said it was
 * copied "rather than reasoned out again". Copies of a rule about what a scan
 * DOES are worse than most, because the tool that shows why a module did not
 * run then answers from its own copy - so it can say "would have run" about a
 * module the engine had already excluded, and be believed.
 *
 * The unpacker loop is why this returns a REASON and not a yes/no: it needs to
 * count what excluded a module, and the examiner needs a word for it.
 *
 * ORDER MATTERS AND IS PART OF THE ANSWER. Subtype is tested last because it is
 * only meaningful once the format is known - two formats' subtype values
 * deliberately collide, and testing target first is what makes reading
 * ctx->subtype safe.
 */
/*
 * Does this module name that target id.
 *
 * Linear, over at most KOF_TARGET_LIST_MAX entries and in practice over one.
 * Written here rather than in each caller for the reason kof_module_precond
 * itself exists: a rule about what a scan DOES, spelled twice, is a tool that
 * can disagree with the engine about which modules ran.
 */
static inline int kof_module_targets(const struct kof_module *m, uint8_t target)
{
	uint8_t i;

	if (!m->n_target)
		return 1;              /* named everything - see n_target */
	for (i = 0; i < m->n_target; i++)
		if (m->target[i] == target)
			return 1;
	return 0;
}

enum kof_precond {
	KOF_PRECOND_OK = 0,
	KOF_PRECOND_TARGET,      /* targets another format */
	KOF_PRECOND_SIZE,        /* object is below its minimum size */
	KOF_PRECOND_ARCH,        /* targets another architecture */
	KOF_PRECOND_SUBTYPE      /* targets another kind of this format */
};

static inline enum kof_precond kof_module_precond(const struct kof_module *m,
						  const struct kof_obj_ctx *ctx,
						  uint64_t size)
{
	if (!kof_module_targets(m, ctx->format))
		return KOF_PRECOND_TARGET;
	if (size < m->size_min)
		return KOF_PRECOND_SIZE;
	/* An architecture outside the bit width cannot be named by a mask, so a
	 * module that constrains architecture does not cover it. */
	if (m->arch_mask &&
	    (ctx->arch >= 32 || !(m->arch_mask & (1u << ctx->arch))))
		return KOF_PRECOND_ARCH;
	/*
	 * FILTER ON POSITIVE KNOWLEDGE ONLY - subtype 0 is "not known", and a
	 * thing not known must never cost a detection.
	 *
	 * Without the middle test this axis silently loses rules. A PHP web
	 * shell whose "<?php" sits past the sniff window, or a fragment with no
	 * tag at all, comes out as a script of no particular kind; a PHP rule
	 * then declined it, and nothing anywhere said so. That is a worse
	 * failure than running the rule, because the saving is a few
	 * microseconds and the cost is the whole point of the scanner.
	 *
	 * So the mask only ever removes an object whose kind IS known and is
	 * not one the module asked for - a Python file with a shebang, tested
	 * against a PHP rule. Recognition quality becomes a dial on
	 * performance instead of a dial on coverage: better sniffing declines
	 * more, worse sniffing declines less, and neither changes what is
	 * found. Zero is also what every container reports, so this is the same
	 * rule those already relied on.
	 */
	if (m->subtype_mask && ctx->subtype != 0 &&
	    (ctx->subtype >= 32 || !(m->subtype_mask & (1u << ctx->subtype))))
		return KOF_PRECOND_SUBTYPE;
	/*
	 * AND THE FAMILY, WHICH IS WHAT SUBTYPE 0 STILL KNOWS.
	 *
	 * Everything above is about the LANGUAGE, and the paragraph above
	 * explains why not knowing it must not decline. The family is a
	 * different answer to a different question and it survives exactly the
	 * case that defeats the kind: "<% ... %>" with no directive is asp,
	 * aspx or jsp - we cannot say which, and we can say it is not php,
	 * because php's tag is "<?php" and this is not it.
	 *
	 * So a module whose declared subtypes ALL sit in some other family is
	 * declined. Within the family nothing changes: the one aspx rule and
	 * the two jsp rules still see a bare server page, which is the whole
	 * reason this is not spelled as "default the page to asp".
	 *
	 * Found from a report - a KOF_SCRIPT_PHP rule for Weevely reported
	 * tests/unit/word_modes.c, which carries "<%@ Page Language=..." as a
	 * string literal. The family had been computed by the parser, used to
	 * carve the file, and then dropped before this test.
	 *
	 * KOF_SFAM_NONE and KOF_SFAM_HTML return an all-ones mask, so they
	 * decline nothing and every format that has no family is untouched.
	 */
	if (m->subtype_mask && ctx->format == KOF_FMT_SCRIPT &&
	    !(m->subtype_mask & kof_script_fam_mask(ctx->subfamily)))
		return KOF_PRECOND_SUBTYPE;
	return KOF_PRECOND_OK;
}


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
	 * then reject - the same argument dbcore.h makes for one kind per pack,
	 * applied to the loaded form.
	 */
	struct kof_module   *mods;
	uint32_t             n_mods;

	/*
	 * THE DETECTORS GROUPED BY THE FORMAT THEY TARGET.
	 *
	 * The scan used to walk every module for every object and let
	 * kof_module_precond throw most of them away. That is a few integer
	 * compares each, which sounds free and is not: the cost is
	 * objects x modules, and the module table stops fitting in cache long
	 * before the record count gets interesting. Measured on a synthetic base
	 * of four million records packed sixty four to a module - 62 500 modules
	 * - a corpus of 2999 small text files spent 187 million evaluations and
	 * 4.55 s, which is 11 MB/s, while the same wall clock scanned 2896 MB of
	 * large samples. The cost is per FILE, not per byte.
	 *
	 * A module cannot match an object whose format bit is absent from its
	 * its target list - that is the first line of kof_module_precond - so the
	 * grouping is exact rather than a filter that has to be re-checked.
	 * `mod_at[b] .. mod_at[b + 1]` is the run of module indices for target
	 * bit b, in the same order the flat walk had them, so what runs and in
	 * what order does not change.
	 *
	 * A module targeting several formats appears in several runs; the total
	 * is the sum of the popcounts, which for a real base is barely more than
	 * the module count because a rule names one format.
	 */
	uint32_t            *mod_by_target;
	uint32_t             mod_at[KOF_TARGET_COUNT + 1u];

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
	 * EVERY FORMAT ANY LOADED MODULE TARGETS, or-ed into one mask.
	 *
	 * Read by the scanner to answer a producer's question: would anything
	 * look inside a child of this format - see fmt_wanted in kofmod/kofsig.h
	 * for why that is the gate asked early rather than a policy.
	 *
	 * COMPUTED HERE AND NOT READ FROM THE PACK, although a pack header
	 * carries the same union of its own modules (any_target, dbcore.h).
	 * That field is per pack, and a database is a directory of them split
	 * by kind and format - sigs-pe, unpack-elf, heur-elf - so the union
	 * that matters is over everything actually loaded. Walking the three
	 * arrays once at load is cheaper than reasoning about which packs came
	 * back, and it cannot disagree with the modules the scan will run.
	 *
	 * ALL THREE ARRAYS. A detector targeting a format will search a child
	 * of it; an unpacker will try to peel one; a heuristic will gather
	 * facts from one. Any of the three is a reason the child is worth
	 * making.
	 */
	/* One bit per target id - a presence set, since an id is a number and
	 * not a bit. The same shape kof_pack_hdr.any_target has. */
	uint64_t             any_target;

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
	 * Every loaded pack's similarity blocks, laid end to end, and the
	 * hashes they slice.
	 *
	 * One table for all packs rather than one per pack, because the matcher
	 * builds a single inverted index over it - which is what makes a scan
	 * cost the same whether one pack is loaded or twelve. A module's
	 * block_base says where its own slice starts.
	 *
	 * Empty in every build with no plague rules, and an empty set costs an
	 * index that is never consulted.
	 */
	struct kof_plague_block *blk_tab;
	uint32_t                 n_blk;
	uint32_t                *blk_pool;
	uint32_t                 n_blk_pool;
	/* The index built over the two above - see detector/matchers/kofplague.h. NULL
	 * when there are no blocks. */
	struct kof_plague_set   *plague;

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
	 * The multi-pattern matchers, one per region mask.
	 *
	 * Owned here rather than by the scanner because the marker set is the
	 * DATABASE's: built once when the packs are loaded, read-only after, and
	 * therefore shared by every scanner thread. Building it per scanner would
	 * duplicate a table sized by the base once per thread - the same mistake
	 * the memo already refuses to make for the symbol block.
	 *
	 * NULL is not an error. It means every mask is answered the way it was
	 * before this existed, one search per (marker, region).
	 */
	struct kof_multimatch_set *multi;

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
 * A database is one or more packs; dbcore.h defines what is in one. Given a
 * directory, every *.ksig in it is loaded and the tables above are the concatenation
 * of theirs - a pack that fails validation is refused on its own and the rest still
 * load, so one corrupt file does not take the database with it.
 *
 * Returns NULL if nothing loaded.
 */
/*
 * THE DATABASE, LOADED. TABLES ONLY.
 *
 * Packs mapped, modules absorbed, the code arena taken, pattern ids made unique
 * and region masks made dense. What it does NOT do is build `plague` and
 * `multi`, which are left NULL: those are indexes the DETECTOR owns, and a
 * loader that built them would have to call into the layer that consumes it.
 *
 * An engine from here is usable for everything that reads the tables and is
 * not ready to scan with. Use kof_db_load below unless you are the assembler.
 */
struct kof_engine *kof_db_load_tables(const char *path);

/*
 * Free what kof_db_load_tables took. It does not touch `plague` or `multi` -
 * it cannot, for the same reason it did not build them - so a caller that
 * built them frees them first. kof_db_free does exactly that.
 */
void               kof_db_free_tables(struct kof_engine *);

/*
 * THE ENGINE, ASSEMBLED: the tables above plus the detector's indexes over
 * them. This is what everything except the assembler itself should call.
 *
 * DECLARED HERE AND DEFINED IN detector/dbindex.c, which is the same
 * arrangement kof_fid_of has in fidset.h and is here for a related reason: the
 * name belongs beside struct kof_engine, and the definition belongs in the
 * layer that knows what an index is. The alternative was the loader calling
 * kof_plague_build and kof_multimatch_build itself, which made these two
 * directories mutually dependent - dbloader.c reaching up into
 * detector/matchers while kofmultimatch.c reached back down for kof_db_str.
 *
 * Semantics are unchanged from when this was one function, and the name is
 * unchanged so that every caller is too.
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

#endif /* KOFENG_DBLOADER_H */