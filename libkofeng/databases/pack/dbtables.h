/*
 * dbtables.h - the LAYOUT of a loaded database, and the accessors that read it.
 *
 * What dbloader.c produces and everything else consumes: struct kof_engine and
 * the records it holds (modules, string descriptors, packs still mapped, the
 * diagnoses), the precondition test on a module, and the functions that turn an
 * id into text or bytes (dbaccess.c). Data and reads - nothing here builds a
 * matcher or looks at an object under scan.
 *
 * It sits BELOW the detectors, in databases/pack/, because the matchers read it:
 * kofmultimatch.c asks kof_db_str for a marker's bytes and kofmatch.c takes the
 * string flags from dbcore.h. It used to live in dbloader.h, next to the loader,
 * and the loader includes the matchers (kof_diag_load, the multimatch set), so
 * detectors/pattern and databases included each other. The loader stays in
 * databases/, above the detectors; the layout is here, below them.
 */

#ifndef KOFENG_DBTABLES_H
#define KOFENG_DBTABLES_H

#include <stddef.h>
#include <stdint.h>

#include <kofmod/kofsig.h>
#include <kofmod/kofdiagtree.h>
#include <kofmod/kofmutation.h>
#include <kofmod/script.h>   /* kof_script_fam_mask - the subfamily test below */
#include "../../kofcore/kofcore.h"   /* kof_crc32, kof_round_up */
#include "dbcore.h"       /* KOF_STR_MAX_LEN, KOF_BLOB_MAX_CODE */
#include "dbkix.h"        /* struct kof_kix: the block index a pack may carry */
#include "../../kofcore/kofbudget.h"   /* struct kof_budget */


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
struct kofpix;
struct kofpix_set;

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

	/*
	 * THE STRING SECTION, RESOLVED ONCE.
	 *
	 * kof_db_str re-read the header, re-derived both section offsets and
	 * re-checked every one of them against the map length on every call -
	 * and it is called once per marker a module asks about. With 200 000
	 * rules loaded that came to 561,467,262 instructions, 10.1% of the
	 * scan, computing the same two pointers.
	 *
	 * These are the bounds as they were when the pack was validated. What
	 * still comes out of the mapping - a descriptor's own off and len - is
	 * still checked at every call, because that is per-string and cannot
	 * be hoisted.
	 *
	 * (kof_db_str used to re-read the section offsets partly to cope with
	 * another process rewriting the file underneath a MAP_PRIVATE mapping.
	 * That is a different problem at a different scale and self-defence is
	 * where it belongs, not in a function called nine million times.)
	 *
	 * desc is NULL when the section did not validate; kof_db_str then
	 * refuses, which is what it did before for the same packs.
	 */
	const struct kof_str_ent *desc;   /* STR_DESC, or NULL */
	uint32_t                  n_desc; /* entries in it */
	const uint8_t            *pool;   /* STR_POOL */
	uint64_t                  pool_len;

	/*
	 * THE BLOCK INDEX TRAILER (pack/dbkix.h), when the pack has one.
	 *
	 * `fd` stays open for it, because the index is READ with pread and not mapped: a pack
	 * truncated after load is then a short read and a status, never a signal. -1 when the pack
	 * has no trailer and the descriptor was closed. `len` is what is MAPPED: the whole file for
	 * a pack without a trailer, and only the part before it for one with - the index body is
	 * never mapped. `kix` is the opened index until the matcher takes it (it is NULL after, and
	 * the matcher closes it); `file_size` is the whole file.
	 */
	int                       fd;
	uint64_t                  file_size;
	int                       has_kix;
	struct kof_kix_footer     foot;
	struct kof_kix           *kix;
	/*
	 * THE PATTERN TABLE (detectors/pattern/kofpix.h), the same way: a part of the tail, read with pread
	 * through `pix_sl` (sliced, checksummed), the descriptor shared with the block index. `pix` is
	 * the open table, made after the load once the ledger can say how big its filter may be, from the
	 * part when the pack has one and built in memory when it has not; NULL when there is none (the
	 * pack declares no markers, or the ledger could not afford one: reported, and those markers are
	 * answered by the exact per-marker path). `pix_in_ram` says which.
	 */
	int                       has_pix;
	struct kof_kix_footer     pix_foot;
	struct kof_slices         pix_sl;
	struct kofpix            *pix;
	int                       pix_in_ram;
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

	/* size_min before scan_mask, so that no padding sits between them: 144 bytes a module became 136 (a
	 * module is the one record that is resident for every rule). */
	uint64_t size_min;    /* 0: no minimum. No maximum by design - see
			       * KOF_TARGET_SIZE_MIN in kofsig.h. */
	uint32_t scan_mask;   /* 0: names no region, so cannot be skipped that way */
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

	/* enum kof_analyze; see KOF_ANALYZE_STEP in kofsig.h.
	 * Meaningless and unread for a detector. */
	uint32_t step;

	/* The kind of content the module takes out, into the pack's name pool, or
	 * 0. Read with kof_db_content(). */
	uint32_t content_off;

	/*
	 * enum kof_pack_kind, from the pack this came out of.
	 *
	 * The arrays above already say which kind a module is, so this is for the
	 * one place that has a module and not the array it came from.
	 */
	uint8_t  kind;
	/*
	 * Does a diagnose name this module as a reader (KDIG_SEC_USERS carries the
	 * source of each rule that calls it): it asks for the diagnose analysis,
	 * which costs more than any search, so it is run after the cheap questions -
	 * see db_index_tier_order. Worked out when the database is loaded, from the
	 * source each module already carries; 0 when no diagnose names it, and for a
	 * module whose source is unknown.
	 */
	uint8_t  reads_diag;

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

/*
 * The kind of data a module asks for, which is the order the scan runs them in (cheapest first): 0 neither
 * markers nor blocks, 1 blocks, 2 markers, 3 a diagnose names it as its reader. The one place the rule is
 * written: the loader sorts the per-format lists by it and the walk merges two lists by it.
 */
static inline uint32_t kof_module_tier(const struct kof_module *m)
{
	return m->reads_diag ? 3u : m->n_str ? 2u : m->n_block ? 1u : 0u;
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
/* The most diagnoses one engine will hold, and how many nodes one of them may
 * have. The table is allocated for the number the packs ACTUALLY carry, and
 * this is only the bound against a hostile pack (a table of 65535 empty records
 * would otherwise be a gigabyte): it was 256, a number nobody chose, and a
 * database of 300 lost the last 44 silently - tests/unit/caps_db.c. A database
 * over it is reported (kdb_diag_full), not silently truncated. */
#define KOF_DB_MAX_DIAG       4096u
/* Nodes one diagnose may have: KOF_DIAG_MAX_NODE, which the source reader takes too. */
#define KOF_DB_MAX_DIAG_NODE   KOF_DIAG_MAX_NODE
/*
 * A DIAGNOSE'S NAME IS WHAT THE RECORD CAN HOLD: its length is one byte, so 255
 * characters and the terminator. It was 48, while the source reader accepted 63.
 */
#define KOF_DB_DIAG_NAME       256u

/* One disease in the names table; `type` is the kof_maltype it was declared with. */
struct kof_disease_ent {
	uint32_t    id;
	uint8_t     type;
	const char *name;
};

struct kof_engine {
	uint8_t *code;        /* arena base, mapped read + execute */
	size_t   code_cap;

	/*
	 * THE DIAGNOSES, read from the diag-<kind>.kdig packs beside the signature packs.
	 *
	 * Not in a pack: the pack header carries a fixed-size section table,
	 * so one more section is a format change every database has to be
	 * rebuilt for - and a diagnose has no module, no pattern and no blob
	 * in it, which is all a pack exists to carry.
	 */
	struct kof_diag      *diag;
	struct kof_diag_node *diag_node;
	char                 *diag_name;
	/* The string stores of the diagnoses (their signs and symbols), ONE BLOCK PER
	 * PACK sized by the records it carries: a string takes no more store than the
	 * record bytes it was read from, so no record overflows it. Freed with the
	 * engine. */
	char                **diag_arena;
	uint32_t              n_diag_arena;
	uint32_t              n_diag;
	uint32_t              diag_room;   /* what the tables were allocated for */
	int                   diag_full;   /* some diagnose was not loaded: over the bound */
	/* Diagnoses refused because their 32-bit id (KOF_DIAG_ID) equals one
	 * already loaded. Each is also named on stderr when met; this is what an
	 * API caller can read - kdb_diag_collisions. */
	uint32_t              diag_collide;
	/*
	 * WHAT THE LOADER COULD NOT READ, said where a caller can read it - the stderr
	 * line each one also gets is for a person at a terminal, and a host linked to
	 * the library never sees it.
	 *   diag_refused   records that did not parse (a count, a length or a field
	 *                  this build does not accept) or ran past their pack: each
	 *                  is a diagnose that is absent, which a rule naming it reads
	 *                  as an object that does not do the thing.
	 *   diag_packs_refused  .kdig files not read whole: a header that does not add
	 *                  up, a file past the allowance, a store it could not
	 *                  allocate. Their records are in no count above.
	 */
	uint32_t              diag_refused;
	uint32_t              diag_packs_refused;
	/*
	 * THE DISEASES' NAMES, from diseases.kdig: id to name and type, ascending by
	 * id. For a tool that has an id and must show one - a scan reads ids only.
	 * Empty when the database has none.
	 */
	struct kof_disease_ent *disease;
	char                 *disease_pool;
	uint32_t              n_disease;
	/* Scratch of the load, freed when it ends: the names the diagnoses' USERS
	 * sections carried, to match against the modules' sources once. */
	char                **diag_user;
	uint32_t              n_diag_user, cap_diag_user;

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
	/* The modules that name NO target (every format), once, at the end of mod_by_target's allocation;
	 * kof_mod_walk merges this list with a format's own. NULL / 0 when there is none. */
	uint32_t            *mod_any;
	uint32_t             n_mod_any;

	/*
	 * HOW MANY MARKERS EACH REGION COULD HAVE LIVE, PER FORMAT - decided
	 * once here instead of recounted for every object.
	 *
	 * multi_prepass needs one thing from the module list: whether a region
	 * has at least KOF_MULTIMATCH_MIN_LIVE markers behind it, which is the
	 * only question the sweep's router asks (sx_multi_prepass). It used to answer that by
	 * walking every module in the database, per object. At 200 000 modules
	 * that walk measured 4,158,329,009 instructions - 15.4% of the scan and
	 * the largest single item in the profile - to compare a total against
	 * eight.
	 *
	 * The total does not depend on the object's BYTES, only on its format,
	 * so it is summed at load and read at scan.
	 *
	 * AN UPPER BOUND, AND THAT IS SAFE HERE. The per-object walk also
	 * dropped modules on size, arch and subtype; this does not, so a region
	 * can be swept that the exact count would have left alone. That changes
	 * how the answer is REACHED and never what it is: a sweep writes into
	 * `found`, and a module still only reads it through kof_match_lookup,
	 * which applies the module's own preconditions. A rule scoped away from
	 * this object cannot be reported by a sweep that ran anyway.
	 *
	 * NULL when it could not be allocated, and multi_prepass then walks the
	 * modules as it always did - slower and identical.
	 */
	uint32_t            *live_cap;   /* [KOF_TARGET_COUNT][KOF_MULTIMATCH_BITS] */

	struct kof_module   *unp;
	uint32_t             n_unp;

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
	 * by kind and format - sigs-pe, unpack-elf - so the union
	 * that matters is over everything actually loaded. Walking the two
	 * arrays once at load is cheaper than reasoning about which packs came
	 * back, and it cannot disagree with the modules the scan will run.
	 *
	 * BOTH ARRAYS. A detector targeting a format will search a child of it;
	 * an unpacker will try to peel one. Either is a reason the child is worth
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

	/*
	 * The raw region masks of every range of every module, concatenated: SCRATCH OF THE LOAD (the loader
	 * numbers the distinct masks from it, sums the live-marker caps and gives it back), NULL once the load
	 * is over. What stays is one BYTE a range, rng_uid below, and the bits behind it, mask_bits: a range is
	 * just a region mask, but named, and 4 bytes of mask per range was 4 bytes per rule in memory for a
	 * handful of distinct values.
	 */
	uint32_t            *rng_tab;
	uint32_t             n_rng;

	/*
	 * Every loaded pack's similarity blocks, laid end to end. A module's block_base says
	 * where its own slice starts.
	 *
	 * BORROWED from the pack's mapping when exactly one pack carries blocks (the usual case:
	 * nothing is copied, and the table is the pack's own section), and a heap copy when
	 * several do (16 bytes a block; their `first_hash` stay local to their own pack, since
	 * the hash pools are not concatenated any more). The hashes themselves are NOT held:
	 * the matcher's index lives in the pack (pack/dbkix.h) and reads them from there, so
	 * what a database with blocks costs in memory does not follow its hash count. Only the
	 * viewer reads this table (kof_inspect_mutation: mask, normalizer and count of each
	 * block). `blk_owned` says whether it is to be freed.
	 *
	 * Empty in every build with no mutation rules, and an empty set costs an
	 * index that is never consulted.
	 */
	struct kof_mutation_block *blk_tab;
	uint32_t                 n_blk;
	int                      blk_owned;
	uint32_t                 n_blk_pool;   /* hashes in all of them: a count, the pool itself is not held */
	/* The index built over the two above - see detectors/mutations/kofmutation.h. NULL
	 * when there are no blocks. */
	struct kof_mutation_set   *mutation;
	/*
	 * APPENDED: what building that index said, where a host can read it - see
	 * kdb_mutation_status. `mutation_status` is the KOF_MTN_B_* word (0 is clean;
	 * a REFUSED bit means `mutation` is NULL and similarity rules score nothing),
	 * `mutation_bytes` what the index holds resident, shared by every scanner, and
	 * `mutation_keys` its distinct hash values.
	 */
	uint32_t                   mutation_status;
	uint32_t                   mutation_keys;
	uint64_t                   mutation_bytes;

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
	uint8_t             *rng_uid;   /* one byte a range: the dense id of its mask (KOF_MAX_DISTINCT_MASKS is 256) */
	uint32_t             n_masks;

	/* Patterns the whole database declares, after identical ones are merged. */
	uint32_t             n_uid;

	/*
	 * THE PATTERN TABLES, one per pack (kof_db_pack.pix), and what they say together.
	 *
	 * The marker set is the DATABASE's: opened once when the packs are loaded, read-only after, and
	 * therefore shared by every scanner thread. Each scanner holds only a bounded context against
	 * them (kofpix_ctx), so what a scanner costs does not follow the number of markers.
	 *
	 * `mask_bits` is the raw region bits behind each dense mask id, so a scan knows which regions a
	 * mask is asking about (rng_uid is parallel to rng_tab, so the first entry carrying an id is as
	 * good as any - they all carry the same bits, which is what made them one id).
	 * `pix_regions` is the regions some table can sweep; `pix_status` is KOF_PIX_B_* (zero is clean),
	 * `pix_bytes` what the tables hold in memory, `pix_markers` how many markers they key and
	 * `pix_max_run` the longest run of markers sharing a key hash - kmatch_tables reads the last
	 * two and kdb_pattern_status the others. NULL tables are not an error: every mask is then answered
	 * one marker at a time, exactly.
	 */
	uint32_t            *mask_bits;      /* [n_masks] */
	struct kofpix_set   *pix_set;        /* every pack's table, swept together (NULL: none) */
	uint32_t             pix_regions;
	uint32_t             pix_status;
	uint32_t             pix_max_run;
	uint64_t             pix_bytes;
	uint64_t             pix_markers;

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

	/* APPENDED (memory work): the engine's memory budget, the root of every ledger - see
	 * kofcore/kofbudget.h. Allocated and freed by keng_open / keng_close (kofeng.c), NULL
	 * for an engine made any other way, which then has no engine-level cap. */
	struct kof_budget *budget;
};

/*
 * THE MODULES FOR ONE FORMAT, in the order the scan runs them: the format's own list and the list of the
 * modules that name no target, merged by (tier, module) - exactly the order each format had when a generic
 * module was copied into all of them. With no index (it could not be allocated) it is the flat array, and
 * the scan's own precondition drops what does not apply, as it always did.
 */
struct kof_mod_walk {
	const struct kof_engine *e;
	const uint32_t *a, *a_end, *b, *b_end;
	uint32_t        flat, n_flat;
	int             indexed;
};

static inline void kof_mod_walk_begin(struct kof_mod_walk *w, const struct kof_engine *e, uint32_t format)
{
	w->e = e;
	w->a = w->a_end = w->b = w->b_end = NULL;
	w->indexed = e->mod_by_target && format < KOF_TARGET_COUNT;
	w->flat = 0;
	w->n_flat = e->n_mods;
	if (w->indexed) {
		w->a = e->mod_by_target + e->mod_at[format];
		w->a_end = e->mod_by_target + e->mod_at[format + 1u];
		w->b = e->mod_any;
		w->b_end = e->mod_any ? e->mod_any + e->n_mod_any : NULL;
	}
}

/* How many modules the walk will yield: what the scan counts as not considered for the others. */
static inline uint32_t kof_mod_walk_count(const struct kof_mod_walk *w)
{
	return w->indexed ? (uint32_t)(w->a_end - w->a) + (w->b ? (uint32_t)(w->b_end - w->b) : 0u) : w->n_flat;
}

/* The next module index; 0 at the end. */
static inline int kof_mod_walk_next(struct kof_mod_walk *w, uint32_t *idx)
{
	if (!w->indexed) {
		if (w->flat >= w->n_flat)
			return 0;
		*idx = w->flat++;
		return 1;
	}
	if (w->a < w->a_end && (!w->b || w->b >= w->b_end)) {
		*idx = *w->a++;
		return 1;
	}
	if (w->b && w->b < w->b_end && w->a >= w->a_end) {
		*idx = *w->b++;
		return 1;
	}
	if (w->a < w->a_end) {
		uint32_t x = *w->a, y = *w->b;
		uint32_t tx = kof_module_tier(&w->e->mods[x]), ty = kof_module_tier(&w->e->mods[y]);

		if (tx < ty || (tx == ty && x < y)) {
			*idx = x;
			w->a++;
		} else {
			*idx = y;
			w->b++;
		}
		return 1;
	}
	return 0;
}


/* The name and type of a disease, from its id; NULL when the database does not
 * name it. The pointer lives as long as the engine. */
const struct kof_disease_ent *kof_db_disease(const struct kof_engine *, uint32_t id);

/* Every disease the database names, ascending by id: how many, and the i-th (NULL
 * past the end). For a tool that lists them - a person choosing one to declare. */
uint32_t kof_db_disease_count(const struct kof_engine *);
const struct kof_disease_ent *kof_db_disease_at(const struct kof_engine *, uint32_t i);


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

/* The family KOF_TARGET_NAME declared for this module, read from the pack the
 * same way kof_db_name reads a finding's variant - out of the mapping, bounds
 * checked on every call rather than trusted from load time, for the reason
 * kof_db_name's own comment gives. NULL if the record does not hold together;
 * "" (not NULL) for a module that legitimately declared none. */
const char *kof_db_family(const struct kof_engine *, const struct kof_module *);

/* The kind of content a module takes out, or NULL. See KOF_TARGET_CONTENT. */
const char *kof_db_content(const struct kof_engine *,
			   const struct kof_module *);

/*
 * Where this module's source lives inside the bases tree, or NULL.
 *
 * Carried by the build rather than re-derived: a tool that has a scan result and
 * wants the rule's source should ask, not go looking. See kof_pack_mod.src_off
 * for the bug that came of looking.
 */
const char *kof_db_source(const struct kof_engine *, const struct kof_module *);


#endif /* KOFENG_DBTABLES_H */
