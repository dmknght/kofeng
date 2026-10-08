/*
 * objctx.c - the scan context, as a module sees it.
 *
 * Builds a kof_obj_ctx and serves every call made through it. That makes this the
 * entire untrusted boundary: module code comes out of a database and runs native, and
 * every byte it can reach it reaches through one of these functions - so each one
 * bounds checks, and an out of range read yields zero rather than faulting. Ten
 * functions audited once beats bounds arithmetic repeated in every module.
 *
 * It sits with the scanner rather than beside the ABI headers in core/kofmod because
 * every line of it reads the scanner's per-object state - the match context, the
 * loaded engine, what the running module has reported. Put next to the headers it
 * would declare, it would reach sideways for all of that and be less cohesive, not
 * more. The headers are the contract; this is the scanner honouring it.
 *
 * One of a family of units, divided by what they serve - see objctx_int.h.
 * THIS one is the boundary itself: the byte readers, string
 * search, reports and debug facts, the region/entropy/similarity/repair/code
 * accessors, the code-use map, the vtable and the attach. Child production, the
 * decoders, the interpreter, the pathogen analysis and the script forms are
 * their own units, each bounded by the same rule: a mistake here is a memory
 * safety bug rather than a wrong answer, so each reads end to end on its own.
 *
 * Nothing here decides anything. These read, compare, and hand a declared string to
 * the matcher; what to do with the answer is the scan routine's business.
 */

/* Before any include, and _GNU_SOURCE rather than _POSIX_C_SOURCE, for the
 * reason dbloader.c gives at length: kofplatform.h's POSIX branch has an inline
 * kof_memmem whose body calls memmem, which glibc declares only under this
 * macro - and _POSIX_C_SOURCE actively suppresses it. */
#define _GNU_SOURCE

#include <kofmod/kofsym.h>
#include <kofmod/heur.h>   /* KOF_ENG_USE_EMU - a module's declaration */
#include "../kofcore/kofplatform.h"
#include "../kofcore/kofdebug.h"   /* kof_write_all - the spill file below */
#include "../analyzers/parsers/binaries/elf/elf_sym.h"
#include <kofmod/kofpathogen.h>
#include "../analyzers/parsers/binaries/pe/pe_sym.h"
#include <celllysis/xref.h>
#include "../disinfect/pzero.h"
#include "../analyzers/normalize/executables.h"
#include "scan.h"
#include "objctx_int.h"
#include <kofmod/elf.h>
#include "../extractors/unpack/emu_unpack.h"
#include "../extractors/unpack/elf_rebuild.h"

#include "../extractors/decomp/ovba.h"
#include "../extractors/decomp/lzma.h"
#include "../extractors/decomp/aplib.h"
#include "../extractors/decomp/aspack.h"
#include "../extractors/decomp/lzmat.h"
#include "../extractors/decomp/bcj.h"
#include "../extractors/decomp/rar3.h"
#include "../extractors/decomp/rar5.h"
#include "../extractors/decomp/bcj2.h"
/* The script folding pass and the lexical table it is driven from - see
 * kof_scan_script_fold below. */
#include "../analyzers/parsers/scripts/script_norm.h"
#include "../analyzers/parsers/scripts/script_parse.h"
/*
 * The one format header the scan path includes, and it is not a shortcut.
 *
 * BCJ2 is not a coding that happens to appear in 7z - it IS a 7z folder shape.
 * Which packed stream carries the code, which carries the call targets, which the
 * jump targets, and which the range coder is stated by the folder's bind pairs and
 * nowhere else. A general "multi stream coding" hook in the module ABI would be an
 * abstraction with exactly one user, invented to avoid naming the thing it is for.
 */
#include <kofmod/sevenzip.h>

#include "../detectors/overlord/matchers/kofmultimatch.h"
#include "../detectors/pathogen/kofdiag.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <celllysis/space.h>

struct kof_match_ctx *oc_mc(const struct kof_obj_ctx *ctx)
{
	return &kof_scan_of(ctx)->m;
}

static uint8_t c_rd8(const struct kof_obj_ctx *ctx, uint64_t off)
{
	uint8_t v = 0;
	kof_rd_u8(oc_mc(ctx)->data, off, &v);
	return v;
}

static uint16_t c_rd16(const struct kof_obj_ctx *ctx, uint64_t off)
{
	uint16_t v = 0;
	kof_rd_u16(oc_mc(ctx)->data, off, 0, &v);
	return v;
}

static uint32_t c_rd32(const struct kof_obj_ctx *ctx, uint64_t off)
{
	uint32_t v = 0;
	kof_rd_u32(oc_mc(ctx)->data, off, 0, &v);
	return v;
}

static uint64_t c_rd64(const struct kof_obj_ctx *ctx, uint64_t off)
{
	uint64_t v = 0;
	kof_rd_u64(oc_mc(ctx)->data, off, 0, &v);
	return v;
}

static int c_memeq(const struct kof_obj_ctx *ctx, uint64_t off, const void *pat,
		   uint32_t len)
{
	kof_buf s = kof_slice(oc_mc(ctx)->data, off, len);
	if (s.n != len)
		return 0;
	return memcmp(s.p, pat, len) == 0;
}

static uint32_t c_csum(const struct kof_obj_ctx *ctx, uint64_t off, uint32_t len)
{
	kof_buf s = kof_slice(oc_mc(ctx)->data, off, len);
	if (s.n != len)
		return 0;
	return kof_crc32(s.p, s.n);
}

/*
 * A MODULE'S VERDICT, IN THE HOST'S VOCABULARY.
 *
 * The level crosses the module ABI like every other argument here, and it was
 * the one that was stored without being read. There are four values; anything
 * else reaches the result array as a number no host can place, and what a host
 * does with one is not "show it oddly" - kverdict_level_rank answers 0 for an
 * unknown level, the same as for nothing at all, so the finding is counted in
 * no bucket, does not raise the file's verdict, and the file is reported
 * CLEAN with a detection sitting in its result. A stale database, a build that
 * renumbered, or a module that computed a level rather than naming one all
 * arrive here.
 *
 * Clamped to the least specific value rather than dropped, which is exactly
 * what oc_incomplete does with a reason outside its own vocabulary and for the
 * same reason: the module found SOMETHING, and the level is how sure it is,
 * not whether it is there.
 */
static void c_report(const struct kof_obj_ctx *ctx, uint32_t level,
		     uint32_t name_id)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (level != (uint32_t)KOF_LVL_INFECT &&
	    level != (uint32_t)KOF_LVL_HEUR &&
	    level != (uint32_t)KOF_LVL_ACT)
		level = (uint32_t)KOF_LVL_SUSPECT;
	sc->rep_level   = level;
	sc->rep_name_id = name_id;
	sc->rep_valid   = 1;
}

/* ---- searching a declared string ------------------------------------------- */

/*
 * The string a module named, resolved against the running module's slice.
 *
 * NULL if the id is outside it. That is the only thing to check here: the id came
 * from a build-assigned constant, but a wrong pack would make it index another
 * module's string, and a signature reporting on somebody else's pattern is worse
 * than one that reports nothing.
 */
static const struct kof_str_ent *str_of(const struct kof_scanner *sc, uint32_t id,
					const uint8_t **bytes)
{
	return kof_db_str(sc->eng, sc->cur_mod, id, bytes);
}

/*
 * The module facing search: resolve the range it named, then let the matcher answer.
 *
 * Everything about *how* to answer is the matcher's - the presence set, the memo,
 * the word boundaries. What is left here is the only part that needs the object's
 * parse: turning a named range into extents.
 */
static uint32_t c_data_xref(const struct kof_obj_ctx *ctx, uint64_t va,
			    uint64_t size);
/* Declared here for the same reason the two above are: the search below has a
 * resource failure to report and the recorder is defined with the other
 * scanner-state writers, further down. */

/*
 * The extents of one half of the symbol block, LAST RECORD FIRST.
 *
 * The same shape a region resolve produces, over a different buffer: one run per
 * record, and adjacent records of the same half coalesced into one. Coalescing
 * is deliberate and matches the region contract - a pattern lying across the
 * join between two adjacent extents is found - and it also makes the engine's
 * view of a half byte-identical to the contiguous half kofviewer displays, so a
 * marker taken from the SYM_EXP pane matches exactly the run it was taken from.
 *
 * Records only: KOF_SYM_HDRLEN is skipped, for the reason in kofsig.h.
 *
 *
 * WHY BACKWARDS.
 *
 * A symbol table is written runtime-first: the null record, the section and
 * file entries, then libc and the toolchain, and the author's own symbols
 * LAST. A rule scoped to a symbol half is nearly always asking about one of
 * the author's, so the answer is at the end of the table and a forward walk
 * pays for the whole runtime prefix to reach it. bases/heur/scloader_00.c
 * already walks its records this way for exactly this reason.
 *
 * IT CANNOT CHANGE AN ANSWER, and that is what makes it free rather than a
 * trade. kof_match_lookup returns whether the pattern is PRESENT - match_ranges
 * takes the extents in array order and stops at the first hit, so reversing
 * them reorders the work and not the result. The best case improves, the worst
 * case is the same walk, and nothing is skipped.
 *
 * The other search - kof_find_str_where, which answers WHERE - would be a
 * different matter, since the first hit found is the hit reported. It never
 * comes through here: it takes a module-computed offset and length rather than
 * a range id, so it has no extents to reverse.
 *
 * Each run still holds its own bytes in file order - only the RUNS are
 * reversed - because a run is one contiguous region and match_one scans it
 * forward like any other.
 */
/*
 * Search the halves of the symbol block that `mask` names.
 *
 * NOT MEMOISED, and that is not an oversight. The memo cell is keyed on the
 * (marker, mask) pair, so a mask that names a symbol half AND a file region is
 * one question with two buffers behind it - answering half of it and stamping
 * the cell would make the other half unreachable for every later asker. The
 * block is small enough that repeating the search is cheaper than the bug.
 */
static int c_find_str_sym(const struct kof_obj_ctx *ctx, uint32_t mask,
			  const uint8_t *bytes, const struct kof_str_ent *e)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint32_t sym_n = 0;
	const uint8_t *sym = oc_syms(ctx, &sym_n);
	int half;

	if (!sym)
		return 0;
	if (!sc->msym_bound) {
		kof_match_begin(&sc->msym, kof_buf_make(sym, sym_n));
		sc->msym_bound = 1;
	}
	/* Imports then exports, so a mask naming both stops on the first half
	 * that answers rather than always walking the longer one. */
	for (half = 0; half < 2; half++) {
		if (!(mask & (half ? KOF_SCAN_SYM_EXP : KOF_SCAN_SYM_IMP)))
			continue;
		/*
		 * Built once for this object and then reused, because the
		 * split is the object's and not the pattern's. See sym_ext in
		 * scan.h.
		 */
		if (!sc->sym_ext_done[half]) {
			if (!sc->sym_ext[half]) {
				sc->sym_ext[half] =
					malloc(KOF_SCAN_MAX_EXTENTS *
					       sizeof *sc->sym_ext[half]);
				if (!sc->sym_ext[half]) {
					/* Not "the symbol is absent", which is
					 * what a bare zero says and what a
					 * rule would read it as. The block was
					 * never searched. */
					oc_scan_broken(sc, KOF_BROKEN_LIMIT);
					return 0;
				}
			}
			sc->sym_ext_n[half] =
				kof_sym_extents(sym, sym_n,
						half ? KOF_SCAN_SYM_EXP
						     : KOF_SCAN_SYM_IMP,
						sc->sym_ext[half],
						KOF_SCAN_MAX_EXTENTS);
			sc->sym_ext_done[half] = 1;
		}
		if (sc->sym_ext_n[half] &&
		    kof_match_lookup(&sc->msym, KOF_MEMO_NONE,
				     sc->sym_ext[half], sc->sym_ext_n[half],
				     bytes, e->len, e->kind, e->flags, 0))
			return 1;
	}
	return 0;
}

/*
 * A DECLARED STRING WAS FOUND IN THIS OBJECT - see kof_scanner.str_hit.
 *
 * Recorded at the four hooks that answer a marker search rather than at the
 * one that looks the fastest, because a rule reaches them by different names -
 * kof_find_str, _at, _in, _where - and a fact recorded at some of them is a
 * fact that is wrong the first time a rule uses another.
 */
static int str_found(struct kof_scanner *sc, int r)
{
	if (r && sc)
		sc->str_hit = 1;
	return r;
}

static int c_find_str(const struct kof_obj_ctx *ctx, uint32_t str_id,
		      uint32_t range_id)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const struct kof_module *m = sc->cur_mod;
	const uint8_t *bytes;
	const struct kof_str_ent *e = str_of(sc, str_id, &bytes);
	struct kof_range *ext = sc->ext;
	uint32_t n;

	uint32_t mask, slot, uid;

	if (!e || range_id >= m->n_rng || m->rng_base + range_id >= sc->eng->n_rng)
		return 0;
	mask = sc->eng->rng_tab[m->rng_base + range_id];

	/*
	 * The memo slot is the QUESTION, not the asker.
	 *
	 * Two modules declaring the same marker get the same uid from the build, and
	 * the same region mask resolves to the same extents - so they are asking one
	 * question and it is answered once. Keying by module instead made the answer
	 * private to whoever asked first, and nobody can ask a signature author to
	 * know which markers other authors chose.
	 */
	/*
	 * The symbol halves first, because they are not in the object and the
	 * resolve below cannot describe them.
	 *
	 * A mask may name both spaces - SYM_EXP | CODE is a sayable thing and
	 * means "in either" - so this answers its half and falls through with
	 * the file bits still to do. When there are none left the whole
	 * question was about the block and the memo is skipped, which is what
	 * c_find_str_sym's note is about.
	 */
	if (mask & KOF_SCAN_SYM) {
		uint32_t sslot = KOF_MEMO_NONE;
		int found;

		/*
		 * A mask naming ONLY symbol halves keys the memo like any
		 * other, and must: it is one marker, one range, one buffer -
		 * the same question however many modules ask it. Two rules
		 * naming the same symbol used to pay two walks of the block
		 * each time, which is exactly what the memo exists to stop.
		 *
		 * The cell lives in sc->m even though the search runs on
		 * sc->msym. The slot is derived from (marker, mask) and a
		 * symbol mask has its own rng_uid, so these cells cannot
		 * collide with a file range's - and sc->m is begun once per
		 * object, so its generation invalidates them at exactly the
		 * right moment. Giving msym a memo of its own would instead
		 * duplicate a table sized by the whole database.
		 *
		 * A MIXED mask gets none of this. SYM_EXP | CODE is one
		 * question over two buffers, so a cell stamped after answering
		 * half of it would make the other half unreachable for every
		 * later asker.
		 */
		if (!(mask & ~KOF_SCAN_SYM)) {
			uid = sc->eng->packs[m->pack_id].uid_base + e->uid;
			sslot = uid * sc->eng->n_masks +
				sc->eng->rng_uid[m->rng_base + range_id];
			found = kof_match_memo_get(&sc->m, sslot);
			if (found >= 0)
				return str_found(sc, found);
		}
		found = c_find_str_sym(ctx, mask, bytes, e);
		if (sslot != KOF_MEMO_NONE)
			kof_match_memo_put(&sc->m, sslot, found);
		if (found)
			return str_found(sc, 1);
		mask &= ~KOF_SCAN_SYM;
		if (!mask)
			return 0;
		n = kof_scan_resolve_range(ctx, mask, ext);
		return str_found(sc,
				 kof_match_lookup(&sc->m, KOF_MEMO_NONE, ext,
						  n, bytes, e->len, e->kind,
						  e->flags,
						  &sc->st.gram_answers));
	}

	uid = sc->eng->packs[m->pack_id].uid_base + e->uid;
	{
		uint32_t mask_uid = sc->eng->rng_uid[m->rng_base + range_id];

		slot = uid * sc->eng->n_masks + mask_uid;

		/*
		 * A SWEEP MAY ALREADY KNOW, and asking it is cheaper than
		 * having been told.
		 *
		 * multi_prepass records which masks a sweep can answer for;
		 * the answer itself stays in sc->found until this asks. See
		 * uid_slot in kofmultimatch.h for what distributing it instead
		 * cost at scale.
		 */
		if (sc->mask_ok && mask_uid < sc->eng->n_masks &&
		    sc->mask_ok[mask_uid]) {
			int a = kof_multimatch_answer(sc->eng->multi, uid,
						      mask_uid, sc->found);

			if (a >= 0) {
				sc->st.multi_answers++;
				return str_found(sc, a);
			}
		}
	}

	n = kof_scan_resolve_range(ctx, mask, ext);
	return str_found(sc, kof_match_lookup(&sc->m, slot, ext, n, bytes,
					      e->len, e->kind, e->flags,
					      &sc->st.gram_answers));
}

/*
 * Compare at an offset the module computed.
 *
 * The offset is logic, not metadata: it comes from the entry point, from a field
 * read out of the object, from arithmetic on either. That is why it is a parameter
 * and not a declaration - the build cannot know it, and asking an author to declare
 * a value that depends on the file would be asking for the wrong thing. The bytes
 * stay metadata and stay in the database, which is what the two calls keep apart.
 *
 * The bound is the host's. Left to the module it would be a rule a signature has to
 * remember, on the one path where forgetting it reads outside the mapping, so it is
 * checked inside kof_match_at where it cannot be forgotten.
 */
static int c_find_str_at(const struct kof_obj_ctx *ctx, uint32_t str_id,
			 uint64_t off)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const uint8_t *bytes;
	const struct kof_str_ent *e = str_of(sc, str_id, &bytes);

	if (!e)
		return 0;
	return str_found(sc, kof_match_at(&sc->m, off, bytes, e->len,
					  e->kind, e->flags));
}

static int c_find_str_in(const struct kof_obj_ctx *ctx, uint32_t str_id,
			 uint64_t off, uint64_t len)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const uint8_t *bytes;
	const struct kof_str_ent *e = str_of(sc, str_id, &bytes);

	if (!e)
		return 0;
	return str_found(sc, kof_match_in(&sc->m, off, len, bytes, e->len,
					  e->kind, e->flags));
}

/*
 * The same search, answering where instead of whether.
 *
 * Available to detectors as well as unpackers - it is a read, not a production -
 * which is why it sits with the other content accessors rather than below.
 */
static uint64_t c_find_str_where(const struct kof_obj_ctx *ctx, uint32_t str_id,
				 uint64_t off, uint64_t len)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const uint8_t *bytes;
	const struct kof_str_ent *e = str_of(sc, str_id, &bytes);

	if (!e)
		return KOF_BROKEN;
	{
		uint64_t at = kof_match_where(&sc->m, off, len, bytes, e->len,
					      e->kind, e->flags);

		/* Answering WHERE is answering WHETHER - see str_found. */
		str_found(sc, at != KOF_BROKEN);
		return at;
	}
}

/*
 * Record why an object was not finished, keeping the first answer.
 *
 * First rather than worst, because the reasons arrive in causal order: a decoder
 * that met an unsupported coding stops producing, and the budget it then fails to
 * spend is a consequence rather than a second problem.
 */
void oc_scan_broken(struct kof_scanner *sc, uint32_t reason)
{
	if (!sc->broken)
		sc->broken = reason;
	if (reason == KOF_BROKEN_LIMIT)
		sc->stop = 1;
}

/*
 * A limit that bounded ONE decode, and says nothing about the next.
 *
 * oc_scan_broken's sticky stop is right for a budget: past a ceiling there is
 * nowhere to put what comes next, so asking again wastes time. It is wrong for
 * the declared-ratio clamp, which is a sanity bound on ONE stream's own header -
 * a folder claiming to expand 56x tells you nothing about the folder after it.
 *
 * Measured on Win32.Fearso.c.7z: two content folders, the first declaring
 * 342267 -> 19069533 and the second an ordinary 358660 -> 392128. Clamping the
 * first set stop, and the second - which decodes perfectly - was never
 * attempted. Eleven more archives in the same collection fail the same way, and
 * the reported reason was a budget the caller had not actually run out of.
 */
void oc_scan_capped(struct kof_scanner *sc, uint32_t reason)
{
	if (!sc->broken)
		sc->broken = reason;
}

/*
 * Whether the object may still PRODUCE, which is not the same question as whether
 * it is complete.
 *
 * A recorded reason used to stop everything, and that is wrong for three of the
 * four reasons there are. DAMAGED, UNSUPPORTED and ENCRYPTED describe what was
 * found; they are not instructions to stop looking. Only a limit is - past a
 * ceiling there is nowhere to put what comes next, and asking again produces the
 * same answer more slowly.
 *
 * Measured on a real workbook whose directory chain runs past the end of the file:
 * the module reports the damage, carries on as the ABI says it may, and every
 * extraction after that point returned nothing - so a document with three VBA
 * modules in it came back with none, and the reason it came back with none was that
 * it had said it was damaged.
 */
int oc_can_produce(const struct kof_scanner *sc)
{
	return sc->cur_src && !sc->stop;
}

/* A decoder's status, in the vocabulary the caller sees. Stopping is the
 * receiver's limit; everything else is the stream failing. */
uint32_t oc_broken_of_status(enum kof_decomp_status st)
{
	if (st == KOF_DEC_STOPPED)
		return KOF_BROKEN_LIMIT;
	/* A coding this build lacks is a gap in the engine, not damage in the file,
	 * and the two are reported apart because they lead different places. */
	if (st == KOF_DEC_UNSUPPORTED)
		return KOF_BROKEN_UNSUPPORTED;
	return KOF_BROKEN_DAMAGED;
}

/*
 * A module saying it did not finish.
 *
 * The same flag every host-side limit sets, reached from the other side. Available
 * to detectors as well: a detector that could not follow a structure has the same
 * thing to say, and the answer it must not give is "clean".
 */
void oc_incomplete(const struct kof_obj_ctx *ctx, uint32_t reason)
{
	/* The module's vocabulary is the host's; a value outside it is recorded as
	 * the least specific reason rather than stored and printed as a number. */
	if (reason != KOF_BROKEN_UNSUPPORTED && reason != KOF_BROKEN_DAMAGED &&
	    reason != KOF_BROKEN_ENCRYPTED)
		reason = KOF_BROKEN_LIMIT;
	kof_scan_of(ctx)->rep_reason = reason;
	oc_scan_broken(kof_scan_of(ctx), reason);
}

/*
 * A note on its way out.
 *
 * Resolved through the same name table a finding uses - a note and a detection are
 * both authored text keyed by the line that wrote them - and dropped entirely when
 * nobody is listening, which is the normal case.
 */
static void c_debug(const struct kof_obj_ctx *ctx, uint32_t name_id, uint64_t value)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const char *text;

	if (!sc->cur_mod)
		return;
	/* An id the table does not know is a stale table, and says so rather than
	 * borrowing the neighbouring name - the same rule findings follow. */
	text = kof_db_name(sc->eng, sc->cur_mod, name_id);
	if (!text)
		text = "unknown";
	/*
	 * THE MODULE NAMING ITSELF, KEPT - see kof_scanner.mod_tag.
	 *
	 * "MPRESS.PE.lc" carries the module's name in front of the field, and
	 * this is the only place the engine ever sees it. Taken here so a
	 * child can be stamped with it at the push, rather than left for a
	 * tool to guess at from whichever note happened to arrive last.
	 */
	{
		const char *dot = text, *last = 0;

		for (; *dot; dot++)
			if (*dot == '.')
				last = dot;
		if (last && last != text) {
			size_t n = (size_t)(last - text);

			if (n >= sizeof sc->mod_tag)
				n = sizeof sc->mod_tag - 1u;
			memcpy(sc->mod_tag, text, n);
			sc->mod_tag[n] = 0;
			sc->mod_tag_of = sc->cur_mod;
		}
	}
	if (!sc->debug_cb)
		return;
	/* The field, not the whole name: consumers ask "which version" without
	 * caring which module answered, the same way they always did - only
	 * without finding the dot themselves once per fact per object. */
	sc->debug_cb(kverdict_fact_id(text), text, value, sc->debug_user);
}


/* Section names are fixed length and may be truncated; comparing the whole of
 * a short literal against them is all this needs. */
static int kof_str_ne(const char *a, const char *b)
{
	while (*a && *a == *b) { a++; b++; }
	return *a != *b;
}

/*
 * WHAT THE CODE DOES WITH ONE DATA ADDRESS.
 *
 * The sweep is over the EXECUTABLE sections only, and it is one sweep for the
 * object rather than one per question: the answer does not depend on which
 * address is asked about, so building it per ask would decode the same
 * instructions once for every variable a rule considers - which is the shape
 * that makes an analysis too slow to enable by default.
 *
 * ELF only for now, and x86 only, because that is what can be swept: the
 * decoder is an x86 decoder. Any other object answers zero, which a rule reads
 * as "nothing known" rather than "not used" - see KOF_XREF_PARTIAL.
 */
static uint32_t c_data_xref(const struct kof_obj_ctx *ctx, uint64_t va,
			    uint64_t size)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint32_t f;

	if (!sc->latch[KOF_OL_USE]) {
		const struct kof_elf_info *e = ctx->file_header;
		uint32_t i;

		sc->latch[KOF_OL_USE] = 1;
		/*
		 * NOTHING KNOWN IS NOT THE SAME AS NOTHING FOUND.
		 *
		 * The decoder behind this reads x86, so an ARM or a MIPS
		 * object cannot be swept at all - and answering plain zero
		 * would tell a rule that no code refers to the address, which
		 * is a different and much stronger claim than "this build
		 * cannot say". A rule gating on the answer would then reject
		 * every candidate on every non-x86 file, silently, and the
		 * shellcode finder did exactly that for one build.
		 */
		if (ctx->format != KOF_FMT_ELF || !e ||
		    (ctx->arch != KOF_ARCH_X86 && ctx->arch != KOF_ARCH_X86_64))
			return KOF_XREF_PARTIAL;
		/*
		 * EVERY executable section, under ONE budget.
		 *
		 * Not the first one: the first executable section of an
		 * ordinary ELF is .init, twenty three bytes that name no
		 * variable, and stopping there answered "nothing is called"
		 * for every file. The budget is what bounds the work, and it
		 * is a total rather than a per-section limit so that a file
		 * with many small executable sections costs the same as one
		 * with a single large one.
		 */
		{
			uint32_t left = KOF_XREF_MAX, pass;
			uint64_t biggest = 0;
			kof_buf b = kof_src_buf(sc->cur_src);

			/*
			 * THE SIZE THAT IS THERE, not the size that is
			 * claimed, and the two are a whole ELF header field
			 * apart.
			 *
			 * sh_size is a 64-bit number the file writes and the
			 * parser records without clamping - it only flags
			 * SEC_PAST_EOF - so `biggest` taken from it is won by
			 * whichever section lies hardest. That section then
			 * owns pass 0 alone, is dropped there for holding no
			 * bytes, and every real section falls to pass 1 in
			 * TABLE ORDER - which is .init, .plt, .plt.got,
			 * .plt.sec and then .text, exactly the order the two
			 * passes exist to avoid. One wrong field turns the
			 * ordering off and nothing says so.
			 *
			 * kof_clip_len is the engine's own answer to "how much
			 * of this is really here" and is what the sweep below
			 * takes its bytes from, so ordering on anything else
			 * is ordering on a different number than the one being
			 * spent.
			 */
			for (i = 0; i < e->sec_count &&
				    i < KOF_ELF_MAX_SECTIONS; i++) {
				uint64_t have;

				if (e->sec[i].type != 1u ||
				    !(e->sec[i].flags & 0x4u))
					continue;
				have = kof_clip_len(b.n, e->sec[i].file_off,
						    e->sec[i].file_size);
				if (have > biggest)
					biggest = have;
			}

			sc->use = kof_xref_new();
			/*
			 * WHAT THE COMPILER PUT THERE, from the ELF's own
			 * structure and not from symbols - the files this has
			 * to work on are stripped.
			 *
			 *   the entry point               _start
			 *   .init_array, .fini_array      frame_dummy and
			 *                                 __do_global_dtors_aux
			 *   every executable section
			 *   that is not .text             .init .fini .plt
			 *
			 * What those regions call is startup as well, resolved
			 * inside the map - which is the only way the tm_clones
			 * pair is ever found, since nothing names them.
			 */
			if (sc->use && e->entry_addr)
				kof_xref_startup(sc->use, e->entry_addr);
			for (i = 0; sc->use && i < e->sec_count &&
				    i < KOF_ELF_MAX_SECTIONS; i++) {
				const struct kof_elf_sec *sec = &e->sec[i];
				uint32_t w = ctx->arch == KOF_ARCH_X86 ? 4u : 8u;
				uint64_t k, have;

				if (sec->type == 1u && (sec->flags & 0x4u) &&
				    kof_str_ne(sec->name, ".text"))
					kof_xref_startup(sc->use, sec->mem_addr);
				if (sec->type != 14u && sec->type != 15u)
					continue;   /* INIT_ARRAY, FINI_ARRAY */
				/*
				 * THE LOOP'S LENGTH IS THE OBJECT'S, NOT THE
				 * SECTION HEADER'S.
				 *
				 * sh_size is a 64-bit field the file chooses,
				 * and running to it turned one forged section
				 * header into a scan that never returns: a
				 * .init_array declaring 0x7000000000000000
				 * asks for 2^60 turns, each reading bytes the
				 * object does not hold and recording a zero
				 * that the map discards. Nothing faults, so
				 * nothing reports - the scan simply stops
				 * coming back, on a file that is otherwise an
				 * ordinary binary.
				 *
				 * Clipped rather than refused, the way every
				 * other length out of a header is handled
				 * here: a truncated .init_array still names
				 * the constructors it does hold.
				 */
				have = kof_clip_len(b.n, sec->file_off,
						    sec->file_size);
				/*
				 * AND THE READS ARE THE BUFFER'S. Eight c_rd8
				 * calls and eight shifts per entry, each one
				 * re-deriving the match context and re-doing
				 * the bounds arithmetic, where kof_rd_u64 is
				 * the same check once - the accessor every
				 * other reader in this engine uses.
				 */
				for (k = 0; k + w <= have; k += w) {
					uint64_t v = 0;
					uint32_t v32 = 0;

					if (w == 8u) {
						if (!kof_rd_u64(b, sec->file_off
								+ k, 0, &v))
							break;
					} else {
						if (!kof_rd_u32(b, sec->file_off
								+ k, 0, &v32))
							break;
						v = v32;
					}
					/*
					 * The table is 64 entries and an
					 * .init_array can declare more than
					 * the object has room for; past full,
					 * every further turn records nothing.
					 */
					if (!kof_xref_startup(sc->use, v))
						break;
				}
			}
			/*
			 * LARGEST SECTION FIRST, and the budget is why.
			 *
			 * Section table order puts .init, .plt, .plt.got and
			 * .plt.sec ahead of .text, and those are stubs that name
			 * no variable. Sweeping them first spends the budget on
			 * them: measured over 4940 ELF files in one lab, .text
			 * was left NOTHING in 56 of them and was cut short in
			 * another 466 - a tenth of the corpus analysed wrongly,
			 * and silently, because the answer for an address in an
			 * unswept section is "nothing refers to it".
			 *
			 * By size and not by the name ".text", because the name
			 * is a convention and the size is the thing that
			 * matters: whatever holds the most code is where the
			 * code is.
			 */
			for (pass = 0; sc->use && left && pass < 2; pass++)
			for (i = 0; sc->use && left &&
				    i < e->sec_count && i < KOF_ELF_MAX_SECTIONS;
			     i++) {
				const struct kof_elf_sec *sec = &e->sec[i];
				uint64_t have;
				uint32_t n;
				int big;

				if (sec->type != 1u || !(sec->flags & 0x4u))
					continue;       /* PROGBITS, executable */
				/* The same clip the ordering above used, so
				 * what decides the pass and what is swept in
				 * it are one number. */
				have = kof_clip_len(b.n, sec->file_off,
						    sec->file_size);
				if (!have)
					continue;
				big = have >= biggest;
				if ((pass == 0) != (big != 0))
					continue;
				n = have < left ? (uint32_t)have : left;
				kof_xref_add(sc->use, b.p + sec->file_off, n,
						sec->mem_addr,
						ctx->arch == KOF_ARCH_X86
						? 32u : 64u);
				left -= n;
				if (n < have)
					sc->use_cut = 1;
			}
			/* The budget is a total, so the sweep was cut exactly when the
			 * executable bytes the object holds exceed it: a section swept
			 * in part leaves n < have, one never reached leaves nothing
			 * behind to compare, and the total says both. */
			{
				uint64_t total = 0;

				for (i = 0; i < e->sec_count &&
					    i < KOF_ELF_MAX_SECTIONS; i++) {
					const struct kof_elf_sec *sec = &e->sec[i];

					if (sec->type == 1u && (sec->flags & 0x4u))
						total += kof_clip_len(b.n,
								sec->file_off,
								sec->file_size);
				}
				if (total > KOF_XREF_MAX)
					sc->use_cut = 1;
			}
		}
	}
	if (!sc->use)
		return KOF_XREF_PARTIAL;
	f = kof_xref_in(sc->use, va, size);
	/* PARTIAL when either bound bit: the address table is full, or the byte
	 * budget ended before every executable section was swept. Only the
	 * first was reported; "nothing refers to it" was then said of code that
	 * had never been read. */
	{
		uint32_t part = (kof_xref_full(sc->use) || sc->use_cut)
				? KOF_XREF_PARTIAL : 0u;

		return f ? f | part : part;
	}
}

/*
 * WOULD ANYTHING LOOK INSIDE A CHILD OF THIS FORMAT - see fmt_wanted in
 * kofmod/kofsig.h for what this is and why it is not a policy.
 *
 * Four yeses before the database is consulted at all, and each is a case where
 * "no" would be an answer this cannot support:
 *
 *   NO SCANNER OR NO ENGINE - there is nobody to have an opinion.
 *
 *   A RULE ASKED. Evidence on this object beats what the database targets in
 *   general; that is the whole point of the ask.
 *
 *   KOF_FMT_UNKNOWN, which means the producer will not say what the child is.
 *   Nothing can be concluded from "no rule targets unknown" because the child
 *   is not unknown once it is open - it is whatever the sniff chain makes of
 *   it. This is the case a container is used to hide things in, so it is the
 *   case that must never be skipped.
 *
 *   AN EMPTY DATABASE, or a format value this build cannot place. Both are
 *   "no answer" rather than "no": kofexaminer and kofviewer run with no
 *   database at all, and a tool that then produced no children would be
 *   showing a document as though it carried nothing.
 */
static int c_fmt_wanted(const struct kof_obj_ctx *ctx, uint8_t fmt)
{
	const struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc || !sc->eng)
		return 1;
	if (sc->raise_carried)
		return 1;
	if (fmt == KOF_FMT_UNKNOWN || fmt >= KOF_FMT_COUNT)
		return 1;
	if (!sc->eng->any_target)
		return 1;
	/* A target id past the width of the set is not recorded in it, so it is
	 * read as "wanted" - the set is an early-out and must never be the
	 * thing that stops a module running. See any_target_add. */
	return fmt >= 64u ||
	       (sc->eng->any_target & ((uint64_t)1 << fmt)) != 0;
}

/*
 * A region's geometry, from the same resolve every other region call uses.
 *
 * Offered to a DETECTOR as well as to an unpacker, which most producer-side
 * entries are not: this reads nothing, produces nothing and spends no budget -
 * it reports numbers the parse already worked out. A heuristic asking "how much
 * of this file did nothing account for" is exactly the caller it exists for, and
 * a heuristic is a detector.
 */
static int c_region_shape(const struct kof_obj_ctx *ctx, uint32_t mask,
			  struct kof_region_shape *out)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_range *ext;
	uint32_t n, i;

	if (!out)
		return 0;
	memset(out, 0, sizeof *out);
	if (!sc)
		return 0;
	ext = sc->ext_gather;
	n = kof_scan_resolve_range(ctx, mask, ext);
	out->runs = n;
	for (i = 0; i < n; i++) {
		out->bytes += ext[i].len;
		if (ext[i].len > out->widest) {
			out->widest = ext[i].len;
			out->widest_off = ext[i].off;
		}
	}
	return n != 0;
}

/*
 * The same ranges, measured rather than counted. Offered to a detector for the
 * reason c_region_shape is: it reads bytes the object already has, produces
 * nothing, and spends no budget beyond one pass over the region.
 */
static uint32_t c_region_entropy(const struct kof_obj_ctx *ctx, uint32_t mask)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_range *ext;
	uint32_t hist[256];
	kof_buf b;
	uint64_t total = 0;
	uint32_t n, i;

	if (!sc)
		return 0;
	b = oc_mc(ctx)->data;
	if (!b.p || !b.n)
		return 0;
	ext = sc->ext_gather;
	n = kof_scan_resolve_range(ctx, mask, ext);
	if (!n)
		return 0;

	/*
	 * Same memo as c_entropy_at, keyed on the MASK with a length no real
	 * range can have. A region entropy costs a pass over every extent the
	 * mask resolves to, so asking twice is the same waste and the same fix.
	 */
	for (i = 0; i < KOF_ENT_MEMO; i++)
		if (oc_mc(ctx)->ent[i].live &&
		    oc_mc(ctx)->ent[i].off == (uint64_t)mask &&
		    oc_mc(ctx)->ent[i].len == (uint64_t)-1)
			return oc_mc(ctx)->ent[i].val;

	memset(hist, 0, sizeof hist);
	for (i = 0; i < n; i++) {
		kof_buf s2 = kof_slice(b, ext[i].off, ext[i].len);
		uint64_t k;

		for (k = 0; k < s2.n; k++)
			hist[s2.p[k]]++;
		total += s2.n;
	}
	{
		struct kof_match_ctx *m = oc_mc(ctx);
		uint32_t v = kentropy_hist(hist, total);
		uint32_t slot = m->ent_next;

		m->ent[slot].off  = (uint64_t)mask;
		m->ent[slot].len  = (uint64_t)-1;
		m->ent[slot].val  = v;
		m->ent[slot].live = 1;
		m->ent_next = (uint8_t)((slot + 1u) % KOF_ENT_MEMO);
		return v;
	}
}

/* The extent form. See `entropy_at` in kofsig.h for why it is not the same
 * question as c_region_entropy. */
/*
 * THE SAME RANGE IS ASKED ABOUT ONCE PER RULE, AND ANSWERED ONCE.
 *
 * See struct kof_ent_memo for the measurement. The key is the range as the
 * caller named it, not the clipped slice: two callers naming the same range
 * get the same answer, and a caller naming a range that clips to the same
 * bytes is rare enough not to be worth a second key.
 *
 * Round robin rather than LRU: the table is eight entries, the miss cost is
 * exactly the old cost, and a replacement policy that needs its own bookkeeping
 * would spend on every hit what it saves on rare misses.
 */
static uint32_t c_entropy_at(const struct kof_obj_ctx *ctx, uint64_t off,
			     uint64_t len)
{
	struct kof_match_ctx *m = oc_mc(ctx);
	kof_buf s;
	uint32_t i, v;

	for (i = 0; i < KOF_ENT_MEMO; i++)
		if (m->ent[i].live && m->ent[i].off == off &&
		    m->ent[i].len == len)
			return m->ent[i].val;

	s = kof_slice(m->data, off, len);
	v = kentropy_eighths(s.p, s.n);

	i = m->ent_next;
	m->ent[i].off  = off;
	m->ent[i].len  = len;
	m->ent[i].val  = v;
	m->ent[i].live = 1;
	m->ent_next = (uint8_t)((i + 1u) % KOF_ENT_MEMO);
	return v;
}

/*
 * How much of a declared block is in this object.
 *
 * The counting happened before any module ran - see the feed in scan.c - so
 * this is a division, not a search. A module may ask about the same block
 * repeatedly and in any order for nothing.
 */
static uint32_t c_plague_score(const struct kof_obj_ctx *ctx, uint32_t block_id)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	/*
	 * THE MODULE'S BLOCK ID IS ITS OWN, and the pack it came from was given
	 * a base when it was loaded - the same arrangement string ids have. A
	 * module that asked with a raw index would be asking about whatever
	 * block of whatever other pack happened to sit there.
	 */
	{
		uint32_t b, pct, seen = 0, n_hash = 0, id, i;

		if (!sc || !sc->cur_mod)
			return 0;
		b = sc->cur_mod->block_base + block_id;
		pct = kof_plague_pct(&sc->plague, b);
		if (sc->plague_asked < 0)
			sc->plague_asked = 0;

		/*
		 * EVERY BLOCK THE RULE ASKS ABOUT IS PART OF ITS VERDICT.
		 *
		 * It used to keep only the highest-scoring one, which named a
		 * "block A and block B" rule after whichever half happened to
		 * score better and reported that half's percentage as the
		 * whole rule's. Both are now the set's: the name is the fold of
		 * the set (see kof_plague_name_of) and the score is the set's
		 * own containment, matched hashes over declared hashes, which
		 * is the same measurement one block's score already is.
		 *
		 * ONCE EACH. A module may ask about the same block repeatedly
		 * and in any order - see the note above - and counting a block
		 * twice would weight it twice.
		 */
		/* The best any one block reached, which is what the verdict
		 * reports - see kof_scanner.plague_best. Before the
		 * already-counted return below, because a block asked about
		 * twice scores the same twice and this is a maximum. */
		if (pct > sc->plague_best)
			sc->plague_best = pct;
		id = kof_plague_block_id(sc->eng->plague, b);
		for (i = 0; i < sc->n_plague_blk; i++)
			if (sc->plague_blk[i] == id)
				return pct;
		if (sc->n_plague_blk < KOF_PLAGUE_NAME_MAX) {
			sc->plague_blk[sc->n_plague_blk++] = id;
			if (kof_plague_counts(&sc->plague, b, &seen, &n_hash)) {
				sc->plague_hit += seen;
				sc->plague_tot += n_hash;
			}
		}
		return pct;
	}
}

/*
 * HOW MUCH OF A REFERENCE'S STRING SET THIS OBJECT HOLDS.
 *
 * BUILT ON FIRST ASK, not in a prepass. The set costs one pass over the
 * loadable regions and most objects meet no rule that wants one, so the work
 * happens when somebody asks and never otherwise. Asked twice, the second call
 * is a merge over two sorted arrays.
 *
 * ELF ONLY, because the set is defined by what the static library is not - see
 * koflib.h - and that subtraction is an ELF answer. Anything else answers zero,
 * which is the same answer as "none of it was there": a rule cannot tell those
 * apart and must not try.
 */

/* Remember what a similarity measure answered, for the name - see
 * kof_scanner.ovl_asked. The highest of them, because a rule may ask twice
 * and the reader wants the measurement the verdict could have rested on. */

/*
 * The two halves of a described repair - see kof_content.cure_patch.
 *
 * BOUNDS CHECKED HERE and not in the module: a module is a rule, and a rule
 * that could name an offset past the end of the object would be a rule that
 * could corrupt a file the engine was asked to look at. A request outside the
 * object is refused and the cure is told so.
 */
static int c_cure_patch(const struct kof_obj_ctx *ctx, uint64_t off,
			const uint8_t *bytes, uint32_t n)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	kof_buf b = oc_mc(ctx)->data;

	if (!sc || !bytes || !n || n > 16u)
		return 0;
	if (off > b.n || b.n - off < n)
		return 0;
	if (sc->n_cure_fix >= sizeof sc->cure_fix / sizeof sc->cure_fix[0])
		return 0;
	sc->cure_fix[sc->n_cure_fix].off = off;
	sc->cure_fix[sc->n_cure_fix].n = n;
	memcpy(sc->cure_fix[sc->n_cure_fix].b, bytes, n);
	sc->n_cure_fix++;
	return 1;
}

static int c_cure_truncate(const struct kof_obj_ctx *ctx, uint64_t len)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	kof_buf b = oc_mc(ctx)->data;

	/* Cutting to nothing, or to more than there is, is not a repair. */
	if (!sc || !len || len >= b.n)
		return 0;
	sc->cure_trunc = len;
	sc->cure_trunc_set = 1;
	return 1;
}

/*
 * THE DISINFECT STAGE, REACHED FROM A RULE - see libkofeng/disinfect/pzero.h.
 *
 * Thin on purpose. The arithmetic is pzero's and the bounds are this file's,
 * which is the same division cure_patch draws: a rule may name any offset it
 * likes and the host is what decides whether the object has one.
 */
static uint64_t c_pz_clean_end(const struct kof_obj_ctx *ctx)
{
	return kof_pz_clean_end(ctx);
}

static int c_pz_is_code(const struct kof_obj_ctx *ctx, uint64_t off)
{
	return kof_pz_is_code(ctx, off);
}

static uint64_t c_pz_addr_to_off(const struct kof_obj_ctx *ctx, uint64_t addr)
{
	return kof_pz_addr_to_off(ctx, addr);
}

/*
 * THE INPUT IS AN OFFSET AND NOT A POINTER, so the bytes being unmasked are
 * bounded by this object the way every other read a rule makes is. A module
 * hands over its own output buffer, which is its own stack.
 */
static uint32_t c_pz_unmask(const struct kof_obj_ctx *ctx, uint64_t off,
			    uint32_t n, uint32_t mask, uint32_t key,
			    uint8_t *out, uint32_t cap)
{
	kof_buf b = oc_mc(ctx)->data;

	if (!out || !n || off > b.n || b.n - off < n)
		return 0;
	return kof_pz_unmask(b.p + off, n, mask, key, out, cap);
}


/*
 * ---- THE CODE READER'S THREE ENTRY POINTS --------------------------------
 *
 * All the work is in libgenome/celllysis/cursor.c; these only hand it the object's
 * bytes and the cursor that lives in the scanner. See kofmod/cell.h.
 *
 * ANSWERED FOR A DETECTOR TOO, and that is the point of it. Reading code
 * without running it is exactly what a detector should be able to do - it is
 * the interpreter that a detector must not have.
 */
static int c_dis_seek(const struct kof_obj_ctx *ctx, uint64_t off, int keep)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	kof_buf b = oc_mc(ctx)->data;

	if (!sc || off >= b.n)
		return 0;
	return kof_cell_seek(&sc->cell, off, keep);
}

static int c_dis_next(const struct kof_obj_ctx *ctx, struct cell_insn *out)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	kof_buf b = oc_mc(ctx)->data;

	struct cell_space sp;

	if (!sc || !out || !b.p)
		return 0;
	kof_cell_space_init(&sp, ctx, b.p, b.n);
	return kof_cell_next(&sc->cell, &sp, out);
}

static int c_dis_reg(const struct kof_obj_ctx *ctx, uint8_t r, uint64_t *out)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	return sc ? kof_cell_reg(&sc->cell, r, out) : 0;
}

/*
 * Where a module says the infection is - see `infected` in kofsig.h.
 *
 * BOUNDS-CHECKED AGAINST THE OBJECT, like every other range a module hands
 * over: a mark past the end would point a reader at bytes that are not there.
 * A zero length is refused too, because a range of nothing marks nothing.
 */
static void c_infected(const struct kof_obj_ctx *ctx, uint64_t off,
		       uint64_t len, uint32_t kind)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	kof_buf b = oc_mc(ctx)->data;

	if (!sc || !len || off > b.n || b.n - off < len)
		return;
	if (sc->n_infect >= KOF_MAX_INFECTED) {
		/* A bound, and it says so: an infection past the sixteenth was a
		 * span a repair would never be offered, with nothing to tell the
		 * module or the report. */
		oc_scan_capped(sc, KOF_BROKEN_LIMIT);
		return;
	}
	sc->infect[sc->n_infect].off = off;
	sc->infect[sc->n_infect].len = len;
	sc->infect[sc->n_infect].kind = kind;
	sc->n_infect++;
}

/* See kof_content.cure_offer: the module located the damage and says so. */
static void c_cure_offer(const struct kof_obj_ctx *ctx, uint64_t at)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (sc) {
		sc->cure_have = 1;
		sc->cure_at = at;
	}
}

/*
 * WHAT A MEASURE COSTS IS WHAT GATES IT.
 *
 * The string set is a pass over bytes the object was going to be read for
 * anyway and is not gated. The other two are not like that: the block vector
 * is a hashing pass over every selected window, and the chain is a full
 * disassembly sweep. Both are the kind of cost kof_module.heur_level exists to
 * keep off a caller who did not ask for it - see heur_object, which refuses to
 * even ENTER a rule gated above the scan's level.
 *
 * SO THEY ANSWER ZERO BELOW THEIR LEVEL, which a rule cannot tell from "none
 * of it was there". That is the same conflation plague_score makes for a
 * region that was never resolved, and it is deliberate for the same reason: a
 * rule that could tell them apart would start reporting on the scanner's
 * settings rather than on the object.
 */
/*
 * The overlord LEVEL GATE went with the chain surface: ovl_level_ok and
 * ovl_note had no other caller. The idea is still needed - a scan and a
 * researcher opening one sample must not pay the same price - and comes back
 * with the replacement, which is where the two modes are decided.
 */

/*
 * WHICH ADDRESS MEANS WHICH CAPABILITY IN THIS OBJECT.
 *
 * The sweep reads syscalls on its own; an import it can only read if somebody
 * says what lives at the address being called. On a PE that is nearly all of
 * it - there are no syscall instructions to find in ordinary Windows code -
 * so without this a PE sweeps to nothing, which is what it did.
 *
 * BUILT ONCE AND SEARCHED LINEARLY. A few hundred imports at most, asked about
 * once per call instruction, and a sorted lookup would be a second thing to
 * get right for an object whose whole sweep is already bounded.
 */
/*
 * THE CHAIN SURFACE IS UNPLUGGED, and so is what it reached.
 *
 * c_pth_has, c_pth_feeds and c_pth_match used to sit in both vtables, and
 * they were the only way a scan reached the chain builder: a rule asked, the
 * sweep ran. The chain is being replaced - the shape it produced is a WALK
 * flattened into a sequence, and three things it cannot express are the ones
 * that matter: a producer with several consumers is a tree and not a list, a
 * step joined by control rather than by a value has nowhere to live, and a
 * distance in a sequence is broken by inserting one instruction between two
 * steps. The 64-slot set in front of it chose between chains by how much
 * each said, which is a bias against the short decisive shapes - MEASURED on
 * one bot: the engine found `pipe, vfork, dup2, dup2, execl("/bin/sh")` and
 * put only `pipe -> dup2` on the page.
 *
 * So the entry points are gone from the vtables, and so is what was behind
 * them: the sweep, the chain set and the function partition. The VOCABULARY
 * is what was kept - kofmod/kofcap.h and the tables in nucleo.c - because
 * which capability a name or a syscall number means is the part that was
 * right. The replacement reads the same words into a different shape.
 */

/* Containment over the object's block set, against a reference's own. */

/*
 * THE STRUCTURE TRACK, with the library out of both sides when the reference
 * asked for it - see kof_plague_shape.lib_cut.
 *
 * The spans are the ones the scanner already established for this object, so
 * this is not a fourth walk of the same bytes - see kof_scanner.cur_lib. A
 * reference that did not ask gets exactly the arithmetic the inline does,
 * which is what keeps every reference written before the cut existed meaning
 * what it meant.
 */
static uint32_t c_plague_shape(const struct kof_obj_ctx *ctx,
			    const struct kof_plague_shape *ref)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_plague_shape cur;

	if (!ref || !kof_elf(ctx))
		return 0;
	if (!ref->lib_cut || !sc || !sc->cur_lib_ok)
		return kof_plague_shape_pct(kof_elf(ctx), ref, ctx->obj_size);
	kof_plague_shape_of_cut(kof_elf(ctx), ctx->obj_size,
			     sc->cur_lib.span, sc->cur_lib.n, &cur);
	return kof_plague_shape_cmp(&cur, ref);
}


/*
 * WHICH DIAGNOSES THIS OBJECT CARRIES - read once, on the first ask.
 *
 * The walk over the code regions is the expensive half and it happens
 * here, behind the same demand gate the overlord descriptor and the
 * multi-pattern sweep sit behind: an object whose verdict comes from a
 * rule naming no diagnose does not pay for it.
 *
 * A DATABASE WITH NO DIAGNOSES COSTS NOTHING, which is the state this
 * ships in - the flag is set, the walk is skipped, and every ask answers
 * no. That is also the honest answer for an architecture the value model
 * does not have.
 */
static const struct kof_content kof_detect_vtable = {
	c_rd8, c_rd16, c_rd32, c_rd64, c_memeq, c_find_str, c_find_str_at,
	c_find_str_in, c_csum, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, c_find_str_where,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, oc_incomplete, NULL, oc_syms,
	c_data_xref,
	/* Answered for a detector too. The answer is about the database and
	 * not about who is asking, and a rule that wants to know whether its
	 * neighbours care about a format is asking a fair question. */
	c_fmt_wanted, c_region_shape, c_region_entropy, c_entropy_at,
	/* The block vector is gone - see the note in kofsig.h. The SLOT
	 * stays so no other entry moves, exactly as ovl_strings' did. */
	c_plague_score, NULL, NULL /* was c_pth_match */, c_plague_shape,
	c_cure_offer, c_cure_patch, c_cure_truncate,
	c_pz_clean_end, c_pz_is_code, c_pz_addr_to_off, c_pz_unmask,
	/* supersede - a detector produces nothing to be superseded by. */
	NULL,
	/* as_format - nor an image to write a header for. */
	NULL,
	/* packer_build - a detector names families, not builds. */
	NULL,
	/* emu_reg, emu_read - a detector drives no interpreter, so there is
	 * never a machine of its own to read. */
	NULL, NULL,
	/* emu_watch_insn, emu_resume - nor one to pause. */
	NULL, NULL,
	/* import, import_bytes, import_at - a detector produces no child to
	 * have imports. */
	NULL, NULL, NULL,
	/* emu_stop, emu_slice - a detector drives no run at all. */
	NULL, NULL,
	/* And the code reader, which a detector DOES get - see c_dis_seek. */
	c_dis_seek, c_dis_next, c_dis_reg,
	/* emu_region_read - no run, so no region to look into. */
	NULL,
	/* But a detector may mark what it found - see c_infected. */
	c_infected,
	/* And it drives no machine, so it changes none. */
	NULL, NULL, NULL,
	/* The profile's two questions - unplugged, see above. */
	oc_diag, NULL,
	/* the graph that diagnose produced, as records - see kofpathogen.h */
	oc_graph,
	/* two diagnoses meeting at a named node - see kof_diag_share */
	oc_diag_share,
	oc_diag_str,
	/* emu_api_returns, emu_patch - a detector drives no run. */
	NULL, NULL
};

static const struct kof_content kof_unpack_vtable = {
	c_rd8, c_rd16, c_rd32, c_rd64, c_memeq, c_find_str, c_find_str_at,
	c_find_str_in, c_csum, oc_window, oc_emit, oc_child, oc_unpack,
	oc_unpack_peek, oc_child_format, oc_child_kind, oc_child_want, oc_emu_watch, oc_child_entry,
	oc_unpack_chain, c_find_str_where,
	oc_gather, oc_name_next, oc_note_next,
	oc_produced_read, oc_produced_poke, oc_derive, oc_image, oc_at,
	oc_section, oc_sections_reset, oc_child_entry_rva,
	oc_child_dir, oc_layout_of_produced,
	oc_emu_run, oc_emu_region, oc_emu_take, oc_opened_already, oc_incomplete,
	oc_unpack_entry, oc_syms, c_data_xref, c_fmt_wanted, c_region_shape,
	c_region_entropy, c_entropy_at, c_plague_score,
	NULL, NULL /* was c_pth_match */, c_plague_shape, c_cure_offer, c_cure_patch,
	c_cure_truncate,
	c_pz_clean_end, c_pz_is_code, c_pz_addr_to_off, c_pz_unmask,
	oc_supersede, oc_as_format, oc_packer_build, oc_emu_reg, oc_emu_read,
	oc_emu_watch_insn, oc_emu_resume,
	oc_import, oc_import_bytes, oc_import_at,
	oc_emu_slice, oc_emu_stop,
	c_dis_seek, c_dis_next, c_dis_reg,
	oc_emu_region_read, c_infected,
	oc_emu_set_reg, oc_emu_set_ip, oc_emu_write,
	/* The profile's two questions - unplugged, see above. */
	NULL, NULL,
	oc_graph,
	oc_diag_share,
	oc_diag_str,
	oc_emu_api_returns, oc_emu_patch
};

/*
 * Present an object to a module.
 *
 * Every field a module can reach is set here, so what a module is allowed to see is one
 * function rather than an assignment list the scan routine has to keep right.
 */
void kof_mod_attach(struct kof_obj_ctx *ctx, struct kof_scanner *sc)
{
	ctx->content = &kof_detect_vtable;
	ctx->report  = c_report;
	ctx->debug   = c_debug;
	ctx->priv    = sc;
}

/* Swap in the producing surface for the length of one unpacker. */
void kof_mod_unpack_mode(struct kof_obj_ctx *ctx, int on)
{
	/* A name set for a child that was never produced dies with the module that
	 * set it. Otherwise it would be waiting for the next module's first child and
	 * would label it with an entry from a different object. */
	oc_pend_clear(kof_scan_of(ctx));
	ctx->content = on ? &kof_unpack_vtable : &kof_detect_vtable;
}


/*
 * The id for a field name. See kof_on_debug.
 *
 * The text after the last dot when there is one, the whole string when there is
 * not, hashed. Here rather than in a header so the hash has exactly one
 * definition: two of them drifting apart would be an id that means one thing to
 * the engine and another to the tool comparing against it.
 */
uint32_t kverdict_fact_id(const char *field)
{
	const char *dot;

	if (!field || !*field)
		return 0;
	dot = strrchr(field, '.');
	if (dot && dot[1])
		field = dot + 1;
	return kof_crc32(field, (uint64_t)strlen(field));
}


