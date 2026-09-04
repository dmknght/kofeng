/*
 * scan.c - process objects.
 *
 * One job in three steps, and the order is the point:
 *
 *   parse         format facts, so the filter has something to filter on
 *   derive        which regions exist - paid once for all modules
 *   filter + run  per module, cheapest test first
 *
 * The derive step is InitCache from the old Kaspersky engine: a small per-object
 * precomputation so each of very many records can be decided with one instruction.
 *
 * Producing the objects is here too, because it is the same job seen from one step out.
 * A file becomes one object; a directory yields many. When there is an unpacker, a
 * container will yield many the same way, through the same stack. What is *not* here:
 * the untrusted boundary a module reads through (objctx.c), and how a search is
 * answered (the matcher).
 */

/* lstat and the dirent walk are POSIX and the tree builds as strict ISO C11, so the
 * feature level has to be asked for - and before any include, or it does nothing.
 *
 * _GNU_SOURCE, not _POSIX_C_SOURCE: this file includes kofplatform.h (below),
 * whose POSIX branch defines kof_memmem by calling the real memmem - a
 * GNU/BSD extension the compiler must still see declared to compile that
 * inline function, whether or not scan.c itself calls it. _POSIX_C_SOURCE
 * alone does not just omit memmem on glibc, it suppresses it (any of
 * _POSIX_C_SOURCE/_XOPEN_SOURCE defined without _GNU_SOURCE/_DEFAULT_SOURCE
 * opts into strict POSIX). Missed originally because this project's builds
 * so far all ran on Windows, where kof_memmem never touches the real memmem
 * - a real Linux build fails immediately with "implicit declaration of
 * function 'memmem'". _GNU_SOURCE is a superset of _POSIX_C_SOURCE 200809L,
 * so nothing else this file relied on changes. */
#define _GNU_SOURCE

#include "scan.h"
#include "../kofheur/kofheur.h"
/* The rule ABI: the phase ids and what a rule may ask the engine for. The
 * engine-side model next door is a different file with a similar name - see the
 * note at the top of kofmod/heur.h. */
#include "../core/kofmod/heur.h"
#include "../core/kofmod/kofsym.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../core/kofplatform.h"

struct kof_scanner *kof_scan_of(const struct kof_obj_ctx *ctx)
{
	return (struct kof_scanner *)(void *)(uintptr_t)ctx->priv;
}

struct kof_scanner *kof_scan_new(const struct kof_engine *eng)
{
	struct kof_scanner *sc = calloc(1, sizeof *sc);

	if (!sc)
		return NULL;
	sc->eng = eng;
	sc->sink_fd = -1;   /* 0 is stdin; calloc would have made this a live fd */

	/* The matcher owns the search state: the presence set and the memo are how a
	 * search is answered, not how a scan is bookkept. */
	if (!kof_match_state_init(&sc->m, eng->n_str, eng->memo_size))
		goto fail;
	/*
	 * The symbol block's matcher: its own presence table, sized for a
	 * block rather than for a file, and no memo.
	 *
	 * 20 bits is 1M slots - 2MB against the file table's 32MB - and the
	 * block is capped at KOF_SYM_MAX_BYTES, a quarter megabyte, so
	 * occupancy stays under a quarter even at the cap and is a fraction of
	 * a percent at the median few kilobytes.
	 *
	 * The threshold is 2 rather than 140 because the arithmetic behind 140
	 * is about a buffer of megabytes: stamping costs one pass, and over a
	 * block this small the second search already pays it back.
	 *
	 * No memo here - c_find_str keeps the cell in sc->m, where the slot is
	 * already allocated by the database. See the note there.
	 */
	sc->msym.gram_bits = 20;
	sc->msym.gram_min = 2;
	if (!kof_match_state_init(&sc->msym, eng->n_str, 0))
		goto fail;
	return sc;

fail:
	kof_scan_free(sc);
	return NULL;
}

void kof_scan_free(struct kof_scanner *sc)
{
	uint32_t i;

	if (!sc)
		return;
	kof_match_state_free(&sc->m);
	kof_match_state_free(&sc->msym);
	kof_scan_kids_reset(sc);
	free(sc->kids);
	free(sc->kid_packer);
	free(sc->kid_family);
	for (i = 0; i < KOF_FMT_COUNT; i++)
		free(sc->view[i]);
	free(sc->inf);
	free(sc->sym);
	free(sc->sym_ext[0]);
	free(sc->sym_ext[1]);
	free(sc);
}

const struct kof_stats *kof_scan_stats(const struct kof_scanner *sc)
{
	return &sc->st;
}

/* ---- the byte accessors handed to a module --------------------------------- */

/*
 * Turn a named range into extents.
 *
 * Here rather than in objctx.c because only the parse knows where a region is, and this
 * is the file that ran it. KOF_SCAN_ALL needs no parse at all, which is what lets a
 * module naming only that region run against input nothing identified.
 */
uint32_t kof_scan_resolve_range(const struct kof_obj_ctx *ctx, uint32_t scan_mask,
				struct kof_range *ext)
{
	uint32_t n;

	if (scan_mask & KOF_SCAN_ALL) {
		ext[0].off = 0;
		ext[0].len = ctx->obj_size;
		return ctx->obj_size ? 1u : 0u;
	}
	if (!ctx->resolve_scan)
		return 0;
	n = ctx->resolve_scan(ctx, scan_mask, ext, KOF_SCAN_MAX_EXTENTS);
	if (n >= KOF_SCAN_MAX_EXTENTS) {
		/*
		 * The region did not fit, so what follows searches part of it.
		 *
		 * Said rather than swallowed. A buffer that filled exactly is
		 * indistinguishable from one that filled and had more to write, and
		 * the two lead to the same place: a search over some of a region,
		 * reported as a search over the region. That is the one answer this
		 * engine must never give quietly, so it is a limit like any other -
		 * the caller set the size, and the caller can be told it bound.
		 */
		struct kof_scanner *sc = kof_scan_of(ctx);

		if (!sc->broken)
			sc->broken = KOF_BROKEN_LIMIT;
		n = KOF_SCAN_MAX_EXTENTS;
	}
	return n;
}

/* ---- deriving per-object facts --------------------------------------------- */

/*
 * Which regions this object has, as a mask of region bits.
 *
 * Computed once per object, not once per module. Resolving a region walks the segment
 * and section tables and sorts the result, so doing it per module would cost more than
 * running the cheap modules it is meant to save. Done once, the per-module test is a
 * single AND.
 */
static uint32_t regions_present(const struct kof_obj_ctx *ctx, uint32_t wanted)
{
	struct kof_range *ext = kof_scan_of(ctx)->ext;
	uint32_t present = 0, bit;

	if (ctx->obj_size)
		present |= KOF_SCAN_ALL;
	if (!ctx->resolve_scan)
		return present;

	/*
	 * Only the regions some module names. A region nobody asks about does not
	 * need an answer, and one of them is a complement - it builds and sorts the
	 * whole claimed set to produce one range.
	 *
	 * Every bit, not the first sixteen. The ceiling used to be 16 because no
	 * format defined a region above bit 7, which made adding one a silent loss:
	 * the region would never be marked present, so the prefilter would skip
	 * every module that named it, and a detection that does not happen is not
	 * something a test notices. Thirty-one masked tests cost nothing.
	 */
	for (bit = 1; bit < 32; bit++) {
		uint32_t m = 1u << bit;

		if (!(wanted & m) || (m & KOF_SCAN_SYM))
			continue;
		if (ctx->resolve_scan(ctx, m, ext, KOF_SCAN_MAX_EXTENTS))
			present |= m;
	}
	return present;
}

/*
 * The same question about the two halves of the symbol block.
 *
 * Separate from the loop above because resolve_scan answers about the FILE, and
 * these are not in it - asked there, a format's resolver would say no to bits it
 * has never heard of and the prefilter would skip every module naming them.
 * Silent, and exactly the loss the note above describes.
 *
 * Still gated on `wanted`, so the block is not built for an object no module
 * asks about - which is nearly all of them.
 */
static uint32_t sym_halves_present(const struct kof_obj_ctx *ctx,
				   uint32_t wanted)
{
	uint32_t n = 0, total, i, present = 0;
	const uint8_t *b;

	if (!(wanted & KOF_SCAN_SYM) || !ctx->content || !ctx->content->syms)
		return 0;
	b = ctx->content->syms(ctx, &n);
	total = kof_sym_count(b, n);
	for (i = 0; i < total && present != KOF_SCAN_SYM; i++) {
		const uint8_t *r = kof_sym_rec(b, n, i);

		if (!r)
			continue;
		present |= (r[KOF_SYM_R_FLAGS] & KOF_SYM_F_UNDEFINED)
			 ? KOF_SCAN_SYM_IMP : KOF_SCAN_SYM_EXP;
	}
	return present & wanted;
}

/*
 * Can this module be ruled out without calling it?
 *
 * Every test reads a field of the module's record against a fact already produced.
 * None touches the blob, which is what makes this a pre-use filter rather than the
 * same conditions written inside the module - those are correct and save nothing,
 * because reaching them costs the call.
 *
 * Absent constraints mean unconstrained, so a module with an empty record runs. The
 * default has to fall that way: over-running costs time, under-running costs
 * detections and would not show up as a failure anywhere.
 */
/*
 * `out` is the per-object result and may be NULL - the unpack pass has no
 * result to fill yet. Passed rather than derived from the stats, because those
 * are cumulative and a per-object number taken by differencing them is wrong
 * the moment two objects are in flight.
 */
static int prefilter(const struct kof_module *m, const struct kof_obj_ctx *ctx,
		     uint32_t present, struct kof_stats *st,
		     struct kof_result *out)
{
	st->considered++;

	if (!(m->target_mask & (1u << ctx->format))) {
		st->by_target++;
		return 0;
	}
	if (ctx->obj_size < m->size_min) {
		st->by_size++;
		return 0;
	}
	if (m->arch_mask) {
		/* An architecture outside the bit width cannot be named by a mask, so
		 * a module that constrains architecture does not cover it. */
		if (ctx->arch >= 32 || !(m->arch_mask & (1u << ctx->arch))) {
			st->by_arch++;
			return 0;
		}
	}
	/*
	 * What kind of that format, in the format's own vocabulary.
	 *
	 * Safe to test with no idea which format this is, because target_mask was
	 * tested first: a module constraining subtype named one format's values, and
	 * this line is only reached for an object of a format that module declared.
	 * That is what lets KOF_ELF_REL and KOF_PE_DLL share the number 1.
	 */
	if (m->subtype_mask) {
		if (ctx->subtype >= 32 ||
		    !(m->subtype_mask & (1u << ctx->subtype))) {
			st->by_subtype++;
			return 0;
		}
	}
	/* A module that names regions cannot match if none exist here: every search
	 * it performs would be over an empty range. One that names none - scalar
	 * only - has nothing to be excused by, and runs. */
	if (m->scan_mask && !(m->scan_mask & present)) {
		st->by_region++;
		return 0;
	}

	st->ran++;
	if (out)
		out->examined++;
	return 1;
}

/* ---- naming a finding ------------------------------------------------------ */

/*
 * <target>/<what the author wrote>
 *
 *     ELF-x64/Botnet:Mirai-04gix              (KOF_MALVAR_AUTO)
 *     PE-x86/Hacktool:Meterpreter-Generic     (KOF_MALVAR_GENERIC)
 *     Zip/Exploit:ZipSlip-CVE-2018-1002200    (a custom variant)
 *
 * The target is composed and not authored: it is what the engine established by
 * parsing, so a module cannot claim a format it was not run against or an
 * architecture the object does not have. Everything after the "/" is authored -
 * a type from enum kof_maltype, a family, a variant - which is the part that
 * needs a person, and the "/" marks exactly that boundary: computed fact on the
 * left, human classification on the right.
 *
 * Three different separators past the "/", one per boundary, each chosen not to
 * collide with what a variant already tends to contain: KOF_MALVAR_AUTO's own
 * output and hand written variants like "CVE-2018-1002200" both use "-"
 * internally, so "-" is spent on exactly one boundary (family/variant) and nowhere
 * else, or "Mirai-CVE-2018-1002200" would read as a run of hyphens with no visible
 * structure. ":" separates type from family, matching how a reader already parses
 * "Category: Item" elsewhere; "." is avoided entirely here for the same collision
 * reason "-" is only used once.
 *
 * Format and architecture are one token joined by a dash rather than two parts.
 * They answer one question - what does this run on - and splitting them made every
 * name carry a separator that never told anyone anything.
 *
 * The operating system is absent on purpose. ELF does not say it, so "Linux" would
 * be a guess wearing the clothes of a fact, which is also why this reads "ELF-x64"
 * and not the "Linux/x64" other engines write.
 *
 * An object with no architecture - a script, or one nothing identified - gets the
 * format alone. A "-any" suffix would be a field describing nothing.
 */
/*
 * The one spelling. See kof_name_compose in kofeng.h for why it is a function.
 *
 * "#" between the family and the variant, not "-": a family name may contain a
 * hyphen and several in bases/ do, so the old separator could not be told from
 * the name around it by eye or by anything reading the string back. "#" appears
 * in no family and in no variant.
 */
void kof_name_compose(char *out, size_t cap, const char *target,
		      const char *maltype, const char *family,
		      const char *variant)
{
	int has_t = target && target[0];
	int has_v = variant && variant[0];

	if (!out || !cap)
		return;
	if (has_t && has_v)
		snprintf(out, cap, "%s/%s:%s#%s", target, maltype, family,
			 variant);
	else if (has_t)
		snprintf(out, cap, "%s/%s:%s", target, maltype, family);
	else if (has_v)
		snprintf(out, cap, "%s:%s#%s", maltype, family, variant);
	else
		snprintf(out, cap, "%s:%s", maltype, family);
}

static void finding_str(const struct kof_scanner *sc,
			const struct kof_obj_ctx *ctx,
			const struct kof_module *m, char *out, size_t cap)
{
	const char *variant = kof_db_name(sc->eng, m, sc->rep_name_id);
	const char *family  = kof_db_family(sc->eng, m);
	/*
	 * "Heur" where a maltype would be, for a rule.
	 *
	 * A maltype is a claim about what something DOES - trojan, rootkit,
	 * miner - and a rule has not established one. Writing the word here
	 * rather than adding it to the maltype enum keeps it out of the
	 * vocabulary a signature chooses from, which is what stops a signature
	 * from ever being able to claim it.
	 */
	const char *maltype = m->kind == KOF_PACK_HEUR
			      ? "Heur" : kof_maltype_name(m->maltype);
	const char *fmt = kof_format_name(ctx->format);
	char fmtarch[32];

	if (ctx->arch == KOF_ARCH_ANY || ctx->format == KOF_FMT_UNKNOWN)
		snprintf(fmtarch, sizeof fmtarch, "%s", fmt);
	else
		snprintf(fmtarch, sizeof fmtarch, "%s-%s", fmt,
			 kof_arch_name(ctx->arch));

	kof_name_compose(out, cap, fmtarch, maltype,
			 (family && family[0]) ? family : "unknown",
			 variant ? variant : "unknown");
}

/* ---- identify -------------------------------------------------------------- */

/*
 * The format table.
 *
 * Each collector answers two questions separately: does this object look like
 * mine, and - once a buffer exists - what does it say. The split is what lets the
 * view be allocated only for formats actually met, and it is why sniff takes no
 * buffer.
 *
 * Order is priority. It matters as soon as two formats can claim one object, and
 * writing it down here is cheaper than discovering it is implied by the order of
 * two if statements somewhere.
 */
struct parser {
	uint8_t  format;                       /* enum kof_format */
	uint32_t view_size;
	int (*sniff)(kof_buf);
	int (*parse)(kof_buf, void *view, struct kof_obj_ctx *);
};

static int elf_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_elf_parse(b, (struct kof_elf_info *)v, c);
}

static int pe_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_pe_parse(b, (struct kof_pe_info *)v, c);
}

static int gzip_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_gzip_parse(b, (struct kof_gzip_info *)v, c);
}

static int docole_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_docole_parse(b, (struct kof_docole_info *)v, c);
}

static int zip_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_zip_parse(b, (struct kof_zip_info *)v, c);
}

static int tar_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_tar_parse(b, (struct kof_tar_info *)v, c);
}

static int sevenzip_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_7z_parse(b, (struct kof_7z_info *)v, c);
}

static int rar_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_rar_parse(b, (struct kof_rar_info *)v, c);
}

static int xz_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_xz_parse(b, (struct kof_xz_info *)v, c);
}

static int rtf_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_rtf_parse(b, (struct kof_rtf_info *)v, c);
}

static int pdf_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_pdf_parse(b, (struct kof_pdf_info *)v, c);
}

static const struct parser parsers[] = {
	{ KOF_FMT_ELF,  (uint32_t)sizeof(struct kof_elf_info),
	  kof_elf_sniff,  elf_parse_thunk  },
	{ KOF_FMT_PE,   (uint32_t)sizeof(struct kof_pe_info),
	  kof_pe_sniff,   pe_parse_thunk   },
	{ KOF_FMT_GZIP, (uint32_t)sizeof(struct kof_gzip_info),
	  kof_gzip_sniff, gzip_parse_thunk },
	{ KOF_FMT_DOCOLE, (uint32_t)sizeof(struct kof_docole_info),
	  kof_docole_sniff, docole_parse_thunk },
	/*
	 * One row, two formats. The parse decides between ZIP and DOCZIP from the
	 * entry names and sets ctx->format itself, so the format named here is only
	 * which VIEW to allocate - and both share one.
	 */
	{ KOF_FMT_ZIP, (uint32_t)sizeof(struct kof_zip_info),
	  kof_zip_sniff, zip_parse_thunk },
	{ KOF_FMT_TAR, (uint32_t)sizeof(struct kof_tar_info),
	  kof_tar_sniff, tar_parse_thunk },
	{ KOF_FMT_7Z, (uint32_t)sizeof(struct kof_7z_info),
	  kof_7z_sniff, sevenzip_parse_thunk },
	{ KOF_FMT_RAR, (uint32_t)sizeof(struct kof_rar_info),
	  kof_rar_sniff, rar_parse_thunk },
	{ KOF_FMT_XZ, (uint32_t)sizeof(struct kof_xz_info),
	  kof_xz_sniff, xz_parse_thunk },
	{ KOF_FMT_RTF, (uint32_t)sizeof(struct kof_rtf_info),
	  kof_rtf_sniff, rtf_parse_thunk },
	{ KOF_FMT_PDF, (uint32_t)sizeof(struct kof_pdf_info),
	  kof_pdf_sniff, pdf_parse_thunk }
};

/*
 * Decide what the object is and fill the matching view.
 *
 * Nothing is allocated for a format the sniff rejected, and a view once allocated
 * is kept: a directory of ELF binaries allocates one view for the whole walk, and
 * a scanner that never meets a PE never allocates a PE view.
 *
 * An allocation failure leaves the object unidentified rather than failing the
 * scan. That is the same answer an unrecognised format gets, and it is the right
 * one: the object still gets scanned by every module whose target covers unknown.
 */
static void identify(struct kof_scanner *sc, kof_buf buf, struct kof_obj_ctx *ctx)
{
	uint32_t i;

	for (i = 0; i < sizeof parsers / sizeof parsers[0]; i++) {
		const struct parser *p = &parsers[i];

		if (!p->sniff(buf))
			continue;
		if (!sc->view[p->format]) {
			sc->view[p->format] = malloc(p->view_size);
			if (!sc->view[p->format])
				return;
		}
		if (p->parse(buf, sc->view[p->format], ctx))
			return;
	}
}

/* ---- the routine ---------------------------------------------------------- */

/*
 * Run the unpackers, once the detectors have had their say.
 *
 * After, not before, and that ordering is a decision rather than a convenience. An
 * archive whose entry names carry "../" is an exploit against whatever will open
 * it, and it has already been named by the time this runs - so unless the caller
 * asked for everything, there is nothing to gain from opening it and a budget to
 * lose. The same policy that already decides whether to keep running detectors
 * decides whether to open the container.
 */
/*
 * HOW MANY LAYERS OF PACKING THE INTERPRETER WILL GO THROUGH.
 *
 * Counted in PACKER layers, not tree depth - a tar inside a tar is not two
 * layers of packing, and pdepth already makes that distinction for the
 * heuristic. Emulator output is marked as a packer's, so it adds a layer like
 * any other unpacked payload.
 *
 * Two, because a packer wrapped in another packer is a real thing and a third
 * layer has not been seen: no object in the malware corpus reaches even the
 * second by this route. The reason for a ceiling at all is cost - each layer is
 * its own budget, up to 256 million instructions, so an object crafted to nest
 * could otherwise spend minutes of a scan on itself.
 */
#define EMU_MAX_PACKER_DEPTH 1u

/*
 * How many times one scan will honour a rule's ask for the emulator.
 *
 * A number and not a fraction of the tree, because the thing being bounded is
 * wall time on a tree of any size. 512 is what the measured population supports
 * with room to spare: the rule that asks today fires on 18 of 4398 malware
 * objects and on none of 5252 clean ones, so a scan that reaches this ceiling
 * is looking at something no measured corpus resembles - and the honest thing
 * then is to stop interpreting, not to keep going.
 */
#define HEUR_EMU_MAX 512u

/*
 * The preconditions an unpacker gets, the same a detector does minus the region
 * test an unpacker has no use for. Its own function because the two passes below
 * both apply it, and a check that lived in one loop and not the other would let
 * the family pass run a module the general pass would have ruled out.
 */
static int unp_eligible(const struct kof_module *m,
			const struct kof_obj_ctx *ctx,
			const struct kof_scan_option *opt)
{
	/*
	 * KOF_EMU_ONLY replaces the packer modules and only those. A container
	 * still has to be opened by the code that knows its format - there is
	 * nothing to interpret in a zip.
	 */
	if (opt->emu_use == KOF_EMU_ONLY && m->unp_kind == KOF_UNP_PACKER)
		return 0;
	if (!(m->target_mask & (1u << ctx->format)))
		return 0;
	if (ctx->obj_size < m->size_min)
		return 0;
	if (m->arch_mask &&
	    (ctx->arch >= 32 || !(m->arch_mask & (1u << ctx->arch))))
		return 0;
	return 1;
}

/* Whether an unpacker's declared family is the one a rule predicted. Both are
 * strings; NULL on either side is "no", so an unpacker that declares no family
 * never matches and an object with no prediction never has a family pass. */
static int unp_is_family(const struct kof_scanner *sc,
			 const struct kof_module *m, const char *predict)
{
	const char *fam;

	if (!predict)
		return 0;
	fam = kof_db_family(sc->eng, m);
	return fam && strcmp(fam, predict) == 0;
}

static uint32_t unpack_object(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
			 const struct kof_scan_option *opt,
			 const struct kof_result *res, uint32_t pdepth,
			 uint32_t want, const char *predict)
{
	uint32_t i;
	int applies = 0, family_opened = 0;

	if (sc->eng->n_unp == 0)
		return 0;
	/*
	 * A NAMED OBJECT NEED NOT BE OPENED. A GUESSED ONE MUST BE.
	 *
	 * The findings are counted, not just tested: a heuristic says the object
	 * has a shape, which is the opposite of knowing what is in it - and the
	 * one rule that exists says "this is a payload and I cannot read it",
	 * which is a reason to open the object rather than to stop. Testing
	 * res->n alone made a rule firing at EXAMINE cancel the unpacking of the
	 * very object it fired on, so a sample that used to yield three children
	 * yielded none and the payload inside was never scanned.
	 */
	if (res->n && !opt->all_matches) {
		uint32_t k, named = 0;

		for (k = 0; k < res->n; k++)
			if (res->v[k].level != KOF_LEVEL_HEUR)
				named++;
		if (named)
			return 0;
	}

	/*
	 * A fresh attempt for every object.
	 *
	 * Hitting a limit while unpacking one container does not mean the tree is
	 * finished: the memory ceiling is about what is alive at this instant, and
	 * by the time a child is being unpacked its siblings have been scanned and
	 * released, so there is room again. What does carry across the whole tree
	 * is `budget`, which is never reset - that is the bomb defence, and it is
	 * the one that has to be cumulative.
	 *
	 * Sticky exhaustion looked harmless and quietly halved the engine: the
	 * first container to reach the ceiling stopped every container after it.
	 */
	sc->broken = 0;
	/* Per object, like sc->broken: whether a packer opened the LAST object
	 * says nothing about this one. */
	sc->packed_here = 0;
	/*
	 * Cleared with it, and per OBJECT rather than per file.
	 *
	 * The two are set together and have to be cleared together: a ceiling that
	 * stopped one object must not stop the next, because the next is scanned
	 * after this one has been released and the room it held is back. Clearing
	 * only at the root made one limit anywhere in a tree end the tree.
	 */
	sc->stop = 0;

	kof_mod_unpack_mode(ctx, 1);

	/*
	 * FAMILY FIRST, when a rule predicted one.
	 *
	 * A heuristic that fired on this object may have named the family it
	 * expects - see KOF_HEUR_PREDICT. The decoders of that family are tried
	 * before any other, so an object correctly predicted is opened by the
	 * one module written for it and the rest are never entered.
	 *
	 * This is a REORDERING and never a filter, and the distinction is the
	 * whole safety of it. If the predicted family's decoders open the object
	 * the general pass is skipped - the best case, and the only time
	 * anything is saved. If they do not, the general pass runs every
	 * eligible unpacker exactly as it always has. So a wrong prediction
	 * costs the order it imposed and misses nothing: the worst case is the
	 * old case. The number of children before and after is how "did it open
	 * it" is answered, because producing a child is the only thing an
	 * unpacker does that the next pass would want to know about.
	 */
	if (predict) {
		uint32_t kids0 = sc->n_kids;

		for (i = 0; i < sc->eng->n_unp && !sc->broken; i++) {
			const struct kof_module *m = &sc->eng->unp[i];

			if (!unp_eligible(m, ctx, opt) ||
			    !unp_is_family(sc, m, predict))
				continue;
			applies = 1;
			sc->cur_mod = m;
			m->fn(ctx);
			sc->cur_mod = NULL;
		}
		family_opened = sc->n_kids > kids0;
	}

	/*
	 * The general pass, unless the predicted family already opened it.
	 *
	 * It skips the family-matched modules when a prediction was made,
	 * because the family pass above already ran them - re-running one that
	 * declined would be doing its work twice.
	 */
	for (i = 0; !family_opened && i < sc->eng->n_unp; i++) {
		const struct kof_module *m = &sc->eng->unp[i];

		if (!unp_eligible(m, ctx, opt))
			continue;
		/* Skip what the family pass already tried. Guarded on `predict`
		 * so the resolve-and-compare is not paid on the overwhelming
		 * majority of objects, which no rule spoke for. */
		if (predict && unp_is_family(sc, m, predict))
			continue;

		applies = 1;
		if (sc->broken)
			break;          /* nothing left to spend on this tree */

		sc->cur_mod = m;
		m->fn(ctx);
		sc->cur_mod = NULL;
	}
	/*
	 * A COMPLETE FILE SITTING AT AN OFFSET IS NOT AN UNPACKING PROBLEM.
	 *
	 * Run whatever the modules did or did not do, because carrying a
	 * payload and being packed are independent: a dropper can be neither,
	 * either or both. It costs one search of the object for two magics, and
	 * the header test behind it selects none of 1 328 clean binaries.
	 *
	 * Off at --heur 0, and that is the right switch for it rather than one
	 * of its own. Level 0 means "name families and nothing else": no facts
	 * gathered, nothing scored, no evidence produced that is not a match.
	 * A payload carried inside another file is exactly that kind of
	 * evidence - and a caller who has asked for the cheapest possible pass
	 * should not be given a tree of children they did not ask for.
	 *
	 * BEFORE THE INTERPRETER, because the two questions overlap and this is
	 * the one with an answer. A packed file and a file carrying a payload
	 * look alike from outside - both are mostly bytes that are not code -
	 * but "is there a whole executable at this offset" is decided by
	 * reading a header, while "what does this unpack to" is decided by
	 * running it for up to 256 million instructions. Cheap and certain
	 * first. They are not exclusive either: a packed dropper is both, and
	 * whichever runs first, the children get the other treatment when they
	 * are scanned in turn.
	 */
	if (!sc->broken && !opt->heur_off && kof_scan_embedded(ctx))
		applies = 1;
	/*
	 * NOTHING OPENED IT, SO RUN IT.
	 *
	 * Last, and only when every module that declared this format has had
	 * its turn and none of them produced anything. That ordering is the
	 * whole economy of it: a family with a static unpacker is opened by
	 * reading, which costs a pass over the object, and emulating it as well
	 * would pay a million instructions to learn the same thing. What is
	 * left when they all decline is either a packer nobody here has written
	 * a module for, or an object too damaged to read - and both are cases
	 * where running it is the only remaining way to see inside.
	 *
	 * `broken` is checked first for the same reason the module loop checks
	 * it: once the tree's budget is gone there is nothing to spend.
	 */
	/*
	 * A RULE MAY ASK FOR THE EMULATOR ON THIS OBJECT, and only this one.
	 *
	 * `want` came back from the EXAMINE phase in the caller and is passed
	 * down rather than stored, so it cannot outlive the object it was asked
	 * for. Three things still say no:
	 *
	 *   - an explicit --emu never, which is what emu_forbidden is for. The
	 *     option word alone cannot tell that apart from the NEVER that
	 *     --heur 1 leaves behind, and turning the second into emulation is
	 *     the whole point of the ask.
	 *   - the packer depth ceiling, unchanged.
	 *   - a ceiling on how many asks a whole scan honours. Without it a
	 *     directory of objects that all match one rule turns a five second
	 *     scan into minutes, and that is a cost a file's contents would be
	 *     choosing.
	 */
	/*
	 * A RULE'S ASK IS THE GATE when it fires, in any mode that permits the
	 * emulator at all.
	 *
	 *   - it does not fire under --emu never (emu_forbidden), which is the
	 *     one refusal a rule may not talk past;
	 *   - it yields to a static unpacker that already opened the object
	 *     (!packed_here) - the same guard the AUTO fallback carries, because
	 *     a payload peeled without running anything must not be run as well;
	 *   - it is bounded by the packer depth and by HEUR_EMU_MAX.
	 *
	 * When it does fire, the emulator is FORCED - the entropy gate below is
	 * skipped. That is the performance point and a correctness fix at once.
	 * Cheaper: the rule read a few parse fields where the gate makes a
	 * byte-histogram pass over every executable segment. Stricter: the gate
	 * needs DENSE_MIN bytes of code before its estimate means anything, and a
	 * meterpreter payload is smaller than that - so the gate returned NO on
	 * exactly the objects the rule fires on, and --heur 2 missed a shikata
	 * sample --heur 1 caught. The shape fires on 0 of 5252 clean objects, so
	 * it is a safe thing to force emulation on.
	 */
	if (!sc->broken && (want & KOF_ENG_USE_EMU) &&
	    !opt->emu_forbidden && !sc->packed_here &&
	    pdepth <= EMU_MAX_PACKER_DEPTH &&
	    sc->st.heur_emu < HEUR_EMU_MAX) {
		sc->st.heur_emu++;
		if (kof_scan_emu_unpack(ctx, 1))
			applies = 1;
	} else if (!sc->broken && opt->emu_use != KOF_EMU_NEVER &&
		   pdepth <= EMU_MAX_PACKER_DEPTH &&
		   (opt->emu_use == KOF_EMU_ONLY || !sc->packed_here)) {
		/* The entropy gate, for objects no rule spoke for. */
		if (kof_scan_emu_unpack(ctx, opt->emu_use == KOF_EMU_ONLY))
			applies = 1;
	}
	kof_mod_unpack_mode(ctx, 0);

	/*
	 * "Not fully examined" means both halves: something wanted to open this
	 * object, and the budget was gone. The budget is shared by the whole tree,
	 * so once it runs out every later object inherits the flag - and reporting
	 * that on an object no unpacker would have touched anyway is noise that
	 * makes the real case harder to see.
	 */
	return applies ? sc->broken : 0;
}

/*
 * WHAT THE HEURISTIC IS ALLOWED TO SEE, AND WHY IT IS GATHERED HERE.
 *
 * Everything below already exists by the time this runs: the anomaly word came
 * out of the parse, the depth came down the walk, and whether an unpacker gave up
 * is the value unpack_object just returned. Nothing is searched for and no pass is
 * made over the object, which is why this runs unless the caller switched it off
 * rather than only when the caller asked for it.
 *
 * Marker-derived evidence is deliberately absent. Knowing that a family has two
 * markers present but did not fire means asking about markers whose module's
 * logic never reached them, which is a pass over the object that would
 * otherwise not happen - so it is not free, and nothing here gathers it. There
 * was a --heur level for asking; it gathered nothing and changed no verdict, so
 * it is gone. If that evidence is ever collected it needs its own switch again,
 * and the switch should arrive with the collector rather than before it.
 */
static void heur_object(struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
			const struct kof_scan_option *opt, uint32_t pdepth,
			uint32_t partial, struct kof_result *out)
{
	const struct kof_heur_model *m = kof_heur_default();
	struct kof_heur_facts f;
	const char *guess = "Unknown";
	int32_t score = 0;

	if (opt->heur_off)
		return;

	memset(&f, 0, sizeof f);
	f.format       = ctx->format;
	/*
	 * PACKER layers, not tree depth.
	 *
	 * A file three directories down inside a tar is not three layers of
	 * packing, it is a directory tree - and depth counted every child the
	 * same way, so an ordinary archive of archives scored like something
	 * that had been wrapped to be hidden. Only a module that declared itself
	 * KOF_UNP_PACKER adds a layer now.
	 */
	f.anomalies    = kof_heur_anomalies(ctx);
	/*
	 * The object that WAS packed, not the one that came out.
	 *
	 * See kof_scanner.packed_here. Both are true of a packed sample and they
	 * are different objects: this marks the file on disk, and packer_depth
	 * above marks what was inside it.
	 */
	if (sc->packed_here)
		f.flags |= KOF_HEUR_FL(KOF_HEUR_F_PACKED);
	if (partial)
		f.flags |= KOF_HEUR_FL(KOF_HEUR_F_UNPACK_PARTIAL);
	if (!kof_heur_score(m, &f, &score, &guess))
		return;                 /* no model for this format - say nothing */

	/*
	 * Published before the bar is consulted.
	 *
	 * The bar decides whether this becomes a FINDING; it does not decide
	 * whether the caller is allowed to know the number. An examiner wants
	 * the score on every object precisely so it can show how far short of
	 * the bar something came.
	 */
	out->heur_scored    = 1;
	out->heur_score     = score;
	out->heur_flags     = f.flags;
	out->heur_anomalies = f.anomalies;
	out->heur_depth     = pdepth > 255u ? 255u : (uint8_t)pdepth;

	if (score < m->bar_centinats || out->n >= KOF_MAX_FINDINGS)
		return;

	/*
	 * A NAMED FAMILY SUPERSEDES A GUESS ABOUT THE SHAPE.
	 *
	 * The heuristic's measured worth is on objects the database MISSED -
	 * eleven percent of those, at this bar. On an object it did not miss it
	 * contributes nothing to the verdict, and printing both put two
	 * verdicts on one object: "Botnet:Mirai" and "Heur:Truncated" for the
	 * same bytes, leaving a reader to work out which one the scanner
	 * actually means.
	 *
	 * The SCORE is still published above, so an examiner shows how the
	 * object scored either way. What is suppressed is the second verdict,
	 * not the second fact.
	 */
	{
		uint32_t k;

		for (k = 0; k < out->n; k++)
			if (out->v[k].level != KOF_LEVEL_HEUR)
				return;
	}

	{
		struct kof_finding *fi = &out->v[out->n++];

		fi->level = KOF_LEVEL_HEUR;
		/*
		 * <target>/Heur:<what it looks like>:<how strongly>.
		 *
		 * Three parts because a reader asks three things and a bare
		 * number answers none of them: which population it was judged
		 * against, what the evidence suggests, and how far past the bar
		 * it went. The middle word comes from the model's own table -
		 * the engine does not know these words - so a heuristic
		 * authored elsewhere names its own findings.
		 *
		 * Heur is not a family and never becomes one. It is the engine
		 * saying it recognised a shape, not a thing.
		 */
		char fmtarch[32];
		const char *fmt = kof_format_name(ctx->format);

		if (ctx->arch == KOF_ARCH_ANY || ctx->format == KOF_FMT_UNKNOWN)
			snprintf(fmtarch, sizeof fmtarch, "%s", fmt);
		else
			snprintf(fmtarch, sizeof fmtarch, "%s-%s", fmt,
				 kof_arch_name(ctx->arch));
		snprintf(fi->name, sizeof fi->name, "%s/Heur:%s#s%d",
			 fmtarch, guess, score);
	}
}

/*
 * THE HEURISTIC RULES, at one of their two points in an object's life.
 *
 * Returns the OR of what the rules that FIRED asked the engine for - see
 * KOF_HEUR_WANT in kofmod/heur.h. An OR and not a last-writer, so two rules
 * asking for the same thing is the same request and the answer does not depend
 * on the order the packs happened to load in. That matters: --jobs must not
 * change a verdict, and scan_mt is the test that says so.
 *
 * The mask is returned rather than stored on the scanner. A field would be
 * state, and state is exactly how "this object asked for the emulator" becomes
 * "the rest of the scan uses it" - the bug this is shaped to make impossible.
 */
static uint32_t heur_run(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
			 const struct kof_scan_option *opt,
			 struct kof_result *out, uint32_t phase,
			 uint32_t present, const char **predict)
{
	uint32_t want = 0, i;
	/*
	 * ZERO MEANS UNSTATED, and unstated is level 1.
	 *
	 * Not a default written into the struct, because there is no
	 * initialiser to write it in: every caller declares a
	 * kof_scan_option on the stack and clears it, so a field whose
	 * useful value is 1 arrives as 0. Reading 0 as "the level every rule
	 * ran at before there was a choice" is what keeps kofexamine, the
	 * unit tests and any embedder working unchanged - the alternative
	 * silently disabled every heuristic for all of them.
	 *
	 * Level 0 is not spelled here: it is opt->heur_off, tested above.
	 */
	uint32_t lvl = opt->heur_level ? opt->heur_level : 1u;

	if (predict)
		*predict = NULL;
	if (opt->heur_off)
		return 0;
	for (i = 0; i < sc->eng->n_heur; i++) {
		const struct kof_module *m = &sc->eng->heur[i];

		if (m->heur_phase != phase)
			continue;
		/*
		 * A rule gated above this scan's level is not ENTERED, not
		 * merely ignored afterwards. That is the whole point of the
		 * declaration: the cost it was gated for - and for a rule that
		 * walks a symbol table, that cost is real - must not be paid by
		 * a caller who did not ask for it. Beside the phase test
		 * because they are the same kind of thing, a property of the
		 * rule that the scan compares against without running anything.
		 */
		if (m->heur_level > lvl)
			continue;
		if (!prefilter(m, ctx, present, &sc->st, out))
			continue;

		sc->rep_valid = 0;
		sc->cur_mod   = m;
		m->fn(ctx);
		sc->cur_mod   = NULL;

		if (!sc->rep_valid)
			continue;
		want |= m->heur_want;
		/*
		 * The FIRST prediction wins, and it is kept whether or not this
		 * rule's finding survives the named-family test below.
		 *
		 * Kept, because a prediction is used for two different things: it
		 * is written into the finding, and it decides which decoder is
		 * tried first. The second is worth having even on an object a
		 * signature already named - the name is about the container, the
		 * decoder is about what is inside it.
		 */
		if (predict && !*predict) {
			const char *pf = kof_db_heur_predict(sc->eng, m);

			if (pf && pf[0])
				*predict = pf;
		}
		/*
		 * A NAMED FAMILY SUPERSEDES A GUESS ABOUT THE SHAPE, and the
		 * rule is the same one the scored model follows a few functions
		 * down. The ASK is not suppressed with it: whether the object
		 * is worth interpreting was decided before anything was named,
		 * and withdrawing it here would leave a rule that fires and
		 * does nothing on precisely the objects a signature already
		 * half-recognised.
		 */
		{
			uint32_t k;
			int named = 0;

			for (k = 0; k < out->n; k++)
				if (out->v[k].level != KOF_LEVEL_HEUR)
					named = 1;
			if (named)
				continue;
		}
		if (out->n < KOF_MAX_FINDINGS) {
			struct kof_finding *f = &out->v[out->n++];
			const char *pf = kof_db_heur_predict(sc->eng, m);

			f->level = KOF_LEVEL_HEUR;
			/*
			 * <target>/Heur:<family>#<variant>?<shape>.
			 *
			 * The name follows the shape a detector's does - maltype,
			 * family, variant - and reads the same way: the FAMILY is what
			 * the object is, here what the rule PREDICTS it is, and the "?"
			 * carries the one thing a heuristic must admit - that the family
			 * is a guess and the SHAPE after the mark is the only thing
			 * actually shown. A rule that recognises a shellcode layout and
			 * expects Meterp reads Heur:Meterp#<variant>?Shellcode: the
			 * guessed family where a reader looks for one, the evidence
			 * behind the mark.
			 *
			 * Composed here and not through finding_str because that one is
			 * shared with the detectors and puts the MODULE's declared
			 * family in that slot - which for a rule is the shape it is
			 * named for, not the family it guesses. With no prediction the
			 * shape is all there is, and finding_str writing it as the
			 * family is exactly right.
			 */
			if (pf && pf[0]) {
				const char *variant =
					kof_db_name(sc->eng, m, sc->rep_name_id);
				const char *shape = kof_db_family(sc->eng, m);
				const char *fmt = kof_format_name(ctx->format);
				char fmtarch[32];
				size_t at;

				if (ctx->arch == KOF_ARCH_ANY ||
				    ctx->format == KOF_FMT_UNKNOWN)
					snprintf(fmtarch, sizeof fmtarch, "%s", fmt);
				else
					snprintf(fmtarch, sizeof fmtarch, "%s-%s",
						 fmt, kof_arch_name(ctx->arch));
				kof_name_compose(f->name, sizeof f->name, fmtarch,
						 "Heur", pf,
						 variant ? variant : "unknown");
				at = strlen(f->name);
				if (shape && shape[0] && at + 2 < sizeof f->name)
					snprintf(f->name + at, sizeof f->name - at,
						 "?%s", shape);
			} else {
				finding_str(sc, ctx, m, f->name, sizeof f->name);
			}
		} else {
			out->dropped++;
		}
		/* One HEUR line per object, the same way the detector loop
		 * stops at the first family - and for the same reason: the
		 * rules after it can only lengthen a list that already says
		 * what the object looks like. */
		if (!opt->all_matches)
			break;
	}
	return want;
}

static void scan_object(struct kof_scanner *sc, kof_buf buf,
			const struct kof_scan_option *opt, struct kof_result *out,
			uint32_t pdepth, int from_packer,
			const char *inherit_predict)
{
	struct kof_obj_ctx ctx;
	uint32_t present, i, want;
	const char *predict = NULL;

	out->from_packer = (uint8_t)(from_packer != 0);
	memset(&ctx, 0, sizeof ctx);
	kof_mod_attach(&ctx, sc);

	/*
	 * How big the object is, before anything tries to identify it.
	 *
	 * It is a property of the bytes, not of the parse, and leaving it to the
	 * collectors meant an object nothing recognised reported a size of zero.
	 * Everything downstream reads that as an empty file: KOF_SCAN_ALL resolves
	 * to no extents, so regions_present drops it, so the prefilter skips every
	 * module that names it - which is precisely the modules written to run on
	 * anything, the ones with no format header at all. They could not match an
	 * unidentified object, ever, and nothing said so.
	 */
	ctx.obj_size = buf.n;

	kof_match_begin(&sc->m, buf);
	/* A new object: whatever block the last one had is not this one's, and
	 * neither is the matcher bound to it. */
	sc->sym_done = 0;
	sc->sym_n = 0;
	sc->msym_bound = 0;
	sc->sym_ext_done[0] = sc->sym_ext_done[1] = 0;

	identify(sc, buf, &ctx);

	present = regions_present(&ctx, sc->eng->scan_mask);
	present |= sym_halves_present(&ctx, sc->eng->scan_mask);
	sc->st.objects++;
	sc->st.object_bytes += buf.n;

	for (i = 0; i < sc->eng->n_mods; i++) {
		const struct kof_module *m = &sc->eng->mods[i];

		if (!prefilter(m, &ctx, present, &sc->st, out))
			continue;

		sc->rep_valid = 0;
		sc->cur_mod   = m;
		m->fn(&ctx);
		sc->cur_mod   = NULL;

		if (!sc->rep_valid)
			continue;

		/* Accumulate. Keeping only the last would drop a finding whenever two
		 * families match one object, and the cap is counted rather than
		 * silently applied. */
		if (out->n < KOF_MAX_FINDINGS) {
			struct kof_finding *f = &out->v[out->n++];
			f->level = sc->rep_level;
			finding_str(sc, &ctx, m, f->name, sizeof f->name);
		} else {
			out->dropped++;
		}

		/*
		 * Stop unless the caller asked for everything. The remaining modules
		 * can only lengthen a list that already says the object is not clean,
		 * and on a database of any size that is most of the work.
		 *
		 * It saves nothing on a clean object, which is nearly every object -
		 * this is a bound on the worst case, not a throughput win.
		 */
		if (!opt->all_matches)
			break;
	}

	/* Before the next kof_match_begin clears them. */
	sc->st.searches       += sc->m.n_calls;
	sc->st.bytes_searched += sc->m.n_bytes_scanned;
	sc->st.gram_bytes     += sc->m.n_bytes_indexed;

	/*
	 * EXAMINE: what the object IS, asked before it is opened.
	 *
	 * Here and not earlier so a rule knows whether a family was named, and
	 * here and not later because this is the last moment at which what it
	 * asks for can still change what happens to the object.
	 */
	want = heur_run(sc, &ctx, opt, out, KOF_HEUR_EXAMINE, present, &predict);
	/*
	 * A rule's own guess wins; the inherited one is the fallback.
	 *
	 * A heuristic firing on THIS object knows more about it than its parent
	 * did - so its prediction takes precedence. The inherited family is for
	 * the case no rule fired at all, which is exactly the formatless
	 * intermediate layer a decoder peels: nothing recognises it, but its
	 * parent was a Meterp payload, so it very probably is one too, and
	 * trying that decoder first is the whole point of carrying the guess
	 * down.
	 */
	if (!predict)
		predict = inherit_predict;

	out->broken = unpack_object(sc, &ctx, opt, out, pdepth, want, predict);

	/* VERDICT: how it was reached, which only exists once it has been. */
	(void)heur_run(sc, &ctx, opt, out, KOF_HEUR_VERDICT, present, NULL);

	/*
	 * A RULE'S HEUR IS A LAST RESORT, and an object that OPENED is not the
	 * last resort - its children are.
	 *
	 * A rule says "I could not identify this, but here is its shape". When
	 * the object unpacks, the thing worth identifying is what came out, not
	 * the wrapper: rc4_1 is an encrypted stager, and the reader wants the
	 * Trojan:Meterp on the payload three layers down, not a Heur:Shellcode
	 * on the ciphertext that carried it. So a rule's heur on an object that
	 * produced children is dropped.
	 *
	 * THE SIGNAL IS NOT LOST, it MOVES. The same shape rule fires on the
	 * decoded child; if nothing can name that child either, the child
	 * produces no children of its own, so its heur is kept. The prediction
	 * ends up on the leaf that nothing could open or name, which is where
	 * "I could not identify this" belongs.
	 *
	 * DONE BEFORE heur_object, so only the RULE heur is dropped. The scored
	 * model that follows is about the object's own structure - a truncated
	 * header is truncated whether or not the object unpacked - so it is
	 * added after this and stays. Only children this object PRODUCED count;
	 * sc->n_kids is reset before it was scanned, and a container's members
	 * are its children too, but a container carries no rule heur to drop.
	 */
	if (sc->n_kids > 0 && out->n > 0) {
		uint32_t r, w = 0;

		for (r = 0; r < out->n; r++)
			if (out->v[r].level != KOF_LEVEL_HEUR)
				out->v[w++] = out->v[r];
		out->n = w;
	}

	/* Last, because the unpack result is one of the facts. */
	heur_object(sc, &ctx, opt, pdepth, out->broken == KOF_BROKEN_DAMAGED, out);
}

/*
 * Iterative, with its own stack of pending directories.
 *
 * Not recursive, and no depth ceiling: a filesystem may legally be deeper than any
 * number picked here, and putting the limit on the C stack makes the failure mode a
 * stack overflow - a crash, in a library, out of a directory tree. On the heap, running
 * out is reported instead. max_depth is policy for callers who want it, not a safety
 * net.
 *
 * Paths grow rather than living in a fixed buffer, so an over-long one fails visibly
 * instead of being skipped without a word.
 */
struct pending {
	char    *path;
	uint32_t depth;
};

/*
 * The work queue of a parallel walk: paths in, one worker each takes one out.
 *
 * BOUNDED, and that is the only interesting decision in it. An unbounded queue
 * would let the producer run the whole directory tree ahead of the workers and
 * hold every path in the tree at once - 14 000 strings here, and no bound at all
 * on a larger one. A bound makes the producer wait when the workers are behind,
 * which is exactly when it should.
 *
 * A ring of pointers rather than a list: the paths are strdup'd by the producer
 * and freed by whoever takes them, so ownership moves with the pointer and there
 * is nothing to walk on shutdown but the slots still holding one.
 */
struct mtq {
	pthread_mutex_t lock;
	pthread_cond_t  can_put, can_take;
	char          **slot;
	size_t          cap, head, tail, n;
	int             closed;      /* the producer has finished enumerating */
	int             aborted;     /* a callback asked to stop */
};

struct walk;
static void mtq_put(struct walk *w, const char *path, size_t len);

struct walk {
	struct kof_scanner *sc;
	const struct kof_scan_option *opt;
	kof_on_object cb;
	void *user;

	struct pending *stack;
	size_t          n, cap;

	char   *path_buf;     /* reusable, holds the entry currently being examined */
	size_t  path_cap;

	int      aborted;
	int      out_of_memory;
	uint64_t objects;

	/* Set only on the producer of a parallel walk: where a regular file goes
	 * instead of being scanned here. NULL in every single threaded walk, and
	 * the one branch that tests it is the whole difference between them. */
	struct mtq *q;
};

static int push_dir(struct walk *w, const char *path, size_t len, uint32_t depth)
{
	if (w->n == w->cap) {
		size_t nc = w->cap ? w->cap * 2 : 64;
		struct pending *nv = realloc(w->stack, nc * sizeof *nv);
		if (!nv) {
			w->out_of_memory = 1;
			return 0;
		}
		w->stack = nv;
		w->cap = nc;
	}
	w->stack[w->n].path = kof_strdup_n(path, len);
	if (!w->stack[w->n].path) {
		w->out_of_memory = 1;
		return 0;
	}
	w->stack[w->n].depth = depth;
	w->n++;
	return 1;
}

/* Grow the reusable buffer to hold at least `need` bytes including the terminator. */
static int path_reserve(struct walk *w, size_t need)
{
	if (need <= w->path_cap)
		return 1;
	{
		size_t nc = w->path_cap ? w->path_cap : 256;
		char *nv;
		while (nc < need)
			nc *= 2;
		nv = realloc(w->path_buf, nc);
		if (!nv) {
			w->out_of_memory = 1;
			return 0;
		}
		w->path_buf = nv;
		w->path_cap = nc;
	}
	return 1;
}

/*
 * Scan one object and everything it turns out to contain.
 *
 * Iterative, with its own stack, for the same reason the directory walk is: the
 * depth of an object tree is chosen by whoever built the file, and putting it on
 * the C stack makes the failure mode a crash inside a library. It also keeps
 * exactly one parsed view of each format in use at a time - a child parsed while
 * its parent's view was still live would overwrite it, since there is one view per
 * format per scanner.
 *
 * A child holds a reference to whatever its bytes live in, so the parent's mapping
 * survives exactly as long as something still points into it and no longer.
 */
/*
 * HOW DEEP AN OBJECT MAY BE UNPACKED, AND WHY IT IS NOT A NUMBER.
 *
 * A fixed depth is wrong in both directions at once. Twenty layers of a
 * meterpreter payload is twenty passes over about a kilobyte - measured, a
 * twenty deep chain of this engine's own XOR unwrapper is 21 objects and
 * finishes instantly - while twenty layers of a five megabyte archive is a
 * hundred megabytes of decompression, which is the shape a bomb takes. Pick a
 * number that allows the first and it permits the second; pick one that refuses
 * the second and it truncates the first.
 *
 * So the allowance is derived from what a layer COSTS, which is the size of the
 * object about to be opened:
 *
 *     allowed = CHAIN_BYTES / size, clamped to [CHAIN_MIN, CHAIN_MAX]
 *
 *        200 B  ->  64   a stager encoded over and over
 *      64 KB    ->  64   still nothing
 *       1 MB    ->  64
 *       5 MB    ->  12   an archive: roughly the ten to twenty a reader expects
 *      16 MB    ->   4
 *      64 MB+   ->   4   the floor, so something is always looked at
 *
 * The floor matters as much as the ceiling: an object too large to descend far
 * into still gets four levels, because refusing outright would hide a payload
 * behind one big container. And this bounds LAYERS, not bytes - the produced
 * byte budget already bounds those, tree wide, and a second byte limit here
 * would be the same rule written twice.
 */
#define CHAIN_BYTES  (64u << 20)
#define CHAIN_MIN    4u
#define CHAIN_MAX    64u

static uint32_t depth_allowance(uint64_t size)
{
	uint64_t n;

	if (!size)
		return CHAIN_MAX;
	n = (uint64_t)CHAIN_BYTES / size;
	if (n > CHAIN_MAX)
		return CHAIN_MAX;
	if (n < CHAIN_MIN)
		return CHAIN_MIN;
	return (uint32_t)n;
}

struct layer {
	struct kof_objsrc *src;
	char              *name;
	uint32_t           depth;    /* in the object tree, for max_depth */
	/*
	 * PACKER layers only.
	 *
	 * Separate from `depth` because the two answer different questions and
	 * conflating them was the bug: max_depth bounds how far the walk goes and
	 * must count every child, while the heuristic weighs how many times this
	 * program was wrapped to be hidden and must count none of the containers.
	 */
	uint32_t           pdepth;
	int                from_packer;  /* its producer was a packer */
	/*
	 * The family its producer decodes, inherited as a prediction, or NULL.
	 *
	 * A pointer into a pack mapping, valid for the life of the engine, so it
	 * is copied here as-is. It is what carries the Meterp guess down through
	 * the formatless intermediate layers a decoder peels, on which no
	 * heuristic fires - see scan_object.
	 */
	const char        *inherit_predict;
};

static void scan_tree(struct walk *w, struct kof_objsrc *root, const char *path)
{
	struct layer *stack = NULL;
	uint32_t n = 0, cap = 0;

	/* The root is not copied into the stack; it is scanned first and its
	 * children seed it. */
	struct kof_objsrc *src = kof_src_ref(root);
	char *name = kof_strdup_n(path, strlen(path));
	uint32_t depth = 0, pdepth = 0;
	int from_packer = 0;            /* the root came off the disk */
	const char *inherit = NULL;     /* the root inherits no prediction */

	/* Every other allocation failure in this function sets out_of_memory so
	 * the walk is reported incomplete rather than clean - this one didn't,
	 * which meant an OOM here dropped the root's finding silently instead
	 * (the callback guard below already tolerates a NULL name, so nothing
	 * crashes; it just never gets called). */
	if (!name)
		w->out_of_memory = 1;

	kof_scan_budget(w->sc, kof_src_buf(root).n, w->opt);

	for (;;) {
		struct kof_result res;
		uint32_t i;

		/*
		 * Cleared WHOLE, not field by field.
		 *
		 * It was three assignments, and that is a shape that goes stale
		 * the moment the struct grows: the heuristic fields were added
		 * and every object carried whatever the stack happened to hold,
		 * so a zip reported itself packed. A memset cannot forget a
		 * field, which is the only property worth having here.
		 */
		memset(&res, 0, sizeof res);

		w->sc->cur_src = src;
		kof_scan_kids_reset(w->sc);
		scan_object(w->sc, kof_src_buf(src), w->opt, &res, pdepth,
			    from_packer, inherit);
		w->sc->cur_src = NULL;

		/*
		 * A LAYER LEFT UNOPENED IS SAID SO, BEFORE THE VERDICT IS.
		 *
		 * The cost limit below refuses children, and refusing one in
		 * silence would report an object as examined when a layer of it
		 * was never looked at - the failure this engine's budgets are
		 * careful never to produce. Decided here rather than at the push
		 * because the callback has not fired yet: after it, the verdict
		 * for this object is already out.
		 *
		 * It reads as "not fully examined", the same channel a
		 * decompressor uses when its budget runs out, because it is the
		 * same statement: something was produced and nobody looked at it.
		 * Measured over 12.9GB and 60 248 objects it never once fires -
		 * so this is a guard for the file that has not turned up yet
		 * rather than a thing the scan does today.
		 */
		if (!res.broken) {
			for (i = 0; i < w->sc->n_kids; i++)
				if (depth + 1u >
				    depth_allowance(kof_src_buf(w->sc->kids[i]).n)) {
					res.broken = KOF_BROKEN_LIMIT;
					break;
				}
		}

		w->objects++;
		{
			kof_buf ob = kof_src_buf(src);

			if (w->cb && name &&
			    w->cb(name, ob.p, ob.n, &res, w->user) != 0)
				w->aborted = 1;
		}

		/* Take the children before anything else can reset them. */
		if (!w->aborted && !w->out_of_memory &&
		    (!w->opt->max_depth || depth + 1 <= w->opt->max_depth)) {
			/*
			 * PUSHED BACKWARDS SO THEY COME OUT FORWARDS.
			 *
			 * The stack is what makes this depth-first without
			 * recursion, and a stack reverses whatever order things
			 * go onto it. Pushed 0..n-1, the children came back
			 * n-1..0 - so an archive listed its last entry first,
			 * and a dropper carrying one payload per architecture
			 * showed them bottom to top in the viewer's tree. The
			 * numbering was right all along; only the order they
			 * were walked in was backwards.
			 */
			for (i = w->sc->n_kids; i-- > 0; ) {
				char kid[512];

				if (n == cap) {
					uint32_t nc = cap ? cap * 2 : 16;
					struct layer *nv = realloc(stack,
								   nc * sizeof *nv);
					if (!nv) {
						w->out_of_memory = 1;
						break;
					}
					stack = nv;
					cap = nc;
				}
				/*
				 * The index AND the name, not the name alone.
				 *
				 * An index on its own says nothing about which of
				 * fifty entries was found, which is what this used
				 * to print. A name on its own is not unique: an
				 * archive may hold two entries with the same name,
				 * and sanitising two different names can collapse
				 * them into one string. Together they are always
				 * exactly one entry.
				 */
				{
					const char *lab =
						kof_src_label_of(w->sc->kids[i]);

					if (*lab)
						snprintf(kid, sizeof kid,
							 "%s//%u:%s",
							 name ? name : "?", i, lab);
					else
						snprintf(kid, sizeof kid, "%s//%u",
							 name ? name : "?", i);
				}
				/*
				 * The cost limit, asked about the CHILD rather
				 * than about this object: what a layer costs is
				 * the size of the thing that layer produced, and
				 * a bomb's children are larger than it is. Asking
				 * the parent would let a small archive hand back
				 * a huge one at full depth, which is the case the
				 * limit exists for.
				 */
				if (depth + 1u >
				    depth_allowance(kof_src_buf(w->sc->kids[i]).n))
					continue;   /* said above, before the verdict */
				stack[n].src = kof_src_ref(w->sc->kids[i]);
				stack[n].name = kof_strdup_n(kid, strlen(kid));
				if (!stack[n].name)
					w->out_of_memory = 1;
				stack[n].depth = depth + 1;
				stack[n].from_packer = w->sc->kid_packer &&
						       w->sc->kid_packer[i];
				stack[n].pdepth = pdepth +
					(stack[n].from_packer ? 1u : 0u);
				stack[n].inherit_predict =
					w->sc->kid_family ? w->sc->kid_family[i]
							  : NULL;
				n++;
			}
		}
		kof_scan_kids_reset(w->sc);

		/* Nothing to release by hand: a produced source gives its bytes back
		 * when it is destroyed, so every path that drops one - here, the
		 * child cap, an aborted walk - accounts for it without knowing that
		 * it has to. */
		kof_src_unref(src);
		free(name);

		if (w->aborted || n == 0)
			break;
		n--;
		src = stack[n].src;
		name = stack[n].name;
		depth = stack[n].depth;
		pdepth = stack[n].pdepth;
		from_packer = stack[n].from_packer;
		inherit = stack[n].inherit_predict;
	}

	while (n > 0) {
		n--;
		kof_src_unref(stack[n].src);
		free(stack[n].name);
	}
	free(stack);
}

static void scan_file(struct walk *w, const char *path)
{
	struct kof_objsrc *src;
	int err = 0;

	src = kof_src_file(path, &err);
	if (!src) {
		w->sc->st.unreadable++;
		return;
	}
	scan_tree(w, src, path);
	kof_src_unref(src);
}

static void read_dir(struct walk *w, const char *dir, uint32_t depth)
{
	size_t dir_len = strlen(dir);
	struct dirent *de;
	DIR *d;

	d = opendir(dir);
	if (!d) {
		/* Unreadable, or a path the system would not accept. Counted, because a
		 * subtree that silently vanishes reads as a subtree with nothing in it. */
		w->sc->st.unreadable++;
		return;
	}
	while (!w->aborted && !w->out_of_memory && (de = readdir(d)) != NULL) {
		size_t nl, total;
		struct stat sb;

		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;

		nl = strlen(de->d_name);
		total = dir_len + 1 + nl + 1;
		if (!path_reserve(w, total))
			break;
		memcpy(w->path_buf, dir, dir_len);
		w->path_buf[dir_len] = '/';
		memcpy(w->path_buf + dir_len + 1, de->d_name, nl + 1);

		/* lstat, not stat: a symlink is not followed unless asked for, so a link
		 * pointing at an ancestor cannot turn this into a loop. */
		if ((w->opt->follow_symlinks ? stat : kof_lstat)(w->path_buf, &sb) != 0) {
			w->sc->st.unreadable++;
			continue;
		}

		if (S_ISDIR(sb.st_mode)) {
			if (!w->opt->recurse_dirs)
				continue;
			if (w->opt->max_depth && depth + 1 > w->opt->max_depth)
				continue;
			push_dir(w, w->path_buf, dir_len + 1 + nl, depth + 1);
		} else if (S_ISREG(sb.st_mode)) {
			if (w->q)
				mtq_put(w, w->path_buf, dir_len + 1 + nl);
			else
				scan_file(w, w->path_buf);
		}
		/* anything else - socket, device, fifo - is not an object */
	}
	closedir(d);
}

/*
 * Scan bytes the caller already has, under a name of their choosing.
 *
 * Same machinery as a file: one source, then scan_tree, which is the part that
 * knows how an object turns into a tree of them. The directory walk above is
 * about finding files; this is about scanning one thing, and the two share
 * everything below that distinction.
 *
 * It exists because a tool that has already scanned a file may want to ask a
 * DIFFERENT question about one object inside it - kofviewer runs the
 * interpreter on a node the reader picked, having built the tree with the
 * static unpackers - and re-scanning the whole file with different options
 * would answer that question about every object instead of the one asked about.
 *
 * The bytes are borrowed, not taken: they must outlive the call.
 */
int kof_scan_bytes(struct kof_scanner *sc, const void *bytes, uint64_t n,
		   const char *name, const struct kof_scan_option *opt,
		   kof_on_object cb, void *user)
{
	static const struct kof_scan_option conservative;
	struct kof_objsrc *src;
	struct walk w;

	if (!sc || !bytes || !n)
		return KOF_ERR_ARG;
	memset(&w, 0, sizeof w);
	w.sc   = sc;
	w.opt  = opt ? opt : &conservative;
	w.cb   = cb;
	w.user = user;

	/*
	 * A window over nothing: kof_src_window needs a parent, and there is no
	 * parent here. kof_src_heap takes ownership of a heap block and this
	 * caller's bytes are not one, so the source is built to borrow - see
	 * kof_src_borrow.
	 */
	src = kof_src_borrow(bytes, n);
	if (!src)
		return KOF_ERR_OPEN;
	scan_tree(&w, src, name ? name : "");
	kof_src_unref(src);
	free(w.path_buf);
	return w.objects ? (int)w.objects : 0;
}

/* ---- the parallel walk ---------------------------------------------------- */

static void mtq_put(struct walk *w, const char *path, size_t len)
{
	struct mtq *q = w->q;
	char *copy = kof_strdup_n(path, len);

	if (!copy) {
		w->out_of_memory = 1;
		return;
	}
	pthread_mutex_lock(&q->lock);
	while (q->n == q->cap && !q->aborted)
		pthread_cond_wait(&q->can_put, &q->lock);
	if (q->aborted) {
		pthread_mutex_unlock(&q->lock);
		free(copy);
		w->aborted = 1;
		return;
	}
	q->slot[q->tail] = copy;
	q->tail = (q->tail + 1u) % q->cap;
	q->n++;
	pthread_cond_signal(&q->can_take);
	pthread_mutex_unlock(&q->lock);
}

/* One path, or NULL when there will be no more. The caller owns what it gets. */
static char *mtq_take(struct mtq *q)
{
	char *p;

	pthread_mutex_lock(&q->lock);
	while (q->n == 0 && !q->closed && !q->aborted)
		pthread_cond_wait(&q->can_take, &q->lock);
	if (q->n == 0 || q->aborted) {
		pthread_mutex_unlock(&q->lock);
		return NULL;
	}
	p = q->slot[q->head];
	q->head = (q->head + 1u) % q->cap;
	q->n--;
	pthread_cond_signal(&q->can_put);
	pthread_mutex_unlock(&q->lock);
	return p;
}

/*
 * What a worker sees. Its own walk - so its own path buffer, its own object
 * count and its own scanner - plus the queue and the lock that serialises the
 * callback.
 */
struct worker {
	struct walk       w;
	struct mtq       *q;
	pthread_mutex_t  *cb_lock;
	kof_on_object     cb;
	void             *user;
	pthread_t         id;
};

/*
 * The callback, under the lock.
 *
 * Serialised rather than left to the caller because the alternative is a
 * callback contract that changes with the number of scanners - every existing
 * caller would have to be audited for thread safety before it could ever pass
 * more than one. The lock is held only for the call itself, and a callback that
 * merely counts or prints is nowhere near the cost of the scan that produced it.
 */
static int worker_cb(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct worker *wk = user;
	int rc;

	pthread_mutex_lock(wk->cb_lock);
	rc = wk->cb ? wk->cb(name, bytes, len, res, wk->user) : 0;
	pthread_mutex_unlock(wk->cb_lock);
	if (rc) {
		pthread_mutex_lock(&wk->q->lock);
		wk->q->aborted = 1;
		pthread_cond_broadcast(&wk->q->can_take);
		pthread_cond_broadcast(&wk->q->can_put);
		pthread_mutex_unlock(&wk->q->lock);
	}
	return rc;
}

static void *worker_main(void *arg)
{
	struct worker *wk = arg;
	char *path;

	while ((path = mtq_take(wk->q)) != NULL) {
		scan_file(&wk->w, path);
		free(path);
		if (wk->w.aborted)
			break;
	}
	return NULL;
}

int kof_scan_walk_mt(struct kof_scanner **scs, unsigned n_sc, const char *path,
		     const struct kof_scan_option *opt, kof_on_object cb,
		     void *user)
{
	struct mtq q;
	struct walk prod;
	struct worker *wk = NULL;
	pthread_mutex_t cb_lock;
	struct stat sb;
	uint64_t total = 0;
	unsigned i, started = 0;
	int rc;

	if (!scs || !n_sc || !scs[0] || !path)
		return KOF_ERR_ARG;
	/*
	 * One scanner is the ordinary walk, and taking that path rather than
	 * running a producer and a single worker keeps the common case free of
	 * threads entirely - including the object ORDER, which a caller that
	 * asked for one scanner has every reason to expect unchanged.
	 */
	if (n_sc == 1)
		return kof_scan_walk(scs[0], path, opt, cb, user);

	if ((opt->follow_symlinks ? stat : kof_lstat)(path, &sb) != 0)
		return KOF_ERR_OPEN;
	/* A single file has nothing to spread. */
	if (!S_ISDIR(sb.st_mode))
		return kof_scan_walk(scs[0], path, opt, cb, user);
	if (!opt->recurse_dirs)
		return KOF_ERR_OPEN;

	memset(&q, 0, sizeof q);
	/* Four slots per worker: enough that a worker starting a small file does
	 * not wait on the producer, small enough that the producer cannot run
	 * away from them. */
	q.cap = (size_t)n_sc * 4u;
	q.slot = calloc(q.cap, sizeof *q.slot);
	if (!q.slot)
		return KOF_ERR_READ;   /* no memory for the queue */
	if (pthread_mutex_init(&q.lock, NULL) != 0 ||
	    pthread_cond_init(&q.can_put, NULL) != 0 ||
	    pthread_cond_init(&q.can_take, NULL) != 0 ||
	    pthread_mutex_init(&cb_lock, NULL) != 0) {
		free(q.slot);
		return KOF_ERR_READ;   /* no memory for the queue */
	}

	wk = calloc(n_sc, sizeof *wk);
	if (!wk) {
		free(q.slot);
		return KOF_ERR_READ;   /* no memory for the queue */
	}
	for (i = 0; i < n_sc; i++) {
		wk[i].q        = &q;
		wk[i].cb_lock  = &cb_lock;
		wk[i].cb       = cb;
		wk[i].user     = user;
		wk[i].w.sc     = scs[i] ? scs[i] : scs[0];
		wk[i].w.opt    = opt;
		wk[i].w.cb     = worker_cb;
		wk[i].w.user   = &wk[i];
		if (pthread_create(&wk[i].id, NULL, worker_main, &wk[i]) != 0)
			break;
		started++;
	}

	/*
	 * The producer runs on this thread, and it is the existing walk with the
	 * queue attached: same directory reading, same symlink policy, same depth
	 * limit, same stack. Nothing about finding files is written twice.
	 */
	memset(&prod, 0, sizeof prod);
	prod.sc  = scs[0];
	prod.opt = opt;
	prod.q   = started ? &q : NULL;
	if (!started) {
		/* No thread could be created: scan on this thread rather than
		 * returning nothing, which is the answer a caller can still use. */
		free(wk);
		pthread_mutex_destroy(&q.lock);
		pthread_cond_destroy(&q.can_put);
		pthread_cond_destroy(&q.can_take);
		pthread_mutex_destroy(&cb_lock);
		free(q.slot);
		return kof_scan_walk(scs[0], path, opt, cb, user);
	}

	{
		size_t n = strlen(path);
		while (n > 1 && path[n - 1] == '/')
			n--;
		push_dir(&prod, path, n, 0);
	}
	while (!prod.aborted && !prod.out_of_memory && prod.n > 0) {
		struct pending p = prod.stack[--prod.n];
		read_dir(&prod, p.path, p.depth);
		free(p.path);
	}
	while (prod.n > 0)
		free(prod.stack[--prod.n].path);
	free(prod.stack);
	free(prod.path_buf);

	pthread_mutex_lock(&q.lock);
	q.closed = 1;
	pthread_cond_broadcast(&q.can_take);
	pthread_mutex_unlock(&q.lock);

	for (i = 0; i < started; i++) {
		pthread_join(wk[i].id, NULL);
		total += wk[i].w.objects;
	}

	/* Whatever a stopped run left in the ring. */
	while (q.n > 0) {
		free(q.slot[q.head]);
		q.head = (q.head + 1u) % q.cap;
		q.n--;
	}
	free(q.slot);
	free(wk);
	pthread_mutex_destroy(&q.lock);
	pthread_cond_destroy(&q.can_put);
	pthread_cond_destroy(&q.can_take);
	pthread_mutex_destroy(&cb_lock);

	rc = (int)total;
	return rc;
}

int kof_scan_walk(struct kof_scanner *sc, const char *path,
		  const struct kof_scan_option *opt, kof_on_object cb, void *user)
{
	struct walk w;
	struct stat sb;
	int rc;

	memset(&w, 0, sizeof w);
	w.sc   = sc;
	w.opt  = opt;
	w.cb   = cb;
	w.user = user;

	if ((opt->follow_symlinks ? stat : kof_lstat)(path, &sb) != 0)
		return KOF_ERR_OPEN;

	if (!S_ISDIR(sb.st_mode)) {
		scan_file(&w, path);
		rc = w.objects ? (int)w.objects : KOF_ERR_OPEN;
		free(w.path_buf);
		return rc;
	}

	if (!opt->recurse_dirs)
		return KOF_ERR_OPEN;

	{
		/* A trailing slash would put "//" in every child path. */
		size_t n = strlen(path);
		while (n > 1 && path[n - 1] == '/')
			n--;
		if (!push_dir(&w, path, n, 0))
			goto done;
	}

	/* Depth first, by taking from the end: a directory's children are examined
	 * before its siblings, which keeps the pending set small and the page cache
	 * warm. Breadth first would hold a whole level at once. */
	while (!w.aborted && !w.out_of_memory && w.n > 0) {
		struct pending p = w.stack[--w.n];
		read_dir(&w, p.path, p.depth);
		free(p.path);
	}

done:
	while (w.n > 0)
		free(w.stack[--w.n].path);
	free(w.stack);
	free(w.path_buf);
	/* Running out of heap mid-walk is reported, not fatal: what was scanned before
	 * it is still a result, and the caller can tell the walk was cut short. */
	return (int)w.objects;
}