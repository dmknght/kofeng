/*
 * objctx_diag.c - the pathogen analysis and the symbol block, as a module sees them.
 *
 * WHAT THIS SERVES: the calls a rule makes to ask what a diagnose found (kof_diag,
 * kof_diag_share, kof_diag_str, the graph), the object's symbols (completed from
 * what a serving diagnose resolved), and the routing that decides whether the
 * analysis runs on an object at all (the facts, the gates, the demand).
 *
 * OPEN: "reading is asking" (diag_demand) infers the demand for the analysis
 * from which accessor a rule called. A rule that touches the pathogen surface
 * should declare it (KOF_ENG_USE_PATHOGEN) and the loader refuse one that does
 * not; removing the inference first makes every such rule read an empty analysis
 * (twelve detections, measured). The relocation bias in ref_note is x86's and is
 * applied only to x86 machines.
 */

/* ------------------------------------------------------------ */
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
#include "../analyzers/nucleo/nucleo.h"
#include "../analyzers/normalize/executables.h"
#include "scan.h"
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

#include "objctx_int.h"

static const struct kof_apihash *sc_apihash(struct kof_scanner *sc,
					    const struct kof_obj_ctx *ctx);
static int diag_when_met(const struct kof_obj_ctx *ctx,
			 const struct kof_diag *d);
static void diag_ready(struct kof_scanner *sc, const struct kof_obj_ctx *ctx);

/*
 * READING THE PATHOGEN SURFACE IS ASKING FOR IT. A rule that names a diagnose,
 * asks which two meet, reads a name a diagnose carries, or reaches for the graph
 * is the demand for the analysis, and the engine says so in ONE place. Four
 * accessors each wrote the two stores out themselves, one bug at a time - "twelve
 * detections disappearing the moment the rule stopped naming a diagnose and
 * started reading nodes", "a rule whose only pathogen call was this one read an
 * analysis that never ran" - and each fix added one more copy. `diag_read` is
 * also what labels the finding Pathogen rather than Pattern.
 */
static void diag_demand(struct kof_scanner *sc)
{
	sc->diag_ask = 1;
	sc->diag_read = 1;
}

/*
 * The object's symbol records, built at most once.
 *
 * ELF and PE, each through its own builder - see the note inside. Any other
 * format gets NULL, which a rule reads as "no symbols" and stops on, the same
 * answer a stripped ELF gives. The buffer is the scanner's and outlives the
 * module call; it is NOT rebuilt per ask, so ten rules asking cost one walk.
 */
/*
 * THE PATHOGEN GRAPH A RULE READS - see kofmod/kofpathogen.h.
 *
 * Serialised once per object from the analysis that already ran, and NULL
 * when none did. Reading it cannot make it run: that is what
 * KOF_ENG_USE_PATHOGEN is for, and an object nobody asked about has no graph
 * to hand over.
 */
const uint8_t *oc_graph(const struct kof_obj_ctx *ctx, uint32_t *nbytes)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (nbytes)
		*nbytes = 0;
	if (!sc)
		return NULL;
	/*
	 * READING THE GRAPH IS ASKING FOR IT - the same rule oc_diag follows.
	 * A verdict is an algorithm over the graph, so a rule that reaches
	 * for it is the demand; without this it read the answer of an
	 * analysis that had not happened and got nothing. Measured as twelve
	 * detections disappearing the moment the rule stopped naming a
	 * diagnose and started reading nodes.
	 */
	diag_demand(sc);
	diag_ready(sc, ctx);
	if (!sc->diag_graph)
		return NULL;
	if (!sc->latch[KOF_OL_GRAPH_BLOCK]) {
		sc->latch[KOF_OL_GRAPH_BLOCK] = 1;
		if (!sc->gr)
			sc->gr = malloc(KOF_GR_MAX_BYTES);
		sc->gr_n = sc->gr ? kof_diag_graph_build(sc->diag_graph,
							 sc->gr,
							 KOF_GR_MAX_BYTES)
				  : 0;
	}
	if (!sc->gr_n)
		return NULL;
	if (nbytes)
		*nbytes = sc->gr_n;
	return sc->gr;
}

/*
 * ---- WHAT AN OBJECT'S SYMBOLS ARE COMPLETED FROM -------------------------
 *
 * The symbol block is read out of the object's own tables, and for some
 * objects those tables cannot say what the program uses: a PE that finds its
 * APIs by walking the loader data lists nothing it calls. A diagnose that
 * resolves them DECLARES so - KOF_DIAG_SERVES - and the engine then takes the
 * resolved names as the object's imports: the analysis result REPLACES the
 * table's emptiness in the object description, for everything that reads it.
 *
 * ONE TABLE, so a new kind of resolution is a row and not another branch in
 * oc_syms: the serve bit a diagnose declares, the format it applies to, the
 * analysis product (computed once per object, shared with the graph - the
 * diagnose reads the same result later), and how the product is merged into
 * the block. NORMALISE IS NOT ASKED TO DO THIS ITSELF and cannot skip it: its
 * symbols are this block, so it gets the completed one or, when nothing could
 * be resolved - the usual case - the table's own.
 */
struct sym_serve {
	uint8_t     bit;                /* KOF_SERVE_*                          */
	uint8_t     format;             /* KOF_FMT_* the product is made for    */
	const void *(*product)(struct kof_scanner *, const struct kof_obj_ctx *);
	uint32_t    (*merge)(const void *product, uint8_t *blk, uint32_t n,
			     uint32_t cap);
};

static const void *serve_apihash(struct kof_scanner *sc,
				 const struct kof_obj_ctx *ctx)
{
	return sc_apihash(sc, ctx);
}

static uint32_t merge_apihash(const void *p, uint8_t *blk, uint32_t n,
			      uint32_t cap)
{
	const struct kof_apihash *a = p;

	if (!a || !a->n_call)
		return n;
	if (n < KOF_SYM_HDRLEN)         /* no directory records at all */
		n = kof_pe_syms((kof_buf){ NULL, 0 }, NULL, blk, cap);
	return kof_apihash_syms(a, blk, n, cap);
}

static const struct sym_serve sym_serves[] = {
	{ KOF_SERVE_PE_SYMBOLS, KOF_FMT_PE, serve_apihash, merge_apihash },
};

/*
 * THE SYMBOLS THE ENGINE COMPLETED, for the result. A tool shows what the
 * engine returned and does not rebuild it from the file - and for an object
 * whose table cannot say what it uses, what the engine returned is the
 * completed block. NULL when nothing was added: the object's own table is then
 * the answer and the tool's reading of it is the same one.
 */
const uint8_t *kof_scan_served_syms(const struct kof_obj_ctx *ctx, uint32_t *n)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint32_t nb = 0;

	if (n)
		*n = 0;
	if (!sc || ctx->format != KOF_FMT_PE)
		return NULL;
	(void)oc_syms(ctx, &nb);
	if (!sc->sym_served || !nb)
		return NULL;
	if (n)
		*n = nb;
	return sc->sym;
}

/* Does a diagnose in the database declare this, with its conditions holding
 * for this object. Nothing declared, nothing run. */
static int sc_serves(const struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
		     uint8_t bit)
{
	uint32_t i;

	if (!sc->eng)
		return 0;
	for (i = 0; i < sc->eng->n_diag; i++) {
		const struct kof_diag *d = &sc->eng->diag[i];

		if ((d->serves & bit) && diag_when_met(ctx, d))
			return 1;
	}
	return 0;
}

static void sym_serve(struct kof_scanner *sc, const struct kof_obj_ctx *ctx)
{
	size_t k;

	for (k = 0; k < sizeof sym_serves / sizeof sym_serves[0]; k++) {
		const struct sym_serve *r = &sym_serves[k];

		if (ctx->format != r->format || !sc_serves(sc, ctx, r->bit))
			continue;
		uint32_t before = sc->sym_n;

		sc->sym_n = r->merge(r->product(sc, ctx), sc->sym, sc->sym_n,
				     KOF_SYM_MAX_BYTES);
		if (sc->sym_n != before)
			sc->sym_served = 1;
	}
}

const uint8_t *oc_syms(const struct kof_obj_ctx *ctx, uint32_t *nbytes)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	/*
	 * WHAT THE PRODUCER DECLARED BEATS WHAT THE BYTES WOULD YIELD.
	 *
	 * Only a rendering carries one - see kof_src_declare_syms - and only
	 * because its own headers cannot produce it: they describe the file
	 * before the transform, so building from them reads whatever now lies
	 * at a stale offset and finds nothing. Tested first and not as a
	 * fallback, because "nothing" is exactly what the builder returns for
	 * such an object, and a fallback would never be reached.
	 */
	{
		uint32_t dn = 0;
		const uint8_t *d = kof_src_syms_of(sc->cur_src, &dn);

		if (d && dn) {
			/* A header with no records answers NULL, and the count
			 * goes with it: "nothing here, and here is how much of
			 * it" is a pair no caller should have to reconcile,
			 * and every other exit from this function pairs them. */
			int any = kof_sym_count(d, dn) != 0;

			if (nbytes)
				*nbytes = any ? dn : 0u;
			return any ? d : NULL;
		}
	}

	if (!sc->latch[KOF_OL_SYM]) {
		sc->latch[KOF_OL_SYM] = 1;
		sc->sym_n = 0;
		if (ctx->file_header &&
		    (ctx->format == KOF_FMT_ELF ||
		     ctx->format == KOF_FMT_PE)) {
			if (!sc->sym)
				sc->sym = malloc(KOF_SYM_MAX_BYTES);
			/* Which builder is kof_syms_build's decision, in one
			 * place - see sym_any.c. */
			if (sc->sym)
				sc->sym_n = kof_syms_build(ctx->format,
							   sc->m.data.p,
							   sc->m.data.n,
							   ctx->file_header,
							   sc->sym,
							   KOF_SYM_MAX_BYTES);
			if (sc->sym)
				sym_serve(sc, ctx);
		}
	}
	/* A header with no records is not worth handing back: every reader
	 * would have to test the count anyway, and NULL says it once. */
	if (!kof_sym_count(sc->sym, sc->sym_n)) {
		if (nbytes)
			*nbytes = 0;
		return NULL;
	}
	if (nbytes)
		*nbytes = sc->sym_n;
	return sc->sym;
}


/*
 * DOES THIS OBJECT CARRY THE SIGNS THIS DIAGNOSE ASKED FOR - see
 * struct kof_diag.need.
 *
 * AN ANCHOR, NOT A VERDICT. It decides where to spend the analysis, so a
 * false one costs time and nothing else; demanding that it be clean is
 * asking the cheap test to do the expensive test's job. A diagnose naming
 * no sign is tried wherever its route can run.
 *
 * UNDEFINED SYMBOLS ONLY. A defined one is a name the author chose and can
 * change or strip; an undefined one is resolved by the loader against the
 * kernel's export table by exact name, so it is there or the object does
 * not work.
 */
/*
 * ---- THE FACTS THE ENGINE PUBLISHES ABOUT AN OBJECT ---------------------
 *
 * One question each, answered off the parse, and nothing here knows what
 * any of them is FOR. A diagnose states the condition - see
 * KOF_DIAG_HAS_ATTRB and enum kof_diag_fact - and this only fetches.
 *
 * IT USED TO BE THE OTHER WAY ROUND: a handful of named bits, each one's
 * meaning a few lines of C in this file, and a diagnose could only ask what
 * somebody had already written. One of them, ONE_LOAD, was a compound of
 * three clauses under a single name, so what a diagnose using it actually
 * demanded could not be read off the diagnose - and when one clause turned
 * out to be a build detail rather than a behaviour, nothing in the
 * declaration showed it.
 *
 * A FACT THIS BUILD DOES NOT KNOW ANSWERS NO. The loader refuses a
 * diagnose naming one, so reaching here with an unknown fact means the two
 * ends of the database disagree, and the safe answer to "should the
 * expensive analysis run" is no.
 */
static int fact_holds(const struct kof_obj_ctx *ctx, uint16_t fact,
		      uint64_t want)
{
	const struct kof_elf_info *ei = NULL;
	const struct kof_pe_info *pi = NULL;
	uint32_t i;

	if (!ctx)
		return 0;
	if (ctx->format == KOF_FMT_ELF) {
		ei = kof_elf(ctx);
		if (!ei || !ei->valid)
			return 0;
	} else if (ctx->format == KOF_FMT_PE) {
		pi = kof_pe(ctx);
		if (!pi)
			return 0;
	}

	switch (fact) {
	case KOF_FACT_ENTRY_PERM:
		/*
		 * EACH FORMAT'S OWN WORD FOR IT. The two permission enums
		 * happen to agree bit for bit and that is not something to
		 * rely on - KOF_PERM_X and KOF_PE_PERM_X are declared apart
		 * on purpose.
		 */
		if (ei)
			return ((uint64_t)ei->entry_perm & want) == want;
		if (pi)
			return ((uint64_t)pi->entry_perm & want) == want;
		return 0;               /* no answer is not a yes */
	case KOF_FACT_MAP_PERM:
		if (ei) {
			for (i = 0; i < ei->seg_count &&
				    i < KOF_ELF_MAX_SEGMENTS; i++)
				if (ei->seg[i].type == 1u &&      /* PT_LOAD */
				    ((uint64_t)ei->seg[i].perm & want) == want)
					return 1;
			return 0;
		}
		if (pi) {
			/* A section, which is where PE declares the same
			 * thing about a mapping. */
			for (i = 0; i < pi->sec_count; i++)
				if (((uint64_t)pi->sec[i].perm & want) == want)
					return 1;
			return 0;
		}
		return 0;
	case KOF_FACT_SECTIONS:
		if (ei)
			return (uint64_t)ei->shnum == want;
		if (pi)
			return (uint64_t)pi->sec_count == want;
		return 0;
	case KOF_FACT_OBJ_KIND:
		if (ei)
			return (uint64_t)ei->e_type == want;
		return 0;
	case KOF_FACT_FORMAT:
		return (uint64_t)ctx->format == want;
	case KOF_FACT_INTERP:
		/* PT_INTERP, from the program headers - the loader's own test for
		 * "this needs a dynamic linker". Only an ELF has the question. */
		if (!ei)
			return 0;
		for (i = 0; i < ei->seg_count && i < KOF_ELF_MAX_SEGMENTS; i++)
			if (ei->seg[i].type == 3u)
				return want == 1u;
		return want == 0u;
	default:
		return 0;
	}
}

/* Every condition a diagnose stated - see KOF_DIAG_HAS_ATTRB. */
static int diag_when_met(const struct kof_obj_ctx *ctx,
			 const struct kof_diag *d)
{
	uint8_t i;

	for (i = 0; i < d->n_when; i++)
		if (!fact_holds(ctx, d->when[i].fact, d->when[i].val))
			return 0;
	return 1;
}

static int diag_gate_open(struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
			  uint32_t i);

/* Does a VERDICT read this diagnose. Only a verdict ASKS: asking means the
 * object is worth the analysis and worth interpreting. Unknown counts as yes. */
static int diag_read_by_verdict(const struct kof_diag *d)
{
	return !d->users_known || d->n_users != 0u;
}

/* Is it RUN: read by a verdict, or serving the engine itself - see
 * KOF_DIAG_SERVES, which no verdict has to name. */
static int diag_used(const struct kof_diag *d)
{
	return diag_read_by_verdict(d) || d->serves != 0u;
}

int kof_scan_diag_sign_asks(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint32_t i;

	if (!sc || !sc->eng)
		return 0;
	for (i = 0; i < sc->eng->n_diag; i++) {
		const struct kof_diag *d = &sc->eng->diag[i];

		/*
		 * A SIGN IS WHAT MAKES AN OBJECT WORTH ANALYSING; a condition
		 * that only says where the route can run is not one. KOF_FACT_INTERP
		 * is of the second kind: a static ELF is not a reason to look, it is
		 * the only place the system call sweep has anything to find. Counting
		 * it as a sign made every static ELF ask - and a toolchain's ordinary
		 * R|X binary then started the analysis.
		 */
		{
			uint32_t signs = d->n_needcap;
			uint8_t w;

			for (w = 0; w < d->n_when; w++)
				if (d->when[w].fact != KOF_FACT_INTERP)
					signs++;
			if (!signs)
				continue;
		}
		/*
		 * A DIAGNOSE NO VERDICT READS DOES NOT ASK. Asking means "this
		 * object is worth the analysis AND worth interpreting" - see the
		 * caller - and a diagnose that exists to SERVE the engine
		 * (KOF_DIAG_SERVES) is answered by the step it serves, not by
		 * emulating every object its conditions admit. MEASURED when it
		 * did: the PE diagnose, whose only condition is the format, put the
		 * whole PE corpus through the emulating unpackers - 10.9 s to 26.6 s,
		 * and two .NET assemblies reported damaged by an unpacker that had
		 * no business running on them.
		 */
		if (!diag_read_by_verdict(d))
			continue;
		if (diag_gate_open(sc, ctx, i))
			return 1;
	}
	return 0;
}

/* Does any verdict read this diagnose. Unknown counts as yes - see
 * KDIG_SEC_USERS. */

/*
 * ---- DOES THE CODE REFER INTO THIS SYMBOL - see KOF_DIAG_DECLARE_SYMBOL ---------------
 *
 * ONE QUESTION, answered for every diagnose that declared one in a single
 * walk of the object's code relocations. The engine does not know which
 * symbols matter: the diagnoses name them, and this only says whether an
 * instruction's operand is a relocation against that name at an offset other
 * than zero.
 *
 * THE OFFSET IS THE ADDEND, CORRECTED FOR HOW IT IS ENCODED. An absolute
 * relocation carries the offset as it is. A PC-relative one carries it minus
 * four, because the CPU adds the displacement to the address of the NEXT
 * instruction - so `lea rdi, [rip + sym]` is `sym - 4`, an addend of -4 for
 * what is plainly offset zero. Reading the raw addend would call every such
 * handle a field. Four is added back for the two PC-relative types. A trailing
 * immediate shifts it further and a relocation does not say by how much; that
 * only ever LOWERS the estimate, so it can miss a field at a tiny offset and
 * never invents one.
 *
 * MEASURED on 900 clean kernel modules for __this_module: 853 references to
 * the handle, all of them absolute at addend zero, and one module reaching a
 * field - its own name. Both Diamorphine builds and both hcrootkit builds
 * reach several.
 */
#define KOF_RELOC_PC32  2u
#define KOF_RELOC_PLT32 4u

struct refscan {
	const struct kof_scanner *sc;
	const uint8_t *file;
	uint64_t       size;
	uint32_t       n;                   /* diagnoses considered */
	uint8_t       *rleft;               /* refs still unmet, per diagnose */
	uint8_t      (*rhit)[KOF_DIAG_MAX_NEED];
	uint32_t       pending;             /* diagnoses with refs unmet */
	int            x86;                 /* the relocation types below are this machine's */
};

/* The name at a file offset equals `want`, without reading past the object. */
static int name_is(const struct refscan *rs, uint64_t off, const char *want)
{
	size_t L = strlen(want);

	if (off >= rs->size || rs->size - off < L + 1u)
		return 0;
	return memcmp(rs->file + off, want, L + 1u) == 0;
}

/*
 * What the PE resolves for itself, built the first time anything asks and kept
 * until the object is done with - see kof_scanner.apihash. NULL for anything
 * that is not a PE, and for a PE the analysis could not run on.
 */
static const struct kof_apihash *sc_apihash(struct kof_scanner *sc,
					    const struct kof_obj_ctx *ctx)
{
	if (!sc->latch[KOF_OL_APIHASH]) {
		kof_buf b = oc_mc(ctx)->data;

		sc->latch[KOF_OL_APIHASH] = 1;
		if (ctx->format == KOF_FMT_PE && b.p && b.n)
			sc->apihash = kof_apihash_run(ctx, b.p, b.n);
	}
	return sc->apihash;
}

/*
 * The object's relocation table, built the first time anything asks and kept
 * until the object is done with - see kof_scanner.relocs. NULL for an object
 * that is not a relocatable ELF, which the callers read as "no relocations".
 */
static const struct kof_elf_relocs *sc_relocs(struct kof_scanner *sc,
					      const struct kof_obj_ctx *ctx)
{
	if (!sc->latch[KOF_OL_RELOCS]) {
		const struct kof_elf_info *ei = ctx->format == KOF_FMT_ELF
						? kof_elf(ctx) : NULL;
		kof_buf b = oc_mc(ctx)->data;

		sc->latch[KOF_OL_RELOCS] = 1;
		if (ei && ei->valid && b.p) {
			sc->relocs = calloc(1, sizeof *sc->relocs);
			if (sc->relocs)
				(void)kof_elf_reloc_table(b, ei, KOF_ELF_RELOC_CODE,
						  sc->relocs);
		}
	}
	return sc->relocs;
}

static void ref_note(struct refscan *rs, const struct kof_elf_reloc *r)
{
	int64_t eff;
	uint32_t i;

	/*
	 * THE TYPE NUMBERS AND THE +4 ARE x86's AND x86-64'S: R_X86_64_PC32 and
	 * R_386_PC32 are 2, PLT32 is 4, and the CPU adds the displacement to the
	 * address of the NEXT instruction, so the addend of a handle is -4. On any
	 * other machine those numbers mean other relocations and the correction
	 * would turn an ordinary reference into a "field" - so for them there is no
	 * claim to make, and a diagnose demanding one is not answered yes.
	 */
	if (!rs->x86)
		return;
	eff = r->addend + ((r->type == KOF_RELOC_PC32 ||
			    r->type == KOF_RELOC_PLT32) ? 4 : 0);
	/* an instruction's operand, with a name, reaching into the symbol */
	if (!r->code || !r->nameoff || eff <= 0)
		return;
	for (i = 0; i < rs->n; i++) {
		const struct kof_diag *d = &rs->sc->eng->diag[i];
		uint8_t k;

		if (!rs->rleft[i])
			continue;
		for (k = 0; k < d->n_ref; k++)
			if (!rs->rhit[i][k] &&
			    name_is(rs, r->nameoff, d->ref[k])) {
				rs->rhit[i][k] = 1;
				if (!--rs->rleft[i])
					rs->pending--;
				break;
			}
	}
}

/*
 * WHICH DIAGNOSES THIS OBJECT PASSES THE GATE OF - all of them, in one walk.
 *
 * A gate is two kinds of sign. What the file IS (KOF_DIAG_HAS_ATTRB) is a few
 * header fields the parser has already read. What it IMPORTS (the sequence a diagnose declares, or its head and tails)
 * is in the symbol table, and that is the part that cost something: it used
 * to be answered diagnose by diagnose, each one a pass over the whole table,
 * and asked twice - once to decide whether to start the analysis and once to
 * decide which routes it needed. The question has one answer per object, so
 * it is worked out once, the table is walked once, and every diagnose's
 * unmet signs are ticked off in that single pass.
 *
 * A DIAGNOSE WITH NO SIGN PASSES. It makes no claim about which files suit
 * it, so nothing excludes it - see kof_scan_diag_sign_asks for why that does
 * not also make it a reason to START the analysis.
 */
static void diag_gates(struct kof_scanner *sc, const struct kof_obj_ctx *ctx)
{
	uint8_t unmet[KOF_DB_MAX_DIAG], ok[KOF_DB_MAX_DIAG];
	uint8_t rleft[KOF_DB_MAX_DIAG];
	uint8_t hit[KOF_DB_MAX_DIAG][KOF_DIAG_MAX_NEED];
	uint8_t rhit[KOF_DB_MAX_DIAG][KOF_DIAG_MAX_NEED];
	uint32_t n, i, pending = 0, rpending = 0, sn = 0, total, r;
	const uint8_t *sb;

	if (sc->latch[KOF_OL_DIAG_GATE])
		return;
	sc->latch[KOF_OL_DIAG_GATE] = 1;
	memset(sc->diag_gate, 0, sizeof sc->diag_gate);
	memset(unmet, 0, sizeof unmet);
	memset(ok, 0, sizeof ok);
	memset(rleft, 0, sizeof rleft);
	n = sc->eng ? sc->eng->n_diag : 0u;
	if (n > sizeof sc->diag_gate * 8u)
		n = (uint32_t)(sizeof sc->diag_gate * 8u);

	/* ---- STAGE ONE: what the file is, and what it imports ----------- */
	for (i = 0; i < n; i++) {
		const struct kof_diag *d = &sc->eng->diag[i];

		/*
		 * A DIAGNOSE NO VERDICT READS IS NOT RUN - see KDIG_SEC_USERS.
		 *
		 * Decided before anything about the object is asked, because it
		 * is the cheapest test there is and the one that matters most:
		 * an unread diagnose that passes its gate starts the analysis
		 * for an answer nobody collects. Only a count the build wrote
		 * as ZERO closes it; a diagnose whose users were never written
		 * down is unknown and keeps running.
		 */
		if (!diag_used(d))
			continue;
		if (!diag_when_met(ctx, d))
			continue;               /* the file is not the shape */
		if (!d->n_needcap) {
			ok[i] = 1;
			continue;
		}
		unmet[i] = d->n_needcap;
		memset(hit[i], 0, sizeof hit[i]);
		pending++;
	}
	if (pending) {
		sb = oc_syms(ctx, &sn);
		total = kof_sym_count(sb, sn);
		for (r = 0; r < total && pending; r++) {
			const uint8_t *rec = kof_sym_rec(sb, sn, r);
			uint16_t cap;

			if (!rec || !(rec[KOF_SYM_R_FLAGS] & KOF_SYM_F_UNDEFINED))
				continue;
			/* WHICH CAPABILITY THIS IMPORT IS, said once by nucleo's one
			 * name table - a diagnose names the capability, never the
			 * spelling. */
			cap = kof_flow_cap_of_name((const char *)(rec + KOF_SYM_R_NAME));
			if (cap == KOF_NUCLEO_NONE)
				continue;
			for (i = 0; i < n; i++) {
				const struct kof_diag *d = &sc->eng->diag[i];
				uint8_t k;

				if (!unmet[i])
					continue;
				for (k = 0; k < d->n_needcap; k++)
					if (!hit[i][k] &&
					    (d->needcap[k] == cap ||
					     d->needcap[k] == kof_flow_cap_generic(cap))) {
						/* each sign counts once,
						 * however many records spell
						 * it */
						hit[i][k] = 1;
						if (!--unmet[i]) {
							ok[i] = 1;
							pending--;
						}
						break;
					}
			}
		}
	}

	/*
	 * ---- STAGE TWO: what its code refers into -----------------------
	 *
	 * ONLY FOR A DIAGNOSE THAT GOT THIS FAR. The relocation table is read
	 * after the cheaper signs have already ruled most objects out, and
	 * not at all when nothing declared a reference - which is why this is
	 * a second stage and not folded into the first.
	 */
	for (i = 0; i < n; i++) {
		const struct kof_diag *d = &sc->eng->diag[i];

		if (!ok[i] || !d->n_ref)
			continue;
		rleft[i] = d->n_ref;
		memset(rhit[i], 0, sizeof rhit[i]);
		rpending++;
	}
	if (rpending) {
		const struct kof_elf_relocs *t = sc_relocs(sc, ctx);
		kof_buf b = oc_mc(ctx)->data;
		struct refscan rs;
		uint32_t q;

		rs.sc = sc;
		rs.file = b.p;
		rs.size = b.n;
		rs.n = n;
		rs.rleft = rleft;
		rs.rhit = rhit;
		rs.pending = rpending;
		rs.x86 = ctx->arch == KOF_ARCH_X86 || ctx->arch == KOF_ARCH_X86_64;
		/* A format with no relocation table cannot satisfy a diagnose that
		 * demands one: no answer is not a yes. Stops once nothing is left to
		 * find, which is a saving on the READ and not a bound on the table. */
		for (q = 0; t && q < t->n && rs.pending; q++)
			ref_note(&rs, &t->v[q]);
	}

	for (i = 0; i < n; i++)
		if (ok[i] && !rleft[i])
			sc->diag_gate[i >> 3] |= (uint8_t)(1u << (i & 7u));
}

/* Does diagnose `i` pass this object's gate. */
static int diag_gate_open(struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
			  uint32_t i)
{
	diag_gates(sc, ctx);
	return i < sizeof sc->diag_gate * 8u &&
	       ((sc->diag_gate[i >> 3] >> (i & 7u)) & 1u);
}

static void diag_ready(struct kof_scanner *sc, const struct kof_obj_ctx *ctx)
{
	struct kof_diag_scan *ds;
	kof_buf b;
	uint32_t i;

	if (sc->latch[KOF_OL_DIAG])
		return;
	/*
	 * NOBODY ASKED, SO NOBODY PAYS - see KOF_ENG_USE_PATHOGEN. The sweep
	 * is proportional to the object and this is the one place that can
	 * decline it; a rule that recognised something turns it on for the
	 * object it fired on, and a tool reporting rather than scanning turns
	 * it on through kof_scan_diag_force.
	 *
	 * THE LATCH IS NOT TAKEN ON A REFUSAL. It marks work that was DONE,
	 * and taking it here would mean the first question asked before
	 * anything asked for the analysis settles the object for good - a
	 * tool that then turns the analysis on through want_diag is refused
	 * by a latch recording that nobody had asked yet. Measured: the
	 * database test lost rwx_exec exactly that way.
	 *
	 * Re-deciding costs one test of a flag, which is less than the memset
	 * the refusal would otherwise do.
	 */
	if (!sc->diag_ask)
		return;
	sc->latch[KOF_OL_DIAG] = 1;
	memset(sc->diag_hit, 0, sizeof sc->diag_hit);
	if (!sc->eng || !sc->eng->n_diag)
		return;
	b = oc_mc(ctx)->data;
	if (!b.p || !b.n)
		return;
	/*
	 * ---- ONLY THE ROUTES THE LOADED DIAGNOSES ASK FOR ----------------
	 *
	 * KOF_DIAG_ANALYSIS was being parsed, stored and never read: every scan ran
	 * every route whatever the database wanted. A diagnose about raw
	 * shellcode has no imports to read and one about LoadLibrary has no
	 * syscall to find, so the other route is work with nowhere to put its
	 * answer.
	 *
	 * THE UNION, because the database decides together. One diagnose
	 * asking for the symbol route is enough reason to run it; no diagnose
	 * asking is the only reason not to.
	 */
	{
		unsigned run = 0;
		struct kof_diag_seq seqv[KOF_DB_MAX_DIAG];
		uint32_t n_seq = 0;

		for (i = 0; i < sc->eng->n_diag; i++) {
			/* a diagnose whose signs are absent asks for no
			 * route - see diag_gates */
			if (!diag_gate_open(sc, ctx, i))
				continue;
			/* A head built from two calls is built for the diagnose
			 * that declared it, and for it alone. */
			if (sc->eng->diag[i].seq_first && n_seq < KOF_DB_MAX_DIAG) {
				seqv[n_seq].made = sc->eng->diag[i].node[0].cap;
				seqv[n_seq].first = sc->eng->diag[i].seq_first;
				seqv[n_seq].then = sc->eng->diag[i].seq_then;
				n_seq++;
			}
			if (sc->eng->diag[i].via & KOF_DIAG_ANALYSIS_SYSCALL)
				run |= KOF_DIAG_RUN_SYSCALL;
			if (sc->eng->diag[i].via & KOF_DIAG_ANALYSIS_SYMBOL)
				run |= KOF_DIAG_RUN_SYMBOL;
			if (sc->eng->diag[i].via & KOF_DIAG_ANALYSIS_EMULATE)
				run |= KOF_DIAG_RUN_EMULATE;
			if (sc->eng->diag[i].via & KOF_DIAG_ANALYSIS_APIHASH)
				run |= KOF_DIAG_RUN_APIHASH;
		}
		if (!run)
			return;
		/*
		 * NOTHING NARROWS WHICH CAPABILITIES ARE RECORDED, and a loop
		 * that built such a set per object was removed with the
		 * parameter that ignored it - see kof_diag_scan_with. The set
		 * cannot be derived: a verdict reads nodes no diagnose names.
		 */
		struct kof_diag_inputs in;

		in.relocs = sc_relocs(sc, ctx);
		in.seq = seqv;
		in.n_seq = n_seq;
		/* The analysis result, from the latch: the normaliser may have
		 * asked already, and whichever asks first pays once. Only
		 * computed here when the database wants the route. */
		in.apihash = (run & KOF_DIAG_RUN_APIHASH)
			     ? sc_apihash(sc, ctx) : NULL;
		ds = kof_diag_scan_with_inputs(ctx, b.p, b.n, run, &in);
	}
	if (!ds)
		return;
	KOF_TIME_BEGIN(KOF_T_DIAG_MATCH);
	memset(sc->diag_n_bind, 0, sizeof sc->diag_n_bind);
	for (i = 0; i < sc->eng->n_diag && i < sizeof sc->diag_hit * 8u; i++) {
		uint8_t nb = 0;

		/* An unread diagnose is not matched: nobody collects the answer,
		 * and the shared graph is still there for the ones that are. */
		if (!diag_used(&sc->eng->diag[i]))
			continue;
		/* every node it bound comes back - see kof_scanner.diag_bind */
		if (kof_diag_match(ds, &sc->eng->diag[i],
				   sc->diag_bind[i], &nb)) {
			sc->diag_hit[i >> 3] |= (uint8_t)(1u << (i & 7u));
			sc->diag_n_bind[i] = nb > KOF_DB_MAX_DIAG_NODE
					   ? (uint8_t)KOF_DB_MAX_DIAG_NODE : nb;
		}
	}
	KOF_TIME_END(KOF_T_DIAG_MATCH);
	/*
	 * AND THE GRAPH STAYS - see kof_scanner.diag_graph. It is what the
	 * verdict layer reads; freeing it here would make every reader pay
	 * for the analysis again.
	 */
	sc->diag_graph = ds;
}

/*
 * ASK FOR ALL OF THEM, for a caller that is reporting rather than scanning
 * - see kof_scan_option.want_diag. Same work the first rule to ask would
 * have paid for, done once and at a moment the caller chose.
 */
void kof_scan_diag_force(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc)
		return;
	/* The caller IS the asker here - see KOF_ENG_USE_PATHOGEN. Setting it
	 * rather than bypassing the test keeps one gate on this work. */
	sc->diag_ask = 1;
	diag_ready(sc, ctx);
}

/*
 * DO TWO DIAGNOSES MEET AT A NODE OF THIS CAPABILITY - see kof_diag_share.
 *
 * THE CAPABILITY IS PART OF THE QUESTION and not a filter bolted on. "The
 * stager's read and the socket's read are the same read" is the claim; "the
 * two have some node in common" is a weaker one that a shared allocation or
 * a shared resolve would also satisfy, and those are what a packed binary is
 * full of. Naming the node makes the verdict say which shape it means, and
 * it is the reason a diagnose no longer declares its own join points: the
 * pair is known at the verdict, never at the declaration.
 */
int oc_diag_share(const struct kof_obj_ctx *ctx, uint16_t cap,
			uint16_t a, uint16_t b)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint32_t ia, ib, i;

	if (!sc || !cap || !a || !b)
		return 0;
	/* ASKING IS THE DEMAND, exactly as in oc_diag - this is the same
	 * question about two diagnoses, and it used to call diag_ready
	 * without setting the flag it is gated on, so a rule whose ONLY
	 * pathogen call was this one read an analysis that never ran. */
	diag_demand(sc);
	diag_ready(sc, ctx);
	ia = ib = sc->eng->n_diag;
	for (i = 0; i < sc->eng->n_diag && i < sizeof sc->diag_hit * 8u; i++) {
		if (sc->eng->diag[i].id == a)
			ia = i;
		if (sc->eng->diag[i].id == b)
			ib = i;
	}
	if (ia >= sc->eng->n_diag || ib >= sc->eng->n_diag)
		return 0;
	if (!((sc->diag_hit[ia >> 3] >> (ia & 7u)) & 1u) ||
	    !((sc->diag_hit[ib >> 3] >> (ib & 7u)) & 1u))
		return 0;
	/*
	 * REACHABILITY, not a shared node - see kof_diag_flow_join. The byte
	 * a socket read produced (a node of `cap` that NETRECV `b` bound)
	 * must flow into the region MEMEXEC `a` is about, and a scratch
	 * buffer between the read and the region is links in the middle that
	 * still link, not a break. The old test here asked only whether one
	 * node was bound by both, which a scratch buffer steps around.
	 */
	return kof_diag_flow_join(sc->diag_graph, cap,
				  sc->diag_bind[ia], sc->diag_n_bind[ia],
				  sc->diag_bind[ib], sc->diag_n_bind[ib]);
}

/*
 * DOES THIS DIAGNOSE MATCH, AND DOES IT CARRY THESE NAMES - see
 * kof_diag_str_any and _all in kofsig.h for what the answer means, and why false is
 * not the same as "no".
 *
 * A diagnose's names are the ones the analysis read at the call sites its
 * tree BOUND: each name is kept with the node of the call it was handed to,
 * and the diagnose is the thing that says which of those calls it is about.
 *
 * ASKING IS THE DEMAND, as in every other call that reads the analysis, and
 * it is also what labels the finding Pathogen, so the flag is set here.
 */
int oc_diag_str(const struct kof_obj_ctx *ctx, uint16_t id,
			   const char *name)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const struct kof_diag *d = NULL;
	uint32_t i;

	if (!sc || !sc->eng || !id || !name)
		return 0;
	diag_demand(sc);
	diag_ready(sc, ctx);
	for (i = 0; i < sc->eng->n_diag && i < sizeof sc->diag_hit * 8u; i++)
		if (sc->eng->diag[i].id == id)
			break;
	if (i >= sc->eng->n_diag || i >= sizeof sc->diag_hit * 8u)
		return 0;
	/* The diagnose has to have matched: a name beside a behaviour that did
	 * not happen is not evidence of it. */
	if (!((sc->diag_hit[i >> 3] >> (i & 7u)) & 1u) || !sc->diag_graph)
		return 0;
	d = &sc->eng->diag[i];
	/*
	 * THE NAMES THIS DIAGNOSE CARRIES are the ones read at the call sites
	 * its tree bound - see kof_diag_scan_name - and not the ones handed to
	 * any call of the same capability. It used to be the second: a
	 * diagnose's names were those tagged with a capability one of its
	 * nodes named, so two diagnoses with a node of the same capability
	 * saw each other's.
	 */
	return kof_diag_scan_name(sc->diag_graph, d, name);
}

int oc_diag(const struct kof_obj_ctx *ctx, uint16_t id)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint32_t i;

	/* Ids are one based, because zero is what an uninitialised field
	 * holds and a rule that asked for diagnose zero by accident would
	 * otherwise be asking a real question. */
	if (!sc || !id)
		return 0;
	/*
	 * THE RULE ASKING IS THE ASKER - see KOF_ENG_USE_PATHOGEN.
	 *
	 * A signature runs before any heuristic does, so a rule reading a
	 * diagnose cannot wait for one to turn the analysis on: it would
	 * read the answer of an analysis that has not happened and get no.
	 * Naming a diagnose in a rule IS the demand, and it is as scoped as
	 * the rule - a rule targeting ELF asks on ELF and nowhere else.
	 */
	diag_demand(sc);
	diag_ready(sc, ctx);
	/* The id is the name's hash now, not a position - see KOF_DIAG_ID.
	 * The bit is still the diagnose's slot, which is its position. */
	for (i = 0; i < sc->eng->n_diag && i < sizeof sc->diag_hit * 8u; i++)
		if (sc->eng->diag[i].id == id)
			return (sc->diag_hit[i >> 3] >> (i & 7u)) & 1u;
	return 0;
}

