/*
 * objctx_diag.c - the diagnose analysis and the symbol block, as a module sees them.
 *
 * WHAT THIS SERVES: the calls a rule makes to ask what a diagnose found (kof_diag,
 * kof_diag_share, kgenome_diag_str, the graph), the object's symbols (completed from
 * what a serving diagnose resolved), and the routing that decides whether the
 * analysis runs on an object at all (the facts, the gates, the demand).
 *
 * OPEN: "reading is asking" (oc_diag_demand) infers the demand for the analysis
 * from which accessor a rule called. A rule that touches the diagnose surface
 * should declare it (KOF_ENG_USE_DIAGNOSE) and the loader refuse one that does
 * not; removing the inference first makes every such rule read an empty analysis
 * (twelve detections, measured). The relocation bias in ref_note is x86's and is
 * applied only to x86 machines.
 */

/* ------------------------------------------------------------ */
#define _GNU_SOURCE

#include "../kofcore/kofdebug.h"   /* kof_write_all - the spill file below */
#include "../analyzers/parsers/binaries/pe/pe_sym.h"
#include <celllysis/nucleo.h>
#include <kofmod/elf.h>
#include <kofmod/pe.h>

/* The script folding pass and the lexical table it is driven from - see
 * kof_scan_script_forms below. */
/*
 * The one format header the scan path includes, and it is not a shortcut.
 *
 * BCJ2 is not a coding that happens to appear in 7z - it IS a 7z folder shape.
 * Which packed stream carries the code, which carries the call targets, which the
 * jump targets, and which the range coder is stated by the folder's bind pairs and
 * nowhere else. A general "multi stream coding" hook in the module ABI would be an
 * abstraction with exactly one user, invented to avoid naming the thing it is for.
 */

#include "../detectors/linkage/kofdiag.h"

#include "objctx_int.h"
#include "../analyzers/genome_obj.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const struct kgenome_diag_apihash_set *sc_apihash(struct kof_scanner *sc,
					    const struct kof_obj_ctx *ctx);
static int diag_when_met(const struct kof_obj_ctx *ctx,
			 const struct kof_diag *d);

/*
 * READING THE DIAGNOSE SURFACE IS ASKING FOR IT. A rule that names a diagnose,
 * asks which two meet, reads a name a diagnose carries, or reaches for the graph
 * is the demand for the analysis, and the engine says so in ONE place. Four
 * accessors each wrote the two stores out themselves, one bug at a time - "twelve
 * detections disappearing the moment the rule stopped naming a diagnose and
 * started reading nodes", "a rule whose only diagnose call was this one read an
 * analysis that never ran" - and each fix added one more copy. `diag_read` is
 * also what labels the finding Diagnose rather than Pattern.
 */
void oc_diag_demand(struct kof_scanner *sc)
{
	sc->obj.diag.ask = 1;
	sc->mod.diag_read = 1;
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
 * THE DIAGNOSE GRAPH A RULE READS - see kofmod/kofdiagtree.h.
 *
 * Serialised once per object from the analysis that already ran, and NULL
 * when none did. Reading it cannot make it run: that is what
 * KOF_ENG_USE_DIAGNOSE is for, and an object nobody asked about has no graph
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
	oc_diag_demand(sc);
	oc_diag_ready(sc, ctx);
	if (!sc->obj.diag.graph)
		return NULL;
	if (!sc->obj.latch[KOF_OL_GRAPH_BLOCK]) {
		sc->obj.latch[KOF_OL_GRAPH_BLOCK] = 1;
		/*
		 * SIZED BY THE GRAPH, not by a constant: the block is a header and one
		 * record per node, and the node count is the scan's (it scales with
		 * the object's code - kgenome_budget.max_nodes), so a fixed block of
		 * 4096 records would have refused every graph past it whole. It is
		 * allocated once per object, here, after the scan that produced it.
		 */
		if (!sc->diag.gr) {
			uint32_t nn = kgenome_diag_scan_count(sc->obj.diag.graph);

			sc->diag.gr_cap = KOF_GR_HDRLEN + nn * KOF_GR_RECLEN;
			sc->diag.gr = nn ? malloc(sc->diag.gr_cap) : NULL;
		}
		sc->obj.diag.gr_n = sc->diag.gr ? kof_diag_graph_build(sc->obj.diag.graph,
							 sc->diag.gr,
							 sc->diag.gr_cap)
				  : 0;
	}
	if (!sc->obj.diag.gr_n)
		return NULL;
	if (nbytes)
		*nbytes = sc->obj.diag.gr_n;
	return sc->diag.gr;
}

/*
 * ---- WHAT A MODULE REPORTED IS MERGED WHEN THE BLOCK IS BUILT ------------
 *
 * The symbol block is read out of the object's own tables, and for some
 * objects those tables cannot say what the program uses: a PE that finds its
 * APIs by walking the loader data lists nothing it calls. Recovering them is
 * the same kind of work as recovering any other thing a program hides from a
 * static reader, so it is a decrypt module's job - it asks the engine for the
 * APIs the program resolves (oc_api_resolved) and reports them (oc_sym_import).
 * A diagnose reads what the object does; it does not complete the description
 * of the object.
 *
 * ONE MERGE PATH. The block is completed here and nowhere else: a report
 * arriving after the block was built is appended to it in place by the same
 * function (oc_sym_import). kof_apihash_syms, which spelled the same merge for
 * a test, is gone.
 *
 * THE REPORT REPLACES THE TABLE'S EMPTINESS in the object description, for
 * everything that reads it. NORMALISE IS NOT ASKED TO DO THIS ITSELF and
 * cannot skip it: its symbols are this block, so it gets the completed one or,
 * when nothing was reported - the usual case - the table's own.
 */
static void sym_declared(struct kof_scanner *sc, uint32_t from)
{
	const char **dll, **name;
	uint32_t i, n = sc->obj.sym.n_decl - from, before = sc->obj.sym.n;

	if (sc->obj.sym.n_decl <= from)
		return;
	dll = malloc((size_t)n * sizeof *dll);
	name = malloc((size_t)n * sizeof *name);
	if (!dll || !name) {
		free(dll);
		free(name);
		return;
	}
	for (i = 0; i < n; i++) {
		dll[i] = sc->syms.decl[from + i].dll;
		name[i] = sc->syms.decl[from + i].fn;
	}
	if (sc->obj.sym.n < KOF_SYM_HDRLEN)         /* no directory records at all */
		sc->obj.sym.n = kof_pe_syms((kof_buf){ NULL, 0 }, NULL, sc->syms.buf,
					sc->syms.cap);
	/* Room for what is added first, so the records already there are never at
	 * risk: a block that cannot hold the addition is left as it was, with its
	 * truncated byte set (kof_pe_syms_add_imports). The bound is the block's. */
	{
		uint64_t need = (uint64_t)sc->obj.sym.n + kof_pe_syms_add_room(dll, name, n);

		if (need > KOF_SYM_ABS_MAX_BYTES)
			need = KOF_SYM_ABS_MAX_BYTES;
		if (sc->syms.buf && sc->syms.cap < need) {
			uint8_t *g = realloc(sc->syms.buf, (size_t)need);

			if (g) {
				sc->syms.buf = g;
				sc->syms.cap = (uint32_t)need;
			}
		}
	}
	sc->obj.sym.n = kof_pe_syms_add_imports(sc->syms.buf, sc->obj.sym.n,
					    sc->syms.cap, dll, name,
					    n);
	/* The list the module reported may be short, and the block's own byte
	 * says so: the run it came from was stopped while still going. */
	if (sc->obj.diag.apihash && sc->obj.diag.apihash->status != KGENOME_OK && sc->obj.sym.n >= KOF_SYM_HDRLEN)
		sc->syms.buf[KOF_SYM_H_TRUNC] = 1;
	if (sc->obj.sym.n != before)
		sc->obj.sym.served = 1;
	free(dll);
	free(name);
}

/* The i-th distinct API this PE resolves for itself - see api_resolved in
 * struct kof_content. */
uint32_t oc_api_resolved(const struct kof_obj_ctx *ctx, uint32_t i,
			 char *dll, uint32_t dll_cap, char *fn,
			 uint32_t fn_cap)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const struct kgenome_diag_apihash_set *a;
	const char **d, **nm;
	uint32_t n;

	if (!sc || !dll || !fn || !dll_cap || !fn_cap)
		return 0;
	a = sc_apihash(sc, ctx);
	if (!a || !a->n_call)
		return 0;
	d = malloc((size_t)a->n_call * sizeof *d);
	nm = malloc((size_t)a->n_call * sizeof *nm);
	if (!d || !nm) {
		free(d);
		free(nm);
		return 0;
	}
	n = kgenome_diag_apihash_distinct(a, d, nm);
	if (i < n) {
		snprintf(dll, dll_cap, "%s", d[i]);
		snprintf(fn, fn_cap, "%s", nm[i]);
	}
	free(d);
	free(nm);
	return i < n;
}

/* Report one import of this object - see sym_import in struct kof_content.
 * The block is rebuilt on its next read so the report is in it. */
uint32_t oc_sym_import(const struct kof_obj_ctx *ctx, const char *dll,
		       const char *fn)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_sym_decl *d;
	uint32_t i;

	if (!sc || !dll || !fn || !dll[0] || !fn[0] || ctx->format != KOF_FMT_PE)
		return 0;
	for (i = 0; i < sc->obj.sym.n_decl; i++)
		if (!strcmp(sc->syms.decl[i].dll, dll) &&
		    !strcmp(sc->syms.decl[i].fn, fn))
			return 1;               /* kept once */
	if (sc->obj.sym.n_decl == sc->syms.cap_decl) {
		uint32_t nc = sc->syms.cap_decl ? sc->syms.cap_decl * 2u : 32u;
		struct kof_sym_decl *nv = realloc(sc->syms.decl, (size_t)nc * sizeof *nv);

		if (!nv)
			return 0;
		sc->syms.decl = nv;
		sc->syms.cap_decl = nc;
	}
	d = &sc->syms.decl[sc->obj.sym.n_decl];
	d->dll = strdup(dll);
	d->fn = strdup(fn);
	if (!d->dll || !d->fn) {
		free(d->dll);
		free(d->fn);
		return 0;
	}
	sc->obj.sym.n_decl++;
	/*
	 * A block not built yet takes the report when it is. One that was is
	 * completed IN PLACE by the same merge: rebuilding it from the file for
	 * every reported import made a module that declares N of them pay N
	 * builds, and the append lands on the same bytes - imports go after the
	 * last import in report order, a repeat is skipped - as the build
	 * followed by one merge of all of them does.
	 */
	if (sc->obj.latch[KOF_OL_SYM] && sc->syms.buf && ctx->file_header)
		sym_declared(sc, sc->obj.sym.n_decl - 1u);
	else
		sc->obj.latch[KOF_OL_SYM] = 0;
	/* What was derived from the block as it stood is stale either way. */
	sc->obj.sym.bound = 0;
	sc->obj.sym.ext_done[0] = sc->obj.sym.ext_done[1] = 0;
	return 1;
}

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
	if (!sc->obj.sym.served || !nb)
		return NULL;
	if (n)
		*n = nb;
	return sc->syms.buf;
}

/*
 * THE OBJECT'S SYMBOL BLOCK, SIZED BY THE TABLE IT HAS.
 *
 * It was one allocation of KOF_SYM_MAX_BYTES (4096 records) and a symbol past the
 * 4096th was not in it - a rule on it did not fire, and 24 of 272 measured ELF
 * files have more (tests/unit/caps_syms.c). Sizing, and growing the buffer until
 * the block was not cut, is kof_syms_build_grow's: the records kept are
 * max(4096, min(declared, KOF_SYM_ABS_MAX_RECS)), the pool is as long as the
 * names, and the bound on both is KOF_SYM_ABS_MAX_BYTES. The buffer is kept for
 * the next object and only grows.
 *
 * Past the bound the header's `truncated` byte is set, and kof_scan_incomplete
 * reads it.
 */
static void sym_build(struct kof_scanner *sc, const struct kof_obj_ctx *ctx)
{
	const struct kgenome_pe_imptab *imp =
		ctx->format == KOF_FMT_PE ? oc_pe_imports(sc, ctx) : NULL;

	sc->obj.sym.n = kof_syms_build_grow(ctx->format, sc->match.m.data.p, sc->match.m.data.n,
					ctx->file_header, imp, &sc->syms.buf,
					&sc->syms.cap);
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
		const uint8_t *d = kof_src_syms_of(sc->cur.src, &dn);

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

	if (!sc->obj.latch[KOF_OL_SYM]) {
		sc->obj.latch[KOF_OL_SYM] = 1;
		sc->obj.sym.n = 0;
		/* A rendering is never asked for symbols its bytes would give: what
		 * the parent's block held was declared above, and an empty one is
		 * the answer - see objprod.h. */
		if (!sc->cur.prod && ctx->file_header &&
		    (ctx->format == KOF_FMT_ELF ||
		     ctx->format == KOF_FMT_PE)) {
			sym_build(sc, ctx);
			if (sc->syms.buf)
				sym_declared(sc, 0);
		}
	}
	/* A header with no records is not worth handing back: every reader
	 * would have to test the count anyway, and NULL says it once. */
	if (!kof_sym_count(sc->syms.buf, sc->obj.sym.n)) {
		if (nbytes)
			*nbytes = 0;
		return NULL;
	}
	if (nbytes)
		*nbytes = sc->obj.sym.n;
	return sc->syms.buf;
}


/* The object's walk, empty until the first reader fills it. */
static struct kgenome_diag_walk *oc_walk(struct kof_scanner *sc)
{
	if (!sc->obj.diag.walk)
		sc->obj.diag.walk = kgenome_diag_walk_new();
	return sc->obj.diag.walk;
}

/* `want_trace`: the wrapper resolution will read the code again, so the walk
 * that finds the entries keeps its decode for it. */
static const struct kgenome_func_set *funcs_of(const struct kof_obj_ctx *ctx,
					   int want_trace)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	/* Once per object, like the symbol block it is read from the table of:
	 * "built, and there were none" is an answer and is not asked again. */
	if (!sc->obj.latch[KOF_OL_FUNCS]) {
		sc->obj.latch[KOF_OL_FUNCS] = 1;
		kgenome_funcs_free(&sc->obj.sym.funcs);
		/*
		 * A RENDERING'S FUNCTIONS ARE ITS PARENT'S, FOUND AGAIN BY BYTES, and
		 * never built from the rendering: it carries an image description now
		 * (so `file_header` is set), but the description is the parent's moved
		 * through a transform and the bytes are not a loadable image - a walk
		 * of them would find the entries of a layout that is gone. "Built, and
		 * there were none" is an answer here as everywhere else.
		 */
		if (!sc->cur.prod && ctx->file_header) {
			struct kgenome_obj gobj;

			kof_genome_obj(ctx, &gobj);
			kgenome_diag_funcs_with_walk(&gobj, sc->match.m.data.p, sc->match.m.data.n,
						 oc_walk(sc), want_trace,
						 &sc->obj.sym.funcs);
		} else {
			/* A normalised view: its producer mapped them over - see
			 * kgenome_funcs_remap. */
			uint32_t n = 0;
			const struct kgenome_func *d = kof_src_funcs_of(sc->cur.src, &n);

			if (d && n) {
				sc->obj.sym.funcs.v = malloc(n * sizeof *sc->obj.sym.funcs.v);
				if (sc->obj.sym.funcs.v) {
					memcpy(sc->obj.sym.funcs.v, d, n * sizeof *d);
					sc->obj.sym.funcs.n = n;
				} else {
					sc->obj.sym.funcs.status = KGENOME_NOMEM;
				}
			}
		}
	}
	return &sc->obj.sym.funcs;
}

const struct kgenome_func_set *oc_funcs(const struct kof_obj_ctx *ctx)
{
	return funcs_of(ctx, 0);
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
	const struct kgenome_elf_info *ei = NULL;
	const struct kgenome_pe_info *pi = NULL;
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
		 * rely on - KGENOME_PERM_X and KGENOME_PE_PERM_X are declared apart
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
				    i < KGENOME_ELF_MAX_SEGMENTS; i++)
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
	default:
		return 0;
	}
}

/*
 * WHICH ANALYSES THIS FILE CAN SERVE, read off the file.
 *
 * The analyses differ by an order of cost and by what each can see. A diagnose
 * says which it is written for (KOF_DIAG_ANALYSIS) and the route that runs is the
 * INTERSECTION of what it declared and what the object can serve - what the
 * object's format and content make possible, never an exclusive class chosen by
 * what evidence the file happens to carry:
 *
 *   an object file (a kernel module)  its names - SYMBOL. No program entry, no
 *                                     system call to find.
 *   an ELF with PT_INTERP             SYMBOL. The loader's own test for "this
 *                                     needs a dynamic linker": its calls are
 *                                     imports, and it contains no system call.
 *   any other ELF (static)            SYMBOL and SYSCALL. A static program says
 *                                     what it calls by name when it has symbols,
 *                                     and enters the kernel by an instruction in
 *                                     its own code whether it has them or not -
 *                                     a section table and a .symtab are
 *                                     evidence of how it was LINKED, not a
 *                                     reason the sweep has nothing to find. The
 *                                     old selection switched SYSCALL off for any
 *                                     static ELF with a section table or a
 *                                     symbol, so a diagnose that declared SYSCALL
 *                                     only (rwx_exec, the botnet net diagnoses)
 *                                     was NO_ROUTE on a stripped static bot that
 *                                     still had section headers
 *                                     (tests/unit/view_equiv.c route matrix).
 *   a PE                              its names, and what it resolves for itself
 *                                     - APIHASH
 *
 * THE COST IS NOT DECIDED HERE. The sweep was MEASURED to be 90% of the scan on
 * 254 ELF files when every static one was offered it, and what keeps it from being
 * that again is the gate (diag_gates): a diagnose whose file-shape conditions or
 * imports are unmet asks for no route, and a diagnose no rule reads is not run.
 * The route runs when a diagnose that passed its gate declared it.
 *
 * Anything else serves none, so no diagnose is asked.
 */
static unsigned diag_servable(const struct kof_obj_ctx *ctx)
{
	if (ctx->format == KOF_FMT_PE)
		return KGENOME_DIAG_RUN_SYMBOL | KGENOME_DIAG_RUN_APIHASH;
	if (ctx->format == KOF_FMT_ELF) {
		const struct kgenome_elf_info *ei = kof_elf(ctx);
		uint32_t i;

		if (!ei || !ei->valid)
			return 0;
		if (ei->e_type == KGENOME_ELF_REL)
			return KGENOME_DIAG_RUN_SYMBOL;
		for (i = 0; i < ei->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++)
			if (ei->seg[i].type == 3u)
				return KGENOME_DIAG_RUN_SYMBOL;
		return KGENOME_DIAG_RUN_SYMBOL | KGENOME_DIAG_RUN_SYSCALL;
	}
	return 0;
}

/* The analyses a diagnose DECLARED, as the routines the scan runs. */
static unsigned analysis_runs(unsigned analysis)
{
	unsigned r = 0;

	if (analysis & KOF_DIAG_ANALYSIS_SYSCALL)
		r |= KGENOME_DIAG_RUN_SYSCALL;
	if (analysis & KOF_DIAG_ANALYSIS_SYMBOL)
		r |= KGENOME_DIAG_RUN_SYMBOL;
	if (analysis & KOF_DIAG_ANALYSIS_APIHASH)
		r |= KGENOME_DIAG_RUN_APIHASH;
	return r;
}

/* The routines to run for diagnose `d` on this file: what it declared, where the
 * file offers it. Zero means the file has nothing for this diagnose. */
static unsigned diag_routes(const struct kof_diag *d,
			    const struct kof_obj_ctx *ctx)
{
	return analysis_runs(d->analysis) & diag_servable(ctx);
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

/*
 * DOES ANY RULE READ THIS DIAGNOSE. A rule (a signature module that names it
 * with kof_diag) is what ASKS: asking means the object is worth the analysis
 * and worth interpreting. The count is what the database build wrote for the
 * modules it read (KDIG_SEC_USERS); a diagnose whose count was never written
 * down is unknown, and unknown counts as read.
 */
static int diag_has_reader(const struct kof_diag *d)
{
	return !d->users_known || d->n_users != 0u;
}

/* Is it RUN: when a rule reads it - or when a tool asked about all of them, see
 * kof_scan_diag_report. */
static int diag_used(const struct kof_scanner *sc, const struct kof_diag *d)
{
	return sc->obj.diag.all || diag_has_reader(d);
}

enum kgenome_status kof_scan_diag_status(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc)
		return KGENOME_OK;
	/* Live: the graph's own status moves after the scan (a join that the
	 * memory allowance refused is noted on it), so it is read, not cached. */
	return sc->obj.diag.graph ? kgenome_diag_scan_status(sc->obj.diag.graph)
			      : sc->obj.diag.status;
}

void kof_scan_diag_drop(struct kof_scanner *sc)
{
	if (sc->obj.diag.graph) {
		kgenome_diag_scan_free(sc->obj.diag.graph);
		sc->obj.diag.graph = NULL;
	}
	oc_scan_release(sc, sc->obj.diag.charged);
	sc->obj.diag.charged = 0;
	sc->obj.diag.status = KGENOME_OK;
	sc->obj.diag.refused = 0;
}

int kof_scan_incomplete(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	enum kgenome_status st;
	uint32_t i;

	if (!sc)
		return 0;
	for (i = 0; sc->diag.unk && i < sc->diag.bm; i++)
		if (sc->diag.unk[i])
			return 1;
	/* THE CALLER'S BUDGET, WHICH NO DIAGNOSE'S OWN ANSWER CARRIES: a product the
	 * ledger refused (the graph of links a join reads) leaves the diagnose that
	 * needed it answering 'no', and the scan's status is where that is said.
	 * Only the budget (the instruction ceiling and the memory allowance) and an
	 * allocation that failed count here - the per-diagnose limits are already
	 * 'cannot say' through diag_unk. */
	st = kof_scan_diag_status(ctx);
	if (st == KGENOME_OVER_BUDGET || st == KGENOME_NOMEM)
		return 1;
	/* The block counts only when it was built for this object: forcing it here
	 * would make every clean object pay for a table nothing asked for. */
	if (sc->obj.latch[KOF_OL_SYM] && kof_sym_truncated(sc->syms.buf, sc->obj.sym.n))
		return 1;
	return 0;
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
		 * A SIGN IS WHAT MAKES AN OBJECT WORTH ANALYSING: a condition on what
		 * the file is, or an import the diagnose needs. That the file offers
		 * the diagnose's analysis at all is not one - a static ELF is not a
		 * reason to look, it is the only place the system call sweep has
		 * anything to find - and counting it made every static ELF ask, so a
		 * toolchain's ordinary R|X binary started the analysis.
		 */
		if (!d->n_needcap && !d->n_when)
			continue;
		/*
		 * A DIAGNOSE NO RULE READS DOES NOT ASK. Asking means "this
		 * object is worth the analysis AND worth interpreting" - see the
		 * caller. MEASURED when a diagnose whose only condition was the
		 * format asked: it put the whole PE corpus through the emulating
		 * unpackers - 10.9 s to 26.6 s, and two .NET assemblies reported
		 * damaged by an unpacker that had no business running on them.
		 */
		if (!diag_has_reader(d))
			continue;
		if (diag_gate_open(sc, ctx, i))
			return 1;
	}
	return 0;
}

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
static const struct kgenome_diag_apihash_set *sc_apihash(struct kof_scanner *sc,
					    const struct kof_obj_ctx *ctx)
{
	if (!sc->obj.latch[KOF_OL_APIHASH]) {
		kof_buf b = oc_mc(ctx)->data;

		sc->obj.latch[KOF_OL_APIHASH] = 1;
		if (ctx->format == KOF_FMT_PE && b.p && b.n) {
			struct kgenome_obj gobj;

			kof_genome_obj(ctx, &gobj);
			struct kgenome_budget kb;

			kgenome_budget_default(&kb, b.n, kgenome_diag_code_bytes(&gobj, b.n));
			kb.max_bytes = oc_scan_room(sc);
			sc->obj.diag.apihash = kgenome_diag_apihash_run(&gobj, b.p, b.n,
						      oc_pe_imports(sc, ctx), &kb);
		}
	}
	return sc->obj.diag.apihash;
}

/*
 * The PE's import directory, walked the first time anything asks and kept
 * until the object is done with - see kof_scanner.obj.diag.pe_imp. Empty for anything
 * that is not a PE.
 */
const struct kgenome_pe_imptab *oc_pe_imports(struct kof_scanner *sc,
					  const struct kof_obj_ctx *ctx)
{
	if (!sc->obj.latch[KOF_OL_PE_IMPORTS]) {
		kof_buf b = oc_mc(ctx)->data;

		sc->obj.latch[KOF_OL_PE_IMPORTS] = 1;
		if (ctx->format == KOF_FMT_PE && ctx->file_header && b.p)
			kgenome_pe_imptab_build(b, kof_pe(ctx), &sc->obj.diag.pe_imp);
	}
	return &sc->obj.diag.pe_imp;
}

/*
 * The object's relocation table, built the first time anything asks and kept
 * until the object is done with - see kof_scanner.relocs. NULL for an object
 * that is not a relocatable ELF, which the callers read as "no relocations".
 */
static const struct kgenome_elf_relocs *sc_relocs(struct kof_scanner *sc,
					      const struct kof_obj_ctx *ctx)
{
	if (!sc->obj.latch[KOF_OL_RELOCS]) {
		const struct kgenome_elf_info *ei = ctx->format == KOF_FMT_ELF
						? kof_elf(ctx) : NULL;
		kof_buf b = oc_mc(ctx)->data;

		sc->obj.latch[KOF_OL_RELOCS] = 1;
		if (ei && ei->valid && b.p) {
			sc->obj.diag.relocs = calloc(1, sizeof *sc->obj.diag.relocs);
			if (sc->obj.diag.relocs)
				(void)kgenome_elf_reloc_table(b, ei, KGENOME_ELF_RELOC_CODE,
						  sc->obj.diag.relocs);
		}
	}
	return sc->obj.diag.relocs;
}

static void ref_note(struct refscan *rs, const struct kgenome_elf_reloc *r)
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
	/* Per diagnose, so sized by how many the database HAS (sc->diag.cap) and
	 * taken from the heap: a fixed 256 here was one of the places that stopped
	 * the loader reading more than 256 diagnoses. */
	uint8_t *unmet, *ok, *rleft;
	uint8_t (*hit)[KOF_DIAG_MAX_NEED], (*rhit)[KOF_DIAG_MAX_NEED];
	uint32_t n, i, pending = 0, rpending = 0, sn = 0, total, r;
	const uint8_t *sb;

	if (sc->obj.latch[KOF_OL_DIAG_GATE])
		return;
	sc->obj.latch[KOF_OL_DIAG_GATE] = 1;
	memset(sc->diag.gate, 0, sc->diag.bm);
	n = sc->eng ? sc->eng->n_diag : 0u;
	if (n > sc->diag.cap)
		n = sc->diag.cap;
	if (!n)
		return;
	unmet = calloc(n, 3u);
	hit = calloc(n, 2u * sizeof *hit);
	if (!unmet || !hit) {
		/* No gate is a closed gate: nothing runs for an object this scan
		 * could not even look at. */
		free(unmet);
		free(hit);
		return;
	}
	ok = unmet + n;
	rleft = ok + n;
	rhit = hit + n;

	/* ---- STAGE ONE: what the file is, and what it imports ----------- */
	for (i = 0; i < n; i++) {
		const struct kof_diag *d = &sc->eng->diag[i];

		/*
		 * A DIAGNOSE NO RULE READS IS NOT RUN - see KDIG_SEC_USERS.
		 *
		 * Decided before anything about the object is asked, because it
		 * is the cheapest test there is and the one that matters most:
		 * an unread diagnose that passes its gate starts the analysis
		 * for an answer nobody collects. Only a count the build wrote
		 * as ZERO closes it; a diagnose whose users were never written
		 * down is unknown and keeps running.
		 */
		if (!diag_used(sc, d))
			continue;
		if (!diag_when_met(ctx, d))
			continue;               /* the file is not the shape */
		/* The analysis this diagnose is written for is not one the file
		 * offers, so there is nothing for it to find. */
		if (!diag_routes(d, ctx))
			continue;
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
			cap = kgenome_nucleo_cap_of_name(kof_sym_name(sb, sn, rec, NULL));
			if (cap == KGENOME_NUCLEO_NONE)
				continue;
			for (i = 0; i < n; i++) {
				const struct kof_diag *d = &sc->eng->diag[i];
				uint8_t k;

				if (!unmet[i])
					continue;
				for (k = 0; k < d->n_needcap; k++)
					if (!hit[i][k] &&
					    (d->needcap[k] == cap ||
					     d->needcap[k] == kgenome_nucleo_cap_generic(cap))) {
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
		const struct kgenome_elf_relocs *t = sc_relocs(sc, ctx);
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
		rs.x86 = ctx->arch == KGENOME_ARCH_X86 || ctx->arch == KGENOME_ARCH_X86_64;
		/* A format with no relocation table cannot satisfy a diagnose that
		 * demands one: no answer is not a yes. Stops once nothing is left to
		 * find, which is a saving on the READ and not a bound on the table. */
		for (q = 0; t && q < t->n && rs.pending; q++)
			ref_note(&rs, &t->v[q]);
	}

	for (i = 0; i < n; i++)
		if (ok[i] && !rleft[i])
			sc->diag.gate[i >> 3] |= (uint8_t)(1u << (i & 7u));
	free(unmet);
	free(hit);
}

/* Does diagnose `i` pass this object's gate. */
static int diag_gate_open(struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
			  uint32_t i)
{
	diag_gates(sc, ctx);
	return i < sc->diag.cap &&
	       ((sc->diag.gate[i >> 3] >> (i & 7u)) & 1u);
}

void oc_diag_ready(struct kof_scanner *sc, const struct kof_obj_ctx *ctx)
{
	struct kgenome_diag_scan *ds;
	kof_buf b;
	uint32_t i;

	if (sc->obj.latch[KOF_OL_DIAG])
		return;
	/*
	 * NOBODY ASKED, SO NOBODY PAYS - see KOF_ENG_USE_DIAGNOSE. The sweep
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
	if (!sc->obj.diag.ask)
		return;
	sc->obj.latch[KOF_OL_DIAG] = 1;
	memset(sc->diag.hit, 0, sc->diag.bm);
	memset(sc->diag.unk, 0, sc->diag.bm);
	if (!sc->eng || !sc->eng->n_diag)
		return;
	b = oc_mc(ctx)->data;
	if (!b.p || !b.n)
		return;
	/*
	 * ---- ONLY THE ROUTES AN OPEN DIAGNOSE DECLARED, WHERE THE FILE OFFERS THEM --
	 *
	 * Every scan once ran every route whatever the database wanted: a PE has
	 * no syscall to find and a dynamically linked ELF has none either, so the
	 * other route was work with nowhere to put its answer.
	 *
	 * THE UNION, because the database decides together. One diagnose asking for
	 * the symbol route is enough reason to run it; no diagnose asking is the only
	 * reason not to.
	 */
	{
		unsigned run = 0;
		struct kgenome_diag_seq *seqv;
		uint32_t n_seq = 0;

		/* Kept in the scanner, not on the stack: the scan keeps this
		 * pointer for as long as its graph lives (see kof_scanner.diag.seq). */
		seqv = sc->diag.seq;

		for (i = 0; i < sc->eng->n_diag; i++) {
			/* a diagnose whose signs are absent asks for no
			 * route - see diag_gates */
			if (!diag_gate_open(sc, ctx, i))
				continue;
			/* A head built from two calls is built for the diagnose
			 * that declared it, and for it alone. */
			if (sc->eng->diag[i].seq_first && n_seq < sc->diag.cap) {
				seqv[n_seq].made = sc->eng->diag[i].node[0].cap;
				seqv[n_seq].first = sc->eng->diag[i].seq_first;
				seqv[n_seq].then = sc->eng->diag[i].seq_then;
				n_seq++;
			}
			/* what it declared, where the file can serve it */
			run |= diag_routes(&sc->eng->diag[i], ctx);
			if (sc->eng->diag[i].analysis & KOF_DIAG_USES_EMU)
				run |= KGENOME_DIAG_RUN_EMULATE;
		}
		if (!run)
			return;
		/*
		 * NOTHING NARROWS WHICH CAPABILITIES ARE RECORDED, and a loop
		 * that built such a set per object was removed with the
		 * parameter that ignored it - see kgenome_diag_scan_with. The set
		 * cannot be derived: a verdict reads nodes no diagnose names.
		 */
		struct kgenome_diag_inputs in;
		struct kgenome_obj gobj;
		struct kgenome_budget kb;

		in.relocs = sc_relocs(sc, ctx);
		/* Read from the same table the symbol block is, once - and only
		 * for a route that walks functions. */
		in.funcs = (run & (KGENOME_DIAG_RUN_SYMBOL | KGENOME_DIAG_RUN_EMULATE))
			   ? funcs_of(ctx, (run & KGENOME_DIAG_RUN_SYSCALL) != 0) : NULL;
		/* The same walk finds the entries and, for the syscall route, the
		 * kernel-entry sites: one decode of the code. */
		in.walk = oc_walk(sc);
		in.seq = seqv;
		in.n_seq = n_seq;
		/* The analysis result, from the latch: the normaliser may have
		 * asked already, and whichever asks first pays once. Only
		 * computed here when the database wants the route. */
		in.apihash = (run & KGENOME_DIAG_RUN_APIHASH)
			     ? sc_apihash(sc, ctx) : NULL;
		/* The import directory is walked once: the symbol block is
		 * built from the same table. */
		in.imports = ((run & KGENOME_DIAG_RUN_SYMBOL) &&
			      ctx->format == KOF_FMT_PE && ctx->file_header)
			     ? oc_pe_imports(sc, ctx) : NULL;
		kof_genome_obj(ctx, &gobj);
		/*
		 * WHAT THE SCAN MAY COST, from this scanner's own ceiling: the
		 * lib scales every limit with the object (kgenome_budget_default) and
		 * is told the one number it cannot know - how much of the scan's
		 * resident allowance is left - which is the bound on a hostile object.
		 */
		kgenome_budget_default(&kb, b.n, kgenome_diag_code_bytes(&gobj, b.n));
		kb.max_bytes = oc_scan_room(sc);
		in.budget = &kb;
		ds = kgenome_diag_scan_with_inputs(&gobj, b.p, b.n, run, &in);
		/*
		 * READ BACK WHAT THE LIB SAYS ABOUT ITS OWN WORK. The budget went in
		 * with this call (max_bytes is what the scanner has left); the ledger
		 * and the status come out. The bytes the scan holds are charged to the
		 * scanner's ceiling until the graph is dropped, so a limit reached is a
		 * status the verdict path can read (kof_scan_incomplete) and not a
		 * silently shorter graph.
		 */
		if (ds) {
			uint64_t peak;

			sc->obj.diag.status = kgenome_diag_scan_status(ds);
			sc->obj.diag.refused = kgenome_diag_scan_refused(ds);
			sc->obj.diag.charged = kgenome_diag_scan_bytes(ds, &peak);
			/* The most it held is the scanner's peak, what it holds now is
			 * what stays charged. */
			if (peak < sc->obj.diag.charged)
				peak = sc->obj.diag.charged;
			scan_charge(sc, peak);
			oc_scan_release(sc, peak - sc->obj.diag.charged);
		}
		/* The walk's trace stays until the object ends: the xref sweep reads
		 * it too (kgenome_diag_code_run). It is freed with the walk. */
	}
	if (!ds)
		return;
	KOF_TIME_BEGIN(KOF_T_DIAG_MATCH);
	memset(sc->diag.n_bind, 0, sc->diag.cap);
	for (i = 0; i < sc->eng->n_diag && i < sc->diag.cap; i++) {
		uint8_t nb = 0;

		/* An unread diagnose is not matched: nobody collects the answer,
		 * and the shared graph is still there for the ones that are. */
		if (!diag_used(sc, &sc->eng->diag[i]))
			continue;
		/*
		 * THREE ANSWERS, not two: a limit reached on this scan makes a 0
		 * "could not say" - see kof_diag_match_known. Only a diagnose whose
		 * gate is open was ever going to be answered by this scan, so only
		 * that one is incomplete; a diagnose the object's shape or imports
		 * ruled out has an answer, and it is no.
		 *
		 * Every node it bound comes back - see kof_scanner.diag.bind.
		 */
		switch (kof_diag_match_known(ds, &sc->eng->diag[i],
					     sc->diag.bind[i], &nb)) {
		case 1:
			sc->diag.hit[i >> 3] |= (uint8_t)(1u << (i & 7u));
			sc->diag.n_bind[i] = nb > KOF_DB_MAX_DIAG_NODE
					   ? (uint8_t)KOF_DB_MAX_DIAG_NODE : nb;
			break;
		case -1:
			if (diag_gate_open(sc, ctx, i))
				sc->diag.unk[i >> 3] |= (uint8_t)(1u << (i & 7u));
			break;
		default:
			break;
		}
	}
	KOF_TIME_END(KOF_T_DIAG_MATCH);
	/*
	 * AND THE GRAPH STAYS - see kof_scanner.obj.diag.graph. It is what the
	 * verdict layer reads; freeing it here would make every reader pay
	 * for the analysis again.
	 */
	sc->obj.diag.graph = ds;
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
	/* The caller IS the asker here - see KOF_ENG_USE_DIAGNOSE. Setting it
	 * rather than bypassing the test keeps one gate on this work. */
	sc->obj.diag.ask = 1;
	oc_diag_ready(sc, ctx);
}

_Static_assert(KOF_DIAG_REPORT_NODES >= KOF_DB_MAX_DIAG_NODE,
	       "a report must hold every node a diagnose may bind");

uint32_t kof_scan_diag_count(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc || !sc->eng)
		return 0;
	return sc->eng->n_diag < sc->diag.cap ? sc->eng->n_diag : sc->diag.cap;
}

int kof_scan_diag_report(const struct kof_obj_ctx *ctx, uint32_t i,
			 struct kof_diag_report *out)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const struct kof_diag *d;

	if (!sc || !sc->eng || !out || i >= kof_scan_diag_count(ctx))
		return 0;
	/*
	 * ONLY WHAT THE SCAN ALREADY COMPUTED. diag_all was set when the object
	 * began - see st_facts - so the one analysis covered every diagnose and
	 * this reads its answer; a caller that did not ask has nothing here, and
	 * running the analysis now would be a second pass over the object.
	 */
	if (!sc->obj.diag.all)
		return 0;
	/* The analysis itself, if no rule had asked for it yet: the one run. */
	kof_scan_diag_force(ctx);

	d = &sc->eng->diag[i];
	memset(out, 0, sizeof *out);
	out->name = d->name;
	out->id = d->id;
	out->n_node = d->n_node > KOF_DB_MAX_DIAG_NODE
		      ? (uint8_t)KOF_DB_MAX_DIAG_NODE : d->n_node;
	/* The order the gate applies them in - see diag_gates. */
	if (!diag_when_met(ctx, d)) {
		out->state = KOF_DIAG_ST_SHAPE;
	} else if (!diag_routes(d, ctx)) {
		out->state = KOF_DIAG_ST_NO_ROUTE;
	} else if (!diag_gate_open(sc, ctx, i)) {
		out->state = KOF_DIAG_ST_SIGNS;
	} else if (!((sc->diag.hit[i >> 3] >> (i & 7u)) & 1u) ||
		   !sc->obj.diag.graph) {
		out->state = KOF_DIAG_ST_SEEN;
	} else {
		uint8_t k, nb = sc->diag.n_bind[i];

		out->state = KOF_DIAG_ST_MATCH;
		for (k = 0; k < nb && k < out->n_node; k++) {
			uint16_t b = sc->diag.bind[i][k];
			const struct kgenome_diag_hit *h =
				b < kgenome_diag_scan_count(sc->obj.diag.graph)
				? kgenome_diag_scan_at(sc->obj.diag.graph, b) : NULL;

			out->cap[k] = d->node[k].cap;
			out->at[k] = h ? h->at : 0;
			out->n_bound++;
		}
	}
	return 1;
}
