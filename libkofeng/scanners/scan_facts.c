/*
 * scan_facts.c - what is true of an object before any module looks at it: its
 * format and architecture, which regions and symbol halves exist, whether a library
 * was linked in, and the cheap per-module prefilter that uses them.
 */

#define _GNU_SOURCE

#include "scan_int.h"
#include "objctx_int.h"
#include "../kofcore/kofmod/kofsym.h"
#include "../analyzers/parsers/kofformat.h"
#include "../kofcore/kofmod/elf.h"
#include "../kofcore/kofmod/pe.h"
#include <stdlib.h>
#include <string.h>


/*
 * Which regions this object has, as a mask of region bits.
 *
 * Computed once per object, not once per module. Resolving a region walks the segment
 * and section tables and sorts the result, so doing it per module would cost more than
 * running the cheap modules it is meant to save. Done once, the per-module test is a
 * single AND.
 */
uint32_t sx_regions_present(const struct kof_obj_ctx *ctx, uint32_t wanted)
{
	struct kof_range *ext = kof_scan_of(ctx)->cache.ext;
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
	 * the region would never be marked present, so the sx_prefilter would skip
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
 * has never heard of and the sx_prefilter would skip every module naming them.
 * Silent, and exactly the loss the note above describes.
 *
 * Still gated on `wanted`, so the block is not built for an object no module
 * asks about - which is nearly all of them.
 */
uint32_t sx_sym_halves_present(const struct kof_obj_ctx *ctx,
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
 * `out` is the per-object result and may be NULL - the unpack pass has no
 * result to fill yet. Passed rather than derived from the stats, because those
 * are cumulative and a per-object number taken by differencing them is wrong
 * the moment two objects are in flight.
 */
int sx_prefilter(const struct kof_module *m, const struct kof_obj_ctx *ctx,
		     uint32_t present, struct kof_stats *st,
		     struct kof_result *out)
{
	st->considered++;

	/* The declared preconditions, from kof_module_precond - the one place
	 * that applies them. What is left here is only the counting. */
	switch (kof_module_precond(m, ctx, ctx->obj_size)) {
	case KOF_PRECOND_TARGET:  st->by_target++;  return 0;
	case KOF_PRECOND_SIZE:    st->by_size++;    return 0;
	case KOF_PRECOND_ARCH:    st->by_arch++;    return 0;
	case KOF_PRECOND_SUBTYPE: st->by_subtype++; return 0;
	case KOF_PRECOND_OK:      break;
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

/*
 * THE RESOLVER FOR AN OBJECT WHOSE REGIONS WERE DECLARED.
 *
 * Same shape as every parser's: a mask in, the ranges that answer it out. The
 * difference is only where the answer comes from - a table the producer filled
 * rather than a walk over headers - and the callers cannot tell, which is the
 * point. A rule naming scan_range_data on a normalised view gets the view's
 * data, at the view's offsets, through the same call it always used.
 */
uint32_t sx_declared_resolve_scan(const struct kof_obj_ctx *ctx,
				      uint32_t scan_mask, struct kof_range *out,
				      uint32_t max_out)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint32_t i, n = 0;

	if (!sc || !out || !max_out)
		return 0;
	for (i = 0; i < sc->cur.n_rgn && n < max_out; i++) {
		if (!(sc->cur.rgn[i].mask & scan_mask))
			continue;
		/* An empty region is not a range. A parser would not return one
		 * and a matcher asked to search it would search nothing. */
		if (!sc->cur.rgn[i].len)
			continue;
		out[n].off = sc->cur.rgn[i].off;
		out[n].len = sc->cur.rgn[i].len;
		n++;
	}
	return n;
}

/*
 * AN OBJECT THAT IS TOLD WHAT IT IS, AND IS NOT ASKED.
 *
 * A normalised view carries the image description of the parent it renders, with
 * every file offset moved through the transform (see kof_src_desc). Installed
 * where a parse would have put its answer - the format's view struct, and the
 * context's format, architecture, subtype and entry - so everything downstream
 * reads the same fields it always did and cannot tell the difference, except
 * that the fields are TRUE. The parse is not run: it would read the parent's
 * header out of bytes that are no longer where that header points.
 *
 * Returns 0 when there is nothing to install (the object is identified from its
 * bytes), or when the view struct cannot be had - an object that is then raw,
 * which is the honest answer for one that cannot be described.
 */
int sx_inherit_image(struct kof_scanner *sc, struct kof_obj_ctx *ctx)
{
	const struct kof_src_desc *d = kof_src_desc_of(sc->cur.src);
	const struct kof_parser *p;

	if (!d || d->fmt >= KOF_TARGET_COUNT)
		return 0;
	p = kof_parser_of(d->fmt);
	if (!p || d->info_len > p->view_size)
		return 0;
	/* A view that owns tables cannot be adopted from bytes: it holds pointers. The image of a
	 * container is not one that a transform could have produced, and the object stays raw. */
	if (kof_view_ops_of(d->fmt))
		return 0;
	if (!sc->cache.view[d->fmt]) {
		sc->cache.view[d->fmt] = malloc(p->view_size);
		if (!sc->cache.view[d->fmt]) {
			/* raw is the answer for an object that cannot be described, and it is SAID */
			OC_LIMIT(sc, "image view not allocated, the object stays raw");
			return 0;
		}
	}
	memset(sc->cache.view[d->fmt], 0, p->view_size);
	memcpy(sc->cache.view[d->fmt], d->info, d->info_len);
	ctx->format = d->fmt;
	ctx->arch = d->arch;
	ctx->subtype = d->subtype;
	ctx->entry_off = d->entry_off;
	ctx->file_header = sc->cache.view[d->fmt];
	return 1;
}

/*
 * A format whose modules read no view of it: kofmod has no accessor for these
 * four, so the id is the whole claim. Every other format has a view-struct
 * accessor (`kof_zip(ctx)` for ZIP and DOCZIP, `kof_pe`, `kof_pdf` ...), which is
 * a cast of ctx->file_header with no null check - see sx_identify.
 */
static int fmt_is_viewless(uint8_t fmt)
{
	return fmt == KOF_FMT_TEXT || fmt == KOF_FMT_MACHO ||
	       fmt == KOF_FMT_IMAGE || fmt == KOF_FMT_FONT;
}

/*
 * THE LEDGER AND A VIEW THAT OWNS TABLES (zip, pdf: struct kof_view_ops).
 *
 * Before the parse: the room it may take is what the per-object ledger has left, because
 * the parse allocates to the size of the file and must be told what the engine can afford
 * - the one number it cannot work out. After it: what it holds is charged, and stays
 * charged until sx_views_release gives it back at the end of the object. A parse that
 * cannot grow a table says so itself (the format's "full" anomaly, read by
 * kof_parser_cut_bits below), so nothing here decides what is lost.
 */
static void view_arm(const struct kof_scanner *sc, uint8_t fmt, void *view)
{
	const struct kof_view_ops *o = kof_view_ops_of(fmt);

	if (o) {
		uint64_t room = oc_scan_room(sc);

		/* Never zero: zero is a caller that keeps no account, which this one does. */
		o->mem(view)->room = room ? room : 1u;
	}
}

static void view_charge(struct kof_scanner *sc, uint8_t fmt, void *view)
{
	const struct kof_view_ops *o = kof_view_ops_of(fmt);
	uint64_t held;

	if (!o)
		return;
	held = o->mem(view)->held;
	if (held) {
		scan_charge(sc, held);
		sc->cache.view_held += held;
	}
}

/*
 * THE WALK A MODULE'S kof_zip_next / kof_pdf_next REACHES: the next row of this object's
 * view, through the format's own handle (kof_view_ops). NULL when the format has no
 * walkable table, when the object was not parsed, and at the end. It is the host's call
 * and not an array in the view so that the host counts it - see sx_walk_check.
 */
const void *oc_view_next(const struct kof_obj_ctx *ctx, uint32_t *cursor)
{
	const struct kof_view_ops *o = kof_view_ops_of(ctx->format);

	if (!o || !ctx->file_header || !cursor)
		return NULL;
	return o->next((void *)(uintptr_t)ctx->file_header, cursor);
}

void sx_views_release(struct kof_scanner *sc)
{
	uint32_t i;

	for (i = 0; i < KOF_TARGET_COUNT; i++) {
		const struct kof_view_ops *o;

		if (!sc->cache.view[i])
			continue;
		o = kof_view_ops_of((uint8_t)i);
		if (o)
			o->release(sc->cache.view[i]);
	}
	oc_scan_release(sc, sc->cache.view_held);
	sc->cache.view_held = 0;
	sx_ext_release(sc);
}

/*
 * AN UNPACK MODULE FOR A FORMAT WITH A WALKABLE TABLE THAT NEVER WALKED IT.
 *
 * The one thing that tells a module built for the layout before the tables were dynamic
 * from one that simply had nothing to do: such a module reads `z->n_entries` /
 * `p->n_objects` at the offsets its build put them, finds the legacy field - zero, kept
 * for exactly this - runs no loop, and returns having produced nothing and said nothing. A
 * pack built before the change and loaded by this engine would otherwise turn every archive
 * and document into one that was "examined". The walk is a vtable slot, so the host counts
 * its calls (struct kof_view_mem.walked); a view with rows and no calls is that module.
 *
 * Asked after a module that NAMES the object's format as its target and unwraps it - a
 * module for another format, or one that targets anything, was not written to read this
 * table and is not held to it. UNSUPPORTED is the reason because it is the one a later
 * build closes: the fix is to rebuild the database. The first reason recorded is the one
 * kept, so a module that reported its own better one is not overwritten.
 */
void sx_walk_check(struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
		   const struct kof_module *m)
{
	const struct kof_view_ops *o = kof_view_ops_of(ctx->format);
	const struct kof_view_mem *vm;
	uint32_t k;

	if (!o || !ctx->file_header || m->step != KOF_ANALYZE_UNWRAP)
		return;
	for (k = 0; k < m->n_target && m->target[k] != ctx->format; k++)
		;
	if (k == m->n_target)
		return;
	vm = o->mem((void *)(uintptr_t)ctx->file_header);
	if (vm->rows && !vm->walked)
		oc_scan_broken(sc, KOF_BROKEN_UNSUPPORTED);
}

void sx_identify(struct kof_scanner *sc, kof_buf buf, struct kof_obj_ctx *ctx,
		     uint8_t as_format, const void *as_view, uint32_t as_view_len)
{
	const struct kof_parser *parsers;
	uint64_t keep[KOF_PARSER_KEEP / sizeof(uint64_t)];
	uint32_t i, n;

	/*
	 * A FORMAT THE CALLER DECLARED, which is not something any sniff can
	 * answer.
	 *
	 * Every format below is recognised from its bytes. A collected event is
	 * not: a record has no magic, and a submitted script block is a
	 * PowerShell fragment that no file format claims - so a submission
	 * scanned through the sniff chain comes out "unrecognised", and every
	 * rule written about it is filtered out before it runs. That was the
	 * whole gap: the viewer could show the thing and the scanner could not
	 * be told what it was.
	 *
	 * The caller knows. It read the record off a channel or out of a log,
	 * and it is the only side that can know - so it says, and the sniff
	 * chain is skipped rather than consulted and overruled.
	 *
	 * The parse still runs and may still refuse. Being told is not being
	 * right, and a declaration that does not survive its own parser leaves
	 * the object unidentified exactly as a failed sniff would.
	 */
	/*
	 * DECLARED RAW, WHICH IS A CLAIM AND NOT A FORMAT.
	 *
	 * The caller is not saying "this is format 0", it is saying "do not ask
	 * the bytes". The two differ for one producer that matters: a
	 * normalised view still begins with its parent's magic and is no longer
	 * that format, so a sniff gets the right answer to the wrong question.
	 *
	 * Left at KOF_FMT_UNKNOWN, with no parser run, which is what the object
	 * now is - and every rule written for raw still searches it, because
	 * raw is what those rules target.
	 */
	if (as_format == KOF_FMT_DECLARED_RAW)
		return;
	if (as_format) {
		const struct kof_parser *p = kof_parser_of(as_format);

		/*
		 * SAID WHEN THERE IS NOTHING TO PARSE - AND ONLY THEN.
		 *
		 * KOF_FMT_TEXT, MACHO, IMAGE and FONT have no row in the parser
		 * table: there is no header to read and no region to carve, so
		 * there is nothing for a parser to do. For those the id IS the
		 * whole claim, and it matters because ctx->format is what
		 * kof_module_precond tests FIRST - an object left at zero is
		 * offered only to the modules that target unknown, so a
		 * container that knew it had handed over a script got the rules
		 * for a bare blob.
		 *
		 * A FORMAT WITH A PARSER IS DIFFERENT, AND SETTING IT HERE
		 * CRASHED. This was written to set the id unconditionally, on
		 * the argument that failing to read a structure is no reason to
		 * forget what the thing was said to be. True of a claim; false
		 * of this field. A module that targets a format reads that
		 * format's VIEW - kof_pdf(ctx) is a cast of ctx->file_header,
		 * with no null check anywhere, because a module reached for a
		 * format is entitled to assume it was parsed.
		 *
		 * So a declared format whose parse then REFUSES used to leave
		 * the id set and file_header NULL, and the first module to
		 * accept it dereferenced nothing. Reproduced: declare
		 * KOF_FMT_PDF for an /ObjStm - whose decoded form has no %PDF-
		 * header, so the parse correctly refuses - and the scan
		 * segfaults. That is exactly the shape "decide what to parse
		 * from the description" would produce, so it is not a
		 * hypothetical.
		 *
		 * The rule: the id survives a refusal only where a refusal
		 * cannot happen. With a parser present it is set below, after
		 * the parse agreed.
		 */
		/*
		 * A ROW-LESS FORMAT KEEPS ITS ID ONLY WHEN NO MODULE READS A VIEW OF IT.
		 *
		 * The line this replaces set ctx->format for EVERY format without a
		 * row, on the reading above that "there is nothing to parse". True for
		 * four of them and false for the rest: KOF_FMT_DOCZIP has no row of its
		 * own (the ZIP row's parse chooses between ZIP and DOCZIP), yet the
		 * module that targets it begins `kof_zip(ctx)->valid`, a cast of the
		 * NULL file_header - SIGSEGV for kscan_bytes(..., as_format =
		 * KOF_FMT_DOCZIP) (tests/unit/hostile_engine_scan.c, c_as_doczip).
		 * The rule is the one stated for a refused parse just above, applied
		 * to the case with no parse: an id without its view is never left
		 * standing, and the object is unidentified, which is what a failed
		 * sniff gives.
		 */
		if (!p) {
			if (fmt_is_viewless(as_format))
				ctx->format = as_format;
			return;
		}
		if (!sc->cache.view[as_format]) {
			sc->cache.view[as_format] = malloc(p->view_size);
			if (!sc->cache.view[as_format]) {
				OC_LIMIT(sc, "format view not allocated, the object is unidentified");
				return;
			}
		}
		/*
		 * ZEROED EVERY TIME, not once when it was allocated.
		 *
		 * A view is reused across objects, and the sniff path
		 * can do that because each of those parsers fills every
		 * field it later reads. This path cannot: the fields the
		 * CALLER supplies are exactly the ones the parse does
		 * not compute, so a view left as the last object found
		 * it hands this object the last one's answers. That was
		 * the bug - the first event in a run resolved its
		 * regions from a zero extent and every event after it
		 * from the previous event's.
		 */
		memset(sc->cache.view[as_format], 0, p->view_size);
		/*
		 * NEVER OVER A VIEW THAT OWNS TABLES: its first bytes after the clear are not fields the
		 * caller knows but the pointers the parse lets go of before it clears them, and a caller's
		 * bytes there are a free() of whatever it wrote. A container computes everything its view
		 * holds (the declared view exists for the fields a parse does NOT compute: a PE's
		 * layout), so there is nothing to supply.
		 */
		if (as_view && as_view_len && !kof_view_ops_of(as_format) &&
		    as_view_len <= p->view_size)
			memcpy(sc->cache.view[as_format], as_view,
			       as_view_len);
		/*
		 * The parse sets ctx->format itself when it succeeds -
		 * every collector does, and one row even chooses
		 * between two formats while doing it. So there is
		 * nothing to set here on success, and nothing to undo
		 * on failure: an object whose declared parse refused is
		 * unidentified, which is the same answer a failed sniff
		 * gives and is the honest one.
		 */
		view_arm(sc, as_format, sc->cache.view[as_format]);
		(void)p->parse(buf, sc->cache.view[as_format], ctx);
		view_charge(sc, as_format, sc->cache.view[as_format]);
		/* A parse that agreed sets its own id AND its view; one that left the
		 * id without the view (a half-built row) must not hand a module a
		 * format whose accessor casts NULL. */
		if (ctx->format && !ctx->file_header && !fmt_is_viewless(ctx->format))
			ctx->format = KOF_FMT_UNKNOWN;
		return;
	}

	parsers = kof_parser_list(&n);
	for (i = 0; i < n; i++) {
		const struct kof_parser *p = &parsers[i];
		const struct kof_parser_keep *kp = kof_parser_keep_of(p->format);

		/* A row with a keep buffer reads the object once for both questions
		 * (struct kof_parser_keep); the others sniff and then parse. */
		if (kp ? !kp->sniff(buf, keep) : !p->sniff(buf))
			continue;
		if (!sc->cache.view[p->format]) {
			/* calloc: a view the parse clears by itself is then touched only where it
			 * is written, so its arrays cost resident memory for what was used. */
			sc->cache.view[p->format] = calloc(1, p->view_size);
			if (!sc->cache.view[p->format]) {
				OC_LIMIT(sc, "format view not allocated, the object is unidentified");
				return;
			}
		}
		/*
		 * ZEROED HERE TOO, AND THE REASON THE SNIFF PATH WAS EXEMPT HAS
		 * EXPIRED.
		 *
		 * The exemption was written down: a view is reused across
		 * objects and the sniff path can do that "because each of those
		 * parsers fills every field it later reads". That stopped being
		 * true when a parser gained a field the CALLER fills -
		 * kgenome_pe_info.layout, which pe_parse deliberately preserves
		 * across its own memset because clearing it would make every
		 * declared mapped image parse as a file.
		 *
		 * A sniffed object has no caller-supplied anything, so it must
		 * not inherit one. It did: scanning a manually-mapped image
		 * (declared MAPPED) left that in the view, and the next PE this
		 * scanner SNIFFED - an ordinary file - was parsed as though its
		 * sections were at virtual addresses. Every region then resolved
		 * to the wrong bytes, quietly, for the rest of that scanner's
		 * life or until another declared scan happened to reset it.
		 *
		 * Measured as a heuristic firing twice on one module: once on
		 * the mapped image and once on the file-layout copy un-mapped
		 * from it, which cannot be mapped and said it was.
		 */
		if (!kof_parser_self_clears(p))
			memset(sc->cache.view[p->format], 0, p->view_size);
		view_arm(sc, p->format, sc->cache.view[p->format]);
		if (kp ? kp->parse(buf, sc->cache.view[p->format], ctx, keep)
		       : p->parse(buf, sc->cache.view[p->format], ctx)) {
			view_charge(sc, p->format, sc->cache.view[p->format]);
			/* A table of the parse was full: the members past it were
			 * not read, and the object says so (see kof_parser_cut_bits). */
			if (p->anomalies(sc->cache.view[p->format]) &
			    kof_parser_cut_bits(p))
				oc_scan_limit(sc);
			return;
		}
	}
}

/*
 * A PE whose code was never readable, asked once and only when nothing opened
 * the object. See the call site for why it is not a module.
 *
 * The thresholds: 64 KB, because below that a dense section is a resource or a
 * certificate rather than a program; 7.9 bits, which is where compressed and
 * encrypted sit and where compiled code does not go - emu_unpack_gate.c measures
 * the same boundary at 7.5 over 2678 clean PEs, and this is stricter again
 * because it is answering a harder question with no second signal beside it.
 */
#define DENSE_MIN_SEC   (64u << 10)
#define DENSE_EIGHTHS_R 63u             /* 7.875 bits per byte */

void sx_dense_code_unread(struct kof_scanner *sc,
			      const struct kof_obj_ctx *ctx)
{
	const struct kgenome_pe_info *pe = kof_pe(ctx);
	uint32_t i;

	if (!pe || !pe->valid || pe->entry_sec >= pe->sec_count)
		return;
	for (i = 0; i < pe->sec_count && i < KGENOME_PE_MAX_SECTIONS; i++) {
		const struct kgenome_pe_sec *s = &pe->sec[i];

		if (i == pe->entry_sec || !kgenome_pe_sec_is_code(s))
			continue;
		if (s->file_size < DENSE_MIN_SEC || !s->file_off)
			continue;
		if (!ctx->content->entropy_at ||
		    ctx->content->entropy_at(ctx, s->file_off, s->file_size) <
		    DENSE_EIGHTHS_R)
			continue;
		/* The first reason recorded is the one kept, which is why
		 * this is guarded rather than assigned. */
		if (!sc->obj.open.broken)
			sc->obj.open.broken = KOF_BROKEN_UNSUPPORTED;
		return;
	}
}

/*
 * WHICH BYTES OF THIS OBJECT BELONG TO THE STATIC LIBRARY - ASKED ONCE, HERE.
 *
 * Beside the parse, because that is what it needs and because every consumer
 * of the answer runs after it: the normaliser leaves these bytes out of the
 * view, the block builder puts a block on the library side of enum
 * kgenome_mutation_side when it lands in one, and both used to work it out for
 * themselves. See kof_scanner.cur.lib.
 *
 * TWO TIERS, AND THE SECOND IS GATED ON HOW THE OBJECT WAS LINKED.
 *
 * The marker span runs from a loadable segment's first library string to its
 * last and takes everything between. In a STATIC build that is right - the
 * library is laid down in one run and the strings bound it. In a DYNAMIC one
 * there is no static library at all, so the strings it finds are the
 * program's own and the span between them is the program: measured, an 8MB
 * miner with a PT_INTERP yielded a 7MB "library" across its CODE.
 *
 * So the marker tier is asked only when nothing is going to be loaded in
 * beside this file, and the symbol tier - which claims exactly what a symbol
 * covers and nothing between symbols - is asked always.
 */

void sx_lib_facts(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
		      kof_buf buf)
{
	sc->cur.lib.n = 0;
	sc->cur.lib_ok = 0;
	if (kof_src_kind_of(sc->cur.src) == KOF_ENT_NORMALIZED) {
		/*
		 * A VIEW KNOWS WHERE ITS LIBRARY IS BECAUSE IT WAS TOLD.
		 *
		 * The bytes are in it - moved to the end under SLIB_CODE and
		 * SLIB_DATA, see KGENOME_SCAN_ELF_SLIB_CODE - and nothing here can
		 * work them out a second time: kgenome_true_find reads segment
		 * offsets, and a view's headers describe the file before the
		 * transform. The declared table is the answer, and it came from
		 * this same field one object ago.
		 *
		 * WITHOUT THIS THEY ARE THE AUTHOR'S. Every window is then
		 * KGENOME_MUTATION_SIDE_USER, so a block cut from somebody's own code
		 * is credited by libc - which is the one thing the side
		 * mechanism exists to stop. Measured when it was missing: ten
		 * files dropped from infected to suspected, because a rule that
		 * now scored 10 on library bytes reported before the rule that
		 * actually recognised them.
		 */
		uint32_t i;

		for (i = 0; i < sc->cur.n_rgn &&
			    sc->cur.lib.n < KGENOME_TRUE_MAX_SPANS_ALL; i++) {
			if (!(sc->cur.rgn[i].mask &
			      (KGENOME_SCAN_ELF_SLIB_CODE |
			       KGENOME_SCAN_ELF_SLIB_DATA)))
				continue;
			if (!sc->cur.rgn[i].len)
				continue;
			sc->cur.lib.span[sc->cur.lib.n].off =
				sc->cur.rgn[i].off;
			sc->cur.lib.span[sc->cur.lib.n].len =
				sc->cur.rgn[i].len;
			sc->cur.lib.n++;
		}
		sc->cur.lib_ok = sc->cur.lib.n != 0;
		return;
	}
	if (!ctx || ctx->format != KOF_FMT_ELF || !ctx->file_header)
		return;
	if (!buf.p || !buf.n)
		return;
	/* Which tier the object needs is the object's question, answered in one
	 * place - see kgenome_true_find_object. */
	kgenome_true_find_object(buf, kof_elf(ctx), &sc->cur.lib);
	sc->cur.lib_ok = 1;
}
