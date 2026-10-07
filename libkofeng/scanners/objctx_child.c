/*
 * objctx_child.c - declaring and producing a child object.
 *
 * WHAT THIS SERVES: a module that opens, decodes or carves something does not
 * return bytes; it DECLARES a child - its label, kind, entry, format, regions,
 * symbols, what is to be done to it - and emits its bytes, and the engine closes
 * that into one object and queues it. This unit is the whole life of that
 * declaration: the pending set a module writes to (pend_*), the sink its bytes
 * land in, the close (oc_child) that spends everything, and the quota that
 * bounds it (the child cap, the memory ceiling, the per-object cap).
 *
 * THE RULE THAT HOLDS IT TOGETHER: every pending declaration is spent by the
 * child it was written for. kid_push clears the whole pending set (oc_pend_clear);
 * before that was true a second module's child inherited the first one's
 * emulator request and derived_by.
 */

#define _GNU_SOURCE

#include <kofmod/kofsym.h>
#include <kofmod/heur.h>   /* KOF_ENG_USE_EMU - a module's declaration */
#include "../kofcore/kofplatform.h"
#include "../kofcore/kofdebug.h"   /* kof_write_all - the spill file below */
#include "../analyzers/parsers/binaries/elf/elf_sym.h"
#include <kofmod/kofpathogen.h>
#include "../analyzers/parsers/binaries/pe/pe_sym.h"
#include "../analyzers/parsers/binaries/disasm/xref.h"
#include "../disinfect/pzero.h"
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

/* ---- producing child objects ------------------------------------------------ */

/*
 * Where memory stops being the cheaper place to keep the answer.
 *
 * Below this a child is a malloc and a memcpy; above it the bytes go to an unnamed
 * temporary file and are mapped back, so a scan faults in only the pages it reads.
 * It is not a limit - the limits are the two budgets - only a change of storage.
 */
#define SINK_SPILL (1u << 20)

/*
 * The most one produced object may hold. Past it, the object is closed with what it
 * has and the REST OF THAT ENTRY IS DROPPED.
 *
 * Truncation, not chunking, and the difference is the whole point. An entry in a
 * container is a file: it has a header at offset zero and everything else in it is
 * located relative to that header. Cutting it at a byte count and calling the
 * remainder a second object produces something that was never a file - it begins
 * mid-structure, nothing identifies it, so no format is recognised, no region is
 * resolved, and every module that names a format is ruled out before it runs. A
 * stream cut into ten pieces is one object that can be parsed and nine that can
 * only be searched as raw bytes.
 *
 * Keeping the head is what makes the truncated object still worth having: a PE's
 * header, imports, entry point and first sections are all at the front, and so is
 * every structure a detector reads. The tail of an object this large is data.
 *
 * What is given up is real and is reported rather than hidden: an entry longer than
 * this is scanned in part, and the object is marked incomplete. That is the honest
 * trade at this size - an object of this size is almost never a packed executable
 * but an installer or an embedded package, whose interesting parts are entries in
 * their own right and are reached by unpacking it, not by scanning its tail.
 *
 * Clamped to half the resident ceiling below, so the object being built and the one
 * being scanned both fit under it.
 */
/*
 * Sixteen megabytes, and every part of that number was measured.
 *
 * It was 64MB, which is not a ceiling on anything real - it is a ceiling on
 * padding. Across 1352 zip entries in 180 real archives the median entry is 255
 * BYTES and the 95th percentile is 92KB, so 64MB is seven hundred times the
 * percentile that matters and 98.4% of entries never come near it.
 *
 * What it was paying for is the case that dominated the corpus and that nobody
 * would call an attack: a PE inflated with a repeated byte so a scanner with a size
 * limit gives up. One measured sample holds 824KB of DEFLATE expanding to exactly
 * 100MB, of which 95.75% is duplicate 4KB blocks - the whole real program is in the
 * first 2.8MB. That is the shape of the problem, and it is not the bomb the budget
 * was written for: no single object is impossibly expensive, they are each merely
 * expensive enough, and there are thousands of them.
 *
 * WHY NOT LESS. 8MB was tried and it is wrong, which is the useful half of this.
 * It decodes 205MB where 64MB decodes 11292MB and it runs the corpus in 6.70s
 * against 11.42s - and it LOSES A DETECTION. A UPX packed miner of 3.9MB unpacks
 * to 13.1MB, which is not padding: its declared expansion is 3.4x where the padded
 * sample's is 127x. A fixed cap cannot tell those apart, so it has to clear the
 * larger of them.
 *
 * At 16MB the corpus keeps all 52 findings, runs in 7.94s, and decodes 670MB of a
 * document set where 64MB decoded 2542MB. That is the whole of the reasoning: as
 * low as it goes without losing anything that was being found.
 *
 * Losing a tail is reported, never silent - an object cut here is marked as not
 * fully examined with a limit as the reason. A caller who would rather have the
 * whole of a large entry raises max_object_bytes and pays the decompression.
 */
#define KOF_OBJ_CAP (16u << 20)

/*
 * The largest single emit accepted.
 *
 * A decompressor works from lengths written in the file it is decompressing, and a
 * wrong one is the normal hostile case rather than a bug: an entry that declares a
 * gigabyte and holds a kilobyte. The host cannot see how big the module's own
 * buffer is, so it cannot check that the pointer is good for the length - but it
 * can refuse a length no honest caller has, which turns "read a gigabyte from a
 * kilobyte buffer" into a refusal at the first call.
 *
 * A module with more than this to hand over calls again. That is not a burden: a
 * decompressor already works a window at a time.
 */
#define EMIT_MAX (1u << 20)

/*
 * EVERY PENDING DECLARATION, DROPPED.
 *
 * A producer names its next child before it makes it - the label, the kind,
 * the entry index, the format, the region table, the symbol block - and each of
 * those is a claim about ONE child. kid_push spends them as it attaches them,
 * and clears them even when the child is then refused, because the whole
 * failure mode here is a claim outliving the thing it was about and being worn
 * by whatever comes next: a label from another entry, or worse a region table
 * whose offsets are offsets into different bytes.
 *
 * Here rather than written out twice. kof_mod_unpack_mode already spelled the
 * same list for the end of a module, and the two had already drifted - that
 * copy leaves pend_rgn_fmt standing, which is harmless only for as long as
 * nothing reads it without n_pend_rgn.
 */
void oc_pend_clear(struct kof_scanner *sc)
{
	sc->pend_label[0] = 0;
	sc->pend_label_len = 0;
	sc->pend_kind = 0;
	sc->pend_entry = KOF_ENTRY_NONE;
	sc->pend_want = 0;
	sc->pend_want_level = 0;
	sc->pend_n_xw = 0;
	sc->pend_fmt = 0;
	sc->pend_lang = 0;
	sc->pend_subtype = sc->pend_subfam = 0;
	sc->n_pend_rgn = 0;
	sc->pend_rgn_fmt = 0;
	sc->n_pend_syms = 0;
	sc->pend_derived_by = NULL;
	sc->pend_superseded = 0;
	sc->pend_as_fmt = 0;
	sc->pend_as_arch = 0;
	sc->pend_as_base = 0;
	sc->pend_img_fmt = 0;
	sc->n_pend_sec = 0;
	sc->pend_entry_set = 0;
	sc->pend_entry_rva = 0;
	memset(sc->pend_dir, 0, sizeof sc->pend_dir);
	sc->pend_image = 0;
	sc->n_pend_imp = 0;
	sc->imp_pool_n = 0;
	/* Declared per object, like everything else here: a watch one module
	 * named must not still be armed for the next one's run. */
	sc->pend_n_iw = 0;
	sc->pend_iw_len = 0;
	sc->pend_imp_at = 0;
	sc->pend_imp_set = 0;
}

/*
 * The declared sections, as a region partition.
 *
 * ONE MASK PER SECTION, COALESCED WHERE NEIGHBOURS AGREE. The region table has
 * room for KOF_SRC_MAX_REGIONS entries and a split image easily declares more
 * sections than that - mp_split draws up to twelve and a real PE may have
 * ninety-six - so runs of the same kind are joined. They are adjacent by
 * construction: oc_section refuses a section that starts before the previous one
 * ends.
 *
 * PAD AND HOLLOW BECOME UNCLAIMED, which is the whole point of having them.
 * Alignment fill is not DATA - it was being counted as 3972 bytes of it on one
 * sample - and a section with no bytes behind it owns nothing to partition.
 */
/*
 * THE VOCABULARY IS THE FORMAT'S, AND THE TWO DO NOT AGREE PAST THE THIRD BIT.
 *
 * HEADERS, CODE and DATA happen to share their bit numbers between PE and ELF -
 * 1u<<1, 1u<<2, 1u<<3 - and that is a coincidence of two independent choices,
 * not a rule. UNCLAIMED does not: it is 1u<<6 in a PE and 1u<<5 in an ELF,
 * where 1u<<6 is SLIB_CODE and 1u<<5 is OVERLAY. So a table written in one
 * format's words and hung on an object of the other is not slightly wrong, it
 * names a different region - and a module that declared its padding would have
 * had it reported as a static library's code.
 *
 * Which is why this takes the format rather than assuming PE, and why
 * pend_rgn_fmt is set from the same answer.
 */
static void decl_sec_to_regions(struct kof_scanner *sc, uint8_t fmt)
{
	uint32_t i, n = 0;
	uint64_t hdr_end;
	uint32_t m_hdr, m_code, m_data, m_unclaimed;

	if (!sc->pend_sec || !sc->n_pend_sec)
		return;
	if (fmt == KOF_FMT_ELF) {
		m_hdr = KOF_SCAN_ELF_HEADERS;
		m_code = KOF_SCAN_ELF_CODE;
		m_data = KOF_SCAN_ELF_DATA;
		m_unclaimed = KOF_SCAN_ELF_UNCLAIMED;
	} else {
		m_hdr = KOF_SCAN_PE_HEADERS;
		m_code = KOF_SCAN_PE_CODE;
		m_data = KOF_SCAN_PE_DATA;
		m_unclaimed = KOF_SCAN_PE_UNCLAIMED;
	}
	/* Everything before the first section is the header, which no module
	 * declares and every consumer expects. */
	hdr_end = sc->pend_sec[0].rva;
	if (hdr_end && n < KOF_SRC_MAX_REGIONS) {
		sc->pend_rgn[n].mask = m_hdr;
		sc->pend_rgn[n].off = 0;
		sc->pend_rgn[n].len = hdr_end;
		n++;
	}
	for (i = 0; i < sc->n_pend_sec; i++) {
		const struct kof_sec_decl *d = &sc->pend_sec[i];
		uint32_t mask;

		if (d->flags & (KOF_SECF_PAD | KOF_SECF_HOLLOW))
			mask = m_unclaimed;
		else if (d->flags & KOF_SECF_CODE)
			mask = m_code;
		else
			mask = m_data;
		if (n && sc->pend_rgn[n - 1u].mask == mask &&
		    sc->pend_rgn[n - 1u].off + sc->pend_rgn[n - 1u].len ==
		    d->rva) {
			sc->pend_rgn[n - 1u].len += d->vsize;
			continue;
		}
		if (n >= KOF_SRC_MAX_REGIONS) {
			/* The tail of the section table is not in any region, and a
			 * rule scoped to CODE or DATA cannot see it: said, not dropped. */
			oc_scan_capped(sc, KOF_BROKEN_LIMIT);
			break;
		}
		sc->pend_rgn[n].mask = mask;
		sc->pend_rgn[n].off = d->rva;
		sc->pend_rgn[n].len = d->vsize;
		n++;
	}
	sc->n_pend_rgn = n;
	sc->pend_rgn_fmt = fmt;
}

/*
 * THE MODULE'S NAME WHEN THE MODULE NEVER SAID ONE.
 *
 * `kof_db_source` answers where a module's source lives inside the bases tree -
 * "unp/emu_generic_00.c", "decomp/zlibraw.c" - and that was handed to readers
 * as the name of whatever opened an object. It is not a name. It is this
 * project's directory layout on somebody else's screen, and kofviewer showed it
 * in the packer column beside rows that read "MPRESS.PE" and "UPX.PE".
 *
 * A module names itself by the prefix of its first kof_debug note, which is
 * what every module with something to report already does. Eight produce
 * children while reporting nothing - the generic interpreter receiver, the
 * shellcode carver, appended data, bzip2, gzip, the overlay carver, rcpfile
 * and raw zlib - and for those the source stem IS the only name the database
 * carries. So it is reduced to one: the last path component, without its
 * extension and without the "_00" that numbers a module within its family.
 *
 * The result is still derived from a file name, and that is honest - it says
 * the module did not name itself - but it is bounded to a name-shaped word and
 * can never carry a directory.
 */
static void mod_name_of(const char *src, char *out, size_t cap)
{
	const char *b;
	size_t n;

	if (!out || !cap)
		return;
	out[0] = 0;
	if (!src || !*src)
		return;
	for (b = src; *src; src++)
		if (*src == '/' || *src == '\\')
			b = src + 1;
	n = strlen(b);
	if (n > 2u && b[n - 2u] == '.' && b[n - 1u] == 'c')
		n -= 2u;
	/* "_00", "_01": which member of a family, not part of the name. */
	while (n > 1u && b[n - 1u] >= '0' && b[n - 1u] <= '9')
		n--;
	if (n > 1u && b[n - 1u] == '_')
		n--;
	if (!n)
		return;
	if (n >= cap)
		n = cap - 1u;
	memcpy(out, b, n);
	out[n] = 0;
}

/*
 * HOW WIDE THE CHILD IS, which decides the size of a lookup entry and of a
 * thunk - see kof_pe_write_imports.
 *
 * What the module said with kunp_rcstruct_as beats what the parent is, for the
 * reason the header writer gives: a 64-bit payload is routinely carried by a
 * 32-bit container, and nothing else in the child would say so.
 */
static int child_is64(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const struct kof_pe_info *tmpl;

	if (sc && sc->pend_as_fmt == KOF_FMT_PE) {
		if (sc->pend_as_arch == KOF_ARCH_X86_64)
			return 1;
		if (sc->pend_as_arch == KOF_ARCH_X86)
			return 0;
	}
	tmpl = (const struct kof_pe_info *)ctx->file_header;
	return tmpl && tmpl->valid && tmpl->pe32_plus;
}

static int kid_push(struct kof_scanner *sc, struct kof_objsrc *kid)
{
	if (!kid) {
		/*
		 * NO CHILD, AND THE CLAIMS STILL HAVE TO GO.
		 *
		 * This returned without touching them, which is the one path
		 * through this function that let a declaration survive. A
		 * window whose range the object does not hold, or a heap
		 * source that could not be allocated, left the label, the
		 * entry index, the declared format and the region table
		 * standing - and the NEXT child produced, a different entry
		 * entirely, wore all of them.
		 *
		 * Not reported as a limit: a NULL arrives both from an
		 * allocation that failed and from kof_src_window refusing a
		 * range the object does not contain, and the second is an
		 * ordinary answer. Whoever can tell the two apart reports;
		 * see oc_child, which can.
		 */
		oc_pend_clear(sc);
		return 0;
	}
	/*
	 * The pending name belongs to this child and to no other. Consumed whatever
	 * happens next - even if the child is then refused for a limit - because a
	 * name that survived a refusal would be attached to the following child,
	 * which is the one way this could report the wrong entry.
	 */
	if (sc->pend_label_len) {
		/*
		 * THE KIND AND THEN THE NAME, because they answer different
		 * questions and a reader wants both.
		 *
		 * WHAT IT IS comes first and is always there: CONTENT, FONT,
		 * SCRIPT. WHAT IT IS CALLED is an addition - a typeface, a
		 * trigger, a /Type - and it is an addition rather than a
		 * replacement. Using the name alone read "Calibri-Bold" where
		 * the row above it read "CONTENT", so a column that had been
		 * one question became two and the kind of the named rows was
		 * gone.
		 *
		 * Composed HERE so every host spells it the same way. A viewer
		 * that builds this from an entry table and a dump that builds
		 * it from a child were two renderings of one label, and they
		 * had already drifted: one said "FONT Calibri-Bold" and the
		 * other "Calibri-Bold".
		 */
		/*
		 * THE PRODUCER'S NAME, AND ONLY THAT.
		 *
		 * The kind word used to be glued in front of it - "FONT
		 * Calibri-Bold" - so an entry table and a dump would read
		 * alike. They should, and this was the wrong place: the kind
		 * already travels on the object as entry_kind, so writing it
		 * into the NAME makes a second copy that can disagree with
		 * the first. It did - norm_emit labels its view "norm" and
		 * declares the kind NORMALIZED, and the two together came
		 * out as `//0:NORMALIZED norm`.
		 */
		kof_src_label(kid, (const uint8_t *)sc->pend_label,
			      sc->pend_label_len);
		sc->pend_label[0] = 0;
		sc->pend_label_len = 0;
	}
	/*
	 * AND THE KIND TRAVELS ON ITS OWN - the only carrier of that fact,
	 * so a row with no name of its own is drawn from it rather than
	 * having it copied into the name.
	 */
	kof_src_declare_kind(kid, sc->pend_kind);
	sc->pend_kind = 0;
	/* Spent whatever happened to the child, and reset to the sentinel
	 * rather than to zero - zero is entry 0 and is a real answer. */
	kof_src_declare_entry(kid, sc->pend_entry);
	sc->pend_entry = KOF_ENTRY_NONE;
	/* The declared format goes the same way and is cleared the same way,
	 * even on a refusal - a claim left pending would be worn by the next
	 * child, which is a claim about the wrong bytes. */
	if (sc->pend_lang) {
		kof_src_declare_lang(kid, sc->pend_subtype, sc->pend_subfam);
		sc->pend_lang = 0;
		sc->pend_subtype = sc->pend_subfam = 0;
	}
	if (sc->pend_fmt) {
		kof_src_declare_fmt(kid, sc->pend_fmt);
		sc->pend_fmt = 0;
	}
	/* The regions go the same way and are cleared the same way: a table
	 * left pending would be worn by the next child, and its offsets are
	 * offsets into different bytes. */
	/*
	 * SECTIONS BECOME THE REGION TABLE, when a module declared them and did
	 * not declare a region table itself.
	 *
	 * The partition is what every rule is scoped to, and until now the only
	 * way to get one onto a produced child was to synthesise a PE header
	 * and let the engine parse it back. What that loses is measured in
	 * `section` in kofsig.h; this is the other direction, and it is one
	 * pass over a table the module has already filled in.
	 *
	 * A module that declares a region table directly - norm_emit does -
	 * keeps it; the two are not merged, because a caller that said both
	 * meant the explicit one.
	 */
	/*
	 * ONLY FOR A DECLARED PE IMAGE, because the masks are PE's.
	 *
	 * A region bit means nothing on its own - 1u << 5 is UNCLAIMED in an
	 * ELF and OVERLAY in a PE - so a table written in one format's
	 * vocabulary and hung on an object of another is worse than no table.
	 * A producer that declared sections without asking for an image has
	 * described a layout, not a file, and the partition is not derived
	 * from it.
	 */
	if (!sc->n_pend_rgn && sc->n_pend_sec && sc->pend_image)
		decl_sec_to_regions(sc, sc->pend_as_fmt ? sc->pend_as_fmt
							: sc->pend_img_fmt);
	if (sc->n_pend_rgn) {
		kof_src_declare_regions(kid, sc->pend_rgn_fmt, sc->pend_rgn,
					sc->n_pend_rgn);
		sc->n_pend_rgn = 0;
		sc->pend_rgn_fmt = 0;
	}
	if (sc->n_pend_syms) {
		kof_src_declare_syms(kid, sc->pend_syms, sc->n_pend_syms);
		sc->n_pend_syms = 0;
	}
	if (sc->kids_left == 0) {
		/* Refused, and recorded: a container that yields more children than
		 * the caller allows has not been fully examined, and saying so is
		 * the difference between "nothing else here" and "stopped looking". */
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		kof_src_unref(kid);
		return 0;
	}
	if (sc->n_kids == sc->cap_kids) {
		/*
		 * THREE ARRAYS INDEXED BY ONE COUNTER, so they grow together
		 * or not at all - and a growth that fails is a CHILD LOST,
		 * which is the same thing the cap above refuses and has to be
		 * said the same way.
		 *
		 * It was three blocks with a failure path each, and all three
		 * dropped the child without a word: a container whose last
		 * entry could not be recorded reported as fully examined. The
		 * refusal one line up, for a child over the caller's cap, has
		 * the note explaining why that is the difference between
		 * "nothing else here" and "stopped looking" - these are the
		 * same event and were silent.
		 *
		 * cap_kids is committed only once all three have grown. A
		 * partial growth is safe to leave: the arrays are larger than
		 * cap_kids claims, so the next call simply asks for the same
		 * size again.
		 */
		uint32_t nc = sc->cap_kids ? sc->cap_kids * 2 : 8;
		struct kof_objsrc **nv = realloc(sc->kids, nc * sizeof *nv);
		uint8_t *np = NULL;
		const char **nf = NULL;
		uint32_t *nw = NULL, *nl = NULL, *nx = NULL;
		uint64_t *nr = NULL;
		const struct kof_module **nd = NULL;

		if (nv)
			sc->kids = nv;
		if (nv)
			np = realloc(sc->kid_packer, nc * sizeof *np);
		if (np)
			sc->kid_packer = np;
		if (np)
			nf = realloc(sc->kid_family, nc * sizeof *nf);
		if (nf)
			sc->kid_family = nf;
		if (nf)
			nd = realloc(sc->kid_derived_by, nc * sizeof *nd);
		if (nd)
			sc->kid_derived_by = nd;
		if (nd)
			nw = realloc(sc->kid_want, nc * sizeof *nw);
		if (nw)
			sc->kid_want = nw;
		if (nw)
			nl = realloc(sc->kid_want_level, nc * sizeof *nl);
		/* EACH POINTER IS TAKEN THE MOMENT ITS realloc SUCCEEDS, like the
		 * ones above. This one and kid_xw were taken only after every
		 * allocation had worked, so a failure part way returned with
		 * `kid_want_level` still holding a block realloc had already freed. */
		if (nl) {
			sc->kid_want_level = nl;
			nx = realloc(sc->kid_n_xw, nc * sizeof *nx);
		}
		if (nx)
			sc->kid_n_xw = nx;
		if (nx)
			nr = realloc(sc->kid_xw,
				     (size_t)nc * KOF_EMU_EXEC_WATCH * 2u *
				     sizeof *nr);
		if (nr)
			sc->kid_xw = nr;
		if (!nl || !nx || !nr) {
			oc_scan_broken(sc, KOF_BROKEN_LIMIT);
			kof_src_unref(kid);
			return 0;
		}
		sc->cap_kids = nc;
	}
	/*
	 * Which sort of module made this child, recorded as it is made.
	 *
	 * A container's entry and a packer's payload are the same kind of object
	 * to everything downstream, and they are not the same kind of evidence -
	 * see KOF_UNPACK_KIND in kofsig.h.
	 */
	/*
	 * And what the producing module said has to be done to it, spent here
	 * the same way every other pending claim is - see oc_pend_clear on why a
	 * claim may not outlive the one child it was about.
	 */
	sc->kid_want[sc->n_kids] = sc->pend_want;
	sc->kid_want_level[sc->n_kids] = sc->pend_want_level;
	if (sc->kid_n_xw && sc->kid_xw) {
		uint32_t q;

		sc->kid_n_xw[sc->n_kids] = sc->pend_n_xw;
		for (q = 0; q < sc->pend_n_xw; q++) {
			uint64_t *d = sc->kid_xw +
				      (size_t)sc->n_kids * KOF_EMU_EXEC_WATCH *
				      2u + (size_t)q * 2u;

			d[0] = sc->pend_xw[q].rva;
			d[1] = sc->pend_xw[q].len;
		}
	}
	sc->kid_packer[sc->n_kids] =
		(uint8_t)(sc->cur_mod && sc->cur_mod->unp_kind == KOF_UNP_PACKER);
	if (sc->kid_packer[sc->n_kids])
		sc->packed_here = 1;
	/*
	 * The family the producer decodes, so the child can be routed to that
	 * family's decoder first - see the push loop in the walk. NULL when no
	 * module produced it (an emulator image) or the producer declared no
	 * family; empty counts as none, since an unpacker without KOF_TARGET_NAME
	 * interns "".
	 */
	{
		const char *fam = sc->cur_mod
				  ? kof_db_family(sc->eng, sc->cur_mod) : NULL;

		sc->kid_family[sc->n_kids] = (fam && fam[0]) ? fam : NULL;
	}
	/*
	 * AND WHICH MODULE OPENED THE OBJECT THIS CAME OUT OF.
	 *
	 * Recorded here because producing a child is what "opened it" means,
	 * and here is the only place the engine knows both at once: `cur_mod`
	 * is the module running, and the object it is running ON is the one
	 * being scanned. See kof_result.opened_by for why it is the parent
	 * that carries the name and not the child.
	 */
	if (sc->cur_mod && !sc->opened_by[0]) {
		if (sc->mod_tag_of == sc->cur_mod && sc->mod_tag[0]) {
			size_t q = strlen(sc->mod_tag);

			if (q >= KOF_MOD_TAG)
				q = KOF_MOD_TAG - 1u;
			memcpy(sc->opened_by, sc->mod_tag, q);
			sc->opened_by[q] = 0;
		} else {
			mod_name_of(kof_db_source(sc->eng, sc->cur_mod),
				    sc->opened_by, sizeof sc->opened_by);
		}
		/*
		 * AND THE BUILD, WHICH IS ONE ANSWER AND NOT TWO.
		 *
		 * `packer_build` is what a reader is shown, so it is filled
		 * whenever anything opened the object: the module's own claim
		 * when it made one - "PE:MPRESS 2.12-2.19 LZMA", which already
		 * carries the format and the name - and the module's name when
		 * it did not.
		 *
		 * ONE FIELD BECAUSE TWO WERE SHOWN TOGETHER. A tool given both
		 * printed both, and "MPRESS.PE PE:MPRESS 2.12-2.19 LZMA" says
		 * MPRESS twice and PE twice. Whoever consumes this should not
		 * have to decide which of two engine answers to believe.
		 */
		if (sc->pend_build[0] && sc->pend_build_of == sc->cur_mod) {
			size_t q = strlen(sc->pend_build);

			if (q >= sizeof sc->packer_build)
				q = sizeof sc->packer_build - 1u;
			memcpy(sc->packer_build, sc->pend_build, q);
			sc->packer_build[q] = 0;
		} else if (sc->opened_by[0]) {
			size_t q = strlen(sc->opened_by);

			if (q >= sizeof sc->packer_build)
				q = sizeof sc->packer_build - 1u;
			memcpy(sc->packer_build, sc->opened_by, q);
			sc->packer_build[q] = 0;
		}
	}
	/*
	 * AND WHETHER THE INTERPRETER IS WHAT PRODUCED IT.
	 *
	 * `emu_produced` is read in three places - the producer's ask, the
	 * fallback run's gate, and kof_result.emu_unpacked, which is what a
	 * tool uses to know a tree already came from a run - and NOTHING SET
	 * IT. It was cleared per object and read as zero for the life of the
	 * object, every time.
	 *
	 * It dates from when the interpreter made children itself. Under the
	 * object pipeline it does not: a module asks for a run, reads the
	 * regions and declares what it makes of them - see `emu_run` in
	 * kofsig.h - so the only thing that knows a child came out of a run is
	 * the push, while the machine is still live.
	 *
	 * What it cost, measured: kofviewer's "dump with emulator" re-ran the
	 * whole thing on a tree that had already come from a run, because
	 * emu_unpacked said it had not - 17 seconds and 207 million
	 * instructions on a PECompact2 sample, for bytes it already had. And
	 * the two gates that read it were no-ops, so an object whose payload a
	 * run had already recovered could still be handed to a second one.
	 */
	if (sc->emu_run_by && sc->emu_run_by == sc->cur_mod)
		sc->emu_produced = 1;
	/*
	 * AND A CHILD BUILT OUT OF A RUN'S REGIONS IS DERIVED, exactly as one
	 * built with `derive` is - see scan.c, which skips a module for an
	 * object that module produced.
	 *
	 * Only `derive` used to say so, and every emulator-driven unpacker
	 * builds its child the other way: declare sections, take the regions,
	 * close. So the engine handed each of them its own output back and the
	 * module ran the interpreter on it AGAIN. Measured on a Sality sample:
	 * a second invocation, seventeen slices, sixty-eight million
	 * instructions, a duplicate child, and no finding - roughly half the
	 * file's scan time spent proving what the first run had proved.
	 *
	 * THE EXISTING ARGUMENT FOR OFFERING A REBUILT IMAGE TO EVERYONE STILL
	 * HOLDS AND IS NOT TOUCHED. Every OTHER module still sees this child;
	 * MPRESS under MPRESS is still unpacked twice, because that is a
	 * different layer and the second pass is a different call. What stops
	 * is a module meeting its own output, which for an interpreter is
	 * never a second layer - the run already went through as many as it
	 * was going to.
	 */
	if (sc->emu_run_by && sc->emu_run_by == sc->cur_mod &&
	    !sc->pend_derived_by)
		sc->pend_derived_by = sc->cur_mod;
	if (sc->kid_derived_by)
		sc->kid_derived_by[sc->n_kids] = sc->pend_derived_by;
	sc->kids[sc->n_kids++] = kid;
	sc->kids_left--;
	/*
	 * EVERYTHING DECLARED FOR THIS CHILD IS SPENT WITH IT. The label, kind,
	 * entry, language, format, regions and symbols were cleared one by one
	 * above, and the rest - what to do to it (want, xw), who derived it, the
	 * image it becomes (as_*, sections, directories, imports), the watch an
	 * interpreter was armed with - were copied and left standing, against what
	 * the comment on the copy says ("spent here the same way every other pending
	 * claim is"). A second module producing a child in the same turn inherited
	 * the first's emulator request and its `derived_by`, and so was hidden from
	 * the module that should have been offered it. oc_pend_clear is the one list of
	 * what a pending claim is.
	 */
	if (sc->pend_superseded)
		sc->superseded = 1;
	oc_pend_clear(sc);
	return 1;
}

/*
 * Give produced bytes back to the memory ceiling.
 *
 * Hooked to the destruction of every produced source rather than called from the
 * scan loop, so the count falls on every path a child can die on - scanned and
 * released, refused by the child cap, abandoned by an aborted walk - and not only
 * on the one that was remembered.
 *
 * Two spellings because kof_src_on_free takes a void *. Casting this function to
 * that signature and calling through the cast is a call through an incompatible
 * pointer type, which is undefined however reliably it works; a wrapper costs
 * nothing and is simply correct.
 */
void oc_scan_release(struct kof_scanner *sc, uint64_t produced)
{
	sc->resident = produced < sc->resident ? sc->resident - produced : 0;
}

static void scan_release_cb(void *sc, uint64_t produced)
{
	oc_scan_release(sc, produced);
}

/*
 * The other two thirds of the residency account, which every allocating path
 * below was spelling out for itself.
 *
 * There were nine copies of the charge and eight of the headroom question, and
 * they had already drifted: one charge forgot the peak entirely, so the figure
 * a caller reads back as "the most this scan ever held" was short by whatever
 * the RAR filter's scratch was. That is the ordinary fate of an invariant
 * written out by hand in nine places - it is not that any copy is hard, it is
 * that nothing makes the ninth one match the other eight.
 *
 * oc_scan_release is the third and already existed; it also SATURATES, which a
 * bare `sc->resident -= n` does not, so routing the uncharges through it means
 * a mispaired release cannot wrap the count to near 2^64 and refuse every
 * allocation for the rest of the scan.
 */
uint64_t oc_scan_room(const struct kof_scanner *sc)
{
	return sc->resident < sc->resident_max
	     ? sc->resident_max - sc->resident : 0;
}

void oc_scan_charge_(struct kof_scanner *sc, uint64_t n)
{
	sc->resident += n;
	if (sc->resident > sc->st.peak_resident)
		sc->st.peak_resident = sc->resident;
}

/* Which build of the packer - see `packer_build` in kofsig.h. */
void oc_packer_build(const struct kof_obj_ctx *ctx, const char *build)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	size_t i;

	if (!sc || !build)
		return;
	/* Held until this module produces something - see pend_build. */
	for (i = 0; i + 1u < sizeof sc->pend_build && build[i]; i++)
		sc->pend_build[i] = build[i];
	sc->pend_build[i] = 0;
	sc->pend_build_of = sc->cur_mod;
}

/* What the declared image becomes - see `as_format` in kofsig.h. */
void oc_as_format(const struct kof_obj_ctx *ctx, uint8_t fmt,
			uint8_t arch, uint64_t base)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc)
		return;
	sc->pend_as_fmt = fmt;
	sc->pend_as_arch = arch;
	sc->pend_as_base = base;
}

void oc_supersede(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (sc)
		sc->pend_superseded = 1;        /* committed by kid_push */
}

void oc_child_want(const struct kof_obj_ctx *ctx, uint32_t want,
			 uint32_t level)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc)
		return;
	sc->pend_want = want;
	sc->pend_want_level = level;
}

int oc_window(const struct kof_obj_ctx *ctx, uint64_t off, uint64_t len)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!oc_can_produce(sc))
		return 0;
	return kid_push(sc, kof_src_window(sc->cur_src, off, len));
}

/* Move whatever is in memory out to the descriptor, and keep writing there. */
static int sink_spill(struct kof_scanner *sc)
{
	if (sc->sink_fd < 0) {
		sc->sink_fd = kof_src_tmpfile();
		if (sc->sink_fd < 0)
			return 0;
	}
	if (sc->sink_len) {
		if (!kof_write_all(sc->sink_fd, sc->sink_mem, sc->sink_len))
			return 0;
		sc->sink_spilled += sc->sink_len;
		sc->sink_len = 0;
	}
	return 1;
}

/*
 * Bytes that did not exist before.
 *
 * The budget is charged HERE, at the write, and that placement is the whole point.
 * Checking a size after decompressing means the memory has already been spent, and
 * a declared size cannot be checked instead because the file declares it. A module
 * has no way to produce output except through this call, so it has no way to
 * produce output without spending budget - the same reason the bounds check on
 * find_str_at lives in the host.
 */
int oc_emit(const struct kof_obj_ctx *ctx, const void *bytes, uint32_t n)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!oc_can_produce(sc))
		return 0;
	if (n == 0)
		return 1;
	/*
	 * A FIXED SINK IS WRITTEN AT A CURSOR, NOT APPENDED TO.
	 *
	 * The extent is already the right size - it is a copy of the parent, or
	 * an image laid out from declared sections - so an emit places bytes
	 * rather than growing anything, and running past the end is a refusal
	 * and not a reallocation.
	 *
	 * This is what lets a decompressor write into a section. oc_unpack and
	 * every decoder behind it hand their output to oc_emit; moving the
	 * cursor with kunp_rcstruct_at is the whole of "decompress to this address",
	 * and no decoder has to know it happened.
	 */
	if (sc->sink_fixed) {
		/*
		 * BOUNDED BY WHAT WAS ALLOCATED, NOT BY WHAT IS CURRENTLY IN
		 * USE, and the two stopped being the same when
		 * layout_of_produced started cutting.
		 *
		 * The extent is the span the module declared and it does not
		 * move. `sink_len` is how much of it counts as the child, and
		 * layout_of_produced lowers it to where the image's own header
		 * says the image ends. A module that then folds something in
		 * BEHIND the image - emu_harvest.h does, with the pages a run
		 * wrote outside it - is writing inside the extent it paid for
		 * and must not be refused for it. Measured: bounded by
		 * sink_len, every surplus page of 007 Spy.exe was refused at
		 * the first byte and the child came out with the image alone.
		 */
		if (sc->sink_at > sc->sink_cap ||
		    n > sc->sink_cap - sc->sink_at)
			return 0;
		memcpy(sc->sink_mem + sc->sink_at, bytes, n);
		sc->sink_at += n;
		if (sc->sink_at > sc->sink_len)
			sc->sink_len = sc->sink_at;
		return 1;
	}
	/* A length out of a file, refused before it is used to read anything. */
	if (n > EMIT_MAX) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	/* Total work over the whole tree: the bomb defence. Cuts rather than
	 * discards, for the same reason the memory ceiling does - what has already
	 * been decompressed is a real prefix and is worth scanning. */
	if (n > sc->budget) {
		oc_child(ctx);
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	/*
	 * Memory right now: the hard one. Everything produced and still alive,
	 * including what has been written to a temporary file, because that file is
	 * very often on tmpfs and is memory there.
	 *
	 * Hitting it CUTS rather than discards. What has been decompressed so far is
	 * a real prefix of a real object and is worth scanning; throwing it away to
	 * refuse the next byte would mean a container slightly over the ceiling
	 * yielded nothing at all, which is the worst of both - the work was done and
	 * the answer was dropped. So the part in hand is closed as a child, and the
	 * object is marked as not fully examined.
	 *
	 * Residency does not fall here. These children are still pending, and only
	 * come off the count once the walk has scanned and released each of them -
	 * by which time this module has returned. That is the whole reason a cut is
	 * the right answer and "wait for room" is not.
	 */
	/*
	 * Two ceilings, one action. The object cap says this object has enough of
	 * the entry to be worth scanning; the resident ceiling says there is no
	 * memory to hold more of it. Either way what is in hand is closed as a
	 * child and the module is told no.
	 *
	 * Telling it matters: a decompressor that gets a zero stops working on this
	 * entry and moves to the next one, which is what should happen. A module
	 * that ignores the answer and emits again simply gets another zero - the
	 * sink is empty by then, and oc_child makes no child out of nothing.
	 */
	/*
	 * BY SUBTRACTION, because `n` crosses the module ABI.
	 *
	 * sink_len and sink_spilled are the host's own and stay under obj_cap,
	 * but `n` is a length a module passed in, and the sum of three size_t
	 * is the one part of this test that a single bogus length can turn
	 * from a refusal into a pass.
	 */
	if (sc->sink_len + sc->sink_spilled > sc->obj_cap ||
	    n > sc->obj_cap - (sc->sink_len + sc->sink_spilled) ||
	    sc->resident > sc->resident_max ||
	    n > sc->resident_max - sc->resident) {
		oc_child(ctx);
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	if (sc->sink_len + n > SINK_SPILL && !sink_spill(sc)) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	if (sc->sink_fd >= 0) {
		if (write(sc->sink_fd, bytes, n) != (ssize_t)n) {
			/* A short write is almost always a full tmpfs. Recorded, not
			 * swallowed: silently keeping a truncated object would report
			 * a prefix of a file as if it were the file. */
			oc_scan_broken(sc, KOF_BROKEN_LIMIT);
			return 0;
		}
		sc->sink_spilled += n;
	} else {
		if (sc->sink_len > sc->sink_cap ||
		    n > sc->sink_cap - sc->sink_len) {
			size_t nc = sc->sink_cap ? sc->sink_cap : 4096;
			uint8_t *nb;

			while (nc < sc->sink_len + n) {
				if (nc > (size_t)-1 / 2u) {
					oc_scan_broken(sc, KOF_BROKEN_LIMIT);
					return 0;
				}
				nc *= 2;
			}
			nb = realloc(sc->sink_mem, nc);
			if (!nb) {
				oc_scan_broken(sc, KOF_BROKEN_LIMIT);
				return 0;
			}
			sc->sink_mem = nb;
			sc->sink_cap = nc;
		}
		memcpy(sc->sink_mem + sc->sink_len, bytes, n);
		sc->sink_len += n;
	}

	/*
	 * Charged only now, with the bytes actually stored.
	 *
	 * Charging before the write left the count standing when the write failed,
	 * and the ceiling shrank a little for every failure - a limit that tightens
	 * itself over a long scan is a limit nobody can predict.
	 */
	sc->budget -= n;
	scan_charge(sc, n);

	return 1;
}

/*
 * A whole buffer through oc_emit, which takes a uint32 and refuses more than
 * EMIT_MAX at a time.
 *
 * This loop was written out five times - after a buffered decode, after a text
 * coding, after a BCJ2 folder, after a STORED join, and for an emulator image -
 * and three of the five spelled the chunk as a bare `1u << 20` rather than as
 * EMIT_MAX. They are the same number today; nothing made them stay that way,
 * and a change to EMIT_MAX would have moved two of the five.
 *
 * Answers HOW MUCH the sink took, because that is what every caller went on to
 * report: a short count is the sink refusing, which is a real and expected
 * answer here - the budget, the object cap and the resident ceiling all arrive
 * as one.
 */
uint64_t oc_emit_all(const struct kof_obj_ctx *ctx, const uint8_t *p,
			 uint64_t n)
{
	uint64_t at = 0;

	while (at < n) {
		uint64_t chunk = n - at;

		if (chunk > EMIT_MAX)
			chunk = EMIT_MAX;
		if (!oc_emit(ctx, p + at, (uint32_t)chunk))
			break;
		at += chunk;
	}
	return at;
}

/*
 * Decompression, as a host service.
 *
 * The decoder writes into the same sink an ordinary emit does, so nothing here
 * enforces a limit: oc_emit already refuses past the object cap, past the resident
 * ceiling and past the total budget, and a refusal propagates back as a zero from
 * the sink, which stops the decoder where it stands. That is the property worth
 * stating plainly - a decompression bomb is not recognised, it is simply a stream
 * whose sink stops accepting, and it costs the same as any other stream that is
 * cut short.
 */
/* Close the object being emitted and start the next. */
int oc_child(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_objsrc *kid;
	uint64_t held;

	if (!sc->cur_src)
		return 0;
	if (sc->sink_len + sc->sink_spilled == 0)
		return 0;              /* nothing was emitted; not a child */

	/*
	 * THE HEADER, WRITTEN HERE AND NOWHERE ELSE - see oc_image.
	 *
	 * Last, because a declaration is allowed to be corrected until the
	 * child closes: the entry point is often readable only after the
	 * content exists, and a section's kind only after it has been filled.
	 * mpress_pe.c does both by hand today, through thirteen
	 * kunp_rcstruct_poke calls into a header it wrote itself.
	 */
	if (sc->pend_image && sc->sink_mem && sc->n_pend_sec) {
		const struct kof_pe_info *tmpl =
			(const struct kof_pe_info *)ctx->file_header;
		uint64_t span = sc->pend_sec[sc->n_pend_sec - 1u].rva +
				sc->pend_sec[sc->n_pend_sec - 1u].vsize;
		uint64_t entry = sc->pend_entry_set ? sc->pend_entry_rva : 0;
		int ok;

		/*
		 * THE IMPORT DIRECTORY FIRST, BECAUSE THE HEADER POINTS AT IT.
		 *
		 * Written here and not when the module declared it, for the
		 * reason the header is written here: a declaration may be
		 * corrected until the child closes, and the table's size is
		 * not settled until the last entry is in.
		 *
		 * BEFORE the header, because the directory entry it sets is
		 * one of the header's own fields - see the pend_dir walk in
		 * kof_pe_write_hdr. Written after, the header would carry
		 * whatever the parent's import directory said, which points
		 * into the PACKER's sections and not into this child's.
		 *
		 * A failure here is not silent and not fatal to the child: the
		 * bytes it would have written are untouched - see
		 * kof_pe_write_imports, which changes nothing unless the whole
		 * table fits - and no directory is set, so the child goes out
		 * as an image with no imports rather than as one pointing at
		 * a table that is not there.
		 */
		if (sc->pend_imp_set && sc->n_pend_imp) {
			uint64_t n = kof_pe_write_imports(sc->sink_mem,
							  sc->sink_len,
							  sc->pend_imp_at,
							  sc->pend_imp,
							  sc->n_pend_imp,
							  sc->imp_pool,
							  sc->imp_pool_n,
							  child_is64(ctx));

			if (n && sc->pend_imp_at < span &&
			    KOF_PE_DIR_IMPORT < 16u) {
				sc->pend_dir[KOF_PE_DIR_IMPORT].rva =
					sc->pend_imp_at;
				sc->pend_dir[KOF_PE_DIR_IMPORT].size = n;
				sc->pend_dir[KOF_PE_DIR_IMPORT].set = 1;
			}
		}

		/*
		 * WHAT THE MODULE SAID, OR WHAT THE PARENT IS.
		 *
		 * A packer's child is the parent's own image and the parent's
		 * header is the template; that is the `as_fmt == 0` case and it
		 * is the common one. A DECODER's child is shellcode, which is
		 * no format at all until somebody says which one it should
		 * become - and after the first layer the parent is formatless,
		 * so only the module can say. See `as_format` in kofsig.h.
		 */
		if (sc->pend_as_fmt == KOF_FMT_ELF) {
			int is64 = sc->pend_as_arch == KOF_ARCH_X86_64;
			uint16_t mach = (uint16_t)(is64 ? 62u : 3u);

			ok = kof_elf_write_hdr(sc->sink_mem,
					       sc->pend_sec[0].rva, is64, mach,
					       sc->pend_as_base, sc->pend_sec,
					       sc->n_pend_sec, entry,
					       sc->pend_entry_set,
					       span) != 0;
		} else {
			/*
			 * AND FOR PE, WHAT THE MODULE SAID ABOUT WIDTH AND
			 * BASE BEATS WHAT THE PARENT IS.
			 *
			 * The ELF arm above has always read pend_as_arch and
			 * pend_as_base; this one read neither, so a module
			 * could declare KOF_FMT_PE and have its architecture
			 * silently ignored. That is not hypothetical - it is
			 * the reason msf_pe.h wrote its own header instead of
			 * declaring one: msfvenom's 64-bit Windows payload is
			 * routinely carried by a PE32 template, and a payload
			 * described as i386 is disassembled and prefiltered as
			 * i386.
			 *
			 * A COPY OF THE TEMPLATE, not a change to the writer's
			 * arguments. The template is the parent's parse and
			 * supplies subsystem, characteristics and the
			 * directories; only the three fields the module
			 * actually spoke about move. Anything but x86 and
			 * x86-64 leaves all three alone - the declaration
			 * cannot say more than the writer can express, and
			 * guessing a machine number for an architecture this
			 * builds no PE for would be inventing one.
			 */
			struct kof_pe_info as_pe;
			const struct kof_pe_info *use = tmpl;

			if (tmpl && tmpl->valid &&
			    sc->pend_as_fmt == KOF_FMT_PE &&
			    (sc->pend_as_arch == KOF_ARCH_X86 ||
			     sc->pend_as_arch == KOF_ARCH_X86_64)) {
				int is64 = sc->pend_as_arch == KOF_ARCH_X86_64;

				as_pe = *tmpl;
				as_pe.pe32_plus = (uint8_t)(is64 ? 1 : 0);
				as_pe.machine = (uint16_t)(is64 ? 0x8664u
								: 0x014cu);
				if (sc->pend_as_base)
					as_pe.image_base = sc->pend_as_base;
				use = &as_pe;
			}
			ok = (ctx->format == KOF_FMT_PE || sc->pend_as_fmt ==
							   KOF_FMT_PE) &&
			     use && use->valid &&
			     kof_pe_write_hdr(sc->sink_mem,
					      sc->pend_sec[0].rva, use,
					      sc->pend_sec, sc->n_pend_sec,
					      entry, span, sc->pend_dir) != 0;
		}
		if (!ok) {
			/*
			 * A declared image whose header will not fit, or whose
			 * parent is not a PE, is not handed over as a headless
			 * blob: the module asked for a file and got none, and
			 * saying so is the only honest answer.
			 */
			oc_scan_broken(sc, KOF_BROKEN_DAMAGED);
			return 0;
		}
	}

	if (sc->sink_fd >= 0) {
		if (!sink_spill(sc))
			return 0;
		held = sc->sink_spilled;
		kid = kof_src_fd(sc->sink_fd, sc->sink_spilled);
		sc->sink_fd = -1;
		sc->sink_spilled = 0;
	} else {
		held = sc->sink_len;
		kid = kof_src_heap(sc->sink_mem, sc->sink_len);
		sc->sink_mem = NULL;
		sc->sink_cap = 0;
	}
	sc->sink_len = 0;
	sc->sink_fixed = 0;
	sc->sink_at = 0;

	/*
	 * The bytes were charged to the sink and are now the child's. Ownership of
	 * the debt moves with them: from here on the count falls when the child is
	 * destroyed, wherever that happens - scanned and released, refused by the
	 * child cap, or abandoned because the walk was aborted.
	 */
	if (!kid) {
		/*
		 * A WHOLE DECODED OBJECT, GONE, AND IT HAS TO SAY SO.
		 *
		 * Unlike kid_push's NULL - which is also how a window refuses
		 * a range - there is no ordinary reason to be here: the bytes
		 * were produced, they were charged, and the only thing that
		 * failed is the constructor. Returning quietly meant a
		 * container whose entry decoded perfectly and then could not
		 * be wrapped was reported as having nothing in it.
		 */
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		oc_scan_release(sc, held);
		return 0;
	}
	kof_src_on_free(kid, scan_release_cb, sc);
	return kid_push(sc, kid);
}

/*
 * Join a named region into the object being produced.
 *
 * The whole of it is a resolve and a loop of emits, and that is the point: the
 * bytes never leave the host, so a gather is charged, cut and refused by exactly
 * the code that already does that for a decompression. There is no second budget
 * and no path by which a module can assemble more than the ceiling allows.
 *
 * `cap` is the module's own limit and only ever tightens the host's. Applied to
 * what THIS call produces rather than to the object being built, so a module
 * gathering two regions into one child gets a limit per region - which is what a
 * caller means by it, since the sizes it knows are per region.
 *
 * A short return is not an error and is not reported as one: the module asked for a
 * region and got a prefix of it. Whether that is worth calling the object broken is
 * the module's judgement, because only it knows whether the rest mattered.
 */
uint64_t oc_gather(const struct kof_obj_ctx *ctx, uint32_t mask, uint64_t cap)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_range *ext = sc->ext_gather;
	kof_buf b = oc_mc(ctx)->data;
	uint64_t done = 0;
	uint32_t n, i;

	if (!oc_can_produce(sc))
		return 0;

	n = kof_scan_resolve_range(ctx, mask, ext);
	for (i = 0; i < n; i++) {
		kof_buf s = kof_slice(b, ext[i].off, ext[i].len);
		uint64_t at = 0;

		while (at < s.n) {
			uint64_t want = s.n - at;

			if (want > EMIT_MAX)
				want = EMIT_MAX;
			if (cap) {
				if (done >= cap)
					return done;
				if (want > cap - done)
					want = cap - done;
			}
			if (!oc_emit(ctx, s.p + at, (uint32_t)want))
				return done;
			at += want;
			done += want;
		}
	}
	return done;
}

/*
 * Name the next child, from bytes in the object being unpacked.
 *
 * A bounded copy and nothing else. Making the bytes safe to print is NOT done here:
 * it happens once, in kof_src_label, which is the only way a label is ever set. Two
 * places doing it would look like defence in depth and would be the opposite - with
 * both present, breaking either one changes nothing observable, so neither is
 * covered by a test and neither can be shown to work. One place, and the test that
 * mutates it fails.
 */
/*
 * What the next child is, from a producer that knows.
 *
 * A store and nothing else; kid_push is what spends it, and clears it whether
 * the child was accepted or refused. Unconditional like oc_name_next: a call
 * with KOF_FMT_UNKNOWN is a producer saying "I will not name this one", and it
 * has to CLEAR what a previous call left rather than leave it standing.
 */
void oc_child_format(const struct kof_obj_ctx *ctx, uint8_t fmt)
{
	kof_scan_of(ctx)->pend_fmt = fmt;
}

/* What the next child is for. Stored and spent by kid_push, like the two
 * beside it, and cleared there whatever happens to the child. */
void oc_child_kind(const struct kof_obj_ctx *ctx, uint32_t kind)
{
	kof_scan_of(ctx)->pend_kind = kind;
}

/* Which entry the next child is the content of. Stored and spent by kid_push,
 * like the two beside it. */
void oc_child_entry(const struct kof_obj_ctx *ctx, uint32_t index)
{
	kof_scan_of(ctx)->pend_entry = index;
}

void oc_note_next(const struct kof_obj_ctx *ctx, const char *text)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	size_t n;

	if (!text || !*text)
		return;
	n = strlen(text);
	if (n > KOF_SRC_LABEL_MAX - 1u)
		n = KOF_SRC_LABEL_MAX - 1u;
	memcpy(sc->pend_label, text, n);
	sc->pend_label[n] = 0;
	sc->pend_label_len = (uint32_t)n;
}

/*
 * The child as it stands: whatever has spilled to the file, then whatever is
 * still in memory behind it. One address space to the module - see
 * produced_read in kofsig.h.
 */
uint32_t oc_produced_read(const struct kof_obj_ctx *ctx, uint64_t off,
				void *out, uint32_t cap)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint64_t total = sc->sink_spilled + sc->sink_len;
	uint32_t got = 0;

	if (!out || !cap || off >= total)
		return 0;
	if ((uint64_t)cap > total - off)
		cap = (uint32_t)(total - off);
	if (off < sc->sink_spilled && sc->sink_fd >= 0) {
		uint64_t n = sc->sink_spilled - off;

		if (n > cap)
			n = cap;
		got = (uint32_t)kof_pos_io(sc->sink_fd, off, out, n, 0);
		if (got < n)
			return got;             /* short read: say so */
	}
	if (got < cap && sc->sink_mem) {
		uint64_t at = off + got - sc->sink_spilled;
		uint32_t n = cap - got;

		if (at + n > sc->sink_len)
			n = (uint32_t)(sc->sink_len - at);
		memcpy((uint8_t *)out + got, sc->sink_mem + at, n);
		got += n;
	}
	return got;
}

/* And the same span, written over. Never past what exists. */
int oc_produced_poke(const struct kof_obj_ctx *ctx, uint64_t off,
			   const void *bytes, uint32_t n)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint64_t total = sc->sink_spilled + sc->sink_len;
	uint32_t did = 0;

	if (!bytes || !n || off >= total || (uint64_t)n > total - off)
		return 0;
	if (off < sc->sink_spilled && sc->sink_fd >= 0) {
		uint64_t k = sc->sink_spilled - off;

		if (k > n)
			k = n;
		did = (uint32_t)kof_pos_io(sc->sink_fd, off,
					   (void *)(uintptr_t)bytes, k, 1);
		if (did < k)
			return 0;
	}
	if (did < n && sc->sink_mem) {
		uint64_t at = off + did - sc->sink_spilled;

		memcpy(sc->sink_mem + at, (const uint8_t *)bytes + did,
		       n - did);
	}
	return 1;
}

/*
 * THE PARENT AGAIN, AS THE START OF THIS CHILD - see `derive` in kofsig.h.
 *
 * Emitted through the ordinary path rather than handed over by reference, so
 * every budget sees a child the size of its parent, which is what it is. The
 * saving this is for is not memory - it is that the module stops having to
 * re-emit bytes it is not changing, and with them the sort and the overlap
 * resolution it was getting wrong: measured on strxor_tab_00.c, once dropping
 * 114353 bytes and once letting an over-long record swallow its neighbour.
 *
 * REFUSED ON A SINK THAT IS NOT EMPTY. Deriving says where the child STARTS;
 * after anything has been emitted it would mean appending a copy of the parent
 * to it, which no caller wants and which would silently double an object.
 */
/*
 * ---- WHAT A MODULE DECLARES ABOUT THE CHILD IT IS BUILDING ------------------
 *
 * See `section` in kofsig.h for why these exist rather than a synthesised
 * header. The table is the module's statement; nothing here writes a container
 * out of it, and nothing here parses one back.
 */
#define DECL_SEC_MAX 96u        /* what a PE may declare, which is the most any
				 * producer here has reason to */

/*
 * ---- WHAT THE CHILD IMPORTS - see `import` in kofsig.h ---------------------
 *
 * The bounds are the same kind the section table has and are chosen the same
 * way: from what the one container doing this actually holds. MPRESS's hint
 * list is capped at 32 libraries and 512 functions by the module that reads
 * it, so a table of 1024 entries cannot be filled by it, and the pool holds
 * every name those entries can carry at the 64-byte cap that module enforces.
 * A container that wanted more would be refused here and would say so, which
 * is the behaviour a cap is for.
 */
#define DECL_IMP_MAX  1024u
#define DECL_POOL_MAX (64u * 1024u)

/* Put a string in the pool once, and answer where it is. The same library name
 * arrives once per function it exports, so interning is not an economy - it is
 * what keeps the pool bounded by the NUMBER of names rather than by the number
 * of entries. */
static int imp_intern(struct kof_scanner *sc, const char *s, uint32_t *off)
{
	uint32_t k, n = 0;

	if (!s)
		return 0;
	while (s[n]) {
		if (n >= DECL_POOL_MAX)
			return 0;
		n++;
	}
	if (!n)
		return 0;
	for (k = 0; k + n < sc->imp_pool_n; k++)
		if (!memcmp(sc->imp_pool + k, s, n) && !sc->imp_pool[k + n]) {
			*off = k;
			return 1;
		}
	if (sc->imp_pool_n + n + 1u > DECL_POOL_MAX)
		return 0;
	memcpy(sc->imp_pool + sc->imp_pool_n, s, n);
	sc->imp_pool[sc->imp_pool_n + n] = 0;
	*off = sc->imp_pool_n;
	sc->imp_pool_n += n + 1u;
	return 1;
}

/* Defined with kof_scan_emu_unpack, which is the other caller. */

int oc_import(const struct kof_obj_ctx *ctx, const char *dll,
		    const char *fn, uint32_t ordinal, uint64_t iat_rva)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_imp_decl *d;
	uint32_t dll_off = 0, fn_off = 0;

	if (!sc || !dll || !*dll)
		return 0;
	/* One or the other, never both and never neither - a PE import is a
	 * name or a number, and an entry that is neither describes nothing. */
	if ((ordinal != 0) == (fn != NULL && *fn != 0))
		return 0;
	if (ordinal > 0xffffu)
		return 0;
	if (!sc->pend_imp) {
		sc->pend_imp = calloc(DECL_IMP_MAX, sizeof *sc->pend_imp);
		sc->imp_pool = calloc(DECL_POOL_MAX, 1u);
		if (!sc->pend_imp || !sc->imp_pool)
			return 0;
	}
	/* Refused for room, and said: a module building an import table that
	 * does not fit gets 0 back and the child would otherwise be written with
	 * the entries it did not know were missing. */
	if (sc->n_pend_imp >= DECL_IMP_MAX) {
		oc_scan_capped(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	if (!imp_intern(sc, dll, &dll_off) ||
	    (!ordinal && !imp_intern(sc, fn, &fn_off))) {
		oc_scan_capped(sc, KOF_BROKEN_LIMIT);
		return 0;
	}

	d = &sc->pend_imp[sc->n_pend_imp++];
	d->iat_rva = iat_rva;
	d->dll_off = dll_off;
	d->fn_off = fn_off;
	d->ordinal = (uint16_t)ordinal;
	d->_pad = 0;
	return 1;
}

uint64_t oc_import_bytes(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc || !sc->n_pend_imp)
		return 0;
	return kof_pe_imports_size(sc->pend_imp, sc->n_pend_imp,
				   sc->imp_pool, sc->imp_pool_n,
				   child_is64(ctx));
}

/*
 * A SECTION NAME, EIGHT BYTES AT MOST, taken from whatever the module passed.
 * The loop it replaces read `name[w]` for w up to seven whatever the string's
 * length, so a short name was read past its terminator at the one boundary this
 * file exists to harden - and the bytes after it were copied into the table.
 */
static void sec_name_copy(char dst[9], const char *name)
{
	unsigned w = 0;

	if (name)
		for (; w < 8u && name[w]; w++)
			dst[w] = name[w];
	for (; w < 9u; w++)
		dst[w] = 0;
}

/*
 * WHERE THE TABLE GOES, AND THE ROOM FOR IT, WHICH IS ONE ACT AND NOT TWO.
 *
 * A module says "put it here" and the engine writes it when the child closes -
 * but the child's buffer was sized before any of this was knowable, from the
 * sections declared to oc_image, and the table does not fit in it.
 *
 * Measured on 445.exe: the payload is cut back to where the image ends by
 * layout_of_produced, leaving about 2.7 KB of the allocation spare, and the
 * table for its 349 imports needs about 7.8 KB. Asking the module to reserve
 * the room itself is not possible - it cannot know the size until it has
 * declared every import, and by then the buffer exists.
 *
 * So the reservation happens here, where both facts are in hand: the engine
 * computed the size and the engine owns the buffer. It is a bounded, one-time
 * growth for a table the engine is about to write, charged to the same budget
 * as everything else, and refused by the same ceilings.
 */
int oc_import_at(const struct kof_obj_ctx *ctx, uint64_t rva)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint64_t need, end;

	if (!sc || !sc->n_pend_imp || !sc->sink_fixed || !sc->sink_mem)
		return 0;
	need = kof_pe_imports_size(sc->pend_imp, sc->n_pend_imp,
				   sc->imp_pool, sc->imp_pool_n,
				   child_is64(ctx));
	if (!need)
		return 0;
	end = rva + need;
	if (end < rva)
		return 0;
	if (end > sc->sink_cap) {
		uint64_t add = end - sc->sink_cap;
		uint8_t *mem;

		if (end > sc->obj_cap || add > sc->budget ||
		    sc->resident > sc->resident_max ||
		    add > sc->resident_max - sc->resident) {
			oc_scan_broken(sc, KOF_BROKEN_LIMIT);
			return 0;
		}
		mem = realloc(sc->sink_mem, (size_t)end);
		if (!mem) {
			oc_scan_broken(sc, KOF_BROKEN_LIMIT);
			return 0;
		}
		/* The tail has never been written and must not be whatever the
		 * allocator had there: the table does not fill it exactly and
		 * the rest goes into the child. */
		memset(mem + sc->sink_cap, 0, (size_t)add);
		sc->sink_mem = mem;
		sc->sink_cap = (size_t)end;
		sc->budget -= add;
		scan_charge(sc, add);
	}
	if (end > sc->sink_len)
		sc->sink_len = (size_t)end;
	sc->pend_imp_at = rva;
	sc->pend_imp_set = 1;
	return 1;
}

int oc_section(const struct kof_obj_ctx *ctx, const char *name,
		     uint64_t rva, uint64_t vsize, uint32_t perm,
		     uint32_t flags)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_sec_decl *d;
	uint32_t k;
	unsigned q;

	if (!sc->pend_sec) {
		sc->pend_sec = calloc(DECL_SEC_MAX, sizeof *sc->pend_sec);
		if (!sc->pend_sec)
			return -1;
	}
	if (vsize == 0)
		return -1;
	/*
	 * A REGION IS UNIQUE BY ITS ADDRESS, SO DECLARING IT AGAIN REPLACES IT.
	 *
	 * This is what lets a module LOOK AT WHAT IT BUILT before it says what
	 * the thing is. Declaring up front is unavoidable - the engine sizes
	 * the image from the table - but a declaration made before the content
	 * exists is a guess about the PARENT, and getting that backwards was
	 * measured: vmprotect_pe.c marked its destinations hollow from the
	 * parent's shape, so in a child that had just been filled they still
	 * read as empty, the module accepted the same table again, and
	 * explorer.exe came back as seven identical objects.
	 *
	 * So: declare the layout, fill it, read it back, and say again what is
	 * there. The second word is the one that stands. Nothing is appended
	 * twice and no index has to be carried around for it - the address is
	 * the identity.
	 */
	for (k = 0; k < sc->n_pend_sec; k++)
		if (sc->pend_sec[k].rva == rva) {
			struct kof_sec_decl *e = &sc->pend_sec[k];
			unsigned w;

			/* An extent may be corrected, but not over its
			 * neighbour: the table stays ordered and disjoint or
			 * the engine cannot lay the child out from it. */
			if (k + 1u < sc->n_pend_sec &&
			    rva + vsize > sc->pend_sec[k + 1u].rva)
				return -1;
			(void)w;
			sec_name_copy(e->name, name);
			e->vsize = vsize;
			e->perm = perm;
			e->flags = flags;
			return (int)k;
		}
	if (sc->n_pend_sec >= DECL_SEC_MAX)
		return -1;
	d = &sc->pend_sec[sc->n_pend_sec];
	(void)q;
	sec_name_copy(d->name, name);
	d->rva = rva;
	d->vsize = vsize;
	d->perm = perm;
	d->flags = flags;
	return (int)sc->n_pend_sec++;
}

/* Forget the layout - see `sections_reset` in kofsig.h. The image is
 * untouched; a module that clears the table and declares nothing gets a child
 * with no header, which kunp_rcstruct_done refuses. */
int oc_sections_reset(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	sc->n_pend_sec = 0;
	return 1;
}

/* The layout the produced image carries - see `layout_of_produced`. */
uint64_t oc_layout_of_produced(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint64_t entry = 0, base = 0;
	uint32_t n;

	if (!sc->sink_fixed || !sc->sink_mem || !sc->sink_len)
		return 0;
	if (!sc->pend_sec) {
		sc->pend_sec = calloc(DECL_SEC_MAX, sizeof *sc->pend_sec);
		if (!sc->pend_sec)
			return 0;
	}
	n = kof_pe_layout_of(kof_buf_make(sc->sink_mem, sc->sink_len),
			     sc->pend_sec, DECL_SEC_MAX, &entry, &base,
			     sc->pend_dir);
	if (!n)
		return 0;
	/*
	 * AND THE CHILD ENDS WHERE ITS LAST SECTION DOES.
	 *
	 * The image was sized from what the container DECLARED, which is not
	 * where the header found inside it says the image ends. Those trailing
	 * bytes are past every section, so no claim covers them and the
	 * partition calls them an OVERLAY - measured on a UPX child, 3233 bytes
	 * of it on a file that carries nothing appended at all.
	 *
	 * Declaring them as padding does not help: padding is deliberately left
	 * out of the section table, so the last claim would still end before
	 * them. They are dropped, which is also what the path this replaces
	 * did - it built a file sized to the sections and never carried the
	 * remainder at all.
	 */
	{
		uint64_t end = sc->pend_sec[n - 1u].rva +
			       sc->pend_sec[n - 1u].vsize;

		/*
		 * ONLY PADDING IS DROPPED. The bytes past the last section were
		 * cut whatever they held, on the strength of one UPX child whose
		 * 3233 were zeros the container's declared size had left behind.
		 * A tail with a non-zero byte in it is not that: it is something
		 * the image carries after its sections, the partition will call it
		 * an overlay, and a rule scoped to OVERLAY is entitled to see it.
		 */
		if (end && end < sc->sink_len) {
			size_t z;

			for (z = (size_t)end; z < sc->sink_len; z++)
				if (sc->sink_mem[z])
					break;
			if (z == sc->sink_len)
				sc->sink_len = (size_t)end;
		}
		sc->n_pend_sec = n;
		sc->pend_entry_rva = entry;
		sc->pend_entry_set = entry ? 1 : 0;
		/* Where the image ends, for a caller with something to put
		 * behind it - see layout_of_produced. */
		return end ? end : (uint64_t)sc->sink_len;
	}
}

/*
 * A directory a module REBUILT, which overrides whatever the parent had - see
 * `child_dir` in kofsig.h.
 */
int oc_child_dir(const struct kof_obj_ctx *ctx, uint32_t idx,
		       uint64_t rva, uint64_t size)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (idx >= 16u)
		return 0;
	sc->pend_dir[idx].rva = rva;
	sc->pend_dir[idx].size = size;
	sc->pend_dir[idx].set = 1;
	return 1;
}

/* The child's entry point, which is often knowable only after its content
 * exists - mpress_pe.c reads it out of a fix-up stub it has just decompressed. */
int oc_child_entry_rva(const struct kof_obj_ctx *ctx, uint64_t rva)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	sc->pend_entry_rva = rva;
	sc->pend_entry_set = 1;
	return 1;
}

/*
 * THE CHILD IS AN IMAGE THE ENGINE LAYS OUT, from the sections just declared.
 *
 * The other half of `section` in kofsig.h. A module declares where things go,
 * asks for the image, writes content at addresses with kunp_rcstruct_poke in whatever
 * order suits it, and the engine writes the header at the close. No module
 * synthesises a container and no engine parses one back.
 *
 * ZERO FILLED, so a section a module never writes to reads as absent rather
 * than as whatever was in the allocator's memory - which matters most for the
 * sections that ARE absent, the hollow ones.
 */
/* Where the next write lands in a fixed sink - see `at` in kofsig.h. */
int oc_at(const struct kof_obj_ctx *ctx, uint64_t off)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	/* Anywhere inside the extent, for the reason oc_emit gives: the cursor
	 * may be placed past what currently counts as the child, because a cut
	 * back to the image's end is not a cut to the space that was paid
	 * for. */
	if (!sc->sink_fixed || off > sc->sink_cap)
		return 0;
	sc->sink_at = off;
	return 1;
}

int oc_image(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint64_t span;
	uint8_t *mem;

	if (!oc_can_produce(sc) || !sc->cur_src)
		return 0;
	if (sc->sink_len || sc->sink_spilled || !sc->n_pend_sec)
		return 0;
	{
		const struct kof_sec_decl *last =
			&sc->pend_sec[sc->n_pend_sec - 1u];

		span = last->rva + last->vsize;
	}
	if (!span || span > sc->budget || span > sc->obj_cap ||
	    sc->resident > sc->resident_max ||
	    span > sc->resident_max - sc->resident) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	mem = calloc(1, (size_t)span);
	if (!mem) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	free(sc->sink_mem);
	sc->sink_mem = mem;
	sc->sink_cap = (size_t)span;
	sc->sink_len = (size_t)span;
	sc->sink_fixed = 1;             /* fixed size, written at a cursor */
	sc->sink_at = 0;
	sc->pend_image = 1;
	/*
	 * The format whose vocabulary the declared sections will be turned into
	 * regions with, remembered HERE because this is the last point that has
	 * the context - kid_push, where the table is built, does not. A module
	 * that says otherwise with kunp_rcstruct_as overrides it.
	 */
	sc->pend_img_fmt = ctx->format;

	sc->budget -= span;
	scan_charge(sc, span);
	return 1;
}

int oc_derive(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	kof_buf b;
	uint8_t *mem;

	if (!oc_can_produce(sc) || !sc->cur_src)
		return 0;
	if (sc->sink_len || sc->sink_spilled)
		return 0;
	b = kof_src_buf(sc->cur_src);
	if (!b.p || !b.n)
		return 0;

	/* The same three ceilings oc_emit applies, asked once for the whole
	 * copy rather than once per megabyte - a derive is all or nothing, and
	 * half a copy of an object is not a prefix of anything. */
	if (b.n > sc->budget ||
	    b.n > sc->obj_cap ||
	    sc->resident > sc->resident_max ||
	    b.n > sc->resident_max - sc->resident) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}

	/*
	 * ONE ALLOCATION AND ONE COPY, NOT A RUN THROUGH THE SINK.
	 *
	 * Through oc_emit this would cross SINK_SPILL at one megabyte, put the
	 * remaining four and a bit into a temporary file, and turn every later
	 * kunp_rcstruct_poke into a positioned write to a descriptor - on the sample
	 * this was written for, 259 of them. The size is known in full before
	 * the first byte moves, so none of that is necessary: take the memory
	 * once, copy once, and every edit afterwards is a memcpy.
	 *
	 * It also means a derived child never spills, which is deliberate. A
	 * module that derives is editing an object it has already been given
	 * whole, so the memory was there to begin with.
	 */
	mem = malloc((size_t)b.n);
	if (!mem) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	memcpy(mem, b.p, (size_t)b.n);
	free(sc->sink_mem);
	sc->sink_mem = mem;
	sc->sink_cap = (size_t)b.n;
	sc->sink_len = (size_t)b.n;
	sc->sink_fixed = 1;
	sc->sink_at = 0;

	sc->budget -= b.n;
	scan_charge(sc, b.n);

	/* And the fact that makes it safe to offer this child to everyone
	 * else: the module that derived it does not see it again. */
	sc->pend_derived_by = sc->cur_mod;
	return 1;
}

void oc_name_next(const struct kof_obj_ctx *ctx, uint64_t off, uint64_t len)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	kof_buf s = kof_slice(oc_mc(ctx)->data, off, len);
	uint64_t n;

	sc->pend_label[0] = 0;
	sc->pend_label_len = 0;
	if (!s.n)
		return;
	n = s.n < KOF_SRC_LABEL_MAX - 1u ? s.n : KOF_SRC_LABEL_MAX - 1u;
	memcpy(sc->pend_label, s.p, (size_t)n);
	sc->pend_label[n] = 0;
	sc->pend_label_len = (uint32_t)n;
}

/*
 * Two vtables, differing only in whether the producer entries are there.
 *
 * A detector gets NULLs, so kunp_rcstruct_write and kunp_rcstruct_window answer zero for it, and
 * the rule that only an unpacker produces children is carried by the pointers
 * rather than by a check somewhere that could be missed. Same shape as
 * resolve_scan being NULL when nothing identified the object.
 */


/*
 * The budget for one top level object, inherited by everything below it.
 *
 * Derived from the object rather than fixed: a ratio alone refuses a small archive
 * that legitimately expands, and a constant alone gives a tiny file the same
 * allowance as a large one. The floor and the ratio each cover the other's case.
 *
 * One budget for the whole tree. Per-child limits are how a container full of
 * entries that are each individually reasonable adds up to something that is not.
 */
void kof_scan_budget(struct kof_scanner *sc, uint64_t obj_size,
		     const struct kof_scan_option *opt)
{
	uint64_t want = opt->max_produced_bytes;

	if (want == 0) {
		/* A ratio, floored. Sixty-four rather than the thousand a single
		 * DEFLATE layer can reach: this is the total a tree may do, and an
		 * allowance that large on a large input is no allowance at all. */
		want = obj_size > (UINT64_MAX / 64u) ? UINT64_MAX : obj_size * 64u;
		if (want < (64ull << 20))
			want = 64ull << 20;
	}
	sc->budget = want;
	sc->kids_left = opt->max_children ? opt->max_children : 4096u;
	sc->resident = 0;
	sc->resident_max = opt->max_resident_bytes ? opt->max_resident_bytes
						   : (128ull << 20);
	/*
	 * Half the ceiling, at most.
	 *
	 * Not the whole of it: while a child is being unpacked, that child is itself
	 * resident, so a cap the size of the ceiling leaves no room to produce
	 * anything and the tree stops one level down. Half means the object in hand
	 * and the object being built both fit, which is what lets a container be
	 * unpacked one entry at a time.
	 */
	sc->obj_cap = opt->max_object_bytes ? opt->max_object_bytes : KOF_OBJ_CAP;
	if (sc->obj_cap > sc->resident_max / 2)
		sc->obj_cap = sc->resident_max / 2;
	if (sc->obj_cap == 0)
		sc->obj_cap = 1;
	sc->broken = 0;
	sc->stop = 0;
}

void kof_scan_kids_reset(struct kof_scanner *sc)
{
	uint32_t i;

	for (i = 0; i < sc->n_kids; i++)
		kof_src_unref(sc->kids[i]);
	sc->n_kids = 0;
	sc->n_views = 0;        /* counted out of n_kids - see scan.h */
	sc->n_carved = 0;

	kof_scan_sink_discard(sc);
}

/*
 * WHATEVER A MODULE EMITTED AND NEVER CLOSED IS NOT AN OBJECT, and the memory it
 * was holding stops being resident. Also the cursor: `sink_fixed` and `sink_at`
 * were cleared only when a close SUCCEEDED, so a derived or image sink left open
 * by a module whose close was refused kept its cursor into the next module, whose
 * emits then went through the fixed-size arm to a stale position. Called at the
 * start of every object and of every module's turn.
 */
void kof_scan_sink_discard(struct kof_scanner *sc)
{
	oc_scan_release(sc, sc->sink_len + sc->sink_spilled);
	free(sc->sink_mem);
	sc->sink_mem = NULL;
	sc->sink_len = sc->sink_cap = 0;
	if (sc->sink_fd >= 0)
		close(sc->sink_fd);
	sc->sink_fd = -1;
	sc->sink_spilled = 0;
	sc->sink_fixed = 0;
	sc->sink_at = 0;
}


