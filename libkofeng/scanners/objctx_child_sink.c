/*
 * objctx_child_sink.c - the pending set a module declares a child in, the claims a pushed child spends, the sink its bytes land in, and the quota. Split from objctx_child.c; the text is unchanged.
 */

#define _GNU_SOURCE

#include "../kofcore/kofplatform.h"
#include <genotype/image/elf_rebuild.h>

#include "objctx_int.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
 * EVERY PENDING DECLARATION, DROPPED.
 *
 * A producer names its next child before it makes it - the label, the kind,
 * the entry index, the format, the region table, the symbol block - and each of
 * those is a claim about ONE child. oc_kid_push spends them as it attaches them,
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
	sc->pend.label[0] = 0;
	sc->pend.label_len = 0;
	sc->pend.kind = 0;
	sc->pend.entry = KOF_ENTRY_NONE;
	sc->pend.want = 0;
	sc->pend.want_level = 0;
	sc->pend.n_xw = 0;
	sc->pend.fmt = 0;
	sc->pend.lang = 0;
	sc->pend.subtype = sc->pend.subfam = 0;
	sc->pend.n_rgn = 0;
	sc->pend.rgn_fmt = 0;
	sc->pend.n_syms = 0;
	kgenome_funcs_free(&sc->pend.funcs);
	sc->pend.desc_set = 0;
	sc->pend.derived_by = NULL;
	sc->pend.superseded = 0;
	sc->pend.as_fmt = 0;
	sc->pend.as_arch = 0;
	sc->pend.as_base = 0;
	sc->pend.img_fmt = 0;
	sc->pend.n_sec = 0;
	sc->pend.entry_set = 0;
	sc->pend.entry_rva = 0;
	memset(sc->pend.dir, 0, sizeof sc->pend.dir);
	sc->pend.image = 0;
	sc->pend.n_imp = 0;
	sc->pend.imp_pool_n = 0;
	/* Declared per object, like everything else here: a watch one module
	 * named must not still be armed for the next one's run. */
	memset(&sc->pend.decl, 0, sizeof sc->pend.decl);
	sc->pend.imp_at = 0;
	sc->pend.imp_set = 0;
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

	if (!sc->pend.sec || !sc->pend.n_sec)
		return;
	if (fmt == KOF_FMT_ELF) {
		m_hdr = KGENOME_SCAN_ELF_HEADERS;
		m_code = KGENOME_SCAN_ELF_CODE;
		m_data = KGENOME_SCAN_ELF_DATA;
		m_unclaimed = KGENOME_SCAN_ELF_UNCLAIMED;
	} else {
		m_hdr = KGENOME_SCAN_PE_HEADERS;
		m_code = KGENOME_SCAN_PE_CODE;
		m_data = KGENOME_SCAN_PE_DATA;
		m_unclaimed = KGENOME_SCAN_PE_UNCLAIMED;
	}
	/* Everything before the first section is the header, which no module
	 * declares and every consumer expects. */
	hdr_end = sc->pend.sec[0].rva;
	if (hdr_end && n < KOF_SRC_MAX_REGIONS) {
		sc->pend.rgn[n].mask = m_hdr;
		sc->pend.rgn[n].off = 0;
		sc->pend.rgn[n].len = hdr_end;
		n++;
	}
	for (i = 0; i < sc->pend.n_sec; i++) {
		const struct kgenome_sec_decl *d = &sc->pend.sec[i];
		uint32_t mask;

		if (d->flags & (KGENOME_SECF_PAD | KGENOME_SECF_HOLLOW))
			mask = m_unclaimed;
		else if (d->flags & KGENOME_SECF_CODE)
			mask = m_code;
		else
			mask = m_data;
		if (n && sc->pend.rgn[n - 1u].mask == mask &&
		    sc->pend.rgn[n - 1u].off + sc->pend.rgn[n - 1u].len ==
		    d->rva) {
			sc->pend.rgn[n - 1u].len += d->vsize;
			continue;
		}
		if (n >= KOF_SRC_MAX_REGIONS) {
			/* The tail of the section table is not in any region, and a
			 * rule scoped to CODE or DATA cannot see it: said, not dropped. */
			oc_scan_capped(sc, KOF_BROKEN_LIMIT);
			break;
		}
		sc->pend.rgn[n].mask = mask;
		sc->pend.rgn[n].off = d->rva;
		sc->pend.rgn[n].len = d->vsize;
		n++;
	}
	sc->pend.n_rgn = n;
	sc->pend.rgn_fmt = fmt;
}

/*
 * HOW WIDE THE CHILD IS, which decides the size of a lookup entry and of a
 * thunk - see kgenome_pe_write_imports.
 *
 * What the module said with kunp_rcstruct_as beats what the parent is, for the
 * reason the header writer gives: a 64-bit payload is routinely carried by a
 * 32-bit container, and nothing else in the child would say so.
 */
int oc_child_is64(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const struct kgenome_pe_info *tmpl;

	if (sc && sc->pend.as_fmt == KOF_FMT_PE) {
		if (sc->pend.as_arch == KGENOME_ARCH_X86_64)
			return 1;
		if (sc->pend.as_arch == KGENOME_ARCH_X86)
			return 0;
	}
	tmpl = (const struct kgenome_pe_info *)ctx->file_header;
	return tmpl && tmpl->valid && tmpl->pe32_plus;
}

/*
 * THE NAME OF A MODULE THAT TAKES A WRAPPER OFF OR CARVES SOMETHING OUT: the
 * step it is, the format of what it ran on, and what it took out -
 * "Unwrap:Gzip?Deflate", "Unwrap:DocZip", "Unwrap:Raw?Zlib", "Carve:PE?Overlay".
 *
 * Every part is a value the engine already holds. The step is the one the module
 * declared (KOF_ANALYZE_STEP). The format is the NAME OF THE FORMAT of the object
 * it is running on - which tells a .docx from a .zip where the module's own
 * target list, Zip and DocZip, cannot, and which is "Raw" for an object with no
 * format of its own. The content is what the module declared with
 * KOF_TARGET_CONTENT, when it has something to add.
 *
 * UNPACK and DECRYPT modules are named this way too once they declare their
 * content - "Decrypt:ELF?XOR", "Unpack:PE?Themida" - unless they name a build
 * themselves, which carries a version this cannot know.
 */
static int unwrap_name(const struct kof_scanner *sc,
		       const struct kof_obj_ctx *ctx, char *out, size_t cap)
{
	const struct kof_module *m = sc->mod.cur;
	const char *step, *content;
	int n;

	if (!m)
		return 0;
	content = kof_db_content(sc->eng, m);
	/*
	 * A module that unwraps or carves is always named this way. One that
	 * unpacks or decrypts is named this way when it declared what it takes out
	 * and did not name a build of its own: a packer that reads its version
	 * out of the file says "PE:UPX 3.95", which this cannot, and keeps saying
	 * it.
	 */
	if (m->step != (uint32_t)KOF_ANALYZE_UNWRAP &&
	    m->step != (uint32_t)KOF_ANALYZE_CARVE &&
	    (!content || (sc->obj.open.pend_build[0] && sc->obj.open.pend_build_of == m)))
		return 0;
	step = kof_analyze_word(m->step);
	n = snprintf(out, cap, "%s:%s", step, kof_format_name(ctx->format));
	/* Cut at the buffer, never past it. */
	if (content && n > 0 && (size_t)n + 1u < cap)
		snprintf(out + n, cap - (size_t)n, "?%s", content);
	return 1;
}

/*
 * ROOM FOR ONE MORE CHILD in the arrays that are indexed by the child counter.
 * Returns 0 when any of them could not grow, and then nothing is committed - the
 * caller says the child was lost, see the note inside.
 */
static int kid_grow(struct kof_scanner *sc)
{
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
	uint32_t nc = sc->child.cap ? sc->child.cap * 2 : 8;
	struct kof_objsrc **nv = realloc(sc->child.list, nc * sizeof *nv);
	uint8_t *np = NULL;
	const char **nf = NULL;
	uint32_t *nw = NULL, *nl = NULL, *nx = NULL;
	uint64_t *nr = NULL;
	const struct kof_module **nd = NULL;

	if (nv)
		sc->child.list = nv;
	if (nv)
		np = realloc(sc->child.packer, nc * sizeof *np);
	if (np)
		sc->child.packer = np;
	if (np)
		nf = realloc(sc->child.family, nc * sizeof *nf);
	if (nf)
		sc->child.family = nf;
	if (nf)
		nd = realloc(sc->child.derived_by, nc * sizeof *nd);
	if (nd)
		sc->child.derived_by = nd;
	if (nd)
		nw = realloc(sc->child.want, nc * sizeof *nw);
	if (nw)
		sc->child.want = nw;
	if (nw)
		nl = realloc(sc->child.want_level, nc * sizeof *nl);
	/* EACH POINTER IS TAKEN THE MOMENT ITS realloc SUCCEEDS, like the
	 * ones above. This one and kid_xw were taken only after every
	 * allocation had worked, so a failure part way returned with
	 * `kid_want_level` still holding a block realloc had already freed. */
	if (nl) {
		sc->child.want_level = nl;
		nx = realloc(sc->child.n_xw, nc * sizeof *nx);
	}
	if (nx)
		sc->child.n_xw = nx;
	if (nx)
		nr = realloc(sc->child.xw,
			     (size_t)nc * KGENOME_EMU_EXEC_WATCH * 2u *
			     sizeof *nr);
	if (nr)
		sc->child.xw = nr;
	if (!nl || !nx || !nr)
		return 0;
	sc->child.cap = nc;
	return 1;
}

/*
 * EVERYTHING THE PRODUCER DECLARED FOR THIS CHILD, attached to it and spent: the
 * label, kind, entry, language, format, regions, symbols, functions and description.
 * Each is cleared as it is attached, refusal or not - see the notes below.
 */
static void kid_spend_claims(struct kof_scanner *sc, struct kof_objsrc *kid)
{
/*
 * The pending name belongs to this child and to no other. Consumed whatever
 * happens next - even if the child is then refused for a limit - because a
 * name that survived a refusal would be attached to the following child,
 * which is the one way this could report the wrong entry.
 */
if (sc->pend.label_len) {
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
	kof_src_label(kid, (const uint8_t *)sc->pend.label,
		      sc->pend.label_len);
	sc->pend.label[0] = 0;
	sc->pend.label_len = 0;
}
/*
 * AND THE KIND TRAVELS ON ITS OWN - the only carrier of that fact,
 * so a row with no name of its own is drawn from it rather than
 * having it copied into the name.
 */
kof_src_declare_kind(kid, sc->pend.kind);
sc->pend.kind = 0;
/* Spent whatever happened to the child, and reset to the sentinel
 * rather than to zero - zero is entry 0 and is a real answer. */
kof_src_declare_entry(kid, sc->pend.entry);
sc->pend.entry = KOF_ENTRY_NONE;
/* The declared format goes the same way and is cleared the same way,
 * even on a refusal - a claim left pending would be worn by the next
 * child, which is a claim about the wrong bytes. */
if (sc->pend.lang) {
	kof_src_declare_lang(kid, sc->pend.subtype, sc->pend.subfam);
	sc->pend.lang = 0;
	sc->pend.subtype = sc->pend.subfam = 0;
}
if (sc->pend.fmt) {
	kof_src_declare_fmt(kid, sc->pend.fmt);
	sc->pend.fmt = 0;
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
if (!sc->pend.n_rgn && sc->pend.n_sec && sc->pend.image)
	decl_sec_to_regions(sc, sc->pend.as_fmt ? sc->pend.as_fmt
						: sc->pend.img_fmt);
if (sc->pend.n_rgn) {
	kof_src_declare_regions(kid, sc->pend.rgn_fmt, sc->pend.rgn,
				sc->pend.n_rgn);
	sc->pend.n_rgn = 0;
	sc->pend.rgn_fmt = 0;
}
if (sc->pend.n_syms) {
	kof_src_declare_syms(kid, sc->pend.syms, sc->pend.n_syms);
	sc->pend.n_syms = 0;
}
if (sc->pend.funcs.n) {
	kof_src_declare_funcs(kid, sc->pend.funcs.v, sc->pend.funcs.n);
	kgenome_funcs_free(&sc->pend.funcs);
}
if (sc->pend.desc_set) {
	kof_src_declare_desc(kid, &sc->pend.desc);
	sc->pend.desc_set = 0;
}
}

/*
 * WHAT THE PRODUCING MODULE SAID ABOUT THE CHILD, recorded as it is made: the ask
 * (want, the watch), whether a packer made it, and the family it decodes.
 */
static void kid_note_producer(struct kof_scanner *sc)
{
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
sc->child.want[sc->child.n] = sc->pend.want;
sc->child.want_level[sc->child.n] = sc->pend.want_level;
if (sc->child.n_xw && sc->child.xw) {
	uint32_t q;

	sc->child.n_xw[sc->child.n] = sc->pend.n_xw;
	for (q = 0; q < sc->pend.n_xw; q++) {
		uint64_t *d = sc->child.xw +
			      (size_t)sc->child.n * KGENOME_EMU_EXEC_WATCH *
			      2u + (size_t)q * 2u;

		d[0] = sc->pend.xw[q].rva;
		d[1] = sc->pend.xw[q].len;
	}
}
sc->child.packer[sc->child.n] =
	(uint8_t)(sc->mod.cur && kof_step_hides_program(sc->mod.cur->step));
if (sc->child.packer[sc->child.n])
	sc->obj.open.packed_here = 1;
/*
 * The family the producer decodes, so the child can be routed to that
 * family's decoder first - see the push loop in the walk. NULL when no
 * module produced it (an emulator image) or the producer declared no
 * family; empty counts as none, since an unpacker without KOF_TARGET_NAME
 * interns "".
 */
{
	const char *fam = sc->mod.cur
			  ? kof_db_family(sc->eng, sc->mod.cur) : NULL;

	sc->child.family[sc->child.n] = (fam && fam[0]) ? fam : NULL;
}
}

/*
 * WHICH MODULE OPENED THE OBJECT THE CHILD CAME OUT OF, and which build of the
 * packer it is: the answers a reader of the result is shown (opened_by and
 * packer_build), settled where the engine knows both at once.
 */
static void kid_note_opened_by(struct kof_scanner *sc, const struct kof_obj_ctx *ctx)
{
/*
 * AND WHICH MODULE OPENED THE OBJECT THIS CAME OUT OF.
 *
 * Recorded here because producing a child is what "opened it" means,
 * and here is the only place the engine knows both at once: `cur_mod`
 * is the module running, and the object it is running ON is the one
 * being scanned. See kof_result.opened_by for why it is the parent
 * that carries the name and not the child.
 */
if (sc->mod.cur && !sc->obj.open.opened_by[0] &&
    unwrap_name(sc, ctx, sc->obj.open.opened_by, sizeof sc->obj.open.opened_by)) {
	/* One answer and not two - see below: what is shown is the same
	 * name the object was opened by. */
	snprintf(sc->obj.open.packer_build, sizeof sc->obj.open.packer_build, "%s",
		 sc->obj.open.opened_by);
} else if (sc->mod.cur && !sc->obj.open.opened_by[0]) {
	if (sc->obj.open.mod_tag_of == sc->mod.cur && sc->obj.open.mod_tag[0]) {
		size_t q = strlen(sc->obj.open.mod_tag);

		if (q >= KOF_MOD_TAG)
			q = KOF_MOD_TAG - 1u;
		memcpy(sc->obj.open.opened_by, sc->obj.open.mod_tag, q);
		sc->obj.open.opened_by[q] = 0;
	}
	/*
	 * NO NAME FROM THE FILE'S NAME. A module that produces a child says
	 * what it is - kunp_rcstruct_build, or the prefix of its first
	 * kof_debug note - and one that does not is not named after the
	 * directory layout of this project, which is what its source path
	 * used to be turned into. `make check-rules` refuses a module that
	 * produces a child and says neither.
	 */
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
	if (sc->obj.open.pend_build[0] && sc->obj.open.pend_build_of == sc->mod.cur) {
		size_t q = strlen(sc->obj.open.pend_build);

		if (q >= sizeof sc->obj.open.packer_build)
			q = sizeof sc->obj.open.packer_build - 1u;
		memcpy(sc->obj.open.packer_build, sc->obj.open.pend_build, q);
		sc->obj.open.packer_build[q] = 0;
	} else if (sc->obj.open.opened_by[0]) {
		size_t q = strlen(sc->obj.open.opened_by);

		if (q >= sizeof sc->obj.open.packer_build)
			q = sizeof sc->obj.open.packer_build - 1u;
		memcpy(sc->obj.open.packer_build, sc->obj.open.opened_by, q);
		sc->obj.open.packer_build[q] = 0;
	}
}
}

/*
 * WHETHER THE INTERPRETER PRODUCED THE CHILD, and the consequence for who may be
 * offered it again (a child built from a run's regions is derived by that module).
 */
static void kid_note_run(struct kof_scanner *sc)
{
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
if (sc->obj.emu.run_by && sc->obj.emu.run_by == sc->mod.cur)
	sc->obj.emu.produced = 1;
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
if (sc->obj.emu.run_by && sc->obj.emu.run_by == sc->mod.cur &&
    !sc->pend.derived_by)
	sc->pend.derived_by = sc->mod.cur;
}

int oc_kid_push(struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
		    struct kof_objsrc *kid)
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
	kid_spend_claims(sc, kid);
	if (sc->ledger.kids_left == 0) {
		/* Refused, and recorded: a container that yields more children than
		 * the caller allows has not been fully examined, and saying so is
		 * the difference between "nothing else here" and "stopped looking". */
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		kof_src_unref(kid);
		return 0;
	}
	if (sc->child.n == sc->child.cap && !kid_grow(sc)) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		kof_src_unref(kid);
		return 0;
	}
	kid_note_producer(sc);
	kid_note_opened_by(sc, ctx);
	kid_note_run(sc);
	if (sc->child.derived_by)
		sc->child.derived_by[sc->child.n] = sc->pend.derived_by;
	sc->child.list[sc->child.n++] = kid;
	sc->ledger.kids_left--;
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
	if (sc->pend.superseded)
		sc->obj.open.superseded = 1;
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
	sc->ledger.resident = produced < sc->ledger.resident ? sc->ledger.resident - produced : 0;
}

void oc_scan_release_cb(void *sc, uint64_t produced)
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
	return sc->ledger.resident < sc->ledger.resident_max
	     ? sc->ledger.resident_max - sc->ledger.resident : 0;
}

void oc_scan_charge_(struct kof_scanner *sc, uint64_t n)
{
	sc->ledger.resident += n;
	if (sc->ledger.resident > sc->st.peak_resident)
		sc->st.peak_resident = sc->ledger.resident;
}

/* Which build of the packer - see `packer_build` in kofsig.h. */
void oc_packer_build(const struct kof_obj_ctx *ctx, const char *build)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	size_t i;

	if (!sc || !build)
		return;
	/* Held until this module produces something - see pend_build. */
	for (i = 0; i + 1u < sizeof sc->obj.open.pend_build && build[i]; i++)
		sc->obj.open.pend_build[i] = build[i];
	sc->obj.open.pend_build[i] = 0;
	sc->obj.open.pend_build_of = sc->mod.cur;
}

/* What the declared image becomes - see `as_format` in kofsig.h. */
void oc_as_format(const struct kof_obj_ctx *ctx, uint8_t fmt,
			uint8_t arch, uint64_t base)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc)
		return;
	sc->pend.as_fmt = fmt;
	sc->pend.as_arch = arch;
	sc->pend.as_base = base;
}

void oc_supersede(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (sc)
		sc->pend.superseded = 1;        /* committed by oc_kid_push */
}

void oc_child_want(const struct kof_obj_ctx *ctx, uint32_t want,
			 uint32_t level)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc)
		return;
	sc->pend.want = want;
	sc->pend.want_level = level;
}

int oc_window(const struct kof_obj_ctx *ctx, uint64_t off, uint64_t len)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!oc_can_produce(sc))
		return 0;
	return oc_kid_push(sc, ctx, kof_src_window(sc->cur.src, off, len));
}

/* Move whatever is in memory out to the descriptor, and keep writing there. */
int oc_sink_spill(struct kof_scanner *sc)
{
	if (sc->sink.fd < 0) {
		sc->sink.fd = kof_src_tmpfile();
		if (sc->sink.fd < 0)
			return 0;
	}
	if (sc->sink.len) {
		if (!kof_write_all(sc->sink.fd, sc->sink.mem, sc->sink.len))
			return 0;
		sc->sink.spilled += sc->sink.len;
		sc->sink.len = 0;
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
	if (sc->sink.fixed) {
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
		if (sc->sink.at > sc->sink.cap ||
		    n > sc->sink.cap - sc->sink.at)
			return 0;
		memcpy(sc->sink.mem + sc->sink.at, bytes, n);
		sc->sink.at += n;
		if (sc->sink.at > sc->sink.len)
			sc->sink.len = sc->sink.at;
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
	if (n > sc->ledger.budget) {
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
	if (sc->sink.len + sc->sink.spilled > sc->ledger.obj_cap ||
	    n > sc->ledger.obj_cap - (sc->sink.len + sc->sink.spilled) ||
	    sc->ledger.resident > sc->ledger.resident_max ||
	    n > sc->ledger.resident_max - sc->ledger.resident) {
		oc_child(ctx);
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	if (sc->sink.len + n > SINK_SPILL && !oc_sink_spill(sc)) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	if (sc->sink.fd >= 0) {
		if (write(sc->sink.fd, bytes, n) != (ssize_t)n) {
			/* A short write is almost always a full tmpfs. Recorded, not
			 * swallowed: silently keeping a truncated object would report
			 * a prefix of a file as if it were the file. */
			oc_scan_broken(sc, KOF_BROKEN_LIMIT);
			return 0;
		}
		sc->sink.spilled += n;
	} else {
		if (sc->sink.len > sc->sink.cap ||
		    n > sc->sink.cap - sc->sink.len) {
			size_t nc = sc->sink.cap ? sc->sink.cap : 4096;
			uint8_t *nb;

			while (nc < sc->sink.len + n) {
				if (nc > (size_t)-1 / 2u) {
					oc_scan_broken(sc, KOF_BROKEN_LIMIT);
					return 0;
				}
				nc *= 2;
			}
			nb = realloc(sc->sink.mem, nc);
			if (!nb) {
				oc_scan_broken(sc, KOF_BROKEN_LIMIT);
				return 0;
			}
			sc->sink.mem = nb;
			sc->sink.cap = nc;
		}
		memcpy(sc->sink.mem + sc->sink.len, bytes, n);
		sc->sink.len += n;
	}

	/*
	 * Charged only now, with the bytes actually stored.
	 *
	 * Charging before the write left the count standing when the write failed,
	 * and the ceiling shrank a little for every failure - a limit that tightens
	 * itself over a long scan is a limit nobody can predict.
	 */
	sc->ledger.budget -= n;
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
