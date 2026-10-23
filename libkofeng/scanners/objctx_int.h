/*
 * objctx_int.h - what the units of the module-facing context share with each
 * other, and with nothing else.
 *
 * objctx.c used to be one file of eight thousand lines, and "nothing here decides
 * anything" had stopped being checkable: reading, child production, decompression,
 * the interpreter and the diagnose glue sat in one translation unit, every one of
 * them with a `static` helper the others reached for. The units are split by
 * WHAT THEY SERVE, and each says in its first lines what that is:
 *
 *   objctx.c         the vtable, the boundary: readers, matching, reports
 *   objctx_child.c   declaring and producing a child object
 *   objctx_decomp.c  the decoders a module asks the engine to run: the sinks and
 *                    the streaming dispatch; the rest of the family is in
 *                    objctx_decomp_{buf,text,folder,entry}.c and objctx_decrypt.c,
 *                    which share objctx_decomp.h
 *   objctx_emu.c     the interpreter a module asks the engine to drive
 *   objctx_diag.c    the diagnose analysis and the symbol block
 *   objctx_script.c  the two forms of a script
 *
 * A helper two units need is declared HERE, with the `oc_` prefix that marks it
 * as internal to this family. Nothing outside scanners/ includes this header.
 */

#ifndef KOF_OBJCTX_INT_H
#define KOF_OBJCTX_INT_H

#include "scan.h"
#include "../kofcore/kofdebug.h"

/* ---- the boundary (objctx.c) -------------------------------------------- */

/* May this scanner still put a child into the world: it has a source to
 * attach it to and no limit has stopped the object. */
int oc_can_produce(const struct kof_scanner *sc);

/* ---- declaring and producing a child (objctx_child.c, for now objctx.c) ---- */

/* Close what has been emitted as one child. 1 on success. */
int oc_child(const struct kof_obj_ctx *ctx);
/* What the next child IS, as the engine's KOF_UNPACK_KIND word. */
void oc_child_kind(const struct kof_obj_ctx *ctx, uint32_t kind);
/* Emit all of `n` bytes; 1 when every byte was taken, 0 when a limit refused. */
int oc_emit_exact(const struct kof_obj_ctx *ctx, const uint8_t *p, uint64_t n);

/* ---- the interpreter (objctx_emu.c) ---- */
uint32_t oc_emu_run(const struct kof_obj_ctx *ctx, uint32_t vouch);
/* The TREE's interpreter allowance, in instructions, from the ROOT's size and the host's
 * option (kof_scan_budget calls it); what a run may take of it and what it gives back. */
uint64_t oc_emu_tree_insn(uint64_t root_size, uint64_t host_max);
uint64_t oc_emu_afford(struct kof_scanner *sc, uint64_t own);
void oc_emu_charge(struct kof_scanner *sc, uint64_t insn);
/* The diagnose scan's emulating routes against the tree's allowance: begin trims the
 * budget and the routes to what is left (or drops them, said), end charges what ran and
 * marks a scan that lost a route incomplete. The PE API-resolution product likewise. */
struct oc_emu_diag { uint64_t spent; int skipped; };
void oc_emu_diag_begin(struct kof_scanner *sc, struct oc_emu_diag *acct,
		       struct kgenome_budget *kb, unsigned *run);
void oc_emu_diag_end(struct kof_scanner *sc, const struct oc_emu_diag *acct,
		     struct kgenome_diag_scan *ds);
struct kgenome_diag_apihash_set *oc_emu_apihash(struct kof_scanner *sc,
		const struct kgenome_obj *gobj, kof_buf b, const struct kgenome_pe_imptab *imports);
/* Takes ownership of the finished run, gathers what it produced (objctx_emu_gather.c). */
uint32_t oc_emu_gather(const struct kof_obj_ctx *ctx, struct kof_scanner *sc,
		       struct kgenome_emu *e, struct kgenome_emu_unp_report rep);
int oc_emu_region(const struct kof_obj_ctx *ctx, uint32_t i,
			uint64_t *va, uint64_t *len, uint32_t *kind);
uint32_t oc_emu_region_read(const struct kof_obj_ctx *ctx, uint32_t i,
				  uint64_t off, uint8_t *out, uint32_t n);
void oc_emu_set_reg(const struct kof_obj_ctx *ctx, uint32_t gpr,
			  uint64_t value);
void oc_emu_set_ip(const struct kof_obj_ctx *ctx, uint64_t va);
uint32_t oc_emu_api_returns(const struct kof_obj_ctx *ctx, const char *name,
			    uint64_t ret);
uint32_t oc_emu_patch(const struct kof_obj_ctx *ctx, const uint8_t *find,
		      const uint8_t *rep, uint32_t n);
uint32_t oc_emu_write(const struct kof_obj_ctx *ctx, uint64_t va,
			    const uint8_t *bytes, uint32_t n);
int oc_emu_take(const struct kof_obj_ctx *ctx, uint32_t i);
int oc_opened_already(const struct kof_obj_ctx *ctx);
uint32_t oc_api_resolved(const struct kof_obj_ctx *ctx, uint32_t i,
			 char *dll, uint32_t dll_cap, char *fn,
			 uint32_t fn_cap);
uint32_t oc_sym_import(const struct kof_obj_ctx *ctx, const char *dll,
		       const char *fn);

/* ---- shared helpers (objctx.c) ---- */
uint64_t oc_scan_room(const struct kof_scanner *sc);
uint64_t oc_emit_all(const struct kof_obj_ctx *ctx, const uint8_t *p,
			 uint64_t n);
/*
 * THE THREE WAYS AN OBJECT IS SAID TO BE CUT, each with the place that said it. The macros
 * pass __FILE__ and __LINE__ so a `make DEBUG=1` run prints one "[cut] file:line ..." line
 * for every report - the list of what a bound took from this object, without a debugger -
 * and a release build carries no string (KOF_TRACE compiles to nothing; the two arguments
 * are the only cost, and only at a place that is already the slow path of a refusal).
 * OC_LIMIT adds the reason in words, for a report that has no other name.
 */
void oc_scan_capped_at(struct kof_scanner *sc, uint32_t reason, const char *file, int line);
void oc_scan_limit_at(struct kof_scanner *sc, const char *file, int line);
void oc_scan_broken_at(struct kof_scanner *sc, uint32_t reason, const char *file, int line);
#define oc_scan_capped(sc, reason) oc_scan_capped_at((sc), (reason), __FILE__, __LINE__)
#define oc_scan_limit(sc)          oc_scan_limit_at((sc), __FILE__, __LINE__)
#define oc_scan_broken(sc, reason) oc_scan_broken_at((sc), (reason), __FILE__, __LINE__)
/*
 * AN ENTRY'S OWN BOUND IS NOT THE TREE'S. A child that exceeds its own object cap or
 * its declared-ratio clamp is CUT: the bytes decoded so far are its content and it
 * carries LIMIT itself (kof_src_cut), the entry is counted in limit_hits, and the
 * parent's loop goes on to the next entry. Only a bound of the whole tree - the
 * produced-bytes budget, the resident ceiling, the child quota, the window allowance,
 * an allocation - is sticky (oc_scan_broken: `stop`) and ends the walk, and says so.
 * When nothing of the entry was kept there is no child to carry it, and the PARENT
 * reports it (oc_scan_limit: a report, no control flow).
 */
enum { OC_REFUSE_CUT = 1, OC_REFUSE_CUT_OPENED = 2 };
void oc_entry_cut(struct kof_scanner *sc);
void oc_entry_cut_close(const struct kof_obj_ctx *ctx);
void oc_entry_begin(struct kof_scanner *sc);
#define OC_LIMIT(sc, why) do { KOF_TRACE("[cut] %s:%d %s\n", __FILE__, __LINE__, (why)); oc_scan_limit(sc); } while (0)

/* ---- the diagnose analysis and symbols (objctx_diag.c) ---- */
const uint8_t *oc_graph(const struct kof_obj_ctx *ctx, uint32_t *nbytes);
const uint8_t *oc_syms(const struct kof_obj_ctx *ctx, uint32_t *nbytes);
/* The functions of the object, built once - see funcs.h. Never NULL. */
const struct kgenome_func_set *oc_funcs(const struct kof_obj_ctx *ctx);
int oc_diag(const struct kof_obj_ctx *ctx, uint16_t id);
int oc_diag_share(const struct kof_obj_ctx *ctx, uint16_t cap,
			uint16_t a, uint16_t b);
int oc_diag_str(const struct kof_obj_ctx *ctx, uint16_t id,
			   const char *name);
/* The same three questions with the diagnose named by its full 32-bit id - see
 * diag32 in struct kof_content. */
int oc_diag32(const struct kof_obj_ctx *ctx, uint32_t id);
int oc_diag_share32(const struct kof_obj_ctx *ctx, uint16_t cap,
		    uint32_t a, uint32_t b);
int oc_diag_str32(const struct kof_obj_ctx *ctx, uint32_t id, const char *name);

/* ---- the boundary (objctx.c) ---- */
static inline struct kof_match_ctx *oc_mc(const struct kof_obj_ctx *ctx)
{
	return &kof_scan_of(ctx)->match.m;
}

/* The PE's import directory, walked once for the object and kept by the scanner
 * (objctx_diag.c). Every reader of it - the symbol block, the PE diagnose, the
 * API-hash run and the emulator's IAT - takes this one table. */
struct kgenome_pe_imptab;
const struct kgenome_pe_imptab *oc_pe_imports(struct kof_scanner *sc,
					  const struct kof_obj_ctx *ctx);

/* ---- decoders (objctx_decomp*.c, objctx_decrypt.c) ---- */
uint64_t oc_unpack(const struct kof_obj_ctx *ctx, uint32_t method,
			 uint64_t off, uint64_t len, uint64_t out_hint);
/* A range of the object, decrypted with a cipher a module named - see
 * kofmod/kofdecode.h. The first produces; the second fills the caller's buffer. */
uint64_t oc_decrypt(const struct kof_obj_ctx *ctx, const struct kof_capsid *c,
		    uint64_t off, uint64_t len);
uint32_t oc_decrypt_peek(const struct kof_obj_ctx *ctx, const struct kof_capsid *c,
			 uint64_t off, uint64_t len, void *out, uint32_t cap);
uint32_t oc_capsid_apply(const struct kof_capsid *c, const void *in, uint32_t n,
			 void *out, uint32_t cap);
uint32_t oc_unpack_peek(const struct kof_obj_ctx *ctx, uint32_t method,
			      uint64_t off, uint64_t len, void *out,
			      uint32_t cap);
uint64_t oc_unpack_entry(const struct kof_obj_ctx *ctx, uint32_t method,
			       uint32_t index, uint64_t out_hint);
uint64_t oc_unpack_chain(const struct kof_obj_ctx *ctx, uint32_t index);
/* The walk behind kof_zip_next / kof_pdf_next (scan_facts.c). */
const void *oc_view_next(const struct kof_obj_ctx *ctx, uint32_t *cursor);

/* ---- shared helpers (objctx.c) ---- */
void oc_scan_release(struct kof_scanner *sc, uint64_t produced);
uint32_t oc_broken_of_status(enum kuncoat_status st);
void oc_incomplete(const struct kof_obj_ctx *ctx, uint32_t reason);
int oc_emit(const struct kof_obj_ctx *ctx, const void *bytes, uint32_t n);

/* ---- memory ceiling (objctx.c) ---- */
void oc_scan_charge_(struct kof_scanner *sc, uint64_t n);

/* The names quota (KOF_SCAN_NAMES): take `n` bytes of it, 0 when they do not fit; give
 * them back (saturating). The _cb spelling is the one a source holds for its label
 * (kof_src_label_account), for the reason oc_scan_release_cb exists. */
int  oc_names_take(struct kof_scanner *sc, uint64_t n);
void oc_names_give(struct kof_scanner *sc, uint64_t n);
void oc_names_give_cb(void *sc, uint64_t n);

/* Charge the memory ceiling, recording WHICH function asked so a refusal can say
 * who ran out of room (kof_scanner.ledger.res_why). A macro for __func__. */
#define scan_charge(sc, n) (((sc)->ledger.res_why = __func__), oc_scan_charge_(sc, n))

/* ---- what a script puts its own literals through (objctx_script_dec.c) ---- */
struct oc_script_dec;           /* the decode state of one script object: opaque */
struct oc_script_form_req {
	uint32_t       lang;    /* enum kgenome_textual_lang_id */
	const uint8_t *in;
	uint32_t       n;
	uint8_t       *out;     /* `cap` bytes, at least KGENOME_TEXTUAL_FORM_CAP(n) */
	uint64_t       cap;
	uint8_t        fragment;        /* code with no opening tag */
	struct oc_script_dec *dec;      /* NULL: no literal is decoded */
};
uint64_t oc_script_dec_room(const struct kof_scanner *sc, uint64_t n);
/*
 * What a script computes, written where it was computed (objctx_script_consts.c): the number of right sides replaced, with the text in
 * `*text` (malloc'ed, `*text_n` bytes, `*charged` to give back with oc_scan_release) - or 0 and nothing allocated.
 */
/* Does the engine write what a script of this language computes where it was computed: the lib's evaluator reads the language and its row has a `quote`. */
int oc_script_consts_serves(uint32_t lang);
uint32_t oc_script_consts(struct kof_scanner *sc, uint32_t lang, kof_buf b, uint8_t **text, uint32_t *text_n, uint64_t *charged);
/*
 * THE SCAN OF A SCRIPT'S TEXT, ONE FOR THE NAMES, THE CONSTANTS AND THE GRAPH (objctx_textscan.c).
 *
 * oc_syms_build builds the symbol block of an object (a script's from from the names the one scan told (making the scan when no stage has); oc_text_consts hands the constants stage
 * what the same scan collected, and oc_text_take gives the diagnose stage its graph - NULL unless it is for this very text (the buffer, its length and its language), when
 * that stage scans for itself. kof_scan_text_drop frees what is held.
 */
struct oc_consts;
uint32_t oc_syms_build(struct kof_scanner *sc, const struct kof_obj_ctx *ctx, const struct kgenome_pe_imptab *imp, uint32_t *passes);
struct oc_consts *oc_text_consts(struct kof_scanner *sc, uint32_t lang, kof_buf b);
int oc_text_eval_cut(const struct kof_scanner *sc);
struct kgenome_diag_scan *oc_text_take(struct kof_scanner *sc, uint32_t lang, kof_buf b);
/* the constants collector (objctx_script_consts.c): the callbacks of the scan's on_const and on_head, the collector they fill and its release */
struct oc_consts *oc_consts_new(const struct kof_scanner *sc, uint32_t lang, uint64_t n);
void oc_consts_free(struct oc_consts *c);
void oc_consts_on_const(void *u, uint64_t off, uint64_t len, const uint8_t *val, uint32_t n);
void oc_consts_on_head(void *u, uint64_t off, uint64_t len, const uint8_t *val, uint32_t n);
struct oc_script_dec *oc_script_dec_new(struct kof_scanner *sc, uint32_t lang, uint64_t room);
void oc_script_dec_end(struct oc_script_dec *d);
uint32_t oc_script_form(const struct oc_script_form_req *rq, uint32_t *n_dec);

/* ---- the interpreter, vtable entries (objctx_emu.c) ---- */
void oc_emu_watch(const struct kof_obj_ctx *ctx, uint64_t rva,
			uint64_t len);
uint64_t oc_emu_reg(const struct kof_obj_ctx *ctx, uint32_t gpr);
uint32_t oc_emu_read(const struct kof_obj_ctx *ctx, uint64_t va,
			   uint8_t *out, uint32_t n);
void oc_emu_watch_insn(const struct kof_obj_ctx *ctx,
			     const uint8_t *bytes, uint32_t n, uint32_t len);
void oc_emu_slice(const struct kof_obj_ctx *ctx, uint64_t insn);
uint32_t oc_emu_stop(const struct kof_obj_ctx *ctx);
uint32_t oc_emu_resume(const struct kof_obj_ctx *ctx);

/* ---- child production, vtable entries (objctx_child.c) ---- */
int oc_window(const struct kof_obj_ctx *ctx, uint64_t off, uint64_t len);
void oc_supersede(const struct kof_obj_ctx *ctx);
int oc_section(const struct kof_obj_ctx *ctx, const char *name,
		     uint64_t rva, uint64_t vsize, uint32_t perm,
		     uint32_t flags);
int oc_sections_reset(const struct kof_obj_ctx *ctx);
uint32_t oc_produced_read(const struct kof_obj_ctx *ctx, uint64_t off,
				void *out, uint32_t cap);
int oc_produced_poke(const struct kof_obj_ctx *ctx, uint64_t off,
			   const void *bytes, uint32_t n);
void oc_packer_build(const struct kof_obj_ctx *ctx, const char *build);
void oc_note_next(const struct kof_obj_ctx *ctx, const char *text);
void oc_name_next(const struct kof_obj_ctx *ctx, uint64_t off, uint64_t len);
uint64_t oc_layout_of_produced(const struct kof_obj_ctx *ctx);
int oc_import(const struct kof_obj_ctx *ctx, const char *dll,
		    const char *fn, uint32_t ordinal, uint64_t iat_rva);
uint64_t oc_import_bytes(const struct kof_obj_ctx *ctx);
int oc_import_at(const struct kof_obj_ctx *ctx, uint64_t rva);
uint64_t oc_sec_span(const struct kof_scanner *sc);
int oc_image(const struct kof_obj_ctx *ctx);
uint64_t oc_gather(const struct kof_obj_ctx *ctx, uint32_t mask, uint64_t cap);
int oc_derive(const struct kof_obj_ctx *ctx);
void oc_child_want(const struct kof_obj_ctx *ctx, uint32_t want,
			 uint32_t level);
void oc_child_format(const struct kof_obj_ctx *ctx, uint8_t fmt);
void oc_child_entry(const struct kof_obj_ctx *ctx, uint32_t index);
int oc_child_entry_rva(const struct kof_obj_ctx *ctx, uint64_t rva);
int oc_child_dir(const struct kof_obj_ctx *ctx, uint32_t idx,
		       uint64_t rva, uint64_t size);
int oc_at(const struct kof_obj_ctx *ctx, uint64_t off);
void oc_as_format(const struct kof_obj_ctx *ctx, uint8_t fmt,
			uint8_t arch, uint64_t base);

/* ---- child production (objctx_child.c) ---- */
void oc_pend_clear(struct kof_scanner *sc);
int oc_pend_regions(struct kof_scanner *sc, uint32_t need);

/* ---- what the units of the child family share (objctx_child*.c) ---- */
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

int oc_child_is64(const struct kof_obj_ctx *ctx);
int oc_kid_push(struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
		    struct kof_objsrc *kid);
void oc_scan_release_cb(void *sc, uint64_t produced);
/* What one collected child costs besides its bytes (its record and its row in sc->child), charged to the
 * resident ceiling when it is pushed - see kid_charge, objctx_child_sink.c. */
uint64_t oc_kid_cost(void);
void oc_diag_trim(struct kof_scanner *sc);
int oc_sink_spill(struct kof_scanner *sc);
/* objctx_spill.c: where a big object goes, and what happens when that place is not there. */
int oc_spill_usable(struct kof_scanner *sc);
int oc_spill_peek(struct kof_scanner *sc);
void oc_sink_reserve(struct kof_scanner *sc, uint64_t n);
int oc_sink_adopt(struct kof_scanner *sc, uint8_t *mem, size_t cap, size_t n);
int oc_spill_open(struct kof_scanner *sc);
int oc_spill_write(struct kof_scanner *sc, const void *p, uint64_t n);
int oc_spill_file_open(void *scanner);
int oc_spill_file_write(void *scanner, int fd, const void *p, uint64_t n);
void kof_scan_spill_hook(struct kof_scanner *sc, const struct kof_spill_io *io);

/* ---- what the emulator units share (objctx_emu*.c) ---- */
/*
 * Hand one recovered image to the sink. Emitted in pieces because oc_emit takes
 * a uint32 length and refuses anything over EMIT_MAX - a decompressor already
 * works a window at a time and so does this.
 */
/*
 * ---- ONE OBJECT OUT OF A RUN, NOT A HANDFUL --------------------------------
 *
 * A run leaves two kinds of thing behind: the IMAGE a stub assembled, and
 * SURPLUS - pages it decompressed into the heap, made executable, or simply
 * wrote. Handing each one over separately is what produced the rows of
 * anonymous blobs beside the file: `emu:image@0x400000`, `emu:exec@0x20002000`,
 * `emu:written@...`, each re-parsed from nothing by whoever looked at it.
 *
 * They are one program. So the image is reconstructed and the surplus is folded
 * into it as EXTRA SECTIONS past its end - each keeping the guest address it
 * was lifted from, in its name, because that is the only thing tying it back to
 * where the run put it. One child, one section table, one thing to look at.
 *
 * AND WHEN THERE IS NO IMAGE, THE SURPLUS IS STILL WORTH HAVING. A stub that
 * never assembles a PE - a shellcode decoder, a packer that runs its payload
 * from the heap - leaves only surplus, and that is then the result rather than
 * a leftover. It goes out raw, one child per region, which is what this did for
 * everything before the reconstruction existed.
 */
#define EMU_EXTRA_MAX 32u

struct emu_extra {
	const uint8_t *p;
	/* Set when `p` is a copy this function made - see the note in
	 * kof_scanner.emu.rgn. It is handed to the scanner with the region and
	 * freed with it. */
	uint8_t       *own;
	uint64_t       n, va;
	int            code;
};

/* ---- what the diagnose units share (objctx_diag*.c) ---- */
void oc_diag_ready(struct kof_scanner *sc, const struct kof_obj_ctx *ctx);
/* The routines of the diagnose scan diagnose `d` may run on this object (objctx_diag_route.c); zero: the object has nothing for it. */
unsigned oc_diag_routes(const struct kof_diag *d, const struct kof_obj_ctx *ctx);

/*
 * THE TEXT ROUTE (objctx_diag_text.c). A script is read by its lexer and not as an object model, so it has its own pieces of the
 * diagnose stage: whether the route can read this object, which capability a name of its symbols is, and the scan.
 */
int oc_text_served(const struct kof_obj_ctx *ctx);
uint16_t oc_name_cap(const struct kof_obj_ctx *ctx, const char *name);
struct kgenome_diag_scan *oc_diag_scan_text(struct kof_scanner *sc, const struct kof_obj_ctx *ctx, kof_buf b,
					    struct kgenome_budget *kb, enum kgenome_status *refused);
void oc_diag_demand(struct kof_scanner *sc);
/* Which diagnose was called, in one greppable line (objctx_diag_trace.c). */
void oc_diag_trace_scan(struct kof_scanner *sc);
void oc_diag_trace_ask(struct kof_scanner *sc, uint32_t i);

#endif /* KOF_OBJCTX_INT_H */
