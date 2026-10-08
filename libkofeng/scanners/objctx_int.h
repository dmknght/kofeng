/*
 * objctx_int.h - what the units of the module-facing context share with each
 * other, and with nothing else.
 *
 * objctx.c used to be one file of eight thousand lines, and "nothing here decides
 * anything" had stopped being checkable: reading, child production, decompression,
 * the interpreter and the pathogen glue sat in one translation unit, every one of
 * them with a `static` helper the others reached for. The units are split by
 * WHAT THEY SERVE, and each says in its first lines what that is:
 *
 *   objctx.c         the vtable, the boundary: readers, matching, reports
 *   objctx_child.c   declaring and producing a child object
 *   objctx_decomp.c  the decoders a module asks the engine to run
 *   objctx_emu.c     the interpreter a module asks the engine to drive
 *   objctx_diag.c    the pathogen analysis and the symbol block
 *   objctx_script.c  the two forms of a script
 *
 * A helper two units need is declared HERE, with the `oc_` prefix that marks it
 * as internal to this family. Nothing outside scanners/ includes this header.
 */

#ifndef KOF_OBJCTX_INT_H
#define KOF_OBJCTX_INT_H

#include "scan.h"

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
uint32_t oc_emu_gather(const struct kof_obj_ctx *ctx,
			   struct kof_scanner *sc, struct kof_emu *e,
			   struct kof_emu_unp_report rep);

/* ---- shared helpers (objctx.c) ---- */
uint64_t oc_scan_room(const struct kof_scanner *sc);
uint64_t oc_emit_all(const struct kof_obj_ctx *ctx, const uint8_t *p,
			 uint64_t n);
void oc_scan_capped(struct kof_scanner *sc, uint32_t reason);

/* ---- shared helpers (objctx.c) ---- */
void oc_scan_broken(struct kof_scanner *sc, uint32_t reason);

/* ---- the pathogen analysis and symbols (objctx_diag.c) ---- */
const uint8_t *oc_graph(const struct kof_obj_ctx *ctx, uint32_t *nbytes);
const uint8_t *oc_syms(const struct kof_obj_ctx *ctx, uint32_t *nbytes);
int oc_diag(const struct kof_obj_ctx *ctx, uint16_t id);
int oc_diag_share(const struct kof_obj_ctx *ctx, uint16_t cap,
			uint16_t a, uint16_t b);
int oc_diag_str(const struct kof_obj_ctx *ctx, uint16_t id,
			   const char *name);

/* ---- the boundary (objctx.c) ---- */
static inline struct kof_match_ctx *oc_mc(const struct kof_obj_ctx *ctx)
{
	return &kof_scan_of(ctx)->m;
}

/* ---- decoders (objctx_decomp.c) ---- */
uint64_t oc_unpack(const struct kof_obj_ctx *ctx, uint32_t method,
			 uint64_t off, uint64_t len, uint64_t out_hint);
uint32_t oc_unpack_peek(const struct kof_obj_ctx *ctx, uint32_t method,
			      uint64_t off, uint64_t len, void *out,
			      uint32_t cap);
uint64_t oc_unpack_entry(const struct kof_obj_ctx *ctx, uint32_t method,
			       uint32_t index, uint64_t out_hint);
uint64_t oc_unpack_chain(const struct kof_obj_ctx *ctx, uint32_t index);

/* ---- shared helpers (objctx.c) ---- */
void oc_scan_release(struct kof_scanner *sc, uint64_t produced);
uint32_t oc_broken_of_status(enum kof_decomp_status st);
void oc_incomplete(const struct kof_obj_ctx *ctx, uint32_t reason);
int oc_emit(const struct kof_obj_ctx *ctx, const void *bytes, uint32_t n);

/* ---- memory ceiling (objctx.c) ---- */
void oc_scan_charge_(struct kof_scanner *sc, uint64_t n);

/* Charge the memory ceiling, recording WHICH function asked so a refusal can say
 * who ran out of room (kof_scanner.res_why). A macro for __func__. */
#define scan_charge(sc, n) (((sc)->res_why = __func__), oc_scan_charge_(sc, n))

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

#endif /* KOF_OBJCTX_INT_H */
