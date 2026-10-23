/*
 * api_engine_slots.c - the module ABI's wrapper macros, against a vtable that RECORDS.
 *
 * A module never calls the engine: it calls a macro (kofchild.h, kofmodemu.h, ...) that reads a
 * slot of `ctx->content` and calls it, and every one of them has two behaviours a module is written against:
 *
 *   SURFACE WITHOUT THE SLOT   the slot is NULL - a detector's vtable has no producing slots, an old host has
 *                              not heard of a new one - and the macro answers its safe default, which is NOT
 *                              always 0: a refused section is -1, an address with no file offset is KOF_BROKEN.
 *   SURFACE WITH THE SLOT      the macro forwards its arguments in order, widened as the macro says (a 64 bit
 *                              address is not cut to 32, a byte argument is cut to 8), and returns what the
 *                              slot returned, whole.
 *
 * api_engine_modabi.c reaches a few of the slots through probe modules that run inside a scan; the ones that
 * need an emulator or a producing host (emu_*, dis_*, import*, section, derive, ...) cannot be reached
 * that way without building each of those machines, and the arithmetic of the macro is the same on a fake.
 * The libs behind the real slots are tested where they live (tests/lib/genome, tests/lib/uncoat).
 *
 * Under a sanitiser the fake's pointer arguments are real buffers: a macro that forwarded the wrong
 * argument would hand the slot the wrong pointer and the checks on `p0`..`p2` would fail.
 */

#include "hostile_engine.h"

#include <kofmod/kofsig.h>
#include <kofmod/zip.h>
#include <kofmod/pdf.h>
#include <kofmod/cell.h>
#include <kofmod/pe.h>
#include <kofmod/elf.h>
#include <kofmod/clr.h>
#include <kofmod/kofcap.h>
#include <kofmod/kofmutation.h>
#include <kofmod/aspack_tab.h>
#include <kofmod/kofdiagtree.h>
#include <phenotype/diag_scan.h>
#include <phenotype/diag_scan_state.h>
#include <phenotype/emu.h>
#include <phenotype/diag_private.h>
#include <celllysis/nucleo.h>
#include <celllysis/xref.h>
#include <celllysis/trueline.h>
#include <genotype/image/elf_rebuild.h>

#define BIG   0x1122334455667788ull

static struct rec {
	unsigned    calls;
	const char *last;
	uint64_t    a[6];
	const void *p[3];
} R;

#define REC(n) do { R.calls++; R.last = (n); } while (0)

/* ---- the slots: record the arguments, answer a value that does not fit in 32 bits where the type allows ---- */

static uint32_t s_api_resolved(const struct kof_obj_ctx *c, uint32_t i, char *dll, uint32_t dc, char *fn, uint32_t fc)
{
	(void)c; REC("api_resolved"); R.a[0] = i; R.a[1] = dc; R.a[2] = fc; R.p[0] = dll; R.p[1] = fn;
	return 0x7001u;
}
static void s_as_format(const struct kof_obj_ctx *c, uint8_t fmt, uint8_t arch, uint64_t base)
{
	(void)c; REC("as_format"); R.a[0] = fmt; R.a[1] = arch; R.a[2] = base;
}
static int s_at(const struct kof_obj_ctx *c, uint64_t off) { (void)c; REC("at"); R.a[0] = off; return 11; }
static int s_derive(const struct kof_obj_ctx *c) { (void)c; REC("derive"); return 12; }
static int s_child_dir(const struct kof_obj_ctx *c, uint32_t idx, uint64_t rva, uint64_t size)
{
	(void)c; REC("child_dir"); R.a[0] = idx; R.a[1] = rva; R.a[2] = size; return 13;
}
static int s_entry(const struct kof_obj_ctx *c, uint64_t rva) { (void)c; REC("entry"); R.a[0] = rva; return 14; }
static int s_image(const struct kof_obj_ctx *c) { (void)c; REC("image"); return 15; }
static int s_import(const struct kof_obj_ctx *c, const char *dll, const char *fn, uint32_t ord, uint64_t iat)
{
	(void)c; REC("import"); R.p[0] = dll; R.p[1] = fn; R.a[0] = ord; R.a[1] = iat; return 16;
}
static int s_import_at(const struct kof_obj_ctx *c, uint64_t rva) { (void)c; REC("import_at"); R.a[0] = rva; return 17; }
static uint64_t s_import_bytes(const struct kof_obj_ctx *c) { (void)c; REC("import_bytes"); return BIG; }
static int s_reset(const struct kof_obj_ctx *c) { (void)c; REC("sections_reset"); return 18; }
static int s_section(const struct kof_obj_ctx *c, const char *name, uint64_t rva, uint64_t vsize, uint32_t perm, uint32_t flags)
{
	(void)c; REC("section"); R.p[0] = name; R.a[0] = rva; R.a[1] = vsize; R.a[2] = perm; R.a[3] = flags; return 19;
}
static uint64_t s_chain(const struct kof_obj_ctx *c, uint32_t index) { (void)c; REC("unpack_chain"); R.a[0] = index; return BIG; }
static uint32_t s_sym_import(const struct kof_obj_ctx *c, const char *dll, const char *fn)
{
	(void)c; REC("sym_import"); R.p[0] = dll; R.p[1] = fn; return 0x7002u;
}
static uint64_t s_unpack(const struct kof_obj_ctx *c, uint32_t method, uint64_t off, uint64_t len, uint64_t hint)
{
	(void)c; REC("unpack"); R.a[0] = method; R.a[1] = off; R.a[2] = len; R.a[3] = hint; return BIG;
}
static void s_incomplete(const struct kof_obj_ctx *c, uint32_t reason) { (void)c; REC("incomplete"); R.a[0] = reason; }

static int s_dis_next(const struct kof_obj_ctx *c, struct cell_insn *out) { (void)c; REC("dis_next"); R.p[0] = out; return 21; }
static int s_dis_reg(const struct kof_obj_ctx *c, uint8_t r, uint64_t *out) { (void)c; REC("dis_reg"); R.a[0] = r; R.p[0] = out; return 22; }
static int s_dis_seek(const struct kof_obj_ctx *c, uint64_t off, int keep) { (void)c; REC("dis_seek"); R.a[0] = off; R.a[1] = (uint64_t)keep; return 23; }

static uint32_t s_emu_api_returns(const struct kof_obj_ctx *c, const char *name, uint64_t ret)
{
	(void)c; REC("emu_api_returns"); R.p[0] = name; R.a[0] = ret; return 0x7003u;
}
static void s_emu_watch(const struct kof_obj_ctx *c, uint64_t rva, uint64_t len) { (void)c; REC("emu_watch"); R.a[0] = rva; R.a[1] = len; }
static uint32_t s_emu_patch(const struct kof_obj_ctx *c, const uint8_t *f, const uint8_t *r, uint32_t n)
{
	(void)c; REC("emu_patch"); R.p[0] = f; R.p[1] = r; R.a[0] = n; return 0x7004u;
}
static uint32_t s_emu_read(const struct kof_obj_ctx *c, uint64_t va, uint8_t *out, uint32_t n)
{
	(void)c; REC("emu_read"); R.a[0] = va; R.p[0] = out; R.a[1] = n; return 0x7005u;
}
static uint64_t s_emu_reg(const struct kof_obj_ctx *c, uint32_t gpr) { (void)c; REC("emu_reg"); R.a[0] = gpr; return BIG; }
static int s_emu_region(const struct kof_obj_ctx *c, uint32_t i, uint64_t *va, uint64_t *len, uint32_t *kind)
{
	(void)c; REC("emu_region"); R.a[0] = i; R.p[0] = va; R.p[1] = len; R.p[2] = kind;
	*va = BIG; *len = BIG + 1u; *kind = 9u;
	return 24;
}
static uint32_t s_emu_region_read(const struct kof_obj_ctx *c, uint32_t i, uint64_t off, uint8_t *out, uint32_t n)
{
	(void)c; REC("emu_region_read"); R.a[0] = i; R.a[1] = off; R.p[0] = out; R.a[2] = n; return 0x7006u;
}
static uint32_t s_emu_resume(const struct kof_obj_ctx *c) { (void)c; REC("emu_resume"); return 0x7007u; }
static uint32_t s_emu_run(const struct kof_obj_ctx *c, uint32_t v) { (void)c; REC("emu_run"); R.a[0] = v; return 0x7008u; }
static void s_emu_set_ip(const struct kof_obj_ctx *c, uint64_t va) { (void)c; REC("emu_set_ip"); R.a[0] = va; }
static void s_emu_set_reg(const struct kof_obj_ctx *c, uint32_t gpr, uint64_t v) { (void)c; REC("emu_set_reg"); R.a[0] = gpr; R.a[1] = v; }
static void s_emu_slice(const struct kof_obj_ctx *c, uint64_t n) { (void)c; REC("emu_slice"); R.a[0] = n; }
static uint32_t s_emu_stop(const struct kof_obj_ctx *c) { (void)c; REC("emu_stop"); return 0x7009u; }
static int s_emu_take(const struct kof_obj_ctx *c, uint32_t i) { (void)c; REC("emu_take"); R.a[0] = i; return 25; }
static void s_child_want(const struct kof_obj_ctx *c, uint32_t w, uint32_t lvl) { (void)c; REC("child_want"); R.a[0] = w; R.a[1] = lvl; }
static void s_emu_watch_insn(const struct kof_obj_ctx *c, const uint8_t *b, uint32_t n, uint32_t len)
{
	(void)c; REC("emu_watch_insn"); R.p[0] = b; R.a[0] = n; R.a[1] = len;
}
static uint32_t s_emu_write(const struct kof_obj_ctx *c, uint64_t va, const uint8_t *b, uint32_t n)
{
	(void)c; REC("emu_write"); R.a[0] = va; R.p[0] = b; R.a[1] = n; return 0x700au;
}

static void s_infected(const struct kof_obj_ctx *c, uint64_t off, uint64_t len, uint32_t kind)
{
	(void)c; REC("infected"); R.a[0] = off; R.a[1] = len; R.a[2] = kind;
}
static uint32_t s_data_xref(const struct kof_obj_ctx *c, uint64_t va, uint64_t size)
{
	(void)c; REC("data_xref"); R.a[0] = va; R.a[1] = size; return 0x700cu;
}
static const uint8_t *s_graph(const struct kof_obj_ctx *c, uint32_t *nbytes)
{
	static const uint8_t g[8] = { 1 };

	(void)c; REC("graph"); *nbytes = 8;
	return g;
}
static int s_diag_str32(const struct kof_obj_ctx *c, uint32_t diag, const char *name)
{
	(void)c; REC("diag_str32"); R.a[0] = diag; R.p[0] = name; return 27;
}

/* view_next: the cursor is the caller's, the row is whatever the host says it is, NULL ends the walk */
static const char s_row_a[] = "zip row", s_row_b[] = "pdf row";
static const void *s_view_next(const struct kof_obj_ctx *c, uint32_t *cursor)
{
	REC("view_next"); R.p[0] = cursor; R.a[0] = *cursor;
	(void)c;
	if (*cursor >= 2u)
		return NULL;
	return (*cursor)++ == 0u ? (const void *)s_row_a : (const void *)s_row_b;
}

static const struct kof_content full = {
	.api_resolved = s_api_resolved, .as_format = s_as_format, .at = s_at, .derive = s_derive, .child_dir = s_child_dir,
	.child_entry_rva = s_entry, .image = s_image, .import = s_import, .import_at = s_import_at,
	.import_bytes = s_import_bytes, .sections_reset = s_reset, .section = s_section, .unpack_chain = s_chain,
	.sym_import = s_sym_import, .unpack = s_unpack, .incomplete = s_incomplete,
	.dis_next = s_dis_next, .dis_reg = s_dis_reg, .dis_seek = s_dis_seek,
	.emu_api_returns = s_emu_api_returns, .emu_watch = s_emu_watch, .emu_patch = s_emu_patch, .emu_read = s_emu_read,
	.emu_reg = s_emu_reg, .emu_region = s_emu_region, .emu_region_read = s_emu_region_read, .emu_resume = s_emu_resume,
	.emu_run = s_emu_run, .emu_set_ip = s_emu_set_ip, .emu_set_reg = s_emu_set_reg, .emu_slice = s_emu_slice,
	.emu_stop = s_emu_stop, .emu_take = s_emu_take, .child_want = s_child_want, .emu_watch_insn = s_emu_watch_insn,
	.emu_write = s_emu_write,
	.infected = s_infected, .data_xref = s_data_xref, .graph = s_graph, .diag_str32 = s_diag_str32,
	.view_next = s_view_next,
};
static const struct kof_content bare;           /* a surface with none of those slots */

#define CALLED(n) (R.calls == 1u && R.last && !strcmp(R.last, (n)))
#define ARM() memset(&R, 0, sizeof R)

/* ---- the child-making macros ------------------------------------------------------------------------------------ */

static void forwarded(const struct kof_obj_ctx *ctx)
{
	char dll[8], fn[8];
	uint8_t buf[16];
	uint64_t va = 0, len = 0;
	uint32_t kind = 0, nb = 0;
	int rc_i;
	uint64_t rc64;
	uint32_t rc32;
	struct cell_insn ins;
	uint64_t reg = 0;
	const uint8_t find[2] = { 1, 2 }, rep[2] = { 3, 4 };

	ARM();
	CK(kunp_rcstruct_section("sect", BIG, BIG + 1u, 7, 0x90) == 19 && CALLED("section") && !strcmp(R.p[0], "sect") &&
	   R.a[0] == BIG && R.a[1] == BIG + 1u && R.a[2] == 7u && R.a[3] == 0x90u, "section: name, 64 bit rva and size, perm, flags; the slot's answer");
	ARM();
	kunp_rcstruct_as(0x103, 0x204, BIG);
	CK(CALLED("as_format") && R.a[0] == 3u && R.a[1] == 4u && R.a[2] == BIG, "as: format and arch are bytes, the base is 64 bit");
	ARM();
	CK(kunp_rcstruct_at(BIG) == 11 && CALLED("at") && R.a[0] == BIG, "at: the offset is not cut to 32 bits");
	ARM();
	CK(kunp_rcstruct_derive() == 12 && CALLED("derive"), "derive");
	ARM();
	CK(kunp_rcstruct_dir(5, BIG, BIG + 2u) == 13 && CALLED("child_dir") && R.a[0] == 5u && R.a[1] == BIG && R.a[2] == BIG + 2u, "dir");
	ARM();
	CK(kunp_rcstruct_entry(BIG) == 14 && CALLED("entry") && R.a[0] == BIG, "entry");
	ARM();
	CK(kunp_rcstruct_image() == 15 && CALLED("image"), "image");
	ARM();
	CK(kunp_rcstruct_import("k32.dll", "Sleep", 0x1ffffu, BIG) == 16 && CALLED("import") && !strcmp(R.p[0], "k32.dll") &&
	   !strcmp(R.p[1], "Sleep") && R.a[0] == 0x1ffffu && R.a[1] == BIG, "import: dll, function, ordinal, slot address");
	ARM();
	CK(kunp_rcstruct_import_at(BIG) == 17 && CALLED("import_at") && R.a[0] == BIG, "import_at");
	ARM();
	CK(kunp_rcstruct_import_bytes() == BIG && CALLED("import_bytes"), "import_bytes answers 64 bits whole");
	ARM();
	CK(kunp_rcstruct_reset() == 18 && CALLED("sections_reset"), "reset");
	ARM();
	rc64 = kunp_static_decode_chain(3);
	CK(rc64 == BIG && CALLED("unpack_chain") && R.a[0] == 3u, "decode_chain: the index; 64 bit answer");
	ARM();
	rc32 = kunp_sym_import("a.dll", "Fn");
	CK(rc32 == 0x7002u && CALLED("sym_import") && !strcmp(R.p[0], "a.dll") && !strcmp(R.p[1], "Fn"), "sym_import");
	ARM();
	rc32 = kunp_api_resolved(4, dll, sizeof dll, fn, sizeof fn);
	CK(rc32 == 0x7001u && CALLED("api_resolved") && R.a[0] == 4u && R.a[1] == sizeof dll && R.a[2] == sizeof fn && R.p[0] == dll && R.p[1] == fn,
	   "api_resolved: index, both buffers and both capacities in order");
	ARM();
	rc64 = kof_unpack_deflate(BIG, 100);
	CK(rc64 == BIG && CALLED("unpack") && R.a[0] == KOF_UNP_DEFLATE && R.a[1] == BIG && R.a[2] == 100u && R.a[3] == 0u,
	   "deflate is the decode of method DEFLATE with no output hint");
	ARM();
	rc64 = kof_unpack_zlib(8, 9);
	CK(rc64 == BIG && CALLED("unpack") && R.a[0] == KOF_UNP_ZLIB && R.a[1] == 8u && R.a[2] == 9u, "zlib is the decode of method ZLIB");

	/* the emulator's surface */
	ARM();
	CK(kunp_emu_api_returns("GetTickCount", BIG) == 0x7003u && CALLED("emu_api_returns") && !strcmp(R.p[0], "GetTickCount") && R.a[0] == BIG, "api_returns");
	ARM();
	kunp_emu_oep_range(BIG, 0x40);
	CK(CALLED("emu_watch") && R.a[0] == BIG && R.a[1] == 0x40u, "oep_range is the watch slot");
	ARM();
	CK(kunp_emu_patch(find, rep, 2) == 0x7004u && CALLED("emu_patch") && R.p[0] == find && R.p[1] == rep && R.a[0] == 2u, "patch: find, replacement, length");
	ARM();
	CK(kunp_emu_read(BIG, buf, sizeof buf) == 0x7005u && CALLED("emu_read") && R.a[0] == BIG && R.p[0] == buf && R.a[1] == sizeof buf, "read");
	ARM();
	CK(kunp_emu_reg(7) == BIG && CALLED("emu_reg") && R.a[0] == 7u, "reg answers 64 bits whole");
	ARM();
	rc_i = kunp_emu_region(2, &va, &len, &kind);
	CK(rc_i == 24 && CALLED("emu_region") && R.a[0] == 2u && R.p[0] == &va && R.p[1] == &len && R.p[2] == &kind && va == BIG && len == BIG + 1u && kind == 9u,
	   "region: the three out pointers are the module's own");
	ARM();
	CK(kunp_emu_region_read(1, BIG, buf, 4) == 0x7006u && CALLED("emu_region_read") && R.a[0] == 1u && R.a[1] == BIG && R.p[0] == buf && R.a[2] == 4u, "region_read");
	ARM();
	CK(kunp_emu_resume() == 0x7007u && CALLED("emu_resume"), "resume");
	ARM();
	CK(kunp_emu_run(2) == 0x7008u && CALLED("emu_run") && R.a[0] == 2u, "run");
	ARM();
	kunp_emu_set_ip(BIG);
	CK(CALLED("emu_set_ip") && R.a[0] == BIG, "set_ip");
	ARM();
	kunp_emu_set_reg(3, BIG);
	CK(CALLED("emu_set_reg") && R.a[0] == 3u && R.a[1] == BIG, "set_reg: a 64 bit value");
	ARM();
	kunp_emu_slice(BIG);
	CK(CALLED("emu_slice") && R.a[0] == BIG, "slice");
	ARM();
	CK(kunp_emu_stop() == 0x7009u && CALLED("emu_stop"), "stop");
	ARM();
	CK(kunp_emu_take(6) == 25 && CALLED("emu_take") && R.a[0] == 6u, "take");
	ARM();
	kunp_emu_want(3, 2);
	CK(CALLED("child_want") && R.a[0] == 3u && R.a[1] == 2u, "want is the child_want slot: what, level");
	ARM();
	kunp_emu_watch_insn(find, 2, 5);
	CK(CALLED("emu_watch_insn") && R.p[0] == find && R.a[0] == 2u && R.a[1] == 5u, "watch_insn: bytes, count, length in order");
	ARM();
	CK(kunp_emu_write(BIG, find, 2) == 0x700au && CALLED("emu_write") && R.a[0] == BIG && R.p[0] == find && R.a[1] == 2u, "write");

	/* the disassembler's */
	ARM();
	CK(cell_next(&ins) == 21 && CALLED("dis_next") && R.p[0] == &ins, "cell_next");
	ARM();
	CK(cell_reg(0x1ff, &reg) == 22 && CALLED("dis_reg") && R.a[0] == 0xffu && R.p[0] == &reg, "cell_reg: the register is a byte");
	ARM();
	CK(cell_seek(BIG, 1) == 23 && CALLED("dis_seek") && R.a[0] == BIG && R.a[1] == 1u, "cell_seek");

	/* the mark */
	ARM();
	kof_mark_infected(BIG, 5, 2);
	CK(CALLED("infected") && R.a[0] == BIG && R.a[1] == 5u && R.a[2] == 2u, "mark_infected");
	ARM();
	CK(kof_data_xref(BIG, 8) == 0x700cu && CALLED("data_xref") && R.a[0] == BIG && R.a[1] == 8u, "data_xref");
	ARM();
	{
		const uint8_t *g = kof_diag_graph(&nb);

		CK(g != NULL && nb == 8u && CALLED("graph"), "diag_graph: the block and its length");
	}
	ARM();
	CK(kof_diag_str_one(trojan_x_00, "needle") == 27 && CALLED("diag_str32") && R.a[0] == kof_diag_id32_("trojan_x_00") && !strcmp(R.p[0], "needle"),
	   "diag_str_one asks by the diagnose's full id");
	/* the container walk: one slot, the cursor passed through and advanced by the host, the row returned whole */
	{
		uint32_t cur = 0;
		const struct kof_zip_entry *ze;
		const struct kof_pdf_object *po;

		ARM();
		ze = kof_zip_next(ctx, &cur);
		CK(CALLED("view_next") && (const void *)ze == (const void *)s_row_a && cur == 1u && R.p[0] == &cur && R.a[0] == 0u,
		   "kof_zip_next: the slot is asked with the module's cursor, which the host advanced, and the row comes back");
		po = kof_pdf_next(ctx, &cur);
		CK((const void *)po == (const void *)s_row_b && cur == 2u && R.calls == 2u && R.a[0] == 1u,
		   "kof_pdf_next: the same slot, the next row");
		CK(kof_zip_next(ctx, &cur) == NULL && cur == 2u, "the walk ends where the host says: NULL, the cursor where it was");
	}
}

/* a producer macro that returns from its caller */
static void broken_exit(const struct kof_obj_ctx *ctx)
{
	KUNP_RCSTRUCT_BROKEN(KOF_UNP_DAMAGED);
	R.calls += 100u;                    /* not reached */
}

static void broken_run(const struct kof_obj_ctx *ctx)
{
	ARM();
	broken_exit(ctx);
	CK(CALLED("incomplete") && R.a[0] == KOF_UNP_DAMAGED, "KUNP_RCSTRUCT_BROKEN records the reason and RETURNS from the module's function");
}

/* ---- a surface without the slots ---------------------------------------------------------------------------- */

static void defaults(const struct kof_obj_ctx *ctx)
{
	char dll[8], fn[8];
	uint8_t buf[16];
	uint64_t va = 5, len = 6, reg = 7;
	uint32_t kind = 8, nb = 9;
	struct cell_insn ins;
	int bad = 0;

	ARM();
	/* the defaults are not all 0: a refused section is -1, an address that is not in the file is KOF_BROKEN */
	CK(kunp_rcstruct_section("s", 1, 2, 3, 4) == -1, "no section slot: -1, the same as a refusal");
	bad += kunp_rcstruct_at(1) != 0 || kunp_rcstruct_derive() != 0 || kunp_rcstruct_dir(1, 2, 3) != 0 || kunp_rcstruct_entry(1) != 0;
	bad += kunp_rcstruct_image() != 0 || kunp_rcstruct_import("a", "b", 1, 2) != 0 || kunp_rcstruct_import_at(1) != 0;
	bad += kunp_rcstruct_import_bytes() != 0 || kunp_rcstruct_reset() != 0 || kunp_static_decode_chain(1) != 0;
	bad += kunp_sym_import("a", "b") != 0 || kunp_api_resolved(1, dll, 8, fn, 8) != 0;
	bad += kof_unpack_deflate(1, 2) != 0 || kof_unpack_zlib(1, 2) != 0;
	CK(!bad, "every producing macro on a surface without producing slots answers 0");
	kunp_rcstruct_as(1, 2, 3);
	kunp_emu_want(1, 2);
	kunp_emu_oep_range(1, 2);
	kunp_emu_set_ip(1);
	kunp_emu_set_reg(1, 2);
	kunp_emu_slice(1);
	kunp_emu_watch_insn(buf, 1, 2);
	kof_mark_infected(1, 2, 3);
	bad = kunp_emu_api_returns("x", 1) != 0 || kunp_emu_patch(buf, buf, 1) != 0 || kunp_emu_read(1, buf, 1) != 0 ||
	      kunp_emu_reg(1) != 0 || kunp_emu_region(0, &va, &len, &kind) != 0 || kunp_emu_region_read(0, 1, buf, 1) != 0 ||
	      kunp_emu_resume() != 0 || kunp_emu_run(1) != 0 || kunp_emu_stop() != 0 || kunp_emu_take(0) != 0 ||
	      kunp_emu_write(1, buf, 1) != 0;
	CK(!bad && va == 5u && len == 6u && kind == 8u, "the emulator macros on a surface without it: 0, and the out parameters are left alone");
	bad = cell_next(&ins) != 0 || cell_reg(1, &reg) != 0 || cell_seek(1, 0) != 0;
	CK(!bad && reg == 7u, "the disassembler macros: 0, out parameter untouched");
	bad = kof_data_xref(1, 2) != 0 ||
	      kof_diag_graph(&nb) != NULL || kof_diag_str_one(x_00, "y") != 0;
	CK(!bad && nb == 9u, "data_xref, graph, diag_str_one: 0 or NULL");
	{
		uint32_t cur = 5;

		CK(kof_zip_next(ctx, &cur) == NULL && kof_pdf_next(ctx, &cur) == NULL && cur == 5u,
		   "no view_next slot (an old host): the walk is empty and the cursor is left alone");
	}
	CK(R.calls == 0u, "and nothing was called");
	/* the producer's `return` still happens with no slot behind it */
	broken_exit(ctx);
	CK(R.calls == 0u, "KUNP_RCSTRUCT_BROKEN with no slot returns without calling anything (and without reaching what follows)");
}

/* ---- the aliases: the module-facing spelling IS the lib's ------------------------------------------------------ */

/*
 * A module reaches a lib through a name from the module ABI (`#define kof_xref_in kgenome_xref_in`), and
 * CLAUDE.md states the rule: the lib defines `kgenome_` names and the module-facing spelling is an alias. A
 * second implementation under the old name would drift; so the check is that the name IS the lib's - the same
 * function, the same type, the same answer - and a function that is `static inline` in the lib is called both ways.
 */
typedef void (*anyfn)(void);

static void aliases(void)
{
	struct kgenome_pe_info pe;
	uint8_t a[128], b[128];
	unsigned i;

	CK((anyfn)kof_diag_role_of_arg == (anyfn)kgenome_diag_role_of_arg, "kof_diag_role_of_arg is the lib's function");
	CK((anyfn)kof_diag_str_add == (anyfn)kgenome_diag_str_add, "kof_diag_str_add");
	CK((anyfn)kof_emu_get_reg == (anyfn)kgenome_emu_get_reg, "kof_emu_get_reg");
	CK((anyfn)kof_emu_read == (anyfn)kgenome_emu_read, "kof_emu_read");
	CK((anyfn)kof_emu_watch == (anyfn)kgenome_emu_watch, "kof_emu_watch");
	CK((anyfn)kof_flow_name_arg == (anyfn)kgenome_nucleo_name_arg, "kof_flow_name_arg is the nucleo's");
	CK((anyfn)kof_flow_cap_name == (anyfn)kgenome_nucleo_cap_name, "kof_flow_cap_name is the nucleo's");
	CK((anyfn)kof_true_find == (anyfn)kgenome_true_find, "kof_true_find");
	CK((anyfn)kof_xref_in == (anyfn)kgenome_xref_in, "kof_xref_in");

	/* the same answer from both spellings, and a real one */
	for (i = 1; i < 40u; i++) {
		const char *n1 = kof_flow_cap_name((uint16_t)i), *n2 = kgenome_nucleo_cap_name((uint16_t)i);

		CK(n1 == n2 || (n1 && n2 && !strcmp(n1, n2)), "capability %u has one name from both spellings", i);
	}
	CK(kof_flow_cap_name(1) != NULL && kof_flow_cap_name(1)[0], "capability 1 is named");
	for (i = 1; i < 40u; i++)
		CK(kof_diag_role_of_arg((uint16_t)i, 0) == kgenome_diag_role_of_arg((uint16_t)i, 0), "role of argument 0 of capability %u", i);
	CK(kof_mutation_mix(0x12345678u) == kgenome_mutation_mix(0x12345678u) && kof_mutation_mix(1) != kof_mutation_mix(2),
	   "the mutation mix is the lib's, and it mixes");

	/* a PE info with no sections: nothing is mapped, no rva has an offset, in either spelling */
	memset(&pe, 0, sizeof pe);
	CK(kof_pe_is_mapped(&pe) == kgenome_pe_is_mapped(&pe), "kof_pe_is_mapped");
	CK(kof_pe_rva_to_off(&pe, 0x1000) == kgenome_pe_rva_to_off(&pe, 0x1000), "kof_pe_rva_to_off");

	/* the ELF header writer writes the same bytes through either name */
	memset(a, 0, sizeof a);
	memset(b, 0, sizeof b);
	{
		struct kgenome_sec_decl sec;
		uint64_t wa, wb;

		memset(&sec, 0, sizeof sec);
		memcpy(sec.name, ".text", 6);
		sec.rva = 0x78;
		sec.vsize = 100;
		sec.perm = 7;
		sec.flags = 0;
		wa = kof_elf_write_hdr(a, 0x78, 1, 0x3e, 0x400000, &sec, 1, 0x78, 1, 0x78 + 100);
		wb = kgenome_elf_write_hdr(b, 0x78, 1, 0x3e, 0x400000, &sec, 1, 0x78, 1, 0x78 + 100);
		CK(wa == wb && wa > 0 && !memcmp(a, b, sizeof a), "kof_elf_write_hdr writes what the lib writes (%llu bytes)",
		   (unsigned long long)wa);
	}
	CK(a[0] == 0x7f && a[1] == 'E' && a[2] == 'L' && a[3] == 'F', "and it is an ELF header");

	/* the types: one struct, one enum, one table under both names */
	CK(sizeof(struct kof_elf_seg) == sizeof(struct kgenome_elf_seg), "kof_elf_seg is the lib's struct");
	CK(sizeof(struct kof_clr_meta) == sizeof(struct kgenome_clr_meta), "kof_clr_meta is the lib's struct");
	CK(sizeof(struct cell_insn) == sizeof(struct kgenome_cell_insn), "cell_insn is the lib's struct");
	CK(sizeof(struct cell_operand) == sizeof(struct kgenome_cell_operand), "cell_operand is the lib's struct");
	CK(sizeof(struct kof_diag_str) == sizeof(struct kgenome_diag_str), "kof_diag_str is the lib's struct");
	CK(sizeof(enum kof_diag_kind) == sizeof(enum kgenome_diag_kind) && sizeof(enum kof_diag_role) == sizeof(enum kgenome_diag_role) &&
	   sizeof(enum kof_arch) == sizeof(enum kgenome_arch) && sizeof(enum kof_mutation_norm) == sizeof(enum kgenome_mutation_norm) &&
	   sizeof(enum kof_mutation_side) == sizeof(enum kgenome_mutation_side), "the enums are the lib's");
	{
		enum kof_diag_kind k = KGENOME_DIAG_KIND_SHARED;
		enum kof_mutation_side sd = (enum kof_mutation_side)0;

		CK(k == KGENOME_DIAG_KIND_SHARED && (int)sd == 0, "an enumerator of the lib is a value of the module's type");
	}
	CK(sizeof kof_aspack_tab == sizeof kuncoat_aspack_tab && !memcmp(kof_aspack_tab, kuncoat_aspack_tab, sizeof kof_aspack_tab),
	   "kof_aspack_tab is the lib's table");
}

int main(void)
{
	struct kof_obj_ctx ctx;

	memset(&ctx, 0, sizeof ctx);
	ctx.content = &full;
	forwarded(&ctx);
	broken_run(&ctx);
	ctx.content = &bare;
	defaults(&ctx);
	aliases();
	printf("api_engine_slots: %u checks, %u failed\n", he_checks, he_fails);
	return he_fails != 0;
}
