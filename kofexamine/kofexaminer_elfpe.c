#define _GNU_SOURCE

/*
 * kofexaminer_elfpe.c - the ELF and PE printers, the symbol-record block and the
 * declared regions of a recovered object. Split from kofexaminer.c by format
 * family, no logic changed.
 */

#include "kofexaminer_private.h"

static void print_syms(const uint8_t *blk, uint32_t w);

/*
 * THE SYMBOL RECORDS THE ENGINE HANDED OVER WITH A RECOVERED OBJECT, or NULL.
 *
 * Only a RENDERING carries any - see kof_result.syms. A normalised view's
 * headers describe the file before the transform, so building a block from them
 * reads whatever now lies at a stale offset and finds nothing: this tool
 * printed "symbols none count=0" for a view whose parent has 994 records.
 *
 * File scope, beside kex_g_parent_format, because the printer is reached through
 * the format table and the result is not one of its arguments. Set for the
 * length of one object and cleared with it, so the file's own symbols are never
 * printed under a child's name.
 */
const uint8_t *kex_g_decl_syms;
uint32_t       kex_g_decl_syms_n;
/* The units of the parent's cut the view's decode rewrote - see kof_result.fixed. */
const struct kof_range *kex_g_decl_fixed;
uint32_t       kex_g_decl_fixed_n;

/*
 * AND THE REGIONS IT DECLARED, for the same reason and with the same lifetime.
 *
 * A normalised view's headers describe the file before the transform, so
 * parsing it gives a table over bytes that have moved - and the static
 * library, which the view carries at its end under SLIB_CODE and SLIB_DATA, is
 * in no header at all. Dumped from the parse, the LAYOUT file said the view had
 * five ordinary regions and nothing else; the engine's table says where the
 * toolchain's half went.
 */
struct kof_scan_region kex_g_decl_rgn[KOF_MAX_REGIONS];
/* What the engine said this object's language is - see kof_result.lang_known. */
uint8_t                kex_g_decl_lang, kex_g_decl_subtype, kex_g_decl_subfam;
uint32_t               kex_g_decl_rgn_n;

uint32_t kex_declared_regions(const struct kof_obj_ctx *ctx,
				 uint32_t scan_mask, struct kof_range *out,
				 uint32_t max_out)
{
	(void)ctx;
	/* The filtering is shared with the viewer - see kof_declared_regions. */
	return kof_declared_regions(kex_g_decl_rgn, kex_g_decl_rgn_n, scan_mask, out,
				    max_out);
}

void kex_print_elf(const void *view, const struct kof_obj_ctx *ctx,
		      kof_buf buf)
{
	const struct kgenome_elf_info *e = view;
	uint32_t i;

	printf("  class     %s %s%s%s  type=%u machine=%u\n",
	       e->elf_class == KGENOME_ELFCLASS_64 ? "ELF64" : "ELF32", kex_C_ID,
	       e->elf_data == KGENOME_ELFDATA_BE ? "big-endian" : "little-endian",
	       kex_C_OFF, e->e_type, e->e_machine);
	printf("  entry     addr=%s0x%llx%s ", kex_C_LOC,
	       (unsigned long long)e->entry_addr, kex_C_OFF);
	kex_put_off("off", ctx->entry_off);
	printf(" perm=");
	kex_put_perm(e->entry_perm);
	printf("\n");
	kex_print_claimed("segments", e->phnum, e->phnum_claimed);
	for (i = 0; i < e->seg_count; i++) {
		printf("     ");
		kex_put_type(kof_inspect_ptype_name, e->seg[i].type, 16);
		printf(" off=%s%-9llu%s size=%s%-9llu%s "
		       "vaddr=%s0x%-10llx%s perm=",
		       kex_C_LOC, (unsigned long long)e->seg[i].file_off, kex_C_OFF,
		       kex_C_SIZE, (unsigned long long)e->seg[i].file_size, kex_C_OFF,
		       kex_C_LOC, (unsigned long long)e->seg[i].mem_addr, kex_C_OFF);
		kex_put_perm(e->seg[i].perm);
		printf("\n");
	}
	kex_print_claimed("sections", e->shnum, e->shnum_claimed);
	for (i = 0; i < e->sec_count; i++) {
		printf("     %s%-20s%s off=%s%-9llu%s size=%s%-9llu%s ",
		       kex_C_ID, e->sec[i].name, kex_C_OFF,
		       kex_C_LOC, (unsigned long long)e->sec[i].file_off, kex_C_OFF,
		       kex_C_SIZE, (unsigned long long)e->sec[i].file_size, kex_C_OFF);
		kex_put_type(kof_inspect_shtype_name, e->sec[i].type, 0);
		printf("\n");
	}
	if (kex_g_decl_syms && kex_g_decl_syms_n) {
		/* What the producer said, because this object cannot say it
		 * itself - see kex_g_decl_syms. */
		print_syms(kex_g_decl_syms, kex_g_decl_syms_n);
	} else {
		static uint8_t blk[KOF_SYM_MAX_BYTES];

		print_syms(blk, kof_elf_syms(buf, e, blk, sizeof blk));
	}
}

/*
 * The symbol table, as the block kofsym.h defines rather than as ELF states it.
 *
 * Printed from the SAME bytes a rule would match, not from a second walk of the
 * section - so what is on the screen and what a signature sees cannot drift.
 * Each field gets the colour its KIND gets everywhere else in this tool: an
 * address is kex_C_LOC, a size is kex_C_SIZE, a name is kex_C_ID. Reading a record then
 * needs no legend, because the colours already mean those things on the segment
 * and section rows above.
 */
/*
 * Takes the BUILT BLOCK rather than the file and its parse.
 *
 * It used to call kof_elf_syms itself, which made it an ELF function by
 * construction. A PE has imports and exports in the same layout now - see
 * analyzers/parsers/binaries/pe_sym.c - so the builder is the caller's business and
 * this prints whatever it is handed. One printer, one layout, two formats.
 */
static void print_syms(const uint8_t *blk, uint32_t w)
{
	uint32_t count, i;

	if (!blk || w < KOF_SYM_HDRLEN)
		return;
	count = kof_sym_count(blk, w);
	printf("  symbols   %s%s%s  count=%s%u%s%s\n",
	       kex_C_ID, kof_sym_origin_name(blk, w),
	       kex_C_OFF, kex_C_SIZE, count, kex_C_OFF,
	       blk[KOF_SYM_H_TRUNC] ? "  (truncated: the block is full)" : "");
	for (i = 0; i < count; i++) {
		const uint8_t *r = kof_sym_rec(blk, w, i);

		if (!r)
			break;
		uint64_t val = kof_sym_u64(r, KOF_SYM_R_VALUE);
		uint64_t sz  = kof_sym_u64(r, KOF_SYM_R_SIZE);
		uint8_t  fl  = r[KOF_SYM_R_FLAGS];

		printf("     %s%-7s%s %s%-6s%s value=%s0x%-10llx%s size=%s%-8llu%s "
		       "%s%s%s%s %s%s%s\n",
		       kex_C_ID,   kof_sym_type_name(r[KOF_SYM_R_TYPE]), kex_C_OFF,
		       kex_C_WARN, kof_sym_bind_name(r[KOF_SYM_R_BIND]), kex_C_OFF,
		       kex_C_LOC,  (unsigned long long)val, kex_C_OFF,
		       kex_C_SIZE, (unsigned long long)sz,  kex_C_OFF,
		       kex_C_DIM,
		       (fl & KOF_SYM_F_UNDEFINED)   ? "UND " : "",
		       (fl & KOF_SYM_F_IN_WRITABLE) ? "W" : "",
		       kex_C_OFF,
		       kex_C_ID, kof_sym_name(blk, w, r, NULL), kex_C_OFF);
	}
}

void kex_print_pe(const void *view, const struct kof_obj_ctx *ctx,
		      kof_buf buf)
{
	const struct kgenome_pe_info *p = view;
	uint32_t i;

	(void)buf;

	printf("  image     %s  machine=0x%04x characteristics=0x%04x\n",
	       p->pe32_plus ? "PE32+" : "PE32", p->machine, p->characteristics);
	printf("  stub      lfanew=%llu gap=%llu\n",
	       (unsigned long long)p->lfanew, (unsigned long long)p->stub_len);
	printf("  headers   end=%llu declared=%llu\n",
	       (unsigned long long)p->header_end,
	       (unsigned long long)p->size_of_headers);
	printf("  entry     rva=0x%llx ", (unsigned long long)p->entry_rva);
	kex_put_off("off", ctx->entry_off);
	printf(" sec=%s perm=",
	       p->entry_sec < p->sec_count ? p->sec[p->entry_sec].name : "none");
	kex_put_perm(p->entry_perm);
	printf("\n");
	printf("  summary   code=%llu init=%llu uninit=%llu base_of_code=0x%llx\n",
	       (unsigned long long)p->size_of_code,
	       (unsigned long long)p->size_of_init_data,
	       (unsigned long long)p->size_of_uninit_data,
	       (unsigned long long)p->base_of_code);
	if (p->cert_len)
		printf("  signature off=%llu len=%llu\n",
		       (unsigned long long)p->cert_off,
		       (unsigned long long)p->cert_len);
	if (p->overlay_len)
		printf("  overlay   off=%llu len=%llu\n",
		       (unsigned long long)p->overlay_off,
		       (unsigned long long)p->overlay_len);
	kex_print_claimed("sections", p->nsec, p->nsec_claimed);
	for (i = 0; i < p->sec_count; i++) {
		printf("     %-9s off=%-9llu raw=%-9llu rva=0x%-8llx vsz=0x%-8llx ",
		       p->sec[i].name, (unsigned long long)p->sec[i].file_off,
		       (unsigned long long)p->sec[i].file_size,
		       (unsigned long long)p->sec[i].mem_rva,
		       (unsigned long long)p->sec[i].mem_size);
		kex_put_perm(p->sec[i].perm);
		/* Only when it differs: printing it always would bury the one case
		 * that matters under a column that repeats the previous one. */
		if (p->sec[i].file_size &&
		    (p->sec[i].claim_off != p->sec[i].file_off ||
		     p->sec[i].claim_len != p->sec[i].file_size))
			printf("  owns=[%llu,%llu)",
			       (unsigned long long)p->sec[i].claim_off,
			       (unsigned long long)(p->sec[i].claim_off +
						    p->sec[i].claim_len));
		printf("\n");
	}
	/* The imports and exports, in the same block and printed by the same
	 * function an ELF's symbols are - see print_syms. */
	if (kex_g_decl_syms && kex_g_decl_syms_n) {
		/* What the engine handed over with a normalised view: the view's own
		 * headers describe the file before the transform, so rebuilding from
		 * them printed "none" for a view whose parent has records - and says
		 * nothing of the APIs the program resolved for itself. The tool shows
		 * what the engine returned. */
		print_syms(kex_g_decl_syms, kex_g_decl_syms_n);
	} else {
		static uint8_t blk[KOF_SYM_MAX_BYTES];

		print_syms(blk, kof_pe_syms(buf, p, blk, sizeof blk));
	}
}
