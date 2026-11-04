/*
 * fntab_pe_cfg.c - the load-configuration strategy of the PE function table: the function tables the linker writes for the loader - Control Flow Guard's list of valid indirect-call
 * targets (/guard:cf) and, on x86, the list of safe exception handlers (/SAFESEH). Each entry is the RVA of a function; the list is exact by construction (the loader refuses a call
 * to anything else), and it names what a direct call never does: the functions whose address is taken (callbacks, vtable members, handlers). Starts only.
 *
 * THE FORMAT. IMAGE_LOAD_CONFIG_DIRECTORY starts with its own Size (u32); a field exists only when Size reaches past it. PE32+: GuardCFFunctionTable (VA, u64) at 0x80, GuardCFFunctionCount
 * (u64) at 0x88, GuardFlags (u32) at 0x90. PE32: SEHandlerTable (VA, u32) at 0x40 and SEHandlerCount at 0x44; GuardCFFunctionTable at 0x50, GuardCFFunctionCount at 0x54, GuardFlags at 0x58.
 * A CF entry is an RVA followed by (GuardFlags >> 28) & 15 bytes of metadata (the stride); a handler entry is an RVA. The table's VA less the image base is its RVA.
 *
 * MEASURED (agent-reported, the oracle of this change): 1506 of 2428 x64 images of the sample carry the CF table; its entries hit 8.2% of the .pdata starts (address-taken functions) and
 * 25753 entries are functions .pdata has no entry for (leaves).
 *
 * HOSTILE INPUT: a Size too small for a field, a VA below the image base, a count past what the file holds (bounded by the file), an entry that is not in an executable section (counted in
 * out->n_bad), a stride that makes the table leave the file (the read stops) - each leaves the table as far as it validated and says so; the list's own cap is reported (P_CAP).
 */
#include <kofcore.h>
#include <genotype/image/pe_types.h>
#include "funcs.h"
#include "pe_image.h"
#include "fntab_private.h"

/* One table: `va` its address, `count` entries, `stride` bytes an entry (the RVA first). */
static void read_table(kof_buf file, const struct kgenome_pe_info *p, uint64_t va, uint64_t count, uint64_t stride, struct kgenome_fntab_list *out)
{
	uint64_t tab, i;

	if (!va || !count || va < p->image_base)
		return;
	tab = kgenome_pe_rva_to_off(p, va - p->image_base);
	if (tab == KGENOME_BROKEN || tab >= file.n)
		return;
	if (count > (file.n - tab) / stride)
		count = (file.n - tab) / stride;
	for (i = 0; i < count; i++) {
		uint32_t rva;
		uint64_t off, end;
		struct kgenome_func f;

		if (!kof_rd_u32(file, tab + i * stride, 0, &rva))
			break;
		if (!kgenome_fntab_pe_code_rva(p, file, rva, &off, &end)) {
			out->n_bad++;
			continue;
		}
		memset(&f, 0, sizeof f);
		f.off = off;
		f.source = KGENOME_FN_S_EXPORT;         /* an address table the image declares (the export table's class) */
		if (!kgenome_fntab_list_add(out, &f))
			return;
	}
}

void kgenome_fntab_pe_cfg(kof_buf file, const struct kgenome_pe_info *p, struct kgenome_fntab_list *out)
{
	const struct kgenome_pe_dir *d;
	uint64_t lc;
	uint32_t size;

	if (!file.p || !p || !p->valid)
		return;
	d = &p->dir[KGENOME_PE_DIR_LOAD_CONFIG];
	if (!d->rva)
		return;
	lc = kgenome_pe_rva_to_off(p, d->rva);
	if (lc == KGENOME_BROKEN || lc >= file.n || !kof_rd_u32(file, lc, 0, &size))
		return;
	if (p->pe32_plus) {
		uint64_t va = 0, cnt = 0;
		uint32_t fl = 0;

		if (size >= 0x94u && kof_rd_u64(file, lc + 0x80u, 0, &va) && kof_rd_u64(file, lc + 0x88u, 0, &cnt) && kof_rd_u32(file, lc + 0x90u, 0, &fl))
			read_table(file, p, va, cnt, 4u + ((fl >> 28) & 15u), out);
	} else {
		uint32_t va = 0, cnt = 0, fl = 0;

		if (size >= 0x48u && kof_rd_u32(file, lc + 0x40u, 0, &va) && kof_rd_u32(file, lc + 0x44u, 0, &cnt))
			read_table(file, p, va, cnt, 4u, out);                  /* the safe exception handlers */
		if (size >= 0x5cu && kof_rd_u32(file, lc + 0x50u, 0, &va) && kof_rd_u32(file, lc + 0x54u, 0, &cnt) && kof_rd_u32(file, lc + 0x58u, 0, &fl))
			read_table(file, p, va, cnt, 4u + ((fl >> 28) & 15u), out);
	}
}
