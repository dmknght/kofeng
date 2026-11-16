/*
 * fntab_elf_initarr.c - the loader-array strategy of the ELF function table: the functions the dynamic loader (or a static binary's own start-up code) calls from
 * .preinit_array, .init_array and .fini_array, which nothing in the program calls directly (constructors, destructors, frame_dummy).
 *
 * THE FORMAT. Each array is a run of pointers of the class's width (4 or 8 bytes) in the file's byte order, every one the address of a function. Found by section type
 * (SHT_INIT_ARRAY 14, SHT_FINI_ARRAY 15, SHT_PREINIT_ARRAY 16) when the file has a section table; otherwise through PT_DYNAMIC: DT_INIT_ARRAY 25 / DT_INIT_ARRAYSZ 27,
 * DT_FINI_ARRAY 26 / DT_FINI_ARRAYSZ 28, DT_PREINIT_ARRAY 32 / DT_PREINIT_ARRAYSZ 33 (address and size in bytes). Starts only: an array says where a function begins,
 * never where it ends. On ARM a pointer with bit 0 set is a Thumb function (isa_mode THUMB, `off` even).
 *
 * LIMIT (named, not guessed past): a slot of a position-independent file may hold 0 in the file and get its value from a relative relocation at load time (AArch64 by
 * default, any RELA target the linker did not apply in place). Such a slot, and the all-ones sentinel of the old .ctors convention, is counted in out->n_bad and left
 * out: the relocations are not read here. NEXT: read the R_*_RELATIVE relocations that patch the array (the dynamic relocation table is metadata too).
 *
 * HOSTILE INPUT: an array is read only as far as the file holds it (its size bounded by the file), a pointer that is not in an executable, file-backed segment or that
 * lies in a stub section is counted (n_bad) and refused; the dynamic table is read until DT_NULL or its segment's end; the list's own cap is reported (P_CAP).
 */
#include <string.h>

#include <kofcore.h>
#include <genotype/image/elf_types.h>
#include "elf_image.h"
#include "fntab_private.h"

#define SHT_INIT_ARRAY 14u
#define SHT_FINI_ARRAY 15u
#define SHT_PREINIT_ARRAY 16u
#define PT_DYNAMIC 2u
#define EM_ARM 40u

static int rd_word(kof_buf f, uint64_t off, int wide, int be, uint64_t *v)
{
	uint32_t x;

	if (wide)
		return kof_rd_u64(f, off, be, v);
	if (!kof_rd_u32(f, off, be, &x))
		return 0;
	*v = x;
	return 1;
}

/* One array: `n` bytes of pointers at file offset `at`. */
static void read_array(kof_buf file, const struct kgenome_elf_info *e, uint64_t at, uint64_t n, struct kgenome_fntab_list *out)
{
	const int wide = e->elf_class == KGENOME_ELFCLASS_64, be = e->elf_data == KGENOME_ELFDATA_BE;
	const uint64_t w = wide ? 8u : 4u;
	const uint64_t ones = wide ? UINT64_MAX : 0xffffffffu;
	uint64_t i;

	if (at >= file.n)
		return;
	if (n > file.n - at)
		n = file.n - at;
	for (i = 0; i + w <= n; i += w) {
		uint64_t va, off;
		struct kgenome_func f;

		if (!rd_word(file, at + i, wide, be, &va))
			break;
		memset(&f, 0, sizeof f);
		if (e->e_machine == EM_ARM && (va & 1u)) {
			va &= ~(uint64_t)1u;
			f.isa_mode = KGENOME_FN_ISA_THUMB;
		}
		if (!va || va == ones || va == (ones & ~(uint64_t)1u) || !kgenome_fntab_elf_code_va(e, va, &off)) {
			out->n_bad++;
			continue;
		}
		f.off = off;
		f.source = KGENOME_FN_S_INITARR;
		if (!kgenome_fntab_list_add(out, &f))
			return;
	}
}

/* No section table: the arrays named by the dynamic table. */
static void read_dynamic(kof_buf file, const struct kgenome_elf_info *e, struct kgenome_fntab_list *out)
{
	const int wide = e->elf_class == KGENOME_ELFCLASS_64, be = e->elf_data == KGENOME_ELFDATA_BE;
	const uint64_t w = wide ? 8u : 4u;
	uint64_t addr[3] = { 0, 0, 0 }, size[3] = { 0, 0, 0 };
	uint32_t i, k;

	for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++) {
		const struct kgenome_elf_seg *g = &e->seg[i];
		uint64_t pos, end;

		if (g->type != PT_DYNAMIC || g->file_off >= file.n)
			continue;
		end = g->file_size < file.n - g->file_off ? g->file_off + g->file_size : file.n;
		for (pos = g->file_off; pos + 2u * w <= end; pos += 2u * w) {
			uint64_t tag, val;

			if (!rd_word(file, pos, wide, be, &tag) || !rd_word(file, pos + w, wide, be, &val) || !tag)
				break;
			switch (tag) {
			case 25: addr[0] = val; break;
			case 27: size[0] = val; break;
			case 26: addr[1] = val; break;
			case 28: size[1] = val; break;
			case 32: addr[2] = val; break;
			case 33: size[2] = val; break;
			default: break;
			}
		}
		break;                  /* one dynamic table: the loader reads the first */
	}
	for (k = 0; k < 3u; k++) {
		uint64_t at;

		if (!addr[k] || !size[k])
			continue;
		/* the array itself is data (a writable segment, RELRO): placed by any loadable segment's file half, not only an executable one */
		if (!kgenome_elf_va_to_off(e, addr[k], 1, &at)) {
			out->n_bad++;
			continue;
		}
		read_array(file, e, at, size[k], out);
	}
}

void kgenome_fntab_initarr(kof_buf file, const struct kgenome_elf_info *e, struct kgenome_fntab_list *out)
{
	uint32_t i;
	int any = 0;

	if (!file.p || !e || !e->valid || !out || e->e_type == KGENOME_ELF_REL)
		return;
	for (i = 1; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
		const struct kgenome_elf_sec *s = &e->sec[i];

		if (s->type != SHT_INIT_ARRAY && s->type != SHT_FINI_ARRAY && s->type != SHT_PREINIT_ARRAY)
			continue;
		any = 1;
		if (s->file_size)
			read_array(file, e, s->file_off, s->file_size, out);
	}
	if (!any && e->sec_count <= 1u)
		read_dynamic(file, e, out);
}
