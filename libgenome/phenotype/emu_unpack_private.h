/*
 * emu_unpack_private.h - what the files of the emulated unpack share (the gate, the ELF and PE images, the dump). NOT PART OF THE SURFACE.
 */
#ifndef KGENOME_EMU_UNP_PRIVATE_H
#define KGENOME_EMU_UNP_PRIVATE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <kofcore.h>       /* kof_st_le16/32 */
#include <kofplatform.h>   /* kof_memmem */
#include <kofdebug.h>
#include <kofentropy.h>
#include "emu_unpack.h"
#include <genotype/image/pe_image.h>   /* kgenome_pe_imports */

/* Where an ET_DYN object is placed, matching what a loader with ASLR off does.
 * The value matters only in that a stub reading its own addresses must find
 * them consistent; any base a real loader could have chosen will do. */
/*
 * p_type for PT_LOAD. The public view keeps the raw value, and this is the only
 * one it takes to answer "is this mapped"; the collector's own copy is not
 * exported and duplicating its whole table for one constant would be worse
 * than naming the one constant.
 */
#define KGENOME_EMU_UNP_PT_LOAD_TYPE  1u

#define KGENOME_EMU_UNP_STACK_TOP     0x00007ffffffff000ull

/*
 * The 32-bit stack, and it has to be its own number rather than the one above
 * masked down.
 *
 * A 32-bit guest computes stack addresses in 32 bits, so an esp of
 * 0x7ffffffff000 truncates to 0xfffff000 the moment the code touches it - and
 * then writes there, to a page nothing mapped. Measured: bloxor faulted on its
 * second instruction, writing to 0xffffef34. This is where Linux actually puts
 * a 32-bit stack, so the guest's own arithmetic lands inside what is mapped.
 */
#define KGENOME_EMU_UNP_STACK_TOP_32  0xfffff000ull

/*
 * A MEGABYTE, WHICH IS WHAT WINDOWS GIVES A THREAD.
 *
 * 64 pages - 256 KB - was enough for a Linux packer stub, which pushes a
 * frame or two and gets on with it. A protected PE runs its own loader first,
 * and that is ordinary compiled code with ordinary recursion in it: measured,
 * one stopped writing to 0xfffbeffe, which is two bytes below where 64 pages
 * ended. Nothing about the file was wrong; the stack was.
 *
 * The cost is address space and not memory - pages are committed as they are
 * touched - so the number is the one a real thread gets rather than the
 * smallest that happened to work.
 */
#define KGENOME_EMU_UNP_STACK_PAGES   256u

/*
 * WHERE A PE GOES WHEN IT DECLARES NOWHERE.
 *
 * ImageBase 0 is legal and a loader is then free to place the image. This has
 * no relocation machinery and a stub's absolute addresses are written against
 * the base the linker chose, so the useful default is the one the toolchains
 * use: 0x400000 for a 32-bit image and 0x140000000 for 64-bit. Both are where
 * an unrelocated image expects to find itself.
 */
#define KGENOME_EMU_UNP_PE_BASE_32    0x0000000000400000ull

#define KGENOME_EMU_UNP_PE_BASE_64    0x0000000140000000ull

/*
 * THE RETURN ADDRESS A PE ENTRY POINT IS CALLED WITH, and it deliberately
 * points at nothing mapped. A stub that RETURNS rather than jumping to its
 * payload then stops with a fault at an address that is recognisably this
 * value, instead of running on through whatever bytes happened to follow.
 */
#define KGENOME_EMU_UNP_PE_RET_MAGIC  0x00000000deadf00dull

/*
 * AND THE ADDRESS SPACE IS A MEGABYTE OF IT, of which only the pages above
 * hold anything.
 *
 * A guest that has a module base does not stop at the end of what this
 * bothered to write: it walks the image the header describes. Measured, one
 * sample read base+0x20b6c - past sixteen pages, and past nothing, so it
 * faulted. A real kernel32 is about this size, the extra pages are zero, and
 * kgenome_emu_map takes a mapped span larger than its contents for exactly this.
 */
/* The interpreter needs this number too - see KGENOME_EMU_WIN_MOD_SPAN. */
#define KGENOME_EMU_UNP_K32_SPAN       KGENOME_EMU_WIN_MOD_SPAN

/* How many functions one module image can export. Above the largest module in
 * the interpreter's table with room to grow - see the note where it bites. */
#define KGENOME_EMU_UNP_K32_MAX_EXPORTS 192u

/* ---- what one part offers another ---- */

/*
 * THE IMAGE LOADER (emu_unpack_map.c): what laying an executable's extents into
 * the emulator learned, and the three calls that fill it. One for an ELF
 * segment and a PE section alike; the format's policy is a field.
 */
#define KGENOME_EMU_UNP_BACK_MAX (KGENOME_PE_MAX_SECTIONS + 1)

struct kgenome_emu_unp_map {
	uint64_t base_lo;       /* the lowest address mapped (the caller's initial value until then) */
	uint64_t lowest_x;      /* where code could start, the lowest executable extent */
	uint64_t back_lo[KGENOME_EMU_UNP_BACK_MAX];   /* ranges holding REAL FILE BYTES, */
	uint64_t back_hi[KGENOME_EMU_UNP_BACK_MAX];   /* which is not the same as mapped */
	uint32_t n_back, mapped;
	int      improvised;    /* the entry is a guess */
	int      flat;          /* the file was mapped whole, for want of a header */
	int      borrow;        /* the bytes outlive the machine: whole pages are borrowed, not copied */
};

struct kgenome_emu_unp_extent {
	uint64_t va, off, file_size, mem_size;   /* file_size comes back clipped to the file */
	unsigned perm;          /* KGENOME_EMU_R/W/X */
	int      code;          /* an executable extent: counts toward lowest_x */
	uint64_t code_skip;     /* bytes at its front that are headers, not code */
	int      skip_past_end; /* an extent starting past the file: skip it (1) or map it as zero fill (0) */
};

void kgenome_emu_unp_map_init(struct kgenome_emu_unp_map *m, uint64_t base_lo);
int kgenome_emu_unp_map_extent(struct kgenome_emu *e, struct kgenome_emu_unp_map *m,
			       const uint8_t *file, uint64_t n,
			       struct kgenome_emu_unp_extent *x);
int kgenome_emu_unp_map_flat(struct kgenome_emu *e, struct kgenome_emu_unp_map *m,
			     uint64_t at, const uint8_t *file, uint64_t n);
int kgenome_emu_unp_map_entry(struct kgenome_emu_unp_map *m, uint64_t declared,
			      int flat_is_backed, const char *no_entry,
			      struct kgenome_emu_unp_report *rep, uint64_t *out);

int kgenome_emu_unp_build_teb_pe(struct kgenome_emu *e, unsigned bits, uint64_t image_base,
		uint64_t stack_lo, uint64_t stack_hi);
int kgenome_emu_unp_build_module_pe(struct kgenome_emu *e, unsigned bits, unsigned mi);
unsigned kgenome_emu_unp_fill_iat_pe(struct kgenome_emu *e,
		const struct kgenome_pe_imptab *tab, kof_buf f, const struct kgenome_pe_info *info,
		uint64_t base, unsigned bits);
int kgenome_emu_unp_build_stack_pe(struct kgenome_emu *e, unsigned bits);
unsigned kgenome_emu_unp_perm_of_pe(uint32_t p);
enum kgenome_emu_stop kgenome_emu_unp_emu_run_while_producing(struct kgenome_emu *e,
		uint64_t slice, int hand_back, unsigned extensions);

#endif /* KGENOME_EMU_UNP_PRIVATE_H */
