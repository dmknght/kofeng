/*
 * audit_pmeta2_rank - independent audit round 2 of the metadata-only function table (2026-11-16), defect PMA-8.
 *
 * ELF64 ET_EXEC: an FDE pc=0x400100..0x40010a whose CFI starts in the alignment fill before its function (glibc asm:
 * cfi_startproc before .p2align - `_dl_tlsdesc_undefweak` in fix_ptest e64_static_zlib/full: FDE 0x6b585+25, symbol
 * 0x6b590+14) and a .symtab FUNC `f` of size 5 at 0x400105 (the function itself), _start FUNC 16 at 0x400110.
 * Oracle (readelf -sW / --debug-dump=frames): .symtab says the function starts at 0x105 and is 5 bytes; the FDE says
 * 0x100+10. Both are exact; the design ranks .symtab over the FDE and records a disagreement (DISAGREE), never silently.
 *
 * Main after pmeta3 (M): the sized symbol is dropped ("start inside an exact body", n_extra) and the FDE is the HIGH entry
 * starting in the fill at 0x100; n_disagree 0. Round 1 main kept the symbol. Real files: set356 9 symbols (f01a3c 0x88c10,
 * ...), fix_ptest zlib full 1. Control: the same object with no .symtab - the FDE is the HIGH entry (passes).
 * Built in memory; linked against libkgenome.a alone.
 */
#include "audit_pmeta_kit.h"

#define VB64 0x400000u

static uint8_t img[8192];

static void one(int with_symtab)
{
	struct ak_elf e = { 1, 62, 2, 0, VB64, VB64 + 0x110, 0, 0, { { 0 } }, 0 };
	struct kgenome_func_set fs;
	static const char str[] = "\0f\0_start";
	static const uint8_t cie[24] = { 0x14, 0, 0, 0, 0, 0, 0, 0, 1, 'z', 'R', 0, 1, 0x78, 16, 1, 0x1b,
					 0x0c, 7, 8, 0x90, 1, 0, 0 };
	static const uint8_t body[10] = { 0x0f, 0x1f, 0x40, 0x00, 0x90,         /* 5 bytes of nop fill */
					  0x48, 0x8b, 0x47, 0x08, 0xc3 };       /* f: mov rax,[rdi+8]; ret */
	size_t n;
	uint32_t i;

	printf("PMA-8 FDE starting in the fill before a sized .symtab FUNC%s\n", with_symtab ? "" : " - control: no .symtab");
	memset(img, 0, sizeof img);
	e.sec[1] = (struct ak_sec){ ".text", 1, 6, 0x100, 0x20, 0, 0, 0 };
	e.sec[2] = (struct ak_sec){ ".eh_frame", 1, 2, 0x140, 52, 0, 0, 0 };
	e.sec[3] = (struct ak_sec){ ".symtab", 2, 0, 0x1a0, 24 * 3, 4, 2, 24 };
	e.sec[4] = (struct ak_sec){ ".strtab", 3, 0, 0x200, sizeof str, 0, 0, 0 };
	e.nsec = with_symtab ? 5 : 3;
	memcpy(img + 0x100, body, 10);
	memset(img + 0x10a, 0xcc, 6);
	memset(img + 0x110, 0x90, 15);
	img[0x11f] = 0xc3;
	memcpy(img + 0x140, cie, 24);
	ak32(img + 0x158, 0x14);
	ak32(img + 0x15c, 0x158 + 4 - 0x140);
	ak32(img + 0x160, (uint32_t)(0x100 - 0x160));    /* pcrel sdata4: 0x400100 */
	ak32(img + 0x164, 10);
	ak_sym(img, 0x1a0 + 24, 1, 1, VB64 + 0x105, 5, (0 << 4) | 2, 1);     /* f: LOCAL FUNC, 5 bytes */
	ak_sym(img, 0x1a0 + 48, 1, 3, VB64 + 0x110, 16, (1 << 4) | 2, 1);    /* _start: GLOBAL FUNC */
	memcpy(img + 0x200, str, sizeof str);
	n = ak_elf_finish(img, sizeof img, &e, 0x240, 0x280);
	CK(n != 0 && ak_table(img, n, &fs));
	if (with_symtab) {
		i = kgenome_funcs_start(&fs, 0x105);
		CK(i != KGENOME_FUNCS_NONE);
		if (i != KGENOME_FUNCS_NONE) {
			CK(fs.v[i].trust == KGENOME_FN_TRUST_HIGH);
			CK((fs.v[i].source & KGENOME_FN_S_SYMTAB) != 0);
			CK(fs.v[i].len == 5);
		}
		CK(fs.n_disagree != 0);         /* the FDE's other extent is recorded, not lost silently */
	} else {
		i = kgenome_funcs_start(&fs, 0x100);
		CK(i != KGENOME_FUNCS_NONE && fs.v[i].trust == KGENOME_FN_TRUST_HIGH && fs.v[i].len == 10);
	}
	kgenome_funcs_free(&fs);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	one(0);
	one(1);
	printf("audit_pmeta2_rank: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
