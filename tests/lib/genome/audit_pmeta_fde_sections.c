/*
 * audit_pmeta_fde_sections - independent audit of the metadata-only function table (2026-11-16), defect PMA-1.
 *
 * Oracle: the .eh_frame of the object built below holds TWO valid FDEs, one per executable section (readelf
 * --debug-dump=frames lists both: pc=0x400100..0x400106 and pc=0x400110..0x400116). An FDE is an EXACT source (start and
 * size), so the function table must hold both as entries of trust HIGH with the FDE bit and length 6, whichever section
 * holds the entry point and whatever the second executable section is called (.init, .fini, .plt.got and a custom
 * section are all real places gcc/ld put code that carries an FDE).
 *
 * Observed on main (M): only the FDEs of ONE executable section are kept (the one holding the entry; with e_entry 0 the
 * other one); the other FDE is refused, the object says P_BAD_FDE and the function's bytes become a trust-NONE unit.
 * Real cases: the PLT FDEs of every gcc/ld dynamic executable; a function in a custom section
 * (__attribute__((section("mycode")))): its full twin keeps it from .symtab only, its stripped twin loses it.
 *
 * Built in memory (no fixture). Linked against libkgenome.a alone.
 */
#include <kgenome.h>
#include <genotype/image/elf_image.h>
#include <genotype/image/funcs.h>
#include <phenotype/diag_scan.h>

#include "hk.h"

#define VB 0x400000u
#define TEXT_OFF 0x100u
#define SEC2_OFF 0x110u
#define EH_OFF 0x120u

static void p16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void p32(uint8_t *p, uint32_t v) { p16(p, (uint16_t)v); p16(p + 2, (uint16_t)(v >> 16)); }
static void p64(uint8_t *p, uint64_t v) { p32(p, (uint32_t)v); p32(p + 4, (uint32_t)(v >> 32)); }

/* One FDE of 24 bytes at eh_frame offset `at` (file offset), CIE at EH_OFF, pc-relative sdata4 start, `n` bytes. */
static void fde(uint8_t *img, uint32_t at, uint32_t target, uint32_t n)
{
	p32(img + at, 0x14);
	p32(img + at + 4, at + 4 - EH_OFF);
	p32(img + at + 8, (uint32_t)((int32_t)target - (int32_t)(at + 8)));
	p32(img + at + 12, n);
	img[at + 16] = 0;                       /* augmentation length; 7 DW_CFA_nop follow (zero bytes) */
}

/* ELF64 x86-64 ET_EXEC: .text at 0x100 and `sec2` at 0x110 (both SHF_ALLOC|SHF_EXECINSTR, 8 bytes, one 6-byte function
 * each: push rbp; mov rbp,rsp; pop rbp; ret), .eh_frame (one CIE "zR", pcrel sdata4, then one FDE per function), .shstrtab.
 * One PT_LOAD R-X maps the whole file. Answers the file size. */
static size_t build(uint8_t *img, size_t cap, const char *sec2, uint64_t entry, int control)
{
	static const uint8_t body[8] = { 0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3, 0xcc, 0xcc };
	static const uint8_t cie[24] = { 0x14, 0, 0, 0, 0, 0, 0, 0, 1, 'z', 'R', 0, 1, 0x78, 16, 1, 0x1b,
					 0x0c, 7, 8, 0x90, 1, 0, 0 };
	char shs[64];
	size_t n2 = strlen(sec2), shs_n, shs_off, sh_off, size;
	uint32_t eh_n = 24 * 3 + 4;

	memset(img, 0, cap);
	shs_n = 0;
	memcpy(shs + shs_n, "\0.text\0", 7); shs_n += 7;
	memcpy(shs + shs_n, sec2, n2 + 1); shs_n += n2 + 1;
	memcpy(shs + shs_n, ".eh_frame\0.shstrtab\0", 20); shs_n += 20;
	shs_off = EH_OFF + eh_n;
	sh_off = (shs_off + shs_n + 7) & ~(size_t)7;
	size = sh_off + 64 * 5;
	if (size > cap)
		return 0;
	memcpy(img, "\x7f" "ELF\x02\x01\x01", 7);
	p16(img + 16, 2); p16(img + 18, 62); p32(img + 20, 1); p64(img + 24, entry); p64(img + 32, 64); p64(img + 40, sh_off);
	p16(img + 52, 64); p16(img + 54, 56); p16(img + 56, 1); p16(img + 58, 64); p16(img + 60, 5); p16(img + 62, 4);
	p32(img + 64, 1); p32(img + 68, 5); p64(img + 72, 0); p64(img + 80, VB); p64(img + 88, VB); p64(img + 96, size);
	p64(img + 104, size); p64(img + 112, 0x1000);
	memcpy(img + TEXT_OFF, body, 8);
	memcpy(img + SEC2_OFF, body, 8);
	memcpy(img + EH_OFF, cie, 24);
	fde(img, EH_OFF + 24, TEXT_OFF, 6);
	fde(img, EH_OFF + 48, SEC2_OFF, 6);
	memcpy(img + shs_off, shs, shs_n);
	{
		/* name, type, flags, addr, offset, size */
		const uint32_t nm[5] = { 0, 1, 7, (uint32_t)(8 + n2), (uint32_t)(8 + n2 + 10) };
		const uint32_t ty[5] = { 0, 1, 1, 1, 3 };
		const uint64_t fl[5] = { 0, 6, 6, 2, 0 };
		const uint64_t of[5] = { 0, TEXT_OFF, SEC2_OFF, EH_OFF, shs_off };
		const uint64_t sz[5] = { 0, control ? 0x18 : 8, 8, eh_n, shs_n };
		for (int i = 1; i < 5; i++) {
			uint8_t *s = img + sh_off + 64 * i;

			if (control && i == 2)
				continue;       /* control: one .text holds both functions; the second header stays SHT_NULL */
			p32(s, nm[i]); p32(s + 4, ty[i]); p64(s + 8, fl[i]); p64(s + 16, fl[i] & 2 ? VB + of[i] : 0);
			p64(s + 24, of[i]); p64(s + 32, sz[i]); p64(s + 48, 1);
		}
	}
	return size;
}

static void one(const char *sec2, uint64_t entry, int control)
{
	static uint8_t img[4096];
	size_t n = build(img, sizeof img, sec2, entry, control);
	struct kgenome_elf_info ei;
	struct kgenome_obj obj;
	struct kgenome_func_set fs;
	const uint64_t want[2] = { TEXT_OFF, SEC2_OFF };

	printf("case: second section %s, e_entry %#llx%s\n", sec2, (unsigned long long)entry, control ? " (control: both in .text, passes on main)" : "");
	CK(n != 0);
	memset(&ei, 0, sizeof ei);
	memset(&obj, 0, sizeof obj);
	memset(&fs, 0, sizeof fs);
	CK(kgenome_elf_image_parse(kof_buf_make(img, n), &ei, &obj));
	obj.file_header = &ei;
	kgenome_diag_funcs_of(&obj, img, n, &fs);
	for (int k = 0; k < 2; k++) {
		uint32_t i = kgenome_funcs_start(&fs, want[k]);

		CK(i != KGENOME_FUNCS_NONE);
		if (i == KGENOME_FUNCS_NONE)
			continue;
		CK(fs.v[i].trust == KGENOME_FN_TRUST_HIGH);
		CK((fs.v[i].source & KGENOME_FN_S_FDE) != 0);
		CK(fs.v[i].len == 6);
	}
	CK((fs.partial & KGENOME_FNTAB_P_BAD_FDE) == 0);   /* both FDEs are valid: nothing was refused */
	kgenome_funcs_free(&fs);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	one("mycode", VB + TEXT_OFF, 1);   /* control: the same two FDEs in ONE executable section - the checks below hold on main */
	one("mycode", VB + TEXT_OFF, 0);
	one(".init", VB + TEXT_OFF, 0);
	one(".plt.got", VB + TEXT_OFF, 0);
	one("mycode", VB + SEC2_OFF, 0);   /* entry in the second section: on main the .text FDE is then the one refused */
	one("mycode", 0, 0);               /* e_entry 0, as a shared object may have */
	printf("audit_pmeta_fde_sections: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
