/*
 * audit_pmeta_pe_clr - independent audit of the metadata-only function table (2026-11-16), defect PMA-5.
 *
 * A PE32 x86 DLL whose CLR header (data directory 14) says the image is NOT IL-only (COR20 flags 0: a mixed-mode C++/CLI
 * image carries native code), with an export table naming one native function at RVA 0x1010 and the entry at 0x1000.
 * Oracle (the PE/COFF spec, ECMA-335 II.25.3.3): the export address table and AddressOfEntryPoint declare two starts in the
 * executable .text; COMIMAGE_FLAGS_ILONLY (bit 0) is clear, so .text holds native code. Real case: pe120 201_130 (mixed
 * x86, 2344 SafeSEH handlers + the entry): 1.65 MB of .text in no unit, every declared start dropped.
 *
 * Main (M): any image with a CLR header gets an EMPTY table (case PE_CLR, P_MANAGED): both declared starts are dropped and
 * no byte of .text is in a unit. Control: the same image without the CLR directory has both starts (trust MEDIUM).
 * Built in memory; linked against libkgenome.a alone.
 */
#include "audit_pmeta_kit.h"

static uint8_t img[4096];

static size_t pe_object(int clr)
{
	const uint32_t lf = 0x40, oh = lf + 24, so = oh + 0xe0;

	memset(img, 0, sizeof img);
	img[0] = 'M'; img[1] = 'Z';
	ak32(img + 0x3c, lf);
	memcpy(img + lf, "PE\0\0", 4);
	ak16(img + lf + 4, 0x14c); ak16(img + lf + 6, 2); ak16(img + lf + 20, 0xe0); ak16(img + lf + 22, 0x2102);
	ak16(img + oh, 0x10b);
	ak32(img + oh + 4, 0x200); ak32(img + oh + 8, 0x200);           /* SizeOfCode, SizeOfInitializedData */
	ak32(img + oh + 16, 0x1000);                                    /* AddressOfEntryPoint */
	ak32(img + oh + 20, 0x1000); ak32(img + oh + 24, 0x2000);       /* BaseOfCode, BaseOfData */
	ak32(img + oh + 28, 0x10000000);                                /* ImageBase */
	ak32(img + oh + 32, 0x1000); ak32(img + oh + 36, 0x200);        /* SectionAlignment, FileAlignment */
	ak16(img + oh + 40, 6); ak16(img + oh + 48, 6);                 /* OS, subsystem versions */
	ak32(img + oh + 56, 0x3000); ak32(img + oh + 60, 0x200);        /* SizeOfImage, SizeOfHeaders */
	ak16(img + oh + 68, 3);                                         /* Subsystem CUI */
	ak16(img + oh + 70, 0x0540);                                    /* DllCharacteristics: DYNAMIC_BASE, NX, NO_SEH */
	ak32(img + oh + 72, 0x100000); ak32(img + oh + 76, 0x1000); ak32(img + oh + 80, 0x100000); ak32(img + oh + 84, 0x1000);
	ak32(img + oh + 92, 16);                                        /* NumberOfRvaAndSizes */
	ak32(img + oh + 96, 0x2000); ak32(img + oh + 100, 0x40);        /* [0] export directory */
	if (clr) {
		ak32(img + oh + 96 + 8 * 14, 0x2080); ak32(img + oh + 100 + 8 * 14, 72);   /* [14] CLR runtime header */
	}
	memcpy(img + so, ".text\0\0\0", 8);
	ak32(img + so + 8, 0x20); ak32(img + so + 12, 0x1000); ak32(img + so + 16, 0x200); ak32(img + so + 20, 0x200);
	ak32(img + so + 36, 0x60000020);
	memcpy(img + so + 40, ".rdata\0\0", 8);
	ak32(img + so + 48, 0x200); ak32(img + so + 52, 0x2000); ak32(img + so + 56, 0x200); ak32(img + so + 60, 0x400);
	ak32(img + so + 76, 0x40000040);
	/* .text (file 0x200 = RVA 0x1000): the entry stub and one exported native function */
	img[0x200] = 0xb8; ak32(img + 0x201, 1); img[0x205] = 0xc2; ak16(img + 0x206, 12);   /* mov eax,1 ; ret 12 */
	img[0x210] = 0x55; img[0x211] = 0x89; img[0x212] = 0xe5; img[0x213] = 0x5d; img[0x214] = 0xc3;
	/* .rdata (file 0x400 = RVA 0x2000): export directory, EAT, DLL name, CLR header, metadata root */
	ak32(img + 0x400 + 12, 0x2030);         /* Name */
	ak32(img + 0x400 + 16, 1);              /* Base */
	ak32(img + 0x400 + 20, 1);              /* NumberOfFunctions */
	ak32(img + 0x400 + 28, 0x2028);         /* AddressOfFunctions */
	ak32(img + 0x428, 0x1010);              /* EAT[0]: the native function */
	memcpy(img + 0x430, "m.dll", 6);
	ak32(img + 0x480, 72); ak16(img + 0x484, 2); ak16(img + 0x486, 5);
	ak32(img + 0x488, 0x20d0); ak32(img + 0x48c, 32);                   /* MetaData */
	ak32(img + 0x490, 0);                                               /* Flags: ILONLY clear = mixed-mode */
	ak32(img + 0x4d0, 0x424a5342); ak16(img + 0x4d4, 1); ak16(img + 0x4d6, 1);
	ak32(img + 0x4dc, 12); memcpy(img + 0x4e0, "v4.0.30319", 10);
	return 0x600;
}

static void one(int clr)
{
	struct kgenome_func_set fs;
	size_t n = pe_object(clr);
	uint32_t i;

	printf("PMA-5 PE x86 DLL %s\n", clr ? "with a mixed-mode CLR header (ILONLY clear)" : "without a CLR header (control)");
	CK(ak_table(img, n, &fs));
	/* round 4 (rule changed): the export and the entry are declared starts of the native code, not units */
	(void)i;
	CK((ak_start_src(&fs, 0x210, NULL) & KGENOME_FN_S_EXPORT) != 0);    /* the export */
	CK((ak_start_src(&fs, 0x200, NULL) & KGENOME_FN_S_ENTRY) != 0);     /* the entry */
	CK(ak_uncovered(&fs, 0x200, 0x220) == 0);
	kgenome_funcs_free(&fs);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	one(0);
	one(1);
	printf("audit_pmeta_pe_clr: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
