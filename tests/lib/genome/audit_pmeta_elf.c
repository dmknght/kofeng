/*
 * audit_pmeta_elf - independent audit of the metadata-only function table (2026-11-16): the ELF defects PMA-2, PMA-3,
 * PMA-4, PMA-6, PMA-7. Each case builds one object in memory (audit_pmeta_kit.h) and states the oracle - what readelf
 * says the object declares - next to the check. Each case RED on main at the time of the audit (M); a control case per
 * defect shows the same checks hold where the defect's trigger is absent. Linked against libkgenome.a alone.
 */
#include "audit_pmeta_kit.h"

#define VB64 0x400000u
#define VB32 0x10000u

static uint8_t img[8192];

/* PMA-2. ELF64 ET_EXEC with NO section table: one PT_LOAD R-X over the file, a PT_DYNAMIC whose DT_INIT_ARRAY holds two
 * code pointers, 0x400120 (below the entry 0x400180) and 0x4001c0 (above it). Oracle (readelf -dW + the two slots):
 * two init_array starts. Main: the start below the entry is dropped (n_extra) and the bytes below the entry are in no
 * unit; with a section table the same object is right (control `with_sections`). */
static size_t pma2_object(int with_sections, int no_meta)
{
	size_t size = 0x400;

	memset(img, 0, sizeof img);
	memcpy(img, "\x7f" "ELF\x02\x01\x01", 7);
	ak16(img + 16, 2); ak16(img + 18, 62); ak32(img + 20, 1); ak64(img + 24, VB64 + 0x180); ak64(img + 32, 64);
	ak64(img + 40, with_sections ? 0x2c0 : 0); ak16(img + 52, 64); ak16(img + 54, 56); ak16(img + 56, 2);
	ak16(img + 58, 64); ak16(img + 60, with_sections ? 5 : 0); ak16(img + 62, with_sections ? 4 : 0);
	if (no_meta)
		ak16(img + 56, 1);      /* no PT_DYNAMIC: the object declares no function at all (case NO_META) */
	ak32(img + 64, 1); ak32(img + 68, 5); ak64(img + 80, VB64); ak64(img + 88, VB64); ak64(img + 96, size);
	ak64(img + 104, size); ak64(img + 112, 0x1000);
	ak32(img + 120, 2); ak32(img + 124, 6); ak64(img + 128, 0x220); ak64(img + 136, VB64 + 0x220);
	ak64(img + 144, VB64 + 0x220); ak64(img + 152, 0x30); ak64(img + 160, 0x30); ak64(img + 168, 8);
	for (unsigned a = 0x100; a < 0x200; a += 0x20) {
		static const uint8_t fn[6] = { 0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3 };
		memcpy(img + a, fn, 6);
		memset(img + a + 6, 0xcc, 26);
	}
	ak64(img + 0x200, VB64 + 0x120);
	ak64(img + 0x208, VB64 + 0x1c0);
	ak64(img + 0x220, 25); ak64(img + 0x228, VB64 + 0x200);       /* DT_INIT_ARRAY */
	ak64(img + 0x230, 27); ak64(img + 0x238, 16);                 /* DT_INIT_ARRAYSZ */
	if (with_sections) {
		static const char shs[] = "\0.text\0.init_array\0.dynamic\0.shstrtab";
		const uint32_t nm[5] = { 0, 1, 7, 19, 28 }, ty[5] = { 0, 1, 14, 6, 3 };
		const uint64_t fl[5] = { 0, 6, 3, 3, 0 }, of[5] = { 0, 0x100, 0x200, 0x220, 0x280 }, sz[5] = { 0, 0x100, 16, 0x30, sizeof shs };

		memcpy(img + 0x280, shs, sizeof shs);
		for (int i = 1; i < 5; i++) {
			uint8_t *s = img + 0x2c0 + 64 * i;
			ak32(s, nm[i]); ak32(s + 4, ty[i]); ak64(s + 8, fl[i]); ak64(s + 16, fl[i] & 2 ? VB64 + of[i] : 0);
			ak64(s + 24, of[i]); ak64(s + 32, sz[i]); ak64(s + 48, 8);
		}
		size = 0x2c0 + 64 * 5;
	}
	return size;
}

/* PMA-2b. The same object with no PT_DYNAMIC: no function metadata at all (P_NO_META). Design: the code extent is ONE
 * NONE unit and the entry point does not split it. Main without a section table: the one unit starts AT THE ENTRY, the
 * code below it is in no unit (set356: 51 such ELF files, 6.1 MB, e.g. boatnet.i486 0..0x52a0 lost). */
static void pma2b(int with_sections)
{
	struct kgenome_func_set fs;
	size_t n = pma2_object(with_sections, 1);

	printf("PMA-2b no metadata at all, %s\n", with_sections ? "with a section table (control)" : "no section table");
	CK(ak_table(img, n, &fs));
	if (!with_sections)     /* the control's section table still names .init_array: it has metadata */
		CK((fs.partial & KGENOME_FNTAB_P_NO_META) != 0);
	CK(ak_uncovered(&fs, 0x100, 0x200) == 0);
	kgenome_funcs_free(&fs);
}

static void pma2(int with_sections)
{
	struct kgenome_func_set fs;
	size_t n = pma2_object(with_sections, 0);
	uint32_t i;

	printf("PMA-2 init_array start below the entry, %s\n", with_sections ? "with a section table (control)" : "no section table");
	CK(ak_table(img, n, &fs));
	/* round 4 (rule changed): the two init_array pointers are declared starts, not units */
	(void)i;
	CK((ak_start_src(&fs, 0x120, NULL) & KGENOME_FN_S_INITARR) != 0);
	CK((ak_start_src(&fs, 0x1c0, NULL) & KGENOME_FN_S_INITARR) != 0);
	CK(ak_uncovered(&fs, 0x100, 0x200) == 0);      /* the code before the entry is in a unit too */
	kgenome_funcs_free(&fs);
}

/* PMA-3. ELF64 ET_EXEC, .text 0x100..0x121: _start FUNC 16 at 0x100, `table` a NOTYPE symbol of size 16 at 0x110 (data in
 * .text: `.long 1,2,3,4` / `.size table,16`, as gcc -nostdlib built it), `after` FUNC 1 at 0x120. Oracle (readelf -sW):
 * two FUNC symbols; `table` is NOTYPE, which declares no function. Main: `table` is an entry of trust HIGH, source SYMTAB.
 * Control: _start and after are HIGH with their sizes. */
static void pma3(void)
{
	struct ak_elf e = { 1, 62, 2, 0, VB64, VB64 + 0x100, 0, 0, { { 0 } }, 0 };
	struct kgenome_func_set fs;
	static const char str[] = "\0table\0after\0_start";
	size_t n;
	uint32_t i;

	printf("PMA-3 NOTYPE symbol with a size inside .text\n");
	memset(img, 0, sizeof img);
	e.sec[1] = (struct ak_sec){ ".text", 1, 6, 0x100, 0x21, 0, 0, 0 };
	e.sec[2] = (struct ak_sec){ ".symtab", 2, 0, 0x200, 24 * 4, 3, 3, 24 };
	e.sec[3] = (struct ak_sec){ ".strtab", 3, 0, 0x280, sizeof str, 0, 0, 0 };
	e.nsec = 4;
	memset(img + 0x100, 0x90, 15);
	img[0x10f] = 0xc3;
	for (int k = 0; k < 4; k++)
		ak32(img + 0x110 + 4 * k, (uint64_t)k + 1);
	img[0x120] = 0xc3;
	ak_sym(img, 0x200 + 24, 1, 1, VB64 + 0x110, 16, (0 << 4) | 0, 1);   /* table: LOCAL NOTYPE */
	ak_sym(img, 0x200 + 48, 1, 7, VB64 + 0x120, 1, (0 << 4) | 2, 1);    /* after: LOCAL FUNC */
	ak_sym(img, 0x200 + 72, 1, 13, VB64 + 0x100, 16, (1 << 4) | 2, 1);  /* _start: GLOBAL FUNC */
	memcpy(img + 0x280, str, sizeof str);
	n = ak_elf_finish(img, sizeof img, &e, 0x2c0, 0x300);
	CK(n != 0 && ak_table(img, n, &fs));
	i = kgenome_funcs_start(&fs, 0x110);
	CK(i == KGENOME_FUNCS_NONE || fs.v[i].trust != KGENOME_FN_TRUST_HIGH);
	i = kgenome_funcs_start(&fs, 0x100);
	CK(i != KGENOME_FUNCS_NONE && fs.v[i].trust == KGENOME_FN_TRUST_HIGH && fs.v[i].len == 16);
	i = kgenome_funcs_start(&fs, 0x120);
	CK(i != KGENOME_FUNCS_NONE && fs.v[i].trust == KGENOME_FN_TRUST_HIGH && fs.v[i].len == 1);
	kgenome_funcs_free(&fs);
}

/* PMA-4. ELF64 ET_REL (gcc -c of two 32-aligned functions plus an asm `.fixup` section): .text 0x40..0x68 with f1 FUNC 4 at
 * 0 and f2 FUNC 8 at 0x20, the bytes between them alignment fill; .fixup 0x68..0x6e, SHF_EXECINSTR, no symbol. Oracle
 * (readelf -SW): two executable sections, 46 bytes of code. Every byte of a code extent is in exactly one unit (the table's
 * own invariant: a run no metadata declares is an entry of trust NONE). Main: 34 + 6 bytes are in no unit and the table says
 * COMPLETE. Control: f1 and f2 are HIGH. */
static void pma4(void)
{
	struct ak_elf e = { 1, 62, 1, 0, 0, 0, 0, 0, { { 0 } }, 0 };
	struct kgenome_func_set fs;
	static const char str[] = "\0f1\0f2";
	static const uint8_t f1[4] = { 0x8d, 0x47, 0x01, 0xc3 };
	static const uint8_t f2[8] = { 0xe8, 0, 0, 0, 0, 0x01, 0xc0, 0xc3 };
	static const uint8_t fx[6] = { 0xb8, 1, 0, 0, 0, 0xc3 };
	size_t n;
	uint32_t i;

	printf("PMA-4 ET_REL: alignment fill between functions and a code section with no symbol\n");
	memset(img, 0, sizeof img);
	e.sec[1] = (struct ak_sec){ ".text", 1, 6, 0x40, 0x28, 0, 0, 0 };
	e.sec[2] = (struct ak_sec){ ".fixup", 1, 6, 0x68, 6, 0, 0, 0 };
	e.sec[3] = (struct ak_sec){ ".symtab", 2, 0, 0x70, 24 * 3, 4, 1, 24 };
	e.sec[4] = (struct ak_sec){ ".strtab", 3, 0, 0xc0, sizeof str, 0, 0, 0 };
	e.nsec = 5;
	memcpy(img + 0x40, f1, 4);
	memset(img + 0x44, 0x90, 0x1c);
	memcpy(img + 0x60, f2, 8);
	memcpy(img + 0x68, fx, 6);
	ak_sym(img, 0x70 + 24, 1, 1, 0, 4, (1 << 4) | 2, 1);
	ak_sym(img, 0x70 + 48, 1, 4, 0x20, 8, (1 << 4) | 2, 1);
	memcpy(img + 0xc0, str, sizeof str);
	n = ak_elf_finish(img, sizeof img, &e, 0xd0, 0x100);
	CK(n != 0 && ak_table(img, n, &fs));
	i = kgenome_funcs_start(&fs, 0x40);
	CK(i != KGENOME_FUNCS_NONE && fs.v[i].trust == KGENOME_FN_TRUST_HIGH && fs.v[i].len == 4);
	i = kgenome_funcs_start(&fs, 0x60);
	CK(i != KGENOME_FUNCS_NONE && fs.v[i].trust == KGENOME_FN_TRUST_HIGH && fs.v[i].len == 8);
	CK(ak_uncovered(&fs, 0x40, 0x68) == 0);
	CK(ak_uncovered(&fs, 0x68, 0x6e) == 0);
	CK(fs.state != KGENOME_FNTAB_COMPLETE || ak_uncovered(&fs, 0x40, 0x6e) == 0);   /* never COMPLETE with code in no unit */
	kgenome_funcs_free(&fs);
}

/* PMA-6. ELF64 ET_EXEC with an FDE pc=0x400100..0x40010a (exact: start and size) whose start no sized symbol names, and a
 * .symtab holding _start FUNC 16 at 0x400110. Oracle (readelf --debug-dump=frames / -sW): the FDE is the only exact source
 * for 0x100..0x10a. Design: every fact of every exact source is kept, exact ranks over start-only. Main: when the object has
 * a .symtab the FDE is a check only - not kept (n_extra, P_SYMTAB) - and 0x100..0x10a is a NONE unit (mode 1); with a FUNC
 * symbol of size 0 one byte inside it (glibc's __restore_rt: the FDE starts one `nop` before the symbol, mode 2) the bytes
 * go to a MEDIUM entry at 0x101 instead. Control (mode 0): the same object with no .symtab: the FDE is a HIGH entry. */
static void pma6(int mode)
{
	struct ak_elf e = { 1, 62, 2, 0, VB64, VB64 + 0x110, 0, 0, { { 0 } }, 0 };
	struct kgenome_func_set fs;
	static const char str[] = "\0__restore_rt\0_start";
	static const uint8_t cie[24] = { 0x14, 0, 0, 0, 0, 0, 0, 0, 1, 'z', 'R', 0, 1, 0x78, 16, 1, 0x1b,
					 0x0c, 7, 8, 0x90, 1, 0, 0 };
	static const uint8_t rt[10] = { 0x90, 0xb8, 0x0f, 0, 0, 0, 0x0f, 0x05, 0xcc, 0xcc };
	static const char *const what[3] = { " - control: no .symtab", " - .symtab without a symbol there",
					     " - .symtab with a size-0 FUNC symbol one byte inside it" };
	size_t n;
	uint32_t i;

	printf("PMA-6 FDE-only start%s\n", what[mode]);
	memset(img, 0, sizeof img);
	e.sec[1] = (struct ak_sec){ ".text", 1, 6, 0x100, 0x20, 0, 0, 0 };
	e.sec[2] = (struct ak_sec){ ".eh_frame", 1, 2, 0x140, 52, 0, 0, 0 };
	e.sec[3] = (struct ak_sec){ ".symtab", 2, 0, 0x1a0, 24 * 3, 4, 2, 24 };
	e.sec[4] = (struct ak_sec){ ".strtab", 3, 0, 0x200, sizeof str, 0, 0, 0 };
	e.nsec = mode ? 5 : 3;
	memcpy(img + 0x100, rt, 10);
	memset(img + 0x10a, 0xcc, 6);
	memset(img + 0x110, 0x90, 15);
	img[0x11f] = 0xc3;
	memcpy(img + 0x140, cie, 24);
	ak32(img + 0x158, 0x14);
	ak32(img + 0x15c, 0x158 + 4 - 0x140);
	ak32(img + 0x160, (uint32_t)(0x100 - 0x160));    /* pcrel sdata4: 0x400100 */
	ak32(img + 0x164, 10);
	if (mode == 2)
		ak_sym(img, 0x1a0 + 24, 1, 1, VB64 + 0x101, 0, (0 << 4) | 2, 1);
	if (mode)
		ak_sym(img, 0x1a0 + 48, 1, 14, VB64 + 0x110, 16, (1 << 4) | 2, 1);
	memcpy(img + 0x200, str, sizeof str);
	n = ak_elf_finish(img, sizeof img, &e, 0x240, 0x280);
	CK(n != 0 && ak_table(img, n, &fs));
	i = kgenome_funcs_start(&fs, 0x100);
	CK(i != KGENOME_FUNCS_NONE);
	if (i != KGENOME_FUNCS_NONE) {
		CK(fs.v[i].trust == KGENOME_FN_TRUST_HIGH);
		CK((fs.v[i].source & KGENOME_FN_S_FDE) != 0);
		CK(fs.v[i].len == 10);
	}
	kgenome_funcs_free(&fs);
}

/* PMA-7. ELF32 ARM (EABI5) ET_EXEC: .text 0x100..0x120 with two Thumb functions at 0x100 and 0x110 (`bx lr`), an
 * .ARM.exidx with one row per function (prel31, EXIDX_CANTUNWIND), e_entry = 0x10101 (bit 0: Thumb). Oracle (readelf -h
 * -u): the entry function starts at 0x10100 and is Thumb; exidx rows at 0x10100 and 0x10110. Main: a MEDIUM entry starts
 * at the ODD offset 0x101 (inside the exidx function at 0x100), isa DEFAULT. Control (`arm_entry`): e_entry 0x10100. */
static void pma7(int arm_entry)
{
	struct ak_elf e = { 0, 40, 2, 0x05000000u, VB32, VB32 + 0x100 + (arm_entry ? 0 : 1), 0, 0, { { 0 } }, 0 };
	struct kgenome_func_set fs;
	size_t n;
	uint32_t i;

	printf("PMA-7 Thumb entry point (e_entry bit 0)%s\n", arm_entry ? " - control: even entry" : "");
	memset(img, 0, sizeof img);
	e.sec[1] = (struct ak_sec){ ".text", 1, 6, 0x100, 0x20, 0, 0, 0 };
	e.sec[2] = (struct ak_sec){ ".ARM.exidx", 0x70000001u, 0x82, 0x120, 16, 1, 0, 0 };
	e.nsec = 3;
	for (unsigned a = 0x100; a < 0x120; a += 2) {
		img[a] = 0x00;
		img[a + 1] = 0xbf;      /* nop.n */
	}
	img[0x10c] = 0x70; img[0x10d] = 0x47;   /* bx lr */
	img[0x11c] = 0x70; img[0x11d] = 0x47;
	ak32(img + 0x120, (uint32_t)(0x100 - 0x120) & 0x7fffffffu);
	ak32(img + 0x124, 1);
	ak32(img + 0x128, (uint32_t)(0x110 - 0x128) & 0x7fffffffu);
	ak32(img + 0x12c, 1);
	n = ak_elf_finish(img, sizeof img, &e, 0x140, 0x180);
	CK(n != 0 && ak_table(img, n, &fs));
	CK(kgenome_funcs_start(&fs, 0x101) == KGENOME_FUNCS_NONE);
	{
		/* round 4 (rule changed): the entry is a declared start (with the exidx row), not a unit */
		unsigned isa = 0;

		(void)i;
		CK((ak_start_src(&fs, 0x100, &isa) & KGENOME_FN_S_ENTRY) != 0);
		if (!arm_entry)
			CK(isa == KGENOME_FN_ISA_THUMB);
	}
	kgenome_funcs_free(&fs);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	pma2(1);
	pma2(0);
	pma2b(1);
	pma2b(0);
	pma3();
	pma4();
	pma6(0);
	pma6(1);
	pma6(2);
	pma7(1);
	pma7(0);
	printf("audit_pmeta_elf: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
