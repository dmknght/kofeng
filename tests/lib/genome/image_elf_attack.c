/*
 * image_elf_attack - coverage-driven attack on kgenome_elf_image_parse (round 2, fix_engine2): the
 * machine table past x86/ARM/MIPS (read for the class that names one machine for two widths), the program
 * and section tables cut by the end of the object in each class and order, and the link/info words a
 * section header cut short does not carry. The twin of image_pe_attack for the other format: every case is
 * an object the hk builder wrote, with one field moved by the test.
 */

#define _GNU_SOURCE

#include <kgenome.h>

#include "hk.h"

static void result(const char *id, const char *what, int before)
{
	printf("%s %s: %s\n", id, what, hk_fails == before ? "ok" : "FAILED");
}

static struct kgenome_elf_info info;
static struct kgenome_obj obj;

static int parse_n(const struct hk_elf *e, uint64_t n)
{
	memset(&info, 0, sizeof info);
	memset(&obj, 0, sizeof obj);
	return kgenome_elf_image_parse(kof_buf_make(e->b, n), &info, &obj);
}

/* e_machine, and what the object's architecture must be for each class and order */
static void t_machine(void)
{
	static const struct { uint16_t m; uint32_t a32, a64; } tab[] = {
		{ 3, KGENOME_ARCH_X86, KGENOME_ARCH_X86 }, { 62, KGENOME_ARCH_X86_64, KGENOME_ARCH_X86_64 },
		{ 40, KGENOME_ARCH_ARM, KGENOME_ARCH_ARM }, { 183, KGENOME_ARCH_ARM64, KGENOME_ARCH_ARM64 },
		{ 243, KGENOME_ARCH_RISCV32, KGENOME_ARCH_RISCV64 }, { 8, KGENOME_ARCH_MIPS, KGENOME_ARCH_MIPS64 },
		{ 20, KGENOME_ARCH_PPC, KGENOME_ARCH_PPC }, { 21, KGENOME_ARCH_PPC64, KGENOME_ARCH_PPC64 },
		{ 45, KGENOME_ARCH_ARC, KGENOME_ARCH_ARC }, { 93, KGENOME_ARCH_ARC, KGENOME_ARCH_ARC },
		{ 195, KGENOME_ARCH_ARC, KGENOME_ARCH_ARC }, { 42, KGENOME_ARCH_SH, KGENOME_ARCH_SH },
		{ 4, KGENOME_ARCH_M68K, KGENOME_ARCH_M68K }, { 2, KGENOME_ARCH_SPARC, KGENOME_ARCH_SPARC },
		{ 18, KGENOME_ARCH_SPARC, KGENOME_ARCH_SPARC }, { 43, KGENOME_ARCH_SPARC64, KGENOME_ARCH_SPARC64 },
		{ 189, KGENOME_ARCH_MICROBLAZE, KGENOME_ARCH_MICROBLAZE }, { 94, KGENOME_ARCH_XTENSA, KGENOME_ARCH_XTENSA },
		{ 76, KGENOME_ARCH_CRIS, KGENOME_ARCH_CRIS }, { 92, KGENOME_ARCH_OR1K, KGENOME_ARCH_OR1K },
		{ 0, KGENOME_ARCH_OTHER, KGENOME_ARCH_OTHER }, { 22, KGENOME_ARCH_OTHER, KGENOME_ARCH_OTHER },
		{ 113, KGENOME_ARCH_OTHER, KGENOME_ARCH_OTHER },    /* Altera Nios II: not CRIS */
		{ 0xffff, KGENOME_ARCH_OTHER, KGENOME_ARCH_OTHER },
	};
	static struct hk_elf e;
	unsigned i, is64, be;
	int before = hk_fails;

	for (is64 = 0; is64 < 2u; is64++)
		for (be = 0; be < 2u; be++)
			for (i = 0; i < sizeof tab / sizeof tab[0]; i++) {
				const uint32_t want = is64 ? tab[i].a64 : tab[i].a32;

				hk_elf(&e, (int)is64, (int)be, 0);
				hk_w(e.b + 18, tab[i].m, 2, (int)be);
				CK(parse_n(&e, e.n));
				if (obj.arch != want)
					printf("  machine %u class %u order %u: arch %u, expected %u\n", tab[i].m, 32u + 32u * is64, be,
					       (unsigned)obj.arch, (unsigned)want);
				CK(obj.arch == want);
			}
	result("Q1 ", "machine to architecture, both classes and orders", before);
}

/* tables cut by the end of the object, in every class and order */
static void t_cut_tables(void)
{
	static struct hk_elf e;
	unsigned is64, be, cut;
	int before = hk_fails;

	for (is64 = 0; is64 < 2u; is64++)
		for (be = 0; be < 2u; be++) {
			hk_elf(&e, (int)is64, (int)be, 0);
			/* the program header table ends mid-entry: that entry is not read, said */
			for (cut = 1; cut < e.ph_ent; cut += (is64 ? 7u : 5u)) {
				CK(parse_n(&e, (uint64_t)e.ph + cut));
				CK(info.seg_count == 0u);
				CK((info.anomalies & KGENOME_ELF_ANOM_SEG_PAST_EOF) != 0);
			}
			/* the whole entry is there */
			CK(parse_n(&e, (uint64_t)e.ph + e.ph_ent));
			CK(info.seg_count == 1u);
			/* the section header table: every cut of the last header. A header is read whole or not at all
			 * (kof_slice answers an empty buffer for a range that is not inside the object), so a cut one
			 * is not a section with zeroed link and info words - which link_info's comment used to say -
			 * it is the end of the table, said. */
			for (cut = 1; cut < e.sh_ent; cut += (is64 ? 7u : 3u)) {
				CK(parse_n(&e, (uint64_t)e.sh + 5u * e.sh_ent + cut));
				CK(info.sec_count == 5u);
				CK((info.anomalies & KGENOME_ELF_ANOM_SEC_PAST_EOF) != 0);
			}
			CK(parse_n(&e, (uint64_t)e.sh + 6u * e.sh_ent));
			CK(info.sec_count == 6u && (info.anomalies & KGENOME_ELF_ANOM_SEC_PAST_EOF) == 0);
		}
	result("Q2 ", "program and section tables cut by the end of the object", before);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	t_machine();
	t_cut_tables();
	if (hk_fails) {
		printf("image_elf_attack: %d check(s) failed\n", hk_fails);
		return 1;
	}
	printf("image_elf_attack: ok\n");
	return 0;
}
