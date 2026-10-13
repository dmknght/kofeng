/*
 * api_constants - the public MACROS and enumerators of libgenome, held to what
 * they stand for: a number the ELF or PE format fixes is that number, a flag
 * is one bit that fits the field it travels in and collides with no other, a
 * table built by an X-macro has one row per member and no repeated key, and the
 * capability word's fields tile the 16 bits they are packed into.
 *
 * Most of these are the "untested" macros of docs/api_coverage_genome.txt. They
 * look inert and are not: a flag word narrowed to a uint8_t drops its ninth bit
 * silently, an action numbered past the stride falls out of KGENOME_NUCLEO_VALID
 * (this has happened once - see the comment in capability_word.h - and a test
 * of the vocabulary skipped the two words for the same reason), and an
 * architecture value that is not below KGENOME_ARCH_COUNT is a mask bit that
 * does not exist.
 */

#include <kgenome.h>
#include <genotype/x86/x86.h>
#include <celllysis/decode_arm32.h>
#include <genotype/arm32/arm32.h>
#include <genotype/arm32/thumb.h>

#include "hk.h"
#include "../../unit/known_miss.h"

static unsigned popcount64(uint64_t v)
{
	unsigned n = 0;

	while (v) {
		v &= v - 1u;
		n++;
	}
	return n;
}

/* every entry a single bit, distinct, within `width` bits */
static void one_bit_each(const char *what, const uint64_t *v, unsigned n, unsigned width)
{
	uint64_t seen = 0;
	unsigned i;

	for (i = 0; i < n; i++) {
		if (popcount64(v[i]) != 1 || (width < 64 && v[i] >> width) || (seen & v[i])) {
			printf("  FAIL %s[%u] = %#llx is not a distinct bit below bit %u\n", what, i,
			       (unsigned long long)v[i], width);
			hk_fails++;
		}
		seen |= v[i];
	}
}

/* ---- the formats' own numbers ------------------------------------------------------------------------- */

static void t_format_numbers(void)
{
	/* ELF: the standard's values */
	CK(KGENOME_ELF_PT_LOAD == 1);
	CK(KGENOME_ELF_PF_X == 1 && KGENOME_ELF_PF_W == 2 && KGENOME_ELF_PF_R == 4);
	CK(KGENOME_ELF_SHT_NULL == 0 && KGENOME_ELF_SHT_PROGBITS == 1 && KGENOME_ELF_SHT_SYMTAB == 2 &&
	   KGENOME_ELF_SHT_STRTAB == 3 && KGENOME_ELF_SHT_RELA == 4 && KGENOME_ELF_SHT_NOBITS == 8 &&
	   KGENOME_ELF_SHT_REL == 9 && KGENOME_ELF_SHT_DYNSYM == 11);
	CK(KGENOME_ELF_SHF_WRITE == 1 && KGENOME_ELF_SHF_ALLOC == 2 && KGENOME_ELF_SHF_EXEC == 4);
	CK(KGENOME_ELF_SHN_UNDEF == 0);
	CK(KGENOME_ELFCLASS_NONE == 0 && KGENOME_ELFCLASS_32 == 1 && KGENOME_ELFCLASS_64 == 2);
	CK(KGENOME_ELFDATA_NONE == 0 && KGENOME_ELFDATA_LE == 1 && KGENOME_ELFDATA_BE == 2);
	CK(KGENOME_ELF_NONE == 0 && KGENOME_ELF_REL == 1 && KGENOME_ELF_EXEC == 2 && KGENOME_ELF_DYN == 3 &&
	   KGENOME_ELF_CORE == 4 && KGENOME_ELF_TYPE_COUNT == 5);
	/* the program header's flags are the PERM_ bits in a different order: translated, never cast */
	CK((unsigned)KGENOME_PERM_X == KGENOME_ELF_PF_X && (unsigned)KGENOME_PERM_W == KGENOME_ELF_PF_W && (unsigned)KGENOME_PERM_R == KGENOME_ELF_PF_R);
	CK((unsigned)KGENOME_PE_PERM_X == (unsigned)KGENOME_PERM_X && (unsigned)KGENOME_PE_PERM_W == (unsigned)KGENOME_PERM_W &&
	   (unsigned)KGENOME_PE_PERM_R == (unsigned)KGENOME_PERM_R);
	CK(KGENOME_ELF_MAX_SEGMENTS == 64 && KGENOME_ELF_MAX_SECTIONS == 128 && KGENOME_ELF_SECNAME_MAX == 32);
	CK(KGENOME_ELF_SECNAME_SCAN >= KGENOME_ELF_SECNAME_MAX);
	CK(KGENOME_SYMNAME_MAX == 64);
	CK(KGENOME_ELF_INFO_VERSION == 1);
	/* the claimed regions of an ELF are the four it names and nothing else */
	CK(KGENOME_SCAN_ELF_CLAIMED == (KGENOME_SCAN_ELF_HEADERS | KGENOME_SCAN_ELF_CODE | KGENOME_SCAN_ELF_DATA | KGENOME_SCAN_ELF_NOLOAD));
	CK(!(KGENOME_SCAN_ELF_CLAIMED & (KGENOME_SCAN_ELF_UNCLAIMED | KGENOME_SCAN_ELF_SLIB_CODE | KGENOME_SCAN_ELF_SLIB_DATA)));
	{
		const uint64_t b[] = { KGENOME_SCAN_ELF_HEADERS, KGENOME_SCAN_ELF_CODE, KGENOME_SCAN_ELF_DATA,
			KGENOME_SCAN_ELF_NOLOAD, KGENOME_SCAN_ELF_UNCLAIMED, KGENOME_SCAN_ELF_SLIB_CODE, KGENOME_SCAN_ELF_SLIB_DATA };
		one_bit_each("SCAN_ELF", b, 7, 8);
	}
	/* PE */
	CK(KGENOME_PE_DOS_MAGIC == 0x5a4du && KGENOME_PE_SIG_MAGIC == 0x00004550u && KGENOME_PE_SIG_LEN == 4);
	CK(KGENOME_PE_COFF_LEN == 20 && KGENOME_PE_SEC_LEN == 40 && KGENOME_PE_MIN_OPT_LEN == 96);
	CK(KGENOME_PE_REL_ABSOLUTE == 0 && KGENOME_PE_REL_HIGHLOW == 3 && KGENOME_PE_REL_DIR64 == 10);
	CK(KGENOME_PE_CHAR_DLL == 0x2000 && KGENOME_PE_SUBSYS_NATIVE == 1);
	CK(KGENOME_PE_SECNAME_MAX == 9 && KGENOME_PE_MAX_SECTIONS == 96 && KGENOME_PE_INFO_VERSION == 1);
	CK(KGENOME_PE_DIR_COUNT == 16 && KGENOME_PE_DIR_EXPORT == 0 && KGENOME_PE_DIR_IMPORT == 1 &&
	   KGENOME_PE_DIR_SECURITY == 4 && KGENOME_PE_DIR_BASERELOC == 5 && KGENOME_PE_DIR_COM_DESCRIPTOR == 14);
	CK(KGENOME_PE_EXE == 0 && KGENOME_PE_DLL == 1 && KGENOME_PE_SYS == 2 && KGENOME_PE_IMAGE_COUNT == 3);
	CK(KGENOME_PE_LAYOUT_FILE == 0 && KGENOME_PE_LAYOUT_MAPPED == 1);
	CK(KGENOME_PE_ORIGIN_NONE == 0 && KGENOME_PE_ORIGIN_MANUAL < KGENOME_PE_ORIGIN_REPLACED);
	CK(KGENOME_PE_IMP_DLLLEN == 64);
	CK(KGENOME_PE_ANOM_COUNT == 27);
	{
		/* the anomaly words are single bits, one per member, in a 64-bit field */
		uint64_t b[KGENOME_PE_ANOM_COUNT], v;
		unsigned i;
		for (i = 0; i < KGENOME_PE_ANOM_COUNT; i++) {
			v = 1ull << i;
			b[i] = v;
		}
		CK(KGENOME_PE_ANOM_BAD_MZ == b[0] && KGENOME_PE_ANOM_RSRC_UNALIGNED == b[26]);
		one_bit_each("PE_ANOM", b, KGENOME_PE_ANOM_COUNT, 32);
	}
	CK(KGENOME_ELF_ANOM_COUNT == 24 && KGENOME_ELF_ANOM_BAD_MAGIC == 1ull && KGENOME_ELF_ANOM_SECTAB_MISSING == 1ull << 23);
	CK(KGENOME_SCAN_PE_CLAIMED & KGENOME_SCAN_PE_HEADERS);
	CK(KGENOME_SCAN_PE_CLAIMED & KGENOME_SCAN_CLR_CLAIMED);
	CK(!(KGENOME_SCAN_PE_CLAIMED & KGENOME_SCAN_PE_UNCLAIMED));
	{
		/* PE and CLR region bits live in one word and must not meet */
		const uint64_t b[] = { KGENOME_SCAN_PE_HEADERS, KGENOME_SCAN_PE_CODE, KGENOME_SCAN_PE_DATA, KGENOME_SCAN_PE_SIGNATURE,
			KGENOME_SCAN_PE_OVERLAY, KGENOME_SCAN_PE_UNCLAIMED, KGENOME_SCAN_PE_RESOURCE, KGENOME_SCAN_CLR_HEADER,
			KGENOME_SCAN_CLR_TABLES, KGENOME_SCAN_CLR_STRINGS, KGENOME_SCAN_CLR_US, KGENOME_SCAN_CLR_BLOB,
			KGENOME_SCAN_CLR_RESOURCE };
		one_bit_each("SCAN_PE+CLR", b, 13, 32);
	}
	CK(KGENOME_CLR_ANOM_COUNT == 5 && KGENOME_CLR_CLAIM_MAX == 7);
	CK(KGENOME_FMT_NONE == 0 && KGENOME_FMT_ELF == 1 && KGENOME_FMT_PE == 2);
	/* the section declaration flags: three independent axes with masks over them */
	CK(KGENOME_SECF_PLAIN == 0 && KGENOME_SECF_READ == 0);
	{
		const uint64_t what[] = { KGENOME_SECF_CODE, KGENOME_SECF_DATA, KGENOME_SECF_PAD, KGENOME_SECF_HOLLOW };
		const uint64_t origin[] = { KGENOME_SECF_REBUILT, KGENOME_SECF_SYNTHETIC };
		const uint64_t state[] = { KGENOME_SECF_COMPRESSED, KGENOME_SECF_CIPHERTEXT, KGENOME_SECF_VIRTUALISED };
		uint64_t all[9];
		unsigned i, n = 0;
		for (i = 0; i < 4; i++) all[n++] = what[i];
		for (i = 0; i < 2; i++) all[n++] = origin[i];
		for (i = 0; i < 3; i++) all[n++] = state[i];
		one_bit_each("SECF", all, n, 16);
		CK(KGENOME_SECF_ORIGIN_MASK == (KGENOME_SECF_REBUILT | KGENOME_SECF_SYNTHETIC));
		CK(KGENOME_SECF_STATE_MASK == (KGENOME_SECF_COMPRESSED | KGENOME_SECF_CIPHERTEXT | KGENOME_SECF_VIRTUALISED));
		CK(!(KGENOME_SECF_ORIGIN_MASK & KGENOME_SECF_STATE_MASK));
		CK(!((KGENOME_SECF_CODE | KGENOME_SECF_DATA | KGENOME_SECF_PAD | KGENOME_SECF_HOLLOW) &
		     (KGENOME_SECF_ORIGIN_MASK | KGENOME_SECF_STATE_MASK)));
	}
}

/* ---- flags and the fields they travel in -------------------------------------------------------------------- */

static void t_flag_words(void)
{
	/* a node's flags are a uint8_t (kgenome_nucleo_cap_of_*, `uint8_t *flags`): every bit fits */
	{
		const uint64_t f[] = { KGENOME_NUCLEO_F_LOW8, KGENOME_NUCLEO_F_LOOP, KGENOME_NUCLEO_F_EXECUTED,
			KGENOME_NUCLEO_F_VIA_REG, KGENOME_NUCLEO_F_WX, KGENOME_NUCLEO_F_DGRAM, KGENOME_NUCLEO_F_LOCAL,
			KGENOME_NUCLEO_F_BY_NAME };
		one_bit_each("NUCLEO_F", f, 8, 8);
	}
	/* a hit's `bits` is a uint8_t too */
	{
		const uint64_t f[] = { KGENOME_DIAG_H_OPAQUE, KGENOME_DIAG_H_REGION_STACK, KGENOME_DIAG_H_ZERO_OK,
			KGENOME_DIAG_H_ARG_UNKNOWN, KGENOME_DIAG_H_RAW_SYSCALL, KGENOME_DIAG_H_SUPERSEDED, KGENOME_DIAG_H_VAL,
			KGENOME_DIAG_H_SYMREF };
		one_bit_each("DIAG_H", f, 8, 8);
	}
	{
		const uint64_t f[] = { KGENOME_DIAG_RUN_SYSCALL, KGENOME_DIAG_RUN_SYMBOL, KGENOME_DIAG_RUN_EMULATE, KGENOME_DIAG_RUN_APIHASH };
		one_bit_each("DIAG_RUN", f, 4, 8);
		CK(KGENOME_DIAG_RUN_ALL == (KGENOME_DIAG_RUN_SYSCALL | KGENOME_DIAG_RUN_SYMBOL | KGENOME_DIAG_RUN_EMULATE | KGENOME_DIAG_RUN_APIHASH));
		CK((KGENOME_DIAG_RUN_DEFAULT & ~KGENOME_DIAG_RUN_ALL) == 0 && KGENOME_DIAG_RUN_DEFAULT != 0);
	}
	/* the xref word is uint32 but its answers live in the low nine bits */
	{
		const uint64_t f[] = { KGENOME_XREF_READ, KGENOME_XREF_WRITE, KGENOME_XREF_CALL, KGENOME_XREF_JUMP, KGENOME_XREF_ARG,
			KGENOME_XREF_PARTIAL, KGENOME_XREF_RGN_ICALL, KGENOME_XREF_RGN_NEAR, KGENOME_XREF_USER };
		one_bit_each("XREF", f, 9, 9);
	}
	/* the cell instruction: flags (uint8_t) and operand flags (uint8_t) */
	{
		const uint64_t f[] = { KGENOME_CELL_F_FAR, KGENOME_CELL_F_INDIRECT, KGENOME_CELL_F_REP };
		const uint64_t o[] = { KGENOME_CELL_OF_WRITE, KGENOME_CELL_OF_READ, KGENOME_CELL_OF_RIPREL, KGENOME_CELL_OF_HIGH8 };
		one_bit_each("CELL_F", f, 3, 8);
		one_bit_each("CELL_OF", o, 4, 8);
	}
	/* the x86 decoder's words: the instruction's flags are uint16, an operand's `mf` is uint16, access is uint8 */
	{
		const uint64_t g[] = { KGENOME_GF_X86_REX, KGENOME_GF_X86_66, KGENOME_GF_X86_67, KGENOME_GF_X86_LOCK, KGENOME_GF_X86_F2,
			KGENOME_GF_X86_F3, KGENOME_GF_X86_SEG, KGENOME_GF_X86_MODRM, KGENOME_GF_X86_SIB, KGENOME_GF_X86_M66,
			KGENOME_GF_X86_RIPREL };
		const uint64_t m[] = { KGENOME_X86_M_SEG, KGENOME_X86_M_BASE, KGENOME_X86_M_INDEX, KGENOME_X86_M_DISP, KGENOME_X86_M_RIPREL,
			KGENOME_X86_M_BCAST, KGENOME_X86_M_STACK, KGENOME_X86_M_STRING, KGENOME_X86_M_DIRECT, KGENOME_X86_M_AG,
			KGENOME_X86_M_BITBASE, KGENOME_X86_M_MIB, KGENOME_X86_M_VSIB, KGENOME_X86_M_SHSTK };
		const uint64_t a[] = { KGENOME_X86_ACC_R, KGENOME_X86_ACC_W, KGENOME_X86_ACC_CR, KGENOME_X86_ACC_CW };
		const uint64_t of[] = { KGENOME_X86_OF_DEFAULT, KGENOME_X86_OF_SEXT_OP1, KGENOME_X86_OF_SEXT_DWS };
		const uint64_t sf[] = { KGENOME_X86_SF_WRITE, KGENOME_X86_SF_READ, KGENOME_X86_SF_RIPREL, KGENOME_X86_SF_HIGH8 };
		one_bit_each("GF_X86", g, 11, 16);
		one_bit_each("X86_M", m, 14, 16);
		one_bit_each("X86_ACC", a, 4, 8);
		one_bit_each("X86_OF", of, 3, 8);
		one_bit_each("X86_SF", sf, 4, 8);
	}
	/* the sweep's operand is the cell's, bit for bit (decode_x86.c asserts the layout; the flags here) */
	CK(KGENOME_X86_SF_WRITE == KGENOME_CELL_OF_WRITE && KGENOME_X86_SF_READ == KGENOME_CELL_OF_READ &&
	   KGENOME_X86_SF_RIPREL == KGENOME_CELL_OF_RIPREL && KGENOME_X86_SF_HIGH8 == KGENOME_CELL_OF_HIGH8);
	CK(KGENOME_X86_SK_NONE == KGENOME_CELL_O_NONE && KGENOME_X86_SK_REG == KGENOME_CELL_O_REG &&
	   KGENOME_X86_SK_MEM == KGENOME_CELL_O_MEM && KGENOME_X86_SK_IMM == KGENOME_CELL_O_IMM &&
	   KGENOME_X86_SK_REL == KGENOME_CELL_O_REL);
	CK(KGENOME_X86_SREG_NONE == KGENOME_CELL_REG_NONE);
	/* the emulator's flags and protections */
	CK(KGENOME_EMU_X == 1 && KGENOME_EMU_W == 2 && KGENOME_EMU_R == 4);
	CK(KGENOME_EMU_X == KGENOME_ELF_PF_X && KGENOME_EMU_W == KGENOME_ELF_PF_W && KGENOME_EMU_R == KGENOME_ELF_PF_R);
}

/* ---- the register numberings the pieces share ----------------------------------------------------------------- */

static void t_register_numbers(void)
{
	/* the cell's x86 registers are the encoding's, which is also the emulator's order for the first eight */
	CK(KGENOME_CELL_REG_AX == KGENOME_EMU_RAX && KGENOME_CELL_REG_CX == KGENOME_EMU_RCX &&
	   KGENOME_CELL_REG_DX == KGENOME_EMU_RDX && KGENOME_CELL_REG_BX == KGENOME_EMU_RBX &&
	   KGENOME_CELL_REG_SP == KGENOME_EMU_RSP && KGENOME_CELL_REG_BP == KGENOME_EMU_RBP &&
	   KGENOME_CELL_REG_SI == KGENOME_EMU_RSI && KGENOME_CELL_REG_DI == KGENOME_EMU_RDI);
	CK(KGENOME_CELL_REG_AX == 0 && KGENOME_CELL_REG_DI == 7 && KGENOME_CELL_REG_NONE == 0xff);
	CK(KGENOME_EMU_NGPR == 16 && KGENOME_EMU_R15 == 15 && KGENOME_X86_NGPR == 16);
	/* the segment numbering is the decoder's, and the emulator's FS and GS are 4 and 5 */
	CK(KGENOME_CELL_SEG_ES == 0 && KGENOME_CELL_SEG_CS == 1 && KGENOME_CELL_SEG_SS == 2 &&
	   KGENOME_CELL_SEG_DS == 3 && KGENOME_CELL_SEG_FS == 4 && KGENOME_CELL_SEG_GS == 5);
	CK(KGENOME_CELL_SR_CR == 0 && KGENOME_CELL_SR_DR == 1 && KGENOME_CELL_SR_TR == 2);
	/* ARM: sp, lr, pc */
	CK(KGENOME_ARM_SP == 13 && KGENOME_ARM_LR == 14 && KGENOME_ARM_PC == 15);
	CK(KGENOME_ARM_R(0) == 1u && KGENOME_ARM_R(15) == 0x8000u && KGENOME_ARM_R(63) == 1ull << 63);
	CK(KGENOME_ARM_SH_NONE == 0 && KGENOME_ARM_SH_LSL == 1 && KGENOME_ARM_SH_LSR == 2 &&
	   KGENOME_ARM_SH_ASR == 3 && KGENOME_ARM_SH_ROR == 4 && KGENOME_ARM_SH_RRX == 5);
	/* the class and kind enums end where their count says */
	CK(KGENOME_CELL_OTHER == 0 && KGENOME_CELL_OP_COUNT > KGENOME_CELL_UD && KGENOME_CELL_UD == KGENOME_CELL_OP_COUNT - 1);
	CK(KGENOME_CELL_O_NONE == 0 && KGENOME_CELL_O_REL == 4);
	CK(KGENOME_CELL_STACK == 16);
}

/* ---- the architecture table ---------------------------------------------------------------------------------------- */

static void t_arch_table(void)
{
	static const struct { unsigned v; const char *w; } rows[] = {
#define ROW(name, val, word) { val, word },
		KGENOME_ARCH_LIST(ROW)
#undef ROW
	};
	const unsigned n = sizeof rows / sizeof rows[0];
	unsigned i, j;

	CK(n == KGENOME_ARCH_COUNT);
	CK(KGENOME_ARCH_ANY == 0 && KGENOME_ARCH_X86 == 1 && KGENOME_ARCH_X86_64 == 2 && KGENOME_ARCH_ARM == 3 &&
	   KGENOME_ARCH_ARM64 == 4 && KGENOME_ARCH_MIPS == 6 && KGENOME_ARCH_OTHER == 255);
	for (i = 0; i < n; i++) {
		CK(rows[i].v == i);                                  /* dense: a value is a bit position of a mask */
		CK(rows[i].v < KGENOME_ARCH_COUNT && rows[i].w && rows[i].w[0] && strlen(rows[i].w) <= 5);
		for (j = i + 1; j < n; j++)
			CK(strcmp(rows[i].w, rows[j].w) != 0);
	}
	CK(KGENOME_NA == UINT64_MAX && KGENOME_BROKEN == UINT64_MAX - 1u && KGENOME_NA != KGENOME_BROKEN);
	/* the object-type tables */
	{
		static const struct { unsigned v; } e[] = {
#define EROW(name, val) { val },
			KGENOME_ELF_TYPE_LIST(EROW)
#undef EROW
		};
		static const struct { unsigned v; } p[] = {
#define PROW(name, val) { val },
			KGENOME_PE_IMAGE_LIST(PROW)
#undef PROW
		};
		CK(sizeof e / sizeof e[0] == KGENOME_ELF_TYPE_COUNT);
		CK(sizeof p / sizeof p[0] == KGENOME_PE_IMAGE_COUNT);
		for (i = 0; i < sizeof e / sizeof e[0]; i++)
			CK(e[i].v == i);
		for (i = 0; i < sizeof p / sizeof p[0]; i++)
			CK(p[i].v == i);
	}
	/* the CLR region list names every region and no other */
	{
		unsigned cnt = 0;
#define CNT(x) cnt++;
		KGENOME_CLR_REGIONS(CNT)
#undef CNT
		CK(cnt == 6);
	}
	CK(KGENOME_GT_ARCH_X86_32 == 0 && KGENOME_GT_ARCH_X86_64 == 1);
	CK(KGENOME_INVALID == KGENOME_BAD_INPUT);
	CK(KGENOME_NUCLEO_A_MIPS32 == 1 && KGENOME_NUCLEO_A_X86_64 == 12);
	CK(KGENOME_NUCLEO_ROLE_NONE == 0 && KGENOME_NUCLEO_ROLE_MMAP == 1 && KGENOME_NUCLEO_ROLE_CLONE == 2 &&
	   KGENOME_NUCLEO_ROLE_SOCK == 3);
	CK(KGENOME_NUCLEO_AF_UNIX == 1 && KGENOME_NUCLEO_SOCK_DGRAM == 2 && KGENOME_NUCLEO_SOCK_RAW == 3);
	CK(KGENOME_NUCLEO_CLONE_THREAD == 0x10000u);
	CK(KGENOME_NAME_DIRECT == 1 && KGENOME_NAME_OBJECT == 2 && KGENOME_NAME_DIRECT != KGENOME_NAME_OBJECT);
}

/* ---- the capability word --------------------------------------------------------------------------------------------- */

static int km_cap_valid(void *arg)
{
	/* every capability the vocabulary names is a VALID word */
	unsigned c, bad = 0;

	(void)arg;
	for (c = 1; c < 0x10000u; c++) {
		const char *nm = kgenome_nucleo_cap_name((uint16_t)c);

		if (nm && strcmp(nm, "?") && !KGENOME_NUCLEO_VALID(c))
			bad++;
	}
	return bad ? 1 : 0;
}

static int km_cap_group_io(void *arg)
{
	/* a word's group is the group it was made with, and no two words share a dense slot */
	int seen[(KGENOME_CG_COUNT + 1) * KGENOME_NUCLEO_ACT_MAX];
	unsigned c, bad = 0;

	(void)arg;
	if (KGENOME_NUCLEO_GROUP(KGENOME_NUCLEO_MEM_READ) != KGENOME_CG_IO ||
	    KGENOME_NUCLEO_GROUP(KGENOME_NUCLEO_MEM_WRITE) != KGENOME_CG_IO ||
	    KGENOME_NUCLEO_GROUP(KGENOME_NUCLEO_FD_NONBLOCK) != KGENOME_CG_IO)
		bad++;
	memset(seen, 0, sizeof seen);
	for (c = 1; c < 0x10000u; c++) {
		const char *nm = kgenome_nucleo_cap_name((uint16_t)c);

		if (nm && strcmp(nm, "?") && KGENOME_NUCLEO_VALID(c) && seen[KGENOME_NUCLEO_DENSE(c)]++)
			bad++;
	}
	return bad ? 1 : 0;
}

static void t_capability_word(void)
{
	unsigned c, named = 0, valid = 0;
	int sig = 0;

	/* the field layout: context in bits 12-15, group in 8-11, action in 0-7 */
	CK(KGENOME_NUCLEO_MK(0, 0, 0) == 0);
	CK(KGENOME_NUCLEO_MK(1, 0, 0) == 0x1000 && KGENOME_NUCLEO_MK(0, 1, 0) == 0x100 && KGENOME_NUCLEO_MK(0, 0, 1) == 1);
	CK(KGENOME_NUCLEO_MK(0xf, 0xf, 0xff) == 0xffff);
	CK(KGENOME_NUCLEO_MK(0x10, 0, 0) == 0);                          /* a context past four bits wraps out of the 16-bit word */
	CK(KGENOME_NUCLEO_GROUP(0xffff) == 15 && KGENOME_NUCLEO_ACT(0xffff) == 255);
	CK(KGENOME_CG_BARE == 0 && KGENOME_CG_COUNT == 17 && KGENOME_CG_IO == KGENOME_CG_COUNT - 1);
	CK(KGENOME_CCTX_USER == 0 && KGENOME_CCTX_KERNEL == 1);
	CK(KGENOME_NUCLEO_ACT_MAX == 16);
	CK(KGENOME_NUCLEO_GROUP(KGENOME_NUCLEO_MK(0, KGENOME_CG_MEM, 1)) == KGENOME_CG_MEM);
	CK(KGENOME_NUCLEO_GROUP(KGENOME_NUCLEO_MK(0, KGENOME_CG_SERVICE, 1)) == KGENOME_CG_SERVICE);
	/* round trip of every (group, action) of the vocabulary's own groups */
	for (c = 0; c < 16; c++) {
		unsigned a;
		for (a = 0; a < 256; a++) {
			uint16_t w = KGENOME_NUCLEO_MK(0, c, a);
			CK(KGENOME_NUCLEO_GROUP(w) == c && KGENOME_NUCLEO_ACT(w) == a);
			CK(KGENOME_NUCLEO_DENSE(w) == c * KGENOME_NUCLEO_ACT_MAX + a);
		}
	}
	CK(!KGENOME_NUCLEO_VALID(0));
	CK(!KGENOME_NUCLEO_VALID(KGENOME_NUCLEO_MK(0, KGENOME_CG_MEM, 0)));              /* action 0 is "none" */
	CK(!KGENOME_NUCLEO_VALID(KGENOME_NUCLEO_MK(0, KGENOME_CG_MEM, KGENOME_NUCLEO_ACT_MAX)));
	CK(KGENOME_NUCLEO_VALID(KGENOME_NUCLEO_MK(0, KGENOME_CG_MEM, KGENOME_NUCLEO_ACT_MAX - 1u)));
	CK(KGENOME_NUCLEO_VALID(KGENOME_NUCLEO_MK(0, KGENOME_CG_MEM, 1)));

	/* every named capability: unique name, a valid word, a dense slot of its own, and the generic of
	 * a word is itself named */
	for (c = 1; c < 0x10000u; c++) {
		const char *nm = kgenome_nucleo_cap_name((uint16_t)c);
		unsigned g;

		if (!nm || !strcmp(nm, "?"))
			continue;
		named++;
		if (KGENOME_NUCLEO_VALID(c))
			valid++;
		g = kgenome_nucleo_cap_generic((uint16_t)c);
		if (g) {
			const char *gn = kgenome_nucleo_cap_name((uint16_t)g);
			CK(gn && strcmp(gn, "?") != 0);
		}
	}
	CK(named >= 60);
	{
		unsigned a, b;
		for (a = 1; a < 0x10000u; a++) {
			const char *na = kgenome_nucleo_cap_name((uint16_t)a);
			if (!na || !strcmp(na, "?") || a > 0x4ffu)
				continue;
			for (b = a + 1u; b < 0x10000u && b <= 0x4ffu; b++) {
				const char *nb = kgenome_nucleo_cap_name((uint16_t)b);
				if (nb && !strcmp(na, nb))
					CK(0);
			}
		}
	}
	CK(!strcmp(kgenome_nucleo_cap_name(0), "?"));
	CK(!strcmp(kgenome_nucleo_cap_name(0xffff), "?"));

	KM_CHECK(hk_isolated(km_cap_valid, NULL, 10, &sig) == HK_OK,
		 "a capability the vocabulary names is not a valid capability word: net-hdrincl is action 16 of its group",
		 "celllysis/capability_word.h: KGENOME_CA_NET_HDRINCL is the sixteenth action of KGENOME_CG_NET, so "
		 "KGENOME_NUCLEO_ACT(KGENOME_NUCLEO_NET_HDRINCL) == KGENOME_NUCLEO_ACT_MAX: KGENOME_NUCLEO_VALID is 0 for it "
		 "(libkofeng/databases/diagsrc.c:105 skips it in the table check; tests/lib/genome/diag_roles.c skips it) and "
		 "KGENOME_NUCLEO_DENSE gives 64, the slot of action 0 of the next group. The same class of defect the comment "
		 "in capability_word.h records for mem-action-read/write. Repro: KGENOME_NUCLEO_VALID(0x310) == 0 while "
		 "kgenome_nucleo_cap_name(0x310) == \"net-hdrincl\"");
	(void)valid;
	KM_CHECK(hk_isolated(km_cap_group_io, NULL, 10, &sig) == HK_OK,
		 "the I/O capabilities do not fit the capability word: mem-read is context KERNEL, group BARE, and shares a dense slot with sleep",
		 "celllysis/capability_word.h: KGENOME_CG_IO is 16 and KGENOME_CG_COUNT is 17, but KGENOME_NUCLEO_MK keeps a group in 4 "
		 "bits (8-11) and KGENOME_NUCLEO_GROUP masks with 0xf, so KGENOME_NUCLEO_MK(USER, CG_IO, 1) = 0x1001 carries 16 into the "
		 "context field: KGENOME_NUCLEO_GROUP(KGENOME_NUCLEO_MEM_READ) == 0 (BARE), its context is KERNEL, and "
		 "KGENOME_NUCLEO_DENSE gives 1, the slot of `sleep` (0x0001); mem-write/anti-debug likewise. The guard "
		 "`typedef char kgenome_cap_groups_fit[(KGENOME_CG_COUNT <= 64) ? 1 : -1]` states the wrong limit (16). "
		 "Repro: KGENOME_NUCLEO_GROUP(0x1001) != KGENOME_CG_IO");
}

/* ---- the sizes and limits the headers publish ------------------------------------------------------------------------- */

static void t_limits(void)
{
	/* the budget's floors and the scaling constants are what the defaults are derived from */
	CK(KGENOME_NODES_MIN == 4096u && KGENOME_NAMES_MIN == 1024u && KGENOME_INSN_MIN == 2000000ull &&
	   KGENOME_RESOLVE_MIN == 4000000ull && KGENOME_RESOLVE_MIN >= KGENOME_INSN_MIN);
	CK(KGENOME_MAX_INDEX == 0xfffeu && KGENOME_MAX_INDEX < 0xffffu);          /* 0xffff is "none", 0xfffe "stack" */
	CK(KGENOME_DIAG_FROM_STACK == KGENOME_MAX_INDEX);
	CK(KGENOME_NAMES_MIN <= KGENOME_NODES_MIN);
	/* a node index is 16 bits wide in a hit's link */
	{
		struct kgenome_diag_in in;
		in.from = (uint16_t)KGENOME_MAX_INDEX;
		CK(in.from == KGENOME_MAX_INDEX);
	}
	CK(KGENOME_EMU_PAGE == 4096u && (KGENOME_EMU_PAGE & (KGENOME_EMU_PAGE - 1u)) == 0);
	CK(KGENOME_EMU_DEF_PAGES == 16u * 1024u);
	CK(KGENOME_EMU_IDLE == 4u << 20 && KGENOME_EMU_QUIET == 1500u);
	CK(KGENOME_EMU_MAX_VMA == 1024u && KGENOME_EMU_MAX_SNAP == 64u && KGENOME_EMU_SAY == 4096u);
	CK(KGENOME_EMU_EXEC_WATCH == 16u && KGENOME_EMU_WATCH_MAX == 16u && KGENOME_EMU_INSN_WATCH == 8u &&
	   KGENOME_EMU_INSN_WATCH_LEN == 8u && KGENOME_EMU_SHIM_MAX == 16u && KGENOME_EMU_SHIM_NAME == 48u);
	CK(KGENOME_EMU_TRACE == 256u && KGENOME_EMU_SYSLOG == 64u && KGENOME_EMU_UNKSYS == 8u && KGENOME_EMU_ITRACE_MAX == 262144u);
	CK(KGENOME_EMU_PATCH_LEN == 16u && KGENOME_EMU_PATCH_MAX == 16u && KGENOME_EMU_EXTEND_MAX == 8u &&
	   KGENOME_EMU_UNP_PE_RUN_CHUNKS == 8u);
	/* a module's span holds its images, and a stub is a power-of-two stride */
	CK(KGENOME_EMU_WIN_MOD_SPAN == 256u * KGENOME_EMU_PAGE && KGENOME_EMU_WIN_STUB == 16u && KGENOME_EMU_WIN_STUB_RVA == 0x1000u);
	CK(KGENOME_EMU_WIN_MOD_K32 == 0 && KGENOME_EMU_WIN_MOD_NTDLL == 1 && KGENOME_EMU_WIN_MOD_USER32 == 2 &&
	   KGENOME_EMU_WIN_MOD_ADVAPI32 == 3 && KGENOME_EMU_WIN_MOD_SHELL32 == 4 && KGENOME_EMU_WIN_MOD_SHLWAPI == 5 &&
	   KGENOME_EMU_WIN_MOD_MSVCRT == 6 && KGENOME_EMU_WIN_MOD_OLE32 == 7 && KGENOME_EMU_WIN_MOD_KBASE == 8 &&
	   KGENOME_EMU_WIN_MOD_WS2 == 9 && KGENOME_EMU_WIN_MOD_COUNT == 10);
	{
		/* every module id names a module, and the names are the libraries' */
		static const struct { unsigned id; const char *want; } m[] = {
			{ KGENOME_EMU_WIN_MOD_K32, "kernel32" }, { KGENOME_EMU_WIN_MOD_NTDLL, "ntdll" },
			{ KGENOME_EMU_WIN_MOD_USER32, "user32" }, { KGENOME_EMU_WIN_MOD_ADVAPI32, "advapi32" },
			{ KGENOME_EMU_WIN_MOD_SHELL32, "shell32" }, { KGENOME_EMU_WIN_MOD_SHLWAPI, "shlwapi" },
			{ KGENOME_EMU_WIN_MOD_MSVCRT, "msvcrt" }, { KGENOME_EMU_WIN_MOD_OLE32, "ole32" },
			{ KGENOME_EMU_WIN_MOD_KBASE, "kernelbase" }, { KGENOME_EMU_WIN_MOD_WS2, "ws2_32" } };
		unsigned i;
		for (i = 0; i < sizeof m / sizeof m[0]; i++) {
			const char *nm = kgenome_emu_win_mod_name(m[i].id);
			CK(nm != NULL && strstr(nm, m[i].want) != NULL);
		}
	}
	/* the mutation windows */
	CK(KGENOME_MUTATION_NG == 8u && KGENOME_MUTATION_MIN_HASH == 16u && KGENOME_MUTATION_MINHASH_K == 32u);
	CK(KGENOME_MUTATION_BASE == 16777619u && KGENOME_MUTATION_MIX == 2654435761u);
	CK((KGENOME_MUTATION_SEG_AVG & (KGENOME_MUTATION_SEG_AVG - 1u)) == 0);   /* the cut masks with avg - 1 */
	CK(KGENOME_MUTATION_RAW == 0 && KGENOME_MUTATION_XOR == 1 && KGENOME_MUTATION_SUB == 2 && KGENOME_MUTATION_NORM_COUNT == 3);
	CK(KGENOME_MUTATION_SIDE_USER == 0 && KGENOME_MUTATION_SIDE_LIB == 1);
	CK(KGENOME_TRUE_MAX_SPANS == 16u && KGENOME_TRUE_MAX_SPANS_ALL == 2048u);
	CK(KGENOME_XREF_MAX == 8192u);
	/* the decode tables' index sizes */
	CK(KGENOME_ARM32_KEYS == 4096u && KGENOME_THUMB_NARROW_KEYS == 1024u && KGENOME_THUMB_WIDE_KEYS == 1024u);
	CK(KGENOME_ARM32_DIRECT == 0x8000u && KGENOME_ARM32_UNLIKELY(0) == 0);
	CK(KGENOME_X86_MAX_OPS == 10 && KGENOME_X86_TEXT == 160u);
	/* the diagnose graph */
	CK(KGENOME_DIAG_KIND_PRODUCED == 0 && KGENOME_DIAG_KIND_SHARED == 1);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);

	t_format_numbers();
	t_flag_words();
	t_register_numbers();
	t_arch_table();
	t_capability_word();
	t_limits();
	printf("api_constants: %d failure(s), %u known\n", hk_fails, km_known());
	return hk_fails != 0 || km_failed();
}
