/*
 * pe_sym.c - a PE's imports and exports, in the KSYM layout.
 *
 * The PE half of what elf_sym.c does for ELF, and it exists so that a rule
 * asking "what does this object import" or "what does it export" asks it the
 * same way whatever the format is. The layout, the record length and the enum
 * values are kofmod/kofsym.h's; nothing here is PE-shaped except where the
 * names come from.
 *
 *
 * WHAT A PE CALLS A SYMBOL
 *
 * ELF has one table with a bind field that says whether an entry is defined
 * here or wanted from elsewhere. A PE has TWO tables that mean those two
 * things: the import directory, which is a list of what this file needs from
 * other modules, and the export directory, which is what it offers. So the
 * mapping is not a guess:
 *
 *   an import  ->  STT_FUNC, STB_GLOBAL, KOF_SYM_F_UNDEFINED
 *   an export  ->  STT_FUNC, STB_GLOBAL, KOF_SYM_F_DEFINED
 *
 * STT_FUNC for both, and that is an approximation worth naming: a PE import or
 * export can be data - a variable exported from a DLL - and the directories do
 * not say which. ELF's own STT_NOTYPE would be the honest answer for "not
 * stated", but it would also throw away the fact that the overwhelming
 * majority ARE functions, which is what a rule wants to key on. FUNC is
 * therefore what is written, and this comment is where that is admitted.
 *
 *
 * NAMES: "DLL!function"
 *
 * An import's name alone is not what identifies it - CreateFileW from
 * kernel32 and from a helper DLL that forwards it are different facts - and
 * the DLL is in a different structure from the function, so a rule matching
 * bytes could not otherwise see both at once. Joined with '!', which is the
 * form every Windows tool writes and no symbol name contains.
 *
 * An import BY ORDINAL has no name at all, and is written "DLL!#nnn". That is
 * a real technique rather than an edge case: importing by ordinal is a way of
 * not saying which function is being used, and a rule looking for it needs the
 * ordinal to be matchable.
 *
 * WHICH HALF LOSES WHEN THE PAIR DOES NOT FIT. The record's name field is
 * KOF_SYM_NAMELEN and "DLL!function" can exceed it, so one of the two is cut -
 * and it must be the DLL. The function name is what identifies an import; the
 * module is what disambiguates it, and a rule that has the function and a
 * truncated module still has something to match, while the reverse has nothing.
 * So the DLL is capped at DLL_ROOM and the function takes the rest. DLL_ROOM
 * is 16, which holds every ordinary Windows module name whole - kernel32.dll
 * is 12, advapi32.dll is 12 - and cuts only the long api-ms-win-* forms, where
 * the interesting half is the function anyway.
 */
#define DLL_ROOM 16

#include <stdio.h>
#include <string.h>

#include <kofcore.h>
#include <kofmod/kofsym.h>
#include <kofmod/pe.h>
#include "pe_sym.h"

/* The import descriptor, whose fields this walks by offset for the reason
 * elf_sym.c walks Elf64_Sym by offset: the struct is a file format, not a C
 * declaration, and reading it as one is what makes the endianness and the
 * packing somebody else's problem. */
#define IMP_ORIG_THUNK   0u    /* 4  OriginalFirstThunk (the name table)   */
#define IMP_NAME         12u   /* 4  RVA of the DLL name                   */
#define IMP_FIRST_THUNK  16u   /* 4  FirstThunk (the IAT)                  */
#define IMP_LEN          20u

#define EXP_N_FUNCS      20u   /* 4  NumberOfFunctions                     */
#define EXP_N_NAMES      24u   /* 4  NumberOfNames                         */
#define EXP_FUNCS        28u   /* 4  AddressOfFunctions                    */
#define EXP_NAMES        32u   /* 4  AddressOfNames                        */
#define EXP_ORDS         36u   /* 4  AddressOfNameOrdinals                 */

/*
 * How many descriptors and thunks one file may contribute.
 *
 * Bounded because both are NUL-terminated lists inside the file, so a hostile
 * or damaged one can be as long as the file is: the terminator is data. Nothing
 * here trusts a count it was given.
 */
#define MAX_DLLS   256u
#define MAX_THUNKS 4096u

static void put16(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t v)
{
	put16(p, v & 0xffffu);
	put16(p + 2, v >> 16);
}

static void put64(uint8_t *p, uint64_t v)
{
	put32(p, (uint32_t)v);
	put32(p + 4, (uint32_t)(v >> 32));
}

/*
 * Copy a NUL-terminated name out of the file at `off`, sanitised.
 *
 * Printable only, for the reason elf_sym.c gives: the field is compared
 * against text in a rule, and a control byte from a hostile name table would
 * end a pattern early or, worse, match one. Returns the length written.
 */
static uint32_t name_at(kof_buf f, uint64_t off, char *out, uint32_t cap)
{
	uint32_t i = 0;

	if (!off || off >= f.n)
		return 0;
	while (i + 1u < cap && off + i < f.n) {
		uint8_t c = f.p[off + i];

		if (!c)
			break;
		out[i++] = (c >= 0x20u && c < 0x7fu) ? (char)c : '?';
	}
	out[i] = 0;
	return i;
}

/* One record, with the fields every caller of this file sets the same way. */
static void rec_put(uint8_t *rec, uint8_t flags, uint64_t value,
		    const char *name)
{
	uint32_t i;

	memset(rec, 0, KOF_SYM_RECLEN);
	rec[KOF_SYM_R_TYPE]  = 2u;              /* STT_FUNC - see the header */
	rec[KOF_SYM_R_BIND]  = 1u;              /* STB_GLOBAL */
	rec[KOF_SYM_R_VIS]   = 0u;              /* STV_DEFAULT */
	rec[KOF_SYM_R_FLAGS] = flags;
	/* 0xffff, "not a real section index", which is what a PE import or
	 * export is: the directories name a module and an RVA, not a section.
	 * Spelled the same way elf_sym.c spells an ELF reserved index so a rule
	 * comparing the field has one value to compare against. */
	put16(rec + KOF_SYM_R_SHNDX, 0xffffu);
	put64(rec + KOF_SYM_R_VALUE, value);
	for (i = 0; i + 1u < KOF_SYM_NAMELEN && name[i]; i++)
		rec[KOF_SYM_R_NAME + i] = (uint8_t)name[i];
}

/* The imports, appended from `n` onward. Returns the new count. */
static uint32_t do_imports(kof_buf f, const struct kof_pe_info *p,
			   uint8_t *out, uint32_t want, uint32_t n)
{
	uint64_t desc = kof_pe_rva_to_off(p, p->dir[KOF_PE_DIR_IMPORT].rva);
	uint32_t d;

	if (!p->dir[KOF_PE_DIR_IMPORT].rva || !desc)
		return n;
	for (d = 0; d < MAX_DLLS && n < want; d++) {
		uint64_t at = desc + (uint64_t)d * IMP_LEN, tbl;
		uint32_t orig = 0, first = 0, nm = 0, t;
		char dll[64], sym[KOF_SYM_NAMELEN];

		if (at + IMP_LEN > f.n)
			break;
		if (!kof_rd_u32(f, at + IMP_ORIG_THUNK, 0, &orig) ||
		    !kof_rd_u32(f, at + IMP_NAME, 0, &nm) ||
		    !kof_rd_u32(f, at + IMP_FIRST_THUNK, 0, &first))
			break;
		/* An all-zero descriptor ends the table. Checked on the fields
		 * that matter rather than on the whole struct, because a
		 * descriptor with only a timestamp left over is still the end. */
		if (!orig && !first && !nm)
			break;
		if (!name_at(f, kof_pe_rva_to_off(p, nm), dll, sizeof dll))
			snprintf(dll, sizeof dll, "?");

		/*
		 * The NAME table if there is one, else the IAT.
		 *
		 * OriginalFirstThunk is the one that still holds names after
		 * the loader has written addresses over FirstThunk. A file on
		 * disk has both intact, but a MEMORY IMAGE dumped to disk - and
		 * this engine is handed those - has only the names in the
		 * original, so preferring it is what makes a dump readable.
		 */
		tbl = kof_pe_rva_to_off(p, orig ? orig : first);
		if (!tbl)
			continue;
		for (t = 0; t < MAX_THUNKS && n < want; t++) {
			uint64_t te = tbl + (uint64_t)t *
					    (p->pe32_plus ? 8u : 4u);
			uint64_t val = 0;
			uint32_t lo = 0;

			if (p->pe32_plus) {
				if (!kof_rd_u64(f, te, 0, &val))
					break;
			} else {
				if (!kof_rd_u32(f, te, 0, &lo))
					break;
				val = lo;
			}
			if (!val)
				break;                  /* end of this DLL */
			/*
			 * The top bit means "by ordinal", and the ordinal is
			 * the low sixteen. Tested on the right bit for the
			 * width: 0x80000000 for PE32 and 0x8000000000000000
			 * for PE32+, which is why the two are not one test.
			 */
			if (val & (p->pe32_plus ? 0x8000000000000000ull
						: 0x80000000ull)) {
				snprintf(sym, sizeof sym, "%.*s!#%u",
					 DLL_ROOM, dll,
					 (unsigned)(val & 0xffffu));
			} else {
				char fn[KOF_SYM_NAMELEN];
				uint64_t ho = kof_pe_rva_to_off(p, val);

				/* An IMAGE_IMPORT_BY_NAME is a hint word then
				 * the string, so the name is two bytes in. */
				if (!ho || !name_at(f, ho + 2u, fn, sizeof fn))
					continue;
				/* Both halves bounded explicitly rather than
				 * left to snprintf: the truncation is
				 * INTENDED, and saying so in the format is
				 * what tells a reader - and the compiler -
				 * that it was chosen and not overlooked. */
				snprintf(sym, sizeof sym, "%.*s!%.*s",
					 DLL_ROOM, dll,
					 (int)(sizeof sym - DLL_ROOM - 2u),
					 fn);
			}
			rec_put(out + KOF_SYM_HDRLEN +
				(uint64_t)n * KOF_SYM_RECLEN,
				KOF_SYM_F_UNDEFINED, 0, sym);
			n++;
		}
	}
	return n;
}

/* The exports, appended from `n` onward. Returns the new count. */
static uint32_t do_exports(kof_buf f, const struct kof_pe_info *p,
			   uint8_t *out, uint32_t want, uint32_t n)
{
	uint64_t d = kof_pe_rva_to_off(p, p->dir[KOF_PE_DIR_EXPORT].rva);
	uint32_t n_names = 0, a_names = 0, a_ords = 0, a_funcs = 0, i;

	if (!p->dir[KOF_PE_DIR_EXPORT].rva || !d)
		return n;
	if (!kof_rd_u32(f, d + EXP_N_NAMES, 0, &n_names) ||
	    !kof_rd_u32(f, d + EXP_NAMES,   0, &a_names) ||
	    !kof_rd_u32(f, d + EXP_ORDS,    0, &a_ords)  ||
	    !kof_rd_u32(f, d + EXP_FUNCS,   0, &a_funcs))
		return n;
	if (n_names > MAX_THUNKS)
		n_names = MAX_THUNKS;

	/*
	 * The NAMED exports only.
	 *
	 * A PE can export by ordinal with no name, and those are reachable
	 * through AddressOfFunctions alone. They are left out because the
	 * record's identity here is its name: an entry with none would be
	 * "?" repeated, which is a row that says nothing and a pattern that
	 * matches every other one like it. The count in the header still says
	 * how many records there are, so nothing pretends the block is the
	 * whole directory.
	 */
	for (i = 0; i < n_names && n < want; i++) {
		uint64_t no = kof_pe_rva_to_off(p, a_names) + (uint64_t)i * 4u;
		uint32_t nrva = 0, frva = 0;
		uint16_t ord = 0;
		char fn[KOF_SYM_NAMELEN];

		if (!a_names || !kof_rd_u32(f, no, 0, &nrva))
			break;
		if (!name_at(f, kof_pe_rva_to_off(p, nrva), fn, sizeof fn))
			continue;
		/* The RVA comes through the ordinal table, which is what maps a
		 * name to its slot in AddressOfFunctions. Skipped rather than
		 * guessed when either table is missing: a value of zero would
		 * read as "at the image base". */
		if (a_ords && a_funcs &&
		    kof_rd_u16(f, kof_pe_rva_to_off(p, a_ords) +
				  (uint64_t)i * 2u, 0, &ord))
			(void)kof_rd_u32(f, kof_pe_rva_to_off(p, a_funcs) +
					    (uint64_t)ord * 4u, 0, &frva);
		rec_put(out + KOF_SYM_HDRLEN + (uint64_t)n * KOF_SYM_RECLEN,
			(uint8_t)(KOF_SYM_F_DEFINED |
				  (frva ? KOF_SYM_F_IN_EXEC : 0u)),
			frva, fn);
		n++;
	}
	return n;
}

uint32_t kof_pe_syms(kof_buf file, const struct kof_pe_info *p,
		     uint8_t *out, uint32_t cap)
{
	uint32_t want, n = 0;

	if (!out || cap < KOF_SYM_HDRLEN)
		return 0;
	memset(out, 0, KOF_SYM_HDRLEN);
	out[KOF_SYM_H_MAGIC + 0] = KOF_SYM_MAGIC0;
	out[KOF_SYM_H_MAGIC + 1] = KOF_SYM_MAGIC1;
	out[KOF_SYM_H_MAGIC + 2] = KOF_SYM_MAGIC2;
	out[KOF_SYM_H_MAGIC + 3] = KOF_SYM_MAGIC3;
	put16(out + KOF_SYM_H_VERSION, KOF_SYM_VERSION);
	put16(out + KOF_SYM_H_RECLEN,  KOF_SYM_RECLEN);
	/*
	 * No `_start` to record, so the field says "absent" - and it has to be
	 * written rather than left as the memset's zero, because zero is a
	 * valid index and a reader would take it as "begin at record 1". Same
	 * reasoning as elf_sym.c; see KOF_SYM_H_START.
	 */
	put16(out + KOF_SYM_H_START, KOF_SYM_NO_START);
	out[KOF_SYM_H_ORIGIN] = KOF_SYM_ORIGIN_NONE;

	if (!file.p || !p || !p->valid)
		return KOF_SYM_HDRLEN;

	want = (cap - KOF_SYM_HDRLEN) / KOF_SYM_RECLEN;
	if (want > KOF_SYM_MAX_RECS)
		want = KOF_SYM_MAX_RECS;

	/*
	 * IMPORTS FIRST, and the order is part of the contract.
	 *
	 * kofviewer splits the block into SYM_IMP and SYM_EXP by walking it and
	 * sorting on the UNDEFINED flag, so the order here does not decide what
	 * lands where. It decides what a reader sees in kofexamine, which
	 * prints the block in order - and a PE is read imports-first because
	 * that is the half that says what the file DOES.
	 */
	n = do_imports(file, p, out, want, n);
	n = do_exports(file, p, out, want, n);

	put32(out + KOF_SYM_H_COUNT, n);
	/*
	 * The origin, said rather than left as NONE.
	 *
	 * "none" over a block with four records in it reads as a contradiction,
	 * and the honest answer exists: the records came from the import and
	 * export directories. Only when there ARE records - a PE with neither
	 * directory genuinely has no origin.
	 */
	if (n)
		out[KOF_SYM_H_ORIGIN] = KOF_SYM_ORIGIN_PE_DIR;
	/*
	 * TRUNCATED when the block filled exactly, which is the only thing this
	 * can honestly say.
	 *
	 * Both walks stop at `want`, and neither looks ahead, so "n == want"
	 * means the cap is what ended them and there MAY be more. Conservative
	 * on purpose: a reader told the block might be short can go and check,
	 * while one told it is complete when it is not has no reason to.
	 *
	 * The first version of this compared `want` against the expression
	 * `want` was computed from, which is only ever true when the record cap
	 * clamped it - so a file with more imports than the block holds was
	 * reported as complete.
	 */
	if (n && n == want)
		out[KOF_SYM_H_TRUNC] = 1;
	return KOF_SYM_HDRLEN + n * KOF_SYM_RECLEN;
}
