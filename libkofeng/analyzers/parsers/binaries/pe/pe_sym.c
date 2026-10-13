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
 * THE MODULE IS CAPPED AT DLL_ROOM, THE FUNCTION IS NOT. The name is no longer
 * bound by a 40 byte field (it is whatever length the pool needs, up to
 * KOF_SYM_NAME_MAX), so the function is kept whole - it is what identifies an
 * import. The module is what disambiguates it, and DLL_ROOM is 16, which holds
 * every ordinary Windows module name whole - kernel32.dll is 12, advapi32.dll is
 * 12 - and cuts only the long api-ms-win-* forms. That cut is a SPELLING and not
 * a limit (rules written against the block already say "api-ms-win-core-"), so it
 * is kept, and it is the one cut here that does not set NAMECUT.
 */
#define DLL_ROOM 16

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kofcore.h>
#include <kofmod/kofsym.h>
#include <kofmod/pe.h>
#include "pe_sym.h"
#include "pe_parse.h"
#include "../funcs.h"
#include "../sym_pool.h"

/* The import descriptor is walked by kgenome_pe_imports in pe_parse.c, which is
 * the only place that knows its field offsets - see the note there. What is
 * left here is how an import is SPELLED in a KSYM record. */

#define EXP_N_FUNCS      20u   /* 4  NumberOfFunctions                     */
#define EXP_N_NAMES      24u   /* 4  NumberOfNames                         */
#define EXP_FUNCS        28u   /* 4  AddressOfFunctions                    */
#define EXP_NAMES        32u   /* 4  AddressOfNames                        */
#define EXP_ORDS         36u   /* 4  AddressOfNameOrdinals                 */

/*
 * How many exported names one file may contribute.
 *
 * Bounded because NumberOfNames is a field the file writes, and a hostile one
 * can claim as many as it likes. Nothing here trusts a count it was given.
 * The import side has its own bounds, in pe_parse.c, for the same reason.
 */
#define MAX_THUNKS 4096u

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

/* One symbol, with the fields every caller of this file sets the same way: an
 * import or an export is a global function (see the header), named `name`. */
static int sym_put(struct kof_symw *w, uint8_t flags, uint64_t value,
		   const char *name, uint32_t name_len, int cut)
{
	struct kof_symrec r;

	r.type  = 2u;                   /* STT_FUNC - see the header */
	r.bind  = 1u;                   /* STB_GLOBAL */
	r.vis   = 0u;                   /* STV_DEFAULT */
	r.flags = flags;
	/* 0xffff, "not a real section index", which is what a PE import or
	 * export is: the directories name a module and an RVA, not a section.
	 * Spelled the same way elf_sym.c spells an ELF reserved index so a rule
	 * comparing the field has one value to compare against. */
	r.shndx = 0xffffu;
	r.size  = 0;
	r.value = value;
	r.name = name;
	r.name_len = name_len;
	r.cut = (uint8_t)cut;
	return kof_symw_put(w, &r);
}

/* "dll!func", or "dll!#ordinal" when imported without a name - one spelling for
 * the import table and for a name a module reports. `func` is NUL-terminated and
 * already printable. Returns the length. */
static uint32_t spell_import(char *out, const char *dll, const char *func)
{
	const uint32_t cap = DLL_ROOM + 1u + KOF_SYM_NAME_MAX + 2u;
	int k = snprintf(out, cap, "%.*s!%s", DLL_ROOM, dll, func);

	/* snprintf answers the length it WOULD have written: what was written
	 * ends at the buffer. */
	return k < 0 ? 0 : ((uint32_t)k < cap ? (uint32_t)k : cap - 1u);
}

/*
 * THE IMPORTS, spelled as records.
 *
 * The directory is walked once, into a kgenome_pe_imptab, and this is only what a
 * KSYM record makes of each entry: "dll!func", or "dll!#ordinal" for the ones
 * imported without a name, with the printable-only policy applied for the
 * reason elf_sym.c gives.
 *
 * NO VALUE IS RECORDED. The table knows the slot the import goes through,
 * and a record keeps zero because that is what this block has always said
 * and a rule written against it compares names. The slot is available to
 * anyone who reads the table, which is what the PE diagnose does.
 */
static void do_imports(struct kof_symw *w, kof_buf f, const struct kgenome_pe_imptab *t)
{
	char nm[KOF_SYM_NAME_MAX + 2u], clean[KOF_SYM_NAME_MAX + 2u];
	char sym[DLL_ROOM + 1u + KOF_SYM_NAME_MAX + 2u];
	uint32_t k;

	for (k = 0; k < t->n; k++) {
		const struct kgenome_pe_imp *e = &t->v[k];
		const char *dll = t->dll[e->dll];
		uint32_t i, len;

		if (kgenome_pe_imp_name(f, e, nm, sizeof nm)) {
			for (i = 0; nm[i]; i++)
				clean[i] = (nm[i] >= 0x20 && nm[i] < 0x7f)
					 ? nm[i] : '?';
			clean[i] = 0;
			len = spell_import(sym, dll, clean);
		} else {
			snprintf(clean, sizeof clean, "#%u", (unsigned)e->ordinal);
			len = spell_import(sym, dll, clean);
		}
		/* A name past KOF_SYM_NAME_MAX is cut by the writer, which says so
		 * on the record. */
		if (!sym_put(w, KOF_SYM_F_UNDEFINED, 0, sym, len, 0))
			break;
	}
}

/* The exports, appended after the imports. */
static void do_exports(struct kof_symw *w, kof_buf f, const struct kgenome_pe_info *p)
{
	uint64_t d = kgenome_pe_rva_to_off(p, p->dir[KGENOME_PE_DIR_EXPORT].rva);
	uint32_t n_names = 0, a_names = 0, a_ords = 0, a_funcs = 0, i;
	char fn[KOF_SYM_NAME_MAX + 1u];

	if (!p->dir[KGENOME_PE_DIR_EXPORT].rva || !d)
		return;
	if (!kof_rd_u32(f, d + EXP_N_NAMES, 0, &n_names) ||
	    !kof_rd_u32(f, d + EXP_NAMES,   0, &a_names) ||
	    !kof_rd_u32(f, d + EXP_ORDS,    0, &a_ords)  ||
	    !kof_rd_u32(f, d + EXP_FUNCS,   0, &a_funcs))
		return;
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
	for (i = 0; i < n_names; i++) {
		uint64_t no = kgenome_pe_rva_to_off(p, a_names) + (uint64_t)i * 4u;
		uint32_t nrva = 0, frva = 0, len;
		uint16_t ord = 0;
		int cut;

		if (!a_names || !kof_rd_u32(f, no, 0, &nrva))
			break;
		len = name_at(f, kgenome_pe_rva_to_off(p, nrva), fn, sizeof fn);
		if (!len)
			continue;
		/* The RVA comes through the ordinal table, which is what maps a
		 * name to its slot in AddressOfFunctions. Skipped rather than
		 * guessed when either table is missing: a value of zero would
		 * read as "at the image base". */
		if (a_ords && a_funcs &&
		    kof_rd_u16(f, kgenome_pe_rva_to_off(p, a_ords) +
				  (uint64_t)i * 2u, 0, &ord))
			(void)kof_rd_u32(f, kgenome_pe_rva_to_off(p, a_funcs) +
					    (uint64_t)ord * 4u, 0, &frva);
		/* name_at stops at the buffer's size: the name goes on when the
		 * byte after what it copied is not the terminator. */
		{
			uint64_t no2 = kgenome_pe_rva_to_off(p, nrva);

			cut = len == KOF_SYM_NAME_MAX && no2 + len < f.n &&
			      f.p[no2 + len] != 0;
		}
		if (!sym_put(w, (uint8_t)(KOF_SYM_F_DEFINED |
					  (frva ? KOF_SYM_F_IN_EXEC : 0u)),
			     frva, fn, len, cut))
			break;
	}
}

uint32_t kof_pe_syms(kof_buf file, const struct kgenome_pe_info *p,
		     uint8_t *out, uint32_t cap)
{
	return kof_pe_syms_with(file, p, NULL, out, cap);
}

uint32_t kof_pe_syms_with(kof_buf file, const struct kgenome_pe_info *p,
			  const struct kgenome_pe_imptab *tab,
			  uint8_t *out, uint32_t cap)
{
	struct kgenome_pe_imptab own;
	struct kof_symw w;
	uint32_t bytes;

	if (!out || cap < KOF_SYM_HDRLEN)
		return 0;
	/* Unknown count: a PE's imports are walked, not counted. */
	kof_symw_begin(&w, out, cap, 0, 0);
	/*
	 * No `_start` to record, so the field says "absent" - kof_symw_begin wrote
	 * that, because zero is a valid index and a reader would take it as
	 * "begin at record 1". Same reasoning as elf_sym.c; see KOF_SYM_H_START.
	 */
	out[KOF_SYM_H_ORIGIN] = KOF_SYM_ORIGIN_NONE;

	if (!file.p || !p || !p->valid)
		return kof_symw_end(&w);

	/*
	 * IMPORTS FIRST, and the order is part of the contract.
	 *
	 * kofviewer splits the block into SYM_IMP and SYM_EXP by walking it and
	 * sorting on the UNDEFINED flag, so the order here does not decide what
	 * lands where. It decides what a reader sees in kofexaminer, which
	 * prints the block in order - and a PE is read imports-first because
	 * that is the half that says what the file DOES.
	 */
	if (!tab) {
		kgenome_pe_imptab_build(file, p, &own);
		tab = &own;
	}
	do_imports(&w, file, tab);
	if (tab == &own)
		kgenome_pe_imptab_free(&own);
	do_exports(&w, file, p);

	bytes = kof_symw_end(&w);
	/*
	 * The origin, said rather than left as NONE.
	 *
	 * "none" over a block with four records in it reads as a contradiction,
	 * and the honest answer exists: the records came from the import and
	 * export directories. Only when there ARE records - a PE with neither
	 * directory genuinely has no origin.
	 */
	if (w.n)
		out[KOF_SYM_H_ORIGIN] = KOF_SYM_ORIGIN_PE_DIR;
	/*
	 * TRUNCATED is the writer's: a symbol it was offered and could not hold -
	 * the table or the pool was full. It was "the block filled exactly",
	 * which could not tell a full block from a cut one; now it is the cut.
	 */
	return bytes;
}

/*
 * IMPORTS THE PROGRAM FOUND FOR ITSELF, put where imports go.
 *
 * The block is imports first and exports after, and that order is the
 * contract (see kof_pe_syms), so a record is INSERTED after the last import
 * and the exports move up - appending would leave a resolved import below the
 * exports, in the half a reader takes for "what the file offers".
 *
 * A NAME THE DIRECTORY ALREADY LISTS IS NOT ADDED AGAIN: a program that
 * imports VirtualAlloc and also resolves it has said one thing twice, and the
 * block is a set of what the file uses. Compared without regard to case,
 * because the directory spells the module the way the linker did and the
 * resolver spells it the way the loader model does.
 *
 * `cap` bounds the block exactly as it does in kof_pe_syms, and a record that
 * does not fit is dropped with the header's truncated byte set - never
 * silently.
 */
static int same_name(const char *a, const char *b)
{
	for (; *a && *b; a++, b++) {
		char x = *a, y = *b;

		if (x >= 'A' && x <= 'Z')
			x = (char)(x - 'A' + 'a');
		if (y >= 'A' && y <= 'Z')
			y = (char)(y - 'A' + 'a');
		if (x != y)
			return 0;
	}
	return *a == *b;
}

/* The bytes an insert of `n` imports can add to a block: what the engine makes room
 * for before calling kof_pe_syms_add_imports. An upper bound. */
uint32_t kof_pe_syms_add_room(const char *const *dll, const char *const *name,
			      uint32_t n)
{
	uint64_t t = 0;
	uint32_t i;

	for (i = 0; i < n; i++) {
		size_t d = strlen(dll[i]), f = strlen(name[i]);

		if (d > DLL_ROOM)
			d = DLL_ROOM;
		if (f > KOF_SYM_NAME_MAX)
			f = KOF_SYM_NAME_MAX;
		t += KOF_SYM_RECLEN + KOF_SYM_KEYLEN + d + 1u + f + 1u;
	}
	return t > 0xffffffffu ? 0xffffffffu : (uint32_t)t;
}

uint32_t kof_pe_syms_add_imports(uint8_t *blk, uint32_t n_bytes, uint32_t cap,
				 const char *const *dll, const char *const *name,
				 uint32_t n)
{
	char sym[DLL_ROOM + 1u + KOF_SYM_NAME_MAX + 2u];
	struct kof_symw w;
	uint8_t *old;
	uint32_t count, at, i, added = 0, room, old_trunc, origin, k;
	uint32_t pool_in;

	if (!blk || n_bytes < KOF_SYM_HDRLEN || n_bytes > cap)
		return n_bytes;
	count = kof_sym_count(blk, n_bytes);
	if (kof_sym_pool_at(blk, n_bytes) > n_bytes)
		return n_bytes;
	pool_in = n_bytes - (uint32_t)kof_sym_pool_at(blk, n_bytes);
	/* Everything that could be added, so the table and the pool are reserved
	 * once and the records already there are never at risk. */
	room = kof_pe_syms_add_room(dll, name, n);
	if ((uint64_t)n_bytes + room > cap) {
		blk[KOF_SYM_H_TRUNC] = 1;
		return n_bytes;
	}
	old = malloc(n_bytes);
	if (!old) {
		blk[KOF_SYM_H_TRUNC] = 1;
		return n_bytes;
	}
	memcpy(old, blk, n_bytes);
	old_trunc = old[KOF_SYM_H_TRUNC];
	origin = old[KOF_SYM_H_ORIGIN];

	/* The first record that is not an import: where the new ones go. */
	for (at = 0; at < count; at++) {
		const uint8_t *r = kof_sym_rec(old, n_bytes, at);

		if (!r || !(r[KOF_SYM_R_FLAGS] & KOF_SYM_F_UNDEFINED))
			break;
	}
	kof_symw_begin(&w, blk, cap, count + n, pool_in + room);
	/* The block is REBUILT, in order, with the new records between the imports
	 * and the exports: the pool is in record order (see kof_sym_index_at), so an
	 * insert is a copy and not a memmove of the pool. */
	for (k = 0; k < at; k++)
		(void)kof_symw_put_from(&w, old, n_bytes, kof_sym_rec(old, n_bytes, k));
	for (i = 0; i < n; i++) {
		uint32_t len = spell_import(sym, dll[i], name[i]), nl;
		const uint8_t *r;

		for (k = 0; (r = kof_sym_rec(old, n_bytes, k)) != NULL; k++)
			if (same_name(sym, kof_sym_name(old, n_bytes, r, &nl)))
				break;
		if (r)
			continue;
		/* Or one this call has already offered. */
		for (k = 0; k < i; k++) {
			char prev[DLL_ROOM + 1u + KOF_SYM_NAME_MAX + 2u];

			(void)spell_import(prev, dll[k], name[k]);
			if (same_name(prev, sym))
				break;
		}
		if (k < i)
			continue;
		if (!sym_put(&w, KOF_SYM_F_UNDEFINED, 0, sym, len, 0))
			break;
		added++;
	}
	for (k = at; k < count; k++)
		(void)kof_symw_put_from(&w, old, n_bytes, kof_sym_rec(old, n_bytes, k));
	n_bytes = kof_symw_end(&w);
	blk[KOF_SYM_H_ORIGIN] = (uint8_t)(added ? KOF_SYM_ORIGIN_PE_RESOLVED : origin);
	if (old_trunc)
		blk[KOF_SYM_H_TRUNC] = 1;
	free(old);
	return n_bytes;
}
