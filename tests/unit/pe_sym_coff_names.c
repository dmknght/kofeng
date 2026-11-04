/*
 * pe_sym_coff_names.c - closes PE-SYM-NAME-GAP at the engine layer (pe_sym.c,
 * kof_pe_syms_with): an unstripped mingw/cygwin PE's own COFF local function symbols
 * now get a real name in the KSYM block kof_sym_name_at/kof_func_name search.
 *
 * RED, confirmed by running this file against base/ (the coordinator's pre-patch tree,
 * merge 136): fntab_pe_coff.c already set a COFF-sourced kgenome_func's value/shndx
 * correctly (merge 133), but kof_pe_syms_with built the KSYM block from the import and
 * export directories only, so kof_sym_name_at found no matching record and
 * kof_func_name fell back to fcn_<off> for both t_names_resolve's functions - cut == 0
 * for cut comparisons is unaffected, this is a return-value/fallback difference.
 * GREEN here: kof_pe_syms_with also walks the file's own COFF table
 * (kgenome_pe_coff_syms, pe_coff_sym.c) and both functions resolve to their real name.
 *
 * Also pinned: an inline (<=8 byte) name AND a string-table (>8 byte) name both
 * resolve; import/export names already in the block (hk_pe's ExitProcess,
 * MessageBoxA) are byte-identical to before - no regression; the origin byte reads
 * KOF_SYM_ORIGIN_PE_COFF once a COFF record lands in the block, not the old
 * "imports+exports" label, which would be false of it; a file with no COFF table
 * still reports KOF_SYM_ORIGIN_PE_DIR exactly as before (hk_pe() unmodified, in
 * t_no_coff_table_unaffected).
 */
#include "../lib/genome/hk.h"
#include <genotype/image/pe_image.h>
#include <genotype/image/fntab.h>
#include "../../libkofeng/analyzers/parsers/binaries/pe/pe_sym.h"
#include "../../libkofeng/analyzers/parsers/binaries/funcs.h"
#include "../../libkofeng/kofcore/kofmod/kofsym.h"

static struct hk_pe P;

/*
 * Appends a COFF symbol table with REAL names after hk_pe()'s declared end (P.n ==
 * 0x800, HK_PE_MAX == 0x1000: plenty of room past it). `name[i]` inline when it is 8
 * bytes or fewer, otherwise through the string table right after the records. All at
 * section 1 (.text), Type 0x20 (function). `cls[i]` is the StorageClass (2 EXTERNAL,
 * 3 STATIC). Updates `p->n` to include what was appended; returns PointerToSymbolTable.
 */
static uint32_t append_coff_syms(struct hk_pe *p, const char *const *name,
				 const uint32_t *value, const uint8_t *cls, unsigned n)
{
	uint32_t coff_off = p->n, total_str = 4u, stroff = 4u, i;
	uint8_t *t = p->b + coff_off;
	uint8_t *str = t + (uint32_t)n * 18u;

	for (i = 0; i < n; i++)
		if (strlen(name[i]) > 8u)
			total_str += (uint32_t)strlen(name[i]) + 1u;
	memset(t, 0, (uint32_t)n * 18u + total_str);
	for (i = 0; i < n; i++) {
		uint8_t *r = t + i * 18u;
		size_t l = strlen(name[i]);

		if (l <= 8u) {
			memcpy(r, name[i], l);
		} else {
			hk_w(r + 4, stroff, 4, 0);
			memcpy(str + stroff, name[i], l + 1u);
			stroff += (uint32_t)l + 1u;
		}
		hk_w(r + 8, value[i], 4, 0);
		hk_w(r + 12, 1, 2, 0);          /* section 1: .text */
		hk_w(r + 14, 0x20, 2, 0);       /* Type: DTYPE_FUNCTION */
		r[16] = cls[i];
	}
	hk_w(str, total_str, 4, 0);
	hk_w(p->b + p->lfanew + 12, coff_off, 4, 0);
	hk_w(p->b + p->lfanew + 16, n, 4, 0);
	p->n = coff_off + (uint32_t)n * 18u + total_str;
	return coff_off;
}

static const uint8_t *find_rec(const uint8_t *b, uint32_t n, const char *needle)
{
	uint32_t i;
	const uint8_t *r;

	for (i = 0; (r = kof_sym_rec(b, n, i)) != NULL; i++) {
		uint32_t l;
		const char *nm = kof_sym_name(b, n, r, &l);

		if (l == strlen(needle) && !memcmp(nm, needle, l))
			return r;
	}
	return NULL;
}

/* The full chain: fntab_pe_coff.c's boundary (merge 133) and pe_sym.c's name
 * (this patch), through kof_func_name exactly as a consumer (kofexamine, the
 * CFG dialog, scan_explain.c) calls it. */
static void t_names_resolve(void)
{
	static const char *nm[2] = { "calc", "a_mingw_generated_helper_name" };
	static const uint32_t val[2] = { 0x10, 0x180 };
	static const uint8_t cls[2] = { 2, 2 };
	struct kgenome_pe_info pi;
	struct kgenome_obj o;
	struct kgenome_fntab_list l;
	static uint8_t blk[1u << 16];
	uint32_t n;
	char out[64];

	hk_args(0, NULL);
	hk_pe(&P, 1);
	append_coff_syms(&P, nm, val, cls, 2);

	memset(&pi, 0, sizeof pi);
	CK(kgenome_pe_image_parse(kof_buf_make(P.b, P.n), &pi, &o));

	memset(&l, 0, sizeof l);
	kgenome_fntab_pe_coff(kof_buf_make(P.b, P.n), &pi, &l);
	CK(l.n == 2u);
	if (l.n != 2u) {
		kgenome_fntab_list_free(&l);
		return;
	}
	CK(l.v[0].value == 0x10u && l.v[0].shndx == 1u);
	CK(l.v[1].value == 0x180u && l.v[1].shndx == 1u);

	n = kof_pe_syms_with(kof_buf_make(P.b, P.n), &pi, NULL, blk, sizeof blk);
	CK(n >= KOF_SYM_HDRLEN);

	/* GREEN here; on base/ (pre-patch) both calls return 0 and `out` reads
	 * "fcn_00000010" / "fcn_00000180" - the exact symptom PE-SYM-NAME-GAP names. */
	CK(kof_func_name(&l.v[0], blk, n, out, sizeof out) == 1);
	CK(!strcmp(out, "calc"));
	CK(kof_func_name(&l.v[1], blk, n, out, sizeof out) == 1);
	CK(!strcmp(out, "a_mingw_generated_helper_name"));

	/* The origin now says so, honestly - not the old "directories" label, which
	 * would be false of a block that is mostly the file's own function names. */
	CK(kof_sym_origin(blk, n) == KOF_SYM_ORIGIN_PE_COFF);

	kgenome_fntab_list_free(&l);
}

/* A STATIC (file-local) COFF function resolves the same way as an EXTERNAL one -
 * kof_sym_name_at keys on (value, shndx), not bind (see sym_put's own comment). */
static void t_static_storage_class_resolves_too(void)
{
	static const char *nm[1] = { "local_calc" };
	static const uint32_t val[1] = { 0x20 };
	static const uint8_t cls[1] = { 3 };      /* STATIC */
	struct kgenome_pe_info pi;
	struct kgenome_obj o;
	struct kgenome_fntab_list l;
	static uint8_t blk[1u << 16];
	uint32_t n;
	char out[64];

	hk_pe(&P, 0);
	append_coff_syms(&P, nm, val, cls, 1);

	memset(&pi, 0, sizeof pi);
	CK(kgenome_pe_image_parse(kof_buf_make(P.b, P.n), &pi, &o));
	memset(&l, 0, sizeof l);
	kgenome_fntab_pe_coff(kof_buf_make(P.b, P.n), &pi, &l);
	CK(l.n == 1u);
	if (l.n != 1u) {
		kgenome_fntab_list_free(&l);
		return;
	}
	n = kof_pe_syms_with(kof_buf_make(P.b, P.n), &pi, NULL, blk, sizeof blk);
	CK(kof_func_name(&l.v[0], blk, n, out, sizeof out) == 1);
	CK(!strcmp(out, "local_calc"));
	kgenome_fntab_list_free(&l);
}

/* NO REGRESSION: the import and export names hk_pe() always carries are unchanged,
 * byte for byte, and the block is still imports-first - adding the COFF pass did not
 * disturb the existing contract (silent_cuts_names.c pins the NAMECUT half of this
 * same contract; this pins the plain names). */
static void t_imports_exports_unaffected(void)
{
	static uint8_t blk[1u << 16];
	struct kgenome_pe_info pi;
	struct kgenome_obj o;
	uint32_t n, cut = 9;
	const uint8_t *r;

	hk_pe(&P, 1);
	memset(&pi, 0, sizeof pi);
	CK(kgenome_pe_image_parse(kof_buf_make(P.b, P.n), &pi, &o));
	n = kof_pe_syms(kof_buf_make(P.b, P.n), &pi, blk, sizeof blk);

	r = find_rec(blk, n, "kernel32.dll!ExitProcess");
	CK(r != NULL && (r[KOF_SYM_R_FLAGS] & KOF_SYM_F_UNDEFINED) != 0 && kof_sym_name_cut(r) == 0);
	r = find_rec(blk, n, "user32.dll!MessageBoxA");
	CK(r != NULL && (r[KOF_SYM_R_FLAGS] & KOF_SYM_F_UNDEFINED) != 0);
	r = find_rec(blk, n, "Alpha");
	CK(r != NULL && (r[KOF_SYM_R_FLAGS] & KOF_SYM_F_DEFINED) != 0);
	(void)cut;

	/* No COFF table (hk_pe() alone never writes one): the origin is unchanged by
	 * this patch, still "imports+exports" and not the new value. */
	CK(kof_sym_origin(blk, n) == KOF_SYM_ORIGIN_PE_DIR);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	t_names_resolve();
	t_static_storage_class_resolves_too();
	t_imports_exports_unaffected();
	printf("pe_sym_coff_names: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
