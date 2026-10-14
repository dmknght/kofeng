/*
 * api_engine_macros.c - macros of the public headers that have a value or an expansion a caller depends on,
 * checked against what the engine does with them.
 *
 *   LIMITS      the sizes of the result's tables (KOF_MAX_FIX, KOF_MAX_INFECTED, KOF_MAX_REGIONS,
 *               KOF_DIAG_REPORT_NODES), what a top level object's entry is (KOF_ENTRY_NONE) and a child's is not,
 *               the room a symbol block is planned with (KOF_SYM_BYTES_FOR)
 *   X-LISTS     the lists an enum and a name table are both generated from (KOF_ENGINE_LIST, KOF_VERDICT_LIST,
 *               KOF_PDF_CLASSES, KOF_SCAN_PROC_LIST, AMSI_REGIONS, KOF_AMSI_KIND_LIST, KOF_SCRIPT_TYPE_LIST; the KOF_AMSI_KIND_X and KOF_SCRIPT_TYPE_X builders are #undef'd by their headers after the enum): one row
 *               per enumerator, the names the functions answer are the list's, the bits of a region list are
 *               distinct and are the region mask the header names as claimed
 *   TOKENS      KOF_PASTE / KOF_PASTE2 (expand then paste, and not), KOF_NARG (1..16 arguments)
 *   SEARCH      KOF_FS_ONE / PICK / FOLD and KOF_DFS_FOLD / kof_diag_str_all, against a find_str that records:
 *               one call per string, `&&` stops at the first miss and `||` at the first hit, the ids are the
 *               module's own names pasted
 *   CODING      KOF_ENG_CLASS_PUT / OF round trip, KOF_UNP_ASPACK_MARK, KOF_UNP_LZMA_MPRESS_PROPS give a
 *               distinct method for every lc/lp/pb the LZMA header can carry
 *   WRITE       KOF_WRITE_CHUNK is a size one write(2) takes and the chunks of a write add up (a write that
 *               crosses a chunk would need 256 MB of buffer: the value is checked, the loop is not run)
 *
 * What is NOT here, and why: KOF_MEMMEM_FAIL_MAX / KOF_MEMMEM_GIVE_UP exist only in the Windows branch of
 * kofplatform_os.h (the POSIX build calls the C library's memmem); KOF_DSRC_NAME_LEN / KOF_DSRC_STR_LEN,
 * KOF_MULTIMATCH_* and KOF_ENT_MEMO are limits inside the loader / the pattern tables whose only observable is
 * a refusal at exactly that size (tests/unit/diagsrc.c and api_engine_detect.c pin the behaviour by value).
 */

#include "hostile_engine.h"

#include "kofplatform.h"
#include <kofmod/kofsig.h>
#include <kofmod/kofsym.h>
#include <kofmod/pdf.h>
#include <kofmod/proc.h>
#include <kofmod/amsi.h>
#include <kofmod/script.h>
#include <kofmod/heur.h>
#include <kofmod/kofverdict.h>
#include <kofmod/kofdiagnose.h>

/* ---- limits ------------------------------------------------------------------------------------------------------ */

#define ELEMS(a) (sizeof(a) / sizeof((a)[0]))

static void limits(void)
{
	struct kof_result res;
	struct kof_diag_report rep;

	CK(ELEMS(res.repair.fix) == KOF_MAX_FIX, "the fix table holds KOF_MAX_FIX (%zu)", ELEMS(res.repair.fix));
	CK(ELEMS(res.infected) == KOF_MAX_INFECTED, "the infected table holds KOF_MAX_INFECTED (%zu)", ELEMS(res.infected));
	CK(ELEMS(res.region) == KOF_MAX_REGIONS, "the region table holds KOF_MAX_REGIONS (%zu)", ELEMS(res.region));
	CK(ELEMS(rep.cap) == KOF_DIAG_REPORT_NODES && ELEMS(rep.at) == KOF_DIAG_REPORT_NODES,
	   "a diagnose report holds KOF_DIAG_REPORT_NODES nodes in both arrays");
	CK(KOF_ENTRY_NONE == 0xffffffffu && KOF_ENTRY_NONE > KOF_MAX_REGIONS, "no entry is a number a table could reach");
	CK(KOF_SYM_BYTES_FOR(0) == KOF_SYM_HDRLEN, "a symbol block of no records is its header");
	CK(KOF_SYM_BYTES_FOR(1) == KOF_SYM_HDRLEN + KOF_SYM_RECLEN + KOF_SYM_POOL_PER_REC &&
	   KOF_SYM_BYTES_FOR(1000) - KOF_SYM_BYTES_FOR(999) == KOF_SYM_RECLEN + KOF_SYM_POOL_PER_REC,
	   "each record is a record and its planned pool; the plan is linear");
	CK(KOF_WRITE_CHUNK > 0 && KOF_WRITE_CHUNK < 0x7fffffffu && (KOF_WRITE_CHUNK & (KOF_WRITE_CHUNK - 1u)) == 0,
	   "a write chunk is a power of two that fits an int (%u)", KOF_WRITE_CHUNK);
}

/* a top level object has no entry of a parent; a member of an archive says which it is */
static struct { unsigned objs, top_none, child_none, max_child; } ent;

static int ent_cb(const char *name, const void *bytes, uint64_t len, const struct kof_result *r, void *u)
{
	(void)name; (void)bytes; (void)len; (void)u;
	if (!ent.objs++)
		ent.top_none = r->entry_of == KOF_ENTRY_NONE;
	else {
		ent.child_none += r->entry_of == KOF_ENTRY_NONE;
		if (r->entry_of != KOF_ENTRY_NONE && r->entry_of > ent.max_child)
			ent.max_child = r->entry_of;
	}
	return 0;
}

static void le16(uint8_t *p, unsigned v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static size_t pdf3(uint8_t *f)
{
	size_t at = (size_t)sprintf((char *)f, "%%PDF-1.4\n");
	unsigned i;

	for (i = 1; i <= 3u; i++) {
		at += (size_t)sprintf((char *)f + at, "%u 0 obj\n<< /Length 8 >>\nstream\n", i);
		memcpy(f + at, "STREAM0!", 8);
		f[at + 6] = (uint8_t)('0' + i);
		at += 8;
		at += (size_t)sprintf((char *)f + at, "\nendstream\nendobj\n");
	}
	at += (size_t)sprintf((char *)f + at, "trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n0\n%%%%EOF\n");
	return at;
}

static size_t zip3(uint8_t *f)
{
	size_t at = 0, cd, lo = 0;
	unsigned i;
	static const char *nm[3] = { "a.bin", "b.bin", "c.bin" };

	for (i = 0; i < 3u; i++) {
		le32(f + at, 0x04034b50u); le16(f + at + 4, 10); le32(f + at + 18, 8); le32(f + at + 22, 8); le16(f + at + 26, 5);
		memcpy(f + at + 30, nm[i], 5);
		memcpy(f + at + 35, "ABCDEFG", 7); f[at + 42] = (uint8_t)('0' + i);
		at += 43;
	}
	cd = at;
	for (i = 0; i < 3u; i++) {
		le32(f + at, 0x02014b50u); le16(f + at + 4, 20); le16(f + at + 6, 10); le32(f + at + 20, 8); le32(f + at + 24, 8);
		le16(f + at + 28, 5); le32(f + at + 42, (uint32_t)lo);
		memcpy(f + at + 46, nm[i], 5);
		at += 51; lo += 43;
	}
	le32(f + at, 0x06054b50u); le16(f + at + 8, 3); le16(f + at + 10, 3);
	le32(f + at + 12, (uint32_t)(at - cd)); le32(f + at + 16, (uint32_t)cd);
	return at + 22;
}

static void entry_none(const char *db)
{
	kof_engine *e = keng_open(db);
	kof_scanner *sc = e ? kscan_new(e) : NULL;
	uint8_t z[1024];
	struct kof_scan_option opt;
	size_t n;

	CK(sc != NULL, "an engine to scan with (%s)", db);
	if (!sc) {
		if (e)
			keng_close(e);
		return;
	}
	memset(&opt, 0, sizeof opt);
	opt.all_matches = 1;
	memset(z, 0, sizeof z);
	n = pdf3(z);
	memset(&ent, 0, sizeof ent);
	(void)kscan_bytes(sc, z, n, "e.pdf", &opt, ent_cb, NULL);
	CK(ent.objs == 4u, "a PDF of three streams is four objects (%u)", ent.objs);
	CK(ent.top_none == 1u, "the top level object's entry is KOF_ENTRY_NONE");
	CK(ent.child_none == 0u && ent.max_child < 3u, "every stream says which entry of its parent it is (%u have none, largest %u)",
	   ent.child_none, ent.max_child);
	/* a container with no entry table says nothing about which member this is */
	memset(z, 0, sizeof z);
	n = zip3(z);
	memset(&ent, 0, sizeof ent);
	(void)kscan_bytes(sc, z, n, "e.zip", &opt, ent_cb, NULL);
	CK(ent.objs == 4u && ent.top_none == 1u, "a zip of three members is four objects (%u)", ent.objs);
	printf("  zip members with no entry: %u of 3 (observed: a zip member does not carry its entry index; a PDF stream does)\n", ent.child_none);
	kscan_free(sc);
	keng_close(e);
}

/* ---- the X-lists -------------------------------------------------------------------------------------------------- */

static unsigned bad_rows;

static void lists(void)
{
	unsigned seen_bits, n, i;
	uint32_t mask, bit;

	/* engines: a name for each, in the order of the enum, and "none" for what is not one */
	n = 0;
#define X_ENG(name, word) CK((uint32_t)(name) == n && !strcmp(kof_engine_name((uint32_t)(name)), word), "engine %s is row %u and spelled %s", #name, n, word); n++;
	KOF_ENGINE_LIST(X_ENG)
#undef X_ENG
	CK(n == KOF_ENGINE_COUNT, "the engine list has one row per enumerator (%u of %u)", n, (unsigned)KOF_ENGINE_COUNT);
	CK(!strcmp(kof_engine_name(KOF_ENGINE_COUNT), "none") && !strcmp(kof_engine_name(0xffffffffu), "none"), "past the list: none");
	n = 0;
#define X_VER(name, word) CK((uint32_t)(name) == n && !strcmp(kof_verdict_word((uint32_t)(name)), word), "verdict %s is row %u and spelled %s", #name, n, word); n++;
	KOF_VERDICT_LIST(X_VER)
#undef X_VER
	CK(n == KOF_VERDICT_COUNT, "the verdict list has one row per enumerator (%u of %u)", n, (unsigned)KOF_VERDICT_COUNT);

	/* region lists: distinct single bits, the union is what the header says is claimed */
	mask = 0; n = 0; bad_rows = 0;
#define X_PROC(bit_) { uint32_t b_ = (uint32_t)(bit_); if (!b_ || (b_ & (b_ - 1u)) || (mask & b_)) bad_rows++; mask |= b_; n++; }
	KOF_SCAN_PROC_LIST(X_PROC)
#undef X_PROC
	CK(n == 3u && !bad_rows && mask == (uint32_t)KOF_SCAN_PROC_CLAIMED, "process regions: three distinct bits, together the claimed mask");
	mask = 0; n = 0; bad_rows = 0;
#define X_AMSI(bit_) { uint32_t b_ = (uint32_t)(bit_); if (!b_ || (b_ & (b_ - 1u)) || (mask & b_)) bad_rows++; mask |= b_; n++; }
	AMSI_REGIONS(X_AMSI)
#undef X_AMSI
	CK(n == 2u && !bad_rows && mask == (uint32_t)KOF_SCAN_AMSI_CLAIMED, "AMSI regions: two distinct bits, together the claimed mask");
	mask = 0; n = 0; bad_rows = 0;
#define X_PDF(name, bit_) { uint32_t b_ = (uint32_t)(bit_); if (!b_ || (b_ & (b_ - 1u)) || (mask & b_)) bad_rows++; mask |= b_; n++; }
	KOF_PDF_CLASSES(X_PDF)
#undef X_PDF
	CK(n == KOF_PDF_CLS_COUNT && !bad_rows, "PDF classes: %u rows, one per class, each a distinct single bit", n);
	seen_bits = 0;
	for (i = 0, bit = 1; i < 32u; i++, bit <<= 1)
		seen_bits += (mask & bit) != 0;
	CK(seen_bits == n, "and no two classes share a bit");

	n = 0;
#define X_KIND(name, val) CK((int)(name) == (val) && (unsigned)(val) < KOF_AMSI_KIND_COUNT, "AMSI kind %s = %d", #name, (val)); \
	{ uint32_t out_ = 99; CK(kof_amsi_kind_from_name(#name, &out_) == 1 && out_ == (uint32_t)(val), "%s reads back by name", #name); } n++;
	KOF_AMSI_KIND_LIST(X_KIND)
#undef X_KIND
	CK(n == KOF_AMSI_KIND_COUNT, "the AMSI list has one row per kind (%u)", n);
	n = 0;
#define X_ST(name, val) CK((int)(name) == (val) && (unsigned)(val) < KOF_SCRIPT_TYPE_COUNT, "script type %s = %d", #name, (val)); n++;
	KOF_SCRIPT_TYPE_LIST(X_ST)
#undef X_ST
	CK(n <= KOF_SCRIPT_TYPE_COUNT && n > 1u, "the script list has %u rows within %u", n, (unsigned)KOF_SCRIPT_TYPE_COUNT);
}

/* ---- tokens ------------------------------------------------------------------------------------------------------- */

#define PFX foo
#define KOF_TEST_VAL_ 17

static void tokens(void)
{
	int KOF_PASTE(ab, 1) = 4;
	int KOF_PASTE2(cd, 2) = 5;
	int foo_x = 6;
	int PFX_y = 7;

	CK(ab1 == 4 && cd2 == 5, "paste joins two tokens");
	CK(KOF_PASTE(PFX, _x) == 6, "KOF_PASTE expands its arguments first: PFX is foo, so foo_x");
	CK(KOF_PASTE2(PFX, _y) == 7, "KOF_PASTE2 does not: PFX_y");
	(void)foo_x; (void)PFX_y;
	CK(KOF_NARG(a) == 1 && KOF_NARG(a, b) == 2 && KOF_NARG(a, b, c) == 3 && KOF_NARG(1, 2, 3, 4, 5, 6, 7, 8) == 8 &&
	   KOF_NARG(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16) == 16, "KOF_NARG counts one to sixteen");
	CK(KOF_NARG_(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 77, 0) == 77, "and KOF_NARG_ is the 17th argument");
}

/* ---- search macros against a recording find_str ----------------------------------------------------------------- */

enum { kof_strid_aa = 11, kof_strid_bb = 12, kof_strid_cc = 13, kof_rangeid_all = 3, kof_rangeid_hdr = 4,
       kof_strid_s01 = 11, kof_strid_s02, kof_strid_s03, kof_strid_s04, kof_strid_s05, kof_strid_s06, kof_strid_s07, kof_strid_s08,
       kof_strid_s09, kof_strid_s10, kof_strid_s11, kof_strid_s12, kof_strid_s13, kof_strid_s14, kof_strid_s15, kof_strid_s16 };

static struct { unsigned calls; uint32_t seq[16], range[16]; uint32_t present_mask; } fs;
static struct { unsigned calls; uint32_t id; const char *seq[8]; unsigned present; } ds;

static int rec_find_str(const struct kof_obj_ctx *c, uint32_t str_id, uint32_t range_id)
{
	(void)c;
	if (fs.calls < 16u) {
		fs.seq[fs.calls] = str_id;
		fs.range[fs.calls] = range_id;
	}
	fs.calls++;
	return (fs.present_mask >> (str_id - 11u)) & 1u;
}

static int rec_diag_str32(const struct kof_obj_ctx *c, uint32_t diag, const char *name)
{
	(void)c;
	ds.id = diag;
	if (ds.calls < 8u)
		ds.seq[ds.calls] = name;
	ds.calls++;
	return (ds.present >> (name[0] - 'a')) & 1;
}

static void search(void)
{
	static const struct kof_content vt = { .find_str = rec_find_str, .diag_str32 = rec_diag_str32 };
	struct kof_obj_ctx cx;
	const struct kof_obj_ctx *ctx = &cx;

	memset(&cx, 0, sizeof cx);
	cx.content = &vt;

	memset(&fs, 0, sizeof fs);
	fs.present_mask = 0x2u;         /* only bb */
	CK(KOF_FS_ONE(all, aa) == 0 && fs.calls == 1u && fs.seq[0] == kof_strid_aa && fs.range[0] == kof_rangeid_all,
	   "FS_ONE asks the host once, by the module's own pasted ids");
	memset(&fs, 0, sizeof fs);
	fs.present_mask = 0x2u;
	CK(KOF_FS_ONE(hdr, bb) == 1 && fs.range[0] == kof_rangeid_hdr, "and by the range's id");

	memset(&fs, 0, sizeof fs);
	fs.present_mask = 0x2u;
	CK(kof_find_str_any(all, aa, bb, cc) == 1 && fs.calls == 2u && fs.seq[1] == kof_strid_bb, "any: stops at the first hit (two of three asked)");
	memset(&fs, 0, sizeof fs);
	fs.present_mask = 0x2u;
	CK(kof_find_str_all(all, aa, bb, cc) == 0 && fs.calls == 1u, "all: stops at the first miss (one of three asked)");
	memset(&fs, 0, sizeof fs);
	fs.present_mask = 0x7u;
	CK(kof_find_str_all(all, aa, bb, cc) == 1 && fs.calls == 3u && fs.seq[0] == kof_strid_aa && fs.seq[1] == kof_strid_bb && fs.seq[2] == kof_strid_cc,
	   "all present: all three asked, in the order written");
	memset(&fs, 0, sizeof fs);
	fs.present_mask = 0;
	CK(kof_find_str_any(all, aa) == 0 && fs.calls == 1u, "one string: the single form");
	memset(&fs, 0, sizeof fs);
	CK(KOF_FS_FOLD(||, all, aa, bb) == 0 && fs.calls == 2u, "FOLD with `||` over two, none present: both asked");
	memset(&fs, 0, sizeof fs);
	fs.present_mask = 0x1u;
	CK(KOF_FS_PICK(2, &&, all, aa, bb) == 0 && fs.calls == 2u, "PICK(2) is the two string form");

	/* every arity of the fold: 1 to 16 strings, all asked in order when all are present (KOF_FS_1 .. KOF_FS_16) */
#define ARITY(n, ...) do { \
		memset(&fs, 0, sizeof fs); \
		fs.present_mask = 0xffffu; \
		CK(kof_find_str_all(all, __VA_ARGS__) == 1 && fs.calls == (n), "kof_find_str_all of %d strings asks %u", (n), fs.calls); \
		CK(fs.seq[0] == kof_strid_s01 && fs.seq[(n) - 1] == kof_strid_s01 + (n) - 1, "in order, first to last (%d)", (n)); \
		memset(&fs, 0, sizeof fs); \
		CK(kof_find_str_any(all, __VA_ARGS__) == 0 && fs.calls == (n), "none present: any asks all %d", (n)); \
	} while (0)
	ARITY(1, s01);
	ARITY(2, s01, s02);
	ARITY(3, s01, s02, s03);
	ARITY(4, s01, s02, s03, s04);
	ARITY(5, s01, s02, s03, s04, s05);
	ARITY(6, s01, s02, s03, s04, s05, s06);
	ARITY(7, s01, s02, s03, s04, s05, s06, s07);
	ARITY(8, s01, s02, s03, s04, s05, s06, s07, s08);
	ARITY(9, s01, s02, s03, s04, s05, s06, s07, s08, s09);
	ARITY(10, s01, s02, s03, s04, s05, s06, s07, s08, s09, s10);
	ARITY(11, s01, s02, s03, s04, s05, s06, s07, s08, s09, s10, s11);
	ARITY(12, s01, s02, s03, s04, s05, s06, s07, s08, s09, s10, s11, s12);
	ARITY(13, s01, s02, s03, s04, s05, s06, s07, s08, s09, s10, s11, s12, s13);
	ARITY(14, s01, s02, s03, s04, s05, s06, s07, s08, s09, s10, s11, s12, s13, s14);
	ARITY(15, s01, s02, s03, s04, s05, s06, s07, s08, s09, s10, s11, s12, s13, s14, s15);
	ARITY(16, s01, s02, s03, s04, s05, s06, s07, s08, s09, s10, s11, s12, s13, s14, s15, s16);
#undef ARITY
	{
		static const char *const n8[] = { "a", "b", "c", "d", "e", "f", "g", "h" };
		unsigned k;

		/* and a diagnose's strings, 1 to 8 (KOF_DFS_1 .. KOF_DFS_8): in order, one call each */
#define DARITY(n, ...) do { \
			memset(&ds, 0, sizeof ds); \
			ds.present = 0xffu; \
			CK(kof_diag_str_all(my_diag_00, __VA_ARGS__) == 1 && ds.calls == (n), "kof_diag_str_all of %d strings asks %u", (n), ds.calls); \
			for (k = 0; k < (n); k++) \
				CK(!strcmp(ds.seq[k], n8[k]), "string %u of %d in order", k, (n)); \
		} while (0)
		DARITY(1, "a");
		DARITY(2, "a", "b");
		DARITY(3, "a", "b", "c");
		DARITY(4, "a", "b", "c", "d");
		DARITY(5, "a", "b", "c", "d", "e");
		DARITY(6, "a", "b", "c", "d", "e", "f");
		DARITY(7, "a", "b", "c", "d", "e", "f", "g");
		DARITY(8, "a", "b", "c", "d", "e", "f", "g", "h");
#undef DARITY
	}

	/* the same, for a diagnose's strings */
	memset(&ds, 0, sizeof ds);
	ds.present = 0x2u;              /* "b" */
	CK(kof_diag_str_one(my_diag_00, "a") == 0 && ds.calls == 1u && ds.id == kof_diag_id32_("my_diag_00"), "diag_str_one asks by the diagnose's id");
	memset(&ds, 0, sizeof ds);
	ds.present = 0x7u;
	CK(kof_diag_str_all(my_diag_00, "a", "b", "c") == 1 && ds.calls == 3u && !strcmp(ds.seq[0], "a") && !strcmp(ds.seq[2], "c"),
	   "diag_str_all asks each in order");
	memset(&ds, 0, sizeof ds);
	ds.present = 0x5u;
	CK(kof_diag_str_all(my_diag_00, "a", "b", "c") == 0 && ds.calls == 2u, "and stops at the first miss");
	memset(&ds, 0, sizeof ds);
	ds.present = 0x4u;
	CK(KOF_DFS_FOLD(||, my_diag_00, "a", "b", "c") == 1 && ds.calls == 3u, "DFS_FOLD with `||` runs to the hit");
}

/* ---- the codings -------------------------------------------------------------------------------------------------- */

static void codings(void)
{
	uint32_t t, w;
	unsigned lc, lp, pb, n = 0, dup = 0;
	static uint8_t seen[1024];

	/* the class is stored plus one, so that the empty word means "no class" and class 0 is a class */
	for (t = 0; t < 255u; t++) {
		w = KOF_ENG_CLASS_PUT(t);
		if (KOF_ENG_CLASS_OF(w) != t + 1u || (w & ((1u << KOF_ENG_CLASS_SHIFT) - 1u)))
			break;
	}
	CK(t == 255u, "a class put into a word comes out as class + 1, touching no bit below the shift (stopped at %u)", t);
	CK(KOF_ENG_CLASS_PUT(0) != 0 && KOF_ENG_CLASS_OF(0) == 0, "class 0 is not the empty word, and the empty word has no class");
	CK(KOF_ENG_CLASS_OF(0xabu | KOF_ENG_CLASS_PUT(9)) == 10u, "other bits of the word do not move the class");
	CK(KOF_ENG_CLASS_OF(KOF_ENG_CLASS_PUT(255)) == 0, "class 255 does not fit the byte and reads as none (classes are 0..254)");

	CK(KOF_UNP_ASPACK_MARK(0) == (uint32_t)KOF_UNP_ASPACK_E8E9 && KOF_UNP_ASPACK_MARK(0x1e8) == (uint32_t)KOF_UNP_ASPACK_E8E9 + 0xe8u &&
	   KOF_UNP_ASPACK_MARK(0xff) == (uint32_t)KOF_UNP_ASPACK_E8E9 + 0xffu, "the ASPack mark is the base plus the mark byte, and only the byte");

	for (lc = 0; lc <= 8u; lc++)
		for (lp = 0; lp <= 4u; lp++)
			for (pb = 0; pb <= 4u; pb++) {
				uint32_t m32 = KOF_UNP_LZMA_MPRESS_PROPS(lc, lp, pb, 32);
				uint32_t m64 = KOF_UNP_LZMA_MPRESS_PROPS(lc, lp, pb, 64);
				uint32_t k32 = m32 - (uint32_t)KOF_UNP_LZMA_MPRESS32, k64 = m64 - (uint32_t)KOF_UNP_LZMA_MPRESS64;

				n++;
				if (k32 >= 1024u || k64 >= 1024u || k32 != k64 || seen[k32]++)
					dup++;
			}
	CK(n == 225u && dup == 0, "every lc/lp/pb of an LZMA header is a method of its own, and the same offset for 32 and 64 bits (%u collisions)", dup);
	CK(KOF_UNP_LZMA_MPRESS_PROPS(0, 0, 0, 64) == (uint32_t)KOF_UNP_LZMA_MPRESS64 && KOF_UNP_LZMA_MPRESS_PROPS(0, 0, 0, 32) == (uint32_t)KOF_UNP_LZMA_MPRESS32 &&
	   KOF_UNP_LZMA_MPRESS_PROPS(0, 0, 0, 31) == (uint32_t)KOF_UNP_LZMA_MPRESS32, "the width picks the base: 64 is the 64 bit one, anything else the 32 bit one");
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/release/databases";

	limits();
	lists();
	tokens();
	search();
	codings();
	entry_none(db);
	printf("api_engine_macros: %u checks, %u failed\n", he_checks, he_fails);
	return he_fails != 0;
}
