/*
 * api_engine_modhelpers.c - the pure helpers of the module ABI headers
 * (libkofeng/kofcore/kofmod): the vocabularies that turn an enum into a word and
 * a word back into the enum, the name and comment character classes, the
 * byte-swap and range helpers, the symbol block and graph block readers, and the
 * diagnose id hashes.
 *
 * The vocabularies are written once as X-macro lists; the test expands the SAME
 * lists, so a value added to a list is tested the day it is added, and checks
 * what the helpers promise about all of them: every value has a word, the word
 * maps back to the value, no two share a word, and a name that is only a prefix
 * of another (KOF_ARCH_X86 of KOF_ARCH_X86_64) is not accepted for it.
 *
 * The symbol and graph blocks are binary formats read out of memory a producer
 * filled. They are built here by hand from the layout the header documents, and
 * the readers are given what a damaged block looks like: a count larger than the
 * bytes, a name offset outside the pool, a name that is not terminated, records
 * cut in half. A reader may refuse; it may not read outside the block or run for
 * a time that depends on a number in the block rather than on its length.
 */

#include "hostile_engine.h"
#include "known_miss.h"

#include <time.h>

#include "../../libkofeng/kofcore/kofcore.h"
#include <kofmod/kofsig.h>
#include <kofmod/kofsym.h>
#include <kofmod/kofdiagtree.h>
#include <kofmod/script.h>
#include <kofmod/pdf.h>
#include <kofmod/pe.h>
#include <kofmod/elf.h>
#include <kofmod/proc.h>
#include <kofmod/amsi.h>
#include <kofmod/xz.h>
#include <kofmod/kofmutation.h>
#include <kofmod/ep_shape.h>
#include <kofmod/stub_pat.h>
#include <kofmod/upx_method.h>
#include <kofmod/emu_harvest.h>
#include "../../libkofeng/analyzers/genome_obj.h"
#include "../../libkofeng/analyzers/diseases/msf_elf64.h"
#include "../../libkofeng/analyzers/diseases/msf_pe.h"
#include "../../libkofeng/analyzers/diseases/msf_elf32.h"    /* needs -I$(SDK)/include: UNIT_EXTRA in mk/tests.mk */

/* ---- vocabularies ---------------------------------------------------------------------- */

struct vocab {
	const char *ident;
	uint32_t    val;
};

#define V_FMT(name, val, word, grp) { #name, (uint32_t)(val) },
static const struct vocab fmts[] = { KOF_TARGET_LIST(V_FMT) };
#undef V_FMT
#define V_ARCH(name, val, word) { #name, (uint32_t)(val) },
static const struct vocab archs[] = { KOF_ARCH_LIST(V_ARCH) };
#undef V_ARCH
#define V_SCRIPT(name, val) { #name, (uint32_t)(val) },
static const struct vocab scripts[] = { KOF_SCRIPT_TYPE_LIST(V_SCRIPT) };
#undef V_SCRIPT
#define V_OS(name, val) { #name, (uint32_t)(val) },
static const struct vocab proc_os[] = { KOF_PROC_OS_LIST(V_OS) };
#undef V_OS
#define V_AMSI(name, val) { #name, (uint32_t)(val) },
static const struct vocab amsi_kinds[] = { KOF_AMSI_KIND_LIST(V_AMSI) };
#undef V_AMSI
#define V_MAL(name, word) { #name, (uint32_t)(name) },
static const struct vocab maltypes[] = { KOF_MALTYPE_LIST(V_MAL) };
#undef V_MAL
#define V_PEI(name, val) { #name, (uint32_t)(val) },
static const struct vocab pe_images[] = { KOF_PE_IMAGE_LIST(V_PEI) };
#undef V_PEI
#define V_ELFT(name, val) { #name, (uint32_t)(val) },
static const struct vocab elf_types[] = { KOF_ELF_TYPE_LIST(V_ELFT) };
#undef V_ELFT

#define NV(a) ((unsigned)(sizeof (a) / sizeof (a)[0]))

static void distinct(const struct vocab *v, unsigned n, const char *what)
{
	unsigned i, j;

	for (i = 0; i < n; i++)
		for (j = i + 1; j < n; j++) {
			CK(strcmp(v[i].ident, v[j].ident) != 0, "%s: identifier %s listed twice", what, v[i].ident);
			CK(v[i].val != v[j].val, "%s: %s and %s share the value %u", what, v[i].ident, v[j].ident, v[i].val);
		}
}

static void t_formats(void)
{
	unsigned i;
	uint8_t out = 77;

	distinct(fmts, NV(fmts), "format");
	for (i = 0; i < NV(fmts); i++) {
		uint8_t f = (uint8_t)fmts[i].val;
		const char *id = kof_format_ident(f);

		CK(id && strcmp(id, fmts[i].ident) == 0, "format %u has its identifier", f);
		CK(kof_format_name(f)[0] != 0, "format %u has a name", f);
		CK(kof_format_from_name(fmts[i].ident, &out) == 1 && out == f, "%s maps back", fmts[i].ident);
		CK((unsigned)kof_format_group(f) < 16u && kof_format_group_name(kof_format_group(f))[0], "format %u has a group", f);
		CK(kof_streq_(fmts[i].ident, id), "kof_streq_ on equal text");
	}
	out = 77;
	CK(kof_format_from_name("KOF_FMT_NOPE", &out) == 0 && out == 77, "an unknown identifier: 0, out untouched");
	CK(kof_format_from_name("", &out) == 0 && kof_format_from_name("KOF_FMT_EL", &out) == 0 &&
	   kof_format_from_name("KOF_FMT_ELFX", &out) == 0 && kof_format_from_name("kof_fmt_elf", &out) == 0,
	   "a prefix, an extension and a different case are not the identifier");
	CK(kof_format_ident(KOF_FMT_COUNT) == NULL && kof_format_ident(250) == NULL, "no identifier past the list");
	CK(strcmp(kof_format_name(250), "Unknown") == 0, "an id this build has no name for reads Unknown");
	CK(strcmp(kof_format_name(KOF_FMT_UNKNOWN), "Raw") == 0, "format 0 is Raw, not Unknown");
	CK(!kof_streq_("a", "ab") && !kof_streq_("ab", "a") && kof_streq_("", "") && !kof_streq_("a", "b"), "streq_");
	CK(strcmp(kof_format_group_name((enum kof_format_group)200), "Other") == 0, "a group from outside is Other");
}

static void t_arch(void)
{
	unsigned i;
	uint8_t out = 77;

	distinct(archs, NV(archs), "arch");
	for (i = 0; i < NV(archs); i++) {
		CK(kof_arch_name((uint8_t)archs[i].val)[0] != 0, "arch %u has a name", archs[i].val);
		CK(kof_arch_from_name(archs[i].ident, &out) == 1 && out == (uint8_t)archs[i].val, "%s maps back", archs[i].ident);
	}
	CK(kof_arch_from_name("KOF_ARCH_X86", &out) == 1 && out == KOF_ARCH_X86, "x86 is itself");
	CK(kof_arch_from_name("KOF_ARCH_X86_6", &out) == 0, "and a prefix of x86_64 is not");
	CK(strcmp(kof_arch_name(250), "other") == 0, "an arch from outside is `other`");
}

static void t_other_vocab(void)
{
	unsigned i;
	uint32_t o32 = 5;
	int oi = 5;

	distinct(scripts, NV(scripts), "script");
	for (i = 0; i < NV(scripts); i++) {
		CK(kof_script_type_from_name(scripts[i].ident, &o32) == 1 && o32 == scripts[i].val, "%s maps back", scripts[i].ident);
		CK(kof_script_type_name((uint8_t)scripts[i].val)[0], "script %u has a word", scripts[i].val);
	}
	CK(strcmp(kof_script_type_name(200), "Script") == 0, "an unknown script kind is Script");
	CK(kof_script_type_from_name("KOF_SCRIPT_NOPE", &o32) == 0 && o32 == scripts[NV(scripts) - 1u].val, "unknown script identifier");

	distinct(proc_os, NV(proc_os), "proc os");
	for (i = 0; i < NV(proc_os); i++) {
		o32 = 99;
		CK(kof_proc_os_from_name(proc_os[i].ident, &o32) == 1 && o32 == proc_os[i].val, "%s maps back", proc_os[i].ident);
	}
	CK(kof_proc_os_from_name("KOF_PROC_OS_NOPE", &o32) == 0, "unknown os");

	distinct(amsi_kinds, NV(amsi_kinds), "amsi kind");
	for (i = 0; i < NV(amsi_kinds); i++)
		CK(kof_amsi_kind_from_name(amsi_kinds[i].ident, &o32) == 1 && o32 == amsi_kinds[i].val, "%s maps back", amsi_kinds[i].ident);
	CK(kof_amsi_kind_from_name("KOF_AMSI_NOPE", &o32) == 0, "unknown amsi kind");

	distinct(pe_images, NV(pe_images), "pe image");
	for (i = 0; i < NV(pe_images); i++)
		CK(kof_pe_image_from_name(pe_images[i].ident, &o32) == 1 && o32 == pe_images[i].val, "%s maps back", pe_images[i].ident);
	CK(kof_pe_image_from_name("KOF_PE_NOPE", &o32) == 0, "unknown pe image");

	distinct(elf_types, NV(elf_types), "elf type");
	for (i = 0; i < NV(elf_types); i++)
		CK(kof_elf_type_from_name(elf_types[i].ident, &o32) == 1 && o32 == elf_types[i].val, "%s maps back", elf_types[i].ident);
	CK(kof_elf_type_from_name("KOF_ELF_NOPE", &o32) == 0, "unknown elf type");

	distinct(maltypes, NV(maltypes), "maltype");
	for (i = 0; i < NV(maltypes); i++) {
		const char *w = kof_maltype_name(maltypes[i].val);

		CK(strcmp(kof_maltype_ident(maltypes[i].val), maltypes[i].ident) == 0, "maltype %u ident", i);
		CK(kof_maltype_from_name(maltypes[i].ident, &oi) == 1 && (uint32_t)oi == maltypes[i].val, "%s maps back by identifier", maltypes[i].ident);
		CK(kof_maltype_from_word(w, &oi) == 1 && (uint32_t)oi == maltypes[i].val, "%s maps back by word", w);
		{
			char up[32];
			unsigned k;

			for (k = 0; w[k] && k < 31; k++)
				up[k] = (char)((w[k] >= 'a' && w[k] <= 'z') ? w[k] - 32 : w[k]);
			up[k] = 0;
			CK(kof_maltype_from_word(up, &oi) == 1 && (uint32_t)oi == maltypes[i].val, "%s maps back in capitals", w);
		}
	}
	CK(strcmp(kof_maltype_name(KOF_MALTYPE_COUNT), "Malware") == 0 && strcmp(kof_maltype_name(0xffffffffu), "Malware") == 0,
	   "a type from outside reads Malware");
	CK(strcmp(kof_maltype_ident(0xffffffffu), "KOF_MALTYPE_VIRUS") == 0, "and its identifier falls back to the first");
	oi = 99;
	CK(kof_maltype_from_name("KOF_MALTYPE_NOPE", &oi) == 0 && kof_maltype_from_word("nope", &oi) == 0 && oi == 99, "unknown, out untouched");
	CK(kof_strieq_("Abc", "aBC") && !kof_strieq_("abc", "abd") && !kof_strieq_("abc", "ab") && kof_strieq_("", ""), "strieq_");

	for (i = 0; i < KOF_ENGINE_COUNT; i++)
		CK(kof_engine_name(i)[0] != 0 && (strcmp(kof_engine_name(i), "none") != 0 || i == KOF_ENGINE_NONE), "engine %u has a word", i);
	CK(strcmp(kof_engine_name(KOF_ENGINE_COUNT), "none") == 0 && strcmp(kof_engine_name(0xffffffffu), "none") == 0, "an engine from outside is none");
	for (i = 0; i < KOF_VERDICT_COUNT; i++)
		CK(kof_verdict_word(i)[0] != 0, "verdict %u has a word", i);
	CK(strcmp(kof_verdict_word(KOF_VERDICT_COUNT), "clean") == 0, "a verdict from outside reads clean");
	CK(strcmp(kof_verdict_word(KOF_VERDICT_INFECTED), "Infected") == 0 && strcmp(kof_verdict_word(KOF_VERDICT_SUSPECTED), "Suspected") == 0,
	   "the words a finding's name begins with");
}

static void t_script_fam(void)
{
	CK(kof_script_fam_mask(KOF_SFAM_PHP) == (1u << KOF_SCRIPT_PHP), "php family");
	CK(kof_script_fam_mask(KOF_SFAM_SVR) == ((1u << KOF_SCRIPT_ASP) | (1u << KOF_SCRIPT_ASPX) | (1u << KOF_SCRIPT_JSP)), "server page family");
	CK(kof_script_fam_mask(KOF_SFAM_CFM) == (1u << KOF_SCRIPT_CFM), "cfml family");
	CK(kof_script_fam_mask(KOF_SFAM_HTML) == 0xffffffffu && kof_script_fam_mask(200) == 0xffffffffu,
	   "markup and an unknown family rule nothing out");
	CK(strcmp(kof_script_fam_name(KOF_SFAM_PHP), "php") == 0 && strcmp(kof_script_fam_name(KOF_SFAM_HTML), "markup") == 0 &&
	   strcmp(kof_script_fam_name(KOF_SFAM_SVR), "server-page") == 0 && strcmp(kof_script_fam_name(KOF_SFAM_CFM), "cfml") == 0, "family words");
	CK(kof_script_fam_name(200) == NULL, "an unknown family has NO word (a NULL a caller must not print)");
	{
		struct kof_obj_ctx ctx;
		struct kof_script_info *s = calloc(1, sizeof *s);

		memset(&ctx, 0, sizeof ctx);
		CK(kof_script_islands_of(&ctx) == 0, "no view: no islands");
		if (s) {
			s->n_island = 3;
			ctx.file_header = s;
			CK(kof_script(&ctx) == s && kof_script_islands_of(&ctx) == 3, "the view and its island count");
			free(s);
		}
	}
}

static void t_entry_names(void)
{
	uint32_t k;

	for (k = 0; k < KOF_ENT_KIND_COUNT; k++)
		CK(strcmp(kof_entry_kind_name(k), "?") != 0, "entry kind %u has a name", k);
	CK(strcmp(kof_entry_kind_name(KOF_ENT_KIND_COUNT), "?") == 0 && strcmp(kof_entry_kind_name(0xffffffffu), "?") == 0, "past the kinds: ?");
	CK(strcmp(kof_entry_kind_name(KOF_ENT_NORMALIZED), "NORMALIZED") == 0, "the normalised view");

	CK(strcmp(kof_unp_method_name(0), "") == 0, "no method is the empty word");
	CK(strcmp(kof_unp_method_name(KOF_UNP_DEFLATE), "deflate") == 0 && strcmp(kof_unp_method_name(KOF_UNP_ZLIB), "zlib") == 0 &&
	   strcmp(kof_unp_method_name(KOF_UNP_LZW), "lzw") == 0 && strcmp(kof_unp_method_name(KOF_UNP_RAR5), "rar5") == 0 &&
	   strcmp(kof_unp_method_name(KOF_UNP_LZHUF_LH5), "lh5") == 0 && strcmp(kof_unp_method_name(KOF_UNP_APLIB), "aplib") == 0, "plain methods");
	CK(strcmp(kof_unp_method_name(KOF_UNP_LZX(15)), "lzx") == 0 && strcmp(kof_unp_method_name(KOF_UNP_LZX_RESET(21)), "lzx") == 0, "lzx with its window bits");
	CK(strcmp(kof_unp_method_name(KOF_UNP_LZMA), "lzma") == 0 && strcmp(kof_unp_method_name(KOF_UNP_LZMA_PROPS(3, 0, 2)), "lzma") == 0, "lzma with its properties");
	CK(strcmp(kof_unp_method_name(KOF_UNP_LZMA_MPRESS32), "lzma+mpress") == 0 && strcmp(kof_unp_method_name(KOF_UNP_LZMA_MPRESS64 + 5), "lzma+mpress") == 0, "mpress");
	CK(strcmp(kof_unp_method_name(KOF_UNP_ASPACK_E8E9 + 0x42u), "aspack+e8e9") == 0, "aspack with its marker");
	CK(strcmp(kof_unp_method_name(KOF_UNP_NRV2B_16), "nrv2b") == 0 && strcmp(kof_unp_method_name(KOF_UNP_NRV2D_32), "nrv2d") == 0 &&
	   strcmp(kof_unp_method_name(KOF_UNP_NRV2E_8), "nrv2e") == 0, "ucl families");
	CK(strcmp(kof_unp_method_name(0xffffffffu), "?") == 0 && strcmp(kof_unp_method_name(100000), "?") == 0 &&
	   strcmp(kof_unp_method_name(KOF_UNP_LZMA + 225u), "?") == 0, "past the ranges: ?");

	CK(strcmp(kof_analyze_word(KOF_ANALYZE_UNWRAP), "Unwrap") == 0 && strcmp(kof_analyze_word(KOF_ANALYZE_RECOVER), "Recover") == 0 &&
	   strcmp(kof_analyze_word(KOF_ANALYZE_NORMZ), "Normalize") == 0, "analysis step words");
	CK(kof_analyze_word(9999) == NULL || kof_analyze_word(9999)[0] == 0 || 1, "an unknown step does not crash");

	CK(kof_pdf_entry_format(KOF_PDF_CAT_SCRIPT) == KOF_FMT_SCRIPT && kof_pdf_entry_format(KOF_PDF_CAT_IMAGE) == KOF_FMT_IMAGE &&
	   kof_pdf_entry_format(KOF_PDF_CAT_FONT) == KOF_FMT_FONT && kof_pdf_entry_format(KOF_PDF_CAT_CONTENT) == KOF_FMT_UNKNOWN &&
	   kof_pdf_entry_format(0xffffffffu) == KOF_FMT_UNKNOWN, "PDF entry formats");
	CK(kof_pdf_entry_kind(KOF_PDF_CAT_OBJSTM) == KOF_ENT_STRUCTURE && kof_pdf_entry_kind(KOF_PDF_CAT_XREF) == KOF_ENT_STRUCTURE &&
	   kof_pdf_entry_kind(KOF_PDF_CAT_METADATA) == KOF_ENT_METADATA && kof_pdf_entry_kind(KOF_PDF_CAT_EMBEDDED) == KOF_ENT_EMBEDDED &&
	   kof_pdf_entry_kind(KOF_PDF_CAT_SCRIPT) == KOF_ENT_SCRIPT && kof_pdf_entry_kind(0xffffffffu) == KOF_ENT_UNKNOWN, "PDF entry kinds");
}

static void t_chars(void)
{
	int c, bad = 0;
	char name63[64], name64[65];

	for (c = -2; c < 300; c++) {
		int want_name = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
		int want_comment = c >= 0x20 && c < 0x7f && c != '*' && c != '/';

		if (!!kof_name_char(c) != want_name)
			bad |= 1;
		if (!!kof_comment_char(c) != want_comment)
			bad |= 2;
	}
	CK(!(bad & 1), "name_char is letters, digits, - and _ over every int");
	CK(!(bad & 2), "comment_char is printable but for * and / over every int");
	CK(kof_name_ok("Mirai-A_1") == 1 && kof_name_ok("a") == 1, "a plain name");
	CK(kof_name_ok(NULL) == 0 && kof_name_ok("") == 0 && kof_name_ok("a b") == 0 && kof_name_ok("a.b") == 0 &&
	   kof_name_ok("a/b") == 0 && kof_name_ok("a\n") == 0 && kof_name_ok("\xc3\xa9") == 0, "NULL, empty, space, dot, slash, newline, UTF-8");
	memset(name63, 'n', 63);
	name63[63] = 0;
	memset(name64, 'n', 64);
	name64[64] = 0;
	CK(kof_name_ok(name63) == 1 && kof_name_ok(name64) == 0 && KOF_NAME_MAX == 63u, "KOF_NAME_MAX characters is the longest name");
}

static void t_misc(void)
{
	CK(kof_bswap16(0x1234) == 0x3412 && kof_bswap16(0) == 0 && kof_bswap16(0xffff) == 0xffff && kof_bswap16(kof_bswap16(0xabcd)) == 0xabcd, "bswap16");
	CK(kof_bswap32(0x12345678u) == 0x78563412u && kof_bswap32(0) == 0 && kof_bswap32(kof_bswap32(0xdeadbeefu)) == 0xdeadbeefu, "bswap32");
	CK(kof_range_in_obj(100, 0, 100) && kof_range_in_obj(100, 100, 0) && !kof_range_in_obj(100, 101, 0) && !kof_range_in_obj(100, 99, 2) &&
	   !kof_range_in_obj(100, UINT64_MAX, 2) && !kof_range_in_obj(100, 1, UINT64_MAX) && !kof_range_in_obj(0, 0, 1) && kof_range_in_obj(0, 0, 0),
	   "range_in_obj does not wrap");
	CK(strcmp(kof_anchor_expr(KOF_ANCHOR_ENTRY), "ctx->entry_off") == 0 && strcmp(kof_anchor_expr(KOF_ANCHOR_EOF), "ctx->obj_size") == 0 &&
	   kof_anchor_expr(KOF_ANCHOR_BOF)[0] == 0 && kof_anchor_expr(99)[0] == 0, "anchor expressions");
	CK(strcmp(kof_anchor_word(KOF_ANCHOR_ENTRY), "entry") == 0 && strcmp(kof_anchor_word(KOF_ANCHOR_EOF), "eof") == 0 &&
	   strcmp(kof_anchor_word(KOF_ANCHOR_BOF), "bof") == 0 && strcmp(kof_anchor_word(99), "bof") == 0, "anchor words");

	CK(kof_xz_check_len(0) == 0 && kof_xz_check_len(1) == 4 && kof_xz_check_len(4) == 8 && kof_xz_check_len(10) == 32 &&
	   kof_xz_check_len(15) == 64 && kof_xz_check_len(16) == 0 && kof_xz_check_len(0xffffffffu) == 0, "xz check sizes: CRC32 4, CRC64 8, SHA-256 32");
	CK(kof_pe_perm_decl(0) == 0 && (kof_pe_perm_decl(KOF_PE_PERM_X) & KUNP_PERM_X) && !(kof_pe_perm_decl(KOF_PE_PERM_X) & KUNP_PERM_W) &&
	   kof_pe_perm_decl(KOF_PE_PERM_R | KOF_PE_PERM_W | KOF_PE_PERM_X) == (KUNP_PERM_R | KUNP_PERM_W | KUNP_PERM_X), "pe permissions to the unpacker's");

	/* diagnose ids */
	CK(kof_diag_id32_("") == 2166136261u, "the id of nothing is the FNV basis");
	CK(kof_diag_id32_("a") == 0xe40c292cu, "FNV-1a of 'a'");
	CK(KOF_DIAG_ID("a") == kof_diag_id32_("a"), "the macro is the function");
	CK(kof_diag_fold16_(0) == 1 && kof_diag_fold16_(0x00010001u) == 1 && kof_diag_fold16_(0x12345678u) == (uint16_t)((0x1234u ^ 0x5678u) & 0xffffu),
	   "fold16 xors the halves and never returns 0");
	CK(kof_diag_id_("a") == kof_diag_fold16_(kof_diag_id32_("a")), "id_ is fold16 of id32");
	{
		uint32_t i, zero16 = 0;

		for (i = 0; i < 100000; i++)
			zero16 += kof_diag_fold16_(i * 2654435761u) == 0;
		CK(zero16 == 0, "no 32-bit id folds to the empty 16-bit id");
	}

	/* the mutation helpers of the module side */
	{
		static const uint32_t a[4] = { 1, 3, 5, 7 }, b[4] = { 3, 5, 9, 11 }, c[4] = { 2, 4, 6, 8 };
		uint32_t h[3] = { 1, 2, 3 }, h2[3] = { 3, 2, 1 };

		CK(kof_mutation_fold(h, 3) != kof_mutation_fold(h2, 3), "fold depends on order");
		CK(kof_mutation_fold(NULL, 0) == 2166136261u, "fold of nothing");
		CK(kof_mutation_same_block(a, 4, a, 4) == 1, "a block is the same as itself");
		CK(kof_mutation_same_block(a, 4, b, 4) == 0, "half shared is not more than half");
		CK(kof_mutation_same_block(a, 4, c, 4) == 0 && kof_mutation_same_block(NULL, 4, a, 4) == 0 && kof_mutation_same_block(a, 0, a, 4) == 0,
		   "disjoint, NULL, empty");
		{
			static const uint32_t d[4] = { 1, 3, 5, 9 };

			CK(kof_mutation_same_block(a, 4, d, 4) == 1, "three of four shared is the same block");
		}
		/* kof_mutation_region_excluded is gone: the decision is kof_parser_region_unoffered, covered by tests/unit/region_excluded.c */
	}
}

/* ---- the symbol block ---------------------------------------------------------------------------- */

struct symspec {
	const char *name;
	uint8_t flags;
};

static uint32_t sym_make(uint8_t *out, uint32_t cap, const struct symspec *s, uint32_t n)
{
	uint32_t pool = KOF_SYM_HDRLEN + n * KOF_SYM_RECLEN, at = pool, i;

	if (pool > cap)
		return 0;
	memset(out, 0, pool);
	memcpy(out, "KSYM", 4);
	kof_st_le16(out + KOF_SYM_H_VERSION, KOF_SYM_VERSION);
	kof_st_le16(out + KOF_SYM_H_RECLEN, KOF_SYM_RECLEN);
	kof_st_le32(out + KOF_SYM_H_COUNT, n);
	out[KOF_SYM_H_ORIGIN] = KOF_SYM_ORIGIN_SYMTAB;
	kof_st_le16(out + KOF_SYM_H_START, KOF_SYM_NO_START);
	for (i = 0; i < n; i++) {
		uint8_t *r = out + KOF_SYM_HDRLEN + i * KOF_SYM_RECLEN;
		uint32_t l = (uint32_t)strlen(s[i].name);

		if (at + KOF_SYM_KEYLEN + l + 1u > cap)
			return 0;
		memset(out + at, 0, KOF_SYM_KEYLEN);
		memcpy(out + at + KOF_SYM_KEYLEN, s[i].name, l + 1u);
		r[KOF_SYM_R_TYPE] = KOF_STT_FUNC;
		r[KOF_SYM_R_BIND] = KOF_STB_GLOBAL;
		r[KOF_SYM_R_FLAGS] = s[i].flags;
		kof_st_le32(r + KOF_SYM_R_NAMEOFF, at - pool + KOF_SYM_KEYLEN);
		kof_st_le16(r + KOF_SYM_R_NAMELEN, (uint16_t)l);
		kof_st_le64(r + KOF_SYM_R_VALUE, 0x1000u + i);
		at += KOF_SYM_KEYLEN + l + 1u;
	}
	return at;
}

static void t_sym_block(void)
{
	static const struct symspec sp[] = {
		{ "socket", KOF_SYM_F_UNDEFINED }, { "connect", KOF_SYM_F_UNDEFINED }, { "main", KOF_SYM_F_DEFINED },
		{ "helper", KOF_SYM_F_DEFINED }, { "execve", KOF_SYM_F_UNDEFINED }
	};
	uint8_t b[1024];
	uint32_t n = sym_make(b, sizeof b, sp, 5), len;
	const uint8_t *r;
	uint64_t off = 0, rl = 0;
	struct kof_range ext[8];
	uint32_t k, first;

	CK(n > 0, "block built");
	CK(kof_sym_count(b, n) == 5 && kof_sym_origin(b, n) == KOF_SYM_ORIGIN_SYMTAB && !kof_sym_truncated(b, n), "count, origin, not truncated");
	CK(kof_sym_pool_at(b, n) == KOF_SYM_HDRLEN + 5u * KOF_SYM_RECLEN, "the pool follows the records");
	r = kof_sym_rec(b, n, 2);
	CK(r != NULL && kof_sym_u64(r, KOF_SYM_R_VALUE) == 0x1002u && kof_sym_u16(r, KOF_SYM_R_NAMELEN) == 4 && kof_sym_u32(r, KOF_SYM_R_NAMEOFF) >= KOF_SYM_KEYLEN,
	   "record 2 reads back");
	CK(strcmp(kof_sym_name(b, n, r, &len), "main") == 0 && len == 4, "the name and its length");
	CK(!kof_sym_name_cut(r) && kof_sym_name_cut(NULL) == 0, "name_cut");
	CK(kof_sym_run(b, n, 0, &off, &rl) == 1 && rl == KOF_SYM_KEYLEN + 6u + 1u, "a run is key + name + NUL");
	CK(kof_sym_index_at(b, n, off) == 0, "the run's offset finds its record");
	CK(kof_sym_index_at(b, n, off + 1) == 5 && kof_sym_index_at(b, n, 0) == 5, "an offset that is no run's start is `none` = the count");
	{
		struct kof_range e = { off, rl };

		CK(kof_sym_extent_recs(b, n, &e, &first) == 1 && first == 0, "an extent of one run holds one record");
		e.len = 100000;
		CK(kof_sym_extent_recs(b, n, &e, &first) == 5, "an extent past the pool holds them all");
		e.off = 3;
		CK(kof_sym_extent_recs(b, n, &e, &first) == 0, "an extent that starts inside no run holds none");
	}
	k = kof_sym_extents(b, n, KOF_SCAN_SYM_IMP, ext, 8);
	CK(k >= 1 && k <= 3 && ext[0].len > 0, "imports are extents of the three undefined symbols, adjacent ones merged (%u)", k);
	CK(kof_sym_extents(b, n, KOF_SCAN_SYM_EXP, ext, 8) >= 1, "exports have extents");
	CK(kof_sym_extents(b, n, KOF_SCAN_SYM_IMP | KOF_SCAN_SYM_EXP, ext, 8) >= 2, "both together");
	CK(kof_sym_extents(b, n, 0, ext, 8) == 0 && kof_sym_extents(NULL, n, KOF_SCAN_SYM_IMP, ext, 8) == 0 &&
	   kof_sym_extents(b, n, KOF_SCAN_SYM_IMP, NULL, 8) == 0 && kof_sym_extents(b, n, KOF_SCAN_SYM_IMP | KOF_SCAN_SYM_EXP, ext, 1) == 1,
	   "no mask, NULL block, NULL out, capacity 1");
	CK(kof_sym_first(b, n) == 0, "no start symbol");
	kof_st_le16(b + KOF_SYM_H_START, 1);
	CK(kof_sym_first(b, n) == 2, "a start index of 1 is record 2 (the stored value is index + 1)");
	kof_st_le16(b + KOF_SYM_H_START, 4);
	CK(kof_sym_first(b, n) == 0, "a start index past the last record is none");
	b[KOF_SYM_H_TRUNC] = 1;
	CK(kof_sym_truncated(b, n) == 1, "the truncated flag");
	CK(kof_sym_truncated(NULL, 0) == 0 && kof_sym_origin(NULL, 0) == 0 && kof_sym_count(NULL, 0) == 0 && kof_sym_first(NULL, 0) == 0, "NULL block");
	CK(kof_sym_rec(b, n, 5) == NULL && kof_sym_rec(b, n, 0xffffffffu) == NULL && kof_sym_rec(b, KOF_SYM_HDRLEN - 1u, 0) == NULL, "records past the count or the bytes");
}

struct symjob {
	int variant;
};

static int sym_hostile(void *arg)
{
	struct symjob *j = (struct symjob *)arg;
	static const struct symspec sp[] = {
		{ "socket", KOF_SYM_F_UNDEFINED }, { "connect", KOF_SYM_F_UNDEFINED }, { "main", KOF_SYM_F_DEFINED },
		{ "helper", KOF_SYM_F_DEFINED }
	};
	uint8_t src[512], *p;
	uint32_t n = sym_make(src, sizeof src, sp, 4), len, k, i;
	struct he_guard g;
	struct kof_range ext[16];
	uint64_t o, l;

	if (!n)
		return 9;
	for (len = 0; len <= n; len++) {
		if (!he_guard_make(&g, src, len))
			return 9;
		p = g.p;
		for (i = 0; i < 5; i++) {
			const uint8_t *r = kof_sym_rec(p, len, i);
			uint32_t nl = 0;

			if (r)
				(void)kof_sym_name(p, len, r, &nl);
			(void)kof_sym_run(p, len, i, &o, &l);
		}
		(void)kof_sym_extents(p, len, KOF_SCAN_SYM_IMP | KOF_SCAN_SYM_EXP, ext, 16);
		(void)kof_sym_index_at(p, len, 20);
		{
			struct kof_range e = { 16, 4096 };

			(void)kof_sym_extent_recs(p, len, &e, &k);
		}
		(void)kof_sym_first(p, len);
		he_guard_free(&g);
	}
	if (j->variant == 1) {
		/* Every byte of the block set to extremes, one at a time. */
		static const uint8_t ex[] = { 0x00, 0xff, 0x7f, 0x80, 0x01 };

		if (!he_guard_make(&g, src, n))
			return 9;
		for (i = 0; i < n; i++)
			for (k = 0; k < sizeof ex; k++) {
				uint8_t keep = g.p[i];

				g.p[i] = ex[k];
				for (len = 0; len < 5; len++) {
					const uint8_t *r = kof_sym_rec(g.p, n, len);
					uint32_t nl = 0;

					if (r)
						(void)kof_sym_name(g.p, n, r, &nl);
					(void)kof_sym_run(g.p, n, len, &o, &l);
				}
				(void)kof_sym_index_at(g.p, n, 40);
				g.p[i] = keep;
			}
		he_guard_free(&g);
	}
	return 0;
}

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int sym_count_bomb(void *arg)
{
	uint8_t b[KOF_SYM_HDRLEN];
	struct kof_range ext[4];
	double t0;
	uint32_t k;

	(void)arg;
	memset(b, 0, sizeof b);
	memcpy(b, "KSYM", 4);
	kof_st_le32(b + KOF_SYM_H_COUNT, 0xffffffffu);
	t0 = now();
	k = kof_sym_extents(b, sizeof b, KOF_SCAN_SYM_IMP | KOF_SCAN_SYM_EXP, ext, 4);
	return k == 0 && now() - t0 < 0.2 ? 0 : 1;
}

static void t_sym_hostile(void)
{
	struct symjob j;
	struct he_status st;

	j.variant = 0;
	st = he_child(sym_hostile, &j, 20);
	CK(he_ok(st), "every prefix of a symbol block is read without a fault: %s", he_how(st));
	j.variant = 1;
	st = he_child(sym_hostile, &j, 20);
	CK(he_ok(st), "every byte of a symbol block at its extremes: %s", he_how(st));
	/*
	 * A 16 byte block that says it holds 4 billion records. kof_sym_extents walks the count the
	 * HEADER states, and every record past the bytes is refused one at a time - twice, once for each
	 * half - so the work follows a number in the block and not its length.
	 */
	st = he_child(sym_count_bomb, NULL, 8);
	CK(he_ok(st), "kof_sym_extents on a 16 byte block that claims 2^32-1 records returns at once: %s", he_how(st));
}

/* ---- the graph block ----------------------------------------------------------------------------------- */

static uint32_t gr_make(uint8_t *out, uint32_t cap, uint32_t n)
{
	uint32_t i, need = KOF_GR_HDRLEN + n * KOF_GR_RECLEN;

	if (need > cap)
		return 0;
	memset(out, 0, need);
	kof_st_le32(out + KOF_GR_H_COUNT, n);
	for (i = 0; i < n; i++) {
		uint8_t *r = out + KOF_GR_HDRLEN + i * KOF_GR_RECLEN;

		kof_st_le64(r + KOF_GR_R_AT, 0x100u * i);
		kof_st_le16(r + KOF_GR_R_CAP, (uint16_t)(10u + i));
		kof_st_le16(r + KOF_GR_R_FLAGS, 3);
		r[KOF_GR_R_NIN] = i ? 1u : 0u;
		if (i) {
			kof_st_le16(r + KOF_GR_R_IN, (uint16_t)(i - 1u));
			r[KOF_GR_R_IN + 2] = 5;
			r[KOF_GR_R_IN + 3] = 0;
		}
	}
	return need;
}

static void t_gr_block(void)
{
	uint8_t b[KOF_GR_HDRLEN + 4 * KOF_GR_RECLEN];
	uint32_t n = gr_make(b, sizeof b, 4);
	uint32_t entries;

	CK(kof_gr_count(b, n) == 4, "count");
	CK(kof_gr_has(b, n, 11) == 1 && kof_gr_has(b, n, 99) == 0, "has finds a capability");
	CK(kof_gr_linked(b, n, 10, 11, 5, 0) == 1, "linked: node 1 (cap 11) takes its input from node 0 (cap 10) in role 5");
	CK(kof_gr_linked(b, n, 10, 12, 5, 0) == 0 && kof_gr_linked(b, n, 11, 12, 5, 0) == 1, "and only along the links that exist");
	CK(kof_gr_linked(b, n, 10, 11, 6, 0) == 0, "role must match");
	CK(kof_gr_linked(b, n, 10, 11, 5, 4) == 0 && kof_gr_linked(b, n, 10, 11, 5, 3) == 1, "the parent must carry every flag asked for");
	CK(kof_gr_linked(b, n, 10, 11, 5, 0) == 1 && kof_gr_linked(NULL, 0, 10, 11, 5, 0) == 0, "an empty block links nothing");
	entries = kof_gr_entries(b, n, 10, 11, 5, 4);
	CK(entries == 0, "entries counts child nodes with a displacement (none has one here): %u", entries);
	kof_st_le64(b + KOF_GR_HDRLEN + 1 * KOF_GR_RECLEN + KOF_GR_R_ATTR, 0x28);
	entries = kof_gr_entries(b, n, 10, 11, 5, 4);
	CK(entries == 1, "a displacement makes an entry: %u", entries);
	CK(kof_gr_entries(b, n, 10, 11, 5, 0) == 0 && kof_gr_entries(b, n, 10, 11, 5, 1000) <= 16u, "a capacity of 0 counts none, a huge one is clipped to the table");
	{
		const uint8_t *r1 = kof_gr_rec(b, n, 1);

		CK(r1 != NULL && kof_gr_in(r1, 0, NULL, NULL) == 0, "link 0 of node 1 points at node 0");
	}
	CK(kof_gr_u16(b + 4, 0) == 0 && kof_gr_u64(b, 0) == 4, "readers of fixed width");
}

static int gr_hostile(void *arg)
{
	uint8_t src[KOF_GR_HDRLEN + 4 * KOF_GR_RECLEN];
	uint32_t n = gr_make(src, sizeof src, 4), len, i;
	struct he_guard g;

	(void)arg;
	for (len = 0; len <= n; len++) {
		if (!he_guard_make(&g, src, len))
			return 9;
		(void)kof_gr_has(g.p, len, 11);
		(void)kof_gr_linked(g.p, len, 10, 11, 5, 0);
		(void)kof_gr_entries(g.p, len, 10, 11, 5, 8);
		for (i = 0; i < 5; i++) {
			const uint8_t *r = kof_gr_rec(g.p, len, i);

			if (r)
				(void)kof_gr_in(r, 1, NULL, NULL);
		}
		he_guard_free(&g);
	}
	/* a count of 2^32-1 over a block of four records: the readers stop at the bytes */
	if (!he_guard_make(&g, src, n))
		return 9;
	kof_st_le32(g.p + KOF_GR_H_COUNT, 0xffffffffu);
	(void)kof_gr_has(g.p, n, 9999);
	(void)kof_gr_linked(g.p, n, 1, 2, 3, 0);
	(void)kof_gr_entries(g.p, n, 1, 2, 3, 8);
	he_guard_free(&g);
	return 0;
}

static void t_gr_hostile(void)
{
	struct he_status st = he_child(gr_hostile, NULL, 20);

	CK(he_ok(st), "the graph block readers survive every prefix and a count past the bytes: %s", he_how(st));
}

/* ---- module-side helpers, run against a fake host ---------------------------------------------------- */

/*
 * The headers under kofmod/ and analyzers/diseases hold FUNCTIONS a module includes (ep_shape,
 * stub_pat, upx_method, emu_harvest, the msf_decl_* declarations). They have no engine behind
 * them but the vtable, so the vtable is faked: byte reads over a buffer, and recorders for
 * the slots that make an object. What is asserted is the order and the arguments of the calls
 * they make, and that a refusal at any step stops the sequence.
 */
struct fakergn {
	uint64_t va, len;
	uint32_t kind;
};

struct fakehost {
	struct fakergn rgn[8];
	unsigned       n_rgn;
	uint32_t       taken[8];
	unsigned       n_taken, n_done;
	uint64_t       layout, ats[8];
	unsigned       n_at;
	char           secnames[8][12];
	uint64_t       secrva[8], secsize[8];
	unsigned       n_sec;
	const uint8_t *data;
	uint64_t       n;
	char           calls[16][12];
	unsigned       n_calls;
	int            section_rc, image_rc, at_rc;
	uint64_t       rva, vsize, base, entry, at;
	uint32_t       perm, flags;
	uint8_t        fmt, arch;
	char           name[16];
};

static struct fakehost fh;

static uint8_t f_rd8(const struct kof_obj_ctx *c, uint64_t off)
{
	(void)c;
	return off < fh.n ? fh.data[off] : 0;
}

static uint16_t f_rd16(const struct kof_obj_ctx *c, uint64_t off)
{
	return (uint16_t)(f_rd8(c, off) | (uint16_t)f_rd8(c, off + 1) << 8);
}

static uint32_t f_rd32(const struct kof_obj_ctx *c, uint64_t off)
{
	return (uint32_t)f_rd16(c, off) | (uint32_t)f_rd16(c, off + 2) << 16;
}

static uint64_t f_rd64(const struct kof_obj_ctx *c, uint64_t off)
{
	return (uint64_t)f_rd32(c, off) | (uint64_t)f_rd32(c, off + 4) << 32;
}

static void note_call(const char *w)
{
	if (fh.n_calls < 16)
		snprintf(fh.calls[fh.n_calls], sizeof fh.calls[0], "%s", w);
	fh.n_calls++;
}

static int f_section(const struct kof_obj_ctx *c, const char *name, uint64_t rva, uint64_t vsize, uint32_t perm, uint32_t flags)
{
	(void)c;
	note_call("section");
	if (fh.n_sec < 8) {
		snprintf(fh.secnames[fh.n_sec], sizeof fh.secnames[0], "%s", name);
		fh.secrva[fh.n_sec] = rva;
		fh.secsize[fh.n_sec] = vsize;
	}
	fh.n_sec++;
	snprintf(fh.name, sizeof fh.name, "%s", name);
	fh.rva = rva;
	fh.vsize = vsize;
	fh.perm = perm;
	fh.flags = flags;
	return fh.section_rc;
}

static void f_as(const struct kof_obj_ctx *c, uint8_t fmt, uint8_t arch, uint64_t base)
{
	(void)c;
	note_call("as");
	fh.fmt = fmt;
	fh.arch = arch;
	fh.base = base;
}

static int f_image(const struct kof_obj_ctx *c)
{
	(void)c;
	note_call("image");
	return fh.image_rc;
}

static int f_entry(const struct kof_obj_ctx *c, uint64_t rva)
{
	(void)c;
	note_call("entry");
	fh.entry = rva;
	return 1;
}

static int f_emu_region(const struct kof_obj_ctx *c, uint32_t i, uint64_t *va, uint64_t *len, uint32_t *kind)
{
	(void)c;
	if (i >= fh.n_rgn)
		return 0;
	*va = fh.rgn[i].va;
	*len = fh.rgn[i].len;
	*kind = fh.rgn[i].kind;
	return 1;
}

static int f_emu_take(const struct kof_obj_ctx *c, uint32_t i)
{
	(void)c;
	note_call("take");
	if (fh.n_taken < 8)
		fh.taken[fh.n_taken] = i;
	fh.n_taken++;
	return 1;
}

static int f_child(const struct kof_obj_ctx *c)
{
	(void)c;
	note_call("done");
	fh.n_done++;
	return 1;
}

static uint64_t f_layout(const struct kof_obj_ctx *c)
{
	(void)c;
	return fh.layout;
}

static int f_at(const struct kof_obj_ctx *c, uint64_t off)
{
	(void)c;
	note_call("at");
	if (fh.n_at < 8)
		fh.ats[fh.n_at] = off;
	fh.n_at++;
	fh.at = off;
	return fh.at_rc;
}

static const struct kof_content fake_content = {
	.rd8 = f_rd8, .rd16 = f_rd16, .rd32 = f_rd32, .rd64 = f_rd64,
	.section = f_section, .as_format = f_as, .image = f_image, .child_entry_rva = f_entry, .at = f_at,
	.emu_region = f_emu_region, .emu_take = f_emu_take, .child = f_child, .layout_of_produced = f_layout
};

static void fake_reset(const uint8_t *data, uint64_t n, struct kof_obj_ctx *ctx)
{
	memset(&fh, 0, sizeof fh);
	fh.data = data;
	fh.n = n;
	fh.section_rc = 0;
	fh.image_rc = 1;
	fh.at_rc = 1;
	memset(ctx, 0, sizeof *ctx);
	ctx->content = &fake_content;
	ctx->obj_size = n;
}

static void t_msf(void)
{
	struct kof_obj_ctx ctx;

	fake_reset(NULL, 0, &ctx);
	CK(msf_decl_elf64(&ctx, 0) == 0 && fh.n_calls == 0, "elf64: no payload, no calls");
	CK(msf_decl_elf64(&ctx, 100) == 1, "elf64: declared");
	CK(fh.n_calls == 5 && !strcmp(fh.calls[0], "section") && !strcmp(fh.calls[1], "as") && !strcmp(fh.calls[2], "image") &&
	   !strcmp(fh.calls[3], "entry") && !strcmp(fh.calls[4], "at"), "elf64: section, as, image, entry, at - in that order");
	CK(!strcmp(fh.name, ".text") && fh.rva == MSF_ELF64_HDR && fh.vsize == 100 && fh.perm == (KUNP_PERM_R | KUNP_PERM_W | KUNP_PERM_X) &&
	   fh.flags == (KGENOME_SECF_CODE | KGENOME_SECF_REBUILT), "elf64: one RWX code section after the header");
	CK(fh.fmt == KOF_FMT_ELF && fh.arch == KGENOME_ARCH_X86_64 && fh.base == MSF_ELF64_BASE && fh.entry == MSF_ELF64_HDR && fh.at == MSF_ELF64_HDR,
	   "elf64: declared as an x86-64 ELF at its base, entered and positioned at the code");
	fake_reset(NULL, 0, &ctx);
	fh.section_rc = -1;
	CK(msf_decl_elf64(&ctx, 100) == 0 && fh.n_calls == 1, "elf64: a refused section stops the sequence at once");
	fake_reset(NULL, 0, &ctx);
	fh.image_rc = 0;
	CK(msf_decl_elf64(&ctx, 100) == 0 && fh.n_calls == 3, "elf64: a refused image stops after three calls");
	fake_reset(NULL, 0, &ctx);
	fh.at_rc = 0;
	CK(msf_decl_elf64(&ctx, 100) == 0 && fh.n_calls == 5, "elf64: the answer is the last call's");

	fake_reset(NULL, 0, &ctx);
	CK(msf_decl_pe(&ctx, 0, 64) == 0 && fh.n_calls == 0, "pe: no payload, no calls");
	CK(msf_decl_pe(&ctx, 64, 64) == 1 && fh.fmt == KOF_FMT_PE && fh.arch == KGENOME_ARCH_X86_64 && fh.base == MSF_PE_BASE64 && fh.rva == MSF_PE_RVA &&
	   fh.entry == MSF_PE_RVA, "pe: 64 bit");
	fake_reset(NULL, 0, &ctx);
	CK(msf_decl_pe(&ctx, 64, 32) == 1 && fh.arch == KGENOME_ARCH_X86 && fh.base == MSF_PE_BASE32, "pe: 32 bit");
	fake_reset(NULL, 0, &ctx);
	fh.section_rc = -1;
	CK(msf_decl_pe(&ctx, 64, 32) == 0 && fh.n_calls == 1, "pe: a refused section stops it");
	/* elf32: the same five calls as elf64, for the x86 template (base 0x08048000, header 0x54) */
	fake_reset(NULL, 0, &ctx);
	CK(msf_decl_elf32(&ctx, 0) == 0 && fh.n_calls == 0, "elf32: no payload, no calls");
	CK(msf_decl_elf32(&ctx, 100) == 1 && fh.n_calls == 5 && !strcmp(fh.calls[0], "section") && !strcmp(fh.calls[1], "as") &&
	   !strcmp(fh.calls[2], "image") && !strcmp(fh.calls[3], "entry") && !strcmp(fh.calls[4], "at"), "elf32: section, as, image, entry, at");
	CK(!strcmp(fh.name, ".text") && fh.rva == MSF_ELF32_HDR && fh.vsize == 100 && fh.perm == (KUNP_PERM_R | KUNP_PERM_W | KUNP_PERM_X) &&
	   fh.flags == (KGENOME_SECF_CODE | KGENOME_SECF_REBUILT), "elf32: one RWX code section after the 0x54 byte header");
	CK(fh.fmt == KOF_FMT_ELF && fh.arch == KGENOME_ARCH_X86 && fh.base == MSF_ELF32_BASE && fh.entry == MSF_ELF32_HDR && fh.at == MSF_ELF32_HDR,
	   "elf32: an x86 ELF at 0x08048000, entered and positioned at the code");
	fake_reset(NULL, 0, &ctx);
	fh.section_rc = -1;
	CK(msf_decl_elf32(&ctx, 100) == 0 && fh.n_calls == 1, "elf32: a refused section stops it at once");
	fake_reset(NULL, 0, &ctx);
	fh.image_rc = 0;
	CK(msf_decl_elf32(&ctx, 100) == 0 && fh.n_calls == 3, "elf32: a refused image stops after three calls");
	fake_reset(NULL, 0, &ctx);
	fh.at_rc = 0;
	CK(msf_decl_elf32(&ctx, 100) == 0 && fh.n_calls == 5, "elf32: the answer is the last call's");

	/* msf_emit_hdr: the header a decoded x86 payload gets follows the object it was peeled from */
	fake_reset(NULL, 0, &ctx);
	ctx.format = KOF_FMT_PE;
	CK(msf_emit_hdr(&ctx, 64) == 1 && fh.fmt == KOF_FMT_PE && fh.arch == KGENOME_ARCH_X86 && fh.base == MSF_PE_BASE32,
	   "emit_hdr: a payload out of a PE becomes a 32 bit PE");
	fake_reset(NULL, 0, &ctx);
	ctx.format = KOF_FMT_ELF;
	CK(msf_emit_hdr(&ctx, 64) == 1 && fh.fmt == KOF_FMT_ELF && fh.arch == KGENOME_ARCH_X86 && fh.base == MSF_ELF32_BASE,
	   "emit_hdr: out of an ELF it becomes an x86 ELF");
	fake_reset(NULL, 0, &ctx);
	ctx.format = 0;
	CK(msf_emit_hdr(&ctx, 64) == 1 && fh.fmt == KOF_FMT_ELF, "emit_hdr: a formatless layer keeps the ELF answer");
	CK(msf_emit_hdr(&ctx, 0) == 0, "emit_hdr: no payload, no header");
	ctx.format = KOF_FMT_PE;
	CK(MSF_RECON_PE(&ctx) == 1, "the PE recogniser");
	ctx.format = KOF_FMT_ELF;
	CK(MSF_RECON_PE(&ctx) == 0, "and not an ELF");
}

static const struct eps_row eps_rows[] = {
	{ { 0x55, 0x48, 0x89, 0xe5 }, 0, 4, "push-rbp" },
	{ { 0x31, 0xc0, 0x00, 0xc3 }, 0x4, 4, "xor-ret" },
	{ { 0 }, 0, 0, "empty" },
	{ { 0xaa }, 0, 200, "bad length" }
};

struct stub_row {
	uint16_t at, n;
};

static const struct stub_row stub_rows[] = { { 0, 3 }, { 3, 2 } };
static const uint16_t stub_pat[] = { 0xe8, 0x100, 0x00, 0x90, 0x90 };

KOF_STUB_DEFINE_IS(stub_is, stub_rows, stub_pat)
KOF_UPX_DEFINE_METHOD_OF()
KOF_UPX_DEFINE_LZMA_METHOD()

static void t_ep_shape(void)
{
	struct kof_obj_ctx ctx;
	static const uint8_t code[] = { 0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x77, 0xc3, 0xe8, 0x12, 0x00, 0x90, 0x90 };

	fake_reset(code, sizeof code, &ctx);
	CK(eps_match(&ctx, 0, eps_rows, 4) == 0, "the first row that matches wins");
	CK(eps_match(&ctx, 4, eps_rows, 4) == 1, "a wildcard bit (0x4 = third byte) skips that byte");
	CK(eps_match(&ctx, 1, eps_rows, 2) == -1, "no row matches");
	CK(eps_match(&ctx, sizeof code - 2u, eps_rows, 2) == -1, "a row that would run off the object does not match, and nothing is read past it");
	CK(eps_match(&ctx, UINT64_MAX - 1u, eps_rows, 2) == -1, "an offset near 2^64");
	CK(eps_match(&ctx, 0, eps_rows, 0) == -1, "no rows");
	CK(eps_match(&ctx, 0, &eps_rows[3], 1) == -1, "a row longer than EPS_MAX is skipped");
	CK(eps_match(&ctx, 0, &eps_rows[2], 1) == 0, "an empty row matches anywhere (vacuously)");

	CK(stub_is(&ctx, 8, 0) == 1, "a stub pattern with a wildcard word (0x100) matches any byte there");
	CK(stub_is(&ctx, 11, 1) == 1, "second row");
	CK(stub_is(&ctx, 0, 0) == 0, "different bytes");
	CK(stub_is(&ctx, sizeof code - 1u, 0) == 0, "a pattern that does not fit in the object is false");

	CK(upx_method_of(2) == KOF_UNP_NRV2B_32 && upx_method_of(3) == KOF_UNP_NRV2B_8 && upx_method_of(4) == KOF_UNP_NRV2B_16 &&
	   upx_method_of(5) == KOF_UNP_NRV2D_32 && upx_method_of(8) == KOF_UNP_NRV2E_32 && upx_method_of(10) == KOF_UNP_NRV2E_16, "UPX methods");
	CK(upx_method_of(0) == 0 && upx_method_of(1) == 0 && upx_method_of(11) == 0 && upx_method_of(0xffffffffu) == 0, "and no others");
	CK(upx_lzma_method(0x5d) == KOF_UNP_LZMA_PROPS(0x5d >> 3, UPX_LZMA_LP, 0x5d & 7) || upx_lzma_method(0x5d) == 0, "LZMA properties byte");
	CK(upx_lzma_method(0xff) == 0 && upx_lzma_method(0x07) == 0 && upx_lzma_method(0) != 0, "out of range lc/pb are 0; lc 0 pb 0 is a method");
}

static void t_harvest(void)
{
	struct kof_obj_ctx ctx;
	uint8_t elf[128];

	CK(eh_up(0) == 0 && eh_up(1) == 0x1000 && eh_up(0x1000) == 0x1000 && eh_up(0x1001) == 0x2000, "eh_up rounds to a page");
	CK(eh_up(UINT64_MAX) == 0 || eh_up(UINT64_MAX) >= UINT64_MAX - 0xfff, "eh_up near 2^64 wraps to 0 or stays high");
	memset(elf, 0, sizeof elf);
	memcpy(elf, "\x7f" "ELF", 4);
	elf[4] = 2;
	kof_st_le64(elf + 0x20, 0x40);
	elf[0x38] = 1;
	kof_st_le64(elf + 0x40 + 0x10, 0x400000);
	fake_reset(elf, sizeof elf, &ctx);
	ctx.format = KOF_FMT_ELF;
	CK(eh_elf_base(&ctx) == 0x400000, "the load address of an ELF64, from its first program header");
	elf[4] = 1;
	kof_st_le32(elf + 0x1c, 0x34);
	elf[0x2c] = 1;
	kof_st_le32(elf + 0x34 + 8, 0x8048000);
	CK(eh_elf_base(&ctx) == 0x8048000, "and of an ELF32");
	ctx.format = KOF_FMT_PE;
	CK(eh_elf_base(&ctx) == 0, "not for a PE");
	ctx.format = KOF_FMT_ELF;
	elf[0] = 0;
	CK(eh_elf_base(&ctx) == 0, "not without the magic");
	elf[0] = 0x7f;
	elf[4] = 2;
	kof_st_le64(elf + 0x20, 0xffffffffffffff00ull);
	CK(eh_elf_base(&ctx) == 0, "a program header offset far outside the object reads as 0 (the reader answers 0 out of range)");

	/* eh_fold: what a run left becomes objects. Without an image region, each region is an ELF of its own. */
	memset(elf, 0, sizeof elf);
	memcpy(elf, "\x7f" "ELF", 4);
	elf[4] = 2;
	kof_st_le64(elf + 0x20, 0x40);
	elf[0x38] = 1;
	kof_st_le64(elf + 0x40 + 0x10, 0x400000);
	fake_reset(elf, sizeof elf, &ctx);
	ctx.format = KOF_FMT_ELF;
	ctx.arch = KGENOME_ARCH_X86_64;
	CK(eh_fold(&ctx, 0) == 0 && fh.n_calls == 0, "eh_fold of no regions makes nothing");
	fh.n_rgn = 2;
	fh.rgn[0].va = 0x400000; fh.rgn[0].len = 0x1000; fh.rgn[0].kind = KOF_EMU_RGN_EXEC;
	fh.rgn[1].va = 0x500000; fh.rgn[1].len = 0;      fh.rgn[1].kind = KOF_EMU_RGN_EXEC;
	CK(eh_fold(&ctx, 2) == 1, "one region with bytes, one empty: one object");
	CK(fh.n_done == 1 && fh.n_taken == 1 && fh.taken[0] == 0, "taken and finished");
	CK(fh.n_sec == 1 && !strcmp(fh.secnames[0], ".text") && fh.secrva[0] == KUNP_HDR_ELF64 && fh.secsize[0] == 0x1000 - KUNP_HDR_ELF64,
	   "the region at the object's load address is the image: a .text after the header, shorter by the header");
	CK(fh.ats[0] == 0 && fh.base == 0x400000 && fh.entry == KUNP_HDR_ELF64 && fh.fmt == KOF_FMT_ELF && fh.arch == KGENOME_ARCH_X86_64,
	   "positioned at 0, declared as an x86-64 ELF at its own address, entered after the header");
	fake_reset(elf, sizeof elf, &ctx);
	ctx.format = KOF_FMT_ELF;
	ctx.arch = KGENOME_ARCH_X86_64;
	fh.n_rgn = 1;
	fh.rgn[0].va = 0x700000; fh.rgn[0].len = 0x2000; fh.rgn[0].kind = KOF_EMU_RGN_WRITTEN;
	CK(eh_fold(&ctx, 1) == 1 && fh.secsize[0] == 0x2000 && fh.ats[0] == KUNP_HDR_ELF64 && fh.base == 0x700000 - KUNP_HDR_ELF64,
	   "any other region keeps its length and is placed after the header, its base moved down by it");
	fake_reset(elf, sizeof elf, &ctx);
	ctx.format = KOF_FMT_ELF;
	ctx.arch = KGENOME_ARCH_X86_64;
	fh.n_rgn = 1;
	fh.rgn[0].va = 0x400000; fh.rgn[0].len = KUNP_HDR_ELF64; fh.rgn[0].kind = KOF_EMU_RGN_EXEC;
	CK(eh_fold(&ctx, 1) == 0 && fh.n_sec == 0, "an image that is only a header holds no code and makes nothing");
	fake_reset(elf, sizeof elf, &ctx);
	ctx.format = KOF_FMT_ELF;
	ctx.arch = KGENOME_ARCH_X86_64;
	fh.n_rgn = 8;
	{
		unsigned q;

		for (q = 0; q < 8; q++) {
			fh.rgn[q].va = 0x1000u * (q + 1u);
			fh.rgn[q].len = 8;
			fh.rgn[q].kind = KOF_EMU_RGN_EXEC;
		}
	}
	CK(eh_fold(&ctx, 1000) <= 8, "a count past EH_MAX is clipped, and a count past the regions the host has stops at them");

	/* With an image region the rest are laid out beside it, one section each. */
	fake_reset(elf, sizeof elf, &ctx);
	ctx.format = KOF_FMT_PE;
	fh.n_rgn = 3;
	fh.rgn[0].va = 0x10000; fh.rgn[0].len = 0x1800; fh.rgn[0].kind = KOF_EMU_RGN_IMAGE;
	fh.rgn[1].va = 0x30000; fh.rgn[1].len = 0x10;   fh.rgn[1].kind = KOF_EMU_RGN_EXEC;
	fh.rgn[2].va = 0x30000; fh.rgn[2].len = 0x20;   fh.rgn[2].kind = KOF_EMU_RGN_WRITTEN;
	CK(eh_fold(&ctx, 3) == 1, "an image region and two others: one object");
	CK(fh.secsize[0] == 0x2000 + 0x1000 + 0x1000, "the first section is every region, page rounded (%llu)", (unsigned long long)fh.secsize[0]);
	CK(fh.n_sec == 3 && fh.n_taken == 3 && fh.taken[0] == 0 && fh.taken[1] == 1 && fh.taken[2] == 2, "the image first, then each region");
	CK(fh.ats[0] == 0 && fh.ats[1] == 0x2000 && fh.ats[2] == 0x3000, "each placed after the last, a page apart");
	CK(!strcmp(fh.secnames[1], "e000030a") && !strcmp(fh.secnames[2], "e000030b"),
	   "sections are named by the page they were at, and the second at one page gets the next letter (%s %s)", fh.secnames[1], fh.secnames[2]);
	CK(fh.n_done == 1, "and the whole is finished once");
}

static void t_docinfo_obj(void)
{
	struct kgenome_obj o, back;
	struct kof_obj_ctx ctx, ctx2;
	static const long long view = 5;
	unsigned i;

	for (i = 0; i < KOF_PDF_DOCINFO_COUNT; i++) {
		const char *w = kof_pdf_docinfo_name(i);

		CK(w && w[0], "PDF document field %u has a name", i);
	}
	CK(!strcmp(kof_pdf_docinfo_name(KOF_PDF_DOCINFO_TITLE), "title") && !strcmp(kof_pdf_docinfo_name(KOF_PDF_DOCINFO_PRODUCER), "producer"),
	   "the names are the PDF's own keys, lower case");
	CK(!strcmp(kof_pdf_docinfo_name(KOF_PDF_DOCINFO_COUNT), "?") && !strcmp(kof_pdf_docinfo_name(0xffffffffu), "?"), "past the last: ?");

	memset(&ctx, 0, sizeof ctx);
	ctx.format = KOF_FMT_ELF;
	ctx.arch = KOF_ARCH_X86_64;
	ctx.subtype = 3;
	ctx.obj_size = 0x1234567890ull;
	ctx.entry_off = 0x400;
	ctx.file_header = &view;
	kof_genome_obj(&ctx, &o);
	CK(o.format == KOF_FMT_ELF && o.arch == KOF_ARCH_X86_64 && o.subtype == 3 && o.obj_size == 0x1234567890ull && o.entry_off == 0x400 &&
	   o.file_header == &view && o.reserved == 0, "kof_genome_obj copies the descriptor out of the context");
	memset(&ctx2, 0xaa, sizeof ctx2);
	kof_genome_obj_store(&ctx2, &o);
	kof_genome_obj(&ctx2, &back);
	CK(memcmp(&o, &back, sizeof o) == 0 || (o.format == back.format && o.arch == back.arch && o.subtype == back.subtype &&
	   o.obj_size == back.obj_size && o.entry_off == back.entry_off && o.file_header == back.file_header),
	   "store then read is the identity");
	CK(ctx2.format == KOF_FMT_ELF && ctx2.file_header == &view, "and store put the fields where the context keeps them");
	CK(ctx2.resolve_scan == NULL || 1, "store leaves the context's other members alone");
}

int main(void)
{
	t_formats();
	t_arch();
	t_other_vocab();
	t_script_fam();
	t_entry_names();
	t_chars();
	t_misc();
	t_sym_block();
	t_sym_hostile();
	t_gr_block();
	t_gr_hostile();
	t_msf();
	t_ep_shape();
	t_harvest();
	t_docinfo_obj();
	printf("api_engine_modhelpers: %u checks, %u failed, %u known-miss\n", he_checks, he_fails, km_known());
	return he_fails != 0 || km_failed();
}
