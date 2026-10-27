/*
 * kx_inspect - the API of kofexamine/kofinspect*.c that needs no terminal and no file: the vocabulary tables, the PDF text
 * line, hex respacing, the region label, identify / declare over valid, truncated and corrupt objects, the region map, where
 * a marker is (kof_locate_str), the event and what-built-it describers, the region entropy.
 *
 * Writing an object out (kof_dump_*) and the paths it meets is tests/unit/kx_dump.c.
 *
 * Group by FUNCTION: each function below is one suite of data rows. Every row states the CORRECT behaviour; a defect the
 * suite knows is a KM_CHECK (known_miss.h: green while it is there, red the day it is fixed) carrying its id:
 *   EX-1  kof_inspect_identify returns NULL when a sniff accepted and the parse refused (the engine tries the next row)
 *   EX-2  kof_inspect_findings is declared in kofinspect.h and defined nowhere
 *   EX-3  kof_hex_respace drops the tail of the pattern when the room is exactly what its own guard asks for
 *   EX-4  kof_pdf_text shows the low byte of a UTF-16BE character whose high byte is not zero
 * Old tests that touch this API: tests/unit/codec_forms.c (codec_ui and the string forms through kofinspect.c), the TUI tests
 * through the viewer (BUG-n rows); none called these functions directly.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../kofexamine/kofinspect_private.h"
#include "../lib/ctr_writers.h"
#include "../lib/genome/hk.h"
#include "known_miss.h"

static int fails, checks;

#undef CK
#define CK(cond) do { checks++; if (!(cond)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)
#define CKS(a, b) do { const char *a_ = (a), *b_ = (b); checks++; \
	if (!(a_ ? (b_ && !strcmp(a_, b_)) : !b_)) { \
		printf("  FAIL %s:%d  %s -> \"%s\" wanted \"%s\"\n", __FILE__, __LINE__, #a, a_ ? a_ : "(null)", b_ ? b_ : "(null)"); \
		fails++; } } while (0)

/* ------------------------------------------------------------------------- the vocabulary tables */

static void names_suite(void)
{
	static const struct { uint32_t v; const char *n; } pt[] = {
		{0, "PT_NULL"}, {1, "PT_LOAD"}, {2, "PT_DYNAMIC"}, {3, "PT_INTERP"}, {4, "PT_NOTE"}, {5, "PT_SHLIB"},
		{6, "PT_PHDR"}, {7, "PT_TLS"}, {0x6474e550u, "PT_GNU_EH_FRAME"}, {0x6474e551u, "PT_GNU_STACK"},
		{0x6474e552u, "PT_GNU_RELRO"}, {0x6474e553u, "PT_GNU_PROPERTY"}, {0x65a3dbe6u, "PT_OPENBSD_RANDOMIZE"} };
	static const struct { uint32_t v; const char *n; } sh[] = {
		{0, "SHT_NULL"}, {1, "SHT_PROGBITS"}, {2, "SHT_SYMTAB"}, {3, "SHT_STRTAB"}, {4, "SHT_RELA"}, {5, "SHT_HASH"},
		{6, "SHT_DYNAMIC"}, {7, "SHT_NOTE"}, {8, "SHT_NOBITS"}, {9, "SHT_REL"}, {10, "SHT_SHLIB"}, {11, "SHT_DYNSYM"},
		{14, "SHT_INIT_ARRAY"}, {15, "SHT_FINI_ARRAY"}, {16, "SHT_PREINIT_ARRAY"}, {17, "SHT_GROUP"},
		{18, "SHT_SYMTAB_SHNDX"}, {0x6ffffff6u, "SHT_GNU_HASH"}, {0x6ffffffdu, "SHT_GNU_VERDEF"},
		{0x6ffffffeu, "SHT_GNU_VERNEED"}, {0x6fffffffu, "SHT_GNU_VERSYM"} };
	uint32_t v, k, i;
	static const uint32_t centres[] = { 0, 0x6474e550u, 0x65a3dbe6u, 0x6ffffff6u, 0x70000000u, 0xfffffff0u };

	/* every value in a window round each named one: named exactly where the table says, NULL (not "?") elsewhere */
	for (k = 0; k < sizeof centres / sizeof centres[0]; k++)
		for (v = centres[k] - (centres[k] ? 12u : 0u); v != centres[k] + 40u; v++) {
			const char *want = NULL, *want2 = NULL;

			for (i = 0; i < sizeof pt / sizeof pt[0]; i++)
				if (pt[i].v == v)
					want = pt[i].n;
			for (i = 0; i < sizeof sh / sizeof sh[0]; i++)
				if (sh[i].v == v)
					want2 = sh[i].n;
			CKS(kof_inspect_ptype_name(v), want);
			CKS(kof_inspect_shtype_name(v), want2);
		}
	CKS(kof_inspect_ptype_name(0xffffffffu), NULL);
	CKS(kof_inspect_shtype_name(0xffffffffu), NULL);

	/* subtype names, per format */
	CKS(kof_inspect_subtype_name(KOF_FMT_ELF, KGENOME_ELF_NONE), "ET_NONE");
	CKS(kof_inspect_subtype_name(KOF_FMT_ELF, KGENOME_ELF_REL), "ET_REL");
	CKS(kof_inspect_subtype_name(KOF_FMT_ELF, KGENOME_ELF_EXEC), "ET_EXEC");
	CKS(kof_inspect_subtype_name(KOF_FMT_ELF, KGENOME_ELF_DYN), "ET_DYN");
	CKS(kof_inspect_subtype_name(KOF_FMT_ELF, KGENOME_ELF_CORE), "ET_CORE");
	CKS(kof_inspect_subtype_name(KOF_FMT_ELF, 200), "ET_?");
	CKS(kof_inspect_subtype_name(KOF_FMT_PE, KGENOME_PE_EXE), "EXE");
	CKS(kof_inspect_subtype_name(KOF_FMT_PE, KGENOME_PE_DLL), "DLL");
	CKS(kof_inspect_subtype_name(KOF_FMT_PE, KGENOME_PE_SYS), "SYS");
	CKS(kof_inspect_subtype_name(KOF_FMT_PE, 250), "?");
	CKS(kof_inspect_subtype_name(KOF_EVT_AMSI, KOF_AMSI_IMAGE), "image");
	CKS(kof_inspect_subtype_name(KOF_EVT_AMSI, KOF_AMSI_COMMAND), "command");
	CKS(kof_inspect_subtype_name(KOF_EVT_AMSI, 99), NULL);
	CKS(kof_inspect_subtype_name(KOF_EVT_PROC, KOF_PROC_OS_WINDOWS), "windows");
	CKS(kof_inspect_subtype_name(KOF_EVT_PROC, KOF_PROC_OS_LINUX), "linux");
	CKS(kof_inspect_subtype_name(KOF_EVT_PROC, KOF_PROC_OS_MACOS), "macos");
	CKS(kof_inspect_subtype_name(KOF_EVT_PROC, 99), NULL);
	CKS(kof_inspect_subtype_name(KOF_FMT_SCRIPT, KOF_SCRIPT_ANY), NULL);
	for (v = 0; v < 256; v++) {
		if (v != KOF_SCRIPT_ANY)
			CKS(kof_inspect_subtype_name(KOF_FMT_SCRIPT, (uint8_t)v), kof_script_type_name((uint8_t)v));
		/* a format with no subtype vocabulary answers NULL for every value */
		CKS(kof_inspect_subtype_name(KOF_FMT_UNKNOWN, (uint8_t)v), NULL);
	}

	/* the symbol block's words */
	CKS(kof_sym_type_name(KOF_STT_NOTYPE), "NOTYPE");
	CKS(kof_sym_type_name(KOF_STT_OBJECT), "OBJECT");
	CKS(kof_sym_type_name(KOF_STT_FUNC), "FUNC");
	CKS(kof_sym_type_name(KOF_STT_SECTION), "SECTION");
	CKS(kof_sym_type_name(KOF_STT_FILE), "FILE");
	CKS(kof_sym_type_name(KOF_STT_COMMON), "COMMON");
	CKS(kof_sym_type_name(KOF_STT_TLS), "TLS");
	CKS(kof_sym_type_name(KOF_STT_GNU_IFUNC), "GNU_IFUNC");
	CKS(kof_sym_type_name(0x7f), "?");
	CKS(kof_sym_bind_name(KOF_STB_LOCAL), "LOCAL");
	CKS(kof_sym_bind_name(KOF_STB_GLOBAL), "GLOBAL");
	CKS(kof_sym_bind_name(KOF_STB_WEAK), "WEAK");
	CKS(kof_sym_bind_name(KOF_STB_GNU_UNIQUE), "GNU_UNIQ");
	CKS(kof_sym_bind_name(0x77), "?");
	CKS(kof_sym_vis_name(KOF_STV_DEFAULT), "DEFAULT");
	CKS(kof_sym_vis_name(KOF_STV_INTERNAL), "INTERNAL");
	CKS(kof_sym_vis_name(KOF_STV_HIDDEN), "HIDDEN");
	CKS(kof_sym_vis_name(KOF_STV_PROTECTED), "PROTECTED");
	CKS(kof_sym_vis_name(0x55), "?");
	{
		uint8_t blk[KOF_SYM_HDRLEN];

		memset(blk, 0, sizeof blk);
		CKS(kof_sym_origin_name(NULL, 99), "none");
		CKS(kof_sym_origin_name(blk, KOF_SYM_HDRLEN - 1u), "none");
		for (v = 0; v < 8; v++) {
			static const char *const w[] = { "none", ".symtab", ".dynsym", "imports+exports", "imports+exports+resolved" };

			blk[KOF_SYM_H_ORIGIN] = (uint8_t)v;
			CKS(kof_sym_origin_name(blk, KOF_SYM_HDRLEN), v < 5 ? w[v] : "none");
			/* a block shorter than the header never reads the origin byte whatever it holds */
			CKS(kof_sym_origin_name(blk, KOF_SYM_H_ORIGIN), "none");
		}
	}
}

/* ------------------------------------------------------------------------------ kof_region_label */

static void label_suite(void)
{
	static const struct { const char *in, *out; } r[] = {
		{ "KOF_SCAN_ELF_CODE", "CODE" }, { "KOF_SCAN_ALL", "ALL" }, { "KOF_SCAN_SYM_IMP", "IMP" },
		{ "KOF_SCAN_PDF_CONTENT_METADATA", "CONTENT_METADATA" }, { "KOF_SCAN_EMBEDDED", "EMBEDDED" },
		{ "A_B", "A_B" }, { "A_B_C", "C" }, { "A_B_C_D", "D" }, { "ABC", "ABC" }, { "", "" }, { "_", "_" },
		{ "__", "" }, { "___", "" }, { "_a_b_c", "c" }, { "KOF__X", "X" } };
	unsigned i;

	for (i = 0; i < sizeof r / sizeof r[0]; i++)
		CKS(kof_region_label(r[i].in), r[i].out);
	CKS(kof_region_label(NULL), "?");
	/* the answer is always a suffix of the input: never a copy, never past its end */
	for (i = 0; i < sizeof r / sizeof r[0]; i++) {
		const char *a = kof_region_label(r[i].in);

		CK(a >= r[i].in && a <= r[i].in + strlen(r[i].in));
	}
}

/* --------------------------------------------------------------------------------- kof_hex_respace */

static void respace_suite(void)
{
	static const char alpha[] = { '0', 'a', 'F', ' ', '\t', 'g' };
	static const size_t caps[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 16, 40 };
	char in[8], out[64], canary[64];
	unsigned len, ci, shown = 0;
	unsigned long total = 0, tail_lost = 0;

	for (len = 0; len <= 6; len++) {
		unsigned long count = 1, c;
		unsigned i;

		for (i = 0; i < len; i++)
			count *= sizeof alpha;
		for (c = 0; c < count; c++) {
			unsigned long t = c;
			char digits[8], spaced[16];
			unsigned nd = 0, ns = 0, bad = 0;

			for (i = 0; i < len; i++) {
				in[i] = alpha[t % sizeof alpha];
				t /= sizeof alpha;
				if (in[i] == 'g')
					bad = 1;
				else if (in[i] != ' ' && in[i] != '\t')
					digits[nd++] = in[i];
			}
			in[len] = 0;
			for (i = 0; i < nd; i++) {
				if (i && i % 2 == 0)
					spaced[ns++] = ' ';
				spaced[ns++] = digits[i];
			}
			spaced[ns] = 0;
			for (ci = 0; ci < sizeof caps / sizeof caps[0]; ci++) {
				size_t cap = caps[ci];
				char want_orig[64];
				int is_orig, is_spaced;

				memset(out, 0x7e, sizeof out);
				memset(canary, 0x7e, sizeof canary);
				kof_hex_respace(in, out, cap);
				total++;
				/* never a byte past `cap` */
				CK(!memcmp(out + cap, canary + cap, sizeof out - cap));
				/* always terminated inside the room */
				CK(memchr(out, 0, cap) != NULL);
				snprintf(want_orig, cap, "%s", in);
				is_orig = !strcmp(out, want_orig);
				is_spaced = !bad && !strcmp(out, spaced);
				/* non-hex text is always copied as it is */
				if (bad) {
					CK(is_orig);
					continue;
				}
				/* either the whole respaced text or the input as it was: nothing in between */
				if (!is_orig && !is_spaced) {
					tail_lost++;
					if (shown++ < 3)
						printf("  note: respace(\"%s\", cap %zu) = \"%s\" (pairs \"%s\")\n", in, cap, out, spaced);
				}
			}
		}
	}
	CK(total > 2000);
	/* EX-3 (2026-10-27, M) [sev L]: kof_hex_respace("ab", out, 5) writes "a": its guard (n/2+2 <= cap-n) admits cap 5 for
	 * two digits, and the copy loop's own bound (n+4 < cap) stops one byte earlier. Trigger: a pattern whose spaced length
	 * is cap-3 or cap-2. Effect: the tail of a hex pattern is dropped from a row, the very loss the comment rules out.
	 * Reproducer: this row. Fix: bound the loop by cap - 1. */
	KM_CHECK(tail_lost == 0, "kof_hex_respace returned neither the respaced pairs nor the input (the tail was cut)", "EX-3");
	{
		char o[8];

		kof_hex_respace("abcd", o, 5);
		CK(o[0] != 0);
	}
	CKS((kof_hex_respace("aabbcc", out, 64), out), "aa bb cc");
	CKS((kof_hex_respace("a a b b", out, 64), out), "aa bb");
	CKS((kof_hex_respace("", out, 64), out), "");
	CKS((kof_hex_respace("zz", out, 64), out), "zz");
	CKS((kof_hex_respace("aabbcc", out, 3), out), "aa");   /* does not fit: the input, cut by the room */
}

/* ----------------------------------------------------------------------------------- kof_pdf_text */

/* The oracle: the rules of the comment in kofinspect.c with the buffer handled as a plain growing array. */
static uint32_t pdf_oracle(const uint8_t *p, uint64_t n, int hex, char *out, uint32_t cap)
{
	uint8_t b[512];
	unsigned have = 0;
	uint64_t i;
	uint32_t w = 0;
	int wide = 0, hi = -1;

	if (!cap)
		return 0;
	out[0] = 0;
	if (hex) {
		for (i = 0; i < n && have < 512; i++) {
			int v = p[i] >= '0' && p[i] <= '9' ? p[i] - '0' : p[i] >= 'a' && p[i] <= 'f' ? p[i] - 'a' + 10
			      : p[i] >= 'A' && p[i] <= 'F' ? p[i] - 'A' + 10 : -1;

			if (v < 0)
				continue;
			if (hi < 0)
				hi = v;
			else {
				b[have++] = (uint8_t)(hi * 16 + v);
				hi = -1;
			}
		}
		if (hi >= 0 && have < 512)
			b[have++] = (uint8_t)(hi * 16);
	} else {
		for (i = 0; i < n && have < 512; i++) {
			if (p[i] == '\\' && i + 1 < n) {
				i++;
				b[have++] = p[i] == 'n' ? '\n' : p[i] == 'r' ? '\r' : p[i] == 't' ? '\t' : p[i] == 'b' ? '\b'
					  : p[i] == 'f' ? '\f' : p[i];
			} else
				b[have++] = p[i];
		}
	}
	wide = have >= 2 && b[0] == 0xfe && b[1] == 0xff;
	for (i = wide ? 3 : 0; i < have && w + 1 < cap; i += wide ? 2 : 1)
		out[w++] = b[i] >= 0x20 && b[i] < 0x7f ? (char)b[i] : '.';
	out[w] = 0;
	return w;
}

static void pdf_suite(void)
{
	static const uint8_t alpha[] = { 'A', 'n', '\\', '0', 'f', 'F', ' ', 0x00, 0xfe, 0xff, '(' };
	uint8_t in[6];
	char got[48], want[48];
	unsigned len, hex, i;
	unsigned long total = 0;
	uint32_t caps[] = { 1, 2, 4, 40 }, ci;

	/* every string of up to five bytes over an eleven-byte alphabet (escape, hex digits, blank, NUL, the BOM bytes), both
	 * modes, four room sizes, against the oracle */
	for (hex = 0; hex < 2; hex++)
		for (len = 0; len <= 5; len++) {
			unsigned long count = 1, c;

			for (i = 0; i < len; i++)
				count *= sizeof alpha;
			for (c = 0; c < count; c++) {
				unsigned long t = c;

				for (i = 0; i < len; i++) {
					in[i] = alpha[t % sizeof alpha];
					t /= sizeof alpha;
				}
				for (ci = 0; ci < 4; ci++) {
					uint32_t r, w;

					memset(got, 0x7e, sizeof got);
					memset(want, 0x7e, sizeof want);
					r = kof_pdf_text(in, len, (int)hex, got, caps[ci]);
					w = pdf_oracle(in, len, (int)hex, want, caps[ci]);
					total++;
					if (r != w || strcmp(got, want) || got[caps[ci]] != 0x7e)
						if (fails < 6) {
							printf("  FAIL pdf_text hex=%u len=%u cap=%u: got %u \"%s\" oracle %u \"%s\"\n", hex, len,
							       caps[ci], r, got, w, want);
							fails++;
						}
					CK(r == strlen(got));
				}
			}
		}
	CK(total > 300000ul);
	CK(kof_pdf_text(in, 3, 0, NULL, 10) == 0);
	CK(kof_pdf_text(NULL, 3, 0, got, 10) == 0 && got[0] == 0);
	CK(kof_pdf_text(in, 0, 0, got, 10) == 0 && got[0] == 0);
	CK(kof_pdf_text(in, 3, 0, got, 0) == 0);

	/* EX-4 (2026-10-27, M) [sev L]: a UTF-16BE title is shown by its LOW bytes, so U+0141 and U+4141 both read "A".
	 * Trigger: /Title <FEFF01410142>. Effect: a document whose title is not ASCII shows an ASCII title in the Properties
	 * row. Fix: show '.' (or the code point) for a unit whose high byte is not zero. */
	{
		static const uint8_t t[] = { 0xfe, 0xff, 0x01, 0x41, 0x41, 0x42, 0x00, 0x43 };

		kof_pdf_text(t, sizeof t, 0, got, sizeof got);
		KM_CHECK(got[0] != 'A', "UTF-16BE units with a non-zero high byte are shown as their low byte", "EX-4");
	}
	/* one megabyte: bounded by the 512-byte work buffer, terminated, no more than the room */
	{
		uint8_t *big = malloc(1u << 20);
		char line[100];
		uint32_t r;

		CK(big != NULL);
		if (big) {
			memset(big, 'x', 1u << 20);
			r = kof_pdf_text(big, 1u << 20, 0, line, sizeof line);
			CK(r == sizeof line - 1u && strlen(line) == r);
			r = kof_pdf_text(big, 1u << 20, 1, line, sizeof line);
			CK(r == strlen(line) && r < sizeof line);
			memset(big, '\\', 1u << 20);
			r = kof_pdf_text(big, 1u << 20, 0, line, sizeof line);
			CK(r == strlen(line));
			free(big);
		}
	}
}

/* ----------------------------------------------------------------------------- identify / declare */

#define OBJ_MAX 4096

struct obj {
	const char *name;
	uint8_t     b[OBJ_MAX];
	uint32_t    n;
	uint8_t     want_fmt;      /* the format identify must answer for the whole object, 0 = any */
};

static struct obj corpus[64];
static unsigned n_corpus;

static struct obj *add(const char *name, const void *p, size_t n, uint8_t fmt)
{
	struct obj *o = &corpus[n_corpus++];

	o->name = name;
	o->n = (uint32_t)(n < OBJ_MAX ? n : OBJ_MAX);
	memcpy(o->b, p, o->n);
	o->want_fmt = fmt;
	return o;
}

static void build_corpus(void)
{
	static struct hk_elf e;
	static struct hk_pe p;
	static const char *const fmts[] = { "zip", "tar", "rar", "lha", "arj", "cab", "chm", "7z", "ole", "pdf", "gzip", "rar5" };
	static const char *const names[] = { "elf32le", "elf32be", "elf64le", "elf64be", "elf32rel", "elf64rel" };
	static const char text[] = "#!/bin/sh\necho hello\nexit 0\n";
	uint8_t noise[300];
	unsigned i, k;
	uint32_t s = 12345;

	for (i = 0; i < 6; i++) {
		hk_elf(&e, (i & 2) != 0, (i & 1) != 0 && i < 4, i >= 4);
		add(names[i], e.b, e.n, KOF_FMT_ELF);
	}
	for (i = 0; i < 2; i++) {
		hk_pe(&p, (int)i);
		add(i ? "pe32plus" : "pe32", p.b, p.n, KOF_FMT_PE);
	}
	for (k = 0; k < sizeof fmts / sizeof fmts[0]; k++) {
		static const char inner[] = "hello inner member, hello inner member, hello inner member";
		struct cw in = { 0 }, w;
		unsigned f = cw_find(fmts[k]);

		if (f >= CW_NFORMATS)
			continue;
		cw_put(&in, inner, sizeof inner - 1u);
		w = cw_wrap(f, &in);
		if (!w.oom && w.n)
			add(fmts[k], w.p, w.n, 0);
		cw_free(&w);
		cw_free(&in);
	}
	/* CHIMERAS: a tar block whose NAME is the first bytes of another format. The earlier row's sniff accepts, its parse
	 * refuses, and the tar row (whose sniff looks at offset 257) accepts: the engine names tar, and EX-1 is the examiner
	 * naming nothing. The checksum is recomputed after the name is patched. */
	{
		static const uint8_t chn[][8] = {
			{ 0x7f, 'E', 'L', 'F', 2, 1, 1, 0 }, { 0x7f, 'E', 'L', 'F', 1, 1, 1, 0 }, { 'M', 'Z', 0, 0, 0, 0, 0, 0 },
			{ 'P', 'K', 3, 4, 0, 0, 0, 0 }, { 0x1f, 0x8b, 8, 0, 0, 0, 0, 0 }, { 'R', 'a', 'r', '!', 0x1a, 7, 0, 0 },
			{ '%', 'P', 'D', 'F', '-', '1', '.', '4' }, { '7', 'z', 0xbc, 0xaf, 0x27, 0x1c, 0, 4 } };
		struct cw in = { 0 }, w;
		unsigned c;

		cw_put(&in, "hello inner member", 18);
		w = cw_wrap(cw_find("tar"), &in);
		for (c = 0; c < sizeof chn / sizeof chn[0] && !w.oom && w.n >= 512; c++) {
			uint8_t t[1024];
			unsigned q, sum = 0;

			memcpy(t, w.p, w.n < sizeof t ? w.n : sizeof t);
			memcpy(t, chn[c], 8);
			memset(t + 148, ' ', 8);
			for (q = 0; q < 512; q++)
				sum += t[q];
			snprintf((char *)t + 148, 8, "%06o", sum);
			t[155] = ' ';
			add("chimera", t, w.n < sizeof t ? w.n : sizeof t, 0);
		}
		cw_free(&w);
		cw_free(&in);
	}
	/* an MZ stub with a PE pointer that goes nowhere, then an archive: the PE row's sniff accepts and its parse refuses */
	{
		static const char *const arch[] = { "zip", "7z", "rar", "cab" };
		unsigned c;

		for (c = 0; c < sizeof arch / sizeof arch[0]; c++) {
			struct cw in = { 0 }, w;
			uint8_t t[OBJ_MAX];
			unsigned stub = 64u;

			cw_put(&in, "hello inner member", 18);
			w = cw_wrap(cw_find(arch[c]), &in);
			if (!w.oom && w.n && stub + w.n <= sizeof t) {
				memset(t, 0, stub);
				t[0] = 'M'; t[1] = 'Z';
				t[0x3c] = 0x00; t[0x3d] = 0x00; t[0x3e] = 0x01;      /* e_lfanew = 0x10000, past the object */
				memcpy(t + stub, w.p, w.n);
				add("mz+archive", t, stub + w.n, 0);
			}
			cw_free(&w);
			cw_free(&in);
		}
	}
	add("script", text, sizeof text - 1u, 0);
	for (i = 0; i < sizeof noise; i++) {
		s = s * 1664525u + 1013904223u;
		noise[i] = (uint8_t)(s >> 24);
	}
	add("noise", noise, sizeof noise, 0);
	add("empty", "", 0, 0);
}

/* The engine's own loop (scan_facts.c, sx_identify) without the keep buffer: the first row whose sniff AND parse agree. */
static unsigned sniff_then_refused;

static const struct kof_parser *engine_identify(kof_buf buf, struct kof_obj_ctx *ctx, void **view)
{
	uint32_t n, i;
	const struct kof_parser *pl = kof_parser_list(&n);

	*view = NULL;
	memset(ctx, 0, sizeof *ctx);
	for (i = 0; i < n; i++) {
		void *v;

		if (!pl[i].sniff(buf))
			continue;
		v = calloc(1, pl[i].view_size);
		if (!v)
			return NULL;
		if (pl[i].parse(buf, v, ctx)) {
			*view = v;
			return &pl[i];
		}
		sniff_then_refused++;
		free(v);
	}
	return NULL;
}

static void check_parsed(const struct kof_parser *p, const struct kof_obj_ctx *ctx, uint64_t n, const char *what)
{
	struct kof_range ext[KOF_SCAN_MAX_EXTENTS > 4096 ? 4096 : KOF_SCAN_MAX_EXTENTS];
	uint32_t k, e, got;

	if (!(p->n_regions <= 32 && p->regions && p->region_name)) {
		printf("  FAIL %s: parser row with %u regions\n", what, p->n_regions);
		fails++;
		return;
	}
	CK(ctx->format == p->format);
	if (!ctx->resolve_scan)
		return;
	for (k = 0; k < p->n_regions; k++) {
		got = ctx->resolve_scan(ctx, p->regions[k], ext, (uint32_t)(sizeof ext / sizeof ext[0]));
		for (e = 0; e < got && e < sizeof ext / sizeof ext[0]; e++)
			if (ext[e].off > n || ext[e].len > n - ext[e].off) {
				printf("  FAIL %s: region %s extent %llu+%llu outside the %llu byte object\n", what,
				       p->region_name(p->regions[k]), (unsigned long long)ext[e].off,
				       (unsigned long long)ext[e].len, (unsigned long long)n);
				fails++;
				return;
			}
	}
}

static unsigned ex1_hits, ex1_total;

static void one_identify(const uint8_t *b, uint32_t n, const char *what, int whole, uint8_t want_fmt)
{
	struct kof_obj_ctx ctx, ctx2;
	void *view = NULL, *view2 = NULL, *ev = NULL;
	struct kof_obj_ctx ectx;
	const struct kof_parser *p, *p2, *ep;
	kof_buf buf = kof_buf_make(b, n);

	p = kof_inspect_identify(buf, &ctx, &view);
	CK((p != NULL) == (view != NULL));
	if (p) {
		check_parsed(p, &ctx, n, what);
		if (whole && want_fmt)
			CK(p->format == want_fmt);
	}
	/* twice, the same */
	p2 = kof_inspect_identify(buf, &ctx2, &view2);
	CK(p == p2);
	if (p && p2)
		CK(ctx.format == ctx2.format);
	/* the engine's loop, for EX-1 */
	ep = engine_identify(buf, &ectx, &ev);
	ex1_total++;
	if (ep && !p)
		ex1_hits++;
	kof_inspect_free(p, view);
	kof_inspect_free(p2, view2);
	kof_inspect_free(ep, ev);
}

static void identify_suite(void)
{
	unsigned i, p, v;
	static uint8_t work[OBJ_MAX];
	static const uint8_t flip[] = { 0x00, 0xff, 0x80, 0x01 };

	for (i = 0; i < n_corpus; i++) {
		struct obj *o = &corpus[i];

		one_identify(o->b, o->n, o->name, 1, o->want_fmt);
		/* every prefix */
		for (p = 0; p <= o->n; p++)
			one_identify(o->b, p, o->name, 0, 0);
		/* every byte of the first 512, four hostile values each */
		memcpy(work, o->b, o->n);
		for (p = 0; p < o->n && p < 512; p++) {
			uint8_t keep = work[p];

			for (v = 0; v < sizeof flip; v++) {
				work[p] = flip[v];
				one_identify(work, o->n, o->name, 0, 0);
			}
			work[p] = keep;
		}
	}
	CK(ex1_total > 5000);
	/* EX-1 (2026-10-24, R) [sev M]: when a sniff accepts and the parse refuses, kof_inspect_identify returns NULL, where the
	 * engine's identify goes on to the next row. NOT REPRODUCED (2026-10-27, M): `ex1_hits` counts the objects of this suite
	 * on which the engine names a format and the examiner names none, and it is zero over 74,000 objects (prefixes and byte
	 * changes of every format, a tar block named as an ELF, PE, zip, gzip, rar or 7z header, an MZ stub in front of an
	 * archive): 54 of them hit a refusal (a gzip header cut at 3..9 bytes, a PE cut at 139..151 bytes) and no later row
	 * accepts those bytes. The defect is latent: it shows the day a row after a refusing one can accept what it refused.
	 * This row holds the agreement as it is today; it goes red the day they differ, with the object named in the count. */
	CK(ex1_hits == 0);
}

static void declare_suite(void)
{
	unsigned i, f;
	struct kof_obj_ctx ctx;
	void *view;
	const struct kof_parser *p;

	/* every format number, over every object of the corpus: a row that exists parses or refuses, one that does not is NULL,
	 * and a refusal leaves no view behind */
	for (f = 0; f < 256; f++)
		for (i = 0; i < n_corpus; i++) {
			kof_buf b = kof_buf_make(corpus[i].b, corpus[i].n);

			view = (void *)(uintptr_t)1;
			p = kof_inspect_declare(b, (uint8_t)f, &ctx, &view);
			if (!p) {
				CK(view == NULL);
				continue;
			}
			CK(view != NULL && p->format == f && ctx.format != KOF_FMT_UNKNOWN);
			kof_inspect_free(p, view);
		}
	/* a declared process record or AMSI submission has no magic: the declaration is what makes the row parse */
	{
		static const uint8_t junk[64] = { 0 };

		p = kof_inspect_declare(kof_buf_make(junk, sizeof junk), KOF_EVT_PROC, &ctx, &view);
		if (p)
			kof_inspect_free(p, view);
		p = kof_inspect_declare(kof_buf_make(junk, sizeof junk), KOF_EVT_AMSI, &ctx, &view);
		if (p)
			kof_inspect_free(p, view);
		p = kof_inspect_declare(kof_buf_make(NULL, 0), KOF_FMT_ELF, &ctx, &view);
		CK(!p && !view);
	}
}

/* --------------------------------------------------------------- region map, declared regions */

static void region_suite(void)
{
	unsigned i, shown = 0;

	for (i = 0; i < n_corpus; i++) {
		struct obj *o = &corpus[i];
		struct kof_obj_ctx ctx;
		void *view;
		const struct kof_parser *p = kof_inspect_identify(kof_buf_make(o->b, o->n), &ctx, &view);
		struct kof_region_map m;
		struct kof_range ext[KOF_SCAN_MAX_EXTENTS > 4096 ? 4096 : KOF_SCAN_MAX_EXTENTS];
		uint64_t off;
		uint32_t k, e, nn;

		if (!p)
			continue;
		CK(kof_region_map_build(&m, &ctx, p));
		CK(m.n_reg <= 32);
		/* the map answers, byte by byte, what the parser's resolver says: the first region (in the parser's order) holding
		 * the offset, 0 when none */
		for (off = 0; off < o->n; off++) {
			uint32_t want = 0;

			for (k = 0; k < p->n_regions && !want; k++) {
				nn = ctx.resolve_scan ? ctx.resolve_scan(&ctx, p->regions[k], ext, (uint32_t)(sizeof ext / sizeof ext[0])) : 0;
				for (e = 0; e < nn && e < sizeof ext / sizeof ext[0]; e++)
					if (off >= ext[e].off && off - ext[e].off < ext[e].len) {
						want = p->regions[k];
						break;
					}
			}
			if (kof_region_map_at(&m, off) != want && shown++ < 3) {
				printf("  FAIL region_map_at(%s, %llu) = %x wanted %x\n", o->name, (unsigned long long)off,
				       kof_region_map_at(&m, off), want);
				fails++;
			}
		}
		CK(kof_region_map_at(&m, ~0ull) == 0);
		kof_region_map_free(&m);
		CK(m.n_reg == 0);
		kof_region_map_free(&m);               /* twice: a freed map is empty */
		kof_inspect_free(p, view);
	}
	CK(kof_region_map_at(NULL, 5) == 0);
	{
		struct kof_region_map m;

		CK(kof_region_map_build(&m, NULL, NULL) == 0 && m.n_reg == 0);
	}

	/* kof_declared_regions: the rows of a child's declaration that name the mask and have a length */
	{
		struct kof_scan_region rg[5];
		struct kof_range out[5];

		memset(rg, 0, sizeof rg);
		rg[0].mask = 1; rg[0].off = 10; rg[0].len = 5;
		rg[1].mask = 2; rg[1].off = 20; rg[1].len = 5;
		rg[2].mask = 3; rg[2].off = 30; rg[2].len = 0;          /* no length: not in this object */
		rg[3].mask = 3; rg[3].off = 40; rg[3].len = 7;
		rg[4].mask = 4; rg[4].off = 50; rg[4].len = 9;
		CK(kof_declared_regions(rg, 5, 1, out, 5) == 2 && out[0].off == 10 && out[1].off == 40 && out[1].len == 7);
		CK(kof_declared_regions(rg, 5, 2, out, 5) == 2 && out[0].off == 20 && out[1].off == 40);
		CK(kof_declared_regions(rg, 5, 4, out, 5) == 1 && out[0].off == 50);
		CK(kof_declared_regions(rg, 5, 8, out, 5) == 0);
		CK(kof_declared_regions(rg, 5, 3, out, 1) == 1);        /* the output room bounds it */
		CK(kof_declared_regions(rg, 5, 3, out, 0) == 0);
		CK(kof_declared_regions(NULL, 5, 3, out, 5) == 0);
		CK(kof_declared_regions(rg, 5, 3, NULL, 5) == 0);
		CK(kof_declared_regions(rg, 0, 3, out, 5) == 0);
	}
}

/* ---------------------------------------------------------------------------- kof_locate_str */

static void locate_suite(void)
{
	static uint8_t obj[8192];
	static struct kof_match_ctx m, ms;
	static struct kof_range scratch[16];
	struct kof_locate out;
	struct kof_region_map map;
	static const uint8_t pat[] = "NEEDLE";
	uint32_t i, n;
	int r;

	memset(&map, 0, sizeof map);
	memset(obj, 'x', sizeof obj);
	memset(&m, 0, sizeof m);
	memset(&ms, 0, sizeof ms);
	memcpy(obj + 100, "NEEDLE", 6);
	memcpy(obj + 5000, "NEEDLE", 6);
	kof_match_begin(&m, kof_buf_make(obj, sizeof obj));

	/* found: the first occurrence is `at`, both are hits, the length of a fixed pattern is its own */
	r = kof_locate_str(&m, &ms, &map, kof_buf_make(obj, sizeof obj), NULL, 0, 0, pat, 6, KOF_STR_LITERAL, 0, 6, 6, scratch, 16, &out);
	CK(r == 1 && out.at == 100 && out.n_hits == 2 && out.hits[0] == 100 && out.hits[1] == 5000 && !out.clipped);
	CK(out.hit_len[0] == 6 && out.hit_len[1] == 6 && !out.off_rgn && out.in_rgn);
	/* absent: at is the nowhere value and nothing is claimed */
	r = kof_locate_str(&m, &ms, &map, kof_buf_make(obj, sizeof obj), NULL, 0, 0, (const uint8_t *)"ABSENT", 6, KOF_STR_LITERAL, 0, 6, 6, scratch, 16, &out);
	CK(r == 0 && out.at == KGENOME_BROKEN && out.n_hits == 0);
	/* no pattern, no length */
	CK(kof_locate_str(&m, &ms, &map, kof_buf_make(obj, sizeof obj), NULL, 0, 0, NULL, 6, KOF_STR_LITERAL, 0, 6, 6, scratch, 16, &out) == 0);
	CK(out.at == KGENOME_BROKEN);
	CK(kof_locate_str(&m, &ms, &map, kof_buf_make(obj, sizeof obj), NULL, 0, 0, pat, 0, KOF_STR_LITERAL, 0, 6, 6, scratch, 16, &out) == 0);
	/* longer than the object: refused, not read past it */
	CK(kof_locate_str(&m, &ms, &map, kof_buf_make(obj, 4), NULL, 0, 0, pat, 6, KOF_STR_LITERAL, 0, 6, 6, scratch, 16, &out) == 0);
	/* the object NULL */
	CK(kof_locate_str(&m, &ms, &map, kof_buf_make(NULL, 0), NULL, 0, 0, pat, 6, KOF_STR_LITERAL, 0, 6, 6, scratch, 16, &out) == 0);
	/* more occurrences than the list holds: the list is full, clipped says so, `at` is still the first */
	for (i = 0; i < 200; i++)
		memcpy(obj + 200 + i * 20, "NEEDLE", 6);
	kof_match_begin(&m, kof_buf_make(obj, sizeof obj));
	r = kof_locate_str(&m, &ms, &map, kof_buf_make(obj, sizeof obj), NULL, 0, 0, pat, 6, KOF_STR_LITERAL, 0, 6, 6, scratch, 16, &out);
	CK(r == 1 && out.at == 100 && out.n_hits == KOF_LOCATE_HITS && out.clipped);
	for (n = 1; n < out.n_hits; n++)
		CK(out.hits[n] > out.hits[n - 1]);          /* strictly increasing: the walk made progress each time */
	/* overlapping occurrences: "aa" in "aaaa" is at 0, 1 and 2 - the walk restarts one byte past a hit, not past its length */
	{
		static const uint8_t aa[] = "aa";
		static uint8_t ov[16];

		memset(ov, 'b', sizeof ov);
		memcpy(ov + 4, "aaaa", 4);
		kof_match_begin(&m, kof_buf_make(ov, sizeof ov));
		r = kof_locate_str(&m, &ms, &map, kof_buf_make(ov, sizeof ov), NULL, 0, 0, aa, 2, KOF_STR_LITERAL, 0, 2, 2, scratch, 16, &out);
		CK(r == 1 && out.n_hits == 3 && out.hits[0] == 4 && out.hits[1] == 5 && out.hits[2] == 6);
		/* case-insensitive */
		memcpy(ov + 4, "AaAa", 4);
		kof_match_begin(&m, kof_buf_make(ov, sizeof ov));
		r = kof_locate_str(&m, &ms, &map, kof_buf_make(ov, sizeof ov), NULL, 0, 0, aa, 2, KOF_STR_LITERAL, KOF_STR_ICASE, 2, 2, scratch, 16, &out);
		CK(r == 1 && out.n_hits == 3);
		kof_match_begin(&m, kof_buf_make(ov, sizeof ov));
		r = kof_locate_str(&m, &ms, &map, kof_buf_make(ov, sizeof ov), NULL, 0, 0, aa, 2, KOF_STR_LITERAL, 0, 2, 2, scratch, 16, &out);
		CK(r == 0);
		kof_match_begin(&m, kof_buf_make(obj, sizeof obj));
	}
	/* a whole-word search: "needle" inside "xneedle" is not a hit, the one after a blank is */
	{
		static const uint8_t nd[] = "needle";
		static uint8_t fw[32];

		memset(fw, '.', sizeof fw);
		memcpy(fw + 2, "xneedle", 7);
		memcpy(fw + 12, "needle", 6);
		kof_match_begin(&m, kof_buf_make(fw, sizeof fw));
		r = kof_locate_str(&m, &ms, &map, kof_buf_make(fw, sizeof fw), NULL, 0, 0, nd, 6, KOF_STR_LITERAL, KOF_STR_FULLWORD, 6, 6, scratch, 16, &out);
		CK(r == 1 && out.n_hits == 1 && out.at == 12);
		kof_match_begin(&m, kof_buf_make(obj, sizeof obj));
	}
	/* a mask that names a region the occurrence is not in: present, nowhere the mask names (off_rgn) */
	{
		static struct kof_range ext[1];
		uint32_t mask_region = 0x8000u;

		ext[0].off = 6000; ext[0].len = 100;
		map.n_reg = 1; map.mask[0] = mask_region; map.ext[0] = ext; map.n[0] = 1;
		memset(obj, 'x', sizeof obj);
		memcpy(obj + 100, "NEEDLE", 6);
		kof_match_begin(&m, kof_buf_make(obj, sizeof obj));
		r = kof_locate_str(&m, &ms, &map, kof_buf_make(obj, sizeof obj), NULL, 0, mask_region, pat, 6, KOF_STR_LITERAL, 0, 6, 6, scratch, 16, &out);
		CK(r == 1 && out.at == 100 && out.off_rgn && !out.in_rgn);
		memcpy(obj + 6020, "NEEDLE", 6);
		kof_match_begin(&m, kof_buf_make(obj, sizeof obj));
		r = kof_locate_str(&m, &ms, &map, kof_buf_make(obj, sizeof obj), NULL, 0, mask_region, pat, 6, KOF_STR_LITERAL, 0, 6, 6, scratch, 16, &out);
		CK(r == 1 && out.at == 6020 && out.in_rgn && !out.off_rgn && out.at_mask == mask_region && out.n_hits == 2 && out.cur_hit == 1);
	}
}

/* ----------------------------------------------------------------------- describing, as lines */

struct lines {
	char     t[64][600];
	unsigned n;
};

static void take(void *u, const char *s)
{
	struct lines *l = u;

	if (l->n < 64) {
		snprintf(l->t[l->n], sizeof l->t[0], "%s", s);
		l->n++;
	}
}

static int has(const struct lines *l, const char *sub)
{
	unsigned i;

	for (i = 0; i < l->n; i++)
		if (strstr(l->t[i], sub))
			return 1;
	return 0;
}

static void describe_suite(void)
{
	static const struct kof_inspect_style st = { "<I>", "<L>", "<W>", "</>" };
	struct kofevt_log_hdr h;
	struct lines l;
	uint64_t cnt[32];
	unsigned v;

	/* the log header: five rows, the version row differs with and without a version, the pid row only with a pid */
	memset(&h, 0, sizeof h);
	h.platform = KOF_PLAT_LINUX;
	h.build = 7;
	memset(&l, 0, sizeof l);
	kof_inspect_event_log(&h, 12, 34, &st, take, &l);
	CK(l.n == 4 && has(&l, "collected") && has(&l, "Linux watcher  build 7") && has(&l, "events") && has(&l, "12") &&
	   has(&l, "records") && has(&l, "34") && !has(&l, "traced pid"));
	h.src_major = 2; h.src_minor = 5; h.root_pid = 4242; h.platform = KOF_PLAT_WINDOWS;
	memset(&l, 0, sizeof l);
	kof_inspect_event_log(&h, 0, 0, &st, take, &l);
	CK(l.n == 5 && has(&l, "Windows watcher 2.5  build 7") && has(&l, "traced pid") && has(&l, "4242"));
	h.platform = 99;
	memset(&l, 0, sizeof l);
	kof_inspect_event_log(&h, ~0ull, ~0ull, NULL, take, &l);                    /* no style: plain text */
	CK(l.n == 5 && has(&l, "18446744073709551615") && !has(&l, "<I>") && has(&l, " watcher 2.5"));
	/* null guards */
	kof_inspect_event_log(NULL, 1, 1, &st, take, &l);
	kof_inspect_event_log(&h, 1, 1, &st, NULL, &l);

	/* the verbs: two to a line, a hidden one is marked, a zero count is skipped, vb 0 never shown */
	memset(cnt, 0, sizeof cnt);
	memset(&l, 0, sizeof l);
	kof_inspect_event_verbs(cnt, ~0u, &st, take, &l);
	CK(l.n == 0);
	cnt[0] = 99;
	cnt[1] = 3; cnt[2] = 4; cnt[3] = 5;
	memset(&l, 0, sizeof l);
	kof_inspect_event_verbs(cnt, 0x0000000au, &st, take, &l);            /* keep verbs 1 and 3 */
	CK(l.n == 2 && !has(&l, "99") && has(&l, "hidden"));
	{
		unsigned hid = 0, i;

		for (i = 0; i < l.n; i++)
			hid += strstr(l.t[i], "hidden") != NULL;
		CK(hid == 1);
	}
	for (v = 1; v < 32; v++)
		cnt[v] = v;
	memset(&l, 0, sizeof l);
	kof_inspect_event_verbs(cnt, 0, NULL, take, &l);
	CK(l.n == 16);                                                       /* 31 verbs, two a line */
	kof_inspect_event_verbs(NULL, 0, &st, take, &l);
	kof_inspect_event_verbs(cnt, 0, &st, NULL, &l);

	/* an event of every verb value, with odd field contents: lines are bounded and each field row is a location */
	for (v = 0; v < 64; v++) {
		struct kof_evt e;
		unsigned i;

		memset(&e, 0, sizeof e);
		e.verb = (uint16_t)v;
		e.pid = 1234; e.ppid = 1; e.actor_pid = 5; e.tid = 6; e.stamp = 132000000000000000ull + v; e.seq = v;
		memset(&l, 0, sizeof l);
		kof_inspect_event(&e, &st, take, &l);
		CK(l.n <= kof_evt_n_fields(&e));
		for (i = 0; i < l.n; i++)
			CK(strlen(l.t[i]) < sizeof l.t[i] && strlen(l.t[i]) > 3);
		memset(&l, 0, sizeof l);
		kof_inspect_event(&e, NULL, take, &l);
		CK(!has(&l, "<L>"));
	}
	kof_inspect_event(NULL, &st, take, &l);
}

/* ----------------------------------------------------- what built an object, region entropy */

static void toolchain_suite(void)
{
	static const struct kof_inspect_style st = { "<I>", "<L>", "<W>", "</>" };
	static struct kgenome_pe_info pe;
	static struct kgenome_elf_info el;
	struct kof_obj_ctx ctx;
	struct lines l;
	uint8_t data[128];
	unsigned i;

	memset(&ctx, 0, sizeof ctx);
	memset(&pe, 0, sizeof pe);
	ctx.format = KOF_FMT_PE;
	/* a PE with no CLR and no linker version says nothing */
	memset(&l, 0, sizeof l);
	kof_inspect_toolchain(&ctx, &pe, kof_buf_make(data, sizeof data), &st, take, &l);
	CK(l.n == 0);
	kof_inspect_dotnet(&ctx, &pe, &st, take, &l);
	CK(l.n == 0);
	/* with a linker version and a CLI header */
	pe.linker_major = 14; pe.linker_minor = 29; pe.clr_len = 72; pe.clr_major = 2; pe.clr_minor = 5; pe.clr_flags = 1;
	snprintf(pe.clr_version, sizeof pe.clr_version, "v4.0.30319");
	kof_inspect_toolchain(&ctx, &pe, kof_buf_make(data, sizeof data), &st, take, &l);
	CK(l.n == 2 && has(&l, ".NET  runtime 2.5  metadata v4.0.30319  IL only") && has(&l, "14.29"));
	pe.clr_version[0] = 0;
	pe.clr_flags = 0;
	memset(&l, 0, sizeof l);
	kof_inspect_toolchain(&ctx, &pe, kof_buf_make(data, sizeof data), &st, take, &l);
	CK(has(&l, "metadata ?") && !has(&l, "IL only"));
	/* the metadata rows */
	pe.clr.root_off = 0x200; pe.clr.streams = 5; pe.clr.streams_read = 3;
	pe.clr.tables.off = 0x300; pe.clr.tables.len = 16; pe.clr.strings.off = 0x400; pe.clr.strings.len = 8;
	pe.clr.res_off = 0x500; pe.clr.res_len = 99;
	pe.clr.anomalies = 0x1f;
	memset(&l, 0, sizeof l);
	kof_inspect_dotnet(&ctx, &pe, &st, take, &l);
	CK(has(&l, "metadata") && has(&l, "(fewer than declared)") && has(&l, "#~") && has(&l, "#Strings") && !has(&l, "#US") &&
	   has(&l, "resources") && l.n == 9);
	pe.clr.streams_read = 5;
	memset(&l, 0, sizeof l);
	kof_inspect_dotnet(&ctx, &pe, &st, take, &l);
	CK(!has(&l, "(fewer than declared)"));
	/* wrong format or no info: nothing */
	ctx.format = KOF_FMT_ELF;
	memset(&l, 0, sizeof l);
	kof_inspect_dotnet(&ctx, &pe, &st, take, &l);
	CK(l.n == 0);
	kof_inspect_dotnet(NULL, &pe, &st, take, &l);
	kof_inspect_dotnet(&ctx, NULL, &st, take, &l);
	kof_inspect_toolchain(NULL, &pe, kof_buf_make(data, 1), &st, take, &l);
	kof_inspect_toolchain(&ctx, NULL, kof_buf_make(data, 1), &st, take, &l);

	/* an ELF: static or dynamic from PT_INTERP, the compiler from .comment (clipped to the object and to the row) */
	memset(&el, 0, sizeof el);
	ctx.format = KOF_FMT_ELF;
	memset(data, 0, sizeof data);
	memcpy(data + 8, "GCC: (GNU) 13.2.0\0second", 24);
	el.sec_count = 1;
	snprintf(el.sec[0].name, sizeof el.sec[0].name, ".comment");
	el.sec[0].file_off = 8; el.sec[0].file_size = 40;
	memset(&l, 0, sizeof l);
	kof_inspect_toolchain(&ctx, &el, kof_buf_make(data, sizeof data), &st, take, &l);
	CK(l.n == 2 && has(&l, "static") && has(&l, "GCC: (GNU) 13.2.0") && !has(&l, "second"));
	el.seg_count = 2; el.seg[1].type = 3;
	memset(&l, 0, sizeof l);
	kof_inspect_toolchain(&ctx, &el, kof_buf_make(data, sizeof data), &st, take, &l);
	CK(has(&l, "dynamic"));
	/* hostile: a section past the object, a size that wraps, a count past the table */
	el.sec[0].file_off = ~0ull - 4; el.sec[0].file_size = 100;
	memset(&l, 0, sizeof l);
	kof_inspect_toolchain(&ctx, &el, kof_buf_make(data, sizeof data), &st, take, &l);
	CK(l.n == 1);
	el.sec[0].file_off = 100; el.sec[0].file_size = ~0ull;
	memset(&l, 0, sizeof l);
	kof_inspect_toolchain(&ctx, &el, kof_buf_make(data, sizeof data), &st, take, &l);
	CK(l.n == 2 || l.n == 1);
	el.sec_count = ~0u; el.seg_count = ~0u;
	memset(&l, 0, sizeof l);
	kof_inspect_toolchain(&ctx, &el, kof_buf_make(data, sizeof data), &st, take, &l);
	CK(l.n >= 1);
	for (i = 0; i < l.n; i++)
		CK(strlen(l.t[i]) < 200);
}

static void entropy_suite(void)
{
	unsigned i;

	CK(kof_inspect_region_entropy(NULL, kof_buf_make((const uint8_t *)"ab", 2), 1) == 0);
	for (i = 0; i < n_corpus; i++) {
		struct obj *o = &corpus[i];
		struct kof_obj_ctx ctx;
		void *view;
		const struct kof_parser *p = kof_inspect_identify(kof_buf_make(o->b, o->n), &ctx, &view);
		uint32_t k, e;

		if (!p)
			continue;
		for (k = 0; k < p->n_regions; k++) {
			uint32_t hist[256], mode, want;
			struct kof_range ext[256];
			uint64_t total, bn;
			uint32_t ne, x;

			for (mode = 0; mode < 2; mode++) {
				/* the whole object, then half of it: a buffer shorter than what the regions describe is clipped, not read past.
				 * The oracle is a histogram of the clipped extents, taken here. */
				bn = mode ? o->n / 2u : o->n;
				e = kof_inspect_region_entropy(&ctx, kof_buf_make(o->b, bn), p->regions[k]);
				CK(e <= 64u);       /* eighths of a bit per byte: 8 bits is 64 */
				memset(hist, 0, sizeof hist);
				total = 0;
				ne = ctx.resolve_scan ? ctx.resolve_scan(&ctx, p->regions[k], ext, 256) : 0;
				for (x = 0; x < ne && x < 256; x++) {
					uint64_t from = ext[x].off, len = ext[x].len, q;

					if (from >= bn)
						continue;
					if (len > bn - from)
						len = bn - from;
					for (q = 0; q < len; q++)
						hist[o->b[from + q]]++;
					total += len;
				}
				want = bn && ne ? kentropy_hist(hist, total) : 0;
				CK(e == want);
			}
			CK(kof_inspect_region_entropy(&ctx, kof_buf_make(NULL, 0), p->regions[k]) == 0);
		}
		kof_inspect_free(p, view);
	}
}

/* EX-2: kofinspect.h declares kof_inspect_findings; no unit defines it. The row below is the absence, found by the
 * linker: a weak reference to the symbol is NULL as long as nothing defines it. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wredundant-decls"
extern void kof_inspect_findings(const struct kof_finding *, uint32_t, const struct kof_inspect_style *, kof_inspect_line, void *)
	__attribute__((weak));
#pragma GCC diagnostic pop

/* kof_inspect_mutation needs a scanner of a loaded engine to answer anything; what a unit can hold is the guards. */
static void mutation_guards(void)
{
	static struct kof_scanner sc;
	static struct kof_engine eng;
	struct kof_mutation_view v[2];

	memset(v, 0x5a, sizeof v);
	CK(kof_inspect_mutation(NULL, v, 2) == 0);
	CK(kof_inspect_mutation(&sc, NULL, 2) == 0);
	CK(kof_inspect_mutation(&sc, v, 0) == 0);
	CK(kof_inspect_mutation(&sc, v, 2) == 0);           /* a scanner with no engine */
	sc.eng = &eng;
	CK(kof_inspect_mutation(&sc, v, 2) == 0);           /* an engine with no blocks */
	eng.n_blk = 3;
	CK(kof_inspect_mutation(&sc, v, 2) == 0);           /* blocks, and a scanner whose object has no mutation set */
	CK(((uint8_t *)v)[0] == 0x5a);                      /* nothing was written in any of them */
}

static void declared_not_defined(void)
{
	/* EX-2 (2026-10-27, M) [sev L]: kofinspect.h:396 declares kof_inspect_findings and no .c file defines it (nm of every
	 * kofexamine object, and a grep of the tree, agree). A caller links against a function that is not there. Fix: define
	 * it or delete the declaration. */
	KM_CHECK(kof_inspect_findings != NULL, "kof_inspect_findings is declared in kofinspect.h and defined in no unit", "EX-2");
}

int main(void)
{
	build_corpus();
	CK(n_corpus >= 20);
	names_suite();
	label_suite();
	respace_suite();
	pdf_suite();
	identify_suite();
	declare_suite();
	region_suite();
	locate_suite();
	describe_suite();
	toolchain_suite();
	entropy_suite();
	mutation_guards();
	declared_not_defined();
	printf("kx_inspect: %d checks, %s\n", checks, fails || km_failed() ? "FAILED" : "ok");
	return fails != 0 || km_failed();
}
