/*
 * fnprint_adv_trueline - what the scan path's library spans (trueline.c) let an author hide.
 *
 * NOT A TEST OF THE PROTOTYPE. The spans that the block matcher uses today are made from NAMES and
 * STRINGS: a symbol in the implementation's reserved namespace (ISO C 7.1.3) convicts its whole STT_FILE
 * group, and three marker strings within 5120 bytes of each other make a span from the first to the
 * last. An author who patches the file chooses both. This file builds the two exploits in memory and
 * pins them as known misses, with the exact edit that makes each one work, so that nobody takes the
 * trueline tiers for a filter that locates evidence: it can only create blind spots a patcher steers.
 * The prototype's rules (fnprint_adv_names.c, fnprint_adv_stream.c) do not read either signal.
 *
 *   1. RESERVED_IDENTIFIER_NAME_CUTS_AUTHOR_CODE: the author renames his function `_payload`
 *      (any identifier that begins with an underscore): the function, and every other symbol of its
 *      object file, is cut from the view as the library's.
 *   2. MARKER_STRINGS_BRACKET_AUTHOR_CODE: three strings from the marker table ("malloc(): ", "__libc_",
 *      "GLIBC_") written before, inside and after his code, each within 5120 bytes of the next: the span
 *      from the first to the last cuts everything between, his code included.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <celllysis/trueline.h>
#include "../../libkofeng/analyzers/parsers/binaries/elf/elf_parse.h"
#include "../../libkofeng/kofcore/kofmod/elf.h"
#include "known_miss.h"

static int fails;

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { uint32_t i; for (i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8u * i)); }
static void put64(uint8_t *p, uint64_t v) { uint32_t i; for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8u * i)); }

#define VBASE    0x400000u
#define TEXT_OFF 0x1000u
#define SH_OFF   0x6000u
#define SYM_OFF  0x4000u
#define STR_OFF  0x5000u
#define SHSTR_OFF 0x5800u
#define SEC_N    5u
#define SYM_ENT  24u

static const char shstr[] = "\0.text\0.symtab\0.strtab\0.shstrtab\0";

static void sym(uint8_t *p, uint32_t name, uint8_t info, uint16_t shndx, uint64_t value, uint64_t size)
{
	put32(p + 0, name); p[4] = info; p[5] = 0; put16(p + 6, shndx); put64(p + 8, value); put64(p + 16, size);
}

static void section(uint8_t *p, uint32_t name, uint32_t type, uint64_t flags, uint64_t addr, uint64_t off,
		    uint64_t size, uint32_t link, uint64_t entsz)
{
	put32(p + 0, name); put32(p + 4, type); put64(p + 8, flags); put64(p + 16, addr); put64(p + 24, off);
	put64(p + 32, size); put32(p + 40, link); put32(p + 44, 0); put64(p + 48, 1); put64(p + 56, entsz);
}

/* One executable segment of `text_len` bytes; the symbol table says what the caller says. */
static uint8_t *build(uint64_t text_len, const char *strtab, uint32_t strtab_n, uint32_t n_sym,
		      void (*syms)(uint8_t *), uint64_t *out_n)
{
	uint64_t n = SH_OFF + SEC_N * 64u;
	uint8_t *b = calloc(1, (size_t)n), *p;

	if (!b)
		return NULL;
	memcpy(b, "\177ELF", 4);
	b[4] = 2; b[5] = 1; b[6] = 1;
	put16(b + 16, 2); put16(b + 18, 62); put32(b + 20, 1);
	put64(b + 24, VBASE + TEXT_OFF); put64(b + 32, 64); put64(b + 40, SH_OFF);
	put16(b + 52, 64); put16(b + 54, 56); put16(b + 56, 1); put16(b + 58, 64); put16(b + 60, SEC_N); put16(b + 62, 4);
	p = b + 64;
	put32(p + 0, 1); put32(p + 4, 5); put64(p + 8, 0); put64(p + 16, VBASE); put64(p + 24, VBASE);
	put64(p + 32, TEXT_OFF + text_len); put64(p + 40, TEXT_OFF + text_len); put64(p + 48, 0x1000);
	memset(b + TEXT_OFF, 0xbb, (size_t)text_len);
	memcpy(b + STR_OFF, strtab, strtab_n);
	memcpy(b + SHSTR_OFF, shstr, sizeof shstr);
	if (syms)
		syms(b + SYM_OFF);
	p = b + SH_OFF;
	section(p + 64u * 0, 0, 0, 0, 0, 0, 0, 0, 0);
	section(p + 64u * 1, 1u, 1u, 6u, VBASE + TEXT_OFF, TEXT_OFF, text_len, 0, 0);
	section(p + 64u * 2, 7u, 2u, 0, 0, SYM_OFF, n_sym * SYM_ENT, 3u, SYM_ENT);
	section(p + 64u * 3, 15u, 3u, 0, 0, STR_OFF, strtab_n, 0, 0);
	section(p + 64u * 4, 23u, 3u, 0, 0, SHSTR_OFF, sizeof shstr, 0, 0);
	*out_n = n;
	return b;
}

static int touches(const struct kgenome_true_all *r, uint64_t off, uint64_t len)
{
	uint32_t i;

	for (i = 0; i < r->n; i++)
		if (off < r->span[i].off + r->span[i].len && r->span[i].off < off + len)
			return 1;
	return 0;
}

/* ---- 1. the reserved identifier ---------------------------------------------------- */

static const char strtab1[] = "\0evil.c\0_payload\0";
static void syms1(uint8_t *p)
{
	sym(p + SYM_ENT * 1, 1u, 4u, 0xfff1u, 0, 0);                          /* FILE evil.c */
	sym(p + SYM_ENT * 2, 8u, 2u, 1u, VBASE + TEXT_OFF, 0x100);            /* LOCAL FUNC _payload */
}

static void t_reserved_name(void)
{
	struct kof_obj_ctx ctx;
	struct kgenome_elf_info e;
	struct kgenome_true_all all;
	uint64_t n;
	uint8_t *b = build(0x100, strtab1, sizeof strtab1, 3, syms1, &n);

	if (!b) { fails++; return; }
	memset(&ctx, 0, sizeof ctx);
	memset(&e, 0, sizeof e);
	if (!kof_elf_parse(kof_buf_make(b, n), &e, &ctx)) { printf("  FAIL the fixture did not parse\n"); fails++; free(b); return; }
	kgenome_true_find_all(kof_buf_make(b, n), &e, &all);
	KM_CHECK(!touches(&all, TEXT_OFF, 0x100),
		 "an author function renamed to an identifier that begins with an underscore stays in the view",
		 "RESERVED_IDENTIFIER_NAME_CUTS_AUTHOR_CODE");
	free(b);
}

/* ---- 2. the marker strings -------------------------------------------------------- */

static const char strtab2[] = "\0";

static void t_marker_strings(void)
{
	struct kof_obj_ctx ctx;
	struct kgenome_elf_info e;
	struct kgenome_true_result r;
	uint64_t n, len = 0x3000;
	uint8_t *b = build(len, strtab2, sizeof strtab2, 1, NULL, &n);
	uint32_t i, cut = 0;

	if (!b) { fails++; return; }
	memcpy(b + TEXT_OFF + 0x000, "malloc(): ", 10);          /* before his code */
	memcpy(b + TEXT_OFF + 0x1400, "__libc_", 7);             /* inside it */
	memcpy(b + TEXT_OFF + 0x2800, "GLIBC_", 6);              /* after it, each under 5120 bytes from the last */
	memset(&ctx, 0, sizeof ctx);
	memset(&e, 0, sizeof e);
	if (!kof_elf_parse(kof_buf_make(b, n), &e, &ctx)) { printf("  FAIL the fixture did not parse\n"); fails++; free(b); return; }
	kgenome_true_find(kof_buf_make(b, n), &e, &r);
	for (i = 0; i < r.n; i++)
		if (r.span[i].off <= TEXT_OFF + 0x800 && TEXT_OFF + 0x1000 <= r.span[i].off + r.span[i].len)
			cut = 1;
	KM_CHECK(!cut, "code between three marker strings of the library's table stays in the view (the strings are the author's to write)",
		 "MARKER_STRINGS_BRACKET_AUTHOR_CODE");
	free(b);
}

int main(void)
{
	t_reserved_name();
	t_marker_strings();
	printf("fnprint_adv_trueline: %s (known-miss %u)\n", fails ? "FAIL" : "ok", km_known());
	return fails != 0 || km_failed();
}
