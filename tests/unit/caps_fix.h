/*
 * caps_fix.h - hand-built ELF images and the engine's own parse path, shared by
 * the tests that probe a limit (caps_*.c) and the view/parent tests.
 *
 * Header-only and static so each test stays one self-contained program, the way
 * diag_nodes.c is: the images are built here, in memory, from bytes.
 */

#ifndef KOFENG_TESTS_CAPS_FIX_H
#define KOFENG_TESTS_CAPS_FIX_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "../../libkofeng/kofcore/kofmod/kofcap.h"
#include "../../libkofeng/analyzers/parsers/kofformat.h"
#include "../../libkofeng/detectors/linkage/kofdiag.h"
#include "../../libkofeng/analyzers/genome_obj.h"

static int fails __attribute__((unused));

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

static inline void put16(uint8_t *b, unsigned at, uint16_t v)
{
	b[at] = (uint8_t)v;
	b[at + 1u] = (uint8_t)(v >> 8);
}
static inline void put32(uint8_t *b, unsigned at, uint32_t v)
{
	unsigned i;

	for (i = 0; i < 4u; i++)
		b[at + i] = (uint8_t)(v >> (8u * i));
}
static inline void put64(uint8_t *b, unsigned at, uint64_t v)
{
	unsigned i;

	for (i = 0; i < 8u; i++)
		b[at + i] = (uint8_t)(v >> (8u * i));
}

/* x86-64 ELF, one RWX PT_LOAD from offset zero, entry at +0x78 (msfvenom's
 * template: the segment CONTAINS the ELF header). Returns the file length. */
static inline uint64_t cf_elf64(uint8_t *b, uint64_t cap, const uint8_t *code, uint64_t n)
{
	memset(b, 0, (size_t)cap);
	memcpy(b, "\177ELF\2\1\1", 7);
	put16(b, 16, 2);
	put16(b, 18, 0x3e);
	put32(b, 20, 1);
	put64(b, 24, 0x400078u);
	put64(b, 32, 64);
	put16(b, 52, 64);
	put16(b, 54, 56);
	put16(b, 56, 1);
	put32(b, 64, 1);
	put32(b, 68, 7);
	put64(b, 80, 0x400000u);
	put64(b, 96, 0x78u + n);
	put64(b, 104, 0x78u + n);
	memcpy(b + 0x78, code, (size_t)n);
	return 0x78u + n;
}

/* i386 ELF, one R-X PT_LOAD from offset zero, entry at +0x54. */
static inline uint64_t cf_elf32(uint8_t *b, uint64_t cap, const uint8_t *code, uint64_t n)
{
	memset(b, 0, (size_t)cap);
	memcpy(b, "\177ELF\1\1\1", 7);
	put16(b, 16, 2);
	put16(b, 18, 3);
	put32(b, 20, 1);
	put32(b, 24, 0x8048054u);
	put32(b, 28, 52);
	put16(b, 40, 52);
	put16(b, 42, 32);
	put16(b, 44, 1);
	put32(b, 52, 1);
	put32(b, 60, 0x8048000u);
	put32(b, 68, (uint32_t)(0x54u + n));
	put32(b, 72, (uint32_t)(0x54u + n));
	put32(b, 76, 5);
	memcpy(b + 0x54, code, (size_t)n);
	return 0x54u + n;
}

/* Parse through the engine's own table, as a scan does, and run `run`. */
static inline struct kgenome_diag_scan *cf_scan(const uint8_t *b, uint64_t n, unsigned run,
				     struct kof_obj_ctx *ctx, void *view)
{
	const struct kof_parser *pl;
	uint32_t np, i;
	kof_buf buf;

	buf.p = b;
	buf.n = n;
	memset(ctx, 0, sizeof *ctx);
	pl = kof_parser_list(&np);
	for (i = 0; i < np; i++)
		if (pl[i].sniff && pl[i].sniff(buf) &&
		    pl[i].parse && pl[i].parse(buf, view, ctx)) {
			struct kgenome_obj gobj;

			kof_genome_obj(ctx, &gobj);
			return kgenome_diag_scan_with(&gobj, b, n, run);
		}
	return NULL;
}

static inline const struct kgenome_diag_hit *cf_find(const struct kgenome_diag_scan *s,
					  uint16_t cap)
{
	uint32_t i;

	for (i = 0; s && i < kgenome_diag_scan_count(s); i++)
		if (kgenome_diag_scan_at(s, i)->cap == cap)
			return kgenome_diag_scan_at(s, i);
	return NULL;
}

static inline unsigned cf_count_cap(const struct kgenome_diag_scan *s, uint16_t cap)
{
	uint32_t i;
	unsigned n = 0;

	for (i = 0; s && i < kgenome_diag_scan_count(s); i++)
		n += kgenome_diag_scan_at(s, i)->cap == cap;
	return n;
}

/* The rwx_exec tree: W+X allocation, a read into it, a jump to it. */
static inline int cf_match_rwx(const struct kgenome_diag_scan *s)
{
	static const struct kof_diag_node nd[] = {
		{ KGENOME_NUCLEO_ALLOC_EXEC, KGENOME_FLOWF_WX, KOF_DIAG_NO_PARENT,
		  KGENOME_DIAG_ROLE_NONE, 0, 0, 0, NULL },
		{ KGENOME_NUCLEO_MEM_READ, 0, 0, KGENOME_DIAG_ROLE_BUFFER, 0, 0, 0, NULL },
		{ KGENOME_NUCLEO_EXEC_REG, 0, 0, KGENOME_DIAG_ROLE_TARGET, 0, 0, 0, NULL },
	};
	static const struct kof_diag dg = {
		.id = 1, .analysis = KOF_DIAG_ANALYSIS_SYSCALL, .n_node = 3,
		.name = "rwx_exec", .node = nd
	};
	uint16_t bind[4];
	uint8_t nb = 0;

	return s && kof_diag_match(s, &dg, bind, &nb) == 1;
}


/*
 * Append a section table to an image built by cf_elf64: .text over the code,
 * .shstrtab, and with `syms` a .symtab/.strtab holding `_start` and `main` (what
 * an unstripped static build carries). A file with a section table and no
 * .symtab is what `strip` leaves of a static binary. Returns the new length.
 * `code_at`/`code_n` locate the code in the image, `va` its address.
 */
static inline uint64_t cf_add_sections(uint8_t *b, uint64_t len, int wide,
				       uint64_t code_at, uint64_t code_n,
				       uint64_t va, int syms)
{
	static const char shs[] = "\0.text\0.symtab\0.strtab\0.shstrtab\0";
	static const char str[] = "\0_start\0main\0";
	unsigned nsec = syms ? 5u : 3u;
	uint64_t shstr_off = (len + 7u) & ~7ull, sym_off, str_off, sh_off;
	uint8_t *sh;
	unsigned esz = wide ? 24u : 16u;

	memcpy(b + shstr_off, shs, sizeof shs);
	sym_off = (shstr_off + sizeof shs + 7u) & ~7ull;
	str_off = sym_off + 3u * esz;
	sh_off = (str_off + sizeof str + 7u) & ~7ull;
	if (syms) {
		uint8_t *q = b + sym_off;

		memset(q, 0, 3u * esz);
		if (wide) {
			put32(q + esz, 0, 1); q[esz + 4] = 0x12; put16(q + esz, 6, 1);
			put64(q + esz, 8, va); put64(q + esz, 16, 8);
			put32(q + 2u * esz, 0, 8); q[2u * esz + 4] = 0x12; put16(q + 2u * esz, 6, 1);
			put64(q + 2u * esz, 8, va); put64(q + 2u * esz, 16, 8);
		}
		memcpy(b + str_off, str, sizeof str);
	}
	memset(b + sh_off, 0, nsec * 64u);
	sh = b + sh_off;
	/* .text */
	put32(sh + 64, 0, 1); put32(sh + 64, 4, 1); put64(sh + 64, 8, 6);
	put64(sh + 64, 16, va); put64(sh + 64, 24, code_at); put64(sh + 64, 32, code_n);
	put64(sh + 64, 48, 1);
	if (syms) {
		put32(sh + 128, 0, 7); put32(sh + 128, 4, 2); put64(sh + 128, 24, sym_off);
		put64(sh + 128, 32, 3u * esz); put32(sh + 128, 40, 3); put64(sh + 128, 48, 8);
		put64(sh + 128, 56, esz);
		put32(sh + 192, 0, 15); put32(sh + 192, 4, 3); put64(sh + 192, 24, str_off);
		put64(sh + 192, 32, sizeof str); put64(sh + 192, 48, 1);
	}
	put32(sh + 64 * (nsec - 1u), 0, 23); put32(sh + 64 * (nsec - 1u), 4, 3);
	put64(sh + 64 * (nsec - 1u), 24, shstr_off); put64(sh + 64 * (nsec - 1u), 32, sizeof shs);
	put64(sh + 64 * (nsec - 1u), 48, 1);
	put64(b, 40, sh_off);
	put16(b, 60, (uint16_t)nsec);
	put16(b, 62, (uint16_t)(nsec - 1u));
	return sh_off + nsec * 64u;
}

/* The i386 form of the above, without symbols: a section table and no .symtab. */
static inline uint64_t cf_add_sections32(uint8_t *b, uint64_t len, uint64_t code_at,
					 uint64_t code_n, uint32_t va)
{
	static const char shs[] = "\0.text\0.shstrtab\0";
	uint64_t shstr_off = (len + 7u) & ~7ull, sh_off;
	uint8_t *sh;

	memcpy(b + shstr_off, shs, sizeof shs);
	sh_off = (shstr_off + sizeof shs + 7u) & ~7ull;
	memset(b + sh_off, 0, 3u * 40u);
	sh = b + sh_off;
	put32(sh + 40, 0, 1); put32(sh + 40, 4, 1); put32(sh + 40, 8, 6);
	put32(sh + 40, 12, va); put32(sh + 40, 16, (uint32_t)code_at);
	put32(sh + 40, 20, (uint32_t)code_n); put32(sh + 40, 32, 1);
	put32(sh + 80, 0, 7); put32(sh + 80, 4, 3); put32(sh + 80, 16, (uint32_t)shstr_off);
	put32(sh + 80, 20, (uint32_t)sizeof shs); put32(sh + 80, 32, 1);
	put32(b, 32, (uint32_t)sh_off);
	put16(b, 46, 40); put16(b, 48, 3); put16(b, 50, 2);
	return sh_off + 3u * 40u;
}

/*
 * A relocatable x86-64 object - what a kernel module is - whose one function
 * builds a credential structure and installs it:
 *
 *     call prepare_creds ; mov rdi,rax ; call commit_creds ; ret
 *
 * with both calls through R_X86_64_PLT32 relocations against undefined symbols,
 * which is how a compiler emits them and the only way the diagnose
 * kmod_give_root (the SYMBOL route) can see them. `n_fill` defined symbols are
 * put BEFORE the two imports in the symbol table, so the imports are symbol
 * number n_fill + 1 and n_fill + 2 (the null symbol is 0). `swap` puts the
 * imports' names the other way round, which is NOT the diagnose (commit before
 * prepare cannot be linked).
 */
static inline uint64_t cf_kmod(uint8_t *b, uint64_t cap, unsigned n_fill, int swap)
{
	static const char shs[] = "\0.text\0.rela.text\0.symtab\0.strtab\0.shstrtab\0";
	static const uint8_t text[] = {
		0xe8, 0, 0, 0, 0, 0x48, 0x89, 0xc7, 0xe8, 0, 0, 0, 0, 0xc3
	};
	static uint8_t str[1u << 18];
	const char *n1 = swap ? "commit_creds" : "prepare_creds";
	const char *n2 = swap ? "prepare_creds" : "commit_creds";
	const char *fn = "god_mode";
	unsigned nsym = 1u + 1u + n_fill + 2u, i, at = 1;
	uint64_t text_off = 0x40, rela_off = 0x60, sym_off = 0x90, str_off, shstr_off, sh_off;
	uint64_t strn;
	uint8_t *p, *q;

	memset(b, 0, (size_t)cap);
	str[0] = 0;
	/* names in table order: the function, the fills, the two imports */
	memcpy(str + at, fn, strlen(fn) + 1u); at += (unsigned)strlen(fn) + 1u;
	for (i = 0; i < n_fill; i++) {
		char nm[24];

		snprintf(nm, sizeof nm, "fill_%05u", i);
		memcpy(str + at, nm, strlen(nm) + 1u);
		at += (unsigned)strlen(nm) + 1u;
	}
	memcpy(str + at, n1, strlen(n1) + 1u); at += (unsigned)strlen(n1) + 1u;
	memcpy(str + at, n2, strlen(n2) + 1u); at += (unsigned)strlen(n2) + 1u;
	strn = at;
	str_off = sym_off + (uint64_t)nsym * 24u;
	shstr_off = str_off + strn;
	sh_off = (shstr_off + sizeof shs + 7u) & ~7ull;
	memcpy(b, "\177ELF\2\1\1", 7);
	put16(b, 16, 1); put16(b, 18, 62); put32(b, 20, 1);
	put64(b, 40, sh_off);
	put16(b, 52, 64); put16(b, 58, 64); put16(b, 60, 6); put16(b, 62, 5);
	memcpy(b + text_off, text, sizeof text);
	p = b + rela_off;                       /* 2 x Elf64_Rela */
	put64(p, 0, 1); put64(p, 8, ((uint64_t)(n_fill + 2u) << 32) | 4u); put64(p, 16, (uint64_t)-4);
	put64(p + 24, 0, 9); put64(p + 24, 8, ((uint64_t)(n_fill + 3u) << 32) | 4u);
	put64(p + 24, 16, (uint64_t)-4);
	at = 1;
	/* symbol 1: the function (GLOBAL FUNC in .text, the whole of it) */
	q = b + sym_off + 24u;
	put32(q, 0, at); q[4] = (uint8_t)((1u << 4) | 2u); put16(q, 6, 1);
	put64(q, 8, 0); put64(q, 16, sizeof text);
	at += (unsigned)strlen(fn) + 1u;
	for (i = 0; i < n_fill; i++) {          /* data symbols: not functions */
		char tmp[24];

		q = b + sym_off + (uint64_t)(i + 2u) * 24u;
		snprintf(tmp, sizeof tmp, "fill_%05u", i);
		put32(q, 0, at);
		q[4] = (uint8_t)((1u << 4) | 1u);       /* GLOBAL OBJECT */
		put16(q, 6, 1);
		put64(q, 8, i & 7u); put64(q, 16, 0);
		at += (unsigned)strlen(tmp) + 1u;
	}
	q = b + sym_off + (uint64_t)(n_fill + 2u) * 24u;
	put32(q, 0, at); q[4] = (uint8_t)((1u << 4) | 2u);          /* UNDEF FUNC */
	at += (unsigned)strlen(n1) + 1u;
	q += 24;
	put32(q, 0, at); q[4] = (uint8_t)((1u << 4) | 2u);
	memcpy(b + str_off, str, (size_t)strn);
	memcpy(b + shstr_off, shs, sizeof shs);
	p = b + sh_off;
	put32(p + 64, 0, 1); put32(p + 64, 4, 1); put64(p + 64, 8, 6);          /* .text */
	put64(p + 64, 24, text_off); put64(p + 64, 32, sizeof text); put64(p + 64, 48, 16);
	put32(p + 128, 0, 7); put32(p + 128, 4, 4); put64(p + 128, 8, 0x40);    /* .rela.text */
	put64(p + 128, 24, rela_off); put64(p + 128, 32, 48); put32(p + 128, 40, 3);
	put32(p + 128, 44, 1); put64(p + 128, 48, 8); put64(p + 128, 56, 24);
	put32(p + 192, 0, 18); put32(p + 192, 4, 2); put64(p + 192, 24, sym_off); /* .symtab */
	put64(p + 192, 32, (uint64_t)nsym * 24u); put32(p + 192, 40, 4);
	put32(p + 192, 44, 1); put64(p + 192, 48, 8); put64(p + 192, 56, 24);
	put32(p + 256, 0, 26); put32(p + 256, 4, 3); put64(p + 256, 24, str_off); /* .strtab */
	put64(p + 256, 32, strn); put64(p + 256, 48, 1);
	put32(p + 320, 0, 34); put32(p + 320, 4, 3); put64(p + 320, 24, shstr_off); /* .shstrtab */
	put64(p + 320, 32, sizeof shs); put64(p + 320, 48, 1);
	return sh_off + 6u * 64u;
}

/* ---- x86-64 emitters, bytes only -------------------------------------------- */

static inline unsigned cf_emit(uint8_t *c, unsigned at, const void *p, unsigned n)
{
	memcpy(c + at, p, n);
	return at + n;
}

/*
 * The stager, x86-64: mmap(0, 0x1000, RWX, MAP_PRIVATE|ANON), read(0, buf,
 * 0x1000) into it, jmp into it. The three nodes rwx_exec names, linked by the
 * returned pointer. Returns the new offset.
 */
static inline unsigned cf_stager64(uint8_t *c, unsigned at)
{
	static const uint8_t s[] = {
		0x31, 0xff,                         /* xor edi,edi            */
		0xb8, 0x09, 0x00, 0x00, 0x00,       /* mov eax,9   mmap       */
		0xbe, 0x00, 0x10, 0x00, 0x00,       /* mov esi,0x1000         */
		0xba, 0x07, 0x00, 0x00, 0x00,       /* mov edx,7   RWX        */
		0x41, 0xba, 0x22, 0x00, 0x00, 0x00, /* mov r10d,0x22          */
		0x45, 0x31, 0xc9,                   /* xor r9d,r9d            */
		0x0f, 0x05,                         /* syscall                */
		0x48, 0x89, 0xc6,                   /* mov rsi,rax            */
		0x31, 0xff,                         /* xor edi,edi            */
		0xba, 0x00, 0x10, 0x00, 0x00,       /* mov edx,0x1000         */
		0x31, 0xc0,                         /* xor eax,eax read       */
		0x0f, 0x05,                         /* syscall                */
		0xff, 0xe6                          /* jmp rsi                */
	};

	return cf_emit(c, at, s, sizeof s);
}

/*
 * One read(0, buf, n) the diagnose does not care about: a MEM_READ node with no
 * link. `salt` varies the bytes (an immediate in an instruction that is dead
 * to the read) so a run of them is not a period the decoder can lock onto:
 * 11 bytes, and a different offset for the syscall every time.
 */
static inline unsigned cf_filler64(uint8_t *c, unsigned at, unsigned salt)
{
	uint8_t s[] = {
		0xbe, 0, 0, 0, 0,                   /* mov esi,salt           */
		0x31, 0xff,                         /* xor edi,edi            */
		0x31, 0xc0,                         /* xor eax,eax  read      */
		0x0f, 0x05                          /* syscall                */
	};

	put32(s, 1, salt * 2654435761u);
	return cf_emit(c, at, s, sizeof s);
}

#endif /* KOFENG_TESTS_CAPS_FIX_H */
