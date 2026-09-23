/*
 * lib_symbols.c - the symbol tier of koflib: which bytes a file's own symbol
 * table attributes to the C library, and which it does not.
 *
 * WHAT THIS IS FOR. The marker tier finds STRINGS, so it finds library DATA and
 * never library CODE. The symbol tier reads .symtab instead: a name in the
 * implementation's reserved namespace (ISO C 7.1.3) proves the object file it
 * was defined in came out of the toolchain, and every other symbol in that same
 * STT_FILE group goes with it - including the plainly named ones an author
 * could also have written.
 *
 * AND WHAT IT MUST NOT DO, which is the assertion that matters. The author's
 * own code stays in the view. An earlier version widened each object file to
 * its lowest and highest offset and cut 100% of a real binary's .text with the
 * program's own main inside it; a later one closed the gaps between library
 * runs and cut `main` again, because main is GLOBAL and the guard only looked
 * at locals. The fixture below is built so both failures are visible: the
 * author's function is global, and it sits BETWEEN two library ones.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/detector/overlord/koflib.h"
#include "../../libkofeng/analyzer/parsers/binaries/elf_parse.h"
#include "../../libkofeng/kofcore/kofmod/elf.h"

static int fails;

static void ok(const char *what)
{
	printf("  ok   %s\n", what);
}

static void bad(const char *what)
{
	printf("  FAIL %s\n", what);
	fails++;
}

static void put16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t v)
{
	uint32_t i;

	for (i = 0; i < 4; i++)
		p[i] = (uint8_t)(v >> (8u * i));
}

static void put64(uint8_t *p, uint64_t v)
{
	uint32_t i;

	for (i = 0; i < 8; i++)
		p[i] = (uint8_t)(v >> (8u * i));
}

/*
 * THE FIXTURE.
 *
 * One loadable segment holding a .text of three functions laid out
 *
 *     [ lib_a ][ author ][ lib_b ]
 *
 * so that a tier which reduces the library to "lowest offset to highest" must
 * take `author` with it, and one that keeps each symbol's own extent cannot.
 *
 * The symbol table is the real point: two STT_FILE groups, one naming a library
 * source and defining a reserved name beside a plain one, the other naming the
 * author's and defining only a plain one.
 */
#define VBASE     0x400000u
#define TEXT_OFF  0x1000u
#define FN_LEN    0x100u
#define TEXT_LEN  (3u * FN_LEN)
#define SH_OFF    0x4000u
#define SYM_OFF   0x2000u
#define STR_OFF   0x3000u
#define SEC_N     5u        /* null, .text, .symtab, .strtab, .shstrtab */
#define SYM_N     6u                    /* null, FILE, 2, FILE, 1        */
#define SYM_ENT   24u

/* The string table, laid out by hand so the offsets below are readable. */
static const char strtab[] =
	"\0"                    /*  0 */
	"libc-something.c\0"    /*  1 */
	"__lib_internal\0"      /* 18 */
	"memcpy\0"              /* 33 */
	"author.c\0"            /* 40 */
	"author_fn\0";          /* 49 */
#define S_LIBFILE  1u
#define S_RESERVED 18u
#define S_PLAIN    33u
#define S_USERFILE 40u
#define S_AUTHOR   49u

/* Where each function starts, in the file and in memory. */
#define LIB_A_OFF  (TEXT_OFF)
#define AUTHOR_OFF (TEXT_OFF + FN_LEN)
#define LIB_B_OFF  (TEXT_OFF + 2u * FN_LEN)

static void sym(uint8_t *p, uint32_t name, uint8_t info, uint16_t shndx,
		uint64_t value, uint64_t size)
{
	put32(p + 0, name);
	p[4] = info;
	p[5] = 0;
	put16(p + 6, shndx);
	put64(p + 8, value);
	put64(p + 16, size);
}

static void section(uint8_t *p, uint32_t name, uint32_t type, uint64_t flags,
		    uint64_t addr, uint64_t off, uint64_t size, uint32_t link,
		    uint64_t entsz)
{
	put32(p + 0,  name);
	put32(p + 4,  type);
	put64(p + 8,  flags);
	put64(p + 16, addr);
	put64(p + 24, off);
	put64(p + 32, size);
	put32(p + 40, link);
	put32(p + 44, 0);
	put64(p + 48, 1);
	put64(p + 56, entsz);
}

/*
 * The section-NAME table, which is a different table from .strtab and has to be
 * its own section: e_shstrndx names the one the section names are read from,
 * and pointing it at .strtab makes every section name read out of the symbol names
 * instead - which is how this fixture first failed, with .strtab unfindable by
 * name and the whole tier silently skipped.
 */
static const char shstr[] = "\0.text\0.symtab\0.strtab\0.shstrtab\0";
#define SH_TEXT   1u
#define SH_SYMTAB 7u
#define SH_STRTAB 15u
#define SH_SHSTR  23u
#define SHSTR_OFF 0x3800u

static uint8_t *build(uint64_t *out_n)
{
	uint64_t n = SH_OFF + SEC_N * 64u;
	uint8_t *b = calloc(1, (size_t)n);
	uint8_t *p;
	uint32_t i;

	if (!b)
		return NULL;

	memcpy(b, "\177ELF", 4);
	b[4] = 2; b[5] = 1; b[6] = 1;           /* 64-bit, LE, v1 */
	put16(b + 16, 2);                       /* ET_EXEC */
	put16(b + 18, 62);                      /* x86-64 */
	put32(b + 20, 1);
	put64(b + 24, VBASE + TEXT_OFF);        /* entry */
	put64(b + 32, 64);                      /* phoff */
	put64(b + 40, SH_OFF);                  /* shoff */
	put16(b + 52, 64);                      /* ehsize */
	put16(b + 54, 56); put16(b + 56, 1);    /* one program header */
	put16(b + 58, 64); put16(b + 60, SEC_N);
	put16(b + 62, 4);                       /* shstrndx: .shstrtab */

	p = b + 64;                             /* PT_LOAD, R+X */
	put32(p + 0, 1); put32(p + 4, 5);
	put64(p + 8,  0);
	put64(p + 16, VBASE);
	put64(p + 24, VBASE);
	put64(p + 32, TEXT_OFF + TEXT_LEN);
	put64(p + 40, TEXT_OFF + TEXT_LEN);
	put64(p + 48, 0x1000);

	/* Three distinguishable runs of code. */
	memset(b + LIB_A_OFF,  0xa1, FN_LEN);
	memset(b + AUTHOR_OFF, 0xbb, FN_LEN);
	memset(b + LIB_B_OFF,  0xa2, FN_LEN);

	memcpy(b + STR_OFF, strtab, sizeof strtab);
	memcpy(b + SHSTR_OFF, shstr, sizeof shstr);

	p = b + SYM_OFF;
	i = 0;
	sym(p + SYM_ENT * i++, 0, 0, 0, 0, 0);                  /* the null one */
	/* The library's object file, then what it defines. */
	sym(p + SYM_ENT * i++, S_LIBFILE,  4u, 0xfff1u, 0, 0);          /* FILE */
	sym(p + SYM_ENT * i++, S_RESERVED, 2u, 1u,
	    VBASE + LIB_A_OFF, FN_LEN);                         /* LOCAL FUNC */
	sym(p + SYM_ENT * i++, S_PLAIN,    2u, 1u,
	    VBASE + LIB_B_OFF, FN_LEN);                         /* LOCAL FUNC */
	/* The author's, which names nothing reserved. */
	sym(p + SYM_ENT * i++, S_USERFILE, 4u, 0xfff1u, 0, 0);          /* FILE */
	/*
	 * GLOBAL, not local, and that is the point of the fixture.
	 *
	 * ELF gives a global symbol no STT_FILE group, so nothing can acquit it
	 * by provenance - and the gap-closing pass, which fills the space
	 * between two library runs when nothing the author wrote falls into it,
	 * once read "nothing the author wrote" as "no local of an unconvicted
	 * group". A real binary's `main` is global, sat in a gap that looked
	 * clean by that reading, and was cut. An unknown symbol has to block
	 * its gap, and this is the symbol that says so.
	 */
	sym(p + SYM_ENT * i++, S_AUTHOR, (uint8_t)((1u << 4) | 2u), 1u,
	    VBASE + AUTHOR_OFF, FN_LEN);                        /* GLOBAL FUNC */

	p = b + SH_OFF;
	section(p + 64u * 0, 0, 0, 0, 0, 0, 0, 0, 0);
	section(p + 64u * 1, SH_TEXT,   1u /* PROGBITS */, 6u /* A|X */,
		VBASE + TEXT_OFF, TEXT_OFF, TEXT_LEN, 0, 0);
	section(p + 64u * 2, SH_SYMTAB, 2u /* SYMTAB */, 0,
		0, SYM_OFF, SYM_N * SYM_ENT, 3u, SYM_ENT);
	section(p + 64u * 3, SH_STRTAB, 3u /* STRTAB */, 0,
		0, STR_OFF, sizeof strtab, 0, 0);
	section(p + 64u * 4, SH_SHSTR,  3u /* STRTAB */, 0,
		0, SHSTR_OFF, sizeof shstr, 0, 0);

	*out_n = n;
	return b;
}

static int covers(const struct kof_lib_all *r, uint64_t off, uint64_t len)
{
	uint32_t i;

	for (i = 0; i < r->n; i++)
		if (r->span[i].off <= off &&
		    off + len <= r->span[i].off + r->span[i].len)
			return 1;
	return 0;
}

static int touches(const struct kof_lib_all *r, uint64_t off, uint64_t len)
{
	uint32_t i;

	for (i = 0; i < r->n; i++)
		if (off < r->span[i].off + r->span[i].len &&
		    r->span[i].off < off + len)
			return 1;
	return 0;
}

/*
 * AND THE SYMBOL HALF OF THE SAME QUESTION.
 *
 * A normalised view carries the symbols its parent had, minus the ones the
 * library cut took away, because the view's own headers can no longer produce
 * them - see norm_syms in the scanner.
 *
 * WHAT THIS LOCKS IS THE AGREEMENT BETWEEN THE TWO HALVES. A record may be
 * dropped only when the bytes it covers were cut, and kept otherwise. Anything
 * else - a name test, a tidier rule about toolchain markers - makes the symbol
 * half say the library was taken out where the byte half still has it, and the
 * two describe different files. So the assertion is not "the toolchain's
 * symbols are gone", it is "exactly the cut ones are gone".
 */
static void the_symbol_half_agrees_with_the_byte_half(void)
{
	struct kof_obj_ctx ctx;
	struct kof_elf_info e;
	struct kof_lib_all lib;
	uint8_t *b;
	uint64_t n;

	b = build(&n);
	if (!b)
		return;
	memset(&ctx, 0, sizeof ctx);
	memset(&e, 0, sizeof e);
	if (!kof_elf_parse(kof_buf_make(b, n), &e, &ctx)) {
		free(b);
		return;
	}
	kof_lib_find_all(kof_buf_make(b, n), &e, &lib);

	/*
	 * The three functions the fixture lays out, asked the way norm_syms
	 * asks - by address, through kof_lib_has_addr, which is the one place
	 * the translation lives.
	 */
	if (kof_lib_has_addr(&e, &lib, VBASE + LIB_A_OFF, FN_LEN))
		ok("syms: the library function's record would be dropped");
	else
		bad("syms: a cut function's record would have been kept");
	if (kof_lib_has_addr(&e, &lib, VBASE + LIB_B_OFF, FN_LEN))
		ok("syms: and so would its plainly named neighbour's");
	else
		bad("syms: a cut function's record would have been kept");
	if (!kof_lib_has_addr(&e, &lib, VBASE + AUTHOR_OFF, FN_LEN))
		ok("syms: the author's record is kept, as its bytes are");
	else
		bad("syms: the author's record would be dropped though its "
		    "bytes survive");

	/*
	 * A RECORD THAT COVERS NOTHING WAS CUT FROM NOTHING. `__CTOR_LIST__`
	 * and the rest of the toolchain's markers have no size, so no span can
	 * contain them and they stay - which is right, because the bytes they
	 * point at are still in the view. This is the case a name test got
	 * wrong.
	 */
	if (!kof_lib_has_addr(&e, &lib, VBASE + LIB_A_OFF, 0))
		ok("syms: a size-less record is not claimed by any span");
	else
		bad("syms: a record covering no bytes was taken for the "
		    "library's");
	free(b);
}

int main(void)
{
	struct kof_obj_ctx ctx;
	struct kof_elf_info e;
	struct kof_lib_result lib;
	struct kof_lib_all all;
	uint8_t *b;
	uint64_t n;

	b = build(&n);
	if (!b) {
		bad("out of memory");
		return 1;
	}
	memset(&ctx, 0, sizeof ctx);
	memset(&e, 0, sizeof e);
	if (!kof_elf_parse(kof_buf_make(b, n), &e, &ctx)) {
		bad("the synthetic ELF did not parse");
		free(b);
		return 1;
	}

	printf("the symbol tier:\n");

	/*
	 * THE MARKER TIER ALONE SEES NOTHING HERE, which is the whole reason
	 * the second one exists: this file has no library strings in it at all,
	 * and every byte of its libc is code.
	 */
	kof_lib_find(kof_buf_make(b, n), &e, &lib);
	if (lib.n)
		bad("the marker tier claimed a span with no markers present");
	else
		ok("markers alone find nothing - there is no library text here");

	kof_lib_find_all(kof_buf_make(b, n), &e, &all);
	if (!all.n) {
		bad("the symbol tier found no library at all");
		free(b);
		return 1;
	}
	if (covers(&all, LIB_A_OFF, FN_LEN))
		ok("the reserved name's own function is cut");
	else
		bad("a function named in the implementation's namespace survived");

	/*
	 * The point of the GROUP: `memcpy` is a name an author could have
	 * written, and it is cut here because it shares an object file with a
	 * name that could only be the library's.
	 */
	if (covers(&all, LIB_B_OFF, FN_LEN))
		ok("and so is the plainly named one beside it in the same file");
	else
		bad("the group's other function was left in");

	/*
	 * AND THE ASSERTION THIS TEST EXISTS FOR.
	 */
	if (touches(&all, AUTHOR_OFF, FN_LEN))
		bad("the author's own function was cut with the library");
	else
		ok("the author's function is untouched between the two");

	free(b);

	printf("\n");
	the_symbol_half_agrees_with_the_byte_half();

	if (fails) {
		printf("lib symbols: %d failure(s)\n", fails);
		return 1;
	}
	printf("lib symbols: ok\n");
	return 0;
}
