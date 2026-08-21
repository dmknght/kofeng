/*
 * kofexamine - show what the engine sees in a file.
 *
 *   kofexamine <file>...
 *   kofexamine --dump <file>...
 *
 * The collectors recover a great deal about an object and the scanner uses almost
 * none of it directly - it hands the view to modules and prints their verdicts.
 * This prints the view itself, which is what you want when a signature does not
 * fire and the question is whether the module is wrong or the parse is.
 *
 * With --dump, each file gets a directory of its own holding one file per region,
 * created beside the file it came from - /samples/wget.exe produces
 * /samples/_wget.exe_dump/ - not in whatever directory the tool happened to be run
 * from. Results belong next to their input: a run over three directories otherwise
 * piles everything into one, and the only thing left saying where a region came
 * from is a name that is already being shortened when it gets long.
 *
 * The naming is binwalk's _<name>.extracted convention: already the shape people
 * expect, and the leading underscore keeps results sorted together and away from
 * what was being examined.
 *
 * A directory that cannot be created stops the run rather than skipping that file.
 * A dump missing some of its inputs looks exactly like a dump of fewer inputs, and
 * nothing downstream can tell the difference.
 *
 * Region files are named after the region's enum identifier, so
 * _wget.exe_dump/02.KOF_SCAN_PE_CODE is exactly the bytes a module asking for
 * that region would have been searched over, and the name is one somebody can
 * grep for to find where it came from.
 *
 * The number is the order the regions start in, in this object. Not the order of
 * the enum: on a normal ELF the first PT_LOAD is read-only, so DATA begins right
 * after the headers and CODE does not start until well into the file, and
 * numbering by the enum would put them the wrong way round. Numbering by where
 * each region actually begins says something true about the file in front of you.
 *
 * It orders starts, not layout - regions interleave, and CODE and DATA alternate
 * section by section. The LAYOUT file in the directory has every extent in offset
 * order, which is the layout itself rather than a hint at it. Their sizes sum to the object because the regions
 * partition it - which is printed on the summary line so it can be read rather
 * than assumed.
 *
 * Two inputs with the same basename share a directory and the second overwrites
 * the first. That is the same thing binwalk does and the same thing a shell does
 * with a redirect; making it an error would be surprising more often than it
 * would be useful.
 *
 * They do not reassemble into the original by concatenation. Each file holds one
 * region's bytes in offset order, but the regions themselves interleave, and the
 * dump does not record where each run came from. Sizes summing is the property
 * that holds; byte-for-byte reassembly is not offered and should not be inferred.
 *
 *
 * WHY THIS REACHES INTO INTERNAL HEADERS
 *
 * kofscanner is built against the staged SDK and nothing else, deliberately. This
 * is not, and the difference is worth stating rather than treating as a lapse.
 *
 * The public host surface answers one question - what did you find - and the
 * format views belong to the other public surface, the one a signature module is
 * written against. Neither offers "parse this and hand me the view", because no
 * host has needed it. Adding it to kofeng.h to serve this tool would be designing
 * a public API for a consumer that lives in the same tree, and would put the
 * module ABI in front of hosts that have no business with it.
 *
 * So this links the internal collectors, the way a debugger links the thing it
 * debugs. If a consumer outside this tree ever wants the same thing, that is the
 * moment to design an inspect surface, and the shape of it is already visible
 * here.
 */

/* _GNU_SOURCE, not _POSIX_C_SOURCE: this file includes kofplatform.h (below),
 * whose POSIX branch defines kof_memmem by calling the real memmem - a
 * GNU/BSD extension the compiler must still see declared to compile that
 * inline function, whether or not this file itself calls it. _POSIX_C_SOURCE
 * alone does not just omit memmem on glibc, it suppresses it (any of
 * _POSIX_C_SOURCE/_XOPEN_SOURCE defined without _GNU_SOURCE/_DEFAULT_SOURCE
 * opts into strict POSIX) - missed originally because every build so far ran
 * on Windows, where kof_memmem never touches the real memmem. Before any
 * include, not after: a feature test macro placed later has no effect. */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#include <kofeng.h>
#include "../libkofeng/core/kofplatform.h"
#include <kofcore.h>
#include <kofmod/kofsig.h>
#include <kofmod/elf.h>
#include <kofmod/pe.h>
#include <kofmod/gzip.h>
#include <kofmod/docole.h>
#include <kofmod/zip.h>
#include <kofmod/tar.h>
#include <kofmod/sevenzip.h>
#include <kofmod/rar.h>
#include <kofmod/xz.h>
#include <kofmod/rtf.h>

#include "../libkofeng/kofparsers/binaries/elf_parse.h"
#include "../libkofeng/kofparsers/binaries/pe_parse.h"
#include "../libkofeng/kofparsers/containers/gzip_parse.h"
#include "../libkofeng/kofparsers/containers/docole_parse.h"
#include "../libkofeng/kofparsers/containers/zip_parse.h"
#include "../libkofeng/kofparsers/containers/tar_parse.h"
#include "../libkofeng/kofparsers/containers/sevenzip_parse.h"
#include "../libkofeng/kofparsers/containers/rar_parse.h"
#include "../libkofeng/kofparsers/containers/xz_parse.h"
#include "../libkofeng/kofparsers/containers/rtf_parse.h"
#include "../libkofeng/kofparsers/containers/pdf_parse.h"

#include "kofinspect.h"
#include "../libkofeng/kofmatchers/hexprog.h"

/*
 * What one format offers a tool: how to recognise it, how to parse it, how big
 * its view is, and the names of the things it can report.
 *
 * No name field: the parse sets ctx->format and kof_format_name turns that into
 * one, so a second copy here would be a second thing that could disagree.
 *
 * The same shape as the scanner's parser table and for the same reason - adding a
 * format should be a row, not an edit spread over every consumer.
 */
/* ---- colour ----------------------------------------------------------------
 *
 * Four roles and nothing else, because colour that does not answer a question is
 * noise that makes the colour which does answer one harder to see. Numbers and
 * offsets are deliberately left plain: they are most of the screen, and colouring
 * them would drown the handful of places where a colour means something.
 *
 *   name   the object being described - bold, so a run over a directory can be
 *          scrolled and the boundaries found without reading
 *   bad    something is wrong with the file: an anomaly, a name that escapes its
 *          root, a checksum that disagrees, a region sum that does not add up,
 *          a module every one of whose markers is here
 *   warn   something is unusual but not wrong: an encrypted entry, a declared
 *          expansion that is large rather than absurd, a count that does not
 *          match its claim, a module some of whose markers are here
 *   note   a fact worth finding, carrying no judgement: a marker present in the
 *          wrong region, a container kind
 *   dim    what is almost always uninteresting - a module ruled out before it ran
 *
 * Off unless stdout is a terminal, and off when NO_COLOR is set whatever the
 * terminal is: this tool's output is piped into grep and diffed against itself,
 * and escape sequences in either is a bug rather than a preference.
 */
/*
 * The format of the object most recently described.
 *
 * Read when a recovered object is announced, to say whether what produced it was
 * a packer or an opener - and the two are not the same news. A zip yielding its
 * entries is a zip doing its job; an ELF that had to be unpacked before anything
 * could be read is a packed executable, which is worth looking at whatever came
 * out of it.
 *
 * The engine cannot answer this - decomp and unp modules compile to one pack
 * kind and it does not tell them apart, which the Makefile says in as many words
 * - so it is derived from the object rather than asked of the module. And it is
 * the PARENT's format that decides, which is what this holds: a recovered object
 * is announced before it is itself examined, so at that moment this is still the
 * format of the thing it came out of.
 */
static uint8_t g_parent_format;

static const char *C_OFF  = "";
static const char *C_NAME = "";
static const char *C_BAD  = "";
static const char *C_WARN = "";
static const char *C_NOTE = "";
static const char *C_DIM  = "";

/*
 * The second axis: what KIND of value this is, rather than whether it is trouble.
 *
 * Deliberately drawn from the colours the trouble scale does not use, so the two
 * never have to be told apart by context. A blue number is a number; a red one is
 * a number somebody should look at. Three kinds is all a dump of this shape has:
 *
 *   id     what a thing IS   - class, region and section names, pattern kind
 *   loc    WHERE it is       - file offsets, virtual addresses, hit positions.
 *          Cyan, the same ink the trouble scale uses for a fact carrying no
 *          judgement, because an offset is exactly that. The two never appear in
 *          one column, so sharing an ink costs nothing and keeps the palette at
 *          the number of things a reader can actually hold.
 *   size   HOW MUCH of it    - lengths, byte counts
 *
 * The split is worth the colour because the columns interleave: "off=3316
 * size=0 vaddr=0x128cf4" is three different questions in one line, and reading
 * which is which is most of the work of reading the line.
 */
static const char *C_ID   = "";
static const char *C_LOC  = "";
static const char *C_SIZE = "";

static int stdout_is_tty(void)
{
#ifdef _WIN32
	return _isatty(_fileno(stdout));
#else
	return isatty(1);
#endif
}

static void colour_enable(int on)
{
	if (!on)
		return;
#ifdef _WIN32
	/* A Windows console does not interpret escape sequences until asked, and
	 * asking fails on the consoles that never will - so a failure here is a
	 * console without colour rather than an error. */
	{
		HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
		DWORD m = 0;

		if (h == INVALID_HANDLE_VALUE || !GetConsoleMode(h, &m) ||
		    !SetConsoleMode(h, m | 0x0004u))
			return;
	}
#endif
	C_OFF  = "\033[0m";
	C_NAME = "\033[1m";
	C_BAD  = "\033[31m";
	C_WARN = "\033[33m";
	C_NOTE = "\033[36m";
	/* Bright black rather than SGR 2: "faint" is optional and a fair number
	 * of terminals ignore it, which would silently lose the one distinction
	 * an absent marker has. Grey is a colour and every terminal has it. */
	C_DIM  = "\033[90m";
	C_ID   = "\033[34m";
	C_LOC  = "\033[36m";
	C_SIZE = "\033[32m";
}

/* The two notes every parser prints, so a call site says which it is rather than
 * spelling an escape twice. */
static void note_bad(const char *what)
{
	printf("%s   <- %s%s", C_BAD, what, C_OFF);
}

static void note_warn(const char *what)
{
	printf("%s   <- %s%s", C_WARN, what, C_OFF);
}

static void note_note(const char *what)
{
	printf("%s   <- %s%s", C_NOTE, what, C_OFF);
}

/* "n of m declared", where a disagreement is the thing worth seeing. */
static void print_claimed(const char *label, uint32_t have, uint32_t claimed)
{
	if (have == claimed)
		printf("  %-9s %u of %u declared\n", label, have, claimed);
	else
		printf("  %-9s %s%u of %u%s declared\n", label, C_WARN, have,
		       claimed, C_OFF);
}


/* In the order everyone writes them, not the order the bits happen to sit in. */











/* An offset that could not be resolved prints as what it is, not as a number
 * that would be mistaken for one. */
static void put_off(const char *label, uint64_t v)
{
	/* "unresolved" is not a value, it is a parse that applies here and could
	 * not finish - the one case on this line worth a second look. */
	if (v == KOF_NA)
		printf("%s=%sn/a%s", label, C_DIM, C_OFF);
	else if (v == KOF_BROKEN)
		printf("%s=%sunresolved%s", label, C_WARN, C_OFF);
	else
		printf("%s=%s%llu%s", label, C_LOC, (unsigned long long)v,
		       C_OFF);
}

/*
 * A region name with its KOF_SCAN_<FMT>_ prefix skipped, for the summary column.
 *
 * The full identifier is what a file is named, because that is what somebody
 * greps for. Six of them on one line is not something anybody reads, so the part
 * that is the same on every one is dropped here rather than kept in a second
 * table that could disagree with the first.
 */
static const char *short_region(const char *name)
{
	const char *p = name;
	int underscores = 0;

	if (!name)
		return "?";
	/* KOF_SCAN_<FMT>_NAME: past the third underscore. */
	while (*p && underscores < 3) {
		if (*p == '_')
			underscores++;
		p++;
	}
	return underscores == 3 ? p : name;
}

static void put_perm(uint32_t p)
{
	/* Writable and executable at once is the one combination on this line
	 * worth seeing from across the room: nothing a compiler emits needs it. */
	const char *c = ((p & 2) && (p & 1)) ? C_BAD : C_ID;

	printf("%s%c%c%c%s", c, (p & 4) ? 'R' : '-', (p & 2) ? 'W' : '-',
	       (p & 1) ? 'X' : '-', C_OFF);
}

/*
 * A segment or section type as the word people write, not the number.
 *
 * Same argument the format line already makes with ET_EXEC against type=2: a
 * reader who knows what PT_GNU_STACK is cannot get that from 1685382481, and a
 * reader who does not is no worse off. Colour was the other option and would not
 * have helped - the problem is not that the number is hard to find on the line.
 *
 * Written here rather than in elf.h because it is a spelling for people. The
 * parser has no use for it and a module cannot print.
 *
 * Unknown values fall back to the number, which is the case the table exists to
 * make rare rather than to hide: an arch-specific type is a real thing to meet
 * and PT_ARM_EXIDX and PT_MIPS_REGINFO are the same number, so naming one would
 * be wrong half the time.
 */
static const char *elf_ptype_name(uint32_t t)
{
	switch (t) {
	case 0:          return "PT_NULL";
	case 1:          return "PT_LOAD";
	case 2:          return "PT_DYNAMIC";
	case 3:          return "PT_INTERP";
	case 4:          return "PT_NOTE";
	case 5:          return "PT_SHLIB";
	case 6:          return "PT_PHDR";
	case 7:          return "PT_TLS";
	case 0x6474e550: return "PT_GNU_EH_FRAME";
	case 0x6474e551: return "PT_GNU_STACK";
	case 0x6474e552: return "PT_GNU_RELRO";
	case 0x6474e553: return "PT_GNU_PROPERTY";
	case 0x65a3dbe6: return "PT_OPENBSD_RANDOMIZE";
	default:         return NULL;
	}
}

static const char *elf_shtype_name(uint32_t t)
{
	switch (t) {
	case 0:          return "SHT_NULL";
	case 1:          return "SHT_PROGBITS";
	case 2:          return "SHT_SYMTAB";
	case 3:          return "SHT_STRTAB";
	case 4:          return "SHT_RELA";
	case 5:          return "SHT_HASH";
	case 6:          return "SHT_DYNAMIC";
	case 7:          return "SHT_NOTE";
	case 8:          return "SHT_NOBITS";
	case 9:          return "SHT_REL";
	case 10:         return "SHT_SHLIB";
	case 11:         return "SHT_DYNSYM";
	case 14:         return "SHT_INIT_ARRAY";
	case 15:         return "SHT_FINI_ARRAY";
	case 16:         return "SHT_PREINIT_ARRAY";
	case 17:         return "SHT_GROUP";
	case 18:         return "SHT_SYMTAB_SHNDX";
	case 0x6ffffff6: return "SHT_GNU_HASH";
	case 0x6ffffffd: return "SHT_GNU_VERDEF";
	case 0x6ffffffe: return "SHT_GNU_VERNEED";
	case 0x6fffffff: return "SHT_GNU_VERSYM";
	default:         return NULL;
	}
}

/* The name when there is one, the number when there is not, colour either way -
 * both answer the same question and the column should not change meaning. */
static void put_type(const char *(*name)(uint32_t), uint32_t t, int width)
{
	const char *w = name(t);
	char num[24];

	if (!w) {
		snprintf(num, sizeof num, "%u", t);
		w = num;
	}
	printf("%s%-*s%s", C_ID, width, w, C_OFF);
}

static void print_elf(const void *view, const struct kof_obj_ctx *ctx,
		      kof_buf buf)
{
	const struct kof_elf_info *e = view;
	uint32_t i;

	(void)buf;

	printf("  class     %s %s%s%s  type=%u machine=%u\n",
	       e->elf_class == KOF_ELFCLASS_64 ? "ELF64" : "ELF32", C_ID,
	       e->elf_data == KOF_ELFDATA_BE ? "big-endian" : "little-endian",
	       C_OFF, e->e_type, e->e_machine);
	printf("  entry     addr=%s0x%llx%s ", C_LOC,
	       (unsigned long long)e->entry_addr, C_OFF);
	put_off("off", ctx->entry_off);
	printf(" perm=");
	put_perm(e->entry_perm);
	printf("\n");
	print_claimed("segments", e->phnum, e->phnum_claimed);
	for (i = 0; i < e->seg_count; i++) {
		printf("     ");
		put_type(elf_ptype_name, e->seg[i].type, 16);
		printf(" off=%s%-9llu%s size=%s%-9llu%s "
		       "vaddr=%s0x%-10llx%s perm=",
		       C_LOC, (unsigned long long)e->seg[i].file_off, C_OFF,
		       C_SIZE, (unsigned long long)e->seg[i].file_size, C_OFF,
		       C_LOC, (unsigned long long)e->seg[i].mem_addr, C_OFF);
		put_perm(e->seg[i].perm);
		printf("\n");
	}
	print_claimed("sections", e->shnum, e->shnum_claimed);
	for (i = 0; i < e->sec_count; i++) {
		printf("     %s%-20s%s off=%s%-9llu%s size=%s%-9llu%s ",
		       C_ID, e->sec[i].name, C_OFF,
		       C_LOC, (unsigned long long)e->sec[i].file_off, C_OFF,
		       C_SIZE, (unsigned long long)e->sec[i].file_size, C_OFF);
		put_type(elf_shtype_name, e->sec[i].type, 0);
		printf("\n");
	}
}

static void print_pe(const void *view, const struct kof_obj_ctx *ctx,
		      kof_buf buf)
{
	const struct kof_pe_info *p = view;
	uint32_t i;

	(void)buf;

	printf("  image     %s  machine=0x%04x characteristics=0x%04x\n",
	       p->pe32_plus ? "PE32+" : "PE32", p->machine, p->characteristics);
	printf("  stub      lfanew=%llu gap=%llu\n",
	       (unsigned long long)p->lfanew, (unsigned long long)p->stub_len);
	printf("  headers   end=%llu declared=%llu\n",
	       (unsigned long long)p->header_end,
	       (unsigned long long)p->size_of_headers);
	printf("  entry     rva=0x%llx ", (unsigned long long)p->entry_rva);
	put_off("off", ctx->entry_off);
	printf(" sec=%s perm=",
	       p->entry_sec < p->sec_count ? p->sec[p->entry_sec].name : "none");
	put_perm(p->entry_perm);
	printf("\n");
	printf("  summary   code=%llu init=%llu uninit=%llu base_of_code=0x%llx\n",
	       (unsigned long long)p->size_of_code,
	       (unsigned long long)p->size_of_init_data,
	       (unsigned long long)p->size_of_uninit_data,
	       (unsigned long long)p->base_of_code);
	if (p->cert_len)
		printf("  signature off=%llu len=%llu\n",
		       (unsigned long long)p->cert_off,
		       (unsigned long long)p->cert_len);
	if (p->overlay_len)
		printf("  overlay   off=%llu len=%llu\n",
		       (unsigned long long)p->overlay_off,
		       (unsigned long long)p->overlay_len);
	print_claimed("sections", p->nsec, p->nsec_claimed);
	for (i = 0; i < p->sec_count; i++) {
		printf("     %-9s off=%-9llu raw=%-9llu rva=0x%-8llx vsz=0x%-8llx ",
		       p->sec[i].name, (unsigned long long)p->sec[i].file_off,
		       (unsigned long long)p->sec[i].file_size,
		       (unsigned long long)p->sec[i].mem_rva,
		       (unsigned long long)p->sec[i].mem_size);
		put_perm(p->sec[i].perm);
		/* Only when it differs: printing it always would bury the one case
		 * that matters under a column that repeats the previous one. */
		if (p->sec[i].file_size &&
		    (p->sec[i].claim_off != p->sec[i].file_off ||
		     p->sec[i].claim_len != p->sec[i].file_size))
			printf("  owns=[%llu,%llu)",
			       (unsigned long long)p->sec[i].claim_off,
			       (unsigned long long)(p->sec[i].claim_off +
						    p->sec[i].claim_len));
		printf("\n");
	}
}

/*
 * What a gzip wrapper says about the stream it holds, before anything decodes it.
 *
 * The declared ratio is printed beside the sizes rather than left to be worked
 * out: it is the number worth looking at first on a container, and a file that
 * admits to expanding a thousandfold is one to open deliberately.
 */
static void print_gzip(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_gzip_info *g = v;

	(void)ctx;
	(void)buf;

	printf("  method    %u%s\n", g->method,
	       g->method == KOF_GZIP_DEFLATE ? " (deflate)" : " (not deflate)");
	printf("  flags     0x%02x%s%s%s%s%s\n", g->flags,
	       (g->flags & KOF_GZIP_FTEXT)    ? " TEXT"    : "",
	       (g->flags & KOF_GZIP_FHCRC)    ? " HCRC"    : "",
	       (g->flags & KOF_GZIP_FEXTRA)   ? " EXTRA"   : "",
	       (g->flags & KOF_GZIP_FNAME)    ? " NAME"    : "",
	       (g->flags & KOF_GZIP_FCOMMENT) ? " COMMENT" : "");
	printf("  mtime     %u   os=%u xfl=%u\n", g->mtime, g->os, g->xfl);
	printf("  stream    off=%llu len=%llu\n",
	       (unsigned long long)g->data_off, (unsigned long long)g->data_len);
	if (g->name_len)
		printf("  name      off=%llu len=%llu\n",
		       (unsigned long long)g->name_off,
		       (unsigned long long)g->name_len);
	if (g->comment_len)
		printf("  comment   off=%llu len=%llu\n",
		       (unsigned long long)g->comment_off,
		       (unsigned long long)g->comment_len);
	if (g->trailer_off) {
		printf("  trailer   off=%llu crc=0x%08x isize=%u",
		       (unsigned long long)g->trailer_off, g->crc32, g->isize);
		if (g->data_len && g->isize / g->data_len >= 100u)
			note_warn("declared expansion is large");
		printf("\n");
	}
}

/*
 * What a compound file holds, before a byte of any stream is joined up.
 *
 * The four content sizes are the point of the display. They are what the directory
 * DECLARED, which is available for free, and the question they answer is the one
 * worth asking first about a document: how much of it is macros. A file whose
 * macros outweigh its text is not a document that happens to have a macro.
 *
 * Runs are printed as a count per class rather than listed, because the number is
 * the interesting part - it is how fragmented the stream is, and so how much a
 * gather would have to join.
 */
static void print_docole(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	static const char *const cls_name[KOF_DOCOLE_CLS_COUNT] = {
		"headers", "directory", "content_data", "content_macros",
		"content_metadata", "resources"
	};
	const struct kof_docole_info *o = v;
	uint32_t runs[KOF_DOCOLE_CLS_COUNT] = { 0 };
	uint32_t i;

	(void)ctx;
	(void)buf;

	printf("  version   %u.%u   sector=%u mini=%u cutoff=%u\n",
	       o->major, o->minor, o->sector_size, o->mini_sector_size,
	       o->mini_cutoff);
	printf("  directory %u entries: %u streams, %u storages%s%s\n",
	       o->dir_count, o->stream_count, o->storage_count,
	       o->has_macros ? ", macros present" : "",
	       o->encrypted ? ", CONTENT IS ENCRYPTED" : "");
	printf("  declared  data=%llu macros=%llu metadata=%llu resources=%llu%s\n",
	       (unsigned long long)o->data_bytes,
	       (unsigned long long)o->macro_bytes,
	       (unsigned long long)o->meta_bytes,
	       (unsigned long long)o->resource_bytes, "");
	if (o->macro_bytes > KOF_DOCOLE_MACRO_SUSPECT)
		note_warn("macros are larger than any honest document");

	for (i = 0; i < o->n_runs; i++) {
		if (o->run[i].cls >= KOF_DOCOLE_CLS_COUNT)
			continue;
		runs[o->run[i].cls]++;
	}
	for (i = 0; i < KOF_DOCOLE_CLS_COUNT; i++)
		if (runs[i])
			printf("  %-17s %llu bytes in %u run%s\n", cls_name[i],
			       (unsigned long long)o->region_bytes[i], runs[i],
			       runs[i] == 1 ? "" : "s");
}





/*
 * An entry name, as it is safe to put on a line.
 *
 * The FULL name, path and all, unlike the label the scanner puts in a report - a
 * report answers "which entry", and this answers "what does this archive hold",
 * and the second one wants word/vbaProject.bin rather than vbaProject.bin.
 *
 * The filtering is the same either way and is here rather than at each printer
 * because it was written twice, once for zip and once for tar, identically. Two
 * copies of the rule that keeps a terminal escape out of the output is one copy too
 * many: the name comes from the archive, and an ESC in it rewrites the line.
 */
static void print_entry_name(kof_buf buf, uint64_t off, uint32_t len, uint32_t cap)
{
	uint32_t k;

	for (k = 0; k < len && k < cap && kof_in_range(buf, off + k, 1); k++) {
		uint8_t c = buf.p[off + k];

		putchar(c >= 0x20 && c < 0x7f ? (int)c : '.');
	}
}

/*
 * What an archive states about itself, before a byte of any entry is decoded.
 *
 * The entry table is the display, not a summary of it: a zip's evidence IS its
 * entries - what they are called, how they are packed, whether they can be read at
 * all - and a total hides exactly the one row that matters. Capped, because an APK
 * has hundreds and nobody reads those; the ones marked suspicious are printed
 * whatever their position, so the cap can never hide the interesting one.
 *
 * Each row names the REGION its data landed in, and that column is there to stop
 * this table and --dump from looking like two unrelated descriptions of one file.
 * They describe different things on purpose - a table of entries is what the
 * archive says it holds, and a dump of regions is what a signature would actually
 * be searched over - and without the column there is nothing connecting them. With
 * it, every byte of every row can be found in exactly one dumped file.
 *
 * What this tool does NOT show is the entries OPENED: decompressing them costs
 * budget and belongs to an unpacker, which runs in the scanner and not here. The
 * scanner is where the tree is - it names children as <file>//6//0 - and a .docm
 * reaches its macros three layers down that way, through zip, then the compound
 * file inside it, then the macro streams.
 */
#define ZIP_SHOW 12u

static void print_zip(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_zip_info *z = v;
	uint32_t i, shown = 0;

	(void)ctx;

	printf("  kind      %s   %u entries", kof_zip_kind_name(z->kind),
	       z->n_entries);
	if (z->declared_entries != z->n_entries)
		printf(" (%u declared)", z->declared_entries);
	if (z->n_encrypted)
		printf(", %u ENCRYPTED", z->n_encrypted);
	printf("\n");
	printf("  central   off=%llu size=%llu   eocd=%llu\n",
	       (unsigned long long)z->cd_off, (unsigned long long)z->cd_size,
	       (unsigned long long)z->eocd_off);
	printf("  declared  packed=%llu unpacked=%llu",
	       (unsigned long long)z->total_csize,
	       (unsigned long long)z->total_usize);
	if (z->total_csize)
		printf("   ratio %.1fx",
		       (double)z->total_usize / (double)z->total_csize);
	printf("\n");
	if (z->comment_len)
		printf("  comment   off=%llu len=%llu\n",
		       (unsigned long long)z->comment_off,
		       (unsigned long long)z->comment_len);

	for (i = 0; i < z->n_entries; i++) {
		const struct kof_zip_entry *e = &z->entry[i];

		if (shown >= ZIP_SHOW && !e->suspicious)
			continue;
		shown++;
		printf("    [%3u] m=%-3u %9llu -> %-9llu @%-9llu %-6s ", i, e->method,
		       (unsigned long long)e->csize, (unsigned long long)e->usize,
		       (unsigned long long)e->data_off,
		       !e->data_off ? "-" :
		       (e->method == KOF_ZIP_M_STORE &&
			!(e->suspicious & KOF_ZIP_ENT_ENCRYPTED))
		       ? "STORED" : "PACKED");
		print_entry_name(buf, e->name_off, e->name_len, 60u);
		if (e->suspicious & KOF_ZIP_ENT_TRAVERSAL)
			note_bad("ESCAPES THE EXTRACT ROOT");
		if (e->suspicious & KOF_ZIP_ENT_ENCRYPTED)
			note_warn("encrypted");
		if (e->suspicious & KOF_ZIP_ENT_NO_LOCAL)
			note_bad("no local header there");
		if (e->suspicious & KOF_ZIP_ENT_RATIO)
			note_bad("declared expansion is absurd");
		printf("\n");
	}
	if (z->n_entries > shown)
		printf("    ... %u more\n", z->n_entries - shown);
}


/*
 * The subtype's name, which only means anything alongside the format.
 *
 * Here rather than in a format header because it is a spelling for a person, and
 * both enums are already the values the header field holds - elf.h and pe.h say
 * what they mean, and this says how to print them.
 */

/*
 * What a tar holds. The entry table is the display for the reason a zip's is: the
 * evidence in an archive IS its entries, and a total hides the one row that matters.
 */
static void print_tar(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_tar_info *t = v;
	uint32_t i, shown = 0;

	(void)ctx;

	printf("  entries   %u: %u file(s), %u dir(s), %u link(s)\n",
	       t->n_entries, t->n_files, t->n_dirs, t->n_links);
	printf("  declared  %llu bytes of content",
	       (unsigned long long)t->total_size);
	if (!t->end_off)
		note_bad("no end blocks: cut short");
	printf("\n");

	for (i = 0; i < t->n_entries; i++) {
		const struct kof_tar_entry *e = &t->entry[i];

		if (shown >= 12u && !e->suspicious)
			continue;
		shown++;
		printf("    [%3u] %c %9llu @%-9llu ", i,
		       e->typeflag ? (char)e->typeflag : '0',
		       (unsigned long long)e->size,
		       (unsigned long long)e->data_off);
		print_entry_name(buf, e->name_off, e->name_len, 60u);
		if (e->suspicious & KOF_TAR_ENT_TRAVERSAL)
			note_bad("ESCAPES THE EXTRACT ROOT");
		if (e->suspicious & KOF_TAR_ENT_PAST_EOF)
			note_bad("content is not in this file");
		if (e->suspicious & KOF_TAR_ENT_SLACK)
			note_bad("padding is not zeroes");
		if (e->suspicious & KOF_TAR_ENT_BAD_SUM)
			note_bad("checksum disagrees");
		printf("\n");
	}
	if (t->n_entries > shown)
		printf("    ... %u more\n", t->n_entries - shown);
}


/*
 * What a 7z states about itself without anything being decoded.
 *
 * The header kind is the line worth reading: it is the difference between an
 * archive this build cannot open yet and one that no build ever will.
 */
static void print_7z(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_7z_info *z = v;

	(void)ctx;
	(void)buf;

	printf("  version   %u.%u\n", z->major, z->minor);
	printf("  header    %s at %llu, %llu bytes",
	       kof_7z_header_kind_name(z->header_kind),
	       (unsigned long long)z->next_hdr_off,
	       (unsigned long long)z->next_hdr_size);
	if (z->hdr_coder)
		printf("   coder=0x%06x", z->hdr_coder);
	printf("\n");
	if (z->hdr_pack_size)
		printf("  coded at  %llu, %llu bytes -> %llu   lc=%u lp=%u pb=%u\n",
		       (unsigned long long)z->hdr_pack_off,
		       (unsigned long long)z->hdr_pack_size,
		       (unsigned long long)z->hdr_unpack_size,
		       z->hdr_lc, z->hdr_lp, z->hdr_pb);
	if (z->header_kind == KOF_7Z_HDR_ENCRYPTED)
		printf("  note      the file list itself is ciphertext: nothing in "
		       "this archive is readable\n");
	else if (z->header_kind == KOF_7Z_HDR_CODED)
		printf("  note      the file list is compressed: entries are not "
		       "listed until it is decoded\n");
}


/*
 * What a RAR states about itself, which for RAR3 is nearly everything except the
 * content: every name, size and flag is in the clear.
 */
static void print_rar(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_rar_info *r = v;
	uint32_t i, shown = 0;

	(void)ctx;

	printf("  version   RAR%u   %u entries", r->rar_version, r->n_entries);
	if (r->n_encrypted)
		printf(", %u ENCRYPTED", r->n_encrypted);
	if (r->n_stored)
		printf(", %u stored", r->n_stored);
	printf("\n");
	printf("  declared  packed=%llu unpacked=%llu",
	       (unsigned long long)r->total_csize,
	       (unsigned long long)r->total_usize);
	if (r->total_csize)
		printf("   ratio %.1fx",
		       (double)r->total_usize / (double)r->total_csize);
	printf("\n");
	if (r->anomalies & KOF_RAR_ANOM_UNSUPPORTED)
		printf("  note      RAR5: structure walked; compressed entries need a\n"
		       "            decoder this build does not have\n");
	if (r->anomalies & KOF_RAR_ANOM_SOLID)
		printf("  note      solid: entries share one compression window, so "
		       "none can be decoded alone\n");

	for (i = 0; i < r->n_entries; i++) {
		const struct kof_rar_entry *e = &r->entry[i];

		if (shown >= ZIP_SHOW && !e->suspicious)
			continue;
		shown++;
		printf("    [%3u] m=%02x %9llu -> %-9llu @%-9llu %-6s ", i,
		       e->method, (unsigned long long)e->csize,
		       (unsigned long long)e->usize,
		       (unsigned long long)e->data_off,
		       !e->data_off ? "-" :
		       (e->method == KOF_RAR_M_STORE &&
			!(e->suspicious & KOF_RAR_ENT_ENCRYPTED))
		       ? "STORED" : "PACKED");
		print_entry_name(buf, e->name_off, e->name_len, 60u);
		if (e->suspicious & KOF_RAR_ENT_TRAVERSAL)
			note_bad("ESCAPES THE EXTRACT ROOT");
		if (e->suspicious & KOF_RAR_ENT_ENCRYPTED)
			note_warn("encrypted");
		if (e->suspicious & KOF_RAR_ENT_PAST_EOF)
			note_bad("data runs past the end");
		if (e->suspicious & KOF_RAR_ENT_RATIO)
			note_bad("declared expansion is absurd");
		if (e->suspicious & KOF_RAR_ENT_SPLIT)
			note_warn("split across volumes");
		printf("\n");
	}
	if (r->n_entries > shown)
		printf("    ... %u more\n", r->n_entries - shown);
}


/* What an xz says about itself, which is where its blocks are and what codes
 * them - both of which come from the index rather than from the blocks. */
static void print_xz(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_xz_info *x = v;
	uint32_t i, shown = 0;

	(void)ctx;
	(void)buf;

	printf("  check     %u (%u byte(s))   %u block(s)", x->check,
	       x->check_len, x->n_blocks);
	if (x->declared_blocks != x->n_blocks)
		printf(" (%u declared)", x->declared_blocks);
	printf("\n");
	printf("  index     off=%llu len=%llu   footer=%llu\n",
	       (unsigned long long)x->index_off, (unsigned long long)x->index_len,
	       (unsigned long long)x->footer_off);
	printf("  declared  packed=%llu unpacked=%llu",
	       (unsigned long long)x->total_comp,
	       (unsigned long long)x->total_uncomp);
	if (x->total_comp)
		printf("   ratio %.1fx",
		       (double)x->total_uncomp / (double)x->total_comp);
	printf("\n");

	for (i = 0; i < x->n_blocks; i++) {
		const struct kof_xz_block *b = &x->block[i];

		if (shown >= ZIP_SHOW && !b->suspicious)
			continue;
		shown++;
		printf("    [%3u] filter=0x%02x x%u  %9llu -> %-9llu @%llu", i,
		       b->filter, b->n_filters, (unsigned long long)b->comp_size,
		       (unsigned long long)b->uncomp_size,
		       (unsigned long long)b->data_off);
		if (b->suspicious & KOF_XZ_BLK_CHAIN)
			note_warn("a filter runs in front of the coder");
		if (b->suspicious & KOF_XZ_BLK_PAST_EOF)
			note_bad("data runs past the end");
		if (b->suspicious & KOF_XZ_BLK_RATIO)
			note_bad("declared expansion is absurd");
		printf("\n");
	}
	if (x->n_blocks > shown)
		printf("    ... %u more\n", x->n_blocks - shown);
}


/* What an RTF carries, which is embedded objects and how hard it worked to hide
 * where they start. */
static void print_rtf(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_rtf_info *r = v;
	uint32_t i;

	(void)ctx;

	printf("  groups    depth %u   %u control word(s)   %u \\bin run(s)\n",
	       r->max_depth, r->n_controls, r->n_bin);
	printf("  objects   %u embedded\n", r->n_objects);
	for (i = 0; i < r->n_objects; i++) {
		const struct kof_rtf_object *o = &r->obj[i];

		printf("    [%2u] hex %llu byte(s) at %llu -> %llu decoded", i,
		       (unsigned long long)o->data_len,
		       (unsigned long long)o->data_off,
		       (unsigned long long)o->hex_bytes);
		if (o->class_len) {
			printf("  class=");
			print_entry_name(buf, o->class_off, o->class_len, 32u);
		}
		if (o->suspicious & KOF_RTF_OBJ_OLE)
			note_note("a compound file");
		if (o->suspicious & KOF_RTF_OBJ_OLE1)
			note_note("an OLE1 package");
		if (o->suspicious & KOF_RTF_OBJ_UPDATE)
			note_bad("OPENS WITHOUT BEING CLICKED");
		if (o->suspicious & KOF_RTF_OBJ_BAD_HEX)
			note_bad("the hex does not pair up");
		printf("\n");
	}
}


static void print_pdf(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_pdf_info *p = v;
	uint32_t i, shown = 0;

	(void)ctx; (void)buf;
	printf("  version   PDF %u.%u   header at %llu\n", p->ver_major,
	       p->ver_minor, (unsigned long long)p->header_off);
	printf("  objects   %u (%u with a stream)   startxref=%llu\n",
	       p->n_objects, p->n_streams, (unsigned long long)p->startxref);
	for (i = 0; i < p->n_objects && shown < 12u; i++) {
		const struct kof_pdf_object *o = &p->object[i];

		if (!o->flags && !o->filters)
			continue;
		printf("    [%3u] %u %u obj  dict=%llu+%llu stream=%llu+%llu"
		       "  flags=0x%x filters=0x%x\n", i, o->num, o->gen,
		       (unsigned long long)o->dict_off,
		       (unsigned long long)o->dict_len,
		       (unsigned long long)o->stream_off,
		       (unsigned long long)o->stream_len, o->flags, o->filters);
		shown++;
	}
}




static const char *base_of(const char *path)
{
	const char *s = strrchr(path, '/');

	return s ? s + 1 : path;
}

/*
 * The directory one file's regions are written into.
 *
 * _<name>_dump when the name allows it. When it does not - too long for a
 * filesystem component, or carrying characters that would make the result awkward
 * to use - the readable part is kept and a checksum of the whole original name is
 * appended, so two files that differ only past the cut still get different
 * directories. Dropping to a bare checksum would be simpler and would make every
 * result unrecognisable.
 */
#define DUMP_NAME_MAX  255            /* what a filesystem component usually holds */
#define DUMP_KEEP_MAX  48             /* readable prefix retained when shortening */

/* Room for a leading path plus a dump directory name. Refused rather than
 * truncated if an input needs more. */
#define PATH_ROOM      (4096 + DUMP_NAME_MAX + 1)

/* Bytes a dump name may carry as they are: anything else is replaced, so a name
 * out of a file cannot become a separator or a parent reference. */
static int name_char_ok(unsigned char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
}

static void dump_dir_name(const char *base, char *out, size_t cap)
{
	size_t n = strlen(base), i, keep = 0;
	int clean = 1;

	for (i = 0; i < n; i++)
		if (!name_char_ok((unsigned char)base[i])) {
			clean = 0;
			break;
		}

	if (clean && n + sizeof "__dump" - 1 <= DUMP_NAME_MAX &&
	    n + sizeof "__dump" < cap) {
		snprintf(out, cap, "_%s_dump", base);
		return;
	}

	while (keep < n && keep < DUMP_KEEP_MAX &&
	       name_char_ok((unsigned char)base[keep]))
		keep++;
	snprintf(out, cap, "_%.*s%s%08x_dump", (int)keep, base, keep ? "-" : "",
		 kof_crc32(base, n));
}

/*
 * Where this file's regions go: a directory beside the file itself.
 *
 * The leading part of the path is kept verbatim, because it names a directory
 * that already exists and is not ours to rename. Only the last component is
 * turned into a dump name.
 *
 * Zero if the result would not fit, which is a refusal rather than a truncation:
 * a truncated path names a different directory, and creating it would put one
 * file's regions somewhere another file's regions can also land.
 */
static int dump_dir_for(const char *path, char *out, size_t cap)
{
	const char *base = base_of(path);
	size_t lead = (size_t)(base - path);
	char name[DUMP_NAME_MAX + 1];

	dump_dir_name(base, name, sizeof name);
	if (lead + strlen(name) + 1 > cap)
		return 0;
	memcpy(out, path, lead);
	memcpy(out + lead, name, strlen(name) + 1);
	return 1;
}

/*
 * Every extent of every region, in file order.
 *
 * The numbered files say where each region begins; this says where each run of
 * each region is, which is the layout itself. It is also where the partition
 * claim becomes checkable line by line: consecutive rows are adjacent, the first
 * starts at zero and the last ends at the file size, or one of those is not true
 * and the row it breaks on says which region got it wrong.
 */
struct layout_row {
	uint64_t    off, len;
	const char *name;
};

/*
 * The printer for a format, chosen by what the parse said the object is.
 *
 * A switch rather than a column in the shared table: the table describes an
 * object, and how this particular front end draws one is not a property of the
 * object. It is also the whole of what stayed behind when the table moved.
 */
static void print_view(uint8_t format, const void *view,
		       const struct kof_obj_ctx *ctx, kof_buf buf)
{
	switch (format) {
	case KOF_FMT_ELF:    print_elf(view, ctx, buf);    break;
	case KOF_FMT_PE:     print_pe(view, ctx, buf);     break;
	case KOF_FMT_GZIP:   print_gzip(view, ctx, buf);   break;
	case KOF_FMT_DOCOLE: print_docole(view, ctx, buf); break;
	case KOF_FMT_ZIP:
	case KOF_FMT_DOCZIP: print_zip(view, ctx, buf);    break;
	case KOF_FMT_TAR:    print_tar(view, ctx, buf);    break;
	case KOF_FMT_7Z:     print_7z(view, ctx, buf);     break;
	case KOF_FMT_RAR:    print_rar(view, ctx, buf);    break;
	case KOF_FMT_XZ:     print_xz(view, ctx, buf);     break;
	case KOF_FMT_RTF:    print_rtf(view, ctx, buf);    break;
	case KOF_FMT_PDF:    print_pdf(view, ctx, buf);    break;
	default:                                           break;
	}
}

static int layout_file(const char *dir, const struct kof_inspect_fmt *f,
		       const struct kof_obj_ctx *ctx)
{
	static struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	static struct layout_row row[KOF_SCAN_MAX_EXTENTS * 8];
	char path[PATH_ROOM];
	uint32_t nrow = 0, i, k, j;
	FILE *out;

	for (i = 0; i < f->n_regions; i++) {
		const char *rn = f->region_name(f->regions[i]);
		uint32_t n = ctx->resolve_scan
			   ? ctx->resolve_scan(ctx, f->regions[i], ext,
					       KOF_SCAN_MAX_EXTENTS) : 0;
		for (k = 0; k < n && nrow < sizeof row / sizeof row[0]; k++) {
			row[nrow].off = ext[k].off;
			row[nrow].len = ext[k].len;
			row[nrow].name = rn ? rn : "?";
			nrow++;
		}
	}
	for (i = 1; i < nrow; i++) {
		struct layout_row t = row[i];
		for (j = i; j > 0 && row[j - 1].off > t.off; j--)
			row[j] = row[j - 1];
		row[j] = t;
	}

	if ((size_t)snprintf(path, sizeof path, "%s/LAYOUT", dir) >= sizeof path)
		return 0;
	out = fopen(path, "w");
	if (!out) {
		fprintf(stderr, "kofexamine: cannot write %s: %s\n", path,
			strerror(errno));
		return 0;
	}
	fprintf(out, "%-12s %-12s %s\n", "offset", "length", "region");
	for (i = 0; i < nrow; i++)
		fprintf(out, "%-12llu %-12llu %s\n",
			(unsigned long long)row[i].off,
			(unsigned long long)row[i].len, row[i].name);
	if (fclose(out) != 0) {
		fprintf(stderr, "kofexamine: cannot write %s\n", path);
		return 0;
	}
	return 1;
}

/*
 * Write one region to its own file.
 *
 * The extents of a region are concatenated in offset order, which is what a
 * module searching that region sees as one logical run of bytes. Two extents that
 * are not adjacent in the file are adjacent here, and that is the honest
 * representation: a pattern spanning the join is one a module would find.
 */
static int dump_region(const char *dir, uint32_t rank, const char *region,
		       const struct kof_obj_ctx *ctx, kof_buf buf, uint32_t bit,
		       uint64_t *out_len)
{
	static struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	char name[4096];
	uint32_t n, i;
	FILE *f;

	*out_len = 0;
	n = ctx->resolve_scan ? ctx->resolve_scan(ctx, bit, ext,
						  KOF_SCAN_MAX_EXTENTS) : 0;
	if (n == 0)
		return 1;                /* an empty region is not a failure */

	/* The directory already names the object, and the region's enum identifier
	 * already names the format, so the file is just the region. */
	if ((size_t)snprintf(name, sizeof name, "%s/%02u.%s", dir, rank, region)
	    >= sizeof name) {
		fprintf(stderr, "kofexamine: output path too long under %s\n", dir);
		return 0;
	}
	f = fopen(name, "wb");
	if (!f) {
		fprintf(stderr, "kofexamine: cannot write %s\n", name);
		return 0;
	}
	for (i = 0; i < n; i++) {
		if (fwrite(buf.p + ext[i].off, 1, (size_t)ext[i].len, f)
		    != (size_t)ext[i].len) {
			fprintf(stderr, "kofexamine: short write to %s\n", name);
			fclose(f);
			return 0;
		}
		*out_len += ext[i].len;
	}
	return fclose(f) == 0;
}

/*
 * Everything this tool does to one object's bytes.
 *
 * Split out from examine() so the same work can be done on bytes that never were a
 * file: with --db the engine hands back what an unpacker produced, and the whole
 * point of looking at those is that they get the identical treatment - identified,
 * described, and dumped region by region. A second copy of this for children would
 * be a second thing to keep in step.
 *
 * `dir` is where a dump goes, or NULL for no dump. The caller decides it, because
 * where a child's dump belongs is a question about the tree and not about the bytes.
 */

/*
 * What a declared marker actually is, written the way its author wrote it.
 *
 * Two kinds and they are not the same question. A literal's bytes are in the
 * pool and hex is the honest rendering - a marker is bytes, and half of them are
 * not printable in the objects this looks at.
 *
 * A HEX pattern's bytes in the pool are NOT the pattern. They are the compiled
 * program - a header, a step table, an alternative table and a byte/mask area -
 * so hex-encoding them would print the matcher's internals and call them a
 * signature. It is reconstructed instead, which is exact: the compiler throws
 * away only whitespace, and every part it keeps has one spelling.
 *
 * Truncated at a width rather than printed whole. A pattern may be 512 bytes and
 * this is a column in a table; the point of the column is recognising a marker,
 * not carrying it, and the db id beside it is what identifies one exactly.
 */
#define VALUE_MAX_BYTES 20u

static void put_hex_bytes(const uint8_t *b, uint32_t n)
{
	uint32_t i, show = n > VALUE_MAX_BYTES ? VALUE_MAX_BYTES : n;

	for (i = 0; i < show; i++)
		printf("%02X", b[i]);
	if (show < n)
		printf("...");
}

/* One byte of a compiled alternative, back to the spelling hex_byte() read. */
static void put_prog_byte(uint8_t v, uint8_t m)
{
	if (m == 0xff)
		printf("%02X", v);
	else if (m == 0x00)
		printf("??");
	else if (m == 0xf0)
		printf("%X?", (v >> 4) & 0xf);
	else
		printf("?%X", v & 0xf);
}

static void put_hex_program(const uint8_t *p, uint32_t len)
{
	const struct kof_hex_hdr *h = (const void *)p;
	const struct kof_hex_step *st;
	const struct kof_hex_alt *al;
	uint32_t i, k, out = 0;

	/* Read out of a database, so every offset is checked before it is used -
	 * the same rule the matcher follows on the same bytes. */
	if (len < sizeof *h || h->total_len > len ||
	    h->steps_off + (uint32_t)h->n_steps * sizeof *st > len ||
	    h->alts_off + (uint32_t)h->n_alts * sizeof *al > len) {
		printf("(unreadable program)");
		return;
	}
	st = (const void *)(p + h->steps_off);
	al = (const void *)(p + h->alts_off);

	for (i = 0; i < h->n_steps && out < VALUE_MAX_BYTES; i++) {
		uint32_t lo = st[i].gap_min, hi = st[i].gap_max;

		if (hi) {
			if (!lo && hi >= KOF_HEX_GAP_OPEN)
				printf("[-]");
			else if (hi >= KOF_HEX_GAP_OPEN)
				printf("[%u-]", lo);
			else if (lo == hi)
				printf("[%u]", lo);
			else
				printf("[%u-%u]", lo, hi);
		}
		if (st[i].n_alts > 1)
			printf("(");
		for (k = 0; k < st[i].n_alts; k++) {
			const struct kof_hex_alt *a = &al[st[i].alt_first + k];
			const uint8_t *d = p + a->data_off;
			const uint8_t *msk = d + a->len;
			uint32_t j;

			if ((uint64_t)a->data_off + a->len > len)
				break;
			if (k)
				printf("|");
			for (j = 0; j < a->len && out < VALUE_MAX_BYTES; j++, out++)
				put_prog_byte(d[j], (a->flags & KOF_HEX_ALT_MASKED)
						    ? msk[j] : 0xff);
		}
		if (st[i].n_alts > 1)
			printf(")");
	}
	if (out >= VALUE_MAX_BYTES)
		printf("...");
}

static void put_value(const struct kof_touch_str *s, int plain)
{
	if (!plain)
		printf("%s", C_SIZE);
	if (s->kind == KOF_STR_HEX)
		put_hex_program(s->bytes, s->len);
	else
		put_hex_bytes(s->bytes, s->len);
	if (!plain)
		printf("%s", C_OFF);
}

/* ---- back to the source ----------------------------------------------------
 *
 * A pack carries the line a detection was written on and not the file it was
 * written in - struct kof_pack_mod has no room for a path and no need of one at
 * scan time. So the thread back to the text is (family, line) plus a source tree
 * to look in, which is what --sources is.
 *
 * Matched on the family alone. KOF_TARGET_NAME is one declaration per file by
 * rule, so a family names a file; two files claiming one family is a mistake in
 * the tree rather than a case to resolve, and it is reported as one.
 *
 * Text scanning rather than compiling: this wants the same two facts ksigbuilder
 * --extract reads, and running a build to print a path would make an examiner
 * depend on a toolchain it otherwise does not need.
 */
#define SRC_MAX       1024u
#define SRC_MAX_LINES 64u

struct src_ent {
	char     family[80];
	char     path[PATH_ROOM];
	/* The lines this file writes a detection on. Needed because a family does
	 * NOT name a file: bases/signatures/mirai.c and mirai_42bb.c both declare
	 * "Mirai" on purpose - one generic, one for a variant - so the family alone
	 * resolved to whichever the directory happened to list first and put a
	 * confident wrong path next to every finding from the other. The line an id
	 * carries belongs to exactly one of them, so family plus line is the key
	 * that actually identifies a module. */
	uint32_t line[SRC_MAX_LINES];
	uint32_t n_line;
};

static struct src_ent  *g_src;
static uint32_t         g_n_src;

/*
 * One source: the family it declares and the lines it reports on.
 *
 * Read the restricted way ksigbuilder reads them - KOF_TARGET_NAME's second
 * argument quote to quote, and the line of every KOF_SCAN_INFECT/SUSPECT, which
 * is the number ksigbuilder writes into the name table beside the blob.
 */
static int src_read(const char *path, struct src_ent *out)
{
	FILE *f = fopen(path, "r");
	char line[1024];
	uint32_t lineno = 0;

	if (!f)
		return 0;
	out->family[0] = 0;
	out->n_line = 0;
	while (fgets(line, sizeof line, f)) {
		char *p, *q;
		size_t n = 0;

		lineno++;
		if (!out->family[0] &&
		    (p = strstr(line, "KOF_TARGET_NAME(")) != NULL &&
		    (p = strchr(p, ',')) != NULL &&
		    (q = strchr(p, '"')) != NULL) {
			for (q++; *q && *q != '"' &&
			     n + 1 < sizeof out->family; q++)
				out->family[n++] = *q;
			out->family[n] = 0;
		}
		if ((strstr(line, "KOF_SCAN_INFECT(") ||
		     strstr(line, "KOF_SCAN_SUSPECT(")) &&
		    out->n_line < SRC_MAX_LINES)
			out->line[out->n_line++] = lineno;
	}
	fclose(f);
	return out->family[0] != 0;
}

static void src_add(const char *path)
{
	struct src_ent *e;

	if (g_n_src >= SRC_MAX)
		return;
	e = &g_src[g_n_src];
	if ((size_t)snprintf(e->path, PATH_ROOM, "%s", path) >= PATH_ROOM)
		return;
	if (src_read(path, e))
		g_n_src++;
}

/* The tree, one level down as well as at the top - the same shape the Makefile
 * globs, because that is the shape a content tree has. */
static void src_scan(const char *dir, int depth)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	char path[PATH_ROOM];

	if (!d)
		return;
	while ((e = readdir(d)) != NULL) {
		size_t n = strlen(e->d_name);

		if (e->d_name[0] == '.')
			continue;
		if ((size_t)snprintf(path, sizeof path, "%s/%s", dir,
				     e->d_name) >= sizeof path)
			continue;
		if (n > 2 && strcmp(e->d_name + n - 2, ".c") == 0)
			src_add(path);
		else if (depth > 0)
			src_scan(path, depth - 1);
	}
	closedir(d);
}

static int src_open(const char *dir)
{
	g_src = calloc(SRC_MAX, sizeof *g_src);
	if (!g_src)
		return 0;
	src_scan(dir, 1);
	if (!g_n_src)
		fprintf(stderr, "kofexamine: no signature sources under %s\n",
			dir);
	return 1;
}

/* The file that declares this family AND reports on this line. Both, for the
 * reason struct src_ent gives. */
static const char *src_path_of(const char *family, uint32_t line)
{
	uint32_t i, k;

	for (i = 0; i < g_n_src; i++) {
		if (strcmp(g_src[i].family, family) != 0)
			continue;
		for (k = 0; k < g_src[i].n_line; k++)
			if (g_src[i].line[k] == line)
				return g_src[i].path;
	}
	return NULL;
}

/* ---- what the database already knows -------------------------------------- */

/*
 * The modules whose markers are in this object, and how close each one came.
 *
 * Printed rather than decided on: every line here is an observation, and the one
 * verdict in this tool comes from the unpack pass below, which runs the engine.
 * A module listed as holding every marker has NOT fired - its conditions are
 * compiled code and were never evaluated - and the wording says so.
 */
static void print_markers(struct kof_engine *eng, kof_buf buf,
			  const struct kof_obj_ctx *ctx)
{
	struct kof_touch *v = NULL;
	uint32_t n = 0, i, j, shown;

	if (!kof_touch_object(eng, buf, ctx, &v, &n)) {
		printf("  markers   out of memory\n");
		return;
	}
	if (n == 0) {
		printf("  markers   nothing in the database has a marker here\n");
		kof_touch_free(v, n);
		return;
	}

	printf("  markers   %u module(s) have at least one marker in this "
	       "object\n", n);

	for (i = 0; i < n; i++) {
		const struct kof_touch *t = &v[i];
		/* The bucket already ranks these; the colour says the same thing
		 * without being read. Nothing here has fired - that is the
		 * scanner's word - so even "every marker" is a warning about
		 * where to look rather than a verdict. */
		const char *c = t->kind == KOF_TOUCH_COMPLETE   ? C_BAD  :
				t->kind == KOF_TOUCH_PARTIAL    ? C_WARN :
				t->kind == KOF_TOUCH_ELSEWHERE  ? C_NOTE : C_DIM;

		/*
		 * The name a scan would print, less the target - which is on the
		 * format line above and is not this module's to claim anyway.
		 * Spelled with the engine's own separators so a row here can be
		 * matched against a verdict by eye rather than by working out
		 * which family a family name belongs to.
		 *
		 * One variant is the common case and is written out. Several and
		 * only the first is, with a count: which one a module WOULD
		 * report depends on logic that is compiled code, so listing them
		 * all would be offering a choice nothing here can resolve.
		 */
		char name[96];
		const char *var = t->n_names && t->name[0] ? t->name[0] : NULL;

		if (var && t->n_names > 1)
			snprintf(name, sizeof name, "%s:%s-%s +%u",
				 kof_maltype_name(t->maltype),
				 t->family[0] ? t->family : "?", var,
				 t->n_names - 1u);
		else if (var)
			snprintf(name, sizeof name, "%s:%s-%s",
				 kof_maltype_name(t->maltype),
				 t->family[0] ? t->family : "?", var);
		else
			snprintf(name, sizeof name, "%s:%s",
				 kof_maltype_name(t->maltype),
				 t->family[0] ? t->family : "?");

		{
			char head[48];

			snprintf(head, sizeof head, "%s (%u/%u)",
				 kof_touch_kind_name(t->kind),
				 t->kind == KOF_TOUCH_INELIGIBLE ? t->n_present
								: t->n_in_rgn,
				 t->n_str);
			printf("     %s%-22s%s %s%-34s%s", c, head, C_OFF,
			       C_ID, name, C_OFF);
		}
		/* Where the logic is. Not what it is - that is compiled code -
		 * but the line somebody can read to find out, which is the
		 * question a row here raises and cannot answer on its own. */
		if (g_n_src && t->family[0] && t->n_names) {
			const char *sp = src_path_of(t->family, t->name_id[0]);

			if (sp)
				printf("  %s%s:%u%s", C_DIM, sp,
				       t->name_id[0], C_OFF);
		}
		if (t->ruled_out)
			printf("   %s", t->ruled_out);
		else if (t->kind == KOF_TOUCH_ELSEWHERE)
			printf("   present, but not where it looks");
		printf("\n");

		/* Titled, because four numbers in a row with inline labels reads
		 * as prose and compares as neither. Dim: it is a legend and the
		 * rows under it are the content. */
		printf("        %skind          db id     size  at          "
		       "value%s\n", C_DIM, C_OFF);
		/*
		 * Every marker the module declares, present or not.
		 *
		 * The absent ones are the point of the whole section: a module
		 * at four of five is a variant to write, and which one is
		 * missing is the first thing its author needs. They were being
		 * skipped, which left the row saying 4/5 and no way to see
		 * which four.
		 *
		 * Three states, and they are not two: found where the module
		 * looks, found somewhere else, not in the object at all. The
		 * middle one already had a note; the last one is the whole row
		 * dimmed, so a block of them reads as absence rather than as
		 * data to compare.
		 */
		for (j = 0, shown = 0; j < t->n_str && shown < 16u; j++) {
			const struct kof_touch_str *s = &t->str[j];
			int miss = s->at == KOF_BROKEN;
			const char *ci = miss ? "" : C_ID;
			const char *cs = miss ? "" : C_SIZE;
			const char *cl = miss ? "" : C_LOC;
			const char *co = miss ? "" : C_OFF;
			char kind[16];

			shown++;

			/*
			 * "hex" and "str" are the words the declarations use -
			 * KOF_DEFINE_HEXSTR and KOF_DEFINE_STR - so the column
			 * names what a source would have to write, and the two
			 * are the same width so the column does not step.
			 *
			 * "fuw" for the same reason, against "sub": a word that
			 * is one character shorter than its opposite moves
			 * every field after it on half the rows.
			 */
			if (s->kind == KOF_STR_HEX)
				snprintf(kind, sizeof kind, "hex");
			else
				/* Both rules always, never a default left
				 * unwritten: "str" alone would mean substring
				 * and case-sensitive to whoever remembers the
				 * defaults and nothing to whoever does not. */
				snprintf(kind, sizeof kind, "str: %s-%s",
					 (s->flags & KOF_STR_FULLWORD) ? "fuw"
								       : "sub",
					 (s->flags & KOF_STR_ICASE) ? "i" : "c");

			if (miss)
				printf("%s", C_DIM);
			printf("        %s%-11s%s %6u %s%8u%s  ",
			       ci, kind, co, s->uid, cs, s->len, co);
			if (miss)
				printf("%-10s  ", "-");
			else
				printf("%s%-10llu%s  ", cl,
				       (unsigned long long)s->at, co);
			put_value(s, miss);
			/* The note only means something when regions were
			 * resolved at all. A module ruled out by its target
			 * never had its regions looked at, so saying its marker
			 * is outside them would be inventing a comparison. */
			if (!miss && t->kind != KOF_TOUCH_INELIGIBLE &&
			    !s->in_rgn)
				note_warn("outside its regions");
			if (miss)
				printf("%s", C_OFF);
			printf("\n");
		}
		if (t->n_str > shown)
			printf("        %s... %u more%s\n", C_DIM,
			       t->n_str - shown, C_OFF);

	}
	kof_touch_free(v, n);
}

static int examine_bytes(kof_buf buf, const char *display, const char *dir,
			 struct kof_engine *eng)
{
	struct kof_obj_ctx ctx;
	void *view = 0;
	const struct kof_inspect_fmt *f = 0;
	uint64_t total = 0;
	uint32_t i;
	int rc = 0;
	const int dump = dir != 0;

	{
		printf("%s%s%s\n", C_NAME, display, C_OFF);
		f = kof_inspect_identify(buf, &ctx, &view);
		g_parent_format = ctx.format;
		if (!f) {
			printf("  format    %sunrecognised%s, %s%llu%s bytes\n",
			       C_WARN, C_OFF, C_SIZE,
			       (unsigned long long)buf.n, C_OFF);
			/* Still worth asking. No format means every module is
			 * ruled out and every marker is reported as such, which
			 * is a truthful answer and occasionally the useful one. */
			if (eng) {
				ctx.obj_size = buf.n;
				print_markers(eng, buf, &ctx);
			}
			rc = 1;
			goto out;
		}

		/*
		 * The subtype spelled in the format's own vocabulary, because that is
		 * what a module declares. A number would be no use: the same value
		 * means REL for an ELF and DLL for a PE, and which one it is is
		 * exactly what the reader is here to find out.
		 */
		printf("  format    %s %s%s%s%s%s  %s%llu%s bytes\n",
		       kof_format_name(ctx.format),
		       C_ID, kof_arch_name(ctx.arch),
		       kof_inspect_subtype_name(ctx.format, ctx.subtype) ? " " : "",
		       kof_inspect_subtype_name(ctx.format, ctx.subtype)
		       ? kof_inspect_subtype_name(ctx.format, ctx.subtype) : "",
		       C_OFF, C_SIZE, (unsigned long long)buf.n, C_OFF);
		print_view(ctx.format, view, &ctx, buf);

		/* Regions last: they are the summary the rest explains, and with
		 * --dump they are also the manifest of what was written. */
		printf("  regions  ");
		for (i = 0; i < f->n_regions; i++) {
			static struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
			const char *rn = f->region_name(f->regions[i]);
			uint64_t len = 0;
			uint32_t n, k;

			n = ctx.resolve_scan
			  ? ctx.resolve_scan(&ctx, f->regions[i], ext,
					     KOF_SCAN_MAX_EXTENTS) : 0;
			for (k = 0; k < n; k++)
				len += ext[k].len;
			total += len;
			printf(" %s%s%s=%s%llu%s", C_ID, short_region(rn), C_OFF,
			       C_SIZE, (unsigned long long)len, C_OFF);
		}
		/* The partition, stated rather than assumed: if these do not add
		 * up, every region-scoped search on this object is looking at the
		 * wrong bytes and this is where it shows. */
		printf("  (sum %llu of %llu", (unsigned long long)total,
		       (unsigned long long)buf.n);
		if (total != buf.n)
			printf("%s MISMATCH%s", C_BAD, C_OFF);
		printf(")\n");

		{
			uint64_t anom = f->anomalies(view);
			if (anom) {
				printf("  anomalies%s", C_BAD);
				for (i = 0; i < 64; i++) {
					const char *an;
					if (!(anom >> i & 1))
						continue;
					an = f->anomaly_name(i);
					if (an)
						printf(" %s", an);
					else
						printf(" bit%u", i);
				}
				printf("%s\n", C_OFF);
			}
		}

		if (dump) {
			static struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
			uint64_t first[16];
			uint32_t order[16], nord = 0;
			uint64_t wrote = 0;
			uint32_t written = 0, k;

			if (kof_mkdir(dir, 0777) != 0 && errno != EEXIST) {
				fprintf(stderr, "kofexamine: cannot create %s: "
						"%s\n", dir, strerror(errno));
				rc = -1;
				goto out;
			}
			/* Order the regions by where each one begins. A region
			 * with no extents is not written and does not take a
			 * number, so the numbers are contiguous over what is
			 * actually there. */
			for (i = 0; i < f->n_regions && nord < 16; i++) {
				uint32_t n = ctx.resolve_scan
					   ? ctx.resolve_scan(&ctx, f->regions[i],
							      ext,
							      KOF_SCAN_MAX_EXTENTS)
					   : 0;
				if (n == 0)
					continue;
				first[nord] = ext[0].off;
				order[nord] = i;
				nord++;
			}
			for (i = 1; i < nord; i++) {
				uint64_t fo = first[i];
				uint32_t oi = order[i];
				for (k = i; k > 0 && first[k - 1] > fo; k--) {
					first[k] = first[k - 1];
					order[k] = order[k - 1];
				}
				first[k] = fo;
				order[k] = oi;
			}

			for (i = 0; i < nord; i++) {
				uint64_t len;
				if (!dump_region(dir, i + 1,
						 f->region_name(f->regions[order[i]]),
						 &ctx, buf, f->regions[order[i]],
						 &len))
					goto out;
				if (len) {
					written++;
					wrote += len;
				}
			}

			/*
			 * The layout itself. The numbered files say where each
			 * region starts; this says where every run of every
			 * region is, in file order, which is the only form that
			 * shows the interleaving.
			 */
			if (!layout_file(dir, f, &ctx))
				goto out;

			printf("  dumped    %u region(s), %llu byte(s) -> %s/\n",
			       written, (unsigned long long)wrote, dir);
		}
		if (eng)
			print_markers(eng, buf, &ctx);
		rc = 1;
	}
out:
	free(view);
	return rc;
}

/*
 * The file on disk, mapped and handed to the same routine as everything else.
 */
static int examine(const char *path, int dump, struct kof_engine *eng)
{
	struct stat st;
	void *map;
	char dir[PATH_ROOM];
	int fd, rc;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "kofexamine: cannot open %s\n", path);
		return 0;
	}
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
		fprintf(stderr, "kofexamine: %s is not a regular non-empty file\n",
			path);
		close(fd);
		return 0;
	}
	map = kof_map_file_ro(fd, (uint64_t)st.st_size);
	close(fd);
	if (!map) {
		fprintf(stderr, "kofexamine: cannot map %s\n", path);
		return 0;
	}
	if (dump && !dump_dir_for(path, dir, sizeof dir)) {
		fprintf(stderr, "kofexamine: path too long to place a dump beside "
				"%s\n", path);
		kof_unmap_file(map, (uint64_t)st.st_size);
		return -1;
	}
	rc = examine_bytes(kof_buf_make(map, (uint64_t)st.st_size), path,
			   dump ? dir : 0, eng);
	kof_unmap_file(map, (uint64_t)st.st_size);
	return rc;
}

/* ---- what the unpackers recover -------------------------------------------- */

/*
 * The one thing here that is not a parse.
 *
 * Everything else in this tool reads structure out of the file in front of it.
 * Whether a file is packed is not structure - it is a verdict, and verdicts come
 * from modules. So this runs the engine rather than answering on its own: a
 * database is loaded, its unpackers are given the object, and what they produced
 * is reported. A second implementation of "does this look like UPX" living in a
 * tool would be a thing to keep in step with the modules, and it would disagree
 * with them exactly when it mattered.
 *
 * It needs --db for that reason, and says so rather than guessing when it has none.
 */
/*
 * What a module worked out, on its way to working it out.
 *
 * Two audiences and they want it differently, so it goes to both.
 *
 * --debug prints it as it happens, because a note that arrives before the module
 * returns is a note about work in progress and buffering it would lose that
 * ordering.
 *
 * The unpack report keeps it instead. "recovered 90796 bytes" does not say WHAT
 * unpacked it, and that is not detail - a signature written against a recovered
 * object only ever runs when that same unpacker still claims the sample, so the
 * packer is part of what the object IS. The engine does not name the producing
 * module on the callback, but the module names itself here, and it does so while
 * running and therefore before the object it produces arrives. That ordering is
 * what makes the association sound rather than a guess.
 */
/* What the last unpacker said about itself, for the object it is about to
 * produce. See on_debug and on_unpacked. */
struct unp_run {
	const char *dump_dir;     /* NULL when not dumping */
	/*
	 * The producing module's name, and only that.
	 *
	 * A module reports "UPX.ELF.version 13", "UPX.ELF.method 14" - its own
	 * name, a field, a value. The name is what a recovered object needs
	 * beside it; the fields are detail and --debug already prints them as
	 * they happen. Sticky rather than cleared per object, because a zip
	 * opener says its piece once and then yields forty entries, and every
	 * one of them came from it.
	 */
	char        via[64];
	/* Carried so a recovered object gets the same treatment its parent got.
	 * A marker inside an unpacked image is the case where "which module does
	 * this belong to" is hardest to answer by eye, so leaving the recovered
	 * objects out of it would omit the answer where it is worth most. */
	struct kof_engine *touch;
	uint32_t    produced;
	uint32_t    partial;
	int         err;
};

static int g_debug;


static void on_debug(const char *what, uint64_t value, void *user)
{
	struct unp_run *u = user;

	if (g_debug)
		printf("  debug     %-18s %10llu\n", what,
		       (unsigned long long)value);
	if (u) {
		const char *dot = strrchr(what, '.');
		size_t n = dot ? (size_t)(dot - what) : strlen(what);

		if (n >= sizeof u->via)
			n = sizeof u->via - 1u;
		memcpy(u->via, what, n);
		u->via[n] = 0;
	}
}


/* One recovered object, written whole. Separate from the region writer because a
 * region is a slice of a mapping and this is a buffer the engine handed over. */
static int write_whole(const char *path, const void *p, uint64_t n)
{
	FILE *f = fopen(path, "wb");

	if (!f) {
		fprintf(stderr, "kofexamine: cannot create %s: %s\n", path,
			strerror(errno));
		return 0;
	}
	if (n && fwrite(p, 1, (size_t)n, f) != (size_t)n) {
		fprintf(stderr, "kofexamine: short write to %s\n", path);
		fclose(f);
		return 0;
	}
	fclose(f);
	return 1;
}

static int on_unpacked(const char *name, const void *bytes, uint64_t len,
		       const struct kof_result *res, void *user)
{
	struct unp_run *u = user;
	const char *tail = strstr(name, "//");
	char tag[128], path[1024], sub[1152];

	/* The first object is the file itself, which the rest of this tool has
	 * already described in far more detail. */
	if (!tail)
		return 0;

	u->produced++;
	if (res->broken)
		u->partial++;
	/*
	 * <number>.<name>, or <number> alone.
	 *
	 * The number is what makes it unique and is the whole identity; the name is
	 * there so a directory listing is readable, and it is the label the engine
	 * already reduced to a bare basename of printable ASCII - so nothing here has
	 * to decide what to do about a separator or a "..", because neither can have
	 * survived. An entry called "../" arrives with no label at all and gets the
	 * number by itself.
	 *
	 * snprintf into a buffer sized from KOF_SRC_LABEL_MAX is what bounds it. A
	 * name is attacker chosen and archives carry long ones; the label is capped
	 * when it is made, and this is capped again where it becomes a path, because
	 * the two caps protect different things and only one of them is here.
	 */
	{
		const char *lab = strchr(tail, ':');

		if (lab)
			snprintf(tag, sizeof tag, "%u.%s", u->produced, lab + 1);
		else
			snprintf(tag, sizeof tag, "%u", u->produced);
	}
	printf("  recovered %s%-18s%s %s%10llu%s bytes", C_ID, tag, C_OFF,
	       C_SIZE, (unsigned long long)len, C_OFF);
	if (u->via[0]) {
		int packed = g_parent_format == KOF_FMT_ELF ||
			     g_parent_format == KOF_FMT_PE ||
			     g_parent_format == KOF_FMT_MACHO;

		printf("   via %s%s%s", packed ? C_BAD : C_NOTE, u->via, C_OFF);
	}
	if (res->broken)
		printf("   %s%s%s", C_BAD, kof_broken_name(res->broken), C_OFF);
	printf("\n");

	/*
	 * Writing is what needs a directory. Looking does not.
	 *
	 * These two were one branch, and that was the bug: a recovered object was
	 * only ever examined as a side effect of being dumped. For a packed sample
	 * the recovered object is the ONLY one that carries markers - the packed
	 * parent carries compressed bytes and nothing else - so --markers went
	 * silent on precisely the files it exists for, and said "nothing in the
	 * database has a marker here" while the scanner reported the child
	 * infected. Truthful about the parent and useless about the sample.
	 */
	if (!u->dump_dir) {
		if (u->touch) {
			printf("\n");
			if (examine_bytes(kof_buf_make(bytes, len), name, 0,
					  u->touch) < 0)
				u->err = 1;
		}
		return 0;
	}
	if ((size_t)snprintf(path, sizeof path, "%s/unpacked.%s", u->dump_dir, tag)
	    >= sizeof path) {
		u->err = 1;
		return 1;
	}
	if (!write_whole(path, bytes, len)) {
		u->err = 1;
		return 0;
	}

	/*
	 * And then examine what came out, exactly as though it had been the file.
	 *
	 * Stopping at the raw bytes would leave the job half done for the one person
	 * this tool is for. A signature is written against a REGION - the author has
	 * to see what CODE and DATA are once the packer is off, and those are
	 * properties of the recovered object, not of the packed one. Writing the
	 * bytes and making somebody run the tool again on them would be handing over
	 * the input to the question rather than the answer.
	 *
	 * Recursion is the engine's job and it has already done it: an object nested
	 * two layers down arrives here as its own callback, so each one gets its own
	 * directory and nothing here has to walk anything.
	 */
	if ((size_t)snprintf(sub, sizeof sub, "%s.regions", path) >= sizeof sub) {
		u->err = 1;
		return 0;
	}
	if (kof_mkdir(sub, 0777) != 0 && errno != EEXIST) {
		fprintf(stderr, "kofexamine: cannot create %s: %s\n", sub,
			strerror(errno));
		u->err = 1;
		return 0;
	}
	printf("\n");
	if (examine_bytes(kof_buf_make(bytes, len), name, sub, u->touch) < 0)
		u->err = 1;
	return 0;
}

/*
 * Run the database's unpackers over one file and report what came out.
 *
 * all_matches is on, and that is not a detail: without it the engine stops at the
 * first detection and never opens the container, which is right for scanning and
 * wrong for a tool whose entire question is what is inside.
 */
static int unpack_pass(kof_engine *eng, const char *path, const char *dump_dir,
		       int verbose, int markers)
{
	struct kof_scan_option opt;
	struct unp_run u;
	kof_scanner *sc;

	memset(&opt, 0, sizeof opt);
	memset(&u, 0, sizeof u);
	opt.all_matches = 1;
	u.dump_dir = dump_dir;
	u.touch = markers ? eng : NULL;
	g_debug = verbose;

	sc = kof_scanner_new(eng);
	if (!sc) {
		fprintf(stderr, "kofexamine: out of memory\n");
		return 0;
	}
	kof_scanner_on_debug(sc, on_debug, &u);
	kof_scan_path(sc, path, &opt, on_unpacked, &u);
	kof_scanner_free(sc);

	if (u.produced == 0)
		printf("  unpacked  nothing - no unpacker in the database claimed it\n");
	else
		printf("  unpacked  %u object(s)%s\n", u.produced,
		       u.partial ? "  (some only in part)" : "");
	return !u.err;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s [--dump] [--db <dir>] <file>...\n"
		"\n"
		"  --dump     also write each region of each file into a directory\n"
		"             beside it: <path>/_<name>_dump/<region enum name>\n"
		"  --db <dir> run that database's unpackers too, and report what\n"
		"             they recovered. With --dump the recovered objects are\n"
		"             written beside the regions as unpacked.<n>\n"
		"  --debug    also print what modules worked out along the way -\n"
		"             versions, methods, counts. Needs --db.\n"
		"  --color    force colour on; --no-color forces it off. The default\n"
		"             is colour when stdout is a terminal and NO_COLOR is unset.\n"
		"  --sources  D  where the signature sources are, so a marker row can\n"
		"             name the file and line its logic is written on. Needs\n"
		"             --markers.\n"
		"  --markers  list every database marker found in the file and whose\n"
		"             it is, including modules that did not fire, with the\n"
		"             reason each did not. Needs --db.\n",
		argv0);
}

/*
 * Arguments in any order.
 *
 * Two passes, and the reason is a bug rather than a preference: with one pass a
 * file was examined AT THE MOMENT IT WAS SEEN, so an option written after it had
 * not been read yet. "kofexamine a.elf --dump" examined a.elf without dumping and
 * then set a flag nothing went on to use - no error, no output missing, just
 * silently the wrong thing. Collecting the options first makes where they sit stop
 * mattering.
 */
int main(int argc, char **argv)
{
	const char *db = NULL;
	kof_engine *eng = NULL;
	const char *sources = NULL;
	int dump = 0, verbose = 0, markers = 0, colour = -1;
	int i, files = 0, bad = 0;

	/* First pass: the options, wherever they are. */
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--dump") == 0) {
			dump = 1;
		} else if (strcmp(argv[i], "--debug") == 0) {
			verbose = 1;
		} else if (strcmp(argv[i], "--markers") == 0) {
			markers = 1;
		} else if (strcmp(argv[i], "--sources") == 0) {
			if (++i >= argc) {
				fprintf(stderr, "%s: --sources needs a "
						"directory\n", argv[0]);
				return 2;
			}
			sources = argv[i];
		} else if (strcmp(argv[i], "--color") == 0 ||
			   strcmp(argv[i], "--colour") == 0) {
			colour = 1;
		} else if (strcmp(argv[i], "--no-color") == 0 ||
			   strcmp(argv[i], "--no-colour") == 0) {
			colour = 0;
		} else if (strcmp(argv[i], "--db") == 0) {
			if (++i >= argc) {
				fprintf(stderr, "%s: --db needs a directory\n",
					argv[0]);
				return 2;
			}
			db = argv[i];
		} else if (argv[i][0] == '-' && argv[i][1]) {
			fprintf(stderr, "%s: unrecognised argument '%s'\n",
				argv[0], argv[i]);
			usage(argv[0]);
			return 2;
		}
	}

	/* Auto unless said otherwise, and NO_COLOR wins over the terminal: this
	 * output gets piped into grep and diffed against itself, and an escape
	 * sequence in either is a bug rather than a preference. */
	if (colour < 0)
		colour = stdout_is_tty() && getenv("NO_COLOR") == NULL;
	colour_enable(colour);

	if (sources && !src_open(sources)) {
		fprintf(stderr, "%s: out of memory\n", argv[0]);
		return 2;
	}

	if (db) {
		eng = kof_engine_open(db);
		if (!eng) {
			fprintf(stderr, "%s: cannot load a database from %s\n",
				argv[0], db);
			return 2;
		}
	}

	/* Second pass: everything that was not an option is a file, and by now every
	 * option has been read whether it was written before or after it. */
	for (i = 1; i < argc; i++) {
		int r;

		if (strcmp(argv[i], "--db") == 0 ||
		    strcmp(argv[i], "--sources") == 0) {
			i++;               /* its value, already taken */
			continue;
		}
		if (argv[i][0] == '-' && argv[i][1])
			continue;

		r = examine(argv[i], dump, markers ? eng : NULL);
		if (r >= 0 && eng) {
			char dir[PATH_ROOM];
			const char *d = NULL;

			if (dump && dump_dir_for(argv[i], dir, sizeof dir))
				d = dir;
			if (!unpack_pass(eng, argv[i], d, verbose, markers))
				r = -1;
		}

		files++;
		if (r < 0) {
			kof_engine_close(eng);
			return 2;          /* could not write: see above */
		}
		if (!r)
			bad = 1;
	}

	kof_engine_close(eng);
	if (files == 0) {
		usage(argv[0]);
		return 2;
	}
	return bad ? 1 : 0;
}
