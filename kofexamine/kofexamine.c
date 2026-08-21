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
struct fmt {
	uint32_t    view_size;
	int       (*sniff)(kof_buf);
	int       (*parse)(kof_buf, void *, struct kof_obj_ctx *);
	const uint32_t *regions;
	uint32_t    n_regions;
	const char *(*region_name)(uint32_t);
	const char *(*anomaly_name)(unsigned);
	/*
	 * The bytes as well as the view, because a printer may need to show text
	 * that lives in the object rather than in the parse - a zip keeps its entry
	 * names in the file and the view only points at them. Every printer takes
	 * it and most ignore it, which is cheaper than a second callback shape.
	 */
	void      (*print)(const void *, const struct kof_obj_ctx *, kof_buf);
	/*
	 * The anomaly word, fetched rather than reached for.
	 *
	 * This was a cast to whichever view the format was not - PE if the printer
	 * was print_pe, ELF otherwise - and it read the right field only because
	 * gzip happens to lay its header out like ELF's. The first format that did
	 * not printed an anomaly it had never set. One line per format beats one
	 * conditional that has to be right about every format at once.
	 */
	uint64_t  (*anomalies)(const void *);
};

static int elf_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_elf_parse(b, (struct kof_elf_info *)v, c);
}

static int gzip_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_gzip_parse(b, (struct kof_gzip_info *)v, c);
}

static int docole_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_docole_parse(b, (struct kof_docole_info *)v, c);
}

static int zip_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_zip_parse(b, (struct kof_zip_info *)v, c);
}

static int tar_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_tar_parse(b, (struct kof_tar_info *)v, c);
}

static int rtf_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_rtf_parse(b, (struct kof_rtf_info *)v, c);
}

static int xz_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_xz_parse(b, (struct kof_xz_info *)v, c);
}

static int rar_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_rar_parse(b, (struct kof_rar_info *)v, c);
}

static int sevenzip_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_7z_parse(b, (struct kof_7z_info *)v, c);
}

static int pe_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_pe_parse(b, (struct kof_pe_info *)v, c);
}

/* An offset that could not be resolved prints as what it is, not as a number
 * that would be mistaken for one. */
static void put_off(const char *label, uint64_t v)
{
	if (v == KOF_NA)
		printf("%s=n/a", label);
	else if (v == KOF_BROKEN)
		printf("%s=unresolved", label);
	else
		printf("%s=%llu", label, (unsigned long long)v);
}

/* In the order everyone writes them, not the order the bits happen to sit in. */
static void put_perm(uint32_t p)
{
	putchar((p & 4) ? 'R' : '-');
	putchar((p & 2) ? 'W' : '-');
	putchar((p & 1) ? 'X' : '-');
}

static void print_elf(const void *view, const struct kof_obj_ctx *ctx,
		      kof_buf buf)
{
	const struct kof_elf_info *e = view;
	uint32_t i;

	(void)buf;

	printf("  class     %s %s  type=%u machine=%u\n",
	       e->elf_class == KOF_ELFCLASS_64 ? "ELF64" : "ELF32",
	       e->elf_data == KOF_ELFDATA_BE ? "big-endian" : "little-endian",
	       e->e_type, e->e_machine);
	printf("  entry     addr=0x%llx ", (unsigned long long)e->entry_addr);
	put_off("off", ctx->entry_off);
	printf(" perm=");
	put_perm(e->entry_perm);
	printf("\n");
	printf("  segments  %u of %u declared\n", e->phnum, e->phnum_claimed);
	for (i = 0; i < e->seg_count; i++)
		printf("     type=%-2u off=%-9llu size=%-9llu vaddr=0x%-10llx perm=%s%s%s\n",
		       e->seg[i].type, (unsigned long long)e->seg[i].file_off,
		       (unsigned long long)e->seg[i].file_size,
		       (unsigned long long)e->seg[i].mem_addr,
		       (e->seg[i].perm & KOF_PERM_R) ? "R" : "-",
		       (e->seg[i].perm & KOF_PERM_W) ? "W" : "-",
		       (e->seg[i].perm & KOF_PERM_X) ? "X" : "-");
	printf("  sections  %u of %u declared\n", e->shnum, e->shnum_claimed);
	for (i = 0; i < e->sec_count; i++)
		printf("     %-20s off=%-9llu size=%-9llu type=%u\n",
		       e->sec[i].name, (unsigned long long)e->sec[i].file_off,
		       (unsigned long long)e->sec[i].file_size, e->sec[i].type);
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
	printf("  sections  %u of %u declared\n", p->nsec, p->nsec_claimed);
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
	if (g->trailer_off)
		printf("  trailer   off=%llu crc=0x%08x isize=%u%s\n",
		       (unsigned long long)g->trailer_off, g->crc32, g->isize,
		       g->data_len && g->isize / g->data_len >= 100u
		       ? "   <- declared expansion is large" : "");
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
	       (unsigned long long)o->resource_bytes,
	       o->macro_bytes > KOF_DOCOLE_MACRO_SUSPECT
	       ? "   <- macros are larger than any honest document" : "");

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

static uint64_t anom_elf(const void *v)
{
	return ((const struct kof_elf_info *)v)->anomalies;
}

static uint64_t anom_pe(const void *v)
{
	return ((const struct kof_pe_info *)v)->anomalies;
}

static uint64_t anom_gzip(const void *v)
{
	return ((const struct kof_gzip_info *)v)->anomalies;
}

static uint64_t anom_docole(const void *v)
{
	return ((const struct kof_docole_info *)v)->anomalies;
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
			printf("   <- ESCAPES THE EXTRACT ROOT");
		if (e->suspicious & KOF_ZIP_ENT_ENCRYPTED)
			printf("   <- encrypted");
		if (e->suspicious & KOF_ZIP_ENT_NO_LOCAL)
			printf("   <- no local header there");
		if (e->suspicious & KOF_ZIP_ENT_RATIO)
			printf("   <- declared expansion is absurd");
		printf("\n");
	}
	if (z->n_entries > shown)
		printf("    ... %u more\n", z->n_entries - shown);
}

static uint64_t anom_zip(const void *v)
{
	return ((const struct kof_zip_info *)v)->anomalies;
}

/*
 * The subtype's name, which only means anything alongside the format.
 *
 * Here rather than in a format header because it is a spelling for a person, and
 * both enums are already the values the header field holds - elf.h and pe.h say
 * what they mean, and this says how to print them.
 */
static const char *subtype_name(uint8_t fmt, uint8_t sub)
{
	if (fmt == KOF_FMT_ELF)
		switch (sub) {
		case KOF_ELF_NONE: return "ET_NONE";
		case KOF_ELF_REL:  return "ET_REL";
		case KOF_ELF_EXEC: return "ET_EXEC";
		case KOF_ELF_DYN:  return "ET_DYN";
		case KOF_ELF_CORE: return "ET_CORE";
		default:           return "ET_?";
		}
	if (fmt == KOF_FMT_PE)
		switch (sub) {
		case KOF_PE_EXE: return "EXE";
		case KOF_PE_DLL: return "DLL";
		case KOF_PE_SYS: return "SYS";
		default:         return "?";
		}
	return 0;
}

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
	printf("  declared  %llu bytes of content%s\n",
	       (unsigned long long)t->total_size,
	       t->end_off ? "" : "   <- no end blocks: cut short");

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
			printf("   <- ESCAPES THE EXTRACT ROOT");
		if (e->suspicious & KOF_TAR_ENT_PAST_EOF)
			printf("   <- content is not in this file");
		if (e->suspicious & KOF_TAR_ENT_SLACK)
			printf("   <- padding is not zeroes");
		if (e->suspicious & KOF_TAR_ENT_BAD_SUM)
			printf("   <- checksum disagrees");
		printf("\n");
	}
	if (t->n_entries > shown)
		printf("    ... %u more\n", t->n_entries - shown);
}

static uint64_t anom_tar(const void *v)
{
	return ((const struct kof_tar_info *)v)->anomalies;
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

static uint64_t anom_7z(const void *v)
{
	return ((const struct kof_7z_info *)v)->anomalies;
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
			printf("   <- ESCAPES THE EXTRACT ROOT");
		if (e->suspicious & KOF_RAR_ENT_ENCRYPTED)
			printf("   <- encrypted");
		if (e->suspicious & KOF_RAR_ENT_PAST_EOF)
			printf("   <- data runs past the end");
		if (e->suspicious & KOF_RAR_ENT_RATIO)
			printf("   <- declared expansion is absurd");
		if (e->suspicious & KOF_RAR_ENT_SPLIT)
			printf("   <- split across volumes");
		printf("\n");
	}
	if (r->n_entries > shown)
		printf("    ... %u more\n", r->n_entries - shown);
}

static uint64_t anom_rar(const void *v)
{
	return ((const struct kof_rar_info *)v)->anomalies;
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
			printf("   <- a filter runs in front of the coder");
		if (b->suspicious & KOF_XZ_BLK_PAST_EOF)
			printf("   <- data runs past the end");
		if (b->suspicious & KOF_XZ_BLK_RATIO)
			printf("   <- declared expansion is absurd");
		printf("\n");
	}
	if (x->n_blocks > shown)
		printf("    ... %u more\n", x->n_blocks - shown);
}

static uint64_t anom_xz(const void *v)
{
	return ((const struct kof_xz_info *)v)->anomalies;
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
			printf("   <- a compound file");
		if (o->suspicious & KOF_RTF_OBJ_OLE1)
			printf("   <- an OLE1 package");
		if (o->suspicious & KOF_RTF_OBJ_UPDATE)
			printf("   <- OPENS WITHOUT BEING CLICKED");
		if (o->suspicious & KOF_RTF_OBJ_BAD_HEX)
			printf("   <- the hex does not pair up");
		printf("\n");
	}
}

static int pdf_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_pdf_parse(b, (struct kof_pdf_info *)v, c);
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

static uint64_t anom_pdf(const void *v)
{
	return ((const struct kof_pdf_info *)v)->anomalies;
}

static uint64_t anom_rtf(const void *v)
{
	return ((const struct kof_rtf_info *)v)->anomalies;
}

static const struct fmt formats[] = {
	{ (uint32_t)sizeof(struct kof_elf_info), kof_elf_sniff, elf_parse_thunk,
	  kof_elf_region_bits, KOF_ELF_REGION_COUNT,
	  kof_elf_region_name, kof_elf_anomaly_name, print_elf, anom_elf },
	{ (uint32_t)sizeof(struct kof_pe_info), kof_pe_sniff, pe_parse_thunk,
	  kof_pe_region_bits, KOF_PE_REGION_COUNT,
	  kof_pe_region_name, kof_pe_anomaly_name, print_pe, anom_pe },
	{ (uint32_t)sizeof(struct kof_gzip_info), kof_gzip_sniff, gzip_parse_thunk,
	  kof_gzip_region_bits, KOF_GZIP_REGION_COUNT,
	  kof_gzip_region_name, kof_gzip_anomaly_name, print_gzip, anom_gzip },
	{ (uint32_t)sizeof(struct kof_docole_info), kof_docole_sniff,
	  docole_parse_thunk, kof_docole_region_bits, KOF_DOCOLE_REGION_COUNT,
	  kof_docole_region_name, kof_docole_anomaly_name, print_docole,
	  anom_docole },
	{ (uint32_t)sizeof(struct kof_zip_info), kof_zip_sniff, zip_parse_thunk,
	  kof_zip_region_bits, KOF_ZIP_REGION_COUNT,
	  kof_zip_region_name, kof_zip_anomaly_name, print_zip, anom_zip },
	{ (uint32_t)sizeof(struct kof_tar_info), kof_tar_sniff, tar_parse_thunk,
	  kof_tar_region_bits, KOF_TAR_REGION_COUNT,
	  kof_tar_region_name, kof_tar_anomaly_name, print_tar, anom_tar },
	{ (uint32_t)sizeof(struct kof_7z_info), kof_7z_sniff, sevenzip_parse_thunk,
	  kof_7z_region_bits, KOF_7Z_REGION_COUNT,
	  kof_7z_region_name, kof_7z_anomaly_name, print_7z, anom_7z },
	{ (uint32_t)sizeof(struct kof_rar_info), kof_rar_sniff, rar_parse_thunk,
	  kof_rar_region_bits, KOF_RAR_REGION_COUNT,
	  kof_rar_region_name, kof_rar_anomaly_name, print_rar, anom_rar },
	{ (uint32_t)sizeof(struct kof_xz_info), kof_xz_sniff, xz_parse_thunk,
	  kof_xz_region_bits, KOF_XZ_REGION_COUNT,
	  kof_xz_region_name, kof_xz_anomaly_name, print_xz, anom_xz },
	{ (uint32_t)sizeof(struct kof_rtf_info), kof_rtf_sniff, rtf_parse_thunk,
	  kof_rtf_region_bits, KOF_RTF_REGION_COUNT,
	  kof_rtf_region_name, kof_rtf_anomaly_name, print_rtf, anom_rtf },
	{ (uint32_t)sizeof(struct kof_pdf_info), kof_pdf_sniff, pdf_parse_thunk,
	  kof_pdf_region_bits, KOF_PDF_REGION_COUNT,
	  kof_pdf_region_name, kof_pdf_anomaly_name, print_pdf, anom_pdf }
};

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

static int layout_file(const char *dir, const struct fmt *f,
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
static int examine_bytes(kof_buf buf, const char *display, const char *dir)
{
	struct kof_obj_ctx ctx;
	void *view = 0;
	const struct fmt *f = 0;
	uint64_t total = 0;
	uint32_t i;
	int rc = 0;
	const int dump = dir != 0;

	{
		memset(&ctx, 0, sizeof ctx);
		printf("%s\n", display);

		for (i = 0; i < sizeof formats / sizeof formats[0]; i++) {
			if (!formats[i].sniff(buf))
				continue;
			view = malloc(formats[i].view_size);
			if (view && formats[i].parse(buf, view, &ctx))
				f = &formats[i];
			else {
				free(view);
				view = 0;
			}
			break;
		}
		if (!f) {
			printf("  format    unrecognised, %llu bytes\n",
			       (unsigned long long)buf.n);
			rc = 1;
			goto out;
		}

		/*
		 * The subtype spelled in the format's own vocabulary, because that is
		 * what a module declares. A number would be no use: the same value
		 * means REL for an ELF and DLL for a PE, and which one it is is
		 * exactly what the reader is here to find out.
		 */
		printf("  format    %s %s%s%s  %llu bytes\n",
		       kof_format_name(ctx.format), kof_arch_name(ctx.arch),
		       subtype_name(ctx.format, ctx.subtype) ? " " : "",
		       subtype_name(ctx.format, ctx.subtype)
		       ? subtype_name(ctx.format, ctx.subtype) : "",
		       (unsigned long long)buf.n);
		f->print(view, &ctx, buf);

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
			printf(" %s=%llu", short_region(rn),
			       (unsigned long long)len);
		}
		/* The partition, stated rather than assumed: if these do not add
		 * up, every region-scoped search on this object is looking at the
		 * wrong bytes and this is where it shows. */
		printf("  (sum %llu of %llu%s)\n", (unsigned long long)total,
		       (unsigned long long)buf.n,
		       total == buf.n ? "" : " MISMATCH");

		{
			uint64_t anom = f->anomalies(view);
			if (anom) {
				printf("  anomalies");
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
				printf("\n");
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
		rc = 1;
	}
out:
	free(view);
	return rc;
}

/*
 * The file on disk, mapped and handed to the same routine as everything else.
 */
static int examine(const char *path, int dump)
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
			   dump ? dir : 0);
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
/* Printed as it happens: a note that arrives before the module returns is a note
 * about work in progress, and buffering it would lose that ordering. */
static void on_debug(const char *what, uint64_t value, void *user)
{
	(void)user;
	printf("  debug     %-18s %10llu\n", what, (unsigned long long)value);
}

struct unp_run {
	const char *dump_dir;     /* NULL when not dumping */
	uint32_t    produced;
	uint32_t    partial;
	int         err;
};

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
	printf("  recovered %-18s %10llu bytes%s%s\n", tag,
	       (unsigned long long)len, res->broken ? "   " : "",
	       res->broken ? kof_broken_name(res->broken) : "");

	if (!u->dump_dir)
		return 0;
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
	if (examine_bytes(kof_buf_make(bytes, len), name, sub) < 0)
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
		       int verbose)
{
	struct kof_scan_option opt;
	struct unp_run u;
	kof_scanner *sc;

	memset(&opt, 0, sizeof opt);
	memset(&u, 0, sizeof u);
	opt.all_matches = 1;
	u.dump_dir = dump_dir;

	sc = kof_scanner_new(eng);
	if (!sc) {
		fprintf(stderr, "kofexamine: out of memory\n");
		return 0;
	}
	if (verbose)
		kof_scanner_on_debug(sc, on_debug, NULL);
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
		"             versions, methods, counts. Needs --db.\n",
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
	int dump = 0, verbose = 0;
	int i, files = 0, bad = 0;

	/* First pass: the options, wherever they are. */
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--dump") == 0) {
			dump = 1;
		} else if (strcmp(argv[i], "--debug") == 0) {
			verbose = 1;
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

		if (strcmp(argv[i], "--db") == 0) {
			i++;               /* its value, already taken */
			continue;
		}
		if (argv[i][0] == '-' && argv[i][1])
			continue;

		r = examine(argv[i], dump);
		if (r >= 0 && eng) {
			char dir[PATH_ROOM];
			const char *d = NULL;

			if (dump && dump_dir_for(argv[i], dir, sizeof dir))
				d = dir;
			if (!unpack_pass(eng, argv[i], d, verbose))
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
