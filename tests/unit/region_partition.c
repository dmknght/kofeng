/*
 * region_partition - every region of a format must partition the object.
 *
 * The property under test: for any object a collector claims, the regions it
 * defines cover every byte exactly once. Not "roughly", not "mostly" - the sum of
 * the region lengths equals the file size, and no two regions overlap.
 *
 * It matters because the whole scan-scoping design rests on it. A module that
 * asks for CODE | DATA gets one pass over the union, and that is only true if the
 * two do not overlap; a byte in no region is a byte no signature can reach, and a
 * byte in two is a byte searched twice with no way to notice.
 *
 * ELF held this over 319 objects while it was being developed. PE is new and has
 * held it over eight, which is the corpus that exists. Both numbers are printed
 * so neither gets mistaken for the other.
 *
 * The region lists come from the collectors rather than being written out here, so
 * a region added to a format is covered by this test the moment it exists.
 *
 * Directories to walk can be given on the command line. With none, it uses the
 * PE corpus in the tree and /usr/bin, and skips whichever is absent rather than
 * failing - a machine without one of them should not fail the build.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <kofmod/kofsig.h>
#include <kofmod/elf.h>
#include <kofmod/pe.h>

#include "../../libkofeng/kofparsers/binaries/elf_parse.h"
#include "../../libkofeng/kofparsers/binaries/pe_parse.h"
#include "../../libkofeng/kofparsers/containers/gzip_parse.h"
#include "../../libkofeng/kofparsers/containers/docole_parse.h"
#include "../../libkofeng/kofparsers/containers/zip_parse.h"
#include "../../libkofeng/kofparsers/containers/tar_parse.h"
#include "../../libkofeng/kofparsers/containers/sevenzip_parse.h"
#include "../../libkofeng/kofparsers/containers/rar_parse.h"
#include "../../libkofeng/kofparsers/containers/xz_parse.h"
#include "../../libkofeng/kofparsers/containers/rtf_parse.h"
#include "../../libkofeng/kofparsers/containers/pdf_parse.h"

struct tally {
	uint64_t objects, failures, capped;
};

static int cmp_range(const void *a, const void *b)
{
	const struct kof_range *x = a, *y = b;

	if (x->off < y->off)
		return -1;
	return x->off > y->off;
}

/*
 * Collect every extent of every region, then check the union.
 *
 * Sorting and walking rather than a bitmap over the file: a bitmap would be the
 * obvious way and would need memory proportional to the object, which is the one
 * thing this is meant to be able to run over a whole directory of them.
 */
/*
 * Returns 0 for a partition that holds, 1 for one that does not, and -1 for a file
 * where the question cannot be asked.
 *
 * The third case is real and is not a failure: a region is resolved into a caller's
 * buffer of KOF_SCAN_MAX_EXTENTS, and a file with more extents than that gets the
 * first of them plus KOF_BROKEN_LIMIT on the scan. What comes back is then a PART of
 * the region by design, so checking it against the whole object would report a hole
 * the parser did not leave. Measured on this machine one benign 1.4MB PDF does it:
 * four thousand objects with a stream each, and the objects and the gaps between
 * them are each an extent.
 */
static int check(const char *path, kof_buf buf, struct kof_obj_ctx *ctx,
		 const uint32_t *regions, uint32_t n_regions, const char *fmt)
{
	/* Static: KOF_SCAN_MAX_EXTENTS is sized for an archive with thousands of
	 * runs, and eight times that on the stack is megabytes. One test, one
	 * thread, so a single copy is all that is ever needed. */
	static struct kof_range all[KOF_SCAN_MAX_EXTENTS * 8];
	static struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	uint32_t n_all = 0, i, k;
	uint64_t covered = 0, cursor = 0;
	int bad = 0;

	for (i = 0; i < n_regions; i++) {
		uint32_t n = ctx->resolve_scan
			   ? ctx->resolve_scan(ctx, regions[i], ext,
					       KOF_SCAN_MAX_EXTENTS)
			   : 0;
		if (n == KOF_SCAN_MAX_EXTENTS) {
			printf("  NOTE %s [%s]: region 0x%x has more extents "
			       "than one resolve holds - partition not checked\n",
			       path, fmt, regions[i]);
			return -1;
		}
		for (k = 0; k < n; k++) {
			if (n_all == sizeof all / sizeof all[0]) {
				printf("  FAIL %s: more extents than the test holds\n",
				       path);
				return 1;
			}
			all[n_all++] = ext[k];
		}
	}

	qsort(all, n_all, sizeof all[0], cmp_range);

	for (i = 0; i < n_all; i++) {
		if (all[i].off < cursor) {
			printf("  FAIL %s [%s]: overlap at %llu (previous ended %llu)\n",
			       path, fmt, (unsigned long long)all[i].off,
			       (unsigned long long)cursor);
			bad = 1;
			break;
		}
		if (all[i].off > cursor) {
			printf("  FAIL %s [%s]: %llu byte(s) in no region at %llu\n",
			       path, fmt, (unsigned long long)(all[i].off - cursor),
			       (unsigned long long)cursor);
			bad = 1;
			break;
		}
		cursor = all[i].off + all[i].len;
		covered += all[i].len;
	}
	if (!bad && covered != buf.n) {
		printf("  FAIL %s [%s]: covered %llu of %llu byte(s)\n", path, fmt,
		       (unsigned long long)covered, (unsigned long long)buf.n);
		bad = 1;
	}
	return bad;
}

/*
 * The collectors, in the order the engine tries them.
 *
 * The same order and not a convenient one: which format a polyglot is read as is
 * decided by that order, so a test that used its own would be checking a partition
 * the scanner never computes.
 */
typedef int (*rp_parse)(kof_buf, void *, struct kof_obj_ctx *);

#define RP_WRAP(name, type, fn)                                            \
	static int name(kof_buf b, void *v, struct kof_obj_ctx *c)         \
	{ return fn(b, (type *)v, c); }

RP_WRAP(q_elf,    struct kof_elf_info,    kof_elf_parse)
RP_WRAP(q_pe,     struct kof_pe_info,     kof_pe_parse)
RP_WRAP(q_gzip,   struct kof_gzip_info,   kof_gzip_parse)
RP_WRAP(q_docole, struct kof_docole_info, kof_docole_parse)
RP_WRAP(q_zip,    struct kof_zip_info,    kof_zip_parse)
RP_WRAP(q_tar,    struct kof_tar_info,    kof_tar_parse)
RP_WRAP(q_7z,     struct kof_7z_info,     kof_7z_parse)
RP_WRAP(q_rar,    struct kof_rar_info,    kof_rar_parse)
RP_WRAP(q_xz,     struct kof_xz_info,     kof_xz_parse)
RP_WRAP(q_rtf,    struct kof_rtf_info,    kof_rtf_parse)
RP_WRAP(q_pdf,    struct kof_pdf_info,    kof_pdf_parse)

static const struct fmt {
	const char *name;
	int (*sniff)(kof_buf);
	rp_parse parse;
	size_t view_size;
	const uint32_t *bits;
	uint32_t n_bits;
} fmts[] = {
	{ "ELF",    kof_elf_sniff,    q_elf,    sizeof(struct kof_elf_info),    kof_elf_region_bits,    KOF_ELF_REGION_COUNT },
	{ "PE",     kof_pe_sniff,     q_pe,     sizeof(struct kof_pe_info),     kof_pe_region_bits,     KOF_PE_REGION_COUNT },
	{ "gzip",   kof_gzip_sniff,   q_gzip,   sizeof(struct kof_gzip_info),   kof_gzip_region_bits,   KOF_GZIP_REGION_COUNT },
	{ "docole", kof_docole_sniff, q_docole, sizeof(struct kof_docole_info), kof_docole_region_bits, KOF_DOCOLE_REGION_COUNT },
	{ "zip",    kof_zip_sniff,    q_zip,    sizeof(struct kof_zip_info),    kof_zip_region_bits,    KOF_ZIP_REGION_COUNT },
	{ "tar",    kof_tar_sniff,    q_tar,    sizeof(struct kof_tar_info),    kof_tar_region_bits,    KOF_TAR_REGION_COUNT },
	{ "7z",     kof_7z_sniff,     q_7z,     sizeof(struct kof_7z_info),     kof_7z_region_bits,     KOF_7Z_REGION_COUNT },
	{ "rar",    kof_rar_sniff,    q_rar,    sizeof(struct kof_rar_info),    kof_rar_region_bits,    KOF_RAR_REGION_COUNT },
	{ "xz",     kof_xz_sniff,     q_xz,     sizeof(struct kof_xz_info),     kof_xz_region_bits,     KOF_XZ_REGION_COUNT },
	{ "rtf",    kof_rtf_sniff,    q_rtf,    sizeof(struct kof_rtf_info),    kof_rtf_region_bits,    KOF_RTF_REGION_COUNT },
	{ "pdf",    kof_pdf_sniff,    q_pdf,    sizeof(struct kof_pdf_info),    kof_pdf_region_bits,    KOF_PDF_REGION_COUNT }
};
#define N_FMT (sizeof fmts / sizeof fmts[0])

static void one_file(const char *path, struct tally *t)
{
	struct kof_obj_ctx ctx;
	struct stat st;
	void *map;
	kof_buf buf;
	uint32_t k;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return;
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
		close(fd);
		return;
	}
	map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (map == MAP_FAILED)
		return;

	buf = kof_buf_make(map, (uint64_t)st.st_size);
	for (k = 0; k < N_FMT; k++) {
		void *view;

		if (!fmts[k].sniff(buf))
			continue;
		/* The view is allocated after the sniff and freed before the next
		 * file, so a run over a large tree holds one of them and not
		 * eleven. */
		view = malloc(fmts[k].view_size);
		if (view) {
			memset(&ctx, 0, sizeof ctx);
			if (fmts[k].parse(buf, view, &ctx)) {
				int r = check(path, buf, &ctx, fmts[k].bits,
					      fmts[k].n_bits, fmts[k].name);

				if (r < 0)
					t[k].capped++;
				else {
					t[k].objects++;
					t[k].failures += (uint64_t)r;
				}
			}
			free(view);
		}
		break;
	}
	munmap(map, (size_t)st.st_size);
}

static void walk(const char *dir, struct tally *t)
{
	DIR *d = opendir(dir);
	struct dirent *de;
	char path[4096];

	if (!d)
		return;
	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.')
			continue;
		if ((size_t)snprintf(path, sizeof path, "%s/%s", dir, de->d_name)
		    >= sizeof path)
			continue;
		one_file(path, t);
	}
	closedir(d);
}

int main(int argc, char **argv)
{
	/*
	 * A directory per format, so every collector meets real files rather than
	 * only the ones a hostile generator makes up.
	 *
	 * Two candidates for gzip because neither is on every system: manual pages
	 * are compressed on most distributions and not on all, and the locale
	 * charmaps are there wherever glibc is. A directory that does not exist is
	 * skipped silently, and the count printed at the end says whether anything
	 * was actually found - "gzip 0/0" is visibly nothing tested rather than a
	 * pass.
	 */
	static const char *defaults[] = {
		"build/test/fixtures", "/usr/bin",
		"/usr/share/man/man1", "/usr/share/i18n/charmaps",
		"/usr/share/xml/docbook/xml/xsl-stylesheets"
	};
	struct tally t[N_FMT];
	uint64_t seen = 0, failed = 0;
	uint32_t k;
	int i;

	memset(t, 0, sizeof t);
	if (argc > 1)
		for (i = 1; i < argc; i++)
			walk(argv[i], t);
	else
		for (i = 0; i < (int)(sizeof defaults / sizeof defaults[0]); i++)
			walk(defaults[i], t);

	printf("partition:");
	for (k = 0; k < N_FMT; k++) {
		printf("  %s %llu/%llu", fmts[k].name,
		       (unsigned long long)(t[k].objects - t[k].failures),
		       (unsigned long long)t[k].objects);
		if (t[k].capped)
			printf("(+%llu capped)", (unsigned long long)t[k].capped);
		seen += t[k].objects;
		failed += t[k].failures;
	}
	if (!seen) {
		printf("  (no objects found - nothing tested)\n");
		return 0;
	}
	printf("\n");
	return failed != 0;
}
