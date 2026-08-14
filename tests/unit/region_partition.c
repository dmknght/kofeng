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

struct tally {
	uint64_t objects, failures;
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
		if (n == KOF_SCAN_MAX_EXTENTS)
			printf("  NOTE %s: region 0x%x hit the extent cap\n",
			       path, regions[i]);
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

static void one_file(const char *path, struct tally *elf, struct tally *pe,
		     struct tally *gz, struct tally *ole, struct tally *zip,
		     struct tally *tar, struct tally *sz, struct tally *rar)
{
	struct kof_obj_ctx ctx;
	struct kof_elf_info *ei;
	struct kof_pe_info *pi;
	struct kof_gzip_info *gi;
	struct kof_docole_info *oi;
	struct kof_zip_info *zi;
	struct kof_tar_info *ti;
	struct kof_7z_info *si;
	struct kof_rar_info *ri;
	struct stat st;
	void *map;
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

	{
		kof_buf buf = kof_buf_make(map, (uint64_t)st.st_size);

		memset(&ctx, 0, sizeof ctx);
		if (kof_elf_sniff(buf)) {
			ei = malloc(sizeof *ei);
			if (ei && kof_elf_parse(buf, ei, &ctx)) {
				elf->objects++;
				elf->failures += (uint64_t)check(path, buf, &ctx,
					kof_elf_region_bits,
					KOF_ELF_REGION_COUNT, "ELF");
			}
			free(ei);
		} else if (kof_pe_sniff(buf)) {
			pi = malloc(sizeof *pi);
			if (pi && kof_pe_parse(buf, pi, &ctx)) {
				pe->objects++;
				pe->failures += (uint64_t)check(path, buf, &ctx,
					kof_pe_region_bits,
					KOF_PE_REGION_COUNT, "PE");
			}
			free(pi);
		} else if (kof_gzip_sniff(buf)) {
			gi = malloc(sizeof *gi);
			if (gi && kof_gzip_parse(buf, gi, &ctx)) {
				gz->objects++;
				gz->failures += (uint64_t)check(path, buf, &ctx,
					kof_gzip_region_bits,
					KOF_GZIP_REGION_COUNT, "gzip");
			}
			free(gi);
		} else if (kof_docole_sniff(buf)) {
			oi = malloc(sizeof *oi);
			if (oi && kof_docole_parse(buf, oi, &ctx)) {
				ole->objects++;
				ole->failures += (uint64_t)check(path, buf, &ctx,
					kof_docole_region_bits,
					KOF_DOCOLE_REGION_COUNT, "docole");
			}
			free(oi);
		} else if (kof_zip_sniff(buf)) {
			zi = malloc(sizeof *zi);
			if (zi && kof_zip_parse(buf, zi, &ctx)) {
				zip->objects++;
				zip->failures += (uint64_t)check(path, buf, &ctx,
					kof_zip_region_bits,
					KOF_ZIP_REGION_COUNT, "zip");
			}
			free(zi);
		} else if (kof_tar_sniff(buf)) {
			ti = malloc(sizeof *ti);
			if (ti && kof_tar_parse(buf, ti, &ctx)) {
				tar->objects++;
				tar->failures += (uint64_t)check(path, buf, &ctx,
					kof_tar_region_bits,
					KOF_TAR_REGION_COUNT, "tar");
			}
			free(ti);
		} else if (kof_rar_sniff(buf)) {
			ri = malloc(sizeof *ri);
			if (ri && kof_rar_parse(buf, ri, &ctx)) {
				rar->objects++;
				rar->failures += (uint64_t)check(path, buf, &ctx,
					kof_rar_region_bits,
					KOF_RAR_REGION_COUNT, "rar");
			}
			free(ri);
		} else if (kof_7z_sniff(buf)) {
			si = malloc(sizeof *si);
			if (si && kof_7z_parse(buf, si, &ctx)) {
				sz->objects++;
				sz->failures += (uint64_t)check(path, buf, &ctx,
					kof_7z_region_bits,
					KOF_7Z_REGION_COUNT, "7z");
			}
			free(si);
		}
	}
	munmap(map, (size_t)st.st_size);
}

static void walk(const char *dir, struct tally *elf, struct tally *pe,
		 struct tally *gz, struct tally *ole, struct tally *zip,
		     struct tally *tar, struct tally *sz, struct tally *rar)
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
		one_file(path, elf, pe, gz, ole, zip, tar, sz, rar);
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
		"/usr/share/man/man1", "/usr/share/i18n/charmaps"
	};
	struct tally elf = { 0, 0 }, pe = { 0, 0 }, gz = { 0, 0 },
		     ole = { 0, 0 }, zip = { 0, 0 }, tar = { 0, 0 }, rar = { 0, 0 },
		     sz = { 0, 0 };
	int i;

	if (argc > 1)
		for (i = 1; i < argc; i++)
			walk(argv[i], &elf, &pe, &gz, &ole, &zip, &tar, &sz, &rar);
	else
		for (i = 0; i < (int)(sizeof defaults / sizeof defaults[0]); i++)
			walk(defaults[i], &elf, &pe, &gz, &ole, &zip, &tar, &sz, &rar);

	printf("partition: ELF %llu/%llu  PE %llu/%llu  gzip %llu/%llu  "
	       "docole %llu/%llu  zip %llu/%llu  tar %llu/%llu  7z %llu/%llu  "
	       "rar %llu/%llu",
	       (unsigned long long)(elf.objects - elf.failures),
	       (unsigned long long)elf.objects,
	       (unsigned long long)(pe.objects - pe.failures),
	       (unsigned long long)pe.objects,
	       (unsigned long long)(gz.objects - gz.failures),
	       (unsigned long long)gz.objects,
	       (unsigned long long)(ole.objects - ole.failures),
	       (unsigned long long)ole.objects,
	       (unsigned long long)(zip.objects - zip.failures),
	       (unsigned long long)zip.objects,
	       (unsigned long long)(tar.objects - tar.failures),
	       (unsigned long long)tar.objects,
	       (unsigned long long)(sz.objects - sz.failures),
	       (unsigned long long)sz.objects,
	       (unsigned long long)(rar.objects - rar.failures),
	       (unsigned long long)rar.objects);
	if (elf.objects == 0 && pe.objects == 0 && gz.objects == 0 &&
	    ole.objects == 0 && zip.objects == 0 && tar.objects == 0 &&
	    sz.objects == 0) {
		printf("  (no objects found - nothing tested)\n");
		return 0;
	}
	printf("\n");
	return (elf.failures || pe.failures || gz.failures || ole.failures ||
		zip.failures || tar.failures || sz.failures ||
		rar.failures) ? 1 : 0;
}