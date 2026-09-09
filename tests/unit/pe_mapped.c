/*
 * pe_mapped - a PE the loader has mapped is still a PE, and its regions still
 * partition it.
 *
 * WHAT IS BEING PROVED, AND WHY IT NEEDED PROVING SEPARATELY.
 *
 * The scan regions of a PE come from the section table, and the section table
 * states two different sets of numbers: where a section is in the FILE, and
 * where the loader puts it in MEMORY. Every region resolver in this tree used
 * the first, because until memory could be scanned the first was the only one
 * that was ever true.
 *
 * Reading an image out of a process makes the second one true instead, and the
 * failure mode of getting that wrong is the quiet kind: CODE resolves to a
 * range that is inside the object, is full of bytes, and is not the code. No
 * error, no anomaly, just every region rule running against the wrong input and
 * matching nothing. So this test does what region_partition does for the file
 * shape, over the same files laid out the other way.
 *
 * Three properties:
 *
 *   1. The mapped regions partition the mapped image - sum of lengths equals
 *      SizeOfImage, and no two regions overlap.
 *   2. CODE moves. Its first range starts at the first executable section's
 *      VirtualAddress, not its PointerToRawData. A file where the two happen to
 *      be equal proves nothing and is not counted.
 *   3. The file shape is unchanged, so this could not have been bought by
 *      breaking what already worked.
 *
 * The images are built here rather than read from a process: the loader's job,
 * for this purpose, is memcpy per section into a zeroed SizeOfImage buffer, and
 * a test that needed a running Windows process could not run on the CI that
 * has to catch the regression.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>

#include <kofmod/kofsig.h>
#include <kofmod/pe.h>

#include "../../libkofeng/kofparsers/binaries/pe_parse.h"

struct tally {
	uint64_t seen;          /* PE files parsed both ways */
	uint64_t part_file;     /* file layout partitioned */
	uint64_t part_mapped;   /* mapped layout partitioned */
	uint64_t moved;         /* CODE resolved to the VA, not the file offset */
	uint64_t same_addr;     /* the two were equal - proves nothing */
	uint64_t bad;
};

static int cmp_range(const void *a, const void *b)
{
	const struct kof_range *x = a, *y = b;

	if (x->off < y->off)
		return -1;
	return x->off > y->off;
}

/*
 * Sum every region, check they do not overlap, return the total.
 *
 * The overlap check is the half that a sum alone would miss: two regions each
 * claiming the same thousand bytes while a third claims none still adds up.
 */
static uint64_t partition_of(const struct kof_obj_ctx *ctx, int *overlap)
{
	struct kof_range r[4096];
	const uint32_t *bits;
	uint32_t n_bits, i, k, n = 0;
	uint64_t sum = 0;

	*overlap = 0;
	bits = kof_pe_region_bits;
	n_bits = KOF_PE_REGION_COUNT;

	for (k = 0; k < n_bits; k++) {
		uint32_t got = ctx->resolve_scan(ctx, bits[k], r + n,
						 4096u - n);
		for (i = 0; i < got; i++)
			sum += r[n + i].len;
		n += got;
		if (n >= 4096u)
			return sum;     /* capped; caller treats as inconclusive */
	}
	qsort(r, n, sizeof r[0], cmp_range);
	for (i = 1; i < n; i++)
		if (r[i].off < r[i - 1].off + r[i - 1].len)
			*overlap = 1;
	return sum;
}

static uint64_t first_code(const struct kof_obj_ctx *ctx, int *found)
{
	struct kof_range r[64];
	uint32_t n = ctx->resolve_scan(ctx, KOF_SCAN_PE_CODE, r, 64u);
	uint32_t i;
	uint64_t lo = 0;

	*found = 0;
	for (i = 0; i < n; i++)
		if (!*found || r[i].off < lo) {
			lo = r[i].off;
			*found = 1;
		}
	return lo;
}

static void one_file(const char *path, struct tally *t)
{
	struct kof_pe_info info;
	struct kof_obj_ctx ctx;
	struct stat st;
	unsigned char *file, *mem;
	uint64_t img, sum, code_file, code_mem, raw_first = 0, va_first = 0;
	uint32_t i;
	int fd, overlap, got_file, got_mem, have_first = 0;
	size_t rd;
	FILE *f;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return;
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
		close(fd);
		return;
	}
	close(fd);
	f = fopen(path, "rb");
	if (!f)
		return;
	file = malloc((size_t)st.st_size);
	if (!file) {
		fclose(f);
		return;
	}
	rd = fread(file, 1, (size_t)st.st_size, f);
	fclose(f);
	if (rd != (size_t)st.st_size) {
		free(file);
		return;
	}

	memset(&info, 0, sizeof info);
	memset(&ctx, 0, sizeof ctx);
	if (!kof_pe_parse(kof_buf_make(file, (uint64_t)st.st_size), &info,
			  &ctx) || !ctx.resolve_scan) {
		free(file);
		return;                 /* not a PE, or refused: not our business */
	}

	sum = partition_of(&ctx, &overlap);
	if (sum == (uint64_t)st.st_size && !overlap)
		t->part_file++;
	else
		t->bad++;
	code_file = first_code(&ctx, &got_file);

	img = info.size_of_image;
	if (!img || img > (1ull << 31)) {
		free(file);
		return;
	}
	for (i = 0; i < info.sec_count && !have_first; i++)
		if (info.sec[i].characteristics & 0x20000000u) {  /* MEM_EXECUTE */
			raw_first = info.sec[i].file_off;
			va_first = info.sec[i].mem_rva;
			have_first = 1;
		}

	mem = calloc(1, (size_t)img);
	if (!mem) {
		free(file);
		return;
	}
	{
		uint64_t h = info.size_of_headers;

		if (h > (uint64_t)st.st_size)
			h = (uint64_t)st.st_size;
		if (h > img)
			h = img;
		memcpy(mem, file, (size_t)h);
	}
	for (i = 0; i < info.sec_count; i++) {
		uint64_t off = info.sec[i].file_off;
		uint64_t len = info.sec[i].file_size;
		uint64_t va  = info.sec[i].mem_rva;

		if (!len || off + len > (uint64_t)st.st_size || va + len > img)
			continue;
		memcpy(mem + va, file + off, (size_t)len);
	}

	memset(&info, 0, sizeof info);
	memset(&ctx, 0, sizeof ctx);
	info.layout = KOF_PE_LAYOUT_MAPPED;
	if (!kof_pe_parse(kof_buf_make(mem, img), &info, &ctx) ||
	    !ctx.resolve_scan) {
		printf("  %s: mapped parse refused\n", path);
		t->bad++;
		free(mem);
		free(file);
		return;
	}

	t->seen++;
	sum = partition_of(&ctx, &overlap);
	if (sum == img && !overlap) {
		t->part_mapped++;
	} else {
		printf("  %s: mapped sum=%llu size=%llu overlap=%d\n", path,
		       (unsigned long long)sum, (unsigned long long)img,
		       overlap);
		t->bad++;
	}

	code_mem = first_code(&ctx, &got_mem);
	if (have_first && got_file && got_mem) {
		if (raw_first == va_first) {
			t->same_addr++;
		} else if (code_mem == va_first && code_file == raw_first) {
			t->moved++;
		} else {
			printf("  %s: CODE file=0x%llx (raw 0x%llx) "
			       "mapped=0x%llx (va 0x%llx)\n", path,
			       (unsigned long long)code_file,
			       (unsigned long long)raw_first,
			       (unsigned long long)code_mem,
			       (unsigned long long)va_first);
			t->bad++;
		}
	}

	free(mem);
	free(file);
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
		if (snprintf(path, sizeof path, "%s/%s", dir, de->d_name) >=
		    (int)sizeof path)
			continue;
		one_file(path, t);
	}
	closedir(d);
}

int main(int argc, char **argv)
{
	static const char *defaults[] = {
		"build/release/bin", "build/test/fixtures", "samples"
	};
	struct tally t;
	int i;

	memset(&t, 0, sizeof t);
	if (argc > 1)
		for (i = 1; i < argc; i++)
			walk(argv[i], &t);
	else
		for (i = 0; i < (int)(sizeof defaults / sizeof defaults[0]); i++)
			walk(defaults[i], &t);

	printf("pe mapped: %llu image(s)  partition file %llu, mapped %llu  "
	       "CODE moved %llu (%llu identical addresses)\n",
	       (unsigned long long)t.seen,
	       (unsigned long long)t.part_file,
	       (unsigned long long)t.part_mapped,
	       (unsigned long long)t.moved,
	       (unsigned long long)t.same_addr);

	if (!t.seen) {
		printf("  (no PE found - nothing tested)\n");
		return 0;
	}
	if (!t.moved) {
		printf("  no image had CODE at a different address in the two "
		       "layouts - the property was not exercised\n");
		return 1;
	}
	return t.bad != 0;
}
