/*
 * pe_unmap - a mapped image, put back to the file it was mapped from.
 *
 * THE ASSERTION IS BYTE IDENTITY WITH THE ORIGINAL FILE, and it is chosen for
 * the reason pe_rebuild's is: a rebuilt PE that parses, identifies and reports
 * sane sections can still have every section's CONTENT taken from the wrong
 * place, and nothing but a byte comparison notices.
 *
 * The round trip is:
 *
 *   file  --(this test lays it out)-->  image at base+D
 *         --(this test relocates it)-->  image as the loader would leave it
 *         --(kof_pe_unmap undoes both)-->  file again
 *
 * A shared misreading of the relocation table would have to apply +D and -D to
 * the SAME wrong address to cancel, and the comparison is against the original
 * file rather than against anything this test computed - so a table that was
 * quietly skipped shows up as bytes that are still relocated. `relocs_undone`
 * is asserted non-zero for the same reason: an image whose relocations were all
 * skipped would otherwise pass by never having been changed.
 *
 * Only the SECTIONS and the HEADERS are compared. The alignment padding between
 * sections is in the file, is not mapped, and is not something an un-map can
 * know - a rebuilt file has zeroes there and that is correct.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include <kofmod/kofsig.h>
#include <kofmod/pe.h>

#include "../../libkofeng/kofparsers/binaries/pe_parse.h"
#include "../../libkofeng/kofunpack/pe_unmap.h"

#define DELTA 0x13370000ull

static int failures;
static uint64_t images, with_relocs;

static void fail(const char *path, const char *why)
{
	printf("  FAIL %s: %s\n", path, why);
	failures++;
}

static unsigned char *slurp(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	unsigned char *b;
	long n;

	if (!f)
		return NULL;
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (n <= 0) {
		fclose(f);
		return NULL;
	}
	b = malloc((size_t)n);
	if (!b || fread(b, 1, (size_t)n, f) != (size_t)n) {
		free(b);
		fclose(f);
		return NULL;
	}
	fclose(f);
	*len = (size_t)n;
	return b;
}

/*
 * Apply the base relocations forward, which is the loader's half of the round
 * trip. Deliberately written from the format rather than shared with the code
 * under test.
 */
static uint32_t relocate(unsigned char *img, uint64_t img_len,
			 const struct kof_pe_info *p, uint64_t delta)
{
	uint64_t at, end;
	uint32_t done = 0;

	if (p->n_dirs <= KOF_PE_DIR_BASERELOC)
		return 0;
	at = p->dir[KOF_PE_DIR_BASERELOC].rva;
	end = at + p->dir[KOF_PE_DIR_BASERELOC].size;
	if (!p->dir[KOF_PE_DIR_BASERELOC].size || end > img_len)
		return 0;

	while (at + 8 <= end) {
		uint32_t page, blk;
		uint64_t e;

		memcpy(&page, img + at, 4);
		memcpy(&blk, img + at + 4, 4);
		if (blk < 8 || at + blk > end)
			break;
		for (e = at + 8; e + 2 <= at + blk; e += 2) {
			uint16_t ent;
			uint64_t rva;
			uint32_t type;

			memcpy(&ent, img + e, 2);
			type = (uint32_t)(ent >> 12);
			rva = (uint64_t)page + (ent & 0x0fff);
			if (type == 3u && rva + 4 <= img_len) {
				uint32_t v;

				memcpy(&v, img + rva, 4);
				v += (uint32_t)delta;
				memcpy(img + rva, &v, 4);
				done++;
			} else if (type == 10u && rva + 8 <= img_len) {
				uint64_t v;

				memcpy(&v, img + rva, 8);
				v += delta;
				memcpy(img + rva, &v, 8);
				done++;
			}
		}
		at += blk;
	}
	return done;
}

static void one_file(const char *path)
{
	struct kof_pe_info info;
	struct kof_obj_ctx ctx;
	struct kof_pe_unmap_info ui;
	unsigned char *file, *img;
	uint8_t *back = NULL;
	uint64_t back_len = 0, img_len;
	size_t flen = 0;
	uint32_t i, applied;

	file = slurp(path, &flen);
	if (!file)
		return;

	memset(&info, 0, sizeof info);
	memset(&ctx, 0, sizeof ctx);
	if (!kof_pe_parse(kof_buf_make(file, flen), &info, &ctx) || !info.valid) {
		free(file);
		return;
	}
	img_len = info.size_of_image;
	if (!img_len || img_len > (1ull << 31)) {
		free(file);
		return;
	}

	img = calloc(1, (size_t)img_len);
	if (!img) {
		free(file);
		return;
	}
	{
		uint64_t h = info.size_of_headers;

		if (h > flen)
			h = flen;
		if (h > img_len)
			h = img_len;
		memcpy(img, file, (size_t)h);
	}
	for (i = 0; i < info.sec_count; i++) {
		uint64_t off = info.sec[i].file_off;
		uint64_t len = info.sec[i].file_size;
		uint64_t va = info.sec[i].mem_rva;

		if (!len || off + len > flen || va + len > img_len)
			continue;
		memcpy(img + va, file + off, (size_t)len);
	}

	images++;
	applied = relocate(img, img_len, &info, DELTA);
	if (applied)
		with_relocs++;

	if (!kof_pe_unmap(kof_buf_make(img, img_len), info.image_base + DELTA,
			  1ull << 30, &back, &back_len, &ui)) {
		fail(path, "unmap refused a mapped image");
		free(img);
		free(file);
		return;
	}

	if (applied && ui.relocs_undone == 0)
		fail(path, "relocations were applied and none were undone");
	if (ui.delta != (int64_t)DELTA)
		fail(path, "delta not as declared");

	/* the headers */
	{
		uint64_t h = info.size_of_headers;

		if (h > flen)
			h = flen;
		if (h > back_len)
			h = back_len;
		if (h && memcmp(back, file, (size_t)h) != 0)
			fail(path, "headers differ");
	}

	/* every section's content */
	for (i = 0; i < info.sec_count; i++) {
		uint64_t off = info.sec[i].file_off;
		uint64_t len = info.sec[i].file_size;

		if (!len || off + len > flen || off + len > back_len)
			continue;
		if (memcmp(back + off, file + off, (size_t)len) != 0) {
			char why[128];

			snprintf(why, sizeof why,
				 "section %u (%.8s) content differs", i,
				 info.sec[i].name);
			fail(path, why);
			break;
		}
	}

	free(back);

	/*
	 * A second pass with no address given must copy the bytes and touch no
	 * relocation - which is what a caller that does not know where the
	 * image was mapped has to get, since a wrong delta is worse than none.
	 */
	back = NULL;
	if (kof_pe_unmap(kof_buf_make(img, img_len), 0, 1ull << 30, &back,
			 &back_len, &ui)) {
		if (ui.relocs_undone != 0)
			fail(path, "relocations undone with no address given");
		free(back);
	} else {
		fail(path, "unmap refused with no address given");
	}

	free(img);
	free(file);
}

static void walk(const char *dir)
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
		one_file(path);
	}
	closedir(d);
}

/* Nothing that looks like a mapped PE must come back as one. */
static void refusals(void)
{
	static unsigned char junk[512];
	uint8_t *out = NULL;
	uint64_t n = 0;
	size_t i;

	for (i = 0; i < sizeof junk; i++)
		junk[i] = (unsigned char)(i * 7u + 3u);

	if (kof_pe_unmap(kof_buf_make(junk, sizeof junk), 0, 1u << 20, &out, &n,
			 NULL))
		fail("<junk>", "unmap accepted arbitrary bytes");

	junk[0] = 'M';
	junk[1] = 'Z';
	if (kof_pe_unmap(kof_buf_make(junk, sizeof junk), 0, 1u << 20, &out, &n,
			 NULL))
		fail("<MZ only>", "unmap accepted an MZ with no PE header");

	if (kof_pe_unmap(kof_buf_make(junk, 0), 0, 1u << 20, &out, &n, NULL))
		fail("<empty>", "unmap accepted an empty buffer");
}

int main(int argc, char **argv)
{
	static const char *defaults[] = {
		"build/release/bin", "build/test/fixtures", "samples"
	};
	int i;

	refusals();
	if (argc > 1)
		for (i = 1; i < argc; i++)
			walk(argv[i]);
	else
		for (i = 0; i < (int)(sizeof defaults / sizeof defaults[0]); i++)
			walk(defaults[i]);

	printf("pe unmap: %llu image(s) round-tripped, %llu carried relocations\n",
	       (unsigned long long)images, (unsigned long long)with_relocs);
	if (!images) {
		printf("  (no PE found - nothing tested)\n");
		return 0;
	}
	if (!with_relocs) {
		printf("  no image carried a relocation table - the half this "
		       "exists for was not exercised\n");
		return 1;
	}
	printf("pe unmap: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
