/*
 * kofdump - print the facts the collector recovered from an object.
 *
 * This is the collector's first deliverable and it is useful on its own: if it
 * is not useful standing alone, it will not be useful to a matcher either.
 *
 * Two output modes. The default block form is for looking at one file. The
 * -1 form prints one tab separated line per file so a corpus can be measured
 * with awk and sort, which is how facts earn their place: a fact that is absent
 * on most files, or whose values all land in one bucket, does not discriminate
 * and should not be carried.
 *
 * Exit status is 0 whenever every file was processed without the parser
 * crashing, even for files that are not ELF or are badly malformed. Those are
 * results, not errors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "../../libkofeng/kofparser/elf/elf_parse.h"

struct bitname {
	uint64_t bit;
	const char *name;
};

static const struct bitname anom_names[] = {
	{ KOF_ELF_ANOM_BAD_MAGIC,         "bad_magic" },
	{ KOF_ELF_ANOM_BAD_CLASS,         "bad_class" },
	{ KOF_ELF_ANOM_BAD_ENDIAN,        "bad_endian" },
	{ KOF_ELF_ANOM_BAD_VERSION,       "bad_version" },
	{ KOF_ELF_ANOM_TRUNCATED_HEADER,  "truncated_header" },
	{ KOF_ELF_ANOM_PHOFF_PAST_EOF,    "phoff_past_eof" },
	{ KOF_ELF_ANOM_PHENTSIZE_ODD,     "phentsize_odd" },
	{ KOF_ELF_ANOM_PHNUM_CLAMPED,     "phnum_clamped" },
	{ KOF_ELF_ANOM_SHOFF_PAST_EOF,    "shoff_past_eof" },
	{ KOF_ELF_ANOM_SHNUM_CLAMPED,     "shnum_clamped" },
	{ KOF_ELF_ANOM_SEG_PAST_EOF,      "seg_past_eof" },
	{ KOF_ELF_ANOM_SEG_FILESZ_GT_MEM, "seg_filesz_gt_mem" },
	{ KOF_ELF_ANOM_SEG_OVERLAP,       "seg_overlap" },
	{ KOF_ELF_ANOM_NO_LOAD_SEGMENT,   "no_load_segment" },
	{ KOF_ELF_ANOM_ENTRY_ZERO,        "entry_zero" },
	{ KOF_ELF_ANOM_ENTRY_UNMAPPED,    "entry_unmapped" },
	{ KOF_ELF_ANOM_ENTRY_ZEROFILL,    "entry_zerofill" },
	{ KOF_ELF_ANOM_ENTRY_NOT_EXEC,    "entry_not_exec" },
	{ KOF_ELF_ANOM_SHENTSIZE_ODD,     "shentsize_odd" },
	{ KOF_ELF_ANOM_SHSTRNDX_BAD,      "shstrndx_bad" },
	{ KOF_ELF_ANOM_SEC_PAST_EOF,      "sec_past_eof" },
	{ KOF_ELF_ANOM_SECNAME_UNREAD,    "secname_unread" },
	{ KOF_ELF_ANOM_SECNAME_TRUNC,     "secname_trunc" },
	{ KOF_ELF_ANOM_SECTAB_MISSING,    "sectab_missing" },
	{ 0, NULL }
};

static const char *class_str(uint8_t c)
{
	switch (c) {
	case KOF_ELFCLASS_32: return "elf32";
	case KOF_ELFCLASS_64: return "elf64";
	default:              return "none";
	}
}

static const char *data_str(uint8_t d)
{
	switch (d) {
	case KOF_ELFDATA_LE: return "le";
	case KOF_ELFDATA_BE: return "be";
	default:             return "none";
	}
}

static const char *arch_str(uint8_t a)
{
	switch (a) {
	case KOF_ARCH_ANY:     return "any";
	case KOF_ARCH_X86:     return "x86";
	case KOF_ARCH_X86_64:  return "x86_64";
	case KOF_ARCH_ARM:     return "arm";
	case KOF_ARCH_ARM64:   return "arm64";
	case KOF_ARCH_RISCV64: return "riscv64";
	case KOF_ARCH_MIPS:    return "mips";
	case KOF_ARCH_PPC64:   return "ppc64";
	default:               return "other";
	}
}

static void perm_str(uint32_t p, char out[4])
{
	out[0] = (p & KOF_PERM_R) ? 'r' : '-';
	out[1] = (p & KOF_PERM_W) ? 'w' : '-';
	out[2] = (p & KOF_PERM_X) ? 'x' : '-';
	out[3] = 0;
}

/* KOF_NA and KOF_BROKEN are printed by name: the difference between "does not
 * apply" and "could not be determined" is the whole reason they are separate. */
static void print_off(uint64_t v)
{
	if (v == KOF_NA)
		fputs("na", stdout);
	else if (v == KOF_BROKEN)
		fputs("broken", stdout);
	else
		printf("0x%llx", (unsigned long long)v);
}

static void print_anoms(uint64_t a, const char *sep)
{
	int first = 1;
	int i;
	if (a == 0) {
		fputs("-", stdout);
		return;
	}
	for (i = 0; anom_names[i].name; i++) {
		if (!(a & anom_names[i].bit))
			continue;
		if (!first)
			fputs(sep, stdout);
		fputs(anom_names[i].name, stdout);
		first = 0;
	}
}

/*
 * Resolve and print each region.
 *
 * Regions are computed rather than stored, so this is the only way to see what a
 * signature will be handed. The named total against the file size is the number that
 * says whether a region discriminates.
 */
static void print_regions(const struct kof_obj_ctx *ctx)
{
	static const struct { uint32_t bit; const char *name; } rgns[] = {
		{ KOF_SCAN_ELF_HEADERS,   "headers"   },
		{ KOF_SCAN_ELF_CODE,      "code"      },
		{ KOF_SCAN_ELF_DATA,      "data"      },
		{ KOF_SCAN_ELF_NOLOAD,    "noload"    },
		{ KOF_SCAN_ELF_UNCLAIMED, "unclaimed" },
		{ 0, NULL }
	};
	struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	int i;

	if (!ctx->resolve_scan)
		return;

	for (i = 0; rgns[i].name; i++) {
		uint32_t n, k;
		uint64_t tot = 0;

		n = ctx->resolve_scan(ctx, rgns[i].bit, ext,
				      KOF_SCAN_MAX_EXTENTS);
		printf("  rgn %-10s", rgns[i].name);
		if (n == 0) {
			printf(" absent\n");
			continue;
		}
		for (k = 0; k < n; k++)
			tot += ext[k].len;
		printf(" %u ext total=0x%llx (%.1f%% of file)\n", n,
		       (unsigned long long)tot,
		       ctx->obj_size ? 100.0 * (double)tot /
					(double)ctx->obj_size : 0.0);
		for (k = 0; k < n && k < 8; k++)
			printf("      [%u] off=0x%-8llx len=0x%llx\n", k,
			       (unsigned long long)ext[k].off,
			       (unsigned long long)ext[k].len);
		if (n > 8)
			printf("      ... %u more\n", n - 8);
	}
}

static void print_block(const char *path, const struct kof_obj_ctx *ctx,
			const struct kof_elf_info *e)
{
	char perm[4];
	uint32_t i;

	printf("%s\n", path);
	if (!e->valid) {
		printf("  not_elf         size=%llu\n",
		       (unsigned long long)ctx->obj_size);
		return;
	}

	perm_str(e->entry_perm, perm);

	printf("  class=%s data=%s arch=%s type=%u machine=%u size=%llu\n",
	       class_str(e->elf_class), data_str(e->elf_data),
	       arch_str(ctx->arch), e->e_type, e->e_machine,
	       (unsigned long long)ctx->obj_size);
	printf("  version=%u os_abi=%u abi_version=%u\n",
	       e->e_version, e->os_abi, e->abi_version);

	printf("  entry_addr=0x%llx entry_off=",
	       (unsigned long long)e->entry_addr);
	print_off(ctx->entry_off);
	printf(" perm=%s\n", perm);

	printf("  phoff=0x%llx phentsize=%u phnum=%u(claimed %u) load=%u\n",
	       (unsigned long long)e->phoff, e->phentsize, e->phnum,
	       e->phnum_claimed, e->load_count);
	printf("  shoff=0x%llx shentsize=%u shnum=%u(claimed %u) shstrndx=%u\n",
	       (unsigned long long)e->shoff, e->shentsize, e->shnum,
	       e->shnum_claimed, e->shstrndx);

	printf("  vaddr=[");
	if (e->min_vaddr == KOF_NA)
		printf("na");
	else
		printf("0x%llx,0x%llx", (unsigned long long)e->min_vaddr,
		       (unsigned long long)e->max_vaddr);
	printf("]\n");

	printf("  anomalies=");
	print_anoms(e->anomalies, ",");
	printf("\n");

	print_regions(ctx);

	for (i = 0; i < e->seg_count; i++) {
		const struct kof_elf_seg *s = &e->seg[i];
		char sp[4];
		perm_str(s->perm, sp);
		printf("  seg[%2u] type=%-2u %s off=0x%-8llx sz=0x%-8llx "
		       "va=0x%-10llx msz=0x%llx\n",
		       i, s->type, sp,
		       (unsigned long long)s->file_off,
		       (unsigned long long)s->file_size,
		       (unsigned long long)s->mem_addr,
		       (unsigned long long)s->mem_size);
	}
	for (i = 0; i < e->sec_count; i++) {
		const struct kof_elf_sec *s = &e->sec[i];
		printf("  sec[%2u] type=%-2u flags=0x%-4llx off=0x%-8llx "
		       "sz=0x%-8llx va=0x%-10llx %s\n",
		       i, s->type, (unsigned long long)s->flags,
		       (unsigned long long)s->file_off,
		       (unsigned long long)s->file_size,
		       (unsigned long long)s->mem_addr,
		       s->name);
	}
}

/*
 * Tab separated, one row per file, for corpus measurement.
 *
 * Column order is a contract: tests/corpus/measure.sh and the Makefile both
 * index into it. New fields are appended before anomalies, which stays last
 * because it is the only variable width field.
 *
 *  1 path        2 valid       3 class      4 data       5 e_type
 *  6 e_machine   7 arch        8 file_size  9 entry_addr 10 entry_off
 * 11 entry_perm 12 seg_count  13 sec_count 14 anomalies
 */
static void print_line(const char *path, const struct kof_obj_ctx *ctx,
		       const struct kof_elf_info *e)
{
	char perm[4];
	perm_str(e->entry_perm, perm);

	printf("%s\t%d\t%s\t%s\t%u\t%u\t%s\t%llu\t0x%llx\t",
	       path, e->valid ? 1 : 0, class_str(e->elf_class),
	       data_str(e->elf_data), e->e_type, e->e_machine,
	       arch_str(ctx->arch),
	       (unsigned long long)ctx->obj_size,
	       (unsigned long long)e->entry_addr);
	print_off(ctx->entry_off);
	printf("\t%s\t%u\t%u\t", perm, e->seg_count, e->sec_count);
	print_anoms(e->anomalies, "|");
	printf("\n");
}

static int do_file(const char *path, int oneline, struct kof_elf_info *info)
{
	struct kof_obj_ctx ctx;
	struct stat st;
	void *map = NULL;
	kof_buf buf;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "kofdump: %s: cannot open\n", path);
		return 0;
	}
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
		close(fd);
		return 0;
	}

	if (st.st_size > 0) {
		map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE,
			   fd, 0);
		if (map == MAP_FAILED) {
			fprintf(stderr, "kofdump: %s: cannot map\n", path);
			close(fd);
			return 0;
		}
	}
	close(fd);

	memset(&ctx, 0, sizeof ctx);
	
	buf = kof_buf_make(map, (uint64_t)st.st_size);
	kof_elf_parse(buf, info, &ctx);

	if (oneline)
		print_line(path, &ctx, info);
	else
		print_block(path, &ctx, info);

	if (map)
		munmap(map, (size_t)st.st_size);
	return 1;
}

int main(int argc, char **argv)
{
	struct kof_elf_info *info;
	int oneline = 0;
	int i, first = 1;

	if (argc > 1 && strcmp(argv[1], "-1") == 0) {
		oneline = 1;
		first = 2;
	}
	if (argc <= first) {
		fprintf(stderr, "usage: kofdump [-1] file...\n");
		return 2;
	}

	/* One instance, reused across every file. The struct carries the segment
	 * and section arrays inline, so allocating per file would mean a fresh
	 * 11KB and a free for each one. */
	info = malloc(sizeof *info);
	if (!info) {
		fprintf(stderr, "kofdump: out of memory\n");
		return 2;
	}

	for (i = first; i < argc; i++)
		do_file(argv[i], oneline, info);

	free(info);
	return 0;
}
