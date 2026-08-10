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

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>

#include <kofcore.h>
#include <kofmod/kofsig.h>
#include <kofmod/elf.h>
#include <kofmod/pe.h>

#include "../libkofeng/kofparsers/elf/elf_parse.h"
#include "../libkofeng/kofparsers/pe/pe_parse.h"

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
	void      (*print)(const void *, const struct kof_obj_ctx *);
};

static int elf_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_elf_parse(b, (struct kof_elf_info *)v, c);
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

static void print_elf(const void *view, const struct kof_obj_ctx *ctx)
{
	const struct kof_elf_info *e = view;
	uint32_t i;

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

static void print_pe(const void *view, const struct kof_obj_ctx *ctx)
{
	const struct kof_pe_info *p = view;
	uint32_t i;

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

static const struct fmt formats[] = {
	{ (uint32_t)sizeof(struct kof_elf_info), kof_elf_sniff, elf_parse_thunk,
	  kof_elf_region_bits, KOF_ELF_REGION_COUNT,
	  kof_elf_region_name, kof_elf_anomaly_name, print_elf },
	{ (uint32_t)sizeof(struct kof_pe_info), kof_pe_sniff, pe_parse_thunk,
	  kof_pe_region_bits, KOF_PE_REGION_COUNT,
	  kof_pe_region_name, kof_pe_anomaly_name, print_pe }
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
 * A name may be used in a directory name if it cannot be mistaken for something
 * else on a command line or in a terminal.
 *
 * Not a security boundary - a basename cannot contain a slash, so there is no
 * traversal to prevent here. It is about the name being usable afterwards: a
 * directory whose name holds a newline, a quote or a control character is one
 * that every subsequent command has to quote correctly, and one that prints as
 * something other than what it is.
 */
static int name_char_ok(unsigned char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
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
	struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
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
	struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
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

static int examine(const char *path, int dump)
{
	struct kof_obj_ctx ctx;
	struct stat st;
	void *map, *view = 0;
	const struct fmt *f = 0;
	uint64_t total = 0;
	uint32_t i;
	int fd, rc = 0;

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
	map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (map == MAP_FAILED) {
		fprintf(stderr, "kofexamine: cannot map %s\n", path);
		return 0;
	}

	{
		kof_buf buf = kof_buf_make(map, (uint64_t)st.st_size);

		memset(&ctx, 0, sizeof ctx);
		printf("%s\n", path);

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

		printf("  format    %s %s  %llu bytes\n",
		       kof_format_name(ctx.format), kof_arch_name(ctx.arch),
		       (unsigned long long)buf.n);
		f->print(view, &ctx);

		/* Regions last: they are the summary the rest explains, and with
		 * --dump they are also the manifest of what was written. */
		printf("  regions  ");
		for (i = 0; i < f->n_regions; i++) {
			struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
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
			uint64_t anom = (f->print == print_pe)
				      ? ((const struct kof_pe_info *)view)->anomalies
				      : ((const struct kof_elf_info *)view)->anomalies;
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
			char dir[PATH_ROOM];
			struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
			uint64_t first[16];
			uint32_t order[16], nord = 0;
			uint64_t wrote = 0;
			uint32_t written = 0, k;

			if (!dump_dir_for(path, dir, sizeof dir)) {
				fprintf(stderr, "kofexamine: path too long to "
						"place a dump beside %s\n", path);
				rc = -1;
				goto out;
			}
			if (mkdir(dir, 0777) != 0 && errno != EEXIST) {
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
	munmap(map, (size_t)st.st_size);
	return rc;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s [--dump] <file>...\n"
		"\n"
		"  --dump  also write each region of each file into a directory\n"
		"          beside it: <path>/_<name>_dump/<region enum name>\n",
		argv0);
}

int main(int argc, char **argv)
{
	int dump = 0;
	int i, files = 0, bad = 0;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--dump") == 0) {
			dump = 1;
		} else if (argv[i][0] == '-' && argv[i][1]) {
			fprintf(stderr, "%s: unrecognised argument '%s'\n",
				argv[0], argv[i]);
			usage(argv[0]);
			return 2;
		} else {
			int r = examine(argv[i], dump);

			files++;
			if (r < 0)
				return 2;   /* could not write: see above */
			if (!r)
				bad = 1;
		}
	}
	if (files == 0) {
		usage(argv[0]);
		return 2;
	}
	return bad ? 1 : 0;
}
