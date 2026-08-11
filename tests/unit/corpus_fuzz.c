/*
 * corpus_fuzz - break real files and see what the collectors do.
 *
 * The generative fuzzer builds headers from nothing, which reaches the corners a
 * real file never has. This does the opposite: it takes files that parse cleanly
 * and damages them a little. Those are different bug classes and neither finds the
 * other's. A field that is only ever read when three other fields are consistent is
 * hard to reach from random bytes and trivial to reach by flipping one byte of a
 * working binary - and that is exactly how the PE region overlap was found.
 *
 * What is asserted on every mutant that parses:
 *
 *   the regions still partition the object exactly
 *   no extent runs past the end or wraps
 *   entry_off is a sentinel or an offset inside the object
 *   resolve_scan survives a mask with bits no format defines
 *   an RVA the file never mentions resolves to an offset inside the object, or
 *     to KOF_BROKEN, and never to something in between
 *
 * Two cheap tricks keep this fast enough to sit in `make unit`:
 *
 *   the mutation is undone rather than the file recopied, so an iteration costs a
 *   parse and not a memcpy of the object
 *
 *   mutations land in the first 64KB, where every structure a parser reads lives.
 *   Damage in the middle of a section changes nothing any of this looks at, so
 *   spending iterations there would measure the random number generator
 *
 * Deterministic: a failure names a file, a seed and a round.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include <kofmod/kofsig.h>
#include <kofmod/elf.h>
#include <kofmod/pe.h>

#include "partition_check.h"
#include "../../libkofeng/kofparsers/binaries/elf_parse.h"
#include "../../libkofeng/kofparsers/binaries/pe_parse.h"
#include "../../libkofeng/kofparsers/containers/gzip_parse.h"
#include "../../libkofeng/kofparsers/containers/docole_parse.h"

#define HEADER_ZONE (64u * 1024u)
#define MAX_OBJ     (4u * 1024u * 1024u)

static uint64_t rng_state = 1;

static uint64_t rnd(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 7;
	rng_state ^= rng_state << 17;
	return rng_state;
}

/*
 * A byte an attacker would choose.
 *
 * Uniform random would spend most of its time on values that every bounds check
 * rejects at the first branch. The interesting bytes are the ones that make a
 * count enormous, an offset land exactly on a boundary, or a field read as zero.
 */
static uint8_t hostile_byte(void)
{
	switch (rnd() % 8) {
	case 0: return 0x00;
	case 1: return 0xff;
	case 2: return 0x7f;
	case 3: return 0x80;
	case 4: return 0x01;
	default: return (uint8_t)rnd();
	}
}

struct tally {
	uint64_t parsed, checked;
};

/* Everything a parser can be asked after it has run, asked with values it never
 * saw. None of it should be reachable with a bad answer, and none of it should
 * crash: a module may ask any of this about any object. */
static void poke_accessors(const struct kof_obj_ctx *ctx, uint64_t obj_size,
			   const char *what, struct pc_report *rep)
{
	struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	uint32_t i;

	/* Region bits that no format defines. The mask reaches a parser as bytes
	 * out of a database, so unknown bits have to be ignored rather than
	 * indexed with. */
	if (ctx->resolve_scan) {
		static const uint32_t junk[] = {
			0xffffffffu, 0x80000000u, 0xfffffff0u, 0u, 0x0000ff00u
		};

		for (i = 0; i < sizeof junk / sizeof junk[0]; i++) {
			uint32_t n = ctx->resolve_scan(ctx, junk[i], ext,
						       KOF_SCAN_MAX_EXTENTS);
			uint32_t k;

			if (n > KOF_SCAN_MAX_EXTENTS) {
				printf("  FAIL %s: resolve_scan returned %u extents\n",
				       what, n);
				rep->failed++;
				return;
			}
			for (k = 0; k < n; k++)
				if (ext[k].off > obj_size ||
				    ext[k].len > obj_size - ext[k].off) {
					printf("  FAIL %s: extent [%llu,%llu) outside "
					       "a %llu byte object\n", what,
					       (unsigned long long)ext[k].off,
					       (unsigned long long)ext[k].len,
					       (unsigned long long)obj_size);
					rep->failed++;
					return;
				}
		}
	}

	/*
	 * The entry point is handed to modules as an offset. Three answers are
	 * legal and nothing else is: not applicable, could not be determined, or
	 * a place inside the object.
	 */
	if (ctx->entry_off != KOF_NA && ctx->entry_off != KOF_BROKEN &&
	    ctx->entry_off >= obj_size) {
		printf("  FAIL %s: entry_off %llu is outside a %llu byte object\n",
		       what, (unsigned long long)ctx->entry_off,
		       (unsigned long long)obj_size);
		rep->failed++;
	}

	if (ctx->format == KOF_FMT_PE && ctx->file_header) {
		const struct kof_pe_info *pe = ctx->file_header;
		static const uint64_t rvas[] = {
			0, 1, 0x1000, 0x7fffffff, 0xffffffff, 0xfffffffffull
		};

		for (i = 0; i < sizeof rvas / sizeof rvas[0]; i++) {
			uint64_t off = kof_pe_rva_to_off(pe, rvas[i]);

			if (off != KOF_BROKEN && off >= obj_size) {
				printf("  FAIL %s: rva 0x%llx resolved to %llu, "
				       "outside a %llu byte object\n", what,
				       (unsigned long long)rvas[i],
				       (unsigned long long)off,
				       (unsigned long long)obj_size);
				rep->failed++;
				return;
			}
		}
	}
}

/* Parse one buffer and run every check over it. */
static void one(kof_buf buf, struct kof_elf_info *ei, struct kof_pe_info *pi,
		struct kof_gzip_info *gi, struct kof_docole_info *oi,
		const char *what,
		struct pc_report *rep, struct tally *t)
{
	struct kof_obj_ctx ctx;

	memset(&ctx, 0, sizeof ctx);

	if (kof_elf_sniff(buf)) {
		if (!kof_elf_parse(buf, ei, &ctx))
			return;
		t->parsed++;
		pc_check(what, &ctx, buf.n, kof_elf_region_bits,
			 KOF_ELF_REGION_COUNT, rep);
	} else if (kof_pe_sniff(buf)) {
		if (!kof_pe_parse(buf, pi, &ctx))
			return;
		t->parsed++;
		pc_check(what, &ctx, buf.n, kof_pe_region_bits,
			 KOF_PE_REGION_COUNT, rep);
	} else if (kof_gzip_sniff(buf)) {
		if (!kof_gzip_parse(buf, gi, &ctx))
			return;
		t->parsed++;
		pc_check(what, &ctx, buf.n, kof_gzip_region_bits,
			 KOF_GZIP_REGION_COUNT, rep);
	} else if (kof_docole_sniff(buf)) {
		if (!kof_docole_parse(buf, oi, &ctx))
			return;
		t->parsed++;
		pc_check(what, &ctx, buf.n, kof_docole_region_bits,
			 KOF_DOCOLE_REGION_COUNT, rep);
	} else {
		return;
	}
	t->checked++;
	poke_accessors(&ctx, buf.n, what, rep);
}

static void fuzz_file(const char *path, uint32_t rounds, struct pc_report *rep,
		      struct tally *t)
{
	struct kof_elf_info *ei = malloc(sizeof *ei);
	struct kof_pe_info *pi = malloc(sizeof *pi);
	struct kof_gzip_info *gi = malloc(sizeof *gi);
	struct kof_docole_info *oi = malloc(sizeof *oi);
	struct stat st;
	uint8_t *buf = NULL;
	uint64_t n;
	uint32_t r;
	int fd;
	char what[512];

	if (!ei || !pi || !gi || !oi)
		goto out;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto out;
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
	    (uint64_t)st.st_size > MAX_OBJ) {
		close(fd);
		goto out;
	}
	n = (uint64_t)st.st_size;
	buf = malloc((size_t)n);
	if (!buf || read(fd, buf, (size_t)n) != (ssize_t)n) {
		close(fd);
		goto out;
	}
	close(fd);

	/* The file as it is, first: a corpus file that does not hold the invariant
	 * unmutated is a finding about the parser, not about the fuzzer. */
	snprintf(what, sizeof what, "%s clean", path);
	one(kof_buf_make(buf, n), ei, pi, gi, oi, what, rep, t);

	/*
	 * Truncation, which is its own bug class: every length check in a parser
	 * is exercised by cutting the object short of the structure it is about to
	 * read. Swept geometrically rather than exhaustively - the interesting
	 * lengths are the small ones, where the headers are.
	 */
	{
		uint64_t cut;

		for (cut = 1; cut < n && cut < HEADER_ZONE; cut = cut * 3 / 2 + 1) {
			snprintf(what, sizeof what, "%s cut@%llu", path,
				 (unsigned long long)cut);
			one(kof_buf_make(buf, cut), ei, pi, gi, oi, what, rep, t);
		}
	}

	/*
	 * Mutate, parse, undo. The undo is what keeps an iteration to a parse
	 * instead of a copy of the object, which is what makes a thousand of them
	 * per file affordable.
	 */
	for (r = 0; r < rounds; r++) {
		uint64_t zone = n < HEADER_ZONE ? n : HEADER_ZONE;
		uint32_t k, nmut = 1 + (uint32_t)(rnd() % 8);
		uint64_t at[8];
		uint8_t old[8];

		for (k = 0; k < nmut; k++) {
			at[k] = rnd() % zone;
			old[k] = buf[at[k]];
			buf[at[k]] = hostile_byte();
		}

		snprintf(what, sizeof what, "%s round=%u", path, r);
		one(kof_buf_make(buf, n), ei, pi, gi, oi, what, rep, t);

		for (k = 0; k < nmut; k++)
			buf[at[k]] = old[k];
	}
out:
	free(buf);
	free(ei);
	free(pi);
	free(gi);
	free(oi);
}

/* Take the first `cap` regular files from a directory, in readdir order. */
static uint32_t collect(const char *dir, char **out, uint32_t cap)
{
	DIR *d = opendir(dir);
	struct dirent *de;
	uint32_t n = 0;

	if (!d)
		return 0;
	while (n < cap && (de = readdir(d)) != NULL) {
		char path[1024];
		struct stat st;

		if (de->d_name[0] == '.')
			continue;
		if ((size_t)snprintf(path, sizeof path, "%s/%s", dir, de->d_name)
		    >= sizeof path)
			continue;
		if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
			continue;
		out[n] = strdup(path);
		if (!out[n])
			break;
		n++;
	}
	closedir(d);
	return n;
}

int main(int argc, char **argv)
{
	static const char *dirs[] = { "build/test/fixtures", "/usr/bin" };
	struct pc_report rep = { 0, 0, 0 };
	struct tally t = { 0, 0 };
	char *files[64];
	uint32_t n_files = 0;
	int i;
	uint32_t rounds = 4000;
	uint64_t seed = 20240101u;

	if (argc > 1)
		seed = strtoull(argv[1], 0, 0);
	if (argc > 2)
		rounds = (uint32_t)strtoul(argv[2], 0, 0);
	rng_state = seed ? seed : 1;

	/*
	 * Directories after the rounds, so this can be aimed at a real sample
	 * collection rather than only at the tree's own corpus. Mutating malware
	 * headers is a different distribution from mutating /usr/bin: they are
	 * built by hand, already odd, and much closer to what a parser meets.
	 */
	if (argc > 3) {
		for (i = 3; i < argc && n_files < 64; i++)
			n_files += collect(argv[i], files + n_files,
					   64 - n_files);
	} else {
		/* PE first and all of it - eight files is the whole corpus - then
		 * as many ELF objects as the time budget allows. */
		n_files = collect(dirs[0], files, 16);
		n_files += collect(dirs[1], files + n_files, 48);
	}

	if (n_files == 0) {
		printf("corpus fuzz: no files found - nothing tested\n");
		return 0;
	}

	/* Failures are printed, but only the first few: a parser that breaks the
	 * partition tends to break it on everything, and ten thousand identical
	 * lines bury the one file worth looking at. */
	for (i = 0; i < (int)n_files; i++) {
		if (rep.failed > 8)
			rep.quiet = 1;
		fuzz_file(files[i], rounds, &rep, &t);
		free(files[i]);
	}

	printf("corpus fuzz: %u file(s), %llu parse(s), partition %llu/%llu\n",
	       n_files, (unsigned long long)t.parsed,
	       (unsigned long long)(rep.checked - rep.failed),
	       (unsigned long long)rep.checked);
	return rep.failed != 0;
}
