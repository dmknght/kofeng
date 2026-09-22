/*
 * koflib.c - the marker span.
 *
 * ONE TIER, BECAUSE ONE TIER IS WHAT WAS MEASURED. See the note in koflib.h.
 */

#include "koflib.h"

#include <string.h>

#include <kofmod/elf.h>
#include "../kofparsers/rangelist.h"

/* ELF's own value; the parser keeps p_type verbatim. Defined here for the same
 * reason every other file that needs it defines it: there is no ELF constants
 * header, and one line beats a dependency. */
#define PT_LOAD 1u

/*
 * THE MARKERS.
 *
 * Text the library owns and a program does not write for itself: strerror's
 * table, the dynamic loader's complaints, the allocator's abort messages.
 * Covering glibc, uclibc and musl.
 *
 * MEASURED COVERAGE, so nobody has to guess what this reaches: a span was found
 * in 100% of 638 /usr/bin objects and 100% of 574 packed clean ones, cutting a
 * mean 7.6% and 8.3% of the file; in 70% of 472 malware objects, cutting 12.6%;
 * and in only 14% of 514 IoT-botnet ELFs, cutting 0.5%. That last figure is the
 * known hole and it is the one that matters most - a stripped static uclibc
 * build has no strerror table to find. Closing it needs a tier this does not
 * have yet.
 */
static const char *const markers[] = {
	"No such file or directory", "Permission denied", "Bad address",
	"Cannot allocate memory", "Invalid argument", "Broken pipe",
	"Connection refused", "Resource temporarily unavailable",
	"Operation not permitted", "Interrupted system call",
	"No space left on device", "Too many open files", "Unknown error",
	"malloc(): ", "free(): ", "double free", "__libc_", "GLIBC_",
	"_dl_", "uClibc", "musl", "/lib/ld", "ld-linux",
	"Assertion", "assertion", "stack smashing", "buffer overflow"
};

/*
 * A SPAN, NOT THE MATCHES. One marker says a byte belongs to the library; what
 * is wanted is the run of bytes around it, and the linker puts a library's
 * read-only data down in one piece. So the span runs from the lowest hit to the
 * highest and everything between is cut - including whatever the author
 * happened to put there. That is the wide cut koflib.h says it makes.
 *
 * THREE HITS, NOT ONE. "Permission denied" is a string malware writes too, and
 * a span taken from a single match would cut a region because of one string.
 * Three distinct positions is a table, and a table is the library's.
 */
static void marker_span(const uint8_t *p, uint64_t n, uint64_t base,
			struct kof_rlist *l, uint64_t obj)
{
	uint64_t lo = (uint64_t)-1, hi = 0;
	uint32_t k, hits = 0;

	if (n < 64)
		return;
	for (k = 0; k < sizeof markers / sizeof markers[0]; k++) {
		uint64_t mlen = (uint64_t)strlen(markers[k]);
		const uint8_t *q = p;
		uint64_t left = n;

		while (left >= mlen) {
			const uint8_t *f = (const uint8_t *)memchr(q, markers[k][0],
							(size_t)(left - mlen + 1));
			uint64_t at;

			if (!f)
				break;
			if (!memcmp(f, markers[k], (size_t)mlen)) {
				at = (uint64_t)(f - p);
				if (at < lo)
					lo = at;
				if (at + mlen > hi)
					hi = at + mlen;
				hits++;
			}
			left = n - (uint64_t)(f - p) - 1;
			q = f + 1;
		}
	}
	if (hits < 3 || hi <= lo)
		return;
	kof_rl_add(l, obj, base + lo, hi - lo);
}

void kof_lib_find(kof_buf file, const struct kof_elf_info *e,
		  struct kof_lib_result *out)
{
	struct kof_rlist l;
	uint32_t s;

	if (!out)
		return;
	memset(out, 0, sizeof *out);
	if (!file.p || !file.n || !e || !e->valid)
		return;
	kof_rl_init(&l, out->span, KOF_LIB_MAX_SPANS);

	/* Per loadable segment, so a hit in one cannot cut another. */
	for (s = 0; s < e->seg_count && s < KOF_ELF_MAX_SEGMENTS; s++) {
		const struct kof_elf_seg *g = &e->seg[s];
		uint64_t len;

		if (g->type != PT_LOAD || !g->file_size)
			continue;
		if (g->file_off >= file.n)
			continue;
		len = file.n - g->file_off;
		if (len > g->file_size)
			len = g->file_size;
		marker_span(file.p + g->file_off, len, g->file_off, &l, file.n);
	}
	out->n = kof_rl_normalise(&l);
}
