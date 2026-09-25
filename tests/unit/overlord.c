/*
 * overlord - the library cut, and the two-track comparison over it.
 *
 * The properties worth a test are the ones where being wrong is silent:
 *
 *   1. A SHARED LIBRARY IS NOT A MATCH. Two programs that share only their
 *      libc must not look alike; that is the whole reason the cut exists, and
 *      an implementation that got it backwards would appear to work - it would
 *      match more, not less - right up until it matched everything.
 *
 *   2. ONE MARKER IS NOT A TABLE. "Permission denied" is a string malware
 *      writes too, and a span taken from a single hit would cut a region
 *      because of one string, quietly deleting whatever the author put there.
 *
 *   3. SHAPE WITHOUT CONTENT STILL ANSWERS. The structure track is the one that
 *      survives an encrypted payload, so it must fire on two objects that share
 *      no string at all - and the string track must stay quiet on them.
 *
 *   4. REGIONS PAIR BY WHAT THEY ARE. An extra segment in one build must not
 *      slide a code region against a data one; by index it silently does, and
 *      every dimension after it is noise.
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/detector/overlord/koflib.h"
#include "../../libkofeng/detector/overlord/kofoverlord.h"
#include "../../libkofeng/analyzer/parsers/binaries/elf_parse.h"
#include "../../libkofeng/kofcore/kofmod/elf.h"

static int fails;

static void bad(const char *what)
{
	printf("  FAIL %s\n", what);
	fails++;
}

static void ok(const char *what)
{
	printf("  ok   %s\n", what);
}

/* ---- a synthetic ELF64 LSB executable with two PT_LOAD segments ---- */

#define SEG1_OFF 0x1000u
#define SEG2_OFF 0x5000u
#define SEG1_LEN 0x4000u
#define SEG2_LEN 0x1000u
#define VBASE    0x400000u

static void put16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void put32(uint8_t *p, uint32_t v)
{
	p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}
static void put64(uint8_t *p, uint64_t v) { put32(p,(uint32_t)v); put32(p+4,(uint32_t)(v>>32)); }

/*
 * Printable strings, deterministic in `seed`, laid down with a NUL between
 * them. Strings and not random bytes because the string track is what is being
 * tested, and random bytes yield no printable run long enough to count.
 */
static void put_strings(uint8_t *p, uint32_t n, uint32_t seed, uint32_t count)
{
	uint32_t at = 0, i, k, x = seed ? seed : 1u;

	memset(p, 0, n);
	for (i = 0; i < count && at + 24u < n; i++) {
		for (k = 0; k < 16u; k++) {
			x ^= x << 13; x ^= x >> 17; x ^= x << 5;
			p[at + k] = (uint8_t)('a' + (x % 26u));
		}
		at += 17u;                      /* 16 printable plus the NUL */
	}
}

struct halves { uint32_t user_seed, lib_seed; int markers; };

static void fill(uint8_t *s1, uint32_t n1, uint8_t *s2, uint32_t n2, void *u)
{
	struct halves *h = u;
	uint32_t half = n1 / 2u;

	put_strings(s1, half, h->user_seed, 40u);            /* the author's */
	put_strings(s1 + half, n1 - half, h->lib_seed, 40u); /* the library's */
	put_strings(s2, n2, h->user_seed ^ 0x5a5au, 20u);
	if (h->markers) {
		memcpy(s1 + half + 16,  "No such file or directory", 25);
		memcpy(s1 + half + 200, "Permission denied", 17);
		memcpy(s1 + half + 600, "Cannot allocate memory", 22);
	} else {
		/* exactly one marker: not a table, and must not cut */
		memcpy(s1 + half + 200, "Permission denied", 17);
	}
}

static uint8_t *build_elf(uint64_t *out_n, uint16_t machine, uint64_t extra_bss,
			  uint32_t user_seed, uint32_t lib_seed, int markers)
{
	uint64_t n = SEG2_OFF + SEG2_LEN;
	uint8_t *b = calloc(1, (size_t)n);
	struct halves h;
	uint8_t *ph;

	if (!b)
		return 0;
	memcpy(b, "\177ELF", 4);
	b[4] = 2; b[5] = 1; b[6] = 1;
	put16(b + 16, 2);                    /* ET_EXEC */
	put16(b + 18, machine);
	put32(b + 20, 1);
	put64(b + 24, VBASE + SEG1_OFF);
	put64(b + 32, 64);
	put64(b + 40, 0);
	put16(b + 52, 64);
	put16(b + 54, 56);
	put16(b + 56, 2);
	put16(b + 58, 64);

	ph = b + 64;
	put32(ph + 0, 1); put32(ph + 4, 5);            /* PT_LOAD, R+X */
	put64(ph + 8,  SEG1_OFF);
	put64(ph + 16, VBASE + SEG1_OFF);
	put64(ph + 24, VBASE + SEG1_OFF);
	put64(ph + 32, SEG1_LEN);
	put64(ph + 40, SEG1_LEN);
	put64(ph + 48, 0x1000);

	ph += 56;
	put32(ph + 0, 1); put32(ph + 4, 6);            /* PT_LOAD, R+W */
	put64(ph + 8,  SEG2_OFF);
	put64(ph + 16, VBASE + SEG2_OFF);
	put64(ph + 24, VBASE + SEG2_OFF);
	put64(ph + 32, SEG2_LEN);
	put64(ph + 40, SEG2_LEN + extra_bss);
	put64(ph + 48, 0x1000);

	h.user_seed = user_seed; h.lib_seed = lib_seed; h.markers = markers;
	fill(b + SEG1_OFF, SEG1_LEN, b + SEG2_OFF, SEG2_LEN, &h);
	*out_n = n;
	return b;
}

static int parse_of(uint8_t *b, uint64_t n, struct kof_elf_info *e)
{
	struct kof_obj_ctx ctx;

	memset(&ctx, 0, sizeof ctx);
	memset(e, 0, sizeof *e);
	return kof_elf_parse(kof_buf_make(b, n), e, &ctx);
}

/*
 * Build a descriptor the way the engine does: the library spans are the
 * caller's to establish, and they are THIS object's - see kof_ovl_build.
 */
static int ovl_build_of(struct kof_ovl_desc *d, uint8_t *p, uint64_t n,
			const struct kof_elf_info *e)
{
	struct kof_lib_result l;

	kof_lib_find(kof_buf_make(p, n), e, &l);
	return kof_ovl_build(d, kof_buf_make(p, n), e, l.span, l.n);
}

int main(void)
{
	struct kof_elf_info e1, e2;
	struct kof_lib_result lib;
	struct kof_ovl_desc *d1, *d2;
	struct kof_ovl_vec v;
	uint8_t *a, *b;
	uint64_t na, nb;

	d1 = calloc(1, sizeof *d1);
	d2 = calloc(1, sizeof *d2);
	if (!d1 || !d2)
		return 1;

	printf("the marker span:\n");
	a = build_elf(&na, 62, 0, 0x1111u, 0x2222u, 1);
	if (!a || !parse_of(a, na, &e1)) {
		bad("the synthetic ELF did not parse");
		return 1;
	}
	kof_lib_find(kof_buf_make(a, na), &e1, &lib);
	if (!lib.n)
		bad("three markers did not produce a span");
	else
		ok("three markers bound a span");
	if (lib.n && lib.span[0].len >= SEG1_LEN)
		bad("the span swallowed the whole region");
	else
		ok("the span is bounded by the markers, not the region");
	free(a);

	a = build_elf(&na, 62, 0, 0x1111u, 0x2222u, 0);
	parse_of(a, na, &e1);
	kof_lib_find(kof_buf_make(a, na), &e1, &lib);
	if (lib.n)
		bad("a single marker still produced a span");
	else
		ok("one marker is not a table - nothing is cut");
	free(a);

	printf("\ntwo objects that share only their library:\n");
	a = build_elf(&na, 62, 0, 0x1111u, 0x9999u, 1);
	b = build_elf(&nb, 62, 0, 0x7777u, 0x9999u, 1);
	parse_of(a, na, &e1); parse_of(b, nb, &e2);
	ovl_build_of(d1, a, na, &e1);
	ovl_build_of(d2, b, nb, &e2);
	kof_ovl_compare(d1, d2, &v);
	if (kof_ovl_verdict(&v) & KOF_OVL_STRINGS)
		bad("a shared library alone made the strings track fire");
	else
		ok("a shared library alone does not match");
	free(a); free(b);

	printf("\ntwo objects that share their author's half:\n");
	a = build_elf(&na, 62, 0, 0x1234u, 0x1111u, 1);
	b = build_elf(&nb, 62, 0, 0x1234u, 0x8888u, 1);
	parse_of(a, na, &e1); parse_of(b, nb, &e2);
	ovl_build_of(d1, a, na, &e1);
	ovl_build_of(d2, b, nb, &e2);
	kof_ovl_compare(d1, d2, &v);
	if (!(v.applied & KOF_OVL_D_STRINGS))
		bad("the strings dimension did not apply where both have content");
	else if (!(kof_ovl_verdict(&v) & KOF_OVL_STRINGS))
		bad("a shared author half did not match");
	else
		ok("a shared author half matches (strings track)");
	free(a); free(b);

	printf("\nshape without content - the encrypted-payload track:\n");
	a = build_elf(&na, 62, 0, 0x0101u, 0x0202u, 0);
	b = build_elf(&nb, 62, 0, 0xf0f0u, 0x0f0fu, 0);
	parse_of(a, na, &e1); parse_of(b, nb, &e2);
	ovl_build_of(d1, a, na, &e1);
	ovl_build_of(d2, b, nb, &e2);
	kof_ovl_compare(d1, d2, &v);
	if (!(kof_ovl_verdict(&v) & KOF_OVL_STRUCTURE))
		bad("identical shape did not fire the structure track");
	else
		ok("identical shape matches with no content in common");
	if (kof_ovl_verdict(&v) & KOF_OVL_STRINGS)
		bad("unrelated content fired the strings track");
	else
		ok("and the strings track correctly stays quiet");
	free(a); free(b);

	printf("\na different size is a different program:\n");
	a = build_elf(&na, 62, 0, 0x0101u, 0x0202u, 0);
	parse_of(a, na, &e1);
	ovl_build_of(d1, a, na, &e1);
	/* halve the file on the descriptor's own terms */
	d2 = memcpy(d2, d1, sizeof *d1);
	d2->fsize = d1->fsize / 4u;
	d2->region[0].fsz = d1->region[0].fsz / 4u;
	kof_ovl_compare(d1, d2, &v);
	if (kof_ovl_verdict(&v) & KOF_OVL_STRUCTURE)
		bad("a quarter-size object still matched on shape");
	else
		ok("a size that does not fit stops the structure track");
	free(a);

	printf("\nregions pair by what they are:\n");
	a = build_elf(&na, 62, 0, 0x2468u, 0x1357u, 0);
	parse_of(a, na, &e1);
	ovl_build_of(d1, a, na, &e1);
	memcpy(d2, d1, sizeof *d1);
	/* swap the two regions in the copy: an index pairing would now compare
	 * the executable region against the writable one and agree with nothing */
	{
		struct kof_ovl_region t = d2->region[0];

		d2->region[0] = d2->region[1];
		d2->region[1] = t;
	}
	kof_ovl_compare(d1, d2, &v);
	if (v.str_mean < 900)
		bad("swapping the region order changed the answer");
	else
		ok("the same object with its regions listed in the other order "
		   "still matches itself");
	free(a);

	printf("\na different machine is reported as different:\n");
	a = build_elf(&na, 62, 0, 0x1234u, 0x1111u, 0);
	b = build_elf(&nb, 40, 0, 0x1234u, 0x1111u, 0);
	parse_of(a, na, &e1); parse_of(b, nb, &e2);
	ovl_build_of(d1, a, na, &e1);
	ovl_build_of(d2, b, nb, &e2);
	kof_ovl_compare(d1, d2, &v);
	if (v.same_arch)
		bad("two machines were called the same architecture");
	else
		ok("the architectures are reported as different");
	free(a); free(b);
	free(d1); free(d2);

	/*
	 * THE STRUCTURE TRACK WITH THE LIBRARY OUT.
	 *
	 * Being wrong here is silent in the usual way: the cut either happens
	 * on both sides or on neither, and a reference that disagrees with the
	 * object about which it is compares two different quantities and simply
	 * scores low. So the test is that the cut CHANGES the numbers, that it
	 * says so in the reference, and that a reference which never asked for
	 * it is measured exactly as it was before.
	 */
	printf("\nthe structure track, with and without the library:\n");
	{
		struct kof_lib_result slib;
		struct kof_ovl_shape raw, cut;

		a = build_elf(&na, 62, 0, 0x1111u, 0x2222u, 1);
		if (!a || !parse_of(a, na, &e1)) {
			bad("the synthetic ELF did not parse");
		} else {
			kof_lib_find(kof_buf_make(a, na), &e1, &slib);
			kof_ovl_shape_of(&e1, na, &raw);
			kof_ovl_shape_of_cut(&e1, na, slib.span, slib.n, &cut);

			if (raw.lib_cut)
				bad("an uncut shape claimed the library was out");
			else
				ok("an uncut shape says so");
			if (!cut.lib_cut)
				bad("a cut shape did not record that it was cut");
			else
				ok("a cut shape records it");
			if (!slib.n)
				bad("the markers produced no span to cut");
			else if (cut.region_fsz[0] >= raw.region_fsz[0])
				bad("the cut did not take anything out of the "
				    "region the library is in");
			else
				ok("the library's bytes are out of the region");
			if (cut.fsize >= raw.fsize)
				bad("the cut did not shrink the file size");
			else
				ok("the file size is the author's bytes");
			/* Same object, same question: an uncut reference must
			 * answer exactly what it always did. */
			if (kof_ovl_shape_cmp(&raw, &raw) != 100u)
				bad("an object did not match its own uncut shape");
			else
				ok("an uncut reference is measured as before");
			if (kof_ovl_shape_cmp(&cut, &cut) != 100u)
				bad("an object did not match its own cut shape");
			else
				ok("a cut reference matches a cut object");
			free(a);
		}
	}

	if (fails) {
		printf("overlord: %d check(s) failed\n", fails);
		return 1;
	}
	printf("overlord: marker span, one marker is not a table, library-only vs "
	       "author-only, structure without content, size, region pairing, "
	       "machine, the library cut in a shape - ok\n");
	return 0;
}
