/*
 * diag_shape_gate - the file attributes that route an object into the
 * pathogen analysis.
 *
 * The engine publishes what it read out of the header - see enum
 * kof_diag_fact - and a diagnose registers the conditions it wants those to
 * meet, with KOF_DIAG_WHEN. The engine routes on that. The two stager
 * diagnoses register two: a mapping that is writable and executable, and no
 * section table.
 *
 * WHY THE ASSERTION IS ON THE ENGINE'S BEHAVIOUR AND NOT ON THE PREDICATE.
 * The gate decides what the most expensive thing the engine does is spent
 * on. Both ways of being wrong are silent: a gate that stopped firing would
 * lose every encrypted stager without a single test going red, and one that
 * fired too widely would cost a factor of two on an ordinary scan and look
 * exactly like a slow machine. So this watches kof_stats.heur_emu, which is
 * the engine's own count of objects interpreted because something asked.
 *
 * THIS WAS A HEURISTIC RULE, bases/heur/shellcode_00.c, which carried the
 * same shape test and asked on the diagnose's behalf. It had to publish a
 * verdict to be allowed to ask - Heur:Meterp?Shellcode on every object it
 * fired on, saying only that the engine had decided to look - and the test
 * lived in a different module from the declaration it was gating.
 *
 *
 * WHAT IS ASSERTED
 *
 *   FIRES        A single-segment RWX ELF with no section table is
 *                interpreted. This is the whole point of the declaration.
 *
 *   NOT A SIZE   A four kilobyte object of the same shape fires too. Size was
 *                tried as the discriminator and rejected on the measurement -
 *                the largest malware object with this shape is 1266 bytes and
 *                the smallest clean ELF on the machine is 1192 - so a size
 *                bound creeping back in has to fail something.
 *
 *   NOT RWX      The same single segment as R|X, which is what a toolchain
 *                emits, is silent. That bit is what separates a file whose
 *                author meant to write code at runtime from one that did not.
 *
 *   TWO SEGMENTS An ELF with a data segment beside its RWE code STILL ASKS,
 *                and that is asserted on purpose. The declaration used to
 *                demand one program header as well - the msfvenom raw
 *                template's layout - which is a build detail and not a
 *                behaviour: the same payload in a full ELF template carries
 *                six. A condition narrower than it needs to be is a
 *                detection in disguise, and its misses are the kind nobody
 *                sees. This case is what keeps that one from coming back.
 *
 *   SECTION TAB  An ELF that kept its section header table is silent, which
 *                is KOF_FACT_SECTIONS doing its job. It stays because the
 *                W+X population is the one that will grow: as more malware
 *                ships such a mapping that attribute alone stops
 *                separating, and the stripped section table is the half
 *                that still does.
 *
 * The ELFs are built in memory and written to one temporary file, because a
 * scan needs a path.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofeng.h"

static int failures;

static void fail(const char *what)
{
	printf("  FAIL %s\n", what);
	failures++;
}

/* Real amd64, so the object is code by any reading of it: the opening of the
 * msfvenom stager. Its content is not what the term looks at - the shape is -
 * but a file of zeroes would leave the reader wondering. */
static const uint8_t code[] = {
	0x31,0xff,0x6a,0x09,0x58,0x99,0xb6,0x10,0x48,0x89,0xd6,0x4d,0x31,0xc9,
	0x6a,0x22,0x41,0x5a,0x6a,0x07,0x5a,0x0f,0x05,0x48,0x85,0xc0,0x78,0x51,
	0x6a,0x0a,0x41,0x59,0x50,0x6a,0x29,0x58,0x99,0x6a,0x02,0x5f,0x6a,0x01,
	0x5e,0x0f,0x05,0x48,0x85,0xc0,0x78,0x3b,0x48,0x97,0x48,0xb9,0x02,0x00
};

#define SEC_N 1u

/*
 * One ELF64, in the shapes the assertions need.
 *
 *   segs    1 or 2 PT_LOADs; the second is read-write, where a toolchain puts
 *           the data a program has.
 *   sectab  non-zero to append a one-entry section header table, which is what
 *           an unstripped binary carries.
 *   body_n  how many bytes of code to lay down, `code` repeating, so the same
 *           shape can be built at two sizes.
 */
static uint64_t build(uint8_t *f, unsigned segs, int sectab, uint64_t body_n,
		      int wx)
{
	const uint64_t base = 0x400000, off = 0x78;
	uint64_t len = off + body_n, shoff = 0;
	uint8_t *ph = f + 64;
	unsigned i, s;

	memset(f, 0, (size_t)(len + 64 * 4));
	memcpy(f, "\177ELF\2\1\1", 7);
	f[0x10] = 2;                                  /* ET_EXEC   */
	f[0x12] = 0x3e;                               /* EM_X86_64 */
	f[0x14] = 1;
	for (i = 0; i < 8; i++)
		f[0x18 + i] = (uint8_t)((base + off) >> (i * 8));
	f[0x20] = 64;                                 /* e_phoff   */
	f[0x34] = 64;                                 /* ehsize    */
	f[0x36] = 56;                                 /* phentsize */
	f[0x38] = (uint8_t)segs;                      /* phnum     */
	f[0x3a] = 64;                                 /* shentsize */

	for (s = 0; s < segs; s++) {
		uint8_t *p = ph + s * 56;
		uint64_t va = base + s * 0x200000;

		p[0] = 1;                             /* PT_LOAD   */
		/* RWE, which is what msfvenom's template emits and what
		 * KOF_DIAG_SH_ENTRY_WX is about; then R|W for a second
		 * segment, as a toolchain would. `wx` turns the first one
		 * back into a toolchain's R|X for the negative case. */
		p[4] = s == 0 ? (wx ? 7 : 5) : 6;
		for (i = 0; i < 8; i++) {
			p[0x10 + i] = (uint8_t)(va >> (i * 8));
			p[0x18 + i] = (uint8_t)(va >> (i * 8));
			p[0x20 + i] = (uint8_t)(len >> (i * 8));
			p[0x28 + i] = (uint8_t)(len >> (i * 8));
		}
		p[0x30] = 0x10;
	}
	for (i = 0; i < body_n; i++)
		f[off + i] = code[i % (sizeof code)];

	if (sectab) {
		shoff = len;
		/* One entry, SHT_PROGBITS, so the parser has a usable table. */
		f[shoff + 4] = 1;
		len = shoff + 64;
		f[0x3c] = (uint8_t)SEC_N;             /* e_shnum */
		for (i = 0; i < 8; i++)
			f[0x28 + i] = (uint8_t)(shoff >> (i * 8));
	}
	return len;
}

static char seen[256];

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	uint32_t k;

	(void)name; (void)bytes; (void)len; (void)user;
	/*
	 * ACROSS EVERY OBJECT OF THE FILE, not just the last one.
	 *
	 * This cleared `seen` on entry, so each object overwrote the one
	 * before and what survived was whatever came last. That held while a
	 * file of this shape produced exactly one object. It stopped holding
	 * when the normaliser began making a view of any binary with a long
	 * zero run - the file reported Heur:Shellcode, the clean view came
	 * after it, and the finding was erased by an object that had nothing
	 * to say.
	 *
	 * The question this test asks is "did the ENGINE report it", and that
	 * is a question about the file, so the answer accumulates. Clearing
	 * belongs to the caller, before the scan, where it already is.
	 */
	if (!res)
		return 0;
	for (k = 0; k < res->n; k++)
		if (res->v[k].level == KOF_LEVEL_HEUR && !seen[0]) {
			snprintf(seen, sizeof seen, "%s", res->v[k].name);
			break;
		}
	return 0;
}

/*
 * Returns non-zero when the object was reported as a heuristic whose SHAPE is
 * Shellcode. A rule names itself Heur:<predicted-family>#<variant>?<shape>, so
 * the shape "Shellcode" sits after the "?" when there is a prediction (there is
 * one here, Meterp) and right after "Heur:" when there is not. Both are a Heur
 * finding carrying the word Shellcode, which is what this asks.
 */
/*
 * WHAT THE RULE DOES IS ASK, SO THAT IS WHAT THIS WATCHES.
 *
 * It used to look for "Heur:...Shellcode" in the verdict. The rule now
 * fires with KOF_HEUR_ACT - the shape is a reason to LOOK and not a thing
 * to conclude - so there is no verdict to look for, and a test that kept
 * looking for one would have reported the rule as broken for doing exactly
 * what it was changed to do.
 *
 * kof_stats.heur_emu is the engine's own count of objects interpreted
 * because a rule asked, which is this rule's entire effect.
 */
static int shape_asked(kof_scanner *sc, const char *path,
			  const uint8_t *f, uint64_t n)
{
	const struct kof_stats *st;
	uint64_t emu_before;

	struct kof_scan_option opt;
	FILE *fp = fopen(path, "wb");

	if (!fp || fwrite(f, 1, (size_t)n, fp) != (size_t)n) {
		if (fp)
			fclose(fp);
		fail("could not write the temporary object");
		return 0;
	}
	fclose(fp);
	memset(&opt, 0, sizeof opt);
	opt.max_produced_bytes = 1u << 20;
	opt.max_resident_bytes = 16u << 20;
	opt.max_object_bytes   = 1u << 20;
	seen[0] = '\0';
	st = kscan_stats(sc);
	emu_before = st ? st->heur_emu : 0u;
	if (kscan_path(sc, path, &opt, on_object, NULL) < 0) {
		fail("the scan could not run");
		return 0;
	}
	st = kscan_stats(sc);
	return st && st->heur_emu > emu_before;
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/release/databases";
	const char *path = "build/test/heur_shellcode.tmp";
	static uint8_t f[16384];
	kof_engine *eng;
	kof_scanner *sc;
	uint64_t n;

	eng = keng_open(db);
	if (!eng) {
		printf("diag shape gate: cannot open %s\n", db);
		return 2;
	}
	sc = kscan_new(eng);
	if (!sc) {
		keng_close(eng);
		return 2;
	}

	n = build(f, 1, 0, sizeof code, 1);
	printf("  1 segment, không section table, %llu B -> %s\n",
	       (unsigned long long)n, shape_asked(sc, path, f, n)
	       ? "asked for the interpreter" : "IM LẶNG");
	if (!shape_asked(sc, path, f, n))
		fail("the shape the term exists for did not ask");

	n = build(f, 1, 0, 4096, 1);
	printf("  cùng shape nhưng %llu B      -> %s\n",
	       (unsigned long long)n, shape_asked(sc, path, f, n)
	       ? "asked for the interpreter" : "IM LẶNG");
	if (!shape_asked(sc, path, f, n))
		fail("a size bound has crept back into the term");

	n = build(f, 1, 0, sizeof code, 0);
	printf("  cùng shape nhưng R|X           -> %s\n",
	       shape_asked(sc, path, f, n) ? "asked for the interpreter"
					   : "im lặng");
	if (shape_asked(sc, path, f, n))
		fail("a toolchain's R|X code segment asked");

	/*
	 * AND THE TWO THE GATE DELIBERATELY DOES NOT EXCLUDE.
	 *
	 * The declaration also demanded a missing section table and a single
	 * PT_LOAD covering the file - the whole msfvenom template shape -
	 * and dropping those was measured to change nothing: same time, same
	 * files found. They were asserted here as SILENT, so these two cases
	 * are what would quietly re-tighten the gate if somebody put them
	 * back. A gate is the cheapest necessary condition; precision is the
	 * tree's job and the verdict's, and a gate narrower than it needs to
	 * be fails in the one direction nobody can see.
	 */
	n = build(f, 2, 0, sizeof code, 1);
	printf("  2 segment, entry RWE           -> %s\n",
	       shape_asked(sc, path, f, n) ? "asked for the interpreter" : "im lặng");
	if (!shape_asked(sc, path, f, n))
		fail("a data segment beside the code closed the gate");

	n = build(f, 1, 1, sizeof code, 1);
	printf("  CÓ section table, entry RWE    -> %s\n",
	       shape_asked(sc, path, f, n) ? "asked for the interpreter" : "im lặng");
	if (shape_asked(sc, path, f, n))
		fail("a file that kept its section table asked");

	remove(path);
	kscan_free(sc);
	keng_close(eng);
	printf("diag shape gate: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
