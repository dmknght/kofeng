/*
 * prod_once - THE RUN-COUNT INVARIANT: every product of an object (symbols, functions,
 * the decode walk, relocations, imports, the API-hash set, the diagnose graph, the
 * address-use map) is built ONCE from the object's bytes, however many rules,
 * diagnoses and routes read it.
 *
 * HOW IT IS COUNTED. kof_prod_ran (scan.c) is called where a product is built; a build
 * past the first for one object is a repeat in sc->prod_repeat, which survives the
 * object. The lib's own builds are brought in the same way: a scan that was not
 * handed a product builds its own (kgenome_diag_scan_own), and the walk counts its
 * decode passes (kgenome_diag_walk_runs). So a producer that runs on its own, apart
 * from the engine's latch, is seen too.
 *
 * WHAT THIS SCANS: hand-built ELF and PE objects, through the whole pipeline
 * (kscan_bytes) against the test database - static and stripped, with and without
 * symbols, 32 and 64 bit, a relocatable object, a PE that resolves its own APIs -
 * each on a FRESH scanner and again twice on ONE scanner, so a product that leaks
 * into the next object, or is rebuilt because the latch was not reset, shows.
 *
 * THE EXCEPTIONS are tasks that exist to run a product again, and the table below is
 * where they are named, each with its reason; the code that does it says so with
 * kof_prod_again, which does not count as a repeat. Today the table is EMPTY: the
 * emulator runs are not products of the object (a request, with a start and a
 * budget of its own), and no other task re-makes one. A product that needs a
 * second run for a real reason is added here with that reason, not allowed by
 * raising a number.
 */

#include "caps_fix.h"
#include "caps_e2e.h"
#include "caps_pe_fix.h"
#include "../../libkofeng/scanners/scan.h"

static struct { enum kof_prodkind p; unsigned allowed; const char *reason; } exceptions[] = {
	{ KOF_PROD_COUNT, 0, "none: no task re-makes a product of the object" }
};

static unsigned allowed(enum kof_prodkind p)
{
	unsigned i;

	for (i = 0; i < sizeof exceptions / sizeof exceptions[0]; i++)
		if (exceptions[i].p == p)
			return exceptions[i].allowed;
	return 0;
}

static uint8_t img[1u << 21];
static uint8_t code[1u << 20];

static void check_scanner(kof_scanner *sc, const char *what)
{
	unsigned p;

	for (p = 0; p < KOF_PROD_COUNT; p++) {
		unsigned r = kof_scan_prod_repeats(sc, (enum kof_prodkind)p);

		if (r > allowed((enum kof_prodkind)p))
			printf("  %s: product '%s' was made again for one object %u time(s)\n",
			       what, kof_prod_name((enum kof_prodkind)p), r);
		CK(r <= allowed((enum kof_prodkind)p));
	}
}

static void scan_it(const char *what, const uint8_t *b, uint64_t len, int times)
{
	kof_scanner *sc = kscan_new(e2e_eng);
	struct kof_scan_option opt;
	struct e2e r;
	int i;

	CK(sc != NULL);
	if (!sc)
		return;
	memset(&opt, 0, sizeof opt);
	opt.max_produced_bytes = 64u << 20;
	opt.max_resident_bytes = 256u << 20;
	opt.max_object_bytes = 64u << 20;
	for (i = 0; i < times; i++) {
		memset(&r, 0, sizeof r);
		(void)kscan_bytes(sc, b, len, what, &opt, e2e_on_object, &r);
		CK(r.n > 0);
		/* nothing is built more than once for the object just scanned */
		{
			unsigned p;

			for (p = 0; p < KOF_PROD_COUNT; p++)
				CK(sc->obj.prod_runs[p] <= 1u + allowed((enum kof_prodkind)p));
		}
	}
	check_scanner(sc, what);
	kscan_free(sc);
}

static void elf_shapes(void)
{
	unsigned n, i;
	uint64_t len;

	n = cf_stager64(code, 0);
	len = cf_elf64(img, sizeof img, code, n);
	scan_it("elf64 stager, no sections", img, len, 3);
	len = cf_add_sections(img, len, 1, 0x78, n, 0x400078, 1);
	scan_it("elf64 stager, with symbols", img, len, 3);

	for (n = 0, i = 0; i < 300; i++)
		n = cf_filler64(code, n, i);
	n = cf_stager64(code, n);
	len = cf_elf64(img, sizeof img, code, n);
	scan_it("elf64, 300 reads then the stager", img, len, 2);
	len = cf_add_sections(img, len, 1, 0x78, n, 0x400078, 0);
	scan_it("elf64 stripped, with a section table", img, len, 2);

	n = cf_stager64(code, 0);
	len = cf_elf32(img, sizeof img, code, n);
	scan_it("elf32", img, len, 2);

	len = cf_kmod(img, sizeof img, 4, 0);
	scan_it("relocatable object (kernel module shape)", img, len, 3);
}

static void pe_shapes(void)
{
	unsigned n;
	uint64_t len;

	n = pe32_stager(code, 0);
	len = pe_code(img, sizeof img, code, n, 0);
	scan_it("pe32 stager", img, len, 3);
	n = pe64_stager(code, 0);
	len = pe_code(img, sizeof img, code, n, 1);
	scan_it("pe64 stager", img, len, 3);
}

/* The counter itself: a named repeat is not a repeat, an unnamed one is. */
static void counter(void)
{
	kof_scanner *sc = kscan_new(e2e_eng);

	CK(sc != NULL);
	if (!sc)
		return;
	CK(kof_scan_prod_repeats(sc, KOF_PROD_SYMS) == 0);
	kof_prod_ran(sc, KOF_PROD_SYMS);
	CK(kof_scan_prod_repeats(sc, KOF_PROD_SYMS) == 0);
	kof_prod_again(sc, KOF_PROD_SYMS);
	CK(kof_scan_prod_repeats(sc, KOF_PROD_SYMS) == 0);
	kof_prod_ran(sc, KOF_PROD_SYMS);
	CK(kof_scan_prod_repeats(sc, KOF_PROD_SYMS) == 1);
	CK(kof_scan_prod_repeats(sc, KOF_PROD_FUNCS) == 0);
	CK(strcmp(kof_prod_name(KOF_PROD_WALK), "walk") == 0);
	kscan_free(sc);
}

int main(void)
{
	if (!e2e_open(NULL)) {
		printf("prod_once: no test database\n");
		return 1;
	}
	counter();
	elf_shapes();
	pe_shapes();
	printf("prod_once: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
