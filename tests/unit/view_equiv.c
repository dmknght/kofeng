/*
 * view_equiv - detection must not depend on HOW the object reached the engine:
 * as the file, as its normalised view, as an unpacked child, or as the same
 * payload in a different container.
 *
 * WHAT THESE CATCH, one class each:
 *
 *   VIEW vs PARENT    the normalised view (zero-run collapse, UTF-16 narrowing,
 *                     base64 decode - scan_norm.c) is scanned as an object of
 *                     its own. A diagnose that matches the file and not its
 *                     view means the verdict depends on whether the view was
 *                     made, which depends on padding the author chose. Miss
 *                     class: "detection lost in the view" - and the reverse,
 *                     a view that detects what the file does not, would be a
 *                     wrong-expected result.
 *   UNPACKED CHILD    the payload, once a packer module has produced it, is
 *                     the same object it would have been as a file: same
 *                     verdict. Miss class: "child analysed differently from a
 *                     file".
 *   ROUTE MATRIX      the SAME payload (the rwx_exec stager, bytes identical)
 *                     in ELF x86-64 / i386, with and without a section table,
 *                     with and without a symbol table, and as PE32 / PE64.
 *                     Which analysis routine runs is decided by what the
 *                     container offers (objctx_diag.c diag_servable), not by
 *                     what the bytes do. Miss class: "route gate": a payload
 *                     that is detected in one wrapper and silent in another.
 *
 * EVERY EXPECTATION IS THE CORRECT BEHAVIOUR (all rows detected, view equal to
 * parent). Rows the engine gets right are normal checks; rows it gets wrong
 * are KM_CHECKs - KNOWN-MISS now, FIXED-UNEXPECTEDLY (red) the day they are
 * fixed. The measured finding is printed beside each.
 *
 * NOT BUILT, and why: a base64-payload view fixture. The decode pass rewrites a
 * span of an OVERLAY, and the diagnose reads code regions only, so a payload
 * there is never code the diagnose could be asked about - there is no
 * expected verdict to pin, and an invented one would be a guess.
 */

#include "caps_fix.h"
#include "caps_pe_fix.h"
#include "caps_e2e.h"
#include "known_miss.h"

static uint8_t img[1u << 21];
static uint8_t code[1u << 20];
static unsigned char view[1u << 22];

/* the i386 stager of diag_nodes.c, byte for byte */
static const uint8_t stager32[] = {
	0x6a, 0x0a, 0x5e, 0x31, 0xdb, 0xf7, 0xe3, 0x53, 0x43, 0x53,
	0x6a, 0x02, 0xb0, 0x66, 0x89, 0xe1, 0xcd, 0x80, 0x97, 0x5b,
	0x68, 0xc0, 0xa8, 0x32, 0x0c, 0x68, 0x02, 0x00, 0x22, 0xb8,
	0x89, 0xe1, 0x6a, 0x66, 0x58, 0x50, 0x51, 0x57, 0x89, 0xe1,
	0x43, 0xcd, 0x80, 0x85, 0xc0, 0x79, 0x19, 0x4e, 0x74, 0x3d,
	0x68, 0xa2, 0x00, 0x00, 0x00, 0x58, 0x6a, 0x00, 0x6a, 0x05,
	0x89, 0xe3, 0x31, 0xc9, 0xcd, 0x80, 0x85, 0xc0, 0x79, 0xbd,
	0xeb, 0x27, 0xb2, 0x07, 0xb9, 0x00, 0x10, 0x00, 0x00, 0x89,
	0xe3, 0xc1, 0xeb, 0x0c, 0xc1, 0xe3, 0x0c, 0xb0, 0x7d, 0xcd,
	0x80, 0x85, 0xc0, 0x78, 0x10, 0x5b, 0x89, 0xe1, 0x99, 0xb6,
	0x0c, 0xb0, 0x03, 0xcd, 0x80, 0x85, 0xc0, 0x78, 0x02, 0xff,
	0xe1, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xbb, 0x01, 0x00, 0x00,
	0x00, 0xcd, 0x80
};

static int same_findings(const struct e2e_obj *a, const struct e2e_obj *b)
{
	uint32_t i;

	if (a->n != b->n)
		return 0;
	for (i = 0; i < a->n && i < E2E_MAX_FIND; i++)
		if (strcmp(a->find[i], b->find[i]))
			return 0;
	return 1;
}

static const struct e2e_obj *child_of(const struct e2e *r, uint32_t kind)
{
	unsigned i;

	for (i = 1; i < r->n; i++)
		if (r->o[i].entry_kind == kind)
			return &r->o[i];
	return NULL;
}

/* ---- the view ------------------------------------------------------------- */

static void wide_text(uint8_t *b, uint64_t *len)
{
	const char *w = "Permission denied Connection refused";
	unsigned i;

	for (i = 0; w[i]; i++) {
		b[(*len)++] = (uint8_t)w[i];
		b[(*len)++] = 0;
	}
}

static void view_vs_parent(void)
{
	struct e2e r;
	const struct e2e_obj *v;
	uint64_t len;
	unsigned n;

	/*
	 * ELF: the stager, then an overlay of 8 KB of zeros and a UTF-16 string.
	 * The view collapses the one and narrows the other; the code is kept.
	 */
	n = cf_stager64(code, 0);
	len = cf_elf64(img, sizeof img, code, n);
	memset(img + len, 0, 8192);
	len += 8192;
	wide_text(img, &len);
	CK(e2e_scan(img, len, &r));
	CK(e2e_verdict_is(&r.o[0], "Dropper"));
	v = child_of(&r, KOF_ENT_NORMALIZED);
	CK(v != NULL);                                  /* the fixture makes a view */
	if (v) {
		CK(same_findings(&r.o[0], v));
		CK(e2e_verdict_is(v, "Dropper"));
	}

	/*
	 * ELF with a section table AND a gap of zeros between the code and that
	 * table: the collapse moves .symtab, .strtab and the section headers, so
	 * the view's header (the parent's, byte for byte) points at the wrong
	 * bytes. The view is handed the parent's description with the offsets
	 * moved and the parent's analysis, so it still says Dropper.
	 */
	n = cf_stager64(code, 0);
	len = cf_elf64(img, sizeof img, code, n);
	memset(img + len, 0, 6000);
	len += 6000;
	len = cf_add_sections(img, len, 1, 0x78, n, 0x400078, 1);
	wide_text(img, &len);
	CK(e2e_scan(img, len, &r));
	CK(e2e_verdict_is(&r.o[0], "Dropper"));
	v = child_of(&r, KOF_ENT_NORMALIZED);
	CK(v != NULL);
	if (v) {
		CK(same_findings(&r.o[0], v));
		CK(e2e_verdict_is(v, "Dropper"));
	}

	/*
	 * PE32: the same shape. The view collapses the zero tail of the file and
	 * narrows the string, which MOVES every byte after the first collapsed run
	 * - and the view's header is the parent's, still naming the old offsets. The
	 * view is not parsed: it is handed the parent's image description with its
	 * offsets carried through the transform, and the parent's analysis, so it
	 * says what the parent says.
	 */
	{
		uint8_t c[480];
		unsigned cn = pe32_stager(c, 0);

		len = pe32_code(img, sizeof img, c, cn);
		memset(img + len, 0, 6000);
		len += 6000;
		wide_text(img, &len);
		CK(e2e_scan(img, len, &r));
		CK(e2e_verdict_is(&r.o[0], "Dropper"));
		v = child_of(&r, KOF_ENT_NORMALIZED);
		CK(v != NULL);
		if (v) {
			CK(same_findings(&r.o[0], v));
			CK(e2e_verdict_is(v, "Dropper"));
		}
	}
	{
		uint8_t c[480];
		unsigned cn = pe64_stager(c, 0);

		len = pe_code(img, sizeof img, c, cn, 1);
		memset(img + len, 0, 6000);
		len += 6000;
		wide_text(img, &len);
		CK(e2e_scan(img, len, &r));
		CK(e2e_verdict_is(&r.o[0], "Dropper"));
		v = child_of(&r, KOF_ENT_NORMALIZED);
		CK(v != NULL);
		if (v) {
			CK(same_findings(&r.o[0], v));
			CK(e2e_verdict_is(v, "Dropper"));
		}
	}
}

/* ---- the unpacked child ---------------------------------------------------- */

/*
 * The module of tests/sigs/custom_stub_demo.c: a marker, then bytes XORed with a
 * rolling key (0x5a, +0x1b per literal) with `ESC n b` for runs. The payload is
 * the headerless x86-64 stager ELF.
 */
static uint64_t custom_packed(const uint8_t *inner, unsigned il, uint8_t *out)
{
	uint64_t ol;
	unsigned k;
	uint8_t key = 0x5a;

	code[0] = 0xc3;
	ol = cf_elf64(out, 8192, code, 1);              /* the host: an ELF that returns */
	memcpy(out + ol, "KOFSTUB0", 8);
	ol += 8;
	for (k = 0; k < il; k++) {
		uint8_t c = (uint8_t)(inner[k] ^ key);

		if (c == 0xa5) {                        /* would read as the escape */
			out[ol++] = 0xa5; out[ol++] = 1; out[ol++] = inner[k];
		} else {
			out[ol++] = c;
			key = (uint8_t)(key + 0x1b);
		}
	}
	return ol;
}

static void unpacked_child(void)
{
	static uint8_t inner[4096], outer[8192];
	struct e2e alone, packed;
	uint64_t il, ol;
	unsigned n;

	n = cf_stager64(code, 0);
	il = cf_elf64(inner, sizeof inner, code, n);
	CK(e2e_scan(inner, il, &alone));
	CK(e2e_verdict_is(&alone.o[0], "Dropper"));

	ol = custom_packed(inner, (unsigned)il, outer);
	CK(e2e_scan(outer, ol, &packed));
	CK(packed.n >= 2);                              /* host and what it unpacked */
	if (packed.n >= 2) {
		/* the host says nothing - the payload is hidden in it - and the
		 * child says what the same bytes say as a file */
		CK(!e2e_verdict_is(&packed.o[0], "Dropper"));
		CK(same_findings(&packed.o[1], &alone.o[0]));
		CK(e2e_verdict_is(&packed.o[1], "Dropper"));
	}
}

/* ---- the route matrix ------------------------------------------------------- */

struct row { const char *what; int detected; };

static struct row rows[16];
static unsigned n_rows;

static void row(const char *what, const uint8_t *b, uint64_t len)
{
	struct e2e r;

	CK(e2e_scan(b, len, &r));
	rows[n_rows].what = what;
	rows[n_rows].detected = r.n && e2e_verdict_is(&r.o[0], "Dropper");
	n_rows++;
}

static void route_matrix(void)
{
	uint8_t c[480];
	uint64_t len;
	unsigned n, i;

	n = cf_stager64(code, 0);
	len = cf_elf64(img, sizeof img, code, n);
	row("ELF x86-64, no section table (msfvenom template)", img, len);

	len = cf_add_sections(img, len, 1, 0x78, n, 0x400078, 0);
	row("ELF x86-64, section table, no .symtab (stripped)", img, len);
	/* THE ANALYSIS ITSELF IS NOT THE PROBLEM: asked directly, the syscall
	 * sweep finds the stager in the very same file. What is silent is the
	 * decision not to ask - the cause named on the KNOWN-MISS below. */
	{
		struct kof_obj_ctx ctx;
		struct kgenome_diag_scan *s;

		memset(view, 0, sizeof view);
		s = cf_scan(img, len, KGENOME_DIAG_RUN_SYSCALL, &ctx, view);
		CK(cf_match_rwx(s) == 1);
		kgenome_diag_scan_free(s);
	}

	len = cf_elf64(img, sizeof img, code, n);
	len = cf_add_sections(img, len, 1, 0x78, n, 0x400078, 1);
	row("ELF x86-64, section table and .symtab", img, len);

	len = cf_elf32(img, sizeof img, stager32, sizeof stager32);
	row("ELF i386, no section table", img, len);

	len = cf_elf32(img, sizeof img, stager32, sizeof stager32);
	len = cf_add_sections32(img, len, 0x54, sizeof stager32, 0x8048054u);
	row("ELF i386, section table, no .symtab", img, len);

	n = pe32_stager(c, 0);
	len = pe32_code(img, sizeof img, c, n);
	row("PE32, API calls through the loader data", img, len);

	n = pe64_stager(c, 0);
	len = pe_code(img, sizeof img, c, n, 1);
	row("PE32+, API calls through the loader data", img, len);

	for (i = 0; i < n_rows; i++)
		printf("    %-52s %s\n", rows[i].what,
		       rows[i].detected ? "detected" : "NOT detected");

	/* every row is detected, whatever the container carries */
	CK(rows[0].detected);
	CK(rows[1].detected);                  /* the stager in an x86-64 ELF with a section table (stripped) is detected */
	CK(rows[2].detected);                  /* the stager in an x86-64 ELF with a .symtab is detected */
	CK(rows[3].detected);
	CK(rows[4].detected);                  /* the stager in an i386 ELF with a section table is detected */
	CK(rows[5].detected);
	CK(rows[6].detected);
}

int main(int argc, char **argv)
{
	if (!e2e_open(argc > 1 ? argv[1] : NULL)) {
		printf("view equiv: cannot open the test database\n");
		return 2;
	}
	view_vs_parent();
	unpacked_child();
	route_matrix();
	printf("view equiv: %u known miss(es) recorded, %s\n", km_known(),
	       fails || km_failed() ? "FAILED" : "ok");
	return fails != 0 || km_failed();
}
