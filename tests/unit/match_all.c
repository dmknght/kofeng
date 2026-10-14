/*
 * match_all - the default scan stops at the first hit, and all_matches really does not.
 *
 * BOTH BEHAVIOURS ARE KEPT, behind one flag (kof_scan_option.all_matches): off, an object
 * that a detector named ends the open chain (no normalised view, no block similarity on
 * it), a HEUR line ends the heuristic pass, an INFECT ends the detect stage when the
 * database declares no disease; on, none of them happens. Which should be the default is
 * the owner's call (CLAUDE.md 12, "Where the first-hit stops are"); this test is what
 * makes that review a matter of reading numbers: it pins what each setting does.
 *
 * THE OBJECT is the plain ELF fixture, which carries the compiler's comment: the
 * any-format rule (tests/sigs/sig_anyfmt.c, "GCC: (GNU)") names it at the DETECT stage,
 * and it has a normalised view on which the whole-object block rule
 * (tests/sigs/mutations/anyregion_00.c) fires - on the VIEW, because a block is cut from
 * the view when there is one. So:
 *
 *   all_matches OFF  the detector's finding only; the chain is ended, so the view and the
 *                    block rule never ran on a detected object.
 *   all_matches ON   the detector's finding AND the block rule's, on the view: every
 *                    pattern and every block hash was evaluated on a detected object.
 *
 * (Diagnoses under the flag are held by diag_gate.c: with all_matches the stop at an
 * infection is off and every detector reports; the first-hit stop at a HEUR line and the
 * unpack cancel have their own rows in scan_logic.c.)
 */

#include "caps_fix.h"
#include "caps_e2e.h"
#include "../../libkofeng/kofcore/kofoption.h"

struct seen {
	unsigned objects, views;
	unsigned any_fmt, any_region, any_region_on_view;
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct seen *s = user;
	uint32_t i;

	(void)bytes; (void)len;
	s->objects++;
	if (res->entry_kind == KOF_ENT_NORMALIZED)
		s->views++;
	for (i = 0; i < res->n; i++) {
		if (strstr(res->v[i].name, "AnyFmtTest"))
			s->any_fmt++;
		if (strstr(res->v[i].name, "AnyRegion")) {
			s->any_region++;
			if (res->entry_kind == KOF_ENT_NORMALIZED || (name && strstr(name, "//")))
				s->any_region_on_view++;
		}
	}
	return 0;
}

static struct seen scan(const uint8_t *b, size_t n, int all)
{
	struct kof_scan_option opt;
	struct seen s;
	kof_scanner *sc;

	memset(&s, 0, sizeof s);
	memset(&opt, 0, sizeof opt);
	opt.all_matches = all;
	opt.max_produced_bytes = 64u << 20;
	opt.max_resident_bytes = 256u << 20;
	opt.max_object_bytes = 64u << 20;
	sc = kscan_new(e2e_eng);
	if (sc) {
		(void)kscan_bytes(sc, b, n, "fixture.bin", &opt, on_object, &s);
		kscan_free(sc);
	}
	return s;
}

static uint8_t buf[1u << 20];

int main(int argc, char **argv)
{
	FILE *f = fopen("build/test/fixtures/plain-elf64", "rb");
	size_t n;
	struct seen off, on;

	(void)argc; (void)argv;
	if (!f || !e2e_open(argc > 1 ? argv[1] : NULL)) {
		printf("match_all: no fixture or database - nothing tested\n");
		return 0;
	}
	n = fread(buf, 1, sizeof buf, f);
	fclose(f);

	off = scan(buf, n, 0);
	on = scan(buf, n, 1);
	printf("  off: %u object(s), %u view(s), AnyFmtTest %u, AnyRegion %u (on a view %u)\n",
	       off.objects, off.views, off.any_fmt, off.any_region, off.any_region_on_view);
	printf("  on : %u object(s), %u view(s), AnyFmtTest %u, AnyRegion %u (on a view %u)\n",
	       on.objects, on.views, on.any_fmt, on.any_region, on.any_region_on_view);

	/* the detector names the object either way */
	CK(off.any_fmt >= 1u && on.any_fmt >= 1u);
	/* OFF: the detected object's chain is over: no view, no block similarity */
	CK(off.views == 0u);
	CK(off.any_region == 0u);
	/* ON: the view was made and the block rule was evaluated on it */
	CK(on.views >= 1u);
	CK(on.any_region >= 1u && on.any_region_on_view >= 1u);
	/* what is evaluated only grows */
	CK(on.objects >= off.objects);

	if (fails) {
		printf("match_all: %d check(s) failed\n", fails);
		return 1;
	}
	printf("match_all: all_matches off ends a detected object's chain, on runs the view and the block rule\n");
	return 0;
}
