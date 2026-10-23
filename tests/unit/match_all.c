/*
 * match_all - nothing a detector says ends the scan of its object.
 *
 * What a module says is a note and the verdict is read off every disease an object has,
 * so a detector that matched does not end the open chain (the normalised view and the
 * block similarity run on it) nor the detect stage.
 *
 * THE OBJECT is the plain ELF fixture, which carries the compiler's comment: the
 * any-format rule (tests/sigs/sig_anyfmt.c, "GCC: (GNU)") matches it at the DETECT stage,
 * and it has a normalised view on which the whole-object block rule
 * (tests/sigs/mutations/anyregion_00.c) matches - on the VIEW, because a block is cut from
 * the view when there is one. So the scan holds the detector's note AND the block
 * rule's, on the view: every pattern and every block hash was evaluated on a matched
 * object.
 *
 * (The detect stage's own rows are in diag_gate.c; the unpack cancel's in scan_logic.c.)
 */

#include "caps_fix.h"
#include "caps_e2e.h"
#include "notes.h"
#include "../../libkofeng/kofcore/kofoption.h"

struct seen {
	unsigned objects, views;
	unsigned any_fmt, any_region, any_region_on_view;
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct seen *s = user;
	struct note_list got;
	uint32_t i;

	(void)bytes; (void)len;
	notes_here(&got);
	s->objects++;
	if (res->entry_kind == KOF_ENT_NORMALIZED)
		s->views++;
	for (i = 0; i < got.n; i++) {
		if (strstr(got.name[i], "AnyFmtTest"))
			s->any_fmt++;
		if (strstr(got.name[i], "AnyRegion")) {
			s->any_region++;
			if (res->entry_kind == KOF_ENT_NORMALIZED || (name && strstr(name, "//")))
				s->any_region_on_view++;
		}
	}
	return 0;
}

static struct seen scan(const uint8_t *b, size_t n)
{
	struct kof_scan_option opt;
	struct seen s;
	kof_scanner *sc;

	memset(&s, 0, sizeof s);
	memset(&opt, 0, sizeof opt);
	opt.max_produced_bytes = 64u << 20;
	opt.max_resident_bytes = 256u << 20;
	opt.max_object_bytes = 64u << 20;
	sc = kscan_new(e2e_eng);
	notes_watch(sc);
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
	struct seen s;

	(void)argc; (void)argv;
	if (!f || !e2e_open(argc > 1 ? argv[1] : NULL)) {
		printf("match_all: no fixture or database - nothing tested\n");
		return 0;
	}
	n = fread(buf, 1, sizeof buf, f);
	fclose(f);

	s = scan(buf, n);
	printf("  %u object(s), %u view(s), AnyFmtTest %u, AnyRegion %u (on a view %u)\n",
	       s.objects, s.views, s.any_fmt, s.any_region, s.any_region_on_view);

	/* the detector names the object */
	CK(s.any_fmt >= 1u);
	/* and the view was made and the block rule was evaluated on it */
	CK(s.views >= 1u);
	CK(s.any_region >= 1u && s.any_region_on_view >= 1u);

	if (fails) {
		printf("match_all: %d check(s) failed\n", fails);
		return 1;
	}
	printf("match_all: a detected object still gets its view and its block rule\n");
	return 0;
}
