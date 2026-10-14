/*
 * silent_loss_results - the containers a RESULT is carried in (findings, names,
 * range lists) held to one invariant: more than fits gives the full result or a
 * SIGNAL a caller can read.
 *
 *   findings_cap   KOF_MAX_FINDINGS / KOF_MAX_EVIDENCE: sixteen detectors and a
 *                  disease on one object. The overflow is COUNTED in
 *                  kof_result.dropped, the verdict keeps its reserved slot, and
 *                  the disease of a dropped finding still reaches the syndrome
 *                  (sx_disease_add runs before the room is looked at). Needs the
 *                  test database (build/test/databases-sigs), like
 *                  verdict_branches.c.
 *   name_clip      kof_finding.name[224]: when a name does not fit the FAMILY gives,
 *                  the variant, shape and reason stay whole, and `name_cut` says so.
 *   packer_name    KOF_NAME_MAX_LEN (192): the library packer and the loader hold a
 *                  name to it, as ksigbuilder does.
 *   rlist_full     struct kof_rlist: kof_rl_add past `cap`, and a kof_rl_subtract
 *                  split that does not fit, drop a range and set `overflow`; the
 *                  region resolvers hand it to the engine through kof_rl_finish.
 *
 * KM_CHECK is for a loss with no signal; a test returns fails != 0 ||
 * km_failed(), so the day a cap is fixed the marker goes red.
 */

#define _GNU_SOURCE

#include "caps_fix.h"
#include "caps_e2e.h"
#include "known_miss.h"
#include "../../libkofeng/databases/dbpacker.h"
#include "../../libkofeng/databases/dbloader_int.h"
#include "../../libkofeng/databases/pack/dbcore.h"
#include "../../libkofeng/kofcore/rangelist.h"
#include "../../libkofeng/kofcore/runlist.h"
#include "../../libkofeng/verdictor/verdict.h"

/* ---- KOF_MAX_FINDINGS -------------------------------------------------------- */

static void findings_cap(void)
{
	static uint8_t b[1024];
	struct e2e r;

	memset(b, 0x41, sizeof b);
	/* all three groups of fillers (7 + 7 + 2 detectors) and the disease's own
	 * detector: 17 findings of evidence for 15 places */
	memcpy(b, "FINDINGS_FILL_A", 15);
	memcpy(b + 40, "FINDINGS_FILL_B", 15);
	memcpy(b + 120, "FINDINGS_FILL_C", 15);
	memcpy(b + 80, "VERDICT_FIXTURE_BETA", 20);
	CK(e2e_scan(b, sizeof b, &r));
	CK(r.n >= 1u);
	printf("    17 evidence findings: n %u, dropped %u, verdict '%s'\n",
	       r.o[0].n, r.o[0].dropped, r.o[0].verdict);

	/* the array is full, and the engine says that findings are missing */
	CK(r.o[0].n == KOF_MAX_FINDINGS);
	CK(r.o[0].dropped == 17u - KOF_MAX_EVIDENCE);
	/* the evidence that did not fit was a detector's: the verdict is the
	 * syndrome's and is still there, derived from the disease of the finding
	 * that was dropped */
	CK(e2e_verdict_is(&r.o[0], "Miner"));
	CK(r.o[0].verdict[0] != 0);

	/* just inside the bound: nothing is dropped */
	memset(b, 0x41, sizeof b);
	memcpy(b, "FINDINGS_FILL_A", 15);
	memcpy(b + 40, "FINDINGS_FILL_B", 15);
	CK(e2e_scan(b, sizeof b, &r));
	CK(r.o[0].n == 14u && r.o[0].dropped == 0u);
}

/* ---- a name that does not fit a finding ---------------------------------------- */

static void name_clip(void)
{
	static char fam[260];
	struct kof_finding f;

	memset(fam, 'F', 250);
	fam[250] = 0;
	memset(&f, 0, sizeof f);
	kverdict_name(&f, "ELF-x64", "Trojan", fam, "Gen", "Shape");
	/* what a reader of a finding wants: the whole name, or a way to know it was
	 * cut. The part that gives is the FAMILY: the variant and the shape, which
	 * tell two rules of one family apart, stay whole, and name_cut says so. */
	CK(f.variant.n == 3u && f.shape.n == 5u);
	CK(f.family.n < 250u && f.family.n > 100u);
	CK(f.name_cut == 1u);
	CK(!memcmp(f.name + f.variant.at, "Gen", 3) && !memcmp(f.name + f.shape.at, "Shape", 5));
	CK(strlen(f.name) < sizeof f.name);

	/* a name that fits is not flagged, and is exactly what it always was */
	memset(&f, 0xff, sizeof f);
	kverdict_name(&f, "ELF-x64", "Trojan", "Fam", "Gen", "Shape");
	CK(f.name_cut == 0u && !strcmp(f.name, "ELF-x64/Trojan:Fam#Gen!Shape"));
	/* the longest family a pack may carry (191) beside a long variant still fits
	 * or is cut in the family - never in the variant */
	memset(fam, 'F', 191);
	fam[191] = 0;
	{
		static char var[200];

		memset(var, 'v', 190);
		var[190] = 0;
		memset(&f, 0, sizeof f);
		kverdict_name(&f, "ELF-x64", "Trojan", fam, var, "Shape");
		CK(f.variant.n == 190u && f.shape.n == 5u && f.name_cut == 1u);
	}
	/* the struct did not grow: the flag sits in what the layout already padded */
	_Static_assert(offsetof(struct kof_finding, name_cut) < offsetof(struct kof_finding, sim_of),
		       "name_cut must live in the padding before sim_of");
}

/* ---- KOF_NAME_MAX_LEN ----------------------------------------------------------- */

static void packer_name(void)
{
	static char fam[300];
	static const uint8_t code_ret[] = { 0xc3u };
	struct kof_pw_mod m;
	size_t len = 0;
	uint8_t *img;

	memset(fam, 'x', sizeof fam - 1u);
	fam[sizeof fam - 1u] = 0;
	memset(&m, 0, sizeof m);
	m.code = code_ret;
	m.code_len = 1;
	m.scan_mask = KOF_SCAN_ALL;
	m.family = fam;
	img = kof_pack_build(KOF_PACK_DETECT, &m, 1, &len);
	CK(img == NULL);        /* the library packer holds a name to the bound the tool does */
	free(img);

	/* the longest name there is room for builds, and is read back */
	fam[KOF_NAME_MAX_LEN - 1u] = 0;
	img = kof_pack_build(KOF_PACK_DETECT, &m, 1, &len);
	CK(img != NULL);
	if (img) {
		struct kof_pack_hdr *h = (struct kof_pack_hdr *)img;
		uint8_t *at;

		CK(kof_db_pack_valid(img, len, "built") == 1);
		/* a pack from another writer: the family's terminator gone, so the string
		 * runs on past the bound - with the checksum made right, so that the
		 * length is the only thing wrong */
		at = memmem(img, len, "xxxxxxxxxxxxxxxx", 16u);
		if (at && at[KOF_NAME_MAX_LEN - 1u] == 0) {
			at[KOF_NAME_MAX_LEN - 1u] = 'x';
			h->crc32 = kof_crc32(img + KOF_PACK_CRC_FROM, len - KOF_PACK_CRC_FROM);
			CK(kof_db_pack_valid(img, len, "built") == 0);
		} else {
			CK(0 && "the fixture family was not found in the image");
		}
	}
	free(img);
}

/* ---- range lists ------------------------------------------------------------------ */

static void rlist_full(void)
{
	struct kof_range buf[8], cut;
	struct kof_rlist l;
	struct kof_runs rn;
	struct kof_run rbuf[4];
	unsigned i;

	kof_rl_init(&l, buf, 8);
	CK(!l.overflow);
	for (i = 0; i < 9u; i++)
		kof_rl_add(&l, 1000u, i * 100u, 10u);
	/* nine disjoint ranges asked, eight kept: the ninth is gone - and the list SAYS
	 * so (n == cap alone is also what "exactly full" looks like) */
	CK(l.n == 8u && l.overflow == 1u);
	/* exactly full is not overflow */
	kof_rl_init(&l, buf, 8);
	for (i = 0; i < 8u; i++)
		kof_rl_add(&l, 1000u, i * 100u, 10u);
	CK(l.n == 8u && l.overflow == 0u);
	/* a range clipped to nothing is not a dropped one either */
	kof_rl_add(&l, 1000u, 5000u, 10u);
	CK(l.overflow == 0u);

	/* a subtraction that splits a range needs a place for the other half */
	kof_rl_init(&l, buf, 1);
	kof_rl_add(&l, 1000u, 0u, 500u);
	cut.off = 100u;
	cut.len = 50u;
	kof_rl_subtract(&l, &cut, 1);
	CK(l.n == 1u && l.overflow == 1u);
	/* with room it keeps both halves and says nothing */
	kof_rl_init(&l, buf, 2);
	kof_rl_add(&l, 1000u, 0u, 500u);
	kof_rl_subtract(&l, &cut, 1);
	CK(l.n == 2u && l.overflow == 0u);

	/* what a resolver hands the engine: "did not fit" (count == cap), the tail made
	 * of zero-length ranges, offsets still ascending - also when merging would have
	 * brought the list back under cap */
	kof_rl_init(&l, buf, 4);
	kof_rl_add(&l, 1000u, 0u, 100u);
	kof_rl_add(&l, 1000u, 100u, 100u);       /* touches: merges with the first */
	kof_rl_add(&l, 1000u, 300u, 10u);
	kof_rl_add(&l, 1000u, 400u, 10u);
	kof_rl_add(&l, 1000u, 500u, 10u);        /* dropped */
	CK(l.overflow == 1u);
	CK(kof_rl_finish(&l) == 4u);
	CK(buf[0].off == 0u && buf[0].len == 200u && buf[1].off == 300u && buf[2].off == 400u);
	CK(buf[3].len == 0u && buf[3].off >= buf[2].off + buf[2].len);
	/* and a list that did not overflow answers its own count */
	kof_rl_init(&l, buf, 4);
	kof_rl_add(&l, 1000u, 0u, 100u);
	kof_rl_add(&l, 1000u, 100u, 100u);
	CK(kof_rl_finish(&l) == 1u);

	/* the run list HAS a flag */
	kof_runs_init(&rn, rbuf, 4, 1);
	for (i = 0; i < 5u; i++)
		kof_runs_add(&rn, 10000u, i * 100u, 10u, 0u);
	CK(rn.n <= 4u);
	CK(rn.full != 0u);
}

int main(int argc, char **argv)
{
	if (!e2e_open(argc > 1 ? argv[1] : NULL)) {
		printf("silent loss results: cannot open the test database\n");
		return 2;
	}
	findings_cap();
	name_clip();
	packer_name();
	rlist_full();
	printf("silent loss results: %u known miss(es) recorded, %s\n", km_known(),
	       fails || km_failed() ? "FAILED" : "ok");
	return fails != 0 || km_failed();
}
