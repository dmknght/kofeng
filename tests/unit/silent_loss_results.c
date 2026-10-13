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
 *   name_clip      kof_finding.name[224]: a family past what is left is cut and
 *                  the variant, the shape and the reason go with it. No flag.
 *   packer_name    KOF_NAME_MAX_LEN (192) is a constant nothing in the library
 *                  enforces: kof_pack_build takes a 300-character family.
 *   rlist_full     struct kof_rlist: kof_rl_add past `cap` returns, and a
 *                  kof_rl_subtract split that does not fit is dropped; neither
 *                  leaves a flag. kof_runs does (`full`).
 *
 * KM_CHECK is for a loss with no signal; a test returns fails != 0 ||
 * km_failed(), so the day a cap is fixed the marker goes red.
 */

#include "caps_fix.h"
#include "caps_e2e.h"
#include "known_miss.h"
#include "../../libkofeng/databases/dbpacker.h"
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
	 * cut. The finding has no truncated flag; the part that goes is the variant
	 * and the shape, which is what tells two rules of one family apart. */
	KM_CHECK(f.variant.n == 3u && f.shape.n == 5u,
		 "a finding whose family fills the name still carries its variant and shape",
		 "kof_finding.name[224] verdict.c:67 lost: variant, shape and reason are cut "
		 "off a long name with no flag; identity of the rule, not the detection");
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
	KM_CHECK(img == NULL,
		 "a family name longer than KOF_NAME_MAX_LEN is refused by the pack builder",
		 "KOF_NAME_MAX_LEN dbcore.h:486 lost: defined and enforced only by the "
		 "ksigbuilder tool; the library packer and loader take 300 characters and "
		 "the finding clips them (see name_clip)");
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
	for (i = 0; i < 9u; i++)
		kof_rl_add(&l, 1000u, i * 100u, 10u);
	/* nine disjoint ranges asked, eight kept: the ninth is gone and the list has
	 * nothing to say so (n == cap is also what "exactly full" looks like) */
	KM_CHECK(l.n == 9u,
		 "a range list given one range more than its capacity keeps it or says so",
		 "struct kof_rlist rangelist.h:69 (kof_rl_add) lost: the range past cap is "
		 "dropped, no flag; reachable only where a parser's own count limit is above "
		 "the list's [Inference]");

	/* a subtraction that splits a range needs a place for the other half */
	kof_rl_init(&l, buf, 1);
	kof_rl_add(&l, 1000u, 0u, 500u);
	cut.off = 100u;
	cut.len = 50u;
	kof_rl_subtract(&l, &cut, 1);
	KM_CHECK(l.n == 2u,
		 "a range split by a subtraction keeps both halves when the list is full or says so",
		 "struct kof_rlist rangelist.h:213 (kof_rl_subtract) lost: the upper half "
		 "[150,500) is dropped when the list is full, no flag");

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
