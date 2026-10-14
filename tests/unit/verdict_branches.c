/*
 * verdict_branches - what the syndrome layer makes of EVERY SHAPE of disease set.
 *
 * Two layers, both pinned, because the verdict a person reads is the product of
 * both and either can be wrong while the other is right:
 *
 *   kof_synd_infer / kof_synd_name   (databases/pack/kofsyndrome.c)
 *       the set algebra and the four spellings, on a table small enough to read;
 *   sx_syndrome_verdict              (verdictor/syndrome.c)
 *       how that lands in a finding: level, type word, family, reason, and
 *       whether it lands at all - through the whole scan, on objects built from
 *       the detector fixtures tests/sigs/sig_verdict_*.c and the exemplars
 *       tests/sigs/syndromes/vd_*.c.
 *
 * WHAT THIS CATCHES, per case. A WRONG-EXPECTED verdict is worse than a missed
 * one: an object is named a Botnet when its behaviours are what a Miner shows
 * too, or Predict is printed for a set that proved a type, or Unresolved for a
 * set the table does cover. The cases are one per branch:
 *
 *   proven, one type           {alpha, beta}       Miner:Agent, Infected
 *   proven, two types          {eps, zeta}         Rootkit:Agent ?Exploit
 *   proven, two exemplars      {alpha, beta, gamma} Botnet:Agent ?Miner  (a
 *                                                  query that shows two samples
 *                                                  proves both - and is a
 *                                                  superset of each)
 *   proven, three types        {alpha..delta}      Trojan:Agent ?Botnet+Miner
 *   possible, one type         {beta}, {delta}     X:Agent.Predict, Suspected
 *   possible, several          {alpha}, {gamma}    Malware:Ambiguous ?A,B
 *   none possible              {orphan}            Malware:Unresolved, Infected
 *   unknown beside known       {alpha, orphan}     Unresolved (a behaviour nobody
 *                                                  verified is not evidence for
 *                                                  any type, and blocks them all)
 *   nothing found              {}                  no verdict at all
 *
 * and the one the cap in sx_syndrome_verdict makes: the finding array holds 16;
 * when it is full the verdict is DROPPED (res->dropped++) and the object has no
 * verdict at all. That is recorded below as a KNOWN-MISS - the verdict is the
 * object's identity and is the one finding that must not be what is cut.
 *
 * ONE PIN THAT IS A QUESTION, NOT A DEFECT: {eps} alone is named
 * Ambiguous(Rootkit,Exploit) although the only exemplar compatible with it was
 * a sample that was BOTH. [Inference] The set of possible types is a union over
 * exemplars and loses that two of them came from one sample. It is pinned as it
 * is so that a change is seen; whether "Rootkit+Exploit:Agent.Predict" is the
 * right word is the owner's call.
 */

#include "caps_fix.h"
#include "caps_pe_fix.h"
#include "caps_e2e.h"
#include "known_miss.h"
#include "../../libkofeng/databases/pack/kofsyndrome.h"
#include "../../libkofeng/analyzers/diseases/kofdisease.h"

#define T(x) (1u << (x))

/* ---- layer 1: the inference, on a table -------------------------------------- */

static uint32_t id(const char *s)
{
	return kof_disease_id(s);
}

static void inference(void)
{
	/* the same four exemplars the fixtures declare, as ids */
	static uint32_t miner[2], botnet[2], trojan[2], multi[2];
	struct kof_synd_in in[4];
	struct kof_synd_set *s;
	struct kof_synd_result r;
	char nm[96];
	uint32_t q[4];

	miner[0] = id("verdict/alpha");  miner[1] = id("verdict/beta");
	botnet[0] = id("verdict/alpha"); botnet[1] = id("verdict/gamma");
	trojan[0] = id("verdict/gamma"); trojan[1] = id("verdict/delta");
	multi[0] = id("verdict/eps");    multi[1] = id("verdict/zeta");
	in[0].type_mask = T(KOF_MALTYPE_MINER);   in[0].n_dis = 2; in[0].dis = miner;
	in[1].type_mask = T(KOF_MALTYPE_BOTNET);  in[1].n_dis = 2; in[1].dis = botnet;
	in[2].type_mask = T(KOF_MALTYPE_TROJAN);  in[2].n_dis = 2; in[2].dis = trojan;
	in[3].type_mask = T(KOF_MALTYPE_ROOTKIT) | T(KOF_MALTYPE_EXPLOIT);
	in[3].n_dis = 2; in[3].dis = multi;
	s = kof_synd_build(in, 4);
	CK(s && kof_synd_count(s) == 4u);

	/* proven, one type: the query IS an exemplar and only it shows it */
	q[0] = id("verdict/alpha"); q[1] = id("verdict/beta");
	CK(kof_synd_infer(s, q, 2, &r) == 1);
	CK(r.guaranteed == T(KOF_MALTYPE_MINER) && r.possible == 0 && r.n_compat == 1);
	kof_synd_name(&r, nm, sizeof nm);
	CK(!strcmp(nm, "Miner:Agent"));

	/* possible, one: a strict subset of one exemplar */
	q[0] = id("verdict/beta");
	CK(kof_synd_infer(s, q, 1, &r) == 1);
	CK(r.guaranteed == 0 && r.possible == T(KOF_MALTYPE_MINER) && r.n_compat == 1);
	kof_synd_name(&r, nm, sizeof nm);
	CK(!strcmp(nm, "Miner:Agent.Predict"));

	/* possible, several: a subset of two exemplars of different types */
	q[0] = id("verdict/alpha");
	CK(kof_synd_infer(s, q, 1, &r) == 1);
	CK(r.guaranteed == 0 && r.n_compat == 2);
	CK(r.possible == (T(KOF_MALTYPE_MINER) | T(KOF_MALTYPE_BOTNET)));
	kof_synd_name(&r, nm, sizeof nm);
	CK(!strcmp(nm, "Ambiguous(Botnet,Miner)"));

	/* proven twice: a superset of two exemplars proves both types, and is
	 * compatible with none (no sample showed all three) */
	q[0] = id("verdict/alpha"); q[1] = id("verdict/beta"); q[2] = id("verdict/gamma");
	CK(kof_synd_infer(s, q, 3, &r) == 1);
	CK(r.guaranteed == (T(KOF_MALTYPE_MINER) | T(KOF_MALTYPE_BOTNET)));
	CK(r.possible == 0 && r.n_compat == 0);
	kof_synd_name(&r, nm, sizeof nm);
	CK(!strcmp(nm, "Botnet+Miner:Agent"));

	/* proven with a leftover: the query is an exemplar AND a subset of a
	 * different one's - not here (no exemplar contains another), so build
	 * it: {alpha, gamma} is the botnet exemplar and a subset of nothing else */
	q[0] = id("verdict/alpha"); q[1] = id("verdict/gamma");
	CK(kof_synd_infer(s, q, 2, &r) == 1);
	CK(r.guaranteed == T(KOF_MALTYPE_BOTNET) && r.possible == 0);

	/* one exemplar of two types: proven, both, in the type-bit order */
	q[0] = id("verdict/eps"); q[1] = id("verdict/zeta");
	CK(kof_synd_infer(s, q, 2, &r) == 1);
	CK(r.guaranteed == (T(KOF_MALTYPE_ROOTKIT) | T(KOF_MALTYPE_EXPLOIT)));
	kof_synd_name(&r, nm, sizeof nm);
	CK(!strcmp(nm, "Rootkit+Exploit:Agent"));

	/* nothing covers it, and the unknown one blocks the known one */
	q[0] = id("verdict/alpha"); q[1] = id("verdict/orphan");
	CK(kof_synd_infer(s, q, 2, &r) == 1);
	CK(r.guaranteed == 0 && r.possible == 0 && r.n_unknown == 1 && r.n_compat == 0);
	kof_synd_name(&r, nm, sizeof nm);
	CK(!strcmp(nm, "Malware:Unresolved"));

	/* no disease: no answer */
	CK(kof_synd_infer(s, q, 0, &r) == 0 && r.n_query == 0);
	kof_synd_free(s);
}

/* ---- layer 2: through the scan ----------------------------------------------- */

static uint8_t buf[1024];
static uint8_t img[1u << 20];
static uint8_t code[4096];

/* an object carrying the markers of `set`, a space-separated list in capitals */
static int build(const char *set)
{
	const char *p = set;
	unsigned at = 0;
	char tok[32];

	memset(buf, 0x41, sizeof buf);
	while (*p) {
		unsigned l = 0;

		while (*p && *p != ' ' && l + 1u < sizeof tok)
			tok[l++] = *p++;
		tok[l] = 0;
		while (*p == ' ')
			p++;
		if (l) {
			snprintf((char *)buf + at, 60, "VERDICT_FIXTURE_%s", tok);
			at += 40;
		}
	}
	return (int)at;
}

static void scan_set(const char *set, struct e2e *r)
{
	build(set);
	CK(e2e_scan(buf, sizeof buf, r));
}

static void expect(const char *set, const char *name, const char *level,
		   const char *reason)
{
	struct e2e r;
	const struct e2e_obj *o;
	char got[112], want[112];

	scan_set(set, &r);
	o = &r.o[0];
	CK(o->verdict[0] != 0);
	CK(o->has_syndrome);
	e2e_type_of(o->verdict, got, sizeof got);
	/* the finding reads  <Level>#Raw/<Type>:<Family>[.Variant]!Syndrome[?<reason>] */
	snprintf(want, sizeof want, "%s#Raw/%s!Syndrome%s%s", level, name,
		 reason ? "?" : "", reason ? reason : "");
	if (strcmp(o->verdict, want)) {
		printf("  FAIL {%s}: verdict '%s', expected '%s'\n", set, o->verdict, want);
		fails++;
	}
}

static void scan_verdicts(void)
{
	struct e2e r;

	expect("ALPHA BETA",       "Miner:Agent",          "Infected",  NULL);
	expect("GAMMA DELTA",      "Trojan:Agent",         "Infected",  NULL);
	expect("ALPHA GAMMA",      "Botnet:Agent",         "Infected",  NULL);
	expect("EPS ZETA",         "Rootkit:Agent",        "Infected",  "Exploit");
	expect("ALPHA BETA GAMMA", "Botnet:Agent",         "Infected",  "Miner");
	expect("ALPHA BETA GAMMA DELTA", "Trojan:Agent",   "Infected",  "Botnet+Miner");
	expect("BETA",             "Miner:Agent.Predict",  "Suspected", NULL);
	expect("DELTA",            "Trojan:Agent.Predict", "Suspected", NULL);
	expect("ALPHA",            "Malware:Ambiguous",    "Suspected", "Botnet,Miner");
	expect("GAMMA",            "Malware:Ambiguous",    "Suspected", "Trojan,Botnet");
	expect("EPS",              "Malware:Ambiguous",    "Suspected", "Rootkit,Exploit");
	expect("ORPHAN",           "Malware:Unresolved",   "Infected",  NULL);
	expect("ALPHA ORPHAN",     "Malware:Unresolved",   "Infected",  NULL);

	/*
	 * THE DISEASES THE OTHER FIXTURES DECLARE, pinned to the exact finding: the
	 * byte-marker detector of sig_disease_00.c (flood-network/udp), the
	 * rwx_exec diagnose on an ELF and on a PE, and kmod_give_root on a kernel
	 * module. Each syndrome fixture names exactly one of them, so each is a
	 * proven single type.
	 */
	{
		static uint8_t b[1024], c[480];
		unsigned n;
		uint64_t len;

		memset(b, 0x41, sizeof b);
		memcpy(b + 16, "DISEASE_FIXTURE_MARKER", 22);
		CK(e2e_scan(b, sizeof b, &r));
		CK(!strcmp(r.o[0].verdict, "Infected#Raw/Botnet:Agent!Syndrome"));

		/* a behaviour two exemplars share, beside one only one shows: the
		 * botnet exemplar is a subset of the query and discriminates */
		memcpy(b + 80, "VERDICT_FIXTURE_ALPHA", 21);
		CK(e2e_scan(b, sizeof b, &r));
		CK(!strcmp(r.o[0].verdict, "Infected#Raw/Botnet:Agent!Syndrome"));

		n = cf_stager64(code, 0);
		len = cf_elf64(img, sizeof img, code, n);
		CK(e2e_scan(img, len, &r));
		CK(!strcmp(r.o[0].verdict, "Infected#ELF-x64/Dropper:Agent!Syndrome"));

		n = pe32_stager(c, 0);
		len = pe32_code(img, sizeof img, c, n);
		CK(e2e_scan(img, len, &r));
		CK(!strcmp(r.o[0].verdict, "Infected#PE-x86/Dropper:Agent!Syndrome"));

		len = cf_kmod(img, sizeof img, 0, 0);
		CK(e2e_scan(img, len, &r));
		CK(!strcmp(r.o[0].verdict, "Infected#ELF-x64/Rootkit:Agent!Syndrome"));

		/* and the same two calls the wrong way round are NOT the diagnose:
		 * no disease, so no syndrome and no syndrome verdict (the fixture's own
		 * disease-less pattern detector is the object's verdict, not a syndrome) */
		len = cf_kmod(img, sizeof img, 0, 1);
		CK(e2e_scan(img, len, &r));
		CK(!strstr(r.o[0].verdict, "!Syndrome") && !r.o[0].has_syndrome);
	}

	/* the numbers the verdict was made from travel with the result */
	scan_set("ALPHA", &r);
	CK(r.o[0].syn.n_query == 1 && r.o[0].syn.n_compat == 2 && r.o[0].syn.n_unknown == 0);
	scan_set("ORPHAN", &r);
	CK(r.o[0].syn.n_query == 1 && r.o[0].syn.n_unknown == 1);

	/* nothing found, nothing said */
	scan_set("", &r);
	CK(r.o[0].n == 0 && r.o[0].verdict[0] == 0 && !r.o[0].has_syndrome);

	/* the detector's own finding is evidence, and is not the verdict */
	scan_set("BETA", &r);
	CK(r.o[0].n == 2);
	CK(strstr(r.o[0].find[0], "VerdictBeta") != NULL);
	CK(strstr(r.o[0].find[1], "Syndrome") != NULL);
}

/*
 * THE EVIDENCE IS FULL. Sixteen detectors in three groups (7 + 7 + 2) fire on a
 * marker each, and the disease detector adds its own finding; the verdict is
 * added LAST, and its slot (the 16th, KOF_MAX_EVIDENCE) is not the evidence's.
 *
 *   14 fillers + the disease's detector = 15 evidence, the verdict is the 16th.
 *   15 fillers + the disease's detector = 16 evidence wanted: the 16th is
 *   counted in res->dropped, and the verdict still has its slot.
 */
static void findings_cap(void)
{
	static uint8_t b[1024];
	struct e2e r;

	memset(b, 0x41, sizeof b);
	memcpy(b, "FINDINGS_FILL_A", 15);
	memcpy(b + 40, "FINDINGS_FILL_B", 15);
	memcpy(b + 80, "VERDICT_FIXTURE_BETA", 20);
	CK(e2e_scan(b, sizeof b, &r));
	CK(r.o[0].n == 16u && r.o[0].dropped == 0);
	CK(e2e_verdict_is(&r.o[0], "Miner"));           /* the verdict fits */

	memcpy(b + 120, "FINDINGS_FILL_C", 15);
	CK(e2e_scan(b, sizeof b, &r));
	CK(r.o[0].n == 16u);
	CK(r.o[0].dropped >= 1u);       /* regression guard: the loss is COUNTED */
	printf("    16 fillers + a disease: %u findings, verdict '%s', dropped %u\n",
	       r.o[0].n, r.o[0].verdict, r.o[0].dropped);
	CK(e2e_verdict_is(&r.o[0], "Miner"));   /* a full evidence array keeps the verdict */
}

int main(int argc, char **argv)
{
	if (!e2e_open(argc > 1 ? argv[1] : NULL)) {
		printf("verdict branches: cannot open the test database\n");
		return 2;
	}
	inference();
	scan_verdicts();
	findings_cap();
	printf("verdict branches: %u known miss(es) recorded, %s\n", km_known(),
	       fails || km_failed() ? "FAILED" : "ok");
	return fails != 0 || km_failed();
}
