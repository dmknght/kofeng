/*
 * verdict_diseases - the object's verdict is made of the diseases it has, and it says what
 * it was made of.
 *
 * What is pinned, because a person reads the product of it:
 *
 *   THE WAY BACK: the verdict carries the ids of the diseases and of the diagnoses
 *   that matched, and the engine turns an id into a name (kdb_diagnose_name,
 *   kdb_diagnose_disease, kdb_disease_name, kdb_disease_type). The objects here are built
 *   to match the fixture diagnoses of tests/sigs/diagnoses/, which declare the diseases.
 *
 *   THE CUT: a list longer than KOF_VERDICT_TRACE is cut and the total says so.
 *
 * (THE RULE that names a verdict from a set of diseases - the lead is the most specific,
 * the other types are the reason - is a pure function and is pinned directly, on sets of
 * diseases, in api_engine_verdict.c.)
 */

#include "caps_fix.h"
#include "caps_pe_fix.h"
#include "caps_e2e.h"
#include "../../libkofeng/analyzers/diseases/kofdisease.h"

static uint8_t buf[1024];
static uint8_t img[1u << 20];
static uint8_t code[4096];

/* The name a verdict has: the verdict word, '#', then the rest. */
static void vname(char *out, size_t cap, const char *rest)
{
	snprintf(out, cap, "%s#%s", kof_verdict_word(KOF_VERDICT_INFECTED), rest);
}

/* Whether the verdict lists the diagnose of this name. */
static int lists(const struct kof_finding *f, const char *name)
{
	uint32_t i;

	for (i = 0; i < f->n_diag; i++) {
		const char *n = kdb_diagnose_name(e2e_eng, f->diag[i]);

		if (n && !strcmp(n, name))
			return 1;
	}
	return 0;
}

static void the_way_back(void)
{
	struct e2e r;
	const struct kof_finding *f;
	uint32_t i;
	unsigned n;
	uint64_t len;
	char want[160];

	CK(!strcmp(kdb_disease_name(e2e_eng, kof_disease_id("exec/rwx-region")), "exec/rwx-region"));
	CK(kdb_disease_type(e2e_eng, kof_disease_id("exec/rwx-region")) == (int)KOF_MALTYPE_DROPPER);
	CK(!strcmp(kdb_disease_name(e2e_eng, kof_disease_id("kernel/giveroot")), "kernel/giveroot"));
	CK(kdb_disease_type(e2e_eng, kof_disease_id("kernel/giveroot")) == (int)KOF_MALTYPE_ROOTKIT);
	CK(kdb_disease_name(e2e_eng, kof_disease_id("no/such")) == NULL);
	CK(kdb_disease_type(e2e_eng, kof_disease_id("no/such")) == -1);

	/* a diagnose that matched: the verdict lists it, and the engine names it and the
	 * disease it declares */
	n = cf_stager64(code, 0);
	len = cf_elf64(img, sizeof img, code, n);
	CK(e2e_scan(img, len, &r));
	CK(r.o[0].has_verdict);
	vname(want, sizeof want, "ELF-x64/Dropper:exec.rwx-region!Diagnose");
	CK(!strcmp(r.o[0].verdict, want));
	f = &r.o[0].vf;
	CK(f->n_diag >= 1u && f->diag_total == f->n_diag);
	CK(lists(f, "rwx_exec"));
	for (i = 0; i < f->n_diag; i++)         /* every listed diagnose declares the disease */
		CK(kdb_diagnose_disease(e2e_eng, f->diag[i]) == kof_disease_id("exec/rwx-region"));
	CK(f->n_disease == 1u && f->disease[0] == kof_disease_id("exec/rwx-region"));
	CK(kdb_diagnose_name(e2e_eng, 0xdeadbeefu) == NULL && kdb_diagnose_disease(e2e_eng, 0xdeadbeefu) == 0u);

	n = pe32_stager(code, 0);
	len = pe32_code(img, sizeof img, code, n);
	CK(e2e_scan(img, len, &r));
	vname(want, sizeof want, "PE-x86/Dropper:exec.rwx-region!Diagnose");
	CK(!strcmp(r.o[0].verdict, want));
	CK(lists(&r.o[0].vf, "rwx_exec_pe"));

	len = cf_kmod(img, sizeof img, 0, 0);
	CK(e2e_scan(img, len, &r));
	vname(want, sizeof want, "ELF-x64/Rootkit:kernel.giveroot!Diagnose");
	CK(!strcmp(r.o[0].verdict, want));
	CK(r.o[0].vf.n_diag == 1u && lists(&r.o[0].vf, "kmod_give_root"));

	/* the same two calls the wrong way round are not the diagnose: no disease, no verdict */
	len = cf_kmod(img, sizeof img, 0, 1);
	CK(e2e_scan(img, len, &r));
	CK(!r.o[0].has_verdict);
}

/* A verdict of more diseases than the trace holds is cut, and says by how much. */
static void the_cut_is_said(void)
{
	struct kof_verdict_disease dis[24];
	uint32_t diag[24], i;
	struct kof_verdict_in in;
	struct kof_finding f;

	for (i = 0; i < 24u; i++) {
		dis[i].id = 100u + i;
		dis[i].type = (uint8_t)KOF_MALTYPE_BOTNET;
		dis[i].name = "a/b";
		diag[i] = 500u + i;
	}
	memset(&in, 0, sizeof in);
	in.dis = dis;
	in.n_dis = 20;
	in.diag = diag;
	in.n_diag = 18;
	kof_verdict_make(&in, &f);
	CK(f.n_disease == KOF_VERDICT_TRACE && f.disease_total == 20u);
	CK(f.n_diag == KOF_VERDICT_TRACE && f.diag_total == 18u);
	CK(f.disease[0] == 100u && f.diag[KOF_VERDICT_TRACE - 1u] == 500u + KOF_VERDICT_TRACE - 1u);
	CK(f.engine == (uint8_t)KOF_ENGINE_DIAGNOSE);

	/* a disease the database does not name is not left out of the name's inputs */
	dis[0].name = NULL;
	dis[0].type = 0xffu;
	in.n_dis = 1;
	in.n_diag = 0;
	kof_verdict_make(&in, &f);
	CK(strstr(f.name, "Malware:unnamed") != NULL);
	CK(f.engine == (uint8_t)KOF_ENGINE_NONE && f.n_disease == 1u);
}

int main(int argc, char **argv)
{
	if (!e2e_open(argc > 1 ? argv[1] : NULL)) {
		printf("verdict diseases: cannot open the test database\n");
		return 2;
	}
	the_way_back();
	the_cut_is_said();
	printf("verdict diseases: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
