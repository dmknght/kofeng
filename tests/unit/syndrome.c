/*
 * syndrome.c - what a set of diseases makes, from verified exemplars.
 *
 * The cases are the ones the measurement found, on a table small enough to
 * read: a syndrome that discriminates, one that two types share, a behaviour
 * nobody verified, tags that never appeared on one sample together, and a
 * C&C that was down.
 */
#include <stdio.h>
#include <string.h>
#include "../../libkofeng/databases/pack/kofsyndrome.h"
#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "../../libkofeng/analyzers/diseases/kofdisease.h"

static int failures;

static void check(int cond, const char *what)
{
	if (!cond) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

#define T(x) (1u << (x))

static const char *const bot_full[]  = { "cnc/recv", "flood/raw", "cnc/nonblock" };
static const char *const bot_flood[] = { "flood/raw", "cnc/recv" };
static const char *const trojan[]    = { "cnc/recv", "exec/syscall" };
static const char *const miner[]     = { "cnc/recv", "cnc/nonblock" };
static const char *const root[]      = { "kernel/selfhide", "kernel/giveroot" };
static const char *const exploit[]   = { "exploit/lpe" };
static const char *const both[]      = { "exploit/lpe", "cnc/recv", "flood/raw" };

/* The cases are written in words; the algorithm sees ids. */
struct text_in {
	uint32_t           type_mask;
	uint32_t           n_dis;
	const char *const *dis;
};

static const struct text_in in[] = {
	{ T(KOF_MALTYPE_BOTNET),  3, bot_full },
	{ T(KOF_MALTYPE_BOTNET),  2, bot_flood },
	{ T(KOF_MALTYPE_TROJAN),  2, trojan },
	{ T(KOF_MALTYPE_MINER),   2, miner },
	{ T(KOF_MALTYPE_ROOTKIT), 2, root },
	{ T(KOF_MALTYPE_EXPLOIT), 1, exploit },
	{ T(KOF_MALTYPE_BOTNET) | T(KOF_MALTYPE_EXPLOIT), 3, both },
	{ T(KOF_MALTYPE_BOTNET),  0, NULL },    /* shows nothing: dropped */
};

static int infer_s(const struct kof_synd_set *s, const char *const *q, uint32_t n,
		   struct kof_synd_result *r)
{
	uint32_t ids[16], i;

	for (i = 0; i < n && i < 16u; i++)
		ids[i] = kof_disease_id(q[i]);
	return kof_synd_infer(s, ids, n, r);
}

static struct kof_synd_set *build_s(const struct text_in *t, uint32_t n)
{
	static uint32_t ids[16][8];
	struct kof_synd_in o[16];
	uint32_t i, j;

	for (i = 0; i < n && i < 16u; i++) {
		for (j = 0; j < t[i].n_dis; j++)
			ids[i][j] = kof_disease_id(t[i].dis[j]);
		o[i].type_mask = t[i].type_mask;
		o[i].n_dis = t[i].n_dis;
		o[i].dis = ids[i];
	}
	return kof_synd_build(o, n);
}

static void name_of(struct kof_synd_set *s, const char *const *q, uint32_t n,
		    char *out, size_t cap)
{
	struct kof_synd_result r;

	infer_s(s, q, n, &r);
	kof_synd_name(&r, out, cap);
}

int main(void)
{
	struct kof_synd_set *s = build_s(in, sizeof in / sizeof *in);
	struct kof_synd_result r;
	char nm[96];

	check(s && kof_synd_count(s) == 7u, "the exemplar with no disease is dropped");

	/* a syndrome only Botnet shows proves Botnet */
	{
		const char *q[] = { "flood/raw", "cnc/recv" };
		const char *q1[] = { "flood/raw" };

		/* Botnet shows exactly this, and so does the botnet-with-exploit
		 * sample, whose types include Botnet: proven; Exploit is only
		 * possible, because that sample is a superset of the query. */
		infer_s(s, q, 2, &r);
		check(r.guaranteed == T(KOF_MALTYPE_BOTNET), "flood + recv proves Botnet");
		check(r.possible & T(KOF_MALTYPE_EXPLOIT) && !(r.guaranteed & T(KOF_MALTYPE_EXPLOIT)),
		      "and leaves Exploit possible, not proven");
		/* one tag shows less than any syndrome: nothing proven, Botnet possible */
		infer_s(s, q1, 1, &r);
		check(!r.guaranteed && (r.possible & T(KOF_MALTYPE_BOTNET)),
		      "one tag alone proves nothing");
	}
	/* recv + nonblock is what a Miner and a Botnet both show: nothing proven */
	{
		const char *q[] = { "cnc/recv", "cnc/nonblock" };

		name_of(s, q, 2, nm, sizeof nm);
		check(!strcmp(nm, "Ambiguous(Botnet,Miner)"), "shared tags are not a name");
	}
	/* the same syndrome shown by a Trojan is NOT enough to call it a Botnet */
	{
		const char *q[] = { "cnc/recv", "exec/syscall" };

		infer_s(s, q, 2, &r);
		check(!(r.guaranteed & T(KOF_MALTYPE_BOTNET)), "a Trojan's syndrome does not prove Botnet");
		check(r.guaranteed & T(KOF_MALTYPE_TROJAN), "it proves what only it shows");
	}
	/* rootkit */
	{
		const char *q[] = { "kernel/selfhide", "kernel/giveroot" };

		name_of(s, q, 2, nm, sizeof nm);
		check(!strcmp(nm, "Rootkit:Agent"), "selfhide + giveroot is a Rootkit");
	}
	/* two types shown together, one sample carrying both */
	{
		const char *q[] = { "exploit/lpe", "cnc/recv", "flood/raw" };

		infer_s(s, q, 3, &r);
		check((r.guaranteed & T(KOF_MALTYPE_BOTNET)) && (r.guaranteed & T(KOF_MALTYPE_EXPLOIT)),
		      "botnet carrying an exploit is both");
		kof_synd_name(&r, nm, sizeof nm);
		check(!strcmp(nm, "Botnet+Exploit:Agent"), "the name carries both");
	}
	/* a behaviour nobody verified */
	{
		const char *q[] = { "cnc/recv", "never/seen" };

		infer_s(s, q, 2, &r);
		check(r.n_unknown == 1u && !r.n_compat, "an unverified behaviour matches nothing");
		kof_synd_name(&r, nm, sizeof nm);
		check(!strcmp(nm, "Malware:Unresolved"), "and the name says so");
	}
	/* tags that never appeared on one sample together are not joined */
	{
		const char *q[] = { "exec/syscall", "flood/raw" };

		infer_s(s, q, 2, &r);
		check(!r.n_compat, "tags from different samples are not one syndrome");
	}
	/* duplicates are one; nothing asked is no answer */
	{
		const char *q[] = { "kernel/selfhide", "kernel/selfhide" };

		infer_s(s, q, 2, &r);
		check(r.n_query == 1u, "a duplicate is counted once");
		check(!infer_s(s, NULL, 0, &r) && !r.n_query, "no disease, no answer");
	}
	/* a behaviour nobody verified, asked about twice, is one behaviour */
	{
		const char *q[] = { "never/seen", "never/seen", "cnc/recv" };

		infer_s(s, q, 3, &r);
		check(r.n_query == 2u && r.n_unknown == 1u,
		      "an unverified behaviour asked twice is counted once");
	}
	/* an empty set answers unresolved, and is not an error */
	{
		struct kof_synd_set *e = build_s(NULL, 0);
		const char *q[] = { "x" };

		infer_s(e, q, 1, &r);
		kof_synd_name(&r, nm, sizeof nm);
		check(e && !strcmp(nm, "Malware:Unresolved"), "no exemplars: unresolved");
		kof_synd_free(e);
	}
	/* a short buffer is cut, terminated, and the true length returned */
	{
		const char *q[] = { "kernel/selfhide", "kernel/giveroot" };
		char tiny[5];
		size_t l;

		infer_s(s, q, 2, &r);
		l = kof_synd_name(&r, tiny, sizeof tiny);
		check(l == strlen("Rootkit:Agent") && tiny[4] == 0 && !strncmp(tiny, "Root", 4),
		      "a short buffer is cut and terminated");
	}
	kof_synd_free(s);
	if (failures) {
		printf("syndrome: %d failure(s)\n", failures);
		return 1;
	}
	printf("syndrome: discriminating syndromes prove a type, shared ones do not, "
	       "a botnet with an exploit is both, an unverified behaviour matches "
	       "nothing, tags of different samples are not joined - ok\n");
	return 0;
}
