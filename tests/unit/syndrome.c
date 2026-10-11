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
#include "../../libkofeng/detectors/pathogen/syndromes/kofsyndrome.h"
#include "../../libkofeng/kofcore/kofmod/kofsig.h"

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

static const struct kof_synd_in in[] = {
	{ T(KOF_MALTYPE_BOTNET),  3, bot_full },
	{ T(KOF_MALTYPE_BOTNET),  2, bot_flood },
	{ T(KOF_MALTYPE_TROJAN),  2, trojan },
	{ T(KOF_MALTYPE_MINER),   2, miner },
	{ T(KOF_MALTYPE_ROOTKIT), 2, root },
	{ T(KOF_MALTYPE_EXPLOIT), 1, exploit },
	{ T(KOF_MALTYPE_BOTNET) | T(KOF_MALTYPE_EXPLOIT), 3, both },
	{ T(KOF_MALTYPE_BOTNET),  0, NULL },    /* shows nothing: dropped */
};

static void name_of(struct kof_synd_set *s, const char *const *q, uint32_t n,
		    char *out, size_t cap)
{
	struct kof_synd_result r;

	kof_synd_infer(s, q, n, &r);
	kof_synd_name(&r, out, cap);
}

int main(void)
{
	struct kof_synd_set *s = kof_synd_build(in, sizeof in / sizeof *in);
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
		kof_synd_infer(s, q, 2, &r);
		check(r.guaranteed == T(KOF_MALTYPE_BOTNET), "flood + recv proves Botnet");
		check(r.possible & T(KOF_MALTYPE_EXPLOIT) && !(r.guaranteed & T(KOF_MALTYPE_EXPLOIT)),
		      "and leaves Exploit possible, not proven");
		/* one tag shows less than any syndrome: nothing proven, Botnet possible */
		kof_synd_infer(s, q1, 1, &r);
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

		kof_synd_infer(s, q, 2, &r);
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

		kof_synd_infer(s, q, 3, &r);
		check((r.guaranteed & T(KOF_MALTYPE_BOTNET)) && (r.guaranteed & T(KOF_MALTYPE_EXPLOIT)),
		      "botnet carrying an exploit is both");
		kof_synd_name(&r, nm, sizeof nm);
		check(!strcmp(nm, "Botnet+Exploit:Agent"), "the name carries both");
	}
	/* a behaviour nobody verified */
	{
		const char *q[] = { "cnc/recv", "never/seen" };

		kof_synd_infer(s, q, 2, &r);
		check(r.n_unknown == 1u && !r.n_compat, "an unverified behaviour matches nothing");
		kof_synd_name(&r, nm, sizeof nm);
		check(!strcmp(nm, "Malware:Unresolved"), "and the name says so");
	}
	/* tags that never appeared on one sample together are not joined */
	{
		const char *q[] = { "exec/syscall", "flood/raw" };

		kof_synd_infer(s, q, 2, &r);
		check(!r.n_compat, "tags from different samples are not one syndrome");
	}
	/* duplicates are one; nothing asked is no answer */
	{
		const char *q[] = { "kernel/selfhide", "kernel/selfhide" };

		kof_synd_infer(s, q, 2, &r);
		check(r.n_query == 1u, "a duplicate is counted once");
		check(!kof_synd_infer(s, NULL, 0, &r) && !r.n_query, "no disease, no answer");
	}
	/* an empty set answers unresolved, and is not an error */
	{
		struct kof_synd_set *e = kof_synd_build(NULL, 0);
		const char *q[] = { "x" };

		kof_synd_infer(e, q, 1, &r);
		kof_synd_name(&r, nm, sizeof nm);
		check(e && !strcmp(nm, "Malware:Unresolved"), "no exemplars: unresolved");
		kof_synd_free(e);
	}
	/* a short buffer is cut, terminated, and the true length returned */
	{
		const char *q[] = { "kernel/selfhide", "kernel/giveroot" };
		char tiny[5];
		size_t l;

		kof_synd_infer(s, q, 2, &r);
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
