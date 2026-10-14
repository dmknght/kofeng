/*
 * scan_share - two scanners on one engine, under the default memory cap.
 *
 *   TWO MADE, TWO SCAN   kscan_new twice on an engine at the default 512 MiB: both exist, and the same
 *                        object gives the same answer on either (no verdict depends on which scanner).
 *   MANY MADE FIRST      six scanners made before any scans: every one scans at once on its own thread
 *                        and none is refused - the fair share is the same for all six (this is the shape
 *                        normalizer_engine.c's thread test has since the flake was fixed).
 *   MADE WHILE ANOTHER   A scanner takes (cap - database) / scanners alive for the length of an object, but not more
 *   SCANS                than its ledger can use, which is the resident allowance (kof_scan_root_share). It used to take the
 *                        whole fair share - 490 MB of 512 for the first of a process, with an allowance of 128 - so the scanners made while it scanned took what was left, 1/2 + 1/3 + 1/4 + 1/5
 *                        of the room for a chain of four, and the fourth was refused or starved (it was the one-in-six flake
 *                        of normalizer_engine under load; this case was the known miss ROOT_SHARE_TAKES_ALL_ROOM). Now the
 *                        chain is made and every scanner scans its object whole. A scanner whose host asks for more than the fair share still gets the fair share.
 *   WHY A SCANNER IS NOT   kscan_new_ex answers the reason with the NULL: no engine, the budget cannot afford the fixed cost
 *   MADE                   (the cap is read, not guessed from the NULL), and kscan_new_why_str has a spelling for each.
 */

#define _GNU_SOURCE

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofeng.h"
#include "known_miss.h"

static unsigned checks, fails;

#define CK(cond, ...) do { \
	checks++; \
	if (!(cond)) { \
		printf("  FAIL %s:%d: ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		fails++; \
	} \
} while (0)

static kof_engine *eng;
static uint8_t obj[1u << 16];

struct seen {
	unsigned objs, broken, finds;
};

static int on_object(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct seen *s = user;

	(void)name; (void)bytes; (void)len;
	s->objs++;
	s->broken |= res->broken;
	s->finds += res->n;
	return 0;
}

static void scan_with(kof_scanner *sc, struct seen *s)
{
	struct kof_scan_option opt;

	memset(&opt, 0, sizeof opt);
	opt.all_matches = 1;
	opt.max_produced_bytes = 64u << 20;
	opt.max_resident_bytes = 256u << 20;
	opt.max_object_bytes = 64u << 20;
	(void)kscan_bytes(sc, obj, sizeof obj, "share", &opt, on_object, s);
}

/* ---- two made, two scan -------------------------------------------------------------- */

static void two_scanners(kof_engine *e)
{
	kof_scanner *a = kscan_new(e), *b = kscan_new(e);
	struct seen sa, sb;

	CK(keng_memory_cap(e) == (512ull << 20), "the default cap is 512 MiB (%llu)", (unsigned long long)keng_memory_cap(e));
	CK(a != NULL && b != NULL, "two kscan_new on one engine at the default cap: %p %p", (void *)a, (void *)b);
	if (a && b) {
		memset(&sa, 0, sizeof sa);
		memset(&sb, 0, sizeof sb);
		scan_with(a, &sa);
		scan_with(b, &sb);
		CK(sa.objs == sb.objs && sa.broken == sb.broken && sa.finds == sb.finds && !sa.broken,
		   "the same object on two scanners: %u/%u objects, broken %u/%u", sa.objs, sb.objs, sa.broken, sb.broken);
		/* and once more, in the other order, after both have scanned */
		memset(&sa, 0, sizeof sa);
		memset(&sb, 0, sizeof sb);
		scan_with(b, &sb);
		scan_with(a, &sa);
		CK(sa.objs == sb.objs && sa.broken == sb.broken && !sa.broken, "and again, the other way round");
	}
	/* what a refused scanner would owe: the engine's own account is back to the database when both are freed */
	if (a)
		kscan_free(a);
	if (b)
		kscan_free(b);
	CK(keng_memory_peak(e) <= keng_memory_cap(e), "the engine's peak %llu is within its cap",
	   (unsigned long long)keng_memory_peak(e));
}

/* ---- many made first, all scan at once ------------------------------------------------------- */

#define NT 6u

struct tj {
	kof_scanner *sc;
	pthread_barrier_t *bar;
	unsigned bad, runs;
};

static void *thread_main(void *p)
{
	struct tj *t = p;
	unsigned i;

	for (i = 0; i < 30u; i++) {
		struct seen s;

		memset(&s, 0, sizeof s);
		pthread_barrier_wait(t->bar);          /* every scan of a round starts together */
		scan_with(t->sc, &s);
		t->runs++;
		if (s.broken || !s.objs)
			t->bad++;
	}
	return NULL;
}

static void many_made_first(void)
{
	struct tj t[NT];
	pthread_t id[NT];
	pthread_barrier_t bar;
	unsigned i, made = 0, bad = 0, runs = 0;

	pthread_barrier_init(&bar, NULL, NT);
	for (i = 0; i < NT; i++) {
		memset(&t[i], 0, sizeof t[i]);
		t[i].sc = kscan_new(eng);
		t[i].bar = &bar;
		made += t[i].sc != NULL;
	}
	CK(made == NT, "%u of %u scanners made at the default cap", made, NT);
	if (made == NT) {
		for (i = 0; i < NT; i++)
			pthread_create(&id[i], NULL, thread_main, &t[i]);
		for (i = 0; i < NT; i++) {
			pthread_join(id[i], NULL);
			bad += t[i].bad;
			runs += t[i].runs;
		}
		CK(runs == NT * 30u && bad == 0, "scans refused or empty with %u scanners alive: %u of %u", NT, bad, runs);
	}
	for (i = 0; i < NT; i++)
		if (t[i].sc)
			kscan_free(t[i].sc);
	pthread_barrier_destroy(&bar);
}

/* ---- made while another scans (known miss) ----------------------------------------------------- */

/*
 * A chain: a scanner is made, scans, and inside its callback the next one is made and scans - four deep, beside
 * one idle scanner that exists from the start. Each is made at the moment it is needed, which is what a host that
 * grows its pool under load does. The first scan alone sees one or two holders and takes (cap - database) / that;
 * what is left is what the others find.
 */
#define CHAIN 4u

static struct { unsigned made, whole, depth, refused; int why; uint64_t resident; } chain;

static int chain_cb(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user);

static void chain_run(unsigned d)
{
	int why = KSCAN_NEW_OK;
	kof_scanner *sc = kscan_new_ex(eng, &why);
	struct kof_scan_option opt;
	struct seen s;

	if (!sc) {
		chain.refused++;
		chain.why = why;
		return;
	}
	chain.made++;
	memset(&s, 0, sizeof s);
	memset(&opt, 0, sizeof opt);
	opt.all_matches = 1;
	opt.max_produced_bytes = 64u << 20;
	opt.max_resident_bytes = chain.resident;
	opt.max_object_bytes = 64u << 20;
	chain.depth = d;
	(void)kscan_bytes(sc, obj, sizeof obj, "chain", &opt, chain_cb, &s);
	chain.whole += !s.broken && s.objs >= 1u;
	kscan_free(sc);
}

static int chain_cb(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct seen *s = user;
	unsigned d = chain.depth;

	(void)name; (void)bytes; (void)len;
	s->objs++;
	s->broken |= res->broken;
	if (s->objs == 1u && d + 1u < CHAIN) {
		chain_run(d + 1u);
		chain.depth = d;
	}
	return 0;
}

static void chain_once(uint64_t resident, const char *what, unsigned want_made)
{
	kof_scanner *idle = kscan_new(eng);

	CK(idle != NULL, "the idle scanner");
	memset(&chain, 0, sizeof chain);
	chain.resident = resident;
	chain_run(0);
	printf("  chain of %u scanners (%s), each made inside the previous one's scan: %u made, %u scanned whole, %u refused\n",
	       CHAIN, what, chain.made, chain.whole, chain.refused);
	/* a scanner that is made scans its object whole, and one that is not made says why */
	CK(chain.whole == chain.made && chain.made + chain.refused <= CHAIN,
	   "%s: every scanner made scans whole (%u made, %u whole)", what, chain.made, chain.whole);
	CK(chain.made >= want_made, "%s: %u made, at least %u wanted", what, chain.made, want_made);
	CK(!chain.refused || chain.why == KSCAN_NEW_BUDGET, "%s: the refusal is the budget's (%d)", what, chain.why);
	if (idle)
		kscan_free(idle);
}

static void made_while_scanning(void)
{
	/* the built-in allowance (128 MiB): all four are made and scan whole */
	chain_once(0, "default allowance", CHAIN);
	/* a host that names 256 MiB for each of five scanners asks for more than the cap: the first ones are made
	 * and whole, and the one the budget cannot afford is refused with its reason, not made and starved */
	chain_once(256u << 20, "256 MiB each", 3u);
}

/* ---- why a scanner is not made ------------------------------------------------------------- */

static void why_not_made(void)
{
	int why = 99;
	kof_scanner *v[64];
	unsigned n = 0, i;
	uint64_t small = keng_memory_db(eng) + (40ull << 20);

	CK(kscan_new_ex(NULL, &why) == NULL && why == KSCAN_NEW_NO_ENGINE, "no engine: %d", why);
	CK(kscan_new_ex(NULL, NULL) == NULL && kscan_new(NULL) == NULL, "no engine, and no place to say it");
	v[0] = kscan_new_ex(eng, &why);
	CK(v[0] != NULL && why == KSCAN_NEW_OK, "made: %d", why);
	kscan_free(v[0]);
	/* a cap that holds the database and a few scanners: scanners are made until the budget refuses one */
	CK(keng_set_memory_cap(eng, small) != 0, "set a small cap (%llu)", (unsigned long long)small);
	for (i = 0; i < 64u; i++) {
		why = 99;
		v[n] = kscan_new_ex(eng, &why);
		if (!v[n])
			break;
		n++;
	}
	CK(n >= 1u && i < 64u && why == KSCAN_NEW_BUDGET, "refused by the budget after %u: reason %d (%s)", n, why,
	   kscan_new_why_str(why));
	CK(kscan_new(eng) == NULL, "the short form answers the same NULL");
	while (n)
		kscan_free(v[--n]);
	CK(keng_set_memory_cap(eng, 0) != 0, "default cap again");
	CK(strcmp(kscan_new_why_str(KSCAN_NEW_BUDGET), kscan_new_why_str(KSCAN_NEW_NOMEM)) != 0 &&
	   strcmp(kscan_new_why_str(-5), kscan_new_why_str(KSCAN_NEW_OK)) != 0, "a spelling for each reason, and for a value that is none");
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/test/databases-sigs";
	unsigned i;

	eng = keng_open(db);
	if (!eng) {
		printf("scan_share: no database at %s - nothing tested\n", db);
		return 0;
	}
	for (i = 0; i < sizeof obj; i++)
		obj[i] = (uint8_t)(i * 31u);
	memcpy(obj, "\x7f" "ELF", 4);
	two_scanners(eng);
	{
		/* and on the product's own database, which is the one a host really loads */
		kof_engine *e2 = keng_open("build/release/databases");

		if (e2) {
			two_scanners(e2);
			keng_close(e2);
		}
	}
	many_made_first();
	made_while_scanning();
	why_not_made();
	keng_close(eng);
	printf("scan_share: %u checks, %u failed, %u known miss\n", checks, fails, km_known());
	return fails != 0 || km_failed();
}
