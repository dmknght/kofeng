/*
 * fridge - the verdict cache remembers, and never remembers wrong.
 *
 * A cache is the one component where being fast is worthless and being right is
 * everything: a wrong hit is a false clean on a file somebody scanned, and it
 * is invisible because the scan that would have caught it never ran. So the
 * properties here are about correctness first and capacity second.
 *
 *   1. A stored verdict comes back. A key never stored does not.
 *   2. Identities are compared IN FULL. Two keys that differ in one byte -
 *      including the last one, and including their length - are two keys, even
 *      when they are forced into the same slot.
 *   3. The worst finding is what is kept, by the engine's own ranking, so a
 *      cached answer does not depend on which module happened to be first in
 *      the database.
 *   4. Over-long identities are refused rather than truncated. Truncating is
 *      how two different things become one.
 *   5. Eviction stays bounded and never invents an entry: after storing far
 *      more than the capacity, everything that answers must answer with what
 *      was stored under that exact key.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <pthread.h>

/*
 * The engine header, which koffridge.h deliberately no longer drags in: it
 * forward-declares struct kof_result so the Windows collector need not compile
 * the whole engine ABI - see the note at the top of that header. A test that
 * BUILDS a verdict needs the real type and the KOF_LEVEL_* values, so it asks
 * for them itself.
 */
#include "../../libkofeng/kofeng.h"
#include "../../libkoforbit/koffridge/koffridge.h"

static int fails;

static void ck(int cond, const char *what)
{
	if (!cond) {
		printf("  FAIL: %s\n", what);
		fails++;
	}
}

static void result_with(struct kof_result *r, uint32_t n,
			const uint32_t *levels, const char *const *names)
{
	uint32_t i;

	memset(r, 0, sizeof *r);
	r->n = n;
	for (i = 0; i < n; i++) {
		r->v[i].level = levels[i];
		snprintf(r->v[i].name, sizeof r->v[i].name, "%s", names[i]);
	}
}

/*
 * SEVERAL THREADS ON ONE FRIDGE, and the assertion is not "it did not crash".
 *
 * A lock that is missing shows up as a crash only sometimes; what it shows up
 * as reliably is a WRONG ANSWER - an entry half written by one thread and read
 * by another, so a key comes back with somebody else's verdict. That is
 * invisible in a scanner, because a verdict that is merely wrong looks exactly
 * like a verdict.
 *
 * So every thread uses keys only IT writes, with a verdict name derived from
 * the key. Any hit must carry the name that key was stored with. A torn entry
 * fails that, and so does a probe that walked into another shard.
 *
 * The keys are sized so the table cannot hold them all: eviction runs
 * throughout, which is the path that WRITES to slots other lookups are reading
 * and is therefore the one worth racing.
 */
#define HAM_THREADS 8
#define HAM_KEYS    2000

struct hammer {
	struct koffridge *f;
	uint32_t          id;      /* which thread */
	uint64_t          wrong;   /* a hit that carried the wrong verdict */
	uint64_t          hits;
};

static void ham_name(char *out, size_t cap, uint32_t who, uint32_t k)
{
	snprintf(out, cap, "PE-x86/Test:T%uK%u", who, k);
}

static void *ham_run(void *arg)
{
	struct hammer *h = arg;
	struct kof_result res;
	struct koffridge_verdict v;
	uint32_t pass, k;

	for (pass = 0; pass < 4; pass++) {
		for (k = 0; k < HAM_KEYS; k++) {
			uint64_t key = ((uint64_t)h->id << 32) | k;
			char want[64];

			ham_name(want, sizeof want, h->id, k);
			memset(&res, 0, sizeof res);
			res.n = 1;
			res.v[0].level = KOF_LEVEL_INFECT;
			snprintf(res.v[0].name, sizeof res.v[0].name, "%s",
				 want);
			(void)koffridge_put(h->f, &key, sizeof key, &res);

			if (koffridge_get(h->f, &key, sizeof key, &v)) {
				h->hits++;
				if (strcmp(v.name, want) != 0)
					h->wrong++;
			}
		}
	}
	return NULL;
}

static void concurrent(void)
{
	pthread_t     th[HAM_THREADS];
	struct hammer hm[HAM_THREADS];
	struct koffridge *f = koffridge_open(1024, 0x2026091301ull);
	struct koffridge_stat st;
	uint64_t wrong = 0, hits = 0;
	int i, made = 0;

	ck(f != NULL, "open for the concurrent pass");
	if (!f)
		return;

	for (i = 0; i < HAM_THREADS; i++) {
		memset(&hm[i], 0, sizeof hm[i]);
		hm[i].f = f;
		hm[i].id = (uint32_t)i;
		if (pthread_create(&th[i], NULL, ham_run, &hm[i]) == 0)
			made++;
		else
			break;
	}
	for (i = 0; i < made; i++)
		pthread_join(th[i], NULL);

	ck(made == HAM_THREADS, "every thread started");
	for (i = 0; i < made; i++) {
		wrong += hm[i].wrong;
		hits  += hm[i].hits;
	}
	ck(wrong == 0, "no key ever answered with another key's verdict");
	ck(hits > 0, "the concurrent pass hit at least once");

	/*
	 * The totals have to add up to what was actually done. Eight threads
	 * times four passes times the key count is the number of puts, and a
	 * counter updated without its lock loses some of them.
	 */
	koffridge_stats(f, &st);
	ck(st.stores + st.refused ==
	   (uint64_t)made * 4ull * HAM_KEYS,
	   "every put is counted exactly once");
	ck(st.hits + st.misses == (uint64_t)made * 4ull * HAM_KEYS,
	   "every get is counted exactly once");
	ck(st.used <= st.capacity, "never more entries than slots");

	printf("  concurrent: %d thread(s), %llu hit(s), %llu wrong, "
	       "%llu stored, %llu evicted\n", made,
	       (unsigned long long)hits, (unsigned long long)wrong,
	       (unsigned long long)st.stores,
	       (unsigned long long)st.evictions);
	koffridge_close(f);
}

/* ===================== THE SAME FACT, SEEN AGAIN =====================
 *
 * The dedup table lives in koffridge, so its cases live in koffridge s test.
 * They were a separate file for as long as it was a separate module.
 */
static void sfail(const char *what)
{
	printf("  FAIL %s\n", what);
	fails++;
}

#define WINDOW 1000ull

/* ------------------------------------------------------------------- basics */

static void first_then_repeat(void)
{
	struct koffridge_seen *s = koffridge_seen_open(256u, WINDOW);
	struct koffridge_seen_stat st;

	if (!s) {
		sfail("no table");
		return;
	}

	if (koffridge_seen_mark(s, "alpha", 5u, 100ull) != 0)
		sfail("the first sighting was not fresh");
	if (koffridge_seen_mark(s, "alpha", 5u, 101ull) != 1)
		sfail("the second sighting was not the first repeat");
	if (koffridge_seen_mark(s, "alpha", 5u, 102ull) != 2)
		sfail("the third sighting did not count");

	/* A different identity is not the same identity. */
	if (koffridge_seen_mark(s, "beta", 4u, 103ull) != 0)
		sfail("a different identity was called a repeat");

	koffridge_seen_stats(s, &st);
	if (st.asked != 4u || st.fresh != 2u || st.repeat != 2u)
		printf("  FAIL the tally says asked=%llu fresh=%llu "
		       "repeat=%llu\n", (unsigned long long)st.asked,
		       (unsigned long long)st.fresh,
		       (unsigned long long)st.repeat);
	fails += (st.asked != 4u || st.fresh != 2u || st.repeat != 2u);

	koffridge_seen_close(s);
}

/*
 * A PREFIX IS NOT THE SAME IDENTITY, which is the bug a length-less hash has.
 * "Run" and "Run\Updater" are a real pair here: one is a key and the other is a
 * value under it, and collapsing them would report the value write and hide the
 * key, or the reverse.
 */
static void length_matters(void)
{
	struct koffridge_seen *s = koffridge_seen_open(256u, WINDOW);

	if (!s) {
		sfail("no table");
		return;
	}
	if (koffridge_seen_mark(s, "Run", 3u, 1ull) != 0)
		sfail("first");
	if (koffridge_seen_mark(s, "Run\\Updater", 11u, 2ull) != 0)
		sfail("a longer identity with the same prefix was suppressed");
	koffridge_seen_close(s);
}

/* ------------------------------------------------------------- the window */

/*
 * PAST THE WINDOW IT IS FRESH AGAIN, and this is the case that keeps a watchdog
 * visible. Something re-establishing persistence every few seconds must not
 * become one line for the whole run - see kofseen.h.
 */
static void window_expires(void)
{
	struct koffridge_seen *s = koffridge_seen_open(256u, WINDOW);

	if (!s) {
		sfail("no table");
		return;
	}
	if (koffridge_seen_mark(s, "x", 1u, 1000ull) != 0)
		sfail("first");
	if (koffridge_seen_mark(s, "x", 1u, 1500ull) != 1)
		sfail("a repeat inside the window was not suppressed");
	/* 1000 past the LAST sighting, which is 1500. */
	if (koffridge_seen_mark(s, "x", 1u, 2501ull) != 0)
		sfail("a repeat past the window was still suppressed");
	/* And the count started over rather than carrying across. */
	if (koffridge_seen_mark(s, "x", 1u, 2502ull) != 1)
		sfail("the count did not restart with the new window");
	koffridge_seen_close(s);
}

/*
 * AN OUT-OF-ORDER STAMP MUST NOT EXPIRE ANYTHING.
 *
 * ETW buffers are per processor, so a record stamped earlier than one already
 * seen is normal traffic and not corruption. The interval is unsigned: computed
 * the wrong way round it wraps to something astronomically larger than any
 * window, and every late record would read as fresh - which would turn the
 * collapser off precisely on the busy machines that need it, because that is
 * when reordering happens.
 */
static void out_of_order(void)
{
	struct koffridge_seen *s = koffridge_seen_open(256u, WINDOW);

	if (!s) {
		sfail("no table");
		return;
	}
	if (koffridge_seen_mark(s, "y", 1u, 5000ull) != 0)
		sfail("first");
	if (koffridge_seen_mark(s, "y", 1u, 4000ull) != 1)
		sfail("a record stamped EARLIER was treated as past the window");
	if (koffridge_seen_mark(s, "y", 1u, 1ull) != 2)
		sfail("a much earlier stamp expired the entry");
	koffridge_seen_close(s);
}

/* ---------------------------------------------------------------- eviction */

/*
 * WHEN IT RUNS OUT OF ROOM IT MUST FAIL TOWARDS NOISE.
 *
 * Far more distinct identities than the table holds, then the oldest one again.
 * Whatever happened in between, the answer for a forgotten identity has to be
 * "fresh" - one duplicate reported. The unacceptable outcome is the reverse: a
 * NEW identity landing on an evicted slot and being told it is a repeat, which
 * would delete an event that never happened before.
 */
static void eviction_fails_safe(void)
{
	struct koffridge_seen *s = koffridge_seen_open(256u, WINDOW);
	struct koffridge_seen_stat st;
	char key[32];
	unsigned i;
	int wrong = 0;

	if (!s) {
		sfail("no table");
		return;
	}

	/*
	 * EVERY ONE OF THESE IS NEW, so every answer must be 0. A single
	 * non-zero is the fatal direction: it means an identity nobody had
	 * ever seen was suppressed.
	 */
	for (i = 0; i < 4000u; i++) {
		int n = snprintf(key, sizeof key, "id-%u", i);

		if (koffridge_seen_mark(s, key, (uint32_t)n, 1000ull + i) != 0)
			wrong++;
	}
	if (wrong)
		printf("  FAIL %d identity(s) that were new came back as "
		       "repeats\n", wrong);
	fails += wrong ? 1 : 0;

	koffridge_seen_stats(s, &st);
	if (st.used > st.cap)
		sfail("the table reports more entries than it holds");
	if (!st.evicted)
		sfail("4000 identities into a 256-entry table evicted nothing - "
		     "the table is not bounded");

	koffridge_seen_close(s);
}

/*
 * AND THE REDUCTION HAS TO ACTUALLY REDUCE. A table that evicted so eagerly
 * that nothing was ever recognised would pass every assertion above - each one
 * is about not suppressing - and be useless. This is the other side: a small
 * working set, repeated, must collapse.
 */
static void reduces(void)
{
	struct koffridge_seen *s = koffridge_seen_open(256u, WINDOW);
	struct koffridge_seen_stat st;
	char key[32];
	unsigned i, k;

	if (!s) {
		sfail("no table");
		return;
	}
	/* Eight distinct facts, restated a hundred times each - which is the
	 * shape the registry provider actually produces. */
	for (k = 0; k < 100u; k++) {
		for (i = 0; i < 8u; i++) {
			int n = snprintf(key, sizeof key, "fact-%u", i);

			koffridge_seen_mark(s, key, (uint32_t)n, 2000ull);
		}
	}
	koffridge_seen_stats(s, &st);
	if (st.fresh != 8u)
		printf("  FAIL 8 distinct facts produced %llu fresh\n",
		       (unsigned long long)st.fresh);
	fails += (st.fresh != 8u) ? 1 : 0;
	if (st.repeat != 792u)
		printf("  FAIL expected 792 suppressions, got %llu\n",
		       (unsigned long long)st.repeat);
	fails += (st.repeat != 792u) ? 1 : 0;

	koffridge_seen_close(s);
}

/*
 * A TABLE THAT IS NOT FULL MUST NOT FORGET ANYTHING.
 *
 * THIS IS THE TEST THAT WAS MISSING, and its absence is why a real defect
 * shipped past every case above: all of them assert CORRECTNESS - the right
 * answer for an identity that is present - and a table can give every one of
 * those right answers while quietly being useless.
 *
 * The defect was the index. Slots were chosen from the HIGH bits of an FNV
 * hash, and FNV mixes upward, so short inputs sharing a suffix - which every
 * registry path does, being a long common prefix and a short tail - landed in
 * the same probe runs. At a quarter full the table was evicting: 2000
 * identities into 8192 slots produced 56112 evictions and suppressed 71.5% of
 * a stream it should have suppressed 99% of.
 *
 * Nothing about that is visible from a correctness test. It is visible here,
 * because at a quarter load the only acceptable number of evictions is none.
 */
static void not_full_forgets_nothing(void)
{
	struct koffridge_seen *s = koffridge_seen_open(8192u, 1000000ull);
	struct koffridge_seen_stat st;
	char key[96];
	unsigned pass, i;

	if (!s) {
		sfail("no table");
		return;
	}

	/*
	 * Registry-shaped keys on purpose: a long shared prefix and a short
	 * distinguishing tail is the input that broke it, and a test using
	 * "id-1", "id-2" would not have.
	 */
	for (pass = 0; pass < 3u; pass++) {
		for (i = 0; i < 2000u; i++) {
			int n = snprintf(key, sizeof key,
				"REGISTRY/MACHINE/SOFTWARE/Microsoft/Windows/"
				"CurrentVersion/Uninstall/Product%u", i);

			koffridge_seen_mark(s, key, (uint32_t)n, 1000ull + pass);
		}
	}

	koffridge_seen_stats(s, &st);
	if (st.evicted)
		printf("  FAIL 2000 identities in 8192 slots evicted %llu - "
		       "the index is clustering\n",
		       (unsigned long long)st.evicted);
	fails += st.evicted ? 1 : 0;

	/* Two passes over 2000 known identities must be 4000 suppressions. */
	if (st.fresh != 2000u || st.repeat != 4000u)
		printf("  FAIL expected 2000 fresh and 4000 repeats, got "
		       "%llu and %llu\n", (unsigned long long)st.fresh,
		       (unsigned long long)st.repeat);
	fails += (st.fresh != 2000u || st.repeat != 4000u) ? 1 : 0;

	koffridge_seen_close(s);
}

/* ------------------------------------------------------------------ hostile */

/*
 * THE CALLS NOBODY MEANS TO MAKE. A collector under load is where a null or a
 * zero-length identity would come from - a record whose object failed to decode
 * - and a table that crashed there would take the sensor down.
 */
static void hostile(void)
{
	struct koffridge_seen *s = koffridge_seen_open(0u, 0ull);   /* both defaults */
	char big[4096];

	if (!s) {
		sfail("no table with default sizes");
		return;
	}
	if (koffridge_seen_mark(NULL, "a", 1u, 1ull) != 0)
		sfail("a null table did not answer fresh");
	if (koffridge_seen_mark(s, NULL, 4u, 1ull) != 0)
		sfail("a null identity did not answer fresh");
	if (koffridge_seen_mark(s, "a", 0u, 1ull) != 0)
		sfail("a zero-length identity did not answer fresh");

	/* An identity far longer than any path, twice. */
	memset(big, 'k', sizeof big);
	if (koffridge_seen_mark(s, big, (uint32_t)sizeof big, 1ull) != 0)
		sfail("a very long identity was not fresh");
	if (koffridge_seen_mark(s, big, (uint32_t)sizeof big, 2ull) != 1)
		sfail("a very long identity did not match itself");

	/* Stamp zero, and the largest stamp there is. */
	if (koffridge_seen_mark(s, "z", 1u, 0ull) != 0)
		sfail("a zero stamp was not fresh");
	if (koffridge_seen_mark(s, "z", 1u, ~0ull) != 0)
		sfail("a jump to the maximum stamp did not expire the entry");

	koffridge_seen_stats(s, NULL);       /* must not crash */
	koffridge_seen_clear(s);
	if (koffridge_seen_mark(s, "z", 1u, 5ull) != 0)
		sfail("clear did not forget");
	koffridge_seen_close(s);
	koffridge_seen_close(NULL);          /* must not crash */
}

int main(void)
{
	struct koffridge *f;
	struct koffridge_verdict v;
	struct koffridge_stat st;
	struct kof_result res;
	struct koffridge_fileid id;
	char line[160];
	uint32_t i;

	f = koffridge_open(64, 0x2026090901ull);
	ck(f != NULL, "open");
	if (!f)
		return 1;
	ck(koffridge_db_stamp(f) == 0x2026090901ull, "db stamp kept");

	/* 1. store and retrieve, clean */
	memset(&id, 0, sizeof id);
	id.volume = 3; id.index = 77; id.size = 4096; id.mtime = 111;
	ck(!koffridge_get(f, &id, sizeof id, &v), "miss before store");
	ck(koffridge_put(f, &id, sizeof id, NULL) == 1, "store clean");
	ck(koffridge_get(f, &id, sizeof id, &v) == 1, "hit after store");
	ck(v.findings == 0 && v.name[0] == '\0', "clean verdict is clean");

	/* 2a. one byte different is a different key */
	id.mtime = 112;
	ck(!koffridge_get(f, &id, sizeof id, &v), "mtime change misses");
	id.mtime = 111;
	id.index = 78;
	ck(!koffridge_get(f, &id, sizeof id, &v), "index change misses");

	/* 2b. same bytes, different length */
	{
		static const unsigned char k[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

		ck(koffridge_put(f, k, 8, NULL) == 1, "store 8-byte key");
		ck(koffridge_get(f, k, 8, &v) == 1, "hit 8-byte key");
		ck(!koffridge_get(f, k, 7, &v), "same prefix, shorter, misses");
	}

	/* 3. the worst finding is the one kept */
	{
		static const uint32_t lv[3] = { KOF_LEVEL_HEUR,
						KOF_LEVEL_INFECT,
						KOF_LEVEL_SUSPECT };
		static const char *const nm[3] = { "PE-x86/Heur:Blob#a?Shell",
						   "PE-x86/Trojan:Meterp#la8hj",
						   "PE-x86/Adware:Foo#b" };
		unsigned char k = 9;

		result_with(&res, 3, lv, nm);
		ck(koffridge_put(f, &k, 1, &res) == 1, "store 3 findings");
		ck(koffridge_get(f, &k, 1, &v) == 1, "hit 3 findings");
		ck(v.findings == 3, "count kept");
		ck(v.level == KOF_LEVEL_INFECT, "worst level kept");
		ck(strcmp(v.name, nm[1]) == 0, "worst name kept");
	}

	/* broken is carried, not flattened to clean */
	{
		unsigned char k = 10;

		memset(&res, 0, sizeof res);
		res.broken = 7;
		ck(koffridge_put(f, &k, 1, &res) == 1, "store broken");
		ck(koffridge_get(f, &k, 1, &v) == 1, "hit broken");
		ck(v.findings == 0 && v.broken == 7, "broken carried");
	}

	/*
	 * WHEN A HIT IS A REASON TO SKIP, which is the question every caller
	 * actually has and the one that was got wrong.
	 *
	 * A `get` whose result nobody reads compiles, runs, and silences the
	 * detection it just made - measured as 613 infected files in one run
	 * and 1 in the next, with the cache in between. koffridge_skip makes
	 * the check the return value so there is nothing to forget; these are
	 * the three answers it has to give.
	 */
	{
		unsigned char kc = 20, ki = 21, kb = 22;

		ck(koffridge_put(f, &kc, 1, NULL) == 1, "store clean");
		memset(&res, 0, sizeof res);
		res.n = 1;
		res.v[0].level = KOF_LEVEL_INFECT;
		snprintf(res.v[0].name, sizeof res.v[0].name, "Test:Thing");
		ck(koffridge_put(f, &ki, 1, &res) == 1, "store infected");
		memset(&res, 0, sizeof res);
		res.broken = 3;
		ck(koffridge_put(f, &kb, 1, &res) == 1, "store broken");

		ck(koffridge_skip(f, &kc, 1) == 1, "a clean hit skips");
		/* THE ONE THAT MATTERS. */
		ck(koffridge_skip(f, &ki, 1) == 0,
		   "an INFECTED hit must NOT skip - this is the bug");
		/* A scan that stopped looking did not find nothing. */
		ck(koffridge_skip(f, &kb, 1) == 0, "a broken hit must not skip");
		/* And a miss is not a hit. */
		{
			unsigned char miss = 99;

			ck(koffridge_skip(f, &miss, 1) == 0, "a miss scans");
		}
		ck(koffridge_skip(NULL, &kc, 1) == 0, "no table scans");
	}

	/* 4. too long is refused */
	{
		unsigned char big[KOFFRIDGE_ID_MAX + 1];

		memset(big, 0xab, sizeof big);
		ck(koffridge_put(f, big, sizeof big, NULL) == 0,
		   "over-long identity refused");
		ck(!koffridge_get(f, big, sizeof big, &v),
		   "over-long identity never hits");
	}

	koffridge_clear(f);
	koffridge_stats(f, &st);
	ck(st.used == 0, "clear empties");

	/* 5. far past capacity: every answer must be the one stored */
	{
		uint32_t hits = 0, wrong = 0;

		for (i = 0; i < 4000; i++) {
			uint32_t key = i;

			memset(&res, 0, sizeof res);
			res.n = 1;
			res.v[0].level = KOF_LEVEL_INFECT;
			snprintf(res.v[0].name, sizeof res.v[0].name,
				 "PE-x86/Test:Id#%u", i);
			(void)koffridge_put(f, &key, sizeof key, &res);
		}
		for (i = 0; i < 4000; i++) {
			uint32_t key = i;
			char want[64];

			if (!koffridge_get(f, &key, sizeof key, &v))
				continue;
			hits++;
			snprintf(want, sizeof want, "PE-x86/Test:Id#%u", i);
			if (strcmp(v.name, want) != 0)
				wrong++;
		}
		ck(wrong == 0, "no key ever answered with another key's verdict");
		ck(hits > 0 && hits <= 64, "hits bounded by capacity");
		printf("  over-capacity: %u of 4000 still cached (cap 64)\n",
		       hits);
	}

	koffridge_stats(f, &st);
	koffridge_describe(f, line, sizeof line);
	printf("  %s\n", line);
	ck(st.capacity == 64, "capacity is what was asked for");

	/*
	 * 6. SAVED AND RELOADED, and every refusal path taken deliberately.
	 *
	 * The cache exists to be reused across runs - measured, it is the
	 * difference between a 4.4 second whole-machine sweep and a 0.75 second
	 * one - which means the file format is now something a wrong answer can
	 * come out of. Each check below is a way that could happen.
	 */
	{
		const char *path = "build/test/fridge_persist.bin";
		const char *why = "";
		struct koffridge *g;
		uint32_t key_a = 0x1234u, key_b = 0x5678u;
		uint32_t n;

		koffridge_clear(f);
		memset(&res, 0, sizeof res);
		res.n = 1;
		res.v[0].level = KOF_LEVEL_INFECT;
		snprintf(res.v[0].name, sizeof res.v[0].name,
			 "PE-x86/Trojan:Kept#1");
		ck(koffridge_put(f, &key_a, sizeof key_a, &res) == 1,
		   "store before save");
		ck(koffridge_put(f, &key_b, sizeof key_b, NULL) == 1,
		   "store clean before save");
		ck(koffridge_save(f, path) == 1, "save");

		/* Same db stamp: both verdicts must come back intact. */
		g = koffridge_open(64, 0x2026090901ull);
		ck(g != NULL, "reopen");
		if (g) {
			n = koffridge_load(g, path, &why);
			ck(n == 2, "both entries loaded");
			ck(koffridge_get(g, &key_a, sizeof key_a, &v) == 1,
			   "loaded entry hits");
			ck(v.findings == 1 &&
			   strcmp(v.name, "PE-x86/Trojan:Kept#1") == 0,
			   "loaded verdict is the one stored");
			ck(koffridge_get(g, &key_b, sizeof key_b, &v) == 1 &&
			   v.findings == 0, "loaded clean verdict is clean");
			/*
			 * A load is not work this run did. Counting it as
			 * stores would have the summary claim the very work the
			 * cache exists to avoid.
			 */
			koffridge_stats(g, &st);
			ck(st.stores == 0, "a load reports no stores");
			koffridge_close(g);
		}

		/*
		 * A DIFFERENT DATABASE DISCARDS THE FILE WHOLE. The entries are
		 * readable and every one of them was reached by rules this run
		 * does not have, which is the one refusal here that is about
		 * trust rather than corruption.
		 */
		g = koffridge_open(64, 0x2026091299ull);
		if (g) {
			ck(koffridge_load(g, path, &why) == 0,
			   "a changed database loads nothing");
			ck(koffridge_get(g, &key_a, sizeof key_a, &v) == 0,
			   "and leaves no entry behind");
			koffridge_close(g);
		}

		/*
		 * A NAME WITH NO NUL IN IT, which the file is allowed to
		 * contain and a caller is not allowed to be handed.
		 *
		 * The file is a trust input - the header says so, and says the
		 * checksum stops nobody who edits it deliberately. This
		 * rewrites the entry's name field to 224 bytes of 'A',
		 * recomputes the checksum the way anybody would, and loads it.
		 * Before the fix that came back unterminated and kofmemscan
		 * printed it with %s: AddressSanitizer called it a 225-byte
		 * read past the end of the verdict.
		 */
		{
			FILE *fp = fopen(path, "r+b");
			long sz;
			unsigned char *b;

			if (fp) {
				fseek(fp, 0, SEEK_END);
				sz = ftell(fp);
				fseek(fp, 0, SEEK_SET);
				b = malloc((size_t)sz);
				if (b && fread(b, 1, (size_t)sz, fp) ==
				    (size_t)sz) {
					unsigned hs = *(unsigned short *)(b + 6);
					unsigned es = *(unsigned *)(b + 8);
					unsigned ne = *(unsigned *)(b + 12);
					unsigned long long h =
						1469598103934665603ull;
					unsigned char *e = b + hs;
					long k;

					/* name[] is the tail of every entry. */
					for (k = 0; k < (long)ne; k++)
						memset(e + (size_t)k * es +
						       es - 224, 'A', 224);
					for (k = 0; k < (long)ne * (long)es;
					     k++) {
						h ^= e[k];
						h *= 1099511628211ull;
					}
					memcpy(b + 24, &h, 8);   /* sum */
					fseek(fp, 0, SEEK_SET);
					if (fwrite(b, 1, (size_t)sz, fp) !=
					    (size_t)sz)
						ck(0, "rewrite the fridge");
				}
				free(b);
				fclose(fp);
			}

			g = koffridge_open(64, 0x2026090901ull);
			if (g) {
				ck(koffridge_load(g, path, &why) > 0,
				   "a hand-edited file still loads");
				if (koffridge_get(g, &key_a, sizeof key_a, &v)) {
					size_t ln = 0;

					while (ln < sizeof v.name &&
					       v.name[ln])
						ln++;
					ck(ln < sizeof v.name,
					   "and its name is NUL terminated");
				} else {
					ck(0, "the edited entry is there");
				}
				koffridge_close(g);
			}
		}

		/* A missing file is the ordinary first run, not an error. */
		g = koffridge_open(64, 0x2026090901ull);
		if (g) {
			ck(koffridge_load(g, "build/test/no_such_fridge.bin",
					  &why) == 0, "absent file loads none");
			koffridge_close(g);
		}

		/*
		 * ONE FLIPPED BYTE ANYWHERE IN THE ENTRIES DISCARDS ALL OF
		 * THEM. A partially-trusted cache is the failure this guards:
		 * the entry that survived corruption would answer for a file
		 * whose verdict came out of a damaged record.
		 */
		{
			FILE *fp = fopen(path, "r+b");

			if (fp) {
				int c;

				/* Past the header, into the first entry. */
				ck(fseek(fp, 48, SEEK_SET) == 0, "seek entry");
				c = fgetc(fp);
				ck(fseek(fp, 48, SEEK_SET) == 0, "seek back");
				fputc(c ^ 0xff, fp);
				fclose(fp);

				g = koffridge_open(64, 0x2026090901ull);
				if (g) {
					ck(koffridge_load(g, path, &why) == 0,
					   "a flipped byte loads nothing");
					koffridge_close(g);
				}
			}
		}
		remove(path);
	}

	koffridge_close(f);

	/* 7. SEVERAL THREADS AT ONCE - see the note on struct hammer. */
	concurrent();

	/* The dedup half of this module. */
	first_then_repeat();
	length_matters();
	window_expires();
	out_of_order();
	eviction_fails_safe();
	reduces();
	not_full_forgets_nothing();
	hostile();

	printf("fridge: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
