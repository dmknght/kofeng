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
	printf("fridge: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
