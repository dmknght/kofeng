/*
 * fidset - the clean-file set, over the cases that would make it lie.
 *
 * Three properties, and the last two are the ones worth a test:
 *
 *   1. what went in comes back, and nothing else does.
 *   2. IT SURVIVES A ROUND TRIP THROUGH THE FILE. The file's layout is the
 *      lookup structure - a fence over a sorted array - so a save that gets
 *      the fence or the block bounds wrong produces a file that loads, answers,
 *      and answers WRONG. Nothing downstream could tell.
 *   3. A DIFFERENT DATABASE IS NOT READ AT ALL. A database update can change
 *      any verdict in it, including every clean one; a set carried across one
 *      would skip files it has no current answer for, silently and for as long
 *      as the file survives.
 *
 * Sizes are chosen to cross the fence stride - 512 keys to a block - because
 * everything interesting about the layout happens at a block boundary, and a
 * test with fifty keys would exercise one block and prove nothing about the
 * search that picks between them.
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "../../libkoforbit/koffridge/fidset.h"

static int fails;

static void bad(const char *what)
{
	printf("  FAIL %s\n", what);
	fails++;
}

/* A distinct identity per i, built the way a platform module would. */
static struct kof_fid fid_of(uint64_t i)
{
	struct kof_fid f;

	memset(&f, 0, sizeof f);
	memcpy(f.node, &i, sizeof i);
	f.size = 1000u + i;
	f.born = 111u;
	f.written = 222u + i;
	return f;
}

#define N 5000u          /* ~10 blocks of 512 */

/* The engine these answers belong to - see kof_fidset_open. Fixed here, and
 * changed in one case below, because it invalidates a file exactly as the
 * database stamp does. */
#define ENG 0x900DC0DEu

int main(void)
{
	static const char *path = "build/temp/fidset_test.bin";
	struct kof_fidset *s;
	struct kof_fidset_stat st;
	uint64_t i, key[N];

	for (i = 0; i < N; i++) {
		struct kof_fid f = fid_of(i);

		key[i] = kof_fid_key(&f);
		if (!key[i])
			bad("a key came back zero, which is the empty slot");
	}

	/*
	 * THE KEY IS A FUNCTION OF THE IDENTITY AND OF NOTHING ELSE - the same
	 * identity twice is the same key, and one field different is not.
	 */
	{
		struct kof_fid a = fid_of(7), b = fid_of(7);

		if (kof_fid_key(&a) != kof_fid_key(&b))
			bad("the same identity gave two keys");
		b.written++;
		if (kof_fid_key(&a) == kof_fid_key(&b))
			bad("a changed write time did not change the key");
	}

	remove(path);

	/* ---- in memory, before anything is written ---- */
	s = kof_fidset_open(0xABCDu, ENG);
	if (!s)
		return printf("  FAIL open\n"), 1;
	for (i = 0; i < N; i += 2u)
		kof_fidset_add(s, key[i]);
	for (i = 0; i < N; i++) {
		int want = (i % 2u) == 0u;

		if (kof_fidset_has(s, key[i]) != want) {
			bad("a key this run added is not there, or one it did "
			    "not is");
			break;
		}
	}
	/* Adding twice is free and must not grow anything. */
	kof_fidset_add(s, key[0]);
	kof_fidset_stats(s, &st);
	if (st.added != N / 2u)
		bad("adding a key twice counted twice");

	if (!kof_fidset_save(s, path))
		bad("save refused");
	kof_fidset_close(s);

	/* ---- back from the file ---- */
	s = kof_fidset_open(0xABCDu, ENG);
	if (!kof_fidset_load(s, path))
		bad("the file did not load");
	kof_fidset_stats(s, &st);
	if (st.mapped != N / 2u)
		bad("the file holds a different number of keys than were put "
		    "in it");
	for (i = 0; i < N; i++) {
		int want = (i % 2u) == 0u;

		if (kof_fidset_has(s, key[i]) != want) {
			printf("  FAIL round trip disagrees at %llu "
			       "(block %llu)\n", (unsigned long long)i,
			       (unsigned long long)(i / 2u / 512u));
			fails++;
			break;
		}
	}

	/*
	 * A SECOND RUN ADDS TO WHAT IS THERE. The merge is two sorted runs, and
	 * a merge that drops one side is a cache that forgets everything older
	 * than the last sweep while still looking like it works.
	 */
	for (i = 1u; i < N; i += 2u)
		kof_fidset_add(s, key[i]);
	if (!kof_fidset_save(s, path))
		bad("the second save refused");
	kof_fidset_close(s);

	s = kof_fidset_open(0xABCDu, ENG);
	if (!kof_fidset_load(s, path))
		bad("the merged file did not load");
	kof_fidset_stats(s, &st);
	if (st.mapped != N)
		bad("the merge lost or duplicated keys");
	for (i = 0; i < N; i++)
		if (!kof_fidset_has(s, key[i])) {
			bad("a key from the FIRST run is gone after a merge");
			break;
		}
	/* And nothing that was never added. */
	{
		struct kof_fid f = fid_of(N + 1u);

		if (kof_fidset_has(s, kof_fid_key(&f)))
			bad("a key nobody added came back present");
	}
	kof_fidset_close(s);

	/*
	 * ---- WHAT THE HEADER SAYS ABOUT THE FILE ITSELF ----
	 *
	 * A cache is read by a person as well as by a scanner: "how old are
	 * these answers" is asked of every cache that ever surprised anybody.
	 * The field is an integer of seconds and nothing decides anything by it
	 * - see the note on `made` - so what is checked here is that it is
	 * WRITTEN and comes back, not that it expires something.
	 */
	{
		uint64_t before = (uint64_t)time(NULL);

		s = kof_fidset_open(0xABCDu, ENG);
		if (!kof_fidset_load(s, path))
			bad("the file did not load for the header check");
		kof_fidset_stats(s, &st);
		if (!st.made)
			bad("the file does not say when it was written");
		else if (st.made + 300u < before || st.made > before + 300u)
			bad("the time in the header is not the time it was "
			    "written");
		kof_fidset_close(s);
	}

	/*
	 * ---- TAKING ONE OUT, which is the only way this set shrinks ----
	 *
	 * The run that learns a cached file is not clean is the one that did
	 * not ask the cache - a --no-cache sweep, or one under a newer
	 * database. If the entry survives that, the next ordinary run skips a
	 * file something was just found in.
	 */
	s = kof_fidset_open(0xABCDu, ENG);
	if (!kof_fidset_load(s, path))
		bad("the set did not load for the drop");
	if (!kof_fidset_drop(s, key[3]))
		bad("drop refused");
	if (kof_fidset_has(s, key[3]))
		bad("a dropped key still answers present");
	if (!kof_fidset_has(s, key[4]))
		bad("dropping one key took another with it");
	/* Dropping the same key twice is free, like adding one twice. */
	kof_fidset_drop(s, key[3]);
	kof_fidset_stats(s, &st);
	if (st.dropped != 1u)
		bad("dropping a key twice counted twice");
	if (!kof_fidset_save(s, path))
		bad("the save after a drop refused");
	kof_fidset_close(s);

	s = kof_fidset_open(0xABCDu, ENG);
	if (!kof_fidset_load(s, path))
		bad("the file did not load after a drop");
	kof_fidset_stats(s, &st);
	if (st.mapped != N - 1u)
		bad("the saved file did not lose exactly the dropped key");
	if (kof_fidset_has(s, key[3]))
		bad("a dropped key came back from the file");
	for (i = 0; i < N; i++) {
		if (i == 3u)
			continue;
		if (!kof_fidset_has(s, key[i])) {
			bad("a drop took an unrelated key with it");
			break;
		}
	}
	/* And it can be put back: a file that is clean again is cacheable
	 * again, and the drop list must not outlive the save. */
	kof_fidset_add(s, key[3]);
	if (!kof_fidset_has(s, key[3]))
		bad("a key added after a drop is not there");
	kof_fidset_close(s);

	s = kof_fidset_open(0xABCDu, ENG);
	(void)kof_fidset_load(s, path);
	kof_fidset_drop(s, key[9]);
	kof_fidset_close(s);       /* dropped, never saved: the file is intact */
	s = kof_fidset_open(0xABCDu, ENG);
	if (!kof_fidset_load(s, path) || !kof_fidset_has(s, key[9]))
		bad("a drop that was never saved changed the file");
	kof_fidset_close(s);

	/*
	 * ---- A DIFFERENT ENGINE READS NOTHING EITHER ----
	 *
	 * Same rules, same files, a build whose parsers carve differently: a
	 * verdict from the old one is about bytes the new one may not agree
	 * are there. The file is refused whole, like a database change.
	 */
	s = kof_fidset_open(0xABCDu, ENG + 1u);
	if (kof_fidset_load(s, path))
		bad("a set written by another engine build was loaded");
	if (kof_fidset_has(s, key[0]))
		bad("a set written by another engine build answered a query");
	kof_fidset_close(s);

	/*
	 * ---- a different database reads nothing ----
	 */
	s = kof_fidset_open(0xABCDu + 1u, ENG);
	if (kof_fidset_load(s, path))
		bad("a set written under another database was loaded");
	if (kof_fidset_has(s, key[0]))
		bad("a set written under another database answered a query");
	kof_fidset_close(s);

	/* ---- a truncated file is not a smaller set ---- */
	{
		FILE *f = fopen(path, "rb+");

		if (f) {
			fseek(f, 0, SEEK_END);
			{
				long n = ftell(f);

				fclose(f);
				if (truncate(path, n - 16) == 0) {
					s = kof_fidset_open(0xABCDu, ENG);
					if (kof_fidset_load(s, path))
						bad("a truncated file loaded");
					kof_fidset_close(s);
				}
			}
		}
	}
	remove(path);

	if (fails) {
		printf("fidset: %d check(s) failed\n", fails);
		return 1;
	}
	printf("fidset: keys, blocks, round trip, merge, drop, header, "
	       "db and engine stamps, truncation - ok\n");
	return 0;
}
