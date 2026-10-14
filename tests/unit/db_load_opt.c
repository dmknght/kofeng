/*
 * db_load_opt - the similarity index's allowance at load, and what the host can read back about it.
 *
 *   kof_db_load_opt         the load with the CALLER'S allowance: 0 is the engine's default
 *                           (KOF_DB_INDEX_ALLOW), a number below what the index needs REFUSES the index and
 *                           loads everything else - the engine still scans, `mutation` is NULL
 *   kdb_mutation_status     what building the index said (KOF_MTN_B_*), the bytes it holds, its distinct hashes
 *   KOF_MTN_*               the status bits are single and distinct, KOF_MTN_B_REFUSED is the union of the five
 *                           that refuse, a refusal is never mistaken for a degraded filter, the per-object
 *                           status bits do not overlap the build's
 *
 * The test database has a similarity index (tests/sigs: mutation blocks), 96 distinct hashes today; the
 * numbers below are read from the engine, not typed in, so a changed signature set moves nothing here.
 */

#include "hostile_engine.h"

#include "../../libkofeng/databases/dbloader.h"
#include "../../libkofeng/databases/pack/dbkix.h"
#include "../../libkofeng/detectors/mutations/kofmutation.h"

static const char *db = "build/test/databases-sigs";

static int one_obj(const char *name, const void *b, uint64_t n, const struct kof_result *r, void *u)
{
	(void)name; (void)b; (void)n; (void)r;
	(*(unsigned *)u)++;
	return 0;
}

static unsigned scan_some(kof_engine *e)
{
	kof_scanner *sc = kscan_new(e);
	uint8_t buf[512];
	unsigned n = 0, i;
	struct kof_scan_option opt;

	if (!sc)
		return 0;
	for (i = 0; i < sizeof buf; i++)
		buf[i] = (uint8_t)(i * 7u);
	memset(&opt, 0, sizeof opt);
	(void)kscan_bytes(sc, buf, sizeof buf, "x", &opt, one_obj, &n);
	kscan_free(sc);
	return n;
}

static void bits(void)
{
	const uint32_t b[] = { KOF_MTN_B_FILTER_DEGRADED, KOF_MTN_B_NO_FILTER, KOF_MTN_B_OVER_BUDGET, KOF_MTN_B_TOO_MANY_BLOCKS,
			       KOF_MTN_B_BAD_BLOCK, KOF_MTN_B_NOMEM, KOF_MTN_B_TOO_BIG };
	uint32_t seen = 0;
	unsigned i;

	for (i = 0; i < sizeof b / sizeof b[0]; i++) {
		CK(b[i] && (b[i] & (b[i] - 1u)) == 0 && !(seen & b[i]), "build status bit %u is one distinct bit (0x%x)", i, b[i]);
		seen |= b[i];
	}
	CK(KOF_MTN_B_REFUSED == (KOF_MTN_B_OVER_BUDGET | KOF_MTN_B_TOO_MANY_BLOCKS | KOF_MTN_B_BAD_BLOCK | KOF_MTN_B_NOMEM | KOF_MTN_B_TOO_BIG | KOF_MTN_B_TOO_MANY_CLASSES),
	   "REFUSED is the six that refuse");
	CK(!(KOF_MTN_B_REFUSED & (KOF_MTN_B_FILTER_DEGRADED | KOF_MTN_B_NO_FILTER)), "a degraded or absent filter is not a refusal: the set is built and correct");
	CK(KOF_MTN_S_WALK_TRUNCATED != KOF_MTN_S_STATE_NOMEM && !(KOF_MTN_S_WALK_TRUNCATED & KOF_MTN_S_STATE_NOMEM) &&
	   (KOF_MTN_S_WALK_TRUNCATED & (KOF_MTN_S_WALK_TRUNCATED - 1u)) == 0 && (KOF_MTN_S_STATE_NOMEM & (KOF_MTN_S_STATE_NOMEM - 1u)) == 0,
	   "the per-object status bits are two distinct single bits");
	CK(KOF_MTN_BUILD_NO_FILTER == 1u, "build flag selector");
	CK(KOF_KIX_FILTER_CAP == ((uint64_t)16u << 20), "the filter of a block index is capped at 16 MiB");
}

static void load_opt(void)
{
	kof_engine *e = keng_open(db), *tiny, *deflt, *big;
	uint64_t bytes = 0, bytes2 = 0, b3 = 0;
	uint32_t keys = 0, keys2 = 0, k3 = 0, st, st2;
	struct kof_db_load_opt o;

	CK(e != NULL, "the test database opens (%s)", db);
	if (!e)
		return;
	st = kdb_mutation_status(e, &bytes, &keys);
	CK(st == 0 && bytes > 0 && keys > 0, "the default load builds the index: status %u, %llu bytes, %u hashes", st, (unsigned long long)bytes, keys);
	CK(kdb_mutation_status(e, NULL, NULL) == 0, "the out parameters are optional");

	memset(&o, 0, sizeof o);
	deflt = kof_db_load_opt(db, &o);
	CK(deflt != NULL, "allowance 0 loads");
	if (deflt) {
		st2 = kdb_mutation_status(deflt, &bytes2, &keys2);
		CK(st2 == st && bytes2 == bytes && keys2 == keys, "allowance 0 is the default: the same index (%llu bytes, %u hashes)", (unsigned long long)bytes2, keys2);
		keng_close(deflt);
	}
	o.max_index_bytes = (uint64_t)1 << 30;
	big = kof_db_load_opt(db, &o);
	CK(big != NULL && kdb_mutation_status(big, &b3, &k3) == 0 && k3 == keys, "an ample allowance builds the same index");
	if (big)
		keng_close(big);

	o.max_index_bytes = 1;
	tiny = kof_db_load_opt(db, &o);        /* prints one line to stderr: that is the engine saying so */
	CK(tiny != NULL, "a one byte allowance still loads the database");
	if (tiny) {
		st2 = kdb_mutation_status(tiny, &bytes2, &keys2);
		CK((st2 & KOF_MTN_B_OVER_BUDGET) && (st2 & KOF_MTN_B_REFUSED) && keys2 == 0,
		   "but the index is refused and says why: status 0x%x, %u hashes", st2, keys2);
		CK(bytes2 > 0 && bytes2 > o.max_index_bytes, "and the bytes it REACHED are reported (%llu), not zero", (unsigned long long)bytes2);
		CK(scan_some(tiny) >= 1u, "the engine without its index still scans");
		keng_close(tiny);
	}
	CK(scan_some(e) >= 1u, "and the one with it");
	CK(kof_db_load_opt("build/test/no_such_database_dir", &o) == NULL, "a path that is not a database is NULL, not an engine with nothing in it");
	keng_close(e);
}

int main(void)
{
	bits();
	load_opt();
	printf("db_load_opt: %u checks, %u failed\n", he_checks, he_fails);
	return he_fails != 0;
}
