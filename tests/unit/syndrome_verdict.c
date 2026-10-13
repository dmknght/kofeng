/*
 * syndrome_verdict - the object's verdict is what the syndromes make of its diseases.
 *
 * tests/sigs/sig_disease_00.c is a detector that declares the disease
 * flood-network/udp, and tests/sigs/syndromes/botnet_00.c is a verified sample
 * that was a botnet and showed exactly that disease. So an object carrying the
 * marker has the disease, the disease proves the type, and the verdict is
 * Botnet:Agent by the syndrome engine - while the detector's own finding stays in
 * the array as evidence and does not take the slot.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofeng.h"
#include <kofmod/kofsig.h>   /* KOF_ENGINE_SYNDROME, KOF_MALTYPE_BOTNET */

static int fails;

static void ok(const char *what, int cond)
{
	printf("  %s %s\n", cond ? "ok  " : "FAIL", what);
	if (!cond)
		fails++;
}

static struct kof_result first_res;
static int n_obj;

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	(void)name; (void)bytes; (void)len; (void)user;
	if (n_obj == 0)
		first_res = *res;
	n_obj++;
	return 0;
}

static int write_file(const char *path, const void *p, size_t n)
{
	FILE *f = fopen(path, "wb");

	if (!f)
		return 0;
	fwrite(p, 1, n, f);
	fclose(f);
	return 1;
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/test/databases-sigs";
	const char *path = "build/test/syndrome_verdict.tmp";
	uint8_t buf[128];
	struct kof_scan_option opt;
	kof_engine *e;
	kof_scanner *sc;
	uint32_t i, verdict = (uint32_t)-1, evidence = (uint32_t)-1;

	e = keng_open(db);
	if (!e) {
		printf("syndrome verdict: cannot open %s\n", db);
		return 2;
	}
	sc = kscan_new(e);
	memset(&opt, 0, sizeof opt);
	opt.max_produced_bytes = 1u << 20;
	opt.max_resident_bytes = 16u << 20;
	opt.max_object_bytes   = 1u << 20;

	for (i = 0; i < sizeof buf; i++)
		buf[i] = (uint8_t)(0x40u + i);
	memcpy(buf + 16, "DISEASE_FIXTURE_MARKER", 22);
	if (!sc || !write_file(path, buf, sizeof buf)) {
		printf("syndrome verdict: cannot set up\n");
		return 2;
	}
	n_obj = 0;
	(void)kscan_path(sc, path, &opt, on_object, NULL);
	for (i = 0; i < first_res.n; i++) {
		if (strstr(first_res.v[i].name, "DiseaseTest"))
			evidence = i;
		if (first_res.v[i].is_verdict)
			verdict = i;
	}
	ok("the detector's finding is kept as evidence", evidence != (uint32_t)-1);
	ok("and it is not the verdict", evidence != (uint32_t)-1 &&
	   !first_res.v[evidence].is_verdict);
	ok("the object has a verdict", verdict != (uint32_t)-1);
	ok("it is the syndrome engine's", verdict != (uint32_t)-1 &&
	   first_res.v[verdict].engine == KOF_ENGINE_SYNDROME);
	ok("the disease proved the type: Botnet:Agent", verdict != (uint32_t)-1 &&
	   strstr(first_res.v[verdict].name, "Botnet:Agent") != NULL);
	ok("proven, so Infected", verdict != (uint32_t)-1 &&
	   first_res.v[verdict].level == KOF_LEVEL_INFECT);
	ok("the result carries the inference too", first_res.has_syndrome &&
	   first_res.syndrome.guaranteed == (1u << KOF_MALTYPE_BOTNET));

	/* nothing found, nothing said */
	for (i = 0; i < sizeof buf; i++)
		buf[i] = (uint8_t)(0x40u + i);
	write_file(path, buf, sizeof buf);
	n_obj = 0;
	memset(&first_res, 0, sizeof first_res);
	(void)kscan_path(sc, path, &opt, on_object, NULL);
	ok("a clean object has no finding at all", first_res.n == 0);

	remove(path);
	kscan_free(sc);
	keng_close(e);
	printf("syndrome verdict: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
