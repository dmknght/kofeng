/*
 * engine3_limits - limits that must be SAID (kofeng/CLAUDE.md rule 4), fixed in fix_engine3.
 *
 *   BE-8     a script larger than the object cap gets no form and no decoded literals; the object says so (a LIMIT, counted in
 *            limit_hits) and one at the cap does not. A caller that raises the cap gets the form (nothing is said).
 *
 * Why the old tests missed it: (b) the form's tests (script_*, diag_text_*) use scripts of a few KB; none put a script over the
 * cap, so the early return of script_pass_open ran with no assertion on what it answered.
 */
#define _GNU_SOURCE
#include "hostile_engine.h"
#include "../lib/ctr_scan.h"

static uint8_t *php_of_size(size_t n)
{
	static const char line[] = "$a = 'x';\n";
	uint8_t *p = (uint8_t *)malloc(n);
	size_t i = 6;

	if (!p)
		return NULL;
	memcpy(p, "<?php\n", 6);
	while (i + sizeof line - 1u <= n) {
		memcpy(p + i, line, sizeof line - 1u);
		i += sizeof line - 1u;
	}
	while (i < n)
		p[i++] = '\n';
	return p;
}

static int script_over_cap(void *unused)
{
	static const size_t cap = 1u << 20;
	static const size_t sizes[] = { (1u << 20) - 64u, 1u << 20, (1u << 20) + 64u, (3u << 20) };
	unsigned i;

	(void)unused;
	for (i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
		struct kof_scan_option o = cs_opt();
		struct cs_run r;
		uint8_t *p = php_of_size(sizes[i]);
		int over = sizes[i] > cap;

		if (!p)
			return 9;
		o.max_object_bytes = cap;
		if (cs_scan(p, sizes[i], "x.php", &o, &r))
			return 9;
		if (over) {
			CK(r.o[0].broken == KOF_BROKEN_LIMIT, "php of %zu bytes over a %zu byte cap: the root says %u, not Limit (BE-8)", sizes[i], cap, r.o[0].broken);
			CK(r.limit_hits >= 1, "php of %zu bytes over the cap: limit_hits %llu (BE-8)", sizes[i], (unsigned long long)r.limit_hits);
		} else {
			CK(r.o[0].broken == 0 && r.limit_hits == 0, "php of %zu bytes at or under the cap: nothing is reported (root %u, limit_hits %llu)", sizes[i], r.o[0].broken,
			   (unsigned long long)r.limit_hits);
		}
		cs_free(&r);
		free(p);
	}
	return he_fails != 0 ? 1 : 0;
}

int main(void)
{
	static const struct { int (*fn)(void *); const char *what; } jobs[] = {
		{ script_over_cap, "BE-8 script over the object cap" }
	};
	unsigned i, bad = 0;

	cs_eng = keng_open(HE_DB);
	for (i = 0; i < sizeof jobs / sizeof jobs[0]; i++) {
		struct he_status st = he_child(jobs[i].fn, NULL, 120);

		printf("engine3_limits %-34s %s\n", jobs[i].what, he_how(st));
		bad |= !he_ok(st);
	}
	printf("engine3_limits: %s\n", bad ? "FAIL" : "ok");
	return bad ? 1 : 0;
}
