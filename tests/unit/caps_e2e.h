/*
 * caps_e2e.h - scan an in-memory object through the whole pipeline (kscan_bytes)
 * against the test database and keep what the engine SAID about every object it
 * opened: the parent, and whatever child it made of it. What a test module said it
 * found is its note (see notes.h) - `find` - and what the engine concluded is the
 * verdict.
 *
 * Needs caps_fix.h first. The database is build/test/databases-sigs unless the
 * test is given another as argv[1] - see e2e_open.
 */

#ifndef KOFENG_TESTS_CAPS_E2E_H
#define KOFENG_TESTS_CAPS_E2E_H

#include "notes.h"

#define E2E_MAX_OBJ  6u
#define E2E_MAX_FIND 8u

struct e2e_obj {
	char     name[96];
	uint32_t entry_kind;
	uint32_t n;                  /* notes the test modules made on it         */
	uint32_t broken;             /* kof_result.broken                         */
	uint32_t examined;
	char     find[E2E_MAX_FIND][112];
	char     verdict[112];       /* the verdict's name, or ""                 */
	int      has_verdict;
	struct kof_finding vf;       /* the verdict itself, ids and all           */
	int      vf_incomplete;      /* kof_result.verdict_incomplete             */
};

struct e2e {
	unsigned       n;
	struct e2e_obj o[E2E_MAX_OBJ];
};

static kof_engine  *e2e_eng;
static kof_scanner *e2e_sc;

static inline int e2e_open(const char *db)
{
	if (e2e_sc)
		return 1;
	e2e_eng = keng_open(db ? db : "build/test/databases-sigs");
	if (!e2e_eng)
		return 0;
	e2e_sc = kscan_new(e2e_eng);
	notes_watch(e2e_sc);
	return e2e_sc != NULL;
}

static inline int e2e_on_object(const char *name, const void *bytes, uint64_t len,
				const struct kof_result *res, void *user)
{
	struct e2e *r = user;
	struct e2e_obj *o;
	struct note_list got;
	uint32_t i;

	(void)bytes; (void)len;
	notes_here(&got);
	if (r->n >= E2E_MAX_OBJ)
		return 0;
	o = &r->o[r->n++];
	memset(o, 0, sizeof *o);
	snprintf(o->name, sizeof o->name, "%s", name ? name : "");
	o->entry_kind = res->entry_kind;
	o->n = got.n;
	o->broken = res->broken;
	o->examined = res->examined;
	o->has_verdict = res->has_verdict;
	o->vf_incomplete = res->verdict_incomplete;
	if (res->has_verdict) {
		o->vf = res->verdict;
		snprintf(o->verdict, sizeof o->verdict, "%s", res->verdict.name);
	}
	for (i = 0; i < got.n && i < E2E_MAX_FIND; i++)
		snprintf(o->find[i], sizeof o->find[i], "%s", got.name[i]);
	return 0;
}

static inline int e2e_scan(const uint8_t *b, uint64_t len, struct e2e *r)
{
	struct kof_scan_option opt;

	memset(r, 0, sizeof *r);
	if (!e2e_open(NULL))
		return 0;
	notes_clear();
	memset(&opt, 0, sizeof opt);
	opt.max_produced_bytes = 64u << 20;
	opt.max_resident_bytes = 256u << 20;
	opt.max_object_bytes = 64u << 20;
	(void)kscan_bytes(e2e_sc, b, len, "e2e", &opt, e2e_on_object, r);
	return r->n > 0;
}

/* Did this object's verdict name this type word, e.g. "Dropper". */
static inline int e2e_verdict_is(const struct e2e_obj *o, const char *word)
{
	return o->verdict[0] && strstr(o->verdict, word) != NULL;
}

#endif /* KOFENG_TESTS_CAPS_E2E_H */
