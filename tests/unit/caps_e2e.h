/*
 * caps_e2e.h - scan an in-memory object through the whole pipeline (kscan_bytes)
 * against the test database and keep what the verdict path SAID about every
 * object it opened: the parent, and whatever child it made of it.
 *
 * ALL MATCHES ON, because a finding on an object stops the walk into its
 * children otherwise, and the view/parent tests compare exactly those children.
 *
 * Needs caps_fix.h first. The database is build/test/databases-sigs unless the
 * test is given another as argv[1] - see e2e_open.
 */

#ifndef KOFENG_TESTS_CAPS_E2E_H
#define KOFENG_TESTS_CAPS_E2E_H

#define E2E_MAX_OBJ  6u
#define E2E_MAX_FIND 8u

struct e2e_obj {
	char     name[96];
	uint32_t entry_kind;
	uint32_t n;                  /* findings                                  */
	uint32_t broken;             /* kof_result.broken                         */
	uint32_t examined;
	uint32_t dropped;            /* findings counted but not kept             */
	char     find[E2E_MAX_FIND][112];
	char     verdict[112];       /* the finding with is_verdict, or ""        */
	int      has_syndrome;
	struct kof_synd_result syn;
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
	return e2e_sc != NULL;
}

static inline int e2e_on_object(const char *name, const void *bytes, uint64_t len,
				const struct kof_result *res, void *user)
{
	struct e2e *r = user;
	struct e2e_obj *o;
	uint32_t i;

	(void)bytes; (void)len;
	if (r->n >= E2E_MAX_OBJ)
		return 0;
	o = &r->o[r->n++];
	memset(o, 0, sizeof *o);
	snprintf(o->name, sizeof o->name, "%s", name ? name : "");
	o->entry_kind = res->entry_kind;
	o->n = res->n;
	o->broken = res->broken;
	o->examined = res->examined;
	o->dropped = res->dropped;
	o->has_syndrome = res->has_syndrome;
	o->syn = res->syndrome;
	for (i = 0; i < res->n; i++) {
		if (i < E2E_MAX_FIND)
			snprintf(o->find[i], sizeof o->find[i], "%s", res->v[i].name);
		if (res->v[i].is_verdict)
			snprintf(o->verdict, sizeof o->verdict, "%s", res->v[i].name);
	}
	return 0;
}

static inline int e2e_scan(const uint8_t *b, uint64_t len, struct e2e *r)
{
	struct kof_scan_option opt;

	memset(r, 0, sizeof *r);
	if (!e2e_open(NULL))
		return 0;
	memset(&opt, 0, sizeof opt);
	opt.all_matches = 1;
	opt.max_produced_bytes = 64u << 20;
	opt.max_resident_bytes = 256u << 20;
	opt.max_object_bytes = 64u << 20;
	(void)kscan_bytes(e2e_sc, b, len, "e2e", &opt, e2e_on_object, r);
	return r->n > 0;
}

/* "ELF-x64/Dropper:Agent!Syndrome" -> "Dropper:Agent". Empty when there is none. */
static inline const char *e2e_type_of(const char *verdict, char *out, size_t cap)
{
	const char *s = strchr(verdict, '/'), *e;
	size_t l;

	out[0] = 0;
	if (!s)
		return out;
	s++;
	e = strchr(s, '!');
	l = e ? (size_t)(e - s) : strlen(s);
	if (l >= cap)
		l = cap - 1u;
	memcpy(out, s, l);
	out[l] = 0;
	return out;
}

/* Did this object's verdict name this type word, e.g. "Dropper". */
static inline int e2e_verdict_is(const struct e2e_obj *o, const char *word)
{
	return o->verdict[0] && strstr(o->verdict, word) != NULL;
}

#endif /* KOFENG_TESTS_CAPS_E2E_H */
