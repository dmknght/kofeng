/*
 * ctr_scan.h - what the container tests share beside the writers (ctr_writers.h): one scan of a byte buffer through the
 * whole engine, kept as a table of the objects the walk reported, with the facts a hostile-container test asserts on.
 *
 *   cs_scan(bytes, n, root, &opt, &run)   one scanner, kscan_bytes on a guard-page copy, every object recorded
 *   cs_find(&run, "tail")                 the first object whose name ends in `tail`
 *   run.broken_limit / limit_hits / peak / child_bytes / depth   the budget facts (kofoption.h, kof_stats)
 *
 * Needs hostile_engine.h (the guard buffer, HE_DB) included first. The engine is opened once per process; a forked child
 * inherits it, so a case that crashes the walk takes only its own child.
 */
#ifndef KOF_TESTS_CTR_SCAN_H
#define KOF_TESTS_CTR_SCAN_H

#define CS_MAXOBJ 4096u

struct cs_obj {
	char     name[192];
	uint64_t len;
	uint32_t broken;
	uint32_t depth;
	uint64_t hash;          /* FNV-1a of the bytes */
	uint8_t  head[32];
};

struct cs_run {
	struct cs_obj *o;
	unsigned       n;             /* objects seen (may exceed CS_MAXOBJ; only the first CS_MAXOBJ are kept) */
	int            rc;
	uint64_t       child_bytes;   /* bytes of every object below the root */
	uint64_t       broken, broken_limit;
	uint64_t       limit_hits, peak, names_invalid;
	uint32_t       max_depth;
	uint64_t       max_name;
	unsigned       slash_forged;  /* object names whose leaf contains the separator, or whose depth is not the depth of its path */
};

static kof_engine *cs_eng;

static inline uint64_t cs_fnv(const void *p, uint64_t n)
{
	uint64_t h = 1469598103934665603ull, i;

	for (i = 0; i < n; i++)
		h = (h ^ ((const uint8_t *)p)[i]) * 1099511628211ull;
	return h;
}

static inline int cs_on(const char *name, const void *b, uint64_t len, const struct kof_result *res, void *user)
{
	struct cs_run *r = (struct cs_run *)user;
	uint32_t d = kobj_depth(name);

	if (r->n < CS_MAXOBJ) {
		struct cs_obj *o = &r->o[r->n];

		snprintf(o->name, sizeof o->name, "%s", name);
		o->len = len;
		o->broken = res ? res->broken : 0u;
		o->depth = d;
		o->hash = cs_fnv(b, len);
		memset(o->head, 0, sizeof o->head);
		memcpy(o->head, b, len < sizeof o->head ? (size_t)len : sizeof o->head);
	}
	if (d > 0) {                                  /* the leaf of a child holds no path separator: a name cannot forge "//" or a path */
		const char *leaf = name, *q;

		for (q = name; *q; q++)
			if (q[0] == '/' && q[1] == '/')
				leaf = q + 2;
		for (q = leaf; *q; q++)
			if (*q == '/' || *q == '\\' || (uint8_t)*q < 0x20)
				r->slash_forged++;
	}
	r->n++;
	if (d > 0)
		r->child_bytes += len;
	if (res && res->broken) {
		r->broken++;
		if (res->broken == KOF_BROKEN_LIMIT)
			r->broken_limit++;
	}
	if (d > r->max_depth)
		r->max_depth = d;
	if (strlen(name) > r->max_name)
		r->max_name = strlen(name);
	return 0;
}

static inline int cs_scan(const void *bytes, size_t n, const char *root, const struct kof_scan_option *opt, struct cs_run *r)
{
	kof_scanner *sc;
	struct he_guard g;

	memset(r, 0, sizeof *r);
	r->o = (struct cs_obj *)calloc(CS_MAXOBJ, sizeof *r->o);
	if (!r->o)
		return -1;
	if (!cs_eng)
		cs_eng = keng_open(HE_DB);
	sc = cs_eng ? kscan_new(cs_eng) : NULL;
	if (!sc || !he_guard_make(&g, bytes, n)) {
		kscan_free(sc);
		return -1;
	}
	r->rc = kscan_bytes(sc, g.p, g.n, root, opt, cs_on, r);
	r->limit_hits = kscan_stats(sc)->limit_hits;
	r->peak = kscan_stats(sc)->peak_resident;
	r->names_invalid = kscan_stats(sc)->names_invalid;
	he_guard_free(&g);
	kscan_free(sc);
	return 0;
}

static inline void cs_free(struct cs_run *r)
{
	free(r->o);
	memset(r, 0, sizeof *r);
}

static inline const struct cs_obj *cs_find(const struct cs_run *r, const char *tail)
{
	unsigned i, k = r->n < CS_MAXOBJ ? r->n : CS_MAXOBJ;
	size_t tl = strlen(tail);

	for (i = 0; i < k; i++) {
		size_t nl = strlen(r->o[i].name);

		if (nl >= tl && !strcmp(r->o[i].name + nl - tl, tail))
			return &r->o[i];
	}
	return NULL;
}

/* A scan option with the budgets of a small test, as hostile_engine_archives.c sets them. */
static inline struct kof_scan_option cs_opt(void)
{
	struct kof_scan_option o = he_opt();

	o.max_resident_bytes = 128ull << 20;
	o.max_produced_bytes = 64ull << 20;
	o.max_object_bytes = 32ull << 20;
	return o;
}

/* Fill n bytes with a pattern that tells members apart (member k, offset i). */
static inline void cs_fill(uint8_t *p, size_t n, unsigned k)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)('a' + (k * 7u + i * 13u) % 26u);
}

#endif
