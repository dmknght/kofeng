/*
 * dbaccess.c - reading a loaded database: ids to text and bytes.
 *
 * The accessors of struct kof_engine (pack/dbtables.h): a disease by id, a
 * module's declared string by id, its names, family, source. They read what
 * dbloader.c laid out and never build or change it, which is why they sit with
 * the layout and not with the loader: the matchers (detectors/pattern) call
 * kof_db_str, and the loader includes the matchers, so the accessor could not
 * stay in dbloader.c without detectors and databases including each other.
 *
 * Every function here is const over the engine and is safe on many threads.
 */

#include <string.h>

#include "dbtables.h"

uint32_t kof_db_disease_count(const struct kof_engine *e)
{
	return e ? e->n_disease : 0;
}

const struct kof_disease_ent *kof_db_disease_at(const struct kof_engine *e, uint32_t i)
{
	return e && i < e->n_disease ? &e->disease[i] : NULL;
}

const struct kof_disease_ent *kof_db_disease(const struct kof_engine *e, uint32_t id)
{
	uint32_t lo = 0, hi = e ? e->n_disease : 0;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (e->disease[mid].id == id)
			return &e->disease[mid];
		if (id < e->disease[mid].id)
			hi = mid;
		else
			lo = mid + 1u;
	}
	return NULL;
}

/*
 * The pack's string descriptor and the engine's are the same sixteen bits of layout,
 * which is what lets the descriptors be used where they lie instead of copied. If
 * either ever moves, this stops the cast rather than letting it read shifted fields.
 */
_Static_assert(sizeof(struct kof_str_ent) == sizeof(struct kof_pack_str),
	       "string descriptor layout drifted from the pack's");

const struct kof_str_ent *kof_db_str(const struct kof_engine *e,
				     const struct kof_module *m, uint32_t id,
				     const uint8_t **bytes)
{
	const struct kof_db_pack *p;
	const struct kof_str_ent *d;

	if (!m || id >= m->n_str || m->pack_id >= e->n_packs)
		return NULL;
	p = &e->packs[m->pack_id];
	/* Section bounds resolved when the pack was loaded - see
	 * kof_db_pack.desc for why that is both cheaper and safer. */
	if (!p->desc || !p->pool)
		return NULL;
	if ((uint64_t)m->str_base + m->n_str > p->n_desc)
		return NULL;

	d = p->desc + m->str_base + id;
	/* Still read out of the mapping, so still checked. */
	if ((uint64_t)d->off + d->len > p->pool_len)
		return NULL;
	*bytes = p->pool + d->off;
	return d;
}

/*
 * The text a module reports, read out of the pack that carries it.
 *
 * Out of the mapping, not out of a table, because a table of every name in the
 * database would be the biggest thing the engine holds and this is the only function
 * that would ever read it - once per finding, which over a whole corpus is tens of
 * calls. The pack's own name section is already an index: descriptors sorted beside
 * a pool, addressed by the offset the module's slice gives.
 *
 * EVERY BOUND IS CHECKED HERE even though the loader checked the same ones, and that
 * is not belt and braces. The loader checked a file; what is read now is a mapping
 * of that file, and a MAP_PRIVATE mapping may or may not show writes another process
 * made since - the format's own header says so. A name that was terminated at load
 * need not still be, and this returns a pointer that the caller prints. Checking
 * costs a comparison on a path that runs when something has already been detected.
 *
 * NULL for anything that does not hold, which the callers already handle: a finding
 * with no name is reported by id, and a wrong answer here would be a name invented
 * out of whatever followed it in the file.
 */
/*
 * One of a module's names, by id or by position.
 *
 * Two questions with one body of bounds checks between them. A finding reports an
 * id and wants the text for it; a tool that lists what a module can report has no
 * id to offer and wants them in order. Splitting the two would be two copies of
 * the checks, which is the one thing this function is careful about - see the
 * note on kof_db_name for why a mapping is re-validated on every call rather than
 * trusted from load time.
 *
 * `by_index` picks which: non-zero and `key` is a position in the module's slice,
 * zero and it is the id the module reports.
 */
static const char *db_name_lookup(const struct kof_engine *e,
				  const struct kof_module *m, uint32_t key,
				  int by_index, uint32_t *id_out)
{
	const struct kof_pack_hdr *h;
	const struct kof_pack_name *pn;
	const uint8_t *base;
	const char *pool;
	uint64_t pool_off, pool_len, desc_off;
	uint32_t i;

	if (m->pack_id >= e->n_packs)
		return NULL;
	base = e->packs[m->pack_id].map;
	if (!base)
		return NULL;
	h = (const void *)base;

	desc_off = h->sec[KOF_SEC_NAME_DESC].off;
	pool_off = h->sec[KOF_SEC_NAME_POOL].off;
	pool_len = h->sec[KOF_SEC_NAME_POOL].len;
	/* The slice the module names has to be inside the section the header
	 * names, which has to be inside the mapping. */
	if ((uint64_t)m->name_base + m->n_names > h->n_names)
		return NULL;
	if (desc_off > e->packs[m->pack_id].len ||
	    (uint64_t)h->n_names * sizeof *pn >
		    e->packs[m->pack_id].len - desc_off)
		return NULL;
	if (pool_off > e->packs[m->pack_id].len ||
	    pool_len > e->packs[m->pack_id].len - pool_off)
		return NULL;

	pn = (const void *)(base + desc_off);
	pool = (const char *)base + pool_off;

	for (i = 0; i < m->n_names; i++) {
		const struct kof_pack_name *d = &pn[m->name_base + i];

		if (by_index ? i != key : d->id != key)
			continue;
		if (id_out)
			*id_out = d->id;
		if (d->off >= pool_len)
			return NULL;
		/* Terminated inside the pool, or it is not a string this may hand
		 * to printf. */
		if (memchr(pool + d->off, 0, (size_t)(pool_len - d->off)) == NULL)
			return NULL;
		return pool + d->off;
	}
	return NULL;
}

const char *kof_db_name(const struct kof_engine *e, const struct kof_module *m,
			uint32_t name_id)
{
	return db_name_lookup(e, m, name_id, 0, NULL);
}

const char *kof_db_name_at(const struct kof_engine *e,
			   const struct kof_module *m, uint32_t index,
			   uint32_t *id_out)
{
	return db_name_lookup(e, m, index, 1, id_out);
}

/*
 * The family KOF_TARGET_NAME declared, read the same way kof_db_name reads a
 * finding's variant - same pool, same mapping, same reason to check on every
 * call instead of trusting the load time pass (see the comment on kof_db_name).
 *
 * Simpler than kof_db_name: family_off is not a table of candidates to search
 * by id, it is the one offset this module's record carries, so there is no loop
 * here - just the same two checks kof_db_name's loop body makes for whichever
 * descriptor it found.
 */
/*
 * A string at `off` in the module's own pack's name pool, or NULL.
 *
 * One function because three fields are stored the same way - the family, the
 * predicted family and the source path - and each is an offset that has to be
 * bounded against the pool and checked for a terminator before it is returned
 * as a C string. Three copies of that would be three places for one of the two
 * checks to go missing.
 */
static const char *db_pool_str(const struct kof_engine *e,
			       const struct kof_module *m, uint32_t off)
{
	const struct kof_pack_hdr *h;
	const uint8_t *base;
	const char *pool;
	uint64_t pool_off, pool_len;

	if (!m || m->pack_id >= e->n_packs)
		return NULL;
	base = e->packs[m->pack_id].map;
	if (!base)
		return NULL;
	h = (const void *)base;

	pool_off = h->sec[KOF_SEC_NAME_POOL].off;
	pool_len = h->sec[KOF_SEC_NAME_POOL].len;
	if (pool_off > e->packs[m->pack_id].len ||
	    pool_len > e->packs[m->pack_id].len - pool_off)
		return NULL;

	pool = (const char *)base + pool_off;
	if (off >= pool_len)
		return NULL;
	if (memchr(pool + off, 0, (size_t)(pool_len - off)) == NULL)
		return NULL;
	return pool + off;
}

const char *kof_db_family(const struct kof_engine *e, const struct kof_module *m)
{
	return db_pool_str(e, m, m ? m->family_off : 0);
}

/*
 * The family a heuristic rule PREDICTS, or NULL when it predicts nothing.
 *
 * Zero is "no prediction" and not "offset zero": the packer interns nothing for
 * a rule without KOF_HEUR_PREDICT, and offset zero in the pool belongs to
 * whatever string happened to be interned first.
 */
const char *kof_db_heur_predict(const struct kof_engine *e,
				const struct kof_module *m)
{
	if (!m || !m->heur_predict_off)
		return NULL;
	return db_pool_str(e, m, m->heur_predict_off);
}

/* Zero is "none declared", for the same reason as above. */
const char *kof_db_content(const struct kof_engine *e,
			   const struct kof_module *m)
{
	if (!m || !m->content_off)
		return NULL;
	return db_pool_str(e, m, m->content_off);
}

/*
 * The source this module was written in, relative to the bases tree.
 *
 * NULL when the database does not carry one - a module compiled outside a tree,
 * or a pack built before the field existed. A caller joins it with its own idea
 * of where the tree is; the database records the path INSIDE the tree and not an
 * absolute one, because an absolute path is a fact about the machine that built
 * the database rather than about the module.
 */
const char *kof_db_source(const struct kof_engine *e, const struct kof_module *m)
{
	const struct kof_pack_hdr *h;
	const uint8_t *base;
	const char *pool;
	uint64_t pool_off, pool_len;

	if (!m || m->pack_id >= e->n_packs)
		return NULL;
	base = e->packs[m->pack_id].map;
	if (!base)
		return NULL;
	h = (const void *)base;

	pool_off = h->sec[KOF_SEC_NAME_POOL].off;
	pool_len = h->sec[KOF_SEC_NAME_POOL].len;
	if (pool_off > e->packs[m->pack_id].len ||
	    pool_len > e->packs[m->pack_id].len - pool_off)
		return NULL;

	pool = (const char *)base + pool_off;
	if (!m->src_off || m->src_off >= pool_len)
		return NULL;
	if (memchr(pool + m->src_off, 0,
		   (size_t)(pool_len - m->src_off)) == NULL)
		return NULL;
	return pool + m->src_off;
}
