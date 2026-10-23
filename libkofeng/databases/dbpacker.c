/*
 * dbpacker.c - build a pack image.
 *
 * Two passes over the modules. The first sizes everything and fills the pools, so
 * that by the end every section's length is known; the second writes the fixed
 * stride tables now that the pool offsets they refer to are settled. Sizing and
 * writing in one pass would mean growing the image while writing into it, which
 * is how an offset ends up pointing at where something used to be.
 *
 * Sharing is only ever of pool bytes. The descriptor tables cannot be shared,
 * because a module addresses its strings as a contiguous run - str_first plus a
 * module-local id - and a run cannot be contiguous and shared at the same time.
 * The waste that would save is eight bytes per duplicate descriptor against the
 * bytes themselves, which is the part worth sharing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kofmod/kofsig.h>   /* the per-module maxima the ABI declares */

#include "dbpacker.h"
#include "pack/dbcore.h"
#include "pack/hexprog.h"
#include "pack/dbkix.h"
#include "../detectors/mutations/kofmutflt.h"   /* the pre-built block filter */
#include "../detectors/pattern/kofpix.h"
#include "../kofcore/kofcore.h"

/* A growable byte buffer, alive only while building. */
struct buf {
	uint8_t *p;
	size_t   len, cap;
};

static int buf_need(struct buf *b, size_t extra)
{
	size_t want;
	uint8_t *np;

	if (b->cap - b->len >= extra)
		return 1;
	want = b->cap ? b->cap : 4096;
	while (want - b->len < extra) {
		if (want > (size_t)-1 / 2)
			return 0;
		want *= 2;
	}
	np = realloc(b->p, want);
	if (!np)
		return 0;
	b->p = np;
	b->cap = want;
	return 1;
}

static int buf_add(struct buf *b, const void *data, size_t len, uint32_t *out_off)
{
	if (len > 0xffffffffu || b->len > 0xffffffffu - len)
		return 0;
	if (!buf_need(b, len))
		return 0;
	*out_off = (uint32_t)b->len;
	memcpy(b->p + b->len, data, len);
	b->len += len;
	return 1;
}

/*
 * Where a run of bytes already in a pool starts.
 *
 * Open addressed, keyed on a checksum of the content, and the slot holds the
 * offset and length so a collision is settled by comparing the bytes. Linear
 * search would be correct and quadratic: at five thousand strings that is
 * twelve million comparisons, and the population this is meant for is two orders
 * larger than that.
 */
struct dedup {
	struct {
		uint32_t off, len, uid;
		/*
		 * PART OF THE KEY, because bytes alone are not the identity.
		 *
		 * The uid is what the scan memo is keyed by, so two entries
		 * that share one answer must be two entries that ASK THE SAME
		 * QUESTION. Identical bytes with different options do not:
		 * "<%" as a substring, as a fullword and as a token are three
		 * different questions about the same two bytes.
		 *
		 * Measured before the fix: a module asking all three in one
		 * range got the first one's answer three times, and swapping
		 * the order of the calls swapped the answer. Both readings
		 * looked like a working rule.
		 */
		uint8_t  tag;
		uint8_t  used;
	} *slot;
	uint32_t mask;
	uint32_t next_uid;
};

static int dedup_init(struct dedup *d, uint32_t expect)
{
	uint32_t cap = 16;
	/* The comparison is 64 bit: expect * 2 in 32 bits wraps for a large set,
	 * and a wrapped target leaves the table tiny, which turns into a build
	 * failure rather than a wrong answer but for a reason nobody could read. */
	while ((uint64_t)cap < (uint64_t)expect * 2u && cap < (1u << 30))
		cap *= 2;
	d->slot = calloc(cap, sizeof *d->slot);
	if (!d->slot)
		return 0;
	d->mask = cap - 1;
	return 1;
}

static void dedup_free(struct dedup *d)
{
	free(d->slot);
	d->slot = NULL;
}

/*
 * Offset of `data` in `pool`, appending it first if it is not there yet.
 *
 * The table is sized up front from the number of entries the caller will add, so
 * it never grows and a full table is a build error rather than an infinite probe.
 */
/*
 * Intern the bytes and hand back both where they landed and WHICH PATTERN THEY ARE.
 *
 * The offset is what the descriptor points at; the uid is what the memo is keyed by.
 * They are produced together because they are the same fact - two modules that get
 * the same offset are declaring the same pattern, and the uid is that stated in a
 * form the scan path can index with.
 */
static int pool_intern_tag(struct dedup *d, struct buf *pool, const void *data,
			   uint32_t len, uint8_t tag, uint32_t *out_off,
			   uint32_t *out_uid)
{
	uint32_t h = (kof_crc32(data, len) ^ ((uint32_t)tag * 0x9e3779b9u)) &
		     d->mask;
	uint32_t probes = 0;

	while (d->slot[h].used) {
		if (d->slot[h].len == len && d->slot[h].tag == tag &&
		    memcmp(pool->p + d->slot[h].off, data, len) == 0) {
			*out_off = d->slot[h].off;
			*out_uid = d->slot[h].uid;
			return 1;
		}
		h = (h + 1) & d->mask;
		if (++probes > d->mask)
			return 0;
	}
	if (!buf_add(pool, data, len, out_off))
		return 0;
	d->slot[h].off  = *out_off;
	d->slot[h].len  = len;
	d->slot[h].tag  = tag;
	d->slot[h].uid  = d->next_uid++;
	d->slot[h].used = 1;
	*out_uid = d->slot[h].uid;
	return 1;
}

/* Bytes with no options of their own - the name pool. */
static int pool_intern(struct dedup *d, struct buf *pool, const void *data,
		       uint32_t len, uint32_t *out_off, uint32_t *out_uid)
{
	return pool_intern_tag(d, pool, data, len, 0u, out_off, out_uid);
}

/*
 * A C STRING into the name pool, terminator and all.
 *
 * pool_intern is the byte primitive and serves two pools with two different
 * conventions: the string pool holds patterns, which are bytes and end where
 * their length says, and the name pool holds C strings, which end at a NUL that
 * has to be WRITTEN because nothing appends one.
 *
 * Keeping those two straight was left to each caller remembering to add one to
 * a strlen, and the first caller that did not paid for it in a way that looked
 * like something else entirely: the source path went in without its terminator,
 * the very next string interned - a variant name - landed immediately after it,
 * and reading the path back returned "signatures/Prometei_00.c" run together
 * with "p1tox". Nothing had confused a path with a variant name; there was
 * simply no boundary between them, and a C string read finds the next NUL in
 * the pool whoever it belongs to.
 *
 * So the name pool gets its own front door and the convention stops being a
 * thing to remember.
 */
static int name_intern(struct dedup *d, struct buf *pool, const char *str,
		       uint32_t *out_off, uint32_t *out_uid)
{
	return pool_intern(d, pool, str, (uint32_t)strlen(str) + 1u,
			   out_off, out_uid);
}

/*
 * Everything the first pass produces. Held together so the second pass has one
 * thing to read from and the failure path has one thing to release.
 */
struct built {
	struct buf str_pool, name_pool, code;

	struct kof_pack_mod  *mod;
	struct kof_pack_str  *str;
	struct kof_pack_name *name;
	uint32_t             *rng;
	struct kof_mutation_block *blk;
	uint32_t                *pool;

	uint32_t n_mods, n_str, n_name, n_rng, n_blk, n_pool;

	uint64_t any_target;
	uint32_t any_scan, any_arch;
	uint64_t min_size_min;
	uint32_t memo_slots;
};

static void built_free(struct built *b)
{
	free(b->str_pool.p);
	free(b->name_pool.p);
	free(b->code.p);
	free(b->mod);
	free(b->str);
	free(b->name);
	free(b->rng);
	free(b->blk);
	free(b->pool);
}

/*
 * Total descriptor counts, so the tables are allocated once at the right size
 * instead of grown.
 *
 * Summed in 64 bits and refused if a total does not fit a uint32. That is not
 * defensive politeness: the counts index the tables that are allocated from them,
 * so a total that wrapped would allocate a table smaller than what is then written
 * into it - a heap overflow reached by arithmetic rather than by a bad pointer.
 *
 * Zero on a total that cannot be represented.
 */
static int count_all(const struct kof_pw_mod *mods, uint32_t n, struct built *b)
{
	uint64_t s = 0, r = 0, m = 0, bl = 0, pl = 0;
	uint32_t i;

	b->n_mods = n;
	for (i = 0; i < n; i++) {
		s += mods[i].n_str;
		r += mods[i].n_rng;
		m += mods[i].n_names;
		bl += mods[i].n_blk;
		pl += mods[i].n_pool;
	}
	if (s > 0xffffffffu || r > 0xffffffffu || m > 0xffffffffu ||
	    bl > 0xffffffffu || pl > 0xffffffffu)
		return 0;
	b->n_str  = (uint32_t)s;
	b->n_rng  = (uint32_t)r;
	b->n_name = (uint32_t)m;
	b->n_blk  = (uint32_t)bl;
	b->n_pool = (uint32_t)pl;
	return 1;
}

/* What the pieces of collect() share: the pack being built, the two interning sets, and
 * how far into each table the modules so far have written. */
struct collect_cx {
	struct built *b;
	struct dedup  ds, dn;
	uint32_t      si, ni, ri, bi, pi;
};

/*
 * THE TABLES AND THE TWO INTERNING SETS, sized from the totals: allocated once at the
 * right size and never grown. Returns 0 when a total does not fit or memory ran out.
 */
static int collect_alloc(struct collect_cx *cx, const struct kof_pw_mod *mods,
			 uint32_t n)
{
	struct built *b = cx->b;

	if (!count_all(mods, n, b))
		return 0;

	b->mod  = calloc(b->n_mods ? b->n_mods : 1, sizeof *b->mod);
	b->str  = calloc(b->n_str  ? b->n_str  : 1, sizeof *b->str);
	b->name = calloc(b->n_name ? b->n_name : 1, sizeof *b->name);
	b->rng  = calloc(b->n_rng  ? b->n_rng  : 1, sizeof *b->rng);
	b->blk  = calloc(b->n_blk  ? b->n_blk  : 1, sizeof *b->blk);
	b->pool = calloc(b->n_pool ? b->n_pool : 1, sizeof *b->pool);
	if (!b->mod || !b->str || !b->name || !b->rng)
		return 0;
	/*
	 * dn interns, per module, a family AND (when present) a content and a
	 * source path, plus one entry per name - so up to n_name + 3n distinct
	 * strings, and one more for the empty string reserved below. It is sized
	 * for all of them up front: dedup_init takes an expected count rather
	 * than growing, so a table that fills mid-build is a build error, not a
	 * silent wrong answer.
	 */
	if (!dedup_init(&cx->ds, b->n_str ? b->n_str : 1) ||
	    !dedup_init(&cx->dn, (b->n_name ? b->n_name : 1) + 3u * (n ? n : 1) + 1u))
		return 0;

	/*
	 * RESERVE POOL OFFSET ZERO for the empty string, so nothing else lands
	 * there. content_off and src_off use 0 to mean "absent", and the loader
	 * reads it back that way (kof_db_content, kof_db_source) - but offset 0 is
	 * otherwise whatever string was interned first, module 0's family. Without
	 * this, a content equal to that string dedups to offset 0 and is silently
	 * read as none. Both fields are only ever set for a non-empty value, so
	 * pinning "" here means a real one can never collide with the sentinel.
	 */
	{
		uint32_t empty_off, empty_uid;

		if (!name_intern(&cx->dn, &b->name_pool, "", &empty_off, &empty_uid))
			return 0;
	}
	return 1;
}

/* A text a finding's name is made of: shorter than KOF_NAME_MAX_LEN, terminator
 * included. NULL is no text and fits. */
static int name_fits(const char *s)
{
	return !s || memchr(s, 0, KOF_NAME_MAX_LEN) != NULL;
}

/* THE CALLER'S ARRAYS AND PER-MODULE MAXIMA, refused before any of them is walked. */
static int collect_check(const struct kof_pw_mod *m)
{
	/*
	 * The caller's arrays are checked here rather than trusted. This
	 * is a library entry point: a length with no bytes behind it is a
	 * memcpy from NULL, which is a crash inside the writer for a
	 * mistake made outside it, and the writer is the only place that
	 * can tell the difference.
	 */
	if (m->code_len == 0 || m->code_len > KOF_BLOB_MAX_CODE || !m->code)
		return 0;
	if ((m->n_str && !m->str) || (m->n_rng && !m->rng) ||
	    (m->n_names && !m->name) ||
	    (m->n_blk && !m->blk) || (m->n_pool && !m->pool))
		return 0;

	/*
	 * The per-module maxima the module ABI already declares, enforced
	 * here because this is where they first have consequences. Before
	 * any loop, not after: a count is the only description of how long
	 * the caller's array is, so a count that is wrong has to be refused
	 * before it is used to walk one - questioning it afterwards means
	 * the walk already happened.
	 *
	 * They also make n_str x n_rng bounded by 4096, so the memo total
	 * below cannot overflow whatever a caller passes.
	 */
	if (m->n_str > KOF_MAX_STR_PER_MODULE ||
	    m->n_rng > KOF_MAX_RANGE_PER_MODULE)
		return 0;
	/*
	 * A NAME THE ENGINE CANNOT STORE IS REFUSED HERE, not only by ksigbuilder.
	 * KOF_NAME_MAX_LEN was enforced by the tool that happens to write most packs;
	 * this is the library entry point, and a pack made through it with a
	 * 300-character family used to be accepted, loaded, and reported cut. Every
	 * text a finding is composed from is held to it: the family, the family a
	 * rule predicts, and each detection name.
	 */
	if (!name_fits(m->family))
		return 0;
	{
		uint32_t k;

		for (k = 0; k < m->n_names; k++)
			if (!m->name[k].text || !name_fits(m->name[k].text))
				return 0;
	}
	return 1;
}

/* THE MODULE'S BLOB AND ITS RECORD: the code (16-byte aligned), the counts and offsets,
 * and what it declared as text - family, prediction, content, source - interned. */
static int collect_head(struct collect_cx *cx, const struct kof_pw_mod *m,
			struct kof_pack_mod *o)
{
	struct built *b = cx->b;
	uint32_t code_off;

	/* Each blob starts 16 byte aligned so its entry point is never
	 * misaligned for the target's calling convention. */
	{
		uint64_t pad = kof_round_up(b->code.len, KOF_PACK_BLOB_ALIGN)
			       - b->code.len;
		static const uint8_t zero[KOF_PACK_BLOB_ALIGN] = { 0 };
		uint32_t dummy;
		if (pad && !buf_add(&b->code, zero, (size_t)pad, &dummy))
			return 0;
	}
	if (!buf_add(&b->code, m->code, m->code_len, &code_off))
		return 0;

	o->code_off   = code_off;
	o->code_len   = m->code_len;
	o->str_first  = cx->si;
	o->n_str      = m->n_str;
	o->rng_first  = cx->ri;
	o->n_rng      = m->n_rng;
	o->blk_first  = cx->bi;
	o->n_blk      = m->n_blk;
	o->name_first = cx->ni;
	o->n_names    = m->n_names;

	/*
	 * What KOF_TARGET_NAME declared, once per module rather than once
	 * per finding - see the comment on struct kof_pack_mod. Interned
	 * into the same pool and the same dedup table a finding's variant
	 * uses (dn), so two modules declaring the same family share the
	 * bytes. Empty rather than skipped when a module declared none,
	 * so family_off is always a real offset to a real string and the
	 * loader never has to treat it as a special case.
	 *
	 * An UNPACK module may well declare one - the msf decoders do,
	 * and the scanner's family pass reads exactly this field to run
	 * a predicted family's unpackers in front of the rest.
	 */
	{
		const char *fam = m->family ? m->family : "";
		uint32_t family_uid;

		if (!name_intern(&cx->dn, &b->name_pool, fam,
				 &o->family_off, &family_uid))
			return 0;
	}
	o->maltype = m->maltype;
	o->step = m->step;
	/* The record's reserved fields (see struct kof_pack_mod) stay as the array
	 * was made: zero. */
	/* Interned like the family and the source path: the text lives
	 * once in the pool and the record carries an offset. */
	if (m->content && m->content[0]) {
		uint32_t content_uid;

		if (!name_intern(&cx->dn, &b->name_pool, m->content,
				 &o->content_off, &content_uid))
			return 0;
	}
	if (m->src && m->src[0]) {
		uint32_t src_uid;

		if (!name_intern(&cx->dn, &b->name_pool, m->src,
				 &o->src_off, &src_uid))
			return 0;
	}
	return 1;
}

/* THE MODULE'S STRINGS, validated and interned; a compiled program stays aligned. */
static int collect_strs(struct collect_cx *cx, const struct kof_pw_mod *m)
{
	struct built *b = cx->b;
	uint32_t k;

	for (k = 0; k < m->n_str; k++, cx->si++) {
		const struct kof_pw_str *s = &m->str[k];
		uint32_t off, uid = 0;
		/* Per kind: a compiled hex program is a header and two
		 * tables, so its length is not comparable with a
		 * literal's and the literal cap would refuse ordinary
		 * patterns. */
		if (!s->bytes || s->len == 0)
			return 0;
		if (s->kind == KOF_STR_LITERAL) {
			if (s->len > KOF_STR_MAX_LEN)
				return 0;
		} else if (s->kind == KOF_STR_HEX) {
			if (s->len > KOF_HEX_MAX_PROG)
				return 0;
		} else {
			return 0;
		}
		/*
		 * A compiled program is read as a struct, so it has to be
		 * aligned - the matcher casts the pool bytes rather than
		 * copying them out, which is the whole reason the strides
		 * are fixed. UBSan on a real corpus is what found this;
		 * on x86 the unaligned read merely works, and on the
		 * architectures the pack format already names it does not.
		 *
		 * Interned without dedup for the same reason: a matching
		 * run of bytes elsewhere in the pool is very unlikely to
		 * be aligned, and reusing it would undo the padding. Hex
		 * programs are few and the copy is bytes.
		 */
		if (s->kind == KOF_STR_HEX) {
			static const uint8_t pad[4] = { 0 };
			uint32_t dummy;

			if (b->str_pool.len % KOF_HEX_PROG_ALIGN &&
			    !buf_add(&b->str_pool, pad,
				     KOF_HEX_PROG_ALIGN -
				     b->str_pool.len % KOF_HEX_PROG_ALIGN,
				     &dummy))
				return 0;
			if (!buf_add(&b->str_pool, s->bytes, s->len, &off))
				return 0;
			/* Compiled programs are not interned - they must stay
			 * aligned - so each gets an id of its own and shares
			 * with nothing. */
			uid = cx->ds.next_uid++;
		/* The options are part of the identity - see dedup.tag.
		 * Same bytes, different options: two entries, two uids,
		 * two memo slots. The pool holds the bytes twice, which
		 * is a handful of bytes for a question that was being
		 * answered wrongly. */
		} else if (!pool_intern_tag(&cx->ds, &b->str_pool, s->bytes,
					    s->len, s->flags,
					    &off, &uid)) {
			return 0;
		}
		b->str[cx->si].uid   = uid;
		b->str[cx->si].off   = off;
		b->str[cx->si].len   = s->len;
		b->str[cx->si].kind  = s->kind;
		b->str[cx->si].flags = s->flags;
	}
	return 1;
}

/* THE RANGES, THE BLOCKS (rebased into the pack's pool), THE POOL AND THE NAMES. */
static int collect_tables(struct collect_cx *cx, const struct kof_pw_mod *m)
{
	struct built *b = cx->b;
	uint32_t k;

	for (k = 0; k < m->n_rng; k++, cx->ri++)
		b->rng[cx->ri] = m->rng[k];
	/*
	 * The blocks, REBASED into the pack's pool as they are copied.
	 * A module's block records index its own hashes from zero, and
	 * the pack has one pool for all of them - so first_hash moves
	 * by however many hashes came before. The same rebasing a
	 * string offset gets, and the same failure if it is skipped:
	 * a block that reads another module's hashes and scores
	 * against them.
	 */
	for (k = 0; k < m->n_blk; k++, cx->bi++) {
		b->blk[cx->bi] = m->blk[k];
		b->blk[cx->bi].first_hash += cx->pi;
	}
	for (k = 0; k < m->n_pool; k++, cx->pi++)
		b->pool[cx->pi] = m->pool[k];
	for (k = 0; k < m->n_names; k++, cx->ni++) {
		const struct kof_pw_name *nm = &m->name[k];
		uint32_t off, nuid;
		if (!nm->text)
			return 0;
		/* Names share the pool too, but nothing keys on their id. */
		if (!name_intern(&cx->dn, &b->name_pool, nm->text, &off,
				 &nuid))
			return 0;
		(void)nuid;
		b->name[cx->ni].id  = nm->id;
		b->name[cx->ni].off = off;
	}
	return 1;
}

/* WHAT THE PACK'S DESCRIBES AS A WHOLE, derived from this module: the union of the
 * targets, scans and architectures, the smallest minimum size, and the memo total. */
static int collect_union(struct built *b, const struct kof_pw_mod *m, uint32_t i)
{
	/*
	 * The union. Derived here and nowhere else: a value that claims
	 * more than its members do stops running them, and a detection
	 * that did not happen is not something a test notices.
	 */
	/*
	 * The union is a PRESENCE SET over target ids now, not an OR of
	 * masks: an id is an ordinary number, so "something here is for
	 * target t" is a bit of this per id rather than the id itself.
	 * A module that names no target names every one of them.
	 */
	if (!m->n_target) {
		b->any_target = ~(uint64_t)0;
	} else {
		uint8_t ti;

		for (ti = 0; ti < m->n_target &&
			     ti < KOF_TARGET_LIST_MAX; ti++)
			if (m->target[ti] < 64u)
				b->any_target |= (uint64_t)1
						 << m->target[ti];
	}
	b->any_scan   |= m->scan_mask;
	b->any_arch   |= m->arch_mask;

	/* Plain minimum. Zero already means "no minimum", and it is the
	 * smallest value there is, so a module without one drags the
	 * pack's minimum to zero on its own - which is the right answer
	 * and needs no special case to reach it. */
	if (i == 0 || m->size_min < b->min_size_min)
		b->min_size_min = m->size_min;

	/* In 64 bits: n_str x n_rng in 32 would wrap for an absurd module
	 * and hand back a small product that passes any check made after
	 * it. The memo is indexed with this number. */
	{
		uint64_t slots = (uint64_t)m->n_str * m->n_rng;
		if (slots > 0xffffffffu ||
		    b->memo_slots > 0xffffffffu - slots)
			return 0;
		b->memo_slots += (uint32_t)slots;
	}
	return 1;
}

static int collect(const struct kof_pw_mod *mods, uint32_t n, struct built *b)
{
	struct collect_cx cx;
	uint32_t i;
	int ok = 0;

	memset(&cx, 0, sizeof cx);
	cx.b = b;

	if (!collect_alloc(&cx, mods, n))
		goto out;
	for (i = 0; i < n; i++) {
		const struct kof_pw_mod *m = &mods[i];

		if (!collect_check(m) || !collect_head(&cx, m, &b->mod[i]) ||
		    !collect_strs(&cx, m) || !collect_tables(&cx, m) ||
		    !collect_union(b, m, i))
			goto out;
	}
	ok = 1;
out:
	dedup_free(&cx.ds);
	dedup_free(&cx.dn);
	return ok;
}

/*
 * THE PATTERN TABLE of this pack, as a part of its tail (kofpix_build_pack says what a table holds;
 * the loader builds the same one in memory from the same sections for a pack that has none).
 * A table smaller than `embed_min` (KOFPIX_EMBED_MIN unless the caller asked otherwise) is not written:
 * building it at load costs less than opening a part, and a pack of a few kilobytes does not grow by tens.
 *
 * Returns the part's image (kof_pix_make: the table, its slice CRCs and the footer) or NULL, with
 * *nomem set when NULL is an allocation failure and not "nothing to write".
 */
static uint8_t *make_pix_part(const struct built *b, uint64_t at, uint64_t old_len,
			      uint64_t embed_min, uint64_t *len, int *nomem)
{
	struct kofpix_pack_view v;
	struct kofpix_build_stat st;
	uint64_t sec_len = 0;
	uint8_t *sec, *part = NULL;

	*nomem = 0;
	*len = 0;
	memset(&v, 0, sizeof v);
	v.mod = b->mod; v.n_mod = b->n_mods;
	v.str = b->str; v.n_str = b->n_str;
	v.rng = b->rng; v.n_rng = b->n_rng;
	v.pool = b->str_pool.p; v.pool_len = b->str_pool.len;
	sec = kofpix_build_pack(&v, &sec_len, &st);
	if (!sec) {
		*nomem = sec_len == ~(uint64_t)0;
		return NULL;
	}
	if (sec_len >= embed_min) {
		part = kof_pix_make(sec, sec_len, (uint32_t)(st.n_rec > 0xffffffffu ? 0xffffffffu : st.n_rec),
				    at, old_len, 0, len);
		if (!part)
			*nomem = 1;
	}
	free(sec);
	return part;
}

static int cmp_u32_asc(const void *a, const void *b)
{
	uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;

	return x < y ? -1 : x > y;
}

/*
 * The pre-built filter of the blocks' keys (detectors/mutations/kofmutflt.h): the DISTINCT multiplied hashes, ascending,
 * stored at KOF_MFLT_R_DEFAULT bits. The loader keeps it at the width its ledger grants and builds nothing. Peak
 * memory here is 4 bytes a hash of the pool and the largest partition's scratch (30 MB). NULL (and the pack
 * gets the bloom filter it always had) when the pack has no blocks or an allocation fails.
 */
static uint8_t *build_xf(const struct built *b, uint64_t *len)
{
	uint32_t *keys, i, j, m = 0, st = 0;
	uint64_t n = 0;
	uint8_t *reg;

	for (i = 0; i < b->n_blk; i++)
		n += b->blk[i].n_hash;
	if (!n || n > 0xfffffff0ull)
		return NULL;
	keys = malloc((size_t)n * sizeof *keys);
	if (!keys)
		return NULL;
	for (i = 0; i < b->n_blk; i++)
		for (j = 0; j < b->blk[i].n_hash; j++)
			keys[m++] = b->pool[b->blk[i].first_hash + j] * KOF_KIX_MULT;
	qsort(keys, m, sizeof *keys, cmp_u32_asc);
	for (i = 0, j = 0; i < m; i++)
		if (!j || keys[i] != keys[j - 1u])
			keys[j++] = keys[i];
	reg = kof_mflt_build(keys, j, KOF_MFLT_R_DEFAULT, len, &st);
	free(keys);
	return reg;
}

/*
 * Append the tail of the pack to the image: the pattern table when the pack has keyable markers and
 * the block index when it has blocks (see pack/dbkix.h for the container). Returns 0 only on an
 * allocation failure; a set a part cannot describe (more than 256 distinct region/normalizer/side
 * combinations, an entry count past 32 bits) is SAID on stderr and the pack is written without that
 * part - the loader then builds the structure in memory under its ledger, or refuses it loudly
 * (KOF_MTN_B_OVER_BUDGET for the blocks, KOF_PIX_B_OVER_BUDGET for the markers).
 *
 * Nothing before the tail moves: every record keeps its layout and the format version is untouched.
 * What changes is the length the header states and the CRC over it, which is what lets an engine
 * that does not know the tail load the pack as one with a long tail. Both footers carry the CRC of
 * the OLD part as the file will hold it - which includes the header's new file_len - so a newer engine
 * can check the part it reads at load without reading the tail.
 */
static int append_tail(uint8_t **imgp, uint64_t *offp, const struct built *b, uint64_t embed_min)
{
	struct kof_kix_build_in in;
	struct kof_kix_build_res res;
	uint64_t old_len = *offp, at = kof_round_up(old_len, KOF_KIX_ALIGN), plen = 0, tlen = 0, total;
	struct kof_pack_hdr *h;
	uint8_t *tr = NULL, *pix = NULL, *img, *xf;
	uint64_t xf_len = 0;
	uint32_t crc;
	int nomem = 0;

	if (b->n_str) {
		pix = make_pix_part(b, at, old_len, embed_min, &plen, &nomem);
		if (nomem)
			return 0;
	}
	if (b->n_blk) {
		memset(&in, 0, sizeof in);
		in.blk = b->blk; in.n_blk = b->n_blk;
		in.pool = b->pool; in.n_pool = b->n_pool;
		xf = build_xf(b, &xf_len);
		if (xf) {
			in.xf = xf; in.xf_bytes = xf_len; in.xf_kind = KOF_KIX_XF_FUSE;
		}
		tr = kof_kix_make(&in, at + plen, old_len, 0, &tlen, &res);
		free(xf);
		if (!tr) {
			if (res.status & KOF_KIX_B_NOMEM) {
				free(pix);
				return 0;
			}
			fprintf(stderr, "dbpacker: no similarity index in this pack (status 0x%x: %s); "
				"the loader will build one in memory\n", res.status,
				(res.status & KOF_KIX_B_TOO_MANY_CLASSES) ? "more than 256 region/normalizer/side classes"
				: (res.status & KOF_KIX_B_TOO_BIG) ? "more entries than 32 bits address"
				: "the blocks do not describe a set");
		}
	}
	if (!pix && !tr)
		return 1;
	total = at + plen + tlen;
	if (total > (uint64_t)((size_t)-1) / 2u) {
		free(pix);
		free(tr);
		return 0;
	}
	img = realloc(*imgp, (size_t)total);
	if (!img) {
		free(pix);
		free(tr);
		return 0;
	}
	memset(img + old_len, 0, (size_t)(total - old_len));
	h = (struct kof_pack_hdr *)img;
	h->file_len = total;
	/* The old part as the file will hold it, header included. */
	crc = kof_crc32(img + KOF_PACK_CRC_FROM, old_len - KOF_PACK_CRC_FROM);
	if (pix) {
		kof_kix_seal(pix, plen, crc);
		memcpy(img + at, pix, (size_t)plen);
	}
	if (tr) {
		kof_kix_seal(tr, tlen, crc);
		memcpy(img + at + plen, tr, (size_t)tlen);
	}
	free(pix);
	free(tr);
	*imgp = img;
	*offp = total;
	return 1;
}

uint8_t *kof_pack_build(uint32_t kind, const struct kof_pw_mod *mods, uint32_t n,
			size_t *out_len)
{
	return kof_pack_build_opt(kind, mods, n, NULL, out_len);
}

uint8_t *kof_pack_build_opt(uint32_t kind, const struct kof_pw_mod *mods, uint32_t n,
			    const struct kof_pack_opt *opt, size_t *out_len)
{
	struct built b;
	struct kof_pack_hdr *h;
	uint64_t off, len[KOF_SEC_COUNT], at[KOF_SEC_COUNT];
	uint8_t *img = NULL;
	uint32_t i;

	if (!mods || n == 0 || !out_len)
		return NULL;

	memset(&b, 0, sizeof b);
	if (!collect(mods, n, &b))
		goto out;

	memset(len, 0, sizeof len);
	/* One FIXED row per module: the count, then the ids. Fixed so the row
	 * for module i is at i * stride and needs no index of its own, and the
	 * count inside it is what says how much of the row means anything. */
	len[KOF_SEC_PRE_TARGET] = (uint64_t)b.n_mods * KOF_PRE_TARGET_STRIDE;
	len[KOF_SEC_PRE_SCAN]   = (uint64_t)b.n_mods * 4;
	len[KOF_SEC_PRE_ARCH]   = (uint64_t)b.n_mods * 4;
	len[KOF_SEC_PRE_SUBTYPE] = (uint64_t)b.n_mods * 4;
	len[KOF_SEC_PRE_SIZE]   = (uint64_t)b.n_mods * 8;
	len[KOF_SEC_MODS]       = (uint64_t)b.n_mods * sizeof(struct kof_pack_mod);
	len[KOF_SEC_STR_DESC]   = (uint64_t)b.n_str  * sizeof(struct kof_pack_str);
	len[KOF_SEC_STR_POOL]   = b.str_pool.len;
	len[KOF_SEC_NAME_DESC]  = (uint64_t)b.n_name * sizeof(struct kof_pack_name);
	len[KOF_SEC_NAME_POOL]  = b.name_pool.len;
	len[KOF_SEC_RANGE]      = (uint64_t)b.n_rng  * 4;
	len[KOF_SEC_MUTATION_BLK] = (uint64_t)b.n_blk  * sizeof(struct kof_mutation_block);
	len[KOF_SEC_MUTATION_POOL] = (uint64_t)b.n_pool * 4;
	len[KOF_SEC_CODE]       = b.code.len;
	/* The inverted index is not built yet. Zero length is how a pack says it
	 * has none, and the loader falls back to asking each module in turn. */
	len[KOF_SEC_IDX_BITMAP] = 0;
	len[KOF_SEC_IDX_SLOT]   = 0;

	off = kof_round_up(sizeof(struct kof_pack_hdr), KOF_PACK_SEC_ALIGN);
	for (i = 0; i < KOF_SEC_COUNT; i++) {
		/* Every section the same; the code section stopped being page
		 * aligned in the file - see KOF_PACK_SEC_ALIGN for what that
		 * cost and why nothing needed it. */
		off = kof_round_up(off, KOF_PACK_SEC_ALIGN);
		at[i] = off;
		off += len[i];
	}
	if (off > (uint64_t)((size_t)-1))
		goto out;

	img = calloc(1, (size_t)off);
	if (!img)
		goto out;

	for (i = 0; i < b.n_mods; i++) {
		{
			uint8_t *row = img + at[KOF_SEC_PRE_TARGET] +
				       (size_t)i * KOF_PRE_TARGET_STRIDE;
			uint8_t nt = mods[i].n_target;

			if (nt > KOF_TARGET_LIST_MAX)
				nt = KOF_TARGET_LIST_MAX;
			row[0] = nt;
			memcpy(row + 1, mods[i].target, nt);
		}
		((uint32_t *)(img + at[KOF_SEC_PRE_SCAN]))[i]   = mods[i].scan_mask;
		((uint32_t *)(img + at[KOF_SEC_PRE_ARCH]))[i]   = mods[i].arch_mask;
		((uint32_t *)(img + at[KOF_SEC_PRE_SUBTYPE]))[i] =
			mods[i].subtype_mask;
		((uint64_t *)(img + at[KOF_SEC_PRE_SIZE]))[i]   = mods[i].size_min;
	}
	if (len[KOF_SEC_MODS])
		memcpy(img + at[KOF_SEC_MODS], b.mod, (size_t)len[KOF_SEC_MODS]);
	if (len[KOF_SEC_STR_DESC])
		memcpy(img + at[KOF_SEC_STR_DESC], b.str, (size_t)len[KOF_SEC_STR_DESC]);
	if (len[KOF_SEC_STR_POOL])
		memcpy(img + at[KOF_SEC_STR_POOL], b.str_pool.p,
		       (size_t)len[KOF_SEC_STR_POOL]);
	if (len[KOF_SEC_NAME_DESC])
		memcpy(img + at[KOF_SEC_NAME_DESC], b.name,
		       (size_t)len[KOF_SEC_NAME_DESC]);
	if (len[KOF_SEC_NAME_POOL])
		memcpy(img + at[KOF_SEC_NAME_POOL], b.name_pool.p,
		       (size_t)len[KOF_SEC_NAME_POOL]);
	if (len[KOF_SEC_RANGE])
		memcpy(img + at[KOF_SEC_RANGE], b.rng, (size_t)len[KOF_SEC_RANGE]);
	if (len[KOF_SEC_MUTATION_BLK])
		memcpy(img + at[KOF_SEC_MUTATION_BLK], b.blk,
		       (size_t)len[KOF_SEC_MUTATION_BLK]);
	if (len[KOF_SEC_MUTATION_POOL])
		memcpy(img + at[KOF_SEC_MUTATION_POOL], b.pool,
		       (size_t)len[KOF_SEC_MUTATION_POOL]);
	if (len[KOF_SEC_CODE])
		memcpy(img + at[KOF_SEC_CODE], b.code.p, (size_t)len[KOF_SEC_CODE]);

	h = (struct kof_pack_hdr *)img;
	h->magic   = KOF_PACK_MAGIC;
	h->major = KOF_PACK_MAJOR;
	h->minor = KOF_PACK_MINOR;
	h->build = KOF_PACK_BUILD;
	/* Which vtable the blobs expect. Taken from the header this packer was built
	 * against, which is the same SDK the modules were compiled against - they come
	 * out of one tree and one `make`. */
	h->abi_version = KOFSIG_ABI_VERSION;
	h->machine = KOF_PACK_MACH_HOST;
	h->file_len = off;
	h->n_mods  = b.n_mods;
	h->n_str   = b.n_str;
	h->n_rng   = b.n_rng;
	h->n_names = b.n_name;
	h->n_blk   = b.n_blk;
	h->n_pool  = b.n_pool;
	h->any_target   = b.any_target;
	h->any_scan     = b.any_scan;
	h->any_arch     = b.any_arch;
	h->kind         = kind;
	h->min_size_min = b.min_size_min;
	h->memo_slots   = b.memo_slots;
	h->idx_bits     = 0;
	h->n_idx_slots  = 0;
	for (i = 0; i < KOF_SEC_COUNT; i++) {
		h->sec[i].off = at[i];
		h->sec[i].len = len[i];
	}

	/* The tail: the pattern table and the block index (append_tail). */
	if (!append_tail(&img, &off, &b, opt && opt->pix_embed_min ? opt->pix_embed_min : KOFPIX_EMBED_MIN))
		goto out;

	/* Last, and over everything after itself, so it covers the header it is
	 * written into. */
	h = (struct kof_pack_hdr *)img;
	h->crc32 = kof_crc32(img + KOF_PACK_CRC_FROM, off - KOF_PACK_CRC_FROM);

	*out_len = (size_t)off;
out:
	built_free(&b);
	return img;
}