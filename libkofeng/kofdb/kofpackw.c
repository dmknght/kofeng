/*
 * kofpackw.c - build a pack image.
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

#include <stdlib.h>
#include <string.h>

#include <kofmod/kofsig.h>   /* the per-module maxima the ABI declares */

#include "kofpackw.h"
#include "kofpack.h"
#include "../kofmatchers/hexprog.h"
#include "../core/kofcore.h"

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
		uint32_t off, len;
		uint8_t  used;
	} *slot;
	uint32_t mask;
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
static int pool_intern(struct dedup *d, struct buf *pool, const void *data,
		       uint32_t len, uint32_t *out_off)
{
	uint32_t h = kof_crc32(data, len) & d->mask;
	uint32_t probes = 0;

	while (d->slot[h].used) {
		if (d->slot[h].len == len &&
		    memcmp(pool->p + d->slot[h].off, data, len) == 0) {
			*out_off = d->slot[h].off;
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
	d->slot[h].used = 1;
	return 1;
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

	uint32_t n_mods, n_str, n_name, n_rng;

	uint32_t any_target, any_scan, any_arch;
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
	uint64_t s = 0, r = 0, m = 0;
	uint32_t i;

	b->n_mods = n;
	for (i = 0; i < n; i++) {
		s += mods[i].n_str;
		r += mods[i].n_rng;
		m += mods[i].n_names;
	}
	if (s > 0xffffffffu || r > 0xffffffffu || m > 0xffffffffu)
		return 0;
	b->n_str  = (uint32_t)s;
	b->n_rng  = (uint32_t)r;
	b->n_name = (uint32_t)m;
	return 1;
}

static int collect(const struct kof_pw_mod *mods, uint32_t n, struct built *b)
{
	struct dedup ds, dn;
	uint32_t i, k, si = 0, ni = 0, ri = 0;
	int ok = 0;

	memset(&ds, 0, sizeof ds);
	memset(&dn, 0, sizeof dn);

	if (!count_all(mods, n, b))
		goto out;

	b->mod  = calloc(b->n_mods ? b->n_mods : 1, sizeof *b->mod);
	b->str  = calloc(b->n_str  ? b->n_str  : 1, sizeof *b->str);
	b->name = calloc(b->n_name ? b->n_name : 1, sizeof *b->name);
	b->rng  = calloc(b->n_rng  ? b->n_rng  : 1, sizeof *b->rng);
	if (!b->mod || !b->str || !b->name || !b->rng)
		goto out;
	if (!dedup_init(&ds, b->n_str ? b->n_str : 1) ||
	    !dedup_init(&dn, b->n_name ? b->n_name : 1))
		goto out;

	for (i = 0; i < n; i++) {
		const struct kof_pw_mod *m = &mods[i];
		struct kof_pack_mod *o = &b->mod[i];
		uint32_t code_off;

		/*
		 * The caller's arrays are checked here rather than trusted. This
		 * is a library entry point: a length with no bytes behind it is a
		 * memcpy from NULL, which is a crash inside the writer for a
		 * mistake made outside it, and the writer is the only place that
		 * can tell the difference.
		 */
		if (m->code_len == 0 || m->code_len > KOF_BLOB_MAX_CODE || !m->code)
			goto out;
		if ((m->n_str && !m->str) || (m->n_rng && !m->rng) ||
		    (m->n_names && !m->name))
			goto out;

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
			goto out;

		/* Each blob starts 16 byte aligned so its entry point is never
		 * misaligned for the target's calling convention. */
		{
			uint64_t pad = kof_round_up(b->code.len, KOF_PACK_BLOB_ALIGN)
				       - b->code.len;
			static const uint8_t zero[KOF_PACK_BLOB_ALIGN] = { 0 };
			uint32_t dummy;
			if (pad && !buf_add(&b->code, zero, (size_t)pad, &dummy))
				goto out;
		}
		if (!buf_add(&b->code, m->code, m->code_len, &code_off))
			goto out;

		o->code_off   = code_off;
		o->code_len   = m->code_len;
		o->str_first  = si;
		o->n_str      = m->n_str;
		o->rng_first  = ri;
		o->n_rng      = m->n_rng;
		o->name_first = ni;
		o->n_names    = m->n_names;

		for (k = 0; k < m->n_str; k++, si++) {
			const struct kof_pw_str *s = &m->str[k];
			uint32_t off;
			/* Per kind: a compiled hex program is a header and two
			 * tables, so its length is not comparable with a
			 * literal's and the literal cap would refuse ordinary
			 * patterns. */
			if (!s->bytes || s->len == 0)
				goto out;
			if (s->kind == KOF_STR_LITERAL) {
				if (s->len > KOF_STR_MAX_LEN)
					goto out;
			} else if (s->kind == KOF_STR_HEX) {
				if (s->len > KOF_HEX_MAX_PROG)
					goto out;
			} else {
				goto out;
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
					goto out;
				if (!buf_add(&b->str_pool, s->bytes, s->len, &off))
					goto out;
			} else if (!pool_intern(&ds, &b->str_pool, s->bytes, s->len,
						&off)) {
				goto out;
			}
			b->str[si].off   = off;
			b->str[si].len   = s->len;
			b->str[si].kind  = s->kind;
			b->str[si].flags = s->flags;
		}
		for (k = 0; k < m->n_rng; k++, ri++)
			b->rng[ri] = m->rng[k];
		for (k = 0; k < m->n_names; k++, ni++) {
			const struct kof_pw_name *nm = &m->name[k];
			uint32_t off, tlen;
			if (!nm->text)
				goto out;
			tlen = (uint32_t)strlen(nm->text) + 1;   /* with the NUL */
			if (!pool_intern(&dn, &b->name_pool, nm->text, tlen, &off))
				goto out;
			b->name[ni].id  = nm->id;
			b->name[ni].off = off;
		}

		/*
		 * The union. Derived here and nowhere else: a value that claims
		 * more than its members do stops running them, and a detection
		 * that did not happen is not something a test notices.
		 */
		b->any_target |= m->target_mask;
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
				goto out;
			b->memo_slots += (uint32_t)slots;
		}
	}
	ok = 1;
out:
	dedup_free(&ds);
	dedup_free(&dn);
	return ok;
}

uint8_t *kof_pack_build(uint32_t kind, const struct kof_pw_mod *mods, uint32_t n,
			size_t *out_len)
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
	len[KOF_SEC_PRE_TARGET] = (uint64_t)b.n_mods * 4;
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
	len[KOF_SEC_CODE]       = b.code.len;
	/* The inverted index is not built yet. Zero length is how a pack says it
	 * has none, and the loader falls back to asking each module in turn. */
	len[KOF_SEC_IDX_BITMAP] = 0;
	len[KOF_SEC_IDX_SLOT]   = 0;

	off = kof_round_up(sizeof(struct kof_pack_hdr), KOF_PACK_SEC_ALIGN);
	for (i = 0; i < KOF_SEC_COUNT; i++) {
		uint64_t a = (i == KOF_SEC_CODE) ? KOF_PACK_CODE_ALIGN
						 : KOF_PACK_SEC_ALIGN;
		off = kof_round_up(off, a);
		at[i] = off;
		off += len[i];
	}
	if (off > (uint64_t)((size_t)-1))
		goto out;

	img = calloc(1, (size_t)off);
	if (!img)
		goto out;

	for (i = 0; i < b.n_mods; i++) {
		((uint32_t *)(img + at[KOF_SEC_PRE_TARGET]))[i] = mods[i].target_mask;
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
	if (len[KOF_SEC_CODE])
		memcpy(img + at[KOF_SEC_CODE], b.code.p, (size_t)len[KOF_SEC_CODE]);

	h = (struct kof_pack_hdr *)img;
	h->magic   = KOF_PACK_MAGIC;
	h->version = KOF_PACK_VERSION;
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

	/* Last, and over everything after itself, so it covers the header it is
	 * written into. */
	h->crc32 = kof_crc32(img + KOF_PACK_CRC_FROM, off - KOF_PACK_CRC_FROM);

	*out_len = (size_t)off;
out:
	built_free(&b);
	return img;
}