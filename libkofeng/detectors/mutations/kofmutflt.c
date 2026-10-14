/*
 * kofmutflt.c - the partitioned binary fuse filter of the block index. Layout, the ladder and the
 * reasons are in kofmutflt.h.
 *
 * The construction is the 3-wise binary fuse filter (Graf and Lemire, "Binary Fuse Filters: Fast and
 * Smaller Than Xor Filters"): every key maps to one slot in each of three consecutive segments of the
 * part's array; the entries are chosen, by peeling, so that the XOR of a member's three entries is its
 * fingerprint. A non-member's XOR is a fingerprint-wide random number, equal to its own fingerprint with
 * probability 2^-w. The hash is 64 bits made from the 32-bit key, the part's seed and a bijective mixer, so
 * two distinct keys never collide before the filter and the retry on a failed peel is a new seed.
 */

#define _GNU_SOURCE
#include <math.h>
#include <stdlib.h>
#include <string.h>
#if defined(__linux__)
#include <sys/mman.h>
#endif

#include "kofmutflt.h"
#include "../../kofcore/kofcore.h"

#if defined(__GNUC__)
#define MFLT_PREFETCH(p) __builtin_prefetch(p)
#else
#define MFLT_PREFETCH(p) ((void)(p))
#endif

struct mflt_ent {              /* the table entry as it is on disk: 32 bytes */
	uint64_t seed;
	uint64_t off;
	uint32_t n_key;
	uint32_t seg_log;
	uint32_t seg_count;
	uint32_t entries;
};
_Static_assert(sizeof(struct mflt_ent) == KOF_MFLT_PART_LEN, "an fuse table entry is 32 bytes");

struct mflt_hdr {
	uint32_t magic, version;
	uint32_t r, part_bits, n_part, pad;
	uint64_t n_key;
	uint64_t region_len;
	uint8_t  reserved[24];
};
_Static_assert(sizeof(struct mflt_hdr) == KOF_MFLT_HDR_LEN, "the fuse header is 64 bytes");

/* A part as it is resident. `arr` NULL: not resident, the part passes every key. */
struct mflt_part {
	uint64_t       seed;
	const uint8_t *arr;
	uint32_t       scl;          /* seg_count * seg_len: the span the first slot is drawn from */
	uint32_t       seg_len;
	uint32_t       mask;         /* seg_len - 1 */
	uint32_t       pad;
};

struct kof_mflt {
	uint32_t          w, part_bits, n_part, n_res;
	uint64_t          n_key, resident;
	struct mflt_part *part;
	uint8_t          *mem;
};

static inline uint64_t mix64(uint64_t x)
{
	x ^= x >> 33;
	x *= 0xff51afd7ed558ccdull;
	x ^= x >> 33;
	x *= 0xc4ceb9fe1a85ec53ull;
	x ^= x >> 33;
	return x;
}

static inline uint64_t key_hash(uint32_t key, uint64_t seed)
{
	return mix64((uint64_t)key ^ seed);
}

/* The three slots of `hash` in a part of segment length `1 << sl` and `scl` first-slot span. */
static inline void slots(uint64_t hash, uint32_t scl, uint32_t seg_len, uint32_t *h0, uint32_t *h1,
			 uint32_t *h2)
{
	uint32_t a = (uint32_t)(((hash >> 32) * (uint64_t)scl) >> 32), mask = seg_len - 1u;

	*h0 = a;
	*h1 = (a + seg_len) ^ ((uint32_t)(hash >> 18) & mask);
	*h2 = (a + 2u * seg_len) ^ ((uint32_t)hash & mask);
}

static inline uint32_t fprint(uint64_t hash)
{
	return (uint32_t)(hash ^ (hash >> 32));
}

/* ---- shape --------------------------------------------------------------------- */

/* Segment length (log2) and segment count for `m` keys, the reference's sizing. */
static void shape(uint32_t m, uint32_t *seg_log, uint32_t *seg_count)
{
	double t = 0.06679, factor, cap;
	uint32_t e = 0, seg_len, init;
	uint64_t len;

	while (t * 3.33 <= (double)m && e < KOF_MFLT_MAX_SEG_LOG) {
		t *= 3.33;
		e++;
	}
	seg_len = 1u << e;
	factor = m > 1u ? 0.875 + 0.25 * 13.815510557964274 / log((double)m) : 2.0;
	if (factor < 1.125)
		factor = 1.125;
	cap = (double)m * factor;
	init = (uint32_t)((cap + seg_len - 1u) / seg_len);
	init = init > 2u ? init - 2u : 1u;
	len = ((uint64_t)init + 2u) * seg_len;
	*seg_log = e;
	*seg_count = (uint32_t)((len + seg_len - 1u) / seg_len);
	*seg_count = *seg_count <= 2u ? 1u : *seg_count - 2u;
}

static uint32_t part_bits_for(uint64_t n)
{
	uint32_t b = 0;

	while (b < KOF_MFLT_MAX_PART_BITS && (n >> b) > KOF_MFLT_PART_KEYS)
		b++;
	return b;
}

uint64_t kof_mflt_region_bytes(uint64_t n_key, uint32_t r)
{
	uint32_t pb = part_bits_for(n_key), np = 1u << pb;
	uint64_t per = n_key / np + 1u, total;
	uint32_t sl, sc;

	shape((uint32_t)per, &sl, &sc);
	total = KOF_MFLT_HDR_LEN + (uint64_t)np * KOF_MFLT_PART_LEN + 64u;
	/* An upper bound: a part may hold more than the mean, so allow a quarter more and the padding. */
	total += (uint64_t)np * (((uint64_t)sc + 2u) * (1ull << sl) * (r / 8u) * 5u / 4u + 128u);
	return total;
}

/* ---- the packer's half ----------------------------------------------------------- */

struct pbuild {
	uint32_t *cnt;
	uint64_t *xh;
	uint64_t *order;
	uint8_t  *which;
	uint32_t *stack;
	uint16_t *fp;
};

/* Peel one part. keys[0, m): ascending, distinct. Returns the seed that worked (in *seed), 0 on failure. */
static int peel_part(const uint32_t *keys, uint32_t m, uint32_t seg_log, uint32_t seg_count,
		     uint64_t *seed, struct pbuild *b, uint32_t alen)
{
	uint32_t seg_len = 1u << seg_log, scl = seg_count * seg_len, attempt, i;

	for (attempt = 0; attempt < 128u; attempt++) {
		uint32_t ns = 0, n_ord = 0;

		*seed = mix64(*seed + 0x9e3779b97f4a7c15ull + attempt);
		memset(b->cnt, 0, (size_t)alen * sizeof *b->cnt);
		memset(b->xh, 0, (size_t)alen * sizeof *b->xh);
		for (i = 0; i < m; i++) {
			uint64_t h = key_hash(keys[i], *seed);
			uint32_t h0, h1, h2;

			slots(h, scl, seg_len, &h0, &h1, &h2);
			b->cnt[h0]++; b->xh[h0] ^= h;
			b->cnt[h1]++; b->xh[h1] ^= h;
			b->cnt[h2]++; b->xh[h2] ^= h;
		}
		for (i = 0; i < alen; i++)
			if (b->cnt[i] == 1u)
				b->stack[ns++] = i;
		while (ns) {
			uint32_t s = b->stack[--ns], h0, h1, h2, o1, o2;
			uint64_t h;

			if (b->cnt[s] != 1u)
				continue;
			h = b->xh[s];
			slots(h, scl, seg_len, &h0, &h1, &h2);
			b->order[n_ord] = h;
			if (s == h0) {
				b->which[n_ord] = 0; o1 = h1; o2 = h2;
			} else if (s == h1) {
				b->which[n_ord] = 1; o1 = h0; o2 = h2;
			} else {
				b->which[n_ord] = 2; o1 = h0; o2 = h1;
			}
			n_ord++;
			b->cnt[s] = 0;
			b->cnt[o1]--; b->xh[o1] ^= h;
			if (b->cnt[o1] == 1u)
				b->stack[ns++] = o1;
			b->cnt[o2]--; b->xh[o2] ^= h;
			if (b->cnt[o2] == 1u)
				b->stack[ns++] = o2;
		}
		if (n_ord == m) {
			/* Assign in reverse order of removal. */
			memset(b->fp, 0, (size_t)alen * sizeof *b->fp);
			while (n_ord) {
				uint64_t h;
				uint32_t h0, h1, h2, f;

				n_ord--;
				h = b->order[n_ord];
				slots(h, scl, seg_len, &h0, &h1, &h2);
				f = fprint(h) ^ b->fp[h0] ^ b->fp[h1] ^ b->fp[h2];
				b->fp[b->which[n_ord] == 0 ? h0 : b->which[n_ord] == 1 ? h1 : h2] = (uint16_t)f;
			}
			return 1;
		}
	}
	return 0;
}

uint8_t *kof_mflt_build(const uint32_t *keys, uint64_t n, uint32_t r, uint64_t *len,
			uint32_t *status)
{
	uint32_t pb, np, p, st = 0;
	uint64_t cap, at;
	uint8_t *reg = NULL;
	struct mflt_hdr h;
	struct mflt_ent *tab = NULL;
	struct pbuild b;
	uint64_t i, from, mmax = 0;
	uint32_t amax = 0, sl, sc;

	memset(&b, 0, sizeof b);
	if (len)
		*len = 0;
	if (r != 8u && r != 16u) {
		st |= KOF_MFLT_B_BAD_ARG;
		goto out;
	}
	for (i = 1; i < n; i++)
		if (keys[i] <= keys[i - 1u]) {
			st |= KOF_MFLT_B_BAD_ARG;
			goto out;
		}
	if (n > 0xfffffff0ull) {
		st |= KOF_MFLT_B_BAD_ARG;
		goto out;
	}
	pb = part_bits_for(n);
	np = 1u << pb;
	cap = kof_mflt_region_bytes(n, r);
	reg = calloc(1, (size_t)cap);
	tab = calloc(np, sizeof *tab);
	if (!reg || !tab) {
		st |= KOF_MFLT_B_NOMEM;
		goto out;
	}
	/* The largest part sizes the scratch. */
	for (p = 0, from = 0; p < np; p++) {
		uint64_t to = from;

		while (to < n && (pb ? (keys[to] >> (32u - pb)) : 0u) == p)
			to++;
		if (to - from > mmax)
			mmax = to - from;
		from = to;
	}
	shape((uint32_t)mmax, &sl, &sc);
	amax = (sc + 2u) << sl;
	b.cnt = malloc((size_t)amax * sizeof *b.cnt);
	b.xh = malloc((size_t)amax * sizeof *b.xh);
	b.order = malloc((size_t)(mmax + 1u) * sizeof *b.order);
	b.which = malloc((size_t)(mmax + 1u));
	b.stack = malloc((size_t)amax * sizeof *b.stack);
	b.fp = malloc((size_t)amax * sizeof *b.fp);
	if (!b.cnt || !b.xh || !b.order || !b.which || !b.stack || !b.fp) {
		st |= KOF_MFLT_B_NOMEM;
		goto out;
	}
	at = KOF_MFLT_HDR_LEN + (uint64_t)np * KOF_MFLT_PART_LEN;
	at = (at + 63u) & ~63ull;
	for (p = 0, from = 0; p < np; p++) {
		uint64_t to = from, seed = 0x5deece66dull * (p + 1u);
		uint32_t m, alen, j;
		uint64_t bytes;

		while (to < n && (pb ? (keys[to] >> (32u - pb)) : 0u) == p)
			to++;
		m = (uint32_t)(to - from);
		tab[p].n_key = m;
		if (m) {
			uint32_t seg_log, seg_count;

			shape(m, &seg_log, &seg_count);
			alen = (seg_count + 2u) << seg_log;
			bytes = (uint64_t)alen * (r / 8u);
			if (at + bytes + 64u > cap) {
				st |= KOF_MFLT_B_NOMEM;
				goto out;
			}
			if (!peel_part(keys + from, m, seg_log, seg_count, &seed, &b, alen)) {
				st |= KOF_MFLT_B_NO_SEED;
				goto out;
			}
			tab[p].seed = seed;
			tab[p].off = at;
			tab[p].seg_log = seg_log;
			tab[p].seg_count = seg_count;
			tab[p].entries = alen;
			if (r == 8u)
				for (j = 0; j < alen; j++)
					reg[at + j] = (uint8_t)b.fp[j];
			else
				memcpy(reg + at, b.fp, (size_t)alen * 2u);
			at += (bytes + 63u) & ~63ull;
		}
		from = to;
	}
	memset(&h, 0, sizeof h);
	h.magic = KOF_MFLT_MAGIC;
	h.version = KOF_MFLT_VERSION;
	h.r = r;
	h.part_bits = pb;
	h.n_part = np;
	h.n_key = n;
	h.region_len = at;
	memcpy(reg, &h, sizeof h);
	memcpy(reg + KOF_MFLT_HDR_LEN, tab, (size_t)np * sizeof *tab);
	if (len)
		*len = at;
	free(tab);
	free(b.cnt); free(b.xh); free(b.order); free(b.which); free(b.stack); free(b.fp);
	if (status)
		*status = 0;
	return reg;
out:
	free(reg);
	free(tab);
	free(b.cnt); free(b.xh); free(b.order); free(b.which); free(b.stack); free(b.fp);
	if (status)
		*status = st;
	return NULL;
}

/* ---- the loader's half ----------------------------------------------------------- */

static uint64_t packed_bytes(uint64_t entries, uint32_t w)
{
	/* Padded to 8 so a part starts on a word, and 8 more for the last load's overhang. */
	return (((entries * w + 7u) / 8u) + 7u) / 8u * 8u + 8u;
}

/* The entries are read at three random places a window: with 4 KiB pages a filter of tens of MB misses the TLB on all
 * three, and the same filter on 2 MiB pages is read in a third of the time (measured). Advice only. */
static void *big_alloc(size_t n)
{
	void *p = NULL;

#if defined(__linux__) && defined(MADV_HUGEPAGE)
	if (n >= (4u << 20) && posix_memalign(&p, 2u << 20, n) == 0) {
		madvise(p, n, MADV_HUGEPAGE);
		return p;
	}
#endif
	return malloc(n);
}

static void why_set(char *why, size_t n, const char *msg)
{
	if (why && n) {
		size_t l = strlen(msg);

		if (l >= n)
			l = n - 1u;
		memcpy(why, msg, l);
		why[l] = 0;
	}
}

static int read_tab(const struct kof_mflt_io *io, struct mflt_hdr *h, struct mflt_ent **tab,
		    char *why, size_t why_len)
{
	uint32_t i;
	uint64_t tab_end, minimum;

	*tab = NULL;
	if (!io || !io->read || io->len < KOF_MFLT_HDR_LEN ||
	    !io->read(io->ctx, 0, h, sizeof *h)) {
		why_set(why, why_len, "the fuse filter header cannot be read");
		return 0;
	}
	if (h->magic != KOF_MFLT_MAGIC || h->version != KOF_MFLT_VERSION ||
	    (h->r != 8u && h->r != 16u) || h->part_bits > KOF_MFLT_MAX_PART_BITS ||
	    h->n_part != (1u << h->part_bits) || h->region_len != io->len) {
		why_set(why, why_len, "the fuse filter header is not one this build reads");
		return 0;
	}
	tab_end = KOF_MFLT_HDR_LEN + (uint64_t)h->n_part * KOF_MFLT_PART_LEN;
	if (tab_end > io->len) {
		why_set(why, why_len, "the fuse filter table does not fit its region");
		return 0;
	}
	*tab = malloc((size_t)h->n_part * sizeof **tab);
	if (!*tab) {
		why_set(why, why_len, "no memory for the fuse filter table");
		return 0;
	}
	if (!io->read(io->ctx, KOF_MFLT_HDR_LEN, *tab, (size_t)h->n_part * sizeof **tab)) {
		why_set(why, why_len, "the fuse filter table cannot be read");
		goto bad;
	}
	minimum = (tab_end + 63u) & ~63ull;
	for (i = 0; i < h->n_part; i++) {
		const struct mflt_ent *e = &(*tab)[i];
		uint64_t bytes;

		if (!e->n_key) {
			if (e->entries || e->seg_count)
				goto bad_tab;
			continue;
		}
		if (e->seg_log > KOF_MFLT_MAX_SEG_LOG || !e->seg_count ||
		    (uint64_t)(e->seg_count + 2u) << e->seg_log != e->entries ||
		    (uint64_t)e->seg_count << e->seg_log > 0xffffffffull ||
		    e->entries < 3u)
			goto bad_tab;
		bytes = (uint64_t)e->entries * (h->r / 8u);
		if (e->off < minimum || e->off % 64u || e->off > io->len || bytes > io->len - e->off)
			goto bad_tab;
		minimum = e->off + bytes;
	}
	return 1;
bad_tab:
	why_set(why, why_len, "the fuse filter table describes a part that does not fit");
bad:
	free(*tab);
	*tab = NULL;
	return 0;
}

int kof_mflt_probe(const struct kof_mflt_io *io, struct kof_mflt_info *info, char *why,
		   size_t why_len)
{
	struct mflt_hdr h;
	struct mflt_ent *tab;
	uint32_t i, wi;
	uint64_t ent = 0, nk = 0, mx = 0, bw[5];

	if (!read_tab(io, &h, &tab, why, why_len))
		return 0;
	for (wi = 0; wi < 5u; wi++)
		bw[wi] = sizeof(struct kof_mflt) + (uint64_t)h.n_part * sizeof(struct mflt_part) + 8u;
	for (i = 0; i < h.n_part; i++) {
		ent += tab[i].entries;
		nk += tab[i].n_key;
		if (tab[i].entries > mx)
			mx = tab[i].entries;
		if (tab[i].entries)
			for (wi = 0; wi < 5u; wi++)
				bw[wi] += packed_bytes(tab[i].entries, 1u << wi);
	}
	free(tab);
	if (nk != h.n_key) {
		why_set(why, why_len, "the fuse filter's parts do not add up to its keys");
		return 0;
	}
	if (info) {
		info->r = h.r;
		info->part_bits = h.part_bits;
		info->n_part = h.n_part;
		info->n_key = h.n_key;
		info->entries = ent;
		info->max_entries = mx;
		memcpy(info->bytes_w, bw, sizeof bw);
	}
	return 1;
}

uint64_t kof_mflt_bytes(const struct kof_mflt_info *info, uint32_t w, uint32_t n_res)
{
	uint32_t wi = w >= 16u ? 4u : w >= 8u ? 3u : w >= 4u ? 2u : w >= 2u ? 1u : 0u;
	uint64_t base = sizeof(struct kof_mflt) + (uint64_t)info->n_part * sizeof(struct mflt_part) + 8u;

	if (!n_res || n_res >= info->n_part)
		return info->bytes_w[wi];
	/* A share of the entries, and one part more for the unevenness. */
	return base + (info->bytes_w[wi] - base) / info->n_part * n_res +
	       packed_bytes(info->max_entries, w);
}

/* Keep the low `w` bits of the entries in src[0, n), which are bytes [rel, rel + n) of a part stored at `r` bits an
 * entry (8: a byte, 16: a u16 whose low byte is the odd one when `low_odd`), into the part's packed array. A chunk
 * may cut a u16 in two, so the position of every byte is kept. */
static void scatter(uint8_t *dst, uint32_t w, uint32_t r, uint64_t low_odd, uint64_t rel, const uint8_t *src,
		    uint64_t n)
{
	uint64_t x;

	if (w == r) {                           /* the common case: the stored width is the kept one */
		memcpy(dst + rel, src, (size_t)n);
		return;
	}
	for (x = 0; x < n; x++) {
		uint64_t byte = rel + x, e = r == 16u ? byte >> 1 : byte;
		uint8_t v = src[x];

		if (r == 16u && (byte & 1u) != low_odd)
			continue;                       /* the high byte of a u16 is dropped: w <= 8 */
		if (w == 8u) {
			dst[e] = v;
		} else {
			uint64_t bit = e * w;

			dst[bit >> 3] |= (uint8_t)((v & ((1u << w) - 1u)) << (bit & 7u));
		}
	}
}

struct kof_mflt *kof_mflt_open(const struct kof_mflt_io *io, uint32_t w, uint32_t n_res,
			       uint32_t crc, char *why, size_t why_len)
{
	struct mflt_hdr h;
	struct mflt_ent *tab = NULL;
	struct kof_mflt *f = NULL;
	uint8_t *chunk = NULL, *mem = NULL;
	uint64_t total = 0, o, at = 0;
	uint32_t i, c = 0;
	const uint64_t CH = 1u << 20;
	const uint16_t one = 1u;
	const uint64_t low_odd = *(const uint8_t *)(const void *)&one ? 0u : 1u;   /* which byte of a u16 is the low one */

	if (!read_tab(io, &h, &tab, why, why_len))
		return NULL;
	if ((w != 1u && w != 2u && w != 4u && w != 8u && w != 16u) || w > h.r) {
		why_set(why, why_len, "the fuse filter cannot be kept at that width");
		goto fail;
	}
	if (!n_res || n_res > h.n_part)
		n_res = h.n_part;
	for (i = 0; i < n_res; i++)
		total += tab[i].entries ? packed_bytes(tab[i].entries, w) : 0u;
	f = calloc(1, sizeof *f);
	mem = big_alloc((size_t)total + 8u);
	chunk = malloc((size_t)CH);
	if (!f || !mem || !chunk)
		goto nomem;
	f->part = calloc(h.n_part, sizeof *f->part);
	if (!f->part)
		goto nomem;
	memset(mem, 0, (size_t)total + 8u);
	f->mem = mem;
	f->w = w;
	f->part_bits = h.part_bits;
	f->n_part = h.n_part;
	f->n_res = n_res;
	f->n_key = h.n_key;
	f->resident = sizeof *f + (uint64_t)h.n_part * sizeof *f->part + total + 8u;

	/* One pass over the whole region, in order, through the CRC; the parts that are kept are cut out of it. */
	for (i = 0; i < h.n_part; i++) {
		f->part[i].seed = tab[i].seed;
		f->part[i].seg_len = 1u << tab[i].seg_log;
		f->part[i].mask = f->part[i].seg_len - 1u;
		f->part[i].scl = tab[i].seg_count << tab[i].seg_log;
		if (i < n_res && tab[i].entries) {
			f->part[i].arr = mem + at;
			at += packed_bytes(tab[i].entries, w);
		} else {
			f->part[i].arr = NULL;
		}
	}
	/* The CRC covers everything, so the read is in order from 0; entries are cut out as the chunks pass. */
	{
		uint32_t cur = 0;
		uint64_t part_start = 0;

		for (o = 0; o < io->len;) {
			uint64_t n = io->len - o < CH ? io->len - o : CH, k;

			if (!io->read(io->ctx, o, chunk, (size_t)n)) {
				why_set(why, why_len, "the fuse filter cannot be read (the file is shorter than it says)");
				goto fail;
			}
			c = kof_crc32_cont(c, chunk, n);
			/* Which bytes of this chunk belong to a kept part's entries. */
			for (k = 0; k < n;) {
				uint64_t pos = o + k;

				while (cur < n_res && (!tab[cur].entries ||
				       pos >= tab[cur].off + (uint64_t)tab[cur].entries * (h.r / 8u))) {
					cur++;
				}
				if (cur >= n_res)
					break;
				part_start = tab[cur].off;
				if (pos < part_start) {
					k += part_start - pos < n - k ? part_start - pos : n - k;
					continue;
				}
				{
					uint64_t end = part_start + (uint64_t)tab[cur].entries * (h.r / 8u);
					uint64_t take = end - pos < n - k ? end - pos : n - k, x;
					uint8_t *dst = (uint8_t *)(uintptr_t)f->part[cur].arr;
					scatter(dst, w, h.r, low_odd, pos - part_start, chunk + k, take);
					k += take;
				}
			}
			o += n;
		}
	}
	if (c != crc) {
		why_set(why, why_len, "the fuse filter does not match its checksum");
		goto fail;
	}
	free(chunk);
	free(tab);
	return f;
nomem:
	why_set(why, why_len, "no memory for the fuse filter");
fail:
	free(chunk);
	free(tab);
	if (f) {
		free(f->part);
		free(f);
	}
	free(mem);
	return NULL;
}

void kof_mflt_close(struct kof_mflt *f)
{
	if (!f)
		return;
	free(f->part);
	free(f->mem);
	free(f);
}

void kof_mflt_stat(const struct kof_mflt *f, struct kof_mflt_stat *o)
{
	memset(o, 0, sizeof *o);
	if (!f)
		return;
	o->w = f->w;
	o->n_part = f->n_part;
	o->n_res = f->n_res;
	o->resident = f->resident;
	o->n_key = f->n_key;
}

static int mem_read(void *ctx, uint64_t off, void *buf, size_t n)
{
	const uint8_t *r = ctx;

	memcpy(buf, r + off, n);
	return 1;
}

struct kof_mflt *kof_mflt_open_mem(const uint8_t *region, uint64_t len, uint32_t w, uint32_t n_res,
				   char *why, size_t why_len)
{
	struct kof_mflt_io io;

	io.read = mem_read;
	io.ctx = (void *)(uintptr_t)region;
	io.len = len;
	return kof_mflt_open(&io, w, n_res, kof_crc32(region, len), why, why_len);
}

int kof_mflt_test(const struct kof_mflt *f, uint32_t vp)
{
	const struct mflt_part *q = &f->part[f->part_bits ? vp >> (32u - f->part_bits) : 0u];
	uint64_t hash;
	uint32_t h0, h1, h2, fp, got;

	if (!q->arr)
		return q->scl != 0;     /* a part left out passes every key; a part with no keys passes none */
	hash = key_hash(vp, q->seed);
	slots(hash, q->scl, q->seg_len, &h0, &h1, &h2);
	fp = fprint(hash);
	switch (f->w) {
	case 8:
		return (uint8_t)(fp ^ q->arr[h0] ^ q->arr[h1] ^ q->arr[h2]) == 0;
	case 16: {
		const uint16_t *a = (const uint16_t *)(const void *)q->arr;

		return (uint16_t)(fp ^ a[h0] ^ a[h1] ^ a[h2]) == 0;
	}
	default: {
		uint32_t w = f->w, m = (1u << w) - 1u;

		uint64_t b0 = (uint64_t)h0 * w, b1 = (uint64_t)h1 * w, b2 = (uint64_t)h2 * w;

		got = ((uint32_t)q->arr[b0 >> 3] >> (b0 & 7u)) ^
		      ((uint32_t)q->arr[b1 >> 3] >> (b1 & 7u)) ^
		      ((uint32_t)q->arr[b2 >> 3] >> (b2 & 7u));
		return ((fp ^ got) & m) == 0;
	}
	}
}

void kof_mflt_pre(const struct kof_mflt *f, uint32_t vp, struct kof_mflt_pre *p)
{
	const struct mflt_part *q = &f->part[f->part_bits ? vp >> (32u - f->part_bits) : 0u];
	uint64_t hash;
	uint32_t w = f->w;

	if (!q->arr) {
		p->arr = NULL;
		p->fp = q->scl != 0;
		return;
	}
	hash = key_hash(vp, q->seed);
	slots(hash, q->scl, q->seg_len, &p->h0, &p->h1, &p->h2);
	p->fp = fprint(hash);
	p->arr = q->arr;
	if (w >= 8u) {
		uint32_t sh = w == 16u ? 1u : 0u;

		MFLT_PREFETCH(q->arr + ((size_t)p->h0 << sh));
		MFLT_PREFETCH(q->arr + ((size_t)p->h1 << sh));
		MFLT_PREFETCH(q->arr + ((size_t)p->h2 << sh));
	} else {
		MFLT_PREFETCH(q->arr + (((uint64_t)p->h0 * w) >> 3));
		MFLT_PREFETCH(q->arr + (((uint64_t)p->h1 * w) >> 3));
		MFLT_PREFETCH(q->arr + (((uint64_t)p->h2 * w) >> 3));
	}
}

int kof_mflt_post(const struct kof_mflt *f, const struct kof_mflt_pre *p)
{
	const uint8_t *a = p->arr;

	if (!a)
		return (int)p->fp;
	switch (f->w) {
	case 8:
		return (uint8_t)(p->fp ^ a[p->h0] ^ a[p->h1] ^ a[p->h2]) == 0;
	case 16: {
		const uint16_t *s = (const uint16_t *)(const void *)a;

		return (uint16_t)(p->fp ^ s[p->h0] ^ s[p->h1] ^ s[p->h2]) == 0;
	}
	default: {
		uint32_t w = f->w, m = (1u << w) - 1u;
		uint64_t b0 = (uint64_t)p->h0 * w, b1 = (uint64_t)p->h1 * w, b2 = (uint64_t)p->h2 * w;
		uint32_t got = ((uint32_t)a[b0 >> 3] >> (b0 & 7u)) ^ ((uint32_t)a[b1 >> 3] >> (b1 & 7u)) ^
			       ((uint32_t)a[b2 >> 3] >> (b2 & 7u));

		return ((p->fp ^ got) & m) == 0;
	}
	}
}

/* ---- the size rule ------------------------------------------------------------------ */

uint64_t kof_mflt_ceiling(uint64_t room, uint64_t cap, uint32_t scanners, uint64_t scan_fixed)
{
	uint64_t reserve, c;

	if (!scanners)
		scanners = KOF_MFLT_SCANNERS;
	if (!scan_fixed)
		scan_fixed = KOF_MFLT_SCAN_FIXED;
	reserve = (uint64_t)scanners * scan_fixed;
	/* A small ledger cannot reserve more than it has: past half of the room the reserve stops growing, so
	 * a 64 MiB engine still gets a filter (a quarter of its other half). */
	if (reserve > room / 2u)
		reserve = room / 2u;
	c = (room - reserve) / KOF_MFLT_SHARE_DEN;
	return cap && c > cap / KOF_MFLT_CAP_DEN ? cap / KOF_MFLT_CAP_DEN : c;
}

/* ---- the bank --------------------------------------------------------------------------- */

struct kof_fbank_xf {
	struct kof_mflt_io   io;
	uint32_t             crc;
	uint64_t             pairs;
	struct kof_mflt_info info;
	uint32_t             n_res;      /* partitions kept (0: all) */
	int                  skip;       /* not one partition fits */
};

struct kof_fbank *kof_fbank_new(uint32_t max_xf)
{
	struct kof_fbank *b = calloc(1, sizeof *b);

	if (!b)
		return NULL;
	b->xf = calloc(max_xf ? max_xf : 1u, sizeof *b->xf);
	b->fx = calloc(max_xf ? max_xf : 1u, sizeof *b->fx);
	if (!b->xf || !b->fx) {
		free(b->xf);
		free(b->fx);
		free(b);
		return NULL;
	}
	b->xf_ok = 1;
	return b;
}

void kof_fbank_free(struct kof_fbank *b)
{
	uint32_t i;

	if (!b)
		return;
	for (i = 0; i < b->nfx; i++)
		kof_mflt_close(b->fx[i]);
	free(b->fx);
	free(b->xf);
	free(b->flt_mem);
	free(b);
}

int kof_fbank_add_xf(struct kof_fbank *b, const struct kof_mflt_io *io, uint32_t crc, uint64_t pairs)
{
	struct kof_fbank_xf *x = &b->xf[b->n_xf];
	char why[160];

	if (!kof_mflt_probe(io, &x->info, why, sizeof why))
		return 0;
	x->io = *io;
	x->crc = crc;
	x->pairs = pairs;
	b->n_xf++;
	b->xf_pairs += pairs;
	return 1;
}

uint64_t kof_fbank_bloom_default(uint64_t n_keys, uint32_t bpk, uint64_t stored_max)
{
	uint64_t bytes = KOF_KIX_FILTER_MIN, want = n_keys * (bpk ? bpk : KOF_KIX_FILTER_BPK) / 8u;

	want -= want / 4u;
	while (bytes < want && (!stored_max || bytes < stored_max))
		bytes <<= 1;
	return bytes;
}

int kof_fbank_bloom_alloc(struct kof_fbank *b, uint64_t bytes)
{
	/* 64-byte lines on 64-byte boundaries, so a window's probe is one cache line; aligned by hand because
	 * aligned_alloc is not on every host this builds on. */
	uint8_t *mem = malloc((size_t)bytes + 64u);

	if (!mem)
		return 0;
	memset(mem, 0, (size_t)bytes + 64u);
	b->flt_mem = mem;
	b->flt = (uint8_t *)(((uintptr_t)mem + 63u) & ~(uintptr_t)63u);
	b->flt_bytes = bytes;
	b->flt_lbits = kof_kix_flt_lbits(bytes);
	return 1;
}

int kof_fbank_bloom_or(struct kof_fbank *b, const struct kof_kix *k)
{
	return kof_kix_filter_or(k, b->flt, b->flt_bytes);
}

int kof_fbank_open_xf(struct kof_fbank *b, uint64_t grant)
{
	uint32_t w, i;
	uint64_t tot = 0;

	if (!b->n_xf)
		return 1;
	/* The widest width every pack has (one stored at 8 bits cannot be kept at 16) whose bytes fit. */
	for (w = KOF_MFLT_R_MAX; w >= 1u; w >>= 1) {
		for (tot = 0, i = 0; i < b->n_xf; i++)
			tot += kof_mflt_bytes(&b->xf[i].info, w < b->xf[i].info.r ? w : b->xf[i].info.r, 0);
		if (tot <= grant)
			break;
	}
	if (!w) {
		/* Not one bit a slot: a share of every pack's partitions, at one bit. */
		for (tot = 0, i = 0; i < b->n_xf; i++)
			tot += kof_mflt_bytes(&b->xf[i].info, 1u, 0);
		w = 1u;
		for (i = 0; i < b->n_xf; i++) {
			b->xf[i].n_res = (uint32_t)((uint64_t)b->xf[i].info.n_part * grant / tot);
			b->xf[i].skip = b->xf[i].n_res == 0;
		}
	}
	for (i = 0; i < b->n_xf; i++) {
		struct kof_fbank_xf *x = &b->xf[i];
		struct kof_mflt_stat st;
		char why[160];

		if (x->skip) {
			b->xf_ok = 0;
			continue;
		}
		b->fx[b->nfx] = kof_mflt_open(&x->io, w < x->info.r ? w : x->info.r, x->n_res, x->crc, why,
					      sizeof why);
		if (!b->fx[b->nfx])
			return 0;
		kof_mflt_stat(b->fx[b->nfx], &st);
		b->nfx++;
		b->fx_bytes += st.resident;
		b->parts += st.n_part;
		b->res += st.n_res;
		b->w = st.w;
	}
	return 1;
}

uint32_t kof_fbank_pass_n(const struct kof_fbank *b, const uint32_t *vp, const uint8_t *flat, uint32_t n,
			  uint32_t *out)
{
	uint32_t i, k = 0;

	if (n > KOF_FBANK_BATCH)
		n = KOF_FBANK_BATCH;
	/* A filter that fits the cache has no misses to overlap: ask one at a time (measured: batching it costs 6-12% below 8 MB and gains 20% above 16 MB, on a 16 MB L3). */
	if (b->flt_bytes + b->fx_bytes <= KOF_FBANK_CACHE) {
		for (i = 0; i < n; i++)
			if (!flat[i] && kof_fbank_pass(b, vp[i]))
				out[k++] = vp[i];
		return k;
	}
	if (b->filtered && b->nfx == 1u && !b->flt) {
		struct kof_mflt_pre pre[KOF_FBANK_BATCH];

		for (i = 0; i < n; i++)
			kof_mflt_pre(b->fx[0], vp[i], &pre[i]);
		for (i = 0; i < n; i++)
			if (kof_mflt_post(b->fx[0], &pre[i]) && !flat[i])
				out[k++] = vp[i];
		return k;
	}
	if (b->filtered && b->flt)
		for (i = 0; i < n; i++)
			MFLT_PREFETCH(b->flt + ((uint64_t)kof_kix_flt_line(vp[i], b->flt_lbits) << 6));
	for (i = 0; i < n; i++)
		if (kof_fbank_pass(b, vp[i]) && !flat[i])
			out[k++] = vp[i];
	return k;
}
