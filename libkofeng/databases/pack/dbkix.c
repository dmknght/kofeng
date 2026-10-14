/*
 * dbkix.c - the block index container: build the trailer, open it, read it. Layout and the
 * reasons for it are in dbkix.h.
 *
 * ONE RULE FOR EVERY READ. Nothing here maps the file. A read is pread, and a file that is
 * shorter than the footer said, or gone, or unreadable, is a short read and a status. The
 * 64 KiB slice check means a bad byte in the body is found by the first read that needs it
 * and is reported by every later one; it is never a wrong credit and never a signal.
 *
 * WHAT THE LOAD READS. The footer (64 bytes), the header with its class table, the
 * directory and the slice CRC table (about 260 KB and 4 bytes a 64 KiB of body), and the
 * filter once, streamed through its CRC. That is O(directory + filter), independent of how
 * many hashes the body holds: 8e3, 8e6 and 3.2e7 hashes read the same ~260 KB plus a filter
 * that is capped (KOF_KIX_FILTER_CAP). The body is read by the scan, a bucket at a time.
 */

#define _GNU_SOURCE

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dbkix.h"
#include "dbcrc.h"
#include <celllysis/mutation.h>   /* KGENOME_MUTATION_MIN_HASH, KGENOME_MUTATION_NORM_COUNT */
#include "../../kofcore/kofcore.h"
#include "../../kofcore/kofplatform.h"

/* Header plus the class table, rounded to the alignment; where the directory starts. */
#define KIX_HDR_LEN    (256u + KOF_KIX_MAX_CLASS * (uint32_t)sizeof(struct kof_kix_class))
#define KIX_PLAUSIBLE_META(nslice) \
	((uint64_t)KIX_HDR_LEN + 4ull * (KOF_KIX_N_DIR + 1u) + 4ull * (nslice) + 3ull * KOF_KIX_ALIGN)
/* The most blocks the entry's reference addresses (block << 8). */
#define KIX_MAX_BLOCK  0x00ffffffu
#define KIX_READ_CHUNK (1u << 20)
#define KIX_PAGE       4096u

/* ---- sources: a file read by pread, or a buffer ------------------------------- */

struct kix_src {
	int            fd;
	const uint8_t *mem;       /* non-NULL: read from memory */
	uint64_t       base, len; /* bytes [base, base + len) of the file, or of the buffer */
};

static int src_read(const struct kix_src *s, uint64_t off, void *out, size_t n)
{
	if (off > s->len || n > s->len - off)
		return 0;
	if (s->mem) {
		memcpy(out, s->mem + s->base + off, n);
		return 1;
	}
	return kof_pread(s->fd, out, n, s->base + off) == n;
}

/* The same read over the sliced reader's own source. */
static int slice_src_read(const struct kof_slices *s, uint64_t off, void *out, size_t n)
{
	if (off > s->src_len || n > s->src_len - off)
		return 0;
	if (s->mem) {
		memcpy(out, s->mem + s->base + off, n);
		return 1;
	}
	return kof_pread(s->fd, out, n, s->base + off) == n;
}

struct kof_kix {
	struct kix_src       idx, blk, pool;
	struct kof_kix_hdr   h;
	struct kof_kix_class cls[KOF_KIX_MAX_CLASS];
	uint32_t            *dir;     /* N_DIR + 1 */
	struct kof_slices    sl;      /* the body, one CRC per 64 KiB */
	uint8_t             *image;   /* owned, for a memory index */
	uint32_t             n_blk, n_pool;
	uint64_t             resident;
	int                  in_memory;
};

static uint64_t round_up(uint64_t v, uint64_t a)
{
	return (v + a - 1u) / a * a;
}

static void why_set(char *why, size_t n, const char *msg)
{
	if (why && n)
		snprintf(why, n, "%s", msg);
}

/* ---- building ----------------------------------------------------------------- */

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y;
}

/* The classes of the blocks, and each block's: the (mask, norm, side) a window's call is
 * matched against. 0 and a status when there are more than a byte can name. */
static int make_classes(const struct kof_kix_build_in *in, struct kof_kix_class *cls,
			uint32_t *n_class, uint8_t *of_block)
{
	uint32_t i, j, n = 0, last = 0;

	for (i = 0; i < in->n_blk; i++) {
		const struct kof_mutation_block *b = &in->blk[i];

		if (n && cls[last].mask == b->scan_mask && cls[last].norm == b->norm &&
		    cls[last].side == b->side) {
			of_block[i] = (uint8_t)last;
			continue;
		}
		for (j = 0; j < n; j++)
			if (cls[j].mask == b->scan_mask && cls[j].norm == b->norm &&
			    cls[j].side == b->side)
				break;
		if (j == n) {
			if (n == KOF_KIX_MAX_CLASS)
				return 0;
			cls[n].mask = b->scan_mask;
			cls[n].norm = b->norm;
			cls[n].side = b->side;
			cls[n].pad = 0;
			n++;
		}
		last = j;
		of_block[i] = (uint8_t)j;
	}
	*n_class = n;
	return 1;
}

uint64_t kof_kix_filter_default(uint64_t n_keys, uint32_t bpk)
{
	uint64_t bytes = KOF_KIX_FILTER_MIN, want = n_keys * (bpk ? bpk : KOF_KIX_FILTER_BPK) / 8u;

	want -= want / 4u;
	while (bytes < want && bytes < KOF_KIX_FILTER_CAP)
		bytes <<= 1;
	return bytes;
}

static uint64_t filter_size(uint64_t n_key, uint32_t bpk, uint64_t forced)
{
	uint64_t bytes = KOF_KIX_FILTER_MIN;

	if (!forced)
		return kof_kix_filter_default(n_key, bpk);
	/* The caller's, rounded up to what a filter can be. */
	while (bytes < forced && bytes < ((uint64_t)1 << 40))
		bytes <<= 1;
	return bytes;
}

/* Where everything goes, for `np` entries and a filter of `fbytes`: the one place the layout is computed, by
 * the writer and by whoever needs to know what an image will cost before building it. */
struct kix_layout {
	uint64_t off_dir, off_crc, off_body, off_flt, off_xf, total;
	uint32_t n_slice;
};

static void kix_layout(uint64_t np, uint64_t fbytes, uint64_t xbytes, struct kix_layout *l)
{
	l->n_slice = (uint32_t)((np * KOF_KIX_ENTRY + KOF_KIX_SLICE - 1u) >> KOF_KIX_SLICE_SHIFT);
	l->off_dir = round_up(KIX_HDR_LEN, KOF_KIX_ALIGN);
	l->off_crc = l->off_dir + round_up(4ull * (KOF_KIX_N_DIR + 1u), KOF_KIX_ALIGN);
	l->off_body = round_up(l->off_crc + 4ull * l->n_slice, KOF_KIX_ALIGN);
	l->off_flt = l->off_body + round_up(np * KOF_KIX_ENTRY, KOF_KIX_ALIGN);
	l->off_xf = l->off_flt + fbytes;
	l->total = l->off_xf + xbytes + sizeof(struct kof_kix_footer);
}

uint64_t kof_kix_image_bytes(uint64_t n_pair, uint64_t filter_bytes)
{
	struct kix_layout l;

	kix_layout(n_pair, filter_bytes, 0, &l);
	return l.total;
}

/* Put the bucket's entries in order of (lo16, ref, cls) and count its distinct values and its
 * longest run. `col` is the bucket in the body: lo16[n] | ref[n] | cls[n]. */
static void sort_bucket(uint8_t *col, uint32_t n, uint64_t *tmp, uint32_t *n_key,
			uint32_t *max_run)
{
	/* A bucket starts at 7 bytes an entry from the body, so its columns are at ANY alignment:
	 * every load and store below is a memcpy. */
	uint8_t *rf = col + 2ull * n, *cl = col + 6ull * n;
	uint32_t i, run = 1;
	uint16_t prev = 0;

	for (i = 0; i < n; i++) {
		uint32_t r;
		uint16_t l;

		memcpy(&l, col + 2ull * i, 2);
		memcpy(&r, rf + 4ull * i, 4);
		tmp[i] = ((uint64_t)l << 40) | ((uint64_t)r << 8) | cl[i];
	}
	if (n <= 24) {
		for (i = 1; i < n; i++) {
			uint64_t x = tmp[i];
			uint32_t j = i;

			while (j && tmp[j - 1] > x) {
				tmp[j] = tmp[j - 1];
				j--;
			}
			tmp[j] = x;
		}
	} else {
		qsort(tmp, n, sizeof *tmp, cmp_u64);
	}
	for (i = 0; i < n; i++) {
		uint32_t r = (uint32_t)(tmp[i] >> 8);
		uint16_t l = (uint16_t)(tmp[i] >> 40);

		memcpy(col + 2ull * i, &l, 2);
		memcpy(rf + 4ull * i, &r, 4);
		cl[i] = (uint8_t)tmp[i];
	}
	if (n)
		*n_key += 1u;
	for (i = 0; i < n; i++) {
		uint16_t l = (uint16_t)(tmp[i] >> 40);

		if (i && l != prev) {
			(*n_key)++;
			run = 1;
		} else if (i && ++run > *max_run) {
			*max_run = run;
		}
		prev = l;
	}
	if (*max_run < 1u && n)
		*max_run = 1u;
}

static int validate_blocks(const struct kof_kix_build_in *in, uint64_t *np, uint32_t *status)
{
	uint32_t i;

	*np = 0;
	if ((in->n_blk && !in->blk) || (in->n_pool && !in->pool)) {
		*status |= KOF_KIX_B_BAD_BLOCK;
		return 0;
	}
	if (in->n_blk > KIX_MAX_BLOCK) {
		*status |= KOF_KIX_B_TOO_MANY_BLOCKS;
		return 0;
	}
	for (i = 0; i < in->n_blk; i++) {
		const struct kof_mutation_block *b = &in->blk[i];

		if (b->n_hash < KGENOME_MUTATION_MIN_HASH || b->n_hash > KOF_MUTATION_MAX_HASH ||
		    b->first_hash > in->n_pool || b->n_hash > in->n_pool - b->first_hash ||
		    b->norm >= KGENOME_MUTATION_NORM_COUNT) {
			*status |= KOF_KIX_B_BAD_BLOCK;
			return 0;
		}
		*np += b->n_hash;
	}
	if (*np > 0xfffffffeu) {
		*status |= KOF_KIX_B_TOO_BIG;
		return 0;
	}
	return 1;
}

uint8_t *kof_kix_make(const struct kof_kix_build_in *in, uint64_t trailer_off,
		      uint64_t old_len, uint32_t old_crc, uint64_t *out_len,
		      struct kof_kix_build_res *res)
{
	struct kof_kix_build_res local;
	struct kof_kix_hdr h;
	struct kof_kix_footer ft;
	struct kof_kix_class cls[KOF_KIX_MAX_CLASS];
	uint8_t *of_block = NULL, *img = NULL, *body;
	uint32_t *dir = NULL, *fill = NULL;
	uint64_t *tmp = NULL;
	uint64_t np, meta_len, off_dir, off_crc, off_body, off_flt, off_xf, fbytes, xf_bytes, total;
	uint32_t status = 0, n_class = 0, i, j, k, max_bucket = 0, n_key = 0, max_run = 0;
	uint32_t n_slice, top = 0, lbits;

	if (!res)
		res = &local;
	memset(res, 0, sizeof *res);
	if (out_len)
		*out_len = 0;
	if (!validate_blocks(in, &np, &status))
		goto refuse;
	of_block = malloc(in->n_blk ? in->n_blk : 1u);
	if (!of_block) {
		status |= KOF_KIX_B_NOMEM;
		goto refuse;
	}
	if (!make_classes(in, cls, &n_class, of_block)) {
		status |= KOF_KIX_B_TOO_MANY_CLASSES;
		goto refuse;
	}

	/* The sizes, before any big allocation: the caller's allowance is charged against the image, the
	 * directory's two counters (KOF_KIX_SCRATCH) and, once the buckets are counted, the sort's scratch. */
	/* The filter is sized from the entries, not the distinct values, so the image has its final size before
	 * the sort that counts them (no second copy of a 200 MB body). A database that repeats hashes across
	 * blocks gets a filter a little larger than it needed, which is at most KOF_KIX_FILTER_CAP. */
	xf_bytes = in->xf ? in->xf_bytes : 0;
	if (in->xf && (in->xf_kind != KOF_KIX_XF_FUSE || !xf_bytes || xf_bytes % KOF_KIX_ALIGN)) {
		status |= KOF_KIX_B_BAD_BLOCK;
		goto refuse;
	}
	fbytes = xf_bytes ? 0 : filter_size(np, in->filter_bpk, in->filter_bytes);
	{
		struct kix_layout l;

		kix_layout(np, fbytes, xf_bytes, &l);
		n_slice = l.n_slice; off_dir = l.off_dir; off_crc = l.off_crc; off_body = l.off_body;
		off_flt = l.off_flt; off_xf = l.off_xf; total = l.total;
	}
	meta_len = off_body;
	res->bytes = total;
	if (in->max_bytes && total + KOF_KIX_SCRATCH > in->max_bytes) {
		status |= KOF_KIX_B_OVER_BUDGET;
		goto refuse;
	}

	dir = calloc((size_t)KOF_KIX_N_DIR + 1u, sizeof *dir);
	fill = calloc(KOF_KIX_N_DIR, sizeof *fill);
	if (!dir || !fill) {
		status |= KOF_KIX_B_NOMEM;
		goto refuse;
	}
	for (i = 0; i < in->n_blk; i++)
		for (j = 0; j < in->blk[i].n_hash; j++) {
			uint32_t v = in->pool[in->blk[i].first_hash + j];

			dir[((v * KOF_KIX_MULT) >> (32u - KOF_KIX_DIR_BITS)) + 1u]++;
			if (v > top)
				top = v;
		}
	for (k = 0; k < KOF_KIX_N_DIR; k++) {
		if (dir[k + 1u] > max_bucket)
			max_bucket = dir[k + 1u];
		dir[k + 1u] += dir[k];
	}
	if (in->max_bytes && total + (uint64_t)max_bucket * 8u + KOF_KIX_SCRATCH > in->max_bytes) {
		status |= KOF_KIX_B_OVER_BUDGET;
		res->bytes = total + (uint64_t)max_bucket * 8u;
		goto refuse;
	}
	img = calloc(1, (size_t)total);
	tmp = malloc((size_t)(max_bucket ? max_bucket : 1u) * sizeof *tmp);
	if (!img || !tmp) {
		status |= KOF_KIX_B_NOMEM;
		goto refuse;
	}
	body = img + off_body;

	/* Place every entry in its bucket. Blocks are visited in order and slots in order,
	 * so within a bucket the refs go in ascending already; sort_bucket makes the order
	 * explicit rather than depending on that. */
	for (i = 0; i < in->n_blk; i++)
		for (j = 0; j < in->blk[i].n_hash; j++) {
			uint32_t v = in->pool[in->blk[i].first_hash + j];
			uint32_t vp = v * KOF_KIX_MULT, b = vp >> (32u - KOF_KIX_DIR_BITS);
			uint32_t n = dir[b + 1u] - dir[b], at = fill[b]++;
			uint8_t *col = body + (uint64_t)KOF_KIX_ENTRY * dir[b];
			uint16_t lo = (uint16_t)(vp & 0xffffu);
			uint32_t ref = (i << 8) | j;

			memcpy(col + 2ull * at, &lo, 2);
			memcpy(col + 2ull * n + 4ull * at, &ref, 4);
			col[6ull * n + at] = of_block[i];
		}
	for (k = 0; k < KOF_KIX_N_DIR; k++) {
		uint32_t n = dir[k + 1u] - dir[k];

		if (n)
			sort_bucket(body + (uint64_t)KOF_KIX_ENTRY * dir[k], n, tmp, &n_key, &max_run);
	}
	free(tmp);
	tmp = NULL;
	free(fill);
	fill = NULL;

	/* The filter and the footer follow the body, in the image allocated above. */
	if (fbytes) {
		lbits = kof_kix_flt_lbits(fbytes);
		for (i = 0; i < in->n_blk; i++)
			for (j = 0; j < in->blk[i].n_hash; j++)
				kof_kix_flt_add(img + off_flt, lbits, in->pool[in->blk[i].first_hash + j] * KOF_KIX_MULT);
	}
	if (xf_bytes)
		memcpy(img + off_xf, in->xf, (size_t)xf_bytes);

	memset(&h, 0, sizeof h);
	h.magic = KOF_KIX_MAGIC_HDR;
	h.version = xf_bytes ? KOF_KIX_VERSION_XF : KOF_KIX_VERSION;
	h.n_block = in->n_blk;
	h.n_class = n_class;
	h.n_pair = np;
	h.n_key = n_key;
	h.max_mult = max_run;
	h.top = top;
	h.mult = KOF_KIX_MULT;
	h.dir_bits = KOF_KIX_DIR_BITS;
	h.slice_shift = KOF_KIX_SLICE_SHIFT;
	h.filter_k = KOF_KIX_FILTER_K;
	h.entry = KOF_KIX_ENTRY;
	h.filter_bytes = fbytes;
	h.filter_crc = fbytes ? kof_crc32(img + off_flt, fbytes) : 0;
	h.n_slice = n_slice;
	h.off_class = 256u;
	h.off_dir = off_dir;
	h.off_crc = off_crc;
	h.off_body = off_body;
	h.body_len = np * KOF_KIX_ENTRY;
	h.off_filter = off_flt;
	if (xf_bytes) {
		h.off_xf = off_xf;
		h.xf_bytes = xf_bytes;
		h.xf_crc = kof_crc32(in->xf, xf_bytes);
		h.xf_kind = in->xf_kind;
	}
	memcpy(img, &h, sizeof h);
	memcpy(img + 256u, cls, (size_t)n_class * sizeof cls[0]);
	memcpy(img + off_dir, dir, 4ull * (KOF_KIX_N_DIR + 1u));
	for (i = 0; i < n_slice; i++) {
		uint64_t from = (uint64_t)i << KOF_KIX_SLICE_SHIFT;
		uint64_t len = h.body_len - from < KOF_KIX_SLICE ? h.body_len - from : KOF_KIX_SLICE;
		uint32_t c = kof_crc32(body + from, len);

		memcpy(img + off_crc + 4ull * i, &c, 4);
	}
	memset(&ft, 0, sizeof ft);
	ft.magic = KOF_KIX_MAGIC_FOOT;
	ft.version = h.version;
	ft.trailer_off = trailer_off;
	ft.meta_len = meta_len;
	ft.body_len = h.body_len;
	ft.filter_off = off_flt;
	ft.old_len = old_len;
	ft.old_crc = old_crc;
	ft.meta_crc = kof_crc32(img, meta_len);
	ft.n_item = in->n_blk;
	ft.footer_crc = kof_crc32(&ft, sizeof ft - 4u);
	memcpy(img + off_xf + xf_bytes, &ft, sizeof ft);

	res->n_pair = (uint32_t)np;
	res->n_key = n_key;
	res->max_mult = max_run;
	res->n_class = n_class;
	res->filter_bytes = fbytes;
	res->xf_bytes = xf_bytes;
	res->bytes = total;
	if (out_len)
		*out_len = total;
	free(dir);
	free(of_block);
	return img;

refuse:
	res->status = status;
	free(img);
	free(tmp);
	free(fill);
	free(dir);
	free(of_block);
	return NULL;
}

void kof_kix_seal(uint8_t *image, uint64_t len, uint32_t old_crc)
{
	struct kof_kix_footer ft;

	if (len < sizeof ft)
		return;
	memcpy(&ft, image + len - sizeof ft, sizeof ft);
	ft.old_crc = old_crc;
	ft.footer_crc = kof_crc32(&ft, sizeof ft - 4u);
	memcpy(image + len - sizeof ft, &ft, sizeof ft);
}

/* ---- opening ------------------------------------------------------------------ */

int kof_kix_probe(int fd, uint64_t size, struct kof_kix_footer *ft)
{
	struct kof_kix_footer f;

	if (size < sizeof f + 64u)
		return 0;
	if (kof_pread(fd, &f, sizeof f, size - sizeof f) != sizeof f)
		return 0;
	if (f.magic != KOF_KIX_MAGIC_FOOT ||
	    (f.version != KOF_KIX_VERSION && f.version != KOF_KIX_VERSION_XF) ||
	    kof_crc32(&f, sizeof f - 4u) != f.footer_crc)
		return 0;
	/* Where it says things are must be inside the file, in the order they were written. */
	if (f.trailer_off % KOF_KIX_ALIGN || f.old_len > f.trailer_off ||
	    f.trailer_off > size || f.meta_len > size - f.trailer_off ||
	    f.body_len > size - f.trailer_off - f.meta_len ||
	    f.filter_off < f.meta_len + f.body_len ||
	    f.filter_off > size - f.trailer_off - sizeof f)
		return 0;
	if (ft)
		*ft = f;
	return 1;
}

/* ---- the pattern part and the tail ----------------------------------------------- */

/* The pattern part's footer, checked against where its part ends (`end`, a file offset). The part is
 * [trailer_off, end): the table (body_len bytes), padding to 64, the slice CRC table, padding to 64, the
 * footer - so every length is a function of body_len and a footer that says otherwise is refused. */
static int pix_foot_valid(const struct kof_kix_footer *f, uint64_t end)
{
	uint64_t n_slice;

	if (f->magic != KOF_PIX_MAGIC_FOOT || f->version != KOF_KIX_VERSION ||
	    kof_crc32(f, sizeof *f - 4u) != f->footer_crc)
		return 0;
	if (f->trailer_off % KOF_KIX_ALIGN || f->old_len > f->trailer_off ||
	    end < sizeof *f || f->trailer_off > end - sizeof *f || f->body_len == 0 ||
	    f->body_len > (uint64_t)0xfffffffeu * KOF_KIX_ENTRY)
		return 0;
	n_slice = (f->body_len + KOF_KIX_SLICE - 1u) >> KOF_KIX_SLICE_SHIFT;
	return f->filter_off == round_up(f->body_len, KOF_KIX_ALIGN) &&
	       f->meta_len == round_up(4u * n_slice, KOF_KIX_ALIGN) &&
	       f->filter_off + f->meta_len + sizeof *f == end - f->trailer_off;
}

static int foot_read(int fd, uint64_t end, struct kof_kix_footer *f)
{
	return end >= sizeof *f && kof_pread(fd, f, sizeof *f, end - sizeof *f) == sizeof *f;
}

int kof_tail_probe(int fd, uint64_t size, struct kof_tail *t)
{
	struct kof_kix_footer f, g;
	uint64_t end;

	memset(t, 0, sizeof *t);
	if (size < 2u * sizeof f || !foot_read(fd, size, &f))
		return 0;
	if (f.magic == KOF_KIX_MAGIC_FOOT) {
		if (!kof_kix_probe(fd, size, &t->kix))
			return 0;
		t->has_kix = 1;
		t->old_len = t->kix.old_len;
		t->old_crc = t->kix.old_crc;
		end = t->kix.trailer_off;
		/* A pattern part, when there is one, ends exactly where the block index starts. */
		if (end > t->kix.old_len && foot_read(fd, end, &g) && pix_foot_valid(&g, end) &&
		    g.old_len == t->kix.old_len && g.old_crc == t->kix.old_crc &&
		    g.trailer_off >= t->kix.old_len) {
			t->pix = g;
			t->has_pix = 1;
		}
		return 1;
	}
	if (f.magic == KOF_PIX_MAGIC_FOOT && pix_foot_valid(&f, size)) {
		t->pix = f;
		t->has_pix = 1;
		t->old_len = f.old_len;
		t->old_crc = f.old_crc;
		return 1;
	}
	return 0;
}

uint8_t *kof_pix_make(const uint8_t *sec, uint64_t sec_len, uint32_t n_item, uint64_t at,
		      uint64_t old_len, uint32_t old_crc, uint64_t *len)
{
	struct kof_kix_footer ft;
	uint64_t n_slice, crc_off, crc_len, total, i;
	uint8_t *img;

	if (len)
		*len = 0;
	if (!sec || !sec_len || at % KOF_KIX_ALIGN || old_len > at ||
	    sec_len > (uint64_t)0xfffffffeu * KOF_KIX_ENTRY)
		return NULL;
	n_slice = (sec_len + KOF_KIX_SLICE - 1u) >> KOF_KIX_SLICE_SHIFT;
	crc_off = round_up(sec_len, KOF_KIX_ALIGN);
	crc_len = round_up(4u * n_slice, KOF_KIX_ALIGN);
	total = crc_off + crc_len + sizeof ft;
	if (total > (uint64_t)((size_t)-1) / 2u)
		return NULL;
	img = calloc(1, (size_t)total);
	if (!img)
		return NULL;
	memcpy(img, sec, (size_t)sec_len);
	for (i = 0; i < n_slice; i++) {
		uint64_t from = i << KOF_KIX_SLICE_SHIFT;
		uint64_t n = sec_len - from < KOF_KIX_SLICE ? sec_len - from : KOF_KIX_SLICE;
		uint32_t c = kof_crc32(sec + from, n);

		memcpy(img + crc_off + 4u * i, &c, 4);
	}
	memset(&ft, 0, sizeof ft);
	ft.magic = KOF_PIX_MAGIC_FOOT;
	ft.version = KOF_KIX_VERSION;
	ft.trailer_off = at;
	ft.meta_len = crc_len;
	ft.body_len = sec_len;
	ft.filter_off = crc_off;
	ft.old_len = old_len;
	ft.old_crc = old_crc;
	ft.meta_crc = kof_crc32(img + crc_off, crc_len);
	ft.n_item = n_item;
	ft.footer_crc = kof_crc32(&ft, sizeof ft - 4u);
	memcpy(img + total - sizeof ft, &ft, sizeof ft);
	if (len)
		*len = total;
	return img;
}

int kof_pix_open_file(int fd, uint64_t file_size, const struct kof_kix_footer *ft,
		      struct kof_slices *sl, char *why, size_t why_len)
{
	struct kof_slices_req rq;
	uint8_t *tab;
	uint64_t part_len;

	if (!ft || ft->magic != KOF_PIX_MAGIC_FOOT || ft->trailer_off > file_size) {
		why_set(why, why_len, "no pattern part to open");
		return 0;
	}
	part_len = file_size - ft->trailer_off;
	if (ft->filter_off > part_len || ft->meta_len > part_len - ft->filter_off ||
	    ft->meta_len > ((uint64_t)1 << 28)) {
		why_set(why, why_len, "pattern part: the slice table does not fit its place");
		return 0;
	}
	tab = malloc((size_t)(ft->meta_len ? ft->meta_len : 1u));
	if (!tab) {
		why_set(why, why_len, "no memory for the pattern part's slice table");
		return 0;
	}
	if (kof_pread(fd, tab, (size_t)ft->meta_len, ft->trailer_off + ft->filter_off) != ft->meta_len) {
		why_set(why, why_len, "pattern part: the slice table cannot be read (the file is shorter than it says)");
		free(tab);
		return 0;
	}
	if (kof_crc32_fast_cont(0, tab, ft->meta_len) != ft->meta_crc) {
		why_set(why, why_len, "pattern part: the slice table does not match its checksum");
		free(tab);
		return 0;
	}
	memset(&rq, 0, sizeof rq);
	rq.fd = fd;
	rq.base = ft->trailer_off;
	rq.src_len = part_len;
	rq.body_off = 0;
	rq.body_len = ft->body_len;
	rq.crc = (const uint32_t *)(const void *)tab;
	if (!kof_slices_init(sl, &rq)) {
		why_set(why, why_len, "no memory for the pattern part's slices");
		free(tab);
		return 0;
	}
	free(tab);
	return 1;
}

static void kix_free(struct kof_kix *k)
{
	if (!k)
		return;
	free(k->dir);
	kof_slices_done(&k->sl);
	free(k->image);
	free(k);
}

void kof_kix_close(struct kof_kix *k)
{
	kix_free(k);
}

/* The header and what hangs off it, checked, from `meta` (the bytes [0, meta_len) of the
 * trailer). Everything the scan reads without a further check is settled here. 0 with `why`. */
static int kix_parse(struct kof_kix *k, const uint8_t *meta, uint64_t meta_len,
		     uint64_t trailer_len, char *why, size_t why_len)
{
	const struct kof_kix_hdr *h = &k->h;
	uint64_t i, off_crc_len;
	uint32_t n_slice;

	memcpy(&k->h, meta, sizeof k->h);
	if (h->magic != KOF_KIX_MAGIC_HDR ||
	    (h->version != KOF_KIX_VERSION && h->version != KOF_KIX_VERSION_XF)) {
		why_set(why, why_len, "not an index header this build reads");
		return 0;
	}
	if (h->entry != KOF_KIX_ENTRY || h->dir_bits != KOF_KIX_DIR_BITS ||
	    h->slice_shift != KOF_KIX_SLICE_SHIFT || h->filter_k != KOF_KIX_FILTER_K ||
	    !(h->mult & 1u)) {
		why_set(why, why_len, "index parameters this build does not read");
		return 0;
	}
	if (h->n_pair > 0xfffffffeu || h->body_len != h->n_pair * KOF_KIX_ENTRY ||
	    h->n_class > KOF_KIX_MAX_CLASS || h->n_block > KIX_MAX_BLOCK) {
		why_set(why, why_len, "index counts do not agree");
		return 0;
	}
	n_slice = (uint32_t)((h->body_len + KOF_KIX_SLICE - 1u) >> KOF_KIX_SLICE_SHIFT);
	off_crc_len = round_up(4ull * (KOF_KIX_N_DIR + 1u), KOF_KIX_ALIGN);
	if (h->n_slice != n_slice || h->off_class != 256u ||
	    h->off_dir != round_up(KIX_HDR_LEN, KOF_KIX_ALIGN) ||
	    h->off_crc != h->off_dir + off_crc_len ||
	    h->off_body != round_up(h->off_crc + 4ull * n_slice, KOF_KIX_ALIGN) ||
	    h->off_body != meta_len ||
	    h->off_filter != h->off_body + round_up(h->body_len, KOF_KIX_ALIGN)) {
		why_set(why, why_len, "index offsets do not agree");
		return 0;
	}
	if (h->version == KOF_KIX_VERSION_XF) {
		/* The extension is the filter: no bloom filter, a region where it would be. */
		if (h->filter_bytes || h->filter_crc || h->xf_kind != KOF_KIX_XF_FUSE || !h->xf_bytes ||
		    h->xf_bytes % KOF_KIX_ALIGN || h->off_xf != h->off_filter ||
		    h->xf_bytes > trailer_len || h->off_xf + h->xf_bytes + sizeof(struct kof_kix_footer) != trailer_len) {
			why_set(why, why_len, "index extension does not fit its place");
			return 0;
		}
	} else {
		if (h->off_xf || h->xf_bytes || h->xf_crc || h->xf_kind) {
			why_set(why, why_len, "index extension in a version that has none");
			return 0;
		}
		if (h->filter_bytes < KOF_KIX_FILTER_MIN || (h->filter_bytes & (h->filter_bytes - 1u)) ||
		    h->filter_bytes > ((uint64_t)1 << 40) ||
		    h->off_filter + h->filter_bytes + sizeof(struct kof_kix_footer) != trailer_len) {
			why_set(why, why_len, "index filter does not fit its place");
			return 0;
		}
	}
	memcpy(k->cls, meta + h->off_class, (size_t)h->n_class * sizeof k->cls[0]);
	for (i = 0; i < h->n_class; i++)
		if (k->cls[i].norm >= KGENOME_MUTATION_NORM_COUNT) {
			why_set(why, why_len, "index class names a normaliser that does not exist");
			return 0;
		}
	k->dir = malloc(((size_t)KOF_KIX_N_DIR + 1u) * sizeof *k->dir);
	if (!k->dir) {
		why_set(why, why_len, "no memory for the index directory");
		return 0;
	}
	memcpy(k->dir, meta + h->off_dir, ((size_t)KOF_KIX_N_DIR + 1u) * sizeof *k->dir);
	{
		struct kof_slices_req rq;

		memset(&rq, 0, sizeof rq);
		rq.fd = k->idx.fd;
		rq.mem = k->idx.mem;
		rq.base = k->idx.base;
		rq.src_len = k->idx.len;
		rq.body_off = h->off_body;
		rq.body_len = h->body_len;
		rq.crc = (const uint32_t *)(const void *)(meta + h->off_crc);
		rq.verified = k->in_memory;       /* what was just built is not checked again per slice */
		if (!kof_slices_init(&k->sl, &rq)) {
			why_set(why, why_len, "no memory for the index slice table");
			return 0;
		}
	}
	/* The directory is read as an offset with no check on the scan path. */
	if (k->dir[0] != 0 || k->dir[KOF_KIX_N_DIR] != (uint32_t)h->n_pair) {
		why_set(why, why_len, "index directory does not span its entries");
		return 0;
	}
	for (i = 0; i < KOF_KIX_N_DIR; i++)
		if (k->dir[i] > k->dir[i + 1u]) {
			why_set(why, why_len, "index directory does not climb");
			return 0;
		}
	k->resident = sizeof *k + ((uint64_t)KOF_KIX_N_DIR + 1u) * 4u + 5ull * n_slice;
	return 1;
}

struct kof_kix *kof_kix_open_file(const struct kof_kix_loc *loc,
				  const struct kof_kix_footer *ft,
				  char *why, size_t why_len)
{
	struct kof_kix *k;
	uint8_t *meta = NULL, *chunk = NULL;
	uint64_t trailer_len, o;
	uint32_t c;

	if (!loc || !ft || ft->trailer_off > loc->file_size) {
		why_set(why, why_len, "no trailer to open");
		return NULL;
	}
	trailer_len = loc->file_size - ft->trailer_off;
	if (ft->meta_len < KIX_HDR_LEN || ft->meta_len > trailer_len ||
	    ft->meta_len > KIX_PLAUSIBLE_META(((uint64_t)0xfffffffeu * KOF_KIX_ENTRY >> KOF_KIX_SLICE_SHIFT) + 1u)) {
		why_set(why, why_len, "index header length is not plausible");
		return NULL;
	}
	k = calloc(1, sizeof *k);
	if (!k) {
		why_set(why, why_len, "no memory for the index");
		return NULL;
	}
	k->idx.fd = loc->fd;
	k->idx.base = ft->trailer_off;
	k->idx.len = trailer_len;
	k->blk.fd = loc->fd;
	k->blk.base = loc->blk_off;
	k->blk.len = (uint64_t)loc->n_blk * sizeof(struct kof_mutation_block);
	k->pool.fd = loc->fd;
	k->pool.base = loc->pool_off;
	k->pool.len = (uint64_t)loc->n_pool * 4u;
	k->n_blk = loc->n_blk;
	k->n_pool = loc->n_pool;

	meta = malloc((size_t)ft->meta_len);
	if (!meta) {
		why_set(why, why_len, "no memory for the index header");
		goto fail;
	}
	if (!src_read(&k->idx, 0, meta, (size_t)ft->meta_len)) {
		why_set(why, why_len, "the index header cannot be read (the file is shorter than it says)");
		goto fail;
	}
	if (kof_crc32_fast_cont(0, meta, ft->meta_len) != ft->meta_crc) {
		why_set(why, why_len, "the index header, directory or slice table does not match its checksum");
		goto fail;
	}
	if (!kix_parse(k, meta, ft->meta_len, trailer_len, why, why_len))
		goto fail;
	if (k->h.version != ft->version || k->h.n_block != loc->n_blk || k->h.n_block != ft->n_item ||
	    k->h.off_filter != ft->filter_off || k->h.body_len != ft->body_len) {
		why_set(why, why_len, "the index and the pack disagree about the blocks");
		goto fail;
	}
	free(meta);
	meta = NULL;

	/* The filter, once, through its CRC. It is not kept: the loader asks for it folded to
	 * the size the engine's ledger grants (kof_kix_filter_or). */
	chunk = malloc(KIX_READ_CHUNK);
	if (!chunk) {
		why_set(why, why_len, "no memory to check the index filter");
		goto fail;
	}
	for (c = 0, o = 0; o < k->h.filter_bytes;) {
		uint64_t n = k->h.filter_bytes - o < KIX_READ_CHUNK ? k->h.filter_bytes - o : KIX_READ_CHUNK;

		if (!src_read(&k->idx, k->h.off_filter + o, chunk, (size_t)n)) {
			why_set(why, why_len, "the index filter cannot be read (the file is shorter than it says)");
			goto fail;
		}
		c = kof_crc32_fast_cont(c, chunk, n);
		o += n;
	}
	if (c != k->h.filter_crc) {
		why_set(why, why_len, "the index filter does not match its checksum");
		goto fail;
	}
	free(chunk);
	return k;

fail:
	free(meta);
	free(chunk);
	kix_free(k);
	return NULL;
}

struct kof_kix *kof_kix_open_mem(uint8_t *image, uint64_t len,
				 const struct kof_mutation_block *blk, uint32_t n_blk,
				 const uint32_t *pool, uint32_t n_pool,
				 char *why, size_t why_len)
{
	struct kof_kix_footer ft;
	struct kof_kix *k;

	if (!image || len < sizeof ft) {
		why_set(why, why_len, "no index image");
		free(image);
		return NULL;
	}
	memcpy(&ft, image + len - sizeof ft, sizeof ft);
	k = calloc(1, sizeof *k);
	if (!k) {
		why_set(why, why_len, "no memory for the index");
		free(image);
		return NULL;
	}
	k->image = image;
	k->in_memory = 1;
	k->idx.mem = image;
	k->idx.len = len;
	k->blk.mem = (const uint8_t *)blk;
	k->blk.len = (uint64_t)n_blk * sizeof *blk;
	k->pool.mem = (const uint8_t *)pool;
	k->pool.len = (uint64_t)n_pool * 4u;
	k->n_blk = n_blk;
	k->n_pool = n_pool;
	if (ft.magic != KOF_KIX_MAGIC_FOOT || ft.meta_len > len ||
	    !kix_parse(k, image, ft.meta_len, len, why, why_len)) {
		if (ft.magic != KOF_KIX_MAGIC_FOOT)
			why_set(why, why_len, "no index footer");
		k->image = NULL;       /* the caller's to free: nothing was taken over */
		kix_free(k);
		free(image);
		return NULL;
	}
	k->resident = k->resident + len;
	return k;
}

void kof_kix_info(const struct kof_kix *k, struct kof_kix_info *o)
{
	memset(o, 0, sizeof *o);
	if (!k)
		return;
	o->n_block = k->h.n_block;
	o->n_key = k->h.n_key;
	o->max_mult = k->h.max_mult;
	o->top = k->h.top;
	o->mult = k->h.mult;
	o->n_class = k->h.n_class;
	o->filter_k = k->h.filter_k;
	o->n_pair = k->h.n_pair;
	o->body_len = k->h.body_len;
	o->filter_bytes = k->h.filter_bytes;
	o->xf_bytes = k->h.xf_bytes;
	o->xf_crc = k->h.xf_crc;
	o->xf_kind = k->h.xf_kind;
	o->resident = k->resident;
	o->in_memory = k->in_memory;
}

const uint32_t *kof_kix_dir(const struct kof_kix *k)
{
	return k ? k->dir : NULL;
}

const struct kof_kix_class *kof_kix_class(const struct kof_kix *k, uint32_t *n)
{
	if (n)
		*n = k ? k->h.n_class : 0;
	return k ? k->cls : NULL;
}

/* ---- reading ------------------------------------------------------------------ */

static void io_count(struct kof_kix_io *io, uint64_t bytes)
{
	if (io) {
		io->bytes += bytes;
		io->reads++;
	}
}

/* Check slice `s` against its CRC, once for everybody. The answer is stored: 1 good, 2 bad. */
static int slice_check(const struct kof_slices *sl, uint32_t s, struct kof_kix_io *io)
{
	_Atomic uint8_t *st = &sl->ok[s];
	uint8_t buf[KOF_KIX_SLICE];
	uint64_t from = (uint64_t)s << KOF_KIX_SLICE_SHIFT;
	uint64_t len = sl->body_len - from < KOF_KIX_SLICE ? sl->body_len - from : KOF_KIX_SLICE;
	uint8_t v = atomic_load(st);

	if (v == 1)
		return 1;
	if (v == 2) {
		if (io)
			io->err |= KOF_KIX_E_CRC;
		return 0;
	}
	if (!slice_src_read(sl, sl->body_off + from, buf, (size_t)len)) {
		if (io)
			io->err |= KOF_KIX_E_IO;
		return 0;
	}
	io_count(io, len);
	if (kof_crc32_fast_cont(0, buf, len) != sl->crc[s]) {
		atomic_store(st, 2);
		if (io)
			io->err |= KOF_KIX_E_CRC;
		return 0;
	}
	atomic_store(st, 1);
	return 1;
}

int kof_slices_init(struct kof_slices *s, const struct kof_slices_req *rq)
{
	uint32_t n;

	memset(s, 0, sizeof *s);
	if (!rq || rq->body_off > rq->src_len || rq->body_len > rq->src_len - rq->body_off ||
	    (rq->body_len && !rq->crc) || (!rq->mem && rq->fd < 0) ||
	    (rq->body_len >> KOF_KIX_SLICE_SHIFT) > 0xfffffff0u)
		return 0;
	n = (uint32_t)((rq->body_len + KOF_KIX_SLICE - 1u) >> KOF_KIX_SLICE_SHIFT);
	s->crc = malloc((size_t)(n ? n : 1u) * sizeof *s->crc);
	s->ok = calloc(n ? n : 1u, sizeof *s->ok);
	if (!s->crc || !s->ok) {
		free(s->crc);
		free(s->ok);
		memset(s, 0, sizeof *s);
		return 0;
	}
	if (n)
		memcpy(s->crc, rq->crc, (size_t)n * sizeof *s->crc);
	s->fd = rq->fd;
	s->mem = rq->mem;
	s->base = rq->base;
	s->src_len = rq->src_len;
	s->body_off = rq->body_off;
	s->body_len = rq->body_len;
	s->n_slice = n;
	if (rq->verified)
		for (uint32_t i = 0; i < n; i++)
			atomic_store(&s->ok[i], 1);
	return 1;
}

void kof_slices_done(struct kof_slices *s)
{
	free(s->crc);
	free((void *)(uintptr_t)s->ok);
	memset(s, 0, sizeof *s);
}

int kof_slices_read(const struct kof_slices *s, uint64_t off, void *out, size_t n,
		    struct kof_kix_io *io)
{
	uint64_t cost;
	uint32_t sl, s1;

	if (!n)
		return 1;
	if (off > s->body_len || n > s->body_len - off) {
		if (io)
			io->err |= KOF_KIX_E_IO;
		return 0;
	}
	if (io) {
		/* A read costs its bytes or a page: a thousand two-byte reads are not free. */
		cost = n < KIX_PAGE ? KIX_PAGE : n;
		if (io->spent > io->budget || cost > io->budget - io->spent) {
			io->err |= KOF_KIX_E_BUDGET;
			return 0;
		}
		io->spent += cost;
	}
	s1 = (uint32_t)((off + n - 1u) >> KOF_KIX_SLICE_SHIFT);
	for (sl = (uint32_t)(off >> KOF_KIX_SLICE_SHIFT); sl <= s1; sl++)
		if (!slice_check(s, sl, io))
			return 0;
	if (!slice_src_read(s, s->body_off + off, out, n)) {
		if (io)
			io->err |= KOF_KIX_E_IO;
		return 0;
	}
	io_count(io, n);
	return 1;
}

int kof_kix_body(const struct kof_kix *k, uint64_t off, void *out, size_t n,
		 struct kof_kix_io *io)
{
	return kof_slices_read(&k->sl, off, out, n, io);
}

int kof_kix_block(const struct kof_kix *k, uint32_t b, struct kof_mutation_block *out,
		  struct kof_kix_io *io)
{
	if (b >= k->n_blk || !src_read(&k->blk, (uint64_t)b * sizeof *out, out, sizeof *out)) {
		if (io)
			io->err |= KOF_KIX_E_IO;
		return 0;
	}
	io_count(io, sizeof *out);
	/* Checked at load, and the file may have changed since: the slice is bounded again. */
	if (out->n_hash < KGENOME_MUTATION_MIN_HASH || out->n_hash > KOF_MUTATION_MAX_HASH ||
	    out->first_hash > k->n_pool || out->n_hash > k->n_pool - out->first_hash) {
		if (io)
			io->err |= KOF_KIX_E_IO;
		return 0;
	}
	return 1;
}

int kof_kix_block_hashes(const struct kof_kix *k, uint32_t b, uint32_t *out,
			 uint32_t *n_out, struct kof_kix_io *io)
{
	struct kof_mutation_block rec;

	*n_out = 0;
	if (!kof_kix_block(k, b, &rec, io))
		return 0;
	if (!src_read(&k->pool, (uint64_t)rec.first_hash * 4u, out, (size_t)rec.n_hash * 4u)) {
		if (io)
			io->err |= KOF_KIX_E_IO;
		return 0;
	}
	io_count(io, (uint64_t)rec.n_hash * 4u);
	*n_out = rec.n_hash;
	return 1;
}

int kof_kix_xf_read(const struct kof_kix *k, uint64_t off, void *out, size_t n)
{
	if (!k || !k->h.xf_bytes || off > k->h.xf_bytes || n > k->h.xf_bytes - off)
		return 0;
	return src_read(&k->idx, k->h.off_xf + off, out, n);
}

int kof_kix_filter_or(const struct kof_kix *k, uint8_t *dst, uint64_t dst_bytes)
{
	uint64_t S = k->h.filter_bytes, D = dst_bytes, o;
	uint8_t *chunk;
	uint32_t c = 0;
	uint32_t fold = 0, tile = 0;

	if (D < KOF_KIX_FILTER_MIN || (D & (D - 1u)))
		return 0;
	chunk = malloc(KIX_READ_CHUNK);
	if (!chunk)
		return 0;
	if (S >= D)
		fold = (uint32_t)(S / D);        /* source lines per destination line */
	else
		tile = (uint32_t)(D / S);        /* destination lines per source line */
	for (o = 0; o < S;) {
		uint64_t n = S - o < KIX_READ_CHUNK ? S - o : KIX_READ_CHUNK, l;

		if (!src_read(&k->idx, k->h.off_filter + o, chunk, (size_t)n)) {
			free(chunk);
			return 0;
		}
		c = kof_crc32_fast_cont(c, chunk, n);
		for (l = 0; l < n / 64u; l++) {
			uint64_t ls = o / 64u + l, w;
			const uint8_t *src = chunk + l * 64u;

			if (fold) {
				uint64_t *d = (uint64_t *)(void *)(dst + (ls / fold) * 64u);

				for (w = 0; w < 8; w++) {
					uint64_t x;

					memcpy(&x, src + 8u * w, 8);
					d[w] |= x;
				}
			} else {
				uint32_t t;

				for (t = 0; t < tile; t++) {
					uint64_t *d = (uint64_t *)(void *)(dst + (ls * tile + t) * 64u);

					for (w = 0; w < 8; w++) {
						uint64_t x;

						memcpy(&x, src + 8u * w, 8);
						d[w] |= x;
					}
				}
			}
		}
		o += n;
	}
	free(chunk);
	return c == k->h.filter_crc;
}
