/*
 * fidset.c - see fidset.h for what this is and what it deliberately is not.
 *
 * THE FILE IS THE INDEX.
 *
 *     header
 *     fence[]   every FENCE_STRIDE'th key, in order
 *     key[]     every key, ascending
 *
 * A lookup binary searches `fence` - which is a few hundred entries for a
 * hundred thousand keys, and stays in cache because every lookup reads it -
 * and then searches one block of `key`. One page of the large array is touched
 * per query instead of the seventeen a plain binary search over the whole of it
 * would scatter across.
 *
 * Nothing is copied out of the mapping and nothing is parsed into a struct. The
 * bytes on disk ARE the array, which is why a hundred thousand entries cost a
 * hundred thousand entries of disk and almost no resident memory.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "fidset.h"
#include "../../libkofeng/kofcore/kofplatform.h"

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#else
#include <windows.h>
#endif

#define FID_MAGIC        "KOFFIDS1"
/*
 * 3. The header grew `made` and then `eng_stamp`, and each is a different
 * layout: a reader that took an older file at its word would find the key count
 * where a timestamp now is. The version is what stops that being found out by
 * reading the wrong field.
 */
#define FID_VERSION      3u
/*
 * HOW MANY KEYS ONE FENCE ENTRY COVERS.
 *
 * 512 keys is 4096 bytes, which is a page: a block search touches exactly one.
 * Larger and a block spans pages; smaller and the fence grows for nothing.
 */
#define FENCE_STRIDE     512u

/*
 * THE HEADER SAYS WHAT THE FILE IS, WHAT IT IS TRUE OF, AND WHEN IT WAS MADE.
 *
 *   magic     what this file is, before any field of it is believed
 *   version   THIS format. A file of another one is refused whole rather
 *             than read with the fields of a different layout.
 *   stride    the fence's, checked because the search reads it
 *   db_stamp  WHICH DATABASE these answers belong to - see
 *             kof_engine_db_stamp. Not a build date: a date cannot tell one
 *             database from another built the same hour, and removing a pack
 *             does not move it at all.
 *   eng_stamp WHICH ENGINE produced them. The rules can be identical and the
 *             answer still change - see kof_fidset_open.
 *   made      WHEN, as seconds since the epoch - an INTEGER, not text. A
 *             timestamp written as text is a parser, a locale and a decision
 *             about what "now" is spelled like; as a number it is eight bytes
 *             that every reader agrees about and that sorts. Nothing decides
 *             anything by it: the DATABASE is what invalidates a cache, and an
 *             age that expired entries would be a second rule saying something
 *             the stamp already says. It is here to be READ - by a person
 *             asking how old this file is, and by a tool reporting it.
 *   n         how many keys follow
 */
struct fid_hdr {
	char     magic[8];
	uint32_t version;
	uint32_t stride;
	uint64_t db_stamp;
	uint64_t eng_stamp;
	uint64_t made;
	uint64_t n;
};

/*
 * THE HEADER IS A FILE FORMAT, NOT A STRUCT, and two compilers have to agree
 * about it byte for byte - this is written by gcc on Linux and read by
 * whatever built the Windows side.
 *
 * The layout is chosen so no padding is needed: eight bytes of magic, two
 * uint32 that fill one eight-byte slot between them, then two uint64 already
 * aligned. Asserted rather than trusted, because a compiler that padded it
 * would produce a file the other side reads as truncated - and the failure
 * would be a cache that silently never loads.
 */
_Static_assert(sizeof(struct fid_hdr) == 48,
	       "fid_hdr has padding: the on-disk header is not 48 bytes");

/*
 * BYTE ORDER IS NOT CHECKED AND DOES NOT NEED TO BE. The numbers are written
 * native, so a file carried to a machine of the other endianness reads
 * `version` as 0x01000000 and is refused by the version test before anything
 * else is believed. That is the right outcome and it costs no field.
 */

struct kof_fidset {
	uint64_t db_stamp;
	uint64_t eng_stamp;

	/* the mapped file, or nothing */
	void          *map;
	size_t         map_len;
#ifdef _WIN32
	/*
	 * Windows needs the two handles kept to undo the mapping, which POSIX
	 * does not - munmap takes the address. Held here rather than closed
	 * early: closing the section handle while a view is alive is legal but
	 * closing the FILE handle is what a reader expects to be able to do,
	 * and keeping both makes the teardown one shape instead of two.
	 */
	void          *w_file;
	void          *w_map;
#endif
	const uint64_t *fence;
	uint64_t        n_fence;
	const uint64_t *key;
	uint64_t        n_key;

	/* what this run added: unsorted, with a table over it so a repeat in
	 * the same run is answered without a scan */
	uint64_t *add;
	uint64_t  n_add, cap_add;
	uint32_t *idx;          /* open addressing over `add`, 1 based */
	uint64_t  n_idx;        /* power of two */

	/*
	 * WHAT THIS RUN TOOK OUT - see kof_fidset_drop.
	 *
	 * A plain array walked linearly, and no table over it, because of what
	 * is in it: one entry per file a scan actually found something in. A
	 * sweep that fills this has bigger news than its cache. The empty case
	 * is what every lookup pays, and that is one test of n_drop.
	 */
	uint64_t *drop;
	uint64_t  n_drop, cap_drop;

	struct kof_fidset_stat st;
};

/* ---- the key -------------------------------------------------------------- */

uint64_t kof_fid_key(const struct kof_fid *f)
{
	const uint8_t *p = (const uint8_t *)f;
	uint64_t h = 1469598103934665603ull;
	size_t i;

	if (!f)
		return 0;
	for (i = 0; i < sizeof *f; i++) {
		h ^= p[i];
		h *= 1099511628211ull;
	}
	/*
	 * ZERO IS NOT A KEY. The index below uses it for an empty slot, and a
	 * real key that collided with the sentinel would be invisible in the
	 * table while being present in the array - findable on a reload and not
	 * before it, which is the kind of difference nothing would ever notice.
	 */
	return h ? h : 1ull;
}

/* ---- the run's own additions ---------------------------------------------- */

static int idx_grow(struct kof_fidset *s)
{
	uint64_t want = s->n_idx ? s->n_idx * 2u : 1024u;
	uint32_t *ni = calloc((size_t)want, sizeof *ni);
	uint64_t i;

	if (!ni)
		return 0;
	for (i = 0; i < s->n_add; i++) {
		uint64_t h = s->add[i] & (want - 1u);

		while (ni[h])
			h = (h + 1u) & (want - 1u);
		ni[h] = (uint32_t)(i + 1u);
	}
	free(s->idx);
	s->idx = ni;
	s->n_idx = want;
	return 1;
}

static int add_has(const struct kof_fidset *s, uint64_t key)
{
	uint64_t h;

	if (!s->n_idx)
		return 0;
	h = key & (s->n_idx - 1u);
	while (s->idx[h]) {
		if (s->add[s->idx[h] - 1u] == key)
			return 1;
		h = (h + 1u) & (s->n_idx - 1u);
	}
	return 0;
}

static int drop_has(const struct kof_fidset *s, uint64_t key)
{
	uint64_t i;

	for (i = 0; i < s->n_drop; i++)
		if (s->drop[i] == key)
			return 1;
	return 0;
}

/* ---- the mapping ---------------------------------------------------------- */

static int map_has(struct kof_fidset *s, uint64_t key)
{
	uint64_t lo, hi, blk, from, to;

	if (!s->n_key)
		return 0;
	/*
	 * Which block the key would be in. The fence holds the FIRST key of
	 * each block, so the answer is the last fence entry not greater than
	 * the key - and when the key is below every one of them it is below the
	 * whole set.
	 */
	if (key < s->fence[0])
		return 0;
	lo = 0;
	hi = s->n_fence - 1u;
	while (lo < hi) {
		uint64_t mid = lo + (hi - lo + 1u) / 2u;

		if (s->fence[mid] <= key)
			lo = mid;
		else
			hi = mid - 1u;
	}
	blk = lo;

	from = blk * FENCE_STRIDE;
	to = from + FENCE_STRIDE;
	if (to > s->n_key)
		to = s->n_key;
	s->st.pages++;

	while (from < to) {
		uint64_t mid = from + (to - from) / 2u;

		if (s->key[mid] == key)
			return 1;
		if (s->key[mid] < key)
			from = mid + 1u;
		else
			to = mid;
	}
	return 0;
}

/* ---- open, load, close ---------------------------------------------------- */

struct kof_fidset *kof_fidset_open(uint64_t db_stamp, uint64_t eng_stamp)
{
	struct kof_fidset *s = calloc(1, sizeof *s);

	if (!s)
		return NULL;
	s->db_stamp = db_stamp;
	s->eng_stamp = eng_stamp;
	return s;
}

/*
 * Move `tmp` onto `path`, REPLACING whatever is there. Non-zero on success.
 *
 * WHY NOT rename(). POSIX rename replaces the destination atomically and this
 * file used it on both platforms. Measured on Windows 11 ARM64:
 *
 *     rename(tmp, path) with path present   -1, errno 17 EEXIST
 *
 * ISO C leaves the case undefined and the Microsoft runtime refuses it. So the
 * FIRST save of a cache worked, every save after it failed, and the failure
 * was silent from the outside - the set simply never grew past its first run.
 * The unit test caught it as three failures in a row and the middle one names
 * the symptom exactly: "the merge lost or duplicated keys".
 */
static int replace_file(const char *tmp, const char *path)
{
#ifdef _WIN32
	return MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING) != 0;
#else
	return rename(tmp, path) == 0;
#endif
}

static void unmap(struct kof_fidset *s)
{
#ifndef _WIN32
	if (s->map)
		munmap(s->map, s->map_len);
#else
	if (s->map)
		UnmapViewOfFile(s->map);
	if (s->w_map && s->w_map != INVALID_HANDLE_VALUE)
		CloseHandle((HANDLE)s->w_map);
	if (s->w_file && s->w_file != INVALID_HANDLE_VALUE)
		CloseHandle((HANDLE)s->w_file);
	s->w_map = NULL;
	s->w_file = NULL;
#endif
	s->map = NULL;
	s->map_len = 0;
	s->fence = s->key = NULL;
	s->n_fence = s->n_key = 0;
	/*
	 * AND THE COUNT THAT DESCRIBED IT.
	 *
	 * Loading a second file unmaps the first. Leaving `mapped` at the old
	 * number meant a failed load reported the size of a set that is no
	 * longer there - a caller checking whether the cache was worth keeping
	 * would read the previous run's answer.
	 */
	s->st.mapped = 0;
	s->st.made   = 0;
}

void kof_fidset_close(struct kof_fidset *s)
{
	if (!s)
		return;
	unmap(s);
	free(s->add);
	free(s->idx);
	free(s->drop);
	free(s);
}

int kof_fidset_load(struct kof_fidset *s, const char *path)
{
#ifndef _WIN32
	struct fid_hdr h;
	struct stat st;
	size_t want;
	void *m;
	int fd;

	if (!s || !path || !path[0])
		return 0;
	unmap(s);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;
	if (fstat(fd, &st) != 0 || (size_t)st.st_size < sizeof h) {
		close(fd);
		return 0;
	}
	if (read(fd, &h, sizeof h) != (ssize_t)sizeof h) {
		close(fd);
		return 0;
	}
	/*
	 * EVERY ONE OF THESE DISCARDS THE WHOLE FILE, and none of them salvages
	 * what it could still parse. A cache that kept the entries it
	 * understood would be answering from a contract it has just admitted it
	 * does not share.
	 */
	if (memcmp(h.magic, FID_MAGIC, sizeof h.magic) != 0 ||
	    h.version != FID_VERSION || h.stride != FENCE_STRIDE ||
	    h.db_stamp != s->db_stamp || h.eng_stamp != s->eng_stamp) {
		close(fd);
		return 0;
	}
	/*
	 * h.n IS BOUNDED BY THE BYTES ON DISK BEFORE IT IS USED IN ARITHMETIC.
	 *
	 * Without this, "want == the file's size" is not the check it looks
	 * like. h.n is a uint64 out of the file, so h.n + FENCE_STRIDE - 1
	 * wraps and (n_fence + h.n) * 8 wraps again, and the two wraps can be
	 * chosen to land on a real size: h.n = 9205392754131862016 makes
	 * n_fence 17979282722913793 and want exactly 48, so a 48-byte file is
	 * accepted with n_key claiming nine quintillion keys over eight bytes
	 * of mapping. Every lookup after that binary searches whatever follows
	 * the page.
	 *
	 * The file's own size is the one number here that is not the file's
	 * claim about itself, so it is what the claim is measured against.
	 */
	if (h.n > ((uint64_t)st.st_size - sizeof h) / sizeof(uint64_t)) {
		close(fd);
		return 0;
	}
	{
		uint64_t n_fence = h.n ? (h.n + FENCE_STRIDE - 1u) / FENCE_STRIDE
				       : 0u;

		want = sizeof h + (size_t)(n_fence + h.n) * sizeof(uint64_t);
		if (want != (size_t)st.st_size) {
			close(fd);
			return 0;      /* truncated, or longer than it claims */
		}
		m = mmap(NULL, want, PROT_READ, MAP_PRIVATE, fd, 0);
		close(fd);
		if (m == MAP_FAILED)
			return 0;
		s->map = m;
		s->map_len = want;
		s->fence = (const uint64_t *)((const char *)m + sizeof h);
		s->n_fence = n_fence;
		s->key = s->fence + n_fence;
		s->n_key = h.n;
		s->st.mapped = h.n;
		s->st.made   = h.made;
		/*
		 * AN EMPTY SET IS NOT A LOADED ONE. Answering 0 while holding a
		 * mapping would leave the caller believing there is nothing to
		 * unmap and this object holding a descriptor's worth of address
		 * space for a file with no keys in it.
		 */
		if (!s->n_key) {
			unmap(s);
			return 0;
		}
	}
	return 1;
#else
	/*
	 * THE SAME FILE, THE SAME CHECKS, A DIFFERENT WAY TO MAP IT.
	 *
	 * Everything the POSIX half refuses on is refused here for the same
	 * reason and in the same order - magic, version, stride, database
	 * stamp, then a length that must match exactly what the header claims.
	 * A shorter file is a truncated write and a longer one is not this
	 * format; neither is salvaged.
	 *
	 * FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, because
	 * saving replaces this file by renaming another over it. A mapping that
	 * blocked that would make the second run of a sweep unable to write
	 * what the first one learned - and the view stays valid afterwards,
	 * since it refers to the section rather than to the name.
	 */
	struct fid_hdr h;
	LARGE_INTEGER sz;
	DWORD got = 0;
	HANDLE fh, mh;
	void *view;
	size_t want;
	uint64_t n_fence;

	if (!s || !path || !path[0])
		return 0;
	unmap(s);
	fh = CreateFileA(path, GENERIC_READ,
			 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			 NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fh == INVALID_HANDLE_VALUE)
		return 0;
	if (!GetFileSizeEx(fh, &sz) || (uint64_t)sz.QuadPart < sizeof h) {
		CloseHandle(fh);
		return 0;
	}
	if (!ReadFile(fh, &h, (DWORD)sizeof h, &got, NULL) ||
	    got != (DWORD)sizeof h) {
		CloseHandle(fh);
		return 0;
	}
	if (memcmp(h.magic, FID_MAGIC, sizeof h.magic) != 0 ||
	    h.version != FID_VERSION || h.stride != FENCE_STRIDE ||
	    h.db_stamp != s->db_stamp || h.eng_stamp != s->eng_stamp ||
	    h.n == 0) {
		CloseHandle(fh);
		return 0;
	}
	/* Bounded against the file's real size first - see the note on the
	 * POSIX side, the arithmetic below wraps without it. */
	if ((uint64_t)sz.QuadPart < sizeof h ||
	    h.n > ((uint64_t)sz.QuadPart - sizeof h) / sizeof(uint64_t)) {
		CloseHandle(fh);
		return 0;
	}
	n_fence = (h.n + FENCE_STRIDE - 1u) / FENCE_STRIDE;
	want = sizeof h + (size_t)(n_fence + h.n) * sizeof(uint64_t);
	if ((uint64_t)want != (uint64_t)sz.QuadPart) {
		CloseHandle(fh);
		return 0;
	}
	mh = CreateFileMappingA(fh, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!mh) {
		CloseHandle(fh);
		return 0;
	}
	view = MapViewOfFile(mh, FILE_MAP_READ, 0, 0, 0);
	if (!view) {
		CloseHandle(mh);
		CloseHandle(fh);
		return 0;
	}
	s->w_file = fh;
	s->w_map = mh;
	s->map = view;
	s->map_len = want;
	s->fence = (const uint64_t *)((const char *)view + sizeof h);
	s->n_fence = n_fence;
	s->key = s->fence + n_fence;
	s->n_key = h.n;
	s->st.mapped = h.n;
	s->st.made   = h.made;
	return 1;
#endif
}

/* ---- the two operations --------------------------------------------------- */

int kof_fidset_has(struct kof_fidset *s, uint64_t key)
{
	int r;

	if (!s || !key)
		return 0;
	/* Taken out this run, whatever the file says. Counted as a miss below,
	 * which is what it is to the caller. */
	if (s->n_drop && drop_has(s, key))
		return ++s->st.miss, 0;
	r = add_has(s, key) || map_has(s, key);
	if (r)
		s->st.hit++;
	else
		s->st.miss++;
	return r;
}

int kof_fidset_add(struct kof_fidset *s, uint64_t key)
{
	uint64_t h;

	if (!s || !key)
		return 0;
	if (add_has(s, key) || map_has(s, key))
		return 1;
	/*
	 * The index stores a 1-based position in a uint32, so the array it
	 * indexes cannot outgrow that. Four billion files in one run is not a
	 * case anybody meets, but a silent truncation here would make an entry
	 * point at the wrong key - present in the array, wrong in the table,
	 * and only findable after a reload.
	 */
	if (s->n_add >= 0xfffffffeu)
		return 0;
	if (s->n_add + 1u > s->cap_add) {
		uint64_t want = s->cap_add ? s->cap_add * 2u : 512u;
		uint64_t *na = realloc(s->add, (size_t)want * sizeof *na);

		if (!na)
			return 0;
		s->add = na;
		s->cap_add = want;
	}
	if ((s->n_add + 1u) * 2u > s->n_idx && !idx_grow(s))
		return 0;
	s->add[s->n_add++] = key;
	h = key & (s->n_idx - 1u);
	while (s->idx[h])
		h = (h + 1u) & (s->n_idx - 1u);
	s->idx[h] = (uint32_t)s->n_add;   /* 1 based */
	s->st.added = s->n_add;
	return 1;
}

int kof_fidset_drop(struct kof_fidset *s, uint64_t key)
{
	if (!s || !key)
		return 0;
	if (drop_has(s, key))
		return 1;
	/*
	 * A KEY THAT IS NOT THERE IS NOT A REMOVAL, and the count says so.
	 *
	 * Every file a scan finds something in is offered here, and on a tree
	 * of samples that is most of them - none of which the cache ever held.
	 * Recording those would report "68 entries dropped" about a set that
	 * lost nothing, and the one number worth reading is how many stale
	 * clean answers this run actually took out.
	 */
	if (!add_has(s, key) && !map_has(s, key))
		return 1;
	if (s->n_drop + 1u > s->cap_drop) {
		uint64_t want = s->cap_drop ? s->cap_drop * 2u : 64u;
		uint64_t *nd = realloc(s->drop, (size_t)want * sizeof *nd);

		if (!nd)
			return 0;
		s->drop = nd;
		s->cap_drop = want;
	}
	s->drop[s->n_drop++] = key;
	s->st.dropped = s->n_drop;
	return 1;
}

/* ---- writing it back ------------------------------------------------------ */

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y ? 1 : 0;
}

int kof_fidset_save(struct kof_fidset *s, const char *path)
{
	struct fid_hdr h;
	uint64_t *out, n = 0, i = 0, j = 0, n_fence;
	char tmp[1024];
	FILE *f;
	int ok = 0;

	if (!s || !path || !path[0])
		return 0;
	/*
	 * NOTHING TO SAY, and a set that only LOST keys is not that: the run
	 * kof_fidset_drop exists for adds nothing, because it was told to trust
	 * nothing. There is still no file to write when the mapping is empty
	 * too, which is what this tests.
	 */
	if (!s->n_add && !s->n_key)
		return 1;

	/*
	 * TWO SORTED RUNS, MERGED. The mapping is already in order and the
	 * additions are sorted here, so the result is one linear pass rather
	 * than a sort of everything on every save.
	 *
	 * `add` may be NULL here - a run that only dropped never allocated it -
	 * and qsort is declared never to take one, whatever the count says.
	 */
	if (s->n_add)
		qsort(s->add, (size_t)s->n_add, sizeof *s->add, cmp_u64);
	out = malloc((size_t)(s->n_key + s->n_add) * sizeof *out);
	if (!out)
		return 0;
	while (i < s->n_key || j < s->n_add) {
		uint64_t v;

		if (j >= s->n_add || (i < s->n_key && s->key[i] <= s->add[j]))
			v = s->key[i++];
		else
			v = s->add[j++];
		/* Taken out this run: written by neither side. */
		if (s->n_drop && drop_has(s, v))
			continue;
		/* Both sides may hold it, and the run may hold it twice. */
		if (!n || out[n - 1u] != v)
			out[n++] = v;
	}

	n_fence = n ? (n + FENCE_STRIDE - 1u) / FENCE_STRIDE : 0u;
	memcpy(h.magic, FID_MAGIC, sizeof h.magic);
	h.version = FID_VERSION;
	h.stride = FENCE_STRIDE;
	h.db_stamp = s->db_stamp;
	h.eng_stamp = s->eng_stamp;
	/* Seconds since the epoch, and a clock that refuses is a zero rather
	 * than a guess: a file whose age cannot be read is better than one that
	 * claims an age it does not have. */
	{
		time_t now = time(NULL);

		h.made = now == (time_t)-1 ? 0u : (uint64_t)now;
	}
	h.n = n;

	if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp) {
		free(out);
		return 0;
	}
	/*
	 * CREATED, NOT OPENED, AND ONLY IF THE NAME WAS FREE.
	 *
	 * fopen(tmp, "wb") follows a symlink and takes its mode from the
	 * umask. The name is "<the cache>.tmp" - predictable - and the cache
	 * path comes from the caller, which for kofscanner is --cache-file and
	 * so need not be in a directory only this user can write. Planting
	 * that name as a link made the save write through it: demonstrated,
	 * the target file came back holding this file's header.
	 *
	 * kof_fopen_new refuses any name that already exists, link included.
	 * The retry after remove() is safe for the same reason it is useful: a
	 * stale .tmp from an interrupted save is cleared, and if somebody wins
	 * the race to recreate it the exclusive create fails and nothing is
	 * written - a lost save, never a write somewhere else.
	 */
	f = kof_fopen_new(tmp);
	if (!f) {
		remove(tmp);
		f = kof_fopen_new(tmp);
	}
	if (!f) {
		free(out);
		return 0;
	}
	ok = fwrite(&h, sizeof h, 1, f) == 1;
	for (i = 0; ok && i < n_fence; i++)
		ok = fwrite(&out[i * FENCE_STRIDE], sizeof *out, 1, f) == 1;
	if (ok && n)
		ok = fwrite(out, sizeof *out, (size_t)n, f) == n;
	if (fclose(f) != 0)
		ok = 0;
	free(out);
	if (!ok) {
		remove(tmp);
		return 0;
	}
	/*
	 * RENAMED INTO PLACE, so a reader sees the whole of the old file or the
	 * whole of the new one. A half written cache that still parses is the
	 * worst outcome available here - it would answer, and be wrong.
	 *
	 * THE MAPPING GOES FIRST, AND ON WINDOWS THAT IS NOT TIDINESS.
	 *
	 * Measured on Windows 11 ARM64, replacing a file this process still has
	 * mapped - opened with FILE_SHARE_DELETE, which is supposed to allow
	 * exactly this:
	 *
	 *     MoveFileEx(MOVEFILE_REPLACE_EXISTING)   0, error 5 ACCESS_DENIED
	 *
	 * The share mode governs the FILE; an open section object is a separate
	 * reference and the replace is refused while one exists. So the old
	 * mapping is released before the new file takes its place, and the set
	 * re-reads it afterwards - which also leaves `add` merged into `key`
	 * rather than counted twice by a later save.
	 *
	 * A failed re-map is not a failed save. The file on disk is correct and
	 * complete; this set simply has nothing mapped, which fidset.h already
	 * defines as "every lookup will miss".
	 */
	unmap(s);
	if (!replace_file(tmp, path)) {
		remove(tmp);
		(void)kof_fidset_load(s, path);   /* put back what was there */
		return 0;
	}
	s->n_add = 0;
	free(s->idx);
	s->idx = NULL;
	s->n_idx = 0;
	/* The file no longer holds them, so neither does the list: keeping it
	 * would make a second save re-filter keys that are already gone and
	 * would answer "not here" for a key added back afterwards. */
	s->n_drop = 0;
	(void)kof_fidset_load(s, path);
	return 1;
}

void kof_fidset_stats(const struct kof_fidset *s, struct kof_fidset_stat *out)
{
	if (!out)
		return;
	if (!s) {
		memset(out, 0, sizeof *out);
		return;
	}
	*out = s->st;
}
