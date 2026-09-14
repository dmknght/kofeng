/*
 * koffridge.c - the verdict cache. See koffridge.h for what it is keyed on and
 * why that is the only decision that matters.
 *
 * SHAPE: open addressing, linear probing, one flat allocation. No buckets, no
 * per-entry malloc, no arena. An entry is 288 bytes and the whole table is one
 * calloc, so a lookup is a hash, a mask and at most KOF_PROBE cache lines - and
 * the structure has no way to fragment over a long-running walk.
 *
 * EVICTION: least recently used WITHIN THE PROBE RUN, and nowhere else. A full
 * LRU needs a list and two pointer writes per hit, on the path this exists to
 * make cheap; a clock needs a sweep hand and a pass that can find nothing. The
 * probe run is the only set of slots this key could ever occupy, so the worst
 * entry in it is the right one to drop, and finding it costs the walk that was
 * happening anyway.
 */

/*
 * Before the first system header, or it does nothing.
 *
 * Two things in this file need it. kofplatform.h, included below, calls
 * memmem, lstat and realpath - none of which a bare -std=c11 declares. And the
 * mtime read further down selects its sub-second branch on exactly this macro:
 * without it the cache key falls back to whole-second mtime, which is the
 * precision this cache was measured to need.
 *
 * The header deliberately does not define it for its includers - a feature test
 * macro belongs to the translation unit, not to a header included partway
 * through one - so the translation unit says it here.
 */
#ifndef _WIN32
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * pthreads, because that is what this tree already threads with - see the work
 * queue in libkofeng/kofscanners/scan.c - and because every target that
 * compiles this file already links -pthread. On Windows that resolves through
 * winpthreads, statically, for the reason the Makefile gives beside the flag.
 */
#include <pthread.h>

#include "../../libkofeng/kofeng.h"
#include "koffridge.h"

/* kof_mkdir and KOF_PATH_SEP - the two things a default path needs and the
 * one place this tree already says how they differ per platform. */
#include "../../libkofeng/core/kofplatform.h"

/*
 * THE ONE PLATFORM-DEPENDENT THING IN THIS FILE, and it is confined to the
 * function below.
 *
 * Everything else here is a hash table over opaque keys and compiles the same
 * everywhere. What a file's identity IS, though, is a question only the
 * operating system answers, and the two answers are the same four numbers
 * reached through different calls - so the split is at the call and not at the
 * structure, and no caller learns which platform it is on.
 */
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#endif

int koffridge_identify(const char *path, struct koffridge_fileid *out)
{
	if (!out)
		return 0;
	memset(out, 0, sizeof *out);
	if (!path || !path[0])
		return 0;

#ifdef _WIN32
	{
		BY_HANDLE_FILE_INFORMATION bi;
		HANDLE h;

		/*
		 * Zero access rights: this asks for METADATA and opens nothing
		 * it could read. That is what lets it identify a file the
		 * caller has no right to the contents of, and it is why the
		 * share mode allows delete - a file somebody else is in the
		 * middle of replacing must not have its identification blocked,
		 * and must certainly not have its replacement blocked by this.
		 */
		h = CreateFileA(path, 0,
				FILE_SHARE_READ | FILE_SHARE_WRITE |
				FILE_SHARE_DELETE,
				NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
				NULL);
		if (h == INVALID_HANDLE_VALUE)
			return 0;
		if (!GetFileInformationByHandle(h, &bi)) {
			CloseHandle(h);
			return 0;
		}
		CloseHandle(h);

		out->volume = bi.dwVolumeSerialNumber;
		out->index  = ((uint64_t)bi.nFileIndexHigh << 32) |
			      bi.nFileIndexLow;
		out->size   = ((uint64_t)bi.nFileSizeHigh << 32) |
			      bi.nFileSizeLow;
		out->mtime  = ((uint64_t)bi.ftLastWriteTime.dwHighDateTime
			       << 32) | bi.ftLastWriteTime.dwLowDateTime;
		return 1;
	}
#else
	{
		struct stat st;

		/*
		 * stat and not lstat, on purpose: two paths that reach the same
		 * file through different links ARE the same file and should
		 * share one answer, which is the whole point of keying on
		 * st_dev and st_ino rather than on the path. A symlink of its
		 * own has no content to scan.
		 */
		if (stat(path, &st) != 0)
			return 0;
		if (!S_ISREG(st.st_mode))
			return 0;

		out->volume = (uint64_t)st.st_dev;
		out->index  = (uint64_t)st.st_ino;
		out->size   = (uint64_t)st.st_size;

		/*
		 * NANOSECONDS, AND THE SECOND WAS NOT ENOUGH.
		 *
		 * This used to take st_mtime - whole seconds - on the argument
		 * that a second is finer than the thing being guarded against.
		 * Measured, it is not. Three rewrites of one file, in place,
		 * same inode, same length:
		 *
		 *     mtime seconds  1789209554 1789209554 1789209554
		 *     mtime nsec      370836748  371003014  371007003
		 *
		 * At second granularity all three are the same file, so the
		 * cache serves the first scan's verdict for the third file's
		 * bytes. An attacker does not have to restore a timestamp for
		 * that - they have to be quick, and a write takes microseconds.
		 *
		 * The nanosecond field costs nothing: it arrives in the same
		 * stat. Windows needs no change, its FILETIME is already in
		 * 100ns units.
		 *
		 * WHAT IT STILL DOES NOT FIX is a filesystem that normalises
		 * timestamps - measured, 74% of the system files on this host
		 * have mtime 0, and their nsec is 0 too. See the header.
		 */
#if defined(st_mtime) || defined(_BSD_SOURCE) || defined(_SVID_SOURCE) || \
    (defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200809L) || \
    defined(_GNU_SOURCE) || defined(__APPLE__)
		out->mtime  = (uint64_t)st.st_mtime * 1000000000ull +
			      (uint64_t)st.st_mtim.tv_nsec;
#else
		/* No sub-second field on this system: the coarse answer, and
		 * the same units, so the two cannot be compared by accident. */
		out->mtime  = (uint64_t)st.st_mtime * 1000000000ull;
#endif
		return 1;
	}
#endif
}

/*
 * 4096 entries, about 1.2MB.
 *
 * Chosen against the thing it is for: the distinct modules behind every mapping
 * on a Windows workstation number in the low hundreds, and a whole-machine file
 * scan does not use this at all. Four thousand is an order of magnitude over
 * the working set it was sized for, which is where a default belongs - large
 * enough that nobody meets the eviction path by accident, small enough that a
 * caller who wanted a big one still has to say so.
 */
#define KOF_FRIDGE_DEFAULT 4096u

/*
 * How far a lookup walks before it gives up.
 *
 * 16 slots is one to two cache lines' worth of the hash array and is far past
 * the run lengths linear probing produces below a 0.75 load factor. Past it the
 * table is not full, it is BADLY DISTRIBUTED, and continuing to walk turns a
 * bounded miss into an unbounded one.
 */
#define KOF_PROBE 16u

struct entry {
	uint64_t h;             /* the identity's hash, 0 when the slot is free */
	uint64_t used;          /* the tick this entry was last read or written */
	uint32_t id_len;
	uint8_t  id[KOFFRIDGE_ID_MAX];
	struct koffridge_verdict v;
};

/*
 * ONE INDEPENDENT TABLE PER LOCK, rather than one table behind one lock.
 *
 * The header used to say this was deliberately not thread safe, and gave a
 * reason worth keeping: a single mutex would put a contended lock on the fast
 * path of every object looked up. That reason was right about a single mutex
 * and wrong as an argument for not doing it at all, and the caller it said had
 * not appeared has now appeared - the scanner runs several threads.
 *
 * Sharding answers the original objection directly instead of ignoring it.
 * Each shard is a whole small table: its own entries, its own mask, its own
 * eviction tick, its own counters. A key belongs to exactly one, so a probe
 * run and the eviction it may perform never cross a lock boundary, and two
 * threads working on different keys almost never meet.
 *
 * SIXTEEN, and the number is a trade between contention and eviction quality.
 * More shards mean less contention and SMALLER shards; a shard has to hold
 * several probe runs or it starts evicting keys it had room for. At the
 * default 4096 total that is 256 entries each, which is sixteen probe runs.
 */
#define KOF_SHARDS 16u

struct shard {
	struct entry *e;
	uint32_t cap;           /* a power of two */
	uint32_t mask;
	uint32_t used;
	uint64_t tick;
	struct koffridge_stat st;
	pthread_mutex_t lock;
};

struct koffridge {
	struct shard s[KOF_SHARDS];

	/*
	 * HOW MANY OF THOSE ARE IN USE, which is not always all of them.
	 *
	 * A shard has to hold several probe runs or it evicts keys it had room
	 * for, so there is a floor on how small one can usefully be - and
	 * sixteen shards of that floor is more memory than a caller asking for
	 * a small cache budgeted. Forcing the floor anyway turned a request for
	 * 64 entries into 512: eight times the memory, silently.
	 *
	 * So the SHARD COUNT gives way, not the capacity. A small fridge gets
	 * fewer, larger shards and the size it asked for; a big one gets all
	 * sixteen. Always a power of two, because shard_of masks with it.
	 */
	uint32_t n_shards;
	uint32_t mask_shards;

	uint32_t cap;           /* the total across every shard */
	uint64_t db_stamp;
};

/*
 * FNV-1a, and the reason a stronger hash is not needed here: a collision costs
 * a probe, never a wrong answer. The identity bytes are compared in full before
 * any entry is returned, so this only has to spread - which FNV does, on the
 * short structured keys this takes - and not to resist anything.
 *
 * Never returns 0; that value marks a free slot.
 */
static uint64_t hash_id(const void *p, uint32_t n)
{
	const uint8_t *b = p;
	uint64_t h = 1469598103934665603ull;
	uint32_t i;

	for (i = 0; i < n; i++) {
		h ^= b[i];
		h *= 1099511628211ull;
	}
	return h ? h : 1ull;
}

static uint32_t round_pow2(uint32_t n)
{
	uint32_t p = 1;

	while (p < n && p < (1u << 30))
		p <<= 1;
	return p;
}

/*
 * WHICH SHARD A KEY BELONGS TO - the HIGH bits of the hash.
 *
 * The low bits already choose the slot inside a shard, so reusing them here
 * would put every key that collides in a shard on the same slot within it, and
 * the probe run would do the work twice.
 */
static uint32_t shard_of(const struct koffridge *f, uint64_t h)
{
	return (uint32_t)(h >> 56) & f->mask_shards;
}

struct koffridge *koffridge_open(uint32_t capacity, uint64_t db_stamp)
{
	struct koffridge *f = calloc(1, sizeof *f);
	uint32_t total, per, i;

	if (!f)
		return NULL;

	/*
	 * THE CAPACITY IS WHAT WAS ASKED FOR; THE SHARD COUNT IS WHAT GIVES.
	 *
	 * Each shard needs room for a few probe runs, so a fixed sixteen of
	 * them imposes a floor on the total - and a caller asking for 64
	 * entries would have been handed 512. Dividing the other way round
	 * keeps the number the caller budgeted and spends fewer locks on a
	 * small table, which is the right trade: a small table is not the one
	 * with contention to relieve.
	 */
	total = round_pow2(capacity ? capacity : KOF_FRIDGE_DEFAULT);
	f->n_shards = total / (KOF_PROBE * 2u);
	if (f->n_shards > KOF_SHARDS)
		f->n_shards = KOF_SHARDS;
	if (f->n_shards < 1u)
		f->n_shards = 1u;
	f->n_shards = round_pow2(f->n_shards);
	f->mask_shards = f->n_shards - 1u;

	per = total / f->n_shards;
	if (per < 1u)
		per = 1u;
	per = round_pow2(per);

	for (i = 0; i < f->n_shards; i++) {
		struct shard *s = &f->s[i];

		s->cap = per;
		s->mask = per - 1u;
		s->e = calloc(per, sizeof *s->e);
		if (!s->e || pthread_mutex_init(&s->lock, NULL) != 0) {
			free(s->e);
			s->e = NULL;
			while (i-- > 0) {
				pthread_mutex_destroy(&f->s[i].lock);
				free(f->s[i].e);
			}
			free(f);
			return NULL;
		}
	}
	f->cap = per * f->n_shards;
	f->db_stamp = db_stamp;
	return f;
}

void koffridge_close(struct koffridge *f)
{
	uint32_t i;

	if (!f)
		return;
	for (i = 0; i < f->n_shards; i++) {
		pthread_mutex_destroy(&f->s[i].lock);
		free(f->s[i].e);
	}
	free(f);
}

uint64_t koffridge_db_stamp(const struct koffridge *f)
{
	return f ? f->db_stamp : 0ull;
}

void koffridge_clear(struct koffridge *f)
{
	uint32_t i;

	if (!f)
		return;
	for (i = 0; i < f->n_shards; i++) {
		struct shard *s = &f->s[i];

		pthread_mutex_lock(&s->lock);
		memset(s->e, 0, (size_t)s->cap * sizeof *s->e);
		s->used = 0;
		s->st.used = 0;
		pthread_mutex_unlock(&s->lock);
	}
}

static int same_id(const struct entry *e, uint64_t h, const void *id,
		   uint32_t id_len)
{
	return e->h == h && e->id_len == id_len &&
	       memcmp(e->id, id, id_len) == 0;
}

/* See the header: the check IS the return value, so it cannot be skipped. */
int koffridge_skip(struct koffridge *f, const void *id, uint32_t id_len)
{
	struct koffridge_verdict v;

	if (!koffridge_get(f, id, id_len, &v))
		return 0;
	/*
	 * BROKEN COUNTS AS NOT CLEAN. A scan that ran out of budget did not
	 * find nothing - it stopped looking, and remembering "stopped looking"
	 * as "nothing there" is how a decompression bomb becomes a way of not
	 * being scanned. The struct's own note on `broken` says the same.
	 */
	return v.findings == 0u && v.broken == 0u;
}

int koffridge_get(struct koffridge *f, const void *id, uint32_t id_len,
		  struct koffridge_verdict *out)
{
	struct shard *s;
	uint64_t h;
	uint32_t i, slot;
	int found = 0;

	if (!f || !id || !id_len || id_len > KOFFRIDGE_ID_MAX) {
		if (f) {
			/* Charged to shard 0: a key this could not hash has no
			 * shard of its own, and the miss still has to be
			 * counted somewhere the total will find it. */
			pthread_mutex_lock(&f->s[0].lock);
			f->s[0].st.misses++;
			pthread_mutex_unlock(&f->s[0].lock);
		}
		return 0;
	}
	h = hash_id(id, id_len);
	s = &f->s[shard_of(f, h)];
	slot = (uint32_t)h & s->mask;

	/*
	 * A LOOK-UP TAKES THE LOCK, AND THAT IS NOT AVOIDABLE BY BEING CLEVER.
	 *
	 * It reads an entry that another thread may be overwriting through
	 * eviction, and it WRITES - `used` is what keeps an entry alive, so a
	 * hit that did not record itself would make the thing most looked up
	 * the first thing dropped.
	 */
	pthread_mutex_lock(&s->lock);
	for (i = 0; i < KOF_PROBE; i++) {
		struct entry *e = &s->e[(slot + i) & s->mask];

		/*
		 * A free slot ends the run. Nothing here ever deletes an entry
		 * - eviction overwrites - so there are no tombstones and a hole
		 * genuinely means the key was never inserted.
		 */
		if (!e->h)
			break;
		if (same_id(e, h, id, id_len)) {
			e->used = ++s->tick;
			if (out)
				*out = e->v;
			s->st.hits++;
			found = 1;
			break;
		}
	}
	if (!found)
		s->st.misses++;
	pthread_mutex_unlock(&s->lock);
	return found;
}

/*
 * Which finding to keep, when the scan produced more than one.
 *
 * The worst, by kof_level_rank - which is the engine's own ordering and not a
 * second one invented here. A cache that kept the first would keep whichever
 * module happened to sit earliest in the database, and the answer would change
 * with a database update for no reason anybody could see.
 */
static void fill_verdict(struct koffridge_verdict *v,
			 const struct kof_result *res)
{
	uint32_t i, best = 0;
	int best_rank = -1;

	memset(v, 0, sizeof *v);
	if (!res)
		return;
	v->broken = res->broken;
	v->findings = res->n;
	if (!res->n)
		return;
	for (i = 0; i < res->n && i < KOF_MAX_FINDINGS; i++) {
		int r = kof_level_rank(res->v[i].level);

		if (r > best_rank) {
			best_rank = r;
			best = i;
		}
	}
	v->level = res->v[best].level;
	memcpy(v->name, res->v[best].name, sizeof v->name);
	v->name[sizeof v->name - 1] = '\0';
}

/*
 * The slot this identity should be written to, with the key already in place.
 *
 * EXTRACTED SO THERE IS ONE COPY OF IT. Two callers store entries now - a scan
 * reporting a verdict and a cache file being loaded - and the probe, the
 * "rescanned wins" rule and the eviction choice are subtle enough that a second
 * copy would be a second set of behaviours the moment either was touched. The
 * only thing the callers differ on is what they put in `v` and what they set
 * `used` to, so that is all they are left to do.
 *
 * NULL when the identity cannot be stored, with `refused` already counted.
 */
/*
 * The slot this identity should be written to, with the key already in place.
 *
 * TAKES A SHARD AND A HASH, NOT THE FRIDGE. Both callers have already chosen
 * the shard and taken its lock - and both have to, because the probe below
 * reads every entry in the run and may overwrite one. Passing the hash in
 * rather than recomputing it also keeps the shard choice and the slot choice
 * derived from the same number, which is the thing that must not drift.
 *
 * The caller holds `s->lock`. NULL when the identity cannot be stored, with
 * `refused` already counted.
 */
static struct entry *slot_for(struct shard *s, uint64_t h, const void *id,
			      uint32_t id_len)
{
	uint32_t i, slot, victim = 0;
	uint64_t victim_used = 0;
	int have_victim = 0;
	struct entry *e = NULL;

	slot = (uint32_t)h & s->mask;

	for (i = 0; i < KOF_PROBE; i++) {
		uint32_t at = (slot + i) & s->mask;

		e = &s->e[at];
		if (!e->h) {
			s->used++;
			s->st.used = s->used;
			goto claim;
		}
		if (same_id(e, h, id, id_len))
			return e;        /* rescanned: the newer answer wins */
		if (!have_victim || e->used < victim_used) {
			victim = at;
			victim_used = e->used;
			have_victim = 1;
		}
	}

	/*
	 * The run is full. Drop its least recently used entry rather than
	 * refusing, because a key that cannot be stored is a key that will miss
	 * for the rest of the walk - and the entry being dropped is by
	 * construction the one in this run that has gone longest unwanted.
	 */
	if (!have_victim) {
		s->st.refused++;
		return NULL;
	}
	e = &s->e[victim];
	s->st.evictions++;

claim:
	e->h = h;
	e->id_len = id_len;
	memcpy(e->id, id, id_len);
	if (id_len < KOFFRIDGE_ID_MAX)
		memset(e->id + id_len, 0, KOFFRIDGE_ID_MAX - id_len);
	return e;
}

int koffridge_put(struct koffridge *f, const void *id, uint32_t id_len,
		  const struct kof_result *res)
{
	struct shard *s;
	struct entry *e;
	uint64_t h;

	if (!f || !id || !id_len || id_len > KOFFRIDGE_ID_MAX) {
		if (f) {
			pthread_mutex_lock(&f->s[0].lock);
			f->s[0].st.refused++;
			pthread_mutex_unlock(&f->s[0].lock);
		}
		return 0;
	}
	h = hash_id(id, id_len);
	s = &f->s[shard_of(f, h)];

	pthread_mutex_lock(&s->lock);
	e = slot_for(s, h, id, id_len);
	if (e) {
		fill_verdict(&e->v, res);
		e->used = ++s->tick;
		s->st.stores++;
	}
	pthread_mutex_unlock(&s->lock);
	return e != NULL;
}

void koffridge_stats(struct koffridge *f, struct koffridge_stat *out)
{
	uint32_t i;

	if (!out)
		return;
	memset(out, 0, sizeof *out);
	if (!f)
		return;

	/*
	 * SUMMED SHARD BY SHARD, EACH UNDER ITS OWN LOCK.
	 *
	 * So the totals are not a torn read of counters another thread is
	 * incrementing. They are still not an INSTANT: by the time the last
	 * shard is added the first may have moved on. That is the right answer
	 * for what these are - a report of a walk, read when it is over - and
	 * stopping every thread to get a consistent snapshot would cost more
	 * than the number is worth.
	 */
	for (i = 0; i < f->n_shards; i++) {
		struct shard *s = &f->s[i];

		pthread_mutex_lock(&s->lock);
		out->hits      += s->st.hits;
		out->misses    += s->st.misses;
		out->stores    += s->st.stores;
		out->evictions += s->st.evictions;
		out->refused   += s->st.refused;
		out->used      += s->used;
		out->capacity  += s->cap;
		pthread_mutex_unlock(&s->lock);
	}
}

size_t koffridge_describe(struct koffridge *f, char *buf, size_t cap)
{
	struct koffridge_stat st;
	uint64_t look;
	int n;

	if (!buf || !cap)
		return 0;
	if (!f) {
		buf[0] = '\0';
		return 0;
	}
	koffridge_stats(f, &st);
	look = st.hits + st.misses;
	n = snprintf(buf, cap,
		     "fridge: %llu hit, %llu miss (%.1f%%), %llu stored, "
		     "%llu evicted, %u/%u used",
		     (unsigned long long)st.hits,
		     (unsigned long long)st.misses,
		     look ? (double)st.hits * 100.0 / (double)look : 0.0,
		     (unsigned long long)st.stores,
		     (unsigned long long)st.evictions,
		     st.used, st.capacity);
	if (n < 0)
		return 0;
	return (size_t)n < cap ? (size_t)n : cap - 1u;
}

/* ------------------------------------------------------------ persistence */

/*
 * "KRFG". The whole point of a magic is that a file which is not one is
 * refused before anything in it is believed, so it is checked first and the
 * version straight after.
 */
#define FILE_MAGIC   0x4746524bu
/*
 * TWO, because the KEY changed meaning.
 *
 * koffridge_identify now puts nanoseconds where it put seconds, so every entry
 * a version-1 file holds is keyed on a number this build would never compute.
 * Those entries are not wrong, they are unreachable - they would load, sit in
 * the table, and never match anything again.
 *
 * A cache that silently holds entries nobody can hit is worse than no cache:
 * it occupies the capacity the working set needs and reports a hit rate that
 * looks like a tuning problem. So the version refuses them, which is what the
 * field is for.
 */
#define FILE_VERSION 2u

/*
 * A CAP ON WHAT A FILE MAY ASK THIS TO ALLOCATE, and it is here because
 * n_entries is a number read out of a file.
 *
 * Nothing is allocated from it - entries are read one at a time into one
 * struct - so this only bounds how long a corrupt count can keep the loop
 * going. A file claiming four billion entries is refused rather than read
 * until it runs out.
 */
#define FILE_ENTRIES_MAX (1u << 22)

struct file_hdr {
	uint32_t magic;
	uint16_t version;
	uint16_t hdr_size;

	/*
	 * sizeof(struct entry), because the entries are written AS the structs
	 * they are. A build whose entry differs by one byte would read every
	 * field of every entry from the wrong place, and there is no way to
	 * notice that from the values - so it is refused on the size instead.
	 */
	uint32_t entry_size;
	uint32_t n_entries;

	/*
	 * THE DATABASE THESE VERDICTS CAME FROM. A mismatch discards the file,
	 * for the reason in the header: a database update can change any
	 * verdict in here, and most of all the clean ones.
	 */
	uint64_t db_stamp;

	/* FNV-1a over the entry array only. Catches a truncated write and a
	 * bad sector; see the header on why it is not security. */
	uint64_t sum;

	uint64_t reserved;
};

static uint64_t fnv(const void *p, size_t n, uint64_t h)
{
	const uint8_t *b = p;
	size_t i;

	for (i = 0; i < n; i++) {
		h ^= b[i];
		h *= 1099511628211ull;
	}
	return h;
}

#define FNV_SEED 1469598103934665603ull

int koffridge_save(struct koffridge *f, const char *path)
{
	struct file_hdr h;
	char tmp[1024];
	FILE *fp;
	uint32_t i, n = 0;
	uint64_t sum = FNV_SEED;

	if (!f || !path || !path[0])
		return 0;
	if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp)
		return 0;

	memset(&h, 0, sizeof h);
	h.magic      = FILE_MAGIC;
	h.version    = FILE_VERSION;
	h.hdr_size   = (uint16_t)sizeof h;
	h.entry_size = (uint32_t)sizeof(struct entry);
	/* n_entries and sum are filled after the entries are written - see
	 * below. The placeholder header is only there to reserve the space. */
	h.db_stamp   = f->db_stamp;

	/*
	 * WRITTEN BESIDE THE TARGET AND RENAMED OVER IT.
	 *
	 * A save that is interrupted - the machine goes down, the disk fills -
	 * must leave the PREVIOUS cache intact rather than half of this one.
	 * Half a cache is worse than none: the header would describe entries
	 * that are not there, and the checksum is the only thing standing
	 * between that and a table full of whatever the tail of the file was.
	 */
	/*
	 * ONE PASS, AND THE HEADER IS PATCHED AFTERWARDS.
	 *
	 * It used to count the entries, then checksum them, then write them -
	 * three walks of the table, which was fine while nothing else could
	 * touch it. With shards under their own locks it is not: another thread
	 * storing a verdict between the count and the write would leave a
	 * header describing a different number of entries than the file holds,
	 * and the reader would take the tail of the file as an entry.
	 *
	 * So the entries go out first, counted and summed as they go, and the
	 * header is written last over the space left for it. Each shard is held
	 * only while its own entries are written.
	 */
	fp = fopen(tmp, "wb");
	if (!fp)
		return 0;
	if (fwrite(&h, 1, sizeof h, fp) != sizeof h)
		goto bad;

	for (i = 0; i < f->n_shards; i++) {
		struct shard *s = &f->s[i];
		uint32_t j;
		int failed = 0;

		pthread_mutex_lock(&s->lock);
		for (j = 0; j < s->cap; j++) {
			if (!s->e[j].h)
				continue;
			if (fwrite(&s->e[j], 1, sizeof s->e[j], fp) !=
			    sizeof s->e[j]) {
				failed = 1;
				break;
			}
			sum = fnv(&s->e[j], sizeof s->e[j], sum);
			n++;
		}
		pthread_mutex_unlock(&s->lock);
		if (failed)
			goto bad;
	}

	h.n_entries = n;
	h.sum = sum;
	if (fseek(fp, 0, SEEK_SET) != 0)
		goto bad;
	if (fwrite(&h, 1, sizeof h, fp) != sizeof h)
		goto bad;
	if (fclose(fp) != 0)
		goto bad_closed;

	remove(path);            /* rename onto an existing file fails on
				  * Windows; removing first is what makes this
				  * one line portable */
	if (rename(tmp, path) != 0)
		goto bad_closed;
	return 1;

bad:
	fclose(fp);
bad_closed:
	remove(tmp);
	return 0;
}

uint32_t koffridge_load(struct koffridge *f, const char *path,
			const char **why)
{
	struct file_hdr h;
	FILE *fp;
	uint32_t i, got = 0;
	uint64_t sum = FNV_SEED;
	struct entry *buf;

	if (why)
		*why = "";
	if (!f || !path || !path[0]) {
		if (why)
			*why = "no cache path";
		return 0;
	}
	fp = fopen(path, "rb");
	if (!fp) {
		if (why)
			*why = "no cache yet";
		return 0;
	}
	if (fread(&h, 1, sizeof h, fp) != sizeof h) {
		fclose(fp);
		if (why)
			*why = "too short to hold a header";
		return 0;
	}
	if (h.magic != FILE_MAGIC) {
		fclose(fp);
		if (why)
			*why = "not a fridge file";
		return 0;
	}
	if (h.version != FILE_VERSION || h.hdr_size != sizeof h) {
		fclose(fp);
		if (why)
			*why = "written by a different version";
		return 0;
	}
	if (h.entry_size != sizeof(struct entry)) {
		fclose(fp);
		if (why)
			*why = "written by a build with a different entry";
		return 0;
	}
	/*
	 * THE ONE REFUSAL THAT IS NOT ABOUT CORRUPTION.
	 *
	 * Everything above says the file cannot be read. This says it can be
	 * read and must not be believed: different database, so every verdict
	 * in it was reached by rules this run does not have.
	 */
	if (h.db_stamp != f->db_stamp) {
		fclose(fp);
		if (why)
			*why = "database changed since it was written";
		return 0;
	}
	if (h.n_entries > FILE_ENTRIES_MAX) {
		fclose(fp);
		if (why)
			*why = "claims more entries than a cache can hold";
		return 0;
	}

	/*
	 * READ IT ALL BEFORE ADMITTING ANY OF IT, because the checksum covers
	 * the whole array and is the only thing that catches a truncated save.
	 * Inserting as it went would put half a cache into the table and then
	 * discover the half was all there was.
	 */
	buf = h.n_entries ? calloc(h.n_entries, sizeof *buf) : NULL;
	if (h.n_entries && !buf) {
		fclose(fp);
		if (why)
			*why = "out of memory";
		return 0;
	}
	for (i = 0; i < h.n_entries; i++) {
		if (fread(&buf[i], 1, sizeof *buf, fp) != sizeof *buf) {
			fclose(fp);
			free(buf);
			if (why)
				*why = "ends before the entries it declares";
			return 0;
		}
		sum = fnv(&buf[i], sizeof *buf, sum);
	}
	fclose(fp);

	if (sum != h.sum) {
		free(buf);
		if (why)
			*why = "checksum does not match - discarded whole";
		return 0;
	}

	/*
	 * Through the same slot search the live path uses, so a loaded entry is
	 * an ordinary entry in every respect - see slot_for.
	 *
	 * `used` is 0 rather than a tick: these are the OLDEST things in the
	 * table, so the first entry this run touches survives eviction ahead of
	 * any of them. A tick from the previous run would be a number from a
	 * different sequence.
	 *
	 * `stores` is put back afterwards. A loaded entry was not stored by
	 * this run, and counting it as one would make the summary claim work
	 * that the load is the whole point of not doing.
	 */
	for (i = 0; i < h.n_entries; i++) {
		uint64_t kh;
		struct shard *s;
		struct entry *e;

		if (!buf[i].h || !buf[i].id_len ||
		    buf[i].id_len > KOFFRIDGE_ID_MAX)
			continue;       /* the file disagrees with itself */

		kh = hash_id(buf[i].id, buf[i].id_len);
		s = &f->s[shard_of(f, kh)];

		pthread_mutex_lock(&s->lock);
		e = slot_for(s, kh, buf[i].id, buf[i].id_len);
		if (e) {
			e->v = buf[i].v;
			/*
			 * TERMINATE THE NAME, because nothing on this path has.
			 *
			 * koffridge_put does it on the way in - see the memcpy
			 * there - and the load did not, so the two ways an
			 * entry enters the table did not agree. A file whose
			 * name field holds 224 bytes with no NUL is then handed
			 * to a caller that prints it with %s: confirmed with
			 * AddressSanitizer as a 225-byte read past the end of
			 * the verdict.
			 *
			 * The file is a TRUST INPUT and the header above says
			 * so: the checksum catches a bad sector and stops
			 * nobody who edits the file on purpose. So this is not
			 * about corruption, it is about the case the threat
			 * model already admits.
			 */
			e->v.name[sizeof e->v.name - 1] = '\0';
			e->used = 0;
			got++;
		}
		pthread_mutex_unlock(&s->lock);
	}
	/*
	 * NO `stores` TO PUT BACK ANY MORE, and that is the sharding paying for
	 * itself rather than an omission.
	 *
	 * This used to snapshot the counter and restore it, because a loaded
	 * entry is not work this run did and counting it as a store would have
	 * the summary claim the very work the cache exists to avoid. The
	 * insertion above goes through slot_for, which counts evictions and
	 * refusals and NOT stores - only koffridge_put does that - so there is
	 * nothing to correct.
	 */
	free(buf);

	if (why)
		*why = got ? "loaded" : "held nothing usable";
	return got;
}

/* ---------------------------------------------------- where it lives */

/*
 * The per-user cache directory, created if missing - see the header for why
 * the location IS the safety property.
 */
int koffridge_default_path(char *buf, size_t cap)
{
	const char *home;
	char dir[768];
	int n;

	if (!buf || cap == 0)
		return 0;
	buf[0] = '\0';

#ifdef _WIN32
	/*
	 * LOCALAPPDATA rather than APPDATA: a cache is machine-local state and
	 * has no business following a roaming profile onto other machines,
	 * where its file identities - a volume serial and a file index - mean
	 * nothing at all and would miss on every lookup.
	 */
	home = getenv("LOCALAPPDATA");
	if (!home || !home[0])
		return 0;
	n = snprintf(dir, sizeof dir, "%s\\kofeng", home);
#else
	home = getenv("XDG_CACHE_HOME");
	if (home && home[0]) {
		n = snprintf(dir, sizeof dir, "%s/kofeng", home);
	} else {
		home = getenv("HOME");
		if (!home || !home[0])
			return 0;
		n = snprintf(dir, sizeof dir, "%s/.cache/kofeng", home);
	}
#endif
	if (n < 0 || (size_t)n >= sizeof dir)
		return 0;

	/*
	 * 0700, so the answer holds even on a system whose umask is generous.
	 * An existing directory is fine - what is NOT checked is whether it was
	 * already there with wider permissions, because a cache cannot repair a
	 * home directory somebody else can write, and pretending to would be
	 * worse than not claiming it.
	 */
	(void)kof_mkdir(dir, 0700);

	n = snprintf(buf, cap, "%s%ckofscan.fridge", dir, KOF_PATH_SEP);
	if (n < 0 || (size_t)n >= cap) {
		buf[0] = '\0';
		return 0;
	}
	return 1;
}

/* ============================ THE SAME FACT, SEEN AGAIN =================
 *
 * A SECOND TABLE IN THIS MODULE RATHER THAN A MODULE OF ITS OWN.
 *
 * It answers the same shape of question the verdict table does - "have I
 * already dealt with this" - over the same mechanism: open addressing, linear
 * probing, and eviction of the coldest entry in a probe run. What differs is
 * what an ENTRY MEANS, and those differences are properties of these calls
 * rather than of a separate component:
 *
 *   NO DATABASE STAMP. A verdict is only true of one signature build. Whether
 *   an event has happened before has nothing to do with which rules are
 *   loaded, so nothing here is thrown away when the database changes.
 *
 *   NOTHING IS WRITTEN TO DISK. A file identity survives a reboot and a
 *   verdict about it stays useful; "I have seen this event" must not, or the
 *   first event of a new session - the one that matters most - is suppressed
 *   by a memory of the last one.
 */


#define KFS_CAP_MIN     256u
#define KFS_CAP_MAX  262144u
#define KFS_PROBE        12u

/*
 * FILETIME ticks - 100ns - so this is thirty seconds.
 *
 * Chosen against what the window is FOR rather than by feel. Short enough that
 * a process re-establishing persistence shows up as a line every half minute
 * instead of one line for the whole run; long enough that a burst of the same
 * fact - the eight CreateKey records one nslookup produces - collapses to one.
 * A caller that wants another answer passes one.
 */
#define KFS_WINDOW_DEFAULT 300000000ull

/*
 * TWO HASHES, AND THEY MUST BE INDEPENDENT RATHER THAN TWO READS OF ONE.
 *
 * The identity is not stored - see the header - so the hash is the only
 * evidence that two things are the same, and one 64-bit value is one collision
 * away from suppressing a real event. A second hash over the same bytes with a
 * different seed AND a different multiplier is what makes a false match need
 * both to collide at once.
 *
 * Seeding alone would not be enough for FNV: with the same prime, two inputs
 * that collide under one seed tend to collide under another, because the
 * difference the seed introduces is carried through the same mixing. The
 * multiplier is what has to differ.
 */
static void hash2(const void *p, uint32_t n, uint64_t *a, uint64_t *b)
{
	const unsigned char *s = p;
	uint64_t h1 = 1469598103934665603ull;   /* FNV-1a offset basis */
	uint64_t h2 = 0x9e3779b97f4a7c15ull;    /* a different start... */
	uint32_t i;

	for (i = 0; i < n; i++) {
		h1 ^= s[i];
		h1 *= 1099511628211ull;         /* ...and a different prime */
		h2 ^= s[i];
		h2 *= 0x100000001b3ull ^ 0x2545f4914f6cdd1dull;
	}

	/*
	 * ZERO IS THE EMPTY SLOT, so a hash of zero would make an occupied
	 * entry read as free - and the entry it shadowed would be handed out
	 * to the next identity that probed past it. One value of four billion
	 * moved rather than a flag bit per entry.
	 */
	*a = h1 ? h1 : 1ull;
	*b = h2;
}

struct seen_ent {
	uint64_t h;       /* 0 when the slot is free */
	uint64_t h2;      /* the independent check - see hash2 */
	uint64_t first;   /* when this identity was first seen in this run */
	uint64_t last;    /* when it was last seen; the window is measured here */
	uint64_t used;    /* the tick it was last touched, for eviction */
	uint32_t count;   /* times seen inside the window, saturating */
	uint32_t pad;
};

struct koffridge_seen {
	struct seen_ent *e;
	uint32_t cap;
	uint32_t mask;
	uint32_t used;
	uint64_t tick;
	uint64_t window;
	struct koffridge_seen_stat st;
};

static uint32_t pow2(uint32_t v)
{
	uint32_t p = KFS_CAP_MIN;

	while (p < v && p < KFS_CAP_MAX)
		p <<= 1;
	return p;
}

struct koffridge_seen *koffridge_seen_open(uint32_t capacity, uint64_t window)
{
	struct koffridge_seen *s = calloc(1, sizeof *s);

	if (!s)
		return NULL;
	s->cap    = pow2(capacity ? capacity : 8192u);
	s->mask   = s->cap - 1u;
	s->window = window ? window : KFS_WINDOW_DEFAULT;
	s->e      = calloc(s->cap, sizeof *s->e);
	if (!s->e) {
		free(s);
		return NULL;
	}
	s->st.cap = s->cap;
	return s;
}

void koffridge_seen_close(struct koffridge_seen *s)
{
	if (!s)
		return;
	free(s->e);
	free(s);
}

void koffridge_seen_clear(struct koffridge_seen *s)
{
	if (!s)
		return;
	memset(s->e, 0, (size_t)s->cap * sizeof *s->e);
	s->used = 0;
	s->st.used = 0;
}

uint32_t koffridge_seen_mark(struct koffridge_seen *s, const void *id, uint32_t id_len,
		      uint64_t stamp)
{
	uint64_t a, b;
	uint32_t i, start, victim = 0;
	uint64_t coldest = ~0ull;
	struct seen_ent *e;

	if (!s || !id || !id_len)
		return 0;

	s->st.asked++;
	s->tick++;
	hash2(id, id_len, &a, &b);
	/*
	 * THE LOW BITS, AND THIS IS NOT INTERCHANGEABLE WITH THE HIGH ONES.
	 *
	 * FNV-1a mixes upward: every multiply carries entropy from the low end
	 * toward the high end, so for short inputs the top bits are dominated
	 * by the last few bytes and barely avalanche at all. Indexing on them
	 * clusters keys that share a suffix - which registry paths do, every
	 * one of them, because they are a long common prefix and a short tail.
	 *
	 * MEASURED, because the difference did not look like it would be large.
	 * 200k events over 2000 distinct identities in a table of 8192 - a load
	 * of a quarter, where nothing should ever be evicted:
	 *
	 *   indexed on a >> 32   71.5% suppressed, 56112 evictions
	 *   indexed on a         99.0% suppressed,     0 evictions
	 *
	 * koffridge already did it this way. The two tables were written months
	 * apart and only one of them was right; this comment is so the next one
	 * is not a third attempt.
	 */
	start = (uint32_t)a & s->mask;

	for (i = 0; i < KFS_PROBE; i++) {
		uint32_t k = (start + i) & s->mask;

		e = &s->e[k];

		if (!e->h) {
			/* A free slot ends the run: nothing was ever placed
			 * past it for this hash, so there is nothing further
			 * along to find. */
			e->h     = a;
			e->h2    = b;
			e->first = stamp;
			e->last  = stamp;
			e->used  = s->tick;
			e->count = 1u;
			s->used++;
			s->st.used = s->used;
			s->st.fresh++;
			return 0;
		}

		if (e->h == a && e->h2 == b) {
			uint32_t before;

			e->used = s->tick;

			/*
			 * PAST THE WINDOW IS FRESH AGAIN, and the count starts
			 * over rather than accumulating across windows. A
			 * number that mixed two windows would answer neither
			 * "how loud is this right now" nor "how long has it
			 * been going on" - `first` is what answers the second.
			 *
			 * SIGNED-SAFE ORDER COMPARISON: a stamp older than
			 * `last` means records arrived out of order, which they
			 * do - see the note at the top of kofevt.h. Subtracting
			 * the other way round would wrap to an enormous
			 * interval and call it fresh, so the test is written as
			 * a forward difference that only holds when time has
			 * actually moved on.
			 */
			if (stamp > e->last && stamp - e->last > s->window) {
				e->first = stamp;
				e->last  = stamp;
				e->count = 1u;
				s->st.fresh++;
				return 0;
			}

			if (stamp > e->last)
				e->last = stamp;
			before = e->count;
			if (e->count != 0xffffffffu)
				e->count++;
			s->st.repeat++;
			return before;
		}

		if (e->used < coldest) {
			coldest = e->used;
			victim  = k;
		}
	}

	/*
	 * THE PROBE RUN IS FULL: evict its coldest entry rather than growing or
	 * refusing.
	 *
	 * Which way this fails matters and only one direction is acceptable.
	 * Forgetting an identity makes its next occurrence read as FRESH - one
	 * duplicate reported, which is the noise this was reducing. The other
	 * direction would be to keep the old entry and suppress the new
	 * identity, which loses an event that never happened before. So the
	 * table is allowed to be less effective and never wrong.
	 */
	e = &s->e[victim];
	if (e->h)
		s->st.evicted++;
	e->h     = a;
	e->h2    = b;
	e->first = stamp;
	e->last  = stamp;
	e->used  = s->tick;
	e->count = 1u;
	s->st.fresh++;
	return 0;
}

void koffridge_seen_stats(const struct koffridge_seen *s, struct koffridge_seen_stat *out)
{
	if (!out)
		return;
	if (!s) {
		memset(out, 0, sizeof *out);
		return;
	}
	*out = s->st;
}
