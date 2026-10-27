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
 * queue in libkofeng/scanners/scan.c - and because every target that
 * compiles this file already links -pthread. On Windows that resolves through
 * winpthreads, statically, for the reason the Makefile gives beside the flag.
 */
#include <pthread.h>

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

#include "../../libkofeng/kofeng.h"
#include "koffridge.h"
/* koffridge_seen_evt reads the neutral record - see koffridge.h. */
#include "../evt/kofevt.h"

/* kof_mkdir and KOF_PATH_SEP - the two things a default path needs and the
 * one place this tree already says how they differ per platform. */
#include "../../libkofeng/kofcore/kofcore.h"
#include "../../libkofeng/kofcore/kofplatform.h"

/*
 * NOTHING IN THIS FILE IS PLATFORM-DEPENDENT ANY MORE.
 *
 * It used to hold koffridge_identify, one #ifdef over stat and
 * GetFileInformationByHandle, and that was the whole of the platform in here.
 * It is gone: the identity a file has is kof_fid_of's answer, declared in
 * fidset.h and defined per platform beside the collector that knows the
 * platform. See the note above struct koffridge in the header for what the
 * duplicate cost while both existed.
 *
 * What is left is a hash table over opaque keys, and it compiles the same
 * everywhere.
 */

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
	return kof_hash64_nz(kof_hash64_bytes(p, n));
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
 * What to keep of a scan: the object's verdict, which the engine made
 * (kof_result.verdict). `findings` is 1 for an object that has one, so an object
 * with a verdict is never mistaken for a clean one.
 */
static void fill_verdict(struct koffridge_verdict *v,
			 const struct kof_result *res)
{
	memset(v, 0, sizeof *v);
	if (!res)
		return;
	v->broken = res->broken;
	v->findings = res->has_verdict ? 1u : 0u;
	if (!res->has_verdict)
		return;
	/*
	 * COPIED TO THE NUL AND NOT BY THE FIELD'S SIZE.
	 *
	 * Both arrays are 224 bytes, so a memcpy of the whole field read
	 * nothing it should not - but it copied the TAIL as well as the name.
	 * kof_verdict_name terminates at the length it wrote and leaves
	 * everything after it as whatever the result buffer held, and that
	 * buffer is reused from object to object. The entry then goes to disk
	 * whole, so the previous object's verdict name travelled into the
	 * cache file behind this one's NUL.
	 *
	 * The struct was zeroed at the top of this function; a bounded string
	 * copy leaves those zeros in place.
	 */
	snprintf(v->name, sizeof v->name, "%s", res->verdict.name);
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
 * The identity put nanoseconds where it had put seconds, so every entry a
 * version-1 file holds is keyed on a number this build would never compute.
 * Those entries are not wrong, they are unreachable - they would load, sit in
 * the table, and never match anything again.
 *
 * A cache that silently holds entries nobody can hit is worse than no cache:
 * it occupies the capacity the working set needs and reports a hit rate that
 * looks like a tuning problem. So the version refuses them, which is what the
 * field is for.
 *
 * AND IT STAYED AT TWO WHEN KOFFRIDGE_ID_MAX WENT FROM 48 TO 56, which is
 * worth saying because the obvious move was to bump it again.
 *
 * This field is for a change the file cannot otherwise show: the key means
 * something new while looking identical. Widening the id is not that. It
 * changes sizeof(struct entry), the header carries entry_size, and the load
 * refuses a mismatch with a reason of its own - so the file is already
 * rejected, by the check that describes the actual difference. Bumping the
 * version as well would add a second refusal for one cause and a worse
 * message: "written by a different version" where "written by a build with a
 * different entry" is the true one.
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


int koffridge_save(struct koffridge *f, const char *path)
{
	struct file_hdr h;
	char tmp[1024];
	FILE *fp;
	uint32_t i, n = 0;
	uint64_t sum = KOF_HASH64_INIT;

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
	/*
	 * CREATED, NOT OPENED, AND ONLY IF THE NAME WAS FREE.
	 *
	 * fopen(tmp, "wb") followed a symlink and took its permissions from
	 * the umask. The name is "<the cache>.tmp", which anybody can predict,
	 * and the cache path is the CALLER'S - kofscanner takes --cache-file -
	 * so it need not be in a directory only this user can write. Planting
	 * that name as a link to something else made the save write there
	 * instead. kof_fopen_new refuses a name that already exists, link
	 * included, and creates with 0600.
	 */
	fp = kof_fopen_new(tmp);
	if (!fp) {
		/* A stale one from an interrupted save is ours to clear; a
		 * name that reappears after that is not an accident. */
		remove(tmp);
		fp = kof_fopen_new(tmp);
	}
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
			sum = kof_hash64_update(sum, &s->e[j], sizeof s->e[j]);
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

	/*
	 * ONE STEP, so the name never stops existing.
	 *
	 * This used to remove the target and then rename onto it, because
	 * rename over an existing file fails on Windows. On POSIX it does not
	 * fail, and the remove opened a window in which the cache path was
	 * free for somebody else to create - as a link, pointing anywhere.
	 * kof_rename_over replaces in one call on both platforms.
	 */
	if (!kof_rename_over(tmp, path))
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
	uint64_t sum = KOF_HASH64_INIT;
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
	/* KNOWN DEFECT WP12-11 (2026-10-24, M) [sev M]: koffridge_load callocs
	 * h.n_entries entries before looking at the file size. Trigger: a
	 * 40-byte file whose header claims 4194304 entries. Effect: about 1280
	 * MiB allocated, then the read fails. Reproducer: fuzz orbit/fridge_file
	 * (FZ_MAY_HIT_CAP). Fix: refuse n_entries * sizeof *buf > the file
	 * length. */
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
		sum = kof_hash64_update(sum, &buf[i], sizeof *buf);
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

#ifndef _WIN32
/*
 * IS THE DIRECTORY OURS AND PRIVATE. Opened first, then asked about by the
 * handle, so the answer is about the directory that will be used and not about
 * a name that may have been swapped since. A cache directory that somebody else
 * owns, or that group or world may write, is one in which anyone can plant a
 * cache that declares their own payload clean - and a served hit looks exactly
 * like a file that was examined. So a directory that fails this is not used:
 * the caller carries on WITHOUT persistence, which is slower and not unsafe.
 *
 * (This was the check of the retired libkoforbit/path module; the Windows
 * equivalent is a DACL check and is not written.)
 */
static int dir_is_private(const char *path)
{
	struct stat st;
	int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

	if (fd < 0)
		return 0;
	if (fstat(fd, &st) != 0) {
		close(fd);
		return 0;
	}
	close(fd);
	return S_ISDIR(st.st_mode) && st.st_uid == geteuid() &&
	       !(st.st_mode & (S_IWGRP | S_IWOTH));
}
#endif

/*
 * The per-user cache directory, created if missing - see the header for why
 * the location IS the safety property.
 */
int koffridge_default_path(char *buf, size_t cap)
{
	char base[768];
	char dir[768];
	int n;

	if (!buf || cap == 0)
		return 0;
	buf[0] = '\0';

	/*
	 * THE SYSTEM IS ASKED, NOT THE ENVIRONMENT.
	 *
	 * This read LOCALAPPDATA on Windows and XDG_CACHE_HOME then HOME
	 * elsewhere. All three are environment variables, and a LIBRARY that
	 * reads them takes its idea of where the user lives from whatever the
	 * host process happened to be started with - which is the host's
	 * decision to make, not this code's. They are also unvalidated input:
	 * a service started with a planted HOME wrote its cache wherever the
	 * planter chose, and the cache is a file this code later trusts.
	 *
	 * kof_user_cache_dir asks the platform instead - the passwd database
	 * and the real user id on POSIX, SHGetFolderPathA with
	 * CSIDL_LOCAL_APPDATA on Windows. LOCAL and not roaming, for the
	 * reason the old comment gave and which still holds: a cache keyed on
	 * a volume serial and a file index means nothing on another machine.
	 */
	if (!kof_user_cache_dir(base, sizeof base))
		return 0;
#ifdef _WIN32
	n = snprintf(dir, sizeof dir, "%s\\kofeng", base);
#else
	n = snprintf(dir, sizeof dir, "%s/kofeng", base);
#endif
	if (n < 0 || (size_t)n >= sizeof dir)
		return 0;

	/*
	 * 0700, so the answer holds even on a system whose umask is generous.
	 * An existing directory is accepted only if it is ours and not writable
	 * by group or world (dir_is_private): the cache does not repair a
	 * directory somebody else can write, and it does not use one either.
	 */
	(void)kof_mkdir(dir, 0700);
#ifndef _WIN32
	if (!dir_is_private(dir))
		return 0;
#endif

	n = snprintf(buf, cap, "%s%ckofscan.fridge", dir, KOF_PATH_SEP);
	if (n < 0 || (size_t)n >= cap) {
		buf[0] = '\0';
		return 0;
	}
	return 1;
}
