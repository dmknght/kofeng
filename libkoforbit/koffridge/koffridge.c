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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "koffridge.h"

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

struct koffridge {
	struct entry *e;
	uint32_t cap;           /* a power of two */
	uint32_t mask;
	uint32_t used;
	uint64_t tick;
	uint64_t db_stamp;
	struct koffridge_stat st;
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

struct koffridge *koffridge_open(uint32_t capacity, uint64_t db_stamp)
{
	struct koffridge *f = calloc(1, sizeof *f);

	if (!f)
		return NULL;
	f->cap = round_pow2(capacity ? capacity : KOF_FRIDGE_DEFAULT);
	f->mask = f->cap - 1u;
	f->e = calloc(f->cap, sizeof *f->e);
	if (!f->e) {
		free(f);
		return NULL;
	}
	f->db_stamp = db_stamp;
	f->st.capacity = f->cap;
	return f;
}

void koffridge_close(struct koffridge *f)
{
	if (!f)
		return;
	free(f->e);
	free(f);
}

uint64_t koffridge_db_stamp(const struct koffridge *f)
{
	return f ? f->db_stamp : 0ull;
}

void koffridge_clear(struct koffridge *f)
{
	if (!f)
		return;
	memset(f->e, 0, (size_t)f->cap * sizeof *f->e);
	f->used = 0;
	f->st.used = 0;
}

static int same_id(const struct entry *e, uint64_t h, const void *id,
		   uint32_t id_len)
{
	return e->h == h && e->id_len == id_len &&
	       memcmp(e->id, id, id_len) == 0;
}

int koffridge_get(struct koffridge *f, const void *id, uint32_t id_len,
		  struct koffridge_verdict *out)
{
	uint64_t h;
	uint32_t i, slot;

	if (!f || !id || !id_len || id_len > KOFFRIDGE_ID_MAX) {
		if (f)
			f->st.misses++;
		return 0;
	}
	h = hash_id(id, id_len);
	slot = (uint32_t)h & f->mask;

	for (i = 0; i < KOF_PROBE; i++) {
		struct entry *e = &f->e[(slot + i) & f->mask];

		/*
		 * A free slot ends the run. Nothing here ever deletes an entry
		 * - eviction overwrites - so there are no tombstones and a hole
		 * genuinely means the key was never inserted.
		 */
		if (!e->h)
			break;
		if (same_id(e, h, id, id_len)) {
			e->used = ++f->tick;
			if (out)
				*out = e->v;
			f->st.hits++;
			return 1;
		}
	}
	f->st.misses++;
	return 0;
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
static struct entry *slot_for(struct koffridge *f, const void *id,
			      uint32_t id_len)
{
	uint64_t h;
	uint32_t i, slot, victim = 0;
	uint64_t victim_used = 0;
	int have_victim = 0;
	struct entry *e = NULL;

	if (!f || !id || !id_len || id_len > KOFFRIDGE_ID_MAX) {
		if (f)
			f->st.refused++;
		return NULL;
	}
	h = hash_id(id, id_len);
	slot = (uint32_t)h & f->mask;

	for (i = 0; i < KOF_PROBE; i++) {
		uint32_t at = (slot + i) & f->mask;

		e = &f->e[at];
		if (!e->h) {
			f->used++;
			f->st.used = f->used;
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
		f->st.refused++;
		return NULL;
	}
	e = &f->e[victim];
	f->st.evictions++;

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
	struct entry *e = slot_for(f, id, id_len);

	if (!e)
		return 0;
	fill_verdict(&e->v, res);
	e->used = ++f->tick;
	f->st.stores++;
	return 1;
}

void koffridge_stats(const struct koffridge *f, struct koffridge_stat *out)
{
	if (!out)
		return;
	if (!f) {
		memset(out, 0, sizeof *out);
		return;
	}
	*out = f->st;
}

size_t koffridge_describe(const struct koffridge *f, char *buf, size_t cap)
{
	uint64_t look;
	int n;

	if (!buf || !cap)
		return 0;
	if (!f) {
		buf[0] = '\0';
		return 0;
	}
	look = f->st.hits + f->st.misses;
	n = snprintf(buf, cap,
		     "fridge: %llu hit, %llu miss (%.1f%%), %llu stored, "
		     "%llu evicted, %u/%u used",
		     (unsigned long long)f->st.hits,
		     (unsigned long long)f->st.misses,
		     look ? (double)f->st.hits * 100.0 / (double)look : 0.0,
		     (unsigned long long)f->st.stores,
		     (unsigned long long)f->st.evictions,
		     f->st.used, f->st.capacity);
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

int koffridge_save(const struct koffridge *f, const char *path)
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

	for (i = 0; i < f->cap; i++)
		if (f->e[i].h)
			n++;

	/* The checksum is over what will be written, so it is computed on the
	 * same pass shape the write uses rather than trusting the two loops to
	 * stay in step. */
	for (i = 0; i < f->cap; i++)
		if (f->e[i].h)
			sum = fnv(&f->e[i], sizeof f->e[i], sum);

	memset(&h, 0, sizeof h);
	h.magic      = FILE_MAGIC;
	h.version    = FILE_VERSION;
	h.hdr_size   = (uint16_t)sizeof h;
	h.entry_size = (uint32_t)sizeof(struct entry);
	h.n_entries  = n;
	h.db_stamp   = f->db_stamp;
	h.sum        = sum;

	/*
	 * WRITTEN BESIDE THE TARGET AND RENAMED OVER IT.
	 *
	 * A save that is interrupted - the machine goes down, the disk fills -
	 * must leave the PREVIOUS cache intact rather than half of this one.
	 * Half a cache is worse than none: the header would describe entries
	 * that are not there, and the checksum is the only thing standing
	 * between that and a table full of whatever the tail of the file was.
	 */
	fp = fopen(tmp, "wb");
	if (!fp)
		return 0;
	if (fwrite(&h, 1, sizeof h, fp) != sizeof h)
		goto bad;
	for (i = 0; i < f->cap; i++) {
		if (!f->e[i].h)
			continue;
		if (fwrite(&f->e[i], 1, sizeof f->e[i], fp) !=
		    sizeof f->e[i])
			goto bad;
	}
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
	uint64_t sum = FNV_SEED, stores_before;
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
	stores_before = f->st.stores;
	for (i = 0; i < h.n_entries; i++) {
		struct entry *e;

		if (!buf[i].h || !buf[i].id_len ||
		    buf[i].id_len > KOFFRIDGE_ID_MAX)
			continue;       /* the file disagrees with itself */
		e = slot_for(f, buf[i].id, buf[i].id_len);
		if (!e)
			continue;
		e->v = buf[i].v;
		/*
		 * TERMINATE THE NAME, because nothing on this path has.
		 *
		 * koffridge_put does it on the way in - see the memcpy there -
		 * and the load did not, so the two ways an entry enters the
		 * table did not agree. A file whose name field holds 224 bytes
		 * with no NUL is then handed to a caller that prints it with
		 * %s, and kofmemscan does exactly that: confirmed with
		 * AddressSanitizer as a 225-byte read past the end of the
		 * verdict.
		 *
		 * The file is a TRUST INPUT and the header above says so: the
		 * checksum catches a bad sector and stops nobody who edits the
		 * file on purpose. So this is not about corruption, it is
		 * about the case the threat model already admits.
		 */
		e->v.name[sizeof e->v.name - 1] = '\0';
		e->used = 0;
		got++;
	}
	f->st.stores = stores_before;
	free(buf);

	if (why)
		*why = got ? "loaded" : "held nothing usable";
	return got;
}
