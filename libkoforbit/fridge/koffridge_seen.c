/*
 * koffridge_seen.c - the duplicate-event table: "have I already dealt with this
 * event". See koffridge.h, "the same fact, seen again". The verdict cache it
 * shares a mechanism with is koffridge.c; this half is apart from it because it
 * needs none of the engine (stdint and stdlib, and the neutral event record), is
 * never written to disk, and is not stamped by a database - so a collector that
 * only wants this takes no verdict code with it.
 */
#ifndef _WIN32
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <string.h>

#include "koffridge.h"
/* koffridge_seen_evt reads the neutral record - see koffridge.h. */
#include "../evt/kofevt.h"

#include "../../libkofeng/kofcore/kofcore.h"
#include "../../libkofeng/kofcore/kofplatform.h"

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
	uint64_t h1 = KOF_HASH64_INIT;          /* FNV-1a offset basis */
	uint64_t h2 = 0x9e3779b97f4a7c15ull;    /* a different start... */
	uint32_t i;

	for (i = 0; i < n; i++) {
		h1 = kof_hash64_step(h1, s[i]);  /* ...and a different prime */
		h2 ^= s[i];
		/*
		 * A DIFFERENT, AND ODD, MULTIPLIER.
		 *
		 * This was `0x100000001b3 ^ 0x2545f4914f6cdd1d`, meant to be
		 * "a different prime" - but that XOR evaluates to
		 * 0x2545f5914f6cdcae, which is EVEN. A multiplicative hash with
		 * an even multiplier is not invertible mod 2^64: every multiply
		 * clears one more low bit, so h2's low bits collapse to zero as
		 * the input grows. That guts the whole reason for a second
		 * hash - a false "already seen" is supposed to need both h and
		 * h2 to collide, and an h2 whose low bits are constant collides
		 * far more often than 64 bits would. A known-good odd constant
		 * restores it.
		 */
		h2 *= 0x880355f21e6d1965ull;
	}

	/*
	 * ZERO IS THE EMPTY SLOT, so a hash of zero would make an occupied
	 * entry read as free - and the entry it shadowed would be handed out
	 * to the next identity that probed past it. One value of four billion
	 * moved rather than a flag bit per entry.
	 */
	*a = kof_hash64_nz(h1);
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

/*
 * THE IDENTITY OF A NEUTRAL RECORD - see the note in koffridge.h.
 *
 * Built into a local buffer and hashed by koffridge_seen_mark, so nothing here
 * is stored. The object text is taken through kof_evt_object, which bounds it
 * against the record's arena; the data is taken as raw bytes with its own
 * length, because a registry value is not a string.
 */
uint32_t koffridge_seen_evt(struct koffridge_seen *s, const struct kof_evt *e)
{
	unsigned char id[512];
	size_t n = 0;
	const char *obj;

	if (!s || !e)
		return 0;

#define ID_PUT(src, len)                                                      \
	do {                                                                  \
		size_t l_ = (len);                                            \
		if (l_ > sizeof id - n)                                       \
			l_ = sizeof id - n;                                   \
		memcpy(id + n, (src), l_);                                    \
		n += l_;                                                      \
	} while (0)

	ID_PUT(&e->verb, sizeof e->verb);
	ID_PUT(&e->actor_pid, sizeof e->actor_pid);

	/*
	 * THE OBJECT, FOLDED THE WAY ITS OWN PLATFORM COMPARES PATHS.
	 *
	 * This is the one field where identical treatment would be a BUG
	 * rather than a simplification, and it is why this function is
	 * allowed to be platform specific at all: the fridge is orbit's, and
	 * orbit is where a host's policy lives.
	 *
	 *   WINDOWS compares paths without case and accepts either separator,
	 *   so C:\X\a.exe and c:/x/A.EXE are ONE file. Hashing the bytes as
	 *   they arrived makes them two identities, and a program writing one
	 *   file through two spellings would be suppressed by neither.
	 *
	 *   POSIX does not. /X/a and /x/A are two files, and folding them
	 *   would suppress a real event because a different file happened to
	 *   differ only in case - a silence with nothing to say it happened.
	 *
	 * So the fold is the platform's, and the two are not made to agree.
	 * (libkoforbit/grille's own older kofw_evt_ident hashes the bytes raw on
	 * both counts; a collector moved onto this one gains the fold rather
	 * than losing anything.)
	 */
	obj = kof_evt_object(e);
	if (obj && *obj) {
#ifdef _WIN32
		size_t k, l = strlen(obj);

		for (k = 0; k < l && n < sizeof id; k++) {
			unsigned char c = (unsigned char)obj[k];

			if (c >= 'A' && c <= 'Z')
				c = (unsigned char)(c + 32);
			else if (c == '\\')
				c = '/';
			id[n++] = c;
		}
#else
		ID_PUT(obj, strlen(obj));
#endif
	}

	/*
	 * AND WHAT WAS WRITTEN, when the record carries it. Bounded against
	 * the arena the same way every other reader of off_data is - the
	 * record may have come from a log file, and a length that walks past
	 * text[] is a length a file can claim.
	 */
	if (e->data_len && e->off_data != KOF_TEXT_NONE &&
	    e->off_data < sizeof e->text) {
		size_t dn = e->data_len;

		if (dn > sizeof e->text - e->off_data)
			dn = sizeof e->text - e->off_data;
		ID_PUT(e->text + e->off_data, dn);
	}
#undef ID_PUT

	return koffridge_seen_mark(s, id, (uint32_t)n, e->stamp);
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
