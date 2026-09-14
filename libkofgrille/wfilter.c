/*
 * wfilter.c - see wfilter.h.
 *
 * No Windows API is used here on purpose: this is the half a replayed trace
 * runs through, and the replay path has to build on a host that has no ETW.
 */

#include <string.h>

#include "kofevt.h"
#include "wfilter.h"

/* ---------------------------------------------------------- classification */

/*
 * Substring, with case folding AS AN ARGUMENT - and it has to be an argument.
 *
 * Windows compares paths without regard to case, so `\windows\system32\` and
 * `\WINDOWS\SYSTEM32\` are the same directory and a matcher that folded
 * neither would be evaded by pressing shift. Linux compares paths WITH regard
 * to case, so /etc/PASSWD is a different file from /etc/passwd - and a matcher
 * that folded both would report a technique against a file that is not the one
 * the technique is about.
 *
 * Folding everything was the bug this parameter fixes. There is no single
 * answer that is right for both, so the table says per row, and the row knows
 * because a row is written for one platform.
 *
 * ASCII folding only, which is all these literals need: every one of them is
 * an ASCII path component chosen by Microsoft or by a distribution, and a
 * locale-aware fold would only introduce the Turkish dotless-i problem to a
 * comparison that has no use for it.
 */
/* The path classifier and the technique table moved to libkoforbit/kofevt: they
 * are string work with no OS in them and they describe an EVENT, not a way of
 * collecting one. See kofevt.h. */

/* ------------------------------------------------------ FileKey -> path */

void kofw_ftab_init(struct kofw_ftab *t)
{
	memset(t, 0, sizeof *t);
}

/* Knuth's multiplicative hash over the pointer, probed linearly. A collision
 * costs a step and never a wrong answer: an entry is believed only when the
 * key matches exactly. */
static uint32_t fslot(uint64_t key)
{
	return (uint32_t)((key >> 3) * 2654435761u) % KOFW_FTAB_MAX;
}

void kofw_ftab_add(struct kofw_ftab *t, uint64_t key, const char *name)
{
	uint32_t i, s;

	if (!t || !key || !name || !*name)
		return;

	/* Half full, because linear probing degrades badly past that and this
	 * runs on every name record, which is every file the machine opens. */
	if (t->n >= KOFW_FTAB_MAX / 2u) {
		memset(t->e, 0, sizeof t->e);
		/* The pool goes with the entries. Every offset into it has just
		 * been cleared, and a pool that kept growing across recycles
		 * would fill on its own and force a second recycle for no
		 * reason. */
		t->names_used = 0;
		t->n = 0;
		t->recycled++;
	}

	s = fslot(key);
	for (i = 0; i < KOFW_FTAB_MAX; i++) {
		struct kofw_fent *e = &t->e[(s + i) % KOFW_FTAB_MAX];
		size_t n = 0, room;

		if (e->key && e->key != key)
			continue;
		if (!e->key) {
			t->n++;
			e->key = key;
		}

		while (n < KOFW_FNAME_MAX - 1u && name[n])
			n++;
		if (name[n])
			t->name_cuts++;

		/*
		 * ALREADY STORED, SO NOTHING IS APPENDED.
		 *
		 * This is not an optimisation, it is what makes an append-only
		 * pool affordable here at all: kofw_ftab_add runs on every file
		 * the machine opens, and the same key arrives with the same name
		 * over and over. Appending each time would exhaust the pool in
		 * seconds and force a recycle that throws away every name in it.
		 */
		if (e->len == n &&
		    (size_t)e->off + n < sizeof t->names &&
		    !memcmp(t->names + e->off, name, n))
			return;

		room = sizeof t->names - t->names_used;
		if (n + 1u > room) {
			/*
			 * The pool is full before the table was. Recycling the
			 * table is what frees it - every entry goes at once, so
			 * no offset is left pointing in - and it is the policy
			 * this table already has for being full. Counted,
			 * because a run that does it often is a run whose pool
			 * is too small for the machine.
			 */
			t->names_full++;
			memset(t->e, 0, sizeof t->e);
			t->names_used = 0;
			t->n = 0;
			t->recycled++;
			return;
		}
		memcpy(t->names + t->names_used, name, n);
		t->names[t->names_used + n] = '\0';
		e->off = t->names_used;
		e->len = (uint16_t)n;
		t->names_used += (uint32_t)(n + 1u);
		return;
	}
}

static const char *ftab_find(struct kofw_ftab *t, uint64_t key)
{
	uint32_t i, s;

	if (!t || !key)
		return NULL;
	s = fslot(key);
	for (i = 0; i < KOFW_FTAB_MAX; i++) {
		const struct kofw_fent *e = &t->e[(s + i) % KOFW_FTAB_MAX];

		/* Nothing is ever removed, so an empty slot means absent
		 * rather than further along. */
		if (!e->key)
			return NULL;
		if (e->key == key)
			return e->len && (size_t)e->off + e->len < sizeof t->names
			     ? t->names + e->off : NULL;
	}
	return NULL;
}

int kofw_ftab_resolve(struct kofw_ftab *t, struct kofw_evt *e)
{
	const char *name;
	size_t n, room;

	if (!t || !e)
		return 0;
	/* A record that already has a path keeps it - a name record is its own
	 * answer and must not be overwritten by a lookup of itself. */
	if (e->off_object != KOF_TEXT_NONE || !e->addr)
		return 0;

	name = ftab_find(t, e->addr);
	if (!name || !*name) {
		t->unresolved++;
		return 0;
	}

	/*
	 * Appended on the CONSUMER thread, into whatever the decode left.
	 * Never in the callback: this is a table walk and a copy, and the
	 * callback is the one piece of code the whole machine pays for.
	 */
	if (e->text_len + 1u >= sizeof e->text)
		return 0;
	room = sizeof e->text - e->text_len;
	n = strlen(name);
	if (n + 1u > room) {
		n = room - 1u;
		e->flags |= KOF_EF_TRUNCATED;
	}
	memcpy(e->text + e->text_len, name, n);
	e->text[e->text_len + n] = '\0';
	e->off_object = e->text_len;
	e->text_len   = (uint16_t)(e->text_len + n + 1u);

	/* The field is no longer missing, and saying so is the point: the
	 * record used to arrive flagged PARTIAL with KOF_F_OBJECT set, which
	 * is what a reader saw as [miss 0x40]. */
	e->miss &= ~(uint32_t)KOF_F_OBJECT;
	if (!e->miss)
		e->flags &= (uint8_t)~KOF_EF_PARTIAL;
	t->resolved++;
	return 1;
}

/* --------------------------------------------------------- the process table */

void kofw_ptab_init(struct kofw_ptab *t)
{
	/* unsigned, not uint16_t: `i + 1` promotes to int, and comparing that
	 * against an unsigned bound is a signedness mismatch the tree builds
	 * with -Wsign-compare to catch. */
	unsigned i;

	memset(t, 0, sizeof *t);

	/* Chain the module-range pool into one free list. */
	for (i = 0; i + 1u < KOFW_MODBLK_MAX; i++)
		t->blk[i].next = (uint16_t)(i + 1);
	t->blk[KOFW_MODBLK_MAX - 1].next = KOFW_MODBLK_NONE;
	t->blk_free = 0;
}

/* ------------------------------------------------- where images are mapped */

static void mods_release(struct kofw_ptab *t, struct kofw_pent *p)
{
	uint16_t b = p->mods, next;

	while (b != KOFW_MODBLK_NONE && b < KOFW_MODBLK_MAX) {
		next = t->blk[b].next;
		t->blk[b].n    = 0;
		t->blk[b].next = t->blk_free;
		t->blk_free    = b;
		b = next;
	}
	p->mods      = KOFW_MODBLK_NONE;
	p->mods_full = 0;
}

static void mods_add(struct kofw_ptab *t, struct kofw_pent *p, uint64_t base,
		     uint64_t size)
{
	struct kofw_modblk *blk;

	/*
	 * A MODULE LOAD THAT COULD NOT BE RECORDED WITHDRAWS THE NEGATIVE
	 * CLAIM. It used to just return.
	 *
	 * This is the bug behind a false <<UNBACKED: entry point in no mapped
	 * image>>. A module whose base or size did not decode - ImageSize not
	 * reached because the shape truncated, or spelled differently on some
	 * build - was silently left out of the list while the list went on
	 * claiming to be whole. Every thread that then started inside that
	 * module was in no KNOWN range, so the collector concluded it was in no
	 * range at all, and reported an injection that had not happened.
	 *
	 * The rule the pool exhaustion below already follows: an incomplete
	 * list cannot support "this address is in no image". So mods_full is
	 * set here too - it is the flag that says the negative claim is off -
	 * and the loss is counted so a run can show it happened.
	 *
	 * A false UNBACKED is the worst kind of finding this collector can
	 * produce: it names a specific process as being injected into, on
	 * evidence that is an absence, and the absence was ours.
	 */
	if (!base || !size) {
		p->mods_full = 1;
		t->mod_undecoded++;
		return;
	}

	if (p->mods != KOFW_MODBLK_NONE && p->mods < KOFW_MODBLK_MAX &&
	    t->blk[p->mods].n < KOFW_MODS_PER_BLK) {
		blk = &t->blk[p->mods];
	} else {
		uint16_t b = t->blk_free;

		if (b == KOFW_MODBLK_NONE) {
			/* Out of pool. The list is now incomplete, so it can no
			 * longer support a negative claim - see mods_whole. */
			t->mod_exhausted++;
			p->mods_full = 1;
			return;
		}
		t->blk_free = t->blk[b].next;
		blk         = &t->blk[b];
		blk->n      = 0;
		blk->next   = p->mods;
		p->mods     = b;
	}

	blk->base[blk->n] = base;
	blk->size[blk->n] = size > 0xffffffffu ? 0xffffffffu : (uint32_t)size;
	blk->n++;
}

/*
 * Is `addr` inside any image this process was watched mapping.
 *
 * An unmapped module is NOT removed from the list, deliberately. Keeping a
 * stale range can only make an address look backed when it is not, which
 * suppresses a report; dropping it could make a live module look absent and
 * manufacture one. Between a missed detection and a fabricated one, this errs
 * toward the first.
 */
static int mods_contain(const struct kofw_ptab *t, const struct kofw_pent *p,
			uint64_t addr)
{
	uint16_t b = p->mods;

	while (b != KOFW_MODBLK_NONE && b < KOFW_MODBLK_MAX) {
		const struct kofw_modblk *blk = &t->blk[b];
		uint8_t i;

		for (i = 0; i < blk->n; i++) {
			if (addr >= blk->base[i] &&
			    addr - blk->base[i] < blk->size[i])
				return 1;
		}
		b = blk->next;
	}
	return 0;
}

/* The basename, which is what a name column wants. The full path stays on the
 * record - this table is for reporting, not for matching. */
static const char *leaf(const char *p)
{
	const char *last = p;

	for (; *p; p++) {
		if (*p == '\\' || *p == '/')
			last = p + 1;
	}
	return last;
}

static uint32_t slot_of(uint32_t pid)
{
	/* Knuth's multiplicative hash, probed linearly. A collision costs a step
	 * and never a wrong answer: an entry is believed only when the pid
	 * matches, and the caller checks create_time on top of that. */
	return (pid * 2654435761u) % KOFW_PTAB_MAX;
}

struct kofw_pent *kofw_ptab_find(struct kofw_ptab *t, uint32_t pid)
{
	uint32_t i, s = slot_of(pid);

	for (i = 0; i < KOFW_PTAB_MAX; i++) {
		struct kofw_pent *p = &t->e[(s + i) % KOFW_PTAB_MAX];

		if (!p->used)
			return NULL;
		if (p->pid == pid)
			return p;
	}
	return NULL;
}

/*
 * PUT ONE IMAGE PATH IN THE POOL AND POINT THE ENTRY AT IT.
 *
 * APPEND ONLY, never rewritten in place, because an entry being refreshed must
 * not disturb the offsets already handed to every other entry. The cost of that
 * is that re-adding the same pid spends the pool again; the alternative is a
 * free list inside a string arena, which is an allocator, and this table exists
 * to be cheaper than the thing it replaces.
 *
 * Two ways it can fall short and both are said rather than hidden: a path
 * longer than KOFW_IMAGE_MAX is cut and flagged, and a pool with no room left
 * leaves the entry with no name at all. The second is the honest failure -
 * a missing name is a column a reader cannot fill, where a name that is
 * silently somebody else's would be a column they would believe.
 */
static void name_put(struct kofw_ptab *t, struct kofw_pent *p,
		     const char *image)
{
	size_t n = 0, room;

	p->image_off = 0;
	p->image_len = 0;
	p->image_cut = 0;
	if (!image || !*image)
		return;

	while (n < KOFW_IMAGE_MAX - 1u && image[n])
		n++;
	if (image[n]) {
		p->image_cut = 1u;
		t->image_cuts++;
	}

	room = sizeof t->names - t->names_used;
	if (n + 1u > room) {
		t->names_full++;
		return;
	}
	memcpy(t->names + t->names_used, image, n);
	t->names[t->names_used + n] = '\0';
	p->image_off = t->names_used;
	p->image_len = (uint16_t)n;
	t->names_used += (uint32_t)(n + 1u);
}

const char *kofw_pent_image(const struct kofw_ptab *t,
			    const struct kofw_pent *p)
{
	if (!t || !p || !p->image_len ||
	    (size_t)p->image_off + p->image_len >= sizeof t->names)
		return "";
	return t->names + p->image_off;
}

struct kofw_pent *kofw_ptab_add(struct kofw_ptab *t, uint32_t pid,
				uint64_t create_time, const char *image,
				int recycle)
{
	uint32_t i, s = slot_of(pid);

	/* Half full, because linear probing degrades badly past that and this is
	 * on the path of every process start. */
	if (t->n >= KOFW_PTAB_MAX / 2u) {
		if (!recycle) {
			t->overflow++;
			return NULL;
		}
		/*
		 * Recycling drops every entry, so every module block they held
		 * has to go back to the pool - otherwise it leaks away one
		 * recycle at a time and the detector quietly stops working.
		 */
		unsigned k;

		memset(t->e, 0, sizeof t->e);
		/* Every entry is cleared in the statement above, so nothing
		 * points into the pool any more and it starts again. This is
		 * the ONLY moment those offsets may all be invalidated. */
		t->names_used = 0;
		for (k = 0; k + 1u < KOFW_MODBLK_MAX; k++) {
			t->blk[k].n    = 0;
			t->blk[k].next = (uint16_t)(k + 1);
		}
		t->blk[KOFW_MODBLK_MAX - 1].n    = 0;
		t->blk[KOFW_MODBLK_MAX - 1].next = KOFW_MODBLK_NONE;
		t->blk_free = 0;

		t->n = 0;
		t->n_alive_tracked = 0;
	}

	for (i = 0; i < KOFW_PTAB_MAX; i++) {
		struct kofw_pent *p = &t->e[(s + i) % KOFW_PTAB_MAX];

		if (p->used && p->pid != pid)
			continue;
		if (!p->used) {
			t->n++;
			p->used = 1;
			p->pid  = pid;
			/*
			 * NOT ZERO. Zero is a legal block index, so an entry
			 * left as memset gave it would claim to own the first
			 * block of the pool and read back whatever ranges some
			 * other process had put there.
			 */
			p->mods = KOFW_MODBLK_NONE;
		}
		p->create_time = create_time;
		p->alive       = 1;
		if (image)
			name_put(t, p, image);
		return p;
	}
	return NULL;
}

struct kofw_pent *kofw_ptab_of(struct kofw_ptab *t, uint32_t pid,
			       uint64_t create_time)
{
	struct kofw_pent *p = kofw_ptab_find(t, pid);

	if (!p || !p->used)
		return NULL;
	if (create_time && p->create_time && p->create_time != create_time)
		return NULL;
	return p;
}

/* ---------------------------------------------------------------- the filter */

/*
 * The decision itself. Split from kofw_filter_apply so that recording it
 * cannot be forgotten: the answer is needed by the NEXT record when that one
 * is a continuation, and this function has six ways out.
 */
static int filter_decide(struct kofw_ptab *t, const struct kofw_filter *f,
			 struct kofw_evt *e, uint8_t *why)
{
	const char *obj;
	int scoped = f && f->root_pid != 0;
	struct kofw_pent *p;

	if (why)
		*why = KOFW_REFUSE_NONE;

	/*
	 * A CONTINUATION FOLLOWS ITS PARENT AND IS ASKED NOTHING.
	 *
	 * Its `object` is CONTENT - the middle of a script block - and running
	 * kof_classify over that would be asking which directory a fragment of
	 * PowerShell lives in. The answer would be noise, and worse than noise
	 * on the day the fragment happens to contain the text of a Run key: the
	 * chunk would come out carrying an ATT&CK technique it has no business
	 * asserting, and something downstream would report it.
	 *
	 * So: no classification, no membership test, no policy. It goes exactly
	 * where the record in front of it went.
	 */
	if (e->type == KOF_EVT_CONT) {
		e->obj_loc = KOF_LOC_UNKNOWN;
		e->attack  = KOF_ATT_NONE;
		if (!t->last_kept && why)
			*why = KOFW_REFUSE_PARENT;
		return t->last_kept;
	}

	/*
	 * Classify THE OBJECT ONLY, and leave UNKNOWN when there is none.
	 *
	 * Falling back to the subject's image looked like a free improvement and
	 * is a trap: filter.drop_loc is tested against this field, so a caller
	 * dropping KOF_LOC_SYSTEM to hide the modules every process loads would
	 * also have dropped the ProcessStart of every program that lives in
	 * System32 - which is most of them. The two are different questions and
	 * only one of them has an answer here.
	 *
	 * Done on this side rather than in the decode because it is string work
	 * and the decode runs in the ETW callback, which is the one piece of
	 * code the whole machine pays for.
	 */
	obj = kofw_evt_object(e);
	if (*obj) {
		uint16_t att = KOF_ATT_NONE;

		e->obj_loc = kof_classify(obj, &att);
		e->attack  = att;
	} else {
		e->obj_loc = KOF_LOC_UNKNOWN;
		e->attack  = KOF_ATT_NONE;
	}

	/*
	 * MEMBERSHIP BEFORE FILTERING, always.
	 *
	 * A ProcessStart is about a pid the set has by definition not heard of,
	 * and is admitted on its PARENT. Filtering first would refuse the very
	 * record that grows the tree, and the tree would never grow past its
	 * root.
	 */
	if (e->type == KOF_EVT_PROC_START) {
		int is_kin = !scoped;

		if (scoped) {
			struct kofw_pent *par = kofw_ptab_of(t, e->ppid, 0);
			is_kin = (e->pid == f->root_pid) ||
				 (par && par->tracked);
		}

		p = kofw_ptab_add(t, e->pid, e->create_time,
				  leaf(kofw_evt_image(e)), !scoped);
		if (p && is_kin && !p->tracked) {
			p->tracked = 1;
			t->n_alive_tracked++;
		}
		if (p) {
			/*
			 * The module list starts here and is therefore whole:
			 * every image this process ever maps is downstream of
			 * this event. A process the session did not see start
			 * never gets this bit, and so never gets a verdict.
			 */
			mods_release(t, p);
			p->mods_whole = 1;
		}
	} else if (e->type == KOF_EVT_PROC_STOP) {
		p = kofw_ptab_of(t, e->pid, e->create_time);
		if (p && p->alive) {
			p->alive = 0;
			if (p->tracked && t->n_alive_tracked)
				t->n_alive_tracked--;
		}
		if (p) {
			mods_release(t, p);
			p->mods_whole = 0;
		}
	} else if (e->type == KOF_EVT_IMAGE_LOAD) {
		p = kofw_ptab_of(t, e->pid, 0);
		if (p) {
			mods_add(t, p, e->addr, e->addr_size);

			/*
			 * A module mapped long after the process started.
			 *
			 * Both values are FILETIME, so this is a subtraction
			 * and not a conversion. The comparison is guarded
			 * against a stamp older than the creation time rather
			 * than assumed: records arrive up to a flush timer
			 * late and out of order across CPUs, and an unsigned
			 * subtraction the wrong way round would produce an
			 * enormous positive and flag everything.
			 */
			if (p->mods_whole && p->create_time &&
			    e->stamp > p->create_time &&
			    e->stamp - p->create_time > KOFW_LATE_LOAD_TICKS) {
				e->flags |= KOFW_EF_LATE_LOAD;
				t->late_loads++;
			}
		}
	} else if (e->type == KOF_EVT_THREAD_START && e->addr) {
		p = kofw_ptab_of(t, e->pid, 0);
		/*
		 * THE ONE PLACE THE COLLECTOR SAYS SOMETHING IT WAS NOT TOLD.
		 *
		 * Every other field on a record is a value some provider
		 * supplied. This one is a conclusion drawn from two of them -
		 * where images were mapped, and where a thread began - and it
		 * is drawn here rather than left to a consumer because only the
		 * collector has both, and only it knows whether the module list
		 * is complete enough for the answer to mean anything.
		 */
		/*
		 * AN EMPTY LIST CANNOT SUPPORT THE NEGATIVE CLAIM EITHER, and
		 * leaving that out produced a false UNBACKED on the FIRST
		 * THREAD OF EVERY PROCESS.
		 *
		 * mods_whole says this session saw the process start, so every
		 * image it ever maps is downstream of that record. That is true
		 * about the STREAM and not about the ORDER: ETW buffers are per
		 * processor, records cross CPUs out of order, and an ImageLoad
		 * that happened before the ProcessStart in real time can be
		 * DELIVERED after it. When it is delivered first,
		 * kofw_ptab_of() has no entry for the pid yet and the module is
		 * not recorded; then ProcessStart arrives, mods_release()
		 * empties the list, and mods_whole goes up over nothing.
		 *
		 * The next record is the main thread starting at the
		 * executable's entry point, `mods_contain` is asked about an
		 * empty list, and it answers no. Measured: dns.kevt flagged the
		 * first thread of both cmd.exe and PING.EXE, which is two
		 * injections reported in a trace of `ping`.
		 *
		 * Every Windows process maps at least ntdll, so an empty list
		 * is a list of loads that were MISSED, never a process with no
		 * modules - and this is the same withdrawal mods_full already
		 * performs one function up, for the same reason. A manually
		 * mapped payload still loads ntdll, so nothing real is lost.
		 */
		if (p && p->mods_whole && !p->mods_full &&
		    p->mods != KOFW_MODBLK_NONE &&
		    !mods_contain(t, p, e->addr)) {
			e->flags |= KOFW_EF_UNBACKED;
			t->unbacked++;
		}
	}

	if (!f)
		return 1;

	if (f->types && !(f->types & (1u << e->type))) {
		if (why)
			*why = KOFW_REFUSE_TYPE;
		return 0;
	}

	if (f->drop_loc && (f->drop_loc & (1u << e->obj_loc))) {
		if (why)
			*why = KOFW_REFUSE_LOC;
		return 0;
	}

	if (scoped &&
	    !(f->scope_exempt_prov & (1u << e->provider))) {
		/* Judged on the SUBJECT, which for a file or network event is
		 * the process that acted. */
		p = kofw_ptab_of(t, e->pid,
				 e->type == KOF_EVT_PROC_START ||
				 e->type == KOF_EVT_PROC_STOP
					 ? e->create_time : 0);
		if (!p || !p->tracked) {
			if (why)
				*why = KOFW_REFUSE_SCOPE;
			return 0;
		}
	}

	return 1;
}

/*
 * WHICH VERBS MAY BE COLLAPSED WHEN THEY REPEAT, and this list is the whole
 * safety of the deduplicator. Getting it wrong does not produce noise - it
 * destroys evidence, silently, in a way no counter reveals.
 *
 * The test is: IS A REPEAT OF THIS THE SAME FACT RESTATED, OR A NEW FACT THAT
 * HAPPENS TO LOOK LIKE THE OLD ONE?
 *
 * YES - the same fact restated:
 *
 *   THE REGISTRY VERBS, which is where the volume is. Kernel-Registry is the
 *   most expensive provider in this collector by a wide margin and most of
 *   that is one fact repeated: one nslookup produces EIGHT identical CreateKey
 *   records for a single key, and it only ever reads it.
 *
 *   A FILE APPEARING, being unlinked, or being renamed. The file either exists
 *   or it does not; the second record saying it appeared says nothing new.
 *
 *   A MODULE LOAD, which repeats across processes - and there the pid is part
 *   of the identity, so the same DLL into a different process is not a repeat.
 *
 * NO - and each of these was considered and refused for a specific reason:
 *
 *   FILE_WRITE. Two writes of the same length at the same offset are two
 *   writes. The identity does not carry the offset or the length, so they would
 *   collapse, and a payload written in a loop would report one write.
 *
 *   NET_SEND and NET_RECV. Repetition is QUANTITATIVE here: the tally sums
 *   their sizes, so suppressing repeats would silently understate how many
 *   bytes left the machine.
 *
 *   NET_CONNECT and DNS_QUERY. Repetition IS the detection. A beacon is the
 *   same connection to the same address at a regular interval, and collapsing
 *   that would delete the one property that identifies it. These are noisy and
 *   they are noisy in the way that matters.
 *
 *   PROC_START and PROC_STOP. Never duplicates by construction - the identity
 *   carries (pid, create_time), which is what makes two processes different.
 *   Listing them would cost a hash per process start and match nothing.
 *
 *   A CONTINUATION, which is not an event at all: it is the tail of the record
 *   in front of it, and suppressing one truncates a submission mid-way.
 */
static int may_collapse(uint16_t type)
{
	switch (type) {
	case KOF_EVT_REG_CREATE:
	case KOF_EVT_REG_SET_VALUE:
	case KOF_EVT_REG_DELETE:
	case KOF_EVT_FILE_NEW:
	case KOF_EVT_FILE_DELETE:
	case KOF_EVT_FILE_RENAME:
	case KOF_EVT_IMAGE_LOAD:
	case KOF_EVT_IMAGE_UNLOAD:
		return 1;
	default:
		return 0;
	}
}

/*
 * THE TYPES WHOSE CHURN MAY BE COLLAPSED PER PROCESS, not per object.
 *
 * The registry three, and only them, because they are the measured problem:
 * kofgrille.h calls this provider the most expensive here by a wide margin,
 * and the bulk of it is services restating their own state. A file appearing
 * is not that - it is low volume and every one of them is a distinct fact.
 */
static int may_collapse_coarse(uint16_t type)
{
	return type == KOF_EVT_REG_CREATE ||
	       type == KOF_EVT_REG_SET_VALUE ||
	       type == KOF_EVT_REG_DELETE;
}

/*
 * IS THIS OBJECT SOMEWHERE A RULE COULD CARE ABOUT.
 *
 * The question asked INSTEAD of "is this process noisy", and the difference is
 * the whole safety of coarse collapsing.
 *
 * Keying the reduction on WHO acted - a service, a trusted executable - builds
 * the blind spot every living-off-the-land technique is designed to land in:
 * the answer stops depending on what was done and starts depending on what was
 * running, and an attacker chooses what is running. Keying it on WHERE the
 * write landed cannot be chosen that way. A service that spends all day
 * restating its own configuration is collapsed; the same service the moment it
 * touches a Run key is not, because the key is what changed, not the process.
 *
 * THE BOUNDARY IS ALREADY DRAWN AND IS NOT A SECOND LIST TO MAINTAIN.
 * kof_evt_loc says it in so many words: everything from KOF_LOC_AUTOSTART to
 * KOF_LOC_HOSTS is an ATT&CK technique. TEMP and PIPE are added because they
 * are not techniques by themselves and are where a dropper writes and how one
 * process makes another act for it - the two places kofgrille.h already singles
 * out. Extending the reach of this is one row in the LOCS table, which is where
 * every other consumer of that classification gets better too.
 */
static int object_matters(const struct kofw_evt *e)
{
	if (e->attack != KOF_ATT_NONE)
		return 1;
	if (e->obj_loc >= KOF_LOC_AUTOSTART && e->obj_loc <= KOF_LOC_HOSTS)
		return 1;
	return e->obj_loc == KOF_LOC_TEMP || e->obj_loc == KOF_LOC_PIPE;
}

size_t kofw_evt_ident(const struct kofw_evt *e, void *buf, size_t cap,
		      int *coarse)
{
	unsigned char *p = buf;
	size_t n = 0;
	const char *obj;
	int wide;

	if (coarse)
		*coarse = 0;
	if (!e || !p || !cap || !may_collapse(e->type))
		return 0;

	/*
	 * COARSE MEANS THE OBJECT IS LEFT OUT, so everything this process did
	 * of this kind, to anywhere unremarkable, is ONE entry instead of
	 * thousands.
	 *
	 * That is a trade and it is made deliberately: the table is a shared
	 * bounded resource and eviction does not know one event type from
	 * another, so a service restating its configuration all day evicts the
	 * entries of everything else. Bounding the noise at (process x verb)
	 * is what leaves room for the events that are worth remembering
	 * precisely.
	 *
	 * WHAT IT COSTS, stated rather than discovered: a second write to a
	 * DIFFERENT unremarkable key by the same process, inside the window, is
	 * suppressed. That is the blind spot, it is bounded to objects the
	 * classifier does not recognise, and it is counted - see `coarse`.
	 */
	wide = may_collapse_coarse(e->type) && !object_matters(e);
	if (coarse)
		*coarse = wide;

#define IDENT_PUT(src, len)                                                   \
	do {                                                                  \
		size_t l_ = (len);                                            \
		if (n + l_ > cap)                                             \
			l_ = cap - n;                                         \
		memcpy(p + n, (src), l_);                                     \
		n += l_;                                                      \
	} while (0)

	/*
	 * THE VERB AND THE PROVIDER FIRST, so a path that two providers both
	 * report cannot collapse across them - a file and a registry key can
	 * spell the same string and mean different objects.
	 */
	IDENT_PUT(&e->type, sizeof e->type);
	IDENT_PUT(&e->provider, sizeof e->provider);

	/*
	 * THE SUBJECT AS A PAIR, never the pid alone. Windows reuses pids
	 * quickly, and an identity of pid alone would let a new process inherit
	 * the suppression earned by whatever held that number before it - which
	 * is the exact confusion kofw_evt.create_time exists to prevent.
	 */
	IDENT_PUT(&e->pid, sizeof e->pid);
	IDENT_PUT(&e->create_time, sizeof e->create_time);

	/*
	 * AND THE OBJECT, unless this is the coarse form - in which case the
	 * identity stops at the actor and the verb, which is exactly what makes
	 * it one entry instead of thousands.
	 */
	if (wide)
		goto done;

	obj = kofw_evt_object(e);
	if (obj && *obj)
		IDENT_PUT(obj, strlen(obj));

	/*
	 * WHERE A MODULE LANDED, for the image verbs ONLY.
	 *
	 * Two loads of one module into one process at DIFFERENT bases are two
	 * facts, and without the base they collapse into one. The rundown
	 * duplicates this exists to collapse all carry the same base, so
	 * including it loses none of the reduction.
	 *
	 * SCOPED TO THESE TWO VERBS BECAUSE `addr` IS A BORROWED FIELD. On a
	 * file event it holds the FileKey - a kernel pointer that can differ
	 * between two records naming the same file - so folding it in
	 * unconditionally would make file identities never match and turn the
	 * collapser off for half the verbs it is meant to serve, silently.
	 */
	if (e->type == KOF_EVT_IMAGE_LOAD || e->type == KOF_EVT_IMAGE_UNLOAD)
		IDENT_PUT(&e->addr, sizeof e->addr);

	/*
	 * AND WHAT WAS WRITTEN, when the event wrote something.
	 *
	 * Without this, setting one Run value to two different commands is one
	 * identity and the second write disappears - which is precisely the
	 * write worth seeing, because it is the one that changed something.
	 */
	if (e->data_len && e->off_data != KOF_TEXT_NONE)
		IDENT_PUT(e->text + e->off_data, e->data_len);

done:
#undef IDENT_PUT
	return n;
}

int kofw_filter_apply(struct kofw_ptab *t, const struct kofw_filter *f,
		      struct kofw_evt *e, uint8_t *why)
{
	int keep;

	if (!t || !e)
		return 0;
	keep = filter_decide(t, f, e, why);
	/*
	 * REMEMBERED FOR THE NEXT RECORD, and only for a record that had a
	 * decision to make. A continuation inherited this answer; writing its
	 * own inheritance back over it would be harmless today and wrong the
	 * moment a chain is longer than one chunk, because the parent's answer
	 * has to survive the whole chain.
	 */
	if (e->type != KOF_EVT_CONT)
		t->last_kept = keep ? 1u : 0u;
	return keep;
}
