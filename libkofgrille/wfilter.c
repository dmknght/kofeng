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
/* The path classifier and the technique table moved to libkofeng/kofevt: they
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
		t->n = 0;
		t->recycled++;
	}

	s = fslot(key);
	for (i = 0; i < KOFW_FTAB_MAX; i++) {
		struct kofw_fent *e = &t->e[(s + i) % KOFW_FTAB_MAX];
		size_t k;

		if (e->key && e->key != key)
			continue;
		if (!e->key) {
			t->n++;
			e->key = key;
		}
		for (k = 0; k + 1 < sizeof e->name && name[k]; k++)
			e->name[k] = name[k];
		e->name[k] = '\0';
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
			return e->name;
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
		if (image) {
			size_t k;
			for (k = 0; k + 1 < sizeof p->image && image[k]; k++)
				p->image[k] = image[k];
			p->image[k] = '\0';
		}
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

int kofw_filter_apply(struct kofw_ptab *t, const struct kofw_filter *f,
		      struct kofw_evt *e, uint8_t *why)
{
	const char *obj;
	int scoped = f && f->root_pid != 0;
	struct kofw_pent *p;

	if (why)
		*why = KOFW_REFUSE_NONE;

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
		if (p && p->mods_whole && !p->mods_full &&
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
