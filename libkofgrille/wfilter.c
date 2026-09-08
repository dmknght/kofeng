/*
 * wfilter.c - see wfilter.h.
 *
 * No Windows API is used here on purpose: this is the half a replayed trace
 * runs through, and the replay path has to build on a host that has no ETW.
 */

#include <string.h>

#include "wfilter.h"

/* ---------------------------------------------------------- classification */

/* Case-insensitive substring, ASCII folding only, which is all these literals
 * need. */
static int has(const char *hay, const char *needle)
{
	size_t i, j;

	for (i = 0; hay[i]; i++) {
		for (j = 0; needle[j]; j++) {
			char a = hay[i + j], b = needle[j];

			if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
			if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
			if (a != b)
				break;
		}
		if (!needle[j])
			return 1;
	}
	return 0;
}

const char *kofw_loc_name(uint8_t loc)
{
	switch (loc) {
	case KOFW_LOC_SYSTEM:   return "system";
	case KOFW_LOC_PROGRAMS: return "programs";
	case KOFW_LOC_TEMP:     return "temp";
	case KOFW_LOC_USER:     return "user";
	case KOFW_LOC_OTHER:    return "other";
	default:                return "unknown";
	}
}

uint8_t kofw_classify_path(const char *path)
{
	if (!path || !*path)
		return KOFW_LOC_UNKNOWN;

	/*
	 * TEMP IS TESTED FIRST, and the order is the whole correctness of this
	 * function.
	 *
	 * The per-user temp directory lives INSIDE a user profile
	 * (\Users\<name>\AppData\Local\Temp), so a check for \Users\ that ran
	 * first would swallow it and every dropper's first write would be filed
	 * as ordinary user activity. Longest and most specific wins, always.
	 */
	if (has(path, "\\AppData\\Local\\Temp\\") ||
	    has(path, "\\Windows\\Temp\\") ||
	    /*
	     * The 8.3 spelling of the same place. ETW delivers long device paths
	     * on every build measured here, so this has never yet been the
	     * matching branch - it is present because a path that arrives short
	     * would otherwise be classified as something else entirely, and that
	     * failure would be silent.
	     */
	    has(path, "\\APPDAT~1\\LOCAL~1\\Temp\\") ||
	    has(path, "\\LOCALS~1\\Temp\\"))
		return KOFW_LOC_TEMP;

	if (has(path, "\\Windows\\System32\\")     ||
	    has(path, "\\Windows\\SysWOW64\\")     ||
	    /* The two extra system directories an ARM64 machine has: SyChpe32
	     * holds the compiled-hybrid x86 binaries and SysArm32 the ARM32
	     * ones. Leaving them out made every x86 process on such a host look
	     * like it was loading unknown modules. */
	    has(path, "\\Windows\\SyChpe32\\")     ||
	    has(path, "\\Windows\\SysArm32\\")     ||
	    has(path, "\\Windows\\WinSxS\\")       ||
	    has(path, "\\Windows\\assembly\\")     ||
	    has(path, "\\Windows\\Microsoft.NET\\"))
		return KOFW_LOC_SYSTEM;

	if (has(path, "\\Program Files\\") ||
	    has(path, "\\Program Files (x86)\\") ||
	    has(path, "\\PROGRA~1\\") || has(path, "\\PROGRA~2\\"))
		return KOFW_LOC_PROGRAMS;

	if (has(path, "\\Users\\"))
		return KOFW_LOC_USER;

	return KOFW_LOC_OTHER;
}

/* --------------------------------------------------------- the process table */

void kofw_ptab_init(struct kofw_ptab *t)
{
	memset(t, 0, sizeof *t);
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
		memset(t->e, 0, sizeof t->e);
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
		      struct kofw_evt *e)
{
	const char *obj;
	int scoped = f && f->root_pid != 0;
	struct kofw_pent *p;

	/*
	 * Classify THE OBJECT ONLY, and leave UNKNOWN when there is none.
	 *
	 * Falling back to the subject's image looked like a free improvement and
	 * is a trap: filter.drop_loc is tested against this field, so a caller
	 * dropping KOFW_LOC_SYSTEM to hide the modules every process loads would
	 * also have dropped the ProcessStart of every program that lives in
	 * System32 - which is most of them. The two are different questions and
	 * only one of them has an answer here.
	 *
	 * Done on this side rather than in the decode because it is string work
	 * and the decode runs in the ETW callback, which is the one piece of
	 * code the whole machine pays for.
	 */
	obj = kofw_evt_object(e);
	e->obj_loc = *obj ? kofw_classify_path(obj) : KOFW_LOC_UNKNOWN;

	/*
	 * MEMBERSHIP BEFORE FILTERING, always.
	 *
	 * A ProcessStart is about a pid the set has by definition not heard of,
	 * and is admitted on its PARENT. Filtering first would refuse the very
	 * record that grows the tree, and the tree would never grow past its
	 * root.
	 */
	if (e->type == KOFW_EVT_PROC_START) {
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
	} else if (e->type == KOFW_EVT_PROC_STOP) {
		p = kofw_ptab_of(t, e->pid, e->create_time);
		if (p && p->alive) {
			p->alive = 0;
			if (p->tracked && t->n_alive_tracked)
				t->n_alive_tracked--;
		}
	}

	if (!f)
		return 1;

	if (f->types && !(f->types & (1u << e->type)))
		return 0;

	if (f->drop_loc && (f->drop_loc & (1u << e->obj_loc)))
		return 0;

	if (scoped) {
		/* Judged on the SUBJECT, which for a file or network event is
		 * the process that acted. */
		p = kofw_ptab_of(t, e->pid,
				 e->type == KOFW_EVT_PROC_START ||
				 e->type == KOFW_EVT_PROC_STOP
					 ? e->create_time : 0);
		if (!p || !p->tracked)
			return 0;
	}

	return 1;
}
