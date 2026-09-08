/*
 * wfilter.c - see wfilter.h.
 *
 * No Windows API is used here on purpose: this is the half a replayed trace
 * runs through, and the replay path has to build on a host that has no ETW.
 */

#include <string.h>

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
static int has_ci(const char *hay, const char *needle, int fold)
{
	size_t i, j;

	for (i = 0; hay[i]; i++) {
		for (j = 0; needle[j]; j++) {
			char a = hay[i + j], b = needle[j];

			if (fold) {
				if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
				if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
			}
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
	case KOFW_LOC_SYSTEM:     return "system";
	case KOFW_LOC_PROGRAMS:   return "programs";
	case KOFW_LOC_TEMP:       return "temp";
	case KOFW_LOC_USER:       return "user";
	case KOFW_LOC_AUTOSTART:  return "autostart";
	case KOFW_LOC_SERVICE:    return "service";
	case KOFW_LOC_SCHEDULE:   return "schedule";
	case KOFW_LOC_SHELL_INIT: return "shellinit";
	case KOFW_LOC_PRELOAD:    return "preload";
	case KOFW_LOC_SSH:        return "ssh";
	case KOFW_LOC_CREDENTIAL: return "credential";
	case KOFW_LOC_KERNEL_MOD: return "kmod";
	case KOFW_LOC_WEB_ROOT:   return "webroot";
	case KOFW_LOC_HOSTS:      return "hosts";
	case KOFW_LOC_PIPE:       return "pipe";
	case KOFW_LOC_OTHER:      return "other";
	default:                  return "unknown";
	}
}

const char *kofw_attack_id(uint16_t att)
{
	switch (att) {
#define KOFW_ATT_X_ID(name, tech, word) case name: return tech;
	KOFW_ATTACK_LIST(KOFW_ATT_X_ID)
#undef KOFW_ATT_X_ID
	default: return "";
	}
}

const char *kofw_attack_name(uint16_t att)
{
	switch (att) {
#define KOFW_ATT_X_NAME(name, tech, word) case name: return word;
	KOFW_ATTACK_LIST(KOFW_ATT_X_NAME)
#undef KOFW_ATT_X_NAME
	default: return "";
	}
}

/*
 * THE TABLE, AND WHY ITS ORDER IS ITS CORRECTNESS.
 *
 * One pass, first match wins, MOST SPECIFIC FIRST. That is not a style
 * preference, it is the only ordering that is right, and the reason is one
 * example: the per-user temp directory lives INSIDE a user profile, so a
 * \Users\ row that ran before \AppData\Local\Temp\ would swallow it and every
 * dropper's first write would be filed as ordinary user activity. Every row
 * below is placed by that rule and nothing may be appended without checking it.
 *
 * BOTH PLATFORMS IN ONE TABLE, because a path is unambiguous about which one it
 * is - a backslash row cannot match a Linux path and a /etc row cannot match a
 * Windows one - and two tables would be two places to forget a row.
 *
 * The technique is the ATT&CK id this path IS. Where a row has one, an event
 * that WRITES to it is a finding on its own with no chain and no window behind
 * it: T1547.001 is a value under Run, T1053.005 is a file under System32\Tasks.
 * Where a row has KOFW_ATT_NONE the location is still worth knowing and is not
 * itself a finding.
 */
static const struct {
	const char *needle;
	uint8_t     loc;
	uint16_t    att;
	/*
	 * 1 for a Windows path, 0 for a Linux one. Not derived from the
	 * separator, even though every row happens to agree with it: a derived
	 * rule is one somebody has to re-derive when they add a row, and this
	 * is the field that decides whether /etc/PASSWD is a finding.
	 */
	uint8_t     fold;
} LOCS[] = {
	/*
	 * A PIPE BEFORE ANYTHING ELSE, because \Device\NamedPipe\ is not
	 * under any of the directories below and a row that matched it later
	 * would never be reached anyway - but putting it first says that a
	 * pipe is not a file in a place, it is a different kind of object.
	 */
	{ "\\Device\\NamedPipe\\", KOFW_LOC_PIPE, KOFW_ATT_PIPE_IMPERSONATE, 1 },
	{ "\\pipe\\", KOFW_LOC_PIPE, KOFW_ATT_PIPE_IMPERSONATE, 1 },

	/* ---- temp, FIRST, for the reason above ---------------------------- */
	{ "\\AppData\\Local\\Temp\\", KOFW_LOC_TEMP, KOFW_ATT_NONE, 1 },
	{ "\\Windows\\Temp\\", KOFW_LOC_TEMP, KOFW_ATT_NONE, 1 },
	{ "\\APPDAT~1\\LOCAL~1\\Temp\\", KOFW_LOC_TEMP, KOFW_ATT_NONE, 1 },
	{ "\\LOCALS~1\\Temp\\", KOFW_LOC_TEMP, KOFW_ATT_NONE, 1 },
	{ "/tmp/", KOFW_LOC_TEMP, KOFW_ATT_NONE, 0 },
	{ "/var/tmp/", KOFW_LOC_TEMP, KOFW_ATT_NONE, 0 },
	{ "/dev/shm/", KOFW_LOC_TEMP, KOFW_ATT_NONE, 0 },

	/* ---- the matrix rows, before the generic locations they sit inside - */

	/* Registry autoruns. RunOnce and the Wow6432Node mirror are separate
	 * spellings of the same key and each needs its own row: a needle is a
	 * substring, not a pattern. */
	{ "\\CurrentVersion\\Run", KOFW_LOC_AUTOSTART, KOFW_ATT_RUN_KEY, 1 },
	{ "\\CurrentVersion\\RunOnce", KOFW_LOC_AUTOSTART, KOFW_ATT_RUN_KEY, 1 },
	{ "\\Start Menu\\Programs\\Startup\\",
	  KOFW_LOC_AUTOSTART,  KOFW_ATT_STARTUP_DIR, 1 },
	{ "/.config/autostart/", KOFW_LOC_AUTOSTART, KOFW_ATT_STARTUP_DIR, 0 },

	{ "\\Winlogon\\Shell", KOFW_LOC_AUTOSTART, KOFW_ATT_WINLOGON, 1 },
	{ "\\Winlogon\\Userinit", KOFW_LOC_AUTOSTART, KOFW_ATT_WINLOGON, 1 },

	{ "\\AppInit_DLLs", KOFW_LOC_PRELOAD, KOFW_ATT_APPINIT, 1 },
	{ "\\Image File Execution Options\\",
	  KOFW_LOC_SERVICE,    KOFW_ATT_IFEO, 1 },
	{ "\\CurrentControlSet\\Services\\",
	  KOFW_LOC_SERVICE,    KOFW_ATT_SERVICE, 1 },
	{ "\\System32\\Tasks\\", KOFW_LOC_SCHEDULE, KOFW_ATT_SCHED_TASK, 1 },
	{ "\\Schedule\\TaskCache\\", KOFW_LOC_SCHEDULE, KOFW_ATT_SCHED_TASK, 1 },

	/* Linux persistence. */
	{ "/etc/ld.so.preload", KOFW_LOC_PRELOAD, KOFW_ATT_LD_PRELOAD, 0 },
	{ "/etc/cron", KOFW_LOC_SCHEDULE, KOFW_ATT_CRON, 0 },
	{ "/var/spool/cron", KOFW_LOC_SCHEDULE, KOFW_ATT_CRON, 0 },
	{ "/etc/systemd/system/", KOFW_LOC_SERVICE, KOFW_ATT_SYSTEMD, 0 },
	{ "/lib/systemd/system/", KOFW_LOC_SERVICE, KOFW_ATT_SYSTEMD, 0 },
	{ "/.config/systemd/user/", KOFW_LOC_SERVICE, KOFW_ATT_SYSTEMD, 0 },
	{ "/etc/rc.local", KOFW_LOC_SHELL_INIT, KOFW_ATT_RC_SCRIPT, 0 },
	{ "/etc/init.d/", KOFW_LOC_SERVICE, KOFW_ATT_RC_SCRIPT, 0 },
	{ "/.bashrc", KOFW_LOC_SHELL_INIT, KOFW_ATT_SHELL_PROFILE, 0 },
	{ "/.bash_profile", KOFW_LOC_SHELL_INIT, KOFW_ATT_SHELL_PROFILE, 0 },
	{ "/.profile", KOFW_LOC_SHELL_INIT, KOFW_ATT_SHELL_PROFILE, 0 },
	{ "/etc/profile", KOFW_LOC_SHELL_INIT, KOFW_ATT_SHELL_PROFILE, 0 },
	{ "/.ssh/authorized_keys", KOFW_LOC_SSH, KOFW_ATT_SSH_KEY, 0 },

	/* Identity and privilege. */
	{ "/etc/passwd", KOFW_LOC_CREDENTIAL, KOFW_ATT_ACCOUNT_FILE, 0 },
	{ "/etc/shadow", KOFW_LOC_CREDENTIAL, KOFW_ATT_ACCOUNT_FILE, 0 },
	{ "/etc/sudoers", KOFW_LOC_CREDENTIAL, KOFW_ATT_SUDOERS, 0 },
	{ "\\config\\SAM", KOFW_LOC_CREDENTIAL, KOFW_ATT_CRED_STORE, 1 },
	{ "\\config\\SECURITY", KOFW_LOC_CREDENTIAL, KOFW_ATT_CRED_STORE, 1 },
	{ "\\config\\SYSTEM", KOFW_LOC_CREDENTIAL, KOFW_ATT_CRED_STORE, 1 },

	/* Defence evasion. */
	{ "\\drivers\\etc\\hosts", KOFW_LOC_HOSTS, KOFW_ATT_HOSTS, 1 },
	{ "/etc/hosts", KOFW_LOC_HOSTS, KOFW_ATT_HOSTS, 0 },

	{ "/lib/modules/", KOFW_LOC_KERNEL_MOD, KOFW_ATT_KERNEL_MOD, 0 },
	{ "\\System32\\drivers\\", KOFW_LOC_KERNEL_MOD, KOFW_ATT_KERNEL_MOD, 1 },

	{ "\\inetpub\\wwwroot\\", KOFW_LOC_WEB_ROOT, KOFW_ATT_WEB_SHELL, 1 },
	{ "/var/www/", KOFW_LOC_WEB_ROOT, KOFW_ATT_WEB_SHELL, 0 },

	/* ---- the generic locations, LAST ---------------------------------- */
	{ "\\Windows\\System32\\", KOFW_LOC_SYSTEM, KOFW_ATT_NONE, 1 },
	{ "\\Windows\\SysWOW64\\", KOFW_LOC_SYSTEM, KOFW_ATT_NONE, 1 },
	/* The two extra system directories an ARM64 machine has: SyChpe32
	 * holds the compiled-hybrid x86 binaries and SysArm32 the ARM32 ones.
	 * Leaving them out made every x86 process on such a host look like it
	 * was loading unknown modules. */
	{ "\\Windows\\SyChpe32\\", KOFW_LOC_SYSTEM, KOFW_ATT_NONE, 1 },
	{ "\\Windows\\SysArm32\\", KOFW_LOC_SYSTEM, KOFW_ATT_NONE, 1 },
	{ "\\Windows\\WinSxS\\", KOFW_LOC_SYSTEM, KOFW_ATT_NONE, 1 },
	{ "\\Windows\\assembly\\", KOFW_LOC_SYSTEM, KOFW_ATT_NONE, 1 },
	{ "\\Windows\\Microsoft.NET\\", KOFW_LOC_SYSTEM, KOFW_ATT_NONE, 1 },
	{ "/usr/lib/", KOFW_LOC_SYSTEM, KOFW_ATT_NONE, 0 },
	{ "/usr/lib64/", KOFW_LOC_SYSTEM, KOFW_ATT_NONE, 0 },
	{ "/lib/", KOFW_LOC_SYSTEM, KOFW_ATT_NONE, 0 },
	{ "/lib64/", KOFW_LOC_SYSTEM, KOFW_ATT_NONE, 0 },

	{ "\\Program Files\\", KOFW_LOC_PROGRAMS, KOFW_ATT_NONE, 1 },
	{ "\\Program Files (x86)\\", KOFW_LOC_PROGRAMS, KOFW_ATT_NONE, 1 },
	{ "\\PROGRA~1\\", KOFW_LOC_PROGRAMS, KOFW_ATT_NONE, 1 },
	{ "\\PROGRA~2\\", KOFW_LOC_PROGRAMS, KOFW_ATT_NONE, 1 },
	{ "/usr/bin/", KOFW_LOC_PROGRAMS, KOFW_ATT_NONE, 0 },
	{ "/usr/sbin/", KOFW_LOC_PROGRAMS, KOFW_ATT_NONE, 0 },
	{ "/opt/", KOFW_LOC_PROGRAMS, KOFW_ATT_NONE, 0 },

	{ "\\Users\\", KOFW_LOC_USER, KOFW_ATT_NONE, 1 },
	{ "/home/", KOFW_LOC_USER, KOFW_ATT_NONE, 0 },
	{ "/root/", KOFW_LOC_USER, KOFW_ATT_NONE, 0 },
};

uint8_t kofw_classify(const char *path, uint16_t *att)
{
	size_t i;

	if (att)
		*att = KOFW_ATT_NONE;
	if (!path || !*path)
		return KOFW_LOC_UNKNOWN;

	for (i = 0; i < sizeof LOCS / sizeof LOCS[0]; i++) {
		if (has_ci(path, LOCS[i].needle, LOCS[i].fold)) {
			if (att)
				*att = LOCS[i].att;
			return LOCS[i].loc;
		}
	}
	return KOFW_LOC_OTHER;
}

uint8_t kofw_classify_path(const char *path)
{
	return kofw_classify(path, NULL);
}

/* --------------------------------------------------------- the process table */

void kofw_ptab_init(struct kofw_ptab *t)
{
	uint16_t i;

	memset(t, 0, sizeof *t);

	/* Chain the module-range pool into one free list. */
	for (i = 0; i + 1 < KOFW_MODBLK_MAX; i++)
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

	if (!base || !size)
		return;

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
		uint16_t k;

		memset(t->e, 0, sizeof t->e);
		for (k = 0; k + 1 < KOFW_MODBLK_MAX; k++) {
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
	if (*obj) {
		uint16_t att = KOFW_ATT_NONE;

		e->obj_loc = kofw_classify(obj, &att);
		e->attack  = att;
	} else {
		e->obj_loc = KOFW_LOC_UNKNOWN;
		e->attack  = KOFW_ATT_NONE;
	}

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
	} else if (e->type == KOFW_EVT_PROC_STOP) {
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
	} else if (e->type == KOFW_EVT_IMAGE_LOAD) {
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
	} else if (e->type == KOFW_EVT_THREAD_START && e->addr) {
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
				 e->type == KOFW_EVT_PROC_START ||
				 e->type == KOFW_EVT_PROC_STOP
					 ? e->create_time : 0);
		if (!p || !p->tracked) {
			if (why)
				*why = KOFW_REFUSE_SCOPE;
			return 0;
		}
	}

	return 1;
}
