/*
 * kofreport.c - the accumulator. See kofreport.h for what it is for.
 *
 * WHAT IS IN THIS FILE AND WHAT IS NOT: this is the FEED phase - turning a
 * stream of events into a bounded set of deduplicated fingerprints, deciding
 * which group each is in, and answering questions about the result. The
 * expensive phase is in kofrepart.c and the two emitters are in kofrepfmt.c,
 * because those three jobs fail for different reasons and reading one should
 * not mean reading the others.
 *
 * EVERYTHING HERE IS BOUNDED, AND THAT IS THE WHOLE CONSTRAINT.
 *
 * kof_report_feed runs on the consumer thread, once per kept event, while the
 * ring behind it is filling at whatever rate the machine produces. So: no
 * allocation per event in the common case, no I/O, no syscall, and no loop
 * whose length depends on the trace. What it does is hash a string, probe a
 * table, and bump two counters.
 *
 * The tables have ceilings and the overflow is COUNTED PER KIND. A report that
 * listed five hundred registry writes without saying there had been nine
 * thousand would be telling a reader the list is the whole story, which is the
 * one thing evidence must never do.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "kofrepint.h"

/* ---- the string arena ---------------------------------------------------- */

const char *kofrep_arena_put(struct kofrep_arena *a, const char *s, size_t n)
{
	struct kofrep_ablock *b = a->head;
	char *out;

	if (!s)
		return "";

	if (!b || b->cap - b->used < n + 1u) {
		size_t cap = (n + 1u > KOFREP_ABLOCK) ? n + 1u : KOFREP_ABLOCK;

		b = (struct kofrep_ablock *)malloc(sizeof *b);
		if (!b)
			return "";
		b->p = (char *)malloc(cap);
		if (!b->p) {
			free(b);
			return "";
		}
		b->cap  = cap;
		b->used = 0;
		b->next = a->head;
		a->head = b;
	}

	out = b->p + b->used;
	memcpy(out, s, n);
	out[n] = '\0';
	b->used += n + 1u;
	a->bytes += n + 1u;
	return out;
}

const char *kofrep_arena_str(struct kofrep_arena *a, const char *s)
{
	return s ? kofrep_arena_put(a, s, strlen(s)) : "";
}

void kofrep_arena_free(struct kofrep_arena *a)
{
	struct kofrep_ablock *b = a->head;

	while (b) {
		struct kofrep_ablock *n = b->next;

		free(b->p);
		free(b);
		b = n;
	}
	a->head = NULL;
}

/* ---- names --------------------------------------------------------------- */

const char *kof_fp_kind_name(uint8_t kind)
{
	switch (kind) {
	case KOF_FP_PROCESS:     return "process";
	case KOF_FP_FILE_NEW:    return "file-new";
	case KOF_FP_FILE_WRITE:  return "file-write";
	case KOF_FP_FILE_DELETE: return "file-delete";
	case KOF_FP_FILE_RENAME: return "file-rename";
	case KOF_FP_REGISTRY:    return "registry";
	case KOF_FP_PEER:        return "peer";
	case KOF_FP_DNS:         return "dns";
	case KOF_FP_PIPE:        return "pipe";
	case KOF_FP_MODULE:      return "module";
	case KOF_FP_SCRIPT:      return "script";
	case KOF_FP_UNBACKED:    return "unbacked-thread";
	default:                 return "?";
	}
}

const char *kof_rep_group_name(uint8_t group)
{
	switch (group) {
	case KOF_RG_STABLE:   return "stable";
	case KOF_RG_VOLATILE: return "volatile";
	case KOF_RG_AMBIENT:  return "ambient";
	default:              return "?";
	}
}

const char *kof_fp_seen_name(uint8_t in_sample)
{
	switch (in_sample) {
	case KOF_FP_SEEN_PRESENT: return "present";
	case KOF_FP_SEEN_WIDE:    return "present-wide";
	case KOF_FP_SEEN_PART:    return "fragment";
	case KOF_FP_SEEN_ABSENT:  return "absent";
	default:                  return "unchecked";
	}
}

const char *kof_fp_why_not(uint8_t why)
{
	switch (why) {
	case KOF_FP_WHY_OK:        return "";
	case KOF_FP_WHY_GONE:      return "no longer on disk at the end of the run";
	case KOF_FP_WHY_DENIED:    return "on disk and could not be opened";
	case KOF_FP_WHY_TOO_BIG:   return "over the per-file ceiling";
	case KOF_FP_WHY_BUDGET:    return "the run's evidence budget was spent";
	case KOF_FP_WHY_NOT_ASKED: return "collection was not asked for";
	case KOF_FP_WHY_SHORT:     return "the range is past the end of the file now";
	default:                   return "?";
	}
}

/* ---- small string work --------------------------------------------------- */

static int ci_eq(char a, char b)
{
	if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
	if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
	return a == b;
}

/* Case-insensitive substring, and it is case-insensitive because every path
 * this looks for is a Windows one. A Linux collector's paths are matched by
 * kof_classify, which takes the same care - see the `fold` column there. */
static const char *ci_find(const char *hay, const char *needle)
{
	size_t i, j;

	if (!hay || !needle)
		return NULL;
	for (i = 0; hay[i]; i++) {
		for (j = 0; needle[j]; j++)
			if (!ci_eq(hay[i + j], needle[j]))
				break;
		if (!needle[j])
			return hay + i;
	}
	return NULL;
}

static const char *base_of(const char *path)
{
	const char *b = path;
	const char *p;

	for (p = path; *p; p++)
		if (*p == '\\' || *p == '/')
			b = p + 1;
	return b;
}

static int is_hex(char c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
	       (c >= 'A' && c <= 'F');
}

static int is_dig(char c)
{
	return c >= '0' && c <= '9';
}

/* The longest run of hex digits, and the longest run of decimal digits. Both
 * in one pass because both callers want both. */
static void runs_of(const char *s, unsigned *hex, unsigned *dec)
{
	unsigned h = 0, d = 0, bh = 0, bd = 0;

	for (; *s; s++) {
		if (is_hex(*s)) {
			if (++h > bh) bh = h;
		} else {
			h = 0;
		}
		if (is_dig(*s)) {
			if (++d > bd) bd = d;
		} else {
			d = 0;
		}
	}
	*hex = bh;
	*dec = bd;
}

/*
 * A GUID IN TEXT, 8-4-4-4-12, with or without braces.
 *
 * Its own test rather than falling out of the hex-run rule above, because a
 * GUID's runs are only eight long and a great many deliberate names contain
 * eight hex characters. Matched as a shape, which is what it is.
 */
static int has_guid(const char *s)
{
	static const unsigned want[5] = { 8u, 4u, 4u, 4u, 12u };
	const char *p;

	for (p = s; *p; p++) {
		const char *q = p;
		unsigned    i;

		for (i = 0; i < 5u; i++) {
			unsigned n = 0;

			while (is_hex(*q) && n < want[i]) { q++; n++; }
			if (n != want[i])
				break;
			if (i < 4u) {
				if (*q != '-')
					break;
				q++;
			}
		}
		if (i == 5u)
			return 1;
	}
	return 0;
}

/* A long run of base64-ish characters, which is what an encoded PowerShell
 * command looks like and is the single most common volatile thing in a command
 * line. Forty is chosen to sit above a long flag and well below an -enc
 * payload, the shortest useful one of which is far longer. */
static int has_blob(const char *s)
{
	unsigned run = 0;

	for (; *s; s++) {
		char c = *s;

		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		    is_dig(c) || c == '+' || c == '/' || c == '=') {
			if (++run >= 40u)
				return 1;
		} else {
			run = 0;
		}
	}
	return 0;
}

/*
 * THE INVARIANT SPELLING OF A PATH - what would still be true next run.
 *
 * A user name becomes '*', a run of digits becomes '#', a long hex run becomes
 * '*', a GUID becomes {*}. The result is not a pattern any matcher here
 * consumes: it is what a researcher reads and what a signature draft takes its
 * string from, which is why it keeps the punctuation and the extension - those
 * are the parts a rule can actually anchor on.
 *
 * Returns 1 if anything was replaced.
 */
static int normalise(const char *in, char *out, size_t cap)
{
	size_t o = 0;
	int    hit = 0;
	const char *p = in;

	while (*p && o + 4u < cap) {
		const char *u;

		/* \Users\<somebody>\ - the name is the machine's, not the
		 * sample's, and it is the most common reason a perfectly good
		 * path is useless as a string. */
		u = NULL;
		if ((*p == '\\' || *p == '/') &&
		    (ci_find(p, "\\Users\\") == p || ci_find(p, "/home/") == p))
			u = p;
		if (u) {
			size_t seg = (*p == '\\') ? 7u : 6u;
			const char *e;

			memcpy(out + o, p, seg);
			o += seg;
			p += seg;
			for (e = p; *e && *e != '\\' && *e != '/'; e++)
				;
			if (e != p) {
				out[o++] = '*';
				hit = 1;
				p = e;
			}
			continue;
		}

		if (is_hex(*p)) {
			const char *e = p;
			unsigned n = 0;

			while (is_hex(*e)) { e++; n++; }
			/* Six is the threshold because five hex characters
			 * appear inside ordinary words - "decade", "faced" -
			 * and a random temp stem is eight or more. */
			if (n >= 6u) {
				out[o++] = '*';
				hit = 1;
				p = e;
				continue;
			}
			if (n >= 5u && is_dig(*p)) {
				out[o++] = '#';
				hit = 1;
				p = e;
				continue;
			}
		}

		if (is_dig(*p)) {
			const char *e = p;
			unsigned n = 0;

			while (is_dig(*e)) { e++; n++; }
			if (n >= 5u) {
				out[o++] = '#';
				hit = 1;
				p = e;
				continue;
			}
		}

		out[o++] = *p++;
	}
	out[o < cap ? o : cap - 1u] = '\0';
	return hit;
}

/* ---- the grouping -------------------------------------------------------- */

/*
 * WHICH GROUP, AND WHY IN WORDS.
 *
 * See the header on why this groups rather than filters. Every branch sets a
 * reason, because the reason is what lets a reader overrule the decision - and
 * they will need to: a six-hex basename is usually random and "ffmpeg" is not.
 *
 * ORDER MATTERS, most specific first, for the same reason kofevt.c's location
 * table says so about itself. A temp path is also under a user profile, and
 * reporting the profile is the less useful of the two answers.
 */
static void classify(struct kof_report *r, uint8_t kind, uint8_t loc,
		     const char *text, uint8_t *group, const char **why,
		     const char **norm)
{
	char     buf[512];
	unsigned hex = 0, dec = 0;
	const char *b;

	*group = KOF_RG_STABLE;
	*why   = "";
	*norm  = "";

	if (!text || !*text)
		return;

	/* OUR OWN OUTPUT, first, because a report that presented its own log
	 * file as something the sample created would be evidence of nothing
	 * but itself. */
	if ((r->info.dir && *r->info.dir && ci_find(text, r->info.dir)) ||
	    (r->info.log && *r->info.log && ci_find(text, r->info.log))) {
		*group = KOF_RG_AMBIENT;
		*why   = "written by this tool, not by the sample";
		return;
	}

	/* A module out of a system directory is what every process on the
	 * machine loads. Only for modules: a sample that WRITES into System32
	 * is the opposite of ambient, and that is a different kind. */
	if (kind == KOF_FP_MODULE && loc == KOF_LOC_SYSTEM) {
		*group = KOF_RG_AMBIENT;
		*why   = "a system module every process loads";
		return;
	}

	if (kind == KOF_FP_PEER) {
		/* Loopback is a program talking to itself, which is ambient
		 * until something else says otherwise. Everything routable is
		 * left alone - an allowlist of "known good" addresses is
		 * exactly how a report hides a payload behind a cloud front. */
		if (!strncmp(text, "127.", 4) || !strncmp(text, "[::1]", 5)) {
			*group = KOF_RG_AMBIENT;
			*why   = "loopback";
		}
		return;
	}

	b = base_of(text);
	runs_of(b, &hex, &dec);

	if (has_guid(text)) {
		*group = KOF_RG_VOLATILE;
		*why   = "holds a GUID";
		if (normalise(text, buf, sizeof buf))
			*norm = kofrep_arena_str(&r->arena, buf);
		return;
	}

	if (kind == KOF_FP_PROCESS || kind == KOF_FP_SCRIPT) {
		if (has_blob(text)) {
			*group = KOF_RG_VOLATILE;
			*why   = "holds an encoded blob that will differ next run";
			if (normalise(text, buf, sizeof buf))
				*norm = kofrep_arena_str(&r->arena, buf);
			return;
		}
	}

	/*
	 * A RANDOM BASENAME. Eight hex characters in a filename is a name
	 * something generated; six is the point where it stops appearing in
	 * ordinary words. The reason says which, so a false one is visible.
	 */
	if (hex >= 8u) {
		*group = KOF_RG_VOLATILE;
		*why   = "random-looking basename";
		if (normalise(text, buf, sizeof buf))
			*norm = kofrep_arena_str(&r->arena, buf);
		return;
	}
	if (dec >= 5u) {
		*group = KOF_RG_VOLATILE;
		*why   = "holds a long number - a pid, a timestamp or a counter";
		if (normalise(text, buf, sizeof buf))
			*norm = kofrep_arena_str(&r->arena, buf);
		return;
	}

	/*
	 * UNDER A USER PROFILE, last of the volatile rules, because the
	 * account name is the least interesting reason a path will not recur
	 * and anything more specific has already claimed the fingerprint.
	 */
	if (ci_find(text, "\\Users\\") || ci_find(text, "/home/")) {
		*group = KOF_RG_VOLATILE;
		*why   = "under a user profile, so the path differs per machine";
		if (normalise(text, buf, sizeof buf))
			*norm = kofrep_arena_str(&r->arena, buf);
	}
}

/* ---- the table ----------------------------------------------------------- */

static uint32_t hash_of(uint8_t kind, const char *s)
{
	/* FNV-1a, folded over a case-insensitive view: the same path spelled
	 * with a different case is the same artefact, and Windows will hand
	 * over both spellings within one trace. */
	uint32_t h = 2166136261u ^ kind;

	for (; *s; s++) {
		char c = *s;

		if (c >= 'A' && c <= 'Z')
			c = (char)(c + 32);
		h ^= (uint8_t)c;
		h *= 16777619u;
	}
	return h;
}

static int same(const struct kof_fingerprint *f, uint8_t kind, const char *s)
{
	const char *a = f->text;

	if (f->kind != kind)
		return 0;
	while (*a && *s) {
		if (!ci_eq(*a, *s))
			return 0;
		a++;
		s++;
	}
	return *a == *s;
}

/*
 * FIND OR ADD. Returns the fingerprint, or NULL when the table is full - in
 * which case the caller counts the drop against the kind.
 *
 * `text` is copied into the arena only when the fingerprint is new, which is
 * the property that makes a program writing one value ten thousand times cost
 * one string rather than ten thousand.
 */
static struct kof_fingerprint *intern(struct kof_report *r, uint8_t kind,
				      const char *text)
{
	uint32_t h, i;
	struct kof_fingerprint *f;

	if (!text || !*text)
		return NULL;

	h = hash_of(kind, text);
	for (i = 0; i < KOFREP_SLOTS; i++) {
		uint32_t at = (h + i) & (KOFREP_SLOTS - 1u);
		uint32_t ix = r->slot[at];

		if (!ix) {
			if (r->n_fp >= KOFREP_FP_MAX)
				return NULL;
			f = &r->fp[r->n_fp];
			memset(f, 0, sizeof *f);
			f->kind = kind;
			f->text = kofrep_arena_str(&r->arena, text);
			f->norm = "";
			f->why  = "";
			f->spill = "";
			f->bytes.why_not = KOF_FP_WHY_NOT_ASKED;
			r->slot[at] = ++r->n_fp;
			r->order_stale = 1;
			return f;
		}
		if (same(&r->fp[ix - 1u], kind, text))
			return &r->fp[ix - 1u];
	}
	return NULL;   /* the probe wrapped: the table is full */
}

/*
 * FIND, AND NEVER ADD - what the finish phase uses to hang bytes and verdicts
 * on what the feed phase recorded.
 *
 * Separate from intern() rather than a flag on it, because the difference is
 * not a parameter: a phase that could create a fingerprint would be able to
 * report something no event established, and the whole claim of this library
 * is that every line in a report came off the trace.
 */
struct kof_fingerprint *kofrep_find(struct kof_report *r, uint8_t kind,
				    const char *text)
{
	uint32_t h, i;

	if (!r || !text || !*text)
		return NULL;

	h = hash_of(kind, text);
	for (i = 0; i < KOFREP_SLOTS; i++) {
		uint32_t at = (h + i) & (KOFREP_SLOTS - 1u);
		uint32_t ix = r->slot[at];

		if (!ix)
			return NULL;
		if (same(&r->fp[ix - 1u], kind, text))
			return &r->fp[ix - 1u];
	}
	return NULL;
}

int kof_report_spill(struct kof_report *r, const char *path, const char *alt)
{
	/*
	 * BOTH COLLECTED KINDS, because one path can be interned under each:
	 * a dropper CREATES a file and then WRITES it, and the finish phase
	 * collects both rows. Attaching to only one leaves the other reporting
	 * that the bytes were not captured, next to a row saying they were.
	 */
	static const uint8_t kinds[] = { KOF_FP_FILE_NEW, KOF_FP_FILE_WRITE };
	const char *copy = NULL;
	unsigned k;
	int hit = 0;

	if (!r || !path || !*path || !alt || !*alt)
		return -1;
	for (k = 0; k < sizeof kinds / sizeof kinds[0]; k++) {
		struct kof_fingerprint *f = kofrep_find(r, kinds[k], path);

		if (!f)
			continue;
		hit = 1;
		/* First copy wins. A file written ten thousand times would
		 * otherwise cost ten thousand arena strings for a fallback
		 * only one of them can be. */
		if (f->spill && f->spill[0])
			continue;
		if (!copy) {
			copy = kofrep_arena_str(&r->arena, alt);
			if (!copy)
				return -1;
		}
		f->spill = copy;
	}
	return hit ? 0 : -1;
}

/* ---- opening and closing ------------------------------------------------- */

struct kof_report *kof_report_open(const struct kof_report_info *info)
{
	struct kof_report *r = (struct kof_report *)calloc(1, sizeof *r);

	if (!r)
		return NULL;

	r->fp    = (struct kof_fingerprint *)calloc(KOFREP_FP_MAX, sizeof *r->fp);
	r->slot  = (uint32_t *)calloc(KOFREP_SLOTS, sizeof *r->slot);
	r->proc  = (struct kof_rep_proc *)calloc(KOFREP_PROC_MAX, sizeof *r->proc);
	r->order = (uint32_t *)calloc(KOFREP_FP_MAX, sizeof *r->order);
	if (!r->fp || !r->slot || !r->proc || !r->order) {
		kof_report_close(r);
		return NULL;
	}

	if (info) {
		r->info = *info;
		/* Copied, so a caller's argv, or a buffer it is about to reuse,
		 * is not what the report prints an hour later. */
		r->info.tool        = kofrep_arena_str(&r->arena, info->tool);
		r->info.subject     = kofrep_arena_str(&r->arena, info->subject);
		r->info.subject_cmd = kofrep_arena_str(&r->arena, info->subject_cmd);
		r->info.dir         = kofrep_arena_str(&r->arena, info->dir);
		r->info.log         = kofrep_arena_str(&r->arena, info->log);
	}
	return r;
}

void kof_report_close(struct kof_report *r)
{
	if (!r)
		return;
	free(r->fp);
	free(r->slot);
	free(r->proc);
	free(r->order);
	kofrep_arena_free(&r->arena);
	free(r);
}

void kof_report_ended(struct kof_report *r, enum kof_rep_end how, double secs)
{
	if (!r)
		return;
	r->ended   = how;
	r->seconds = secs;
}

void kof_report_health(struct kof_report *r, const struct kof_evt_health *h,
		       uint64_t out_of_tree)
{
	if (!r)
		return;
	if (h)
		r->health = *h;
	r->out_of_tree = out_of_tree;
	r->have_health = 1;
}

/* ---- the process table --------------------------------------------------- */

static struct kof_rep_proc *proc_find(struct kof_report *r, uint32_t pid,
				      uint64_t create_time)
{
	uint32_t i;

	/*
	 * (pid, create_time) AND NOT pid, and the fallback is deliberate: a
	 * file event does not carry a creation time, so a lookup by pid alone
	 * has to be possible. It takes the LAST match, which is the newest
	 * process to have held the number - the right answer when a pid has
	 * been reused inside one trace, and the only answer available.
	 */
	for (i = r->n_proc; i-- > 0; ) {
		if (r->proc[i].pid != pid)
			continue;
		if (!create_time || !r->proc[i].create_time ||
		    r->proc[i].create_time == create_time)
			return &r->proc[i];
	}
	return NULL;
}

static struct kof_rep_proc *proc_add(struct kof_report *r, const struct kof_evt *e)
{
	const struct kof_evt_proc *pr = kof_evt_as_proc(e);
	struct kof_rep_proc *p, *parent;

	if (r->n_proc >= KOFREP_PROC_MAX) {
		r->proc_dropped++;
		return NULL;
	}
	p = &r->proc[r->n_proc++];
	memset(p, 0, sizeof *p);
	p->pid         = e->pid;
	p->ppid        = e->ppid;
	p->create_time = pr ? pr->create_time : 0;
	p->started     = e->stamp;
	p->image       = kofrep_arena_str(&r->arena, kof_evt_image(e));
	p->cmdline     = kofrep_arena_str(&r->arena, kof_evt_cmdline(e));
	p->cmd_raced   = (e->flags & KOF_EF_CMDLINE_RACED) ? 1u : 0u;

	/*
	 * THE ROOT'S COMMAND LINE FROM THE HOST, WHEN THE TRACE LOST IT.
	 *
	 * The collector reads a command line out of the new process's PEB and
	 * that is the one field on a record which can lose a race - a process
	 * that exits in milliseconds is gone before it can be read, and `ping`
	 * is exactly that. So a report of the run that was asked for printed
	 * "[unread: the process was gone before it could be read]" for the
	 * command the OPERATOR TYPED.
	 *
	 * For the root of the tree the host is authoritative: it composed the
	 * command line and passed it to CreateProcess. Taking it from there is
	 * not the report inventing evidence, it is the report using the one
	 * source that cannot have lost it. Only for the root, and only when the
	 * trace has nothing: a child's command line is not something the host
	 * knows, and guessing there WOULD be invention.
	 */
	if ((!p->cmdline || !*p->cmdline) && p->pid == r->info.root_pid &&
	    r->info.subject_cmd && *r->info.subject_cmd) {
		p->cmdline   = r->info.subject_cmd;
		p->cmd_raced = 0;
	}

	/*
	 * DEPTH FROM THE PARENT ALREADY IN THE TABLE, computed once here
	 * rather than by a printer walking the tree.
	 *
	 * It works because a parent's ProcessStart necessarily precedes its
	 * child's - a process cannot create one before it exists - and that
	 * holds even though events arrive out of order, because the ORDER of
	 * two events is not what is being relied on: the parent had to be
	 * added to the table by the time the child's record is fed, and if it
	 * was not, the child is a root of what this trace saw. Which is the
	 * honest answer for a process whose parent started before the session.
	 */
	parent = e->ppid ? proc_find(r, e->ppid, 0) : NULL;
	p->depth = parent ? parent->depth + 1u : 0u;
	return p;
}

/* ---- feed ---------------------------------------------------------------- */

/* Returns the fingerprint so a caller can qualify it further - which one does:
 * a registry CREATE is not a change, and only feed() knows the verb. */
static struct kof_fingerprint *note(struct kof_report *r, uint8_t kind,
				    const char *text, const struct kof_evt *e,
				    uint64_t index)
{
	struct kof_fingerprint *f;

	if (!text || !*text)
		return NULL;

	f = intern(r, kind, text);
	if (!f) {
		r->dropped[kind < KOF_FP_KIND_COUNT ? kind : 0]++;
		return NULL;
	}

	if (!f->count) {
		f->first_seen  = e->stamp;
		f->first_index = index;
		/*
		 * THE ACTOR, EXCEPT FOR A PROCESS - where the actor is the
		 * PARENT and the line is about the child.
		 *
		 * kof_evt.actor_pid is who CAUSED an event, which for a file
		 * write is the writer and is the single most important fact on
		 * the record. For a ProcessStart it is whoever called
		 * CreateProcess - which for the root of a traced tree is
		 * kofmontrace itself. The report printed
		 * "process ...\cmd.exe pid=10000" against a tree whose only
		 * pids were 19184 and 19824: a number belonging to no process
		 * in the report, on the line naming the process.
		 *
		 * Parentage is not lost by choosing the subject here - the
		 * process tree above shows it, and it shows it better, indented.
		 */
		f->actor_pid   = (kind == KOF_FP_PROCESS)
					 ? e->pid
					 : (e->actor_pid ? e->actor_pid
							 : e->pid);
		f->loc         = e->loc;
		f->attack      = e->attack;
		classify(r, kind, e->loc, f->text, &f->group, &f->why,
			 &f->norm);
		if (e->flags & KOF_EF_TRUNCATED)
			f->flags |= KOF_FP_F_CUT;
	} else if (f->actor_pid && f->actor_pid != (e->actor_pid ? e->actor_pid
								: e->pid)) {
		/* Two processes of the tree did the same thing, which is worth
		 * a flag: a path touched by both the dropper and its child is
		 * the handover. */
		f->flags |= KOF_FP_F_SHARED;
	}

	/*
	 * THE TECHNIQUE TAG IS TAKEN FROM THE EVENT AND NEVER INVENTED HERE.
	 *
	 * kofevt.h is explicit that the tag is an INPUT and that no consumer
	 * may present it as a detection. A report obeys that by carrying it on
	 * the fingerprint - where it names the LOCATION that was written, in a
	 * section that says so - and by never turning it into a finding of its
	 * own. The first non-zero wins rather than the last, so a path that is
	 * classified once keeps that answer.
	 */
	if (!f->attack && e->attack)
		f->attack = e->attack;

	f->last_seen = e->stamp;
	if (f->count != 0xffffffffu)
		f->count++;
	return f;
}

void kof_report_feed(struct kof_report *r, const struct kof_evt *e,
		     uint64_t index)
{
	if (!r || !e)
		return;

	/*
	 * A CONTINUATION IS NOT AN EVENT. It is the tail of the record in
	 * front of it - see KOF_EVT_CONT - and feeding it would add a
	 * fingerprint per four hundred bytes of one script.
	 *
	 * The consequence is stated rather than hidden: a script longer than
	 * one record is reported from its FIRST record only, so the text is a
	 * prefix and carries KOF_FP_F_CUT. Joining the chunks needs
	 * kof_evt_join and a buffer, which is the expensive phase's business
	 * and not this one's.
	 */
	if (e->verb == KOF_EVT_CONT)
		return;

	r->n_events++;
	if (!r->first_stamp)
		r->first_stamp = e->stamp;
	r->last_stamp = e->stamp;

	switch (e->verb) {
	case KOF_EVT_PROC_START: {
		struct kof_rep_proc *p = proc_find(r, e->pid,
			kof_evt_as_proc(e) ? kof_evt_as_proc(e)->create_time
					   : 0);

		/* A ProcessStart for a pid already in the table with the same
		 * creation time is a duplicate record, not a second process. */
		if (!p || (kof_evt_as_proc(e) &&
			   p->create_time != kof_evt_as_proc(e)->create_time))
			(void)proc_add(r, e);

		/*
		 * THE COMMAND LINE IS THE FINGERPRINT, not the image path.
		 *
		 * "powershell.exe started" is not something anybody can act
		 * on; the arguments are the whole event for every
		 * living-off-the-land technique. The image is on the process
		 * entry, where it belongs, and a process with no readable
		 * command line falls back to it so that the fingerprint exists
		 * at all.
		 */
		{
			const char *cl = kof_evt_cmdline(e);

			/* The root's, from the host, when the trace lost the
			 * race - see proc_add, which does the same for the
			 * process entry and explains why only the root. */
			if ((!cl || !*cl) && e->pid == r->info.root_pid &&
			    r->info.subject_cmd && *r->info.subject_cmd)
				cl = r->info.subject_cmd;

			note(r, KOF_FP_PROCESS, (cl && *cl) ? cl
							   : kof_evt_image(e),
			     e, index);
		}
		break;
	}
	case KOF_EVT_PROC_STOP: {
		const struct kof_evt_proc *pr = kof_evt_as_proc(e);
		struct kof_rep_proc *p = proc_find(r, e->pid,
						   pr ? pr->create_time : 0);

		if (p) {
			p->exited    = 1;
			p->stopped   = e->stamp;
			p->exit_code = pr ? pr->exit_code : 0;
		}
		break;
	}

	case KOF_EVT_FILE_NEW:
		/*
		 * A PIPE IS NOT A FILE IN A PLACE, it is a different kind of
		 * object - kofevt.c's location table puts the test first for
		 * the same reason. getsystem creates a pipe, has a SYSTEM
		 * service connect, and impersonates the token that arrives;
		 * reporting that among the dropped files buries it.
		 */
		note(r, e->loc == KOF_LOC_PIPE ? KOF_FP_PIPE : KOF_FP_FILE_NEW,
		     kof_evt_object(e), e, index);
		break;

	case KOF_EVT_FILE_WRITE: {
		struct kof_fingerprint *f;
		const struct kof_evt_file *fl = kof_evt_as_file(e);

		note(r, KOF_FP_FILE_WRITE, kof_evt_object(e), e, index);

		/*
		 * THE RANGE, AND ONLY THE FIRST ONE PER PATH.
		 *
		 * A program appending to a file produces a write per buffer,
		 * and keeping every range would be an unbounded list on the
		 * drain path - the one thing this phase may not have. So the
		 * fingerprint holds the FIRST range and the total the writes
		 * claimed, and says so: `claimed` grows with each write while
		 * `offset` stays where the first one landed.
		 *
		 * That is enough for what the range is for. A reader wants to
		 * know where the sample started writing and how much it wrote;
		 * the bytes are read back from there in the expensive phase,
		 * and a gap in the middle of a sparse write is a case this
		 * reports as a length rather than pretending to reconstruct.
		 */
		f = intern(r, KOF_FP_FILE_WRITE, kof_evt_object(e));
		if (f && fl) {
			if (f->count <= 1u) {
				f->bytes.offset  = fl->offset;
				f->bytes.claimed = fl->size;
			} else if (fl->size) {
				f->bytes.claimed += fl->size;
				if (fl->offset < f->bytes.offset)
					f->bytes.offset = fl->offset;
			}
		}
		break;
	}

	case KOF_EVT_FILE_DELETE: {
		struct kof_fingerprint *prev;

		note(r, KOF_FP_FILE_DELETE, kof_evt_object(e), e, index);

		/*
		 * A FILE THIS TREE CREATED AND THEN REMOVED, which is a
		 * dropper cleaning up after itself and is the reason its bytes
		 * will not be there to collect. Marked on the CREATE
		 * fingerprint, because that is the one a reader will be looking
		 * at when they wonder where the file went.
		 */
		prev = intern(r, KOF_FP_FILE_NEW, kof_evt_object(e));
		if (prev && prev->count)
			prev->flags |= KOF_FP_F_SELF_DEL;
		break;
	}

	case KOF_EVT_FILE_RENAME:
		note(r, KOF_FP_FILE_RENAME, kof_evt_object(e), e, index);
		break;

	case KOF_EVT_REG_SET_VALUE:
	case KOF_EVT_REG_DELETE:
		note(r, KOF_FP_REGISTRY, kof_evt_object(e), e, index);
		break;

	case KOF_EVT_REG_CREATE: {
		/*
		 * A CREATE IS NOT A CHANGE, AND IT IS GROUPED RATHER THAN
		 * DROPPED.
		 *
		 * RegCreateKeyEx opens an existing key as readily as it makes a
		 * new one and the kernel raises CreateKey either way - see the
		 * note in wevt_decode.c's type_of. So every key a program
		 * merely reads arrives here, and a report that listed them all
		 * as registry modifications would bury the one SetValue that
		 * established persistence under fifty opens of Tcpip
		 * parameters. That is not hypothetical: it is what
		 * nslookup.kevt is, eight times over.
		 *
		 * Dropping them would be the easy answer and is the one this
		 * library refuses everywhere else: a dropped fingerprint is a
		 * judgement the reader cannot see or overrule. So it is kept
		 * and grouped as ambient WITH THE REASON PRINTED - unless the
		 * path is one the matrix has a name for, because "created a key
		 * under Run" is worth a reader's attention even before the
		 * value arrives.
		 */
		struct kof_fingerprint *f = note(r, KOF_FP_REGISTRY,
						 kof_evt_object(e), e, index);

		if (f && f->count == 1u && !f->attack &&
		    f->group == KOF_RG_STABLE) {
			f->group = KOF_RG_AMBIENT;
			f->why   = "a key opened with create disposition, "
				   "which is how every program reads one - "
				   "the SetValue is the event";
		}
		break;
	}

	case KOF_EVT_IMAGE_LOAD:
		note(r, KOF_FP_MODULE, kof_evt_object(e), e, index);
		break;

	case KOF_EVT_DNS_QUERY:
		note(r, KOF_FP_DNS, kof_evt_object(e), e, index);
		break;

	case KOF_EVT_NET_CONNECT:
	case KOF_EVT_NET_SEND:
	case KOF_EVT_NET_RECV: {
		const struct kof_evt_net *n = kof_evt_as_net(e);
		char peer[KOF_IP_STR_MAX + 16];
		char ip[KOF_IP_STR_MAX];
		uint16_t dp;

		if (!n || kof_evt_ip_is_unset(n->daddr))
			break;
		dp = (uint16_t)((n->dport >> 8) | (n->dport << 8));
		kof_evt_ip_str(n->daddr, ip, sizeof ip);

		/* One spelling, and it is the one somebody pastes into a
		 * search: brackets around a v6 address because
		 * 2001:db8::1:443 cannot be read. */
		if (kof_evt_ip_is_v6(n->daddr))
			snprintf(peer, sizeof peer, "[%s]:%u", ip,
				 (unsigned)dp);
		else
			snprintf(peer, sizeof peer, "%s:%u", ip, (unsigned)dp);
		note(r, KOF_FP_PEER, peer, e, index);
		break;
	}

	case KOF_EVT_AMSI_SCAN: {
		/*
		 * CONTENT AND NOT A PATH, so it is taken by length and not as
		 * a string: a submission may hold NULs, and UTF-16 read as
		 * bytes has one at index 1 - which as a string is exactly one
		 * character. That mistake was made once in this tree already
		 * and is why kof_evt carries content_len.
		 */
		const char *ct = NULL;
		size_t      cn = 0;
		char        buf[256];
		size_t      i, o = 0;

		if (!kof_evt_content(e, &ct, &cn) || !cn)
			break;

		/*
		 * ONE LINE OF IT, with control characters folded to spaces.
		 *
		 * The fingerprint's text is what identifies the submission and
		 * what a reader sees; the bytes are in the log at
		 * `first_index`, which is where somebody who needs all of them
		 * goes. Folding is not sanitising for a terminal - that is the
		 * printer's job and it does it again - it is so that two
		 * submissions differing only in line endings are one
		 * fingerprint.
		 */
		for (i = 0; i < cn && o + 1u < sizeof buf; i++) {
			unsigned char c = (unsigned char)ct[i];

			if (c == '\r' || c == '\n' || c == '\t')
				c = ' ';
			if (c < 0x20u || c >= 0x7fu)
				continue;
			if (c == ' ' && o && buf[o - 1u] == ' ')
				continue;
			buf[o++] = (char)c;
		}
		buf[o] = '\0';
		if (o) {
			struct kof_fingerprint *f;

			note(r, KOF_FP_SCRIPT, buf, e, index);
			f = intern(r, KOF_FP_SCRIPT, buf);
			/* A submission is almost always longer than the record
			 * - kofevt.h says so - and the flag is what stops a
			 * signature being written from a prefix as if it were
			 * the whole thing. */
			if (f && (cn > o || (e->flags & KOF_EF_TRUNCATED)))
				f->flags |= KOF_FP_F_CUT;
		}
		break;
	}

	case KOF_EVT_THREAD_START:
		/*
		 * THE ONE FINGERPRINT WITH NO STRING.
		 *
		 * An unbacked entry point is what a manually mapped payload
		 * and a remote injection both look like, and there is no path
		 * to name - that is the entire point of it. So the text is the
		 * process it happened in, which is the only identifying thing
		 * there is, and the address is in the log at first_index.
		 *
		 * Only when the flag is set. kofgrille.h is careful that the
		 * flag is set only when the answer is KNOWABLE - the session
		 * has to have seen the process start - and a report that
		 * inferred it from a missing module list would be reporting a
		 * gap in the trace as an injection.
		 */
		if (e->flags & KOF_EF_UNBACKED) {
			struct kof_rep_proc *p = proc_find(r, e->pid, 0);

			note(r, KOF_FP_UNBACKED,
			     (p && p->image && *p->image) ? p->image
							  : kof_evt_image(e),
			     e, index);
		}
		break;

	/*
	 * AN UNTYPED RECORD, FILED BY ITS PROVIDER - and without this the
	 * report is EMPTY where it matters most today.
	 *
	 * wevt_decode.c's type_of() has no ids for Kernel-Registry and none for
	 * the DNS client, on purpose: it refuses to copy numbers out of
	 * documentation, because an event typed as the wrong thing is still a
	 * typed event and nothing downstream can tell. So on this build every
	 * registry write and every name lookup arrives as KOF_EVT_RAW.
	 *
	 * The cases above would therefore never fire, and a report of a dropper
	 * that established persistence in a Run key would list no registry
	 * activity at all - which reads as a sample that touched nothing.
	 *
	 * What IS established is the PROVIDER. `source` says which subsystem
	 * raised the record, the GUIDs behind those are checked against
	 * `logman query providers`, and field_of already puts the key path and
	 * the queried name in the object arena. So the fingerprint is filed by
	 * provider, which is a fact, rather than by a guessed verb.
	 *
	 * WHAT IS LOST BY NOT KNOWING THE VERB, stated rather than papered
	 * over: a registry fingerprint does not say whether the key was
	 * created, set or deleted, and a lookup's count may include the cache
	 * hits that follow it - the resolver raises several events per
	 * resolution. Both disappear the moment the ids are typed, which is
	 * three lines in type_of() and a trace to read them off.
	 */
	case KOF_EVT_RAW:
		if (e->source == KOF_SRC_REGISTRY)
			note(r, KOF_FP_REGISTRY, kof_evt_object(e), e, index);
		/*
		 * A NAMED PIPE, WHICH ARRIVES WITH NO VERB BY DESIGN.
		 *
		 * kofevt.h refuses a verb for "a file was opened" on purpose -
		 * the test it sets is whether a detection can be stated in one
		 * sentence using it, and that one cannot. Kernel-File's id 12
		 * (Create|FileIo, per the provider's keyword table) is
		 * therefore untyped and always will be.
		 *
		 * But a pipe is only ever visible through it. kofgrille.h
		 * subscribes to file opens for exactly this reason and says so:
		 * a pipe is how one process makes another act for it, and
		 * getsystem creates a pipe, has a SYSTEM service connect, and
		 * impersonates the token that arrives. Without this line the
		 * whole technique produces a report that mentions nothing.
		 *
		 * The LOCATION is what makes it safe to file: wfilter.c
		 * classifies the object of every event including an untyped
		 * one, and \Device\NamedPipe\ is the first row of kofevt.c's
		 * table. So this is not guessing at an id - it is reading a
		 * classification that already happened.
		 */
		else if (e->source == KOF_SRC_FILE && e->loc == KOF_LOC_PIPE)
			note(r, KOF_FP_PIPE, kof_evt_object(e), e, index);
		/*
		 * DNS IS NOT FILED FROM A RAW RECORD, AND IT USED TO BE.
		 *
		 * While no DNS id was typed this was the only way a name
		 * reached a report. Now 3008 is typed - see type_of - and the
		 * fallback became actively wrong: the resolver raises five or
		 * six events per resolution (the call, the cache lookup, the
		 * wire, the server's answer, the completion), every one of them
		 * carries the same name, and they dedup onto one fingerprint
		 * whose COUNT would then say a sample looked a host up six
		 * times. The set stays right and the number lies, which is the
		 * worse of the two failures.
		 *
		 * Registry keeps its fallback because the shape is opposite:
		 * each record carries a DIFFERENT key path, so dedup cannot
		 * inflate anything, and only the four mutation ids are
		 * subscribed at all. If those ids ever differ on some build,
		 * the fallback is what stops a report going silent about
		 * persistence.
		 */
		break;

	default:
		break;
	}
}

/* ---- reading ------------------------------------------------------------- */

static int cmp_fp(const void *pa, const void *pb, const struct kof_report *r)
{
	const struct kof_fingerprint *a = &r->fp[*(const uint32_t *)pa];
	const struct kof_fingerprint *b = &r->fp[*(const uint32_t *)pb];

	if (a->group != b->group)
		return a->group < b->group ? -1 : 1;
	if (a->kind != b->kind)
		return a->kind < b->kind ? -1 : 1;
	if (a->first_seen != b->first_seen)
		return a->first_seen < b->first_seen ? -1 : 1;
	return 0;
}

/*
 * An insertion sort over the index array, and the choice is deliberate.
 *
 * qsort would need the report in a file-static to reach it from the
 * comparator, or qsort_s, which is not portable between the compilers this
 * tree builds with. n is at most KOFREP_FP_MAX and this runs once per report, not per
 * event - the whole sort is invisible beside opening one of the files it is
 * about to describe.
 */
static void reorder(struct kof_report *r)
{
	uint32_t i, j;

	r->n_order = 0;
	for (i = 0; i < r->n_fp; i++)
		r->order[r->n_order++] = i;

	for (i = 1; i < r->n_order; i++) {
		uint32_t v = r->order[i];

		for (j = i; j > 0; j--) {
			if (cmp_fp(&r->order[j - 1u], &v, r) <= 0)
				break;
			r->order[j] = r->order[j - 1u];
		}
		r->order[j] = v;
	}
	r->order_stale = 0;
}

size_t kof_report_count(struct kof_report *r)
{
	return r ? r->n_fp : 0;
}

const struct kof_fingerprint *kof_report_at(struct kof_report *r, size_t i)
{
	/*
	 * NOT const, AND THE SIGNATURE IS WHERE THAT HAD TO BE ADMITTED.
	 *
	 * Reading the i'th fingerprint builds the reading order on demand, so
	 * the call writes to the report. It was declared const with the cast
	 * hidden inside, which -Wcast-qual caught and was right to: a const
	 * pointer that the function casts away is not a promise, it is a note
	 * to the compiler that nobody reads. Better to say what the function
	 * does than to describe the cast.
	 *
	 * The alternative was sorting eagerly, which means sorting on the
	 * drain path - and the key includes `group`, which is not known until
	 * after the fingerprint is interned. Both roads lead here.
	 */
	if (!r || i >= r->n_fp)
		return NULL;
	if (r->order_stale)
		reorder(r);
	return &r->fp[r->order[i]];
}

size_t kof_report_procs(struct kof_report *r)
{
	return r ? r->n_proc : 0;
}

const struct kof_rep_proc *kof_report_proc_at(struct kof_report *r, size_t i)
{
	if (!r || i >= r->n_proc)
		return NULL;
	return &r->proc[i];
}

uint64_t kof_report_dropped(struct kof_report *r, uint8_t kind)
{
	if (!r || kind >= KOF_FP_KIND_COUNT)
		return 0;
	return r->dropped[kind];
}
