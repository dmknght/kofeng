/*
 * rule_roundtrip - open every shipped rule in the editor, write it back, and
 * check that nothing about it changed.
 *
 * WHY THIS IS THE TEST THAT WAS MISSING. kofviewer's panel is a MODEL of a
 * signature - formats, ranges, patterns, matchers, conditions - and a rule goes
 * through it whenever anybody looks at one. Every field the model cannot hold
 * is a field that disappears on the next save, silently, from a file that still
 * compiles and still finds things.
 *
 * Three such losses were found by hand in one week: the subtype (the reader
 * knew KOF_ELF_ and KOF_PE_ and the writer had learned KOF_SCRIPT_),
 * KOF_TARGET_FORMAT (written and never read at all, so every reopened draft had
 * an empty format mask), and the scan RANGE - region names were resolved
 * against whatever object the reader happened to have open, so opening an ELF
 * rule while looking at a php file and saving it turned
 * KOF_SCAN_ELF_CODE into KOF_SCAN_ALL. 49 of the 52 rules in bases/signatures
 * are region-scoped, so that one was nearly all of them.
 *
 * None of the three failed a build, none printed anything, and none changed
 * what the rule found on the sample it was written from. They changed what it
 * searched.
 *
 * THE PROPERTY: read -> generate -> read gives the same draft. A writer that
 * drops a field shows up as the second draft differing from the first, whatever
 * the file looks like.
 *
 * A rule the panel REFUSES to write is not a failure here. mirai_00 carries
 * logic the model does not express and the editor says so rather than writing a
 * lesser rule; that refusal is the model working, and the count is printed so a
 * refusal that spreads is visible.
 */

/* mkdtemp and readdir: POSIX, and the same declaration pack_load.c asks for. */
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>

#include "../../kofexamine/kofeditor.h"
#include "../../kofexamine/kofinspect.h"

static int fails;
static struct kof_editor E;
static struct object obs[4];
static uint32_t n_obj = 1, foreign;
static char sample[16][128], who[16][48], made[24];
static uint32_t n_sample, n_who;
static struct kof_range scratch[KOF_SCAN_MAX_EXTENTS];

static void bad(const char *rule, const char *what)
{
	printf("  FAIL %-24s %s\n", rule, what);
	fails++;
}

/*
 * A DRAFT OWNS HEAP - every declared pattern's bytes - and draft_clear is what
 * gives it back. Zeroing the editor on top of a loaded draft drops those
 * pointers instead, which the sanitised build reports as a leak per rule and
 * per string: 283 allocations over the 53 rules here.
 */
static void ed_done(void)
{
	if (E.obj)
		draft_clear(&E);
}

static void ed_init(void)
{
	ed_done();
	memset(&E, 0, sizeof E);
	memset(obs, 0, sizeof obs);
	memset(sample, 0, sizeof sample);
	memset(who, 0, sizeof who);
	made[0] = 0;
	n_sample = n_who = 0;
	/*
	 * AND THE FOREIGN FLAG, which is not inside the editor.
	 *
	 * It says "this file holds logic the panel cannot write back", and it
	 * is the host's variable rather than the draft's. Left set from the
	 * previous rule it made every rule after the first foreign one look
	 * foreign too - fifty-one declines where there are eight.
	 */
	foreign = 0;
	E.obj = obs;
	E.n_obj = &n_obj;
	E.foreign = &foreign;
	E.foreign_w = &foreign;
	E.sample = sample;
	E.n_sample = &n_sample;
	E.who = who;
	E.n_who = &n_who;
	E.made = &made;
	E.scratch = scratch;
}

/*
 * What a rule MEANS, as one string.
 *
 * Compared as text rather than field by field so that a field added to the
 * model later is compared the moment it is written here, and so a failure says
 * which part differs instead of only that something did.
 */
static void draft_text(struct kof_editor *e, char *out, size_t cap)
{
	size_t n = 0;
	uint32_t i;

	n += (size_t)snprintf(out + n, cap - n,
			      "fmt=%#x type=%u family=%s\n",
			      e->dr.fmt_mask, e->dr.maltype, e->dr.family);
	for (i = 0; i < OPT_COUNT && n < cap; i++)
		if (e->dr.opt_on[i])
			n += (size_t)snprintf(out + n, cap - n,
					      "opt%u=%llu\n", i,
					      (unsigned long long)
					      e->dr.opt_val[i]);
	for (i = 0; i < e->dr.n_decl && n < cap; i++) {
		const struct decl *d = &e->dr.decl[i];
		uint32_t k;

		n += (size_t)snprintf(out + n, cap - n,
				      "str%u hex=%d wide=%d fw=%d mask=%#x "
				      "nbytes=%u hexs=%s bytes=", i, d->hex,
				      d->wide, d->fullword, d->mask,
				      d->nbytes, d->hexs);
		for (k = 0; k < d->nbytes && n + 3u < cap; k++)
			n += (size_t)snprintf(out + n, cap - n, "%02X",
					      d->bytes[k]);
		n += (size_t)snprintf(out + n, cap - n, "\n");
	}
	for (i = 0; i < e->dr.n_grp && n < cap; i++)
		n += (size_t)snprintf(out + n, cap - n,
				      "grp%u rule=%d thresh=%u mask=%#x "
				      "at=%llu\n", i, e->dr.grp[i].rule,
				      e->dr.grp[i].thresh, e->dr.grp[i].mask,
				      (unsigned long long)e->dr.grp[i].at_off);
	for (i = 0; i < e->dr.n_cnd && n < cap; i++) {
		const struct cond *c = &e->dr.cnd[i];

		n += (size_t)snprintf(out + n, cap - n,
				      "cnd%u expr=%s op=%d join=%d level=%d "
				      "var=%d name=%s parent=%d\n", i, c->expr,
				      c->op, c->join, c->level, c->var_kind,
				      c->variant, c->parent);
	}
}

int main(void)
{
	static char a[16384], b[16384];
	static const char *dir = "bases/signatures";
	char outdir[] = "build/test/rt_XXXXXX";
	uint32_t n_ok = 0, n_declined = 0;
	struct dirent *de;
	DIR *d;

	if (!mkdtemp(outdir)) {
		printf("rule roundtrip: cannot make a work directory\n");
		return 0;               /* not the property under test */
	}
	d = opendir(dir);
	if (!d) {
		printf("rule roundtrip: %s is not there - run from the tree "
		       "root\n", dir);
		return 0;
	}
	while ((de = readdir(d)) != NULL) {
		char path[512], gen[sizeof E.dr.gen_path];
		size_t ln = strlen(de->d_name);

		if (ln < 3 || strcmp(de->d_name + ln - 2, ".c"))
			continue;
		snprintf(path, sizeof path, "%s/%s", dir, de->d_name);

		ed_init();
		E.basedir = outdir;
		if (!draft_from_source(&E, path)) {
			bad(de->d_name, "the editor could not read it at all");
			continue;
		}
		draft_text(&E, a, sizeof a);

		generate(&E, 0);
		if (!E.dr.gen_ok) {
			/* Said out loud, with the reason the panel gives. */
			n_declined++;
			if (getenv("RT_WHY"))
				printf("  declined %-22s %s\n", de->d_name,
				       E.dr.warn);
			continue;
		}
		/* COPIED, not pointed at: ed_init below zeroes the editor,
		 * and the path lives inside it. */
		snprintf(gen, sizeof gen, "%s", E.dr.gen_path);

		ed_init();
		E.basedir = outdir;
		if (!draft_from_source(&E, gen)) {
			bad(de->d_name, "the rule it wrote cannot be read "
			    "back");
			continue;
		}
		draft_text(&E, b, sizeof b);

		if (strcmp(a, b) != 0) {
			const char *p = a, *q = b;
			char la[200], lb[200];
			size_t k;

			/* The first line that differs, which is the field. */
			while (*p && *q) {
				const char *ea = strchr(p, '\n');
				const char *eb = strchr(q, '\n');

				if (!ea || !eb)
					break;
				if ((size_t)(ea - p) != (size_t)(eb - q) ||
				    memcmp(p, q, (size_t)(ea - p)))
					break;
				p = ea + 1;
				q = eb + 1;
			}
			for (k = 0; k + 1 < sizeof la && p[k] && p[k] != '\n';
			     k++)
				la[k] = p[k];
			la[k] = 0;
			for (k = 0; k + 1 < sizeof lb && q[k] && q[k] != '\n';
			     k++)
				lb[k] = q[k];
			lb[k] = 0;
			printf("  FAIL %-24s the save changed it\n"
			       "        was:  %s\n        came back: %s\n",
			       de->d_name, la, lb);
			fails++;
			continue;
		}
		n_ok++;
	}
	closedir(d);
	ed_done();

	if (!n_ok && !n_declined) {
		printf("rule roundtrip: no rules were read - nothing was "
		       "tested\n");
		return 1;
	}
	if (fails) {
		printf("rule roundtrip: %d rule(s) changed on save\n", fails);
		return 1;
	}
	printf("rule roundtrip: %u rule(s) survive read-write-read "
	       "unchanged, %u declined by the model - ok\n", n_ok, n_declined);
	return 0;
}
