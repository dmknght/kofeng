/*
 * SWITCHED OFF (owner, 2026-10-27): the Syndrome table and its tag-source backend (kofexamine/kv_syn.c, kv_syntable.c,
 * libkofeng/databases/tagsrc*, ksigbuilder/ksb_tags.c) stay in the tree and are to be removed later, when asked. The menu item
 * is Manage > Syndromes, listed and greyed. Do not extend this code.
 */
/*
 * ksb_tags.c - `ksigbuilder --tags <dir>`: the Check of the tag sources.
 *
 * The same kof_tagset_check the viewer's Check runs, printed one line to a
 * finding and ended by the counts. Nothing is written. The exit status is 1
 * when there is an error, so a build can refuse a directory the viewer would.
 */

#include "ksb.h"
#include <databases/tagsrc.h>

static void say(void *ud, int level, const char *subject, const char *msg)
{
	static const char *const word[] = { "info", "warning", "error" };
	unsigned *count = ud;

	if (level >= 0 && level <= 2)
		count[level]++;
	printf("%s: %s: %s\n", word[level >= 0 && level <= 2 ? level : 0],
	       subject, msg);
}

int ksb_tags_main(int argc, char **argv)
{
	struct kof_tagset set;
	struct kof_tagsrc_report rep;
	unsigned count[3] = { 0, 0, 0 };
	int errs;

	if (argc != 3) {
		fprintf(stderr, "usage: %s --tags <directory>\n", argv[0]);
		return 2;
	}
	kof_tagset_init(&set);
	if (!kof_tagset_load(&set, argv[2])) {
		fprintf(stderr, "ksigbuilder: cannot read %s\n", argv[2]);
		return 2;
	}
	rep.say = say;
	rep.ud = count;
	errs = kof_tagset_check(&set, &rep);
	printf("%zu entities, %d error(s), %u warning(s), %u note(s)\n",
	       set.n, errs, count[KOF_TAGSRC_WARN], count[KOF_TAGSRC_INFO]);
	kof_tagset_free(&set);
	return errs ? 1 : 0;
}
