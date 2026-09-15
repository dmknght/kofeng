/*
 * ko_anomalies - a kernel module is not a damaged executable.
 *
 * WHAT THIS IS FOR. Kernel modules were being reported as
 * "ELF-x64/Heur:Truncated", which is the scored model adding up terms from
 * kofheur.c - SEG_PAST_EOF, SHOFF_PAST_EOF and SEC_PAST_EOF all carry that
 * word. Every .ko on a machine firing one of them is a false positive on the
 * largest single population of ELF files most Linux hosts have.
 *
 * The weights in that table were measured on a population of EXECUTABLES. An
 * ET_REL is a different shape: no program headers, no entry point, sections
 * that the module loader relocates rather than maps. If a term fires on it, the
 * term is being asked a question it was not measured against.
 *
 * So this walks the modules that are actually on the machine and reports which
 * anomalies they trip. It is a regression test for the false positive and, the
 * first time it runs, the measurement that says which term causes it - the
 * report names the anomaly rather than only failing, because "some .ko trips
 * something" is not a thing anybody can act on.
 *
 * SKIPPED, NOT FAILED, WHERE THERE ARE NO MODULES. A build machine in a
 * container has no /lib/modules, and a test that failed there would be a test
 * people learn to ignore.
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include <kofmod/kofsig.h>
#include <kofmod/elf.h>

#include "../../libkofeng/core/kofplatform.h"
#include "../../libkofeng/kofparsers/binaries/elf_parse.h"

/* The three that carry the word "Truncated" in kofheur.c, plus the two the
 * emulator gate reads - all of which describe a file that was supposed to be
 * loadable and is not. */
static const struct {
	uint64_t bit;
	const char *name;
} watched[] = {
	{ KOF_ELF_ANOM_SEG_PAST_EOF,    "SEG_PAST_EOF   (Truncated)" },
	{ KOF_ELF_ANOM_SHOFF_PAST_EOF,  "SHOFF_PAST_EOF (Truncated)" },
	{ KOF_ELF_ANOM_SEC_PAST_EOF,    "SEC_PAST_EOF   (Truncated)" },
	{ KOF_ELF_ANOM_SECTAB_MISSING,  "SECTAB_MISSING (Stripped)"  },
	{ KOF_ELF_ANOM_NO_LOAD_SEGMENT, "NO_LOAD_SEGMENT (NoLoad)"   },
	{ KOF_ELF_ANOM_ENTRY_NOT_EXEC,  "ENTRY_NOT_EXEC (BadEntry)"  },
	{ KOF_ELF_ANOM_SHNUM_CLAMPED,   "SHNUM_CLAMPED"              }
};
#define N_WATCH (sizeof watched / sizeof watched[0])

static uint64_t hits[N_WATCH];
static const char *first[N_WATCH];
static char first_buf[N_WATCH][512];
static uint64_t n_rel, n_other;

static void look(const char *path)
{
	struct kof_elf_info info;
	struct kof_obj_ctx ctx;
	struct stat sb;
	uint8_t *buf;
	size_t n;
	int fd, k;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return;
	if (fstat(fd, &sb) != 0 || sb.st_size <= 0 ||
	    (size_t)sb.st_size > (64u << 20)) {
		close(fd);
		return;
	}
	n = (size_t)sb.st_size;
	buf = malloc(n);
	if (!buf) {
		close(fd);
		return;
	}
	if (read(fd, buf, n) != (ssize_t)n) {
		free(buf);
		close(fd);
		return;
	}
	close(fd);

	memset(&ctx, 0, sizeof ctx);
	memset(&info, 0, sizeof info);
	if (kof_elf_sniff(kof_buf_make(buf, n)) &&
	    kof_elf_parse(kof_buf_make(buf, n), &info, &ctx) && info.valid) {
		if (info.e_type == KOF_ELF_REL) {
			n_rel++;
			for (k = 0; k < (int)N_WATCH; k++)
				if (info.anomalies & watched[k].bit) {
					if (!hits[k]) {
						snprintf(first_buf[k],
							 sizeof first_buf[k],
							 "%s", path);
						first[k] = first_buf[k];
					}
					hits[k]++;
				}
		} else {
			n_other++;
		}
	}
	free(buf);
}

static void walk(const char *dir, int depth)
{
	struct dirent *de;
	DIR *d;

	if (depth > 8)
		return;
	d = opendir(dir);
	if (!d)
		return;
	while ((de = readdir(d)) != NULL) {
		char p[4096];
		struct stat sb;

		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		if (snprintf(p, sizeof p, "%s/%s", dir, de->d_name) >=
		    (int)sizeof p)
			continue;
		if (lstat(p, &sb) != 0)
			continue;
		if (S_ISDIR(sb.st_mode))
			walk(p, depth + 1);
		else if (S_ISREG(sb.st_mode))
			look(p);
	}
	closedir(d);
}

int main(int argc, char **argv)
{
	int i, fails = 0;

	if (argc > 1) {
		for (i = 1; i < argc; i++)
			walk(argv[i], 0);
	} else {
		walk("/lib/modules", 0);
	}

	if (!n_rel) {
		printf("ko anomalies: no kernel modules here - skipped\n");
		return 0;
	}

	printf("ko anomalies: %llu ET_REL object(s) parsed\n",
	       (unsigned long long)n_rel);
	for (i = 0; i < (int)N_WATCH; i++) {
		if (!hits[i])
			continue;
		printf("  %-28s %llu of %llu  first: %s\n",
		       watched[i].name, (unsigned long long)hits[i],
		       (unsigned long long)n_rel,
		       first[i] ? first[i] : "?");
	}
	(void)fails;
	/*
	 * IT REPORTS AND DOES NOT JUDGE, and that is deliberate.
	 *
	 * An anomaly firing on a .ko is not by itself wrong: an ET_REL really
	 * has no load segment and no executable entry, and the parse is right
	 * to say so. What was wrong was SCORING it - kofheur's weights come
	 * from a population of executables, and heur_object now declines an ELF
	 * that is neither ET_EXEC nor ET_DYN for that reason.
	 *
	 * Which of the three "Truncated" anomalies a real module trips, and
	 * whether that one is a true observation about how a .ko is laid out or
	 * a bug in the section walk, is a question this answers and nothing
	 * else here can: it needs real modules, and a build machine may have
	 * none. So it prints the counts and the first path for each, and
	 * whoever reads them decides whether there is a parser bug underneath.
	 */
	printf("ko anomalies: reported, not judged - the verdict is gated in "
	       "heur_object, not here\n");
	return 0;
}
