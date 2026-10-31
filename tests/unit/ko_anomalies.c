/*
 * ko_anomalies - a kernel module is not a damaged executable.
 *
 * WHAT THIS IS FOR. An ET_REL is a different shape from an executable: no
 * program headers, no entry point, sections that the module loader relocates
 * rather than maps. So this walks the modules that are actually on the machine
 * and reports which parser anomalies they trip - the report names the anomaly
 * rather than only failing, because "some .ko trips something" is not a thing
 * anybody can act on. It was written when a scored model (since removed) turned
 * these anomalies into a verdict; the anomalies themselves are the parser's.
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

#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/analyzers/parsers/binaries/elf/elf_parse.h"

/* The anomalies that describe a file that was supposed to be loadable and is not. */
static const struct {
	uint64_t bit;
	const char *name;
} watched[] = {
	{ KGENOME_ELF_ANOM_SEG_PAST_EOF,    "SEG_PAST_EOF   (Truncated)" },
	{ KGENOME_ELF_ANOM_SHOFF_PAST_EOF,  "SHOFF_PAST_EOF (Truncated)" },
	{ KGENOME_ELF_ANOM_SEC_PAST_EOF,    "SEC_PAST_EOF   (Truncated)" },
	{ KGENOME_ELF_ANOM_SECTAB_MISSING,  "SECTAB_MISSING (Stripped)"  },
	{ KGENOME_ELF_ANOM_NO_LOAD_SEGMENT, "NO_LOAD_SEGMENT (NoLoad)"   },
	{ KGENOME_ELF_ANOM_ENTRY_NOT_EXEC,  "ENTRY_NOT_EXEC (BadEntry)"  },
	{ KGENOME_ELF_ANOM_SHNUM_CLAMPED,   "SHNUM_CLAMPED"              }
};
#define N_WATCH (sizeof watched / sizeof watched[0])

static uint64_t hits[N_WATCH];
static const char *first[N_WATCH];
static char first_buf[N_WATCH][512];
static uint64_t n_rel, n_other;

static void look(const char *path)
{
	struct kgenome_elf_info info;
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
	if (kgenome_elf_sniff(kof_buf_make(buf, n)) &&
	    kof_elf_parse(kof_buf_make(buf, n), &info, &ctx) && info.valid) {
		if (info.e_type == KGENOME_ELF_REL) {
			n_rel++;
			for (k = 0; k < (int)N_WATCH; k++)
				if (info.anomalies & watched[k].bit) {
					if (!hits[k]) {
						/* A precision, not a bare %s: a
						 * module path can be 4096 and
						 * this buffer is 512. Truncating
						 * is fine - it is a name printed
						 * in a summary - but saying so
						 * is what keeps the build quiet
						 * about it. */
						snprintf(first_buf[k],
							 sizeof first_buf[k],
							 "%.*s",
							 (int)sizeof first_buf[k] - 1,
							 path);
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
	 * to say so. Whether a real module trips one of the "past EOF" anomalies
	 * because of how a .ko is laid out or because of a bug in the section
	 * walk is a question only real modules answer, and a build machine may
	 * have none. So it prints the counts and the first path for each, and
	 * whoever reads them decides whether there is a parser bug underneath.
	 */
	printf("ko anomalies: reported, not judged\n");
	return 0;
}
