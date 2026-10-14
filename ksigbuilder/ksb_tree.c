/*
 * ksb_tree.c - --tree: a content directory in, a database out; the sources
 *    built side by side.
 */

#include "ksb.h"

#include <dirent.h>

/*
 * ---------------------------------------------------------------------------
 * --tree: a content directory in, a database out, with no shell involved.
 *
 *     ksigbuilder --tree <bases-dir> <artefact-dir> <database-dir>
 *
 * Walks the tree the way the build did - the top level and one level below it,
 * so the three kind directories are directories rather than a naming convention
 * - compiles every source, then packs the artefacts.
 *
 * WHY THIS EXISTS AND NOT JUST --module. A caller that has make and a POSIX
 * shell can loop over the sources itself, and did. A caller that has neither -
 * a Windows host with a compiler and PowerShell, which is the ordinary case
 * once MSYS2 is not assumed - cannot, and should not have to: the directory
 * layout, the order, and the emptying of the artefact directory before a build
 * are all decisions this program already owns. The loop belongs with them.
 *
 * The artefact directory is emptied first, and that is not tidiness: ksigbuilder
 * packs a DIRECTORY rather than a list of files, so anything left from a
 * previous run is in the database. A signature deleted from the source would
 * otherwise keep shipping because its blob was never removed - and the build
 * succeeds either way, which is what makes it worth doing here rather than
 * trusting every caller to remember.
 * ---------------------------------------------------------------------------
 */
int ksb_is_c_source(const char *name)
{
	size_t n = strlen(name);

	return n > 2u && !strcmp(name + n - 2u, ".c");
}

static int tree_one(struct ksb_ctx *ksb, char **argv, const char *src,
		    const char *artefacts, int *built)
{
	char *xa[4];

	xa[0] = argv[0];
	xa[1] = (char *)(size_t)"--module";
	xa[2] = (char *)(size_t)src;
	xa[3] = (char *)(size_t)artefacts;
	if (ksb_module_main(ksb, 4, xa) != 0)
		return 0;
	(*built)++;
	return 1;
}

/* ---- building the sources side by side ------------------------------------
 *
 * WHAT IS PARALLEL HERE AND WHAT IS NOT.
 *
 * One source becomes one artefact whose name is derived from its path, and
 * nothing a module build reads is written by another: the compile, the link and
 * the extraction touch only files named after that source. So the sources are
 * independent and the PACK step, which reads the whole artefact directory and
 * groups it, is not - it runs after, once, as it always did.
 *
 * MEASURED BEFORE IT WAS WRITTEN. The tree is 84 modules and 2.2 s in one
 * process, 27 ms each, of which the process machinery - 1177 execve and 420
 * clone for the whole tree - is 24 ms, about 1%. The other 99% is the compiler
 * doing its work, which is why this runs N compilers at once rather than trying
 * to make one cheaper: the same cc, the same ld, the same linker script.
 *
 * A PROCESS PER SOURCE, ON BOTH HOSTS. A module build is written against
 * one context - the source text, the declarations read out of it, the
 * counters - that a build fills and does not hand back clean, and making it
 * re-entrant would be a rewrite of the half of this tool that has nothing to
 * do with speed. POSIX forks, which hands the child a copy of all of it;
 * Windows has no fork, so it starts THIS program again with
 * the --module mode that already exists. Both are one process per source and
 * neither is a second way of building a module.
 *
 * AND THE LOG STAYS IN ORDER. Each child writes what it would have printed into
 * a file of its own and the parent prints them in SOURCE order as it collects
 * them, so the build reads exactly as the serial one did - which matters,
 * because warnings about a pattern being too short are read from this log.
 */
struct tree_job {
#ifdef _WIN32
	HANDLE proc;
#else
	pid_t  pid;
#endif
	int    live;
	char   log[512];
};

/* Print one child's captured output and remove the file it was in. */
static void job_flush(struct tree_job *j)
{
	FILE *f = fopen(j->log, "rb");
	char buf[4096];
	size_t n;

	if (f) {
		while ((n = fread(buf, 1, sizeof buf, f)) > 0)
			fwrite(buf, 1, n, stdout);
		fclose(f);
	}
	remove(j->log);
	fflush(stdout);
}

/*
 * Start one build in a child. Answers 0 when the child could not be started,
 * which the caller turns into a serial build of that source rather than a
 * failure: a process limit is not a reason to refuse to compile a signature.
 */
static int job_start(struct ksb_ctx *ksb, struct tree_job *j, char **argv,
		     const char *src, const char *artefacts,
		     const char *tmpdir, uint32_t n)
{
	j->live = 0;
	/* Named for THIS builder and this source, so two builds running side by
	 * side - the product tree and a working set - cannot read each other's
	 * logs. */
	snprintf(j->log, sizeof j->log, "%s/ksb-%lu-%u.log", tmpdir,
#ifdef _WIN32
		 (unsigned long)GetCurrentProcessId(),
#else
		 (unsigned long)getpid(),
#endif
		 n);
#ifdef _WIN32
	{
		char cmd[8192];
		STARTUPINFOA si;
		PROCESS_INFORMATION pi;
		SECURITY_ATTRIBUTES sa;
		HANDLE h;

		if (snprintf(cmd, sizeof cmd, "\"%s\" --module \"%s\" \"%s\"",
			     argv[0], src, artefacts) >= (int)sizeof cmd)
			return 0;
		memset(&sa, 0, sizeof sa);
		sa.nLength = sizeof sa;
		sa.bInheritHandle = TRUE;
		h = CreateFileA(j->log, GENERIC_WRITE, FILE_SHARE_READ, &sa,
				CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (h == INVALID_HANDLE_VALUE)
			return 0;
		memset(&si, 0, sizeof si);
		si.cb = sizeof si;
		si.dwFlags = STARTF_USESTDHANDLES;
		si.hStdOutput = h;
		si.hStdError = h;
		si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
		memset(&pi, 0, sizeof pi);
		if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL,
				    &si, &pi)) {
			CloseHandle(h);
			return 0;
		}
		CloseHandle(h);
		CloseHandle(pi.hThread);
		j->proc = pi.hProcess;
		j->live = 1;
		return 1;
	}
#else
	{
		pid_t pid;

		fflush(NULL);   /* nothing of the parent's is written twice */
		pid = fork();
		if (pid < 0)
			return 0;
		if (pid == 0) {
			int built = 0, ok;
			FILE *f = freopen(j->log, "wb", stdout);

			if (f)
				(void)dup2(fileno(stdout), fileno(stderr));
			ok = tree_one(ksb, argv, src, artefacts, &built);
			/*
			 * FLUSHED BY HAND, because _exit does not.
			 *
			 * exit() would, and it would also run the atexit
			 * handlers and the teardown of a process that is a COPY
			 * of the parent - which is what _exit is for in a
			 * child. So the one thing that would have been lost is
			 * done explicitly: without it every buffered line a
			 * module printed died with the child, and the build log
			 * held only what went to stderr.
			 */
			fflush(NULL);
			_exit(ok ? 0 : 1);
		}
		j->pid = pid;
		j->live = 1;
		return 1;
	}
#endif
}

/* Wait for one child. Non-zero when it finished successfully. */
static int job_wait(struct tree_job *j)
{
#ifdef _WIN32
	DWORD code = 1;

	WaitForSingleObject(j->proc, INFINITE);
	GetExitCodeProcess(j->proc, &code);
	CloseHandle(j->proc);
	j->live = 0;
	return code == 0;
#else
	int status = 0;

	while (waitpid(j->pid, &status, 0) < 0 && errno == EINTR)
		;
	j->live = 0;
	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
#endif
}

/*
 * The list the walk collects. GROWN, AND IT USED TO BE CAPPED AT 4096.
 *
 * The cap was argued from the shipping tree being 84 sources, and as a number
 * that is still true. What made it wrong was the code around it:
 *
 *     if (n_srcs < TREE_MAX_SRC)
 *             snprintf(srcs[n_srcs++], ...);
 *
 * Over the cap a source was DROPPED IN SILENCE. No message, no non-zero exit,
 * a database that builds cleanly and is missing rules - and a scan that then
 * misses detections with nothing anywhere saying why. Found by building a
 * 6181-source tree: 4096 modules loaded, 2085 discarded, and the corpus went
 * from 72 detections to 61 with a build log that reported no problem at all.
 *
 * A build tool may refuse work it cannot do. It may not pretend to have done
 * it. The list is grown instead, so there is no cap to be over.
 */
#define TREE_SRC_MAX  4200u

/*
 * THE CEILING ON WORKERS, AND WHY THERE IS ONE AT ALL.
 *
 * Each worker is a compiler, and a compiler is not a light process: asking for
 * more of them than the machine can run does not build anything faster, it
 * makes every other thing on that machine wait - including the editor the
 * person is watching the build from. A build tool that can be told to take the
 * whole machine will be, by a script nobody re-reads.
 *
 * So the number asked for is clamped to what the host actually has, and to
 * TREE_MAX_JOBS whatever the host says. Sixteen is far above the 84 modules
 * that ship - the tree is already under a second at eight - and low enough that
 * a wrong number cannot be catastrophic.
 */
#define TREE_MAX_JOBS 16u

static uint32_t tree_job_cap(void)
{
#ifdef _WIN32
	SYSTEM_INFO si;

	GetSystemInfo(&si);
	return si.dwNumberOfProcessors ? (uint32_t)si.dwNumberOfProcessors : 1u;
#else
	long n = sysconf(_SC_NPROCESSORS_ONLN);

	return n > 0 ? (uint32_t)n : 1u;
#endif
}

static int tree_src_cmp(const void *a, const void *b)
{
	return strcmp((const char *)a, (const char *)b);
}

/*
 * Build every source, `jobs` at a time, and answer 0 when any of them failed.
 *
 * ONE AT A TIME IS STILL THE PATH ON WINDOWS and whenever jobs is 1: there is
 * no fork there, and re-exec'ing this program per source to get one would be a
 * second way of building a module - which is the thing this file exists to not
 * have. See the note over job_start.
 *
 * A FAILURE STOPS THE LAUNCHING, NOT THE COLLECTING. The children already
 * running are waited for and their output printed: a build that fails should
 * say everything it found, and half a log with orphaned processes behind it is
 * worse than a slightly longer one.
 */
static int tree_build(struct ksb_ctx *ksb, char **argv,
		      char (*srcs)[TREE_SRC_MAX], uint32_t n,
		      const char *artefacts, uint32_t jobs, int *built)
{
	uint32_t i;

	if (jobs > 1u && n > 1u) {
		static struct tree_job job[TREE_MAX_JOBS];
		const char *tmp = ksb->opt.tmpdir;
		uint32_t next = 0, live = 0, slot = 0, win;
		int bad = 0;

		if (!tmp || !tmp[0])
			tmp = kof_tmpdir();
		win = jobs < n ? jobs : n;
		for (i = 0; i < win; i++)
			job[i].live = 0;

		/* Fill the window. */
		for (i = 0; i < win && next < n; i++, next++) {
			if (job_start(ksb, &job[i], argv, srcs[next], artefacts,
				      tmp, next))
				live++;
			else if (!tree_one(ksb, argv, srcs[next], artefacts, built))
				bad = 1;        /* no fork - built here */
		}

		/*
		 * COLLECTED IN SLOT ORDER, WHICH IS SOURCE ORDER: slot i holds
		 * sources i, i+win, i+2*win..., so walking the slots in a ring
		 * prints them in the order the list had. An empty slot is one
		 * whose source list ran out; it is skipped, never waited on
		 * twice - a second waitpid on a reaped child answers ECHILD
		 * with the status untouched, which reads as "exited 0" and
		 * would count a module that was never built.
		 */
		while (live) {
			int ok;

			if (!job[slot].live) {
				slot = (slot + 1u) % win;
				continue;
			}
			ok = job_wait(&job[slot]);
			job_flush(&job[slot]);
			live--;
			if (!ok)
				bad = 1;
			else
				(*built)++;
			if (next < n && !bad) {
				if (job_start(ksb, &job[slot], argv, srcs[next],
					      artefacts, tmp, next))
					live++;
				else if (!tree_one(ksb, argv, srcs[next], artefacts,
						   built))
					bad = 1;
				next++;
			}
			slot = (slot + 1u) % win;
		}
		return !bad;
	}
	for (i = 0; i < n; i++)
		if (!tree_one(ksb, argv, srcs[i], artefacts, built))
			return 0;
	return 1;
}

/*
 * One more source on the list, growing it when it is full.
 *
 * Doubling from 256: a hand-written tree never reallocates more than a few
 * times, and a generated one of two hundred thousand does it eighteen. Answers
 * 0 only when the machine is out of memory, which the caller reports rather
 * than skipping the source - see the note on TREE_SRC_MAX.
 */
static int tree_src_add(char (**srcs)[TREE_SRC_MAX], uint32_t *n,
			uint32_t *cap, const char *path)
{
	if (*n == *cap) {
		uint32_t want = *cap ? *cap * 2u : 256u;
		char (*nv)[TREE_SRC_MAX] = realloc(*srcs,
						   (size_t)want * TREE_SRC_MAX);

		if (!nv)
			return 0;
		*srcs = nv;
		*cap = want;
	}
	snprintf((*srcs)[(*n)++], TREE_SRC_MAX, "%s", path);
	return 1;
}

/* "--jobs N" after the three paths, clamped to what the host can usefully run.
 * Zero, with the usage printed, when the command line is wrong. */
static int tree_args(int argc, char **argv, uint32_t *jobs)
{
	*jobs = 1;

	if (argc == 7 && strcmp(argv[5], "--jobs") == 0) {
		long v = strtol(argv[6], NULL, 10);
		uint32_t cap = tree_job_cap();

		*jobs = v > 0 ? (uint32_t)v : 1u;
		if (cap > TREE_MAX_JOBS)
			cap = TREE_MAX_JOBS;
		/* Clamped rather than refused: a number out of a script is not
		 * worth failing a build over, and the clamp is what the number
		 * meant - "as many as this machine can usefully run". */
		if (*jobs > cap) {
			if (v > (long)cap)
				fprintf(stderr, "ksigbuilder: %ld job(s) asked "
					"for, %u used - see TREE_MAX_JOBS\n",
					v, cap);
			*jobs = cap;
		}
		argc = 5;
	}
	if (argc != 5) {
		fprintf(stderr, "usage: %s --tree <bases-dir> <artefact-dir> "
				"<database-dir> [--jobs N]\n", argv[0]);
		return 0;
	}
	return 1;
}

/* Walk the tree: the sources at the top and one level down, as a list. Zero, or
 * the exit code. The list is the caller's, and is freed here on failure. */
static int tree_collect(const char *base, char (**srcs)[TREE_SRC_MAX],
			uint32_t *n_srcs, uint32_t *n_cap)
{
	DIR *d;
	struct dirent *e;

	/*
	 * THE WALK IS A LIST, AND THE LIST IS SORTED.
	 *
	 * Collected before anything is built, because the builds can then run
	 * side by side - see the note over job_start. Sorted because readdir
	 * order is the filesystem's and nobody's else: the same tree gave a
	 * different build log on two machines, and a log that reorders itself
	 * is a log nobody diffs.
	 */
	d = opendir(base);
	if (!d) {
		fprintf(stderr, "ksigbuilder: cannot read %s\n", base);
		return 2;
	}
	while ((e = readdir(d)) != NULL) {
		char path[2048];

		if (e->d_name[0] == '.')
			continue;
		snprintf(path, sizeof path, "%s/%s", base, e->d_name);
		if (ksb_is_c_source(e->d_name)) {
			if (!tree_src_add(srcs, n_srcs, n_cap, path)) {
				fprintf(stderr, "ksigbuilder: out of memory "
					"collecting sources\n");
				closedir(d);
				free(*srcs);
				return 1;
			}
			continue;
		}
		/* One level down, which is where the kind directories are. */
		{
			DIR *sd;
			struct dirent *se;

			/*
			 * DIAGNOSES ARE NOT MODULES and must not reach the
			 * module path: they declare no target, no verdict and
			 * no code, so the first thing it would ask them for -
			 * KOF_TARGET_FORMAT - is a thing they correctly do
			 * not have. They are built below, by name, into a
			 * file of their own.
			 */
			if (strcmp(e->d_name, "diagnoses") == 0 ||
			    strcmp(e->d_name, "syndromes") == 0)
				continue;
			sd = opendir(path);
			if (!sd)
				continue;
			while ((se = readdir(sd)) != NULL) {
				char sub[4200];

				if (se->d_name[0] == '.' ||
				    !ksb_is_c_source(se->d_name))
					continue;
				snprintf(sub, sizeof sub, "%s/%s", path,
					 se->d_name);
				if (!tree_src_add(srcs, n_srcs, n_cap,
						  sub)) {
					fprintf(stderr, "ksigbuilder: out of "
						"memory collecting sources\n");
					closedir(sd);
					closedir(d);
					free(*srcs);
					return 1;
				}
			}
			closedir(sd);
		}
	}
	closedir(d);
	qsort(*srcs, *n_srcs, TREE_SRC_MAX, tree_src_cmp);
	return 0;
}

/*
 * AND THE DIAGNOSES, which go through a step of their own.
 *
 * Each is built to a RECORD in the artefact directory, the way a signature
 * is built to a blob, and the records are then written into one pack per
 * KIND - see ksb_write_diag_packs. They used to be one file each in the
 * database directory, which made the database a pack plus however many
 * loose files a build happened to produce.
 *
 * Zero, or the exit code; the syndromes are built here too.
 */
static int tree_diagnoses(struct ksb_ctx *ksb, char *argv0, const char *base,
			  const char *artefacts, const char *db)
{

	char dpath[4200];
	DIR *dd;
	struct dirent *de;
	char **recs = NULL, **kinds = NULL;
	size_t n_recs = 0;

	snprintf(dpath, sizeof dpath, "%s/diagnoses", base);
	dd = opendir(dpath);
	while (dd && (de = readdir(dd)) != NULL) {
		char in[4300], out[4320], *dot, **grown, **kgrown;
		char *da[4], *us;

		if (de->d_name[0] == '.' || !ksb_is_c_source(de->d_name))
			continue;
		/* The kind is the first word: net_cncnonblock_00.c is a net
		 * diagnose. A name with no kind cannot be put in a pack. */
		us = strchr(de->d_name, '_');
		if (!us || us == de->d_name) {
			fprintf(stderr, "ksigbuilder: %s names no kind; a "
				"diagnose is <kind>_<name>_NN.c\n",
				de->d_name);
			closedir(dd);
			return 1;
		}
		snprintf(in, sizeof in, "%s/%s", dpath, de->d_name);
		snprintf(out, sizeof out, "%s/diag-%s", artefacts,
			 de->d_name);
		dot = strrchr(out, '.');
		if (dot)
			memcpy(dot, ".rec", 5u);
		da[0] = argv0;
		da[1] = (char *)(size_t)"--diagnose";
		da[2] = in;
		da[3] = out;
		if (ksb_diagnose_main(ksb, 4, da) != 0) {
			closedir(dd);
			return 1;
		}
		grown = realloc(recs, (n_recs + 1u) * sizeof *recs);
		if (grown)
			recs = grown;
		kgrown = realloc(kinds, (n_recs + 1u) * sizeof *kinds);
		if (kgrown)
			kinds = kgrown;
		if (!grown || !kgrown || !(recs[n_recs] = strdup(out)) ||
		    !(kinds[n_recs] = ksb_dup_n(de->d_name, (size_t)(us - de->d_name)))) {
			fprintf(stderr, "ksigbuilder: out of memory\n");
			closedir(dd);
			return 1;
		}
		n_recs++;
	}
	if (dd)
		closedir(dd);
	if (!ksb_write_diag_packs(db, recs, kinds, n_recs))
		return 1;
	if (!ksb_build_syndromes(ksb, base, db))
		return 1;
	while (n_recs > 0) {
		free(recs[--n_recs]);
		free(kinds[n_recs]);
	}
	free(recs);
	free(kinds);
	return 0;
}

/*
 * THE TWO WAYS A CALL AND A DIAGNOSE CAN DISAGREE, checked in both
 * directions because both are mistakes an author cannot see.
 *
 * A call to a diagnose that does not exist answers no, always and
 * silently - kof_diag returns zero for a name nobody carries - so a
 * verdict that misspells one is a verdict that never fires, and nothing
 * would say so. That is an ERROR.
 *
 * A diagnose nothing calls and that declares no disease is not a mistake in
 * the build but is one in the tree: the engine will not run it, which is the
 * point, but whoever wrote it should be told it does nothing yet. One that
 * declares a disease is read by the verdict (the diseases an object has make
 * it) and is run.
 *
 * Zero when no call is dangling.
 */
static int tree_check_uses(const struct ksb_ctx *ksb, const char *base)
{

	unsigned q, z;
	int dangling = 0;

	for (q = 0; q < ksb->diag.n_uses; q++) {
		for (z = 0; z < ksb->diag.n_built; z++)
			if (!strcmp(ksb->diag.built[z], ksb->diag.uses[q].diag))
				break;
		if (z == ksb->diag.n_built) {
			fprintf(stderr, "ksigbuilder: %s reads diagnose "
				"\"%s\", which no source in %s/diagnoses "
				"declares\n", ksb->diag.uses[q].user,
				ksb->diag.uses[q].diag, base);
			dangling = 1;
		}
	}
	for (z = 0; z < ksb->diag.n_built; z++) {
		for (q = 0; q < ksb->diag.n_uses; q++)
			if (!strcmp(ksb->diag.built[z], ksb->diag.uses[q].diag))
				break;
		/* A diagnose that declares a disease is read by the verdict, which
		 * is made of the diseases an object has - the engine runs it. */
		if (q == ksb->diag.n_uses && !ksb->diag.built_dis[z])
			fprintf(stderr, "ksigbuilder: warning: diagnose "
				"%s is read by no rule and declares no disease, "
				"so the engine will not run it\n", ksb->diag.built[z]);
	}
	if (dangling)
		return 1;
	return 0;
}

int ksb_tree_main(struct ksb_ctx *ksb, int argc, char **argv)
{
	const char *base = argc > 2 ? argv[2] : NULL;
	const char *artefacts = argc > 3 ? argv[3] : NULL;
	const char *db = argc > 4 ? argv[4] : NULL;
	char abs_base[4096];
	char (*srcs)[TREE_SRC_MAX] = NULL;
	uint32_t n_srcs = 0, n_cap = 0, jobs = 1;
	int built = 0, rc;

	if (!tree_args(argc, argv, &jobs))
		return 2;
	/* KOF_BASEDIR is what --module strips to name an artefact, and it has
	 * to be the absolute form of the tree being walked - set here so a
	 * caller cannot pass one that disagrees with the other argument. */
	if (!kof_abs_path(base, abs_base, sizeof abs_base)) {
		fprintf(stderr, "ksigbuilder: no such directory: %s\n", base);
		return 2;
	}
#ifdef _WIN32
	_putenv_s("KOF_BASEDIR", abs_base);
#else
	setenv("KOF_BASEDIR", abs_base, 1);
#endif

	rc = tree_collect(base, &srcs, &n_srcs, &n_cap);
	if (rc)
		return rc;
	if (!tree_build(ksb, argv, srcs, n_srcs, artefacts, jobs, &built)) {
		free(srcs);
		return 1;
	}

	/*
	 * WHICH SIGNATURE READS WHICH DIAGNOSE, before the sources are let go.
	 * See the note on struct diag_use: worked out from the calls, never
	 * declared, so it cannot disagree with what a verdict does.
	 */
	ksb->diag.n_uses = 0;
	{
		uint32_t q;

		for (q = 0; q < n_srcs; q++)
			ksb_uses_scan(ksb, srcs[q]);
		ksb->diag.uses_known = 1;
	}
	free(srcs);
	srcs = NULL;
	if (!built) {
		fprintf(stderr, "ksigbuilder: no sources in %s\n", base);
		return 2;
	}
	printf("   %d source(s) from %s -> %s\n", built, base, artefacts);
	rc = tree_diagnoses(ksb, argv[0], base, artefacts, db);
	if (rc)
		return rc;

	if (tree_check_uses(ksb, base))
		return 1;
	/* And pack, which is what this program did before it did anything
	 * else. */
	{
		char *pa[3];

		pa[0] = argv[0];
		pa[1] = (char *)(size_t)artefacts;
		pa[2] = (char *)(size_t)db;
		return ksb_pack_main(ksb, 3, pa);
	}
}
