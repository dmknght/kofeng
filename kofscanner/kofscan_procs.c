/*
 * kofscan_procs.c - scanning what is running: the cache hooks and ksn_scan_procs. Split from
 * kofscanner.c; the text is unchanged.
 */

/*
 * Before any include, not after: a feature test macro placed after the first
 * system header has no effect at all. The reason is stated in kofscanner.c; this
 * unit is a translation unit of the same program and says the same.
 */
#ifndef _WIN32
#define _GNU_SOURCE
#endif

#include "kofscanner_int.h"

/* ------------------------------------------------- scanning what is running
 *
 * WHY THIS IS IN THE SCANNER AND NOT A TOOL OF ITS OWN.
 *
 * A process is another place bytes live. Everything else about the scan is the
 * same - the same database, the same verdict, the same rollup - and the only
 * thing that differs is where the bytes come from. Splitting it out would give
 * two programs that must agree about what "infected" means.
 *
 *
 * AND WHY THE WALK IS NOT IN HERE.
 *
 * Deciding that a file-backed mapping is scanned as its FILE, that an
 * anonymous executable region is scanned as BYTES, and that a kernel mapping
 * is neither, are answers about an operating system's process table. They
 * belong to the collector that owns that table - libkoforbit/antarc on Linux,
 * libkoforbit/grille on Windows - and this file asks for them through
 * libkoforbit/walk/kofwalk.h. It was written the other way round first,
 * and the cost of that would have been making all three decisions a second
 * time, slightly differently, for the other platform.
 *
 *
 * THE CACHE IS THE WHOLE REASON THIS IS AFFORDABLE, and the number is why.
 *
 * Measured on this machine: 5795 file-backed mappings across the readable
 * processes, and 335 distinct files behind them - 17.3 to one. libc.so.6 is
 * mapped a hundred times. Scanning each mapping would scan libc a hundred
 * times to reach the same answer a hundred times.
 *
 * So a file is identified - one stat - and looked up; on a miss it is scanned
 * and the answer remembered. That needs no process tree and no relationship
 * between processes: the key is the file's identity, so two processes sharing
 * a library share an answer by construction.
 *
 * WHAT CANNOT BE CACHED IS WHAT MATTERS MOST, and that is not a coincidence.
 * Bytes with no file behind them exist in one process at one instant. They are
 * read and scanned every time, and there is little of them - measured, about
 * 48 MB across this machine.
 */


struct procscan {
	struct run       *r;
	kof_scanner      *sc;
	/*
	 * THE SAME SET THE FILE SWEEP USES - see fidset.h.
	 *
	 * It was a koffridge here and nothing at all on the file path, so the
	 * two sweeps cached by different rules with different failure modes and
	 * only one of them was ever exercised. One mechanism now, asked through
	 * the engine, so a fault in it is a fault in both and gets found.
	 */
	struct kof_fidset *fs;
	struct kof_scan_option *opt;
	struct cache_hook hook;

	uint64_t files_scanned, files_cached;
	uint64_t chunks, chunk_bytes;
	/* Runs of a loaded module that differ from the file it was mapped
	 * from - see wdiff.h. Its own line, because an unbacked allocation
	 * and a modified module are different findings. */
	uint64_t patches, patch_bytes;
};

/* One file behind a mapping: scan it only if this sweep has not already
 * answered for it. */

/*
 * THE TWO ANSWERS THE ENGINE ASKS FOR - see cache_seen in kofeng.h.
 *
 * This is the whole of what the engine knows about caching: two functions and
 * an opaque pointer. It does not know the key is a file identity, that the
 * identity comes from a stat, that the set lives in a file, or that anything
 * called a fridge exists. All of that is a property of a MACHINE, and the
 * engine is the part that is the same everywhere.
 *
 * An identity that cannot be established means no caching for that file - not a
 * zeroed key. A key that could not be computed must not be invented: every
 * unidentifiable file would share it, and one of them being called clean would
 * speak for all of them.
 */
int ksn_fid_seen(void *user, const char *path)
{
	struct cache_hook *h = user;
	struct kof_fid id;

	if (!h || !h->fs || !kof_fid_of(path, &id))
		return 0;
	if (!kof_fidset_has(h->fs, kof_fid_key(&id)))
		return 0;
	/*
	 * SKIPPED, AND SAID SO. The same rate limit the scanned path uses, so
	 * a cached sweep costs no more terminal writes than a cold one - it
	 * just stops being silent.
	 */
	if (h->r) {
		h->r->cached_seen++;
		ksn_progress_draw(h->r, path);
	}
	return 1;
}

void ksn_fid_keep(void *user, const char *path)
{
	struct kof_fid id;

	struct cache_hook *h = user;

	if (!h || !h->fs || !kof_fid_of(path, &id))
		return;
	(void)kof_fidset_add(h->fs, kof_fid_key(&id));
}

/*
 * AND THE THIRD ANSWER: this file is not clean, so whatever the set says about
 * it is wrong - see kof_fidset_drop.
 *
 * Wired even when the set is not being READ, which is the case it is for: a
 * --no-cache run is the one that reaches a file an older entry would have
 * skipped, and its finding has to outlive the run that made it.
 */
/*
 * "written 3 h ago", or nothing when the file did not ksn_say.
 *
 * The header keeps seconds since the epoch - an integer, for the reasons the
 * field's own note gives - and a person reading a build log wants an age, so
 * the conversion is here, in the tool that prints, and not in the format.
 */
void ksn_cache_age(uint64_t made, char *out, size_t cap)
{
	time_t now = time(NULL);
	long long age;

	out[0] = 0;
	if (!made || now == (time_t)-1)
		return;
	age = (long long)now - (long long)made;
	if (age < 0)
		age = 0;
	if (age < 90)
		snprintf(out, cap, ", written %llds ago", age);
	else if (age < 90 * 60)
		snprintf(out, cap, ", written %lldm ago", age / 60);
	else if (age < 48 * 3600)
		snprintf(out, cap, ", written %lldh ago", age / 3600);
	else
		snprintf(out, cap, ", written %lld day(s) ago", age / 86400);
}

/*
 * THE ENGINE THESE ANSWERS CAME FROM, as one number - see kof_fidset_open.
 *
 * Version and build together: the build alone moves every hour and the version
 * alone does not move between releases of the same number.
 */
uint64_t ksn_engine_stamp(void)
{
	struct kof_version v;

	memset(&v, 0, sizeof v);
	keng_version(&v);
	return ((uint64_t)v.major << 48) | ((uint64_t)v.minor << 32) | v.build;
}

void ksn_fid_drop(void *user, const char *path)
{
	struct kof_fid id;

	struct cache_hook *h = user;

	if (!h || !h->fs || !kof_fid_of(path, &id))
		return;
	(void)kof_fidset_drop(h->fs, kof_fid_key(&id));
}

/*
 * ONE FILE BEHIND A MAPPING.
 *
 * WHAT THIS USED TO BE was a second implementation of the cache - identify,
 * look up, decide, scan, store - written here because the engine had no way to
 * ask. It has one now, and the whole of that logic is in scan_file where the
 * walk already meets every file. So this is the engine's own path with the same
 * two callbacks the file sweep uses, and there is no second copy left to drift.
 *
 * The counters still live here because they are the report's, not the engine's:
 * `cached` comes back through kof_stats, and this only has to add it up.
 */
static void ps_file(struct procscan *p, const char *path)
{
	uint64_t before_cached = 0;
	const struct kof_stats *st;

	if (!p || !path || !path[0])
		return;
	st = kscan_stats(p->sc);
	if (st)
		before_cached = st->cached;
	(void)kscan_path(p->sc, path, p->opt, ksn_on_object, p->r);
	st = kscan_stats(p->sc);
	if (st && st->cached != before_cached)
		p->files_cached++;
	else
		p->files_scanned++;
}

/* Returns 0, or a KOF_ERR_*. */
int ksn_scan_procs(const struct ksn_procs_req *rq)
{
	struct run *r = rq->r;
	kof_scanner *sc = rq->sc;
	struct kof_scan_option *opt = rq->opt;
	const uint64_t db_stamp = rq->cache.db_stamp;
	const char *cache_path = rq->cache.path;
	const int trust = rq->cache.trust;
	const uint32_t *pids = rq->pick.pids;
	const uint32_t n_pids = rq->pick.n_pids;
	const int compare_modules = rq->pick.compare_modules;
	struct procscan p;
	struct kof_walk_api *w;
	struct kof_walk_option wo;
	struct kof_proc_build b;
	struct kof_walk_item it;
	unsigned char rec[KOF_PROC_REC_MAX];
	uint64_t procs = 0, refused = 0, regions = 0, bytes = 0;
	char line[160];
	/* Filled from the walk BEFORE it is closed - see there. */
	char note[256];
	int err = 0;

	memset(&p, 0, sizeof p);
	note[0] = 0;
	p.r = r;
	p.sc = sc;
	p.opt = opt;
	/*
	 * NO CACHE IS A STATE, NOT A FAILURE. The sweep runs either way; it
	 * simply opens every file. Returning an error because a cache could not
	 * be opened would make a missing cache directory stop a scan.
	 */
	if (cache_path) {
		p.fs = kof_fidset_open(db_stamp, ksn_engine_stamp());
		if (p.fs) {
			struct kof_fidset_stat fst;

			(void)kof_fidset_load(p.fs, cache_path);
			kof_fidset_stats(p.fs, &fst);
			/*
			 * LOADED EVEN WHEN IT IS NOT TRUSTED, and that is what
			 * --no-cache means here.
			 *
			 * Not trusting it is `seen` and `keep` staying unset:
			 * nothing is skipped on its word and nothing new is
			 * written down. What remains is `drop` - a file this
			 * run finds something in must not be left behind in a
			 * set the NEXT run will believe, and the set has to be
			 * in hand to take it out of.
			 */
			if (trust) {
				char when[64];

				ksn_cache_age(fst.made, when, sizeof when);
				fprintf(stderr, "cache: %llu entr%s loaded%s\n",
					(unsigned long long)fst.mapped,
					fst.mapped == 1u ? "y" : "ies", when);
				opt->cache_seen = ksn_fid_seen;
				opt->cache_keep = ksn_fid_keep;
			}
			opt->cache_drop = ksn_fid_drop;
			/* The bundle lives as long as the option does - see
			 * struct cache_hook for why the run is in it. */
			p.hook.fs = p.fs;
			p.hook.r  = r;
			opt->cache_user = &p.hook;
		}
	}

	memset(&wo, 0, sizeof wo);
	wo.pids = pids;
	wo.n_pids = n_pids;
	wo.compare_modules = compare_modules;

	w = kof_walk_open(&wo, &err);
	if (!w) {
		/* The option still points at what is about to be freed, and it
		 * is the caller's struct - it outlives this function. */
		opt->cache_seen = NULL;
		opt->cache_keep = NULL;
		opt->cache_drop = NULL;
		opt->cache_user = NULL;
		kof_fidset_close(p.fs);
		fprintf(stderr, "cannot walk the process table (%d)\n", err);
		return KOF_ERR_OPEN;
	}

	while (w->next_proc(w->self, &b)) {
		char who[256];
		uint32_t n;

		snprintf(who, sizeof who, "pid:%u/%s", b.pid,
			 b.comm && b.comm[0] ? b.comm : "?");

		/*
		 * THE PROCESS ITSELF IS AN OBJECT, and the rules about one
		 * live in the database like every other rule - see
		 * kofmod/proc.h. That is what makes "a shell holding one
		 * socket on both ends of its stdio" a finding somebody can add
		 * without rebuilding the scanner.
		 */
		n = kof_proc_build_rec(&b, rec, sizeof rec);
		if (n) {
			struct kof_scan_option po = *opt;

			po.as_format = KOF_EVT_PROC;
			(void)kscan_bytes(sc, rec, n, who, &po,
					     ksn_on_object, r);
		}

		while (w->next_item(w->self, &it)) {
			if (it.kind == KOF_WALK_FILE) {
				ps_file(&p, it.path);
			} else if (it.kind == KOF_WALK_BYTES) {
				struct kof_scan_option bo = *opt;
				char nm[320];

				/*
				 * THE WORD AS WELL AS THE ADDRESS.
				 *
				 * This named findings by address alone, which
				 * is what kof_walk_item.label exists to fix:
				 * "powershell.exe//00007ffdbf644690" says
				 * where and never what, so a reader has to go
				 * and work out what lives there - and a report
				 * a week later has lost the chance entirely,
				 * because that address means nothing once the
				 * process is gone.
				 *
				 * The address STAYS. It is what a finding is
				 * reported against and what a second tool
				 * would be pointed at; the word is what makes
				 * the line readable, not a replacement for it.
				 */
				if (it.label && it.label[0])
					snprintf(nm, sizeof nm,
						 "%s//%s@%016llx", who,
						 it.label,
						 (unsigned long long)it.addr);
				else
					snprintf(nm, sizeof nm, "%s//%016llx",
						 who,
						 (unsigned long long)it.addr);
				/*
				 * WHAT THE WALK KNOWS AND THE BYTES DO NOT -
				 * copied straight across, never interpreted
				 * here. On Linux nothing is declared and this
				 * is three zero assignments; on Windows it is
				 * what stops every region of a loader-mapped
				 * PE resolving to another section's bytes.
				 * See kof_walk_item.as_format.
				 */
				if (it.as_format) {
					bo.as_format   = it.as_format;
					bo.as_view     = it.as_view;
					bo.as_view_len = it.as_view_len;
				}
				(void)kscan_bytes(sc, it.p, it.len, nm,
						     &bo, ksn_on_object, r);
				/*
				 * COUNTED HERE AND NOT IN THE WALK'S STATS.
				 *
				 * kof_walk_api.stats carries four numbers every
				 * platform has. "How many modules differ from
				 * their file" is not one of them today - Linux
				 * measured its EXEC pages 0% different - and
				 * widening a neutral signature for one
				 * platform's concept is how a neutral header
				 * stops being one. The label is already in the
				 * item, so the host can count what it cares
				 * about without anything being added anywhere.
				 *
				 * AND IT IS AN "ELSE", WHICH IT WAS NOT.
				 *
				 * A modified run is image memory that differs
				 * from its file; unbacked memory is memory no
				 * file holds at all. Adding the first to the
				 * second's counter made turning --modified on
				 * read as though the unbacked count had gone
				 * from 98 to 649 - a six-fold jump in the one
				 * number on that summary that is closest to an
				 * alarm, caused by nothing changing in the
				 * process at all.
				 */
				if (it.label &&
				    strcmp(it.label, "MEM_PATCH") == 0) {
					p.patches++;
					p.patch_bytes += it.len;
				} else {
					p.chunks++;
					p.chunk_bytes += it.len;
				}
			}
		}
	}

	if (w->stats)
		w->stats(w->self, &procs, &refused, &regions, &bytes);
	/*
	 * TAKEN BEFORE close, like the stats above it.
	 *
	 * This was read from the summary further down, after the walk had been
	 * closed and freed - a use-after-free that did not crash and did not
	 * print either, because the freed struct happened to read back as a
	 * walk with the comparison turned off. A silent wrong answer out of
	 * freed memory is the worst shape this could have taken: it looked
	 * exactly like a collector with nothing to ksn_say.
	 */
	if (w->describe)
		(void)w->describe(w->self, note, sizeof note);
	w->close(w->self);

	if (p.fs && cache_path) {
		struct kof_fidset_stat fst;

		/* An untrusted run writes the set back ONLY to take something
		 * out of it - see the load above. */
		kof_fidset_stats(p.fs, &fst);
		if ((trust || fst.dropped) &&
		    !kof_fidset_save(p.fs, cache_path))
			fprintf(stderr, "cache: could not be written to %s\n",
				cache_path);
		if (fst.dropped)
			fprintf(stderr, "cache: %llu entr%s dropped - found "
				"something in a file the cache called clean\n",
				(unsigned long long)fst.dropped,
				fst.dropped == 1u ? "y" : "ies");
	}

	printf("\n--- processes ---\n");
	printf("walked    %llu process(es)", (unsigned long long)procs);
	if (refused)
		printf(", %llu refused", (unsigned long long)refused);
	printf("\n");
	printf("regions   %llu, %.2f MB read out of them\n",
	       (unsigned long long)regions, (double)bytes / 1048576.0);
	printf("modules   %llu scanned, %llu clean from cache",
	       (unsigned long long)p.files_scanned,
	       (unsigned long long)p.files_cached);
	/*
	 * COUNTED APART FROM THE CLEAN ONES. Both skipped a scan, but one of
	 * them produced a FINDING out of the cache, and a reader totalling
	 * "served from cache" against "scanned" would otherwise have no way to
	 * see that some of this run's verdicts were remembered rather than
	 * reached.
	 */
	if (p.files_scanned + p.files_cached)
		printf("  (%.1f%% saved)",
		       (double)p.files_cached * 100.0 /
		       (double)(p.files_scanned + p.files_cached));
	printf("\n");
	printf("unbacked  %llu chunk(s), %.2f MB\n",
	       (unsigned long long)p.chunks,
	       (double)p.chunk_bytes / 1048576.0);
	/*
	 * Only when there were any. A zero here would read as "checked and
	 * none", and on a platform whose walk does not compare modules at all
	 * it would be claiming a check that never ran - see wdiff.h, which is
	 * Windows only.
	 */
	if (p.patches)
		printf("modified  %llu run(s) in loaded module(s), %llu byte(s)"
		       " - differs from the file, which is not yet a verdict\n",
		       (unsigned long long)p.patches,
		       (unsigned long long)p.patch_bytes);
	/*
	 * WHAT THE COLLECTOR HAS TO SAY THAT THE FOUR NUMBERS CANNOT.
	 *
	 * Optional and empty on a collector with nothing extra, so this prints
	 * nothing rather than an empty heading. It is where a count of modules
	 * that could NOT be compared appears - a number that existed and
	 * reached nobody until there was a line for it.
	 */
	if (note[0])
		printf("%s\n", note);
	if (p.fs) {
		struct kof_fidset_stat fst;

		kof_fidset_stats(p.fs, &fst);
		snprintf(line, sizeof line,
			 "cache     %llu known, %llu added, %llu dropped, "
			 "%llu hit, %llu miss",
			 (unsigned long long)fst.mapped,
			 (unsigned long long)fst.added,
			 (unsigned long long)fst.dropped,
			 (unsigned long long)fst.hit,
			 (unsigned long long)fst.miss);
		printf("%s\n", line);
	}

	/*
	 * CLEARED BEFORE THE SET IS FREED, and `opt` is the CALLER'S - it
	 * outlives this function and is reused by whatever runs next. Leaving
	 * the pointers behind would hand a freed set to the following scan,
	 * which is the one shape of use-after-free that would not crash: the
	 * lookup would read whatever the allocator put there and answer yes or
	 * no from it.
	 */
	opt->cache_seen = NULL;
	opt->cache_keep = NULL;
	opt->cache_user = NULL;
	kof_fidset_close(p.fs);
	return 0;
}
