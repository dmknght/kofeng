/*
 * kofscan_out.c - what the scanner prints: colour, the progress line, a verdict line,
 * the per-object callback and the statistics. Split from kofscanner.c; the text is
 * unchanged.
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

/* The escape when stdout is a terminal, nothing otherwise. */
const char *ksn_col(const struct run *r, const char *c)
{
	return r->color ? c : "";
}


/* The colour a level speaks in. */
/*
 * ONE COLUMN, AND WHAT GOES IN IT.
 *
 * The line was "<LEVEL>  <path>: <name>", which spent its widest, first and
 * most-read column on the least specific thing it knew. A reader scanning a
 * page of results wants the finding, and the level is already in the colour it
 * is printed in - so the name takes the column and the level is what colours
 * it. "INFECTED ... : ELF-x64/Botnet:Mirai#el7jd" said the same thing twice.
 *
 * Everything printed per object follows that rule: the most specific thing
 * known goes first, coloured by how strongly it is meant. Where there is
 * nothing more specific - a file that came back clean - the status word stays,
 * because it IS the whole of what is known.
 *
 * The width fits the common detection name (31 of the 55 characters the longest
 * in this corpus runs to) so paths line up for most rows; a longer one pushes
 * its path right rather than being cut.
 */
#define W_TAG 31

static const char *level_col(uint32_t level)
{
	if (level == KOF_LEVEL_INFECT)
		return C_RED;
	return level == KOF_LEVEL_HEUR ? C_MAG : C_YEL;
}



/*
 * Called once per object the engine scanned, findings or not.
 *
 * Returning zero always: this scanner reports everything and stops for nothing. A
 * different caller - an on-access hook that only needs to know whether to block -
 * returns non-zero at the first finding and the engine abandons the rest of the tree.
 */
/*
 * WHERE THE TIME GOES WHEN NOTHING IS FOUND.
 *
 * A scan prints a line per finding, so a subtree with no findings prints
 * nothing at all - and a person watching cannot tell that from a scan that has
 * stopped. Measured on this collection: 1 282 files across five directories
 * yield no finding between them, which is four seconds of silence in the middle
 * of a run, and every report of "it hangs at file X" has been that silence
 * ending at X rather than anything about X.
 *
 * On stderr and only when stderr is a terminal, so a redirect, a pipe or a log
 * gets exactly the bytes it always did. Rate limited to ten a second, because
 * the point is to show that time is passing and not to spend it: at 60 000
 * objects an unlimited version would draw more often than a terminal can scroll.
 */
#define PROGRESS_HZ 10.0

/*
 * CTRL-C STOPS THE SCAN; IT DOES NOT THROW AWAY WHAT THE SCAN FOUND.
 *
 * Without a handler the default action kills the process, and everything the
 * sweep had already established - which files were infected, how many were
 * cached, what was repaired - went with it. A person who interrupts a long
 * scan is almost always interrupting it BECAUSE of something they saw, and
 * answering that with nothing is the worst moment to have nothing to ksn_say.
 *
 * A flag and nothing else. The handler may not print, allocate or touch the
 * run: the callback checks the flag and returns non-zero, which is the walk's
 * own documented way to be abandoned - "Return non-zero to abandon the walk."
 * So the scan unwinds through its ordinary path, the mappings are released,
 * and main goes on to the summary it would have printed anyway.
 *
 * volatile sig_atomic_t because that is the only thing a handler may write.
 */
volatile sig_atomic_t ksn_interrupted;

void ksn_on_interrupt(int sig)
{
	(void)sig;
	ksn_interrupted = 1;
}

/*
 * THE ENGINE'S OWN WAY OUT, asked between modules and between files.
 *
 * The callback abandons the walk at the next OBJECT, which on a tree of
 * ordinary files is immediate and on one large shared object is not: measured
 * on /usr/lib, 150 to 456 ms between the key and the exit. This is the same
 * answer given where the time is spent - see should_stop in kofeng.h.
 *
 * Reads one volatile flag and nothing else, which is what that contract asks
 * for: it runs on a hot path and from every worker thread at once.
 */
int ksn_scan_should_stop(void *user)
{
	(void)user;
	return ksn_interrupted;
}

static double now_s(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/*
 * THE LINE ITSELF, from what the run already knows.
 *
 * Split out of ksn_progress_draw so that restoring the line after a finding was
 * printed over it paints exactly what was there rather than an approximation
 * of it - and so the two can never disagree about the format.
 */
static void progress_paint(struct run *r)
{
	/*
	 * THE CACHED COUNT IS ON THE LINE, AND ONLY WHEN THERE IS ONE.
	 *
	 * Without it a sweep of a tree the cache already answers for reads
	 * "1 object(s)" for minutes - true, and useless, because the number
	 * that is moving is the one not shown. With it the reader can tell a
	 * scan that is working from one that is skipping, which is the
	 * difference between waiting and worrying.
	 */
	if (r->cached_seen)
		fprintf(stderr, "\r\033[K  %llu object(s)  %llu cached  %s",
			(unsigned long long)r->seen,
			(unsigned long long)r->cached_seen, r->last);
	else
		fprintf(stderr, "\r\033[K  %llu object(s)  %s",
			(unsigned long long)r->seen, r->last);
	fflush(stderr);
	r->drawn = 1;
}

void ksn_progress_draw(struct run *r, const char *name)
{
	double now;
	const char *tail;
	size_t n;

	if (!r->progress)
		return;
	r->seen++;
	now = now_s();
	if (r->drawn && now - r->drawn_at < 1.0 / PROGRESS_HZ)
		return;
	r->drawn_at = now;

	/*
	 * The last two path components, THEN whatever object of the file this
	 * is: a full path wraps and a bare basename does not ksn_say which subtree
	 * the scan is in, which is the one thing somebody watching wants.
	 *
	 * THE SEARCH STOPS AT THE FILE, and that is the whole of the fix. An
	 * object is named "<file>//<n>", so scanning the WHOLE name for
	 * slashes finds the two that spell "//" and cuts between them: while
	 * unpacking one sample this line read
	 *
	 *     4850 object(s)  /0
	 *
	 * where it should have read "new_Mirai/Mozi.m.48//0". The name was
	 * there and the progress line threw it away, so a scan working
	 * through a container looked like a scan stuck on nothing.
	 *
	 * kobj_toplevel_len is the same split the rest of this file uses to
	 * key a verdict by its file - see fmap.
	 */
	{
		size_t flen = kobj_toplevel_len(name);
		const char *p1 = NULL, *p2 = NULL;
		size_t i;

		for (i = 0; i < flen; i++)
			if (name[i] == '/') { p2 = p1; p1 = name + i; }
		if (p2)
			tail = p2 + 1;
		else if (p1)
			tail = p1 + 1;
		else
			tail = name;
	}
	n = strlen(tail);
	if (n > 48)
		tail += n - 48;
	snprintf(r->last, sizeof r->last, "%s", tail);
	progress_paint(r);
}

/* Take the line back before anything else writes, so a finding is never printed
 * onto a half-erased progress line. */
void ksn_progress_clear(struct run *r)
{
	if (r->progress && r->drawn) {
		fprintf(stderr, "\r\033[K");
		fflush(stderr);
		r->drawn = 0;
	}
}

/*
 * PUT IT BACK AFTER SOMETHING WAS PRINTED OVER IT.
 *
 * ksn_progress_clear takes the line away so a finding can be written, and until
 * now nothing brought it back: the next draw was the one at the top of the
 * next object, and that one is rate limited to PROGRESS_HZ. On a scan where
 * every file reports - a tree of infected files, which is exactly when a
 * reader is watching - the line was erased on every object and redrawn on
 * almost none, so it was simply never there. Reported as the repair line
 * "erasing" the progress bar; any finding did it, the repair line just made
 * it happen on every file.
 *
 * The rate limit is left alone rather than reset. This does not COUNT
 * anything - seen is not touched - it only paints the line that already
 * belongs on screen, so it cannot make the line move faster than the draws
 * that do count.
 */
static void progress_restore(struct run *r)
{
	if (r->progress && !r->drawn && r->seen)
		progress_paint(r);
}

/*
 * ONE TAGGED LINE, WHICH IS EVERY LINE THIS TOOL PRINTS ABOUT AN OBJECT.
 *
 * A coloured tag in a fixed column, then the name. Six places wrote that
 * printf, and they agreed - but taking the progress line back first was NOT
 * in any of them: it was done once, at the top of ksn_on_object, under a condition
 * that named the findings. The repair line prints later and from a different
 * branch, so it was the one that could land on a progress line nobody had
 * cleared.
 *
 * The clear belongs with the print because it is the same act: write over the
 * line, having first taken it away. Kept apart, the next line added will be
 * apart too, and the fault comes back under a different name.
 */
void ksn_say(struct run *r, const char *colour, const char *tag,
		const char *name)
{
	ksn_progress_clear(r);
	printf("%s%-*s%s %s\n", ksn_col(r, colour), W_TAG, tag,
	       ksn_col(r, C_RST), name);
}

/*
 * Report one finished file under -v, once.
 *
 * Only the clean verdict is streamed here: a finding has already printed in
 * full where it was found, and an unexamined file is reported unconditionally
 * by the sweep at exit - see the note there for why "OK" would be a lie.
 */
/*
 * A VERDICT, FROM THE ENGINE, ALREADY COMPOSED - see kof_on_event_detected.
 *
 * All this tool does with it is put it on the screen. It does not choose
 * which findings count, does not compose a name and does not know the form
 * of one: the engine decided and decoded, and a second tool asking the same
 * engine gets the same line.
 */
void ksn_on_event_detected(const char *object, const char *verdict,
		       const struct kof_finding *f, void *user)
{
	struct run *r = user;

	if (r && object && verdict)
		ksn_say(r, level_col(f ? f->level : 0u), verdict, object);
}

void ksn_v_say_file(struct run *r, const char *file, size_t flen)
{
	struct kverdict_file *e;

	if (!r->verbose || !flen)
		return;
	e = kverdict_filemap_find(r->files, file, flen);
	if (!e || e->host)
		return;
	if (e->level < 0 && !e->broken && e->examined) {
		e->host = 1;
		ksn_say(r, C_GRN, "OK", e->file);
	}
}

/* The file the callback was on has ended: report it, and remember the new one. */
static void v_file_turn(struct run *r, const char *name, size_t flen)
{
	if (!r->stream_v)
		return;
	if (r->cur_len &&
	    (flen != r->cur_len || memcmp(name, r->cur_file, flen) != 0))
		ksn_v_say_file(r, r->cur_file, r->cur_len);
	if (flen && flen < sizeof r->cur_file &&
	    (flen != r->cur_len || memcmp(name, r->cur_file, flen) != 0)) {
		memcpy(r->cur_file, name, flen);
		r->cur_file[flen] = '\0';
		r->cur_len = flen;
	}
}

/*
 * Apply a described repair to the file it was described against.
 *
 * IN PLACE AND IN ORDER: the patches first, then the length. Opening for
 * update rather than rewriting means a file that cannot be written is left
 * exactly as it was rather than half replaced.
 *
 * NO BACKUP IS TAKEN HERE. Whether the original is worth keeping is a policy
 * question with a different answer in a lab and on a mail gateway, and
 * guessing it in a scanner would be answering it for everybody.
 */
static int repair_apply(const char *path, const struct kof_repair *rp)
{
	/*
	 * kof_fopen_rw AND kof_fseek64, NOT fopen AND fseek.
	 *
	 * The opener refuses to follow a link: this file was identified by
	 * scanning THIS file, and if the name now points somewhere else the
	 * answer is to fail rather than to repair whatever it points at.
	 *
	 * The seek is sixty-four bit. `fseek` takes a long, this offset is a
	 * uint64, and on mingw-w64 a long is thirty-two bits - so the cast that
	 * used to be here wrapped, and a wrapped offset does not fail, it puts
	 * the sixteen bytes of a repair somewhere else in the user's file. The
	 * scanner maps a top level file whole however large it is, and
	 * kcure_patch bounds the offset by the OBJECT, so the offset really
	 * can pass 4 GB.
	 */
	FILE *f = kof_fopen_rw(path);
	uint32_t i;
	int ok = 1;

	if (!f)
		return 0;
	for (i = 0; i < rp->n_fix && ok; i++) {
		if (!kof_fseek64(f, rp->fix[i].off) ||
		    fwrite(rp->fix[i].b, 1, rp->fix[i].n, f) != rp->fix[i].n)
			ok = 0;
	}
	if (fclose(f) != 0)
		ok = 0;
	if (ok && rp->truncate)
		ok = kof_truncate_file(path, rp->truncate);
	return ok;
}

int ksn_on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct run *r = user;
	size_t flen = kobj_toplevel_len(name);

	(void)bytes;
	(void)len;

	ksn_progress_draw(r, name);
	/*
	 * NO CLEAR HERE ANY MORE - ksn_say() does it.
	 *
	 * This used to take the progress line back for anything that was about
	 * to print, and the condition had to name every branch below that
	 * prints. It named the findings, the broken reason and the dropped
	 * count; it did not name the repair, which prints from a branch added
	 * later. So a repair could land on a progress line still on screen.
	 *
	 * A condition that has to be kept in step with the code under it is a
	 * condition that will fall out of step. The clear now happens where the
	 * printing happens, so there is nothing to keep in step.
	 *
	 * It also costs nothing when nothing prints: a clean object still
	 * leaves the line alone, which is what the rate limit is protecting.
	 */

	/* The findings print as the engine hands them over - see ksn_on_event_detected. The
	 * file-level roll-up (which file this object belongs to, the worst thing found
	 * anywhere in its tree, whether anything examined it) is the engine's too: one call,
	 * kverdict_filemap_fold, further down. */

	/*
	 * AND THE REPAIR, WHICH IS NOT A SEPARATE DECISION.
	 *
	 * CURE IS WHAT DETECTION MEANS HERE, not a second thing an operator
	 * opts into. A rule that carries a kof_cure has said what the damage
	 * is and how to undo it; the engine ran that cure only because the
	 * rule REPORTED - see the gate in scan.c, which needs rep_valid and
	 * cure_have together - so by the time a repair exists, the question
	 * "is this file infected" has already been answered yes by the rule
	 * that also knows the answer to "what did it change".
	 *
	 * This used to sit behind --cure, on the reasoning that a scanner
	 * which rewrites what it finds cannot be run twice. That reasoning
	 * describes a scanner that GUESSES. This one does not: the repair is
	 * two numbers a rule read out of the file being repaired, the host
	 * refuses any request that does not fit the object, and the file is
	 * still REPORTED as infected afterwards - the verdict is not softened
	 * by having been acted on.
	 *
	 * ONLY AT THE TOP LEVEL. A repair is described against the OBJECT the
	 * module saw, and for a child that is bytes the engine produced in
	 * memory, not a file on disk - there is nothing to write it back to.
	 */
	if (res->repair.n_fix && flen == strlen(name)) {
		uint32_t q;
		int done = repair_apply(name, &res->repair);

		/*
		 * GREEN, AND CAPITALISED, BECAUSE IT IS ADDRESSED TO A PERSON.
		 *
		 * Every other tag on this column is the verdict, and the verdict
		 * speaks in the colour of its level - red for infected and so on.
		 * This one is not a verdict, it is the only line in the output
		 * that says the scanner CHANGED something, and the reader wants
		 * to find it at a glance among the red. Green says it went well;
		 * a repair that could not be written stays red, because that is
		 * a file still infected and still needing a hand.
		 */
		if (done)
			r->repaired++;
		ksn_say(r, done ? C_GRN : C_RED,
		    done ? "  Repaired" : "  NOT repaired", name);
		/*
		 * AND THE BYTES ONLY UNDER -v.
		 *
		 * "four bytes at 24" is for somebody checking the repair against
		 * the rule that described it, which is a thing done once while
		 * writing the rule and never during a sweep. On a run that cures
		 * a hundred files it is three hundred lines between the reader
		 * and the summary.
		 */
		if (r->verbose) {
			for (q = 0; q < res->repair.n_fix; q++)
				printf("             %llu bytes at %llu\n",
				       (unsigned long long)res->repair.fix[q].n,
				       (unsigned long long)res->repair.fix[q].off);
			if (res->repair.truncate)
				printf("             ends at %llu\n",
				       (unsigned long long)res->repair.truncate);
		}
		if (!done)
			printf("             could not be written\n");
	}

	/*
	 * AND WHERE THE INFECTION IS, when a rule said so - see
	 * `struct kof_infected`.
	 *
	 * NOT UNDER THE REPAIR, and not conditional on one. A rule may locate a
	 * family's body without being able to put the host back, and that is
	 * exactly the case where a reader most wants to be told where it is.
	 * Printed under -v for the same reason the repair's byte counts are:
	 * it is for somebody checking a rule, not for a sweep.
	 */
	if (r->verbose && res->n_infected) {
		uint32_t q;

		for (q = 0; q < res->n_infected; q++)
			printf("  %-9s %llu bytes at %llu\n",
			       res->infected[q].kind == KOF_INF_BODY
			       ? "Infection" : "Damage",
			       (unsigned long long)res->infected[q].len,
			       (unsigned long long)res->infected[q].off);
	}

	/*
	 * BROKEN is secondary to a finding, not a second verdict beside it.
	 *
	 * A context-keyed encoder comes back both as a rule's Heur:Shellcode and,
	 * from the unpacker that could not read its key, as "the content is
	 * encrypted". Those are one thing said twice: the finding is the answer,
	 * the encryption is only why nothing further could be read - so with a
	 * finding present it is shown under -v and nowhere else. With no finding it
	 * IS the verdict and always prints. The reason is still tallied either way.
	 */
	if (res->broken) {
		if (res->broken < KOF_BROKEN_COUNT)
			r->by_reason[res->broken]++;
		if (res->n == 0 || r->verbose)
			ksn_say(r, C_CYN, kverdict_broken_name(res->broken), name);
	}

	/* Said under -v what the engine did NOT mark broken: the analysis of a wrapper
	 * ran out and the child it opened into carries the evidence. */
	if (r->verbose && res->analysis_moot)
		ksn_say(r, C_CYN, "Analysis cut, child is the subject", name);

	/*
	 * Roll this object's verdict up into its top-level file. Non-clean objects
	 * always get an entry so the file is counted; a clean object touches one
	 * only under -v, where every file is listed at the end whatever it turned
	 * out to be.
	 *
	 * AN UNEXAMINED OBJECT ALWAYS GETS ONE TOO, for the same reason a broken
	 * one does: it is not clean. Without this it had no entry outside -v, so
	 * the SKIPPED line below had nothing to iterate and the file vanished
	 * into the clean count by subtraction - which is exactly the silence
	 * being fixed. (Both rules are kverdict_filemap_fold's.)
	 */
	kverdict_filemap_fold(r->files, name, res, r->verbose);

	/* This object's verdict is in the file's entry now, so a change of file
	 * means the previous one is finished - see run.cur_file. */
	v_file_turn(r, name, flen);

	if (res->dropped) {
		char tag[48];

		snprintf(tag, sizeof tag, "+%u finding(s) not reported",
			 res->dropped);
		ksn_say(r, C_DIM, tag, name);
		r->dropped += res->dropped;
	}

	/*
	 * PUT THE PROGRESS LINE BACK, and stop here if the reader asked.
	 *
	 * The restore is a no-op unless something above cleared the line, so a
	 * clean object pays a branch. See progress_restore for why the next
	 * object's draw was not enough.
	 */
	progress_restore(r);
	if (ksn_interrupted) {
		ksn_progress_clear(r);
		/*
		 * Non-zero abandons the walk - kofeng.h's own words - so the
		 * scan unwinds normally and main prints the summary for what
		 * it managed to look at. Said once, here, because the walk is
		 * about to stop and a reader who pressed the key wants to know
		 * it was heard rather than that the tool died.
		 */
		fprintf(stderr, "interrupted - reporting what was scanned\n");
		return 1;
	}
	return 0;
}

/*
 * What the filtering earned.
 *
 * Behind a flag rather than always printed, and printed at all rather than merely
 * collected: the engine counts every one of these on every module of every object,
 * and a counter nothing can read is a counter nobody keeps honest. The whole design
 * rests on ruling a module out being much cheaper than running it, and these are the
 * numbers that ksn_say whether it does.
 *
 * `considered` must equal `ran` plus the four rejections - the prefilter has no
 * other exit - so the two columns are also a check on each other.
 */
void ksn_print_stats(const struct kof_stats *st)
{
	uint64_t skipped = st->by_target + st->by_size + st->by_arch +
			  st->by_subtype + st->by_region;

	printf("\n--- filtering ---\n");
	printf("considered %llu module evaluation(s)\n",
	       (unsigned long long)st->considered);
	printf("  ran      %llu\n", (unsigned long long)st->ran);
	printf("  target   %llu\n", (unsigned long long)st->by_target);
	printf("  size     %llu\n", (unsigned long long)st->by_size);
	printf("  arch     %llu\n", (unsigned long long)st->by_arch);
	printf("  subtype  %llu\n", (unsigned long long)st->by_subtype);
	printf("  region   %llu\n", (unsigned long long)st->by_region);
	if (st->ran + skipped != st->considered)
		printf("  NOTE: ran + skipped is %llu, not %llu\n",
		       (unsigned long long)(st->ran + skipped),
		       (unsigned long long)st->considered);

	/*
	 * The batched pass first, because it is what the per-marker line below
	 * is now measured AGAINST. A region swept once appears here; whatever
	 * the sweep could not answer - hex programs, markers too short to key,
	 * the symbol halves - appears there. The second number growing with the
	 * database while the first does not is the shape to watch for.
	 */
	printf("multi      %llu pass(es), %.2f MB read\n",
	       (unsigned long long)st->multi_passes,
	       (double)st->multi_bytes / 1048576.0);
	printf("  pack reads %llu, sweeps that did not finish %llu\n",
	       (unsigned long long)st->multi_reads,
	       (unsigned long long)st->multi_degraded);
	printf("  answers written without a search %llu\n",
	       (unsigned long long)st->multi_answers);
	printf("searches   %llu, %.2f MB read\n",
	       (unsigned long long)st->searches,
	       (double)st->bytes_searched / 1048576.0);
	printf("  answered without scanning %llu\n",
	       (unsigned long long)st->gram_answers);
	printf("presence   %.2f MB indexed\n",
	       (double)st->gram_bytes / 1048576.0);
	/*
	 * Printed even at zero, because zero is the answer a reader wants on a
	 * clean tree: it says the rules that can turn the emulator on did not.
	 */
	printf("heur emu   %llu object(s) interpreted at a rule's request\n",
	       (unsigned long long)st->heur_emu);
	/* What the interpreter executed for the trees scanned, and the objects a tree's
	 * allowance refused (they read Limit): the cost a file's contents can choose. */
	printf("emulated   %llu instruction(s); %llu object(s) refused by the tree's allowance\n",
	       (unsigned long long)st->emu_insn, (unsigned long long)st->emu_budget_denied);
	/* Only when it moved: a bound that cut evidence is news, and zero is not. */
	if (st->limit_hits)
		printf("limits     %llu bound(s) cut evidence (the object says so: Limit)\n",
		       (unsigned long long)st->limit_hits);
	if (st->analysis_moot)
		printf("moot       %llu object(s) whose own analysis ran out of budget but opened into a child (not Limit)\n",
		       (unsigned long long)st->analysis_moot);
}
