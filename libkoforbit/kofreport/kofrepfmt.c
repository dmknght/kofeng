/*
 * kofrepfmt.c - the three ways a report comes out, over one walk of one model.
 *
 * A person reads the text, a pipeline reads the JSON, and kofeditor reads the
 * candidates. All three come from the same accumulated model and none of them
 * computes anything: if a number is in two outputs it is the same number,
 * because it was worked out once in kofreport.c and is only being printed
 * here.
 *
 * That is the same argument kofevtfmt.h makes about rendering an event, and it
 * is made again because it has already gone wrong once in this tree: two
 * renderers of one event drifted, and the tally differed between a --quiet run
 * and a loud one because it was counted inside a print switch.
 *
 *
 * THE ORDER OF THE TEXT REPORT IS AN ARGUMENT, NOT A LAYOUT
 *
 *   what was run          so the reader knows what they are reading about
 *   WHAT WAS NOT SEEN     before any of the findings, because it governs how
 *                         to read all of them: a trace that dropped four
 *                         thousand events is one where an absence proves
 *                         nothing, and a reader who learns that in an appendix
 *                         has already drawn conclusions
 *   the process tree      the spine everything else attaches to
 *   the fingerprints      stable first, because that is the section somebody
 *                         can act on
 *   the tagged locations  labelled as OBSERVATIONS, never as findings
 *   what is not here      the overflow counts
 *
 * Nothing is omitted for being uninteresting. A report that hides a category
 * is one a reader cannot tell from a run that did not produce it.
 */

#include <stdio.h>
#include <string.h>

#include "kofrepint.h"

/* ---- colour -------------------------------------------------------------- */

/*
 * ANSI, AND ONLY WHEN THE CALLER ASKS.
 *
 * A report written to a file with escapes in it is a report nobody can grep,
 * and this library cannot tell whether `out` is a console - the caller is the
 * one holding the FILE. So colour is a parameter, and the escape strings
 * collapse to "" when it is off, which keeps every format string in this file
 * identical between the two modes. One set of format strings is the only way
 * the coloured and plain reports cannot drift apart.
 *
 * The highlight is on the GROUP, because that is the judgement a reader is
 * being asked to check: something marked volatile that looks deliberate, or
 * something marked stable that holds a hostname, is the case where the report
 * is wrong and needs overruling.
 */
struct ink {
	const char *off, *bold, *dim, *stable, *volat, *ambient, *hit, *miss;
};

static void ink_of(struct ink *k, int color)
{
	if (color) {
		k->off     = "\033[0m";
		k->bold    = "\033[1m";
		k->dim     = "\033[2m";
		k->stable  = "\033[32m";   /* green: usable as it stands */
		k->volat   = "\033[33m";   /* amber: usable after normalising */
		k->ambient = "\033[2m";    /* dim: the machine's own noise */
		k->hit     = "\033[36m";
		k->miss    = "\033[31m";
	} else {
		k->off = k->bold = k->dim = k->stable = k->volat =
			k->ambient = k->hit = k->miss = "";
	}
}

static const char *group_ink(const struct ink *k, uint8_t g)
{
	switch (g) {
	case KOF_RG_STABLE:   return k->stable;
	case KOF_RG_VOLATILE: return k->volat;
	default:              return k->ambient;
	}
}

/* ---- shared helpers ------------------------------------------------------ */

/* Seconds since the first event of the trace, which is the clock every line of
 * the event trace itself is stamped with - so a fingerprint's time can be
 * found in the trace by eye. */
static double rel(struct kof_report *r, uint64_t stamp)
{
	if (!r->first_stamp || stamp < r->first_stamp)
		return 0.0;
	return kof_evt_secs_since(r->first_stamp, stamp);
}

/*
 * PRINTABLE, AND CUT AT A LENGTH.
 *
 * The text of a fingerprint came from a file the sample named or a script it
 * submitted, which is to say an attacker chose every byte of it. Printed raw,
 * a terminal escape in it is a report that lies about what it says - the same
 * argument kofevtfmt.c makes at print_sanitised, and it applies here for the
 * same reason and to different data.
 */
static void put_safe(FILE *out, const char *s, size_t cap)
{
	size_t i;

	for (i = 0; s[i] && i < cap; i++) {
		unsigned char c = (unsigned char)s[i];

		fputc((c >= 0x20u && c < 0x7fu) ? (int)c : '.', out);
	}
	if (s[i])
		fputs("...", out);
}

/* ---- the human report ---------------------------------------------------- */

static void write_head(struct kof_report *r, FILE *out,
		       const struct ink *k)
{
	static const char *ENDED[] = {
		"unknown", "interrupted (Ctrl-C)", "reached its timeout",
		"the traced tree exited", "an error"
	};

	fprintf(out, "%s== %s report ==%s\n\n", k->bold,
		r->info.tool && *r->info.tool ? r->info.tool : "kofreport",
		k->off);

	fprintf(out, "subject   : %s\n",
		r->info.subject && *r->info.subject ? r->info.subject : "?");
	if (r->info.subject_cmd && *r->info.subject_cmd)
		fprintf(out, "command   : %s\n", r->info.subject_cmd);
	if (r->subject_sha256[0])
		fprintf(out, "sha256    : %s  (%llu bytes)\n",
			r->subject_sha256,
			(unsigned long long)r->subject_size);
	else
		fprintf(out, "sha256    : %snot computed - the subject could "
			     "not be read%s\n", k->dim, k->off);

	if (r->subject_verdict.asked) {
		const struct kof_fp_verdict *v = &r->subject_verdict;

		fprintf(out, "engine    : %s",
			v->finding[0] ? v->finding : "no finding");
		if (v->packed)
			fprintf(out, ", packed%s%s",
				v->packer[0] ? " by " : "",
				v->packer[0] ? v->packer : "");
		if (v->packer_version)
			fprintf(out, " %llu",
				(unsigned long long)v->packer_version);
		if (v->children)
			fprintf(out, ", %lu object(s) came out of it",
				(unsigned long)v->children);
		fprintf(out, ", entropy %u.%u bits, %lu module(s) ran",
			(unsigned)(v->entropy8 / 8u),
			(unsigned)((v->entropy8 % 8u) * 125u / 100u),
			(unsigned long)v->examined);
		if (v->broken)
			fprintf(out, " %s[the engine did not finish: %s]%s",
				k->miss, kof_broken_name(v->broken), k->off);
		/*
		 * A CLEAN VERDICT WITH NOTHING HAVING RUN IS NOT A CLEAN
		 * VERDICT, and kofeng.h says so at kof_result.examined: a
		 * formatless blob matches no module's declared target, so
		 * every module is excluded and the object comes back with no
		 * findings looking exactly like a scanned and cleared file.
		 */
		else if (!v->finding[0] && !v->examined)
			fprintf(out, " %s[nothing evaluated it - this is not a "
				     "clean verdict]%s", k->miss, k->off);
		fputc('\n', out);
	} else {
		fprintf(out, "engine    : %snot asked - no database was given, "
			     "so nothing here is a verdict%s\n", k->dim,
			k->off);
	}

	fprintf(out, "\nroot pid  : %lu\n", (unsigned long)r->info.root_pid);
	fprintf(out, "build     : %lu\n", (unsigned long)r->info.build);
	fprintf(out, "ran for   : %.1fs, and ended because %s\n", r->seconds,
		ENDED[r->ended < 5u ? r->ended : 0]);
	fprintf(out, "events    : %llu kept\n",
		(unsigned long long)r->n_events);
	if (r->info.log && *r->info.log)
		fprintf(out, "trace     : %s  (every [#N] below is a record in "
			     "it)\n", r->info.log);
	else
		fprintf(out, "trace     : %snot recorded - the [#N] references "
			     "point at nothing%s\n", k->dim, k->off);
	if (r->info.dir && *r->info.dir)
		fprintf(out, "directory : %s\n", r->info.dir);
}

/*
 * WHAT THE RUN DID NOT SEE, AND IT IS NOT AN APPENDIX.
 *
 * Printed second, before anything that was found, because it decides what an
 * absence means. A reader who reaches the fingerprints without knowing the
 * ring dropped nine thousand records will read "no network activity" as a
 * fact, and it is not one.
 */
static void write_gaps(struct kof_report *r, FILE *out,
		       const struct ink *k)
{
	const struct kof_evt_health *h = &r->health;
	int quiet = 1;

	fprintf(out, "\n%s-- how complete this is --%s\n", k->bold, k->off);

	if (!r->have_health) {
		fprintf(out, "  %sthe collector's health was not reported, so "
			     "how much was lost is unknown%s\n", k->miss,
			k->off);
		return;
	}

	if (h->dropped) {
		fprintf(out, "  %s%llu record(s) DROPPED - the consumer fell "
			     "behind and those events are gone%s\n",
			k->miss, (unsigned long long)h->dropped, k->off);
		quiet = 0;
	}
	if (h->upstream_lost) {
		fprintf(out, "  %s%llu record(s) lost UPSTREAM, before the "
			     "collector saw them%s\n", k->miss,
			(unsigned long long)h->upstream_lost, k->off);
		quiet = 0;
	}
	if (h->seq_gaps) {
		fprintf(out, "  %llu hole(s) in the arrival counter\n",
			(unsigned long long)h->seq_gaps);
		quiet = 0;
	}
	if (h->undecoded) {
		fprintf(out, "  %llu record(s) arrived and could not be "
			     "decoded\n", (unsigned long long)h->undecoded);
		quiet = 0;
	}
	if (h->sub_asked & ~h->sub_enabled) {
		fprintf(out, "  %ssome providers were asked for and did not "
			     "enable (asked 0x%lx, got 0x%lx) - whatever they "
			     "report is absent from this report%s\n",
			k->miss, (unsigned long)h->sub_asked,
			(unsigned long)h->sub_enabled, k->off);
		quiet = 0;
	}
	if (r->out_of_tree)
		fprintf(out, "  %llu event(s) discarded as being outside the "
			     "traced tree. A large number here is what a "
			     "payload that MIGRATED looks like.\n",
			(unsigned long long)r->out_of_tree);

	if (quiet)
		fprintf(out, "  nothing was dropped, and every provider asked "
			     "for was enabled.\n");

	if (!r->finished)
		fprintf(out, "  %sthe artefact phase did not run, so no file "
			     "was hashed, collected or scanned%s\n", k->miss,
			k->off);
	else if (!r->had_engine)
		fprintf(out, "  %sno engine was given: artefacts were hashed "
			     "and collected, and nothing was identified%s\n",
			k->dim, k->off);
}

static void write_tree(struct kof_report *r, FILE *out,
		       const struct ink *k)
{
	size_t i, n = kof_report_procs(r);

	fprintf(out, "\n%s-- the process tree --%s\n", k->bold, k->off);
	if (!n) {
		fprintf(out, "  no process event was seen, which for a launched "
			     "subject means the trace began after it had "
			     "already gone.\n");
		return;
	}

	for (i = 0; i < n; i++) {
		const struct kof_rep_proc *p = kof_report_proc_at(r, i);
		uint32_t d = p->depth > 8u ? 8u : p->depth;

		fprintf(out, "  %*s%s[%lu]%s %s", (int)(d * 2u), "",
			k->bold, (unsigned long)p->pid, k->off,
			p->image && *p->image ? p->image : "?");
		if (p->exited)
			fprintf(out, "  exit=%lu at %.3fs",
				(unsigned long)p->exit_code, rel(r, p->stopped));
		else
			fprintf(out, "  %sstill running when the trace ended%s",
				k->hit, k->off);
		fputc('\n', out);

		if (p->cmdline && *p->cmdline) {
			fprintf(out, "  %*s    cmd: ", (int)(d * 2u), "");
			put_safe(out, p->cmdline, 400u);
			fputc('\n', out);
		} else if (p->cmd_raced) {
			/* "It had none" and "we lost the race" are different
			 * facts - see KOF_EF_CMDLINE_RACED - and a report that
			 * showed both as an empty line would be turning a lost
			 * race into a process with no arguments. */
			fprintf(out, "  %*s    cmd: %s[unread: the process was "
				     "gone before it could be read]%s\n",
				(int)(d * 2u), "", k->dim, k->off);
		}
	}
	if (r->proc_dropped)
		fprintf(out, "  ... and %llu more, past the table's ceiling\n",
			(unsigned long long)r->proc_dropped);
}

/* One fingerprint, as the two or three lines a reader needs. */
static void write_fp(struct kof_report *r, FILE *out,
		     const struct ink *k, const struct kof_fingerprint *f)
{
	const struct kof_fp_bytes *b = &f->bytes;

	fprintf(out, "  %s%-11s%s ", group_ink(k, f->group),
		kof_fp_kind_name(f->kind), k->off);
	put_safe(out, f->text, 200u);

	if (f->count > 1u)
		fprintf(out, "  x%lu", (unsigned long)f->count);
	fprintf(out, "  %s%.3fs", k->dim, rel(r, f->first_seen));
	if (f->first_index != KOF_REP_NO_INDEX)
		fprintf(out, " [#%llu]", (unsigned long long)f->first_index);
	fprintf(out, " pid=%lu%s\n", (unsigned long)f->actor_pid, k->off);

	/* The second line carries everything that qualifies the first, and only
	 * what this fingerprint actually has - a row that reads "dport 0" is
	 * worse than no row, which is the rule kofevtfmt.c states for a
	 * properties panel and which holds here. */
	{
		int any = 0;

		/*
		 * KOF_LOC_OTHER IS NOT PRINTED, and the two skipped values are
		 * skipped for opposite reasons.
		 *
		 * KOF_LOC_UNKNOWN means nothing classified the path, which is
		 * a gap. KOF_LOC_OTHER means it WAS classified and is none of
		 * the interesting places - kofevt.h calls that "a fact, not a
		 * failure to decide". Both are correct answers and neither is
		 * worth a row: a line reading "in other" tells a reader
		 * nothing and costs them the second it took to read it.
		 */
		if (f->loc && f->loc != KOF_LOC_UNKNOWN &&
		    f->loc != KOF_LOC_OTHER) {
			fprintf(out, "              in %s", kof_loc_name(f->loc));
			any = 1;
		}
		if (f->attack) {
			fprintf(out, "%s%s %s", any ? ", " : "              ",
				kof_attack_id(f->attack),
				kof_attack_name(f->attack));
			any = 1;
		}
		if (f->flags & KOF_FP_F_SELF_DEL) {
			fprintf(out, "%s%sDELETED AGAIN before the run ended%s",
				any ? ", " : "              ", k->miss, k->off);
			any = 1;
		}
		if (f->flags & KOF_FP_F_SHARED) {
			fprintf(out, "%sseen from more than one process",
				any ? ", " : "              ");
			any = 1;
		}
		if (f->flags & KOF_FP_F_CUT) {
			fprintf(out, "%s%sTEXT WAS CUT - a rule written from "
				     "this matches a prefix%s",
				any ? ", " : "              ", k->miss, k->off);
			any = 1;
		}
		if (any)
			fputc('\n', out);
	}

	if (f->group != KOF_RG_STABLE && f->why && *f->why) {
		fprintf(out, "              %swhy %s: %s%s\n", k->dim,
			kof_rep_group_name(f->group), f->why, k->off);
		if (f->norm && *f->norm) {
			fprintf(out, "              invariant part: ");
			put_safe(out, f->norm, 200u);
			fputc('\n', out);
		}
	}

	/* Was the string in the sample - the line that decides whether this can
	 * become a signature at all. */
	switch (f->in_sample) {
	case KOF_FP_SEEN_PRESENT:
		fprintf(out, "              %sa literal in the sample%s\n",
			k->hit, k->off);
		break;
	case KOF_FP_SEEN_WIDE:
		fprintf(out, "              %sa literal in the sample, UTF-16 "
			     "- KOF_DEFINE_STR_WIDE%s\n", k->hit, k->off);
		break;
	case KOF_FP_SEEN_PART:
		fprintf(out, "              %sonly part of it is in the "
			     "sample%s: use that part%s\n", k->hit,
			(f->flags & KOF_FP_F_WIDE) ? ", as UTF-16" : "",
			k->off);
		break;
	case KOF_FP_SEEN_ABSENT:
		/*
		 * ONE SHORT LINE, AND WORDED FOR EVERY KIND.
		 *
		 * It was three lines of advice about finding the decryptor,
		 * which is right for a path and wrong for an AMSI submission -
		 * that one IS runtime content, so "built at runtime" is not a
		 * discovery about it. What is true of all of them is that the
		 * string is not in the file, so it cannot be the thing a rule
		 * matches. Say that and stop.
		 */
		fprintf(out, "              %snot in the sample's bytes%s\n",
			k->miss, k->off);
		break;
	default:
		break;
	}

	/* The bytes, for the kinds that have any. */
	if (f->kind == KOF_FP_FILE_NEW || f->kind == KOF_FP_FILE_WRITE) {
		if (b->why_not != KOF_FP_WHY_OK) {
			fprintf(out, "              %sno bytes: %s%s\n",
				k->dim, kof_fp_why_not(b->why_not), k->off);
		} else if (f->kind == KOF_FP_FILE_NEW) {
			fprintf(out, "              %llu bytes, sha256 %s\n",
				(unsigned long long)b->file_size,
				b->file_sha256[0] ? b->file_sha256 : "?");
			/*
			 * WHERE THE BYTES CAME FROM, when it is not the
			 * obvious place. Everything else in this report is
			 * read off the disk after the tree is dead;
			 * these were copied while the sample was still
			 * running, because by the end there was nothing left
			 * to read. That is a weaker claim - the sample may
			 * have written the file again after the copy - and a
			 * reader who is not told cannot know to make it.
			 */
			if (f->flags & KOF_FP_F_SPILLED)
				fprintf(out, "              %scaptured DURING "
					     "the run, before it was deleted - "
					     "not the end state%s\n",
					k->dim, k->off);
			if (b->stored[0])
				fprintf(out, "              kept as %s\n",
					b->stored);
		} else {
			fprintf(out, "              wrote %llu byte(s) from "
				     "offset %llu; read %llu back AT THE END "
				     "OF THE RUN\n",
				(unsigned long long)b->claimed,
				(unsigned long long)b->offset,
				(unsigned long long)b->got);
			if (b->sha256[0])
				fprintf(out, "              that range now "
					     "hashes to %s\n", b->sha256);
			if (b->stored[0])
				fprintf(out, "              kept as %s\n",
					b->stored);
		}

		if (b->preview_len) {
			uint32_t j;

			fprintf(out, "              first %lu: ",
				(unsigned long)b->preview_len);
			for (j = 0; j < b->preview_len && j < 24u; j++)
				fprintf(out, "%02x", b->preview[j]);
			fputs("  |", out);
			for (j = 0; j < b->preview_len; j++) {
				unsigned char c = b->preview[j];

				fputc((c >= 0x20u && c < 0x7fu) ? (int)c : '.',
				      out);
			}
			fputs("|\n", out);
		}
	}

	if (f->verdict.asked && (f->verdict.finding[0] || f->verdict.packed)) {
		fprintf(out, "              %sengine: %s", k->hit,
			f->verdict.finding[0] ? f->verdict.finding
					      : "no finding");
		if (f->verdict.packed)
			fprintf(out, ", packed%s%s",
				f->verdict.packer[0] ? " by " : "",
				f->verdict.packer[0] ? f->verdict.packer : "");
		if (f->verdict.children)
			fprintf(out, ", %lu came out of it",
				(unsigned long)f->verdict.children);
		fprintf(out, "%s\n", k->off);
	}
}

static void write_groups(struct kof_report *r, FILE *out,
			 const struct ink *k)
{
	static const char *HEAD[] = {
		"-- fingerprints that look the same every run --",
		"-- fingerprints holding something run-specific --",
		"-- the machine's own noise --"
	};
	static const char *SUB[] = {
		"Signature material. Each of these should recur on another "
		"machine.",
		"Kept, not dropped: the classification below can be wrong, and "
		"the invariant part of each is the half worth a string.",
		"Here so that a reader can see it was considered rather than "
		"missed."
	};
	uint8_t g;
	size_t  i, n = kof_report_count(r);

	for (g = 0; g < KOF_RG_GROUP_COUNT; g++) {
		size_t shown = 0;

		fprintf(out, "\n%s%s%s\n", k->bold, HEAD[g], k->off);
		fprintf(out, "%s%s%s\n\n", k->dim, SUB[g], k->off);

		for (i = 0; i < n; i++) {
			const struct kof_fingerprint *f = kof_report_at(r, i);

			if (!f || f->group != g)
				continue;
			write_fp(r, out, k, f);
			shown++;
		}
		if (!shown)
			fprintf(out, "  none.\n");
	}
}

/*
 * THE TAGGED LOCATIONS, AND THE HEADING IS DOING THE MOST IMPORTANT WORK HERE.
 *
 * kofevt.h is explicit that a technique tag is an INPUT to detection and never
 * an output of one, that every installer on the machine writes to a Run key,
 * and that nothing may surface a tag as if a rule had fired. This section
 * obeys that by saying what the list IS - places the matrix has a name for,
 * that this tree wrote to - and by being separate from anything the report
 * calls a finding.
 */
static void write_tagged(struct kof_report *r, FILE *out,
			 const struct ink *k)
{
	size_t i, n = kof_report_count(r), shown = 0;

	fprintf(out, "\n%s-- locations the ATT&CK matrix names, that this tree "
		     "wrote to --%s\n", k->bold, k->off);
	fprintf(out, "%sOBSERVATIONS, NOT FINDINGS. A location having a "
		     "technique id means the write landed somewhere the matrix\n"
		     "has a name for - which every installer on the machine "
		     "also does. Nothing here fired a rule.%s\n\n",
		k->dim, k->off);

	for (i = 0; i < n; i++) {
		const struct kof_fingerprint *f = kof_report_at(r, i);

		if (!f || !f->attack)
			continue;
		fprintf(out, "  %-10s %-12s ", kof_attack_id(f->attack),
			kof_attack_name(f->attack));
		put_safe(out, f->text, 150u);
		fputc('\n', out);
		shown++;
	}
	if (!shown)
		fprintf(out, "  none.\n");
}

static void write_foot(struct kof_report *r, FILE *out,
		       const struct ink *k)
{
	uint8_t j;
	int     any = 0;

	fprintf(out, "\n%s-- what is not in the lists above --%s\n", k->bold,
		k->off);
	for (j = 0; j < KOF_FP_KIND_COUNT; j++) {
		uint64_t d = kof_report_dropped(r, j);

		if (!d)
			continue;
		fprintf(out, "  %s%llu more %s fingerprint(s) than the table "
			     "holds%s\n", k->miss, (unsigned long long)d,
			kof_fp_kind_name(j), k->off);
		any = 1;
	}
	if (!any)
		fprintf(out, "  nothing: every distinct fingerprint the trace "
			     "produced is listed.\n");

	if (r->finished) {
		fprintf(out, "\n  %lu file(s) collected, %lu could not be, "
			     "%llu byte(s) of written ranges read back\n",
			(unsigned long)r->collected,
			(unsigned long)r->collect_failed,
			(unsigned long long)r->evidence_bytes);
	}

	fprintf(out, "\n%sNo score, on purpose.%s %zu fingerprint(s) is %zu "
		     "things to look at.\n", k->dim, k->off,
		kof_report_count(r), kof_report_count(r));
}

int kof_report_write_text(struct kof_report *r, FILE *out, int color)
{
	struct ink k;

	if (!r || !out)
		return KOF_ERR_ARG;
	ink_of(&k, color);

	write_head(r, out, &k);
	write_gaps(r, out, &k);
	write_tree(r, out, &k);
	write_groups(r, out, &k);
	write_tagged(r, out, &k);
	write_foot(r, out, &k);
	return 0;
}

/* ---- JSON ---------------------------------------------------------------- */

/*
 * ESCAPED PROPERLY, AND THIS IS THE ONE PLACE IN THE FILE WHERE THAT IS A
 * SAFETY PROPERTY RATHER THAN A CORRECTNESS ONE.
 *
 * The strings here came from paths the sample chose and from script content it
 * submitted - raw and unsanitised, deliberately, because the half that scans
 * them must get what arrived. A pipeline reading this JSON will believe it, so
 * anything that could end a string early or inject a key has to be escaped:
 * quotes, backslashes, every control character. Non-ASCII bytes go out as
 * \u00XX rather than raw, because the input is BYTES and JSON is UTF-8 - a
 * lone 0x80 emitted raw makes the whole document invalid and is exactly what a
 * filename from a hostile sample contains.
 */
static void jstr(FILE *out, const char *s, size_t cap)
{
	size_t i;

	fputc('"', out);
	for (i = 0; s && s[i] && i < cap; i++) {
		unsigned char c = (unsigned char)s[i];

		switch (c) {
		case '"':  fputs("\\\"", out); break;
		case '\\': fputs("\\\\", out); break;
		case '\n': fputs("\\n", out);  break;
		case '\r': fputs("\\r", out);  break;
		case '\t': fputs("\\t", out);  break;
		default:
			if (c < 0x20u || c >= 0x7fu)
				fprintf(out, "\\u%04x", (unsigned)c);
			else
				fputc((int)c, out);
		}
	}
	fputc('"', out);
}

static void jbytes(FILE *out, const struct kof_fp_bytes *b)
{
	uint32_t j;

	fputs("{\"offset\":", out);
	fprintf(out, "%llu,\"claimed\":%llu,\"got\":%llu",
		(unsigned long long)b->offset,
		(unsigned long long)b->claimed,
		(unsigned long long)b->got);
	fputs(",\"sha256\":", out);      jstr(out, b->sha256, 64u);
	fputs(",\"file_sha256\":", out); jstr(out, b->file_sha256, 64u);
	fprintf(out, ",\"file_size\":%llu", (unsigned long long)b->file_size);
	fputs(",\"stored\":", out);      jstr(out, b->stored, 95u);
	fprintf(out, ",\"at_finish\":%s", b->at_finish ? "true" : "false");
	fputs(",\"why_not\":", out);     jstr(out, kof_fp_why_not(b->why_not), 200u);
	fputs(",\"preview_hex\":\"", out);
	for (j = 0; j < b->preview_len; j++)
		fprintf(out, "%02x", b->preview[j]);
	fputs("\"}", out);
}

static void jverdict(FILE *out, const struct kof_fp_verdict *v)
{
	fprintf(out, "{\"asked\":%s", v->asked ? "true" : "false");
	fputs(",\"finding\":", out); jstr(out, v->finding, 223u);
	fprintf(out, ",\"packed\":%s,\"depth\":%u,\"entropy_eighths\":%lu"
		     ",\"children\":%lu,\"examined\":%lu,\"broken\":%lu",
		v->packed ? "true" : "false", (unsigned)v->depth,
		(unsigned long)v->entropy8, (unsigned long)v->children,
		(unsigned long)v->examined, (unsigned long)v->broken);
	fputs(",\"packer\":", out); jstr(out, v->packer, 47u);
	fprintf(out, ",\"packer_version\":%llu}",
		(unsigned long long)v->packer_version);
}

int kof_report_write_json(struct kof_report *r, FILE *out)
{
	size_t i, n;

	if (!r || !out)
		return KOF_ERR_ARG;

	fputs("{\n  \"run\": {", out);
	fputs("\"tool\":", out);    jstr(out, r->info.tool, 64u);
	fputs(",\"subject\":", out); jstr(out, r->info.subject, 512u);
	fputs(",\"command\":", out); jstr(out, r->info.subject_cmd, 2048u);
	fputs(",\"sha256\":", out);  jstr(out, r->subject_sha256, 64u);
	fprintf(out, ",\"size\":%llu", (unsigned long long)r->subject_size);
	fprintf(out, ",\"root_pid\":%lu,\"build\":%lu,\"platform\":%u"
		     ",\"arch\":%u,\"seconds\":%.3f,\"events\":%llu"
		     ",\"ended\":%u,\"finished\":%s,\"engine\":%s",
		(unsigned long)r->info.root_pid, (unsigned long)r->info.build,
		(unsigned)r->info.platform, (unsigned)r->info.arch,
		r->seconds, (unsigned long long)r->n_events,
		(unsigned)r->ended, r->finished ? "true" : "false",
		r->had_engine ? "true" : "false");
	fputs(",\"log\":", out); jstr(out, r->info.log, 512u);
	fputs(",\"verdict\":", out); jverdict(out, &r->subject_verdict);
	fputs("},\n", out);

	/*
	 * THE HEALTH IS A TOP-LEVEL OBJECT AND NOT A FOOTNOTE, for the same
	 * reason it is printed second in the text: a consumer that draws a
	 * conclusion from an absence has to be able to see whether the trace
	 * was complete, and it will not go looking.
	 */
	fprintf(out, "  \"completeness\": {\"reported\":%s,\"produced\":%llu"
		     ",\"dropped\":%llu,\"upstream_lost\":%llu,\"seq_gaps\":%llu"
		     ",\"undecoded\":%llu,\"filtered\":%llu"
		     ",\"out_of_tree\":%llu,\"sub_asked\":%lu"
		     ",\"sub_enabled\":%lu},\n",
		r->have_health ? "true" : "false",
		(unsigned long long)r->health.produced,
		(unsigned long long)r->health.dropped,
		(unsigned long long)r->health.upstream_lost,
		(unsigned long long)r->health.seq_gaps,
		(unsigned long long)r->health.undecoded,
		(unsigned long long)r->health.filtered,
		(unsigned long long)r->out_of_tree,
		(unsigned long)r->health.sub_asked,
		(unsigned long)r->health.sub_enabled);

	fputs("  \"processes\": [\n", out);
	n = kof_report_procs(r);
	for (i = 0; i < n; i++) {
		const struct kof_rep_proc *p = kof_report_proc_at(r, i);

		fputs("    {", out);
		fprintf(out, "\"pid\":%lu,\"ppid\":%lu,\"depth\":%lu"
			     ",\"create_time\":%llu,\"exited\":%s"
			     ",\"exit_code\":%lu,\"cmd_raced\":%s",
			(unsigned long)p->pid, (unsigned long)p->ppid,
			(unsigned long)p->depth,
			(unsigned long long)p->create_time,
			p->exited ? "true" : "false",
			(unsigned long)p->exit_code,
			p->cmd_raced ? "true" : "false");
		fputs(",\"image\":", out);   jstr(out, p->image, 512u);
		fputs(",\"cmdline\":", out); jstr(out, p->cmdline, 2048u);
		fprintf(out, ",\"t\":%.3f}%s\n", rel(r, p->started),
			i + 1u < n ? "," : "");
	}
	fputs("  ],\n", out);

	fputs("  \"fingerprints\": [\n", out);
	n = kof_report_count(r);
	for (i = 0; i < n; i++) {
		const struct kof_fingerprint *f = kof_report_at(r, i);

		if (!f)
			break;
		fputs("    {", out);
		fputs("\"kind\":", out);  jstr(out, kof_fp_kind_name(f->kind), 32u);
		fputs(",\"group\":", out); jstr(out, kof_rep_group_name(f->group), 16u);
		fputs(",\"text\":", out);  jstr(out, f->text, 2048u);
		fputs(",\"invariant\":", out); jstr(out, f->norm, 2048u);
		fputs(",\"why_group\":", out); jstr(out, f->why, 200u);
		fputs(",\"where\":", out); jstr(out, kof_loc_name(f->loc), 32u);
		fputs(",\"technique\":", out); jstr(out, kof_attack_id(f->attack), 16u);
		fputs(",\"technique_name\":", out);
		jstr(out, kof_attack_name(f->attack), 48u);
		fputs(",\"in_sample\":", out);
		jstr(out, kof_fp_seen_name(f->in_sample), 16u);
		fprintf(out, ",\"count\":%lu,\"actor_pid\":%lu,\"t\":%.3f"
			     ",\"last_t\":%.3f,\"cut\":%s,\"shared\":%s"
			     ",\"deleted_again\":%s",
			(unsigned long)f->count, (unsigned long)f->actor_pid,
			rel(r, f->first_seen), rel(r, f->last_seen),
			(f->flags & KOF_FP_F_CUT) ? "true" : "false",
			(f->flags & KOF_FP_F_SHARED) ? "true" : "false",
			(f->flags & KOF_FP_F_SELF_DEL) ? "true" : "false");
		if (f->first_index != KOF_REP_NO_INDEX)
			fprintf(out, ",\"record\":%llu",
				(unsigned long long)f->first_index);
		else
			fputs(",\"record\":null", out);
		fputs(",\"bytes\":", out);   jbytes(out, &f->bytes);
		fputs(",\"verdict\":", out); jverdict(out, &f->verdict);
		fprintf(out, "}%s\n", i + 1u < n ? "," : "");
	}
	fputs("  ]\n}\n", out);
	return 0;
}

/* ---- the signature draft ------------------------------------------------- */

/*
 * CANDIDATE STRINGS, IN A FORMAT A C TOOL CAN READ WITH strtok.
 *
 * Tab separated and line oriented rather than JSON, because the consumer is
 * kofeditor - a C program that already parses signature sources with strstr -
 * and handing it a JSON document would mean writing a JSON parser to carry
 * eight fields.
 *
 * NOT A .c FILE, AND THAT IS THE POINT. kofeditor is the signature generator;
 * it writes KOF_DEFINE_STR, KOF_TARGET_RANGE and the matcher body today, and a
 * second generator here would be a second generator to drift. This writes
 * what the trace learned - which strings, how to declare them, and whether
 * they are actually in the bytes - and the generator stays where it is.
 *
 * `seen` is the field that makes the file worth having. A candidate marked
 * absent would produce a signature that can never match, and nothing else in
 * the pipeline would notice: the source compiles, the database builds, the
 * rule loads and it is simply always false.
 */
int kof_report_write_candidates(struct kof_report *r, FILE *out)
{
	size_t i, n;

	if (!r || !out)
		return KOF_ERR_ARG;

	fputs("# kofcandidates 1\n"
	      "# Candidate strings observed by a trace, with whether each is\n"
	      "# actually present in the sample's bytes. Tab separated:\n"
	      "#\n"
	      "#   str <group> <seen> <wide> <kind> <technique> <why> <text>\n"
	      "#\n"
	      "# <seen>  present | present-wide | fragment | absent | unchecked\n"
	      "# <wide>  1 when the literal is UTF-16 in the sample, so the\n"
	      "#         declaration is KOF_DEFINE_STR_WIDE\n"
	      "# <text>  C escaped, and it is the INVARIANT spelling when the\n"
	      "#         group is volatile - the raw one differs every run\n"
	      "#\n"
	      "# A line marked absent is not a candidate: the sample built that\n"
	      "# string at runtime, so a rule using it can never fire.\n", out);

	fputs("subject\t", out);
	fputs(r->subject_sha256[0] ? r->subject_sha256 : "-", out);
	fputc('\t', out);
	fputs(r->info.subject && *r->info.subject ? r->info.subject : "-", out);
	fputc('\n', out);

	n = kof_report_count(r);
	for (i = 0; i < n; i++) {
		const struct kof_fingerprint *f = kof_report_at(r, i);
		const char *text;
		size_t      j;

		if (!f)
			break;

		/* Ambient fingerprints are not candidates: a rule on
		 * ntdll.dll matches every process on the machine. They stay in
		 * the report, where a reader can see they were considered. */
		if (f->group == KOF_RG_AMBIENT)
			continue;
		/* Nothing to declare for these: an unbacked thread has no
		 * string, and a peer is in the binary as four packed bytes if
		 * it is there at all. */
		if (f->kind == KOF_FP_UNBACKED || f->kind == KOF_FP_PEER)
			continue;

		/* The invariant spelling when there is one, because that is
		 * the half that recurs - which is the whole reason `norm`
		 * exists rather than the volatile group being dropped. */
		text = (f->group == KOF_RG_VOLATILE && f->norm && *f->norm)
			       ? f->norm : f->text;

		fprintf(out, "str\t%s\t%s\t%d\t%s\t%s\t%s\t",
			kof_rep_group_name(f->group),
			kof_fp_seen_name(f->in_sample),
			/* From the flag and not from `seen`, because a
			 * fragment can be wide too - a sample holding
			 * "svc32.exe" as UTF-16 inside a path it composes at
			 * runtime is the common case, and reading the encoding
			 * off `seen` would declare it narrow. */
			(f->flags & KOF_FP_F_WIDE) ? 1 : 0,
			kof_fp_kind_name(f->kind),
			f->attack ? kof_attack_id(f->attack) : "-",
			(f->why && *f->why) ? f->why : "-");

		/* C escaped, so the consumer can paste it between the quotes
		 * of a KOF_DEFINE_STR without looking at it - and so that a
		 * tab or a newline in a path the sample chose cannot invent a
		 * column or a row. */
		for (j = 0; text[j] && j < 400u; j++) {
			unsigned char c = (unsigned char)text[j];

			switch (c) {
			case '\\': fputs("\\\\", out); break;
			case '"':  fputs("\\\"", out); break;
			case '\t': fputs("\\t", out);  break;
			case '\n': fputs("\\n", out);  break;
			case '\r': fputs("\\r", out);  break;
			default:
				if (c < 0x20u || c >= 0x7fu)
					fprintf(out, "\\x%02X", (unsigned)c);
				else
					fputc((int)c, out);
			}
		}
		fputc('\n', out);
	}
	return 0;
}
