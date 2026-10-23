/*
 * kofmontrace_scan.c - what a collected artefact is scanned with and the spiller that keeps what the run wrote. Split from kofmontrace.c; the text is unchanged.
 */

/* _GNU_SOURCE before any include - see kofmontrace.c. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif

#include "kofmontrace_int.h"


/* ---------------------------------------------- answering the report's question
 *
 * WHY THIS LIVES HERE AND NOT IN libkoforbit.
 *
 * It used to sit in kofrepart.c, which made a library in orbit the place that
 * decided a host's scan policy: which options, which ceiling, whether the
 * interpreter runs. koffridge.h states the rule for the whole of orbit - it
 * may know the engine's TYPES, never drive it - and holding a kof_scanner and
 * calling kscan_path is driving it.
 *
 * So orbit now declares struct kof_rep_engine and this supplies one. The four
 * lines that build the options are the same four lines; what changed is that
 * they are the host's, which is the side that owns the scanner and knows what
 * a scan of a collected artefact is allowed to cost here.
 */

struct scan_sink {
	struct kof_fp_verdict *v;
	uint32_t               depth0_seen;
	uint32_t               f_version;
};

static void on_note(uint32_t fact, const char *what, uint64_t value, void *user)
{
	struct scan_sink *s = (struct scan_sink *)user;

	if (!s || !s->v || !what)
		return;

	/*
	 * THE FIRST NOTE FROM A MODULE WHOSE NAME IS ITS PACKER'S.
	 *
	 * `what` is authored text - "UPX.ELF.version", "Rar.entries" - and the
	 * part before the first dot is the module. Taken whole up to the last
	 * dot, so "UPX.ELF" survives and the field name does not: which packer
	 * AND which of its variants is the useful half, and a report saying
	 * "UPX" where the module said "UPX.ELF" would be throwing away the one
	 * thing that distinguishes two unpackers.
	 *
	 * First wins. A scan of a nested object emits notes from every layer,
	 * and the outermost is the one the artefact IS.
	 */
	if (!s->v->packer[0]) {
		const char *dot = strrchr(what, '.');
		size_t      n   = dot ? (size_t)(dot - what) : strlen(what);

		if (n >= sizeof s->v->packer)
			n = sizeof s->v->packer - 1u;
		memcpy(s->v->packer, what, n);
		s->v->packer[n] = '\0';
	}

	if (!s->f_version)
		s->f_version = kverdict_fact_id("version");
	if (fact == s->f_version && !s->v->packer_version)
		s->v->packer_version = value;
}

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct scan_sink *s = (struct scan_sink *)user;

	(void)name;
	if (!s || !s->v || !res)
		return 0;

	/*
	 * THE FIRST OBJECT IS THE ONE THE REPORT IS ABOUT; the rest are what
	 * came out of it.
	 *
	 * A file scan reports the file and then every child the engine
	 * produced, in that order, so the first callback is the artefact itself
	 * and each later one is evidence that something was inside it. Counting
	 * children rather than describing them is deliberate: a report about a
	 * dropped file needs to say "packed, one payload came out"; describing
	 * the payload is a scan of the payload, which is a thing somebody asks
	 * for separately.
	 */
	if (!s->depth0_seen++) {
		s->v->asked    = 1;
		s->v->examined = res->examined;
		s->v->broken   = res->broken;
		s->v->depth    = res->heur_depth;
		s->v->packed   = (res->heur_depth || res->from_packer) ? 1u : 0u;
		if (bytes && len)
			s->v->entropy8 = kentropy_eighths(bytes, len);
		if (res->has_verdict)
			snprintf(s->v->finding, sizeof s->v->finding, "%s",
				 res->verdict.name);
	} else {
		s->v->children++;
		/* A CHILD IS WHAT PROVES THE PARENT WAS PACKED, and the parent's
		 * own record may not say so: from_packer is set on the object
		 * an unpacker PRODUCED, not on the one it read. */
		if (res->from_packer)
			s->v->packed = 1;
		/*
		 * A VERDICT ON A CHILD IS THE VERDICT, when the parent had
		 * none. That is the normal shape of a packed sample: the stub
		 * matches nothing and the payload matches a family, and a
		 * report that showed only the parent's verdict would say
		 * "nothing known" about a recognised trojan.
		 */
		if (!s->v->finding[0] && res->has_verdict)
			snprintf(s->v->finding, sizeof s->v->finding, "%s",
				 res->verdict.name);
	}
	return 0;
}

/*
 * DESCEND, AND DO NOT INTERPRET.
 *
 * A report wants to know what came out of a collected file, so the static
 * unpackers and the container walk are on. Emulation is not: kofeng.h measures
 * a UPX-with-LZMA sample at forty million instructions and the worst in its
 * corpus at two hundred and fifty, and a report over a dozen collected files
 * would inherit all of it. A caller who wants that scans the collected file,
 * which is what the files are collected FOR.
 *
 * The note callback is installed and then PUT BACK, because a host that had
 * one of its own must not lose it to this.
 */
int kmt_rep_ask(void *user, const char *path, struct kof_fp_verdict *v)
{
	kof_scanner            *sc = (kof_scanner *)user;
	struct kof_scan_option  opt;
	struct scan_sink        sink;

	if (!sc || !path || !*path || !v)
		return -1;

	memset(&sink, 0, sizeof sink);
	sink.v = v;

	memset(&opt, 0, sizeof opt);
	opt.emu_use = KOF_EMU_NEVER;

	kscan_on_debug(sc, on_note, &sink);
	(void)kscan_path(sc, path, &opt, on_object, &sink);
	kscan_on_debug(sc, NULL, NULL);
	return 0;
}



static uint64_t spill_hash(const char *s)
{
	return kof_hash64_nz(kof_hash64_str(s));   /* 0 means an empty slot */
}

static int spill_seen(struct spiller *sp, const char *path)
{
	uint64_t h = spill_hash(path);
	size_t   n = sizeof sp->seen / sizeof sp->seen[0];
	size_t   i = (size_t)(h % n);
	size_t   k;

	for (k = 0; k < n; k++, i = (i + 1) % n) {
		if (!sp->seen[i]) {
			sp->seen[i] = h;
			return 0;
		}
		if (sp->seen[i] == h)
			return 1;
	}
	return 1;   /* full: treat everything as seen rather than thrash */
}

void kmt_spill_init(struct spiller *sp, const char *rep_dir)
{
	memset(sp, 0, sizeof *sp);
	if (!rep_dir || !*rep_dir)
		return;
	snprintf(sp->guard, sizeof sp->guard, "%s", rep_dir);
	sp->guard_len = strlen(sp->guard);
	snprintf(sp->dir, sizeof sp->dir, "%s/spill", rep_dir);
	sp->ready = (kof_report_mkpath(sp->dir) == 0);
	if (!sp->ready)
		fprintf(stderr, "kofmontrace: cannot make %s - a file the "
			"sample deletes will not be captured\n", sp->dir);
}

void kmt_spill_take(struct spiller *sp, struct kof_report *rep,
		       const struct kof_evt *e)
{
	const char *path;
	char  out[640];
	FILE *in, *dst;
	unsigned char buf[64u * 1024u];
	uint64_t wrote = 0;
	size_t   got;

	if (!sp->ready || !rep)
		return;
	if (e->verb != KOF_EVT_FILE_NEW && e->verb != KOF_EVT_FILE_WRITE)
		return;
	path = kof_evt_object(e);
	if (!path || !*path)
		return;
	/* Our own copies, and the report we are writing into. */
	if (sp->guard_len && !strncmp(path, sp->guard, sp->guard_len))
		return;
	if (sp->n >= SPILL_MAX_FILES) {
		sp->skipped_full++;
		return;
	}
	if (spill_seen(sp, path))
		return;

	in = fopen(path, "rb");
	if (!in) {
		/* Already gone, or not ours to read. Not an error: the report
		 * will say the bytes were not captured, which is true. */
		sp->failed++;
		return;
	}
	/*
	 * THE NAME MUST NOT ALREADY EXIST, and this is the one tool in the
	 * tree where that is not a formality.
	 *
	 * spill/0000.bin, 0001.bin, ... is a shape the sample can predict, and
	 * the sample is RUNNING while this writes: it can drop a symlink at
	 * the next number and have its own bytes copied through it to
	 * anywhere this process can write. kof_fopen_new refuses a name that
	 * is taken, symlink included, so a planted name is a failed capture
	 * instead of a write-what-where.
	 */
	snprintf(out, sizeof out, "%s/%04u.bin", sp->dir, sp->n);
	dst = kof_fopen_new(out);
	if (!dst) {
		fclose(in);
		sp->failed++;
		return;
	}
	while ((got = fread(buf, 1, sizeof buf, in)) > 0) {
		if (wrote + got > SPILL_MAX_ONE ||
		    sp->bytes + wrote + got > SPILL_MAX_TOTAL) {
			/*
			 * A TRUNCATED COPY IS WORSE THAN NONE. Its digest
			 * would name bytes that were never a file, and every
			 * tool downstream treats a digest as an identity. So
			 * the partial copy is removed and the report goes on
			 * saying the bytes were not captured.
			 */
			fclose(dst);
			fclose(in);
			remove(out);
			sp->skipped_big++;
			return;
		}
		if (fwrite(buf, 1, got, dst) != got) {
			fclose(dst);
			fclose(in);
			remove(out);
			sp->failed++;
			return;
		}
		wrote += got;
	}
	fclose(in);
	if (fclose(dst) != 0 || kof_report_spill(rep, path, out) != 0) {
		remove(out);
		sp->failed++;
		return;
	}
	sp->n++;
	sp->bytes += wrote;
}

void kmt_spill_report(const struct spiller *sp, FILE *out)
{
	if (!sp->ready || (!sp->n && !sp->skipped_big && !sp->skipped_full &&
			   !sp->failed))
		return;
	fprintf(out, "   %u file(s) copied during the run, %.2f MB",
		sp->n, (double)sp->bytes / 1048576.0);
	if (sp->skipped_big)
		fprintf(out, "; %llu over the per-file ceiling",
			(unsigned long long)sp->skipped_big);
	if (sp->skipped_full)
		fprintf(out, "; %llu past the table",
			(unsigned long long)sp->skipped_full);
	if (sp->failed)
		fprintf(out, "; %llu unreadable",
			(unsigned long long)sp->failed);
	fputs("\n   These stand in ONLY where the original was deleted before "
	      "the run ended.\n", out);
}
