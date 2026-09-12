/*
 * kofrepart.c - the artefacts: collect them, hash them, read back what was
 * written, and ask the engine what they are.
 *
 * THE SECOND PHASE, AND EVERYTHING EXPENSIVE IS HERE ON PURPOSE.
 *
 * kofreport.c runs on the consumer thread while the ring behind it fills, so
 * it may not open a file. This runs once, after the traced tree is dead, and
 * may do anything - which is the same boundary the kofwatchtower/kofwatchman
 * split draws for the same reason: unbounded I/O on a drain path does not cost
 * a queue, it costs a full ring, and the events dropped are everybody else's.
 *
 * IT ALSO HAS TO BE AFTER THE TREE IS DEAD, not merely after the trace.
 *
 * A file being written while it is read hashes to a value that was never on
 * the disk. A file whose writer is still running can change between the hash
 * and the scan, so the report would name one thing and describe another. And a
 * sample that is still executing is still producing artefacts, so a collection
 * taken while it runs is a collection of a moment nobody can reproduce. The
 * instant the job object closes is the first instant any of this is true, and
 * kofmontrace calls this right after it.
 *
 *
 * WHAT IT CANNOT DO, SAID HERE BECAUSE IT IS THE FIRST QUESTION
 *
 * A file the sample created and then deleted is GONE. There is no event that
 * carries content on either platform, and there is no in-box way to be handed
 * a file's bytes at the moment it is closed - that needs a filesystem
 * minifilter, which is a driver and a different product. So a self-deleting
 * dropper's second stage is reported as KOF_FP_F_SELF_DEL with
 * KOF_FP_WHY_GONE, and the report says plainly that the bytes were not
 * captured rather than showing an empty digest column.
 *
 * What survives even then is the RANGE: the offsets and lengths the write
 * events carried, and the fact of the file. That is less than the bytes and it
 * is not nothing - "wrote 284KB at offset 0 then deleted it" is a stage that
 * existed, at a size, and it is the difference between a gap a reader can
 * reason about and a silence.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "kofrepint.h"
#include "kofeng.h"
#include "kofplatform.h"

/* ---- paths --------------------------------------------------------------- */

/*
 * ONE SEPARATOR, AND IT IS '/'.
 *
 * Every path this file BUILDS is inside the report directory, and it is built
 * with forward slashes on both platforms: Windows accepts them everywhere a
 * backslash goes, the report's own text stays copy-pasteable on either host,
 * and a directory of evidence moved from a Windows machine to a Linux one
 * still reads. Paths that came from the TRACE are never rewritten - those are
 * the sample's own spelling and are evidence.
 */
static void joinp(char *out, size_t cap, const char *a, const char *b)
{
	size_t n = a ? strlen(a) : 0;

	if (!cap)
		return;
	if (!n) {
		snprintf(out, cap, "%s", b ? b : "");
		return;
	}
	if (a[n - 1u] == '/' || a[n - 1u] == '\\')
		snprintf(out, cap, "%s%s", a, b ? b : "");
	else
		snprintf(out, cap, "%s/%s", a, b ? b : "");
}

/* mkdir that is content with the directory already being there, which is the
 * normal case for the second file collected into it. */
static int mkdir_one(const char *path)
{
	if (!path || !*path)
		return 0;
	if (kof_mkdir(path, 0777) == 0)
		return 0;
	return (errno == EEXIST) ? 0 : -1;
}

/*
 * EVERY LEVEL OF IT, because a caller says `--report out/2026-09-12/sample`
 * and means it.
 *
 * mkdir makes one level. The first version called it once, which worked only
 * when every parent already happened to exist - so `--report out\dns` created
 * the report when `out` was there and failed with three "cannot write" lines
 * when it was not. That is a bad failure twice over: it happens AFTER the
 * sample has been run, so the evidence is collected and then dropped on the
 * floor, and the message blames the files rather than the missing directory.
 *
 * WHAT IT DELIBERATELY DOES NOT DO: interpret the path. A prefix that is a
 * drive letter, a UNC root or a leading separator is skipped rather than
 * created - "C:" is not a directory anybody makes, and calling mkdir on it
 * would fail in a way that has to be told apart from a real failure. Walking
 * separators and creating what lies between them is the whole of it.
 */
int kofrep_ensure_dir(const char *path)
{
	char  buf[1024];
	size_t n, i;

	if (!path || !*path)
		return 0;

	n = strlen(path);
	if (n >= sizeof buf)
		return -1;
	memcpy(buf, path, n + 1u);

	/*
	 * Start past any root. "C:\x" begins at index 3, "\\host\share\x" and
	 * "/x" at their first non-separator - and a relative path has no root
	 * to skip, which is the common case.
	 */
	i = 0;
	if (n >= 2u && buf[1] == ':')
		i = 2u;
	while (buf[i] == '/' || buf[i] == '\\')
		i++;

	for (; i <= n; i++) {
		char c = buf[i];

		if (c != '/' && c != '\\' && c != '\0')
			continue;
		/* A trailing separator, or two in a row, names the directory
		 * that was just made. */
		if (i && (buf[i - 1u] == '/' || buf[i - 1u] == '\\'))
			continue;

		buf[i] = '\0';
		if (mkdir_one(buf) != 0)
			return -1;
		if (c == '\0')
			break;
		buf[i] = c;
	}
	return 0;
}

int kof_report_mkpath(const char *dir)
{
	if (!dir || !*dir)
		return 0;
	return kofrep_ensure_dir(dir) == 0 ? 0 : KOF_ERR_OPEN;
}

/* ---- reading bytes ------------------------------------------------------- */

/*
 * A RANGE OF A FILE, READ BACK OFF THE DISK.
 *
 * Returns how many bytes it got, and sets `why` when that is short of what was
 * asked for. Every failure here is an expected outcome rather than an error:
 * the file is gone because the sample deleted it, it is locked because
 * something still has it open, or it is shorter than the write said because it
 * was truncated afterwards. The report names which.
 */
static uint64_t read_range(const char *path, uint64_t off, uint64_t want,
			   void *into, uint8_t *why)
{
	FILE    *f;
	size_t   got;

	*why = KOF_FP_WHY_OK;

	f = fopen(path, "rb");
	if (!f) {
		/* ENOENT and EACCES are different facts and a reader needs
		 * them apart: the first is a dropper that cleaned up, the
		 * second is a file still held open by something. */
		*why = (errno == ENOENT) ? KOF_FP_WHY_GONE : KOF_FP_WHY_DENIED;
		return 0;
	}

	/*
	 * fseeko is POSIX and _fseeki64 is Microsoft's, and this tree builds
	 * with a strict -std=c11 where neither is declared. fseek takes a long,
	 * which on the Windows toolchains here is 32 bits - so an offset past
	 * 2GB would wrap silently and read the wrong bytes, which is precisely
	 * the class of failure this library refuses to commit. Seek in steps
	 * instead: slower than one call, correct on every target, and the loop
	 * runs a handful of times for any offset a dropper actually writes at.
	 */
	{
		uint64_t left = off;

		while (left) {
			long step = (left > 0x40000000ull) ? 0x40000000L
							  : (long)left;

			if (fseek(f, step, SEEK_CUR) != 0) {
				fclose(f);
				*why = KOF_FP_WHY_SHORT;
				return 0;
			}
			left -= (uint64_t)step;
		}
	}

	got = fread(into, 1, (size_t)want, f);
	if (ferror(f))
		*why = KOF_FP_WHY_DENIED;
	else if ((uint64_t)got < want)
		*why = KOF_FP_WHY_SHORT;
	fclose(f);
	return got;
}

/* The first bytes of a range, for the inline preview a reader actually looks
 * at. Kept separate from the digest so that a range too big to hash still has
 * something a human can recognise. */
static void set_preview(struct kof_fp_bytes *b, const unsigned char *p,
			uint64_t n)
{
	uint32_t k = (n > KOF_FP_PREVIEW) ? KOF_FP_PREVIEW : (uint32_t)n;

	memcpy(b->preview, p, k);
	b->preview_len = k;
}

/* ---- what the engine said ------------------------------------------------ */

/*
 * ONE SCAN'S WORTH OF ANSWER, gathered by two callbacks that have to agree.
 *
 * The object callback sees results; the note channel sees what a module worked
 * out on its way to them, which is where a packer's name and version come
 * from. They are collected into one place because a report needs them on one
 * line, and because the notes arrive BEFORE the finding - which is what makes
 * them useful when the finding never comes at all.
 */
/*
 * Ask whoever can answer about one path. Fills `v`, including `asked`, and
 * leaves it untouched when nobody was supplied.
 *
 * The scan itself is NOT here any more - see struct kof_rep_engine. What used
 * to sit at this spot built a kof_scan_option, installed a note callback and
 * called kof_scan_path, which made this file the place that decided a host's
 * scan policy.
 */
static void ask_engine(const struct kof_report_stage *st, const char *path,
		       struct kof_fp_verdict *v)
{
	if (!st || !st->engine || !st->engine->ask || !path || !*path)
		return;
	(void)st->engine->ask(st->engine->user, path, v);
}

/* ---- was the string in the sample --------------------------------------- */

/*
 * THE HALF THAT TURNS AN OBSERVATION INTO SIGNATURE MATERIAL.
 *
 * A trace says which strings are worth looking for. Only the bytes say whether
 * they are there - and the answer decides what a researcher does next:
 *
 *   PRESENT   the literal is in the file. A signature can use it today.
 *   WIDE      it is there as UTF-16, so the declaration is KOF_DEFINE_STR_WIDE
 *             and a byte-exact rule written from the narrow form matches
 *             nothing. kofviewer's note at the KOF_DEFINE_STR_WIDE site makes
 *             the same point from the other side.
 *   FRAGMENT  part of it is - the basename without the directory, usually,
 *             because the sample built the path from a known folder and a
 *             literal name. The fragment is the string worth using.
 *   ABSENT    none of it is. NOT a null result: it means the string was
 *             constructed at runtime or decrypted, which sends a researcher to
 *             find the decryptor instead of writing a rule that can never fire.
 *
 * Searched over the subject's bytes, once, with the whole file in memory. A
 * matcher per candidate over a mapped file would be the same work; holding the
 * bytes is simpler and the ceiling is the caller's max_file_bytes.
 */
static int find_bytes(const unsigned char *hay, size_t hn, const char *needle,
		      size_t nn)
{
	if (!hay || !needle || !nn || nn > hn)
		return 0;
	return kof_memmem(hay, hn, needle, nn) != NULL;
}

static int find_wide(const unsigned char *hay, size_t hn, const char *needle,
		     size_t nn)
{
	unsigned char w[512];
	size_t i;

	if (!nn || nn * 2u > sizeof w)
		return 0;
	/* UTF-16LE of an ASCII string, which is what a Windows binary holds and
	 * what KOF_DEFINE_STR_WIDE compiles to. A non-ASCII candidate is not
	 * widened rather than being widened wrongly: a wrong encoding here
	 * reports ABSENT for a string that is present, which is worse than
	 * saying nothing. */
	for (i = 0; i < nn; i++) {
		if ((unsigned char)needle[i] >= 0x80u)
			return 0;
		w[2u * i]      = (unsigned char)needle[i];
		w[2u * i + 1u] = 0;
	}
	return find_bytes(hay, hn, (const char *)w, nn * 2u);
}

static const char *last_sep(const char *s)
{
	const char *b = s, *p;

	for (p = s; *p; p++)
		if (*p == '\\' || *p == '/')
			b = p + 1;
	return b;
}

/*
 * Takes the fingerprint non-const because it sets KOF_FP_F_WIDE: the encoding
 * is discovered by the same search that decides how much matched, and a second
 * pass to find it again would be the same work with a chance of disagreeing.
 */
static uint8_t verify_one(const unsigned char *hay, size_t hn,
			  struct kof_fingerprint *f)
{
	const char *t = f->text;
	size_t      n;

	if (!hay || !hn || !t || !*t)
		return KOF_FP_SEEN_UNASKED;

	/*
	 * SOME KINDS HAVE NOTHING TO LOOK FOR, and saying "absent" about them
	 * would be a false negative with a confident face. A peer is an address
	 * the sample almost certainly holds in a different form - packed in
	 * four bytes, or assembled from a configuration - and an unbacked
	 * thread has no string at all.
	 */
	if (f->kind == KOF_FP_PEER || f->kind == KOF_FP_UNBACKED)
		return KOF_FP_SEEN_UNASKED;

	n = strlen(t);
	if (n > 400u)
		n = 400u;      /* a command line or a script line; the head of
				* it is what a literal in the binary would be */

	if (find_bytes(hay, hn, t, n))
		return KOF_FP_SEEN_PRESENT;
	if (find_wide(hay, hn, t, n)) {
		f->flags |= KOF_FP_F_WIDE;
		return KOF_FP_SEEN_WIDE;
	}

	/*
	 * THE BASENAME, which is the fragment that is actually there in the
	 * common case: a dropper holds "svc32.exe" and composes the directory
	 * from an API. Reported as a fragment rather than as present, because
	 * the difference decides what string goes in the signature.
	 */
	{
		const char *b = last_sep(t);
		size_t      bn = strlen(b);

		if (bn >= 4u && bn < n) {
			if (find_bytes(hay, hn, b, bn))
				return KOF_FP_SEEN_PART;
			if (find_wide(hay, hn, b, bn)) {
				f->flags |= KOF_FP_F_WIDE;
				return KOF_FP_SEEN_PART;
			}
		}
	}

	/* And the normalised spelling, for a volatile fingerprint whose
	 * invariant part is the half worth a rule - "\AppData\Local\Temp\" on
	 * its own is frequently a literal in the binary. */
	if (f->norm && *f->norm) {
		const char *s = f->norm;
		size_t      sn = strlen(s);
		size_t      k;

		/* Up to the first wildcard: past it the text is this library's
		 * own punctuation and was never in anybody's binary. */
		for (k = 0; k < sn && s[k] != '*' && s[k] != '#'; k++)
			;
		if (k >= 6u) {
			if (find_bytes(hay, hn, s, k))
				return KOF_FP_SEEN_PART;
			if (find_wide(hay, hn, s, k)) {
				f->flags |= KOF_FP_F_WIDE;
				return KOF_FP_SEEN_PART;
			}
		}
	}

	return KOF_FP_SEEN_ABSENT;
}

/* ---- the phase ----------------------------------------------------------- */

static uint64_t cap_or(uint64_t v, uint64_t dflt)
{
	return v ? v : dflt;
}

/*
 * COPY ONE FILE INTO THE CASE DIRECTORY, NAMED BY ITS DIGEST.
 *
 * Content addressed, and that is three decisions at once:
 *
 *   - Two paths holding the same bytes are collected once.
 *   - A filename chosen by the sample never decides a filename on the
 *     analyst's disk. A dropper that writes "..\..\autorun.inf" or a name full
 *     of control characters cannot reach out of the directory, because its
 *     name is not used.
 *   - The stored name is the same string the `Test sample:` line of a
 *     signature source carries and the same one kofviewer opens files by, so
 *     an artefact collected here is already named the way the next tool wants
 *     it.
 */
static int collect_file(struct kof_report *r, const struct kof_report_stage *st,
			struct kof_fingerprint *f, const char *dir,
			uint64_t max_file)
{
	char     store[512], rel[96];
	uint64_t size = 0;
	FILE    *in, *out;
	unsigned char buf[32u * 1024u];
	int      rc = 0;

	if (kof_sha256_file(f->text, f->bytes.file_sha256, &size) != 0) {
		/* The one place the two outcomes are told apart by errno,
		 * because fopen is what failed inside. */
		f->bytes.why_not = (errno == ENOENT) ? KOF_FP_WHY_GONE
						     : KOF_FP_WHY_DENIED;
		f->bytes.file_sha256[0] = '\0';
		return -1;
	}
	f->bytes.file_size = size;
	f->bytes.got       = size;
	f->bytes.claimed   = size;
	f->bytes.at_finish = 1;
	f->bytes.why_not   = KOF_FP_WHY_OK;

	/* The preview comes from the head of the file whether or not it is
	 * copied, because it is what makes a line in the report recognisable -
	 * "MZ" or "#!/bin/sh" or "{" is most of what a reader needs. */
	{
		uint8_t why = KOF_FP_WHY_OK;
		unsigned char head[KOF_FP_PREVIEW];
		uint64_t got = read_range(f->text, 0, sizeof head, head, &why);

		if (got)
			set_preview(&f->bytes, head, got);
	}

	if (!st->collect || !dir || !*dir)
		return 0;
	if (size > max_file) {
		f->bytes.why_not = KOF_FP_WHY_TOO_BIG;
		return 0;
	}

	snprintf(rel, sizeof rel, "files/%s", f->bytes.file_sha256);
	joinp(store, sizeof store, dir, rel);

	/*
	 * ALREADY THERE IS A SUCCESS, not a collision. Content addressing
	 * means the file on disk with that name holds exactly these bytes -
	 * the digest says so - so a second path with the same content is
	 * recorded as stored and nothing is written twice.
	 */
	{
		struct stat sb;

		if (kof_lstat(store, &sb) == 0) {
			snprintf(f->bytes.stored, sizeof f->bytes.stored,
				 "%s", rel);
			return 0;
		}
	}

	in = fopen(f->text, "rb");
	if (!in) {
		f->bytes.why_not = KOF_FP_WHY_DENIED;
		return -1;
	}
	out = fopen(store, "wb");
	if (!out) {
		fclose(in);
		f->bytes.why_not = KOF_FP_WHY_DENIED;
		return -1;
	}
	for (;;) {
		size_t got = fread(buf, 1, sizeof buf, in);

		if (got && fwrite(buf, 1, got, out) != got) {
			rc = -1;
			break;
		}
		if (got < sizeof buf) {
			if (ferror(in))
				rc = -1;
			break;
		}
	}
	fclose(in);
	if (fclose(out) != 0)
		rc = -1;

	if (rc) {
		/* A partial copy is worse than none: it is a file named by a
		 * digest it does not have, which is the one thing content
		 * addressing must never allow. */
		remove(store);
		f->bytes.why_not = KOF_FP_WHY_DENIED;
		return -1;
	}

	snprintf(f->bytes.stored, sizeof f->bytes.stored, "%s", rel);
	r->collected++;
	return 0;
}

/*
 * READ BACK WHAT WAS WRITTEN INTO A FILE THAT ALREADY EXISTED.
 *
 * The range, never the file: the file is somebody else's - hosts, an existing
 * binary, a browser profile - and its own digest would be a fact about it
 * rather than about the sample. What the sample did is the range.
 *
 * The bytes go into the case directory as evidence/<n>-<name>.bin when there
 * are enough of them to be worth a file, and a preview goes in the report
 * either way. And the caveat travels with them: `at_finish` is set, because
 * these are the bytes that were there when the run ended and no event says
 * they are the bytes the write put there.
 */
static void read_written(struct kof_report *r, struct kof_fingerprint *f,
			 const char *dir, uint64_t *budget, uint32_t seq)
{
	enum { CHUNK = 64u * 1024u };
	unsigned char *buf;
	uint64_t want, got;
	uint8_t  why = KOF_FP_WHY_OK;

	f->bytes.at_finish = 1;

	want = f->bytes.claimed;
	if (!want) {
		/* A write event with no length, which the decoder reports when
		 * the payload had no IOSize. Nothing to read and nothing to
		 * claim. */
		f->bytes.why_not = KOF_FP_WHY_SHORT;
		return;
	}
	if (want > CHUNK)
		want = CHUNK;
	if (*budget == 0) {
		f->bytes.why_not = KOF_FP_WHY_BUDGET;
		return;
	}
	if (want > *budget)
		want = *budget;

	buf = (unsigned char *)malloc((size_t)want);
	if (!buf) {
		f->bytes.why_not = KOF_FP_WHY_DENIED;
		return;
	}

	got = read_range(f->text, f->bytes.offset, want, buf, &why);
	f->bytes.got     = got;
	f->bytes.why_not = why;
	if (got) {
		*budget -= got;
		r->evidence_bytes += got;
		set_preview(&f->bytes, buf, got);
		(void)kof_sha256_bytes(buf, got, f->bytes.sha256);

		if (dir && *dir && got >= 16u) {
			char rel[96], path[512];
			FILE *out;

			/*
			 * NUMBERED, not named after the file it came from.
			 * The sample chose that name; using it would let a
			 * path the sample controls decide a filename here.
			 * The report carries the mapping, which is where a
			 * reader looks anyway.
			 */
			snprintf(rel, sizeof rel, "evidence/%04u.bin",
				 (unsigned)seq);
			joinp(path, sizeof path, dir, rel);
			out = fopen(path, "wb");
			if (out) {
				if (fwrite(buf, 1, (size_t)got, out) == got)
					snprintf(f->bytes.stored,
						 sizeof f->bytes.stored, "%s",
						 rel);
				fclose(out);
			}
		}
	}
	free(buf);
}

int kof_report_finish(struct kof_report *r, const struct kof_report_stage *st)
{
	struct kof_report_stage none;
	const char *dir;
	uint64_t    max_file, budget;
	unsigned char *subject = NULL;
	size_t      subject_n = 0;
	uint32_t    i, seq = 0;
	int         looked = 0;

	if (!r)
		return KOF_ERR_ARG;
	if (!st) {
		memset(&none, 0, sizeof none);
		st = &none;
	}

	dir      = r->info.dir;
	max_file = cap_or(st->max_file_bytes, KOFREP_MAX_FILE);
	budget   = cap_or(st->max_evidence_bytes, KOFREP_MAX_EVIDENCE);

	r->finished   = 1;
	r->had_engine = (st->engine && st->engine->ask) ? 1 : 0;

	/*
	 * THE DIRECTORY IS MADE WHETHER OR NOT ANYTHING IS COLLECTED, because
	 * the report itself is written into it. Gating this on `collect` meant
	 * --no-collect produced a report with nowhere to go, and the failure
	 * appeared as three "cannot write" lines from the caller rather than
	 * as the missing mkdir it was.
	 *
	 * The subdirectories are only made when there is something to put in
	 * them: an empty files/ beside a report says a collection happened and
	 * found nothing, which is a different fact.
	 */
	if (dir && *dir) {
		if (kofrep_ensure_dir(dir) != 0)
			return KOF_ERR_OPEN;
		if (st->collect) {
			char sub[512];

			joinp(sub, sizeof sub, dir, "files");
			(void)kofrep_ensure_dir(sub);
			joinp(sub, sizeof sub, dir, "evidence");
			(void)kofrep_ensure_dir(sub);
		}
	}

	/*
	 * THE SUBJECT FIRST, because everything else is described relative to
	 * it and because its bytes are what the candidates are verified
	 * against.
	 */
	if (r->info.subject && *r->info.subject) {
		(void)kof_sha256_file(r->info.subject, r->subject_sha256,
				      &r->subject_size);
		ask_engine(st, r->info.subject, &r->subject_verdict);

		if (r->subject_size && r->subject_size <= max_file) {
			subject = (unsigned char *)malloc(
					(size_t)r->subject_size);
			if (subject) {
				uint8_t why = KOF_FP_WHY_OK;

				subject_n = (size_t)read_range(
					r->info.subject, 0, r->subject_size,
					subject, &why);
				if (!subject_n) {
					free(subject);
					subject = NULL;
				}
			}
		}
	}

	for (i = 0; i < r->n_fp; i++) {
		struct kof_fingerprint *f = &r->fp[i];

		switch (f->kind) {
		case KOF_FP_FILE_NEW:
			looked++;
			if (collect_file(r, st, f, dir, max_file) != 0)
				r->collect_failed++;
			else if (f->bytes.stored[0] || f->bytes.file_sha256[0])
				ask_engine(st, f->text, &f->verdict);
			break;

		case KOF_FP_FILE_WRITE:
			looked++;
			read_written(r, f, st->collect ? dir : NULL, &budget,
				     ++seq);
			break;

		default:
			/*
			 * NOTHING TO COLLECT AND NOTHING TO OPEN. A registry
			 * value, a peer, a name, a command line - the
			 * fingerprint IS the evidence, and there is no file
			 * behind it. Left at KOF_FP_WHY_NOT_ASKED, which reads
			 * correctly: nobody looked, because there was nowhere
			 * to look.
			 */
			break;
		}

		f->in_sample = subject ? verify_one(subject, subject_n, f)
				       : KOF_FP_SEEN_UNASKED;
	}

	free(subject);
	return looked;
}
