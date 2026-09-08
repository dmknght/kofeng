/*
 * kofevtlog.c - see kofevtlog.h.
 *
 * Two headers and nothing else: stdio and stdint, through kofevtlog.h. Not an
 * accident and not a minimalism exercise - it is what lets this file live under
 * libkofeng while libkofgrille includes it, without libkofgrille acquiring a
 * dependency on the engine. The moment something in here needs kofeng.h, this
 * directory has stopped being what it says it is.
 *
 * It is also what makes a Windows log replayable on a Linux CI, which is the
 * only way an event rule ever gets a regression test.
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "kofevtlog.h"

_Static_assert(sizeof(struct kofevt_log_hdr) == KOFEVT_LOG_HDR_SIZE,
	       "the log header is not KOFEVT_LOG_HDR_SIZE bytes");

/*
 * An upper bound on a record, so a wrong rec_size is refused rather than
 * turned into an allocation. Nothing this toolset records is anywhere near it;
 * the number exists so that a corrupt or hostile header cannot ask for a
 * gigabyte per record.
 */
#define KOFEVT_REC_MAX 65536u

struct kofevt_log_w {
	FILE    *fp;
	uint64_t n;
	uint32_t rec_size;
	int      failed;
};

struct kofevt_log_r {
	FILE                   *fp;
	struct kofevt_log_hdr   h;
};

/* ---------------------------------------------------------------- writing */

struct kofevt_log_w *kofevt_log_create(const char *path,
				       const struct kofevt_log_info *info)
{
	struct kofevt_log_w *w;
	struct kofevt_log_hdr hdr;

	if (!path || !*path || !info)
		return NULL;
	/* Refused here because it cannot be recovered from later: every record
	 * in a fixed-record file is found by multiplying by this number. */
	if (info->rec_size == 0u || info->rec_size > KOFEVT_REC_MAX)
		return NULL;

	w = calloc(1, sizeof *w);
	if (!w)
		return NULL;

	w->fp = fopen(path, "wb");
	if (!w->fp) {
		free(w);
		return NULL;
	}
	w->rec_size = info->rec_size;

	memset(&hdr, 0, sizeof hdr);
	hdr.magic       = KOFEVT_LOG_MAGIC;
	hdr.version     = KOFEVT_LOG_VERSION;
	hdr.hdr_size    = (uint16_t)sizeof hdr;
	hdr.rec_size    = info->rec_size;
	hdr.rec_kind    = (uint16_t)info->rec_kind;
	hdr.build       = info->build;
	/* Zero means "this host", which is what a collector wants and is one
	 * less thing for each of them to get right. */
	hdr.platform    = info->platform ? info->platform : kof_platform_self();
	hdr.arch        = info->arch     ? info->arch     : kof_arch_self();
	hdr.root_pid    = info->root_pid;
	hdr.started     = info->started;
	/*
	 * WHAT WAS ASKED FOR AND WHAT WAS RUNNING.
	 *
	 * A log where a provider refused is a different artefact from one where
	 * the machine did none of that thing, and no sequence of records can
	 * tell those apart - the difference is entirely in what was never
	 * collected. Somebody opening this file a month later has no other way
	 * to know.
	 */
	hdr.sub_asked   = info->sub_asked;
	hdr.sub_enabled = info->sub_enabled;

	if (fwrite(&hdr, sizeof hdr, 1, w->fp) != 1) {
		fclose(w->fp);
		free(w);
		return NULL;
	}
	return w;
}

int kofevt_log_write(struct kofevt_log_w *w, const void *rec)
{
	if (!w || !rec)
		return -1;
	/*
	 * Once a write has failed the file is a fixed-record file with a short
	 * record in it, and every record after that one would be read at the
	 * wrong offset. Stopping is the only thing that keeps the part already
	 * written readable.
	 */
	if (w->failed)
		return -1;

	if (fwrite(rec, w->rec_size, 1, w->fp) != 1) {
		w->failed = 1;
		return -1;
	}
	w->n++;
	return 0;
}

uint64_t kofevt_log_close(struct kofevt_log_w *w)
{
	uint64_t n;

	if (!w)
		return 0;
	n = w->n;

	/*
	 * The count goes in last, by seeking back. A file killed before this
	 * ran has zero there, and a reader treats zero as "count them yourself"
	 * rather than as "empty".
	 */
	if (!w->failed &&
	    fseek(w->fp, (long)offsetof(struct kofevt_log_hdr, n_records),
		  SEEK_SET) == 0)
		(void)fwrite(&n, sizeof n, 1, w->fp);

	fclose(w->fp);
	free(w);
	return n;
}

/* ---------------------------------------------------------------- reading */

struct kofevt_log_r *kofevt_log_open(const char *path, uint32_t want_rec_size,
				     uint32_t want_rec_kind, const char **why)
{
	struct kofevt_log_r *r;

	if (why)
		*why = "";
	if (!path || !*path) {
		if (why) *why = "no path";
		return NULL;
	}

	r = calloc(1, sizeof *r);
	if (!r)
		return NULL;

	r->fp = fopen(path, "rb");
	if (!r->fp) {
		if (why) *why = "cannot open";
		free(r);
		return NULL;
	}

	if (fread(&r->h, sizeof r->h, 1, r->fp) != 1) {
		if (why) *why = "shorter than a header";
		goto bad;
	}
	if (r->h.magic != KOFEVT_LOG_MAGIC) {
		if (why) *why = "not a kofevt log";
		goto bad;
	}
	if (r->h.version != KOFEVT_LOG_VERSION) {
		if (why) *why = "a log version this build does not know";
		goto bad;
	}
	if (r->h.rec_size == 0u || r->h.rec_size > KOFEVT_REC_MAX) {
		if (why) *why = "an impossible record size";
		goto bad;
	}
	/*
	 * THE CHECK THE WHOLE FORMAT EXISTS FOR, and it is two checks because
	 * size is not identity.
	 *
	 * A record that grew decodes every field from the wrong offset. A
	 * record of the same size from a DIFFERENT collector decodes every
	 * field from the right offset and means something else entirely. Both
	 * produce a log that is completely plausible and completely wrong, and
	 * nothing downstream can notice either - so both are refused here.
	 *
	 * want_rec_kind KOFEVT_REC_NONE opts out, for a tool that only reports
	 * what a file claims to be and never decodes a record.
	 */
	if (want_rec_size && r->h.rec_size != want_rec_size) {
		if (why) *why = "written by a build whose record is a "
				"different size";
		goto bad;
	}
	if (want_rec_kind != KOFEVT_REC_NONE &&
	    r->h.rec_kind != want_rec_kind) {
		if (why) *why = "written by a different collector";
		goto bad;
	}
	/* Written by a build with a bigger header: skip to where its records
	 * actually start rather than to where ours would. */
	if (r->h.hdr_size > sizeof r->h &&
	    fseek(r->fp, (long)r->h.hdr_size, SEEK_SET) != 0) {
		if (why) *why = "cannot seek past the header";
		goto bad;
	}
	return r;

bad:
	fclose(r->fp);
	free(r);
	return NULL;
}

const struct kofevt_log_hdr *kofevt_log_header(const struct kofevt_log_r *r)
{
	return r ? &r->h : NULL;
}

int kofevt_log_read(struct kofevt_log_r *r, void *out)
{
	if (!r || !out)
		return 0;
	/* A short read is the end - see the note in kofevtlog.h. */
	return fread(out, r->h.rec_size, 1, r->fp) == 1;
}

void kofevt_log_free(struct kofevt_log_r *r)
{
	if (!r)
		return;
	fclose(r->fp);
	free(r);
}
