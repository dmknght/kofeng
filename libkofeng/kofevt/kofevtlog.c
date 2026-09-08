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

/* The largest fixed part a record may declare; skip_one reads one onto the
 * stack. */
#define KOFEVT_HEAD_MAX 1024u

struct kofevt_log_w {
	FILE    *fp;
	uint64_t n;
	uint32_t rec_size;
	uint16_t head_size, len_off;
	int      failed;
};

struct kofevt_log_r {
	FILE                   *fp;
	struct kofevt_log_hdr   h;

	/* One offset per KOFEVT_LOG_STRIDE records - see kofevt_log_seek for
	 * why it is sparse rather than complete. Built on first use. */
	long                   *ckpt;
	uint64_t                n_ckpt, cap_ckpt;
	uint64_t                n_records;   /* what the index counted */
	int                     indexed;
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
	/*
	 * The shape has to be inside the record and the length has to be
	 * inside the head. Refused here because every record in the file is
	 * found by trusting these three numbers, and a file written with a
	 * wrong one is not recoverable afterwards.
	 */
	if (info->head_size == 0u || info->head_size > info->rec_size ||
	    (uint32_t)info->len_off + 2u > info->head_size)
		return NULL;

	w = calloc(1, sizeof *w);
	if (!w)
		return NULL;

	w->fp = fopen(path, "wb");
	if (!w->fp) {
		free(w);
		return NULL;
	}
	w->rec_size  = info->rec_size;
	w->head_size = info->head_size;
	w->len_off   = info->len_off;

	memset(&hdr, 0, sizeof hdr);
	hdr.magic       = KOFEVT_LOG_MAGIC;
	hdr.version     = KOFEVT_LOG_VERSION;
	hdr.hdr_size    = (uint16_t)sizeof hdr;
	hdr.rec_size    = info->rec_size;
	hdr.head_size   = info->head_size;
	hdr.len_off     = info->len_off;
	hdr.rec_kind    = (uint16_t)info->rec_kind;
	hdr.build       = info->build;
	/* Zero means "this host", which is what a collector wants and is one
	 * less thing for each of them to get right. */
	hdr.platform    = info->platform ? info->platform : kof_evt_platform_self();
	hdr.arch        = info->arch     ? info->arch     : kof_evt_arch_self();
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

	{
		const unsigned char *p = rec;
		uint16_t tl;

		/* Read the record's own length field rather than being told
		 * it: one number, in one place, and the writer cannot disagree
		 * with the record it is writing. */
		memcpy(&tl, p + w->len_off, sizeof tl);
		if ((uint32_t)w->head_size + tl > w->rec_size) {
			w->failed = 1;
			return -1;
		}

		if (fwrite(p, w->head_size, 1, w->fp) != 1) {
			w->failed = 1;
			return -1;
		}
		if (tl && fwrite(p + w->head_size, tl, 1, w->fp) != 1) {
			w->failed = 1;
			return -1;
		}
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
	if (r->h.head_size == 0u || r->h.head_size > KOFEVT_HEAD_MAX ||
	    r->h.head_size > r->h.rec_size ||
	    (uint32_t)r->h.len_off + 2u > r->h.head_size) {
		if (why) *why = "an impossible record shape";
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

/*
 * Step over one record without reading its text.
 *
 * The text is what a log is mostly made of, so counting and indexing seek past
 * it rather than copying it - that is the difference between opening a large
 * log and loading one.
 *
 * Returns 0 at the end or on a record that contradicts itself.
 */
static int skip_one(struct kofevt_log_r *r)
{
	/* Generous rather than tight: a record's fixed part is around a
	 * hundred bytes today and the bound only has to be larger than any
	 * head a producer will declare. Too small was a silent zero from
	 * skip_one, which made every seek fail and every count come back 0 -
	 * caught by the test that seeks to record 42. */
	unsigned char head[KOFEVT_HEAD_MAX];
	uint16_t tl;

	if (r->h.head_size > sizeof head)
		return 0;
	if (fread(head, r->h.head_size, 1, r->fp) != 1)
		return 0;

	memcpy(&tl, head + r->h.len_off, sizeof tl);
	if ((uint32_t)r->h.head_size + tl > r->h.rec_size)
		return 0;
	if (tl && fseek(r->fp, (long)tl, SEEK_CUR) != 0)
		return 0;
	return 1;
}

static int build_index(struct kofevt_log_r *r)
{
	uint64_t n = 0;

	if (r->indexed)
		return 1;
	if (fseek(r->fp, (long)r->h.hdr_size, SEEK_SET) != 0)
		return 0;

	for (;;) {
		if (n % KOFEVT_LOG_STRIDE == 0) {
			long at = ftell(r->fp);

			if (at < 0)
				return 0;
			if (r->n_ckpt == r->cap_ckpt) {
				uint64_t nc = r->cap_ckpt ? r->cap_ckpt * 2u
							  : 64u;
				long *nv = realloc(r->ckpt,
						   (size_t)nc * sizeof *nv);
				if (!nv)
					return 0;
				r->ckpt = nv;
				r->cap_ckpt = nc;
			}
			r->ckpt[r->n_ckpt++] = at;
		}
		if (!skip_one(r))
			break;
		n++;
	}

	r->n_records = n;
	r->indexed   = 1;
	return 1;
}

uint64_t kofevt_log_count(struct kofevt_log_r *r)
{
	long save;

	if (!r)
		return 0;
	/* The writer's own count when it closed cleanly. Zero means it did
	 * not, and then the only honest answer is to walk. */
	if (r->h.n_records)
		return r->h.n_records;
	if (r->indexed)
		return r->n_records;

	save = ftell(r->fp);
	if (!build_index(r))
		return 0;
	if (save >= 0)
		(void)fseek(r->fp, save, SEEK_SET);
	return r->n_records;
}

int kofevt_log_seek(struct kofevt_log_r *r, uint64_t n)
{
	uint64_t c, i;

	if (!r)
		return 0;
	if (!build_index(r))
		return 0;
	if (n >= r->n_records)
		return 0;

	c = n / KOFEVT_LOG_STRIDE;
	if (c >= r->n_ckpt)
		return 0;
	if (fseek(r->fp, r->ckpt[c], SEEK_SET) != 0)
		return 0;

	/* At most KOFEVT_LOG_STRIDE - 1 of these, and each is a head read and
	 * a seek rather than a record copy. */
	for (i = c * KOFEVT_LOG_STRIDE; i < n; i++) {
		if (!skip_one(r))
			return 0;
	}
	return 1;
}

const struct kofevt_log_hdr *kofevt_log_header(const struct kofevt_log_r *r)
{
	return r ? &r->h : NULL;
}

int kofevt_log_read(struct kofevt_log_r *r, void *out)
{
	unsigned char *p = out;
	uint16_t tl;

	if (!r || !out)
		return 0;

	/*
	 * Head first, then exactly what its length field asks for.
	 *
	 * The rest of the caller's record is zeroed, so a reader never sees
	 * text left behind by the PREVIOUS record - which is the one way a
	 * variable-length format can hand back something that looks like a
	 * complete path and is two records spliced together.
	 */
	if (fread(p, r->h.head_size, 1, r->fp) != 1)
		return 0;                      /* the end, or a truncated tail */

	memcpy(&tl, p + r->h.len_off, sizeof tl);
	if ((uint32_t)r->h.head_size + tl > r->h.rec_size)
		return 0;                      /* the record contradicts itself */

	memset(p + r->h.head_size, 0, r->h.rec_size - r->h.head_size);
	if (tl && fread(p + r->h.head_size, tl, 1, r->fp) != 1)
		return 0;
	return 1;
}

void kofevt_log_free(struct kofevt_log_r *r)
{
	if (!r)
		return;
	free(r->ckpt);
	fclose(r->fp);
	free(r);
}
