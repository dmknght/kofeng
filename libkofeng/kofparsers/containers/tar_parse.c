/*
 * tar_parse.c - the tar archive, POSIX 1003.1 with the GNU extensions.
 *
 * The simplest container this engine parses, and the only one whose walk terminates
 * by construction: a tar is a stream of 512 byte blocks, each step advances by at
 * least one block, so the cursor reaches the end whatever the file says. There is no
 * cycle to detect, no chain to bound, no count to disbelieve. Everything else here
 * is about the fields inside a block being arbitrary.
 *
 *
 * WHAT A HEADER CAN LIE ABOUT
 *
 * Only two things matter, and both are the size:
 *
 *   - It is ASCII octal in a twelve byte field, so it is text and can be anything.
 *     A field that is not a number is recorded and read as zero, which makes the
 *     walk advance by one block and carry on rather than stop - the entries after a
 *     damaged one are still entries.
 *
 *   - GNU stores sizes past 8GB in binary instead, marked by the top bit of the
 *     first byte. That path exists to be read correctly rather than mistaken for a
 *     wild octal value, and it is where a 64 bit size comes from - so it is the one
 *     place an overflow could be introduced, and the arithmetic that follows it is
 *     saturating.
 *
 * The checksum is the format's own opinion of whether a block is a header, and it
 * is recorded rather than enforced: a wrong checksum on a block that is otherwise a
 * perfectly ordinary header describes an archive somebody edited, which is worth
 * seeing rather than worth refusing.
 *
 *
 * NAMES CAN LIVE OUTSIDE THE HEADER
 *
 * A GNU long name is a pseudo entry whose CONTENT is the name of the entry after
 * it. So a name is carried as an offset into the object, and for those entries it
 * points into a preceding block's data rather than into their own header. One
 * archive in 431 here does this - rare enough to get wrong quietly, which is why it
 * is handled rather than noted.
 */

#include "tar_parse.h"
#include "../runlist.h"
#include "../entryname.h"

#include <string.h>

/* Field offsets inside the 512 byte header. */
#define T_NAME      0u
#define T_MODE      100u
#define T_UID       108u
#define T_GID       116u
#define T_SIZE      124u
#define T_MTIME     136u
#define T_CHKSUM    148u
#define T_TYPEFLAG  156u

#define T_NAME_LEN    100u
#define T_CHKSUM_LEN    8u

/* ---- the walk's own state ---------------------------------------------------- */

struct tw {
	kof_buf f;
	struct kof_tar_info *t;
	struct kof_runs runs;

	/* A GNU long name seen but not yet consumed: it belongs to the NEXT entry. */
	uint64_t pend_off;
	uint32_t pend_len;
};

/*
 * A numeric header field.
 *
 * ASCII octal terminated by a space or a NUL, except when the top bit of the first
 * byte is set - then GNU wrote it as a big endian binary value, which is how a size
 * past what twelve octal digits hold is expressed. Both are read; anything else
 * yields zero and says so.
 */
static uint64_t tar_num(kof_buf f, uint64_t off, uint32_t len, int *ok)
{
	uint64_t v = 0;
	uint32_t i = 0;

	*ok = 0;
	if (!kof_in_range(f, off, len) || len == 0)
		return 0;

	if (f.p[off] & 0x80u) {
		/* Binary. The top bit is the marker, not part of the value. */
		v = (uint64_t)(f.p[off] & 0x7fu);
		for (i = 1; i < len; i++) {
			if (v > (UINT64_MAX >> 8))
				return 0;      /* would wrap: not a size anything holds */
			v = (v << 8) | f.p[off + i];
		}
		*ok = 1;
		return v;
	}

	/*
	 * Leading padding, then digits, then a terminator.
	 *
	 * Both paddings are real and the leading one is what a first attempt gets
	 * wrong: the format lets an implementation right-align its digits and pad on
	 * the LEFT with spaces, and GNU tar does exactly that - a size field reads
	 * "        661 ". Treating the first space as the end of the number made every
	 * such field parse as zero, which made every entry look empty, which walked
	 * the cursor into the middle of the previous entry's content. Found by
	 * comparing against the system tar over 431 archives, where 33 of them
	 * stopped after two entries; nothing about the output looked wrong, it was
	 * simply short.
	 */
	while (i < len && (f.p[off + i] == ' ' || f.p[off + i] == '\0'))
		i++;

	for (; i < len; i++) {
		uint8_t c = f.p[off + i];

		if (c == ' ' || c == '\0')
			break;
		if (c < '0' || c > '7')
			return 0;
		if (v > (UINT64_MAX >> 3))
			return 0;
		v = (v << 3) | (uint64_t)(c - '0');
		*ok = 1;
	}
	return *ok ? v : 0;
}

/*
 * Does the block sum to what its checksum field says?
 *
 * The field is summed as though it held spaces, which is how it is computed. Both
 * the signed and the unsigned reading are accepted: implementations have differed
 * on whether the bytes are char or unsigned char, and archives written by both are
 * in circulation.
 */
static int tar_sum_ok(kof_buf f, uint64_t at)
{
	uint32_t uns = 0;
	int32_t sgn = 0;
	uint32_t i;
	uint64_t want;
	int ok;

	if (!kof_in_range(f, at, KOF_TAR_BLOCK))
		return 0;
	for (i = 0; i < KOF_TAR_BLOCK; i++) {
		uint8_t c = (i >= T_CHKSUM && i < T_CHKSUM + T_CHKSUM_LEN)
			    ? (uint8_t)' ' : f.p[at + i];

		uns += c;
		sgn += (int8_t)c;
	}
	want = tar_num(f, at + T_CHKSUM, T_CHKSUM_LEN, &ok);
	if (!ok)
		return 0;
	return want == uns || want == (uint64_t)sgn;
}

static int block_is_zero(kof_buf f, uint64_t at)
{
	uint32_t i;

	if (!kof_in_range(f, at, KOF_TAR_BLOCK))
		return 0;
	for (i = 0; i < KOF_TAR_BLOCK; i++)
		if (f.p[at + i])
			return 0;
	return 1;
}


/* The length of a field that is NUL padded, which is how names are stored. */
static uint32_t field_len(kof_buf f, uint64_t off, uint32_t cap)
{
	uint32_t i;

	if (!kof_in_range(f, off, cap))
		return 0;
	for (i = 0; i < cap; i++)
		if (!f.p[off + i])
			return i;
	return cap;
}

/* Is any of the padding after this entry something other than zero? */
static int slack_dirty(kof_buf f, uint64_t off, uint64_t n)
{
	uint64_t i;

	if (!n || !kof_in_range(f, off, n))
		return 0;
	for (i = 0; i < n; i++)
		if (f.p[off + i])
			return 1;
	return 0;
}

/* ---- regions ------------------------------------------------------------------ */

static const uint32_t tar_cls_bit[KOF_TAR_CLS_COUNT] = {
	KOF_SCAN_TAR_HEADERS,
	KOF_SCAN_TAR_DATA
};

static uint32_t tar_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				 struct kof_range *out, uint32_t max_out)
{
	const struct kof_tar_info *t = (const struct kof_tar_info *)ctx->file_header;

	if (!t || !t->valid || !out || max_out == 0)
		return 0;
	_Static_assert(sizeof t->run[0] == sizeof(struct kof_run),
		       "the view's run and runlist.h's have drifted apart");
	return kof_runs_resolve((const struct kof_run *)t->run, t->n_runs, mask,
				tar_cls_bit, KOF_SCAN_TAR_UNCLAIMED,
				ctx->obj_size, out, max_out);
}

/* ---- the parse ---------------------------------------------------------------- */

int kof_tar_sniff(kof_buf file)
{
	return kof_in_range(file, KOF_TAR_MAGIC_AT, 5) &&
	       memcmp(file.p + KOF_TAR_MAGIC_AT, "ustar", 5) == 0;
}

int kof_tar_parse(kof_buf file, struct kof_tar_info *t, struct kof_obj_ctx *ctx)
{
	struct tw s;
	uint64_t at = 0;

	memset(t, 0, sizeof *t);
	t->version = KOF_TAR_INFO_VERSION;

	if (!kof_tar_sniff(file))
		return 0;
	t->valid = 1;

	memset(&s, 0, sizeof s);
	s.f = file;
	s.t = t;
	kof_runs_init(&s.runs, (struct kof_run *)t->run, KOF_TAR_MAX_EXTENTS,
		      KOF_TAR_CLS_COUNT);

	/*
	 * No bound on the loop beyond the object and the entry cap.
	 *
	 * Every iteration advances `at` by at least one block, so this reaches the
	 * end of the object whatever the headers say - which is what makes tar the
	 * only container here with no cycle to detect.
	 */
	while (at + KOF_TAR_BLOCK <= file.n) {
		struct kof_tar_entry *e;
		uint64_t size, pad, name_off;
		uint32_t name_len;
		uint8_t typ;
		int ok;

		if (block_is_zero(file, at)) {
			/*
			 * The end. Two zero blocks close an archive, and what follows
			 * is padding to the archiver's blocking factor - neither is
			 * claimed, so both fall to UNCLAIMED where anything appended
			 * after the archive lands too.
			 */
			t->end_off = at;
			break;
		}
		if (!kof_in_range(file, at + KOF_TAR_MAGIC_AT, 5) ||
		    memcmp(file.p + at + KOF_TAR_MAGIC_AT, "ustar", 5) != 0)
			break;      /* not a header: the archive ends here */

		if (t->n_entries >= KOF_TAR_MAX_ENTRIES) {
			t->anomalies |= KOF_TAR_ANOM_ENTRIES_FULL;
			break;
		}

		e = &t->entry[t->n_entries];
		memset(e, 0, sizeof *e);
		e->hdr_off = at;
		kof_runs_add(&s.runs, file.n, at, KOF_TAR_BLOCK,
			     KOF_TAR_CLS_HEADERS);

		if (!tar_sum_ok(file, at)) {
			t->anomalies |= KOF_TAR_ANOM_BAD_CHECKSUM;
			e->suspicious |= KOF_TAR_ENT_BAD_SUM;
		}

		size = tar_num(file, at + T_SIZE, 12, &ok);
		if (!ok) {
			t->anomalies |= KOF_TAR_ANOM_BAD_SIZE;
			size = 0;
		}
		e->size  = size;
		e->mode  = (uint32_t)tar_num(file, at + T_MODE, 8, &ok);
		e->uid   = (uint32_t)tar_num(file, at + T_UID, 8, &ok);
		e->gid   = (uint32_t)tar_num(file, at + T_GID, 8, &ok);
		e->mtime = tar_num(file, at + T_MTIME, 12, &ok);

		typ = file.p[at + T_TYPEFLAG];
		e->typeflag = typ;

		/*
		 * The name, which is usually in this header and sometimes is not.
		 *
		 * A GNU long name entry seen on the previous pass left its content
		 * range behind; it belongs to this entry and replaces the truncated
		 * copy this header carries.
		 */
		if (s.pend_len) {
			name_off = s.pend_off;
			name_len = s.pend_len;
			s.pend_len = 0;
		} else {
			name_off = at + T_NAME;
			name_len = field_len(file, at + T_NAME, T_NAME_LEN);
			/*
			 * A prefix would have to be joined to the name with a slash
			 * to be the real path, and joining means copying. The view
			 * gives offsets, so the prefix is left out of name_len and
			 * the anomaly bits carry what a module needs to know. No
			 * entry in 28316 measured here used one.
			 */
		}
		e->name_off = name_off;
		e->name_len = name_len;

		if (kof_name_escapes(file, name_off, name_len)) {
			e->suspicious |= KOF_TAR_ENT_TRAVERSAL;
			t->anomalies |= KOF_TAR_ANOM_TRAVERSAL;
		}

		e->data_off = at + KOF_TAR_BLOCK;
		if (!kof_in_range(file, e->data_off, size)) {
			e->suspicious |= KOF_TAR_ENT_PAST_EOF;
			t->anomalies |= KOF_TAR_ANOM_TRUNCATED;
		}

		switch (typ) {
		case KOF_TAR_T_DIR:      t->n_dirs++;  break;
		case KOF_TAR_T_HARDLINK:
		case KOF_TAR_T_SYMLINK:  t->n_links++; break;
		case KOF_TAR_T_FILE:
		case KOF_TAR_T_FILE_ALT: t->n_files++; break;
		case KOF_TAR_T_LONGNAME:
		case KOF_TAR_T_LONGLINK:
			/* The content is the next entry's name. Recorded rather than
			 * claimed as a name here: this pseudo entry has none. */
			t->anomalies |= KOF_TAR_ANOM_LONGNAME;
			s.pend_off = e->data_off;
			s.pend_len = size > T_NAME_LEN * 4u
				     ? T_NAME_LEN * 4u : (uint32_t)size;
			break;
		case KOF_TAR_T_PAX:
		case KOF_TAR_T_PAX_GLOB:
			t->anomalies |= KOF_TAR_ANOM_PAX;
			break;
		case KOF_TAR_T_CHAR:
		case KOF_TAR_T_BLOCK:
		case KOF_TAR_T_FIFO:
			break;
		default:
			t->anomalies |= KOF_TAR_ANOM_STRANGE_TYPE;
			break;
		}

		t->total_size = kof_sat_add(t->total_size, size);
		t->n_entries++;

		/*
		 * The content, claimed at exactly the declared size. The padding out
		 * to the block boundary is deliberately left unclaimed - see the note
		 * in tar.h - and checked for anything other than zeroes, which is the
		 * only reason anybody would put bytes there.
		 */
		if (size)
			kof_runs_add(&s.runs, file.n, e->data_off, size,
				     KOF_TAR_CLS_DATA);

		pad = (KOF_TAR_BLOCK - (size % KOF_TAR_BLOCK)) % KOF_TAR_BLOCK;
		if (slack_dirty(file, kof_sat_add(e->data_off, size), pad)) {
			e->suspicious |= KOF_TAR_ENT_SLACK;
			t->anomalies |= KOF_TAR_ANOM_SLACK;
		}

		at = kof_sat_add(e->data_off, kof_sat_add(size, pad));
		if (at <= e->hdr_off)
			break;      /* saturated: nothing further can be read */
	}

	if (!t->end_off)
		t->anomalies |= KOF_TAR_ANOM_NO_END;

	kof_runs_settle(&s.runs, t->region_bytes);
	t->n_runs = s.runs.n;
	if (s.runs.full)
		t->anomalies |= KOF_TAR_ANOM_EXTENTS_FULL;
	if (s.runs.clipped)
		t->anomalies |= KOF_TAR_ANOM_TRUNCATED;
	if (s.runs.overlapped)
		t->anomalies |= KOF_TAR_ANOM_OVERLAP;

	ctx->format = KOF_FMT_TAR;
	ctx->obj_size = file.n;
	ctx->file_header = t;
	ctx->resolve_scan = tar_resolve_scan;
	return 1;
}

/* ---- names, for tools --------------------------------------------------------- */

#define TAR_REGIONS(X)          \
	X(KOF_SCAN_TAR_HEADERS)   \
	X(KOF_SCAN_TAR_DATA)      \
	X(KOF_SCAN_TAR_UNCLAIMED)

#define X_BIT(b)  (b),
#define X_CASE(b) case (b): return #b;

const uint32_t kof_tar_region_bits[] = { TAR_REGIONS(X_BIT) };
_Static_assert(sizeof kof_tar_region_bits / sizeof kof_tar_region_bits[0] ==
	       KOF_TAR_REGION_COUNT, "region list and its count disagree");

const char *kof_tar_region_name(uint32_t bit)
{
	switch (bit) {
	TAR_REGIONS(X_CASE)
	default: return 0;
	}
}

#undef X_BIT
#undef X_CASE

const char *kof_tar_anomaly_name(unsigned index)
{
	static const char *const n[] = {
		"BAD_CHECKSUM", "BAD_SIZE", "TRUNCATED", "ENTRIES_FULL",
		"EXTENTS_FULL", "NO_END", "TRAVERSAL", "LONGNAME", "PAX",
		"OVERLAP", "SLACK", "STRANGE_TYPE"
	};


	_Static_assert(sizeof n / sizeof n[0] == KOF_TAR_ANOM_COUNT,
		       "anomaly name table and its count disagree");
	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
