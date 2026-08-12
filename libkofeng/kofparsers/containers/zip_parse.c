/*
 * zip_parse.c - the zip container, APPNOTE.TXT.
 *
 * An archive that is read from the END. The central directory near the tail lists
 * every entry and where its local header is; the local headers near the front say
 * where the data is. Two descriptions of the same thing, which is the fact that
 * shapes this file, because they are allowed to disagree and a reader that trusts
 * the wrong one reads different bytes than the extractor will.
 *
 *
 * WHICH COPY IS BELIEVED, AND WHY IT MATTERS
 *
 * The central directory is authoritative for WHAT EXISTS: a real extractor walks
 * it, so an entry only in the local headers is one nothing will extract, and an
 * entry only in the central directory is one that will be attempted.
 *
 * The local header is authoritative for WHERE THE DATA IS. Both records carry their
 * own extra-field length, and nothing requires them to match - so data_off is
 * always resolved by reading the local header at the offset the central record
 * gives, never computed from the central record's own lengths. Getting that wrong
 * lands in the middle of an extra field on any archive built to make it, and the
 * result is a scan of the wrong bytes that looks entirely successful.
 *
 * Where the two names disagree, both are recorded and the archive is marked. That
 * disagreement has no innocent explanation: it is how one archive is made to show
 * one name to a listing tool and extract another.
 *
 *
 * WHAT IS FREE HERE, AND IT IS MOST OF THE ANSWER
 *
 * Nothing in this file decompresses anything, and on a document that is not much of
 * a limitation. Measured over 8 OpenDocument files, images are 97.4% of the bytes
 * and every one of them is STORED - so the bulk of a document is already searchable
 * where it lies, and only the 2.5% that is XML costs anything to open. The regions
 * are built so a module can say which of the two it wants.
 *
 *
 * WHAT BOUNDS THE WALK
 *
 * The central directory is a list with a declared count, so unlike a compound file
 * nothing here loops by construction. What it can do is declare more entries than
 * it holds, hold more than it declares, or point every entry at the same bytes -
 * so the count is bounded, the walk stops at the first record that is not one, and
 * overlapping claims are settled rather than believed.
 */

#include "zip_parse.h"
#include "../runlist.h"

#include <string.h>

/* ---- the format ------------------------------------------------------------- */

#define SIG_LOCAL   0x04034b50u    /* PK\3\4 */
#define SIG_CENTRAL 0x02014b50u    /* PK\1\2 */
#define SIG_EOCD    0x06054b50u    /* PK\5\6 */
#define SIG_EOCD64  0x06064b50u    /* PK\6\6 */
#define SIG_LOC64   0x07064b50u    /* PK\6\7 */

#define LOCAL_LEN   30u
#define CENTRAL_LEN 46u
#define EOCD_LEN    22u
#define LOC64_LEN   20u

/* Central directory record. */
#define C_FLAGS     0x08u
#define C_METHOD    0x0au
#define C_CRC       0x10u
#define C_CSIZE     0x14u
#define C_USIZE     0x18u
#define C_NAME_LEN  0x1cu
#define C_EXTRA_LEN 0x1eu
#define C_CMT_LEN   0x20u
#define C_LOCAL_OFF 0x2au

/* Local file header. */
#define L_FLAGS     0x06u
#define L_METHOD    0x08u
#define L_NAME_LEN  0x1au
#define L_EXTRA_LEN 0x1cu

/* End of central directory. */
#define E_N_TOTAL   0x0au
#define E_CD_SIZE   0x0cu
#define E_CD_OFF    0x10u
#define E_CMT_LEN   0x14u

/* ZIP64 end record, and the locator that finds it. */
#define Z_N_TOTAL   0x20u
#define Z_CD_SIZE   0x28u
#define Z_CD_OFF    0x30u
#define Z_LOC_OFF   0x08u

#define U32_MAX_FIELD 0xffffffffu
#define U16_MAX_FIELD 0xffffu

/* The descriptor that follows an entry whose sizes were not known when it was
 * written: an optional signature, then CRC and the two sizes. */
#define SIG_DESCRIPTOR 0x08074b50u
#define DESC_LEN       12u

/* ---- the walk's own state ---------------------------------------------------- */

struct zw {
	kof_buf f;
	struct kof_zip_info *z;
	struct kof_runs runs;
};

static void add(struct zw *s, uint64_t off, uint64_t len, uint32_t cls)
{
	kof_runs_add(&s->runs, s->f.n, off, len, cls);
}

static uint32_t rd32(kof_buf f, uint64_t off)
{
	uint32_t v = 0;
	kof_rd_u32(f, off, 0, &v);
	return v;
}

static uint16_t rd16(kof_buf f, uint64_t off)
{
	uint16_t v = 0;
	kof_rd_u16(f, off, 0, &v);
	return v;
}

/* ---- names -------------------------------------------------------------------- */

/* Case insensitive over ASCII, which is all these comparisons need: every name this
 * matches against is a structural one defined by a packaging format. */
static int name_is(kof_buf f, uint64_t off, uint32_t len, const char *lit)
{
	uint32_t i;

	if (len != (uint32_t)strlen(lit) || !kof_in_range(f, off, len))
		return 0;
	for (i = 0; i < len; i++) {
		uint8_t a = f.p[off + i], b = (uint8_t)lit[i];

		if (a >= 'A' && a <= 'Z')
			a = (uint8_t)(a + 32);
		if (b >= 'A' && b <= 'Z')
			b = (uint8_t)(b + 32);
		if (a != b)
			return 0;
	}
	return 1;
}

/*
 * Does this name escape the directory it will be extracted into?
 *
 * Three ways, and all three are seen in the wild: an absolute path, a Windows drive
 * letter, and a ".." component. The last is checked as a COMPONENT rather than as a
 * substring, because a file honestly called "..config" contains ".." and escapes
 * nothing - matching the substring would make this fire on ordinary archives and
 * stop being read.
 *
 * Backslash counts as a separator as well as slash. The specification says names
 * use forward slashes, which is exactly why an attacker uses the other one: a
 * checker that only knows about "/" is bypassed by a name Windows still splits.
 */
static int name_escapes(kof_buf f, uint64_t off, uint32_t len)
{
	uint32_t i, start = 0;

	if (!len || !kof_in_range(f, off, len))
		return 0;
	if (f.p[off] == '/' || f.p[off] == '\\')
		return 1;
	if (len >= 2 && f.p[off + 1] == ':')
		return 1;

	for (i = 0; i <= len; i++) {
		int sep = (i == len) || f.p[off + i] == '/' || f.p[off + i] == '\\';

		if (!sep)
			continue;
		if (i - start == 2 && f.p[off + start] == '.' &&
		    f.p[off + start + 1] == '.')
			return 1;
		start = i + 1;
	}
	return 0;
}

/*
 * What kind of archive this is, from the names it holds.
 *
 * Order matters and is by how specific the marker is. An APK carries a JAR manifest
 * as well as an Android one, so Android is tested first; an OOXML document and an
 * ODF document have entirely different markers and cannot both match.
 *
 * `mimetype` alone is not enough for ODF - it is a name anything could use - so it
 * is only believed as the FIRST entry, which is what the OpenDocument specification
 * requires and what an ordinary zip tool does not produce by accident.
 */
static uint32_t kind_of(struct zw *s)
{
	const struct kof_zip_info *z = s->z;
	uint32_t i, jar = 0;

	for (i = 0; i < z->n_entries; i++) {
		uint64_t off = z->entry[i].name_off;
		uint32_t len = z->entry[i].name_len;

		if (name_is(s->f, off, len, "AndroidManifest.xml"))
			return KOF_ZIP_APK;
		if (name_is(s->f, off, len, "[Content_Types].xml"))
			return KOF_ZIP_OOXML;
		if (i == 0 && name_is(s->f, off, len, "mimetype"))
			return KOF_ZIP_ODF;
		if (name_is(s->f, off, len, "META-INF/MANIFEST.MF"))
			jar = 1;
	}
	return jar ? KOF_ZIP_JAR : KOF_ZIP_PLAIN;
}

/* ---- finding the end ---------------------------------------------------------- */

/*
 * The end-of-central-directory record.
 *
 * Searched backwards from the tail, because its own comment field can hold anything
 * including another copy of its signature - and an archive with a zip inside its
 * comment has several. The last one whose comment length reaches exactly the end of
 * the file is the real one; that check is what tells a record from a picture of one.
 *
 * If none is consistent, the last signature found is used anyway and the archive is
 * marked. Refusing at that point would throw away a truncated archive whose entries
 * are all still there and all still readable.
 */
static uint64_t find_eocd(kof_buf f)
{
	uint64_t span = f.n < KOF_ZIP_EOCD_SEARCH ? f.n : KOF_ZIP_EOCD_SEARCH;
	uint64_t start = f.n - span, at, best = UINT64_MAX, any = UINT64_MAX;

	if (f.n < EOCD_LEN)
		return UINT64_MAX;

	for (at = f.n - EOCD_LEN + 1; at-- > start; ) {
		if (rd32(f, at) != SIG_EOCD)
			continue;
		if (any == UINT64_MAX)
			any = at;
		if (at + EOCD_LEN + rd16(f, at + E_CMT_LEN) == f.n) {
			best = at;
			break;
		}
	}
	return best != UINT64_MAX ? best : any;
}

/*
 * The ZIP64 records, when a 32 bit field has run out of room.
 *
 * Only consulted when a field is saturated, because that is the only time the
 * specification says to: an archive carrying ZIP64 records it does not need is
 * ordinary, and reading them unconditionally would prefer them to the real values.
 */
static void read_zip64(struct zw *s, uint64_t eocd)
{
	struct kof_zip_info *z = s->z;
	uint64_t loc = eocd - LOC64_LEN, rec;

	if (eocd < LOC64_LEN || rd32(s->f, loc) != SIG_LOC64)
		return;
	if (!kof_rd_u64(s->f, loc + Z_LOC_OFF, 0, &rec))
		return;
	if (rd32(s->f, rec) != SIG_EOCD64)
		return;

	add(s, loc, LOC64_LEN, KOF_ZIP_CLS_HEADERS);
	add(s, rec, 56, KOF_ZIP_CLS_HEADERS);

	{
		uint64_t n = 0, size = 0, off = 0;

		if (kof_rd_u64(s->f, rec + Z_N_TOTAL, 0, &n) && n <= 0xffffffffu)
			z->declared_entries = (uint32_t)n;
		if (kof_rd_u64(s->f, rec + Z_CD_SIZE, 0, &size))
			z->cd_size = size;
		if (kof_rd_u64(s->f, rec + Z_CD_OFF, 0, &off))
			z->cd_off = off;
	}
}

/* ---- one entry ---------------------------------------------------------------- */

/*
 * Place an entry's data by reading its local header.
 *
 * Returns the offset of the first data byte, or 0 when the local header is not
 * where the central directory said. Zero is unambiguous: offset zero is where a
 * local header itself would be, so no entry's DATA can legitimately start there.
 */
static uint64_t place_entry(struct zw *s, struct kof_zip_entry *e)
{
	kof_buf f = s->f;
	uint64_t lh = e->local_off, name, data;
	uint32_t nlen, xlen;

	if (!kof_in_range(f, lh, LOCAL_LEN) || rd32(f, lh) != SIG_LOCAL) {
		s->z->anomalies |= KOF_ZIP_ANOM_BAD_LOCAL;
		e->suspicious |= KOF_ZIP_ENT_NO_LOCAL;
		return 0;
	}
	nlen = rd16(f, lh + L_NAME_LEN);
	xlen = rd16(f, lh + L_EXTRA_LEN);
	name = lh + LOCAL_LEN;
	data = name + nlen + xlen;

	/* The fixed part and the extra field are structure; the name between them is
	 * text somebody chose. Three claims rather than one, which is what keeps
	 * NAMES searchable on its own. */
	add(s, lh, LOCAL_LEN, KOF_ZIP_CLS_HEADERS);
	add(s, name, nlen, KOF_ZIP_CLS_NAMES);
	add(s, name + nlen, xlen, KOF_ZIP_CLS_HEADERS);

	/*
	 * The two copies of the name, compared.
	 *
	 * No innocent explanation exists for a difference: it is how one archive
	 * shows one name to a listing tool and extracts another.
	 */
	if (nlen != e->name_len ||
	    (nlen && kof_in_range(f, name, nlen) &&
	     kof_in_range(f, e->name_off, nlen) &&
	     memcmp(f.p + name, f.p + e->name_off, nlen) != 0))
		s->z->anomalies |= KOF_ZIP_ANOM_LOCAL_MISMATCH;

	/* Sizes written after the data rather than before it. The local header's
	 * copies are zero then, and the central directory's are the real ones -
	 * which is why they are never read from here. */
	if (e->flags & KOF_ZIP_F_DESCRIPTOR)
		add(s, data + e->csize, DESC_LEN +
		    (rd32(f, data + e->csize) == SIG_DESCRIPTOR ? 4u : 0u),
		    KOF_ZIP_CLS_HEADERS);

	return data;
}

/* ---- regions ------------------------------------------------------------------ */

static const uint32_t zip_cls_bit[KOF_ZIP_CLS_COUNT] = {
	KOF_SCAN_ZIP_HEADERS,
	KOF_SCAN_ZIP_NAMES,
	KOF_SCAN_ZIP_STORED,
	KOF_SCAN_ZIP_PACKED
};

static uint32_t zip_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				 struct kof_range *out, uint32_t max_out)
{
	const struct kof_zip_info *z = (const struct kof_zip_info *)ctx->file_header;

	if (!z || !z->valid || !out || max_out == 0)
		return 0;
	_Static_assert(sizeof z->run[0] == sizeof(struct kof_run),
		       "the view's run and runlist.h's have drifted apart");
	return kof_runs_resolve((const struct kof_run *)z->run, z->n_runs, mask,
				zip_cls_bit, KOF_SCAN_ZIP_UNCLAIMED,
				ctx->obj_size, out, max_out);
}

/* ---- the parse ---------------------------------------------------------------- */

int kof_zip_sniff(kof_buf file)
{
	uint32_t sig;

	if (file.n < 4 || !kof_rd_u32(file, 0, 0, &sig))
		return 0;
	return sig == SIG_LOCAL || sig == SIG_EOCD || sig == SIG_EOCD64;
}

int kof_zip_parse(kof_buf file, struct kof_zip_info *z, struct kof_obj_ctx *ctx)
{
	struct zw s;
	uint64_t eocd, at;
	uint32_t i;

	memset(z, 0, sizeof *z);
	z->version = KOF_ZIP_INFO_VERSION;

	if (!kof_zip_sniff(file))
		return 0;
	z->valid = 1;

	memset(&s, 0, sizeof s);
	s.f = file;
	s.z = z;
	kof_runs_init(&s.runs, (struct kof_run *)z->run, KOF_ZIP_MAX_EXTENTS,
		      KOF_ZIP_CLS_COUNT);

	eocd = find_eocd(file);
	if (eocd == UINT64_MAX) {
		/* No end record: the archive was cut, or only its front exists. The
		 * local headers are still there and still say what they hold, but
		 * nothing here walks them - what an extractor would do with this file
		 * is refuse it, and inventing a reading it will never get is worse
		 * than saying the structure is gone. */
		z->anomalies |= KOF_ZIP_ANOM_NO_EOCD;
		goto done;
	}

	z->eocd_off = eocd;
	z->declared_entries = rd16(file, eocd + E_N_TOTAL);
	z->cd_size = rd32(file, eocd + E_CD_SIZE);
	z->cd_off  = rd32(file, eocd + E_CD_OFF);
	z->comment_len = rd16(file, eocd + E_CMT_LEN);
	z->comment_off = eocd + EOCD_LEN;

	add(&s, eocd, EOCD_LEN, KOF_ZIP_CLS_HEADERS);
	add(&s, z->comment_off, z->comment_len, KOF_ZIP_CLS_NAMES);

	if (z->cd_off == U32_MAX_FIELD || z->cd_size == U32_MAX_FIELD ||
	    z->declared_entries == U16_MAX_FIELD)
		read_zip64(&s, eocd);

	/*
	 * Where the central directory REALLY is.
	 *
	 * Its declared offset is relative to the start of the ARCHIVE, which is not
	 * always the start of the file. A self-extracting archive has a stub in front
	 * of it, and an archive carved out of a larger file has been moved backwards;
	 * either way every offset in the file is out by the same amount, and every
	 * real extractor recovers it the same way - the end record must sit exactly
	 * where the directory ends, so the gap between them is the shift.
	 *
	 * Applied only when it lands on an actual central record. That check is what
	 * keeps this from being a way to aim the parse: a file that fakes the sizes to
	 * move the walk somewhere interesting produces no signature there and gets the
	 * declared offset, which is what it said in the first place.
	 *
	 * Found on a real file - a zip carved out of a document, whose every offset
	 * was 77 bytes too large. The parse read no entries at all and reported a
	 * short directory, while every extractor on the machine listed nine.
	 */
	{
		int64_t delta = (int64_t)z->eocd_off -
				(int64_t)(z->cd_off + z->cd_size);
		uint64_t moved = (uint64_t)((int64_t)z->cd_off + delta);

		if (delta != 0 && (int64_t)z->cd_off + delta >= 0 &&
		    kof_in_range(file, moved, 4) && rd32(file, moved) == SIG_CENTRAL) {
			z->base_delta = delta;
			z->cd_off = moved;
			z->anomalies |= KOF_ZIP_ANOM_SFX;
		}
	}

	if (z->cd_off >= file.n) {
		z->anomalies |= KOF_ZIP_ANOM_CD_PAST_EOF;
		goto done;
	}

	/*
	 * Walk the central directory.
	 *
	 * Stops at the first record that is not one rather than trying to resynchronise:
	 * the count is declared, so a short walk is already visible as CD_SHORT, and a
	 * resynchronising walk would invent entries out of whatever bytes followed.
	 */
	at = z->cd_off;
	for (i = 0; i < KOF_ZIP_MAX_ENTRIES; i++) {
		struct kof_zip_entry *e;
		uint32_t nlen, xlen, clen;

		if (!kof_in_range(file, at, CENTRAL_LEN) ||
		    rd32(file, at) != SIG_CENTRAL)
			break;

		e = &z->entry[z->n_entries];
		memset(e, 0, sizeof *e);

		e->flags  = rd16(file, at + C_FLAGS);
		e->method = rd16(file, at + C_METHOD);
		e->crc32  = rd32(file, at + C_CRC);
		e->csize  = rd32(file, at + C_CSIZE);
		e->usize  = rd32(file, at + C_USIZE);
		/* Shifted by the same amount the directory was: the two are stated
		 * in the same coordinates, so correcting one and not the other would
		 * place every entry's data by an offset nothing wrote. */
		{
			int64_t lo = (int64_t)rd32(file, at + C_LOCAL_OFF) +
				     z->base_delta;

			e->local_off = lo >= 0 ? (uint64_t)lo : UINT64_MAX;
		}
		nlen = rd16(file, at + C_NAME_LEN);
		xlen = rd16(file, at + C_EXTRA_LEN);
		clen = rd16(file, at + C_CMT_LEN);
		e->name_off = at + CENTRAL_LEN;
		e->name_len = nlen;

		add(&s, at, CENTRAL_LEN, KOF_ZIP_CLS_HEADERS);
		add(&s, e->name_off, nlen, KOF_ZIP_CLS_NAMES);
		add(&s, e->name_off + nlen, xlen + clen, KOF_ZIP_CLS_HEADERS);

		if (e->flags & KOF_ZIP_F_ENCRYPTED ||
		    e->method == KOF_ZIP_M_AES) {
			e->suspicious |= KOF_ZIP_ENT_ENCRYPTED;
			z->n_encrypted++;
			z->anomalies |= KOF_ZIP_ANOM_ENCRYPTED;
		}
		if (name_escapes(file, e->name_off, nlen)) {
			e->suspicious |= KOF_ZIP_ENT_TRAVERSAL;
			z->anomalies |= KOF_ZIP_ANOM_TRAVERSAL;
		}
		/* Declared, so it can be lied about - which is why it is a hint and
		 * never a bound. What it catches is what a bomb admits to. */
		if (e->csize && e->usize / e->csize >= KOF_ZIP_RATIO_ABSURD) {
			e->suspicious |= KOF_ZIP_ENT_RATIO;
			z->anomalies |= KOF_ZIP_ANOM_RATIO_ABSURD;
		}

		z->total_csize += e->csize;
		z->total_usize += e->usize;
		z->n_entries++;

		at = e->name_off + nlen + xlen + clen;
	}
	if (z->n_entries == KOF_ZIP_MAX_ENTRIES)
		z->anomalies |= KOF_ZIP_ANOM_ENTRIES_FULL;
	else if (z->n_entries < z->declared_entries)
		z->anomalies |= KOF_ZIP_ANOM_CD_SHORT;

	/*
	 * Place every entry's data, in a second pass.
	 *
	 * Second rather than folded into the first because the local headers are at
	 * the front of the file and the central directory is at the back: walking them
	 * together would read the file in two places at once, alternating, for no gain.
	 */
	for (i = 0; i < z->n_entries; i++) {
		struct kof_zip_entry *e = &z->entry[i];
		uint64_t data = place_entry(&s, e);

		if (!data)
			continue;
		e->data_off = data;
		if (!kof_in_range(file, data, e->csize))
			z->anomalies |= KOF_ZIP_ANOM_DATA_PAST_EOF;
		add(&s, data, e->csize,
		    e->method == KOF_ZIP_M_STORE && !(e->suspicious &
						      KOF_ZIP_ENT_ENCRYPTED)
		    ? KOF_ZIP_CLS_STORED : KOF_ZIP_CLS_PACKED);
	}

	z->kind = kind_of(&s);


done:
	kof_runs_settle(&s.runs, z->region_bytes);
	z->n_runs = s.runs.n;
	if (s.runs.full)
		z->anomalies |= KOF_ZIP_ANOM_EXTENTS_FULL;
	if (s.runs.clipped)
		z->anomalies |= KOF_ZIP_ANOM_DATA_PAST_EOF;
	if (s.runs.overlapped)
		z->anomalies |= KOF_ZIP_ANOM_OVERLAP;

	/*
	 * A document is its own format; everything else is an archive.
	 *
	 * The split decided earlier: a module written for documents must not be
	 * entered for an APK, and format is what the prefilter rules on. APK and JAR
	 * stay ZIP with a kind, because they differ from a plain archive in what their
	 * entries are called and not in anything a module would read differently.
	 */
	ctx->format = (z->kind == KOF_ZIP_OOXML || z->kind == KOF_ZIP_ODF)
		      ? KOF_FMT_DOCZIP : KOF_FMT_ZIP;
	ctx->obj_size = file.n;
	ctx->file_header = z;
	ctx->resolve_scan = zip_resolve_scan;
	return 1;
}

/* ---- names, for tools --------------------------------------------------------- */

#define ZIP_REGIONS(X)            \
	X(KOF_SCAN_ZIP_HEADERS)     \
	X(KOF_SCAN_ZIP_NAMES)       \
	X(KOF_SCAN_ZIP_STORED)      \
	X(KOF_SCAN_ZIP_PACKED)      \
	X(KOF_SCAN_ZIP_UNCLAIMED)

#define X_BIT(b)  (b),
#define X_CASE(b) case (b): return #b;

const uint32_t kof_zip_region_bits[] = { ZIP_REGIONS(X_BIT) };
_Static_assert(sizeof kof_zip_region_bits / sizeof kof_zip_region_bits[0] ==
	       KOF_ZIP_REGION_COUNT, "region list and its count disagree");

const char *kof_zip_region_name(uint32_t bit)
{
	switch (bit) {
	ZIP_REGIONS(X_CASE)
	default: return 0;
	}
}

#undef X_BIT
#undef X_CASE

const char *kof_zip_anomaly_name(unsigned index)
{
	static const char *const n[] = {
		"NO_EOCD", "CD_PAST_EOF", "CD_SHORT", "BAD_LOCAL",
		"LOCAL_MISMATCH", "DATA_PAST_EOF", "ENTRIES_FULL", "EXTENTS_FULL",
		"ENCRYPTED", "TRAVERSAL", "RATIO_ABSURD", "OVERLAP", "SFX",
		"UNSUPPORTED"
	};

	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}

const char *kof_zip_kind_name(uint32_t kind)
{
	switch (kind) {
	case KOF_ZIP_OOXML: return "OOXML";
	case KOF_ZIP_ODF:   return "ODF";
	case KOF_ZIP_APK:   return "APK";
	case KOF_ZIP_JAR:   return "JAR";
	default:            return "plain";
	}
}
