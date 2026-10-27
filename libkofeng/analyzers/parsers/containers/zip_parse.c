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

#include <stddef.h>
#include "zip_parse.h"
#include "../../../kofcore/runlist.h"
#include "../../../kofcore/tabgrow.h"
#include "../../../kofcore/entryname.h"

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

		a = kof_lower_byte(a);
		b = kof_lower_byte(b);
		if (a != b)
			return 0;
	}
	return 1;
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
		if (kof_rd32_or0(f, at) != SIG_EOCD)
			continue;
		if (any == UINT64_MAX)
			any = at;
		if (at + EOCD_LEN + kof_rd16_or0(f, at + E_CMT_LEN) == f.n) {
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

	if (eocd < LOC64_LEN || kof_rd32_or0(s->f, loc) != SIG_LOC64)
		return;
	if (!kof_rd_u64(s->f, loc + Z_LOC_OFF, 0, &rec))
		return;
	if (kof_rd32_or0(s->f, rec) != SIG_EOCD64)
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

	if (!kof_in_range(f, lh, LOCAL_LEN) || kof_rd32_or0(f, lh) != SIG_LOCAL) {
		s->z->anomalies |= KOF_ZIP_ANOM_BAD_LOCAL;
		e->suspicious |= KOF_ZIP_ENT_NO_LOCAL;
		return 0;
	}
	nlen = kof_rd16_or0(f, lh + L_NAME_LEN);
	xlen = kof_rd16_or0(f, lh + L_EXTRA_LEN);
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
		    (kof_rd32_or0(f, data + e->csize) == SIG_DESCRIPTOR ? 4u : 0u),
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

KOF_RUNS_RESOLVER(zip, struct kof_zip_info, zip_cls_bit, KOF_SCAN_ZIP_UNCLAIMED)

/* ---- the parse ---------------------------------------------------------------- */

int kof_zip_sniff(kof_buf file)
{
	uint32_t sig;

	if (file.n < 4 || !kof_rd_u32(file, 0, 0, &sig))
		return 0;
	return sig == SIG_LOCAL || sig == SIG_EOCD || sig == SIG_EOCD64;
}

void kof_zip_release(struct kof_zip_info *z)
{
	kof_tab_free((void **)&z->run);
	kof_tab_free((void **)&z->entry);
	z->n_runs = 0;
	z->n_entries = 0;
	z->mem.held = 0;
	z->mem.rows = 0;
}

/*
 * The walk of the table a module reads (kof_zip_next): row `*cursor`, and the count of
 * calls the engine reads to know the table was used. Not const because of that count -
 * the view is the host's, and a module never reaches this function except through the
 * vtable slot that calls it.
 */
const void *kof_zip_row(void *view, uint32_t *cursor)
{
	struct kof_zip_info *z = (struct kof_zip_info *)view;

	if (!z)
		return NULL;
	z->mem.walked++;
	if (!z->valid || !z->entry || *cursor >= z->n_entries)
		return NULL;
	return &z->entry[(*cursor)++];
}

struct kof_view_mem *kof_zip_mem(void *view)
{
	return &((struct kof_zip_info *)view)->mem;
}

int kof_zip_parse(kof_buf file, struct kof_zip_info *z, struct kof_obj_ctx *ctx)
{
	struct zw s;
	uint64_t eocd, at, room, rows_limit;
	uint32_t i, cap_entry = 0;
	int full = 0;

	/*
	 * THE WHOLE VIEW IS CLEARED NOW, because it is small: the 600KB of arrays that
	 * made a header-only clear worth an assert (9.1us per object, 23% of a scan of
	 * one-entry zips) are tables the parse allocates, so there is nothing left to
	 * skip. What the previous parse of this view left behind is let go first; the
	 * caller's room is the one field that is read before the clear and put back
	 * after it.
	 */
	room = z->mem.room;
	kof_zip_release(z);
	memset(z, 0, sizeof *z);
	z->mem.room = room;
	z->version = KOF_ZIP_INFO_VERSION;

	if (!kof_zip_sniff(file))
		return 0;
	z->valid = 1;

	memset(&s, 0, sizeof s);
	s.f = file;
	s.z = z;
	/* What the FILE can make, and not what it says: a central record is at least
	 * KOF_ZIP_CENTRAL_MIN bytes and an entry makes at most KOF_ZIP_RUNS_PER_ENTRY runs. */
	kof_runs_init_dyn(&s.runs, &z->mem, KOF_ZIP_CLS_COUNT,
			  (uint64_t)KOF_ZIP_RUNS_PER_ENTRY *
			  (file.n / KOF_ZIP_CENTRAL_MIN + 1u) + 8u);

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
	z->declared_entries = kof_rd16_or0(file, eocd + E_N_TOTAL);
	z->cd_size = kof_rd32_or0(file, eocd + E_CD_SIZE);
	z->cd_off  = kof_rd32_or0(file, eocd + E_CD_OFF);
	z->comment_len = kof_rd16_or0(file, eocd + E_CMT_LEN);
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
		/*
		 * The end record must sit exactly where the directory ends, so the
		 * directory starts at eocd_off - cd_size. Both numbers come from the file
		 * (a zip64 field is 64 bits wide), so this is unsigned and checked: a size
		 * that cannot fit before the end record is a directory that does not fit in
		 * the file, which is REPORTED (CD_PAST_EOF) and not shifted to; a declared
		 * offset above INT64_MAX has no signed distance and is not shifted either.
		 * The signed sums this replaced overflowed (undefined) for a field of 2^62
		 * or more, and wrapped to a plausible offset for a size just under 2^64.
		 */
		uint64_t moved = 0;

		if (z->cd_size > z->eocd_off) {
			z->anomalies |= KOF_ZIP_ANOM_CD_PAST_EOF;
		} else {
			moved = z->eocd_off - z->cd_size;
			if (moved != z->cd_off && z->cd_off <= (uint64_t)INT64_MAX &&
			    kof_in_range(file, moved, 4) &&
			    kof_rd32_or0(file, moved) == SIG_CENTRAL) {
				z->base_delta = (int64_t)moved - (int64_t)z->cd_off;
				z->cd_off = moved;
				z->anomalies |= KOF_ZIP_ANOM_SFX;
			}
		}
	}

	/* KNOWN DEFECT WP2-D3 (2026-10-24, M) [sev M]: kof_zip_parse opens a zip whose directory offset is past EOF
	 * as NOTHING (anomaly bit only). Trigger: EOCD offset 0x7ffffff0, or entries that cycle. Effect: rc
	 * 1, broken 0. Reproducer: tests/unit/ctr_liars.c zip/offset, zip/cycle (row of WP2-D1). Fix: a
	 * sniffed archive with its directory past EOF sets KOF_BROKEN_DAMAGED. */
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
	/*
	 * HOW MANY RECORDS THE DIRECTORY CAN HOLD, from the bytes it has - not from what
	 * the end record says. Every record is at least CENTRAL_MIN bytes and the walk
	 * advances by at least that, so this is also the most iterations the loop can make.
	 * The table is sized to the claim when the claim is believable (the first growth is
	 * to the declared count, clipped to this) and grows past it when the directory holds
	 * more than it declared: a count the file chose never reaches the allocator whole.
	 */
	rows_limit = (file.n - z->cd_off) / KOF_ZIP_CENTRAL_MIN;
	if (z->declared_entries && z->declared_entries <= rows_limit) {
		void *t = z->entry;

		/* A pre-size, and only that: refused for room it is simply not made and the
		 * loop below grows row by row and keeps what fits. */
		if (kof_tab_grow(&z->mem, &t, &cap_entry, sizeof *z->entry,
				 z->declared_entries, rows_limit))
			z->entry = (struct kof_zip_entry *)t;
	}
	for (;;) {
		struct kof_zip_entry *e;
		uint32_t nlen, xlen, clen;

		if (!kof_in_range(file, at, CENTRAL_LEN) ||
		    kof_rd32_or0(file, at) != SIG_CENTRAL)
			break;

		/* One more row, or the walk stops HERE and says so: the records that follow
		 * are in the directory and not in the table. */
		if (z->n_entries >= cap_entry) {
			void *t = z->entry;

			if (!kof_tab_grow(&z->mem, &t, &cap_entry, sizeof *z->entry,
					  (uint64_t)z->n_entries + 1u, rows_limit)) {
				full = 1;
				break;
			}
			z->entry = (struct kof_zip_entry *)t;
		}
		e = &z->entry[z->n_entries];
		memset(e, 0, sizeof *e);

		e->flags  = kof_rd16_or0(file, at + C_FLAGS);
		e->method = kof_rd16_or0(file, at + C_METHOD);
		e->crc32  = kof_rd32_or0(file, at + C_CRC);
		e->csize  = kof_rd32_or0(file, at + C_CSIZE);
		e->usize  = kof_rd32_or0(file, at + C_USIZE);
		/* Shifted by the same amount the directory was: the two are stated
		 * in the same coordinates, so correcting one and not the other would
		 * place every entry's data by an offset nothing wrote. */
		{
			int64_t lo = (int64_t)kof_rd32_or0(file, at + C_LOCAL_OFF) +
				     z->base_delta;

			e->local_off = lo >= 0 ? (uint64_t)lo : UINT64_MAX;
		}
		nlen = kof_rd16_or0(file, at + C_NAME_LEN);
		xlen = kof_rd16_or0(file, at + C_EXTRA_LEN);
		clen = kof_rd16_or0(file, at + C_CMT_LEN);
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
		if (kof_name_escapes(file, e->name_off, nlen)) {
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
	if (full)
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
		/* KNOWN DEFECT WP2-D4 (2026-10-24, M) [sev M]: A STORED member claiming more bytes than the file
		 * holds becomes a child to EOF: the anomaly bit is set but not reported, and the extent is
		 * not ended at the next header. Trigger: member b (200 bytes) claims more. Effect: a 710 byte
		 * child holding the next member and the directory. Reproducer: tests/unit/ctr_liars.c
		 * zip/claimBoth (green until fixed). Fix: end the extent at the next local header or
		 * directory offset, mark the entry. */
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
	z->run = s.runs.v;
	z->n_runs = s.runs.n;
	z->mem.rows = z->n_entries;
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


	_Static_assert(sizeof n / sizeof n[0] == KOF_ZIP_ANOM_COUNT,
		       "anomaly name table and its count disagree");
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
