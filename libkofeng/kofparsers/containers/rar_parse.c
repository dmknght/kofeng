/*
 * rar_parse.c - walking a RAR3 block chain.
 *
 * The format is a linked list laid out flat: a seven byte header at the front of
 * every block says how long that block's header is and, for the blocks that carry
 * data, how much data follows it. Adding the two gives the next block. There is no
 * central directory to cross check against and no index - one pass forward is the
 * whole structure, which makes this the simplest container walk here and the one
 * with the least redundancy to catch a lie with.
 *
 *
 * WHAT STOPS A HOSTILE FILE
 *
 * The walk advances by HEAD_SIZE + data, and HEAD_SIZE is refused below seven. So
 * every iteration moves strictly forward by at least seven bytes and the loop
 * reaches the end of the object no matter what the headers say - the same property
 * tar has, and for the same reason there is no cycle detection here.
 *
 * The additions are the part that needs care rather than the loop. Sizes are 32 bit
 * fields, optionally paired with a second 32 bit half, and every one of them is
 * attacker controlled - so they are widened to 64 bits before anything is added to
 * an offset, and the result is checked against the object rather than assumed to
 * land inside it.
 */

#include <string.h>

#include "rar_parse.h"
#include "../runlist.h"
#include "../entryname.h"

/* ---- the block header, by offset from its own start --------------------------- */

#define B_CRC        0u
#define B_TYPE       2u
#define B_FLAGS      3u
#define B_SIZE       5u
#define B_BASE_LEN   7u

/* A file block, continuing past the seven byte base. */
#define F_PACK_SIZE  7u
#define F_UNP_SIZE  11u
#define F_HOST_OS   15u
#define F_CRC       16u
#define F_TIME      20u
#define F_UNP_VER   24u
#define F_METHOD    25u
#define F_NAME_LEN  26u
#define F_ATTR      28u
#define F_FIXED_LEN 32u          /* through ATTR, before the optional 64 bit halves */
#define F_HIGH_PACK 32u
#define F_HIGH_UNP  36u
#define F_HIGH_LEN   8u

#define RAR3_MAGIC_LEN 7u
#define RAR5_MAGIC_LEN 8u

/* ---- reads -------------------------------------------------------------------- */

static uint16_t rd16(kof_buf f, uint64_t off)
{
	uint16_t v = 0;

	kof_rd_u16(f, off, 0, &v);
	return v;
}

static uint32_t rd32(kof_buf f, uint64_t off)
{
	uint32_t v = 0;

	kof_rd_u32(f, off, 0, &v);
	return v;
}

/*
 * A RAR5 variable length integer.
 *
 * Seven bits a byte, low order first, the high bit saying another byte follows.
 * Ten bytes is the most that can carry sixty four bits, and refusing the eleventh
 * is what stops a run of 0x80 bytes from walking the object - the shape a hostile
 * archive would use, since every byte of it is a legal continuation.
 */
static uint64_t rd_vint(kof_buf f, uint64_t *at, int *ok)
{
	uint64_t v = 0;
	uint32_t i;

	*ok = 0;
	for (i = 0; i < 10u; i++) {
		uint8_t b = 0;

		if (!kof_rd_u8(f, *at, &b))
			return 0;
		(*at)++;
		v |= (uint64_t)(b & 0x7fu) << (i * 7u);
		if (!(b & 0x80u)) {
			*ok = 1;
			return v;
		}
	}
	return 0;
}

/* ---- the walk's own state ----------------------------------------------------- */

struct rw {
	kof_buf f;
	struct kof_rar_info *r;
	struct kof_runs runs;
};

/* ---- regions ------------------------------------------------------------------ */

static const uint32_t rar_cls_bit[KOF_RAR_CLS_COUNT] = {
	KOF_SCAN_RAR_HEADERS,
	KOF_SCAN_RAR_NAMES,
	KOF_SCAN_RAR_STORED,
	KOF_SCAN_RAR_PACKED
};

static uint32_t rar_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				 struct kof_range *out, uint32_t max_out)
{
	const struct kof_rar_info *r = (const struct kof_rar_info *)ctx->file_header;

	if (!r || !r->valid || !out || max_out == 0)
		return 0;
	_Static_assert(sizeof r->run[0] == sizeof(struct kof_run),
		       "the view's run and runlist.h's have drifted apart");
	return kof_runs_resolve((const struct kof_run *)r->run, r->n_runs, mask,
				rar_cls_bit, KOF_SCAN_RAR_UNCLAIMED,
				ctx->obj_size, out, max_out);
}

/*
 * The RAR5 block chain.
 *
 * Every block is a CRC, its own size, and then a header whose first two numbers say
 * what it is and what follows it. That self description is the whole reason this is
 * worth walking without a decoder: a block whose type this does not know is stepped
 * over exactly, rather than ending the walk, so the file headers after it are still
 * read - and file headers are where the names, the sizes and the stored entries are.
 *
 * What is NOT attempted is decompression. RAR5 entries are coded with a method this
 * build has no decoder for, so a compressed entry is claimed as PACKED and reported;
 * a STORED one is bytes in the clear and becomes a child like any other.
 */
static void rar5_walk(struct rw *s, kof_buf file)
{
	struct kof_rar_info *r = s->r;
	uint64_t at = RAR5_MAGIC_LEN;
	int saw_end = 0;

	kof_runs_add(&s->runs, file.n, 0, RAR5_MAGIC_LEN, KOF_RAR_CLS_HEADERS);

	while (at + 4u < file.n) {
		uint64_t hdr_start, hsize, htype, hflags, dsize = 0;
		uint64_t hdr_end, blk_end;
		int ok;

		at += 4u;                       /* the header's CRC32 */
		hsize = rd_vint(file, &at, &ok);
		if (!ok || hsize == 0) {
			r->anomalies |= KOF_RAR_ANOM_BAD_BLOCK;
			break;
		}
		hdr_start = at;
		/* The size counts from here, so where the header ends is known before
		 * a single field inside it is believed. */
		if (hsize > file.n - hdr_start) {
			r->anomalies |= KOF_RAR_ANOM_TRUNCATED;
			kof_runs_add(&s->runs, file.n, at, file.n - at,
				     KOF_RAR_CLS_HEADERS);
			break;
		}
		hdr_end = hdr_start + hsize;

		htype  = rd_vint(file, &at, &ok);
		if (!ok) break;
		hflags = rd_vint(file, &at, &ok);
		if (!ok) break;
		/* The extra area's size is read to step the cursor over the field,
		 * and then dropped: the area itself is inside hsize, so it needs no
		 * run of its own and bounds nothing. */
		if (hflags & KOF_RAR5_H_EXTRA) {
			rd_vint(file, &at, &ok);
			if (!ok) break;
		}
		if (hflags & KOF_RAR5_H_DATA) {
			dsize = rd_vint(file, &at, &ok);
			if (!ok) break;
		}

		/*
		 * An encryption header means every header AFTER it is ciphertext.
		 *
		 * Walking on reads noise as vints and claims whatever they say - on
		 * the first encrypted archive tried, 139MB of a 139MB file as
		 * "headers". The block itself is claimed and the walk stops, which
		 * is the honest answer: the structure is not readable from here.
		 */
		if (htype == KOF_RAR5_BLK_CRYPT) {
			r->anomalies |= KOF_RAR_ANOM_ENCRYPTED;
			r->n_encrypted++;
			kof_runs_add(&s->runs, file.n, hdr_start, hsize,
				     KOF_RAR_CLS_HEADERS);
			break;
		}

		if (htype == KOF_RAR5_BLK_FILE || htype == KOF_RAR5_BLK_SERVICE) {
			uint64_t fflags, usize, attr, comp, host, nlen, name_off;
			uint32_t method;

			fflags = rd_vint(file, &at, &ok); if (!ok) break;
			usize  = rd_vint(file, &at, &ok); if (!ok) break;
			attr   = rd_vint(file, &at, &ok); if (!ok) break;
			(void)attr;
			if (fflags & KOF_RAR5_F_TIME) at += 4u;
			if (fflags & KOF_RAR5_F_CRC)  at += 4u;
			comp = rd_vint(file, &at, &ok); if (!ok) break;
			host = rd_vint(file, &at, &ok); if (!ok) break;
			(void)host;
			nlen = rd_vint(file, &at, &ok); if (!ok) break;

			name_off = at;
			/* The name has to lie inside the header that declared it -
			 * the same rule the RAR3 walk applies, and for the same
			 * reason.
			 *
			 * name_off > hdr_end checked before the subtraction, not
			 * folded into it: every field above it is an attacker-chosen
			 * vint length advancing `at`, none of them checked against
			 * hdr_end as they're read, so name_off can already be past
			 * hdr_end here. hdr_end - name_off would then underflow to a
			 * huge value and let nlen > ... pass when the name has
			 * already run past its own header - kof_in_range still
			 * catches a read past the real file, but not a name that
			 * lands inside the FILE's data or the next block instead of
			 * its own header, which is what hdr_end was computed to
			 * bound in the first place. */
			if (name_off > hdr_end || nlen > hdr_end - name_off ||
			    !kof_in_range(file, name_off, nlen)) {
				r->anomalies |= KOF_RAR_ANOM_TRUNCATED;
				nlen = 0;
			}

			/*
			 * Bits 7..9 of the compression info are the method, and 0
			 * is stored. Translated onto RAR3's 0x30..0x35 so that
			 * every reader above - the module included - asks one
			 * question about method and not two.
			 */
			method = (uint32_t)(KOF_RAR_M_STORE +
					    ((comp >> 7) & 7u));

			if (r->n_entries < KOF_RAR_MAX_ENTRIES &&
			    htype == KOF_RAR5_BLK_FILE) {
				struct kof_rar_entry *e =
					&r->entry[r->n_entries++];

				memset(e, 0, sizeof *e);
				e->hdr_off  = hdr_start;
				e->csize    = dsize;
				e->usize    = (fflags & KOF_RAR5_F_UNKNOWN) ? 0
									   : usize;
				e->name_off = name_off;
				e->name_len = (uint32_t)nlen;
				e->method   = (uint8_t)method;
				e->flags    = (uint16_t)fflags;
				e->data_off = dsize ? hdr_end : 0;
				/*
				 * The low six bits of the compression info are
				 * the ALGORITHM version, not the format version:
				 * 0 is RAR 5.0 and 1 is the larger-dictionary
				 * scheme RAR 7 added. Recorded so a decoder can
				 * refuse one it was not written for, the same way
				 * unp_ver 20 is refused on the RAR3 side.
				 */
				e->unp_ver  = (uint8_t)(comp & 0x3fu);
				/*
				 * Bit 6 says this entry continues the window of
				 * the one before it. A solid entry decoded alone
				 * is right until its first back reference and
				 * silently wrong after, which is why it is marked
				 * here rather than discovered later.
				 */
				if (comp & 0x40u) {
					e->suspicious |= KOF_RAR_ENT_SOLID;
					r->anomalies |= KOF_RAR_ANOM_SOLID;
				}

				if (nlen &&
				    kof_name_escapes(file, name_off, (uint32_t)nlen)) {
					e->suspicious |= KOF_RAR_ENT_TRAVERSAL;
					r->anomalies |= KOF_RAR_ANOM_TRAVERSAL;
				}
				if (dsize &&
				    !kof_in_range(file, hdr_end, dsize)) {
					e->suspicious |= KOF_RAR_ENT_PAST_EOF;
					r->anomalies |= KOF_RAR_ANOM_TRUNCATED;
				}
			} else if (htype == KOF_RAR5_BLK_FILE) {
				r->anomalies |= KOF_RAR_ANOM_ENTRIES_FULL;
			}

			/* Header on either side of the name, so NAMES is a region
			 * with bytes in it rather than one the header swallowed. */
			if (nlen) {
				kof_runs_add(&s->runs, file.n, name_off, nlen,
					     KOF_RAR_CLS_NAMES);
				kof_runs_add(&s->runs, file.n, hdr_start,
					     name_off - hdr_start,
					     KOF_RAR_CLS_HEADERS);
				kof_runs_add(&s->runs, file.n, name_off + nlen,
					     hdr_end - (name_off + nlen),
					     KOF_RAR_CLS_HEADERS);
			} else {
				kof_runs_add(&s->runs, file.n, hdr_start, hsize,
					     KOF_RAR_CLS_HEADERS);
			}
		} else {
			kof_runs_add(&s->runs, file.n, hdr_start, hsize,
				     KOF_RAR_CLS_HEADERS);
		}

		if (htype == KOF_RAR5_BLK_END)
			saw_end = 1;

		/* The data area, classified by whether it can be read where it lies. */
		if (dsize) {
			uint64_t have = kof_clip_len(file.n, hdr_end, dsize);

			if (have) {
				uint32_t cls = KOF_RAR_CLS_PACKED;

				if (r->n_entries &&
				    r->entry[r->n_entries - 1u].data_off == hdr_end &&
				    r->entry[r->n_entries - 1u].method ==
					    KOF_RAR_M_STORE)
					cls = KOF_RAR_CLS_STORED;
				kof_runs_add(&s->runs, file.n, hdr_end, have, cls);
			}
			if (have != dsize)
				r->anomalies |= KOF_RAR_ANOM_TRUNCATED;
		}

		blk_end = kof_sat_add(hdr_end, dsize);
		if (blk_end <= at || blk_end > file.n) {
			if (blk_end > file.n)
				r->anomalies |= KOF_RAR_ANOM_TRUNCATED;
			else
				r->anomalies |= KOF_RAR_ANOM_BAD_BLOCK;
			break;
		}
		at = blk_end;
		if (saw_end)
			break;
	}

	if (!saw_end)
		r->anomalies |= KOF_RAR_ANOM_NO_END;
}

/* ---- the parse ---------------------------------------------------------------- */

int kof_rar_sniff(kof_buf file)
{
	if (!kof_in_range(file, 0, RAR3_MAGIC_LEN) ||
	    memcmp(file.p, "Rar!\x1a\x07", 6) != 0)
		return 0;
	if (file.p[6] == 0x00)
		return 1;
	/* RAR5 spends one more byte on its version, and it must be followed by a
	 * zero - the format reserves the pair. */
	return file.p[6] == 0x01 && kof_in_range(file, 7, 1) && file.p[7] == 0x00;
}

/*
 * One file block.
 *
 * `size` is the header length the block declared and has already been checked
 * against the object. On success *data is set to how many bytes of file content
 * follow the header - which is where the NEXT block begins, so getting it from here
 * rather than from the caller's copy is the whole reason this returns anything.
 *
 * Returns 0 when the header could not be read, and then *data is not written and
 * the walk must stop: the position of the next block is exactly what was unreadable,
 * so continuing would be guessing at an offset and calling whatever is there a
 * block.
 */
static int file_block(struct rw *s, uint64_t at, uint64_t size, uint16_t flags,
		      uint64_t *data)
{
	struct kof_rar_info *r = s->r;
	struct kof_rar_entry *e;
	uint64_t name_off, hdr_len, csize, usize;
	uint32_t name_len;

	if (!kof_in_range(s->f, at, F_FIXED_LEN) || size < F_FIXED_LEN) {
		r->anomalies |= KOF_RAR_ANOM_TRUNCATED;
		return 0;
	}

	csize = rd32(s->f, at + F_PACK_SIZE);
	usize = rd32(s->f, at + F_UNP_SIZE);
	hdr_len = F_FIXED_LEN;

	/*
	 * The 64 bit halves, when the flag says they are there.
	 *
	 * Both are the HIGH word of a value whose low word was read above, so they
	 * shift by 32 - and both come from the file, which is why the shift happens
	 * in 64 bits on a value already widened rather than on the 32 bit field.
	 */
	if (flags & KOF_RAR3_F_LARGE) {
		if (!kof_in_range(s->f, at + F_HIGH_PACK, F_HIGH_LEN) ||
		    size < F_HIGH_PACK + F_HIGH_LEN) {
			r->anomalies |= KOF_RAR_ANOM_TRUNCATED;
			return 0;
		}
		csize |= (uint64_t)rd32(s->f, at + F_HIGH_PACK) << 32;
		usize |= (uint64_t)rd32(s->f, at + F_HIGH_UNP) << 32;
		hdr_len += F_HIGH_LEN;
	}

	/*
	 * Where the next block starts is now known, and it is known whether or not
	 * this entry gets recorded - so it is published before the cap is tested.
	 * An archive past the cap keeps being WALKED, and its remaining data keeps
	 * being classified into regions; what it stops getting is entry rows.
	 */
	*data = csize;

	if (r->n_entries >= KOF_RAR_MAX_ENTRIES) {
		r->anomalies |= KOF_RAR_ANOM_ENTRIES_FULL;
		return 1;
	}

	name_len = rd16(s->f, at + F_NAME_LEN);
	name_off = at + hdr_len;

	/*
	 * The name has to fit in the header that declared it. A name running past
	 * the block's own end is either a truncated archive or a field built to make
	 * a reader walk off the end of it, and neither is worth reading a byte of.
	 */
	if (name_len > size - hdr_len || !kof_in_range(s->f, name_off, name_len)) {
		r->anomalies |= KOF_RAR_ANOM_TRUNCATED;
		name_len = 0;
	}

	e = &r->entry[r->n_entries++];
	memset(e, 0, sizeof *e);
	e->hdr_off  = at;
	e->csize    = csize;
	e->usize    = usize;
	e->name_off = name_off;
	e->name_len = name_len;
	e->crc32    = rd32(s->f, at + F_CRC);
	e->flags    = flags;
	e->method   = s->f.p[at + F_METHOD];
	e->unp_ver  = s->f.p[at + F_UNP_VER];
	e->data_off = csize ? at + size : 0;

	/* Name first, then the header on either side of it, so the two regions are
	 * disjoint and both are non-empty. */
	if (name_len) {
		kof_runs_add(&s->runs, s->f.n, name_off, name_len,
			     KOF_RAR_CLS_NAMES);
		kof_runs_add(&s->runs, s->f.n, at, name_off - at,
			     KOF_RAR_CLS_HEADERS);
		kof_runs_add(&s->runs, s->f.n, name_off + name_len,
			     (at + size) - (name_off + name_len),
			     KOF_RAR_CLS_HEADERS);
	} else {
		kof_runs_add(&s->runs, s->f.n, at, size, KOF_RAR_CLS_HEADERS);
	}
	if (name_len) {
		/*
		 * A name that escapes the directory it is extracted into. The
		 * check is shared with zip and tar because the attack is: the
		 * archive is not the malware, the extractor is the victim.
		 */
		if (kof_name_escapes(s->f, name_off, name_len)) {
			e->suspicious |= KOF_RAR_ENT_TRAVERSAL;
			r->anomalies |= KOF_RAR_ANOM_TRAVERSAL;
		}
	}

	if (flags & KOF_RAR3_F_ENCRYPTED) {
		e->suspicious |= KOF_RAR_ENT_ENCRYPTED;
		r->anomalies |= KOF_RAR_ANOM_ENCRYPTED;
		r->n_encrypted++;
	}
	if (flags & KOF_RAR3_F_SOLID)
		r->anomalies |= KOF_RAR_ANOM_SOLID;
	if (flags & (KOF_RAR3_F_SPLIT_BEFORE | KOF_RAR3_F_SPLIT_AFTER))
		e->suspicious |= KOF_RAR_ENT_SPLIT;

	if (csize && !kof_in_range(s->f, e->data_off, csize)) {
		e->suspicious |= KOF_RAR_ENT_PAST_EOF;
		r->anomalies |= KOF_RAR_ANOM_TRUNCATED;
	}
	if (csize && usize / csize >= KOF_RAR_RATIO_ABSURD) {
		e->suspicious |= KOF_RAR_ENT_RATIO;
		r->anomalies |= KOF_RAR_ANOM_RATIO_ABSURD;
	}

	r->total_csize += csize;
	r->total_usize += usize;

	/*
	 * Which region the data belongs to, and it is the compression method that
	 * decides - not the entry's name and not what the archive calls itself. A
	 * stored entry IS the file, sitting here in the clear; anything else finds
	 * nothing whatever a pattern is looking for.
	 *
	 * An encrypted entry is packed even when its method says stored: the bytes
	 * are ciphertext either way.
	 */
	if (csize && e->data_off) {
		uint64_t have = kof_in_range(s->f, e->data_off, csize)
					? csize : s->f.n - e->data_off;
		int clear = e->method == KOF_RAR_M_STORE &&
			    !(flags & KOF_RAR3_F_ENCRYPTED);

		if (e->data_off < s->f.n)
			kof_runs_add(&s->runs, s->f.n, e->data_off, have,
				     clear ? KOF_RAR_CLS_STORED
					   : KOF_RAR_CLS_PACKED);
		if (clear)
			r->n_stored++;
	}
	return 1;
}

int kof_rar_parse(kof_buf file, struct kof_rar_info *r, struct kof_obj_ctx *ctx)
{
	struct rw s;
	uint64_t at;
	int saw_end = 0;

	memset(r, 0, sizeof *r);
	r->version = KOF_RAR_INFO_VERSION;

	if (!kof_rar_sniff(file))
		return 0;
	r->valid = 1;

	memset(&s, 0, sizeof s);
	s.f = file;
	s.r = r;
	kof_runs_init(&s.runs, (struct kof_run *)r->run, KOF_RAR_MAX_EXTENTS,
		      KOF_RAR_CLS_COUNT);

	if (file.p[6] == 0x01) {
		/*
		 * RAR5, walked. It shares nothing with RAR3 below the magic -
		 * variable length integers, a different block vocabulary, a
		 * different place for every field - so it gets a walk of its own
		 * rather than a branch inside this one.
		 *
		 * UNSUPPORTED here means only that the walk found nothing to offer.
		 * It used to be raised for every compressed entry too, from when
		 * there was no RAR5 decoder; leaving it there would report an
		 * archive this build reads end to end as a gap.
		 */
		r->rar_version = KOF_RAR_V5;
		rar5_walk(&s, file);
		if (!r->n_entries)
			r->anomalies |= KOF_RAR_ANOM_UNSUPPORTED;
		goto settle;
	} else {
		r->rar_version = KOF_RAR_V3;
		kof_runs_add(&s.runs, file.n, 0, RAR3_MAGIC_LEN,
			     KOF_RAR_CLS_HEADERS);
		at = RAR3_MAGIC_LEN;
	}

	/*
	 * The chain.
	 *
	 * `size` is refused below the seven bytes it is itself part of, so `at`
	 * gains at least seven per iteration and the walk terminates on the object
	 * rather than on a counter.
	 */
	while (at + B_BASE_LEN <= file.n) {
		uint64_t size, data = 0, next;
		uint16_t flags;
		uint8_t typ;

		typ   = file.p[at + B_TYPE];
		flags = rd16(file, at + B_FLAGS);
		size  = rd16(file, at + B_SIZE);

		if (size < B_BASE_LEN) {
			r->anomalies |= KOF_RAR_ANOM_BAD_BLOCK;
			break;
		}
		if (at + size > file.n) {
			r->anomalies |= KOF_RAR_ANOM_TRUNCATED;
			/* Claim what is there, then stop - the rest is not
			 * in the object to be read. */
			kof_runs_add(&s.runs, file.n, at, file.n - at,
				     KOF_RAR_CLS_HEADERS);
			break;
		}

		/*
		 * How much data follows the header. For a file block this field is
		 * the packed size; for anything else it is just a length to skip.
		 * Either way it is 32 bits from the file, widened before use.
		 */
		if (flags & KOF_RAR3_F_ADD_SIZE) {
			if (at + B_BASE_LEN + 4 > file.n) {
				r->anomalies |= KOF_RAR_ANOM_TRUNCATED;
				break;
			}
			data = rd32(file, at + B_BASE_LEN);
		}

		/*
		 * The FILE block claims its own header, because the name sits inside
		 * it and has to be claimed first.
		 *
		 * Claiming the whole block as HEADERS here and adding the name
		 * afterwards left NAMES empty on every RAR ever parsed - the run was
		 * added, the bytes were already spoken for, and a region a signature
		 * can target held nothing. zip splits the same way and gzip says so
		 * in a comment; this was the one that did not.
		 */
		if (typ == KOF_RAR3_BLK_FILE || typ == KOF_RAR3_BLK_SUB) {
			/*
			 * A file block re-reads its own sizes, including the
			 * optional 64 bit halves the base ADD_SIZE field cannot
			 * express - and where the next block starts comes back
			 * from there rather than from the copy read above.
			 */
			if (!file_block(&s, at, size, flags, &data))
				break;
		} else {
			kof_runs_add(&s.runs, file.n, at, size,
				     KOF_RAR_CLS_HEADERS);
		}
		if (typ != KOF_RAR3_BLK_FILE && typ != KOF_RAR3_BLK_SUB &&
		    data && at + size < file.n) {
			uint64_t have = at + size + data <= file.n
						? data : file.n - (at + size);

			kof_runs_add(&s.runs, file.n, at + size, have,
				     KOF_RAR_CLS_PACKED);
		}

		if (typ == KOF_RAR3_BLK_END) {
			saw_end = 1;
			at += size + data;
			break;
		}

		next = at + size + data;
		if (next <= at || next > file.n) {
			/* The addition overflowed, or the block claims data the
			 * object does not hold. Both end the walk. */
			if (next > file.n)
				r->anomalies |= KOF_RAR_ANOM_TRUNCATED;
			else
				r->anomalies |= KOF_RAR_ANOM_BAD_BLOCK;
			break;
		}
		at = next;
	}

	if (r->rar_version == KOF_RAR_V3 && !saw_end)
		r->anomalies |= KOF_RAR_ANOM_NO_END;
settle:
	/* After the settle: that is the pass that finds an overlap. */
	kof_runs_settle(&s.runs, r->region_bytes);
	if (s.runs.full)
		r->anomalies |= KOF_RAR_ANOM_EXTENTS_FULL;
	if (s.runs.overlapped)
		r->anomalies |= KOF_RAR_ANOM_OVERLAP;
	r->n_runs = s.runs.n;

	ctx->obj_size    = file.n;
	ctx->format      = KOF_FMT_RAR;
	ctx->subtype     = (uint8_t)r->rar_version;
	ctx->file_header = r;
	ctx->resolve_scan = rar_resolve_scan;
	return 1;
}

/* ---- names -------------------------------------------------------------------- */

#define RAR_REGIONS(X)          \
	X(KOF_SCAN_RAR_HEADERS)   \
	X(KOF_SCAN_RAR_NAMES)     \
	X(KOF_SCAN_RAR_STORED)    \
	X(KOF_SCAN_RAR_PACKED)    \
	X(KOF_SCAN_RAR_UNCLAIMED)

#define X_BIT(b)  (b),
#define X_CASE(b) case (b): return #b;

const uint32_t kof_rar_region_bits[] = { RAR_REGIONS(X_BIT) };
_Static_assert(sizeof kof_rar_region_bits / sizeof kof_rar_region_bits[0] ==
	       KOF_RAR_REGION_COUNT, "region list and its count disagree");

const char *kof_rar_region_name(uint32_t bit)
{
	switch (bit) {
	RAR_REGIONS(X_CASE)
	default: return 0;
	}
}

#undef X_BIT
#undef X_CASE

const char *kof_rar_anomaly_name(unsigned index)
{
	static const char *const n[] = {
		"BAD_BLOCK", "TRUNCATED", "ENTRIES_FULL", "EXTENTS_FULL",
		"ENCRYPTED", "TRAVERSAL", "RATIO_ABSURD", "OVERLAP", "NO_END",
		"SOLID", "UNSUPPORTED"
	};


	_Static_assert(sizeof n / sizeof n[0] == KOF_RAR_ANOM_COUNT,
		       "anomaly name table and its count disagree");
	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
