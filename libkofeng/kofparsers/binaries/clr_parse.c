/* SPDX-License-Identifier: Apache-2.0 */
/*
 * clr_parse.c - see clr_parse.h for why this is not inside pe_parse.c.
 *
 * Every field read here is attacker controlled, so every read goes through the
 * bounds-checking accessors and every extent is clipped to the object before it
 * is stored. A header that lies produces a short region rather than a read past
 * the end - the same answer every other collector in this tree gives.
 */

#include <string.h>

#include "clr_parse.h"

/*
 * The runtime header, which ECMA-335 II.25.3.3 calls the CLI header - spelled
 * CLR here for the reason clr.h gives. Only the fields anything reads are
 * named; the rest is skipped by offset rather than by a struct, because a
 * struct would invite reading it with a cast and the file is not aligned for
 * that.
 */
#define CLRHDR_SIZE      72u
#define CLRHDR_OFF_CB         0u
#define CLRHDR_OFF_META_RVA   8u
#define CLRHDR_OFF_META_SIZE 12u
#define CLRHDR_OFF_RES_RVA   24u
#define CLRHDR_OFF_RES_SIZE  28u

/* "BSJB", read as a little-endian uint32. */
#define META_MAGIC 0x424a5342u

/*
 * The metadata root header before the version string: the signature, two
 * uint16 versions, a reserved uint32, and the version string's length.
 */
#define META_FIXED 16u

/*
 * WHY THE STREAM COUNT IS BOUNDED AT ALL.
 *
 * The format does not bound it - it is a uint16 - and a header claiming 65535
 * streams would have this walking 65535 name strings out of whatever bytes
 * follow. Five is what every compiler emits, obfuscators add at most a couple
 * more, and the cost of being wrong about the ceiling is one unread stream
 * against an unbounded walk.
 */
#define STREAM_MAX 16u

static void clip_stream(struct kof_clr_stream *s, uint64_t obj_size,
			uint64_t off, uint64_t len, uint32_t *anom)
{
	uint64_t got = kof_clip_len(obj_size, off, len);

	s->off = off;
	s->len = got;
	if (got != len)
		*anom |= KOF_CLR_ANOM_STREAM_CUT;
	if (!got)
		s->off = 0;
}

/*
 * Which of the six a stream name is.
 *
 * By name, because that is what the format keys on: a stream is found by the
 * name in its header and not by its position, and an obfuscator that reorders
 * them is still producing a valid assembly. "#-" is the uncompressed form of
 * "#~" and is worth recording because almost nothing but a metadata rewriter
 * emits it.
 */
static struct kof_clr_stream *stream_slot(struct kof_clr_meta *m,
					  const char *name)
{
	if (!strcmp(name, "#~"))
		return &m->tables;
	if (!strcmp(name, "#-")) {
		m->anomalies |= KOF_CLR_ANOM_TABLES_RAW;
		return &m->tables;
	}
	if (!strcmp(name, "#Strings"))
		return &m->strings;
	if (!strcmp(name, "#US"))
		return &m->us;
	if (!strcmp(name, "#Blob"))
		return &m->blob;
	if (!strcmp(name, "#GUID"))
		return &m->guid;
	return NULL;
}

int kof_clr_read(kof_buf obj, uint64_t clr_off, kof_clr_rva rva,
		 const void *user, struct kof_clr_meta *out)
{
	uint64_t mroot, at, end_max = 0;
	uint32_t cb = 0, meta_rva = 0, meta_size = 0;
	uint32_t res_rva = 0, res_size = 0, vlen = 0, sig = 0;
	uint16_t n_streams = 0;
	uint32_t i;

	if (!out)
		return 0;
	memset(out, 0, sizeof *out);
	if (!rva || !kof_in_range(obj, clr_off, CLRHDR_SIZE))
		return 0;

	/*
	 * `cb` is the header's own size and is checked rather than trusted for
	 * one reason: a value other than 72 means this is not a CLI header at
	 * the offset somebody said it was, and reading the RVAs out of it would
	 * be reading whatever is there.
	 */
	if (!kof_rd_u32(obj, clr_off + CLRHDR_OFF_CB, 0, &cb) ||
	    cb != CLRHDR_SIZE)
		return 0;

	if (!kof_rd_u32(obj, clr_off + CLRHDR_OFF_META_RVA, 0, &meta_rva) ||
	    !kof_rd_u32(obj, clr_off + CLRHDR_OFF_META_SIZE, 0, &meta_size) ||
	    !meta_rva)
		return 0;

	mroot = rva(user, meta_rva);
	if (mroot == KOF_BROKEN || mroot >= obj.n)
		return 0;

	if (!kof_rd_u32(obj, mroot, 0, &sig) || sig != META_MAGIC) {
		/*
		 * Recorded and refused. A COM descriptor pointing at something
		 * that is not a metadata root is a fact about the object worth
		 * having, and going on to read stream headers out of it would
		 * turn that fact into five arbitrary extents.
		 */
		out->anomalies |= KOF_CLR_ANOM_NO_BSJB;
		return 0;
	}

	if (!kof_rd_u32(obj, mroot + 12u, 0, &vlen))
		return 0;
	/*
	 * The length is already rounded up to a multiple of four by the format,
	 * so it is the distance to the next field and not the string's length.
	 * A value large enough to leave the object ends the read.
	 */
	if (vlen > obj.n - mroot || META_FIXED + vlen > obj.n - mroot)
		return 0;
	{
		uint32_t n = vlen;

		if (n > sizeof out->version - 1u)
			n = (uint32_t)(sizeof out->version - 1u);
		memcpy(out->version, obj.p + mroot + META_FIXED, n);
		out->version[n] = '\0';
	}

	at = mroot + META_FIXED + vlen;
	/* Flags(2), then the stream count. */
	if (!kof_rd_u16(obj, at + 2u, 0, &n_streams))
		return 0;
	at += 4u;
	out->streams = n_streams;
	out->root_off = mroot;

	if (n_streams > STREAM_MAX) {
		out->anomalies |= KOF_CLR_ANOM_STREAM_SHORT;
		n_streams = STREAM_MAX;
	}

	for (i = 0; i < n_streams; i++) {
		char name[32];
		uint32_t off = 0, len = 0, j;
		struct kof_clr_stream *slot;
		uint64_t name_at;

		if (!kof_rd_u32(obj, at, 0, &off) ||
		    !kof_rd_u32(obj, at + 4u, 0, &len)) {
			out->anomalies |= KOF_CLR_ANOM_STREAM_SHORT;
			break;
		}
		name_at = at + 8u;
		for (j = 0; j + 1u < sizeof name; j++) {
			uint8_t c = 0;

			if (!kof_rd_u8(obj, name_at + j, &c)) {
				j = 0;
				break;
			}
			name[j] = (char)c;
			if (!c)
				break;
		}
		if (!j && name[0] != '\0') {
			out->anomalies |= KOF_CLR_ANOM_STREAM_SHORT;
			break;
		}
		name[sizeof name - 1u] = '\0';
		if (name[j] != '\0') {
			/* A name that did not terminate inside the buffer this
			 * allows is not a stream name. */
			out->anomalies |= KOF_CLR_ANOM_STREAM_SHORT;
			break;
		}

		/* The header is padded so the next one starts on a four-byte
		 * boundary MEASURED FROM THE METADATA ROOT, not from the file. */
		at = name_at + j + 1u;
		at = mroot + ((at - mroot + 3u) & ~(uint64_t)3u);

		out->streams_read++;
		slot = stream_slot(out, name);
		if (!slot)
			continue;   /* a stream nothing here names */
		if (slot->len || slot->off) {
			/* Two headers claiming the same heap. The first wins;
			 * honouring the second would put one heap's bytes in two
			 * places, which is what the partition forbids. */
			out->anomalies |= KOF_CLR_ANOM_STREAM_OVER;
			continue;
		}
		clip_stream(slot, obj.n, mroot + off, len, &out->anomalies);
		if (slot->len && slot->off + slot->len > end_max)
			end_max = slot->off + slot->len;
	}

	/*
	 * The root's own extent: its header, version string and stream table.
	 * Measured to where the last header ended rather than assumed, because
	 * that is the only number that is true when a stream was unreadable.
	 */
	out->root_len = at > mroot ? at - mroot : 0;
	out->root_len = kof_clip_len(obj.n, mroot, out->root_len);
	if (mroot + out->root_len > end_max)
		end_max = mroot + out->root_len;

	/*
	 * The metadata root's declared size, held against what the streams
	 * actually reached. Not used to bound anything - a heap outside it is
	 * still a heap - but a disagreement is worth recording.
	 */
	if (meta_size && mroot + meta_size < end_max)
		out->anomalies |= KOF_CLR_ANOM_STREAM_CUT;

	/*
	 * Manifest resources, which are NOT inside the metadata root: the CLI
	 * header names them separately, and in every assembly a compiler emits
	 * they sit in the same section after the heaps.
	 */
	if (kof_rd_u32(obj, clr_off + CLRHDR_OFF_RES_RVA, 0, &res_rva) &&
	    kof_rd_u32(obj, clr_off + CLRHDR_OFF_RES_SIZE, 0, &res_size) &&
	    res_rva && res_size) {
		uint64_t ro = rva(user, res_rva);

		if (ro != KOF_BROKEN) {
			uint64_t got = kof_clip_len(obj.n, ro, res_size);

			if (got != res_size)
				out->anomalies |= KOF_CLR_ANOM_STREAM_CUT;
			if (got) {
				out->res_off = ro;
				out->res_len = got;
			}
		}
	}

	return 1;
}

/*
 * The claims, in the order they are laid out.
 *
 * Order matters to whoever settles ownership: kof_rl_settle keeps the earlier
 * claimant when two overlap, and these are handed over sorted by offset anyway,
 * so this only has to be complete.
 */
uint32_t kof_clr_claims(const struct kof_clr_meta *m, struct kof_range *out,
			uint32_t cap)
{
	uint32_t n = 0;

	if (!m || !out || !kof_clr_present(m))
		return 0;

#define ADD(o, l)                          \
	do {                               \
		if ((l) && n < cap) {      \
			out[n].off = (o);  \
			out[n].len = (l);  \
			n++;               \
		}                          \
	} while (0)

	ADD(m->root_off, m->root_len);
	ADD(m->tables.off, m->tables.len);
	ADD(m->strings.off, m->strings.len);
	ADD(m->us.off, m->us.len);
	ADD(m->blob.off, m->blob.len);
	ADD(m->guid.off, m->guid.len);
	ADD(m->res_off, m->res_len);
#undef ADD
	return n;
}

void kof_clr_add_ranges(const struct kof_clr_meta *m, uint32_t mask,
			struct kof_rlist *l, uint64_t obj_size)
{
	if (!m || !l || !kof_clr_present(m))
		return;

	if (mask & KOF_SCAN_CLR_HEADER)
		kof_rl_add(l, obj_size, m->root_off, m->root_len);
	if (mask & KOF_SCAN_CLR_TABLES)
		kof_rl_add(l, obj_size, m->tables.off, m->tables.len);
	if (mask & KOF_SCAN_CLR_STRINGS)
		kof_rl_add(l, obj_size, m->strings.off, m->strings.len);
	if (mask & KOF_SCAN_CLR_US)
		kof_rl_add(l, obj_size, m->us.off, m->us.len);
	if (mask & KOF_SCAN_CLR_BLOB) {
		/* Two heaps, one region - see the note on KOF_SCAN_CLR_BLOB. */
		kof_rl_add(l, obj_size, m->blob.off, m->blob.len);
		kof_rl_add(l, obj_size, m->guid.off, m->guid.len);
	}
	if (mask & KOF_SCAN_CLR_RESOURCE)
		kof_rl_add(l, obj_size, m->res_off, m->res_len);
}

const char *kof_clr_region_name(uint32_t bit)
{
	switch (bit) {
	case KOF_SCAN_CLR_HEADER:   return "CLR_HDR";
	case KOF_SCAN_CLR_TABLES:   return "#~";
	case KOF_SCAN_CLR_STRINGS:  return "#Strings";
	case KOF_SCAN_CLR_US:       return "#US";
	case KOF_SCAN_CLR_BLOB:     return "#Blob";
	case KOF_SCAN_CLR_RESOURCE: return "CLR_RES";
	default:                    return NULL;
	}
}

const char *kof_clr_anomaly_name(unsigned index)
{
	static const char *const n[KOF_CLR_ANOM_COUNT] = {
		"metadata root is not BSJB",
		"a stream reaches past the object",
		"two streams claim the same heap",
		"tables are uncompressed (#-)",
		"fewer stream headers than declared"
	};

	return index < KOF_CLR_ANOM_COUNT ? n[index] : "?";
}
