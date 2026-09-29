/*
 * lnk_parse.c - see lnk_parse.h, and kofmod/lnk.h for the format.
 *
 * ONE PASS, FORWARD, AND EVERY STEP DEPENDS ON THE ONE BEFORE IT. A shell link
 * has no offset table: the id list says how long it is, the link info says how
 * long IT is, and the five strings each say how many characters they hold. So
 * the arguments can only be reached by having correctly measured everything in
 * front of them, and a parser that got any length wrong reports the wrong bytes
 * rather than failing. That is the whole risk in this file, and it is why every
 * length is checked against the file's end before it is used to move.
 *
 * REFUSING IS THE RIGHT ANSWER MORE OFTEN HERE THAN ELSEWHERE. A truncated
 * archive still has entries worth reading; a shell link whose id list runs past
 * the end has lost the position of everything after it. The anomaly is
 * recorded, the walk stops there, and the regions that WERE established stay
 * valid - which is better than continuing from a guessed offset and publishing
 * a region that points at whatever happened to be there.
 *
 * INSIDE LinkInfo AND ExtraData THAT CHANGES, and it is the only place in this
 * file where it does. Those two are addressed by offset rather than by having
 * walked there, so a bad offset costs only the piece it pointed at - the rest
 * of the structure is still at a known position and is still decoded. The two
 * halves of the file want opposite failure modes and get them.
 *
 * THE PARTS ARRAY, and why the regions inside those two structures are recorded
 * during the walk instead of being resolved from fields afterwards. Everything
 * else here is one field to one region: ARGUMENTS is args.off and args.len, and
 * resolving it is a copy. LinkInfo is not - it is a fixed header, up to five
 * pieces at offsets the FILE chose, and whatever is left over, and which bytes
 * belong to LINKINFO is therefore only known once the pieces have been sorted
 * and any collisions between them settled. Doing that on the resolve path would
 * redo it per region per object; doing it here does it once, and leaves resolve
 * a loop over a list.
 */

#include <stddef.h>
#include <string.h>

#include "lnk_parse.h"
#include "../../../kofcore/runlist.h"

#define LNK_HDR_SIZE  76u

/* LinkInfo's fixed header, and the longer form that carries unicode paths. */
#define LNK_INFO_HDR      0x1Cu
#define LNK_INFO_HDR_UNI  0x24u

/* An EnvironmentVariableDataBlock, which IconEnvironmentDataBlock copies:
 * size, signature, 260 bytes of ANSI path, 520 of UTF-16LE. */
#define LNK_ENVBLK_SIZE   788u
#define LNK_ENVBLK_ANSI   8u
#define LNK_ENVBLK_ANSI_N 260u
#define LNK_ENVBLK_UNI    268u
#define LNK_ENVBLK_UNI_N  520u

/* A TrackerDataBlock: size, signature, length, version, then 16 bytes of
 * NetBIOS name and two droid GUIDs this does not read. */
#define LNK_TRKBLK_SIZE   0x60u
#define LNK_TRKBLK_NAME   16u
#define LNK_TRKBLK_NAME_N 16u

/*
 * The one CLSID a shell link carries: 00021401-0000-0000-C000-000000000046,
 * stored the way a GUID is - the first three fields little endian, the last
 * eight bytes in order.
 */
static const uint8_t LNK_CLSID[16] = {
	0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
};

int kof_lnk_sniff(kof_buf file)
{
	uint32_t hdr = 0;

	/*
	 * BOTH FIELDS, NOT JUST THE SIZE. 0x4C at offset zero is four common
	 * bytes - it is 'L' followed by three nulls, which any little-endian
	 * length field of 76 produces. The CLSID is what makes this a shell
	 * link, and checking only the size would claim every file whose first
	 * dword happens to be 76.
	 */
	if (!file.p || file.n < LNK_HDR_SIZE)
		return 0;
	if (!kof_rd_u32(file, 0, 0, &hdr) || hdr != LNK_HDR_SIZE)
		return 0;
	return memcmp(file.p + 4, LNK_CLSID, sizeof LNK_CLSID) == 0;
}

static uint32_t lnk_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				 struct kof_range *out, uint32_t max_out)
{
	const struct kof_lnk_info *k =
		(const struct kof_lnk_info *)ctx->file_header;
	struct kof_rlist l;

	if (!k || !k->valid || !out || max_out == 0)
		return 0;

	kof_rl_init(&l, out, max_out);

	if (mask & KOF_SCAN_LNK_HEADER)
		kof_rl_add(&l, ctx->obj_size, 0, LNK_HDR_SIZE);
	if (mask & KOF_SCAN_LNK_IDLIST)
		kof_rl_add(&l, ctx->obj_size, k->idlist_off, k->idlist_len);
	if (mask & KOF_SCAN_LNK_NAME)
		kof_rl_add(&l, ctx->obj_size, k->name.off, k->name.len);
	if (mask & KOF_SCAN_LNK_RELPATH)
		kof_rl_add(&l, ctx->obj_size, k->relpath.off, k->relpath.len);
	if (mask & KOF_SCAN_LNK_WORKDIR)
		kof_rl_add(&l, ctx->obj_size, k->workdir.off, k->workdir.len);
	if (mask & KOF_SCAN_LNK_ARGUMENTS)
		kof_rl_add(&l, ctx->obj_size, k->args.off, k->args.len);
	if (mask & KOF_SCAN_LNK_ICON)
		kof_rl_add(&l, ctx->obj_size, k->icon.off, k->icon.len);

	/* Everything inside LinkInfo and ExtraData, settled at parse time. */
	if (mask & KOF_SCAN_LNK_PARTS) {
		uint32_t i;

		for (i = 0; i < k->n_parts; i++)
			if (mask & k->part[i].cls)
				kof_rl_add(&l, ctx->obj_size, k->part[i].off,
					   k->part[i].len);
	}

	if (mask & KOF_SCAN_LNK_UNCLAIMED) {
		/* The complement of everything else, obtained by asking for it
		 * - see the same construction in pe_parse.c for why it is not
		 * a second list of the claimants. Seven fixed extents plus the
		 * parts, which is what sizes this. */
		struct kof_range cv[KOF_LNK_MAX_PARTS + 8u];
		struct kof_rlist c;

		kof_rl_init(&c, cv, (uint32_t)(sizeof cv / sizeof cv[0]));
		c.n = lnk_resolve_scan(ctx, KOF_SCAN_LNK_CLAIMED, cv, c.cap);
		kof_rl_complement(&l, &c, ctx->obj_size);
	}
	return kof_rl_normalise(&l);
}

/*
 * One counted string at `at`, into `s`. Returns where the next one starts, or
 * zero when it does not fit - which the caller turns into STRING_PAST_EOF and
 * stops on, because nothing after an unmeasurable string has a known position.
 */
static uint64_t read_string(kof_buf file, uint64_t at, int unicode,
			    struct kof_lnk_str *s)
{
	uint16_t chars = 0;
	uint64_t bytes;

	if (!kof_rd_u16(file, at, 0, &chars))
		return 0;
	/*
	 * CHARACTERS, NOT BYTES, and the width is the header's to say. Reading
	 * the count as a byte length is the classic way to lose a unicode
	 * shell link: the arguments come back half as long as they are, and
	 * everything after them is read from the middle of a UTF-16 pair.
	 */
	bytes = (uint64_t)chars * (unicode ? 2u : 1u);
	if (at + 2u + bytes > file.n)
		return 0;
	s->chars = chars;
	s->off   = at + 2u;
	s->len   = bytes;
	return at + 2u + bytes;
}

/*
 * A NUL-TERMINATED string, which is what LinkInfo and the ExtraData blocks
 * hold - the counted form above belongs to StringData alone, and mixing them
 * up reads a path as a length.
 *
 * Returns the span INCLUDING the terminator, so a caller claiming a region
 * takes the whole field and does not leave the NUL byte in no region at all.
 * `s` gets the string without it. A field with no terminator before `end` is
 * reported as reaching `end`: the bytes are there and are worth publishing,
 * and the file is malformed in a way the caller's bounds already caught.
 */
static uint64_t read_cstr(kof_buf file, uint64_t at, uint64_t end, int wide,
			  struct kof_lnk_str *s)
{
	uint64_t step = wide ? 2u : 1u, p;
	int term = 0;

	if (at >= end || end > file.n)
		return 0;
	for (p = at; p + step <= end; p += step) {
		if (wide) {
			uint16_t c = 0;

			if (!kof_rd_u16(file, p, 0, &c))
				return 0;
			if (!c) {
				term = 1;
				break;
			}
		} else {
			uint8_t c = 0;

			if (!kof_rd_u8(file, p, &c))
				return 0;
			if (!c) {
				term = 1;
				break;
			}
		}
	}
	s->off   = at;
	s->len   = p - at;
	s->chars = (uint32_t)((p - at) / step);
	return (p - at) + (term ? step : 0u);
}

/*
 * Is this string a UNC path - two backslashes at its start? Answered on the
 * bytes rather than on a decoded copy, because that is all this needs: a
 * backslash is 0x5C in both widths and UTF-16LE puts a zero after it.
 */
static int str_is_unc(kof_buf file, const struct kof_lnk_str *s, int unicode)
{
	uint64_t step = unicode ? 2u : 1u;
	uint8_t a = 0, b = 0;

	if (s->chars < 2u || s->len < step * 2u)
		return 0;
	if (!kof_rd_u8(file, s->off, &a) ||
	    !kof_rd_u8(file, s->off + step, &b))
		return 0;
	return a == '\\' && b == '\\';
}

/*
 * Claim [off, len) for `cls`.
 *
 * Runs of one class laid down back to back are joined, which is what keeps the
 * ExtraData blocks this does not break out - five PropertyStore blocks in a
 * row is an ordinary shortcut - from costing five entries.
 */
static void part_add(struct kof_lnk_info *k, uint64_t off, uint64_t len,
		     uint32_t cls)
{
	struct kof_lnk_part *p;

	if (len == 0)
		return;
	if (k->n_parts) {
		p = &k->part[k->n_parts - 1u];
		if (p->cls == cls && p->off + p->len == off) {
			p->len += len;
			return;
		}
	}
	if (k->n_parts >= KOF_LNK_MAX_PARTS) {
		k->anomalies |= KOF_LNK_ANOM_EXTRA_MANY;
		return;
	}
	p = &k->part[k->n_parts++];
	p->off = off;
	p->len = len;
	p->cls = cls;
}

/* One piece of LinkInfo found at an offset the file chose. */
struct lnk_carve {
	uint64_t off, len;
	uint32_t cls;
};

static void carve_put(struct lnk_carve *cv, unsigned *n, unsigned max,
		      uint64_t off, uint64_t len, uint32_t cls)
{
	if (len == 0 || *n >= max)
		return;
	cv[*n].off = off;
	cv[*n].len = len;
	cv[*n].cls = cls;
	(*n)++;
}

/*
 * LinkInfo, whose pieces are at offsets relative to its own start and bounded
 * by its own stated size. Every offset is checked against that size before it
 * is used, and one that fails costs only its own piece.
 */
static void info_decode(kof_buf file, struct kof_lnk_info *k)
{
	uint64_t L = k->info_off, end = k->info_off + k->info_len, at;
	uint32_t hdr = 0, o_vol = 0, o_lbp = 0, o_cnrl = 0, o_sfx = 0;
	uint32_t o_lbpw = 0, o_sfxw = 0;
	struct lnk_carve cv[6];
	unsigned n = 0, i, j;

	if (k->info_len < LNK_INFO_HDR) {
		/* Too short to hold the fixed header: nothing in it can be
		 * located, so the whole extent stays one region. */
		k->anomalies |= KOF_LNK_ANOM_INFO_BAD_OFF;
		part_add(k, L, k->info_len, KOF_SCAN_LNK_LINKINFO);
		return;
	}

	(void)kof_rd_u32(file, L + 4u,  0, &hdr);
	(void)kof_rd_u32(file, L + 8u,  0, &k->info_flags);
	(void)kof_rd_u32(file, L + 12u, 0, &o_vol);
	(void)kof_rd_u32(file, L + 16u, 0, &o_lbp);
	(void)kof_rd_u32(file, L + 20u, 0, &o_cnrl);
	(void)kof_rd_u32(file, L + 24u, 0, &o_sfx);

	/*
	 * THE HEADER SIZE DECIDES WHETHER THE UNICODE OFFSETS EXIST. It is
	 * 0x1C for the short form and 0x24 or more for the long one, and
	 * reading the two extra dwords out of a short LinkInfo would read the
	 * VolumeID as a pair of offsets. Two of the 120 shortcuts measured had
	 * the long form, so this path is not hypothetical.
	 */
	if (hdr < LNK_INFO_HDR || (uint64_t)hdr > k->info_len) {
		k->anomalies |= KOF_LNK_ANOM_INFO_BAD_OFF;
		hdr = LNK_INFO_HDR;
	} else if (hdr >= LNK_INFO_HDR_UNI) {
		(void)kof_rd_u32(file, L + 28u, 0, &o_lbpw);
		(void)kof_rd_u32(file, L + 32u, 0, &o_sfxw);
	}
	k->info_hdr = hdr;

#define OFF_OK(o)  ((o) >= hdr && (uint64_t)(o) < k->info_len)
#define OFF_BAD(o) ((o) != 0u && !OFF_OK(o))

	if (OFF_BAD(o_vol) || OFF_BAD(o_lbp) || OFF_BAD(o_cnrl) ||
	    OFF_BAD(o_sfx) || OFF_BAD(o_lbpw) || OFF_BAD(o_sfxw))
		k->anomalies |= KOF_LNK_ANOM_INFO_BAD_OFF;

	/*
	 * The VolumeID, which states its own size the way LinkInfo does. Its
	 * label offset is relative to the VolumeID, not to the LinkInfo - the
	 * two bases are a step apart and swapping them puts the label in the
	 * middle of the path.
	 */
	if ((k->info_flags & KOF_LNK_INFO_HAS_LOCAL) && OFF_OK(o_vol)) {
		uint64_t V = L + o_vol;
		uint32_t vsz = 0, lbl = 0;

		if (kof_rd_u32(file, V, 0, &vsz) && vsz >= 0x10u &&
		    (uint64_t)o_vol + vsz <= k->info_len) {
			(void)kof_rd_u32(file, V + 4u,  0, &k->drive_type);
			(void)kof_rd_u32(file, V + 8u,  0, &k->volume_serial);
			(void)kof_rd_u32(file, V + 12u, 0, &lbl);
			if (lbl >= 0x10u && lbl < vsz) {
				int wide = 0;

				/* 0x14 is the sentinel that says the label is
				 * elsewhere and unicode - the value is the
				 * flag, which is why it is compared and not
				 * used as an offset. */
				if (lbl == 0x14u && vsz >= 0x14u) {
					uint32_t u = 0;

					if (kof_rd_u32(file, V + 16u, 0, &u) &&
					    u >= 0x14u && u < vsz) {
						lbl = u;
						wide = 1;
					}
				}
				(void)read_cstr(file, V + lbl, V + vsz, wide,
						&k->vol_label);
			}
			carve_put(cv, &n, 6u, V, vsz, KOF_SCAN_LNK_VOLUMEID);
		} else {
			k->anomalies |= KOF_LNK_ANOM_INFO_BAD_OFF;
		}
	}

	if ((k->info_flags & KOF_LNK_INFO_HAS_LOCAL) && OFF_OK(o_lbp)) {
		uint64_t span = read_cstr(file, L + o_lbp, end, 0,
					  &k->local_path);

		carve_put(cv, &n, 6u, L + o_lbp, span, KOF_SCAN_LNK_LOCALPATH);
	}
	if (OFF_OK(o_sfx)) {
		uint64_t span = read_cstr(file, L + o_sfx, end, 0,
					  &k->path_suffix);

		carve_put(cv, &n, 6u, L + o_sfx, span, KOF_SCAN_LNK_LOCALPATH);
	}
	if (OFF_OK(o_lbpw)) {
		uint64_t span = read_cstr(file, L + o_lbpw, end, 1,
					  &k->local_path_w);

		carve_put(cv, &n, 6u, L + o_lbpw, span, KOF_SCAN_LNK_LOCALPATH);
	}
	if (OFF_OK(o_sfxw)) {
		uint64_t span = read_cstr(file, L + o_sfxw, end, 1,
					  &k->path_suffix_w);

		carve_put(cv, &n, 6u, L + o_sfxw, span, KOF_SCAN_LNK_LOCALPATH);
	}

	/*
	 * The network half. Its NetName is the \\host\share a shortcut to a
	 * share carries, and it is the field that says the target is not on
	 * this machine at all.
	 */
	if ((k->info_flags & KOF_LNK_INFO_HAS_NET) && OFF_OK(o_cnrl)) {
		uint64_t C = L + o_cnrl;
		uint32_t csz = 0, nn = 0;

		if (kof_rd_u32(file, C, 0, &csz) && csz >= 0x14u &&
		    (uint64_t)o_cnrl + csz <= k->info_len) {
			if (kof_rd_u32(file, C + 8u, 0, &nn) &&
			    nn >= 0x14u && nn < csz)
				(void)read_cstr(file, C + nn, C + csz, 0,
						&k->net_name);
			carve_put(cv, &n, 6u, C, csz, KOF_SCAN_LNK_NETPATH);
		} else {
			k->anomalies |= KOF_LNK_ANOM_INFO_BAD_OFF;
		}
	}

#undef OFF_OK
#undef OFF_BAD

	/*
	 * SORTED, THEN CLIPPED, THEN LAID DOWN WITH THE GAPS AS LINKINFO.
	 *
	 * The sort is an insertion sort over at most six items, which is the
	 * whole reason it can be one: these are not a table the file supplies
	 * in bulk, they are six named fields. Clipping settles the case the
	 * format allows and nothing prevents - two offsets pointing into each
	 * other - by letting the lower offset keep the bytes, which is the
	 * rule runlist.h uses for the same situation.
	 */
	for (i = 1; i < n; i++) {
		struct lnk_carve t = cv[i];

		for (j = i; j > 0 && cv[j - 1u].off > t.off; j--)
			cv[j] = cv[j - 1u];
		cv[j] = t;
	}

	at = L;
	for (i = 0; i < n; i++) {
		if (cv[i].off < at) {
			uint64_t skip = at - cv[i].off;

			k->anomalies |= KOF_LNK_ANOM_INFO_OVERLAP;
			if (skip >= cv[i].len)
				continue;
			cv[i].off += skip;
			cv[i].len -= skip;
		}
		if (cv[i].off > at)
			part_add(k, at, cv[i].off - at, KOF_SCAN_LNK_LINKINFO);
		part_add(k, cv[i].off, cv[i].len, cv[i].cls);
		at = cv[i].off + cv[i].len;
	}
	if (at < end)
		part_add(k, at, end - at, KOF_SCAN_LNK_LINKINFO);
}

/* Which region a block's signature earns, or zero for the EXTRA pile. */
static uint32_t blk_region(uint32_t sig)
{
	switch (sig) {
	case KOF_LNK_SIG_ENV:     return KOF_SCAN_LNK_ENVTARGET;
	case KOF_LNK_SIG_ICONENV: return KOF_SCAN_LNK_ICONENV;
	case KOF_LNK_SIG_TRACKER: return KOF_SCAN_LNK_TRACKER;
	default:                  return 0;
	}
}

/* Which bit of `blocks` it sets. UNKNOWN for anything MS-SHLLINK does not
 * assign, which includes 0xA000000A - a gap in their numbering, not here. */
static uint32_t blk_bit(uint32_t sig)
{
	switch (sig) {
	case KOF_LNK_SIG_ENV:        return KOF_LNK_BLK_ENV;
	case KOF_LNK_SIG_CONSOLE:    return KOF_LNK_BLK_CONSOLE;
	case KOF_LNK_SIG_TRACKER:    return KOF_LNK_BLK_TRACKER;
	case KOF_LNK_SIG_CONSOLE_FE: return KOF_LNK_BLK_CONSOLE_FE;
	case KOF_LNK_SIG_SPECIAL:    return KOF_LNK_BLK_SPECIAL;
	case KOF_LNK_SIG_DARWIN:     return KOF_LNK_BLK_DARWIN;
	case KOF_LNK_SIG_ICONENV:    return KOF_LNK_BLK_ICONENV;
	case KOF_LNK_SIG_SHIM:       return KOF_LNK_BLK_SHIM;
	case KOF_LNK_SIG_PROPSTORE:  return KOF_LNK_BLK_PROPSTORE;
	case KOF_LNK_SIG_KNOWNFLDR:  return KOF_LNK_BLK_KNOWNFLDR;
	case KOF_LNK_SIG_VISTAIDL:   return KOF_LNK_BLK_VISTAIDL;
	default:                     return KOF_LNK_BLK_UNKNOWN;
	}
}

/*
 * The two blocks that carry a path. They have the same shape - 260 bytes of
 * ANSI followed by 520 of UTF-16LE, both fixed and both NUL-terminated inside
 * their own field - so a short block is a malformed one and is left alone
 * rather than read past.
 */
static void env_decode(kof_buf file, uint64_t off, uint32_t size,
		       struct kof_lnk_str *a, struct kof_lnk_str *w)
{
	if (size < LNK_ENVBLK_SIZE)
		return;
	(void)read_cstr(file, off + LNK_ENVBLK_ANSI,
			off + LNK_ENVBLK_ANSI + LNK_ENVBLK_ANSI_N, 0, a);
	(void)read_cstr(file, off + LNK_ENVBLK_UNI,
			off + LNK_ENVBLK_UNI + LNK_ENVBLK_UNI_N, 1, w);
}

/*
 * ExtraData: blocks of {size, signature, payload}, ended by a size under four.
 * Three of them get a region of their own because of what they hold - see the
 * measurement in lnk.h. The rest are the EXTRA region, joined as they go.
 */
static void extra_walk(kof_buf file, struct kof_lnk_info *k, uint64_t at)
{
	uint64_t start = at;

	while (at + 4u <= file.n) {
		uint32_t sz = 0, sig = 0, cls;

		if (!kof_rd_u32(file, at, 0, &sz) || sz < 4u)
			break;          /* the terminal block */
		if (at + (uint64_t)sz > file.n) {
			k->anomalies |= KOF_LNK_ANOM_EXTRA_PAST_EOF;
			break;
		}
		if (sz >= 8u)
			(void)kof_rd_u32(file, at + 4u, 0, &sig);

		k->blocks |= blk_bit(sig);
		if (blk_bit(sig) == KOF_LNK_BLK_UNKNOWN)
			k->anomalies |= KOF_LNK_ANOM_EXTRA_UNKNOWN;

		switch (sig) {
		case KOF_LNK_SIG_ENV:
			env_decode(file, at, sz, &k->env_target,
				   &k->env_target_w);
			break;
		case KOF_LNK_SIG_ICONENV:
			env_decode(file, at, sz, &k->icon_env, &k->icon_env_w);
			break;
		case KOF_LNK_SIG_TRACKER:
			if (sz >= LNK_TRKBLK_SIZE)
				(void)read_cstr(file, at + LNK_TRKBLK_NAME,
						at + LNK_TRKBLK_NAME +
						LNK_TRKBLK_NAME_N, 0,
						&k->machine_id);
			break;
		default:
			break;
		}

		cls = blk_region(sig);
		part_add(k, at, sz, cls ? cls : KOF_SCAN_LNK_EXTRA);

		k->n_extra++;
		at += sz;
	}
	if (at > start) {
		k->extra_off = start;
		k->extra_len = at - start;
	}
}

int kof_lnk_parse(kof_buf file, struct kof_lnk_info *info,
		  struct kof_obj_ctx *ctx)
{
	uint64_t at;
	uint32_t hdr = 0, v32 = 0;
	uint16_t v16 = 0;
	int unicode;

	if (!file.p || !info || !ctx)
		return 0;
	memset(info, 0, sizeof *info);
	info->version = KOF_LNK_INFO_VERSION;

	if (file.n < LNK_HDR_SIZE) {
		info->anomalies |= KOF_LNK_ANOM_TRUNCATED;
		return 0;
	}
	if (!kof_rd_u32(file, 0, 0, &hdr) || hdr != LNK_HDR_SIZE)
		info->anomalies |= KOF_LNK_ANOM_BAD_SIZE;
	if (memcmp(file.p + 4, LNK_CLSID, sizeof LNK_CLSID) != 0)
		info->anomalies |= KOF_LNK_ANOM_BAD_CLSID;
	/*
	 * Both wrong is not a shell link and is refused; one wrong is a shell
	 * link somebody edited, which is worth parsing and worth saying so
	 * about. The sniff demands both, so this only happens to a caller that
	 * declared the format.
	 */
	if ((info->anomalies & KOF_LNK_ANOM_BAD_SIZE) &&
	    (info->anomalies & KOF_LNK_ANOM_BAD_CLSID))
		return 0;

	(void)kof_rd_u32(file, 20, 0, &info->flags);
	(void)kof_rd_u32(file, 24, 0, &info->attributes);
	(void)kof_rd_u64(file, 28, 0, &info->created);
	(void)kof_rd_u64(file, 36, 0, &info->accessed);
	(void)kof_rd_u64(file, 44, 0, &info->written);
	(void)kof_rd_u32(file, 52, 0, &info->target_size);
	(void)kof_rd_u32(file, 56, 0, &info->icon_index);
	(void)kof_rd_u32(file, 60, 0, &info->show_command);
	if (kof_rd_u16(file, 64, 0, &v16))
		info->hotkey = v16;

	unicode = (info->flags & KOF_LNK_IS_UNICODE) != 0;
	info->unicode = (uint32_t)unicode;
	info->valid = 1;
	at = LNK_HDR_SIZE;

	/*
	 * THE ID LIST, which is a length and then that many bytes of shell
	 * items this does not decode - see the note in lnk.h. It is measured
	 * so the strings after it can be found, and published as a region so a
	 * rule can look inside it.
	 */
	if (info->flags & KOF_LNK_HAS_IDLIST) {
		if (!kof_rd_u16(file, at, 0, &v16) ||
		    at + 2u + (uint64_t)v16 > file.n) {
			info->anomalies |= KOF_LNK_ANOM_IDLIST_PAST_EOF;
			goto done;
		}
		info->idlist_off = at + 2u;
		info->idlist_len = v16;
		at += 2u + (uint64_t)v16;
	}

	/*
	 * LinkInfo states its own total size in its first dword, which is what
	 * makes it skippable without understanding it. FORCE_NO_LINKINFO does
	 * not remove the structure - it tells the shell to ignore it - so the
	 * flag that decides whether it is PRESENT is HasLinkInfo alone.
	 */
	if (info->flags & KOF_LNK_HAS_LINKINFO) {
		if (!kof_rd_u32(file, at, 0, &v32) || v32 < 4u ||
		    at + (uint64_t)v32 > file.n) {
			info->anomalies |= KOF_LNK_ANOM_INFO_PAST_EOF;
			goto done;
		}
		info->info_off = at;
		info->info_len = v32;
		info_decode(file, info);
		at += v32;
	}

	/*
	 * THE FIVE STRINGS, IN THE FORMAT'S ORDER. Each is present only when
	 * its flag is set, and a flag that is clear consumes nothing - so the
	 * order is what identifies them, not anything in the bytes.
	 */
	{
		static const struct {
			uint32_t flag;
			size_t   at;
		} str[] = {
			{ KOF_LNK_HAS_NAME,    offsetof(struct kof_lnk_info, name) },
			{ KOF_LNK_HAS_RELPATH, offsetof(struct kof_lnk_info, relpath) },
			{ KOF_LNK_HAS_WORKDIR, offsetof(struct kof_lnk_info, workdir) },
			{ KOF_LNK_HAS_ARGS,    offsetof(struct kof_lnk_info, args) },
			{ KOF_LNK_HAS_ICON,    offsetof(struct kof_lnk_info, icon) }
		};
		unsigned i;

		for (i = 0; i < sizeof str / sizeof str[0]; i++) {
			struct kof_lnk_str *s;
			uint64_t next;

			if (!(info->flags & str[i].flag))
				continue;
			s = (struct kof_lnk_str *)((char *)info + str[i].at);
			next = read_string(file, at, unicode, s);
			if (!next) {
				memset(s, 0, sizeof *s);
				info->anomalies |= KOF_LNK_ANOM_STRING_PAST_EOF;
				goto done;
			}
			at = next;
		}
	}

	if (at < file.n)
		extra_walk(file, info, at);

done:
	if (info->args.chars > KOF_LNK_ARGS_LONG)
		info->anomalies |= KOF_LNK_ANOM_ARGS_LONG;
	if (info->icon.chars && str_is_unc(file, &info->icon, unicode))
		info->anomalies |= KOF_LNK_ANOM_ICON_UNC;
	/*
	 * The two environment blocks, on whichever width the file filled in.
	 * Both are checked because a block may carry the path in one and not
	 * the other, and a shortcut with a UNC path in only the unicode half
	 * is still a shortcut with a UNC path.
	 */
	if (str_is_unc(file, &info->env_target, 0) ||
	    str_is_unc(file, &info->env_target_w, 1))
		info->anomalies |= KOF_LNK_ANOM_ENV_UNC;
	if (str_is_unc(file, &info->icon_env, 0) ||
	    str_is_unc(file, &info->icon_env_w, 1))
		info->anomalies |= KOF_LNK_ANOM_ICONENV_UNC;

	/*
	 * The two flags that name a block, against the blocks that are there.
	 * Only on a file this walked to the end: one that was cut short is
	 * missing blocks because it is missing bytes, and the PAST_EOF bit it
	 * already carries is the accurate way to say so.
	 */
	if (!(info->anomalies & (KOF_LNK_ANOM_IDLIST_PAST_EOF |
				 KOF_LNK_ANOM_INFO_PAST_EOF |
				 KOF_LNK_ANOM_STRING_PAST_EOF |
				 KOF_LNK_ANOM_EXTRA_PAST_EOF |
				 KOF_LNK_ANOM_TRUNCATED))) {
		int f_env = (info->flags & KOF_LNK_HAS_EXP_STR) != 0;
		int b_env = (info->blocks & KOF_LNK_BLK_ENV) != 0;
		int f_icn = (info->flags & KOF_LNK_HAS_EXP_ICON) != 0;
		int b_icn = (info->blocks & KOF_LNK_BLK_ICONENV) != 0;

		if (f_env != b_env || f_icn != b_icn)
			info->anomalies |= KOF_LNK_ANOM_EXP_MISMATCH;
	}

	ctx->obj_size     = file.n;
	ctx->format       = KOF_FMT_LNK;
	ctx->file_header  = info;
	ctx->resolve_scan = lnk_resolve_scan;
	return 1;
}

#define X_BIT(b)  (b),
#define X_CASE(b) case (b): return #b;

const uint32_t kof_lnk_region_bits[] = { LNK_REGIONS(X_BIT) };
_Static_assert(sizeof kof_lnk_region_bits / sizeof kof_lnk_region_bits[0] ==
	       KOF_LNK_REGION_COUNT, "region list and its count disagree");

const char *kof_lnk_region_name(uint32_t bit)
{
	switch (bit) {
	LNK_REGIONS(X_CASE)
	default: return 0;
	}
}

#undef X_BIT
#undef X_CASE

const char *kof_lnk_anomaly_name(unsigned index)
{
	static const char *const n[] = {
		"BAD_SIZE", "BAD_CLSID", "TRUNCATED", "IDLIST_PAST_EOF",
		"INFO_PAST_EOF", "STRING_PAST_EOF", "EXTRA_PAST_EOF",
		"ARGS_LONG", "ICON_UNC", "INFO_BAD_OFF", "INFO_OVERLAP",
		"ENV_UNC", "ICONENV_UNC", "EXTRA_UNKNOWN", "EXTRA_MANY",
		"EXP_MISMATCH"
	};

	_Static_assert(sizeof n / sizeof n[0] == KOF_LNK_ANOM_COUNT,
		       "anomaly name table and its count disagree");
	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
