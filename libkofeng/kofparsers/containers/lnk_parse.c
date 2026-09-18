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
 */

#include <stddef.h>
#include <string.h>

#include "lnk_parse.h"
#include "../runlist.h"

#define LNK_HDR_SIZE  76u

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
	if (mask & KOF_SCAN_LNK_LINKINFO)
		kof_rl_add(&l, ctx->obj_size, k->info_off, k->info_len);
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
	if (mask & KOF_SCAN_LNK_EXTRA)
		kof_rl_add(&l, ctx->obj_size, k->extra_off, k->extra_len);

	if (mask & KOF_SCAN_LNK_UNCLAIMED) {
		/* The complement of everything else, obtained by asking for it
		 * - see the same construction in pe_parse.c for why it is not
		 * a second list of the claimants. Nine claimed regions. */
		struct kof_range cv[16];
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

	/*
	 * ExtraData: blocks of {size, signature, payload}, ended by a size
	 * under four. Walked for its extent and its count; the blocks
	 * themselves are one region, because what is IN them - an environment
	 * variable target, a console configuration, a tracker record with the
	 * machine's NetBIOS name - is a rule's business and not a shape this
	 * needs to know.
	 */
	if (at < file.n) {
		uint64_t start = at;

		while (at + 4u <= file.n) {
			if (!kof_rd_u32(file, at, 0, &v32) || v32 < 4u)
				break;          /* the terminal block */
			if (at + (uint64_t)v32 > file.n) {
				info->anomalies |= KOF_LNK_ANOM_EXTRA_PAST_EOF;
				break;
			}
			info->n_extra++;
			at += v32;
		}
		if (at > start) {
			info->extra_off = start;
			info->extra_len = at - start;
		}
	}

done:
	if (info->args.chars > KOF_LNK_ARGS_LONG)
		info->anomalies |= KOF_LNK_ANOM_ARGS_LONG;
	if (info->icon.chars && str_is_unc(file, &info->icon, unicode))
		info->anomalies |= KOF_LNK_ANOM_ICON_UNC;

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
		"ARGS_LONG", "ICON_UNC"
	};

	_Static_assert(sizeof n / sizeof n[0] == KOF_LNK_ANOM_COUNT,
		       "anomaly name table and its count disagree");
	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
