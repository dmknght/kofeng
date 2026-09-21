/*
 * lnk_regions - a shell link's five strings land on the right bytes.
 *
 * WHAT THIS IS DEFENDING. A .lnk has no offset table: the id list says how
 * long it is, the link info says how long IT is, and each of the five strings
 * is a character count. So the COMMAND_LINE_ARGUMENTS - the only part anybody
 * scans a shortcut for - can only be reached by having measured everything in
 * front of it correctly, and a parser that got one length wrong publishes a
 * region pointing at the wrong bytes rather than failing. Nothing would say so.
 *
 * So the fixture is built with a distinct marker in every string, and the test
 * asserts that each region contains ITS OWN marker and no other's. An off-by-
 * one in the id list, a byte count read as a character count, or the five
 * strings taken in the wrong order all move at least one marker into the wrong
 * region, and every one of those is a real way to get this format wrong.
 *
 * BUILT FROM BYTES, so it needs no sample and runs on every host. The layout
 * is MS-SHLLINK's; see kofmod/lnk.h.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofparsers/containers/lnk_parse.h"

static int failures;

static void ok_(int cond, const char *what)
{
	if (!cond) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

static void w16(uint8_t *p, unsigned v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

static void w32(uint8_t *p, unsigned long v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static const uint8_t CLSID[16] = {
	0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
};

/* A counted UTF-16LE string. Returns where the next one goes. */
static uint32_t put_str(uint8_t *f, uint32_t at, const char *s)
{
	uint32_t n = (uint32_t)strlen(s), i;

	w16(f + at, n);
	at += 2u;
	for (i = 0; i < n; i++) {
		f[at + i * 2u]      = (uint8_t)s[i];
		f[at + i * 2u + 1u] = 0;
	}
	return at + n * 2u;
}

/* Does the range [off,len) hold this ASCII marker, read as UTF-16LE? */
static int has_marker(const uint8_t *f, uint64_t off, uint64_t len,
		      const char *m)
{
	uint64_t n = strlen(m), i, j;

	if (len < n * 2u)
		return 0;
	for (i = 0; i + n * 2u <= len; i += 2u) {
		for (j = 0; j < n; j++)
			if (f[off + i + j * 2u] != (uint8_t)m[j] ||
			    f[off + i + j * 2u + 1u] != 0)
				break;
		if (j == n)
			return 1;
	}
	return 0;
}

/* A NUL-terminated ANSI string, which is what LinkInfo and the ExtraData
 * blocks hold - StringData's counted form is put_str above, and the test
 * needs both because the file does. Returns where the next byte goes. */
static uint32_t put_cstr(uint8_t *f, uint32_t at, const char *s)
{
	uint32_t n = (uint32_t)strlen(s);

	memcpy(f + at, s, n);
	f[at + n] = 0;
	return at + n + 1u;
}

/* The ANSI twin of has_marker, for those same fields. */
static int has_marker8(const uint8_t *f, uint64_t off, uint64_t len,
		       const char *m)
{
	uint64_t n = strlen(m), i;

	if (len < n)
		return 0;
	for (i = 0; i + n <= len; i++)
		if (memcmp(f + off + i, m, (size_t)n) == 0)
			return 1;
	return 0;
}

#define M_NAME "MARKERNAME"
#define M_REL  "MARKERREL"
#define M_WORK "MARKERWORK"
#define M_ICON "\\\\host\\share\\MARKERICON"

/* The offset-addressed fields, which is where a wrong base shows up: the
 * volume label's offset counts from the VolumeID and the local path's from
 * the LinkInfo, and swapping the two bases lands each inside the other. */
#define M_LABEL "MARKERLABEL"
#define M_PATH  "C:\\MARKERPATH\\target.exe"
#define M_SFX   "MARKERSUFFIX"
#define M_ENV   "\\\\host\\share\\MARKERENV.exe"
#define M_MACH  "MARKERBOX"
#define M_ICONENV "\\\\host\\share\\MARKERICONENV.dll"

int main(void);
int main(void)
{
	uint8_t *f = calloc(1, 8192);
	struct kof_lnk_info *k = calloc(1, sizeof *k);
	struct kof_obj_ctx ctx;
	uint32_t at, idlist_len = 24u, args_chars;
	uint32_t info_at, vol_at, env_at, icn_at, trk_at;
	char args[600];
	uint64_t flen;

	if (!f || !k) {
		printf("lnk regions: out of memory\n");
		free(f);
		free(k);
		return 1;
	}

	/*
	 * A command line past KOF_LNK_ARGS_LONG, which is what an encoded
	 * payload in a shortcut looks like and what the anomaly is for.
	 */
	memset(args, 'A', sizeof args - 1);
	args[sizeof args - 1] = '\0';
	memcpy(args, "MARKERARGS", 10);
	args_chars = (uint32_t)strlen(args);

	w32(f + 0, 76);
	memcpy(f + 4, CLSID, sizeof CLSID);
	w32(f + 20, KOF_LNK_HAS_IDLIST | KOF_LNK_HAS_LINKINFO |
		    KOF_LNK_HAS_NAME |
		    KOF_LNK_HAS_RELPATH | KOF_LNK_HAS_WORKDIR |
		    KOF_LNK_HAS_ARGS | KOF_LNK_HAS_ICON |
		    /* The fixture carries both environment blocks, so it must
		     * carry the flags that claim them - otherwise it is the
		     * inconsistency EXP_MISMATCH exists to report, and the
		     * well-formed case would never be the one under test. */
		    KOF_LNK_HAS_EXP_STR | KOF_LNK_HAS_EXP_ICON |
		    KOF_LNK_IS_UNICODE);
	at = 76u;

	/* The id list: a length and that many bytes this does not decode. */
	w16(f + at, (unsigned)idlist_len);
	at += 2u;
	memset(f + at, 0x41, idlist_len);
	at += idlist_len;

	/*
	 * THE LinkInfo, WHICH IS THE ONE STRUCTURE HERE ADDRESSED BY OFFSET.
	 * Everything else in a shell link is found by having walked to it; the
	 * five fields below are found by adding a number the file supplies to
	 * a base the SPEC supplies, and the two bases are different - the
	 * volume label counts from the VolumeID, the paths from the LinkInfo.
	 * Both markers are distinct so a swapped base cannot pass.
	 */
	info_at = at;
	vol_at  = info_at + 0x1Cu;
	{
		uint32_t p, vsz, lbp_at, sfx_at;

		/* VolumeID, which states its own size the way LinkInfo does. */
		p = put_cstr(f, vol_at + 16u, M_LABEL);
		vsz = p - vol_at;
		w32(f + vol_at + 0u,  vsz);
		w32(f + vol_at + 4u,  3);            /* DRIVE_FIXED */
		w32(f + vol_at + 8u,  0xDEADBEEFu);
		w32(f + vol_at + 12u, 16);           /* label, from HERE */

		lbp_at = p;
		p = put_cstr(f, lbp_at, M_PATH);
		sfx_at = p;
		p = put_cstr(f, sfx_at, M_SFX);

		w32(f + info_at + 0u,  p - info_at);      /* LinkInfoSize */
		w32(f + info_at + 4u,  0x1Cu);            /* header size */
		w32(f + info_at + 8u,  KOF_LNK_INFO_HAS_LOCAL);
		w32(f + info_at + 12u, vol_at - info_at);
		w32(f + info_at + 16u, lbp_at - info_at);
		w32(f + info_at + 20u, 0);                /* no network half */
		w32(f + info_at + 24u, sfx_at - info_at);
		at = p;
	}

	/* The five strings, in the order the format stores them. */
	at = put_str(f, at, M_NAME);
	at = put_str(f, at, M_REL);
	at = put_str(f, at, M_WORK);
	at = put_str(f, at, args);
	at = put_str(f, at, M_ICON);

	/*
	 * THE ExtraData CHAIN: a full-size environment block, a tracker block,
	 * and then the terminal size-under-four.
	 *
	 * FULL SIZE AND NOT A STUB. The block this test used to carry was
	 * twelve bytes with the right signature on it, which walked the chain
	 * and proved nothing about the contents, because the fields are at
	 * FIXED offsets inside a fixed 788 - and a parser reading a stub would
	 * simply read past it. The size is part of what is being tested.
	 */
	env_at = at;
	w32(f + at, 788);
	w32(f + at + 4u, 0xA0000001u);   /* EnvironmentVariableDataBlock */
	(void)put_cstr(f, at + 8u, M_ENV);          /* TargetAnsi, 260 */
	at += 788u;

	/*
	 * AND THE ICON BLOCK, whose UNC path is the one ICON_UNC cannot see -
	 * that anomaly reads ICON_LOCATION, and a shortcut built to make the
	 * shell authenticate outward puts the path here instead. The two are
	 * different fields and need two checks; this is the second one.
	 */
	icn_at = at;
	w32(f + at, 788);
	w32(f + at + 4u, 0xA0000007u);   /* IconEnvironmentDataBlock */
	(void)put_cstr(f, at + 8u, M_ICONENV);
	at += 788u;

	trk_at = at;
	w32(f + at, 0x60);
	w32(f + at + 4u, 0xA0000003u);   /* TrackerDataBlock */
	w32(f + at + 8u, 0x58);          /* Length */
	w32(f + at + 12u, 0);            /* Version */
	(void)put_cstr(f, at + 16u, M_MACH);        /* MachineID, 16 */
	at += 0x60u;

	w32(f + at, 0);
	at += 4u;
	flen = at;

	ok_(kof_lnk_sniff(kof_buf_make(f, flen)), "the sniff claims it");
	memset(&ctx, 0, sizeof ctx);
	if (!kof_lnk_parse(kof_buf_make(f, flen), k, &ctx)) {
		printf("  FAIL the parse refused a well formed link\n");
		free(f);
		free(k);
		return 1;
	}

	ok_(k->valid != 0u, "the header agreed");
	ok_(k->unicode != 0u, "the strings were read as UTF-16");
	ok_(k->idlist_len == idlist_len, "the id list was measured");
	ok_(k->args.chars == args_chars, "the arguments kept their length");

	/*
	 * EACH MARKER IN ITS OWN REGION AND NOWHERE ELSE. This is the whole
	 * test: a length read wrongly anywhere ahead of a string slides every
	 * string after it, and the only way to catch that is to look at what
	 * the region actually contains.
	 */
	ok_(has_marker(f, k->name.off, k->name.len, M_NAME),
	    "NAME holds the description");
	ok_(has_marker(f, k->relpath.off, k->relpath.len, M_REL),
	    "RELPATH holds the relative path");
	ok_(has_marker(f, k->workdir.off, k->workdir.len, M_WORK),
	    "WORKDIR holds the working directory");
	ok_(has_marker(f, k->args.off, k->args.len, "MARKERARGS"),
	    "ARGUMENTS holds the command line");
	ok_(has_marker(f, k->icon.off, k->icon.len, "MARKERICON"),
	    "ICON holds the icon location");

	ok_(!has_marker(f, k->args.off, k->args.len, M_WORK),
	    "ARGUMENTS does not reach back into the working directory");
	ok_(!has_marker(f, k->workdir.off, k->workdir.len, "MARKERARGS"),
	    "WORKDIR does not reach forward into the arguments");

	ok_((k->anomalies & KOF_LNK_ANOM_ARGS_LONG) != 0,
	    "a command line past the threshold is reported");
	ok_((k->anomalies & KOF_LNK_ANOM_ICON_UNC) != 0,
	    "an icon on another machine is reported");
	ok_(k->n_extra == 3u, "the ExtraData chain was walked");

	/*
	 * THE OFFSET-ADDRESSED FIELDS, EACH HOLDING ITS OWN MARKER. A base
	 * confused for the other one, or an offset applied to the file rather
	 * than to the structure, moves at least one of these - and all three
	 * of the LinkInfo strings sit within a few dozen bytes of each other,
	 * so nothing here is caught by luck.
	 */
	ok_(k->info_hdr == 0x1Cu, "the LinkInfo header size was read");
	ok_((k->info_flags & KOF_LNK_INFO_HAS_LOCAL) != 0,
	    "the LinkInfo says it has a local path");
	ok_(k->drive_type == 3u && k->volume_serial == 0xDEADBEEFu,
	    "the volume's drive type and serial were read");
	ok_(has_marker8(f, k->vol_label.off, k->vol_label.len, M_LABEL),
	    "the volume label is the volume label");
	ok_(has_marker8(f, k->local_path.off, k->local_path.len, "MARKERPATH"),
	    "LOCALPATH holds the target path");
	ok_(has_marker8(f, k->path_suffix.off, k->path_suffix.len, M_SFX),
	    "the common path suffix is its own field");
	ok_(!has_marker8(f, k->local_path.off, k->local_path.len, M_SFX),
	    "LOCALPATH does not run on into the suffix");
	ok_(!has_marker8(f, k->local_path.off, k->local_path.len, M_LABEL),
	    "LOCALPATH is not the volume label under another name");

	ok_(has_marker8(f, k->env_target.off, k->env_target.len, "MARKERENV"),
	    "the environment block's target was decoded");
	ok_(has_marker8(f, k->machine_id.off, k->machine_id.len, M_MACH),
	    "the tracker block's machine name was decoded");
	ok_((k->blocks & KOF_LNK_BLK_ENV) && (k->blocks & KOF_LNK_BLK_TRACKER),
	    "both block signatures were recorded");
	ok_(!(k->blocks & KOF_LNK_BLK_UNKNOWN),
	    "neither signature was taken for an unassigned one");
	ok_(has_marker8(f, k->icon_env.off, k->icon_env.len, "MARKERICONENV"),
	    "the icon block's path was decoded");
	ok_(!has_marker8(f, k->env_target.off, k->env_target.len,
			 "MARKERICONENV"),
	    "the two environment blocks did not run into each other");
	ok_((k->anomalies & KOF_LNK_ANOM_ENV_UNC) != 0,
	    "a target on another machine is reported");
	ok_((k->anomalies & KOF_LNK_ANOM_ICONENV_UNC) != 0,
	    "an icon on another machine is reported from the block too");
	ok_(!(k->anomalies & KOF_LNK_ANOM_EXP_MISMATCH),
	    "flags that match the blocks are not reported as a mismatch");
	ok_(!(k->anomalies & KOF_LNK_ANOM_INFO_BAD_OFF),
	    "a well formed LinkInfo reports no bad offset");
	ok_(!(k->anomalies & KOF_LNK_ANOM_INFO_OVERLAP),
	    "a well formed LinkInfo reports no overlap");

	/* The regions those fields feed, resolved rather than read off the
	 * struct - which is what a rule would actually get. */
	{
		struct kof_range r[KOF_LNK_MAX_PARTS + 8u];
		uint32_t n, i;
		int env_seen = 0, trk_seen = 0, icn_seen = 0;

		n = ctx.resolve_scan(&ctx, KOF_SCAN_LNK_ENVTARGET, r,
				     (uint32_t)(sizeof r / sizeof r[0]));
		for (i = 0; i < n; i++)
			env_seen |= (r[i].off == env_at && r[i].len == 788u);
		ok_(env_seen, "ENVTARGET resolves to the whole env block");

		n = ctx.resolve_scan(&ctx, KOF_SCAN_LNK_TRACKER, r,
				     (uint32_t)(sizeof r / sizeof r[0]));
		for (i = 0; i < n; i++)
			trk_seen |= (r[i].off == trk_at && r[i].len == 0x60u);
		ok_(trk_seen, "TRACKER resolves to the whole tracker block");

		n = ctx.resolve_scan(&ctx, KOF_SCAN_LNK_ICONENV, r,
				     (uint32_t)(sizeof r / sizeof r[0]));
		for (i = 0; i < n; i++)
			icn_seen |= (r[i].off == icn_at && r[i].len == 788u);
		ok_(icn_seen, "ICONENV resolves to the whole icon block");

		/* And EXTRA is what is LEFT of the chain, which here is
		 * nothing: both blocks were claimed by name. */
		n = ctx.resolve_scan(&ctx, KOF_SCAN_LNK_EXTRA, r,
				     (uint32_t)(sizeof r / sizeof r[0]));
		ok_(n == 0u, "EXTRA holds only the blocks nothing else claimed");
	}

	/*
	 * AND THE PARTITION HOLDS. Every byte of the object belongs to exactly
	 * one region - the invariant the engine relies on when it hands a
	 * region to a rule.
	 */
	{
		struct kof_range r[KOF_LNK_MAX_PARTS + 16u];
		uint32_t n, i;
		uint64_t total = 0;

		n = ctx.resolve_scan(&ctx, KOF_SCAN_LNK_CLAIMED |
					   KOF_SCAN_LNK_UNCLAIMED, r,
				     (uint32_t)(sizeof r / sizeof r[0]));
		for (i = 0; i < n; i++)
			total += r[i].len;
		ok_(total == flen, "the regions cover the object exactly once");
	}

	/*
	 * TWO LinkInfo FIELDS POINTED AT THE SAME BYTES, which is the case the
	 * clipping in info_decode exists for and the only new way this format
	 * can break the partition.
	 *
	 * Nothing stops a file doing this: the offsets are the file's, they
	 * are bounded only by the structure's own size, and two of them equal
	 * is one dword's edit. Without the clip both carves are published and
	 * the region lengths add up to more than the file - which is the
	 * failure the whole region design rests on not happening, and which no
	 * amount of random fuzzing finds, because a random dword is not a
	 * valid offset.
	 */
	{
		struct kof_lnk_info *k2 = calloc(1, sizeof *k2);
		struct kof_obj_ctx c2;
		struct kof_range r[KOF_LNK_MAX_PARTS + 16u];
		uint32_t n, i;
		uint64_t total = 0;

		if (!k2) {
			printf("  FAIL out of memory\n");
			failures++;
		} else {
			/* The suffix now starts where the path does. */
			w32(f + info_at + 24u, f[info_at + 16u] |
			    ((uint32_t)f[info_at + 17u] << 8) |
			    ((uint32_t)f[info_at + 18u] << 16) |
			    ((uint32_t)f[info_at + 19u] << 24));

			memset(&c2, 0, sizeof c2);
			ok_(kof_lnk_parse(kof_buf_make(f, flen), k2, &c2) != 0,
			    "a link with colliding LinkInfo offsets still parses");
			ok_((k2->anomalies & KOF_LNK_ANOM_INFO_OVERLAP) != 0,
			    "the collision is reported");

			n = c2.resolve_scan(&c2, KOF_SCAN_LNK_CLAIMED |
						 KOF_SCAN_LNK_UNCLAIMED, r,
					    (uint32_t)(sizeof r / sizeof r[0]));
			for (i = 0; i < n; i++)
				total += r[i].len;
			ok_(total == flen,
			    "and the partition survives it");
			free(k2);
		}
	}

	/*
	 * AND THE FLAG TAKEN BACK OFF while the block it claimed stays where
	 * it is - one bit cleared in the header, which is what a shortcut
	 * assembled out of two others looks like.
	 */
	{
		struct kof_lnk_info *k3 = calloc(1, sizeof *k3);
		struct kof_obj_ctx c3;
		uint32_t fl = (uint32_t)f[20] | ((uint32_t)f[21] << 8) |
			      ((uint32_t)f[22] << 16) | ((uint32_t)f[23] << 24);

		if (!k3) {
			printf("  FAIL out of memory\n");
			failures++;
		} else {
			w32(f + 20, fl & ~(uint32_t)KOF_LNK_HAS_EXP_ICON);
			memset(&c3, 0, sizeof c3);
			ok_(kof_lnk_parse(kof_buf_make(f, flen), k3, &c3) != 0,
			    "a link whose flags contradict its blocks parses");
			ok_((k3->anomalies & KOF_LNK_ANOM_EXP_MISMATCH) != 0,
			    "and the contradiction is reported");
			w32(f + 20, fl);
			free(k3);
		}
	}

	/* A file that is not a shell link is not claimed. */
	{
		uint8_t other[128];

		memset(other, 0, sizeof other);
		w32(other, 76);                 /* the size agrees, the CLSID
						 * does not - which is the case
						 * a size-only sniff would get
						 * wrong */
		ok_(!kof_lnk_sniff(kof_buf_make(other, sizeof other)),
		    "a file with the right size field and no CLSID is refused");
	}

	free(f);
	free(k);
	if (failures) {
		printf("lnk regions: %d check(s) failed\n", failures);
		return 1;
	}
	printf("lnk regions: sniff, the five strings in order, a long command "
	       "line, a UNC icon, the LinkInfo paths, the env and tracker "
	       "blocks, the partition - ok\n");
	return 0;
}
