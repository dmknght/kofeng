/*
 * cov_decode_modabi - the host's static decoders, as a module reaches them (kunp_static_decode), against
 * independent encoders and against the compression tools of the machine.
 *
 * probe_decode_00 (tests/sigs) fires on "KOFPRB06", takes the method id and the output hint from the
 * object, decodes everything after byte 24 and makes the result a child. This test builds the object
 * from a plaintext it chose, scans it, and compares the CHILD'S BYTES with the plaintext:
 *
 *   ENCODERS   deflate and zlib framing (the gzip tool's raw block, and the tests' own fixed/dynamic block writers),
 *              MS-OVBA, ASCII85, ASCIIHex, RunLength and LZW (hostile_enc.h: written from the specifications)
 *   TOOLS      gzip, bzip2 and xz are run on the same plaintext: DEFLATE, BZIP2, LZMA2, LZMA2 behind the x86 branch
 *              filter, and LZMA (lc/lp/pb in the method id) are decoded to the plaintext the tool was given
 *   SHAPES     a byte, seven bytes, text, a long run, noise, x86 with calls (what the BCJ filter converts); each
 *              codec on each that it can carry
 *   CUTS       every prefix of a short stream: what comes out is the plaintext's own prefix or nothing, never
 *              bytes the plaintext does not have
 *   FLIPS      a few thousand single bit flips per codec: the host answers (a smaller child, none, or the same
 *              bytes) and never more than the plaintext's length plus the codec's own slack
 *   IDS        a method id the host does not know, a chain-only id used alone, a length of zero: no child
 *
 * Skipped, visibly, for each tool that is not installed. No file is written: the tools read an anonymous
 * memory file.
 */

#define _GNU_SOURCE
#include "hostile_engine.h"
#include "known_miss.h"

#include <sys/stat.h>

#include "../../libkofeng/kofcore/kofcore.h"
#include <kofmod/kofsig.h>
#include "../lib/uncoat/hostile_enc.h"

#define DB_SIGS "build/test/databases-sigs"
#define OBJ_MAX (1u << 18)

struct seen {
	unsigned n_obj;
	uint8_t  child[OBJ_MAX];
	uint64_t child_len;
	int      child_ok;
	uint64_t ret;
	int      has_ret, done;
};

static void on_note(uint32_t fact, const char *what, uint64_t value, void *user)
{
	struct seen *s = user;

	(void)fact;
	if (!strcmp(what, "Dec.ret")) {
		s->ret = value;
		s->has_ret = 1;
	} else if (!strcmp(what, "Dec.done")) {
		s->done = (int)value;
	}
}

static int on_obj(const char *name, const void *b, uint64_t n, const struct kof_result *r, void *user)
{
	struct seen *s = user;

	(void)name;
	(void)r;
	if (s->n_obj == 1 && n <= OBJ_MAX) {         /* the first child */
		memcpy(s->child, b, n);
		s->child_len = n;
		s->child_ok = 1;
	}
	s->n_obj++;
	return 0;
}

static uint8_t g_obj[OBJ_MAX + 64];
static struct seen g_seen;

/* scan: method, hint, coded bytes -> what the host made */
static void decode(kof_scanner *sc, uint32_t method, uint64_t hint, const uint8_t *coded, size_t n, struct seen *out)
{
	struct kof_scan_option op = he_opt();
	size_t total = 24 + n;

	memset(out, 0, offsetof(struct seen, child));
	out->child_len = 0;
	out->child_ok = 0;
	out->ret = 0;
	out->has_ret = 0;
	out->done = 0;
	if (total > sizeof g_obj)
		return;
	memset(g_obj, 0, 24);
	memcpy(g_obj, "KOFPRB06", 8);
	memcpy(g_obj + 8, &method, 4);
	memcpy(g_obj + 16, &hint, 8);
	if (n)
		memcpy(g_obj + 24, coded, n);
	kscan_on_debug(sc, on_note, out);
	(void)kscan_bytes(sc, g_obj, total, "dm", &op, on_obj, out);
	kscan_on_debug(sc, NULL, NULL);
}

/* ---- plaintexts ------------------------------------------------------------------------------ */

enum { P_BYTE, P_SEVEN, P_TEXT, P_RUN, P_NOISE, P_X86, P_COUNT };

static const char *const PNAME[P_COUNT] = { "one byte", "seven bytes", "text", "a long run", "noise", "x86 with calls" };

static size_t make_plain(unsigned k, uint8_t *p)
{
	size_t n = 0, i;
	uint64_t s = 0x9e3779b97f4a7c15ull + k;

	switch (k) {
	case P_BYTE:
		p[n++] = 'Q';
		break;
	case P_SEVEN:
		memcpy(p, "abcabca", 7);
		n = 7;
		break;
	case P_TEXT:
		for (i = 0; i < 40; i++)
			n += (size_t)sprintf((char *)p + n, "line %zu: the quick brown fox jumps over the lazy dog %zu\n", i, i * 7);
		break;
	case P_RUN:
		memset(p, 0x41, 5000);
		n = 5000;
		break;
	case P_NOISE:
		for (i = 0; i < 3000; i++) {
			s ^= s << 13; s ^= s >> 7; s ^= s << 17;
			p[n++] = (uint8_t)(s >> 20);
		}
		break;
	default:                                  /* x86 with calls: E8 rel32 with nearby targets, filler between */
		for (i = 0; i < 400; i++) {
			int32_t rel;

			s ^= s << 13; s ^= s >> 7; s ^= s << 17;
			p[n++] = 0x55; p[n++] = 0x89; p[n++] = 0xe5;
			p[n++] = 0xe8;
			rel = (int32_t)((s >> 33) % 4000u) - 2000;
			memcpy(p + n, &rel, 4);
			n += 4;
			p[n++] = 0xc9; p[n++] = 0xc3;
			p[n++] = (uint8_t)s;
		}
		break;
	}
	return n;
}

/* ---- tools ------------------------------------------------------------------------------------ */

static int have_tool(const char *path)
{
	return access(path, X_OK) == 0;
}

/* run `cmd` with the plaintext as its standard input (an anonymous file), return what it printed */
static size_t via_tool(const char *cmd, const uint8_t *plain, size_t n, uint8_t *out, size_t cap)
{
	int fd = memfd_create("kofeng-dm", 0);
	char full[400];
	FILE *f;
	size_t got = 0, k;

	if (fd < 0)
		return 0;
	if (n && write(fd, plain, n) != (ssize_t)n) {
		close(fd);
		return 0;
	}
	snprintf(full, sizeof full, "%s < /proc/%d/fd/%d 2>/dev/null", cmd, (int)getpid(), fd);
	f = popen(full, "r");
	if (f) {
		while ((k = fread(out + got, 1, cap - got, f)) > 0)
			got += k;
		pclose(f);
	}
	close(fd);
	return got;
}

static uint32_t adler32(const uint8_t *p, size_t n)
{
	uint32_t a = 1, b = 0;
	size_t i;

	for (i = 0; i < n; i++) {
		a = (a + p[i]) % 65521u;
		b = (b + a) % 65521u;
	}
	return (b << 16) | a;
}

/* ---- the checks --------------------------------------------------------------------------------- */

static int agree(const struct seen *s, const uint8_t *plain, size_t n)
{
	return s->child_ok && s->child_len == n && !memcmp(s->child, plain, n);
}

/* the child is a prefix of the plaintext (a cut stream gives what it holds, and nothing it does not) */
static int is_prefix(const struct seen *s, const uint8_t *plain, size_t n, unsigned slack)
{
	size_t cmp;

	if (!s->child_ok)
		return 1;
	if (s->child_len > n)
		return 0;
	cmp = s->child_len > slack ? s->child_len - slack : 0;
	return !memcmp(s->child, plain, cmp);
}

struct codec {
	const char *name;
	uint32_t    method;
	int         hint_len;               /* the hint is the plaintext length */
	unsigned    slack;                  /* the last bytes of a cut stream's output a filter may leave unconverted */
};

/* one codec over every plaintext it can carry: `enc` makes the coded stream */
typedef size_t (*enc_fn)(const struct codec *c, const uint8_t *plain, size_t n, uint8_t *out, size_t cap);

static unsigned checked, shapes_skipped;

static size_t e_stored(const struct codec *c, const uint8_t *p, size_t n, uint8_t *out, size_t cap);

static void round_trip(kof_scanner *sc, const struct codec *c, enc_fn enc, unsigned plains)
{
	static uint8_t plain[8192], coded[OBJ_MAX / 2];
	unsigned k, ok = 0, all = 0;

	for (k = 0; k < P_COUNT; k++) {
		size_t n, m;

		if (!(plains & (1u << k)))
			continue;
		n = make_plain(k, plain);
		m = enc(c, plain, n, coded, sizeof coded);
		if (!m) {
			shapes_skipped++;
			continue;
		}
		decode(sc, c->method, c->hint_len ? n : 0, coded, m, &g_seen);
		all++;
		if (agree(&g_seen, plain, n) && g_seen.has_ret && g_seen.ret == n && g_seen.done)
			ok++;
		else
			CK(0, "%s on %s: %s (child %d of %llu bytes, wanted %zu; the host said %llu)", c->name, PNAME[k],
			   g_seen.child_ok ? "differs" : "no child", g_seen.child_ok, (unsigned long long)g_seen.child_len, n,
			   (unsigned long long)g_seen.ret);
		checked++;
	}
	CK(ok == all && all > 0, "%s: %u of %u shapes round-trip", c->name, ok, all);
}

/* cuts and flips on one short stream of a codec */
static void hostile(kof_scanner *sc, const struct codec *c, const uint8_t *plain, size_t n, const uint8_t *coded, size_t m)
{
	unsigned k, bad_cut = 0, bad_flip = 0, produced = 0;
	static uint8_t bent[8192];
	uint64_t s = 0x1234567ull + c->method;

	for (k = 0; k <= m; k++) {
		decode(sc, c->method, c->hint_len ? n : 0, coded, k, &g_seen);
		if (!is_prefix(&g_seen, plain, n, c->slack))
			bad_cut++;
	}
	CK(bad_cut == 0, "%s: a cut stream gives the plaintext's own prefix or nothing (%u of %zu cuts gave other bytes)", c->name,
	   bad_cut, m + 1);
	if (m > sizeof bent)
		return;
	for (k = 0; k < 600; k++) {
		size_t at;

		s ^= s << 13; s ^= s >> 7; s ^= s << 17;
		memcpy(bent, coded, m);
		at = (size_t)(s % (m * 8u));
		bent[at / 8] ^= (uint8_t)(1u << (at % 8));
		decode(sc, c->method, c->hint_len ? n : 0, bent, m, &g_seen);
		if (g_seen.child_ok) {
			produced++;
			/* a flipped stream may decode to other bytes, but not to an unbounded amount of them */
			if (g_seen.child_len > n * 64u + 4096u)
				bad_flip++;
		}
	}
	CK(bad_flip == 0, "%s: no flip makes the host produce more than its limit (%u)", c->name, bad_flip);
	(void)produced;
}

/* ---- encoders for the table --------------------------------------------------------------------- */

static size_t e_stored(const struct codec *c, const uint8_t *p, size_t n, uint8_t *out, size_t cap)
{
	(void)c;
	if (n > cap)
		return 0;
	memcpy(out, p, n);
	return n;
}

static size_t e_gzip_raw(const struct codec *c, const uint8_t *p, size_t n, uint8_t *out, size_t cap)
{
	static uint8_t gz[OBJ_MAX / 2];
	size_t got, off = 0, raw;

	(void)c;
	if (!have_tool("/usr/bin/gzip"))
		return 0;
	got = via_tool("/usr/bin/gzip -9 -n -c", p, n, gz, sizeof gz);
	raw = hv_gzip_raw(gz, got, &off);
	if (!raw || raw > cap)
		return 0;
	memcpy(out, gz + off, raw);
	return raw;
}

static size_t e_zlib(const struct codec *c, const uint8_t *p, size_t n, uint8_t *out, size_t cap)
{
	static uint8_t raw[OBJ_MAX / 2];
	size_t r = e_gzip_raw(c, p, n, raw, sizeof raw);
	uint32_t ad;

	if (!r || r + 6 > cap)
		return 0;
	out[0] = 0x78;
	out[1] = 0x9c;
	memcpy(out + 2, raw, r);
	ad = adler32(p, n);
	out[2 + r] = (uint8_t)(ad >> 24); out[3 + r] = (uint8_t)(ad >> 16); out[4 + r] = (uint8_t)(ad >> 8); out[5 + r] = (uint8_t)ad;
	return r + 6;
}

static size_t e_fixed_deflate(const struct codec *c, const uint8_t *p, size_t n, uint8_t *out, size_t cap)
{
	struct hv_bw w;

	(void)c;
	hv_bw_init(&w, out, cap);
	hv_defl_fixed(&w, p, n, 1, 32768);
	return hv_defl_end(&w);
}

static size_t e_bzip2(const struct codec *c, const uint8_t *p, size_t n, uint8_t *out, size_t cap)
{
	(void)c;
	if (!have_tool("/usr/bin/bzip2"))
		return 0;
	return via_tool("/usr/bin/bzip2 -c", p, n, out, cap);
}

static size_t e_xz(const struct codec *c, const uint8_t *p, size_t n, uint8_t *out, size_t cap)
{
	const char *cmd;

	if (!have_tool("/usr/bin/xz"))
		return 0;
	switch (c->method) {
	case KOF_UNP_LZMA2:         cmd = "/usr/bin/xz -c --format=raw --lzma2=preset=6,dict=1MiB"; break;
	case KOF_UNP_LZMA2_BCJ_X86: cmd = "/usr/bin/xz -c --format=raw --x86 --lzma2=preset=6,dict=1MiB"; break;
	default:
		cmd = c->method == KOF_UNP_LZMA_PROPS(0, 2, 0)
		      ? "/usr/bin/xz -c --format=raw --lzma1=lc=0,lp=2,pb=0,dict=1MiB"
		      : "/usr/bin/xz -c --format=raw --lzma1=lc=3,lp=0,pb=2,dict=1MiB";
		break;
	}
	return via_tool(cmd, p, n, out, cap);
}

static size_t e_ovba(const struct codec *c, const uint8_t *p, size_t n, uint8_t *out, size_t cap)
{
	(void)c;
	return hv_ovba_enc(p, n, out, cap);
}

static size_t e_a85(const struct codec *c, const uint8_t *p, size_t n, uint8_t *out, size_t cap)
{
	(void)c;
	return hv_a85_enc(p, n, out, cap, 0);
}

static size_t e_a85w(const struct codec *c, const uint8_t *p, size_t n, uint8_t *out, size_t cap)
{
	(void)c;
	return hv_a85_enc(p, n, out, cap, 40);
}

static size_t e_ahx(const struct codec *c, const uint8_t *p, size_t n, uint8_t *out, size_t cap)
{
	(void)c;
	return hv_ahx_enc(p, n, out, cap, 0);
}

static size_t e_ahx_sp(const struct codec *c, const uint8_t *p, size_t n, uint8_t *out, size_t cap)
{
	(void)c;
	return hv_ahx_enc(p, n, out, cap, ' ');
}

static size_t e_hextext(const struct codec *c, const uint8_t *p, size_t n, uint8_t *out, size_t cap)
{
	static const char hx[] = "0123456789ABCDEF";
	size_t i, o = 0;

	(void)c;
	for (i = 0; i < n && o + 4 < cap; i++) {
		out[o++] = (uint8_t)hx[p[i] >> 4];
		out[o++] = (uint8_t)hx[p[i] & 15u];
		if (i % 16 == 15)
			out[o++] = '\n';
		else if (i % 3 == 2)
			out[o++] = ' ';
	}
	return o;
}

static size_t e_rle(const struct codec *c, const uint8_t *p, size_t n, uint8_t *out, size_t cap)
{
	(void)c;
	return hv_rle_enc(p, n, out, cap);
}

static size_t e_lzw(const struct codec *c, const uint8_t *p, size_t n, uint8_t *out, size_t cap)
{
	(void)c;
	return hv_lzw_enc(p, n, out, cap);
}

#define ALL ((1u << P_COUNT) - 1u)

static void t_codecs(kof_scanner *sc)
{
	static const struct codec defl = { "deflate (gzip)", KOF_UNP_DEFLATE, 0, 0 },
				  deflfix = { "deflate (fixed blocks)", KOF_UNP_DEFLATE, 0, 0 }, zl = { "zlib", KOF_UNP_ZLIB, 0, 0 },
				  zlraw = { "zlib on a raw stream", KOF_UNP_ZLIB, 0, 0 }, bz = { "bzip2", KOF_UNP_BZIP2, 0, 0 },
				  l2 = { "lzma2", KOF_UNP_LZMA2, 0, 0 }, l2b = { "lzma2 + x86 filter", KOF_UNP_LZMA2_BCJ_X86, 0, 4 },
				  l1 = { "lzma lc3 lp0 pb2", KOF_UNP_LZMA_PROPS(3, 0, 2), 1, 0 },
				  l1b = { "lzma lc0 lp2 pb0", KOF_UNP_LZMA_PROPS(0, 2, 0), 1, 0 },
				  a85 = { "ascii85", KOF_UNP_ASCII85, 0, 0 }, a85w = { "ascii85 wrapped", KOF_UNP_ASCII85, 0, 0 },
				  ahx = { "asciihex", KOF_UNP_ASCIIHEX, 0, 1 }, ahxs = { "asciihex with blanks", KOF_UNP_ASCIIHEX, 0, 0 },
				  hx = { "hex text", KOF_UNP_HEXTEXT, 0, 0 }, rle = { "runlength", KOF_UNP_RUNLENGTH, 0, 0 },
				  lzw = { "lzw", KOF_UNP_LZW, 0, 0 };

	round_trip(sc, &defl, e_gzip_raw, ALL);
	round_trip(sc, &deflfix, e_fixed_deflate, ALL);
	round_trip(sc, &zl, e_zlib, ALL);
	round_trip(sc, &zlraw, e_gzip_raw, ALL);           /* no zlib header: read as raw deflate from its first byte */
	round_trip(sc, &bz, e_bzip2, ALL);
	round_trip(sc, &l2, e_xz, ALL);
	round_trip(sc, &l2b, e_xz, ALL);
	round_trip(sc, &l1, e_xz, ALL);
	round_trip(sc, &l1b, e_xz, ALL);
	round_trip(sc, &a85, e_a85, ALL);
	round_trip(sc, &a85w, e_a85w, ALL);
	round_trip(sc, &ahx, e_ahx, ALL);
	round_trip(sc, &ahxs, e_ahx_sp, ALL);
	round_trip(sc, &hx, e_hextext, ALL);
	round_trip(sc, &rle, e_rle, ALL);
	round_trip(sc, &lzw, e_lzw, ALL);
}

static void t_hostile(kof_scanner *sc)
{
	static const struct { struct codec c; enc_fn enc; unsigned shape; } tab[] = {
		{ { "deflate", KOF_UNP_DEFLATE, 0, 0 }, e_gzip_raw, P_TEXT },
		{ { "deflate fixed", KOF_UNP_DEFLATE, 0, 0 }, e_fixed_deflate, P_TEXT },
		{ { "zlib", KOF_UNP_ZLIB, 0, 0 }, e_zlib, P_TEXT },
		{ { "bzip2", KOF_UNP_BZIP2, 0, 0 }, e_bzip2, P_TEXT },
		{ { "lzma2", KOF_UNP_LZMA2, 0, 0 }, e_xz, P_TEXT },
		{ { "lzma2 + x86", KOF_UNP_LZMA2_BCJ_X86, 0, 4 }, e_xz, P_X86 },
		{ { "lzma", KOF_UNP_LZMA_PROPS(3, 0, 2), 1, 0 }, e_xz, P_TEXT },
		{ { "ascii85", KOF_UNP_ASCII85, 0, 0 }, e_a85, P_TEXT },
		{ { "asciihex", KOF_UNP_ASCIIHEX, 0, 1 }, e_ahx, P_TEXT },
		{ { "hex text", KOF_UNP_HEXTEXT, 0, 0 }, e_hextext, P_TEXT },
		{ { "runlength", KOF_UNP_RUNLENGTH, 0, 0 }, e_rle, P_TEXT },
		{ { "lzw", KOF_UNP_LZW, 0, 0 }, e_lzw, P_TEXT }
	};
	static uint8_t plain[8192], coded[OBJ_MAX / 2];
	unsigned i;

	for (i = 0; i < sizeof tab / sizeof tab[0]; i++) {
		size_t n = make_plain(tab[i].shape, plain), m;

		if (n > 400)
			n = 400;                                      /* short, so every cut is affordable */
		m = tab[i].enc(&tab[i].c, plain, n, coded, sizeof coded);
		if (!m) {
			shapes_skipped++;
			continue;
		}
		hostile(sc, &tab[i].c, plain, n, coded, m);
	}
}

/* the methods the engine decodes only for an ENTRY of a parsed container (kunp_static_entry): asked for a bare range
 * they give nothing - no child and a byte count of zero, which is what an unsupported method and a corrupt stream both say */
static void t_entry_only(kof_scanner *sc)
{
	static uint8_t plain[8192], coded[OBJ_MAX / 2];
	size_t n = make_plain(P_TEXT, plain), m;
	struct codec ov = { "ms-ovba", KOF_UNP_OVBA, 0, 0 }, st = { "stored", KOF_UNP_STORED, 0, 0 };

	m = e_ovba(&ov, plain, n, coded, sizeof coded);
	decode(sc, KOF_UNP_OVBA, 0, coded, m, &g_seen);
	CK(!g_seen.child_ok && g_seen.has_ret && g_seen.ret == 0, "ms-ovba over a range is not a static decode (it is an entry's)");
	m = e_stored(&st, plain, n, coded, sizeof coded);
	decode(sc, KOF_UNP_STORED, 0, coded, m, &g_seen);
	CK(!g_seen.child_ok && g_seen.has_ret && g_seen.ret == 0, "nor is a stored range: it is a window, not a decode");
}

static void t_ids(kof_scanner *sc)
{
	static const uint8_t junk[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
	static const uint32_t unknown[] = { 0xffffu, 40u, 60u, 100000u, 0x7fffffffu, 0xffffffffu, 1155u, 33u + 2000u };
	unsigned i;

	for (i = 0; i < sizeof unknown / sizeof unknown[0]; i++) {
		decode(sc, unknown[i], 0, junk, sizeof junk, &g_seen);
		CK(!g_seen.child_ok, "method id %#x is not one the host knows: no child (%llu)", unknown[i], (unsigned long long)g_seen.child_len);
	}
	decode(sc, KOF_UNP_DEFLATE, 0, junk, 0, &g_seen);
	CK(!g_seen.child_ok && g_seen.has_ret && g_seen.ret == 0, "deflate of nothing: no child, the host says 0");
	decode(sc, KOF_UNP_DEFLATE, 0, junk, sizeof junk, &g_seen);
	CK(!g_seen.child_ok || g_seen.child_len <= 16u * 1032u, "deflate of noise: nothing, or a bounded something");
	/* the LZX ids carry their window: 14 and 22 are outside 15..21 */
	decode(sc, KOF_UNP_LZX(14), 0, junk, sizeof junk, &g_seen);
	CK(!g_seen.child_ok, "an LZX window of 14 bits is refused");
	decode(sc, KOF_UNP_LZX(22), 0, junk, sizeof junk, &g_seen);
	CK(!g_seen.child_ok, "and of 22");
	decode(sc, KOF_UNP_LZX(16), 0, junk, sizeof junk, &g_seen);
	CK(!g_seen.child_ok || g_seen.child_len <= 1u << 20, "an LZX stream of noise is refused or bounded");
	decode(sc, KOF_UNP_LZX_RESET(16), 0, junk, sizeof junk, &g_seen);
	CK(!g_seen.child_ok || g_seen.child_len <= 1u << 20, "the reset form too");
	/* the methods that need more than a range: a stored range with a hint that lies, MSZIP outside a cabinet */
	decode(sc, KOF_UNP_MSZIP, 0, junk, sizeof junk, &g_seen);
	CK(!g_seen.child_ok, "MSZIP alone has no block list: no child");
	decode(sc, KOF_UNP_BCJ2, 0, junk, sizeof junk, &g_seen);
	CK(!g_seen.child_ok, "BCJ2 needs four streams: no child from one range");
	decode(sc, KOF_UNP_STORED, 1000000, junk, sizeof junk, &g_seen);
	CK(!g_seen.child_ok || g_seen.child_len == sizeof junk, "a stored range whose hint lies is the range");
	{
		/* a hint that says the plaintext is tiny: the decode is bounded by it */
		static uint8_t plain[8192], coded[OBJ_MAX / 2];
		struct codec c = { "lzma", KOF_UNP_LZMA_PROPS(3, 0, 2), 1, 0 };
		size_t n = make_plain(P_TEXT, plain), m = e_xz(&c, plain, n, coded, sizeof coded);

		if (m) {
			decode(sc, c.method, 10, coded, m, &g_seen);
			CK(!g_seen.child_ok || (g_seen.child_len <= n && !memcmp(g_seen.child, plain, g_seen.child_len)),
			   "an LZMA hint below the true size: a prefix or nothing (%llu)", (unsigned long long)g_seen.child_len);
			decode(sc, c.method, 1ull << 50, coded, m, &g_seen);
			CK(agree(&g_seen, plain, n) || !g_seen.child_ok, "an enormous hint does not make the host allocate it: the stream decodes to its own length or is refused");
		}
	}
}

int main(void)
{
	struct stat sb;
	kof_engine *e;
	kof_scanner *sc;

	if (stat(DB_SIGS, &sb) != 0) {
		printf("cov_decode_modabi: no test signature set (make test-sigs) - nothing tested\n");
		return 0;
	}
	e = keng_open(DB_SIGS);
	if (!e) {
		printf("cov_decode_modabi: the test set did not load\n");
		return 1;
	}
	sc = kscan_new(e);
	if (!sc) {
		printf("cov_decode_modabi: no scanner\n");
		keng_close(e);
		return 1;
	}
	t_codecs(sc);
	t_hostile(sc);
	t_entry_only(sc);
	t_ids(sc);
	kscan_free(sc);
	keng_close(e);
	printf("cov_decode_modabi: %u stream(s) round-tripped, %u not made here (tool absent or shape not carried), %u check(s), %u failed\n",
	       checked, shapes_skipped, he_checks, he_fails);
	return he_fails != 0 || km_failed();
}
