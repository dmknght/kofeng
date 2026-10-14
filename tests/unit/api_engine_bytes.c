/*
 * api_engine_bytes.c - the byte-level public surface of the engine's core:
 * <kofcore.h> (bounded readers, hashes, ASCII classes), <kofcmp.h>,
 * <heapsort.h>, <entryname.h>, <kofobjname.h>, <kofhash.h> (SHA-256),
 * <kofentropy.h>.
 *
 * Every function is a small contract with a boundary the callers rely on:
 * a reader returns 0 and leaves its output alone when the window does not
 * hold the bytes, a saturating add never wraps, a classifier agrees with the
 * C locale on all 256 values. Those contracts are asserted exhaustively where
 * the domain is small (the 256-value tables) and on the edges where it is not
 * (offset + length near 2^64).
 *
 * khash_sha256_file is also driven with the paths a hostile caller supplies:
 * a directory, a missing file and an endless device. The header says
 * KOF_ERR_OPEN is returned for "not a regular file"; the endless device is
 * run in a child with an alarm, because the way that contract breaks is by
 * never returning.
 */

#include "hostile_engine.h"
#include "known_miss.h"

#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "../../libkofeng/kofcore/kofcore.h"
#include "../../libkofeng/kofcore/kofcmp.h"
#include "../../libkofeng/kofcore/heapsort.h"
#include "../../libkofeng/kofcore/entryname.h"
#include "../../libkofeng/kofcore/kofobjname.h"
#include "../../libkofeng/kofcore/kofhash.h"
#include "../../libkofeng/kofcore/kofentropy.h"

/* ---- kof_buf and the bounded readers ------------------------------------------ */

static void t_buf(void)
{
	static const uint8_t d[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	kof_buf b = kof_buf_make(d, sizeof d), e;
	uint8_t v8 = 0xaa;
	uint16_t v16 = 0xaaaa;
	uint32_t v32 = 0xaaaaaaaau;
	uint64_t v64 = 0xaaaaaaaaaaaaaaaaull;

	CK(b.p == d && b.n == 8, "kof_buf_make keeps pointer and length");
	e = kof_buf_make(NULL, 99);
	CK(e.p == NULL && e.n == 0, "a NULL pointer is an empty buffer whatever n says");
	e = kof_buf_make(d, 0);
	CK(e.p == d && e.n == 0, "a zero length keeps the pointer");

	CK(kof_in_range(b, 0, 8) && kof_in_range(b, 8, 0) && kof_in_range(b, 7, 1),
	   "whole window, empty tail, last byte are in range");
	CK(!kof_in_range(b, 9, 0), "an offset past the end is out, even for length 0");
	CK(!kof_in_range(b, 0, 9) && !kof_in_range(b, 7, 2), "one byte over is out");
	CK(!kof_in_range(b, UINT64_MAX, 1) && !kof_in_range(b, 1, UINT64_MAX) &&
	   !kof_in_range(b, UINT64_MAX, UINT64_MAX),
	   "off+len near 2^64 must not wrap into range");
	CK(!kof_in_range(kof_buf_make(NULL, 0), 0, 1), "empty buffer holds nothing");

	e = kof_slice(b, 2, 3);
	CK(e.p == d + 2 && e.n == 3, "slice points inside");
	e = kof_slice(b, 8, 0);
	CK(e.n == 0, "empty slice at the end is allowed");
	e = kof_slice(b, 6, 3);
	CK(e.p == NULL && e.n == 0, "an out of range slice is empty, not clipped");
	e = kof_slice(b, UINT64_MAX - 1, 4);
	CK(e.p == NULL && e.n == 0, "slice offset near 2^64");

	CK(kof_rd_u8(b, 7, &v8) == 1 && v8 == 8, "rd_u8 last byte");
	v8 = 0xaa;
	CK(kof_rd_u8(b, 8, &v8) == 0 && v8 == 0xaa, "rd_u8 past the end leaves out untouched");

	CK(kof_rd_u16(b, 0, 0, &v16) == 1 && v16 == 0x0201u, "rd_u16 little endian");
	CK(kof_rd_u16(b, 0, 1, &v16) == 1 && v16 == 0x0102u, "rd_u16 big endian");
	v16 = 0xaaaa;
	CK(kof_rd_u16(b, 7, 0, &v16) == 0 && v16 == 0xaaaau, "rd_u16 one byte short");
	CK(kof_rd_u32(b, 0, 0, &v32) == 1 && v32 == 0x04030201u, "rd_u32 le");
	CK(kof_rd_u32(b, 4, 1, &v32) == 1 && v32 == 0x05060708u, "rd_u32 be");
	v32 = 0xaaaaaaaau;
	CK(kof_rd_u32(b, 5, 0, &v32) == 0 && v32 == 0xaaaaaaaau, "rd_u32 short");
	CK(kof_rd_u64(b, 0, 0, &v64) == 1 && v64 == 0x0807060504030201ull, "rd_u64 le");
	CK(kof_rd_u64(b, 0, 1, &v64) == 1 && v64 == 0x0102030405060708ull, "rd_u64 be");
	v64 = 0xaaaaaaaaaaaaaaaaull;
	CK(kof_rd_u64(b, 1, 0, &v64) == 0 && v64 == 0xaaaaaaaaaaaaaaaaull,
	   "rd_u64 short leaves out untouched (no half write)");
	CK(kof_rd_u64(b, UINT64_MAX - 3, 0, &v64) == 0, "rd_u64 offset + 4 wraps: refused");

	CK(kof_rd16_or0(b, 1) == 0x0302u && kof_rd16_or0(b, 7) == 0 &&
	   kof_rd16_or0(b, UINT64_MAX) == 0, "rd16_or0");
	CK(kof_rd32_or0(b, 1) == 0x05040302u && kof_rd32_or0(b, 5) == 0, "rd32_or0");
	CK(kof_rd64_or0(b, 0) == 0x0807060504030201ull && kof_rd64_or0(b, 1) == 0,
	   "rd64_or0");
}

static void t_le(void)
{
	uint8_t m[8];
	uint64_t i;

	kof_st_le16(m, 0xbeefu);
	CK(m[0] == 0xef && m[1] == 0xbe && kof_ld_le16(m) == 0xbeefu, "st/ld le16");
	kof_st_le32(m, 0xdeadbeefu);
	CK(m[0] == 0xef && m[3] == 0xde && kof_ld_le32(m) == 0xdeadbeefu, "st/ld le32");
	kof_st_le64(m, 0x0123456789abcdefull);
	CK(m[0] == 0xef && m[7] == 0x01 && kof_ld_le64(m) == 0x0123456789abcdefull,
	   "st/ld le64");
	for (i = 0; i < 64; i++) {
		uint64_t v = 1ull << i;

		kof_st_le64(m, v);
		CK(kof_ld_le64(m) == v, "le64 single bit %u", (unsigned)i);
	}
}

/* ---- arithmetic that must saturate -------------------------------------------- */

static void t_arith(void)
{
	CK(kof_sat_add(1, 2) == 3 && kof_sat_add(UINT64_MAX, 1) == UINT64_MAX &&
	   kof_sat_add(UINT64_MAX, UINT64_MAX) == UINT64_MAX &&
	   kof_sat_add(UINT64_MAX - 1, 1) == UINT64_MAX && kof_sat_add(0, 0) == 0,
	   "sat_add");
	CK(kof_round_up(0, 8) == 0 && kof_round_up(1, 8) == 8 && kof_round_up(8, 8) == 8 &&
	   kof_round_up(9, 8) == 16 && kof_round_up(5, 0) == 5 && kof_round_up(5, 1) == 5,
	   "round_up basics, alignment 0 is the identity");
	CK(kof_round_up(UINT64_MAX, 4096) == UINT64_MAX, "round_up saturates instead of wrapping to 0");
	CK(kof_round_up(UINT64_MAX - 4094, 4096) >= UINT64_MAX - 4094,
	   "round_up never goes backwards");

	CK(kof_clip_len(100, 0, 10) == 10 && kof_clip_len(100, 95, 10) == 5 &&
	   kof_clip_len(100, 100, 10) == 0 && kof_clip_len(100, 101, 10) == 0 &&
	   kof_clip_len(100, 0, 0) == 0 && kof_clip_len(100, 10, UINT64_MAX) == 90 &&
	   kof_clip_len(100, UINT64_MAX, UINT64_MAX) == 0 && kof_clip_len(0, 0, 5) == 0,
	   "clip_len");
}

/* ---- hashes ------------------------------------------------------------------- */

static void t_hash(void)
{
	uint8_t all[256];
	unsigned i;
	uint32_t h;
	uint64_t h64;

	CK(kof_crc32("123456789", 9) == 0xcbf43926u, "crc32 check value");
	CK(kof_crc32("", 0) == 0 && kof_crc32(NULL, 0) == 0, "crc32 of nothing is 0");

	CK(kof_hash_bytes("", 0) == KOF_HASH_INIT, "fnv32 of nothing is the offset basis");
	CK(kof_hash_bytes("a", 1) == 0xe40c292cu, "fnv32 'a'");
	CK(kof_hash_bytes("foobar", 6) == 0xbf9cf968u, "fnv32 'foobar'");
	h = KOF_HASH_INIT;
	h = kof_hash_step(h, 'f');
	h = kof_hash_step(h, 'o');
	h = kof_hash_step(h, 'o');
	CK(h == kof_hash_bytes("foo", 3), "fnv32 step equals bytes");

	/*
	 * The basis is NOT the standard FNV-64 one and is pinned on purpose: the
	 * fridge writes these keys into a cache file (see the note in kofcore.h), so
	 * a "fix" here discards every cached verdict. The reference below is the
	 * FNV-1a loop over that same basis, written out independently.
	 */
	CK(KOF_HASH64_INIT == 1469598103934665603ull, "the 64-bit basis is the pinned one");
	CK(kof_hash64_bytes("", 0) == KOF_HASH64_INIT, "fnv64 of nothing");
	{
		uint64_t r = 1469598103934665603ull;
		const char *m = "foobar";
		unsigned k;

		for (k = 0; m[k]; k++)
			r = (r ^ (uint8_t)m[k]) * 1099511628211ull;
		CK(kof_hash64_bytes("foobar", 6) == r, "fnv64 'foobar' against the loop");
		CK(kof_hash64_bytes("a", 1) == (1469598103934665603ull ^ 'a') * 1099511628211ull,
		   "fnv64 'a'");
	}
	CK(kof_hash64_str("foobar") == kof_hash64_bytes("foobar", 6) &&
	   kof_hash64_str("") == KOF_HASH64_INIT, "hash64_str equals bytes over strlen");
	h64 = kof_hash64_update(KOF_HASH64_INIT, "foo", 3);
	h64 = kof_hash64_update(h64, "bar", 3);
	CK(h64 == kof_hash64_bytes("foobar", 6), "hash64_update is incremental");
	CK(kof_hash64_step(KOF_HASH64_INIT, 'a') == kof_hash64_bytes("a", 1), "hash64_step");
	CK(kof_hash64_nz(0) == 1 && kof_hash64_nz(7) == 7 && kof_hash64_nz(UINT64_MAX) == UINT64_MAX,
	   "hash64_nz only maps zero");

	for (i = 0; i < 256; i++)
		all[i] = (uint8_t)i;
	CK(kof_crc32(all, 256) == 0x29058c73u, "crc32 over every byte value");
}

static void t_fact(void)
{
	CK(kof_fact_id(NULL) == 0 && kof_fact_id("") == 0, "fact id of nothing is 0");
	CK(kof_fact_id("version") == kof_crc32("version", 7), "a bare field is the crc");
	CK(kof_fact_id("UPX.ELF.version") == kof_fact_id("version"),
	   "only the last dotted component counts");
	CK(kof_fact_id("a.") == kof_crc32("a.", 2), "a trailing dot keeps the whole text");
	CK(kof_fact_id(".x") == kof_crc32("x", 1), "a leading dot");
	CK(kverdict_fact_id("UPX.ELF.version") == kof_fact_id("version") &&
	   kverdict_fact_id(NULL) == 0, "kverdict_fact_id is the same function");
	CK(kof_fact_id("a") != kof_fact_id("b"), "distinct fields differ");
}

/* ---- ASCII classes: all 256 values against the C locale ----------------------- */

static void t_ascii(void)
{
	unsigned c;
	unsigned bad = 0;

	for (c = 0; c < 256u; c++) {
		uint8_t b = (uint8_t)c;
		int ascii = c < 128u;
		unsigned low = (c >= 'A' && c <= 'Z') ? c + 32u : c;

		if (kof_lower_byte(b) != low) bad |= 1;
		if (!!kof_is_print(b) != (c >= 0x20u && c <= 0x7eu)) bad |= 2;
		if (!!kof_is_digit(b) != (c >= '0' && c <= '9')) bad |= 4;
		if (!!kof_is_alpha(b) != (ascii && isalpha((int)c) != 0)) bad |= 8;
		if (!!kof_is_alnum(b) != (ascii && isalnum((int)c) != 0)) bad |= 16;
		if (!!kof_is_word_byte(b) != (ascii && (isalnum((int)c) != 0 || c == '_'))) bad |= 32;
		if (!!kof_is_space_byte(b) != (ascii && isspace((int)c) != 0)) bad |= 64;
		if (!!kof_is_blank_byte(b) !=
		    (c == ' ' || c == '\t' || c == '\n' || c == '\r')) bad |= 128;
		{
			int hv = kof_hex_val(b), want = -1;

			if (c >= '0' && c <= '9') want = (int)c - '0';
			else if (c >= 'a' && c <= 'f') want = (int)c - 'a' + 10;
			else if (c >= 'A' && c <= 'F') want = (int)c - 'A' + 10;
			if (hv != want) bad |= 256;
		}
		{
			int bv = kof_b64_val(b), want = -1;

			if (c >= 'A' && c <= 'Z') want = (int)c - 'A';
			else if (c >= 'a' && c <= 'z') want = (int)c - 'a' + 26;
			else if (c >= '0' && c <= '9') want = (int)c - '0' + 52;
			else if (c == '+') want = 62;
			else if (c == '/') want = 63;
			if (bv != want) bad |= 512;
		}
	}
	CK(!(bad & 1), "lower_byte matches ASCII folding, high bytes untouched");
	CK(!(bad & 2), "is_print is 0x20..0x7e");
	CK(!(bad & 4), "is_digit");
	CK(!(bad & 8), "is_alpha is ASCII only");
	CK(!(bad & 16), "is_alnum");
	CK(!(bad & 32), "is_word_byte");
	CK(!(bad & 64), "is_space_byte is the isspace set");
	CK(!(bad & 128), "is_blank_byte is space, tab, CR, LF");
	CK(!(bad & 256), "hex_val");
	CK(!(bad & 512), "b64_val");

	CK(kof_hex_byte((const uint8_t *)"7f") == 0x7f && kof_hex_byte((const uint8_t *)"Ab") == 0xab &&
	   kof_hex_byte((const uint8_t *)"g0") == -1 && kof_hex_byte((const uint8_t *)"0g") == -1 &&
	   kof_hex_byte((const uint8_t *)"00") == 0 && kof_hex_byte((const uint8_t *)"ff") == 255,
	   "hex_byte");
	CK(*kof_skip_blank("  \t\r\nx") == 'x' && *kof_skip_blank("") == 0 &&
	   *kof_skip_blank("x ") == 'x', "skip_blank stops at the first non-blank");
	{
		char *s = kof_strdup_n("abcdef", 3);

		CK(s && strcmp(s, "abc") == 0, "strdup_n copies exactly n and terminates");
		free(s);
		s = kof_strdup_n("", 0);
		CK(s && s[0] == 0, "strdup_n of nothing");
		free(s);
	}
}

/* ---- comparators and the heapsort macro ---------------------------------------- */

static inline int u32_before(const uint32_t *a, const uint32_t *b)
{
	return *a < *b;
}

KOF_HEAPSORT(hs32, uint32_t, u32_before)

static void t_sort(void)
{
	uint32_t a32[3] = { 5, 7, 5 };
	uint64_t a64[3] = { 5, UINT64_MAX, 5 };
	static uint32_t v[600], w[600];
	uint32_t n, i, round;

	CK(kof_cmp_u32(&a32[0], &a32[1]) == -1 && kof_cmp_u32(&a32[1], &a32[0]) == 1 &&
	   kof_cmp_u32(&a32[0], &a32[2]) == 0, "cmp_u32");
	a32[1] = 0xffffffffu;
	CK(kof_cmp_u32(&a32[1], &a32[0]) == 1 && kof_cmp_u32(&a32[0], &a32[1]) == -1,
	   "cmp_u32 does not subtract (no wrap at 2^31)");
	CK(kof_cmp_u64(&a64[0], &a64[1]) == -1 && kof_cmp_u64(&a64[1], &a64[0]) == 1 &&
	   kof_cmp_u64(&a64[0], &a64[2]) == 0, "cmp_u64 at 2^64-1");

	he_seed(1234);
	for (round = 0; round < 40; round++) {
		n = round < 8 ? round : he_below(600);
		for (i = 0; i < n; i++) {
			switch (round % 4) {
			case 0:  v[i] = he_below(8); break;     /* many duplicates */
			case 1:  v[i] = i; break;               /* already ordered */
			case 2:  v[i] = n - i; break;           /* reversed */
			default: v[i] = (uint32_t)he_next(); break;
			}
			w[i] = v[i];
		}
		hs32_sort(v, n);
		qsort(w, n, sizeof w[0], kof_cmp_u32);
		CK(n == 0 || memcmp(v, w, n * sizeof v[0]) == 0,
		   "heapsort agrees with qsort (round %u, n %u)", round, n);
	}
	hs32_sort(NULL, 0);
	CK(1, "heapsort over nothing is a no-op");
}

/* ---- names that try to leave their directory ----------------------------------- */

static int esc(const char *s)
{
	size_t n = strlen(s);

	return kof_name_escapes(kof_buf_make(s, n), 0, (uint32_t)n);
}

static void t_name(void)
{
	CK(esc("../x") && esc("a/../b") && esc("a\\..\\b") && esc("..") && esc("a/..") &&
	   esc("/etc/passwd") && esc("\\windows") && esc("C:foo") && esc("c:\\x"),
	   "traversal, absolute and drive letter names escape");
	CK(!esc("a/b/c") && !esc("a..b") && !esc("...") && !esc("a/.../b") && !esc(".") &&
	   !esc("a/./b") && !esc("a/..b") && !esc("a/b.."), "ordinary names do not");
	CK(!kof_name_escapes(kof_buf_make("..", 2), 0, 0), "zero length is not an escape");
	CK(!kof_name_escapes(kof_buf_make("..", 2), 0, 3),
	   "a length past the window is refused, not read");
	CK(!kof_name_escapes(kof_buf_make("..", 2), 5, 1), "an offset past the window");
	CK(!kof_name_escapes(kof_buf_make("..", 2), UINT64_MAX, 1), "offset near 2^64");
	CK(kof_name_escapes(kof_buf_make("ab..", 4), 2, 2),
	   "the name is the slice, not the buffer: '..' at offset 2");
	CK(!kof_name_escapes(kof_buf_make("..x", 3), 2, 1), "a slice that is not '..'");
	{
		/* A NUL inside the declared length is part of the name: the check is
		 * on the bytes, not on a C string. */
		static const char nul[] = { 'a', 0, '/', '.', '.' };

		CK(kof_name_escapes(kof_buf_make(nul, sizeof nul), 0, sizeof nul),
		   "a name with an embedded NUL is judged over its whole length");
	}
}

static void t_objname(void)
{
	char deep[4096];
	size_t i, p = 0;

	CK(kobj_toplevel_len("a//b//c") == 1 && kobj_toplevel_len("abc") == 3 &&
	   kobj_toplevel_len("") == 0 && kobj_toplevel_len("//x") == 0 &&
	   kobj_toplevel_len("a/b") == 3, "toplevel_len stops at the first //");
	CK(strcmp(kobj_leaf("a//b//c"), "c") == 0 && strcmp(kobj_leaf("abc"), "abc") == 0 &&
	   strcmp(kobj_leaf("a//"), "") == 0 && strcmp(kobj_leaf(""), "") == 0 &&
	   strcmp(kobj_leaf("a///b"), "/b") == 0, "leaf is what follows the last //");
	CK(kobj_depth("") == 0 && kobj_depth("a") == 0 && kobj_depth("a//b") == 1 &&
	   kobj_depth("a//b//c") == 2 && kobj_depth("a///b") == 1 && kobj_depth("////") == 2,
	   "depth counts separators left to right, non overlapping");
	CK(kobj_label(NULL) == NULL && kobj_label("") == NULL && kobj_label("abc") == NULL &&
	   kobj_label("12") == NULL && kobj_label("12:") == NULL && kobj_label(":x") == NULL,
	   "no label without digits, colon and text");
	CK(kobj_label("3:norm") && strcmp(kobj_label("3:norm"), "norm") == 0 &&
	   strcmp(kobj_label("007:x:y"), "x:y") == 0, "label is the text after digits and a colon");
	CK(strcmp(KOF_OBJ_LABEL_NORM, "norm") == 0 && strcmp(KOF_OBJ_SEP, "//") == 0 &&
	   KOF_OBJ_SEP_LEN == 2u, "separator constants");

	for (i = 0; p + 4 < sizeof deep && i < 1000; i++) {
		deep[p++] = 'x';
		deep[p++] = '/';
		deep[p++] = '/';
	}
	deep[p++] = 'z';
	deep[p] = 0;
	CK(kobj_depth(deep) == 1000 && strcmp(kobj_leaf(deep), "z") == 0 &&
	   kobj_toplevel_len(deep) == 1, "a 1000 deep chain is read in one pass");
}

/* ---- SHA-256 ------------------------------------------------------------------- */

static void t_sha(void)
{
	char hex[65], hex2[65];
	struct kof_sha256 s;
	uint8_t d[32];
	static uint8_t buf[300];
	unsigned n, i, split;

	CK(khash_sha256_bytes("", 0, hex) == 0 &&
	   strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0,
	   "sha256 of nothing");
	CK(khash_sha256_bytes("abc", 3, hex) == 0 &&
	   strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
	   "sha256 abc");
	CK(khash_sha256_bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, hex) == 0 &&
	   strcmp(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0,
	   "sha256 two-block message");
	CK(khash_sha256_bytes(NULL, 0, hex) == 0 &&
	   strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0,
	   "a NULL pointer with length 0 is the empty message");
	CK(khash_sha256_bytes("x", 1, NULL) == KOF_ERR_ARG, "no output buffer is KOF_ERR_ARG");
	CK(khash_sha256_bytes(NULL, 5, hex) == KOF_ERR_ARG, "bytes NULL with n > 0 is KOF_ERR_ARG");

	for (i = 0; i < sizeof buf; i++)
		buf[i] = (uint8_t)(i * 7u + 3u);
	/* Boundaries around the padding: 0, 1, 55, 56, 63, 64, 65, 119, 120, 128. */
	{
		static const unsigned ns[] = { 0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 255 };
		unsigned k;

		for (k = 0; k < sizeof ns / sizeof ns[0]; k++) {
			n = ns[k];
			khash_sha256_bytes(buf, n, hex);
			for (split = 0; split <= n; split += (n > 20 ? 7u : 1u)) {
				khash_sha256_init(&s);
				khash_sha256_update(&s, buf, split);
				khash_sha256_update(&s, buf + split, n - split);
				khash_sha256_final(&s, d);
				khash_sha256_hex(d, hex2);
				CK(strcmp(hex, hex2) == 0,
				   "chunked digest equals one-shot (n=%u split=%u)", n, split);
			}
			khash_sha256_init(&s);
			for (i = 0; i < n; i++)
				khash_sha256_update(&s, buf + i, 1);
			khash_sha256_update(&s, NULL, 0);
			khash_sha256_final(&s, d);
			khash_sha256_hex(d, hex2);
			CK(strcmp(hex, hex2) == 0, "byte at a time + empty update (n=%u)", n);
		}
	}
	CK(strlen(hex) == 64 && strspn(hex, "0123456789abcdef") == 64,
	   "hex is 64 lowercase digits, terminated");
	{
		/* The state is a plain struct: init resets one that was used. */
		khash_sha256_init(&s);
		khash_sha256_update(&s, "garbage", 7);
		khash_sha256_init(&s);
		khash_sha256_update(&s, "abc", 3);
		khash_sha256_final(&s, d);
		khash_sha256_hex(d, hex);
		CK(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
		   "init after use starts clean");
	}
}

static int sha_dev_zero(void *arg)
{
	char hex[65];
	uint64_t sz = 0;
	int rc;

	(void)arg;
	rc = khash_sha256_file("/dev/zero", hex, &sz);
	return rc == KOF_ERR_OPEN ? 0 : 1;
}

static int sha_fifo(void *arg)
{
	char hex[65];
	uint64_t sz = 0;

	return khash_sha256_file((const char *)arg, hex, &sz) == KOF_ERR_OPEN ? 0 : 1;
}

static void t_sha_file(void)
{
	char path[128], hex[65], ref[65];
	uint64_t size = 99;
	FILE *f;
	struct he_status st;

	snprintf(path, sizeof path, "build/test/api_engine_bytes_%d.tmp", (int)getpid());
	f = fopen(path, "wb");
	if (!f) {
		printf("  (no build/test directory: file hash cases not run)\n");
		return;
	}
	fwrite("abc", 1, 3, f);
	fclose(f);
	CK(khash_sha256_file(path, hex, &size) == 0 && size == 3, "file hash returns the size");
	khash_sha256_bytes("abc", 3, ref);
	CK(strcmp(hex, ref) == 0, "file digest equals the bytes digest");
	CK(khash_sha256_file(path, hex, NULL) == 0, "size is optional");
	remove(path);

	CK(khash_sha256_file(NULL, hex, &size) == KOF_ERR_ARG, "NULL path");
	CK(khash_sha256_file("x", NULL, &size) == KOF_ERR_ARG, "NULL out");
	CK(khash_sha256_file("build/test/definitely-not-here", hex, &size) == KOF_ERR_OPEN,
	   "missing file");
	CK(khash_sha256_file("", hex, &size) == KOF_ERR_OPEN, "empty path");
	{
		int rc = khash_sha256_file("build/test", hex, &size);

		CK(rc == KOF_ERR_OPEN || rc == KOF_ERR_READ, "a directory is refused (rc %d)", rc);
	}

	st = he_child(sha_dev_zero, NULL, 1);
	/*
	 * The header says KOF_ERR_OPEN is "could not be opened, or is not a regular
	 * file". Before the fix khash_sha256_file opened with fopen and never looked
	 * at the type, so an endless device was read until the alarm; a FIFO is the
	 * other half (the open itself blocked), checked below.
	 */
	CK(he_ok(st), "khash_sha256_file refuses a non-regular file (endless device hangs): %s", he_how(st));
	{
		char fifo[128];

		snprintf(fifo, sizeof fifo, "build/test/api_engine_bytes_%d.fifo", (int)getpid());
		if (mkfifo(fifo, 0600) == 0) {
			st = he_child(sha_fifo, fifo, 2);
			CK(he_ok(st), "khash_sha256_file refuses a FIFO without blocking the open: %s", he_how(st));
			unlink(fifo);
		}
	}
}

/* ---- entropy ------------------------------------------------------------------- */

static void t_entropy(void)
{
	static uint8_t flat[256 * 16], two[512], one[1000];
	uint32_t hist[256], e;
	unsigned i;

	CK(kentropy_eighths(NULL, 0) == 0 && kentropy_eighths("x", 0) == 0 &&
	   kentropy_eighths(NULL, 5) == 0, "no bytes carry no information");
	memset(one, 0x41, sizeof one);
	CK(kentropy_eighths(one, sizeof one) == 0, "one repeated byte is 0");
	for (i = 0; i < sizeof flat; i++)
		flat[i] = (uint8_t)i;
	e = kentropy_eighths(flat, sizeof flat);
	CK(e >= 62 && e <= 64, "a flat histogram is 8 bits = 64 eighths (got %u)", e);
	for (i = 0; i < sizeof two; i++)
		two[i] = (uint8_t)(i & 1u);
	e = kentropy_eighths(two, sizeof two);
	CK(e >= 7 && e <= 8, "two equiprobable values are 1 bit = 8 eighths (got %u)", e);

	memset(hist, 0, sizeof hist);
	kentropy_count(hist, flat, sizeof flat);
	CK(hist[0] == 16 && hist[255] == 16, "count adds");
	kentropy_count(hist, flat, sizeof flat);
	CK(hist[7] == 32, "count accumulates across calls");
	kentropy_count(hist, NULL, 0);
	CK(hist[7] == 32, "count of nothing adds nothing");
	CK(kentropy_hist(hist, 512u * 16u) == kentropy_hist(hist, 512u * 16u), "pure");
	CK(kentropy_hist(NULL, 5) == 0 && kentropy_hist(hist, 0) == 0, "hist: NULL or total 0 is 0");
	memset(hist, 0, sizeof hist);
	kentropy_count(hist, flat, sizeof flat);
	CK(kentropy_hist(hist, sizeof flat) == kentropy_eighths(flat, sizeof flat),
	   "hist route and bytes route agree");

	/*
	 * `total` is documented as the sum of the buckets. When it is smaller than one bucket
	 * the bucket is clamped to it: the per-bucket term used to go negative in unsigned
	 * arithmetic and the average was an astronomically large number, which no caller can
	 * tell from "very high entropy" (8 bits is 64 eighths).
	 */
	memset(hist, 0, sizeof hist);
	hist[0] = 100;
	e = kentropy_hist(hist, 10);
	CK(e <= 64, "kentropy_hist with total < bucket stays within 0..64 eighths (got %u)", e);
	hist[1] = 100;
	hist[200] = 3;
	e = kentropy_hist(hist, 50);
	CK(e <= 64, "and with several buckets over the total (got %u)", e);
	/* the contract case is unchanged: a total that is the sum gives the same answer as before */
	memset(hist, 0, sizeof hist);
	hist[0] = 8;
	hist[1] = 8;
	CK(kentropy_hist(hist, 16) == 8, "two equal buckets are 8 eighths (got %u)", kentropy_hist(hist, 16));
}

int main(void)
{
	t_buf();
	t_le();
	t_arith();
	t_hash();
	t_fact();
	t_ascii();
	t_sort();
	t_name();
	t_objname();
	t_sha();
	t_sha_file();
	t_entropy();
	printf("api_engine_bytes: %u checks, %u failed, %u known-miss\n",
	       he_checks, he_fails, km_known());
	return he_fails != 0 || km_failed();
}
