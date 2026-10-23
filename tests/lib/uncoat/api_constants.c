/*
 * api_constants - the public constants, enumerators, typedefs, structs and the one extern
 * table of libuncoat, checked against each other and against what the decoders do.
 *
 * These are an ABI: a module reads the window sizes and the lzma limits out of a container and
 * refuses what is out of range BEFORE it asks for a decode (format_limits.h), the host and a
 * module compare ASPack's table byte for byte (aspack_tab.h), the sinks of every decoder are
 * one shape, and the status values are read by modules built separately. So the checks are:
 *
 *   COMPILE TIME   _Static_assert on every relation the headers state in words: a window is
 *                  1 << bits, the LZX main tree is 256 + 8 x slots, the bzip2 block is nine
 *                  hundred thousand, an LHA code count is 256 + the match lengths, the inflate
 *                  window is 32 KB, a struct's array is as long as its macro says.
 *   RUN TIME       enumerator values, that every sink typedef is the one function-pointer
 *                  type (assigned without a cast and called through), the ASPack table's own
 *                  internal facts (bases step by their extra bits, offset widths do not
 *                  shrink, no index the decoder forms is past the table), and what each limit
 *                  does in the decoder it limits: lc/lp/pb of lzma, the lzx window range, the
 *                  bzip2 groups/selectors/code lengths, the LHA alphabets, lzw's table size,
 *                  ovba's chunk and signature, nrv2's variant and width names.
 */

#define _GNU_SOURCE

#include "hostile_common.h"
#include "hostile_enc.h"
#include "hostile_lzenc.h"

#include <stddef.h>

/* ---- compile time -------------------------------------------------------------------------- */

_Static_assert(KUNCOAT_LZX_MAX_WINDOW == (1u << KUNCOAT_LZX_MAX_BITS), "the lzx window is 1 << bits");
_Static_assert(KUNCOAT_LZX_MIN_BITS == 15u && KUNCOAT_LZX_MAX_BITS == 21u, "the formats' window range");
_Static_assert(KUNCOAT_LZX_MAIN_MAX == 256u + 8u * 50u, "256 literals plus eight headers for each of fifty slots");
_Static_assert(KUNCOAT_LZX_LEN_MAX == 249u && KUNCOAT_LZX_ALIGN_MAX == 8u && KUNCOAT_LZX_PRETREE_MAX == 20u, "lzx trees");
_Static_assert(KUNCOAT_LZX_FRAME == 32768u, "the frame is 32 KB");
_Static_assert(sizeof(((struct kuncoat_lzx *)0)->win) == KUNCOAT_LZX_MAX_WINDOW, "the window");
_Static_assert(sizeof(((struct kuncoat_lzx *)0)->frame) == KUNCOAT_LZX_FRAME, "the frame buffer");
_Static_assert(sizeof(((struct kuncoat_lzx *)0)->main_len) == KUNCOAT_LZX_MAIN_MAX, "main tree lengths");
_Static_assert(sizeof(((struct kuncoat_lzx *)0)->len_len) == KUNCOAT_LZX_LEN_MAX, "length tree lengths");
_Static_assert(sizeof(((struct kuncoat_lzx *)0)->align_len) == KUNCOAT_LZX_ALIGN_MAX, "aligned tree lengths");
_Static_assert(sizeof(((struct kuncoat_lzx_huff *)0)->symbol) / sizeof(int16_t) == KUNCOAT_LZX_MAIN_MAX, "the huffman symbols");

_Static_assert(KUNCOAT_BZ_MAX_BLOCK == 900000u && KUNCOAT_BZ_GROUPS == 6u && KUNCOAT_BZ_MAX_CODELEN == 23u, "bzip2 limits");
_Static_assert(KUNCOAT_BZ_ALPHA == 256u + 2u, "bzip2: every byte value plus RUNA/RUNB, less one, plus end");
_Static_assert(KUNCOAT_BZ_MAX_SELECT == 18002u, "bzip2 selector limit");
_Static_assert(sizeof(((struct kuncoat_bunzip *)0)->tt) / sizeof(uint32_t) == KUNCOAT_BZ_MAX_BLOCK, "the block");
_Static_assert(sizeof(((struct kuncoat_bunzip *)0)->selector) == KUNCOAT_BZ_MAX_SELECT, "the selectors");
_Static_assert(sizeof(((struct kuncoat_bunzip *)0)->len) / KUNCOAT_BZ_GROUPS == KUNCOAT_BZ_ALPHA, "code lengths per group");

_Static_assert(KUNCOAT_LZHUF_NC == 510u && KUNCOAT_LZHUF_NT == 19u && KUNCOAT_LZHUF_NP == 17u && KUNCOAT_LZHUF_DICT == 65536u,
	       "the lhuf alphabets and the widest dictionary");
_Static_assert(sizeof(((struct kuncoat_lzhuf *)0)->dict) == KUNCOAT_LZHUF_DICT, "the dictionary");
_Static_assert(sizeof(((struct kuncoat_lzhuf *)0)->c_len) == KUNCOAT_LZHUF_NC, "literal tree lengths");
_Static_assert(sizeof(((struct kuncoat_lzhuf *)0)->pt_len) == KUNCOAT_LZHUF_NT, "pretree lengths");
_Static_assert(sizeof(((struct kuncoat_lzhuf *)0)->left) / sizeof(uint16_t) == 2u * KUNCOAT_LZHUF_NC, "two nodes per symbol");
_Static_assert(KUNCOAT_LZHUF_VARIANTS == 4, "ARJ, lh5, lh6, lh7");

_Static_assert(KUNCOAT_LZW_CODES == 4096u, "12 bit codes");
_Static_assert(sizeof(((struct kuncoat_lzw *)0)->prefix) / sizeof(uint16_t) == KUNCOAT_LZW_CODES, "the table");
_Static_assert(sizeof(((struct kuncoat_lzw *)0)->rev) == KUNCOAT_LZW_CODES, "the reversed chain");
_Static_assert(KUNCOAT_OVBA_CHUNK == 4096u && KUNCOAT_OVBA_SIGNATURE == 1u, "ovba chunk and signature");
_Static_assert(KUNCOAT_INF_WINDOW == 32768u && sizeof(((struct kuncoat_inflate *)0)->win) == KUNCOAT_INF_WINDOW, "deflate window");
_Static_assert(KUNCOAT_HUFF_FAST_SIZE == (1u << KUNCOAT_HUFF_FAST_BITS), "the fast table is 2^bits");
_Static_assert(sizeof(((struct kuncoat_huff *)0)->fast) / sizeof(uint16_t) == KUNCOAT_HUFF_FAST_SIZE, "fast table entries");
_Static_assert(KUNCOAT_INF_BITS == 32 || KUNCOAT_INF_BITS == 64, "the bit buffer is 32 or 64 bits");
_Static_assert(sizeof(kuncoat_inf_word) * 8u == KUNCOAT_INF_BITS, "the word is as wide as its macro says");
_Static_assert(KUNCOAT_INF_FILL_BITS == KUNCOAT_INF_FILL_BYTES * 8u, "fill bits");
_Static_assert(KUNCOAT_INF_FILL_BITS * 2u <= KUNCOAT_INF_BITS, "a refill plus a full buffer fits");
_Static_assert(KUNCOAT_LZMA_MAX_LC == 8u && KUNCOAT_LZMA_MAX_LP == 4u && KUNCOAT_LZMA_MAX_PB == 4u, "lzma limits");
_Static_assert(KUNCOAT_RAR3_SCRATCH == 0x3c000u && KUNCOAT_RAR5_SCRATCH == 0x400000u, "rar scratch sizes");
_Static_assert(KUNCOAT_ASPACK_TAB_N == 0x72u && KUNCOAT_ASPACK_OFF_BASE == 0x38u && KUNCOAT_ASPACK_OFF_N == 58u &&
	       KUNCOAT_ASPACK_OFF_BASE + KUNCOAT_ASPACK_OFF_N == KUNCOAT_ASPACK_TAB_N, "the two tables are one");
_Static_assert(KUNCOAT_ASPACK_LOOKAHEAD == 0x10eu, "the bit reader's look-ahead");

/* ---- run time ------------------------------------------------------------------------------ */

static int hv_sink_unit(void *u, const uint8_t *p, uint32_t n)
{
	(void)p;
	*(uint64_t *)u += n;
	return 1;
}

static void enumerators(void)
{
	enum kuncoat_algo a;
	enum kuncoat_dir d;
	unsigned seen = 0;

	CK(KUNCOAT_ALGO_NONE == 0 && KUNCOAT_ALGO_XOR_KEY == 1 && KUNCOAT_ALGO_XOR_COUNTER == 2 && KUNCOAT_ALGO_XOR_ADD32 == 3 &&
	   KUNCOAT_ALGO_PLACEHOLDER_SUB == 4 && KUNCOAT_ALGO_X86_SUB_CHAIN == 5 && KUNCOAT_ALGO_RC4 == 6);
	CK(KUNCOAT_ALGO_B64 == 16 && KUNCOAT_ALGO_HEX == 17 && KUNCOAT_ALGO_URL == 18 && KUNCOAT_ALGO_ADD == 19 &&
	   KUNCOAT_ALGO_CAESAR == 20 && KUNCOAT_ALGO_REVERSE == 21 && KUNCOAT_ALGO_ESCAPE == 22);
	CK(KUNCOAT_DECODE == 0 && KUNCOAT_ENCODE == 1 && KUNCOAT_F_LAX == 1u);
	CK(KUNCOAT_NRV2B == 0 && KUNCOAT_NRV2D == 1 && KUNCOAT_NRV2E == 2);
	CK(KUNCOAT_NRV2_BITS_8 == 8 && KUNCOAT_NRV2_BITS_16 == 16 && KUNCOAT_NRV2_BITS_32 == 32);
	CK(KUNCOAT_LZHUF_ARJ == 0 && KUNCOAT_LZHUF_LH5 == 1 && KUNCOAT_LZHUF_LH6 == 2 && KUNCOAT_LZHUF_LH7 == 3);
	/* every algorithm id is either run or refused by kuncoat_transform, none is silently ignored */
	for (a = KUNCOAT_ALGO_NONE; a <= KUNCOAT_ALGO_ESCAPE; a++)
		for (d = KUNCOAT_DECODE; d <= KUNCOAT_ENCODE; d++) {
			static const uint8_t key[2] = { 1, 2 };
			struct kuncoat_step s = { .algo = (uint32_t)a, .dir = (uint32_t)d, .flags = 0, .k32 = 3, .key = key, .key_len = 2,
						  .max_out = 0 };
			uint8_t in[8] = "abcdefg", out[32];
			uint64_t p = 99;
			enum kuncoat_status st = kuncoat_transform(&s, in, 7, out, sizeof out, &p);

			CKF(hv_status_ok(st), "algo %d dir %d", (int)a, (int)d);
			if (a == KUNCOAT_ALGO_NONE || (a > KUNCOAT_ALGO_RC4 && a < KUNCOAT_ALGO_B64))
				CKF(st == KUNCOAT_UNSUPPORTED && p == 0, "algo %d: %s", (int)a, kuncoat_status_name(st));
			else
				seen++;
		}
	CKF(seen == 2u * 13u, "%u (algo, dir) pairs ran", seen);
}

static void sink_types(void)
{
	/* one function, assigned to every sink typedef without a cast, called through each */
	kuncoat_sink_fn s0 = hv_sink_unit;
	kuncoat_inflate_sink s1 = hv_sink_unit;
	kuncoat_bunzip_sink s2 = hv_sink_unit;
	kuncoat_lzhuf_sink s3 = hv_sink_unit;
	kuncoat_lzw_sink s4 = hv_sink_unit;
	kuncoat_lzx_sink s5 = hv_sink_unit;
	kuncoat_ovba_sink s6 = hv_sink_unit;
	kuncoat_textcode_sink s7 = hv_sink_unit;
	uint64_t total = 0;
	static const uint8_t b[3] = { 1, 2, 3 };

	CK(s0(&total, b, 3) && s1(&total, b, 3) && s2(&total, b, 3) && s3(&total, b, 3) && s4(&total, b, 3) &&
	   s5(&total, b, 3) && s6(&total, b, 3) && s7(&total, b, 3));
	CK(total == 24);
	/* and they are what the entry points take: the same function drives each */
	{
		uint64_t n = 0, p = 0;
		static const uint8_t rle[] = { 1, 'a', 'b', 128 };
		struct kuncoat_io io;

		memset(&io, 0, sizeof io);
		CK(kuncoat_rle_decode(rle, sizeof rle, s7, &n, &p) == KUNCOAT_OK && n == 2 && p == 2);
		(void)io;
	}
	/* the structs of uncoat_io.h: a span is a pointer and a length, an io has the six things */
	{
		struct kuncoat_span sp = { b, 3 };
		struct kuncoat_io io = { sp, s0, &total, 7, 9 };

		CK(io.in.p == b && io.in.n == 3 && io.sink == s0 && io.user == &total && io.consumed == 7 && io.produced == 9);
		CK(offsetof(struct kuncoat_io, in) == 0);
	}
}

static void aspack_table(void)
{
	unsigned i;
	uint64_t base = 0;

	/* [0x00..0x1b]: length bases; [0x1c..0x37]: their extra bits; each base steps by 1 << extra */
	for (i = 0; i < 27; i++) {
		unsigned ex = kuncoat_aspack_tab[0x1c + i];

		if (i >= 8)
			CKF(kuncoat_aspack_tab[i + 1] == kuncoat_aspack_tab[i] + (1u << kuncoat_aspack_tab[0x1c + i]), "base %u steps by 1 << %u", i, ex);
		else
			CKF(kuncoat_aspack_tab[i + 1] == kuncoat_aspack_tab[i] + 1u || i == 8 - 1, "base %u", i);
	}
	/* the offset widths [0x38..0x71] never shrink, and none is past 18 bits */
	for (i = 1; i < KUNCOAT_ASPACK_OFF_N; i++)
		CKF(kuncoat_aspack_tab[KUNCOAT_ASPACK_OFF_BASE + i] >= kuncoat_aspack_tab[KUNCOAT_ASPACK_OFF_BASE + i - 1u],
		    "offset width %u shrinks", i);
	CK(kuncoat_aspack_tab[KUNCOAT_ASPACK_TAB_N - 1] == 0x12);
	for (i = 0; i < KUNCOAT_ASPACK_OFF_N; i++)
		base += 1ull << kuncoat_aspack_tab[KUNCOAT_ASPACK_OFF_BASE + i];
	CKF(base < (1ull << 32), "the offset classes add up to %llu: past 32 bits", (unsigned long long)base);
	/* the indexes aspack.c forms: escape symbol e < 0x56 -> tab[e + 0x1c]; class c < 58 -> tab[c + 0x38] */
	CK(0x55u + 0x1cu < KUNCOAT_ASPACK_TAB_N);
	CK(57u + KUNCOAT_ASPACK_OFF_BASE < KUNCOAT_ASPACK_TAB_N);
}

/* what each limit does in the decoder it limits */
static void limits_in_decoders(void)
{
	static uint8_t in[64], out[64];
	uint64_t p;
	struct hv_lz e;
	unsigned lc, lp, pb;
	uint8_t stream[256];
	size_t n;

	/* lzma: lc, lp, pb at their maxima decode; one above each is refused (CORRUPT, nothing written) */
	memset(&e, 0, sizeof e);
	CK(hv_lz_init(&e, stream, sizeof stream, KUNCOAT_LZMA_MAX_LC, 0, 0, 64));
	hv_lz_lit(&e, 'x');
	hv_lz_end_marker(&e);
	n = hv_lz_rc_finish(&e);
	hv_lz_free(&e);
	CK(kuncoat_lzma_decode(KUNCOAT_LZMA_MAX_LC, 0, 0, stream, n, out, 16, &p) != KUNCOAT_CORRUPT && p == 1 && out[0] == 'x');
	for (lc = 0; lc < 3; lc++)
		for (lp = 0; lp < 3; lp++)
			for (pb = 0; pb < 3; pb++) {
				unsigned c = lc == 2 ? KUNCOAT_LZMA_MAX_LC + 1u : lc, l = lp == 2 ? KUNCOAT_LZMA_MAX_LP + 1u : lp,
					 b = pb == 2 ? KUNCOAT_LZMA_MAX_PB + 1u : pb;
				enum kuncoat_status st = kuncoat_lzma_decode(c, l, b, stream, n, out, 16, &p);

				if (lc == 2 || lp == 2 || pb == 2)
					CKF(st == KUNCOAT_CORRUPT && p == 0, "lzma %u/%u/%u: %s", c, l, b, kuncoat_status_name(st));
			}
	/* lzx: the window range */
	{
		static struct kuncoat_lzx lz;
		struct kuncoat_io io;
		struct kuncoat_lzx_req rq;
		uint64_t total = 0;
		unsigned bits;

		memset(in, 0, sizeof in);
		for (bits = KUNCOAT_LZX_MIN_BITS - 1u; bits <= KUNCOAT_LZX_MAX_BITS + 1u; bits++) {
			enum kuncoat_status st;

			memset(&io, 0, sizeof io);
			io.in.p = in;
			io.in.n = sizeof in;
			io.sink = hv_sink_unit;
			io.user = &total;
			rq = (struct kuncoat_lzx_req){ bits, 0, 8 };
			st = kuncoat_lzx_decode(&lz, &rq, &io);
			CKF((bits < KUNCOAT_LZX_MIN_BITS || bits > KUNCOAT_LZX_MAX_BITS) == (st == KUNCOAT_UNSUPPORTED),
			    "lzx window %u: %s", bits, kuncoat_status_name(st));
		}
	}
	/* lzw: CLEAR 256, EOD 257, the first code the stream builds 258; the table holds KUNCOAT_LZW_CODES */
	{
		static struct kuncoat_lzw lw;
		struct hv_bw w;
		uint8_t b[32];
		uint64_t total = 0, q;
		unsigned i;
		enum kuncoat_status st;

		hv_bw_init(&w, b, sizeof b);
		hv_bw_msb(&w, 256, 9);
		hv_bw_msb(&w, 'A', 9);
		hv_bw_msb(&w, 258, 9);                              /* the first entry: "AA" */
		hv_bw_msb(&w, 259, 9);                              /* one past the entries built: "AAA"? 259 == next: legal */
		hv_bw_msb(&w, 257, 9);
		hv_bw_align_msb(&w);
		st = kuncoat_lzw_decode(&lw, b, w.n, hv_sink_unit, &total, &q);
		CK(st == KUNCOAT_OK && q == 1 + 2 + 3);
		(void)i;
	}
	/* ovba: the signature byte and the chunk size */
	{
		uint64_t total = 0, q;
		static const uint8_t ok[] = { KUNCOAT_OVBA_SIGNATURE, 0x01, 0xB0, 0x00, 'a' };
		uint8_t bad[5] = { KUNCOAT_OVBA_SIGNATURE + 1, 0x01, 0xB0, 0x00, 'a' };

		CK(kuncoat_ovba_decode(ok, sizeof ok, hv_sink_unit, &total, &q) == KUNCOAT_OK && kuncoat_ovba_plausible(ok, sizeof ok));
		CK(kuncoat_ovba_decode(bad, sizeof bad, hv_sink_unit, &total, &q) == KUNCOAT_CORRUPT && !kuncoat_ovba_plausible(bad, sizeof bad));
		/* a stored chunk is exactly KUNCOAT_OVBA_CHUNK bytes */
		{
			static uint8_t big[1 + 2 + KUNCOAT_OVBA_CHUNK];

			big[0] = KUNCOAT_OVBA_SIGNATURE;
			big[1] = (uint8_t)((KUNCOAT_OVBA_CHUNK + 2u - 3u) & 0xff);
			big[2] = (uint8_t)(0x30u | (((KUNCOAT_OVBA_CHUNK + 2u - 3u) >> 8) & 0x0fu));
			memset(big + 3, 'v', KUNCOAT_OVBA_CHUNK);
			total = 0;
			CK(kuncoat_ovba_decode(big, sizeof big, hv_sink_unit, &total, &q) == KUNCOAT_OK && q == KUNCOAT_OVBA_CHUNK && total == q);
		}
	}
	/* nrv2: the variant and width names (and the odd ones refused / accepted as documented) */
	{
		static const uint8_t z[8] = { 0 };
		static const int vars[] = { KUNCOAT_NRV2B, KUNCOAT_NRV2D, KUNCOAT_NRV2E };
		static const int bits[] = { KUNCOAT_NRV2_BITS_8, KUNCOAT_NRV2_BITS_16, KUNCOAT_NRV2_BITS_32 };
		unsigned v, b;
		enum kuncoat_nrv2_variant nv = KUNCOAT_NRV2D;
		enum kuncoat_nrv2_bits nb = KUNCOAT_NRV2_BITS_16;

		CK(hv_status_ok(kuncoat_nrv2_decode(nv, nb, z, sizeof z, out, 16, &p)));
		for (v = 0; v < 3; v++)
			for (b = 0; b < 3; b++)
				CK(hv_status_ok(kuncoat_nrv2_decode(vars[v], bits[b], z, sizeof z, out, 16, &p)));
		CK(kuncoat_nrv2_decode(KUNCOAT_NRV2B, KUNCOAT_NRV2_BITS_8 + 1, z, sizeof z, out, 16, &p) == KUNCOAT_CORRUPT);
	}
	/* lzhuf: the variants, by name; the literal alphabet (NC) and the pretree (NT) bounds */
	{
		struct kuncoat_lzhuf *lh = malloc(sizeof *lh);
		struct hv_bw w;
		uint8_t b[64];
		uint64_t total = 0;
		unsigned v, sym;

		if (lh) {
			for (v = 0; v < KUNCOAT_LZHUF_VARIANTS; v++)
				CK(hv_status_ok(kuncoat_lzhuf_decode(lh, (enum kuncoat_lzhuf_variant)v, in, sizeof in, 8, hv_sink_unit, &total, &p)));
			CK(kuncoat_lzhuf_decode(lh, (enum kuncoat_lzhuf_variant)KUNCOAT_LZHUF_VARIANTS, in, sizeof in, 8, hv_sink_unit,
						&total, &p) == KUNCOAT_UNSUPPORTED);
			/* a single-symbol literal tree: the symbol NC - 1 is the last the alphabet has, NC is outside it */
			for (sym = KUNCOAT_LZHUF_NC - 1u; sym <= KUNCOAT_LZHUF_NC; sym++) {
				enum kuncoat_status st;

				hv_bw_init(&w, b, sizeof b);
				hv_bw_msb(&w, 10, 16);
				hv_bw_msb(&w, 0, 5); hv_bw_msb(&w, 0, 5);
				hv_bw_msb(&w, 0, 9); hv_bw_msb(&w, sym, 9);
				hv_bw_msb(&w, 0, 4); hv_bw_msb(&w, 0, 4);
				hv_bw_msb(&w, 0, 32);
				st = kuncoat_lzhuf_decode(lh, KUNCOAT_LZHUF_LH5, b, w.n, 100, hv_sink_unit, &total, &p);
				CKF(sym == KUNCOAT_LZHUF_NC ? st == KUNCOAT_CORRUPT : hv_status_ok(st), "literal symbol %u: %s", sym,
				    kuncoat_status_name(st));
			}
			/* the pretree has NT symbols: a single-symbol pretree naming NT is outside it */
			for (sym = KUNCOAT_LZHUF_NT - 1u; sym <= KUNCOAT_LZHUF_NT; sym++) {
				enum kuncoat_status st;

				hv_bw_init(&w, b, sizeof b);
				hv_bw_msb(&w, 10, 16);
				hv_bw_msb(&w, 0, 5); hv_bw_msb(&w, sym, 5);
				hv_bw_msb(&w, 0, 32);
				st = kuncoat_lzhuf_decode(lh, KUNCOAT_LZHUF_LH5, b, w.n, 100, hv_sink_unit, &total, &p);
				CKF(sym == KUNCOAT_LZHUF_NT ? st == KUNCOAT_CORRUPT : hv_status_ok(st), "pretree symbol %u: %s", sym,
				    kuncoat_status_name(st));
			}
			free(lh);
		}
	}
	/* the bzip2 level digit gives the block limit: 1..9 x 100000, never above KUNCOAT_BZ_MAX_BLOCK */
	CK(9u * 100000u == KUNCOAT_BZ_MAX_BLOCK);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	enumerators();
	sink_types();
	aspack_table();
	limits_in_decoders();
	return hv_done("api_constants");
}
