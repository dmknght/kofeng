/*
 * hostile_enc.h - the ENCODERS the hostile_*.c and api_*.c tests of libuncoat build
 * their valid streams with.
 *
 * Why the tests carry encoders at all: no fixture file may live in the tree, so
 * every input is made in memory by the test that uses it. An encoder written
 * here is also an independent statement of the format, which the decoder under
 * test is then checked against - a decoder wrong in the same way as its author's
 * reading of the format passes a test made from the decoder's own output and
 * fails one made from an encoder written from the specification.
 *
 * Each encoder is the smallest one that produces every construct the decoder has
 * to read (literals, short and long matches, stored blocks, ...). None of them is
 * a good compressor.
 */

#ifndef HOSTILE_ENC_H
#define HOSTILE_ENC_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* The feedback cipher's encoder, written here: c = p ^ key; key += p. */
static inline size_t enc_add32(const uint32_t *pt, size_t nd, uint32_t key, uint8_t *out)
{
	size_t i;

	for (i = 0; i < nd; i++) {
		uint32_t c = pt[i] ^ key;

		out[4 * i] = (uint8_t)c;
		out[4 * i + 1] = (uint8_t)(c >> 8);
		out[4 * i + 2] = (uint8_t)(c >> 16);
		out[4 * i + 3] = (uint8_t)(c >> 24);
		key += pt[i];
	}
	return nd * 4u;
}

/* sub eax,imm; and eax,imm; push eax: the chain that builds a payload on the stack. */
static inline size_t enc_chain(const uint32_t *pt, size_t nd, uint8_t *out)
{
	size_t at = 0, j;
	uint32_t eax = 0;

	out[at++] = 0x25; out[at++] = 0x4a; out[at++] = 0x4d; out[at++] = 0x4e; out[at++] = 0x55;
	out[at++] = 0x25; out[at++] = 0x35; out[at++] = 0x32; out[at++] = 0x31; out[at++] = 0x2a;
	for (j = nd; j-- > 0;) {
		uint32_t imm = eax - pt[j];

		out[at++] = 0x2d;
		out[at++] = (uint8_t)imm; out[at++] = (uint8_t)(imm >> 8);
		out[at++] = (uint8_t)(imm >> 16); out[at++] = (uint8_t)(imm >> 24);
		eax = pt[j];
		out[at++] = 0x50;
	}
	return at;
}


/* ---- bit writers ---------------------------------------------------------------- */

/* LSB first: DEFLATE (and bzip2's opposite, MSB first, below). `p` is caller memory
 * of `cap` bytes; n counts whole bytes written; a write past cap is dropped and
 * `over` is set so a test sizing a buffer wrong is told. */
struct hv_bw {
	uint8_t  *p;
	size_t    cap, n;
	uint64_t  acc;
	unsigned  nb;
	int       over;
};

static inline void hv_bw_init(struct hv_bw *w, uint8_t *p, size_t cap)
{
	w->p = p; w->cap = cap; w->n = 0; w->acc = 0; w->nb = 0; w->over = 0;
}

static inline void hv_bw_byte(struct hv_bw *w, uint8_t b)
{
	if (w->n < w->cap)
		w->p[w->n] = b;
	else
		w->over = 1;
	w->n++;
}

/* `n` low bits of v, least significant bit first. */
static inline void hv_bw_lsb(struct hv_bw *w, uint32_t v, unsigned n)
{
	w->acc |= (uint64_t)(v & (n >= 32 ? 0xffffffffu : ((1u << n) - 1u))) << w->nb;
	w->nb += n;
	while (w->nb >= 8) {
		hv_bw_byte(w, (uint8_t)w->acc);
		w->acc >>= 8;
		w->nb -= 8;
	}
}

/* `n` low bits of v, most significant bit first. */
static inline void hv_bw_msb(struct hv_bw *w, uint32_t v, unsigned n)
{
	while (n--) {
		w->acc = (w->acc << 1) | ((v >> n) & 1u);
		if (++w->nb == 8) {
			hv_bw_byte(w, (uint8_t)w->acc);
			w->acc = 0;
			w->nb = 0;
		}
	}
}

/* Pad with zero bits to a byte boundary (either order: zeros are zeros). */
static inline void hv_bw_align_lsb(struct hv_bw *w)
{
	if (w->nb)
		hv_bw_lsb(w, 0, 8u - w->nb);
}

static inline void hv_bw_align_msb(struct hv_bw *w)
{
	if (w->nb)
		hv_bw_msb(w, 0, 8u - w->nb);
}

/* ---- DEFLATE (RFC 1951): stored, fixed Huffman, dynamic Huffman ------------------ */

static inline void hv_defl_stored(struct hv_bw *w, const uint8_t *d, size_t n, int last)
{
	size_t i;

	hv_bw_lsb(w, last ? 1u : 0u, 1);
	hv_bw_lsb(w, 0, 2);
	hv_bw_align_lsb(w);
	hv_bw_byte(w, (uint8_t)n);
	hv_bw_byte(w, (uint8_t)(n >> 8));
	hv_bw_byte(w, (uint8_t)~n);
	hv_bw_byte(w, (uint8_t)(~n >> 8));
	for (i = 0; i < n; i++)
		hv_bw_byte(w, d[i]);
}

/* A length (3..258) as its symbol 257..285 and the extra bits. */
static inline void hv_len_code(unsigned len, unsigned *sym, unsigned *extra, unsigned *nex)
{
	static const unsigned base[29] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35,
					   43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
	static const unsigned ex[29] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4,
					 4, 4, 5, 5, 5, 5, 0 };
	unsigned s = 28;

	while (base[s] > len)
		s--;
	*sym = 257u + s;
	*extra = len - base[s];
	*nex = ex[s];
}

/* A distance (1..32768) as its symbol 0..29 and the extra bits. */
static inline void hv_dist_code(unsigned dist, unsigned *sym, unsigned *extra, unsigned *nex)
{
	static const unsigned base[30] = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257,
					   385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289,
					   16385, 24577 };
	static const unsigned ex[30] = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9,
					 10, 10, 11, 11, 12, 12, 13, 13 };
	unsigned s = 29;

	while (base[s] > dist)
		s--;
	*sym = s;
	*extra = dist - base[s];
	*nex = ex[s];
}

/* A canonical code, MSB first, written into an LSB-first stream. */
static inline void hv_bw_code(struct hv_bw *w, unsigned code, unsigned len)
{
	unsigned i, r = 0;

	for (i = 0; i < len; i++)
		r |= ((code >> i) & 1u) << (len - 1u - i);
	hv_bw_lsb(w, r, len);
}

/* The fixed code's symbol (0..287). */
static inline void hv_defl_fsym(struct hv_bw *w, unsigned sym)
{
	if (sym < 144u)
		hv_bw_code(w, 0x30u + sym, 8);
	else if (sym < 256u)
		hv_bw_code(w, 0x190u + sym - 144u, 9);
	else if (sym < 280u)
		hv_bw_code(w, sym - 256u, 7);
	else
		hv_bw_code(w, 0xC0u + sym - 280u, 8);
}

static inline void hv_defl_fmatch(struct hv_bw *w, unsigned len, unsigned dist)
{
	unsigned sym, ex, nex;

	hv_len_code(len, &sym, &ex, &nex);
	hv_defl_fsym(w, sym);
	hv_bw_lsb(w, ex, nex);
	hv_dist_code(dist, &sym, &ex, &nex);
	hv_bw_code(w, sym, 5);
	hv_bw_lsb(w, ex, nex);
}

/* One fixed-Huffman block of `d`, with greedy matches over the last `win` bytes. The
 * candidate is the most recent position that hashes alike, so the matches are real
 * and the search is linear. */
static inline void hv_defl_fixed(struct hv_bw *w, const uint8_t *d, size_t n, int last,
				 size_t win)
{
	static int32_t head[65536];
	size_t i = 0, k;

	for (k = 0; k < 65536; k++)
		head[k] = -1;
	hv_bw_lsb(w, last ? 1u : 0u, 1);
	hv_bw_lsb(w, 1, 2);
	while (i < n) {
		size_t best = 0, bd = 0;
		uint32_t h = 0;

		if (i + 3 <= n) {
			h = ((uint32_t)d[i] * 40503u ^ (uint32_t)d[i + 1] * 9973u ^ (uint32_t)d[i + 2]) & 0xffffu;
			if (head[h] >= 0 && i - (size_t)head[h] <= win) {
				size_t j = (size_t)head[h], l = 0;

				while (l < 258 && i + l < n && d[j + l] == d[i + l])
					l++;
				best = l;
				bd = i - j;
			}
		}
		if (best >= 3) {
			hv_defl_fmatch(w, (unsigned)best, (unsigned)bd);
			for (k = 0; k < best; k++)
				if (i + k + 3 <= n)
					head[((uint32_t)d[i + k] * 40503u ^ (uint32_t)d[i + k + 1] * 9973u ^
					      (uint32_t)d[i + k + 2]) & 0xffffu] = (int32_t)(i + k);
			i += best;
		} else {
			if (i + 3 <= n)
				head[h] = (int32_t)i;
			hv_defl_fsym(w, d[i++]);
		}
	}
	hv_defl_fsym(w, 256);
}

/* Canonical codes from lengths (RFC 1951 3.2.2). Over-subscribed input is assigned
 * anyway (the codes simply collide): the tests that want that write it on purpose. */
static inline void hv_canon(const uint8_t *len, unsigned n, uint16_t *code)
{
	unsigned count[16] = { 0 }, next[16], i, c = 0;

	for (i = 0; i < n; i++)
		count[len[i]]++;
	count[0] = 0;
	for (i = 1; i < 16; i++) {
		c = (c + count[i - 1]) << 1;
		next[i] = c;
	}
	for (i = 0; i < n; i++)
		code[i] = len[i] ? (uint16_t)next[len[i]]++ : 0;
}

/*
 * A dynamic block's tables. The code-length alphabet is fixed here: symbols 0..12 get
 * four bits and 13..18 five, which is complete (13/16 + 6/32), so any code length 0..15
 * and the run codes 16, 17, 18 can be written with it.
 */
struct hv_dyn {
	uint8_t  ll[288], dl[32];
	uint16_t lc[288], dc[32];
};

static inline void hv_dyn_begin(struct hv_bw *w, struct hv_dyn *t, int last, const uint8_t *ll,
				unsigned nl, const uint8_t *dl, unsigned nd, int rle)
{
	static const uint8_t order[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
	uint8_t clen[19], all[320];
	uint16_t ccode[19];
	unsigned i, tot = nl + nd;

	memset(t, 0, sizeof *t);
	memcpy(t->ll, ll, nl);
	memcpy(t->dl, dl, nd);
	hv_canon(t->ll, nl, t->lc);
	hv_canon(t->dl, nd, t->dc);
	for (i = 0; i < 19; i++)
		clen[i] = i <= 12 ? 4 : 5;
	hv_canon(clen, 19, ccode);
	memcpy(all, ll, nl);
	memcpy(all + nl, dl, nd);
	hv_bw_lsb(w, last ? 1u : 0u, 1);
	hv_bw_lsb(w, 2, 2);
	hv_bw_lsb(w, nl - 257u, 5);
	hv_bw_lsb(w, nd - 1u, 5);
	hv_bw_lsb(w, 15, 4);                     /* HCLEN: all 19 lengths */
	for (i = 0; i < 19; i++)
		hv_bw_lsb(w, clen[order[i]], 3);
	for (i = 0; i < tot;) {
		unsigned run = 1;

		while (rle && i + run < tot && all[i + run] == all[i] && run < 138)
			run++;
		if (rle && all[i] == 0 && run >= 11) {
			hv_bw_code(w, ccode[18], clen[18]);
			hv_bw_lsb(w, run - 11u, 7);
			i += run;
		} else if (rle && all[i] == 0 && run >= 3) {
			run = run > 10 ? 10 : run;
			hv_bw_code(w, ccode[17], clen[17]);
			hv_bw_lsb(w, run - 3u, 3);
			i += run;
		} else if (rle && i > 0 && all[i] == all[i - 1] && run >= 3) {
			run = run > 6 ? 6 : run;
			hv_bw_code(w, ccode[16], clen[16]);
			hv_bw_lsb(w, run - 3u, 2);
			i += run;
		} else {
			hv_bw_code(w, ccode[all[i]], clen[all[i]]);
			i++;
		}
	}
}

static inline void hv_dyn_sym(struct hv_bw *w, const struct hv_dyn *t, unsigned sym)
{
	hv_bw_code(w, t->lc[sym], t->ll[sym]);
}

static inline void hv_dyn_match(struct hv_bw *w, const struct hv_dyn *t, unsigned len, unsigned dist)
{
	unsigned sym, ex, nex;

	hv_len_code(len, &sym, &ex, &nex);
	hv_dyn_sym(w, t, sym);
	hv_bw_lsb(w, ex, nex);
	hv_dist_code(dist, &sym, &ex, &nex);
	hv_bw_code(w, t->dc[sym], t->dl[sym]);
	hv_bw_lsb(w, ex, nex);
}

/* A valid pair of complete tables over all 286 symbols: literals 0..143 eight bits,
 * 144..255 nine, 256..281 seven, 282..285 eight (26/128 + 4/256 = 28/128, which
 * completes the code); distances 0,1 four bits and 2..29 five (2/16 + 28/32). */
static inline void hv_dyn_std_tables(uint8_t *ll, uint8_t *dl)
{
	unsigned i;

	for (i = 0; i < 286; i++)
		ll[i] = i < 144 ? 8 : i < 256 ? 9 : i < 282 ? 7 : 8;
	for (i = 0; i < 30; i++)
		dl[i] = i < 2 ? 4 : 5;
}

/* Finish: pad the last byte. */
static inline size_t hv_defl_end(struct hv_bw *w)
{
	hv_bw_align_lsb(w);
	return w->n;
}

/* A block of the gzip tool's output: header (10 bytes, plus the name field if the
 * flag is set) and 8-byte trailer removed. Returns the raw deflate length or 0. */
static inline size_t hv_gzip_raw(const uint8_t *gz, size_t n, size_t *off)
{
	size_t at = 10;

	if (n < 18 || gz[0] != 0x1f || gz[1] != 0x8b || gz[2] != 8)
		return 0;
	if (gz[3] & 8) {
		while (at < n && gz[at])
			at++;
		at++;
	}
	if (at + 8 >= n)
		return 0;
	*off = at;
	return n - at - 8;
}

/* ---- the text codings (PDF): ASCII85, ASCIIHex, RunLength -------------------------- */

/* ASCII85 with the "~>" terminator; wrap > 0 puts a newline every `wrap` characters. */
static inline size_t hv_a85_enc(const uint8_t *d, size_t n, uint8_t *out, size_t cap, unsigned wrap)
{
	size_t i, o = 0, col = 0;

#define A85PUT(ch) do { if (o < cap) out[o] = (uint8_t)(ch); o++; \
		if (wrap && ++col == wrap) { if (o < cap) out[o] = '\n'; o++; col = 0; } } while (0)
	for (i = 0; i < n; i += 4) {
		size_t k = n - i < 4 ? n - i : 4, j;
		uint32_t v = 0;
		char c[5];

		for (j = 0; j < 4; j++)
			v = (v << 8) | (j < k ? d[i + j] : 0u);
		if (k == 4 && v == 0) {
			A85PUT('z');
			continue;
		}
		for (j = 5; j-- > 0;) {
			c[j] = (char)('!' + v % 85u);
			v /= 85u;
		}
		for (j = 0; j < k + 1; j++)
			A85PUT(c[j]);
	}
	A85PUT('~');
	A85PUT('>');
#undef A85PUT
	return o;
}

/* ASCIIHex with '>' at the end; sep != 0 is put between bytes. */
static inline size_t hv_ahx_enc(const uint8_t *d, size_t n, uint8_t *out, size_t cap, char sep)
{
	static const char hx[] = "0123456789abcdef";
	size_t i, o = 0;

	for (i = 0; i < n; i++) {
		if (o + 3 <= cap) {
			out[o] = (uint8_t)hx[d[i] >> 4];
			out[o + 1] = (uint8_t)hx[d[i] & 15u];
		}
		o += 2;
		if (sep && i + 1 < n) {
			if (o < cap)
				out[o] = (uint8_t)sep;
			o++;
		}
	}
	if (o < cap)
		out[o] = '>';
	return o + 1;
}

/* RunLength: runs of 3+ equal bytes as repeats, the rest as literal runs, then 128. */
static inline size_t hv_rle_enc(const uint8_t *d, size_t n, uint8_t *out, size_t cap)
{
	size_t i = 0, o = 0, lit = 0, j;

#define RLEPUT(b) do { if (o < cap) out[o] = (uint8_t)(b); o++; } while (0)
	while (i < n) {
		size_t run = 1;

		while (i + run < n && d[i + run] == d[i] && run < 128)
			run++;
		if (run >= 3) {
			if (lit) {
				RLEPUT(lit - 1);
				for (j = 0; j < lit; j++)
					RLEPUT(d[i - lit + j]);
				lit = 0;
			}
			RLEPUT(257 - run);
			RLEPUT(d[i]);
			i += run;
			continue;
		}
		lit++;
		i++;
		if (lit == 128) {
			RLEPUT(127);
			for (j = 0; j < lit; j++)
				RLEPUT(d[i - lit + j]);
			lit = 0;
		}
	}
	if (lit) {
		RLEPUT(lit - 1);
		for (j = 0; j < lit; j++)
			RLEPUT(d[i - lit + j]);
	}
	RLEPUT(128);
#undef RLEPUT
	return o;
}

/* ---- LZW as PDF/TIFF write it: MSB first codes, early change --------------------------- */

static inline size_t hv_lzw_enc(const uint8_t *d, size_t n, uint8_t *out, size_t cap)
{
	static int16_t dict[4096 * 256];
	struct hv_bw w;
	unsigned width = 9, next = 258;
	size_t i = 0, k;
	int32_t cur;

	for (k = 0; k < sizeof dict / sizeof dict[0]; k++)
		dict[k] = -1;
	hv_bw_init(&w, out, cap);
	hv_bw_msb(&w, 256, width);
	if (!n) {
		hv_bw_msb(&w, 257, width);
		hv_bw_align_msb(&w);
		return w.n;
	}
	cur = d[i++];
	while (i < n) {
		unsigned c = d[i];
		int16_t hit = dict[(size_t)cur * 256u + c];

		if (hit >= 0) {
			cur = hit;
			i++;
			continue;
		}
		hv_bw_msb(&w, (uint32_t)cur, width);
		dict[(size_t)cur * 256u + c] = (int16_t)next++;
		if (next >= (1u << width) && width < 12)
			width++;
		if (next >= 4094) {
			hv_bw_msb(&w, 256, width);
			for (k = 0; k < sizeof dict / sizeof dict[0]; k++)
				dict[k] = -1;
			width = 9;
			next = 258;
		}
		cur = d[i++];
	}
	hv_bw_msb(&w, (uint32_t)cur, width);
	next++;
	if (next >= (1u << width) && width < 12)
		width++;
	hv_bw_msb(&w, 257, width);
	hv_bw_align_msb(&w);
	return w.n;
}

/* ---- MS-OVBA compressed container --------------------------------------------------------- */

/* The offset field width the decoder and the specification share. */
static inline unsigned hv_ovba_bits(unsigned produced)
{
	unsigned bits = 4, span = 16;

	while (span < produced && bits < 12) {
		bits++;
		span <<= 1;
	}
	return bits;
}

/* One chunk of up to 4096 bytes, compressed (raw == 0) or stored (raw != 0). */
static inline size_t hv_ovba_chunk(const uint8_t *d, size_t n, uint8_t *out, size_t cap, int raw)
{
	size_t o = 2, i = 0, flagpos = 0;
	unsigned nflag = 8;

	if (raw) {
		size_t k;

		for (k = 0; k < 4096; k++)
			if (o + k < cap)
				out[o + k] = k < n ? d[k] : 0;
		out[0] = (uint8_t)((4096u + 2u - 3u) & 0xff);
		out[1] = (uint8_t)(0x30u | (((4096u + 2u - 3u) >> 8) & 0x0f));
		return 2 + 4096;
	}
	while (i < n) {
		unsigned bits = hv_ovba_bits((unsigned)i), best = 0, bo = 0, maxlen, k;

		if (nflag == 8) {
			flagpos = o;
			if (o < cap)
				out[o] = 0;
			o++;
			nflag = 0;
		}
		maxlen = (0xffffu >> bits) + 3u;
		if (i > 0)
			for (k = 1; k <= i && k <= (1u << bits); k++) {
				unsigned l = 0;

				while (i + l < n && l < maxlen && d[i + l] == d[i + l - k])
					l++;
				if (l > best) {
					best = l;
					bo = k;
				}
			}
		if (best >= 3) {
			uint16_t tok = (uint16_t)(((bo - 1u) << (16u - bits)) | (best - 3u));

			if (o + 1 < cap) {
				out[o] = (uint8_t)tok;
				out[o + 1] = (uint8_t)(tok >> 8);
			}
			o += 2;
			out[flagpos] = (uint8_t)(out[flagpos] | (1u << nflag));
			i += best;
		} else {
			if (o < cap)
				out[o] = d[i];
			o++;
			i++;
		}
		nflag++;
	}
	{
		unsigned sz = (unsigned)(o - 3u);

		out[0] = (uint8_t)sz;
		out[1] = (uint8_t)(0xB0u | ((sz >> 8) & 0x0fu));
	}
	return o;
}

/* A whole container: signature and chunks of 4096. */
static inline size_t hv_ovba_enc(const uint8_t *d, size_t n, uint8_t *out, size_t cap)
{
	size_t o = 1, i = 0;

	out[0] = 1;
	while (i < n || (n == 0 && i == 0)) {
		size_t k = n - i < 4096 ? n - i : 4096;

		if (!n)
			break;
		o += hv_ovba_chunk(d + i, k, out + o, cap - o, 0);
		i += k;
	}
	return o;
}

#endif /* HOSTILE_ENC_H */
