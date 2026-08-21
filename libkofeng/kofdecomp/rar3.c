/*
 * rar3.c - RAR 2.9/3.x LZ decoding.
 *
 * THE OUTPUT IS THE WINDOW.
 *
 * RAR keeps a circular dictionary and flushes it as it fills. This decodes into the
 * caller's buffer instead and lets back references reach into what has already been
 * written, which is what inflate.c and lzma.c here do and for the same reason: an
 * entry is decoded whole into a buffer the host has already bounded, so a second
 * copy of the window would be a megabyte of state and a modulo on every byte to
 * arrive at the same bytes. A distance is then valid exactly when it is no larger
 * than the output so far, which is one comparison and is also the security check.
 *
 * THE BIT READER IS BIG ENDIAN AND PEEKS SIXTEEN.
 *
 * Every field in this format is read as "the top N bits of the next sixteen", then
 * the cursor is advanced by N. That is the shape RAR's own reader has, and matching
 * it exactly is the difference between a decoder that works and one that drifts a
 * bit at a time - so the two operations are kept separate here rather than fused
 * into a single read-and-advance that would be tidier and would not be the format.
 */

#include "rar3.h"

#include <string.h>

#include "../core/kofcore.h"   /* kof_crc32, to name a filter by its code */

/* Table sizes, from the format. */
#define NC   299u                 /* literals and lengths */
#define DC    60u                 /* distances */
#define LDC   17u                 /* low bits of large distances */
#define RC    28u                 /* lengths for repeated distances */
#define BC    20u                 /* the table that codes the tables */
#define TABLE_SIZE (NC + DC + RC + LDC)

#define LOW_DIST_REP_COUNT 16u

static const uint32_t LDecode[28] = {
	0,1,2,3,4,5,6,7,8,10,12,14,16,20,24,28,32,40,48,56,64,80,96,112,128,160,192,224
};
static const uint8_t LBits[28] = {
	0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5
};
static const uint32_t DDecode[60] = {
	0,1,2,3,4,6,8,12,16,24,32,48,64,96,128,192,256,384,512,768,1024,1536,2048,
	3072,4096,6144,8192,12288,16384,24576,32768,49152,65536,98304,131072,196608,
	262144,327680,393216,458752,524288,589824,655360,720896,786432,851968,917504,
	983040,1048576,1310720,1572864,1835008,2097152,2359296,2621440,2883584,
	3145728,3407872,3670016,3932160
};
static const uint8_t DBits[60] = {
	0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13,14,14,
	15,15,16,16,16,16,16,16,16,16,16,16,16,16,16,16,18,18,18,18,18,18,18,18,18,
	18,18,18
};
static const uint32_t SDDecode[8] = { 0,4,8,16,32,64,128,192 };
static const uint8_t SDBits[8] = { 2,2,3,4,5,6,6,6 };

/* ---- the bit reader ----------------------------------------------------------- */

struct br {
	const uint8_t *p;
	uint64_t n;
	uint64_t byte;     /* byte cursor */
	uint32_t bit;      /* 0..7 within it */
	int out_of_input;
};

static uint8_t br_at(struct br *b, uint64_t i)
{
	if (i < b->n)
		return b->p[i];
	b->out_of_input = 1;
	return 0;
}

/* The next sixteen bits, most significant first, without advancing. */
static uint32_t br_peek(struct br *b)
{
	uint32_t v = ((uint32_t)br_at(b, b->byte) << 16) |
		     ((uint32_t)br_at(b, b->byte + 1u) << 8) |
		     (uint32_t)br_at(b, b->byte + 2u);

	return (v >> (8u - b->bit)) & 0xffffu;
}

static void br_skip(struct br *b, uint32_t bits)
{
	b->bit += bits;
	b->byte += b->bit >> 3;
	b->bit &= 7u;
}

static uint32_t br_take(struct br *b, uint32_t bits)
{
	uint32_t v = bits ? (br_peek(b) >> (16u - bits)) : 0u;

	br_skip(b, bits);
	return v;
}

static void br_align(struct br *b)
{
	br_skip(b, (8u - b->bit) & 7u);
}

static int br_done(const struct br *b)
{
	return b->byte >= b->n;
}

/* ---- Huffman ------------------------------------------------------------------ */

/*
 * RAR's canonical decoder, kept in its own shape.
 *
 * `len[k]` is the largest sixteen bit field whose code is at most k bits long, so
 * finding a code's length is a walk up that table and nothing else needs to be
 * searched. `pos[k]` is where codes of that length begin in `num`.
 */
struct huff {
	uint32_t len[16];
	uint32_t pos[16];
	uint16_t num[TABLE_SIZE];
	uint32_t max;
};

static void huff_build(struct huff *d, const uint8_t *bits, uint32_t size)
{
	uint32_t count[16], tmp[16], i;
	uint32_t n = 0, m;

	memset(count, 0, sizeof count);
	memset(d->num, 0, sizeof d->num);
	for (i = 0; i < size; i++)
		count[bits[i] & 0x0fu]++;
	count[0] = 0;

	tmp[0] = d->pos[0] = d->len[0] = 0;
	for (i = 1; i < 16u; i++) {
		n = 2u * (n + count[i]);
		m = n << (15u - i);
		if (m > 0xffffu)
			m = 0xffffu;
		d->len[i] = m;
		tmp[i] = d->pos[i] = d->pos[i - 1u] + count[i - 1u];
	}
	for (i = 0; i < size; i++)
		if (bits[i] & 0x0fu) {
			uint32_t l = bits[i] & 0x0fu;

			if (tmp[l] < TABLE_SIZE)
				d->num[tmp[l]++] = (uint16_t)i;
		}
	d->max = size;
}

static uint32_t huff_decode(struct br *b, const struct huff *d)
{
	uint32_t field = br_peek(b) & 0xfffeu;
	uint32_t bits, idx;

	for (bits = 1; bits < 15u; bits++)
		if (field < d->len[bits])
			break;
	br_skip(b, bits);

	idx = d->pos[bits] + ((field - d->len[bits - 1u]) >> (16u - bits));
	if (idx >= d->max)
		idx = 0;
	return d->num[idx];
}


/* ---- filters ------------------------------------------------------------------ */

/*
 * RAR3 attaches small programs to ranges of the output.
 *
 * The programs are RarVM bytecode, but no archiver has ever shipped one that is not
 * from a fixed set: RAR itself recognises them by the CRC32 of their code and runs
 * native versions, and the interpreter exists only for code nobody writes. So the
 * same thing is done here - identify by CRC, run the native transform, and refuse
 * anything unrecognised - and the VM is not implemented at all.
 *
 *
 * WHY THEY ARE APPLIED AFTERWARDS AND NOT AS THEY ARRIVE
 *
 * A filter rewrites what goes to the FILE. It does not rewrite the window: a later
 * back reference into a filtered range copies the bytes as the LZ stage produced
 * them, not as the filter left them. RAR keeps the two apart by having a window and
 * an output buffer.
 *
 * This decoder has one buffer that is both - see the note at the top of the file -
 * so the two are kept apart in TIME instead. Each filter use is recorded as it is
 * declared, the LZ stage runs to the end untouched, and the transforms are applied
 * once nothing will read the window again. The result is identical and there is no
 * second megabyte of state.
 */
#define VM_GLOBALMEMADDR  0x3c000u

/* RAR's own limit is 8192 filters; a scan does not need to follow an archive that
 * far, and the array is on the stack. Reaching either bound ends the decode with
 * UNSUPPORTED rather than with a partial file called whole. */
#define RAR3_MAX_PRG    64u
#define RAR3_MAX_USES  512u

/* The whole VM code block: the parameters, and the program on its first use. The
 * largest program in the set below is 216 bytes. */
#define RAR3_VMCODE_MAX 1024u

enum rar3_filter {
	RF_NONE = 0,
	RF_E8,          /* x86 CALL rel32 -> absolute */
	RF_E8E9,        /* the same, and JMP too */
	RF_ITANIUM,
	RF_DELTA,       /* channel de-interleave with a running difference */
	RF_RGB,
	RF_AUDIO,
	RF_UPCASE
};

/*
 * The set, by the CRC32 and length of the program's own bytes.
 *
 * Both are checked: a length alone collides and a CRC alone would run a transform on
 * something that only hashes the same. These are RAR's published signatures.
 */
static const struct { uint32_t len, crc; uint8_t type; } STD_FILTERS[] = {
	{  53u, 0xad576887u, RF_E8      },
	{  57u, 0x3cd7e57eu, RF_E8E9    },
	{ 120u, 0x3769893fu, RF_ITANIUM },
	{  29u, 0x0e06077du, RF_DELTA   },
	{ 149u, 0x1c2c5dc8u, RF_RGB     },
	{ 216u, 0xbc85e701u, RF_AUDIO   },
	{  40u, 0x46b9c560u, RF_UPCASE  }
};

/* One application of a filter to one range of the output. */
struct f_use {
	uint64_t start;
	uint32_t len;
	/*
	 * R0 and R1, and no others.
	 *
	 * The VM's seven registers can all be initialised from the stream, but the
	 * transforms below read only two of them - the channel count or image width
	 * in R0, the colour offset in R1. R4 is the block length and R6 the file
	 * offset, both of which are the two fields above; the rest are never read.
	 */
	uint32_t r0, r1;
	uint8_t  type;
};

/* A bit reader over the VM code block. Same shape as the stream's - top bits of the
 * next sixteen - because it is the same reader in RAR. */
struct vbr {
	const uint8_t *p;
	uint32_t n, byte, bit;
	int over;
};

static uint32_t vbr_peek(struct vbr *v)
{
	uint32_t b0 = v->byte < v->n ? v->p[v->byte] : 0u;
	uint32_t b1 = v->byte + 1u < v->n ? v->p[v->byte + 1u] : 0u;
	uint32_t b2 = v->byte + 2u < v->n ? v->p[v->byte + 2u] : 0u;

	if (v->byte >= v->n)
		v->over = 1;
	return (((b0 << 16) | (b1 << 8) | b2) >> (8u - v->bit)) & 0xffffu;
}

static void vbr_skip(struct vbr *v, uint32_t bits)
{
	v->bit += bits;
	v->byte += v->bit >> 3;
	v->bit &= 7u;
}

static uint32_t vbr_take(struct vbr *v, uint32_t bits)
{
	uint32_t x = vbr_peek(v) >> (16u - bits);

	vbr_skip(v, bits);
	return x;
}

/*
 * A number, in RAR's variable width encoding.
 *
 * The top two bits choose the width, and the 0x4000 case has a sub-case that sign
 * extends - which is why this is a transcription rather than a rewrite: the encoding
 * is not derivable from anything, and a value read one bit differently puts a filter
 * on the wrong range of the file.
 */
static uint32_t vm_read_data(struct vbr *v)
{
	uint32_t d = vbr_peek(v);

	switch (d & 0xc000u) {
	case 0:
		vbr_skip(v, 6u);
		return (d >> 10) & 0x0fu;
	case 0x4000:
		if ((d & 0x3c00u) == 0) {
			vbr_skip(v, 14u);
			return 0xffffff00u | ((d >> 2) & 0xffu);
		}
		vbr_skip(v, 10u);
		return (d >> 6) & 0xffu;
	case 0x8000:
		vbr_skip(v, 2u);
		d = vbr_peek(v);
		vbr_skip(v, 16u);
		return d;
	default:
		vbr_skip(v, 2u);
		d = vbr_peek(v) << 16;
		vbr_skip(v, 16u);
		d |= vbr_peek(v);
		vbr_skip(v, 16u);
		return d;
	}
}

static uint8_t std_filter_of(const uint8_t *code, uint32_t n)
{
	uint32_t crc, i;
	uint8_t xsum = 0;

	/* RAR's own validity check: byte zero is the XOR of the rest. */
	for (i = 1; i < n; i++)
		xsum ^= code[i];
	if (n == 0 || xsum != code[0])
		return RF_NONE;

	crc = kof_crc32(code, n);
	for (i = 0; i < sizeof STD_FILTERS / sizeof STD_FILTERS[0]; i++)
		if (STD_FILTERS[i].len == n && STD_FILTERS[i].crc == crc)
			return STD_FILTERS[i].type;
	return RF_NONE;
}

static uint32_t rd32le(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr32le(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

/*
 * The x86 branch transform, undone.
 *
 * The compressor turned every CALL - and for E8E9 every JMP - whose operand looked
 * like a file offset into an absolute address, because absolute addresses repeat
 * across a binary and relative ones do not. This puts them back.
 *
 * `file_off` is where this block begins in the FILE, which is what the addresses
 * were made relative to, and is why the transform cannot be applied to a range
 * without knowing where it sits.
 */
static void filt_e8(uint8_t *d, uint32_t n, uint32_t file_off, int also_e9)
{
	const uint32_t FILE_SIZE = 0x1000000u;
	uint8_t cmp2 = also_e9 ? 0xe9u : 0xe8u;
	uint32_t cur = 0;

	if (n < 5u)
		return;
	while (cur < n - 4u) {
		uint8_t c = d[cur++];

		if (c != 0xe8u && c != cmp2)
			continue;
		{
			uint32_t off = cur + file_off;
			uint32_t addr = rd32le(d + cur);

			if (addr < FILE_SIZE)
				wr32le(d + cur, addr - off);
			else if ((addr & 0x80000000u) &&
				 !((addr + off) & 0x80000000u))
				wr32le(d + cur, addr + FILE_SIZE);
		}
		cur += 4u;
	}
}

/*
 * Channel de-interleave, with the running difference undone.
 *
 * The compressor grouped every channel's bytes together and stored each as a
 * difference from the one before it - which is what makes a wave file or a table of
 * fixed width records compress. Both halves are undone here, in that order.
 *
 * Needs a scratch buffer because the result is a permutation of the input: the
 * source is read in channel-major order and written in interleaved order, so no
 * byte can be written before the byte it displaces has been read.
 */
static int filt_delta(uint8_t *d, uint32_t n, uint32_t chan,
		      uint8_t *scratch, uint64_t scratch_len)
{
	uint32_t ch, src = 0;

	if (chan == 0u || n == 0u || (uint64_t)n > scratch_len)
		return 0;
	memcpy(scratch, d, n);
	for (ch = 0; ch < chan; ch++) {
		uint8_t prev = 0;
		uint32_t at;

		for (at = ch; at < n; at += chan) {
			prev = (uint8_t)(prev - scratch[src++]);
			d[at] = prev;
		}
	}
	return 1;
}

/* ---- the decoder -------------------------------------------------------------- */

struct rar3 {
	struct br b;
	uint8_t *out;
	uint64_t cap, at;

	struct huff LD, DD, LDD, RD, BD;
	uint8_t old_table[TABLE_SIZE];

	uint32_t old_dist[4];
	uint32_t last_dist, last_len;
	uint32_t prev_low_dist, low_dist_rep;
	int tables_read;

	/*
	 * The filter table, and the uses of it that are still to be applied.
	 *
	 * `prg` is one entry per distinct program the stream has declared - RAR
	 * declares a program once and then refers to it by index, so this is what an
	 * index means. `use` is one entry per range it was attached to.
	 */
	uint8_t  prg[RAR3_MAX_PRG];        /* enum rar3_filter */
	uint32_t old_len[RAR3_MAX_PRG];    /* the last block length of each */
	uint32_t exec[RAR3_MAX_PRG];
	uint32_t n_prg, last_filter;

	struct f_use use[RAR3_MAX_USES];
	uint32_t n_uses;

	uint8_t *scratch;
	uint64_t scratch_len;
	/*
	 * Why the loop stopped, when it stopped for a reason the caller must not
	 * read as success.
	 *
	 * A stream may begin LZ and switch to PPM at any block boundary. Breaking
	 * out and reporting OK hands over a file that is the right shape and the
	 * wrong length, which is the one outcome worse than reporting nothing.
	 */
	int gave_up;
};

static void push_dist(struct rar3 *s, uint32_t d)
{
	s->old_dist[3] = s->old_dist[2];
	s->old_dist[2] = s->old_dist[1];
	s->old_dist[1] = s->old_dist[0];
	s->old_dist[0] = d;
}

/*
 * A back reference, bounded by what has been produced.
 *
 * Byte at a time and deliberately not memmove: RAR, like every LZ77 descendant,
 * allows a distance shorter than the length so that a run repeats itself, and a
 * block move would read the source before the overlap was written.
 */
static int copy_string(struct rar3 *s, uint32_t len, uint32_t dist)
{
	uint64_t src;

	if (dist == 0 || (uint64_t)dist > s->at)
		return 0;
	src = s->at - dist;
	while (len-- > 0) {
		if (s->at >= s->cap)
			return 1;             /* the caller's ceiling, not an error */
		s->out[s->at] = s->out[src++];
		s->at++;
	}
	return 1;
}


/*
 * Read one filter declaration from the stream and record what it asks for.
 *
 * The declaration is a length-prefixed run of bytes which is then read AGAIN, as a
 * bitstream of its own, for the parameters - filter index, where the block starts
 * relative to here, how long it is, and any registers. On a filter's first use the
 * program follows and is identified; afterwards only the index is sent.
 *
 * Returns 0 for anything this build will not carry out, which ends the decode: a
 * range left holding pre-filter bytes is a file that is the right length and the
 * wrong contents, and that is the one result worth less than none.
 */
static int read_vm_code(struct rar3 *s)
{
	uint8_t code[RAR3_VMCODE_MAX];
	struct vbr v;
	uint32_t first, len, i, pos, start, blen, mask = 0;
	int fresh;

	first = br_take(&s->b, 8u);
	len = (first & 7u) + 1u;
	if (len == 7u)
		len = br_take(&s->b, 8u) + 7u;
	else if (len == 8u)
		len = br_take(&s->b, 16u);
	if (len == 0u || len > RAR3_VMCODE_MAX)
		return 0;
	for (i = 0; i < len; i++)
		code[i] = (uint8_t)br_take(&s->b, 8u);
	if (s->b.out_of_input)
		return 0;

	memset(&v, 0, sizeof v);
	v.p = code;
	v.n = len;

	if (first & 0x80u) {
		pos = vm_read_data(&v);
		if (pos == 0u) {
			/*
			 * A reset. RAR drops the whole table AND every use of it
			 * that has not been written out yet - which here means
			 * every recorded range the walk has not passed.
			 */
			while (s->n_uses &&
			       s->use[s->n_uses - 1u].start >= s->at)
				s->n_uses--;
			s->n_prg = 0;
			s->last_filter = 0;
		} else {
			pos--;
		}
	} else {
		pos = s->last_filter;
	}
	if (pos > s->n_prg || pos >= RAR3_MAX_PRG)
		return 0;
	s->last_filter = pos;
	fresh = (pos == s->n_prg);
	if (fresh) {
		s->n_prg++;
		s->old_len[pos] = 0;
		s->exec[pos] = 0;
		s->prg[pos] = RF_NONE;
	} else {
		s->exec[pos]++;
	}

	start = vm_read_data(&v);
	if (first & 0x40u)
		start += 258u;
	if (first & 0x20u) {
		blen = vm_read_data(&v);
		s->old_len[pos] = blen;
	} else {
		blen = s->old_len[pos];
	}

	/*
	 * Checked here, before the first write to s->use[s->n_uses] below, not
	 * after: this slot is written unconditionally once a register mask is
	 * present (r0/r1 default to 0 even when the mask bit is unset), so a
	 * check placed after those writes - where it used to be, guarding only
	 * the "commit" store at s->use[s->n_uses].start/.len/.type further down
	 * - let s->n_uses == RAR3_MAX_USES write one struct f_use past the end
	 * of the fixed s->use[RAR3_MAX_USES] array on the stack. r0/r1 there are
	 * attacker-controlled (vm_read_data), and the array is immediately
	 * followed in struct rar3 by n_uses, then the scratch pointer and its
	 * length - so that out-of-bounds write could corrupt the scratch
	 * pointer with attacker-chosen bits, not just overrun a counter.
	 */
	if (s->n_uses >= RAR3_MAX_USES)
		return 0;
	if (first & 0x10u) {
		mask = vbr_take(&v, 7u);
		for (i = 0; i < 7u; i++)
			if (mask & (1u << i)) {
				uint32_t r = vm_read_data(&v);

				if (i == 0u)
					s->use[s->n_uses].r0 = r;
				else if (i == 1u)
					s->use[s->n_uses].r1 = r;
			}
	}
	if (!(mask & 1u))
		s->use[s->n_uses].r0 = 0;
	if (!(mask & 2u))
		s->use[s->n_uses].r1 = 0;

	if (fresh) {
		uint32_t vsize = vm_read_data(&v);
		uint8_t prog[RAR3_VMCODE_MAX];

		if (vsize == 0u || vsize > RAR3_VMCODE_MAX)
			return 0;
		for (i = 0; i < vsize; i++)
			prog[i] = (uint8_t)vbr_take(&v, 8u);
		if (v.over)
			return 0;
		s->prg[pos] = std_filter_of(prog, vsize);
	}
	if (v.over)
		return 0;

	/* A block of zero length is a declaration with nothing to do; RAR allows it
	 * and it costs a slot, so it is dropped rather than recorded. */
	if (blen == 0u)
		return 1;
	if (blen > VM_GLOBALMEMADDR)
		return 0;                      /* larger than the VM could hold */

	s->use[s->n_uses].start = s->at + start;
	s->use[s->n_uses].len = blen;
	s->use[s->n_uses].type = s->prg[pos];
	switch (s->prg[pos]) {
	case RF_E8:
	case RF_E8E9:
		break;
	case RF_DELTA:
		if (!s->scratch || (uint64_t)blen > s->scratch_len)
			return 0;
		break;
	default:
		/*
		 * Recognised and not run, or not recognised at all.
		 *
		 * Itanium, RGB, audio and upcase are in RAR's set and no archive in
		 * the collection this was built against uses one, so implementing
		 * them would be four transforms nothing here can check. They are
		 * refused by name rather than approximated.
		 */
		return 0;
	}
	s->n_uses++;
	return 1;
}

/*
 * Run the recorded transforms, once the window will not be read again.
 *
 * In order, because RAR stacks them: a second filter over the same range takes the
 * first one's output as its input, and applying them in the order they were declared
 * is what reproduces that.
 */
static void apply_filters(struct rar3 *s)
{
	uint32_t i;

	for (i = 0; i < s->n_uses; i++) {
		const struct f_use *u = &s->use[i];

		/* A range the decode never reached. Its bytes are not there to
		 * transform, and half of one would be worse than none. */
		if (u->start + u->len > s->at)
			continue;

		switch (u->type) {
		case RF_E8:
		case RF_E8E9:
			filt_e8(s->out + u->start, u->len,
				(uint32_t)u->start, u->type == RF_E8E9);
			break;
		case RF_DELTA:
			if (!filt_delta(s->out + u->start, u->len, u->r0,
					s->scratch, s->scratch_len))
				s->gave_up = 1;
			break;
		default:
			s->gave_up = 1;
			break;
		}
	}
}

/*
 * Read the block header and the four Huffman tables that follow it.
 *
 * Returns 1 for an LZ block ready to decode, 0 for a stream that cannot be read,
 * and -1 for a PPM block - which is well formed and is not decoded here.
 */
static int read_tables(struct rar3 *s)
{
	uint8_t bitlen[BC];
	uint8_t table[TABLE_SIZE];
	uint32_t i, field;

	br_align(&s->b);
	field = br_peek(&s->b);
	if (field & 0x8000u)
		return -1;                    /* PPM */
	/* The second bit says whether the previous tables are the base this one is
	 * a delta against. Cleared, the delta is against zero. */
	if (!(field & 0x4000u))
		memset(s->old_table, 0, sizeof s->old_table);
	br_skip(&s->b, 2u);

	for (i = 0; i < BC; ) {
		uint32_t l = br_take(&s->b, 4u);

		if (l == 15u) {
			uint32_t z = br_take(&s->b, 4u);

			if (z == 0u) {
				bitlen[i++] = 15u;
			} else {
				z += 2u;
				while (z-- > 0u && i < BC)
					bitlen[i++] = 0u;
			}
		} else {
			bitlen[i++] = (uint8_t)l;
		}
		if (s->b.out_of_input)
			return 0;
	}
	huff_build(&s->BD, bitlen, BC);

	for (i = 0; i < TABLE_SIZE; ) {
		uint32_t num = huff_decode(&s->b, &s->BD);

		if (s->b.out_of_input)
			return 0;
		if (num < 16u) {
			table[i] = (uint8_t)((num + s->old_table[i]) & 0x0fu);
			i++;
		} else if (num < 18u) {
			uint32_t n = num == 16u ? br_take(&s->b, 3u) + 3u
						: br_take(&s->b, 7u) + 11u;

			if (i == 0)
				return 0;     /* nothing to repeat */
			while (n-- > 0u && i < TABLE_SIZE) {
				table[i] = table[i - 1u];
				i++;
			}
		} else {
			uint32_t n = num == 18u ? br_take(&s->b, 3u) + 3u
						: br_take(&s->b, 7u) + 11u;

			while (n-- > 0u && i < TABLE_SIZE)
				table[i++] = 0u;
		}
	}
	s->tables_read = 1;

	huff_build(&s->LD, table, NC);
	huff_build(&s->DD, table + NC, DC);
	huff_build(&s->LDD, table + NC + DC, LDC);
	huff_build(&s->RD, table + NC + DC + LDC, RC);
	memcpy(s->old_table, table, sizeof s->old_table);
	return 1;
}

enum kof_decomp_status kof_rar3_decode(const uint8_t *in, uint64_t in_len,
				       uint8_t *out, uint64_t out_cap,
				       uint8_t *scratch, uint64_t scratch_len,
				       uint64_t *produced)
{
	/*
	 * On the stack, and it matters that it is.
	 *
	 * This was static, on a guess that the tables were too large to be a local.
	 * They are 5.1KB - the guess was wrong by four times - and a static here
	 * would make the decoder unusable from two threads at once, which is the one
	 * property kofdb.h promises about this engine: the database is immutable and
	 * shared, and everything mutable belongs to the thread that made it.
	 */
	struct rar3 s;
	int t, corrupt = 0;

	if (produced)
		*produced = 0;
	if (!in || !out || out_cap == 0)
		return KOF_DEC_CORRUPT;

	memset(&s, 0, sizeof s);
	s.b.p = in;
	s.b.n = in_len;
	s.out = out;
	s.cap = out_cap;
	s.scratch = scratch;
	s.scratch_len = scratch_len;

	t = read_tables(&s);
	if (t < 0) {
		if (produced)
			*produced = 0;
		return KOF_DEC_UNSUPPORTED;
	}
	if (t == 0)
		return KOF_DEC_CORRUPT;

	while (s.at < out_cap) {
		uint32_t num, len, dist, bits;

		if (br_done(&s.b) || s.b.out_of_input)
			break;

		num = huff_decode(&s.b, &s.LD);

		if (num < 256u) {
			s.out[s.at++] = (uint8_t)num;
			continue;
		}
		if (num >= 271u) {
			uint32_t dn;

			num -= 271u;
			if (num >= 28u)
				goto corrupt;
			len = LDecode[num] + 3u;
			bits = LBits[num];
			if (bits)
				len += br_take(&s.b, bits);

			dn = huff_decode(&s.b, &s.DD);
			if (dn >= 60u)
				goto corrupt;
			dist = DDecode[dn] + 1u;
			bits = DBits[dn];
			if (bits) {
				if (dn > 9u) {
					/*
					 * A large distance is split: the high bits
					 * ride here and the low four come from a
					 * table of their own, because the low bits
					 * of consecutive distances repeat and are
					 * worth coding separately.
					 */
					if (bits > 4u)
						dist += br_take(&s.b, bits - 4u) << 4;
					if (s.low_dist_rep > 0u) {
						s.low_dist_rep--;
						dist += s.prev_low_dist;
					} else {
						uint32_t low =
							huff_decode(&s.b, &s.LDD);

						if (low == 16u) {
							s.low_dist_rep =
							    LOW_DIST_REP_COUNT - 1u;
							dist += s.prev_low_dist;
						} else {
							dist += low;
							s.prev_low_dist = low;
						}
					}
				} else {
					dist += br_take(&s.b, bits);
				}
			}
			if (dist >= 0x2000u) {
				len++;
				if (dist >= 0x40000u)
					len++;
			}
			push_dist(&s, dist);
			s.last_len = len;
			s.last_dist = dist;
			if (!copy_string(&s, len, dist))
				goto corrupt;
			continue;
		}
		if (num == 256u) {
			/* End of block: another header follows, unless the stream
			 * ends here. */
			t = read_tables(&s);
			if (t < 0) {
				s.gave_up = 1;        /* PPM from here on */
				break;
			}
			if (t == 0)
				break;
			continue;
		}
		if (num == 257u) {
			if (!read_vm_code(&s)) {
				s.gave_up = 1;
				break;
			}
			continue;
		}
		if (num == 258u) {
			if (s.last_len &&
			    !copy_string(&s, s.last_len, s.last_dist))
				goto corrupt;
			continue;
		}
		if (num < 263u) {
			uint32_t k = num - 259u, ln;

			dist = s.old_dist[k];
			for (; k > 0u; k--)
				s.old_dist[k] = s.old_dist[k - 1u];
			s.old_dist[0] = dist;

			ln = huff_decode(&s.b, &s.RD);
			if (ln >= 28u)
				goto corrupt;
			len = LDecode[ln] + 2u;
			bits = LBits[ln];
			if (bits)
				len += br_take(&s.b, bits);
			s.last_len = len;
			s.last_dist = dist;
			if (!copy_string(&s, len, dist))
				goto corrupt;
			continue;
		}
		/* 263..270: a short distance with a length of two. */
		{
			uint32_t k = num - 263u;

			if (k >= 8u)
				goto corrupt;
			dist = SDDecode[k] + 1u;
			bits = SDBits[k];
			if (bits)
				dist += br_take(&s.b, bits);
			push_dist(&s, dist);
			s.last_len = 2u;
			s.last_dist = dist;
			if (!copy_string(&s, 2u, dist))
				goto corrupt;
		}
	}

	goto done;

	/*
	 * A stream that stopped making sense.
	 *
	 * It joins the exit below rather than returning on the spot, for two
	 * reasons. What came out before it stopped is worth keeping and this
	 * decoder's header promises it - a scanner searches the bytes that arrived,
	 * and returning none of them because the tail was wrong throws away the
	 * part that was right. And if the ceiling was already reached, the whole of
	 * what was asked for is in hand and what the next symbol looked like does
	 * not matter.
	 */
corrupt:
	corrupt = 1;

done:
	apply_filters(&s);
	if (produced)
		*produced = s.at;
	/*
	 * Short output is only OK when the caller's ceiling is what stopped it.
	 * Anything else - a coding this build lacks, an exhausted input - is said
	 * plainly, because the difference decides whether what came back is the
	 * file or a piece of it.
	 */
	if (s.at >= out_cap)
		return KOF_DEC_OK;
	if (corrupt)
		return KOF_DEC_CORRUPT;
	if (s.gave_up)
		return KOF_DEC_UNSUPPORTED;
	return s.b.out_of_input ? KOF_DEC_TRUNCATED : KOF_DEC_UNSUPPORTED;
}
