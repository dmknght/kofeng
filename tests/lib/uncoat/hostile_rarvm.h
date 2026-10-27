/*
 * hostile_rarvm.h - the FILTER DECLARATION of RAR 3 (symbol 257 of an LZ block), written from the decoder's reading of it
 * (libuncoat/decompressors/rar3.c: read_vm_code, apply_vm_code, vm_read_data, std_filter_of), so that a filtered range has an
 * exact expected output.
 *
 * What the decoder reads after symbol 257: a byte `first` (bit 7: a program index follows, 0 resets the table; bit 6: the start is
 * 258 more; bit 5: a block length follows; bit 4: a register mask follows; bits 0-2: the length of the code block in bytes, 1..6,
 * 6 meaning "7 plus the next byte" and 7 "the next 16 bits"), then that many bytes which are read AGAIN as a bit stream of their own:
 *   [index: a number]  start: a number  [length: a number]  [mask: 7 bits, then a number for each bit set]
 *   [on the first use of an index: the program's size as a number, then its bytes of 8 bits]
 * A NUMBER is two bits that choose the width: 00 + 4 bits (0..15); 01 + 8 bits (16..255), or 01 0000 + 8 bits for a small negative;
 * 10 + 16 bits; 11 + 32 bits.
 *
 * The decoder never runs a program: it recognises one of seven by its length and CRC32 (and a first byte that is the XOR of the rest)
 * and runs its own copy. So a test that wants the E8 filter to run needs a program of 53 bytes whose CRC32 is 0xad576887: none can
 * be copied from anywhere here, but a CRC32 is affine over GF(2) and four chosen bytes of a message can be solved for the CRC to be
 * any value, which hv_vm_forge does (with the XOR rule held at the same time: byte 0 depends on the four bytes too, and that is part
 * of the same linear system). The programs forged are not RAR's own bytes; the decoder cannot tell and does not need to.
 *
 * The includer has hostile_common.h, hostile_enc.h (hv_bw) and hostile_rarenc.h in scope first.
 */
#ifndef HOSTILE_RARVM_H
#define HOSTILE_RARVM_H

enum { HV_VM_E8 = 0, HV_VM_E8E9, HV_VM_ITANIUM, HV_VM_DELTA, HV_VM_RGB, HV_VM_AUDIO, HV_VM_UPCASE, HV_VM_KINDS };

/* RAR's published signatures of its seven standard programs: length and CRC32. */
static const struct { uint32_t len, crc; } HV_VM_STD[HV_VM_KINDS] = {
	{ 53u, 0xad576887u }, { 57u, 0x3cd7e57eu }, { 120u, 0x3769893fu }, { 29u, 0x0e06077du },
	{ 149u, 0x1c2c5dc8u }, { 216u, 0xbc85e701u }, { 40u, 0x46b9c560u }
};

/* CRC-32 (the zlib/PNG one), bitwise: a test needs no table. */
static inline uint32_t hv_vm_crc32(const uint8_t *p, size_t n)
{
	uint32_t c = 0xffffffffu;
	size_t i;
	unsigned k;

	for (i = 0; i < n; i++) {
		c ^= p[i];
		for (k = 0; k < 8; k++)
			c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1u)));
	}
	return ~c;
}

/* Byte 0 is the XOR of the others (RAR's own validity check), the four bytes at `at` are `f`. */
static inline uint32_t hv_vm_crc_of(uint8_t *code, uint32_t len, uint32_t at, uint32_t f)
{
	uint32_t i;
	uint8_t x = 0;

	for (i = 0; i < 4; i++)
		code[at + i] = (uint8_t)(f >> (8u * i));
	for (i = 1; i < len; i++)
		x ^= code[i];
	code[0] = x;
	return hv_vm_crc32(code, len);
}

/*
 * A program of `len` bytes whose CRC32 is `crc` and whose first byte is the XOR of the rest, the middle taken from the generator.
 * Returns 1 when solved. The four forged bytes sit at the end; when that system is singular they move down a byte at a time.
 */
static inline int hv_vm_forge(uint8_t *code, uint32_t len, uint32_t crc, uint64_t *rs)
{
	uint32_t shift, i, j;

	for (i = 1; i < len; i++)
		code[i] = (uint8_t)hv_rng32(rs);
	for (shift = 0; shift + 5u <= len && shift < 40u; shift++) {
		uint32_t at = len - 4u - shift, base = hv_vm_crc_of(code, len, at, 0), col[32], rows[32], rhs[32], f = 0;
		int r, c;

		for (i = 0; i < 32; i++)
			col[i] = hv_vm_crc_of(code, len, at, 1u << i) ^ base;
		/* equations: for output bit r, XOR over unknown bits i of (col[i] >> r & 1) * x_i = (crc ^ base) >> r & 1 */
		for (r = 0; r < 32; r++) {
			rows[r] = 0;
			for (i = 0; i < 32; i++)
				if ((col[i] >> r) & 1u)
					rows[r] |= 1u << i;
			rhs[r] = ((crc ^ base) >> r) & 1u;
		}
		for (c = 0, j = 0; c < 32; c++) {                 /* Gauss-Jordan over GF(2) */
			int piv = -1;

			for (r = (int)j; r < 32; r++)
				if ((rows[r] >> c) & 1u) {
					piv = r;
					break;
				}
			if (piv < 0)
				continue;
			{
				uint32_t t = rows[piv]; rows[piv] = rows[j]; rows[j] = t;
				t = rhs[piv]; rhs[piv] = rhs[j]; rhs[j] = t;
			}
			for (r = 0; r < 32; r++)
				if ((uint32_t)r != j && ((rows[r] >> c) & 1u)) {
					rows[r] ^= rows[j];
					rhs[r] ^= rhs[j];
				}
			j++;
		}
		for (r = (int)j; r < 32; r++)
			if (rhs[r])
				break;
		if (r < 32 || j < 32)
			continue;                                   /* no solution (or free variables: take the next position) */
		for (c = 0; c < 32; c++)
			for (r = 0; r < 32; r++)
				if (((rows[r] >> c) & 1u) && (rows[r] & ~(1u << c)) == 0 && rhs[r])
					f |= 1u << c;
		if (hv_vm_crc_of(code, len, at, f) == crc)
			return 1;
	}
	return 0;
}

/* A number in RAR's variable width form. */
static inline void hv_vm_num(struct hv_bw *w, uint32_t v)
{
	if (v < 16u) {
		hv_bw_msb(w, 0, 2);
		hv_bw_msb(w, v, 4);
	} else if (v < 256u) {
		hv_bw_msb(w, 1, 2);
		hv_bw_msb(w, v, 8);
	} else if (v < 65536u) {
		hv_bw_msb(w, 2, 2);
		hv_bw_msb(w, v, 16);
	} else {
		hv_bw_msb(w, 3, 2);
		hv_bw_msb(w, v >> 16, 16);
		hv_bw_msb(w, v & 0xffffu, 16);
	}
}

/* One filter declaration. `idx` 0 sends the reset (a pos of 0), 1.. names a program slot (1-based, the next new one is a first use).
 * `flags` selects the optional parts; prog/vsize are written when `with_prog`. Writes symbol 257 and the block into the stream. */
struct hv_vm_decl {
	unsigned       flags;          /* 0x80 index, 0x40 start + 258, 0x20 length, 0x10 mask */
	uint32_t       idx, start, blen, mask, reg[7];
	const uint8_t *prog;
	uint32_t       vsize;
	int            with_prog;
	int            cut;            /* bytes to drop off the end of the code block (a declaration cut short) */
	uint32_t       len_override;   /* nonzero: the length field says this instead of the code's real length */
	int            neg;            /* the start goes as the small negative form (01 0000 + 8 bits, 0xffffff00 | start & 0xff) */
};

static inline void hv_r3_vm(struct hv_r3 *e, const struct hv_vm_decl *d)
{
	uint8_t code[1200];
	struct hv_bw cw;
	uint32_t n, i, len, first;

	hv_bw_init(&cw, code, sizeof code);
	if (d->flags & 0x80u)
		hv_vm_num(&cw, d->idx);
	if (d->neg) {
		hv_bw_msb(&cw, 1, 2);
		hv_bw_msb(&cw, 0, 4);
		hv_bw_msb(&cw, d->start & 0xffu, 8);
	} else {
		hv_vm_num(&cw, (d->flags & 0x40u) ? d->start - 258u : d->start);
	}
	if (d->flags & 0x20u)
		hv_vm_num(&cw, d->blen);
	if (d->flags & 0x10u) {
		hv_bw_msb(&cw, d->mask, 7);
		for (i = 0; i < 7; i++)
			if (d->mask & (1u << i))
				hv_vm_num(&cw, d->reg[i]);
	}
	if (d->with_prog) {
		hv_vm_num(&cw, d->vsize);
		for (i = 0; i < d->vsize; i++)
			hv_bw_msb(&cw, d->prog[i], 8);
	}
	hv_bw_align_msb(&cw);
	n = (uint32_t)cw.n;
	len = d->len_override ? d->len_override : n;
	first = d->flags;
	if (len <= 6u)
		first |= len - 1u;
	else if (len <= 262u)
		first |= 6u;
	else
		first |= 7u;
	hv_r3_lsym(e, 257);
	hv_bw_msb(&e->w, first, 8);
	if (len > 6u && len <= 262u)
		hv_bw_msb(&e->w, len - 7u, 8);
	else if (len > 262u)
		hv_bw_msb(&e->w, len, 16);
	n -= (uint32_t)d->cut < n ? (uint32_t)d->cut : n;
	for (i = 0; i < n; i++)
		hv_bw_msb(&e->w, code[i], 8);
}

#endif /* HOSTILE_RARVM_H */
