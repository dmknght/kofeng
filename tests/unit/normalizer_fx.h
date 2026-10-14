/*
 * normalizer_fx.h - executables the engine tests normalise, built in memory.
 *
 * An ELF64 with TWO loadable segments (code, then data), an optional section
 * table, and a PE32+ with a code and a data section - each with a stated number
 * of zeros BEFORE the code, AFTER it, INSIDE the data and BEFORE what follows,
 * so that the view's collapse moves the entry, the regions and the section
 * table by a known amount. After the image comes a tail: the encoded payload.
 *
 * What the objects carry that the rules of tests/sigs/norm_view_*.c look for:
 *
 *   entry    twelve bytes at the entry point (90 90 "NormEntry" 90)
 *   data     two markers in the data segment, `data_zeros` apart
 *   tail     one canary, in one encoding, or none
 *
 * The caller owns the buffer. Everything is offsets, so a test can state what
 * moved.
 */

#ifndef KOFENG_TESTS_NORMALIZER_FX_H
#define KOFENG_TESTS_NORMALIZER_FX_H

#include <stdint.h>
#include <string.h>

#define FX_ENTRY_SIG "\x90\x90NormEntry\x90"
#define FX_MARK1     "NormDataMarkOne-91c4"
#define FX_MARK2     "NormDataMarkTwo-3d78"

struct fx {
	uint32_t gap_text;      /* zeros between the headers and the code */
	uint32_t gap_code;      /* zeros between the code and the data */
	uint32_t data_zeros;    /* zeros between the two markers */
	uint32_t gap_end;       /* zeros between the image and the tail */
	int      sections;      /* an ELF section table; a PE always has one */
	const uint8_t *tail;
	size_t   tail_n;
	size_t   code_extra;    /* more code after the entry bytes (nops), so size can be set */
	uint32_t text_flags;    /* PE: the characteristics of .text; 0 is R+X */
	uint32_t extra_sections; /* ELF: more section headers over the data, each one more place to carry */
	const uint8_t *code;    /* the code to use instead of the entry bytes and nops, or NULL */
	size_t   code_len;
};

/* what a builder reports about where things are */
struct fx_at {
	uint64_t len;
	uint64_t entry_off;     /* the entry bytes */
	uint64_t code_off, code_n;
	uint64_t data_off, data_n;
	uint64_t mark1_off, mark2_off;
	uint64_t tail_off;
	uint64_t sh_off, shstr_off;    /* the ELF section table and its string table, or 0 */
};

static inline void fx_put16(uint8_t *b, uint64_t at, uint16_t v)
{
	b[at] = (uint8_t)v;
	b[at + 1u] = (uint8_t)(v >> 8);
}

static inline void fx_put32(uint8_t *b, uint64_t at, uint32_t v)
{
	unsigned i;

	for (i = 0; i < 4u; i++)
		b[at + i] = (uint8_t)(v >> (8u * i));
}

static inline void fx_put64(uint8_t *b, uint64_t at, uint64_t v)
{
	unsigned i;

	for (i = 0; i < 8u; i++)
		b[at + i] = (uint8_t)(v >> (8u * i));
}

/* the code bytes: the entry signature, nops, a return - or the caller's code */
static inline uint64_t fx_code(uint8_t *p, const struct fx *f)
{
	size_t extra = f->code_extra;

	if (f->code) {
		memcpy(p, f->code, f->code_len);
		return f->code_len;
	}
	memcpy(p, FX_ENTRY_SIG, 12u);
	memset(p + 12, 0x90, extra);
	p[12 + extra] = 0xc3;
	return 13u + extra;
}

/* the data bytes: marker one, `zeros` zeros, marker two, a few bytes of text */
static inline uint64_t fx_data(uint8_t *p, uint32_t zeros, uint64_t *m1, uint64_t *m2)
{
	uint64_t n = 0;

	*m1 = n;
	memcpy(p + n, FX_MARK1, 20u);
	n += 20u;
	memset(p + n, 0, zeros);
	n += zeros;
	*m2 = n;
	memcpy(p + n, FX_MARK2, 20u);
	n += 20u;
	memcpy(p + n, " tail of data", 13u);
	return n + 13u;
}

/*
 * ELF64. Layout, in file order:
 *
 *   [0, 0xb0)                 ELF header and two program headers
 *   gap_text zeros            (inside the first segment, outside .text)
 *   code                      .text, PF_R|PF_X, the first segment ends here
 *   gap_code zeros            (in no segment)
 *   data                      .data, PF_R|PF_W, the second segment
 *   gap_end zeros             (in no segment)
 *   [section table]           .text .data .shstrtab, when `sections`
 *   tail
 */
static inline uint64_t fx_elf(uint8_t *b, const struct fx *f, struct fx_at *at)
{
	static const char shs[] = "\0.text\0.data\0.shstrtab\0";
	uint64_t o = 0xb0u, code_n, data_n, text_off, data_off, sh_off = 0, shstr_off = 0, ph, end;
	uint64_t m1, m2;

	text_off = o + f->gap_text;
	memset(b, 0, text_off);
	code_n = fx_code(b + text_off, f);
	o = text_off + code_n;
	end = o;
	data_off = o + f->gap_code;
	memset(b + o, 0, f->gap_code);
	data_n = fx_data(b + data_off, f->data_zeros, &m1, &m2);
	o = data_off + data_n;
	memset(b + o, 0, f->gap_end);
	o += f->gap_end;
	memset(b, 0, 0xb0u);
	memcpy(b, "\177ELF\2\1\1", 7);
	fx_put16(b, 16, 2);
	fx_put16(b, 18, 0x3e);
	fx_put32(b, 20, 1);
	fx_put64(b, 24, 0x400000u + text_off);
	fx_put64(b, 32, 64);
	fx_put16(b, 52, 64);
	fx_put16(b, 54, 56);
	fx_put16(b, 56, 2);
	ph = 64;
	fx_put32(b, ph, 1);                             /* PT_LOAD, R+X: headers and code */
	fx_put32(b, ph + 4, 5);
	fx_put64(b, ph + 16, 0x400000u);
	fx_put64(b, ph + 32, end);
	fx_put64(b, ph + 40, end);
	fx_put64(b, ph + 48, 0x1000u);
	ph += 56;
	fx_put32(b, ph, 1);                             /* PT_LOAD, R+W: data */
	fx_put32(b, ph + 4, 6);
	fx_put64(b, ph + 8, data_off);
	fx_put64(b, ph + 16, 0x600000u + (data_off & 0xfffu));
	fx_put64(b, ph + 32, data_n);
	fx_put64(b, ph + 40, data_n);
	fx_put64(b, ph + 48, 0x1000u);
	if (f->sections) {
		uint64_t shstr = (o + 7u) & ~7ull;
		uint8_t *sh;

		shstr_off = shstr;

		memset(b + o, 0, shstr - o);
		memcpy(b + shstr, shs, sizeof shs);
		sh_off = (shstr + sizeof shs + 7u) & ~7ull;
		memset(b + shstr + sizeof shs, 0, sh_off - shstr - sizeof shs);
		memset(b + sh_off, 0, (4u + f->extra_sections) * 64u);
		sh = b + sh_off;
		fx_put32(sh + 64, 0, 1); fx_put32(sh + 64, 4, 1); fx_put64(sh + 64, 8, 6);
		fx_put64(sh + 64, 16, 0x400000u + text_off); fx_put64(sh + 64, 24, text_off);
		fx_put64(sh + 64, 32, code_n); fx_put64(sh + 64, 48, 1);
		fx_put32(sh + 128, 0, 7); fx_put32(sh + 128, 4, 1); fx_put64(sh + 128, 8, 3);
		fx_put64(sh + 128, 16, 0x600000u + (data_off & 0xfffu)); fx_put64(sh + 128, 24, data_off);
		fx_put64(sh + 128, 32, data_n); fx_put64(sh + 128, 48, 1);
		fx_put32(sh + 192, 0, 13); fx_put32(sh + 192, 4, 3); fx_put64(sh + 192, 24, shstr);
		fx_put64(sh + 192, 32, sizeof shs); fx_put64(sh + 192, 48, 1);
		fx_put64(b, 40, sh_off);
		fx_put16(b, 58, 64);
		{
			uint32_t x;

			for (x = 0; x < f->extra_sections; x++) {
				uint8_t *e = sh + (4u + x) * 64u;

				fx_put32(e, 4, 1);
				fx_put64(e, 8, 2);
				fx_put64(e, 16, 0x600000u + (data_off & 0xfffu) + (x % 60u));
				fx_put64(e, 24, data_off + (x % 60u));
				fx_put64(e, 32, 4);
				fx_put64(e, 48, 1);
			}
		}
		fx_put16(b, 60, (uint16_t)(4u + f->extra_sections));
		fx_put16(b, 62, 3);
		o = sh_off + (4u + f->extra_sections) * 64u;
	}
	if (f->tail_n) {
		memcpy(b + o, f->tail, f->tail_n);
	}
	if (at) {
		at->entry_off = text_off;
		at->code_off = text_off;
		at->code_n = code_n;
		at->data_off = data_off;
		at->data_n = data_n;
		at->mark1_off = data_off + m1;
		at->mark2_off = data_off + m2;
		at->tail_off = o;
		at->sh_off = sh_off;
		at->shstr_off = shstr_off;
		at->len = o + f->tail_n;
	}
	return o + f->tail_n;
}

/*
 * PE32+, headers of 0x400 bytes, `.text` (R+X, not writable, so its bytes are
 * kept) and `.data` (R+W), then the tail as the overlay. The zeros of gap_text lie
 * between the headers and the code, in no section.
 */
static inline uint64_t fx_pe(uint8_t *b, const struct fx *f, struct fx_at *at)
{
	const unsigned o = 0x80u + 24u, sec = o + 0xf0u;
	uint64_t text_off = 0x400u + f->gap_text, code_n, data_n, data_off, raw1, raw2, e;
	uint64_t m1, m2;

	memset(b, 0, 0x400u);
	b[0] = 'M'; b[1] = 'Z';
	fx_put32(b, 0x3c, 0x80);
	memcpy(b + 0x80, "PE\0\0", 4);
	fx_put16(b, 0x84, 0x8664u);
	fx_put16(b, 0x86, 2);
	fx_put16(b, 0x94, 0xf0);
	fx_put16(b, 0x96, 0x22);
	fx_put16(b, o, 0x20bu);
	b[o + 2] = 14;
	fx_put32(b, o + 16, 0x1000u);
	fx_put32(b, o + 20, 0x1000u);
	fx_put64(b, o + 24, 0x140000000ull);
	fx_put32(b, o + 32, 0x1000);
	fx_put32(b, o + 36, 0x200);
	fx_put16(b, o + 40, 6);
	fx_put16(b, o + 48, 6);
	fx_put32(b, o + 56, 0x3000);
	fx_put32(b, o + 60, 0x400);
	fx_put16(b, o + 68, 3);
	fx_put32(b, o + 108, 16);
	memset(b + 0x400, 0, f->gap_text);
	code_n = fx_code(b + text_off, f);
	raw1 = (code_n + 0x1ffu) & ~0x1ffull;
	memset(b + text_off + code_n, 0, raw1 - code_n);
	data_off = text_off + raw1 + f->gap_code;
	memset(b + text_off + raw1, 0, f->gap_code);
	data_n = fx_data(b + data_off, f->data_zeros, &m1, &m2);
	raw2 = (data_n + 0x1ffu) & ~0x1ffull;
	memset(b + data_off + data_n, 0, raw2 - data_n);
	memcpy(b + sec, ".text\0\0\0", 8);
	fx_put32(b, sec + 8, (uint32_t)code_n);
	fx_put32(b, sec + 12, 0x1000u);
	fx_put32(b, sec + 16, (uint32_t)raw1);
	fx_put32(b, sec + 20, (uint32_t)text_off);
	fx_put32(b, sec + 36, f->text_flags ? f->text_flags : 0x60000020u);
	memcpy(b + sec + 40, ".data\0\0\0", 8);
	fx_put32(b, sec + 48, (uint32_t)data_n);
	fx_put32(b, sec + 52, 0x2000u);
	fx_put32(b, sec + 56, (uint32_t)raw2);
	fx_put32(b, sec + 60, (uint32_t)data_off);
	fx_put32(b, sec + 76, 0xc0000040u);
	e = data_off + raw2;
	memset(b + e, 0, f->gap_end);
	e += f->gap_end;
	if (f->tail_n)
		memcpy(b + e, f->tail, f->tail_n);
	if (at) {
		at->entry_off = text_off;
		at->code_off = text_off;
		at->code_n = code_n;
		at->data_off = data_off;
		at->data_n = data_n;
		at->mark1_off = data_off + m1;
		at->mark2_off = data_off + m2;
		at->tail_off = e;
		at->len = e + f->tail_n;
	}
	return e + f->tail_n;
}

#endif /* KOFENG_TESTS_NORMALIZER_FX_H */
