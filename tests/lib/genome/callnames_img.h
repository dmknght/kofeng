/*
 * callnames_img.h - the images the call-name tests read: a dynamically linked x86-64 ELF with a lazy .plt, an IBT .plt.sec and calls through GOT slots, and the
 * PE of hk.h with its code replaced by calls through the IAT. Everything is laid out so the expected table is known from the layout and not from the lib:
 * the offsets below ARE the oracle.
 *
 * ELF (file offset == address): .dynsym 0x100 (rand, puts, exit), .dynstr 0x180, .rela.plt 0x200 (JUMP_SLOT to 0x618 0x620 0x628), .plt 0x300 (PLT0, then
 * the lazy entries of rand at 0x310 and puts at 0x320), .plt.sec 0x400 (endbr64 + jmp [exit] at 0x404), .text 0x500 (the entry), .got.plt 0x600.
 *   0x500 call 0x310        0x505 call [puts slot]        0x50b call 0x400        0x510 jmp [rand slot]
 * Expected: STUB 0x310 rand, STUB 0x320 puts, STUB 0x400 + 0x404 exit, SLOT 0x505 puts, SLOT 0x510 rand.
 */
#ifndef CALLNAMES_IMG_H
#define CALLNAMES_IMG_H

#include <string.h>

#define CI_ELF_SIZE 0x940u
#define CI_DYNSYM   0x100u
#define CI_DYNSTR   0x180u
#define CI_RELA     0x200u
#define CI_PLT      0x300u
#define CI_PLTSEC   0x400u
#define CI_TEXT     0x500u
#define CI_GOT      0x600u
#define CI_SHDR     0x700u
#define CI_SLOT(i)  (CI_GOT + 0x18u + 8u * (i))

static void ci_w(uint8_t *p, uint64_t v, unsigned n)
{
	unsigned i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(v >> (8u * i));
}

static void ci_jmp_slot(uint8_t *b, uint32_t at, uint32_t slot)       /* ff 25 disp32 (6 bytes) */
{
	b[at] = 0xff;
	b[at + 1] = 0x25;
	ci_w(b + at + 2, (uint32_t)(slot - (at + 6u)), 4);
}

static void ci_sh(uint8_t *b, unsigned i, uint32_t name, uint32_t type, uint64_t flags, uint32_t addr, uint32_t size,
		  uint32_t link, uint32_t info, uint32_t ent)
{
	uint8_t *s = b + CI_SHDR + 64u * i;

	ci_w(s, name, 4); ci_w(s + 4, type, 4); ci_w(s + 8, flags, 8); ci_w(s + 16, addr, 8); ci_w(s + 24, addr, 8);
	ci_w(s + 32, size, 8); ci_w(s + 40, link, 4); ci_w(s + 44, info, 4); ci_w(s + 48, 8, 8); ci_w(s + 56, ent, 8);
}

/* Builds the ELF into b (CI_ELF_SIZE bytes, zeroed here). */
static void ci_elf(uint8_t *b)
{
	static const char shn[] = "\0.dynsym\0.dynstr\0.rela.plt\0.plt\0.plt.sec\0.text\0.got.plt\0.shstrtab";
	static const char str[] = "\0rand\0puts\0exit";
	static const uint32_t nm[9] = { 0, 1, 9, 17, 27, 32, 41, 47, 56 };
	unsigned i;
	uint32_t t = CI_TEXT;

	memset(b, 0, CI_ELF_SIZE);
	memcpy(b, "\x7f" "ELF\2\1\1", 7);
	ci_w(b + 16, 3, 2); ci_w(b + 18, 62, 2); ci_w(b + 20, 1, 4); ci_w(b + 24, CI_TEXT, 8); ci_w(b + 32, 64, 8);
	ci_w(b + 40, CI_SHDR, 8); ci_w(b + 52, 64, 2); ci_w(b + 54, 56, 2); ci_w(b + 56, 1, 2); ci_w(b + 58, 64, 2);
	ci_w(b + 60, 9, 2); ci_w(b + 62, 8, 2);
	ci_w(b + 64, 1, 4); ci_w(b + 68, 7, 4); ci_w(b + 96, CI_ELF_SIZE, 8); ci_w(b + 104, CI_ELF_SIZE, 8); ci_w(b + 112, 0x1000, 8);
	memcpy(b + CI_DYNSTR, str, sizeof str);
	for (i = 0; i < 3; i++) {
		uint8_t *sy = b + CI_DYNSYM + 24u * (i + 1u), *r = b + CI_RELA + 24u * i;

		ci_w(sy, 1u + 5u * i, 4);               /* st_name: rand 1, puts 6, exit 11 */
		sy[4] = 0x12;                           /* GLOBAL FUNC, undefined */
		ci_w(r, CI_SLOT(i), 8);
		ci_w(r + 8, ((uint64_t)(i + 1u) << 32) | 7u, 8);
	}
	/* .plt: PLT0 (not an import slot), then the lazy entries of rand and puts */
	b[CI_PLT] = 0xff; b[CI_PLT + 1] = 0x35; ci_w(b + CI_PLT + 2, 0x300, 4);
	ci_jmp_slot(b, CI_PLT + 6u, CI_GOT + 0x10u);
	for (i = 0; i < 2; i++) {
		uint32_t at = CI_PLT + 0x10u + 16u * i;

		ci_jmp_slot(b, at, CI_SLOT(i));
		b[at + 6] = 0x68; ci_w(b + at + 7, i, 4);
		b[at + 11] = 0xe9; ci_w(b + at + 12, (uint32_t)(CI_PLT - (at + 16u)), 4);
	}
	/* .plt.sec: endbr64; jmp [exit]; nops */
	memcpy(b + CI_PLTSEC, "\xf3\x0f\x1e\xfa", 4);
	ci_jmp_slot(b, CI_PLTSEC + 4u, CI_SLOT(2));
	memset(b + CI_PLTSEC + 10u, 0x90, 6);
	/* .text */
	b[t] = 0xe8; ci_w(b + t + 1, (uint32_t)(0x310u - (t + 5u)), 4);
	b[t + 5] = 0xff; b[t + 6] = 0x15; ci_w(b + t + 7, (uint32_t)(CI_SLOT(1) - (t + 11u)), 4);
	b[t + 11] = 0xe8; ci_w(b + t + 12, (uint32_t)(0x400u - (t + 16u)), 4);
	ci_jmp_slot(b, t + 16u, CI_SLOT(0));
	b[t + 22] = 0xc3;
	memcpy(b + 0x680, shn, sizeof shn);
	ci_sh(b, 1, nm[1], 11, 2, CI_DYNSYM, 96, 2, 1, 24);
	ci_sh(b, 2, nm[2], 3, 2, CI_DYNSTR, sizeof str, 0, 0, 0);
	ci_sh(b, 3, nm[3], 4, 2, CI_RELA, 72, 1, 7, 24);
	ci_sh(b, 4, nm[4], 1, 6, CI_PLT, 48, 0, 0, 16);
	ci_sh(b, 5, nm[5], 1, 6, CI_PLTSEC, 16, 0, 0, 16);
	ci_sh(b, 6, nm[6], 1, 6, CI_TEXT, 0x40, 0, 0, 0);
	ci_sh(b, 7, nm[7], 1, 3, CI_GOT, 0x40, 0, 0, 8);
	ci_sh(b, 8, nm[8], 3, 0, 0x680, sizeof shn, 0, 0, 0);
}

/*
 * PE: hk_pe's image (imports kernel32!ExitProcess, kernel32!#5, user32!MessageBoxA; IAT at .idata + 0xa0) with the code replaced. `plus` is x64.
 *   +0x00 call [iat ExitProcess]   +0x06 jmp [iat MessageBoxA]   +0x0c jmp [iat #5]   +0x12 call +0x06   +0x17 ret
 * Expected (file offsets 0x200 + ...): SLOT +0, STUB +6 (MessageBoxA), STUB +0x0c (ordinal 5). The x86 form names the slots absolutely.
 */
static void ci_pe_code(struct hk_pe *p)
{
	const uint64_t base = p->plus ? 0x140000000ull : 0x400000ull, ps = p->plus ? 8u : 4u;
	const uint64_t va = base + 0x1000u, iat = base + 0x20a0u;
	uint8_t *c = p->b + p->text_off;
	const uint64_t slot[3] = { iat, iat + 3u * ps, iat + ps };
	unsigned i;

	memset(c, 0xcc, 0x40);
	for (i = 0; i < 3; i++) {
		const unsigned at = i == 0 ? 0u : i == 1 ? 6u : 12u;

		c[at] = 0xff;
		c[at + 1] = i == 0 ? 0x15 : 0x25;
		if (p->plus)
			ci_w(c + at + 2, (uint32_t)(slot[i] - (va + at + 6u)), 4);
		else
			ci_w(c + at + 2, (uint32_t)slot[i], 4);
	}
	c[18] = 0xe8; ci_w(c + 19, (uint32_t)(6u - 23u), 4);
	c[23] = 0xc3;
}

#endif /* CALLNAMES_IMG_H */
