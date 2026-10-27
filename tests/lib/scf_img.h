/*
 * scf_img.h - hand-built x86-64 ELF loaders for the shellcode-loader finder (kofexamine/kofscfind.c), shared by
 * tests/unit/kofscfind.c and the fuzz adapters of tests/fuzz/kofexamine. Moved verbatim out of kofscfind.c (a builder written
 * twice is two builders): include after caps_fix.h, which supplies put16/32/64. build() leaves where it put the section
 * headers and the symbol table in scf_sh_off / scf_sym_off, for a field map.
 */
#ifndef KOF_TESTS_SCF_IMG_H
#define KOF_TESTS_SCF_IMG_H

#define TEXT_VA   0x400100ull
#define BLOB_N    128u

enum shape {
	INLINE_CALLED,        /* the blob is a global array, and the code calls it    */
	INLINE_READ,          /* ... and the code only reads it                       */
	INLINE_LIBRARY,       /* ... in a file with no PT_INTERP                      */
	INLINE_TABLE,         /* ... and the blob is one repeated byte                */
	INLINE_BIGCODE,       /* ... in a file that is mostly code                    */
	INLINE_BASE64,        /* the blob is base64 text and the code calls it        */
	POINTER_CALLED        /* the global is a pointer to a clear blob in .rodata   */
};


#define SCF_UNUSED __attribute__((unused))
static uint64_t scf_sh_off SCF_UNUSED, scf_sym_off SCF_UNUSED;

static SCF_UNUSED uint32_t lcg(uint32_t *s)
{
	*s = *s * 1664525u + 1013904223u;
	return *s >> 16;
}

static SCF_UNUSED void sec_hdr(uint8_t *h, uint32_t name, uint32_t type, uint64_t flags,
		    uint64_t addr, uint64_t off, uint64_t size, uint32_t link,
		    uint32_t info, uint64_t esz)
{
	put32(h, 0, name);
	put32(h, 4, type);
	put64(h, 8, flags);
	put64(h, 16, addr);
	put64(h, 24, off);
	put64(h, 32, size);
	put32(h, 40, link);
	put32(h, 44, info);
	put64(h, 48, 1);
	put64(h, 56, esz);
}

/*
 * An x86-64 ELF with PT_INTERP, a .text of a few instructions and a global the
 * code treats in the way `shape` says. Returns the length.
 */
static SCF_UNUSED uint64_t build(uint8_t *b, enum shape shape)
{
	static const char shs[] = "\0.text\0.rodata\0.data\0.symtab\0.strtab\0.shstrtab\0";
	static const char str[] = "\0_start\0payload\0";
	const uint64_t text_off = 0x100, ro_off = 0x180, data_off = 0x400;
	uint64_t var_va, var_n, sym_off, str_off, shstr_off, sh_off, len;
	uint32_t seed = 0x1234567u, i, code_n = 0;
	int ptr = shape == POINTER_CALLED, interp = shape != INLINE_LIBRARY;
	uint8_t *c = b + text_off;

	memset(b, 0, 0x2000);
	memcpy(b, "\177ELF\2\1\1", 7);
	put16(b, 16, 2);
	put16(b, 18, 0x3e);
	put32(b, 20, 1);
	put64(b, 24, TEXT_VA);
	put64(b, 32, 64);
	put16(b, 52, 64);
	put16(b, 54, 56);
	put16(b, 56, 2);
	put16(b, 58, 64);
	/* program header 0: PT_INTERP (or PT_NOTE for the library), 1: one RWX PT_LOAD */
	put32(b, 64, interp ? 3u : 4u);
	put64(b, 64 + 8, 0xb0);
	put64(b, 64 + 32, 12);
	put32(b, 64 + 56, 1);
	put32(b, 64 + 56 + 4, 7);
	put64(b, 64 + 56 + 16, 0x400000);
	put64(b, 64 + 56 + 32, 0x2000);
	put64(b, 64 + 56 + 40, 0x2000);
	memcpy(b + 0xb0, "/lib/ld.so", 11);

	/* the data: the blob, or the pointer to it */
	if (ptr) {
		/* a clear blob in .rodata that makes a syscall, and a pointer to it */
		for (i = 0; i < 64u; i++)
			b[ro_off + i] = (uint8_t)(1u + lcg(&seed) % 254u);
		b[ro_off + 20] = 0x0f;
		b[ro_off + 21] = 0x05;
		b[ro_off + 64] = 0;
		put64(b, (unsigned)data_off, 0x400000ull + ro_off);
		var_n = 8;
	} else {
		for (i = 0; i < BLOB_N; i++)
			b[data_off + i] = shape == INLINE_TABLE ? 0x41
				: (uint8_t)(1u + lcg(&seed) % 254u);
		if (shape == INLINE_BASE64) {
			static const char a[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

			for (i = 0; i < BLOB_N; i++)
				b[data_off + i] = (uint8_t)a[lcg(&seed) % 64u];
		}
		var_n = BLOB_N;
	}
	var_va = 0x400000ull + data_off;

	/* the code: lea/mov rax,[rip+var]; call rax; ret - or a read and a ret */
	{
		uint64_t rip = TEXT_VA + 7u;
		int32_t rel = (int32_t)(var_va - rip);

		if (shape == INLINE_READ || shape == INLINE_LIBRARY) {
			/* mov eax,[rip+rel]; ret : the variable is read and nothing more */
			c[code_n++] = 0x8b; c[code_n++] = 0x05;
			put32(c, code_n, (uint32_t)(int32_t)(var_va - (TEXT_VA + 6u)));
			code_n += 4;
			c[code_n++] = 0xc3;
		} else {
			c[code_n++] = 0x48;
			c[code_n++] = ptr ? 0x8b : 0x8d;
			c[code_n++] = 0x05;
			put32(c, code_n, (uint32_t)rel);
			code_n += 4;
			c[code_n++] = 0xff; c[code_n++] = 0xd0;     /* call rax */
			c[code_n++] = 0xc3;
		}
		if (shape == INLINE_BIGCODE)
			code_n = 9000;              /* a program, not a loader */
	}

	sym_off = (data_off + var_n + 16u + 7u) & ~7ull;
	str_off = sym_off + 3u * 24u;
	shstr_off = str_off + sizeof str;
	sh_off = (shstr_off + sizeof shs + 7u) & ~7ull;
	scf_sh_off = sh_off;
	scf_sym_off = sym_off;
	memset(b + sym_off, 0, 3u * 24u);
	put32(b + sym_off + 24, 0, 1);                       /* _start */
	b[sym_off + 24 + 4] = 0x12;
	put16(b + sym_off + 24, 6, 1);
	put64(b + sym_off + 24, 8, TEXT_VA);
	put64(b + sym_off + 24, 16, code_n);
	put32(b + sym_off + 48, 0, 8);                       /* payload */
	b[sym_off + 48 + 4] = 0x11;                          /* GLOBAL OBJECT */
	put16(b + sym_off + 48, 6, 3);                       /* .data */
	put64(b + sym_off + 48, 8, var_va);
	put64(b + sym_off + 48, 16, var_n);
	memcpy(b + str_off, str, sizeof str);
	memcpy(b + shstr_off, shs, sizeof shs);

	memset(b + sh_off, 0, 7u * 64u);
	sec_hdr(b + sh_off + 64, 1, 1, 6, TEXT_VA, text_off, code_n, 0, 0, 0);
	sec_hdr(b + sh_off + 128, 7, 1, 2, 0x400000ull + ro_off, ro_off, 0x80, 0, 0, 0);
	sec_hdr(b + sh_off + 192, 15, 1, 3, var_va, data_off, var_n, 0, 0, 0);
	sec_hdr(b + sh_off + 256, 21, 2, 0, 0, sym_off, 3u * 24u, 5, 1, 24);
	sec_hdr(b + sh_off + 320, 29, 3, 0, 0, str_off, sizeof str, 0, 0, 0);
	sec_hdr(b + sh_off + 384, 37, 3, 0, 0, shstr_off, sizeof shs, 0, 0, 0);
	put64(b, 40, sh_off);
	put16(b, 60, 7);
	put16(b, 62, 6);
	len = sh_off + 7u * 64u;
	if (shape == INLINE_BIGCODE)
		len = len;      /* the code is claimed bigger than it is: the section says it */
	return len;
}


#endif /* KOF_TESTS_SCF_IMG_H */
