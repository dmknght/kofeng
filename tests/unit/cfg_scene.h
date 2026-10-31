/*
 * cfg_scene.h - an ELF64 x86-64 object ASSEMBLED AT RUN TIME for the tests of the CFG signature: functions whose control-flow graphs are given
 * as a spec (blocks, their kind and target), inert code only (nop, jne, jmp, ret), a symbol table that names them, one executable PT_LOAD.
 * Nothing is stored and nothing is malware-shaped: a function is `nop; jne next-but-one; nop; jne ...; ret`.
 *
 * Shared by tests/unit/cfg_sig_match.c (the verdict path and the similarity ladder) and tests/unit/cfg_sig_gen.c (Generate, Save, the builder).
 * Independent of every other kit on purpose (the two kits of the cfg lib tests define the same macro names as the editor's header).
 */
#ifndef KOF_TESTS_CFG_SCENE_H
#define KOF_TESTS_CFG_SCENE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum { CS_EXIT, CS_FALL, CS_JUMP, CS_COND };
#define CS_MAXB 96u

/* One function: block i is `pad[i]` nops and then its terminator. COND jumps to block t[i] and falls into i+1; JUMP goes to t[i]; EXIT is a `ret`;
 * FALL has none and runs into the next block. The last block must be EXIT or JUMP (a fall off the end is allowed and ends the function). */
struct cs_spec {
	uint32_t nb;
	uint8_t  kind[CS_MAXB];
	uint32_t t[CS_MAXB];
	uint8_t  pad[CS_MAXB];
};

/* The x86-64 bytes of a spec; returns their count (out must hold 16 * CS_MAXB). */
static size_t cs_code(const struct cs_spec *g, uint8_t *out)
{
	uint32_t at[CS_MAXB + 1u], b, i;
	size_t n = 0;
	int pass;

	for (pass = 0; pass < 2; pass++) {
		n = 0;
		for (b = 0; b < g->nb; b++) {
			at[b] = (uint32_t)n;
			for (i = 0; i < 1u + g->pad[b]; i++)
				out[n++] = 0x90;
			switch (g->kind[b]) {
			case CS_EXIT:
				out[n++] = 0xc3;
				break;
			case CS_JUMP:
			case CS_COND: {
				const int32_t rel = pass ? (int32_t)at[g->t[b]] - (int32_t)(n + (g->kind[b] == CS_COND ? 6u : 5u)) : 0;

				if (g->kind[b] == CS_COND) {
					out[n++] = 0x0f;
					out[n++] = 0x85;
				} else {
					out[n++] = 0xe9;
				}
				memcpy(out + n, &rel, 4);
				n += 4;
				break;
			}
			default:
				break;
			}
		}
		at[g->nb] = (uint32_t)n;
	}
	return n;
}

#define CS_MAX_OBJ 65536u
#define CS_TEXT_OFF 0x200u
#define CS_VA 0x400000u

struct cs_obj {
	uint8_t  b[CS_MAX_OBJ];
	size_t   n;
	uint32_t n_fn;
	uint64_t f_off[16], f_len[16];
};

static void cs_p16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void cs_p32(uint8_t *p, uint32_t v) { cs_p16(p, (uint16_t)v); cs_p16(p + 2, (uint16_t)(v >> 16)); }
static void cs_p64(uint8_t *p, uint64_t v) { cs_p32(p, (uint32_t)v); cs_p32(p + 4, (uint32_t)(v >> 32)); }

/*
 * Build the object: `lead` bytes of int3 padding, then the functions one after the other (16-byte aligned, int3 between), a symbol table naming
 * them f0, f1, ... Returns 1. `gap` bytes of int3 follow each function (the cut groups functions that are within 32 bytes of each other).
 */
static int cs_build_gap(struct cs_obj *o, const struct cs_spec *fn, uint32_t n_fn, uint32_t lead, uint32_t gap)
{
	uint8_t code[16u * CS_MAXB];
	uint8_t *b = o->b;
	size_t text = CS_TEXT_OFF, at, strtab_off, symtab_off, shstr_off, sh_off, i;
	static const char shstr[] = "\0.text\0.symtab\0.strtab\0.shstrtab";
	char names[256];
	size_t nl = 1;
	uint32_t k;

	if (n_fn > 16u)
		return 0;
	memset(o, 0, sizeof *o);
	memset(b + text, 0xcc, lead);
	at = text + lead;
	names[0] = 0;
	for (k = 0; k < n_fn; k++) {
		const size_t len = cs_code(&fn[k], code);

		at = (at + 15u) & ~(size_t)15u;
		if (at + len + 64u >= CS_MAX_OBJ / 2u)
			return 0;
		memcpy(b + at, code, len);
		o->f_off[k] = at;
		o->f_len[k] = len;
		at += len + gap;
		nl += (size_t)snprintf(names + nl, sizeof names - nl, "f%u", k) + 1u;
	}
	o->n_fn = n_fn;
	at = (at + 15u) & ~(size_t)15u;
	/* the gaps between functions and the padding are int3 */
	for (i = text; i < at; i++) {
		int in_fn = 0;

		for (k = 0; k < n_fn; k++)
			in_fn |= i >= o->f_off[k] && i < o->f_off[k] + o->f_len[k];
		if (!in_fn && i >= text + lead)
			b[i] = 0xcc;
	}
	strtab_off = at;
	memcpy(b + strtab_off, names, nl);
	symtab_off = (strtab_off + nl + 7u) & ~(size_t)7u;
	for (k = 0; k < n_fn; k++) {
		uint8_t *s = b + symtab_off + 24u * (k + 1u);
		size_t nm = 1;
		uint32_t j;

		for (j = 0; j < k; j++)
			nm += strlen(names + nm) + 1u;
		cs_p32(s, (uint32_t)nm);
		s[4] = 0x12;                    /* GLOBAL FUNC */
		cs_p16(s + 6, 1);               /* section 1 */
		cs_p64(s + 8, CS_VA + o->f_off[k]);
		cs_p64(s + 16, o->f_len[k]);
	}
	shstr_off = symtab_off + 24u * (n_fn + 1u);
	memcpy(b + shstr_off, shstr, sizeof shstr);
	sh_off = (shstr_off + sizeof shstr + 7u) & ~(size_t)7u;
	/* ELF header */
	memcpy(b, "\177ELF\2\1\1", 7);
	cs_p16(b + 16, 2);
	cs_p16(b + 18, 0x3e);
	cs_p32(b + 20, 1);
	cs_p64(b + 24, CS_VA + (o->f_off[0] ? o->f_off[0] : text));
	cs_p64(b + 32, 64);
	cs_p64(b + 40, sh_off);
	cs_p16(b + 52, 64);
	cs_p16(b + 54, 56);
	cs_p16(b + 56, 1);
	cs_p16(b + 58, 64);
	cs_p16(b + 60, 5);
	cs_p16(b + 62, 4);
	/* the one PT_LOAD, R+X, over the file up to the end of the code */
	cs_p32(b + 64, 1);
	cs_p32(b + 68, 5);
	cs_p64(b + 72, 0);
	cs_p64(b + 80, CS_VA);
	cs_p64(b + 88, CS_VA);
	cs_p64(b + 96, at);
	cs_p64(b + 104, at);
	cs_p64(b + 112, 0x1000);
	/* section headers: null, .text, .symtab, .strtab, .shstrtab */
	{
		uint8_t *h = b + sh_off + 64u;

		cs_p32(h, 1);  cs_p32(h + 4, 1);  cs_p64(h + 8, 6);  cs_p64(h + 16, CS_VA + text);  cs_p64(h + 24, text);  cs_p64(h + 32, at - text);
		cs_p64(h + 48, 16);
		h += 64;
		cs_p32(h, 7);  cs_p32(h + 4, 2);  cs_p64(h + 24, symtab_off);  cs_p64(h + 32, 24u * (n_fn + 1u));  cs_p32(h + 40, 3);  cs_p32(h + 44, 1);
		cs_p64(h + 48, 8);  cs_p64(h + 56, 24);
		h += 64;
		cs_p32(h, 15); cs_p32(h + 4, 3);  cs_p64(h + 24, strtab_off);  cs_p64(h + 32, nl);  cs_p64(h + 48, 1);
		h += 64;
		cs_p32(h, 23); cs_p32(h + 4, 3);  cs_p64(h + 24, shstr_off);  cs_p64(h + 32, sizeof shstr);  cs_p64(h + 48, 1);
	}
	o->n = sh_off + 5u * 64u;
	return 1;
}

/* The functions apart: 48 bytes of padding between two, more than the cut's gap (32), so each is a unit of its own and is signed on its own. */
static int cs_build(struct cs_obj *o, const struct cs_spec *fn, uint32_t n_fn, uint32_t lead)
{
	return cs_build_gap(o, fn, n_fn, lead, 48);
}

#endif /* KOF_TESTS_CFG_SCENE_H */
