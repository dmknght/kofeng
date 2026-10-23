/*
 * lineage_img.h - the lineage tests' image builders: the code of lineage_cg.h in a dynamically linked ELF
 * (x86-64 or i386) or a PE (x64 or x86) that the engine's own parsers accept.
 *
 * WHAT THE ELF CARRIES: a PT_INTERP, a read+execute segment (headers, .interp, .dynsym, .dynstr, the
 * relocation section, the PLT, the code) and a read+write one (.got.plt, the globals and the pointer
 * table), section headers - and, for half of the images, a .symtab of the functions - so both ways the engine
 * learns where functions are (symbols; call targets) are read. The PLT is the lazy kind or the IBT kind
 * (`endbr64; bnd jmp`), drawn per image. A PE is one executable section holding the code, the thunks, the
 * import directory and the globals, imports by name.
 *
 * Written from the formats' documents, field by field, and not by a function of the engine's parsers.
 */
#ifndef KGENOME_TESTS_LINEAGE_IMG_H
#define KGENOME_TESTS_LINEAGE_IMG_H

#include "lineage_cg.h"

#define LG_IMG_MAX (1u << 18)

struct lg_img {
	uint8_t  b[LG_IMG_MAX];
	uint32_t n;
	uint32_t code_off;              /* the file offset of the first byte of the code */
	uint64_t code_va;
	uint64_t sym[LG_NSYM];
};

static LA_UNUSED void lg_p16(uint8_t *b, uint32_t at, uint32_t v)
{
	b[at] = (uint8_t)v;
	b[at + 1u] = (uint8_t)(v >> 8);
}

static LA_UNUSED void lg_p32(uint8_t *b, uint32_t at, uint32_t v)
{
	lg_p16(b, at, v & 0xffffu);
	lg_p16(b, at + 2u, v >> 16);
}

static LA_UNUSED void lg_p64(uint8_t *b, uint32_t at, uint64_t v)
{
	lg_p32(b, at, (uint32_t)v);
	lg_p32(b, at + 4u, (uint32_t)(v >> 32));
}

/* A word of the target's width. */
static LA_UNUSED void lg_pw(uint8_t *b, uint32_t at, uint64_t v, int wide)
{
	if (wide)
		lg_p64(b, at, v);
	else
		lg_p32(b, at, (uint32_t)v);
}

/* Patch the code's symbol fixups now that the layout names every symbol's address. */
static LA_UNUSED int lg_patch(struct lg_img *g, struct lg_cg *c)
{
	uint32_t i;

	for (i = 0; i < c->a.nfx; i++) {
		const struct la_fx *f = &c->a.fx[i];
		int64_t v;
		uint8_t *p = g->b + g->code_off + f->at;

		if (f->kind == LA_FX_LABEL)
			continue;
		if (f->target < 0 || f->target >= (int)LG_NSYM || !g->sym[f->target])
			return 0;
		if (f->kind == LA_FX_ABS_SYM)
			v = (int64_t)(g->sym[f->target] & 0xffffffffu);
		else
			v = (int64_t)g->sym[f->target] - (int64_t)(g->code_va + f->end);
		lg_p32(p, 0, (uint32_t)v);
	}
	return 1;
}

static LA_UNUSED uint32_t lg_algn(uint32_t v, uint32_t a)
{
	return (v + a - 1u) & ~(a - 1u);
}

/* ---- ELF ---- */

struct lg_sh {
	uint32_t name, type;
	uint64_t flags, addr, off, size;
	uint32_t link, info;
	uint64_t align, entsize;
};

static LA_UNUSED void lg_put_sh(uint8_t *b, uint32_t at, const struct lg_sh *s, int wide)
{
	if (wide) {
		lg_p32(b, at, s->name);
		lg_p32(b, at + 4u, s->type);
		lg_p64(b, at + 8u, s->flags);
		lg_p64(b, at + 16u, s->addr);
		lg_p64(b, at + 24u, s->off);
		lg_p64(b, at + 32u, s->size);
		lg_p32(b, at + 40u, s->link);
		lg_p32(b, at + 44u, s->info);
		lg_p64(b, at + 48u, s->align);
		lg_p64(b, at + 56u, s->entsize);
	} else {
		lg_p32(b, at, s->name);
		lg_p32(b, at + 4u, s->type);
		lg_p32(b, at + 8u, (uint32_t)s->flags);
		lg_p32(b, at + 12u, (uint32_t)s->addr);
		lg_p32(b, at + 16u, (uint32_t)s->off);
		lg_p32(b, at + 20u, (uint32_t)s->size);
		lg_p32(b, at + 24u, s->link);
		lg_p32(b, at + 28u, s->info);
		lg_p32(b, at + 32u, (uint32_t)s->align);
		lg_p32(b, at + 36u, (uint32_t)s->entsize);
	}
}

/* A string table of the names, NUL-separated from a leading NUL; the offset of each is returned in off[]. */
static LA_UNUSED uint32_t lg_strtab(uint8_t *dst, const char *const *names, int n, uint32_t *off)
{
	uint32_t at = 1;
	int i;

	dst[0] = 0;
	for (i = 0; i < n; i++) {
		size_t l = strlen(names[i]);

		off[i] = at;
		memcpy(dst + at, names[i], l + 1u);
		at += (uint32_t)l + 1u;
	}
	return at;
}

static LA_UNUSED int lg_build_elf(struct lg_img *g, struct lg_cg *c, struct lg_rng *r, int with_symtab)
{
	const int wide = c->wide;
	const uint32_t wsz = wide ? 8u : 4u;
	const uint64_t base = wide ? 0x400000ull : 0x08048000ull, rw = base + 0x200000ull;
	const uint32_t ehsz = wide ? 64u : 52u, phsz = wide ? 56u : 32u, shsz = wide ? 64u : 40u;
	const uint32_t symsz = wide ? 24u : 16u, relsz = wide ? 24u : 8u;
	const uint32_t interp = 0x100, dynsym = 0x140, dynstr = 0x280, rel = 0x400, plt = 0x600, text = 0x700;
	const int ibt = wide && lg_rnd(r, 2u);
	/* a position-independent i386 object reaches its slots through ebx, which holds the GOT: `jmp [ebx + slot - GOT]` */
	const int pic = !wide && lg_rnd(r, 3u) == 0;
	/* the slot a call reaches is filled by JUMP_SLOT (7) in lazy binding and by GLOB_DAT (6) where the code goes through the slot itself */
	uint32_t rtype_of[LG_NIMP];
	const uint32_t rx_end = text + c->a.n;
	const uint32_t data_off = lg_algn(rx_end + 16u, 0x1000u);
	const uint32_t got = data_off, glob = data_off + 0x200u, tab = data_off + 0x300u;
	const uint32_t sh_off = data_off + 0x1000u, shstr_off = sh_off + 12u * shsz;
	uint32_t noff[LG_NIMP], nstr, i, nsh = 0, shl = 1, shn[11];
	uint32_t sym_off = 0, str_off = 0, sym_n = 0, strn = 0, fn_str[LG_MAXF];
	const char *const fnn[LG_MAXF] = { "f0", "f1", "f2", "f3" };
	const char *const sn[11] = { ".interp", ".dynsym", ".dynstr", wide ? ".rela.plt" : ".rel.plt", ".plt", ".text",
				     ".got.plt", ".data", ".shstrtab", ".symtab", ".strtab" };
	char shnames[256];
	struct lg_sh sh[12];
	uint8_t *b = g->b;
	int imp;

	if (shstr_off + 0x1000u > LG_IMG_MAX)
		return 0;
	/* the first import is always bound lazily: the lowest JUMP_SLOT is where an i386 PIC object finds its GOT */
	for (imp = 0; imp < LG_NIMP; imp++)
		rtype_of[imp] = imp > 1 && lg_rnd(r, 2u) ? 6u : 7u;
	memset(b, 0, shstr_off + 0x1000u);
	g->code_off = text;
	g->code_va = base + text;
	/* every symbol's address, once */
	memset(g->sym, 0, sizeof g->sym);
	for (imp = 1; imp < LG_NIMP; imp++) {
		g->sym[LG_SYM_STUB(imp)] = base + plt + 16u * (uint32_t)imp;
		g->sym[LG_SYM_THUNK(imp)] = g->sym[LG_SYM_STUB(imp)];     /* an ELF has no thunks: the stub */
		g->sym[LG_SYM_SLOT(imp)] = rw + got + wsz * (uint32_t)(3 + imp - 1);
	}
	for (i = 0; i < LG_MAXG; i++)
		g->sym[LG_SYM_G(i)] = rw + glob + 16u * i;
	g->sym[LG_SYM_TAB] = rw + tab;
	memcpy(b + text, c->a.b, c->a.n);
	if (!lg_patch(g, c))
		return 0;
	nstr = lg_strtab(b + dynstr, lg_elf_names + 1, LG_NIMP - 1, noff);
	strcpy((char *)b + interp, wide ? "/lib64/ld-linux-x86-64.so.2" : "/lib/ld-linux.so.2");
	/* .dynsym (a null symbol, then each import: undefined, global, function) and the relocations of the GOT slots */
	for (imp = 1; imp < LG_NIMP; imp++) {
		const uint32_t at = dynsym + symsz * (uint32_t)imp, ra = rel + relsz * (uint32_t)(imp - 1);
		const uint64_t slot = g->sym[LG_SYM_SLOT(imp)];

		lg_p32(b, at, noff[imp - 1]);
		if (wide) {
			b[at + 4] = 0x12;
			lg_p64(b, ra, slot);
			lg_p64(b, ra + 8u, ((uint64_t)imp << 32) | rtype_of[imp]);
		} else {
			b[at + 12] = 0x12;
			lg_p32(b, ra, (uint32_t)slot);
			lg_p32(b, ra + 4u, ((uint32_t)imp << 8) | rtype_of[imp]);
		}
	}
	/* .plt: PLT0, then a stub of 16 bytes for each import, and the GOT slot it jumps through */
	memset(b + plt, 0xcc, 16u * (uint32_t)LG_NIMP);
	for (imp = 1; imp < LG_NIMP; imp++) {
		uint32_t o = plt + 16u * (uint32_t)imp;
		const uint64_t slot = g->sym[LG_SYM_SLOT(imp)];

		if (ibt) {
			b[o++] = 0xf3; b[o++] = 0x0f; b[o++] = 0x1e; b[o++] = 0xfa;               /* endbr64 */
			b[o++] = 0xf2; b[o++] = 0xff; b[o++] = 0x25;                              /* bnd jmp [rip+d] */
			lg_p32(b, o, (uint32_t)(slot - (base + o + 4u)));
			o += 4;
			b[o++] = 0x0f; b[o++] = 0x1f; b[o++] = 0x44; b[o++] = 0; b[o++] = 0;      /* nop */
			lg_pw(b, got + wsz * (uint32_t)(3 + imp - 1), g->sym[LG_SYM_STUB(imp)], wide);
		} else {
			b[o++] = 0xff; b[o++] = pic ? 0xa3 : 0x25;
			lg_p32(b, o, wide ? (uint32_t)(slot - (base + o + 4u)) : pic ? (uint32_t)(slot - (rw + got)) : (uint32_t)slot);
			o += 4;
			b[o++] = 0x68;
			lg_p32(b, o, (uint32_t)(imp - 1));
			o += 4;
			b[o++] = 0xe9;
			lg_p32(b, o, (uint32_t)((base + plt) - (base + o + 4u)));
			lg_pw(b, got + wsz * (uint32_t)(3 + imp - 1), g->sym[LG_SYM_STUB(imp)] + 6u, wide);
		}
	}
	/* the headers */
	if (wide) {
		memcpy(b, "\177ELF\2\1\1", 7);
		lg_p16(b, 16, 2); lg_p16(b, 18, 0x3e); lg_p32(b, 20, 1);
		lg_p64(b, 24, g->code_va + c->fn_off[0]);
		lg_p64(b, 32, ehsz);
		lg_p16(b, 52, 64); lg_p16(b, 54, 56); lg_p16(b, 56, 3); lg_p16(b, 58, 64);
		lg_p32(b, ehsz, 3); lg_p32(b, ehsz + 4u, 4);
		lg_p64(b, ehsz + 8u, interp); lg_p64(b, ehsz + 16u, base + interp); lg_p64(b, ehsz + 24u, base + interp);
		lg_p64(b, ehsz + 32u, 28); lg_p64(b, ehsz + 40u, 28); lg_p64(b, ehsz + 48u, 1);
		lg_p32(b, ehsz + phsz, 1); lg_p32(b, ehsz + phsz + 4u, 5);
		lg_p64(b, ehsz + phsz + 8u, 0); lg_p64(b, ehsz + phsz + 16u, base); lg_p64(b, ehsz + phsz + 24u, base);
		lg_p64(b, ehsz + phsz + 32u, rx_end); lg_p64(b, ehsz + phsz + 40u, rx_end); lg_p64(b, ehsz + phsz + 48u, 0x1000);
		lg_p32(b, ehsz + 2u * phsz, 1); lg_p32(b, ehsz + 2u * phsz + 4u, 6);
		lg_p64(b, ehsz + 2u * phsz + 8u, data_off); lg_p64(b, ehsz + 2u * phsz + 16u, rw + data_off);
		lg_p64(b, ehsz + 2u * phsz + 24u, rw + data_off);
		lg_p64(b, ehsz + 2u * phsz + 32u, 0x1000); lg_p64(b, ehsz + 2u * phsz + 40u, 0x1000);
		lg_p64(b, ehsz + 2u * phsz + 48u, 0x1000);
	} else {
		memcpy(b, "\177ELF\1\1\1", 7);
		lg_p16(b, 16, 2); lg_p16(b, 18, 3); lg_p32(b, 20, 1);
		lg_p32(b, 24, (uint32_t)(g->code_va + c->fn_off[0]));
		lg_p32(b, 28, ehsz);
		lg_p16(b, 40, 52); lg_p16(b, 42, 32); lg_p16(b, 44, 3); lg_p16(b, 46, 40);
		lg_p32(b, ehsz, 3); lg_p32(b, ehsz + 4u, interp); lg_p32(b, ehsz + 8u, (uint32_t)base + interp);
		lg_p32(b, ehsz + 12u, (uint32_t)base + interp); lg_p32(b, ehsz + 16u, 19); lg_p32(b, ehsz + 20u, 19);
		lg_p32(b, ehsz + 24u, 4); lg_p32(b, ehsz + 28u, 1);
		lg_p32(b, ehsz + phsz, 1); lg_p32(b, ehsz + phsz + 4u, 0); lg_p32(b, ehsz + phsz + 8u, (uint32_t)base);
		lg_p32(b, ehsz + phsz + 12u, (uint32_t)base); lg_p32(b, ehsz + phsz + 16u, rx_end);
		lg_p32(b, ehsz + phsz + 20u, rx_end); lg_p32(b, ehsz + phsz + 24u, 5); lg_p32(b, ehsz + phsz + 28u, 0x1000);
		lg_p32(b, ehsz + 2u * phsz, 1); lg_p32(b, ehsz + 2u * phsz + 4u, data_off);
		lg_p32(b, ehsz + 2u * phsz + 8u, (uint32_t)rw + data_off); lg_p32(b, ehsz + 2u * phsz + 12u, (uint32_t)rw + data_off);
		lg_p32(b, ehsz + 2u * phsz + 16u, 0x1000); lg_p32(b, ehsz + 2u * phsz + 20u, 0x1000);
		lg_p32(b, ehsz + 2u * phsz + 24u, 6); lg_p32(b, ehsz + 2u * phsz + 28u, 0x1000);
	}
	/* the section names, the section headers, and (when asked) the function symbols after them */
	for (i = 0; i < 11u; i++) {
		shn[i] = shl;
		strcpy(shnames + shl, sn[i]);
		shl += (uint32_t)strlen(sn[i]) + 1u;
	}
	shnames[0] = 0;
	memcpy(b + shstr_off, shnames, shl);
	g->n = shstr_off + lg_algn(shl, 16u);
	if (with_symtab) {
		uint32_t at = 1;

		sym_off = g->n;
		sym_n = (uint32_t)c->p->nf + 1u;
		str_off = sym_off + sym_n * symsz;
		b[str_off] = 0;
		for (i = 0; i < (uint32_t)c->p->nf; i++) {
			const size_t l = strlen(fnn[i]);

			fn_str[i] = at;
			memcpy(b + str_off + at, fnn[i], l + 1u);
			at += (uint32_t)l + 1u;
		}
		strn = at;
		for (i = 0; i < (uint32_t)c->p->nf; i++) {
			const uint32_t e = sym_off + (i + 1u) * symsz;
			const uint64_t va = g->code_va + c->fn_off[i], sz = c->fn_end[i] - c->fn_off[i];

			lg_p32(b, e, fn_str[i]);
			if (wide) {
				b[e + 4] = 0x12;
				lg_p16(b, e + 6u, 6);
				lg_p64(b, e + 8u, va);
				lg_p64(b, e + 16u, sz);
			} else {
				lg_p32(b, e + 4u, (uint32_t)va);
				lg_p32(b, e + 8u, (uint32_t)sz);
				b[e + 12] = 0x12;
				lg_p16(b, e + 14u, 6);
			}
		}
		g->n = str_off + strn;
	}
	memset(sh, 0, sizeof sh);
	sh[1] = (struct lg_sh){ shn[0], 1, 2, base + interp, interp, 28, 0, 0, 1, 0 };
	sh[2] = (struct lg_sh){ shn[1], 11, 2, base + dynsym, dynsym, symsz * (uint32_t)LG_NIMP, 3, 1, 8, symsz };
	sh[3] = (struct lg_sh){ shn[2], 3, 2, base + dynstr, dynstr, nstr, 0, 0, 1, 0 };
	sh[4] = (struct lg_sh){ shn[3], wide ? 4u : 9u, 2, base + rel, rel, relsz * (uint32_t)(LG_NIMP - 1), 2, 7, 8, relsz };
	sh[5] = (struct lg_sh){ shn[4], 1, 6, base + plt, plt, 16u * (uint32_t)LG_NIMP, 0, 0, 16, 16 };
	sh[6] = (struct lg_sh){ shn[5], 1, 6, base + text, text, c->a.n, 0, 0, 16, 0 };
	sh[7] = (struct lg_sh){ shn[6], 1, 3, rw + got, got, 0x200, 0, 0, 8, wsz };
	sh[8] = (struct lg_sh){ shn[7], 1, 3, rw + glob, glob, 0x100, 0, 0, 8, 0 };
	sh[9] = (struct lg_sh){ shn[8], 3, 0, 0, shstr_off, shl, 0, 0, 1, 0 };
	nsh = 10;
	if (with_symtab) {
		sh[10] = (struct lg_sh){ shn[9], 2, 0, 0, sym_off, sym_n * symsz, 11, 1, 8, symsz };
		sh[11] = (struct lg_sh){ shn[10], 3, 0, 0, str_off, strn, 0, 0, 1, 0 };
		nsh = 12;
	}
	for (i = 0; i < nsh; i++)
		lg_put_sh(b, sh_off + i * shsz, &sh[i], wide);
	if (wide) {
		lg_p64(b, 40, sh_off);
		lg_p16(b, 60, nsh);
		lg_p16(b, 62, 9);
	} else {
		lg_p32(b, 32, sh_off);
		lg_p16(b, 48, nsh);
		lg_p16(b, 50, 9);
	}
	return g->n <= LG_IMG_MAX;
}

/* ---- PE ---- */

static LA_UNUSED int lg_build_pe(struct lg_img *g, struct lg_cg *c)
{
	const int wide = c->wide;
	const uint32_t hdr = 0x400, fa = 0x200, o = 0x80 + 24u, sec = o + 0xf0u;
	const uint32_t text_rva = 0x1000, idata = 0x4000, data = 0x6000, sect = 0x8000;
	const uint64_t ib = wide ? 0x140000000ull : 0x400000ull;
	const uint32_t w = wide ? 8u : 4u;
	const uint32_t ilt = idata + 0x100u, iat = idata + 0x200u, hn = idata + 0x300u, dll = idata + 0x2f0u;
	uint8_t *b = g->b;
	uint32_t i;
	int imp;

	if (c->a.n > 0x3000u)
		return 0;
	memset(b, 0, hdr + sect);
	g->code_off = hdr;
	g->code_va = ib + text_rva;
	b[0] = 'M'; b[1] = 'Z';
	lg_p32(b, 0x3c, 0x80);
	memcpy(b + 0x80, "PE\0\0", 4);
	lg_p16(b, 0x84, wide ? 0x8664u : 0x014cu);
	lg_p16(b, 0x86, 1);
	lg_p16(b, 0x94, 0xf0);
	lg_p16(b, 0x96, 0x22);
	lg_p16(b, o, wide ? 0x20bu : 0x10bu);
	b[o + 2] = 14;
	lg_p32(b, o + 4, c->a.n);
	lg_p32(b, o + 16, text_rva + c->fn_off[0]);
	lg_p32(b, o + 20, text_rva);
	if (wide) {
		lg_p64(b, o + 24, ib);
		lg_p32(b, o + 32, 0x1000); lg_p32(b, o + 36, fa);
		lg_p16(b, o + 40, 6); lg_p16(b, o + 48, 6);
		lg_p32(b, o + 56, 0x9000); lg_p32(b, o + 60, hdr);
		lg_p16(b, o + 68, 3);
		lg_p32(b, o + 108, 16);
		lg_p32(b, o + 112 + 8, text_rva + idata);
		lg_p32(b, o + 112 + 12, 40);
	} else {
		lg_p32(b, o + 24, 0x1000);
		lg_p32(b, o + 28, (uint32_t)ib);
		lg_p32(b, o + 32, 0x1000); lg_p32(b, o + 36, fa);
		lg_p16(b, o + 40, 6); lg_p16(b, o + 48, 6);
		lg_p32(b, o + 56, 0x9000); lg_p32(b, o + 60, hdr);
		lg_p16(b, o + 68, 3);
		lg_p32(b, o + 92, 16);
		lg_p32(b, o + 96 + 8, text_rva + idata);
		lg_p32(b, o + 96 + 12, 40);
	}
	memcpy(b + sec, ".text\0\0\0", 8);
	lg_p32(b, sec + 8, sect);
	lg_p32(b, sec + 12, text_rva);
	lg_p32(b, sec + 16, sect);
	lg_p32(b, sec + 20, hdr);
	lg_p32(b, sec + 36, 0xe0000020u);
	/* the symbols of the layout: the IAT slots, the thunks, the globals */
	memset(g->sym, 0, sizeof g->sym);
	for (imp = 1; imp < LG_NIMP; imp++) {
		g->sym[LG_SYM_SLOT(imp)] = ib + text_rva + iat + w * (uint32_t)(imp - 1);
		if (c->thunk_used[imp])
			g->sym[LG_SYM_THUNK(imp)] = g->code_va + c->thunk_off[imp];
	}
	for (i = 0; i < LG_MAXG; i++)
		g->sym[LG_SYM_G(i)] = ib + text_rva + data + 16u * i;
	g->sym[LG_SYM_TAB] = ib + text_rva + data + 0x100u;
	memcpy(b + hdr, c->a.b, c->a.n);
	if (!lg_patch(g, c))
		return 0;
	/* the import directory: one DLL, every import by name */
	lg_p32(b, hdr + idata + 0, text_rva + ilt);
	lg_p32(b, hdr + idata + 12, text_rva + dll);
	lg_p32(b, hdr + idata + 16, text_rva + iat);
	memcpy(b + hdr + dll, "dll1.dll", 9);
	{
		const char *const *names = lg_pe_names;

		for (imp = 1; imp < LG_NIMP; imp++) {
			uint32_t e = hn + 0x20u * (uint32_t)(imp - 1);
			uint32_t rva = text_rva + e;

			memcpy(b + hdr + e + 2u, names[imp], strlen(names[imp]) + 1u);
			if (wide) {
				lg_p64(b, hdr + ilt + w * (uint32_t)(imp - 1), rva);
				lg_p64(b, hdr + iat + w * (uint32_t)(imp - 1), rva);
			} else {
				lg_p32(b, hdr + ilt + w * (uint32_t)(imp - 1), rva);
				lg_p32(b, hdr + iat + w * (uint32_t)(imp - 1), rva);
			}
		}
	}
	g->n = hdr + sect;
	return 1;
}

static LA_UNUSED int lg_build(struct lg_img *g, struct lg_cg *c, struct lg_rng *r, int with_symtab)
{
	if (c->a.overflow)
		return 0;
	return c->pe ? lg_build_pe(g, c) : lg_build_elf(g, c, r, with_symtab);
}

#endif /* KGENOME_TESTS_LINEAGE_IMG_H */
