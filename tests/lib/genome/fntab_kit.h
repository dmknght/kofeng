/*
 * fntab_kit.h - the in-memory ELF writer of the function-table tests (a copy of the writer of fntab.c, with the buffer size a variable so that one test can
 * build a file of megabytes), shared by fntab_cov.c and the siblings that attack the same area. fntab.c keeps its own copy: it is edited in another tree.
 */
#ifndef FNTAB_KIT_H
#define FNTAB_KIT_H
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kgenome.h>
#include <genotype/image/fntab.h>
#include <genotype/image/fntab_private.h>
#include <genotype/image/elf_image.h>
#include <phenotype/diag_scan.h>
#include <phenotype/diag_private.h>

static int fails;
static unsigned long checks;            /* assertions executed */
#define CK(c) do { checks++; if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

#define TEXT_OFF 0x100u
#define MAXB 0x4000u
#define MAXB_BIG 0x400000u
static uint32_t g_maxb = 0x4000u;

struct sym { const char *name; uint64_t value, size; uint8_t info; uint16_t shndx; };

struct elf_in {
	int c64, be;
	uint16_t em;
	uint64_t base;                  /* the address of file offset 0 */
	const uint8_t *text;
	uint32_t text_n;
	uint32_t rodata_n;              /* bytes of .rodata behind .text inside the segment */
	const uint8_t *eh;              /* raw .eh_frame, built for lay.eh_va */
	uint32_t eh_n;
	int sections;                   /* 1: a section table */
	int eh_hdr;                     /* 1: PT_GNU_EH_FRAME + the search header */
	const struct sym *sym;
	unsigned nsym;
	int dyn;                        /* the symbols go to .dynsym */
	int eh_section;                 /* 1: .eh_frame is a section (needs sections) */
};

struct lay { uint32_t ro_off, eh_off, hdr_off, seg_end; uint64_t eh_va, text_va; };

static uint32_t al(uint32_t v, uint32_t a) { return (v + a - 1u) & ~(a - 1u); }

static void layout(const struct elf_in *in, struct lay *l)
{
	l->ro_off = al(TEXT_OFF + in->text_n, 4u);
	l->eh_off = al(l->ro_off + in->rodata_n, 8u);
	l->hdr_off = al(l->eh_off + in->eh_n, 4u);
	l->seg_end = l->hdr_off + (in->eh_hdr ? 16u : 0u);
	l->eh_va = in->base + l->eh_off;
	l->text_va = in->base + TEXT_OFF;
}

struct wr { uint8_t *b; int be; };
static void p16(struct wr *w, uint32_t at, uint32_t v) { w->b[at + (w->be ? 1u : 0u)] = (uint8_t)v; w->b[at + (w->be ? 0u : 1u)] = (uint8_t)(v >> 8); }
static void p32(struct wr *w, uint32_t at, uint32_t v) { int i; for (i = 0; i < 4; i++) w->b[at + (uint32_t)(w->be ? 3 - i : i)] = (uint8_t)(v >> (8 * i)); }
static void p64(struct wr *w, uint32_t at, uint64_t v) { int i; for (i = 0; i < 8; i++) w->b[at + (uint32_t)(w->be ? 7 - i : i)] = (uint8_t)(v >> (8 * i)); }
static void pw(struct wr *w, int c64, uint32_t at, uint64_t v) { if (c64) p64(w, at, v); else p32(w, at, (uint32_t)v); }

/* Builds the file into `out` (MAXB bytes) and returns its size. */
static uint32_t elf_build(const struct elf_in *in, uint8_t *out)
{
	struct wr w = { out, in->be };
	struct lay l;
	const int c64 = in->c64;
	const uint32_t ehsz = c64 ? 64u : 52u, phsz = c64 ? 56u : 32u, shsz = c64 ? 64u : 40u, symsz = c64 ? 24u : 16u;
	uint32_t n = 0, phn = 1u + (in->eh_hdr ? 1u : 0u), ph = ehsz, sh = 0, shn = 0, i;
	uint32_t symtab_off = 0, strtab_off = 0, shstr_off = 0, symtab_n = 0, strtab_n = 0, shstr_n = 0;
	char strtab[512], shstr[128];

	memset(out, 0, g_maxb);
	layout(in, &l);
	out[0] = 0x7f; out[1] = 'E'; out[2] = 'L'; out[3] = 'F';
	out[4] = c64 ? 2 : 1; out[5] = in->be ? 2 : 1; out[6] = 1;
	p16(&w, 16, 2);                         /* ET_EXEC */
	p16(&w, 18, in->em);
	p32(&w, 20, 1);
	pw(&w, c64, 24, in->base + TEXT_OFF);   /* the entry point: the first byte of .text */
	pw(&w, c64, 28 + (c64 ? 4u : 0u), ph);  /* e_phoff */
	p16(&w, c64 ? 52 : 40, ehsz);
	p16(&w, c64 ? 54 : 42, phsz);
	p16(&w, c64 ? 56 : 44, phn);
	/* the segment: everything up to the end of the unwind data, R X */
	if (c64) {
		p32(&w, ph, 1); p32(&w, ph + 4, 5); p64(&w, ph + 8, 0); p64(&w, ph + 16, in->base); p64(&w, ph + 24, in->base);
		p64(&w, ph + 32, l.seg_end); p64(&w, ph + 40, l.seg_end); p64(&w, ph + 48, 0x1000);
	} else {
		p32(&w, ph, 1); p32(&w, ph + 4, 0); p32(&w, ph + 8, (uint32_t)in->base); p32(&w, ph + 12, (uint32_t)in->base);
		p32(&w, ph + 16, l.seg_end); p32(&w, ph + 20, l.seg_end); p32(&w, ph + 24, 5); p32(&w, ph + 28, 0x1000);
	}
	if (in->eh_hdr) {
		const uint32_t p2 = ph + phsz, hv = l.hdr_off;
		const uint64_t hva = in->base + hv;
		if (c64) {
			p32(&w, p2, 0x6474e550u); p32(&w, p2 + 4, 4); p64(&w, p2 + 8, hv); p64(&w, p2 + 16, hva); p64(&w, p2 + 24, hva);
			p64(&w, p2 + 32, 16); p64(&w, p2 + 40, 16); p64(&w, p2 + 48, 4);
		} else {
			p32(&w, p2, 0x6474e550u); p32(&w, p2 + 4, hv); p32(&w, p2 + 8, (uint32_t)hva); p32(&w, p2 + 12, (uint32_t)hva);
			p32(&w, p2 + 16, 16); p32(&w, p2 + 20, 16); p32(&w, p2 + 24, 4); p32(&w, p2 + 28, 4);
		}
		/* version 1, eh_frame_ptr pcrel sdata4, fde_count udata4, table datarel sdata4; the pointer is relative to the field at hv + 4 */
		out[hv] = 1; out[hv + 1] = 0x1b; out[hv + 2] = 0x03; out[hv + 3] = 0x3b;
		p32(&w, hv + 4, (uint32_t)(l.eh_va - (hva + 4u)));
		p32(&w, hv + 8, 0);
	}
	memcpy(out + TEXT_OFF, in->text, in->text_n);
	for (i = 0; i < in->rodata_n; i++)
		out[l.ro_off + i] = (uint8_t)(0x41u + i % 26u);                 /* strings: not code */
	if (in->eh_n)
		memcpy(out + l.eh_off, in->eh, in->eh_n);
	n = l.seg_end;
	if (!in->sections)
		return n;
	/* .symtab/.dynsym, .strtab, .shstrtab, then the section table: null .text .rodata .eh_frame [.symtab .strtab] .shstrtab */
	{
		uint32_t k, nm = 1;

		strtab[0] = 0;
		strtab_n = 1;
		for (k = 0; k < in->nsym; k++) {
			size_t ln = strlen(in->sym[k].name) + 1u;
			memcpy(strtab + strtab_n, in->sym[k].name, ln);
			strtab_n += (uint32_t)ln;
		}
		symtab_n = (in->nsym + 1u) * symsz;
		if (in->nsym) {
			symtab_off = al(n, 8u);
			n = symtab_off + symtab_n;
			strtab_off = n;
			memcpy(out + n, strtab, strtab_n);
			n += strtab_n;
			nm = 0;
			strtab_n = 1;
			for (k = 0; k < in->nsym; k++) {
				const struct sym *s = &in->sym[k];
				uint32_t o = symtab_off + (k + 1u) * symsz;

				p32(&w, o, strtab_n);
				if (c64) {
					out[o + 4] = s->info; p16(&w, o + 6, s->shndx); p64(&w, o + 8, s->value); p64(&w, o + 16, s->size);
				} else {
					p32(&w, o + 4, (uint32_t)s->value); p32(&w, o + 8, (uint32_t)s->size); out[o + 12] = s->info; p16(&w, o + 14, s->shndx);
				}
				strtab_n += (uint32_t)strlen(s->name) + 1u;
			}
		}
		(void)nm;
		memcpy(shstr, "\0.text\0.rodata\0.eh_frame\0.symtab\0.strtab\0.shstrtab\0.dynsym\0", 59);
		shstr_n = 59;
		shstr_off = n;
		memcpy(out + n, shstr, shstr_n);
		n += shstr_n;
		sh = al(n, 8u);
		/* names: .text 1, .rodata 7, .eh_frame 15, .symtab 25, .strtab 33, .shstrtab 41, .dynsym 51 */
		{
			uint32_t idx = 0;
#define SEC(name, type, flags, addr, off, size, link, entsz) do { \
	uint32_t o_ = sh + idx * shsz; \
	p32(&w, o_, name); p32(&w, o_ + 4, type); \
	if (c64) { p64(&w, o_ + 8, flags); p64(&w, o_ + 16, addr); p64(&w, o_ + 24, off); p64(&w, o_ + 32, size); p32(&w, o_ + 40, link); p64(&w, o_ + 56, entsz); } \
	else { p32(&w, o_ + 8, (uint32_t)(flags)); p32(&w, o_ + 12, (uint32_t)(addr)); p32(&w, o_ + 16, off); p32(&w, o_ + 20, size); p32(&w, o_ + 24, link); p32(&w, o_ + 36, entsz); } \
	idx++; } while (0)
			SEC(0, 0, 0, 0, 0, 0, 0, 0);
			SEC(1, 1, 6, in->base + TEXT_OFF, TEXT_OFF, in->text_n, 0, 0);
			SEC(7, 1, 2, in->base + l.ro_off, l.ro_off, in->rodata_n ? in->rodata_n : 1u, 0, 0);
			SEC(15, in->eh_section ? 1 : 0, 2, l.eh_va, l.eh_off, in->eh_section ? in->eh_n : 0u, 0, 0);   /* type 0: the slot is kept (the indices) and is no .eh_frame */
			if (in->nsym) {
				const uint32_t strx = idx + 1u;
				SEC(in->dyn ? 51 : 25, in->dyn ? 11 : 2, in->dyn ? 2 : 0, 0, symtab_off, symtab_n, strx, symsz);
				SEC(33, 3, 0, 0, strtab_off, strtab_n, 0, 0);
			}
			SEC(41, 3, 0, 0, shstr_off, shstr_n, 0, 0);
			shn = idx;
			if (c64) { p64(&w, 40, sh); p16(&w, 58, shsz); p16(&w, 60, shn); p16(&w, 62, shn - 1u); }
			else { p32(&w, 32, sh); p16(&w, 46, shsz); p16(&w, 48, shn); p16(&w, 50, shn - 1u); }
			n = sh + shn * shsz;
#undef SEC
		}
	}
	return n;
}

static int parse(const uint8_t *b, uint32_t n, struct kgenome_elf_info *ei, struct kgenome_obj *o)
{
	memset(ei, 0, sizeof *ei);
	memset(o, 0, sizeof *o);
	if (!kgenome_elf_image_parse(kof_buf_make(b, n), ei, o))
		return 0;
	o->file_header = ei;
	return 1;
}


struct fde { uint32_t off, len; };

/* x86-64, 4 functions of 16-byte slots, padded with int3: S (call A; call B; ret), A, B, C (nobody calls it) */
static uint32_t x86_text(uint8_t *t)
{
	memset(t, 0xcc, 0x40);
	t[0] = 0xe8; { int32_t d = 0x10 - 5; memcpy(t + 1, &d, 4); }
	t[5] = 0xe8; { int32_t d = 0x20 - 10; memcpy(t + 6, &d, 4); }
	t[10] = 0xc3;
	memcpy(t + 0x10, "\x55\x48\x89\xe5\x5d\xc3", 6);
	memcpy(t + 0x20, "\x55\x48\x89\xe5\x90\x90\x5d\xc3", 8);
	memcpy(t + 0x30, "\x55\x48\x89\xe5\x5d\xc3", 6);
	return 0x40;
}

__attribute__((unused)) static const struct kgenome_func *fn_at(const struct kgenome_func_set *s, uint64_t off)
{
	uint32_t i;

	for (i = 0; i < s->n; i++)
		if (s->v[i].off == off)
			return &s->v[i];
	return NULL;
}

static uint8_t B[MAXB_BIG];

#endif
