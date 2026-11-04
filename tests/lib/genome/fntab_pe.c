/*
 * fntab_pe - the function table of a PE image (phase A2): libgenome/genotype/image/fntab_pe_*.c, phenotype/fntab_reach.c + fntab_ends.c (the GAPS step),
 * phenotype/fntab_pe_thunk.c, and the PE rows of the selector (fntab_select.c).
 *
 * Every image here is BUILT IN MEMORY by the writer below from the values the test names, so a reader sees the case next to its check. RED means: the row fails on the
 * tree before this change (base): the rows that use only kgenome_diag_funcs_with_walk are compiled against base with -DFNTAB_PE_OLD_API_ONLY to show it (the strategy
 * rows need the new API and are not compiled there).
 *
 * Why the old tests missed what these catch: (a) x86 PE had no function set at all and no test asked for one (mutation_units.c builds a PE and checks only that the
 * x64 .pdata entries come back); the exports, the TLS callbacks, the COFF symbols, the import stubs and the leaf functions had no code to run; (b) the .pdata reader ran
 * only on tables that were well formed: no unwind info outside the file, no version 0, no chained entry, no End < Begin, no count past the section; (c) the .pdata test
 * checked the number of entries, not their start and END.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kgenome.h>
#ifndef FNTAB_PE_OLD_API_ONLY
#include <genotype/image/fntab.h>
#endif
#include <genotype/image/pe_image.h>
#include <phenotype/diag_scan.h>
#include <phenotype/diag_private.h>
#ifndef FNTAB_PE_OLD_API_ONLY
#include <phenotype/frame.h>
#endif

#include "fntab_pe_kit.h"

/* ---- fixtures: x86 code ------------------------------------------------------------------------------------------ */

/* The functions of an x86 image: three, called by direct calls, `cc` between them and zero fill to the end of the raw section (as a linker leaves it). */
static uint32_t x86_image(struct pb *p, uint32_t text_raw)
{
	uint32_t t, k;
	uint8_t *c;

	pb_init(p, 0x4000, 0, 0x14c);
	t = pb_sec(p, ".text", 0x1000, text_raw, text_raw, CH_CODE);
	pb_entry(p, 0x1000);
	c = p->b + t;
	memset(c, 0xcc, 0x60);
	{
		static const uint8_t f1[] = { 0x55, 0x8b, 0xec, 0xe8, 0, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0x5d, 0xc3 };
		static const uint8_t f2[] = { 0x55, 0x8b, 0xec, 0x33, 0xc0, 0x5d, 0xc3 };
		static const uint8_t f3[] = { 0x55, 0x8b, 0xec, 0x90, 0x5d, 0xc3 };

		memcpy(c, f1, sizeof f1); memcpy(c + 0x20, f2, sizeof f2); memcpy(c + 0x40, f3, sizeof f3);
		k = 0x20u - 8u; memcpy(c + 4, &k, 4);              /* call 0x1020 from 0x1003: rel = 0x20 - 8 */
		k = 0x40u - 13u; memcpy(c + 9, &k, 4);             /* call 0x1040 from 0x1008 */
	}
	memset(c + 0x60, 0, 0x200 - 0x60);
	pb_done(p);
	return t;
}

/* The case: PE32 with nothing: the walk's starts (call targets and the entry), the end is the next start less the padding. RED on base: x86 had no function set at all. */
static void t_x86_walk(void)
{
	struct pb p;
	struct tab t;
	uint32_t base = x86_image(&p, 0x200);
	const struct kgenome_func *f;

	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	CK(t.fs.n == 3);
	f = at(&t, base);
	CK(f && f->len == 15);                      /* ends at the ret, the cc padding is not the function */
	f = at(&t, base + 0x20);
	CK(f && f->len == 7);
	f = at(&t, base + 0x40);
	CK(f && f->len == 6);                       /* the last one ends where the padding and the zero fill begin, not at the section's end */
#ifndef FNTAB_PE_OLD_API_ONLY
	/* every end is what the entry REACHES (its `ret`): none is left open, so the state says the starts are partial and no end is (it said both on the next-start rule) */
	CK(f && !(f->flags & KGENOME_FN_F_END_OPEN) && f->end_source == KGENOME_FN_E_REACH);
	CK(t.fs.ccase == KGENOME_FNTAB_C_PE_WALK);
	CK(t.fs.state == KGENOME_FNTAB_PARTIAL && (t.fs.partial & KGENOME_FNTAB_P_STARTS) && !(t.fs.partial & KGENOME_FNTAB_P_ENDS));
#endif
	tab_free(&t);
	free(p.b);
}

/* One walk per object, and the walk is the only decode: the table asked twice gives the same table (idempotence), and an image whose code section is shorter than its
 * VirtualSize ends the last function at the file's bytes (section with VirtualSize > raw). */
static void t_x86_idempotent_and_virtual(void)
{
	struct pb p;
	struct tab a, b;
	uint32_t i;

	x86_image(&p, 0x200);
	w(p.b + p.sec_tab + 8, 0x5000, 4);                  /* VirtualSize far past the raw bytes */
	build(p.b, p.n, &a);
	build(p.b, p.n, &b);
	CK(a.fs.n == 3 && a.fs.n == b.fs.n);
	for (i = 0; i < a.fs.n && i < b.fs.n; i++)
		CK(a.fs.v[i].off == b.fs.v[i].off && a.fs.v[i].len == b.fs.v[i].len && a.fs.v[i].flags == b.fs.v[i].flags);
	CK(table_ok(&a, p.n));
	tab_free(&a); tab_free(&b);
	free(p.b);
}

/* The code extent of a PE section is min(raw size, VirtualSize): the loader maps no more, and the raw bytes past VirtualSize are the file's alignment. A function that lies in them (a call
 * target there) is in no extent and is no start; the extent is the one statement every reader of a PE's code shares (kgenome_diag_extent). */
static void t_virtual_size_cut(void)
{
	struct pb p;
	struct tab t;
	uint32_t base = x86_image(&p, 0x200), d = 0x100u - 8u;
	uint64_t at_;

	w(p.b + p.sec_tab + 8, 0x80, 4);                    /* VirtualSize 0x80 of 0x200 raw bytes */
	memcpy(p.b + base + 4, &d, 4);                      /* the first call now goes to 0x1100, past VirtualSize */
	memcpy(p.b + base + 0x100, "\x55\x8b\xec\x5d\xc3", 5);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	CK(kgenome_diag_extent(&t.obj, 0, p.n, &at_) == 0x80 && at_ == base);
	CK(at(&t, base) && !at(&t, base + 0x100));
	CK(at(&t, base + 0x40));                            /* a start inside the extent is untouched */
	tab_free(&t);
	free(p.b);
}

/* An entry point outside every executable section is not a start (the entry of nothing: counted), and the image still gets its walk starts. */
static void t_entry_outside_code(void)
{
	struct pb p;
	struct tab t;
	uint32_t base = x86_image(&p, 0x200);

	pb_sec(&p, ".data", 0x2000, 0x200, 0x200, CH_DATA);
	pb_entry(&p, 0x2000);
	pb_done(&p);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	CK(t.fs.n == 2);                                    /* 0x1000 is no longer the entry and nobody calls it: its two callees remain */
	CK(!at(&t, base) && at(&t, base + 0x20) && at(&t, base + 0x40));
	tab_free(&t);
	free(p.b);
}

/* Import stubs: `jmp [iat slot]`, six bytes each, back to back, then a real function. A stub is kind THUNK with its own six bytes and does not swallow the function after
 * the last one; without the strategy the last stub would run to the next start (RED on base: no table at all). */
static void t_thunks(void)
{
	struct pb p;
	struct tab t;
	uint32_t i, t0;
	uint8_t *c;

	pb_init(&p, 0x4000, 0, 0x14c);
	t0 = pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_sec(&p, ".idata", 0x2000, 0x200, 0x200, CH_DATA);
	pb_dir(&p, KGENOME_PE_DIR_IAT, 0x2000, 0x20);
	pb_entry(&p, 0x1000);
	c = p.b + t0;
	/* 0x1000: main = call 0x1048 (a function), call 0x1030 and 0x1036 (two stubs), ret ; 0x1030, 0x1036, 0x103c: three stubs back to back; 0x1048: the function after them */
	memset(c, 0xcc, 0x60);
	{
		static const uint8_t main_[] = { 0x55, 0x8b, 0xec, 0xe8, 0, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0x5d, 0xc3 };
		uint32_t d;

		memcpy(c, main_, sizeof main_);
		d = 0x48u - 8u; memcpy(c + 4, &d, 4);           /* call 0x1048 (the function after the stubs) */
		d = 0x30u - 13u; memcpy(c + 9, &d, 4);          /* call 0x1030 (stub 1) */
		d = 0x36u - 18u; memcpy(c + 14, &d, 4);         /* call 0x1036 (stub 2) */
	}
	for (i = 0; i < 3; i++) {                           /* three stubs at 0x1030, 0x1036, 0x103c: jmp dword [0x402000 + 4 i] */
		uint32_t slot = 0x402000u + 4u * i;

		c[0x30 + 6 * i] = 0xff; c[0x31 + 6 * i] = 0x25;
		memcpy(c + 0x32 + 6 * i, &slot, 4);
	}
	c[0x48] = 0x55; c[0x49] = 0x8b; c[0x4a] = 0xec; c[0x4b] = 0x5d; c[0x4c] = 0xc3;
	memset(c + 0x50, 0, 0x200 - 0x50);
	pb_done(&p);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	{
		const struct kgenome_func *s1 = at(&t, t0 + 0x30), *s2 = at(&t, t0 + 0x36), *s3 = at(&t, t0 + 0x3c), *fn = at(&t, t0 + 0x48);

		CK(s1 && s2 && s3);
		CK(s1 && s1->len == 6 && s2 && s2->len == 6 && s3 && s3->len == 6);
		CK(fn && fn->len == 5 && fn->kind == KGENOME_FN_FUNC);
#ifndef FNTAB_PE_OLD_API_ONLY
		CK(s1 && s1->kind == KGENOME_FN_THUNK && s1->end_source == KGENOME_FN_E_INSN);
		CK(s3 && s3->kind == KGENOME_FN_THUNK);
#endif
	}
	tab_free(&t);
	free(p.b);
}

/* THE STUBS THE WALK MET carry the slot they jump through, sorted by offset (the lineage reads the slot of a function that is one `jmp [slot]`: it decoded the head of every function for it).
 * Three stubs of the IAT at a function start; a jump through a slot OUTSIDE the declared IAT (listed, `iat` 0: the table does not kind it a THUNK, the lineage still asks its slot); a jump
 * that does not stand at a function start (after a `mov`: `start` 0). RED on the base: the list held [at, length] pairs of the first kind only, and no slot. */
static void t_stub_slots(void)
{
	struct pb p;
	struct tab t;
	struct kgenome_diag_walk *wk;
	uint32_t i, t0, n = 0, slot_out = 0x403000u, slot_mid = 0x402010u;
	const struct kgenome_diag_stub *sv;
	uint8_t *c;

	pb_init(&p, 0x4000, 0, 0x14c);
	t0 = pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_sec(&p, ".idata", 0x2000, 0x200, 0x200, CH_DATA);
	pb_dir(&p, KGENOME_PE_DIR_IAT, 0x2000, 0x20);
	pb_entry(&p, 0x1000);
	c = p.b + t0;
	memset(c, 0xcc, 0x80);
	c[0] = 0x55; c[1] = 0xc3;
	for (i = 0; i < 3; i++) {                           /* 0x1030, 0x1036, 0x103c */
		uint32_t slot = 0x402000u + 4u * i;

		c[0x30 + 6 * i] = 0xff; c[0x31 + 6 * i] = 0x25;
		memcpy(c + 0x32 + 6 * i, &slot, 4);
	}
	c[0x48] = 0xff; c[0x49] = 0x25; memcpy(c + 0x4a, &slot_out, 4);      /* 0x1048: through data, outside the IAT */
	c[0x50] = 0xc3;
	c[0x60] = 0x89; c[0x61] = 0xc0;                                      /* mov eax,eax: the jump after it is no function start */
	c[0x62] = 0xff; c[0x63] = 0x25; memcpy(c + 0x64, &slot_mid, 4);
	memset(c + 0x70, 0, 0x200 - 0x70);
	pb_done(&p);
	memset(&t, 0, sizeof t);
	t.ok = kgenome_pe_image_parse(kof_buf_make(p.b, p.n), &t.info, &t.obj);
	t.obj.file_header = &t.info;
	CK(t.ok);
	wk = kgenome_diag_walk_new();
	CK(kgenome_diag_walk_ensure(wk, &t.obj, p.b, p.n, 1));
	sv = kgenome_diag_walk_thunks(wk, &n);
	CK(n == 5u);
	for (i = 1; i < n; i++)
		CK(sv[i - 1u].at < sv[i].at);                                   /* sorted by offset */
	CK(n == 5u && sv[0].at == t0 + 0x30 && sv[0].len == 6 && sv[0].slot == 0x402000u && sv[0].iat && sv[0].start);
	CK(n == 5u && sv[2].at == t0 + 0x3c && sv[2].slot == 0x402008u && sv[2].iat && sv[2].start);
	CK(n == 5u && sv[3].at == t0 + 0x48 && sv[3].slot == slot_out && !sv[3].iat && sv[3].start);
	CK(n == 5u && sv[4].at == t0 + 0x62 && sv[4].slot == slot_mid && sv[4].iat && !sv[4].start);
	CK(kgenome_diag_walk_thunk_slot(wk, t0 + 0x36) == 0x402004u);
	CK(kgenome_diag_walk_thunk_slot(wk, t0 + 0x37) == KGENOME_BROKEN);   /* inside a stub, not the start of one */
	CK(kgenome_diag_walk_thunk_slot(wk, t0) == KGENOME_BROKEN);
	CK(kgenome_diag_walk_thunk_slot(NULL, t0 + 0x30) == KGENOME_BROKEN);
	/* what the table makes of them: a THUNK only where the stub starts a function and its slot is the IAT's */
	{
		struct tab tt;
		const struct kgenome_func *a, *o, *m;

		build(p.b, p.n, &tt);
		a = at(&tt, t0 + 0x30);
		o = at(&tt, t0 + 0x48);
		m = at(&tt, t0 + 0x62);
		CK(a && a->kind == KGENOME_FN_THUNK);
		CK(!o || o->kind != KGENOME_FN_THUNK);          /* a jump through data outside the IAT */
		CK(!m || m->kind != KGENOME_FN_THUNK);          /* a jump in the middle of a function */
		tab_free(&tt);
	}
	kgenome_diag_walk_free(wk);
	wk = kgenome_diag_walk_new();
	CK(kgenome_diag_walk_thunk_slot(wk, t0 + 0x30) == KGENOME_BROKEN);   /* a walk that holds nothing */
	kgenome_diag_walk_free(wk);
	free(p.b);
}

/* THE FUNCTIONS ARE FOUND BY ADDRESS WHATEVER THE ORDER OF THE SECTIONS IN THE FILE (the lineage's index by entry address, made from the table, which is in the order of the file): a PE whose
 * second code section in the file has the LOWER address. `main` (section 1, rva 0x3000) is socket(); stop(); connect(it), `stop` (section 2, in the file after it, rva 0x1000 or, in the layout the
 * file order agrees with, 0x4000) is `ud2` alone (does not return: no link into the connect) or `ret` (returns: the link). The call to stop is found by its target's ADDRESS, so the answer is the
 * same in both layouts. RED on an index that is not sorted by address (the call is not found and stop() is taken for a function that returns). Old tests missed it: (b) no image had sections
 * out of order. */
static void t_lineage_sections_out_of_order(void)
{
	unsigned layout, ret;

	for (layout = 0; layout < 2; layout++)
		for (ret = 0; ret < 2; ret++) {
			struct pb p;
			struct kgenome_pe_info pi;
			struct kgenome_obj o;
			struct kgenome_diag_scan *sc;
			const uint32_t main_rva = 0x3000, stop_rva = layout ? 0x1000u : 0x4000u, idata = 0x5000;
			uint32_t t0, t1, ti, i, links = 0, nodes = 0;
			uint8_t *c, *d;

			pb_init(&p, 0x5000, 1, 0x8664);
			t0 = pb_sec(&p, ".text", main_rva, 0x200, 0x200, CH_CODE);
			t1 = pb_sec(&p, ".stop", stop_rva, 0x200, 0x200, CH_CODE);
			ti = pb_sec(&p, ".idata", idata, 0x200, 0x200, CH_DATA);
			pb_dir(&p, KGENOME_PE_DIR_IMPORT, idata, 40);
			pb_entry(&p, main_rva);
			c = p.b + t0;
			memset(c, 0xcc, 0x200);
			{
				static const uint8_t code[] = {
					0x48, 0x83, 0xec, 0x28,                         /* sub rsp,40 */
					0xff, 0x15, 0, 0, 0, 0,                         /* call [socket]  at +4 */
					0x48, 0x89, 0xc3,                               /* mov rbx,rax (callee-saved: it survives the call) */
					0xe8, 0, 0, 0, 0,                               /* call stop      at +13 */
					0x48, 0x89, 0xd9,                               /* mov rcx,rbx */
					0xff, 0x15, 0, 0, 0, 0,                         /* call [connect] at +21 */
					0x48, 0x83, 0xc4, 0x28, 0xc3 };                 /* add rsp,40 ; ret */
				uint32_t d1 = (idata + 0x80u) - (main_rva + 10u), d2 = stop_rva - (main_rva + 18u), d3 = (idata + 0x88u) - (main_rva + 27u);

				memcpy(c, code, sizeof code);
				memcpy(c + 6, &d1, 4);
				memcpy(c + 14, &d2, 4);
				memcpy(c + 23, &d3, 4);
			}
			d = p.b + t1;
			memset(d, 0xcc, 0x200);
			if (ret) { d[0] = 0xc3; } else { d[0] = 0x0f; d[1] = 0x0b; }
			d = p.b + ti;
			memset(d, 0, 0x200);
			{
				uint32_t desc[5] = { idata + 0x60u, 0, 0, idata + 0x40u, idata + 0x80u };
				uint64_t h1 = idata + 0xa0u, h2 = idata + 0xb0u;

				memcpy(d, desc, sizeof desc);
				memcpy(d + 0x40, "ws2_32.dll", 11);
				memcpy(d + 0x60, &h1, 8); memcpy(d + 0x68, &h2, 8);
				memcpy(d + 0x80, &h1, 8); memcpy(d + 0x88, &h2, 8);
				memcpy(d + 0xa2, "socket", 7);
				memcpy(d + 0xb2, "connect", 8);
			}
			pb_done(&p);
			memset(&pi, 0, sizeof pi);
			CK(kgenome_pe_image_parse(kof_buf_make(p.b, p.n), &pi, &o));
			o.file_header = &pi;
			sc = kgenome_diag_scan_with(&o, p.b, p.n, KGENOME_DIAG_RUN_SYMBOL | KGENOME_DIAG_RUN_LINEAGE);
			CK(sc != NULL);
			for (i = 0; sc && i < kgenome_diag_scan_count(sc); i++) {
				const struct kgenome_diag_hit *h = kgenome_diag_scan_at(sc, i);

				nodes++;
				links += h->n_in;
			}
			if (nodes != 2u || links != (ret ? 1u : 0u))
				printf("  layout %u stop %s: %u nodes, %u links, wanted 2 and %u\n", layout, ret ? "returns" : "ud2", nodes, links, ret ? 1u : 0u);
			CK(nodes == 2u && links == (ret ? 1u : 0u));
			kgenome_diag_scan_free(sc);
			free(p.b);
		}
}

/* A signal-return trampoline is an ELF thing (the C library's __restore_rt): the same bytes in a PE are code like any other and no start (the walk's rule is not applied to a PE). */
static void t_sigreturn_not_in_pe(void)
{
	struct pb p;
	struct tab t;
	struct kgenome_diag_walk *wk;
	uint32_t t0, i, n = 0;
	uint8_t *c;
	static const uint8_t stub[] = { 0x48, 0xc7, 0xc0, 0x0f, 0, 0, 0, 0x0f, 0x05 };

	pb_init(&p, 0x4000, 1, 0x8664);
	t0 = pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_entry(&p, 0x1000);
	c = p.b + t0;
	memset(c, 0x90, 0x200);
	c[0] = 0xc3;
	memcpy(c + 1, stub, sizeof stub);
	c[1 + sizeof stub] = 0xc3;
	pb_done(&p);
	memset(&t, 0, sizeof t);
	t.ok = kgenome_pe_image_parse(kof_buf_make(p.b, p.n), &t.info, &t.obj);
	t.obj.file_header = &t.info;
	CK(t.ok);
	wk = kgenome_diag_walk_new();
	kgenome_diag_funcs_with_walk(&t.obj, p.b, p.n, wk, &t.fs);
	for (i = 0; i < t.fs.n; i++)
		n += t.fs.v[i].off == t0 + 1u;
	CK(n == 0);
	tab_free(&t);
	kgenome_diag_walk_free(wk);
	free(p.b);
}

/* kgenome_diag_code_bytes is the UNION of the code extents: two sections whose raw bytes overlap count once, whatever their order in the table. Sections [0x400,0x600), [0x1000,0x1100), [0x500,0x700):
 * the union is 0x300 + 0x100 = 0x400; summed in table order they would be 0x500. RED on a union that does not sort first. */
static void t_code_bytes_union(void)
{
	struct kgenome_pe_info pi;
	struct kgenome_obj o;
	static const struct { uint64_t off, len; } sec[3] = { { 0x400, 0x200 }, { 0x1000, 0x100 }, { 0x500, 0x200 } };
	unsigned i;

	memset(&pi, 0, sizeof pi);
	memset(&o, 0, sizeof o);
	pi.valid = 1;
	pi.sec_count = 3;
	for (i = 0; i < 3; i++) {
		pi.sec[i].file_off = sec[i].off;
		pi.sec[i].file_size = sec[i].len;
		pi.sec[i].perm = KGENOME_PE_PERM_X;
	}
	o.format = KGENOME_FMT_PE;
	o.file_header = &pi;
	CK(kgenome_diag_code_bytes(&o, 0x2000) == 0x400);
}

/* THE STUBS ARE SORTED BY OFFSET WHATEVER THE ORDER OF THE SECTION TABLE: the walk meets the sections in the order of their headers, a PE does not promise the headers are in the order of the file,
 * and the lookup by offset is a binary search. Two code sections, the headers swapped: the second section's stub is met first. RED on a list kept in the order met. */
static void t_stub_order(void)
{
	struct pb p;
	struct tab t;
	struct kgenome_diag_walk *wk;
	uint32_t t0, t1, n = 0, slot0 = 0x402000u, slot1 = 0x402004u;
	const struct kgenome_diag_stub *sv;
	uint8_t *c, hdr[40];

	pb_init(&p, 0x4000, 0, 0x14c);
	t0 = pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	t1 = pb_sec(&p, ".text2", 0x3000, 0x200, 0x200, CH_CODE);
	pb_sec(&p, ".idata", 0x2000, 0x200, 0x200, CH_DATA);
	pb_dir(&p, KGENOME_PE_DIR_IAT, 0x2000, 0x20);
	pb_entry(&p, 0x1000);
	c = p.b + t0;
	memset(c, 0xcc, 0x200);
	c[0] = 0xc3;
	c[0x10] = 0xff; c[0x11] = 0x25; memcpy(c + 0x12, &slot0, 4);
	c = p.b + t1;
	memset(c, 0xcc, 0x200);
	c[0] = 0xc3;
	c[0x10] = 0xff; c[0x11] = 0x25; memcpy(c + 0x12, &slot1, 4);
	pb_done(&p);
	memcpy(hdr, p.b + p.sec_tab, 40);                   /* the table lists .text2 before .text now */
	memcpy(p.b + p.sec_tab, p.b + p.sec_tab + 40, 40);
	memcpy(p.b + p.sec_tab + 40, hdr, 40);
	memset(&t, 0, sizeof t);
	t.ok = kgenome_pe_image_parse(kof_buf_make(p.b, p.n), &t.info, &t.obj);
	t.obj.file_header = &t.info;
	CK(t.ok);
	wk = kgenome_diag_walk_new();
	CK(kgenome_diag_walk_ensure(wk, &t.obj, p.b, p.n, 1));
	sv = kgenome_diag_walk_thunks(wk, &n);
	CK(n == 2u && sv[0].at == t0 + 0x10 && sv[1].at == t1 + 0x10);
	CK(kgenome_diag_walk_thunk_slot(wk, t0 + 0x10) == slot0 && kgenome_diag_walk_thunk_slot(wk, t1 + 0x10) == slot1);
	kgenome_diag_walk_free(wk);
	free(p.b);
}

/* The slot must be inside the image's IAT when it declares one: `jmp [0x403000]` outside it is a jump through data, not a stub. */
static void t_thunk_slot_outside_iat(void)
{
	struct pb p;
	struct tab t;
	uint32_t t0, slot = 0x403000u;
	uint8_t *c;

	pb_init(&p, 0x4000, 0, 0x14c);
	t0 = pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_sec(&p, ".idata", 0x2000, 0x200, 0x200, CH_DATA);
	pb_dir(&p, KGENOME_PE_DIR_IAT, 0x2000, 0x20);
	pb_entry(&p, 0x1000);
	c = p.b + t0;
	memset(c, 0xcc, 0x40);
	c[0] = 0xff; c[1] = 0x25; memcpy(c + 2, &slot, 4);
	c[0x20] = 0x55; c[0x21] = 0xc3;
	memset(c + 0x30, 0, 0x200 - 0x30);
	pb_done(&p);
	build(&p.b[0], p.n, &t);
	{
		const struct kgenome_func *f = at(&t, t0);

		CK(!f || f->kind != KGENOME_FN_THUNK);
	}
	tab_free(&t);
	free(p.b);
}

/* The one int3 right after a call is the function's (the compiler's mark that the call does not return: the unwind table's End includes it in the images measured);
 * the padding after it is not. Zero bytes inside the code (the high half of a jump-table entry) are data, not padding: a function that ends in a table keeps it. */
static void t_tail_rules(void)
{
	struct pb p;
	struct tab t;
	uint32_t t0, d1, d2;
	uint8_t *c;
	/* f: push ebp; call g; call h; int3 (12 bytes, the last is the one after the call).  g: push ebp; jmp eax; then the table of its switch (10 bytes in all),
	 * and h follows at once (no padding): the zero bytes of the table decode as `add [eax],al` and are data. A function with a jump through a register keeps what follows it up to the next start:
	 * the code of its cases may be reached only through the table (REACH_INDIRECT), so its end is the next start. */
	static const uint8_t f[] = { 0x55, 0xe8, 0, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0xcc };
	static const uint8_t g[] = { 0x55, 0xff, 0xe0, 0x10, 0x10, 0x00, 0x00, 0x20, 0x10, 0x00 };      /* push ebp; jmp eax (the switch); the table, 7 bytes: its last zero bytes are the ones the walk reads as `add [eax],al` */

	pb_init(&p, 0x4000, 0, 0x14c);
	t0 = pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_entry(&p, 0x1000);
	c = p.b + t0;
	memset(c, 0xcc, 0x60);
	memcpy(c, f, sizeof f);
	memcpy(c + 0x20, g, sizeof g);
	memcpy(c + 0x2a, "\x55\xc3", 2);                      /* h */
	memset(c + 0x30, 0xcc, 0x30);
	memset(c + 0x60, 0, 0x200 - 0x60);
	d1 = 0x20u - 6u; memcpy(c + 2, &d1, 4);
	d2 = 0x2au - 11u; memcpy(c + 7, &d2, 4);
	pb_done(&p);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	{
		const struct kgenome_func *ff = at(&t, t0), *gg = at(&t, t0 + 0x20), *hh = at(&t, t0 + 0x2a);

		CK(ff && ff->len == 12);                        /* the int3 after the call is the function's, the cc padding after it is not */
		CK(gg && gg->len == 10);                        /* the table's last zero bytes are inside: they end at h, nothing is cut */
#ifndef FNTAB_PE_OLD_API_ONLY
		CK(gg && (gg->flags & KGENOME_FN_F_REACH_INDIRECT) && (gg->flags & KGENOME_FN_F_END_OPEN));
#endif
		CK(hh && hh->len == 2);
	}
	tab_free(&t);
	free(p.b);
}

/* A `jmp X` right after a `ret` or a `jmp` is NOT a thunk in a PE: it is the first instruction of a basic block as often as of a function (the ELF walk takes it as a start; measured
 * on the PE oracle that split 9000 functions of 180000 and gave back 0.9 point of starts). Here a jump into the middle of g, after f's own jmp, must make no start. */
static void t_no_jmp_thunk(void)
{
	struct pb p;
	struct tab t;
	uint32_t t0, d;
	uint8_t *c;

	pb_init(&p, 0x4000, 0, 0x14c);
	t0 = pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_entry(&p, 0x1000);
	c = p.b + t0;
	memset(c, 0xcc, 0x60);
	/* f at 0x1000: push ebp; jmp +0 (to the next instruction); (a block that begins with a jmp:) jmp 0x1028 (the middle of g); ret */
	memcpy(c, "\x55\xeb\x00\xe9\0\0\0\0\xc3", 9);
	d = 0x28u - 8u; memcpy(c + 4, &d, 4);
	memcpy(c + 0x20, "\x55\x8b\xec\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x5d\xc3", 15);       /* g: 15 bytes, 0x1028 is inside */
	memset(c + 0x60, 0, 0x200 - 0x60);
	pb_done(&p);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	CK(at(&t, t0));
	CK(!at(&t, t0 + 0x28));
	tab_free(&t);
	free(p.b);
}

/* ---- fixtures: x64 .pdata ------------------------------------------------------------------------------------------ */

/* Three non-leaf functions (sub rsp / call / add rsp / ret) at 0x1000, 0x1040, 0x1080 and a leaf (xor eax,eax; ret) at 0x1060 with no unwind entry; the unwind info
 * (version 1, no flags, no codes) at .rdata 0x2000; .pdata at 0x3000. */
#define LEAF_RVA 0x1060u
struct x64 { struct pb p; uint32_t text, pdata_off; uint32_t n_rf; };

static void rf(struct pb *p, uint32_t pd, uint32_t i, uint32_t b, uint32_t e, uint32_t u)
{
	uint8_t *x = at_rva(p, pd) + i * 12u;

	w(x, b, 4); w(x + 4, e, 4); w(x + 8, u, 4);
}

static void x64_image(struct x64 *x, uint32_t pd_vsize)
{
	struct pb *p = &x->p;
	static const uint8_t fn[] = { 0x48, 0x83, 0xec, 0x28, 0xe8, 0, 0, 0, 0, 0x48, 0x83, 0xc4, 0x28, 0xc3 };      /* 14 bytes */
	uint32_t i, d;
	uint8_t *c;

	pb_init(p, 0x4000, 1, 0x8664);
	x->text = pb_sec(p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_sec(p, ".rdata", 0x2000, 0x200, 0x200, CH_RDATA);
	x->pdata_off = pb_sec(p, ".pdata", 0x3000, pd_vsize, 0x200, CH_RDATA);
	pb_entry(p, 0x1000);
	c = p->b + x->text;
	memset(c, 0xcc, 0xa0);
	for (i = 0; i < 3; i++)
		memcpy(c + (i == 2 ? 0x80 : i * 0x40), fn, sizeof fn);
	/* 0x1000 calls the leaf, 0x1040 calls the leaf, 0x1080 calls the leaf: the leaf is a call target in this fixture only when asked (see x64_leaf_called) */
	d = LEAF_RVA - 0x1009u; memcpy(c + 5, &d, 4);
	d = LEAF_RVA - 0x1049u; memcpy(c + 0x45, &d, 4);
	d = LEAF_RVA - 0x1089u; memcpy(c + 0x85, &d, 4);
	c[0x60] = 0x31; c[0x61] = 0xc0; c[0x62] = 0xc3;
	memset(c + 0xa0, 0, 0x200 - 0xa0);
	memcpy(at_rva(p, 0x2000), "\x01\0\0\0", 4);       /* unwind info: version 1, flags 0, no codes */
	rf(p, 0x3000, 0, 0x1000, 0x100e, 0x2000);
	rf(p, 0x3000, 1, 0x1040, 0x104e, 0x2000);
	rf(p, 0x3000, 2, 0x1080, 0x108e, 0x2000);
	pb_dir(p, KGENOME_PE_DIR_EXCEPTION, 0x3000, 36);
	x->n_rf = 3;
	pb_done(p);
}

/* The case: PE32+ with .pdata. The non-leaf functions are exact (start, END = EndAddress); the leaf function has no entry and is named by the call that targets it (so a
 * call target in a gap is a start); nothing is made of the padding. RED on base for the leaf. */
static void t_pdata_leaf(void)
{
	struct x64 x;
	struct tab t;
	const struct kgenome_func *f, *leaf;

	x64_image(&x, 36);
	build(x.p.b, x.p.n, &t);
	CK(t.ok && table_ok(&t, x.p.n));
	f = at(&t, x.text);
	CK(f && f->len == 14);
	f = at(&t, x.text + 0x40);
	CK(f && f->len == 14);
	f = at(&t, x.text + 0x80);
	CK(f && f->len == 14);
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(f && f->end_source == KGENOME_FN_E_UNWIND && (f->source & KGENOME_FN_S_PDATA));
	CK(t.fs.ccase == KGENOME_FNTAB_C_PE_PDATA);
#endif
	leaf = at(&t, x.text + 0x60);
	CK(leaf && leaf->len == 3);                         /* the leaf: start from the calls, end at its ret (the cc padding after it is cut) */
	CK(t.fs.n == 4);
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(t.fs.n_extra == 0);                              /* the gap step found a start already there and added none (a second one would be dropped by the ends step and counted) */
#endif
	tab_free(&t);
	free(x.p.b);
}

/* A leaf that NOBODY calls is made by the GAPS step: the first non-padding byte of a gap between exact bodies. The step adds nothing where the table already has a start,
 * nothing in padding, and the entry says it is a gap start with an open end. */
static void t_pdata_gap_leaf(void)
{
	struct x64 x;
	struct tab t;
	const struct kgenome_func *leaf;
	uint32_t zero = 0;

	x64_image(&x, 36);
	memcpy(x.p.b + x.text + 5, &zero, 4);               /* nobody calls the leaf now (the call is to rip+0: the next instruction) */
	memcpy(x.p.b + x.text + 0x45, &zero, 4);
	memcpy(x.p.b + x.text + 0x85, &zero, 4);
	build(x.p.b, x.p.n, &t);
	CK(t.ok && table_ok(&t, x.p.n));
	leaf = at(&t, x.text + 0x60);
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(leaf && (leaf->flags & KGENOME_FN_F_GAP) && !(leaf->flags & KGENOME_FN_F_END_OPEN) && leaf->end_source == KGENOME_FN_E_REACH && leaf->len == 3);
	CK(!at(&t, x.text + 0x0e) && !at(&t, x.text + 0x4e));                      /* the cc padding after a function is no start */
	CK(!at(&t, x.text + 0x9e));
#else
	CK(leaf != NULL);
#endif
	tab_free(&t);
	free(x.p.b);
}

/* A chained entry (UNW_FLAG_CHAININFO) is the cold part of ANOTHER function: not a function of its own, no start is made inside it, and the parent keeps its extent.
 * The unwind info of the chained entry carries the parent's RUNTIME_FUNCTION after the codes. */
static void t_pdata_chained(void)
{
	struct x64 x;
	struct tab t;
	uint32_t i;
	uint8_t *u;

	x64_image(&x, 48);
	/* a fourth entry for the leaf's body 0x1060..0x1063 chained to the function at 0x1000, its unwind info at 0x2010 */
	u = at_rva(&x.p, 0x2010);
	u[0] = 0x01 | (4u << 3); u[1] = 0; u[2] = 0; u[3] = 0;                       /* version 1, CHAININFO, no codes */
	w(u + 4, 0x1000, 4); w(u + 8, 0x100e, 4); w(u + 12, 0x2000, 4);              /* the parent */
	rf(&x.p, 0x3000, 3, 0x1060, 0x1063, 0x2010);
	pb_dir(&x.p, KGENOME_PE_DIR_EXCEPTION, 0x3000, 48);
	build(x.p.b, x.p.n, &t);
	CK(t.ok && table_ok(&t, x.p.n));
	CK(at(&t, x.text) && at(&t, x.text)->len == 14);                            /* the parent keeps its own extent */
	CK(!at(&t, x.text + 0x60));                                                  /* the fragment is no function, and the call that targets it makes none */
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(t.fs.n_extra >= 1);
#endif
	for (i = 0; i < t.fs.n; i++)
		CK(t.fs.v[i].kind != KGENOME_FN_FRAGMENT);
	tab_free(&t);
	free(x.p.b);
}

/* ---- hostile .pdata ------------------------------------------------------------------------------------------------ */

/* Each hostile value alone, on the fixture: the table is still a valid table, and the entry it poisons is refused (counted: P_BAD_FDE) or kept as the rule says. */
static void t_pdata_hostile(void)
{
	struct x64 x;
	struct tab t;
	unsigned k;
	/* name, which field: 0 begin, 1 end, 2 unwind; value (entry 1) */
	static const struct { const char *name; int field; uint32_t value; int refused; } rows[] = {
		{ "end < begin", 1, 0x1030, 1 },
		{ "end == begin", 1, 0x1040, 1 },
		{ "begin outside every section", 0, 0x7000, 1 },
		{ "begin in a data section", 0, 0x2000, 1 },
		{ "unwind outside the image", 2, 0x90000, 1 },
		{ "unwind past the last section", 2, 0x3ffe, 1 },
	};
	unsigned seen = 0;

	for (k = 0; k < sizeof rows / sizeof *rows; k++) {
		x64_image(&x, 36);
		w(at_rva(&x.p, 0x3000) + 12u + rows[k].field * 4u, rows[k].value, 4);
		build(x.p.b, x.p.n, &t);
		CK(t.ok && table_ok(&t, x.p.n));
		CK(at(&t, x.text) && at(&t, x.text + 0x80));
#ifndef FNTAB_PE_OLD_API_ONLY
		CK(!(at(&t, x.text + 0x40) && at(&t, x.text + 0x40)->end_source == KGENOME_FN_E_UNWIND));   /* the poisoned entry gives no exact function */
		CK(t.fs.partial & KGENOME_FNTAB_P_BAD_FDE);
#endif
		if (!(t.fs.partial & KGENOME_FNTAB_P_BAD_FDE))
			printf("  row '%s' not counted\n", rows[k].name);
		seen++;
		tab_free(&t);
		free(x.p.b);
	}
	CK(seen == sizeof rows / sizeof *rows);
}

/* An unwind address with its low bit set is an indirection the format defines and this does not follow: the unwind info is not read and the entry is not a bad record, and its own Begin and End
 * stand (PDATA-1: the entry was dropped with no word, a function of the table lost). RED on main: no entry at x.text + 0x40. */
static void t_pdata_indirect(void)
{
	struct x64 x;
	struct tab t;

	x64_image(&x, 36);
	w(at_rva(&x.p, 0x3000) + 12u + 8u, 0x2001, 4);      /* entry 1's unwind: 0x2000 | 1 */
	build(x.p.b, x.p.n, &t);
	CK(t.ok && table_ok(&t, x.p.n));
	CK(at(&t, x.text) && at(&t, x.text + 0x80));
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(!(t.fs.partial & KGENOME_FNTAB_P_BAD_FDE));
	CK(at(&t, x.text + 0x40) && at(&t, x.text + 0x40)->end_source == KGENOME_FN_E_UNWIND && at(&t, x.text + 0x40)->len > 0);
#endif
	tab_free(&t);
	free(x.p.b);
}

/* group 9 (pe_elf_fixtures): the narrow, previously-unmeasured combination PDATA-1's own comment
 * names - an indirected entry (low bit set) whose UNREAD unwind info, if it HAD been read, would
 * say UNW_FLAG_CHAININFO (a fragment of the function at x.text, not a standalone body). At 0x2010
 * sits a fully valid chained-unwind record naming x.text as the parent (the exact shape
 * t_pdata_chained builds directly, unindirected); entry 1's UnwindData points at it only through
 * the indirection bit, which this reader never follows. Constructed and measured (M), not merely
 * inferred: entry 1 is kept as a PLAIN function exactly as if 0x2010 held nothing at all - never a
 * FRAGMENT, and x.text's own extent is untouched. This is PDATA-1's documented, accepted limit
 * (indirection is deliberately not followed - "the chain is never followed, so it costs nothing" -
 * fntab_pe_pdata.c), not a new defect: a regression pin, confirming the exact behaviour in the one
 * combination the fix's own comment flagged as unmeasured. */
static void t_pdata_indirect_chained(void)
{
	struct x64 x;
	struct tab t;
	uint32_t i;
	uint8_t *u;

	x64_image(&x, 36);
	u = at_rva(&x.p, 0x2010);
	u[0] = 0x01 | (4u << 3); u[1] = 0; u[2] = 0; u[3] = 0;          /* version 1, CHAININFO, no codes: a fully valid chained record */
	w(u + 4, 0x1000, 4); w(u + 8, 0x100e, 4); w(u + 12, 0x2000, 4); /* the parent: x.text itself, a real, valid RUNTIME_FUNCTION */
	w(at_rva(&x.p, 0x3000) + 12u + 8u, 0x2011, 4);                  /* entry 1's unwind: 0x2010 | 1 (indirect) */
	build(x.p.b, x.p.n, &t);
	CK(t.ok && table_ok(&t, x.p.n));
	CK(at(&t, x.text) && at(&t, x.text)->len == 14);                /* the parent's own extent: untouched */
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(!(t.fs.partial & KGENOME_FNTAB_P_BAD_FDE));
	CK(at(&t, x.text + 0x40) && at(&t, x.text + 0x40)->end_source == KGENOME_FN_E_UNWIND &&
	   at(&t, x.text + 0x40)->len == 14 && at(&t, x.text + 0x40)->kind != KGENOME_FN_FRAGMENT);
	for (i = 0; i < t.fs.n; i++)
		CK(t.fs.v[i].kind != KGENOME_FN_FRAGMENT);              /* never masked as a fragment of x.text, whatever 0x2010 says */
#endif
	CK(at(&t, x.text + 0x80));                                      /* the third function, unaffected */
	tab_free(&t);
	free(x.p.b);
}

/* The unwind info's own bytes: version 0 / 3, a flag bit the format does not define (bit 8, 16), a chained parent outside the image. */
static void t_pdata_unwind_info(void)
{
	struct x64 x;
	struct tab t;
	static const struct { uint8_t b0; const char *name; } rows[] = {
		{ 0x00, "version 0" }, { 0x03, "version 3" }, { 0x01 | (8u << 3), "flag 8" }, { 0x01 | (16u << 3), "flag 16" },
	};
	unsigned k;

	for (k = 0; k < sizeof rows / sizeof *rows; k++) {
		x64_image(&x, 36);
		at_rva(&x.p, 0x2000)[0] = rows[k].b0;               /* the unwind info the three entries share */
		build(x.p.b, x.p.n, &t);
		CK(t.ok && table_ok(&t, x.p.n));
#ifndef FNTAB_PE_OLD_API_ONLY
		CK(t.fs.partial & KGENOME_FNTAB_P_BAD_FDE);
		CK(t.fs.ccase == KGENOME_FNTAB_C_PE_WALK);          /* every entry refused: the table was read and is empty: the next row (the walk) */
		CK(!at(&t, x.text) || at(&t, x.text)->end_source != KGENOME_FN_E_UNWIND);
#endif
		if (rows[k].b0 == 0xff)
			printf("%s\n", rows[k].name);
		tab_free(&t);
		free(x.p.b);
	}
	/* an unwind info whose first four bytes are not all in the file: the last two bytes of the file say `01 00` (a valid version and flags), and what follows is not there */
	x64_image(&x, 36);
	{
		uint32_t last = x.p.n - 2u;

		x.p.b[last] = 0x01;
		w(at_rva(&x.p, 0x3000) + 12u + 8u, 0x3000u + (last - x.pdata_off), 4);
	}
	build(x.p.b, x.p.n, &t);
	CK(t.ok && table_ok(&t, x.p.n));
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(t.fs.partial & KGENOME_FNTAB_P_BAD_FDE);
	CK(!at(&t, x.text + 0x40) || at(&t, x.text + 0x40)->end_source != KGENOME_FN_E_UNWIND);
#endif
	tab_free(&t);
	free(x.p.b);
	/* a chained parent whose RUNTIME_FUNCTION lies past the file */
	x64_image(&x, 36);
	{
		uint8_t *u = at_rva(&x.p, 0x2010);

		u[0] = 0x01 | (4u << 3); u[1] = 0; u[2] = 200;      /* 200 unwind codes: the parent record is 400 bytes further: outside the section's bytes */
		rf(&x.p, 0x3000, 1, 0x1040, 0x104e, 0x2010);
	}
	build(x.p.b, x.p.n, &t);
	CK(t.ok && table_ok(&t, x.p.n));
	CK(at(&t, x.text) && at(&t, x.text + 0x80));
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(t.fs.partial & KGENOME_FNTAB_P_BAD_FDE);
#endif
	tab_free(&t);
	free(x.p.b);
}

/* A chain that loops (an entry chained to itself): the chain is never followed, so it costs nothing and the table is valid. */
static void t_pdata_chain_loop(void)
{
	struct x64 x;
	struct tab t;
	uint8_t *u;

	x64_image(&x, 36);
	u = at_rva(&x.p, 0x2010);
	u[0] = 0x01 | (4u << 3);
	w(u + 4, 0x1040, 4); w(u + 8, 0x104e, 4); w(u + 12, 0x2010, 4);                /* the parent is the entry itself */
	rf(&x.p, 0x3000, 1, 0x1040, 0x104e, 0x2010);
	build(x.p.b, x.p.n, &t);
	CK(t.ok && table_ok(&t, x.p.n));
	CK(at(&t, x.text) && at(&t, x.text + 0x80));
	tab_free(&t);
	free(x.p.b);
}

/* The count: the directory says a million entries and the section holds three (the count is bounded by the file), and overlapping entries are both kept and said. */
static void t_pdata_count_and_overlap(void)
{
	struct x64 x;
	struct tab t;

	x64_image(&x, 36);
	pb_dir(&x.p, KGENOME_PE_DIR_EXCEPTION, 0x3000, 12u * 1000000u);
	build(x.p.b, x.p.n, &t);
	CK(t.ok && table_ok(&t, x.p.n));
	CK(at(&t, x.text) && at(&t, x.text + 0x80));
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(!(t.fs.partial & KGENOME_FNTAB_P_BAD_FDE));      /* the zero fill after the entries is the table's padding, not a refused record */
#endif
	tab_free(&t);
	/* overlapping: entry 1 begins inside entry 0's body and ends after it */
	rf(&x.p, 0x3000, 1, 0x1008, 0x1010, 0x2000);
	pb_dir(&x.p, KGENOME_PE_DIR_EXCEPTION, 0x3000, 36);
	build(x.p.b, x.p.n, &t);
	CK(t.ok && table_ok(&t, x.p.n));
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(t.fs.n_disagree >= 1);
	CK(at(&t, x.text) && (at(&t, x.text)->flags & KGENOME_FN_F_DISAGREE));
#endif
	tab_free(&t);
	free(x.p.b);
}

/* An End past the raw bytes of its section is clipped to them (flag CLIPPED) and the entry stays exact up to there. */
static void t_pdata_clip(void)
{
	struct x64 x;
	struct tab t;

	x64_image(&x, 36);
	rf(&x.p, 0x3000, 2, 0x11f0, 0x1300, 0x2000);        /* begins 0x10 before the raw section's end and ends 0x100 past it */
	memset(at_rva(&x.p, 0x11f0), 0x90, 0x10);
	build(x.p.b, x.p.n, &t);
	CK(t.ok && table_ok(&t, x.p.n));
	{
		const struct kgenome_func *f = at(&t, x.text + 0x1f0);

		CK(f && f->len == 0x10);
#ifndef FNTAB_PE_OLD_API_ONLY
		CK(f && (f->flags & KGENOME_FN_F_CLIPPED));
#endif
	}
	tab_free(&t);
	free(x.p.b);
}

/* 1.2 million entries: past the cap the table is OVER_BUDGET with P_CAP (said), never silent, and it is still a valid table. */
static void t_pdata_cap(void)
{
	struct pb p;
	struct tab t;
	static const uint32_t n_ent = 1200000u;
	uint32_t i, raw;
	uint8_t *x;

	pb_init(&p, 0x400 + 0x200 + 0x200 + n_ent * 12u + 0x400, 1, 0x8664);
	pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_sec(&p, ".rdata", 0x2000, 0x200, 0x200, CH_RDATA);
	raw = pb_sec(&p, ".pdata", 0x3000, n_ent * 12u, n_ent * 12u, CH_RDATA);
	pb_entry(&p, 0x1000);
	memset(p.b + 0x400, 0xcc, 0x200);
	p.b[0x400] = 0xc3;
	memcpy(at_rva(&p, 0x2000), "\x01\0\0\0", 4);
	x = p.b + raw;
	for (i = 0; i < n_ent; i++) {                       /* every entry is the same 16 bytes of code: duplicates, as a hostile table is */
		w(x + i * 12u, 0x1000u + (i & 0xf), 4); w(x + i * 12u + 4, 0x1000u + (i & 0xf) + 1u, 4); w(x + i * 12u + 8, 0x2000, 4);
	}
	pb_dir(&p, KGENOME_PE_DIR_EXCEPTION, 0x3000, n_ent * 12u);
	pb_done(&p);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(t.fs.state == KGENOME_FNTAB_OVER_BUDGET && (t.fs.partial & KGENOME_FNTAB_P_CAP));
#endif
	tab_free(&t);
	free(p.b);
}

/* ---- exports, TLS, COFF -------------------------------------------------------------------------------------------- */

/* Export-only DLL: the table names two functions in the code, a forwarder (an RVA inside the export directory) and a data export (an RVA in .rdata). Starts from the first two
 * only; the walk finds nothing else (nothing calls). RED on base: x86 had no table. */
static void t_exports(void)
{
	struct pb p;
	struct tab t;
	uint32_t t0, x;
	uint8_t *c;

	pb_init(&p, 0x4000, 0, 0x14c);
	t0 = pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_sec(&p, ".edata", 0x2000, 0x200, 0x200, CH_RDATA);
	pb_entry(&p, 0);
	c = p.b + t0;
	memset(c, 0xcc, 0x60);
	memcpy(c, "\x55\x8b\xec\x5d\xc3", 5);
	memcpy(c + 0x20, "\x33\xc0\xc3", 3);
	memset(c + 0x60, 0, 0x200 - 0x60);
	x = off_of(&p, 0x2000);
	w(p.b + x + 20, 4, 4);                              /* NumberOfFunctions */
	w(p.b + x + 28, 0x2040, 4);                         /* AddressOfFunctions */
	w(p.b + x + 0x40, 0x1000, 4);                       /* function */
	w(p.b + x + 0x44, 0x1020, 4);                       /* function (by ordinal: no name) */
	w(p.b + x + 0x48, 0x2010, 4);                       /* a forwarder: inside the directory */
	w(p.b + x + 0x4c, 0x2100, 4);                       /* data */
	pb_dir(&p, KGENOME_PE_DIR_EXPORT, 0x2000, 0x60);
	pb_done(&p);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	CK(t.fs.n == 2);
	CK(at(&t, t0) && at(&t, t0 + 0x20));
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(at(&t, t0) && (atz(&t, t0)->source & KGENOME_FN_S_EXPORT));
	{
		struct kgenome_fntab_list l;

		memset(&l, 0, sizeof l);
		kgenome_fntab_pe_export(kof_buf_make(p.b, p.n), &t.info, &l);
		CK(l.n == 2 && l.n_bad == 2);                   /* the forwarder and the data export are counted, not followed */
		kgenome_fntab_list_free(&l);
	}
#endif
	tab_free(&t);
	free(p.b);
}

#ifndef FNTAB_PE_OLD_API_ONLY
/* A forwarder string that lies INSIDE a code section (the export directory placed in .text by a packer): its RVA is code by the section table and a start by that alone, so only the
 * directory's own range says it is not. */
static void t_export_forwarder_in_code(void)
{
	struct pb p;
	struct kgenome_fntab_list l;
	struct tab t;
	uint32_t t0, x;
	uint8_t *c;

	pb_init(&p, 0x4000, 0, 0x14c);
	t0 = pb_sec(&p, ".text", 0x1000, 0x400, 0x400, CH_CODE);
	pb_entry(&p, 0);
	c = p.b + t0;
	memset(c, 0xcc, 0x100);
	memcpy(c, "\x55\xc3", 2);
	x = t0 + 0x100;
	w(p.b + x + 20, 2, 4);
	w(p.b + x + 28, 0x1140, 4);
	w(p.b + 0x0 + t0 + 0x140, 0x1000, 4);               /* function */
	w(p.b + t0 + 0x144, 0x1160, 4);                     /* a forwarder: inside the directory (0x1100..0x1200), and in .text */
	memcpy(p.b + t0 + 0x160, "other.Func", 11);
	pb_dir(&p, KGENOME_PE_DIR_EXPORT, 0x1100, 0x100);
	pb_done(&p);
	build(p.b, p.n, &t);
	memset(&l, 0, sizeof l);
	kgenome_fntab_pe_export(kof_buf_make(p.b, p.n), &t.info, &l);
	CK(l.n == 1 && l.n_bad == 1);
	kgenome_fntab_list_free(&l);
	tab_free(&t);
	free(p.b);
}

#endif

/* The load configuration's tables: the safe exception handlers (x86) and the Control Flow Guard target list (an RVA and one metadata byte an entry, by GuardFlags): exact starts
 * of functions nothing calls directly. An entry in no code section is counted; a Size that does not reach a field means the field is absent; a count past the file is bounded. */
static void cfg_image(struct pb *p, uint32_t lc_size, uint32_t seh_cnt, uint32_t cf_cnt, uint32_t *t0)
{
	uint32_t x, i;
	uint8_t *c;

	pb_init(p, 0x4000, 0, 0x14c);
	*t0 = pb_sec(p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_sec(p, ".rdata", 0x2000, 0x400, 0x400, CH_RDATA);
	pb_entry(p, 0x1000);
	c = p->b + *t0;
	memset(c, 0xcc, 0x80);
	for (i = 0; i < 4; i++)
		memcpy(c + 0x20 * i, "\x55\x8b\xec\x5d\xc3", 5);
	memset(c + 0x80, 0, 0x200 - 0x80);
	x = off_of(p, 0x2000);
	w(p->b + x, lc_size, 4);
	w(p->b + x + 0x40, 0x402100u, 4); w(p->b + x + 0x44, seh_cnt, 4);               /* SEHandlerTable, count */
	w(p->b + x + 0x50, 0x402200u, 4); w(p->b + x + 0x54, cf_cnt, 4);                /* GuardCFFunctionTable, count */
	w(p->b + x + 0x58, 1u << 28, 4);                                                 /* GuardFlags: one metadata byte an entry */
	w(p->b + x + 0x100, 0x1020, 4); w(p->b + x + 0x104, 0x1040, 4);                  /* the handlers */
	w(p->b + x + 0x200, 0x1060, 4); p->b[x + 0x204] = 0x01;                          /* a CF target + its metadata */
	w(p->b + x + 0x205, 0x1000, 4); p->b[x + 0x209] = 0x00;                          /* a second target */
	w(p->b + x + 0x20a, 0x2000, 4); p->b[x + 0x20e] = 0x00;                          /* a CF entry that is data */
	pb_dir(p, KGENOME_PE_DIR_LOAD_CONFIG, 0x2000, lc_size);
	pb_done(p);
}

static void t_cfg_tables(void)
{
	struct pb p;
	struct tab t;
	uint32_t t0;

	cfg_image(&p, 0x5c, 2, 3, &t0);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	CK(at(&t, t0) && at(&t, t0 + 0x20) && at(&t, t0 + 0x40) && at(&t, t0 + 0x60));      /* the entry, two handlers, one CF target: nobody calls any of them */
	CK(t.fs.n == 4);
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(at(&t, t0 + 0x60) && (atz(&t, t0 + 0x60)->source & KGENOME_FN_S_EXPORT));
	{
		struct kgenome_fntab_list l;

		memset(&l, 0, sizeof l);
		kgenome_fntab_pe_cfg(kof_buf_make(p.b, p.n), &t.info, &l);
		CK(l.n == 4 && l.n_bad == 1);                       /* two handlers, two CF targets; the entry that is data is counted */
		kgenome_fntab_list_free(&l);
	}
#endif
	tab_free(&t);
	free(p.b);
	/* Size 0x48: the handler table is there, the CF fields are not */
	cfg_image(&p, 0x48, 2, 3, &t0);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	CK(at(&t, t0 + 0x20) && at(&t, t0 + 0x40));
	/* the function at 0x60 is code behind padding that nothing names: the REACH step finds it (a gap start), the CF table does not (it was no start before that step) */
	CK(at(&t, t0 + 0x60) && !(atz(&t, t0 + 0x60)->source & KGENOME_FN_S_EXPORT) && (atz(&t, t0 + 0x60)->flags & KGENOME_FN_F_GAP));
	tab_free(&t);
	free(p.b);
	/* Size 0x20: no field at all */
	cfg_image(&p, 0x20, 2, 3, &t0);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n) && at(&t, t0 + 0x20) && !(atz(&t, t0 + 0x20)->source & KGENOME_FN_S_EXPORT));
	tab_free(&t);
	free(p.b);
	/* counts of 4 billion: bounded by the file */
	cfg_image(&p, 0x5c, 0xffffffffu, 0xffffffffu, &t0);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	CK(at(&t, t0 + 0x20) && at(&t, t0 + 0x60));
	tab_free(&t);
	/* a table VA below the image base */
	w(p.b + off_of(&p, 0x2000) + 0x40, 0x1000, 4);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	tab_free(&t);
	free(p.b);
}

/* TLS callbacks: an array of VAs ended by a null. Each is a start (source ENTRY). A 257th entry past the bound is said (P_CAP). */
static void tls_image(struct pb *p, unsigned n_cb, uint32_t *t0)
{
	uint32_t x, i;
	uint8_t *c;

	pb_init(p, 0x6000, 0, 0x14c);
	*t0 = pb_sec(p, ".text", 0x1000, 0x400, 0x400, CH_CODE);
	pb_sec(p, ".tls", 0x2000, 0x1000, 0x1000, CH_DATA);
	pb_entry(p, 0x1000);
	c = p->b + *t0;
	memset(c, 0xcc, 0x400);
	memcpy(c, "\x55\xc3", 2);
	for (i = 0; i < 8; i++)
		memcpy(c + 0x40 + 0x20 * i, "\x33\xc0\xc2\x0c\x00", 5);
	x = off_of(p, 0x2000);
	w(p->b + x + 12, 0x402100u, 4);                     /* AddressOfCallBacks (a VA) */
	for (i = 0; i < n_cb; i++)
		w(p->b + x + 0x100 + 4u * i, 0x401040u + 0x20u * (i % 8u), 4);
	pb_dir(p, KGENOME_PE_DIR_TLS, 0x2000, 24);
	pb_done(p);
}

static void t_tls(void)
{
	struct pb p;
	struct tab t;
	uint32_t t0;

	tls_image(&p, 3, &t0);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	CK(at(&t, t0 + 0x40) && at(&t, t0 + 0x60) && at(&t, t0 + 0x80));
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(at(&t, t0 + 0x40) && (at(&t, t0 + 0x40)->source & KGENOME_FN_S_ENTRY));
#endif
	tab_free(&t);
	free(p.b);
#ifndef FNTAB_PE_OLD_API_ONLY
	{
		struct kgenome_fntab_list l;
		struct pb q;
		struct tab u;
		uint32_t t1;

		/* exactly the bound: no null needed, nothing said; one more: said */
		tls_image(&q, KGENOME_FNTAB_TLS_MAX, &t1);
		build(q.b, q.n, &u);
		memset(&l, 0, sizeof l);
		kgenome_fntab_pe_tls(kof_buf_make(q.b, q.n), &u.info, &l);
		CK(!(l.partial & KGENOME_FNTAB_P_CAP));
		kgenome_fntab_list_free(&l);
		tab_free(&u);
		free(q.b);
		tls_image(&q, KGENOME_FNTAB_TLS_MAX + 1u, &t1);
		build(q.b, q.n, &u);
		memset(&l, 0, sizeof l);
		kgenome_fntab_pe_tls(kof_buf_make(q.b, q.n), &u.info, &l);
		CK(l.partial & KGENOME_FNTAB_P_CAP);
		CK(u.fs.state == KGENOME_FNTAB_OVER_BUDGET);
		kgenome_fntab_list_free(&l);
		tab_free(&u);
		free(q.b);
	}
#endif
}

/* group 18 (pe_elf_fixtures): a hostile callback array - an address inside the TLS section
 * itself (not executable), an address below the image base, and (second block below) a
 * truncated array whose one entry is the file's very last bytes, with no null terminator and
 * nothing past it to read. Neither bad address stops the walk from finding the real callbacks
 * on either side of them. */
static void t_tls_hostile(void)
{
	struct pb p;
	struct tab t;
	struct kgenome_fntab_list l;
	uint32_t x, t0;

	pb_init(&p, 0x6000, 0, 0x14c);
	t0 = pb_sec(&p, ".text", 0x1000, 0x400, 0x400, CH_CODE);
	pb_sec(&p, ".tls", 0x2000, 0x1000, 0x1000, CH_DATA);
	pb_entry(&p, 0x1000);
	memset(p.b + t0, 0xcc, 0x400);
	memcpy(p.b + t0, "\x33\xc0\xc2\x0c\x00", 5);             /* a real callback: xor eax,eax; ret 0xc */
	memcpy(p.b + t0 + 0x20, "\x33\xc0\xc2\x0c\x00", 5);      /* a second real callback, past the two bad entries */
	x = off_of(&p, 0x2000);
	w(p.b + x + 12, 0x402100u, 4);                            /* AddressOfCallBacks */
	w(p.b + x + 0x100 + 0, 0x401000u, 4);                     /* [0] a real callback: .text */
	w(p.b + x + 0x100 + 4, 0x402010u, 4);                     /* [1] inside .tls itself: no executable section holds it */
	w(p.b + x + 0x100 + 8, 0x10u, 4);                         /* [2] below the image base (0x400000) */
	w(p.b + x + 0x100 + 12, 0x401020u, 4);                    /* [3] a second real callback */
	w(p.b + x + 0x100 + 16, 0, 4);                            /* null terminator */
	pb_dir(&p, KGENOME_PE_DIR_TLS, 0x2000, 24);
	pb_done(&p);

	build(p.b, p.n, &t);
	memset(&l, 0, sizeof l);
	kgenome_fntab_pe_tls(kof_buf_make(p.b, p.n), &t.info, &l);
	CK(l.n == 2 && l.n_bad == 2);                             /* the two real callbacks found, the two hostile ones counted and left out */
	CK(at(&t, t0) && at(&t, t0 + 0x20));                      /* and both land in the final, merged table too */
	kgenome_fntab_list_free(&l);
	tab_free(&t);
	free(p.b);

	{
		struct pb q;
		struct tab u;
		uint32_t t1, xq;

		pb_init(&q, 0x6000, 0, 0x14c);
		t1 = pb_sec(&q, ".text", 0x1000, 0x400, 0x400, CH_CODE);
		pb_sec(&q, ".tls", 0x2000, 0x1000, 0x1000, CH_DATA);
		pb_entry(&q, 0x1000);
		memset(q.b + t1, 0xcc, 0x400);
		memcpy(q.b + t1, "\x33\xc0\xc2\x0c\x00", 5);
		xq = off_of(&q, 0x2000);
		w(q.b + xq + 12, 0x402ffcu, 4);                   /* AddressOfCallBacks: the one entry is the section's (and the file's) very last 4 bytes */
		w(q.b + xq + 0xffc, 0x401000u, 4);
		pb_dir(&q, KGENOME_PE_DIR_TLS, 0x2000, 24);
		pb_done(&q);
		CK(q.n == xq + 0x1000u);                          /* nothing follows the one entry: the next read is out of the buffer, not a null */

		build(q.b, q.n, &u);
		memset(&l, 0, sizeof l);
		kgenome_fntab_pe_tls(kof_buf_make(q.b, q.n), &u.info, &l);
		CK(l.n == 1 && !l.n_bad && !(l.partial & KGENOME_FNTAB_P_CAP));
		kgenome_fntab_list_free(&l);
		tab_free(&u);
		free(q.b);
	}
}

/* COFF symbols (an image from a toolchain that keeps them): function-typed symbols with a section number. Two with no size, one with an auxiliary TotalSize (exact), a data symbol
 * (type 0), a function symbol in a data section. The case is PE_COFF: starts from the symbols, the length from the aux record where there is one. RED on base: no table. */
static void t_coff(void)
{
	struct pb p;
	struct tab t;
	uint32_t t0;
	uint8_t *c;
	static const struct csym sy[] = {
		{ 0x00, 1, 0x20, 2, 0 },        /* main: no size */
		{ 0x20, 1, 0x20, 3, 9 },        /* helper: TotalSize 9 */
		{ 0x40, 1, 0x00, 2, 0 },        /* data label in .text: no */
		{ 0x50, 1, 0x20, 2, 0 },        /* tail: no size */
		{ 0x10, 2, 0x20, 2, 0 },        /* a function symbol in .data: refused */
	};

	pb_init(&p, 0x4000, 0, 0x14c);
	t0 = pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_sec(&p, ".data", 0x2000, 0x200, 0x200, CH_DATA);
	pb_entry(&p, 0);
	c = p.b + t0;
	memset(c, 0xcc, 0x70);
	memcpy(c, "\x55\x8b\xec\x5d\xc3", 5);
	memcpy(c + 0x20, "\x55\x8b\xec\x33\xc0\x5d\xc3", 7);
	memcpy(c + 0x50, "\x55\xc3", 2);
	memset(c + 0x70, 0, 0x200 - 0x70);
	pb_syms(&p, sy, 5);
	pb_done(&p);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	CK(at(&t, t0) && at(&t, t0 + 0x20) && at(&t, t0 + 0x50));
	CK(!at(&t, t0 + 0x40));
	CK(at(&t, t0 + 0x20) && at(&t, t0 + 0x20)->len == 9);       /* the aux size, exact */
	CK(at(&t, t0) && atz(&t, t0)->len == 5);                     /* no size: next start less the padding */
	CK(at(&t, t0 + 0x50) && at(&t, t0 + 0x50)->len == 2);
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(t.fs.ccase == KGENOME_FNTAB_C_PE_COFF);
	{
		struct kgenome_fntab_list l;

		memset(&l, 0, sizeof l);
		kgenome_fntab_pe_coff(kof_buf_make(p.b, p.n), &t.info, &l);
		CK(l.n == 3);                                       /* main, helper, tail: the function symbol in .data is not an entry of the list */
		CK(l.n_bad == 1);                                   /* ... and is counted */
		kgenome_fntab_list_free(&l);
	}
	CK(at(&t, t0 + 0x20) && at(&t, t0 + 0x20)->end_source == KGENOME_FN_E_SYMBOL && (at(&t, t0 + 0x20)->source & KGENOME_FN_S_COFF));
	CK(at(&t, t0) && (atz(&t, t0)->flags & KGENOME_FN_F_SIZE0) && !(atz(&t, t0)->flags & KGENOME_FN_F_END_OPEN) && atz(&t, t0)->end_source == KGENOME_FN_E_REACH);
#endif
	tab_free(&t);
	free(p.b);
}

/* A symbol table the file does not hold (count past the file, pointer past the file) is not read past the buffer, and an image whose symbol table lists no function falls to the
 * next row (the retry is visible in the case). */
static void t_coff_hostile(void)
{
	struct pb p;
	struct tab t;
	uint32_t t0;
	static const struct csym none[] = { { 0, 1, 0x00, 2, 0 } };

	t0 = x86_image(&p, 0x200);
	pb_syms(&p, none, 1);
	pb_done(&p);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	CK(at(&t, t0 + 0x20));
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(t.fs.ccase == KGENOME_FNTAB_C_PE_WALK);
#endif
	tab_free(&t);
	w(p.b + p.lfanew + 16, 0x7fffffffu, 4);             /* NumberOfSymbols far past the file */
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	tab_free(&t);
	w(p.b + p.lfanew + 12, 0xfffffff0u, 4);             /* the table pointer past the file */
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	tab_free(&t);
	free(p.b);
}

/* A managed image (a CLI header): the code is IL, no native table is defined for it: empty, PARTIAL with the reason, and no walk is made. */
static void t_clr(void)
{
	struct pb p;
	struct tab t;

	x86_image(&p, 0x200);
	pb_dir(&p, KGENOME_PE_DIR_COM_DESCRIPTOR, 0x1000, 72);
	w(p.b + 0x400, 72, 4);                              /* cb */
	w(p.b + 0x400 + 4, 2, 2);
	build(p.b, p.n, &t);
	CK(t.ok);
#ifndef FNTAB_PE_OLD_API_ONLY
	if (t.info.clr_len) {
		CK(t.fs.ccase == KGENOME_FNTAB_C_PE_CLR && t.fs.n == 0);
		CK(t.fs.state == KGENOME_FNTAB_PARTIAL && (t.fs.partial & KGENOME_FNTAB_P_MANAGED));
	}
#endif
	tab_free(&t);
	free(p.b);
}

/* ---- hostile images --------------------------------------------------------------------------------------------- */

/* Sections that overlap in the file, a section with a zero raw size, a code section of 64 MB: the table is valid and the walk is bounded (the trace is a cache with its own cap). */
static void t_hostile_images(void)
{
	struct pb p;
	struct tab t;
	uint32_t t0;

	/* two code sections over the same bytes: the functions are listed once each (one start, one entry) */
	t0 = x86_image(&p, 0x200);
	pb_sec(&p, ".text2", 0x3000, 0x200, 0x200, CH_CODE);
	w(p.b + p.sec_tab + 40 + 20, t0, 4);                /* its raw data is the first section's */
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	tab_free(&t);
	free(p.b);
	/* 64 MB of code: nops and a function every 4 KB, every one called from the entry's chain is too long for a fixture: only the bound is checked */
	{
		static const uint32_t sz = 64u << 20;
		uint8_t *c;

		pb_init(&p, 0x400 + sz + 0x1000, 0, 0x14c);
		t0 = pb_sec(&p, ".text", 0x1000, sz, sz, CH_CODE);
		pb_entry(&p, 0x1000);
		c = p.b + t0;
		memset(c, 0x90, sz);
		{
			uint32_t i;

			for (i = 0; i + 0x1000u < sz; i += 0x1000u)
				memcpy(c + i, "\x55\x8b\xec\x5d\xc3", 5);
		}
		pb_done(&p);
		build(p.b, p.n, &t);
		CK(t.ok && table_ok(&t, p.n));
		CK(t.fs.n >= 1 && t.fs.n < 20000);
		tab_free(&t);
		free(p.b);
	}
}

/* Poison: every byte of the .pdata and of the unwind info set to 0x00 and 0xff in turn, and every prefix cut of the file: the table is always valid (sorted, inside the file). */
static void t_poison(void)
{
	struct x64 x;
	struct tab t;
	uint32_t i, n;
	const uint32_t zones[2][2] = { { 0x3000, 36 }, { 0x2000, 4 } };
	unsigned z;
	uint8_t keep;

	for (z = 0; z < 2; z++) {
		x64_image(&x, 36);
		for (i = 0; i < zones[z][1]; i++) {
			uint8_t *b = at_rva(&x.p, zones[z][0]) + i;
			unsigned v;

			keep = *b;
			for (v = 0; v < 2; v++) {
				*b = v ? 0xffu : 0x00u;
				build(x.p.b, x.p.n, &t);
				CK(t.ok && table_ok(&t, x.p.n));
				tab_free(&t);
			}
			*b = keep;
		}
		free(x.p.b);
	}
	x64_image(&x, 36);
	n = x.p.n;
	for (i = 0; i < n; i += 61u) {                      /* every 61st prefix (all of them is 70 MB of work for no new path) */
		build(x.p.b, i, &t);
		CK(!t.ok || table_ok(&t, i));
		tab_free(&t);
	}
	free(x.p.b);
}

#ifndef FNTAB_PE_OLD_API_ONLY
/* ---- the selector and the merge ----------------------------------------------------------------------------------- */

static void t_selector(void)
{
	/* the PE rows of the decision table (fntab_select.c): metadata -> case -> run */
	static const uint16_t S = KGENOME_FNTAB_X_PE_EXPORT | KGENOME_FNTAB_X_PE_TLS | KGENOME_FNTAB_X_PE_CFG | KGENOME_FNTAB_X_WALK | KGENOME_FNTAB_X_PE_THUNK;
	static const struct { struct kgenome_fntab_meta m; unsigned ccase, run; } rows[] = {
		{ { .format = KGENOME_FMT_PE, .pe_clr = 1, .pe_x86 = 1, .pe_x64_pdata = 1 }, KGENOME_FNTAB_C_PE_CLR, 0 },
		{ { .format = KGENOME_FMT_PE, .pe_x86 = 1, .pe_x64_pdata = 1 }, KGENOME_FNTAB_C_PE_PDATA,
		  KGENOME_FNTAB_X_PDATA | S | KGENOME_FNTAB_X_PE_REACH },
		{ { .format = KGENOME_FMT_PE, .pe_x86 = 1, .pe_x64_pdata = 1, .pe_coff = 1 }, KGENOME_FNTAB_C_PE_PDATA,
		  KGENOME_FNTAB_X_PDATA | S | KGENOME_FNTAB_X_PE_REACH | KGENOME_FNTAB_X_PE_COFF },
		/* a table read and found empty is the next row: the meta says it, the selector does not guess */
		{ { .format = KGENOME_FMT_PE, .pe_x86 = 1, .pe_x64_pdata = 1, .pdata_empty = 1 }, KGENOME_FNTAB_C_PE_WALK, S | KGENOME_FNTAB_X_PE_REACH },
		{ { .format = KGENOME_FMT_PE, .pe_x86 = 1, .pe_x64_pdata = 1, .pdata_empty = 1, .pe_coff = 1 }, KGENOME_FNTAB_C_PE_COFF,
		  KGENOME_FNTAB_X_PE_COFF | S | KGENOME_FNTAB_X_PE_REACH },
		{ { .format = KGENOME_FMT_PE, .pe_x86 = 1, .pe_coff = 1 }, KGENOME_FNTAB_C_PE_COFF, KGENOME_FNTAB_X_PE_COFF | S | KGENOME_FNTAB_X_PE_REACH },
		{ { .format = KGENOME_FMT_PE, .pe_x86 = 1, .pe_coff = 1, .coff_empty = 1 }, KGENOME_FNTAB_C_PE_WALK, S | KGENOME_FNTAB_X_PE_REACH },
		{ { .format = KGENOME_FMT_PE, .pe_x86 = 1 }, KGENOME_FNTAB_C_PE_WALK, S | KGENOME_FNTAB_X_PE_REACH },
		/* no executable section holds a byte of the file: nothing to table, whatever the machine or the tables say (a managed image is still managed) */
		{ { .format = KGENOME_FMT_PE, .pe_x86 = 1, .pe_x64_pdata = 1, .pe_nocode = 1 }, KGENOME_FNTAB_C_PE_NOCODE, 0 },
		{ { .format = KGENOME_FMT_PE, .pe_arm = 1, .pe_nocode = 1 }, KGENOME_FNTAB_C_PE_NOCODE, 0 },
		{ { .format = KGENOME_FMT_PE, .pe_clr = 1, .pe_nocode = 1 }, KGENOME_FNTAB_C_PE_CLR, 0 },
		/* ARM64 / Thumb-2: the packed exception table and the starts the image declares; no walk */
		{ { .format = KGENOME_FMT_PE, .pe_arm = 1 }, KGENOME_FNTAB_C_PE_ARM,
		  KGENOME_FNTAB_X_PE_ARMPDATA | KGENOME_FNTAB_X_PE_EXPORT | KGENOME_FNTAB_X_PE_TLS | KGENOME_FNTAB_X_PE_CFG },
		{ { .format = KGENOME_FMT_PE }, KGENOME_FNTAB_C_PE_NONE, 0 },
		{ { .format = KGENOME_FMT_PE, .pe_coff = 1 }, KGENOME_FNTAB_C_PE_NONE, 0 },
	};
	unsigned i;
	struct kgenome_fntab_plan p;

	for (i = 0; i < sizeof rows / sizeof *rows; i++) {
		p = kgenome_fntab_select(&rows[i].m);
		if (p.ccase != rows[i].ccase || p.run != rows[i].run)
			printf("  PE selector row %u: case %u run 0x%x\n", i, p.ccase, p.run);
		CK(p.ccase == rows[i].ccase && p.run == rows[i].run && !p.check_only);
	}
}

/* The probe: metadata of a real image -> the meta fields the table above reads. */
static void t_probe(void)
{
	struct x64 x;
	struct pb p;
	struct tab t;
	struct kgenome_fntab_meta m;
	static const struct csym sy[] = { { 0, 1, 0x20, 2, 0 } };

	x64_image(&x, 36);
	build(x.p.b, x.p.n, &t);
	kgenome_fntab_probe(KGENOME_FMT_PE, kof_buf_make(x.p.b, x.p.n), &t.info, &m);
	CK(m.pe_x64_pdata && m.pe_x86 && !m.pe_clr && !m.pe_coff);
	tab_free(&t);
	free(x.p.b);
	x86_image(&p, 0x200);
	pb_syms(&p, sy, 1);
	pb_done(&p);
	build(p.b, p.n, &t);
	kgenome_fntab_probe(KGENOME_FMT_PE, kof_buf_make(p.b, p.n), &t.info, &m);
	CK(!m.pe_x64_pdata && m.pe_x86 && m.pe_coff);
	tab_free(&t);
	free(p.b);
}

/* Order independence: the merge of the same entries in every order gives the same table (the one place two sources meet), including the fragment mask and an import stub that is
 * also a call target; and the merge is idempotent on its own output. */
static void t_merge_order(void)
{
	struct kgenome_func e[5];
	unsigned perm[5] = { 0, 1, 2, 3, 4 }, k, n_ok = 0, total = 0;
	struct kgenome_func_set ref;
	int have_ref = 0;

	memset(e, 0, sizeof e);
	e[0].off = 0x100; e[0].len = 0x40; e[0].source = KGENOME_FN_S_PDATA; e[0].end_source = KGENOME_FN_E_UNWIND;
	e[1].off = 0x200; e[1].len = 0x10; e[1].source = KGENOME_FN_S_PDATA; e[1].end_source = KGENOME_FN_E_UNWIND; e[1].kind = KGENOME_FN_FRAGMENT;
	e[2].off = 0x208; e[2].source = KGENOME_FN_S_WALK;                         /* a walk start inside the fragment: not a function */
	e[3].off = 0x300; e[3].len = 6; e[3].source = KGENOME_FN_S_WALK; e[3].end_source = KGENOME_FN_E_INSN; e[3].kind = KGENOME_FN_THUNK;
	e[4].off = 0x300; e[4].source = KGENOME_FN_S_WALK;                         /* the same address as a call target: one entry */
	memset(&ref, 0, sizeof ref);
	/* all 120 permutations of 5 */
	{
		unsigned a, b, c, d, f;

		for (a = 0; a < 5; a++) for (b = 0; b < 5; b++) for (c = 0; c < 5; c++) for (d = 0; d < 5; d++) for (f = 0; f < 5; f++) {
			struct kgenome_fntab_list l;
			struct kgenome_func_set s;
			unsigned idx[5] = { a, b, c, d, f }, m, ok = 1;

			for (m = 0; m < 5; m++)
				for (k = m + 1; k < 5; k++)
					if (idx[m] == idx[k])
						ok = 0;
			if (!ok)
				continue;
			memset(&l, 0, sizeof l);
			memset(&s, 0, sizeof s);
			for (m = 0; m < 5; m++)
				kgenome_fntab_list_add(&l, &e[idx[m]]);
			kgenome_fntab_merge(&l, 0, &s);
			total++;
			if (!have_ref) {
				ref = s;
				have_ref = 1;
				n_ok++;
				continue;
			}
			if (s.n == ref.n && !memcmp(s.v, ref.v, s.n * sizeof *s.v) && s.n_extra == ref.n_extra)
				n_ok++;
			kgenome_funcs_free(&s);
		}
	}
	(void)perm;
	CK(total == 120 && n_ok == total);
	CK(ref.n == 2 && ref.v[0].off == 0x100 && ref.v[1].off == 0x300 && ref.v[1].kind == KGENOME_FN_THUNK && (ref.v[1].source & KGENOME_FN_S_WALK));
	CK(ref.n_extra >= 2);                               /* the fragment, and the start inside it */
	kgenome_funcs_free(&ref);
}
#endif

/* ---- the REACH step: the end of an entry is the end of what it reaches ---------------------------------------------- */

/*
 * THE ENDS BY REACH, and the marks a compiler leaves. f0: push ebp; mov ebp,esp; call g; int3 (the int3 right after a call is the body's own mark: the call does not return).
 * f1 (called by nobody, after the padding): push ebp; mov ebp,esp; xor eax,eax; pop ebp; ret - a leaf behind padding is a START (the first byte past the padding is code that ends).
 * f2: push ebp; call g; nop; then the padding: the one nop after a call is the mark too. g: push ebp; ret.
 * RED on base for the ends of f1 and f2 and for the start of f1: the end was the next start less the padding the walk saw; f1 had no start (x86 has no exception table to hold a leaf).
 */
static void t_reach_ends(void)
{
	struct pb p;
	struct tab t;
	uint8_t code[0x100];
	uint32_t t0;
	const struct kgenome_func *f;

	memset(code, 0xcc, sizeof code);
	memcpy(code, "\x55\x8b\xec\xe8\0\0\0\0\xcc", 9);                     rel32(code, 3, 5, 0x60);
	memcpy(code + 0x20, "\x55\x8b\xec\x33\xc0\x5d\xc3", 7);
	memcpy(code + 0x40, "\x55\xe8\0\0\0\0\x90", 7);                      rel32(code, 0x41, 5, 0x60);
	memcpy(code + 0x60, "\x55\xc3", 2);
	t0 = code_image(&p, 0, code, sizeof code);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	f = at(&t, t0);
	CK(f && f->len == 9);                                                /* the int3 after the call is the function's: the code behind it is not reached through it */
	f = at(&t, t0 + 0x20);
	CK(f && f->len == 7);                                                /* a start the walk could not find: nothing calls it, and padding stands in front of it */
	f = at(&t, t0 + 0x40);
	CK(f && f->len == 7);                                                /* the nop after the call, not the int3 padding behind it */
	f = at(&t, t0 + 0x60);
	CK(f && f->len == 2);
	CK(t.fs.n == 4);
#ifndef FNTAB_PE_OLD_API_ONLY
	f = at(&t, t0 + 0x20);
	CK(f && (f->flags & KGENOME_FN_F_GAP) && !(f->flags & KGENOME_FN_F_END_OPEN) && f->end_source == KGENOME_FN_E_REACH && f->source == KGENOME_FN_S_WALK);
	CK(at(&t, t0) && atz(&t, t0)->end_source == KGENOME_FN_E_REACH && !(atz(&t, t0)->flags & KGENOME_FN_F_END_OPEN));
	CK(!(t.fs.partial & KGENOME_FNTAB_P_ENDS) && (t.fs.partial & KGENOME_FNTAB_P_STARTS));
#endif
	tab_free(&t);
	free(p.b);
}

/*
 * DATA IS NOT A FUNCTION, and what REACH does not know it says. A: `push ebp; ret` and the 8 bytes of a jump table right behind it (no padding): the table is not code that ends, so it is no start and the
 * entry ends at its `ret`. B: `push ebp; jmp eax; <the table>`: a reachable jump through a register - the code of the cases may be reached only through the table - the end stays the next
 * start and the entry says REACH_INDIRECT. C: `push ebp; call g` and g follows with NO terminator between (the call before it may not return, or g's start is inside the function): REACH_OPEN, the end stays
 * the next start. D: `push ebp` then bytes that do not decode: REACH_NONE.
 */
static void t_reach_states(void)
{
	static const uint8_t tbl[] = { 0x10, 0x10, 0x00, 0x00, 0x20, 0x10, 0x00, 0x00 };
	struct pb p;
	struct tab t;
	uint8_t code[0x100];
	uint32_t t0;
	const struct kgenome_func *f;

	/* A: f = 55 c3 + the table; g (called) at 0x20 */
	memset(code, 0xcc, sizeof code);
	memcpy(code, "\x55\xe8\0\0\0\0\xc3", 7); rel32(code, 1, 5, 0x20);
	memcpy(code + 7, tbl, sizeof tbl);
	memcpy(code + 0x20, "\x55\xc3", 2);
	t0 = code_image(&p, 0, code, sizeof code);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	f = at(&t, t0);
	CK(f && f->len == 7);                                                /* it ends at the ret ... */
	CK(!at(&t, t0 + 7) && !at(&t, t0 + 8) && !at(&t, t0 + 11));          /* ... and no start was made in the table */
	tab_free(&t);
	free(p.b);
	/* B: the switch */
	memset(code, 0xcc, sizeof code);
	memcpy(code, "\x55\xe8\0\0\0\0\xff\xe0", 8); rel32(code, 1, 5, 0x20);
	memcpy(code + 8, tbl, sizeof tbl);
	memcpy(code + 0x20, "\x55\xc3", 2);
	t0 = code_image(&p, 0, code, sizeof code);
	build(p.b, p.n, &t);
	f = at(&t, t0);
	CK(t.ok && f && f->len == 16);                                       /* up to the next start, the table inside */
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(f && (f->flags & KGENOME_FN_F_REACH_INDIRECT) && (f->flags & KGENOME_FN_F_END_OPEN) && f->end_source != KGENOME_FN_E_REACH);
#endif
	tab_free(&t);
	free(p.b);
	/* C: runs into the next start: `push ebp; mov ebp,esp` and g right behind it with no terminator between (g's start may be inside the function); g is called by h */
	memset(code, 0xcc, sizeof code);
	memcpy(code, "\x55\x8b\xec\x55\xc3", 5);
	memcpy(code + 0x20, "\xe8\0\0\0\0\xc3", 6); rel32(code, 0x20, 5, 3);
	t0 = code_image(&p, 0, code, sizeof code);
	build(p.b, p.n, &t);
	f = at(&t, t0);
	CK(t.ok && f && f->len == 3 && at(&t, t0 + 3));
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(f && (f->flags & KGENOME_FN_F_REACH_OPEN) && (f->flags & KGENOME_FN_F_END_OPEN));
#endif
	tab_free(&t);
	free(p.b);
	/* D: bytes that do not decode (0f 04 is no instruction) inside what is reached */
	memset(code, 0xcc, sizeof code);
	memcpy(code, "\x55\xe8\0\0\0\0\x0f\x04\x0f\x04\xc3", 11); rel32(code, 1, 5, 0x20);
	memcpy(code + 0x20, "\x55\xc3", 2);
	t0 = code_image(&p, 0, code, sizeof code);
	build(p.b, p.n, &t);
	f = at(&t, t0);
	CK(t.ok && f && f->len >= 6 && at(&t, t0 + 0x20));
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(f && (f->flags & KGENOME_FN_F_REACH_NONE) && f->end_source != KGENOME_FN_E_REACH);
#endif
	tab_free(&t);
	free(p.b);
}

/*
 * THE BODY'S OWN BLOCKS BEHIND ITS RET. Code that ends, right behind the end of a body with no padding between and no prologue, is more of that body (the block a compiler puts behind the `ret` that
 * nothing branches to); with a prologue instruction it is a function (a start in a gap); data that does not end is neither. f: push ebp; ret; xor eax,eax; ret (a dead tail). h: push ebp; ret; push ebp;
 * mov ebp,esp; pop ebp; ret (a function right behind, no padding: the prologue says so).
 */
static void t_reach_adjacent(void)
{
	struct pb p;
	struct tab t;
	uint8_t code[0x100];
	uint32_t t0;
	const struct kgenome_func *f;

	memset(code, 0xcc, sizeof code);
	memcpy(code, "\x55\xe8\0\0\0\0\xc3\x31\xc0\xc3", 10); rel32(code, 1, 5, 0x20);
	memcpy(code + 0x20, "\x55\xc3\x55\x8b\xec\x5d\xc3", 7);
	t0 = code_image(&p, 0, code, sizeof code);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	f = at(&t, t0);
	CK(f && f->len == 10);                                               /* the dead `xor eax,eax; ret` is the body's (its `ret imm16` would be the pop count) */
	f = at(&t, t0 + 0x20);
	CK(f && f->len == 2);                                                /* a ret, then a prologue: a new function ... */
	f = at(&t, t0 + 0x22);
	CK(f && f->len == 5);                                                /* ... which is a start, with no padding */
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(f && (f->flags & KGENOME_FN_F_GAP));
#endif
	tab_free(&t);
	free(p.b);
}

/*
 * A JUMP TO THE BYTE BEHIND AN INT3 RUN is the start of another function (an int3 is never executed inside a body: it is the padding between functions); two noreturn call blocks of one body, the second reached
 * by a branch and standing behind the first one's mark with no padding, are one function. f: push ebp; test eax,eax; je L; call g; int3; L: call g; int3 (+ padding); the tail jump `jmp h` of k lands behind padding.
 */
static void t_reach_jump_targets(void)
{
	struct pb p;
	struct tab t;
	uint8_t code[0x100];
	uint32_t t0;
	const struct kgenome_func *f;

	memset(code, 0xcc, sizeof code);
	memcpy(code, "\x55\x85\xc0\x74\x06\xe8\0\0\0\0\xcc\xe8\0\0\0\0\xcc", 17); rel32(code, 5, 5, 0x60); rel32(code, 0xb, 5, 0x60);
	memcpy(code + 0x20, "\x55\xe9\0\0\0\0", 6); rel32(code, 0x21, 5, 0x40);     /* k: a tail jump to the function behind the padding, which nothing calls */
	memcpy(code + 0x40, "\x55\x8b\xec\x5d\xc3", 5);
	memcpy(code + 0x60, "\x55\xc3", 2);
	t0 = code_image(&p, 0, code, sizeof code);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	f = at(&t, t0);
	CK(f && f->len == 17);                                               /* both call blocks, up to the second mark */
	CK(!at(&t, t0 + 0xb));                                               /* the second block is not a function: one int3, and it follows a call */
	CK(at(&t, t0 + 0x40) && atz(&t, t0 + 0x40)->len == 5);                /* the jump target behind the padding is */
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(at(&t, t0 + 0x40) && (atz(&t, t0 + 0x40)->flags & KGENOME_FN_F_GAP));
#endif
	tab_free(&t);
	free(p.b);
}

/*
 * FNR-3, the x86 SEH handler case: a function reached ONLY by a `mov reg, imm32` that stores its address (the fs:[0] EXCEPTION_REGISTRATION_RECORD install an x86 SEH frame does -
 * `reg.handler = handler;` lowers to exactly this, `movl $handler,-0x8(%ebp)`), never by a `call`/`jmp`, standing between two call-reached functions with NO padding at all between
 * it and the one before it (matching real mingw-w64 i686-gcc output byte for byte: measured with `i686-w64-mingw32-gcc` at -O0 default alignment, -O0 -falign-functions=1 and -O2,
 * all three stripped of symbols, none carrying a Load Config directory (no /SAFESEH table): in all three the handler sat immediately after the preceding function's `ret` with zero
 * separating bytes). FNR-3's own comment says this code is "cut before it" (swallowed into the preceding entry) because fntab_reach.c's graph never walks an edge into it; measured
 * here, that is NOT what happens: the GAPS step in this SAME file finds it anyway, because it does not need an edge - it starts a candidate right after the entry it already closed and
 * keeps it when that candidate's OWN decode ends (a `ret`) before the next known start. Not reproduced here, and not measured: MSVC's `_except_handler3`-based scope table (no MSVC
 * toolchain on this host) and a handler that does not end cleanly before the next start - those remain exactly the open gap FNR-3 names, this fixture is the narrower, now-measured one.
 */
static void t_seh_handler_gap_fnr3(void)
{
	struct pb p;
	struct tab t;
	uint8_t code[0x100];
	uint32_t t0;
	const struct kgenome_func *f;

	memset(code, 0xcc, sizeof code);
	/* entry: push ebp; mov ebp,esp; mov eax,0x401020 (&handler, a DATA reference - the fs:[0] install, never a call/jmp); call 0x40; pop ebp; ret */
	memcpy(code, "\x55\x8b\xec\xb8\x20\x10\x40\x00\xe8\0\0\0\0\x5d\xc3", 15);
	rel32(code, 8, 5, 0x40);
	memcpy(code + 0x20, "\x55\x8b\xec\x33\xc0\x5d\xc3", 7);          /* the handler: nothing calls or jumps here, no padding before it */
	memcpy(code + 0x40, "\x55\x8b\xec\x90\x5d\xc3", 6);              /* called from the entry, right behind the handler with no padding either */
	t0 = code_image(&p, 0, code, sizeof code);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	f = at(&t, t0);
	CK(f && f->len == 15);                                               /* the entry: ends at its own ret, the handler's address is just a value it loaded */
	f = at(&t, t0 + 0x40);
	CK(f && f->len == 6);                                                /* the call-reached function right behind the handler */
	f = at(&t, t0 + 0x20);
	CK(f && f->len == 7);                                                /* the handler itself: found with no edge at all naming it, and the exact length */
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(f && (f->flags & KGENOME_FN_F_GAP) && f->source == KGENOME_FN_S_WALK && f->end_source == KGENOME_FN_E_REACH);
#endif
	tab_free(&t);
	free(p.b);
}

/* The mark in the frame: the facts of a PE function that ends in `call; int3` say its control does not run on (RUNS_OUT is the next function's code), so the lineage reads it as a function that
 * never returns; the same bytes in a function that goes on through the int3 (the byte is the first of a following block that a branch reaches) do not. RED on base: RUNS_OUT was set. */
#ifndef FNTAB_PE_OLD_API_ONLY
static void t_trap_exit_frame_one(uint8_t mark)
{
	struct pb p;
	struct tab t;
	uint8_t code[0x100];
	uint32_t t0, fi;
	struct kgenome_frame_src s;
	struct kgenome_frame fr;
	const uint16_t *bits;
	uint32_t q;
	int runs_out = 0, ret = 0;

	memset(code, 0xcc, sizeof code);
	memcpy(code, "\x55\xe8\0\0\0\0\xcc", 7); rel32(code, 1, 5, 0x60);                  /* push ebp; call g; int3: a function that never returns */
	code[6] = mark;
	memcpy(code + 0x60, "\x55\xc3", 2);
	t0 = code_image(&p, 0, code, sizeof code);
	build(p.b, p.n, &t);
	CK(t.ok && atz(&t, t0)->len == 7);
	memset(&s, 0, sizeof s);
	s.obj = &t.obj; s.base = p.b; s.size = p.n; s.fs = &t.fs;
	CK(kgenome_frame_make(&s, t0, 7, 0u, &fr) == KGENOME_FRAME_OK);
	bits = kgenome_frame_facts_of(&fr, &s);
	CK(bits != NULL);
	for (q = 0; bits && q < fr.cfg.n_all; q++) {
		runs_out |= (bits[q] & KGENOME_FRAME_B_RUNS_OUT) != 0;
		ret |= (bits[q] & KGENOME_FRAME_B_RET) != 0;
	}
	CK(!runs_out && !ret);                                               /* no exit by running out, none by ret: it does not return */
	kgenome_frame_release(&fr, NULL);
	(void)fi;
	tab_free(&t);
	free(p.b);
}

static void t_trap_exit_frame(void) { t_trap_exit_frame_one(0xcc); t_trap_exit_frame_one(0xf4); }
#endif

/* A PE whose executable sections hold no byte of the file (the code arrives at run time): nothing to table, and the table says why. */
static void t_nocode(void)
{
	struct pb p;
	struct tab t;

	pb_init(&p, 0x4000, 0, 0x14c);
	pb_sec(&p, ".text", 0x1000, 0x1000, 0, CH_CODE);                      /* a section of virtual size and no raw bytes */
	pb_sec(&p, ".data", 0x2000, 0x200, 0x200, CH_DATA);
	pb_entry(&p, 0x1000);
	pb_done(&p);
	build(p.b, p.n, &t);
	CK(t.ok && t.fs.n == 0);
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(t.fs.ccase == KGENOME_FNTAB_C_PE_NOCODE && t.fs.state == KGENOME_FNTAB_PARTIAL && (t.fs.partial & KGENOME_FNTAB_P_NO_CODE) && t.fs.partial == KGENOME_FNTAB_P_NO_CODE);
#endif
	tab_free(&t);
	free(p.b);
}

#ifndef FNTAB_PE_OLD_API_ONLY
/*
 * ARM64 and Thumb-2: the packed exception table (8-byte entries). Written from the format's documentation: no sample exists (Inference), so this is the oracle. Entries: packed flag 1 with the length in
 * the word; xdata (flag 0) with FunctionLength in its first word; and the refusals, each counted: the reserved flag 3, a zero length, an xdata version other than 0, a start outside the code.
 */
static void arm_image(struct pb *p, unsigned machine, uint32_t *t0, const uint32_t *ent, unsigned n_ent)
{
	unsigned i;

	pb_init(p, 0x4000, machine == 0xaa64, machine);
	*t0 = pb_sec(p, ".text", 0x1000, 0x1000, 0x1000, CH_CODE);
	pb_sec(p, ".rdata", 0x2000, 0x200, 0x200, CH_RDATA);
	pb_sec(p, ".pdata", 0x3000, 0x100, 0x200, CH_RDATA);
	pb_entry(p, 0x1000);
	memset(p->b + *t0, 0x1f, 0x100);
	memset(p->b + *t0 + 0x100, 0, 0xf00);
	w(at_rva(p, 0x2000), 8, 4);               /* xdata 0: FunctionLength 8 units, version 0 */
	w(at_rva(p, 0x2004), 0x100000u | 8u, 4);  /* xdata 1: version 0 but a stray bit 20 (X): still read */
	w(at_rva(p, 0x2008), (1u << 18) | 8u, 4); /* xdata 2: version 1: refused */
	w(at_rva(p, 0x200c), (1u << 22) | 8u, 4); /* xdata 3: the F (fragment) bit of Thumb-2 */
	w(at_rva(p, 0x2010), 0x20000u, 4);        /* xdata 4: FunctionLength 0x20000 units (bit 17): past the section, clipped */
	for (i = 0; i < n_ent; i++) { w(at_rva(p, 0x3000) + i * 8u, ent[i * 2], 4); w(at_rva(p, 0x3000) + i * 8u + 4u, ent[i * 2 + 1], 4); }
	pb_dir(p, KGENOME_PE_DIR_EXCEPTION, 0x3000, n_ent * 8u);
	pb_done(p);
}

static void t_pdata_arm(void)
{
	struct pb p;
	struct tab t;
	uint32_t t0;
	const struct kgenome_func *f;
	/* ARM64: packed 4 units (16 bytes) at 0x1000; xdata 8 units (32 bytes) at 0x1040; the reserved flag; a zero packed length; xdata version 1; a start in no code; the zero fill of the table */
	static const uint32_t a64[] = { 0x1000, (4u << 2) | 1u, 0x1040, 0x2000, 0x1080, 3u, 0x10a0, 1u, 0x10c0, 0x2008, 0x9000, (4u << 2) | 1u, 0, 0 };
	/* Thumb-2: the start has bit 0 set; packed 4 units of 2 bytes (8 bytes); xdata 8 units (16 bytes); an F (fragment) record that is no function of the table */
	static const uint32_t thm[] = { 0x1001, (4u << 2) | 1u, 0x1021, 0x2000, 0x1041, 0x200c };

	arm_image(&p, 0xaa64, &t0, a64, 7);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	CK(t.fs.ccase == KGENOME_FNTAB_C_PE_ARM);
	f = at(&t, t0);
	CK(f && f->len == 16 && f->end_source == KGENOME_FN_E_UNWIND && (f->source & KGENOME_FN_S_PDATA));
	f = at(&t, t0 + 0x40);
	CK(f && f->len == 32 && f->end_source == KGENOME_FN_E_UNWIND);
	CK(t.fs.n == 2);                                                     /* the entries held two (the entry point is the first one: it names the same start); the walk is not run (x86 only) */
	CK(t.fs.state == KGENOME_FNTAB_PARTIAL && (t.fs.partial & KGENOME_FNTAB_P_STARTS) && (t.fs.partial & KGENOME_FNTAB_P_BAD_FDE));
	tab_free(&t);
	free(p.b);
	arm_image(&p, 0x1c4, &t0, thm, 3);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n) && t.fs.ccase == KGENOME_FNTAB_C_PE_ARM);
	f = at(&t, t0);
	CK(f && f->len == 8 && f->isa_mode == KGENOME_FN_ISA_THUMB);           /* the even address, the length in halfwords */
	f = at(&t, t0 + 0x20);
	CK(f && f->len == 16 && f->isa_mode == KGENOME_FN_ISA_THUMB);
	CK(!at(&t, t0 + 0x40) && t.fs.n_extra >= 1);   /* a fragment is a mask, never an entry of a finished table */
	tab_free(&t);
	free(p.b);
	/* the widths of the length fields: 0x400 packed units (bit 10) and 0x20000 xdata units (bit 17) are read whole and clipped to the section; the reserved flag with a non-zero length is refused */
	{
		static const uint32_t wide[] = { 0x1100, (0x400u << 2) | 1u, 0x1040, (4u << 2) | 3u };
		static const uint32_t xwide[] = { 0x1100, 0x2010 };

		arm_image(&p, 0xaa64, &t0, wide, 2);
		build(p.b, p.n, &t);
		CK(t.ok && atz(&t, t0 + 0x100)->len > 0x400u && (atz(&t, t0 + 0x100)->flags & KGENOME_FN_F_CLIPPED));
		CK(!at(&t, t0 + 0x40));
		tab_free(&t);
		free(p.b);
		arm_image(&p, 0xaa64, &t0, xwide, 1);
		build(p.b, p.n, &t);
		CK(t.ok && atz(&t, t0 + 0x100)->len > 0x400u && (atz(&t, t0 + 0x100)->flags & KGENOME_FN_F_CLIPPED));
		tab_free(&t);
		free(p.b);
		arm_image(&p, 0x1c2, &t0, thm, 1);                               /* the older Thumb machine id is the same case */
		build(p.b, p.n, &t);
		CK(t.ok && t.fs.ccase == KGENOME_FNTAB_C_PE_ARM && atz(&t, t0)->len == 8);
		tab_free(&t);
		free(p.b);
	}
	/* a machine whose exception directory this tree cannot read: empty, and it says so */
	arm_image(&p, 0x1c0, &t0, thm, 1);
	build(p.b, p.n, &t);
	CK(t.ok && t.fs.n == 0 && t.fs.ccase == KGENOME_FNTAB_C_PE_NONE && (t.fs.partial & KGENOME_FNTAB_P_NO_TABLE));
	tab_free(&t);
	free(p.b);
}
#endif


/* A body that runs on into padding that is NOT behind its int3 mark ends where the padding begins: f: push ebp; call g; nop; nop; nop and g right behind (g is called by h): the nop after the call
 * is the mark, the two nops after it are padding, g's start is where the walk's run of padding ends. A call and its mark behind a `ret` (the block of a call that does not return, with no padding
 * before it) is more of that body: f2: push ebp; call g; ret; call g; nop and then the padding. */
static void t_reach_padding_and_marks(void)
{
	struct pb p;
	struct tab t;
	uint8_t code[0x100];
	uint32_t t0;
	const struct kgenome_func *f;

	memset(code, 0xcc, sizeof code);
	memcpy(code, "\x55\xe8\0\0\0\0\x90\x90\x90", 9); rel32(code, 1, 5, 9);                   /* f: 9 bytes, g at 9 */
	memcpy(code + 9, "\x55\xc3", 2);
	memcpy(code + 0x20, "\x55\xe8\0\0\0\0\xc3\xe8\0\0\0\0\x90", 13); rel32(code, 0x21, 5, 9); rel32(code, 0x27, 5, 9);
	memcpy(code + 0x40, "\xe8\0\0\0\0\xc3", 6); rel32(code, 0x40, 5, 0x20);                    /* h: calls f2 */
	t0 = code_image(&p, 0, code, sizeof code);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	f = at(&t, t0);
	CK(f && f->len == 7);                                                /* the call and its one-nop mark; the other two nops are padding */
	f = at(&t, t0 + 0x20);
	CK(f && f->len == 13);                                               /* the call block behind the ret is the body's, up to its mark */
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(atz(&t, t0)->end_source == KGENOME_FN_E_REACH && atz(&t, t0 + 0x20)->end_source == KGENOME_FN_E_REACH);
#endif
	tab_free(&t);
	free(p.b);
}

/* The window: a body longer than the first window (4096 bytes) is read to its end; one longer than the bound of cost (1 MiB) is said, not cut: REACH_NONE, the end the next start. */
static void t_reach_windows(void)
{
	static const uint32_t big[] = { 6000, 1200000 };
	unsigned k;

	for (k = 0; k < 2; k++) {
		struct pb p;
		struct tab t;
		uint32_t t0, n = big[k], i;
		const struct kgenome_func *f;

		pb_init(&p, 0x180000, 0, 0x14c);
		t0 = pb_sec(&p, ".text", 0x1000, n + 0x200, n + 0x200, CH_CODE);
		pb_entry(&p, 0x1000);
		for (i = 0; i + 2 <= n; i += 2) { p.b[t0 + i] = 0x89; p.b[t0 + i + 1] = 0xc0; }       /* mov eax,eax: a body of straight code */
		p.b[t0 + n] = 0xc3;
		memset(p.b + t0 + n + 1, 0xcc, 0x1ff);
		pb_done(&p);
		build(p.b, p.n, &t);
		f = at(&t, t0);
		CK(t.ok && f);
		if (k == 0) {
			CK(f && f->len == n + 1);                                    /* the whole body: the window grew past the first 4096 bytes */
#ifndef FNTAB_PE_OLD_API_ONLY
			CK(atz(&t, t0)->end_source == KGENOME_FN_E_REACH);
#endif
		} else {
#ifndef FNTAB_PE_OLD_API_ONLY
			CK(atz(&t, t0)->flags & KGENOME_FN_F_REACH_NONE);            /* over the bound: the entry says so and keeps the next-start end */
			CK(atz(&t, t0)->end_source != KGENOME_FN_E_REACH && (atz(&t, t0)->flags & KGENOME_FN_F_END_OPEN));
#endif
			CK(f && f->len > 1000000u);
		}
		tab_free(&t);
		free(p.b);
	}
}

/* Two chained fragments behind a function: no start is made inside either (the cover is sorted and read), and the padding between them is padding. */
static void t_pdata_two_fragments(void)
{
	struct x64 x;
	struct tab t;
	uint8_t *u;

	x64_image(&x, 60);
	memset(x.p.b + x.text + 0x60, 0xcc, 0x20);
	memcpy(x.p.b + x.text + 0x60, "\x31\xc0\xc3", 3);                       /* the first fragment */
	memcpy(x.p.b + x.text + 0x68, "\x31\xc0\xc3", 3);                       /* the second, behind padding */
	u = at_rva(&x.p, 0x2010);
	u[0] = 0x01 | (4u << 3); u[1] = 0; u[2] = 0; u[3] = 0;
	w(u + 4, 0x1000, 4); w(u + 8, 0x100e, 4); w(u + 12, 0x2000, 4);
	rf(&x.p, 0x3000, 3, 0x1060, 0x1063, 0x2010);
	rf(&x.p, 0x3000, 4, 0x1068, 0x106b, 0x2010);
	pb_dir(&x.p, KGENOME_PE_DIR_EXCEPTION, 0x3000, 60);
	build(x.p.b, x.p.n, &t);
	CK(t.ok && table_ok(&t, x.p.n));
	CK(!at(&t, x.text + 0x60) && !at(&t, x.text + 0x68) && !at(&t, x.text + 0x63));
	CK(t.fs.n == 3);                                                     /* the three non-leaf functions */
	tab_free(&t);
	free(x.p.b);
}

#ifndef FNTAB_PE_OLD_API_ONLY
/* The ARM64 / Thumb-2 strategy read directly, against hostile directories: the wrong machine, no directory, an RVA in no section, a directory larger than the file, a length past the section. */
static void t_pdata_arm_hostile(void)
{
	struct pb p;
	struct tab t;
	struct kgenome_fntab_list l;
	uint32_t t0;
	static const uint32_t ent[] = { 0x1000, (4u << 2) | 1u, 0x1040, (0x3ffu << 2) | 1u };      /* the second: 1023 units: past the section's raw bytes: clipped */

	arm_image(&p, 0xaa64, &t0, ent, 2);
	build(p.b, p.n, &t);
	CK(t.ok && atz(&t, t0 + 0x40)->len > 0 && (atz(&t, t0 + 0x40)->flags & KGENOME_FN_F_CLIPPED));
	/* the same list read as x86, and with the directory gone or pointing nowhere or past the file */
	memset(&l, 0, sizeof l);
	kgenome_fntab_pdata_arm(kof_buf_make(p.b, p.n), &t.info, &l);
	CK(l.n == 2);
	kgenome_fntab_list_free(&l);
	t.info.machine = 0x14c;
	memset(&l, 0, sizeof l);
	kgenome_fntab_pdata_arm(kof_buf_make(p.b, p.n), &t.info, &l);
	CK(l.n == 0);                                                        /* not a machine of this strategy */
	t.info.machine = 0xaa64;
	t.info.dir[KGENOME_PE_DIR_EXCEPTION].size = 0;
	kgenome_fntab_pdata_arm(kof_buf_make(p.b, p.n), &t.info, &l);
	CK(l.n == 0);                                                        /* no directory */
	t.info.dir[KGENOME_PE_DIR_EXCEPTION].size = 16; t.info.dir[KGENOME_PE_DIR_EXCEPTION].rva = 0x7ffff000u;
	kgenome_fntab_pdata_arm(kof_buf_make(p.b, p.n), &t.info, &l);
	CK(l.n == 0);                                                        /* an RVA that is in no section */
	t.info.dir[KGENOME_PE_DIR_EXCEPTION].rva = 0x3000; t.info.dir[KGENOME_PE_DIR_EXCEPTION].size = 0xfffffff0u;
	kgenome_fntab_pdata_arm(kof_buf_make(p.b, p.n), &t.info, &l);
	CK(l.n == 2);                                                        /* a size past the file: the entries the file holds (the rest of the section is the zero fill) */
	kgenome_fntab_list_free(&l);
	kgenome_fntab_pdata_arm(kof_buf_make(NULL, 0), &t.info, &l);
	CK(l.n == 0);
	tab_free(&t);
	free(p.b);
}
#endif


/* An int3 that the code falls into (the padding of the next function) is not the body's: `push ebp; mov ebp,esp` then int3 padding ends at the int3, whatever stands behind. And a branch whose target lies in
 * the last bytes of the first window (4096): the instruction it names is cut by the window, the window grows and the branch is followed. */
static void t_reach_fall_and_edge(void)
{
	struct pb p;
	struct tab t;
	uint8_t code[0x100];
	uint32_t t0, n, i;
	const struct kgenome_func *f;

	memset(code, 0xcc, sizeof code);
	memcpy(code, "\x55\xe8\0\0\0\0\x8b\xec", 8); rel32(code, 1, 5, 0x20);
	memcpy(code + 0x20, "\x55\xc3", 2);
	t0 = code_image(&p, 0, code, sizeof code);
	build(p.b, p.n, &t);
	f = at(&t, t0);
	CK(t.ok && f && f->len == 8);                                        /* `mov ebp,esp` then int3 padding: the body ends where the code falls into the int3 */
	tab_free(&t);
	free(p.b);
	/* a function: `test eax,eax; je 4093; ret`, filler, and at 4093 `mov eax,[0x12345678]; ret` (the instruction crosses the first window's end at 4096) */
	pb_init(&p, 0x20000, 0, 0x14c);
	n = 4200;
	t0 = pb_sec(&p, ".text", 0x1000, n + 0x200, n + 0x200, CH_CODE);
	pb_entry(&p, 0x1000);
	for (i = 0; i + 2 <= n; i += 2) { p.b[t0 + i] = 0x89; p.b[t0 + i + 1] = 0xc0; }
	memcpy(p.b + t0, "\x85\xc0\x0f\x84\0\0\0\0\xc3", 9);                /* test eax,eax; je 4090; ret */
	{ uint32_t d = 4093u - 8u; memcpy(p.b + t0 + 4, &d, 4); }
	memcpy(p.b + t0 + 4093, "\xa1\x78\x56\x34\x12\xc3", 6);              /* mov eax,[0x12345678] at 4093..4097: the first window (4096 bytes) cuts it; ret at 4098 */
	p.b[t0 + 4090] = 0xc3; p.b[t0 + 4091] = 0x90; p.b[t0 + 4092] = 0x90;      /* the filler ends in a ret and nop padding (an int3 run would make 4093 a function: the jump target behind it): only the branch reaches the block at 4093 */
	memset(p.b + t0 + 4099, 0xcc, 0x200);
	pb_done(&p);
	build(p.b, p.n, &t);
	f = at(&t, t0);
	CK(t.ok && f && f->len == 4099u && !at(&t, t0 + 4093u));                                    /* the block at 4093 is cut by the first window, reached through the branch, and the body ends at its ret */
	tab_free(&t);
	free(p.b);
}

/* What a function begins with, x64: with no padding behind the ret of a function, code that starts `push r`, `sub rsp,n`, `mov rax,rsp` or stores into the home space [rsp+n] is the next function (a start);
 * the same bytes without such a first instruction are more of the body behind it. */
static void t_reach_prologues(void)
{
	static const struct { const char *first; unsigned n; int start; } rows[] = {
		{ "\x40\x53\x48\x83\xec\x20\xc3", 7, 1 },                      /* push rbx; sub rsp,0x20; ret */
		{ "\x48\x83\xec\x28\xc3", 5, 1 },                              /* sub rsp,0x28; ret */
		{ "\x48\x8b\xc4\xc3", 4, 1 },                                  /* mov rax,rsp; ret */
		{ "\x48\x89\x5c\x24\x08\xc3", 6, 1 },                          /* mov [rsp+8],rbx; ret */
		{ "\x48\x89\x4d\xf8\xc3", 5, 1 },                              /* mov [rbp-8],rcx; ret */
		{ "\x31\xc0\xc3", 3, 0 },                                      /* xor eax,eax; ret */
		{ "\x48\x8b\x01\xc3", 4, 0 },                                  /* mov rax,[rcx]; ret: a load, not a prologue */
		{ "\x89\xc1\xc3", 3, 0 },                                      /* mov ecx,eax; ret: a register copy that is not from rsp */
	};
	unsigned k;

	for (k = 0; k < sizeof rows / sizeof *rows; k++) {
		struct pb p;
		struct tab t;
		uint8_t code[0x100];
		uint32_t t0;

		memset(code, 0xcc, sizeof code);
		memcpy(code, "\x55\xc3", 2);
		memcpy(code + 2, rows[k].first, rows[k].n);
		memcpy(code + 0x20, "\x55\xc3", 2);                          /* a second start (so the first body's bound is known) */
		t0 = code_image(&p, 1, code, sizeof code);
		build(p.b, p.n, &t);
		CK(t.ok && table_ok(&t, p.n));
		CK((at(&t, t0 + 2) != NULL) == rows[k].start);
		CK(atz(&t, t0)->len == (rows[k].start ? 2u : 2u + rows[k].n));
		tab_free(&t);
		free(p.b);
	}
}


/* Evidence of a start, and of no start. (1) A jump to the byte behind ONE int3 that follows a `jmp` (not a call: no mark) is a start. (2) Zero bytes behind padding are the fill and no start, even when a `ret` stands
 * behind them. (3) After a `ret`, `call; nop` with no padding is the block of a call that does not return (more of the body) and the prologue right behind it is a new function: the general rule alone would
 * take both as one body. (4) After a `ret`, a bare `jmp eax` with no padding does not end by a `ret`: it is neither more of the body nor a start. (5) The zero fill that reaches the end of the section joins the
 * padding in front of it: an entry that REACH leaves open (a switch) ends where the padding begins and not at the section's end. */
static void t_reach_kills(void)
{
	struct pb p;
	struct tab t;
	uint8_t code[0x100];
	uint32_t t0;
	const struct kgenome_func *f;

	memset(code, 0xcc, sizeof code);
	memcpy(code, "\x55\xe9\0\0\0\0\xcc\x55\xc3", 9); rel32(code, 1, 5, 7);       /* f: push ebp; jmp g; int3; g: push ebp; ret */
	t0 = code_image(&p, 0, code, sizeof code);
	build(p.b, p.n, &t);
	CK(t.ok && at(&t, t0 + 7) && atz(&t, t0 + 7)->len == 2);
	tab_free(&t);
	free(p.b);
	memset(code, 0xcc, sizeof code);
	memcpy(code, "\x55\xc3", 2);
	memcpy(code + 0x20, "\x00\x00\xc3", 3);
	t0 = code_image(&p, 0, code, sizeof code);
	build(p.b, p.n, &t);
	CK(t.ok && atz(&t, t0)->len == 2 && !at(&t, t0 + 0x20));
	tab_free(&t);
	free(p.b);
	memset(code, 0xcc, sizeof code);
	memcpy(code, "\x55\xe8\0\0\0\0\xc3\xe8\0\0\0\0\x90\x55\x8b\xec\x5d\xc3", 19); rel32(code, 1, 5, 0x40); rel32(code, 7, 5, 0x40);
	memcpy(code + 0x40, "\x55\xc3", 2);
	t0 = code_image(&p, 0, code, sizeof code);
	build(p.b, p.n, &t);
	CK(t.ok && atz(&t, t0)->len == 13);
	f = at(&t, t0 + 13);
	CK(f && f->len == 5);
	tab_free(&t);
	free(p.b);
	memset(code, 0xcc, sizeof code);
	memcpy(code, "\x55\xc3\xff\xe0", 4);
	t0 = code_image(&p, 0, code, sizeof code);
	build(p.b, p.n, &t);
	CK(t.ok && atz(&t, t0)->len == 2 && !at(&t, t0 + 2));
	tab_free(&t);
	free(p.b);
	memset(code, 0xcc, sizeof code);
	memcpy(code, "\x55\xff\xe0", 3);                                  /* a switch: REACH_INDIRECT, its end stays open */
	memset(code + 0x10, 0, sizeof code - 0x10);                          /* padding to 0x10, then the zero fill to the end of the section */
	t0 = code_image(&p, 0, code, sizeof code);
	memset(p.b + t0 + 0x10, 0, 0x1f0);
	build(p.b, p.n, &t);
	CK(t.ok && atz(&t, t0)->len == 3);
	tab_free(&t);
	free(p.b);
}

/*
 * FNR-2 (2026-11-04): a `ret` with no padding behind it, followed by bytes that happen to decode and end
 * (independently re-run from that offset), was absorbed into the previous body on the decode guess alone. The
 * fixture below is the exact reproducer bytes of corpus file corp300/166_117.bin, function offset 0x100f0 (the
 * 82 bytes from the oracle's measured truth end 0x102a4 to its wrong end 0x102f6: an x64 indirect-call-heavy
 * stretch that happens to decode cleanly and end in its own `ret`, but is not reached by any real edge of the
 * first body - it is the START of a DIFFERENT function the walk had not yet named). No existing test built this
 * shape (fntab_pe.c's own t_reach_states case A only tries 8 bytes of a jump table that does not decode to a
 * terminator at all - reason (b), no boundary input that actually LOOKS like code). Fixed: the chunk is no
 * longer absorbed without a real control-flow edge from the body naming it; it is left as an unclaimed gap.
 */
static void fnr2_no_evidence_absorb(void)
{
	static const uint8_t junk[] = {
		0xe3, 0xe3, 0x15, 0xe3, 0x7c, 0x6c, 0xf7, 0x73, 0x73, 0x73, 0x73, 0x73, 0x40, 0x53, 0x48, 0x83,
		0xec, 0x20, 0x48, 0x8b, 0xd9, 0xff, 0x15, 0xf1, 0xb1, 0x00, 0x00, 0x48, 0x63, 0xd0, 0x41, 0xb9,
		0x10, 0x00, 0x00, 0x00, 0x48, 0xff, 0xc2, 0x4c, 0x8b, 0xc3, 0x33, 0xc9, 0x48, 0x8d, 0x14, 0x53,
		0xff, 0x15, 0x16, 0xb6, 0x00, 0x00, 0xff, 0x15, 0xc8, 0xb4, 0x00, 0x00, 0x4c, 0x8b, 0xc3, 0x33,
		0xd2, 0x48, 0x8b, 0xc8, 0xff, 0x15, 0xc2, 0xb4, 0x00, 0x00, 0x33, 0xc0, 0x48, 0x83, 0xc4, 0x20,
		0x5b, 0xc3
	};
	struct pb p;
	struct tab t;
	uint8_t code[0x100];
	uint32_t t0;
	const struct kgenome_func *f;

	memset(code, 0xcc, sizeof code);
	memcpy(code, "\x55\xc3", 2);                    /* f: push ebp; ret - no other start is declared near it */
	memcpy(code + 2, junk, sizeof junk);
	t0 = code_image(&p, 1, code, sizeof code);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	f = atz(&t, t0);
	CK(f && f->len == 2);                           /* the ret, not the chunk behind it with no real edge to it */
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(f && f->end_source == KGENOME_FN_E_REACH && !(f->flags & KGENOME_FN_F_END_OPEN));
	/* the chunk itself is not turned into a function either: nothing reached it and its own first bytes (e3 e3: JECXZ) are not a prologue */
	CK(!at(&t, t0 + 2));
#endif
	tab_free(&t);
	free(p.b);
	/* the "no call" shape has no length bound (a length cap was tried and rejected: it improved this corpus
	 * further but regressed tests/lib/genome/lineage_seed.c's LG_F_DEAD generator, which expects an arbitrarily
	 * long call-free dead tail still absorbed - see the KNOWN... note at the fntab_reach.c call site). A long
	 * call-free run that only coincidentally ends, with no call to flag it as a separate function, IS still
	 * absorbed: xor eax,eax (x4) + ret, no call, no real edge, is taken as more of the body regardless of size. */
	memset(code, 0xcc, sizeof code);
	memcpy(code, "\x55\xc3\x31\xc0\x31\xc9\x31\xd2\x31\xdb\xc3", 11);
	t0 = code_image(&p, 1, code, sizeof code);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	f = atz(&t, t0);
	CK(f && f->len == 11);                          /* no call anywhere in it: absorbed whatever its length */
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(f && f->end_source == KGENOME_FN_E_REACH);
#endif
	tab_free(&t);
	free(p.b);
}

/* FNR-2v2 (2026-11-04): RED on the merged FNR-2 (`!rc.has_call` alone) - a chunk with no call of its own, but
 * carrying an int3 that is NOT right after a call, must not pass as the dead-tail SHAPE evidence FNR-2 meant:
 * that int3 fell through classify() as ordinary code (FNR-1; defect FNR-4), not because this is really a
 * continuation of the body before it. Measured on the PE oracle (oracle -p pe120.txt) this one condition is a
 * small, safe piece of the 231-vs-188 distinct-long regression, not the dominant one (FNR-4 is: it inflates an
 * entry's OWN reach_of(), outside this absorption decision, in 75% of the 148 cases there - see the comment at
 * the fntab_reach.c call site). */
static void fnr2v2_trap_not_absorbed(void)
{
	struct pb p;
	struct tab t;
	uint8_t code[0x100];
	uint32_t t0;
	const struct kgenome_func *f;

	memset(code, 0xcc, sizeof code);
	memcpy(code, "\x55\xc3\x31\xc0\xcc\xc3", 6);    /* f: push ebp; ret : xor eax,eax; int3; ret - no call in the tail, but an int3 inside it */
	t0 = code_image(&p, 1, code, sizeof code);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	f = atz(&t, t0);
	CK(f && f->len == 2);                           /* the ret, not the trap-laden chunk behind it */
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(f && f->end_source == KGENOME_FN_E_REACH && !(f->flags & KGENOME_FN_F_END_OPEN));
	/* the chunk itself is not turned into a function either: nothing reached it and its own first bytes (xor eax,eax) are not a prologue */
	CK(!at(&t, t0 + 2));
#endif
	tab_free(&t);
	free(p.b);
}

/* FNR-4 (2026-11-04): classify()'s FNR-1 fix lets a bare int3/hlt not right after a CALL fall through as ordinary
 * flow, so graph_of()'s OWN reachable-block walk (fntab_reach.c) could run straight through a genuine, multi-byte
 * alignment run and into the next function's own bytes, inside the SAME block. This needs the probe function's
 * block to have NO terminator of its own before the padding (a `ret` ends a block with no fall-through edge, so a
 * function that returns is never at risk here regardless of FNR-4 - that is what fnr2_no_evidence_absorb and
 * fnr2v2_trap_not_absorbed above already cover, through the SEPARATE gap-absorption heuristic in the while loop of
 * kgenome_fntab_reach(), for an UNREACHABLE adjacent chunk with no edge into it at all). Case 1's `f` is a single
 * `push ebp` with no ret: nothing ends its block before `g`'s own `ret`, so block 0 is one continuous reachable
 * run from f's entry through the padding into g - on the unfixed code classify() lets every int3 of the run fall
 * through as ordinary flow (none of them is right after a CALL) and graph_of()'s own `end` extends straight into
 * g's `ret`, giving f->len==0x12 and no separate `g` start at all (RED, confirmed in the redcheck run below).
 */
static void fnr4_reach_stops_at_padding(void)
{
	struct pb p;
	struct tab t;
	uint8_t code[0x100];
	uint32_t t0;
	const struct kgenome_func *f, *g;

	memset(code, 0xcc, sizeof code);
	memcpy(code, "\x55", 1);                 /* f: push ebp - no ret: nothing of its own ends the block before the padding */
	memcpy(code + 0x10, "\x55\xc3", 2);      /* g: push ebp; ret - a real second function behind 15 bytes of alignment padding, no call anywhere near it */
	t0 = code_image(&p, 1, code, sizeof code);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	f = atz(&t, t0);
	CK(f && f->len == 1);                    /* f's own push, not the 15 bytes of padding plus g */
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(f && f->end_source == KGENOME_FN_E_REACH);
#endif
	g = at(&t, t0 + 0x10);
	CK(g != NULL && g->len == 2);            /* g is still found, behind the padding f no longer swallows */
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(g && g->source == KGENOME_FN_S_WALK && (g->flags & KGENOME_FN_F_GAP));
#endif
	tab_free(&t);
	free(p.b);
	/* Non-regression (FNR-1's own case, now exercised through graph_of()'s reachable-block walk rather than the
	 * gap-absorption heuristic): a single int3 that is NOT part of any recorded padding run - real instructions
	 * right on both sides, so the walk's own pad scan closes it as a one-byte entry, which crosses_pad's length
	 * filter rejects - must still fall through as ordinary flow and not stop the reach. `f` here is again
	 * terminator-free until its own final `ret`, so the whole 7-byte chunk is one reachable block; if crosses_pad
	 * mistook the lone trap for a genuine run, f would wrongly end at the int3 instead of its own ret. */
	memset(code, 0xcc, sizeof code);
	memcpy(code, "\x55\x31\xc0\xcc\x31\xc9\xc3", 7);        /* f: push ebp; xor eax,eax; int3; xor ecx,ecx; ret - no terminator before the lone int3 */
	t0 = code_image(&p, 1, code, sizeof code);
	build(p.b, p.n, &t);
	CK(t.ok && table_ok(&t, p.n));
	f = atz(&t, t0);
	CK(f && f->len == 7);                    /* the whole chunk, including past the lone int3: not a recorded run, does not stop the walk */
#ifndef FNTAB_PE_OLD_API_ONLY
	CK(f && f->end_source == KGENOME_FN_E_REACH);
#endif
	tab_free(&t);
	free(p.b);
}

int main(void)
{
	t_x86_walk();
	t_x86_idempotent_and_virtual();
	t_entry_outside_code();
	t_virtual_size_cut();
	t_thunks();
	t_stub_slots();
	t_stub_order();
	t_sigreturn_not_in_pe();
	t_code_bytes_union();
	t_lineage_sections_out_of_order();
	t_thunk_slot_outside_iat();
	t_tail_rules();
	t_no_jmp_thunk();
	t_reach_ends();
	t_reach_states();
	t_reach_adjacent();
	t_reach_jump_targets();
	t_seh_handler_gap_fnr3();
	t_reach_padding_and_marks();
	t_reach_windows();
	t_reach_fall_and_edge();
	t_reach_prologues();
	t_reach_kills();
	fnr2_no_evidence_absorb();
	fnr2v2_trap_not_absorbed();
	fnr4_reach_stops_at_padding();
	t_pdata_two_fragments();
	t_nocode();
#ifndef FNTAB_PE_OLD_API_ONLY
	t_trap_exit_frame();
	t_pdata_arm();
	t_pdata_arm_hostile();
#endif
	t_pdata_leaf();
	t_pdata_gap_leaf();
	t_pdata_chained();
	t_pdata_hostile();
	t_pdata_unwind_info();
	t_pdata_indirect();
	t_pdata_indirect_chained();
	t_pdata_chain_loop();
	t_pdata_count_and_overlap();
	t_pdata_clip();
	t_pdata_cap();
	t_exports();
#ifndef FNTAB_PE_OLD_API_ONLY
	t_export_forwarder_in_code();
#endif
	t_tls();
	t_tls_hostile();
	t_cfg_tables();
	t_coff();
	t_coff_hostile();
	t_clr();
	t_hostile_images();
	t_poison();
#ifndef FNTAB_PE_OLD_API_ONLY
	t_selector();
	t_probe();
	t_merge_order();
#endif
	printf("fntab_pe: %d failure(s)\n", fails);
	return fails != 0;
}
