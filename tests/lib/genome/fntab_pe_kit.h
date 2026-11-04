/*
 * fntab_pe_kit.h - the in-memory PE writer and the table helpers of the PE function-table tests (fntab_pe.c, fntab_pe_oom.c): every image is BUILT from the values the test names.
 * One writer, shared; a test includes it after <kgenome.h> and the headers it needs.
 */
#ifndef FNTAB_PE_KIT_H
#define FNTAB_PE_KIT_H

#define FPK_UNUSED __attribute__((unused))     /* a test that includes the kit uses some of it */

static int fails;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

/* ---- the writer ------------------------------------------------------------------------------------------------ */

#define MAXSEC 6
struct pb {
	uint8_t *b;
	uint32_t cap, n;
	int plus;
	uint32_t lfanew, dirs, sec_tab, nsec;
	struct { uint32_t rva, vsize, raw, rawsz, ch; } s[MAXSEC];
	uint32_t sym_off, nsym;
};

#define CH_CODE 0x60000020u     /* CNT_CODE | MEM_EXECUTE | MEM_READ */
#define CH_DATA 0xc0000040u
#define CH_RDATA 0x40000040u

static void w(uint8_t *p, uint64_t v, unsigned n)
{
	unsigned i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(v >> (8u * i));
}

static void pb_init(struct pb *p, uint32_t cap, int plus, unsigned machine)
{
	uint8_t *b;
	uint32_t o;

	memset(p, 0, sizeof *p);
	p->b = calloc(1, cap);
	p->cap = cap;
	p->plus = plus;
	p->lfanew = 0x80;
	b = p->b;
	b[0] = 'M'; b[1] = 'Z';
	w(b + 0x3c, p->lfanew, 4);
	memcpy(b + p->lfanew, "PE\0\0", 4);
	w(b + p->lfanew + 4, machine, 2);
	w(b + p->lfanew + 20, plus ? 240u : 224u, 2);
	w(b + p->lfanew + 22, 0x22, 2);
	o = p->lfanew + 24u;
	w(b + o, plus ? 0x20b : 0x10b, 2);
	w(b + o + 16, 0x1000, 4);                       /* entry */
	w(b + o + 20, 0x1000, 4);                       /* BaseOfCode */
	if (plus) {
		w(b + o + 24, 0x140000000ull, 8);
		w(b + o + 32, 0x1000, 4); w(b + o + 36, 0x200, 4);
		w(b + o + 68, 3, 2); w(b + o + 108, 16, 4);
	} else {
		w(b + o + 28, 0x400000, 4);
		w(b + o + 32, 0x1000, 4); w(b + o + 36, 0x200, 4);
		w(b + o + 68, 3, 2); w(b + o + 92, 16, 4);
	}
	w(b + o + 56, 0x10000, 4);                      /* SizeOfImage: set again by pb_done */
	w(b + o + 60, 0x400, 4);                        /* SizeOfHeaders */
	p->dirs = o + (plus ? 112u : 96u);
	p->sec_tab = p->dirs + 128u;
	p->n = 0x400;
}

/* A section at `rva`, `rawsz` bytes in the file (rounded to 0x200); returns its file offset. */
static uint32_t pb_sec(struct pb *p, const char *name, uint32_t rva, uint32_t vsize, uint32_t rawsz, uint32_t ch)
{
	uint8_t *h = p->b + p->sec_tab + p->nsec * 40u;
	uint32_t raw = p->n;

	rawsz = (rawsz + 0x1ffu) & ~0x1ffu;
	memcpy(h, name, strlen(name) > 8 ? 8 : strlen(name));
	w(h + 8, vsize, 4); w(h + 12, rva, 4); w(h + 16, rawsz, 4); w(h + 20, raw, 4); w(h + 36, ch, 4);
	p->s[p->nsec].rva = rva; p->s[p->nsec].vsize = vsize; p->s[p->nsec].raw = raw; p->s[p->nsec].rawsz = rawsz; p->s[p->nsec].ch = ch;
	p->nsec++;
	p->n += rawsz;
	w(p->b + p->lfanew + 6, p->nsec, 2);
	return raw;
}

static uint8_t *at_rva(struct pb *p, uint32_t rva)
{
	unsigned i;

	for (i = 0; i < p->nsec; i++)
		if (rva >= p->s[i].rva && rva - p->s[i].rva < p->s[i].rawsz)
			return p->b + p->s[i].raw + (rva - p->s[i].rva);
	return NULL;
}

FPK_UNUSED static uint32_t off_of(struct pb *p, uint32_t rva) { return (uint32_t)(at_rva(p, rva) - p->b); }

FPK_UNUSED static void pb_dir(struct pb *p, unsigned i, uint32_t rva, uint32_t size)
{
	w(p->b + p->dirs + i * 8u, rva, 4);
	w(p->b + p->dirs + i * 8u + 4u, size, 4);
}

static void pb_entry(struct pb *p, uint32_t rva) { w(p->b + p->lfanew + 24 + 16, rva, 4); }

static void pb_done(struct pb *p)
{
	uint32_t top = 0, i;

	for (i = 0; i < p->nsec; i++) {
		uint32_t e = (p->s[i].rva + (p->s[i].vsize > p->s[i].rawsz ? p->s[i].vsize : p->s[i].rawsz) + 0xfffu) & ~0xfffu;

		if (e > top)
			top = e;
	}
	w(p->b + p->lfanew + 24 + 56, top, 4);
}

/* COFF symbols: appended after the last section. `aux` is the TotalSize of a function's auxiliary record, or 0 for none. */
struct csym { uint32_t value; int16_t sec; uint16_t type; uint8_t cls; uint32_t aux; };
FPK_UNUSED static void pb_syms(struct pb *p, const struct csym *s, unsigned n)
{
	unsigned i, k = 0;
	uint8_t *t = p->b + p->n;

	for (i = 0; i < n; i++) {
		memset(t + k * 18u, 0, 18);
		memcpy(t + k * 18u, "sym", 3);
		w(t + k * 18u + 8, s[i].value, 4);
		w(t + k * 18u + 12, (uint16_t)s[i].sec, 2);
		w(t + k * 18u + 14, s[i].type, 2);
		t[k * 18u + 16] = s[i].cls;
		t[k * 18u + 17] = s[i].aux ? 1 : 0;
		k++;
		if (s[i].aux) {
			memset(t + k * 18u, 0, 18);
			w(t + k * 18u + 4, s[i].aux, 4);
			k++;
		}
	}
	w(p->b + p->lfanew + 12, p->n, 4);
	w(p->b + p->lfanew + 16, k, 4);
	p->n += k * 18u + 4u;
}

/* ---- the table ------------------------------------------------------------------------------------------------- */

struct tab {
	struct kgenome_pe_info info;
	struct kgenome_obj obj;
	struct kgenome_func_set fs;
	int ok;
};

FPK_UNUSED static void build(const uint8_t *b, uint32_t n, struct tab *t)
{
	memset(t, 0, sizeof *t);
	t->ok = kgenome_pe_image_parse(kof_buf_make(b, n), &t->info, &t->obj);
	t->obj.file_header = &t->info;
	t->obj.obj_size = n;
	if (t->ok)
		kgenome_diag_funcs_with_walk(&t->obj, b, n, NULL, &t->fs);
}

FPK_UNUSED static void tab_free(struct tab *t) { kgenome_funcs_free(&t->fs); }

static const struct kgenome_func g_nofunc;      /* what atz answers for an offset that is no start: a zero entry (len 0, no flags), so a check reads it without a null test */

static const struct kgenome_func *at(const struct tab *t, uint64_t off)
{
	uint32_t i;

	for (i = 0; i < t->fs.n; i++)
		if (t->fs.v[i].off == off)
			return &t->fs.v[i];
	return NULL;
}

FPK_UNUSED static const struct kgenome_func *atz(const struct tab *t, uint64_t off) { const struct kgenome_func *f = at(t, off); return f ? f : &g_nofunc; }

/* The invariants of any finished table, whatever the image: sorted, each entry inside the file, no empty entry, no fragment. */
FPK_UNUSED static int table_ok(const struct tab *t, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < t->fs.n; i++) {
		const struct kgenome_func *f = &t->fs.v[i];

		if (!f->len || f->off + f->len > n || f->off + f->len < f->off || f->kind == KGENOME_FN_FRAGMENT)
			return 0;
		if (i && f->off <= t->fs.v[i - 1].off)
			return 0;
	}
	return 1;
}


/* A .text of 0x200 raw bytes with `n` bytes of code at its start, the rest zero (as a linker leaves a section's tail); PE32 (x64 == 0) or PE32+ (x64) with NO exception table. The
 * bytes between the functions the test writes itself. Returns the file offset of .text. */
FPK_UNUSED static uint32_t code_image(struct pb *p, int x64, const uint8_t *code, uint32_t n)
{
	uint32_t t;

	pb_init(p, 0x4000, x64, x64 ? 0x8664 : 0x14c);
	t = pb_sec(p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_entry(p, 0x1000);
	memset(p->b + t, 0xcc, 0x100);
	memcpy(p->b + t, code, n);
	memset(p->b + t + 0x100, 0, 0x100);
	pb_done(p);
	return t;
}

/* rel32 of a call or jump at `from` (the address of the instruction's last byte + 1 is `from + len`) to `to`. */
FPK_UNUSED static void rel32(uint8_t *c, uint32_t at, uint32_t len, uint32_t to) { uint32_t d = to - (at + len); memcpy(c + at + len - 4u, &d, 4); }

#endif /* FNTAB_PE_KIT_H */
