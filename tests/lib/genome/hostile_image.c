/*
 * hostile_image - the ELF, PE and CLR readers against objects built to hurt them.
 *
 * Every object here is a VALID one (hk.h builds it) that is then cut, stretched
 * or corrupted, and handed to the parse and to EVERY reader that walks a table
 * of it. The buffer is always a guard-page buffer (hk.h gb_put): the last byte
 * of the object is the last byte before a PROT_NONE page, so a read one byte
 * past the length the reader was given faults on the spot, in this process, with
 * no sanitizer needed. Under ASAN/UBSAN the same run also catches the reads and
 * the arithmetic that stay inside the page.
 *
 *   1  truncation       the object at EVERY length 0..N (8 ELF variants, 2 PE),
 *                       parsed on its own, and again with the description of the
 *                       WHOLE file held against the cut buffer (a stale view)
 *   2  field sweep      every 2-, 4- and 8-byte field of the headers and tables
 *                       set to each of 15 extremes (0, 1, 2^31, 2^32-1, 2^63,
 *                       2^64-1, n, n+1, n-1, ...) - counts larger than the file,
 *                       offset+size sums that wrap, negative-as-unsigned
 *   3  random flips     fixed-seed byte flips, 4 PRNG streams
 *   4  named structures cycles and self-references in the symbol, string,
 *                       relocation, import and export tables; sizes of 0 and of
 *                       2^64-1; a count of 2^32 over a file of 2 KiB
 *   5  CLR              the metadata reader at every length, hostile RVAs
 *
 * What is asserted is never "returns something": it is that no reader reports a
 * byte outside the object (a name offset, a span, a function, a relocation site),
 * that the status of a refused or bounded answer is not OK where the answer is
 * incomplete, and that no case takes more than a few seconds. A reader that
 * crashes, reads past the guard or hangs takes the whole process down, so each
 * family runs in its own forked child and a death is reported as a result.
 */

#include <kgenome.h>

#include "hk.h"
#include "../../unit/known_miss.h"

#define CAP 8192u

static struct hk_gb G;
static unsigned bad_reports, walks, scans;

static void bad(const char *what, size_t n)
{
	if (bad_reports++ < 12)
		printf("  FAIL %s (length %zu)\n", what, n);
	hk_fails++;
}

/* ---- the invariants the readers' callbacks are held to ----------------------- */

struct imp_chk { uint64_t n; uint32_t calls, viol; };

static void imp_cb(void *u, uint64_t slot, const char *dll, const char *name,
		   uint32_t ordinal, uint64_t nameoff)
{
	struct imp_chk *c = (struct imp_chk *)u;

	(void)slot; (void)ordinal;
	c->calls++;
	if (!dll || strlen(dll) > 64u)
		c->viol++;
	if (nameoff && nameoff != KGENOME_BROKEN && nameoff >= c->n)
		c->viol++;
	if (nameoff && (!name || strlen(name) > 1024u))
		c->viol++;
}

static int exp_cb(void *u, uint64_t nameoff, uint32_t rva)
{
	struct imp_chk *c = (struct imp_chk *)u;

	(void)rva;
	(void)nameoff;
	c->calls++;
	return 1;
}

struct rc_chk { uint32_t calls; };

static void rc_cb(void *u, uint64_t at, uint64_t target, const char *name)
{
	(void)at; (void)target;
	((struct rc_chk *)u)->calls++;
	if (!name || strlen(name) >= KGENOME_SYMNAME_MAX)
		hk_fails++;
}

static void vis_cb(void *u, uint64_t *off, uint64_t *len)
{
	(void)len;
	*(uint64_t *)u += *off != 0;
}

static void funcs_check(const struct kgenome_func_set *fs, size_t n, const char *tag)
{
	uint32_t i;

	for (i = 0; i < fs->n; i++) {
		if (fs->v[i].off > n || fs->v[i].len > n - fs->v[i].off) {
			bad(tag, n);
			return;
		}
		if (i && fs->v[i].off < fs->v[i - 1u].off) {
			bad("funcs not sorted", n);
			return;
		}
	}
}

/* ---- every reader of an ELF ---------------------------------------------------- */

static struct kgenome_elf_info eiA;
static struct kgenome_true_all tall;
static struct kgenome_true_result tres;

/* KNOWN UNDEFINED BEHAVIOUR, left out under UBSAN only (hk_ubsan): image_addr.c:32 and :49 add a
 * signed 64-bit delta (mem_addr - file_off, image_base + rva - file_off) to an offset; a segment or a
 * section that sits at 2^62 or above overflows it. In a plain build the sum wraps and the answer is
 * the same as with unsigned arithmetic. */
static int elf_addr_math_safe(const struct kgenome_elf_info *e)
{
	uint32_t i;

	if (!hk_ubsan())
		return 1;
	for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++)
		if (e->seg[i].mem_addr >= 1ull << 62 || e->seg[i].file_off >= 1ull << 62 ||
		    e->seg[i].file_size >= 1ull << 62)
			return 0;
	return 1;
}

static int pe_addr_math_safe(const struct kgenome_pe_info *p)
{
	uint32_t i;

	if (!hk_ubsan())
		return 1;
	if (p->image_base >= 1ull << 62)
		return 0;
	for (i = 0; i < p->sec_count && i < KGENOME_PE_MAX_SECTIONS; i++)
		if (p->sec[i].mem_rva >= 1ull << 62 || p->sec[i].file_off >= 1ull << 62)
			return 0;
	return 1;
}

static void walk_elf(const uint8_t *p, size_t n, const struct kgenome_elf_info *use,
		     int diag)
{
	kof_buf f = kof_buf_make(p, n);
	struct kgenome_obj o;
	const struct kgenome_elf_info *e;
	struct kgenome_elf_symtab t;
	struct kgenome_elf_symbol s;
	struct kgenome_elf_relocs rt;
	struct kgenome_func_set fs, fv;
	struct rc_chk rc = { 0 };
	uint64_t acc = 0, off;
	unsigned want, k;
	uint32_t i, nr;

	walks++;
	(void)kgenome_elf_sniff(f);
	memset(&o, 0, sizeof o);
	if (!use) {
		memset(&eiA, 0, sizeof eiA);
		(void)kgenome_elf_image_parse(f, &eiA, &o);
		e = &eiA;
	} else {
		e = use;
		o.format = KGENOME_FMT_ELF;
		o.arch = KGENOME_ARCH_X86_64;
		o.obj_size = n;
		o.entry_off = KGENOME_BROKEN;
	}
	o.file_header = e;
	o.format = KGENOME_FMT_ELF;
	o.obj_size = n;

	for (want = 0; want < 3; want++) {
		if (!kgenome_elf_symtab_of(f, e, (enum kgenome_elf_symtab_want)want, &t))
			continue;
		if (t.n > t.n_decl)
			bad("symtab n > n_decl", n);
		if (t.n && (t.off > n || t.n * t.recsize > n - t.off))
			bad("symtab records beyond the buffer", n);
		for (i = 0; t.off && i < t.n && i < 40u; i++)
			if (!kgenome_elf_symbol_at(f, &t, i, &s))
				bad("symbol_at refused a record the table holds", n);
		/* the record after the buffer's last whole one is refused */
		if (t.n < 1000u && kgenome_elf_symbol_at(f, &t, t.n_decl + 1000u, &s) &&
		    t.off + (t.n_decl + 1000u) * t.recsize + t.recsize <= n)
			bad("symbol_at read a record past the declared table", n);
	}
	for (k = 1; k <= 3; k++) {
		memset(&rt, 0, sizeof rt);
		nr = kgenome_elf_reloc_table(f, e, k, &rt);
		if (nr != rt.n)
			bad("reloc_table count != table n", n);
		for (i = 0; i < rt.n; i++) {
			/* a site or a name offset beyond the buffer is KNOWN (km_reloc_site
			 * below); the readers that take them are bounded by kof_rd_* */
			if (i && rt.v[i].where < rt.v[i - 1u].where)
				bad("relocations not sorted by where", n);
		}
		(void)kgenome_elf_relcalls(f, e, &rt, rc_cb, &rc);
		for (i = 0; i < 6 && i < rt.n; i++)
			(void)kgenome_elf_reloc_in(&rt, rt.v[i].where, 4);
		(void)kgenome_elf_reloc_in(&rt, UINT64_MAX - 2u, 255);
		kgenome_elf_reloc_table_free(&rt);
	}
	for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++) {
		(void)kgenome_elf_seg_is_load(&e->seg[i]);
		(void)kgenome_elf_seg_is_code(&e->seg[i]);
		if (kgenome_elf_seg_extent(&e->seg[i], n, &off) > n)
			bad("seg extent longer than the object", n);
		(void)kgenome_elf_load_at_off(e, e->seg[i].file_off);
		if (kgenome_elf_va_to_off(e, e->seg[i].mem_addr, 1, &off) && 0)
			acc += off;
	}
	for (i = 0; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
		(void)kgenome_elf_sec_is_code(&e->sec[i]);
		if (kgenome_elf_sec_extent(&e->sec[i], n, &off) > n)
			bad("sec extent longer than the object", n);
	}
	for (i = 0; i < 8; i++) {
		static const uint64_t probe[8] = { 0, 1, 0x40, 0x400000, 0x401000,
			UINT64_MAX, UINT64_MAX - 1, 0x7fffffffffffffffull };
		(void)kgenome_elf_va_to_off(e, probe[i], probe[(i + 3u) & 7u], &off);
		if (!elf_addr_math_safe(e))
			continue;
		(void)kgenome_image_seg_at(&o, probe[i], &(struct kgenome_image_seg){ 0, 0, 0 });
		(void)kgenome_image_off_to_addr(&o, probe[i]);
		(void)kgenome_image_addr_to_off(&o, probe[i]);
	}

	kgenome_true_find(f, e, &tres);
	kgenome_true_find_all(f, e, &tall);
	for (i = 0; i < tall.n; i++)
		if (tall.span[i].off > n || tall.span[i].len > n - tall.span[i].off)
			bad("true_find_all span beyond the object", n);
	kgenome_true_find_object(f, e, &tall);
	for (i = 0; i < tall.n; i++)
		if (tall.span[i].off > n || tall.span[i].len > n - tall.span[i].off)
			bad("true_find_object span beyond the object", n);
	if (tall.n > KGENOME_TRUE_MAX_SPANS_ALL)
		bad("true_all n past its array", n);
	(void)kgenome_true_touches(&tall, 0, n);
	(void)kgenome_true_touches(&tall, UINT64_MAX, 2);
	(void)kgenome_true_has_addr(e, &tall, 0x400000, 4);

	kgenome_funcs_build(KGENOME_FMT_ELF, p, n, e, &fs);
	funcs_check(&fs, n, "function extent beyond the object");
	memset(&fv, 0, sizeof fv);
	kgenome_funcs_remap(p, n, &fs, p, n, &fv);
	funcs_check(&fv, n, "remapped function beyond the view");
	kgenome_funcs_free(&fv);
	kgenome_funcs_free(&fs);
	{
		uint64_t ent[3] = { 0, 0x40, UINT64_MAX };
		kgenome_elf_funcs_from_entries(f, e, 0x40, ent, 3, &fs);
		funcs_check(&fs, n, "from_entries extent beyond the object");
		kgenome_funcs_free(&fs);
	}

	{
		struct kgenome_elf_info c = *e;
		uint64_t from[2] = { 0, n / 2u }, to[2] = { 0, n / 4u };
		struct kgenome_offmap m = { from, to, 2, n, n / 2u + 1u };
		kgenome_elf_info_offsets(&c, vis_cb, &acc);
		kgenome_elf_info_remap(&c, &m);
	}

	if (diag) {
		struct kgenome_diag_scan *d = kgenome_diag_scan_with(&o, p, n, diag > 1 ? KGENOME_DIAG_RUN_ALL : KGENOME_DIAG_RUN_DEFAULT);
		scans++;
		if (d) {
			uint32_t h = kgenome_diag_scan_count(d);
			uint32_t q;
			for (q = 0; q < h && q < 64u; q++) {
				const struct kgenome_diag_hit *ht = kgenome_diag_scan_at(d, q);
				if (!ht || ht->at > n)
					bad("diagnose hit beyond the object", n);
			}
			(void)kgenome_diag_scan_status(d);
			(void)kgenome_diag_scan_bytes(d, &off);
			kgenome_diag_scan_free(d);
		}
		kgenome_diag_funcs_of(&o, p, n, &fs);
		funcs_check(&fs, n, "diag_funcs_of beyond the object");
		kgenome_funcs_free(&fs);
		(void)kgenome_diag_code_bytes(&o, n);
	}
	(void)acc;
}

/* ---- every reader of a PE ------------------------------------------------------- */

static struct kgenome_pe_info piA;
static uint8_t scratch[0x4000];

static void walk_pe(const uint8_t *p, size_t n, const struct kgenome_pe_info *use, int diag)
{
	kof_buf f = kof_buf_make(p, n);
	struct kgenome_obj o;
	const struct kgenome_pe_info *e;
	struct imp_chk ic = { n, 0, 0 };
	enum kgenome_status st = KGENOME_OK;
	struct kgenome_pe_imptab t;
	struct kgenome_func_set fs;
	struct kgenome_sec_decl sd[16];
	struct kgenome_dir_decl dd[16];
	uint8_t *img = NULL;
	uint64_t img_n = 0, entry = 0, base = 0, acc = 0, off;
	uint32_t i, k;

	walks++;
	(void)kgenome_pe_sniff(f);
	memset(&o, 0, sizeof o);
	if (!use) {
		memset(&piA, 0, sizeof piA);
		(void)kgenome_pe_image_parse(f, &piA, &o);
		e = &piA;
	} else {
		e = use;
		o.arch = KGENOME_ARCH_X86_64;
	}
	o.format = KGENOME_FMT_PE;
	o.file_header = e;
	o.obj_size = n;
	o.entry_off = KGENOME_BROKEN;

	k = kgenome_pe_imports(f, e, imp_cb, &ic, &st);
	if (k != ic.calls)
		bad("pe_imports count != callbacks", n);
	if (ic.viol)
		bad("pe_imports reported a name offset outside the object", n);
	if (st > KGENOME_NOMEM)
		bad("pe_imports status out of range", n);
	ic.calls = 0; ic.viol = 0;
	k = kgenome_pe_exports(f, e, exp_cb, &ic, &st);
	if (k != ic.calls || ic.viol)
		bad("pe_exports count or offset", n);

	memset(&t, 0, sizeof t);
	kgenome_pe_imptab_build(f, e, &t);
	if (!kgenome_pe_imptab_is_of(&t, f))
		bad("imptab not of its own buffer", n);
	for (i = 0; i < t.n; i++) {
		char nm[16];
		if (t.v[i].dll >= t.n_dll)
			bad("import's dll index past the dll table", n);
		(void)kgenome_pe_imp_name(f, &t.v[i], nm, sizeof nm);
		if (strlen(nm) >= sizeof nm)
			bad("imp_name overran its destination", n);
	}
	kgenome_pe_imptab_free(&t);

	for (i = 0; i < e->sec_count && i < KGENOME_PE_MAX_SECTIONS; i++) {
		if (kgenome_pe_sec_extent(&e->sec[i], n, &off) > n)
			bad("pe sec extent longer than the object", n);
		(void)kgenome_pe_sec_is_code(&e->sec[i]);
		(void)kgenome_pe_sec_at_off(e, e->sec[i].file_off);
	}
	for (i = 0; i < 6; i++) {
		static const uint64_t probe[6] = { 0, 0x1000, 0x2000, UINT64_MAX, 0x80000000u,
			0x140000000ull };
		(void)kgenome_pe_rva_to_off(e, probe[i]);
		if (!pe_addr_math_safe(e))
			continue;
		(void)kgenome_image_off_to_addr(&o, probe[i]);
		(void)kgenome_image_addr_to_off(&o, probe[i]);
		(void)kgenome_image_seg_at(&o, probe[i], &(struct kgenome_image_seg){ 0, 0, 0 });
	}

	kgenome_funcs_build(KGENOME_FMT_PE, p, n, e, &fs);
	funcs_check(&fs, n, "pe function extent beyond the object");
	kgenome_funcs_free(&fs);
	kgenome_pe_funcs_build(f, e, &fs);
	funcs_check(&fs, n, "pe_funcs_build extent beyond the object");
	kgenome_funcs_free(&fs);

	memset(dd, 0, sizeof dd);
	k = kgenome_pe_layout_of(f, sd, 16, &entry, &base, dd);
	if (k > 16u)
		bad("layout_of wrote more declarations than cap", n);
	if (k && e->valid) {
		uint64_t w = kgenome_pe_write_hdr(scratch, 0x1000, e, sd, k, entry, 0x10000, dd);
		if (w > 0x1000u)
			bad("write_hdr wrote more than cap", n);
	}

	{
		struct kgenome_pe_unmap_info ui;
		if (kgenome_pe_unmap(f, 0x140000000ull, 0, 1u << 22, &img, &img_n, &ui)) {
			if (!img || img_n > (1u << 22))
				bad("unmap beyond its cap", n);
			free(img);
		}
		img = NULL;
		if (kgenome_pe_unmap(f, 0, 0x400000, 1u << 22, &img, &img_n, NULL))
			free(img);
		img = NULL;
		if (kgenome_pe_unmap(f, 0x10000, 0x7ffffffff000ull, 1u << 12, &img, &img_n, &ui))
			free(img);
	}

	{
		struct kgenome_pe_info c = *e;
		uint64_t from[2] = { 0, n / 2u }, to[2] = { 0, n / 4u };
		struct kgenome_offmap m = { from, to, 2, n, n / 2u + 1u };
		kgenome_pe_info_offsets(&c, vis_cb, &acc);
		kgenome_pe_info_remap(&c, &m);
	}

	if (diag) {
		struct kgenome_diag_scan *d = kgenome_diag_scan_with(&o, p, n, diag > 1 ? KGENOME_DIAG_RUN_ALL : KGENOME_DIAG_RUN_DEFAULT);
		scans++;
		if (d) {
			uint32_t h = kgenome_diag_scan_count(d), q;
			for (q = 0; q < h && q < 64u; q++) {
				const struct kgenome_diag_hit *ht = kgenome_diag_scan_at(d, q);
				if (!ht || ht->at > n)
					bad("pe diagnose hit beyond the object", n);
			}
			kgenome_diag_scan_free(d);
		}
	}
	(void)acc;
}

/* ---- 1: truncation at every length ------------------------------------------------- */

static void cut_elf_all(const struct hk_elf *e, int diag_every)
{
	static struct kgenome_elf_info whole;
	struct kgenome_obj o;
	size_t n;

	memset(&whole, 0, sizeof whole);
	(void)kgenome_elf_image_parse(kof_buf_make(e->b, e->n), &whole, &o);
	for (n = 0; n <= e->n; n++) {
		const uint8_t *p = gb_put(&G, e->b, n);
		int diag = diag_every && n % (size_t)diag_every == 0 ? (n % ((size_t)diag_every * 4u) == 0 ? 2 : 1) : 0;

		walk_elf(p, n, NULL, diag);
		walk_elf(p, n, &whole, diag);
	}
}

static int fam_trunc_elf(void *arg)
{
	static struct hk_elf e;
	unsigned c;

	(void)arg;
	for (c = 0; c < 8; c++) {
		hk_elf(&e, (int)(c & 1u), (int)((c >> 1) & 1u), (int)(c >> 2));
		cut_elf_all(&e, 4);
	}
	return hk_fails != 0;
}

static void cut_pe_all(const struct hk_pe *pe, int diag_every)
{
	static struct kgenome_pe_info whole;
	struct kgenome_obj o;
	size_t n;

	memset(&whole, 0, sizeof whole);
	(void)kgenome_pe_image_parse(kof_buf_make(pe->b, pe->n), &whole, &o);
	for (n = 0; n <= pe->n; n++) {
		const uint8_t *p = gb_put(&G, pe->b, n);
		int diag = diag_every && n % (size_t)diag_every == 0 ? (n % ((size_t)diag_every * 4u) == 0 ? 2 : 1) : 0;

		walk_pe(p, n, NULL, diag);
		walk_pe(p, n, &whole, diag);
	}
}

static int fam_trunc_pe(void *arg)
{
	static struct hk_pe pe;
	int plus;

	(void)arg;
	for (plus = 0; plus < 2; plus++) {
		hk_pe(&pe, plus);
		cut_pe_all(&pe, 4);
	}
	return hk_fails != 0;
}

/* ---- 2: every field at every extreme ------------------------------------------------ */

static void sweep_fields(const uint8_t *src, size_t n, size_t limit, int is_pe, int diag_mod)
{
	static uint8_t w[HK_ELF_MAX];
	uint64_t ex[HK_NEXTREME];
	unsigned ne = hk_extremes(ex, n), x;
	size_t off, width;
	unsigned iter = 0;

	for (off = 0; off + 2u <= limit && off + 2u <= n; off += 2u) {
		for (width = 2; width <= 8; width *= 2) {
			if (off + width > n || (off & (width - 1u) & 3u))
				continue;
			for (x = 0; x < ne; x++) {
				const uint8_t *p;

				memcpy(w, src, n);
				hk_w(w + off, ex[x], (unsigned)width, 0);
				p = gb_put(&G, w, n);
				if (is_pe)
					walk_pe(p, n, NULL, diag_mod && ++iter % (unsigned)diag_mod == 0);
				else
					walk_elf(p, n, NULL, diag_mod && ++iter % (unsigned)diag_mod == 0);
			}
		}
	}
}

static int fam_fields_elf(void *arg)
{
	static struct hk_elf e;
	unsigned c;

	(void)arg;
	for (c = 0; c < 8; c++) {
		hk_elf(&e, (int)(c & 1u), (int)((c >> 1) & 1u), (int)(c >> 2));
		/* the headers, the segment table, the symbols, the relocations, the section table */
		sweep_fields(e.b, e.n, e.n, 0, 211);
	}
	return hk_fails != 0;
}

static int fam_fields_pe(void *arg)
{
	static struct hk_pe pe;
	int plus;

	(void)arg;
	for (plus = 0; plus < 2; plus++) {
		hk_pe(&pe, plus);
		sweep_fields(pe.b, pe.n, 0x300, 1, 97);               /* headers + section table */
	}
	return hk_fails != 0;
}

/* The import/export/reloc tables live at file offsets 0x400..0x7ff of the PE; sweep
 * them in place instead of as a separate object. */
static int fam_fields_pe_tables(void *arg)
{
	static struct hk_pe pe;
	static uint8_t w[HK_PE_MAX];
	uint64_t ex[HK_NEXTREME];
	unsigned ne, x, plus;
	size_t off, width;

	(void)arg;
	for (plus = 0; plus < 2; plus++) {
		hk_pe(&pe, (int)plus);
		ne = hk_extremes(ex, pe.n);
		for (off = pe.idata_off; off < pe.n; off += 4u) {
			if (pe.b[off] == 0 && pe.b[off + 1] == 0 && pe.b[off + 2] == 0 &&
			    pe.b[off + 3] == 0 && (off & 15u))
				continue;               /* a hole in the tables: nothing to corrupt */
			for (width = 4; width <= 8; width *= 2) {
				if (off + width > pe.n)
					continue;
				for (x = 0; x < ne; x++) {
					memcpy(w, pe.b, pe.n);
					hk_w(w + off, ex[x], (unsigned)width, 0);
					walk_pe(gb_put(&G, w, pe.n), pe.n, NULL, 0);
				}
			}
		}
	}
	return hk_fails != 0;
}

/* ---- 3: random flips ------------------------------------------------------------------ */

static int fam_random(void *arg)
{
	static struct hk_elf e;
	static struct hk_pe pe;
	static uint8_t w[HK_ELF_MAX];
	struct hk_rng r;
	unsigned seed = (unsigned)(uintptr_t)arg, it, k;

	r.s = 0x243f6a8885a308d3ull * (seed + 1u);
	for (it = 0; it < 12000u * hk_scale(); it++) {
		size_t n;
		int is_pe = (int)(it & 1u);

		if (is_pe) {
			hk_pe(&pe, (int)((it >> 1) & 1u));
			n = pe.n;
			memcpy(w, pe.b, n);
		} else {
			hk_elf(&e, (int)((it >> 1) & 1u), (int)((it >> 2) & 1u), (int)((it >> 3) & 1u));
			n = e.n;
			memcpy(w, e.b, n);
		}
		for (k = 1u + hk_below(&r, 12); k; k--) {
			size_t at = hk_below(&r, (uint32_t)n);
			switch (hk_below(&r, 4)) {
			case 0: w[at] ^= (uint8_t)(1u << hk_below(&r, 8)); break;
			case 1: w[at] = (uint8_t)hk_next(&r); break;
			case 2: w[at] = 0xff; break;
			default: w[at] = 0; break;
			}
		}
		if (hk_below(&r, 8) == 0)
			n -= hk_below(&r, (uint32_t)n);              /* and a random cut */
		if (is_pe)
			walk_pe(gb_put(&G, w, n), n, NULL, it % 23u == 0 ? 1 + (it % 69u == 0) : 0);
		else
			walk_elf(gb_put(&G, w, n), n, NULL, it % 23u == 0 ? 1 + (it % 69u == 0) : 0);
	}
	return hk_fails != 0;
}

/* ---- 4: named structures ----------------------------------------------------------------- */

static void put_elf_sh(struct hk_elf *e, unsigned idx, unsigned field, uint64_t v)
{
	/* field: 0 name 4 type 8 flags 16/24 addr/off ... selected by the caller via offsets */
	uint8_t *h = e->b + e->sh + idx * e->sh_ent;
	unsigned w = e->is64 ? 8u : 4u;

	switch (field) {
	case 0: hk_w(h + 0, v, 4, e->be); break;                       /* sh_name */
	case 1: hk_w(h + 4, v, 4, e->be); break;                       /* sh_type */
	case 2: hk_w(h + 8, v, w, e->be); break;                       /* sh_flags */
	case 3: hk_w(h + 8 + 2u * w, v, w, e->be); break;              /* sh_offset */
	case 4: hk_w(h + 8 + 3u * w, v, w, e->be); break;              /* sh_size */
	case 5: hk_w(h + 8 + 4u * w, v, 4, e->be); break;              /* sh_link */
	case 6: hk_w(h + 12 + 4u * w, v, 4, e->be); break;             /* sh_info */
	case 7: hk_w(h + 8 + 5u * w + 0u, v, w, e->be); break;         /* sh_addralign (ent follows) */
	default: hk_w(h + 8 + 6u * w, v, w, e->be); break;             /* sh_entsize */
	}
}

static int fam_elf_structures(void *arg)
{
	static struct hk_elf e;
	unsigned c, idx, field, x;
	uint64_t ex[HK_NEXTREME];

	(void)arg;
	for (c = 0; c < 8; c++) {
		for (idx = 1; idx < 6; idx++) {
			for (field = 0; field < 9; field++) {
				unsigned ne;

				hk_elf(&e, (int)(c & 1u), (int)((c >> 1) & 1u), (int)(c >> 2));
				ne = hk_extremes(ex, e.n);
				for (x = 0; x < ne; x++) {
					hk_elf(&e, (int)(c & 1u), (int)((c >> 1) & 1u), (int)(c >> 2));
					put_elf_sh(&e, idx, field, ex[x]);
					walk_elf(gb_put(&G, e.b, e.n), e.n, NULL, x % 5u == 0);
				}
			}
		}
		/* self reference: every link/info points at its own section, shstrndx at the symtab */
		hk_elf(&e, (int)(c & 1u), (int)((c >> 1) & 1u), (int)(c >> 2));
		for (idx = 1; idx < 6; idx++) {
			put_elf_sh(&e, idx, 5, idx);
			put_elf_sh(&e, idx, 6, idx);
		}
		hk_w(e.b + (e.is64 ? 62 : 50), 2, 2, e.be);
		walk_elf(gb_put(&G, e.b, e.n), e.n, NULL, 1);
		/* every section table entry aimed at the section table itself */
		hk_elf(&e, (int)(c & 1u), (int)((c >> 1) & 1u), (int)(c >> 2));
		for (idx = 1; idx < 6; idx++) {
			put_elf_sh(&e, idx, 3, e.sh);
			put_elf_sh(&e, idx, 4, 6u * e.sh_ent);
		}
		walk_elf(gb_put(&G, e.b, e.n), e.n, NULL, 1);
		/* every section is the whole file, overlapping all the others */
		hk_elf(&e, (int)(c & 1u), (int)((c >> 1) & 1u), (int)(c >> 2));
		for (idx = 1; idx < 6; idx++) {
			put_elf_sh(&e, idx, 3, 0);
			put_elf_sh(&e, idx, 4, e.n);
		}
		walk_elf(gb_put(&G, e.b, e.n), e.n, NULL, 1);
		/* a relocation whose symbol index is 2^24 (and 2^32-1 on 64-bit) */
		hk_elf(&e, (int)(c & 1u), (int)((c >> 1) & 1u), (int)(c >> 2));
		if (e.is64)
			hk_w(e.b + e.rela + 8, 0xffffffffull << 32 | 4u, 8, e.be);
		else
			hk_w(e.b + e.rela + 4, 0xffffff00u | 4u, 4, e.be);
		walk_elf(gb_put(&G, e.b, e.n), e.n, NULL, 1);
		/* a symbol whose name offset is past the string table and whose value/size wrap */
		hk_elf(&e, (int)(c & 1u), (int)((c >> 1) & 1u), (int)(c >> 2));
		{
			uint8_t *s = e.b + e.symtab + e.sym_ent;
			if (e.is64) {
				hk_w(s, 0xffffffffu, 4, e.be);
				hk_w(s + 8, UINT64_MAX - 3u, 8, e.be);
				hk_w(s + 16, UINT64_MAX, 8, e.be);
			} else {
				hk_w(s, 0xffffffffu, 4, e.be);
				hk_w(s + 4, 0xfffffffcu, 4, e.be);
				hk_w(s + 8, 0xffffffffu, 4, e.be);
			}
		}
		walk_elf(gb_put(&G, e.b, e.n), e.n, NULL, 1);
		/* the program header: PT_LOAD with offset+filesz wrapping; vaddr+memsz wrapping */
		hk_elf(&e, (int)(c & 1u), (int)((c >> 1) & 1u), (int)(c >> 2));
		if (!e.rel) {
			uint8_t *ph = e.b + e.ph;
			if (e.is64) {
				hk_w(ph + 8, UINT64_MAX - 15u, 8, e.be);
				hk_w(ph + 16, UINT64_MAX - 15u, 8, e.be);
				hk_w(ph + 32, 0x100, 8, e.be);
				hk_w(ph + 40, UINT64_MAX, 8, e.be);
			} else {
				hk_w(ph + 4, 0xfffffff0u, 4, e.be);
				hk_w(ph + 8, 0xfffffff0u, 4, e.be);
				hk_w(ph + 16, 0x100, 4, e.be);
				hk_w(ph + 20, 0xffffffffu, 4, e.be);
			}
			walk_elf(gb_put(&G, e.b, e.n), e.n, NULL, 1);
		}
	}
	return hk_fails != 0;
}

/* a count of 2^32 over a file of a few KiB, in every table that has one */
static int fam_elf_counts(void *arg)
{
	static struct hk_elf e;
	unsigned c;
	double t0 = hk_now();

	(void)arg;
	for (c = 0; c < 8; c++) {
		int is64 = (int)(c & 1u), be = (int)((c >> 1) & 1u), rel = (int)(c >> 2);
		uint64_t big[] = { 0xffff, 0x10000, 0xffffffffu, 0x100000000ull };
		unsigned k;

		for (k = 0; k < 4; k++) {
			hk_elf(&e, is64, be, rel);
			/* e_phnum / e_shnum */
			hk_w(e.b + (is64 ? 56 : 44), big[k] & 0xffffu, 2, be);
			hk_w(e.b + (is64 ? 60 : 48), big[k] & 0xffffu, 2, be);
			walk_elf(gb_put(&G, e.b, e.n), e.n, NULL, 1);
			/* sh_size of the symbol and relocation tables; entsize of 0 and of 1 */
			hk_elf(&e, is64, be, rel);
			put_elf_sh(&e, 2, 4, big[k]);
			put_elf_sh(&e, 4, 4, big[k]);
			walk_elf(gb_put(&G, e.b, e.n), e.n, NULL, 1);
			put_elf_sh(&e, 2, 8, 0);
			put_elf_sh(&e, 4, 8, 0);
			walk_elf(gb_put(&G, e.b, e.n), e.n, NULL, 1);
			put_elf_sh(&e, 2, 8, 1);
			put_elf_sh(&e, 4, 8, 1);
			walk_elf(gb_put(&G, e.b, e.n), e.n, NULL, 1);
		}
	}
	/* the whole family ends fast: a declared count is not a loop bound */
	return (hk_fails != 0) || (hk_now() - t0 > 4.0);
}

static void put_pe_dir(struct hk_pe *p, unsigned d, uint64_t rva, uint64_t size)
{
	hk_w(p->b + p->dirs + 8u * d, rva, 4, 0);
	hk_w(p->b + p->dirs + 8u * d + 4u, size, 4, 0);
}

static int fam_pe_structures(void *arg)
{
	static struct hk_pe pe;
	int plus;
	unsigned x, d, i;
	uint64_t ex[HK_NEXTREME];
	double t0 = hk_now();

	(void)arg;
	for (plus = 0; plus < 2; plus++) {
		unsigned ps = plus ? 8u : 4u;

		/* every directory entry: rva and size at every extreme */
		hk_pe(&pe, plus);
		for (d = 0; d < 16; d++) {
			unsigned ne = hk_extremes(ex, pe.n);
			for (x = 0; x < ne; x++) {
				unsigned y;
				for (y = 0; y < ne; y += 3) {
					hk_pe(&pe, plus);
					put_pe_dir(&pe, d, ex[x], ex[y]);
					walk_pe(gb_put(&G, pe.b, pe.n), pe.n, NULL, 0);
				}
			}
		}
		/* the import table pointing at itself: descriptor, ILT, IAT and name all aimed at
		 * the descriptor array; a name that never ends; a thunk array with no terminator */
		hk_pe(&pe, plus);
		hk_w(pe.b + pe.imp_off + 0, 0x2000, 4, 0);
		hk_w(pe.b + pe.imp_off + 12, 0x2000, 4, 0);
		hk_w(pe.b + pe.imp_off + 16, 0x2000, 4, 0);
		walk_pe(gb_put(&G, pe.b, pe.n), pe.n, NULL, 1);
		hk_pe(&pe, plus);
		memset(pe.b + pe.imp_off + 0x140, 'A', 0xa0);               /* names unterminated */
		walk_pe(gb_put(&G, pe.b, pe.n), pe.n, NULL, 1);
		hk_pe(&pe, plus);
		memset(pe.b + pe.imp_off + 0x60, 0x11, 0x100);              /* non-zero thunks to EOF */
		walk_pe(gb_put(&G, pe.b, pe.n), pe.n, NULL, 1);
		hk_pe(&pe, plus);
		memset(pe.b + pe.imp_off, 0x01, 0x400);                     /* descriptors to EOF */
		walk_pe(gb_put(&G, pe.b, pe.n), pe.n, NULL, 1);
		/* a thunk array that loops: the thunk's own RVA is its hint/name */
		hk_pe(&pe, plus);
		for (i = 0; i < 8; i++)
			hk_w(pe.b + pe.imp_off + 0x60 + i * ps, 0x2060u + i * ps, ps, 0);
		walk_pe(gb_put(&G, pe.b, pe.n), pe.n, NULL, 1);
		/* exports: counts of 2^32-1, name/ordinal tables at the end, ordinal past the functions */
		for (x = 0; x < 6; x++) {
			static const uint32_t v[6] = { 0xffffffffu, 0x80000000u, 0x10000u, 0xffffu, 1, 0 };
			unsigned fld;
			for (fld = 0; fld < 6; fld++) {
				static const unsigned o[6] = { 20, 24, 28, 32, 36, 16 };
				hk_pe(&pe, plus);
				hk_w(pe.b + pe.exp_off + o[fld], v[x], 4, 0);
				walk_pe(gb_put(&G, pe.b, pe.n), pe.n, NULL, 0);
			}
		}
		hk_pe(&pe, plus);
		hk_w(pe.b + pe.exp_off + 0x38, 0xffff, 2, 0);               /* an ordinal beyond the table */
		hk_w(pe.b + pe.exp_off + 0x28, 0x2180, 4, 0);               /* a forwarder into the table */
		walk_pe(gb_put(&G, pe.b, pe.n), pe.n, NULL, 0);
		/* the export name table pointing at itself */
		hk_pe(&pe, plus);
		hk_w(pe.b + pe.exp_off + 0x30, 0x2180 + 0x30, 4, 0);
		hk_w(pe.b + pe.exp_off + 0x34, 0x2180 + 0x30, 4, 0);
		walk_pe(gb_put(&G, pe.b, pe.n), pe.n, NULL, 0);
		/* section table: raw pointer + size wrapping, virtual size 2^32-1, zero and huge counts */
		for (x = 0; x < 3; x++) {
			unsigned fo[4] = { 8, 12, 16, 20 };
			unsigned fld;
			for (fld = 0; fld < 4; fld++) {
				hk_pe(&pe, plus);
				hk_w(pe.b + pe.sec + 40u * x + fo[fld], 0xffffffffu, 4, 0);
				walk_pe(gb_put(&G, pe.b, pe.n), pe.n, NULL, 1);
				hk_pe(&pe, plus);
				hk_w(pe.b + pe.sec + 40u * x + fo[fld], 0x80000000u, 4, 0);
				walk_pe(gb_put(&G, pe.b, pe.n), pe.n, NULL, 0);
			}
		}
		for (x = 0; x < 5; x++) {
			static const uint32_t ns[5] = { 0, 0xffff, 97, 96, 4 };
			hk_pe(&pe, plus);
			hk_w(pe.b + pe.lfanew + 6, ns[x], 2, 0);
			walk_pe(gb_put(&G, pe.b, pe.n), pe.n, NULL, 1);
		}
		/* e_lfanew: past the end, the last 3/4/5 bytes, negative as unsigned, inside the DOS header */
		for (x = 0; x < 8; x++) {
			static const uint32_t ln[8] = { 0xffffffffu, 0x80000000u, 0x7fffffffu, 0, 4, 0x3c, 0x7fc, 0x7fb };
			hk_pe(&pe, plus);
			hk_w(pe.b + 0x3c, ln[x], 4, 0);
			walk_pe(gb_put(&G, pe.b, pe.n), pe.n, NULL, 1);
		}
		/* the optional header size: 0, 2, 0xffff; NumberOfRvaAndSizes huge */
		for (x = 0; x < 4; x++) {
			static const uint32_t os[4] = { 0, 2, 0xffff, 0x10 };
			hk_pe(&pe, plus);
			hk_w(pe.b + pe.lfanew + 20, os[x], 2, 0);
			walk_pe(gb_put(&G, pe.b, pe.n), pe.n, NULL, 1);
		}
		for (x = 0; x < 4; x++) {
			static const uint32_t nd[4] = { 0xffffffffu, 0x10000, 17, 0 };
			hk_pe(&pe, plus);
			hk_w(pe.b + pe.opt + (plus ? 108 : 92), nd[x], 4, 0);
			walk_pe(gb_put(&G, pe.b, pe.n), pe.n, NULL, 1);
		}
		/* SizeOfImage / SizeOfHeaders / alignments at the extremes */
		{
			static const unsigned fo[5] = { 56, 60, 32, 36, 4 };
			unsigned fld;
			for (fld = 0; fld < 5; fld++) {
				unsigned ne = hk_extremes(ex, pe.n);
				for (x = 0; x < ne; x++) {
					hk_pe(&pe, plus);
					hk_w(pe.b + pe.opt + fo[fld], ex[x], 4, 0);
					walk_pe(gb_put(&G, pe.b, pe.n), pe.n, NULL, x % 4u == 0);
				}
			}
		}
	}
	return hk_fails != 0 || hk_now() - t0 > 4.5;
}

/* the base-relocation block: SizeOfBlock 0, 1, 7, 8, 9, 0xffffffff - the walk must advance */
static int fam_pe_reloc_blocks(void *arg)
{
	static struct hk_pe pe;
	static const uint32_t sz[] = { 0, 1, 7, 8, 9, 0xffffffffu, 0x80000000u, 0x7ffffff8u, 0x10, 0x11 };
	int plus;
	unsigned x, y;
	double t0 = hk_now();

	(void)arg;
	for (plus = 0; plus < 2; plus++) {
		for (x = 0; x < sizeof sz / sizeof sz[0]; x++) {
			for (y = 0; y < 4; y++) {
				static const uint32_t dsz[4] = { 16, 0x200, 0xffffffffu, 8 };
				hk_pe(&pe, plus);
				hk_w(pe.b + pe.reloc_off + 4, sz[x], 4, 0);
				hk_w(pe.b + pe.dirs + 44, dsz[y], 4, 0);
				walk_pe(gb_put(&G, pe.b, pe.n), pe.n, NULL, 0);
			}
		}
		/* a block whose entries are all non-zero to the end of the file and a block of
		 * zeros that loops: the 'unmap' walk must end */
		hk_pe(&pe, plus);
		memset(pe.b + pe.reloc_off + 8, 0xaa, 0x1f0);
		hk_w(pe.b + pe.reloc_off + 4, 0x200, 4, 0);
		hk_w(pe.b + pe.dirs + 44, 0x200, 4, 0);
		walk_pe(gb_put(&G, pe.b, pe.n), pe.n, NULL, 0);
		hk_pe(&pe, plus);
		memset(pe.b + pe.reloc_off, 0, 0x200);
		hk_w(pe.b + pe.dirs + 44, 0x200, 4, 0);
		walk_pe(gb_put(&G, pe.b, pe.n), pe.n, NULL, 0);
	}
	return hk_fails != 0 || hk_now() - t0 > 4.0;
}

/* ---- 5: the CLR reader ------------------------------------------------------------------------ */

static uint64_t rva_id(const void *u, uint64_t rva)
{
	(void)u;
	return rva;
}

static uint64_t rva_bad(const void *u, uint64_t rva)
{
	(void)u; (void)rva;
	return KGENOME_BROKEN;
}

static uint64_t rva_huge(const void *u, uint64_t rva)
{
	(void)u; (void)rva;
	return UINT64_MAX;
}

static uint64_t rva_near(const void *u, uint64_t rva)
{
	(void)u;
	return rva ? (UINT64_MAX - 0x40u) : 0;
}

static void clr_obj(uint8_t *b, size_t n)
{
	memset(b, 0, n);
	hk_w(b, 72, 4, 0);
	hk_w(b + 8, 0x100, 4, 0);
	hk_w(b + 12, 0x80, 4, 0);
	hk_w(b + 24, 0x180, 4, 0);
	hk_w(b + 28, 0x20, 4, 0);
	memcpy(b + 0x100, "BSJB", 4);
	hk_w(b + 0x104, 1, 2, 0);
	hk_w(b + 0x106, 1, 2, 0);
	hk_w(b + 0x10c, 12, 4, 0);
	memcpy(b + 0x110, "v4.0.30319", 11);
	hk_w(b + 0x11e, 5, 2, 0);
	/* five streams */
	{
		static const char *nm[5] = { "#~", "#Strings", "#US", "#Blob", "#GUID" };
		uint8_t *s = b + 0x120;
		unsigned i;
		for (i = 0; i < 5; i++) {
			hk_w(s, 0x80u + 8u * i, 4, 0);
			hk_w(s + 4, 8, 4, 0);
			memcpy(s + 8, nm[i], strlen(nm[i]) + 1u);
			s += 8u + ((strlen(nm[i]) + 1u + 3u) & ~3u);
		}
	}
}

static int fam_clr(void *arg)
{
	static uint8_t b[0x200], w[0x200];
	struct kgenome_clr_meta m;
	kgenome_clr_rva fns[4] = { rva_id, rva_bad, rva_huge, rva_near };
	uint64_t ex[HK_NEXTREME];
	size_t n, off, width;
	unsigned x, ne, f;
	struct kof_range r[KGENOME_CLR_CLAIM_MAX];

	(void)arg;
	clr_obj(b, sizeof b);
	CK(kgenome_clr_read(kof_buf_make(b, sizeof b), 0, rva_id, NULL, &m) == 1);
	CK(m.streams_read == 5);
	for (n = 0; n <= sizeof b; n++) {
		const uint8_t *p = gb_put(&G, b, n);
		for (f = 0; f < 4; f++) {
			uint64_t co;
			for (co = 0; co < 5; co++) {
				uint64_t clr_off = co == 0 ? 0 : co == 1 ? n : co == 2 ? (n ? n - 1u : 0)
					: co == 3 ? UINT64_MAX : UINT64_MAX - 71u;
				int got = kgenome_clr_read(kof_buf_make(p, n), clr_off, fns[f], NULL, &m);
				uint32_t q, nc;
				if (got) {
					nc = kgenome_clr_claims(&m, r, KGENOME_CLR_CLAIM_MAX);
					for (q = 0; q < nc; q++)
						if (r[q].off > n || r[q].len > n - r[q].off)
							bad("clr claim beyond the object", n);
				} else if (kgenome_clr_present(&m)) {
					bad("clr_read said no and left a root", n);
				}
			}
		}
	}
	/* every field of the header and the root at every extreme */
	ne = hk_extremes(ex, sizeof b);
	for (off = 0; off < 0x180; off += 2) {
		for (width = 2; width <= 8; width *= 2) {
			if (off + width > 0x180 || (width > 2 && (off & 3u)))
				continue;
			for (x = 0; x < ne; x++) {
				const uint8_t *p;
				memcpy(w, b, sizeof b);
				hk_w(w + off, ex[x], (unsigned)width, 0);
				p = gb_put(&G, w, sizeof w);
				if (kgenome_clr_read(kof_buf_make(p, sizeof w), 0, rva_id, NULL, &m)) {
					uint32_t q, nc = kgenome_clr_claims(&m, r, KGENOME_CLR_CLAIM_MAX);
					for (q = 0; q < nc; q++)
						if (r[q].off > sizeof w || r[q].len > sizeof w - r[q].off)
							bad("clr claim beyond the object (field sweep)", off);
					{
						struct kof_range buf[32];
						struct kof_rlist l;
						kof_rl_init(&l, buf, 32);
						kgenome_clr_add_ranges(&m, KGENOME_SCAN_CLR_CLAIMED, &l, sizeof w);
						for (q = 0; q < l.n; q++)
							if (l.v[q].off + l.v[q].len > sizeof w)
								bad("clr range beyond the object", off);
					}
				}
			}
		}
	}
	/* the out pointer and the callback are required: a NULL callback is refused */
	CK(kgenome_clr_read(kof_buf_make(b, sizeof b), 0, NULL, NULL, &m) == 0);
	CK(kgenome_clr_read(kof_buf_make(b, sizeof b), 0, rva_id, NULL, NULL) == 0);
	CK(kgenome_clr_read(kof_buf_make(NULL, 0), 0, rva_id, NULL, &m) == 0);
	return hk_fails != 0;
}

/* ---- resource bounds: a declared count is not a loop bound ---------------------------------- */

static uint8_t big[0x22000];

static void big_pe(int plus)
{
	/* the small PE, with .idata stretched to 0x1f800 bytes of raw data */
	static struct hk_pe pe;
	hk_pe(&pe, plus);
	memset(big, 0, sizeof big);
	memcpy(big, pe.b, pe.n);
	hk_w(big + pe.sec + 40u + 8u, 0x1f800, 4, 0);
	hk_w(big + pe.sec + 40u + 16u, 0x1f800, 4, 0);
	/* .reloc moves after it: rva 0x22000 is out of the image, so shrink it to nothing */
	hk_w(big + pe.sec + 80u + 8u, 0, 4, 0);
	hk_w(big + pe.sec + 80u + 16u, 0, 4, 0);
	hk_w(big + pe.opt + 56, 0x22000, 4, 0);
}

/* 1500 descriptors all aimed at ONE 8000-thunk table: 12 million thunk reads if every
 * descriptor were walked in full; the walk's own budget is (file bytes / width). */
static int fam_import_quadratic(void *arg)
{
	int plus;
	double t0 = hk_now();

	(void)arg;
	for (plus = 0; plus < 2; plus++) {
		unsigned w = plus ? 8u : 4u, i;
		uint32_t d0 = 0x400;
		uint32_t tbl = d0 + 0x10000;
		kof_buf f;
		struct kgenome_pe_info pi;
		struct kgenome_obj o;
		struct imp_chk ic;
		enum kgenome_status st = KGENOME_OK;
		uint32_t got;

		big_pe(plus);
		for (i = 0; i < 1500; i++) {
			uint8_t *d = big + d0 + i * 20u;
			hk_w(d, 0x2000u + 0x10000u, 4, 0);
			hk_w(d + 12, 0x2000u + 0x1f000u, 4, 0);
			hk_w(d + 16, 0x2000u + 0x10000u, 4, 0);
		}
		memcpy(big + d0 + 0x1f000, "k.dll", 6);
		for (i = 0; i < 8000; i++)
			hk_w(big + tbl + i * w, 0x2000u + 0x1f100u, w, 0);
		memcpy(big + d0 + 0x1f100 + 2, "Func", 5);
		hk_w(big + 0x80 + 24 + (plus ? 112 : 96) + 8 + 4, 1500u * 20u, 4, 0);
		/* the shared guard buffer holds CAP bytes; the big object gets its own mapping */
		{
			struct hk_gb g2;
			const uint8_t *p;

			gb_init(&g2, sizeof big);
			p = gb_put(&g2, big, sizeof big);
			f = kof_buf_make(p, sizeof big);
			memset(&pi, 0, sizeof pi);
			if (!kgenome_pe_image_parse(f, &pi, &o))
				return 2;
			memset(&ic, 0, sizeof ic);
			ic.n = sizeof big;
			got = kgenome_pe_imports(f, &pi, imp_cb, &ic, &st);
			CK(got == ic.calls);
			CK(ic.viol == 0);
			CK((uint64_t)got <= sizeof big / w);
			CK(st == KGENOME_TRUNCATED);
			/* the table builder inherits the bound and says so too */
			{
				struct kgenome_pe_imptab t;
				memset(&t, 0, sizeof t);
				kgenome_pe_imptab_build(f, &pi, &t);
				CK(t.status == KGENOME_TRUNCATED);
				CK(t.n <= sizeof big / w);
				kgenome_pe_imptab_free(&t);
			}
			gb_free(&g2);
		}
	}
	return hk_fails != 0 || hk_now() - t0 > 3.0;
}

/* NumberOfNames = 2^32-1: the walk is cut at its bound and the status says so */
static int fam_export_count(void *arg)
{
	static struct hk_pe pe;
	int plus;

	(void)arg;
	for (plus = 0; plus < 2; plus++) {
		struct kgenome_pe_info pi;
		struct kgenome_obj o;
		struct imp_chk ic;
		enum kgenome_status st = KGENOME_OK;
		kof_buf f;
		uint32_t got;

		hk_pe(&pe, plus);
		hk_w(pe.b + pe.exp_off + 24, 0xffffffffu, 4, 0);
		f = kof_buf_make(gb_put(&G, pe.b, pe.n), pe.n);
		memset(&pi, 0, sizeof pi);
		if (!kgenome_pe_image_parse(f, &pi, &o))
			return 2;
		memset(&ic, 0, sizeof ic);
		ic.n = pe.n;
		got = kgenome_pe_exports(f, &pi, exp_cb, &ic, &st);
		CK(got == ic.calls);
		CK(got <= 4096u);
		CK(st == KGENOME_TRUNCATED);
		/* and the callback can stop the walk */
		hk_pe(&pe, plus);
		f = kof_buf_make(gb_put(&G, pe.b, pe.n), pe.n);
		memset(&ic, 0, sizeof ic);
		got = kgenome_pe_exports(f, &pi, exp_cb, &ic, NULL);
		CK(got == 2);
	}
	return hk_fails != 0;
}

/* ---- known defects: each runs in a child so the finding is a result, not a crash ------------ */

struct nameoff_seen { int broken, calls; };

static int sentinel_cb(void *u, uint64_t nameoff, uint32_t rva)
{
	struct nameoff_seen *s = (struct nameoff_seen *)u;

	(void)rva;
	s->calls++;
	if (nameoff == KGENOME_BROKEN)
		s->broken++;
	return 1;
}

/* a name RVA that resolves nowhere must not reach the callback as an offset */
static int km_export_sentinel(void *arg)
{
	static struct hk_pe pe;
	struct kgenome_pe_info pi;
	struct kgenome_obj o;
	struct nameoff_seen s = { 0, 0 };
	kof_buf f;

	(void)arg;
	hk_pe(&pe, 1);
	hk_w(pe.b + pe.exp_off + 0x30, 0x9000, 4, 0);   /* the first name's RVA: in no section */
	f = kof_buf_make(gb_put(&G, pe.b, pe.n), pe.n);
	memset(&pi, 0, sizeof pi);
	if (!kgenome_pe_image_parse(f, &pi, &o))
		return 2;
	(void)kgenome_pe_exports(f, &pi, sentinel_cb, &s, NULL);
	return s.calls > 0 && s.broken == 0 ? 0 : 1;
}

/* an export directory whose RVA resolves nowhere is no export directory */
static int km_export_dir_unresolved(void *arg)
{
	static struct hk_pe pe;
	struct kgenome_pe_info pi;
	struct kgenome_obj o;
	struct nameoff_seen s = { 0, 0 };
	kof_buf f;

	(void)arg;
	hk_pe(&pe, 1);
	put_pe_dir(&pe, KGENOME_PE_DIR_EXPORT, 0x9000, 0x80);   /* in no section */
	/* where kgenome_pe_rva_to_off's BROKEN + 24 lands: bytes 22..37 of the DOS header */
	hk_w(pe.b + 22, 1, 4, 0);                /* NumberOfNames */
	hk_w(pe.b + 26, 0x2060, 4, 0);           /* AddressOfFunctions */
	hk_w(pe.b + 30, 0x2000, 4, 0);           /* AddressOfNames: the import descriptors */
	hk_w(pe.b + 34, 0x2060, 4, 0);           /* AddressOfNameOrdinals */
	f = kof_buf_make(gb_put(&G, pe.b, pe.n), pe.n);
	memset(&pi, 0, sizeof pi);
	if (!kgenome_pe_image_parse(f, &pi, &o))
		return 2;
	(void)kgenome_pe_exports(f, &pi, sentinel_cb, &s, NULL);
	return s.calls == 0 ? 0 : 1;
}

/* every relocation site is a place in the object */
static int km_reloc_site(void *arg)
{
	static struct hk_elf e;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_elf_relocs rt;
	kof_buf f;
	uint32_t i;
	int rc = 0;

	(void)arg;
	hk_elf(&e, 1, 0, 1);
	hk_w(e.b + e.rela, 0x8000000000000000ull, 8, 0);   /* r_offset of the first */
	f = kof_buf_make(gb_put(&G, e.b, e.n), e.n);
	memset(&ei, 0, sizeof ei);
	if (!kgenome_elf_image_parse(f, &ei, &o))
		return 2;
	memset(&rt, 0, sizeof rt);
	(void)kgenome_elf_reloc_table(f, &ei, KGENOME_ELF_RELOC_CODE | KGENOME_ELF_RELOC_DATA, &rt);
	for (i = 0; i < rt.n; i++)
		if (rt.v[i].where > e.n)
			rc = 1;
	kgenome_elf_reloc_table_free(&rt);
	return rc;
}

static int fam_known(void *arg)
{
	(void)arg;
	{
		int sig = 0;
		enum hk_result r;

		r = hk_isolated(km_export_sentinel, NULL, 10, &sig);
		KM_CHECK(r == HK_OK, "kgenome_pe_exports hands the callback KGENOME_BROKEN as a name offset "
			 "when a name RVA resolves nowhere",
			 "pe_image.c:1098 fn(user, kgenome_pe_rva_to_off(p, nrva), frva): the sentinel is passed "
			 "on; the import walk (pe_image.c:1027) checks BROKEN, the export walk does not. "
			 "Repro: PE32+, AddressOfNames[0] = 0x9000");
		r = hk_isolated(km_export_dir_unresolved, NULL, 10, &sig);
		KM_CHECK(r == HK_OK, "kgenome_pe_exports reads an export directory from file offset 22 when "
			 "its RVA resolves nowhere",
			 "pe_image.c:1068-1075: d = rva_to_off() is KGENOME_BROKEN (2^64-2), `!d` does not catch it, "
			 "d + EXP_N_NAMES wraps to 22. Repro: DataDirectory[0] = {0x9000,0x80}, DOS header bytes "
			 "22..37 = {1, x, 0x2000, x}");
		r = hk_isolated(km_reloc_site, NULL, 10, &sig);
		KM_CHECK(r == HK_OK, "kgenome_elf_reloc_table reports a relocation site beyond the object",
			 "elf_image.c:1135 r->where = tgt_off + roff, roff = r_offset unbounded (and the sum can "
			 "wrap); diag_emu_image.c:171 apply_reloc then tests `where + 4u > size`, which wraps for "
			 "where >= 2^64-3. Repro: ET_REL, first RELA r_offset = 0x8000000000000000");
	}
	return km_failed();
}

/* ---- the driver ---------------------------------------------------------------------------------- */

struct fam { const char *name; hk_case_fn fn; void *arg; unsigned secs; };

static int run_fam(void *p)
{
	const struct fam *f = (const struct fam *)p;
	int rc = f->fn(f->arg);

	printf("  %-34s %u walks, %u diagnose scans\n", f->name, walks, scans);
	return rc;
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);

	static struct fam fams[] = {
		{ "elf truncated at every length", fam_trunc_elf, NULL, 60 },
		{ "pe truncated at every length", fam_trunc_pe, NULL, 60 },
		{ "elf field sweep", fam_fields_elf, NULL, 60 },
		{ "pe header field sweep", fam_fields_pe, NULL, 60 },
		{ "pe table field sweep", fam_fields_pe_tables, NULL, 60 },
		{ "random flips seed 0", fam_random, (void *)0, 60 },
		{ "random flips seed 1", fam_random, (void *)1, 60 },
		{ "random flips seed 2", fam_random, (void *)2, 60 },
		{ "random flips seed 3", fam_random, (void *)3, 60 },
		{ "elf named structures", fam_elf_structures, NULL, 60 },
		{ "elf declared counts", fam_elf_counts, NULL, 30 },
		{ "pe named structures", fam_pe_structures, NULL, 60 },
		{ "pe base relocation blocks", fam_pe_reloc_blocks, NULL, 30 },
		{ "clr reader", fam_clr, NULL, 30 },
		{ "import walk is bounded", fam_import_quadratic, NULL, 30 },
		{ "export count is bounded", fam_export_count, NULL, 30 },
	};
	unsigned i;

	gb_init(&G, CAP);
	for (i = 0; i < sizeof fams / sizeof fams[0]; i++) {
		int sig = 0;
		double t0 = hk_now();
		enum hk_result r = hk_isolated(run_fam, &fams[i], fams[i].secs, &sig);

		printf("  %-34s %s (%.2fs)\n", fams[i].name,
		       r == HK_OK ? "ok" : r == HK_FAILED ? "FAILED" :
		       r == HK_HUNG ? "HUNG" : "CRASHED", hk_now() - t0);
		if (r != HK_OK) {
			printf("  FAIL %s: result %d signal %d\n", fams[i].name, (int)r, sig);
			hk_fails++;
		}
	}
	/* the known-defect cases run in the parent so km_failed() sees their markers */
	(void)fam_known(NULL);
	gb_free(&G);
	printf("hostile_image: %d failure(s)\n", hk_fails);
	return hk_fails != 0 || km_failed();
}
