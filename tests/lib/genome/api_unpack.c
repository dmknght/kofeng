/*
 * api_unpack - the unpacking run's entry points that no test named
 * (kgenome_emu_unp_build, kgenome_emu_unp_pe_image) and the ones they sit beside
 * (the gates, the ELF and PE runs), against the contract and against hostile
 * objects.
 *
 * What is asserted is what a caller depends on: a refusal is NULL and leaves the
 * report zeroed; a built image is the file mapped where its headers say, started
 * at its entry, and still unrun; the instruction and page ceilings are the
 * caller's budget; a rebuilt PE parses as a PE and never exceeds its cap. Then
 * the same entry points over every length of an ELF and a PE and over the fields
 * of their headers set to the extremes: whatever the file declares, the guest
 * ends inside its budget and the host does not fault.
 */

#include <kgenome.h>

#include "hk.h"
#include "../../unit/known_miss.h"

static struct hk_gb G;

/* ---- the ELF image -------------------------------------------------------------------------------- */

/* xor edi,edi ; mov eax,60 ; syscall    (exit(0)) - written over the .text of the builder's object */
static void put_exit_stub(struct hk_elf *e)
{
	static const uint8_t code[] = { 0x31, 0xff, 0xb8, 0x3c, 0, 0, 0, 0x0f, 0x05 };

	memcpy(e->b + e->text, code, sizeof code);
}

static void t_elf_build(void)
{
	static struct hk_elf e;
	static struct kgenome_elf_info info;
	struct kgenome_obj o;
	struct kgenome_emu_unp_report rep;
	struct kgenome_budget bud;
	struct kgenome_emu *em;
	kof_buf f;

	hk_elf(&e, 1, 0, 0);
	put_exit_stub(&e);
	f = kof_buf_make(e.b, e.n);
	memset(&info, 0, sizeof info);
	CK(kgenome_elf_image_parse(f, &info, &o));
	kgenome_budget_default(&bud, e.n, e.n);

	/* build: the file mapped where it says, started at its entry, not run */
	memset(&rep, 0xaa, sizeof rep);
	em = kgenome_emu_unp_build(e.b, e.n, &info, &bud, &rep);
	CK(em != NULL);
	CK(rep.entry == 0x400000u + e.text && rep.improvised == 0);
	CK(kgenome_emu_rip(em) == 0x400000u + e.text);
	CK(kgenome_emu_insn_count(em) == 0);
	CK(kgenome_emu_get_reg(em, KGENOME_EMU_RSP) != 0);                  /* a stack was made */
	{
		uint8_t b[4] = { 0 };
		CK(kgenome_emu_read(em, 0x400000, b, 4) == 1 && !memcmp(b, "\x7f" "ELF", 4));   /* the headers are mapped */
		CK(kgenome_emu_read(em, rep.entry, b, 2) == 1 && b[0] == 0x31 && b[1] == 0xff);
	}
	CK(kgenome_emu_run(em) == KGENOME_EMU_STOP_EXIT);
	kgenome_emu_free(em);

	/* a run is the same build plus the run and the harvest */
	memset(&rep, 0xaa, sizeof rep);
	em = kgenome_emu_unp_run(e.b, e.n, &info, &bud, &rep);
	CK(em != NULL && rep.stop == KGENOME_EMU_STOP_EXIT && rep.insn >= 3 && rep.entry == 0x400000u + e.text);
	CK(rep.detail != NULL);
	kgenome_emu_free(em);

	/* the ceilings are the caller's: one instruction, then BUDGET */
	bud.max_insn = 1;
	em = kgenome_emu_unp_run(e.b, e.n, &info, &bud, &rep);
	CK(em != NULL && rep.stop == KGENOME_EMU_STOP_BUDGET && rep.insn == 1);
	kgenome_emu_free(em);
	/* zero means the default, and a NULL budget is every default */
	bud.max_insn = 0;
	bud.max_bytes = 0;
	em = kgenome_emu_unp_run(e.b, e.n, &info, &bud, &rep);
	CK(em != NULL && rep.stop == KGENOME_EMU_STOP_EXIT);
	kgenome_emu_free(em);
	em = kgenome_emu_unp_run(e.b, e.n, &info, NULL, NULL);
	CK(em != NULL);
	kgenome_emu_free(em);
	/* the page ceiling arithmetic does not wrap: max_bytes near 2^64 is still a run */
	kgenome_budget_default(&bud, e.n, e.n);
	bud.max_bytes = UINT64_MAX;
	em = kgenome_emu_unp_run(e.b, e.n, &info, &bud, &rep);
	CK(em != NULL && rep.stop == KGENOME_EMU_STOP_EXIT);
	kgenome_emu_free(em);
	bud.max_bytes = UINT64_MAX - 4094u;                    /* + 4095 wraps to 0 */
	em = kgenome_emu_unp_run(e.b, e.n, &info, &bud, &rep);
	CK(em != NULL);
	kgenome_emu_free(em);
	bud.max_bytes = 1;
	em = kgenome_emu_unp_run(e.b, e.n, &info, &bud, &rep);          /* one page: the load may not fit; no fault */
	kgenome_emu_free(em);

	/* the refusals: NULL, no file, an invalid parse - and the report is zeroed */
	memset(&rep, 0xaa, sizeof rep);
	CK(kgenome_emu_unp_build(NULL, e.n, &info, &bud, &rep) == NULL && rep.entry == 0 && rep.stop == 0 && rep.insn == 0);
	memset(&rep, 0xaa, sizeof rep);
	CK(kgenome_emu_unp_build(e.b, 0, &info, &bud, &rep) == NULL && rep.insn == 0);
	CK(kgenome_emu_unp_build(e.b, e.n, NULL, &bud, &rep) == NULL);
	{
		struct kgenome_elf_info bad = info;
		bad.valid = 0;
		CK(kgenome_emu_unp_build(e.b, e.n, &bad, &bud, &rep) == NULL);
		CK(kgenome_emu_unp_run(e.b, e.n, &bad, &bud, NULL) == NULL);
	}
	kgenome_budget_default(&bud, e.n, e.n);
	{
		struct kgenome_emu *b = kgenome_emu_unp_build(e.b, e.n, &info, &bud, NULL);   /* the report is optional */
		CK(b != NULL);
		kgenome_emu_free(b);
	}
	{
		/* an ELF32 is run as i386 code: the width comes from the file */
		static struct hk_elf e32;
		static struct kgenome_elf_info i32;
		struct kgenome_obj o32;
		static const uint8_t exit32[] = { 0x31, 0xdb, 0xb8, 1, 0, 0, 0, 0xcd, 0x80 };

		hk_elf(&e32, 0, 0, 0);
		memcpy(e32.b + e32.text, exit32, sizeof exit32);
		memset(&i32, 0, sizeof i32);
		CK(kgenome_elf_image_parse(kof_buf_make(e32.b, e32.n), &i32, &o32));
		kgenome_budget_default(&bud, e32.n, e32.n);
		em = kgenome_emu_unp_run(e32.b, e32.n, &i32, &bud, &rep);
		CK(em != NULL && rep.stop == KGENOME_EMU_STOP_EXIT);
		kgenome_emu_free(em);
	}
}

static void t_gates(void)
{
	static struct hk_elf e;
	static struct hk_pe pe;
	static struct kgenome_elf_info ei;
	static struct kgenome_pe_info pi;
	struct kgenome_obj eo, po;
	enum kgenome_emu_unp_why w;

	hk_elf(&e, 1, 0, 0);
	hk_pe(&pe, 1);
	CK(kgenome_elf_image_parse(kof_buf_make(e.b, e.n), &ei, &eo));
	CK(kgenome_pe_image_parse(kof_buf_make(pe.b, pe.n), &pi, &po));
	eo.file_header = &ei;
	po.file_header = &pi;
	/* a plain small object is not a packer: whatever the answer, it is one of the documented ones */
	w = kgenome_emu_unp_gate(&eo, &ei, e.b, e.n);
	CK(w >= KGENOME_EMU_UNP_NO && w <= KGENOME_EMU_UNP_WHY_APPENDED);
	w = kgenome_emu_unp_gate_pe(&po, &pi, pe.b, pe.n);
	CK(w >= KGENOME_EMU_UNP_NO && w <= KGENOME_EMU_UNP_WHY_APPENDED);
	/* the refusals: NULL anything, zero length */
	CK(kgenome_emu_unp_gate(&eo, &ei, e.b, 0) == KGENOME_EMU_UNP_NO);
	CK(kgenome_emu_unp_gate(&eo, &ei, NULL, 0) == KGENOME_EMU_UNP_NO);
	CK(kgenome_emu_unp_gate_pe(&po, &pi, pe.b, 0) == KGENOME_EMU_UNP_NO);
	CK(kgenome_emu_unp_gate_pe(&po, &pi, NULL, 0) == KGENOME_EMU_UNP_NO);
}

/* ---- the PE run and the image it rebuilds ----------------------------------------------------------------- */

static void t_pe_run_and_image(void)
{
	static struct hk_pe pe;
	static struct kgenome_pe_info pi, out_pi;
	struct kgenome_obj o;
	struct kgenome_emu_unp_report rep;
	struct kgenome_emu_unp_pe_req rq;
	struct kgenome_budget bud;
	struct kgenome_emu *em;
	uint8_t *img = NULL;
	uint64_t img_n = 0;
	int plus;

	for (plus = 0; plus < 2; plus++) {
		hk_pe(&pe, plus);
		/* mov eax, 7 ; ... ; ret into the void - the stub ends in a fault, which is an answer */
		memset(&pi, 0, sizeof pi);
		CK(kgenome_pe_image_parse(kof_buf_make(pe.b, pe.n), &pi, &o));
		kgenome_budget_default(&bud, pe.n, pe.n);
		memset(&rq, 0, sizeof rq);
		rq.file = pe.b;
		rq.n = pe.n;
		rq.info = &pi;
		rq.bud = &bud;
		rq.rep = &rep;
		em = kgenome_emu_unp_run_pe(&rq);
		CK(em != NULL);
		CK(rep.insn > 0 && rep.insn <= bud.max_insn);
		if (em) {
			uint64_t base = pi.image_base;
			/* the rebuilt image: a PE, within its cap, whose sections are the run's */
			CK(kgenome_emu_unp_pe_image(em, &pi, base, 1u << 20, &img, &img_n) == 1);
			CK(img != NULL && img_n > 0 && img_n <= (1u << 20));
			if (img) {
				struct kgenome_obj o2;
				CK(img_n > pe.lfanew && !memcmp(img, "MZ", 2));
				memset(&out_pi, 0, sizeof out_pi);
				CK(kgenome_pe_image_parse(kof_buf_make(img, img_n), &out_pi, &o2) == 1 && out_pi.valid);
				CK(out_pi.sec_count >= 1 && out_pi.pe32_plus == pi.pe32_plus);
				free(img);
			}
			img = NULL;
			/* the cap is the cap: too small is a refusal, never a short write */
			if (kgenome_emu_unp_pe_image(em, &pi, base, 0, &img, &img_n) == 1)
				CK(img_n == 0);
			if (img)
				free(img);
			img = NULL;
			{
				uint64_t c;
				for (c = 1; c < 0x2000; c = c * 3u + 1u) {
					img_n = 0;
					if (kgenome_emu_unp_pe_image(em, &pi, base, c, &img, &img_n) == 1) {
						CK(img_n <= c);
						free(img);
					}
					img = NULL;
				}
			}
			/* the refusals */
			CK(kgenome_emu_unp_pe_image(NULL, &pi, base, 1u << 20, &img, &img_n) == 0);
			CK(kgenome_emu_unp_pe_image(em, NULL, base, 1u << 20, &img, &img_n) == 0);
			CK(kgenome_emu_unp_pe_image(em, &pi, base, 1u << 20, NULL, &img_n) == 0);
			CK(kgenome_emu_unp_pe_image(em, &pi, base, 1u << 20, &img, NULL) == 0);
			{
				struct kgenome_pe_info none = pi;
				none.valid = 0;
				CK(kgenome_emu_unp_pe_image(em, &none, base, 1u << 20, &img, &img_n) == 0);
				none = pi;
				none.sec_count = 0;
				CK(kgenome_emu_unp_pe_image(em, &none, base, 1u << 20, &img, &img_n) == 0);
			}
			/* an image base that does not match the run: refused or empty, never wild */
			{
				uint64_t bases[4] = { 0, 1, UINT64_MAX, 0x7fffffffffffffffull };
				unsigned k;
				for (k = 0; k < 4; k++) {
					img = NULL;
					img_n = 0;
					if (kgenome_emu_unp_pe_image(em, &pi, bases[k], 1u << 20, &img, &img_n) == 1) {
						CK(img_n <= (1u << 20));
						free(img);
					}
				}
			}
			kgenome_emu_free(em);
		}
	}
	/* the run's refusals */
	memset(&rep, 0xaa, sizeof rep);
	rq.file = NULL;
	CK(kgenome_emu_unp_run_pe(&rq) == NULL && rep.insn == 0);
	rq.file = pe.b;
	rq.n = 0;
	CK(kgenome_emu_unp_run_pe(&rq) == NULL);
	rq.n = pe.n;
	rq.info = NULL;
	CK(kgenome_emu_unp_run_pe(&rq) == NULL);
}

/* ---- declarations: the counts the caller supplies --------------------------------------------------------- */

static int decl_case(void *arg)
{
	/* a declaration whose counts exceed its arrays: the struct sits at the end of a guard page,
	 * so reading entry [max] faults */
	unsigned which = (unsigned)(uintptr_t)arg;
	static struct hk_pe pe;
	static struct kgenome_pe_info pi;
	struct kgenome_obj o;
	struct kgenome_budget bud;
	struct kgenome_emu_unp_pe_req rq;
	struct kgenome_emu_decl *d;
	struct hk_gb g;
	struct kgenome_emu *em;

	hk_pe(&pe, 1);
	memset(&pi, 0, sizeof pi);
	if (!kgenome_pe_image_parse(kof_buf_make(pe.b, pe.n), &pi, &o))
		return 2;
	kgenome_budget_default(&bud, pe.n, pe.n);
	bud.max_insn = 5000;
	gb_init(&g, sizeof *d);
	d = (struct kgenome_emu_decl *)gb_put(&g, NULL, sizeof *d);
	memset(d, 0, sizeof *d);
	if (which == 0)
		d->n_patch = 1000;
	else if (which == 1)
		d->n_iw = 1000;
	else
		d->n_shim = 1000;
	memset(&rq, 0, sizeof rq);
	rq.file = pe.b;
	rq.n = pe.n;
	rq.info = &pi;
	rq.bud = &bud;
	rq.decl = d;
	em = kgenome_emu_unp_run_pe(&rq);
	kgenome_emu_free(em);
	gb_free(&g);
	return 0;
}

static void t_decl_counts(void)
{
	int sig = 0;
	enum hk_result r0 = hk_isolated(decl_case, (void *)0, 10, &sig);
	enum hk_result r1 = hk_isolated(decl_case, (void *)1, 10, &sig);
	enum hk_result r2 = hk_isolated(decl_case, (void *)2, 10, &sig);

	CK(r0 == HK_OK);               /* the patch table is clamped to KGENOME_EMU_PATCH_MAX */
	KM_CHECK(r1 == HK_OK && r2 == HK_OK,
		 "kgenome_emu_unp_run_pe reads past a declaration's arrays when n_iw or n_shim exceeds them",
		 "emu_unpack_pe.c:409,413 pe_declare_watches loops `k < decl->n_iw` / `k < decl->n_shim` reading "
		 "decl->iw[k] / decl->shim[k] with no clamp to KGENOME_EMU_INSN_WATCH (8) / KGENOME_EMU_SHIM_MAX (16), "
		 "where apply_patches (emu_unpack_pe.c:36) clamps n_patch. Repro: n_iw or n_shim = 1000 in a "
		 "struct kgenome_emu_decl at the end of a page");
}

/* ---- hostile objects: the builders over every length and every field ---------------------------------------- */

static int fam_elf_run(void *arg)
{
	static struct hk_elf e;
	static struct kgenome_elf_info info;
	struct kgenome_obj o;
	struct kgenome_budget bud;
	struct kgenome_emu_unp_report rep;
	uint64_t ex[HK_NEXTREME];
	unsigned c, n, k, x, runs = 0;

	(void)arg;
	for (c = 0; c < 4; c++) {
		hk_elf(&e, (int)(c & 1u), 0, 0);
		put_exit_stub(&e);
		if (c & 2u)
			e.b[16] = 3;                       /* ET_DYN: linked at zero, the loader picks the base */
		/* every length */
		for (n = 0; n <= e.n; n += 2) {
			const uint8_t *p = gb_put(&G, e.b, n);
			struct kgenome_emu *em;

			memset(&info, 0, sizeof info);
			(void)kgenome_elf_image_parse(kof_buf_make(p, n), &info, &o);
			kgenome_budget_default(&bud, n, n);
			bud.max_insn = 20000;
			bud.max_bytes = 1u << 24;
			em = kgenome_emu_unp_run(p, n, &info, &bud, &rep);
			if (em && rep.insn > bud.max_insn)
				hk_fails++;
			kgenome_emu_free(em);
			runs++;
		}
		/* every field at every extreme, over the headers and the segment table */
		hk_extremes(ex, e.n);
		for (k = 0; c < 2 && k < e.ph + e.ph_ent; k += 4) {
			unsigned wd;
			for (wd = 4; wd <= 8; wd *= 2) {
				if (k + wd > e.n || (wd > 2 && (k & 3u)))
					continue;
				for (x = 0; x < HK_NEXTREME; x++) {
					static uint8_t w[HK_ELF_MAX];
					struct kgenome_emu *em;

					memcpy(w, e.b, e.n);
					hk_w(w + k, ex[x], wd, 0);
					memset(&info, 0, sizeof info);
					(void)kgenome_elf_image_parse(kof_buf_make(gb_put(&G, w, e.n), e.n), &info, &o);
					kgenome_budget_default(&bud, e.n, e.n);
					bud.max_insn = 5000;
					bud.max_bytes = 1u << 24;
					em = kgenome_emu_unp_run(gb_put(&G, w, e.n), e.n, &info, &bud, &rep);
					if (em && rep.insn > bud.max_insn)
						hk_fails++;
					kgenome_emu_free(em);
					runs++;
				}
			}
		}
	}
	printf("  elf: %u runs\n", runs);
	return hk_fails != 0;
}

static int fam_pe_run(void *arg)
{
	static struct hk_pe pe;
	static struct kgenome_pe_info info;
	struct kgenome_obj o;
	struct kgenome_budget bud;
	struct kgenome_emu_unp_report rep;
	struct kgenome_emu_unp_pe_req rq;
	uint64_t ex[HK_NEXTREME];
	unsigned plus, n, k, x, runs = 0;

	(void)arg;
	for (plus = 0; plus < 2; plus++) {
		hk_pe(&pe, (int)plus);
		for (n = 0; n <= pe.n; n += 17) {
			const uint8_t *p = gb_put(&G, pe.b, n);
			struct kgenome_emu *em;
			uint8_t *img = NULL;
			uint64_t img_n = 0;

			memset(&info, 0, sizeof info);
			(void)kgenome_pe_image_parse(kof_buf_make(p, n), &info, &o);
			kgenome_budget_default(&bud, n, n);
			bud.max_insn = 20000;
			bud.max_bytes = 1u << 24;
			memset(&rq, 0, sizeof rq);
			rq.file = p;
			rq.n = n;
			rq.info = &info;
			rq.bud = &bud;
			rq.rep = &rep;
			em = kgenome_emu_unp_run_pe(&rq);
			if (em) {
				if (rep.insn > bud.max_insn)
					hk_fails++;
				if (kgenome_emu_unp_pe_image(em, &info, info.image_base, 1u << 20, &img, &img_n) == 1) {
					if (img_n > (1u << 20))
						hk_fails++;
					free(img);
				}
				kgenome_emu_free(em);
			}
			runs++;
		}
		hk_extremes(ex, pe.n);
		{
			/* the fields the loader reads: NumberOfSections, entry, image base, SizeOfImage, SizeOfHeaders,
			 * and each section's virtual size, RVA, raw size, raw pointer and characteristics */
			unsigned offs[16], no = 0, q;

			offs[no++] = pe.lfanew + 6u;
			offs[no++] = pe.opt + 16u;
			offs[no++] = pe.opt + (plus ? 24u : 28u);
			offs[no++] = pe.opt + 56u;
			offs[no++] = pe.opt + 60u;
			for (q = 0; q < 2; q++) {
				offs[no++] = pe.sec + 40u * q + 8u;
				offs[no++] = pe.sec + 40u * q + 12u;
				offs[no++] = pe.sec + 40u * q + 16u;
				offs[no++] = pe.sec + 40u * q + 20u;
				offs[no++] = pe.sec + 40u * q + 36u;
			}
			for (k = 0; k < no; k++) {
				unsigned wd;
				for (wd = 4; wd <= 8; wd *= 2) {
					for (x = 0; x < HK_NEXTREME; x++) {
						static uint8_t w[HK_PE_MAX];
						struct kgenome_emu *em;
						uint8_t *img = NULL;
						uint64_t img_n = 0;

						memcpy(w, pe.b, pe.n);
						hk_w(w + offs[k], ex[x], wd, 0);
						memset(&info, 0, sizeof info);
						(void)kgenome_pe_image_parse(kof_buf_make(gb_put(&G, w, pe.n), pe.n), &info, &o);
						kgenome_budget_default(&bud, pe.n, pe.n);
						bud.max_insn = 5000;
						bud.max_bytes = 1u << 24;
						memset(&rq, 0, sizeof rq);
						rq.file = gb_put(&G, w, pe.n);
						rq.n = pe.n;
						rq.info = &info;
						rq.bud = &bud;
						rq.rep = &rep;
						em = kgenome_emu_unp_run_pe(&rq);
						if (em) {
							if (rep.insn > bud.max_insn)
								hk_fails++;
							if (kgenome_emu_unp_pe_image(em, &info, info.image_base, 1u << 20, &img, &img_n) == 1) {
								if (img_n > (1u << 20))
									hk_fails++;
								free(img);
							}
							kgenome_emu_free(em);
						}
						runs++;
					}
				}
			}
		}
	}
	printf("  pe: %u runs\n", runs);
	return hk_fails != 0;
}

struct fam { const char *name; hk_case_fn fn; unsigned secs; };

int main(int argc, char **argv)
{
	hk_args(argc, argv);

	static const struct fam fams[] = {
		{ "elf image: every length, every header field", fam_elf_run, 120 },
		{ "pe image: every length, every header field", fam_pe_run, 120 },
	};
	unsigned i;

	gb_init(&G, 8192);
	t_elf_build();
	t_gates();
	t_pe_run_and_image();
	t_decl_counts();
	for (i = 0; i < sizeof fams / sizeof fams[0]; i++) {
		int sig = 0;
		double t0 = hk_now();
		enum hk_result r = hk_isolated(fams[i].fn, NULL, fams[i].secs, &sig);

		printf("  %-48s %s (%.2fs)\n", fams[i].name,
		       r == HK_OK ? "ok" : r == HK_FAILED ? "FAILED" : r == HK_HUNG ? "HUNG" : "CRASHED",
		       hk_now() - t0);
		if (r != HK_OK) {
			printf("  FAIL %s: result %d signal %d\n", fams[i].name, (int)r, sig);
			hk_fails++;
		}
	}
	gb_free(&G);
	printf("api_unpack: %d failure(s), %u known\n", hk_fails, km_known());
	return hk_fails != 0 || km_failed();
}
