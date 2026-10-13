/*
 * api_diag - the diagnose scan's small public calls that no test named: where an
 * ELF's code is (kgenome_diag_code_range), the function lists (funcs_of,
 * funcs_with_walk, funcs_of_view), the scan's status note, the PE API-hash
 * product, and the walk object that carries one decode between them.
 *
 * Each is held to what its comment says it returns and to the ownership rule of
 * the lib: the caller owns the function set and frees it with kgenome_funcs_free;
 * the apihash set belongs to the scan and is freed with it; a refusal leaves the
 * out parameter ZEROED, never half written.
 */

#include <kgenome.h>

#include "hk.h"
#include "../../unit/known_miss.h"

static struct hk_elf E;
static struct hk_pe  P;
static struct kgenome_elf_info ei;
static struct kgenome_pe_info pi;

static void parse_both(void)
{
	struct kgenome_obj o;

	hk_elf(&E, 1, 0, 0);
	hk_pe(&P, 1);
	memset(&ei, 0, sizeof ei);
	memset(&pi, 0, sizeof pi);
	CK(kgenome_elf_image_parse(kof_buf_make(E.b, E.n), &ei, &o));
	CK(kgenome_pe_image_parse(kof_buf_make(P.b, P.n), &pi, &o));
}

static struct kgenome_obj elf_obj(void)
{
	struct kgenome_obj o;
	kgenome_elf_image_parse(kof_buf_make(E.b, E.n), &ei, &o);
	o.file_header = &ei;
	return o;
}

/* ---- code_range -------------------------------------------------------------------------------- */

static int code_range_index_case(void *arg)
{
	struct hk_gb g;
	struct kgenome_elf_info *e;
	uint64_t at = 0;

	(void)arg;
	gb_init(&g, sizeof *e);
	e = (struct kgenome_elf_info *)gb_put(&g, &ei, sizeof *e);
	/* a segment index no parse produces: the table has KGENOME_ELF_MAX_SEGMENTS entries */
	(void)kgenome_diag_code_range(e, 100000, 1u << 20, &at);
	gb_free(&g);
	return 0;
}

/* an object that is only headers (or shorter) has no code: the headers are not code */
static int code_range_headers_case(void *arg)
{
	uint64_t at = 99, have;

	(void)arg;
	have = kgenome_diag_code_range(&ei, 0, E.ph + E.ph_ent, &at);           /* exactly the headers */
	if (have != 0)
		return 1;
	at = 99;
	have = kgenome_diag_code_range(&ei, 0, 10, &at);                        /* inside the ELF header */
	return have == 0 ? 0 : 2;
}

static void t_code_range(void)
{
	uint64_t at, have;
	struct kgenome_elf_info w;
	int sig = 0;

	parse_both();
	/* the segment holds the headers: the range starts past the program header table */
	at = 99;
	have = kgenome_diag_code_range(&ei, 0, E.n, &at);
	CK(at == E.ph + E.ph_ent && have == E.n - (E.ph + E.ph_ent));
	/* a segment that is not code, and an index with no segment, answer 0 and leave `at` alone */
	at = 99;
	CK(kgenome_diag_code_range(&ei, 1, E.n, &at) == 0 && at == 99);
	CK(kgenome_diag_code_range(&ei, 63, E.n, &at) == 0 && at == 99);
	w = ei;
	w.seg[0].perm = KGENOME_PERM_R | KGENOME_PERM_W;
	CK(kgenome_diag_code_range(&w, 0, E.n, &at) == 0 && at == 99);
	/* clipped to the object */
	at = 99;
	have = kgenome_diag_code_range(&ei, 0, E.ph + E.ph_ent + 50u, &at);
	CK(have == 50 && at == E.ph + E.ph_ent);
	CK(kgenome_diag_code_range(&ei, 0, 0, &at) == 0);
	/* a program header table that claims to wrap the address space does not move the start */
	w = ei;
	w.phoff = UINT64_MAX - 10u;
	w.phnum = 0xffff;
	w.phentsize = 0xffff;
	at = 99;
	have = kgenome_diag_code_range(&w, 0, E.n, &at);
	CK(at <= E.n && have <= E.n);
	w = ei;
	w.phoff = 0x7fffffffffffffffull;
	at = 99;
	have = kgenome_diag_code_range(&w, 0, E.n, &at);
	CK(at <= E.n && have <= E.n);
	/* a segment whose file range is beyond the object */
	w = ei;
	w.seg[0].file_off = UINT64_MAX - 2u;
	w.seg[0].file_size = 100;
	at = 99;
	CK(kgenome_diag_code_range(&w, 0, E.n, &at) == 0 && at == 99);
	w = ei;
	w.seg[0].file_off = 0;
	w.seg[0].file_size = UINT64_MAX;
	at = 99;
	have = kgenome_diag_code_range(&w, 0, E.n, &at);
	CK(have <= E.n);
	/* the extent helpers it stands on */
	CK(kgenome_diag_code_bytes(NULL, 100) == 100);
	CK(kgenome_diag_code_bytes(NULL, 0) == 0);
	{
		struct kgenome_obj o = elf_obj();
		CK(kgenome_diag_code_bytes(&o, E.n) > 0 && kgenome_diag_code_bytes(&o, E.n) <= E.n - (E.ph + E.ph_ent));   /* the walk starts at .text, past the headers */
		CK(kgenome_diag_code_bytes(&o, 0) == 0);
		o.format = KGENOME_FMT_NONE;
		CK(kgenome_diag_code_bytes(&o, 77) == 77);
		o.format = KGENOME_FMT_ELF;
		ei.valid = 0;
		CK(kgenome_diag_code_bytes(&o, 77) == 77);                 /* never zero for a non-empty object */
		ei.valid = 1;
	}
	{
		struct kgenome_obj po;
		memset(&po, 0, sizeof po);
		po.format = KGENOME_FMT_PE;
		po.file_header = &pi;
		CK(kgenome_diag_code_bytes(&po, P.n) == 0x200);            /* the .text section's raw size */
	}
	{
		enum hk_result r = hk_isolated(code_range_index_case, NULL, 10, &sig);
		enum hk_result rh = hk_isolated(code_range_headers_case, NULL, 10, &sig);

		KM_CHECK(rh == HK_OK, "kgenome_diag_code_range returns the ELF header as code when the object is only headers",
			 "diag_code.c:67 `if (*at < hdr && hdr - *at < have)`: for an object whose size equals the end of the "
			 "program header table (hdr - at == have) the start is not moved and `have` bytes of ELF header are "
			 "returned as code; a shorter object keeps its 10 header bytes the same way. "
			 "Repro: kgenome_diag_code_range(&info, 0, e_phoff + e_phnum*e_phentsize, &at) != 0");
		KM_CHECK(r == HK_OK, "kgenome_diag_code_range reads seg[i] for any i the caller passes",
			 "diag_code.c kgenome_diag_code_seg: `&e->seg[i]` with no `i < KGENOME_ELF_MAX_SEGMENTS`; "
			 "kgenome_diag_extent_count clamps for the loops that call it, the public function does not. "
			 "Repro: kgenome_diag_code_range(&info, 100000, size, &at) with info at the end of a page");
	}
}

/* ---- notes ----------------------------------------------------------------------------------------- */

static void t_note(void)
{
	struct kgenome_obj o = elf_obj();
	struct kgenome_diag_scan *s;

	s = kgenome_diag_scan(&o, E.b, E.n);
	CK(s != NULL);
	CK(kgenome_diag_scan_status(s) == KGENOME_OK);
	kgenome_diag_note(s, KGENOME_OK);
	CK(kgenome_diag_scan_status(s) == KGENOME_OK);
	kgenome_diag_note(s, KGENOME_OVER_BUDGET);
	CK(kgenome_diag_scan_status(s) == KGENOME_OVER_BUDGET);
	kgenome_diag_note(s, KGENOME_TRUNCATED);                /* the worse of the two stays */
	CK(kgenome_diag_scan_status(s) == KGENOME_OVER_BUDGET);
	kgenome_diag_note(s, KGENOME_NOMEM);
	CK(kgenome_diag_scan_status(s) == KGENOME_NOMEM);
	kgenome_diag_note(s, KGENOME_OK);
	CK(kgenome_diag_scan_status(s) == KGENOME_NOMEM);
	kgenome_diag_note(s, (enum kgenome_status)99);          /* nonsense is "worse" but never an index */
	(void)kgenome_diag_scan_status(s);
	kgenome_diag_note(NULL, KGENOME_NOMEM);                 /* and a NULL scan is ignored */
	kgenome_diag_scan_free(s);
	kgenome_diag_scan_free(NULL);
}

/* ---- the function lists ---------------------------------------------------------------------------------- */

static void funcs_inside(const struct kgenome_func_set *fs, uint64_t n, const char *tag)
{
	uint32_t i;

	for (i = 0; i < fs->n; i++) {
		if (fs->v[i].off > n || fs->v[i].len > n - fs->v[i].off) {
			printf("  FAIL %s: function %u [%llu+%llu) outside the %llu-byte object\n", tag, i,
			       (unsigned long long)fs->v[i].off, (unsigned long long)fs->v[i].len, (unsigned long long)n);
			hk_fails++;
		}
	}
}

static void t_funcs(void)
{
	struct kgenome_obj o = elf_obj();
	struct kgenome_func_set a, b, c, v;
	struct kgenome_diag_walk *w;
	kof_buf f = kof_buf_make(E.b, E.n);
	static uint8_t zero[HK_ELF_MAX];

	/* the symbols' extents: main and helper */
	kgenome_diag_funcs_of(&o, E.b, E.n, &a);
	CK(a.status == KGENOME_OK && a.n == 2);
	CK(a.v[0].off == E.text && a.v[0].len == 6 && a.v[1].off == E.text + 10u && a.v[1].len == 6);
	funcs_inside(&a, E.n, "funcs_of");
	/* with a caller's walk and without one: the same answer, and the walk is reusable */
	w = kgenome_diag_walk_new();
	CK(w != NULL);
	kgenome_diag_funcs_with_walk(&o, E.b, E.n, w, 0, &b);
	kgenome_diag_funcs_with_walk(&o, E.b, E.n, w, 1, &c);
	CK(b.n == a.n && c.n == a.n && !memcmp(a.v, b.v, a.n * sizeof a.v[0]) && !memcmp(a.v, c.v, a.n * sizeof a.v[0]));
	kgenome_funcs_free(&c);
	kgenome_diag_funcs_with_walk(&o, E.b, E.n, NULL, 0, &c);        /* NULL walk: one is made and freed inside */
	CK(c.n == a.n);
	kgenome_funcs_free(&b);
	kgenome_funcs_free(&c);
	kgenome_diag_walk_free(w);
	kgenome_diag_walk_free(NULL);

	/* an object with no symbols: the functions its code enters (or none), inside the object */
	{
		struct kgenome_elf_info stripped = ei;
		struct kgenome_obj so = o;
		unsigned i;

		for (i = 0; i < stripped.sec_count; i++)
			if (stripped.sec[i].type == KGENOME_ELF_SHT_SYMTAB)
				stripped.sec[i].type = 0;
		so.file_header = &stripped;
		kgenome_diag_funcs_of(&so, E.b, E.n, &b);
		funcs_inside(&b, E.n, "funcs_of (stripped)");
		kgenome_funcs_free(&b);
	}
	/* the out parameter is written whole even when nothing is found */
	memset(&b, 0x55, sizeof b);
	{
		struct kgenome_obj none = o;
		none.file_header = NULL;
		kgenome_diag_funcs_of(&none, E.b, E.n, &b);
		CK(b.n == 0 && b.v == NULL && b.status == KGENOME_OK);
	}
	memset(&b, 0x55, sizeof b);
	kgenome_diag_funcs_of(&o, E.b, 0, &b);
	CK(b.n == 0 && b.v == NULL);
	funcs_inside(&b, 0, "funcs_of (empty)");
	{
		/* a PE: the exception table is the source, and this object has one 24 bytes long */
		struct kgenome_obj po;
		struct kgenome_func_set pf;
		memset(&po, 0, sizeof po);
		po.format = KGENOME_FMT_PE;
		po.file_header = &pi;
		kgenome_diag_funcs_of(&po, P.b, P.n, &pf);
		funcs_inside(&pf, P.n, "funcs_of (pe)");
		kgenome_funcs_free(&pf);
	}

	/* a view: the parent's functions, found again in the view's bytes */
	kgenome_diag_funcs_of_view(&o, f, &a, f, &v);                    /* the parent's own set handed in */
	CK(v.n == a.n);
	kgenome_funcs_free(&v);
	kgenome_diag_funcs_of_view(&o, f, NULL, f, &v);                  /* NULL builds it */
	CK(v.n == a.n);
	kgenome_funcs_free(&v);
	memcpy(zero, E.b, E.n);
	memset(zero + E.text, 0x90, 6);                                  /* main's bytes are gone from the view */
	kgenome_diag_funcs_of_view(&o, f, &a, kof_buf_make(zero, E.n), &v);
	CK(v.n <= a.n);
	funcs_inside(&v, E.n, "funcs_of_view");
	kgenome_funcs_free(&v);
	/* a view the same length but all zeros, a view shorter than a function, an empty one */
	memset(zero, 0, sizeof zero);
	kgenome_diag_funcs_of_view(&o, f, &a, kof_buf_make(zero, E.n), &v);
	funcs_inside(&v, E.n, "funcs_of_view (zeros)");
	kgenome_funcs_free(&v);
	kgenome_diag_funcs_of_view(&o, f, &a, kof_buf_make(zero, 3), &v);
	funcs_inside(&v, 3, "funcs_of_view (short)");
	kgenome_funcs_free(&v);
	memset(&v, 0x55, sizeof v);
	kgenome_diag_funcs_of_view(&o, f, &a, kof_buf_make(NULL, 0), &v);
	CK(v.n == 0 && v.v == NULL);
	memset(&v, 0x55, sizeof v);
	kgenome_diag_funcs_of_view(NULL, f, &a, f, &v);
	CK(v.n == 0 && v.v == NULL);
	memset(&v, 0x55, sizeof v);
	kgenome_diag_funcs_of_view(&o, kof_buf_make(NULL, 0), &a, f, &v);
	CK(v.n == 0 && v.v == NULL);
	kgenome_funcs_free(&a);
}

/* ---- the PE API-hash product ------------------------------------------------------------------------------- */

static void t_apihash(void)
{
	struct kgenome_obj po, eo = elf_obj();
	struct kgenome_diag_scan *s;
	const struct kgenome_diag_apihash_set *a, *b;
	const char *dll[4], *name[4];

	memset(&po, 0, sizeof po);
	po.format = KGENOME_FMT_PE;
	po.arch = KGENOME_ARCH_X86_64;
	po.obj_size = P.n;
	po.file_header = &pi;
	po.entry_off = P.text_off;

	/* an ELF has no PEB to walk: no product */
	s = kgenome_diag_scan(&eo, E.b, E.n);
	CK(kgenome_diag_apihash(s, &eo) == NULL);
	kgenome_diag_scan_free(s);
	/* a PE: the run happens once, the set belongs to the scan and the answer is stable */
	s = kgenome_diag_scan_with(&po, P.b, P.n, KGENOME_DIAG_RUN_ALL);
	CK(s != NULL);
	a = kgenome_diag_apihash(s, &po);
	b = kgenome_diag_apihash(s, &po);
	CK(a != NULL && a == b);
	if (a) {
		CK(a->n_call == 0 || a->call != NULL);
		CK(a->n_peb <= a->cap_peb || a->n_peb == 0);
		CK(a->status >= KGENOME_OK && a->status <= KGENOME_NOMEM);
		(void)dll; (void)name;
		CK(kgenome_diag_apihash_distinct(a, NULL, NULL) == 0 || a->n_call > 0);
	}
	kgenome_diag_scan_free(s);
}

/* ---- the caller's budget is the bound, and a scan that stops says so --------------------------------------- */

static void t_budgets(void)
{
	/* the object, and 300 `mov eax, 41 ; syscall ; ret` stubs after it inside the one PT_LOAD */
	static uint8_t img[4096];
	struct kgenome_elf_info info;
	struct kgenome_obj o;
	unsigned n = E.n, i, k;
	static const uint64_t bytes[] = { 1, 8, 100, 1000, 20000, 100000, 1u << 20 };

	memcpy(img, E.b, E.n);
	for (i = 0; i < 300 && n + 8u <= sizeof img; i++) {
		static const uint8_t sc[] = { 0xb8, 0x29, 0, 0, 0, 0x0f, 0x05, 0xc3 };
		memcpy(img + n, sc, sizeof sc);
		n += (unsigned)sizeof sc;
	}
	hk_w(img + E.ph + 32, n, 8, 0);
	hk_w(img + E.ph + 40, n + 0x100u, 8, 0);
	memset(&info, 0, sizeof info);
	CK(kgenome_elf_image_parse(kof_buf_make(img, n), &info, &o));
	o.file_header = &info;

	/* a byte allowance: what the scan charged never exceeds it, whatever it was */
	for (k = 0; k < sizeof bytes / sizeof bytes[0]; k++) {
		struct kgenome_budget b;
		struct kgenome_diag_inputs in;
		struct kgenome_diag_scan *s;
		uint64_t peak = 0, used;

		memset(&b, 0, sizeof b);
		memset(&in, 0, sizeof in);
		b.max_bytes = bytes[k];
		in.budget = &b;
		s = kgenome_diag_scan_with_inputs(&o, img, n, KGENOME_DIAG_RUN_ALL, &in);
		CK(s != NULL);
		if (!s)
			continue;
		used = kgenome_diag_scan_bytes(s, &peak);
		CK(used <= peak);
		CK(peak <= bytes[k]);
		if (bytes[k] < 64u)
			CK(kgenome_diag_scan_status(s) != KGENOME_OK);          /* nothing fits: it says so */
		CK(kgenome_diag_scan_status(s) <= KGENOME_NOMEM);
		kgenome_diag_scan_free(s);
	}
	/* a node allowance: the graph stops at it and the scan says TRUNCATED, never more nodes than allowed */
	{
		static const uint32_t nodes[] = { 1, 2, 10, 299 };
		for (k = 0; k < sizeof nodes / sizeof nodes[0]; k++) {
			struct kgenome_budget b;
			struct kgenome_diag_inputs in;
			struct kgenome_diag_scan *s;

			memset(&b, 0, sizeof b);
			memset(&in, 0, sizeof in);
			b.max_nodes = nodes[k];
			in.budget = &b;
			s = kgenome_diag_scan_with_inputs(&o, img, n, KGENOME_DIAG_RUN_DEFAULT, &in);
			CK(s != NULL);
			if (!s)
				continue;
			CK(kgenome_diag_scan_count(s) <= nodes[k]);
			CK(kgenome_diag_scan_count(s) == 0 || kgenome_diag_scan_status(s) == KGENOME_TRUNCATED);
			CK(kgenome_diag_scan_full(s) == (kgenome_diag_scan_count(s) == nodes[k]));
			kgenome_diag_scan_free(s);
		}
		/* more than the 16-bit index can name is the index's width, not the caller's choice */
		{
			struct kgenome_budget b;
			struct kgenome_diag_inputs in;
			struct kgenome_diag_scan *s;
			memset(&b, 0, sizeof b);
			memset(&in, 0, sizeof in);
			b.max_nodes = 0xffffffffu;
			b.max_names = 0xffffffffu;
			in.budget = &b;
			s = kgenome_diag_scan_with_inputs(&o, img, n, KGENOME_DIAG_RUN_ALL, &in);
			CK(s != NULL && kgenome_diag_scan_count(s) <= KGENOME_MAX_INDEX);
			kgenome_diag_scan_free(s);
		}
	}
	/* instruction and step ceilings of one: the run stops at once and the status is not OK */
	{
		struct kgenome_budget b;
		struct kgenome_diag_inputs in;
		struct kgenome_diag_scan *s;

		memset(&b, 0, sizeof b);
		memset(&in, 0, sizeof in);
		b.max_insn = 1;
		b.max_steps = 1;
		b.max_insn_resolve = 1;
		in.budget = &b;
		s = kgenome_diag_scan_with_inputs(&o, img, n, KGENOME_DIAG_RUN_ALL, &in);
		CK(s != NULL);
		if (s) {
			CK(kgenome_diag_scan_status(s) != KGENOME_OK);
			kgenome_diag_scan_free(s);
		}
	}
	/* a deadline of 1 ms and zero everywhere else is still a finished scan */
	{
		struct kgenome_budget b;
		struct kgenome_diag_inputs in;
		struct kgenome_diag_scan *s;

		memset(&b, 0, sizeof b);
		memset(&in, 0, sizeof in);
		b.deadline_ms = 1;
		in.budget = &b;
		s = kgenome_diag_scan_with_inputs(&o, img, n, KGENOME_DIAG_RUN_ALL, &in);
		CK(s != NULL);
		kgenome_diag_scan_free(s);
	}
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);

	parse_both();
	t_code_range();
	t_note();
	t_funcs();
	t_apihash();
	t_budgets();
	printf("api_diag: %d failure(s), %u known\n", hk_fails, km_known());
	return hk_fails != 0 || km_failed();
}
