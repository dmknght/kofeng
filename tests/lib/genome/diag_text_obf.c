/*
 * diag_text_obf - the obfuscation measure of a script (kgenome_diag_text_obf, diag_scan.h; diag_text_obf.c, EXPERIMENTAL 2026-11-13).
 *
 * What is pinned, each a property the owner's definition asks of the number:
 *   - a name written at the call, a callback held in a variable, and string processing of DATA are 0 (code that is not hiding anything is at the floor);
 *   - DISPATCH is not hiding: an identity with a run-time leaf (`'get_' . $field`) is dynamic and adds nothing;
 *   - a name MADE out of constants is counted by the transforms that made it, exactly (k), and more transforms is a higher value (monotone);
 *   - an element picked out of an array literal is one transform; code handed to eval as one literal is written, k = 0;
 *   - hoho.php's shape: create_function built by one str_replace, its body by six joins and one str_replace - k = 8, and the body is a record of its own;
 *   - js: a function of the program handed constants where a member KEY is read is a refused step (a string-array decoder); a module loader's `r(12)` held
 *     in a variable and called is dispatch, not hiding (the rule that kept WordPress's webpack bundles at the floor);
 *   - asking for the measure changes nothing else the scan answers (status, cut evaluations, nodes).
 * RED on the code before it: the request member, the set and the entry did not exist (tests/lib/genome links libkgenome.a alone: a build failure). The mutants
 * that must turn it red are listed in the report of the work package (exp_obflm part 7).
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <phenotype/diag_scan.h>
#include <celllysis/nucleo.h>
#include <textual/textual.h>

static int fails;

#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

/* str_replace, byte for byte (the engine's hook is not reachable from a libgenome-only test: the same stand-in as diag_text_islands.c). */
static int apply(void *user, const struct kgenome_textual_call *c, const uint8_t *in, uint32_t len, uint8_t *out, uint32_t cap, uint32_t *n_out)
{
	uint32_t i, w = 0;

	(void)user;
	if (c->op != KGENOME_TEXTUAL_DEC_REPLACE || !c->n1)
		return 0;
	for (i = 0; i < len;) {
		if (i + c->n1 <= len && !memcmp(in + i, c->s1, c->n1)) {
			if (w + c->n2 > cap)
				return 0;
			if (c->n2)
				memcpy(out + w, c->s2, c->n2);
			w += c->n2;
			i += c->n1;
		} else {
			if (w + 1u > cap)
				return 0;
			out[w++] = in[i++];
		}
	}
	*n_out = w;
	return 1;
}

/* The measure of `src` with the caller's islands `isl[0..n_isl)` (the engine hands its parse's: kof_script_places). */
static void measure_isl(const char *src, uint32_t lang, const struct kgenome_diag_text_place *isl, uint32_t n_isl, struct kgenome_diag_text_obf_set *s)
{
	struct kgenome_diag_text_req rq = { .base = (const uint8_t *)src, .size = strlen(src), .lang = lang, .apply = apply, .obf = s, .obf_isl = isl,
					    .n_obf_isl = n_isl };

	kgenome_diag_text_obf(&rq);
}

static void measure(const char *src, uint32_t lang, struct kgenome_diag_text_obf_set *s)
{
	measure_isl(src, lang, NULL, 0u, s);
}

/* The record of the file (layer 0): there is exactly one. */
static const struct kgenome_diag_text_obf_rec *file_rec(const struct kgenome_diag_text_obf_set *s)
{
	uint32_t i;
	const struct kgenome_diag_text_obf_rec *r = NULL;

	for (i = 0; i < s->n; i++)
		if (s->v[i].layer == 0u) {
			if (r)
				return NULL;
			r = &s->v[i];
		}
	return r;
}

static uint32_t milli_of(uint32_t k, uint32_t n_eff)
{
	return (uint32_t)((uint64_t)(log2(1.0 + (double)k) * 1000.0 + 0.5) / n_eff);
}

static void floor_cases(void)
{
	static const struct { const char *name, *src; uint32_t lang, bound; } c[] = {
		{ "written names", "<?php echo strlen('x'); $a = substr($b, 1); foo(1, 2); $o->m(3);", KGENOME_TEXTUAL_LANG_PHP, 0 },
		{ "callback in a variable", "<?php $f = 'strlen'; $f('x');", KGENOME_TEXTUAL_LANG_PHP, 1 },
		{ "string processing of data", "<?php $s = str_replace('a', 'b', $t); $u = 'x' . $s . 'y'; echo strtoupper($u);", KGENOME_TEXTUAL_LANG_PHP, 0 },
		{ "eval of one literal", "<?php eval('echo 1;');", KGENOME_TEXTUAL_LANG_PHP, 0 },
		/* a member called is the object's method: a variable of the same name is another thing (js reads a bare name as a variable) */
		{ "member named like a variable", "var m = 'a' + 'b';\no.m(1);\n", KGENOME_TEXTUAL_LANG_JS, 0 },
	};
	uint32_t i;

	for (i = 0; i < sizeof c / sizeof c[0]; i++) {
		struct kgenome_diag_text_obf_set s;
		const struct kgenome_diag_text_obf_rec *r;

		measure(c[i].src, c[i].lang, &s);
		r = file_rec(&s);
		CK(r != NULL, "%s: no file record", c[i].name);
		if (r) {
			CK(r->n_eff >= 1u, "%s: no effect found (n_eff %u)", c[i].name, r->n_eff);
			CK(r->n_built == 0u && r->n_refused == 0u && r->bits_milli == 0u, "%s: counted as hidden (built %u refused %u bits %llu)", c[i].name,
			   r->n_built, r->n_refused, (unsigned long long)r->bits_milli);
			CK(r->n_bound == c[i].bound, "%s: bound %u, want %u (a name or code written at the call is no variable read)", c[i].name, r->n_bound, c[i].bound);
		}
		CK(kgenome_diag_text_obf_value(&s) == 0u, "%s: value %u, want 0", c[i].name, kgenome_diag_text_obf_value(&s));
		CK(s.status == KGENOME_OK, "%s: status %d", c[i].name, (int)s.status);
		kgenome_diag_text_obf_free(&s);
	}
}

static void dispatch_is_not_hiding(void)
{
	struct kgenome_diag_text_obf_set s;
	const struct kgenome_diag_text_obf_rec *r;

	measure("<?php function g($field) { $m = 'get_' . $field; $m(); }", KGENOME_TEXTUAL_LANG_PHP, &s);
	r = file_rec(&s);
	CK(r && r->n_dynamic == 1u && r->n_built == 0u && r->bits_milli == 0u, "dispatch: dynamic %u built %u bits %llu", r ? r->n_dynamic : 0u,
	   r ? r->n_built : 0u, r ? (unsigned long long)r->bits_milli : 0ull);
	kgenome_diag_text_obf_free(&s);
}

/* A name joined out of n + 1 literal pieces is k = n, one effect: the value is exactly 1000 * log2(1 + n). */
static void joins_counted_and_monotone(void)
{
	static const char *const src[] = {
		"<?php $f = 'str' . 'len'; $f('x');",
		"<?php $f = 'st' . 'r' . 'len'; $f('x');",
		"<?php $f = 's' . 't' . 'r' . 'len'; $f('x');",
	};
	uint32_t i, prev = 0;

	for (i = 0; i < 3u; i++) {
		struct kgenome_diag_text_obf_set s;
		const struct kgenome_diag_text_obf_rec *r;
		uint32_t v;

		measure(src[i], KGENOME_TEXTUAL_LANG_PHP, &s);
		r = file_rec(&s);
		v = kgenome_diag_text_obf_value(&s);
		CK(r && r->n_eff == 1u && r->n_built == 1u && r->k_max == i + 1u, "joins %u: eff %u built %u kmax %u", i + 1u, r ? r->n_eff : 0u,
		   r ? r->n_built : 0u, r ? r->k_max : 0u);
		CK(v == milli_of(i + 1u, 1u), "joins %u: value %u, want %u", i + 1u, v, milli_of(i + 1u, 1u));
		CK(v > prev, "joins %u: value %u not above %u (not monotone)", i + 1u, v, prev);
		prev = v;
		kgenome_diag_text_obf_free(&s);
	}
}

/* The effects a value is divided over: one hidden call among three is a third of one hidden call alone. */
static void mean_over_effects(void)
{
	struct kgenome_diag_text_obf_set s;
	const struct kgenome_diag_text_obf_rec *r;

	measure("<?php $f = 'str' . 'len'; $f('x'); foo(); bar();", KGENOME_TEXTUAL_LANG_PHP, &s);
	r = file_rec(&s);
	CK(r && r->n_eff == 3u && kgenome_diag_text_obf_milli(r) == milli_of(1u, 3u), "mean: eff %u milli %u want %u", r ? r->n_eff : 0u,
	   r ? kgenome_diag_text_obf_milli(r) : 0u, milli_of(1u, 3u));
	kgenome_diag_text_obf_free(&s);
}

/* `.=` is a join written as a statement: one step per append. */
static void append_is_one_step(void)
{
	struct kgenome_diag_text_obf_set s;
	const struct kgenome_diag_text_obf_rec *r;

	measure("<?php $f = 'str'; $f .= 'len'; $f('x');", KGENOME_TEXTUAL_LANG_PHP, &s);
	r = file_rec(&s);
	CK(r && r->n_built == 1u && r->k_max == 1u, "append: built %u kmax %u", r ? r->n_built : 0u, r ? r->k_max : 0u);
	kgenome_diag_text_obf_free(&s);
}

static void element_is_one_step(void)
{
	struct kgenome_diag_text_obf_set s;
	const struct kgenome_diag_text_obf_rec *r;

	measure("<?php $a = array('strlen', 'trim'); $a[1]('x');", KGENOME_TEXTUAL_LANG_PHP, &s);
	r = file_rec(&s);
	CK(r && r->n_eff == 1u && r->n_built == 1u && r->k_max == 1u, "element: eff %u built %u kmax %u", r ? r->n_eff : 0u, r ? r->n_built : 0u,
	   r ? r->k_max : 0u);
	kgenome_diag_text_obf_free(&s);
}

#define HOHO \
	"<?php\n" \
	"$p='c'.'T|';$H='d'.'T|';$v='e';$L='f';$j='g';$r='h';$I='i;';\n" \
	"$l=str_replace('k','','ckrekatek_fuknkkction');\n" \
	"$U=str_replace('T|','',$v.$p.$j.$r.$L.$H.$I);\n" \
	"$s=$l('',$U);$s();\n"

/* The callee: one str_replace. The code: the seven variables joined (six joins) and one str_replace; $p and $H are themselves joins (two more). */
static void hoho_shape(void)
{
	struct kgenome_diag_text_obf_set s;
	const struct kgenome_diag_text_obf_rec *r;
	uint32_t i, layers = 0;

	measure(HOHO, KGENOME_TEXTUAL_LANG_PHP, &s);
	r = file_rec(&s);
	CK(r && r->k_max == 1u + 6u + 1u + 2u, "hoho: kmax %u, want 10", r ? r->k_max : 0u);
	CK(r && r->n_built == 1u, "hoho: built %u, want 1 (the create_function call)", r ? r->n_built : 0u);
	CK(r && r->n_dynamic == 1u, "hoho: dynamic %u, want 1 ($s(): what create_function returned)", r ? r->n_dynamic : 0u);
	for (i = 0; i < s.n; i++)
		layers += s.v[i].layer == 1u;
	CK(layers == 1u, "hoho: %u records of layer 1, want 1 (the body create_function runs)", layers);
	CK(kgenome_diag_text_obf_value(&s) == (r ? kgenome_diag_text_obf_milli(r) : 1u), "hoho: the value is the file's, the body's layer is plain");
	kgenome_diag_text_obf_free(&s);
}

static void js_key_decoder_and_loader(void)
{
	struct kgenome_diag_text_obf_set s;
	const struct kgenome_diag_text_obf_rec *r;

	measure("function d(i) { return 'log'; }\nconsole[d(0x1a)]('x');\n", KGENOME_TEXTUAL_LANG_JS, &s);
	r = file_rec(&s);
	CK(r && r->n_refused == 1u && r->k_max == 1u, "js key decoder: refused %u kmax %u", r ? r->n_refused : 0u, r ? r->k_max : 0u);
	kgenome_diag_text_obf_free(&s);

	measure("var m = r(12);\nm.default(1);\nvar k = r(13);\nk(2);\n", KGENOME_TEXTUAL_LANG_JS, &s);
	r = file_rec(&s);
	CK(r && r->n_refused == 0u && r->bits_milli == 0u, "js loader: refused %u bits %llu (a module, not a name)", r ? r->n_refused : 0u,
	   r ? (unsigned long long)r->bits_milli : 0ull);
	kgenome_diag_text_obf_free(&s);
}

/* The same text scanned with and without the measure: status, cut evaluations and nodes are the same. */
static void measure_changes_nothing(void)
{
	static const char *const src[] = { HOHO, "<?php $f = 's' . 't' . 'r' . 'len'; $f($_GET['x']); eval(gzinflate(base64_decode('AAAA')));" };
	uint32_t i;

	for (i = 0; i < 2u; i++) {
		struct kgenome_diag_text_obf_set set;
		struct kgenome_diag_text_req a = { .base = (const uint8_t *)src[i], .size = strlen(src[i]), .lang = KGENOME_TEXTUAL_LANG_PHP, .apply = apply };
		struct kgenome_diag_text_req b = a;
		struct kgenome_diag_scan *sa, *sb;

		memset(&set, 0, sizeof set);
		b.obf = &set;
		sa = kgenome_diag_scan_text(&a);
		sb = kgenome_diag_scan_text(&b);
		CK(sa && sb, "scan %u failed", i);
		if (sa && sb) {
			CK(kgenome_diag_scan_status(sa) == kgenome_diag_scan_status(sb), "text %u: status %d with the measure, %d without", i,
			   (int)kgenome_diag_scan_status(sb), (int)kgenome_diag_scan_status(sa));
			CK(kgenome_diag_scan_eval_cut(sa) == kgenome_diag_scan_eval_cut(sb), "text %u: eval_cut differs", i);
			CK(kgenome_diag_scan_count(sa) == kgenome_diag_scan_count(sb), "text %u: nodes differ", i);
		}
		CK(set.n >= 1u, "text %u: no record", i);
		kgenome_diag_scan_free(sa);
		kgenome_diag_scan_free(sb);
		kgenome_diag_text_obf_free(&set);
	}
}

/*
 * A BOUND THE MEASURE HITS IS THE MEASURE'S: a member key nested past the evaluator's bracket bound (KGENOME_DTX_EV_NEST, 256) is cut when the measure reads it -
 * the walk never evaluates a key - so the scan's own status must stay what the walk left (OK) and the set must say TRUNCATED (rule 4).
 */
static void measure_cut_is_its_own(void)
{
	enum { DEPTH = 300 };
	char *src = malloc(64u + 2u * DEPTH);
	struct kgenome_diag_text_obf_set set;
	struct kgenome_diag_scan *sa, *sb;
	size_t n = 0;
	int k;

	if (!src) {
		CK(0, "no memory");
		return;
	}
	n += (size_t)sprintf(src + n, "o[");
	for (k = 0; k < DEPTH; k++)
		src[n++] = '(';
	n += (size_t)sprintf(src + n, "'x'");
	for (k = 0; k < DEPTH; k++)
		src[n++] = ')';
	n += (size_t)sprintf(src + n, "](1);\n");
	{
		struct kgenome_diag_text_req a = { .base = (const uint8_t *)src, .size = n, .lang = KGENOME_TEXTUAL_LANG_JS, .apply = apply };
		struct kgenome_diag_text_req b = a;

		memset(&set, 0, sizeof set);
		b.obf = &set;
		sa = kgenome_diag_scan_text(&a);
		sb = kgenome_diag_scan_text(&b);
	}
	CK(sa && sb, "scan failed");
	if (sa && sb)
		CK(kgenome_diag_scan_status(sa) == kgenome_diag_scan_status(sb) && kgenome_diag_scan_eval_cut(sa) == kgenome_diag_scan_eval_cut(sb),
		   "deep key: the measure changed the scan (status %d / %d, eval_cut %u / %u)", (int)kgenome_diag_scan_status(sb), (int)kgenome_diag_scan_status(sa),
		   kgenome_diag_scan_eval_cut(sb), kgenome_diag_scan_eval_cut(sa));
	CK(set.status == KGENOME_TRUNCATED, "deep key: the set's status %d, want TRUNCATED (the measure's own cut is said)", (int)set.status);
	kgenome_diag_scan_free(sa);
	kgenome_diag_scan_free(sb);
	kgenome_diag_text_obf_free(&set);
	free(src);
}

/* Does the record's capability list hold `cap`, and is the list ascending with no repeat. */
static int caps_ok(const struct kgenome_diag_text_obf_rec *r)
{
	uint32_t i;

	for (i = 1; i < r->n_cap; i++)
		if (r->cap[i - 1u] >= r->cap[i])
			return 0;
	return 1;
}

static int has_cap(const struct kgenome_diag_text_obf_rec *r, uint16_t cap)
{
	uint32_t i;

	for (i = 0; i < r->n_cap; i++)
		if (r->cap[i] == cap)
			return 1;
	return 0;
}

/*
 * ONE RECORD PER ISLAND (owner 2026-11-14), the islands the CALLER names (the engine's parse: any kind of island it has, not only a php tag - the measure
 * finds none of its own). Two islands of one page: the name is made in the first and called in the second, so the evaluator must still read the whole file
 * (a variable crosses islands) while the effect and its node belong to the island that holds the call. A call outside every island is the TEXT record's,
 * after the islands. With no island named the file is one TEXT record, whatever tags it has. The capabilities are the route's nodes: distinct, ascending,
 * in the island that made them.
 */
static void islands_and_caps(void)
{
	static const char page[] = "<?php $f = 'sys' . 'tem'; ?>\n<p>hello</p>\n<?php $f($_GET['c']); echo base64_decode('YQ=='); base64_decode('Yg=='); ?>\n";
	static const char js[] = "var a = 'ev' + 'al';\nwindow[a]('1');\n";
	const char *i2 = strstr(page, "<?php $f(");
	const char *e2 = strstr(i2, "?>") + 2;
	const char *d2 = strstr(i2, "base64_decode('Yg==')");
	struct kgenome_diag_text_place isl[2] = { { 0u, (uint64_t)(strstr(page, "?>") + 2 - page) }, { (uint64_t)(i2 - page), (uint64_t)(e2 - i2) } };
	struct kgenome_diag_text_place cut[2] = { isl[0], { (uint64_t)(i2 - page), (uint64_t)(d2 - i2) } };
	struct kgenome_diag_text_obf_set s;
	const struct kgenome_diag_text_obf_rec *a, *b;

	measure_isl(page, KGENOME_TEXTUAL_LANG_PHP, isl, 2u, &s);
	CK(s.n == 2u && s.status == KGENOME_OK, "page: %u records status %d, want 2 (two islands, no layer)", s.n, (int)s.status);
	if (s.n == 2u) {
		a = &s.v[0];
		b = &s.v[1];
		CK(a->kind == KGENOME_DIAG_TEXT_OBF_ISLAND && a->at == isl[0].off && a->len == isl[0].len && a->layer == 0u,
		   "island 1: kind %u at %llu len %llu", a->kind, (unsigned long long)a->at, (unsigned long long)a->len);
		CK(b->kind == KGENOME_DIAG_TEXT_OBF_ISLAND && b->at == isl[1].off && b->len == isl[1].len,
		   "island 2: kind %u at %llu len %llu", b->kind, (unsigned long long)b->at, (unsigned long long)b->len);
		CK(a->n_eff == 0u && a->n_cap == 0u, "island 1 calls nothing: eff %u caps %u", a->n_eff, a->n_cap);
		CK(b->n_built == 1u && b->k_max == 1u, "island 2: the name made in island 1 is called here: built %u kmax %u", b->n_built, b->k_max);
		CK(caps_ok(b) && has_cap(b, KGENOME_NUCLEO_EXEC_IMAGE) && has_cap(b, KGENOME_NUCLEO_DECODE) && has_cap(b, KGENOME_NUCLEO_REQUEST),
		   "island 2 caps: %u, want exec, decode, request, ascending and distinct", b->n_cap);
		CK(kgenome_diag_text_obf_value(&s) == kgenome_diag_text_obf_milli(b) && kgenome_diag_text_obf_milli(a) == 0u,
		   "the value is the hiding island's, not a mean with the empty one");
	}
	kgenome_diag_text_obf_free(&s);

	/* the caller's island ends before the last call: that call is the TEXT record's, after the islands, and its capability with it */
	measure_isl(page, KGENOME_TEXTUAL_LANG_PHP, cut, 2u, &s);
	CK(s.n == 3u && s.v[2].kind == KGENOME_DIAG_TEXT_OBF_TEXT && s.v[2].n_eff == 1u && has_cap(&s.v[2], KGENOME_NUCLEO_DECODE) && s.v[1].len == cut[1].len,
	   "cut island: %u records, the third kind %u eff %u", s.n, s.n > 2u ? s.v[2].kind : 9u, s.n > 2u ? s.v[2].n_eff : 0u);
	kgenome_diag_text_obf_free(&s);

	/* no island named: the page is one TEXT record - the measure does not look for tags itself */
	measure(page, KGENOME_TEXTUAL_LANG_PHP, &s);
	CK(s.n == 1u && s.v[0].kind == KGENOME_DIAG_TEXT_OBF_TEXT && s.v[0].at == 0u && s.v[0].len == strlen(page), "page, no island: %u records kind %u",
	   s.n, s.n ? s.v[0].kind : 9u);
	kgenome_diag_text_obf_free(&s);

	/* no islands: the whole text, one record */
	measure(js, KGENOME_TEXTUAL_LANG_JS, &s);
	CK(s.n >= 1u && s.v[0].kind == KGENOME_DIAG_TEXT_OBF_TEXT && s.v[0].at == 0u && s.v[0].len == strlen(js), "js: first record kind %u at %llu len %llu",
	   s.n ? s.v[0].kind : 9u, s.n ? (unsigned long long)s.v[0].at : 0ull, s.n ? (unsigned long long)s.v[0].len : 0ull);
	kgenome_diag_text_obf_free(&s);
}

/*
 * A CALLER'S TABLE IS INPUT: an island that is empty, out of order, overlapping the one before or past the text is not taken, the set says TRUNCATED, and
 * what it would have held is the TEXT record's - never dropped. Every shape of a bad place, one at a time, after one good island.
 */
static void bad_places(void)
{
	static const char page[] = "<?php $f = 'sys' . 'tem'; ?>\n<?php $f('x'); ?>\n";
	uint64_t n = strlen(page), e1 = (uint64_t)(strstr(page, "?>") + 2 - page);
	const struct kgenome_diag_text_place bad[] = {
		{ e1 + 1u, 0u }, { 0u, 3u }, { e1 - 1u, 4u }, { n, 1u }, { n + 1u, 1u }, { e1 + 1u, n }, { UINT64_MAX, 2u }, { e1 + 1u, UINT64_MAX },
	};
	uint32_t i;

	for (i = 0; i < sizeof bad / sizeof *bad; i++) {
		struct kgenome_diag_text_place isl[2] = { { 0u, e1 }, bad[i] };
		struct kgenome_diag_text_obf_set s;

		measure_isl(page, KGENOME_TEXTUAL_LANG_PHP, isl, 2u, &s);
		CK(s.status == KGENOME_TRUNCATED && s.n == 2u && s.v[0].kind == KGENOME_DIAG_TEXT_OBF_ISLAND && s.v[1].kind == KGENOME_DIAG_TEXT_OBF_TEXT &&
			   s.v[1].n_eff == 1u,
		   "bad place %u: status %d, %u records, want TRUNCATED, the good island and the call in TEXT", i, (int)s.status, s.n);
		kgenome_diag_text_obf_free(&s);
	}
}

/* The order of the set: the file's records first (by offset), then the layers - the layer is walked, and recorded, while the file is. Each layer says how long
 * the code it ran is and where it was run from. */
static void layer_records(void)
{
	struct kgenome_diag_text_obf_set s;
	uint32_t i, seen_layer = 0, bad = 0;

	measure(HOHO, KGENOME_TEXTUAL_LANG_PHP, &s);
	for (i = 0; i < s.n; i++) {
		if (s.v[i].layer) {
			seen_layer = 1;
			bad += s.v[i].kind != KGENOME_DIAG_TEXT_OBF_LAYER || !s.v[i].len || s.v[i].at >= sizeof HOHO;
		} else
			bad += seen_layer || s.v[i].kind == KGENOME_DIAG_TEXT_OBF_LAYER;
		bad += !caps_ok(&s.v[i]);
	}
	CK(seen_layer && !bad, "hoho: layer seen %u, %u records out of order or misdescribed", seen_layer, bad);
	kgenome_diag_text_obf_free(&s);
}

int main(void)
{
	floor_cases();
	dispatch_is_not_hiding();
	joins_counted_and_monotone();
	mean_over_effects();
	append_is_one_step();
	element_is_one_step();
	hoho_shape();
	js_key_decoder_and_loader();
	measure_changes_nothing();
	measure_cut_is_its_own();
	islands_and_caps();
	bad_places();
	layer_records();
	printf("diag_text_obf: %s (%d failed)\n", fails ? "FAIL" : "ok", fails);
	return fails ? 1 : 0;
}
