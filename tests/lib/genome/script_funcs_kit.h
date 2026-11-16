/*
 * script_funcs_kit.h - the shared kit of the script_funcs_<lang>.c tests of libgenome (one copy, not six). A test defines SF_LANG (the
 * language), SF_STRAT (the strategy under test) and SF_CR (1 when a lone CR ends a line in the language) and then includes this file, after
 * "hk.h", <kgenome.h> and <celllysis/script_private.h>.
 */
#ifndef KGENOME_TESTS_SCRIPT_FUNCS_KIT_H
#define KGENOME_TESTS_SCRIPT_FUNCS_KIT_H


struct sf_want {
	const char *from, *to, *name;
	int open;
};

/* Every property an answer has whatever the text. */
static void sf_props(uint64_t n, const struct kgenome_fntab_list *l)
{
	uint32_t i;

	CK(!(l->partial & KGENOME_FNTAB_P_NO_TABLE));
	for (i = 0; i < l->n; i++) {
		const struct kgenome_func *f = &l->v[i];

		CK(f->kind == KGENOME_FN_SCRIPT);
		CK(f->end_source == KGENOME_FN_E_SCRIPT);
		CK(f->len > 0 && f->off + f->len <= n);
		CK(!i || f->off >= l->v[i - 1u].off + l->v[i - 1u].len);
		CK(!f->name_len || (f->name_off >= f->off && f->name_off + f->name_len <= f->off + f->len));
		/* an open end is the end of the text, or the next entry's start (funcs.h: "the end is the next start") */
		CK(!(f->flags & KGENOME_FN_F_END_OPEN) || f->off + f->len == n ||
		   (i + 1u < l->n && l->v[i + 1u].off == f->off + f->len));
		CK(!(f->flags & KGENOME_FN_F_END_OPEN) || (l->partial & KGENOME_FNTAB_P_ENDS));
	}
}

/* The answer for [p, p + n) lexed as `lang`. 0 when the text could not be made or the strategy said no memory. */
static int sf_run_lang(uint32_t lang, const uint8_t *p, size_t n, struct kgenome_fntab_list *l)
{
	struct kgenome_script_text t;
	int ok;

	memset(l, 0, sizeof *l);
	if (!kgenome_script_text_make(lang, 0, p, n, &t))
		return 0;
	ok = SF_STRAT(&t, l);
	kgenome_script_text_free(&t);
	sf_props(n, l);
	return ok;
}

static int sf_run(const uint8_t *p, size_t n, struct kgenome_fntab_list *l)
{
	return sf_run_lang(SF_LANG, p, n, l);
}

static uint64_t sf_find(const char *s, size_t n, size_t from, const char *needle)
{
	size_t k = strlen(needle), i;

	for (i = from; i + k <= n; i++)
		if (memcmp(s + i, needle, k) == 0)
			return i;
	printf("  marker \"%s\" not found after %zu\n", needle, from);
	hk_fails++;
	return n;
}

static int sf_wordb(uint8_t c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c >= 0x80u;
}

/* The first `needle` after `from` that is not a part of a longer word (a name marker "f" is not the f of "def"). */
static uint64_t sf_find_word(const char *s, size_t n, size_t from, const char *needle)
{
	size_t k = strlen(needle), i;

	for (i = from; i + k <= n; i++)
		if (memcmp(s + i, needle, k) == 0 && !(i && sf_wordb((uint8_t)s[i - 1u]) && sf_wordb((uint8_t)needle[0])) &&
		    !(i + k < n && sf_wordb((uint8_t)s[i + k]) && sf_wordb((uint8_t)needle[k - 1u])))
			return i;
	printf("  name \"%s\" not found after %zu\n", needle, from);
	hk_fails++;
	return n;
}

/* `src` (n bytes) gives exactly the entries in `w` (nw of them). A `from` marker that begins with a line break names the byte
 * after that break (a label ":f" at a line start, not the ":f" of "call :f"). */
static void sf_check_lang(uint32_t lang, const char *where, const char *src, size_t n, const struct sf_want *w, uint32_t nw)
{
	struct kgenome_fntab_list l;
	uint64_t cur = 0;
	uint32_t i;
	int bad = hk_fails;

	CK(sf_run_lang(lang, (const uint8_t *)src, n, &l));
	CK(l.n == nw);
	for (i = 0; i < nw && i < l.n; i++) {
		const struct kgenome_func *f = &l.v[i];
		uint64_t off = sf_find(src, n, (size_t)cur, w[i].from) + (w[i].from[0] == '\n');
		/* open 1: runs to the end of the text; open 2: ends where the `to` marker BEGINS (the next start) */
		uint64_t end = w[i].open == 1 ? n : sf_find(src, n, (size_t)off + 1u, w[i].to) + (w[i].open ? 0u : strlen(w[i].to));

		CK(f->off == off);
		CK(f->off + f->len == end);
		CK(!!(f->flags & KGENOME_FN_F_END_OPEN) == !!w[i].open);
		if (w[i].name && *w[i].name) {
			CK(f->name_off == sf_find_word(src, n, (size_t)off, w[i].name));
			CK(f->name_len == strlen(w[i].name));
		} else {
			CK(f->name_len == 0);
		}
		cur = end;
	}
	if (hk_fails != bad) {
		printf("  in case %s: got %u\n", where, l.n);
		for (i = 0; i < l.n; i++)
			printf("    [%llu, +%llu) name %u+%u flags %x\n", (unsigned long long)l.v[i].off,
			       (unsigned long long)l.v[i].len, l.v[i].name_off, l.v[i].name_len, l.v[i].flags);
	}
	kgenome_fntab_list_free(&l);
}

static void sf_check(const char *where, const char *src, size_t n, const struct sf_want *w, uint32_t nw)
{
	sf_check_lang(SF_LANG, where, src, n, w, nw);
}

/* The same entries with CRLF, with lone CR (where the language has it) and behind a BOM: every offset moved by the bytes added. */
static void sf_variants(const char *where, const char *src)
{
	size_t n = strlen(src), i, k;
	struct kgenome_fntab_list base, v;
	uint8_t *buf = malloc(2u * n + 4u);
	uint64_t *map = malloc((n + 1u) * sizeof *map);
	int mode;

	if (!buf || !map) {
		free(buf);
		free(map);
		CK(0);
		return;
	}
	CK(sf_run((const uint8_t *)src, n, &base));
	for (mode = 0; mode < 3; mode++) {
		if (mode == 1 && !SF_CR)
			continue;
		k = 0;
		if (mode == 2) {
			memcpy(buf, "\xef\xbb\xbf", 3);
			k = 3;
		}
		for (i = 0; i < n; i++) {
			map[i] = k;
			if (src[i] == '\n' && mode == 0) {
				buf[k++] = '\r';
				buf[k++] = '\n';
			} else if (src[i] == '\n' && mode == 1) {
				buf[k++] = '\r';
			} else {
				buf[k++] = (uint8_t)src[i];
			}
		}
		map[n] = k;
		CK(sf_run(buf, k, &v));
		CK(v.n == base.n);
		for (i = 0; i < v.n && i < base.n; i++) {
			uint64_t be = base.v[i].off + base.v[i].len;

			CK(v.v[i].off == map[base.v[i].off]);
			/* an end just past a line's last byte stays before its break, whatever the break is */
			CK(v.v[i].off + v.v[i].len == (be == n ? k : map[be]));
			CK(v.v[i].name_off == (base.v[i].name_len ? map[base.v[i].name_off] : 0u));
			CK(v.v[i].name_len == base.v[i].name_len);
			CK(v.v[i].flags == base.v[i].flags);
		}
		if (v.n != base.n)
			printf("  variant %d of %s: %u entries, LF gave %u\n", mode, where, v.n, base.n);
		kgenome_fntab_list_free(&v);
	}
	kgenome_fntab_list_free(&base);
	free(buf);
	free(map);
}

#define SF_CASE(name, src, ...) do { \
	static const struct sf_want w_[] = { __VA_ARGS__ }; \
	sf_check(name, src, strlen(src), w_, (uint32_t)(sizeof w_ / sizeof w_[0])); \
	sf_variants(name, src); \
} while (0)
#define SF_NONE(name, src) do { \
	sf_check(name, src, strlen(src), NULL, 0); \
	sf_variants(name, src); \
} while (0)

/* A text of `reps` copies of `unit` (and `head` before them) is read in under 2 s and gives `want` entries. */
static void sf_hostile(const char *where, const char *head, const char *unit, uint32_t reps, uint32_t want)
{
	size_t hl = strlen(head), ul = strlen(unit), n = hl + ul * reps, i;
	uint8_t *buf = malloc(n ? n : 1u);
	struct kgenome_fntab_list l;
	double t0, dt;

	if (!buf) {
		CK(0);
		return;
	}
	memcpy(buf, head, hl);
	for (i = 0; i < reps; i++)
		memcpy(buf + hl + i * ul, unit, ul);
	t0 = hk_now();
	CK(sf_run(buf, n, &l));
	dt = hk_now() - t0;
	CK(l.n == want);
	CK(dt < 2.0);
	printf("  hostile %s: %zu bytes, %u entries, %.3f s\n", where, n, l.n, dt);
	kgenome_fntab_list_free(&l);
	free(buf);
}

#endif /* KGENOME_TESTS_SCRIPT_FUNCS_KIT_H */
