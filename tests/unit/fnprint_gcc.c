/*
 * fnprint_gcc (integration) - the walk against what gcc and ld say about a link. A small program of
 * known shape (a main, helpers that call each other, a signal handler whose address is taken, a
 * switch, recursion, libc calls) is built by the host's gcc with fixed flags into the build tree, with
 * a linker map. The map says, for every byte of code, which input object it came from: the author's
 * objects or the C library, the start-up files and libgcc. That is the exact label the walk is held to.
 *
 * SKIPPED, NOT FAILED, WHERE THERE IS NO GCC (or no static libc): the test says so and passes - a build
 * machine without a compiler is not a bug of the walk. Where gcc exists it runs, ~3 s, in
 * build/test/fnprint_gcc, never /tmp, with flags that do not vary between hosts.
 *
 * Held to it (stable configurations only):
 *   - main is found, and is the function the map calls main;
 *   - no function of the library is called AUTHOR (static: -O0 and -O2, with and without symbols; the
 *     weight of what is called AUTHOR but is library is zero);
 *   - every function of the program that the symbols name is found and called AUTHOR in the stripped file
 *     too (walk set plus the code the walk cuts out of its extents);
 *   - the same program built with and without -fcf-protection has the same fingerprints (strong and weak).
 */
#include <kgenome.h>

#include "../lib/genome/hk.h"

struct elfo {
	uint8_t *b;
	size_t n;
	struct kgenome_obj g;
	struct kgenome_elf_info *info;
	struct kgenome_func_set fs;
	struct kgenome_cell_space sp;
	int fs_sym;
	int link_dynamic;
	uint64_t code_end;
	int ok;
};

static void elfo_free(struct elfo *e)
{
	free(e->b);
	free(e->info);
	kgenome_funcs_free(&e->fs);
	memset(e, 0, sizeof *e);
}

static int elfo_load(struct elfo *e, const char *path)
{
	FILE *f = fopen(path, "rb");
	uint32_t i;
	long sz;

	memset(e, 0, sizeof *e);
	if (!f)
		return 0;
	fseek(f, 0, SEEK_END);
	sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	e->b = malloc((size_t)sz);
	e->n = (size_t)sz;
	if (!e->b || fread(e->b, 1, e->n, f) != e->n) {
		fclose(f);
		return 0;
	}
	fclose(f);
	e->info = calloc(1, sizeof *e->info);
	if (!e->info || !kgenome_elf_image_parse(kof_buf_make(e->b, e->n), e->info, &e->g))
		return 0;
	e->g.file_header = e->info;
	kgenome_funcs_build(e->g.format, e->b, e->n, e->g.file_header, &e->fs);
	e->fs_sym = e->fs.n != 0;
	if (!e->fs.n) {
		kgenome_funcs_free(&e->fs);
		memset(&e->fs, 0, sizeof e->fs);
		kgenome_diag_funcs_of(&e->g, e->b, e->n, &e->fs);
	}
	for (i = 0; i < e->info->seg_count; i++)
		if (e->info->seg[i].type == 3u)
			e->link_dynamic = 1;
	e->code_end = KGENOME_BROKEN;
	for (i = 0; i < e->info->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
		const struct kgenome_elf_sec *sc = &e->info->sec[i];

		if (kgenome_elf_sec_is_code(sc) && sc->file_off + sc->file_size <= e->n &&
		    (e->code_end == KGENOME_BROKEN || sc->file_off + sc->file_size > e->code_end))
			e->code_end = sc->file_off + sc->file_size;
	}
	kgenome_cell_space_init(&e->sp, &e->g, e->b, e->n);
	e->ok = e->fs.n > 0;
	return e->ok;
}

static uint64_t va_of(const struct elfo *e, uint64_t off)
{
	struct kgenome_image_seg g;

	return e->sp.seg_at(e->sp.priv, off, &g) ? off + (uint64_t)g.delta : off;
}

/* ---- the map: which input object each stretch of code came from ------------------- */

struct span { uint64_t lo, hi; };
struct amap {
	struct span a[64];
	uint32_t n;
	uint64_t main_va;
};

static int map_load(struct amap *m, const char *path)
{
	FILE *f = fopen(path, "r");
	char line[1024], prev[256] = "";

	memset(m, 0, sizeof *m);
	if (!f)
		return 0;
	while (fgets(line, sizeof line, f)) {
		unsigned long long a, s;
		char sec[256], file[512];
		int k;

		/* ` .text.startup  0x... 0x... /path/auth_x.o`, or the name alone on one line and the rest on the next */
		if ((k = sscanf(line, " %255s 0x%llx 0x%llx %511s", sec, &a, &s, file)) == 4 && sec[0] == '.') {
			;
		} else if (line[0] == ' ' && line[1] == '.' && sscanf(line, " %255s", prev) == 1 && strchr(line + 1, ' ') == NULL) {
			continue;
		} else if (sscanf(line, " 0x%llx 0x%llx %511s", &a, &s, file) == 3 && prev[0] == '.') {
			snprintf(sec, sizeof sec, "%s", prev);
			prev[0] = 0;
		} else {
			unsigned long long v;
			char sym[128];

			if (!m->main_va && sscanf(line, " 0x%llx %127s", &v, sym) == 2 && !strcmp(sym, "main"))
				m->main_va = v;
			if (line[0] != ' ' || line[1] != '.')
				prev[0] = 0;
			continue;
		}
		prev[0] = 0;
		if (s && strstr(file, "auth_") && !strncmp(sec, ".text", 5) && m->n < 64) {
			m->a[m->n].lo = a;
			m->a[m->n].hi = a + s;
			m->n++;
		}
	}
	fclose(f);
	return m->n > 0 && m->main_va;
}

static int is_author_va(const struct amap *m, uint64_t va)
{
	uint32_t i;

	for (i = 0; i < m->n; i++)
		if (va >= m->a[i].lo && va < m->a[i].hi)
			return 1;
	return 0;
}

/* ---- building ---------------------------------------------------------------------- */

static const char *src_a =
	"#include <signal.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n"
	"int helper_sum(const int *v, int n);\nint helper_mix(int x);\nlong helper_rec(int n);\n"
	"static volatile int g_stop;\n"
	"static void on_sig(int s) { g_stop = s; }\n"
	"static int classify(int c)\n{\n\tswitch (c) {\n\tcase 0: return 10; case 1: return 21; case 2: return 33; case 3: return 47;\n"
	"\tcase 4: return 52; case 5: return 68; case 6: return 71; case 7: return 89; default: return -1;\n\t}\n}\n"
	"__attribute__((noinline)) static int scan(const char *s)\n{\n\tint h = 0;\n\twhile (*s)\n\t\th = h * 31 + classify(*s++ & 7);\n\treturn h;\n}\n"
	"int main(int argc, char **argv)\n{\n\tint v[16], i, r = 0;\n\tchar buf[64];\n\tsignal(SIGINT, on_sig);\n"
	"\tfor (i = 0; i < 16; i++)\n\t\tv[i] = helper_mix(i + argc);\n\tr += helper_sum(v, 16);\n\tr += (int)helper_rec(argc + 5);\n"
	"\tmemset(buf, 'a' + (r & 7), sizeof buf - 1);\n\tbuf[sizeof buf - 1] = 0;\n\tr += scan(argc > 1 ? argv[1] : buf);\n"
	"\tprintf(\"%d %zu\\n\", r + g_stop, strlen(buf));\n\treturn 0;\n}\n";

static const char *src_b =
	"int helper_mix(int x)\n{\n\tx ^= x << 13; x ^= x >> 7; x ^= x << 17;\n\treturn x * 2654435761u + 7;\n}\n"
	"int helper_sum(const int *v, int n)\n{\n\tint i, s = 0;\n\tfor (i = 0; i < n; i++)\n\t\ts += helper_mix(v[i]) & 0xff;\n\treturn s;\n}\n"
	"long helper_rec(int n)\n{\n\treturn n < 2 ? n : helper_rec(n - 1) + helper_rec(n - 2);\n}\n";

#define DIR "build/test/fnprint_gcc"

static int write_src(void)
{
	FILE *f;

	if (system("mkdir -p " DIR) != 0)
		return 0;
	f = fopen(DIR "/auth_a.c", "w");
	if (!f)
		return 0;
	fputs(src_a, f);
	fclose(f);
	f = fopen(DIR "/auth_b.c", "w");
	if (!f)
		return 0;
	fputs(src_b, f);
	fclose(f);
	return 1;
}

/* One configuration: objects, link with a map, the stripped copy. 0 when gcc refused it. */
static int build(const char *tag, const char *flags, const char *ldflags)
{
	char a[256], o1[300], o2[300];

	snprintf(o1, sizeof o1, DIR "/%s_auth_a.o", tag);
	snprintf(o2, sizeof o2, DIR "/%s_auth_b.o", tag);
	snprintf(a, sizeof a, DIR "/%s", tag);
	{
		char cmd[4096];

		snprintf(cmd, sizeof cmd, "gcc %s -c " DIR "/auth_a.c -o %s 2>/dev/null && gcc %s -c " DIR "/auth_b.c -o %s 2>/dev/null && "
			 "gcc %s %s %s -o %s.out -Wl,-Map=%s.map 2>/dev/null && gcc %s %s %s -s -o %s.strip 2>/dev/null",
			 flags, o1, flags, o2, o1, o2, ldflags, a, a, o1, o2, ldflags, a);
		return system(cmd) == 0;
	}
}

/* Is a static libc there? A trivial program linked -static. */
static int have_static(void)
{
	return system("echo 'int main(void){return 0;}' > " DIR "/probe.c && gcc -static " DIR "/probe.c -o " DIR "/probe 2>/dev/null") == 0;
}

/* ---- what is held to ----------------------------------------------------------------- */

struct run {
	struct kgenome_fnprint_set s;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
};

static void do_walk(const struct elfo *e, struct run *r)
{
	struct kgenome_fnprint_req rq;

	memset(&rq, 0, sizeof rq);
	rq.p = e->b;
	rq.n = e->n;
	rq.arch = KGENOME_ARCH_X86_64;
	rq.space = &e->sp;
	rq.funcs = &e->fs;
	rq.entry_off = e->g.entry_off;
	rq.code_end = e->code_end;
	rq.link = e->link_dynamic ? KGENOME_FNP_LINK_DYNAMIC : KGENOME_FNP_LINK_STATIC;
	rq.extents = e->fs_sym ? KGENOME_FNP_EXT_SIZED : KGENOME_FNP_EXT_ENTRY_WALK;
	rq.stat = &r->st;
	kgenome_fnprint_collect(&rq, &r->s);
}

static const struct kgenome_fnprint_fn *find_va(const struct elfo *e, const struct run *r, uint64_t va)
{
	uint32_t i;

	for (i = 0; i < r->s.n; i++)
		if (va_of(e, r->s.fn[i].off) == va)
			return &r->s.fn[i];
	return NULL;
}

/* The weight called AUTHOR that the map says is not the author's. */
static uint64_t leaked_weight(const struct elfo *e, const struct run *r, const struct amap *m, uint32_t *n_fns)
{
	uint64_t w = 0;
	uint32_t i;

	*n_fns = 0;
	for (i = 0; i < r->s.n; i++) {
		const struct kgenome_fnprint_fn *f = &r->s.fn[i];

		if (f->cls == KGENOME_FNP_AUTHOR && !is_author_va(m, va_of(e, f->off))) {
			w += f->weight;
			(*n_fns)++;
		}
	}
	return w;
}

/* One configuration, held to the map. `expect_zero_fns`: no library function at all may be called AUTHOR. */
static void check_config(const char *tag, int expect_zero_fns)
{
	char p1[300], p2[300], pm[300];
	struct elfo es, eu;
	struct run rs, ru;
	struct amap m;
	uint32_t i, found = 0, total = 0, nl, exact = 0;
	const struct kgenome_fnprint_fn *mf;

	snprintf(p1, sizeof p1, DIR "/%s.out", tag);
	snprintf(p2, sizeof p2, DIR "/%s.strip", tag);
	snprintf(pm, sizeof pm, DIR "/%s.map", tag);
	memset(&rs, 0, sizeof rs);
	memset(&ru, 0, sizeof ru);
	CK(map_load(&m, pm));
	CK(elfo_load(&eu, p1) && eu.fs_sym);
	CK(elfo_load(&es, p2) && !es.fs_sym);
	if (hk_fails)
		goto out;
	do_walk(&eu, &ru);
	do_walk(&es, &rs);
	/* main */
	CK(ru.st.main_off != KGENOME_BROKEN && va_of(&eu, ru.st.main_off) == m.main_va);
	CK(rs.st.main_off != KGENOME_BROKEN && va_of(&es, rs.st.main_off) == m.main_va);
	mf = find_va(&es, &rs, m.main_va);
	CK(mf && mf->cls == KGENOME_FNP_AUTHOR && (mf->reason & KGENOME_FNP_R_MAIN));
	/* nothing of the library carries weight as the program's */
	CK(leaked_weight(&eu, &ru, &m, &nl) == 0);
	if (expect_zero_fns)
		CK(nl == 0);
	CK(leaked_weight(&es, &rs, &m, &nl) == 0);
	if (expect_zero_fns)
		CK(nl == 0);
	/* every function of the program the symbols name is found, and is the program's, in the stripped file */
	for (i = 0; i < ru.s.n; i++) {
		uint64_t va = va_of(&eu, ru.s.fn[i].off);

		if (!is_author_va(&m, va) || ru.s.fn[i].n_insn < 4)
			continue;
		total++;
		{
			const struct kgenome_fnprint_fn *g = find_va(&es, &rs, va);

			if (g && g->cls == KGENOME_FNP_AUTHOR)
				found++;
		}
	}
	CK(total >= 4 && found == total);
	/*
	 * The symbol set's fingerprint of a function and the stripped file's agree whenever the stripped file's body ends where the
	 * function does. It does not always: a function whose last instruction is a call that does not return (main, with the stack
	 * protector: call __stack_chk_fail) has no terminal, and an entry walk reads on into the next function. Counted, not hidden.
	 */
	for (i = 0; i < ru.s.n; i++) {
		uint64_t va = va_of(&eu, ru.s.fn[i].off);
		const struct kgenome_fnprint_fn *g;

		if (!is_author_va(&m, va) || ru.s.fn[i].n_insn < 4)
			continue;
		g = find_va(&es, &rs, va);
		if (g && g->body_len == ru.s.fn[i].body_len) {
			exact++;
			CK(g->fp == ru.s.fn[i].fp && g->fw == ru.s.fn[i].fw);
		}
	}
	CK(exact >= 3);
out:
	kgenome_fnprint_set_free(&rs.s, NULL);
	kgenome_fnprint_set_free(&ru.s, NULL);
	elfo_free(&es);
	elfo_free(&eu);
}

/* The same program with and without the landing pads of -fcf-protection: the same fingerprints. */
static void check_cf_protection(void)
{
	struct elfo a, b;
	struct run ra, rb;
	struct amap ma, mb;
	uint32_t i, j, same = 0, total = 0;

	memset(&ra, 0, sizeof ra);
	memset(&rb, 0, sizeof rb);
	CK(map_load(&ma, DIR "/s2.map") && map_load(&mb, DIR "/s2cf.map"));
	CK(elfo_load(&a, DIR "/s2.out") && elfo_load(&b, DIR "/s2cf.out"));
	if (hk_fails)
		goto out;
	do_walk(&a, &ra);
	do_walk(&b, &rb);
	for (i = 0; i < ra.s.n; i++) {
		if (!is_author_va(&ma, va_of(&a, ra.s.fn[i].off)) || ra.s.fn[i].n_insn < 4)
			continue;
		/* the counterpart in the other build: the author function with the same weak fingerprint and size class */
		total++;
		for (j = 0; j < rb.s.n; j++)
			if (is_author_va(&mb, va_of(&b, rb.s.fn[j].off)) && rb.s.fn[j].fp == ra.s.fn[i].fp && rb.s.fn[j].fw == ra.s.fn[i].fw) {
				same++;
				break;
			}
	}
	CK(total >= 4 && same >= total - total / 5);        /* at most one in five differs for a reason that is not the pad */
out:
	kgenome_fnprint_set_free(&ra.s, NULL);
	kgenome_fnprint_set_free(&rb.s, NULL);
	elfo_free(&a);
	elfo_free(&b);
}

int main(void)
{
	int st;

	if (system("gcc --version > /dev/null 2>&1") != 0) {
		printf("fnprint_gcc: SKIPPED - no gcc on this host\n");
		return 0;
	}
	if (!write_src()) {
		printf("fnprint_gcc: SKIPPED - cannot write " DIR "\n");
		return 0;
	}
	st = have_static();
	if (st) {
		/* static, with and without the CET landing pads, and -O0: the layouts of a gcc/ld/glibc link */
		if (build("s2", "-O2 -fcf-protection=none", "-static -no-pie") && build("s2cf", "-O2 -fcf-protection=full", "-static -no-pie") &&
		    build("s0", "-O0 -fcf-protection=none", "-static -no-pie")) {
			check_config("s2", 1);
			check_config("s2cf", 1);
			check_config("s0", 1);
			check_cf_protection();
		} else {
			printf("fnprint_gcc: SKIPPED static - gcc could not build the configurations\n");
		}
	} else {
		printf("fnprint_gcc: SKIPPED static - no static libc here\n");
	}
	/* dynamic: crtbegin's helpers are not the program's; what follows the program's last function is kept (no libc in the file) */
	if (build("d2", "-O2 -fcf-protection=none", "-no-pie"))
		check_config("d2", 0);
	else
		printf("fnprint_gcc: SKIPPED dynamic - gcc could not build it\n");
	printf("fnprint_gcc: %s\n", hk_fails ? "FAIL" : "ok");
	return hk_fails != 0;
}
